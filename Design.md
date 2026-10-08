# Design

## Overview

Theo is a static analysis tool that monitors the access privileges third-party dependencies exercise in a Java project. It answers two questions: what sensitive APIs does each dependency call, and which of those calls are actually reachable from the client project's own code? By running Theo across builds, developers can detect when a dependency update introduces new privilege usage -- a file-reading library that starts opening network sockets, for example.

Sensitive APIs are operations like filesystem I/O, network access, reflection, process execution, and native code loading. The full list lives in `theo-commons/src/main/resources/sensitive_apis.json`, categorized by class, method, and category (e.g., `FILESYSTEM`, `NETWORK`, `REFLECTION`).

## Architecture

The analysis pipeline has four stages. All are orchestrated by `AnalysisOrchestrator` inside the Maven plugin.

### 1. Preprocess (package-to-dependency map)

The `preprocess` goal (or inline logic in the `analyze` goal when the map is missing) walks Maven's resolved dependency tree and scans each JAR to build a JSON map from Java package names to Maven GAV coordinates. This map is the foundation for attributing call-graph edges to specific dependencies.

Output: `target/theo-package-map.json`

### 2. Per-dependency analysis via package-static-analyzer subprocess

For each dependency JAR, `DependencyAnalyzer` launches `package-static-analyzer` as a subprocess. The analyzer builds a call graph with SootUp, walks it from the dependency's entry points, and records every path that reaches a sensitive API. The result is a JSON report listing each sensitive API call, the access type (direct or indirect), the entry-point method, and the full call path.

By default, all dependencies (direct and transitive) are analyzed. The `theo.directOnly` flag restricts analysis to direct dependencies only, which can be useful for large dependency trees where transitive analysis is too slow or noisy.

Results are cached by GAV coordinates. Unchanged dependencies are skipped on subsequent runs. SNAPSHOT dependencies are always re-analyzed because their contents are mutable.

### 3. Client reachability analysis

`ClientReachabilityAnalyzer` loads the client project's compiled JAR, builds a separate call graph rooted at the project's own public methods (filtered by `theo.packageNames`), and determines which dependency-side sensitive APIs are actually reachable from the client's code. This separates "the dependency can do X" from "our code lets the dependency do X."

### 4. Merge, change detection, and report generation

The orchestrator merges per-dependency reports into an `AnalysisSummary`, compares it against the cached last-run summary via `ChangeDetector`, and passes both to `HtmlReportGenerator`. Three HTML reports are written to `target/theo-report/`, with sensitive APIs grouped by category and subcategory.

## Key design decisions

### Maven plugin instead of CLI

Theo runs as a Maven plugin rather than a standalone CLI tool. This integrates it into the build lifecycle and gives it direct access to Maven's resolved dependency model -- the full transitive closure of dependencies with their JAR file paths, GAV coordinates, and scopes. A CLI tool would need to replicate Maven's dependency resolution or require the user to provide it externally.

### Merged preprocessor

The preprocessor was originally a separate plugin that had to run before the static analyzer. It was merged into the same plugin (as the `preprocess` goal) to reduce user configuration. The `analyze` goal also builds the package map inline if it detects the preprocess step was skipped, so users can run a single command.

### Subprocess for package-static-analyzer

Each dependency is analyzed by launching `package-static-analyzer` as a separate JVM process rather than calling its analysis logic in-process. There are several reasons:

- **Static state**: `PackageStaticAnalyzer` uses static fields and SootUp maintains global state that does not reset cleanly between invocations within the same JVM. Running each analysis in a fresh process avoids contamination.
- **`System.exit` in `Main`**: The CLI entry point calls `System.exit()`, which would terminate the Maven build if invoked in-process.
- **Memory isolation**: SootUp's call graph construction is memory-intensive. A subprocess gets its own heap and is cleaned up by the OS when it exits, preventing accumulation across dozens of dependencies.
- **No modification requirement**: The package-static-analyzer is also used independently (by `package-miner`) and its behavior must remain unchanged. Wrapping it as a subprocess lets the Maven plugin use it as-is.

### SootUp with Rapid Type Analysis

Call graphs are constructed using SootUp's `RapidTypeAnalysisAlgorithm`. RTA offers a practical balance: it resolves virtual calls by tracking which types are instantiated (more precise than Class Hierarchy Analysis) without the cost of points-to analysis. It handles Java bytecode directly, so source code is not required. SootUp was chosen over the original Soot framework because it is actively maintained and has a cleaner API.

### CFR for decompilation

Reports include decompiled source code snippets for the methods that reach sensitive APIs. CFR was chosen because it is the best-maintained Java decompiler with a clean programmatic API. It is used only for display purposes in the HTML reports.

### OSV.dev for CVE checking

The `cve-check` goal runs the full analysis and then queries the OSV.dev API for known vulnerabilities. OSV.dev was chosen because it is free, requires no API key, and aggregates data from NVD, GitHub Security Advisories, and other sources. It provides dependency-level vulnerability information (which versions of a library are affected), not method-level information.

### CWE-based CVE categorization

CVEs are placed under the same categories as sensitive APIs using CWE IDs. Each CVE/advisory includes CWE tags (e.g. CWE-22 for path traversal), and the mapping from CWE to Theo's categories comes directly from Table II of [the work by Rahman et al.](https://arxiv.org/abs/2408.02846). This is deterministic and auditable — a CVE tagged CWE-78 goes under PROCESS/OPERATING_SYSTEM, CWE-918 under NETWORK/CONNECTION, etc. CVEs with CWEs not in the table, or with no CWE tags, are placed under OTHER.

### Unaudited capability badges

When a reachable sensitive API's category has no known CVE for that dependency, the reachable report shows an "unaudited capability" badge with the most representative CWE for that subcategory. This flags gaps in CVE coverage — not vulnerabilities, but capabilities that haven't been audited. The badge tooltip explains what it means (e.g. "This dependency has operating system capability with no known CVE in this category. Historically associated with CWE-78.").

### `<details>`/`<summary>` for HTML reports

The reports use HTML5 `<details>` and `<summary>` elements for collapsible sections. This keeps the reports functional without any JavaScript, CSS frameworks, or external assets. The HTML is self-contained and renders correctly in all modern browsers.

### Persistent cache in `~/.theo/cache/`

The cache directory defaults to `~/.theo/cache/` rather than a location under `target/`. This is deliberate: `mvn clean` wipes `target/`, and re-analyzing all dependencies from scratch on every clean build is expensive. The cache location is configurable via the `theo.cacheDir` property.

### Three separate reports

Each report serves a different use case:

- **`all-dependencies.html`**: Full inventory of every sensitive API call across all dependencies. Useful for auditing.
- **`reachable.html`**: Filtered to only the sensitive APIs that the client project's code can actually reach. This is the actionable view for most developers.
- **`changes.html`**: Diff against the previous run. Shows added, modified, and removed dependencies and their privilege changes.

All three are generated by default. The `theo.reachableOnly` flag restricts output to just `reachable.html`, which is useful when only the actionable view matters (e.g. in CI pipelines where the full inventory is noise).

### Dependency metadata (scope and depth)

Each dependency in the reports is annotated with its Maven scope (compile, runtime, test, provided) and its depth in the dependency tree (1 = direct, 2+ = transitive). Depth comes from Maven's `Artifact.getDependencyTrail()`. This metadata helps developers understand which dependencies they chose directly versus which were pulled in transitively — a sensitive API access from a transitive dependency at depth 4 is harder to notice and control than one from a direct dependency.

### Change detection via cached last-run

Changes are detected by comparing the current `AnalysisSummary` against the previous one stored in the cache (`last-run.json`), not by inspecting git history or version control diffs. This approach is simpler and more reliable: it works regardless of the VCS in use, handles non-version-controlled projects, and directly compares analysis outputs rather than trying to infer changes from source diffs.

### SNAPSHOT dependencies always re-analyzed

Maven SNAPSHOT versions are mutable -- the same version string can refer to different bytecode at different times. The cache therefore always skips SNAPSHOTs and forces a fresh analysis. Release versions are immutable by Maven convention and can be safely cached.

## Cache structure

```
~/.theo/cache/
  dependencies/
    {groupId}/
      {artifactId}/
        {version}/
          report.json          # per-dependency analysis results
  projects/
    {groupId}__{artifactId}/
      last-run.json            # full AnalysisSummary from last run
```

- `report.json` contains the `DependencyReport` for a single dependency: its GAV, the list of sensitive API entries (each with access type, entry point, and full call path), and whether it has any sensitive APIs.
- `last-run.json` contains the complete `AnalysisSummary` from the most recent analysis of a project, used by `ChangeDetector` to produce the changes report. The project version is excluded from the cache path so that version bumps still compare against the previous run.

## Extending

To add new sensitive APIs, edit `theo-commons/src/main/resources/sensitive_apis.json`. Each entry requires:

```json
{
  "className": "java.lang.ProcessBuilder",
  "method": "start",
  "subcategory": "EXEC",
  "category": "PROCESS"
}
```

Rebuild `theo-commons` after changes (`mvn install -pl theo-commons`). Both the Maven plugin and the standalone analyzer load the API list from the classpath at runtime.
