[![Build Status][ci-shield]][ci-link]

# Theo

Theo monitors access privileges originating from third-party dependencies via static analysis. It identifies sensitive Java API calls (filesystem, network, reflection, process execution, etc.) made by each dependency, determines which of those are reachable from the client project's code, detects changes across runs, and checks dependencies for known CVEs.

## Modules

| Module | Description |
|--------|-------------|
| `theo-commons` | Shared utilities: sensitive API definitions (`sensitive_apis.json`), package matching |
| `theo-static-maven-plugin` | Maven plugin with `preprocess`, `analyze`, and `cve-check` goals |
| `package-static-analyzer` | CLI tool that analyzes a single package JAR for sensitive API usage |
| `package-miner` | Batch analysis tool for mining Maven Central packages |

## Quick start

Build all modules:

```
mvn clean install
```

Add the plugin to the target project's `pom.xml`:

```xml
<build>
  <plugins>
    <plugin>
      <groupId>io.github.sparkrew</groupId>
      <artifactId>theo-static-maven-plugin</artifactId>
      <version>1.0-SNAPSHOT</version>
    </plugin>
  </plugins>
</build>
```

Run the analysis:

```
mvn theo-static:analyze -Dtheo.packageNames=com.example.app
```

Check dependencies for known CVEs (run after `analyze`):

```
mvn theo-static:cve-check
```

### Goals

- **`preprocess`** -- Builds a package-to-dependency map from Maven's resolved dependencies.
- **`analyze`** -- Analyzes all dependencies for sensitive API usage, determines client reachability, detects changes from the previous run, and generates HTML reports.
- **`cve-check`** -- Queries OSV.dev for known vulnerabilities in the analyzed dependencies and augments reports with CVE badges.

### Configuration

| Property | Default | Description |
|----------|---------|-------------|
| `theo.packageNames` | (required) | Comma-separated package names of the client project |
| `theo.skipSameGroupId` | `true` | Skip dependencies that share the client project's groupId |
| `theo.verbose` | `true` | Show all changes in CLI output; when false, only reachable changes |
| `theo.cacheDir` | `~/.theo/cache` | Persistent cache directory |
| `theo.reportDir` | `target/theo-report` | Report output directory |
| `theo.analyzerJarPath` | (auto-resolved) | Path to the package-static-analyzer JAR |

To include same-groupId dependencies in the analysis:

```
mvn theo-static:analyze -Dtheo.packageNames=com.example.app -Dtheo.skipSameGroupId=false
```

## Reports

The `analyze` goal generates three HTML reports in `target/theo-report/`:

- `all-dependencies.html` -- Every sensitive API call from every dependency.
- `reachable.html` -- Only sensitive APIs reachable from the client project's code.
- `changes.html` -- What changed since the last run (added, modified, removed dependencies and their sensitive API usage).

## Cache

Analysis results are cached in `~/.theo/cache/` by default (configurable via `theo.cacheDir`). The cache survives `mvn clean` and avoids re-analyzing unchanged dependencies.

The first run can take a few minutes to complete becuase it analyzes all the dependencies one by one, but the subsequent runs will be faster with caching. 

## Design

For design decisions and architecture details, see [Design.md](Design.md).

<!-- references -->

[ci-shield]: https://github.com/sparkrew/theo/actions/workflows/test.yml/badge.svg?branch=main
[ci-link]: https://github.com/sparkrew/theo/actions
