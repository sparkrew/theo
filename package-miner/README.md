# Package Miner

Mines Maven Central for popular Java packages, downloads their JARs and all transitive dependencies, runs the Theo static analyzer with a complete classpath for accurate call graph construction, and tracks how sensitive API permissions change across releases.

## Pipeline Overview

The pipeline has four phases, each checkpointed so it can resume after interruption.

```
Phase 1: SELECT       Popular Java packages from Maven Central (by download count)
Phase 2: ANALYZE      Download JAR + deps, run preprocessor + static analyzer
Phase 3: SCM TRACK    Extract SCM info from POMs (for packages with sensitive APIs)
Phase 4: VERSIONS     Analyze release history from Maven Central (batched)
```

---

## Phase 1: SELECT

Queries Maven Central's Solr search API (`search.maven.org/solrsearch/select`) for packages sorted by download count (`ec_count desc`), paging 200 results at a time with a 1-second rate limit.

### Filters applied (on Solr response fields only — no POM download needed)

**Timestamp filter:** Packages whose `timestamp` field is before the cutoff year (default 2021) are skipped.

**Language filter (quick check):** The package's `groupId` and `artifactId` are checked for substrings: `kotlin`, `scala`, `kotlinx`, `groovy`, `clojure`. This catches obvious non-Java packages without downloading their POM.

**Popularity ranking:** Maven Central's Solr API uses `ec_count` as a sort parameter but does not return it in the response. The `downloadCount` field uses the inverse ordinal position from Solr results (`Long.MAX_VALUE - rank`) so the first result gets the highest value.

**Checkpoint:** `selected_packages.json`

---

## Phase 2: ANALYZE

For each selected package, executed in parallel across worker threads:

### 1. Download
- **Bytecode JAR** from `repo1.maven.org` (required — SootUp needs compiled `.class` files)
- **Source JAR** (optional — used for cleaner package name extraction)
- **POM** (for dependency resolution)

### 2. Dependency resolution
A temporary Maven project is created from the downloaded POM. Two Maven goals are run in it:

**Preprocessor** (`theo-preprocessor-maven-plugin:preprocess`): Resolves all transitive dependencies and scans their JARs to build `package-map.json` — maps Java package names to their Maven dependency coordinates. Timeout: 10 minutes.

**Dependency copy** (`dependency:copy-dependencies`): Downloads all transitive runtime dependency JARs into a per-package folder (`deps/<pkgKey>/`). Timeout: 10 minutes.

### 3. Static analysis
The `package-static-analyzer` is invoked as a subprocess with the full classpath:
```
java -jar <analyzer-jar> analyze \
  -j <project-jar> -p <package-names> -m <package-map> -r <report-file> \
  -d <deps-dir>
```

When `-d` is provided, SootUp loads the project JAR plus all dependency JARs from the directory, giving it a **complete classpath** for accurate call graph construction. Entry points are filtered to only the project's own classes (using the `-p` package names), so dependency methods are not treated as entry points.

Each path is classified as:
- **DIRECT**: the package's own code calls the sensitive API
- **INDIRECT**: the call goes through one or more dependencies

The package map distinguishes project code from dependency code, so even if the project JAR is a fat/uber JAR, the classification works correctly.

### 4. Package name extraction
Java package names are extracted from the JAR by scanning `.class` entries. Dependency packages (from the package map) are subtracted to handle uber JARs. A minimum of 3 dot-separated segments is required for a base package name (e.g., `com.example.project`). Falls back to the groupId if nothing is found.

**Checkpoint:** `checkpoint.json` (list of completed `groupId:artifactId:version` coordinates)

---

## Phase 3: SCM TRACKING

After analysis completes, for packages that have at least one sensitive API, the POM is downloaded and parsed for `<scm>` tags. Packages are categorized into three groups:

- **No SCM tag** → `packages_no_scm.json`
- **Non-GitHub SCM** (GitLab, Bitbucket, etc.) → `packages_non_github_scm.json` (includes the raw SCM URL)
- **GitHub SCM** → `packages_with_github_scm.json` (includes the normalized GitHub URL)

The SCM tag is parsed from `<url>`, `<connection>`, and `<developerConnection>` in priority order. A regex normalizes all URL formats to `https://github.com/owner/repo`.

SCM info is tracked for reporting purposes only — it does not affect package selection or analysis.

---

## Phase 4: VERSION HISTORY

For packages with sensitive APIs, ordered by the number of detected APIs (descending), processed in batches (default 100).

### Version discovery
Uses Maven Central's `core=gav` Solr API to fetch all published versions within the configured time range (default 5 years).

### Version filtering
Only **stable releases** are analyzed. Versions are rejected if they match any of:
`SNAPSHOT`, `alpha`, `beta`, `-rc`, `-m<N>` (milestone), `nightly`, `dev`, `preview`, `incubating`

All stable version transitions are analyzed — **major, minor, and patch** changes are all included.

### Analysis per version
For each stable version: download the JAR, resolve dependencies, run preprocessor, run analyzer.

### Change tracking
The `VersionHistoryTracker` parses each version's report, extracts direct and indirect API sets, and computes diffs between consecutive versions. APIs appearing in both direct and indirect are kept in direct only.

### Visualization
An HTML report (`permission_changes_report.html`) is generated with:
- Summary statistics (total packages, with/without changes, total versions analyzed)
- Per-package heatmap grids (versions × APIs) color-coded: blue = direct, light blue = indirect, red = newly added direct, orange = newly added indirect, yellow = removed
- Per-package change logs

**Checkpoint:** `version_history_checkpoint.json` (batch index for resume)

---

## Building

From the project root:

```bash
# Build the package-miner fat JAR
mvn package -pl package-miner -am -DskipTests

# Build the package-static-analyzer fat JAR (needed as input)
mvn package -pl package-static-analyzer -am -DskipTests
```

---

## Usage

```bash
java -jar package-miner/target/package-miner-1.0-SNAPSHOT-jar-with-dependencies.jar mine \
  -o /path/to/output \
  -j /path/to/package-static-analyzer-1.0-SNAPSHOT-jar-with-dependencies.jar \
  -t 2000 \
  -w 4
```

### CLI Options

| Option | Required | Default | Description |
|---|---|---|---|
| `-o, --output-dir` | Yes | — | Directory where all results are written |
| `-j, --analyzer-jar` | Yes | — | Path to the `package-static-analyzer` fat JAR |
| `-t, --total-packages` | No | `2000` | Number of packages to analyze |
| `-w, --workers` | No | `1` | Number of parallel workers |
| `--download-dir` | No | `<output-dir>/jars` | Directory for downloaded JARs |
| `--analyze-all-versions` | No | `true` | Enable/disable version history analysis |
| `--version-history-years` | No | `5` | Years of release history to analyze |
| `--version-history-batch-size` | No | `100` | Packages per version-history batch |
| `--cutoff-year` | No | `2021` | Skip packages not updated since this year |

### Output Directory Structure

```
output-dir/
  sensitive_api_usage.csv           Main result: packages × 219 sensitive APIs
  mining_summary.json               Pipeline statistics
  selected_packages.json            Phase 1 checkpoint
  checkpoint.json                   Phase 2 checkpoint (completed packages)
  version_history_checkpoint.json   Phase 4 checkpoint (batch index)
  packages_no_scm.json              Packages with no SCM tag (sensitive APIs only)
  packages_non_github_scm.json      Packages with non-GitHub SCM
  packages_with_github_scm.json     Packages with GitHub SCM
  jars/                             Downloaded JARs
  poms/                             Downloaded POM files
  deps/                             Resolved dependency JARs (per-package subdirs)
  temp-projects/                    Temporary Maven project dirs
  package-maps/                     Generated package-map.json per package
  reports/                          Analyzer report JSONs per package
  paths/                            Call path JSONs (packages with sensitive APIs)
  version-history/                  Per-package version history JSONs
  permission_changes_report.html    Interactive HTML visualization
```

### CSV Format

```
groupId,artifactId,version,scmUrl,java.io.FileInputStream.<init>,...
com.google.guava,guava,32.1.3-jre,,True,...
```

4 metadata columns followed by 219 sensitive API columns with `True`/`False` values.

### Resuming After Interruption

Re-run the same command. The tool will:
- Reuse the package list from `selected_packages.json`
- Skip packages already in `checkpoint.json`
- Skip version-history batches in `version_history_checkpoint.json`
- Skip JARs, POMs, reports, and package maps that already exist on disk
- Skip dependency directories that already contain JARs

---

## Key Implementation Details

**Full classpath analysis:** The key improvement over naive JAR-only analysis. By downloading all transitive dependency JARs and passing them to SootUp alongside the project JAR, the call graph is complete. Without dependencies, SootUp silently drops call edges to unresolvable classes — missing INDIRECT paths. The package map still correctly classifies which calls go through dependencies.

**XML parsing:** POM parsing uses `javax.xml.parsers.DocumentBuilderFactory` with external DTD, general entities, and parameter entities disabled (XXE prevention). No XML library dependency needed.

**Kotlin/Scala detection:** Quick check on groupId/artifactId substrings (`kotlin`, `scala`, `kotlinx`, `groovy`, `clojure`). A deeper POM-based check (`ScmExtractor.isKotlinOrScala`) scans for language-specific plugins and dependencies but is not used during selection (no POM download in phase 1).

**Sensitive APIs:** 219 identifiers from `theo-commons/src/main/resources/sensitive_apis.json` covering FILESYSTEM, NETWORK, REFLECTION, SERIALIZATION, CRYPTOGRAPHY, DATABASE, and PROCESS_EXECUTION.

**Thread safety:** `ResultWriter` uses a synchronized write lock. `CheckpointManager` uses `Collections.synchronizedSet`. `MiningStats` uses `AtomicInteger` counters.

**Timeouts:** Build/preprocessor: 10 min each. Dependency resolution: 10 min. Analyzer: 30 min. Maven Central requests: 60 sec.

---

## Known Limitations & Future Work

- **SCM inheritance from parent POMs:** Many packages inherit `<scm>` from a parent POM. The child POM on Maven Central often doesn't redeclare it, so SCM tracking undercounts. A future improvement would chase parent POMs.
- **Non-GitHub hosting:** Packages on GitLab, Bitbucket, etc. are tracked in `packages_non_github_scm.json` but not analyzed differently.
- **Java version constraints:** The preprocessor and dependency resolution run `mvn` with the system's JDK. Packages requiring a different Java version may fail during these steps.
- **POM-only artifacts:** Packages with packaging type `pom` (BOMs, parent POMs) have no JAR and are recorded with empty API columns.
