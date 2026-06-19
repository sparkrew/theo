# Mining Maven-Central 

Here we mine Maven-Central to quantify the usage of sensitive APIs by the packages uploaded.

## How it works

1. **Package Selection**: Maven Central currently has about 3 million packages.
   We select 2000 packages as the initial step. 
    - We first select the 1000 most widely used packages (sorted by download count).
    - Then we select 1000 packages randomly from the rest of the packages (using a fixed seed for reproducibility).
   
   For these 2000 packages we select the latest version available.

2. **JAR Download**: For these selected packages we download the source JARs from Maven Central.
   If a source JAR is not available, we fall back to the regular (bytecode) JAR.
   Downloaded JARs are cached on disk so re-runs don't re-download.

3. **Static Analysis**: We run the Theo static analyzer (`theo-static`) on each JAR to find the sensitive APIs used by these packages.
   The list of sensitive APIs considered here is the same list defined in `theo-commons/src/main/resources/sensitive_apis.json`.
   The analysis runs in parallel (configurable number of workers) and saves checkpoints after each package, so it can resume from where it stopped in case of failure.

4. **Results**:
    - A **CSV file** (`sensitive_api_usage.csv`) with 2000 rows (one per package) and 219 columns (one per sensitive API), containing `True`/`False` values showing whether each package uses each sensitive API.
    - For each package that has at least one sensitive API access, a **JSON file** in the `paths/` directory with the call paths from entry points to the sensitive APIs. Each path record contains:
      - The entry point method
      - The sensitive API method
      - The full call path between them

## Building

From the project root:

```bash
mvn package -pl package-miner -am -DskipTests
```

This produces `package-miner/target/package-miner-1.0-SNAPSHOT-jar-with-dependencies.jar`.

You also need the `theo-static` fat JAR, built the same way:

```bash
mvn package -pl theo-static -am -DskipTests
```

## Usage

```bash
java -jar package-miner-1.0-SNAPSHOT-jar-with-dependencies.jar mine \
  -o /path/to/output \
  -j /path/to/theo-static-1.0-SNAPSHOT-jar-with-dependencies.jar \
  -t 2000 \
  -w 4
```

### Options

| Option | Required | Default | Description |
|---|---|---|---|
| `-o, --output-dir` | Yes | — | Directory where all results are written |
| `-j, --theo-static-jar` | Yes | — | Path to the theo-static fat JAR |
| `-t, --total-packages` | No | 2000 | Total packages to analyze (half popular, half random) |
| `-w, --workers` | No | 1 | Number of parallel analysis workers |
| `--download-dir` | No | `<output-dir>/jars` | Where to store downloaded JARs |

### Output directory structure

```
output-dir/
  sensitive_api_usage.csv      # Main result: packages × sensitive APIs matrix
  selected_packages.json       # The 2000 selected packages (for reproducibility)
  checkpoint.json              # Tracks completed packages (for resumability)
  jars/                        # Downloaded JAR files
  reports/                     # Raw theo-static report JSONs (one per package)
  package-maps/                # Minimal package map files (needed by theo-static)
  paths/                       # Per-package call path JSONs (only for packages with sensitive API usage)
```

### Resuming after interruption

If the process is interrupted, simply re-run the same command. The tool will:
- Reuse the previously selected package list from `selected_packages.json`
- Skip packages already recorded in `checkpoint.json`
- Skip JAR downloads that already exist on disk

## Future work

- As the second phase, we will conduct a longitudinal analysis of the package sensitive API changes over the last 3 years, scanning all versions released in that period for packages that have sensitive API accesses.
