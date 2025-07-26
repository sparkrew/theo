#!/bin/bash

set -e
set -o pipefail

source ./settings.conf

ORIGINAL_DIR=$(pwd)

# Move to project source directory
cd "$PROJECT_SOURCE_CODE_PATH" || { echo "Error: Failed to cd into $PROJECT_SOURCE_CODE_PATH"; exit 1; }

cd ../
mvn clean install -DskipTests
cd web

# Run Theo Preprocessor
mvn io.github.chains-project:theo-preprocessor-maven-plugin:1.0-SNAPSHOT:preprocess \
    -DoutputFile="$PACKAGE_MAP_OUTPUT_PATH"

# This is the other script to generate the AOP XML. We have to go back to the original directory to run that.
cd "$ORIGINAL_DIR"
source ./generate_aop_xml.sh

# Move to project source directory
cd "$PROJECT_SOURCE_CODE_PATH" || { echo "Error: Failed to cd into $PROJECT_SOURCE_CODE_PATH"; exit 1; }

# Backup original jar
cp "$THEO_JAVA_AGENT_JAR_PATH" "${THEO_JAVA_AGENT_JAR_PATH}.bak"

# Create temp workspace
TMP_DIR=$(mktemp -d)
unzip -q "$THEO_JAVA_AGENT_JAR_PATH" -d "$TMP_DIR"

# Inject aop.xml
mkdir -p "$TMP_DIR/META-INF"
cp "$AOP_XML_PATH" "$TMP_DIR/META-INF/aop.xml"

# Rebuild jar with aop.xml
pushd "$TMP_DIR" >/dev/null
zip -qr "$THEO_JAVA_AGENT_JAR_PATH" ./*
popd >/dev/null

# Convert string booleans to lowercase to handle TRUE/true/False/etc.
NOISE_REMOVAL=$(echo "$NOISE_REMOVAL" | tr '[:upper:]' '[:lower:]')
WRITE_DIFF_TO_FILE=$(echo "$WRITE_DIFF_TO_FILE" | tr '[:upper:]' '[:lower:]')

# Backup reports from previous version if they exist
OLD_STATIC_REPORT_CONTENT=""
OLD_DYNAMIC_REPORT_CONTENT=""

if [[ -f "theo-static-report.json" ]]; then
  OLD_STATIC_REPORT_CONTENT=$(cat theo-static-report.json)
  cp theo-static-report.json theo-static-report.old.json
fi

if [[ -f "theo-test-report.json" ]]; then
  OLD_DYNAMIC_REPORT_CONTENT=$(cat theo-test-report.json)
  cp theo-test-report.json theo-test-report.old.json
fi

# Common JVM args
JVM_ARGS="--add-opens=java.base/java.lang=ALL-UNNAMED \
--add-opens=java.base/java.util=ALL-UNNAMED \
-XX:StartFlightRecording=name=jfrTestRecording,settings=$JFR_SETTINGS_FILE_PATH,filename=$JFR_REPORT_PATH \
-javaagent:$THEO_JAVA_AGENT_JAR_PATH"

# Run test or exec based on MODE
if [ "$MODE" = "test" ]; then
  echo "Running in TEST mode..."
  mvn test -Dtheo.argLine="$JVM_ARGS"
else
  echo "Running in WORKLOAD mode..."
  echo "Setting up Python virtual environment..."

    VENV_DIR=".venv"
    PYTHON_BIN="/opt/homebrew/opt/python@3.13/bin/python3.13"

    if [ ! -d "$VENV_DIR" ]; then
      $PYTHON_BIN -m venv "$VENV_DIR"
    fi

    source "$VENV_DIR/bin/activate"

    echo "Installing required Python packages..."
    pip install --quiet psutil

    echo "Running e2e workload using $E2E_PATH..."
    python "$E2E_PATH"

    deactivate
fi

# Run Static Analyzer
java -jar "$THEO_STATIC_ANALYZER_JAR_PATH" process \
  -j "$PROJECT_JAR_PATH" \
  -p "$PROJECT_PACKAGE_NAME" \
  -m "$PACKAGE_MAP_OUTPUT_PATH"

# Run Dynamic Analyzer (test-exec)
java -jar "$THEO_DYNAMIC_ANALYZER_JAR_PATH" process \
  -j "$JFR_REPORT_PATH" \
  -p "$PROJECT_PACKAGE_NAME" \
  -m "$PACKAGE_MAP_OUTPUT_PATH" \
  -n "$NOISE_REMOVAL"

# Compare with reports from the previous version if they exist
EXIT_CODE=0

if [[ -n "$OLD_STATIC_REPORT_CONTENT" ]]; then
  if ! diff -u theo-static-report.old.json theo-static-report.json > static_diff.patch; then
    echo -e "\n Dependency privileges have changed compared to the previous version according to the static analysis!"
    cat static_diff.patch | sed 's/^-/\x1b[31m-/;s/^+/\x1b[32m+/;s/$/\x1b[0m/'
    [[ "$WRITE_DIFF_TO_FILE" == "true" ]] && cp static_diff.patch theo-static-report.diff
    EXIT_CODE=1
  else
    echo "Dependency privileges have not changed since the last version according to the static analysis!"
  fi
fi

if [[ -n "$OLD_DYNAMIC_REPORT_CONTENT" ]]; then
  if ! diff -u theo-test-report.old.json theo-test-report.json > dynamic_diff.patch; then
    echo -e "\n Dependency privileges have changed compared to the previous version according to the dynamic analysis!"
    cat dynamic_diff.patch | sed 's/^-/\x1b[31m-/;s/^+/\x1b[32m+/;s/$/\x1b[0m/'
    [[ "$WRITE_DIFF_TO_FILE" == "true" ]] && cp dynamic_diff.patch theo-test-report.diff
    EXIT_CODE=1
  else
    echo "Dependency privileges have not changed since the last version according to the dynamic analysis!"
  fi
fi

cd "$ORIGINAL_DIR"
# Clean up and restore original jar
mv "${THEO_JAVA_AGENT_JAR_PATH}.bak" "$THEO_JAVA_AGENT_JAR_PATH"
rm -rf "$TMP_DIR"

exit $EXIT_CODE
