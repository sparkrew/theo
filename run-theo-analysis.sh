#!/bin/bash

set -e
set -o pipefail

SCRIPT_DIR="$(dirname "$(realpath "$0")")"
source "$SCRIPT_DIR"/settings.conf

# Move to project source directory
cd "$PROJECT_SOURCE_CODE_PATH" || { echo "Error: Failed to cd into $PROJECT_SOURCE_CODE_PATH"; exit 1; }

# Run Theo Preprocessor
mvn io.github.chains-project:theo-preprocessor-maven-plugin:1.0-SNAPSHOT:preprocess \
    -DoutputFile="$PACKAGE_MAP_OUTPUT_PATH"

# This is the other script to generate the AOP XML. We have to go back to the original directory to run that.
cd "$SCRIPT_DIR"
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
  echo "Running e2e workload..."
  pwd
  mvn exec:exec \
    -Dexec.executable=java \
    -Dexec.args="\
  --add-opens=java.base/java.lang=ALL-UNNAMED \
  --add-opens=java.base/java.util=ALL-UNNAMED \
  -XX:StartFlightRecording=name=jfrTestRecording,settings=/Users/yogyagamage/Documents/UdeM/theo/settings.jfc,filename=/Users/yogyagamage/Documents/KTH/theo/prod/pdfbox/app/jfr-report1.jfr \
  -javaagent:/Users/yogyagamage/Documents/UdeM/theo/theo-agent/target/theo-agent-1.0-SNAPSHOT-jar-with-dependencies.jar \
  -cp $PROJECT_JAR_PATH:. \
  RunAllOperations"
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
if [[ -n "$OLD_STATIC_REPORT_CONTENT" ]]; then
  diff -u theo-static-report.old.json theo-static-report.json > static_diff.patch || true
  [[ "$WRITE_DIFF_TO_FILE" == "true" ]] && cp static_diff.patch theo-static-report.diff
fi

if [[ -n "$OLD_DYNAMIC_REPORT_CONTENT" ]]; then
  diff -u theo-test-report.old.json theo-test-report.json > dynamic_diff.patch || true
  [[ "$WRITE_DIFF_TO_FILE" == "true" ]] && cp dynamic_diff.patch theo-test-report.diff
fi

cd "$SCRIPT_DIR"
# Clean up and restore original jar
mv "${THEO_JAVA_AGENT_JAR_PATH}.bak" "$THEO_JAVA_AGENT_JAR_PATH"
rm -rf "$TMP_DIR"
