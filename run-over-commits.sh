#!/bin/bash

set -e
set -o pipefail

# Load settings
SCRIPT_DIR="$(dirname "$(realpath "$0")")"
source "$SCRIPT_DIR"/settings.conf

mkdir -p "$REPORTS_DIR"

cd "$PROJECT_ROOT_DIR"

START_COMMIT="296cf4bb80553607d15544a96bf8bf861de7bc6a"

# Get short date format (YYYY-MM-DD)
START_DATE=$(git show -s --format=%cd --date=short "$START_COMMIT")
echo "Start date of commit $START_COMMIT is $START_DATE"

# Get all commits in that range
COMMITS=()
while IFS= read -r line; do
  echo "Found commit: $line"
  COMMITS+=("$line")
done < <(git log --since="2024-07-28" --until="2025-07-28" --format="%H" --reverse)

echo "Total: ${#COMMITS[@]}"

for COMMIT in "${COMMITS[@]}"; do
    echo "Processing commit $COMMIT"

    git checkout "$COMMIT"

    # Extract version from pom.xml in web module
    VERSION=$(xmllint --xpath "/*[local-name()='project']/*[local-name()='parent']/*[local-name()='version']/text()" "$PROJECT_SOURCE_CODE_PATH/pom.xml")

    if [ -z "$VERSION" ]; then
        echo "Could not find version in pom.xml for commit $COMMIT. Skipping..."
        continue
    fi

    # Update PROJECT_JAR_PATH in settings.conf
    sed -i.bak -E "s|^PROJECT_JAR_PATH=.*|PROJECT_JAR_PATH=\"$PROJECT_SOURCE_CODE_PATH/target/pdfbox-app-$VERSION.jar\"|" "$SCRIPT_DIR/settings.conf"

    # Clean build
    cd "$PROJECT_ROOT_DIR"
    mvn clean install -DskipTests

    # Run analysis and capture logs
    COMMIT_REPORT_DIR="$REPORTS_DIR/$COMMIT"
    mkdir -p "$COMMIT_REPORT_DIR"

    LOG_FILE="$COMMIT_REPORT_DIR/analysis.log"

    bash "$ANALYSIS_SCRIPT" > "$LOG_FILE" 2>&1

    cd "$PROJECT_SOURCE_CODE_PATH"

    # Copy output reports to commit folder
    for file in theo-*-report.json theo-*-report.old.json *.diff *.patch; do
        if [ -f "$file" ]; then
            cp "$file" "$COMMIT_REPORT_DIR/"
        fi
    done
    echo "Finished commit $COMMIT"
done

# Restore original state
git checkout trunk
