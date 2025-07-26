#!/bin/bash

set -e
set -o pipefail

REPO_DIR="/Users/yogyagamage/Documents/KTH/theo/prod/graphhopper-new"
WEB_DIR="$REPO_DIR/web"
SETTINGS_CONF="/Users/yogyagamage/Documents/UdeM/theo/settings.conf"
ANALYSIS_SCRIPT="/Users/yogyagamage/Documents/UdeM/theo/run-theo-analysis.sh"
REPORTS_DIR="/Users/yogyagamage/Documents/UdeM/theo-reports/all-auto"

mkdir -p "$REPORTS_DIR"

cd "$REPO_DIR"

# Get commits from the last 6 months
COMMITS=$(git log --since="6 months ago" --format="%H" --reverse)

for COMMIT in $COMMITS; do
    echo "Processing commit $COMMIT"

    git checkout "$COMMIT"

    # Extract version from pom.xml in web module
    VERSION=$(xmllint --xpath "/*[local-name()='project']/*[local-name()='version']/text()" "$WEB_DIR/pom.xml")

    if [ -z "$VERSION" ]; then
        echo "Could not find version in pom.xml for commit $COMMIT. Skipping..."
        continue
    fi

    # Update PROJECT_JAR_PATH in settings.conf
    sed -i.bak -E "s|^PROJECT_JAR_PATH=.*|PROJECT_JAR_PATH=\"$WEB_DIR/target/graphhopper-web-$VERSION.jar\"|" "$SETTINGS_CONF"

    # Clean build
    cd "$REPO_DIR"
    mvn clean install -DskipTests

    # Run analysis and capture logs
    COMMIT_REPORT_DIR="$REPORTS_DIR/$COMMIT"
    mkdir -p "$COMMIT_REPORT_DIR"

    LOG_FILE="$COMMIT_REPORT_DIR/analysis.log"

    bash "$ANALYSIS_SCRIPT" > "$LOG_FILE" 2>&1

    # Copy output reports to commit folder
    for file in theo-*-report.json theo-*-report.old.json *.patch; do
        if [ -f "$file" ]; then
            cp "$file" "$COMMIT_REPORT_DIR/"
        fi
    done

    echo "Finished commit $COMMIT"
done

# Restore original state
git checkout master
