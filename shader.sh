#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(dirname "$(realpath "$0")")"
source "$SCRIPT_DIR"/settings.conf

POM_FILE="/Users/yogyagamage/Documents/KTH/theo/prod/graphhopper-new/web/pom.xml"

cd "$PROJECT_SOURCE_CODE_PATH" || { echo "Error: Failed to cd into $PROJECT_SOURCE_CODE_PATH"; exit 1; }

# --- Step 1: Run the Maven plugin to generate package mapping ---
echo "[INFO] Running theo-preprocessor-maven-plugin..."
mvn io.github.chains-project:theo-preprocessor-maven-plugin:1.0-SNAPSHOT:preprocess \
    -DoutputFile="$PACKAGE_MAP_OUTPUT_PATH"

if [[ ! -f "$PACKAGE_MAP_OUTPUT_PATH" ]]; then
  echo "[ERROR] Output file $PACKAGE_MAP_OUTPUT_PATH not found!"
  exit 1
fi

# --- Step 4: Insert includes + relocations into pom.xml ---
echo "[INFO] Updating pom.xml with maven-shade-plugin includes and relocations..."

# 1. Collect conflicts
CONFLICTS=$(jq -r '
  to_entries[]
  | select(.value | length > 1)
  | .key
' "$PACKAGE_MAP_OUTPUT_PATH")

DEPS=$(jq -r '
  to_entries[]
  | select(.value | length > 1)
  | .value[]
' "$PACKAGE_MAP_OUTPUT_PATH" | sort -u)

# 2. Build includes
INCLUDE_LINES=$(echo "$DEPS" | sed 's/^/          <include>/;s/$/<\/include>/')

# 3. Build relocations
RELOCATE_LINES=$(echo "$CONFLICTS" | while read -r pkg; do
  cat <<EOF
          <relocation>
            <pattern>$pkg</pattern>
            <shadedPattern>com.myproject.shaded.$pkg</shadedPattern>
          </relocation>
EOF
done)

# 4. Create block into a temp file
BLOCK_FILE=$(mktemp)
cat > "$BLOCK_FILE" <<EOF
        <includes>
$INCLUDE_LINES
        </includes>
        <relocations>
$RELOCATE_LINES
        </relocations>
EOF

# 5. Inject block after <configuration> inside maven-shade-plugin
TMPFILE=$(mktemp)
awk -v blk="$BLOCK_FILE" '
  /<artifactId>maven-shade-plugin<\/artifactId>/ { inPlugin=1 }
  inPlugin && /<configuration>/ {
    print
    system("cat " blk)
    inPlugin=0
    next
  }
  { print }
' "$POM_FILE" > "$TMPFILE"
mv "$TMPFILE" "$POM_FILE"

# --- Step 5: Run the Maven plugin again ---
echo "[INFO] Running theo-preprocessor-maven-plugin again..."
mvn io.github.chains-project:theo-preprocessor-maven-plugin:1.0-SNAPSHOT:preprocess \
    -DoutputFile="$PACKAGE_MAP_OUTPUT_PATH"

echo "[INFO] Done!"
