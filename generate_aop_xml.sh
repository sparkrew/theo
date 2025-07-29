#!/usr/bin/env bash

# Load settings
SCRIPT_DIR="$(dirname "$(realpath "$0")")"
source "$SCRIPT_DIR"/settings.conf

# Required variables from settings
: "${PROJECT_PACKAGE_NAME:?Need PROJECT_PACKAGE_NAME in settings}"
: "${PACKAGE_MAP_OUTPUT_PATH:?Need PACKAGE_MAP_OUTPUT_PATH in settings}"

# Output file
AOP_XML_PATH="aop.xml"

# The beginning of the XML
cat > "$AOP_XML_PATH" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<aspectj>
    <aspects>
        <aspect name="io.github.chains_project.theo.theo_agent.agent.SensitiveApiAspect"/>
    </aspects>

    <weaver options="-Xset:weaveJavaxPackages=true -Xlint:ignore">

        <include within="${PROJECT_PACKAGE_NAME}.*"/>
EOF

# Append third-party packages from JSON
jq -r 'keys[] | select(test("-") | not)' "$PACKAGE_MAP_OUTPUT_PATH" | while read -r pkg; do
    echo "        <include within=\"${pkg}.*\"/>" >> "$AOP_XML_PATH"
done

# Append fixed includes and excludes
cat >> "$AOP_XML_PATH" <<'EOF'

        <include within="io.github.chains_project.theo.theo_agent.agent.SensitiveApiAspect"/>
        <!-- JDK classes that contain sensitive APIs -->
        <include within="java.util.Properties"/>
        <include within="javax.crypto.*"/>
        <include within="java.sql.*"/>
        <include within="javax.sql.*"/>
        <include within="java.net.URI"/>
        <include within="javax.servlet.http.HttpServletRequest"/>
        <include within="javax.servlet.http.HttpServletResponse"/>
        <include within="jakarta.servlet.ServletContext"/>
        <include within="java.net.HttpsURLConnection"/>
        <include within="java.net.HttpURLConnection"/>
        <include within="java.net.JarURLConnection"/>
        <include within="jakarta.servlet.http.HttpServletRequest"/>
        <include within="jakarta.servlet.http.HttpServletResponse"/>
        <include within="java.net.http.HttpClient"/>
        <include within="javax.net.ssl.HttpsURLConnection"/>
        <include within="javax.security.auth.login.LoginContext"/>
        <include within="javax.servlet.http.Cookie"/>
        <include within="javax.servlet.http.HttpServlet"/>
        <include within="javax.servlet.http.HttpServletRequestWrapper"/>
        <include within="javax.servlet.http.HttpSession"/>
        <include within="java.net.http.WebSocket.Builder"/>
        <include within="java.net.http.WebSocket"/>
        <include within="java.nio.channels.ServerSocketChannel"/>
        <include within="java.rmi.server.RMISocketFactory"/>
        <include within="java.net.URLDecoder"/>
        <include within="java.net.URLEncoder"/>
        <include within="java.nio.charset.CharsetDecoder"/>
        <include within="java.nio.charset.CharsetEncoder"/>
        <include within="java.util.Base64.Encoder"/>
        <include within="java.util.Base64.Decoder"/>
        <include within="javax.websocket.Decoder.Binary"/>
        <include within="javax.websocket.Decoder.Text"/>
        <include within="java.beans.PropertyDescriptor"/>
        <include within="java.util.ServiceLoader"/>
        <include within="javax.script.ScriptEngine"/>
        <include within="javax.script.ScriptEngineFactory"/>
        <include within="javax.script.ScriptEngineManager"/>

        <!-- classes that might cause issues -->
        <exclude within="java.lang.String"/>
        <exclude within="java.lang.Object"/>
        <exclude within="java.lang.Thread"/>
        <exclude within="java.util.*"/>
        <exclude within="org.aspectj.*"/>
        <exclude within="jdk.jfr.*"/>
    </weaver>
</aspectj>
EOF

export AOP_XML_PATH="$(realpath "$AOP_XML_PATH")"
