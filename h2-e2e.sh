#!/bin/bash

# Database settings
DB_URL="jdbc:h2:tcp://localhost/~/test"
DB_USER="sa"
DB_PASS=""

read -r -a JVM_OPTS <<< "$JVM_ARGS"

# Start H2 server in the background
echo "Starting H2 server with JVM args: $JVM_ARGS"
java "${JVM_OPTS[@]}" -cp "$PROJECT_JAR_PATH" org.h2.tools.Server -tcp -tcpAllowOthers -ifNotExists > h2.log 2>&1 &
SERVER_PID=$!

# Give server a few seconds to start
echo "Waiting for H2 server (TCP, port 9092) to be ready..."
until (echo > /dev/tcp/localhost/9092) >/dev/null 2>&1; do
    sleep 3
done
echo "H2 server is ready."

# Run SQL commands using H2's shell tool
echo "Running SQL workload..."
java -cp "$PROJECT_JAR_PATH" org.h2.tools.Shell \
  -url "$DB_URL" \
  -user "$DB_USER" \
  -password "$DB_PASS" <<EOF
DROP TABLE IF EXISTS users;
CREATE TABLE users(id INT PRIMARY KEY, name VARCHAR(255));
INSERT INTO users VALUES(1, 'Alice');
INSERT INTO users VALUES(2, 'Bob');
UPDATE users SET name='Charlie' WHERE id=2;
SELECT * FROM users;
EXIT
EOF

# Stop the server
echo "Stopping H2 server..."
kill $SERVER_PID

echo "Done."
