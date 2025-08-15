#!/bin/bash
set -e

if ! grep -q "<id>workload</id>" pom.xml; then
    echo "Adding 'workload' profile to pom.xml..."

    ed -s pom.xml <<'EOF'
/<\/project>/i
    <profiles>
        <profile>
            <id>workload</id>
            <build>
                <plugins>
                    <plugin>
                        <groupId>org.springframework.boot</groupId>
                        <artifactId>spring-boot-maven-plugin</artifactId>
                        <configuration>
                            <jvmArguments>
                                --add-opens=java.base/java.lang=ALL-UNNAMED
                                --add-opens=java.base/java.util=ALL-UNNAMED
                                -XX:StartFlightRecording=name=jfrTestRecording,settings=/Users/yogyagamage/Documents/UdeM/theo/settings.jfc,filename=/Users/yogyagamage/Documents/KTH/theo/prod/DemoSite/api/jfr-report1.jfr
                                -javaagent:/Users/yogyagamage/Documents/UdeM/theo/theo-agent/target/theo-agent-1.0-SNAPSHOT-jar-with-dependencies.jar
                            </jvmArguments>
                        </configuration>
                    </plugin>
                </plugins>
            </build>
        </profile>
    </profiles>
.
w
q
EOF
else
    echo "'workload' profile already exists in pom.xml."
fi

# Start API in background with workload profile
echo "Starting API with workload profile..."
mvn spring-boot:run -Pworkload > api.log 2>&1 &
PID_API=$!

# Wait until API port is open
HOST_API="http://localhost:8082"
echo "Waiting for API to be ready..."
until (echo > /dev/tcp/localhost/8082) >/dev/null 2>&1; do
    sleep 5
done
echo "API is up."

#####################################
# Workload: Example API calls
#####################################
echo "Fetching categories..."
curl -X GET --header 'Accept: application/xml' "$HOST_API/api/v1/catalog/categories?limit=20"

echo "Creating a new customer..."
curl -X POST --header 'Content-Type: application/json' --header 'Accept: application/xml' -d '{
   "customerAttributes": [
     {
       "customerId": 0,
       "id": 0,
       "name": "tom",
       "value": "string"
     }
   ],
   "emailAddress": "tom@gmail.com",
   "firstName": "tom",
   "id": 0,
   "lastName": "tom",
   "registered": true
 }' "$HOST_API/api/v1/customer"

echo "Fetching cart for the customer..."
curl -X GET --header 'Accept: application/xml' "$HOST_API/api/v1/cart?customerId=0"

echo "Adding item to cart..."
curl -X GET --header 'Accept: application/xml' "$HOST_API/api/v1/cart/configure/1"

#####################################
echo "Workload complete."

# Stop API
kill $PID_API
echo "API stopped."
