#!/bin/bash
BASE_URL="http://localhost:8080"

echo "🚀 Starting attack simulation..."

# Common paths scan
for path in admin wp-admin phpmyadmin login administrator config.php .env; do
    echo "Scanning: /$path"
    curl -s "$BASE_URL/$path" > /dev/null
    sleep 0.5
done

# SQL injection attempts
for payload in "' OR 1=1--" "'; DROP TABLE users;--" "UNION SELECT * FROM passwords"; do
    echo "SQL injection: $payload"
    curl -s "$BASE_URL/search?q=$payload" > /dev/null
    sleep 0.5
done

echo "✅ Attack simulation complete"
