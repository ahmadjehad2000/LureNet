#!/bin/bash

set -e

echo "Creating HTTP directory structure..."

# Main directories
mkdir -p http/{middleware,core,analysis,routes,intelligence,utils,tests}

# Config directories
mkdir -p http/config/profiles

# Asset directories  
mkdir -p http/{templates,static/{css,js},decoys/{phishing,malware},certs,logs}

touch http/__init__.py
touch http/middleware/__init__.py
touch http/core/__init__.py
touch http/analysis/__init__.py
touch http/routes/__init__.py
touch http/intelligence/__init__.py
touch http/utils/__init__.py
touch http/tests/__init__.py

# Create placeholder files
touch http/main.py
touch http/middleware/intelligence.py
touch http/middleware/capture.py
touch http/middleware/deception.py
touch http/core/intelligence.py
touch http/core/response_engine.py
touch http/core/correlation.py
touch http/analysis/pattern_detector.py
touch http/analysis/tool_fingerprinter.py
touch http/analysis/payload_analyzer.py
touch http/analysis/tls_analyzer.py
touch http/routes/vulnerable_paths.py
touch http/routes/phishing.py
touch http/routes/file_server.py
touch http/intelligence/exporter.py
touch http/intelligence/storage.py
touch http/intelligence/dashboard.py
touch http/utils/logger.py
touch http/utils/helpers.py
touch http/config/profiles/apache.yaml
touch http/config/profiles/nginx.yaml
touch http/config/profiles/iis.yaml
touch http/config/vulnerabilities.yaml
touch http/config/intelligence.yaml
touch http/tests/test_http.py

echo "Structure created successfully!"
echo "Directory tree:"
tree http/ || find http/ -type d | sort
