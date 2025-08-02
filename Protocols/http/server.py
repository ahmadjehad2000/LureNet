# server.py

from flask import Flask, request, render_template, send_from_directory
from http import HTTPStatus
import random
import ssl
import os
import threading
import sys

from emulations import apache, nginx, iis
from vulnerable_paths.wp_admin import wp_admin_bp
from fingerprints.tls_fingerprinter import log_tls_fingerprint
from utils.logger import log_request, log_warning

app = Flask(__name__)
app.register_blueprint(wp_admin_bp)

@app.before_request
def before_request():
    log_request(request)
    if request.scheme == "https":
        try:
            log_tls_fingerprint()  # Call without any input to use simulated data
        except Exception as e:
            print(f"[!] TLS fingerprinting error: {e}")

@app.route("/", methods=["GET", "POST"])
def index():
    headers = get_emulated_headers()
    if random.random() < 0.2:
        return "", HTTPStatus.SERVICE_UNAVAILABLE, headers
    elif random.random() < 0.1:
        return render_template("error.html"), HTTPStatus.INTERNAL_SERVER_ERROR, headers
    return render_template("index.html"), HTTPStatus.OK, headers

@app.route("/malware/<filename>")
def serve_malware(filename):
    return send_from_directory("decoys/malware", filename, mimetype="application/octet-stream")

@app.route("/favicon.ico")
def favicon():
    return "", HTTPStatus.NO_CONTENT

def get_emulated_headers():
    """Rotate between common server headers to confuse recon tools."""
    profiles = [
        apache.apache_headers,
        nginx.nginx_headers,
        iis.iis_headers,
    ]
    return random.choice(profiles)()

def run_http():
    try:
        app.run(host="0.0.0.0", port=80)
    except OSError as e:
        log_warning(f"HTTP server failed to start on port 80: {e}")

def run_https():
    cert_path = os.path.abspath("certs/server.crt")
    key_path = os.path.abspath("certs/server.key")

    if os.path.exists(cert_path) and os.path.exists(key_path):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=cert_path, keyfile=key_path)
        try:
            app.run(host="0.0.0.0", port=443, ssl_context=context)
        except PermissionError:
            log_warning("Permission denied: Port 443 requires root or CAP_NET_BIND_SERVICE.")
            print("[!] Run as sudo or bind to a higher port like 8443 for testing.")
        except OSError as e:
            log_warning(f"HTTPS server failed to start: {e}")
    else:
        print("[!] SSL certificate or key not found in 'certs/'. Skipping HTTPS.")

if __name__ == "__main__":
    threading.Thread(target=run_http, daemon=True).start()
    run_https()
