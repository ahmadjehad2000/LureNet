# fingerprints/tls_fingerprinter.py

import hashlib
import datetime
from utils.logger import log_event

def log_tls_fingerprint(client_hello_data: dict = None) -> str:
    
    #Simulates TLS fingerprint logging. Uses mock data if real Client Hello is unavailable.
    

    # Use default mock data if none provided
    if not isinstance(client_hello_data, dict):
        client_hello_data = {
            "version": 771,
            "cipher_suites": [4865, 4866, 49195],
            "extensions": [0, 11, 10, 35],
            "elliptic_curves": [29, 23, 24],
            "ec_point_formats": [0]
        }

    ja3_components = [
        str(client_hello_data.get("version", "771")),
        "-".join(map(str, client_hello_data.get("cipher_suites", [4865, 4866]))),
        "-".join(map(str, client_hello_data.get("extensions", [0, 11, 10]))),
        "-".join(map(str, client_hello_data.get("elliptic_curves", [29, 23]))),
        "-".join(map(str, client_hello_data.get("ec_point_formats", [0])))
    ]
    ja3_string = ",".join(ja3_components)
    ja3_hash = hashlib.md5(ja3_string.encode()).hexdigest()

    timestamp = datetime.datetime.utcnow().isoformat()
    log_event("TLS", f"[TLS-FP] {timestamp} :: JA3: {ja3_string} :: Hash: {ja3_hash}")

    return ja3_hash
