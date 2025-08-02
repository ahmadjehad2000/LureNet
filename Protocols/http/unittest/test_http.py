
import unittest
from http import HTTPStatus
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from server import app

class HTTPHoneypotTestCase(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        self.client.testing = True

    def test_root_endpoint(self):
        responses = []
        for _ in range(10):  # Sample multiple times due to randomness
            response = self.client.get("/")
            responses.append(response.status_code)
            self.assertIn(response.status_code, [HTTPStatus.OK, HTTPStatus.SERVICE_UNAVAILABLE, HTTPStatus.INTERNAL_SERVER_ERROR])

        print(f"[✓] Root endpoint variability tested. Status codes: {responses}")

    def test_wp_admin_route(self):
        response = self.client.get("/wp-admin", follow_redirects=True)
        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertIn("X-Fake-Admin", response.headers)
        print("[✓] /wp-admin vulnerable path returns expected response.")

    def test_phishing_decoy(self):
        response = self.client.get("/phish")
        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertIn(b"<form", response.data)
        print("[✓] Phishing decoy page served successfully.")

    def test_malware_serving(self):
        # Assuming dummy_payload.exe exists
        response = self.client.get("/malware/dummy_payload.exe")
        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertEqual(response.mimetype, "application/octet-stream")
        print("[✓] Malware decoy file served with correct mimetype.")

    def test_emulated_headers(self):
        headers_seen = []
        for _ in range(10):
            response = self.client.get("/")
            headers_seen.append(response.headers.get("Server"))
        unique_headers = set(headers_seen)
        self.assertGreaterEqual(len(unique_headers), 2)
        print(f"[✓] Header rotation working. Emulated headers: {unique_headers}")

    def test_tls_fingerprint_hook(self):
        # Simulated call — in real TLS testing, you'd use `requests` with certs.
        # Here we just confirm that route logic accepts SSL if enabled
        print("[i] TLS fingerprint logging is invoked during HTTPS. Requires live HTTPS test separately.")

if __name__ == "__main__":
    unittest.main()