# utils/logger.py

import logging
import os
from logging.handlers import RotatingFileHandler
from datetime import datetime, timezone

LOG_DIR = "logs"
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

LOG_FILE = os.path.join(LOG_DIR, "http_honeypot.log")

def setup_logger(name="honeypot", level=logging.INFO):
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.propagate = False

    if not logger.handlers:
        formatter = logging.Formatter(
            fmt="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )

        file_handler = RotatingFileHandler(LOG_FILE, maxBytes=5*1024*1024, backupCount=5)
        file_handler.setFormatter(formatter)

        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(formatter)

        logger.addHandler(file_handler)
        logger.addHandler(stream_handler)

    return logger

# Global logger instance
logger = setup_logger()


def log_request(request, extra_info=None):
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    method = request.method
    path = request.path
    agent = request.headers.get("User-Agent", "Unknown")
    timestamp = datetime.now(timezone.utc).isoformat()

    ip_details = get_ip_info(ip)
    logger.info(f"[HTTP] {ip} ({ip_details}) {method} {path} UA=\"{agent}\"")

    if extra_info:
        logger.info(f"[EXTRA] {extra_info}")



def get_ip_info(ip):
    try:
        if ip.startswith("127.") or ip == "::1":
            return "Localhost"
        resp = requests.get(f"http://ip-api.com/json/{ip}?fields=country,regionName,city,org,as,query", timeout=2)
        if resp.status_code == 200:
            data = resp.json()
            return f"{data.get('country', '')}, {data.get('regionName', '')}, {data.get('city', '')} | Org: {data.get('org', '')} | AS: {data.get('as', '')}"
    except Exception as e:
        logger.warning(f"[GeoIP] Failed to lookup {ip}: {e}")
    return "Unknown"

def log_event(event_type, message):
    logger.info(f"[{event_type}] {message}")


def log_warning(message):
    logger.warning(message)


def log_error(message):
    logger.error(message)
