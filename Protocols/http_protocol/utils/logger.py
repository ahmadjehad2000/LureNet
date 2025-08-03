import logging

class SimpleLogger:
    def info(self, msg): print(f"INFO: {msg}")
    def warning(self, msg): print(f"WARNING: {msg}")
    def critical(self, msg): print(f"CRITICAL: {msg}")
    def error(self, msg): print(f"ERROR: {msg}")

def setup_logger(name=None):
    return SimpleLogger()
