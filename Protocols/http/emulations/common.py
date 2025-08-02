# emulations/common.py

from flask import make_response
import random
import time

class EmulationBase:
    def __init__(self, request):
        self.request = request

    def delay_response(self):
        time.sleep(random.uniform(0.1, 0.5))

    def get_headers(self):
        raise NotImplementedError

    def generate_response(self, content, status=200, content_type="text/html"):
        self.delay_response()
        response = make_response(content, status)
        for k, v in self.get_headers().items():
            response.headers[k] = v
        response.headers["Content-Type"] = content_type
        return response
