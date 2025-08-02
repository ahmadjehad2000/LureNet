# emulations/__init__.py

import random
from .apache import apache_headers
from .nginx import nginx_headers
from .iis import iis_headers

EMULATIONS = [apache_headers, nginx_headers, iis_headers]

def get_emulator(request, mode="random"):
    if mode == "random":
        emulator_cls = random.choice(EMULATIONS)
    elif mode == "apache":
        emulator_cls = apache_headers
    elif mode == "nginx":
        emulator_cls = nginx_headers
    elif mode == "iis":
        emulator_cls = iis_headers
    else:
        raise ValueError("Unknown emulation mode")
    return emulator_cls(request)
