# emulations/iis.py

def iis_headers(server="Microsoft-IIS/10.0", x_powered_by="ASP.NET"):
    return {
        "Server": server,
        "X-Powered-By": x_powered_by,
        "Content-Type": "text/html; charset=UTF-8",
        "Connection": "keep-alive",
    }
