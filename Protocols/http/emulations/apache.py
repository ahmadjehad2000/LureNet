# emulations/apache.py

def apache_headers(server="Apache/2.4.1 (Unix)", x_powered_by="PHP/5.3.3"):
    return {
        "Server": server,
        "X-Powered-By": x_powered_by,
        "Content-Type": "text/html; charset=UTF-8",
        "Connection": "keep-alive",
    }
