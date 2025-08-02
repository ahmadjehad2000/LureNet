# emulations/nginx.py

def nginx_headers(server="nginx/1.18.0", x_powered_by="PHP/7.4.3"):
    return {
        "Server": server,
        "X-Powered-By": x_powered_by,
        "Content-Type": "text/html; charset=UTF-8",
        "Connection": "keep-alive",
    }
