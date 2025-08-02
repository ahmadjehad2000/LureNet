# vulnerable_paths/wp_admin.py

from flask import Blueprint, request, render_template, make_response
from http import HTTPStatus
from utils.logger import log_request
from emulations.apache import apache_headers
import random
import os

wp_admin_bp = Blueprint("wp_admin", __name__, url_prefix="/wp-admin")
wp_admin_route = wp_admin_bp

def fallback_login_page():
    """Simple inline fallback in case wp_login.html template is missing."""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>WordPress › Login</title>
        <meta charset="UTF-8">
        <meta name="robots" content="noindex,nofollow">
    </head>
    <body class="login">
        <div id="login">
            <h1><a href="#">WordPress</a></h1>
            <form name="loginform" id="loginform" action="/wp-admin/" method="post">
                <p><label>Username<br><input type="text" name="log" size="20"></label></p>
                <p><label>Password<br><input type="password" name="pwd" size="20"></label></p>
                <p class="submit"><input type="submit" value="Log In"></p>
            </form>
        </div>
    </body>
    </html>
    """

@wp_admin_bp.route("/", methods=["GET", "POST"])
@wp_admin_bp.route("/", methods=["GET", "POST"])
def wp_admin_login():
    log_request(request, tag="wp-admin")
    headers = apache_headers(server="Apache/2.4.1 (Unix)", x_powered_by="PHP/5.3.3")
    headers["X-Fake-Admin"] = "login-interface"

    if request.method == "POST":
        username = request.form.get("log", "")
        password = request.form.get("pwd", "")
        if username and password:
            print(f"[WP-ADMIN] Login attempt: {username}:{password}")
        return render_template("error.html"), HTTPStatus.UNAUTHORIZED, headers

    if random.random() < 0.1:
        return "", HTTPStatus.SERVICE_UNAVAILABLE, headers

    return render_template("wp_login.html"), HTTPStatus.OK, headers

@wp_admin_bp.route("/plugin-editor.php", methods=["GET"])
def fake_plugin_editor():
    log_request(request, tag="wp-admin/plugin-editor")
    headers = apache_headers()
    html = """
    <html>
    <head><title>Plugin Editor</title></head>
    <body>
        <h1>Edit Plugin: vulnerable-plugin/vuln.php</h1>
        <textarea rows="20" cols="80">// Simulated vulnerable code here...</textarea>
        <br><button>Update File</button>
    </body>
    </html>
    """
    return html, HTTPStatus.OK, headers

@wp_admin_bp.route("/admin-ajax.php", methods=["POST"])
def fake_admin_ajax():
    log_request(request, tag="wp-admin/ajax")
    headers = apache_headers()
    return ('{"success": false, "data": "invalid_nonce"}', HTTPStatus.OK, headers)
