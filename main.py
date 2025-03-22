from flask import Flask
from flask import render_template
from flask import request
from flask import redirect
from flask import url_for
from flask import session
from flask_session import Session
import pyotp
import user_management as dbHandler
import qrcode
from flask import flash
import logging

import bcrypt

from flask_wtf.csrf import CSRFProtect


app = Flask(__name__)
app.secret_key='aaabbbddss'
app.config["SESSION_PERMAMENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_FILE_DIR"] = "./flask_session_cache"
Session(app)
csrf = CSRFProtect(app)

@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'  # Protects against clickjacking
    response.headers['Content-Security-Policy'] = "nosniff"  # CSP clickjacking protection
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response

@app.route("/success.html", methods=["POST", "GET", "PUT", "PATCH", "DELETE"])
def addFeedback():
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        return checkurl(url)
    if request.method == "POST":
        feedback = request.form["feedback"]
        dbHandler.insertFeedback(feedback)
        dbHandler.listFeedback()
        return render_template("/success.html", state=True, value="Back")
    else:
        dbHandler.listFeedback()
        return render_template("/success.html", state=True, value="Back")

@app.route("/signup.html", methods=["POST", "GET", "PUT", "PATCH", "DELETE"])
def signup():
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        return checkurl(url)
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        DoB = request.form["dob"]
        dbHandler.insertUser(username, password, DoB)
        return render_template("/index.html")
    else:
        return render_template("/signup.html")


@app.route("/index.html", methods=["POST", "GET", "PUT", "PATCH", "DELETE"])
@app.route("/", methods=["POST", "GET"])
def home():
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        return checkurl(url)
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = dbHandler.retrieveUsers(username, password)

        if user:
            session['username'] = username
            session['two_factor_key'] = user[4]
            key = session.get('two_factor_key')
            uri = pyotp.totp.TOTP(key).provisioning_uri(name=session.get('username'), issuer_name='2fa App')
            qrcode.make(uri).save("static/newCode.png")
            return render_template("/2fa.html")
        else:
            flash('Invalid username or password!', 'error')
            return render_template("/index.html")
    else:
        return render_template("/index.html")

ALLOWED_PATHS = {"/index.html", "/signup.html", "/success.html", "/2fa.html"}

def checkurl(url):
    # Ensure it's a valid path (prevent open redirects)
    if url in ALLOWED_PATHS:
        return redirect(url, code=302)
    # Redirect to home if URL is invalid
    return redirect(url_for("home"))

@app.route("/2fa.html", methods=["POST", "GET"])
def two_factor():
    if request.method == "POST":
            code = request.form["code"]
            key = session.get('two_factor_key')
            print(key)
            if key is None:
                return render_template("/2fa.html", error="No Key!")
            if pyotp.TOTP(key).verify(code):
                return render_template("/success.html", value=session.get('username'), state=True)
            else:
                return render_template("/2fa.html", error="Invalid Code")
    else:
        key = session.get('two_factor_key')
        uri = pyotp.totp.TOTP(key).provisioning_uri(name=session.get('username'), issuer_name='2fa App')
        qrcode.make(uri).save("static/newCode.png")
        return render_template("/2fa.html")


if __name__ == "__main__":
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
    app.run(debug=False, host="0.0.0.0", port=5000)
