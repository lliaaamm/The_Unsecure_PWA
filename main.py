from flask import Flask
from flask import render_template
from flask import request
from flask import redirect
from flask import url_for
from flask import session
import user_management as dbHandler
import pyqrcode
import pyotp
import os
import base64
from io import BytesIO


app = Flask(__name__)
app.secret_key = 'my_secret_key'

@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'  # Protects against clickjacking
    response.headers['Content-Security-Policy'] = (
        "frame-ancestors 'self'; "
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://trusted-scripts.example.com; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https://trusted-images.example.com; "
        "connect-src 'self' https://api.example.com"
    )  # CSP rules

    return response


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
 #   if request.method == "GET" and request.args.get("url"):
  #      url = request.args.get("url", "")
   #     return checkurl(url)
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        isLoggedIn = dbHandler.retrieveUsers(username, password)
        if isLoggedIn:
            dbHandler.listFeedback()
            return render_template("/2fa.html", value=username, state=isLoggedIn)
        else:
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

@app.route("/enable_2fa", methods=["GET", "POST"])

def enable_2fa():
    """
    Enable Two-Factor Authentication (2FA) for users with debug logs to troubleshoot QR code issues.
    """
    if session.get('2fa_verified'):
        return redirect(url_for('addFeedback'))

    otp_secret = session.get('user_secret')
    if not otp_secret:
        app.logger.error("2FA secret not found in session. Redirecting to home.")
        return redirect(url_for('home'))

    try:
        # Generate TOTP provisioning URI
        totp = pyotp.TOTP(otp_secret)
        provisioning_uri = totp.provisioning_uri(name=session.get('username'), issuer_name="SecureApp")

        # Create QR code
        qr_code = pyqrcode.create(provisioning_uri)
        qr_buffer = BytesIO()
        qr_code.svg(qr_buffer, scale=5)
        qr_code_b64 = base64.b64encode(qr_buffer.getvalue()).decode()

        # Store QR code in session for reuse
        session['qr_code'] = qr_code_b64
    except Exception as e:
        app.logger.exception(f"Error while generating QR code: {e}")
        return jsonify({'error': 'An error occurred while generating the QR code. Please try again later.'}), 500

    return render_template("2fa.html", qr_code=qr_code_b64)


@app.route("/verify_2fa", methods=["POST", "GET"])
def verify_2fa():
    """
    Verify the submitted OTP for 2FA.
    """
    if request.method == "POST":
        otp_secret = session.get('user_secret', "")
        user_otp = request.form.get("otp", "")

        totp = pyotp.TOTP(otp_secret)
        if totp.verify(user_otp):
            session['2fa_verified'] = True
            return render_template("success.html", state=True, value="Back")

        qr_code = session.get('qr_code', "")
        return render_template("2fa.html", qr_code=qr_code, error="Invalid OTP. Try Again.")

    return redirect(url_for('enable_2fa'))

if __name__ == "__main__":
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
    app.run(debug=False, host="0.0.0.0", port=5000)
