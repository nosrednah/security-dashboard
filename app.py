from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import bcrypt
import requests
import hashlib
import os
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev-secret-change-in-prod")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///dashboard.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login_page"


# --- Models ---

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    scans = db.relationship("ScanHistory", backref="user", lazy=True)

class ScanHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    scan_type = db.Column(db.String(20), nullable=False)
    input_value = db.Column(db.String(300), nullable=False)
    result = db.Column(db.String(300), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


with app.app_context():
    db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# --- Auth routes ---

@app.route("/")
def home():
    if not current_user.is_authenticated:
        return redirect(url_for("login_page"))
    return render_template("index.html", username=current_user.username)

@app.route("/login")
def login_page():
    return render_template("auth.html")

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username already taken"}), 400

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    user = User(username=username, password_hash=hashed.decode())
    db.session.add(user)
    db.session.commit()
    login_user(user)
    return jsonify({"success": True})

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "")

    user = User.query.filter_by(username=username).first()
    if not user or not bcrypt.checkpw(password.encode(), user.password_hash.encode()):
        return jsonify({"error": "Invalid username or password"}), 401

    login_user(user)
    return jsonify({"success": True})

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login_page"))


# --- History route ---

@app.route("/history")
@login_required
def history():
    scans = ScanHistory.query.filter_by(user_id=current_user.id).order_by(ScanHistory.created_at.desc()).limit(50).all()
    return jsonify([{
        "type": s.scan_type,
        "input": s.input_value,
        "result": s.result,
        "time": s.created_at.strftime("%Y-%m-%d %H:%M")
    } for s in scans])


# --- Security tool routes ---

@app.route("/check-email", methods=["POST"])
@login_required
def check_email():
    data = request.get_json()
    email = data["email"]

    try:
        response = requests.get(
            "https://api.proxynova.com/comb",
            params={"query": email},
            headers={"User-Agent": "SecurityDashboard/1.0"},
            timeout=8
        )
        if response.status_code == 200:
            result = response.json()
            lines = result.get("lines", [])
            exact = [l for l in lines if l.lower().startswith(email.lower() + ":")]
            if exact:
                message = f"⚠️ Email found in {len(exact)} leaked record(s) in breach databases."
            else:
                message = "✅ Good news! No breaches found for this email."
        else:
            message = f"❌ Error checking email (status {response.status_code})"
    except requests.Timeout:
        message = "❌ Request timed out. Try again later."
    except requests.RequestException as e:
        message = f"❌ Request failed: {str(e)}"

    db.session.add(ScanHistory(user_id=current_user.id, scan_type="Email", input_value=email, result=message))
    db.session.commit()
    return jsonify({"message": message})


@app.route("/check-password", methods=["POST"])
@login_required
def check_password():
    data = request.get_json()
    password = data["password"]

    score = 0
    feedback = []

    if len(password) >= 8:
        score += 1
    else:
        feedback.append("At least 8 characters")
    if any(c.isupper() for c in password):
        score += 1
    else:
        feedback.append("Add uppercase letters")
    if any(c.islower() for c in password):
        score += 1
    else:
        feedback.append("Add lowercase letters")
    if any(c.isdigit() for c in password):
        score += 1
    else:
        feedback.append("Add numbers")
    if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
        score += 1
    else:
        feedback.append("Add special characters")

    if score <= 2:
        strength = "Weak"
    elif score == 3:
        strength = "Medium"
    elif score == 4:
        strength = "Strong"
    else:
        strength = "Very Strong"

    # Check HIBP Pwned Passwords (k-anonymity — only first 5 chars of hash sent)
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    pwned_count = 0
    try:
        res = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=5)
        for line in res.text.splitlines():
            h, count = line.split(":")
            if h == suffix:
                pwned_count = int(count)
                break
    except Exception:
        pass

    message = f"Strength: {strength}" + (f" | Pwned {pwned_count:,}x" if pwned_count else "")
    db.session.add(ScanHistory(user_id=current_user.id, scan_type="Password", input_value="(hidden)", result=message))
    db.session.commit()
    return jsonify({"strength": strength, "score": score, "feedback": feedback, "pwned": pwned_count})


@app.route("/check-url", methods=["POST"])
@login_required
def check_url():
    data = request.get_json()
    url = data["url"]

    api_key = os.getenv("GOOGLE_API_KEY")
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    payload = {
        "client": {"clientId": "security-dashboard", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    response = requests.post(endpoint, json=payload)
    result = response.json()

    if result.get("matches"):
        message = "⚠️ Warning! This URL is dangerous."
    else:
        message = "✅ This URL appears to be safe."

    db.session.add(ScanHistory(user_id=current_user.id, scan_type="URL", input_value=url, result=message))
    db.session.commit()
    return jsonify({"message": message})


if __name__ == "__main__":
    app.run(debug=True)
