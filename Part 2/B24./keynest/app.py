import os
import io
import secrets
import string
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, jsonify
)
from flask_sqlalchemy import SQLAlchemy
import bcrypt
import pyotp
import qrcode
import qrcode.image.svg

# Fernet = AES-128-CBC + HMAC-SHA256 — symmetric authenticated encryption.
# Vault passwords are encrypted at rest; only decryptable with the app's
# ENCRYPTION_KEY. Even if the database file is stolen, passwords are unreadable.
from cryptography.fernet import Fernet

# ---------------------------------------------------------------------------
# App & database setup
# ---------------------------------------------------------------------------

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL", "sqlite:///keynest.db"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)

db = SQLAlchemy(app)

# ---------------------------------------------------------------------------
# Encryption key — load from environment or generate and save to file.
# In production, set ENCRYPTION_KEY as an environment variable (never commit it).
# ---------------------------------------------------------------------------

KEY_FILE = "encryption.key"

def load_or_create_key():
    env_key = os.environ.get("ENCRYPTION_KEY")
    if env_key:
        return env_key.encode()
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    return key

fernet = Fernet(load_or_create_key())

def encrypt(plaintext: str) -> str:
    return fernet.encrypt(plaintext.encode()).decode()

def decrypt(ciphertext: str) -> str:
    return fernet.decrypt(ciphertext.encode()).decode()

# ---------------------------------------------------------------------------
# Database models
# ---------------------------------------------------------------------------

class User(db.Model):
    __tablename__ = "users"
    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(80), unique=True, nullable=False)
    display_name  = db.Column(db.String(120), nullable=False)
    password_hash = db.Column(db.LargeBinary, nullable=False)
    role          = db.Column(db.String(20), nullable=False, default="child")
    avatar        = db.Column(db.String(4), default="?")
    color         = db.Column(db.String(12), default="#E6F1FB")
    text_color    = db.Column(db.String(12), default="#0C447C")
    mfa_secret    = db.Column(db.String(64), nullable=False)
    mfa_verified  = db.Column(db.Boolean, default=False)
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)
    vault_entries = db.relationship("VaultEntry", backref="owner_user",
                                    lazy=True, cascade="all, delete-orphan")

    def check_password(self, password: str) -> bool:
        return bcrypt.checkpw(password.encode(), self.password_hash)

    def set_password(self, password: str):
        self.password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())


class VaultEntry(db.Model):
    __tablename__     = "vault_entries"
    id                = db.Column(db.Integer, primary_key=True)
    site              = db.Column(db.String(120), nullable=False)
    username_field    = db.Column(db.String(120), default="")
    # password_encrypted stores the Fernet-encrypted vault password
    password_encrypted = db.Column(db.Text, nullable=False)
    icon              = db.Column(db.String(4), default="🔑")
    owner_id          = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at        = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at        = db.Column(db.DateTime, default=datetime.utcnow,
                                  onupdate=datetime.utcnow)

    def set_password(self, plaintext: str):
        self.password_encrypted = encrypt(plaintext)

    def get_password(self) -> str:
        return decrypt(self.password_encrypted)


class AuditLog(db.Model):
    __tablename__ = "audit_log"
    id         = db.Column(db.Integer, primary_key=True)
    timestamp  = db.Column(db.DateTime, default=datetime.utcnow)
    username   = db.Column(db.String(80), nullable=False)
    action     = db.Column(db.String(200), nullable=False)
    granted    = db.Column(db.Boolean, nullable=False)
    detail     = db.Column(db.String(200), default="")


def log_event(username, action, granted, detail=""):
    entry = AuditLog(username=username, action=action,
                     granted=granted, detail=detail)
    db.session.add(entry)
    db.session.commit()

# ---------------------------------------------------------------------------
# RBAC
# ---------------------------------------------------------------------------

ROLE_PERMISSIONS = {
    "admin":  ["view_own", "view_all", "add_own", "add_any", "edit_any",
               "delete_any", "manage_members", "view_log"],
    "parent": ["view_own", "view_all", "add_own", "add_any", "edit_any", "view_log"],
    "child":  ["view_own", "add_own", "edit_own"],
}

ROLE_COLORS = {
    "admin":  ("MO", "#FAECE7", "#712B13"),
    "parent": ("JA", "#EEEDFE", "#3C3489"),
    "child":  ("?",  "#E6F1FB", "#0C447C"),
}

def can(permission, role=None):
    r = role or session.get("role", "")
    return permission in ROLE_PERMISSIONS.get(r, [])

def can_access_entry(entry):
    if can("view_all"):
        return True
    return entry.owner_id == session.get("user_id")

def can_edit_entry(entry):
    if can("edit_any"):
        return True
    return can("edit_own") and entry.owner_id == session.get("user_id")

# ---------------------------------------------------------------------------
# Decorators
# ---------------------------------------------------------------------------

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

def permission_required(permission):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not can(permission):
                log_event(session.get("username", "?"),
                          f"Attempted: {permission}", False, "Insufficient role")
                return jsonify({"error": "Access denied"}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator

# ---------------------------------------------------------------------------
# Auth — Registration
# ---------------------------------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username     = request.form.get("username", "").strip().lower()
        display_name = request.form.get("display_name", "").strip()
        password     = request.form.get("password", "")
        confirm      = request.form.get("confirm", "")
        role         = request.form.get("role", "child")

        # Admin role requires an invite code set via ADMIN_CODE env var
        admin_code   = request.form.get("admin_code", "").strip()

        if not username or not display_name or not password:
            flash("All fields are required.", "error")
            return render_template("register.html")

        if password != confirm:
            flash("Passwords do not match.", "error")
            return render_template("register.html")

        if len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
            return render_template("register.html")

        if User.query.filter_by(username=username).first():
            flash("Username already taken.", "error")
            return render_template("register.html")

        if role == "admin":
            expected = os.environ.get("ADMIN_CODE", "admin123")
            if admin_code != expected:
                flash("Invalid admin code.", "error")
                return render_template("register.html")

        initials = "".join(p[0].upper() for p in display_name.split()[:2])
        _, color, text_color = ROLE_COLORS.get(role, ROLE_COLORS["child"])

        user = User(
            username=username,
            display_name=display_name,
            role=role,
            avatar=initials or "?",
            color=color,
            text_color=text_color,
            mfa_secret=pyotp.random_base32(),
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        log_event(username, "Registered", True)
        flash("Account created! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

# ---------------------------------------------------------------------------
# Auth — Login + MFA
# ---------------------------------------------------------------------------

@app.route("/", methods=["GET"])
def index():
    return redirect(url_for("dashboard") if "username" in session else url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()

        if not user or not user.check_password(password):
            flash("Invalid username or password.", "error")
            log_event(username, "Login attempt", False, "Bad credentials")
            return render_template("login.html")

        session["pending_mfa_user"] = username
        log_event(username, "Password verified — MFA required", True)

        return redirect(url_for("mfa_setup") if not user.mfa_verified
                        else url_for("mfa_verify"))

    return render_template("login.html")

@app.route("/mfa/setup")
def mfa_setup():
    username = session.get("pending_mfa_user")
    if not username:
        return redirect(url_for("login"))
    user = User.query.filter_by(username=username).first()
    uri = pyotp.TOTP(user.mfa_secret).provisioning_uri(
        name=user.display_name, issuer_name="KeyNest"
    )
    factory = qrcode.image.svg.SvgPathImage
    img = qrcode.make(uri, image_factory=factory)
    buf = io.BytesIO()
    img.save(buf)
    qr_svg = buf.getvalue().decode("utf-8")
    return render_template("mfa_setup.html", qr_svg=qr_svg,
                           secret=user.mfa_secret,
                           display_name=user.display_name)

@app.route("/mfa/verify", methods=["GET", "POST"])
def mfa_verify():
    username = session.get("pending_mfa_user")
    if not username:
        return redirect(url_for("login"))
    user = User.query.filter_by(username=username).first()

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        totp = pyotp.TOTP(user.mfa_secret)
        if totp.verify(code, valid_window=1):
            user.mfa_verified = True
            db.session.commit()
            session.pop("pending_mfa_user", None)
            session.permanent = True
            session["username"]     = username
            session["user_id"]      = user.id
            session["role"]         = user.role
            session["display_name"] = user.display_name
            log_event(username, "MFA verified — Login complete", True)
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid or expired code. Try again.", "error")
            log_event(username, "MFA attempt failed", False, "Wrong TOTP code")

    return render_template("mfa_verify.html", display_name=user.display_name)

@app.route("/logout")
def logout():
    log_event(session.get("username", "?"), "Logout", True)
    session.clear()
    return redirect(url_for("login"))

# ---------------------------------------------------------------------------
# Change password
# ---------------------------------------------------------------------------

@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        current  = request.form.get("current", "")
        new_pw   = request.form.get("new_password", "")
        confirm  = request.form.get("confirm", "")
        user = User.query.filter_by(username=session["username"]).first()

        if not user.check_password(current):
            flash("Current password is incorrect.", "error")
            return render_template("change_password.html")

        if new_pw != confirm:
            flash("New passwords do not match.", "error")
            return render_template("change_password.html")

        if len(new_pw) < 8:
            flash("Password must be at least 8 characters.", "error")
            return render_template("change_password.html")

        user.set_password(new_pw)
        db.session.commit()
        log_event(session["username"], "Changed master password", True)
        flash("Password updated successfully.", "success")
        return redirect(url_for("dashboard"))

    return render_template("change_password.html")

# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@app.route("/dashboard")
@login_required
def dashboard():
    user_id = session["user_id"]
    role    = session["role"]
    if can("view_all"):
        entries = VaultEntry.query.order_by(VaultEntry.created_at.desc()).all()
    else:
        entries = VaultEntry.query.filter_by(owner_id=user_id)\
                            .order_by(VaultEntry.created_at.desc()).all()
    users   = User.query.all()
    logs    = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(25).all()
    return render_template(
        "dashboard.html",
        display_name=session["display_name"],
        username=session["username"],
        role=role,
        entries=entries,
        users=users,
        logs=logs,
        can=can,
        can_edit_entry=can_edit_entry,
    )

# ---------------------------------------------------------------------------
# Vault API
# ---------------------------------------------------------------------------

@app.route("/api/vault/<int:entry_id>/password")
@login_required
def get_password(entry_id):
    entry = VaultEntry.query.get_or_404(entry_id)
    if not can_access_entry(entry):
        log_event(session["username"], f"Viewed {entry.site} password",
                  False, "Access denied")
        return jsonify({"error": "Access denied"}), 403
    log_event(session["username"], f"Viewed {entry.site} password", True)
    return jsonify({"password": entry.get_password()})

@app.route("/api/vault", methods=["POST"])
@login_required
def add_entry():
    if not can("add_own"):
        return jsonify({"error": "Access denied"}), 403
    data     = request.get_json()
    site     = data.get("site", "").strip()
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    owner_id = data.get("owner_id", session["user_id"])

    if not can("add_any"):
        owner_id = session["user_id"]

    if not site or not password:
        return jsonify({"error": "Site and password are required"}), 400

    entry = VaultEntry(site=site, username_field=username,
                       owner_id=owner_id, icon="🔑")
    entry.set_password(password)
    db.session.add(entry)
    db.session.commit()
    log_event(session["username"], f"Added entry: {site}", True)
    return jsonify({"id": entry.id, "message": "Created"}), 201

@app.route("/api/vault/<int:entry_id>", methods=["PUT"])
@login_required
def edit_entry(entry_id):
    entry = VaultEntry.query.get_or_404(entry_id)
    if not can_edit_entry(entry):
        log_event(session["username"], f"Edit {entry.site}", False, "Denied")
        return jsonify({"error": "Access denied"}), 403
    data = request.get_json()
    if "site"     in data: entry.site           = data["site"]
    if "username" in data: entry.username_field = data["username"]
    if "password" in data: entry.set_password(data["password"])
    entry.updated_at = datetime.utcnow()
    db.session.commit()
    log_event(session["username"], f"Edited entry: {entry.site}", True)
    return jsonify({"message": "Updated"})

@app.route("/api/vault/<int:entry_id>", methods=["DELETE"])
@login_required
@permission_required("delete_any")
def delete_entry(entry_id):
    entry = VaultEntry.query.get_or_404(entry_id)
    site  = entry.site
    db.session.delete(entry)
    db.session.commit()
    log_event(session["username"], f"Deleted entry: {site}", True)
    return jsonify({"message": "Deleted"})

# ---------------------------------------------------------------------------
# Password generator
# ---------------------------------------------------------------------------

@app.route("/api/generate", methods=["POST"])
@login_required
def generate_password():
    data    = request.get_json() or {}
    length  = min(max(int(data.get("length", 16)), 8), 64)
    charset = ""
    if data.get("upper",   True):  charset += string.ascii_uppercase
    if data.get("lower",   True):  charset += string.ascii_lowercase
    if data.get("numbers", True):  charset += string.digits
    if data.get("symbols", False): charset += "!@#$%^&*()-_=+[]{}"
    if not charset: charset = string.ascii_letters
    password = "".join(secrets.choice(charset) for _ in range(length))
    return jsonify({"password": password})

# ---------------------------------------------------------------------------
# Members
# ---------------------------------------------------------------------------

@app.route("/api/members")
@login_required
@permission_required("manage_members")
def get_members():
    users = User.query.all()
    return jsonify([{"id": u.id, "display_name": u.display_name,
                     "role": u.role, "username": u.username} for u in users])

@app.route("/api/members/<int:user_id>/role", methods=["PUT"])
@login_required
@permission_required("manage_members")
def update_role(user_id):
    user = User.query.get_or_404(user_id)
    new_role = request.get_json().get("role")
    if new_role not in ROLE_PERMISSIONS:
        return jsonify({"error": "Invalid role"}), 400
    user.role = new_role
    db.session.commit()
    log_event(session["username"], f"Changed {user.username} role to {new_role}", True)
    return jsonify({"message": "Updated"})

# ---------------------------------------------------------------------------
# Initialise DB and seed first admin if empty
# ---------------------------------------------------------------------------

def seed_db():
    if User.query.count() > 0:
        return
    admin = User(
        username="admin",
        display_name="Admin",
        role="admin",
        avatar="AD",
        color="#FAECE7",
        text_color="#712B13",
        mfa_secret=pyotp.random_base32(),
    )
    admin.set_password("admin123")
    db.session.add(admin)
    db.session.commit()
    log_event("system", "Database seeded with default admin", True)
    print("\n  Default admin account created:")
    print("  Username: admin")
    print("  Password: admin123")
    print("  Change this immediately after first login!\n")

with app.app_context():
    db.create_all()
    seed_db()

if __name__ == "__main__":
    app.run(debug=False, port=5000)
