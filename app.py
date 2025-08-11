import re
import time
import json
import sqlite3
import threading
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, request, jsonify
from email_validator import validate_email, EmailNotValidError
import bcrypt
from user_agents import parse as ua_parse

app = Flask(__name__)

DB = "auth.db"

# ---------------------------
# Config
# ---------------------------
FAIL_WINDOW_SEC = 900              # 15 min sliding window
ALERT_SUPPRESSION_SEC = 90         # minimum spacing between identical alerts
BRUTE_FORCE_FAILS = 8              # per user within window
SPRAY_DISTINCT_USERS = 10          # per IP using same password
ENUM_DISTINCT_USERS = 20           # non-existent users probed by same IP
HONEYTOKENS = {"svc_backup@company.local", "admin_test", "payroll-report"}  # usernames/emails never used by real users
DISPOSABLE_EMAIL_DOMAINS = {
    "mailinator.com","10minutemail.com","tempmail.com","guerrillamail.com",
    "trashmail.com","yopmail.com","getnada.com","sharklasers.com"
}
COMMON_WEAK_PASSWORDS = {
    "123456","123456789","password","qwerty","111111","123123","abc123",
    "password1","iloveyou","admin","welcome","letmein","monkey","dragon"
}
# Password regex: at least 10 chars, 1 lower, 1 upper, 1 digit, 1 special
STRONG_PW = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{10,}$")

# In-memory event buffers for IDS
login_events = []  # list of dicts with ts, ip, user, ok, pwd, ua, exists
lock = threading.Lock()

# Deduplicate repeated alerts
_last_alert_time = defaultdict(lambda: 0)

# ---------------------------
# Helpers / DB
# ---------------------------
def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            email TEXT UNIQUE,
            pwdhash BLOB,
            created_at TEXT
        );
    """)
    conn.commit()
    conn.close()

def now():
    return datetime.utcnow()

def rate_limit_alert(key):
    t = time.time()
    if t - _last_alert_time[key] >= ALERT_SUPPRESSION_SEC:
        _last_alert_time[key] = t
        return True
    return False

def emit_alert(kind, details):
    key = f"{kind}:{json.dumps(details, sort_keys=True)}"
    if rate_limit_alert(key):
        alert = {
            "time_utc": now().isoformat() + "Z",
            "kind": kind,
            "details": details
        }
        # For demo, just print to stdout. Replace with Slack/email/syslog as needed.
        print("[ALERT]", json.dumps(alert))

def is_disposable(email_domain):
    return email_domain.lower() in DISPOSABLE_EMAIL_DOMAINS

def looks_like_fake_username(u):
    # very short, all digits, or nonsense patterns
    if len(u) < 3:
        return True
    if u.isdigit():
        return True
    if re.fullmatch(r"[a-z]{1,2}\d{3,}", u):
        return True
    if "test" in u.lower() or "fake" in u.lower():
        return True
    return False

def password_risk(pwd):
    reasons = []
    if pwd.lower() in COMMON_WEAK_PASSWORDS:
        reasons.append("common_password")
    if len(pwd) < 10:
        reasons.append("too_short")
    if not STRONG_PW.search(pwd):
        reasons.append("weak_complexity")
    # quick heuristic: keyboard walks
    if re.search(r"(?i)(qwerty|asdf|zxcv|1234|abcd)", pwd):
        reasons.append("keyboard_walk")
    return reasons

def validate_new_account(username, email, password):
    issues = []

    # Email
    try:
        v = validate_email(email, check_deliverability=False)
        domain = v.domain
        if is_disposable(domain):
            issues.append("disposable_email_domain")
    except EmailNotValidError as e:
        issues.append("invalid_email_format")

    # Username
    if looks_like_fake_username(username):
        issues.append("suspicious_username")

    # Password
    pw_issues = password_risk(password)
    issues.extend(pw_issues)

    # Optional: HIBP k-anonymity lookup could be added here (offline in this demo)
    return issues

def hash_pw(p):
    return bcrypt.hashpw(p.encode(), bcrypt.gensalt())

def check_pw(p, h):
    return bcrypt.checkpw(p.encode(), h)

def find_user(by_username_or_email):
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username=? OR email=?", (by_username_or_email, by_username_or_email))
    row = cur.fetchone()
    conn.close()
    return row

def create_user(username, email, password):
    conn = db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO users(username, email, pwdhash, created_at) VALUES(?,?,?,?)",
        (username, email, hash_pw(password), now().isoformat() + "Z")
    )
    conn.commit()
    conn.close()

# ---------------------------
# Middleware
# ---------------------------
def require_json(fn):
    @wraps(fn)
    def _w(*args, **kwargs):
        if not request.is_json:
            return jsonify({"error": "JSON required"}), 400
        return fn(*args, **kwargs)
    return _w

def client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr or "0.0.0.0").split(",")[0].strip()

# ---------------------------
# Routes
# ---------------------------
@app.route("/health")
def health():
    return {"ok": True}

@app.route("/register", methods=["POST"])
@require_json
def register():
    data = request.get_json()
    username = data.get("username","").strip()
    email = data.get("email","").strip()
    password = data.get("password","")

    issues = validate_new_account(username, email, password)
    if issues:
        return jsonify({"ok": False, "message": "Credential risks detected", "issues": issues}), 400

    if find_user(username) or find_user(email):
        return jsonify({"ok": False, "message": "User already exists"}), 409

    try:
        create_user(username, email, password)
    except sqlite3.IntegrityError:
        return jsonify({"ok": False, "message": "User already exists"}), 409

    return jsonify({"ok": True, "message": "Registered"})

@app.route("/login", methods=["POST"])
@require_json
def login():
    data = request.get_json()
    user_input = data.get("user","").strip()        # username or email
    password = data.get("password","")
    ip = client_ip()
    ua = request.headers.get("User-Agent","-")

    row = find_user(user_input)
    exists = bool(row)
    ok = False

    if row:
        ok = check_pw(password, row["pwdhash"])

    # record event for IDS
    with lock:
        login_events.append({
            "ts": time.time(),
            "ip": ip,
            "user": user_input,
            "ok": ok,
            "pwd": password if not ok else None,  # store only on failure for spray detection; consider hashing
            "ua": ua,
            "exists": exists
        })

    if user_input in HONEYTOKENS or user_input.lower() in {h.lower() for h in HONEYTOKENS}:
        emit_alert("honeytoken_attempt", {"ip": ip, "user": user_input})

    if ok:
        return jsonify({"ok": True, "message": "Logged in"})
    else:
        return jsonify({"ok": False, "message": "Invalid credentials"}), 401

# ---------------------------
# IDS thread
# ---------------------------
def window_events(seconds):
    cutoff = time.time() - seconds
    with lock:
        # prune old
        while login_events and login_events[0]["ts"] < cutoff - 60:
            login_events.pop(0)
        return [e for e in login_events if e["ts"] >= cutoff]

def ids_loop():
    while True:
        time.sleep(3)
        ev = window_events(FAIL_WINDOW_SEC)

        # Brute force: many failures for same user
        fails_by_user = defaultdict(list)
        for e in ev:
            if not e["ok"] and e["exists"]:
                fails_by_user[e["user"]].append(e)
        for user, items in fails_by_user.items():
            ips = {i["ip"] for i in items}
            if len(items) >= BRUTE_FORCE_FAILS:
                emit_alert("brute_force", {
                    "user": user,
                    "fail_count": len(items),
                    "distinct_ips": len(ips),
                    "window_sec": FAIL_WINDOW_SEC
                })

        # Password spraying: same password, many users from one IP
        failures = [e for e in ev if not e["ok"]]
        by_ip_pwd = defaultdict(list)
        for e in failures:
            key = (e["ip"], e.get("pwd") or "")
            by_ip_pwd[key].append(e)
        for (ip, pwd), items in by_ip_pwd.items():
            users = {i["user"] for i in items}
            if len(users) >= SPRAY_DISTINCT_USERS and len(pwd) > 0:
                emit_alert("password_spray", {
                    "ip": ip,
                    "password": pwd,
                    "distinct_users": len(users),
                    "window_sec": FAIL_WINDOW_SEC
                })

        # Username enumeration: many nonexistent users from one IP
        by_ip_nonexistent = defaultdict(list)
        for e in ev:
            if not e["exists"]:
                by_ip_nonexistent[e["ip"]].append(e)
        for ip, items in by_ip_nonexistent.items():
            users = {i["user"] for i in items}
            if len(users) >= ENUM_DISTINCT_USERS:
                emit_alert("username_enumeration", {
                    "ip": ip,
                    "distinct_nonexistent_users": len(users),
                    "window_sec": FAIL_WINDOW_SEC
                })

        # Strange UA churn from same IP + same user (session hijack-ish)
        by_user_ip = defaultdict(list)
        for e in ev:
            by_user_ip[(e["user"], e["ip"])].append(e)
        for key, items in by_user_ip.items():
            uas = {i["ua"] for i in items if i["ua"]}
            if len(uas) >= 6 and any(i["ok"] for i in items):
                emit_alert("device_churn", {
                    "user": key[0],
                    "ip": key[1],
                    "distinct_user_agents": len(uas),
                    "window_sec": FAIL_WINDOW_SEC
                })

# start IDS thread
init_db()
t = threading.Thread(target=ids_loop, daemon=True)
t.start()

# ---------------------------
# Demo convenience endpoints
# ---------------------------
@app.route("/_demo/users", methods=["GET"])
def list_users():
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT username, email, created_at FROM users")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return jsonify(rows)

@app.route("/_demo/honeytokens", methods=["GET"])
def list_honey():
    return jsonify(sorted(HONEYTOKENS))

if __name__ == "__main__":
    # For production, run behind a real WSGI server (gunicorn/uwsgi) and TLS
    app.run(host="127.0.0.1", port=5000, debug=True)
