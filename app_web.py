import re
import time
import json
import sqlite3
import threading
import queue
from collections import defaultdict
from datetime import datetime
from functools import wraps

from flask import Flask, request, jsonify, Response, make_response

try:
    from email_validator import validate_email, EmailNotValidError
except Exception:
    # soft fallback if package isn't installed
    def validate_email(x, **kwargs):
        class V: domain = x.split("@",1)[1]
        if "@" not in x: raise ValueError("invalid")
        return V()
    EmailNotValidError = ValueError

import bcrypt

app = Flask(__name__)
DB = "auth.db"

# ---------------------------
# Config
# ---------------------------
FAIL_WINDOW_SEC = 900          # look-back window for IDS (15 min)
ALERT_SUPPRESSION_SEC = 90     # suppress duplicate alerts for this many seconds
BRUTE_FORCE_FAILS = 8
SPRAY_DISTINCT_USERS = 10
ENUM_DISTINCT_USERS = 20
HONEYTOKENS = {"svc_backup@company.local", "admin_test", "payroll-report"}
DISPOSABLE_EMAIL_DOMAINS = {
    "mailinator.com","10minutemail.com","tempmail.com","guerrillamail.com",
    "trashmail.com","yopmail.com","getnada.com","sharklasers.com"
}
COMMON_WEAK_PASSWORDS = {
    "123456","123456789","password","qwerty","111111","123123","abc123",
    "password1","iloveyou","admin","welcome","letmein","monkey","dragon"
}
STRONG_PW = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{10,}$")

# IDS state
login_events = []
lock = threading.Lock()
_last_alert_time = defaultdict(lambda: 0)

# Alerts fan-out queue for GUI
alert_queue = queue.SimpleQueue()

# ---------------------------
# DB/helpers
# ---------------------------
def db():
    conn = sqlite3.connect(DB, check_same_thread=False)
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
        print("[ALERT]", json.dumps(alert))
        try:
            alert_queue.put(alert, block=False)
        except Exception:
            pass

def is_disposable(domain):
    return domain.lower() in DISPOSABLE_EMAIL_DOMAINS

def looks_like_fake_username(u):
    if len(u) < 3: return True
    if u.isdigit(): return True
    if re.fullmatch(r"[a-z]{1,2}\d{3,}", u): return True
    if "test" in u.lower() or "fake" in u.lower(): return True
    return False

def password_risk(pwd):
    reasons = []
    if pwd.lower() in COMMON_WEAK_PASSWORDS:
        reasons.append("common_password")
    if len(pwd) < 10:
        reasons.append("too_short")
    if not STRONG_PW.search(pwd):
        reasons.append("weak_complexity")
    if re.search(r"(?i)(qwerty|asdf|zxcv|1234|abcd)", pwd):
        reasons.append("keyboard_walk")
    return reasons

def validate_new_account(username, email, password):
    issues = []
    try:
        v = validate_email(email, check_deliverability=False)
        if is_disposable(v.domain):
            issues.append("disposable_email_domain")
    except EmailNotValidError:
        issues.append("invalid_email_format")

    if looks_like_fake_username(username):
        issues.append("suspicious_username")

    issues.extend(password_risk(password))
    return issues

def hash_pw(p): return bcrypt.hashpw(p.encode(), bcrypt.gensalt())
def check_pw(p, h): return bcrypt.checkpw(p.encode(), h)

def find_user(identifier):
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username=? OR email=?", (identifier, identifier))
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
# API
# ---------------------------
@app.get("/health")
def health(): return {"ok": True}

@app.post("/register")
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

@app.post("/login")
@require_json
def login():
    data = request.get_json()
    user_input = data.get("user","").strip()
    password = data.get("password","")
    ip = client_ip()
    ua = request.headers.get("User-Agent","-")

    row = find_user(user_input)
    exists = bool(row)
    ok = False

    if row:
        ok = check_pw(password, row["pwdhash"])

    with lock:
        login_events.append({
            "ts": time.time(),
            "ip": ip,
            "user": user_input,
            "ok": ok,
            "pwd": password if not ok else None,
            "ua": ua,
            "exists": exists
        })

    if user_input.lower() in {h.lower() for h in HONEYTOKENS}:
        emit_alert("honeytoken_attempt", {"ip": ip, "user": user_input})

    if ok:
        return jsonify({"ok": True, "message": "Logged in"})
    else:
        return jsonify({"ok": False, "message": "Invalid credentials"}), 401

@app.get("/_demo/users")
def list_users():
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT username, email, created_at FROM users")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return jsonify(rows)

@app.get("/_demo/honeytokens")
def list_honey(): return jsonify(sorted(HONEYTOKENS))

# ---------------------------
# IDS loop
# ---------------------------
def window_events(seconds):
    cutoff = time.time() - seconds
    with lock:
        # trim old events (older than window + 60s slack)
        while login_events and login_events[0]["ts"] < cutoff - 60:
            login_events.pop(0)
        return [e for e in login_events if e["ts"] >= cutoff]

def ids_loop():
    while True:
        time.sleep(2.5)
        ev = window_events(FAIL_WINDOW_SEC)

        # Brute force: many failures for same existing user
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

        # Password spray: same password, many users from one IP
        failures = [e for e in ev if not e["ok"]]
        by_ip_pwd = defaultdict(list)
        for e in failures:
            key = (e["ip"], e.get("pwd") or "")
            by_ip_pwd[key].append(e)
        for (ip, pwd), items in by_ip_pwd.items():
            users = {i["user"] for i in items}
            if len(users) >= SPRAY_DISTINCT_USERS and len(pwd) > 0:
                emit_alert("password_spray", {
                    "ip": ip, "password": pwd, "distinct_users": len(users), "window_sec": FAIL_WINDOW_SEC
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
                    "ip": ip, "distinct_nonexistent_users": len(users), "window_sec": FAIL_WINDOW_SEC
                })

        # Device churn (many UAs for same user+IP and at least one success)
        by_user_ip = defaultdict(list)
        for e in ev:
            by_user_ip[(e["user"], e["ip"])].append(e)
        for key, items in by_user_ip.items():
            uas = {i["ua"] for i in items if i["ua"]}
            if len(uas) >= 6 and any(i["ok"] for i in items):
                emit_alert("device_churn", {
                    "user": key[0], "ip": key[1], "distinct_user_agents": len(uas), "window_sec": FAIL_WINDOW_SEC
                })

# Start IDS background thread
init_db()
threading.Thread(target=ids_loop, daemon=True).start()

# ---------------------------
# GUI (single-page app)
# ---------------------------
INDEX_HTML = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>IDS</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <link rel="icon" type="image/jpeg" href="data:image/jpeg;base64,
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
  ">
  <style>
    :root { --bg:#0b1020; --panel:#121a33; --card:#1a2447; --text:#e9ecf5; --muted:#a9b1c7; --accent:#6aa6ff; --bad:#ff7b7b; --good:#58d68d; }
    *{box-sizing:border-box;}
    html, body { height: 100%; }

    /* Page layout: title at top, content centered below */
    body{
      margin:0;
      font-family:system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
      background:linear-gradient(180deg,#0b1020,#0a0f1f);
      color:var(--text);
      display:flex;
      flex-direction:column; /* header then main */
      min-height:100vh;
    }

    header{
      padding:20px 16px;
      border-bottom:1px solid #222a4a;
      background:rgba(11,16,32,.8);
      backdrop-filter: blur(8px);
      text-align:center;
    }
    header h1{ font-size:28px; font-weight:700; margin:0; }
    header .rule{ margin-top:8px; color:var(--muted); }

    main{
      flex:1;
      display:flex;
      align-items:center;     /* center vertically */
      justify-content:center; /* center horizontally */
      padding:24px 12px;
    }

    .container{
      background-color:#10142a;
      padding:20px;
      border-radius:12px;
      box-shadow:0 0 20px rgba(0,0,0,0.5);
      width:min(760px, 95vw);
    }

    .card{background:var(--card); border:1px solid #232c53; border-radius:16px; padding:16px; box-shadow:0 10px 30px rgba(0,0,0,.25);}
    h2{font-size:18px; margin:0 0 12px;}
    label{display:block; font-size:13px; color:var(--muted); margin-bottom:6px;}
    input{width:100%; padding:10px 12px; border-radius:10px; border:1px solid #334070; background:#0f1733; color:var(--text);}
    button{padding:10px 14px; border-radius:10px; border:1px solid #3a4a86; background:#19265a; color:var(--text); cursor:pointer;}
    button:hover{border-color:#5370d8;}
    .row{display:grid; grid-template-columns:1fr 1fr; gap:12px;}
    .muted{color:var(--muted); font-size:13px;}
    .flex{display:flex; gap:10px; flex-wrap:wrap;}
    .sep{height:1px; background:#223066; margin:12px 0;}
    .toast{margin-top:8px; padding:10px; border-radius:10px; background:#10183a; border:1px solid #2b3666;}
    .log{font-family:ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; background:#0e162f; border:1px solid #28335f; padding:10px; border-radius:10px; max-height:240px; overflow:auto;}
    .ok{color:#58d68d;} .bad{color:#ff7b7b;}
  </style>
</head>
<body>
  <header>
    <h1>Intrusion Detection System</h1>
    <div class="rule">_____________________________________________________</div>
  </header>

  <main>
    <div class="container card">
      <h2>Register</h2>
      <div class="row">
        <div>
          <label>Username</label>
          <input id="reg_user" placeholder="e.g. alice" />
        </div>
        <div>
          <label>Email</label>
          <input id="reg_email" placeholder="e.g. alice@example.com" />
        </div>
      </div>
      <div style="margin-top:12px;">
        <label>Password</label>
        <input id="reg_pass" type="password" placeholder="Use combination of numbers and passwords" />
      </div>
      <div style="margin-top:12px;">
        <button onclick="register()">Create account</button>
      </div>
      <div id="reg_out" class="toast muted"></div>

      <div class="sep"></div>
      <h2>Login</h2>
      <div class="row">
        <div>
          <label>Username or Email</label>
          <input id="login_user" placeholder="alice or alice@example.com" />
        </div>
        <div>
          <label>Password</label>
          <input id="login_pass" type="password" placeholder="••••••••" />
        </div>
      </div>
      <div style="margin-top:12px;">
        <button onclick="login()">Sign in</button>
      </div>
      <div id="login_out" class="toast muted"></div>

      <div class="sep"></div>
      <h2>Testing</h2>
      <div class="flex">
        <button onclick="spray()">Password spray x12</button>
        <button onclick="enumUsers()">Username enumeration x25</button>
        <button onclick="honey()">Touch honeytoken</button>
        <button onclick="brute()">Brute force x9 (user: alice)</button>
      </div>
      <div class="muted" style="margin-top:8px;">Testing the features</div>

  </main>

  <script>
  async function register(){
    const out = document.getElementById('reg_out');
    out.textContent = 'Submitting...';
    const body = {
      username: document.getElementById('reg_user').value.trim(),
      email: document.getElementById('reg_email').value.trim(),
      password: document.getElementById('reg_pass').value
    };
    const r = await fetch('/register', {
      method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)
    });
    const j = await r.json().catch(()=>({}));
    if(r.ok){
      out.innerHTML = '<span class="ok">✅ Registered:</span> '+ (j.message||'OK');
    }else{
      const issues = (j.issues||[]).join(', ') || j.message || 'Error';
      out.innerHTML = '<span class="bad">❌ Rejected:</span> ' + issues;
    }
  }

  async function login(){
    const out = document.getElementById('login_out');
    out.textContent = 'Submitting...';
    const body = {
      user: document.getElementById('login_user').value.trim(),
      password: document.getElementById('login_pass').value
    };
    const r = await fetch('/login', {
      method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)
    });
    const j = await r.json().catch(()=>({}));
    if(r.ok){
      out.innerHTML = '<span class="ok">✅ '+ (j.message||'Logged in') +'</span>';
    }else{
      out.innerHTML = '<span class="bad">❌ '+ (j.message||'Invalid') +'</span>';
    }
  }

  // Demo buttons
  async function spray(){
    for(let i=1;i<=12;i++){
      await fetch('/login',{method:'POST',headers:{'Content-Type':'application/json'},
        body: JSON.stringify({user:'user'+i, password:'Winter2025!'})});
    }
  }
  async function enumUsers(){
    for(let i=1;i<=25;i++){
      await fetch('/login',{method:'POST',headers:{'Content-Type':'application/json'},
        body: JSON.stringify({user:'ghost'+i, password:'anything'})});
    }
  }
  async function honey(){
    await fetch('/login',{method:'POST',headers:{'Content-Type':'application/json'},
      body: JSON.stringify({user:'admin_test', password:'whatever'})});
  }
  async function brute(){
    for(let i=1;i<=9;i++){
      await fetch('/login',{method:'POST',headers:{'Content-Type':'application/json',
        'User-Agent':'GUI-Test/'+i}, body: JSON.stringify({user:'alice', password:'wrong'+i})});
    }
  }

#   // Alerts stream
#   (function(){
#     const log = document.getElementById('alerts');
#     const es = new EventSource('/alerts_stream');
#     es.onmessage = (e)=>{
#       try{
#         const a = JSON.parse(e.data);
#         const line = '['+a.time_utc+'] '+a.kind+': '+JSON.stringify(a.details);
#         const div = document.createElement('div');
#         div.textContent = line;
#         log.prepend(div);
#       }catch(err){}
#     };
#     es.onerror = ()=>{ /* silent */ };
#   })();
  </script>
</body>
</html>
"""

@app.get("/")
def index():
    resp = make_response(INDEX_HTML)
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp

@app.get("/alerts_stream")
def alerts_stream():
    def gen():
        # initial message to open stream
        yield "data: " + json.dumps({"time_utc": now().isoformat()+"Z", "kind":"stream_open", "details":{}}) + "\n\n"
        while True:
            a = alert_queue.get()
            yield "data: " + json.dumps(a) + "\n\n"
    headers = {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "X-Accel-Buffering": "no"
    }
    return Response(gen(), headers=headers)

if __name__ == "__main__":
    # For production, use a real WSGI server and TLS
    app.run(host="127.0.0.1", port=5000, debug=True)
