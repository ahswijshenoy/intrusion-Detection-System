# front_end_ids_admin.py
import os, re, time, json, sqlite3, threading, queue
from collections import defaultdict
from datetime import datetime
from functools import wraps

from flask import Flask, request, jsonify, Response, make_response, redirect, url_for, session

try:
    from email_validator import validate_email, EmailNotValidError
except Exception:
    def validate_email(x, **kwargs):
        class V: domain = x.split("@",1)[1]
        if "@" not in x: raise ValueError("invalid")
        return V()
    EmailNotValidError = ValueError

import bcrypt

# --- Optional Scapy (for UDP flood sim) ---
try:
    import scapy.all as scp
    SCAPY_OK = True
except Exception:
    SCAPY_OK = False

app = Flask(__name__)
app.secret_key = os.environ.get("APP_SECRET_KEY", "dev-change-this")  # change in prod
DB = "auth.db"

# =========================
# IDS config/state
# =========================
FAIL_WINDOW_SEC = 900
ALERT_SUPPRESSION_SEC = 90
BRUTE_FORCE_FAILS = 8
SPRAY_DISTINCT_USERS = 10
ENUM_DISTINCT_USERS = 20
HONEYTOKENS = {"svc_backup@company.local", "admin_test", "payroll-report"}

login_events = []
_lock = threading.Lock()
_last_alert_time = defaultdict(lambda: 0)
alert_queue = queue.SimpleQueue()

# =========================
# DB helpers
# =========================
def db():
    c = sqlite3.connect(DB, check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c

def init_db():
    conn = db()
    cur = conn.cursor()
    cur.executescript("""
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY,
      username TEXT UNIQUE,
      email TEXT UNIQUE,
      pwdhash BLOB,
      role TEXT DEFAULT 'user',
      created_at TEXT
    );
    """)
    conn.commit(); conn.close()

def ensure_role_column():
    """Adds role column if DB existed before we added it."""
    conn = db(); cur = conn.cursor()
    cur.execute("PRAGMA table_info(users)")
    cols = [r["name"] for r in cur.fetchall()]
    if "role" not in cols:
        cur.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'")
        conn.commit()
    conn.close()

def create_default_admin():
    conn = db(); cur = conn.cursor()
    cur.execute("SELECT 1 FROM users WHERE role='admin' LIMIT 1")
    if not cur.fetchone():
        pwdhash = bcrypt.hashpw(b"ChangeMe!2025", bcrypt.gensalt())
        cur.execute(
            "INSERT INTO users(username,email,pwdhash,role,created_at) VALUES(?,?,?,?,?)",
            ("admin","admin@example.com", pwdhash, "admin", datetime.utcnow().isoformat()+"Z")
        )
        conn.commit()
    conn.close()

def find_user(identifier):
    conn = db(); cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username=? OR email=?", (identifier, identifier))
    row = cur.fetchone(); conn.close()
    return row

def now(): return datetime.utcnow()

def rate_limit_alert(key):
    t = time.time()
    if t - _last_alert_time[key] >= ALERT_SUPPRESSION_SEC:
        _last_alert_time[key] = t
        return True
    return False

def emit_alert(kind, details):
    key = f"{kind}:{json.dumps(details, sort_keys=True)}"
    if rate_limit_alert(key):
        alert = {"time_utc": now().isoformat()+"Z", "kind": kind, "details": details}
        print("[ALERT]", json.dumps(alert))
        try: alert_queue.put(alert, block=False)
        except Exception: pass

# =========================
# Auth / misc helpers
# =========================
def require_json(fn):
    @wraps(fn)
    def w(*a, **k):
        if not request.is_json: return jsonify({"error":"JSON required"}), 400
        return fn(*a, **k)
    return w

def require_admin(fn):
    @wraps(fn)
    def w(*a, **k):
        if not session.get("admin_user"):
            return redirect(url_for("login_page"))
        return fn(*a, **k)
    return w

def client_ip():
    return (request.headers.get("X-Forwarded-For", request.remote_addr or "0.0.0.0")
            .split(",")[0].strip())

# =========================
# UDP flood simulator (admin only)
# =========================
_udp_stop = threading.Event()
_udp_thread = None

def _udp_flood_worker(ip_dst: str, seconds: int, pps: int):
    end = time.time() + seconds
    interval = 1.0 / max(1, pps)
    while time.time() < end and not _udp_stop.is_set():
        pkt = scp.IP(src=str(scp.RandIP()), dst=ip_dst) / scp.UDP(
            sport=scp.RandShort(), dport=scp.RandShort()
        )
        try:
            scp.send(pkt, count=1, verbose=False)
        except Exception as e:
            print("[udp_flood] send error:", e)
            break
        time.sleep(interval)

@app.post("/admin/udpflood/start")
@require_admin
@require_json
def admin_udpflood_start():
    if not SCAPY_OK:
        return jsonify({"ok": False, "message": "Scapy not available on server"}), 500
    data = request.get_json() or {}
    ip = (data.get("ip") or "").strip()
    seconds = int(max(1, min(int(data.get("seconds", 5)), 30)))   # clamp 1..30
    pps     = int(max(1, min(int(data.get("pps", 100)), 1000)))   # clamp 1..1000
    if not re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", ip):
        return jsonify({"ok": False, "message": "Invalid target IP"}), 400
    global _udp_thread
    if _udp_thread and _udp_thread.is_alive():
        return jsonify({"ok": False, "message": "UDP flood already running"}), 409
    _udp_stop.clear()
    _udp_thread = threading.Thread(target=_udp_flood_worker, args=(ip, seconds, pps), daemon=True)
    _udp_thread.start()
    emit_alert("udpflood_started", {"ip": ip, "seconds": seconds, "pps": pps})
    return jsonify({"ok": True, "message": f"Started UDP flood to {ip} for {seconds}s @ {pps} pps"})

@app.post("/admin/udpflood/stop")
@require_admin
def admin_udpflood_stop():
    if not (_udp_thread and _udp_thread.is_alive()):
        return jsonify({"ok": False, "message": "No UDP flood running"}), 409
    _udp_stop.set()
    emit_alert("udpflood_stopped", {})
    return jsonify({"ok": True, "message": "Stopped"})

# =========================
# Public pages (Login) + Admin Dashboard
# =========================
LOGIN_HTML = """
<!doctype html><html lang="en"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>IDS Admin Login</title>
<style>
:root{--bg:#0b1020;--card:#10142a;--text:#e9ecf5;--muted:#a9b1c7;--accent:#6aa6ff;}
*{box-sizing:border-box} html,body{height:100%}
body{margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;background:linear-gradient(180deg,#0b1020,#0a0f1f);color:var(--text);display:flex;align-items:center;justify-content:center}
.card{width:min(420px,92vw);background:var(--card);border:1px solid #232c53;border-radius:14px;padding:22px;box-shadow:0 10px 30px rgba(0,0,0,.25)}
h1{margin:0 0 14px;font-size:22px;text-align:center}
label{display:block;margin:10px 0 6px;color:var(--muted);font-size:13px}
input{width:100%;padding:10px 12px;border-radius:10px;border:1px solid #334070;background:#0f1733;color:var(--text)}
button{margin-top:14px;width:100%;padding:10px 14px;border-radius:10px;border:1px solid #3a4a86;background:#19265a;color:var(--text);cursor:pointer}
button:hover{border-color:#5370d8}
.toast{margin-top:10px;color:var(--muted);text-align:center}
</style></head><body>
<div class="card">
  <h1>Intrusion Detection System – Admin</h1>
  <label>Username or Email</label>
  <input id="user" placeholder="admin"/>
  <label>Password</label>
  <input id="pass" type="password" placeholder="••••••••"/>
  <button onclick="login()">Sign in</button>
  <div id="out" class="toast"></div>
</div>
<script>
async function login(){
  const out=document.getElementById('out');
  out.textContent='Signing in...';
  const r=await fetch('/admin/login',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({user:document.getElementById('user').value.trim(),password:document.getElementById('pass').value})});
  const j=await r.json().catch(()=>({}));
  if(r.ok){ location.href='/dashboard'; } else { out.textContent=j.message||'Invalid credentials'; }
}
</script></body></html>
"""

DASHBOARD_HTML = """
<!doctype html><html lang="en"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>IDS Dashboard</title>
<style>
:root{--bg:#0b1020;--panel:#121a33;--card:#1a2447;--text:#e9ecf5;--muted:#a9b1c7;--accent:#6aa6ff;}
*{box-sizing:border-box} html,body{height:100%}
body{margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;background:linear-gradient(180deg,#0b1020,#0a0f1f);color:var(--text);display:flex;flex-direction:column;min-height:100vh}
header{padding:20px 16px;border-bottom:1px solid #222a4a;background:rgba(11,16,32,.8);backdrop-filter:blur(8px);display:flex;justify-content:space-between;align-items:center}
h1{margin:0;font-size:22px}
main{flex:1;display:grid;gap:16px;grid-template-columns:1fr 1fr; padding:20px;max-width:1100px;margin:0 auto}
.card{background:var(--card);border:1px solid #232c53;border-radius:16px;padding:16px;box-shadow:0 10px 30px rgba(0,0,0,.25)}
h2{font-size:18px;margin:0 0 12px}
label{display:block;margin:8px 0 6px;color:var(--muted);font-size:13px}
input{width:100%;padding:10px 12px;border-radius:10px;border:1px solid #334070;background:#0f1733;color:var(--text)}
button{padding:10px 14px;border-radius:10px;border:1px solid #3a4a86;background:#19265a;color:var(--text);cursor:pointer}
button:hover{border-color:#5370d8}
.flex{display:flex;gap:10px;flex-wrap:wrap}
.log{font-family:ui-monospace, Menlo, Consolas, monospace;background:#0e162f;border:1px solid #28335f;padding:10px;border-radius:10px;max-height:320px;overflow:auto}
.bad{color:#ff7b7b}.ok{color:#58d68d}
@media(max-width:920px){ main{grid-template-columns:1fr} }
.toast{margin-top:8px;color:#a9b1c7}
</style></head><body>
<header>
  <h1>Intrusion Detection System – Dashboard</h1>
  <div>
    <button onclick="location.href='/_demo/users'">Users JSON</button>
    <button onclick="location.href='/logout'">Logout</button>
  </div>
</header>
<main>
  <section class="card">
    <h2>Admin Login Test</h2>
    <div class="flex">
      <div style="flex:1;min-width:220px">
        <label>Username</label>
        <input id="login_user" placeholder="alice or alice@example.com"/>
      </div>
      <div style="flex:1;min-width:180px">
        <label>Password</label>
        <input id="login_pass" type="password" placeholder="••••••••"/>
      </div>
    </div>
    <div style="margin-top:12px">
      <button onclick="login()">Sign in (test)</button>
      <span id="login_out" class="bad"></span>
    </div>

    <h2 style="margin-top:18px">Generate Events (Testing)</h2>
    <div class="flex">
      <button onclick="spray()">Password spray x12</button>
      <button onclick="enumUsers()">Username enumeration x25</button>
      <button onclick="honey()">Touch honeytoken</button>
      <button onclick="brute()">Brute force x9 (user: alice)</button>
    </div>

    <h2 style="margin-top:18px">Lab Simulation – UDP Flood (Admin)</h2>
    <div class="flex" style="margin-bottom:10px">
      <div style="min-width:200px;flex:1">
        <label>Target IP</label>
        <input id="udp_ip" placeholder="e.g. 10.0.0.5"/>
      </div>
      <div style="min-width:120px">
        <label>Duration (seconds)</label>
        <input id="udp_seconds" type="number" value="5" min="1" max="30"/>
      </div>
      <div style="min-width:140px">
        <label>Packets per second</label>
        <input id="udp_pps" type="number" value="100" min="1" max="1000"/>
      </div>
    </div>
    <div class="flex">
      <button onclick="startUdpflood()">Start flood</button>
      <button onclick="stopUdpflood()">Stop</button>
    </div>
    <div id="udp_msg" class="toast"></div>
    <div class="toast">⚠️ For lab/VPC use only. Requires privileges for raw packets.</div>
  </section>

  <section class="card">
    <h2>Live Alerts</h2>
    <div id="alerts" class="log"></div>
  </section>
</main>

<script>
async function login(){
  const out=document.getElementById('login_out');
  out.textContent='';
  const body={user:document.getElementById('login_user').value.trim(),
              password:document.getElementById('login_pass').value};
  const r=await fetch('/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  const j=await r.json().catch(()=>({}));
  if(r.ok){ out.textContent='✅ '+(j.message||'Logged in'); out.className='ok'; }
  else{ out.textContent='❌ '+(j.message||'Invalid'); out.className='bad'; }
}
async function spray(){for(let i=1;i<=12;i++){await fetch('/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({user:'user'+i,password:'Winter2025!'})});}}
async function enumUsers(){for(let i=1;i<=25;i++){await fetch('/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({user:'ghost'+i,password:'anything'})});}}
async function honey(){await fetch('/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({user:'admin_test',password:'whatever'})});}
async function brute(){for(let i=1;i<=9;i++){await fetch('/login',{method:'POST',headers:{'Content-Type':'application/json','User-Agent':'GUI-Test/'+i},body:JSON.stringify({user:'alice',password:'wrong'+i})});}}

async function startUdpflood(){
  const ip=document.getElementById('udp_ip').value.trim();
  const seconds=parseInt(document.getElementById('udp_seconds').value||'5',10);
  const pps=parseInt(document.getElementById('udp_pps').value||'100',10);
  const out=document.getElementById('udp_msg');
  out.textContent='Starting...';
  const r=await fetch('/admin/udpflood/start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip,seconds,pps})});
  const j=await r.json().catch(()=>({}));
  out.textContent=j.message || (r.ok?'Started':'Failed');
}
async function stopUdpflood(){
  const out=document.getElementById('udp_msg');
  out.textContent='Stopping...';
  const r=await fetch('/admin/udpflood/stop',{method:'POST'});
  const j=await r.json().catch(()=>({}));
  out.textContent=j.message || (r.ok?'Stopped':'No flood running');
}

// Alerts stream
(function(){
  const log=document.getElementById('alerts');
  const es=new EventSource('/alerts_stream');
  es.onmessage=(e)=>{try{const a=JSON.parse(e.data);const line=`[${a.time_utc}] ${a.kind}: ${JSON.stringify(a.details)}`;const d=document.createElement('div');d.textContent=line;log.prepend(d);}catch(_){}}})();
</script>
</body></html>
"""

# =========================
# Routes
# =========================
@app.get("/")
def root():
    return redirect(url_for("login_page"))

@app.get("/login")
def login_page():
    if session.get("admin_user"):
        return redirect(url_for("dashboard"))
    return make_response(LOGIN_HTML)

@app.post("/admin/login")
@require_json
def admin_login():
    d = request.get_json()
    user = (d.get("user") or "").strip()
    pwd = d.get("password") or ""
    row = find_user(user)
    if not row or row["role"] != "admin" or not bcrypt.checkpw(pwd.encode(), row["pwdhash"]):
        return jsonify({"ok": False, "message": "Invalid admin credentials"}), 401
    session["admin_user"] = row["username"]
    return jsonify({"ok": True})

@app.get("/dashboard")
@require_admin
def dashboard():
    return make_response(DASHBOARD_HTML)

@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))

# existing user login endpoint (used to generate IDS events)
@app.post("/login")
@require_json
def user_login_api():
    d = request.get_json()
    user_input = (d.get("user") or "").strip()
    password = d.get("password") or ""
    ip = client_ip()
    ua = request.headers.get("User-Agent","-")

    row = find_user(user_input)
    exists = bool(row)
    ok = False
    if row: ok = bcrypt.checkpw(password.encode(), row["pwdhash"])

    with _lock:
        login_events.append({
            "ts": time.time(), "ip": ip, "user": user_input,
            "ok": ok, "pwd": password if not ok else None, "ua": ua, "exists": exists
        })

    if user_input.lower() in {"svc_backup@company.local","admin_test","payroll-report"}:
        emit_alert("honeytoken_attempt", {"ip": ip, "user": user_input})

    if ok: return jsonify({"ok": True, "message": "Logged in"})
    return jsonify({"ok": False, "message": "Invalid credentials"}), 401

@app.get("/_demo/users")
@require_admin
def list_users():
    c = db(); cur = c.cursor()
    cur.execute("SELECT username,email,role,created_at FROM users ORDER BY created_at DESC")
    rows = [dict(r) for r in cur.fetchall()]; c.close()
    return jsonify(rows)

@app.get("/alerts_stream")
@require_admin
def alerts_stream():
    def gen():
        yield "data: " + json.dumps({"time_utc": now().isoformat()+"Z", "kind":"stream_open", "details":{}}) + "\n\n"
        while True:
            a = alert_queue.get()
            yield "data: " + json.dumps(a) + "\n\n"
    headers = {"Content-Type":"text/event-stream","Cache-Control":"no-cache","Connection":"keep-alive","X-Accel-Buffering":"no"}
    return Response(gen(), headers=headers)

# =========================
# IDS background loop
# =========================
def window_events(seconds):
    cutoff = time.time() - seconds
    with _lock:
        while login_events and login_events[0]["ts"] < cutoff - 60:
            login_events.pop(0)
        return [e for e in login_events if e["ts"] >= cutoff]

def ids_loop():
    while True:
        time.sleep(2.5)
        ev = window_events(FAIL_WINDOW_SEC)

        # brute force
        fails_by_user = defaultdict(list)
        for e in ev:
            if not e["ok"] and e["exists"]:
                fails_by_user[e["user"]].append(e)
        for user, items in fails_by_user.items():
            ips = {i["ip"] for i in items}
            if len(items) >= BRUTE_FORCE_FAILS:
                emit_alert("brute_force", {"user": user, "fail_count": len(items),
                                           "distinct_ips": len(ips), "window_sec": FAIL_WINDOW_SEC})

        # password spray
        failures = [e for e in ev if not e["ok"]]
        by_ip_pwd = defaultdict(list)
        for e in failures:
            key = (e["ip"], e.get("pwd") or "")
            by_ip_pwd[key].append(e)
        for (ip, pwd), items in by_ip_pwd.items():
            users = {i["user"] for i in items}
            if len(users) >= SPRAY_DISTINCT_USERS and len(pwd) > 0:
                emit_alert("password_spray", {"ip": ip, "password": pwd,
                                              "distinct_users": len(users), "window_sec": FAIL_WINDOW_SEC})

        # username enumeration
        by_ip_nonexistent = defaultdict(list)
        for e in ev:
            if not e["exists"]:
                by_ip_nonexistent[e["ip"]].append(e)
        for ip, items in by_ip_nonexistent.items():
            users = {i["user"] for i in items}
            if len(users) >= ENUM_DISTINCT_USERS:
                emit_alert("username_enumeration", {"ip": ip, "distinct_nonexistent_users": len(users),
                                                    "window_sec": FAIL_WINDOW_SEC})

        # device churn
        by_user_ip = defaultdict(list)
        for e in ev: by_user_ip[(e["user"], e["ip"])] += [e]
        for (user, ip), items in by_user_ip.items():
            uas = {i["ua"] for i in items if i["ua"]}
            if len(uas) >= 6 and any(i["ok"] for i in items):
                emit_alert("device_churn", {"user": user, "ip": ip,
                                            "distinct_user_agents": len(uas), "window_sec": FAIL_WINDOW_SEC})

# =========================
# Boot
# =========================
if __name__ == "__main__":
    init_db()
    ensure_role_column()
    create_default_admin()
    threading.Thread(target=ids_loop, daemon=True).start()
    # Run as admin/root for raw packet send if using UDP flood
    app.run(host="127.0.0.1", port=5000, debug=True)
