"""CareLedger: a purpose-written educational patient-record prototype.

Standard-library-only local application. Use fictional patient data only.
NOT suitable for real clinical use or regulatory compliance.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import hmac
import html
import os
import re
import secrets
import sqlite3
import threading
import time
from datetime import date, datetime, timezone
from contextlib import contextmanager
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlsplit

ROOT = Path(__file__).resolve().parent
DEFAULT_DB = ROOT / "careledger-demo.sqlite3"
CSS = (ROOT / "assets" / "styles.css").read_text(encoding="utf-8")
SESSION_DURATION = 2 * 60 * 60
SESSIONS: dict[str, dict] = {}
SESSION_LOCK = threading.Lock()
ALLOWED_STATUS = ("Active", "Follow-up", "Archived")
DEMO_PASSWORD = "DemoPass!2026"  # DEMO ONLY; never deploy with default accounts.


def escape(s: object) -> str:
    return html.escape(str(s if s is not None else ""), quote=True)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def password_digest(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 260_000)
    return f"{salt.hex()}:{derived.hex()}"


def check_password(password: str, stored: str) -> bool:
    try:
        salt_hex, hash_hex = stored.split(":")
        derived = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), 260_000)
        return hmac.compare_digest(derived, bytes.fromhex(hash_hex))
    except (ValueError, TypeError):
        return False


def open_db(path: Path) -> sqlite3.Connection:
    """Open a database connection, usable across multiple write transactions."""
    conn = sqlite3.connect(path, timeout=5)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


@contextmanager
def db_connection(path: Path):
    """One request-scoped connection, committed and then closed automatically."""
    db = open_db(path)
    try:
        with db:
            yield db
    finally:
        db.close()


def init_db(path: Path = DEFAULT_DB) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with db_connection(path) as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK (role IN ('admin','clinician','viewer'))
        );
        CREATE TABLE IF NOT EXISTS patients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            date_of_birth TEXT NOT NULL,
            appointment_date TEXT NOT NULL,
            care_summary TEXT NOT NULL,
            status TEXT NOT NULL CHECK (status IN ('Active','Follow-up','Archived')),
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER NOT NULL REFERENCES patients(id),
            user_id INTEGER NOT NULL REFERENCES users(id),
            action TEXT NOT NULL CHECK (action IN ('CREATED','UPDATED')),
            changed_fields TEXT NOT NULL,
            happened_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS patients_name ON patients(full_name);
        CREATE INDEX IF NOT EXISTS audit_patient_id ON audit(patient_id);
        """)
        if db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            db.executemany("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", [
                (name, password_digest(DEMO_PASSWORD), name) for name in ("admin", "clinician", "viewer")
            ])
        if db.execute("SELECT COUNT(*) FROM patients").fetchone()[0] == 0:
            db.executemany("""INSERT INTO patients
                (full_name, date_of_birth, appointment_date, care_summary, status, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)""", [
                ("Amina Bello", "1994-08-22", "2026-11-04", "Routine wellbeing review; fictional demonstration record.", "Active", utc_now()),
                ("Daniel Reed", "1988-02-14", "2026-11-06", "Scheduled follow-up consultation; fictional demonstration record.", "Follow-up", utc_now()),
                ("Maya Lewis", "2001-05-18", "2026-11-10", "Annual health appointment; fictional demonstration record.", "Active", utc_now()),
                ("Noah Carter", "1979-12-09", "2026-11-12", "Previous visit completed; fictional demonstration record.", "Archived", utc_now()),
                ("Zara Ahmed", "1997-03-27", "2026-11-14", "Preventative care discussion; fictional demonstration record.", "Active", utc_now()),
            ])


def validate_patient(form: dict[str, str]) -> dict[str, str]:
    payload = {k: (form.get(k) or "").strip() for k in (
        "full_name", "date_of_birth", "appointment_date", "care_summary", "status"
    )}
    name = payload["full_name"]
    if not (2 <= len(name) <= 80) or not re.fullmatch(r"[^<>\r\n\x00-\x1f]+", name):
        raise ValueError("Name must have 2–80 printable characters.")
    for key, label in (("date_of_birth", "Date of birth"), ("appointment_date", "Appointment date")):
        try:
            parsed = date.fromisoformat(payload[key])
        except ValueError:
            raise ValueError(f"{label} must be a valid YYYY-MM-DD date.") from None
        if not (date(1900, 1, 1) <= parsed <= date(2100, 12, 31)):
            raise ValueError(f"{label} must be between 1900 and 2100.")
    if date.fromisoformat(payload["date_of_birth"]) > date.today():
        raise ValueError("Date of birth cannot be in the future.")
    if len(payload["care_summary"]) > 700:
        raise ValueError("Care summary must be 700 characters or fewer.")
    if not payload["care_summary"]:
        raise ValueError("Care summary is required.")
    if payload["status"] not in ALLOWED_STATUS:
        raise ValueError("Select a valid status.")
    return payload


def create_patient(db: sqlite3.Connection, actor: sqlite3.Row, values: dict[str, str]) -> int:
    if actor["role"] not in ("admin", "clinician"):
        raise PermissionError("This account cannot create records.")
    data = validate_patient(values)
    with db:
        cursor = db.execute("""INSERT INTO patients (full_name,date_of_birth,appointment_date,care_summary,status,updated_at)
          VALUES (:full_name,:date_of_birth,:appointment_date,:care_summary,:status,:updated_at)""",
          {**data, "updated_at": utc_now()})
        patient_id = cursor.lastrowid
        db.execute("INSERT INTO audit (patient_id,user_id,action,changed_fields,happened_at) VALUES (?,?,?,?,?)",
                   (patient_id, actor["id"], "CREATED", "New record", utc_now()))
    return int(patient_id)


def update_patient(db: sqlite3.Connection, actor: sqlite3.Row, patient_id: int, values: dict[str, str]) -> list[str]:
    if actor["role"] not in ("admin", "clinician"):
        raise PermissionError("This account cannot edit records.")
    data = validate_patient(values)
    patient = db.execute("SELECT * FROM patients WHERE id = ?", (patient_id,)).fetchone()
    if patient is None:
        raise LookupError("Record not found.")
    changed = [key.replace("_", " ").title() for key in data if data[key] != patient[key]]
    if not changed:
        return []
    with db:
        db.execute("""UPDATE patients SET full_name=:full_name,date_of_birth=:date_of_birth,
            appointment_date=:appointment_date,care_summary=:care_summary,status=:status,updated_at=:updated_at
            WHERE id=:patient_id""", {**data, "updated_at": utc_now(), "patient_id": patient_id})
        db.execute("INSERT INTO audit (patient_id,user_id,action,changed_fields,happened_at) VALUES (?,?,?,?,?)",
                   (patient_id, actor["id"], "UPDATED", ", ".join(changed), utc_now()))
    return changed


def status_badge(value: str) -> str:
    color = {"Active": "green", "Follow-up": "amber", "Archived": "muted"}.get(value, "muted")
    return f'<span class="pill {color}"><span class="pill-dot"></span>{escape(value)}</span>'


def nav_item(href: str, label: str, icon: str, active: bool) -> str:
    return f'<a class="nav-link {"active" if active else ""}" href="{href}"><span class="nav-icon">{icon}</span>{label}</a>'


def frame(content: str, user: sqlite3.Row | None, active: str = "", title: str = "Overview") -> str:
    if user is None:
        return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
        <title>{escape(title)} · CareLedger</title><style>{CSS}</style></head><body class="login-page">{content}</body></html>'''
    initials = "".join(x[0].upper() for x in user["username"].split())[:2]
    sidebar = f'''<aside class="sidebar"><a class="brand" href="/"><span class="brand-icon">✦</span><span>careledger<span class="brand-period">.</span></span></a>
    <div class="workspace-label">WORKSPACE</div>
    <nav>{nav_item('/', 'Overview', '▦', active=='home')}{nav_item('/patients/new', 'New patient', '＋', active=='new') if user['role']!='viewer' else ''}
    {nav_item('/audit', 'Audit trail', '◴', active=='audit') if user['role'] in ('admin','clinician') else ''}</nav>
    <div class="sidebar-bottom"><div class="sandbox-note"><div class="sandbox-heading">✧ &nbsp;Learning prototype</div><p>Fictional patient records only. Never enter real personal or medical data.</p></div>
    <div class="profile"><div class="avatar">{escape(initials)}</div><div class="profile-detail"><b>{escape(user['username'].title())}</b><span>{escape(user['role'].title())} account</span></div></div>
    <form method="post" action="/logout"><input type="hidden" name="csrf" value="{{csrf}}"><button class="logout" aria-label="Sign out" title="Sign out">↗</button></form></div></aside>'''
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
    <title>{escape(title)} · CareLedger</title><style>{CSS}</style></head><body><div class="app-shell">{sidebar}<main class="content"><div class="topbar"><span>CARE MANAGEMENT <span class="topbar-chevron">/</span> {escape(title).upper()}</span><div class="topbar-tag"><span class="online-dot"></span> DEMO ENVIRONMENT</div></div>{content}<footer>CareLedger • Educational prototype • Synthetic data only <span>Built with Python + SQLite</span></footer></main></div></body></html>'''


def page_login(error: str = "") -> str:
    danger = f'<div class="login-error">{escape(error)}</div>' if error else ''
    return f'''<section class="login-wrap"><div class="login-left"><a class="brand login-brand" href="/login"><span class="brand-icon">✦</span>careledger<span class="brand-period">.</span></a>
    <div class="login-story"><span class="eyebrow light">SECURE SYSTEMS START WITH GOOD DESIGN</span><h1>Every record<br>has a story.<br><em>Keep it safe.</em></h1><p>An educational prototype exploring healthcare data, permission controls and traceable changes.</p></div>
    <div class="login-copy">Learning prototype &nbsp;·&nbsp; Not for clinical use</div></div>
    <div class="login-right"><div class="login-card"><div class="login-icon">✦</div><span class="eyebrow">WELCOME BACK</span><h2>Sign in to CareLedger</h2><p class="login-intro">Use one of the fictional demo accounts to explore the application.</p>{danger}
    <form method="post" action="/login"><label>Account</label><select name="username" required><option value="clinician">Clinician — create and edit</option><option value="admin">Administrator — full access</option><option value="viewer">Viewer — read only</option></select>
    <label>Password</label><input type="password" name="password" value="{DEMO_PASSWORD}" required><button class="btn primary login-submit">Sign in <span>→</span></button></form>
    <div class="demo-hint">DEMO PASSWORD <code>{DEMO_PASSWORD}</code></div><p class="privacy-line">⚑ &nbsp; Only use fictional patient information.</p></div></div></section>'''


def page_dashboard(db: sqlite3.Connection, user: sqlite3.Row, query: str = "", message: str = "") -> str:
    stats = dict(db.execute("SELECT status, COUNT(*) AS n FROM patients GROUP BY status").fetchall())
    total = sum(stats.values())
    qlike = f"%{query[:70]}%"
    rows = db.execute("""SELECT * FROM patients WHERE full_name LIKE ? OR ('PT-' || printf('%04d', id+1000)) LIKE ?
        ORDER BY updated_at DESC, id DESC LIMIT 100""", (qlike, qlike)).fetchall()
    patient_rows = "".join(f'''<tr><td><a class="patient-link" href="/patients/{r['id']}"><span class="patient-mini">{escape(''.join(s[0] for s in r['full_name'].split()[:2]))}</span><b>{escape(r['full_name'])}</b></a></td>
        <td class="muted">PT-{r['id']+1000:04d}</td><td>{status_badge(r['status'])}</td><td>{escape(r['appointment_date'])}</td><td class="muted">{escape(r['updated_at'][:10])}</td><td><a class="table-arrow" href="/patients/{r['id']}">↗</a></td></tr>''' for r in rows)
    notice = f'<div class="notice">✓ {escape(message)}</div>' if message else ''
    button = '<a class="btn primary" href="/patients/new">＋ &nbsp; New record</a>' if user["role"] != "viewer" else ''
    return f'''<section class="page-head"><div><span class="eyebrow">YOUR WORKSPACE</span><h1>Patient overview<span class="heading-dot">.</span></h1><p>Organised information. Thoughtful access. Traceable changes.</p></div>{button}</section>{notice}
    <div class="metrics"><div class="metric"><span>TOTAL RECORDS</span><strong>{total:02d}</strong><small>All fictional patient files</small><div class="metric-symbol">▣</div></div>
    <div class="metric"><span>ACTIVE PATIENTS</span><strong>{stats.get('Active',0):02d}</strong><small>Open records</small><div class="metric-symbol">♧</div></div>
    <div class="metric"><span>FOLLOW-UPS</span><strong>{stats.get('Follow-up',0):02d}</strong><small>Pending appointments</small><div class="metric-symbol">◷</div></div></div>
    <section class="panel table-panel"><div class="panel-top"><div><span class="eyebrow">PATIENT DIRECTORY</span><h2>Patient records <span class="count-bubble">{len(rows)}</span></h2></div>
    <form action="/" method="get" class="search"><span>⌕</span><input type="search" name="q" value="{escape(query)}" placeholder="Search name or ID…" aria-label="Search name or ID"></form></div>
    <div class="table-scroll"><table><thead><tr><th>PATIENT NAME</th><th>RECORD ID</th><th>STATUS</th><th>NEXT APPOINTMENT</th><th>UPDATED</th><th></th></tr></thead>
    <tbody>{patient_rows or '<tr><td colspan="6" class="empty">No matching records.</td></tr>'}</tbody></table></div></section>
    <div class="insight-grid"><div class="insight-panel"><div class="insight-icon">✳</div><h3>Designed for accountability</h3><p>Edits record the account responsible and which fields changed, without duplicating sensitive details in the audit log.</p></div>
    <div class="insight-panel"><div class="insight-icon mint">⌘</div><h3>Access with intention</h3><p>Different account roles have different permissions, demonstrating how systems can support confidentiality and usability.</p></div></div>'''


def patient_form(r: dict[str, str], csrf: str, action: str, btn_label: str) -> str:
    fields = f'''<div class="form-grid"><div><label for="full_name">Full name <span>*</span></label><input id="full_name" name="full_name" maxlength="80" required value="{escape(r.get('full_name',''))}" placeholder="e.g. Alex Morgan"></div>
    <div><label for="date_of_birth">Date of birth <span>*</span></label><input id="date_of_birth" name="date_of_birth" type="date" required value="{escape(r.get('date_of_birth',''))}"></div>
    <div><label for="appointment_date">Appointment date <span>*</span></label><input id="appointment_date" name="appointment_date" type="date" required value="{escape(r.get('appointment_date',''))}"></div>
    <div><label for="status">Record status <span>*</span></label><select id="status" name="status">{''.join(f'<option value="{escape(s)}" {"selected" if r.get("status","Active")==s else ""}>{escape(s)}</option>' for s in ALLOWED_STATUS)}</select></div></div>
    <label for="care_summary">Care summary <span>*</span></label><textarea id="care_summary" name="care_summary" maxlength="700" rows="5" required placeholder="Fictional educational notes only…">{escape(r.get('care_summary',''))}</textarea>'''
    return f'''<form method="post" action="{escape(action)}" class="patient-form"><input type="hidden" name="csrf" value="{escape(csrf)}">{fields}<div class="form-actions"><a class="btn ghost" href="/">Cancel</a><button class="btn primary">{escape(btn_label)} →</button></div></form>'''


def page_new(csrf: str, error: str = "", form: dict | None = None) -> str:
    danger = f'<div class="notice error">{escape(error)}</div>' if error else ''
    return f'''<section class="page-head"><div><span class="eyebrow">PATIENT DIRECTORY / NEW</span><h1>Create patient record<span class="heading-dot">.</span></h1><p>Add a fictional entry to explore data collection and validation.</p></div></section>{danger}
    <div class="panel form-panel"><div class="section-label">PATIENT INFORMATION</div>{patient_form(form or {},csrf,'/patients','Create patient record')}</div>'''


def page_patient(db: sqlite3.Connection, user: sqlite3.Row, patient_id: int, csrf: str, error: str = "", form: dict | None = None, message: str = "") -> str:
    patient = db.execute("SELECT * FROM patients WHERE id = ?", (patient_id,)).fetchone()
    if patient is None:
        raise LookupError("Record not found.")
    p = dict(patient)
    recent = db.execute("""SELECT audit.*, users.username FROM audit JOIN users ON users.id=audit.user_id
        WHERE patient_id=? ORDER BY audit.id DESC LIMIT 6""", (patient_id,)).fetchall()
    activity = "".join(f'''<li><div class="timeline-dot"></div><div><strong>{escape(r['action'].title())}</strong><p>{escape(r['changed_fields'])}</p><small>By {escape(r['username'])} · {escape(r['happened_at'][:16].replace('T',' '))} UTC</small></div></li>''' for r in recent)
    notice = f'<div class="notice error">{escape(error)}</div>' if error else (f'<div class="notice">✓ {escape(message)}</div>' if message else '')
    edit = (f'''<section class="panel form-panel"><div class="section-label">UPDATE THIS RECORD</div>
      <h2 class="form-title">Record details</h2>{patient_form(form or p, csrf, f'/patients/{patient_id}/update','Save changes')}</section>''' if user["role"] != "viewer" else '''<div class="notice neutral">Read-only account: editing is disabled for your role.</div>''')
    return f'''<section class="page-head"><div><span class="eyebrow"><a href="/">PATIENT DIRECTORY</a> / PT-{patient_id+1000:04d}</span><h1>{escape(p['full_name'])}<span class="heading-dot">.</span></h1><p>Record PT-{patient_id+1000:04d} &nbsp; {status_badge(p['status'])}</p></div><a class="btn ghost" href="/">← Back to records</a></section>{notice}
    <div class="record-layout"><div>{edit}</div><aside class="panel history-panel"><span class="eyebrow">ACCOUNTABILITY</span><h2>Change history</h2><p>Tracked account activity, without storing old medical notes in the audit trail.</p><ol class="timeline">{activity or '<li>No recorded changes.</li>'}</ol></aside></div>'''


def page_audit(db: sqlite3.Connection) -> str:
    rows = db.execute("""SELECT audit.*, users.username FROM audit JOIN users ON users.id=audit.user_id
        ORDER BY audit.id DESC LIMIT 150""").fetchall()
    trs = "".join(f'''<tr><td>{escape(r['happened_at'][:16].replace('T',' '))} UTC</td><td><a href="/patients/{r['patient_id']}">PT-{r['patient_id']+1000:04d}</a></td><td><span class="pill muted">{escape(r['action'])}</span></td><td>{escape(r['username'])}</td><td>{escape(r['changed_fields'])}</td></tr>''' for r in rows)
    return f'''<section class="page-head"><div><span class="eyebrow">SYSTEM ACTIVITY</span><h1>Audit trail<span class="heading-dot">.</span></h1><p>Who changed a record, what changed and when.</p></div></section><section class="panel table-panel"><div class="panel-top"><div><span class="eyebrow">TRACEABLE BY DESIGN</span><h2>Recent changes</h2></div></div><div class="table-scroll"><table><thead><tr><th>TIME</th><th>RECORD</th><th>ACTION</th><th>ACCOUNT</th><th>FIELDS</th></tr></thead><tbody>{trs or '<tr><td colspan="5" class="empty">No changes yet.</td></tr>'}</tbody></table></div></section>'''


class CareLedgerServer(ThreadingHTTPServer):
    daemon_threads = True
    def __init__(self, address: tuple, db_path: Path):
        super().__init__(address, RequestHandler)
        self.db_path = db_path


class RequestHandler(BaseHTTPRequestHandler):
    server: CareLedgerServer

    def log_message(self, fmt: str, *args: object) -> None:
        return  # Keep demo output quiet.

    def send_page(self, content: str, status: int = 200, cookie: str | None = None) -> None:
        body = content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'")
        self.send_header("Cache-Control", "no-store")
        if cookie is not None:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(body)

    def redirect(self, path: str, cookie: str | None = None) -> None:
        self.send_response(303)
        self.send_header("Location", path)
        if cookie is not None:
            self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def auth(self):
        cookies = SimpleCookie()
        try:
            cookies.load(self.headers.get("Cookie", ""))
            token = cookies.get("careledger_session")
        except Exception:
            return None, None
        if token is None:
            return None, None
        with SESSION_LOCK:
            sess = SESSIONS.get(token.value)
            if not sess or sess["expires"] < time.time():
                SESSIONS.pop(token.value, None)
                return None, None
        with db_connection(self.server.db_path) as db:
            user = db.execute("SELECT * FROM users WHERE id=?", (sess["user_id"],)).fetchone()
        return user, sess

    def page(self, content: str, user=None, sess=None, active="", title="Overview", status=200):
        rendered = frame(content,user,active,title)
        if sess:
            rendered = rendered.replace("{csrf}", escape(sess["csrf"]))
        self.send_page(rendered,status)

    def require_session(self):
        user, sess = self.auth()
        if not user:
            self.redirect("/login")
            return None, None
        return user, sess

    def reject(self, status: int, message: str, user=None, sess=None):
        self.page(f'<section class="page-head"><div><span class="eyebrow">ERROR {status}</span><h1>{escape(message)}</h1><p><a href="/">← Return to overview</a></p></div></section>',user,sess,title="Error",status=status)

    def do_GET(self):
        parsed = urlsplit(self.path)
        path = parsed.path
        if path == "/login":
            user,_ = self.auth()
            if user:
                return self.redirect("/")
            return self.send_page(frame(page_login(), None, title="Sign in"))
        user,sess = self.require_session()
        if not user:
            return
        try:
            with db_connection(self.server.db_path) as db:
                if path == "/":
                    query = parse_qs(parsed.query).get("q", [""])[0][:70]
                    msg = parse_qs(parsed.query).get("message", [""])[0][:120]
                    return self.page(page_dashboard(db,user,query,msg),user,sess,active="home")
                if path == "/patients/new":
                    if user["role"]=="viewer":
                        return self.reject(403,"You cannot create patient records.",user,sess)
                    return self.page(page_new(sess["csrf"]),user,sess,active="new",title="New record")
                if path == "/audit":
                    if user["role"]=="viewer":
                        return self.reject(403,"Audit access is restricted.",user,sess)
                    return self.page(page_audit(db),user,sess,active="audit",title="Audit trail")
                match = re.fullmatch(r"/patients/(\d+)",path)
                if match:
                    pid = int(match.group(1))
                    msg = parse_qs(parsed.query).get("message",[""])[0][:120]
                    return self.page(page_patient(db,user,pid,sess["csrf"],message=msg),user,sess,title="Patient record")
        except LookupError as ex:
            return self.reject(404,str(ex),user,sess)
        return self.reject(404,"Page not found.",user,sess)

    def read_form(self) -> dict[str,str] | None:
        try:
            length = int(self.headers.get("Content-Length","0"))
        except ValueError:
            return None
        if not (0 < length <= 12_000) or self.headers.get("Content-Type","").split(";")[0] != "application/x-www-form-urlencoded":
            return None
        raw = self.rfile.read(length).decode("utf-8",errors="replace")
        return {k:v[0] for k,v in parse_qs(raw,keep_blank_values=True).items()}

    def do_POST(self):
        parsed = urlsplit(self.path)
        path = parsed.path
        # Local-only origin restriction protects against external POST attempts.
        origin = self.headers.get("Origin", "")
        expected = f"http://{self.headers.get('Host','')}"
        if origin and origin != expected:
            return self.reject(403,"Cross-origin requests are blocked.")
        form = self.read_form()
        if form is None:
            return self.reject(400,"Invalid form submission.")
        if path == "/login":
            username = form.get("username","")
            password = form.get("password","")
            with db_connection(self.server.db_path) as db:
                user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            if not user or not check_password(password,user["password_hash"]):
                return self.send_page(frame(page_login("Please check your credentials."),None,title="Sign in"),status=401)
            token=secrets.token_urlsafe(32)
            sess={"user_id":user["id"],"csrf":secrets.token_urlsafe(32),"expires":time.time()+SESSION_DURATION}
            with SESSION_LOCK:
                SESSIONS[token]=sess
            return self.redirect("/",f"careledger_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_DURATION}")
        user,sess=self.require_session()
        if not user:
            return
        if not secrets.compare_digest(form.get("csrf",""),sess["csrf"]):
            return self.reject(403,"Invalid security token.",user,sess)
        if path=="/logout":
            try:
                cookies=SimpleCookie();cookies.load(self.headers.get("Cookie",""))
                token=cookies.get("careledger_session")
                if token:
                    with SESSION_LOCK:
                        SESSIONS.pop(token.value,None)
            except Exception:
                pass
            return self.redirect("/login","careledger_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")
        with db_connection(self.server.db_path) as db:
            if path=="/patients":
                if user["role"]=="viewer":
                    return self.reject(403,"You cannot create patient records.",user,sess)
                try:
                    new_id=create_patient(db,user,form)
                    return self.redirect(f"/patients/{new_id}?message=Record%20created%20successfully")
                except ValueError as ex:
                    return self.page(page_new(sess["csrf"],str(ex),form),user,sess,active="new",title="New record",status=422)
            match=re.fullmatch(r"/patients/(\d+)/update",path)
            if match:
                if user["role"]=="viewer":
                    return self.reject(403,"You cannot edit patient records.",user,sess)
                pid=int(match.group(1))
                try:
                    fields=update_patient(db,user,pid,form)
                    notice="Changes%20saved%20and%20logged" if fields else "No%20changes%20to%20save"
                    return self.redirect(f"/patients/{pid}?message={notice}")
                except ValueError as ex:
                    return self.page(page_patient(db,user,pid,sess["csrf"],error=str(ex),form=form),user,sess,title="Patient record",status=422)
                except LookupError as ex:
                    return self.reject(404,str(ex),user,sess)
        return self.reject(404,"Page not found.",user,sess)


def serve(host: str="127.0.0.1",port:int=8765,db: Path=DEFAULT_DB):
    if host not in ("127.0.0.1","localhost","::1"):
        raise ValueError("This demonstration app must only bind to localhost.")
    init_db(db)
    httpd=CareLedgerServer((host,port),db)
    print(f"CareLedger demo is running at http://{host}:{httpd.server_port}",flush=True)
    print("Demo accounts: clinician, admin, viewer | Password:", DEMO_PASSWORD,flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    parser=argparse.ArgumentParser(description="CareLedger local educational healthcare record prototype")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    args=parser.parse_args()
    serve(port=args.port,db=args.db)
