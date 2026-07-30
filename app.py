#!/usr/bin/env python3
import base64
import html
import hmac
import hashlib
import os
import secrets
import shutil
import smtplib
import sqlite3
import ssl
import time
import urllib.parse
from datetime import datetime, timezone
from email.message import EmailMessage
from email.parser import BytesParser
from email.policy import default as email_policy
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def load_env_file():
    env_path = ROOT / ".env"
    if not env_path.exists():
        return
    for raw_line in env_path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key:
            os.environ.setdefault(key, value)


load_env_file()

DATA_DIR = Path(os.environ.get("DATA_DIR", ROOT / "data"))
UPLOAD_DIR = DATA_DIR / "uploads" / "private"
DB_PATH = DATA_DIR / "mission_haiti.db"
STATIC_DIR = ROOT / "static"
SESSION_SECRET = os.environ.get("SESSION_SECRET", "dev-only-change-me-before-deploying")
MAX_UPLOAD_BYTES = 75 * 1024 * 1024
APP_BASE_URL = os.environ.get("APP_BASE_URL", "http://127.0.0.1:8001").rstrip("/")
COOKIE_SECURE = APP_BASE_URL.startswith("https://")
SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USERNAME = os.environ.get("SMTP_USERNAME", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
SMTP_FROM_EMAIL = os.environ.get("SMTP_FROM_EMAIL", SMTP_USERNAME)
SMTP_FROM_NAME = os.environ.get("SMTP_FROM_NAME", "Mission-Haiti")
SMTP_USE_TLS = os.environ.get("SMTP_USE_TLS", "true").lower() in ("1", "true", "yes", "on")
SMTP_USE_SSL = os.environ.get("SMTP_USE_SSL", "false").lower() in ("1", "true", "yes", "on")
PASSWORD_TOKEN_TTL_SECONDS = 7 * 24 * 60 * 60

ROLES = {"admin": "Admin", "staff": "Haiti staff", "sponsor": "Sponsor"}
FILE_KINDS = {
    "profile_photo": "Profile photo",
    "report_card": "Grades/report card",
    "photo": "Photo",
    "video": "Video",
}


class MultipartField:
    def __init__(self, name, filename, content_type, data, value=""):
        self.name = name
        self.filename = filename
        self.type = content_type
        self.file = BytesIO(data)
        self.value = value


class MultipartForm(dict):
    def add(self, field):
        if field.name in self:
            existing = self[field.name]
            if isinstance(existing, list):
                existing.append(field)
            else:
                self[field.name] = [existing, field]
        else:
            self[field.name] = field


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def hash_password(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 220_000)
    return base64.b64encode(salt + digest).decode()


def verify_password(password, stored):
    raw = base64.b64decode(stored.encode())
    salt, expected = raw[:16], raw[16:]
    actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 220_000)
    return hmac.compare_digest(actual, expected)


def sign_session(user_id):
    payload = str(user_id).encode()
    sig = hmac.new(SESSION_SECRET.encode(), payload, hashlib.sha256).hexdigest()
    return f"{user_id}.{sig}"


def unsign_session(value):
    if not value or "." not in value:
        return None
    user_id, sig = value.split(".", 1)
    expected = hmac.new(SESSION_SECRET.encode(), user_id.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return None
    return int(user_id) if user_id.isdigit() else None


def qmarks(values):
    return ",".join("?" for _ in values)


def session_cookie(value, max_age=None):
    parts = [f"mh_session={value}", "HttpOnly", "SameSite=Lax", "Path=/"]
    if COOKIE_SECURE:
        parts.append("Secure")
    if max_age is not None:
        parts.append(f"Max-Age={max_age}")
    return "; ".join(parts)


def send_email(recipient, subject, body):
    if not SMTP_HOST or not SMTP_FROM_EMAIL:
        print(f"EMAIL SKIPPED to {recipient}: SMTP is not configured\n{subject}\n{body}\n")
        return "skipped", "SMTP is not configured."

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = f"{SMTP_FROM_NAME} <{SMTP_FROM_EMAIL}>"
    message["To"] = recipient
    message.set_content(body)

    try:
        if SMTP_USE_SSL:
            with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=15, context=ssl.create_default_context()) as server:
                if SMTP_USERNAME or SMTP_PASSWORD:
                    server.login(SMTP_USERNAME, SMTP_PASSWORD)
                server.send_message(message)
        else:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
                if SMTP_USE_TLS:
                    server.starttls(context=ssl.create_default_context())
                if SMTP_USERNAME or SMTP_PASSWORD:
                    server.login(SMTP_USERNAME, SMTP_PASSWORD)
                server.send_message(message)
    except Exception as exc:
        print(f"EMAIL FAILED to {recipient}: {exc}")
        return "failed", str(exc)

    print(f"EMAIL SENT to {recipient}: {subject}")
    return "sent", "Email sent."


def password_token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def token_expires_at():
    return datetime.fromtimestamp(time.time() + PASSWORD_TOKEN_TTL_SECONDS, timezone.utc).isoformat(timespec="seconds")


def init_db():
    DATA_DIR.mkdir(exist_ok=True)
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('admin','staff','sponsor')),
                sponsor_id INTEGER,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS update_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                update_id INTEGER,
                kind TEXT NOT NULL,
                original_name TEXT NOT NULL,
                storage_name TEXT NOT NULL UNIQUE,
                content_type TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                uploaded_by INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(update_id) REFERENCES updates(id) ON DELETE CASCADE,
                FOREIGN KEY(uploaded_by) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS students (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                school TEXT NOT NULL,
                grade_level TEXT NOT NULL,
                age INTEGER,
                birthdate TEXT,
                sex TEXT,
                profile_photo_file_id INTEGER,
                active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                FOREIGN KEY(profile_photo_file_id) REFERENCES update_files(id)
            );
            CREATE TABLE IF NOT EXISTS sponsors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                user_id INTEGER UNIQUE,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS sponsor_students (
                sponsor_id INTEGER NOT NULL,
                student_id INTEGER NOT NULL,
                PRIMARY KEY (sponsor_id, student_id),
                FOREIGN KEY(sponsor_id) REFERENCES sponsors(id) ON DELETE CASCADE,
                FOREIGN KEY(student_id) REFERENCES students(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS updates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                student_id INTEGER NOT NULL,
                note TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('draft','pending','approved')) DEFAULT 'draft',
                created_by INTEGER NOT NULL,
                approved_by INTEGER,
                created_at TEXT NOT NULL,
                submitted_at TEXT,
                approved_at TEXT,
                FOREIGN KEY(student_id) REFERENCES students(id) ON DELETE CASCADE,
                FOREIGN KEY(created_by) REFERENCES users(id),
                FOREIGN KEY(approved_by) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS email_notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                update_id INTEGER NOT NULL,
                sponsor_id INTEGER NOT NULL,
                recipient_email TEXT NOT NULL,
                subject TEXT NOT NULL,
                body TEXT NOT NULL,
                sent_at TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'queued',
                provider_message TEXT,
                attempted_at TEXT,
                FOREIGN KEY(update_id) REFERENCES updates(id),
                FOREIGN KEY(sponsor_id) REFERENCES sponsors(id)
            );
            CREATE TABLE IF NOT EXISTS password_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                purpose TEXT NOT NULL CHECK(purpose IN ('invite','reset')),
                expires_at TEXT NOT NULL,
                used_at TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_password_tokens_hash ON password_tokens(token_hash);
            """
        )
        existing_email_columns = {row["name"] for row in conn.execute("PRAGMA table_info(email_notifications)").fetchall()}
        if "status" not in existing_email_columns:
            conn.execute("ALTER TABLE email_notifications ADD COLUMN status TEXT NOT NULL DEFAULT 'queued'")
        if "provider_message" not in existing_email_columns:
            conn.execute("ALTER TABLE email_notifications ADD COLUMN provider_message TEXT")
        if "attempted_at" not in existing_email_columns:
            conn.execute("ALTER TABLE email_notifications ADD COLUMN attempted_at TEXT")
        existing_student_columns = {row["name"] for row in conn.execute("PRAGMA table_info(students)").fetchall()}
        if "age" not in existing_student_columns:
            conn.execute("ALTER TABLE students ADD COLUMN age INTEGER")
        if "birthdate" not in existing_student_columns:
            conn.execute("ALTER TABLE students ADD COLUMN birthdate TEXT")
        if "sex" not in existing_student_columns:
            conn.execute("ALTER TABLE students ADD COLUMN sex TEXT")
        count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if count:
            return
        admin_hash = hash_password("admin123")
        staff_hash = hash_password("staff123")
        sponsor_hash = hash_password("sponsor123")
        ts = now()
        conn.execute("INSERT INTO users (name,email,password_hash,role,created_at) VALUES (?,?,?,?,?)", ("Admin User", "admin@mission-haiti.local", admin_hash, "admin", ts))
        conn.execute("INSERT INTO users (name,email,password_hash,role,created_at) VALUES (?,?,?,?,?)", ("Haiti Staff", "staff@mission-haiti.local", staff_hash, "staff", ts))
        sponsor_user = conn.execute("INSERT INTO users (name,email,password_hash,role,created_at) VALUES (?,?,?,?,?)", ("Demo Sponsor", "sponsor@example.com", sponsor_hash, "sponsor", ts)).lastrowid
        student_id = conn.execute("INSERT INTO students (name,school,grade_level,active,created_at) VALUES (?,?,?,?,?)", ("Marie Joseph", "Mission-Haiti School", "Grade 5", 1, ts)).lastrowid
        sponsor_id = conn.execute("INSERT INTO sponsors (name,email,user_id,created_at) VALUES (?,?,?,?)", ("Demo Sponsor", "sponsor@example.com", sponsor_user, ts)).lastrowid
        conn.execute("UPDATE users SET sponsor_id=? WHERE id=?", (sponsor_id, sponsor_user))
        conn.execute("INSERT INTO sponsor_students (sponsor_id,student_id) VALUES (?,?)", (sponsor_id, student_id))


def escape(value):
    return html.escape("" if value is None else str(value), quote=True)


def csrf_token():
    return secrets.token_urlsafe(24)


class App(BaseHTTPRequestHandler):
    server_version = "MissionHaitiMVP/0.1"

    def log_message(self, fmt, *args):
        print(f"{self.address_string()} - {fmt % args}")

    def do_GET(self):
        self.route("GET")

    def do_POST(self):
        self.route("POST")

    def route(self, method):
        parsed = urllib.parse.urlparse(self.path)
        self.path_only = parsed.path.rstrip("/") or "/"
        self.query = urllib.parse.parse_qs(parsed.query)
        self.user = self.current_user()
        try:
            if self.path_only.startswith("/static/") and method == "GET":
                return self.static_file(self.path_only.removeprefix("/static/"))
            if self.path_only == "/login":
                return self.login_get() if method == "GET" else self.login_post()
            if self.path_only == "/forgot-password":
                return self.forgot_password_get() if method == "GET" else self.forgot_password_post()
            if self.path_only == "/set-password":
                return self.set_password_get() if method == "GET" else self.set_password_post()
            if self.path_only == "/logout" and method == "POST":
                return self.logout_post()
            if self.path_only.startswith("/files/") and method == "GET":
                return self.file_get(int(self.path_only.split("/")[-1]))
            if not self.user:
                return self.redirect("/login")
            if self.path_only.startswith("/files/") and self.path_only.endswith("/delete") and method == "POST":
                return self.file_delete_post(int(self.path_only.split("/")[-2]))
            if self.path_only in ("/", "/dashboard") and method == "GET":
                return self.dashboard()
            if self.path_only == "/students" and method == "GET":
                return self.students_index()
            if self.path_only == "/students/new":
                return self.student_new_get() if method == "GET" else self.student_new_post()
            if self.path_only.startswith("/students/") and self.path_only.endswith("/edit"):
                student_id = int(self.path_only.split("/")[-2])
                return self.student_edit_get(student_id) if method == "GET" else self.student_edit_post(student_id)
            if self.path_only.startswith("/students/") and self.path_only.endswith("/delete") and method == "POST":
                return self.student_delete_post(int(self.path_only.split("/")[-2]))
            if self.path_only.startswith("/students/") and method == "GET":
                return self.student_detail(int(self.path_only.split("/")[-1]))
            if self.path_only == "/sponsors" and method == "GET":
                return self.sponsors_index()
            if self.path_only == "/sponsors/new":
                return self.sponsor_new_get() if method == "GET" else self.sponsor_new_post()
            if self.path_only.startswith("/sponsors/") and self.path_only.endswith("/edit"):
                sponsor_id = int(self.path_only.split("/")[-2])
                return self.sponsor_edit_get(sponsor_id) if method == "GET" else self.sponsor_edit_post(sponsor_id)
            if self.path_only.startswith("/sponsors/") and self.path_only.endswith("/delete") and method == "POST":
                return self.sponsor_delete_post(int(self.path_only.split("/")[-2]))
            if self.path_only.startswith("/sponsors/") and self.path_only.endswith("/invite") and method == "POST":
                return self.sponsor_invite_post(int(self.path_only.split("/")[-2]))
            if self.path_only == "/admins" and method == "GET":
                return self.admins_index()
            if self.path_only.startswith("/admins/") and self.path_only.endswith("/delete") and method == "POST":
                return self.admin_delete_post(int(self.path_only.split("/")[-2]))
            if self.path_only == "/updates/new":
                return self.update_new_get() if method == "GET" else self.update_new_post()
            if self.path_only.startswith("/updates/"):
                parts = self.path_only.split("/")
                update_id = int(parts[2])
                if len(parts) == 3 and method == "GET":
                    return self.update_detail(update_id)
                if len(parts) == 4 and parts[3] == "submit" and method == "POST":
                    return self.update_submit(update_id)
                if len(parts) == 4 and parts[3] == "approve" and method == "POST":
                    return self.update_approve(update_id)
                if len(parts) == 4 and parts[3] == "resend" and method == "POST":
                    return self.update_resend(update_id)
            if self.path_only.startswith("/emails/") and self.path_only.endswith("/retry") and method == "POST":
                return self.email_retry(int(self.path_only.split("/")[-2]))
            if self.path_only.startswith("/portal/students/") and method == "GET":
                return self.portal_student(int(self.path_only.split("/")[-1]))
            return self.not_found()
        except PermissionError:
            return self.error_page(HTTPStatus.FORBIDDEN, "Access denied")
        except ValueError as exc:
            return self.error_page(HTTPStatus.BAD_REQUEST, str(exc) or "The request could not be processed.")

    def current_user(self):
        cookie = SimpleCookie(self.headers.get("Cookie", ""))
        user_id = unsign_session(cookie.get("mh_session").value) if cookie.get("mh_session") else None
        if not user_id:
            return None
        with db() as conn:
            return conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()

    def require_roles(self, *roles):
        if not self.user or self.user["role"] not in roles:
            raise PermissionError()

    def send_html(self, content, status=HTTPStatus.OK, extra_headers=None):
        body = content.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; media-src 'self'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
        if extra_headers:
            for key, value in extra_headers.items():
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def redirect(self, target):
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", target)
        self.end_headers()

    def layout(self, title, body):
        nav = ""
        if self.user:
            nav = f"""
            <nav class="topnav">
              <a class="brand" href="/dashboard"><img src="/static/mission-haiti-logo.svg" alt=""><span>Mission-Haiti</span></a>
              <div class="navlinks">
                <a href="/dashboard">Dashboard</a>
                {self.role_links()}
                <form method="post" action="/logout"><button class="linkbtn">Sign out</button></form>
              </div>
            </nav>
            """
        return f"""<!doctype html>
        <html lang="en">
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1">
          <title>{escape(title)} - Mission-Haiti</title>
          <link rel="stylesheet" href="/static/styles.css">
        </head>
        <body>
          {nav}
          <main class="shell">{body}</main>
        </body>
        </html>"""

    def role_links(self):
        role = self.user["role"]
        if role == "sponsor":
            return ""
        links = ['<a href="/students">Students</a>']
        if role == "admin":
            links.append('<a href="/sponsors">Sponsors</a>')
            links.append('<a href="/admins">Admins</a>')
        if role in ("admin", "staff"):
            links.append('<a href="/updates/new">New update</a>')
        return "".join(links)

    def form_fields(self):
        content_type = self.headers.get("Content-Type", "")
        length = int(self.headers.get("Content-Length", "0"))
        if length > MAX_UPLOAD_BYTES:
            raise ValueError("Upload too large")
        if content_type.startswith("multipart/form-data"):
            body = self.rfile.read(length)
            parser_input = f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode() + body
            message = BytesParser(policy=email_policy).parsebytes(parser_input)
            form = MultipartForm()
            for part in message.iter_parts():
                disposition = part.get("Content-Disposition", "")
                if "form-data" not in disposition:
                    continue
                name = part.get_param("name", header="content-disposition")
                if not name:
                    continue
                filename = part.get_filename()
                payload = part.get_payload(decode=True) or b""
                if filename:
                    field = MultipartField(name, filename, part.get_content_type(), payload)
                else:
                    charset = part.get_content_charset() or "utf-8"
                    value = payload.decode(charset, errors="replace")
                    field = MultipartField(name, "", part.get_content_type(), b"", value)
                form.add(field)
            return form
        raw = self.rfile.read(length).decode()
        return urllib.parse.parse_qs(raw)

    def val(self, form, name, default=""):
        if isinstance(form, MultipartForm):
            field = form[name] if name in form else None
            if field is None or getattr(field, "filename", None):
                return default
            return field.value.strip()
        return form.get(name, [default])[0].strip()

    def vals(self, form, name):
        if isinstance(form, MultipartForm):
            if name not in form:
                return []
            fields = form[name] if isinstance(form[name], list) else [form[name]]
            return [f.value for f in fields if not f.filename and f.value]
        return form.get(name, [])

    def optional_int(self, value, label):
        if not value:
            return None
        try:
            number = int(value)
        except ValueError:
            raise ValueError(f"{label} must be a whole number.")
        if number < 0:
            raise ValueError(f"{label} cannot be negative.")
        return number

    def save_file(self, field, kind, uploaded_by, update_id=None):
        if field is None or not getattr(field, "filename", ""):
            return None
        original = Path(field.filename).name
        content_type = field.type or "application/octet-stream"
        storage_name = secrets.token_urlsafe(24)
        target = UPLOAD_DIR / storage_name
        size = 0
        with target.open("wb") as out:
            while True:
                chunk = field.file.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_UPLOAD_BYTES:
                    target.unlink(missing_ok=True)
                    raise ValueError("Upload too large")
                out.write(chunk)
        with db() as conn:
            return conn.execute(
                "INSERT INTO update_files (update_id,kind,original_name,storage_name,content_type,size_bytes,uploaded_by,created_at) VALUES (?,?,?,?,?,?,?,?)",
                (update_id, kind, original, storage_name, content_type, size, uploaded_by, now()),
            ).lastrowid

    def create_password_token(self, conn, user_id, purpose):
        token = secrets.token_urlsafe(40)
        conn.execute(
            "INSERT INTO password_tokens (user_id,token_hash,purpose,expires_at,created_at) VALUES (?,?,?,?,?)",
            (user_id, password_token_hash(token), purpose, token_expires_at(), now()),
        )
        return token

    def send_password_link(self, conn, user, purpose):
        token = self.create_password_token(conn, user["id"], purpose)
        link = f"{APP_BASE_URL}/set-password?token={urllib.parse.quote(token)}"
        verb = "set up" if purpose == "invite" else "reset"
        subject = f"Mission-Haiti sponsor portal password {verb}"
        body = (
            f"Hello {user['name']},\n\n"
            f"Use this secure link to {verb} your Mission-Haiti sponsor portal password:\n"
            f"{link}\n\n"
            "This link expires in 7 days and can only be used once.\n\n"
            "If you did not request this, you can ignore this email.\n\n"
            "Mission-Haiti"
        )
        return send_email(user["email"], subject, body)

    def login_get(self, message=""):
        body = f"""
        <section class="auth">
          <div class="authcopy">
            <img class="authlogo" src="/static/mission-haiti-logo.svg" alt="Mission-Haiti logo">
            <p class="eyebrow">Secure sponsor updates</p>
            <h1>Mission-Haiti portal</h1>
            <p>Staff can create updates for review. Sponsors see only approved updates for students linked to them.</p>
            <div class="photo-strip" aria-hidden="true">
              <img src="/static/students-classroom.png" alt="">
            </div>
          </div>
          <form class="panel" method="post" action="/login">
            <h2>Sign in</h2>
            {f'<p class="alert">{escape(message)}</p>' if message else ''}
            <label>Email <input required type="email" name="email" autocomplete="email"></label>
            <label>Password <input required type="password" name="password" autocomplete="current-password"></label>
            <button class="primary">Sign in</button>
            <p class="muted"><a href="/forgot-password">Set or reset sponsor password</a></p>
            <p class="muted">Demo: admin@mission-haiti.local / admin123</p>
          </form>
        </section>
        """
        return self.send_html(self.layout("Sign in", body))

    def login_post(self):
        form = self.form_fields()
        email = self.val(form, "email").lower()
        password = self.val(form, "password")
        with db() as conn:
            user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if not user or not verify_password(password, user["password_hash"]):
            return self.login_get("Email or password was not recognized.")
        headers = {"Set-Cookie": session_cookie(sign_session(user["id"]))}
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", "/dashboard")
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()

    def forgot_password_get(self, message=""):
        body = f"""
        <section class="auth">
          <div class="authcopy">
            <img class="authlogo" src="/static/mission-haiti-logo.svg" alt="Mission-Haiti logo">
            <p class="eyebrow">Sponsor access</p>
            <h1>Reset password</h1>
            <p>Enter the email on your sponsor record and we will send a secure link to set a new password.</p>
          </div>
          <form class="panel" method="post" action="/forgot-password">
            <h2>Email a secure link</h2>
            {f'<p class="notice">{escape(message)}</p>' if message else ''}
            <label>Email <input required type="email" name="email" autocomplete="email"></label>
            <button class="primary">Send password link</button>
            <p class="muted"><a href="/login">Back to sign in</a></p>
          </form>
        </section>
        """
        return self.send_html(self.layout("Reset password", body))

    def forgot_password_post(self):
        form = self.form_fields()
        email = self.val(form, "email").lower()
        with db() as conn:
            user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
            if user:
                self.send_password_link(conn, user, "reset")
        return self.forgot_password_get("If that email is in the system, a password link has been sent.")

    def set_password_get(self, message=""):
        token = self.query.get("token", [""])[0]
        user = self.user_for_password_token(token)
        if not user:
            body = """
            <section class="auth">
              <div class="authcopy">
                <img class="authlogo" src="/static/mission-haiti-logo.svg" alt="Mission-Haiti logo">
                <p class="eyebrow">Secure sponsor updates</p>
                <h1>Link expired</h1>
                <p>This password link is expired or has already been used.</p>
              </div>
              <div class="panel">
                <h2>Need a new link?</h2>
                <p class="muted">Request another secure password link from the reset page.</p>
                <a class="button primary" href="/forgot-password">Send a new link</a>
              </div>
            </section>
            """
            return self.send_html(self.layout("Set password", body), HTTPStatus.BAD_REQUEST)
        body = f"""
        <section class="auth">
          <div class="authcopy">
            <img class="authlogo" src="/static/mission-haiti-logo.svg" alt="Mission-Haiti logo">
            <p class="eyebrow">Welcome</p>
            <h1>Set your password</h1>
            <p>Create a password for {escape(user["email"])}. After saving, you will be signed in to the secure portal.</p>
          </div>
          <form class="panel" method="post" action="/set-password">
            <h2>Choose a password</h2>
            {f'<p class="alert">{escape(message)}</p>' if message else ''}
            <input type="hidden" name="token" value="{escape(token)}">
            <label>New password <input required type="password" name="password" autocomplete="new-password" minlength="8"></label>
            <label>Confirm password <input required type="password" name="password_confirm" autocomplete="new-password" minlength="8"></label>
            <button class="primary">Save password</button>
          </form>
        </section>
        """
        return self.send_html(self.layout("Set password", body))

    def set_password_post(self):
        form = self.form_fields()
        token = self.val(form, "token")
        password = self.val(form, "password")
        password_confirm = self.val(form, "password_confirm")
        if len(password) < 8:
            self.query = {"token": [token]}
            return self.set_password_get("Please choose a password with at least 8 characters.")
        if password != password_confirm:
            self.query = {"token": [token]}
            return self.set_password_get("The password confirmation did not match.")
        token_hash = password_token_hash(token)
        with db() as conn:
            row = conn.execute(
                """SELECT pt.*, u.* FROM password_tokens pt
                   JOIN users u ON u.id=pt.user_id
                   WHERE pt.token_hash=? AND pt.used_at IS NULL AND pt.expires_at > ?""",
                (token_hash, now()),
            ).fetchone()
            if not row:
                self.query = {"token": [token]}
                return self.set_password_get("This password link is expired or has already been used.")
            conn.execute("UPDATE users SET password_hash=? WHERE id=?", (hash_password(password), row["user_id"]))
            conn.execute("UPDATE password_tokens SET used_at=? WHERE id=?", (now(), row["id"]))
            conn.execute("UPDATE password_tokens SET used_at=? WHERE user_id=? AND used_at IS NULL AND id<>?", (now(), row["user_id"], row["id"]))
            user_id = row["user_id"]
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", "/dashboard")
        self.send_header("Set-Cookie", session_cookie(sign_session(user_id)))
        self.end_headers()

    def user_for_password_token(self, token):
        if not token:
            return None
        with db() as conn:
            return conn.execute(
                """SELECT u.* FROM password_tokens pt
                   JOIN users u ON u.id=pt.user_id
                   WHERE pt.token_hash=? AND pt.used_at IS NULL AND pt.expires_at > ?""",
                (password_token_hash(token), now()),
            ).fetchone()

    def logout_post(self):
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", "/login")
        self.send_header("Set-Cookie", session_cookie("", max_age=0))
        self.end_headers()

    def dashboard(self):
        if self.user["role"] == "sponsor":
            return self.sponsor_dashboard()
        with db() as conn:
            pending = conn.execute("SELECT u.*, s.name student_name FROM updates u JOIN students s ON s.id=u.student_id WHERE u.status='pending' ORDER BY u.submitted_at DESC").fetchall()
            drafts = conn.execute("SELECT u.*, s.name student_name FROM updates u JOIN students s ON s.id=u.student_id WHERE u.status IN ('draft','pending') ORDER BY u.created_at DESC LIMIT 8").fetchall()
            counts = {
                "students": conn.execute("SELECT COUNT(*) FROM students WHERE active=1").fetchone()[0],
                "sponsors": conn.execute("SELECT COUNT(*) FROM sponsors").fetchone()[0],
                "approved": conn.execute("SELECT COUNT(*) FROM updates WHERE status='approved'").fetchone()[0],
            }
        review = "".join(f'<li><a href="/updates/{u["id"]}">{escape(u["student_name"])} update</a> <span class="pill">{escape(u["status"])}</span></li>' for u in (pending if self.user["role"] == "admin" else drafts))
        body = f"""
        <header class="pagehead">
          <div><p class="eyebrow">{escape(ROLES[self.user["role"]])}</p><h1>Dashboard</h1></div>
          <a class="button primary" href="/updates/new">Create update</a>
        </header>
        <section class="mission-banner">
          <img src="/static/students-classroom.png" alt="">
          <div>
            <p class="eyebrow">Privacy-first updates</p>
            <h2>Share progress with the right sponsor, only after approval.</h2>
            <p>Drafts stay internal, admins review before release, and sponsors only see records linked to their own students.</p>
          </div>
        </section>
        <section class="stats">
          <div><strong>{counts["students"]}</strong><span>Active students</span></div>
          <div><strong>{counts["sponsors"]}</strong><span>Sponsors</span></div>
          <div><strong>{counts["approved"]}</strong><span>Approved updates</span></div>
        </section>
        <section class="panel">
          <h2>{'Pending admin review' if self.user["role"] == "admin" else 'Drafts and submitted updates'}</h2>
          <ul class="list">{review or '<li class="muted">No updates waiting right now.</li>'}</ul>
        </section>
        """
        return self.send_html(self.layout("Dashboard", body))

    def sponsor_dashboard(self):
        with db() as conn:
            students = conn.execute(
                """SELECT st.* FROM students st
                   JOIN sponsor_students ss ON ss.student_id=st.id
                   WHERE ss.sponsor_id=? AND st.active=1 ORDER BY st.name""",
                (self.user["sponsor_id"],),
            ).fetchall()
        cards = "".join(self.student_card(s, portal=True) for s in students)
        body = f"""
        <header class="pagehead"><div><p class="eyebrow">Sponsor portal</p><h1>Your students</h1></div></header>
        <section class="mission-banner sponsor">
          <img src="/static/students-classroom.png" alt="">
          <div>
            <p class="eyebrow">Connected with care</p>
            <h2>Approved school updates in one secure place.</h2>
            <p>Each update is reviewed before it appears here, and only linked sponsors can view it.</p>
          </div>
        </section>
        <section class="grid">{cards or '<p class="muted">No students are linked to your account yet.</p>'}</section>
        """
        return self.send_html(self.layout("Sponsor portal", body))

    def student_card(self, student, portal=False):
        url = f"/portal/students/{student['id']}" if portal else f"/students/{student['id']}"
        photo = f'<img alt="" src="/files/{student["profile_photo_file_id"]}">' if student["profile_photo_file_id"] else '<div class="avatar">MH</div>'
        status = "Active" if student["active"] else "Inactive"
        age = f' · Age {escape(student["age"])}' if "age" in student.keys() and student["age"] is not None else ""
        return f"""
        <a class="card" href="{url}">
          {photo}
          <div><h3>{escape(student["name"])}</h3><p>{escape(student["school"])} · {escape(student["grade_level"])}{age}</p><span class="pill">{status}</span></div>
        </a>
        """

    def student_info_list(self, student):
        birthdate = student["birthdate"] or "Not listed"
        age = student["age"] if student["age"] is not None else "Not listed"
        sex = student["sex"] or "Not listed"
        return f"""
        <p><b>School:</b> {escape(student["school"])}</p>
        <p><b>Grade:</b> {escape(student["grade_level"])}</p>
        <p><b>Age:</b> {escape(age)}</p>
        <p><b>Birthdate:</b> {escape(birthdate)}</p>
        <p><b>Sex:</b> {escape(sex)}</p>
        """

    def students_index(self):
        self.require_roles("admin", "staff")
        with db() as conn:
            students = conn.execute("SELECT * FROM students ORDER BY active DESC, name").fetchall()
        body = f"""
        <header class="pagehead"><div><p class="eyebrow">Records</p><h1>Students</h1></div><a class="button primary" href="/students/new">Add student</a></header>
        <section class="grid">{''.join(self.student_card(s) for s in students) or '<p class="muted">No students yet.</p>'}</section>
        """
        return self.send_html(self.layout("Students", body))

    def student_new_get(self, message=""):
        self.require_roles("admin", "staff")
        body = f"""
        <header class="pagehead"><div><p class="eyebrow">Student records</p><h1>Add student</h1></div></header>
        <form class="panel form" method="post" enctype="multipart/form-data">
          {f'<p class="alert">{escape(message)}</p>' if message else ''}
          <p class="hint">Name, school, and grade level are required. The profile photo is optional.</p>
          <label>Name <input required name="name" placeholder="Student name"></label>
          <label>School <input required name="school" placeholder="School name"></label>
          <label>Grade level <input required name="grade_level" placeholder="Example: Grade 4"></label>
          <label>Age <input type="number" min="0" max="30" name="age" placeholder="Example: 11"></label>
          <label>Birthdate <input type="date" name="birthdate"></label>
          <label>Sex <select name="sex"><option value="">Choose one</option><option>Female</option><option>Male</option></select></label>
          <label>Profile photo <input type="file" name="profile_photo" accept=".jpg,.jpeg,.png,image/jpeg,image/png"></label>
          <p class="hint">JPG, JPEG, or PNG photos up to 75 MB.</p>
          <label class="check"><input type="checkbox" name="active" checked> Active</label>
          <button class="primary">Save student</button>
        </form>
        """
        return self.send_html(self.layout("Add student", body))

    def student_new_post(self):
        self.require_roles("admin", "staff")
        try:
            form = self.form_fields()
            name = self.val(form, "name")
            school = self.val(form, "school")
            grade_level = self.val(form, "grade_level")
            age = self.optional_int(self.val(form, "age"), "Age")
            birthdate = self.val(form, "birthdate")
            sex = self.val(form, "sex")
            if not name or not school or not grade_level:
                return self.student_new_get("Please fill in the student name, school, and grade level.")
            photo_field = form["profile_photo"] if isinstance(form, MultipartForm) and "profile_photo" in form else None
            photo_id = self.save_file(photo_field, "profile_photo", self.user["id"])
            with db() as conn:
                student_id = conn.execute(
                    "INSERT INTO students (name,school,grade_level,age,birthdate,sex,profile_photo_file_id,active,created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                    (name, school, grade_level, age, birthdate, sex, photo_id, 1 if self.val(form, "active") else 0, now()),
                ).lastrowid
            return self.redirect(f"/students/{student_id}")
        except ValueError as exc:
            return self.student_new_get(str(exc))
        except (OSError, sqlite3.Error) as exc:
            return self.student_new_get(f"The student could not be saved: {exc}")

    def student_detail(self, student_id):
        self.require_roles("admin", "staff")
        with db() as conn:
            student = conn.execute("SELECT * FROM students WHERE id=?", (student_id,)).fetchone()
            if not student:
                return self.not_found()
            profile_file = conn.execute("SELECT * FROM update_files WHERE id=?", (student["profile_photo_file_id"],)).fetchone() if student["profile_photo_file_id"] else None
            sponsors = conn.execute(
                """SELECT sp.* FROM sponsors sp JOIN sponsor_students ss ON ss.sponsor_id=sp.id WHERE ss.student_id=? ORDER BY sp.name""",
                (student_id,),
            ).fetchall()
            updates = conn.execute("SELECT * FROM updates WHERE student_id=? ORDER BY created_at DESC", (student_id,)).fetchall()
        profile_remove = ""
        if profile_file:
            profile_remove = f"""
            <form method="post" action="/files/{profile_file["id"]}/delete" class="inline-form">
              <button class="danger">Remove profile photo</button>
            </form>
            """
        admin_actions = ""
        if self.user["role"] == "admin":
            admin_actions = f"""
            <a class="button" href="/students/{student_id}/edit">Edit student</a>
            <form method="post" action="/students/{student_id}/delete"><button class="danger">Remove student</button></form>
            """
        body = f"""
        <header class="pagehead"><div><p class="eyebrow">Student</p><h1>{escape(student["name"])}</h1></div><div class="actions">{admin_actions}<a class="button primary" href="/updates/new?student_id={student_id}">Create update</a></div></header>
        <section class="detail">
          <div class="panel">{self.student_card(student)}{self.student_info_list(student)}{profile_remove}</div>
          <div class="panel"><h2>Sponsors</h2><ul class="list">{''.join(f'<li>{escape(s["name"])} · {escape(s["email"])}</li>' for s in sponsors) or '<li class="muted">No linked sponsors.</li>'}</ul></div>
        </section>
        <section class="panel"><h2>Updates</h2><ul class="list">{''.join(f'<li><a href="/updates/{u["id"]}">{escape(u["created_at"][:10])} update</a> <span class="pill">{escape(u["status"])}</span></li>' for u in updates) or '<li class="muted">No updates yet.</li>'}</ul></section>
        """
        return self.send_html(self.layout(student["name"], body))

    def student_edit_get(self, student_id, message=""):
        self.require_roles("admin")
        with db() as conn:
            student = conn.execute("SELECT * FROM students WHERE id=?", (student_id,)).fetchone()
            if not student:
                return self.not_found()
        active_checked = "checked" if student["active"] else ""
        sex_options = "".join(
            f'<option value="{escape(option)}" {"selected" if student["sex"] == option else ""}>{escape(option)}</option>'
            for option in ("Female", "Male")
        )
        body = f"""
        <header class="pagehead"><div><p class="eyebrow">Admin</p><h1>Edit student</h1></div><a class="button" href="/students/{student_id}">Back to student</a></header>
        <form class="panel form" method="post" enctype="multipart/form-data">
          {f'<p class="alert">{escape(message)}</p>' if message else ''}
          <p class="hint">Update the student record. Choose a new profile photo only if you want to replace the current one.</p>
          <label>Name <input required name="name" value="{escape(student["name"])}"></label>
          <label>School <input required name="school" value="{escape(student["school"])}"></label>
          <label>Grade level <input required name="grade_level" value="{escape(student["grade_level"])}"></label>
          <label>Age <input type="number" min="0" max="30" name="age" value="{escape(student["age"] if student["age"] is not None else "")}"></label>
          <label>Birthdate <input type="date" name="birthdate" value="{escape(student["birthdate"] or "")}"></label>
          <label>Sex <select name="sex"><option value="">Choose one</option>{sex_options}</select></label>
          <label>Replace profile photo <input type="file" name="profile_photo" accept=".jpg,.jpeg,.png,image/jpeg,image/png"></label>
          <p class="hint">JPG, JPEG, or PNG photos up to 75 MB.</p>
          <label class="check"><input type="checkbox" name="active" {active_checked}> Active</label>
          <button class="primary">Save changes</button>
        </form>
        """
        return self.send_html(self.layout("Edit student", body))

    def student_edit_post(self, student_id):
        self.require_roles("admin")
        try:
            form = self.form_fields()
            name = self.val(form, "name")
            school = self.val(form, "school")
            grade_level = self.val(form, "grade_level")
            age = self.optional_int(self.val(form, "age"), "Age")
            birthdate = self.val(form, "birthdate")
            sex = self.val(form, "sex")
            if not name or not school or not grade_level:
                return self.student_edit_get(student_id, "Please fill in the student name, school, and grade level.")
            photo_field = form["profile_photo"] if isinstance(form, MultipartForm) and "profile_photo" in form else None
            new_photo_id = self.save_file(photo_field, "profile_photo", self.user["id"])
            with db() as conn:
                student = conn.execute("SELECT * FROM students WHERE id=?", (student_id,)).fetchone()
                if not student:
                    return self.not_found()
                conn.execute(
                    "UPDATE students SET name=?, school=?, grade_level=?, age=?, birthdate=?, sex=?, active=? WHERE id=?",
                    (name, school, grade_level, age, birthdate, sex, 1 if self.val(form, "active") else 0, student_id),
                )
                old_photo_id = student["profile_photo_file_id"]
                if new_photo_id:
                    conn.execute("UPDATE students SET profile_photo_file_id=? WHERE id=?", (new_photo_id, student_id))
                    if old_photo_id:
                        old_file = conn.execute("SELECT storage_name FROM update_files WHERE id=?", (old_photo_id,)).fetchone()
                        conn.execute("DELETE FROM update_files WHERE id=?", (old_photo_id,))
                    else:
                        old_file = None
                else:
                    old_file = None
            if old_file:
                try:
                    (UPLOAD_DIR / old_file["storage_name"]).unlink(missing_ok=True)
                except OSError:
                    pass
            return self.redirect(f"/students/{student_id}")
        except ValueError as exc:
            return self.student_edit_get(student_id, str(exc))
        except (OSError, sqlite3.Error) as exc:
            return self.student_edit_get(student_id, f"The student could not be saved: {exc}")

    def student_delete_post(self, student_id):
        self.require_roles("admin")
        storage_names = []
        try:
            with db() as conn:
                student = conn.execute("SELECT * FROM students WHERE id=?", (student_id,)).fetchone()
                if not student:
                    return self.not_found()
                update_ids = [row["id"] for row in conn.execute("SELECT id FROM updates WHERE student_id=?", (student_id,)).fetchall()]
                if student["profile_photo_file_id"]:
                    file = conn.execute("SELECT storage_name FROM update_files WHERE id=?", (student["profile_photo_file_id"],)).fetchone()
                    if file:
                        storage_names.append(file["storage_name"])
                if update_ids:
                    for file in conn.execute(f"SELECT storage_name FROM update_files WHERE update_id IN ({qmarks(update_ids)})", update_ids).fetchall():
                        storage_names.append(file["storage_name"])
                    conn.execute(f"DELETE FROM email_notifications WHERE update_id IN ({qmarks(update_ids)})", update_ids)
                conn.execute("DELETE FROM sponsor_students WHERE student_id=?", (student_id,))
                conn.execute("DELETE FROM students WHERE id=?", (student_id,))
                if student["profile_photo_file_id"]:
                    conn.execute("DELETE FROM update_files WHERE id=?", (student["profile_photo_file_id"],))
            self.delete_storage_files(storage_names)
            return self.redirect("/students")
        except sqlite3.Error as exc:
            return self.error_page(HTTPStatus.BAD_REQUEST, f"The student could not be removed: {exc}")

    def sponsors_index(self):
        self.require_roles("admin")
        message = self.query.get("message", [""])[0]
        with db() as conn:
            sponsors = conn.execute("SELECT * FROM sponsors ORDER BY name").fetchall()
            links = conn.execute("SELECT ss.sponsor_id, st.name FROM sponsor_students ss JOIN students st ON st.id=ss.student_id ORDER BY st.name").fetchall()
        names = {}
        for link in links:
            names.setdefault(link["sponsor_id"], []).append(link["name"])
        rows = "".join(
            f'<tr><td>{escape(s["name"])}</td><td>{escape(s["email"])}</td><td>{escape(", ".join(names.get(s["id"], [])))}</td><td><div class="actions"><a class="button" href="/sponsors/{s["id"]}/edit">Edit</a><form method="post" action="/sponsors/{s["id"]}/invite"><button>Send password link</button></form><form method="post" action="/sponsors/{s["id"]}/delete"><button class="danger">Remove</button></form></div></td></tr>'
            for s in sponsors
        )
        body = f"""
        <header class="pagehead"><div><p class="eyebrow">Records</p><h1>Sponsors</h1></div><a class="button primary" href="/sponsors/new">Add sponsor</a></header>
        {f'<p class="notice">{escape(message)}</p>' if message else ''}
        <div class="tablewrap"><table><thead><tr><th>Name</th><th>Email</th><th>Linked students</th><th></th></tr></thead><tbody>{rows or '<tr><td colspan="4">No sponsors yet.</td></tr>'}</tbody></table></div>
        """
        return self.send_html(self.layout("Sponsors", body))

    def sponsor_new_get(self):
        self.require_roles("admin")
        with db() as conn:
            students = conn.execute("SELECT * FROM students WHERE active=1 ORDER BY name").fetchall()
        options = "".join(f'<label class="check"><input type="checkbox" name="student_ids" value="{s["id"]}"> {escape(s["name"])}</label>' for s in students)
        body = f"""
        <header class="pagehead"><div><p class="eyebrow">Sponsor records</p><h1>Add sponsor</h1></div></header>
        <form class="panel form" method="post">
          <label>Name <input required name="name"></label>
          <label>Email <input required type="email" name="email"></label>
          <label class="check"><input type="checkbox" name="send_invite" checked> Email this sponsor a secure password setup link</label>
          <fieldset><legend>Linked students</legend>{options or '<p class="muted">Add students first.</p>'}</fieldset>
          <button class="primary">Save sponsor</button>
        </form>
        """
        return self.send_html(self.layout("Add sponsor", body))

    def sponsor_new_post(self):
        self.require_roles("admin")
        form = self.form_fields()
        name, email = self.val(form, "name"), self.val(form, "email").lower()
        send_invite = bool(self.val(form, "send_invite"))
        if not name or not email:
            return self.sponsor_new_get()
        try:
            with db() as conn:
                user_id = conn.execute(
                    "INSERT INTO users (name,email,password_hash,role,created_at) VALUES (?,?,?,?,?)",
                    (name, email, hash_password(secrets.token_urlsafe(32)), "sponsor", now()),
                ).lastrowid
                sponsor_id = conn.execute("INSERT INTO sponsors (name,email,user_id,created_at) VALUES (?,?,?,?)", (name, email, user_id, now())).lastrowid
                conn.execute("UPDATE users SET sponsor_id=? WHERE id=?", (sponsor_id, user_id))
                for student_id in self.vals(form, "student_ids"):
                    conn.execute("INSERT OR IGNORE INTO sponsor_students (sponsor_id,student_id) VALUES (?,?)", (sponsor_id, int(student_id)))
            message = "Sponsor saved."
            if send_invite:
                with db() as conn:
                    user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
                    status, provider_message = self.send_password_link(conn, user, "invite")
                message = f"Sponsor saved. Password setup email {status}: {provider_message}"
            return self.redirect(f"/sponsors?message={urllib.parse.quote(message)}")
        except sqlite3.IntegrityError:
            return self.error_page(HTTPStatus.BAD_REQUEST, "That email is already being used by another account.")
        except sqlite3.Error as exc:
            return self.error_page(HTTPStatus.BAD_REQUEST, f"The sponsor could not be saved: {exc}")

    def sponsor_edit_get(self, sponsor_id, message=""):
        self.require_roles("admin")
        with db() as conn:
            sponsor = conn.execute("SELECT * FROM sponsors WHERE id=?", (sponsor_id,)).fetchone()
            if not sponsor:
                return self.not_found()
            students = conn.execute("SELECT * FROM students ORDER BY active DESC, name").fetchall()
            linked = {row["student_id"] for row in conn.execute("SELECT student_id FROM sponsor_students WHERE sponsor_id=?", (sponsor_id,)).fetchall()}
        options = "".join(
            f'<label class="check"><input type="checkbox" name="student_ids" value="{s["id"]}" {"checked" if s["id"] in linked else ""}> {escape(s["name"])} <span class="muted">{escape(s["grade_level"])}</span></label>'
            for s in students
        )
        body = f"""
        <header class="pagehead"><div><p class="eyebrow">Sponsor records</p><h1>Edit sponsor</h1></div><a class="button" href="/sponsors">Back to sponsors</a></header>
        <form class="panel form" method="post">
          {f'<p class="alert">{escape(message)}</p>' if message else ''}
          <label>Name <input required name="name" value="{escape(sponsor["name"])}"></label>
          <label>Email <input required type="email" name="email" value="{escape(sponsor["email"])}"></label>
          <label>New password <input name="password" placeholder="Leave blank to keep current password"></label>
          <p class="hint">Use "Send password link" on the sponsor list when you want the sponsor to set their own password by email.</p>
          <fieldset><legend>Linked students</legend>{options or '<p class="muted">Add students first.</p>'}</fieldset>
          <button class="primary">Save changes</button>
        </form>
        """
        return self.send_html(self.layout("Edit sponsor", body))

    def sponsor_edit_post(self, sponsor_id):
        self.require_roles("admin")
        form = self.form_fields()
        name = self.val(form, "name")
        email = self.val(form, "email").lower()
        password = self.val(form, "password")
        student_ids = [int(student_id) for student_id in self.vals(form, "student_ids")]
        if not name or not email:
            return self.sponsor_edit_get(sponsor_id, "Please add the sponsor name and email.")
        try:
            with db() as conn:
                sponsor = conn.execute("SELECT * FROM sponsors WHERE id=?", (sponsor_id,)).fetchone()
                if not sponsor:
                    return self.not_found()
                conn.execute("UPDATE sponsors SET name=?, email=? WHERE id=?", (name, email, sponsor_id))
                if sponsor["user_id"]:
                    conn.execute("UPDATE users SET name=?, email=? WHERE id=?", (name, email, sponsor["user_id"]))
                    if password:
                        conn.execute("UPDATE users SET password_hash=? WHERE id=?", (hash_password(password), sponsor["user_id"]))
                else:
                    user_id = conn.execute(
                        "INSERT INTO users (name,email,password_hash,role,sponsor_id,created_at) VALUES (?,?,?,?,?,?)",
                        (name, email, hash_password(password or secrets.token_urlsafe(32)), "sponsor", sponsor_id, now()),
                    ).lastrowid
                    conn.execute("UPDATE sponsors SET user_id=? WHERE id=?", (user_id, sponsor_id))
                conn.execute("DELETE FROM sponsor_students WHERE sponsor_id=?", (sponsor_id,))
                for student_id in student_ids:
                    conn.execute("INSERT OR IGNORE INTO sponsor_students (sponsor_id,student_id) VALUES (?,?)", (sponsor_id, student_id))
            return self.redirect("/sponsors")
        except sqlite3.IntegrityError:
            return self.sponsor_edit_get(sponsor_id, "That email is already being used by another account.")
        except sqlite3.Error as exc:
            return self.sponsor_edit_get(sponsor_id, f"The sponsor could not be saved: {exc}")

    def sponsor_delete_post(self, sponsor_id):
        self.require_roles("admin")
        try:
            with db() as conn:
                sponsor = conn.execute("SELECT * FROM sponsors WHERE id=?", (sponsor_id,)).fetchone()
                if not sponsor:
                    return self.not_found()
                if sponsor["user_id"]:
                    conn.execute("DELETE FROM password_tokens WHERE user_id=?", (sponsor["user_id"],))
                conn.execute("DELETE FROM email_notifications WHERE sponsor_id=?", (sponsor_id,))
                conn.execute("DELETE FROM sponsor_students WHERE sponsor_id=?", (sponsor_id,))
                conn.execute("DELETE FROM sponsors WHERE id=?", (sponsor_id,))
                if sponsor["user_id"]:
                    conn.execute("DELETE FROM users WHERE id=? AND role='sponsor'", (sponsor["user_id"],))
            return self.redirect("/sponsors")
        except sqlite3.Error as exc:
            return self.error_page(HTTPStatus.BAD_REQUEST, f"The sponsor could not be removed: {exc}")

    def sponsor_invite_post(self, sponsor_id):
        self.require_roles("admin")
        try:
            with db() as conn:
                sponsor = conn.execute("SELECT * FROM sponsors WHERE id=?", (sponsor_id,)).fetchone()
                if not sponsor:
                    return self.not_found()
                if sponsor["user_id"]:
                    user = conn.execute("SELECT * FROM users WHERE id=?", (sponsor["user_id"],)).fetchone()
                else:
                    user_id = conn.execute(
                        "INSERT INTO users (name,email,password_hash,role,sponsor_id,created_at) VALUES (?,?,?,?,?,?)",
                        (sponsor["name"], sponsor["email"], hash_password(secrets.token_urlsafe(32)), "sponsor", sponsor_id, now()),
                    ).lastrowid
                    conn.execute("UPDATE sponsors SET user_id=? WHERE id=?", (user_id, sponsor_id))
                    user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
                status, provider_message = self.send_password_link(conn, user, "reset")
            message = f"Password email {status}: {provider_message}"
            return self.redirect(f"/sponsors?message={urllib.parse.quote(message)}")
        except sqlite3.Error as exc:
            return self.error_page(HTTPStatus.BAD_REQUEST, f"The password link could not be sent: {exc}")

    def admins_index(self):
        self.require_roles("admin")
        with db() as conn:
            users = conn.execute("SELECT * FROM users WHERE role IN ('admin','staff') ORDER BY role, name").fetchall()
            admin_count = conn.execute("SELECT COUNT(*) FROM users WHERE role='admin'").fetchone()[0]
        rows = ""
        for user in users:
            action = '<span class="muted">Current user</span>' if user["id"] == self.user["id"] else ""
            if not action:
                if user["role"] == "admin" and admin_count <= 1:
                    action = '<span class="muted">Last admin</span>'
                else:
                    action = f'<form method="post" action="/admins/{user["id"]}/delete"><button class="danger">Remove</button></form>'
            rows += f'<tr><td>{escape(user["name"])}</td><td>{escape(user["email"])}</td><td>{escape(ROLES[user["role"]])}</td><td>{action}</td></tr>'
        body = f"""
        <header class="pagehead"><div><p class="eyebrow">Admin</p><h1>Admins</h1></div></header>
        <div class="tablewrap"><table><thead><tr><th>Name</th><th>Email</th><th>Role</th><th></th></tr></thead><tbody>{rows or '<tr><td colspan="4">No admin users found.</td></tr>'}</tbody></table></div>
        """
        return self.send_html(self.layout("Admins", body))

    def admin_delete_post(self, user_id):
        self.require_roles("admin")
        if user_id == self.user["id"]:
            return self.error_page(HTTPStatus.BAD_REQUEST, "You cannot remove the account you are currently using.")
        try:
            with db() as conn:
                user = conn.execute("SELECT * FROM users WHERE id=? AND role IN ('admin','staff')", (user_id,)).fetchone()
                if not user:
                    return self.not_found()
                admin_count = conn.execute("SELECT COUNT(*) FROM users WHERE role='admin'").fetchone()[0]
                if user["role"] == "admin" and admin_count <= 1:
                    return self.error_page(HTTPStatus.BAD_REQUEST, "You must keep at least one admin account.")
                conn.execute("UPDATE updates SET created_by=? WHERE created_by=?", (self.user["id"], user_id))
                conn.execute("UPDATE updates SET approved_by=? WHERE approved_by=?", (self.user["id"], user_id))
                conn.execute("UPDATE update_files SET uploaded_by=? WHERE uploaded_by=?", (self.user["id"], user_id))
                conn.execute("DELETE FROM users WHERE id=?", (user_id,))
            return self.redirect("/admins")
        except sqlite3.Error as exc:
            return self.error_page(HTTPStatus.BAD_REQUEST, f"The admin account could not be removed: {exc}")

    def update_new_get(self, message=""):
        self.require_roles("admin", "staff")
        selected = self.query.get("student_id", [""])[0]
        with db() as conn:
            students = conn.execute("SELECT * FROM students WHERE active=1 ORDER BY name").fetchall()
        options = "".join(f'<option value="{s["id"]}" {"selected" if str(s["id"]) == selected else ""}>{escape(s["name"])}</option>' for s in students)
        body = f"""
        <header class="pagehead"><div><p class="eyebrow">Draft first</p><h1>Create student update</h1></div></header>
        <form class="panel form" method="post" enctype="multipart/form-data">
          {f'<p class="alert">{escape(message)}</p>' if message else ''}
          <label>Student <select required name="student_id">{options}</select></label>
          <label>Written note <textarea required name="note" rows="7"></textarea></label>
          <label>Grades/report card <input type="file" name="report_card" accept=".pdf,.jpg,.jpeg,.png,.doc,.docx"></label>
          <label>Photos <input type="file" name="photos" accept="image/*" multiple></label>
          <label>Videos <input type="file" name="videos" accept="video/*" multiple></label>
          <button class="primary">Save draft</button>
        </form>
        """
        return self.send_html(self.layout("Create update", body))

    def update_new_post(self):
        self.require_roles("admin", "staff")
        try:
            form = self.form_fields()
            student_id = int(self.val(form, "student_id"))
            note = self.val(form, "note")
            if not note:
                return self.update_new_get("Please add a written note before saving the draft.")
            with db() as conn:
                update_id = conn.execute(
                    "INSERT INTO updates (student_id,note,status,created_by,created_at) VALUES (?,?,?,?,?)",
                    (student_id, note, "draft", self.user["id"], now()),
                ).lastrowid
            if isinstance(form, MultipartForm):
                if "report_card" in form:
                    fid = self.save_file(form["report_card"], "report_card", self.user["id"], update_id)
                    if fid:
                        with db() as conn:
                            conn.execute("UPDATE update_files SET update_id=? WHERE id=?", (update_id, fid))
                for name, kind in (("photos", "photo"), ("videos", "video")):
                    if name in form:
                        fields = form[name] if isinstance(form[name], list) else [form[name]]
                        for field in fields:
                            fid = self.save_file(field, kind, self.user["id"], update_id)
                            if fid:
                                with db() as conn:
                                    conn.execute("UPDATE update_files SET update_id=? WHERE id=?", (update_id, fid))
            return self.redirect(f"/updates/{update_id}")
        except ValueError as exc:
            return self.update_new_get(str(exc))
        except (OSError, sqlite3.Error) as exc:
            return self.update_new_get(f"The update could not be saved: {exc}")

    def update_detail(self, update_id):
        with db() as conn:
            update = conn.execute("SELECT u.*, s.name student_name, s.id student_id FROM updates u JOIN students s ON s.id=u.student_id WHERE u.id=?", (update_id,)).fetchone()
            if not update:
                return self.not_found()
            if self.user["role"] == "sponsor" and not self.sponsor_can_view_student(update["student_id"], approved_only=True):
                raise PermissionError()
            files = conn.execute("SELECT * FROM update_files WHERE update_id=? ORDER BY kind, original_name", (update_id,)).fetchall()
            notifications = conn.execute("SELECT * FROM email_notifications WHERE update_id=? ORDER BY sent_at DESC", (update_id,)).fetchall() if self.user["role"] == "admin" else []
        actions = ""
        if self.user["role"] in ("admin", "staff") and update["status"] == "draft":
            actions += f'<form method="post" action="/updates/{update_id}/submit"><button class="primary">Submit for admin review</button></form>'
        if self.user["role"] == "admin" and update["status"] == "pending":
            actions += f'<form method="post" action="/updates/{update_id}/approve"><button class="primary">Approve and notify sponsors</button></form>'
        if self.user["role"] == "admin" and update["status"] == "approved":
            actions += f'<form method="post" action="/updates/{update_id}/resend"><button class="primary">Resend to sponsors</button></form>'
        email_log = ""
        if self.user["role"] == "admin":
            rows = "".join(
                f'<tr><td>{escape(n["recipient_email"])}</td><td><span class="pill">{escape(n["status"])}</span></td><td>{escape(n["provider_message"] or "")}</td><td>{escape((n["attempted_at"] or n["sent_at"])[:19])}</td><td>{self.email_retry_button(n)}</td></tr>'
                for n in notifications
            )
            email_log = f"""
            <section class="panel">
              <h2>Email notifications</h2>
              <div class="tablewrap"><table><thead><tr><th>Recipient</th><th>Status</th><th>Message</th><th>Time</th><th></th></tr></thead><tbody>{rows or '<tr><td colspan="5">No email notifications yet.</td></tr>'}</tbody></table></div>
            </section>
            """
        body = f"""
        <header class="pagehead"><div><p class="eyebrow">Update</p><h1>{escape(update["student_name"])}</h1></div><span class="pill">{escape(update["status"])}</span></header>
        <section class="panel">
          <p class="note">{escape(update["note"])}</p>
          <div class="actions">{actions}</div>
        </section>
        <section class="panel"><h2>Files</h2>{self.file_list(files)}</section>
        {email_log}
        """
        return self.send_html(self.layout("Student update", body))

    def email_retry_button(self, notification):
        if notification["status"] == "sent":
            return ""
        return f'<form method="post" action="/emails/{notification["id"]}/retry"><button>Retry</button></form>'

    def email_retry(self, notification_id):
        self.require_roles("admin")
        with db() as conn:
            notification = conn.execute("SELECT * FROM email_notifications WHERE id=?", (notification_id,)).fetchone()
            if not notification:
                return self.not_found()
            status, provider_message = send_email(notification["recipient_email"], notification["subject"], notification["body"])
            conn.execute(
                "UPDATE email_notifications SET status=?, provider_message=?, attempted_at=?, sent_at=? WHERE id=?",
                (status, provider_message, now(), now(), notification_id),
            )
            return self.redirect(f"/updates/{notification['update_id']}")

    def update_submit(self, update_id):
        self.require_roles("admin", "staff")
        with db() as conn:
            update = conn.execute("SELECT * FROM updates WHERE id=?", (update_id,)).fetchone()
            if not update:
                return self.not_found()
            if self.user["role"] == "staff" and update["created_by"] != self.user["id"]:
                raise PermissionError()
            conn.execute("UPDATE updates SET status='pending', submitted_at=? WHERE id=?", (now(), update_id))
        return self.redirect(f"/updates/{update_id}")

    def update_approve(self, update_id):
        self.require_roles("admin")
        with db() as conn:
            update = conn.execute("SELECT u.*, s.name student_name FROM updates u JOIN students s ON s.id=u.student_id WHERE u.id=?", (update_id,)).fetchone()
            if not update:
                return self.not_found()
            conn.execute("UPDATE updates SET status='approved', approved_by=?, approved_at=? WHERE id=?", (self.user["id"], now(), update_id))
            self.send_update_notifications(conn, update)
        return self.redirect(f"/updates/{update_id}")

    def update_resend(self, update_id):
        self.require_roles("admin")
        with db() as conn:
            update = conn.execute("SELECT u.*, s.name student_name FROM updates u JOIN students s ON s.id=u.student_id WHERE u.id=?", (update_id,)).fetchone()
            if not update:
                return self.not_found()
            if update["status"] != "approved":
                return self.error_page(HTTPStatus.BAD_REQUEST, "Only approved updates can be resent.")
            self.send_update_notifications(conn, update)
        return self.redirect(f"/updates/{update_id}")

    def send_update_notifications(self, conn, update):
        sponsors = conn.execute(
            """SELECT sp.* FROM sponsors sp JOIN sponsor_students ss ON ss.sponsor_id=sp.id WHERE ss.student_id=?""",
            (update["student_id"],),
        ).fetchall()
        for sponsor in sponsors:
            subject = f"New Mission-Haiti update for {update['student_name']}"
            body = (
                f"Hello {sponsor['name']},\n\n"
                f"A new approved Mission-Haiti update is available for {update['student_name']}.\n\n"
                f"View it in your secure sponsor portal:\n"
                f"{APP_BASE_URL}/portal/students/{update['student_id']}\n\n"
                "For privacy, please do not forward this link. You will need to sign in to view the update.\n\n"
                "Mission-Haiti"
            )
            status, provider_message = send_email(sponsor["email"], subject, body)
            conn.execute(
                "INSERT INTO email_notifications (update_id,sponsor_id,recipient_email,subject,body,sent_at,status,provider_message,attempted_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (update["id"], sponsor["id"], sponsor["email"], subject, body, now(), status, provider_message, now()),
            )

    def portal_student(self, student_id):
        if not self.sponsor_can_view_student(student_id, approved_only=False):
            raise PermissionError()
        with db() as conn:
            student = conn.execute("SELECT * FROM students WHERE id=? AND active=1", (student_id,)).fetchone()
            updates = conn.execute("SELECT * FROM updates WHERE student_id=? AND status='approved' ORDER BY approved_at DESC", (student_id,)).fetchall()
            file_map = {}
            if updates:
                ids = [u["id"] for u in updates]
                for file in conn.execute(f"SELECT * FROM update_files WHERE update_id IN ({qmarks(ids)}) ORDER BY kind, original_name", ids).fetchall():
                    file_map.setdefault(file["update_id"], []).append(file)
        body_updates = ""
        for update in updates:
            body_updates += f"""
            <article class="panel update">
              <p class="eyebrow">{escape((update["approved_at"] or update["created_at"])[:10])}</p>
              <p class="note">{escape(update["note"])}</p>
              {self.file_list(file_map.get(update["id"], []))}
            </article>
            """
        body = f"""
        <header class="pagehead"><div><p class="eyebrow">Sponsor portal</p><h1>{escape(student["name"])}</h1></div></header>
        <section class="detail"><div class="panel">{self.student_card(student, portal=True)}</div><div class="panel"><h2>Student information</h2>{self.student_info_list(student)}</div></section>
        <section>{body_updates or '<div class="panel"><p class="muted">No approved updates yet.</p></div>'}</section>
        """
        return self.send_html(self.layout(student["name"], body))

    def sponsor_can_view_student(self, student_id, approved_only):
        if self.user["role"] != "sponsor":
            return True
        with db() as conn:
            linked = conn.execute(
                "SELECT 1 FROM sponsor_students ss JOIN students st ON st.id=ss.student_id WHERE ss.sponsor_id=? AND ss.student_id=? AND st.active=1",
                (self.user["sponsor_id"], student_id),
            ).fetchone()
            return bool(linked)

    def file_list(self, files):
        if not files:
            return '<p class="muted">No files attached.</p>'
        items = []
        for f in files:
            label = FILE_KINDS.get(f["kind"], f["kind"])
            if f["content_type"].startswith("image/"):
                preview = f'<img class="thumb" alt="" src="/files/{f["id"]}">'
            elif f["content_type"].startswith("video/"):
                preview = f'<video class="thumb" controls preload="metadata" src="/files/{f["id"]}"></video>'
            else:
                preview = '<div class="fileicon">FILE</div>'
            remove = ""
            if self.user and self.user["role"] in ("admin", "staff"):
                remove = f"""
                <form method="post" action="/files/{f["id"]}/delete">
                  <button class="danger">Remove</button>
                </form>
                """
            items.append(f"""
            <div class="filecard">
              <a class="filelink" href="/files/{f["id"]}">
                {preview}
                <span>{escape(label)}</span>
                <b>{escape(f["original_name"])}</b>
              </a>
              {remove}
            </div>
            """)
        return '<div class="files">' + "".join(items) + "</div>"

    def file_get(self, file_id):
        if not self.user:
            return self.redirect("/login")
        with db() as conn:
            file = conn.execute("SELECT * FROM update_files WHERE id=?", (file_id,)).fetchone()
            if not file:
                return self.not_found()
            allowed = self.user["role"] in ("admin", "staff")
            if self.user["role"] == "sponsor":
                if file["kind"] == "profile_photo":
                    allowed = bool(conn.execute("SELECT 1 FROM sponsor_students ss JOIN students st ON st.id=ss.student_id WHERE ss.sponsor_id=? AND st.profile_photo_file_id=?", (self.user["sponsor_id"], file_id)).fetchone())
                elif file["update_id"]:
                    allowed = bool(conn.execute(
                        """SELECT 1 FROM updates u
                           JOIN sponsor_students ss ON ss.student_id=u.student_id
                           WHERE u.id=? AND u.status='approved' AND ss.sponsor_id=?""",
                        (file["update_id"], self.user["sponsor_id"]),
                    ).fetchone())
            if not allowed:
                raise PermissionError()
        path = UPLOAD_DIR / file["storage_name"]
        if not path.exists():
            return self.not_found()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", file["content_type"])
        self.send_header("Content-Length", str(path.stat().st_size))
        self.send_header("Content-Disposition", f'inline; filename="{file["original_name"].replace(chr(34), "")}"')
        self.send_header("Cache-Control", "private, no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        with path.open("rb") as src:
            shutil.copyfileobj(src, self.wfile)

    def file_delete_post(self, file_id):
        self.require_roles("admin", "staff")
        with db() as conn:
            file = conn.execute("SELECT * FROM update_files WHERE id=?", (file_id,)).fetchone()
            if not file:
                return self.not_found()
            conn.execute("UPDATE students SET profile_photo_file_id=NULL WHERE profile_photo_file_id=?", (file_id,))
            conn.execute("DELETE FROM update_files WHERE id=?", (file_id,))
        path = UPLOAD_DIR / file["storage_name"]
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        return self.redirect(self.return_path())

    def delete_storage_files(self, storage_names):
        for storage_name in storage_names:
            try:
                (UPLOAD_DIR / storage_name).unlink(missing_ok=True)
            except OSError:
                pass

    def return_path(self):
        referer = self.headers.get("Referer", "")
        parsed = urllib.parse.urlparse(referer)
        if parsed.netloc == self.headers.get("Host") and parsed.path:
            target = parsed.path
            if parsed.query:
                target += f"?{parsed.query}"
            return target
        return "/dashboard"

    def static_file(self, name):
        safe = Path(name).name
        path = STATIC_DIR / safe
        if not path.exists():
            return self.not_found()
        content_type = {
            ".css": "text/css",
            ".svg": "image/svg+xml",
            ".png": "image/png",
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
        }.get(path.suffix.lower(), "application/octet-stream")
        body = path.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def error_page(self, status, message):
        return self.send_html(self.layout(status.phrase, f'<section class="panel"><h1>{status.value}</h1><p>{escape(message)}</p><a class="button" href="/dashboard">Back to dashboard</a></section>'), status)

    def not_found(self):
        return self.error_page(HTTPStatus.NOT_FOUND, "That page could not be found.")


def main():
    init_db()
    port = int(os.environ.get("PORT", "8000"))
    host = os.environ.get("HOST", "127.0.0.1")
    server = ThreadingHTTPServer((host, port), App)
    print(f"Mission-Haiti MVP running at http://{host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
