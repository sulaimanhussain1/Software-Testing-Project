import csv
import io
import os
import re
import secrets
import uuid
from datetime import datetime, timedelta
from functools import wraps

from flask import (Flask, Response, abort, flash, g, redirect, render_template,
                   request, send_from_directory, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

import db

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.environ.get("TESTBOARD_UPLOADS", os.path.join(BASE_DIR, "uploads"))
os.makedirs(UPLOAD_DIR, exist_ok=True)

ROLES = ("admin", "qa", "dev")
ROLE_LABEL = {"admin": "Administrator", "qa": "QA Tester", "dev": "Developer"}
ROLE_HOME = {"admin": "admin_dashboard", "qa": "qa_dashboard", "dev": "dev_dashboard"}

BUG_STATUSES = ["New", "Assigned", "In Progress", "Fixed", "Reopened", "Closed"]
OPEN_STATUSES = ["New", "Assigned", "In Progress", "Fixed", "Reopened"]
SEVERITIES = ["Critical", "High", "Medium", "Low"]
PRIORITIES = ["Critical", "High", "Medium", "Low"]
EXEC_STATUSES = ["Pass", "Fail", "Blocked", "Skip"]

ALLOWED_EXT = {"png", "jpg", "jpeg", "gif", "webp", "bmp", "pdf", "txt", "log",
               "csv", "json", "xml", "xlsx", "xls", "docx", "doc", "zip",
               "mp4", "webm", "mov"}
IMAGE_EXT = {"png", "jpg", "jpeg", "gif", "webp", "bmp"}
MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_FILES_PER_POST = 5


def get_secret_key():
    env = os.environ.get("TESTBOARD_SECRET")
    if env:
        return env
    path = os.path.join(BASE_DIR, ".secret_key")
    if os.path.exists(path):
        with open(path) as fh:
            return fh.read().strip()
    key = secrets.token_hex(32)
    with open(path, "w") as fh:
        fh.write(key)
    return key


app = Flask(__name__)
app.secret_key = get_secret_key()
app.config.update(
    MAX_CONTENT_LENGTH=MAX_FILES_PER_POST * MAX_FILE_BYTES + 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
)
app.teardown_appcontext(db.close_db)


# ---------- Small helpers ----------

def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def get_form(name, default=""):
    return (request.form.get(name, default) or "").strip()


def safe_next(target):
    if target and target.startswith("/") and not target.startswith("//") and "\\" not in target:
        return target
    return None


def notify(user_ids, message, link=None):
    for user_id in set(u for u in user_ids if u):
        db.get_db().execute(
            "INSERT INTO notifications (user_id, message, link, created_at) VALUES (?,?,?,?)",
            (user_id, message, link, now()))
    db.get_db().commit()


def get_admin_ids():
    return [r["id"] for r in db.query("SELECT id FROM users WHERE role='admin' AND active=1")]


def add_event(bug_id, kind, body=""):
    eid = db.execute(
        "INSERT INTO bug_events (bug_id, user_id, kind, body, created_at) VALUES (?,?,?,?,?)",
        (bug_id, g.user["id"], kind, body, now()))
    db.execute("UPDATE bugs SET updated_at=? WHERE id=?", (now(), bug_id))
    return eid


def save_files(bug_id=None, event_id=None, execution_id=None, field="files"):
    saved, errors = 0, []
    files = [f for f in request.files.getlist(field) if f and f.filename]
    if len(files) > MAX_FILES_PER_POST:
        errors.append(f"Maximum {MAX_FILES_PER_POST} files at a time – extra files ignored.")
        files = files[:MAX_FILES_PER_POST]
    for f in files:
        display = os.path.basename(f.filename.replace("\\", "/"))[:120]
        ext = os.path.splitext(display)[1].lower().lstrip(".")
        if ext not in ALLOWED_EXT:
            errors.append(f"'{display}' skipped – file type .{ext or '?'} not allowed.")
            continue
        f.stream.seek(0, os.SEEK_END)
        size = f.stream.tell()
        f.stream.seek(0)
        if size > MAX_FILE_BYTES:
            errors.append(f"'{display}' skipped – larger than {MAX_FILE_BYTES // (1024 * 1024)} MB.")
            continue
        if size == 0:
            errors.append(f"'{display}' skipped – file is empty.")
            continue
        stored = f"{uuid.uuid4().hex}.{ext}"
        f.save(os.path.join(UPLOAD_DIR, stored))
        db.execute(
            """INSERT INTO attachments (bug_id, event_id, execution_id, original_name,
               stored_name, mime, size, uploaded_by, uploaded_at) VALUES (?,?,?,?,?,?,?,?,?)""",
            (bug_id, event_id, execution_id, display or secure_filename(f.filename) or "file",
             stored, f.mimetype, size, g.user["id"], now()))
        saved += 1
    for e in errors:
        flash(e, "warning")
    return saved


def get_modules():
    rows = db.query("""SELECT module FROM test_cases UNION SELECT module FROM bugs
                       ORDER BY module COLLATE NOCASE""")
    return [r["module"] for r in rows]


def get_users(role, active_only=True):
    sql = "SELECT * FROM users WHERE role=?"
    if active_only:
        sql += " AND active=1"
    return db.query(sql + " ORDER BY full_name COLLATE NOCASE", (role,))


# ---------- Auth, CSRF, permissions ----------

@app.before_request
def before_each_request():
    g.user = None
    user_id = session.get("uid")
    if user_id:
        user = db.query("SELECT * FROM users WHERE id=?", (user_id,), one=True)
        if user and user["active"]:
            g.user = user
        else:
            session.clear()

    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)

    if request.method == "POST":
        sent = request.form.get("_csrf", "")
        if not sent or not secrets.compare_digest(sent, session["csrf"]):
            flash("Your session expired – please try again.", "error")
            return redirect(request.referrer or url_for("login"))


def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if not g.user:
            return redirect(url_for("login", next=request.full_path.rstrip("?")))
        return fn(*a, **kw)
    return wrapper


def role_required(*roles):
    def deco(fn):
        @wraps(fn)
        @login_required
        def wrapper(*a, **kw):
            if g.user["role"] not in roles:
                abort(403)
            return fn(*a, **kw)
        return wrapper
    return deco


@app.errorhandler(403)
def forbidden(_e):
    if not g.get("user"):
        return redirect(url_for("login"))
    return render_template("error.html", code=403, title="Access denied",
                           message="This page belongs to a different role. "
                                   "Use the sidebar to go to your own panel."), 403


@app.errorhandler(404)
def not_found(_e):
    if not g.get("user"):
        return redirect(url_for("login"))
    return render_template("error.html", code=404, title="Page not found",
                           message="The page you are looking for does not exist."), 404


@app.errorhandler(413)
def too_large(_e):
    flash(f"Upload too large – max {MAX_FILE_BYTES // (1024 * 1024)} MB per file, "
          f"{MAX_FILES_PER_POST} files.", "error")
    return redirect(request.referrer or url_for("home"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for(ROLE_HOME[g.user["role"]]))
    if request.method == "POST":
        username = get_form("username").lower()
        password = request.form.get("password", "")
        user = db.query("SELECT * FROM users WHERE username=? OR lower(full_name)=?", (username, username), one=True)
        if user and check_password_hash(user["password_hash"], password):
            if not user["active"]:
                flash("This account has been deactivated. Contact your administrator.", "error")
                return render_template("login.html"), 403
            session.clear()
            session["uid"] = user["id"]
            session.permanent = True
            db.execute("UPDATE users SET last_login=? WHERE id=?", (now(), user["id"]))
            next_page = safe_next(request.args.get("next"))
            return redirect(next_page or url_for(ROLE_HOME[user["role"]]))
        flash("Invalid username or password.", "error")
        return render_template("login.html", username=username), 401
    return render_template("login.html")


@app.post("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


@app.route("/")
def home():
    if not g.user:
        return redirect(url_for("login"))
    return redirect(url_for(ROLE_HOME[g.user["role"]]))


@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    if request.method == "POST":
        current = request.form.get("current", "")
        new = request.form.get("new", "")
        confirm = request.form.get("confirm", "")
        if not check_password_hash(g.user["password_hash"], current):
            flash("Current password is incorrect.", "error")
        elif len(new) < 6:
            flash("New password must be at least 6 characters.", "error")
        elif new != confirm:
            flash("New password and confirmation do not match.", "error")
        else:
            db.execute("UPDATE users SET password_hash=? WHERE id=?",
                       (generate_password_hash(new), g.user["id"]))
            flash("Password changed successfully.", "success")
            return redirect(url_for("account"))
    return render_template("account.html")


# ---------- Template context: navigation, badges, filters ----------

def build_nav(user):
    role = user["role"]
    user_id = user["id"]
    if role == "admin":
        unassigned_bugs = db.query(
            """SELECT COUNT(*) c FROM bugs b LEFT JOIN users d ON d.id=b.assigned_to
               WHERE b.status!='Closed' AND (b.assigned_to IS NULL OR d.active=0)""", one=True)["c"]
        unassigned_tc = db.query(
            """SELECT COUNT(*) c FROM test_cases t LEFT JOIN users q ON q.id=t.assigned_to
               WHERE t.assigned_to IS NULL OR q.active=0""", one=True)["c"]
        return [
            ("Overview", [
                ("admin_dashboard", "Dashboard", "grid", None, ["admin_dashboard"]),
            ]),
            ("Manage Work", [
                ("admin_assign", "Assign Work", "assign", unassigned_bugs + unassigned_tc, ["admin_assign"]),
                ("admin_test_cases", "Test Cases", "file", None,
                 ["admin_test_cases", "tc_new", "tc_edit", "tc_view"]),
                ("admin_bugs", "All Bugs", "bug", None, ["admin_bugs", "bug_detail"]),
            ]),
            ("Administration", [
                ("admin_users", "Users", "users", None, ["admin_users", "admin_user_new", "admin_user_edit"]),
                ("reports", "Reports", "chart", None, ["reports"]),
            ]),
        ]
    if role == "qa":
        pending = db.query(
            """SELECT COUNT(*) c FROM test_cases t WHERE t.assigned_to=?
               AND NOT EXISTS (SELECT 1 FROM executions e WHERE e.test_case_id=t.id)""",
            (user_id,), one=True)["c"]
        verify = db.query("SELECT COUNT(*) c FROM bugs WHERE status='Fixed'", one=True)["c"]
        return [
            ("Overview", [
                ("qa_dashboard", "Dashboard", "grid", None, ["qa_dashboard"]),
            ]),
            ("Testing", [
                ("qa_test_cases", "My Test Cases", "file", pending or None,
                 ["qa_test_cases", "qa_execute", "tc_new", "tc_edit", "tc_view"]),
                ("qa_bug_new", "Report a Bug", "plus", None, ["qa_bug_new"]),
                ("qa_bugs", "Bugs / Verify", "bug", verify or None, ["qa_bugs", "bug_detail"]),
            ]),
            ("Reports", [
                ("reports", "Reports", "chart", None, ["reports"]),
            ]),
        ]
    active = db.query(
        "SELECT COUNT(*) c FROM bugs WHERE assigned_to=? AND status IN ('Assigned','In Progress','Reopened')",
        (user_id,), one=True)["c"]
    return [
        ("Overview", [
            ("dev_dashboard", "Dashboard", "grid", None, ["dev_dashboard"]),
        ]),
        ("My Work", [
            ("dev_bugs", "My Bugs", "bug", active or None, ["dev_bugs", "bug_detail"]),
            ("reports", "Reports", "chart", None, ["reports"]),
        ]),
    ]


@app.context_processor
def template_data():
    ctx = {
        "csrf_token": session.get("csrf", ""),
        "ROLE_LABEL": ROLE_LABEL,
        "BUG_STATUSES": BUG_STATUSES,
        "SEVERITIES": SEVERITIES,
        "PRIORITIES": PRIORITIES,
        "EXEC_STATUSES": EXEC_STATUSES,
        "IMAGE_EXT": IMAGE_EXT,
    }
    if g.get("user"):
        ctx["nav"] = build_nav(g.user)
        ctx["unread"] = db.query(
            "SELECT COUNT(*) c FROM notifications WHERE user_id=? AND is_read=0",
            (g.user["id"],), one=True)["c"]
    return ctx


@app.template_filter("dt")
def show_datetime(value):
    if not value:
        return "—"
    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S").strftime("%d %b %Y, %H:%M")
    except ValueError:
        return value


@app.template_filter("d")
def show_date(value):
    if not value:
        return "—"
    try:
        return datetime.strptime(value[:10], "%Y-%m-%d").strftime("%d %b %Y")
    except ValueError:
        return value


@app.template_filter("slug")
def slug(value):
    return re.sub(r"[^a-z0-9]+", "-", (value or "").lower()).strip("-")


@app.template_filter("filesize")
def file_size(n):
    n = n or 0
    for unit in ("B", "KB", "MB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


@app.template_filter("initials")
def initials(name):
    parts = (name or "?").split()
    return "".join(p[0] for p in parts[:2]).upper()


# ---------- Stats helpers (used by dashboards + reports) ----------

def count_by(sql, args=(), keys=()):
    out = {k: 0 for k in keys}
    for r in db.query(sql, args):
        out[r[0]] = r[1]
    return out


LAST_RESULT = "(SELECT status FROM executions e WHERE e.test_case_id=tc.id ORDER BY e.id DESC LIMIT 1)"


def test_case_counts(where="1=1", args=()):
    return count_by(
        f"""SELECT COALESCE({LAST_RESULT}, 'Not Run') st, COUNT(*)
            FROM test_cases tc WHERE {where} GROUP BY st""",
        args, keys=["Pass", "Fail", "Blocked", "Skip", "Not Run"])


def pass_rate(c):
    done = c["Pass"] + c["Fail"] + c["Blocked"] + c["Skip"]
    return round(c["Pass"] / done * 100) if done else 0


def bug_trend(days=14, where="1=1", args=()):
    labels, reported, closed = [], [], []
    today = datetime.now().date()
    start = today - timedelta(days=days - 1)
    rep = count_by(f"SELECT substr(created_at,1,10), COUNT(*) FROM bugs b WHERE created_at>=? AND {where} GROUP BY 1",
                 (start.isoformat(), *args))
    clo = count_by(f"SELECT substr(closed_at,1,10), COUNT(*) FROM bugs b WHERE closed_at>=? AND {where} GROUP BY 1",
                 (start.isoformat(), *args))
    for i in range(days):
        d = (start + timedelta(days=i)).isoformat()
        labels.append((start + timedelta(days=i)).strftime("%d %b"))
        reported.append(rep.get(d, 0))
        closed.append(clo.get(d, 0))
    return {"labels": labels, "reported": reported, "closed": closed}


def recent_activity(where="1=1", args=(), limit=10):
    return db.query(
        f"""SELECT ev.*, u.full_name, b.bug_code, b.title, b.id AS bid
            FROM bug_events ev JOIN bugs b ON b.id=ev.bug_id
            LEFT JOIN users u ON u.id=ev.user_id
            WHERE {where} ORDER BY ev.id DESC LIMIT {int(limit)}""", args)


def developer_stats():
    return db.query(
        """SELECT u.id, u.full_name,
             COALESCE(SUM(CASE WHEN b.status IN ('Assigned','In Progress','Reopened') THEN 1 ELSE 0 END),0) active,
             COALESCE(SUM(CASE WHEN b.status='Fixed' THEN 1 ELSE 0 END),0) awaiting,
             COALESCE(SUM(CASE WHEN b.status='Closed' THEN 1 ELSE 0 END),0) closed,
             COALESCE(SUM(b.reopen_count),0) reopens,
             AVG(CASE WHEN b.fixed_at IS NOT NULL AND b.assigned_at IS NOT NULL
                 THEN (julianday(b.fixed_at)-julianday(b.assigned_at))*24 END) avg_hours
           FROM users u LEFT JOIN bugs b ON b.assigned_to=u.id
           WHERE u.role='dev' AND u.active=1 GROUP BY u.id ORDER BY u.full_name COLLATE NOCASE""")


def qa_stats():
    return db.query(
        """SELECT u.id, u.full_name,
             (SELECT COUNT(*) FROM test_cases t WHERE t.assigned_to=u.id) assigned,
             (SELECT COUNT(*) FROM test_cases t WHERE t.assigned_to=u.id
                AND NOT EXISTS (SELECT 1 FROM executions e WHERE e.test_case_id=t.id)) pending,
             (SELECT COUNT(*) FROM executions e WHERE e.executed_by=u.id) executed,
             (SELECT COUNT(*) FROM bugs b WHERE b.reported_by=u.id) reported
           FROM users u WHERE u.role='qa' AND u.active=1 ORDER BY u.full_name COLLATE NOCASE""")


# ---------- ADMIN PANEL ----------

@app.route("/admin")
@role_required("admin")
def admin_dashboard():
    bug_status = count_by("SELECT status, COUNT(*) FROM bugs GROUP BY status", keys=BUG_STATUSES)
    bug_sev = count_by("SELECT severity, COUNT(*) FROM bugs WHERE status!='Closed' GROUP BY severity", keys=SEVERITIES)
    bug_mod = db.query("""SELECT module, COUNT(*) c FROM bugs WHERE status!='Closed'
                          GROUP BY module ORDER BY c DESC LIMIT 8""")
    tcs = test_case_counts()
    kpi = {
        "users": db.query("SELECT COUNT(*) c FROM users WHERE active=1", one=True)["c"],
        "tc_total": sum(tcs.values()),
        "tc_unassigned": db.query("SELECT COUNT(*) c FROM test_cases WHERE assigned_to IS NULL", one=True)["c"],
        "pass_rate": pass_rate(tcs),
        "bugs_open": sum(bug_status[s] for s in OPEN_STATUSES),
        "bugs_unassigned": db.query(
            "SELECT COUNT(*) c FROM bugs WHERE assigned_to IS NULL AND status!='Closed'", one=True)["c"],
        "awaiting": bug_status["Fixed"],
        "reopened": bug_status["Reopened"],
    }
    return render_template(
        "admin/dashboard.html", kpi=kpi, bug_status=bug_status, bug_sev=bug_sev,
        bug_mod=[dict(r) for r in bug_mod], tcs=tcs, trend=bug_trend(),
        devs=developer_stats(), qas=qa_stats(), activity=recent_activity())


USERNAME_RE = re.compile(r"^[a-z0-9._-]{3,30}$")


@app.route("/admin/users")
@role_required("admin")
def admin_users():
    role = request.args.get("role", "")
    sql = """SELECT u.*,
               (SELECT COUNT(*) FROM bugs b WHERE b.assigned_to=u.id AND b.status IN ('Assigned','In Progress','Reopened')) dev_active,
               (SELECT COUNT(*) FROM test_cases t WHERE t.assigned_to=u.id) qa_assigned
             FROM users u"""
    args = ()
    if role in ROLES:
        sql += " WHERE u.role=?"
        args = (role,)
    users = db.query(sql + " ORDER BY u.role, u.full_name COLLATE NOCASE", args)
    totals = count_by("SELECT role, COUNT(*) FROM users WHERE active=1 GROUP BY role", keys=ROLES)
    return render_template("admin/users.html", users=users, role=role, totals=totals)


def check_user_form(editing=None):
    full_name = get_form("full_name")
    username = get_form("username").lower()
    role = get_form("role")
    password = request.form.get("password", "")
    errors = []
    if not full_name:
        errors.append("Full name is required.")
    if not USERNAME_RE.match(username):
        errors.append("Username must be 3-30 characters: letters, numbers, dot, dash or underscore.")
    if role not in ROLES:
        errors.append("Please choose a role.")
    if editing is None and len(password) < 6:
        errors.append("Password must be at least 6 characters.")
    if editing is not None and password and len(password) < 6:
        errors.append("New password must be at least 6 characters.")
    dup = db.query("SELECT id FROM users WHERE username=? AND id!=?",
                   (username, editing["id"] if editing else 0), one=True)
    if dup:
        errors.append(f"Username '{username}' is already taken.")
    return dict(full_name=full_name, username=username, role=role, password=password), errors


@app.route("/admin/users/new", methods=["GET", "POST"])
@role_required("admin")
def admin_user_new():
    form = {"role": request.args.get("role", "qa")}
    if request.method == "POST":
        form, errors = check_user_form()
        if errors:
            for e in errors:
                flash(e, "error")
        else:
            db.execute(
                """INSERT INTO users (full_name, username, password_hash, role, created_at)
                   VALUES (?,?,?,?,?)""",
                (form["full_name"], form["username"], generate_password_hash(form["password"]),
                 form["role"], now()))
            flash(f"{ROLE_LABEL[form['role']]} account '{form['username']}' created.", "success")
            return redirect(url_for("admin_users"))
    return render_template("admin/user_form.html", form=form, editing=None)


@app.route("/admin/users/<int:user_id>/edit", methods=["GET", "POST"])
@role_required("admin")
def admin_user_edit(user_id):
    user = db.query("SELECT * FROM users WHERE id=?", (user_id,), one=True) or abort(404)
    if request.method == "POST":
        form, errors = check_user_form(user)
        if user["id"] == g.user["id"] and form["role"] != "admin":
            errors.append("You cannot remove your own admin role.")
        if errors:
            for e in errors:
                flash(e, "error")
            return render_template("admin/user_form.html", form=form, editing=user)
        db.execute("UPDATE users SET full_name=?, username=?, role=? WHERE id=?",
                   (form["full_name"], form["username"], form["role"], user_id))
        if form["password"]:
            db.execute("UPDATE users SET password_hash=? WHERE id=?",
                       (generate_password_hash(form["password"]), user_id))
        flash("User updated.", "success")
        return redirect(url_for("admin_users"))
    return render_template("admin/user_form.html", form=dict(user), editing=user)


@app.post("/admin/users/<int:user_id>/toggle")
@role_required("admin")
def admin_user_toggle(user_id):
    user = db.query("SELECT * FROM users WHERE id=?", (user_id,), one=True) or abort(404)
    if user["id"] == g.user["id"]:
        flash("You cannot deactivate your own account.", "error")
    else:
        new = 0 if user["active"] else 1
        db.execute("UPDATE users SET active=? WHERE id=?", (new, user_id))
        flash(f"{user['full_name']} {'activated' if new else 'deactivated'}.", "success")
    return redirect(request.referrer or url_for("admin_users"))


@app.route("/admin/assign")
@role_required("admin")
def admin_assign():
    show_all = request.args.get("show") == "all"
    bug_where = "b.status!='Closed'" + ("" if show_all else " AND (b.assigned_to IS NULL OR d.active=0)")
    bugs = db.query(
        f"""SELECT b.*, d.full_name developer, r.full_name reporter
            FROM bugs b LEFT JOIN users d ON d.id=b.assigned_to LEFT JOIN users r ON r.id=b.reported_by
            WHERE {bug_where}
            ORDER BY CASE b.severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 ELSE 3 END, b.id""")
    tc_where = "1=1" if show_all else "(tc.assigned_to IS NULL OR q.active=0)"
    tcs = db.query(
        f"""SELECT tc.*, q.full_name qa_name, {LAST_RESULT} last_status
            FROM test_cases tc LEFT JOIN users q ON q.id=tc.assigned_to
            WHERE {tc_where}
            ORDER BY CASE tc.priority WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 ELSE 3 END, tc.id""")
    return render_template("admin/assign.html", bugs=bugs, tcs=tcs, show_all=show_all,
                           devs=get_users("dev"), qas=get_users("qa"),
                           dev_load=developer_stats(), qa_load=qa_stats())


def assign_bug(bug, dev_id):
    dev = db.query("SELECT * FROM users WHERE id=? AND role='dev' AND active=1", (dev_id,), one=True)
    if not dev or bug["status"] == "Closed":
        return False
    new_status = bug["status"] if bug["status"] in ("Reopened", "Fixed") else "Assigned"
    db.execute("UPDATE bugs SET assigned_to=?, assigned_by=?, assigned_at=?, status=? WHERE id=?",
               (dev["id"], g.user["id"], now(), new_status, bug["id"]))
    add_event(bug["id"], "assigned", f"Assigned to {dev['full_name']}")
    notify([dev["id"]], f"{bug['bug_code']} assigned to you: {bug['title']}",
           url_for("bug_detail", bug_id=bug["id"]))
    return True


@app.post("/admin/assign/bugs")
@role_required("admin")
def admin_assign_bugs():
    ids = [int(i) for i in request.form.getlist("ids") if i.isdigit()]
    dev_id = request.form.get("user_id", type=int)
    if not ids or not dev_id:
        flash("Select at least one bug and a developer.", "error")
        return redirect(request.referrer or url_for("admin_assign"))
    done = 0
    for bid in ids:
        bug = db.query("SELECT * FROM bugs WHERE id=?", (bid,), one=True)
        if bug and assign_bug(bug, dev_id):
            done += 1
    flash(f"{done} bug(s) assigned.", "success" if done else "error")
    return redirect(request.referrer or url_for("admin_assign"))


@app.post("/admin/assign/test-cases")
@role_required("admin")
def admin_assign_tcs():
    ids = [int(i) for i in request.form.getlist("ids") if i.isdigit()]
    qa_id = request.form.get("user_id", type=int)
    due = get_form("due_date") or None
    qa = db.query("SELECT * FROM users WHERE id=? AND role='qa' AND active=1", (qa_id,), one=True)
    if not ids or not qa:
        flash("Select at least one test case and a QA tester.", "error")
        return redirect(request.referrer or url_for("admin_assign"))
    for tid in ids:
        db.execute("UPDATE test_cases SET assigned_to=?, assigned_by=?, assigned_at=?, due_date=? WHERE id=?",
                   (qa["id"], g.user["id"], now(), due, tid))
    notify([qa["id"]], f"{len(ids)} test case(s) assigned to you" + (f" (due {due})" if due else ""),
           url_for("qa_test_cases"))
    flash(f"{len(ids)} test case(s) assigned to {qa['full_name']}.", "success")
    return redirect(request.referrer or url_for("admin_assign"))


# ---------- TEST CASES (shared by admin + QA, separate list pages per role) ----------

def show_test_cases(role):
    f_module = request.args.get("module", "")
    f_priority = request.args.get("priority", "")
    f_state = request.args.get("state", "")
    f_qa = request.args.get("qa", "")
    search = request.args.get("search", "").strip()
    where, args = ["1=1"], []
    if role == "qa":
        where.append("tc.assigned_to=?")
        args.append(g.user["id"])
    elif f_qa == "none":
        where.append("tc.assigned_to IS NULL")
    elif f_qa.isdigit():
        where.append("tc.assigned_to=?")
        args.append(int(f_qa))
    if f_module:
        where.append("tc.module=?")
        args.append(f_module)
    if f_priority:
        where.append("tc.priority=?")
        args.append(f_priority)
    if search:
        where.append("(tc.title LIKE ? OR tc.steps LIKE ?)")
        args += [f"%{search}%"] * 2
    inner = f"""SELECT tc.*, q.full_name qa_name, {LAST_RESULT} last_status,
                  (SELECT COUNT(*) FROM bugs b WHERE b.test_case_id=tc.id AND b.status!='Closed') open_bugs
                FROM test_cases tc LEFT JOIN users q ON q.id=tc.assigned_to
                WHERE {' AND '.join(where)}"""
    outer, oargs = "SELECT * FROM (" + inner + ") x", list(args)
    if f_state == "Not Run":
        outer += " WHERE last_status IS NULL"
    elif f_state in EXEC_STATUSES:
        outer += " WHERE last_status=?"
        oargs.append(f_state)
    cases = db.query(outer + " ORDER BY id DESC" if role == "admin" else outer + " ORDER BY (last_status IS NOT NULL), id", oargs)
    base_where = "tc.assigned_to=?" if role == "qa" else "1=1"
    summary = test_case_counts(base_where, (g.user["id"],) if role == "qa" else ())
    tpl = "admin/test_cases.html" if role == "admin" else "qa/test_cases.html"
    return render_template(tpl, cases=cases, summary=summary, modules=get_modules(),
                           qas=get_users("qa"), f=dict(module=f_module, priority=f_priority,
                                                          state=f_state, qa=f_qa, search=search))


@app.route("/admin/test-cases")
@role_required("admin")
def admin_test_cases():
    return show_test_cases("admin")


@app.route("/qa/test-cases")
@role_required("qa")
def qa_test_cases():
    return show_test_cases("qa")


def read_test_case_form(existing=None):
    data = dict(
        title=get_form("title"), module=get_form("module"),
        priority=get_form("priority", "Medium"), steps=get_form("steps"), expected=get_form("expected"),
        assigned_to=request.form.get("assigned_to", type=int), due_date=get_form("due_date") or None)
    errors = []
    if not data["title"]:
        errors.append("Title is required.")
    if not data["module"]:
        errors.append("Module is required.")
    if data["priority"] not in PRIORITIES:
        errors.append("Invalid priority.")
    return data, errors


@app.route("/test-cases/new", methods=["GET", "POST"])
@role_required("admin", "qa")
def tc_new():
    form = {"priority": "Medium"}
    if request.method == "POST":
        form, errors = read_test_case_form()
        if errors:
            for e in errors:
                flash(e, "error")
        else:
            assignee = g.user["id"] if g.user["role"] == "qa" else form["assigned_to"]
            db.execute(
                """INSERT INTO test_cases (title, module, priority, steps, expected, created_by,
                   assigned_to, assigned_by, assigned_at, due_date, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (form["title"], form["module"], form["priority"], form["steps"], form["expected"],
                 g.user["id"], assignee, g.user["id"] if assignee else None,
                 now() if assignee else None, form["due_date"], now()))
            if assignee and assignee != g.user["id"]:
                notify([assignee], f"New test case assigned: {form['title']}", url_for("qa_test_cases"))
            flash("Test case created.", "success")
            return redirect(url_for("admin_test_cases" if g.user["role"] == "admin" else "qa_test_cases"))
    return render_template("tc_form.html", form=form, editing=None, modules=get_modules(),
                           qas=get_users("qa"))


def can_edit_test_case(tc):
    return g.user["role"] == "admin" or (g.user["role"] == "qa" and tc["created_by"] == g.user["id"])


@app.route("/test-cases/<int:tc_id>/edit", methods=["GET", "POST"])
@role_required("admin", "qa")
def tc_edit(tc_id):
    tc = db.query("SELECT * FROM test_cases WHERE id=?", (tc_id,), one=True) or abort(404)
    if not can_edit_test_case(tc):
        abort(403)
    if request.method == "POST":
        form, errors = read_test_case_form(tc)
        if errors:
            for e in errors:
                flash(e, "error")
            return render_template("tc_form.html", form=form, editing=tc, modules=get_modules(),
                                   qas=get_users("qa"))
        db.execute("UPDATE test_cases SET title=?, module=?, priority=?, steps=?, expected=? WHERE id=?",
                   (form["title"], form["module"], form["priority"], form["steps"], form["expected"], tc_id))
        if g.user["role"] == "admin":
            new_qa = form["assigned_to"]
            if new_qa != tc["assigned_to"]:
                db.execute("UPDATE test_cases SET assigned_to=?, assigned_by=?, assigned_at=? WHERE id=?",
                           (new_qa, g.user["id"], now(), tc_id))
                if new_qa:
                    notify([new_qa], f"Test case assigned: {form['title']}", url_for("qa_test_cases"))
            db.execute("UPDATE test_cases SET due_date=? WHERE id=?", (form["due_date"], tc_id))
        flash("Test case updated.", "success")
        return redirect(url_for("tc_view", tc_id=tc_id))
    return render_template("tc_form.html", form=dict(tc), editing=tc, modules=get_modules(),
                           qas=get_users("qa"))


@app.post("/test-cases/<int:tc_id>/delete")
@role_required("admin")
def tc_delete(tc_id):
    db.execute("DELETE FROM test_cases WHERE id=?", (tc_id,))
    flash("Test case deleted.", "info")
    return redirect(url_for("admin_test_cases"))


@app.route("/test-cases/<int:tc_id>")
@role_required("admin", "qa")
def tc_view(tc_id):
    tc = db.query(
        """SELECT tc.*, q.full_name qa_name, c.full_name creator FROM test_cases tc
           LEFT JOIN users q ON q.id=tc.assigned_to LEFT JOIN users c ON c.id=tc.created_by
           WHERE tc.id=?""", (tc_id,), one=True) or abort(404)
    executions = db.query(
        """SELECT e.*, u.full_name tester FROM executions e LEFT JOIN users u ON u.id=e.executed_by
           WHERE e.test_case_id=? ORDER BY e.id DESC""", (tc_id,))
    atts = db.query("SELECT * FROM attachments WHERE execution_id IN (SELECT id FROM executions WHERE test_case_id=?)",
                    (tc_id,))
    exec_files = {}
    for a in atts:
        exec_files.setdefault(a["execution_id"], []).append(a)
    bugs = db.query("SELECT b.*, d.full_name developer FROM bugs b LEFT JOIN users d ON d.id=b.assigned_to "
                    "WHERE b.test_case_id=? ORDER BY b.id DESC", (tc_id,))
    can_execute = g.user["role"] == "qa" and tc["assigned_to"] == g.user["id"]
    return render_template("tc_view.html", tc=tc, executions=executions, exec_files=exec_files,
                           bugs=bugs, can_execute=can_execute, can_edit=can_edit_test_case(tc))


# ---------- QA MODE ----------

@app.route("/qa")
@role_required("qa")
def qa_dashboard():
    user_id = g.user["id"]
    tcs = test_case_counts("tc.assigned_to=?", (user_id,))
    mine = count_by("SELECT status, COUNT(*) FROM bugs WHERE reported_by=? GROUP BY status", (user_id,), keys=BUG_STATUSES)
    to_verify = db.query(
        """SELECT b.*, d.full_name developer FROM bugs b LEFT JOIN users d ON d.id=b.assigned_to
           WHERE b.status='Fixed' ORDER BY b.fixed_at DESC LIMIT 6""")
    todo = db.query(
        """SELECT tc.* FROM test_cases tc WHERE tc.assigned_to=?
            AND NOT EXISTS (SELECT 1 FROM executions e WHERE e.test_case_id=tc.id)
            ORDER BY CASE tc.priority WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 ELSE 3 END,
                     COALESCE(tc.due_date,'9999') LIMIT 6""", (user_id,))
    reopened = db.query("SELECT COUNT(*) c FROM bugs WHERE reported_by=? AND status='Reopened'", (user_id,), one=True)["c"]
    return render_template(
        "qa/dashboard.html", tcs=tcs, mine=mine, to_verify=to_verify, todo=todo,
        total_tc=sum(tcs.values()), rate=pass_rate(tcs), reopened=reopened,
        verify_count=db.query("SELECT COUNT(*) c FROM bugs WHERE status='Fixed'", one=True)["c"],
        trend=bug_trend(14, "b.reported_by=?", (user_id,)),
        activity=recent_activity("b.reported_by=?", (user_id,)))


def create_bug(title, module, severity, steps, expected, actual, build, tc_id=None, exec_id=None):
    bug_id = db.execute(
        """INSERT INTO bugs (bug_code, test_case_id, execution_id, title, module, severity, status,
           steps, expected, actual, build, reported_by, created_at, updated_at)
           VALUES (?,?,?,?,?,?,'New',?,?,?,?,?,?,?)""",
        ("TMP-" + uuid.uuid4().hex[:8], tc_id, exec_id, title, module, severity, steps, expected,
         actual, build, g.user["id"], now(), now()))
    code = f"BUG-{bug_id:03d}"
    db.execute("UPDATE bugs SET bug_code=? WHERE id=?", (code, bug_id))
    add_event(bug_id, "reported", f"Reported by {g.user['full_name']}")
    notify(get_admin_ids(), f"{code} reported ({severity}) – needs assignment: {title}",
           url_for("bug_detail", bug_id=bug_id))
    return bug_id, code


def read_bug_form():
    data = dict(title=get_form("bug_title"), module=get_form("bug_module"),
                severity=get_form("severity", "Medium"), steps=get_form("bug_steps"),
                expected=get_form("bug_expected"), actual=get_form("bug_actual"))
    errors = []
    if not data["title"]:
        errors.append("Bug title is required.")
    if not data["module"]:
        errors.append("Module is required.")
    if data["severity"] not in SEVERITIES:
        errors.append("Invalid severity.")
    return data, errors


@app.route("/qa/execute/<int:tc_id>", methods=["GET", "POST"])
@role_required("qa")
def qa_execute(tc_id):
    tc = db.query("SELECT * FROM test_cases WHERE id=?", (tc_id,), one=True) or abort(404)
    if tc["assigned_to"] != g.user["id"]:
        abort(403)
    history = db.query("SELECT e.*, u.full_name tester FROM executions e LEFT JOIN users u ON u.id=e.executed_by "
                       "WHERE test_case_id=? ORDER BY e.id DESC LIMIT 5", (tc_id,))
    last_build = db.query("SELECT build FROM executions WHERE executed_by=? ORDER BY id DESC LIMIT 1",
                          (g.user["id"],), one=True)
    open_bugs = db.query("SELECT * FROM bugs WHERE test_case_id=? AND status!='Closed' ORDER BY id DESC", (tc_id,))
    form = {"bug_title": f"{tc['title']} – failed", "bug_module": tc["module"], "severity": tc["priority"],
            "bug_steps": tc["steps"], "bug_expected": tc["expected"], "build": last_build["build"] if last_build else ""}

    if request.method == "POST":
        status = get_form("status")
        build = get_form("build")
        actual = get_form("actual")
        notes = get_form("notes")
        want_bug = request.form.get("report_bug") == "1" and status in ("Fail", "Blocked")
        errors = []
        if status not in EXEC_STATUSES:
            errors.append("Please choose a result (Pass / Fail / Blocked / Skip).")
        if status in ("Fail", "Blocked") and not actual:
            errors.append("Describe the actual result for a Fail/Blocked execution.")
        bug_data = {}
        if want_bug:
            bug_data, bug_errors = read_bug_form()
            errors += bug_errors
        if errors:
            for e in errors:
                flash(e, "error")
            form.update(request.form.to_dict())
            form.update(bug_data)
            return render_template("qa/execute.html", tc=tc, history=history, form=form, open_bugs=open_bugs)

        exec_id = db.execute(
            """INSERT INTO executions (test_case_id, status, actual, build, notes, executed_by, executed_at)
               VALUES (?,?,?,?,?,?,?)""", (tc_id, status, actual, build, notes, g.user["id"], now()))
        bug_id = None
        if want_bug:
            bug_id, code = create_bug(bug_data["title"], bug_data["module"], bug_data["severity"],
                                     bug_data["steps"], bug_data["expected"], bug_data["actual"] or actual,
                                     build, tc_id, exec_id)
        n = save_files(bug_id=bug_id, execution_id=exec_id)
        extra = f" {n} file(s) uploaded." if n else ""
        if bug_id:
            flash(f"Result saved as {status}. Bug {code} reported to admin for assignment.{extra}", "warning")
        else:
            flash(f"Result saved as {status}.{extra}", "success")
        return redirect(url_for("qa_test_cases"))
    return render_template("qa/execute.html", tc=tc, history=history, form=form, open_bugs=open_bugs)


@app.route("/qa/bugs/new", methods=["GET", "POST"])
@role_required("qa")
def qa_bug_new():
    form = {"severity": "Medium"}
    if request.method == "POST":
        data, errors = read_bug_form()
        form = {**request.form.to_dict(), **data}
        if errors:
            for e in errors:
                flash(e, "error")
        else:
            bug_id, code = create_bug(data["title"], data["module"], data["severity"], data["steps"],
                                     data["expected"], data["actual"], get_form("build"))
            n = save_files(bug_id=bug_id)
            flash(f"Bug {code} reported" + (f" with {n} file(s)." if n else "."), "success")
            return redirect(url_for("bug_detail", bug_id=bug_id))
    return render_template("qa/bug_new.html", form=form, modules=get_modules())


# ---------- DEVELOPER MODE ----------

@app.route("/dev")
@role_required("dev")
def dev_dashboard():
    user_id = g.user["id"]
    st = count_by("SELECT status, COUNT(*) FROM bugs WHERE assigned_to=? GROUP BY status", (user_id,), keys=BUG_STATUSES)
    sev = count_by("SELECT severity, COUNT(*) FROM bugs WHERE assigned_to=? AND status IN ('Assigned','In Progress','Reopened') "
                 "GROUP BY severity", (user_id,), keys=SEVERITIES)
    queue = db.query(
        """SELECT b.*, r.full_name reporter FROM bugs b LEFT JOIN users r ON r.id=b.reported_by
           WHERE b.assigned_to=? AND b.status IN ('Reopened','In Progress','Assigned')
           ORDER BY CASE b.status WHEN 'Reopened' THEN 0 WHEN 'In Progress' THEN 1 ELSE 2 END,
                    CASE b.severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 ELSE 3 END
           LIMIT 8""", (user_id,))
    me = next((r for r in developer_stats() if r["id"] == user_id), None)
    return render_template("dev/dashboard.html", st=st, sev=sev, queue=queue, me=me,
                           active=st["Assigned"] + st["In Progress"] + st["Reopened"],
                           trend=bug_trend(14, "b.assigned_to=?", (user_id,)),
                           activity=recent_activity("b.assigned_to=?", (user_id,)))


# ---------- BUGS – lists (per role) + shared detail / actions ----------

def show_bugs(role):
    f = dict(status=request.args.get("status", ""), severity=request.args.get("severity", ""),
             module=request.args.get("module", ""), dev=request.args.get("dev", ""),
             mine=request.args.get("mine", ""), search=request.args.get("search", "").strip())
    where, args = ["1=1"], []
    if role == "dev":
        where.append("b.assigned_to=?")
        args.append(g.user["id"])
    if role == "qa" and f["mine"] == "1":
        where.append("b.reported_by=?")
        args.append(g.user["id"])
    if f["status"] == "open":
        where.append("b.status!='Closed'")
    elif f["status"] in BUG_STATUSES:
        where.append("b.status=?")
        args.append(f["status"])
    if f["severity"] in SEVERITIES:
        where.append("b.severity=?")
        args.append(f["severity"])
    if f["module"]:
        where.append("b.module=?")
        args.append(f["module"])
    if role == "admin" and f["dev"] == "none":
        where.append("b.assigned_to IS NULL")
    elif role == "admin" and f["dev"].isdigit():
        where.append("b.assigned_to=?")
        args.append(int(f["dev"]))
    if f["search"]:
        where.append("(b.title LIKE ? OR b.bug_code LIKE ? OR b.steps LIKE ?)")
        args += [f"%{f['search']}%"] * 3
    bugs = db.query(
        f"""SELECT b.*, d.full_name developer, r.full_name reporter FROM bugs b
            LEFT JOIN users d ON d.id=b.assigned_to LEFT JOIN users r ON r.id=b.reported_by
            WHERE {' AND '.join(where)}
            ORDER BY CASE b.status WHEN 'Reopened' THEN 0 WHEN 'Fixed' THEN 1 WHEN 'New' THEN 2
                     WHEN 'Assigned' THEN 3 WHEN 'In Progress' THEN 4 ELSE 5 END,
                     CASE b.severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 ELSE 3 END,
                     b.id DESC""", args)
    scope_where, scope_args = ("b.assigned_to=?", (g.user["id"],)) if role == "dev" else ("1=1", ())
    status_counts = count_by(f"SELECT status, COUNT(*) FROM bugs b WHERE {scope_where} GROUP BY status",
                           scope_args, keys=BUG_STATUSES)
    mods = db.query("SELECT DISTINCT module FROM bugs ORDER BY module COLLATE NOCASE")
    return render_template("bugs_list.html", bugs=bugs, f=f, role=role, status_counts=status_counts,
                           modules=[m["module"] for m in mods], devs=get_users("dev"))


@app.route("/admin/bugs")
@role_required("admin")
def admin_bugs():
    return show_bugs("admin")


@app.route("/qa/bugs")
@role_required("qa")
def qa_bugs():
    return show_bugs("qa")


@app.route("/dev/bugs")
@role_required("dev")
def dev_bugs():
    return show_bugs("dev")


def get_bug(bug_id):
    bug = db.query(
        """SELECT b.*, d.full_name developer, r.full_name reporter, ab.full_name assigner,
                  tc.title tc_title
           FROM bugs b LEFT JOIN users d ON d.id=b.assigned_to LEFT JOIN users r ON r.id=b.reported_by
           LEFT JOIN users ab ON ab.id=b.assigned_by LEFT JOIN test_cases tc ON tc.id=b.test_case_id
           WHERE b.id=?""", (bug_id,), one=True) or abort(404)
    if g.user["role"] == "dev" and bug["assigned_to"] != g.user["id"]:
        abort(403)
    return bug


def bug_permissions(bug):
    role, user_id, st = g.user["role"], g.user["id"], bug["status"]
    mine_dev = role == "dev" and bug["assigned_to"] == user_id
    return {
        "assign": role == "admin" and st != "Closed",
        "start": mine_dev and st in ("Assigned", "Reopened"),
        "fix": mine_dev and st in ("Assigned", "In Progress", "Reopened"),
        "close": role in ("qa", "admin") and st == "Fixed",
        "reopen": role in ("qa", "admin") and st in ("Fixed", "Closed"),
        "comment": True,
    }


@app.route("/bug/<int:bug_id>")
@login_required
def bug_detail(bug_id):
    bug = get_bug(bug_id)
    events = db.query("""SELECT ev.*, u.full_name, u.role FROM bug_events ev LEFT JOIN users u ON u.id=ev.user_id
                         WHERE ev.bug_id=? ORDER BY ev.id""", (bug_id,))
    files = db.query("SELECT * FROM attachments WHERE bug_id=? ORDER BY id", (bug_id,))
    by_event, report_files = {}, []
    for a in files:
        if a["event_id"]:
            by_event.setdefault(a["event_id"], []).append(a)
        else:
            report_files.append(a)
    return render_template("bug_detail.html", bug=bug, events=events, by_event=by_event,
                           report_files=report_files, perms=bug_permissions(bug), devs=get_users("dev"))


@app.post("/bug/<int:bug_id>/<action>")
@login_required
def bug_action(bug_id, action):
    bug = get_bug(bug_id)
    perms = bug_permissions(bug)
    if action not in perms or not perms[action]:
        flash("That action is not allowed for this bug right now.", "error")
        return redirect(url_for("bug_detail", bug_id=bug_id))

    comment = get_form("comment")
    link = url_for("bug_detail", bug_id=bug_id)
    code = bug["bug_code"]

    def with_files(kind, body):
        eid = add_event(bug_id, kind, body)
        return eid, save_files(bug_id=bug_id, event_id=eid)

    if action == "assign":
        dev_id = request.form.get("user_id", type=int)
        if not assign_bug(bug, dev_id):
            flash("Choose an active developer.", "error")
        else:
            if comment:
                add_event(bug_id, "comment", comment)
            flash("Bug assigned.", "success")

    elif action == "start":
        db.execute("UPDATE bugs SET status='In Progress' WHERE id=?", (bug_id,))
        add_event(bug_id, "started", "Started working on this bug")
        notify([bug["reported_by"]], f"{code} is now In Progress", link)
        flash("Marked as In Progress.", "success")

    elif action == "fix":
        if not comment:
            flash("Please describe what you fixed (comment is required).", "error")
        else:
            db.execute("UPDATE bugs SET status='Fixed', fixed_at=?, closed_at=NULL WHERE id=?", (now(), bug_id))
            _, n = with_files("fixed", comment)
            notify([bug["reported_by"]] + get_admin_ids(), f"{code} marked Fixed – ready for QA verification", link)
            flash("Marked as Fixed – QA will verify." + (f" {n} file(s) uploaded." if n else ""), "success")

    elif action == "close":
        db.execute("UPDATE bugs SET status='Closed', closed_at=? WHERE id=?", (now(), bug_id))
        with_files("closed", comment or "Verified – bug closed")
        notify([bug["assigned_to"]], f"{code} verified and Closed", link)
        flash(f"{code} closed.", "success")

    elif action == "reopen":
        if not comment:
            flash("Please explain why the bug is being reopened (comment is required).", "error")
        else:
            db.execute("""UPDATE bugs SET status='Reopened', fixed_at=NULL, closed_at=NULL,
                          reopen_count=reopen_count+1 WHERE id=?""", (bug_id,))
            with_files("reopened", comment)
            notify([bug["assigned_to"]] + get_admin_ids(), f"{code} REOPENED by {g.user['full_name']}", link)
            flash(f"{code} reopened and sent back to the developer.", "warning")

    elif action == "comment":
        files = [f for f in request.files.getlist("files") if f and f.filename]
        if not comment and not files:
            flash("Write a comment or attach a file.", "error")
        else:
            _, n = with_files("comment", comment)
            targets = [bug["reported_by"], bug["assigned_to"]] + get_admin_ids()
            notify([t for t in targets if t != g.user["id"]], f"New comment on {code} by {g.user['full_name']}", link)
            flash("Comment added.", "success")
    return redirect(link)


@app.route("/files/<int:attachment_id>")
@login_required
def download(attachment_id):
    attachment = db.query("SELECT * FROM attachments WHERE id=?", (attachment_id,), one=True) or abort(404)
    if g.user["role"] == "dev":
        bug = db.query("SELECT assigned_to FROM bugs WHERE id=?", (attachment["bug_id"],), one=True) if attachment["bug_id"] else None
        if not bug or bug["assigned_to"] != g.user["id"]:
            abort(403)
    ext = os.path.splitext(attachment["stored_name"])[1].lstrip(".").lower()
    inline = ext in IMAGE_EXT or ext == "pdf"
    if request.args.get("dl") == "1":
        inline = False
    return send_from_directory(UPLOAD_DIR, attachment["stored_name"], as_attachment=not inline,
                               download_name=attachment["original_name"], mimetype=attachment["mime"] or None)


@app.route("/notifications")
@login_required
def notifications():
    rows = db.query("SELECT * FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT 100", (g.user["id"],))
    return render_template("notifications.html", rows=rows)


@app.post("/notifications/read-all")
@login_required
def notifications_read_all():
    db.execute("UPDATE notifications SET is_read=1 WHERE user_id=?", (g.user["id"],))
    return redirect(url_for("notifications"))


@app.route("/notifications/<int:nid>/go")
@login_required
def notification_go(nid):
    n = db.query("SELECT * FROM notifications WHERE id=? AND user_id=?", (nid, g.user["id"]), one=True) or abort(404)
    db.execute("UPDATE notifications SET is_read=1 WHERE id=?", (nid,))
    return redirect(safe_next(n["link"]) or url_for("notifications"))


# ---------- REPORTS (dashboard analytics + CSV export) ----------

def report_filters():
    return dict(build=request.args.get("build", ""), module=request.args.get("module", ""),
                date_from=request.args.get("from", ""), date_to=request.args.get("to", ""))


def bug_filter(f, alias="b"):
    where, args = ["1=1"], []
    if g.user["role"] == "dev":
        where.append(f"{alias}.assigned_to=?")
        args.append(g.user["id"])
    if f["module"]:
        where.append(f"{alias}.module=?")
        args.append(f["module"])
    if f["build"]:
        where.append(f"{alias}.build=?")
        args.append(f["build"])
    if f["date_from"]:
        where.append(f"substr({alias}.created_at,1,10)>=?")
        args.append(f["date_from"])
    if f["date_to"]:
        where.append(f"substr({alias}.created_at,1,10)<=?")
        args.append(f["date_to"])
    return " AND ".join(where), args


def exec_filter(f):
    where, args = ["1=1"], []
    if f["module"]:
        where.append("tc.module=?")
        args.append(f["module"])
    if f["build"]:
        where.append("e.build=?")
        args.append(f["build"])
    if f["date_from"]:
        where.append("substr(e.executed_at,1,10)>=?")
        args.append(f["date_from"])
    if f["date_to"]:
        where.append("substr(e.executed_at,1,10)<=?")
        args.append(f["date_to"])
    return " AND ".join(where), args


@app.route("/reports")
@login_required
def reports():
    f = report_filters()
    bug_where, bug_args = bug_filter(f)
    exec_where, exec_args = exec_filter(f)
    is_dev = g.user["role"] == "dev"
    bug_status = count_by(f"SELECT status, COUNT(*) FROM bugs b WHERE {bug_where} GROUP BY status", bug_args, keys=BUG_STATUSES)
    bug_sev = count_by(f"SELECT severity, COUNT(*) FROM bugs b WHERE {bug_where} GROUP BY severity", bug_args, keys=SEVERITIES)
    bug_mod = db.query(
        f"""SELECT module, COUNT(*) total,
              SUM(CASE WHEN status='Closed' THEN 1 ELSE 0 END) closed,
              SUM(CASE WHEN status!='Closed' THEN 1 ELSE 0 END) open
            FROM bugs b WHERE {bug_where} GROUP BY module ORDER BY total DESC""", bug_args)
    bugs = db.query(
        f"""SELECT b.*, d.full_name developer, r.full_name reporter FROM bugs b
            LEFT JOIN users d ON d.id=b.assigned_to LEFT JOIN users r ON r.id=b.reported_by
            WHERE {bug_where} ORDER BY b.id DESC LIMIT 200""", bug_args)
    ctx = dict(f=f, bug_status=bug_status, bug_sev=bug_sev, bug_mod=bug_mod, bugs=bugs,
               total_bugs=sum(bug_status.values()), is_dev=is_dev,
               modules=get_modules(),
               builds=[r["build"] for r in db.query(
                   "SELECT DISTINCT build FROM executions WHERE build!='' ORDER BY build DESC")])
    if not is_dev:
        ex = count_by(f"""SELECT e.status, COUNT(*) FROM executions e JOIN test_cases tc ON tc.id=e.test_case_id
                        WHERE {exec_where} GROUP BY e.status""", exec_args, keys=EXEC_STATUSES)
        done = sum(ex.values())
        ctx.update(
            ex=ex, ex_total=done, ex_rate=round(ex["Pass"] / done * 100) if done else 0,
            ex_by_module=db.query(
                f"""SELECT tc.module,
                      COUNT(*) total,
                      SUM(CASE WHEN e.status='Pass' THEN 1 ELSE 0 END) passed,
                      SUM(CASE WHEN e.status='Fail' THEN 1 ELSE 0 END) failed,
                      SUM(CASE WHEN e.status='Blocked' THEN 1 ELSE 0 END) blocked,
                      SUM(CASE WHEN e.status='Skip' THEN 1 ELSE 0 END) skipped
                    FROM executions e JOIN test_cases tc ON tc.id=e.test_case_id
                    WHERE {exec_where} GROUP BY tc.module ORDER BY total DESC""", exec_args),
            executions=db.query(
                f"""SELECT e.*, tc.title, tc.module, u.full_name tester FROM executions e
                    JOIN test_cases tc ON tc.id=e.test_case_id LEFT JOIN users u ON u.id=e.executed_by
                    WHERE {exec_where} ORDER BY e.id DESC LIMIT 200""", exec_args),
            tc_state=test_case_counts(),
            devs=developer_stats(), qas=qa_stats())
    return render_template("reports.html", **ctx)


def make_csv(name, header, rows):
    def safe(v):
        v = "" if v is None else str(v)
        return "'" + v if v[:1] in ("=", "+", "-", "@") else v
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(header)
    for r in rows:
        w.writerow([safe(c) for c in r])
    return Response("﻿" + out.getvalue(), mimetype="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="{name}_{datetime.now():%Y%m%d}.csv"'})


@app.route("/reports/export")
@login_required
def reports_export():
    kind = request.args.get("type", "bugs")
    f = report_filters()
    if kind == "bugs":
        bug_where, bug_args = bug_filter(f)
        rows = db.query(
            f"""SELECT b.bug_code, b.title, b.module, b.severity, b.status, r.full_name, d.full_name,
                       b.build, b.created_at, b.assigned_at, b.fixed_at, b.closed_at, b.reopen_count
                FROM bugs b LEFT JOIN users r ON r.id=b.reported_by LEFT JOIN users d ON d.id=b.assigned_to
                WHERE {bug_where} ORDER BY b.id""", bug_args)
        return make_csv("bugs", ["Bug ID", "Title", "Module", "Severity", "Status", "Reported By",
                                      "Assigned To", "Build", "Reported At", "Assigned At", "Fixed At",
                                      "Closed At", "Reopen Count"], [list(r) for r in rows])
    if g.user["role"] == "dev":
        abort(403)
    if kind == "executions":
        exec_where, exec_args = exec_filter(f)
        rows = db.query(
            f"""SELECT tc.id, tc.title, tc.module, e.status, e.build, u.full_name, e.executed_at, e.actual, e.notes
                FROM executions e JOIN test_cases tc ON tc.id=e.test_case_id
                LEFT JOIN users u ON u.id=e.executed_by WHERE {exec_where} ORDER BY e.id""", exec_args)
        return make_csv("executions", ["TC ID", "Test Case", "Module", "Result", "Build", "Executed By",
                                            "Executed At", "Actual Result", "Notes"],
                             [[f"TC-{r[0]:03d}", *list(r)[1:]] for r in rows])
    if kind == "test_cases":
        rows = db.query(f"""SELECT tc.id, tc.title, tc.module, tc.priority, q.full_name, tc.due_date,
                                   COALESCE({LAST_RESULT}, 'Not Run'), tc.steps, tc.expected
                            FROM test_cases tc LEFT JOIN users q ON q.id=tc.assigned_to ORDER BY tc.id""")
        return make_csv("test_cases", ["TC ID", "Title", "Module", "Priority", "Assigned QA", "Due",
                                            "Latest Result", "Steps", "Expected"],
                             [[f"TC-{r[0]:03d}", *list(r)[1:]] for r in rows])
    if kind == "team" and g.user["role"] == "admin":
        rows = [[r["full_name"], "Developer", r["active"], r["awaiting"], r["closed"], r["reopens"],
                 round(r["avg_hours"], 1) if r["avg_hours"] is not None else ""] for r in developer_stats()]
        return make_csv("team_developers", ["Developer", "Role", "Active Bugs", "Awaiting QA", "Closed",
                                                 "Reopens", "Avg Hours To Fix"], rows)
    abort(404)


# ---------- Startup ----------

def bootstrap():
    db.init_db()
    conn = db.connect()
    if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        conn.execute(
            "INSERT INTO users (full_name, username, password_hash, role, created_at) VALUES (?,?,?,?,?)",
            ("Muhammad Shahrukh", "shahrukh", generate_password_hash("41955"), "admin", now()))
        conn.commit()
        print("First run: created admin account  ->  username: shahrukh   password: 41955")
    conn.close()


bootstrap()

if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1", host="127.0.0.1", port=5000)
