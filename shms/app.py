"""
Simple Hospital Management System (SHMS)
----------------------------------------
A LEARNING PROJECT built from the SHMS PRD. Not for real patient data.

Run:  python app.py      then open http://127.0.0.1:5000
"""
import os
import secrets
import sqlite3
from datetime import date, datetime, timedelta
from functools import wraps

from flask import (Flask, abort, flash, g, redirect, render_template,
                   request, session, url_for)
from markupsafe import Markup
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FMT = "%Y-%m-%d %H:%M:%S"
SLOT_MINUTES = 15          # appointment slot length
MAX_FAILED_LOGINS = 5      # FR2: lock after 5 failed logins
LOCK_MINUTES = 15
DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
ROLES = ["Admin", "Receptionist", "Doctor", "Patient"]
PAYMENT_METHODS = ["Cash", "Card", "UPI"]

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-only-change-me")
app.config["DB_PATH"] = os.environ.get("SHMS_DB", os.path.join(BASE_DIR, "hospital.db"))
app.permanent_session_lifetime = timedelta(minutes=30)   # FR2: 30 min idle timeout
app.jinja_env.filters["money"] = lambda v: f"{(v or 0):,.2f}"

# --------------------------------------------------------------------------
# Database
# --------------------------------------------------------------------------
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('Admin','Receptionist','Doctor','Patient')),
    is_active INTEGER NOT NULL DEFAULT 1,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT
);
CREATE TABLE IF NOT EXISTS patients (
    patient_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER REFERENCES users(user_id),
    name TEXT NOT NULL,
    age INTEGER NOT NULL CHECK (age BETWEEN 0 AND 120),
    gender TEXT NOT NULL,
    phone TEXT NOT NULL,
    address TEXT,
    emergency_contact TEXT,
    is_active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS doctors (
    doctor_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER REFERENCES users(user_id),
    name TEXT NOT NULL,
    specialization TEXT NOT NULL,
    consultation_fee REAL NOT NULL DEFAULT 0,
    available_days TEXT NOT NULL,
    available_from TEXT NOT NULL,
    available_to TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS appointments (
    appointment_id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id INTEGER NOT NULL REFERENCES patients(patient_id),
    doctor_id INTEGER NOT NULL REFERENCES doctors(doctor_id),
    date TEXT NOT NULL,
    time_slot TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Scheduled'
        CHECK (status IN ('Scheduled','Completed','Cancelled','No-show')),
    cancel_reason TEXT
);
-- BR1 / FR8: a doctor can have only one live appointment per date + slot.
CREATE UNIQUE INDEX IF NOT EXISTS ux_doctor_slot
    ON appointments(doctor_id, date, time_slot) WHERE status != 'Cancelled';
CREATE TABLE IF NOT EXISTS visit_records (
    record_id INTEGER PRIMARY KEY AUTOINCREMENT,
    appointment_id INTEGER NOT NULL UNIQUE REFERENCES appointments(appointment_id),
    symptoms TEXT,
    diagnosis TEXT NOT NULL,
    prescription TEXT,
    addendum TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS bills (
    bill_id INTEGER PRIMARY KEY AUTOINCREMENT,
    appointment_id INTEGER NOT NULL UNIQUE REFERENCES appointments(appointment_id),
    discount REAL NOT NULL DEFAULT 0,
    total_amount REAL NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'Unpaid' CHECK (status IN ('Paid','Unpaid')),
    payment_method TEXT,
    paid_at TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS bill_items (
    item_id INTEGER PRIMARY KEY AUTOINCREMENT,
    bill_id INTEGER NOT NULL REFERENCES bills(bill_id),
    description TEXT NOT NULL,
    amount REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
    log_id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity TEXT NOT NULL,
    entity_id INTEGER,
    action TEXT NOT NULL,
    details TEXT,
    user_id INTEGER,
    created_at TEXT NOT NULL
);
"""


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DB_PATH"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Create tables and a default admin account (admin / admin123)."""
    db = get_db()
    db.executescript(SCHEMA)
    if not db.execute("SELECT 1 FROM users").fetchone():
        db.execute("INSERT INTO users (username, password_hash, role) VALUES (?,?,?)",
                   ("admin", generate_password_hash("admin123"), "Admin"))
    db.commit()


def now():
    return datetime.now().strftime(FMT)


def parse_date(text):
    try:
        return datetime.strptime(text or "", "%Y-%m-%d").date()
    except ValueError:
        return None


def parse_time(text):
    try:
        return datetime.strptime(text or "", "%H:%M").time()
    except ValueError:
        return None


def audit(entity, entity_id, action, details=""):
    """Record who did what and when (FR5 / NFR audit)."""
    uid = g.user["user_id"] if g.get("user") else None
    get_db().execute(
        "INSERT INTO audit_log (entity, entity_id, action, details, user_id, created_at) "
        "VALUES (?,?,?,?,?,?)", (entity, entity_id, action, details, uid, now()))


# --------------------------------------------------------------------------
# Authentication, roles and CSRF protection
# --------------------------------------------------------------------------
@app.before_request
def load_user():
    g.user, g.doctor_id, g.patient_id = None, None, None
    uid = session.get("user_id")
    if uid:
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE user_id=? AND is_active=1", (uid,)).fetchone()
        if user is None:
            session.clear()
        else:
            g.user = user
            if user["role"] == "Doctor":
                row = db.execute("SELECT doctor_id FROM doctors WHERE user_id=?", (uid,)).fetchone()
                g.doctor_id = row["doctor_id"] if row else None
            elif user["role"] == "Patient":
                row = db.execute("SELECT patient_id FROM patients WHERE user_id=?", (uid,)).fetchone()
                g.patient_id = row["patient_id"] if row else None
    if request.method == "POST":
        token = session.get("csrf_token")
        if not token or token != request.form.get("csrf_token"):
            abort(400, "Invalid or missing security token. Reload the page and try again.")


@app.context_processor
def inject_globals():
    token = session.setdefault("csrf_token", secrets.token_hex(16))
    return dict(
        user=g.get("user"),
        today=date.today().isoformat(),
        csrf_input=lambda: Markup(f'<input type="hidden" name="csrf_token" value="{token}">'),
    )


def login_required(*roles):
    """Allow only logged-in users, optionally restricted to the given roles (FR1)."""
    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            if g.user is None:
                return redirect(url_for("login", next=request.path))
            if roles and g.user["role"] not in roles:
                abort(403)
            return view(*args, **kwargs)
        return wrapper
    return decorator


@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(404)
def http_error(err):
    return render_template("error.html", code=err.code, message=err.description), err.code


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        db = get_db()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        u = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if u and u["locked_until"] and u["locked_until"] > now():
            flash("This account is temporarily locked. Please try again later.", "error")
        elif u and u["is_active"] and check_password_hash(u["password_hash"], password):
            db.execute("UPDATE users SET failed_attempts=0, locked_until=NULL WHERE user_id=?",
                       (u["user_id"],))
            db.commit()
            session.clear()                                  # prevent session fixation
            session["user_id"] = u["user_id"]
            session["csrf_token"] = secrets.token_hex(16)
            session.permanent = True
            nxt = request.args.get("next", "")
            if nxt.startswith("/") and not nxt.startswith("//"):
                return redirect(nxt)
            return redirect(url_for("dashboard"))
        else:
            if u:
                fails, locked = u["failed_attempts"] + 1, None
                if fails >= MAX_FAILED_LOGINS:
                    locked = (datetime.now() + timedelta(minutes=LOCK_MINUTES)).strftime(FMT)
                    fails = 0
                db.execute("UPDATE users SET failed_attempts=?, locked_until=? WHERE user_id=?",
                           (fails, locked, u["user_id"]))
                db.commit()
            flash("Invalid username or password.", "error")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


# --------------------------------------------------------------------------
# Dashboard
# --------------------------------------------------------------------------
APPT_SELECT = """
SELECT a.*, p.name AS patient_name, d.name AS doctor_name,
       (SELECT 1 FROM visit_records v WHERE v.appointment_id = a.appointment_id) AS has_visit,
       (SELECT bill_id FROM bills b WHERE b.appointment_id = a.appointment_id) AS bill_id
FROM appointments a
JOIN patients p ON p.patient_id = a.patient_id
JOIN doctors d ON d.doctor_id = a.doctor_id
"""


def get_appt(aid):
    a = get_db().execute(APPT_SELECT + " WHERE a.appointment_id=?", (aid,)).fetchone()
    if a is None:
        abort(404)
    return a


@app.route("/")
@login_required()
def dashboard():
    if g.user["role"] == "Patient":
        return redirect(url_for("my_records"))
    db = get_db()
    today = date.today().isoformat()
    sql, params = APPT_SELECT + " WHERE a.date=?", [today]
    if g.user["role"] == "Doctor":
        sql += " AND a.doctor_id=?"
        params.append(g.doctor_id)
    todays = db.execute(sql + " ORDER BY a.time_slot", params).fetchall()
    stats = {}
    if g.user["role"] in ("Admin", "Receptionist"):
        stats = {
            "patients": db.execute("SELECT COUNT(*) FROM patients WHERE is_active=1").fetchone()[0],
            "today": len(todays),
            "unpaid": db.execute("SELECT COUNT(*) FROM bills WHERE status='Unpaid'").fetchone()[0],
            "collected": db.execute(
                "SELECT COALESCE(SUM(total_amount),0) FROM bills "
                "WHERE status='Paid' AND substr(paid_at,1,10)=?", (today,)).fetchone()[0],
        }
    return render_template("dashboard.html", todays=todays, stats=stats)


# --------------------------------------------------------------------------
# Patients (FR3 - FR5)
# --------------------------------------------------------------------------
def read_patient_form(form):
    data = {k: form.get(k, "").strip()
            for k in ("name", "age", "gender", "phone", "address", "emergency_contact")}
    errors = []
    if not data["name"]:
        errors.append("Name is required.")
    if not (data["age"].isdigit() and 0 <= int(data["age"]) <= 120):
        errors.append("Age must be a number from 0 to 120.")
    if data["gender"] not in ("Male", "Female", "Other"):
        errors.append("Please choose a gender.")
    if not (data["phone"].isdigit() and len(data["phone"]) == 10):
        errors.append("Phone must be exactly 10 digits.")
    return data, errors


def get_patient(pid):
    p = get_db().execute("SELECT * FROM patients WHERE patient_id=?", (pid,)).fetchone()
    if p is None:
        abort(404)
    return p


@app.route("/patients")
@login_required("Admin", "Receptionist", "Doctor")
def patients():
    q = request.args.get("q", "").strip()
    sql, params = "SELECT * FROM patients", []
    if q:
        sql += " WHERE name LIKE ? OR phone LIKE ?"
        params = [f"%{q}%", f"%{q}%"]
        if q.isdigit():
            sql += " OR patient_id = ?"
            params.append(int(q))
    rows = get_db().execute(sql + " ORDER BY name LIMIT 200", params).fetchall()
    return render_template("patients.html", rows=rows, q=q)


@app.route("/patients/new", methods=["GET", "POST"])
@login_required("Admin", "Receptionist")
def patient_new():
    db = get_db()
    data, errors, dup = {}, [], None
    if request.method == "POST":
        data, errors = read_patient_form(request.form)
        if not errors:
            dup = db.execute("SELECT * FROM patients WHERE lower(name)=lower(?) AND phone=?",
                             (data["name"], data["phone"])).fetchone()
            if not dup or request.form.get("force"):          # FR4: duplicate warning
                cur = db.execute(
                    "INSERT INTO patients (name, age, gender, phone, address, emergency_contact) "
                    "VALUES (?,?,?,?,?,?)",
                    (data["name"], int(data["age"]), data["gender"], data["phone"],
                     data["address"], data["emergency_contact"]))
                audit("patient", cur.lastrowid, "created", data["name"])
                db.commit()
                flash(f"Patient registered. Patient ID: {cur.lastrowid}", "ok")
                return redirect(url_for("patient_detail", pid=cur.lastrowid))
    return render_template("patient_form.html", p=data, errors=errors, dup=dup, editing=False)


@app.route("/patients/<int:pid>")
@login_required("Admin", "Receptionist", "Doctor")
def patient_detail(pid):
    db = get_db()
    p = get_patient(pid)
    appts = db.execute(APPT_SELECT + " WHERE a.patient_id=? ORDER BY a.date DESC, a.time_slot DESC",
                       (pid,)).fetchall()
    history = []
    if g.user["role"] in ("Admin", "Doctor"):                  # FR12: visit history
        history = db.execute(
            "SELECT v.*, a.date, a.time_slot, d.name AS doctor_name FROM visit_records v "
            "JOIN appointments a ON a.appointment_id=v.appointment_id "
            "JOIN doctors d ON d.doctor_id=a.doctor_id WHERE a.patient_id=? "
            "ORDER BY a.date DESC, a.time_slot DESC", (pid,)).fetchall()
    return render_template("patient_detail.html", p=p, appts=appts, history=history)


@app.route("/patients/<int:pid>/edit", methods=["GET", "POST"])
@login_required("Admin", "Receptionist")
def patient_edit(pid):
    db = get_db()
    p = get_patient(pid)
    errors, data = [], dict(p)
    if request.method == "POST":
        data, errors = read_patient_form(request.form)
        if not errors:
            changes = [f"{k}: '{p[k] or ''}' -> '{data[k]}'"
                       for k in data if str(p[k] or "") != data[k]]
            db.execute("UPDATE patients SET name=?, age=?, gender=?, phone=?, address=?, "
                       "emergency_contact=? WHERE patient_id=?",
                       (data["name"], int(data["age"]), data["gender"], data["phone"],
                        data["address"], data["emergency_contact"], pid))
            audit("patient", pid, "edited", "; ".join(changes) or "no changes")
            db.commit()
            flash("Patient details updated.", "ok")
            return redirect(url_for("patient_detail", pid=pid))
    return render_template("patient_form.html", p=data, errors=errors, dup=None,
                           editing=True, pid=pid)


@app.route("/patients/<int:pid>/toggle", methods=["POST"])
@login_required("Admin", "Receptionist")
def patient_toggle(pid):
    p = get_patient(pid)
    new = 0 if p["is_active"] else 1
    get_db().execute("UPDATE patients SET is_active=? WHERE patient_id=?", (new, pid))
    audit("patient", pid, "activated" if new else "deactivated")   # BR5: never delete
    get_db().commit()
    return redirect(url_for("patient_detail", pid=pid))


# --------------------------------------------------------------------------
# Doctors (FR6)
# --------------------------------------------------------------------------
def read_doctor_form(form):
    data = {k: form.get(k, "").strip()
            for k in ("name", "specialization", "consultation_fee", "available_from", "available_to")}
    days = [d for d in DAYS if d in form.getlist("days")]
    errors = []
    if not data["name"] or not data["specialization"]:
        errors.append("Name and specialization are required.")
    try:
        if float(data["consultation_fee"]) < 0:
            raise ValueError
    except ValueError:
        errors.append("Consultation fee must be a number, 0 or more.")
    if not days:
        errors.append("Select at least one available day.")
    t1, t2 = parse_time(data["available_from"]), parse_time(data["available_to"])
    if not t1 or not t2 or t1 >= t2:
        errors.append("Available hours must be valid and 'from' must be before 'to'.")
    return data, days, errors


def get_doctor(did):
    d = get_db().execute("SELECT * FROM doctors WHERE doctor_id=?", (did,)).fetchone()
    if d is None:
        abort(404)
    return d


@app.route("/doctors")
@login_required("Admin", "Receptionist")
def doctors():
    rows = get_db().execute("SELECT * FROM doctors ORDER BY name").fetchall()
    return render_template("doctors.html", rows=rows)


@app.route("/doctors/new", methods=["GET", "POST"])
@app.route("/doctors/<int:did>/edit", methods=["GET", "POST"])
@login_required("Admin")
def doctor_form(did=None):
    db = get_db()
    doc = get_doctor(did) if did else None
    data = dict(doc) if doc else {"available_from": "09:00", "available_to": "17:00"}
    sel_days = doc["available_days"].split(",") if doc else ["Mon", "Tue", "Wed", "Thu", "Fri"]
    errors = []
    if request.method == "POST":
        data, sel_days, errors = read_doctor_form(request.form)
        if not errors:
            vals = (data["name"], data["specialization"], float(data["consultation_fee"]),
                    ",".join(sel_days), data["available_from"], data["available_to"])
            if doc:
                db.execute("UPDATE doctors SET name=?, specialization=?, consultation_fee=?, "
                           "available_days=?, available_from=?, available_to=? WHERE doctor_id=?",
                           vals + (did,))
                audit("doctor", did, "edited", data["name"])
            else:
                cur = db.execute("INSERT INTO doctors (name, specialization, consultation_fee, "
                                 "available_days, available_from, available_to) VALUES (?,?,?,?,?,?)", vals)
                audit("doctor", cur.lastrowid, "created", data["name"])
            db.commit()
            flash("Doctor saved.", "ok")
            return redirect(url_for("doctors"))
    return render_template("doctor_form.html", d=data, days=DAYS, sel_days=sel_days,
                           errors=errors, editing=bool(doc))


@app.route("/doctors/<int:did>/toggle", methods=["POST"])
@login_required("Admin")
def doctor_toggle(did):
    d = get_doctor(did)
    new = 0 if d["is_active"] else 1
    get_db().execute("UPDATE doctors SET is_active=? WHERE doctor_id=?", (new, did))
    audit("doctor", did, "activated" if new else "deactivated")    # FR6: deactivate, never delete
    get_db().commit()
    return redirect(url_for("doctors"))


# --------------------------------------------------------------------------
# User accounts (FR1)
# --------------------------------------------------------------------------
@app.route("/users", methods=["GET", "POST"])
@login_required("Admin")
def users():
    db = get_db()
    errors = []
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "")
        link_id = request.form.get("link_id", type=int)
        if not username:
            errors.append("Username is required.")
        elif db.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
            errors.append("That username already exists.")
        if len(password) < 6:
            errors.append("Password must be at least 6 characters.")
        if role not in ROLES:
            errors.append("Choose a valid role.")
        table, key = {"Doctor": ("doctors", "doctor_id"), "Patient": ("patients", "patient_id")}.get(role, (None, None))
        if table and not db.execute(f"SELECT 1 FROM {table} WHERE {key}=? AND user_id IS NULL",
                                    (link_id,)).fetchone():
            errors.append(f"Choose the {role.lower()} record this account belongs to.")
        if not errors:
            cur = db.execute("INSERT INTO users (username, password_hash, role) VALUES (?,?,?)",
                             (username, generate_password_hash(password), role))
            if table:
                db.execute(f"UPDATE {table} SET user_id=? WHERE {key}=?", (cur.lastrowid, link_id))
            audit("user", cur.lastrowid, "created", f"{username} ({role})")
            db.commit()
            flash("Account created.", "ok")
            return redirect(url_for("users"))
    return render_template(
        "users.html", errors=errors, roles=ROLES,
        rows=db.execute("SELECT * FROM users ORDER BY user_id").fetchall(),
        free_doctors=db.execute("SELECT doctor_id, name FROM doctors WHERE user_id IS NULL AND is_active=1").fetchall(),
        free_patients=db.execute("SELECT patient_id, name FROM patients WHERE user_id IS NULL AND is_active=1").fetchall())


@app.route("/users/<int:uid>/toggle", methods=["POST"])
@login_required("Admin")
def user_toggle(uid):
    if uid == g.user["user_id"]:
        flash("You cannot deactivate your own account.", "error")
    else:
        db = get_db()
        u = db.execute("SELECT * FROM users WHERE user_id=?", (uid,)).fetchone() or abort(404)
        db.execute("UPDATE users SET is_active=? WHERE user_id=?", (0 if u["is_active"] else 1, uid))
        audit("user", uid, "deactivated" if u["is_active"] else "activated", u["username"])
        db.commit()
    return redirect(url_for("users"))


# --------------------------------------------------------------------------
# Appointments (FR7 - FR10)
# --------------------------------------------------------------------------
def free_slots(doctor, day, exclude_appt=None):
    """Free slots for a doctor on a date (FR14): inside their hours, not booked, not in the past."""
    d = parse_date(day)
    if d is None or DAYS[d.weekday()] not in doctor["available_days"].split(","):
        return []
    start = datetime.combine(d, parse_time(doctor["available_from"]))
    end = datetime.combine(d, parse_time(doctor["available_to"]))
    sql = "SELECT time_slot FROM appointments WHERE doctor_id=? AND date=? AND status!='Cancelled'"
    params = [doctor["doctor_id"], day]
    if exclude_appt:
        sql += " AND appointment_id!=?"
        params.append(exclude_appt)
    booked = {r["time_slot"] for r in get_db().execute(sql, params)}
    slots, t = [], start
    while t + timedelta(minutes=SLOT_MINUTES) <= end:
        label = t.strftime("%H:%M")
        if label not in booked and t > datetime.now():
            slots.append(label)
        t += timedelta(minutes=SLOT_MINUTES)
    return slots


@app.route("/appointments")
@login_required("Admin", "Receptionist", "Doctor")
def appointments():
    day = request.args.get("date", date.today().isoformat())   # blank = all dates
    doctor_id = request.args.get("doctor_id", type=int)
    status = request.args.get("status", "")
    sql, params = APPT_SELECT + " WHERE 1=1", []
    if day:
        sql += " AND a.date=?"
        params.append(day)
    if g.user["role"] == "Doctor":
        doctor_id = g.doctor_id
    if doctor_id:
        sql += " AND a.doctor_id=?"
        params.append(doctor_id)
    if status:
        sql += " AND a.status=?"
        params.append(status)
    rows = get_db().execute(sql + " ORDER BY a.date, a.time_slot", params).fetchall()
    doctors_ = get_db().execute("SELECT doctor_id, name FROM doctors ORDER BY name").fetchall()
    return render_template("appointments.html", rows=rows, day=day, doctor_id=doctor_id,
                           status=status, doctors=doctors_)


@app.route("/appointments/new", methods=["GET", "POST"])
@login_required("Admin", "Receptionist")
def appointment_new():
    db = get_db()
    patient_id = request.values.get("patient_id", type=int)
    doctor_id = request.values.get("doctor_id", type=int)
    day = request.values.get("date", "")
    errors, slots, checked = [], [], False
    patient = db.execute("SELECT * FROM patients WHERE patient_id=? AND is_active=1", (patient_id,)).fetchone()
    doctor = db.execute("SELECT * FROM doctors WHERE doctor_id=? AND is_active=1", (doctor_id,)).fetchone()
    if request.method == "POST" or (patient_id and doctor_id and day):
        d = parse_date(day)
        if not patient or not doctor:
            errors.append("Choose an active patient and an active doctor.")
        elif d is None:
            errors.append("Choose a valid date.")
        elif d < date.today():
            errors.append("Past dates cannot be booked.")                       # FR19
        else:
            checked, slots = True, free_slots(doctor, day)
    if request.method == "POST" and not errors:
        slot = request.form.get("slot", "")
        if slot not in slots:
            errors.append("That slot is not available. Please choose another one.")
        else:
            try:
                cur = db.execute("INSERT INTO appointments (patient_id, doctor_id, date, time_slot) "
                                 "VALUES (?,?,?,?)", (patient_id, doctor_id, day, slot))
            except sqlite3.IntegrityError:                                      # FR8 (double booking)
                errors.append("Sorry, that slot was just booked by someone else.")
            else:
                audit("appointment", cur.lastrowid, "booked", f"{patient['name']} with {doctor['name']} {day} {slot}")
                db.commit()
                flash("Appointment booked.", "ok")
                return redirect(url_for("appointments", date=day))
        slots = free_slots(doctor, day) if doctor else []
    return render_template(
        "appointment_form.html", appt=None, errors=errors, slots=slots, checked=checked, day=day,
        patient_id=patient_id, doctor_id=doctor_id,
        patients=db.execute("SELECT patient_id, name, phone FROM patients WHERE is_active=1 ORDER BY name").fetchall(),
        doctors=db.execute("SELECT doctor_id, name, specialization FROM doctors WHERE is_active=1 ORDER BY name").fetchall())


@app.route("/appointments/<int:aid>/reschedule", methods=["GET", "POST"])
@login_required("Admin", "Receptionist")
def appointment_reschedule(aid):
    db = get_db()
    appt = get_appt(aid)
    if appt["status"] != "Scheduled":
        abort(403, "Only scheduled appointments can be rescheduled.")
    doctor = get_doctor(appt["doctor_id"])
    day = request.values.get("date", "")
    errors, slots, checked = [], [], False
    if day:
        d = parse_date(day)
        if d is None:
            errors.append("Choose a valid date.")
        elif d < date.today():
            errors.append("Past dates cannot be booked.")
        else:
            checked, slots = True, free_slots(doctor, day, exclude_appt=aid)
    if request.method == "POST" and not errors:
        slot = request.form.get("slot", "")
        if slot not in slots:
            errors.append("That slot is not available. Please choose another one.")
        else:
            try:
                db.execute("UPDATE appointments SET date=?, time_slot=? WHERE appointment_id=?", (day, slot, aid))
            except sqlite3.IntegrityError:
                errors.append("Sorry, that slot was just booked by someone else.")
            else:
                audit("appointment", aid, "rescheduled", f"{appt['date']} {appt['time_slot']} -> {day} {slot}")
                db.commit()
                flash("Appointment rescheduled.", "ok")
                return redirect(url_for("appointments", date=day))
        slots = free_slots(doctor, day, exclude_appt=aid)
    return render_template("appointment_form.html", appt=appt, errors=errors, slots=slots,
                           checked=checked, day=day, patient_id=None, doctor_id=None,
                           patients=[], doctors=[])


@app.route("/appointments/<int:aid>/cancel", methods=["POST"])
@login_required("Admin", "Receptionist")
def appointment_cancel(aid):
    appt = get_appt(aid)
    reason = request.form.get("reason", "").strip()
    if appt["status"] != "Scheduled":
        flash("Only scheduled appointments can be cancelled.", "error")
    elif not reason:
        flash("Please give a reason for cancelling.", "error")
    else:
        get_db().execute("UPDATE appointments SET status='Cancelled', cancel_reason=? WHERE appointment_id=?",
                         (reason, aid))
        audit("appointment", aid, "cancelled", reason)
        get_db().commit()
        flash("Appointment cancelled. The slot is free again.", "ok")
    return redirect(request.referrer or url_for("appointments"))


@app.route("/appointments/<int:aid>/noshow", methods=["POST"])
@login_required("Admin", "Receptionist")
def appointment_noshow(aid):
    appt = get_appt(aid)
    if appt["status"] == "Scheduled":
        get_db().execute("UPDATE appointments SET status='No-show' WHERE appointment_id=?", (aid,))
        audit("appointment", aid, "no-show")
        get_db().commit()
    return redirect(request.referrer or url_for("appointments"))


# --------------------------------------------------------------------------
# Visit records (FR11, FR12)
# --------------------------------------------------------------------------
def doctor_owns(appt):
    return g.user["role"] == "Doctor" and g.doctor_id == appt["doctor_id"]


@app.route("/appointments/<int:aid>/visit", methods=["GET", "POST"])
@login_required("Admin", "Doctor")
def visit(aid):
    db = get_db()
    appt = get_appt(aid)
    if g.user["role"] == "Doctor" and not doctor_owns(appt):
        abort(403, "This appointment belongs to another doctor.")
    rec = db.execute("SELECT * FROM visit_records WHERE appointment_id=?", (aid,)).fetchone()
    errors = []
    can_write = doctor_owns(appt)
    if request.method == "POST":
        if not can_write or rec or appt["status"] != "Scheduled":     # BR6, one record per visit
            abort(403, "A visit record can be added once, by the treating doctor, for a scheduled appointment.")
        symptoms = request.form.get("symptoms", "").strip()
        diagnosis = request.form.get("diagnosis", "").strip()
        prescription = request.form.get("prescription", "").strip()
        if not diagnosis:
            errors.append("Diagnosis is required.")
        else:
            cur = db.execute("INSERT INTO visit_records (appointment_id, symptoms, diagnosis, prescription, created_at) "
                             "VALUES (?,?,?,?,?)", (aid, symptoms, diagnosis, prescription, now()))
            db.execute("UPDATE appointments SET status='Completed' WHERE appointment_id=?", (aid,))   # FR21
            audit("visit_record", cur.lastrowid, "created", f"appointment {aid}")
            db.commit()
            flash("Visit record saved. Appointment marked Completed.", "ok")
            return redirect(url_for("visit", aid=aid))
    return render_template("visit.html", a=appt, rec=rec, errors=errors, can_write=can_write,
                           form=request.form)


@app.route("/appointments/<int:aid>/addendum", methods=["POST"])
@login_required("Doctor")
def visit_addendum(aid):
    """Records are never edited or deleted; corrections are appended as dated notes (FR23)."""
    db = get_db()
    appt = get_appt(aid)
    rec = db.execute("SELECT * FROM visit_records WHERE appointment_id=?", (aid,)).fetchone()
    if not doctor_owns(appt) or not rec:
        abort(403)
    note = request.form.get("note", "").strip()
    if note:
        text = (rec["addendum"] or "") + f"[{now()}] {note}\n"
        db.execute("UPDATE visit_records SET addendum=? WHERE record_id=?", (text, rec["record_id"]))
        audit("visit_record", rec["record_id"], "addendum added")
        db.commit()
    return redirect(url_for("visit", aid=aid))


# --------------------------------------------------------------------------
# Billing (FR13 - FR15)
# --------------------------------------------------------------------------
def recalc_bill(bill_id):
    db = get_db()
    subtotal = db.execute("SELECT COALESCE(SUM(amount),0) FROM bill_items WHERE bill_id=?", (bill_id,)).fetchone()[0]
    discount = db.execute("SELECT discount FROM bills WHERE bill_id=?", (bill_id,)).fetchone()[0]
    db.execute("UPDATE bills SET total_amount=? WHERE bill_id=?", (max(round(subtotal - discount, 2), 0), bill_id))


def get_bill(bid):
    b = get_db().execute(
        "SELECT b.*, a.date, a.time_slot, a.patient_id, p.name AS patient_name, p.phone AS patient_phone, "
        "d.name AS doctor_name, d.specialization FROM bills b "
        "JOIN appointments a ON a.appointment_id=b.appointment_id "
        "JOIN patients p ON p.patient_id=a.patient_id "
        "JOIN doctors d ON d.doctor_id=a.doctor_id WHERE b.bill_id=?", (bid,)).fetchone()
    if b is None:
        abort(404)
    return b


def editable_bill(bid):
    b = get_bill(bid)
    if b["status"] == "Paid":                                        # BR3
        abort(403, "A paid bill cannot be edited. An Admin can reopen it first.")
    return b


@app.route("/bills")
@login_required("Admin", "Receptionist")
def bills():
    status = request.args.get("status", "")
    sql = ("SELECT b.*, a.date, p.name AS patient_name, d.name AS doctor_name FROM bills b "
           "JOIN appointments a ON a.appointment_id=b.appointment_id "
           "JOIN patients p ON p.patient_id=a.patient_id JOIN doctors d ON d.doctor_id=a.doctor_id")
    params = []
    if status in ("Paid", "Unpaid"):
        sql += " WHERE b.status=?"
        params.append(status)
    rows = get_db().execute(sql + " ORDER BY b.bill_id DESC LIMIT 300", params).fetchall()
    return render_template("bills.html", rows=rows, status=status)


@app.route("/appointments/<int:aid>/bill/create", methods=["POST"])
@login_required("Admin", "Receptionist")
def bill_create(aid):
    db = get_db()
    appt = get_appt(aid)
    if appt["status"] != "Completed":                                 # BR3
        flash("A bill can be created only for a completed appointment.", "error")
        return redirect(request.referrer or url_for("appointments"))
    existing = db.execute("SELECT bill_id FROM bills WHERE appointment_id=?", (aid,)).fetchone()
    if existing:
        return redirect(url_for("bill_view", bid=existing["bill_id"]))
    fee = db.execute("SELECT consultation_fee FROM doctors WHERE doctor_id=?", (appt["doctor_id"],)).fetchone()[0]
    cur = db.execute("INSERT INTO bills (appointment_id, created_at) VALUES (?,?)", (aid, now()))
    db.execute("INSERT INTO bill_items (bill_id, description, amount) VALUES (?,?,?)",
               (cur.lastrowid, "Consultation fee", fee))
    recalc_bill(cur.lastrowid)
    audit("bill", cur.lastrowid, "created", f"appointment {aid}")
    db.commit()
    return redirect(url_for("bill_view", bid=cur.lastrowid))


@app.route("/bills/<int:bid>")
@login_required("Admin", "Receptionist")
def bill_view(bid):
    items = get_db().execute("SELECT * FROM bill_items WHERE bill_id=? ORDER BY item_id", (bid,)).fetchall()
    return render_template("bill.html", b=get_bill(bid), items=items, methods=PAYMENT_METHODS)


@app.route("/bills/<int:bid>/items", methods=["POST"])
@login_required("Admin", "Receptionist")
def bill_add_item(bid):
    editable_bill(bid)
    desc = request.form.get("description", "").strip()
    try:
        amount = round(float(request.form.get("amount", "")), 2)
        if amount <= 0:
            raise ValueError
    except ValueError:
        flash("Enter a description and an amount above 0.", "error")
        return redirect(url_for("bill_view", bid=bid))
    if not desc:
        flash("Enter a description and an amount above 0.", "error")
    else:
        get_db().execute("INSERT INTO bill_items (bill_id, description, amount) VALUES (?,?,?)", (bid, desc, amount))
        recalc_bill(bid)
        audit("bill", bid, "item added", f"{desc}: {amount}")
        get_db().commit()
    return redirect(url_for("bill_view", bid=bid))


@app.route("/bills/<int:bid>/items/<int:item_id>/delete", methods=["POST"])
@login_required("Admin", "Receptionist")
def bill_delete_item(bid, item_id):
    editable_bill(bid)
    get_db().execute("DELETE FROM bill_items WHERE item_id=? AND bill_id=?", (item_id, bid))
    recalc_bill(bid)
    audit("bill", bid, "item removed", str(item_id))
    get_db().commit()
    return redirect(url_for("bill_view", bid=bid))


@app.route("/bills/<int:bid>/discount", methods=["POST"])
@login_required("Admin", "Receptionist")
def bill_discount(bid):
    editable_bill(bid)
    db = get_db()
    subtotal = db.execute("SELECT COALESCE(SUM(amount),0) FROM bill_items WHERE bill_id=?", (bid,)).fetchone()[0]
    try:
        discount = round(float(request.form.get("discount", "0") or 0), 2)
        if not 0 <= discount <= subtotal:
            raise ValueError
    except ValueError:
        flash("Discount must be between 0 and the bill subtotal.", "error")
        return redirect(url_for("bill_view", bid=bid))
    db.execute("UPDATE bills SET discount=? WHERE bill_id=?", (discount, bid))
    recalc_bill(bid)
    audit("bill", bid, "discount set", str(discount))
    db.commit()
    return redirect(url_for("bill_view", bid=bid))


@app.route("/bills/<int:bid>/pay", methods=["POST"])
@login_required("Admin", "Receptionist")
def bill_pay(bid):
    editable_bill(bid)
    method = request.form.get("payment_method", "")
    if method not in PAYMENT_METHODS:
        flash("Choose a payment method.", "error")
    else:
        get_db().execute("UPDATE bills SET status='Paid', payment_method=?, paid_at=? WHERE bill_id=?",
                         (method, now(), bid))
        audit("bill", bid, "marked paid", method)
        get_db().commit()
        flash("Bill marked as Paid.", "ok")
    return redirect(url_for("bill_view", bid=bid))


@app.route("/bills/<int:bid>/unpay", methods=["POST"])
@login_required("Admin")
def bill_unpay(bid):
    get_bill(bid)
    get_db().execute("UPDATE bills SET status='Unpaid', payment_method=NULL, paid_at=NULL WHERE bill_id=?", (bid,))
    audit("bill", bid, "reopened (marked unpaid)")
    get_db().commit()
    return redirect(url_for("bill_view", bid=bid))


@app.route("/bills/<int:bid>/print")
@login_required("Admin", "Receptionist", "Patient")
def bill_print(bid):
    """Printable bill. Use the browser's Print > Save as PDF to get a PDF (FR15)."""
    b = get_bill(bid)
    if g.user["role"] == "Patient" and b["patient_id"] != g.patient_id:
        abort(403)
    items = get_db().execute("SELECT * FROM bill_items WHERE bill_id=? ORDER BY item_id", (bid,)).fetchall()
    return render_template("bill_print.html", b=b, items=items,
                           subtotal=sum(i["amount"] for i in items))


# --------------------------------------------------------------------------
# Reports, audit log, patient portal
# --------------------------------------------------------------------------
@app.route("/reports")
@login_required("Admin")
def reports():
    db = get_db()
    day = request.args.get("date") or date.today().isoformat()
    by_status = {r["status"]: r["n"] for r in db.execute(
        "SELECT status, COUNT(*) AS n FROM appointments WHERE date=? GROUP BY status", (day,))}
    seen = db.execute("SELECT COUNT(DISTINCT patient_id) FROM appointments WHERE date=? AND status='Completed'",
                      (day,)).fetchone()[0]
    collected = db.execute("SELECT COALESCE(SUM(total_amount),0) FROM bills "
                           "WHERE status='Paid' AND substr(paid_at,1,10)=?", (day,)).fetchone()[0]
    unpaid = db.execute(
        "SELECT b.bill_id, b.total_amount, a.date, p.name AS patient_name FROM bills b "
        "JOIN appointments a ON a.appointment_id=b.appointment_id "
        "JOIN patients p ON p.patient_id=a.patient_id WHERE b.status='Unpaid' "
        "ORDER BY a.date ASC, b.bill_id ASC").fetchall()                  # FR16: oldest first
    return render_template("reports.html", day=day, by_status=by_status, seen=seen,
                           collected=collected, unpaid=unpaid)


@app.route("/audit")
@login_required("Admin")
def audit_log():
    rows = get_db().execute(
        "SELECT l.*, u.username FROM audit_log l LEFT JOIN users u ON u.user_id=l.user_id "
        "ORDER BY l.log_id DESC LIMIT 200").fetchall()
    return render_template("audit.html", rows=rows)


@app.route("/my")
@login_required("Patient")
def my_records():
    db = get_db()
    appts = db.execute(APPT_SELECT + " WHERE a.patient_id=? ORDER BY a.date DESC, a.time_slot DESC",
                       (g.patient_id,)).fetchall()
    bills_ = db.execute(
        "SELECT b.*, a.date FROM bills b JOIN appointments a ON a.appointment_id=b.appointment_id "
        "WHERE a.patient_id=? ORDER BY b.bill_id DESC", (g.patient_id,)).fetchall()
    return render_template("my_records.html", appts=appts, bills=bills_)


if __name__ == "__main__":
    with app.app_context():
        init_db()
    # Set FLASK_DEBUG=1 for auto-reload while learning/developing. Never use debug mode on a public server.
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
