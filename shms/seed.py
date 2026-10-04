"""Fill the database with FAKE demo data so you can try every screen.

Usage:  python seed.py
"""
from datetime import date, timedelta

from werkzeug.security import generate_password_hash

from app import app, get_db, init_db

with app.app_context():
    init_db()
    db = get_db()
    if db.execute("SELECT COUNT(*) FROM doctors").fetchone()[0]:
        print("Demo data already exists - nothing to do.")
        raise SystemExit

    doctors = [
        ("Dr. Anita Rao", "General Medicine", 500, "Mon,Tue,Wed,Thu,Fri,Sat,Sun", "09:00", "13:00"),
        ("Dr. Rahul Sen", "Pediatrics", 600, "Mon,Wed,Fri", "10:00", "16:00"),
        ("Dr. Meera Das", "Orthopedics", 800, "Tue,Thu,Sat", "11:00", "17:00"),
    ]
    for d in doctors:
        db.execute("INSERT INTO doctors (name, specialization, consultation_fee, available_days, "
                   "available_from, available_to) VALUES (?,?,?,?,?,?)", d)

    patients = [
        ("Ravi Das", 34, "Male", "9876500001", "Silchar", "9876500101"),
        ("Priya Sharma", 28, "Female", "9876500002", "Guwahati", ""),
        ("Amit Roy", 45, "Male", "9876500003", "Shillong", ""),
        ("Sunita Devi", 62, "Female", "9876500004", "Silchar", "9876500104"),
        ("Kabir Singh", 8, "Male", "9876500005", "Aizawl", "9876500105"),
    ]
    for p in patients:
        db.execute("INSERT INTO patients (name, age, gender, phone, address, emergency_contact) "
                   "VALUES (?,?,?,?,?,?)", p)

    def make_user(username, password, role, table=None, key=None, link=None):
        cur = db.execute("INSERT INTO users (username, password_hash, role) VALUES (?,?,?)",
                         (username, generate_password_hash(password), role))
        if table:
            db.execute(f"UPDATE {table} SET user_id=? WHERE {key}=?", (cur.lastrowid, link))

    make_user("reception", "recep123", "Receptionist")
    make_user("dr.rao", "doctor123", "Doctor", "doctors", "doctor_id", 1)
    make_user("ravi", "patient123", "Patient", "patients", "patient_id", 1)

    tomorrow = (date.today() + timedelta(days=1)).isoformat()
    for pid, did, slot in [(1, 1, "09:00"), (2, 1, "09:15"), (3, 2, "10:00")]:
        db.execute("INSERT INTO appointments (patient_id, doctor_id, date, time_slot) VALUES (?,?,?,?)",
                   (pid, did, tomorrow, slot))
    db.commit()

print("Demo data created. Logins:")
print("  admin      / admin123   (Admin)")
print("  reception  / recep123   (Receptionist)")
print("  dr.rao     / doctor123  (Doctor)")
print("  ravi       / patient123 (Patient)")
