# SHMS - Simple Hospital Management System

A learning project built from the SHMS PRD (Python + Flask + SQLite).
**Fake data only. Not for real patients or real hospital use.**

## Run it

```bash
pip install -r requirements.txt
python seed.py        # optional: creates demo data and logins
python app.py         # open http://127.0.0.1:5000
python -m unittest -v # optional: runs the end-to-end tests
```

## Demo logins (created by `seed.py`)

| Username   | Password   | Role         |
|------------|------------|--------------|
| admin      | admin123   | Admin        |
| reception  | recep123   | Receptionist |
| dr.rao     | doctor123  | Doctor       |
| ravi       | patient123 | Patient      |

Change or remove these before showing the app to anyone else.

## What it covers (PRD mapping)

- **Login and roles (FR1-FR4):** hashed passwords, role-based screens, lock after 5 failed logins, 30-minute idle timeout, CSRF protection.
- **Patients (FR5-FR9):** register, validate, search by name/phone/ID, duplicate warning, edit with audit log, deactivate.
- **Doctors (FR10-FR12):** add, edit, deactivate; fee, available days and hours.
- **Appointments (FR13-FR19):** free-slot booking, double-booking blocked, reschedule, cancel with reason, no-show, daily list sorted by time, past dates rejected.
- **Visit records (FR20-FR23):** diagnosis and prescription, appointment becomes Completed, history view, records are never deleted (corrections are added as addenda).
- **Billing (FR24-FR28):** bill from a completed visit, extra items, discount, Paid/Unpaid with payment method, printable bill (use the browser's "Save as PDF").
- **Reports (FR29-FR30):** daily summary and unpaid bills (Admin).
- **Audit log:** who changed what and when (Admin).

## Files

- `app.py` - routes, rules and database code
- `templates/` - HTML pages (Jinja)
- `seed.py` - fake demo data
- `test_smoke.py` - tests that walk through the main PRD flow

## Known limits (on purpose, for simplicity)

SQLite only, one hospital, 15-minute slots, no tax or insurance, no email/SMS, no real security hardening beyond the basics above.
