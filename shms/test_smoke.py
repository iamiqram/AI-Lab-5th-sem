"""End-to-end smoke tests that walk through the main flow of the PRD.

Run:  python -m unittest -v
"""
import os
import tempfile
import unittest
from datetime import date, timedelta

import app as shms


class ShmsTests(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        shms.app.config.update(DB_PATH=self.path, TESTING=True)
        with shms.app.app_context():
            shms.init_db()

    def tearDown(self):
        os.remove(self.path)

    # ---- helpers ----
    def new_client(self):
        return shms.app.test_client()

    def post(self, c, url, data=None, follow=False):
        c.get("/login")                       # makes sure a CSRF token exists
        with c.session_transaction() as s:
            token = s["csrf_token"]
        return c.post(url, data={**(data or {}), "csrf_token": token}, follow_redirects=follow)

    def login(self, username, password):
        c = self.new_client()
        r = self.post(c, "/login", {"username": username, "password": password})
        return c, r

    def admin_setup(self):
        """Admin creates a doctor, a doctor login and a receptionist login."""
        admin, _ = self.login("admin", "admin123")
        self.post(admin, "/doctors/new", {
            "name": "Dr. Test", "specialization": "General", "consultation_fee": "500",
            "days": list(shms.DAYS), "available_from": "09:00", "available_to": "12:00"})
        self.post(admin, "/users", {"username": "recep", "password": "secret1", "role": "Receptionist"})
        self.post(admin, "/users", {"username": "doc", "password": "secret1", "role": "Doctor", "link_id": "1"})
        return admin

    # ---- tests ----
    def test_login_required_and_bad_login(self):
        c = self.new_client()
        self.assertEqual(c.get("/patients").status_code, 302)
        _, r = self.login("admin", "wrong")
        self.assertEqual(r.status_code, 200)               # stays on login page

    def test_account_lockout_after_five_failures(self):
        for _ in range(5):
            self.login("admin", "bad")
        _, r = self.login("admin", "admin123")             # correct password, but locked
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"locked", r.data)

    def test_csrf_is_enforced(self):
        c = self.new_client()
        c.get("/login")
        r = c.post("/login", data={"username": "admin", "password": "admin123"})
        self.assertEqual(r.status_code, 400)

    def test_role_restrictions(self):
        self.admin_setup()
        recep, _ = self.login("recep", "secret1")
        self.assertEqual(recep.get("/doctors/new").status_code, 403)
        self.assertEqual(recep.get("/reports").status_code, 403)
        doc, _ = self.login("doc", "secret1")
        self.assertEqual(doc.get("/bills").status_code, 403)

    def test_full_visit_flow(self):
        admin = self.admin_setup()
        recep, _ = self.login("recep", "secret1")
        tomorrow = (date.today() + timedelta(days=1)).isoformat()

        # register patients + duplicate warning
        person = {"name": "Ravi Das", "age": "34", "gender": "Male", "phone": "9876500001"}
        self.post(recep, "/patients/new", person)
        r = self.post(recep, "/patients/new", person)
        self.assertIn(b"already exists", r.data)
        self.post(recep, "/patients/new", {**person, "name": "Priya Sharma", "phone": "9876500002"})
        bad = self.post(recep, "/patients/new", {**person, "phone": "123"})
        self.assertIn(b"10 digits", bad.data)

        # book, then double-booking is rejected (FR8)
        self.post(recep, "/appointments/new",
                  {"patient_id": "1", "doctor_id": "1", "date": tomorrow, "slot": "10:00"})
        r = self.post(recep, "/appointments/new",
                      {"patient_id": "2", "doctor_id": "1", "date": tomorrow, "slot": "10:00"})
        self.assertIn(b"not available", r.data)
        free = recep.get(f"/appointments/new?patient_id=2&doctor_id=1&date={tomorrow}")
        self.assertNotIn(b'value="10:00"', free.data)      # booked slot is no longer offered

        # past dates are rejected (FR19)
        yesterday = (date.today() - timedelta(days=1)).isoformat()
        r = self.post(recep, "/appointments/new",
                      {"patient_id": "2", "doctor_id": "1", "date": yesterday, "slot": "10:00"})
        self.assertIn(b"Past dates", r.data)

        # no bill before the visit is completed (BR3)
        self.post(recep, "/appointments/1/bill/create")
        with shms.app.app_context():
            self.assertEqual(shms.get_db().execute("SELECT COUNT(*) FROM bills").fetchone()[0], 0)

        # doctor records the visit -> appointment becomes Completed (FR11, FR21)
        doc, _ = self.login("doc", "secret1")
        self.assertIn(b"Ravi Das", doc.get("/appointments?date=").data)
        self.post(doc, "/appointments/1/visit", {"symptoms": "Fever", "diagnosis": "Viral fever",
                                                 "prescription": "Rest"})
        with shms.app.app_context():
            st = shms.get_db().execute("SELECT status FROM appointments WHERE appointment_id=1").fetchone()[0]
        self.assertEqual(st, "Completed")
        self.assertEqual(self.post(doc, "/appointments/1/visit", {"diagnosis": "again"}).status_code, 403)
        self.post(doc, "/appointments/1/addendum", {"note": "Follow-up in 3 days"})
        self.assertIn(b"Follow-up in 3 days", doc.get("/appointments/1/visit").data)
        self.assertIn(b"Viral fever", doc.get("/patients/1").data)          # visit history (FR12)

        # billing (FR13 - FR15, BR3)
        self.post(recep, "/appointments/1/bill/create")
        self.post(recep, "/bills/1/items", {"description": "Blood test", "amount": "200"})
        self.post(recep, "/bills/1/discount", {"discount": "100"})
        with shms.app.app_context():
            total = shms.get_db().execute("SELECT total_amount FROM bills WHERE bill_id=1").fetchone()[0]
        self.assertEqual(total, 600.0)                                     # 500 + 200 - 100
        self.post(recep, "/bills/1/pay", {"payment_method": "UPI"})
        self.assertEqual(self.post(recep, "/bills/1/items",
                                   {"description": "Late add", "amount": "50"}).status_code, 403)
        self.assertEqual(recep.get("/bills/1/print").status_code, 200)

        # reports (FR16)
        rep = admin.get("/reports")
        self.assertIn(b"600.00", rep.data)
        self.assertEqual(self.post(recep, "/bills/1/unpay").status_code, 403)   # only Admin reopens
        self.post(admin, "/bills/1/unpay")
        self.assertIn(b"Open", admin.get("/reports").data)                      # now in unpaid list

        # cancel frees the slot (FR9)
        self.post(recep, "/appointments/new",
                  {"patient_id": "2", "doctor_id": "1", "date": tomorrow, "slot": "10:15"})
        self.post(recep, "/appointments/2/cancel", {"reason": "Patient request"})
        self.assertIn(b"10:15", recep.get(f"/appointments/new?patient_id=2&doctor_id=1&date={tomorrow}").data)

        # edits are audited (FR5)
        self.post(recep, "/patients/1/edit", {**person, "phone": "9876500009"})
        self.assertIn(b"9876500009", admin.get("/audit").data)

    def test_every_page_renders_for_admin(self):
        admin = self.admin_setup()
        for url in ["/", "/patients", "/patients/new", "/doctors", "/doctors/new", "/doctors/1/edit",
                    "/appointments", "/appointments/new", "/bills", "/reports", "/users", "/audit"]:
            self.assertEqual(admin.get(url).status_code, 200, url)

    def test_patient_portal_only_sees_own_data(self):
        admin = self.admin_setup()
        self.post(admin, "/patients/new", {"name": "Ravi Das", "age": "34", "gender": "Male", "phone": "9876500001"})
        self.post(admin, "/users", {"username": "ravi", "password": "secret1", "role": "Patient", "link_id": "1"})
        ravi, _ = self.login("ravi", "secret1")
        self.assertEqual(ravi.get("/my").status_code, 200)
        self.assertEqual(ravi.get("/patients").status_code, 403)


if __name__ == "__main__":
    unittest.main()
