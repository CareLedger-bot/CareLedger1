"""Tests for CareLedger's data rules and localhost web interface."""
from __future__ import annotations

import http.client
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.parse import urlencode

import app as care

SAMPLE = {
    "full_name": "Alex Morgan",
    "date_of_birth": "1995-01-17",
    "appointment_date": "2026-11-12",
    "care_summary": "Synthetic record created for automated tests.",
    "status": "Active",
}


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.dbpath = Path(self.temp.name) / "demo.sqlite3"
        care.init_db(self.dbpath)
        self.db = care.open_db(self.dbpath)
        self.clinician = self.db.execute("SELECT * FROM users WHERE username='clinician'").fetchone()
        self.viewer = self.db.execute("SELECT * FROM users WHERE username='viewer'").fetchone()

    def tearDown(self):
        self.db.close()
        self.temp.cleanup()

    def test_sample_data_is_fictional(self):
        people = self.db.execute("SELECT COUNT(*) FROM patients").fetchone()[0]
        self.assertEqual(people, 5)
        self.assertIn("fictional", self.db.execute("SELECT care_summary FROM patients LIMIT 1").fetchone()[0])

    def test_create_search_update_audit_history(self):
        pid = care.create_patient(self.db, self.clinician, SAMPLE)
        result = self.db.execute("SELECT * FROM patients WHERE full_name LIKE ?", ("%Alex%",)).fetchone()
        self.assertEqual(result["id"], pid)
        amended = {**SAMPLE, "status": "Follow-up", "care_summary": "New fictional update"}
        changed = care.update_patient(self.db, self.clinician, pid, amended)
        self.assertEqual(set(changed), {"Status", "Care Summary"})
        history = self.db.execute("SELECT action, changed_fields FROM audit WHERE patient_id=? ORDER BY id", (pid,)).fetchall()
        self.assertEqual([r["action"] for r in history], ["CREATED", "UPDATED"])
        self.assertIn("Status", history[1]["changed_fields"])
        self.assertNotIn("New fictional update", history[1]["changed_fields"])

    def test_no_audit_entry_when_nothing_changed(self):
        pid = care.create_patient(self.db, self.clinician, SAMPLE)
        self.assertEqual(care.update_patient(self.db, self.clinician, pid, SAMPLE), [])
        count = self.db.execute("SELECT COUNT(*) FROM audit WHERE patient_id=?", (pid,)).fetchone()[0]
        self.assertEqual(count, 1)

    def test_viewer_cannot_create_or_change(self):
        with self.assertRaises(PermissionError):
            care.create_patient(self.db, self.viewer, SAMPLE)
        with self.assertRaises(PermissionError):
            care.update_patient(self.db, self.viewer, 1, SAMPLE)

    def test_input_validation(self):
        invalid = [
            {**SAMPLE, "full_name": ""},
            {**SAMPLE, "date_of_birth": "2026-02-30"},
            {**SAMPLE, "date_of_birth": "2050-01-01"},
            {**SAMPLE, "status": "Deleted"},
            {**SAMPLE, "care_summary": ""},
            {**SAMPLE, "care_summary": "x" * 701},
            {**SAMPLE, "appointment_date": "not-a-date"},
        ]
        for entry in invalid:
            with self.subTest(entry=entry):
                with self.assertRaises(ValueError):
                    care.validate_patient(entry)

    def test_sql_injection_string_is_treated_as_data(self):
        name = "Robert'); DROP TABLE patients; --"
        pid = care.create_patient(self.db, self.clinician, {**SAMPLE, "full_name": name})
        self.assertEqual(self.db.execute("SELECT full_name FROM patients WHERE id=?", (pid,)).fetchone()[0], name)
        self.assertGreater(self.db.execute("SELECT COUNT(*) FROM patients").fetchone()[0], 0)

    def test_escaped_output_is_not_html(self):
        self.assertEqual(care.escape('<script>alert("x")</script>'), '&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;')

    def test_password_hash_check(self):
        digest = care.password_digest("example")
        self.assertTrue(care.check_password("example", digest))
        self.assertFalse(care.check_password("wrong", digest))
        self.assertNotIn("example", digest)


class WebTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.dbpath = Path(cls.temp.name) / "web.sqlite3"
        care.init_db(cls.dbpath)
        cls.srv = care.CareLedgerServer(("127.0.0.1", 0), cls.dbpath)
        cls.thread = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        cls.thread.join(timeout=3)
        cls.temp.cleanup()

    def send(self, method, path, fields=None, cookie=None, origin=None):
        headers = {}
        payload = None
        if fields is not None:
            payload = urlencode(fields)
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        if cookie:
            headers["Cookie"] = cookie
        if origin:
            headers["Origin"] = origin
        connection = http.client.HTTPConnection("127.0.0.1", self.srv.server_port, timeout=5)
        connection.request(method, path, body=payload, headers=headers)
        response = connection.getresponse()
        result = response.status, dict(response.getheaders()), response.read().decode("utf8")
        connection.close()
        return result

    def login(self, role="clinician"):
        status, headers, _ = self.send("POST", "/login", {"username": role, "password": care.DEMO_PASSWORD})
        self.assertEqual(status, 303)
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        token = cookie.partition("=")[2]
        with care.SESSION_LOCK:
            csrf = care.SESSIONS[token]["csrf"]
        return cookie, csrf

    def test_login_and_search(self):
        cookie, _ = self.login()
        code, _, page = self.send("GET", "/?q=Zara", cookie=cookie)
        self.assertEqual(code, 200)
        self.assertIn("Zara Ahmed", page)
        self.assertNotIn("Daniel Reed", page)

    def test_invalid_password_is_rejected(self):
        code, _, page = self.send("POST", "/login", {"username": "clinician", "password": "bad"})
        self.assertEqual(code, 401)
        self.assertIn("Please check your credentials", page)

    def test_viewer_permissions_and_csrf(self):
        cookie, csrf = self.login("viewer")
        status, _, _ = self.send("GET", "/patients/new", cookie=cookie)
        self.assertEqual(status, 403)
        status, _, _ = self.send("POST", "/patients", {**SAMPLE, "csrf": csrf}, cookie=cookie)
        self.assertEqual(status, 403)
        cookie, csrf = self.login("clinician")
        status, _, _ = self.send("POST", "/patients", {**SAMPLE, "csrf": "incorrect"}, cookie=cookie)
        self.assertEqual(status, 403)
        status, _, _ = self.send("POST", "/patients", {**SAMPLE, "csrf": csrf}, cookie=cookie)
        self.assertEqual(status, 303)

    def test_cross_origin_posts_rejected(self):
        _, _, page = self.send("POST", "/login", {"username": "clinician", "password": care.DEMO_PASSWORD}, origin="https://example.com")
        self.assertIn("Cross-origin requests are blocked", page)


if __name__ == "__main__":
    unittest.main()
