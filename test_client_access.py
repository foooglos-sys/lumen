import base64
import json
import os
import tempfile
import unittest
from unittest.mock import patch

import config


class ClientAccessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.original_database = config.DATABASE
        config.DATABASE = os.path.join(cls.tmp.name, "test.db")
        import app
        cls.module = app
        cls.original_client_dir = app.CLIENT_DIR
        app.CLIENT_DIR = os.path.join(cls.tmp.name, "client")
        os.makedirs(os.path.join(app.CLIENT_DIR, "test"))
        for name, content in [("profile.json", "{}"), ("payload.bin", "private-build")]:
            with open(os.path.join(app.CLIENT_DIR, "test", name), "w") as f:
                f.write(content)
        app.app.config["TESTING"] = True

    @classmethod
    def tearDownClass(cls):
        config.DATABASE = cls.original_database
        cls.module.CLIENT_DIR = cls.original_client_dir
        cls.tmp.cleanup()

    def setUp(self):
        self.client = self.module.app.test_client()
        with self.module.app.app_context():
            db = self.module.get_db()
            db.execute("DELETE FROM client_bans")
            db.execute("DELETE FROM users")
            db.execute("INSERT INTO users(id,nick,password_hash,sub_until,hwid) VALUES(1,'test','hash',?, 'device')",
                       (self.module.FOREVER,))
            db.commit()
            user = db.execute("SELECT * FROM users WHERE id=1").fetchone()
            self.token = self.module.client_token(user, "device")

    def get_file(self, token=None):
        return self.client.get("/api/client/test/file/payload.bin",
                               headers={"Authorization": "Bearer " + (token or self.token)})

    def update_user(self, field, value):
        with self.module.app.app_context():
            db = self.module.get_db()
            db.execute(f"UPDATE users SET {field}=? WHERE id=1", (value,))
            db.commit()

    def test_valid_download_and_no_cache(self):
        response = self.get_file()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, b"private-build")
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        response.close()

    def test_fake_tokens_and_direct_access(self):
        for token in ["fake", self.token[:-1] + ("0" if self.token[-1] != "0" else "1"),
                      "9" * 5000 + ".1." + "0" * 64]:
            self.assertEqual(self.get_file(token).status_code, 401)
        self.assertEqual(self.client.get("/api/client/test/file/payload.bin").status_code, 401)
        self.assertEqual(self.client.get("/client/test/payload.bin").status_code, 404)

    def test_revocation(self):
        for field, value in [("password_hash", "changed"), ("hwid_reset_at", "2026-09-27"),
                             ("hwid", None), ("sub_until", "2000-01-01 00:00:00")]:
            self.setUp()
            self.update_user(field, value)
            self.assertEqual(self.get_file().status_code, 401, field)
            self.assertEqual(self.client.get("/api/client/test/manifest", headers={
                "Authorization": "Bearer " + self.token}).status_code, 401)

    def test_expiry(self):
        with patch.object(self.module.time, "time", return_value=9999999999):
            self.assertEqual(self.get_file().status_code, 401)

    def test_disabled_client(self):
        from types import SimpleNamespace
        with patch.object(self.module.settings, "current", return_value=SimpleNamespace(CLIENT_STATUS="down")):
            self.assertEqual(self.get_file().status_code, 401)

    def test_path_escape(self):
        self.assertFalse(self.module.contained_client_file("test", "../../test.db"))
        response = self.client.get("/api/client/test/file/../profile.json", headers={
            "Authorization": "Bearer " + self.token})
        self.assertEqual(response.status_code, 404)

    def test_signed_manifest(self):
        response = self.client.get("/api/client/test/manifest?nonce=challenge", headers={
            "Authorization": "Bearer " + self.token})
        envelope = response.get_json()
        payload = base64.b64decode(envelope["payload"])
        config.SIGNING_KEY.public_key().verify(base64.b64decode(envelope["sig"]), payload)
        self.assertEqual(json.loads(payload)["nonce"], "challenge")

    def test_malformed_login(self):
        self.assertEqual(self.client.post("/api/client", json=[1]).status_code, 400)

    def test_device_ban_revokes_and_survives_hwid_reset(self):
        with self.module.app.app_context():
            db = self.module.get_db()
            db.execute("INSERT INTO client_bans(user_id,hwid,actor_id) VALUES(1,'device',99)")
            db.commit()
        self.assertEqual(self.get_file().status_code, 401)
        self.assertEqual(self.client.get("/api/client/session", headers={
            "Authorization": "Bearer " + self.token}).status_code, 401)
        self.update_user("hwid", None)
        with self.module.app.app_context():
            self.assertTrue(self.module.client_banned(1, "different-device"))
            self.assertTrue(self.module.client_banned(2, "device"))
            self.assertFalse(self.module.client_banned(2, "different-device"))

    def test_security_event_uses_server_identity(self):
        from unittest.mock import MagicMock
        response = MagicMock()
        response.__enter__.return_value.read.return_value = b'{"ok":true}'
        with patch.dict(os.environ, {"TELEGRAM_BOT_TOKEN": "test-token", "TELEGRAM_CHAT_ID": "123"}), \
             patch.object(self.module, "urlopen", return_value=response) as send, \
             patch.object(self.module, "too_many", return_value=False):
            result = self.client.post("/api/client/security-event", json={
                "event": "instrumentation_detected", "nick": "forged-victim"},
                headers={"Authorization": "Bearer " + self.token})
        self.assertEqual(result.status_code, 202)
        message = json.loads(send.call_args.args[0].data)["text"]
        self.assertIn("test", message)
        self.assertNotIn("forged-victim", message)
        self.assertTrue(result.json["telegram_delivered"])

    def test_security_event_requires_auth_and_valid_event(self):
        self.assertEqual(self.client.post("/api/client/security-event", json={}).status_code, 401)
        self.assertEqual(self.client.post("/api/client/security-event", json={"event": []},
            headers={"Authorization": "Bearer " + self.token}).status_code, 400)

    def test_ban_route_denies_regular_user(self):
        with self.module.app.app_context():
            user = self.module.get_db().execute("SELECT * FROM users WHERE id=1").fetchone()
            stamp = self.module.password_stamp(user)
        with self.client.session_transaction() as session:
            session["uid"] = 1
            session["pw"] = stamp
            session["csrf"] = "test-csrf"
        self.assertEqual(self.client.post("/admin/users/2/client-ban", data={
            "action": "ban", "csrf": "test-csrf"}).status_code, 404)

    def test_admin_ban_and_unban_with_csrf(self):
        with self.module.app.app_context():
            db = self.module.get_db()
            db.execute("INSERT INTO users(id,nick,password_hash,role) VALUES(2,'moderator','hash','admin')")
            db.commit()
            user = db.execute("SELECT * FROM users WHERE id=2").fetchone()
            stamp = self.module.password_stamp(user)
        with self.client.session_transaction() as session:
            session["uid"] = 2
            session["pw"] = stamp
            session["csrf"] = "test-csrf"
        page = self.client.get("/admin/users")
        self.assertEqual(page.status_code, 200)
        self.assertIn("Добавить в ЧСП", page.get_data(as_text=True))
        denied = self.client.post("/admin/users/1/client-ban", data={"action": "ban"})
        self.assertEqual(denied.status_code, 302)
        with self.module.app.app_context():
            self.assertFalse(self.module.client_banned(1, "device"))
        for action, expected in [("ban", 401), ("unban", 200)]:
            result = self.client.post("/admin/users/1/client-ban", data={
                "action": action, "csrf": "test-csrf"})
            self.assertEqual(result.status_code, 302)
            response = self.get_file()
            self.assertEqual(response.status_code, expected)
            response.close()


if __name__ == "__main__":
    unittest.main()
