"""Read-only account availability regressions; all API calls are mocked."""
import importlib.util
import os
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("availability_app",
    os.environ.get("MAIL_TEST_APP", str(Path(__file__).resolve().parents[1] / "app.py")))
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)


class AccountAvailabilityTests(unittest.TestCase):
    def query(self, response):
        client = app.NetEaseClient()
        with patch.object(client, "call", return_value=response):
            return client.account_exists("employee")

    def test_exact_business_marker_means_absent(self):
        self.assertFalse(self.query({"success": False, "code": -3,
            "message": "通用业务操作失败: ACCOUNT.NOTEXIST:employee@example.com账号不存在"}))

    def test_legacy_not_found_code_remains_supported(self):
        self.assertFalse(self.query({"success": False, "code": -4}))

    def test_existing_account_remains_occupied(self):
        self.assertTrue(self.query({"success": True, "data": {"accountName": "employee"}}))

    def test_other_failures_remain_blocking(self):
        for code, message in [(-3, "permission denied"), (-3, "账号不存在"),
                              (-3, "ACCOUNT.NOTEXIST_OTHER"), (-3, ""),
                              (-301, "ACCOUNT.NOTEXIST:employee@example.com")]:
            with self.subTest(code=code, message=message):
                with self.assertRaises(app.ServiceError):
                    self.query({"success": False, "code": code, "message": message})
