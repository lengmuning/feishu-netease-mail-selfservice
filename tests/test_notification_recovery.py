"""Isolated regression tests: never call live mail or Feishu APIs."""
import importlib.util
import os
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location(
    "mail_recovery", os.environ.get("MAIL_TEST_APP", str(Path(__file__).resolve().parents[1] / "app.py")))
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)


class NotificationRecoveryTests(unittest.TestCase):
    def exercise(self, action, final, write_error=False, notify_error=False):
        contact = {"name": "测试员工", "employee_no": "T001", "mobile": "13800138000",
                   "email": "employee@example.com"}
        claims = {"open_id": "test-open", "employee_no": "T001"}
        before = {"state": "eligible" if action == "provision" else "matched",
                  "record": {"accountName": "employee", "primaryEmail": contact["email"]}}
        events = []
        fs, ne = Mock(), Mock()
        fs.require_active_employee.return_value = contact
        fs.department_path.return_value = (["公司"], None)
        ne.account_exists.return_value = False
        ne.resolve_or_create_unit.return_value = ("unit", [])

        def check(*args, **kwargs):
            events.append("check")
            if events.count("check") == 1:
                return before
            if isinstance(final, Exception):
                raise final
            return final

        def write(*args):
            events.append("write")
            if write_error:
                raise app.ServiceError("write failed", 502)

        def notify(*args):
            events.append("notify")
            if notify_error and events.count("notify") == 2:
                raise app.ServiceError("notify failed", 502)

        ne.check_employee.side_effect = check
        ne.create_account.side_effect = write
        ne.update_password.side_effect = write
        with patch.object(app, "feishu", fs), patch.object(app, "netease", ne), \
             patch.object(app, "NETEASE_DOMAIN", "example.com"), \
             patch.object(app, "READ_ONLY", False), patch.object(app, "audit"), \
             patch.object(app, "limiter", Mock()), \
             patch.object(app, "send_feishu_text_with_retry", side_effect=notify) as sender:
            if write_error:
                with self.assertRaises(app.ServiceError):
                    app.Handler._mail_action(None, action, claims, "test")
                self.assertEqual(sender.call_count, 1)
                return
            result = app.Handler._mail_action(None, action, claims, "test")
            self.assertEqual(events, ["check", "notify", "write", "notify", "check"])
            self.assertIn("邮箱地址：employee@example.com", sender.call_args.args[1])
            self.assertNotIn("password", result)
            if isinstance(final, Exception) or final.get("state") != "matched":
                self.assertFalse(result["actions"]["provision"])
                self.assertFalse(result["actions"]["password"])
                self.assertIn("暂未核实", result["message"])
            if notify_error:
                self.assertIn("飞书发送失败", result["message"])
            else:
                self.assertIn("密码已通过飞书发送", result["message"])

    def test_password_delivered_before_readback_for_both_actions(self):
        for action in ("provision", "password"):
            for final in ({"state": "matched"}, {"state": "eligible"},
                          app.ServiceError("read timeout", 502), ValueError("bad response")):
                with self.subTest(action=action, final=type(final).__name__):
                    self.exercise(action, final)

    def test_failed_writes_do_not_send_success_password(self):
        for action in ("provision", "password"):
            self.exercise(action, {}, write_error=True)

    def test_delivery_failure_stays_visible_when_readback_fails(self):
        for action in ("provision", "password"):
            self.exercise(action, app.ServiceError("read timeout", 502), notify_error=True)
