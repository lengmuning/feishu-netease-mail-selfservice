import importlib.util
import os
from pathlib import Path
import unittest


os.environ.setdefault("SESSION_SECRET", "test-session-secret-with-32-bytes")
MODULE_PATH = Path(__file__).resolve().parents[1] / "app.py"
SPEC = importlib.util.spec_from_file_location("mail_self_service_app", MODULE_PATH)
app = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(app)

# Deployment-neutral fixtures.  Real domains, unit ids and names live only in
# the production config.env, never in the repository.
DOMAIN = "example.com"
LEGACY_DOMAIN = "legacy.example.com"
COMPANY = "示例科技有限公司"
ROOT_UNIT_ID = "100000"


class NormalizationTests(unittest.TestCase):
    def test_normalize_phone_removes_cn_prefix(self):
        self.assertEqual(app.normalize_phone("+86-138 0013 8000"), "13800138000")

    def test_masked_phone_only_keeps_last_four(self):
        self.assertEqual(app.masked_phone("13800138000"), "*******8000")

    def test_account_emails_include_primary_alias_and_mail_accounts(self):
        account = {
            "accountName": "alice",
            "domain": LEGACY_DOMAIN,
            "aliasList": ["short"],
            "aliasEmailList": [f"alice@{DOMAIN}"],
            "mailAccountList": [{"accountName": "alice", "domain": "another.example"}],
        }
        self.assertEqual(
            app.account_emails(account, DOMAIN),
            [
                f"alice@{LEGACY_DOMAIN}",
                f"alice@{DOMAIN}",
                f"short@{DOMAIN}",
                "alice@another.example",
            ],
        )

    def test_session_signature_rejects_tampering(self):
        codec = app.SessionCodec(b"test-session-secret-with-32-bytes")
        token = codec.encode({"exp": 4102444800, "employee_no": "A001"})
        self.assertEqual(codec.decode(token)["employee_no"], "A001")
        self.assertIsNone(codec.decode(token + "x"))

    def test_oauth_query_is_removed_from_access_log_line(self):
        line = "GET /auth/feishu/callback?code=secret&state=signed HTTP/1.1"
        self.assertEqual(
            app.sanitize_request_line(line),
            "GET /auth/feishu/callback HTTP/1.1",
        )


class ProvisionGuardTests(unittest.TestCase):
    def setUp(self):
        app.NETEASE_DOMAIN = DOMAIN
        app.FEISHU_DEPARTMENT_ANCHOR = COMPANY
        app.NETEASE_ROOT_UNIT_ID = ROOT_UNIT_ID
        app.NETEASE_ROOT_UNIT_NAME = COMPANY

    def test_target_is_derived_from_the_feishu_work_email(self):
        account, email = app.provision_target({"email": f"Zhang.San@{DOMAIN.upper()}"})
        self.assertEqual(account, "zhang.san")
        self.assertEqual(email, f"zhang.san@{DOMAIN}")

    def test_work_email_outside_the_pinned_domain_is_rejected(self):
        with self.assertRaises(app.ServiceError):
            app.provision_target({"email": "zhangsan@gmail.com"})

    def test_missing_work_email_is_rejected(self):
        with self.assertRaises(app.ServiceError):
            app.provision_target({"email": ""})

    def test_browser_may_not_name_a_target(self):
        app.reject_target_keys({})
        for payload in ({"employeeNo": "A002"}, {"accountName": "other"}, {"password": "x"}, {"foo": 1}):
            with self.assertRaises(app.ServiceError):
                app.reject_target_keys(payload)

    def test_generated_password_avoids_ambiguous_characters(self):
        for _ in range(200):
            password = app.generate_initial_password()
            self.assertGreaterEqual(len(password), 8)
            self.assertFalse(set(password) & set("O0Il1"))
            self.assertTrue(any(c.isupper() for c in password))
            self.assertTrue(any(c.isdigit() for c in password))

    def test_rate_limiter_stops_the_sixth_attempt(self):
        limiter = app.RateLimiter()
        for _ in range(5):
            limiter.check("ou_1", "provision")
        with self.assertRaises(app.ServiceError):
            limiter.check("ou_1", "provision")
        limiter.check("ou_2", "provision")

    def test_concurrent_write_for_one_employee_is_refused(self):
        locks = app.OperationLocks()
        with locks.hold("A001"):
            with self.assertRaises(app.ServiceError):
                with locks.hold("A001"):
                    pass
            with locks.hold("A002"):
                pass
        with locks.hold("A001"):
            pass

    def test_notification_carries_the_address_and_password(self):
        text = app.notification_text("provision", "张三", f"zhangsan@{DOMAIN}", "Ab234567!x")
        self.assertIn(f"zhangsan@{DOMAIN}", text)
        self.assertIn("Ab234567!x", text)

    def test_department_path_is_scoped_below_company_anchor(self):
        self.assertEqual(
            app.relative_department_path(["集团", COMPANY, "战略企划", "信息运维岗"]),
            ["战略企划", "信息运维岗"],
        )

    def test_department_path_without_company_anchor_is_rejected(self):
        with self.assertRaises(app.ServiceError):
            app.relative_department_path(["其他租户", "信息运维岗"])

    def test_empty_anchor_mirrors_the_whole_path_below_the_root_unit(self):
        # Feishu tenants organized by function have no company node in the path.
        app.FEISHU_DEPARTMENT_ANCHOR = ""
        self.assertEqual(
            app.relative_department_path(["运营中心", "供应保障部", "材料供应链", "成都仓储岗"]),
            ["运营中心", "供应保障部", "材料供应链", "成都仓储岗"],
        )

    def test_consecutive_duplicate_department_names_are_preserved(self):
        app.FEISHU_DEPARTMENT_ANCHOR = ""
        path = ["示例新材料有限公司", "示例新材料有限公司", "清洗厂", "清洗工艺科"]
        self.assertEqual(app.relative_department_path(path), path)

    def test_existing_repeated_name_hierarchy_is_resolved_exactly(self):
        app.FEISHU_DEPARTMENT_ANCHOR = ""
        app.CREATE_MISSING_UNITS = False

        class FakeNetEase(app.NetEaseClient):
            def units(self, refresh=False):
                return [
                    {"unitId": ROOT_UNIT_ID, "unitName": COMPANY, "unitParentId": ""},
                    {"unitId": "20", "unitName": "示例新材料有限公司", "unitParentId": ROOT_UNIT_ID},
                    {"unitId": "21", "unitName": "示例新材料有限公司", "unitParentId": "20"},
                    {"unitId": "22", "unitName": "清洗厂", "unitParentId": "21"},
                    {"unitId": "23", "unitName": "清洗工艺科", "unitParentId": "22"},
                ]

        unit_id, created = FakeNetEase().resolve_or_create_unit(
            ["示例新材料有限公司", "示例新材料有限公司", "清洗厂", "清洗工艺科"]
        )
        self.assertEqual(unit_id, "23")
        self.assertEqual(created, [])

    def test_missing_department_is_created_under_exact_parent(self):
        app.CREATE_MISSING_UNITS = True

        class FakeNetEase(app.NetEaseClient):
            def __init__(self):
                super().__init__()
                self.items = [
                    {"unitId": ROOT_UNIT_ID, "unitName": COMPANY, "unitParentId": ""},
                    {"unitId": "10", "unitName": "战略企划", "unitParentId": ROOT_UNIT_ID},
                ]

            def units(self, refresh=False):
                return list(self.items)

            def create_unit(self, parent_id, name):
                unit_id = str(len(self.items) + 10)
                self.items.append({"unitId": unit_id, "unitName": name, "unitParentId": parent_id})
                return unit_id

        client = FakeNetEase()
        unit_id, created = client.resolve_or_create_unit([COMPANY, "战略企划", "信息运维岗"])
        self.assertEqual(created, ["信息运维岗"])
        self.assertEqual(unit_id, "12")
        self.assertEqual(client.items[-1]["unitParentId"], "10")

    def test_root_unit_name_is_verified_only_when_configured(self):
        """The unit id addresses the tree; the name is an optional assertion."""
        listing = {"success": True, "data": [
            {"unitId": ROOT_UNIT_ID, "unitName": "改名后的公司", "unitParentId": ""}]}

        def client(configured_name):
            app.NETEASE_ROOT_UNIT_NAME = configured_name
            c = app.NetEaseClient()
            c.call = lambda *a, **k: listing
            return c

        # Empty name: any observed name is accepted, and it is recorded.
        c = client("")
        self.assertEqual(len(c.units()), 1)
        self.assertEqual(c.root_unit_name, "改名后的公司")

        # Configured and mismatched: refuse, naming both sides.
        with self.assertRaises(app.ServiceError) as caught:
            client("原来的公司").units()
        self.assertIn("改名后的公司", str(caught.exception))
        self.assertIn("原来的公司", str(caught.exception))

        # Configured and matching: accepted.
        self.assertEqual(len(client("改名后的公司").units()), 1)

    def test_missing_root_unit_is_refused_even_without_a_configured_name(self):
        app.NETEASE_ROOT_UNIT_NAME = ""
        c = app.NetEaseClient()
        c.call = lambda *a, **k: {"success": True, "data": [
            {"unitId": "999", "unitName": "别的公司", "unitParentId": ""}]}
        with self.assertRaises(app.ServiceError) as caught:
            c.units()
        self.assertIn(ROOT_UNIT_ID, str(caught.exception))

    def test_feishu_path_without_company_node_maps_under_the_root_unit(self):
        """The common shape: NetEase carries the company as its root unit and the
        Feishu path below it verbatim, while Feishu itself has no company node."""
        app.FEISHU_DEPARTMENT_ANCHOR = ""
        app.CREATE_MISSING_UNITS = False

        class FakeNetEase(app.NetEaseClient):
            def units(self, refresh=False):
                return [
                    {"unitId": ROOT_UNIT_ID, "unitName": COMPANY, "unitParentId": ""},
                    {"unitId": "700", "unitName": "战略企划", "unitParentId": ROOT_UNIT_ID},
                    {"unitId": "710", "unitName": "数智化办公室", "unitParentId": "700"},
                    {"unitId": "711", "unitName": "信息运维岗", "unitParentId": "710"},
                ]

            def create_unit(self, parent_id, name):  # pragma: no cover
                raise AssertionError("existing units must be reused, not recreated")

        unit_id, created = FakeNetEase().resolve_or_create_unit(
            ["战略企划", "数智化办公室", "信息运维岗"]
        )
        self.assertEqual(unit_id, "711")
        self.assertEqual(created, [])

    def test_missing_department_is_refused_when_auto_create_is_off(self):
        app.CREATE_MISSING_UNITS = False

        class FakeNetEase(app.NetEaseClient):
            def units(self, refresh=False):
                return [{"unitId": ROOT_UNIT_ID, "unitName": COMPANY, "unitParentId": ""}]

        with self.assertRaises(app.ServiceError):
            FakeNetEase().resolve_or_create_unit([COMPANY, "不存在的部门"])


if __name__ == "__main__":
    unittest.main()
