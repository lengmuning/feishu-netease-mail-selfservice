#!/usr/bin/env python3
"""Independent Feishu-authenticated NetEase enterprise mail self-service."""

from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import logging
from logging.handlers import TimedRotatingFileHandler
import mimetypes
import os
from pathlib import Path
import re
import secrets
import socketserver
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib import error as urlerror
from urllib import parse as urlparse
from urllib import request as urlrequest
import uuid


BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
DATA_DIR = Path(os.environ.get("DATA_DIR", str(BASE_DIR / "data")))
LOG_DIR = Path(os.environ.get("LOG_DIR", str(BASE_DIR / "logs")))

BIND_HOST = os.environ.get("BIND_HOST", "127.0.0.1")
BIND_PORT = int(os.environ.get("BIND_PORT", "8500"))
PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "").strip().rstrip("/")
BASE_PATH = os.environ.get("BASE_PATH", "").strip().rstrip("/")
TRUST_PROXY = os.environ.get("TRUST_PROXY", "0") == "1"
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "1") == "1"
COOKIE_SAMESITE = os.environ.get("COOKIE_SAMESITE", "None").strip().capitalize()
if COOKIE_SAMESITE not in {"Lax", "Strict", "None"}:
    raise RuntimeError("COOKIE_SAMESITE must be Lax, Strict, or None")
if COOKIE_SAMESITE == "None" and not COOKIE_SECURE:
    raise RuntimeError("SameSite=None requires COOKIE_SECURE=1")
SESSION_TTL = int(os.environ.get("SESSION_TTL", "900"))
SESSION_COOKIE = os.environ.get("SESSION_COOKIE", "netease_mail_session")
SESSION_SECRET = os.environ.get("SESSION_SECRET", "").encode("utf-8")
HTTP_TIMEOUT = float(os.environ.get("HTTP_TIMEOUT", "20"))

FEISHU_APP_ID = os.environ.get("FEISHU_APP_ID", "").strip()
FEISHU_APP_SECRET = os.environ.get("FEISHU_APP_SECRET", "").strip()
FEISHU_TENANT_KEY = os.environ.get("FEISHU_TENANT_KEY", "").strip()
FEISHU_OPEN_BASE = os.environ.get("FEISHU_OPEN_BASE", "https://open.feishu.cn").rstrip("/")
FEISHU_AUTHORIZE_URL = os.environ.get(
    "FEISHU_AUTHORIZE_URL", "https://accounts.feishu.cn/open-apis/authen/v1/authorize"
)

NETEASE_BASE_URL = os.environ.get("NETEASE_BASE_URL", "https://api.qiye.163.com").rstrip("/")
NETEASE_APP_ID = os.environ.get("NETEASE_APP_ID", "").strip()
NETEASE_AUTH_CODE = os.environ.get("NETEASE_AUTH_CODE", "").strip()
NETEASE_ORG_OPEN_ID = os.environ.get("NETEASE_ORG_OPEN_ID", "").strip()
NETEASE_DOMAIN = os.environ.get("NETEASE_DOMAIN", "").strip().lower()
NETEASE_ROOT_UNIT_ID = os.environ.get("NETEASE_ROOT_UNIT_ID", "").strip()
# The pinned root unit is deployment-specific and must come from config; an
# empty name leaves the NetEase client unconfigured rather than guessing.
NETEASE_ROOT_UNIT_NAME = os.environ.get("NETEASE_ROOT_UNIT_NAME", "").strip()
FEISHU_DEPARTMENT_ANCHOR = os.environ.get(
    "FEISHU_DEPARTMENT_ANCHOR", NETEASE_ROOT_UNIT_NAME
).strip()
CREATE_MISSING_UNITS = os.environ.get("CREATE_MISSING_UNITS", "1") == "1"
NETEASE_WEB_LOGIN_URL = os.environ.get("NETEASE_WEB_LOGIN_URL", "https://qiye.163.com/login/").strip()
# READ_ONLY is the master kill switch for every NetEase write.  Set it to 1 to
# put the service back into the observation-only mode it shipped with.
READ_ONLY = os.environ.get("READ_ONLY", "1") != "0"
# 0-no change required, 1-web login must change it, 2-web login must change it
# and clients cannot log in until it is changed.
PASS_CHANGE_FIRST_LOGIN = int(os.environ.get("NETEASE_PASS_CHANGE_FIRST_LOGIN", "2"))
VISIBLE_IN_ADDR = int(os.environ.get("NETEASE_VISIBLE_IN_ADDR", "1"))
INITIAL_PASSWORD_DIGITS = int(os.environ.get("INITIAL_PASSWORD_DIGITS", "6"))
# Seconds a Feishu authentication stays fresh enough for the actions in
# FRESH_AUTH_ACTIONS.  0 or less switches re-authentication off entirely: the
# generated password only ever reaches the account owner's own Feishu, so a
# hijacked session cannot steal a credential either way, and the check buys
# protection against nuisance resets alone.
FRESH_AUTH_TTL = int(os.environ.get("FRESH_AUTH_TTL", "300"))
FRESH_AUTH_ENABLED = FRESH_AUTH_TTL > 0

EMPLOYEE_NO_RE = re.compile(r"^[A-Za-z0-9._-]{2,64}$")
ACCOUNT_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$")
# NetEase business code for "the requested record does not exist".
NETEASE_NOT_FOUND = -4

WRITE_ACTIONS = {"provision", "password"}
# "provision" delivers its generated password to the account owner's Feishu, so
# a stolen browser session gains nothing from it.  "password" replaces the
# password of a mailbox that already exists and therefore requires a recent
# Feishu authentication, exactly like the OA password reset.
FRESH_AUTH_ACTIONS = {"password"}
# The browser must never name a target.  Identity comes from the signed session.
TARGET_KEYS = {
    "accountname",
    "account_name",
    "employeeno",
    "employee_no",
    "jobnumber",
    "job_number",
    "domain",
    "email",
    "mobile",
    "openid",
    "open_id",
    "unitid",
    "unit_id",
    "password",
}


def _require_secret(name: str, value: bytes) -> bytes:
    if len(value) < 24:
        raise RuntimeError(f"{name} must contain at least 24 bytes")
    return value


class ServiceError(Exception):
    def __init__(self, message: str, status: int = 400, detail: Any = None):
        super().__init__(message)
        self.status = status
        self.detail = detail


class IntegrationUnavailable(ServiceError):
    def __init__(self, message: str):
        super().__init__(message, 503)


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class SessionCodec:
    def __init__(self, secret: bytes):
        self.secret = secret

    def _digest(self, body: str) -> "hmac.HMAC":
        return hmac.new(self.secret, body.encode("ascii"), hashlib.sha256)

    def encode(self, value: Dict[str, Any]) -> str:
        payload = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
        body = _b64e(payload)
        return body + "." + _b64e(self._digest(body).digest())

    def decode(self, token: str) -> Optional[Dict[str, Any]]:
        try:
            body, signature = token.rsplit(".", 1)
            digest = self._digest(body)
            if not hmac.compare_digest(signature, _b64e(digest.digest())):
                return None
            value = json.loads(_b64d(body).decode("utf-8"))
            if not isinstance(value, dict) or int(value.get("exp", 0)) < int(time.time()):
                return None
            return value
        except (ValueError, TypeError, json.JSONDecodeError):
            return None


def json_request(
    method: str,
    url: str,
    payload: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    data = None if payload is None else json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    request_headers = {"Accept": "application/json", **(headers or {})}
    if data is not None:
        request_headers.setdefault("Content-Type", "application/json; charset=utf-8")
    req = urlrequest.Request(url, data=data, headers=request_headers, method=method)
    try:
        with urlrequest.urlopen(req, timeout=HTTP_TIMEOUT) as response:
            raw = response.read().decode("utf-8", "replace")
    except urlerror.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace")
        try:
            parsed = json.loads(raw)
        except ValueError:
            raise ServiceError("上游服务返回 HTTP 错误", 502, {"status": exc.code}) from exc
        if isinstance(parsed, dict):
            return parsed
        raise ServiceError("上游服务返回异常内容", 502, {"status": exc.code}) from exc
    except (urlerror.URLError, TimeoutError, OSError) as exc:
        raise ServiceError("无法连接上游服务", 502) from exc
    try:
        result = json.loads(raw)
    except ValueError as exc:
        raise ServiceError("上游服务返回非 JSON 内容", 502) from exc
    if not isinstance(result, dict):
        raise ServiceError("上游服务返回的数据结构无效", 502)
    return result


def normalize_email(value: Any) -> str:
    return str(value or "").strip().lower()


def normalize_phone(value: Any) -> str:
    digits = re.sub(r"\D", "", str(value or ""))
    if len(digits) == 13 and digits.startswith("86"):
        digits = digits[2:]
    return digits


def masked_phone(value: Any) -> str:
    phone = normalize_phone(value)
    if not phone:
        return "未填写"
    if len(phone) <= 4:
        return "*" * len(phone)
    return "*" * (len(phone) - 4) + phone[-4:]


def unique_strings(values: Iterable[Any]) -> List[str]:
    result: List[str] = []
    seen: Set[str] = set()
    for value in values:
        text = str(value or "").strip()
        if text and text not in seen:
            seen.add(text)
            result.append(text)
    return result


def account_emails(account: Dict[str, Any], default_domain: str = "") -> List[str]:
    values: List[Any] = []
    name = str(account.get("accountName") or "").strip()
    domain = str(account.get("domain") or default_domain).strip()
    if name and domain:
        values.append(f"{name}@{domain}")
    values.extend(account.get("aliasEmailList") or [])
    values.extend(account.get("aliasList") or [])
    for item in account.get("mailAccountList") or []:
        if isinstance(item, dict) and item.get("accountName") and item.get("domain"):
            values.append(f"{item['accountName']}@{item['domain']}")
    normalized: List[str] = []
    for value in values:
        email = normalize_email(value)
        if email and "@" not in email and default_domain:
            email = f"{email}@{default_domain}"
        if email and email not in normalized:
            normalized.append(email)
    return normalized


def account_phones(account: Dict[str, Any]) -> Set[str]:
    return {
        value
        for value in (
            normalize_phone(account.get("mobile")),
            normalize_phone(account.get("bindMobile")),
            normalize_phone(account.get("securityMobile")),
        )
        if value
    }


def relative_department_path(department_path: Iterable[Any]) -> List[str]:
    """Return the departments to mirror below the pinned NetEase root unit.

    ``FEISHU_DEPARTMENT_ANCHOR`` names the Feishu department that stands for the
    company, and only the part of the path below it is mirrored.  That is what
    keeps one company's employees out of another's unit tree when a single
    Feishu tenant holds several companies.

    Leave the anchor empty when the Feishu tree has no such node -- a tenant
    organized by function rather than by legal entity, or one that holds a
    single company.  The whole path is then mirrored below the root unit, and
    the company boundary is the one already enforced elsewhere: a dedicated
    Feishu application per tenant, the pinned root unit, and the work-email
    domain check in ``provision_target``.
    """
    cleaned: List[str] = []
    for value in department_path:
        name = str(value or "").strip()
        # Department identity includes its position in the hierarchy. Adjacent
        # parent and child units may legitimately carry the same display name.
        if name:
            cleaned.append(name)
    if not FEISHU_DEPARTMENT_ANCHOR:
        return cleaned
    try:
        anchor_index = cleaned.index(FEISHU_DEPARTMENT_ANCHOR)
    except ValueError as exc:
        raise ServiceError(
            f"飞书组织路径未包含「{FEISHU_DEPARTMENT_ANCHOR}」，禁止在错误组织下创建邮箱",
            409,
        ) from exc
    return cleaned[anchor_index + 1 :]


class FeishuClient:
    def __init__(self) -> None:
        self._tenant_token: Optional[str] = None
        self._tenant_expire_at = 0.0
        self._lock = threading.Lock()

    def configured(self) -> bool:
        return bool(FEISHU_APP_ID and FEISHU_APP_SECRET)

    def exchange_code(self, code: str, redirect_uri: str) -> Dict[str, Any]:
        if not self.configured():
            raise IntegrationUnavailable("飞书应用尚未配置")
        response = json_request(
            "POST",
            f"{FEISHU_OPEN_BASE}/open-apis/authen/v2/oauth/token",
            {
                "grant_type": "authorization_code",
                "client_id": FEISHU_APP_ID,
                "client_secret": FEISHU_APP_SECRET,
                "code": code,
                "redirect_uri": redirect_uri,
            },
        )
        token = response.get("access_token") or (response.get("data") or {}).get("access_token")
        if not token:
            raise ServiceError("飞书授权码换取用户令牌失败", 502, {"code": response.get("code")})
        info = json_request(
            "GET",
            f"{FEISHU_OPEN_BASE}/open-apis/authen/v1/user_info",
            headers={"Authorization": f"Bearer {token}"},
        )
        user = info.get("data") or {}
        if not user.get("open_id"):
            raise ServiceError("飞书未返回当前用户 open_id", 502)
        return user

    def tenant_token(self) -> str:
        with self._lock:
            if self._tenant_token and time.time() < self._tenant_expire_at - 60:
                return self._tenant_token
            response = json_request(
                "POST",
                f"{FEISHU_OPEN_BASE}/open-apis/auth/v3/tenant_access_token/internal",
                {"app_id": FEISHU_APP_ID, "app_secret": FEISHU_APP_SECRET},
            )
            token = response.get("tenant_access_token")
            if not token:
                raise ServiceError("获取飞书 tenant_access_token 失败", 502, {"code": response.get("code")})
            self._tenant_token = str(token)
            self._tenant_expire_at = time.time() + int(response.get("expire", 7200))
            return self._tenant_token

    def contact_user(self, open_id: str) -> Dict[str, Any]:
        quoted = urlparse.quote(open_id, safe="")
        response = json_request(
            "GET",
            f"{FEISHU_OPEN_BASE}/open-apis/contact/v3/users/{quoted}"
            "?user_id_type=open_id&department_id_type=open_department_id",
            headers={"Authorization": f"Bearer {self.tenant_token()}"},
        )
        if response.get("code") not in (None, 0):
            raise ServiceError("读取飞书员工通讯录失败", 502, {"code": response.get("code")})
        return (response.get("data") or {}).get("user") or {}

    def department(self, department_id: str) -> Dict[str, Any]:
        quoted = urlparse.quote(department_id, safe="")
        response = json_request(
            "GET",
            f"{FEISHU_OPEN_BASE}/open-apis/contact/v3/departments/{quoted}"
            "?department_id_type=open_department_id&user_id_type=open_id",
            headers={"Authorization": f"Bearer {self.tenant_token()}"},
        )
        if response.get("code") not in (None, 0):
            raise ServiceError("读取飞书部门信息失败", 502, {"code": response.get("code")})
        return (response.get("data") or {}).get("department") or {}

    def department_path(self, contact: Dict[str, Any]) -> Tuple[List[str], Optional[str]]:
        department_ids = unique_strings(contact.get("department_ids") or [])
        if not department_ids:
            return [], "飞书名片未返回所属部门"
        current = department_ids[0]
        path: List[str] = []
        seen: Set[str] = set()
        try:
            while current and current not in seen and len(path) < 32:
                seen.add(current)
                item = self.department(current)
                if item.get("name"):
                    path.append(str(item["name"]))
                parent = str(item.get("parent_department_id") or "")
                if not parent or parent == "0":
                    break
                current = parent
            path.reverse()
            return path, None
        except ServiceError as exc:
            return [], str(exc)

    def send_text(self, open_id: str, text: str, message_uuid: Optional[str] = None) -> None:
        if not self.configured():
            raise IntegrationUnavailable("飞书应用尚未配置")
        response = json_request(
            "POST",
            f"{FEISHU_OPEN_BASE}/open-apis/im/v1/messages?receive_id_type=open_id",
            {
                "receive_id": open_id,
                "msg_type": "text",
                "content": json.dumps({"text": text}, ensure_ascii=False, separators=(",", ":")),
                # A stable uuid lets Feishu deduplicate our retries so a slow
                # response never delivers the same password twice.
                "uuid": message_uuid or str(uuid.uuid4()),
            },
            headers={"Authorization": f"Bearer {self.tenant_token()}"},
        )
        if response.get("code") not in (None, 0):
            raise ServiceError("飞书通知发送失败", 502, {"code": response.get("code")})

    def require_active_employee(self, open_id: str, employee_no: str) -> Dict[str, Any]:
        """Re-read the directory immediately before a write.

        A browser session issued before the employee was frozen or resigned must
        not be able to create or repassword a mailbox.
        """
        contact = self.contact_user(open_id)
        if str(contact.get("employee_no") or "").strip() != employee_no:
            raise ServiceError("飞书身份与员工编号不一致，操作已拒绝", 403)
        self.require_active_contact(contact)
        return contact

    def resolve_identity(self, code: str, redirect_uri: str) -> Dict[str, str]:
        auth_user = self.exchange_code(code, redirect_uri)
        tenant_key = str(auth_user.get("tenant_key") or "")
        if FEISHU_TENANT_KEY and tenant_key != FEISHU_TENANT_KEY:
            raise ServiceError("飞书租户不匹配", 403)
        open_id = str(auth_user["open_id"])
        contact = self.contact_user(open_id)
        employee_no = str(contact.get("employee_no") or auth_user.get("employee_no") or "").strip()
        if not EMPLOYEE_NO_RE.fullmatch(employee_no):
            raise ServiceError("飞书通讯录未配置有效员工编号", 403)
        self.require_active_contact(contact)
        return {
            "open_id": open_id,
            "union_id": str(auth_user.get("union_id") or ""),
            "tenant_key": tenant_key,
            "name": str(contact.get("name") or auth_user.get("name") or "飞书用户"),
            "employee_no": employee_no,
        }

    @staticmethod
    def require_active_contact(contact: Dict[str, Any]) -> None:
        status = contact.get("status") or {}
        if status and (status.get("is_frozen") or status.get("is_resigned") or status.get("is_unactivated")):
            raise ServiceError("当前飞书员工状态不允许使用邮箱自助服务", 403)

    def verified_contact(self, claims: Dict[str, Any]) -> Dict[str, Any]:
        contact = self.contact_user(str(claims["open_id"]))
        if str(contact.get("employee_no") or "").strip() != str(claims["employee_no"]):
            raise ServiceError("飞书身份与员工编号不一致", 403)
        self.require_active_contact(contact)
        return contact


class NetEaseClient:
    def __init__(self) -> None:
        self._access_token: Optional[str] = None
        self._access_expire_at = 0.0
        self._token_lock = threading.Lock()
        self._cache_lock = threading.Lock()
        self._unit_write_lock = threading.Lock()
        self._units_cache: Tuple[float, List[Dict[str, Any]]] = (0.0, [])
        self._accounts_cache: Tuple[float, List[Dict[str, Any]]] = (0.0, [])
        # Name the pinned root unit currently carries in NetEase.  Recorded on
        # every unit listing so the page can show it and a rename leaves a trace
        # even when NETEASE_ROOT_UNIT_NAME is empty and nothing is enforced.
        self.root_unit_name = ""

    def configured(self) -> bool:
        return all(
            [
                NETEASE_APP_ID,
                NETEASE_AUTH_CODE,
                NETEASE_ORG_OPEN_ID,
                NETEASE_DOMAIN,
                NETEASE_ROOT_UNIT_ID,
            ]
        )

    def _token(self, force: bool = False) -> str:
        if not self.configured():
            raise IntegrationUnavailable("网易企业邮箱接口尚未配置")
        with self._token_lock:
            if not force and self._access_token and time.time() < self._access_expire_at - 60:
                return self._access_token
            response = json_request(
                "POST",
                f"{NETEASE_BASE_URL}/api/pub/token/acquireToken",
                {
                    "appId": NETEASE_APP_ID,
                    "authCode": NETEASE_AUTH_CODE,
                    "orgOpenId": NETEASE_ORG_OPEN_ID,
                },
            )
            if not response.get("success") or not (response.get("data") or {}).get("accessToken"):
                raise ServiceError("网易接口鉴权失败", 502, {"code": response.get("code")})
            self._access_token = str(response["data"]["accessToken"])
            self._access_expire_at = time.time() + 3600
            return self._access_token

    def call(self, path: str, payload: Dict[str, Any], retry: bool = True) -> Dict[str, Any]:
        token = self._token()
        headers = {
            "qiye-access-token": token,
            "qiye-app-id": NETEASE_APP_ID,
            "qiye-org-open-id": NETEASE_ORG_OPEN_ID,
            "domain": NETEASE_DOMAIN,
        }
        response = json_request("POST", NETEASE_BASE_URL + path, payload, headers)
        if response.get("code") in (-300, -301) and retry:
            self._token(force=True)
            return self.call(path, payload, retry=False)
        return response

    @staticmethod
    def _require_success(response: Dict[str, Any], action: str) -> Any:
        if not response.get("success"):
            raise ServiceError(
                f"网易接口{action}失败",
                502,
                {"code": response.get("code"), "message": response.get("message")},
            )
        return response.get("data")

    def units(self, refresh: bool = False) -> List[Dict[str, Any]]:
        with self._cache_lock:
            expires, cached = self._units_cache
            if not refresh and cached and time.time() < expires:
                return cached
        response = self.call("/api/open/unit/getUnitList", {"domain": NETEASE_DOMAIN})
        items = list(self._require_success(response, "查询部门") or [])
        root = next((item for item in items if str(item.get("unitId")) == NETEASE_ROOT_UNIT_ID), None)
        if not root:
            # Without the root unit every later step would silently address an
            # empty subtree, so stop here whatever the name setting says.
            raise ServiceError(
                f"网易中不存在部门 {NETEASE_ROOT_UNIT_ID}，已停止查询", 503
            )
        observed = str(root.get("unitName") or "").strip()
        if NETEASE_ROOT_UNIT_NAME and observed != NETEASE_ROOT_UNIT_NAME:
            # Name the two values: a rename is otherwise indistinguishable from
            # a wrong unit id, and the difference decides how you recover.
            raise ServiceError(
                f"网易部门 {NETEASE_ROOT_UNIT_ID} 实际名称为「{observed}」，"
                f"与配置的「{NETEASE_ROOT_UNIT_NAME}」不一致，已停止查询",
                503,
            )
        if observed != self.root_unit_name:
            if self.root_unit_name:
                log.warning(
                    "netease root unit %s renamed from %r to %r",
                    NETEASE_ROOT_UNIT_ID, self.root_unit_name, observed,
                )
            else:
                log.info("netease root unit %s is named %r", NETEASE_ROOT_UNIT_ID, observed)
            self.root_unit_name = observed
        with self._cache_lock:
            self._units_cache = (time.time() + 300, items)
        return items

    def unit_map(self, refresh: bool = False) -> Dict[str, Dict[str, Any]]:
        return {str(item.get("unitId")): item for item in self.units(refresh)}

    def descendant_unit_ids(self, refresh: bool = False) -> Set[str]:
        items = self.units(refresh)
        children: Dict[str, List[str]] = {}
        for item in items:
            parent = str(item.get("unitParentId") or "")
            children.setdefault(parent, []).append(str(item.get("unitId")))
        result: Set[str] = set()
        stack = [NETEASE_ROOT_UNIT_ID]
        while stack:
            current = stack.pop()
            if current in result:
                continue
            result.add(current)
            stack.extend(children.get(current, []))
        return result

    def unit_path(self, unit_id: Any) -> List[Dict[str, str]]:
        mapping = self.unit_map()
        current = str(unit_id or "")
        path: List[Dict[str, str]] = []
        seen: Set[str] = set()
        while current and current not in seen:
            seen.add(current)
            item = mapping.get(current)
            if not item:
                break
            path.append({"unitId": current, "unitName": str(item.get("unitName") or "")})
            if current == NETEASE_ROOT_UNIT_ID:
                break
            current = str(item.get("unitParentId") or "")
        path.reverse()
        return path

    def accounts(self, refresh: bool = False) -> List[Dict[str, Any]]:
        with self._cache_lock:
            expires, cached = self._accounts_cache
            if not refresh and cached and time.time() < expires:
                return cached
        result: List[Dict[str, Any]] = []
        page = 1
        while page <= 100:
            response = self.call(
                "/api/open/unit/getAccountList",
                {
                    "domain": NETEASE_DOMAIN,
                    "unitId": NETEASE_ROOT_UNIT_ID,
                    "recursion": True,
                    "pageNum": page,
                    "pageSize": 50,
                },
            )
            data = self._require_success(response, "查询账号列表") or {}
            batch = list(data.get("list") or [])
            result.extend(batch)
            count = int(data.get("count") or len(result))
            if not batch or len(result) >= count:
                break
            page += 1
        if page > 100:
            raise ServiceError("网易账号列表分页异常", 502)
        with self._cache_lock:
            self._accounts_cache = (time.time() + 120, result)
        return result

    def job_matches(self, employee_no: str) -> List[Dict[str, Any]]:
        response = self.call(
            "/api/open/account/getAccountListByNicknameAndJobNo",
            {"domain": NETEASE_DOMAIN, "jobNumber": employee_no},
        )
        data = self._require_success(response, "按工号查询账号") or {}
        return list(data.get("list") or [])

    def account_detail(self, account_name: str) -> Dict[str, Any]:
        payload = {"domain": NETEASE_DOMAIN, "accountName": account_name}
        response = self.call("/api/open/account/getAccount", payload)
        detail = dict(self._require_success(response, "查询账号") or {})
        aliases = self.call("/api/open/account/getAccountAliasList", payload)
        if aliases.get("success"):
            detail["aliasEmailList"] = unique_strings(
                list(detail.get("aliasEmailList") or []) + list((aliases.get("data") or {}).get("alias") or [])
            )
        mobile = self.call("/api/open/mobile/getMobile", payload)
        if mobile.get("success") and (mobile.get("data") or {}).get("mobile"):
            detail["securityMobile"] = (mobile.get("data") or {}).get("mobile")
        return detail

    def account_exists(self, account_name: str) -> bool:
        """Definitive existence check, including accounts outside the pinned root.

        ``check_employee`` only walks the pinned organization, so an unrelated
        mailbox holding the same name elsewhere in the domain would otherwise go
        unnoticed until creation failed.
        """
        response = self.call(
            "/api/open/account/getAccount",
            {"domain": NETEASE_DOMAIN, "accountName": account_name},
        )
        if response.get("success"):
            return bool(response.get("data"))
        # getAccount also reports an absent account via the generic -3 code.
        # Require its exact business marker; other -3 failures remain errors.
        account_not_found = response.get("code") == -3 and re.search(
            r"(?<![A-Za-z0-9_.])ACCOUNT\.NOTEXIST(?=:|\s|$)",
            str(response.get("message") or ""),
        ) is not None
        if response.get("code") == NETEASE_NOT_FOUND or account_not_found:
            return False
        raise ServiceError(
            "网易接口查询账号可用性失败",
            502,
            {"code": response.get("code"), "message": response.get("message")},
        )

    def _matching_child_units(self, parent_id: str, name: str, refresh: bool = False) -> List[Dict[str, Any]]:
        allowed = self.descendant_unit_ids(refresh)
        return [
            item
            for item in self.units(refresh)
            if str(item.get("unitId") or "") in allowed
            and str(item.get("unitParentId") or "") == parent_id
            and str(item.get("unitName") or "").strip() == name
        ]

    def create_unit(self, parent_id: str, name: str) -> str:
        if READ_ONLY:
            raise ServiceError("当前实例为只读模式，未启用部门创建", 403)
        if parent_id not in self.descendant_unit_ids():
            raise ServiceError("上级部门不在指定组织下，部门创建已拒绝", 403)
        response = self.call(
            "/api/open/unit/createUnit",
            {
                "domain": NETEASE_DOMAIN,
                "unitName": name,
                "parentId": parent_id,
                "unitDesc": "由飞书企业邮箱自助服务同步创建",
            },
        )
        self._require_success(response, f"创建部门「{name}」")
        self.invalidate()
        matches = self._matching_child_units(parent_id, name, refresh=True)
        if len(matches) != 1:
            raise ServiceError(f"网易部门「{name}」创建后校验失败，请管理员核查", 502)
        return str(matches[0].get("unitId") or "")

    def resolve_or_create_unit(self, department_path: List[str]) -> Tuple[str, List[str]]:
        """Walk the exact parent/child path below the pinned root, creating gaps."""
        segments = relative_department_path(department_path)
        parent_id = NETEASE_ROOT_UNIT_ID
        created: List[str] = []
        with self._unit_write_lock:
            for name in segments:
                matches = self._matching_child_units(parent_id, name, refresh=bool(created))
                if len(matches) > 1:
                    raise ServiceError(
                        f"网易部门「{name}」在同一上级下存在重复记录，禁止自动选择",
                        409,
                    )
                if matches:
                    parent_id = str(matches[0].get("unitId") or "")
                    continue
                if not CREATE_MISSING_UNITS:
                    raise ServiceError(f"网易中缺少部门「{name}」，自动创建功能未启用", 409)
                parent_id = self.create_unit(parent_id, name)
                created.append(name)
        return parent_id, created

    def create_account(
        self,
        account_name: str,
        display_name: str,
        employee_no: str,
        phone: str,
        password: str,
        unit_id: str,
    ) -> Dict[str, Any]:
        if READ_ONLY:
            raise ServiceError("当前实例为只读模式，未启用邮箱开通", 403)
        if unit_id not in self.descendant_unit_ids():
            raise ServiceError("目标部门不在指定组织下，开通已拒绝", 403)
        payload: Dict[str, Any] = {
            "domain": NETEASE_DOMAIN,
            "accountName": account_name,
            "name": display_name,
            "jobNumber": employee_no,
            "password": password,
            "passType": 0,
            "passChangeFirstLogin": PASS_CHANGE_FIRST_LOGIN,
            "visibleInAddr": VISIBLE_IN_ADDR,
            "unitId": unit_id,
        }
        if phone:
            payload["bindMobile"] = phone
        response = self.call("/api/open/account/createAccount", payload)
        data = self._require_success(response, "创建账号") or {}
        returned = str(data.get("accountName") or "").strip()
        if returned and returned != account_name:
            raise ServiceError("网易接口返回了不一致的账号名，请管理员核查", 502)
        self.invalidate()
        return data

    def update_password(self, account_name: str, password: str) -> None:
        if READ_ONLY:
            raise ServiceError("当前实例为只读模式，未启用密码重置", 403)
        response = self.call(
            "/api/open/account/updatePassword",
            {
                "domain": NETEASE_DOMAIN,
                "accountName": account_name,
                "password": password,
                "passType": 0,
                "passChangeFirstLogin": PASS_CHANGE_FIRST_LOGIN,
            },
        )
        self._require_success(response, "重置密码")

    def invalidate(self) -> None:
        with self._cache_lock:
            self._units_cache = (0.0, [])
            self._accounts_cache = (0.0, [])

    def check_employee(self, contact: Dict[str, Any], refresh: bool = False) -> Dict[str, Any]:
        result = self._evaluate(contact, refresh)
        state = str(result.get("state") or "")
        writable = not READ_ONLY and self.configured()
        result["readOnly"] = READ_ONLY
        result["actions"] = {
            "provision": writable and state == "eligible",
            "password": writable and state == "matched",
        }
        # Lets the page describe the password reset accurately instead of
        # promising a re-authentication step that may be switched off.
        result["freshAuthRequired"] = FRESH_AUTH_ENABLED
        return result

    def _evaluate(self, contact: Dict[str, Any], refresh: bool = False) -> Dict[str, Any]:
        employee_no = str(contact.get("employee_no") or "").strip()
        work_email = normalize_email(contact.get("email") or contact.get("enterprise_email"))
        phone = normalize_phone(contact.get("mobile"))
        missing = [
            label
            for label, value in (("工号", employee_no), ("工作邮箱", work_email), ("手机号", phone))
            if not value
        ]
        if missing:
            return {
                "state": "blocked",
                "message": "飞书名片缺少" + "、".join(missing) + "，暂不能判断是否可开通",
                "checks": {"employeeNo": bool(employee_no), "workEmail": bool(work_email), "mobile": bool(phone)},
                "canProvision": False,
            }

        root_units = self.descendant_unit_ids(refresh)
        all_accounts = self.accounts(refresh)
        job_records = self.job_matches(employee_no)

        account_by_name: Dict[str, Dict[str, Any]] = {}
        for account in all_accounts:
            name = str(account.get("accountName") or "").strip()
            if name:
                account_by_name[name] = account

        email_names = {
            name
            for name, account in account_by_name.items()
            if work_email in account_emails(account, NETEASE_DOMAIN)
        }
        phone_names = {
            name
            for name, account in account_by_name.items()
            if phone and phone in account_phones(account)
        }
        job_names = {str(item.get("accountName") or "").strip() for item in job_records if item.get("accountName")}
        candidates = job_names | email_names | phone_names

        if not candidates:
            return {
                "state": "eligible",
                "message": "网易中未发现相同工号、工作邮箱或手机号记录，可以进入开通流程",
                "checks": {"employeeNo": True, "workEmail": True, "mobile": True},
                "canProvision": not READ_ONLY,
                "readOnly": READ_ONLY,
                "targetRoot": {"unitId": NETEASE_ROOT_UNIT_ID, "unitName": NETEASE_ROOT_UNIT_NAME},
            }

        details: Dict[str, Dict[str, Any]] = {}
        for name in sorted(candidates):
            try:
                details[name] = self.account_detail(name)
            except ServiceError:
                details[name] = dict(account_by_name.get(name) or next((x for x in job_records if x.get("accountName") == name), {}))

        if len(job_names) == 1:
            account_name = next(iter(job_names))
            detail = details.get(account_name, {})
            emails = account_emails(detail, NETEASE_DOMAIN)
            phones = account_phones(detail)
            unit_id = str(detail.get("unitId") or "")
            root_ok = unit_id in root_units
            email_ok = work_email in emails
            phone_ok = phone in phones
            unique_ok = candidates == {account_name}
            checks = {
                "employeeNo": True,
                "workEmail": email_ok,
                "mobile": phone_ok,
                "targetOrganization": root_ok,
                "uniqueAccount": unique_ok,
            }
            record = {
                "accountName": account_name,
                "primaryEmail": f"{account_name}@{detail.get('domain') or NETEASE_DOMAIN}",
                "aliases": [email for email in emails if email != f"{account_name}@{detail.get('domain') or NETEASE_DOMAIN}"],
                "status": detail.get("status"),
                "unitPath": self.unit_path(unit_id),
                "mobileMasked": masked_phone(next(iter(phones), "")),
            }
            if all(checks.values()):
                return {
                    "state": "matched",
                    "message": "网易账号、工号、工作邮箱、手机号和所属组织均匹配，不支持重复开通",
                    "checks": checks,
                    "record": record,
                    "canProvision": False,
                }
            return {
                "state": "conflict",
                "message": "网易中存在该工号，但部分信息不一致，请管理员核查，禁止自动创建",
                "checks": checks,
                "record": record,
                "canProvision": False,
            }

        return {
            "state": "conflict",
            "message": "网易中发现相同邮箱、手机号或重复工号记录，请管理员核查，禁止自动创建",
            "checks": {
                "employeeNo": len(job_names) == 0,
                "workEmail": len(email_names) == 0,
                "mobile": len(phone_names) == 0,
                "uniqueAccount": len(candidates) <= 1,
            },
            "conflictCount": len(candidates),
            "canProvision": False,
        }


feishu = FeishuClient()
netease = NetEaseClient()
codec: SessionCodec
audit_lock = threading.Lock()
log = logging.getLogger("netease-mail-self-service")


def audit(action: str, claims: Optional[Dict[str, Any]], result: str, request_id: str, detail: str = "") -> None:
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "requestId": request_id,
        "action": action,
        "result": result,
        "openId": (claims or {}).get("open_id", ""),
        "employeeNo": (claims or {}).get("employee_no", ""),
        "detail": detail[:240],
    }
    line = json.dumps(entry, ensure_ascii=False, separators=(",", ":"))
    with audit_lock:
        # Recreate the directory rather than turning a missing log path into a
        # 500 on every request; the audit trail also goes to the service log.
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        with (LOG_DIR / "audit.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
    log.info("AUDIT %s", line)


class RateLimiter:
    def __init__(self) -> None:
        self._events: Dict[Tuple[str, str], List[float]] = {}
        self._lock = threading.Lock()

    def check(self, principal: str, action: str, limit: int = 5, window: int = 600) -> None:
        now = time.time()
        key = (principal, action)
        with self._lock:
            events = [ts for ts in self._events.get(key, []) if now - ts < window]
            if len(events) >= limit:
                raise ServiceError("操作过于频繁，请稍后再试", 429)
            events.append(now)
            self._events[key] = events


limiter = RateLimiter()


class OperationLocks:
    """Serialize writes per employee so a double click cannot create twice."""

    def __init__(self) -> None:
        self._guard = threading.Lock()
        self._locks: Dict[str, threading.Lock] = {}

    @contextmanager
    def hold(self, employee_no: str):
        with self._guard:
            lock = self._locks.setdefault(employee_no, threading.Lock())
        if not lock.acquire(blocking=False):
            raise ServiceError("该账号已有操作正在处理中，请勿重复提交", 409)
        try:
            yield
        finally:
            lock.release()


operation_locks = OperationLocks()


def reject_target_keys(payload: Dict[str, Any]) -> None:
    for key in payload:
        if str(key).lower() in TARGET_KEYS:
            raise ServiceError("请求不得指定员工编号或目标账号", 400)
    if payload:
        raise ServiceError("请求包含不允许的字段", 400)


def generate_initial_password() -> str:
    """Ambiguity-free password: no O/0, I/l/1, so it survives being read aloud."""
    upper = "ABCDEFGHJKMNPQRSTUVWXYZ"
    lower = "abcdefghjkmnpqrstuvwxyz"
    digits = "23456789"
    count = max(4, min(INITIAL_PASSWORD_DIGITS, 10))
    return (
        secrets.choice(upper)
        + secrets.choice(lower)
        + "".join(secrets.choice(digits) for _ in range(count))
        + "!"
        + secrets.choice(lower)
    )


def provision_target(contact: Dict[str, Any]) -> Tuple[str, str]:
    """Derive the mailbox name from the Feishu work email, never from the browser."""
    work_email = normalize_email(contact.get("email") or contact.get("enterprise_email"))
    local, sep, domain = work_email.partition("@")
    if not sep:
        raise ServiceError("飞书名片缺少工作邮箱，无法确定邮箱账号名", 409)
    if domain != NETEASE_DOMAIN:
        raise ServiceError(f"飞书工作邮箱域名不是 {NETEASE_DOMAIN}，开通已拒绝", 409)
    if not ACCOUNT_NAME_RE.fullmatch(local):
        raise ServiceError("飞书工作邮箱前缀不符合邮箱账号名规则，开通已拒绝", 409)
    return local, work_email


def notification_text(action: str, name: str, email: str, password: str) -> str:
    display_name = name or "同事"
    location = f"登录地址：{NETEASE_WEB_LOGIN_URL}\n" if NETEASE_WEB_LOGIN_URL else ""
    if action == "provision":
        return (
            f"{display_name}，你的企业邮箱已开通。\n"
            f"{location}"
            f"邮箱地址：{email}\n"
            f"初始密码：{password}\n"
            "请尽快登录并修改密码。"
        )
    return (
        f"{display_name}，你的企业邮箱密码已重置。\n"
        f"{location}"
        f"邮箱地址：{email}\n"
        f"新随机密码：{password}\n"
        "请立即使用该密码登录，并在登录后修改密码。如非本人操作，请立即联系信息运维。"
    )


def precheck_text(action: str, name: str) -> str:
    display_name = name or "同事"
    if action == "provision":
        return f"{display_name}，系统正在为你开通企业邮箱，请稍候。"
    return f"{display_name}，系统正在重置你的企业邮箱密码，请稍候。"


def send_feishu_text_with_retry(open_id: str, text: str, attempts: int = 3) -> None:
    message_uuid = str(uuid.uuid4())
    last_error: Optional[ServiceError] = None
    for attempt in range(max(1, attempts)):
        try:
            feishu.send_text(open_id, text, message_uuid=message_uuid)
            return
        except ServiceError as exc:
            last_error = exc
            if attempt + 1 < attempts:
                time.sleep(attempt + 1)
    raise last_error or ServiceError("飞书通知发送失败", 502)


def cookie_value(header: str, name: str) -> str:
    for part in (header or "").split(";"):
        key, sep, value = part.strip().partition("=")
        if sep and key == name:
            return value
    return ""


def sanitize_request_line(value: str) -> str:
    """Remove OAuth codes and state values before writing access logs."""
    parts = value.split(" ")
    if len(parts) == 3 and "?" in parts[1]:
        parts[1] = urlparse.urlsplit(parts[1]).path
    return " ".join(parts)


class Handler(BaseHTTPRequestHandler):
    server_version = "netease-mail-self-service/1.0"
    sys_version = ""

    def version_string(self) -> str:
        return self.server_version

    def _client_ip(self) -> str:
        if TRUST_PROXY:
            return self.headers.get("X-Forwarded-For", self.client_address[0]).split(",")[0].strip()
        return self.client_address[0]

    def log_message(self, fmt: str, *args: Any) -> None:
        safe_args = list(args)
        if safe_args and isinstance(safe_args[0], str):
            safe_args[0] = sanitize_request_line(safe_args[0])
        log.info("%s %s", self._client_ip(), fmt % tuple(safe_args))

    def _request_id(self) -> str:
        return self.headers.get("X-Request-ID") or str(uuid.uuid4())

    def _headers(self, status: int, content_type: str, length: int, cookie: Optional[str] = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Pragma", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; "
            "frame-ancestors 'self' https://*.feishu.cn",
        )
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()

    def _json(self, status: int, value: Dict[str, Any], cookie: Optional[str] = None) -> None:
        body = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self._headers(status, "application/json; charset=utf-8", len(body), cookie)
        self.wfile.write(body)

    def _error(self, exc: ServiceError, request_id: str) -> None:
        self._json(exc.status, {"ok": False, "message": str(exc), "requestId": request_id})

    def _redirect(self, location: str, cookie: Optional[str] = None) -> None:
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()

    def _session(self) -> Optional[Dict[str, Any]]:
        return codec.decode(cookie_value(self.headers.get("Cookie", ""), SESSION_COOKIE))

    def _require_session(self) -> Dict[str, Any]:
        claims = self._session()
        if not claims or not claims.get("employee_no") or not claims.get("open_id"):
            raise ServiceError("请先通过飞书登录", 401)
        return claims

    def _require_fresh_auth(self, claims: Dict[str, Any]) -> None:
        if not FRESH_AUTH_ENABLED:
            return
        auth_time = int(claims.get("auth_time") or claims.get("iat") or 0)
        if int(time.time()) - auth_time > FRESH_AUTH_TTL:
            raise ServiceError("敏感操作前需要重新通过飞书验证身份", 401)

    def _read_json(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        if length < 0 or length > 64 * 1024:
            raise ServiceError("请求体过大", 413)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            value = json.loads(raw.decode("utf-8") or "{}")
        except (ValueError, UnicodeDecodeError) as exc:
            raise ServiceError("请求必须是 JSON", 400) from exc
        if not isinstance(value, dict):
            raise ServiceError("请求必须是 JSON 对象", 400)
        return value

    def _require_csrf(self, claims: Dict[str, Any]) -> None:
        supplied = self.headers.get("X-CSRF-Token", "")
        if not supplied or not hmac.compare_digest(str(claims.get("csrf", "")), supplied):
            raise ServiceError("请求校验失败，请刷新页面后重试", 403)

    def _cookie(self, claims: Dict[str, Any]) -> str:
        parts = [
            f"{SESSION_COOKIE}={codec.encode(claims)}",
            "Path=/",
            f"Max-Age={SESSION_TTL}",
            "HttpOnly",
            f"SameSite={COOKIE_SAMESITE}",
        ]
        if COOKIE_SECURE:
            parts.append("Secure")
        return "; ".join(parts)

    def _redirect_uri(self) -> str:
        if not PUBLIC_BASE_URL:
            raise IntegrationUnavailable("PUBLIC_BASE_URL 尚未配置")
        return f"{PUBLIC_BASE_URL}/auth/feishu/callback"

    def _state(self) -> str:
        now = int(time.time())
        return codec.encode({"purpose": "feishu-oauth", "iat": now, "exp": now + 600, "nonce": secrets.token_hex(16)})

    def _check_state(self, value: str) -> None:
        state = codec.decode(value)
        if not state or state.get("purpose") != "feishu-oauth":
            raise ServiceError("飞书登录状态无效或已过期", 400)

    def _serve_static(self, path: str) -> None:
        relative = "index.html" if path in ("/", "/index.html") else path.lstrip("/")
        if relative not in {"index.html", "app.js", "styles.css"}:
            raise ServiceError("页面不存在", 404)
        target = STATIC_DIR / relative
        if not target.is_file():
            raise ServiceError("页面文件不存在", 404)
        body = target.read_bytes()
        if target.name == "index.html":
            body = body.replace(b"{{BASE_PATH}}", BASE_PATH.encode("utf-8"))
            # Prefer the configured name; with verification switched off fall
            # back to whatever NetEase last reported for the pinned unit.
            display_root = NETEASE_ROOT_UNIT_NAME or netease.root_unit_name or "—"
            body = body.replace(
                b"{{ROOT_UNIT_NAME}}", html.escape(display_root).encode("utf-8")
            )
        content_type = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        if target.suffix in {".html", ".js", ".css"}:
            content_type += "; charset=utf-8"
        self._headers(200, content_type, len(body))
        self.wfile.write(body)

    def do_GET(self) -> None:
        request_id = self._request_id()
        parsed = urlparse.urlparse(self.path)
        try:
            if parsed.path == "/healthz":
                return self._json(
                    200,
                    {
                        "ok": True,
                        "service": "netease-mail-self-service",
                        "readOnly": READ_ONLY,
                        "writeEnabled": not READ_ONLY and feishu.configured() and netease.configured(),
                        "feishuConfigured": feishu.configured(),
                        "neteaseConfigured": netease.configured(),
                        "rootUnitId": NETEASE_ROOT_UNIT_ID,
                    },
                )
            if parsed.path == "/auth/feishu/start":
                if not feishu.configured():
                    raise IntegrationUnavailable("独立飞书应用尚未配置")
                query = urlparse.urlencode(
                    {
                        "app_id": FEISHU_APP_ID,
                        "client_id": FEISHU_APP_ID,
                        "redirect_uri": self._redirect_uri(),
                        "response_type": "code",
                        "state": self._state(),
                    }
                )
                return self._redirect(f"{FEISHU_AUTHORIZE_URL}?{query}")
            if parsed.path == "/auth/feishu/callback":
                query = urlparse.parse_qs(parsed.query)
                code = (query.get("code") or [""])[0]
                state = (query.get("state") or [""])[0]
                if not code:
                    raise ServiceError("飞书未返回授权码", 400)
                self._check_state(state)
                identity = feishu.resolve_identity(code, self._redirect_uri())
                now = int(time.time())
                claims: Dict[str, Any] = {
                    **identity,
                    "iat": now,
                    "auth_time": now,
                    "exp": now + SESSION_TTL,
                    "csrf": secrets.token_urlsafe(24),
                }
                audit("login", claims, "success", request_id)
                return self._redirect("/", self._cookie(claims))
            if parsed.path == "/logout":
                cookie = (
                    f"{SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; "
                    f"SameSite={COOKIE_SAMESITE}"
                )
                if COOKIE_SECURE:
                    cookie += "; Secure"
                return self._redirect("/?logged_out=1", cookie)
            if parsed.path == "/api/me":
                claims = self._require_session()
                contact = feishu.verified_contact(claims)
                department_path, department_warning = feishu.department_path(contact)
                return self._json(
                    200,
                    {
                        "ok": True,
                        "user": {
                            "name": contact.get("name") or claims.get("name"),
                            "employeeNo": claims.get("employee_no"),
                            "workEmail": normalize_email(contact.get("email") or contact.get("enterprise_email")),
                            "mobileMasked": masked_phone(contact.get("mobile")),
                            "departmentPath": department_path,
                            "departmentWarning": department_warning,
                        },
                        "csrfToken": claims.get("csrf"),
                    },
                )
            if parsed.path == "/api/status":
                claims = self._require_session()
                contact = feishu.verified_contact(claims)
                result = netease.check_employee(contact)
                audit("status", claims, "success", request_id, str(result.get("state")))
                return self._json(200, {"ok": True, "data": result, "requestId": request_id})
            return self._serve_static(parsed.path)
        except ServiceError as exc:
            audit("get:" + parsed.path, self._session(), "denied", request_id, str(exc))
            self._error(exc, request_id)
        except Exception:
            log.exception("unhandled GET error request_id=%s", request_id)
            self._error(ServiceError("服务器内部错误", 500), request_id)

    def _mail_action(self, action: str, claims: Dict[str, Any], request_id: str) -> Dict[str, Any]:
        """Run one NetEase write under the same guarantees as the OA actions."""
        employee_no = str(claims["employee_no"])
        open_id = str(claims["open_id"])
        limiter.check(open_id, action)
        with operation_locks.hold(employee_no):
            contact = feishu.require_active_employee(open_id, employee_no)
            # Re-evaluate against live NetEase data inside the lock: the cached
            # verdict the browser rendered may be minutes old.
            status = netease.check_employee(contact, refresh=True)
            state = str(status.get("state") or "")
            if action == "provision" and state != "eligible":
                raise ServiceError(
                    "当前状态不允许开通邮箱：" + str(status.get("message") or state), 409, status
                )
            if action == "password" and state != "matched":
                raise ServiceError(
                    "当前状态不允许重置邮箱密码：" + str(status.get("message") or state), 409, status
                )

            display_name = str(contact.get("name") or claims.get("name") or "")
            password = generate_initial_password()

            # Resolve the target with read-only calls first.  A request that is
            # going to be rejected must not announce itself to the employee, who
            # would otherwise be left with "请稍候" and no follow-up message.
            if action == "provision":
                account_name, work_email = provision_target(contact)
                if netease.account_exists(account_name):
                    raise ServiceError("网易中已存在同名账号，开通已拒绝，请联系管理员核查", 409)
                department_path, department_warning = feishu.department_path(contact)
                if not department_path:
                    # Report why the path is missing instead of letting the
                    # anchor check blame an organization path we never read.
                    raise ServiceError(
                        "未能读取飞书组织路径（"
                        + (department_warning or "原因未知")
                        + "），开通已拒绝",
                        409,
                    )
                # Reject a path we cannot map before telling the employee the
                # mailbox is on its way; resolve_or_create_unit repeats this.
                relative_department_path(department_path)
            else:
                record = status.get("record") or {}
                account_name = str(record.get("accountName") or "")
                work_email = str(record.get("primaryEmail") or "")
                if not account_name:
                    raise ServiceError("未能确定要重置密码的邮箱账号", 409)

            # Fail closed when Feishu cannot deliver: a password we generate but
            # cannot hand over would lock the employee out of their own mailbox.
            # Every NetEase write below this point is gated on it, unit creation
            # included.
            try:
                send_feishu_text_with_retry(open_id, precheck_text(action, display_name))
            except ServiceError as exc:
                audit(action + ":notify-precheck", claims, "denied", request_id, str(exc))
                raise ServiceError(
                    "飞书机器人通知不可用，暂不能执行操作，请确认机器人能力和消息权限已发布生效", 502
                ) from exc

            if action == "provision":
                unit_id, created_units = netease.resolve_or_create_unit(department_path)
                netease.create_account(
                    account_name,
                    display_name or account_name,
                    employee_no,
                    normalize_phone(contact.get("mobile")),
                    password,
                    unit_id,
                )
                message = "企业邮箱开通成功"
                unit_warning = (
                    "；已同步创建网易部门：" + " / ".join(created_units)
                    if created_units
                    else ""
                )
            else:
                unit_warning = ""
                netease.update_password(account_name, password)
                message = "企业邮箱密码重置成功"

            # Deliver the password immediately after a successful write. A slow
            # or failed read-back must never prevent delivery of live credentials.
            try:
                send_feishu_text_with_retry(
                    open_id, notification_text(action, display_name, work_email, password)
                )
                audit(action + ":notify", claims, "success", request_id, "message accepted")
                message += "，密码已通过飞书发送给你"
            except ServiceError as exc:
                audit(action + ":notify", claims, "warning", request_id, str(exc))
                log.warning("feishu notification failed request_id=%s action=%s", request_id, action)
                message += "；操作已完成，但随机密码飞书发送失败，请立即联系管理员重置密码"
            verify_warning = ""
            try:
                after = netease.check_employee(contact, refresh=True)
            except Exception:
                # Do not reuse the pre-write eligible state or expose raw errors.
                # The write succeeded, but its final state is not yet verified.
                log.warning("post-write verification failed request_id=%s action=%s", request_id, action)
                after = {
                    "state": "error",
                    "readOnly": READ_ONLY,
                    "canProvision": False,
                    "actions": {"provision": False, "password": False},
                }
            if str(after.get("state")) != "matched":
                verify_warning = "；操作已完成，但最终状态暂未核实，请稍后刷新核对，勿重复操作"
                after = {**after, "canProvision": False,
                         "actions": {"provision": False, "password": False}}
            if unit_warning:
                message += unit_warning
            message += verify_warning
            return {**after, "message": message, "accountName": account_name}

    def do_POST(self) -> None:
        request_id = self._request_id()
        parsed = urlparse.urlparse(self.path)
        claims: Optional[Dict[str, Any]] = None
        action = ""
        try:
            if parsed.path == "/api/refresh":
                action = "refresh"
            elif parsed.path.startswith("/api/action/"):
                action = parsed.path.rsplit("/", 1)[-1]
                if action not in WRITE_ACTIONS:
                    raise ServiceError("不支持的操作", 404)
            else:
                raise ServiceError("接口不存在", 404)

            claims = self._require_session()
            self._require_csrf(claims)
            reject_target_keys(self._read_json())

            if action == "refresh":
                contact = feishu.verified_contact(claims)
                result = netease.check_employee(contact, refresh=True)
                audit("refresh", claims, "success", request_id, str(result.get("state")))
                return self._json(200, {"ok": True, "data": result, "requestId": request_id})

            if READ_ONLY:
                raise ServiceError("当前实例为只读模式，未启用邮箱写操作", 403)
            if action in FRESH_AUTH_ACTIONS:
                self._require_fresh_auth(claims)
            result = self._mail_action(action, claims, request_id)
            audit(action, claims, "success", request_id, str(result.get("state")))
            return self._json(200, {"ok": True, "data": result, "requestId": request_id})
        except ServiceError as exc:
            audit(action or ("post:" + parsed.path), claims or self._session(), "denied", request_id, str(exc))
            self._error(exc, request_id)
        except Exception:
            log.exception("unhandled POST error request_id=%s", request_id)
            audit(action or ("post:" + parsed.path), claims, "error", request_id, "internal error")
            self._error(ServiceError("服务器内部错误", 500), request_id)


class ServiceHTTPServer(ThreadingHTTPServer):
    """Bind without BaseHTTPServer's blocking reverse-DNS lookup."""

    daemon_threads = True

    def server_bind(self) -> None:
        socketserver.TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        self.server_name = str(host)
        self.server_port = int(port)


def configure_logging() -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    handler = TimedRotatingFileHandler(
        LOG_DIR / "service.log", when="midnight", interval=1, backupCount=30, encoding="utf-8", utc=True
    )
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    log.setLevel(getattr(logging, os.environ.get("LOG_LEVEL", "INFO").upper(), logging.INFO))
    log.addHandler(handler)


def main() -> None:
    global codec
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    configure_logging()
    codec = SessionCodec(_require_secret("SESSION_SECRET", SESSION_SECRET))
    server = ServiceHTTPServer((BIND_HOST, BIND_PORT), Handler)
    log.info(
        "starting host=%s port=%s read_only=%s root_unit=%s",
        BIND_HOST,
        BIND_PORT,
        READ_ONLY,
        NETEASE_ROOT_UNIT_ID,
    )
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
