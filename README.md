# NetEase Enterprise Mail Self-Service via Feishu

A small, dependency-free Python service that lets employees provision their
own NetEase Enterprise Mail (网易企业邮箱) mailbox and reset its password,
authenticated by Feishu (飞书). It is built for the case the official
Feishu ↔ NetEase directory sync does not cover: **several Feishu tenants
sharing one NetEase mail administration console**, each pinned to its own
organization unit.

One instance serves one Feishu tenant and one NetEase organization unit.
Run more instances for more tenants; they can share the same NetEase
open-platform application while each uses its own Feishu application.

Python 3.9+ standard library only. No database, no framework.

## How it decides

The signed Feishu user is the only possible target. The browser cannot submit
an employee number, account, email, phone, unit or password; any request body
naming one is rejected.

1. Read the current employee's employee number, work email, mobile and
   department path from Feishu.
2. Query NetEase by employee number, then compare the work email against the
   primary address and every alias, compare the normalized mobile, and require
   the account to sit below the pinned root unit.
3. Exact unique match → `matched`: password reset is offered, provisioning is
   refused.
4. No employee-number, email or mobile hit → `eligible`: provisioning is
   offered.
5. Partial, duplicate or out-of-root hit → `conflict`: nothing is offered.
6. Feishu card missing any of the three identity values → `blocked`.

Every response carries an `actions` object the page renders directly, so the
browser never re-derives what is permitted.

## Provisioning

For an `eligible` employee the write endpoint repeats the Feishu and NetEase
checks inside a per-employee lock. The account name is the local part of the
Feishu work email, which must sit in `NETEASE_DOMAIN`. The Feishu department
path is cut at `FEISHU_DEPARTMENT_ANCHOR` and matched parent-by-parent below
the root unit; with `CREATE_MISSING_UNITS=1` missing child units are created
there, otherwise the operation stops and names the missing unit. Duplicate
sibling names always stop it.

NetEase receives the employee number, mobile, display name, target unit and a
server-generated password. `NETEASE_PASS_CHANGE_FIRST_LOGIN=2` forces a web
password change and blocks clients until it is changed. A post-write query
confirms the final state; anything short of `matched` is surfaced as a warning
rather than an abort, because the password still has to reach the employee.

Before any NetEase write the Feishu bot sends a preflight message; if it
cannot deliver, the write is refused. On success the bot privately sends the
mailbox address, initial password and web login URL. Passwords are never
returned to the browser or written to logs.

## Security and operations

- `READ_ONLY=1` is the shipped default and the master write kill switch.
- Every POST needs the signed session cookie and the CSRF token.
- Password reset requires a Feishu authentication newer than `FRESH_AUTH_TTL`.
- Employee status is re-read from Feishu immediately before every write.
- Writes are rate limited (5 per 10 minutes per user) and serialized per
  employee; unit creation has a separate global lock.
- OAuth query parameters are stripped from access logs.
- Runtime and audit logs (`audit.jsonl`) live under `LOG_DIR`.
- The systemd unit runs as an unprivileged account with a read-only filesystem
  except for its data and log directories.

## Endpoints

| Route | Purpose |
| --- | --- |
| `GET /healthz` | Liveness and configuration summary |
| `GET /auth/feishu/start` | Begin Feishu OAuth |
| `GET /auth/feishu/callback` | OAuth callback, issues the session cookie |
| `GET /logout` | Clear the session |
| `GET /api/me` | Feishu identity for the page |
| `GET /api/status` | Cached comparison verdict |
| `POST /api/refresh` | Verdict, bypassing the cache |
| `POST /api/action/provision` | Create the mailbox |
| `POST /api/action/password` | Reset its password |

Every `POST` requires `X-CSRF-Token` and an empty JSON object body.

## Feishu application

Create a dedicated custom app for each instance:

- Enable **web app** and **bot**.
- Whitelist `${PUBLIC_BASE_URL}/auth/feishu/callback` as the redirect URL.
- Grant contact scopes for user basics, employee id, email, mobile and
  department, plus the scope to send messages as the bot.
- Set the availability scope to cover every employee who will use it.
- **Publish a version.** Scope changes do not take effect until released.

Missing scopes do not error; the fields simply come back empty. A missing
employee-id scope therefore shows up as a login refusal, missing email or
mobile as `blocked`, and a missing department scope as an unreadable path.

The mail service uses the same app for login, directory reads and bot
delivery, so all `open_id` values stay in one application scope. Do not try to
reuse another app's bot: `open_id` is per-application.

## NetEase application

The NetEase open-platform app needs these interfaces registered:
`getUnitList`, `getAccountList`, `getAccount`, `getAccountAliasList`,
`getMobile`, `getAccountListByNicknameAndJobNo`, and for writes
`createAccount`, `updatePassword` and (only with `CREATE_MISSING_UNITS=1`)
`createUnit`.

## Deployment

```bash
sudo useradd --system --home /opt/netease-mail-self-service --shell /usr/sbin/nologin netease-mail
sudo mkdir -p /opt/netease-mail-self-service/{data,logs}
sudo cp -r app.py static /opt/netease-mail-self-service/
sudo cp config.env.example /opt/netease-mail-self-service/config.env   # then edit
sudo chown -R netease-mail:netease-mail /opt/netease-mail-self-service
sudo cp systemd/netease-mail-self-service.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now netease-mail-self-service
curl -s http://127.0.0.1:8500/healthz
```

Put a TLS-terminating reverse proxy in front and point `PUBLIC_BASE_URL` at
its public origin. Set `TRUST_PROXY=1` so client IPs in logs come from
`X-Forwarded-For`.

Rollout order: keep `READ_ONLY=1`, verify OAuth, the identity card, the
department path (it must contain `FEISHU_DEPARTMENT_ANCHOR`), bot delivery and
the NetEase verdict; then set `READ_ONLY=0` and provision one test account
before opening it up.

## Verification

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests -v
node --check static/app.js
python3 -m py_compile app.py
```
