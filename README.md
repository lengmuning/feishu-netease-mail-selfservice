# Feishu × NetEase Enterprise Mail Self-Service

**[English](#english)** | **[中文](#中文)**

---

<a name="english"></a>
## English

A small, dependency-free Python service that lets employees provision their
own NetEase Enterprise Mail (网易企业邮箱) mailbox and reset its password,
authenticated by Feishu (飞书 / Lark). It is built for the case the official
Feishu ↔ NetEase directory sync does not cover: **several Feishu tenants
sharing one NetEase mail administration console**, each pinned to its own
organization unit.

One instance serves one Feishu tenant and one NetEase organization unit.
Run more instances for more tenants; they can share the same NetEase
open-platform application while each uses its own Feishu application.

Python 3.9+ standard library only. No database, no framework.

### How it decides

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

### Provisioning

For an `eligible` employee the write endpoint repeats the Feishu and NetEase
checks inside a per-employee lock. The account name is the local part of the
Feishu work email, which must sit in `NETEASE_DOMAIN`. The Feishu department
path is cut at `FEISHU_DEPARTMENT_ANCHOR` and matched parent-by-parent below
the root unit; with `CREATE_MISSING_UNITS=1` missing child units are created
there, otherwise the operation stops and names the missing unit. Duplicate
sibling names always stop it.

NetEase receives the employee number, mobile, Feishu display name, target unit
and a server-generated password. `NETEASE_PASS_CHANGE_FIRST_LOGIN=2` forces a
web password change and blocks clients until it is changed. After NetEase
accepts the write, the service delivers the password before the post-write
query. A slow or failed read-back can therefore never suppress a live
credential; the page disables both write actions and asks the employee to
refresh later instead of repeating the operation.

Before any NetEase write the Feishu bot sends a preflight message; if it
cannot deliver, the write is refused. On success the bot privately sends the
mailbox address, initial password and web login URL. Passwords are never
returned to the browser or written to logs.

The desktop UI uses a compact four-column identity card and content-sized
comparison cards so the identity, verdict and actions fit into a typical
Feishu desktop window. It falls back to a single-column layout on mobile.

### Security and operations

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

### Endpoints

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

### Feishu application

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

### NetEase application

The NetEase open-platform app needs these interfaces registered:
`getUnitList`, `getAccountList`, `getAccount`, `getAccountAliasList`,
`getMobile`, `getAccountListByNicknameAndJobNo`, and for writes
`createAccount`, `updatePassword` and (only with `CREATE_MISSING_UNITS=1`)
`createUnit`.

### Deployment

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

### Verification

The suite currently contains 20 tests, including regression cases for both
provisioning and password reset when notification delivery or the NetEase
read-back fails.

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests -v
node --check static/app.js
python3 -m py_compile app.py
```

---

<a name="中文"></a>
## 中文

一个无第三方依赖的小型 Python 服务：员工通过飞书身份登录，自助开通本人的网易企业邮箱、重置本人的邮箱密码。它面向的是官方「飞书 ↔ 网易通讯录同步」覆盖不到的场景——**多个飞书租户共用同一个网易企业邮箱管理后台**，每个租户钉死在网易里各自的组织单元下。

一个实例只服务一个飞书租户、只对应网易里的一个组织单元。多个租户就跑多个实例：共用同一个网易开放平台应用，各用各的飞书应用。

仅使用 Python 3.9+ 标准库，无数据库、无框架。

### 判定规则

签名会话中的飞书用户是唯一可能的操作对象。浏览器不能提交工号、账号名、邮箱、手机号、部门或密码，请求体里出现任何这类字段都会被拒绝。

1. 从飞书读取当前员工的工号、工作邮箱、手机号和部门路径。
2. 先按工号查网易，再把工作邮箱与主地址及所有别名比对，把规范化后的手机号比对，并要求账号位于钉死的根部门之下。
3. 唯一且完全匹配 → `matched`：可以改密，禁止重复开通。
4. 工号、邮箱、手机号都没有命中 → `eligible`：可以开通。
5. 部分命中、重复命中或不在根部门下 → `conflict`：什么都不能做。
6. 飞书名片缺少三项身份信息中的任意一项 → `blocked`。

每个响应都携带一个 `actions` 对象，页面直接按它渲染按钮，浏览器从不自行推断权限。

### 开通流程

对 `eligible` 的员工，写接口会在按工号加的锁内重新执行飞书和网易两侧的校验。账号名取飞书工作邮箱 `@` 前面的部分，域名必须等于 `NETEASE_DOMAIN`。飞书部门路径在 `FEISHU_DEPARTMENT_ANCHOR` 处截断，只保留其后的部分，然后从网易根部门开始逐级按「父部门 + 名称」匹配；`CREATE_MISSING_UNITS=1` 时缺失的子部门会被创建，否则操作停止并报出缺少的部门名。同级重名一律停止。

写入网易的字段有工号、手机号、飞书姓名、目标部门和服务端生成的随机密码。`NETEASE_PASS_CHANGE_FIRST_LOGIN=2` 强制首次 Web 登录改密，改密前客户端不能登录。网易确认写操作成功后，系统先把密码发送给员工，再查询网易确认最终状态。因此，复查超时或失败不会阻断有效密码的发送；页面会禁用两个写操作并提示稍后刷新核对，避免员工重复操作。

任何网易写操作之前，飞书机器人先发一条预检消息，发不出去就拒绝写入。成功后机器人私聊发送邮箱地址、初始密码和 Web 登录地址。密码不回传浏览器、不写入日志。

桌面端采用紧凑的四列身份信息区和按内容收缩的核对卡片，使身份、结论和操作按钮能在常见飞书桌面窗口中完整显示；手机端自动切换为单列布局。

### 安全与运维

- `READ_ONLY=1` 是出厂默认值，也是所有写操作的总开关。
- 每个 POST 都需要签名会话 cookie 和 CSRF token。
- 改密要求飞书授权时间在 `FRESH_AUTH_TTL` 秒以内。
- 每次写操作前都会重新读取飞书通讯录里的员工状态。
- 写操作按人限流（每人每 10 分钟 5 次）并按工号串行；部门创建另有全局锁。
- 访问日志中会剥掉 OAuth 的查询参数。
- 运行日志和审计日志（`audit.jsonl`）位于 `LOG_DIR`。
- systemd 单元以非特权账号运行，除数据和日志目录外文件系统只读。

### 接口

| 路由 | 用途 |
| --- | --- |
| `GET /healthz` | 存活探测与配置摘要 |
| `GET /auth/feishu/start` | 发起飞书 OAuth |
| `GET /auth/feishu/callback` | OAuth 回调，签发会话 cookie |
| `GET /logout` | 清除会话 |
| `GET /api/me` | 页面所需的飞书身份 |
| `GET /api/status` | 带缓存的核对结论 |
| `POST /api/refresh` | 绕过缓存的核对结论 |
| `POST /api/action/provision` | 开通邮箱 |
| `POST /api/action/password` | 重置密码 |

所有 `POST` 都需要 `X-CSRF-Token` 头和一个空 JSON 对象作为请求体。

### 飞书应用

为每个实例单独建一个自建应用：

- 同时启用**网页应用**和**机器人**能力。
- 在重定向 URL 白名单中加入 `${PUBLIC_BASE_URL}/auth/feishu/callback`。
- 授予通讯录权限：用户基本信息、工号、邮箱、手机号、部门；再加以应用身份发消息的权限。
- 可用范围覆盖所有将使用该服务的员工。
- **发布版本。** 权限变更在发版前不会生效。

缺少权限时不会报错，对应字段只是返回为空。所以：缺工号权限表现为登录被拒，缺邮箱或手机号权限表现为 `blocked`，缺部门权限表现为组织路径无法读取。

登录、读通讯录、机器人发消息全部使用同一个应用，所有 `open_id` 保持在同一应用作用域内。不要尝试借用其他应用的机器人：`open_id` 是按应用隔离的。

### 网易应用

网易开放平台应用需要注册这些接口：`getUnitList`、`getAccountList`、`getAccount`、`getAccountAliasList`、`getMobile`、`getAccountListByNicknameAndJobNo`；写操作需要 `createAccount`、`updatePassword`，以及（仅当 `CREATE_MISSING_UNITS=1`）`createUnit`。

### 部署

```bash
sudo useradd --system --home /opt/netease-mail-self-service --shell /usr/sbin/nologin netease-mail
sudo mkdir -p /opt/netease-mail-self-service/{data,logs}
sudo cp -r app.py static /opt/netease-mail-self-service/
sudo cp config.env.example /opt/netease-mail-self-service/config.env   # 然后编辑
sudo chown -R netease-mail:netease-mail /opt/netease-mail-self-service
sudo cp systemd/netease-mail-self-service.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now netease-mail-self-service
curl -s http://127.0.0.1:8500/healthz
```

前面放一个做 TLS 终结的反向代理，`PUBLIC_BASE_URL` 填它的公网地址。设置 `TRUST_PROXY=1`，日志里的客户端 IP 才会取自 `X-Forwarded-For`。

上线顺序：保持 `READ_ONLY=1`，依次验证 OAuth、身份卡片、部门路径（必须包含 `FEISHU_DEPARTMENT_ANCHOR`）、机器人投递和网易核对结论；然后把 `READ_ONLY` 改为 `0`，先用测试账号开通一次，再向员工开放。

### 验证

当前测试套件共 20 项，覆盖邮箱开通和密码重置，也覆盖飞书通知失败、网易写后复查失败等回归场景。

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests -v
node --check static/app.js
python3 -m py_compile app.py
```
