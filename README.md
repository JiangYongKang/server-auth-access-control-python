# 会话认证与访问控制服务（自包含实现）

一套不依赖外部 JWT/鉴权中间件、仅基于 FastAPI + Python 标准库实现的会话认证与访问控制流程。
重点保证**令牌生命周期、权限判定与失败处理在并发和重启场景下结果确定、可复现**。

## 1. 快速开始

```bash
# 依赖（Python 3.14）
uv sync            # 或 pip install fastapi[standard] pytest

# 启动（首次启动自动种入三个演示账号）
fastapi dev main.py
# uvicorn main:app --reload

# 运行测试（打印输入与判定依据见下）
python3 -m pytest                       # 静默，仅失败时打印日志
python3 -m pytest --log-cli-level=INFO  # 实时打印每次判定的输入与依据
```

演示账号（仅用于本地，密码见 `app/auth/service.py` 的 `_SEED_USERS`）：

| 账号  | 密码           | 作用域 |
|-------|----------------|--------|
| admin | admin-password | `profile:read`, `admin:action` |
| alice | alice-password | `profile:read` |
| bob   | bob-password   | （无） |

## 2. HTTP 接口

| 方法 | 路径 | 所需作用域 | 说明 |
|------|------|------------|------|
| POST | `/auth/login` | - | 凭据校验，签发访问/刷新令牌；可选 `client_id` 设备标识 |
| POST | `/auth/refresh` | - | 刷新令牌轮换 |
| GET  | `/auth/sessions` | 有效访问令牌 | 列出本人所有存活会话 |
| POST | `/auth/logout` | 有效访问令牌 | 登出（撤销）当前会话 |
| POST | `/auth/sessions/revoke` | 有效访问令牌 | 按 `session_id` 撤销本人指定会话 |
| POST | `/auth/sessions/revoke-others` | 有效访问令牌 | 撤销本人除当前外的全部会话 |
| GET  | `/protected/profile` | `profile:read` | 受保护资源 |
| POST | `/protected/admin/action` | `admin:action` | 受保护资源 |

```bash
# 登录（client_id 可选，不携带时行为与旧版一致）
curl -s -X POST localhost:8000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice-password","client_id":"alice-laptop"}'

# 访问受保护资源
curl -s localhost:8000/protected/profile -H "Authorization: Bearer <access_token>"

# 刷新（轮换）
curl -s -X POST localhost:8000/auth/refresh \
  -H 'Content-Type: application/json' \
  -d '{"refresh_token":"<refresh_token>"}'

# 查看自己的会话（含设备标识、建立时间、最近刷新时间、是否当前会话）
curl -s localhost:8000/auth/sessions -H "Authorization: Bearer <access_token>"

# 登出当前会话
curl -s -X POST localhost:8000/auth/logout -H "Authorization: Bearer <access_token>"

# 撤销指定会话 / 撤销除当前外全部会话
curl -s -X POST localhost:8000/auth/sessions/revoke \
  -H 'Content-Type: application/json' -H "Authorization: Bearer <access_token>" \
  -d '{"session_id":"<session_id>"}'
curl -s -X POST localhost:8000/auth/sessions/revoke-others \
  -H "Authorization: Bearer <access_token>"
```

## 3. 令牌生命周期

### 3.1 访问令牌（access token）

- 格式为自实现的两段式签名令牌：`base64url(payload).base64url(HMAC-SHA256(secret, payload))`。
- 载荷含 `sub / jti / sid(会话) / fid(令牌族) / sco(作用域) / iat / exp / typ`。
- 有效期默认 15 分钟（`access_token_ttl_seconds`），**过期后必须重新用刷新令牌换取**。
- 访问令牌不存库；服务端验证签名与有效期之外，还会在存储临界区内核对
  其所属会话是否仍然存活——会话被撤销时令牌**立即失效**（见 3.4）。

### 3.2 刷新令牌（refresh token）与轮换

- 刷新令牌是 `base64url({"jti","fid","typ":"refresh"}).HMAC` 的签名信封，
  其 `jti` 在服务端有一条记录（是否已消费、过期时间、所属 family/session）。
- 一次登录创建一个**会话（session）**和一个**令牌族（family）**。
- 每次刷新执行**轮换（rotation）**：
  1. 校验信封签名 → 查到服务端记录；
  2. 旧刷新令牌立即标记 `consumed=True`；
  3. 签发新的访问令牌 + 新的刷新令牌（同一 session、同一 family）。

### 3.3 重放检测与会话整体失效

- 已消费的刷新令牌再次出现 = **重放（replay）**，判定为令牌被盗：
  - 该旧令牌得到原因 `refresh_token_consumed`；
  - 其所属 **session/family 立即整体吊销**；
  - 族内其他（尚未消费的）新令牌再使用时得到原因 `refresh_family_revoked`。
  - 两种原因**互不相同、可区分**。

### 3.4 会话管理（查看 / 登出 / 撤销）

- **设备标识**：登录可携带可选的 `client_id`（客户端自报的设备/客户端标识），
  随会话保存；不携带时行为与旧版完全一致，老客户端无需修改。
- **会话列表**：`GET /auth/sessions` 只返回**本人**所有存活会话，每条含
  `session_id / client_id / created_at / last_refresh_at / is_current`。
  列表不包含任何他人会话，也没有任何接口可探测他人会话是否存在。
- **三种主动撤销**：
  1. `POST /auth/logout` —— 撤销当前请求所在的会话；
  2. `POST /auth/sessions/revoke` —— 按 `session_id` 撤销自己的一条会话；
     目标不属于自己或不存在时**不做任何变更**，响应与成功一致，不泄露目标是否存在；
  3. `POST /auth/sessions/revoke-others` —— 撤销自己除当前会话外的全部会话。
- **撤销即时生效**：会话被撤销后，其已签发的访问令牌**立即失效**
  （`authenticate` 在校验签名/有效期之外，还在存储临界区内检查会话状态，
  判定为 `session_revoked`，不再等待访问令牌自然过期）；
  其刷新令牌同样立即无法再换出新令牌（`refresh_family_revoked`）。
- **幂等**：重复撤销同一会话是 no-op，对外结果一致；不会牵连其它会话；
  已撤销会话的撤销原因不被覆盖，也**不能被重新激活**。
- **并发确定性**：撤销与在途的刷新/访问通过存储临界区串行化——
  撤销一旦生效，之后该会话的访问与刷新一律被拒；
  不会出现“撤销与刷新同时成功且新令牌仍可用”的情况
  （刷新先完成时，新签发的令牌对随撤销立即一并失效）。

### 3.5 会话数量上限与清理

- **上限**：`AuthConfig.max_active_sessions_per_user`（默认 8）限制同一用户同时存活的会话数。
  登录导致超限时，按**创建时间从旧到新**撤销最旧的存活会话（确定性规则），
  登录响应通过 `evicted_sessions` 字段明确告知调用方哪些会话被驱逐；
  被驱逐会话的访问/刷新令牌立即失效（`session_revoked` / `refresh_family_revoked`）。
  已撤销/已过期的会话不占名额。
- **清理**：`AuthService.cleanup(now)` 移除已撤销或已过期的会话、以及已过期的刷新令牌记录，
  防止状态无限堆积；**存活（未撤销且未过期）的会话与其令牌记录绝不受影响**；
  未过期的已消费记录保留，重放检测在清理后仍然有效。
  被清理的会话之后仍被确定性地拒绝（不会复活）。
- **重启一致**：会话状态、撤销标记、上限计数与限流状态全部持久化在
  `data/auth_store.json`，清理或进程重启后上述判定结果保持一致。

### 3.6 失败原因（错误码）一览

| 场景 | error code | HTTP 状态 |
|------|-----------|-----------|
| 用户名/密码错误 | `invalid_credentials` | 401 |
| 账号被停用 | `account_locked` | 401 |
| 登录尝试过多（锁定中） | `rate_limited_login` | 429 |
| 刷新令牌无法识别/伪造 | `refresh_token_invalid` | 401 |
| 刷新令牌过期 | `refresh_token_expired` | 401 |
| 刷新令牌已被消费（重放） | `refresh_token_consumed` | 401 |
| 令牌族已被吊销 | `refresh_family_revoked` | 401 |
| 刷新尝试过多 | `rate_limited_refresh` | 429 |
| 同一族并发刷新冲突 | `refresh_concurrent` | 429 |
| 访问令牌缺失 | `access_token_missing` | **404** |
| 访问令牌结构损坏 | `access_token_malformed` | **404** |
| 三段式 JWT/外形不符（伪造） | `access_token_forgery` | **404** |
| 签名不匹配（篡改） | `access_token_signature_invalid` | **404** |
| 访问令牌过期 | `access_token_expired` | **404** |
| 缺少所需作用域 | `access_scope_insufficient` | **404** |
| 越权尝试过多 | `rate_limited_access` | **404** |
| 会话已撤销/不存在（登出、按会话撤销、超额驱逐） | `session_revoked` | **404**（受保护资源）/ 401（/auth/**） |

> 失败原因全集定义见 `app/auth/errors.py`。

## 4. 权限模型：基于作用域，默认拒绝

- 每个用户拥有一组 scope；访问令牌在签发时快照该 scope 列表。
- 每个受保护接口通过 `Depends(require_scope("<scope>")))` 声明**显式所需作用域**。
- 判定规则：`required_scope in token.scopes` 才放行，否则拒绝；
  令牌缺失、伪造、签名无效、过期等一律拒绝——**默认拒绝（default deny）**。
- **不泄露资源存在性**：对 `/protected/**` 的任何认证/授权失败都返回 **404 Not Found**，
  与“路径真的不存在”外形完全一致，未授权方无法据此探测资源；
  响应体仍带有可区分的 `error` 字段，供已授权的客户端程序化排错。

## 5. 频次限制与失败累积

- 三类操作分别按主体计数（状态保存在服务端，随每次变更落盘）：
  - 登录：键 `login:<username>`；
  - 刷新：键 `refresh:<username>`；
  - 越权/非法访问：键 `access:<subject>`（无法识别主体时为 `access:unknown`）。
- 固定窗口（默认 15 分钟，`failure_window_seconds`）内失败累计达到阈值即**锁定**：
  - 登录 `login_max_failures=5`，锁 `login_lock_seconds=900`s；
  - 刷新 `refresh_max_failures=5`，锁 900s；
  - 越权访问 `access_max_failures=10`，锁 300s。
  （测试中阈值/时长通过 `AuthConfig` 调小，保证快速、确定。）
- **限制生效期间请求被明确拒绝（429 / 404+限流码），绝不静默放行。**
- 计数与锁定持久化在 JSON 存储中，**进程重启后依然成立**；窗口外计数自动重置。

## 6. 并发正确性

刷新轮换必须保证“同一份刷新令牌的并发使用不会同时成功”：

1. **进程内**：每个 family 一把非阻塞互斥锁，并发刷新只有一个进入临界区，
   其余立即得到 `refresh_concurrent`（不被误判为重放、不误伤合法会话）。
2. **跨进程**：以 db 目录下的 family 锁文件做 `flock(LOCK_EX|LOCK_NB)`，
   多进程/重启后并发刷新仍然只有一个成功（见 `tests/test_multiprocess.py`）。
3. 状态“判定 + 变更 + 落盘”在存储临界区内原子完成；
   越权失败计数在并发下不丢失（见 `tests/test_concurrency.py`）。
4. **撤销 vs 在途请求**：会话撤销与刷新/访问判定在同一存储临界区内串行化，
   撤销生效后该会话的访问与刷新一律被拒，结果与线程/进程调度顺序无关
   （见 `tests/test_sessions.py` 的并发确定性用例，重复多轮结果一致）。

## 7. 持久化与可复现性

- 所有用户、会话、刷新令牌、限流状态保存在 `data/auth_store.json`，
  采用临时文件 + fsync + `os.replace` 原子替换，避免半写损坏。
- 业务失败（错误密码、重放吊销、锁定计数）同样落盘——异常退出不影响状态持久化。
- 服务方法的当前时间通过参数 `now` 显式注入，测试使用固定基准时间 `T0`，
  因此相同输入在任意机器、任意次数运行都得到相同判定序列
  （见 `tests/test_determinism.py`）。

## 8. 代码结构

```
app/auth/
  errors.py          # 错误码枚举 + 异常类型（失败原因可区分的单一事实源）
  models.py          # User/Session/RefreshTokenRecord/Config/Database 等数据模型
  security.py        # PBKDF2 密码哈希、HMAC 访问令牌签发/校验、刷新令牌信封
  store.py           # JSON 原子持久化 + 进程内锁
  rate_limit.py      # 窗口失败累积 + 锁定
  service.py         # 核心：登录 / 刷新轮换重放 / 访问判定 / 并发互斥
  dependencies.py    # FastAPI 装配与 require_scope 依赖
  config_loader.py   # 从 JSON 配置装配服务（跨进程/重启测试用）
main.py              # HTTP 路由 + 统一失败处理（受保护资源失败一律 404）
tests/               # 轮换/重放、越权、并发、跨进程、重启、确定性、HTTP 端到端
```

## 9. 本地验证清单

```bash
python3 -m pytest --log-cli-level=INFO   # 全部 59 个用例并观察输入/判定日志
```

重点对应需求：

- 令牌轮换与重放：`tests/test_token_rotation.py`
- 作用域默认拒绝与可区分失败原因：`tests/test_access_control.py`
- 会话管理（列表可见性、三种撤销、即时失效、幂等、并发确定性、上限、清理）：`tests/test_sessions.py`
- 线程并发（刷新互斥、越权计数不丢失）：`tests/test_concurrency.py`
- 跨进程并发：`tests/test_multiprocess.py`
- 重启后吊销/锁定保持：`tests/test_persistence.py`
- 重复运行判定稳定：`tests/test_determinism.py`
- HTTP 状态码 / 404 资源隐藏 / 429 限流 / 会话端点：`tests/test_http_api.py`
