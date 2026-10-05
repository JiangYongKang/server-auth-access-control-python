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
| POST | `/auth/login` | - | 凭据校验，签发访问/刷新令牌；可附 `device_id` 标识设备 |
| POST | `/auth/refresh` | - | 刷新令牌轮换 |
| GET  | `/auth/sessions` | 合法访问令牌 | 列出本人所有活跃会话 |
| POST | `/auth/logout` | 合法访问令牌 | 登出当前会话 |
| DELETE | `/auth/sessions/{session_id}` | 合法访问令牌 | 撤销本人指定会话 |
| POST | `/auth/sessions/revoke-others` | 合法访问令牌 | 撤销本人除当前外的全部会话 |
| GET  | `/protected/profile` | `profile:read` | 受保护资源 |
| POST | `/protected/admin/action` | `admin:action` | 受保护资源 |

```bash
# 登录（device_id 可选；不带也能正常登录，兼容老客户端）
curl -s -X POST localhost:8000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice-password","device_id":"my-phone"}'

# 访问受保护资源
curl -s localhost:8000/protected/profile -H "Authorization: Bearer <access_token>"

# 刷新（轮换）
curl -s -X POST localhost:8000/auth/refresh \
  -H 'Content-Type: application/json' \
  -d '{"refresh_token":"<refresh_token>"}'

# 查看自己名下的活跃会话（含 device_id / 建立时间 / 最近刷新时间 / 是否当前会话）
curl -s localhost:8000/auth/sessions -H "Authorization: Bearer <access_token>"

# 登出当前会话
curl -s -X POST localhost:8000/auth/logout -H "Authorization: Bearer <access_token>"

# 撤销指定会话（仅限本人；他人或不存在的 id 一律 404 session_not_found）
curl -s -X DELETE localhost:8000/auth/sessions/<session_id> \
  -H "Authorization: Bearer <access_token>"

# 撤销除当前会话外的全部会话
curl -s -X POST localhost:8000/auth/sessions/revoke-others \
  -H "Authorization: Bearer <access_token>"
```

## 3. 令牌生命周期

### 3.1 访问令牌（access token）

- 格式为自实现的两段式签名令牌：`base64url(payload).base64url(HMAC-SHA256(secret, payload))`。
- 载荷含 `sub / jti / sid(会话) / fid(令牌族) / sco(作用域) / iat / exp / typ`。
- 有效期默认 15 分钟（`access_token_ttl_seconds`），**过期后必须重新用刷新令牌换取**。
- 访问令牌不存库、无状态；服务端只验证签名与有效期。

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

### 3.4 会话管理：查看 / 登出 / 撤销

- 登录时可附 `device_id`（客户端自报的设备/客户端标识，可选）；
  不带 `device_id` 的老客户端登录行为完全不变。
- `GET /auth/sessions` 只返回**本人**名下仍活跃的会话，每条含
  `session_id / device_id / created_at / last_refresh_at / is_current`；
  他人的会话既不出现在列表里，也无法通过任何接口探测其是否存在。
- 三种主动撤销路径：
  1. `POST /auth/logout` —— 登出当前会话；
  2. `DELETE /auth/sessions/{session_id}` —— 按 id 撤销本人指定会话；
     撤销他人或不存在的 id 一律返回 `404 session_not_found`，两种情形对外完全一致；
  3. `POST /auth/sessions/revoke-others` —— 撤销本人除当前会话外的全部会话。
- **撤销即时生效**：会话一旦被撤销，其已签发的访问令牌**立即失效**
  （访问判定会核对服务端会话状态，不等访问令牌自然到期，
  失败原因 `access_session_revoked`）；其刷新令牌也不能再换发新令牌
  （失败原因 `refresh_session_revoked`，与重放导致的 `refresh_family_revoked` 可区分）。
- **幂等**：对同一会话重复撤销结果一致——仍处撤销态、保留首次撤销原因、
  不会牵连其它会话、也不会被重新激活。
- **并发确定性**：撤销与在途刷新通过同一把 family 互斥锁串行化
  （撤销阻塞等待在途刷新结束；刷新持锁期间撞进来的请求得到 `refresh_concurrent`）。
  撤销一旦生效，之后该会话的访问与刷新一律被拒；
  不会出现撤销与刷新同时成功、或撤销后又刷出新令牌对的情况。

### 3.5 会话上限与清理

- 同一用户的活跃会话数上限由 `max_active_sessions_per_user` 配置（默认 10）。
  登录后若超出上限，**按建立时间从最旧开始逐出**：被逐出会话立即吊销
  （`revoke_reason=evicted_by_session_limit`），其访问/刷新令牌随即失效，
  调用方在会话列表（该会话消失）与令牌失败原因（`*_session_revoked`）中均可观察到。
- 清理（`AuthService.cleanup()`，登录时也会机会性执行）只删除：
  已撤销或已过期的会话、已过期的刷新令牌记录、所属会话已不存在的令牌记录、
  以及窗口已结束且未锁定的限流状态。
  **仍在有效期内的会话与令牌一律保留**——包括已消费但未过期的刷新令牌记录
  （它们是重放检测的证据，删除会把重放误判成“无法识别”）。
- 会话撤销状态、上限逐出结果与清理结果全部落盘，**进程重启后依然成立**。

### 3.6 失败原因（错误码）一览

| 场景 | error code | HTTP 状态 |
|------|-----------|-----------|
| 用户名/密码错误 | `invalid_credentials` | 401 |
| 账号被停用 | `account_locked` | 401 |
| 登录尝试过多（锁定中） | `rate_limited_login` | 429 |
| 刷新令牌无法识别/伪造 | `refresh_token_invalid` | 401 |
| 刷新令牌过期 | `refresh_token_expired` | 401 |
| 刷新令牌已被消费（重放） | `refresh_token_consumed` | 401 |
| 令牌族已被吊销（重放） | `refresh_family_revoked` | 401 |
| 会话已被撤销（登出/撤销/逐出） | `refresh_session_revoked` | 401 |
| 刷新尝试过多 | `rate_limited_refresh` | 429 |
| 同一族并发刷新冲突 | `refresh_concurrent` | 429 |
| 访问令牌缺失 | `access_token_missing` | **404** |
| 访问令牌结构损坏 | `access_token_malformed` | **404** |
| 三段式 JWT/外形不符（伪造） | `access_token_forgery` | **404** |
| 签名不匹配（篡改） | `access_token_signature_invalid` | **404** |
| 访问令牌过期 | `access_token_expired` | **404** |
| 缺少所需作用域 | `access_scope_insufficient` | **404** |
| 会话已撤销（访问令牌即时失效） | `access_session_revoked` | **404**（/protected）/ 401（/auth/sessions 等） |
| 越权尝试过多 | `rate_limited_access` | **404** |
| 撤销他人/不存在的会话 | `session_not_found` | **404** |

> 失败原因全集定义见 `app/auth/errors.py`。

## 4. 权限模型：基于作用域，默认拒绝

- 每个用户拥有一组 scope；访问令牌在签发时快照该 scope 列表。
- 每个受保护接口通过 `Depends(require_scope("<scope>")))` 声明**显式所需作用域**。
- 判定规则：`required_scope in token.scopes` 才放行，否则拒绝；
  令牌缺失、伪造、签名无效、过期等一律拒绝——**默认拒绝（default deny）**。
- **会话状态也是访问判定的一部分**：除签名与有效期外，访问判定还会核对
  令牌所属会话在服务端的状态；会话被撤销（登出/按 id 撤销/上限逐出/重放吊销）
  后，其访问令牌立即以 `access_session_revoked` 拒绝，与作用域判定、
  限流计数完全兼容（撤销类失败同样计入 `access:<subject>` 失败窗口）。
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
4. **撤销与刷新/访问的竞争**：撤销操作阻塞式获取同一把 family 锁，
   与在途刷新串行化——要么刷新先完成、撤销随后生效，要么撤销先生效、
   刷新随后被拒；两种交错下最终状态一致（会话撤销、后续访问/刷新全拒），
   重复运行结果稳定（见 `tests/test_sessions.py` 的 race 用例）。

## 7. 持久化与可复现性

- 所有用户、会话（含设备标识/撤销状态/过期时间）、刷新令牌、限流状态
  保存在 `data/auth_store.json`，
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
  service.py         # 核心：登录 / 刷新轮换重放 / 访问判定 / 会话管理 / 并发互斥
  dependencies.py    # FastAPI 装配与 require_scope 依赖
  config_loader.py   # 从 JSON 配置装配服务（跨进程/重启测试用）
main.py              # HTTP 路由 + 统一失败处理（受保护资源失败一律 404）
tests/               # 轮换/重放、越权、并发、跨进程、重启、确定性、HTTP 端到端
```

## 9. 本地验证清单

```bash
python3 -m pytest --log-cli-level=INFO   # 全部 55 个用例并观察输入/判定日志
```

重点对应需求：

- 会话管理（列表只含本人、三种撤销、即时失效、幂等、并发确定性、上限/清理/重启）：`tests/test_sessions.py`
- 令牌轮换与重放：`tests/test_token_rotation.py`
- 作用域默认拒绝与可区分失败原因：`tests/test_access_control.py`
- 线程并发（刷新互斥、越权计数不丢失）：`tests/test_concurrency.py`
- 跨进程并发：`tests/test_multiprocess.py`
- 重启后吊销/锁定保持：`tests/test_persistence.py`
- 重复运行判定稳定：`tests/test_determinism.py`
- HTTP 状态码 / 404 资源隐藏 / 429 限流：`tests/test_http_api.py`
