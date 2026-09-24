# 会话认证与访问控制服务

基于 FastAPI 的自包含认证服务：凭据校验、访问/刷新令牌签发与轮换、基于作用域的
访问控制（默认拒绝）、频次限制与失败累积。所有状态持久化到 JSON 文件，进程重启后
依然成立。

## 架构

| 模块 | 职责 |
| --- | --- |
| `app/errors.py` | 可区分的失败原因枚举与 `AuthError` |
| `app/tokens.py` | HMAC-SHA256 签名令牌（JWT 风格）签发/校验、不透明刷新令牌 |
| `app/store.py` | 线程安全、原子落盘的 JSON 存储（用户/会话/事件计数） |
| `app/ratelimit.py` | 滑动窗口频次限制 + 失败累积锁定 |
| `app/auth.py` | 认证服务：登录、刷新轮换、重放检测、作用域判定 |
| `app/main.py` | HTTP 层：`create_app()` 工厂与路由 |

## 令牌生命周期

1. **登录** `POST /login`：校验凭据（PBKDF2 散列比对），签发访问令牌
   （HMAC 签名，含 `sub/sid/scopes/exp`，默认 15 分钟）与刷新令牌
   （不透明随机串，落盘仅存 SHA-256 散列，默认 7 天）。
2. **刷新轮换** `POST /refresh`：旧刷新令牌立即进入会话的"已消费历史"并失效，
   同一会话（`sid` 不变）签发新令牌对。
3. **重放检测**：再次使用已消费的刷新令牌 → 返回 `refresh_token_reused`，
   且**整个会话被吊销**（该会话的访问令牌、当前刷新令牌全部失效）。
4. **会话吊销**：`authenticate` 每次都会检查会话状态，被吊销会话的令牌一律
   返回 `session_revoked`。

## 权限模型

- 基于作用域（scope），**默认拒绝**：`authorize` 要求所需作用域是令牌作用域的子集。
- 权限判定先于资源查找：未授权请求对"资源存在/不存在"得到完全一致的响应，
  不泄露受保护资源是否存在。
- 失败原因互相区分（HTTP 状态码 + `error` 字段）：

| 原因 | 状态码 | 含义 |
| --- | --- | --- |
| `invalid_credentials` | 401 | 用户名或密码错误 |
| `token_missing` | 401 | 未提供 Bearer 令牌 |
| `token_invalid` | 401 | 伪造 / 签名无效 / 格式错误 |
| `token_expired` | 401 | 令牌已过期 |
| `token_type_mismatch` | 401 | 令牌类型不符 |
| `refresh_token_unknown` | 401 | 刷新令牌不存在 |
| `refresh_token_reused` | 401 | 重放已消费的刷新令牌（会话被吊销） |
| `session_revoked` | 401 | 会话已失效 |
| `insufficient_scope` | 403 | 缺少所需作用域 |
| `rate_limited` | 429 | 频次超限或处于锁定期 |

## 频次限制规则

- 滑动窗口计数（默认 60 秒窗口、5 次尝试、锁定 300 秒，可在 `create_app` 调整）。
- 登录/刷新失败按主体累积，达到阈值后进入锁定期；锁定期内的请求被**明确拒绝**
  （`rate_limited`），而非静默放行；成功后失败计数清零。
- 刷新临界区串行化：同一主体的并发刷新只有一个能成功，其余按
  `refresh_token_reused` / `session_revoked` 拒绝。
- 计数与锁定标记写入状态文件，**进程重启后依然生效**。

## 本地验证

```bash
uv sync                 # 安装依赖
uv run pytest           # 运行全部测试（日志打印输入与判定依据）
uv run uvicorn main:app --reload   # 启动服务
```

接口示例：

```bash
curl -X POST localhost:8000/register -H 'content-type: application/json' \
  -d '{"sub":"alice","password":"pw","scopes":["read"]}'
curl -X POST localhost:8000/login -H 'content-type: application/json' \
  -d '{"sub":"alice","password":"pw"}'
curl localhost:8000/resources/doc-1 -H "Authorization: Bearer <access_token>"
curl -X POST localhost:8000/refresh -H 'content-type: application/json' \
  -d '{"refresh_token":"<refresh_token>"}'
```

## 测试覆盖

- `tests/test_tokens.py`：令牌往返、过期/伪造/签名无效原因区分。
- `tests/test_auth_service.py`：轮换、重放吊销会话、越权默认拒绝、并发刷新
  仅一个成功、锁定与重放在进程重启后仍成立。
- `tests/test_http.py`：HTTP 状态码与原因映射、未授权不泄露资源存在性。
