# 会话式身份认证与访问控制（Java / Spring Boot）

一套可在本地运行的会话式（Session-based）身份认证与访问控制能力，覆盖
**凭证签发 → 校验 → 刷新（轮换）→ 撤销** 的完整链路，在并发与异常情况下保证
判定结果**一致、收敛、可区分、可解释**。

- 短期访问凭证（Access Token）+ 可轮换的长期刷新凭证（Refresh Token）
- 刷新轮换（Rotation）+ 重放检测（Reuse Detection）：旧凭证重复使用 → 整链失效
- 基于角色聚合权限（RBAC）的访问控制，**默认拒绝**未声明允许的访问
- 连续失败登录抑制（账户锁定）与主动撤销，并发下计数/状态一致
- 每一次认证与授权判定都写审计，**审计写入失败不改变最终判定结果**

---

## 1. 快速开始

环境要求：JDK 21+、Maven 3.6+。

```bash
# 运行全部测试（21 个，含并发刷新、重放、过期、撤销、权限不足等）
mvn test

# 启动服务（默认 8080 端口）
mvn spring-boot:run
```

启动时自动预置三个演示账户（密码均为 `password-123`，密码以“盐 + SHA-256”存储）：

| 用户名 | 角色  | 权限 |
|--------|-------|------|
| alice  | ADMIN | `profile:read` `admin:read` `admin:write` |
| bob    | USER  | `profile:read` |
| carol  | GUEST | （无任何权限） |

### 本地验证（curl）

```bash
# 1) 登录，拿到 accessToken / refreshToken
curl -s -X POST http://localhost:8080/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"bob","password":"password-123"}'

# 2) 携带访问凭证访问受保护资源
curl -s http://localhost:8080/api/demo/profile \
  -H "Authorization: Bearer <accessToken>"

# 3) 刷新（轮换），旧 refreshToken 立即失效
curl -s -X POST http://localhost:8080/api/auth/refresh \
  -H 'Content-Type: application/json' \
  -d '{"refreshToken":"<refreshToken>"}'

# 4) 再次使用旧 refreshToken —— 触发重放检测，HTTP 409，整链失效
# 5) 登出（主动撤销当前会话）
curl -s -X POST http://localhost:8080/api/auth/logout \
  -H "Authorization: Bearer <accessToken>" \
  -H 'Content-Type: application/json' -d '{}'

# 6) 查询审计记录（需 ADMIN）
curl -s http://localhost:8080/api/demo/audits \
  -H "Authorization: Bearer <alice 的 accessToken>"
```

### HTTP 端点

| 方法 & 路径 | 鉴权要求 | 说明 |
|---|---|---|
| `POST /api/auth/login` | 公开 | 校验账号密码，失败计数/锁定，成功签发凭证 |
| `POST /api/auth/refresh` | 公开（凭刷新凭证） | 轮换签发；重放时整链失效 |
| `POST /api/auth/logout` | 已认证（`profile:read`） | 主动撤销；撤销他人会话需 `admin:write` |
| `GET  /api/demo/profile` | `profile:read` | 演示资源 |
| `GET  /api/demo/admin`   | `admin:read` | 仅 ADMIN |
| `GET  /api/demo/audits`  | `admin:read` | 查询全部审计记录 |
| 其他 `/api/**` | — | **默认拒绝**（`403 INSUFFICIENT_PERMISSION`） |

---

## 2. 凭证模型

凭证为**随机不透明字符串**（`SecureRandom` 生成、十六进制编码），只在签发响应中
明文出现一次；内存中只保存其 **SHA-256 哈希**，不保存明文。

| 凭证 | 生命周期 | 默认 TTL | 用途 |
|---|---|---|---|
| Access Token（短期） | 登录或刷新时签发；刷新轮换后旧证立即失效 | 900s | 每次请求置于 `Authorization: Bearer ...` |
| Refresh Token（长期） | 仅用于刷新；**一次性**，刷新即轮换 | 1800s | 换取新的一组凭证 |

两者均以哈希建立**持久索引**（即使已轮换/已撤销也保留索引），这是把
“查无此凭证（未认证）”“已撤销”“已过期”“重放”区分开的关键。

TTL 与锁定参数均可在 `application.properties` 中通过 `security.*` 覆盖：

```properties
security.access-token-ttl-seconds=900
security.refresh-token-ttl-seconds=1800
security.max-login-failures=5
security.lock-duration-seconds=300
security.token-bytes=32
```

## 3. 权限模型（RBAC + 默认拒绝）

- 用户拥有若干**角色**，角色声明一组**权限字符串**；授权时取用户所有角色权限的并集，
  对“路径所需权限”做**精确匹配**。
- **默认拒绝**：
  - 任何未在策略表中登记的 `/api/**` 路径一律 `403 INSUFFICIENT_PERMISSION`；
  - 已认证但缺少所需权限同样 `403 INSUFFICIENT_PERMISSION`。
  - 任何一种拒绝都**不会被静默放行**。

### 可区分的判定原因（`DecisionReason`）

| 原因码 | 含义 | HTTP |
|---|---|---|
| `ALLOWED` | 允许 | 200 |
| `UNAUTHENTICATED` | 未携带 / 无法识别凭证（含已被轮换掉的旧访问凭证） | 401 |
| `EXPIRED` | 凭证已过期 | 401 |
| `REVOKED` | 会话或凭证已撤销（主动撤销或随整链失效） | 401 |
| `INSUFFICIENT_PERMISSION` | 权限不足 / 命中默认拒绝 | 403 |
| `BAD_CREDENTIALS` | 用户名或密码错误 | 401 |
| `ACCOUNT_LOCKED` | 连续失败登录被临时抑制 | 429 |
| `TOKEN_UNKNOWN` | 刷新凭证不存在、无法识别 | 401 |
| `REFRESH_TOKEN_REUSED` | 已轮换的旧刷新凭证被再次使用 | 409 |

校验访问凭证时按 **已撤销 → 已过期 → 是否当前凭证** 的顺序判定，保证原因唯一可区分。

## 4. 刷新轮换、重放检测与并发语义

### 4.1 会话链（Session Chain）

一次登录创建一条会话链，链上始终只有“当前那一组”访问/刷新凭证与一个单调递增的
`rotationVersion`。刷新 = 在同一条链上把当前凭证**轮换**为新凭证（会话 ID 不变）。

### 4.2 刷新轮换

1. 旧刷新凭证必须处于 `ACTIVE`；
2. 在锁内生成并落库新凭证、切换链上当前指针；
3. 旧刷新凭证标记为 `REPLACED`（索引保留），旧访问凭证标记为 `REPLACED`。

### 4.3 重放检测（Refresh Token Reuse Detection）

已 `REPLACED` 的旧刷新凭证再次出现，意味着凭证可能被盗用（合法客户端只会持有最新
凭证）。此时：

- 返回独立原因 **`REFRESH_TOKEN_REUSED`（HTTP 409）**，与 `TOKEN_UNKNOWN`、`REVOKED` 区分；
- **整条会话链立即撤销（family/chain invalidation）**：链上当前的访问凭证与刷新凭证
  同时失效；
- 撤销为**终态且幂等**，重复重放不会改变首次撤销原因。

### 4.4 并发一致性（锁模型）

- 每个刷新凭证哈希一把锁（`RefreshTokenStore` 每键锁）：**同一刷新凭证的并发刷新
  完全串行**，第一个请求完成轮换后，后到请求看到的必然是 `REPLACED`，从而被当作重放，
  **绝不会产生两条同时有效的链**。
- 每条会话链一把锁（`SessionStore` 每链锁）：链上“读-判-写”（轮换/撤销）原子完成。
- 固定加锁顺序 **凭证锁 → 链锁**，避免死锁。
- 登录失败计数按**用户名加锁**，同一用户的“读计数 → 判锁定 → 校验密码 → 写计数”
  原子完成，并发失败不丢计数、计数精确收敛到锁定阈值。
- 存储基于 `ConcurrentHashMap`，状态字段使用 `volatile`，保证撤销等状态对并发读立即可见。

> 说明（family-breach 语义）：在“同一凭证并发刷新”的极端竞争中，可能出现一个线程先
> 成功轮换、其余线程随后触发重放检测。此时严格按“重放即整链失效”处理——即便那一个
> 刚成功的凭证也随链一起撤销。最终状态唯一收敛为“无有效凭证、只有一条链”，安全优先
> 于可用性。`TokenServiceTest.concurrentRefreshProducesSingleChain` 对该收敛结果做了断言。

## 5. 失败登录抑制与主动撤销

- 连续密码错误达到 `security.max-login-failures`（默认 5）次后，账户被锁定
  `security.lock-duration-seconds`（默认 300s）；锁定窗口内**即使密码正确也返回
  `ACCOUNT_LOCKED`（HTTP 429）**。
- 登录成功会清零失败计数；锁定到期后下次该用户操作惰性恢复。
- `POST /api/auth/logout` 主动撤销会话：链、当前访问凭证、当前刷新凭证同步进入撤销态，
  撤销即时生效且幂等。

## 6. 审计（可追溯，且不影响判定）

- 每一次 `LOGIN / ISSUE / ACCESS / REFRESH / REFRESH_REPLAY / REVOKE` 都写一条审计记录，
  包含时间、动作、用户、会话、结果（SUCCESS/DENIED）、可区分原因码与判定依据明细。
- 审计同时以 `INFO` 日志输出（关键输入与判定依据），测试日志中可直接看到。
- **审计写入失败只记录错误日志，绝不向认证/授权流程抛异常**，因此不会改变、更不会
  “放行”最终判定。
- 可通过 `GET /api/demo/audits`（ADMIN）查看，或观察控制台 `AUDIT ...` 日志。

---

## 7. 代码结构

```
config/        SecurityProperties（TTL/锁定配置）、ClockConfig（可替换时钟，便于过期测试）
auth/model/    DecisionReason、Role、Account、AuthContext、AccessDecision、
               TokenIssued、AuditEvent、SessionChain、AccessTokenEntry、RefreshTokenEntry
auth/store/    AccountStore / AccessTokenStore / RefreshTokenStore /
               SessionStore / LoginFailureStore / AuditStore（内存实现 + 分键锁）
auth/security/ TokenHasher、AuditService、Authenticator、TokenService、AccessGuard
auth/web/      AuthController、SecurityInterceptor、WebConfig、ErrorResponse
demo/          DataInitializer（预置账户）、DemoController、AuditController
```

## 8. 测试

```bash
mvn test
```

| 测试类 | 覆盖场景 |
|---|---|
| `TokenServiceTest` | 签发/校验、刷新轮换、**旧凭证重放整链失效**、未知凭证、访问/刷新过期、主动撤销、**16 线程并发刷新收敛** |
| `AuthenticatorTest` | 密码错误、阈值锁定、锁定期正确密码仍拒绝、到期恢复、成功清零、**20 线程并发失败计数精确一致** |
| `AccessGuardTest` | 未认证/过期/撤销/权限不足四类原因可区分、角色权限聚合、重放后访问判定为 REVOKED |
| `AuthFlowIntegrationTest` | HTTP 全链路、默认拒绝、401/403/409/429 状态码区分、登出即时失效、审计可追溯 |

测试使用可变固定时钟驱动过期场景，并在日志中打印关键输入（如凭证前缀、所需权限）
与判定依据（reason、链版本号、撤销原因），便于人工核对。

## 9. 说明与边界

- 本实现为**单机内存存储**，面向本地运行与语义验证；生产环境应替换为带事务/持久化的
  存储（如数据库 + 行锁/乐观版本号），并将哈希算法升级为带慢因子的口令哈希（如 Argon2）。
- 演示账户与口令仅用于本地，请勿用于生产。
