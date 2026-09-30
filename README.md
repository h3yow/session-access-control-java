# 会话式身份认证与访问控制（本地可运行）

基于 Spring Boot 3.4 / Java 21 实现的一套**会话式认证与访问控制**服务，覆盖凭证
**签发 → 校验 → 刷新（轮换）→ 撤销**的完整链路，重点保证并发与异常情况下判定结果
**一致、可区分、可解释、可审计**。

---

## 1. 快速开始

```bash
# 运行全部测试（38 个，含并发刷新/复用检测/过期/撤销/权限/会话治理/HTTP 端到端）
mvn test

# 启动本地服务（默认 8080 端口）
mvn spring-boot:run
```

启动时自动初始化三个演示用户：

| 用户名 | 密码 | 角色 | 展开后的有效权限 |
|--------|------|------|------------------|
| alice | `password123` | `ROLE_USER` | `profile:read` |
| admin | `admin123` | `ROLE_ADMIN` | `profile:read`, `admin:read` |
| bob | `bob123` | `ROLE_FINANCE` | `profile:read`, `finance:read` |

> 角色本身不隐式放行任何资源，只按显式映射表展开为细粒度权限。

### 1.1 本地手动验证（curl）

```bash
# 登录，拿到 accessToken / refreshToken
curl -s -X POST http://localhost:8080/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"password123"}'

# 携带短期访问凭证访问受保护资源
curl -s http://localhost:8080/api/resources/profile \
  -H "Authorization: Bearer <accessToken>"

# 刷新：返回全新的凭证对，旧 refreshToken 立即失效
curl -s -X POST http://localhost:8080/api/auth/refresh \
  -H 'Content-Type: application/json' \
  -d '{"refreshToken":"<refreshToken>"}'

# 主动撤销：会话链与该会话所有访问凭证立即失效
curl -s -X POST http://localhost:8080/api/auth/revoke \
  -H 'Content-Type: application/json' \
  -d '{"refreshToken":"<refreshToken>"}'

# 会话治理：列出当前用户所有仍活跃的会话（响应不含任何凭证内容）
curl -s http://localhost:8080/api/sessions \
  -H "Authorization: Bearer <accessToken>"

# 撤销其中某一台设备（按会话 ID）
curl -s -X POST http://localhost:8080/api/sessions/<sessionId>/revoke \
  -H "Authorization: Bearer <accessToken>"

# 撤销"除当前这台之外"的其他全部会话
curl -s -X POST http://localhost:8080/api/sessions/revoke-others \
  -H "Authorization: Bearer <accessToken>"
```

受保护资源（均需显式权限，未标注的 `/api/**` 路径默认拒绝）：

| 路径 | 所需权限 |
|------|----------|
| `GET /api/resources/profile` | `profile:read` |
| `GET /api/resources/admin/dashboard` | `admin:read` |
| `GET /api/resources/reports/finance` | `finance:read` |
| `GET /api/sessions` | `session:manage`（仅能查看本人会话） |
| `POST /api/sessions/{id}/revoke` | `session:manage`（仅能撤销本人会话） |
| `POST /api/sessions/revoke-others` | `session:manage` |

公开端点：`POST /api/auth/login|refresh|revoke`（不经过访问拦截器）。

### 1.2 观察过期行为

将 TTL 调短后重启，或直接参考使用可控时钟的单元测试：

```properties
# src/main/resources/application.properties
auth.token.access-ttl=PT15M      # 短期访问凭证有效期（绝对过期）
auth.token.refresh-ttl=PT12H     # 长期刷新凭证有效期（会话绝对过期上限）
auth.session.idle-ttl=PT30M      # 闲置窗口：多久既无访问也无刷新就自动失效
auth.session.max-per-user=5      # 同一用户活跃会话数量上限
auth.login.max-failures=5        # 连续失败锁定阈值
auth.login.lock-duration=PT5M    # 锁定时长
```

---

## 2. 凭证模型

- **短期访问凭证（Access Token）**：256-bit URL-safe 随机不透明字符串，默认 15 分钟有效。
  服务端保存 `AccessRecord`（会话归属、过期时间、撤销标记），因此撤销可以**即时生效**，
  无需等待自然过期。
- **长期刷新凭证（Refresh Token）**：同为高熵不透明串，默认 12 小时有效，归属于一条
  **会话链（SessionChain）**。刷新时**必须轮换**：签发新 refresh 凭证，旧凭证立即失效。

### 2.1 刷新轮换与复用检测（核心安全语义）

每次刷新在**会话对象监视器内做 CAS 式比对替换**：

1. 提交的 refresh 凭证等于链上当前凭证 → 原子换发新凭证对；
2. 提交的凭证能解析到会话、但**不等于链上当前凭证**（说明是被轮换掉的旧凭证再次出现，
   典型的凭证被盗用/重放信号）→ 判定 `REFRESH_TOKEN_REUSED`，**整条会话链立即撤销**，
   该会话历史上签发的全部访问凭证级联失效；
3. 同一凭证被并发刷新时，监视器保证只有一个线程看到"凭证匹配"并成功，其余线程要么直接
   竞争失败，要么被识别为复用 —— **绝不会产生两条同时有效的链**。

### 2.2 认证结果原因（可区分，绝不静默放行）

| 场景 | AuthOutcome | HTTP |
|------|-------------|------|
| 登录成功 / 刷新成功 / 撤销成功 | `LOGIN_SUCCESS` / `REFRESH_SUCCESS` / `REVOKE_SUCCESS` | 200 |
| 用户名或密码错误 | `INVALID_CREDENTIALS` | 401 |
| 连续失败达到阈值 / 锁定期内 | `ACCOUNT_LOCKED` | 423 |
| 刷新凭证无法识别 | `REFRESH_TOKEN_UNKNOWN` | 401 |
| 刷新凭证已过期 | `REFRESH_TOKEN_EXPIRED` | 401 |
| 会话已撤销（含复用后再刷新） | `SESSION_REVOKED` | 401 |
| 旧刷新凭证被重复使用 | `REFRESH_TOKEN_REUSED` | 401 |
| 撤销未知凭证 | `REVOKE_NOT_FOUND` | 404 |

---

## 3. 会话治理模型（活跃 / 闲置 / 淘汰 / 撤销）

每条会话链除"当前刷新凭证"外，还维护两个时间字段：`createdAt`（登录时间）与
`lastActivityAt`（最近一次活动时间，访问放行或刷新成功时推进）。会话有五种状态：

| 状态 | 含义 | 是否终态 | 如何进入 |
|------|------|----------|----------|
| `ACTIVE` | 正常存活 | 否 | 登录成功 |
| `REVOKED` | 主动撤销（本人单条撤销 / revoke-others / 旧凭证复用） | 是 | 治理 API、复用检测 |
| `IDLE_TIMEOUT` | 闲置超时：超过闲置窗口既无访问也无刷新 | 是 | 惰性判定 |
| `EVICTED` | 容量超限被淘汰 | 是 | 登录时容量治理 |
| `EXPIRED` | 到达刷新凭证绝对过期时间 | 是 | 惰性判定 |

- **惰性生效**：闲置/绝对过期不依赖后台任务，在每次访问、刷新、列表、撤销时做一次性状态收敛；
  状态转换是幂等的，终态会话**不可被任何操作重新激活**。
- **闲置 vs 绝对过期可区分**：闲置看 `lastActivityAt + idle-ttl`，绝对过期看
  `refreshTokenExpiresAt`，两者独立判定（恰在闲置边界相等时不算超时）。

### 3.1 会话列表与撤销 API（均需登录，权限 `session:manage`）

| 方法/路径 | 行为 | 关键状态码 |
|-----------|------|-----------|
| `GET /api/sessions` | 返回本人名下所有**仍活跃**会话 | 200；未认证 401 |
| `POST /api/sessions/{id}/revoke` | 撤销指定一条会话 | 200；越权 403 `SESSION_NOT_OWNED`；不存在 404 `SESSION_NOT_FOUND`；已终态 409 `SESSION_NOT_ACTIVE` |
| `POST /api/sessions/revoke-others` | 撤销除当前会话外的其他活跃会话，返回 `affected` 数 | 200 |

`GET /api/sessions` 的每条记录（`SessionView`）**刻意不包含任何访问/刷新凭证**，只有：

```json
{
  "sessionId": "...",
  "createdAt": "2026-09-30T00:00:00Z",
  "lastActivityAt": "2026-09-30T00:12:30Z",
  "refreshExpiresAt": "2026-09-30T12:00:00Z",
  "current": true
}
```

- `current=true` 标识"携带当前访问凭证的这条会话"。
- **隔离边界**：所有操作都以认证后的 `username` 为边界；列表不可能出现他人会话，
  撤销他人会话返回明确的 `SESSION_NOT_OWNED`（且不改变对方任何状态）。

### 3.2 容量上限与淘汰语义

- 同一用户的活跃会话数超过 `auth.session.max-per-user`（默认 5）时，新登录在**同一用户临界区**
  内先惰性收敛闲置/过期会话，再淘汰**最久未活动**的一条（`lastActivityAt` 相同则按会话 ID
  稳定排序，结果唯一）。
- **本次新登录的会话永不参与淘汰**；刚刚发生过访问/刷新（活动时间最新）的会话不会被误伤；
  正在进行中的刷新持有同一把用户锁，其活动计数不会被算错。
- 容量按用户独立计算，不跨用户共享。

### 3.3 并发与收敛语义

锁层级全局固定为 **用户监视器 → 会话监视器**，登录（含淘汰）、刷新、访问活动推进、列表惰性扫描、
定向/批量撤销都先取用户锁：

- 同一条会话并发刷新：严格一次成功，其余识别为复用或已撤销，绝不产生两条有效链；
- 并发撤销与刷新交错：最终唯一收敛为 `REVOKED`；撤销是幂等操作（多次撤销都成功返回，
  但只发生一次 `ACTIVE -> REVOKED` 转换），撤销后该会话的访问与刷新立即被拒；
- 并发登录超过容量：活跃会话数稳定收敛到上限，淘汰结果确定。

### 3.4 治理相关的拒绝原因（与既有原因并列、彼此可区分）

刷新侧（`AuthOutcome`）：

| 场景 | outcome |
|------|---------|
| 凭证到达绝对过期时间 | `REFRESH_TOKEN_EXPIRED` |
| 会话闲置超时 | `SESSION_IDLE` |
| 会话因容量被淘汰 | `SESSION_EVICTED` |
| 会话已主动撤销 | `SESSION_REVOKED` |

访问侧（`AccessDeniedReason`）：会话终止原因会**带原因地级联**标记其历史访问凭证——
主动撤销为 `TOKEN_REVOKED`，闲置为 `SESSION_IDLE`，淘汰为 `SESSION_EVICTED`；
若访问凭证自身先到期则仍是 `TOKEN_EXPIRED`；会话已达绝对过期为 `SESSION_EXPIRED`。

---

## 4. 权限模型与默认拒绝

访问判定按固定顺序短路执行，每一步都给出独立、可区分的拒绝原因：

| 顺序 | 判定 | 拒绝原因 | HTTP |
|------|------|----------|------|
| 1 | 是否携带 `Authorization: Bearer …` | `MISSING_CREDENTIAL` | 401 |
| 2 | 访问凭证是否可识别 | `UNKNOWN_TOKEN` | 401 |
| 3 | 访问凭证自身是否已绝对过期 | `TOKEN_EXPIRED` | 401 |
| 4 | 凭证是否因会话终止被级联撤销（区分撤销/闲置/淘汰） | `TOKEN_REVOKED` / `SESSION_IDLE` / `SESSION_EVICTED` | 401 |
| 5 | 所属会话链是否仍存活（惰性识别撤销/闲置/淘汰/绝对过期） | `SESSION_REVOKED` / `SESSION_IDLE` / `SESSION_EVICTED` / `SESSION_EXPIRED` | 401 |
| 6 | 端点是否显式声明所需权限 | `INSUFFICIENT_PERMISSION`（默认拒绝） | 403 |
| 7 | 用户角色展开权限 + 显式权限是否包含所需权限 | `INSUFFICIENT_PERMISSION` | 403 |

- 端点通过 `@RequirePermission("xxx:read")` **显式声明**权限；未标注的受保护路径一律默认拒绝。
- 撤销记录保留在存储中，因此返回 `TOKEN_REVOKED` 而非 `UNKNOWN_TOKEN`；访问放行时会在用户
  临界区内推进会话 `lastActivityAt`。
- 所有内置角色都显式含 `session:manage`，但治理服务仍以会话归属做第二层隔离（只能管自己的）。

---

## 5. 并发与撤销语义汇总

- **并发刷新**：用户监视器 + 会话监视器 + CAS 轮换，同一 refresh 凭证并发刷新严格只有一次成功
  （由 `ConcurrentRefreshTests`、`ConcurrentGovernanceTests` 多线程压测验证）。
- **复用收敛**：旧凭证一旦再次使用，全链撤销；此后无论新、旧凭证，访问与刷新都被拒绝，
  最终状态唯一收敛为 `REVOKED`。
- **主动撤销**：`/api/auth/revoke` 与治理撤销端点都把链置为终态并级联标记该会话访问凭证，
  即时生效、终态幂等。
- **登录失败抑制**：每个用户名独立监视器，失败计数在并发下精确累加；达到阈值的**当次请求**
  即返回 `ACCOUNT_LOCKED`；登录成功清零；锁定窗口过后自动恢复。

---

## 6. 审计

- 每一次认证（登录/刷新/撤销）、授权（允许/拒绝）与会话治理（列表/单条撤销/批量撤销/淘汰）
  判定都由 `AuditService` 记录，同时输出结构化日志
  （`audit|action=…|subject=…|result=…|detail=…`）并保留内存快照。
- 治理审计动作名为 `SESSION_GOVERNANCE`，detail 含会话 ID、活跃条数、被淘汰/撤销目标等关键依据；
  越权尝试记录 `SESSION_NOT_OWNED`。
- 审计写入被 try/catch 完全包裹：**写入失败只记录内部告警，不改变最终判定结果**。
- 单元测试运行时可在日志中看到关键输入（用户名、凭证前缀、所需权限）与判定依据
  （拒绝原因、会话 ID、角色/权限集合）。

---

## 7. 测试清单

```bash
mvn test
```

| 测试类 | 覆盖内容 |
|--------|----------|
| `RefreshTokenTests` | 刷新轮换、旧凭证重复使用导致全链失效、级联撤销访问凭证、未知凭证原因可区分 |
| `ConcurrentRefreshTests` | 24 线程并发刷新同一凭证：恰好一次成功、无双链、状态最终收敛；两波刷新复用 |
| `ExpiryAndRevocationTests` | 访问凭证过期、刷新凭证过期、主动撤销后访问/刷新全部拒绝 |
| `AccessControlTests` | 拒绝原因彼此可区分、角色放行、跨角色权限不足、未声明权限默认拒绝 |
| `LoginSuppressionTests` | 失败锁定、成功清零、窗口过期恢复、并发失败计数精确、每判定必审计 |
| `SessionGovernanceTests` | 多用户多端列表隔离、单条撤销立即生效、撤销其他、终态不可复活、越权拒绝、审计可见 |
| `IdleAndEvictionTests` | 闲置惰性生效且与绝对过期可区分、活动续命、超容量淘汰最久未活动、最新会话不被误伤、容量按用户隔离 |
| `ConcurrentGovernanceTests` | 同会话并发刷新/撤销交错唯一收敛、并发登录超容量计数稳定、并发定向撤销只一次转换 |
| `HttpEndToEndTests` / `HttpGovernanceEndToEndTests` | MockMvc 全链路 HTTP 状态码与 reason 断言（401/403/404/409/423）、列表不泄漏凭证 |

---

## 8. 主要代码结构与兼容范围

```
clock/       TickClock 统一时间源（测试用 MutableTickClock 可控推进）
token/       TokenIssuer 高熵凭证签发、TokenPair 凭证对
session/     SessionChain（含 createdAt/lastActivityAt）、SessionState 五态、
             AccessRecord（带原因的撤销）、SessionRepository（用户锁+会话锁、终态收敛、淘汰）
auth/        AuthService（登录/容量淘汰/刷新/撤销）、LoginFailureTracker、PasswordHasher、UserDirectory
access/      AccessControlService（认证+默认拒绝授权+活动推进）、@RequirePermission
governance/  SessionGovernanceService、SessionView（无凭证视图）、GovernanceResult/Outcome
audit/       AuditService（审计失败不影响判定）
config/      AuthorizationInterceptor、WebConfig、DataInitializer
web/         AuthController、SessionController、ProtectedApiController、DTO
```

兼容范围（对既有行为）：

- 登录/刷新/撤销/访问的既有请求与响应字段保持不变；既有 19 个用例全部不回归。
- 新增配置项均有默认值（闲置 30m、容量 5），不配置也能按既有方式运行。
- 会话存储仍为进程内内存实现，重启即清空（与改造前一致），分布式部署需替换为共享存储。
- 无后台调度：闲置/过期在请求路径上惰性判定，不依赖定时任务。
