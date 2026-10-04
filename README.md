# 会话式身份认证与访问控制（本地可运行）

基于 Spring Boot 3.4 / Java 21 实现的一套**会话式认证与访问控制**服务，覆盖凭证
**签发 → 校验 → 刷新（轮换）→ 撤销 → 会话治理**的完整链路，重点保证并发与异常情况下判定结果
**一致、可区分、可解释、可审计**。

在登录/刷新轮换/撤销之上，本服务还提供一层**会话治理**：用户可以查看自己名下所有仍存活的会话、
精确踢掉某一台设备、一键撤销除当前外的其它会话；系统同时提供**闲置超时自动失效**与
**单用户活跃会话容量上限淘汰**两类自动治理。

---

## 1. 快速开始

```bash
# 运行全部测试（37 个，含并发刷新/复用检测/过期/撤销/权限/会话治理/绝对过期/HTTP 端到端）
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

# 会话治理：列举本人名下所有仍存活的会话（需携带访问凭证，响应不含任何凭证内容）
curl -s http://localhost:8080/api/sessions \
  -H "Authorization: Bearer <accessToken>"

# 精确踢掉某一台设备/某一次登录（按列表里的 sessionId）
curl -s -X POST http://localhost:8080/api/sessions/revoke \
  -H "Authorization: Bearer <accessToken>" -H 'Content-Type: application/json' \
  -d '{"sessionId":"<目标 sessionId>"}'

# 一键撤销除当前会话外的其它全部会话
curl -s -X DELETE http://localhost:8080/api/sessions/others \
  -H "Authorization: Bearer <accessToken>"
```

受保护资源（均需显式权限，未标注的 `/api/**` 路径默认拒绝）：

| 路径 | 所需权限 |
|------|----------|
| `GET /api/resources/profile` | `profile:read` |
| `GET /api/resources/admin/dashboard` | `admin:read` |
| `GET /api/resources/reports/finance` | `finance:read` |
| `GET /api/sessions` | `session:manage`（三个内置角色均含） |
| `POST /api/sessions/revoke` | `session:manage` |
| `DELETE /api/sessions/others` | `session:manage` |

公开端点：`POST /api/auth/login|refresh|revoke`（不经过访问拦截器）。

### 1.2 观察过期行为

将 TTL 调短后重启，或直接参考使用可控时钟的单元测试：

```properties
# src/main/resources/application.properties
auth.token.access-ttl=PT15M      # 短期访问凭证有效期
auth.token.refresh-ttl=PT12H     # 长期刷新凭证有效期（会话绝对有效期，锚定登录时刻）
auth.login.max-failures=5        # 连续失败锁定阈值
auth.login.lock-duration=PT5M    # 锁定时长
```

本地验证"绝对过期"语义（推荐用可控时钟的自动化测试，稳定可复现）：

```bash
# 只跑绝对过期用例，日志中可见每个 CASE 的场景、判定原因与通过情况
mvn test -Dtest=AbsoluteExpiryTests
```

手动验证：把 `auth.token.refresh-ttl` 调短（如 `PT2M`）、`auth.session.idle-timeout`
保持较大（如 `PT30M`）后重启，登录拿到凭证对，期间持续访问保持活跃；2 分钟后：
`GET /api/sessions` 名单中该会话消失、携带未自然到期的 access 凭证访问返回
401 `SESSION_EXPIRED`、刷新返回 401 `REFRESH_TOKEN_EXPIRED`，且之后任何请求都无法复活该会话。

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

## 2.5 会话治理模型（活跃 / 闲置 / 淘汰 / 撤销）

每条会话链除了"当前刷新凭证 + 绝对过期时间"外，还记录两个活动时间：

- `createdAt`：**登录时间**，用于辨认"是哪次登录"；
- `lastActivityAt`：**最近一次活动时间**，访问放行与刷新成功都会推进它。

会话状态机只有一个存活态，其余均为**终态（不可被重新激活）**：

| 状态 | 含义 | 触发方式 |
|------|------|----------|
| `ACTIVE` | 唯一存活态，可访问、可刷新 | 登录成功 |
| `REVOKED` | 被**主动撤销**（用户踢设备 / 撤销接口 / 检测到刷新凭证复用） | 主动操作或复用检测 |
| `IDLE_TIMEOUT` | **闲置超时**：一段时间内既无访问也无刷新，自动失效 | 懒判定（访问/刷新/列举/淘汰时） |
| `EVICTED` | **容量淘汰**：同一用户活跃会话超过上限，最久未活动者被淘汰 | 每次新登录建档后 |
| `EXPIRED` | 刷新凭证到达**绝对过期时间**（与闲置相互独立） | 懒判定（访问/刷新/列举/淘汰时） |

关键区分：**闲置失效 ≠ 凭证绝对过期**。

- 闲置看的是"距上次活动多久"（`now - lastActivityAt > idle-timeout`），只要持续在用就不会闲置；
- 绝对过期看的是"距登录多久"（`now >= refreshTokenExpiresAt`，锚定登录时刻，刷新不延长）。

### 2.5.1 绝对过期的可见语义（名单 / 访问 / 刷新一致失效）

当一条会话的刷新凭证已过绝对有效期、但闲置窗口还没到（刚还有活动）时：

- **名单**：`GET /api/sessions` 在列举前先做"绝对过期 + 闲置"懒收敛，已绝对过期的会话
  **不会出现在存活名单中**，也不会被任何入口当作可继续使用的会话；
- **访问**：即使该会话此前签发的 access 凭证表面上还没自然到期，访问一律拒绝，
  原因为 `SESSION_EXPIRED`（HTTP 401）——与 `TOKEN_EXPIRED`（access 凭证自身到期）、
  `SESSION_IDLE_TIMEOUT`（闲置）、`SESSION_REVOKED`（主动撤销/复用）、
  `SESSION_EVICTED`（容量淘汰）彼此可区分；
- **刷新**：一律拒绝，原因为 `REFRESH_TOKEN_EXPIRED`；
- **终态不可逆**：一旦收敛为 `EXPIRED`，后续任何请求（访问/刷新/列举/再次撤销）
  都不能把它重新变回可用；绝对过期判定与闲置判定在**同一把会话锁内原子完成**
  （绝对过期优先），名单、访问、刷新三个入口在同一时刻看到同一个唯一状态，
  并发下最终状态唯一收敛，不会重新出现有效的会话链。

### 2.5.2 会话列举与归属隔离

- `GET /api/sessions` 仅返回**调用者本人**名下仍为 `ACTIVE` 的会话；列举前先做一次
  **绝对过期 + 闲置**收敛，保证"存活集合"与随后的访问/刷新判定一致。
- 每条返回 `sessionId / createdAt / lastActivityAt / current`，其中 `current` 标识
  "发起本次查询的这条会话"。**响应中绝不出现任何 access/refresh 凭证内容**。
- 归属边界来自当前访问凭证解析出的用户，而非请求参数；天然不可能列举到他人会话。

### 2.5.3 精确撤销与"撤销其它"

- `POST /api/sessions/revoke` 按 `sessionId` 精确撤销：会话进入 `REVOKED` 并**级联撤销该会话全部
  访问凭证**，因此撤销后该设备的下一次访问与刷新**立即被拒**，无需等待自然过期。
- `DELETE /api/sessions/others` 撤销除当前会话外的全部存活会话，**绝不误伤当前会话**。
- 对已经处于终态的会话再次撤销是**幂等**的（返回成功并在消息中注明既有终态）；终态不会被覆盖、
  不会被"重新激活"。

### 2.5.4 各类拒绝原因的区别

访问被拒（`AccessDeniedReason`，HTTP 401/403）：

| 原因 | 含义 |
|------|------|
| `MISSING_CREDENTIAL` / `UNKNOWN_TOKEN` | 未携带凭证 / 凭证无法识别 |
| `TOKEN_EXPIRED` | 访问凭证自身 15 分钟到期（凭证级绝对过期） |
| `TOKEN_REVOKED` | 访问凭证因所属会话被**主动撤销**而级联失效 |
| `SESSION_REVOKED` | 所属会话处于 `REVOKED`（主动撤销/复用） |
| `SESSION_IDLE_TIMEOUT` | 所属会话**闲置超时** |
| `SESSION_EVICTED` | 所属会话被**容量淘汰** |
| `SESSION_EXPIRED` | 所属会话的刷新凭证已**绝对过期** |
| `INSUFFICIENT_PERMISSION` | 默认拒绝 / 权限不足（403） |

刷新被拒（`AuthOutcome`，HTTP 401）：`REFRESH_TOKEN_UNKNOWN`（无法识别）、
`REFRESH_TOKEN_EXPIRED`（绝对过期）、`SESSION_IDLE_TIMEOUT`（闲置）、`SESSION_EVICTED`（淘汰）、
`SESSION_REVOKED`（已撤销/复用）、`REFRESH_TOKEN_REUSED`（旧凭证复用，撤销整条链）。

会话治理写操作（`GovernanceOutcome`）：`SESSION_REVOKED` / `SESSIONS_REVOKED_OTHERS`（200）、
`SESSION_NOT_FOUND`（404）、`SESSION_FORBIDDEN`（**越权操作他人会话，403**）。

### 2.5.5 容量与并发语义

- **每用户一把用户级监视器**。登录"建档 + 闲置收敛 + 容量淘汰"在同一把锁内原子完成；
  刷新按固定加锁顺序 **先用户锁、后会话锁**（与登录一致，不会死锁），
  因此容量计数/淘汰不会与同一用户**正在进行中的刷新**相互算错。
- 超过 `auth.session.max-per-user`（默认 5）时，按 `(lastActivityAt, sessionId)` 全序选出
  **最久未活动**的会话淘汰为 `EVICTED`，直到回到上限以内；本次新登录的会话始终被保护，
  绝不被自己触发的淘汰误伤。淘汰**不级联**撤销访问凭证，以便访问时仍能区分出 `SESSION_EVICTED`。
- 所有状态流转只能 `ACTIVE -> 某个唯一终态`（`transitionIfActive` 单向 CAS）。
  多个请求并发撤销/刷新/淘汰同一条会话时，先到的终态胜出且不被覆盖，**最终状态唯一收敛，
  绝不会出现两条同时有效的链**。
- 闲置与绝对过期判定均为**懒收敛**：访问、刷新、列举、容量淘汰前都会在锁内把已失效的
  `ACTIVE` 会话收敛为对应终态（绝对过期优先于闲置，同一把会话锁内原子完成），
  无需后台定时任务；容量淘汰前先收敛绝对过期与闲置会话，已失效会话不占活跃容量。

可配置项（`application.properties`）：

```properties
auth.session.idle-timeout=PT30M   # 闲置超时：期间既无访问也无刷新则自动失效
auth.session.max-per-user=5       # 单用户活跃会话数量上限，超出淘汰最久未活动者
```

### 2.5.6 兼容范围

- 既有 `POST /api/auth/login|refresh|revoke` 的路径、请求体、成功与既有失败原因/状态码保持不变；
  会话治理是在其上**叠加**的一层，不改变原接口契约。
- 会话链的内存结构新增了 `createdAt / lastActivityAt` 与三个终态枚举；本工程为内存存储、无持久化，
  无需数据迁移。重启后所有会话清空（与既有行为一致）。
- 主动撤销/复用检测对访问凭证的级联撤销语义保持不变（仍返回 `TOKEN_REVOKED`）；
  新增的 `IDLE_TIMEOUT / EVICTED / EXPIRED` 只在对应新场景下出现，均为**新增枚举值**，
  不改变原有任何判定的返回原因。
- 三个内置角色统一追加了自身会话治理权限 `session:manage`；自定义角色/显式权限模型不受影响。
- 新接口为无状态只读/写视图，列表与响应体不含任何凭证内容；治理操作同样全程审计。

---

## 3. 权限模型与默认拒绝

访问判定按固定顺序短路执行，每一步都给出独立、可区分的拒绝原因：

| 顺序 | 判定 | 拒绝原因 | HTTP |
|------|------|----------|------|
| 1 | 是否携带 `Authorization: Bearer …` | `MISSING_CREDENTIAL` | 401 |
| 2 | 访问凭证是否可识别 | `UNKNOWN_TOKEN` | 401 |
| 3 | 访问凭证是否已撤销 | `TOKEN_REVOKED` | 401 |
| 4 | 访问凭证是否已过期 | `TOKEN_EXPIRED` | 401 |
| 5 | 所属会话是否已闲置超时 | `SESSION_IDLE_TIMEOUT` | 401 |
| 6 | 所属会话是否已被容量淘汰 | `SESSION_EVICTED` | 401 |
| 7 | 所属会话是否已主动撤销/复用失效 | `SESSION_REVOKED` | 401 |
| 8 | 所属会话刷新凭证是否已绝对过期 | `SESSION_EXPIRED` | 401 |
| 9 | 端点是否显式声明所需权限 | `INSUFFICIENT_PERMISSION`（默认拒绝） | 403 |
| 10 | 用户角色展开权限 + 显式权限是否包含所需权限 | `INSUFFICIENT_PERMISSION` | 403 |

- 端点通过 `@RequirePermission("xxx:read")` **显式声明**权限；未标注的受保护路径一律默认拒绝。
- 撤销与过期是两个独立原因：撤销记录保留在存储中，因此返回 `TOKEN_REVOKED` 而非 `UNKNOWN_TOKEN`。

---

## 4. 并发与撤销语义汇总

- **并发刷新**：会话级监视器 + CAS 轮换，同一 refresh 凭证并发刷新严格只有一次成功
  （由 `ConcurrentRefreshTests` 以 24 线程压测验证）。
- **复用收敛**：旧凭证一旦再次使用，全链撤销；此后无论新、旧凭证，访问与刷新都被拒绝，
  最终状态唯一收敛为 `REVOKED`。
- **主动撤销**：`/api/auth/revoke` 或会话治理 `/api/sessions/revoke` 将链置为 `REVOKED`
  并级联撤销该会话所有访问凭证，即时生效；终态不可复活，重复撤销幂等。
- **状态单向收敛**：会话只能从 `ACTIVE` 进入唯一终态（`REVOKED/IDLE_TIMEOUT/EVICTED/EXPIRED`），
  并发撤销/刷新/淘汰时先到的终态胜出且不被覆盖。
- **用户级锁与容量淘汰**：登录建档+闲置收敛+淘汰在用户锁内原子完成，刷新按 user→session 固定锁序，
  保证并发登录/刷新/撤销下活跃计数稳定、不会超过上限、不会误伤当前会话或正在刷新的会话。
- **登录失败抑制**：每个用户名独立监视器，失败计数在并发下精确累加；达到阈值的**当次请求**
  即返回 `ACCOUNT_LOCKED`；登录成功清零；锁定窗口过后自动恢复。

---

## 5. 审计

- 每一次认证（登录/刷新/撤销）与授权（允许/拒绝）判定都由 `AuditService` 记录，
  同时输出结构化日志（`audit|action=…|subject=…|result=…|detail=…`）并保留内存快照。
- 审计写入被 try/catch 完全包裹：**写入失败只记录内部告警，不改变最终判定结果**。
- 单元测试运行时可在日志中看到关键输入（用户名、凭证前缀、所需权限）与判定依据
  （拒绝原因、会话 ID、角色/权限集合）。

---

## 6. 测试清单

```bash
# 运行全部测试（37 个，含并发刷新/复用检测/过期/撤销/权限/会话治理/绝对过期/HTTP 端到端）
mvn test
```

| 测试类 | 覆盖内容 |
|--------|----------|
| `RefreshTokenTests` | 刷新轮换、旧凭证重复使用导致全链失效、级联撤销访问凭证、未知凭证原因可区分 |
| `ConcurrentRefreshTests` | 24 线程并发刷新同一凭证：恰好一次成功、无双链、状态最终收敛；两波刷新复用 |
| `ExpiryAndRevocationTests` | 访问凭证过期、刷新凭证过期、主动撤销后访问/刷新全部拒绝 |
| `AbsoluteExpiryTests` | 绝对过期先到、闲置未到时：名单隐藏、访问 `SESSION_EXPIRED`、刷新 `REFRESH_TOKEN_EXPIRED`；到期边界精确一致；终态不可复活；五类拒绝原因两两可区分；并发名单/访问/刷新最终状态唯一收敛 |
| `AccessControlTests` | 六类拒绝原因彼此可区分、角色放行、跨角色权限不足、未声明权限默认拒绝 |
| `LoginSuppressionTests` | 失败锁定、成功清零、窗口过期恢复、并发失败计数精确、每判定必审计 |
| `SessionGovernanceTests` | 多用户多端登录列举（无凭证/当前标记/跨用户隔离）、精确撤销即时生效且不可复活、撤销其它、闲置与绝对过期可区分、容量淘汰最久未活动且不误伤当前/在刷新会话、越权查看撤销被拒、并发撤销+刷新终态唯一收敛、混合并发计数稳定 |
| `SessionHttpTests` | 会话列表/精确撤销/撤销其它的 HTTP 全链路、响应无凭证、越权 403 `SESSION_FORBIDDEN`、未知 404 |
| `HttpEndToEndTests` | MockMvc 全链路 HTTP 状态码与 reason 断言（401/403/423/404） |

---

## 7. 主要代码结构

```
clock/       TickClock 统一时间源（测试用 MutableTickClock 可控推进）
token/       TokenIssuer 高熵凭证签发、TokenPair 凭证对
session/     SessionChain 会话链（登录/最近活动时间+状态机）、AccessRecord、SessionView、SessionRepository（并发+撤销+闲置+淘汰核心）
auth/        AuthService（登录/刷新/撤销）、LoginFailureTracker、PasswordHasher、UserDirectory
access/      AccessControlService（认证+闲置/淘汰/过期终态判定+默认拒绝授权）、@RequirePermission
governance/  SessionGovernanceService（列举/精确撤销/撤销其它）、GovernanceOutcome/GovernanceResult
audit/       AuditService（审计失败不影响判定）
config/      AuthorizationInterceptor、WebConfig、DataInitializer
web/         AuthController、ProtectedApiController、SessionController、DTO
```
