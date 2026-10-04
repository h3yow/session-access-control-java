# 会话式身份认证与访问控制（本地可运行）

基于 Spring Boot 3.4 / Java 21 实现的一套**会话式认证与访问控制**服务，覆盖凭证
**签发 → 校验 → 刷新（轮换）→ 撤销 → 会话治理**的完整链路，重点保证并发与异常情况下判定结果
**一致、可区分、可解释、可审计**。

在登录/刷新轮换/撤销之上，本服务还提供一层**会话治理**：用户可以查看自己名下所有仍存活的会话、
精确踢掉某一台设备、一键撤销除当前外的其它会话；系统同时提供**长期登录凭证的绝对有效期**、
**闲置超时自动失效**与**单用户活跃会话容量上限淘汰**三类自动治理。

> **绝对过期的一致语义（本次修复重点）**：会话的长期登录凭证（链上 refresh 凭证）一旦到了自己的
> **绝对有效期**，无论闲置窗口是否还没到，也无论该会话最近签发的短期访问凭证表面上是否还没自然到期，
> 会话都立即不再存活：**名单不再展示、访问与刷新一律拒绝**（原因分别为 `SESSION_EXPIRED` /
> `REFRESH_TOKEN_EXPIRED`），并收敛为终态 `EXPIRED`，之后任何请求都不能把它变回可用。
> 名单、访问、刷新三个入口共用同一条生命周期规则、在同一把锁下判定，到期点前后并发也不会出现
> “名单显示存活但访问已拒绝”或“部分请求放行、部分拒绝”的矛盾。

---

## 1. 快速开始

```bash
# 运行全部测试（37 个，含绝对过期专项、并发刷新/复用检测/过期/撤销/权限/会话治理/HTTP 端到端）
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
auth.token.refresh-ttl=PT12H     # 长期刷新凭证有效期
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
| 长期登录凭证已到绝对有效期 | `REFRESH_TOKEN_EXPIRED` | 401 |
| 会话闲置超时 | `SESSION_IDLE_TIMEOUT` | 401 |
| 会话被容量淘汰 | `SESSION_EVICTED` | 401 |
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
| `EXPIRED` | 长期登录凭证（链上 refresh 凭证）到达**绝对过期时间**（与闲置相互独立） | 懒收敛（名单/访问/刷新/淘汰任一入口触碰时） |

关键区分：**闲置失效 ≠ 凭证绝对过期**。

- 闲置看的是"距上次活动多久"（`now - lastActivityAt > idle-timeout`），只要持续在用就不会闲置；
- 绝对过期看的是"距登录多久"（`now >= refreshTokenExpiresAt`，锚定登录时刻，刷新不延长）。

当两个条件在同一时刻都成立时，**绝对过期优先**：链状态唯一收敛为 `EXPIRED`，刷新原因唯一为
`REFRESH_TOKEN_EXPIRED`，不会被归为闲置。

### 2.5.0 绝对过期在名单与访问中的可见语义（重点）

长期登录凭证到点后的行为在三个入口保持**同一规则、同一把锁、唯一终态**：

| 入口 | 绝对过期后的表现 | 可区分原因 |
|------|------------------|-----------|
| 会话名单 `GET /api/sessions`（含从**另一条仍有效会话**查看） | 该会话**不再出现在存活名单**（名单只返回 `ACTIVE`） | 不展示即为"已失效" |
| 受保护接口访问（短期 access token） | **拒绝**，即使该 access token 表面还没自然到期 | `SESSION_EXPIRED` |
| 刷新 `POST /api/auth/refresh` | **拒绝**（当前与历史 refresh 凭证同因） | `REFRESH_TOKEN_EXPIRED` |

- 收敛由 `SessionRepository.evaluateLifecycle` 统一完成：在会话监视器内先判绝对过期
  （`!now.isBefore(refreshTokenExpiresAt)`，即 `now >= 到期点`，边界点即刻失效），再判闲置。
- 访问与名单/容量治理均按**先用户锁、后会话锁**的固定顺序加锁，与刷新一致；因此到期点前后
  并发的名单、访问、刷新请求要么全部放行（到期前一刻）、要么全部拒绝（到达到期点），
  最终状态唯一收敛为 `EXPIRED`，不会重新出现有效的会话链。
- 绝对过期**不级联撤销**访问凭证（否则原因会被混淆成 `TOKEN_REVOKED`）：
  - 会话绝对过期、但 access token 表面未到期 → `SESSION_EXPIRED`；
  - access token 自身 15 分钟自然到期（会话是否过期都可能）→ `TOKEN_EXPIRED`；
  - 两类"过期"始终可以清楚区分。
- `EXPIRED` 是终态：此后再刷新、再访问、再等待、再次（幂等）撤销都不会改变或复活它；
  先到的终态胜出，后到的撤销不会把 `EXPIRED` 改写成 `REVOKED`。

### 2.5.1 会话列举与归属隔离

- `GET /api/sessions` 仅返回**调用者本人**名下仍为 `ACTIVE` 的会话；列举前先在用户锁内做一次
  **生命周期收敛（绝对过期 + 闲置）**，保证"存活集合"与随后的访问、刷新判定遵循同一条规则：
  已绝对过期的会话（即使闲置窗口未到）绝不会残留在存活名单里。
- 每条返回 `sessionId / createdAt / lastActivityAt / current`，其中 `current` 标识
  "发起本次查询的这条会话"。**响应中绝不出现任何 access/refresh 凭证内容**。
- 归属边界来自当前访问凭证解析出的用户，而非请求参数；天然不可能列举到他人会话。

### 2.5.2 精确撤销与"撤销其它"

- `POST /api/sessions/revoke` 按 `sessionId` 精确撤销：会话进入 `REVOKED` 并**级联撤销该会话全部
  访问凭证**，因此撤销后该设备的下一次访问与刷新**立即被拒**，无需等待自然过期。
- `DELETE /api/sessions/others` 撤销除当前会话外的全部存活会话，**绝不误伤当前会话**。
- 对已经处于终态的会话再次撤销是**幂等**的（返回成功并在消息中注明既有终态）；终态不会被覆盖、
  不会被"重新激活"。

### 2.5.3 各类拒绝原因的区别

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

### 2.5.4 容量与并发语义

- **每用户一把用户级监视器**。登录"建档 + 生命周期收敛（绝对过期 + 闲置）+ 容量淘汰"在同一把锁内
  原子完成；刷新与**访问**都按固定加锁顺序 **先用户锁、后会话锁**（与登录一致，不会死锁），
  名单则在用户锁内对名下会话逐一收敛，因此容量计数/淘汰不会与同一用户正在进行中的刷新或访问
  相互算错，到期点的名单与访问/刷新判定也不会互相矛盾。
- 超过 `auth.session.max-per-user`（默认 5）时，按 `(lastActivityAt, sessionId)` 全序选出
  **最久未活动**的会话淘汰为 `EVICTED`，直到回到上限以内；本次新登录的会话始终被保护，
  绝不被自己触发的淘汰误伤。淘汰**不级联**撤销访问凭证，以便访问时仍能区分出 `SESSION_EVICTED`。
- 所有状态流转只能 `ACTIVE -> 某个唯一终态`（`transitionIfActive` 单向 CAS）。
  多个请求并发撤销/刷新/淘汰同一条会话时，先到的终态胜出且不被覆盖，**最终状态唯一收敛，
  绝不会出现两条同时有效的链**。
- 时间到点（绝对过期/闲置）为**懒收敛**：名单、访问、刷新、容量淘汰前都会在锁内对触及的
  `ACTIVE` 会话执行同一套 `evaluateLifecycle`（**绝对过期优先于闲置**），无需后台定时任务。
  绝对过期的会话一旦被任一入口收敛为 `EXPIRED`，终态不可复活。

可配置项（`application.properties`）：

```properties
auth.session.idle-timeout=PT30M   # 闲置超时：期间既无访问也无刷新则自动失效
auth.session.max-per-user=5       # 单用户活跃会话数量上限，超出淘汰最久未活动者
```

### 2.5.5 兼容范围

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
| 5 | 所属会话是否已主动撤销/复用失效 | `SESSION_REVOKED` | 401 |
| 6 | 所属会话的长期凭证是否已**绝对过期**（access token 表面未到期也拒） | `SESSION_EXPIRED` | 401 |
| 7 | 所属会话是否已闲置超时 | `SESSION_IDLE_TIMEOUT` | 401 |
| 8 | 所属会话是否已被容量淘汰 | `SESSION_EVICTED` | 401 |
| 9 | 端点是否显式声明所需权限 | `INSUFFICIENT_PERMISSION`（默认拒绝） | 403 |
| 10 | 用户角色展开权限 + 显式权限是否包含所需权限 | `INSUFFICIENT_PERMISSION` | 403 |

> 第 5~8 步在会话监视器内由同一次 `evaluateLifecycle` 给出唯一终态（先到的终态保留、绝不复活）；
> 其中绝对过期先于闲置判定。注意第 4 步（`TOKEN_EXPIRED`）针对**短期访问凭证自身**到期，
> 第 6 步（`SESSION_EXPIRED`）针对**会话长期凭证**到点，两者短路顺序不同、原因彼此可区分。

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
- **绝对过期一致可见**：名单/访问/刷新共用 `evaluateLifecycle`（绝对过期优先于闲置）并在同一
  user→session 锁序下判定；长期凭证到点后名单立即不展示、访问（access token 表面未到期亦然）
  返回 `SESSION_EXPIRED`、刷新返回 `REFRESH_TOKEN_EXPIRED`，终态 `EXPIRED` 不可被任何后续请求复活；
  到期边界前后两侧的并发请求结果各自完全一致（见 `AbsoluteExpiryTests`）。
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
# 运行全部测试（37 个，含绝对过期专项、并发刷新/复用检测/过期/撤销/权限/会话治理/HTTP 端到端）
mvn test

# 只运行绝对过期专项（7 个用例）
mvn test -Dtest=AbsoluteExpiryTests
```

运行测试时日志会先打印每个**业务模块**横幅，再逐条打印 `[用例开始] / [用例通过] ✅ /
[用例失败] ❌`，类结束给出“模块小结（用例数/通过数/失败数）”，可直接从日志核对覆盖了哪些业务、
各用例是否通过。该机制由测试侧的 `BusinessCoverageLoggingExtension`
（`src/test/resources/META-INF/services` 自动注册）统一提供，对既有用例同样生效。

| 测试类 | 覆盖内容 |
|--------|----------|
| `RefreshTokenTests` | 刷新轮换、旧凭证重复使用导致全链失效、级联撤销访问凭证、未知凭证原因可区分 |
| `ConcurrentRefreshTests` | 24 线程并发刷新同一凭证：恰好一次成功、无双链、状态最终收敛；两波刷新复用 |
| `ExpiryAndRevocationTests` | 访问凭证过期、刷新凭证过期、主动撤销后访问/刷新全部拒绝 |
| `AccessControlTests` | 六类拒绝原因彼此可区分、角色放行、跨角色权限不足、未声明权限默认拒绝 |
| `LoginSuppressionTests` | 失败锁定、成功清零、窗口过期恢复、并发失败计数精确、每判定必审计 |
| `AbsoluteExpiryTests` | **绝对有效期专项**：绝对过期先到、闲置窗口未到时名单（含从另一条有效会话视角）不再展示且链收敛 EXPIRED；表面未到期的 access token 访问被拒 `SESSION_EXPIRED`、刷新被拒 `REFRESH_TOKEN_EXPIRED`，并与 `TOKEN_EXPIRED`/闲置/撤销/淘汰可区分；到期边界（到期前一刻放行、`now==到期点`即刻拒绝）；绝对与闲置同时成立时绝对优先；EXPIRED 终态历经刷新/等待/幂等撤销均不复活；到期点 36 线程混合并发（名单+访问+刷新）与边界前后两侧并发的结果各自一致、唯一收敛 |
| `SessionGovernanceTests` | 多用户多端登录列举（无凭证/当前标记/跨用户隔离）、精确撤销即时生效且不可复活、撤销其它、闲置与绝对过期可区分、容量淘汰最久未活动且不误伤当前/在刷新会话、越权查看撤销被拒、并发撤销+刷新终态唯一收敛、混合并发计数稳定 |
| `SessionHttpTests` | 会话列表/精确撤销/撤销其它的 HTTP 全链路、响应无凭证、越权 403 `SESSION_FORBIDDEN`、未知 404 |
| `HttpEndToEndTests` | MockMvc 全链路 HTTP 状态码与 reason 断言（401/403/423/404） |

### 6.1 本地怎么验证“绝对过期”语义

单元测试使用可控时钟，能在毫秒内稳定复现“长期凭证到点、闲置窗口未到、access token 表面未到期”
这一关键局面（见 `AbsoluteExpiryTests.setupAtAbsoluteExpiry` 的时间线）：

```bash
mvn test -Dtest=AbsoluteExpiryTests
# 关注日志：
#   [绝对过期-名单] 存活名单=[...]（不含过期会话）
#   [绝对过期-访问] 表面未到期的访问凭证被拒 reason=SESSION_EXPIRED
#   [绝对过期-刷新] 当前/旧 refresh 凭证均被拒 outcome=REFRESH_TOKEN_EXPIRED（非 REUSED）
#   [绝对过期-边界并发] t=60m00s 访问拒绝 30/30、名单隐藏 10/10、刷新拒绝 10/10
```

也可把 TTL 调成“长期凭证比短期凭证更早需要观察”的组合后启动服务，用 curl 走
登录 →（等待超过 `refresh-ttl` 但保持在一个闲置窗口内可通过持续访问另一条会话对照）→
用过期会话的 access token 访问、用其 refresh token 刷新、从另一条有效会话 `GET /api/sessions`：

```properties
# src/main/resources/application.properties
auth.token.access-ttl=PT15M      # 短期访问凭证有效期
auth.token.refresh-ttl=PT1H      # 长期登录凭证绝对有效期（调短便于观察）
auth.session.idle-timeout=PT30M  # 闲置窗口
auth.session.max-per-user=5
```

预期：到点后访问返回 401 `SESSION_EXPIRED`、刷新返回 401 `REFRESH_TOKEN_EXPIRED`、
名单中不再出现该会话；继续等待至该 access token 自身到期后访问原因变为 `TOKEN_EXPIRED`。

---

## 7. 主要代码结构

```
clock/       TickClock 统一时间源（测试用 MutableTickClock 可控推进）
token/       TokenIssuer 高熵凭证签发、TokenPair 凭证对
session/     SessionChain 会话链（登录/最近活动时间+状态机）、AccessRecord、SessionView、SessionRepository（并发+撤销+生命周期收敛（绝对过期/闲置）+淘汰核心）
auth/        AuthService（登录/刷新/撤销）、LoginFailureTracker、PasswordHasher、UserDirectory
access/      AccessControlService（认证+会话终态（撤销/绝对过期/闲置/淘汰）判定+默认拒绝授权）、@RequirePermission
governance/  SessionGovernanceService（列举/精确撤销/撤销其它）、GovernanceOutcome/GovernanceResult
audit/       AuditService（审计失败不影响判定）
config/      AuthorizationInterceptor、WebConfig、DataInitializer
web/         AuthController、ProtectedApiController、SessionController、DTO
```
