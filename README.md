# 会话式身份认证与访问控制（本地可运行）

基于 Spring Boot 3.4 / Java 21 实现的一套**会话式认证与访问控制**服务，覆盖凭证
**签发 → 校验 → 刷新（轮换）→ 撤销**的完整链路，重点保证并发与异常情况下判定结果
**一致、可区分、可解释、可审计**。

---

## 1. 快速开始

```bash
# 运行全部测试（19 个，含并发刷新/复用检测/过期/撤销/权限/HTTP 端到端）
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
```

受保护资源（均需显式权限，未标注的 `/api/**` 路径默认拒绝）：

| 路径 | 所需权限 |
|------|----------|
| `GET /api/resources/profile` | `profile:read` |
| `GET /api/resources/admin/dashboard` | `admin:read` |
| `GET /api/resources/reports/finance` | `finance:read` |

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
| 刷新凭证已过期 | `REFRESH_TOKEN_EXPIRED` | 401 |
| 会话已撤销（含复用后再刷新） | `SESSION_REVOKED` | 401 |
| 旧刷新凭证被重复使用 | `REFRESH_TOKEN_REUSED` | 401 |
| 撤销未知凭证 | `REVOKE_NOT_FOUND` | 404 |

---

## 3. 权限模型与默认拒绝

访问判定按固定顺序短路执行，每一步都给出独立、可区分的拒绝原因：

| 顺序 | 判定 | 拒绝原因 | HTTP |
|------|------|----------|------|
| 1 | 是否携带 `Authorization: Bearer …` | `MISSING_CREDENTIAL` | 401 |
| 2 | 访问凭证是否可识别 | `UNKNOWN_TOKEN` | 401 |
| 3 | 访问凭证是否已撤销 | `TOKEN_REVOKED` | 401 |
| 4 | 访问凭证是否已过期 | `TOKEN_EXPIRED` | 401 |
| 5 | 所属会话链是否仍存活 | `SESSION_REVOKED` | 401 |
| 6 | 端点是否显式声明所需权限 | `INSUFFICIENT_PERMISSION`（默认拒绝） | 403 |
| 7 | 用户角色展开权限 + 显式权限是否包含所需权限 | `INSUFFICIENT_PERMISSION` | 403 |

- 端点通过 `@RequirePermission("xxx:read")` **显式声明**权限；未标注的受保护路径一律默认拒绝。
- 撤销与过期是两个独立原因：撤销记录保留在存储中，因此返回 `TOKEN_REVOKED` 而非 `UNKNOWN_TOKEN`。

---

## 4. 并发与撤销语义汇总

- **并发刷新**：会话级监视器 + CAS 轮换，同一 refresh 凭证并发刷新严格只有一次成功
  （由 `ConcurrentRefreshTests` 以 24 线程压测验证）。
- **复用收敛**：旧凭证一旦再次使用，全链撤销；此后无论新、旧凭证，访问与刷新都被拒绝，
  最终状态唯一收敛为 `REVOKED`。
- **主动撤销**：`/api/auth/revoke` 将链置为 `REVOKED` 并级联撤销该会话所有访问凭证，
  即时生效。
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
mvn test
```

| 测试类 | 覆盖内容 |
|--------|----------|
| `RefreshTokenTests` | 刷新轮换、旧凭证重复使用导致全链失效、级联撤销访问凭证、未知凭证原因可区分 |
| `ConcurrentRefreshTests` | 24 线程并发刷新同一凭证：恰好一次成功、无双链、状态最终收敛；两波刷新复用 |
| `ExpiryAndRevocationTests` | 访问凭证过期、刷新凭证过期、主动撤销后访问/刷新全部拒绝 |
| `AccessControlTests` | 六类拒绝原因彼此可区分、角色放行、跨角色权限不足、未声明权限默认拒绝 |
| `LoginSuppressionTests` | 失败锁定、成功清零、窗口过期恢复、并发失败计数精确、每判定必审计 |
| `HttpEndToEndTests` | MockMvc 全链路 HTTP 状态码与 reason 断言（401/403/423/404） |

---

## 7. 主要代码结构

```
clock/      TickClock 统一时间源（测试用 MutableTickClock 可控推进）
token/      TokenIssuer 高熵凭证签发、TokenPair 凭证对
session/    SessionChain 会话链、AccessRecord 访问凭证记录、SessionRepository（并发+撤销核心）
auth/       AuthService（登录/刷新/撤销）、LoginFailureTracker、PasswordHasher、UserDirectory
access/     AccessControlService（认证+默认拒绝授权）、@RequirePermission
audit/      AuditService（审计失败不影响判定）
config/     AuthorizationInterceptor、WebConfig、DataInitializer
web/        AuthController、ProtectedApiController、DTO
```
