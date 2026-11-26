# JWT 校验接口对接说明

> 受众：需要校验用户 access token、并读取角色/状态的后端或服务对接方  
> 基址：全文用 `{api_base}` 表示 ai_service API 根（使用你们项目既有配置，勿把文档示例环境地址写进代码）

---

## 1. 做什么

调用方拿到用户登录后的 **access token** 后，向本接口校验：

- token 是否有效（签名、过期、注销、环境绑定等）
- 对应的 **用户 ID、角色（user_type）、账号状态（status）、机构** 等必要信息

典型场景：下游服务收到 `Authorization: Bearer <token>`，不想自己解 JWT，改调本接口确认身份。

---

## 2. 接口

| 项 | 说明 |
|----|------|
| 方法 | `GET` 或 `POST`（行为相同，任选其一） |
| 路径 | `{api_base}/auth/verify_token` |
| 鉴权 | **必填**请求头 `Authorization: Bearer <access_token>`（也支持 `Token <access_token>`） |
| 请求体 | 无（`POST` 也不需要 body） |
| Content-Type | 成功为 `application/json` |

### 2.1 调用时机

1. 用户已通过统一登录拿到 access token  
2. 调用方需要确认「这个 token 现在还能用」并拿到 `user_id` / 角色 / 状态  
3. **不要**用本接口代替登录；登录仍走既有 `/auth/login`、`/auth/ajax_login` 或 OAuth 换票

### 2.2 请求示例

```http
GET {api_base}/auth/verify_token HTTP/1.1
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Accept: application/json
```

```bash
curl -sS -X GET "{api_base}/auth/verify_token" \
  -H "Authorization: Bearer {access_token}" \
  -H "Accept: application/json"
```

```bash
# 与 GET 等价
curl -sS -X POST "{api_base}/auth/verify_token" \
  -H "Authorization: Bearer {access_token}" \
  -H "Accept: application/json"
```

---

## 3. 成功响应（HTTP 200）

### 3.1 示例

```json
{
  "valid": true,
  "user_id": 8743,
  "username": "someone@example.com",
  "email": "someone@example.com",
  "real_name": "张三",
  "mobile": "13800138000",
  "org_id": 12,
  "org_name": "示例机构",
  "display_org_name": "",
  "user_type": "org_member",
  "user_type_code": 6,
  "user_type_label": "机构普通用户",
  "status": "active",
  "status_code": 2,
  "status_label": "有效",
  "lang": "zhCN",
  "auth_is_active": true,
  "token_kind": "access",
  "is_from_alpha_mind": true
}
```

### 3.2 字段说明

| 字段 | 类型 | 说明 |
|------|------|------|
| `valid` | boolean | 恒为 `true`（能进到 200 即表示 token 校验通过） |
| `user_id` | number | 平台用户 ID（AlphaMind / ais 用户主键，下游鉴权请用此字段） |
| `username` | string | 登录名 |
| `email` | string | 邮箱，可能为空串 |
| `real_name` | string | 真实姓名，可能为空串 |
| `mobile` | string | 手机号，可能为空串 |
| `org_id` | number | 所属机构 ID；个人用户一般为 `0` |
| `org_name` | string | 机构名称；`org_id=0` 或查不到时为空串 |
| `display_org_name` | string | 个人用户展示用机构名（不影响权限），可能为空串 |
| `user_type` | string | 角色编码，见 §4.1 |
| `user_type_code` | number | 角色数字码，见 §4.1 |
| `user_type_label` | string | 角色展示名（随请求语言） |
| `status` | string | 账号状态编码，见 §4.2 |
| `status_code` | number | 账号状态数字码，见 §4.2 |
| `status_label` | string | 状态展示名（随请求语言） |
| `lang` | string | 用户语言偏好，如 `zhCN` / `zhTW` / `en` |
| `auth_is_active` | boolean \| null | 统一登录侧是否启用；查不到关联账号时为 `null` |
| `token_kind` | string | token 类型：`access` / `permanent` / `task_session` / `platform_api_key` |
| `is_from_alpha_mind` | boolean | 是否 AlphaMind 身份体系下的 token |

**对接建议：**

- 以 `valid === true` 且 HTTP 200 视为通过  
- 业务权限优先看 `user_type` / `user_type_code` 与 `status` / `status_code`  
- 写操作建议要求 `status === "active"`（或 `status_code === 2`）

---

## 4. 枚举

### 4.1 角色 `user_type` / `user_type_code`

| code | `user_type` | 含义（中文） |
|------|-------------|--------------|
| 1 | `admin` | 系统管理员 |
| 2 | `billing_ops` | 计费与运营 |
| 3 | `dev_test` | 开发测试 |
| 4 | `individual` | 个人 |
| 5 | `org_admin` | 机构管理员 |
| 6 | `org_member` | 机构普通用户 |

### 4.2 状态 `status` / `status_code`

| code | `status` | 含义（中文） |
|------|----------|--------------|
| 0 | `unverified` | 未验证 |
| 1 | `pending` | 待审核 |
| 2 | `active` | 有效 |
| 3 | `expired` | 到期 |
| 4 | `locked` | 禁用 |
| 5 | `deleted` | 已删除 |

---

## 5. 错误响应

| HTTP | 典型 JSON | 含义 | 调用方建议动作 |
|------|-----------|------|----------------|
| 401 | `{"msg":"..."}` 或 `{"message":"..."}`（框架/鉴权层，形状可能仅有文案字段） | 缺少 token、token 非法、过期、已注销、环境不匹配等 | 要求用户重新登录，换新 access token 后再调 |
| 401 | `{"valid": false, "message": "用户不存在或令牌无效"}` | token 解出后对应用户不存在/无效 | 同视为未登录；勿重试同一 token |
| 403 | `{"message": "..."}` | 当前环境不允许该用户访问（如 beta 白名单限制） | 提示无权限；不要当网络错误重试 |
| 5xx | 视网关/服务而定 | 服务异常 | 有限次重试；仍失败则告警 |

说明：

- **鉴权失败时**，多数路径由统一 JWT 中间件直接返回 401，**不一定**带 `valid: false`  
- 业务层用户缺失时会返回 `valid: false` + `message`  
- 对接方应以 **HTTP 状态码** 为主：非 200 一律视为校验未通过

---

## 6. 客户端伪代码

```text
function verifyAccessToken(accessToken):
  resp = HTTP GET {api_base}/auth/verify_token
         Header Authorization: Bearer {accessToken}
  if resp.status != 200:
    treat as invalid / force re-login
    return null
  body = resp.json
  if body.valid != true:
    treat as invalid
    return null
  return body   # 使用 user_id / user_type / status 等
```

---

## 7. 注意

1. **只校验 access token**；不要把 refresh token、业务临时码当本接口入参。  
2. **不要缓存「永久有效」**：token 可过期或被注销，敏感操作应再次调用或短 TTL 缓存。  
3. 本接口**不写**用户最近活动，可被下游频繁调用，但仍建议合理限流。  
4. `token_kind` 为 `permanent` / `platform_api_key` / `task_session` 时语义与普通用户 JWT 不同；若你们只接受用户登录态，请限制 `token_kind === "access"`。  
5. 基址使用调用方已有的 `{api_base}` 配置，勿写死环境域名。
