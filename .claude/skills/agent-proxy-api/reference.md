# agent-proxy 接口详细参考（非 admin）

配合 [SKILL.md](SKILL.md) 使用；本文是字段级细节与完整示例。
`<BASE>` = 部署地址（本机默认 `http://127.0.0.1:8800`）。

## 1. 注册 / 管理：`/api/v1/mappings`

### POST /api/v1/mappings（注册）→ 201

```bash
curl -X POST <BASE>/api/v1/mappings \
  -H "Authorization: Bearer 888" -H "Content-Type: application/json" \
  -d '{"type":"mcp","name":"demo","upstream_url":"http://host.docker.internal:9902/sse",
       "headers":{"X-Credential":"real-secret"},"test_request":{"method":"GET","path":"/","expect_status":200}}'
```

请求体（Pydantic 校验，非法 → 400 INVALID_PARAM）：

| 字段 | 类型 | 说明 |
|---|---|---|
| `type` | `"http"` \| `"mcp"` | 必填；决定代理分发管线 |
| `upstream_url` | str ≤2048 | 必填；需通过 SSRF 校验（私网地址默认拒绝，dev `SSRF_ALLOW_PRIVATE=true` 放行） |
| `name` | str ≤128 | 可选展示名 |
| `visibility` | `"private"`(默认) \| `"public"` | public 仅 admin（403） |
| `auth_mode` | `"static"`(默认) \| `"oauth"` | oauth：按用户注入本人 access_token（M6 托管） |
| `headers` | dict[str,str] ≤32 项 | **存储注入头**（真实值）；值 ≤4096；落库 Fernet 加密 |
| `test_request` | `{method,path,expect_status?}` | 可选；method 限白名单动词；多余键注册即拒 |

响应 `RegisteredOut`：`{mapping_id(12位), name, type, visibility, auth_mode, proxy_url,
headers: {"Authorization":"{{RUNTIME_TOKEN}}"}, status}`——headers 即**代理
调用配置**（头名跟随 `PROXY_AUTH_HEADER`；结构=名称+地址+headers；平台把
`{{RUNTIME_TOKEN}}` 运行时替换为用户 token），proxy_url = `<BASE>/p/{id}`
（mcp 型追加上游端点路径，如 `/p/{id}/sse`）。

### GET /api/v1/mappings?page=1&page_size=20 → 列表

`[{mapping_id,name,type,upstream_url,proxy_url,status,created_at,updated_at}]`——**不含 headers**。仅返回本人映射。

### GET /api/v1/mappings/resolve → 详情（原始 MCP/HTTP 配置）

两种寻址**二选一**（同传/均缺 → 400 INVALID_PARAM）：
- `?proxy_url=<值>`：12 位 mapping_id、完整代理地址（host 必须等于本服务 EXTERNAL_BASE）、URL 编码形态；
- `?name=<映射名>`（设计 v3）：按名称取**本人**映射（重名取最新创建；admin 跨属主请走 id 形态）。

用途：用户拿 mcp-name + 代理身份凭据取回原始配置（name、真实 url、真实 header），
用户端页面据代理地址/名称反查展示。返回 `MappingDetailOut` =
RegisteredOut 全字段 + `upstream_url` + **真实 headers 明文** + `test_request` + 时间戳。
（审计动作 `view_credentials`；非 owner → 404 MAPPING_NOT_FOUND 隐藏存在性。）

### GET/PUT/DELETE /api/v1/mappings/{id}

- GET 详情：同 resolve 返回。
- PUT 局部更新：body 为 MappingCreate 字段的子集 + `status:"active"|"disabled"`；
  未触及 `headers` 时照常更新；**触及 headers 且存储密文不可解** → 409 CREDENTIAL_CORRUPT。
- DELETE → 204（级联清理 OAuth client/credential 行与缓存）。
- 三者均 owner 或 admin；非 owner 一律 404。

### POST /api/v1/mappings/{id}/test → `{ok, status_code, latency_ms, detail}`

配置有效性探测：http 型按 `test_request`（无则 HEAD 根路径；严格模式缺 expect_status 一律判失败）；
mcp 型探测式 auto——先 Streamable initialize 硬判定，405/404/406 回落 SSE 握手。
非 2xx → ok=false，detail 带上游状态。

## 2. 内置公共映射（public）：`/api/v1/builtin-mappings`

面向「系统级共享映射 + 用户 OAuth 自助绑定」。非 public 的 id 一律 404（隐藏存在性）。

| 端点 | 语义 |
|---|---|
| `GET /api/v1/builtin-mappings` | public 列表：`{mapping_id,name,type,proxy_url,headers(代理调用配置，头名跟随 PROXY_AUTH_HEADER),auth_mode,binding,status}`（设计 v3：不再解密存储头）；binding 仅 oauth 型有值（static=null） |
| `PUT /{id}/client` | **仅 admin** 手动配置 OAuth 客户端 `{client_id,client_secret?,token_auth:"client_secret_basic"|"client_secret_post"|"none",authorize_url,token_url,scopes?}`；upsert；secret 加密落库、永不回显 |
| `GET /{id}/client` | **仅 admin** 查看（`client_secret_configured` 布尔） |
| `POST /{id}/authorize` | body `{"front_redirect":"https://页面/回调"}`（域须在 CORS 白名单）→ `{authorization_url}`；**引导用户浏览器打开**，AS 回调代理 `/oauth/callback/{id}` 后 302 回 `front_redirect?binding=success|failed&reason=...` |
| `GET /{id}/binding` | `{binding:"unbound"|"authorizing"|"bound"|"invalid", expires_at?, scope?}`（授权后页面轮询） |
| `DELETE /{id}/binding` | 204 解绑；提供方支持时 best-effort revoke |
| `POST /{id}/test` | admin=测静态配置（不注入）；普通用户须 `auth_mode=oauth` 且已绑定，以本人凭证实测（static → 400 OAUTH_NOT_APPLICABLE；未绑定 → 401 OAUTH_BINDING_REQUIRED） |

oauth 型映射代理调用时按用户注入 `Authorization: Bearer <本人 access_token>`（forced 最高优先，压过调用方自带 Authorization），
过期前 60s 自动刷新（并发安全）；无绑定 → 401 OAUTH_BINDING_REQUIRED。
`GET /oauth/callback/{mapping_id}` 是浏览器回调端点（无 JWT，state 关联）——不要手工调用。

## 3. 代理转发：`/p/{mapping_id}[/{path}]`

管线：Bearer 鉴权 → 映射加载（密文解密 fail-closed）→ 可见性（private 仅 owner 403；
public 任意有效身份）→ disabled → 404 → oauth 凭证注入 → 按 type 分发。

### 分发语义（type=mcp）

| 调用 | 命中管线 | 行为 |
|---|---|---|
| GET/HEAD 且路径 == 注册端点路径（upstream_url 的 path，空则 `/`） | SSE | 长连接透传；`event: endpoint` 的 data 改写为 `/p/{id}<path>?<query>`（相对路径）；其余行字节级透传（含心跳注释） |
| 其余方法/路径 | HTTP | 目标 = 上游 origin 根 + 子路径（`build_origin_target`）；JSON-RPC POST / DELETE 会话 / GET 推送流都走此行 |

type=http：`/p/{id}/{path}` → `upstream_url + /{path}`（前缀拼接，query 原样）。
同源重定向代理内部跟随（每跳有上限，超限 502 TOO_MANY_REDIRECTS）。

### 出站/入站 header 规则（安全核心，设计 v2/v3）

- 出站 = 存储 `upstream_headers` 全量（真实值，小写归一）∪ **调用方 header 全量透传**
  （同名调用方覆盖存储——skill 教传的 `Authorization` 等上游头原样直达）；
  oauth 型映射注入的本人凭证 forced 最高优先，压过调用方同名头。
- 保留命名空间（来源无关，绝不透传）：`x-proxy-authorization`（代理身份，已消费）、
  `cookie`（防平台会话 `ap_sess` 泄漏）、`host`（由转发目标派生，防 vhost 路由破坏）；
  hop-by-hop（connection/keep-alive/te/trailer/transfer-encoding/upgrade/proxy-*）双向剥离。
- 响应头剥 hop-by-hop 后原样回传，绝不含存储真实 header。

### 完整示例：SSE 型 initialize + tools/list（python 标准库）

```python
import json, threading, http.client
from urllib.parse import urlparse

BASE = "http://127.0.0.1:8800"; TOKEN = "888"; MAPPING = "aqTNLiJXlCaN"
SSE_PATH = f"/p/{MAPPING}/sse"    # ← 必须是注册响应里的 proxy_url 的路径部分（含端点路径）；
u = urlparse(BASE)                #    GET /p/{id} 根路径走原始透传管线，endpoint 事件不会被改写
hdrs = {"Authorization": f"Bearer {TOKEN}", "Accept": "text/event-stream"}
endpoint, results = None, {}

def reader():                      # 1) SSE 长连接线程：endpoint 事件 + message 结果
    global endpoint
    c = http.client.HTTPConnection(u.hostname, u.port, timeout=120)
    c.request("GET", SSE_PATH, headers=hdrs)
    r = c.getresponse(); assert r.status == 200
    event = None
    for raw in r:                  # 按行迭代（SSE 以空行结束事件块）
        line = raw.decode().rstrip("\r\n")
        if line.startswith("event:"): event = line[6:].strip()
        elif line.startswith("data:") and event == "endpoint":
            endpoint = line[5:].strip()          # 相对路径 /p/{id}/messages?session_id=...
        elif line.startswith("data:") and event == "message":
            d = json.loads(line[5:].strip())
            if isinstance(d, dict) and "id" in d: results[d["id"]] = d

threading.Thread(target=reader, daemon=True).start()
while endpoint is None: pass       # 等首个 endpoint 事件

def rpc(payload):                  # 2) JSON-RPC POST 到消息端点 → 202 空体，结果走 SSE
    path = endpoint if endpoint.startswith("/") else "/" + endpoint
    c = http.client.HTTPConnection(u.hostname, u.port, timeout=30)
    c.request("POST", path, json.dumps(payload),
              {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"})
    r = c.getresponse(); r.read(); assert r.status == 202, r.status

rpc({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
     "protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"demo","version":"0"}}})
while 1 not in results: pass
rpc({"jsonrpc":"2.0","method":"notifications/initialized"})
rpc({"jsonrpc":"2.0","id":2,"method":"tools/list"})
while 2 not in results: pass
print([t["name"] for t in results[2]["result"]["tools"]])
```

Streamable 型等价操作（curl 可完成）：

```bash
# initialize：响应头取 mcp-session-id（如 sess-m4）
curl -sS -D - -X POST <BASE>/p/<id>/mcp \
  -H "Authorization: Bearer 888" -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"demo","version":"0"}}}'
# 后续请求带 -H "mcp-session-id: sess-m4"；结束会话：
curl -X DELETE <BASE>/p/<id>/mcp -H "Authorization: Bearer 888" -H "mcp-session-id: sess-m4"
```

## 4. 错误码表（统一 body `{"code","message","request_id"}`）

| status | code | 场景 |
|---|---|---|
| 400 | INVALID_PARAM | 参数/URL/header 校验失败（含 SSRF 拒绝） |
| 400 | OAUTH_NOT_APPLICABLE | static 映射上做 OAuth 语义操作 |
| 400 | OAUTH_STATE_INVALID | state 过期/重放/伪造/跨映射 |
| 401 | INVALID_TOKEN | 无 Bearer 或校验失败（Bearer 失败不回退 Cookie） |
| 401 | OAUTH_BINDING_REQUIRED | oauth 映射该用户未绑定（引导 authorize） |
| 403 | FORBIDDEN | 非 admin 做 admin 操作；非 owner 调 private 映射 |
| 404 | MAPPING_NOT_FOUND | 不存在/已禁用/非 owner/非 public（隐藏存在性） |
| 404 | OAUTH_CLIENT_NOT_CONFIGURED | admin 查 client 但未配置 |
| 409 | CREDENTIAL_CORRUPT | PUT 触及 headers 但存储密文不可解 |
| 413 | BODY_TOO_LARGE | 代理请求体超限 |
| 500 | INTERNAL_ERROR | 服务端异常（含密文解密系统级失败 fail-closed） |
| 502 | UPSTREAM_ERROR / TOO_MANY_REDIRECTS / OAUTH_CLIENT_SETUP_FAILED | 上游失败/重定向超限/DCR·discovery 失败 |
| 503 | PROXY_BUSY | 代理并发满 |
| 504 | UPSTREAM_TIMEOUT | 上游超时 |

## 5. dev / 生产差异

| 项 | dev（本机） | 生产 |
|---|---|---|
| 认证 | stub（`TOKEN_VERIFY_IMPL=stub`）：`Authorization: Bearer 纯数字`=user_id；信封 token 自带 role | `TOKEN_VERIFY_IMPL=third_party`：调 `{VERIFY_API_BASE}/auth/verify_token` 验签（默认 beta 基址，生产切 `https://app.9m-tec.com/ai-service`）；身份以响应 `user_id` 为准，`user_type=admin` 命中 admin 判定；5xx → 503 AUTH_SERVICE_UNAVAILABLE |
| 认证头名 | 本机部署设 `PROXY_AUTH_HEADER=X-Proxy-Authorization`（v2 分离模式，skill 流程兼容） | 默认 `Authorization`（统一 token：既鉴权又透传上游） |
| 私网上游 | `SSRF_ALLOW_PRIVATE=true` 放行（host.docker.internal 可用） | 默认 false——私网 upstream_url 注册即 400 |
| EXTERNAL_BASE | `http://127.0.0.1:8800` | 真实域名（proxy_url/重写都基于它） |
| admin | 信封 token `{"user_id":1,"role":"admin"}`（不验签） | 统一登录角色（`user_type`） |

部署/环境变量全集见仓库 `docs/DEPLOYMENT.md`；设计语义见
`docs/superpowers/specs/2026-11-21-agent-proxy-design.md` §6/§8/§14；
验签接口契约见 `docs/auth_verify_token_integration.md`。
