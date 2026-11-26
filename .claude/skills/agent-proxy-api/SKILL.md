---
name: agent-proxy-api
description: Use when calling or integrating with agent-proxy（MCP/HTTP 出站代理）——注册/查询/测试映射、经 /p/ 代理调用上游 HTTP 或 MCP 服务（SSE/Streamable 传输）、处理代理的 401/403/404/502/504，或为 Agent 平台接入代理地址与占位符 headers
---

# agent-proxy API（非 admin 接口）

## Overview

agent-proxy 是 Agent 平台的出站代理：**真实上游地址与凭据只存代理侧**，调用方只持
`Bearer` 身份 + 代理地址。两类消费面：管理 REST（`/api/v1/...`）与代理转发（`/p/{mapping_id}`）。
本机部署 base_url 默认 `http://127.0.0.1:8800`（下文 `<BASE>`）。
字段表/错误码/完整示例见同目录 [reference.md](reference.md)。

## 鉴权（先读）

- 身份通道头名**可配置**（`PROXY_AUTH_HEADER`，默认 **`Authorization`**）：
  `Authorization: Bearer <token>`。**凭证校验失败必 401，不回退**。
- 默认 `Authorization` 下该头**身兼两职**：代理鉴权 + （映射未配同名头时）原样透传
  上游——统一 token 场景：skill 教传的 `Authorization: Token xxx`（或平台 token）
  即可直通。`TOKEN_VERIFY_IMPL=third_party` 时验签接口原生支持 `Bearer`/`Token`
  两种 scheme；dev/stub 只认 `Bearer <纯数字>` 与信封票据。
- 若部署把 `PROXY_AUTH_HEADER` 配成其他名字（如 `X-Proxy-Authorization`）：
  该头变纯代理私有（鉴权后**绝不透传**），`Authorization` 恢复普通透传头（v2 分离模式）。
- dev/stub 部署：**纯数字 token 即 user_id**（`Authorization: Bearer 888` → user_id=888）。
- 需要 admin（建 public 映射、配置 OAuth 客户端）时用信封 token（仅 stub，不验签）：
  `x.<base64url(JSON)>.y`，JSON 至少 `{"user_id":1,"role":"admin"}`。
- 错误统一形状：`{"code","message","request_id"}`，响应头带 `X-Request-ID`。

## 端点快查

| 路径 | 方法 | 语义 | 权限 |
|---|---|---|---|
| `/healthz` `/readyz` | GET | 存活 / 依赖就绪 | 无 |
| `/metrics` | GET | Prometheus 文本 | 无 |
| `/api/v1/mappings` | POST | 注册映射 → 201（body 见下） | 登录 |
| `/api/v1/mappings` | GET | 我的映射列表（无真实 headers） | 登录 |
| `/api/v1/mappings/resolve?proxy_url=<12位id或完整代理地址>` 或 `?name=<映射名>` | GET | 按 id/代理地址/**名称**取回**原始配置**（真实 upstream_url/headers，重名取最新，限本人） | owner/admin |
| `/api/v1/mappings/{id}` | GET/PUT/DELETE | 详情 / 局部更新 / 删除(204) | owner/admin |
| `/api/v1/mappings/{id}/test` | POST | 配置有效性探测 → `{ok,status_code,latency_ms,detail}` | owner/admin |
| `/api/v1/builtin-mappings` | GET | public 映射列表 + 我的 OAuth 绑定状态 | 登录 |
| `/api/v1/builtin-mappings/{id}/authorize` | POST | 发起 OAuth 授权（浏览器流程起跳） | 登录 |
| `/api/v1/builtin-mappings/{id}/binding` | GET/DELETE | 绑定状态 / 解绑(204) | 登录 |
| `/api/v1/builtin-mappings/{id}/test` | POST | admin 测静态；普通用户以本人凭证测 | 见注 |
| `/p/{mapping_id}[/{path}]` | ANY | **代理转发**（HTTP/MCP 统一入口） | private:owner；public:登录 |

注册 body：`{"type":"http"|"mcp","upstream_url":"...","name"?,"visibility"?,"auth_mode"?,"headers":{...},"test_request"?}`
→ 201 返回 `{mapping_id, name, proxy_url, headers:{"Authorization":"{{RUNTIME_TOKEN}}"}, status}`
——**headers 即代理调用配置**（头名跟随 `PROXY_AUTH_HEADER`，结构=名称+地址+headers，
与输入一致）：平台把 `{{RUNTIME_TOKEN}}` 运行时替换为用户 token 后，agent 用这份
配置直访代理；真实地址/凭据由代理保管，仅 resolve/详情可查。

## 经代理调用（核心）

出站 header 合并优先级：**oauth 托管注入 > 存储 headers（映射配置，权威凭据）>
调用方 headers（未配置的头原样透传）**。
- 映射配了某 header → 存储值**替换**调用方同名头（托管语义）；
- 映射没配 → 调用方的头原样透传（agent-email「直接使用 token」场景）；
- 恒不透传：`Cookie`（防平台会话泄漏）、`Host`（按转发目标派生）、hop-by-hop；
  认证头在默认 `Authorization` 下可透传（统一 token），配置为其他名字则纯代理私有。
注册/列表响应的 `headers` 字段（`{{RUNTIME_TOKEN}}` 形态）就是**该映射的调用配置**
——照抄使用，不要手写上游真实头，也**不要**把占位符原样发到代理（须先由平台替换）。

**HTTP 型**：`proxy_url`（不含端点路径）后拼子路径，方法/查询串原样：
`curl <BASE>/p/<id>/api/v1/users -H "Authorization: Bearer 888" -d '...'`

**MCP SSE 型**（proxy_url 已含注册端点路径，如 `/p/<id>/sse`）：
1. `GET` proxy_url，带 `Accept: text/event-stream` → 200 SSE 长连接，**保持不断开**；
2. 首个 `event: endpoint` 的 `data:` 是**相对路径**（`/p/<id>/messages?...`）——拼 `<BASE>` 后作为消息端点；
3. JSON-RPC（initialize / notifications/initialized / tools/list / tools/call）POST 到该端点 → **一律 202 空体**，结果经 SSE 流的 `event: message` 下发（按 JSON-RPC id 关联）。

**MCP Streamable 型**（proxy_url 已含 `/mcp` 类端点路径）：
`POST` JSON-RPC 直达 proxy_url，带 `Accept: application/json, text/event-stream` → 同步 200（JSON 或 SSE）；
从 initialize 响应头取 `mcp-session-id`，后续请求**必须带回**；`DELETE` proxy_url 结束会话。

## 常见错误

| 症状 | 真相 |
|---|---|
| SSE 模式 POST 返回 202 空体 | 正常——结果在 SSE 流的 message 事件里，别等 POST 响应体 |
| 拿 endpoint 的 data 直接当完整 URL | 它是**相对路径**，要拼 base_url |
| SSE 型 GET `/p/{id}` 根路径 | 必须 GET **proxy_url 全路径**（含端点路径，如 `/p/{id}/sse`）——根路径走原始透传管线，endpoint 事件**不被改写**，拿到的是上游私有地址 |
| 注册时 upstream_url 用 127.0.0.1 | 容器内不可达宿主机——用 `host.docker.internal`（生产默认禁私网地址，`SSRF_ALLOW_PRIVATE=true` 才放行） |
| 建 public 映射 403 FORBIDDEN | 仅 admin；stub 下要用信封 token 带 `role:"admin"` |
| 调/查别人映射 403 / 404 | private 映射非 owner：调用 403、详情/resolve 404；404 也可能=已禁用（隐藏存在性） |
| 502 UPSTREAM_ERROR / 504 UPSTREAM_TIMEOUT / 503 PROXY_BUSY | 上游失败/超时/代理并发满；413 BODY_TOO_LARGE 请求体超限 |
| 401 OAUTH_BINDING_REQUIRED（oauth 映射） | 该用户未完成 OAuth 绑定——走 builtin authorize 浏览器流程 |
| 探测代理路径（猜 /openapi.json /docs） | 没有；接口就是本表，别浪费请求 |
