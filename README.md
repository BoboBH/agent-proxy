# agent-proxy

Agent 平台对外 MCP / HTTP 出站代理：真实地址与凭据只存代理侧，Agent 仅持有代理地址与占位符 header。

- 设计文档：`docs/superpowers/specs/2026-11-21-agent-proxy-design.md`
- 实施计划：`docs/superpowers/plans/`

## 快速开始

````bash
D:/Python312/python.exe -m venv .venv
.venv/Scripts/python.exe -m pip install -e ".[dev]" -i https://pypi.tuna.tsinghua.edu.cn/simple
cp .env.example .env   # 按环境修改
.venv/Scripts/python.exe -m agent_proxy  # 读取 .env 启动
````

## 测试

````bash
.venv/Scripts/python.exe -m pytest -v   # 需本地 MySQL(root/123456) 与 Redis(6379)
````

## MCP Inspector 联调（M3）

见 `scripts/inspector_m3.md`：以 SSE 传输经代理连接 mock MCP 上游，完成
tools/list 与 tools/call 的人工验收步骤（协议级自动化覆盖见
`tests/integration/test_proxy_mcp_sse.py`）。

## MCP Inspector 联调（M4：Streamable HTTP）

见 `scripts/inspector_m4.md`：以 Streamable HTTP 传输经代理连接 mock MCP 上游
（`scripts/mock_mcp_streamable_server.py`，9903），完成 tools/list 与 tools/call
的人工验收步骤（协议级自动化覆盖见 `tests/integration/test_proxy_mcp_streamable.py`）。

## OAuth 凭证托管（M6）联调

见 `scripts/mock_oauth_as_server.py`（mock OAuth2 AS+RS，9904；preset 手动客户端
`manual-cl`/`manual-cs-123456`；`POST /_test/reset` 重置）。浏览器走全流程：

1. 管理员建公共映射：`POST /api/v1/mappings`（`visibility=public`、`auth_mode=oauth`，
   `.env` 需 `SSRF_ALLOW_PRIVATE=true`）；
2. 手动模式配 client：`PUT /api/v1/builtin-mappings/{id}/client`（authorize/token URL
   指向 9904），或留空走 DCR（上游须提供 well-known + registration_endpoint）；
3. `POST /api/v1/builtin-mappings/{id}/authorize`（`front_redirect` 须在
   `CORS_ALLOWED_ORIGINS` 白名单）→ 浏览器打开返回的 `authorization_url` 同意 →
   回调 302 回 `front_redirect?binding=success`；
4. `GET /api/v1/builtin-mappings/{id}/binding` 确认 `bound` 后，以任意绑定用户 JWT
   调 `/p/{id}/...`——代理按用户注入其 `Authorization: Bearer <本人 token>`（oauth 托管凭证，压过调用方自带同名头）。

## 管理页面（M7）

浏览器打开 `http://127.0.0.1:8800/admin`（未登录自动 302 到登录页）。`LOGIN_IMPL=stub`
为本地假登录：填写整数用户 ID（如 `888`；内部系统 user_id 为整数）、需要管理员视图把
角色选为 `admin`，提交即换取服务端会话（Redis `ap:sess:{sid}`，TTL `ADMIN_SESSION_TTL`，
Cookie `ap_sess` 属性 HttpOnly+SameSite=Lax；`EXTERNAL_BASE` 为 https 的部署必须置
`SESSION_COOKIE_SECURE=true`）。

- 我的映射：注册（响应含代理地址与占位符 header，「保存到 Agent」）/ resolve 回显编辑 /
  test / 删除；
- 内置 MCP：列表（auth_mode、我的绑定状态）/ OAuth 授权绑定跳转 / 解绑 / test /
  保存到 Agent；
- 公共映射管理（仅 `role=admin`）：visibility=public 映射 CRUD + test + OAuth client
  手动配置；
- 退出登录：删除服务端会话（Cookie 中的 sid 随即失效）。

页面 API 全部走既有 `/api/v1` 接口（同源 fetch 携带 Cookie，`get_current_identity`
双通道：Bearer 优先——Agent/API 场景不变，无 Bearer 回退 Cookie 会话）；权限与 API
完全一致，页面不做越权捷径。

## 接口速览

| 方法 | 路径 | 说明 |
|---|---|---|
| POST/GET/PUT/DELETE | /api/v1/mappings[/{id}] | 映射 CRUD（JWT） |
| POST | /api/v1/mappings/{id}/test | 配置有效性测试：http 连通 / test_request 严格验证；mcp 探测式 auto（先 Streamable initialize，拒绝 POST 回落 SSE 握手） |
| GET | /api/v1/mappings/resolve?proxy_url= | 按代理地址回显真实配置 |
| GET | /api/v1/builtin-mappings | 内置（公共）映射列表：name/type/proxy_url/占位符 headers/auth_mode + 我的绑定状态（M6） |
| PUT/GET | /api/v1/builtin-mappings/{id}/client | OAuth 客户端手动配置 / 查看（仅 admin，secret 脱敏）（M6） |
| POST | /api/v1/builtin-mappings/{id}/authorize | 发起 OAuth 授权绑定：front_redirect 域白名单 → authorization_url（M6） |
| GET | /oauth/callback/{mapping_id} | OAuth 回调（无 JWT，一次性 state 关联；code 换 token 强制加密落库）（M6） |
| GET/DELETE | /api/v1/builtin-mappings/{id}/binding | 我的绑定状态查询 / 解绑（dcr 客户端 best-effort revoke）（M6） |
| POST | /api/v1/builtin-mappings/{id}/test | 公共映射测试：admin 测静态配置；已绑定用户测本人 OAuth 凭证（失效提示重新授权）（M6） |
| GET | /admin | 管理页面入口：未携带会话 302 → LoginProvider.login_url（stub=本地登录页）（M7） |
| GET/POST | /admin/login · /admin/auth/callback · /admin/logout | stub 登录页 / 回跳建会话（Set-Cookie ap_sess，HttpOnly+SameSite=Lax）/ 退出删除会话（M7） |
| ANY | /p/{mapping_id}/{path} | 代理转发：http 前缀流式转发（M2）；mcp SSE 传输 + endpoint 事件改写（M3）；mcp Streamable HTTP（M4，POST/GET/DELETE 透传 + 会话头双向透传）；OAuth 公共映射按用户注入本人凭证（M6） |
| GET | /healthz /readyz /metrics | 运维端点 |

## Prometheus 指标（/metrics，§15.2）

`ap_requests_total{route,type,status}` · `ap_request_duration_seconds{route,type}` ·
`ap_upstream_duration_seconds{type}` · `ap_upstream_errors_total{type,code}` ·
`ap_bytes_total{direction}` · `ap_sse_active_connections` · `ap_inflight_requests` ·
`ap_oauth_actions_total{action}`。标签仅低基数维度（不含 user_id/mapping_id），
按映射/用户排查走审计日志 + request_id 关联。
