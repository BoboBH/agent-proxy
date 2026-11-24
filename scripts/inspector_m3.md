# MCP Inspector 联调（M3：SSE 传输经代理）

设计 §16 M3 验收硬要求：MCP Inspector 以 SSE 传输连接 agent-proxy，完成
tools/list 与 tools/call。本页为人工验收清单；协议级自动化验证已由
`tests/integration/test_proxy_mcp_sse.py`（裸 httpx SSE 客户端全链路）覆盖。

## 0. 前置

> 以下命令均在 Git Bash 下执行（路径为 Windows 的 `.venv/Scripts/` 形态）。

- venv 已建且依赖已装（`D:/Python312/python.exe -m venv .venv` + `pip install -e ".[dev]"`）
- 本机 MySQL(3306) / Redis(6379) 可用；Node/npx 可用
- MySQL 需已建库 `agent_proxy`（应用启动只建表不建库，全新 MySQL 直接启动会报
  Unknown database 1049）——先在 MySQL 执行：

  ```sql
  CREATE DATABASE IF NOT EXISTS agent_proxy DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
  ```

- 仓库根 `.env` 至少包含：

```
AGENT_PROXY_LISTEN=127.0.0.1:8800
EXTERNAL_BASE=http://127.0.0.1:8800
TOKEN_VERIFY_IMPL=stub
SSRF_ALLOW_PRIVATE=true          # 本机 mock 上游 127.0.0.1:9902 需放开内网校验
MYSQL_DSN=mysql+aiomysql://root:123456@127.0.0.1:3306/agent_proxy
REDIS_URL=redis://127.0.0.1:6379/1
TRACE_MODE=metadata              # 排障时临时改 body
```

## 1. 启动三个进程

终端 1——代理：

```bash
.venv/Scripts/python.exe -m agent_proxy     # 监听 127.0.0.1:8800
```

终端 2——mock MCP SSE 上游：

```bash
.venv/Scripts/python.exe scripts/mock_mcp_sse_server.py    # 监听 127.0.0.1:9902
```

终端 3——MCP Inspector：

```bash
npx @modelcontextprotocol/inspector
```

## 2. 生成 stub token（TOKEN_VERIFY_IMPL=stub 本地身份，不验签）

```bash
.venv/Scripts/python.exe -c "import base64,json; print('stub.'+base64.urlsafe_b64encode(json.dumps({'user_id':'u888','user_name':'inspector-demo'}).encode()).decode().rstrip('=')+'.sig')"
```

下文记为 `<TOKEN>`（Inspector 与注册接口共用）。

## 3. 注册 mcp 映射

```bash
curl -s -X POST http://127.0.0.1:8800/api/v1/mappings \
  -H "Authorization: Bearer <TOKEN>" -H "Content-Type: application/json" \
  -d '{"type":"mcp","upstream_url":"http://127.0.0.1:9902/sse","headers":{"Authorization":"Bearer sk-demo-123456"}}'
```

响应 `proxy_url` 应为 `http://127.0.0.1:8800/p/<mapping_id>/sse`；记 `<mapping_id>`。

## 4. Inspector 连接（SSE 传输）

1. 打开 Inspector UI（默认 http://localhost:6274），左侧连接配置：
   - Transport Type：`SSE`
   - URL：`http://127.0.0.1:8800/p/<mapping_id>/sse`
   - Authentication → Custom Header：名称 `Authorization`，值 `Bearer <TOKEN>`
2. 点击 **Connect**。

预期：连接成功。内部发生了什么——代理完成 SSE 握手并把上游 endpoint 事件
`data: /messages?session_id=test123` 改写为
`data: /p/<mapping_id>/messages?session_id=test123` 下发，Inspector 后续
JSON-RPC POST 自动回到代理（origin 根还原转发到上游）。

## 5. 人工验收清单（对照 §16 M3 行）

- [ ] **tools/list**：Tools 标签列出 1 个工具 `echo`（description「回显输入文本」）
- [ ] **tools/call**：运行 `echo`，参数 `{"text":"hello-m3"}` → 结果文本包含 `hello-m3`
- [ ] **（可选）Ping**：服务器 Ping 成功
- [ ] **（可选）Disconnect**：断开后代理无异常堆积，`logs/agent-proxy.log` 可见
      「SSE 连接关闭」记录

## 6. trace 观察（可选，排障向）

`.env` 改 `TRACE_MODE=body` 并重启代理后重复第 4-5 步，`logs/trace.log.*` 同
request_id 下应能看到：

- `phase=request`（GET，`url=http://127.0.0.1:9902/sse`，Authorization 为指纹）
- `phase=response`（status=200，连接建立）
- `phase=sse_event, event=endpoint`（改写前 `/messages?session_id=****(len=7)`）
- `phase=sse_event, event=endpoint_rewritten`（改写后 `/p/<mapping_id>/messages?...`）
- `phase=sse_event, event=message`（tools/list、tools/call 的 JSON-RPC 响应）
- 心跳注释行不出现

## 7. 常见问题

| 现象 | 原因与处理 |
|---|---|
| Connect 后 401 | Custom Header 未配置或拼写错误（stub token 不验签、不过期） |
| 注册 400（内网/SSRF 拒绝） | `.env` 未设 `SSRF_ALLOW_PRIVATE=true` |
| 9902 被占用 | 结束遗留进程：`netstat -ano \| findstr :9902` 查到 PID，`taskkill //PID <pid> //F`（Git Bash 下双斜杠，避免被路径转换）；或改用 `.venv/Scripts/python.exe scripts/mock_mcp_sse_server.py --port 9903` 启动（注册的 upstream_url 端口同步改） |
| Inspector UI 字段对不上 | 以当前版本 UI 为准，关键字段为 Transport Type=SSE、URL、Custom Header |
