# M4 MCP Inspector 联调（Streamable HTTP 传输）——人工验收清单

对照设计 §16 M4 验收行：Inspector 以 **Streamable HTTP** 传输经代理完成
initialize / tools/list / tools/call。协议级自动化等价覆盖见
`tests/integration/test_proxy_mcp_streamable.py`。

## 0. 前置

> 以下命令均在 Git Bash 下执行（路径为 Windows 的 `.venv/Scripts/` 形态）。

- venv 已建且依赖已装：

  ```bash
  D:/Python312/python.exe -m venv .venv
  .venv/Scripts/python.exe -m pip install -e ".[dev]" -i https://pypi.tuna.tsinghua.edu.cn/simple
  ```

- 本机 MySQL(3306) / Redis(6379) / Node(npx) 可用

项目根 `.env`（不存在则从以下最小集创建；测试/演示用，生产勿抄）：

```bash
EXTERNAL_BASE=http://127.0.0.1:8800
MYSQL_DSN=mysql+aiomysql://root:123456@127.0.0.1:3306/agent_proxy
REDIS_URL=redis://127.0.0.1:6379/1
SSRF_ALLOW_PRIVATE=true
TRACE_MODE=metadata              # 排障时临时改 body
```

首次运行需建库（MySQL 已有实例，仅建库不动表结构，表由应用 lifespan create_all）：

```bash
mysql -h127.0.0.1 -uroot -p123456 -e "CREATE DATABASE IF NOT EXISTS agent_proxy DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
```

## 1. 启动三个进程

终端 1——代理：

```bash
.venv/Scripts/python.exe -m agent_proxy     # 默认 0.0.0.0:8800（可用 AGENT_PROXY_LISTEN 收敛）
```

终端 2——mock MCP Streamable 上游：

```bash
.venv/Scripts/python.exe scripts/mock_mcp_streamable_server.py    # 监听 127.0.0.1:9903
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

## 3. 注册 mcp 映射（Streamable 上游）

```bash
curl -s -X POST http://127.0.0.1:8800/api/v1/mappings \
  -H "Authorization: Bearer <TOKEN>" -H "Content-Type: application/json" \
  -d '{"type":"mcp","upstream_url":"http://127.0.0.1:9903/mcp","headers":{"Authorization":"Bearer sk-demo-123456"}}'
```

响应 `proxy_url` 应为 `http://127.0.0.1:8800/p/<mapping_id>/mcp`；记 `<mapping_id>`。

（可选）保存前先调 test 接口验证（M4 探测式 auto：先 Streamable initialize）：

```bash
curl -s -X POST http://127.0.0.1:8800/api/v1/mappings/<mapping_id>/test \
  -H "Authorization: Bearer <TOKEN>"
# 预期 {"ok": true, "status_code": 200, ..., "detail": "Streamable initialize 成功（serverInfo.name=mock-mcp-streamable）"}
```

## 4. Inspector 连接（Streamable HTTP 传输）

1. 打开 Inspector UI（默认 http://localhost:6274），左侧连接配置：
   - Transport Type：`Streamable HTTP`
   - URL：`http://127.0.0.1:8800/p/<mapping_id>/mcp`
   - Authentication → Custom Header：名称 `Authorization`，值 `Bearer <TOKEN>`
2. 点击 **Connect**。

预期：连接成功。内部发生了什么——Inspector 向代理 POST initialize（JSON-RPC），
代理按上游 origin 根还原转发到 `http://127.0.0.1:9903/mcp`；上游返回
application/json + `Mcp-Session-Id: sess-m4`，代理把会话头透传回 Inspector；
后续 tools/list / tools/call 携带同一会话头原样透传（载荷零改写，§8.4）。

## 5. 人工验收清单（对照 §16 M4 行）

> **状态：待人工执行勾选**（M4 人工验收痕迹；勾选完成后在此标注验收日期与执行人）。

- [ ] **tools/list**：Tools 标签列出 1 个工具 `echo`（description「回显输入文本」）
- [ ] **tools/call**：运行 `echo`，参数 `{"text":"hello-m4"}` → 结果文本包含 `hello-m4`
- [ ] **（可选）test 接口**：第 3 步的 test 调用返回 ok=true 且 detail 含
      `Streamable initialize 成功`
- [ ] **（可选）Disconnect**：断开后代理无异常堆积，`logs/agent-proxy.log` 可见
      相关连接关闭记录（Inspector 会话结束 DELETE /mcp 的 204 经代理透传；
      mock 独立入口关闭 access log，如需观察上游访问可临时改
      `scripts/mock_mcp_streamable_server.py` 的 `access_log=True`）

## 6. trace 观察（可选，排障向）

`.env` 改 `TRACE_MODE=body` 并重启代理后重复第 4-5 步，`logs/trace.log.*` 同
request_id 下应能看到：

- `phase=request`（POST，`url=http://127.0.0.1:9903/mcp`，Authorization 为指纹，
  body 为 initialize JSON-RPC 全文）
- `phase=response`（status=200，body 含 serverInfo）
- 同一会话的 tools/list / tools/call 各有一对 request/response 行，`Mcp-Session-Id`
  头名在列（值非敏感，body 模式显原值）

## 7. 常见问题

| 现象 | 原因与处理 |
|---|---|
| Connect 后 401 | Custom Header 未配置或拼写错误（stub token 不验签、不过期） |
| Connect 后 400 | mock 会话头校验：Inspector 初始化丢失 Mcp-Session-Id（检查代理未改写响应头；直连 9903 对照） |
| 注册 400（内网/SSRF 拒绝） | `.env` 未设 `SSRF_ALLOW_PRIVATE=true` |
| 9903 被占用 | 结束遗留的 mock 进程（终端 2 Ctrl+C）后重启；强杀可 `netstat -ano \| findstr :9903` 查 PID 后 `taskkill //PID <pid> //F`（Git Bash 下双斜杠） |
| Inspector UI 字段对不上 | 以当前版本 UI 为准，关键字段为 Transport Type=Streamable HTTP、URL、Custom Header |
