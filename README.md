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

## 接口速览

| 方法 | 路径 | 说明 |
|---|---|---|
| POST/GET/PUT/DELETE | /api/v1/mappings[/{id}] | 映射 CRUD（JWT） |
| POST | /api/v1/mappings/{id}/test | 配置有效性测试：http 连通 / test_request 严格验证；mcp 探测式 auto（先 Streamable initialize，拒绝 POST 回落 SSE 握手） |
| GET | /api/v1/mappings/resolve?proxy_url= | 按代理地址回显真实配置 |
| ANY | /p/{mapping_id}/{path} | 代理转发：http 前缀流式转发（M2）；mcp SSE 传输 + endpoint 事件改写（M3）；mcp Streamable HTTP（M4，POST/GET/DELETE 透传 + 会话头双向透传） |
| GET | /healthz /readyz /metrics | 运维端点 |
