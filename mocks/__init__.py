"""Mock 上游服务（MCP SSE / MCP Streamable / OAuth2 AS+RS）：集成测试与 Inspector
人工联调共用。

从 tests 包下沉为顶层包的原因：scripts 联调入口曾以 sys.path hack 导入
tests.integration.mock_*（「tests 当库用」反模式）——tests 只应被 pytest 收集，
共享的 mock 上游应是正式模块。

独立入口（仓库根目录执行，`python -m` 保证 mocks 可导入）：
    .venv/Scripts/python.exe -m mocks.mcp_sse          # 127.0.0.1:9902
    .venv/Scripts/python.exe -m mocks.mcp_streamable   # 127.0.0.1:9903
    .venv/Scripts/python.exe -m mocks.oauth_as         # 127.0.0.1:9904

服务不打包 wheel，本包亦不入镜像构建上下文（.dockerignore 已排除 mocks/）。
"""
