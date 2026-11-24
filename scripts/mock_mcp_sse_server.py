"""独立入口：mock MCP SSE 上游（与 tests/integration/mock_mcp_sse.py 同一应用）。

用法（Inspector 联调，见 scripts/inspector_m3.md）：
    .venv/Scripts/python.exe scripts/mock_mcp_sse_server.py     # 监听 127.0.0.1:9902
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # 仓库根（使 tests 包可导入）

import uvicorn  # noqa: E402

from tests.integration.mock_mcp_sse import build_mcp_sse_app  # noqa: E402

if __name__ == "__main__":
    uvicorn.run(build_mcp_sse_app(), host="127.0.0.1", port=9902,
                log_level="warning", access_log=False)
