"""独立入口：mock MCP SSE 上游（与 tests/integration/mock_mcp_sse.py 同一应用）。

用法（Inspector 联调，见 scripts/inspector_m3.md）：
    .venv/Scripts/python.exe scripts/mock_mcp_sse_server.py          # 监听 127.0.0.1:9902
    .venv/Scripts/python.exe scripts/mock_mcp_sse_server.py --port 9903   # 自定义端口
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # 仓库根（使 tests 包可导入）

import uvicorn  # noqa: E402

from tests.integration.mock_mcp_sse import build_mcp_sse_app  # noqa: E402


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="mock MCP SSE 上游（Inspector 联调用）")
    parser.add_argument("--port", type=int, default=9902,
                        help="监听端口（默认 9902）")
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    uvicorn.run(build_mcp_sse_app(), host="127.0.0.1", port=args.port,
                log_level="info", access_log=False)
