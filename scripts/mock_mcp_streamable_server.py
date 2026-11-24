"""独立入口：mock MCP Streamable 上游（与 tests/integration/mock_mcp_streamable.py 同一应用）。

用法（Inspector 联调，见 scripts/inspector_m4.md）：
    .venv/Scripts/python.exe scripts/mock_mcp_streamable_server.py          # 监听 127.0.0.1:9903
    .venv/Scripts/python.exe scripts/mock_mcp_streamable_server.py --port 9913   # 自定义端口
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # 仓库根（使 tests 包可导入）

import uvicorn  # noqa: E402

from tests.integration.mock_mcp_streamable import build_mcp_streamable_app  # noqa: E402


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="mock MCP Streamable 上游（Inspector 联调用）")
    parser.add_argument("--port", type=int, default=9903,
                        help="监听端口（默认 9903）")
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    uvicorn.run(build_mcp_streamable_app(), host="127.0.0.1", port=args.port,
                log_level="info", access_log=False)
