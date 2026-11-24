"""独立入口：mock OAuth2 AS+RS（与 tests/integration/mock_oauth_as.py 同一应用）。

用法（M6/M7 联调，浏览器走 authorize → 同意 → 回调全流程）：
    .venv/Scripts/python.exe scripts/mock_oauth_as_server.py          # 监听 127.0.0.1:9904
    .venv/Scripts/python.exe scripts/mock_oauth_as_server.py --port 9914   # 自定义端口

注意：换端口（如 9914）时，mock_oauth_as.py 内的 BASE / _PRESET_REDIRECT_PREFIXES
与 well-known 元数据 URL 不随动——独立入口仅用于 9904 标准端口的浏览器联调；
端口改配属联调时手工改 mock 常量的场景。
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # 仓库根（使 tests 包可导入）

import uvicorn  # noqa: E402

from tests.integration.mock_oauth_as import build_oauth_as_app  # noqa: E402


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="mock OAuth2 AS+RS（OAuth 绑定联调用）")
    parser.add_argument("--port", type=int, default=9904, help="监听端口（默认 9904）")
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    uvicorn.run(build_oauth_as_app(), host="127.0.0.1", port=args.port,
                log_level="info", access_log=False)
