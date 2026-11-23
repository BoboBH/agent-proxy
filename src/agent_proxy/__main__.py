"""入口：python -m agent_proxy（读取 .env 后启动 uvicorn）。"""
from __future__ import annotations

import uvicorn

from .config import Settings, load_dotenv_file
from .main import create_app


def main() -> None:
    load_dotenv_file(".env")
    settings = Settings.from_env()
    host, _, port = settings.listen.rpartition(":")
    app = create_app(settings)
    uvicorn.run(app, host=host or "0.0.0.0", port=int(port or 8800), log_config=None)


if __name__ == "__main__":
    main()
