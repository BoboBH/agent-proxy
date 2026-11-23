"""入口：python -m agent_proxy（读取 .env 后启动 uvicorn）。"""
from __future__ import annotations

import logging
import sys

import uvicorn

from .config import ConfigError, Settings, load_dotenv_file
from .main import create_app


def _parse_listen(listen: str) -> tuple[str, int]:
    host, _, port = listen.rpartition(":")
    if not host or not port.isdigit():
        raise ConfigError(f"非法 AGENT_PROXY_LISTEN: {listen!r}（应为 host:port）")
    return host, int(port)


def main() -> None:
    load_dotenv_file(".env")
    try:
        settings = Settings.from_env()
        host, port = _parse_listen(settings.listen)
    except ConfigError as exc:
        print(f"配置错误: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
    app = create_app(settings)
    # log_config=None 关闭 uvicorn 默认日志配置，启动/绑定信息随之丢失；
    # uvicorn.error 还会继承 root 的 WARNING 级别过滤掉 INFO 消息，
    # 因此需显式设 INFO 并挂控制台 handler（agent_proxy 自身日志走文件）。
    console = logging.StreamHandler()
    console.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    uvicorn_error = logging.getLogger("uvicorn.error")
    uvicorn_error.setLevel(logging.INFO)
    uvicorn_error.propagate = False
    uvicorn_error.addHandler(console)
    uvicorn.run(
        app,
        host=host,
        port=port,
        log_config=None,
        timeout_graceful_shutdown=settings.shutdown_drain_seconds,
    )


if __name__ == "__main__":
    main()
