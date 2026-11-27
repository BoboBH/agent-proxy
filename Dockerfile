# agent-proxy 生产镜像（部署交付，详见 docs/DEPLOYMENT.md）。
# 服务形态：单容器直接运行 app/ 源码——不打包 wheel、不安装包本体；
# 依赖按 uv.lock --frozen 冻结复现（与本地 uv sync 同源同速，源已固化清华镜像）。
FROM python:3.12-slim

# PyPI 源可覆盖：docker build --build-arg PIP_INDEX_URL=... UV_DEFAULT_INDEX=... .
# ARG 仅构建期使用（pip 装 uv / uv 下载依赖兜底），不残留运行镜像
ARG PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple
ARG UV_DEFAULT_INDEX=https://pypi.tuna.tsinghua.edu.cn/simple
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    # 容器内日志直写文件（LOG_DIR=logs → /app/logs，挂卷持久化），无 stdout 缓冲问题
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# uv 经 pip 镜像安装（不依赖 ghcr）；依赖层独立于源码层缓存——改源码重建不重装依赖。
# only-system：用镜像自带 CPython，禁止 uv 另行下载解释器（来源在 GitHub，国内不稳）
RUN pip install --no-cache-dir --index-url "${PIP_INDEX_URL}" uv
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-cache \
        --default-index "${UV_DEFAULT_INDEX}" \
        --python-preference only-system

# 服务源码（uvicorn 从 WORKDIR 直导 app 包；admin/*.html 模板随源码目录就位）
COPY app/ ./app/

# 非 root 运行；logs 目录属主提前建好（具名卷首挂时继承该属主）
RUN useradd --create-home --shell /usr/sbin/nologin appuser \
    && mkdir -p /app/logs \
    && chown -R appuser:appuser /app
USER appuser

# uv sync 产出的项目虚拟环境（依赖在此），uvicorn 由其解析
ENV VIRTUAL_ENV=/app/.venv \
    PATH="/app/.venv/bin:$PATH"

EXPOSE 8800

# slim 无 curl/wget：用自带 python 探活 /healthz（失败/非 200 均 urllib 抛错非零退出）
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["python", "-c", "import sys,urllib.request; r=urllib.request.urlopen('http://127.0.0.1:8800/healthz', timeout=4); sys.exit(0 if r.status == 200 else 1)"]

# .env 不进镜像（见 .dockerignore）：compose 经 env_file 注入环境变量，
# Settings（pydantic-settings）直接读进程环境变量；容器内监听恒 0.0.0.0:8800，
# 优雅停机排空 10s 与 compose stop_grace_period=15s 配套（留 5s 余量）
ENTRYPOINT ["uvicorn", "app.main:app"]
