# agent-proxy 生产镜像（部署交付，详见 docs/DEPLOYMENT.md）。
# 单阶段构建：pip 直接安装本包（src 布局 + pyproject package-data，admin/*.html
# 模板随 wheel 分发——缺模板运行期 TemplateNotFound，见 M7 债务 11）。
FROM python:3.12-slim

# PyPI 源可覆盖：docker build --build-arg PIP_INDEX_URL=https://pypi.org/simple .
ARG PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple
ENV PIP_INDEX_URL=${PIP_INDEX_URL} \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    # 容器内日志直写文件（LOG_DIR=logs → /app/logs，挂卷持久化），无 stdout 缓冲问题
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# 源码 + 打包声明（pip install . 按 setuptools src 布局装出 agent_proxy 包）
COPY pyproject.toml ./
COPY src/ ./src/

# 依赖全为纯 wheel（无编译需求，slim 够用）；装完清理缓存
RUN pip install --no-cache-dir .

# 非 root 运行；logs 目录属主提前建好（具名卷首挂时继承该属主）
RUN useradd --create-home --shell /usr/sbin/nologin appuser \
    && mkdir -p /app/logs \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 8800

# slim 无 curl/wget：用自带 python 探活 /healthz（失败/非 200 均 urllib 抛错非零退出）
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["python", "-c", "import sys,urllib.request; r=urllib.request.urlopen('http://127.0.0.1:8800/healthz', timeout=4); sys.exit(0 if r.status == 200 else 1)"]

# .env 不打进镜像（见 .dockerignore）：compose 经 env_file 注入环境变量；
# python -m agent_proxy 启动时 load_dotenv_file(".env") 仅 setdefault，环境变量已在即不覆盖
ENTRYPOINT ["python", "-m", "agent_proxy"]
