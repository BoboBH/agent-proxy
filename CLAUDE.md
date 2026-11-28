# agent-proxy 项目规则

## Skill 约定（用户指令 2026-11-28）

- 平台接口的封装**一律做成 skill**（`.claude/skills/`，随仓库入库），供 agent 安装后自验与调用；
- skill 内容更新后**必须同步双份**：仓库 `.claude/skills/` + 本机用户级 `C:/Users/bobo/.claude/skills/`；
- 接口行为变更（新增端点/参数/鉴权变化）时，**对应 skill 文档必须同步更新**（与代码同一提交）。

## Git 操作规则（用户指令 2026-11-27）

- **不要自动 commit 和 push**——仅在用户于对话中明确要求时执行；
- 代码/文档改动完成后默认保留在工作区，由用户决定何时提交。

## 部署规则（用户指令 2026-11-24，长期有效）

- **Docker 部署必须使用宿主机（本机）Redis 与 MySQL，禁止在 compose 中自建 redis/mysql 服务**。
- compose 只部署 agent-proxy 单容器；存储连接走 `host.docker.internal`（compose `environment` 覆盖 `MYSQL_DSN` / `REDIS_URL`，`extra_hosts` 已配 host-gateway）。
- `.env` 保留 `127.0.0.1` 供本地 venv 直跑（`.venv/Scripts/python.exe -m uvicorn app.main:app --host 0.0.0.0 --port 8800`），与 compose 覆盖值共存不冲突。
- 依据：本机已有 MySQL 8.4 / Redis（避免数据分散与双实例运维）；`.dockerignore` 已排除 `.env`（MASTER_KEY 不进镜像）。
- 若未来确需形态 A（容器内自建存储），须用户当时明确同意后再改 compose。

## 其他

- 测试/开发环境（**已切统一 token 模式，2026-11-27**）：`TOKEN_VERIFY_IMPL=third_party` + `VERIFY_API_BASE=https://app.9m-tec.com/ai-service`（生产验签）；认证头默认 `Authorization`（统一 token：验签+透传上游一头搞定），可用 `PROXY_AUTH_HEADER` 配置切换；调用方凭据即真实登录 token（prd 签发，24h），过期 401 后换新。契约见 docs/auth_verify_token_integration.md。
- 测试运行：`.venv/Scripts/python.exe -m pytest`；真实 TCP 用端口 9901-9910，勿与其他进程并发跑测试。
- **临时测试数据（用户指令 2026-11-27，反转 11-25 规则）**：临时测试跑的数据统一放项目 `temp/` 目录下，目录不存在时可直接创建；**`temp/` 已从 git 排除（.gitignore），不入库**——脚本/报告类可复用产物视需要单独确认后再提交。
