# agent-proxy 项目规则

## 部署规则（用户指令 2026-11-24，长期有效）

- **Docker 部署必须使用宿主机（本机）Redis 与 MySQL，禁止在 compose 中自建 redis/mysql 服务**。
- compose 只部署 agent-proxy 单容器；存储连接走 `host.docker.internal`（compose `environment` 覆盖 `MYSQL_DSN` / `REDIS_URL`，`extra_hosts` 已配 host-gateway）。
- `.env` 保留 `127.0.0.1` 供本地 venv 直跑（`python -m agent_proxy`），与 compose 覆盖值共存不冲突。
- 依据：本机已有 MySQL 8.4 / Redis（避免数据分散与双实例运维）；`.dockerignore` 已排除 `.env`（MASTER_KEY 不进镜像）。
- 若未来确需形态 A（容器内自建存储），须用户当时明确同意后再改 compose。

## 其他

- 测试/开发环境：stub 认证——`X-Proxy-Authorization: Bearer <纯数字>` 的数字即 user_id（设计 v2：`Authorization` 已让位上游语义，调用方可透传）；企业 token 校验接口文档后续提供（`third_party` 保持抽象，勿提前实现）。
- 测试运行：`.venv/Scripts/python.exe -m pytest`；真实 TCP 用端口 9901-9910，勿与其他进程并发跑测试。
- **临时测试数据（用户指令 2026-11-25）**：临时测试跑的数据统一放项目 `temp/` 目录下，目录不存在时可直接创建；该目录**不要加入 .gitignore**。
