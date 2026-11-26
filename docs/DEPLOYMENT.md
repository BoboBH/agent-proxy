# agent-proxy 部署文档

> 适用版本：main 分支（M7 完成 + 收尾批次，pytest 480 基线）。
> 对应设计：`docs/superpowers/specs/2026-11-21-agent-proxy-design.md` §12.1（部署形态）。

## 1. 架构与组件

一句话：**FastAPI 单体应用（uvicorn，端口 8800）+ MySQL（映射/OAuth 凭证持久化）+ Redis（缓存 / 管理会话 / OAuth state / 刷新锁）**——Agent 与浏览器只触达 8800，真实上游地址与凭据只存代理侧。

| 组件 | 镜像 | 说明 |
|---|---|---|
| agent-proxy | `agent-proxy:latest`（`python:3.12-slim` 基础，源码构建） | 非 root（`appuser`）运行；`python -m agent_proxy`；`EXPOSE 8800`；HEALTHCHECK 探 `/healthz` |
| mysql | `mysql:8.4` | 库 `agent_proxy`（镜像入口 `MYSQL_DATABASE` 建库，应用首启建表）；utf8mb4；数据卷 `mysql-data` |
| redis | `redis:7-alpine` | db `1`；`--appendonly yes`（可选，见 compose 注释）；数据卷 `redis-data` |
| 日志卷 | `logs` → `/app/logs` | `agent-proxy.log` / `audit.log` / `trace.log` 三类滚动文件：按天 + 单文件 50MB 立即滚动、保留 7 天 |

端口：宿主机 `8800` → 容器 `8800`；MySQL/Redis 仅在 compose 内部网络（`mysql:3306`、`redis:6379`），默认不映射宿主机。

## 2. 前置要求与部署形态对照

| | 形态 A：本机一键栈（本交付默认） | 形态 B：复用外部 MySQL / Redis（生产推荐） |
|---|---|---|
| 前置软件 | Docker Desktop（含 compose v2） | 同左（或 Linux + Docker Engine）；可达的 MySQL 8.x / Redis 3.0+ |
| 启动方式 | `docker compose up -d --build`，三服务全启 | 删除 compose 中 mysql/redis 服务块（见 compose 文件头说明），`.env` 的 `MYSQL_DSN`/`REDIS_URL` 指向外部 |
| 适用场景 | 开发 / 演示 / 验收（Windows 本机注意：防火墙放行端口、主机睡眠即下线——不适合长期驻留） | 生产（设计 §12.1：同一份 compose 直接迁移；无外网服务器可本机 `docker save` → 拷贝 → `docker load`） |

磁盘需求约 2GB（镜像 + MySQL 初始化）；宿主机 8800 端口需空闲。

## 3. 形态 A：本地 Docker 一键部署

### 3.1 准备 `.env`

```bash
cp .env.example .env
```

逐项核对（**加粗为必改/必填**，其余默认即可）：

| 配置 | 必填/默认 | 说明 |
|---|---|---|
| **`MASTER_KEY`** | **必填，无默认** | 敏感字段（upstream_headers / OAuth 凭证 / client_secret）强制 Fernet 加密的密钥，缺失拒绝启动。高熵生成：`python -c "import secrets; print(secrets.token_urlsafe(48))"`（无本机 python 时：`docker run --rm python:3.12-slim python -c "..."`）。见 §8 Q4 的 `.env` 行内注释规则——urlsafe 字符集天然无 `#`，安全 |
| **`EXTERNAL_BASE`** | 默认 `http://127.0.0.1:8800` | 本机演示保持默认；局域网联调改 `http://<局域网IP>:8800`（proxy_url 拼接、OAuth redirect_uri、front_redirect 白名单都依赖它；改了它，冒烟命令里的地址也要同步） |
| `AGENT_PROXY_LISTEN` | 默认 `0.0.0.0:8800` | 保持默认：容器内监听地址恒为 `0.0.0.0:8800`（改宿主机端口走 compose ports 左侧映射） |
| `MYSQL_ROOT_PASSWORD` | 形态 A 默认 `123456` | 仅形态 A（compose 内置 MySQL）使用：root 密码，与 compose 的 mysql 服务及 DSN 同源插值；形态 B 不需要 |
| `MYSQL_DSN` / `REDIS_URL` | `.env.example` 默认值 | **形态 A 下不生效**：compose `environment` 将其覆盖为容器网络服务名（`mysql` / `redis`）；只有形态 B 才需要在 `.env` 改这两个值 |
| `ENV` | `dev` | `prod` 门禁：stub 校验/登录实现拒绝启动（生产见 §5） |
| `TOKEN_VERIFY_IMPL` / `LOGIN_IMPL` | `stub` | 当前唯一可用实现；`company_sso` / `third_party` 为 M8+ 债务 |
| `SESSION_COOKIE_SECURE` | `false` | **`EXTERNAL_BASE` 为 https 的部署必须置 `true`**（否则浏览器不回传 Cookie，管理页面不可用） |
| `SSRF_ALLOW_PRIVATE` | `false` | 仅联调环境放开内网上游；生产保持 `false` |
| `LOG_DIR` | `logs` | 保持默认（compose 卷挂 `/app/logs`；改值需同步改卷目标路径） |
| `CORS_ALLOWED_ORIGINS` | 空 | 页面为同源 fetch **不依赖 CORS**；仅跨域管理页 / 浏览器直连 `/api/v1` 才配白名单（逗号分隔，空=不开；`/p/*` 恒不开） |
| `TRACE_MODE` | `metadata` | `body` 仅排障期临时开启（含请求/响应体，注意落盘面） |
| 其余（超时/池上限/体上限/会话 TTL 等） | `.env.example` 默认 | 语义见设计 §12 配置表 |

### 3.2 启动

```bash
docker compose up -d --build     # 首次构建约 1–3 分钟（pip 源可用 --build-arg PIP_INDEX_URL 覆盖）
docker compose ps                # 三服务均 Up（healthy）
docker compose logs -f agent-proxy   # stdout 仅 uvicorn 行（见下）
docker compose exec agent-proxy tail -f /app/logs/agent-proxy.log   # 应用日志走文件（含建表与「agent-proxy 启动: …」行）
```

> 日志预期（勿误判）：应用 logger（`agent_proxy`）只挂**文件** handler（滚动日志，propagate=False），
> 容器 stdout 只有 uvicorn 行——`Application startup complete.` / `Uvicorn running on http://0.0.0.0:8800`；
> 「agent-proxy 启动: listen=…」等应用日志在 `/app/logs/agent-proxy.log`（经上面的 `tail -f` 查看），
> stdout 缺它**不是**启动失败。

首启自动建表：应用 lifespan 内 `create_all` 建三张业务表（`proxy_mapping` / `proxy_oauth_credential` / `proxy_oauth_client`），并自检 MySQL（`SELECT 1`）与 Redis（`ping`）连通，任一失败即 fail-fast 退出（见 §8 Q2）。

### 3.3 健康验证

```bash
curl -s http://127.0.0.1:8800/healthz    # {"status":"ok"}          进程面
curl -s http://127.0.0.1:8800/readyz     # {"status":"ready"}       依赖面（MySQL+Redis）
curl -s http://127.0.0.1:8800/metrics | grep -E "^ap_" | head   # §15.2 八项指标族
```

`/readyz` 依赖不可用时返回 503 `{"status":"unavailable","error":...}`。

### 3.4 最小冒烟（注册 → 详情 → resolve → 删除）

stub 令牌格式与测试同源：`stub.<base64url(JSON)>.sig`，`user_id` 为**整数**（收尾批次整数化）：

```bash
TOKEN=$(python -c "import base64,json; print('stub.'+base64.urlsafe_b64encode(json.dumps({'user_id':888,'user_name':'冒烟','role':'admin'}).encode()).decode().rstrip('=')+'.sig')")
BASE=http://127.0.0.1:8800

# 1) 注册（upstream 用公网地址——SSRF_ALLOW_PRIVATE=false 拒内网；响应含代理地址与占位符 header）
curl -s -X POST $BASE/api/v1/mappings -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"type":"http","upstream_url":"https://example.com/","name":"smoke","headers":{"Authorization":"Bearer sk-real-key"}}'
# → 201 {"mapping_id":"...","proxy_url":"http://127.0.0.1:8800/p/...","headers":{"X-Proxy-Authorization":"{{RUNTIME_TOKEN}}"},...}

# 2) 详情（真实 header 仅详情/resolve 对 owner/admin 可见）
curl -s $BASE/api/v1/mappings/<mapping_id> -H "Authorization: Bearer $TOKEN"

# 3) resolve（proxy_url 需 URL 编码；host 必须等于 EXTERNAL_BASE 的 host）
curl -s "$BASE/api/v1/mappings/resolve?proxy_url=<urlencode 的 proxy_url>" -H "Authorization: Bearer $TOKEN"

# 4) 删除（204；Agent 侧代理地址随即 404）
curl -s -o /dev/null -w "%{http_code}\n" -X DELETE $BASE/api/v1/mappings/<mapping_id> -H "Authorization: Bearer $TOKEN"
```

浏览器页面冒烟：打开 `http://127.0.0.1:8800/admin` → 未登录 302 到登录页 → stub 登录（用户 ID `888`，需要管理员视图选角色 `admin`）→ 我的映射注册/编辑/删除 + 公共映射管理入口（admin 角色）→ 退出登录。

MCP Inspector 人工联调（可选）：`scripts/inspector_m3.md`（SSE 传输）与 `scripts/inspector_m4.md`（Streamable HTTP）——注意 mock 上游（9902/9903）需在**宿主机**跑（容器栈只含代理本身），并临时置 `SSRF_ALLOW_PRIVATE=true` 后 `docker compose up -d --build` 重建。

### 3.5 停止与清理

```bash
docker compose down        # 停止并删容器，保留卷（mysql-data / redis-data / logs）——推荐
docker compose down -v     # 连数据卷一并删除：MySQL 数据 / 会话 / 日志全丢，仅演示栈可再用
```

## 4. 形态 B：复用外部 MySQL / Redis（生产）

1. 编辑 `docker-compose.yml`：删去 `mysql` 与 `redis` 两个服务块、`agent-proxy.depends_on` 块，以及 `environment` 里的 `MYSQL_DSN` / `REDIS_URL` 两行（否则会覆盖 `.env` 值）；
2. `.env`：`MYSQL_DSN=mysql+aiomysql://<user>:<pass>@<host>:3306/agent_proxy`、`REDIS_URL=redis://<host>:6379/1`；
3. 外部 MySQL 需先建库（应用只建表不建库）：
   `CREATE DATABASE IF NOT EXISTS agent_proxy DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;`
4. `docker compose up -d --build` 后按 §3.3 验证。

外部 Redis 为 3.x 老版本同样可用（redis-py `<5` + MULTI 事务路径），见 §8 Q3。

## 5. 生产部署核对清单

- [ ] **`EXTERNAL_BASE` = 真实域名**（https）：proxy_url、OAuth `redirect_uri`（精确等于 `{EXTERNAL_BASE}/oauth/callback/{mapping_id}`）、front_redirect 白名单匹配全部依赖它；
- [ ] **`SESSION_COOKIE_SECURE=true`**：EXTERNAL_BASE 为 https 时必须，否则浏览器不回传 `ap_sess` Cookie、管理页面不可用；
- [ ] **`SSRF_ALLOW_PRIVATE=false`**：禁止注册内网上游；
- [ ] **`MASTER_KEY` 高熵且离线备份**：生成命令见 §3.1；**密钥丢失 = 全部密文不可解**（映射详情/转发 fail-closed 404、PUT 触及 headers 409 `CREDENTIAL_CORRUPT`、OAuth 凭证失效），密钥与数据库备份分开存储、均不进仓库/镜像；
- [ ] **`ENV=prod` 门禁已知悉**：prod 下 stub 校验/登录拒绝启动——当前唯一实现即 stub，**正式生产须先接入非 stub 实现**（`third_party` 校验 / `company_sso` 统一登录，M8+ 债务 1），否则无法以 prod 启动；
- [ ] **网关 TLS 终结**：应用侧为 http，TLS 在网关/ingress 终结后回源 8800；`/healthz` `/readyz` `/metrics` 设计定位「无鉴权、仅内网可达」——网关侧 ACL 隔离 `/metrics` 等端点（M7 债务 8）；
- [ ] **审计与 trace 日志卷**：`logs` 具名卷持久化（`audit.log` 审计 / `trace.log` 追踪 / `agent-proxy.log` 运行）；滚动策略按天+50MB、**保留 7 天**——合规要求更长留存需外置采集（sidecar/采集器转发）；`TRACE_MODE=metadata` 生产默认，`body` 仅排障临时开；
- [ ] **备份策略**：MySQL 卷定期 `mysqldump`（含 schema；建议停服窗口或 `--single-transaction`）；Redis 卷可选（缓存自动回源、会话重登自愈，非持久关键数据）；恢复演练至少一次；
- [ ] `CORS_ALLOWED_ORIGINS`：同源部署留空；确有跨域管理页再配精确 origin 白名单；
- [ ] 容量参数过需再调：`UPSTREAM_MAX_CONNECTIONS`（池上限，超限 503 `PROXY_BUSY`）、`MAX_BODY_SIZE`（413 截断阈值）、`ADMIN_SESSION_TTL`。

## 6. 数据库迁移说明

- **首启自动建表**：lifespan `create_all`——全新库直接启动即可，无手工 DDL；
- **升级迁移**：当前无自动迁移框架，schema 变更以**幂等脚本**为既定先例——`scripts/migrate_uid_headers_encryption.py`（收尾批次：uid 整数化 + upstream_headers 强制加密；精修批追加两步：`proxy_oauth_credential.uid` RENAME COLUMN → `user_id`（索引名 `ix_proxy_oauth_credential_uid`/`uk_mapping_uid` 同步 RENAME INDEX 改名）+ 加密列 TEXT → VARCHAR（access_token 4096 / refresh_token 2000 / client_secret 512，前置既有行超长校验——超限行列出并中止）；重复执行全 skip 幂等；执行前备份、建议停服窗口、结束时清理 Redis `ap:mapping:*` 旧形态缓存）。后续 schema 变更照此先例落 `scripts/` 下幂等脚本；
- **Alembic**：记债务（M8+），引入前以幂等脚本过渡；
- **容器栈下执行脚本**：该脚本常量面向宿主机 MySQL（`127.0.0.1:3306`，读 `.env` 的 `MASTER_KEY`/`REDIS_URL`）——形态 A 可临时放开 compose 中 mysql 的 `3306` 端口映射后在宿主机 venv 执行，或 `docker compose exec mysql` 直接执行 SQL。

## 7. 升级与回滚

- **升级**：`git pull` → （如该版本含迁移脚本，按 §6 先行）→ `docker compose up -d --build`。镜像重建，**数据卷不动**（MySQL/Redis/logs 全保留）；
- **升级窗口注记（精修批）**：state 载荷 JSON 键 `uid` → `user_id` 改名后，部署新版本前**已发起**的 OAuth 授权（state 存续 600s 内）回跳将被判 `400 OAUTH_STATE_INVALID` 属预期——重走 authorize 即可；迁移脚本与镜像升级建议同一停服窗口执行；
- **依赖钉版提示**：`pyproject.toml` 依赖为下界约束（`>=`）——镜像重建可能拉入新版本导致构建不可复现；建议后续以 pip-compile / uv lock 生成锁定文件固化依赖（记 M8+ 债务），锁定前升级后建议关注依赖变更；
- **回滚**：`git checkout <旧版本>` → `docker compose up -d --build`。数据卷同样保留；
- **注意**：若目标版本包含不可逆 schema 变更，回滚代码前先用备份还原数据库（`mysqldump` 还原）——幂等脚本不承诺反向迁移；损坏密文行设计为原状保留（fail-closed 404/409），不会无声销毁现场。

## 8. 常见问题（FAQ）

**Q1：端口占用？**
`8800`：宿主机被占时改 compose 映射左侧（如 `"9080:8800"`），`EXTERNAL_BASE` 同步带端口；容器内恒 8800。`9901–9910` 是 **pytest 测试端口簿**（echo 上游 9901 / SSE mock 9902 / Streamable mock 9903 / OAuth mock 9904 / 死端口 9909 / 被测代理 9910），部署栈不使用；仅在同一台机器同时跑测试套件时相关（测试需本机 MySQL/Redis），与容器栈的 mysql:3306（默认不映射宿主）不冲突——若放开了 mysql 的 3306 映射且宿主机自装了 MySQL，则会冲突，保持该映射注释关闭即可。

**Q2：agent-proxy 起不来 / 反复重启——MySQL 未就绪？**
应用 **fail-fast**：lifespan 依次建引擎 → `create_all` → `SELECT 1` → Redis `ping`，任一失败即启动退出（不降级运行）。compose 已用 `depends_on.condition: service_healthy` 等 MySQL/Redis 健康后才起 app；MySQL **首次初始化**（建库）需数十秒，healthcheck 的 `start_period`/`retries` 已兜底；`restart: unless-stopped` 下失败自动重试。排障：`docker compose logs agent-proxy`（配置错误打印「配置错误: …」并以 exit 1 退出，如缺 `MASTER_KEY` / DSN）。

**Q3：Redis 老版本兼容？**
客户端依赖钉死 `redis-py>=4.2,<5`；**服务端 Redis 3.0+ 即可用**——OAuth state 的一次性消费走 `MULTI` 事务（`GETDEL` 3.0 不存在，M6 已实测钉死），`SET NX EX` 刷新锁可用；会话/缓存仅用 GET/SET/DEL/TTL/SCAN。compose 的 `redis:7` 镜像无此顾虑，此兼容只为外部老实例保留。

**Q4：`.env` 行内注释解析规则？**
自研极简加载器（`config.load_dotenv_file`）：逐行 `KEY=VALUE`；`#` 开头整行为注释；值后**「空格 + #」起的内容按行内注释剥除**——`MASTER_KEY=abc # 注释` 会得到 `abc`，而 `MASTER_KEY=abc#def`（# 前无空格）值完整保留；值两端成对引号会被剥除；不识别 `export` 前缀；**不覆盖已存在的环境变量**（compose `env_file`/`environment` 注入的值优先）。建议 `MASTER_KEY` 用 urlsafe 生成（字符集无 `#`/空格，天然无歧义）。

**Q5：`ENCRYPT_AT_REST` 怎么配？**
**已废止**。收尾批次起 `upstream_headers` 与 OAuth 凭证/client_secret 一律强制 `Fernet(MASTER_KEY)` 密文落库（MySQL 与 Redis 缓存均密文形态），无可选开关；`.env` 中残留该键会被静默忽略（Settings 不读取）。`MASTER_KEY` 必填，缺失拒绝启动。

**Q6：`/healthz` 与 `/readyz` 用哪个做探活？**
`/healthz` 是进程面（恒 200），容器 HEALTHCHECK 与网关存活探测用它；`/readyz` 是依赖面（MySQL `SELECT 1` + Redis `ping`，失败 503），编排就绪判断/发布流水线用它。

**Q7：Windows 本机（Docker Desktop）局域网访问不通 / 服务时好时坏？**
Windows 防火墙需放行 8800 入站；`EXTERNAL_BASE` 用局域网 IP 而非 127.0.0.1；主机睡眠/休眠即容器栈停摆——本形态仅开发联调（设计 §12.1），长期驻留用 Linux 服务器（§2 形态 B）。
