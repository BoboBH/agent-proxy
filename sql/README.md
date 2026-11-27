# sql/ — 数据库脚本管理（用户指令 2026-11-27）

本项目的数据库 schema **一律 SQL 脚本化管理**：变更脚本入库、走 code review、
**由 DBA 审核并执行**；应用代码不得在运行期做 schema 变更。

## 约定

1. **命名**：`NNN_描述.sql`，按编号顺序执行（如 `001_init.sql` 全量初始化、
   `002_xxx.sql` 为其后的增量变更）；
2. **不可变**：已执行的脚本不得修改——变更一律追加新编号文件，并在下方登记表补一行；
3. **执行**：DBA 审核后执行（`mysql -h<host> -u<user> -p < sql/NNN_xxx.sql`）；
   执行窗口、备份要求（变更前备份 / 停服窗口）由 DBA 按变更性质决定；
4. **与应用的关系**：应用首启 lifespan 有幂等建表（`create_all` checkfirst，仅建缺失表、
   绝不改既有表）——开发环境可零 SQL 直接启动；生产流程为 **DBA 先执行脚本**，
   应用随后的 create_all 因表已存在而全部跳过，两者不冲突、不漂移；
5. **一致性红线**：SQL 脚本必须与 `../app/core/models.py` 保持同构——改 models 必须同步出
   对应编号的变更脚本，反之亦然（模型为运行时事实源，脚本为 DBA 执行事实源）。

## 变更登记

| 编号 | 日期 | 内容 | 对应模型 |
|---|---|---|---|
| 001_init.sql | 2026-11-27 | 全量初始化：proxy_mapping / proxy_oauth_client / proxy_oauth_credential 三表 + 索引 | `../app/core/models.py` |

## 历史说明

`sql/` 体系建立前，开发库存量升级由临时 Python 幂等迁移脚本完成（2026-11-25：
uid 整数化 + upstream_headers 强制加密；精修批：uid→user_id 改名、加密列
TEXT→VARCHAR），已在开发库执行完毕；该脚本已删，仅存此记录——其后 schema
变更一律走本目录编号 SQL 脚本。
