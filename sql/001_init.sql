-- ============================================================================
-- agent-proxy 数据库初始化脚本（全量 schema）
-- 文件编号：001          适用版本：当前 main（app/models.py 同源）
-- 执行方式：由 DBA 审核后在目标 MySQL 8.0+ 实例执行
--   mysql -h<host> -u<user> -p < sql/001_init.sql
-- 幂等性：建库 IF NOT EXISTS；建表为裸 CREATE（已存在即报错中止——防止误执行到
--   旧库/错库，属预期防护）。应用首启 lifespan 亦有幂等建表（create_all
--   checkfirst），表已存在时跳过，与本脚本不冲突；生产建议 DBA 先执行本脚本。
-- 字符集：库 utf8mb4 / utf8mb4_unicode_ci；表与 create_all 产物一致
--   （utf8mb4 / utf8mb4_0900_ai_ci）。
-- 语义说明（DBA 审核要点）：
--   * access_token / refresh_token / client_secret / upstream_headers 均为
--     Fernet(MASTER_KEY) 密文列（base64 膨胀 4/3，VARCHAR 定长覆盖明文 ~3KB
--     JWT；超长写入显式 1406 报错，应用层按 fail-closed 处理，不静默截断）；
--   * upstream_headers 是唯一 TEXT 列（整个 JSON 变长），其余密文列定长 VARCHAR；
--   * updated_at 无 ON UPDATE 子句——更新时间由应用 SQLAlchemy onupdate 维护；
--   * user_id / owner_uid 为 BIGINT（内部系统用户 ID 整数化，同型整条传递链）。
-- ============================================================================

CREATE DATABASE IF NOT EXISTS agent_proxy
  DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE agent_proxy;

-- ----------------------------------------------------------------------------
-- proxy_mapping：映射注册表（Agent 经 /p/{mapping_id} 代理调用的配置本体）
-- ----------------------------------------------------------------------------
CREATE TABLE `proxy_mapping` (
  `id`               BIGINT       NOT NULL AUTO_INCREMENT,
  `mapping_id`       VARCHAR(16)  NOT NULL,
  `owner_uid`        BIGINT       NOT NULL,
  `name`             VARCHAR(128) NULL,
  `type`             ENUM('http','mcp') NOT NULL,
  `visibility`       ENUM('private','public') NOT NULL,
  `auth_mode`        ENUM('static','oauth') NOT NULL,
  `upstream_url`     VARCHAR(2048) NOT NULL,
  `upstream_headers` TEXT         NOT NULL,
  `test_request`     JSON         NULL,
  `status`           ENUM('active','disabled') NOT NULL,
  `created_at`       DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`       DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `ix_proxy_mapping_mapping_id` (`mapping_id`),
  KEY `ix_proxy_mapping_owner_uid` (`owner_uid`),
  KEY `ix_proxy_mapping_visibility` (`visibility`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ----------------------------------------------------------------------------
-- proxy_oauth_client：内置映射的 OAuth 客户端配置（manual 手动 / dcr 动态注册）
-- ----------------------------------------------------------------------------
CREATE TABLE `proxy_oauth_client` (
  `id`            BIGINT        NOT NULL AUTO_INCREMENT,
  `mapping_id`    VARCHAR(16)   NOT NULL,
  `client_id`     VARCHAR(256)  NOT NULL,
  `client_secret` VARCHAR(512)  NULL,
  `token_auth`    ENUM('client_secret_basic','client_secret_post','none') NOT NULL,
  `authorize_url` VARCHAR(2048) NULL,
  `token_url`     VARCHAR(2048) NULL,
  `scopes`        VARCHAR(512)  NULL,
  `source`        ENUM('dcr','manual') NOT NULL,
  `created_at`    DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`    DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `ix_proxy_oauth_client_mapping_id` (`mapping_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ----------------------------------------------------------------------------
-- proxy_oauth_credential：按（mapping, user）托管的 OAuth 凭证（强制密文落库）
-- ----------------------------------------------------------------------------
CREATE TABLE `proxy_oauth_credential` (
  `id`           BIGINT       NOT NULL AUTO_INCREMENT,
  `mapping_id`   VARCHAR(16)  NOT NULL,
  `user_id`      BIGINT       NOT NULL,
  `access_token` VARCHAR(4096) NOT NULL,
  `refresh_token` VARCHAR(2000) NULL,
  `expires_at`   DATETIME     NULL,
  `scope`        VARCHAR(512) NULL,
  `status`       ENUM('active','invalid') NOT NULL,
  `created_at`   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_mapping_user_id` (`mapping_id`, `user_id`),
  KEY `ix_proxy_oauth_credential_user_id` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
