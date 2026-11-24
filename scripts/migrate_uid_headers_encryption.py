"""开发库一次性迁移（收尾批次，2026-11-25）：user_id 整数化 + upstream_headers 强制加密。

对应 M7 计划「收尾批次」（docs/superpowers/plans/2026-11-24-m7-admin-pages-observability.md）：

1. proxy_mapping.owner_uid / proxy_oauth_credential.uid  VARCHAR(64) → BIGINT
   （先改型后归一：**存在非数字 uid 行时默认中止并列出行明细**——误指向真实库会把
   多用户映射所有权折叠合并进同一 uid，构成 private 越权面；确认为测试数据后需
   显式 `--collapse-non-numeric` 才执行「剥非数字字符归一（'u888'→'888'，剥空落
   '0'）」，之后 MODIFY 列型，索引保留）
2. proxy_mapping.upstream_headers  JSON → TEXT，并把既有明文 JSON 行逐行
   Fernet(MASTER_KEY) 加密回写（复用 oauth.credential.encrypt_text，SHA256 派生）；
   已是密文（gAAAA 前缀）的行跳过 → 脚本可重复执行（幂等）
3. 迁移结束 SCAN+DEL `ap:mapping:*`（评审 Important 2）：迁移前 Redis 缓存是旧明文
   dict 形态，迁移后读取路径 fail-closed（plain_headers 非密文串守卫 → 404）且
   TTL 内不自愈——统一清掉，服务重启/下一请求回源按新 schema 回填密文形态。
   `ap:cred:*`（uid 整数化后旧键不可达）TTL 60s 自然过期，无需处理。
   注意：脚本运行期间若服务仍在写入，可能在清理后回填旧形态——建议停服窗口内执行
   （先停服务 → 跑本脚本 → 起服务）。
4. 测试库 agent_proxy_test 不走本脚本：tests/integration/conftest.py 会话开始时
   drop 三业务表，由 app lifespan create_all 按现行 models 重建

用法：.venv/Scripts/python.exe scripts/migrate_uid_headers_encryption.py
      [--db agent_proxy] [--collapse-non-numeric]
MASTER_KEY / REDIS_URL 从 .env 读取（与运行时同源）；默认库 agent_proxy。
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

import pymysql

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

HOST, PORT, USER, PASSWORD = "127.0.0.1", 3306, "root", "123456"  # 部署/生产复用前改为参数或环境变量注入（勿硬编码凭据）


def read_env_key(repo_root: Path, key: str) -> str:
    """与 config.load_dotenv_file 同规则读 .env 的指定键（运行时同源）。"""
    env_path = repo_root / ".env"
    if not env_path.exists():
        raise SystemExit(f"缺少 .env（{key} 必填）")
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith(f"{key}="):
            value = line.partition("=")[2].strip()
            value = re.sub(r"\s+#.*$", "", value).strip('"').strip("'")
            if value:
                return value
    raise SystemExit(f".env 缺少 {key}")


def column_type(cur, db: str, table: str, column: str) -> str | None:
    cur.execute(
        "SELECT data_type FROM information_schema.columns "
        "WHERE table_schema=%s AND table_name=%s AND column_name=%s",
        (db, table, column))
    row = cur.fetchone()
    return row[0] if row else None


def migrate_uid_column(cur, db: str, table: str, column: str,
                       collapse: bool, detail_columns: str) -> None:
    """VARCHAR → BIGINT；**非数字 uid 行默认中止并列明细**（防误指向真实库时把
    多用户所有权静默折叠进同一 uid → private 越权面），显式 --collapse-non-numeric
    才归一（剥非数字字符，剥空落 '0'）。幂等：已是 bigint 跳过。"""
    if column_type(cur, db, table, column) == "bigint":
        print(f"[skip] {db}.{table}.{column} 已为 BIGINT")
        return
    cur.execute(f"SELECT COUNT(*), SUM({column} NOT REGEXP '^[0-9]+$') FROM {db}.{table}")
    total, non_numeric = cur.fetchone()
    if non_numeric:
        cur.execute(f"SELECT {detail_columns}, {column} FROM {db}.{table} "
                    f"WHERE {column} NOT REGEXP '^[0-9]+$' LIMIT 50")
        bad_rows = cur.fetchall()
        print(f"[guard] {db}.{table}.{column} 存在 {non_numeric}/{total} 行非数字 uid：")
        for bad in bad_rows:
            print("   ", bad)
        if not collapse:
            raise SystemExit(
                "已中止：非数字 uid 会把多用户映射所有权折叠进同一 uid（private 越权面）。"
                "确认全部为测试数据后加 --collapse-non-numeric 重跑，或先人工核对这些行。")
        cur.execute(
            f"UPDATE {db}.{table} SET {column} = "
            f"COALESCE(NULLIF(REGEXP_REPLACE({column}, '[^0-9]', ''), ''), '0') "
            f"WHERE {column} NOT REGEXP '^[0-9]+$'")
        print(f"[data] {db}.{table}.{column} 显式折叠归一化 {non_numeric}/{total} 行")
    cur.execute(f"ALTER TABLE {db}.{table} MODIFY {column} BIGINT NOT NULL")
    print(f"[alter] {db}.{table}.{column} VARCHAR(64) → BIGINT（索引保留）")


def encrypt_headers_rows(cur, db: str, master_key: str) -> None:
    """JSON → TEXT 改型 + 既有明文行 Fernet 加密回写（幂等：gAAAA 前缀跳过）。"""
    from agent_proxy.oauth.credential import encrypt_text

    if column_type(cur, db, "proxy_mapping", "upstream_headers") == "json":
        cur.execute("ALTER TABLE proxy_mapping MODIFY upstream_headers TEXT NOT NULL")
        print("[alter] proxy_mapping.upstream_headers JSON → TEXT")
    else:
        print("[skip] proxy_mapping.upstream_headers 非 JSON（已迁移？）")
    cur.execute("SELECT id, mapping_id, upstream_headers FROM proxy_mapping")
    rows = cur.fetchall()
    encrypted = 0
    for row_id, mapping_id, value in rows:
        if value is None or value.startswith("gAAAA"):
            continue  # 已是密文（重复执行）或空行
        plain = json.dumps(json.loads(value), ensure_ascii=False)  # 先验 JSON 合法
        cur.execute("UPDATE proxy_mapping SET upstream_headers=%s WHERE id=%s",
                    (encrypt_text(plain, master_key), row_id))
        encrypted += 1
    print(f"[data] proxy_mapping.upstream_headers 加密回写 {encrypted}/{len(rows)} 行")


def flush_mapping_cache(redis_url: str) -> None:
    """SCAN+DEL ap:mapping:*（评审 Important 2）：迁移前缓存为旧明文 dict 形态，
    迁移后读取路径 fail-closed（404）且 TTL 内不自愈——统一清掉，回源按新 schema
    回填密文形态。redis_url 为 redis://[:pwd@]host:port/db 形态（.env 同源）。"""
    import redis as redis_sync

    parsed = urlparse(redis_url)
    client = redis_sync.Redis(
        host=parsed.hostname or "127.0.0.1", port=parsed.port or 6379,
        db=int((parsed.path or "/0").lstrip("/") or 0),
        password=parsed.password, socket_timeout=5)
    removed = 0
    try:
        for key in client.scan_iter(match="ap:mapping:*", count=200):
            client.delete(key)
            removed += 1
    except Exception as exc:
        print(f"[redis][WARN] ap:mapping:* 清理失败（{type(exc).__name__}）：请在服务"
              f"重启前手工清理，否则存量键 TTL（CACHE_TTL≤300s）内该批映射 404")
        return
    print(f"[redis] ap:mapping:* 清理 {removed} 键")


def main() -> None:
    repo_root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default="agent_proxy", help="目标库（默认开发库 agent_proxy）")
    parser.add_argument("--collapse-non-numeric", action="store_true",
                        help="显式允许把非数字 uid 折叠归一（仅确认全为测试数据时使用；"
                             "默认中止并列出行明细）")
    args = parser.parse_args()
    master_key = read_env_key(repo_root, "MASTER_KEY")
    redis_url = read_env_key(repo_root, "REDIS_URL")

    conn = pymysql.connect(host=HOST, user=USER, password=PASSWORD, port=PORT, database=args.db)
    try:
        with conn.cursor() as cur:
            migrate_uid_column(cur, args.db, "proxy_mapping", "owner_uid",
                               args.collapse_non_numeric, "id, mapping_id")
            migrate_uid_column(cur, args.db, "proxy_oauth_credential", "uid",
                               args.collapse_non_numeric, "id, mapping_id")
            encrypt_headers_rows(cur, args.db, master_key)
        conn.commit()
        with conn.cursor() as cur:
            for table, column in (("proxy_mapping", "owner_uid"),
                                  ("proxy_oauth_credential", "uid"),
                                  ("proxy_mapping", "upstream_headers")):
                cur.execute(f"SHOW COLUMNS FROM {table} LIKE '{column}'")
                print("verify:", table + "." + column, cur.fetchone())
            cur.execute("SELECT mapping_id, owner_uid, LEFT(upstream_headers, 12), "
                        "LENGTH(upstream_headers) FROM proxy_mapping")
            for row in cur.fetchall():
                print("row:", row)
    finally:
        conn.close()
    flush_mapping_cache(redis_url)
    print("MIGRATION DONE:", args.db)


if __name__ == "__main__":
    main()
