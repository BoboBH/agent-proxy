"""开发库一次性迁移（收尾批次，2026-11-25）：user_id 整数化 + upstream_headers 强制加密。

对应 M7 计划「收尾批次」（docs/superpowers/plans/2026-11-24-m7-admin-pages-observability.md）：

1. proxy_mapping.owner_uid / proxy_oauth_credential.uid  VARCHAR(64) → BIGINT
   （非破坏：先把非数字字符剥除归一（'u888'→'888'，剥空落 '0'；两库均为测试数据），
   再 MODIFY 列型；索引保留）
2. proxy_mapping.upstream_headers  JSON → TEXT，并把既有明文 JSON 行逐行
   Fernet(MASTER_KEY) 加密回写（复用 oauth.credential.encrypt_text，SHA256 派生）；
   已是密文（gAAAA 前缀）的行跳过 → 脚本可重复执行（幂等）
3. 测试库 agent_proxy_test 不走本脚本：tests/integration/conftest.py 会话开始时
   drop 三业务表，由 app lifespan create_all 按现行 models 重建

用法：.venv/Scripts/python.exe scripts/migrate_uid_headers_encryption.py [--db agent_proxy]
MASTER_KEY 从 .env 读取（与运行时同源）；默认库 agent_proxy。
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import pymysql

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

HOST, PORT, USER, PASSWORD = "127.0.0.1", 3306, "root", "123456"


def read_master_key(repo_root: Path) -> str:
    """与 config.load_dotenv_file 同规则读 .env 的 MASTER_KEY（运行时同源）。"""
    env_path = repo_root / ".env"
    if not env_path.exists():
        raise SystemExit("缺少 .env（MASTER_KEY 必填）")
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith("MASTER_KEY="):
            value = line.partition("=")[2].strip()
            value = re.sub(r"\s+#.*$", "", value).strip('"').strip("'")
            if value:
                return value
    raise SystemExit(".env 缺少 MASTER_KEY")


def column_type(cur, db: str, table: str, column: str) -> str | None:
    cur.execute(
        "SELECT data_type FROM information_schema.columns "
        "WHERE table_schema=%s AND table_name=%s AND column_name=%s",
        (db, table, column))
    row = cur.fetchone()
    return row[0] if row else None


def migrate_uid_column(cur, db: str, table: str, column: str) -> None:
    """VARCHAR → BIGINT（先归一数字，再改型；幂等：已是 bigint 跳过）。"""
    if column_type(cur, db, table, column) == "bigint":
        print(f"[skip] {db}.{table}.{column} 已为 BIGINT")
        return
    cur.execute(f"SELECT COUNT(*), SUM({column} NOT REGEXP '^[0-9]+$') FROM {db}.{table}")
    total, non_numeric = cur.fetchone()
    if non_numeric:
        cur.execute(
            f"UPDATE {db}.{table} SET {column} = "
            f"COALESCE(NULLIF(REGEXP_REPLACE({column}, '[^0-9]', ''), ''), '0') "
            f"WHERE {column} NOT REGEXP '^[0-9]+$'")
        print(f"[data] {db}.{table}.{column} 归一数字化 {non_numeric}/{total} 行（测试数据）")
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


def main() -> None:
    repo_root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default="agent_proxy", help="目标库（默认开发库 agent_proxy）")
    args = parser.parse_args()
    master_key = read_master_key(repo_root)

    conn = pymysql.connect(host=HOST, user=USER, password=PASSWORD, port=PORT, database=args.db)
    try:
        with conn.cursor() as cur:
            migrate_uid_column(cur, args.db, "proxy_mapping", "owner_uid")
            migrate_uid_column(cur, args.db, "proxy_oauth_credential", "uid")
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
    print("MIGRATION DONE:", args.db)


if __name__ == "__main__":
    main()
