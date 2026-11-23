"""审计日志行为验证：身份/request_id 贯通、view_credentials 动作、敏感 header 值不落盘。

audit logger 为同步落盘（无队列），请求返回即已写入；但同一测试进程内 handler
跨用例常驻、文件持续 append（同秒滚动的多测试写同一文件属预期），故断言一律按
request_id 在全部 audit.log.* 行中过滤定位，不依赖"最后一行属于本请求"。
"""
import glob
import json

from tests.utils import make_token

BODY = {"type": "http", "upstream_url": "http://10.0.0.5/api/v1", "headers": {}}


def _all_audit_entries() -> list[dict]:
    entries = []
    for path in sorted(glob.glob("logs-test/audit.log.*")):
        with open(path, encoding="utf-8") as fh:
            for line in fh.read().splitlines():
                if line.strip():
                    entries.append(json.loads(line))
    return entries


def _find_audit_entry(request_id: str) -> dict:
    matches = [e for e in _all_audit_entries() if e["request_id"] == request_id]
    assert matches, f"audit 日志中找不到 request_id={request_id} 的记录"
    return matches[-1]


async def test_audit_has_identity_and_request_id(client):
    headers = {"Authorization": f"Bearer {make_token('u888')}"}
    resp = await client.post("/api/v1/mappings", json=BODY, headers=headers)
    assert resp.status_code == 201
    entry = _find_audit_entry(resp.headers["x-request-id"])
    assert entry["user_id"] == "u888" and entry["user_name"] == "张三"
    assert entry["action"] == "mgmt" and entry["status"] == 201
    assert entry["method"] == "POST" and entry["path"] == "/api/v1/mappings"


async def test_view_credentials_audited(client):
    created = (await client.post("/api/v1/mappings", json=BODY,
                                 headers={"Authorization": f"Bearer {make_token('u888')}"})).json()
    mid = created["mapping_id"]
    resp = await client.get(f"/api/v1/mappings/{mid}",
                            headers={"Authorization": f"Bearer {make_token('u888')}"})
    assert resp.status_code == 200
    entry = _find_audit_entry(resp.headers["x-request-id"])
    assert entry["action"] == "view_credentials" and entry["mapping_id"] == mid
    assert entry["user_id"] == "u888"


async def test_audit_never_contains_header_values(client):
    body = {**BODY, "headers": {"Authorization": "Bearer sk-super-secret-value"}}
    resp = await client.post("/api/v1/mappings", json=body,
                             headers={"Authorization": f"Bearer {make_token('u888')}"})
    assert resp.status_code == 201
    content = ""
    for path in glob.glob("logs-test/audit.log.*"):
        with open(path, encoding="utf-8") as fh:
            content += fh.read()
    assert "sk-super-secret-value" not in content
