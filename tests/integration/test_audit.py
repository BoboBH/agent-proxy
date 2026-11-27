"""审计日志行为验证：身份/request_id 贯通、view_credentials 动作、敏感 header 值不落盘。

audit logger 为同步落盘（无队列），请求返回即已写入；但同一测试进程内 handler
跨用例常驻、文件持续 append（同秒滚动的多测试写同一文件属预期），故断言一律按
request_id 在全部 audit.log.* 行中过滤定位，不依赖"最后一行属于本请求"。
"""
import glob
import json

from app.auth import Identity
from app.sso.session import SESSION_COOKIE, create_session
from tests.utils import make_token

BODY = {"type": "http", "upstream_url": "http://10.0.0.5/api/v1", "headers": {}}


def _read_audit_files() -> dict[str, list[str]]:
    """读 logs-test 下全部 audit.log.* → {文件路径: 非空行列表}。"""
    files = {}
    for path in sorted(glob.glob("logs-test/audit.log.*")):
        with open(path, encoding="utf-8") as fh:
            files[path] = [x for x in fh.read().splitlines() if x.strip()]
    return files


def _all_audit_entries() -> list[dict]:
    entries = []
    for path, lines in _read_audit_files().items():
        for line in lines:
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise AssertionError(f"audit 日志存在非 JSON 行: {path}: {line!r}") from exc
    return entries


def _find_audit_entry(request_id: str) -> dict:
    matches = [e for e in _all_audit_entries() if e["request_id"] == request_id]
    assert matches, f"audit 日志中找不到 request_id={request_id} 的记录"
    assert len(matches) == 1, f"重复审计条目: request_id={request_id} 出现 {len(matches)} 次"
    return matches[0]


async def test_audit_has_identity_and_request_id(client):
    headers = {"Authorization": f"Bearer {make_token(888)}"}
    resp = await client.post("/api/v1/mappings", json=BODY, headers=headers)
    assert resp.status_code == 201
    entry = _find_audit_entry(resp.headers["x-request-id"])
    assert entry["user_id"] == 888 and entry["user_name"] == "张三"
    assert entry["action"] == "mgmt" and entry["status"] == 201
    assert entry["method"] == "POST" and entry["path"] == "/api/v1/mappings"


async def test_audit_identity_from_cookie_session(client, app):
    """Cookie 通道变体（M7 评审补充）：审计 user_id/user_name 同样来自服务端会话
    （get_current_identity 双通道写 request.state，middleware 落盘）——页面 fetch
    场景的审计身份贯通与 Bearer 通道一致。"""
    sid = await create_session(app.state.redis,
                               Identity(user_id=777, user_name="李四"), 600)
    resp = await client.post("/api/v1/mappings", json=BODY,
                             headers={"Cookie": f"{SESSION_COOKIE}={sid}"})
    assert resp.status_code == 201
    entry = _find_audit_entry(resp.headers["x-request-id"])
    assert entry["user_id"] == 777 and entry["user_name"] == "李四"
    assert entry["action"] == "mgmt" and entry["status"] == 201


async def test_view_credentials_audited(client):
    created = (await client.post("/api/v1/mappings", json=BODY,
                                 headers={"Authorization": f"Bearer {make_token(888)}"})).json()
    mid = created["mapping_id"]
    resp = await client.get(f"/api/v1/mappings/{mid}",
                            headers={"Authorization": f"Bearer {make_token(888)}"})
    assert resp.status_code == 200
    entry = _find_audit_entry(resp.headers["x-request-id"])
    assert entry["action"] == "view_credentials" and entry["mapping_id"] == mid
    assert entry["user_id"] == 888


async def test_audit_never_contains_header_values(client):
    body = {**BODY, "headers": {"Authorization": "Bearer sk-super-secret-value"}}
    resp = await client.post("/api/v1/mappings", json=body,
                             headers={"Authorization": f"Bearer {make_token(888)}"})
    assert resp.status_code == 201
    for path, lines in _read_audit_files().items():
        text = "\n".join(lines)
        assert "sk-super-secret-value" not in text, f"映射 header 值泄漏进审计日志: {path}"
        assert "stub." not in text, f"调用方 bearer token 泄漏进审计日志: {path}"


async def test_audit_records_bytes_in_out(client):
    resp = await client.post("/api/v1/mappings", json=BODY,
                             headers={"Authorization": f"Bearer {make_token(888)}"})
    assert resp.status_code == 201
    entry = _find_audit_entry(resp.headers["x-request-id"])
    assert entry["bytes_in"] > 0   # 请求体（JSON）被应用实际读取
    assert entry["bytes_out"] > 0  # 响应体实际发送字节数
