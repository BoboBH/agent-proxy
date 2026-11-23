import json
import logging

from agent_proxy import trace
from agent_proxy.logging_setup import flush_trace


def _capture(tmp_path, mode, limit=100):
    handler = logging.FileHandler(tmp_path / "trace.log", encoding="utf-8")
    logger = logging.getLogger("agent_proxy.trace")
    logger.handlers = [handler]
    trace.configure(mode, limit)
    return tmp_path / "trace.log"


def _read(path):
    flush_trace()
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


def test_off_mode_no_records(tmp_path):
    path = _capture(tmp_path, "off")
    trace.log_request("r1", "u1", "m1", "GET", "http://x", {"Authorization": "Bearer abc"})
    assert _read(path) == []


def test_metadata_mode_fingerprint_no_body(tmp_path):
    path = _capture(tmp_path, "metadata")
    trace.log_request("r1", "u1", "m1", "POST", "http://x/api",
                      {"X-API-Key": "sk-very-secret-key", "Content-Type": "application/json"},
                      body=b'{"a":1}', content_type="application/json")
    trace.log_response("r1", 200, 123)
    recs = _read(path)
    assert recs[0]["phase"] == "request"
    assert recs[0]["headers"]["X-API-Key"].startswith("sk-v****") and "(len=" in recs[0]["headers"]["X-API-Key"]
    assert "body" not in recs[0] and "body" not in recs[1]
    assert recs[1] == {"request_id": "r1", "phase": "response", "status": 200, "duration_ms": 123}


def test_body_mode_masks_sensitive_but_keeps_normal(tmp_path):
    path = _capture(tmp_path, "body")
    trace.log_request("r1", "u1", "m1", "POST", "http://x",
                      {"Authorization": "Bearer sk-abc12345", "Accept": "application/json"},
                      body=b'{"q":1}', content_type="application/json")
    recs = _read(path)
    assert recs[0]["body"] == '{"q":1}'
    assert recs[0]["headers"]["Authorization"].startswith("Bear****2345")
    assert recs[0]["headers"]["Accept"] == "application/json"
    assert "sk-abc12345" not in json.dumps(recs[0])


def test_body_truncation(tmp_path):
    path = _capture(tmp_path, "body", limit=10)
    trace.log_request("r1", "u1", "m1", "POST", "http://x", {}, body=b"0123456789ABCDEF")
    recs = _read(path)
    assert recs[0]["body_truncated"] is True and len(recs[0]["body"]) == 10


def test_binary_body_skipped(tmp_path):
    path = _capture(tmp_path, "body")
    trace.log_request("r1", "u1", "m1", "POST", "http://x", {}, body=b"\x00\x01", content_type="application/octet-stream")
    recs = _read(path)
    assert recs[0]["body_bytes"] == 2 and "body" not in recs[0]


def test_sse_event_only_in_body_mode(tmp_path):
    path = _capture(tmp_path, "metadata")
    trace.log_sse_event("r1", "message", b"data")
    assert _read(path) == []
