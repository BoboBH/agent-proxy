import json
import logging

import pytest

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
    assert recs[1]["request_id"] == "r1" and recs[1]["phase"] == "response"
    assert recs[1]["status"] == 200 and recs[1]["duration_ms"] == 123
    assert "ts" in recs[1] and list(recs[1])[0] == "ts"


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


@pytest.mark.parametrize("value", ["", "abc", "abcd1234", "abcdefghij", "sk-short"])
def test_fingerprint_short_value_no_leak(value):
    fp = trace.fingerprint(value)
    assert fp == f"****(len={len(value)})"
    # 原值的任意连续片段（≥2 字符）不应出现在指纹中（单字符与 len 文案撞字母不算泄露）
    chunks = {value[i:i + 2] for i in range(len(value) - 1)}
    assert not (chunks & {fp[i:i + 2] for i in range(len(fp) - 1)}), f"短值指纹不应泄露原值片段: {fp}"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("abcd12345678", "abcd****5678(len=12)"),  # 恰为门槛 12
        ("sk-abcdefgh12345678", "sk-a****5678(len=19)"),
    ],
)
def test_fingerprint_long_value_first4_last4(value, expected):
    assert trace.fingerprint(value) == expected


def test_sensitive_header_substring_fallback_in_body_mode(tmp_path):
    path = _capture(tmp_path, "body")
    trace.log_request("r1", "u1", "m1", "POST", "http://x",
                      {"X-Custom-Token": "tok-9ab2", "X-Request-Id": "abc123"},
                      body=b'{"q":1}', content_type="application/json")
    recs = _read(path)
    assert recs[0]["headers"]["X-Custom-Token"] == "****(len=8)"
    assert recs[0]["headers"]["X-Request-Id"] == "abc123"
    assert "tok-9ab2" not in json.dumps(recs[0])


def test_plus_json_and_yaml_content_types_kept_as_text(tmp_path):
    path = _capture(tmp_path, "body")
    trace.log_request("r1", "u1", "m1", "POST", "http://x", {},
                      body=b'{"a":1}', content_type="application/vnd.api+json")
    trace.log_request("r2", "u1", "m1", "POST", "http://x", {},
                      body=b"a: 1", content_type="application/yaml; charset=utf-8")
    recs = _read(path)
    assert recs[0]["body"] == '{"a":1}' and recs[0]["body_truncated"] is False
    assert recs[1]["body"] == "a: 1" and recs[1]["body_truncated"] is False


def test_sse_event_uses_data_keys_in_body_mode(tmp_path):
    path = _capture(tmp_path, "body")
    trace.log_sse_event("r1", "message", b"hello")
    trace.log_sse_event("r1", "delta", b"x" * 200)
    recs = _read(path)
    assert recs[0]["phase"] == "sse_event" and recs[0]["event"] == "message"
    assert recs[0]["data"] == "hello" and recs[0]["data_truncated"] is False
    assert recs[1]["data_truncated"] is True and len(recs[1]["data"]) == 100
    assert "body" not in recs[0] and "body_truncated" not in recs[0]
