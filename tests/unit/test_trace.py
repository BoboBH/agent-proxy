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
    trace.log_request("r1", 1, "m1", "GET", "http://x", {"Authorization": "Bearer abc"})
    assert _read(path) == []


def test_metadata_mode_fingerprint_no_body(tmp_path):
    path = _capture(tmp_path, "metadata")
    trace.log_request("r1", 1, "m1", "POST", "http://x/api",
                      {"X-API-Key": "sk-very-secret-key", "Content-Type": "application/json"},
                      body=b'{"a":1}', content_type="application/json")
    trace.log_response("r1", 200, 123)
    recs = _read(path)
    assert recs[0]["phase"] == "request"
    assert recs[0]["user_id"] == 1                      # 键名与 Identity.user_id 统一（精修）
    assert recs[0]["headers"]["X-API-Key"].startswith("sk-v****") and "(len=" in recs[0]["headers"]["X-API-Key"]
    assert "body" not in recs[0] and "body" not in recs[1]
    assert recs[1]["request_id"] == "r1" and recs[1]["phase"] == "response"
    assert recs[1]["status"] == 200 and recs[1]["duration_ms"] == 123
    assert "ts" in recs[1] and list(recs[1])[0] == "ts"


def test_body_mode_masks_sensitive_but_keeps_normal(tmp_path):
    path = _capture(tmp_path, "body")
    trace.log_request("r1", 1, "m1", "POST", "http://x",
                      {"Authorization": "Bearer sk-abc12345", "Accept": "application/json"},
                      body=b'{"q":1}', content_type="application/json")
    recs = _read(path)
    assert recs[0]["body"] == '{"q":1}'
    assert recs[0]["headers"]["Authorization"].startswith("Bear****2345")
    assert recs[0]["headers"]["Accept"] == "application/json"
    assert "sk-abc12345" not in json.dumps(recs[0])


def test_body_truncation(tmp_path):
    path = _capture(tmp_path, "body", limit=10)
    trace.log_request("r1", 1, "m1", "POST", "http://x", {}, body=b"0123456789ABCDEF")
    recs = _read(path)
    assert recs[0]["body_truncated"] is True and len(recs[0]["body"]) == 10


def test_binary_body_skipped(tmp_path):
    path = _capture(tmp_path, "body")
    trace.log_request("r1", 1, "m1", "POST", "http://x", {}, body=b"\x00\x01", content_type="application/octet-stream")
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
    trace.log_request("r1", 1, "m1", "POST", "http://x",
                      {"X-Custom-Token": "tok-9ab2", "X-Request-Id": "abc123"},
                      body=b'{"q":1}', content_type="application/json")
    recs = _read(path)
    assert recs[0]["headers"]["X-Custom-Token"] == "****(len=8)"
    assert recs[0]["headers"]["X-Request-Id"] == "abc123"
    assert "tok-9ab2" not in json.dumps(recs[0])


def test_plus_json_and_yaml_content_types_kept_as_text(tmp_path):
    path = _capture(tmp_path, "body")
    trace.log_request("r1", 1, "m1", "POST", "http://x", {},
                      body=b'{"a":1}', content_type="application/vnd.api+json")
    trace.log_request("r2", 1, "m1", "POST", "http://x", {},
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


def test_redact_query_masks_values_keeps_keys():
    out = trace.redact_query("http://x/api?session_id=abcdef12345678&status=paid")
    assert out == "http://x/api?session_id=abcd****5678(len=14)&status=****(len=4)"
    assert "abcdef12345678" not in out


def test_redact_query_no_query_unchanged():
    assert trace.redact_query("http://x/api/v1/orders") == "http://x/api/v1/orders"


def test_log_request_redacts_url_query(tmp_path):
    path = _capture(tmp_path, "metadata")
    trace.log_request("r1", 1, "m1", "GET",
                      "http://x/api?access_token=secret-token-value", {})
    recs = _read(path)
    assert "secret-token-value" not in json.dumps(recs)
    assert "access_token=" in recs[0]["url"]  # 键名保留，值指纹化


def test_compressed_body_recorded_as_binary(tmp_path):
    """M4 accept-encoding 配套：压缩传输编码下的响应体为压缩字节，按文本解码必乱码
    ——content_encoding 非空时走二进制路径（只记 body_bytes），与既有非文本
    Content-Type 行为一致。"""
    path = _capture(tmp_path, "body")
    trace.log_response("r1", 200, 12, body=b"\x1f\x8b\x08\x00binary",
                       content_type="application/json", content_encoding="gzip")
    recs = _read(path)
    assert recs[0] == {"ts": recs[0]["ts"], "request_id": "r1", "phase": "response",
                       "status": 200, "duration_ms": 12,
                       "body_bytes": 10, "body_skipped": "binary"}  # 4B gzip magic + 6B binary = 10（计划原稿误写 8）


def test_request_side_compressed_body_recorded_as_binary(tmp_path):
    """M4 评审携带项：request 侧同样有压缩传输编码（调用方 POST gzip body）——
    log_request 传 content_encoding 走二进制路径，trace 不记乱码。"""
    path = _capture(tmp_path, "body")
    trace.log_request("r1", 1, "m1", "POST", "http://x", {},
                      body=b"\x1f\x8b\x08\x00req", content_type="application/json",
                      content_encoding="gzip")
    recs = _read(path)
    assert recs[0]["body_bytes"] == 7 and "body" not in recs[0]


def test_identity_content_encoding_treated_as_text(tmp_path):
    """M4 评审携带项：identity = 无压缩（RFC 9110），请求/响应体为明文——
    不得按二进制丢弃，仍按文本记录。"""
    path = _capture(tmp_path, "body")
    trace.log_request("r1", 1, "m1", "POST", "http://x", {},
                      body=b'{"q":1}', content_type="application/json",
                      content_encoding="identity")
    trace.log_response("r1", 200, 5, body=b'{"ok":true}', content_type="application/json",
                       content_encoding="identity")
    recs = _read(path)
    assert recs[0]["body"] == '{"q":1}' and recs[0]["body_truncated"] is False
    assert recs[1]["body"] == '{"ok":true}' and recs[1]["body_truncated"] is False
