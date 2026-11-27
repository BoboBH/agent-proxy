"""mcp_sse 纯逻辑单测：路径分发辅助（§8.3 路径分发表）+ SseEndpointRewriter
增量行解析器（§8.3 实现要点——保留行尾、跟踪 event 名、endpoint data 行改写、
其余行字节级透传、跨 chunk 半行缓冲、空行复位事件名）。"""
import pytest

from app.forward.mcp_sse import (MAX_LINE_BYTES, SseEndpointRewriter,
                                         build_origin_target, registered_endpoint_path)


def _feed_all(rewriter, chunks):
    out = []
    for chunk in chunks:
        out.extend(rewriter.feed(chunk))
    out.extend(rewriter.flush())
    return out


# ---------- 路径分发辅助 ----------


def test_registered_endpoint_path_basic_and_deep():
    assert registered_endpoint_path("http://127.0.0.1:9902/sse") == "/sse"
    assert registered_endpoint_path("https://mcp.ex.com/api/mcp/sse") == "/api/mcp/sse"


def test_registered_endpoint_path_empty_becomes_root():
    assert registered_endpoint_path("http://127.0.0.1:9902") == "/"
    assert registered_endpoint_path("http://127.0.0.1:9902/") == "/"


def test_build_origin_target_query_join():
    assert build_origin_target("https://mcp.ex.com/sse", "/messages", "session_id=s1") \
        == "https://mcp.ex.com/messages?session_id=s1"


def test_build_origin_target_deep_path():
    assert build_origin_target("http://127.0.0.1:9902/sse", "/a/b", "") \
        == "http://127.0.0.1:9902/a/b"


def test_build_origin_target_empty_sub_path_hits_origin():
    assert build_origin_target("http://127.0.0.1:9902/sse", "", "") \
        == "http://127.0.0.1:9902"


# ---------- SseEndpointRewriter ----------


def test_rewriter_endpoint_root_relative_rewritten_crlf_preserved():
    rw = SseEndpointRewriter("aB3xK9mQ2wR4")
    lines = _feed_all(rw, [b"event: endpoint\r\ndata: /messages?session_id=test123\r\n\r\n"])
    assert lines == [b"event: endpoint\r\n",
                     b"data: /p/aB3xK9mQ2wR4/messages?session_id=test123\r\n",
                     b"\r\n"]


def test_rewriter_endpoint_absolute_url_takes_path_and_query():
    """§8.3 改写规则：绝对 URL 形式的 endpoint 值取其 path + query。"""
    rw = SseEndpointRewriter("m1m2m3m4m5m6")
    lines = _feed_all(rw, [b"event: endpoint\n"
                           b"data: http://up.example.com:9902/messages?session_id=s1\n\n"])
    assert lines[1] == b"data: /p/m1m2m3m4m5m6/messages?session_id=s1\n"


def test_rewriter_message_retry_heartbeat_bytes_passthrough():
    """message 事件 / retry: 行 / 心跳注释行字节级原样透传（§8.3 实现要点）。"""
    rw = SseEndpointRewriter("m1m2m3m4m5m6")
    raw = (b"retry: 3000\n"
           b": ping\n\n"
           b"event: message\ndata: {\"jsonrpc\":\"2.0\"}\n\n")
    assert _feed_all(rw, [raw]) == [
        b"retry: 3000\n", b": ping\n", b"\n",
        b"event: message\n", b"data: {\"jsonrpc\":\"2.0\"}\n", b"\n"]


def test_rewriter_event_name_resets_after_blank_line():
    """空行结束事件块后 event 名复位：后续 data 行不再被当作 endpoint 改写。"""
    rw = SseEndpointRewriter("m1m2m3m4m5m6")
    out = _feed_all(rw, [b"event: endpoint\n\n", b"data: /messages\n\n"])
    assert out == [b"event: endpoint\n", b"\n", b"data: /messages\n", b"\n"]


def test_rewriter_partial_line_held_across_chunks():
    """跨 chunk 半行缓冲：不完整的行不产出，凑齐行尾后整行处理（保留原始行尾）。"""
    rw = SseEndpointRewriter("m1m2m3m4m5m6")
    out = []
    out += rw.feed(b"event: endp")
    assert out == []                                    # 半行缓冲
    out += rw.feed(b"oint\ndata: /me")
    out += rw.feed(b"ssages?sid=1\n\n")
    out += rw.flush()
    assert out == [b"event: endpoint\n",
                   b"data: /p/m1m2m3m4m5m6/messages?sid=1\n", b"\n"]


def test_rewriter_data_without_leading_space_normalized():
    """`data:` 后无空格（SSE 规范空格可选）：改写输出统一为规范形态 `data: <值>`。"""
    rw = SseEndpointRewriter("m1m2m3m4m5m6")
    out = _feed_all(rw, [b"event: endpoint\ndata:/messages?sid=1\n\n"])
    assert out[1] == b"data: /p/m1m2m3m4m5m6/messages?sid=1\n"


def test_rewriter_non_path_endpoint_value_passthrough():
    """§8.3 限制说明：既非绝对 URL 也非根相对的 endpoint 值原样透传（不改写）。"""
    rw = SseEndpointRewriter("m1m2m3m4m5m6")
    out = _feed_all(rw, [b"event: endpoint\ndata: not-a-path\n\n"])
    assert out[1] == b"data: not-a-path\n"


def test_rewriter_malformed_absolute_url_degrades_to_passthrough():
    """评审 Issue 6：畸形绝对 URL（urlparse 抛 ValueError，如非法 IPv6 字面量
    `http://[bad`）降级为原样透传（不改写、不产 trace 记录），绝不炸整条 SSE 流。"""
    rw = SseEndpointRewriter("m1m2m3m4m5m6")
    out = _feed_all(rw, [b"event: endpoint\ndata: http://[bad\n\n"])
    assert out == [b"event: endpoint\n", b"data: http://[bad\n", b"\n"]
    assert rw.take_trace_records() == []


def test_rewriter_multiple_data_lines_all_rewritten():
    """endpoint 事件块内多条 data 行（SSE 规范允许多值）逐行改写。"""
    rw = SseEndpointRewriter("m1m2m3m4m5m6")
    out = _feed_all(rw, [b"event: endpoint\ndata: /a\nxx\n\n"])
    assert out == [b"event: endpoint\n", b"data: /p/m1m2m3m4m5m6/a\n",
                   b"xx\n", b"\n"]


def test_rewriter_flush_emits_trailing_line_without_ending():
    """流结束冲出无行尾的残留末行（SSE 规范允许最后一行无换行）。"""
    rw = SseEndpointRewriter("m1m2m3m4m5m6")
    rw.feed(b"data: tail-no-newline")
    assert rw.flush() == [b"data: tail-no-newline"]
    assert rw.flush() == []                             # 再次 flush 无残留


def test_rewriter_trace_records_endpoint_pair_and_message_not_heartbeat():
    """trace 记录（§11.1）：endpoint 改写前 + 改写后各一条、message 记 data 载荷；
    心跳注释行不产生记录。"""
    rw = SseEndpointRewriter("m1m2m3m4m5m6")
    rw.feed(b": ping\n\n")
    assert rw.take_trace_records() == []
    rw.feed(b"event: endpoint\ndata: /messages?session_id=abcdef123456\n\n")
    rw.feed(b"event: message\ndata: {\"ok\":1}\n\n")
    recs = rw.take_trace_records()
    assert recs == [("endpoint", b"/messages?session_id=abcdef123456"),
                    ("endpoint_rewritten", b"/p/m1m2m3m4m5m6/messages?session_id=abcdef123456"),
                    ("message", b"{\"ok\":1}")]
    assert rw.take_trace_records() == []                # 取过即清空


# ---------- M3 遗留 Minor（M4 落地）：单行缓冲上限——无换行超长行降级透传 ----------


def test_rewriter_overlong_no_newline_line_degrades_to_passthrough():
    """无换行超长行（> MAX_LINE_BYTES 上限）：降级原样透传已缓冲字节并进入透传
    模式——内存有界、字节级保真，且不产 trace 记录（降级行不改写）。
    （计划原稿把含 `\\n` 的 `event: endpoint\\ndata: ` 整段当「半行」——首行实际
    已完整可解析，此处按行解析语义拆开喂入，断言意图不变。）"""
    rw = SseEndpointRewriter("m1m2m3m4m5m6")
    assert rw.feed(b"event: endpoint\n") == [b"event: endpoint\n"]  # 完整行正常解析
    assert rw.feed(b"data: ") == []                             # 半行缓冲
    blob = b"x" * (MAX_LINE_BYTES + 16)
    out = rw.feed(blob)                                          # 无换行且超上限
    assert out == [b"data: " + blob]                             # 已缓冲字节原样冲出
    assert rw.take_trace_records() == []


def test_rewriter_overflow_mode_resumes_normal_parsing_after_line_end():
    """透传模式持续到行尾：超长行的残余字节原样透传，行尾之后恢复正常解析
    （后续 endpoint 事件照常改写）。"""
    rw = SseEndpointRewriter("m1m2m3m4m5m6")
    blob = b"x" * (MAX_LINE_BYTES + 16)
    produced = []
    produced += rw.feed(b"event: endpoint\n")    # 完整行正常解析（见上注）
    produced += rw.feed(b"data: ")               # 半行缓冲
    produced += rw.feed(blob)                    # 超限：冲出 data:+blob，进入透传模式
    produced += rw.feed(b"\n")                   # 超长行行尾：残余原样透传，模式复位
    produced += rw.feed(b"event: endpoint\ndata: /messages?sid=1\n\n")
    produced += rw.flush()
    assert produced == [b"event: endpoint\n", b"data: " + blob, b"\n",
                        b"event: endpoint\n",
                        b"data: /p/m1m2m3m4m5m6/messages?sid=1\n", b"\n"]


def test_rewriter_flush_after_overflow_passthrough_remaining():
    """透传模式下流结束：EOF 残余（超长行末段）原样透传。"""
    rw = SseEndpointRewriter("m1m2m3m4m5m6")
    rw.feed(b"y" * (MAX_LINE_BYTES + 4))         # 超限冲出 + 进入透传模式
    assert rw.feed(b"tail-no-newline") == []
    assert rw.flush() == [b"tail-no-newline"]


@pytest.mark.parametrize("size", [MAX_LINE_BYTES, MAX_LINE_BYTES + 1],
                         ids=["exact-1MB-buffered-not-flushed", "over-1MB-flushed"])
def test_rewriter_max_line_bytes_exact_boundary(size):
    """单行缓冲上限恰边界钉住（M4 Task 2 评审携带项）：缓冲 == 1MB **不冲出**
    （判定为严格大于 `>`，仍正常缓冲、EOF flush 走正常解析路径产出）；+1 即触发
    冲出降级透传——防 `>=` 式 off-by-one 回归。"""
    rw = SseEndpointRewriter("m1m2m3m4m5m6")
    blob = b"x" * size
    out = rw.feed(blob)                          # 无换行单喂
    if size == MAX_LINE_BYTES:
        assert out == []                         # 恰达上限：仍缓冲（未冲出）
        assert rw.flush() == [blob]              # EOF 残余走正常解析路径原样产出
        assert rw.take_trace_records() == []
    else:
        assert out == [blob]                     # 越界 1 字节：立即冲出降级透传
        assert rw.flush() == []                  # 缓冲已空
        assert rw.take_trace_records() == []     # 降级行不产 trace 记录
