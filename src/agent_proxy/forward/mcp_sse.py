"""MCP SSE 传输代理（设计 §8.3）。

纯逻辑部分：路径分发辅助（注册端点路径 / 上游 origin 根还原）与 SSE 增量行
解析器 SseEndpointRewriter——按行读取（保留原始行尾 \\r\\n / \\n）、跟踪当前
`event:` 名（空行复位）；`event: endpoint` 的 data: 行改写为 /p/{id}<path>?<query>
下发，其余行（message 事件 / retry: 行 / `:` 心跳注释行 / 字段行）字节级原样
透传，每行产出即交由管线 yield（每行立即 flush，不做整体缓冲）。

流式转发管线 stream_sse_forward（Task 4）与 test 探测 probe_sse_mapping（Task 6）
同在本模块；trace 记录由解析器产出（take_trace_records），管线层接 trace.log_sse_event。
"""
from __future__ import annotations

from urllib.parse import urlparse


def registered_endpoint_path(upstream_url: str) -> str:
    """注册 upstream_url 的路径（§8.3 路径分发第 1 行的匹配目标）；无路径按根 `/`。"""
    path = urlparse(upstream_url).path
    return path if path else "/"


def build_origin_target(upstream_url: str, sub_path: str, query: str) -> str:
    """非注册端点路径的转发目标：上游 origin 根 + 子路径 [+ ?query]（§8.3 第 2 行）。

    子路径为空时直达 origin 根；query 为调用方原始 query 串（不重编码，透传）。
    """
    parsed = urlparse(upstream_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    trimmed = sub_path.lstrip("/")
    if not trimmed:
        return origin
    target = f"{origin}/{trimmed}"
    return f"{target}?{query}" if query else target


class SseEndpointRewriter:
    """SSE 增量行解析器（设计 §8.3 实现要点）。

    feed(chunk) → list[bytes]：本次可产出的完整行（保留原始行尾 \\r\\n / \\n）；
    跨 chunk 的半行在内部缓冲。事件名跟踪按 SSE 语义：`event:` 字段设置当前
    事件名，空行（事件块结束）复位；仅 `event: endpoint` 期间的 data: 行改写。
    take_trace_records() 取走自上次调用以来的 trace 记录
    [(event 名, data 字节), ...]，由管线层接 trace.log_sse_event（body 模式生效）。
    """

    def __init__(self, mapping_id: str) -> None:
        self._mapping_id = mapping_id
        self._buffer = b""
        self._current_event = ""
        self._trace_records: list[tuple[str, bytes]] = []

    def feed(self, chunk: bytes) -> list[bytes]:
        self._buffer += chunk
        lines: list[bytes] = []
        while True:
            idx = self._buffer.find(b"\n")
            if idx < 0:
                break
            line = self._buffer[: idx + 1]           # 含行尾 \n
            self._buffer = self._buffer[idx + 1:]
            lines.append(self._handle_line(line))
        return lines

    def flush(self) -> list[bytes]:
        """流结束时冲出无行尾的残留末行（SSE 允许最后一行无换行）。"""
        rest, self._buffer = self._buffer, b""
        return [self._handle_line(rest)] if rest else []

    def take_trace_records(self) -> list[tuple[str, bytes]]:
        records, self._trace_records = self._trace_records, []
        return records

    def _handle_line(self, line: bytes) -> bytes:
        if line.endswith(b"\r\n"):
            body, ending = line[:-2], b"\r\n"
        elif line.endswith(b"\n"):
            body, ending = line[:-1], b"\n"
        else:
            body, ending = line, b""
        text = body.decode("utf-8", "replace")
        if text.startswith(":"):
            return line                              # 心跳注释行：字节级透传，不记 trace
        if text.startswith("event:"):
            self._current_event = text[len("event:"):].strip(" ")
            return line
        if text == "":
            self._current_event = ""                 # 空行 = 事件块结束，事件名复位
            return line
        if text.startswith("data:") and self._current_event == "endpoint":
            return self._rewrite_endpoint_data(text, ending)
        if text.startswith("data:"):
            # message（或未具名事件）的 data 载荷：透传原行 + 产 trace 记录
            self._trace_records.append(
                ("message", text[len("data:"):].lstrip(" ").encode("utf-8")))
        return line                                  # 其余（id:/retry:/字段行）透传

    def _rewrite_endpoint_data(self, text: str, ending: bytes) -> bytes:
        raw_value = text[len("data:"):]
        value = raw_value[1:] if raw_value.startswith(" ") else raw_value
        parsed = urlparse(value)
        if parsed.netloc:                            # 绝对 URL：取 path + query（§8.3 改写规则）
            path_query = parsed.path or "/"
            if parsed.query:
                path_query = f"{path_query}?{parsed.query}"
        elif value.startswith("/"):                  # 根相对路径（官方 SDK 形态）
            path_query = value
        else:                                        # 限制说明：其余值不改写，原样透传
            return text.encode("utf-8") + ending
        rewritten = f"/p/{self._mapping_id}{path_query}"
        self._trace_records.append(("endpoint", value.encode("utf-8")))
        self._trace_records.append(("endpoint_rewritten", rewritten.encode("utf-8")))
        return f"data: {rewritten}".encode("utf-8") + ending
