"""HTTP 前缀流式转发（设计 §8.1 / §8.2）。

本模块职责：路径分发（dot-segment 拒绝）→ URL 拼接 → 出站 header 重建 →
httpx 流式转发（请求体字节计数限流）→ 同源重定向内部跟随 → 响应 hop-by-hop
过滤流式回传。全程不整体缓冲；trace / metrics / 审计全接线。
"""
from __future__ import annotations

from urllib.parse import unquote

from ..errors import AppError


def split_sub_path(full_path: str, mapping_id: str) -> str:
    """/p/{id} 之后的子路径（含前导 /；可为空串）。前缀不匹配 → 400。"""
    prefix = f"/p/{mapping_id}"
    if not full_path.startswith(prefix):
        raise AppError(400, "INVALID_PARAM", "路径与映射不匹配")
    return full_path[len(prefix):]


def _seg_is_dot_segment(seg: str) -> bool:
    # 两层解码：覆盖 %2e（一层编码）与 %252e（两层双重编码）变体
    cur = seg
    for _ in range(2):
        cur = unquote(cur)
        if cur.lower() in (".", ".."):
            return True
    return False


def assert_safe_sub_path(sub_path: str) -> None:
    """拒绝 dot-segment 及 URL 编码变体（设计 §8.1 第 8 条）——防止拼接后逃逸注册前缀。"""
    for seg in sub_path.split("/"):
        if seg and _seg_is_dot_segment(seg):
            raise AppError(400, "INVALID_PARAM", "代理子路径含非法 dot-segment")


def build_forward_target(upstream_url: str, sub_path: str, query: str) -> str:
    """转发URL = upstream_url(规范化去尾斜杠) + /子路径 [+ ?query]（设计 §8.2）。

    子路径为空时直达注册 URL；query 为调用方原始 query 串（不重编码，透传）。
    """
    base = upstream_url.rstrip("/")
    trimmed = sub_path.lstrip("/")
    target = f"{base}/{trimmed}" if trimmed else base
    return f"{target}?{query}" if query else target
