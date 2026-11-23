"""Prometheus 指标定义（标签仅低基数维度，不放 user_id/mapping_id）。"""
from prometheus_client import Counter, Gauge, Histogram

requests_total = Counter("ap_requests_total", "HTTP 请求总数", ["route", "type", "status"])
request_duration = Histogram("ap_request_duration_seconds", "端到端延迟", ["route", "type"])
upstream_duration = Histogram("ap_upstream_duration_seconds", "上游耗时（M2+ 使用）", ["type"])
upstream_errors_total = Counter("ap_upstream_errors_total", "上游失败计数（M2+ 使用）", ["type", "code"])
bytes_total = Counter("ap_bytes_total", "上下行字节数（M2+ 使用）", ["direction"])
sse_active = Gauge("ap_sse_active_connections", "SSE 活跃长连接数（M3+ 使用）")
inflight = Gauge("ap_inflight_requests", "在途请求数")
oauth_actions_total = Counter("ap_oauth_actions_total", "OAuth 凭证事件（M6 使用）", ["action"])
