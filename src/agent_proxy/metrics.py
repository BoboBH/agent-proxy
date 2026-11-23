"""Prometheus 指标定义（标签仅低基数维度，不放 user_id/mapping_id）。"""
from prometheus_client import Counter, Gauge, Histogram

# 直方图桶（终审债务）：prometheus 默认桶对亚毫秒与长耗时（SSE/慢上游）分辨率不足，
# 自定义桶覆盖 5ms ~ 5min（设计 §15.2 / §8.1 第 5 条超时上界 60s、SSE 长连接）
DURATION_BUCKETS = (0.005, 0.01, 0.05, 0.1, 0.5, 1, 5, 10, 30, 60, 300)

requests_total = Counter("ap_requests_total", "HTTP 请求总数", ["route", "type", "status"])
request_duration = Histogram("ap_request_duration_seconds", "端到端延迟", ["route", "type"],
                             buckets=DURATION_BUCKETS)
upstream_duration = Histogram("ap_upstream_duration_seconds", "上游耗时", ["type"],
                              buckets=DURATION_BUCKETS)
upstream_errors_total = Counter("ap_upstream_errors_total", "上游失败计数", ["type", "code"])
bytes_total = Counter("ap_bytes_total", "上下行字节数", ["direction"])
sse_active = Gauge("ap_sse_active_connections", "SSE 活跃长连接数（M3+ 使用）")
inflight = Gauge("ap_inflight_requests", "在途请求数")
oauth_actions_total = Counter("ap_oauth_actions_total", "OAuth 凭证事件（M6 使用）", ["action"])
