"""Prometheus 指标定义（§15.2 八项；标签仅低基数维度，不放 user_id/mapping_id）。

§15.2 对照（M7 完善核对，接线位置）：
- ap_requests_total            Counter   route/type/status  请求计数（middleware；
                                                    route ∈ mgmt/proxy/builtin/admin/ops/other，
                                                    admin 为 M7 管理页面流量）
- ap_request_duration_seconds  Histogram route/type         端到端延迟（middleware）
- ap_upstream_duration_seconds Histogram type             上游耗时（转发管线内观测：
                                                    http_forward/mcp_sse，剔除代理自身开销）
- ap_upstream_errors_total     Counter   type/code         上游连接失败/超时（code ∈
                                                    pool_exhausted/timeout/connect/stream_broken）
- ap_bytes_total               Counter   direction(in/out) 上下行字节（middleware 分片累计）
- ap_sse_active_connections    Gauge     —                 SSE 活跃长连接（mcp_sse；含
                                                    Streamable GET 推送流，M4 语义钉住）
- ap_inflight_requests         Gauge     —                 在途请求（middleware）
- ap_oauth_actions_total       Counter   action            OAuth 凭证事件（M6；action ∈
                                                    bind/unbind/refresh/fail/transient）
基数控制：标签仅 route/type/status/code/direction/action/le——不放 mapping_id/user_id
（映射可删、用户量大，防时间序列爆炸）；按映射/用户排查走审计日志 + request_id 关联。
"""
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
# OAuth 凭证事件（M6）。action ∈ bind / unbind / refresh / fail / transient：
# fail = 业务性拒绝（AS 明确拒绝刷新 400/401/403、回调 AS 拒绝 / 换 token 失败、
# 无 refresh_token 的不可续期终态），transient = 瞬时失败（网络 / discovery /
# token 端点 5xx·429 / 响应畸形——凭证保留可重试）。终审遗留 5 拆分：混计会
# 把提供方抖动计进业务失败，误导告警阈值与「用户需重新授权」的规模判断。
oauth_actions_total = Counter("ap_oauth_actions_total", "OAuth 凭证事件（M6 使用）", ["action"])
