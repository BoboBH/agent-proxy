"""Prometheus 指标完善核对（M7，设计 §15.2）：八项指标族齐全暴露 + 标签基数受控。

M1-M4 已陆续接线（middleware：requests_total/request_duration/inflight/bytes_total；
forward：upstream_duration/upstream_errors_total/sse_active；oauth：oauth_actions_total），
本文件补齐 §15.2 的存在性与基数红线断言；route=admin 由管理页面（M7）流量产生。
"""
import re

from app.services import metrics as m

# §15.2 表逐行（名称与 prometheus_client 输出形态一致）
FAMILIES = (
    ("ap_requests_total", "counter"),
    ("ap_request_duration_seconds", "histogram"),
    ("ap_upstream_duration_seconds", "histogram"),
    ("ap_upstream_errors_total", "counter"),
    ("ap_bytes_total", "counter"),
    ("ap_sse_active_connections", "gauge"),
    ("ap_inflight_requests", "gauge"),
    ("ap_oauth_actions_total", "counter"),
)

# 基数控制（§15.2）：标签仅低基数维度；le 为直方图桶固有标签
ALLOWED_LABELS = {"route", "type", "status", "code", "direction", "action", "le"}


def _touch_all_families() -> None:
    """各带标签指标族补一个样本行（# TYPE 行注册即输出、零样本也在；样本行才需触达；
    进程内全局注册表）。requests_total 的 route 用 mgmt——route="admin" 样本只能
    来自下方真实 GET /admin 页面请求，保证断言与 middleware.route_name 对 /admin
    的分类耦合（评审修复：touch 自建 admin 样本会让断言自满足）。"""
    m.requests_total.labels(route="mgmt", type="-", status="200").inc()
    m.request_duration.labels(route="admin", type="-").observe(0.001)
    m.upstream_duration.labels(type="http").observe(0.002)
    m.upstream_errors_total.labels(type="http", code="connect").inc()
    m.bytes_total.labels(direction="in").inc(1)
    m.sse_active.inc()
    m.sse_active.dec()
    m.inflight.inc()
    m.inflight.dec()
    m.oauth_actions_total.labels(action="bind").inc()


async def test_all_eight_families_and_admin_route_exposed(client):
    await client.get("/admin")            # route=admin（未登录 302 亦计数，M7 页面流量）
    _touch_all_families()
    resp = await client.get("/metrics")
    assert resp.status_code == 200
    for family, typ in FAMILIES:
        assert f"# TYPE {family} {typ}" in resp.text, family
    assert 'route="admin"' in resp.text   # §15.2 route 标签含 admin（页面路由自动计入）
    # 真实页面请求样本行钉住（未登录 302 亦计数）：断言与 /admin → route=admin
    # 分类耦合（touch 用 mgmt，admin 样本唯一来源是上面的 GET /admin）
    assert 'ap_requests_total{route="admin",status="302",type="-"}' in resp.text


async def test_metric_label_cardinality_controlled(client):
    """基数红线（§15.2）：不放 mapping_id / user_id——映射可删、用户量大，防时间序列
    爆炸；按映射/用户排查走审计日志 + request_id 关联。"""
    m.requests_total.labels(route="proxy", type="http", status="200").inc()
    m.upstream_errors_total.labels(type="mcp", code="timeout").inc()
    resp = await client.get("/metrics")
    for line in resp.text.splitlines():
        if not line.startswith("ap_") or "{" not in line:
            continue
        labels = set(re.findall(r'(\w+)="[^"]*"', line.split("{", 1)[1]))
        assert labels <= ALLOWED_LABELS, f"超出基数控制白名单: {line}"
    assert "mapping_id=" not in resp.text
    assert "user_id=" not in resp.text
