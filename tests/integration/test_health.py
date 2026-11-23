async def test_healthz(client):
    resp = await client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}
    assert resp.headers.get("x-request-id")


async def test_readyz(client):
    resp = await client.get("/readyz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ready"}


async def test_metrics_exposes_counters(client):
    await client.get("/healthz")
    resp = await client.get("/metrics")
    assert resp.status_code == 200
    assert "ap_requests_total" in resp.text
    assert "ap_inflight_requests" in resp.text


async def test_request_id_in_error_body(client):
    resp = await client.get("/api/v1/mappings")  # 未带 token → 401（依赖 Task 6，本任务允许 FAIL）
    assert resp.status_code == 401
    body = resp.json()
    assert body["code"] == "INVALID_TOKEN" and body["request_id"]


async def test_metrics_custom_buckets_and_bytes(client):
    await client.get("/healthz")
    resp = await client.get("/metrics")
    text = resp.text
    assert 'le="0.005"' in text and 'le="300.0"' in text  # 自定义直方图桶（终审债务）
    assert "ap_bytes_total" in text                        # bytes 指标已注册
