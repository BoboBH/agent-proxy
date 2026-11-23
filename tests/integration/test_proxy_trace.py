"""trace body 模式集成：/p/ 转发的 request/response 记录 + URL query 脱敏（终审债务 #3）。

body 模式经 TRACE_MODE=body 环境启动专用 app（trace.configure 为进程级全局，
用毕恢复 metadata，避免污染后续用例）。

与计划原稿的差异（评审已知项）：设计 §11.1 的 response 行只有 request_id、
没有 mapping_id，故 response 记录按 request 行的 request_id 关联，而非按
mapping_id 筛选（否则必得空集）。

凭据脱敏的断言范围（计划「trace.log 无完整凭据值」与 §11.1 的对齐）：打码
约束的是代理自己生成的字段（url / headers，任何模式生效）；body 模式对
请求/响应 body 记录原文（仅截断，§11.1「body 含用户业务数据，需与日志
访问权限策略对齐」）——本测试的 echo 上游会把收到的 authorization 头回显
进响应 JSON（header 重建验证依赖该回显契约），故响应 body 原文含凭据属
上游载荷、按设计原样落盘，不视为泄漏。
"""
import glob
import json
import logging
import os

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from tests.utils import make_token

BODY = {"type": "http", "upstream_url": "http://127.0.0.1:9901/api/v1",
        "headers": {"Authorization": "Bearer sk-real-12345678",
                    "X-Plain-Header": "visible-plain-value"}}


@pytest.fixture
def body_env(monkeypatch):
    monkeypatch.setenv("TRACE_MODE", "body")
    yield
    from agent_proxy import trace
    trace.configure("metadata", 64 * 1024)  # 恢复进程级全局（集成夹具 app 会在下次 lifespan 重配）


@pytest_asyncio.fixture
async def body_app(body_env):
    from agent_proxy import trace
    from agent_proxy.config import Settings
    from agent_proxy.main import create_app

    application = create_app(Settings.from_env(os.environ))
    async with application.router.lifespan_context(application):
        trace.configure("body", application.state.settings.trace_body_max_size)  # 钉住全局
        yield application


@pytest_asyncio.fixture
async def body_client(body_app):
    async with AsyncClient(transport=ASGITransport(app=body_app),
                           base_url="http://testserver") as c:
        yield c


def _trace_records():
    records = []
    for path in glob.glob("logs-test/trace.log.*"):
        with open(path, encoding="utf-8") as fh:
            records.extend(json.loads(x) for x in fh.read().splitlines() if x.strip())
    return records


async def test_proxy_trace_body_mode_records_and_redacts_query(body_client):
    from agent_proxy.logging_setup import flush_trace

    resp = await body_client.post("/api/v1/mappings", json=BODY,
                                  headers={"Authorization": f"Bearer {make_token('u888')}"})
    assert resp.status_code == 201
    mid = resp.json()["mapping_id"]
    resp = await body_client.get(f"/p/{mid}/orders?token=secret-token-12345678&status=paid",
                                 headers={"Authorization": f"Bearer {make_token('u888')}"})
    assert resp.status_code == 200
    flush_trace()

    recs = _trace_records()
    req = [r for r in recs if r.get("mapping_id") == mid and r["phase"] == "request"]
    assert req, "body 模式下 /p/ 转发应有 request 记录"
    # 设计 §11.1：response 行只有 request_id（无 mapping_id），按 request_id 关联
    rsp = [r for r in recs if r["phase"] == "response"
           and r["request_id"] == req[0]["request_id"]]
    assert rsp, "body 模式下 /p/ 转发应有 response 记录"

    # URL query 值脱敏（键名保留，值指纹化；"secret-token-12345678" 长 21）
    url = req[0]["url"]
    assert "secret-token-12345678" not in url
    assert "token=secr****5678(len=21)" in url
    assert "status=****(len=4)" in url

    # body 模式：非敏感头显原值，敏感头指纹化（"Bearer sk-real-12345678" 长 23）。
    # 计划原稿用首字母大写 key 取值——Task 1 评审修复后出站 key 统一小写归一，
    # trace 记的是实际发出的 outbound，故按小写 key 断言（语义不变）。
    assert req[0]["headers"]["x-plain-header"] == "visible-plain-value"
    assert req[0]["headers"]["authorization"] == "Bear****5678(len=23)"
    assert "sk-real-12345678" not in json.dumps(req[0])

    # 响应记录：状态码 + body（echo JSON，截断上限内）
    assert rsp[0]["status"] == 200
    assert '"path":"/orders"' in rsp[0]["body"] and rsp[0]["body_truncated"] is False
    # 代理生成的响应 headers 字段同样打码（§11.1：上游响应敏感头同样打码）；
    # body 原文属上游载荷（echo 回显 authorization），不在打码范围（见模块 docstring）
    assert "sk-real-12345678" not in json.dumps(rsp[0]["headers"])
