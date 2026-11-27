"""agent-proxy 性能基准（对真实 Docker 容器；结果供公共服务容量评估）。

场景（隔离因素说明）：
- healthz：进程/网络基线（无鉴权、无缓存、无转发）
- resolve：管理 API + Redis 缓存命中路径（third_party 鉴权缓存命中后）
- forward：/p/ 全管线 = 验签缓存 + 映射缓存 + 审计落盘 + 流式转发到本地 echo
  （echo 在本机 9901——隔离公网上游网络，量出代理自身每请求开销）

鉴权：Authorization: Token <真实JWT>（third_party 验签，进程内 60s TTL 缓存——
  预热后基准窗口内不再出网；冷启动单次验签 RTT 另计，不在本数字内）。

运行：temp/bench_proxy.py <JWT>
"""
import asyncio
import json
import os
import sys
import time

import httpx

BASE = "http://127.0.0.1:8800"
ECHO_UPSTREAM = "http://127.0.0.1:9901/api/v1"
TOK = "Token " + sys.argv[1]
AUTH = {"Authorization": TOK}


def pct(sorted_latencies: list[float], p: float) -> float:
    return sorted_latencies[min(int(len(sorted_latencies) * p), len(sorted_latencies) - 1)]


async def bench(client: httpx.AsyncClient, name: str, method: str, url: str,
                *, n: int, concurrency: int, headers: dict | None = None,
                json_body: dict | None = None) -> dict:
    lat = []
    errors = 0
    sem = asyncio.Semaphore(concurrency)
    t0 = time.perf_counter()

    async def one():
        nonlocal errors
        async with sem:
            t = time.perf_counter()
            try:
                resp = await client.request(method, url, headers=headers, json=json_body)
                if resp.status_code >= 400:
                    errors += 1
                await resp.aread()
            except Exception:
                errors += 1
            lat.append(time.perf_counter() - t)

    await asyncio.gather(*(one() for _ in range(n)))
    wall = time.perf_counter() - t0
    lat.sort()
    return {"name": name, "n": n, "c": concurrency, "errors": errors,
            "rps": round(n / wall, 1), "p50": round(pct(lat, .50) * 1000, 1),
            "p95": round(pct(lat, .95) * 1000, 1), "p99": round(pct(lat, .99) * 1000, 1),
            "max": round(lat[-1] * 1000, 1)}


async def main() -> None:
    token = sys.argv[1]
    results = []
    async with httpx.AsyncClient(timeout=30, trust_env=False,
                                 limits=httpx.Limits(max_connections=300)) as c:
        # 预热：验签缓存（60s TTL）+ 映射缓存 + 连接池
        warm = await c.get(f"{BASE}/p/4oDbQoYTBWB9/api/v1/final", headers=AUTH)
        print(f"预热: {warm.status_code}（首次含冷验签 RTT）")
        for _ in range(30):
            await c.get(f"{BASE}/healthz")

        # 场景 1：健康检查基线
        results.append(await bench(c, "healthz 基线", "GET", f"{BASE}/healthz",
                                   n=500, concurrency=50))
        # 场景 2：resolve（管理 API + 缓存命中）
        results.append(await bench(c, "resolve?name=（缓存命中）", "GET",
                                   f"{BASE}/api/v1/mappings/resolve?name=personal-agent-email-mcp",
                                   n=500, concurrency=50, headers=AUTH))
        # 场景 3：/p/ 全管线转发 → 本地 echo
        results.append(await bench(c, "forward /p/ → echo（全管线）", "GET",
                                   f"{BASE}/p/4oDbQoYTBWB9/api/v1/final",
                                   n=1000, concurrency=50, headers=AUTH))
        results.append(await bench(c, "forward /p/ → echo（c=10）", "GET",
                                   f"{BASE}/p/4oDbQoYTBWB9/api/v1/final",
                                   n=500, concurrency=10, headers=AUTH))

    rows = "\n".join(
        f"| {r['name']} | {r['n']} | {r['c']} | {r['rps']} | {r['p50']} | {r['p95']} | "
        f"{r['p99']} | {r['max']} | {r['errors']} |"
        for r in results)
    report = (
        "# agent-proxy 性能基准（2026-11-26，本机 Docker 单容器 + 宿主机 Redis/MySQL + 本机 echo 上游）\n\n"
        "| 场景 | 请求数 | 并发 | RPS | p50(ms) | p95(ms) | p99(ms) | max(ms) | 错误 |\n"
        "|---|---|---|---|---|---|---|---|---|\n" + rows + "\n\n"
        "说明：third_party 验签在预热后 60s TTL 内不出网（基准窗口覆盖在内）；\n"
        "冷启动（新 token 首请求）另付一次 beta 验签 RTT。echo 上游在本机——数字\n"
        "代表代理自身开销；真实公网上游延迟由上游主导。\n")
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "perf_report.md")
    with open(out, "w", encoding="utf-8") as f:
        f.write(report)
    print(report)


if __name__ == "__main__":
    asyncio.run(main())
