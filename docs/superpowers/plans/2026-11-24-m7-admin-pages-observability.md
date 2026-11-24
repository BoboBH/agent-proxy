# M7 实施计划：Web 管理页面（LoginProvider + SSO 会话）+ Prometheus 完善 + M5 残余扫尾

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 交付 agent-proxy M7（设计 §15 全章 + §16 M7 行）：`LoginProvider` 抽象与 stub 实现（`sso/login.py`，与 TokenVerifier 同风格；login_url(return_to) / exchange(ticket)→Identity）；服务端会话（Redis `ap:sess:{sid}`，TTL `ADMIN_SESSION_TTL`=28800s，Cookie `ap_sess` HttpOnly+SameSite=Lax+Secure 配置化，退出登录删除会话）；`get_current_identity` 双通道（Bearer 优先、失败不回退、无 Bearer 回退 Cookie，既有 API 零破坏）；Web 管理页面（Jinja2 + 原生 JS fetch，无前端构建链：我的映射 / 内置 MCP / 公共映射管理（仅 admin）/ 退出登录，页面 API 全走既有 `/api/v1`，不做越权捷径）；Prometheus §15.2 八项指标完整性与基数受控的断言与文档；M5 终审遗留扫尾（推送流 body 模式 trace 断言、`_first_message_data` 多行 data 已知限制钉住、c/d 项核对）；README/设计注记回写。

**Architecture:** 延续 M1–M6 分层 `api → services → forward/oauth/sso → infra`。新增 `sso` 包两个模块：`login.py`（LoginProvider Protocol + StubLoginProvider + build_login_provider/get_login_provider）与 `session.py`（会话存取：`create_session/get_session/destroy_session` + Cookie 常量 + Identity 载荷编解码）。新增 `api/admin_pages.py`（GET /admin、GET /admin/login、GET /admin/auth/callback、POST /admin/logout）与模板目录 `src/agent_proxy/admin/`（index.html + login.html，随包分发）。改造点仅两处：`api/deps.py` 的 `get_current_identity`（双通道）与 `main.py`（注册 admin 路由）；页面消费的全部业务能力为 M1–M6 既有 API，后端零新增业务接口。`middleware.route_name` 的 `/admin` 分支（M1 预留）使页面流量自动计入 `ap_requests_total{route="admin"}`。

**Tech Stack:** Python 3.12（venv `.venv`，Git Bash 下 `.venv/Scripts/python.exe`）、FastAPI、Jinja2（**已在 pyproject 依赖中**，M1 引入，本计划零新增依赖）、httpx、SQLAlchemy 2 async、redis-py 4.6、uvicorn、pytest + pytest-asyncio。**无新增依赖。**

**对应设计文档:** §15.1（Web 管理页面全节：LoginProvider 抽象/stub、登录时序图、服务端会话、双通道兼容、页面清单四页）、§15.2（Prometheus 八项 + 基数控制）、§6.2（`GET /admin/*` 路由位）、§16 M7 验收行（浏览器经 stub 登录完成全部页面操作；Bearer/Cookie 双通道身份；admin 视图权限隔离；/metrics 指标完整且基数受控）、附录 A「管理页面」决策行。

**范围说明:** 本计划只覆盖 M7 + M5 残余扫尾。**Dockerfile 与 docker-compose 属部署交付（用户要求的部署文档单独批次），本计划不含**；公司统一登录（company_sso Provider）真实对接、CSRF 强化、前端增强等入 M8+ 债务节。

**约定（延续 M1–M6）:** 测试令牌 `stub.<base64url(payload)>.sig`（`tests/utils.make_token`，admin 用 `role="admin"`——stub 登录票据与 StubVerifier 同格式，两者互通）；测试库 `agent_proxy_test` + Redis db9、`SSRF_ALLOW_PRIVATE=true`、`LOG_DIR=logs-test`。当前基线 **417 passed** 全绿为出发点（实测确认：`pytest --collect-only` 417 collected）。commit 中文 + `Co-Authored-By: Claude Code <noreply@anthropic.com>`；真实 TCP 测试风格（mock 上游 uvicorn 真实监听，被测代理 9910）。**测试不要与其他进程并发跑（端口 9901-9910 环境约束；如遇端口占用等待重试）。**

**端口簿:** 9901 echo 上游（不变）、9902 MCP SSE mock（不变）、9903 MCP Streamable mock（不变，本计划增补 `/mcp-multiline-data`，M5 扫尾 b）、9904 mock OAuth AS+RS（不变）、9909 死端口（不变）、9910 被测代理（不变）。**无新增端口。**

**关键决策（实现前先读）：**

1. **Cookie `Secure` 属性配置化（`SESSION_COOKIE_SECURE`，默认 false），不写死 true**。设计 §15.1 定稿 HttpOnly+Secure+SameSite=Lax；但本地开发与全部集成测试为纯 http（EXTERNAL_BASE=http://127.0.0.1:9910 / http://testserver），`Secure` Cookie 在 http 下浏览器与 httpx（http.cookiejar 语义）均**不回传**——写死 true 等于页面在开发/测试环境不可用。因此 Secure 落配置项：默认 false（开发/测试），`.env.example` 与设计注记（Task 7）钉死「EXTERNAL_BASE 为 https 的部署必须置 true」；prod 门禁（stub 实现禁启动）不受影响。HttpOnly 与 SameSite=Lax 恒写死（无环境使它们不可用）。
2. **Bearer 优先且失败不回退（钉住语义）**：`get_current_identity` 携带 `Authorization: Bearer` 时走校验，失败即 401——**不回退** Cookie 会话。理由：失效/已撤销凭证被静默回退掩盖 = 已撤销用户凭残留会话继续放行，安全底线不允许；设计「Bearer 优先、无 Bearer 时回退」的字面语义即「有 Bearer 不回退」。改造点唯一（`api/deps.py`），双通道在函数内闭环，全部既有依赖方（mgmt/proxy/builtin）零改动。
3. **页面身份仅消费 Cookie（`_page_identity`），身份上下文由模板服务端注入**：页面是浏览器场景，HTML 入口不消费 Bearer（fetch 的 Cookie 通道已经够用）；`user_name`/`is_admin` 渲染进 index.html（`IS_ADMIN = {{ is_admin | tojson }}`），`is_admin` 仅决定「公共映射管理」入口显隐——真正的权限边界仍在 `/api/v1` 既有矩阵（非 admin 直打 public 创建/client 配置 → 403，页面不做越权捷径 = 入口隐藏 + API 兜底，Task 4 用例钉住两层）。
4. **stub 登录页即 `LoginProvider.stub` 的 `login_url` 目标，票据构造在浏览器侧**：登录页 JS 按 StubVerifier 同格式（`stub.<base64url(JSON)>.sig`）构造票据，GET 提交 `/admin/auth/callback?ticket=...&return_to=...`——与公司 SSO「回跳携带票据」时序同构；callback 经 `exchange` 换 Identity → 建会话 → Set-Cookie → 302。票据无效 → 302 回登录页（`error=invalid_ticket`），不落会话、不显示原始 JSON 错误。`return_to` 仅接受站内相对路径（`/` 开头且非 `//`，`_safe_return_to` 防开放重定向；回跳 Location 组装前 quote，防 CRLF 头注入——沿用 M6 front_redirect 评审结论）。
5. **会话实现最小化**：Redis 键 `ap:sess:{sid}`，值为 Identity 三字段 JSON（不含任何凭证/敏感值）；sid = `secrets.token_hex(16)`（128bit，与 OAuth state 同强度）；TTL 创建时定（`ADMIN_SESSION_TTL`，默认 28800s），**不做滑动续期**（登出即删；过期 Redis 惰性失效；重放已删 sid 无效）——设计未要求续期，最小实现先行，续期策略入 M8+ 债务。Cookie 通道读取失败（Redis 异常）按未登录处理（WARN 日志），不 500。
6. **无会话场景的错误码不新增**：无 Bearer 且无/坏会话 → 401 `INVALID_TOKEN`（与既有 401 面同码，仅 message 更新为「缺少 Authorization: Bearer token 或登录会话」）——设计 §10 错误码表零变更；页面未登录走 302（由页面路由自身判断，不经 get_current_identity 的 401）。
7. **Prometheus 无新指标**：§15.2 八项 M1–M4 已全部接线（middleware：requests_total/request_duration/inflight/bytes_total；forward：upstream_duration/upstream_errors_total/sse_active；oauth：oauth_actions_total），本计划交付的是**完整性与基数红线的断言**（Task 5）+ metrics.py 文档对照 + README 指标清单；`route="admin"` 标签值由页面流量自然产生（M1 预留的 route_name 分支）。
8. **M5 扫尾口径（终审四项）**：a) 推送流 body 模式 trace 断言 = Streamable GET `/mcp`（SSE 解析管线）的 `message` 事件经 `log_sse_event` 落 trace 的集成断言（设计 §8.4 注记的行为面，M3 已实现未断言）；b) `_first_message_data` 多行 data = **已知限制钉住而非实现拼接**（真实 SDK initialize 均单行 data；mock 增 `/mcp-multiline-data` 回归面 + 单测钉首行行为 + 代码注释）；c) M4 Task 6 proxy.py docstring 已做（核对勾选）；d) 401/500 非 2xx 不回落 / SSE 回落触发器矩阵已在 `test_mgmt_test_endpoint.py` 核销（核对勾选）。
9. **模板目录随包分发**：`src/agent_proxy/admin/`，`Jinja2Templates(directory=Path(__file__).resolve().parent.parent / "admin")` 定位——无运行时配置项、无前端构建链（设计 §15.1 页面清单注）。页面 JS 的 DOM 操作全部 esc() 转义后插入（user_name 等模板变量走 Jinja 自动转义）。

---

## 文件结构（M7 变更后）

```
agent-proxy/
├── docs/superpowers/plans/
│   └── 2026-11-24-m7-admin-pages-observability.md   # 本计划
├── docs/superpowers/specs/
│   └── 2026-11-21-agent-proxy-design.md             # [改] §15.1 实现注记回写（Task 7）
├── src/agent_proxy/
│   ├── admin/
│   │   ├── index.html                               # [新] 管理主页面：我的映射 / 内置 MCP /
│   │   │                                            #      公共映射管理（仅 admin）/ 退出登录
│   │   └── login.html                               # [新] stub 假登录页（选择用户/角色，
│   │                                                #      浏览器侧构造票据提交 callback）
│   ├── api/
│   │   ├── admin_pages.py                           # [新] GET /admin · /admin/login ·
│   │   │                                            #      /admin/auth/callback · POST /admin/logout
│   │   └── deps.py                                  # [改] get_current_identity 双通道
│   │                                                #      （Bearer 优先、Cookie 回退）
│   ├── sso/
│   │   ├── __init__.py                              # [新]
│   │   ├── login.py                                 # [新] LoginProvider 抽象 + StubLoginProvider
│   │   │                                            #      + build/get_login_provider
│   │   └── session.py                               # [新] ap:sess:{sid} 会话存取 +
│   │                                                #      SESSION_COOKIE 常量 + 载荷编解码
│   ├── config.py                                    # [改] session_cookie_secure（默认 false）
│   ├── metrics.py                                   # [改] 模块 docstring 对照 §15.2 八项（仅文档）
│   └── main.py                                      # [改] 注册 admin_pages 路由
├── tests/
│   ├── unit/
│   │   ├── test_sso.py                              # [新] Provider/login_url/exchange + 会话键与
│   │   │                                            #      Identity 载荷编解码
│   │   ├── test_config.py                           # [改] session_cookie_secure 默认/环境
│   │   ├── test_deps.py                             # [改] 双通道（Cookie 回退 / Bearer 优先不回退 /
│   │   │                                            #      失效 sid 401）
│   │   └── test_mcp_streamable.py                   # [改] 多行 data 已知限制钉住（M5 扫尾 b）
│   └── integration/
│       ├── test_sso_session.py                      # [新] ap:sess 写读删 + TTL（真实 Redis）
│       ├── test_cookie_channel.py                   # [新] 既有 API 纯 Cookie 通道兼容 + Bearer 优先
│       ├── test_admin_pages.py                      # [新] 页面路由：302/登录页/callback Cookie 属性/
│       │                                            #      上下文注入/开放重定向/logout
│       ├── test_admin_browser_flow.py               # [新] 浏览器式全流程（Cookie Jar）+ 非 admin
│       │                                            #      隔离 + 真实 TCP 冒烟
│       ├── test_metrics_prometheus.py               # [新] §15.2 八项指标族 + 基数受控断言
│       ├── mock_mcp_streamable.py                   # [改] /mcp-multiline-data（M5 扫尾 b 回归面）
│       └── test_proxy_mcp_streamable.py             # [改] 推送流 body 模式 trace 断言（M5 扫尾 a）
│                                                    #      + 多行 data probe 判失败用例
├── .env.example                                     # [改] SESSION_COOKIE_SECURE（Task 1 随 config 落）
└── README.md                                        # [改] 管理页面快速开始 + 接口速览 +
                                                     #      /metrics 指标清单（Task 7）
```

---

### Task 1: `sso` 包基础层——LoginProvider 抽象 + stub 实现 + Redis 服务端会话存取 + `SESSION_COOKIE_SECURE` 配置

**Files:**
- New: `src/agent_proxy/sso/__init__.py`
- New: `src/agent_proxy/sso/login.py`
- New: `src/agent_proxy/sso/session.py`
- Modify: `src/agent_proxy/config.py`（`session_cookie_secure` 字段 + env 解析）
- Modify: `.env.example`（`SESSION_COOKIE_SECURE`）
- New: `tests/unit/test_sso.py`
- Modify: `tests/unit/test_config.py`
- New: `tests/integration/test_sso_session.py`

- [ ] **Step 1: 写失败测试（单元 + 配置）**

`tests/unit/test_sso.py`（新文件）：

```python
"""sso 基础层单测（M7，设计 §15.1）：LoginProvider 抽象与 stub 实现、会话键与
Identity 载荷编解码、Cookie 常量。Redis 存取的集成面见
tests/integration/test_sso_session.py（真实 Redis）。"""
import pytest

from agent_proxy.auth import Identity, TokenInvalidError
from agent_proxy.sso.login import StubLoginProvider, build_login_provider
from agent_proxy.sso.session import (SESSION_COOKIE, SESSION_KEY_PREFIX,
                                     decode_identity, encode_identity,
                                     new_sid, session_key)


# ---------- LoginProvider 抽象 + stub（§15.1 对接抽象） ----------


def test_stub_login_url_carries_encoded_return_to():
    url = StubLoginProvider().login_url("/admin?p=1")
    assert url.startswith("/admin/login?return_to=")
    assert "return_to=%2Fadmin%3Fp%3D1" in url        # return_to 已 URL 编码（safe=""）


async def test_stub_exchange_decodes_ticket_to_identity():
    """stub 票据与 StubVerifier 同格式（tests.utils.make_token 可直接作票据）——
    「公司 SSO 票据校验」在 stub 形态即 JWT 载荷解码，company_sso Provider 实现时替换。"""
    from tests.utils import make_token

    identity = await StubLoginProvider().exchange(
        make_token("u888", role="admin", user_name="张三"))
    assert identity == Identity(user_id="u888", user_name="张三", role="admin")


async def test_stub_exchange_invalid_ticket_raises_token_invalid():
    with pytest.raises(TokenInvalidError):
        await StubLoginProvider().exchange("stub.not-base64!!^.sig")
    with pytest.raises(TokenInvalidError):
        await StubLoginProvider().exchange("")         # 空 ticket 同样 401 面


def test_build_login_provider_stub_type():
    assert isinstance(build_login_provider("stub"), StubLoginProvider)


def test_build_login_provider_unknown_impl_not_implemented():
    with pytest.raises(NotImplementedError):
        build_login_provider("banana")                 # 白名单在 config.validate，双保险


# ---------- 会话键 / Cookie 常量 / Identity 载荷 ----------


def test_session_key_prefix_and_sid_shape():
    assert SESSION_COOKIE == "ap_sess"
    assert SESSION_KEY_PREFIX == "ap:sess:"
    sid = new_sid()
    assert len(sid) == 32 and set(sid) <= set("0123456789abcdef")   # 128bit hex
    assert session_key(sid) == f"ap:sess:{sid}"
    assert len({new_sid(), new_sid(), new_sid()}) == 3               # 随机性（不碰撞）


def test_identity_payload_encode_decode_roundtrip():
    raw = encode_identity(Identity(user_id="u1", user_name="张三", role="admin"))
    assert decode_identity(raw) == Identity(user_id="u1", user_name="张三", role="admin")
    assert decode_identity(encode_identity(Identity(user_id="u2"))) == Identity(user_id="u2")


def test_decode_identity_rejects_malformed_payload():
    assert decode_identity("not-json") is None
    assert decode_identity('{"no_user_id": 1}') is None
    assert decode_identity('{"user_id": 123}') is None              # user_id 必须 str
    assert decode_identity(b'{"user_id": "bin"}') == Identity(user_id="bin")   # bytes 兼容
```

`tests/unit/test_config.py` 追加（文件末尾）：

```python
def test_session_cookie_secure_default_false_and_env_on():
    # M7（§15.1 注记）：Secure 在纯 http 的开发/测试环境使浏览器不回传 Cookie，
    # 故配置化——默认 false；https 部署必须显式置 true
    assert Settings.from_env(BASE).session_cookie_secure is False
    assert Settings.from_env(BASE).admin_session_ttl == 28800
    s = Settings.from_env({**BASE, "SESSION_COOKIE_SECURE": "true"})
    assert s.session_cookie_secure is True
```

- [ ] **Step 2: 运行预期（FAIL）**

```bash
.venv/Scripts/python.exe -m pytest tests/unit/test_sso.py tests/unit/test_config.py -q
```

Expected: `tests/unit/test_sso.py` 收集失败 `ModuleNotFoundError: No module named 'agent_proxy.sso'`；`test_config.py` 新用例 `assert ... session_cookie_secure` AttributeError FAIL。既有用例不受影响。

- [ ] **Step 3: 实现**

`src/agent_proxy/sso/__init__.py`（新文件）：

```python
"""SSO 登录与会话（M7，设计 §15.1）：LoginProvider 抽象 + 服务端会话。"""
```

`src/agent_proxy/sso/login.py`（新文件）：

```python
"""LoginProvider 抽象 + stub 实现（设计 §15.1，与 auth.TokenVerifier 同风格）。

- stub（默认，开发/测试）：login_url 指向本地假登录页 /admin/login（选择用户/角色，
  浏览器侧按 StubVerifier 同格式构造票据提交 callback）；exchange 复用
  TokenVerifier（StubVerifier）解码——「公司 SSO 的票据校验」在 stub 形态即 JWT
  载荷解码，两者票据互通（测试令牌 stub.<b64url 载荷>.sig 可直接作登录票据）；
- company_sso（后续实现，协议实现时定）：对接公司统一登录，注册为独立 Provider 类
  并在 build_login_provider 白名单放行即可——页面与 API 零改动（§15.1 对接抽象行）。
"""
from __future__ import annotations

from typing import Protocol
from urllib.parse import quote

from ..auth import Identity, build_verifier
from ..config import get_settings


class LoginProvider(Protocol):
    def login_url(self, return_to: str) -> str:
        """跳转登录的地址（携带回跳；stub=本地登录页，company_sso=外部统一登录）。"""
        ...

    async def exchange(self, ticket: str) -> Identity:
        """回跳票据换身份；明确无效（无效/过期/格式错）抛 TokenInvalidError。"""
        ...


class StubLoginProvider:
    """本地假登录（仅开发/测试，prod 禁 stub 由 config.validate 门禁）。"""

    def login_url(self, return_to: str) -> str:
        return f"/admin/login?return_to={quote(return_to, safe='')}"

    async def exchange(self, ticket: str) -> Identity:
        return await build_verifier(get_settings().token_verify_impl).verify(ticket)


def build_login_provider(impl: str) -> LoginProvider:
    if impl == "stub":
        return StubLoginProvider()
    raise NotImplementedError(f"未知 LOGIN_IMPL: {impl}")


_provider: LoginProvider | None = None


def get_login_provider() -> LoginProvider:
    """进程级单例（与 api.deps._get_verifier 同风格）：LOGIN_IMPL 一期仅 stub，
    多 app 实例（测试双夹具 ASGI / 真实 TCP 9910）impl 一致，缓存无分叉。"""
    global _provider
    if _provider is None:
        _provider = build_login_provider(get_settings().login_impl)
    return _provider
```

`src/agent_proxy/sso/session.py`（新文件）：

```python
"""服务端会话（设计 §15.1「会话与鉴权兼容」）：Redis ap:sess:{sid} 存 Identity，
Cookie 仅存不透明 sid。

- TTL 创建时定（ADMIN_SESSION_TTL，默认 28800s），Redis 惰性过期；不做滑动续期
  （登出即删；续期策略为 M8+ 债务）；
- 载荷仅 Identity 三字段 JSON——不含任何凭证/敏感值；
- sid = secrets.token_hex(16)（128bit 随机，与 OAuth state 同强度）；
- 读取失败（Redis 异常）按未登录处理（WARN），不 500——页面场景宁可回登录页。
"""
from __future__ import annotations

import json
import logging
import secrets

from ..auth import Identity

log = logging.getLogger("agent_proxy")

SESSION_COOKIE = "ap_sess"
SESSION_KEY_PREFIX = "ap:sess:"


def session_key(sid: str) -> str:
    return f"{SESSION_KEY_PREFIX}{sid}"


def new_sid() -> str:
    return secrets.token_hex(16)


def encode_identity(identity: Identity) -> str:
    return json.dumps({"user_id": identity.user_id,
                       "user_name": identity.user_name,
                       "role": identity.role}, ensure_ascii=False)


def decode_identity(raw: str | bytes) -> Identity | None:
    """载荷非法（坏 JSON / 缺 user_id / user_id 非 str）→ None（按未登录处理，
    不抛——会话数据损坏不该变成 500）。"""
    try:
        payload = json.loads(raw)
    except (TypeError, ValueError):
        return None
    if not isinstance(payload, dict) or not isinstance(payload.get("user_id"), str):
        return None
    return Identity(user_id=payload["user_id"],
                    user_name=payload.get("user_name"), role=payload.get("role"))


async def create_session(r, identity: Identity, ttl: int) -> str:
    """写入会话并返回 sid（TTL 由调用方传：admin_auth_callback 传
    settings.admin_session_ttl）。"""
    sid = new_sid()
    await r.set(session_key(sid), encode_identity(identity), ex=ttl)
    return sid


async def get_session(r, sid: str) -> Identity | None:
    """sid → Identity；无 sid / 键不存在（过期或已登出）/ 载荷非法 / Redis 异常
    → None（上层按未登录处理）。"""
    if not sid:
        return None
    try:
        raw = await r.get(session_key(sid))
    except Exception as exc:
        log.warning("会话读取失败，按未登录处理: %s", exc)
        return None
    if raw is None:
        return None
    return decode_identity(raw)


async def destroy_session(r, sid: str) -> None:
    """退出登录：删除服务端会话（Cookie 中的 sid 随即失效，重放无效）；幂等。"""
    try:
        await r.delete(session_key(sid))
    except Exception as exc:
        log.warning("会话删除失败: %s", exc)
```

`src/agent_proxy/config.py` 修改两处——字段表 `admin_session_ttl` 之后加一行：

```python
    admin_session_ttl: int = 28800
    session_cookie_secure: bool = False
```

`from_env` 中 `admin_session_ttl=...` 行之后加一行：

```python
            admin_session_ttl=_to_int("ADMIN_SESSION_TTL", e.get("ADMIN_SESSION_TTL", "28800")),
            session_cookie_secure=e.get("SESSION_COOKIE_SECURE", "false").lower() == "true",
```

`.env.example`：定位 `ADMIN_SESSION_TTL=28800` 行（OAuth（M6）小节内），将其改为：

```
# 管理页面会话（M6/M7）
ADMIN_SESSION_TTL=28800                         # 服务端会话 TTL（秒）
SESSION_COOKIE_SECURE=false                     # EXTERNAL_BASE 为 https 的部署必须置 true
```

- [ ] **Step 4: 写集成测试并运行（真实 Redis）**

`tests/integration/test_sso_session.py`（新文件）：

```python
"""服务端会话 Redis 存取集成（M7，§15.1）：ap:sess:{sid} 写读删 + TTL 语义
（真实 Redis db9）。"""
from agent_proxy.auth import Identity
from agent_proxy.sso.session import (create_session, destroy_session, get_session,
                                     new_sid, session_key)


async def test_create_then_get_roundtrip_with_ttl(app):
    identity = Identity(user_id="u888", user_name="张三", role="admin")
    sid = await create_session(app.state.redis, identity, 600)
    assert await get_session(app.state.redis, sid) == identity
    ttl = await app.state.redis.ttl(session_key(sid))
    assert 590 <= ttl <= 600                       # 写入即带 TTL（非持久键）


async def test_get_missing_or_garbage_sid_returns_none(app):
    assert await get_session(app.state.redis, "") is None
    assert await get_session(app.state.redis, new_sid()) is None     # 不存在的 sid
    await app.state.redis.set(session_key("junk"), "not-json")
    assert await get_session(app.state.redis, "junk") is None        # 载荷非法 → None


async def test_destroy_session_removes_key_and_is_idempotent(app):
    sid = await create_session(app.state.redis, Identity(user_id="u1"), 600)
    await destroy_session(app.state.redis, sid)
    assert await get_session(app.state.redis, sid) is None
    await destroy_session(app.state.redis, sid)                      # 幂等（重放/重复登出安全）


async def test_session_ttl_argument_from_settings(app):
    """接线形态钉住：admin_auth_callback 以 settings.admin_session_ttl 传参。"""
    settings = app.state.settings
    sid = await create_session(app.state.redis, Identity(user_id="u2"),
                               settings.admin_session_ttl)
    ttl = await app.state.redis.ttl(session_key(sid))
    assert 0 < ttl <= settings.admin_session_ttl
    await destroy_session(app.state.redis, sid)
```

```bash
.venv/Scripts/python.exe -m pytest tests/unit/test_sso.py tests/unit/test_config.py tests/integration/test_sso_session.py -q
```

Expected: 全绿（unit 9 + config 13 + integration 4，本文件视角 26 passed）。

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(M7): sso 包基础层——LoginProvider 抽象+stub 实现、Redis 服务端会话存取（ap:sess:{sid}）、SESSION_COOKIE_SECURE 配置" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

### Task 2: `get_current_identity` 双通道——Bearer 优先（失败不回退）+ Cookie 会话回退

**Files:**
- Modify: `src/agent_proxy/api/deps.py`
- Modify: `tests/unit/test_deps.py`
- New: `tests/integration/test_cookie_channel.py`

- [ ] **Step 1: 写失败测试（单元）**

`tests/unit/test_deps.py` 整文件替换为（既有 6 用例保留原断言，新增双通道 5 用例）：

```python
import os
from types import SimpleNamespace

os.environ.setdefault("TOKEN_VERIFY_IMPL", "stub")

import pytest
from starlette.requests import Request

from agent_proxy.api.deps import get_current_identity, is_admin
from agent_proxy.auth import Identity, TokenInvalidError
from agent_proxy.sso.session import SESSION_COOKIE, encode_identity, session_key
from tests.utils import make_token


class _FakeRedis:
    """Cookie 通道的最小替身：单测不依赖真实 Redis（集成面见 test_cookie_channel.py）。"""

    def __init__(self, store: dict[str, str] | None = None):
        self.store = dict(store or {})

    async def get(self, key: str):
        return self.store.get(key)


def _request(headers: list[tuple[bytes, bytes]], redis: _FakeRedis | None = None) -> Request:
    # Cookie 通道经 request.app.state.redis 取会话——scope 常挂最小 app 替身；
    # Bearer 通道不触达 app，既有用例不受影响
    return Request(scope={"type": "http", "headers": headers, "state": {},
                          "app": SimpleNamespace(state=SimpleNamespace(redis=redis or _FakeRedis()))})


def _session(sid: str, **claims) -> _FakeRedis:
    uid = claims.pop("user_id")
    return _FakeRedis({session_key(sid): encode_identity(Identity(user_id=uid, **claims))})


async def test_missing_authorization_header():
    req = _request([])
    with pytest.raises(TokenInvalidError) as excinfo:
        await get_current_identity(req)
    assert (excinfo.value.status, excinfo.value.code) == (401, "INVALID_TOKEN")


async def test_non_bearer_scheme_rejected():
    req = _request([(b"authorization", b"Basic dXNlcjpwYXNz")])
    with pytest.raises(TokenInvalidError) as excinfo:
        await get_current_identity(req)
    assert (excinfo.value.status, excinfo.value.code) == (401, "INVALID_TOKEN")


async def test_valid_bearer_writes_state():
    req = _request([(b"authorization", f"Bearer {make_token('u777', role='admin')}".encode())])
    identity = await get_current_identity(req)
    assert identity.user_id == "u777"
    assert identity.role == "admin"
    assert identity.user_name == "张三"
    assert req.state.uid == "u777"
    assert req.state.user_name == "张三"


async def test_non_dict_payload_rejected_as_401():
    req = _request([(b"authorization", b"Bearer stub.MTIz.sig")])  # payload=123 非 dict
    with pytest.raises(TokenInvalidError) as excinfo:
        await get_current_identity(req)
    assert (excinfo.value.status, excinfo.value.code) == (401, "INVALID_TOKEN")


# ---------- M7 双通道：Cookie 会话回退（§15.1「会话与鉴权兼容」） ----------


async def test_cookie_session_fallback_resolves_identity():
    sid = "a" * 32
    redis = _session(sid, user_id="u555", user_name="李四")
    req = _request([(b"cookie", f"{SESSION_COOKIE}={sid}".encode())], redis=redis)
    identity = await get_current_identity(req)
    assert identity.user_id == "u555" and identity.user_name == "李四"
    assert req.state.uid == "u555" and req.state.user_name == "李四"   # 审计身份照常写入


async def test_bearer_precedence_over_cookie_session():
    """Bearer 优先（§15.1）：双通道并存以 Bearer 身份为准（Agent/API 场景语义不变）。"""
    sid = "b" * 32
    redis = _session(sid, user_id="u999")
    req = _request([(b"authorization", f"Bearer {make_token('u777')}".encode()),
                    (b"cookie", f"{SESSION_COOKIE}={sid}".encode())], redis=redis)
    assert (await get_current_identity(req)).user_id == "u777"


async def test_invalid_bearer_does_not_fall_back_to_cookie():
    """Bearer 优先且失败不回退（钉住语义）：带失效 Bearer 却静默回退会话 = 已撤销
    凭证被会话掩盖继续放行，安全底线不允许。"""
    sid = "c" * 32
    redis = _session(sid, user_id="u555")
    req = _request([(b"authorization", b"Bearer stub.broken.sig"),
                    (b"cookie", f"{SESSION_COOKIE}={sid}".encode())], redis=redis)
    with pytest.raises(TokenInvalidError):
        await get_current_identity(req)


async def test_cookie_unknown_or_garbage_sid_401():
    redis = _session("d" * 32, user_id="u555")     # 有效会话在别处；两个 sid 都查不到
    for cookie_value in ("e" * 32, "garbage"):
        req = _request([(b"cookie", f"{SESSION_COOKIE}={cookie_value}".encode())], redis=redis)
        with pytest.raises(TokenInvalidError):
            await get_current_identity(req)


async def test_no_bearer_no_cookie_401():
    req = _request([])
    with pytest.raises(TokenInvalidError):
        await get_current_identity(req)


def test_is_admin_matches_role():
    assert is_admin(Identity(user_id="u1", role="admin"), "admin")


def test_is_admin_false_when_role_mismatch_or_none():
    assert not is_admin(Identity(user_id="u1", role="viewer"), "admin")
    assert not is_admin(Identity(user_id="u1"), "admin")
```

- [ ] **Step 2: 运行预期（FAIL）**

```bash
.venv/Scripts/python.exe -m pytest tests/unit/test_deps.py -q
```

Expected: `ModuleNotFoundError: No module named 'agent_proxy.sso'`（Task 1 已落地 sso 后，则为 5 个新用例 FAIL：cookie 通道尚未实现 → cookie 用例 401 而非身份、`SESSION_COOKIE` 导入失败等）。既有 Bearer 用例全绿。

- [ ] **Step 3: 实现**

`src/agent_proxy/api/deps.py` 整文件替换为：

```python
"""FastAPI 依赖。"""
from __future__ import annotations

from fastapi import Request

from ..auth import Identity, TokenInvalidError, build_verifier
from ..config import get_settings
from ..sso.session import SESSION_COOKIE, get_session


async def get_db(request: Request):
    async with request.app.state.sessionmaker() as session:
        yield session


_verifier = None


def _get_verifier():
    global _verifier
    if _verifier is None:
        _verifier = build_verifier(get_settings().token_verify_impl)
    return _verifier


async def get_current_identity(request: Request) -> Identity:
    """身份双通道（M7，设计 §15.1「会话与鉴权兼容」）：

    - Bearer 优先：Agent / API 场景语义不变；携带 Bearer 而校验失败 → 401，
      **不回退** Cookie——失效凭证被静默回退掩盖 = 已撤销用户凭残留会话放行；
    - 无 Bearer → Cookie 会话回退（管理页面场景，服务端会话 ap:sess:{sid}）；
    - 两通道均未命中 → 401 INVALID_TOKEN（既有 401 面同码，仅 message 更新，
      设计 §10 错误码表零变更）。
    """
    header = request.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        identity = await _get_verifier().verify(header[7:].strip())
    else:
        identity = await _session_identity(request)
        if identity is None:
            raise TokenInvalidError("缺少 Authorization: Bearer token 或登录会话")
    request.state.uid = identity.user_id
    request.state.user_name = identity.user_name or ""
    return identity


async def _session_identity(request: Request) -> Identity | None:
    """Cookie 通道：ap_sess → ap:sess:{sid} → Identity；无 Cookie / 会话不存在 /
    过期（Redis TTL 惰性删除）/ 载荷非法 → None（上层按未登录 401 处理）。"""
    sid = request.cookies.get(SESSION_COOKIE, "")
    if not sid:
        return None
    return await get_session(request.app.state.redis, sid)


def is_admin(identity: Identity, admin_role: str) -> bool:
    return identity.role == admin_role
```

- [ ] **Step 4: 写集成测试并运行**

`tests/integration/test_cookie_channel.py`（新文件）：

```python
"""既有 API 的 Cookie 通道兼容（M7，§15.1「既有 API 兼容零破坏」）：同一
get_current_identity 下 /api/v1 以纯 Cookie 会话访问（页面 fetch 场景）；
Bearer 通道与优先级零破坏。"""
from agent_proxy.auth import Identity
from agent_proxy.sso.session import SESSION_COOKIE, create_session, destroy_session
from tests.utils import make_token

BODY = {"type": "http", "upstream_url": "http://10.0.0.5/api/v1",
        "headers": {"Authorization": "Bearer sk-real-key"}}


async def test_mgmt_create_list_with_cookie_session_only(client, app):
    sid = await create_session(app.state.redis, Identity(user_id="u888", user_name="张三"), 600)
    r = await client.post("/api/v1/mappings", json=BODY, cookies={SESSION_COOKIE: sid})
    assert r.status_code == 201 and r.json()["mapping_id"]
    r = await client.get("/api/v1/mappings", cookies={SESSION_COOKIE: sid})
    assert r.status_code == 200 and len(r.json()) == 1
    assert r.json()[0]["upstream_url"] == BODY["upstream_url"]


async def test_bearer_takes_precedence_over_cookie_in_api(client, app):
    r = await client.post("/api/v1/mappings", json=BODY,
                          headers={"Authorization": f"Bearer {make_token('u888')}"})
    assert r.status_code == 201
    sid = await create_session(app.state.redis, Identity(user_id="u999"), 600)
    r = await client.get("/api/v1/mappings",
                         headers={"Authorization": f"Bearer {make_token('u888')}"},
                         cookies={SESSION_COOKIE: sid})
    # Bearer（u888）优先于 Cookie（u999）：返回 u888 的 1 条而非 u999 的空列表
    assert r.status_code == 200 and len(r.json()) == 1


async def test_destroyed_session_cookie_401(client, app):
    sid = await create_session(app.state.redis, Identity(user_id="u888"), 600)
    await destroy_session(app.state.redis, sid)
    r = await client.get("/api/v1/mappings", cookies={SESSION_COOKIE: sid})
    assert r.status_code == 401 and r.json()["code"] == "INVALID_TOKEN"


async def test_missing_credentials_401_unchanged(client):
    r = await client.get("/api/v1/mappings")
    assert r.status_code == 401 and r.json()["code"] == "INVALID_TOKEN"


async def test_cookie_channel_public_visibility_guard(client, app):
    """Cookie 通道下权限矩阵照旧生效（页面不做越权捷径的 API 侧兜底）。"""
    sid = await create_session(app.state.redis, Identity(user_id="u888"), 600)
    r = await client.post("/api/v1/mappings", json={**BODY, "visibility": "public"},
                          cookies={SESSION_COOKIE: sid})
    assert r.status_code == 403 and r.json()["code"] == "FORBIDDEN"
```

```bash
.venv/Scripts/python.exe -m pytest tests/unit/test_deps.py tests/integration/test_cookie_channel.py -q
```

Expected: 全绿（deps 11 + cookie_channel 5 = 16 passed）。

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(M7): get_current_identity 双通道——Bearer 优先（失败不回退）、无 Bearer 回退 Cookie 会话，既有 API 零破坏" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

### Task 3: 管理页面路由——`/admin` 入口 + stub 登录页 + callback 建会话 + 退出登录（Jinja2 模板）

**Files:**
- New: `src/agent_proxy/api/admin_pages.py`
- New: `src/agent_proxy/admin/login.html`
- New: `src/agent_proxy/admin/index.html`
- Modify: `src/agent_proxy/main.py`
- New: `tests/integration/test_admin_pages.py`

- [ ] **Step 1: 写失败测试**

`tests/integration/test_admin_pages.py`（新文件）：

```python
"""管理页面路由集成（M7，§15.1）：入口 302、stub 登录页、callback 建会话
（Set-Cookie 属性 + Redis 键）、模板身份注入与 admin 视图隔离、开放重定向防护、
退出登录。页面 fetch 的业务流（Cookie 通道走 /api/v1）见 test_admin_browser_flow.py。"""
import json
from urllib.parse import quote

from agent_proxy.auth import Identity
from agent_proxy.sso.session import SESSION_COOKIE, create_session, session_key
from tests.utils import make_token

ADMIN = "/admin"


async def test_admin_without_session_redirects_to_login(client):
    r = await client.get(ADMIN)
    assert r.status_code == 302
    assert r.headers["location"] == "/admin/login?return_to=%2Fadmin"
    assert r.headers.get("set-cookie") is None       # 未登录不落任何 Cookie


async def test_stub_login_page_renders_with_callback_form(client):
    r = await client.get("/admin/login?return_to=%2Fadmin")
    assert r.status_code == 200
    assert 'action="/admin/auth/callback"' in r.text
    assert 'name="return_to"' in r.text
    assert 'id="user_id"' in r.text
    assert '<option value="admin">' in r.text        # 角色选择（admin 即管理员）


async def test_callback_builds_session_and_cookie_attributes(client, app):
    """§15.1 时序 4-6：exchange → 会话入 Redis → Set-Cookie（HttpOnly+SameSite=Lax；
    Secure 由 SESSION_COOKIE_SECURE 配置，测试环境 http 下为 false）→ 302 /admin。"""
    r = await client.get(f"/admin/auth/callback?ticket={make_token('u888', user_name='张三')}")
    assert r.status_code == 302 and r.headers["location"] == "/admin"
    set_cookie = r.headers["set-cookie"]
    assert f"{SESSION_COOKIE}=" in set_cookie
    assert "httponly" in set_cookie.lower()
    assert "samesite=lax" in set_cookie.lower()
    assert "max-age=28800" in set_cookie.lower()     # ADMIN_SESSION_TTL 默认值
    assert "secure" not in set_cookie.lower()        # SESSION_COOKIE_SECURE=false（测试环境）
    raw = await app.state.redis.get(session_key(r.cookies[SESSION_COOKIE]))
    assert raw and json.loads(raw)["user_id"] == "u888"   # 服务端会话已入 Redis


async def test_callback_session_ttl_uses_admin_session_ttl(client, app):
    r = await client.get(f"/admin/auth/callback?ticket={make_token('u1')}")
    ttl = await app.state.redis.ttl(session_key(r.cookies[SESSION_COOKIE]))
    assert 0 < ttl <= app.state.settings.admin_session_ttl
    assert ttl > 8000                                # 非「秒级误传」形态


async def test_admin_renders_with_session_and_identity_context(client, app):
    sid = await create_session(app.state.redis,
                               Identity(user_id="u888", user_name="张三"), 600)
    r = await client.get(ADMIN, cookies={SESSION_COOKIE: sid})
    assert r.status_code == 200
    assert "张三" in r.text                          # 身份上下文由模板注入（§15.1）
    assert "公共映射管理" not in r.text              # 非 admin 视图隔离
    assert 'data-view="public"' not in r.text


async def test_admin_context_admin_role_shows_public_view(client, app):
    sid = await create_session(app.state.redis,
                               Identity(user_id="boss", user_name="管理员", role="admin"), 600)
    r = await client.get(ADMIN, cookies={SESSION_COOKIE: sid})
    assert r.status_code == 200
    assert "公共映射管理" in r.text and 'data-view="public"' in r.text


async def test_callback_invalid_ticket_redirects_login_without_session(client, app):
    r = await client.get(f"/admin/auth/callback?ticket=stub.bad!!.sig&return_to=%2Fadmin")
    assert r.status_code == 302
    assert r.headers["location"].startswith("/admin/login?")
    assert "invalid_ticket" in r.headers["location"]
    assert r.headers.get("set-cookie") is None       # 不落会话
    keys = [k async for k in app.state.redis.scan_iter("ap:sess:*")]
    assert keys == []                                # Redis 无会话残留


async def test_callback_return_to_open_redirect_neutralized(client):
    """return_to 仅站内相对路径（/ 开头且非 //）：绝对地址 / 协议相对地址一律回 /admin。"""
    for bad in ("//evil.com", "https://evil.com/x", "javascript:alert(1)"):
        r = await client.get(
            f"/admin/auth/callback?ticket={make_token('u1')}&return_to={quote(bad, safe='')}")
        assert r.status_code == 302
        assert r.headers["location"] == "/admin"


async def test_logout_deletes_server_session_and_cookie(client, app):
    sid = await create_session(app.state.redis, Identity(user_id="u888"), 600)
    r = await client.post("/admin/logout", cookies={SESSION_COOKIE: sid})
    assert r.status_code == 302
    assert r.headers["location"].startswith("/admin/login")
    assert await app.state.redis.get(session_key(sid)) is None   # 服务端会话已删（§15.1）
    assert "max-age=0" in r.headers["set-cookie"].lower()        # 清浏览器 Cookie
    assert (await client.get(ADMIN, cookies={SESSION_COOKIE: sid})).status_code == 302
```

- [ ] **Step 2: 运行预期（FAIL）**

```bash
.venv/Scripts/python.exe -m pytest tests/integration/test_admin_pages.py -q
```

Expected: 9 用例全 FAIL（`/admin` 404 Not Found——路由未注册）。

- [ ] **Step 3: 实现**

`src/agent_proxy/api/admin_pages.py`（新文件）：

```python
"""Web 管理页面（M7，设计 §15.1）：本服务托管，Jinja2 + 原生 JS fetch，无前端构建链。

路由（tags=["admin"]；middleware.route_name 已把 /admin* 归 route=admin——M1 预留，
ap_requests_total{route="admin"} 由既有中间件自动生效，§15.2）：
- GET  /admin                页面入口：会话有效 → 渲染 index（身份注入模板上下文，
                             is_admin 决定「公共映射管理」入口显隐；权限边界仍在 API，
                             页面不做越权捷径）；无会话 → 302 LoginProvider.login_url
- GET  /admin/login          stub 假登录页（LOGIN_IMPL=stub）：选择用户/角色，浏览器侧
                             按 StubVerifier 同格式构造票据提交 callback；company_sso
                             接入后 login_url 指向外部登录地址，本页自然旁路
- GET  /admin/auth/callback  承接回跳（§15.1 时序 4-6）：exchange(ticket) → Identity →
                             服务端会话入 Redis ap:sess:{sid}（TTL=ADMIN_SESSION_TTL）→
                             Set-Cookie ap_sess（HttpOnly+SameSite=Lax，Secure 由
                             SESSION_COOKIE_SECURE 配置）→ 302 return_to（仅站内路径）；
                             票据无效 → 302 回登录页（error=invalid_ticket，不落会话，
                             页面不显示原始 JSON 错误）
- POST /admin/logout         退出登录（§15.1「退出登录删除会话」）：删 Redis 会话
                             （Cookie 中的 sid 随即失效、重放无效）+ 清 Cookie → 302 登录页

页面 API 全部走既有 /api/v1 接口（同源 fetch 默认携带 Cookie，get_current_identity
Cookie 回退通道，§15.1「既有 API 兼容零破坏」）；页面本身不写任何业务数据。
"""
from __future__ import annotations

from pathlib import Path
from urllib.parse import quote

from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from ..auth import Identity
from ..config import Settings, get_settings
from ..errors import TokenInvalidError
from ..sso.login import get_login_provider
from ..sso.session import SESSION_COOKIE, create_session, destroy_session, get_session

router = APIRouter(tags=["admin"])
# 模板随包分发：src/agent_proxy/admin/（无运行时配置项，Path(__file__) 定位）
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent.parent / "admin"))


def _safe_return_to(return_to: str) -> str:
    """仅接受站内相对路径（/ 开头且非 //），防开放重定向；其余回 /admin。
    （沿用 M6 front_redirect 评审结论：跳转目标必须是服务端可判定的白名单形态。）"""
    if return_to.startswith("/") and not return_to.startswith("//"):
        return return_to
    return "/admin"


async def _page_identity(request: Request) -> Identity | None:
    """页面身份：仅会话 Cookie（页面为浏览器场景，不消费 Bearer——HTML 入口的
    Bearer 无意义且会干扰「未登录 → 302 登录」的判定）。"""
    return await get_session(request.app.state.redis,
                             request.cookies.get(SESSION_COOKIE, ""))


def _set_session_cookie(response: RedirectResponse, settings: Settings, sid: str) -> None:
    response.set_cookie(SESSION_COOKIE, sid, max_age=settings.admin_session_ttl,
                        path="/", httponly=True, samesite="lax",
                        secure=settings.session_cookie_secure)


@router.get("/admin")
async def admin_index(request: Request, settings: Settings = Depends(get_settings)):
    identity = await _page_identity(request)
    if identity is None:
        return RedirectResponse(get_login_provider().login_url("/admin"), status_code=302)
    request.state.uid = identity.user_id                       # 审计身份（middleware 行）
    request.state.user_name = identity.user_name or ""
    request.state.audit_action = "view_admin_page"
    return templates.TemplateResponse(request, "index.html", {
        "user_name": identity.user_name or identity.user_id,
        # is_admin 仅决定入口显隐；越权请求仍由 /api/v1 既有权限矩阵兜底（403/404）
        "is_admin": identity.role == settings.admin_role,
    })


@router.get("/admin/login")
async def admin_login(request: Request, return_to: str = "/admin", error: str = ""):
    request.state.audit_action = "view_login_page"
    return templates.TemplateResponse(request, "login.html", {
        "return_to": _safe_return_to(return_to), "error": error})


@router.get("/admin/auth/callback")
async def admin_auth_callback(request: Request, settings: Settings = Depends(get_settings),
                              ticket: str = "", return_to: str = "/admin"):
    """§15.1 时序 4-6：票据换身份 → 建服务端会话 → Set-Cookie → 302 回页面。
    票据无效不落会话，302 回登录页带 error=invalid_ticket（浏览器友好，排障靠
    服务端日志）；return_to 先过 _safe_return_to，组装 Location 前 quote（防
    CRLF 头注入——M6 front_redirect 评审同款结论）。"""
    try:
        identity = await get_login_provider().exchange(ticket)
    except TokenInvalidError:
        back = quote(f"/admin/login?error=invalid_ticket&return_to="
                     f"{_safe_return_to(return_to)}", safe="/?=&")
        return RedirectResponse(back, status_code=302)
    sid = await create_session(request.app.state.redis, identity,
                               settings.admin_session_ttl)
    request.state.uid = identity.user_id
    request.state.user_name = identity.user_name or ""
    request.state.audit_action = "admin_login"
    response = RedirectResponse(_safe_return_to(return_to), status_code=302)
    _set_session_cookie(response, settings, sid)
    return response


@router.post("/admin/logout")
async def admin_logout(request: Request, settings: Settings = Depends(get_settings)):
    """退出登录：服务端会话删除后 Cookie 中的 sid 立即失效（重放无效），再清
    浏览器 Cookie → 302 登录页。POST（状态变更不走 GET 链接）。"""
    sid = request.cookies.get(SESSION_COOKIE, "")
    if sid:
        await destroy_session(request.app.state.redis, sid)
    request.state.audit_action = "admin_logout"
    response = RedirectResponse(get_login_provider().login_url("/admin"), status_code=302)
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response
```

`src/agent_proxy/admin/login.html`（新文件）：

```html
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>agent-proxy 登录</title>
<style>
  body { font-family: system-ui, -apple-system, sans-serif; max-width: 420px; margin: 72px auto; color: #1f2328; }
  h2 { font-size: 18px; }
  .hint { color: #57606a; font-size: 13px; }
  .error { color: #cf222e; }
  label { display: block; margin: 12px 0 4px; font-size: 13px; color: #57606a; }
  input, select, button { width: 100%; box-sizing: border-box; padding: 8px; font-size: 15px; }
  button { margin-top: 18px; background: #1a7f64; color: #fff; border: 0; border-radius: 6px; cursor: pointer; }
</style>
</head>
<body>
<h2>agent-proxy 管理页面</h2>
{% if error %}<p class="error">登录失败：票据无效或已过期，请重试。</p>{% endif %}
<p class="hint">当前为 LOGIN_IMPL=stub 本地假登录（仅开发/测试）：填写用户与角色提交即换取
服务端会话。生产环境由公司统一登录（LoginProvider=company_sso）替换本页，本服务不提供注册。</p>
<form id="login-form" action="/admin/auth/callback" method="get">
  <input type="hidden" name="return_to" value="{{ return_to }}">
  <label for="user_id">用户 ID</label>
  <input id="user_id" required placeholder="如 u888">
  <label for="user_name">显示名（可选）</label>
  <input id="user_name" placeholder="如 张三">
  <label for="role">角色</label>
  <select id="role">
    <option value="">普通用户</option>
    <option value="admin">admin（管理员）</option>
  </select>
  <button type="submit">登录</button>
</form>
<script>
"use strict";
// stub 票据与 StubVerifier 同格式：stub.<base64url(JSON)>.sig——浏览器侧构造后
// 提交 /admin/auth/callback，由 LoginProvider.exchange 换取服务端会话（与公司
// SSO「回跳携带票据」时序同构；company_sso 接入后本页由外部登录页替代）。
document.getElementById("login-form").addEventListener("submit", function (ev) {
  ev.preventDefault();
  var claims = {
    user_id: document.getElementById("user_id").value.trim(),
    user_name: document.getElementById("user_name").value.trim() || null,
    role: document.getElementById("role").value || null,
  };
  if (!claims.user_id) return;
  var b64 = btoa(unescape(encodeURIComponent(JSON.stringify(claims))))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  var params = new URLSearchParams({
    ticket: "stub." + b64 + ".sig",
    return_to: document.getElementsByName("return_to")[0].value,
  });
  location.href = "/admin/auth/callback?" + params.toString();
});
</script>
</body>
</html>
```

`src/agent_proxy/admin/index.html`（新文件）：

```html
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>agent-proxy 管理页面</title>
<style>
  body { font-family: system-ui, -apple-system, sans-serif; margin: 0; color: #1f2328; }
  header { display: flex; align-items: center; gap: 16px; padding: 12px 24px; background: #1a7f64; color: #fff; }
  header h1 { font-size: 18px; margin: 0; }
  header span { flex: 1; }
  header button { background: rgba(255,255,255,.15); color: #fff; border: 1px solid rgba(255,255,255,.4);
                  border-radius: 6px; padding: 6px 14px; cursor: pointer; }
  nav { display: flex; gap: 8px; padding: 12px 24px; border-bottom: 1px solid #d8dee4; }
  nav button { border: 1px solid #d8dee4; background: #f6f8fa; border-radius: 6px; padding: 6px 16px; cursor: pointer; }
  nav button.active { background: #1a7f64; color: #fff; border-color: #1a7f64; }
  main { padding: 16px 24px; }
  h2 { font-size: 16px; margin: 18px 0 8px; }
  table { border-collapse: collapse; width: 100%; font-size: 14px; }
  th, td { border: 1px solid #d8dee4; padding: 6px 8px; text-align: left; vertical-align: top; }
  th { background: #f6f8fa; }
  code { background: #f6f8fa; padding: 1px 4px; border-radius: 4px; }
  form.card, .card { border: 1px solid #d8dee4; border-radius: 8px; padding: 12px 16px; margin: 12px 0; max-width: 860px; }
  label { display: block; margin: 8px 0 2px; font-size: 13px; color: #57606a; }
  input, select, textarea { width: 100%; box-sizing: border-box; padding: 6px; font-size: 14px; }
  textarea { min-height: 64px; font-family: monospace; }
  button.act { border: 1px solid #d8dee4; background: #f6f8fa; border-radius: 6px; padding: 4px 10px;
               cursor: pointer; margin: 2px; }
  button.primary { background: #1a7f64; color: #fff; border-color: #1a7f64; padding: 8px 18px; }
  .pre { background: #f6f8fa; border: 1px solid #d8dee4; border-radius: 6px; padding: 8px;
         font-family: monospace; font-size: 13px; white-space: pre-wrap; word-break: break-all; }
  .status { color: #57606a; font-size: 13px; margin: 6px 0; min-height: 16px; }
  .ok { color: #1a7f64; } .bad { color: #cf222e; }
  .row-actions { white-space: nowrap; }
</style>
</head>
<body>
<header>
  <h1>agent-proxy 管理页面</h1>
  <span>{{ user_name }}{% if is_admin %}（管理员）{% endif %}</span>
  <button id="logout-btn" type="button">退出登录</button>
</header>
<nav>
  <button class="tab active" data-view="mine" type="button">我的映射</button>
  <button class="tab" data-view="builtin" type="button">内置 MCP</button>
  {% if is_admin %}<button class="tab" data-view="public" type="button">公共映射管理</button>{% endif %}
</nav>
<main>
  <!-- ============ 我的映射（§15.1：列表 / 注册表单含占位符预览 / resolve 回显编辑 / test / 删除） ============ -->
  <section id="view-mine">
    <h2>我的映射</h2>
    <div id="mine-status" class="status"></div>
    <table id="mine-table">
      <thead><tr><th>mapping_id</th><th>名称</th><th>类型</th><th>上游地址</th><th>代理地址</th><th>状态</th><th>操作</th></tr></thead>
      <tbody></tbody>
    </table>

    <form id="mine-form" class="card">
      <h3 id="mine-form-title">注册映射</h3>
      <button id="mine-cancel-edit" class="act" type="button" hidden>取消编辑</button>
      <label>类型</label>
      <select name="type"><option value="http">http</option><option value="mcp">mcp</option></select>
      <label>名称（可选）</label>
      <input name="name" placeholder="显示名">
      <label>上游地址（mcp 建议完整端点，如 https://mcp.ex.com/sse）</label>
      <input name="upstream_url" required placeholder="https://...">
      <label>Header（每行一条 Name: value；注册后仅占位符回显，真实值只存代理侧）</label>
      <textarea name="headers" placeholder="Authorization: Bearer sk-xxx&#10;X-User-Id: u888"></textarea>
      {% if is_admin %}
      <label>可见性</label>
      <select name="visibility"><option value="private">private</option><option value="public">public</option></select>
      {% endif %}
      <label>test_request（可选，http 严格验证）</label>
      <div style="display:flex; gap:8px;">
        <input name="method" placeholder="GET" style="width:90px">
        <input name="path" placeholder="/healthz">
        <input name="expect_status" placeholder="200" style="width:100px">
      </div>
      <p><button id="mine-submit" class="primary" type="submit">注册映射</button></p>
    </form>
    <div id="mine-agent-config"></div>
  </section>

  <!-- ============ 内置 MCP（§15.1：列表含 auth_mode+绑定状态 / 授权绑定跳转 / test） ============ -->
  <section id="view-builtin" hidden>
    <h2>内置 MCP（公共映射）</h2>
    <div id="builtin-status" class="status"></div>
    <table id="builtin-table">
      <thead><tr><th>名称</th><th>类型</th><th>代理地址</th><th>占位符 Header</th><th>auth_mode</th><th>绑定状态</th><th>状态</th><th>操作</th></tr></thead>
      <tbody></tbody>
    </table>
    <p class="status">OAuth 型映射先「授权绑定」再调用；绑定/解绑后点操作里的「刷新」。</p>
    <div id="builtin-agent-config"></div>
  </section>

  {% if is_admin %}
  <!-- ============ 公共映射管理（仅 admin，§15.1：public 映射 CRUD + test + OAuth client 手动配置） ============ -->
  <section id="view-public" hidden>
    <h2>公共映射管理</h2>
    <div id="public-status" class="status"></div>
    <table id="public-table">
      <thead><tr><th>mapping_id</th><th>名称</th><th>类型</th><th>上游地址</th><th>auth_mode</th><th>状态</th><th>操作</th></tr></thead>
      <tbody></tbody>
    </table>

    <form id="public-form" class="card">
      <h3 id="public-form-title">创建公共映射</h3>
      <button id="public-cancel-edit" class="act" type="button" hidden>取消编辑</button>
      <label>类型</label>
      <select name="type"><option value="http">http</option><option value="mcp">mcp</option></select>
      <label>名称</label>
      <input name="name">
      <label>上游地址</label>
      <input name="upstream_url" required>
      <label>Header（每行 Name: value）</label>
      <textarea name="headers"></textarea>
      <label>auth_mode</label>
      <select name="auth_mode"><option value="static">static（共享静态凭据）</option><option value="oauth">oauth（按用户绑定）</option></select>
      <p><button id="public-submit" class="primary" type="submit">创建</button></p>
    </form>
    <div id="public-agent-config"></div>

    <form id="client-form" class="card" hidden>
      <h3 id="client-form-title">OAuth 客户端手动配置</h3>
      <p class="status">manual 模式（保存即覆盖既有 dcr 配置）；client_secret 加密落库、永不回显。</p>
      <label>client_id</label><input name="client_id" required>
      <label>client_secret（留空 = 公共客户端 token_auth=none 场景）</label><input name="client_secret">
      <label>token_auth</label>
      <select name="token_auth">
        <option value="client_secret_post">client_secret_post</option>
        <option value="client_secret_basic">client_secret_basic</option>
        <option value="none">none</option>
      </select>
      <label>authorize_url</label><input name="authorize_url" required>
      <label>token_url</label><input name="token_url" required>
      <label>scopes（空格分隔，可选）</label><input name="scopes">
      <p><button class="primary" type="submit">保存 client</button></p>
    </form>
    <div id="client-info" class="card" hidden></div>
  </section>
  {% endif %}
</main>
<script>
"use strict";
var IS_ADMIN = {{ is_admin | tojson }};
var editMid = null;        // 我的映射：当前编辑的 mapping_id（null = 注册模式）
var publicEditMid = null;  // 公共映射：当前编辑的 mapping_id
var clientMid = null;      // OAuth client 表单目标 mapping_id

function esc(s) {
  return String(s === null || s === undefined ? "" : s)
    .replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
}

async function api(method, url, body) {
  var opts = { method: method, headers: {} };
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  var resp = await fetch(url, opts);
  if (resp.status === 401) { location.href = "/admin"; throw new Error("未登录"); }
  var data = resp.status === 204 ? null : await resp.json().catch(function () { return null; });
  return { ok: resp.ok, status: resp.status, data: data };
}

function setStatus(id, text) {
  var el = document.getElementById(id);
  if (el) el.textContent = text;
}

function parseHeaders(text) {
  var headers = {};
  text.split("\n").forEach(function (line) {
    var t = line.trim();
    if (!t) return;
    var i = t.indexOf(":");
    if (i <= 0) throw new Error("header 行格式须为 Name: value");
    headers[t.slice(0, i).trim()] = t.slice(i + 1).trim();
  });
  return headers;
}

function headersToText(headers) {
  return Object.entries(headers || {}).map(function (kv) { return kv[0] + ": " + kv[1]; }).join("\n");
}

/* 占位符预览（§6.1：POST/PUT 响应 = 代理地址 + 占位符 header，「保存到 Agent」面） */
function showAgentConfig(elId, data) {
  var el = document.getElementById(elId);
  if (!data || !data.proxy_url) { el.innerHTML = ""; return; }
  var lines = Object.entries(data.headers || {}).map(function (kv) {
    return '    "' + esc(kv[0]) + '": "' + esc(kv[1]) + '"';
  }).join(",\n");
  el.innerHTML = '<div class="card"><h3>保存到 Agent（占位符，不含真实值）</h3>' +
    '<div class="pre">代理地址: ' + esc(data.proxy_url) + '\nHeader:\n{\n' + lines + '\n  }</div>' +
    '<p class="status">PUT 更新过 upstream_url 时路径部分可能变化，请以本响应重新保存 Agent 配置（§6.1）。</p></div>';
}

/* ---------- 我的映射 ---------- */

async function loadMine() {
  var r = await api("GET", "/api/v1/mappings?page_size=100");
  var rows = (r.data || []).map(function (m) {
    return '<tr><td><code>' + esc(m.mapping_id) + '</code></td>' +
      '<td>' + esc(m.name) + '</td><td>' + esc(m.type) + '</td>' +
      '<td>' + esc(m.upstream_url) + '</td><td><code>' + esc(m.proxy_url) + '</code></td>' +
      '<td>' + esc(m.status) + '</td>' +
      '<td class="row-actions">' +
      '<button class="act" onclick="editMine(\'' + esc(m.mapping_id) + '\')">编辑</button>' +
      '<button class="act" onclick="testMapping(\'' + esc(m.mapping_id) + '\')">测试</button>' +
      '<button class="act" onclick="delMapping(\'' + esc(m.mapping_id) + '\')">删除</button>' +
      '</td></tr>';
  }).join("");
  document.querySelector("#mine-table tbody").innerHTML =
    rows || '<tr><td colspan="7">暂无映射——用下方表单注册第一条。</td></tr>';
}

/* resolve 回显编辑（§6.4）：按 mapping_id 直查，真实 header 仅注册者/admin 可见 */
async function editMine(mid) {
  var r = await api("GET", "/api/v1/mappings/resolve?proxy_url=" + encodeURIComponent(mid));
  var d = r.data;
  var f = document.getElementById("mine-form");
  f.type.value = d.type;
  f.name.value = d.name || "";
  f.upstream_url.value = d.upstream_url;
  f.headers.value = headersToText(d.headers);
  if (f.visibility) f.visibility.value = d.visibility;
  f.method.value = (d.test_request && d.test_request.method) || "";
  f.path.value = (d.test_request && d.test_request.path) || "";
  f.expect_status.value = (d.test_request && d.test_request.expect_status) || "";
  editMid = mid;
  document.getElementById("mine-form-title").textContent = "编辑映射 " + mid;
  document.getElementById("mine-submit").textContent = "保存修改";
  document.getElementById("mine-cancel-edit").hidden = false;
  setStatus("mine-status", "已回显 " + mid + "（resolve），修改后保存。");
}

async function submitMine(ev) {
  ev.preventDefault();
  var f = ev.target;
  var payload;
  try {
    payload = { type: f.type.value, upstream_url: f.upstream_url.value.trim(),
                headers: parseHeaders(f.headers.value) };
    if (f.name.value.trim() || editMid) payload.name = f.name.value.trim() || null;
    if (f.visibility && !editMid) payload.visibility = f.visibility.value;
    if (f.method.value.trim() && f.path.value.trim()) {
      payload.test_request = { method: f.method.value.trim(), path: f.path.value.trim() };
      if (f.expect_status.value.trim()) {
        payload.test_request.expect_status = parseInt(f.expect_status.value, 10);
      }
    }
  } catch (e) { setStatus("mine-status", e.message); return; }
  var r = editMid
    ? await api("PUT", "/api/v1/mappings/" + editMid, payload)
    : await api("POST", "/api/v1/mappings", payload);
  if (!r.ok) { setStatus("mine-status", "失败: " + ((r.data && r.data.message) || r.status)); return; }
  showAgentConfig("mine-agent-config", r.data);
  setStatus("mine-status", editMid ? "已更新。" : "已注册。");
  resetMineForm();
  loadMine();
}

function resetMineForm() {
  editMid = null;
  var f = document.getElementById("mine-form");
  f.reset();
  document.getElementById("mine-form-title").textContent = "注册映射";
  document.getElementById("mine-submit").textContent = "注册映射";
  document.getElementById("mine-cancel-edit").hidden = true;
}

async function testMapping(mid) {
  var r = await api("POST", "/api/v1/mappings/" + mid + "/test");
  setStatus("mine-status", "test " + mid + ": " + (r.ok ? "通过 " : "失败 ") + JSON.stringify(r.data));
}

async function delMapping(mid) {
  if (!confirm("删除映射 " + mid + "？删除后 Agent 侧代理地址立即 404，请同步清理已保存的代理配置。")) return;
  var r = await api("DELETE", "/api/v1/mappings/" + mid);
  setStatus("mine-status", r.status === 204 ? "已删除 " + mid + "。"
    : "失败: " + ((r.data && r.data.message) || r.status));
  if (editMid === mid) resetMineForm();
  loadMine();
}

/* ---------- 内置 MCP ---------- */

async function loadBuiltin() {
  var r = await api("GET", "/api/v1/builtin-mappings");
  var rows = (r.data || []).map(function (m) {
    var binding = m.auth_mode === "oauth"
      ? '<span class="' + (m.binding === "bound" ? "ok" : "bad") + '">' + esc(m.binding) + "</span>"
      : "-";
    var actions = m.auth_mode === "oauth"
      ? '<button class="act" onclick="authorizeBuiltin(\'' + esc(m.mapping_id) + '\')">授权绑定</button>' +
        '<button class="act" onclick="unbindBuiltin(\'' + esc(m.mapping_id) + '\')">解绑</button>'
      : "";
    return '<tr><td>' + esc(m.name) + '</td><td>' + esc(m.type) + '</td>' +
      '<td><code>' + esc(m.proxy_url) + '</code></td>' +
      '<td><code>' + esc(JSON.stringify(m.headers)) + '</code></td>' +
      '<td>' + esc(m.auth_mode) + '</td><td>' + binding + '</td><td>' + esc(m.status) + '</td>' +
      '<td class="row-actions">' + actions +
      '<button class="act" onclick="testBuiltin(\'' + esc(m.mapping_id) + '\')">测试</button>' +
      '<button class="act" onclick="refreshBuiltin()">刷新</button>' +
      '<button class="act" onclick="saveBuiltinAgent(\'' + esc(m.mapping_id) + '\')">保存到 Agent</button>' +
      '</td></tr>';
  }).join("");
  document.querySelector("#builtin-table tbody").innerHTML =
    rows || '<tr><td colspan="8">暂无内置映射。</td></tr>';
}

function refreshBuiltin() { loadBuiltin(); }

async function authorizeBuiltin(mid) {
  var r = await api("POST", "/api/v1/builtin-mappings/" + mid + "/authorize",
                    { front_redirect: location.origin + "/admin" });
  if (!r.ok) { setStatus("builtin-status", "失败: " + ((r.data && r.data.message) || r.status)); return; }
  setStatus("builtin-status", "已打开授权页；完成后回本页「刷新」查看绑定状态（§14.4 状态机）。");
  window.open(r.data.authorization_url, "_blank");
}

async function unbindBuiltin(mid) {
  if (!confirm("解绑 " + mid + "？提供方支持时同时吊销远端凭证。")) return;
  var r = await api("DELETE", "/api/v1/builtin-mappings/" + mid + "/binding");
  setStatus("builtin-status", r.status === 204 ? "已解绑。" : "失败: " + ((r.data && r.data.message) || r.status));
  loadBuiltin();
}

async function testBuiltin(mid) {
  var r = await api("POST", "/api/v1/builtin-mappings/" + mid + "/test");
  setStatus("builtin-status", "test " + mid + ": " + (r.ok ? "通过 " : "失败 ") + JSON.stringify(r.data));
}

async function saveBuiltinAgent(mid) {
  var r = await api("GET", "/api/v1/builtin-mappings");
  var item = (r.data || []).find(function (x) { return x.mapping_id === mid; });
  if (item) showAgentConfig("builtin-agent-config", item);
}

/* ---------- 公共映射管理（仅 admin） ---------- */

async function loadPublic() {
  var r = await api("GET", "/api/v1/builtin-mappings");
  var rows = (r.data || []).map(function (m) {
    return '<tr><td><code>' + esc(m.mapping_id) + '</code></td><td>' + esc(m.name) + '</td>' +
      '<td>' + esc(m.type) + '</td><td>' + esc(m.proxy_url) + '</td>' +
      '<td>' + esc(m.auth_mode) + '</td><td>' + esc(m.status) + '</td>' +
      '<td class="row-actions">' +
      '<button class="act" onclick="editPublic(\'' + esc(m.mapping_id) + '\')">编辑</button>' +
      '<button class="act" onclick="testPublic(\'' + esc(m.mapping_id) + '\')">测试</button>' +
      '<button class="act" onclick="delPublic(\'' + esc(m.mapping_id) + '\')">删除</button>' +
      '<button class="act" onclick="editClient(\'' + esc(m.mapping_id) + '\')">OAuth client</button>' +
      '</td></tr>';
  }).join("");
  document.querySelector("#public-table tbody").innerHTML =
    rows || '<tr><td colspan="7">暂无公共映射。</td></tr>';
}

/* 详情（admin 可读 public，§14.2）回显 upstream_url/headers/auth_mode */
async function editPublic(mid) {
  var r = await api("GET", "/api/v1/mappings/" + mid);
  var d = r.data;
  var f = document.getElementById("public-form");
  f.type.value = d.type;
  f.name.value = d.name || "";
  f.upstream_url.value = d.upstream_url;
  f.headers.value = headersToText(d.headers);
  f.auth_mode.value = d.auth_mode;
  publicEditMid = mid;
  document.getElementById("public-form-title").textContent = "编辑公共映射 " + mid;
  document.getElementById("public-submit").textContent = "保存修改";
  document.getElementById("public-cancel-edit").hidden = false;
}

async function submitPublic(ev) {
  ev.preventDefault();
  var f = ev.target;
  var payload;
  try {
    payload = { type: f.type.value, upstream_url: f.upstream_url.value.trim(),
                visibility: "public", auth_mode: f.auth_mode.value,
                headers: parseHeaders(f.headers.value),
                name: f.name.value.trim() || null };
  } catch (e) { setStatus("public-status", e.message); return; }
  var r = publicEditMid
    ? await api("PUT", "/api/v1/mappings/" + publicEditMid, payload)
    : await api("POST", "/api/v1/mappings", payload);
  if (!r.ok) { setStatus("public-status", "失败: " + ((r.data && r.data.message) || r.status)); return; }
  showAgentConfig("public-agent-config", r.data);
  setStatus("public-status", publicEditMid ? "已更新。" : "已创建。");
  resetPublicForm();
  loadPublic();
}

function resetPublicForm() {
  publicEditMid = null;
  var f = document.getElementById("public-form");
  f.reset();
  document.getElementById("public-form-title").textContent = "创建公共映射";
  document.getElementById("public-submit").textContent = "创建";
  document.getElementById("public-cancel-edit").hidden = true;
}

async function delPublic(mid) {
  if (!confirm("删除公共映射 " + mid + "？连同 OAuth client/凭证一并清理。")) return;
  var r = await api("DELETE", "/api/v1/mappings/" + mid);
  setStatus("public-status", r.status === 204 ? "已删除。" : "失败: " + ((r.data && r.data.message) || r.status));
  loadPublic();
}

async function testPublic(mid) {
  var r = await api("POST", "/api/v1/builtin-mappings/" + mid + "/test");
  setStatus("public-status", "test " + mid + ": " + (r.ok ? "通过 " : "失败 ") + JSON.stringify(r.data));
}

/* OAuth client 手动配置（§14.3 降级路径；GET 404 = 尚未配置；secret 只回 configured 布尔） */
async function editClient(mid) {
  clientMid = mid;
  var form = document.getElementById("client-form");
  form.hidden = false;
  document.getElementById("client-form-title").textContent = "OAuth 客户端（" + mid + "）";
  var info = document.getElementById("client-info");
  var r = await api("GET", "/api/v1/builtin-mappings/" + mid + "/client");
  if (r.status === 404) {
    info.hidden = true;
    setStatus("public-status", mid + " 尚未配置 client；下方表单保存即 manual 模式。");
    return;
  }
  form.client_id.value = r.data.client_id;
  form.token_auth.value = r.data.token_auth;
  form.authorize_url.value = r.data.authorize_url || "";
  form.token_url.value = r.data.token_url || "";
  form.scopes.value = r.data.scopes || "";
  info.hidden = false;
  info.innerHTML = '<h3>当前配置</h3><div class="pre">source=' + esc(r.data.source) +
    '  client_id=' + esc(r.data.client_id) + '\ntoken_auth=' + esc(r.data.token_auth) +
    '  client_secret=' + (r.data.client_secret_configured ? "已配置（不回显）" : "未配置") + "</div>";
}

async function submitClient(ev) {
  ev.preventDefault();
  var f = ev.target;
  var payload = {
    client_id: f.client_id.value.trim(),
    client_secret: f.client_secret.value || null,
    token_auth: f.token_auth.value,
    authorize_url: f.authorize_url.value.trim(),
    token_url: f.token_url.value.trim(),
    scopes: f.scopes.value.trim() || null,
  };
  var r = await api("PUT", "/api/v1/builtin-mappings/" + clientMid + "/client", payload);
  if (!r.ok) { setStatus("public-status", "失败: " + ((r.data && r.data.message) || r.status)); return; }
  setStatus("public-status", "client 已保存（source=" + r.data.source + "）。");
  f.hidden = true;
  document.getElementById("client-info").hidden = true;
  loadPublic();
}

/* ---------- 会话 / 导航 ---------- */

document.getElementById("logout-btn").addEventListener("click", async function () {
  await fetch("/admin/logout", { method: "POST" });
  location.href = "/admin/login";
});

var loaders = { mine: loadMine, builtin: loadBuiltin, public: loadPublic };
document.querySelectorAll(".tab").forEach(function (btn) {
  btn.addEventListener("click", function () {
    document.querySelectorAll(".tab").forEach(function (b) { b.classList.toggle("active", b === btn); });
    document.querySelectorAll("main > section").forEach(function (s) {
      s.hidden = s.id !== "view-" + btn.dataset.view;
    });
    var load = loaders[btn.dataset.view];
    if (load) load();
  });
});

document.getElementById("mine-form").addEventListener("submit", submitMine);
document.getElementById("mine-cancel-edit").addEventListener("click", function () { resetMineForm(); });
{% if is_admin %}
document.getElementById("public-form").addEventListener("submit", submitPublic);
document.getElementById("public-cancel-edit").addEventListener("click", function () { resetPublicForm(); });
document.getElementById("client-form").addEventListener("submit", submitClient);
{% endif %}
loadMine();
</script>
</body>
</html>
```

`src/agent_proxy/main.py` 修改——import 区 builtin 行之后加：

```python
from .api.builtin import router as builtin_router, callback_router as oauth_callback_router
from .api.admin_pages import router as admin_pages_router
```

`create_app` 的路由注册区（`app.include_router(oauth_callback_router)` 之后）加：

```python
    app.include_router(oauth_callback_router)
    app.include_router(admin_pages_router)
```

- [ ] **Step 4: 运行预期（PASS）**

```bash
.venv/Scripts/python.exe -m pytest tests/integration/test_admin_pages.py tests/unit/test_deps.py tests/unit/test_sso.py -q
```

Expected: 全绿（admin_pages 9 + deps 11 + sso 9 = 29 passed）。既有全量不受影响（`/admin` 为全新静态路由，与 `/p/`、`/oauth/` 无冲突；`route_name` 的 admin 分支 M1 已预留）。

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(M7): 管理页面路由——/admin 入口+stub 登录页+callback 建会话+退出登录（Jinja2 模板，视图按 is_admin 隔离，不做越权捷径）" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

### Task 4: 浏览器式全流程集成——stub 登录完成全部页面操作 + 非 admin 隔离 + 真实 TCP 冒烟

**Files:**
- New: `tests/integration/test_admin_browser_flow.py`

- [ ] **Step 1: 写测试（本任务为集成断言面，实现已在 Task 1–3 落地；先跑一轮确认全绿，若挂则按 systematic-debugging 定位）**

`tests/integration/test_admin_browser_flow.py`（新文件）：

```python
"""浏览器式全流程（M7 §16 验收「浏览器经 stub 登录完成全部页面操作」的自动化面）。

httpx Client 自带 Cookie Jar 模拟浏览器：GET /admin 302 → 登录页可渲染 → 构造
stub 票据（与登录页 JS 同构）→ callback Set-Cookie → 后续请求自动携带 → 经
Cookie 通道完成我的映射（注册/resolve/test/删除）、内置 MCP 列表、（admin）公共
映射 CRUD + OAuth client 手动配置、退出登录；非 admin 视图隔离与 API 侧 403 兜底
（页面不做越权捷径的两层钉住）；真实 TCP 冒烟（9910：页面路由 + Cookie 通道注册）。
"""
import httpx
from httpx import ASGITransport, AsyncClient

from agent_proxy.sso.session import SESSION_COOKIE
from tests.utils import make_token

BASE = "http://testserver"
PROXY = "http://127.0.0.1:9910"
TCP_TIMEOUT = httpx.Timeout(connect=5, read=10, write=10, pool=5)

HTTP_BODY = {"type": "http", "upstream_url": "http://127.0.0.1:9901/api/v1",
             "headers": {"Authorization": "Bearer sk-real-1234567890"}}


def _client(app) -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=app), base_url=BASE)


async def _browser_login(c: AsyncClient, user_id: str, role: str | None = None) -> None:
    """复刻登录页表单行为：入口 302 → 登录页可渲染 → 票据 callback → 会话 Cookie 入 jar。"""
    r = await c.get("/admin")
    assert r.status_code == 302 and r.headers["location"].startswith("/admin/login")
    page = await c.get(r.headers["location"])
    assert page.status_code == 200 and 'action="/admin/auth/callback"' in page.text
    r = await c.get("/admin/auth/callback",
                    params={"ticket": make_token(user_id, role), "return_to": "/admin"})
    assert r.status_code == 302 and r.headers["location"] == "/admin"
    assert c.cookies.get(SESSION_COOKIE), "会话 Cookie 未入 jar"


async def test_full_browser_flow_admin_as_admin(app):
    async with _client(app) as c:
        await _browser_login(c, "boss", role="admin")
        assert (await c.get("/admin")).status_code == 200

        # 我的映射：注册（占位符响应）→ resolve 回显 → test（echo 9901 连通判定）→ 删除
        r = await c.post("/api/v1/mappings", json=HTTP_BODY)
        assert r.status_code == 201
        mid = r.json()["mapping_id"]
        assert r.json()["headers"]["Authorization"] == "${PX:Authorization}"
        r = await c.get("/api/v1/mappings/resolve", params={"proxy_url": mid})
        assert r.json()["headers"]["Authorization"] == "Bearer sk-real-1234567890"
        r = await c.post(f"/api/v1/mappings/{mid}/test")
        assert r.status_code == 200 and r.json()["ok"] is True

        # 内置 MCP 列表（Cookie 通道；空库为空列表）
        assert await c.get("/api/v1/builtin-mappings").json() == []

        # 公共映射管理（admin）：创建 public+oauth → 手动 client → 查看配置 → 删除
        r = await c.post("/api/v1/mappings",
                         json={**HTTP_BODY, "visibility": "public", "auth_mode": "oauth",
                               "name": "公共测试"})
        assert r.status_code == 201
        pub = r.json()["mapping_id"]
        r = await c.put(f"/api/v1/builtin-mappings/{pub}/client", json={
            "client_id": "manual-cl", "client_secret": "manual-cs-123456",
            "token_auth": "client_secret_post",
            "authorize_url": "http://127.0.0.1:9904/oauth/authorize",
            "token_url": "http://127.0.0.1:9904/oauth/token"})
        assert r.status_code == 200 and r.json()["source"] == "manual"
        r = await c.get(f"/api/v1/builtin-mappings/{pub}/client")
        assert r.status_code == 200 and r.json()["client_secret_configured"] is True
        assert (await c.delete(f"/api/v1/mappings/{mid}")).status_code == 204

        # 退出登录：会话删除 → /admin 回到 302 登录（Cookie 已失效）
        assert (await c.post("/admin/logout")).status_code == 302
        assert (await c.get("/admin")).status_code == 302


async def test_non_admin_view_isolated_and_api_privilege_enforced(app):
    """§15.1「admin 视图权限隔离」+「页面不做越权捷径」两层钉住：
    页面入口隐藏（模板不含 public 视图）+ 直接打 API 仍被既有矩阵拦（403）。"""
    async with _client(app) as c:
        r = await c.post("/api/v1/mappings", json={**HTTP_BODY, "visibility": "public"},
                         headers={"Authorization": f"Bearer {make_token('boss', role='admin')}"})
        assert r.status_code == 201
        pub = r.json()["mapping_id"]
        await _browser_login(c, "u888")
        page = await c.get("/admin")
        assert page.status_code == 200
        assert "公共映射管理" not in page.text            # 视图隔离（模板入口隐藏）
        assert 'data-view="public"' not in page.text
        # 页面不做越权捷径：绕过页面直接打 API 同样被既有矩阵拦下
        r = await c.post("/api/v1/mappings", json={**HTTP_BODY, "visibility": "public"})
        assert r.status_code == 403 and r.json()["code"] == "FORBIDDEN"
        r = await c.put(f"/api/v1/builtin-mappings/{pub}/client", json={
            "client_id": "x",
            "authorize_url": "http://127.0.0.1:9904/oauth/authorize",
            "token_url": "http://127.0.0.1:9904/oauth/token"})
        assert r.status_code == 403
        # 内置映射列表任意有效身份可见（§14.2），但 client 配置查询仅 admin
        assert (await c.get("/api/v1/builtin-mappings")).status_code == 200
        assert (await c.get(f"/api/v1/builtin-mappings/{pub}/client")).status_code == 403


async def test_real_tcp_admin_page_and_cookie_channel(real_proxy_app):
    """真实 TCP（9910）：页面路由可达 + stub 登录 → Cookie 通道注册映射 → 页面渲染
    → 退出登录后会话失效（SESSION_COOKIE_SECURE=false 下纯 http 可携带 Cookie）。"""
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        r = await c.get(f"{PROXY}/admin", follow_redirects=False)
        assert r.status_code == 302 and r.headers["location"].startswith("/admin/login")
        r = await c.get(f"{PROXY}/admin/auth/callback",
                        params={"ticket": make_token("u888")}, follow_redirects=False)
        assert r.status_code == 302
        assert c.cookies.get(SESSION_COOKIE)
        r = await c.post(f"{PROXY}/api/v1/mappings", json=HTTP_BODY)
        assert r.status_code == 201
        r = await c.get(f"{PROXY}/admin")
        assert r.status_code == 200 and "我的映射" in r.text
        r = await c.post(f"{PROXY}/admin/logout", follow_redirects=False)
        assert r.status_code == 302
        assert (await c.get(f"{PROXY}/admin")).status_code == 302      # 会话已删
```

- [ ] **Step 2: 运行预期（PASS）**

```bash
.venv/Scripts/python.exe -m pytest tests/integration/test_admin_browser_flow.py -q
```

Expected: 4 passed（真实 TCP 用例依赖 9901 echo / 9904 mock AS / 9910 被测代理夹具；如端口被占用先按约定等待重试）。

- [ ] **Step 3: Commit**

```bash
git add -A
git commit -m "test(M7): 浏览器式全流程——stub 登录完成页面操作闭环、非 admin 视图隔离与 API 403 兜底、真实 TCP 冒烟" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

### Task 5: Prometheus 完善——§15.2 八项指标完整性与基数受控断言 + 指标文档对照

**Files:**
- Modify: `src/agent_proxy/metrics.py`（模块 docstring 对照 §15.2，仅文档零行为）
- New: `tests/integration/test_metrics_prometheus.py`

- [ ] **Step 1: 写失败测试**

`tests/integration/test_metrics_prometheus.py`（新文件）：

```python
"""Prometheus 指标完善核对（M7，设计 §15.2）：八项指标族齐全暴露 + 标签基数受控。

M1-M4 已陆续接线（middleware：requests_total/request_duration/inflight/bytes_total；
forward：upstream_duration/upstream_errors_total/sse_active；oauth：oauth_actions_total），
本文件补齐 §15.2 的存在性与基数红线断言；route=admin 由管理页面（M7）流量产生。
"""
import re

from agent_proxy import metrics as m

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
    """各指标族至少产出一个样本（prometheus 输出才含样本行；进程内全局注册表）。"""
    m.requests_total.labels(route="admin", type="-", status="200").inc()
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
```

- [ ] **Step 2: 运行预期**

```bash
.venv/Scripts/python.exe -m pytest tests/integration/test_metrics_prometheus.py -q
```

Expected: 直接全绿的两种可能都接受——接线本就完整（本任务是断言钉住而非修缺陷）；若 `# TYPE` 断言失败说明某指标族未注册/名字漂移，按 systematic-debugging 修 metrics.py（不允许放宽断言）。

- [ ] **Step 3: metrics.py 文档对照（零行为变更）**

`src/agent_proxy/metrics.py` 模块 docstring 整体替换为：

```python
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
```

（docstring 以下的原有指标定义与注释零改动。）

- [ ] **Step 4: 运行预期（PASS）**

```bash
.venv/Scripts/python.exe -m pytest tests/integration/test_metrics_prometheus.py tests/integration/test_health.py -q
```

Expected: 全绿（2 + 5 = 7 passed）。

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "test(M7): Prometheus §15.2 八项指标族与基数受控断言 + metrics 模块文档对照（无新指标，接线核对）" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

### Task 6: M5 残余扫尾——推送流 body 模式 trace 断言 + `_first_message_data` 多行 data 已知限制钉住 + c/d 核对

**Files:**
- Modify: `tests/integration/test_proxy_mcp_streamable.py`（扫尾 a：推送流 body 模式 trace；扫尾 b：多行 data probe 用例）
- Modify: `tests/unit/test_mcp_streamable.py`（扫尾 b：单测钉首行行为）
- Modify: `src/agent_proxy/forward/mcp_streamable.py`（扫尾 b：`_first_message_data` docstring 已知限制注记）
- Modify: `tests/integration/mock_mcp_streamable.py`（扫尾 b：`/mcp-multiline-data` 回归面）

- [ ] **Step 1: 写失败测试（扫尾 a + b）**

`tests/integration/test_proxy_mcp_streamable.py`——import 行替换为：

```python
from tests.utils import make_token, read_next_message_data, sse_line_iter
```

文件末尾追加两个用例：

```python
async def test_streamable_push_stream_trace_body_mode_records_message_events():
    """M5 扫尾 a（M2 Task 5 评审遗留）：GET /mcp 推送流走 SSE 解析管线——body 模式下
    message 事件经 trace.log_sse_event 记录（设计 §8.4 注记「推送流的 message 事件行
    在 body 模式下记录」的集成断言，M3 已实现未断言）；心跳注释行不记录；无 endpoint
    事件（Streamable 流无改写面，rewriter 字节级无操作）。"""
    import glob
    import json as jsonlib

    from agent_proxy import trace as trace_mod
    from agent_proxy.logging_setup import flush_trace

    created = await _register_streamable()
    mid = created["mapping_id"]
    trace_mod.configure("body", 64 * 1024)   # 进程级全局：真实服务器与测试同进程，钉住后恢复
    try:
        async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
            async with c.stream("GET", f"{PROXY}/p/{mid}/mcp",
                                headers={**AUTH, **SESSION}) as resp:
                assert resp.status_code == 200
                push = await read_next_message_data(resp)   # 首条推送事件读到即断开
    finally:
        flush_trace()
        trace_mod.configure("metadata", 64 * 1024)          # 恢复（集成夹具 lifespan 亦会重配）
    records = []
    for path in glob.glob("logs-test/trace.log.*"):
        with open(path, encoding="utf-8") as fh:
            records.extend(jsonlib.loads(x) for x in fh.read().splitlines() if x.strip())
    reqs = [r for r in records if r.get("mapping_id") == mid and r["phase"] == "request"]
    assert reqs and reqs[0]["url"] == "http://127.0.0.1:9903/mcp"
    assert "sk-mcp4-12345678" not in jsonlib.dumps(reqs)    # 敏感头指纹化（红线复扫）
    req_ids = {r["request_id"] for r in reqs}
    sse = [r for r in records if r["phase"] == "sse_event" and r["request_id"] in req_ids]
    assert {r["event"] for r in sse} == {"message"}         # 推送流仅 message（无 endpoint 事件）
    assert any("push-hello" in r["data"] for r in sse)      # 推送载荷已记录（§11.1）
    assert not any("ping" in (r.get("data") or "") for r in sse), "心跳注释行不记录"


async def test_probe_multiline_data_initialize_judged_failure():
    """M5 扫尾 b（已知限制回归钉）：/mcp-multiline-data 的 initialize 为多行 data
    SSE——_first_message_data 只取首行不拼接 → JSON 解析失败 → ok=false
    「非合法 JSON」（显式失败，不误判 serverInfo 成功；真实 SDK 均单行）。"""
    created = await _register_streamable(
        upstream_url="http://127.0.0.1:9903/mcp-multiline-data")
    mid = created["mapping_id"]
    async with httpx.AsyncClient() as c:
        r = await c.post(f"{PROXY}/api/v1/mappings/{mid}/test",
                         headers={"Authorization": f"Bearer {make_token('u888')}"})
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is False and "非合法 JSON" in body["detail"]
```

`tests/unit/test_mcp_streamable.py` 文件末尾追加：

```python
def test_first_message_data_multiline_data_known_limitation():
    """已知限制钉住（M5 扫尾 b）：多行 data: 不拼接，取首个 data 行——真实 SDK
    （官方 SDK / Inspector）initialize 均为单行 data；多行形态截断后 JSON 解析失败
    判 ok=false（不误判成功）。注释见 _first_message_data，回归面见 mock
    /mcp-multiline-data + test_proxy_mcp_streamable 探测用例。"""
    raw = b'event: message\ndata: {"jsonrpc": "2.0",\ndata: "id": 1}\n\n'
    assert _first_message_data(raw) == b'{"jsonrpc": "2.0",'
```

- [ ] **Step 2: 运行预期（FAIL）**

```bash
.venv/Scripts/python.exe -m pytest tests/unit/test_mcp_streamable.py tests/integration/test_proxy_mcp_streamable.py -q
```

Expected: unit 新用例 PASS（行为本就如此——钉住不改性）；集成两用例 FAIL：推送流 trace 用例在 `sse == {"message"}` 前因 `reqs` 为空或 events 集合含意外值失败的可能性低——**两用例的 FAIL 面主要在 mock 端点不存在**（`/mcp-multiline-data` 404 → probe 判「上游拒绝（status=404）」→ 回落 SSE → detail 非「非合法 JSON」→ FAIL）。这是预期失败面。

- [ ] **Step 3: 实现（mock 端点 + 代码注释）**

`tests/integration/mock_mcp_streamable.py`——`mcp_406` 端点之后追加：

```python
    @app.post("/mcp-multiline-data")
    async def mcp_post_multiline_data():
        # M5 扫尾 b（已知限制回归面）：initialize 响应为「多行 data:」SSE——
        # 探测 _first_message_data 只取首个 data 行（不拼接，注释见
        # forward/mcp_streamable.py）→ 截断 JSON 解析失败 → ok=false，不误判
        # 成功。真实 SDK（官方 SDK / Inspector）initialize 均为单行 data，本端点
        # 仅为已知限制的回归钉子，不代表合理上游形态。
        async def gen():
            yield b'event: message\ndata: {"jsonrpc": "2.0", "id": 1,\n'
            yield b'data: "result": {"protocolVersion": "2025-06-18",\n'
            yield b'data: "serverInfo": {"name": "multiline", "version": "0"}}}\n\n'
        return StreamingResponse(gen(), media_type="text/event-stream")
```

`src/agent_proxy/forward/mcp_streamable.py`——`_first_message_data` docstring 整体替换为：

```python
def _first_message_data(raw: bytes) -> bytes | None:
    """SSE 形态取首个 message（或未具名）事件的 data 载荷；空行复位事件名
    （与 SseEndpointRewriter / probe_sse 行解析同规）。

    已知限制（M5 扫尾 b，不实现拼接）：SSE 规范允许多个 data: 行按 \n 拼接为
    单条载荷，本函数只取首个 data 行——真实 MCP SDK（官方 SDK / Inspector）的
    initialize 响应均为单行 data，探测判定只需取到可解析 JSON；若上游确为多行
    形态则截断内容 JSON 解析失败判 ok=false（显式失败，不误判成功）。拼接实现
    需保留行间分隔语义（\n join），收益不抵复杂度。回归钉子：mock
    /mcp-multiline-data + test_proxy_mcp_streamable 探测用例 + 单测钉首行行为。
    """
```

（函数体零改动。）

- [ ] **Step 4: 运行预期（PASS）**

```bash
.venv/Scripts/python.exe -m pytest tests/unit/test_mcp_streamable.py tests/integration/test_proxy_mcp_streamable.py -q
```

Expected: 全绿（unit 8 + integration 11 = 19 passed）。

- [ ] **Step 5: M5 残余 c/d 项核对（零代码，逐项勾入本计划的「M5 残余处置节」）**

- c) M4 Task 6 评审遗留 proxy.py docstring：`src/agent_proxy/api/proxy.py` 模块 docstring 已含管线/分发/推送流语义说明（M4 终审收尾 commit `c21af28` 落地）——核对勾选，无改动。
- d) 401/500 非 2xx 不回落 / SSE 回落触发器矩阵：`tests/integration/test_mgmt_test_endpoint.py` 「M4 Task 5 评审核销项」节已覆盖（mcp-401 / mcp-500 不回落、405 回落成功、404/406 触发器矩阵）——核对勾选，无改动。

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "test(M5): 推送流 body 模式 trace 断言（M2 Task 5 评审遗留）+ _first_message_data 多行 data 已知限制钉住（mock/单测/注释）" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

### Task 7: README 快速开始/联调节更新 + 设计 §15.1 注记回写 + 全量回归

**Files:**
- Modify: `README.md`
- Modify: `docs/superpowers/specs/2026-11-21-agent-proxy-design.md`（仅 §15.1 注记，不改设计结论）

- [ ] **Step 1: README 更新**

`README.md`——「OAuth 凭证托管（M6）联调」节之后插入：

```markdown
## 管理页面（M7）

浏览器打开 `http://127.0.0.1:8800/admin`（未登录自动 302 到登录页）。`LOGIN_IMPL=stub`
为本地假登录：填写用户 ID（如 `u888`）、需要管理员视图把角色选为 `admin`，提交即换取
服务端会话（Redis `ap:sess:{sid}`，TTL `ADMIN_SESSION_TTL`，Cookie `ap_sess` 属性
HttpOnly+SameSite=Lax；`EXTERNAL_BASE` 为 https 的部署必须置 `SESSION_COOKIE_SECURE=true`）。

- 我的映射：注册（响应含代理地址与占位符 header，「保存到 Agent」）/ resolve 回显编辑 /
  test / 删除；
- 内置 MCP：列表（auth_mode、我的绑定状态）/ OAuth 授权绑定跳转 / 解绑 / test /
  保存到 Agent；
- 公共映射管理（仅 `role=admin`）：visibility=public 映射 CRUD + test + OAuth client
  手动配置；
- 退出登录：删除服务端会话（Cookie 中的 sid 随即失效）。

页面 API 全部走既有 `/api/v1` 接口（同源 fetch 携带 Cookie，`get_current_identity`
双通道：Bearer 优先——Agent/API 场景不变，无 Bearer 回退 Cookie 会话）；权限与 API
完全一致，页面不做越权捷径。
```

「接口速览」表在 `/api/v1/builtin-mappings/{id}/test` 行之后追加两行：

```markdown
| GET | /admin | 管理页面入口：未携带会话 302 → LoginProvider.login_url（stub=本地登录页）（M7） |
| GET/POST | /admin/login · /admin/auth/callback · /admin/logout | stub 登录页 / 回跳建会话（Set-Cookie ap_sess，HttpOnly+SameSite=Lax）/ 退出删除会话（M7） |
```

表尾追加一节：

```markdown
## Prometheus 指标（/metrics，§15.2）

`ap_requests_total{route,type,status}` · `ap_request_duration_seconds{route,type}` ·
`ap_upstream_duration_seconds{type}` · `ap_upstream_errors_total{type,code}` ·
`ap_bytes_total{direction}` · `ap_sse_active_connections` · `ap_inflight_requests` ·
`ap_oauth_actions_total{action}`。标签仅低基数维度（不含 user_id/mapping_id），
按映射/用户排查走审计日志 + request_id 关联。
```

- [ ] **Step 2: 设计文档 §15.1 注记回写**

`docs/superpowers/specs/2026-11-21-agent-proxy-design.md`——§15.1「页面清单」表格之后、`### 15.2` 之前插入：

```markdown
> **代理实现注记（M7）**：会话 Cookie 名 `ap_sess`，属性 `HttpOnly + SameSite=Lax + Path=/`；`Secure` 由 `SESSION_COOKIE_SECURE` 配置（默认 false）——本地开发与集成测试为纯 http，Secure Cookie 在 http 下浏览器与 httpx 均不回传、无法联调与自动化验证；`EXTERNAL_BASE` 为 https 的部署必须置 true。`return_to` 仅接受站内相对路径（`/` 开头且非 `//`，防开放重定向；Location 组装前 quote 防 CRLF 头注入）；stub 登录页在浏览器侧按 StubVerifier 同格式（`stub.<base64url(JSON)>.sig`）构造票据提交 `/admin/auth/callback`，与公司 SSO「回跳携带票据」时序同构，`company_sso` Provider 接入后登录页自然旁路（`login_url` 指向外部地址）。会话 TTL 创建时定（`ADMIN_SESSION_TTL`，默认 28800s），不做滑动续期；退出登录删除 Redis 键。页面身份上下文（user_name / is_admin）由模板服务端注入；权限边界仍在 `/api/v1` 既有矩阵（页面不做越权捷径：入口隐藏 + API 403/404 兜底）。
```

- [ ] **Step 3: 全量回归**

```bash
.venv/Scripts/python.exe -m pytest
```

Expected: **约 458 passed**（基线 417 + Task1 +13 / Task2 +10 / Task3 +9 / Task4 +4 / Task5 +2 / Task6 +3；以实际为准——执行者遇计数偏差应核对用例清单而非放宽断言）。无 WAL/告警；Windows Git Bash 下如遇端口占用（9901-9910）等待重试，不与其他进程并发跑测试。

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "docs(M7): README 管理页面快速开始/接口速览/指标清单 + 设计 §15.1 实现注记回写（M7 完成）" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

## M7 验收清单（对照设计 §16 M7 行 + §15 全章逐条）

- [ ] **§16 M7「浏览器经 stub 登录完成全部页面操作」**：`test_full_browser_flow_admin_as_admin`（Cookie Jar 浏览器模拟：入口 302 → 登录页 → 票据 callback → Set-Cookie → 我的映射注册/resolve/test/删除 + 内置列表 + 公共映射 CRUD + OAuth client 手动配置 + 退出登录）+ `test_real_tcp_admin_page_and_cookie_channel`（真实 TCP 9910 同链路）；登录页表单行为复刻 `_browser_login`（与 login.html JS 同构）
- [ ] **§16 M7「Bearer/Cookie 双通道身份」**：`test_cookie_session_fallback_resolves_identity` / `test_bearer_precedence_over_cookie_session` / `test_invalid_bearer_does_not_fall_back_to_cookie`（失败不回退钉住）/ `test_cookie_unknown_or_garbage_sid_401` / `test_no_bearer_no_cookie_401`（单元）+ `test_mgmt_create_list_with_cookie_session_only` / `test_bearer_takes_precedence_over_cookie_in_api` / `test_destroyed_session_cookie_401` / `test_missing_credentials_401_unchanged`（既有 API 零破坏，集成）
- [ ] **§16 M7「admin 视图权限隔离」**：`test_admin_renders_with_session_and_identity_context`（非 admin 无公共映射入口）/ `test_admin_context_admin_role_shows_public_view` / `test_non_admin_view_isolated_and_api_privilege_enforced`（入口隐藏 + API 403 兜底两层钉住，§15.1「页面不做越权捷径」）
- [ ] **§16 M7「/metrics 指标完整且基数受控」**：`test_all_eight_families_and_admin_route_exposed`（§15.2 八项逐族 TYPE 断言 + `route="admin"` 由页面流量产生）+ `test_metric_label_cardinality_controlled`（样本标签 ⊆ route/type/status/code/direction/action/le，无 mapping_id/user_id——基数控制 M2 已落实，本任务断言钉住）
- [ ] **§15.1 LoginProvider 抽象**：`LoginProvider` Protocol（login_url/exchange 签名与设计一致）+ `StubLoginProvider`（login_url=本地登录页、exchange 复用 StubVerifier）+ `build_login_provider` 白名单（company_sso 接入位）——`test_stub_login_url_carries_encoded_return_to` / `test_stub_exchange_decodes_ticket_to_identity` / `test_build_login_provider_unknown_impl_not_implemented`
- [ ] **§15.1 登录时序**：`test_admin_without_session_redirects_to_login`（302 → login_url）→ `test_stub_login_page_renders_with_callback_form`（本地假登录页：用户/角色选择）→ `test_callback_builds_session_and_cookie_attributes`（exchange → 会话入 Redis → Set-Cookie HttpOnly/SameSite=Lax/max-age → 302 /admin）→ `test_callback_invalid_ticket_redirects_login_without_session`（无效票据不落会话）
- [ ] **§15.1 服务端会话**：Redis `ap:sess:{sid}`（`test_create_then_get_roundtrip_with_ttl` + TTL 语义）+ Cookie 仅存不透明 sid + `ADMIN_SESSION_TTL`（`test_callback_session_ttl_uses_admin_session_ttl`）+ 退出登录删除（`test_logout_deletes_server_session_and_cookie`：Redis 键删除 + Cookie 失效 + 重放 302）
- [ ] **§15.1 页面清单**：我的映射（列表/注册表单含占位符预览 `showAgentConfig`/resolve 回显编辑/test/删除——index.html + 全流程用例）；内置 MCP（列表含 auth_mode+绑定状态/authorize 跳转/test——`loadBuiltin`/`authorizeBuiltin`）；公共映射管理仅 admin（CRUD+test+OAuth client 手动配置——`loadPublic`/`editClient`/`submitClient` + 模板 `{% if is_admin %}`）；退出登录
- [ ] **§15.2 八项指标**：见 Task 5（FAMILIES 表逐行对照 §15.2 表）；`ap_oauth_actions_total` 五种 action（bind/unbind/refresh/fail/transient）为 M6 既有接线，metrics.py docstring 对照钉住
- [ ] **§6.2 路由位**：`GET /admin/*`（main.py 注册 admin_pages router；middleware route_name `/admin` 分支 M1 预留自动生效）
- [ ] **M5 残余**：见下节处置表（a 落地 / b 落地 / c 核对 / d 核对）
- [ ] **全量回归**：`pytest` 全绿（约 458，基线 417 + 净增 ~41）
- [ ] **M7 不含**：Dockerfile/docker-compose（部署文档单独批次）、company_sso Provider 真实对接、CSRF 强化、前端增强（M8+ 债务节）

## M5 残余处置节（终审确认项逐条）

| 项 | 内容 | 处置 | 落点 |
|---|---|---|---|
| a | 推送流 body 模式 trace 断言（M2 Task 5 评审遗留；M3 已实现 `log_sse_event`，设计 §8.4 注记承诺「推送流的 message 事件行在 body 模式下记录」但无集成断言） | **落地**：Streamable GET `/mcp` 推送流 body 模式集成断言（message 事件记录 + 心跳不记录 + 无 endpoint 事件 + 敏感头指纹化） | Task 6 `test_streamable_push_stream_trace_body_mode_records_message_events` |
| b | `_first_message_data` 多行 data 已知限制 | **钉住不实现**：mock 增 `/mcp-multiline-data`（多行 data SSE 回归面）+ 单测钉首行行为 + `_first_message_data` docstring 注记（真实 SDK 单行；多行形态判 ok=false 不误判成功） | Task 6（mock + 单测 + 注释 + probe 用例） |
| c | M4 Task 6 评审遗留 proxy.py docstring | **核对已做**：模块 docstring 已含管线/分发/推送流语义（M4 终审 `c21af28`）——勾选，零改动 | Task 6 Step 5 |
| d | 401/500 无回落 / SSE 回落触发器矩阵 | **核对已核销**：`test_mgmt_test_endpoint.py`「M4 Task 5 评审核销项」节（mcp-401/mcp-500 不回落、405 回落成功、404/406 矩阵）——勾选，零改动 | Task 6 Step 5 |

## M8+ 债务节（本计划明示移交）

1. **company_sso Provider 真实对接**：票据格式/校验端点/登出单点（SLO）协议实现时定；实现为独立 Provider 类 + `build_login_provider` 白名单放行 + config.validate 白名单加 `company_sso`，页面与 API 零改动（设计 §15.1 对接抽象承诺）。
2. **CSRF 强化**：页面写操作（POST/PUT/DELETE fetch）现依赖 SameSite=Lax（跨站 POST/子请求不携带 Cookie）+ 同源 fetch；如需强化加 double-submit token 或 Origin 校验——一期不做，随安全评审批次。
3. **前端增强**：映射列表分页/排序、错误提示细化（区分 INVALID_PARAM 细节）、编辑 diff 预览、绑定状态自动轮询（现为手动「刷新」）、公共映射列表分页。
4. **会话滑动续期 / 并发登录策略**：一期固定 TTL 单会话（登出即删、过期惰性失效）；多设备/续期窗口需求出现时再引入。
5. **SESSION_COOKIE_SECURE 部署核对项**：部署文档批次（Dockerfile/compose 同批）必须在生产 checklist 钉住「EXTERNAL_BASE 为 https → SESSION_COOKIE_SECURE=true」。
6. **M6 页面相关债务承接**：client 行密文损坏（MASTER_KEY 变更）时页面区分提示（接口侧细分 config_invalid 回告码，M6 债务 10）；ENCRYPT_AT_REST（upstream_headers 可选加密）落地后页面提示形态（M6 债务 4）。
7. **/admin 页面安全响应头**：CSP / X-Content-Type-Options 等未加（无外部输入渲染面，模板变量全走 Jinja 自动转义 + JS esc()）；随安全评审批次补。
8. **/metrics 访问控制**：设计定位「无鉴权、仅内网可达」（与 /healthz、/readyz 一致）；网关侧隔离属部署交付，随部署文档批次。
9. **Dockerfile 与 docker-compose**：部署交付（用户要求的部署文档单独批次），本计划不含。
10. **trace 行为页面的覆盖**：管理页面流量（route=admin）的 trace 记录现为 metadata 模式默认行为（无 body 面板）；如需页面侧排障视图（按 request_id 查 trace/audit），属二期可观测性增强。

## 自查记录（对照任务要求）

- **§15 全章逐条**：§15.1 五块（对接抽象 / 登录时序 / 会话与鉴权兼容 / 页面清单 / 原则）各有具名用例或模板落点（见验收清单映射行）；§15.2 八项逐族 TYPE 断言 + 基数红线断言；§16 M7 验收行四要素（浏览器 stub 登录全页面操作 / 双通道 / admin 隔离 / metrics 完整且基数受控）全部有具名用例。
- **签名一致性**：`Identity(user_id/user_name/role)`、`TokenInvalidError(AppError 401/INVALID_TOKEN)`、`build_verifier(get_settings().token_verify_impl)` 均为 auth.py 既有形态；`app.state.redis / app.state.sessionmaker / app.state.settings` 与 main.py lifespan 一致；`request.state.uid/user_name` 审计接线与 middleware 既有字段一致；`is_admin(identity, settings.admin_role)` 复用 deps 既有函数；`Settings.admin_session_ttl` M1 已有（本计划零新增必填配置，仅加 `session_cookie_secure` 带默认值——既有调用零破坏）；模板 `TemplateResponse(request, name, context)` 为 FastAPI ≥0.165 的新签名；`response.set_cookie/delete_cookie` 为 Starlette Response 既有 API；测试侧 `make_token` / `app` / `client` / `real_proxy_app` 夹具复用未改语义。
- **双通道改造点唯一**：仅 `api/deps.py get_current_identity`（+ 私有 `_session_identity`），mgmt/proxy/builtin 全部依赖方零改动；页面路由不碰 `get_current_identity`（`_page_identity` 只读 Cookie，未登录 302 而非 401）。
- **无占位**：全部代码块为最终形态（无 TODO/省略号/「见实现」类占位；模板 HTML/JS 完整可渲染）；每任务「运行预期」给出 FAIL 面；测试计数逐任务给出，全量以实际为准。
- **端口簿**：9901 echo、9902 SSE mock、9903 Streamable mock（+`/mcp-multiline-data`）、9904 mock OAuth AS、9909 死端口、9910 被测代理——与 conftest/脚本/README 一致，无新增端口。
- **范围纪律**：Docker/部署交付、company_sso 对接、CSRF、前端增强全部入债务节；M5 四项仅 a/b 落地（c/d 核对勾选），不夹带其他重构。
- **预期计数**：417 → 约 458（Task1 +13 / Task2 +10 / Task3 +9 / Task4 +4 / Task5 +2 / Task6 +3）。

## 收尾批次（用户指令 2026-11-24，M7 任务全部完成后执行）

**user_id 整数化迁移**：内部系统 user_id 为整数——`proxy_mapping.owner_uid` 与 `proxy_oauth_credential.uid` 由 VARCHAR(64) 迁移为 BIGINT（设计 §5.1/§5.3 已按 BIGINT 定型，fc5046a），`Identity.user_id: str → int`，StubVerifier 数字 token 返回 int，全链路（services/deps/session/审计/schemas/make_token 测试工具/既有库 ALTER）统一适配。执行前需与在途编辑无冲突（M7 各任务完成后进行）。

## 收尾批次追加（用户确认 2026-11-24）

**敏感字段统一强制加密**（复用 M6 已验证的 Fernet 基建，与 user_id 整数化迁移同批收尾执行）：
- `proxy_mapping.upstream_headers` 由明文 JSON 迁移为 Fernet 密文落库（表 schema 评估：JSON→TEXT 密文列，非破坏 ALTER + 既有行一次性加密回写）
- Redis `ap:mapping:{id}` 缓存同步改存密文形态（与 `ap:cred:*` 先例一致，Redis 侧不落明文）
- 删除 `ENCRYPT_AT_REST` 可选开关（强制后无意义，`MASTER_KEY` 必填不变）
- 覆盖面核对：OAuth credential/client_secret 已强制（M6 交付），本批补齐 upstream_headers 即三类敏感数据全密文
- 读取路径透明：load_mapping 解密一次，转发/详情/resolve 对外行为零变化
