# M6 实施计划：公共映射（内置 MCP）+ OAuth 凭证托管（DCR/PKCE/加密存储/按用户注入）

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 交付 agent-proxy M6（设计 §14 全章 + §16 M6 行）：公共映射管理（`auth_mode=oauth` 仅 public、admin 权限矩阵、`GET /api/v1/builtin-mappings` 内置列表）；OAuth 客户端层（DCR RFC 7591 优先 + discovery 链式探测 + 手动配置降级）；授权绑定流程（state+PKCE(S256) 一次性 600s 绑 uid → code 换 token → 强制加密落库 uk(mapping_id,uid) → 302 回跳白名单域）；凭证层（绑定状态机、解绑+revoke、调用时按用户注入 `Authorization: Bearer`、expires_at-60s 自动刷新 + Redis 锁防并发、未绑定 401 `OAUTH_BINDING_REQUIRED`）；test 接口扩展（已绑定用户本人凭证验证 + 凭证失效提示重新授权）；mock OAuth AS+RS（uvicorn 真实监听 9904，DCR/authorize/token/revoke/well-known/RS echo 全端点）经真实 TCP 全链路测试 + 安全专项测试。

**Architecture:** 延续 M1–M4 分层 `api → services → forward/oauth → infra`。新增 `oauth` 包三个模块：`credential.py`（Fernet 强制加密 + 凭证 cache-aside + 刷新锁 + 注入取值）、`client.py`（PKCE/state/authorization_url/token 请求组装/客户端行存取/DCR）、`discovery.py`（`/.well-known/oauth-protected-resource → oauth-authorization-server` 两步探测 + 元数据解析）。新增 `api/builtin.py`（内置映射接口 + `/oauth/callback/{mapping_id}` 回调路由）。转发接线只有一处：`api/proxy.py` 在 `auth_mode=oauth` 时查凭证并把 `authorization`（小写键，与 `build_outbound_headers` 归一一致）写入 `mapping_data["upstream_headers"]` 副本，三形态（http/SSE/Streamable）共用既有管线零改动。

**Tech Stack:** Python 3.12（venv `.venv`，Git Bash 下 `.venv/Scripts/python.exe`）、FastAPI、httpx 0.28.1、SQLAlchemy 2 async、redis-py 4.6、cryptography 50（Fernet，已在 pyproject 依赖中）、uvicorn、pytest + pytest-asyncio。**无新增依赖**。

**对应设计文档:** §5.3（proxy_oauth_client / proxy_oauth_credential DDL——M1 建表已含全部列，本里程碑零 DDL 变更；Redis state/lock/cred 三键）、§6.5（内置接口表：builtin-mappings 列表 / authorize / callback / binding / test）、§6.6（OAuth 绑定用户 test 行 + `OAUTH_BINDING_REQUIRED`）、§13 测试策略（OAuth 行）、§14 全章（14.1 场景 / 14.2 鉴权矩阵 / 14.3 DCR+手动 / 14.4 授权绑定 / 14.5 注入与刷新 / 14.6 安全要点）、§15.2（`ap_oauth_actions_total`）、§16 M6 验收行。

**范围说明:** 本计划只覆盖 M6。M5 残余（集成测试补全的少量项）、M7（管理页面 / SSO / Prometheus 完善）不在本计划内。

**约定（延续 M1–M4）:** 测试令牌 `stub.<base64url(payload)>.sig`（`tests/utils.make_token`，admin 用 `role="admin"`）；测试库 `agent_proxy_test` + Redis db9、`SSRF_ALLOW_PRIVATE=true`、`LOG_DIR=logs-test`。当前基线 **293 passed** 全绿为出发点（实测确认）。commit 中文 + `Co-Authored-By: Claude Code <noreply@anthropic.com>`；真实 TCP 测试风格（mock 上游 uvicorn 真实监听，被测代理 9910）。

**端口簿:** 9901 echo 上游（不变）、9902 MCP SSE mock（不变）、9903 MCP Streamable mock（不变，本计划增补 `/mcp-secure` 端点）、**9904 mock OAuth AS+RS（新）**、9909 死端口（不变）、9910 被测代理（不变）。

**关键决策（实现前先读）：**

1. **本地/测试 Redis 为 3.0.504——没有 `GETDEL` 命令（实测确认）**。state 一次性消费用 **MULTI 事务管道** `pipeline(transaction=True)` 内 `GET + DELETE` 原子取删（Redis 3.0 支持 MULTI/EXEC；并发回调同一 state 仅一方取到值）；刷新锁 `SET NX EX 30` 在 3.0 可用（2.6.12+）。设计 §5.3 的三个 Redis key 语义不变，实现机制在代码注释与本计划钉死，避免执行者"顺手升级为 getdel"后在生产 Redis 6.2+ 与本地 3.0 间行为分叉。设计 §14.4 注记回写（Task 7）。
2. **加密是"强制"而非可选（§14.6）**：access/refresh token、client_secret 一律 `Fernet(key=SHA256(MASTER_KEY)→urlsafe_b64)` 密文落库，**不受 `ENCRYPT_AT_REST` 开关影响**；Redis cred 缓存（`ap:cred:*`，TTL 60s）存同一密文形态，读取时才解密（缓存命中也要过 Fernet——成本可忽略，换来 Redis 侧不落明文）。`MASTER_KEY` 未配置时加密/解密抛 500 `INTERNAL_ERROR`（fail-closed）。`ENCRYPT_AT_REST`（upstream_headers 可选加密）仍是 M7+ 债务，不在本计划。
3. **DCR 优先 + 手动降级（§14.3），discovery 两步链**：upstream origin 下 `/.well-known/oauth-protected-resource`（RFC 9728）取 `authorization_servers[0]`（缺省回退 origin 本身）→ `{as_base}/.well-known/oauth-authorization-server`（RFC 8414）取端点。首次 authorize 时无 client 行 → discovery → `registration_endpoint` 动态注册（redirect_uris 精确单一值、grant_types 含 authorization_code+refresh_token、S256）→ 落行 `source=dcr`（§5.3：authorize_url/token_url 两列 DCR 模式留空，**每次 authorize/callback 实时 discovery 取端点**）；有行 `source=manual` → 直接用行内 URL。discovery/DCR 失败 → `502 OAUTH_CLIENT_SETUP_FAILED`（detail 提示管理员改用手动配置）。手动模式无 revoke 端点配置列 → 解绑仅删本地凭证；**仅 dcr 客户端走 discovery 拿 `revocation_endpoint` 做 best-effort revoke**（§14.4"提供方支持时"）。
4. **回调路由取 `/oauth/callback/{mapping_id}`**（§14.3/§14.6 的 redirect_uri 精确形态），§6.5 表中"GET /oauth/callback"为其缩写；state 载荷含 mapping_id，回调先原子消费 state 再校验「state.mapping_id == 路径 mapping_id」（防跨映射伪造）。AS 错误响应（`?error=`）或缺 code → `302 front_redirect?binding=failed&reason=<短码>`；state 无效/重放/过期/不匹配 → `400 OAUTH_STATE_INVALID`（无安全回跳目标时不做 302）。front_redirect 白名单在 **authorize 时校验**（存入 state），callback 只按 state 存储值回跳。
5. **注入点唯一且最小侵入**：`api/proxy.py` 在 `auth_mode=oauth` 且任意有效身份放行后，查 `(mapping_id, uid)` 凭证 → 无/invalid → `401 OAUTH_BINDING_REQUIRED`（message 附授权引导，满足 §10"body 附授权引导信息"）→ `expires_at-60s` 内刷新（锁防并发）→ 写 `data["upstream_headers"]["authorization"] = f"Bearer {token}"`（**小写键**——`build_outbound_headers` 全小写归一，同名覆盖存储头，§14.2"覆盖存储同名头"）。`data` 是缓存 JSON 反序列化产物/`row_to_dict` 新 dict，本请求私有，跨请求无共享。SSE 建连注入一次（§14.5），Streamable/http 每请求注入。
6. **刷新并发语义**：抢锁成功者执行 refresh（更新 DB 行 + DEL cred 缓存 + `ap_oauth_actions_total{action="refresh"}`）；未抢到锁者轮询 cred 缓存（0.1s 间隔，上限 8s）等新 token，拿到即用，拿到 invalid 或超时 → 401。刷新失败（token 端点非 200/网络/缺 access_token）→ `status=invalid` 落库 + `{action="fail"}` → 401。已知竞态（明示接受）：等待者在刷新者 DEL 缓存前把旧行写回缓存的窗口——60s TTL 兜底且下轮过期再刷自愈，不引入分布式一致复杂度。
7. **绑定状态机数据面**：`authorizing` 态需要索引——state key 以随机 state 命名无法反查 uid，authorize 时另写 `ap:oauth:authz:{mapping_id}:{uid} = state`（同 TTL 600s，callback 成功/解绑删除）。此键为设计 §5.3 三键之外的最小增量，Task 7 回写设计文档。状态判定顺序：credential 行存在 → `bound/invalid`（按 status）；否则 authz 索引存在 → `authorizing`；否则 `unbound`。
8. **M6 新增错误码**（§10 表 Task 7 回写）：`OAUTH_STATE_INVALID`(400)、`OAUTH_CLIENT_NOT_CONFIGURED`(400)、`OAUTH_CLIENT_SETUP_FAILED`(502)、`OAUTH_NOT_APPLICABLE`(400)；`OAUTH_BINDING_REQUIRED`(401) 设计已有。refresh 审计（§14.6"刷新入审计"）复用当前请求 `request_id` + `action=oauth_refresh` 写 `agent_proxy.audit`——同一 request_id 会出现中间件行 + refresh 行两条，既有测试按 request_id 断唯一性不受影响（它们不触发刷新），新测试按 action 过滤。
9. **mock AS 9904 一体化 AS+RS**：well-known×2 + register + authorize（PKCE S256 必须、redirect_uri 精确/前缀校验）+ token（code 一次性、PKCE 校验、client 认证 basic/post/none、`expires_in`/`refresh_sleep`/`fail_refresh` 脚本化）+ revoke（access 吊销连带配对 refresh）+ `/api/**` echo（RS 注入断言面）。**同一 9904 被 ASGI（testserver）与真实 TCP（9910）两套夹具共享** → preset 手动客户端（manual-cl）的 redirect_uri 按前缀白名单放行两 hosts，DCR 客户端仍精确匹配。签发的 access token 同步登记 `mock_mcp_streamable.secure_state["valid_tokens"]`，供 9903 `/mcp-secure`（本计划增补）做"仅有效 token 可用"的凭证失效面；每个集成测试前由 conftest autouse 夹具 `POST /_test/reset` 重置。
10. **mock 9903 增补 `/mcp-secure`**：仅接受 mock AS 签发且未吊销的 token（缺失/失配 401），initialize result `serverInfo.caller` 回告到达上游的 Authorization——"本人凭证到达上游"与"凭证失效提示重新授权"两个用例的断言面（probe 非 2xx 短路语义沿用 M4 定稿：401 不回落直接判失败）。

---

## 文件结构（M6 变更后）

```
agent-proxy/
├── docs/superpowers/plans/
│   └── 2026-11-24-m6-oauth-credentials.md   # 本计划
├── docs/superpowers/specs/
│   └── 2026-11-21-agent-proxy-design.md     # [改] §5.3 Redis 表增 authz 索引键；
│                                           #      §6.5 表增 client 配置接口行；
│                                           #      §10 表增 4 个 M6 错误码；
│                                           #      §14.4 注记（MULTI 取代 GETDEL / authz 索引）
├── scripts/
│   └── mock_oauth_as_server.py              # [新] mock OAuth AS+RS 独立入口（浏览器走全流程联调用）
├── src/agent_proxy/
│   ├── api/
│   │   ├── builtin.py                       # [新] /api/v1/builtin-mappings 列表/authorize/
│   │   │                                    #      client 配置/binding/test + /oauth/callback
│   │   ├── proxy.py                         # [改] auth_mode=oauth 按用户注入（管线唯一接线点）
│   │   └── mgmt.py                          # [改] auth_mode 贯通 + public 详情/改删 admin 矩阵（§14.2）
│   ├── oauth/
│   │   ├── __init__.py                      # [新]
│   │   ├── client.py                        # [新] PKCE/state/URL/token 请求组装 + 客户端行存取
│   │   │                                    #      + ensure_client（DCR RFC 7591 / 手动）
│   │   ├── credential.py                    # [新] Fernet 强制加密 + cred 缓存 + 刷新锁 + 注入取值
│   │   └── discovery.py                     # [新] well-known 两步探测 + 元数据解析
│   ├── main.py                              # [改] 注册 builtin/callback 路由
│   ├── middleware.py                        # [改] route_name：/oauth/* → builtin（metrics/审计 route）
│   ├── schemas.py                           # [改] auth_mode 增量 + OAuth client/authorize/binding/list 模型
│   └── services.py                          # [改] create/update 携带 auth_mode（oauth⇒public 校验）+
│                                            #      public 映射 admin 改删/详情旁路
├── tests/
│   ├── conftest.py                          # [改] env 增 CORS_ALLOWED_ORIGINS（front_redirect 白名单）
│   ├── unit/
│   │   └── test_oauth.py                    # [新] crypto/PKCE/state/URL/token_auth/discovery 解析/白名单
│   └── integration/
│       ├── conftest.py                      # [改] mock_oauth_as_server(9904) 夹具 + 每测 _test/reset
│       ├── mock_oauth_as.py                 # [新] 最小 OAuth2 AS+RS（uvicorn 9904）
│       ├── mock_mcp_streamable.py           # [改] 增 secure_state + /mcp-secure（token 校验面）
│       ├── test_oauth_as_upstream.py        # [新] mock AS 直连冒烟（协议行为钉住）
│       ├── test_oauth_credential_store.py   # [新] 凭证存取层集成（加密/缓存/upsert/删除）
│       ├── test_oauth_client_config.py      # [新] auth_mode CRUD 矩阵 + 手动 client 配置接口
│       ├── test_oauth_binding_flow.py       # [新] authorize→callback→binding 全流程（ASGI）
│       ├── test_oauth_dcr_flow.py           # [新] DCR 全流程 + 解绑 revoke + metrics（真实 TCP）
│       ├── test_oauth_injection.py          # [新] 三形态注入/刷新/并发锁/未绑定 401/test 扩展（真实 TCP）
│       └── test_oauth_security.py           # [新] 安全专项（重放/伪造/白名单/密文/日志无 token）
└── README.md                                # [改] 接口速览 + OAuth 绑定流程说明
```

---

### Task 1: `oauth` 包基础层——Fernet 强制加密 / PKCE / state / URL 与 token 请求组装 / discovery 解析 / front_redirect 白名单

**Files:**
- New: `src/agent_proxy/oauth/__init__.py`
- New: `src/agent_proxy/oauth/credential.py`（crypto + 凭证 cache-aside 存取 + 过期判定）
- New: `src/agent_proxy/oauth/client.py`（纯逻辑部分）
- New: `src/agent_proxy/oauth/discovery.py`（纯解析部分 + 探测函数）
- New: `tests/unit/test_oauth.py`
- New: `tests/integration/test_oauth_credential_store.py`

- [ ] **Step 1: 写失败测试（单元）**

`tests/unit/test_oauth.py`（新文件）：

```python
"""oauth 基础层单测（设计 §14.3 / §14.6）：Fernet 强制加密、PKCE(S256)、
state 载荷、authorization_url / redirect_uri 组装、token_auth 三形态请求组装、
DCR 注册载荷、AS 元数据解析、front_redirect 域白名单。"""
import base64
import hashlib

import pytest

from agent_proxy.errors import AppError
from agent_proxy.oauth.client import (build_authorization_url, build_dcr_payload,
                                      build_redirect_uri, build_token_request,
                                      code_challenge_s256, decode_state_payload,
                                      encode_state_payload, new_code_verifier,
                                      new_state, normalize_token_auth,
                                      state_key, validate_front_redirect)
from agent_proxy.oauth.credential import encrypt_text, decrypt_text, is_expired
from agent_proxy.oauth.discovery import (DiscoveryError, parse_as_metadata,
                                         parse_protected_resource, upstream_origin)

MASTER = "test-master-key"

# RFC 7636 附录 B 官方向量（S256 已知答案，钉死 challenge 算法）
RFC_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
RFC_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

ALLOWED = ("http://127.0.0.1:9910", "http://testserver")


# ---------- crypto（§14.6：强制加密，不受 ENCRYPT_AT_REST 影响） ----------

def test_encrypt_decrypt_roundtrip_and_ciphertext_form():
    ct = encrypt_text("at-secret-value-123456", MASTER)
    assert ct != "at-secret-value-123456"
    assert ct.startswith("gAAAA")                      # Fernet 密文形态（读库验证的判据）
    assert decrypt_text(ct, MASTER) == "at-secret-value-123456"


def test_encrypt_requires_master_key_fail_closed():
    with pytest.raises(AppError) as ei:
        encrypt_text("x", "")
    assert (ei.value.status, ei.value.code) == (500, "INTERNAL_ERROR")


def test_decrypt_wrong_key_maps_to_internal_error():
    ct = encrypt_text("x", MASTER)
    with pytest.raises(AppError) as ei:
        decrypt_text(ct, "another-key")
    assert ei.value.code == "INTERNAL_ERROR"


def test_is_expired_none_means_never_and_skew_60s():
    from datetime import datetime, timedelta
    assert is_expired(None) is False                   # 无 expires_at = 永不过期
    now = datetime.utcnow()
    assert is_expired(now + timedelta(seconds=30), now=now) is True    # 60s 提前量内
    assert is_expired(now + timedelta(seconds=120), now=now) is False
    assert is_expired(now - timedelta(seconds=1), now=now) is True


# ---------- PKCE（RFC 7636 S256 必须） ----------

def test_pkce_s256_known_vector():
    assert code_challenge_s256(RFC_VERIFIER) == RFC_CHALLENGE


def test_pkce_verifier_shape_and_randomness():
    v1, v2 = new_code_verifier(), new_code_verifier()
    assert len(v1) == 43 and v1 != v2                  # 32 字节 → base64url 43 字符
    assert code_challenge_s256(v1) != code_challenge_s256(v2)


# ---------- state（一次性 600s 绑 uid 的载荷，§14.4） ----------

def test_state_roundtrip_and_key_prefix():
    state = new_state()
    assert len(state) == 32                            # token_hex(16)
    assert state_key(state) == f"ap:oauth:state:{state}"
    payload = encode_state_payload(uid="u888", mapping_id="m1m2m3m4m5m6",
                                   code_verifier="v" * 43, front_redirect="http://t/c")
    restored = decode_state_payload(payload)
    assert restored == {"uid": "u888", "mapping_id": "m1m2m3m4m5m6",
                        "code_verifier": "v" * 43, "front_redirect": "http://t/c"}


def test_state_payload_missing_fields_rejected():
    from agent_proxy.errors import AppError
    with pytest.raises(AppError) as ei:
        decode_state_payload('{"uid": "u888"}')
    assert ei.value.code == "OAUTH_STATE_INVALID"
    with pytest.raises(AppError):
        decode_state_payload("not-json")


# ---------- URL / redirect_uri / DCR 载荷 ----------

def test_redirect_uri_exact_form():
    assert build_redirect_uri("http://127.0.0.1:9910/", "m1m2m3m4m5m6") == \
        "http://127.0.0.1:9910/oauth/callback/m1m2m3m4m5m6"


def test_authorization_url_contains_pkce_and_state():
    url = build_authorization_url("http://127.0.0.1:9904/oauth/authorize",
                                  client_id="cl-1",
                                  redirect_uri="http://t/oauth/callback/m1m2m3m4m5m6",
                                  state="s" * 32, code_verifier=RFC_VERIFIER,
                                  scopes="read write")
    assert "response_type=code" in url and "client_id=cl-1" in url
    assert f"code_challenge={RFC_CHALLENGE}" in url
    assert "code_challenge_method=S256" in url and "scope=read+write" in url
    assert "state=" in url and "redirect_uri=http%3A%2F%2Ft%2Foauth%2Fcallback%2F" in url


def test_authorization_url_rejoins_existing_query():
    url = build_authorization_url("http://as/oauth/authorize?prompt=login",
                                  client_id="c", redirect_uri="http://t/cb",
                                  state="s", code_verifier=RFC_VERIFIER, scopes=None)
    assert "prompt=login&" in url


def test_dcr_payload_rfc7591_fields():
    payload = build_dcr_payload("agent-proxy-m1m2m3m4m5m6",
                                "http://t/oauth/callback/m1m2m3m4m5m6")
    assert payload["redirect_uris"] == ["http://t/oauth/callback/m1m2m3m4m5m6"]
    assert set(payload["grant_types"]) == {"authorization_code", "refresh_token"}
    assert payload["token_endpoint_auth_method"] == "client_secret_post"
    assert payload["code_challenge_method"] == "S256"


# ---------- token 请求组装（token_auth 三形态，RFC 6749 §2.3） ----------

def test_token_request_client_secret_post():
    headers, form = build_token_request("client_secret_post", client_id="c1",
                                        client_secret="s1",
                                        extra={"grant_type": "refresh_token",
                                               "refresh_token": "rt1"})
    assert headers == {} and form["client_id"] == "c1" and form["client_secret"] == "s1"
    assert form["grant_type"] == "refresh_token"


def test_token_request_client_secret_basic():
    headers, form = build_token_request("client_secret_basic", client_id="c1",
                                        client_secret="s1", extra={"code": "cd1"})
    assert headers["Authorization"].startswith("Basic ")
    raw = base64.b64decode(headers["Authorization"][len("Basic "):]).decode()
    assert raw == "c1:s1"
    assert "client_secret" not in form and form["code"] == "cd1"


def test_token_request_none_public_client():
    headers, form = build_token_request("none", client_id="pub",
                                        client_secret=None, extra={"code": "cd1"})
    assert headers == {} and form["client_id"] == "pub" and "client_secret" not in form


def test_normalize_token_auth_fallback_to_post():
    assert normalize_token_auth(None) == "client_secret_post"
    assert normalize_token_auth("client_secret_jwt") == "client_secret_post"
    assert normalize_token_auth("client_secret_basic") == "client_secret_basic"


# ---------- discovery 元数据解析（RFC 9728 → RFC 8414 链） ----------

def test_discovery_parse_protected_resource_prefers_first_as_server():
    origin = "http://127.0.0.1:9904"
    assert parse_protected_resource({"authorization_servers": ["http://as-inner"]},
                                    origin) == "http://as-inner"
    assert parse_protected_resource({}, origin) == origin            # 缺省回退 origin
    assert parse_protected_resource("not-a-dict", origin) == origin


def test_discovery_parse_as_metadata_ok_and_missing():
    meta = parse_as_metadata({"authorization_endpoint": "http://a/auth",
                              "token_endpoint": "http://a/token",
                              "registration_endpoint": "http://a/reg"})
    assert meta["registration_endpoint"] == "http://a/reg"
    with pytest.raises(DiscoveryError):
        parse_as_metadata({"authorization_endpoint": "http://a/auth"})   # 缺 token_endpoint
    with pytest.raises(DiscoveryError):
        parse_as_metadata(None)


def test_discovery_upstream_origin_helper():
    assert upstream_origin("https://mcp.ex.com/sse?a=1") == "https://mcp.ex.com"


# ---------- front_redirect 域白名单（§14.6 防开放重定向） ----------

def test_front_redirect_allows_whitelisted_origin_with_path_query():
    out = validate_front_redirect("http://testserver/console?page=1", ALLOWED)
    assert out == "http://testserver/console?page=1"


def test_front_redirect_rejects_outside_whitelist():
    for bad in ("http://evil.example.com/cb",                    # 域不同
                "http://127.0.0.1:8080/cb",                      # 端口不同
                "https://testserver/cb",                         # scheme 不同
                "javascript:alert(1)",                           # 非 http(s)
                "/relative/path",                                # 相对地址
                "", "   "):
        with pytest.raises(AppError) as ei:
            validate_front_redirect(bad, ALLOWED)
        assert ei.value.code == "INVALID_PARAM"


def test_front_redirect_empty_whitelist_fail_closed():
    with pytest.raises(AppError):
        validate_front_redirect("http://testserver/cb", ())
```

- [ ] **Step 2: 写失败测试（集成，凭证存取层，真实 MySQL/Redis）**

`tests/integration/test_oauth_credential_store.py`（新文件）：

```python
"""OAuth 凭证存取层集成（app 夹具 + 真实 MySQL/Redis，设计 §5.3）：
加密 upsert（uk mapping_id+uid）/ cred 缓存 cache-aside（密文形态）/ 失效 /
invalid 标记 / 删除。"""
from datetime import datetime, timedelta

from sqlalchemy import select

from agent_proxy.models import OAuthCredential
from agent_proxy.oauth.credential import (delete_credential, encrypt_text,
                                          invalidate_credential, load_credential,
                                          mark_credential_invalid, save_credential)

MASTER = "test-master-key"
MID = "m1m2m3m4m5m6"
UID = "u888"


async def _save(app, uid=UID, expires=None, access="at-plain-123456",
                refresh="rt-plain-123456", mapping_id=MID):
    async with app.state.sessionmaker() as session:
        await save_credential(session, app.state.redis, mapping_id, uid,
                              access_token_ct=encrypt_text(access, MASTER),
                              refresh_token_ct=(encrypt_text(refresh, MASTER)
                                                if refresh else None),
                              expires_at=expires, scope="read", master_key=MASTER)


async def _raw_row(app, uid=UID, mapping_id=MID):
    async with app.state.sessionmaker() as session:
        return (await session.execute(
            select(OAuthCredential).where(OAuthCredential.mapping_id == mapping_id,
                                          OAuthCredential.uid == uid))).scalar_one()


async def test_save_stores_ciphertext_and_load_decrypts(app):
    await _save(app)
    row = await _raw_row(app)
    assert row.access_token.startswith("gAAAA")        # 落库密文（§14.6 强制加密）
    assert "at-plain-123456" not in row.access_token
    assert row.refresh_token.startswith("gAAAA")
    async with app.state.sessionmaker() as session:
        cred = await load_credential(session, app.state.redis, MID, UID)
    assert cred["status"] == "active" and cred["scope"] == "read"
    assert cred["access_token"].startswith("gAAAA")    # 缓存同密文形态，读取方负责解密


async def test_load_cache_aside_second_read_survives_db_row_loss(app):
    await _save(app)
    async with app.state.sessionmaker() as session:
        assert await load_credential(session, app.state.redis, MID, UID) is not None
    # 直接删 DB 行：第二次读取仍命中 Redis 缓存（cache-aside 生效面）
    async with app.state.sessionmaker() as session:
        row = await _raw_row(app)
        await session.delete(row)
        await session.commit()
    async with app.state.sessionmaker() as session:
        cached = await load_credential(session, app.state.redis, MID, UID)
    assert cached is not None and cached["scope"] == "read"


async def test_invalidate_forces_db_reload(app):
    await _save(app)
    async with app.state.sessionmaker() as session:
        await load_credential(session, app.state.redis, MID, UID)
    await invalidate_credential(app.state.redis, MID, UID)
    async with app.state.sessionmaker() as session:    # 缓存已删 → 回源 DB
        assert await load_credential(session, app.state.redis, MID, UID) is not None


async def test_upsert_overwrites_and_resets_invalid(app):
    await _save(app)
    async with app.state.sessionmaker() as session:
        await mark_credential_invalid(session, app.state.redis, MID, UID)
    row = await _raw_row(app)
    assert row.status == "invalid"
    await _save(app, access="at-second-token-123456")  # 重新授权 = upsert 覆盖
    rows = await _raw_row(app)
    assert rows.status == "active"
    assert rows.access_token.startswith("gAAAA") and "at-second-token" not in rows.access_token


async def test_delete_removes_row_and_cache(app):
    await _save(app)
    async with app.state.sessionmaker() as session:
        assert await delete_credential(session, app.state.redis, MID, UID) is True
        assert await load_credential(session, app.state.redis, MID, UID) is None
        assert await delete_credential(session, app.state.redis, MID, UID) is False


async def test_save_with_null_refresh_and_expiry(app):
    await _save(app, refresh=None)
    row = await _raw_row(app)
    assert row.refresh_token is None and row.expires_at is None
```

- [ ] **Step 3: 实现 oauth 包**

`src/agent_proxy/oauth/__init__.py`（新文件）：

```python
"""OAuth 领域能力包（M6，设计 §14）：discovery / client / credential。"""
```

`src/agent_proxy/oauth/credential.py`（新文件，本任务完整版）：

```python
"""OAuth 凭证层（设计 §5.3 / §14.5 / §14.6）：强制加密存取、cred 缓存、刷新与注入。

安全底线：
- access/refresh token 落库一律 Fernet(MASTER_KEY) 密文，不受 ENCRYPT_AT_REST 开关影响；
- Redis cred 缓存（ap:cred:*，TTL 60s）存同一密文形态，读取方按需解密——缓存命中也过
  Fernet（成本可忽略），换取 Redis 侧不落明文；
- token 明文不入任何日志（本模块日志只记 mapping_id/uid/异常类型名）。

刷新（§14.5，Task 6 交付）：expires_at - 60s 内即视为过期 → refresh_token 换新；
Redis 锁 ap:lock:refresh:{mapping_id}:{uid}（SET NX EX 30）防并发刷新。

兼容性注记（实测钉死）：本地/测试 Redis 为 3.0.504，无 GETDEL 命令——凡需
"原子取删"语义一律用 MULTI 事务管道（pipeline(transaction=True)），不得改写为
getdel（生产 Redis 6.2+ 虽支持，本地 3.0 会直接报 unknown command）。
"""
from __future__ import annotations

import base64
import hashlib
import logging
from datetime import datetime, timedelta

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..errors import AppError
from ..models import OAuthCredential

log = logging.getLogger("agent_proxy")

# 过期提前量（§14.5：expires_at - 60s 过期即 refresh）
REFRESH_SKEW_SECONDS = 60
# 刷新互斥锁 TTL（§5.3：ap:lock:refresh 30s）
REFRESH_LOCK_TTL = 30

_fernet_cache: dict[str, Fernet] = {}


def _fernet(master_key: str) -> Fernet:
    if not master_key:
        # fail-closed：无密钥宁可拒绝加密，绝不落明文（§14.6）
        raise AppError(500, "INTERNAL_ERROR", "MASTER_KEY 未配置，无法加解密 OAuth 凭证")
    f = _fernet_cache.get(master_key)
    if f is None:
        derived = base64.urlsafe_b64encode(
            hashlib.sha256(master_key.encode("utf-8")).digest())
        f = Fernet(derived)
        _fernet_cache[master_key] = f
    return f


def encrypt_text(plaintext: str, master_key: str) -> str:
    return _fernet(master_key).encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt_text(ciphertext: str, master_key: str) -> str:
    try:
        return _fernet(master_key).decrypt(ciphertext.encode("ascii")).decode("utf-8")
    except (InvalidToken, UnicodeEncodeError) as exc:
        raise AppError(500, "INTERNAL_ERROR",
                       "OAuth 凭证解密失败（MASTER_KEY 变更？需重新授权）") from exc


def cred_cache_key(mapping_id: str, uid: str) -> str:
    return f"ap:cred:{mapping_id}:{uid}"


def refresh_lock_key(mapping_id: str, uid: str) -> str:
    return f"ap:lock:refresh:{mapping_id}:{uid}"


def is_expired(expires_at: datetime | None, now: datetime | None = None,
               skew: int = REFRESH_SKEW_SECONDS) -> bool:
    """§14.5：expires_at - skew <= now 视为过期；None 视为永不过期（AS 未下发
    expires_in）。时间统一 naive UTC（写读两侧均为本模块 datetime.utcnow）。"""
    if expires_at is None:
        return False
    now = now or datetime.utcnow()
    return expires_at <= now + timedelta(seconds=skew)


def expires_at_from(expires_in) -> datetime | None:
    """AS 响应 expires_in（秒）→ naive UTC expires_at；缺失/非法/非正数 → None。"""
    try:
        seconds = int(expires_in)
    except (TypeError, ValueError):
        return None
    return datetime.utcnow() + timedelta(seconds=seconds) if seconds > 0 else None


def _row_to_cred(row: OAuthCredential) -> dict:
    return {"access_token": row.access_token, "refresh_token": row.refresh_token,
            "expires_at": row.expires_at.isoformat() if row.expires_at else None,
            "scope": row.scope, "status": row.status}


async def _cache_get(r, mapping_id: str, uid: str) -> dict | None:
    try:
        raw = await r.get(cred_cache_key(mapping_id, uid))
    except Exception as exc:
        log.warning("cred 缓存读取失败，回源 MySQL: %s", exc)
        return None
    if raw is None:
        return None
    try:
        data = json.loads(raw)
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


async def _cache_put(r, mapping_id: str, uid: str, cred: dict, ttl: int = 60) -> None:
    try:
        await r.set(cred_cache_key(mapping_id, uid),
                    json.dumps(cred, ensure_ascii=False), ex=ttl)
    except Exception as exc:
        log.warning("cred 缓存写入失败: %s", exc)


async def invalidate_credential(r, mapping_id: str, uid: str) -> None:
    """绑定 / 解绑 / 刷新后失效 cred 缓存（§5.3：绑定 / 解绑 / 刷新时失效）。"""
    try:
        await r.delete(cred_cache_key(mapping_id, uid))
    except Exception as exc:
        log.warning("cred 缓存删除失败: %s", exc)


async def load_credential(session: AsyncSession, r, mapping_id: str, uid: str) -> dict | None:
    """缓存优先的凭证读取（密文形态，§5.3 cache-aside）；未绑定返回 None。"""
    cached = await _cache_get(r, mapping_id, uid)
    if cached is not None:
        return cached
    row = (await session.execute(
        select(OAuthCredential).where(OAuthCredential.mapping_id == mapping_id,
                                      OAuthCredential.uid == uid)
    )).scalar_one_or_none()
    if row is None:
        return None
    cred = _row_to_cred(row)
    await _cache_put(r, mapping_id, uid, cred)
    return cred


async def save_credential(session: AsyncSession, r, mapping_id: str, uid: str, *,
                          access_token_ct: str, refresh_token_ct: str | None,
                          expires_at: datetime | None, scope: str | None,
                          master_key: str) -> None:
    """uk(mapping_id, uid) upsert：重复授权覆盖旧凭证并复位 active（§14.4 状态机
    invalid → 重新授权 → bound）。密文由调用方以 encrypt_text 产出后传入。"""
    row = (await session.execute(
        select(OAuthCredential).where(OAuthCredential.mapping_id == mapping_id,
                                      OAuthCredential.uid == uid)
    )).scalar_one_or_none()
    if row is None:
        row = OAuthCredential(mapping_id=mapping_id, uid=uid,
                              access_token=access_token_ct,
                              refresh_token=refresh_token_ct, expires_at=expires_at,
                              scope=scope, status="active")
        session.add(row)
    else:
        row.access_token = access_token_ct
        row.refresh_token = refresh_token_ct
        row.expires_at = expires_at
        row.scope = scope
        row.status = "active"
    await session.commit()
    await invalidate_credential(r, mapping_id, uid)


async def mark_credential_invalid(session: AsyncSession, r, mapping_id: str,
                                  uid: str) -> None:
    """刷新失败 → invalid（§14.4：invalid 后调用一律 401，页面引导重新授权）。"""
    row = (await session.execute(
        select(OAuthCredential).where(OAuthCredential.mapping_id == mapping_id,
                                      OAuthCredential.uid == uid)
    )).scalar_one_or_none()
    if row is not None and row.status != "invalid":
        row.status = "invalid"
        await session.commit()
    await invalidate_credential(r, mapping_id, uid)


async def delete_credential(session: AsyncSession, r, mapping_id: str, uid: str) -> bool:
    """解绑：删除本地凭证（revoke 由 api 层在删除前取 token 后 best-effort 调用）。"""
    row = (await session.execute(
        select(OAuthCredential).where(OAuthCredential.mapping_id == mapping_id,
                                      OAuthCredential.uid == uid)
    )).scalar_one_or_none()
    if row is None:
        return False
    await session.delete(row)
    await session.commit()
    await invalidate_credential(r, mapping_id, uid)
    return True
```

注意：`credential.py` 顶部 import 区需补 `import json`（`_cache_get/_cache_put` 使用），最终文件头为：

```python
from __future__ import annotations

import base64
import hashlib
import json
import logging
from datetime import datetime, timedelta
```

`src/agent_proxy/oauth/client.py`（新文件，本任务完整版）：

```python
"""OAuth 客户端层（设计 §14.3）：DCR（RFC 7591）优先 + 手动配置兼容。

本模块 Task 1 交付纯逻辑：PKCE(S256)、state 载荷、authorization_url /
redirect_uri / token 请求 / DCR 载荷组装、token_auth 归一、front_redirect 域
白名单；DB 行存取（load/save）、state 一次性消费（Redis MULTI）与 ensure_client
（discovery → DCR）随 Task 3–5 增量交付。

安全锚点（§14.6）：
- PKCE(S256) 必须——challenge = BASE64URL(SHA256(verifier))（剥 '='）；
- state 一次性、600s TTL、绑定 uid（防 CSRF / 顶号）；
- redirect_uri 精确等于 {EXTERNAL_BASE}/oauth/callback/{mapping_id}；
- front_redirect 仅允许 CORS_ALLOWED_ORIGINS 精确 origin（防开放重定向）。
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
from urllib.parse import urlencode, urlparse

from ..errors import AppError

STATE_KEY_PREFIX = "ap:oauth:state:"


# ---------- PKCE（RFC 7636） ----------

def new_code_verifier() -> str:
    """43-128 字符 base64url；取 32 字节随机 → 43 字符。"""
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")


def code_challenge_s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


# ---------- state（ap:oauth:state:{state}，一次性 600s 绑 uid） ----------

def new_state() -> str:
    return secrets.token_hex(16)                       # 128bit，URL 安全


def state_key(state: str) -> str:
    return f"{STATE_KEY_PREFIX}{state}"


def encode_state_payload(*, uid: str, mapping_id: str, code_verifier: str,
                         front_redirect: str) -> str:
    return json.dumps({"uid": uid, "mapping_id": mapping_id,
                       "code_verifier": code_verifier,
                       "front_redirect": front_redirect}, ensure_ascii=False)


def decode_state_payload(raw: str | bytes) -> dict:
    try:
        payload = json.loads(raw)
    except (ValueError, TypeError) as exc:
        raise AppError(400, "OAUTH_STATE_INVALID", "state 载荷非法") from exc
    required = ("uid", "mapping_id", "code_verifier", "front_redirect")
    if not isinstance(payload, dict) or not all(k in payload for k in required):
        raise AppError(400, "OAUTH_STATE_INVALID", "state 载荷非法")
    return payload


# ---------- URL / 载荷组装 ----------

def build_redirect_uri(external_base: str, mapping_id: str) -> str:
    """精确值（§14.6）：{EXTERNAL_BASE}/oauth/callback/{mapping_id}，不拼额外路径。"""
    return f"{external_base.rstrip('/')}/oauth/callback/{mapping_id}"


def build_authorization_url(authorize_url: str, *, client_id: str, redirect_uri: str,
                            state: str, code_verifier: str,
                            scopes: str | None) -> str:
    params = {"response_type": "code", "client_id": client_id,
              "redirect_uri": redirect_uri, "state": state,
              "code_challenge": code_challenge_s256(code_verifier),
              "code_challenge_method": "S256"}
    if scopes:
        params["scope"] = scopes
    sep = "&" if urlparse(authorize_url).query else "?"
    return f"{authorize_url}{sep}{urlencode(params)}"


def build_dcr_payload(client_name: str, redirect_uri: str) -> dict:
    """RFC 7591 §2 注册载荷：redirect_uris 精确单一值 + PKCE S256 声明。"""
    return {"client_name": client_name, "redirect_uris": [redirect_uri],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "client_secret_post",
            "code_challenge_method": "S256"}


def normalize_token_auth(value: str | None) -> str:
    """token_auth 白名单归一；AS 未声明 / 声明了未实现形态 → client_secret_post
    （RFC 7591 注册时我方显式声明该形态，此处仅兜底历史脏数据）。"""
    if value in ("client_secret_basic", "client_secret_post", "none"):
        return value
    return "client_secret_post"


def build_token_request(token_auth: str, *, client_id: str,
                        client_secret: str | None,
                        extra: dict[str, str]) -> tuple[dict[str, str], dict[str, str]]:
    """按 token_auth 组装 token/revoke 端点请求 (headers, form)。
    client_secret_basic 走 HTTP Basic（RFC 6749 §2.3.1）；client_secret_post 走
    body；none 仅 client_id（公共客户端）。client_id 始终入 form（服务端两种读法兼容）。"""
    form: dict[str, str] = dict(extra)
    form["client_id"] = client_id
    headers: dict[str, str] = {}
    if token_auth == "client_secret_basic" and client_secret is not None:
        raw = f"{client_id}:{client_secret}".encode("utf-8")
        headers["Authorization"] = "Basic " + base64.b64encode(raw).decode("ascii")
    elif client_secret is not None:                    # post / 兜底
        form["client_secret"] = client_secret
    return headers, form


# ---------- front_redirect 域白名单（§14.6 防开放重定向） ----------

def validate_front_redirect(front_redirect: str,
                            allowed_origins: tuple[str, ...]) -> str:
    """仅允许 CORS_ALLOWED_ORIGINS 精确 origin（scheme://host:port）下的地址，
    path/query 保留；空白名单一律拒绝（fail-closed）。非法 → 400 INVALID_PARAM。"""
    if not front_redirect or not front_redirect.strip():
        raise AppError(400, "INVALID_PARAM", "front_redirect 不能为空")
    parsed = urlparse(front_redirect.strip())
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise AppError(400, "INVALID_PARAM", "front_redirect 必须为绝对 http(s) 地址")
    origin = f"{parsed.scheme}://{parsed.netloc}"
    normalized = {o.strip().rstrip("/") for o in allowed_origins}
    if origin not in normalized:
        raise AppError(400, "INVALID_PARAM", f"front_redirect 域不在白名单: {origin}")
    return front_redirect.strip()
```

`src/agent_proxy/oauth/discovery.py`（新文件）：

```python
"""OAuth AS discovery（MCP 授权规范 / RFC 8414 + RFC 9728 链式探测，§14.3）。

探测顺序（upstream origin 起）：
1. GET {origin}/.well-known/oauth-protected-resource（RFC 9728）
   → authorization_servers[0]（缺省/空回退 origin 本身）；
2. GET {as_base}/.well-known/oauth-authorization-server（RFC 8414）
   → authorization_endpoint / token_endpoint / registration_endpoint /
   revocation_endpoint。

任一步非 200 / 网络失败 / 元数据缺关键字段 → DiscoveryError → 授权接口映射
502 OAUTH_CLIENT_SETUP_FAILED（§14.3：提示管理员改用手动配置）。

已知限制（明示接受，Task 7 记入债务节）：AS base 来自上游提供的元数据，代理不
对其做 SSRF 校验（upstream origin 本身已过注册期 SSRF 校验；元数据指向任意主机
属上游自身声明，与「跨源重定向属上游自身行为」同一信任模型）。
"""
from __future__ import annotations

import logging
from urllib.parse import urlparse

import httpx

log = logging.getLogger("agent_proxy")

DISCOVERY_TIMEOUT = 10.0


class DiscoveryError(Exception):
    """discovery 失败（网络 / 非 200 / 元数据缺失）。"""


def upstream_origin(upstream_url: str) -> str:
    parsed = urlparse(upstream_url)
    return f"{parsed.scheme}://{parsed.netloc}"


def parse_protected_resource(payload, origin: str) -> str:
    """RFC 9728 → AS base（authorization_servers[0]；缺省/空/非 dict 回退 origin）。"""
    servers = payload.get("authorization_servers") if isinstance(payload, dict) else None
    if (isinstance(servers, list) and servers
            and isinstance(servers[0], str) and servers[0].strip()):
        return servers[0].strip().rstrip("/")
    return origin.rstrip("/")


def parse_as_metadata(payload) -> dict:
    """RFC 8414 → 授权所需端点集；authorization/token 端点必须存在。"""
    if not isinstance(payload, dict):
        raise DiscoveryError("AS 元数据非 JSON object")
    out = {k: payload.get(k) for k in ("authorization_endpoint", "token_endpoint",
                                       "registration_endpoint", "revocation_endpoint")}
    if not out["authorization_endpoint"] or not out["token_endpoint"]:
        raise DiscoveryError("AS 元数据缺少 authorization_endpoint/token_endpoint")
    return out


async def _get_json(client: httpx.AsyncClient, url: str) -> dict:
    try:
        resp = await client.get(url, timeout=DISCOVERY_TIMEOUT)
    except httpx.HTTPError as exc:
        raise DiscoveryError(f"探测失败 {url}: {type(exc).__name__}") from exc
    if resp.status_code != 200:
        raise DiscoveryError(f"探测 {url} 非 200（status={resp.status_code}）")
    try:
        return resp.json()
    except ValueError as exc:
        raise DiscoveryError(f"探测 {url} 响应非 JSON") from exc


async def discover_authorization_server(client: httpx.AsyncClient,
                                        upstream_origin_value: str) -> dict:
    """两步探测（见模块 docstring）；失败抛 DiscoveryError。
    全局 http_client 为 follow_redirects=False（§8.1 第 7 条），discovery 不跟随
    重定向——well-known 必须直达。"""
    origin = upstream_origin_value.rstrip("/")
    protected = await _get_json(client, f"{origin}/.well-known/oauth-protected-resource")
    as_base = parse_protected_resource(protected, origin)
    return parse_as_metadata(
        await _get_json(client, f"{as_base}/.well-known/oauth-authorization-server"))
```

- [ ] **Step 4: 运行预期**

Run: `.venv/Scripts/python.exe -m pytest tests/unit/test_oauth.py tests/integration/test_oauth_credential_store.py -p no:cacheprovider -q`
Expected: 全部 PASS（单测 17 + 集成 6）。实现前两文件均 FAIL（ModuleNotFoundError: agent_proxy.oauth）。`test_save_stores_ciphertext_and_load_decrypts` 钉住"落库密文 + 缓存密文"双面；PKCE 用 RFC 7636 官方向量防算法漂移。

Run: `.venv/Scripts/python.exe -m pytest -p no:cacheprovider -q`
Expected: 全部 PASS（约 **317** = 基线 293 + 24，以实际为准）。

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(M6): oauth 包基础层——Fernet 强制加密/PKCE(S256)/state/请求组装/discovery 解析/front_redirect 白名单" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

### Task 2: mock OAuth AS+RS（uvicorn 9904）+ conftest 夹具 + CORS 白名单环境 + 9903 `/mcp-secure` 增补 + 独立入口 + 直连冒烟

**Files:**
- New: `tests/integration/mock_oauth_as.py`
- Modify: `tests/integration/mock_mcp_streamable.py`（`secure_state` + `/mcp-secure`）
- Modify: `tests/integration/conftest.py`（`mock_oauth_as_server` 夹具 + 每测重置夹具）
- Modify: `tests/conftest.py`（env 增 `CORS_ALLOWED_ORIGINS`）
- New: `scripts/mock_oauth_as_server.py`
- New: `tests/integration/test_oauth_as_upstream.py`

- [ ] **Step 1: mock AS（完整文件）**

`tests/integration/mock_oauth_as.py`（新文件）：

```python
"""最小 OAuth2 AS+RS（测试专用）：uvicorn.Server 真实监听 127.0.0.1:9904（设计 §14）。

Authorization Server 端点：
- GET /.well-known/oauth-protected-resource   RFC 9728（authorization_servers=[本源]）
- GET /.well-known/oauth-authorization-server RFC 8414 元数据
- POST /oauth/register                        DCR（RFC 7591）——记录请求并签发 client
- GET  /oauth/authorize                       校验 client/redirect_uri/PKCE(S256 必须)
                                              → 签发一次性 code → 302 redirect_uri?code&state
- POST /oauth/token                           authorization_code（code 一次性 + PKCE 校验 +
                                              client 认证 basic/post）与 refresh_token
- POST /oauth/revoke                          RFC 7009（access 吊销连带配对 refresh 作废）

Resource Server 端点（http 形态注入验证面）：
- ANY /api[/{path}]                           echo（method/headers/query 原样返回）

脚本化行为（模块级 as_state，测试直读/直写）：
- expires_in / token_sleep / refresh_sleep / fail_refresh 可控（过期刷新与并发锁用例）；
- registrations / issued / refresh_events / revocations 记录断言面；
- preset 客户端 manual-cl / manual-cs-123456（手动模式用例）：redirect_uris 未注册
  （None），按回调前缀白名单放行——同一 9904 被 ASGI（testserver）与真实 TCP（9910）
  两套夹具共享，前缀白名单 = {"http://127.0.0.1:9910/oauth/callback/",
  "http://testserver/oauth/callback/"}；DCR 客户端仍按注册 redirect_uris 精确匹配；
- POST /_test/reset 重置动态状态（conftest autouse 夹具每个集成测试前调用）；
- 签发的 access token 同步登记 mock_mcp_streamable.secure_state["valid_tokens"]
  （9903 /mcp-secure 的 token 校验面），吊销时移除。

与真实提供方的已知偏离（测试确定性优先）：refresh_token 不轮换（可复用）；
authorize 不渲染同意页（校验通过即视为"同意"）。
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import secrets
from urllib.parse import urlencode

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse

from tests.integration.mock_mcp_streamable import secure_state

BASE = "http://127.0.0.1:9904"
PRESET_CLIENT_ID = "manual-cl"
PRESET_CLIENT_SECRET = "manual-cs-123456"
_PRESET_REDIRECT_PREFIXES = ("http://127.0.0.1:9910/oauth/callback/",
                             "http://testserver/oauth/callback/")


def _fresh_state() -> dict:
    return {
        "registrations": [],
        "clients": {PRESET_CLIENT_ID: {"client_secret": PRESET_CLIENT_SECRET,
                                       "redirect_uris": None, "name": "manual-preset"}},
        "codes": {},            # code -> {client_id, redirect_uri, challenge, scope}
        "used_codes": [],       # code 一次性（用后作废）
        "issued": [],           # {grant, client_id, access_token, refresh_token, ...}
        "refresh_events": [],
        "revocations": [],
        "refresh_tokens": {},   # rt -> client_id
        "revoked_refresh": [],
        "expires_in": 3600,
        "token_sleep": 0.0,
        "refresh_sleep": 0.0,
        "fail_refresh": False,
    }


as_state = _fresh_state()


def build_oauth_as_app() -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.post("/_test/reset")
    async def reset():
        as_state.clear()
        as_state.update(_fresh_state())
        secure_state["valid_tokens"].clear()
        return {"ok": True}

    @app.get("/.well-known/oauth-protected-resource")
    async def protected_resource():
        return {"resource": BASE, "authorization_servers": [BASE],
                "scopes_supported": ["read", "write"],
                "code_challenge_methods_supported": ["S256"]}

    @app.get("/.well-known/oauth-authorization-server")
    async def as_metadata():
        return {"issuer": BASE,
                "authorization_endpoint": f"{BASE}/oauth/authorize",
                "token_endpoint": f"{BASE}/oauth/token",
                "registration_endpoint": f"{BASE}/oauth/register",
                "revocation_endpoint": f"{BASE}/oauth/revoke",
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code", "refresh_token"],
                "code_challenge_methods_supported": ["S256"],
                "token_endpoint_auth_methods_supported": [
                    "client_secret_basic", "client_secret_post", "none"]}

    @app.post("/oauth/register")
    async def register(request: Request):
        try:
            body = await request.json()
        except ValueError:
            return JSONResponse({"error": "invalid_request"}, status_code=400)
        client_id = f"cl-{secrets.token_hex(8)}"
        secret = None
        if body.get("token_endpoint_auth_method") != "none":
            secret = f"cs-{secrets.token_hex(16)}"
        as_state["clients"][client_id] = {
            "client_secret": secret,
            "redirect_uris": list(body.get("redirect_uris") or []),
            "name": body.get("client_name")}
        as_state["registrations"].append(body)
        out = {"client_id": client_id, "client_id_issued_at": 1730000000,
               "redirect_uris": body.get("redirect_uris") or [],
               "grant_types": body.get("grant_types") or ["authorization_code"],
               "token_endpoint_auth_method": (body.get("token_endpoint_auth_method")
                                              or "client_secret_basic"),
               "client_name": body.get("client_name")}
        if secret:
            out["client_secret"] = secret
            out["client_secret_expires_at"] = 0
        return out

    @app.get("/oauth/authorize")
    async def authorize(client_id: str = "", redirect_uri: str = "",
                        response_type: str = "", state: str = "",
                        code_challenge: str = "", code_challenge_method: str = "",
                        scope: str = ""):
        client = as_state["clients"].get(client_id)
        if client is None:
            return JSONResponse({"error": "invalid_client"}, status_code=400)
        if response_type != "code":
            return JSONResponse({"error": "unsupported_response_type"}, status_code=400)
        if client["redirect_uris"] is None:
            # preset 手动客户端：回调前缀白名单（ASGI/真实 TCP 双夹具共享 9904）
            if not redirect_uri.startswith(_PRESET_REDIRECT_PREFIXES):
                return JSONResponse({"error": "invalid_redirect_uri"}, status_code=400)
        elif redirect_uri not in client["redirect_uris"]:
            return JSONResponse({"error": "invalid_redirect_uri"}, status_code=400)
        # PKCE(S256) 必须（§14.6）
        if not code_challenge or code_challenge_method != "S256":
            return JSONResponse({"error": "invalid_request",
                                 "error_description": "code_challenge S256 required"},
                                status_code=400)
        code = f"cd-{secrets.token_hex(16)}"
        as_state["codes"][code] = {"client_id": client_id, "redirect_uri": redirect_uri,
                                   "challenge": code_challenge, "scope": scope}
        query = urlencode({"code": code, "state": state})
        return RedirectResponse(f"{redirect_uri}?{query}", status_code=302)

    async def _issue(client_id: str, scope: str, grant: str) -> JSONResponse:
        if as_state["token_sleep"]:
            await asyncio.sleep(as_state["token_sleep"])
        access = f"at-{secrets.token_hex(16)}"
        refresh = f"rt-{secrets.token_hex(16)}"
        as_state["refresh_tokens"][refresh] = client_id
        as_state["issued"].append({"grant": grant, "client_id": client_id,
                                   "access_token": access, "refresh_token": refresh,
                                   "expires_in": as_state["expires_in"], "scope": scope})
        secure_state["valid_tokens"].add(access)    # 9903 /mcp-secure 校验面
        return JSONResponse({"access_token": access, "token_type": "Bearer",
                             "expires_in": as_state["expires_in"],
                             "refresh_token": refresh, "scope": scope})

    @app.post("/oauth/token")
    async def token(request: Request):
        form = {k: v for k, v in (await request.form()).items()}
        client_id = str(form.get("client_id") or "")
        client_secret = form.get("client_secret")
        authz = request.headers.get("authorization", "")
        if authz.startswith("Basic "):
            # RFC 6749 §2.3.1：Basic 覆盖 form 凭证（与代理 build_token_request 对应）
            try:
                decoded = base64.b64decode(authz[6:].strip()).decode("utf-8")
                client_id, _, basic_secret = decoded.partition(":")
                client_secret = basic_secret
            except Exception:
                return JSONResponse({"error": "invalid_client"}, status_code=401)
        client = as_state["clients"].get(client_id)
        if client is None:
            return JSONResponse({"error": "invalid_client"}, status_code=401)
        if client["client_secret"] is not None and client_secret != client["client_secret"]:
            return JSONResponse({"error": "invalid_client"}, status_code=401)
        grant = form.get("grant_type")
        if grant == "authorization_code":
            code = str(form.get("code") or "")
            record = as_state["codes"].get(code)
            # code 一次性（用后作废）
            if record is None or code in as_state["used_codes"]:
                return JSONResponse({"error": "invalid_grant",
                                     "error_description": "code invalid or already used"},
                                    status_code=400)
            if record["client_id"] != client_id:
                return JSONResponse({"error": "invalid_grant"}, status_code=400)
            if str(form.get("redirect_uri") or "") != record["redirect_uri"]:
                return JSONResponse({"error": "invalid_grant"}, status_code=400)
            # PKCE：S256(code_verifier) == code_challenge（RFC 7636 §4.6）
            verifier = str(form.get("code_verifier") or "")
            challenge = base64.urlsafe_b64encode(
                hashlib.sha256(verifier.encode("ascii")).digest()).decode().rstrip("=")
            if not verifier or challenge != record["challenge"]:
                return JSONResponse({"error": "invalid_grant",
                                     "error_description": "PKCE verification failed"},
                                    status_code=400)
            as_state["used_codes"].append(code)
            return await _issue(client_id, record.get("scope", ""), grant)
        if grant == "refresh_token":
            rt = str(form.get("refresh_token") or "")
            if as_state["fail_refresh"]:            # 脚本化失败：刷新失败→invalid 用例
                return JSONResponse({"error": "invalid_grant",
                                     "error_description": "refresh scripted to fail"},
                                    status_code=400)
            if rt not in as_state["refresh_tokens"] or rt in as_state["revoked_refresh"]:
                return JSONResponse({"error": "invalid_grant"}, status_code=400)
            if as_state["refresh_sleep"]:           # 并发刷新锁用例的竞态窗口
                await asyncio.sleep(as_state["refresh_sleep"])
            as_state["refresh_events"].append({"refresh_token": rt, "client_id": client_id})
            return await _issue(client_id, str(form.get("scope") or ""), grant)
        return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)

    @app.post("/oauth/revoke")
    async def revoke(request: Request):
        form = {k: v for k, v in (await request.form()).items()}
        tok = str(form.get("token") or "")
        as_state["revocations"].append({"token": tok,
                                        "hint": form.get("token_type_hint")})
        secure_state["valid_tokens"].discard(tok)
        # access 吊销连带配对 refresh 作废（按签发记录回查）；直接吊销 rt 形态亦支持
        as_state["refresh_tokens"].pop(tok, None)
        for item in as_state["issued"]:
            if item["access_token"] == tok:
                as_state["revoked_refresh"].append(item["refresh_token"])
        return Response(status_code=200)

    @app.api_route("/api", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
    @app.api_route("/api/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
    async def rs_echo(request: Request, path: str = ""):
        # RS echo：按用户注入断言面（headers 为小写键——uvicorn/h11 归一）
        return {"path": "/" + path, "method": request.method,
                "query": dict(request.query_params.items()),
                "headers": dict(request.headers.items())}

    return app
```

- [ ] **Step 2: mock 9903 增补 `/mcp-secure`（M6 凭证失效断言面）**

`tests/integration/mock_mcp_streamable.py` 三处：

1. 模块 docstring 末尾（`模块级 streamable_state 供测试直读…` 段之后）追加一段：

```
M6 增补：POST /mcp-secure —— 仅接受 mock OAuth AS（9904，mock_oauth_as.py）签发且
未吊销的 access token（secure_state["valid_tokens"] 登记/移除）；缺失/失配回 401
（OAuth 凭证失效面：probe 非 2xx 短路 + 「重新授权」提示用例）。initialize 结果
serverInfo.caller 回告到达上游的 Authorization（「本人凭证到达上游」断言面；
mock 测试值，非真实凭据）。
```

2. 模块级状态区（`streamable_state = {...}` 之后）追加：

```python
# M6 OAuth e2e：mock AS（9904）签发时登记、吊销时移除；/mcp-secure 据此校验
secure_state: dict = {"valid_tokens": set(), "received": []}
```

3. `build_mcp_streamable_app` 内 `/mcp-no-serverinfo` 路由之前插入：

```python
    @app.post("/mcp-secure")
    async def mcp_secure(request: Request):
        # M6（§14.5）：仅接受 mock AS 签发且未吊销的 token；401 = 凭证失效面。
        # serverInfo.caller 回告到达上游的 Authorization——「本人凭证到达上游」断言面。
        authz = request.headers.get("authorization", "")
        rpc = json.loads(await request.body())
        secure_state["received"].append({"rpc": rpc,
                                         "headers": dict(request.headers.items())})
        if authz not in secure_state["valid_tokens"]:
            return JSONResponse({"error": "invalid_token"}, status_code=401)
        params = rpc.get("params") or {}
        return JSONResponse({"jsonrpc": "2.0", "id": rpc.get("id"),
                             "result": {"protocolVersion":
                                        params.get("protocolVersion", "2025-06-18"),
                                        "capabilities": {"tools": {}},
                                        "serverInfo": {"name": "secure-mcp",
                                                       "version": "0",
                                                       "caller": authz}}})
```

- [ ] **Step 3: conftest 夹具 + CORS 白名单环境**

`tests/integration/conftest.py`：import 区追加 `import httpx` 与 `from tests.integration.mock_oauth_as import build_oauth_as_app`；在 `mcp_streamable_upstream_server` 夹具之后新增两个夹具：

```python
@pytest_asyncio.fixture(scope="session", autouse=True, loop_scope="session")
async def mock_oauth_as_server():
    """mock OAuth2 AS+RS：uvicorn 真实监听 127.0.0.1:9904（session 级，独立线程 loop）。

    启动/停机模式与 9901/9902/9903 夹具一致：uvicorn.serve() 挂独立线程独立 loop，
    测试用例经真实 TCP 访问（跨 loop 只过网络，无共享 asyncio 对象）。
    autouse 统一随 session 启动（启动成本 ~1s 一次性）。
    """
    config = uvicorn.Config(build_oauth_as_app(), host="127.0.0.1", port=9904,
                            log_level="warning", access_log=False)
    server = uvicorn.Server(config)
    loop = asyncio.new_event_loop()
    thread = threading.Thread(target=loop.run_until_complete, args=(server.serve(),),
                              daemon=True, name="mock-oauth-as-9904")
    thread.start()
    for _ in range(200):
        if server.started or not thread.is_alive():
            break
        await asyncio.sleep(0.05)
    assert server.started, "mock OAuth AS 启动失败（127.0.0.1:9904 被占用？）"
    yield server
    server.should_exit = True
    thread.join(timeout=10)
    server.force_exit = True  # 兜底：优雅停机超时则强制置位，防止 join 卡死拖垮会话
    thread.join(timeout=5)
    assert not thread.is_alive(), "mock OAuth AS 未在 15s 内停机"
    loop.close()


@pytest.fixture(autouse=True)
async def _reset_oauth_as(mock_oauth_as_server):
    """每个集成测试前重置 mock AS 动态状态（签发登记一并清空）——9904 为进程内
    全局单例，不清则用例间 codes/issued/refresh 计数互相污染（非密封）。"""
    try:
        async with httpx.AsyncClient() as c:
            await c.post("http://127.0.0.1:9904/_test/reset")
    except Exception:
        pass  # 非致命：session 夹具已断言启动成功；此处不阻塞其他用例
    yield
```

`tests/conftest.py`：`os.environ.update({...})` 字典内追加一行（`ENCRYPT_AT_REST` 行之前）：

```python
    "CORS_ALLOWED_ORIGINS": "http://127.0.0.1:9910,http://testserver",
```

说明：该值同时被 `app`（ASGI，EXTERNAL_BASE=http://testserver）与 `real_proxy_app`（真实 TCP，EXTERNAL_BASE=http://127.0.0.1:9910）两套夹具读取——front_redirect 白名单按 EXTERNAL_BASE 对应 origin 配齐；CORSMiddleware 随之启用，但既有用例不发 `Origin` 头，行为不变（实测确认无 CORS 相关既有用例）。

- [ ] **Step 4: 独立入口**

`scripts/mock_oauth_as_server.py`（新文件，与既有 mock 独立入口同构）：

```python
"""独立入口：mock OAuth2 AS+RS（与 tests/integration/mock_oauth_as.py 同一应用）。

用法（M6/M7 联调，浏览器走 authorize → 同意 → 回调全流程）：
    .venv/Scripts/python.exe scripts/mock_oauth_as_server.py          # 监听 127.0.0.1:9904
    .venv/Scripts/python.exe scripts/mock_oauth_as_server.py --port 9914   # 自定义端口
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # 仓库根（使 tests 包可导入）

import uvicorn  # noqa: E402

from tests.integration.mock_oauth_as import build_oauth_as_app  # noqa: E402


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="mock OAuth2 AS+RS（OAuth 绑定联调用）")
    parser.add_argument("--port", type=int, default=9904, help="监听端口（默认 9904）")
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    uvicorn.run(build_oauth_as_app(), host="127.0.0.1", port=args.port,
                log_level="info", access_log=False)
```

注意：独立入口换端口（如 9914）时，`_PRESET_REDIRECT_PREFIXES` 与 9904 元数据 URL 不随动——独立入口仅用于 9904 标准端口的浏览器联调；端口改配属联调时手工改 mock 常量的场景（文件头注明）。

- [ ] **Step 5: 直连冒烟测试**

`tests/integration/test_oauth_as_upstream.py`（新文件）：

```python
"""mock OAuth AS（9904）直连冒烟（真实 TCP）：先钉住 mock 自身协议行为，代理链路
测试（binding/injection/dcr）才有可信参照。覆盖：well-known×2、DCR、authorize
（redirect_uri 精确/PKCE 必须）、token（code 一次性 / PKCE S256 校验 / client 认证
basic+post）、refresh（可复用 + 脚本化失败）、revoke（连带 refresh）、RS echo、
preset 手动客户端。"""
import base64

import httpx

from tests.integration.mock_mcp_streamable import secure_state
from tests.integration.mock_oauth_as import as_state

BASE = "http://127.0.0.1:9904"
VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"   # RFC 7636 附录 B
REDIRECT = "http://127.0.0.1:9910/oauth/callback/m1m2m3m4m5m6"


async def _register(c, **overrides) -> dict:
    payload = {"client_name": "smoke", "redirect_uris": [REDIRECT],
               "grant_types": ["authorization_code", "refresh_token"],
               "token_endpoint_auth_method": "client_secret_post", **overrides}
    resp = await c.post(f"{BASE}/oauth/register", json=payload)
    assert resp.status_code == 200, resp.text
    return resp.json()


def _authorize_params(client_id: str) -> dict:
    return {"client_id": client_id, "redirect_uri": REDIRECT,
            "response_type": "code", "state": "st-1",
            "code_challenge": CHALLENGE, "code_challenge_method": "S256"}


async def _code(c, client_id: str) -> str:
    r = await c.get(f"{BASE}/oauth/authorize", params=_authorize_params(client_id),
                    follow_redirects=False)
    assert r.status_code == 302, r.text
    location = r.headers["location"]
    assert location.startswith(f"{REDIRECT}?code=") and "state=st-1" in location
    return location.split("code=")[1].split("&")[0]


async def test_well_known_pair_served():
    async with httpx.AsyncClient() as c:
        pr = (await c.get(f"{BASE}/.well-known/oauth-protected-resource")).json()
        assert pr["authorization_servers"] == [BASE]
        meta = (await c.get(f"{BASE}/.well-known/oauth-authorization-server")).json()
        assert meta["token_endpoint"] == f"{BASE}/oauth/token"
        assert meta["registration_endpoint"] == f"{BASE}/oauth/register"
        assert meta["revocation_endpoint"] == f"{BASE}/oauth/revoke"
        assert "S256" in meta["code_challenge_methods_supported"]


async def test_dcr_register_issues_client_and_records_request():
    async with httpx.AsyncClient() as c:
        body = await _register(c, client_name="agent-proxy-test")
    assert body["client_id"].startswith("cl-") and body["client_secret"].startswith("cs-")
    assert as_state["registrations"][-1]["client_name"] == "agent-proxy-test"
    assert as_state["registrations"][-1]["redirect_uris"] == [REDIRECT]


async def test_authorize_rejects_wrong_redirect_uri_and_missing_pkce():
    async with httpx.AsyncClient() as c:
        cl = await _register(c)
        bad_redirect = await c.get(f"{BASE}/oauth/authorize", params={
            **_authorize_params(cl["client_id"]),
            "redirect_uri": "http://evil.example.com/cb"}, follow_redirects=False)
        assert bad_redirect.status_code == 400            # redirect_uri 精确匹配
        no_pkce = await c.get(f"{BASE}/oauth/authorize", params={
            "client_id": cl["client_id"], "redirect_uri": REDIRECT,
            "response_type": "code", "state": "s"}, follow_redirects=False)
        assert no_pkce.status_code == 400                 # PKCE 必须
        unknown_client = await c.get(f"{BASE}/oauth/authorize", params={
            **_authorize_params("cl-unknown")}, follow_redirects=False)
        assert unknown_client.status_code == 400


async def test_token_exchange_full_and_code_one_time():
    async with httpx.AsyncClient() as c:
        cl = await _register(c)
        code = await _code(c, cl["client_id"])
        ok = await c.post(f"{BASE}/oauth/token", data={
            "grant_type": "authorization_code", "code": code,
            "redirect_uri": REDIRECT, "code_verifier": VERIFIER,
            "client_id": cl["client_id"], "client_secret": cl["client_secret"]})
        assert ok.status_code == 200
        tokens = ok.json()
        assert tokens["token_type"] == "Bearer" and tokens["expires_in"] == 3600
        assert tokens["access_token"] in secure_state["valid_tokens"]
        # code 一次性：同一 code 第二次换 → invalid_grant
        replay = await c.post(f"{BASE}/oauth/token", data={
            "grant_type": "authorization_code", "code": code,
            "redirect_uri": REDIRECT, "code_verifier": VERIFIER,
            "client_id": cl["client_id"], "client_secret": cl["client_secret"]})
        assert replay.status_code == 400
        assert replay.json()["error"] == "invalid_grant"


async def test_token_pkce_wrong_verifier_rejected():
    async with httpx.AsyncClient() as c:
        cl = await _register(c)
        code = await _code(c, cl["client_id"])
        r = await c.post(f"{BASE}/oauth/token", data={
            "grant_type": "authorization_code", "code": code,
            "redirect_uri": REDIRECT,
            "code_verifier": "wrong-verifier-wrong-verifier-wrong-verifier-wrong",
            "client_id": cl["client_id"], "client_secret": cl["client_secret"]})
    assert r.status_code == 400                          # S256(verifier) != challenge
    assert r.json()["error"] == "invalid_grant"


async def test_token_client_secret_post_mismatch_401():
    async with httpx.AsyncClient() as c:
        cl = await _register(c)
        r = await c.post(f"{BASE}/oauth/token", data={
            "grant_type": "authorization_code", "code": "whatever",
            "client_id": cl["client_id"], "client_secret": "bad-secret"})
    assert r.status_code == 401 and r.json()["error"] == "invalid_client"


async def test_token_client_secret_basic_auth_accepted():
    async with httpx.AsyncClient() as c:
        cl = await _register(c, token_endpoint_auth_method="client_secret_basic")
        code = await _code(c, cl["client_id"])
        basic = base64.b64encode(
            f"{cl['client_id']}:{cl['client_secret']}".encode()).decode()
        r = await c.post(f"{BASE}/oauth/token", data={
            "grant_type": "authorization_code", "code": code,
            "redirect_uri": REDIRECT, "code_verifier": VERIFIER},
            headers={"Authorization": f"Basic {basic}"})
    assert r.status_code == 200


async def test_refresh_grant_and_scripted_failure():
    async with httpx.AsyncClient() as c:
        cl = await _register(c)
        code = await _code(c, cl["client_id"])
        tokens = (await c.post(f"{BASE}/oauth/token", data={
            "grant_type": "authorization_code", "code": code,
            "redirect_uri": REDIRECT, "code_verifier": VERIFIER,
            "client_id": cl["client_id"], "client_secret": cl["client_secret"]})).json()
        r1 = await c.post(f"{BASE}/oauth/token", data={
            "grant_type": "refresh_token", "refresh_token": tokens["refresh_token"],
            "client_id": cl["client_id"], "client_secret": cl["client_secret"]})
        assert r1.status_code == 200
        assert r1.json()["access_token"] != tokens["access_token"]
        assert len(as_state["refresh_events"]) == 1
        # 脚本化失败：fail_refresh=True → invalid_grant（刷新失败→invalid 用例依赖）
        as_state["fail_refresh"] = True
        r2 = await c.post(f"{BASE}/oauth/token", data={
            "grant_type": "refresh_token", "refresh_token": tokens["refresh_token"],
            "client_id": cl["client_id"], "client_secret": cl["client_secret"]})
        assert r2.status_code == 400
        as_state["fail_refresh"] = False
        # 伪造/已吊销 refresh token → invalid_grant
        r3 = await c.post(f"{BASE}/oauth/token", data={
            "grant_type": "refresh_token", "refresh_token": "rt-forged",
            "client_id": cl["client_id"], "client_secret": cl["client_secret"]})
        assert r3.status_code == 400


async def test_revoke_discards_access_and_paired_refresh():
    async with httpx.AsyncClient() as c:
        cl = await _register(c)
        code = await _code(c, cl["client_id"])
        tokens = (await c.post(f"{BASE}/oauth/token", data={
            "grant_type": "authorization_code", "code": code,
            "redirect_uri": REDIRECT, "code_verifier": VERIFIER,
            "client_id": cl["client_id"], "client_secret": cl["client_secret"]})).json()
        rv = await c.post(f"{BASE}/oauth/revoke", data={
            "token": tokens["access_token"], "token_type_hint": "access_token"})
        assert rv.status_code == 200
        assert tokens["access_token"] not in secure_state["valid_tokens"]
        assert tokens["refresh_token"] in as_state["revoked_refresh"]
        r = await c.post(f"{BASE}/oauth/token", data={
            "grant_type": "refresh_token", "refresh_token": tokens["refresh_token"],
            "client_id": cl["client_id"], "client_secret": cl["client_secret"]})
        assert r.status_code == 400                      # 配对 refresh 已连带作废


async def test_preset_manual_client_flow_post():
    async with httpx.AsyncClient() as c:
        code = await _code(c, "manual-cl")
        r = await c.post(f"{BASE}/oauth/token", data={
            "grant_type": "authorization_code", "code": code,
            "redirect_uri": REDIRECT, "code_verifier": VERIFIER,
            "client_id": "manual-cl", "client_secret": "manual-cs-123456"})
    assert r.status_code == 200                          # 手动模式凭证被 mock AS 认可


async def test_rs_echo_returns_headers():
    async with httpx.AsyncClient() as c:
        r = await c.get(f"{BASE}/api/v1/orders?id=1",
                        headers={"Authorization": "Bearer at-echo-probe"})
    assert r.status_code == 200
    body = r.json()
    assert body["path"] == "/v1/orders" and body["query"]["id"] == "1"
    assert body["headers"]["authorization"] == "Bearer at-echo-probe"
```

- [ ] **Step 6: 运行预期**

Run: `.venv/Scripts/python.exe -m pytest tests/integration/test_oauth_as_upstream.py -p no:cacheprovider -q`
Expected: 10 passed（夹具随 session autouse 启动 9904；每测前自动 reset）。

Run: `.venv/Scripts/python.exe -m pytest -p no:cacheprovider -q`
Expected: 全部 PASS（约 **327** = 317 + 10，以实际为准）。既有全部用例不受 9904 夹具与 CORS 环境影响（实测确认无既有用例发 Origin 头）。

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "test(M6): mock OAuth AS+RS（uvicorn 9904，DCR/PKCE/一次性 code/revoke/RS echo）+ 9903 /mcp-secure + 夹具 + 直连冒烟" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

### Task 3: auth_mode 贯通 + 公共映射管理矩阵（§14.2）+ 手动 OAuth client 配置接口

**Files:**
- Modify: `src/agent_proxy/schemas.py`（MappingCreate/Update 增 auth_mode；RegisteredOut 增 auth_mode；OAuthClientSet / OAuthClientOut）
- Modify: `src/agent_proxy/services.py`（create_mapping 增 auth_mode + oauth⇒public 校验；update/delete/get_owned 增 admin public 旁路）
- Modify: `src/agent_proxy/api/mgmt.py`（admin 旁路接线 + auth_mode 透传）
- Modify: `src/agent_proxy/oauth/client.py`（客户端行存取：`load_client_row` / `save_oauth_client_row` / `_row_to_client`）
- New: `src/agent_proxy/api/builtin.py`（本任务先落 `load_public_mapping` / `require_oauth_mode` + client 配置两路由）
- Modify: `src/agent_proxy/main.py`（注册 builtin 路由）
- New: `tests/integration/test_oauth_client_config.py`

- [ ] **Step 1: 写失败测试**

`tests/integration/test_oauth_client_config.py`（新文件）：

```python
"""M6 公共映射管理矩阵 + 手动 OAuth client 配置接口（§14.2 / §14.3 / §6.5）。

- auth_mode=oauth 仅 public（创建/更新两侧 400；public 仍仅 admin，403 先判）；
- §14.2 矩阵：public 的详情 / resolve / test 任意 admin 可见，非注册者普通用户 404；
  public 改删任意 admin 可操作；
- client 配置仅 admin；client_secret 强制加密落库（§14.6）；
- authorize_url / token_url 过 SSRF 校验（scheme/http host 必填）。
"""
from sqlalchemy import select

from agent_proxy.models import OAuthClient
from tests.utils import make_token

ADMIN = {"Authorization": f"Bearer {make_token('uadmin', 'admin')}"}
ADMIN2 = {"Authorization": f"Bearer {make_token('uadmin2', 'admin')}"}
USER = {"Authorization": f"Bearer {make_token('u888')}"}

CLIENT_BODY = {"client_id": "manual-cl", "client_secret": "manual-cs-123456",
               "token_auth": "client_secret_post",
               "authorize_url": "http://127.0.0.1:9904/oauth/authorize",
               "token_url": "http://127.0.0.1:9904/oauth/token", "scopes": "read"}


async def _create(client, headers=ADMIN, **overrides):
    payload = {"type": "http", "visibility": "public", "auth_mode": "oauth",
               "upstream_url": "http://10.0.0.5/api/v1", "headers": {}, **overrides}
    resp = await client.post("/api/v1/mappings", json=payload, headers=headers)
    assert resp.status_code == 201, resp.text
    return resp.json()


async def _put_client(client, mid, headers=ADMIN, body=None):
    return await client.put(f"/api/v1/builtin-mappings/{mid}/client",
                            json=body or CLIENT_BODY, headers=headers)


async def test_create_public_oauth_admin_only_and_echoed(client):
    body = {"type": "http", "visibility": "public", "auth_mode": "oauth",
            "upstream_url": "http://10.0.0.5/api/v1", "headers": {}}
    resp = await client.post("/api/v1/mappings", json=body, headers=USER)
    assert resp.status_code == 403 and resp.json()["code"] == "FORBIDDEN"  # 403 先判
    resp = await client.post("/api/v1/mappings", json=body, headers=ADMIN)
    assert resp.status_code == 201
    assert resp.json()["auth_mode"] == "oauth"           # RegisteredOut 增 auth_mode


async def test_create_private_oauth_rejected_400(client):
    resp = await client.post("/api/v1/mappings", json={
        "type": "http", "visibility": "private", "auth_mode": "oauth",
        "upstream_url": "http://10.0.0.5/api/v1", "headers": {}}, headers=ADMIN)
    assert resp.status_code == 400 and resp.json()["code"] == "INVALID_PARAM"
    assert "oauth" in resp.json()["message"]


async def test_update_flip_oauth_public_to_private_400_and_static_ok(client):
    created = await _create(client)
    mid = created["mapping_id"]
    resp = await client.put(f"/api/v1/mappings/{mid}", json={"visibility": "private"},
                            headers=ADMIN)
    assert resp.status_code == 400                       # oauth 映射不可转 private
    resp = await client.put(f"/api/v1/mappings/{mid}", json={"auth_mode": "static"},
                            headers=ADMIN)
    assert resp.status_code == 200 and resp.json()["auth_mode"] == "static"
    resp = await client.put(f"/api/v1/mappings/{mid}", json={"visibility": "private"},
                            headers=ADMIN)
    assert resp.status_code == 200                       # static 后可转 private


async def test_put_client_requires_admin(client):
    mid = (await _create(client))["mapping_id"]
    resp = await _put_client(client, mid, headers=USER)
    assert resp.status_code == 403 and resp.json()["code"] == "FORBIDDEN"


async def test_put_and_get_client_masked(client, app):
    mid = (await _create(client))["mapping_id"]
    resp = await _put_client(client, mid)
    assert resp.status_code == 200, resp.text
    out = resp.json()
    assert out["client_id"] == "manual-cl" and out["source"] == "manual"
    assert out["client_secret_configured"] is True
    assert "manual-cs-123456" not in resp.text           # secret 永不回显
    resp = await client.get(f"/api/v1/builtin-mappings/{mid}/client", headers=ADMIN)
    assert resp.status_code == 200 and resp.json() == out
    # 落库密文面（§14.6 强制加密）
    async with app.state.sessionmaker() as session:
        row = (await session.execute(
            select(OAuthClient).where(OAuthClient.mapping_id == mid))).scalar_one()
    assert row.client_secret.startswith("gAAAA")
    assert "manual-cs-123456" not in row.client_secret


async def test_put_client_replaces_existing_row(client, app):
    mid = (await _create(client))["mapping_id"]
    await _put_client(client, mid)
    resp = await _put_client(client, mid, body={**CLIENT_BODY, "client_id": "manual-cl2",
                                                "client_secret": None})
    assert resp.status_code == 200
    assert resp.json()["client_id"] == "manual-cl2"
    assert resp.json()["client_secret_configured"] is False
    async with app.state.sessionmaker() as session:
        rows = (await session.execute(
            select(OAuthClient).where(OAuthClient.mapping_id == mid))).scalars().all()
    assert len(rows) == 1                                # uk_mapping upsert，不堆行


async def test_put_client_on_static_mapping_400(client):
    mid = (await _create(client, auth_mode="static"))["mapping_id"]
    resp = await _put_client(client, mid)
    assert resp.status_code == 400 and resp.json()["code"] == "OAUTH_NOT_APPLICABLE"


async def test_builtin_endpoints_hide_private_and_missing(client):
    private = (await _create(client, visibility="private", auth_mode="static",
                             headers=ADMIN))["mapping_id"]
    for path, method in ((f"/api/v1/builtin-mappings/{private}/client", "PUT"),
                         (f"/api/v1/builtin-mappings/{private}/client", "GET")):
        resp = await client.request(method, path, json=CLIENT_BODY, headers=ADMIN)
        assert resp.status_code == 404                   # 非 public 一律 404（隐藏存在性）
    resp = await client.get("/api/v1/builtin-mappings/aaaaaaaaaaaa/client", headers=ADMIN)
    assert resp.status_code == 404


async def test_get_client_before_config_404(client):
    mid = (await _create(client))["mapping_id"]
    resp = await client.get(f"/api/v1/builtin-mappings/{mid}/client", headers=ADMIN)
    assert resp.status_code == 404 and resp.json()["code"] == "OAUTH_CLIENT_NOT_CONFIGURED"


async def test_put_client_bad_scheme_400(client):
    mid = (await _create(client))["mapping_id"]
    resp = await _put_client(client, mid, body={**CLIENT_BODY,
                                                "authorize_url": "ftp://127.0.0.1/x"})
    assert resp.status_code == 400 and resp.json()["code"] == "INVALID_PARAM"


async def test_public_detail_resolve_test_admin_bypass(client):
    """§14.2：public 详情/resolve 回显仅 admin（任意 admin，不限注册者）；
    非注册者普通用户 404；test 同一旁路。"""
    mid = (await _create(client))["mapping_id"]
    resp = await client.get(f"/api/v1/mappings/{mid}", headers=ADMIN2)
    assert resp.status_code == 200                       # 任意 admin 可见
    resp = await client.get(f"/api/v1/mappings/{mid}", headers=USER)
    assert resp.status_code == 404                       # 普通用户隐藏
    from urllib.parse import quote
    resp = await client.get(f"/api/v1/mappings/resolve?proxy_url={quote(mid)}",
                            headers=ADMIN2)
    assert resp.status_code == 200
    resp = await client.post(f"/api/v1/mappings/{mid}/test", headers=ADMIN2)
    assert resp.status_code == 200                       # 不可达上游 → ok=false 但 HTTP 200
    assert resp.json()["ok"] is False


async def test_public_update_delete_by_any_admin(client):
    mid = (await _create(client))["mapping_id"]
    resp = await client.put(f"/api/v1/mappings/{mid}", json={"name": "renamed"},
                            headers=ADMIN2)
    assert resp.status_code == 200 and resp.json()["name"] == "renamed"
    resp = await client.put(f"/api/v1/mappings/{mid}", json={"name": "x"}, headers=USER)
    assert resp.status_code == 404                       # 非注册者普通用户 404 不变
    resp = await client.delete(f"/api/v1/mappings/{mid}", headers=ADMIN2)
    assert resp.status_code == 204
```

- [ ] **Step 2: 实现 schemas 增量**

`src/agent_proxy/schemas.py` 三处：

1. `MappingCreate` 增一行字段（`visibility` 行之后）：

```python
    auth_mode: Literal["static", "oauth"] = "static"
```

2. `MappingUpdate` 增一行字段（`visibility` 行之后）：

```python
    auth_mode: Literal["static", "oauth"] | None = None
```

3. `RegisteredOut` 增一行字段（`visibility` 行之后；POST/PUT 响应回告 auth_mode，页面据此展示绑定要求）：

```python
    auth_mode: str = "static"
```

4. 文件末尾追加：

```python
class OAuthClientSet(BaseModel):
    """PUT /api/v1/builtin-mappings/{id}/client 请求（admin，手动模式，§14.3）。
    client_secret 可空（公共客户端 token_auth=none）。"""
    client_id: str = Field(min_length=1, max_length=256)
    client_secret: str | None = Field(default=None, max_length=1024)
    token_auth: Literal["client_secret_basic", "client_secret_post", "none"] = \
        "client_secret_post"
    authorize_url: str = Field(min_length=1, max_length=2048)
    token_url: str = Field(min_length=1, max_length=2048)
    scopes: str | None = Field(default=None, max_length=512)


class OAuthClientOut(BaseModel):
    """GET/PUT client 响应：secret 只回是否已配置，永不回显值（§14.6）。"""
    mapping_id: str
    client_id: str
    client_secret_configured: bool
    token_auth: str
    authorize_url: str | None = None
    token_url: str | None = None
    scopes: str | None = None
    source: str


class AuthorizeIn(BaseModel):
    """POST /{id}/authorize 请求：回跳页面地址（域白名单校验，§14.6）。"""
    front_redirect: str = Field(min_length=1, max_length=2048)


class AuthorizeOut(BaseModel):
    authorization_url: str


class BindingOut(BaseModel):
    """GET /{id}/binding 响应：binding ∈ unbound/authorizing/bound/invalid（§14.4）。"""
    mapping_id: str
    auth_mode: str
    binding: str
    expires_at: str | None = None
    scope: str | None = None


class BuiltinItemOut(BaseModel):
    """GET /api/v1/builtin-mappings 列表项：占位符 headers，不含真实值（§6.5）；
    binding 仅 auth_mode=oauth 有值（static 为 None）。"""
    mapping_id: str
    name: str | None = None
    type: str
    proxy_url: str
    headers: dict[str, str]
    auth_mode: str
    binding: str | None = None
    status: str
```

- [ ] **Step 3: 实现 services 增量**

`src/agent_proxy/services.py` 四个函数整体替换（`row_to_dict` / `build_proxy_url` / `load_mapping` / `list_mappings` 不动）：

```python
async def get_owned(session: AsyncSession, r, mapping_id: str, uid: str, ttl: int,
                    admin_override: bool = False) -> dict | None:
    """加载并校验归属；非注册者返回 None（404 隐藏存在性）。
    M6（§14.2）：admin_override 时 public 映射对任意 admin 可见（详情/resolve/test）。"""
    data = await load_mapping(session, r, mapping_id, ttl)
    if data is None:
        return None
    if data["owner_uid"] == uid:
        return data
    if admin_override and data["visibility"] == "public":
        return data
    return None


async def create_mapping(session: AsyncSession, r, settings: Settings, owner_uid: str, *,
                         type_: str, name: str | None, visibility: str,
                         upstream_url: str, headers: dict[str, str],
                         test_request: dict | None,
                         auth_mode: str = "static") -> ProxyMapping:
    placeholder.validate_headers(headers)
    # M6（§14.2）：auth_mode=oauth 仅允许 public（public 本身的 admin 限制由 api 层 403 先判）
    if auth_mode == "oauth" and visibility != "public":
        raise ValueError("auth_mode=oauth 仅允许 public 映射")
    url = await async_validate_upstream_url(upstream_url, settings.ssrf_allow_private)
    for attempt in range(5):
        mapping_id = mid_module.new_mapping_id()
        row = ProxyMapping(mapping_id=mapping_id, owner_uid=owner_uid, name=name,
                           type=type_, visibility=visibility, auth_mode=auth_mode,
                           upstream_url=url, upstream_headers=headers,
                           test_request=test_request, status="active")
        session.add(row)
        try:
            await session.commit()
            break
        except IntegrityError:
            await session.rollback()
            if attempt == 4:
                raise AppError(500, "INTERNAL_ERROR", "mapping_id 生成冲突，请重试")
    await session.refresh(row)  # 回填 server_default（created_at/updated_at），避免脱管后过期属性报错
    await cache.invalidate(r, row.mapping_id)
    return row


async def update_mapping(session: AsyncSession, r, settings: Settings, mapping_id: str,
                         owner_uid: str, *, admin_override: bool = False,
                         **patch: Any) -> dict | None:
    """更新；返回 row_to_dict 或 None（不存在/无权限）。
    M6（§14.2）：admin_override 时任意 admin 可改 public 映射；
    auth_mode 变更后仍须满足 oauth⇒public（违规 ValueError → api 层 400）。"""
    row = (await session.execute(
        select(ProxyMapping).where(ProxyMapping.mapping_id == mapping_id)
    )).scalar_one_or_none()
    if row is None:
        return None
    if row.owner_uid != owner_uid and not (admin_override and row.visibility == "public"):
        return None
    new_visibility = patch.get("visibility") or row.visibility
    new_auth_mode = patch.get("auth_mode") or row.auth_mode
    if new_auth_mode == "oauth" and new_visibility != "public":
        raise ValueError("auth_mode=oauth 仅允许 public 映射")
    if patch.get("headers") is not None:
        placeholder.validate_headers(patch["headers"])
        row.upstream_headers = patch["headers"]
    if patch.get("upstream_url"):
        row.upstream_url = await async_validate_upstream_url(
            patch["upstream_url"], settings.ssrf_allow_private)
    for field in ("name", "visibility", "test_request", "status", "auth_mode"):
        if patch.get(field) is not None:
            setattr(row, field, patch[field])
    await session.commit()
    await session.refresh(row)  # 回填 server 端 updated_at，避免 row_to_dict 触发异步下不支持的懒加载
    await cache.invalidate(r, mapping_id)
    return row_to_dict(row)


async def delete_mapping(session: AsyncSession, r, mapping_id: str, owner_uid: str,
                         admin_override: bool = False) -> bool:
    row = (await session.execute(
        select(ProxyMapping).where(ProxyMapping.mapping_id == mapping_id)
    )).scalar_one_or_none()
    if row is None:
        return False
    if row.owner_uid != owner_uid and not (admin_override and row.visibility == "public"):
        return False
    await session.delete(row)
    await session.commit()
    await cache.invalidate(r, mapping_id)
    return True
```

- [ ] **Step 4: 实现 mgmt 接线**

`src/agent_proxy/api/mgmt.py` 五处：

1. `create_mapping_route` 内 `create_mapping(...)` 调用增一行实参（`test_request=body.test_request` 之后）：

```python
            test_request=body.test_request, auth_mode=body.auth_mode)
```

2. `_registered_out` 增 auth_mode（`visibility=data["visibility"],` 行之后）：

```python
        visibility=data["visibility"], auth_mode=data["auth_mode"],
```

3. `resolve_mapping` / `get_detail` / `test_mapping_route` 三个路由的 `get_owned(...)` 调用统一改为带旁路（三处相同改法——`settings.cache_ttl)` 之后加一个实参）：

```python
    data = await get_owned(session, request.app.state.redis, mapping_id,
                           identity.user_id, settings.cache_ttl,
                           admin_override=is_admin(identity, settings.admin_role))
```

（`is_admin` 已在 import 区。）

4. `update_mapping_route`：调用处增 admin 旁路——`update_mapping(session, request.app.state.redis, settings, mapping_id, identity.user_id, **patch)` 改为：

```python
    data = await update_mapping(session, request.app.state.redis, settings,
                                mapping_id, identity.user_id,
                                admin_override=is_admin(identity, settings.admin_role),
                                **patch)
```

5. `delete_mapping_route`：`delete_mapping(session, request.app.state.redis, mapping_id, identity.user_id)` 改为：

```python
    ok = await delete_mapping(session, request.app.state.redis, mapping_id,
                              identity.user_id,
                              admin_override=is_admin(identity, settings.admin_role))
```

（delete 路由无 settings 依赖，`is_admin` 需要 role → 增依赖 `settings: Settings = Depends(get_settings)` 并在签名中补上。）

- [ ] **Step 5: 实现 client.py 行存取 + builtin.py（client 配置两路由）+ main 注册**

`src/agent_proxy/oauth/client.py`：import 区改为：

```python
from __future__ import annotations

import base64
import hashlib
import json
import secrets
from urllib.parse import urlencode, urlparse

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..errors import AppError
from ..models import OAuthClient
from .credential import decrypt_text, encrypt_text
```

文件末尾追加：

```python
# ---------- OAuth 客户端行存取（proxy_oauth_client，uk_mapping 每映射一份） ----------


def _row_to_client(row: OAuthClient, master_key: str) -> dict:
    """行 → client dict：secret 解密、token_auth 归一。revocation_endpoint 仅 DCR
    经 discovery 实时获得（manual 模式无 revoke 端点配置列，§14.4）。"""
    return {"client_id": row.client_id,
            "client_secret": (decrypt_text(row.client_secret, master_key)
                              if row.client_secret else None),
            "token_auth": normalize_token_auth(row.token_auth),
            "authorize_url": row.authorize_url, "token_url": row.token_url,
            "scopes": row.scopes, "source": row.source,
            "revocation_endpoint": None}


async def load_client_row(session: AsyncSession, mapping_id: str) -> OAuthClient | None:
    return (await session.execute(
        select(OAuthClient).where(OAuthClient.mapping_id == mapping_id)
    )).scalar_one_or_none()


async def save_oauth_client_row(session: AsyncSession, mapping_id: str, *,
                                client_id: str, client_secret_plain: str | None,
                                token_auth: str, authorize_url: str | None,
                                token_url: str | None, scopes: str | None,
                                source: str, master_key: str) -> None:
    """upsert；client_secret 强制加密落库（§14.6，不受 ENCRYPT_AT_REST 影响）。"""
    row = await load_client_row(session, mapping_id)
    secret_ct = (encrypt_text(client_secret_plain, master_key)
                 if client_secret_plain else None)
    if row is None:
        row = OAuthClient(mapping_id=mapping_id, client_id=client_id,
                          client_secret=secret_ct, token_auth=token_auth,
                          authorize_url=authorize_url, token_url=token_url,
                          scopes=scopes, source=source)
        session.add(row)
    else:
        row.client_id = client_id
        row.client_secret = secret_ct
        row.token_auth = token_auth
        row.authorize_url = authorize_url
        row.token_url = token_url
        row.scopes = scopes
        row.source = source
    await session.commit()
```

`src/agent_proxy/api/builtin.py`（新文件，本任务完整版——Task 4/5/6 在此文件增量追加路由）：

```python
"""内置公共映射（visibility=public）与 OAuth 接口（设计 §6.5 / §14）。

路由清单（M6 交付序，Task 号对应本计划）：
- PUT/GET /api/v1/builtin-mappings/{id}/client     admin OAuth 客户端手动配置（Task 3）
- GET  /api/v1/builtin-mappings                    列表 + 我的绑定状态（Task 4）
- POST /api/v1/builtin-mappings/{id}/authorize     发起授权（Task 4）
- GET  /api/v1/builtin-mappings/{id}/binding       绑定状态查询（Task 4）
- GET  /oauth/callback/{mapping_id}                OAuth 回调（无 JWT，state 关联，Task 4）
- DELETE /api/v1/builtin-mappings/{id}/binding     解绑 + revoke（Task 5）
- POST /api/v1/builtin-mappings/{id}/test          admin 静态 / 绑定用户本人凭证（Task 6）

静态路由注册顺序："" 列表路由先于动态 /{mapping_id}/...（与 mgmt /resolve 先于
/{mapping_id} 同一先例，FastAPI 按注册顺序匹配）。
隐藏存在性：非 public（private/不存在）一律 404 MAPPING_NOT_FOUND。
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import Identity
from ..config import Settings, get_settings
from ..errors import AppError
from ..models import OAuthClient
from ..oauth.client import load_client_row, save_oauth_client_row
from ..schemas import OAuthClientOut, OAuthClientSet
from ..services import load_mapping
from ..ssrf import async_validate_upstream_url
from .deps import get_current_identity, get_db, is_admin

log = logging.getLogger("agent_proxy")

router = APIRouter(prefix="/api/v1/builtin-mappings", tags=["builtin"])


async def load_public_mapping(session: AsyncSession, r, mapping_id: str, ttl: int) -> dict:
    """内置接口专用加载：必须 visibility=public；private/不存在一律 404（隐藏存在性）。"""
    data = await load_mapping(session, r, mapping_id, ttl)
    if data is None or data["visibility"] != "public":
        raise AppError(404, "MAPPING_NOT_FOUND", "内置映射不存在")
    return data


def require_oauth_mode(data: dict) -> None:
    """static 公共映射（S3 共享凭据）无需绑定：OAuth 语义一律 400 OAUTH_NOT_APPLICABLE。"""
    if data["auth_mode"] != "oauth":
        raise AppError(400, "OAUTH_NOT_APPLICABLE",
                       "该内置映射为 static 模式（共享静态凭据），无需 OAuth 授权/绑定")


def _client_out(mapping_id: str, row: OAuthClient) -> OAuthClientOut:
    return OAuthClientOut(mapping_id=mapping_id, client_id=row.client_id,
                          client_secret_configured=bool(row.client_secret),
                          token_auth=row.token_auth, authorize_url=row.authorize_url,
                          token_url=row.token_url, scopes=row.scopes, source=row.source)


@router.put("/{mapping_id}/client", response_model=OAuthClientOut)
async def set_oauth_client(request: Request, mapping_id: str, body: OAuthClientSet,
                           identity: Identity = Depends(get_current_identity),
                           session=Depends(get_db),
                           settings: Settings = Depends(get_settings)):
    """手动模式 OAuth 客户端配置（§14.3 降级路径，仅 admin）。client_secret 加密落库；
    重复 PUT 为 upsert（亦可将 dcr 配置覆盖为 manual，管理员兜底手段）。"""
    if not is_admin(identity, settings.admin_role):
        raise AppError(403, "FORBIDDEN", "仅管理员可配置 OAuth 客户端")
    data = await load_public_mapping(session, request.app.state.redis, mapping_id,
                                     settings.cache_ttl)
    require_oauth_mode(data)
    try:
        await async_validate_upstream_url(body.authorize_url, settings.ssrf_allow_private)
        await async_validate_upstream_url(body.token_url, settings.ssrf_allow_private)
    except ValueError as exc:  # 含 UpstreamNotAllowed（其子类）
        raise AppError(400, "INVALID_PARAM", str(exc))
    await save_oauth_client_row(session, mapping_id, client_id=body.client_id,
                                client_secret_plain=body.client_secret,
                                token_auth=body.token_auth,
                                authorize_url=body.authorize_url,
                                token_url=body.token_url, scopes=body.scopes,
                                source="manual", master_key=settings.master_key)
    request.state.audit_action = "oauth_client_set"
    request.state.mapping_id = mapping_id
    row = await load_client_row(session, mapping_id)
    return _client_out(mapping_id, row)


@router.get("/{mapping_id}/client", response_model=OAuthClientOut)
async def get_oauth_client(request: Request, mapping_id: str,
                           identity: Identity = Depends(get_current_identity),
                           session=Depends(get_db),
                           settings: Settings = Depends(get_settings)):
    """查看客户端配置（仅 admin）；secret 只回是否已配置，永不回显值（§14.6）。"""
    if not is_admin(identity, settings.admin_role):
        raise AppError(403, "FORBIDDEN", "仅管理员可查看 OAuth 客户端配置")
    await load_public_mapping(session, request.app.state.redis, mapping_id,
                              settings.cache_ttl)
    row = await load_client_row(session, mapping_id)
    if row is None:
        raise AppError(404, "OAUTH_CLIENT_NOT_CONFIGURED", "尚未配置 OAuth 客户端")
    request.state.mapping_id = mapping_id
    return _client_out(mapping_id, row)
```

`src/agent_proxy/main.py`：import 区 `from .api.proxy import router as proxy_router` 之后增一行，路由注册区 `app.include_router(proxy_router)` 之后增一行：

```python
from .api.builtin import router as builtin_router
```

```python
    app.include_router(builtin_router)
```

- [ ] **Step 6: 运行预期**

Run: `.venv/Scripts/python.exe -m pytest tests/integration/test_oauth_client_config.py -p no:cacheprovider -q`
Expected: 11 passed。实现前全 FAIL（builtin 路由 404 / auth_mode 字段被忽略 / public 详情 admin2 仍 404）。

Run: `.venv/Scripts/python.exe -m pytest -p no:cacheprovider -q`
Expected: 全部 PASS（约 **338** = 327 + 11，以实际为准）。既有 mgmt 用例（test_mgmt_api / test_services / test_mgmt_test_endpoint / test_audit）是签名变更的天然回归面——`admin_override` / `auth_mode` 均带默认值，私有映射行为零变化。

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "feat(M6): auth_mode 贯通 + 公共映射管理矩阵（§14.2）+ 手动 OAuth client 配置接口（admin，密文落库）" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

### Task 4: 授权绑定流程——authorize / oauth_callback / binding 查询 / 内置列表接口（手动 client 全流程）

**Files:**
- Modify: `src/agent_proxy/oauth/credential.py`（authz 索引三 helper + `get_binding_status`）
- Modify: `src/agent_proxy/oauth/client.py`（`consume_state` 一次性消费）
- Modify: `src/agent_proxy/api/builtin.py`（列表 / authorize / binding 三路由 + `/oauth/callback/{mapping_id}` 回调 router + `_exchange_token`）
- Modify: `src/agent_proxy/main.py`（注册 callback router）
- Modify: `src/agent_proxy/middleware.py`（route_name：`/oauth/*` → builtin）
- New: `tests/integration/test_oauth_binding_flow.py`

- [ ] **Step 1: 写失败测试**

`tests/integration/test_oauth_binding_flow.py`（新文件）：

```python
"""授权绑定全流程（ASGI client 走代理面，浏览器角色经真实 TCP 访问 9904）：
authorize（state+PKCE 入 Redis / 白名单校验）→ AS 302 → callback（一次性 state、
code+verifier 换 token、强制加密落库）→ binding 状态机 unbound→authorizing→bound；
内置列表 + binding 查询 + 回调失败分支。"""
import httpx
from sqlalchemy import select
from urllib.parse import urlparse, parse_qs

from agent_proxy.models import OAuthCredential
from agent_proxy.oauth.client import state_key
from agent_proxy.oauth.credential import decrypt_text
from tests.integration.mock_oauth_as import as_state
from tests.utils import make_token

ADMIN = {"Authorization": f"Bearer {make_token('uadmin', 'admin')}"}
U888 = {"Authorization": f"Bearer {make_token('u888')}"}
U999 = {"Authorization": f"Bearer {make_token('u999')}"}
FRONT = "http://testserver/console"
MASTER = "test-master-key"

CLIENT_BODY = {"client_id": "manual-cl", "client_secret": "manual-cs-123456",
               "token_auth": "client_secret_post",
               "authorize_url": "http://127.0.0.1:9904/oauth/authorize",
               "token_url": "http://127.0.0.1:9904/oauth/token", "scopes": "read"}


async def _create_oauth(client, type_="http", upstream="http://127.0.0.1:9901/api/v1"):
    resp = await client.post("/api/v1/mappings", json={
        "type": type_, "visibility": "public", "auth_mode": "oauth",
        "upstream_url": upstream, "headers": {}}, headers=ADMIN)
    assert resp.status_code == 201, resp.text
    return resp.json()["mapping_id"]


async def _setup(client, type_="http", upstream="http://127.0.0.1:9901/api/v1"):
    mid = await _create_oauth(client, type_, upstream)
    resp = await client.put(f"/api/v1/builtin-mappings/{mid}/client",
                            json=CLIENT_BODY, headers=ADMIN)
    assert resp.status_code == 200, resp.text
    return mid


async def _authorize(client, mid, headers=U888, front=FRONT):
    return await client.post(f"/api/v1/builtin-mappings/{mid}/authorize",
                             json={"front_redirect": front}, headers=headers)


async def _browser_get(authz_url: str):
    """浏览器角色：真实 TCP 访问 mock AS 9904，返回其 302（不跟随）。"""
    async with httpx.AsyncClient() as browser:
        return await browser.get(authz_url, follow_redirects=False)


def _path_of(url: str) -> str:
    parsed = urlparse(url)
    return parsed.path + (f"?{parsed.query}" if parsed.query else "")


async def _bind(client, mid, headers=U888):
    """完整绑定：返回 (callback_resp, authorization_url)。"""
    r = await _authorize(client, mid, headers)
    assert r.status_code == 200, r.text
    authz_url = r.json()["authorization_url"]
    redir = await _browser_get(authz_url)
    assert redir.status_code == 302, redir.text
    cb = await client.get(_path_of(redir.headers["location"]), follow_redirects=False)
    return cb, authz_url


async def test_full_manual_flow_success_redirect_and_encrypted_storage(client, app):
    mid = await _setup(client)
    cb, _ = await _bind(client, mid)
    assert cb.status_code == 302
    assert cb.headers["location"] == f"{FRONT}?binding=success"
    # 状态机收敛 bound + expires_at 回告（页面轮询面）
    b = await client.get(f"/api/v1/builtin-mappings/{mid}/binding", headers=U888)
    assert b.status_code == 200
    body = b.json()
    assert body["binding"] == "bound" and body["auth_mode"] == "oauth"
    assert body["expires_at"] and body["scope"] == "read"
    # 落库密文面（§14.6 强制加密）+ 解密等于 mock AS 签发值
    async with app.state.sessionmaker() as session:
        row = (await session.execute(select(OAuthCredential).where(
            OAuthCredential.mapping_id == mid))).scalar_one()
    assert row.uid == "u888" and row.access_token.startswith("gAAAA")
    assert "at-" not in row.access_token                  # 明文不落库
    assert decrypt_text(row.access_token, MASTER) == as_state["issued"][-1]["access_token"]
    assert row.refresh_token.startswith("gAAAA")
    # 回调审计身份来自 state（无 JWT）
    assert row.scope == "read"


async def test_binding_authorizing_then_bound(client):
    mid = await _setup(client)
    r = await _authorize(client, mid)
    assert r.status_code == 200 and "authorization_url" in r.json()
    b = await client.get(f"/api/v1/builtin-mappings/{mid}/binding", headers=U888)
    assert b.json()["binding"] == "authorizing"          # state 存续期间
    b999 = await client.get(f"/api/v1/builtin-mappings/{mid}/binding", headers=U999)
    assert b999.json()["binding"] == "unbound"           # 绑定按 uid 隔离
    cb, _ = await _bind(client, mid)
    assert cb.status_code == 302
    b = await client.get(f"/api/v1/builtin-mappings/{mid}/binding", headers=U888)
    assert b.json()["binding"] == "bound"


async def test_authorization_url_shape_and_state_in_redis(client, app):
    mid = await _setup(client)
    r = await _authorize(client, mid)
    url = r.json()["authorization_url"]
    parsed = parse_qs(urlparse(url).query)
    assert parsed["client_id"] == ["manual-cl"]
    assert parsed["response_type"] == ["code"]
    assert parsed["code_challenge_method"] == ["S256"]
    assert parsed["scope"] == ["read"]
    redirect_uri = parsed["redirect_uri"][0]
    assert redirect_uri == f"http://testserver/oauth/callback/{mid}"   # 精确值（§14.6）
    state = parsed["state"][0]
    key = state_key(state)
    ttl = await app.state.redis.ttl(key)
    assert 0 < ttl <= 600                                # OAUTH_STATE_TTL
    import json as jsonlib
    payload = jsonlib.loads(await app.state.redis.get(key))
    assert payload["uid"] == "u888" and payload["mapping_id"] == mid
    assert len(payload["code_verifier"]) == 43
    assert payload["front_redirect"] == FRONT


async def test_rebind_upserts_single_credential_row(client, app):
    mid = await _setup(client)
    cb1, _ = await _bind(client, mid)
    first_token = as_state["issued"][-1]["access_token"]
    cb2, _ = await _bind(client, mid)                    # 重复授权
    assert cb2.headers["location"] == f"{FRONT}?binding=success"
    async with app.state.sessionmaker() as session:
        rows = (await session.execute(select(OAuthCredential).where(
            OAuthCredential.mapping_id == mid))).scalars().all()
    assert len(rows) == 1                                # uk(mapping_id, uid) upsert
    assert decrypt_text(rows[0].access_token, MASTER) != first_token


async def test_builtin_list_items_binding_and_masked_headers(client):
    static_mid = (await client.post("/api/v1/mappings", json={
        "type": "http", "visibility": "public", "auth_mode": "static",
        "upstream_url": "http://10.0.0.5/api/v1",
        "headers": {"Authorization": "Bearer sk-shared-12345678"}}, headers=ADMIN)).json()["mapping_id"]
    oauth_mid = await _setup(client)
    await _bind(client, oauth_mid)                       # u888 绑定
    resp = await client.get("/api/v1/builtin-mappings", headers=U888)
    assert resp.status_code == 200
    items = {x["mapping_id"]: x for x in resp.json()}
    assert static_mid in items and oauth_mid in items
    assert items[static_mid]["binding"] is None          # static 无绑定语义
    assert items[static_mid]["headers"] == {"Authorization": "${PX:Authorization}"}
    assert "sk-shared-12345678" not in resp.text         # 占位符，真实值不出
    assert items[oauth_mid]["binding"] == "bound"
    assert items[oauth_mid]["proxy_url"].startswith("http://testserver/p/")
    resp999 = await client.get("/api/v1/builtin-mappings", headers=U999)
    items999 = {x["mapping_id"]: x for x in resp999.json()}
    assert items999[oauth_mid]["binding"] == "unbound"   # 按调用者视角


async def test_state_replay_rejected_400(client):
    mid = await _setup(client)
    r = await _authorize(client, mid)
    redir = await _browser_get(r.json()["authorization_url"])
    callback = _path_of(redir.headers["location"])
    first = await client.get(callback, follow_redirects=False)
    assert first.status_code == 302
    second = await client.get(callback, follow_redirects=False)
    assert second.status_code == 400                     # state 一次性（重放拒绝）
    assert second.json()["code"] == "OAUTH_STATE_INVALID"


async def test_forged_state_400(client):
    mid = await _setup(client)
    resp = await client.get(f"/oauth/callback/{mid}?code=cd-x&state={'f' * 32}",
                            follow_redirects=False)
    assert resp.status_code == 400 and resp.json()["code"] == "OAUTH_STATE_INVALID"


async def test_state_mapping_mismatch_400(client):
    mid_a = await _setup(client)
    mid_b = await _setup(client)
    r = await _authorize(client, mid_a)
    redir = await _browser_get(r.json()["authorization_url"])
    forged = _path_of(redir.headers["location"]).replace(f"/{mid_a}?", f"/{mid_b}?")
    resp = await client.get(forged, follow_redirects=False)
    assert resp.status_code == 400                       # state 与回调路径不匹配
    assert resp.json()["code"] == "OAUTH_STATE_INVALID"


async def test_callback_as_error_redirects_failed(client, app):
    mid = await _setup(client)
    r = await _authorize(client, mid)
    state = parse_qs(urlparse(r.json()["authorization_url"]).query)["state"][0]
    resp = await client.get(f"/oauth/callback/{mid}?error=access_denied&state={state}",
                            follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == f"{FRONT}?binding=failed&reason=access_denied"
    # AS 拒绝授权不落凭证
    from agent_proxy.oauth.credential import load_credential
    async with app.state.sessionmaker() as session:
        assert await load_credential(session, app.state.redis, mid, "u888") is None


async def test_callback_missing_code_redirects_failed(client):
    mid = await _setup(client)
    r = await _authorize(client, mid)
    state = parse_qs(urlparse(r.json()["authorization_url"]).query)["state"][0]
    resp = await client.get(f"/oauth/callback/{mid}?state={state}",
                            follow_redirects=False)
    assert resp.status_code == 302
    assert "binding=failed&reason=missing_code" in resp.headers["location"]


async def test_front_redirect_whitelist_400(client):
    mid = await _setup(client)
    for bad in ("http://evil.example.com/cb", "http://testserver:8080/cb",
                "javascript:alert(1)", "/relative"):
        resp = await _authorize(client, mid, front=bad)
        assert resp.status_code == 400 and resp.json()["code"] == "INVALID_PARAM"


async def test_authorize_on_static_public_400(client):
    mid = (await client.post("/api/v1/mappings", json={
        "type": "http", "visibility": "public", "auth_mode": "static",
        "upstream_url": "http://10.0.0.5/api/v1", "headers": {}},
        headers=ADMIN)).json()["mapping_id"]
    resp = await _authorize(client, mid)
    assert resp.status_code == 400 and resp.json()["code"] == "OAUTH_NOT_APPLICABLE"
    resp = await client.get(f"/api/v1/builtin-mappings/{mid}/binding", headers=U888)
    assert resp.status_code == 400 and resp.json()["code"] == "OAUTH_NOT_APPLICABLE"


async def test_authorize_without_client_400(client):
    # Task 5 起本用例迁移为 502 OAUTH_CLIENT_SETUP_FAILED（无行 → DCR，上游无元数据）
    mid = await _create_oauth(client)
    resp = await _authorize(client, mid)
    assert resp.status_code == 400
    assert resp.json()["code"] == "OAUTH_CLIENT_NOT_CONFIGURED"


async def test_authorize_private_or_missing_404(client):
    private = (await client.post("/api/v1/mappings", json={
        "type": "http", "visibility": "private",
        "upstream_url": "http://10.0.0.5/api/v1", "headers": {}},
        headers=ADMIN)).json()["mapping_id"]
    resp = await _authorize(client, private)
    assert resp.status_code == 404                       # 非 public 隐藏存在性
    resp = await _authorize(client, "aaaaaaaaaaaa")
    assert resp.status_code == 404
```

- [ ] **Step 2: 实现 credential.py / client.py 增量**

`src/agent_proxy/oauth/credential.py`：文件末尾追加：

```python
# ---------- 授权进行中索引（authorizing 态判定，设计 §14.4 / §5.3 最小增量键） ----------


def authz_index_key(mapping_id: str, uid: str) -> str:
    return f"ap:oauth:authz:{mapping_id}:{uid}"


async def set_authz_index(r, mapping_id: str, uid: str, state: str, ttl: int) -> None:
    """authorize 写入（state 存续期索引，binding 查询据此判 authorizing）；
    callback 成功 / 解绑时删除。"""
    try:
        await r.set(authz_index_key(mapping_id, uid), state, ex=ttl)
    except Exception as exc:
        log.warning("authz 索引写入失败: %s", exc)


async def get_authz_index(r, mapping_id: str, uid: str) -> str | None:
    try:
        return await r.get(authz_index_key(mapping_id, uid))
    except Exception as exc:
        log.warning("authz 索引读取失败: %s", exc)
        return None


async def drop_authz_index(r, mapping_id: str, uid: str) -> None:
    try:
        await r.delete(authz_index_key(mapping_id, uid))
    except Exception as exc:
        log.warning("authz 索引删除失败: %s", exc)


async def get_binding_status(session: AsyncSession, r, mapping_id: str, uid: str) -> str:
    """绑定状态机（§14.4）：unbound → authorizing（state 存续期间）→ bound(active)
    → invalid（refresh 失败 / 提供方吊销）。判定顺序：凭证行 → authz 索引 → unbound。"""
    cred = await load_credential(session, r, mapping_id, uid)
    if cred is not None:
        return "bound" if cred.get("status") == "active" else "invalid"
    if await get_authz_index(r, mapping_id, uid) is not None:
        return "authorizing"
    return "unbound"
```

`src/agent_proxy/oauth/client.py`：文件末尾追加：

```python
# ---------- state 一次性消费（Redis MULTI 事务管道，兼容 Redis 3.0 无 GETDEL） ----------


async def consume_state(r, state: str) -> dict:
    """原子取删：MULTI 事务管道 GET+DEL（并发回调同一 state 仅一方取到值；
    本地/测试 Redis 3.0.504 无 GETDEL，实现机制钉死在 MULTI，不得改写）。
    不存在（过期 / 伪造 / 已消费）→ 400 OAUTH_STATE_INVALID。"""
    pipe = r.pipeline(transaction=True)
    pipe.get(state_key(state))
    pipe.delete(state_key(state))
    results = await pipe.execute()
    raw = results[0]
    if raw is None:
        raise AppError(400, "OAUTH_STATE_INVALID", "state 无效、已使用或已过期")
    return decode_state_payload(raw)
```

- [ ] **Step 3: 实现 builtin.py 四路由 + callback router**

`src/agent_proxy/api/builtin.py`：

1. import 区整体替换为：

```python
from __future__ import annotations

import logging

import httpx
from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import metrics, placeholder
from ..auth import Identity
from ..config import Settings, get_settings
from ..errors import AppError
from ..models import OAuthClient, ProxyMapping
from ..oauth.client import (build_authorization_url, build_redirect_uri,
                            build_token_request, consume_state, encode_state_payload,
                            load_client_row, new_code_verifier, new_state,
                            save_oauth_client_row, state_key, validate_front_redirect)
from ..oauth.credential import (decrypt_text, drop_authz_index, encrypt_text,
                                expires_at_from, get_binding_status, load_credential,
                                save_credential, set_authz_index)
from ..schemas import (AuthorizeIn, AuthorizeOut, BindingOut, BuiltinItemOut,
                       OAuthClientOut, OAuthClientSet)
from ..services import build_proxy_url, load_mapping
from ..ssrf import async_validate_upstream_url
from .deps import get_current_identity, get_db, is_admin
```

2. 在 `_client_out` 函数定义之后、`@router.put(...)` 装饰器之前插入列表路由（静态路由先注册）：

```python
# 静态列表路由先于动态 /{mapping_id}/... 注册（FastAPI 按注册顺序匹配，/resolve 先例）
@router.get("", response_model=list[BuiltinItemOut])
async def list_builtin_mappings(request: Request,
                                identity: Identity = Depends(get_current_identity),
                                session=Depends(get_db),
                                settings: Settings = Depends(get_settings)):
    """内置映射列表（§6.5）：name / type / proxy_url / 占位符 headers / auth_mode +
    我的绑定状态（页面据此保存完整代理配置）。static 映射 binding=None。"""
    rows = (await session.execute(
        select(ProxyMapping).where(ProxyMapping.visibility == "public")
        .order_by(ProxyMapping.id))).scalars().all()
    out = []
    for row in rows:
        binding = None
        if row.auth_mode == "oauth":
            binding = await get_binding_status(session, request.app.state.redis,
                                               row.mapping_id, identity.user_id)
        out.append(BuiltinItemOut(
            mapping_id=row.mapping_id, name=row.name, type=row.type,
            proxy_url=build_proxy_url(settings, row.mapping_id, row.upstream_url, row.type),
            headers=placeholder.mask_headers(row.upstream_headers or {}),
            auth_mode=row.auth_mode, binding=binding, status=row.status))
    return out
```

3. 在 `get_oauth_client` 路由之后追加 authorize / binding / callback：

```python
@router.post("/{mapping_id}/authorize", response_model=AuthorizeOut)
async def authorize_mapping(request: Request, mapping_id: str, body: AuthorizeIn,
                            identity: Identity = Depends(get_current_identity),
                            session=Depends(get_db),
                            settings: Settings = Depends(get_settings)):
    """发起授权（§14.4）：任意有效用户；front_redirect 域白名单校验 → state +
    PKCE verifier 入 Redis（600s，绑 uid）→ 返回 authorization_url。"""
    data = await load_public_mapping(session, request.app.state.redis, mapping_id,
                                     settings.cache_ttl)
    require_oauth_mode(data)
    front_redirect = validate_front_redirect(body.front_redirect,
                                             settings.cors_allowed_origins)
    client_row = await load_client_row(session, mapping_id)
    if client_row is None or not client_row.authorize_url:
        # Task 5 起：无行时改走 ensure_client 的 DCR 分支（§14.3 DCR 优先）
        raise AppError(400, "OAUTH_CLIENT_NOT_CONFIGURED",
                       "该映射尚未配置 OAuth 客户端（管理员手动配置，或首次授权时 DCR）")
    verifier = new_code_verifier()
    state = new_state()
    r = request.app.state.redis
    ttl = settings.oauth_state_ttl
    await r.set(state_key(state), encode_state_payload(
        uid=identity.user_id, mapping_id=mapping_id, code_verifier=verifier,
        front_redirect=front_redirect), ex=ttl)
    await set_authz_index(r, mapping_id, identity.user_id, state, ttl)
    url = build_authorization_url(
        client_row.authorize_url, client_id=client_row.client_id,
        redirect_uri=build_redirect_uri(settings.external_base, mapping_id),
        state=state, code_verifier=verifier, scopes=client_row.scopes)
    request.state.audit_action = "oauth_authorize"
    request.state.mapping_id = mapping_id
    return AuthorizeOut(authorization_url=url)


@router.get("/{mapping_id}/binding", response_model=BindingOut)
async def get_binding_route(request: Request, mapping_id: str,
                            identity: Identity = Depends(get_current_identity),
                            session=Depends(get_db),
                            settings: Settings = Depends(get_settings)):
    """我的绑定状态查询（页面轮询，§14.4 状态机）。"""
    data = await load_public_mapping(session, request.app.state.redis, mapping_id,
                                     settings.cache_ttl)
    require_oauth_mode(data)
    binding = await get_binding_status(session, request.app.state.redis, mapping_id,
                                       identity.user_id)
    expires_at = scope = None
    if binding in ("bound", "invalid"):
        cred = await load_credential(session, request.app.state.redis, mapping_id,
                                     identity.user_id)
        if cred is not None:
            expires_at, scope = cred.get("expires_at"), cred.get("scope")
    request.state.mapping_id = mapping_id
    return BindingOut(mapping_id=mapping_id, auth_mode=data["auth_mode"],
                      binding=binding, expires_at=expires_at, scope=scope)


async def _exchange_token(client, token_url: str, headers: dict,
                          form: dict) -> dict | None:
    """code 换 token（§14.4 第 8 步）；网络失败 / 非 200 / 非 JSON → None（上层回跳
    failed）。日志只记异常类型与状态码——token / client_secret 不入任何日志（§14.6）。"""
    try:
        resp = await client.post(token_url, data=form, headers=headers, timeout=15.0)
    except httpx.HTTPError as exc:
        log.warning("token 端点请求失败: %s", type(exc).__name__)
        return None
    if resp.status_code != 200:
        log.warning("token 端点非 200: status=%s", resp.status_code)
        return None
    try:
        return resp.json()
    except ValueError:
        return None


@callback_router.get("/oauth/callback/{mapping_id}")
async def oauth_callback(request: Request, mapping_id: str,
                         session=Depends(get_db),
                         settings: Settings = Depends(get_settings)):
    """OAuth 回调（§14.4，无 JWT——身份由一次性 state 关联）：
    state 原子取删（重放/过期/伪造 → 400 OAUTH_STATE_INVALID）→ 路径 mapping_id
    与 state 载荷一致性校验（防跨映射伪造）→ AS 错误/缺 code → 302 binding=failed →
    code+verifier 换 token → 强制加密落库 uk(mapping_id,uid)（§14.6）→ 302
    front_redirect?binding=success。front_redirect 为 authorize 时已过白名单的存储值。"""
    state = request.query_params.get("state", "")
    code = request.query_params.get("code", "")
    as_error = request.query_params.get("error", "")
    payload = await consume_state(request.app.state.redis, state)
    request.state.uid = payload["uid"]                   # 审计身份来自 state（无 JWT）
    request.state.mapping_id = payload["mapping_id"]
    request.state.audit_action = "oauth_bind"
    if payload["mapping_id"] != mapping_id:
        raise AppError(400, "OAUTH_STATE_INVALID", "state 与回调路径不匹配")
    front_redirect = payload["front_redirect"]
    sep = "&" if "?" in front_redirect else "?"
    if as_error or not code:
        # 用户在 AS 拒绝授权 / AS 错误重定向 / 缺 code：不落凭证，回跳失败态
        metrics.oauth_actions_total.labels(action="fail").inc()
        reason = as_error or "missing_code"
        return RedirectResponse(
            f"{front_redirect}{sep}binding=failed&reason={reason}", status_code=302)
    data = await load_public_mapping(session, request.app.state.redis, mapping_id,
                                     settings.cache_ttl)
    require_oauth_mode(data)
    client_row = await load_client_row(session, mapping_id)
    if client_row is None or not client_row.token_url:
        raise AppError(400, "OAUTH_CLIENT_NOT_CONFIGURED",
                       "OAuth 客户端配置缺失，无法换取 token")
    headers, form = build_token_request(
        client_row.token_auth, client_id=client_row.client_id,
        client_secret=(decrypt_text(client_row.client_secret, settings.master_key)
                       if client_row.client_secret else None),
        extra={"grant_type": "authorization_code", "code": code,
               "redirect_uri": build_redirect_uri(settings.external_base, mapping_id),
               "code_verifier": payload["code_verifier"]})
    tokens = await _exchange_token(request.app.state.http_client,
                                   client_row.token_url, headers, form)
    if tokens is None or not tokens.get("access_token"):
        metrics.oauth_actions_total.labels(action="fail").inc()
        return RedirectResponse(
            f"{front_redirect}{sep}binding=failed&reason=token_exchange",
            status_code=302)
    await save_credential(session, request.app.state.redis, mapping_id, payload["uid"],
                          access_token_ct=encrypt_text(tokens["access_token"],
                                                       settings.master_key),
                          refresh_token_ct=(encrypt_text(tokens["refresh_token"],
                                                         settings.master_key)
                                            if tokens.get("refresh_token") else None),
                          expires_at=expires_at_from(tokens.get("expires_in")),
                          scope=tokens.get("scope"), master_key=settings.master_key)
    await drop_authz_index(request.app.state.redis, mapping_id, payload["uid"])
    metrics.oauth_actions_total.labels(action="bind").inc()
    return RedirectResponse(f"{front_redirect}{sep}binding=success", status_code=302)
```

4. 模块末尾追加 callback router 定义（须在 `oauth_callback` 使用之前定义——放在 `router = APIRouter(...)` 之后的模块常量区）：

```python
# 回调路由：/oauth/callback 无 JWT（身份由 state 关联），独立 router 便于 main 组装；
# metrics/审计 route 归 builtin（middleware.route_name /oauth/* 分支）
callback_router = APIRouter(tags=["builtin"])
```

（将 `callback_router = APIRouter(tags=["builtin"])` 放在 `router = APIRouter(prefix=...)` 一行的下一行，模块常量区；Step 3 第 3 点的装饰器引用它。）

- [ ] **Step 4: main.py + middleware.py 接线**

`src/agent_proxy/main.py`：builtin import 行改为：

```python
from .api.builtin import router as builtin_router, callback_router as oauth_callback_router
```

注册区 `app.include_router(builtin_router)` 之后增一行：

```python
    app.include_router(oauth_callback_router)
```

`src/agent_proxy/middleware.py`：`route_name` 增一个分支（`/api/v1/builtin` 分支之后）：

```python
    if path.startswith("/oauth/"):
        return "builtin"
```

- [ ] **Step 5: 运行预期**

Run: `.venv/Scripts/python.exe -m pytest tests/integration/test_oauth_binding_flow.py -p no:cacheprovider -q`
Expected: 13 passed。实现前全 FAIL（路由 404）。`test_state_replay_rejected_400` 钉住 MULTI 原子取删；`test_full_manual_flow_success_redirect_and_encrypted_storage` 钉住 302 回跳 + 密文落库 + 解密 == mock AS 签发值三面。

Run: `.venv/Scripts/python.exe -m pytest -p no:cacheprovider -q`
Expected: 全部 PASS（约 **351** = 338 + 13，以实际为准）。

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat(M6): 授权绑定流程——authorize/callback（一次性 state+PKCE，加密落库）+ binding 状态机 + 内置列表接口" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

### Task 5: discovery + DCR（RFC 7591，首次授权自动注册）+ 解绑（revoke best-effort）+ metrics 接线

**Files:**
- Modify: `src/agent_proxy/oauth/client.py`（`ensure_client`：manual 直读 / DCR 注册；discovery 包装）
- Modify: `src/agent_proxy/api/builtin.py`（authorize/callback 改走 `ensure_client`；DELETE binding 路由 + revoke）
- Modify: `tests/integration/test_oauth_binding_flow.py`（`test_authorize_without_client_400` 迁移为 DCR 语义）
- New: `tests/integration/test_oauth_dcr_flow.py`

- [ ] **Step 1: 写失败测试**

`tests/integration/test_oauth_dcr_flow.py`（新文件）：

```python
"""DCR 全流程（真实 TCP 9910 → 9904 AS）：首次 authorize 无 client 行 → discovery
（protected-resource → authorization-server 两步）→ RFC 7591 动态注册 → source=dcr
落库 → 授权绑定 → 按用户注入调用（http 形态经 9904 RS echo 验证）→ 解绑（revoke
连带）→ metrics ap_oauth_actions_total 计数。
（DCR 失败 → 502 OAUTH_CLIENT_SETUP_FAILED 用例在 test_oauth_binding_flow.py 迁移版。）"""
import re

import httpx
from sqlalchemy import select

from agent_proxy.models import OAuthCredential, OAuthClient
from agent_proxy.oauth.credential import decrypt_text
from tests.integration.mock_oauth_as import as_state
from tests.utils import make_token

PROXY = "http://127.0.0.1:9910"
AS = "http://127.0.0.1:9904"
FRONT = "http://127.0.0.1:9910/console"
MASTER = "test-master-key"
ADMIN = {"Authorization": f"Bearer {make_token('uadmin', 'admin')}"}
U888 = {"Authorization": f"Bearer {make_token('u888')}"}
U999 = {"Authorization": f"Bearer {make_token('u999')}"}
TCP_TIMEOUT = httpx.Timeout(connect=5, read=10, write=10, pool=5)


async def _create_oauth_http():
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        resp = await c.post(f"{PROXY}/api/v1/mappings", json={
            "type": "http", "visibility": "public", "auth_mode": "oauth",
            "upstream_url": f"{AS}/api", "headers": {}}, headers=ADMIN)
    assert resp.status_code == 201, resp.text
    return resp.json()["mapping_id"]


async def _authorize(mid, user_headers=U888):
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        resp = await c.post(f"{PROXY}/api/v1/builtin-mappings/{mid}/authorize",
                            json={"front_redirect": FRONT}, headers=user_headers)
    assert resp.status_code == 200, resp.text
    return resp.json()["authorization_url"]


async def _complete_binding(authz_url):
    """浏览器角色：真实 TCP 走 9904 authorize → 302 → 真实 TCP 打到 9910 回调。"""
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as browser:
        redir = await browser.get(authz_url, follow_redirects=False)
        assert redir.status_code == 302, redir.text
        callback_url = redir.headers["location"]
        cb = await browser.get(callback_url, follow_redirects=False)
    return cb


async def _proxy_call(mid, path, headers):
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        return await c.get(f"{PROXY}/p/{mid}/{path}", headers=headers)


async def _cred_token(app, mid, uid="u888") -> str:
    async with app.state.sessionmaker() as session:
        row = (await session.execute(select(OAuthCredential).where(
            OAuthCredential.mapping_id == mid,
            OAuthCredential.uid == uid))).scalar_one()
    return decrypt_text(row.access_token, MASTER)


async def test_dcr_registers_on_first_authorize_and_binds(app):
    as_state["registrations"].clear()
    mid = await _create_oauth_http()
    # 无 client 行 + 上游 9904 有 well-known → DCR 成功
    authz_url = await _authorize(mid)
    assert len(as_state["registrations"]) == 1
    reg = as_state["registrations"][-1]
    assert reg["redirect_uris"] == [f"{PROXY}/oauth/callback/{mid}"]   # 精确单一值
    assert set(reg["grant_types"]) == {"authorization_code", "refresh_token"}
    assert reg["token_endpoint_auth_method"] == "client_secret_post"
    # 落库 source=dcr（§5.3：authorize_url/token_url 留空）
    async with app.state.sessionmaker() as session:
        row = (await session.execute(select(OAuthClient).where(
            OAuthClient.mapping_id == mid))).scalar_one()
    assert row.source == "dcr" and row.authorize_url is None and row.token_url is None
    assert row.client_id.startswith("cl-")
    assert row.client_secret.startswith("gAAAA")
    # 完成 binding
    cb = await _complete_binding(authz_url)
    assert cb.status_code == 302
    assert cb.headers["location"] == f"{FRONT}?binding=success"
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        b = await c.get(f"{PROXY}/api/v1/builtin-mappings/{mid}/binding", headers=U888)
    assert b.json()["binding"] == "bound"


async def test_dcr_injected_call_reaches_upstream_with_own_token(app):
    mid = await _create_oauth_http()
    cb = await _complete_binding(await _authorize(mid))
    assert cb.status_code == 302
    token = await _cred_token(app, mid)
    r = await _proxy_call(mid, "orders?id=1", U888)
    assert r.status_code == 200
    body = r.json()
    # 出站 Authorization: Bearer <该用户 access_token>（§14.5「仅还原注册者 header」唯一例外）
    assert body["headers"]["authorization"] == f"Bearer {token}"
    assert not any(v.startswith("stub.") for v in body["headers"].values())  # JWT 不透传
    # 另一用户未绑定 → 401 OAUTH_BINDING_REQUIRED（任意有效用户可调 public，但须先绑定）
    r999 = await _proxy_call(mid, "orders", U999)
    assert r999.status_code == 401
    assert r999.json()["code"] == "OAUTH_BINDING_REQUIRED"
    assert f"/builtin-mappings/{mid}/authorize" in r999.json()["message"]  # body 附授权引导


async def test_unbind_revokes_and_401_afterwards(app):
    mid = await _create_oauth_http()
    await _complete_binding(await _authorize(mid))
    token = await _cred_token(app, mid)
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        r = await c.delete(f"{PROXY}/api/v1/builtin-mappings/{mid}/binding", headers=U888)
    assert r.status_code == 204
    # 本地凭证删除 + revoke best-effort 到达 AS（dcr 客户端经 discovery 拿 revocation_endpoint）
    async with app.state.sessionmaker() as session:
        rows = (await session.execute(select(OAuthCredential).where(
            OAuthCredential.mapping_id == mid))).scalars().all()
    assert rows == []
    assert any(x["token"] == token for x in as_state["revocations"])
    # 解绑后调用 → 401；binding 状态回 unbound
    r = await _proxy_call(mid, "orders", U888)
    assert r.status_code == 401 and r.json()["code"] == "OAUTH_BINDING_REQUIRED"
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        b = await c.get(f"{PROXY}/api/v1/builtin-mappings/{mid}/binding", headers=U888)
    assert b.json()["binding"] == "unbound"
    # 再解绑 → 404
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        r2 = await c.delete(f"{PROXY}/api/v1/builtin-mappings/{mid}/binding", headers=U888)
    assert r2.status_code == 404


async def test_oauth_metrics_bind_unbind_counters(app):
    mid = await _create_oauth_http()
    await _complete_binding(await _authorize(mid))
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        await c.delete(f"{PROXY}/api/v1/builtin-mappings/{mid}/binding", headers=U888)
        m = await c.get(f"{PROXY}/metrics")
    text = m.text
    bind = re.search(r'^ap_oauth_actions_total\{action="bind"\} ([0-9.]+)$', text, re.M)
    unbind = re.search(r'^ap_oauth_actions_total\{action="unbind"\} ([0-9.]+)$', text, re.M)
    assert bind and float(bind.group(1)) >= 1.0
    assert unbind and float(unbind.group(1)) >= 1.0
```

`tests/integration/test_oauth_binding_flow.py`：**迁移** `test_authorize_without_client_400`（Task 5 起无行 → DCR；9901 echo 无 well-known → 502 SETUP_FAILED，与上条 9904 用例互补，此处保留 ASGI 侧回归面）——整条替换为：

```python
async def test_authorize_without_client_dcr_setup_failed(client):
    """Task 5 迁移：无 client 行不再 400 NOT_CONFIGURED——先走 DCR（§14.3）；
    上游 9901 无 well-known → 502 OAUTH_CLIENT_SETUP_FAILED。"""
    mid = await _create_oauth(client, upstream="http://127.0.0.1:9901/api/v1")
    resp = await _authorize(client, mid)
    assert resp.status_code == 502
    assert resp.json()["code"] == "OAUTH_CLIENT_SETUP_FAILED"
```

（原 `test_authorize_without_client_400` 用例删除；本计划在 test_oauth_dcr_flow.py 中不设重复的 discovery 失败用例——以本迁移版为唯一落点。）

- [ ] **Step 2: 实现 client.py 的 ensure_client（DCR）**

`src/agent_proxy/oauth/client.py`：import 区追加 `import logging`、`import httpx`、`from ..errors import AppError`（已有）、`from .discovery import DiscoveryError, discover_authorization_server, upstream_origin`；模块常量区加 `log = logging.getLogger("agent_proxy")`。文件末尾追加：

```python
# ---------- ensure_client：manual 直读 / DCR 注册（§14.3，authorize 时调用） ----------


async def _discover_or_setup_failed(app_state, mapping_data: dict) -> dict:
    """discovery 包装：失败映射 502 OAUTH_CLIENT_SETUP_FAILED（提示改手动配置）。"""
    try:
        return await discover_authorization_server(
            app_state.http_client, upstream_origin(mapping_data["upstream_url"]))
    except DiscoveryError as exc:
        raise AppError(502, "OAUTH_CLIENT_SETUP_FAILED",
                       f"OAuth discovery 失败（{exc}），请管理员改用手动配置") from exc


async def ensure_client(session: AsyncSession, app_state, mapping_data: dict,
                        master_key: str, redirect_uri: str) -> dict:
    """取/建 OAuth 客户端（§14.3 DCR 优先 + 手动兼容）：
    - proxy_oauth_client 有行 → 直读（secret 解密）；source=dcr 行的 authorize/token
      端点实时 discovery（§5.3：DCR 模式两列留空，提供方改端点无需迁移数据）；
    - 无行 → discovery → RFC 7591 注册（redirect_uris 精确单一值、PKCE S256 声明）
      → 落行 source=dcr；
    - discovery/DCR 失败 → 502 OAUTH_CLIENT_SETUP_FAILED（提示管理员改用手动配置）。
    返回 dict：client_id / client_secret(解密) / token_auth / authorize_url /
    token_url / scopes / source / revocation_endpoint。"""
    mapping_id = mapping_data["mapping_id"]
    row = await load_client_row(session, mapping_id)
    if row is not None:
        client = _row_to_client(row, master_key)
        if row.source == "dcr":
            meta = await _discover_or_setup_failed(app_state, mapping_data)
            client["authorize_url"] = meta["authorization_endpoint"]
            client["token_url"] = meta["token_endpoint"]
            client["revocation_endpoint"] = meta.get("revocation_endpoint")
        return client
    meta = await _discover_or_setup_failed(app_state, mapping_data)
    if not meta.get("registration_endpoint"):
        raise AppError(502, "OAUTH_CLIENT_SETUP_FAILED",
                       "AS 元数据无 registration_endpoint，请管理员改用手动配置")
    payload = build_dcr_payload(f"agent-proxy-{mapping_id}", redirect_uri)
    try:
        resp = await app_state.http_client.post(meta["registration_endpoint"],
                                                json=payload, timeout=15.0)
    except httpx.HTTPError as exc:
        raise AppError(502, "OAUTH_CLIENT_SETUP_FAILED",
                       f"DCR 注册请求失败（{type(exc).__name__}），请改用手动配置") from exc
    if resp.status_code != 200:
        raise AppError(502, "OAUTH_CLIENT_SETUP_FAILED",
                       f"DCR 注册被拒（status={resp.status_code}），请改用手动配置")
    try:
        reg = resp.json()
    except ValueError as exc:
        raise AppError(502, "OAUTH_CLIENT_SETUP_FAILED",
                       "DCR 响应非 JSON，请改用手动配置") from exc
    if not reg.get("client_id"):
        raise AppError(502, "OAUTH_CLIENT_SETUP_FAILED",
                       "DCR 响应缺少 client_id，请改用手动配置")
    token_auth = normalize_token_auth(reg.get("token_endpoint_auth_method"))
    secret_plain = reg.get("client_secret")
    scopes = reg.get("scope")
    await save_oauth_client_row(session, mapping_id, client_id=reg["client_id"],
                                client_secret_plain=secret_plain, token_auth=token_auth,
                                authorize_url=None, token_url=None,
                                scopes=scopes, source="dcr", master_key=master_key)
    return {"client_id": reg["client_id"], "client_secret": secret_plain,
            "token_auth": token_auth, "authorize_url": meta["authorization_endpoint"],
            "token_url": meta["token_endpoint"], "scopes": scopes,
            "source": "dcr", "revocation_endpoint": meta.get("revocation_endpoint")}
```

- [ ] **Step 3: builtin.py 接线 ensure_client + DELETE binding**

`src/agent_proxy/api/builtin.py`：

1. `authorize_mapping` 中「手动 client 直读」段（`client_row = await load_client_row(...)` 到 `raise AppError(400, "OAUTH_CLIENT_NOT_CONFIGURED", ...)` 两处判断）替换为：

```python
    redirect_uri = build_redirect_uri(settings.external_base, mapping_id)
    client = await ensure_client(session, request.app.state, data,
                                 settings.master_key, redirect_uri)
```

其下 `build_authorization_url(...)` 调用改为：

```python
    url = build_authorization_url(
        client["authorize_url"], client_id=client["client_id"],
        redirect_uri=redirect_uri, state=state, code_verifier=verifier,
        scopes=client["scopes"])
```

（docstring 中「Task 5 起：无行时改走 ensure_client 的 DCR 分支」注释随实现落位删除。）

2. `oauth_callback` 中「`client_row = await load_client_row(...)` 到 `raise AppError(400, "OAUTH_CLIENT_NOT_CONFIGURED", ...)`」段替换为：

```python
    client = await ensure_client(session, request.app.state, data,
                                 settings.master_key,
                                 build_redirect_uri(settings.external_base, mapping_id))
```

其下 `headers, form = build_token_request(...)` 与 `_exchange_token(...)` 调用改为：

```python
    headers, form = build_token_request(
        client["token_auth"], client_id=client["client_id"],
        client_secret=client["client_secret"],
        extra={"grant_type": "authorization_code", "code": code,
               "redirect_uri": build_redirect_uri(settings.external_base, mapping_id),
               "code_verifier": payload["code_verifier"]})
    tokens = await _exchange_token(request.app.state.http_client,
                                   client["token_url"], headers, form)
```

（`OAUTH_CLIENT_NOT_CONFIGURED` 语义保留在 GET client 路由——配置查询面。）

3. import 区 `..oauth.client` 组追加 `ensure_client`；新增 revoke 需要的 import：

```python
from ..oauth.client import (build_authorization_url, build_redirect_uri,
                            build_token_request, consume_state, encode_state_payload,
                            ensure_client, load_client_row, new_code_verifier,
                            new_state, save_oauth_client_row, state_key,
                            validate_front_redirect)
```

4. `get_binding_route` 之后追加解绑路由：

```python
@router.delete("/{mapping_id}/binding", status_code=204)
async def unbind_mapping(request: Request, mapping_id: str,
                         identity: Identity = Depends(get_current_identity),
                         session=Depends(get_db),
                         settings: Settings = Depends(get_settings)):
    """解绑（§14.4）：删除本地凭证；提供方支持时（dcr 客户端经 discovery 拿到
    revocation_endpoint）同时 best-effort 调用 revoke——revoke 失败仅 WARN，
    不影响本地解绑；manual 模式无 revoke 端点配置 → 仅删本地凭证。"""
    data = await load_public_mapping(session, request.app.state.redis, mapping_id,
                                     settings.cache_ttl)
    require_oauth_mode(data)
    r = request.app.state.redis
    cred = await load_credential(session, r, mapping_id, identity.user_id)
    if cred is None:
        raise AppError(404, "MAPPING_NOT_FOUND", "尚未绑定，无需解绑")
    access_plain = decrypt_text(cred["access_token"], settings.master_key)
    deleted = await delete_credential(session, r, mapping_id, identity.user_id)
    assert deleted                                        # 上一行已确认存在
    # revoke best-effort（凭证已在本地删除，失败不回滚——本地删除是不可回退语义）
    try:
        client = await ensure_client(session, request.app.state, data,
                                     settings.master_key,
                                     build_redirect_uri(settings.external_base, mapping_id))
        rev = client.get("revocation_endpoint")
        if rev:
            headers, form = build_token_request(
                client["token_auth"], client_id=client["client_id"],
                client_secret=client["client_secret"],
                extra={"token": access_plain, "token_type_hint": "access_token"})
            resp = await request.app.state.http_client.post(rev, data=form,
                                                            headers=headers, timeout=10.0)
            if resp.status_code != 200:
                log.warning("revoke 非 200: status=%s（本地凭证已删除）", resp.status_code)
    except AppError as exc:
        log.warning("revoke 前置（discovery/ensure_client）失败（忽略）: %s", exc.message)
    except httpx.HTTPError as exc:
        log.warning("revoke 请求失败（忽略）: %s", type(exc).__name__)
    metrics.oauth_actions_total.labels(action="unbind").inc()
    request.state.audit_action = "oauth_unbind"
    request.state.mapping_id = mapping_id
    return Response(status_code=204)
```

import 区补 `from fastapi import Response` 与 `from ..oauth.credential import ..., delete_credential`（并入既有 credential import 组）。

- [ ] **Step 4: 运行预期**

Run: `.venv/Scripts/python.exe -m pytest tests/integration/test_oauth_dcr_flow.py tests/integration/test_oauth_binding_flow.py -p no:cacheprovider -q`
Expected: 全部 PASS（DCR 4 + binding 13，其中迁移版 `test_authorize_without_client_dcr_setup_failed` 替换旧用例）。实现前 DCR 用例全 FAIL（authorize 对无行映射仍 400 NOT_CONFIGURED）。

Run: `.venv/Scripts/python.exe -m pytest -p no:cacheprovider -q`
Expected: 全部 PASS（约 **355** = 351 + 4——迁移用例 1 换 1 净 0，DCR 新增 4；以实际为准）。

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(M6): discovery + DCR（RFC 7591 首次授权自动注册）+ 解绑 revoke（best-effort）+ ap_oauth_actions_total 接线" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

### Task 6: 凭证注入 + 过期自动刷新（Redis 锁防并发）+ 转发接线 + builtin test 接口扩展

**Files:**
- Modify: `src/agent_proxy/oauth/credential.py`（`get_callable_credential` / `refresh_credential` / 审计；client 侧 helper 走函数内延迟 import 断循环）
- Modify: `src/agent_proxy/api/proxy.py`（`auth_mode=oauth` 注入——转发管线唯一接线点）
- Modify: `src/agent_proxy/api/builtin.py`（`POST /{id}/test`：admin 静态 / 绑定用户本人凭证 + 失效提示）
- New: `tests/integration/test_oauth_injection.py`

- [ ] **Step 1: 写失败测试**

`tests/integration/test_oauth_injection.py`（新文件）：

```python
"""按用户注入端到端（真实 TCP 9910）：三形态 token 到达上游断言、未绑定/invalid
401、过期自动刷新、并发刷新单飞（Redis 锁）、刷新失败→invalid→重新授权恢复、
builtin test 本人凭证与失效提示（§14.5 / §6.6）。"""
import asyncio
from sqlalchemy import select

import httpx

from agent_proxy.models import OAuthCredential
from agent_proxy.oauth.credential import (decrypt_text, encrypt_text,
                                          invalidate_credential)
from tests.integration.mock_mcp_sse import mock_state
from tests.integration.mock_mcp_streamable import secure_state, streamable_state
from tests.integration.mock_oauth_as import as_state
from tests.utils import make_token

PROXY = "http://127.0.0.1:9910"
AS = "http://127.0.0.1:9904"
FRONT = "http://127.0.0.1:9910/console"
MASTER = "test-master-key"
ADMIN = {"Authorization": f"Bearer {make_token('uadmin', 'admin')}"}
U888 = {"Authorization": f"Bearer {make_token('u888')}"}
U999 = {"Authorization": f"Bearer {make_token('u999')}"}
TCP_TIMEOUT = httpx.Timeout(connect=5, read=10, write=10, pool=5)

CLIENT_BODY = {"client_id": "manual-cl", "client_secret": "manual-cs-123456",
               "token_auth": "client_secret_post",
               "authorize_url": f"{AS}/oauth/authorize",
               "token_url": f"{AS}/oauth/token", "scopes": "read"}


async def _create_oauth(upstream, type_="http"):
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        resp = await c.post(f"{PROXY}/api/v1/mappings", json={
            "type": type_, "visibility": "public", "auth_mode": "oauth",
            "upstream_url": upstream, "headers": {}}, headers=ADMIN)
    assert resp.status_code == 201, resp.text
    return resp.json()["mapping_id"]


async def _setup_manual(upstream, type_="http"):
    mid = await _create_oauth(upstream, type_)
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        resp = await c.put(f"{PROXY}/api/v1/builtin-mappings/{mid}/client",
                           json=CLIENT_BODY, headers=ADMIN)
    assert resp.status_code == 200, resp.text
    return mid


async def _bind(mid, user_headers=U888, front=FRONT):
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        r = await c.post(f"{PROXY}/api/v1/builtin-mappings/{mid}/authorize",
                         json={"front_redirect": front}, headers=user_headers)
        assert r.status_code == 200, r.text
        redir = await c.get(r.json()["authorization_url"], follow_redirects=False)
        assert redir.status_code == 302, redir.text
        cb = await c.get(redir.headers["location"], follow_redirects=False)
    assert cb.status_code == 302, cb.text
    assert "binding=success" in cb.headers["location"]


async def _cred_row(app, mid, uid="u888"):
    async with app.state.sessionmaker() as session:
        return (await session.execute(select(OAuthCredential).where(
            OAuthCredential.mapping_id == mid,
            OAuthCredential.uid == uid))).scalar_one()


async def _cred_token(app, mid, uid="u888") -> str:
    return decrypt_text((await _cred_row(app, mid, uid)).access_token, MASTER)


async def _set_cred_token_ct(app, mid, uid, plaintext):
    """直写凭证（模拟 upstream 侧已吊销的 stale token）：密文形态合法、上游不认。"""
    async with app.state.sessionmaker() as session:
        row = await _cred_row(app, mid, uid)
        row.access_token = encrypt_text(plaintext, MASTER)
        await session.commit()
    await invalidate_credential(app.state.redis, mid, uid)


async def test_injection_http_form_token_reaches_upstream(app):
    mid = await _create_oauth(f"{AS}/api")               # DCR 形态（http）
    await _bind(mid)
    token = await _cred_token(app, mid)
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        r = await c.get(f"{PROXY}/p/{mid}/orders?id=7", headers=U888)
    assert r.status_code == 200
    assert r.json()["headers"]["authorization"] == f"Bearer {token}"


async def test_injection_streamable_form_token_reaches_upstream(app):
    streamable_state["received"].clear()
    mid = await _setup_manual("http://127.0.0.1:9903/mcp", type_="mcp")
    await _bind(mid)
    token = await _cred_token(app, mid)
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        r = await c.post(f"{PROXY}/p/{mid}/mcp", json={
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18"}}, headers=U888)
    assert r.status_code == 200
    rec = streamable_state["received"][-1]
    assert rec["headers"]["authorization"] == f"Bearer {token}"   # 本人 token 到上游
    assert not any(v.startswith("stub.") for v in rec["headers"].values())  # JWT 不透传


async def test_injection_sse_form_token_reaches_upstream(app):
    mid = await _setup_manual("http://127.0.0.1:9902/sse", type_="mcp")
    await _bind(mid)
    token = await _cred_token(app, mid)
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        async with c.stream("GET", f"{PROXY}/p/{mid}/sse", headers=U888) as resp:
            assert resp.status_code == 200
            assert resp.headers["content-type"].startswith("text/event-stream")
            saw_endpoint = False
            async for line in resp.aiter_lines():
                if line.startswith("data:") and "/messages" in line:
                    saw_endpoint = True                   # endpoint 改写不受注入影响
                    break
    assert saw_endpoint
    assert mock_state["last_sse_headers"]["authorization"] == f"Bearer {token}"


async def test_unbound_call_401_with_authorize_guidance():
    mid = await _create_oauth(f"{AS}/api")
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        r = await c.get(f"{PROXY}/p/{mid}/orders", headers=U999)
    assert r.status_code == 401
    body = r.json()
    assert body["code"] == "OAUTH_BINDING_REQUIRED"
    assert f"/builtin-mappings/{mid}/authorize" in body["message"]  # body 附授权引导（§10）


async def test_invalid_status_call_401(app):
    mid = await _create_oauth(f"{AS}/api")
    await _bind(mid)
    async with app.state.sessionmaker() as session:
        row = (await session.execute(select(OAuthCredential).where(
            OAuthCredential.mapping_id == mid,
            OAuthCredential.uid == "u888"))).scalar_one()
        row.status = "invalid"
        await session.commit()
    await invalidate_credential(app.state.redis, mid, "u888")
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        r = await c.get(f"{PROXY}/p/{mid}/orders", headers=U888)
    assert r.status_code == 401 and r.json()["code"] == "OAUTH_BINDING_REQUIRED"


async def test_expired_refresh_single(app):
    """§14.5：expires_at - 60s 内即刷新（脚本化 expires_in=2 越线后首个请求触发；
    刷新签发的新 token 改回 3600，避免 60s skew 内二次刷新干扰计数）。"""
    as_state["expires_in"] = 2
    mid = await _create_oauth(f"{AS}/api")
    await _bind(mid)
    token1 = await _cred_token(app, mid)
    as_state["expires_in"] = 3600                         # 刷新签发的新 token 走正常有效期
    await asyncio.sleep(2.3)                              # 越过过期线（skew 60s 内）
    events_before = len(as_state["refresh_events"])
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        r1 = await c.get(f"{PROXY}/p/{mid}/orders", headers=U888)
        assert r1.status_code == 200
        assert len(as_state["refresh_events"]) == events_before + 1
        token2 = await _cred_token(app, mid)
        assert token2 != token1                           # 刷新后落库新 token
        r2 = await c.get(f"{PROXY}/p/{mid}/orders", headers=U888)
    assert r2.status_code == 200                          # 新 token 有效期内不再刷新
    assert len(as_state["refresh_events"]) == events_before + 1
    assert r2.json()["headers"]["authorization"] == f"Bearer {token2}"


async def test_concurrent_refresh_lock_single_flight(app):
    """并发刷新锁（§14.5）：6 并发请求越过过期线 → 仅 1 次 refresh（其余轮询等待
    新 token），全部 200 且带同一新 token。refresh_sleep=0.8 拉宽竞态窗口。"""
    as_state["refresh_sleep"] = 0.8
    as_state["expires_in"] = 2
    mid = await _create_oauth(f"{AS}/api")
    await _bind(mid)
    token1 = await _cred_token(app, mid)
    as_state["expires_in"] = 3600                         # 刷新签发的新 token 走正常有效期
    await asyncio.sleep(2.3)
    before = len(as_state["refresh_events"])
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        rs = await asyncio.gather(*[c.get(f"{PROXY}/p/{mid}/orders?i={i}", headers=U888)
                                    for i in range(6)])
    assert all(r.status_code == 200 for r in rs), [r.status_code for r in rs]
    assert len(as_state["refresh_events"]) == before + 1  # 锁防并发：仅一次刷新
    token2 = await _cred_token(app, mid)
    assert token2 != token1
    for r in rs:
        assert r.json()["headers"]["authorization"] == f"Bearer {token2}"
    as_state["refresh_sleep"] = 0.0


async def test_refresh_failure_marks_invalid_and_reauth_recovers(app):
    as_state["fail_refresh"] = True
    as_state["expires_in"] = 2
    mid = await _create_oauth(f"{AS}/api")
    await _bind(mid)
    as_state["expires_in"] = 3600                         # 恢复后签发的 token 走正常有效期
    await asyncio.sleep(2.3)
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        r = await c.get(f"{PROXY}/p/{mid}/orders", headers=U888)
    assert r.status_code == 401 and r.json()["code"] == "OAUTH_BINDING_REQUIRED"
    row = await _cred_row(app, mid)
    assert row.status == "invalid"                        # 刷新失败 → invalid（§14.4）
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        b = await c.get(f"{PROXY}/api/v1/builtin-mappings/{mid}/binding", headers=U888)
    assert b.json()["binding"] == "invalid"               # 状态机回告，页面引导重新授权
    # 重新授权恢复（upsert 复位 active）
    as_state["fail_refresh"] = False
    as_state["expires_in"] = 3600
    await _bind(mid)
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        r2 = await c.get(f"{PROXY}/p/{mid}/orders", headers=U888)
    assert r2.status_code == 200


async def test_builtin_test_bound_user_uses_own_credential(app):
    """§6.6：已绑定用户 test = 本人凭证执行对应 mcp 验证；uk 每用户一份互不串用。"""
    mid = await _setup_manual("http://127.0.0.1:9903/mcp-secure", type_="mcp")
    await _bind(mid)
    token = await _cred_token(app, mid)
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        r = await c.post(f"{PROXY}/api/v1/builtin-mappings/{mid}/test", headers=U888)
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True and body["status_code"] == 200   # 有效凭证 → initialize 通过
    assert secure_state["received"][-1]["headers"]["authorization"] == f"Bearer {token}"
    await _bind(mid, U999)                                # 第二用户独立绑定
    token999 = await _cred_token(app, mid, "u999")
    assert token999 != token
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        r999 = await c.post(f"{PROXY}/api/v1/builtin-mappings/{mid}/test", headers=U999)
    assert r999.json()["ok"] is True
    assert secure_state["received"][-1]["headers"]["authorization"] == f"Bearer {token999}"


async def test_builtin_test_stale_token_hints_reauth(app):
    """§6.6：凭证失效提示重新授权——stale token 被 /mcp-secure 拒绝（401 短路，
    不回落，M4 定稿），detail 追加「重新授权」提示。"""
    mid = await _setup_manual("http://127.0.0.1:9903/mcp-secure", type_="mcp")
    await _bind(mid)
    await _set_cred_token_ct(app, mid, "u888", "at-stale-revoked-000000")
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        r = await c.post(f"{PROXY}/api/v1/builtin-mappings/{mid}/test", headers=U888)
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is False and body["status_code"] == 401
    assert body["detail"].startswith("上游拒绝")           # 非 2xx 不回落（M4 语义）
    assert "重新授权" in body["detail"]


async def test_builtin_test_admin_static_no_injection():
    """admin 测静态配置（§6.5）：不注入本人凭证（secure 面 0 访问）。"""
    mid = await _setup_manual("http://127.0.0.1:9903/mcp", type_="mcp")
    secure_state["received"].clear()
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        r = await c.post(f"{PROXY}/api/v1/builtin-mappings/{mid}/test", headers=ADMIN)
    assert r.status_code == 200 and r.json()["ok"] is True
    assert secure_state["received"] == []


async def test_builtin_test_unbound_user_401():
    mid = await _setup_manual("http://127.0.0.1:9903/mcp-secure", type_="mcp")
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        r = await c.post(f"{PROXY}/api/v1/builtin-mappings/{mid}/test", headers=U999)
    assert r.status_code == 401 and r.json()["code"] == "OAUTH_BINDING_REQUIRED"
```

- [ ] **Step 2: 实现 credential.py 刷新与注入**

`src/agent_proxy/oauth/credential.py`：import 区改为（新增 asyncio / time / timezone / httpx / metrics / AppError 已有）：

```python
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import time
from datetime import datetime, timedelta, timezone

import httpx
from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import metrics
from ..errors import AppError
from ..models import OAuthCredential
```

模块常量区（`REFRESH_LOCK_TTL` 之后）追加：

```python
# 未抢到锁时等待他人刷新完成的上限（覆盖慢 token 端点）；0.1s 轮询 cred 缓存
REFRESH_WAIT_SECONDS = 8.0
_WAIT_POLL_INTERVAL = 0.1

# 审计 logger（刷新事件入审计，§14.6；与 middleware 的 per-request 审计同一 logger，
# action=oauth_refresh 区分，request_id 复用当前请求以便关联）
audit_log = logging.getLogger("agent_proxy.audit")
```

文件末尾追加（client 侧 helper 走**函数内延迟 import**——`client.py` 模块级 import 了本模块的加密函数，反向模块级 import 会成环；延迟 import 是断环的标准位置，非占位）：

```python
# ---------- 调用时凭证获取与刷新（§14.5） ----------


def binding_required(mapping_id: str) -> AppError:
    """§10：401 OAUTH_BINDING_REQUIRED，body 附授权引导信息。"""
    return AppError(401, "OAUTH_BINDING_REQUIRED",
                    f"未完成 OAuth 授权绑定或凭证已失效：请先 POST "
                    f"/api/v1/builtin-mappings/{mapping_id}/authorize 完成授权后重试")


def _parse_expires(value) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


async def get_callable_credential(session: AsyncSession, r, app_state,
                                  mapping_data: dict, uid: str, master_key: str,
                                  request_id: str = "") -> str:
    """调用时凭证获取（§14.5）：无 / invalid → 401 OAUTH_BINDING_REQUIRED；
    expires_at - 60s 内 → 刷新（Redis 锁防并发）→ 返回新 access；刷新失败 →
    status=invalid → 401。proxy 注入与 builtin test 共用本入口。"""
    mapping_id = mapping_data["mapping_id"]
    cred = await load_credential(session, r, mapping_id, uid)
    if cred is None or cred.get("status") != "active":
        raise binding_required(mapping_id)
    if not is_expired(_parse_expires(cred.get("expires_at"))):
        return decrypt_text(cred["access_token"], master_key)
    refreshed = await refresh_credential(session, r, app_state, mapping_data, uid,
                                         master_key, request_id)
    if refreshed is None:
        raise binding_required(mapping_id)
    return refreshed


async def refresh_credential(session: AsyncSession, r, app_state, mapping_data: dict,
                             uid: str, master_key: str,
                             request_id: str = "") -> str | None:
    """刷新互斥（§14.5）：抢锁成功者执行 refresh_token 换新（落库 + 失效缓存）；
    未抢到锁者轮询 cred（上限 8s）等他人刷新结果。锁 ap:lock:refresh:{mapping}:{uid}
    SET NX EX 30（§5.3；Redis 3.0 支持 SET NX EX）。返回新 access 或 None（→401）。"""
    mapping_id = mapping_data["mapping_id"]
    lock_key = refresh_lock_key(mapping_id, uid)
    try:
        acquired = await r.set(lock_key, request_id or "refresh", nx=True,
                               ex=REFRESH_LOCK_TTL)
    except Exception as exc:
        log.warning("刷新锁获取失败（按未抢到处理）: %s", exc)
        acquired = None
    if not acquired:
        return await _wait_for_others_refresh(session, r, mapping_id, uid, master_key)
    try:
        return await _do_refresh(session, r, app_state, mapping_data, uid,
                                 master_key, request_id)
    finally:
        try:
            await r.delete(lock_key)
        except Exception:
            pass


async def _wait_for_others_refresh(session: AsyncSession, r, mapping_id: str,
                                   uid: str, master_key: str) -> str | None:
    """锁被他人持有时轮询 cred：拿到非过期的 active token 即用；他人刷新失败
    （invalid）→ None；等待超时 → None（该请求 401，下一请求重试刷新）。"""
    deadline = time.monotonic() + REFRESH_WAIT_SECONDS
    while time.monotonic() < deadline:
        await asyncio.sleep(_WAIT_POLL_INTERVAL)
        cred = await load_credential(session, r, mapping_id, uid)
        if cred is not None and cred.get("status") != "active":
            return None
        if cred is not None and not is_expired(_parse_expires(cred.get("expires_at"))):
            return decrypt_text(cred["access_token"], master_key)
    return None


class _RefreshFailed(Exception):
    """token 端点业务失败（非 200 / 缺 access_token）。"""


async def _do_refresh(session: AsyncSession, r, app_state, mapping_data: dict,
                      uid: str, master_key: str, request_id: str = "") -> str | None:
    """持锁刷新：refresh_token 换新 → upsert 落库 + 失效缓存 + metrics/审计；
    失败 → mark_credential_invalid + {action="fail"} → None。"""
    from .client import build_token_request, load_client_row, _row_to_client
    from .discovery import DiscoveryError, discover_authorization_server, upstream_origin

    mapping_id = mapping_data["mapping_id"]
    cred = await load_credential(session, r, mapping_id, uid)
    if cred is None or not cred.get("refresh_token"):
        await mark_credential_invalid(session, r, mapping_id, uid)
        metrics.oauth_actions_total.labels(action="fail").inc()
        return None
    row = await load_client_row(session, mapping_id)
    client = _row_to_client(row, master_key) if row is not None else None
    token_url = client.get("token_url") if client else None
    try:
        if not token_url:
            # dcr 行两列留空（§5.3）：刷新时实时 discovery 取 token 端点
            meta = await discover_authorization_server(
                app_state.http_client, upstream_origin(mapping_data["upstream_url"]))
            token_url = meta["token_endpoint"]
        headers, form = build_token_request(
            client["token_auth"] if client else "client_secret_post",
            client_id=client["client_id"] if client else "",
            client_secret=client.get("client_secret") if client else None,
            extra={"grant_type": "refresh_token",
                   "refresh_token": decrypt_text(cred["refresh_token"], master_key)})
        resp = await app_state.http_client.post(token_url, data=form,
                                                headers=headers, timeout=15.0)
        if resp.status_code != 200:
            raise _RefreshFailed(f"status={resp.status_code}")
        tokens = resp.json()
        access = tokens.get("access_token")
        if not access:
            raise _RefreshFailed("响应缺少 access_token")
    except (httpx.HTTPError, ValueError, DiscoveryError, _RefreshFailed) as exc:
        await mark_credential_invalid(session, r, mapping_id, uid)
        metrics.oauth_actions_total.labels(action="fail").inc()
        # 日志只记 mapping/uid/异常类型——token 不入任何日志（§14.6）
        log.warning("OAuth 刷新失败 (%s/%s): %s", mapping_id, uid, type(exc).__name__)
        _audit_refresh(request_id, mapping_id, uid, ok=False)
        return None
    expires_at = expires_at_from(tokens.get("expires_in"))
    if tokens.get("refresh_token"):
        refresh_ct = encrypt_text(tokens["refresh_token"], master_key)   # AS 轮换则存新值
    else:
        refresh_ct = cred.get("refresh_token")           # 未轮换：保留原密文
    await save_credential(session, r, mapping_id, uid,
                          access_token_ct=encrypt_text(access, master_key),
                          refresh_token_ct=refresh_ct, expires_at=expires_at,
                          scope=tokens.get("scope"), master_key=master_key)
    metrics.oauth_actions_total.labels(action="refresh").inc()
    _audit_refresh(request_id, mapping_id, uid, ok=True)
    return access


def _audit_refresh(request_id: str, mapping_id: str, uid: str, ok: bool) -> None:
    """刷新入审计日志（§14.6）：复用当前请求 request_id 与中间件请求行关联；
    action=oauth_refresh 区分（测试按 action 过滤；无请求上下文时 request_id 空串）。"""
    audit_log.info(json.dumps({
        "ts": datetime.now(timezone.utc).astimezone().isoformat(timespec="milliseconds"),
        "request_id": request_id, "user_id": uid, "user_name": "",
        "action": "oauth_refresh", "mapping_id": mapping_id, "method": "", "path": "",
        "status": 200 if ok else 401, "duration_ms": 0, "bytes_in": 0, "bytes_out": 0,
        "client_ip": "",
    }, ensure_ascii=False))
```

- [ ] **Step 3: proxy.py 注入接线 + builtin.py test 路由**

`src/agent_proxy/api/proxy.py`：import 区追加 `from ..oauth import credential as oauth_credential`；`_handle_proxy` 整体替换为（分发段原样保留）：

```python
async def _handle_proxy(request: Request, mapping_id: str, identity: Identity,
                        settings: Settings) -> Response:
    # DB session 只包住 load_mapping 与 OAuth 凭证获取（M6）：不走 get_db 依赖——其
    # teardown 在响应发完才执行，SSE/长流会把连接占死（池 10 → ~20 并发即排队）。
    # load_mapping 返回脱管 dict（row_to_dict），session 早关安全。
    async with request.app.state.sessionmaker() as session:
        data = await load_mapping(session, request.app.state.redis, mapping_id,
                                  settings.cache_ttl)
        if data is None:
            raise AppError(404, "MAPPING_NOT_FOUND", "映射不存在")
        # 审计 mapping_id 对后续所有分支生效（含 403/禁用 404）
        request.state.mapping_id = mapping_id
        # metrics type 标签（§15.2 http/mcp；中间件回读 state）
        request.state.proxy_type = "mcp" if data["type"] == "mcp" else "http"
        if data["visibility"] == "private" and data["owner_uid"] != identity.user_id:
            raise AppError(403, "FORBIDDEN", "仅注册者可调用该映射")
        # visibility=public：任意有效身份放行（M6 内置映射场景；M3 数据中不出现 public 用户映射）
        if data["status"] != "active":
            raise AppError(404, "MAPPING_NOT_FOUND", "映射不存在或已禁用")
        if data["auth_mode"] == "oauth":
            # M6 按用户注入（§14.5）：查本人凭证（无/invalid → 401 OAUTH_BINDING_REQUIRED
            # 附授权引导）；expires_at-60s 内刷新（Redis 锁防并发）；出站
            # Authorization: Bearer <本人 access_token> 覆盖存储同名头——「仅还原注册者
            # header」的唯一例外（§14.1）。小写键与 build_outbound_headers 归一一致。
            # data 为本请求私有 dict（缓存 JSON 反序列化产物），写入不跨请求共享。
            token = await oauth_credential.get_callable_credential(
                session, request.app.state.redis, request.app.state, data,
                identity.user_id, settings.master_key, request.state.request_id)
            data = {**data, "upstream_headers": {**data["upstream_headers"],
                                                 "authorization": f"Bearer {token}"}}
    if data["type"] == "mcp":
        # （原 mcp 分发段逐字符保留——路径分发注释、sub_path 归一、SSE/origin 根
        # 分发逻辑均不变，见 Task 5 Step 1 的 M4 定稿注释）
        sub_path = split_sub_path(request.scope["path"], mapping_id)
        assert_safe_sub_path(sub_path)
        if request.method in ("GET", "HEAD") and \
                (sub_path or "/") == registered_endpoint_path(data["upstream_url"]):
            return await stream_sse_forward(request.app.state, data, request)
        target = build_origin_target(data["upstream_url"], sub_path, request.url.query)
        return await stream_http_forward(request.app.state, data, request,
                                         target_override=target, metrics_type="mcp")
    return await stream_http_forward(request.app.state, data, request)
```

（执行注意：函数体内原 mcp 分支的**全部注释**——「路径分发（§8.3 表…）」「M4 分发语义定稿…」「评审 Issue 2（M3）…」三段——必须原样保留，本步只移动了它的外层缩进边界（原本从 `if data is None` 起就在 session 块外，现在鉴权/注入段并入 session 块，分发段保持块外）。）

`src/agent_proxy/api/builtin.py`：import 区追加三行：

```python
from ..forward.http_forward import probe_http_mapping
from ..forward.mcp_streamable import probe_mcp_mapping
from ..oauth.credential import get_callable_credential
```

（`..oauth.credential` 组并入既有 import 行；schemas import 追加 `MappingTestOut`。）`unbind_mapping` 路由之后追加：

```python
@router.post("/{mapping_id}/test", response_model=MappingTestOut)
async def test_builtin_mapping(request: Request, mapping_id: str,
                               identity: Identity = Depends(get_current_identity),
                               session=Depends(get_db),
                               settings: Settings = Depends(get_settings)):
    """公共映射 test（§6.5 / §6.6）：admin 测静态配置（不注入）；其他用户必须已绑定，
    以本人凭证执行对应验证（mcp 走探测式 auto）。无凭证用户 → 401
    OAUTH_BINDING_REQUIRED（§6.6 安全边界）；上游以 401 拒绝 → ok=false + detail
    追加「重新授权」提示（探测语义沿 M4：非 2xx 不回落直接判失败）。"""
    data = await load_public_mapping(session, request.app.state.redis, mapping_id,
                                     settings.cache_ttl)
    request.state.audit_action = "test_mapping"
    request.state.mapping_id = mapping_id
    injected = False
    if is_admin(identity, settings.admin_role):
        probe_data = data                                 # admin：静态配置实测（不注入）
    else:
        token = await get_callable_credential(session, request.app.state.redis,
                                              request.app.state, data,
                                              identity.user_id, settings.master_key,
                                              request.state.request_id)
        probe_data = {**data, "upstream_headers": {**data["upstream_headers"],
                                                   "authorization": f"Bearer {token}"}}
        injected = True
    if probe_data["type"] == "mcp":
        result = await probe_mcp_mapping(request.app.state, probe_data)
    else:
        result = await probe_http_mapping(request.app.state, probe_data)
    if injected and not result["ok"] and result.get("status_code") == 401:
        result["detail"] += "（凭证可能已失效，请重新授权）"
    return result
```

- [ ] **Step 4: 运行预期**

Run: `.venv/Scripts/python.exe -m pytest tests/integration/test_oauth_injection.py -p no:cacheprovider -q`
Expected: 12 passed。实现前注入用例 FAIL（出站无 Authorization / 未绑定调用 200）。`test_concurrent_refresh_lock_single_flight` 经真实 TCP + mock AS refresh_sleep=0.8 钉住「6 并发仅 1 次 refresh」；两条 ~2.3s 级慢用例（过期越线）已标注。

Run: `.venv/Scripts/python.exe -m pytest -p no:cacheprovider -q`
Expected: 全部 PASS（约 **367** = 355 + 12，以实际为准）。既有转发全链路（echo/SSE/Streamable/encoding/trace）是 proxy.py 接线的回归面——static 映射零行为变化（`auth_mode` 默认 static，注入分支不触发）。

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(M6): 按用户凭证注入 + 过期自动刷新（Redis 锁防并发）+ builtin test 本人凭证/失效提示" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

### Task 7: 安全专项 + 设计文档注记回写（§5.3/§6.5/§10/§14.4）+ README + 全量回归

**Files:**
- New: `tests/integration/test_oauth_security.py`
- Modify: `docs/superpowers/specs/2026-11-21-agent-proxy-design.md`（四处注记回写）
- Modify: `README.md`（接口速览 + OAuth 联调说明）

- [ ] **Step 1: 写失败测试**

`tests/integration/test_oauth_security.py`（新文件）：

```python
"""OAuth 安全专项（§14.6 / §13 OAuth 行）。与 binding flow 的重放/伪造用例互补：
- state TTL 钉 600s + 过期（直删模拟）→ 400；
- front_redirect origin 精确匹配（scheme/端口变体拒绝，path/query 保留放行）；
- token / refresh_token / client_secret 落库全密文（明文不落库）；
- 签发 token、refresh token、client_secret、授权 code 不出现在任何日志文件；
- 权限矩阵正向面：非 admin 普通用户可对 admin 建的公共映射发起授权绑定。"""
import glob
import json
from urllib.parse import urlparse, parse_qs

from sqlalchemy import select

from agent_proxy.models import OAuthClient, OAuthCredential
from agent_proxy.oauth.credential import decrypt_text
from tests.utils import make_token

ADMIN = {"Authorization": f"Bearer {make_token('uadmin', 'admin')}"}
U888 = {"Authorization": f"Bearer {make_token('u888')}"}
FRONT = "http://testserver/console"
MASTER = "test-master-key"

CLIENT_BODY = {"client_id": "manual-cl", "client_secret": "manual-cs-123456",
               "token_auth": "client_secret_post",
               "authorize_url": "http://127.0.0.1:9904/oauth/authorize",
               "token_url": "http://127.0.0.1:9904/oauth/token", "scopes": "read"}


async def _setup_and_bind(client):
    created = (await client.post("/api/v1/mappings", json={
        "type": "http", "visibility": "public", "auth_mode": "oauth",
        "upstream_url": "http://10.0.0.5/api/v1", "headers": {}}, headers=ADMIN)).json()
    mid = created["mapping_id"]
    await client.put(f"/api/v1/builtin-mappings/{mid}/client", json=CLIENT_BODY,
                     headers=ADMIN)
    r = await client.post(f"/api/v1/builtin-mappings/{mid}/authorize",
                          json={"front_redirect": FRONT}, headers=U888)
    assert r.status_code == 200, r.text
    authz_url = r.json()["authorization_url"]
    import httpx
    async with httpx.AsyncClient() as browser:
        redir = await browser.get(authz_url, follow_redirects=False)
    assert redir.status_code == 302
    parsed = parse_qs(urlparse(authz_url).query)
    code_from_as = parse_qs(urlparse(redir.headers["location"]).query)["code"][0]
    return mid, parsed["state"][0], code_from_as


async def test_state_ttl_pinned_600(client, app):
    mid, state, _ = await _setup_and_bind(client)
    ttl = await app.state.redis.ttl(f"ap:oauth:state:{state}")
    assert 590 < ttl <= 601                               # OAUTH_STATE_TTL=600


async def test_state_expired_simulated_400(client, app):
    """过期语义：直删 state key 模拟 TTL 到期（600s 等不起）——与「伪造不存在」
    同一 400 分支（consume_state 未命中即 OAUTH_STATE_INVALID）。"""
    mid, state, code = await _setup_and_bind(client)
    await app.state.redis.delete(f"ap:oauth:state:{state}")
    resp = await client.get(f"/oauth/callback/{mid}?code={code}&state={state}",
                            follow_redirects=False)
    assert resp.status_code == 400
    assert resp.json()["code"] == "OAUTH_STATE_INVALID"


async def test_front_redirect_origin_exact_match(client):
    mid = (await client.post("/api/v1/mappings", json={
        "type": "http", "visibility": "public", "auth_mode": "oauth",
        "upstream_url": "http://10.0.0.5/api/v1", "headers": {}}, headers=ADMIN)).json()["mapping_id"]
    await client.put(f"/api/v1/builtin-mappings/{mid}/client", json=CLIENT_BODY,
                     headers=ADMIN)
    for bad in ("https://testserver/cb",                   # scheme 不同
                "http://testserver:8080/cb",               # 端口不同
                "http://evil.testserver/cb",               # 子域形似（netloc 精确比较）
                "http://testserver.evil.com/cb"):
        resp = await client.post(f"/api/v1/builtin-mappings/{mid}/authorize",
                                 json={"front_redirect": bad}, headers=U888)
        assert resp.status_code == 400 and resp.json()["code"] == "INVALID_PARAM"


async def test_all_secrets_ciphertext_at_rest(client, app):
    """§14.6 强制加密三面：client_secret + access_token + refresh_token 全密文。"""
    mid, _, _ = await _setup_and_bind(client)
    async with app.state.sessionmaker() as session:
        client_row = (await session.execute(
            select(OAuthClient).where(OAuthClient.mapping_id == mid))).scalar_one()
        cred_row = (await session.execute(
            select(OAuthCredential).where(
                OAuthCredential.mapping_id == mid))).scalar_one()
    assert client_row.client_secret.startswith("gAAAA")
    assert cred_row.access_token.startswith("gAAAA")
    assert cred_row.refresh_token.startswith("gAAAA")
    dump = f"{client_row.client_secret}{cred_row.access_token}{cred_row.refresh_token}"
    assert "manual-cs-123456" not in dump                 # 明文不落库
    assert decrypt_text(cred_row.access_token, MASTER).startswith("at-")


async def test_issued_secrets_absent_from_all_logs(client, app):
    """§14.6：token、client_secret 不入任何日志（trace/audit/运行日志全文件扫描）；
    授权 code 亦不得入日志（日志只记 path 不含 query）。"""
    mid, state, code = await _setup_and_bind(client)
    async with app.state.sessionmaker() as session:
        cred_row = (await session.execute(
            select(OAuthCredential).where(
                OAuthCredential.mapping_id == mid))).scalar_one()
    access = decrypt_text(cred_row.access_token, MASTER)
    refresh = decrypt_text(cred_row.refresh_token, MASTER)
    secrets_scan = (access, refresh, CLIENT_BODY["client_secret"], code, state)
    for path in glob.glob("logs-test/**/*.log*", recursive=True):
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        for secret in secrets_scan:
            assert secret not in text, f"{path} 泄漏敏感值（{secret[:6]}…）"


async def test_non_admin_user_can_authorize_admin_mapping(client):
    """§14.2 正向面：public 映射任意有效用户可发起授权绑定（admin 仅限创建/改删）。"""
    mid = (await client.post("/api/v1/mappings", json={
        "type": "http", "visibility": "public", "auth_mode": "oauth",
        "upstream_url": "http://10.0.0.5/api/v1", "headers": {}}, headers=ADMIN)).json()["mapping_id"]
    await client.put(f"/api/v1/builtin-mappings/{mid}/client", json=CLIENT_BODY,
                     headers=ADMIN)
    resp = await client.post(f"/api/v1/builtin-mappings/{mid}/authorize",
                             json={"front_redirect": FRONT}, headers=U888)
    assert resp.status_code == 200
    assert "authorization_url" in resp.json()
```

- [ ] **Step 2: 设计文档注记回写（四处）**

`docs/superpowers/specs/2026-11-21-agent-proxy-design.md`：

1. §5.3「Redis 扩展（M6）」表 `ap:lock:refresh` 行之后追加一行：

```markdown
| `ap:oauth:authz:{mapping_id}:{uid}` | 授权进行中索引（binding 查询的 authorizing 态判定；authorize 写入、回调成功 / 解绑删除），M6 实现增量 | 600s |
```

2. §6.5 接口表 `test` 行之前追加两行：

```markdown
| PUT | `/api/v1/builtin-mappings/{mapping_id}/client` | JWT + admin | OAuth 客户端手动配置（14.3 降级路径；client_secret 加密落库；重复 PUT 为 upsert，可将 dcr 配置覆盖为 manual） |
| GET | `/api/v1/builtin-mappings/{mapping_id}/client` | JWT + admin | 查看 OAuth 客户端配置（client_secret 只回是否已配置，永不回显值） |
```

3. §10 错误表 `OAUTH_BINDING_REQUIRED` 行之后追加四行：

```markdown
| OAuth state 无效 / 过期 / 重放 / 与回调路径不匹配 | 400 | `OAUTH_STATE_INVALID` |
| 对 static 公共映射发起 OAuth 语义操作（authorize / binding / client 配置） | 400 | `OAUTH_NOT_APPLICABLE` |
| OAuth 客户端未配置（查询缺配置 / 回调缺配置） | 400 | `OAUTH_CLIENT_NOT_CONFIGURED` |
| OAuth discovery / DCR 失败（body 提示管理员改用手动配置） | 502 | `OAUTH_CLIENT_SETUP_FAILED` |
```

4. §14.4 状态机段（「绑定状态机：…重新授权；用户可主动 DELETE 解绑…」）之后追加注记：

```markdown
> **代理实现注记（M6）**：state 一次性消费以 Redis MULTI 事务管道（GET+DEL）原子取删——兼容部署环境 Redis 3.0（无 `GETDEL` 命令；6.2+ 行为等价，实现机制在代码注释钉死）；`authorizing` 态判定依赖增量索引键 `ap:oauth:authz:{mapping_id}:{uid}`（§5.3 表已补）；刷新失败 → `invalid` 即调用 401，页面引导重新授权（upsert 重新授权复位 active）；manual 模式无 revoke 端点配置列，解绑仅删本地凭证，dcr 客户端经 discovery 取 `revocation_endpoint` 做 best-effort revoke。
```

- [ ] **Step 3: README 更新**

`README.md`：

1. 「接口速览」表 `resolve` 行之后追加：

```markdown
| GET | /api/v1/builtin-mappings | 内置（公共）映射列表：name/type/proxy_url/占位符 headers/auth_mode + 我的绑定状态（M6） |
| PUT/GET | /api/v1/builtin-mappings/{id}/client | OAuth 客户端手动配置 / 查看（仅 admin，secret 脱敏）（M6） |
| POST | /api/v1/builtin-mappings/{id}/authorize | 发起 OAuth 授权绑定：front_redirect 域白名单 → authorization_url（M6） |
| GET | /oauth/callback/{mapping_id} | OAuth 回调（无 JWT，一次性 state 关联；code 换 token 强制加密落库）（M6） |
| GET/DELETE | /api/v1/builtin-mappings/{id}/binding | 我的绑定状态查询 / 解绑（dcr 客户端 best-effort revoke）（M6） |
| POST | /api/v1/builtin-mappings/{id}/test | 公共映射测试：admin 测静态配置；已绑定用户测本人 OAuth 凭证（失效提示重新授权）（M6） |
```

2. 「接口速览」小节之前新增一节：

```markdown
## OAuth 凭证托管（M6）联调

见 `scripts/mock_oauth_as_server.py`（mock OAuth2 AS+RS，9904；preset 手动客户端
`manual-cl`/`manual-cs-123456`；`POST /_test/reset` 重置）。浏览器走全流程：

1. 管理员建公共映射：`POST /api/v1/mappings`（`visibility=public`、`auth_mode=oauth`，
   `.env` 需 `SSRF_ALLOW_PRIVATE=true`）；
2. 手动模式配 client：`PUT /api/v1/builtin-mappings/{id}/client`（authorize/token URL
   指向 9904），或留空走 DCR（上游须提供 well-known + registration_endpoint）；
3. `POST /api/v1/builtin-mappings/{id}/authorize`（`front_redirect` 须在
   `CORS_ALLOWED_ORIGINS` 白名单）→ 浏览器打开返回的 `authorization_url` 同意 →
   回调 302 回 `front_redirect?binding=success`；
4. `GET /api/v1/builtin-mappings/{id}/binding` 确认 `bound` 后，以任意绑定用户 JWT
   调 `/p/{id}/...`——代理按用户注入其 `Authorization: Bearer <本人 token>`。
```

- [ ] **Step 4: 全量回归 + 占位扫描**

Run: `.venv/Scripts/python.exe -m pytest tests/integration/test_oauth_security.py -p no:cacheprovider -q`
Expected: 6 passed。

Run: `.venv/Scripts/python.exe -m pytest -p no:cacheprovider -q`
Expected: 全部 PASS（约 **373** = 367 + 6，以实际为准）。特别确认：`ap_oauth_actions_total` 标签仅 action（bind/unbind/refresh/fail），无 user_id/mapping_id；trace.log / audit.log / 运行日志无 token / client_secret / code 明文（`test_issued_secrets_absent_from_all_logs` 全文件扫描钉住）。

Run: `grep -rn "TODO\|FIXME\|待实现\|NotImplementedError" src/agent_proxy/oauth/ src/agent_proxy/api/builtin.py src/agent_proxy/api/proxy.py src/agent_proxy/api/mgmt.py tests/integration/mock_oauth_as.py scripts/mock_oauth_as_server.py`
Expected: 无匹配（`ThirdPartyVerifier` 的既有 NotImplementedError 不在扫描范围；「占位符」为 placeholder 语义词不在词表）。

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "test(M6): 安全专项（state 过期/白名单精确匹配/全密文落库/日志零泄漏）+ 设计 §5.3/§6.5/§10/§14.4 注记回写 + README（M6 完成）" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

## M6 验收清单（对照设计 §16 M6 行 + §14 全章逐条）

- [ ] **§16 M6「mock AS 全流程：DCR/手动客户端 → 授权绑定 → 回调落库加密 → 按用户注入调用」**：
  - DCR：`test_dcr_registers_on_first_authorize_and_binds`（discovery 两步 → RFC 7591 注册 redirect_uris 精确单一值 → `source=dcr` 落库、两列留空）+ `test_dcr_injected_call_reaches_upstream_with_own_token`（http 形态 token 到上游 = 解密值）
  - 手动：`test_full_manual_flow_success_redirect_and_encrypted_storage`（preset client 全流程 + 302 回跳 success + 落库密文 + 解密 == AS 签发值）
  - 按用户注入三形态：`test_injection_http_form/streamable_form/sse_form_token_reaches_upstream`（echo / Streamable initialize / SSE 建连，本人 token 到上游、JWT 不透传）
- [ ] **§16 M6「未绑定 401」**：`test_unbound_call_401_with_authorize_guidance`（401 `OAUTH_BINDING_REQUIRED` + body 附 authorize 引导）+ `test_invalid_status_call_401`（invalid 同码）+ 解绑后 401（`test_unbind_revokes_and_401_afterwards`）
- [ ] **§16 M6「过期自动刷新」**：`test_expired_refresh_single`（expires_in=2 越线 → 单次刷新、新 token 落库且到上游）+ `test_refresh_failure_marks_invalid_and_reauth_recovers`（刷新失败 → invalid → 401 → 重新授权恢复）
- [ ] **§16 M6「并发刷新锁」**：`test_concurrent_refresh_lock_single_flight`（6 并发 1 次 refresh、全部 200 同一新 token；`ap:lock:refresh` SET NX EX 30）
- [ ] **§16 M6「非 admin 越权 403」**：public 创建/改删 403（既有 `test_create_public_requires_admin` + `test_create_public_oauth_admin_only_and_echoed`）；client 配置 403（`test_put_client_requires_admin`）
- [ ] **§14.1 三角色**：公共映射 admin 建（address 固定任意用户可调——注入用例以 u888/u999 非 admin 调用成功面）；用户绑定 (mapping_id, uid) 唯一（`test_rebind_upserts_single_credential_row`）；按用户注入 = 「仅还原注册者 header」唯一例外（代码注释 + 注入用例钉住）
- [ ] **§14.2 鉴权矩阵**：public 调用任意有效身份（既有 proxy 逻辑 + 注入用例）；public 详情/resolve/test 任意 admin 可见、普通用户 404（`test_public_detail_resolve_test_admin_bypass`）；public 改删任意 admin（`test_public_update_delete_by_any_admin`）；auth_mode 仅 public（`test_create_private_oauth_rejected_400` / `test_update_flip_oauth_public_to_private_400_and_static_ok`）；static 公共映射 OAuth 语义 400（`test_authorize_on_static_public_400` / `test_put_client_on_static_mapping_400`）
- [ ] **§14.3 DCR 优先 + 手动兼容**：DCR 首次授权自动注册（上引）；手动 PUT client（admin、upsert、可覆盖 dcr——`test_put_client_replaces_existing_row`）；discovery/DCR 失败 → 502 `OAUTH_CLIENT_SETUP_FAILED` + 提示手动（`test_authorize_without_client_dcr_setup_failed`）
- [ ] **§14.4 授权绑定流程**：authorize 返回 authorization_url（PKCE S256 参数齐——`test_authorization_url_shape_and_state_in_redis`）；state 一次性 600s 绑 uid（TTL 钉住 + 重放 400 + `consume_state` MULTI 原子取删）；回调 code+verifier 换 token → 加密落库 → 302 `front_redirect?binding=success`；AS 拒绝 → `binding=failed&reason=…`（`test_callback_as_error_redirects_failed`）；绑定状态机 unbound→authorizing→bound→invalid（`test_binding_authorizing_then_bound` / `test_refresh_failure_marks_invalid_and_reauth_recovers`）；解绑 + revoke best-effort（`test_unbind_revokes_and_401_afterwards`，revoke 到达 AS 且配对 refresh 连带作废）
- [ ] **§14.5 调用注入**：static → 静态 headers 还原（既有管线）；oauth → 查凭证 / 无·invalid 401 / expires_at-60s 刷新 / `Authorization: Bearer <该用户 token>` 覆盖同名头（小写键）；SSE 建连注入一次（SSE 用例）
- [ ] **§14.6 安全要点**：见下节逐条核对
- [ ] **§6.5 内置接口全量**：GET builtin-mappings（列表 + 占位符 headers + binding——`test_builtin_list_items_binding_and_masked_headers`）、authorize、callback、binding GET/DELETE、test（`test_builtin_test_bound_user_uses_own_credential` 本人凭证 / stale 失效提示重新授权 / admin 静态 / 未绑定 401）、client PUT/GET（admin、secret 脱敏）
- [ ] **§6.6 OAuth 绑定用户 test**：本人凭证执行 mcp 验证（`/mcp-secure` 上 ok=true）+ 凭证失效提示重新授权（401 短路 + detail 追加提示）
- [ ] **§15.2 指标**：`ap_oauth_actions_total{action}` bind/unbind 计数（`test_oauth_metrics_bind_unbind_counters`）+ refresh/fail（刷新用例路径）；标签基数受控（仅 action）
- [ ] **审计（§14.6）**：oauth_authorize / oauth_bind（uid 来自 state）/ oauth_unbind 审计动作 + oauth_refresh 事件行（复用 request_id、action 区分）
- [ ] **设计注记回写**：§5.3 authz 索引键 / §6.5 client 两接口 / §10 四错误码 / §14.4 MULTI+authz 注记（Task 7 Step 2）
- [ ] **全量回归**：`pytest` 全绿（约 373，基线 293 + 净增 ~80）
- [ ] **M6 不含**：M5 残余集成测试项 / 管理页面 / SSO / Prometheus 完善（M7 交付）

## 安全要点核对节（§14.6 逐条 → 落点）

| §14.6 条目 | 实现 | 测试落点 |
|---|---|---|
| PKCE(S256) 必须 | verifier 43 字符 base64url；challenge=BASE64URL(SHA256)；authorize 必带 | `test_pkce_s256_known_vector`（RFC 7636 官方向量）；`test_pkce_verifier_shape_and_randomness`；mock AS 无 PKCE 拒绝（`test_authorize_rejects_wrong_redirect_uri_and_missing_pkce`）+ 错 verifier 400（`test_token_pkce_wrong_verifier_rejected`） |
| state 一次性 / 600s / 绑 uid | Redis MULTI(GET+DEL) 原子取删；`SETEX 600`；载荷含 uid | `test_state_replay_rejected_400`；`test_state_ttl_pinned_600`；`test_state_expired_simulated_400`；`test_forged_state_400`；载荷含 uid（`test_authorization_url_shape_and_state_in_redis`） |
| redirect_uri 精确 = `{EXTERNAL_BASE}/oauth/callback/{mapping_id}` | `build_redirect_uri` 唯一构造点；DCR 注册与 token 交换同值 | `test_dcr_registers_on_first_authorize_and_binds`（注册 redirect_uris 精确断言）；跨映射伪造 400（`test_state_mapping_mismatch_400`） |
| token 强制加密落库（MASTER_KEY，不受 ENCRYPT_AT_REST 影响） | `encrypt_text` Fernet(SHA256(MASTER_KEY))；无 key fail-closed 500 | `test_save_stores_ciphertext_and_load_decrypts`；`test_encrypt_requires_master_key_fail_closed`；`test_all_secrets_ciphertext_at_rest`（client_secret+access+refresh 三面） |
| 回跳 front_redirect 仅 CORS_ALLOWED_ORIGINS 域 | authorize 时 origin 精确匹配（scheme+netloc），path/query 保留；空白名单 fail-closed | `test_front_redirect_whitelist_400`；`test_front_redirect_origin_exact_match`（scheme/端口/形似域变体）；`test_front_redirect_rejects_outside_whitelist` / `test_front_redirect_empty_whitelist_fail_closed`（单测） |
| token / client_secret 不入任何日志；绑定/解绑/刷新入审计 | oauth 模块日志只记类型名/状态码；全文件扫描；audit action=oauth_authorize/bind/unbind/refresh | `test_issued_secrets_absent_from_all_logs`（token/refresh/secret/code/state 五值全日志扫描）；审计动作由 middleware 既有断言面 + `_audit_refresh` 落盘 |
| （补充）回调无 JWT 防顶号 | 身份仅来自一次性 state（绑 uid），AS 回调无法指定受害者 | `test_full_manual_flow_success_redirect_and_encrypted_storage`（row.uid == 发起者）；重放/伪造系列 |

## M7 债务节（本计划明示移交）

1. **管理页面（M7）**：内置列表 / 授权跳转 / 绑定轮询 / 公共映射 CRUD / OAuth client 手动配置页面——全部 M6 API 已就位（`GET builtin-mappings` 的占位符 headers + binding 字段即页面保存所需全集）；页面直接消费，无需后端增量。
2. **`get_current_identity` Cookie 回退（M7）**：OAuth 回调天然无 JWT（state 关联），授权跳转需浏览器侧携带 JWT 的页面方案由 M7 会话体系统一解决。
3. **手动模式 revoke**：`proxy_oauth_client` 无 revocation_endpoint 列（§5.3 未定义），manual 解绑仅删本地凭证；若 M7 前需要，可加列或复用 token_url 同源约定——本计划不做（§14.4「提供方支持时」）。
4. **ENCRYPT_AT_REST（upstream_headers 可选加密）**：设计 §5.1/§9 项 6 仍为未实现债务，与 OAuth 凭证强制加密互不影响；M7+ 落地。
5. **cred 缓存竞态（明示接受）**：等待者在刷新者 DEL 缓存前把旧行写回缓存的窗口——60s TTL 兜底、下轮过期自愈；不引入版本号/分布式一致。
6. **discovery AS base SSRF**：AS base 来自上游元数据，代理不再对其做 SSRF 校验（upstream origin 注册期已校验；元数据指向属上游自身声明，与跨源重定向同一信任模型）——已写入 discovery.py docstring，如需收紧随二期。
7. **refresh 审计双行**：同一 request_id 在触发刷新的请求下会有中间件行 + oauth_refresh 行两条（action 区分）；若 M7 审计看板按 request_id 唯一聚合，需按 action 过滤。
8. **DCR 客户端失效**：AS 侧若丢掉 client 注册（重启清库等），代理侧 dcr 行已成孤儿 → authorize 时 AS 拒绝；处置为 admin PUT client 覆盖为 manual（upsert 已支持），自动化检测移交 M7+。
9. **delete_mapping 的 TTL 残留键（Task 4 评审携带批债务注记）**：映射删除连带清理 OAuth client/credential 行与 cred 缓存，但三类 TTL 自愈键不主动清理——`ap:oauth:state:*`（≤600s，state 载荷含已删 mapping_id，回调消费时 400 OAUTH_STATE_INVALID 兜底）、`ap:oauth:authz:{mapping_id}:{uid}`（≤600s，binding 查询先回源映射 404，残留无行为影响）、`ap:lock:refresh:{mapping_id}:{uid}`（≤30s，无凭证行后刷新路径不可达）。均有界自愈、无安全面泄漏（state 键值不含 token），不实现清理；如 M7 需要精确清键，随映射删除按前缀扫描。

## 自查记录（对照任务要求）

- **§14 全章逐条**：见上「M6 验收清单」与「安全要点核对节」映射行；§16 M6 验收行七要素（DCR/手动 → 绑定 → 加密落库 → 注入调用 → 未绑定 401 → 过期刷新 → 越权 403）各有具名用例。
- **签名一致性**：`is_admin(identity, settings.admin_role)`、`Settings.master_key / oauth_state_ttl / cors_allowed_origins / external_base / ssrf_allow_private` 均为 config 既有字段（零新增配置项）；`get_callable_credential` 注入值以**小写键** `"authorization"` 写入 `upstream_headers`（`build_outbound_headers` 全小写归一，同名必然覆盖为一行）；`probe_http_mapping / probe_mcp_mapping(app_state, mapping_data)` 签名按现有代码调用；`metrics.oauth_actions_total.labels(action=...)` 与 M1 已定义的 Counter 一致；`row_to_dict` / `load_mapping` / `build_proxy_url` / `placeholder.mask_headers` 复用未改语义；services 新参数（`auth_mode` / `admin_override`）全部带默认值，既有调用（test_services / mgmt）零破坏。
- **Redis 3.0 兼容**：`GETDEL` 不可用已实测，state 一次性消费钉死 MULTI 事务管道；`SET NX EX` 可用已实测；决策 1 + credential.py 模块注记 + 设计 §14.4 注记三处钉死。
- **无占位**：全部代码块为最终形态；每任务「运行预期」给出实现前 FAIL 面；迁移用例给出整条替换文本；慢用例（~2.3s 过期越线 ×2、并发 refresh_sleep 0.8）已显式标注。
- **端口簿**：9901 echo、9902 SSE mock、9903 Streamable mock（+`/mcp-secure`）、**9904 mock OAuth AS+RS（新）**、9909 死端口、9910 被测代理——与 conftest/脚本/README 一致。
- **预期计数**：293 → 约 373（Task1 +24 / Task2 +11 / Task3 +11 / Task4 +13 / Task5 +4 / Task6 +12 / Task7 +6），各任务「运行预期」以实际为准；执行者遇计数偏差应核对用例清单而非放宽断言。
- **范围纪律**：M5 残余不在本计划；M7 移交项全部落在债务节（页面 / Cookie 会话 / manual revoke / ENCRYPT_AT_REST / DCR 孤儿检测）。







