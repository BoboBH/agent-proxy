"""Mock OAuth2 AS+RS（集成测试 / 联调共用）：监听 127.0.0.1:9904（设计 §14）。

Authorization Server 端点：
- GET /.well-known/oauth-protected-resource   RFC 9728（authorization_servers=[本源]）
- GET /.well-known/oauth-authorization-server RFC 8414 元数据
- POST /oauth/register                        DCR（RFC 7591）——记录请求并签发 client
- GET  /oauth/authorize                       校验 client/redirect_uri/PKCE(S256 必须)
                                              → 签发一次性 code → 302 redirect_uri?code&state
- POST /oauth/token                           authorization_code（code 一次性 + 绑定签发
                                              client + PKCE 校验 + client 认证 basic/post）
                                              与 refresh_token（rt 绑定归属 client_id）
- POST /oauth/revoke                          RFC 7009（客户端认证门同 token 端点：
                                              basic/post/none；凭证记入 revocations；
                                              access 吊销连带配对 refresh 作废）

Resource Server 端点（http 形态注入验证面）：
- ANY /api[/{path}]                           echo（method/headers/query 原样返回）

脚本化行为（模块级 as_state，测试直读/直写）：
- expires_in / token_sleep / refresh_sleep / fail_refresh 可控（过期刷新与并发锁用例）；
  refresh_status >0 → 刷新返回该状态码、refresh_payload 非 None → 刷新返回该载荷
  （评审 Important 2 / Minor c：瞬时失败与畸形响应分级用例）；
- registrations / issued / refresh_events / revocations 记录断言面；
- preset 客户端 manual-cl / manual-cs-123456（手动模式用例）：redirect_uris 未注册
  （None），按回调前缀白名单放行——同一 9904 被 ASGI（testserver）与真实 TCP（9910）
  两套夹具共享，前缀白名单 = {"http://127.0.0.1:9910/oauth/callback/",
  "http://testserver/oauth/callback/"}；DCR 客户端仍按注册 redirect_uris 精确匹配；
- POST /_test/reset 重置动态状态（conftest autouse 夹具每个集成测试前调用）；
- 签发的 access token 同步登记 mock_mcp_streamable.secure_state["valid_tokens"]
  （9903 /mcp-secure 的 token 校验面），吊销时移除。

与真实提供方的已知偏离（测试确定性优先）：_issue 每次签发（授权码与刷新均是）
都返回**新的** refresh_token（轮换形态，代理按「响应含 rt 即存新值」落库），
但旧 rt 不作废——真实提供方通常轮换后即失效旧值，此处保留旧值只为降低用例间
耦合（旧 rt 可复用性不得被测试依赖，绑定/刷新用例始终直读最新签发值）；
authorize 不渲染同意页（校验通过即视为"同意"）。

注意：独立入口（python -m mocks.oauth_as）换端口联调时，本模块 BASE /
_PRESET_REDIRECT_PREFIXES / well-known 元数据 URL 不随动——独立入口仅用于 9904
标准端口的浏览器联调；端口改配属联调时手工改本文件常量的场景。
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import secrets
from urllib.parse import parse_qsl, urlencode

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse

from mocks.mcp_streamable import secure_state

BASE = "http://127.0.0.1:9904"
PRESET_CLIENT_ID = "manual-cl"
PRESET_CLIENT_SECRET = "manual-cs-123456"
_PRESET_REDIRECT_PREFIXES = ("http://127.0.0.1:9910/oauth/callback/",
                             "http://testserver/oauth/callback/")


async def _form(request: Request) -> dict[str, str]:
    """token/revoke 端点表单解析（RFC 6749：application/x-www-form-urlencoded）。

    与计划原稿的偏离（实测必要）：starlette 的 request.form() 在本版本强依赖
    python-multipart（未安装即 AssertionError），而计划钉死「无新增依赖」——
    改用 parse_qsl 直解 body（httpx data= 发出的正是 urlencoded 形态，语义一致）。
    """
    body = (await request.body()).decode("utf-8")
    return dict(parse_qsl(body, keep_blank_values=True))


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
        "refresh_status": 0,      # 评审 Important 2：>0 → 刷新返回该状态码（503/429 瞬时失败）
        "refresh_payload": None,  # 评审 Minor c：非 None → 刷新返回该载荷（非 dict JSON 畸形）
        # 精修批评审 Important 1/2：超长载荷脚本位——密文超出列上限（1406）语义用例
        "oversize_token": False,  # True → access_token 4000 字符（Fernet 后 ~5.4KB > 4096）
        "oversize_secret": False, # True → DCR 下发 client_secret 600 字符（密文 > 512）
    }


as_state = _fresh_state()


def build_oauth_as_app() -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.post("/_test/reset")
    async def reset():
        as_state.clear()
        as_state.update(_fresh_state())
        secure_state["valid_tokens"].clear()
        secure_state["received"].clear()   # 9903 /mcp-secure 记录面一并复位（Task 2 评审携带）
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
            # oversize_secret：模拟提供方下发异常超长 secret（落库 1406 面）
            secret = (("cs-" + "x" * 600) if as_state["oversize_secret"]
                      else f"cs-{secrets.token_hex(16)}")
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
        # RFC 7591 §3.2.1：注册成功 = 201 Created（评审 Critical 1：钉住真实提供方
        # 行为——Keycloak/Okta/Auth0 均回 201；代理兼容 200/201 两态）
        return JSONResponse(out, status_code=201)

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
        # oversize_token：模拟提供方下发异常超大 access token（落库 1406 面）
        access = (("at-" + "x" * 4000) if as_state["oversize_token"]
                  else f"at-{secrets.token_hex(16)}")
        refresh = f"rt-{secrets.token_hex(16)}"
        as_state["refresh_tokens"][refresh] = client_id
        as_state["issued"].append({"grant": grant, "client_id": client_id,
                                   "access_token": access, "refresh_token": refresh,
                                   "expires_in": as_state["expires_in"], "scope": scope})
        secure_state["valid_tokens"].add(access)    # 9903 /mcp-secure 校验面
        return JSONResponse({"access_token": access, "token_type": "Bearer",
                             "expires_in": as_state["expires_in"],
                             "refresh_token": refresh, "scope": scope})

    async def _authenticate_client(request: Request, form: dict[str, str]):
        """token/revoke 共用客户端认证门（RFC 6749 §2.3.1 同构，Task 2 评审携带）：
        - Basic 头覆盖 form 凭证（与代理 build_token_request 对应）；
        - client 必须存在；secret 非 None 的客户端必须凭证匹配（basic/post 形态）；
          secret 为 None（token_endpoint_auth_method=none 公共客户端）仅认 client_id。
        返回 (client_id, presented_secret, client, client_auth, error_response)：
        error_response 非 None 即认证失败（401 invalid_client），其余值无意义；
        client_auth ∈ basic/post/none 为请求实际采用的凭证形态。"""
        client_id = str(form.get("client_id") or "")
        client_secret = form.get("client_secret")
        authz = request.headers.get("authorization", "")
        client_auth = "post" if client_secret is not None else "none"
        if authz.startswith("Basic "):
            client_auth = "basic"
            try:
                decoded = base64.b64decode(authz[6:].strip()).decode("utf-8")
                client_id, _, basic_secret = decoded.partition(":")
                client_secret = basic_secret
            except Exception:
                return (client_id, client_secret, None, client_auth,
                        JSONResponse({"error": "invalid_client"}, status_code=401))
        client = as_state["clients"].get(client_id)
        if client is None or (client["client_secret"] is not None
                              and client_secret != client["client_secret"]):
            return (client_id, client_secret, None, client_auth,
                    JSONResponse({"error": "invalid_client"}, status_code=401))
        return client_id, client_secret, client, client_auth, None

    @app.post("/oauth/token")
    async def token(request: Request):
        form = await _form(request)
        client_id, _, client, client_auth, err = await _authenticate_client(request, form)
        if err is not None:
            return err
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
            # rt 绑定校验（Task 2 评审携带）：rt 必须属于请求 client_id（.get 比对
            # 同时覆盖不存在与跨客户端盗用两种形态）
            if (as_state["refresh_tokens"].get(rt) != client_id
                    or rt in as_state["revoked_refresh"]):
                return JSONResponse({"error": "invalid_grant"}, status_code=400)
            if as_state["refresh_status"]:          # 脚本化瞬时失败（评审 Important 2）
                return JSONResponse({"error": "temporarily_unavailable"},
                                    status_code=as_state["refresh_status"])
            if as_state["refresh_payload"] is not None:  # 脚本化畸形响应（评审 Minor c）
                return JSONResponse(as_state["refresh_payload"], status_code=200)
            if as_state["refresh_sleep"]:           # 并发刷新锁用例的竞态窗口
                await asyncio.sleep(as_state["refresh_sleep"])
            # client_auth 记录面（终审遗留 6）：manual client_secret_basic 过期刷新
            # e2e 据此断言 refresh 请求确实走了 Basic 认证门
            as_state["refresh_events"].append({"refresh_token": rt, "client_id": client_id,
                                               "client_auth": client_auth})
            return await _issue(client_id, str(form.get("scope") or ""), grant)
        return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)

    @app.post("/oauth/revoke")
    async def revoke(request: Request):
        form = await _form(request)
        client_id, client_secret, _, client_auth, err = await _authenticate_client(
            request, form)
        if err is not None:
            return err
        tok = str(form.get("token") or "")
        # 凭证记入 revocations：Task 5 断言「凭证确实随 revoke 发出」的断言面
        as_state["revocations"].append({"token": tok,
                                        "hint": form.get("token_type_hint"),
                                        "client_id": client_id,
                                        "client_secret": client_secret,
                                        "client_auth": client_auth})
        secure_state["valid_tokens"].discard(tok)
        # access 吊销连带配对 refresh 作废（按签发记录回查）；直接吊销 rt 形态亦支持
        # （RFC 7009 §2.1：吊销任一 token 连带同对另一枚作废）
        as_state["refresh_tokens"].pop(tok, None)
        for item in as_state["issued"]:
            if item["access_token"] == tok:
                as_state["revoked_refresh"].append(item["refresh_token"])
            if item["refresh_token"] == tok:
                secure_state["valid_tokens"].discard(item["access_token"])
        return Response(status_code=200)

    @app.api_route("/api", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
    @app.api_route("/api/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
    async def rs_echo(request: Request, path: str = ""):
        # RS echo：按用户注入断言面（headers 为小写键——uvicorn/h11 归一）
        return {"path": "/" + path, "method": request.method,
                "query": dict(request.query_params.items()),
                "headers": dict(request.headers.items())}

    return app


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="mock OAuth2 AS+RS（OAuth 绑定联调用）")
    parser.add_argument("--port", type=int, default=9904,
                        help="监听端口（默认 9904）")
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    import uvicorn
    uvicorn.run(build_oauth_as_app(), host="127.0.0.1", port=args.port,
                log_level="info", access_log=False)
