"""
cloudshell_adk_idjag_sdk.py — ADK agent: Smart Triage (ID-JAG) + GitHub (STS), both via SDK.

Two Okta resource connections for the same AI agent (wlp10mv0rrvI9zG9M1d8), both
driven through Okta's okta-client-python SDK and both starting from the same
Agentspace access token (subject_token_type = access_token):

  1. Smart Triage  — Cross-App Access / ID-JAG, via CrossAppAccessFlow
                     (start() = access_token->ID-JAG, resume() = ID-JAG->resource token).
  2. GitHub MCP    — Okta STS / brokered consent, a single RFC 8693 token exchange
                     (requested_token_type = urn:okta:params:oauth:token-type:oauth-sts).
                     Done with manual httpx: CONFIRMED (2026-07-07) that the SDK's
                     TokenExchangeFlow parses the error to OAuth2Error keeping only
                     error/error_description and DROPS Okta's non-standard interaction_uri
                     (additional_fields = {}). Manual httpx reads the full JSON body so we
                     can surface that sts/redirect consent link to the user.

Each resource gets its own token store and its own MCP toolset (own Bearer header).

GitHub consent (brokered): if the STS exchange signals interaction_required, the
interaction_uri (https://.../v1/sts/redirect?...) is pulled from
OAuth2Error.additional_fields; the instruction provider surfaces it as a clickable
"Authorize GitHub" link and waits. Once consent exists the same exchange returns the
GitHub access_token used as Bearer to the GitHub MCP.

Config is read at runtime via _cfg() (from .env locally, env_vars on the worker).

Integration notes (verify on first redeploy)
---------------------------------------------
* Async bridge: the SDK is async but ADK calls our hooks synchronously inside a
  running loop, so SDK coroutines run in a fresh thread (see _run_async).
* PEM: LocalKeyProvider loads the key for the SDK (Smart Triage); the GitHub STS
  client assertion is signed with PyJWT (sync).
* Org-AS issuer/client for the SDK is built by _org_oauth_client() (OKTA_ORG_ISSUER,
  default OKTA_DOMAIN); GitHub httpx posts directly to {ORG}/oauth2/v1/token.
* GitHub tools/list tolerates 401 pre-consent (returns no tools until authorized).

Prerequisites
-------------
    pip install google-adk google-cloud-aiplatform[adk,reasoningengine] \
        mcp httpx okta-client-python cryptography pyjwt python-dotenv
"""

import asyncio
import base64
import json
import os
import re
import sys
import tempfile
import threading
import time
import uuid
from typing import Any, Optional

import httpx
import jwt as pyjwt
from dotenv import load_dotenv
import vertexai
from google.adk.agents.llm_agent import LlmAgent
from google.adk.tools.mcp_tool.mcp_toolset import McpToolset, StreamableHTTPConnectionParams
from google.adk.agents.readonly_context import ReadonlyContext
from google.adk.tools.tool_context import ToolContext
from vertexai import agent_engines
from vertexai.agent_engines import AdkApp

# Okta SDK (installed on the deployed worker via requirements; not needed for py_compile).
from okta_client.authfoundation import (
    OAuth2Client,
    OAuth2ClientConfiguration,
    LocalKeyProvider,
)
from okta_client.authfoundation.oauth2.jwt_bearer_claims import JWTBearerClaims
from okta_client.authfoundation.oauth2.client_authorization import ClientAssertionAuthorization
from okta_client.oauth2auth import CrossAppAccessFlow, CrossAppAccessTarget

load_dotenv()

# ── Google Cloud ───────────────────────────────────────────────────────────────

PROJECT  = os.getenv("GCP_PROJECT",  "project")
LOCATION = os.getenv("GCP_LOCATION", "us-central1")
BUCKET   = os.getenv("GCP_BUCKET",   "gs://project-adk-staging")

vertexai.init(project=PROJECT, location=LOCATION, staging_bucket=BUCKET)

# ── Configuration ──────────────────────────────────────────────────────────────

_CFG_KEYS = (
    "OKTA_DOMAIN",              # e.g. https://acme.okta.com
    "OKTA_ORG_ISSUER",          # optional Org-AS issuer for the SDK (default: OKTA_DOMAIN)
    "IDJAG_AUDIENCE",           # Custom resource AS issuer: {ORG}/oauth2/{RESOURCE_AUTHZ_SERVER}
    "RESOURCE_AUTHZ_SERVER",    # Custom AS resource authz server id
    "IDJAG_SCOPES",             # e.g. mcp:read
    "AT_AI_AGENT_ID",           # iss/sub of the client assertion (agent identity)
    "AT_AGENT_PRIVATE_KEY_ID",  # kid of the signing key
    "AT_AGENT_PRIVATE_KEY_PEM", # RSA private key (PEM) used to sign the client assertion
    "SMARTTRIAGE_MCP_URL",      # Custom MCP endpoint
    "GITHUB_MCP_URL",           # GitHub MCP endpoint
    "GITHUB_RESOURCE_ORN",      # Okta resource ORN for the GitHub STS exchange (resource=)
)

DEFAULT_SMARTTRIAGE_MCP_URL = os.getenv("SMARTTRIAGE_MCP_URL", "https://custom-mcp-server.com/mcp")
DEFAULT_GITHUB_MCP_URL      = os.getenv("GITHUB_MCP_URL", "https://api.githubcopilot.com/mcp")

# auth_id prefix registered in Agentspace config; matches any suffix.
AUTH_ID_PREFIX = os.getenv("AUTH_ID_PREFIX", "okta-authorization_native")


def _cfg(key: str, default: str = "") -> str:
    """Read a config value from the environment at call time."""
    return os.getenv(key, default)


def _private_key_pem() -> str:
    """Return the agent's RSA private key, normalizing escaped newlines."""
    return (
        _cfg("AT_AGENT_PRIVATE_KEY_PEM")
        .replace("\\r\\n", "\n")
        .replace("\\n", "\n")
        .replace("\r", "")
        .strip()
    )


# ── Schema sanitizer ──────────────────────────────────────────────────────────
#
# Gemini API requires all `enum` values to be strings (TYPE_STRING). Some MCP
# tool schemas use boolean enums (e.g. `"enum": [true, false]`), which causes
# a 400 INVALID_ARGUMENT. We walk the schema and coerce them to strings.

def _sanitize_json_schema(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {
            k: (
                [str(v) if not isinstance(v, str) else v for v in val]
                if k == "enum" and isinstance(val, list)
                else _sanitize_json_schema(val)
            )
            for k, val in obj.items()
        }
    if isinstance(obj, list):
        return [_sanitize_json_schema(i) for i in obj]
    return obj


def _patch_mcp_tool_schema(tool: Any) -> None:
    """Sanitize a tool's schema in place — tries the known ADK attribute paths."""
    mcp_tool = getattr(tool, "_mcp_tool", None)
    if mcp_tool is not None and isinstance(getattr(mcp_tool, "inputSchema", None), dict):
        mcp_tool.inputSchema = _sanitize_json_schema(mcp_tool.inputSchema)

    for fd_attr in ("_function_declaration", "function_declaration"):
        fd = getattr(tool, fd_attr, None)
        if fd is None:
            continue
        for p_attr in ("parameters", "_parameters"):
            params = getattr(fd, p_attr, None)
            if isinstance(params, dict):
                setattr(fd, p_attr, _sanitize_json_schema(params))
                break


class SanitizingMcpToolset(McpToolset):
    """McpToolset that coerces non-string enum values to strings before Gemini sees them."""

    async def get_tools(self, *args, **kwargs):
        tools = await super().get_tools(*args, **kwargs)
        for tool in tools or []:
            try:
                _patch_mcp_tool_schema(tool)
            except Exception as exc:
                print(
                    f"[idjag-sdk] schema sanitize failed for {getattr(tool, 'name', '?')}: {exc}",
                    file=sys.stderr, flush=True,
                )
        return tools


class TolerantGitHubMcpToolset(SanitizingMcpToolset):
    """GitHub MCP toolset that tolerates a pre-consent 401 on tools/list: returns
    no tools until the user authorizes (so Smart Triage still loads). GitHub tools
    appear on a later session once _gh_token_store holds a token."""

    async def get_tools(self, *args, **kwargs):
        try:
            return await super().get_tools(*args, **kwargs)
        except Exception as exc:
            print(f"[idjag-sdk] GitHub tools/list unavailable (likely no consent yet): {exc}",
                  file=sys.stderr, flush=True)
            return []


# ── Token lookup helper ────────────────────────────────────────────────────────

def _as_dict(state: Any) -> dict:
    """Convert an ADK State object or plain dict to a regular dict."""
    if not state:
        return {}
    if isinstance(state, dict):
        return state
    try:
        return dict(state)
    except Exception:
        pass
    for attr in ("_data", "_delta", "_value", "_state", "_session_state"):
        raw = getattr(state, attr, None)
        if isinstance(raw, dict):
            return raw
    if hasattr(state, "model_dump"):
        try:
            return state.model_dump()
        except Exception:
            pass
    try:
        return {k: v for k, v in vars(state).items() if not k.startswith("_")}
    except Exception:
        return {}


def _find_token(state: Any) -> tuple[Optional[str], Optional[str]]:
    """Return (token, matched_key) for the first state entry whose key starts
    with AUTH_ID_PREFIX. Returns (None, None) if not found."""
    for k, v in _as_dict(state).items():
        if k.startswith(AUTH_ID_PREFIX) and v:
            return v, k
    return None, None


def _decode_jwt_noverify(token: str) -> dict:
    """Decode a JWT payload without verifying the signature (diagnostics only)."""
    try:
        seg = token.split(".")[1]
        seg += "=" * (-len(seg) % 4)
        return json.loads(base64.urlsafe_b64decode(seg).decode())
    except Exception:
        return {}


def _make_agent_assertion(token_endpoint: str) -> str:
    """private_key_jwt client assertion (PyJWT, sync) for the manual GitHub STS
    exchange. iss=sub=AT_AI_AGENT_ID, aud=<token endpoint>, 5-min exp, RS256.
    (Smart Triage's assertion is handled by the SDK's key_provider.)"""
    now = int(time.time())
    agent_id = _cfg("AT_AI_AGENT_ID")
    payload = {
        "iss": agent_id,
        "sub": agent_id,
        "aud": token_endpoint,
        "iat": now,
        "exp": now + 300,
        "jti": str(uuid.uuid4()),
    }
    return pyjwt.encode(
        payload,
        _private_key_pem(),
        algorithm="RS256",
        headers={"kid": _cfg("AT_AGENT_PRIVATE_KEY_ID"), "typ": "jwt"},
    )


# ── Trace logging ────────────────────────────────────────────────────────────

_REDACT_KEYS = {
    "client_assertion", "subject_token", "assertion", "client_secret",
    "access_token", "id_token", "refresh_token", "token",
}


def _redact(d: Any) -> Any:
    if not isinstance(d, dict):
        return d
    return {
        k: (f"<{k}: {len(str(v))} chars>" if k in _REDACT_KEYS and v else v)
        for k, v in d.items()
    }


def _log_step(label: str, req: Any = None, status: Any = None, resp: Any = None) -> None:
    """Emit one exchange trace step to stderr (Cloud Logging), redacting secrets."""
    print(f"[idjag-sdk] {label}", file=sys.stderr, flush=True)
    if req is not None:
        print(f"[idjag-sdk]     req : {json.dumps(_redact(req))}", file=sys.stderr, flush=True)
    if status is not None:
        body = _redact(resp) if isinstance(resp, dict) else resp
        try:
            body_str = json.dumps(body) if isinstance(body, dict) else str(body)[:400]
        except Exception:
            body_str = str(body)[:400]
        print(f"[idjag-sdk]     resp[{status}] : {body_str}", file=sys.stderr, flush=True)


# ── Async bridge + key provider + shared Org-AS client ─────────────────────────

def _run_async(coro_factory):
    """Run an async coroutine from sync code that is itself inside a running event
    loop (ADK's), using a fresh thread + asyncio.run so we never call asyncio.run()
    on an already-running loop."""
    box: dict = {}

    def runner():
        try:
            box["result"] = asyncio.run(coro_factory())
        except BaseException as exc:  # noqa: BLE001 — re-raised on the caller thread
            box["error"] = exc

    t = threading.Thread(target=runner, daemon=True)
    t.start()
    t.join()
    if "error" in box:
        raise box["error"]
    return box.get("result")


_key_provider_cache: dict = {}


def _key_provider():
    """Build a LocalKeyProvider from the PEM env var (cached). Prefers an in-memory
    loader; falls back to a temp .pem file if only from_pem_file is available."""
    kp = _key_provider_cache.get("kp")
    if kp is not None:
        return kp

    pem = _private_key_pem()
    kid = _cfg("AT_AGENT_PRIVATE_KEY_ID")

    for meth in ("from_pem", "from_pem_string", "from_pem_data"):
        fn = getattr(LocalKeyProvider, meth, None)
        if callable(fn):
            try:
                kp = fn(pem, algorithm="RS256", key_id=kid)
                break
            except Exception:
                kp = None

    if kp is None:
        fd, path = tempfile.mkstemp(suffix=".pem")
        with os.fdopen(fd, "w") as f:
            f.write(pem)
        kp = LocalKeyProvider.from_pem_file(path, algorithm="RS256", key_id=kid)

    _key_provider_cache["kp"] = kp
    return kp


def _org_oauth_client():
    """OAuth2Client for the Okta Org AS, authenticated with the agent's
    private_key_jwt client assertion (SDK-signed via key_provider). Shared by the
    Smart Triage ID-JAG flow and the GitHub STS token exchange."""
    okta = _cfg("OKTA_DOMAIN").rstrip("/")
    org_issuer = _cfg("OKTA_ORG_ISSUER", okta)      # verify on redeploy
    org_token_ep = f"{okta}/oauth2/v1/token"
    agent_id = _cfg("AT_AI_AGENT_ID")
    config = OAuth2ClientConfiguration(
        issuer=org_issuer,
        client_authorization=ClientAssertionAuthorization(
            assertion_claims=JWTBearerClaims(
                issuer=agent_id, subject=agent_id,
                audience=org_token_ep, expires_in=300,
            ),
            key_provider=_key_provider(),
        ),
    )
    return OAuth2Client(configuration=config)


# ── Smart Triage: ID-JAG via okta-client-python CrossAppAccessFlow ─────────────

def _exchange_for_resource_token(user_access_token: str) -> tuple[str, int]:
    """STEP3 (start: access_token -> ID-JAG) + STEP4 (resume: ID-JAG -> resource
    token) via the SDK. Returns (resource_token, exp_epoch); ("", 0) on failure."""
    okta = _cfg("OKTA_DOMAIN").rstrip("/")
    if not okta or not user_access_token:
        _log_step("SmartTriage: missing OKTA_DOMAIN or access token; skipping", status="skip")
        return "", 0

    _sc = _decode_jwt_noverify(user_access_token)
    _log_step("STEP1/2 (Agentspace) access_token received", status="recv",
              resp={"iss": _sc.get("iss"), "aud": _sc.get("aud"), "cid": _sc.get("cid"),
                    "scp": _sc.get("scp"), "exp": _sc.get("exp"), "sub": _sc.get("sub")})

    resource_iss = _cfg("IDJAG_AUDIENCE")             # resource AS issuer
    scopes       = _cfg("IDJAG_SCOPES").split()

    async def _flow():
        flow = CrossAppAccessFlow(client=_org_oauth_client(),
                                  target=CrossAppAccessTarget(issuer=resource_iss))
        _log_step("SmartTriage STEP3 access_token -> ID-JAG via CrossAppAccessFlow.start()",
                  req={"audience": resource_iss, "scope": scopes})
        result = await flow.start(token=user_access_token, token_type="access_token",
                                  audience=resource_iss, scope=scopes)
        _log_step("SmartTriage STEP3 ok: ID-JAG obtained", status="ok",
                  resp={"automatic": getattr(result, "resume_assertion_claims", None) is None})
        _log_step("SmartTriage STEP4 ID-JAG -> resource token via CrossAppAccessFlow.resume()")
        return await flow.resume()

    try:
        token = _run_async(_flow)
    except Exception as exc:
        _log_step("SmartTriage ID-JAG exchange failed", status="ERR", resp=repr(exc))
        return "", 0

    resource_token = getattr(token, "access_token", "") or ""
    if not resource_token:
        _log_step("SmartTriage exchange returned no access_token", status="ERR", resp=repr(token))
        return "", 0

    exp = _resolve_exp(resource_token, getattr(token, "expires_in", None))
    _log_step(f"SmartTriage STEP4 ok: resource token cached (exp={exp}) -> Bearer to MCP")
    return resource_token, exp


def _resolve_exp(token: str, expires_in: Any) -> int:
    """Best-effort resource-token expiry (epoch seconds) for caching."""
    exp = _decode_jwt_noverify(token).get("exp")
    if isinstance(exp, int):
        return exp
    if isinstance(expires_in, int):
        return int(time.time()) + expires_in
    return int(time.time()) + 3600


# ── GitHub: Okta STS / brokered consent (manual httpx exchange) ────────────────
#
# Manual httpx (not the SDK TokenExchangeFlow): CONFIRMED on 2026-07-07 that the SDK
# parses the token-exchange error into OAuth2Error keeping only error/error_description
# and DROPS Okta's non-standard `interaction_uri` (additional_fields came back {}).
# We need that sts/redirect consent URL, so we read the full JSON body ourselves.

def _exchange_github_sts(user_access_token: str) -> tuple[str, int, str]:
    """Single Okta STS token exchange for the GitHub MCP resource.

    Returns (access_token, exp_epoch, interaction_uri):
      * 200 + access_token        -> (token, exp, "")            consent already granted
      * interaction_required      -> ("", 0, interaction_uri)    user must consent
      * anything else / error     -> ("", 0, "")
    """
    okta = _cfg("OKTA_DOMAIN").rstrip("/")
    orn  = _cfg("GITHUB_RESOURCE_ORN")
    if not okta or not user_access_token or not orn:
        _log_step("GitHub STS: missing OKTA_DOMAIN / access token / GITHUB_RESOURCE_ORN",
                  status="skip")
        return "", 0, ""

    token_ep = f"{okta}/oauth2/v1/token"
    payload = {
        "grant_type":            "urn:ietf:params:oauth:grant-type:token-exchange",
        "requested_token_type":  "urn:okta:params:oauth:token-type:oauth-sts",
        "subject_token":         user_access_token,
        "subject_token_type":    "urn:ietf:params:oauth:token-type:access_token",
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion":      _make_agent_assertion(token_ep),
        "resource":              orn,
    }
    _log_step(f"GitHub STS access_token -> oauth-sts (POST {token_ep})", req=payload)
    try:
        r = httpx.post(token_ep, data=payload, timeout=30)
    except Exception as exc:
        _log_step("GitHub STS request error", status="ERR", resp=str(exc))
        return "", 0, ""

    try:
        body = r.json()
        body = body if isinstance(body, dict) else {}
    except Exception:
        body = {}
    _log_step("GitHub STS response", status=r.status_code, resp=(body or r.text))

    if r.status_code == 200 and body.get("access_token"):
        tok = body["access_token"]
        return tok, _resolve_exp(tok, body.get("expires_in")), ""

    if body.get("error") == "interaction_required" and body.get("interaction_uri"):
        _log_step("GitHub STS interaction_required (brokered consent)", status="consent",
                  resp={"interaction_uri": body["interaction_uri"]})
        return "", 0, body["interaction_uri"]

    return "", 0, ""


# ── Token stores + per-request injection ───────────────────────────────────────
#
# Two stores (Smart Triage resource token, GitHub STS token). Plain mutable objects
# (ContextVar is unpicklable); __reduce__ serializes them empty and the worker
# re-populates per request. Shared module-level state — prototype scope.

class _TokenStore:
    def __init__(self):
        self._token = ""
        self._exp = 0

    def get(self) -> str:
        return self._token

    def set(self, value: str, exp: int) -> None:
        self._token = value
        self._exp = exp

    def valid(self) -> bool:
        return bool(self._token) and int(time.time()) < (self._exp - 60)

    def __reduce__(self):
        return (self.__class__, ())


_token_store = _TokenStore()       # Smart Triage resource token
_gh_token_store = _TokenStore()    # GitHub STS token
_gh_state: dict = {"interaction_uri": ""}   # last GitHub consent URL (if any)

# Diagnostic surfaced by dump_state (populated in the instruction-provider context
# where the Agentspace token is present).
_auth_diag: dict = {
    "agentspace_token_received": False,
    "matched_key": None,
    "subject_claims": {},
    "smarttriage_token_cached": False,
    "github_token_cached": False,
    "github_interaction_required": False,
    "github_interaction_uri": "",
}


def _ensure_resource_token(state: Any) -> None:
    """Smart Triage ID-JAG exchange (SDK) → _token_store, when cache empty/expired."""
    if _token_store.valid():
        return
    access_token, _ = _find_token(state)
    if not access_token:
        return
    token, exp = _exchange_for_resource_token(access_token)
    if token:
        _token_store.set(token, exp)
        _auth_diag["smarttriage_token_cached"] = True


def _ensure_github_token(state: Any) -> None:
    """GitHub STS exchange (httpx) → _gh_token_store, or capture the consent
    interaction_uri when brokered consent is required."""
    if _gh_token_store.valid():
        return
    access_token, _ = _find_token(state)
    if not access_token:
        return
    token, exp, interaction_uri = _exchange_github_sts(access_token)
    if token:
        _gh_token_store.set(token, exp)
        _gh_state["interaction_uri"] = ""
        _auth_diag.update(github_token_cached=True,
                          github_interaction_required=False, github_interaction_uri="")
    elif interaction_uri:
        _gh_state["interaction_uri"] = interaction_uri
        _auth_diag.update(github_token_cached=False,
                          github_interaction_required=True, github_interaction_uri=interaction_uri)


def _ensure_tokens(state: Any) -> None:
    """Record the incoming Agentspace token, then run both resource exchanges.
    Failures in one resource never block the other."""
    access_token, matched_key = _find_token(state)
    if not access_token:
        _auth_diag.update(agentspace_token_received=False, matched_key=None, subject_claims={})
        print(f"[idjag-sdk] no access token in state matching prefix={AUTH_ID_PREFIX!r}",
              file=sys.stderr, flush=True)
        return

    _claims = _decode_jwt_noverify(access_token)
    _auth_diag.update(
        agentspace_token_received=True,
        matched_key=matched_key,
        subject_claims={k: _claims.get(k) for k in ("iss", "aud", "exp", "cid", "scp")},
    )

    for name, fn in (("SmartTriage", _ensure_resource_token), ("GitHub", _ensure_github_token)):
        try:
            fn(state)
        except Exception as exc:
            print(f"[idjag-sdk] {name} token ensure failed: {exc}", file=sys.stderr, flush=True)


# ── Dynamic connection params (one per resource, own Bearer header) ────────────

class DynamicStreamableHTTPConnectionParams(StreamableHTTPConnectionParams):
    """Smart Triage MCP params — Bearer from _token_store."""

    def __reduce__(self):
        return (_make_st_params, (self.url, self.timeout))


def _make_st_params(url: str, timeout: float) -> "DynamicStreamableHTTPConnectionParams":
    return DynamicStreamableHTTPConnectionParams(url=url, timeout=timeout)


DynamicStreamableHTTPConnectionParams.headers = property(  # type: ignore[assignment]
    lambda self: (
        {"Authorization": f"Bearer {_token_store.get()}"} if _token_store.get() else {}
    ),
    lambda self, v: None,
)


class GitHubStreamableHTTPConnectionParams(StreamableHTTPConnectionParams):
    """GitHub MCP params — Bearer from _gh_token_store."""

    def __reduce__(self):
        return (_make_github_params, (self.url, self.timeout))


def _make_github_params(url: str, timeout: float) -> "GitHubStreamableHTTPConnectionParams":
    return GitHubStreamableHTTPConnectionParams(url=url, timeout=timeout)


GitHubStreamableHTTPConnectionParams.headers = property(  # type: ignore[assignment]
    lambda self: (
        {"Authorization": f"Bearer {_gh_token_store.get()}"} if _gh_token_store.get() else {}
    ),
    lambda self, v: None,
)


# ── Before-tool callback ───────────────────────────────────────────────────────

def _inject_credential(
    tool: Any,
    args: dict,
    tool_context: ToolContext,
) -> Optional[dict]:
    """Refresh both resource tokens before each tool call. Returns None so the
    tool proceeds (GitHub consent is surfaced via the instruction provider)."""
    _ensure_tokens(tool_context.state)
    return None


# ── Session-id sanitization ─────────────────────────────────────────────────────

_FULL_SESSION_RE = re.compile(r"^projects/.+/sessions/([A-Za-z0-9_-]+)$")


def _sanitize_session_ids(obj: Any) -> Any:
    if isinstance(obj, str):
        m = _FULL_SESSION_RE.match(obj)
        return m.group(1) if m else obj
    if isinstance(obj, dict):
        return {k: _sanitize_session_ids(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_sanitize_session_ids(v) for v in obj]
    return obj


# ── Diagnostic tool ───────────────────────────────────────────────────────────

def dump_state(tool_context: ToolContext) -> dict:
    """Diagnostic: confirms Agentspace token delivery and both resource exchanges
    (via agentspace_auth, recorded by the instruction provider). Remove before prod."""
    state_dict = _as_dict(tool_context.state)
    state_keys = list(state_dict.keys())
    safe_state = {
        k: ("<token>" if isinstance(v, str) and len(v) > 40 else v)
        for k, v in state_dict.items()
    }

    print(f"[idjag-sdk][DIAG] tool_context.state keys: {state_keys}", file=sys.stderr, flush=True)
    print(f"[idjag-sdk][DIAG] agentspace_auth: {_auth_diag}", file=sys.stderr, flush=True)
    return {
        "state_keys": state_keys,
        "state_redacted": safe_state,
        "agentspace_auth": _auth_diag,
        "smarttriage_token_cached": _token_store.valid(),
        "github_token_cached": _gh_token_store.valid(),
        "github_interaction_uri": _gh_state.get("interaction_uri", ""),
        "user_id": getattr(tool_context.session, "user_id", None),
        "session_id": getattr(tool_context.session, "id", None),
    }


# ── Instruction provider ───────────────────────────────────────────────────────

_BASE_INSTRUCTION = (
    "You are an enterprise AI assistant. Use your tools to help users with two "
    "connected systems: Smart Triage (an Okta-protected MCP server for diagnosing "
    "service health, routing incidents, and tracking cloud spend across a "
    "microservices fleet) and GitHub (via the GitHub MCP server).\n\n"
    "IMPORTANT: If a tool returns an authorization or consent link (a URL), do "
    "NOT print the raw URL. Render it as a Markdown link with short "
    "call-to-action text so it shows up as a clickable button, using the EXACT "
    "URL from the tool response, e.g.:\n"
    "    **[🔐 Authorize →](PASTE_THE_EXACT_URL_HERE)**\n"
    "Include the service name in the label when the tool provides it. Never "
    "alter the URL. Ask the user to click it to sign in, and do not proceed "
    "with other tool calls until they confirm they have authorized.\n\n"
    "Access boundaries: If a tool returns a 404, error, 'not found', or "
    "'access denied' for a resource, tell the user you do not have access to "
    "it. Never fabricate, guess, or infer its details, and never reuse data "
    "from an earlier response to answer about a resource the current tool call "
    "could not retrieve.\n\n"
    "Only call tools that are actually available to you. Never invent or guess a "
    "tool name. If the user asks for something no available tool can do (e.g. a "
    "GitHub action before GitHub is authorized), do not call a tool — instead tell "
    "the user plainly, and if a GitHub authorization link is provided below, present "
    "that clickable link and ask them to authorize first."
)

_GITHUB_CONSENT_TEMPLATE = (
    "\n\nGITHUB AUTHORIZATION REQUIRED: GitHub access has not been consented yet. "
    "If the user asks anything that needs GitHub, present this EXACT URL as a "
    "clickable Markdown button labelled '🔐 Authorize GitHub →' and ask them to "
    "click it to grant access, then stop and wait until they confirm. Do not alter "
    "the URL:\n    {uri}"
)


def _instruction_provider(context: ReadonlyContext) -> str:
    """Resolve the system prompt — fires before tools/list; runs both resource
    exchanges so the MCP tools/list calls are authenticated. If GitHub needs
    brokered consent, append the interaction_uri as an authorize directive."""
    state = getattr(context.session, "state", None) or {}
    try:
        state_keys = list(state.keys())
    except Exception:
        state_keys = list(_as_dict(state).keys())
    print(f"[idjag-sdk] instruction_provider session_state keys: {state_keys}",
          file=sys.stderr, flush=True)

    _ensure_tokens(state)

    instruction = _BASE_INSTRUCTION
    consent_uri = _gh_state.get("interaction_uri", "")
    if consent_uri and not _gh_token_store.valid():
        instruction += _GITHUB_CONSENT_TEMPLATE.format(uri=consent_uri)
    return instruction


# ── Agent ──────────────────────────────────────────────────────────────────────

def _build_agent() -> LlmAgent:
    return LlmAgent(
        model="gemini-2.5-flash",
        name="enterprise_adk_agent",
        instruction=_instruction_provider,
        tools=[
            dump_state,
            SanitizingMcpToolset(
                connection_params=DynamicStreamableHTTPConnectionParams(
                    url=_cfg("SMARTTRIAGE_MCP_URL", DEFAULT_SMARTTRIAGE_MCP_URL),
                    timeout=120,
                ),
            ),
            TolerantGitHubMcpToolset(
                connection_params=GitHubStreamableHTTPConnectionParams(
                    url=_cfg("GITHUB_MCP_URL", DEFAULT_GITHUB_MCP_URL),
                    timeout=120,
                ),
            ),
        ],
        before_tool_callback=_inject_credential,
    )


# ── Enterprise ADK App ─────────────────────────────────────────────────────────

class EnterpriseAdkApp(AdkApp):
    """AdkApp for Gemini Enterprise. Per-call resource tokens derived from the
    user access token in session.state (Smart Triage = ID-JAG, GitHub = STS)."""

    def __init__(self, **kwargs):
        super().__init__(**(kwargs or {"agent": _build_agent(), "enable_tracing": True}))

    def streaming_agent_run_with_events(self, **kwargs):
        """Sanitize Agentspace session paths, then delegate to parent."""
        user_id = kwargs.get("user_id", "") or ""
        print(f"[idjag-sdk] streaming_agent_run_with_events user_id={user_id!r}",
              file=sys.stderr, flush=True)

        rj = kwargs.get("request_json")
        if isinstance(rj, str):
            try:
                parsed = json.loads(rj)
                new_rj = json.dumps(_sanitize_session_ids(parsed))
                if new_rj != rj:
                    print("[idjag-sdk] stripped Agentspace session path -> bare id",
                          file=sys.stderr, flush=True)
                kwargs["request_json"] = new_rj
            except Exception as exc:
                print(f"[idjag-sdk] request_json sanitize skipped: {exc}",
                      file=sys.stderr, flush=True)
        elif rj is not None:
            kwargs["request_json"] = _sanitize_session_ids(rj)

        for _skey in ("session_id", "session"):
            if isinstance(kwargs.get(_skey), str):
                kwargs[_skey] = _sanitize_session_ids(kwargs[_skey])

        return super().streaming_agent_run_with_events(**kwargs)


# ── Deploy ─────────────────────────────────────────────────────────────────────

def _build_env_vars() -> dict:
    """Copy config from the local environment into a dict passed to the deployed
    worker so os.getenv() resolves it there."""
    env = {}
    for k in _CFG_KEYS:
        v = os.getenv(k)
        if v:
            env[k] = v
    return env


if __name__ == "__main__":
    remote_app = agent_engines.AgentEngine.create(
        EnterpriseAdkApp(),
        requirements=[
            "google-adk==1.33.0",
            "google-cloud-aiplatform[adk,reasoningengine]",
            "mcp",
            "httpx",
            "okta-client-python",
            "pyjwt",
            "cryptography",
        ],
        env_vars=_build_env_vars(),
        display_name="Jo direct ID-JAG + GitHub STS agent (SDK)",
    )

    print("Done! Resource name:", remote_app.resource_name)
    print()
    print("Update RESOURCE_NAME in test_agent.py to:", remote_app.resource_name)
