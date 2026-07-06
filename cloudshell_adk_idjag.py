"""
cloudshell_adk_idjag.py — ADK agent that performs the Okta ID-JAG exchange itself.

What changed vs. cloudshell_adapter_adk_v2.py
---------------------------------------------
v2 sent the user's raw Okta access token as a Bearer to an external "Okta MCP
Adapter" (on Render), which ran the ID-JAG (Identity Assertion Authorization
Grant / Okta Cross-App Access) exchange and proxied MCP calls. This file removes
the adapter: the agent performs the ID-JAG exchange itself and calls the Smart
Triage MCP directly.

Auth flow
---------
Agentspace logs the user in via a *Custom* Authorization Server whose /authorize
carries `resource=https://smarttriage.com/aud`, so the resulting access token has
that `aud`. Agentspace drops that access token into tool_context.state under a key
starting with AUTH_ID_PREFIX. The agent then:

  STEP3  access_token -> ID-JAG      POST {ORG}/oauth2/v1/token
         grant_type=token-exchange, subject_token_type=access_token,
         requested_token_type=id-jag, audience={ORG}/oauth2/{RESOURCE_AUTHZ_SERVER},
         scope=IDJAG_SCOPES, client_assertion=private_key_jwt (aud = this endpoint)

  STEP4  ID-JAG -> resource token    POST {ORG}/oauth2/{RESOURCE_AUTHZ_SERVER}/v1/token
         grant_type=jwt-bearer, assertion=<ID-JAG>,
         client_assertion=private_key_jwt (aud = this endpoint)

The resource token (Bearer) is cached until ~60s before expiry and used directly
against the Smart Triage MCP. STEP1/STEP2 (login + code->token) are Agentspace's
job; the agent owns STEP3 and STEP4.

Note: the Custom-AS precondition is required — an Org-AS access token is rejected
at STEP3. The dump_state tool decodes the incoming token's iss/aud/exp so the
precondition can be verified after deploy.

Config
------
Read at runtime via os.getenv() (see _cfg / _CFG_KEYS). Locally, python-dotenv
loads .env. When deployed, the same values are passed to the worker via env_vars
on AgentEngine.create(), so os.getenv() resolves them there too. Config is never
read at module top level, keeping the private key out of the cloudpickle payload.

Concurrency: _token_store is a shared module-level object (not per-asyncio-task).
Sufficient for single-user prototype testing; replace with a ContextVar for prod.

Prerequisites
-------------
    pip install google-adk google-cloud-aiplatform[adk,reasoningengine] \
        httpx pyjwt cryptography python-dotenv
"""

import base64
import json
import os
import re
import sys
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

load_dotenv()

# ── Google Cloud ───────────────────────────────────────────────────────────────

PROJECT  = "jo-dev-portal"
LOCATION = "us-central1"
BUCKET   = "gs://jo-dev-portal-adk-staging"

vertexai.init(project=PROJECT, location=LOCATION, staging_bucket=BUCKET)

# ── Configuration ──────────────────────────────────────────────────────────────
#
# All ID-JAG config lives in these env vars. Read them at runtime via _cfg() so
# they resolve from .env locally and from env_vars in the deployed worker — and so
# the private key is never captured into the cloudpickle payload.

_CFG_KEYS = (
    "OKTA_DOMAIN",              # e.g. https://itpoktane24.oktapreview.com
    "IDJAG_AUDIENCE",           # STEP3 audience: {ORG}/oauth2/{RESOURCE_AUTHZ_SERVER}
    "RESOURCE_AUTHZ_SERVER",    # id used in the STEP4 token endpoint
    "IDJAG_SCOPES",             # e.g. smarttriage:read
    "AT_AI_AGENT_ID",           # iss/sub of the client_assertion (the agent identity)
    "AT_AGENT_PRIVATE_KEY_ID",  # kid of the signing key
    "AT_AGENT_PRIVATE_KEY_PEM", # RSA private key (PEM) used to sign the client_assertion
    "SMARTTRIAGE_MCP_URL",      # Smart Triage MCP endpoint
)

DEFAULT_SMARTTRIAGE_MCP_URL = "https://smarttriage-1.onrender.com/mcp"

# auth_id registered in Agentspace config; matches any suffix,
# e.g. okta-authorization-1782243784
AUTH_ID_PREFIX = "okta-authorization_native"


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
    # Path 1: raw MCP tool inputSchema (source of truth before conversion)
    mcp_tool = getattr(tool, "_mcp_tool", None)
    if mcp_tool is not None and isinstance(getattr(mcp_tool, "inputSchema", None), dict):
        mcp_tool.inputSchema = _sanitize_json_schema(mcp_tool.inputSchema)

    # Path 2: already-converted FunctionDeclaration parameters
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
                    f"[idjag] schema sanitize failed for {getattr(tool, 'name', '?')}: {exc}",
                    file=sys.stderr, flush=True,
                )
        return tools


# ── Token lookup helper ────────────────────────────────────────────────────────

def _as_dict(state: Any) -> dict:
    """Convert an ADK State object or plain dict to a regular dict.

    ADK's State object supports .get() but not .keys()/.items() in all
    versions. We try several access patterns to extract the underlying data.
    """
    if not state:
        return {}
    if isinstance(state, dict):
        return state
    # Works if State implements __iter__ + __getitem__ (MutableMapping pattern)
    try:
        return dict(state)
    except Exception:
        pass
    # ADK internal storage attribute names across versions
    for attr in ("_data", "_delta", "_value", "_state", "_session_state"):
        raw = getattr(state, attr, None)
        if isinstance(raw, dict):
            return raw
    # Pydantic model
    if hasattr(state, "model_dump"):
        try:
            return state.model_dump()
        except Exception:
            pass
    # Last resort: public vars
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


# ── JWT helpers ─────────────────────────────────────────────────────────────────

def _make_agent_assertion(token_endpoint: str) -> str:
    """Build the client_assertion (private_key_jwt) that identifies the agent.

    iss=sub=AT_AI_AGENT_ID, aud=<the token endpoint being called>, 5-min exp
    (single-use in practice), signed RS256 with the agent's private key.
    Mirrors AgentFlows/app.py:make_at_agent_assertion.
    """
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


def _decode_jwt_noverify(token: str) -> dict:
    """Decode a JWT payload without verifying the signature (diagnostics only)."""
    try:
        seg = token.split(".")[1]
        seg += "=" * (-len(seg) % 4)
        return json.loads(base64.urlsafe_b64decode(seg).decode())
    except Exception:
        return {}


# ── ID-JAG exchange ──────────────────────────────────────────────────────────────

# Keys redacted in request/response traces — never log raw tokens or secrets.
_REDACT_KEYS = {
    "client_assertion", "subject_token", "assertion", "client_secret",
    "access_token", "id_token", "refresh_token",
}


def _redact(d: Any) -> Any:
    if not isinstance(d, dict):
        return d
    return {
        k: (f"<{k}: {len(str(v))} chars>" if k in _REDACT_KEYS and v else v)
        for k, v in d.items()
    }


def _log_step(label: str, method: str = "", url: str = "",
              req: Any = None, status: Any = None, resp: Any = None) -> None:
    """Emit one ID-JAG trace step to stderr (Cloud Logging), redacting secrets."""
    head = f"[idjag] {label}"
    if method or url:
        head += f" — {method} {url}".rstrip()
    print(head, file=sys.stderr, flush=True)
    if req is not None:
        print(f"[idjag]     req : {json.dumps(_redact(req))}", file=sys.stderr, flush=True)
    if status is not None:
        body = _redact(resp) if isinstance(resp, dict) else resp
        body_str = json.dumps(body) if isinstance(body, dict) else str(body)[:400]
        print(f"[idjag]     resp[{status}] : {body_str}", file=sys.stderr, flush=True)


def _exchange_for_resource_token(user_access_token: str) -> tuple[str, int]:
    """Run STEP3 (access_token -> ID-JAG) then STEP4 (ID-JAG -> resource token).

    Returns (resource_token, exp_epoch). Returns ("", 0) on any failure and logs
    the failing step's status + body to stderr.
    """
    okta = _cfg("OKTA_DOMAIN").rstrip("/")
    if not okta or not user_access_token:
        print("[idjag] missing OKTA_DOMAIN or access token; skipping exchange",
              file=sys.stderr, flush=True)
        return "", 0

    # STEP1/STEP2 (login + code->token at the Custom AS) are performed by Agentspace;
    # the agent receives the resulting access_token in session.state. Log it as the
    # starting point of the trace. `aud` must be the resource for STEP3 to succeed.
    _sc = _decode_jwt_noverify(user_access_token)
    _log_step(
        "STEP1/2 (Agentspace) login + code->token at Custom AS => access_token received",
        req={"note": "performed by Agentspace before the agent runs"},
        status="recv",
        resp={"iss": _sc.get("iss"), "aud": _sc.get("aud"), "cid": _sc.get("cid"),
              "scp": _sc.get("scp"), "exp": _sc.get("exp"), "sub": _sc.get("sub")},
    )

    org_token_endpoint      = f"{okta}/oauth2/v1/token"
    resource_authz          = _cfg("RESOURCE_AUTHZ_SERVER")
    resource_token_endpoint = f"{okta}/oauth2/{resource_authz}/v1/token"

    # STEP3 — access_token -> ID-JAG (Org AS token endpoint)
    step3 = {
        "grant_type":            "urn:ietf:params:oauth:grant-type:token-exchange",
        "subject_token":         user_access_token,
        "subject_token_type":    "urn:ietf:params:oauth:token-type:access_token",
        "requested_token_type":  "urn:ietf:params:oauth:token-type:id-jag",
        "audience":              _cfg("IDJAG_AUDIENCE"),
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion":      _make_agent_assertion(org_token_endpoint),
        "scope":                 _cfg("IDJAG_SCOPES"),
    }
    # NOTE: STEP3 targets the ID-JAG via `audience` only. Okta's Org-AS
    # token-exchange endpoint does NOT accept a `resource` param here and returns
    # 400 invalid_target if one is sent. The target app's aud is bound earlier, at
    # /authorize time (the authorizer's resource=... query param), not here.
    _log_step("STEP3 access_token -> ID-JAG (token-exchange @ Org AS)",
              "POST", org_token_endpoint, req=step3)
    try:
        r3 = httpx.post(org_token_endpoint, data=step3, timeout=30)
    except Exception as exc:
        _log_step("STEP3 request error", status="ERR", resp=str(exc))
        return "", 0
    b3 = _safe_json(r3)
    _log_step("STEP3 response", status=r3.status_code, resp=(b3 or r3.text))
    if r3.status_code != 200 or "access_token" not in b3:
        return "", 0
    id_jag = b3["access_token"]
    _log_step(f"STEP3 ok: ID-JAG obtained (issued_token_type={b3.get('issued_token_type')})")

    # STEP4 — ID-JAG -> resource token (resource authz server token endpoint)
    step4 = {
        "grant_type":            "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion":             id_jag,
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion":      _make_agent_assertion(resource_token_endpoint),
    }
    _log_step("STEP4 ID-JAG -> resource token (jwt-bearer @ resource AS)",
              "POST", resource_token_endpoint, req=step4)
    try:
        r4 = httpx.post(resource_token_endpoint, data=step4, timeout=30)
    except Exception as exc:
        _log_step("STEP4 request error", status="ERR", resp=str(exc))
        return "", 0
    b4 = _safe_json(r4)
    _log_step("STEP4 response", status=r4.status_code, resp=(b4 or r4.text))
    if r4.status_code != 200 or "access_token" not in b4:
        return "", 0

    resource_token = b4["access_token"]
    exp = _resolve_exp(resource_token, b4.get("expires_in"))
    _log_step(f"STEP4 ok: resource token cached (token_type={b4.get('token_type')}, "
              f"scope={b4.get('scope')}, exp={exp}) -> used as Bearer to Smart Triage MCP")
    return resource_token, exp


def _safe_json(resp: httpx.Response) -> dict:
    try:
        body = resp.json()
        return body if isinstance(body, dict) else {}
    except Exception:
        return {}


def _resolve_exp(token: str, expires_in: Any) -> int:
    """Best-effort resource-token expiry (epoch seconds) for caching."""
    exp = _decode_jwt_noverify(token).get("exp")
    if isinstance(exp, int):
        return exp
    if isinstance(expires_in, int):
        return int(time.time()) + expires_in
    return int(time.time()) + 3600


# ── Token store ────────────────────────────────────────────────────────────────
#
# Holds the exchanged *resource* token plus its expiry. Plain mutable object (not
# a ContextVar — cloudpickle cannot serialize ContextVar). __reduce__ serializes
# it as a fresh empty instance; the deployed worker re-populates it per request.

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


_token_store = _TokenStore()

# Last-seen auth diagnostic, populated by _ensure_resource_token (which runs in the
# instruction-provider context where the Agentspace token is present). Surfaced by
# dump_state so "did Agentspace pass the token?" is visible from the chat, not just
# Cloud Logging. Shared module-level state — prototype scope, same caveat as _token_store.
_auth_diag: dict = {
    "agentspace_token_received": False,
    "matched_key": None,
    "subject_claims": {},
    "resource_token_cached": False,
}


def _ensure_resource_token(state: Any) -> None:
    """Ensure _token_store holds a valid resource token, running the ID-JAG
    exchange from the state access token when the cache is empty or expired."""
    if _token_store.valid():
        return

    access_token, matched_key = _find_token(state)
    if not access_token:
        _auth_diag.update(agentspace_token_received=False, matched_key=None,
                          subject_claims={}, resource_token_cached=False)
        print(f"[idjag] no access token in state matching prefix={AUTH_ID_PREFIX!r}",
              file=sys.stderr, flush=True)
        return

    _claims = _decode_jwt_noverify(access_token)
    _auth_diag.update(
        agentspace_token_received=True,
        matched_key=matched_key,
        subject_claims={k: _claims.get(k) for k in ("iss", "aud", "exp", "cid", "scp")},
    )

    token, exp = _exchange_for_resource_token(access_token)
    if token:
        _token_store.set(token, exp)
        _auth_diag["resource_token_cached"] = True
        print(f"[idjag] resource token derived from state[{matched_key!r}]",
              file=sys.stderr, flush=True)


# ── Dynamic connection params ──────────────────────────────────────────────────
#
# __reduce__ on the instance tells cloudpickle to serialize only (url, timeout)
# and reconstruct via _make_dynamic_params. The class is never pickled by value,
# so the property lambda's reference to _token_store is never traversed by
# cloudpickle during serialization.

class DynamicStreamableHTTPConnectionParams(StreamableHTTPConnectionParams):

    def __reduce__(self):
        return (_make_dynamic_params, (self.url, self.timeout))


def _make_dynamic_params(url: str, timeout: float) -> DynamicStreamableHTTPConnectionParams:
    return DynamicStreamableHTTPConnectionParams(url=url, timeout=timeout)


DynamicStreamableHTTPConnectionParams.headers = property(  # type: ignore[assignment]
    lambda self: (
        {"Authorization": f"Bearer {_token_store.get()}"} if _token_store.get() else {}
    ),
    lambda self, v: None,  # no-op setter
)


# ── Before-tool callback ───────────────────────────────────────────────────────

def _inject_credential(
    tool: Any,
    args: dict,
    tool_context: ToolContext,
) -> Optional[dict]:
    """Refresh the resource token before each tool call (fallback to the
    instruction-provider pre-population). Returns None so the tool proceeds."""
    _ensure_resource_token(tool_context.state)
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
    """Diagnostic: returns tool_context.state keys and decodes the incoming
    access token's iss/aud/exp to verify the ID-JAG STEP3 precondition.

    STEP3 only accepts a token minted by the Custom AS with
    aud=https://smarttriage.com/aud. Ask the agent 'show me your state keys'
    after deploying, then confirm iss is the Custom AS and aud is the resource.
    Remove this tool once the precondition is confirmed.
    """
    state_dict = _as_dict(tool_context.state)
    state_keys = list(state_dict.keys())
    safe_state = {
        k: ("<token>" if isinstance(v, str) and len(v) > 40 else v)
        for k, v in state_dict.items()
    }

    access_token, matched_key = _find_token(tool_context.state)
    token_claims = {}
    if access_token:
        dec = _decode_jwt_noverify(access_token)
        token_claims = {k: dec.get(k) for k in ("iss", "aud", "exp", "cid", "scp")}

    print(f"[idjag][DIAG] state keys: {state_keys}", file=sys.stderr, flush=True)
    print(f"[idjag][DIAG] access token key={matched_key!r} claims={token_claims}",
          file=sys.stderr, flush=True)
    return {
        "state_keys": state_keys,
        "state_redacted": safe_state,
        "access_token_key": matched_key,
        "access_token_claims": token_claims,
        "resource_token_cached": _token_store.valid(),
        # Populated by the instruction provider (where session.state holds the token),
        # so this confirms Agentspace delivery even though tool_context.state is empty here.
        "agentspace_auth": _auth_diag,
        "user_id": getattr(tool_context.session, "user_id", None),
        "session_id": getattr(tool_context.session, "id", None),
    }


# ── Instruction provider ───────────────────────────────────────────────────────
#
# Fires before tools/list (system prompt must be resolved before tool discovery).
# The Smart Triage MCP is Okta-protected, so tool discovery itself needs the
# resource token — this is the correct point to run the ID-JAG exchange.

_BASE_INSTRUCTION = (
    "You are an enterprise AI assistant. Use your tools to help users with "
    "Smart Triage, an Okta-protected MCP server for diagnosing service health, "
    "routing incidents, and tracking cloud spend across a microservices fleet.\n\n"
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
    "could not retrieve."
)


def _instruction_provider(context: ReadonlyContext) -> str:
    """Resolve the system prompt — fires before tools/list.

    This is the earliest point where session.state is available. We use it to
    run the ID-JAG exchange so McpToolset's tools/list call is authenticated.
    """
    state = getattr(context.session, "state", None) or {}
    try:
        state_keys = list(state.keys())
    except Exception:
        state_keys = list(_as_dict(state).keys())
    print(f"[idjag] instruction_provider session_state keys: {state_keys}",
          file=sys.stderr, flush=True)

    _ensure_resource_token(state)
    return _BASE_INSTRUCTION


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
        ],
        before_tool_callback=_inject_credential,
    )


# ── Enterprise ADK App ─────────────────────────────────────────────────────────

class EnterpriseAdkApp(AdkApp):
    """AdkApp for Gemini Enterprise.

    Agent is built once at init. The resource token is derived per-call from the
    user access token in tool_context.state via the ID-JAG exchange.
    """

    def __init__(self, **kwargs):
        super().__init__(**(kwargs or {"agent": _build_agent(), "enable_tracing": True}))

    def streaming_agent_run_with_events(self, **kwargs):
        """Sanitize Agentspace session paths, then delegate to parent."""
        user_id = kwargs.get("user_id", "") or ""
        print(f"[idjag] streaming_agent_run_with_events user_id={user_id!r}",
              file=sys.stderr, flush=True)

        rj = kwargs.get("request_json")
        if isinstance(rj, str):
            try:
                parsed = json.loads(rj)
                new_rj = json.dumps(_sanitize_session_ids(parsed))
                if new_rj != rj:
                    print("[idjag] stripped Agentspace session path -> bare id",
                          file=sys.stderr, flush=True)
                kwargs["request_json"] = new_rj
            except Exception as exc:
                print(f"[idjag] request_json sanitize skipped: {exc}",
                      file=sys.stderr, flush=True)
        elif rj is not None:
            kwargs["request_json"] = _sanitize_session_ids(rj)

        for _skey in ("session_id", "session"):
            if isinstance(kwargs.get(_skey), str):
                kwargs[_skey] = _sanitize_session_ids(kwargs[_skey])

        return super().streaming_agent_run_with_events(**kwargs)


# ── Deploy ─────────────────────────────────────────────────────────────────────

def _build_env_vars() -> dict:
    """Copy the ID-JAG config from the local environment (loaded from .env) into
    a dict passed to the deployed worker so os.getenv() resolves it there."""
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
            "pyjwt",
            "cryptography",
        ],
        env_vars=_build_env_vars(),
        display_name="Jo direct ID-JAG agent",
    )

    print("Done! Resource name:", remote_app.resource_name)
    print()
    print("Update RESOURCE_NAME in test_agent.py to:", remote_app.resource_name)
