"""
IAM Sentinel — configuration.

All operational settings come from environment variables so one image promotes across
environments with no rebuilds and no baked-in secrets. validate_startup() fails LOUD on
unsafe config. ENGINE/RULESET versions are stamped into every scan for reproducibility.
"""

import os
import json
import time
import base64

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

PRODUCT_NAME = "IAM Sentinel"
ENGINE_VERSION = "1.0.0"
RULESET_VERSION = "iam-2026.07"          # bump when deterministic rules change

# --- Persistence / audit store ------------------------------------------------------
DATA_DIR = os.getenv("DATA_DIR", os.path.join(BASE_DIR, "data"))
FINDINGS_DB_PATH = os.getenv("FINDINGS_DB_PATH", os.path.join(DATA_DIR, "iam_sentinel.db"))

# --- LLM backend --------------------------------------------------------------------
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://cyber-brain:11434")
OLLAMA_API_URL = f"{OLLAMA_BASE_URL}/api/generate"
OLLAMA_CHAT_URL = f"{OLLAMA_BASE_URL}/api/chat"
VLLM_API_URL = os.getenv("VLLM_API_URL", "http://localhost:8000/v1")

DEFAULT_OLLAMA_MODEL = os.getenv("DEFAULT_OLLAMA_MODEL", "qwen2.5-coder:7b")
DEFAULT_VLLM_MODEL = os.getenv("DEFAULT_VLLM_MODEL", "qwen2.5-coder:7b")

LLM_TIMEOUT_SECONDS = int(os.getenv("LLM_TIMEOUT_SECONDS", "300"))
LLM_MAX_RETRIES = int(os.getenv("LLM_MAX_RETRIES", "2"))
LLM_RETRY_BACKOFF_SECONDS = float(os.getenv("LLM_RETRY_BACKOFF_SECONDS", "1.5"))

LLM_NARRATIVE_ENABLED = os.getenv("LLM_NARRATIVE_ENABLED", "true").lower() in ("1", "true", "yes", "on")

# --- Server -------------------------------------------------------------------------
SERVER_PORT = int(os.getenv("SERVER_PORT", "8080"))
SERVER_HOST = os.getenv("SERVER_HOST", "0.0.0.0")

# --- AuthN / AuthZ ------------------------------------------------------------------
AUTH_ENABLED = os.getenv("AUTH_ENABLED", "true").lower() in ("1", "true", "yes", "on")
_raw_keys = os.getenv("IAM_SENTINEL_API_KEYS", "")

ROLES = ("viewer", "analyst", "admin")
DEFAULT_ROLE = "analyst"


def _parse_api_keys(raw: str) -> dict:
    keys = {}
    for pair in raw.split(","):
        pair = pair.strip()
        if not pair:
            continue
        parts = [p.strip() for p in pair.split(":")]
        if len(parts) >= 3:
            label, role, secret = parts[0], parts[1], ":".join(parts[2:])
        elif len(parts) == 2:
            label, role, secret = parts[0], DEFAULT_ROLE, parts[1]
        else:
            label, role, secret = "client", DEFAULT_ROLE, parts[0]
        role = role if role in ROLES else DEFAULT_ROLE
        if secret:
            keys[secret] = {"actor": label or "client", "role": role}
    return keys


API_KEYS = _parse_api_keys(_raw_keys)

# --- Licensing (Cryptographic Asymmetric Ed25519) ----------------------------------
LICENSE_KEY = os.getenv("LICENSE_KEY", "").strip()
VENDOR_PUB_KEY_FILE = os.path.join(BASE_DIR, "vendor_public.pem")


def verify_license() -> tuple[bool, str, dict]:
    """Verify Ed25519 signature of LICENSE_KEY."""
    if not LICENSE_KEY:
        return True, "Community Mode (No License Key)", {"tier": "Community", "seats": 1, "scans_per_month": 100}

    try:
        raw_json = base64.b64decode(LICENSE_KEY.encode("utf-8")).decode("utf-8")
        data = json.loads(raw_json)
        payload = data["payload"]
        signature = base64.b64decode(data["signature"])

        if not os.path.exists(VENDOR_PUB_KEY_FILE):
            return False, "Vendor public key missing from server", {}

        from cryptography.hazmat.primitives import serialization
        with open(VENDOR_PUB_KEY_FILE, "rb") as f:
            pub_key = serialization.load_pem_public_key(f.read())

        payload_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
        pub_key.verify(signature, payload_bytes)

        if time.time() > payload.get("expires_at", 0):
            return False, f"License for {payload.get('customer')} EXPIRED", payload

        return True, f"Valid {payload.get('tier', 'Licensed')} License", payload
    except Exception as e:
        return False, f"Invalid or Tampered License Key: {e}", {}


LICENSE_OK, LICENSE_STATUS, LICENSE_INFO = verify_license()

# --- SSO (OIDC bearer JWT) ----------------------------------------------------------
SSO_ENABLED = os.getenv("SSO_ENABLED", "false").lower() in ("1", "true", "yes", "on")
JWT_ALG = os.getenv("JWT_ALG", "HS256").upper()            # HS256 | RS256
JWT_SECRET = os.getenv("JWT_SECRET", "")                   # HS256 shared secret
JWT_PUBLIC_KEY = os.getenv("JWT_PUBLIC_KEY", "")           # RS256 PEM
_jwt_pub_file = os.getenv("JWT_PUBLIC_KEY_FILE", "")
if _jwt_pub_file and os.path.exists(_jwt_pub_file):
    with open(_jwt_pub_file) as _f:
        JWT_PUBLIC_KEY = _f.read()
JWT_ISSUER = os.getenv("JWT_ISSUER", "")                   # optional iss check
JWT_AUDIENCE = os.getenv("JWT_AUDIENCE", "")              # optional aud check
JWT_ACTOR_CLAIM = os.getenv("JWT_ACTOR_CLAIM", "sub")     # claim used as the actor
JWT_ROLE_CLAIM = os.getenv("JWT_ROLE_CLAIM", "roles")    # claim carrying group/role(s)
JWT_ROLE_MAP = {}
for _p in os.getenv("JWT_ROLE_MAP", "").split(","):        # "idp-group:role,..."
    if ":" in _p:
        _k, _v = _p.split(":", 1)
        JWT_ROLE_MAP[_k.strip()] = _v.strip()

# --- TLS ----------------------------------------------------------------------------

TLS_CERT_FILE = os.getenv("TLS_CERT_FILE", "")
TLS_KEY_FILE = os.getenv("TLS_KEY_FILE", "")
TLS_ENABLED = bool(TLS_CERT_FILE and TLS_KEY_FILE)

_cors = os.getenv("CORS_ALLOW_ORIGINS", "").strip()
CORS_ALLOW_ORIGINS = [o.strip() for o in _cors.split(",") if o.strip()]
OFFLINE_MODE = os.getenv("OFFLINE_MODE", "true").lower() in ("1", "true", "yes", "on")


class ConfigError(RuntimeError):
    pass


def validate_startup() -> list:
    warnings = []

    # Verify License Key if provided
    if LICENSE_KEY and not LICENSE_OK:
        raise ConfigError(f"LICENSE ERROR: {LICENSE_STATUS}")

    if AUTH_ENABLED and not API_KEYS and not SSO_ENABLED:
        raise ConfigError(
            "AUTH_ENABLED is true but neither API keys nor SSO are configured. Set "
            "IAM_SENTINEL_API_KEYS (e.g. 'analyst:analyst:<secret>'), enable SSO_ENABLED, or "
            "explicitly set AUTH_ENABLED=false for an isolated host. Refusing to start open."
        )

    try:
        os.makedirs(DATA_DIR, exist_ok=True)
    except OSError as e:
        raise ConfigError(f"Cannot create DATA_DIR '{DATA_DIR}': {e}")

    return warnings
