"""
IAM Sentinel — authentication & RBAC.

Two auth methods, both mapped to a common Principal(actor, role):
  * API key   (X-API-Key)         -> role from the key definition
  * SSO / OIDC (Authorization: Bearer <jwt>) -> role from a mapped JWT claim

JWT verification is implemented in-process: HS256 with stdlib hmac; RS256 with the
`cryptography` library. No external calls (keys/secrets are configured locally), so it works
air-gapped. RBAC is a simple ordered hierarchy: viewer < analyst < admin.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass

import config


class AuthError(RuntimeError):
    def __init__(self, message, status=401):
        super().__init__(message)
        self.status = status


@dataclass
class Principal:
    actor: str
    role: str
    method: str          # "apikey" | "sso" | "local"


def role_rank(role: str) -> int:
    try:
        return config.ROLES.index(role)
    except ValueError:
        return -1


def has_role(principal_role: str, required: str) -> bool:
    return role_rank(principal_role) >= role_rank(required)


# --- JWT (minimal, dependency-light) ------------------------------------------------
def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _verify_jwt_signature(signing_input: bytes, signature: bytes, header: dict) -> None:
    alg = header.get("alg")
    if alg != config.JWT_ALG:
        raise AuthError(f"JWT alg '{alg}' does not match configured {config.JWT_ALG}.")
    if alg == "HS256":
        expected = hmac.new(config.JWT_SECRET.encode(), signing_input, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, signature):
            raise AuthError("JWT signature invalid (HS256).")
    elif alg == "RS256":
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.exceptions import InvalidSignature
        pub = serialization.load_pem_public_key(config.JWT_PUBLIC_KEY.encode())
        try:
            pub.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
        except InvalidSignature:
            raise AuthError("JWT signature invalid (RS256).")
    else:
        raise AuthError(f"Unsupported JWT alg '{alg}'.")


def verify_jwt(token: str) -> Principal:
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
    except ValueError:
        raise AuthError("Malformed JWT.")
    header = json.loads(_b64url_decode(header_b64))
    signing_input = f"{header_b64}.{payload_b64}".encode()
    _verify_jwt_signature(signing_input, _b64url_decode(sig_b64), header)

    claims = json.loads(_b64url_decode(payload_b64))

    now = int(time.time())
    if "exp" in claims and now >= int(claims["exp"]):
        raise AuthError("JWT expired.")
    if "nbf" in claims and now < int(claims["nbf"]):
        raise AuthError("JWT not yet valid.")
    if config.JWT_ISSUER and claims.get("iss") != config.JWT_ISSUER:
        raise AuthError("JWT issuer mismatch.")
    if config.JWT_AUDIENCE:
        aud = claims.get("aud")
        aud_ok = (aud == config.JWT_AUDIENCE) or (isinstance(aud, list) and config.JWT_AUDIENCE in aud)
        if not aud_ok:
            raise AuthError("JWT audience mismatch.")

    actor = str(claims.get(config.JWT_ACTOR_CLAIM) or claims.get("sub") or "sso-user")

    # Resolve role: map the first matching group/role claim value; else lowest privilege.
    raw_roles = claims.get(config.JWT_ROLE_CLAIM, [])
    if isinstance(raw_roles, str):
        raw_roles = [raw_roles]
    role = "viewer"
    for r in raw_roles:
        if r in config.JWT_ROLE_MAP:
            role = config.JWT_ROLE_MAP[r]
            break
        if r in config.ROLES:
            role = r
            break
    return Principal(actor=actor, role=role, method="sso")


# --- Unified resolution -------------------------------------------------------------
def resolve_principal(api_key: str | None, bearer: str | None) -> Principal:
    """Resolve the caller to a Principal, or raise AuthError. Called by the API layer."""
    if not config.AUTH_ENABLED:
        return Principal(actor="local", role="admin", method="local")

    if bearer and config.SSO_ENABLED:
        token = bearer[7:].strip() if bearer.lower().startswith("bearer ") else bearer.strip()
        return verify_jwt(token)

    key = (api_key or "").strip()
    if key and key in config.API_KEYS:
        entry = config.API_KEYS[key]
        return Principal(actor=entry["actor"], role=entry["role"], method="apikey")

    raise AuthError("Missing or invalid credentials (X-API-Key or Bearer token).")
