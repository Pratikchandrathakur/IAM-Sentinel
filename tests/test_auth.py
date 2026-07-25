"""
Tests for authentication (API key + JWT SSO) and RBAC.

HS256 JWT is verified with stdlib; RS256 uses `cryptography` (self-skips if absent).

Run:  python3 tests/test_auth.py
"""

import base64
import hashlib
import hmac
import importlib
import json
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def make_hs256_jwt(claims: dict, secret: str) -> str:
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps(claims).encode())
    signing_input = f"{header}.{payload}".encode()
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return f"{header}.{payload}.{_b64url(sig)}"


def reload_auth(env: dict):
    for k, v in env.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    import config
    importlib.reload(config)
    import auth
    importlib.reload(auth)
    return auth, config


class TestApiKeyRBAC(unittest.TestCase):
    def test_roles_parsed_and_resolved(self):
        auth, _ = reload_auth({
            "AUTH_ENABLED": "true", "SSO_ENABLED": "false",
            "IAM_SENTINEL_API_KEYS": "jane:admin:supersecretkeyAAAAAAAA,"
                                     "bob:viewer:viewerkeyBBBBBBBBBB,"
                                     "legacy:legacysecretCCCCCCCCCC",   # no role -> analyst
        })
        p = auth.resolve_principal("supersecretkeyAAAAAAAA", None)
        self.assertEqual((p.actor, p.role, p.method), ("jane", "admin", "apikey"))
        self.assertEqual(auth.resolve_principal("viewerkeyBBBBBBBBBB", None).role, "viewer")
        self.assertEqual(auth.resolve_principal("legacysecretCCCCCCCCCC", None).role, "analyst")

    def test_invalid_key_raises(self):
        auth, _ = reload_auth({"AUTH_ENABLED": "true", "SSO_ENABLED": "false",
                               "IAM_SENTINEL_API_KEYS": "jane:admin:supersecretkeyAAAAAAAA"})
        with self.assertRaises(auth.AuthError):
            auth.resolve_principal("wrong", None)

    def test_rbac_hierarchy(self):
        auth, _ = reload_auth({"AUTH_ENABLED": "true", "IAM_SENTINEL_API_KEYS": "x:admin:k"})
        self.assertTrue(auth.has_role("admin", "analyst"))
        self.assertTrue(auth.has_role("analyst", "analyst"))
        self.assertFalse(auth.has_role("viewer", "analyst"))
        self.assertFalse(auth.has_role("analyst", "admin"))

    def test_auth_disabled_is_local_admin(self):
        auth, _ = reload_auth({"AUTH_ENABLED": "false"})
        p = auth.resolve_principal(None, None)
        self.assertEqual((p.actor, p.role, p.method), ("local", "admin", "local"))


class TestJwtSSO(unittest.TestCase):
    def _env(self, **over):
        base = {
            "AUTH_ENABLED": "true", "SSO_ENABLED": "true", "JWT_ALG": "HS256",
            "JWT_SECRET": "topsecretsharedkey1234567890", "JWT_ISSUER": "https://idp.example.com",
            "JWT_ROLE_CLAIM": "groups", "JWT_ROLE_MAP": "cloudsec-admins:admin,analysts:analyst",
            "JWT_ACTOR_CLAIM": "sub", "IAM_SENTINEL_API_KEYS": "",
        }
        base.update(over)
        return base

    def test_valid_jwt_maps_group_to_role(self):
        auth, cfg = reload_auth(self._env())
        token = make_hs256_jwt(
            {"sub": "jane@example.com", "iss": "https://idp.example.com",
             "groups": ["cloudsec-admins"], "exp": int(time.time()) + 300},
            cfg.JWT_SECRET)
        p = auth.resolve_principal(None, f"Bearer {token}")
        self.assertEqual(p.actor, "jane@example.com")
        self.assertEqual(p.role, "admin")
        self.assertEqual(p.method, "sso")

    def test_expired_jwt_rejected(self):
        auth, cfg = reload_auth(self._env())
        token = make_hs256_jwt({"sub": "x", "iss": "https://idp.example.com",
                                "exp": int(time.time()) - 10}, cfg.JWT_SECRET)
        with self.assertRaises(auth.AuthError):
            auth.resolve_principal(None, f"Bearer {token}")

    def test_bad_signature_rejected(self):
        auth, cfg = reload_auth(self._env())
        token = make_hs256_jwt({"sub": "x", "iss": "https://idp.example.com",
                                "exp": int(time.time()) + 300}, "the-wrong-secret")
        with self.assertRaises(auth.AuthError):
            auth.resolve_principal(None, f"Bearer {token}")

    def test_issuer_mismatch_rejected(self):
        auth, cfg = reload_auth(self._env())
        token = make_hs256_jwt({"sub": "x", "iss": "https://evil.example.com",
                                "exp": int(time.time()) + 300}, cfg.JWT_SECRET)
        with self.assertRaises(auth.AuthError):
            auth.resolve_principal(None, f"Bearer {token}")

    def test_unmapped_group_defaults_to_viewer(self):
        auth, cfg = reload_auth(self._env())
        token = make_hs256_jwt({"sub": "x", "iss": "https://idp.example.com",
                                "groups": ["random-team"], "exp": int(time.time()) + 300},
                               cfg.JWT_SECRET)
        self.assertEqual(auth.resolve_principal(None, f"Bearer {token}").role, "viewer")


if __name__ == "__main__":
    unittest.main(verbosity=2)
