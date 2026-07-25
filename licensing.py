"""
IAM Sentinel — offline licensing.

Enterprises run this air-gapped, so licensing must work with NO phone-home. We use
Ed25519-signed license tokens: the vendor signs a license with a private key; the product
verifies it with an embedded public key. Customers cannot forge or extend a license.

A license token is:  base64url(payload_json) + "." + base64url(ed25519_signature)

If no license is configured the product runs in a limited **Community** tier so it can be
evaluated freely (good for design-partner pilots) — it never hard-locks on eval.
"""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from typing import Optional

import config  # single source of truth: config.verify_license() validates the vendor license

# Demo/pilot public key. Override in production via LICENSE_PUBLIC_KEY (base64 of the raw
# 32-byte Ed25519 public key). Generate a real keypair with:  python license_tool.py keygen
DEMO_PUBLIC_KEY_B64 = os.getenv("LICENSE_PUBLIC_KEY", "")

PLANS = {
    "community": {"seats": 1, "max_scans_per_month": 100,
                  "features": ["audit", "rules"]},
    "team": {"seats": 10, "max_scans_per_month": 5000,
             "features": ["audit", "rules", "history", "diff"]},
    "enterprise": {"seats": 0, "max_scans_per_month": 0,   # 0 == unlimited
                   "features": ["audit", "rules", "history", "diff", "sso", "rbac", "priority_support"]},
}


class LicenseError(RuntimeError):
    pass


@dataclass
class License:
    plan: str = "community"
    customer: str = "Community (unlicensed)"
    license_id: str = "community"
    seats: int = 1                      # 0 == unlimited
    max_scans_per_month: int = 100      # 0 == unlimited
    features: list = field(default_factory=lambda: list(PLANS["community"]["features"]))
    issued: str = ""
    expires: str = ""                   # ISO date "YYYY-MM-DD"; "" == perpetual
    signed: bool = False                # True only when a valid signature was verified

    @property
    def is_expired(self) -> bool:
        if not self.expires:
            return False
        try:
            return date.fromisoformat(self.expires) < datetime.now(timezone.utc).date()
        except ValueError:
            return True

    def has_feature(self, name: str) -> bool:
        return name in self.features

    def to_public_dict(self) -> dict:
        return {
            "plan": self.plan,
            "customer": self.customer,
            "license_id": self.license_id,
            "seats": self.seats,
            "seats_display": "unlimited" if self.seats == 0 else self.seats,
            "max_scans_per_month": self.max_scans_per_month,
            "scans_display": "unlimited" if self.max_scans_per_month == 0 else self.max_scans_per_month,
            "features": self.features,
            "issued": self.issued,
            "expires": self.expires or "perpetual",
            "signed": self.signed,
            "expired": self.is_expired,
        }


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def community_license() -> License:
    p = PLANS["community"]
    return License(plan="community", seats=p["seats"],
                   max_scans_per_month=p["max_scans_per_month"],
                   features=list(p["features"]), signed=False)


def verify_license(token: str, public_key_b64: str = None) -> License:
    """Verify an Ed25519-signed license token. Raises LicenseError on any problem."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature

    pub_b64 = public_key_b64 or DEMO_PUBLIC_KEY_B64
    if not pub_b64:
        raise LicenseError("No license public key configured (LICENSE_PUBLIC_KEY).")

    try:
        payload_b64, sig_b64 = token.strip().split(".", 1)
    except ValueError:
        raise LicenseError("Malformed license token (expected 'payload.signature').")

    payload_bytes = _b64url_decode(payload_b64)
    signature = _b64url_decode(sig_b64)
    try:
        pub = Ed25519PublicKey.from_public_bytes(_b64url_decode(pub_b64))
        pub.verify(signature, payload_bytes)
    except InvalidSignature:
        raise LicenseError("License signature is invalid (tampered or wrong key).")
    except Exception as e:
        raise LicenseError(f"License verification failed: {e}")

    try:
        data = json.loads(payload_bytes)
    except json.JSONDecodeError:
        raise LicenseError("License payload is not valid JSON.")

    plan = data.get("plan", "community")
    defaults = PLANS.get(plan, PLANS["community"])
    lic = License(
        plan=plan,
        customer=data.get("customer", "Unknown"),
        license_id=data.get("license_id", ""),
        seats=int(data.get("seats", defaults["seats"])),
        max_scans_per_month=int(data.get("max_scans_per_month", defaults["max_scans_per_month"])),
        features=data.get("features", list(defaults["features"])),
        issued=data.get("issued", ""),
        expires=data.get("expires", ""),
        signed=True,
    )
    if lic.is_expired:
        raise LicenseError(f"License expired on {lic.expires}.")
    return lic


def _iso_from_ts(ts) -> str:
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).date().isoformat()
    except Exception:
        return ""


def load_active_license() -> License:
    """Build the runtime License from config's verified license (the single source of truth).

    config.verify_license() already validates the Ed25519 signature (via vendor_public.pem)
    and expiry against the vendor's format, and validate_startup() refuses to boot on a
    tampered/expired key. Here we just map that verified payload into the License object the
    metering/quota layer consumes — so a real Team/Enterprise key is actually enforced.
    """
    info = dict(getattr(config, "LICENSE_INFO", None) or {})
    tier = str(info.get("tier", "Community"))
    plan = tier.lower()
    defaults = PLANS.get(plan, PLANS["community"])
    seats = int(info.get("seats", defaults["seats"]))
    scans = int(info.get("scans_per_month", defaults["max_scans_per_month"]))
    signed = bool(getattr(config, "LICENSE_KEY", "")) and bool(getattr(config, "LICENSE_OK", False))
    return License(
        plan=plan,
        customer=info.get("customer", "Community (unlicensed)"),
        license_id=info.get("license_id", plan),
        seats=seats,
        max_scans_per_month=scans,
        features=list(defaults["features"]),
        issued=_iso_from_ts(info.get("issued_at")) if info.get("issued_at") else "",
        expires=_iso_from_ts(info.get("expires_at")) if info.get("expires_at") else "",
        signed=signed,
    )
