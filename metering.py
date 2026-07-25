"""
IAM Sentinel — usage metering & quota enforcement.

Turns a verified License + the audit store into enforceable entitlements:
  * per-month scan quota (max_scans_per_month; 0 == unlimited)
  * seat limit (distinct actors active this calendar month; 0 == unlimited)

Enforcement is deliberately fail-open-to-Community rather than crashing: an over-quota
request is refused with a clear, actionable error, but the service itself stays healthy.
"""

from datetime import datetime, timezone


class QuotaExceeded(RuntimeError):
    """Raised when a request would exceed the licensed seat or scan quota."""
    def __init__(self, message, kind):
        super().__init__(message)
        self.kind = kind          # "scans" | "seats"


def current_month_start_iso() -> str:
    now = datetime.now(timezone.utc)
    return now.replace(day=1, hour=0, minute=0, second=0, microsecond=0).isoformat(timespec="seconds")


def usage_summary(store, license) -> dict:
    since = current_month_start_iso()
    scans = store.count_scans_since(since)
    actors = store.distinct_actors_since(since)
    return {
        "period_start": since,
        "plan": license.plan,
        "scans_used": scans,
        "scans_limit": license.max_scans_per_month,      # 0 == unlimited
        "scans_remaining": (None if license.max_scans_per_month == 0
                            else max(0, license.max_scans_per_month - scans)),
        "seats_used": len(actors),
        "seats_limit": license.seats,                    # 0 == unlimited
        "active_actors": actors,
        "license_expired": license.is_expired,
    }


def enforce_quota(store, license, actor: str) -> None:
    """Raise QuotaExceeded if running one more scan as `actor` would breach the license."""
    since = current_month_start_iso()

    # Seat limit: allow existing actors freely; only block a NEW actor beyond the seat count.
    if license.seats and license.seats > 0:
        actors = set(store.distinct_actors_since(since))
        if actor not in actors and len(actors) >= license.seats:
            raise QuotaExceeded(
                f"Seat limit reached for plan '{license.plan}' ({license.seats} seats). "
                f"Active this month: {sorted(actors)}. Upgrade or free a seat.",
                kind="seats")

    # Scan quota.
    if license.max_scans_per_month and license.max_scans_per_month > 0:
        used = store.count_scans_since(since)
        if used >= license.max_scans_per_month:
            raise QuotaExceeded(
                f"Monthly scan quota reached for plan '{license.plan}' "
                f"({license.max_scans_per_month} scans). Resets next month; upgrade for more.",
                kind="scans")
