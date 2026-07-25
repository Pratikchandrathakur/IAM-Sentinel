"""
Normalized Finding schema — the shared ground-truth foundation for every analyzer.

The core principle of the engine: analyzers emit *verifiable* Findings produced by
deterministic parsers and rule engines. The LLM layer only ever reasons over these
Findings — it never invents them. This makes results reproducible, citable, dedupable,
and measurable (precision/recall against fixtures).

This module is intentionally dependency-free (pure stdlib) so it can be imported by
any analyzer, test, or CLI without pulling in torch/llama-index.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


def sha256_hex(data) -> str:
    """SHA-256 of the exact scanned bytes, for tamper-evident provenance."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        return {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }[self]


class Confidence(str, Enum):
    """How the finding was established.

    CERTAIN  -> deterministic parse/rule match, no interpretation needed.
    FIRM     -> deterministic match that depends on context we cannot fully see.
    TENTATIVE-> heuristic; benefits from human/LLM confirmation.
    """
    CERTAIN = "CERTAIN"
    FIRM = "FIRM"
    TENTATIVE = "TENTATIVE"


@dataclass
class Finding:
    """A single, verifiable security finding.

    `rule_id` + `location` + `evidence` form the natural identity used for dedup and
    for diffing one scan against the next.
    """
    rule_id: str                     # stable machine id, e.g. "IAM.WILDCARD_ACTION"
    title: str                       # short human title
    severity: Severity
    domain: str                      # "iam", "web", "network", "web3", "dfir", ...
    description: str                 # what the deterministic engine actually observed
    evidence: str = ""               # the exact artifact substring / statement that triggered it
    location: str = ""               # where in the artifact (statement Sid, line, file, etc.)
    confidence: Confidence = Confidence.CERTAIN
    remediation_hint: str = ""       # deterministic, tool-authored fix guidance (not LLM prose)
    references: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        """Stable id for dedup/diffing across scans."""
        basis = f"{self.domain}|{self.rule_id}|{self.location}|{self.evidence}"
        return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["confidence"] = self.confidence.value
        d["fingerprint"] = self.fingerprint
        return d


@dataclass
class ScanResult:
    """The full deterministic output for one artifact, before any LLM narrative."""
    domain: str
    target: str = ""                 # what was scanned (filename, "pasted policy", etc.)
    findings: list[Finding] = field(default_factory=list)
    parse_errors: list[str] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)
    # Reproducibility / audit provenance — stamped so any report can be traced to the
    # exact engine + rule pack that produced it.
    engine_version: str = ""
    ruleset_version: str = ""
    scanned_at: str = ""             # ISO-8601 UTC
    artifact_sha256: str = ""        # digest of the exact bytes that were scanned

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def deduped(self) -> list[Finding]:
        seen: set[str] = set()
        out: list[Finding] = []
        for f in sorted(self.findings, key=lambda x: x.severity.rank, reverse=True):
            if f.fingerprint in seen:
                continue
            seen.add(f.fingerprint)
            out.append(f)
        return out

    @property
    def finding_count(self) -> int:
        return len(self.deduped())

    @property
    def highest_severity(self) -> Severity:
        if not self.findings:
            return Severity.INFO
        return max((f.severity for f in self.findings), key=lambda s: s.rank)

    def severity_counts(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.deduped():
            counts[f.severity.value] += 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        deduped = self.deduped()
        return {
            "domain": self.domain,
            "target": self.target,
            "highest_severity": self.highest_severity.value,
            "severity_counts": self.severity_counts(),
            "finding_count": len(deduped),
            "findings": [f.to_dict() for f in deduped],
            "parse_errors": self.parse_errors,
            "stats": self.stats,
            "engine_version": self.engine_version,
            "ruleset_version": self.ruleset_version,
            "scanned_at": self.scanned_at,
            "artifact_sha256": self.artifact_sha256,
        }

    def to_evidence_block(self) -> str:
        """Compact, deterministic rendering fed to the LLM as GROUND TRUTH.

        The LLM is instructed to reason only over these lines and never to add findings
        that are not present here.
        """
        deduped = self.deduped()
        if not deduped:
            return "No deterministic findings. The artifact parsed cleanly with no rule matches."
        lines = []
        for i, f in enumerate(deduped, 1):
            lines.append(
                f"{i}. [{f.severity.value}] ({f.rule_id}, confidence={f.confidence.value}) {f.title}\n"
                f"   Location: {f.location or 'n/a'}\n"
                f"   Observed: {f.description}\n"
                f"   Evidence: {f.evidence or 'n/a'}\n"
                f"   Fix hint: {f.remediation_hint or 'n/a'}"
            )
        return "\n".join(lines)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)
