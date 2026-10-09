"""Deterministic explanation text: the same input always gives the same words."""

from __future__ import annotations

from qlure.correlate.model import Finding, RuleHit
from qlure.correlate.rules import load_config

MAX_EVIDENCE_SHOWN = 4


def _rule_key(hit: RuleHit) -> int:
    return int(hit.rule_id[1:])


def explain_hit(hit: RuleHit) -> str:
    shown = ", ".join(hit.evidence[:MAX_EVIDENCE_SHOWN])
    extra = len(hit.evidence) - MAX_EVIDENCE_SHOWN
    more = f" (+{extra} more)" if extra > 0 else ""
    return (
        f"{hit.rule_id} {hit.name} ({hit.family}, {hit.confidence} confidence): "
        f"{hit.measured}; threshold: {hit.threshold}. Evidence: {shown}{more}."
    )


def explain(finding: Finding) -> str:
    hits = sorted(finding.hits, key=_rule_key)
    if not hits:
        return f"Benign (score {finding.score}): no rule fired."
    families = ", ".join(finding.families)
    count = len(finding.families)
    noun = "family" if count == 1 else "families"
    lines = [
        f"{finding.verdict} (score {finding.score}): {len(hits)} rule(s) fired "
        f"across {count} {noun} ({families})."
    ]
    lines += [f"- {explain_hit(h)}" for h in hits]
    if finding.suppressors:
        names = ", ".join(f"{name} (-{amount})" for name, amount in finding.suppressors)
        lines.append(f"Suppressors applied: {names}.")
    if finding.verdict == "Suspicious" and finding.score >= load_config()["verdicts"]["noteworthy"]:
        lines.append(
            "Held at Suspicious: the score needs two rule families or a high-confidence rule."
        )
    return "\n".join(lines)
