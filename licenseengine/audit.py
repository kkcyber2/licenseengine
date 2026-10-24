"""The audit: turn a component list plus a policy into findings.

The evaluation is expression-aware. For each component we ask the SPDX tree
"is there an acceptable path?", which is exactly the question a lawyer asks.
Three outcomes are possible:

* **acceptable** -- every path is allowed.
* **acceptable via choice** -- a disjunction gives us an allowed branch. Worth a
  notice, because the team must actually make that choice deliberately rather
  than let a tool pick.
* **not acceptable** -- no path is allowed.

Licences that are permissive but absent from the allowlist are *permitted* yet
reported: the policy is the record of what legal actually reviewed, and an
unlisted package slipped past that review.
"""

from __future__ import annotations

from .model import Component, Finding, License, Policy, Report, Severity
from .rules import LicenseDB, load_builtin
from .spdx import (
    AndNode,
    LicenseExpressionError,
    LicenseNode,
    Node,
    OrNode,
    parse_expression,
    walk_licenses,
)

_REMEDY = {
    "unknown": "Add the licence to the catalogue, or replace the dependency.",
    "denied": "Remove the dependency or obtain a commercial licence from its author.",
    "copyleft": "Replace it, isolate it behind a process boundary, or get legal sign-off.",
    "network": "Replace it, or confirm the network-use obligation does not apply.",
    "not_listed": "Add it to the allowlist after review, or pick a different package.",
    "attribution": "Include the copyright notice in your distribution.",
    "notice_file": "Ship the dependency's NOTICE file with your distribution.",
    "too_deep": "Reduce the dependency depth, or accept it explicitly in the policy.",
    "unparseable": "Fix the manifest so it carries a valid SPDX expression.",
    "not_osi": "Confirm the licence terms permit commercial use.",
    "weak": "Confirm the linking arrangement keeps your code out of scope.",
}

# How a rejection of each copyleft level should be scored. Weak copyleft is a
# warning rather than a block: it usually depends on how the library is linked,
# which a scanner cannot know.
_REJECT_SEVERITY = {
    "weak": Severity.WARN,
    "strong": Severity.FAIL,
    "network": Severity.FAIL,
    "unknown": Severity.FAIL,
    "denied": Severity.FAIL,
}


def _leaf_permitted(
    leaf: LicenseNode, policy: Policy, db: LicenseDB
) -> tuple[bool, str]:
    """Is this single licence acceptable, and on what grounds?

    Returns ``(permitted, reason)`` where reason is one of ``allowed``, ``denied``,
    ``unknown``, ``network``, ``strong``, ``weak`` or ``permissive-unlisted``.
    """
    ident = db.normalise(leaf.identifier)

    if ident in {db.normalise(d) for d in policy.denied}:
        return False, "denied"

    lic = db.get(ident)
    if lic is None:
        return policy.allow_unknown, "unknown"

    if ident in {db.normalise(a) for a in policy.allowed}:
        return True, "allowed"

    if lic.copyleft == "network":
        return policy.allow_network_copyleft, "network"
    if lic.copyleft == "strong":
        return policy.allow_copyleft, "strong"
    if lic.copyleft == "weak":
        # Weak copyleft (MPL, LGPL, EPL) attaches to the file or library rather than
        # the whole product, so it is never a hard block -- it is a disclosure duty.
        return True, "weak"

    # Permissive and not explicitly allowed: permitted, but worth flagging.
    return True, "permissive-unlisted"


def _path_permitted(
    node: Node, policy: Policy, db: LicenseDB
) -> tuple[bool, list[str]]:
    """Can the expression be satisfied? Also returns the blocking reasons.

    ``OR`` needs one viable branch (the licensee chooses); ``AND`` needs all of
    them. Blocking reasons are collected so the report can explain *why*.
    """
    if isinstance(node, LicenseNode):
        ok, reason = _leaf_permitted(node, policy, db)
        return ok, ([] if ok else [reason])
    if isinstance(node, OrNode):
        results = [_path_permitted(o, policy, db) for o in node.operands]
        if any(ok for ok, _ in results):
            return True, []
        reasons = [r for _, rs in results for r in rs]
        return False, reasons
    if isinstance(node, AndNode):
        results = [_path_permitted(o, policy, db) for o in node.operands]
        reasons = [r for _, rs in results for r in rs]
        return all(ok for ok, _ in results), reasons
    raise LicenseExpressionError(f"unknown node type {type(node).__name__}")


def _check_component(
    component: Component, policy: Policy, db: LicenseDB
) -> list[Finding]:
    findings: list[Finding] = []
    raw = (component.license_expression or "").strip()

    if not raw:
        findings.append(Finding(
            component=component.name, license_id="", severity=Severity.FAIL,
            code="license-missing",
            message=f"{component.name} declares no licence",
            direct=component.direct, depth=component.depth,
            remedy=_REMEDY["unknown"],
        ))
        return findings

    try:
        tree: Node = parse_expression(raw)
    except LicenseExpressionError as exc:
        findings.append(Finding(
            component=component.name, license_id=raw, severity=Severity.FAIL,
            code="license-unparseable", message=str(exc),
            direct=component.direct, depth=component.depth,
            remedy=_REMEDY["unparseable"],
        ))
        return findings

    if policy.max_depth and component.depth > policy.max_depth:
        findings.append(Finding(
            component=component.name, license_id=raw, severity=Severity.WARN,
            code="depth-exceeded",
            message=(f"{component.name} sits at depth {component.depth}, beyond the "
                     f"policy limit of {policy.max_depth}"),
            direct=component.direct, depth=component.depth,
            remedy=_REMEDY["too_deep"],
        ))

    leaves = walk_licenses(tree)
    resolved: dict[str, License | None] = {
        str(leaf): db.get(leaf.identifier) for leaf in leaves
    }

    ok, reasons = _path_permitted(tree, policy, db)
    if not ok:
        findings.extend(_rejection_findings(component, raw, reasons, leaves, db))
        return findings

    # The expression is satisfiable. Record the softer, still-real obligations.
    findings.extend(
        _obligation_findings(component, raw, tree, leaves, resolved, policy, db)
    )
    return findings


def _rejection_findings(
    component: Component,
    raw: str,
    reasons: list[str],
    leaves: list[LicenseNode],
    db: LicenseDB,
) -> list[Finding]:
    """Build the findings for an expression with no acceptable path."""
    out: list[Finding] = []

    unknown = [
        leaf for leaf in leaves
        if db.get(leaf.identifier) is None
    ]
    if unknown:
        names = ", ".join(sorted({leaf.identifier for leaf in unknown}))
        out.append(Finding(
            component=component.name, license_id=raw, severity=Severity.FAIL,
            code="license-unknown",
            message=(f"{component.name} uses licence id(s) not in the catalogue: "
                     f"{names}"),
            direct=component.direct, depth=component.depth,
            remedy=_REMEDY["unknown"],
        ))

    if "denied" in reasons:
        out.append(Finding(
            component=component.name, license_id=raw, severity=Severity.FAIL,
            code="license-denied",
            message=f"{component.name} ({raw}) is on the policy denylist",
            direct=component.direct, depth=component.depth,
            remedy=_REMEDY["denied"],
        ))

    for level in ("network", "strong", "weak"):
        if level not in reasons:
            continue
        out.append(Finding(
            component=component.name, license_id=raw,
            severity=_REJECT_SEVERITY[level],
            code=f"copyleft-{level}",
            message=(f"{component.name} ({raw}) is {level} copyleft and the policy "
                     f"does not permit it"),
            direct=component.direct, depth=component.depth,
            remedy=_REMEDY["copyleft" if level != "network" else "network"],
        ))

    return out


def _obligation_findings(
    component: Component,
    raw: str,
    tree: Node,
    leaves: list[LicenseNode],
    resolved: dict[str, License | None],
    policy: Policy,
    db: LicenseDB,
) -> list[Finding]:
    """Notices that apply once the licence itself is acceptable."""
    out: list[Finding] = []

    # A disjunction means a human must elect a branch; that is a decision to record.
    if isinstance(tree, OrNode):
        acceptable = [
            str(o) for o in tree.operands
            if isinstance(o, LicenseNode) and _leaf_permitted(o, policy, db)[0]
        ]
        if acceptable:
            out.append(Finding(
                component=component.name, license_id=raw, severity=Severity.NOTICE,
                code="license-choice",
                message=(f"{component.name} offers {raw}; elect {acceptable[0]} "
                         f"explicitly so the choice is recorded"),
                direct=component.direct, depth=component.depth,
                remedy="Record the elected licence in your NOTICE file.",
            ))

    unlisted = [
        str(leaf) for leaf in leaves
        if _leaf_permitted(leaf, policy, db)[1] == "permissive-unlisted"
    ]
    if unlisted:
        out.append(Finding(
            component=component.name, license_id=raw, severity=Severity.NOTICE,
            code="license-not-listed",
            message=(f"{component.name} uses {', '.join(sorted(unlisted))}, which no "
                     f"one has added to the allowlist"),
            direct=component.direct, depth=component.depth,
            remedy=_REMEDY["not_listed"],
        ))

    weak = [
        str(leaf) for leaf in leaves
        if (lic := resolved[str(leaf)]) is not None and lic.copyleft == "weak"
    ]
    if weak:
        # Accepting copyleft turns weak obligations from a warning into a recorded
        # notice: the policy has already made the decision, but the obligation to
        # disclose still stands.
        out.append(Finding(
            component=component.name, license_id=raw,
            severity=Severity.NOTICE if policy.allow_copyleft else Severity.WARN,
            code="copyleft-weak",
            message=(f"{component.name} uses {', '.join(sorted(weak))}; weak copyleft "
                     f"obligations depend on how you link it"),
            direct=component.direct, depth=component.depth,
            remedy=_REMEDY["weak"],
        ))

    if policy.require_attribution:
        needs_attr = [
            str(leaf) for leaf in leaves
            if (lic := resolved[str(leaf)]) is not None and lic.attribution_required
        ]
        if needs_attr:
            out.append(Finding(
                component=component.name, license_id=raw, severity=Severity.NOTICE,
                code="attribution-required",
                message=(f"{component.name} requires its copyright notice in your "
                         f"distribution"),
                direct=component.direct, depth=component.depth,
                remedy=_REMEDY["attribution"],
            ))

    for leaf in leaves:
        lic = resolved[str(leaf)]
        if lic is not None and lic.notice_file_required:
            out.append(Finding(
                component=component.name, license_id=str(leaf),
                severity=Severity.NOTICE, code="notice-file",
                message=f"{component.name} ships a NOTICE file that must be propagated",
                direct=component.direct, depth=component.depth,
                remedy=_REMEDY["notice_file"],
            ))

    for leaf in leaves:
        lic = resolved[str(leaf)]
        if lic is not None and not lic.osi_approved:
            out.append(Finding(
                component=component.name, license_id=str(leaf),
                severity=Severity.WARN, code="not-osi",
                message=(f"{component.name} uses {leaf.identifier}, which is not "
                         f"OSI-approved"),
                direct=component.direct, depth=component.depth,
                remedy=_REMEDY["not_osi"],
            ))

    return out



def audit(
    components: list[Component],
    policy: Policy | None = None,
    db: LicenseDB | None = None,
) -> Report:
    """Audit every component and return a report."""
    policy = policy or Policy()
    db = db or load_builtin()

    findings: list[Finding] = []
    for component in components:
        findings.extend(_check_component(component, policy, db))

    return Report(
        findings=findings,
        components=len(components),
        obligations=_collect_obligations(findings),
    )


def _collect_obligations(findings: list[Finding]) -> dict[str, list[str]]:
    """Group actionable findings by component, sorted for stable output."""
    out: dict[str, list[str]] = {}
    for f in findings:
        if f.severity in (Severity.NOTICE, Severity.WARN, Severity.FAIL):
            out.setdefault(f.component, []).append(f.code)
    return {k: sorted(set(v)) for k, v in sorted(out.items())}


def summarize(report: Report) -> str:
    """One-paragraph human summary, used by the CLI and the JSON report."""
    counts = report.counts()
    parts = [f"{report.components} component(s) audited"]
    parts.append(f"verdict: {report.verdict.value.upper()}")
    detail = ", ".join(f"{n} {k}" for k, n in counts.items() if n)
    if detail:
        parts.append(detail)
    if report.blocking:
        names = sorted({f.component for f in report.blocking})
        shown = ", ".join(names[:5])
        more = f" (+{len(names) - 5} more)" if len(names) > 5 else ""
        parts.append(f"blocking: {shown}{more}")
    return " | ".join(parts)
