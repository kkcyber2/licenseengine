"""Command line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .audit import audit, summarize
from .model import Policy, Severity
from .readers import ManifestError, read_manifest
from .rules import load_builtin


def _policy_from_args(args: argparse.Namespace) -> Policy:
    policy = Policy()
    if args.allow:
        policy.allowed = tuple(args.allow)
    if args.deny:
        policy.denied = tuple(args.deny)
    policy.allow_copyleft = bool(args.allow_copyleft)
    policy.allow_network_copyleft = bool(args.allow_network_copyleft)
    policy.allow_unknown = bool(args.allow_unknown)
    policy.require_attribution = not args.no_attribution
    if args.max_depth is not None:
        policy.max_depth = args.max_depth
    return policy


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="licenseengine",
        description="Audit a dependency manifest against a licence policy.",
    )
    parser.add_argument("manifest", help="path to package-lock.json, requirements.txt, ...")
    parser.add_argument("--allow", nargs="*", metavar="SPDX",
                        help="replace the allowlist")
    parser.add_argument("--deny", nargs="*", metavar="SPDX",
                        help="always reject these licences")
    parser.add_argument("--allow-copyleft", action="store_true",
                        help="permit strong and weak copyleft")
    parser.add_argument("--allow-network-copyleft", action="store_true",
                        help="permit AGPL-style network copyleft")
    parser.add_argument("--allow-unknown", action="store_true",
                        help="do not fail on licences missing from the catalogue")
    parser.add_argument("--no-attribution", action="store_true",
                        help="skip attribution notices")
    parser.add_argument("--max-depth", type=int, default=None,
                        help="warn about dependencies nested deeper than this")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    parser.add_argument("--quiet", action="store_true", help="only the verdict line")
    parser.add_argument("--check", action="store_true",
                        help="exit non-zero when the policy is violated")
    args = parser.parse_args(argv)

    try:
        components = read_manifest(args.manifest)
    except (ManifestError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    report = audit(components, _policy_from_args(args), load_builtin())

    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=False))
    elif args.quiet:
        print(f"{report.verdict.value.upper()} {report.components} component(s)")
    else:
        _print_human(report)

    if args.check and not report.passed:
        return 1
    return 0


def _print_human(report) -> None:
    print(summarize(report))
    if not report.findings:
        return

    order = {Severity.FAIL: 0, Severity.WARN: 1, Severity.NOTICE: 2, Severity.OK: 3}
    for finding in sorted(report.findings, key=lambda f: (order[f.severity], f.component)):
        tag = finding.severity.value.upper().ljust(6)
        depth = "" if finding.direct else f" [transitive, depth {finding.depth}]"
        print(f"  {tag} {finding.component}{depth}")
        print(f"         {finding.message}")
        if finding.remedy:
            print(f"         fix: {finding.remedy}")


if __name__ == "__main__":
    raise SystemExit(main())
