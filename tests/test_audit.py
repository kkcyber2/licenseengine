"""Policy evaluation: what gets flagged and why."""

import pytest

from licenseengine.audit import audit, summarize
from licenseengine.model import Component, Policy, Severity
from licenseengine.rules import load_builtin


def comp(name, lic, direct=True, depth=0):
    return Component(name=name, license_expression=lic, direct=direct, depth=depth)


def codes(report):
    return {f.code for f in report.findings}


def by_code(report, code):
    return [f for f in report.findings if f.code == code]


class TestPermissiveLicences:
    def test_mit_passes_cleanly(self):
        report = audit([comp("left-pad", "MIT")])
        assert report.passed
        assert report.verdict is Severity.NOTICE  # attribution is still required
        assert report.blocking == []

    def test_attribution_notice_is_raised(self):
        report = audit([comp("left-pad", "MIT")])
        assert "attribution-required" in codes(report)

    def test_attribution_can_be_disabled(self):
        policy = Policy(require_attribution=False)
        report = audit([comp("left-pad", "MIT")], policy)
        assert "attribution-required" not in codes(report)

    def test_public_domain_skips_attribution(self):
        report = audit([comp("tiny", "0BSD")])
        assert "attribution-required" not in codes(report)

    def test_apache_requires_notice_file(self):
        report = audit([comp("okhttp", "Apache-2.0")])
        assert "notice-file" in codes(report)
        assert report.passed


class TestCopyleft:
    def test_strong_copyleft_blocks_by_default(self):
        report = audit([comp("readline", "GPL-3.0-only")])
        assert not report.passed
        assert "copyleft-strong" in codes(report)

    def test_agpl_blocks_by_default(self):
        report = audit([comp("mongo-driver", "AGPL-3.0")])
        assert not report.passed
        assert "copyleft-network" in codes(report)

    def test_agpl_needs_its_own_flag(self):
        """Allowing plain copyleft must not silently allow network copyleft."""
        policy = Policy(allow_copyleft=True)
        report = audit([comp("svc", "AGPL-3.0")], policy)
        assert not report.passed

    def test_agpl_allowed_when_network_flag_set(self):
        policy = Policy(allow_copyleft=True, allow_network_copyleft=True)
        report = audit([comp("svc", "AGPL-3.0")], policy)
        assert report.passed

    def test_weak_copyleft_warns_without_blocking(self):
        """MPL/LGPL usually depend on linking, which a scanner cannot see."""
        report = audit([comp("mpl-lib", "MPL-2.0")])
        assert report.passed
        assert "copyleft-weak" in codes(report)
        assert report.verdict is Severity.WARN

    def test_weak_copyleft_downgrades_to_a_notice_once_allowed(self):
        policy = Policy(allow_copyleft=True)
        report = audit([comp("mpl-lib", "MPL-2.0")], policy)
        assert report.passed
        weak = by_code(report, "copyleft-weak")[0]
        assert weak.severity is Severity.NOTICE
        assert report.verdict is Severity.NOTICE

    def test_strong_copyleft_allowed_explicitly(self):
        report = audit([comp("gpl-tool", "GPL-3.0-only")], Policy(allow_copyleft=True))
        assert report.passed

    def test_sspl_is_network_copyleft_and_not_osi(self):
        report = audit([comp("db", "SSPL-1.0")])
        assert not report.passed
        assert "copyleft-network" in codes(report)


class TestExpressions:
    def test_or_with_a_permissive_branch_passes_but_asks_for_a_choice(self):
        report = audit([comp("dual", "(MIT OR GPL-3.0)")])
        assert report.passed, "the licensee may elect MIT"
        assert "license-choice" in codes(report)

    def test_and_with_copyleft_blocks(self):
        report = audit([comp("both", "MIT AND GPL-3.0")])
        assert not report.passed
        assert "copyleft-strong" in codes(report)

    def test_or_with_two_copyleft_branches_blocks(self):
        report = audit([comp("bad", "GPL-3.0 OR AGPL-3.0")])
        assert not report.passed

    def test_and_of_two_permissive_licences_passes(self):
        report = audit([comp("dual", "MIT AND Apache-2.0")])
        assert report.passed

    def test_elected_branch_is_named(self):
        report = audit([comp("dual", "(MIT OR GPL-3.0)")])
        choice = by_code(report, "license-choice")[0]
        assert "MIT" in choice.message


class TestUnknownAndMissing:
    def test_missing_licence_blocks(self):
        report = audit([comp("mystery", "")])
        assert not report.passed
        assert "license-missing" in codes(report)

    def test_unknown_id_blocks_by_default(self):
        report = audit([comp("weird", "Frobnicate-1.0")])
        assert not report.passed
        assert "license-unknown" in codes(report)

    def test_unknown_can_be_allowed(self):
        report = audit([comp("weird", "Frobnicate-1.0")], Policy(allow_unknown=True))
        assert report.passed

    def test_prose_licence_blocks_as_unparseable(self):
        report = audit([comp("legacy", "see the LICENSE file")])
        assert not report.passed
        assert "license-unparseable" in codes(report)

    def test_no_finding_for_component_that_is_fine(self):
        report = audit([comp("fine", "MIT")])
        assert not any(f.severity is Severity.FAIL for f in report.findings)


class TestDenylist:
    def test_denylist_overrides_allowlist(self):
        """A licence on both lists must be rejected; deny wins."""
        policy = Policy(allowed=("MIT", "Apache-2.0"), denied=("Apache-2.0",))
        report = audit([comp("x", "Apache-2.0")], policy)
        assert not report.passed
        assert "license-denied" in codes(report)

    def test_denylist_hits_a_branch_of_an_or(self):
        policy = Policy(denied=("GPL-3.0",))
        report = audit([comp("x", "(MIT OR GPL-3.0)")], policy)
        assert report.passed, "MIT is still electable"


class TestAllowlist:
    def test_unlisted_permissive_licence_is_a_notice(self):
        policy = Policy(allowed=("MIT",))
        report = audit([comp("x", "ISC")], policy)
        assert report.passed
        assert "license-not-listed" in codes(report)

    def test_listed_licence_has_no_not_listed_notice(self):
        policy = Policy(allowed=("MIT",))
        report = audit([comp("x", "MIT")], policy)
        assert "license-not-listed" not in codes(report)

    def test_narrow_allowlist_does_not_make_mit_illegal(self):
        """An empty/odd allowlist must not turn a permissive licence into a failure."""
        policy = Policy(allowed=())
        report = audit([comp("x", "MIT")], policy)
        assert report.passed


class TestDepth:
    def test_transitive_component_records_its_depth(self):
        report = audit([comp("deep", "GPL-3.0-only", direct=False, depth=4)])
        finding = by_code(report, "copyleft-strong")[0]
        assert finding.depth == 4
        assert finding.direct is False

    def test_depth_limit_warns(self):
        policy = Policy(max_depth=2)
        report = audit([comp("deep", "MIT", direct=False, depth=5)], policy)
        assert "depth-exceeded" in codes(report)

    def test_depth_within_limit_does_not_warn(self):
        policy = Policy(max_depth=5)
        report = audit([comp("ok", "MIT", direct=False, depth=3)], policy)
        assert "depth-exceeded" not in codes(report)


class TestAliases:
    @pytest.mark.parametrize("alias,spdx", [
        ("Apache 2.0", "Apache-2.0"),
        ("apache2", "Apache-2.0"),
        ("GPLv3", "GPL-3.0"),
        ("BSD", "BSD-3-Clause"),
        ("mit", "MIT"),
        ("ISC License", "ISC"),
    ])
    def test_common_spellings_normalise(self, alias, spdx):
        assert load_builtin().normalise(alias) == spdx

    def test_unknown_alias_is_left_alone(self):
        assert load_builtin().normalise("Totally-Made-Up") == "Totally-Made-Up"


class TestReport:
    def test_verdict_is_the_worst_finding(self):
        report = audit([
            comp("a", "MIT"),
            comp("b", "GPL-3.0-only"),
        ])
        assert report.verdict is Severity.FAIL

    def test_counts_add_up(self):
        report = audit([comp("a", "MIT"), comp("b", "GPL-3.0-only")])
        assert sum(report.counts().values()) == len(report.findings)

    def test_empty_audit_is_ok(self):
        report = audit([])
        assert report.passed
        assert report.verdict is Severity.OK
        assert report.components == 0

    def test_to_dict_is_json_serialisable(self):
        import json

        report = audit([comp("a", "GPL-3.0-only")])
        payload = json.loads(json.dumps(report.to_dict()))
        assert payload["verdict"] == "fail"
        assert payload["passed"] is False

    def test_obligations_group_by_component(self):
        report = audit([comp("a", "MIT"), comp("b", "Apache-2.0")])
        assert set(report.obligations) == {"a", "b"}
        assert "notice-file" in report.obligations["b"]

    def test_summarize_mentions_the_blocking_component(self):
        report = audit([comp("badlib", "GPL-3.0-only")])
        text = summarize(report)
        assert "badlib" in text
        assert "FAIL" in text

    def test_summary_does_not_explode_on_many_blockers(self):
        report = audit([comp(f"lib{i}", "GPL-3.0-only") for i in range(20)])
        text = summarize(report)
        assert "+15 more" in text
