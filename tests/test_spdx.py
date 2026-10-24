"""SPDX expression parsing: the grammar and the precedence rules."""

import pytest

from licenseengine.spdx import (
    AndNode,
    LicenseExpressionError,
    LicenseNode,
    OrNode,
    evaluate_ids,
    parse_expression,
    walk_licenses,
)


class TestGrammar:
    def test_single_id(self):
        node = parse_expression("MIT")
        assert isinstance(node, LicenseNode)
        assert node.identifier == "MIT"
        assert not node.or_later
        assert node.exception is None

    def test_or_later_suffix(self):
        node = parse_expression("GPL-2.0+")
        assert isinstance(node, LicenseNode)
        assert node.identifier == "GPL-2.0"
        assert node.or_later is True

    def test_with_exception(self):
        node = parse_expression("GPL-2.0-only WITH Classpath-exception-2.0")
        assert isinstance(node, LicenseNode)
        assert node.identifier == "GPL-2.0-only"
        assert node.exception == "Classpath-exception-2.0"

    def test_whitespace_is_irrelevant(self):
        a = parse_expression("MIT OR Apache-2.0")
        b = parse_expression("  MIT   OR    Apache-2.0  ")
        assert str(a) == str(b)

    def test_case_sensitive_ids_are_preserved(self):
        node = parse_expression("Apache-2.0")
        assert isinstance(node, LicenseNode)
        assert node.identifier == "Apache-2.0"


class TestPrecedence:
    def test_and_binds_tighter_than_or(self):
        """A OR B AND C is A OR (B AND C), never (A OR B) AND C."""
        node = parse_expression("A OR B AND C")
        assert isinstance(node, OrNode)
        assert len(node.operands) == 2
        assert isinstance(node.operands[0], LicenseNode)
        assert isinstance(node.operands[1], AndNode)

    def test_parentheses_override_precedence(self):
        node = parse_expression("(A OR B) AND C")
        assert isinstance(node, AndNode)
        assert isinstance(node.operands[0], OrNode)

    def test_chained_or_flattens(self):
        node = parse_expression("A OR B OR C")
        assert isinstance(node, OrNode)
        assert len(node.operands) == 3

    def test_chained_and_flattens(self):
        node = parse_expression("A AND B AND C")
        assert isinstance(node, AndNode)
        assert len(node.operands) == 3

    def test_nested_parens(self):
        node = parse_expression("((MIT))")
        assert isinstance(node, LicenseNode)
        assert node.identifier == "MIT"

    def test_mixed_nesting_round_trips(self):
        text = "(MIT OR Apache-2.0) AND (BSD-3-Clause OR ISC)"
        assert str(parse_expression(text)) == text


class TestRejections:
    @pytest.mark.parametrize("bad", [
        "",
        "   ",
        "MIT OR",
        "OR MIT",
        "(MIT",
        "MIT)",
        "MIT AND AND Apache-2.0",
        "MIT WHERE foo",
    ])
    def test_malformed_expressions_raise(self, bad):
        with pytest.raises(LicenseExpressionError):
            parse_expression(bad)

    def test_prose_is_rejected_not_guessed(self):
        """'See LICENSE file' must not parse as a licence called 'See'."""
        with pytest.raises(LicenseExpressionError):
            parse_expression("See LICENSE file")

    def test_none_raises(self):
        with pytest.raises(LicenseExpressionError):
            parse_expression(None)  # type: ignore[arg-type]

    def test_unbalanced_paren_reports_position(self):
        with pytest.raises(LicenseExpressionError) as exc:
            parse_expression("(MIT OR Apache-2.0")
        assert "parenthes" in str(exc.value).lower()


class TestWalkAndEvaluate:
    def test_walk_returns_each_leaf_once(self):
        leaves = walk_licenses(parse_expression("MIT OR (MIT AND Apache-2.0)"))
        assert sorted(str(leaf) for leaf in leaves) == ["Apache-2.0", "MIT"]

    def test_walk_order_is_left_to_right(self):
        leaves = walk_licenses(parse_expression("BSD-3-Clause AND Apache-2.0"))
        assert [leaf.identifier for leaf in leaves] == ["BSD-3-Clause", "Apache-2.0"]

    def test_or_succeeds_when_one_branch_is_acceptable(self):
        """The licensee picks, so (MIT OR GPL-3.0) is fine under an MIT-only policy."""
        node = parse_expression("MIT OR GPL-3.0")
        assert evaluate_ids(node, {"MIT"}) is True

    def test_and_requires_every_operand(self):
        node = parse_expression("MIT AND GPL-3.0")
        assert evaluate_ids(node, {"MIT"}) is False

    def test_and_succeeds_when_all_acceptable(self):
        node = parse_expression("MIT AND Apache-2.0")
        assert evaluate_ids(node, {"MIT", "Apache-2.0"}) is True

    def test_or_fails_when_no_branch_acceptable(self):
        node = parse_expression("GPL-3.0 OR AGPL-3.0")
        assert evaluate_ids(node, {"MIT"}) is False

    def test_exception_does_not_widen_acceptance(self):
        """A WITH exception is recorded but does not turn a rejected id into a pass."""
        node = parse_expression("GPL-2.0-only WITH Classpath-exception-2.0")
        assert evaluate_ids(node, {"MIT"}) is False
