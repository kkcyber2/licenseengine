"""SPDX licence-expression parsing.

Most tooling treats a licence field as a single opaque string, which is wrong in a
way that matters: ``(MIT OR GPL-3.0)`` and ``MIT AND GPL-3.0`` are completely
different obligations, and a string comparison cannot tell them apart.

This module implements the SPDX 2.3 expression grammar (the subset that appears in
real package manifests) as a recursive-descent parser:

    expression  := compound
    compound    := simple ( ("AND" | "OR") simple )*
    simple      := "(" compound ")" | license-id ["+"] ["WITH" exception]

``AND`` binds tighter than ``OR``, which is what makes
``A OR B AND C`` parse as ``A OR (B AND C)``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

__all__ = [
    "LicenseExpressionError",
    "Node",
    "LicenseNode",
    "AndNode",
    "OrNode",
    "parse_expression",
    "walk_licenses",
    "evaluate_ids",
]


class LicenseExpressionError(ValueError):
    """Raised when a licence expression cannot be parsed.

    An unparseable expression is reported as a finding rather than assumed to be
    permissive; guessing in the permissive direction is how compliance breaches
    happen.
    """


@dataclass(frozen=True)
class Node:
    """Base class for expression nodes."""


@dataclass(frozen=True)
class LicenseNode(Node):
    """A single licence identifier, e.g. ``Apache-2.0`` or ``GPL-2.0+``."""

    identifier: str
    or_later: bool = False
    exception: str | None = None

    def __str__(self) -> str:
        out = self.identifier
        if self.or_later:
            out += "+"
        if self.exception:
            out += f" WITH {self.exception}"
        return out


@dataclass(frozen=True)
class AndNode(Node):
    """Every operand applies simultaneously."""

    operands: tuple[Node, ...]

    def __str__(self) -> str:
        return " AND ".join(
            f"({o})" if isinstance(o, OrNode) else str(o) for o in self.operands
        )


@dataclass(frozen=True)
class OrNode(Node):
    """The licensee may pick one operand."""

    operands: tuple[Node, ...]

    def __str__(self) -> str:
        return " OR ".join(str(o) for o in self.operands)


# SPDX ids are alnum with dots and dashes, optionally suffixed with ``-only`` /
# ``-or-later``. Exceptions follow the same shape. We keep the token set narrow so a
# free-text value ("see LICENSE") fails loudly instead of parsing as an id.
_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.\-]*")
_TOKEN_RE = re.compile(
    r"\s*(?:"
    r"(?P<lparen>\()"
    r"|(?P<rparen>\))"
    r"|(?P<and>\bAND\b)"
    r"|(?P<or>\bOR\b)"
    r"|(?P<with>\bWITH\b)"
    r"|(?P<id>[A-Za-z0-9][A-Za-z0-9.\-]*\+?)"
    r")"
)

# A bare identifier that is really prose. Checked after tokenising so the error can
# point at the offending word.
_REJECT_WORDS = {
    "see", "license", "licence", "proprietary", "unknown", "custom", "none", "n/a",
    "and", "or", "the", "file", "included", "terms",
}


def _tokenize(text: str) -> list[tuple[str, str]]:
    tokens: list[tuple[str, str]] = []
    pos = 0
    length = len(text)
    while pos < length:
        if text[pos].isspace():
            pos += 1
            continue
        m = _TOKEN_RE.match(text, pos)
        if not m or m.end() == pos:
            raise LicenseExpressionError(
                f"unexpected character {text[pos]!r} at offset {pos} in {text!r}"
            )
        kind = m.lastgroup
        assert kind is not None
        tokens.append((kind, m.group(kind)))
        pos = m.end()
    return tokens


class _Parser:
    def __init__(self, tokens: list[tuple[str, str]], source: str) -> None:
        self._tokens = tokens
        self._pos = 0
        self._source = source

    def _peek(self) -> tuple[str, str] | None:
        return self._tokens[self._pos] if self._pos < len(self._tokens) else None

    def _take(self) -> tuple[str, str]:
        tok = self._peek()
        if tok is None:
            raise LicenseExpressionError(
                f"unexpected end of expression in {self._source!r}"
            )
        self._pos += 1
        return tok

    def parse(self) -> Node:
        if not self._tokens:
            raise LicenseExpressionError("empty licence expression")
        node = self._parse_or()
        if self._peek() is not None:
            kind, value = self._peek()  # type: ignore[misc]
            raise LicenseExpressionError(
                f"unexpected {value!r} after complete expression in {self._source!r}"
            )
        return node

    def _parse_or(self) -> Node:
        operands = [self._parse_and()]
        while (tok := self._peek()) and tok[0] == "or":
            self._take()
            operands.append(self._parse_and())
        return operands[0] if len(operands) == 1 else OrNode(tuple(operands))

    def _parse_and(self) -> Node:
        operands = [self._parse_atom()]
        while (tok := self._peek()) and tok[0] == "and":
            self._take()
            operands.append(self._parse_atom())
        return operands[0] if len(operands) == 1 else AndNode(tuple(operands))

    def _parse_atom(self) -> Node:
        tok = self._take()
        kind, value = tok
        if kind == "lparen":
            inner = self._parse_or()
            closing = self._peek()
            if closing is None or closing[0] != "rparen":
                raise LicenseExpressionError(
                    f"unbalanced parenthesis in {self._source!r}"
                )
            self._take()
            return inner
        if kind == "id":
            return self._parse_license(value)
        raise LicenseExpressionError(
            f"expected a licence id or '(' but found {value!r} in {self._source!r}"
        )

    def _parse_license(self, raw: str) -> LicenseNode:
        or_later = raw.endswith("+")
        identifier = raw[:-1] if or_later else raw

        if identifier.lower() in _REJECT_WORDS:
            raise LicenseExpressionError(
                f"{identifier!r} is not an SPDX licence id in {self._source!r}"
            )
        if not _ID_RE.fullmatch(identifier):
            raise LicenseExpressionError(
                f"malformed licence id {identifier!r} in {self._source!r}"
            )

        exception = None
        nxt = self._peek()
        if nxt and nxt[0] == "with":
            self._take()
            exc_tok = self._take()
            if exc_tok[0] != "id":
                raise LicenseExpressionError(
                    f"expected an exception id after WITH in {self._source!r}"
                )
            exception = exc_tok[1]

        return LicenseNode(identifier, or_later=or_later, exception=exception)


def parse_expression(text: str) -> Node:
    """Parse an SPDX licence expression into a node tree.

    Raises :class:`LicenseExpressionError` for anything that is not a well-formed
    expression. Callers decide whether that is a warning or a hard failure.
    """
    if text is None:
        raise LicenseExpressionError("licence expression is None")
    cleaned = text.strip()
    if not cleaned:
        raise LicenseExpressionError("licence expression is empty")
    return _Parser(_tokenize(cleaned), cleaned).parse()


def walk_licenses(node: Node) -> list[LicenseNode]:
    """Every :class:`LicenseNode` in the tree, left to right, without duplicates."""
    seen: set[str] = set()
    out: list[LicenseNode] = []

    def visit(n: Node) -> None:
        if isinstance(n, LicenseNode):
            key = str(n)
            if key not in seen:
                seen.add(key)
                out.append(n)
        elif isinstance(n, (AndNode, OrNode)):
            for child in n.operands:
                visit(child)

    visit(node)
    return out


def evaluate_ids(node: Node, acceptable: set[str]) -> bool:
    """Does the expression offer at least one acceptable path?

    ``OR`` succeeds when any branch does (the licensee picks), ``AND`` only when all
    do. This is the function that makes ``(MIT OR GPL-3.0)`` shippable under an
    MIT-only policy while ``MIT AND GPL-3.0`` is not.
    """
    if isinstance(node, LicenseNode):
        return node.identifier in acceptable or (
            node.or_later and node.identifier in acceptable
        )
    if isinstance(node, OrNode):
        return any(evaluate_ids(o, acceptable) for o in node.operands)
    if isinstance(node, AndNode):
        return all(evaluate_ids(o, acceptable) for o in node.operands)
    raise LicenseExpressionError(f"unknown node type {type(node).__name__}")
