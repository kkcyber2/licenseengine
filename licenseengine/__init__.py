"""License engine: evaluate a dependency graph against a policy and report obligations."""

from .model import Component, License, Policy, Finding, Report
from .spdx import parse_expression, walk_licenses, LicenseExpressionError
from .rules import LicenseDB, load_builtin
from .audit import audit, summarize

__all__ = [
    "Component",
    "License",
    "Policy",
    "Finding",
    "Report",
    "parse_expression",
    "walk_licenses",
    "LicenseExpressionError",
    "LicenseDB",
    "load_builtin",
    "audit",
    "summarize",
]

__version__ = "1.0.0"
