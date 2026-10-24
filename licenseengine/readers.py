"""Read dependency manifests into :class:`Component` lists.

Supported formats are the ones that actually show up in a modern repo:

* ``package-lock.json`` / ``package.json`` (npm)
* ``requirements.txt`` (pip, including ``-e`` and environment markers we ignore)
* ``pyproject.toml`` (PEP 621 ``dependencies`` and Poetry)
* ``go.mod`` (module + require blocks)

The readers are deliberately tolerant of version differences and strict about
missing licence data: a package with no licence field becomes a component with an
empty expression, which the audit reports rather than skips.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .model import Component

__all__ = ["read_manifest", "read_npm", "read_requirements", "read_pyproject", "read_go_mod"]


class ManifestError(ValueError):
    """Raised when a manifest exists but cannot be understood."""


def read_manifest(path: str | Path) -> list[Component]:
    """Dispatch on filename, falling back to structure.

    Exact filenames are the reliable signal, but lockfiles get copied and renamed
    (``demo-lock.json``, ``base.requirements.txt``), so an unrecognised name is
    sniffed rather than rejected.
    """
    p = Path(path)
    if not p.is_file():
        raise ManifestError(f"no such manifest: {p}")
    name = p.name

    if name in ("package-lock.json", "package.json", "npm-shrinkwrap.json"):
        return read_npm(p)
    if name in ("requirements.txt", "requirements-dev.txt"):
        return read_requirements(p)
    if name == "pyproject.toml":
        return read_pyproject(p)
    if name == "go.mod":
        return read_go_mod(p)
    if name.endswith(".txt"):
        return read_requirements(p)

    sniffed = _sniff(p)
    if sniffed is not None:
        return sniffed

    raise ManifestError(
        f"unsupported manifest {name!r}; expected package.json, package-lock.json, "
        f"requirements.txt, pyproject.toml or go.mod"
    )


def _sniff(p: Path) -> list[Component] | None:
    """Detect the format from the file's shape when the name is not conclusive."""
    try:
        text = p.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None

    stripped = text.lstrip()
    if stripped.startswith("{"):
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return None
        if isinstance(data, dict) and (
            "packages" in data or "dependencies" in data or "lockfileVersion" in data
        ):
            return read_npm(p)
        return None

    if stripped.startswith("module ") or "\nrequire (" in text:
        return read_go_mod(p)

    if "[project]" in text or "[tool.poetry]" in text:
        return read_pyproject(p)

    if stripped.startswith("[") or "==" in text or ">=" in text:
        return read_requirements(p)

    return None


def read_npm(path: str | Path) -> list[Component]:
    """npm lockfile (v1 ``dependencies`` tree or v2/v3 ``packages`` map)."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    out: list[Component] = []

    packages = data.get("packages")
    if isinstance(packages, dict):
        for key, meta in packages.items():
            if not key:
                continue  # the root project itself
            if not isinstance(meta, dict) or meta.get("link"):
                continue
            name = meta.get("name") or key.split("node_modules/")[-1]
            lic = meta.get("license", "")
            if isinstance(lic, list):
                lic = " AND ".join(str(x) for x in lic)
            depth = key.count("node_modules/") - 1
            out.append(Component(
                name=name,
                version=str(meta.get("version", "")),
                license_expression=str(lic),
                direct=depth <= 0,
                depth=max(depth, 0),
                ecosystem="npm",
            ))
        return out

    # v1: nested dependency tree
    def walk(deps: dict, depth: int) -> None:
        for name, meta in deps.items():
            if not isinstance(meta, dict):
                continue
            lic = meta.get("license", "")
            if isinstance(lic, list):
                lic = " AND ".join(str(x) for x in lic)
            out.append(Component(
                name=name,
                version=str(meta.get("version", "")),
                license_expression=str(lic),
                direct=depth == 0,
                depth=depth,
                ecosystem="npm",
            ))
            nested = meta.get("dependencies")
            if isinstance(nested, dict):
                walk(nested, depth + 1)

    deps = data.get("dependencies")
    if isinstance(deps, dict):
        walk(deps, 0)
    return out


_REQ_LINE = re.compile(
    r"""
    ^\s*
    (?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)
    \s*
    (?:\[[^\]]*\])?            # extras
    (?:[<>=!~]=?[^;#\s]*)?     # version specifier
    \s*
    (?:;\s*.*)?                # environment marker
    $
    """,
    re.VERBOSE,
)


def read_requirements(path: str | Path) -> list[Component]:
    """pip requirements file.

    Requirements files carry no licence information at all, so every component here
    has an empty expression. That is the honest result: the audit will flag them,
    which is correct -- you cannot prove compliance from a requirements file alone.
    """
    out: list[Component] = []
    for raw in Path(path).read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        # Drop hashes and inline URL fragments.
        line = line.split("--hash", 1)[0].strip()
        m = _REQ_LINE.match(line)
        if not m:
            continue
        out.append(Component(
            name=m.group("name"),
            license_expression="",
            ecosystem="pypi",
        ))
    return out


def read_pyproject(path: str | Path) -> list[Component]:
    """PEP 621 or Poetry dependencies from pyproject.toml.

    Uses ``tomllib`` where available and falls back to a small regex scan, so the
    tool works on Python 3.9 without pulling in a TOML dependency.
    """
    text = Path(path).read_text(encoding="utf-8")
    names: list[str] = []

    try:
        import tomllib  # type: ignore[import-not-found]

        data = tomllib.loads(text)
        project = data.get("project", {})
        for dep in project.get("dependencies", []) or []:
            names.append(_dep_name(str(dep)))
        poetry = data.get("tool", {}).get("poetry", {})
        for dep in (poetry.get("dependencies") or {}):
            if dep.lower() != "python":
                names.append(dep)
        for group in (poetry.get("group") or {}).values():
            for dep in (group.get("dependencies") or {}):
                names.append(dep)
    except Exception:
        # Fallback: scan the dependency arrays by hand.
        in_deps = False
        for raw in text.splitlines():
            stripped = raw.strip()
            if stripped.startswith("dependencies"):
                in_deps = True
                continue
            if in_deps:
                if stripped.startswith("]"):
                    in_deps = False
                    continue
                m = re.match(r'^"([^"]+)"', stripped) or re.match(r"^'([^']+)'", stripped)
                if m:
                    names.append(_dep_name(m.group(1)))

    seen: set[str] = set()
    out: list[Component] = []
    for name in names:
        if name and name.lower() not in seen:
            seen.add(name.lower())
            out.append(Component(name=name, license_expression="", ecosystem="pypi"))
    return out


def _dep_name(spec: str) -> str:
    """``requests[security]>=2.0`` -> ``requests``."""
    return re.split(r"[\[<>=!~; ]", spec.strip(), maxsplit=1)[0]


_GO_REQUIRE = re.compile(r"^\s*(?P<name>[\w.\-/]+)\s+(?P<version>v\S+)", re.MULTILINE)


def read_go_mod(path: str | Path) -> list[Component]:
    """Go modules. Single-line requires and parenthesised blocks."""
    text = Path(path).read_text(encoding="utf-8")
    out: list[Component] = []
    in_block = False

    for raw in text.splitlines():
        line = raw.split("//", 1)[0].strip()
        if not line:
            continue
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        if in_block:
            m = _GO_REQUIRE.match(line)
            if m:
                out.append(Component(
                    name=m.group("name"),
                    version=m.group("version"),
                    license_expression="",
                    ecosystem="golang",
                ))
        elif line.startswith("require "):
            m = _GO_REQUIRE.match(line[len("require "):])
            if m:
                out.append(Component(
                    name=m.group("name"),
                    version=m.group("version"),
                    license_expression="",
                    ecosystem="golang",
                ))
    return out
