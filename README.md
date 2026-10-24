# licenseengine

Audit a dependency manifest against a licence policy and get a verdict you can
defend. This is not a licence scanner that prints a list of names — it parses SPDX
expressions, evaluates them the way the licence actually works, and tells you which
obligation you have to satisfy.

```
$ licenseengine package-lock.json --check
5 component(s) audited | verdict: FAIL | 4 notice, 1 warn, 2 fail | blocking: mongo, some-gpl-tool
  FAIL   mongo
         mongo (SSPL-1.0) is network copyleft and the policy does not permit it
         fix: Replace it, or confirm the network-use obligation does not apply.
  FAIL   some-gpl-tool
         some-gpl-tool (GPL-3.0-only) is strong copyleft and the policy does not permit it
         fix: Replace it, isolate it behind a process boundary, or get legal sign-off.
  WARN   inner [transitive, depth 1]
         inner uses MPL-2.0; weak copyleft obligations depend on how you link it
         fix: Confirm the linking arrangement keeps your code out of scope.
  NOTICE dual
         dual offers (MIT OR GPL-3.0); elect MIT explicitly so the choice is recorded
```

## Install

```bash
pip install -e .
```

No dependencies. Python 3.9+.

## Use

```bash
licenseengine <manifest> [options]
```

| Manifest | Read by |
|---|---|
| `package-lock.json`, `package.json` | `read_npm` (v1 tree and v2/v3 `packages`) |
| `requirements.txt` | `read_requirements` |
| `pyproject.toml` | `read_pyproject` (PEP 621 and Poetry) |
| `go.mod` | `read_go_mod` |

Renamed files are sniffed by content, so `demo-lock.json` still works.

| Flag | Effect |
|---|---|
| `--check` | exit 1 when the policy is violated |
| `--json` | machine-readable report |
| `--quiet` | one line |
| `--allow/--deny SPDX...` | replace the allowlist / add a denylist |
| `--allow-copyleft` | permit strong and weak copyleft |
| `--allow-network-copyleft` | permit AGPL/SSPL |
| `--allow-unknown` | do not fail on licences missing from the catalogue |
| `--no-attribution` | skip attribution notices |
| `--max-depth N` | warn about dependencies nested deeper than N |

## The decisions that make this different

**An expression is not a string.** `(MIT OR GPL-3.0)` is shippable under an MIT-only
policy — you elect MIT. `MIT AND GPL-3.0` is not, because both apply. A tool that
string-matches cannot tell these apart. The parser implements the SPDX 2.3 grammar
with correct precedence (`AND` binds tighter than `OR`) and the audit evaluates the
tree: `OR` needs one viable branch, `AND` needs all of them.

**Unknown is not permissive.** A licence id absent from the catalogue fails the
audit. Guessing in the permissive direction is how compliance breaches happen, and a
typo in a licence field is itself a legal risk worth catching.

**Weak copyleft is a warning, not a block.** MPL, LGPL and EPL attach to the file or
library, and whether they reach your code depends on how you link it — which a
scanner cannot see. Reporting a hard failure there would be false confidence.

**Network copyleft has its own switch.** Allowing `--allow-copyleft` does *not*
silently allow AGPL. Reaching AGPL requires saying so explicitly, because the
network-use trigger is a different decision from source distribution.

**Attribution is tracked separately from permission.** A permissive MIT dependency is
allowed *and* requires its copyright notice. Those are two findings, because they are
two obligations, and teams routinely satisfy the first and forget the second.

**Deny beats allow.** A licence on both lists is rejected.

## Programmatic use

```python
from licenseengine import Component, Policy, audit, summarize

report = audit(
    [
        Component("left-pad", "MIT"),
        Component("svc", "AGPL-3.0", direct=False, depth=2),
    ],
    Policy(allow_copyleft=True),
)

if not report.passed:
    print(summarize(report))
    for finding in report.blocking:
        print(finding.component, finding.code, finding.remedy)
```

## Tests

```bash
python -m pytest
```

113 tests covering the grammar (precedence, parens, exceptions, rejections), policy
evaluation (copyleft levels, denylist precedence, allowlist gaps, depth limits,
aliases), all four manifest readers, and the CLI exit codes.

## Licence

MIT — see [LICENSE](LICENSE).

Built by [Konain Sultan Khan (KK)](https://github.com/kkcyber2).
