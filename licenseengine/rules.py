"""The built-in licence database.

Only licences that commonly appear in a dependency tree are included. An unknown id
is treated as ``unknown`` rather than assumed permissive -- that asymmetry is the
whole point of the tool.

Each entry records the facts a policy actually needs: OSI approval, copyleft
strength, whether a patent grant is included, whether attribution is required, and
whether a NOTICE file must be shipped.
"""

from __future__ import annotations

from .model import License

# copyleft levels:
#   none     - no reciprocity
#   weak     - file/library level (LGPL, MPL, EPL)
#   strong   - derivative work must be licensed alike (GPL)
#   network  - strong, plus network use counts as distribution (AGPL, SSPL)

_BUILTIN: tuple[License, ...] = (
    # ---- permissive -------------------------------------------------------
    License("MIT", "MIT License", True, "none", patent_grant=False),
    License("ISC", "ISC License", True, "none"),
    License("0BSD", "BSD Zero Clause License", True, "none", attribution_required=False),
    License("BSD-2-Clause", "BSD 2-Clause \"Simplified\" License", True, "none"),
    License("BSD-3-Clause", "BSD 3-Clause \"New\" License", True, "none"),
    License("Apache-2.0", "Apache License 2.0", True, "none", patent_grant=True,
            notice_file_required=True),
    License("Unlicense", "The Unlicense", True, "none", attribution_required=False),
    License("CC0-1.0", "Creative Commons Zero v1.0 Universal", True, "none",
            attribution_required=False),
    License("Zlib", "zlib License", True, "none"),
    License("BSL-1.0", "Boost Software License 1.0", True, "none"),
    License("MIT-0", "MIT No Attribution", True, "none", attribution_required=False),
    License("Python-2.0", "Python Software Foundation License 2.0", True, "none"),
    License("PSF-2.0", "Python Software Foundation License 2.0", True, "none"),
    # ---- weak copyleft ----------------------------------------------------
    License("LGPL-2.1", "GNU Lesser General Public License v2.1", True, "weak"),
    License("LGPL-2.1-only", "GNU Lesser General Public License v2.1 only", True, "weak"),
    License("LGPL-2.1-or-later", "GNU Lesser General Public License v2.1 or later", True,
            "weak"),
    License("LGPL-3.0", "GNU Lesser General Public License v3.0", True, "weak"),
    License("LGPL-3.0-only", "GNU Lesser General Public License v3.0 only", True, "weak"),
    License("LGPL-3.0-or-later", "GNU Lesser General Public License v3.0 or later", True,
            "weak"),
    License("MPL-2.0", "Mozilla Public License 2.0", True, "weak", patent_grant=True),
    License("EPL-2.0", "Eclipse Public License 2.0", True, "weak", patent_grant=True),
    License("CDDL-1.0", "Common Development and Distribution License 1.0", True, "weak"),
    # ---- strong copyleft --------------------------------------------------
    License("GPL-2.0", "GNU General Public License v2.0", True, "strong"),
    License("GPL-2.0-only", "GNU General Public License v2.0 only", True, "strong"),
    License("GPL-2.0-or-later", "GNU General Public License v2.0 or later", True, "strong"),
    License("GPL-3.0", "GNU General Public License v3.0", True, "strong", patent_grant=True),
    License("GPL-3.0-only", "GNU General Public License v3.0 only", True, "strong",
            patent_grant=True),
    License("GPL-3.0-or-later", "GNU General Public License v3.0 or later", True, "strong",
            patent_grant=True),
    # ---- network copyleft -------------------------------------------------
    License("AGPL-3.0", "GNU Affero General Public License v3.0", True, "network",
            patent_grant=True),
    License("AGPL-3.0-only", "GNU Affero General Public License v3.0 only", True,
            "network", patent_grant=True),
    License("AGPL-3.0-or-later", "GNU Affero General Public License v3.0 or later", True,
            "network", patent_grant=True),
    License("SSPL-1.0", "Server Side Public License 1.0", False, "network"),
    License("OSL-3.0", "Open Software License 3.0", True, "network", patent_grant=True),
    # ---- source-available / non-OSI --------------------------------------
    License("BUSL-1.1", "Business Source License 1.1", False, "none"),
    License("Elastic-2.0", "Elastic License 2.0", False, "none"),
    License("CC-BY-4.0", "Creative Commons Attribution 4.0", True, "none"),
    License("CC-BY-SA-4.0", "Creative Commons Attribution Share Alike 4.0", True,
            "strong"),
    License("WTFPL", "Do What The F*ck You Want To Public License", False, "none",
            attribution_required=False),
)

# Spellings that appear in manifests which are not SPDX ids but map to one. Kept
# separate from the database so the *input* is normalised without pretending the
# alias is a real identifier.
_ALIASES: dict[str, str] = {
    "apache 2.0": "Apache-2.0",
    "apache2": "Apache-2.0",
    "apache-2": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "apache license, version 2.0": "Apache-2.0",
    "mit license": "MIT",
    "bsd": "BSD-3-Clause",
    "bsd-3": "BSD-3-Clause",
    "bsd-2": "BSD-2-Clause",
    "new bsd": "BSD-3-Clause",
    "simplified bsd": "BSD-2-Clause",
    "gpl": "GPL-3.0",  # ambiguous upstream; SPDX recommends being explicit
    "gplv2": "GPL-2.0",
    "gplv3": "GPL-3.0",
    "gpl-2": "GPL-2.0-only",
    "gpl-3": "GPL-3.0-only",
    "lgpl": "LGPL-3.0",
    "lgplv3": "LGPL-3.0",
    "agpl": "AGPL-3.0",
    "agplv3": "AGPL-3.0",
    "mpl": "MPL-2.0",
    "mpl2": "MPL-2.0",
    "isc license": "ISC",
    "python": "PSF-2.0",
    "psf": "PSF-2.0",
    "unlicensed": "UNKNOWN",
    "proprietary": "UNKNOWN",
}


class LicenseDB:
    """Lookup table of licences, with alias normalisation."""

    def __init__(self, licenses: tuple[License, ...] = _BUILTIN) -> None:
        self._by_id: dict[str, License] = {}
        for lic in licenses:
            if lic.identifier in self._by_id:
                raise ValueError(f"duplicate licence id {lic.identifier}")
            self._by_id[lic.identifier] = lic
        self._aliases = dict(_ALIASES)

    def __len__(self) -> int:
        return len(self._by_id)

    def __contains__(self, identifier: str) -> bool:
        return self.normalise(identifier) in self._by_id

    def normalise(self, identifier: str) -> str:
        """Map an input spelling onto an SPDX id, or return it unchanged.

        Case-insensitive for the alias table only: SPDX ids are case-sensitive, and
        silently accepting ``mit`` as ``MIT`` would hide a malformed manifest. The
        exception is a handful of spellings that are unambiguously the same licence.
        """
        raw = identifier.strip()
        if raw in self._by_id:
            return raw
        lowered = raw.lower()
        if lowered in self._aliases:
            return self._aliases[lowered]
        # Common case-only variations of real ids ("mit", "apache-2.0").
        for known in self._by_id:
            if known.lower() == lowered:
                return known
        return raw

    def get(self, identifier: str) -> License | None:
        return self._by_id.get(self.normalise(identifier))

    def ids(self) -> list[str]:
        return sorted(self._by_id)

    def by_copyleft(self, level: str) -> list[License]:
        return [l for l in self._by_id.values() if l.copyleft == level]


def load_builtin() -> LicenseDB:
    """The default database."""
    return LicenseDB()
