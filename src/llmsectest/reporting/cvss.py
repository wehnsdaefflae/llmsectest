"""CVSS v4.0 scoring for OWASP LLM categories.

Each OWASP LLM category carries a representative ``CVSS:4.0`` base vector
(see :mod:`llmsectest.reporting.owasp_metadata`). This module turns a vector
into its base score and qualitative severity.

Design: the MIT core stays dependency-free. When the optional :mod:`cvss`
package (RedHatProductSecurity, LGPLv3+) is installed it computes the score for
*any* vector — including custom ones. When it is absent we fall back to a table
of scores baked from the ten canonical category vectors, so the standard reports
are fully populated with no extra dependency. A custom vector with no library
installed degrades gracefully to ``None`` (callers then use the marker-based
severity placeholder). Install the optional path with ``pip install
llmsectest[cvss]``.

The baked numbers below were produced with ``cvss`` 3.6 and are asserted to match
the library in the test-suite, so the two paths can never silently diverge.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Tuple

try:  # optional dependency — see module docstring
    from cvss import CVSS4 as _CVSS4

    _HAVE_CVSS = True
except Exception:  # pragma: no cover - exercised only when cvss is absent
    _CVSS4 = None
    _HAVE_CVSS = False


CVSS_VERSION = "4.0"

# Base scores baked from the canonical category vectors (cvss 3.6). The test
# suite recomputes these with the library and fails if they drift, so this table
# is a faithful offline mirror, not a hand-maintained guess.
_BAKED_SCORES: Dict[str, Tuple[float, str]] = {
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:H/VA:N/SC:L/SI:H/SA:N": (9.2, "Critical"),
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:H/SI:N/SA:N": (9.2, "Critical"),
    "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H": (9.5, "Critical"),
    "CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:N/VC:L/VI:H/VA:N/SC:L/SI:H/SA:N": (7.1, "High"),
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N": (9.9, "Critical"),
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H": (10.0, "Critical"),
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N": (8.7, "High"),
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:N/SC:L/SI:L/SA:N": (7.1, "High"),
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:L/VA:N/SC:N/SI:L/SA:N": (5.3, "Medium"),
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:L": (8.7, "High"),
}


@dataclass(frozen=True)
class CVSSScore:
    """A computed CVSS v4.0 base score."""

    vector: str
    base_score: float
    severity: str  # "Critical" / "High" / "Medium" / "Low" / "None"
    version: str = CVSS_VERSION


def score_vector(vector: str) -> Optional[CVSSScore]:
    """Return the CVSS v4.0 base score for a vector, or ``None`` if it cannot
    be scored offline.

    Uses the optional :mod:`cvss` library when available (any vector); otherwise
    falls back to the baked table of canonical category vectors. A non-canonical
    vector with no library installed returns ``None`` rather than guessing.
    """
    if not vector:
        return None
    if _HAVE_CVSS:
        try:
            c = _CVSS4(vector)
            return CVSSScore(vector=vector, base_score=c.base_score, severity=c.severities()[0])
        except Exception:
            return None
    baked = _BAKED_SCORES.get(vector)
    if baked is None:
        return None
    return CVSSScore(vector=vector, base_score=baked[0], severity=baked[1])


def cvss_for_category(marker: str) -> Optional[CVSSScore]:
    """Return the canonical CVSS v4.0 base score for an OWASP marker
    (e.g. ``"owasp_llm01"``), or ``None`` if the category has no vector."""
    # Imported lazily to avoid a circular import at module load time.
    from .owasp_metadata import get_owasp_category

    category = get_owasp_category(marker)
    if category is None or not getattr(category, "cvss_vector", None):
        return None
    return score_vector(category.cvss_vector)


def library_available() -> bool:
    """True if the optional :mod:`cvss` library is installed (any vector can be
    scored); False if only the baked canonical vectors are scorable."""
    return _HAVE_CVSS
