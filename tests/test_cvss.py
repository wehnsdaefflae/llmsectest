"""Tests for CVSS v4.0 scoring of OWASP LLM categories."""

import pytest

from llmsectest.reporting.cvss import (
    CVSS_VERSION,
    CVSSScore,
    _BAKED_SCORES,
    cvss_for_category,
    library_available,
    score_vector,
)
from llmsectest.reporting.owasp_metadata import OWASP_LLM_CATEGORIES

_VALID_SEVERITIES = {"None", "Low", "Medium", "High", "Critical"}


class TestCategoryVectors:
    """Every OWASP category carries a scorable canonical CVSS:4.0 vector."""

    def test_all_categories_have_a_vector(self):
        for marker, category in OWASP_LLM_CATEGORIES.items():
            assert category.cvss_vector.startswith("CVSS:4.0/"), marker

    def test_all_categories_score(self):
        for marker in OWASP_LLM_CATEGORIES:
            score = cvss_for_category(marker)
            assert score is not None, marker
            assert isinstance(score, CVSSScore)
            assert 0.0 <= score.base_score <= 10.0
            assert score.severity in _VALID_SEVERITIES
            assert score.version == CVSS_VERSION == "4.0"

    def test_known_scores(self):
        # LLM06 (excessive agency, full CIA) is the worst case; LLM09
        # (misinformation, user-interaction gated) the least severe.
        assert cvss_for_category("owasp_llm06").base_score == 10.0
        assert cvss_for_category("owasp_llm06").severity == "Critical"
        assert cvss_for_category("owasp_llm09").base_score == 5.3
        assert cvss_for_category("owasp_llm09").severity == "Medium"

    def test_unknown_marker_is_none(self):
        assert cvss_for_category("owasp_llm99") is None
        assert cvss_for_category("not-a-marker") is None


class TestScoreVector:
    def test_empty_vector_is_none(self):
        assert score_vector("") is None
        assert score_vector(None) is None  # type: ignore[arg-type]

    def test_garbage_vector_is_none(self):
        # Both paths must reject an unparseable / unknown vector rather than guess.
        assert score_vector("CVSS:4.0/NONSENSE") is None
        assert score_vector("not a vector") is None

    def test_roundtrip_for_a_canonical_vector(self):
        vector = OWASP_LLM_CATEGORIES["owasp_llm01"].cvss_vector
        score = score_vector(vector)
        assert score is not None
        assert score.vector == vector


class TestBakedTableFidelity:
    """The offline baked scores must equal what the cvss library computes, so the
    dependency-free path can never silently diverge from the real algorithm."""

    def test_every_category_vector_is_baked(self):
        for category in OWASP_LLM_CATEGORIES.values():
            assert category.cvss_vector in _BAKED_SCORES

    @pytest.mark.skipif(not library_available(), reason="cvss library not installed")
    def test_baked_scores_match_library(self):
        from cvss import CVSS4

        for vector, (baked_score, baked_severity) in _BAKED_SCORES.items():
            c = CVSS4(vector)
            assert c.base_score == baked_score, vector
            assert c.severities()[0] == baked_severity, vector


class TestDependencyFreePath:
    """With the optional cvss library absent, canonical vectors still score from
    the baked table and non-canonical vectors degrade to None."""

    def test_baked_fallback(self, monkeypatch):
        import llmsectest.reporting.cvss as cvss_mod

        monkeypatch.setattr(cvss_mod, "_HAVE_CVSS", False)
        vector = OWASP_LLM_CATEGORIES["owasp_llm06"].cvss_vector
        score = cvss_mod.score_vector(vector)
        assert score is not None
        assert score.base_score == 10.0
        assert score.severity == "Critical"
        # A custom/unknown vector cannot be scored offline -> None (no guessing).
        assert cvss_mod.score_vector("CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N") is None
