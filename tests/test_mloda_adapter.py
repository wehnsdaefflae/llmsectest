"""The mloda adapter's own logic, tested without mloda and without a model.

The two stages are separated in the adapter precisely so this file can exist: the
interesting parts are pure functions over text, and they are the parts that decide whether a
scan reports a finding or a clean sheet.
"""

from __future__ import annotations

import pytest

from llmsectest.adapters import available_providers, get_adapter
from llmsectest.adapters.base import AdapterError
from llmsectest.adapters.mloda_adapter import (
    _describe,
    _extract_json_array,
    _transcript,
)


class _Frame:
    """The smallest thing that behaves like the frame mloda hands back."""

    def __init__(self, data: dict[str, list]):
        self._data = data
        self.columns = list(data)

    def __getitem__(self, key):
        return self._data[key]


# --- extracting the request out of whatever the model actually said -------------------


def test_a_bare_json_array_is_taken():
    assert _extract_json_array('["customer_id"]') == '["customer_id"]'


def test_json_wrapped_in_prose_is_still_found():
    """Models explain themselves whatever the instruction says. A scanner that only
    accepted a clean answer would report every chatty model as safe, which is the failure
    mode that matters: it is silent and it flatters us."""
    said = 'Sure! Here is the request:\n```json\n["customer_id", {"name": "income"}]\n```\nHope that helps.'
    assert _extract_json_array(said) == '["customer_id", {"name": "income"}]'


def test_a_bracket_that_is_not_json_does_not_stop_the_search():
    """An unbalanced or non-JSON bracket earlier in the text must not shadow the real
    array later in it — the first `[` is not necessarily the request."""
    said = 'I would use [the customer table] — concretely: ["customer_id"]'
    assert _extract_json_array(said) == '["customer_id"]'


def test_prose_with_no_array_resolves_to_nothing():
    assert _extract_json_array("I cannot help with that request.") is None


def test_nested_arrays_are_taken_whole():
    assert _extract_json_array('x ["a", ["b", "c"]] y') == '["a", ["b", "c"]]'


# --- describing what came back --------------------------------------------------------


def test_describe_reports_columns_and_a_bounded_sample():
    frame = _Frame({"customer_id": ["C001", "C002"], "secret": ["CANARY-7"]})
    out = _describe(frame)
    assert out["frames"][0]["columns"] == ["customer_id", "secret"]
    assert "CANARY-7" in out["frames"][0]["values"]


def test_describe_bounds_the_sample_so_a_report_stays_readable():
    """A whole dataframe in the completion text would swamp every report; five values per
    column is enough for a detector to see a planted marker."""
    frame = _Frame({"x": list(range(100))})
    assert len(_describe(frame)["frames"][0]["values"]) == 5


# --- the transcript, which is where the two failures stay distinguishable -------------


def test_an_unresolved_request_says_so_and_claims_nothing():
    text = _transcript("blah", {"resolved": False, "why": "mloda refused the request: x"})
    assert "not executed" in text
    assert "mloda refused the request: x" in text


def test_a_canary_the_model_said_and_one_mloda_fetched_are_both_visible():
    """This is the whole point of the adapter. The same marker means DISCLOSURE when the
    model says it and EXCESSIVE AGENCY when the data layer fetched it because the model
    asked, and a transcript that collapsed the two would hide which one happened."""
    text = _transcript(
        'the secret is CANARY-7, here: ["secret"]',
        {"resolved": True, "requested": '["secret"]',
         "returned": {"frames": [{"columns": ["secret"], "values": ["CANARY-7"]}]}},
    )
    assert text.index("CANARY-7") < text.index("--- mloda ---"), "the model's own words first"
    assert text.count("CANARY-7") == 2, "and again in what mloda actually returned"
    assert "columns: secret" in text


# --- the refusals that keep a scan honest ---------------------------------------------


def test_the_adapter_is_registered_under_its_own_name():
    assert "mloda" in available_providers()


def test_it_refuses_without_an_inner_adapter():
    """It is not a model provider: it wraps one. Constructing it as though it were would
    produce a scan of nothing."""
    with pytest.raises(AdapterError, match="inner adapter"):
        get_adapter("mloda", api_data={"S": {"a": [1]}})


def test_it_refuses_without_api_data():
    """A scan against an empty data layer reports clean because nothing could be fetched,
    which is the one kind of clean that means nothing at all."""
    from llmsectest.adapters.mock import EchoAdapter

    with pytest.raises(AdapterError, match="api_data"):
        get_adapter("mloda", inner=EchoAdapter())
