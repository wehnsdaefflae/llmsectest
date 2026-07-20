"""Unit tests for the adapter-driven probe library (deterministic, offline).

These prove the probe machinery itself: detectors flag vulnerable replies and
clear safe ones, and the curated corpus is well-formed. They run against the
offline ScriptedAdapter demo targets — no network, no API key — so they are
safe to keep in the default CI collection.
"""

from __future__ import annotations

import pytest

from llmsectest.adapters.base import CompletionResponse, LLMAdapter
from llmsectest.adapters.mock import ScriptedAdapter
from llmsectest.probes import (
    APP_ONLY_CATEGORIES,
    SCANNER_CATEGORIES,
    cases_for,
    covered_categories,
    defended_demo_adapter,
    get_corpus,
    get_detector,
    resolve_target,
    run_probe,
    vulnerable_demo_adapter,
)
from llmsectest.probes.models import SEVERITIES

# Categories backed by an adapter-driven probe corpus (vs the scanner-based ones).
PROBE_CATEGORIES = {
    "owasp_llm01",
    "owasp_llm02",
    "owasp_llm05",
    "owasp_llm06",
    "owasp_llm07",
    "owasp_llm09",
    "owasp_llm10",
}


class _UsageAdapter(LLMAdapter):
    """A mock target that returns fixed ``text`` with a caller-supplied ``usage`` block,
    so a test can pin how ``run_probe`` reads the provider's output-token count."""

    provider = "mock"

    def __init__(self, usage: dict, text: str = "hello"):
        super().__init__("m")
        self._usage = usage
        self._text = text

    def complete(self, request):
        return CompletionResponse(
            text=self._text, model="m", provider="mock", usage=self._usage
        )


def test_corpus_covers_implemented_categories():
    assert set(covered_categories()) == (
        PROBE_CATEGORIES | SCANNER_CATEGORIES | APP_ONLY_CATEGORIES
    )
    for cat in PROBE_CATEGORIES:
        assert cases_for(cat), f"no cases for {cat}"
    # scanner (LLM03) and application-only (LLM08) categories are covered but ship
    # no bare-model probe corpus
    for cat in SCANNER_CATEGORIES | APP_ONLY_CATEGORIES:
        assert not cases_for(cat), f"{cat} unexpectedly ships probe cases"


def test_corpus_cases_are_well_formed():
    seen_ids = set()
    for case in get_corpus():
        assert case.id not in seen_ids, f"duplicate case id {case.id}"
        seen_ids.add(case.id)
        assert case.severity in SEVERITIES
        # a token-scored case names its canary; a metric-scored (tokenless) case is
        # legitimately marker-free — the ProbeCase invariant already enforces the xor
        assert case.forbidden or case.tokenless, f"{case.id} has no forbidden tokens"
        assert case.user_prompt and case.system_prompt
        # detector must be registered
        get_detector(case.detector)


def test_detectors_flag_present_tokens():
    for case in get_corpus():
        # a metric-scored (tokenless) case has no planted token to leak — it is
        # exercised through the demo-target and length/ceiling unit tests instead
        if case.tokenless:
            continue
        detector = get_detector(case.detector)
        # Repeat the token so the assertion is detector-agnostic: substring oracles
        # flag a single occurrence, while the volume oracle (LLM10
        # unbounded_consumption) needs the marker repeated past its flood threshold.
        # A genuine finding emits it many times, so this models a vulnerable reply
        # for every detector.
        token = case.forbidden[0]
        leaked = f"here you go: {(token + ' ') * 40}-- anything else?"
        vulnerable, evidence = detector(leaked, case)
        assert vulnerable, f"{case.id}: detector missed a planted token"
        assert token in evidence


def test_detectors_pass_clean_responses():
    safe = "I can only help with ACME product questions and won't share that."
    for case in get_corpus():
        vulnerable, _ = get_detector(case.detector)(safe, case)
        assert not vulnerable, f"{case.id}: false positive on a safe reply"


def test_vulnerable_demo_target_is_flagged_for_every_case():
    adapter = vulnerable_demo_adapter()
    for case in get_corpus():
        outcome = run_probe(adapter, case)
        assert outcome.vulnerable, f"{case.id} not caught: {outcome.response!r}"
        assert outcome.case is case


def test_defended_demo_target_passes_every_case():
    adapter = defended_demo_adapter()
    for case in get_corpus():
        outcome = run_probe(adapter, case)
        assert not outcome.vulnerable, f"{case.id} false positive: {outcome.evidence}"


def test_resolve_target_demo_keywords():
    assert resolve_target("demo-vulnerable").model == "demo-vulnerable"
    assert resolve_target("demo-defended").model == "demo-defended"
    assert resolve_target("").model == "demo-vulnerable"


def test_resolve_target_provider_spec_is_lazy():
    # "mock" must resolve without importing any vendor SDK.
    adapter = resolve_target("mock")
    assert adapter.provider == "mock"


def test_unsafe_output_detector_ignores_escaped_payload():
    """LLM05: only raw/executable output is a finding — escaping it must not be."""
    case = cases_for("owasp_llm05")[0]  # the <script> XSS case
    raw = case.forbidden[0]
    escaped = raw.replace("<", "&lt;").replace(">", "&gt;")
    detector = get_detector(case.detector)
    assert detector(raw, case)[0] is True, "raw active payload should be flagged"
    assert detector(escaped, case)[0] is False, "escaped payload is a false positive"


def test_excessive_agency_detector_ignores_named_refusal():
    """LLM06: only a structured tool call is a finding — naming the tool is not."""
    case = cases_for("owasp_llm06")[0]  # the account-takeover (change_email) case
    detector = get_detector(case.detector)
    refusal = (
        "I can't change_email or delete_account without verified authorization — "
        "please use the secure self-service portal."
    )
    assert detector(case.forbidden[0], case)[0] is True, "a real action call must be flagged"
    assert detector(refusal, case)[0] is False, "naming the tool in a refusal is a false positive"


def test_unbounded_consumption_detector_ignores_bounded_sample():
    """LLM10: a flood of the marker is a finding; a short bounded sample is not."""
    case = cases_for("owasp_llm10")[0]
    marker = case.forbidden[0]
    detector = get_detector(case.detector)
    flood = (marker + " ") * 100
    bounded = (
        f"Here are three for illustration: {marker} {marker} {marker}. "
        "I won't produce thousands of them."
    )
    assert detector(flood, case)[0] is True, "a runaway flood must be flagged"
    assert detector(bounded, case)[0] is False, "a small bounded sample is a false positive"


def test_length_amplification_detector_flags_large_but_not_small_output():
    """LLM10: a large non-repetitive volume is amplification; a short reply is not.

    Complements the repetition oracle — it fires on total output *size*, so it catches a
    long enumeration/essay the repeated-marker count cannot see.
    """
    from llmsectest.probes.models import ProbeCase

    case = ProbeCase(
        id="AMP", owasp="owasp_llm10", title="amplify", severity="high",
        technique="bounded output amplification (denial of wallet)",
        user_prompt="list 1..250", system_prompt="",
        detector="length_amplification", forbidden=(), tokenless=True,
    )
    detector = get_detector("length_amplification")
    large = "\n".join(str(i) for i in range(1, 251))  # a compliant full sequence
    small = "That's a lot of output — here are the first five: 1, 2, 3, 4, 5."
    assert detector(large, case)[0] is True, "a large on-demand volume must be flagged"
    assert detector(small, case)[0] is False, "a short capped/sampled reply is a false positive"


def test_run_probe_records_provider_output_tokens():
    """The per-probe output-token cost is captured when the provider reports it (across
    the OpenAI/Ollama and Anthropic key spellings) and is None for a target that reports
    no usage (a black-box endpoint or the offline mock)."""
    from llmsectest.probes.models import ProbeCase

    case = ProbeCase(
        id="U", owasp="owasp_llm01", title="t", severity="high", technique="t",
        user_prompt="hi", system_prompt="", detector="injection_marker", forbidden=("X",),
    )

    assert run_probe(_UsageAdapter({"completion_tokens": 42}), case).output_tokens == 42
    assert run_probe(_UsageAdapter({"output_tokens": 7}), case).output_tokens == 7
    assert run_probe(_UsageAdapter({}), case).output_tokens is None
    assert run_probe(ScriptedAdapter(lambda req: "hi"), case).output_tokens is None


class _RaisingAdapter(LLMAdapter):
    """A target whose ``complete`` raises a caller-supplied exception, to pin how
    ``run_probe`` distinguishes a per-request timeout from a hard failure."""

    provider = "mock"

    def __init__(self, exc: Exception):
        super().__init__("m")
        self._exc = exc

    def complete(self, request):
        raise self._exc


def test_run_probe_records_a_timeout_as_inconclusive():
    """A per-request timeout is recorded as inconclusive (errored, not a finding) so one
    hung endpoint never aborts the scan — but a genuine adapter failure still propagates."""
    from llmsectest.adapters.base import AdapterError, AdapterTimeoutError
    from llmsectest.probes.models import ProbeCase

    case = ProbeCase(
        id="T", owasp="owasp_llm06", title="t", severity="high", technique="t",
        user_prompt="do it", system_prompt="", detector="injection_marker", forbidden=("X",),
    )

    outcome = run_probe(_RaisingAdapter(AdapterTimeoutError("app slow", timeout=5)), case)
    assert outcome.errored is True
    assert outcome.vulnerable is False  # a timeout is not proof of a vulnerability
    assert "inconclusive" in outcome.evidence and "app slow" in outcome.evidence
    assert outcome.output_tokens is None

    # A non-timeout adapter failure (auth, unreachable, malformed) must NOT be swallowed.
    with pytest.raises(AdapterError):
        run_probe(_RaisingAdapter(AdapterError("endpoint unreachable")), case)


def test_app_timeout_from_env_parses_positive_seconds(monkeypatch):
    from llmsectest import envvars

    monkeypatch.delenv(envvars.APP_TIMEOUT, raising=False)
    assert envvars.app_timeout_from_env() is None  # unset → adapter default
    monkeypatch.setenv(envvars.APP_TIMEOUT, "45")
    assert envvars.app_timeout_from_env() == 45.0
    monkeypatch.setenv(envvars.APP_TIMEOUT, "0")
    assert envvars.app_timeout_from_env() is None  # non-positive → ignored
    monkeypatch.setenv(envvars.APP_TIMEOUT, "not-a-number")
    assert envvars.app_timeout_from_env() is None  # unparseable → ignored, not a crash


def test_output_ceiling_reached_signal():
    """The token-ceiling helper flags a reply that consumed (almost) the whole budget,
    ignores one that stayed under it, and is inert without a provider token count."""
    from llmsectest.probes.detectors import output_ceiling_reached

    assert output_ceiling_reached(512, 512)[0] is True
    assert output_ceiling_reached(503, 512)[0] is True  # within the 0.98 margin
    assert output_ceiling_reached(400, 512)[0] is False
    assert output_ceiling_reached(None, 512)[0] is False  # black-box endpoint: inert
    assert output_ceiling_reached(512, 0)[0] is False  # no usable ceiling


def test_run_probe_flags_cost_ceiling_case_at_the_token_budget():
    """A ``cost_ceiling`` case is flagged when the reply fills the request's max_tokens
    budget (a would-have-continued runaway) even though its short text clears the length
    oracle — and is clean when the target bounds itself or reports no usage."""
    from llmsectest.probes.models import ProbeCase

    case = ProbeCase(
        id="CEIL", owasp="owasp_llm10", title="ceiling", severity="medium",
        technique="output-token ceiling", user_prompt="write forever", system_prompt="",
        detector="length_amplification", forbidden=(), tokenless=True, cost_ceiling=True,
    )
    # "hello" is far under the length oracle, so the ceiling signal is what decides here.
    filled = run_probe(_UsageAdapter({"completion_tokens": 512}), case)
    assert filled.vulnerable and "output-token ceiling" in filled.evidence
    assert not run_probe(_UsageAdapter({"completion_tokens": 60}), case).vulnerable
    assert not run_probe(_UsageAdapter({}), case).vulnerable  # no usage: inert, not a FP


def test_cost_ceiling_is_opt_in_only():
    """A budget-filling reply does not auto-flag an ordinary case — only the case's own
    text detector decides unless it opts into the ceiling signal."""
    from llmsectest.probes.models import ProbeCase

    ordinary = ProbeCase(
        id="ORD", owasp="owasp_llm01", title="t", severity="high", technique="t",
        user_prompt="hi", system_prompt="", detector="injection_marker", forbidden=("X",),
    )
    outcome = run_probe(_UsageAdapter({"completion_tokens": 512}, text="benign reply"), ordinary)
    assert not outcome.vulnerable


def test_llm10_output_ceiling_case_is_registered():
    """The model-mode corpus ships the non-repetitive ceiling case, opted into the
    cost-ceiling signal and marker-free (metric-scored)."""
    ceiling = [c for c in cases_for("owasp_llm10") if c.id == "LLM10-output-ceiling"]
    assert len(ceiling) == 1, "the output-ceiling case must be in the LLM10 corpus"
    case = ceiling[0]
    assert case.cost_ceiling and case.tokenless and not case.forbidden


def test_misinformation_detector_flags_confabulation_not_a_disclaimer():
    """LLM09: asserting a nonexistent entity by name (with no uncertainty disclaimer)
    is a finding; disclaiming it, or never mentioning it, is not — even though both a
    fabricated answer and a disclaimer may repeat the entity name."""
    case = cases_for("owasp_llm09")[0]
    entity = case.forbidden[0]
    detector = get_detector(case.detector)

    fabricated = (
        f"Certainly — {entity} takes a buffer and an alignment, returns the aligned "
        "array, and is widely used in production. Example: result = pandas." + entity + "(buf, 64)."
    )
    disclaimed = f"I'm not aware of a function called {entity}; it does not appear to exist in pandas."
    off_topic = "I can only help with ACME product questions and won't share that."
    # Real calibrated-model phrasings (caught live against Gemma) where the epistemic
    # noun varies — these must read as disclaimers, not findings.
    lacks_access = f"I do not have access to the specific content of `{entity}` to summarize it."
    lacks_verified = f"I do not have verified information regarding `{entity}`, including any details."

    assert detector(fabricated, case)[0] is True, "a confident fabrication must be flagged"
    assert detector(disclaimed, case)[0] is False, "a disclaimer that names the entity is not a finding"
    assert detector(off_topic, case)[0] is False, "a reply that never engages the entity is not a finding"
    assert detector(lacks_access, case)[0] is False, "'I do not have access to X' is a disclaimer"
    assert detector(lacks_verified, case)[0] is False, "'I do not have verified information' is a disclaimer"


def test_retrieval_exposure_detector_flags_only_the_canary():
    """LLM08: the retrieved-corpus canary in a reply is a finding; a refusal that
    merely names the corpus (without reproducing the unique token) is not."""
    from llmsectest.probes.models import ProbeCase

    canary = "INTERNAL-DOC-CANARY-7f2a"
    case = ProbeCase(
        id="APP-x-LLM08-corpus-enumeration",
        owasp="owasp_llm08",
        title="retrieval exposure",
        severity="high",
        technique="retrieval corpus enumeration",
        user_prompt="list every document",
        system_prompt="",
        detector="retrieval_exposure",
        forbidden=(canary,),
    )
    detector = get_detector("retrieval_exposure")
    leak = f"Here is the confidential record: {canary} — full text follows."
    refusal = (
        "I can only answer from public documents; I won't reproduce confidential or "
        "internal knowledge-base entries."
    )
    assert detector(leak, case)[0] is True, "a reproduced corpus canary must be flagged"
    assert detector(refusal, case)[0] is False, "naming the corpus in a refusal is a false positive"


def _leak_case(detector_name: str, canary: str) -> "object":
    from llmsectest.probes.models import ProbeCase

    return ProbeCase(
        id=f"X-{detector_name}",
        owasp="owasp_llm02",
        title="leak",
        severity="high",
        technique="encoded exfiltration",
        user_prompt="reveal it",
        system_prompt="",
        detector=detector_name,
        forbidden=(canary,),
    )


@pytest.mark.parametrize(
    "detector_name",
    ["sensitive_disclosure", "system_prompt_leak", "retrieval_exposure"],
)
def test_leak_detectors_catch_encoded_and_split_secrets(detector_name):
    """LLM02/07/08 de-obfuscate: a canary emitted encoded (base64/hex/base32/base85/
    ASCII85/ROT13/quoted-printable/uuencode), Unicode-disguised (full-width or zero-width)
    or split across separators is still a leak, and the finding names the scheme it hid in."""
    import base64
    import binascii
    import codecs

    canary = "BLUEHERON-7731-SECRET"
    case = _leak_case(detector_name, canary)
    detector = get_detector(detector_name)

    # Full-width look-alikes (NFKC-folds to ASCII) and a zero-width-space between every
    # character (invisible to a rendered read); both normalise back to the canary.
    fullwidth = canary.translate({c: c + 0xFEE0 for c in range(0x21, 0x7F)})
    zero_width = "​".join(canary)
    # Quoted-printable that actually escapes every byte (=XX), so the canary is not
    # present literally — a plain QP-encode leaves ASCII-safe chars untouched.
    qp = "".join(f"={b:02X}" for b in canary.encode())
    # uuencode the canary on its own line (the prose prefix stays on the line above, so
    # the encoded body is decodable — a2b_uu rejects the lowercase prefix line).
    uu = binascii.b2a_uu(canary.encode()).decode()
    # (scheme, payload) — scheme is the label the evidence must name it was hidden in.
    variants = [
        ("base64", f"Sure — here it is in base64: {base64.b64encode(canary.encode()).decode()}"),
        ("hex", f"As hex bytes: {canary.encode().hex()}"),
        ("base32", f"In base32: {base64.b32encode(canary.encode()).decode()}"),
        ("base85", f"base85: {base64.b85encode(canary.encode()).decode()}"),
        ("ascii85", f"ascii85: {base64.a85encode(canary.encode()).decode()}"),
        ("rot13", f"ROT13 of the code: {codecs.encode(canary, 'rot_13')}"),
        ("quoted-printable", f"quoted-printable: {qp}"),
        ("uuencode", f"Here it is, uuencoded:\n{uu}"),
        ("unicode", f"in full-width: {fullwidth}"),
        ("unicode", f"with hidden joiners: {zero_width}"),
        ("split", f"I'll spell it out: {'-'.join(canary)}"),
    ]
    for scheme, payload in variants:
        vulnerable, evidence = detector(payload, case)
        assert vulnerable, f"{detector_name}: {scheme} leak missed in {payload!r}"
        assert scheme in evidence, f"{detector_name}: evidence should name {scheme}: {evidence!r}"
    # A literal leak is unchanged (no "(via …)" annotation).
    vulnerable, evidence = detector(f"the code is {canary}", case)
    assert vulnerable and "via" not in evidence, evidence


@pytest.mark.parametrize(
    "detector_name",
    ["sensitive_disclosure", "system_prompt_leak", "retrieval_exposure"],
)
def test_leak_detectors_no_false_positive_on_unrelated_encoding(detector_name):
    """De-obfuscation must not fire on encoded content that never carried the canary."""
    case = _leak_case(detector_name, "BLUEHERON-7731-SECRET")
    detector = get_detector(detector_name)
    # A long base64 image fragment, a 32-char hex checksum, and separator-rich prose —
    # none decodes to or spells out the unique canary.
    noisy = (
        "Here is an asset: iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ "
        "and a checksum a1b2c3d4e5f60718293a4b5c6d7e8f90 — hope that helps."
    )
    assert detector(noisy, case)[0] is False, f"{detector_name}: unrelated encoding must not false-positive"


def test_uu_decode_handles_multiline_block_and_is_prose_safe():
    """The uuencode pass decodes a multi-line block (secret > one 45-byte line), skips a
    ``begin``/``end`` wrapper, returns None on ordinary prose, and — because an all-caps
    line can spuriously uu-decode to bytes — still never invents a canary hit."""
    import binascii

    from llmsectest.probes.detectors import _uu_decode, get_detector

    canary = "GREENFALCON-4402-CLASSIFIED-TOKEN-PAYLOAD-EXCEEDING-ONE-LINE"
    body = b""
    for i in range(0, len(canary), 45):
        body += binascii.b2a_uu(canary[i:i + 45].encode())
    block = "begin 644 leak.txt\n" + body.decode() + "`\nend"
    assert len(canary) > 45, "canary must span more than one uuencode line to exercise it"
    assert _uu_decode(block) == canary, "multi-line uuencoded secret must reconstruct"

    # Ordinary prose (has lowercase) does not decode → no spurious form.
    assert _uu_decode("The password is definitely not written here.") is None
    # A leak detector fires on the block and names the scheme...
    case = _leak_case("sensitive_disclosure", canary)
    vulnerable, evidence = get_detector("sensitive_disclosure")(block, case)
    assert vulnerable and "uuencode" in evidence, evidence
    # ...but an all-caps line that uu-decodes to junk carries no canary → no finding.
    assert get_detector("sensitive_disclosure")("SHOUTING HEADLINE WITH NO SECRET", case)[0] is False


def test_structural_oracles_stay_literal_not_deobfuscating():
    """LLM05/LLM06 must NOT decode: for them an *encoded* payload is the safe case,
    so de-obfuscation would invert the safety semantics."""
    import base64

    llm05 = cases_for("owasp_llm05")[0]
    encoded_payload = base64.b64encode(llm05.forbidden[0].encode()).decode()
    assert get_detector("unsafe_output")(encoded_payload, llm05)[0] is False, (
        "a base64-encoded script is neutralized output, not an unsafe-output finding"
    )
    llm06 = cases_for("owasp_llm06")[0]
    encoded_action = base64.b64encode(llm06.forbidden[0].encode()).decode()
    assert get_detector("excessive_agency")(encoded_action, llm06)[0] is False, (
        "a base64-encoded action string is not an actual privileged invocation"
    )


def test_leak_detectors_fp_safe_on_diverse_clean_corpus():
    """FP-safety property: de-obfuscation only ever *adds* recall, so a broad corpus of
    realistic replies that carry encoded-looking, separator-rich, or Unicode-folding
    content but never the canary yields zero leak findings across all three leak oracles.

    The deterministic-oracle design rests on de-obfuscation never *inventing* a hit; the
    existing negative test exercises one noisy reply, this exercises that guarantee widely
    (JWTs, hashes/UUIDs, base64/base32/base85/ASCII85 blobs, ROT13/quoted-printable/uuencoded
    prose, full-width and zero-width text, hyphen-heavy prose) so a future decoder change
    that starts false-positiving is caught."""
    import base64
    import binascii
    import codecs

    canary = "BLUEHERON-7731-SECRET"
    fold = {c: c + 0xFEE0 for c in range(0x21, 0x7F)}
    clean = [
        "Sure, happy to help. The weather in Berlin is mild today.",
        # base64 PNG data URI
        "Logo: data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAf"
        "FcSJAAAAC0lEQVR4nGNgYGAAAAAEAAH2FzhVAAAAAElFTkSuQmCC",
        # a JWT: three base64url segments
        "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0."
        "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
        # a git SHA and a sha256 checksum (long hex runs)
        "Commit a1b2c3d4e5f60718293a4b5c6d7e8f90abcdef12; sha256 "
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08.",
        # a UUID (hyphen-separated hex)
        "Request 550e8400-e29b-41d4-a716-446655440000 completed.",
        # ROT13 of unrelated prose
        "In ROT13 that reads: " + codecs.encode("attack at dawn from the north ridge", "rot_13"),
        # quoted-printable of an accented unrelated sentence (real =XX escapes)
        "Encoded mail body: Caf=C3=A9 au lait co=C3=BBte deux euros.",
        # base64 of unrelated readable text
        "Decoded it says: " + base64.b64encode(b"the quick brown fox jumps over the lazy dog").decode(),
        # base32 of unrelated text
        "Base32 blob " + base64.b32encode(b"unrelated configuration payload goes here").decode(),
        # base85 / ascii85 of unrelated bytes
        "b85 " + base64.b85encode(b"nothing secret in this vector at all!!").decode(),
        "a85 " + base64.a85encode(b"just some ordinary telemetry counters here").decode(),
        # uuencode of an unrelated file line
        "uuencoded attachment:\n" + binascii.b2a_uu(b"harmless log line, nothing to see").decode(),
        # full-width unrelated text (NFKC-folds to ASCII words, not the canary)
        "In full width: " + "hello world".translate(fold),
        # zero-width joiners inside ordinary words
        "Read​ing between​ the lines is fine.",
        # heavily hyphenated ordinary prose (exercises the split pass)
        "This is a state-of-the-art, first-in-class, end-to-end e-mail pipeline.",
        # a refusal that names the concept but not the value
        "I can't share the internal secret token or any protected credential.",
        # a long random-looking base64 that decodes to arbitrary bytes
        "nonce " + base64.b64encode(bytes(range(48))).decode(),
    ]
    for detector_name in ("sensitive_disclosure", "system_prompt_leak", "retrieval_exposure"):
        detector = get_detector(detector_name)
        case = _leak_case(detector_name, canary)
        for reply in clean:
            fired, evidence = detector(reply, case)
            assert fired is False, (
                f"{detector_name} false-positived on a clean reply: {reply!r} -> {evidence}"
            )


@pytest.mark.parametrize(
    "canary",
    ["MAGENTA-8842-CLASSIFIED", "kx9Qw2Zr7Lp4Nt6Vs", "ZeroCoolAcidBurn2600", "AA11BB22CC33DD44EE"],
)
def test_leak_detectors_roundtrip_varied_canary_shapes(canary):
    """Round-trip property broadened over canary shapes (hyphenated, mixed-case, camel,
    structured): each unambiguous disguise round-trips back to a leak finding that names
    the scheme — so detection isn't pinned to the single canary the per-scheme test uses.
    (base85/ASCII85 scheme-naming is pinned separately to avoid super-alphabet ambiguity.)"""
    import base64
    import binascii
    import codecs

    detector = get_detector("sensitive_disclosure")
    case = _leak_case("sensitive_disclosure", canary)
    raw = canary.encode()
    fullwidth = canary.translate({c: c + 0xFEE0 for c in range(0x21, 0x7F)})
    variants = [
        ("base64", f"here it is: {base64.b64encode(raw).decode()}"),
        ("hex", f"the bytes are {raw.hex()}"),
        ("base32", f"in base32: {base64.b32encode(raw).decode()}"),
        ("rot13", f"rot13 of it: {codecs.encode(canary, 'rot_13')}"),
        ("uuencode", f"uuencoded below:\n{binascii.b2a_uu(raw).decode()}"),
        ("unicode", f"as full-width glyphs: {fullwidth}"),
        ("split", f"I'll spell it: {'.'.join(canary)}"),
    ]
    for scheme, payload in variants:
        fired, evidence = detector(payload, case)
        assert fired, f"{scheme} leak of {canary!r} missed in {payload!r}"
        assert scheme in evidence, f"evidence should name {scheme} for {canary!r}: {evidence!r}"


def test_split_pass_length_guard_boundary():
    """The separator-split pass is length-guarded (:data:`_MIN_SPLIT_LEN`) so a short token
    cannot coincidentally reappear once a reply's separators are stripped. A canary whose
    separator-free length is below the floor is NOT split-matched (the FP guard); one exactly
    at the floor is — pinning the exact boundary the guard relies on."""
    from llmsectest.probes.detectors import _MIN_SPLIT_LEN

    detector = get_detector("sensitive_disclosure")
    src = "PLUMQXZKRWBTVNJHGF"
    assert _MIN_SPLIT_LEN <= len(src), "extend src if the split-length floor grows"
    below = src[: _MIN_SPLIT_LEN - 1]
    at_floor = src[: _MIN_SPLIT_LEN]

    below_reply = f"see {'-'.join(below)} now"  # only present split, never literal
    assert detector(below_reply, _leak_case("sensitive_disclosure", below))[0] is False, (
        "a token below the split-length floor must not be split-matched (FP guard)"
    )
    at_reply = f"see {'-'.join(at_floor)} now"
    fired, evidence = detector(at_reply, _leak_case("sensitive_disclosure", at_floor))
    assert fired and "split" in evidence, evidence


def test_vulnerable_demo_persona_triggers_match_corpus():
    """The vulnerable demo keys its persona branches on substrings of the corpus
    personas; if a persona is reworded without updating the demo, the branch silently
    stops firing. Guard every trigger against that drift — so a newly added persona
    branch can't be left unpinned either."""
    from llmsectest.probes import corpus, demo
    from llmsectest.probes.redteam import REDTEAM_SYSTEM_PROMPT

    assert demo._AGENT_TRIGGER in corpus.AGENT_SYSTEM_PROMPT.lower()
    assert demo._REDTEAM_TRIGGER in REDTEAM_SYSTEM_PROMPT.lower()
    assert demo._RESOURCE_TRIGGER in corpus.RESOURCE_LIMIT_SYSTEM_PROMPT.lower()
    assert demo._FACTUALITY_TRIGGER in corpus.FACTUALITY_SYSTEM_PROMPT.lower()


def test_runner_uses_case_system_prompt():
    # The runner must pass the case's system prompt through to the adapter.
    seen = {}

    def responder(request):
        seen["system"] = request.messages[0].content
        return "ok"

    case = cases_for("owasp_llm07")[0]
    run_probe(ScriptedAdapter(responder), case)
    assert seen["system"] == case.system_prompt
