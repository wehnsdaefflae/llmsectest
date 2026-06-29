"""Unit tests for the OWASP LLM04 model-poisoning scanner.

The scanner walks a pickle's *opcode* stream (never unpickles) and flags imports
of code-execution primitives. The crafted-byte helpers below build deterministic
pickle/zip/numpy artifacts without depending on torch/numpy or on
``pickle.whichmodule`` quirks — and, crucially, contain no real payload (the bytes
are never loaded). The benign cases prove a legitimate weights file (OrderedDict /
plain containers) does not false-positive.
"""

from __future__ import annotations

import pickle
import struct
import zipfile
from collections import OrderedDict

from llmsectest.probes.modelpoison import (
    ModelPoisonFinding,
    discover_model_files,
    scan_model_file,
    scan_model_files,
)


def _craft_global_pickle(module: str, name: str) -> bytes:
    """A protocol-0 pickle whose GLOBAL imports ``module.name`` (inert: never loaded)."""
    return f"c{module}\n{name}\n)R.".encode()


def _craft_stack_global_pickle(module: str, name: str) -> bytes:
    """A protocol-4 pickle whose STACK_GLOBAL imports ``module.name`` (inert)."""
    def sbu(s: str) -> bytes:
        b = s.encode()
        return b"\x8c" + bytes([len(b)]) + b
    return b"\x80\x04" + sbu(module) + sbu(name) + b"\x93)R."


def _make_npy(descr: str, trailer: bytes = b"") -> bytes:
    """A minimal valid .npy v1 file with the given dtype ``descr`` + optional trailer."""
    header = "{'descr': %r, 'fortran_order': False, 'shape': (1,), }" % descr
    hb = header.encode("latin-1")
    pad = (64 - (10 + len(hb) + 1) % 64) % 64
    hb = hb + b" " * pad + b"\n"
    return b"\x93NUMPY\x01\x00" + struct.pack("<H", len(hb)) + hb + trailer


# --- raw pickle: dangerous import is caught -------------------------------------

def test_global_os_system_is_critical(tmp_path):
    p = tmp_path / "weights.pkl"
    p.write_bytes(_craft_global_pickle("os", "system"))
    findings = scan_model_file(p)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "critical"
    assert "os" in f.evidence and "system" in f.evidence
    assert f.model_file == "weights.pkl"


def test_stack_global_subprocess_is_critical(tmp_path):
    p = tmp_path / "m.pt"
    p.write_bytes(_craft_stack_global_pickle("subprocess", "Popen"))
    findings = scan_model_file(p)
    assert [f.severity for f in findings] == ["critical"]
    assert "subprocess" in findings[0].evidence


def test_real_reduce_payload_is_flagged(tmp_path):
    """A real ``__reduce__`` RCE pickle (built via the stdlib) is caught — without
    asserting the exact module string, since whichmodule may pick os vs posix."""
    import os

    class _Evil:
        def __reduce__(self):
            return (os.system, ("echo inert-test-payload",))

    p = tmp_path / "model.bin"
    p.write_bytes(pickle.dumps(_Evil()))
    findings = scan_model_file(p)
    assert any(f.severity == "critical" for f in findings)


def test_builtins_eval_is_critical(tmp_path):
    p = tmp_path / "x.pkl"
    p.write_bytes(_craft_global_pickle("builtins", "eval"))
    findings = scan_model_file(p)
    assert findings and findings[0].severity == "critical"


def test_nested_unpickle_primitive_is_critical(tmp_path):
    p = tmp_path / "x.pkl"
    p.write_bytes(_craft_global_pickle("numpy", "load"))
    findings = scan_model_file(p)
    assert findings and findings[0].severity == "critical"


# --- gadget primitive (high) ----------------------------------------------------

def test_operator_attrgetter_is_high_gadget(tmp_path):
    p = tmp_path / "x.pkl"
    p.write_bytes(_craft_global_pickle("operator", "attrgetter"))
    findings = scan_model_file(p)
    assert findings and findings[0].severity == "high"
    assert "gadget" in findings[0].technique


# --- benign files do not false-positive -----------------------------------------

def test_benign_ordereddict_is_clean(tmp_path):
    """A legitimate weights-shaped pickle (OrderedDict of plain numbers) — the
    common real case — must produce no finding."""
    p = tmp_path / "state_dict.pkl"
    p.write_bytes(pickle.dumps(OrderedDict([("layer.weight", [1.0, 2.0, 3.0]),
                                            ("layer.bias", [0.5])])))
    assert scan_model_file(p) == []


def test_benign_plain_dict_is_clean(tmp_path):
    p = tmp_path / "cfg.pkl"
    p.write_bytes(pickle.dumps({"epochs": 3, "lr": 0.01, "layers": [16, 32]}))
    assert scan_model_file(p) == []


# --- containers: PyTorch-style zip ----------------------------------------------

def test_zip_member_pickle_is_scanned(tmp_path):
    p = tmp_path / "model.pt"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("model/data.pkl", _craft_global_pickle("os", "system"))
        zf.writestr("model/data/0", b"\x00\x01\x02rawtensorbytes")  # ignored non-pickle
    findings = scan_model_file(p)
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert findings[0].member == "model/data.pkl"
    assert findings[0].location == "model.pt!model/data.pkl"


def test_zip_with_only_safe_members_is_clean(tmp_path):
    p = tmp_path / "safe.pt"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("safe/data.pkl", pickle.dumps({"w": [1, 2, 3]}))
    assert scan_model_file(p) == []


# --- numpy object array ---------------------------------------------------------

def test_npy_object_array_is_flagged(tmp_path):
    p = tmp_path / "arr.npy"
    p.write_bytes(_make_npy("|O"))
    findings = scan_model_file(p)
    assert findings and findings[0].severity == "medium"
    assert "object" in findings[0].technique


def test_npy_numeric_array_is_clean(tmp_path):
    p = tmp_path / "arr.npy"
    p.write_bytes(_make_npy("<f4", trailer=b"\x00\x00\x80?"))
    assert scan_model_file(p) == []


# --- non-pickle / unknown content does not crash --------------------------------

def test_random_bytes_no_crash_no_finding(tmp_path):
    p = tmp_path / "junk.dat"
    p.write_bytes(b"this is not a pickle at all, just text\n" * 10)
    assert scan_model_file(p) == []


# --- discovery: recursion + prune + sort ----------------------------------------

def test_discover_recurses_and_prunes_vendored(tmp_path):
    (tmp_path / "models").mkdir()
    (tmp_path / "models" / "good.pkl").write_bytes(pickle.dumps({"a": 1}))
    (tmp_path / ".venv" / "lib").mkdir(parents=True)
    (tmp_path / ".venv" / "lib" / "vendored.pkl").write_bytes(
        _craft_global_pickle("os", "system"))
    found = discover_model_files(tmp_path)
    names = {p.name for p in found}
    assert "good.pkl" in names
    assert "vendored.pkl" not in names  # .venv pruned


def test_scan_directory_uses_relative_paths_and_sorts(tmp_path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "evil.pkl").write_bytes(_craft_global_pickle("os", "system"))
    (tmp_path / "sub" / "gadget.pkl").write_bytes(
        _craft_global_pickle("operator", "attrgetter"))
    findings = scan_model_files(tmp_path)
    assert [f.severity for f in findings] == ["critical", "high"]  # worst-first
    assert all(f.model_file.startswith("sub/") for f in findings)


def test_single_safetensors_not_discovered(tmp_path):
    (tmp_path / "model.safetensors").write_bytes(b"safetensors-binary-blob")
    assert discover_model_files(tmp_path) == []


def test_finding_repr_is_compact():
    f = ModelPoisonFinding(id="LLM04-critical-os-system-x", severity="critical",
                           model_file="m.pkl", member="", technique="t",
                           evidence="e", recommendation="r")
    assert repr(f) == "ModelPoisonFinding(LLM04-critical-os-system-x)"
    assert f.location == "m.pkl"
