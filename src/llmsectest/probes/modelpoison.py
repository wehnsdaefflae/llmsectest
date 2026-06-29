"""OWASP LLM04 — Data & Model Poisoning (white-box model-file scan, offline).

The most direct way to *poison a model* is to tamper with the artifact a project
loads: a serialized model file is not just data. Python's ``pickle`` (and every
format built on it — ``torch.save`` ``.pt``/``.pth``/``.ckpt``, ``joblib``,
``numpy`` object arrays, scikit-learn ``.pkl``) executes embedded callables when
it is *loaded*. An attacker who can swap or modify the weights file a project
downloads from a hub therefore gets arbitrary code execution the moment the
victim calls ``torch.load`` / ``pickle.load`` — the classic "load a model, run
the attacker's payload" supply-side poisoning attack (cf. ProtectAI ``modelscan``,
``picklescan``, ``fickling``; Hugging Face's pickle-import scanning).

This module reads a target's model files and flags that risk **statically and
offline** — it walks the pickle *opcode* stream with the standard library
:mod:`pickletools` (no unpickling, so scanning is safe) and reports any opcode
that imports a code-execution primitive on load. No network, no model load, fully
deterministic — safe to run in CI.

What it flags, per model file:

* **code-execution import** (``critical``) — a ``GLOBAL`` / ``STACK_GLOBAL``
  opcode importing an unambiguous OS/process/exec primitive (``os.system``,
  ``subprocess.Popen``, ``builtins.eval``/``exec``, ``socket``, ``ctypes``,
  ``runpy``, a nested ``pickle.loads``/``numpy.load``/``torch.load`` …). A legit
  weights file only references rebuild helpers (``torch._utils._rebuild_tensor``,
  ``collections.OrderedDict``, ``numpy.core.multiarray._reconstruct``), so a hit
  is high-signal — this is a curated denylist of execution primitives, not a
  fuzzy heuristic.
* **gadget primitive** (``high``) — a ``GLOBAL`` importing a reflection/partial-
  application gadget (``operator.attrgetter``/``methodcaller``,
  ``functools.partial``/``reduce``, ``importlib.import_module``) that is the
  building block of a pickle gadget chain. Lower severity because it needs
  chaining and is *occasionally* legitimate, but still surfaced.
* **pickled object array** (``medium``) — a ``numpy`` ``.npy``/``.npz`` whose
  dtype is ``object``, so loading it requires ``allow_pickle=True`` and runs an
  embedded pickle (the trailing pickle is also opcode-scanned for the above).

A model file that contains no dangerous opcode produces no finding. Safetensors
(``.safetensors``) is a code-free format by construction and is not scanned (no
pickle to walk) — using it is the recommended remediation.

Containers understood: raw pickle streams (protocols 0–5) and ZIP archives
(PyTorch ≥1.6 ``.pt``/``.pth``/``.ckpt`` and ``.npz``), whose pickle members are
each scanned. This is the offline, zero-dependency baseline; a richer engine
(ProtectAI ``modelscan`` / ``picklescan`` / ``fickling``) behind an optional
extra is a tracked follow-up, mirroring how LLM03 layers OSV.dev on top of its
offline structural scan.
"""

from __future__ import annotations

import pickletools
import struct
import zipfile
from ast import literal_eval
from dataclasses import dataclass
from pathlib import Path

from .models import SEVERITIES

SEVERITY_RANK = {name: i for i, name in enumerate(SEVERITIES)}

# Directories we never descend into when discovering model files — virtualenvs,
# vendored/installed packages and VCS metadata are not the *project's* own model
# artifacts. Mirrors the supply-chain scanner's prune set.
_PRUNE_DIRS = frozenset({
    ".git", ".hg", ".svn", ".venv", "venv", "env", "node_modules",
    "site-packages", "__pycache__", ".tox", ".nox", "build", "dist",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", "tmp", ".eggs",
})

# File extensions that carry (or can carry) a Python pickle, directly or inside a
# ZIP container. A scan still sniffs the bytes, so an unrecognised extension that
# *is* a pickle is caught and a misnamed non-pickle is harmlessly ignored.
_MODEL_EXTS = frozenset({
    ".pkl", ".pickle", ".pck", ".pcl", ".dump", ".bin", ".ckpt", ".pt", ".pth",
    ".joblib", ".model", ".sav", ".dat", ".npy", ".npz", ".zip", ".pck",
})

# Extensions for code-free serialization formats — recorded so a scan can report
# it *looked* at the model dir and (correctly) found nothing to flag, rather than
# silently ignoring everything. We do not parse them (no embedded pickle).
_SAFE_EXTS = frozenset({".safetensors", ".gguf"})

# Whole modules whose import during unpickling is an unambiguous code-execution
# primitive: importing any name from them at load time means the file runs OS,
# process, network or interpreter code. Curated and exact (like LLM03's
# known-malicious package list) so a hit is high-signal, never a fuzzy guess.
_EXEC_MODULES = frozenset({
    "os", "posix", "nt", "subprocess", "sys", "socket", "shutil", "ctypes",
    "pty", "runpy", "code", "commands", "popen2", "multiprocessing", "pdb",
    "bdb", "webbrowser", "platform", "asyncio", "smtplib", "ftplib",
    "telnetlib", "ssl", "_socket", "_posixsubprocess",
})

# Specific (module, name) execution primitives in modules that are otherwise
# benign — flagged ``critical``. ``builtins``/``__builtin__`` give eval/exec/etc.;
# the *load* family triggers a nested unpickle of attacker-controlled bytes.
_EXEC_GLOBALS: dict[str, frozenset[str]] = {
    "builtins": frozenset({
        "eval", "exec", "execfile", "compile", "__import__", "open", "input",
        "getattr", "setattr", "delattr", "globals", "vars", "breakpoint",
        "memoryview", "apply", "classmethod", "staticmethod",
    }),
    "__builtin__": frozenset({
        "eval", "exec", "execfile", "compile", "__import__", "open", "input",
        "getattr", "setattr", "delattr", "globals", "vars", "apply",
    }),
    "pickle": frozenset({"loads", "load", "Unpickler"}),
    "_pickle": frozenset({"loads", "load", "Unpickler"}),
    "cPickle": frozenset({"loads", "load"}),
    "numpy": frozenset({"load", "loads"}),
    "torch": frozenset({"load"}),
    "pandas": frozenset({"read_pickle"}),
    "joblib": frozenset({"load"}),
}

# Reflection / partial-application gadgets — building blocks of a pickle gadget
# chain. Flagged ``high`` (needs chaining; occasionally legitimate).
_GADGET_GLOBALS: dict[str, frozenset[str]] = {
    "operator": frozenset({"attrgetter", "methodcaller", "itemgetter"}),
    "functools": frozenset({"partial", "reduce"}),
    "importlib": frozenset({"import_module", "__import__"}),
    "imp": frozenset({"load_module", "load_source"}),
}

# Opcodes that push a short string literal — used to resolve a STACK_GLOBAL, whose
# (module, name) are the two most recently pushed strings rather than an inline arg.
_STRING_OPCODES = frozenset({
    "SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE",
    "SHORT_BINSTRING", "BINSTRING", "STRING",
})

# Bound the opcode walk so a giant legacy pickle (tensor data inline) can't make a
# scan run unboundedly; a payload's dangerous import appears in the header opcodes,
# long before any bulk data, so this never hides a real finding.
_MAX_OPCODES = 2_000_000
# Cap the bytes read from a single (possibly huge) container member.
_MAX_MEMBER_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True, repr=False)
class ModelPoisonFinding:
    """A data/model-poisoning risk found in a serialized model artifact."""

    id: str
    severity: str  # one of models.SEVERITIES
    model_file: str  # repo-relative path of the model file
    member: str  # container member (e.g. ZIP entry) the risk is in, or ""
    technique: str
    evidence: str
    recommendation: str

    def __repr__(self) -> str:  # compact id-only repr keeps pytest/SARIF output clean
        return f"ModelPoisonFinding({self.id})"

    @property
    def location(self) -> str:
        """The model file, plus the container member when the risk is nested."""
        return f"{self.model_file}!{self.member}" if self.member else self.model_file


def _slug(text: str) -> str:
    """A short, id-safe slug (alnum + dashes) for a finding id."""
    out = "".join(c if c.isalnum() else "-" for c in text).strip("-").lower()
    while "--" in out:
        out = out.replace("--", "-")
    return out[:48] or "x"


def _classify_global(module: str, name: str) -> tuple[str, str, str] | None:
    """Classify a (module, name) import as a poisoning primitive.

    Returns ``(severity, technique, detail)`` or ``None`` when the import is a
    benign rebuild helper (the common case for legitimate weights files).
    """
    top = module.split(".", 1)[0]
    if top in _EXEC_MODULES:
        return ("critical", "code-execution import in serialized model",
                f"unpickling imports '{module}.{name}' — module '{top}' executes "
                "OS/process/network/interpreter code on load")
    exec_names = _EXEC_GLOBALS.get(module) or _EXEC_GLOBALS.get(top)
    if exec_names and name in exec_names:
        return ("critical", "code-execution import in serialized model",
                f"unpickling imports '{module}.{name}', a code-execution / "
                "nested-unpickle primitive")
    gadget_names = _GADGET_GLOBALS.get(module) or _GADGET_GLOBALS.get(top)
    if gadget_names and name in gadget_names:
        return ("high", "pickle gadget primitive in serialized model",
                f"unpickling imports '{module}.{name}', a reflection/partial-"
                "application gadget used to build pickle exploit chains")
    return None


def _scan_pickle_bytes(data: bytes, model_file: str, member: str) -> list[ModelPoisonFinding]:
    """Walk a pickle opcode stream and flag dangerous GLOBAL / STACK_GLOBAL imports.

    Resolves both the inline-argument ``GLOBAL`` and the proto-4 ``STACK_GLOBAL``
    (whose module/name are the two preceding string pushes). Never unpickles.
    """
    findings: list[ModelPoisonFinding] = []
    seen: set[tuple[str, str]] = set()  # (module, name) — dedupe within a stream
    recent_strings: list[str] = []
    try:
        ops = pickletools.genops(data)
        for i, (opcode, arg, _pos) in enumerate(ops):
            if i > _MAX_OPCODES:
                break
            name_str = opcode.name
            if name_str in _STRING_OPCODES and isinstance(arg, str):
                recent_strings.append(arg)
                if len(recent_strings) > 4:
                    recent_strings.pop(0)
                continue
            module = qualname = None
            if name_str == "GLOBAL" and isinstance(arg, str):
                # pickletools joins the module/name pair with a single space.
                parts = arg.split(" ", 1)
                if len(parts) == 2:
                    module, qualname = parts
            elif name_str == "STACK_GLOBAL" and len(recent_strings) >= 2:
                module, qualname = recent_strings[-2], recent_strings[-1]
            if module is None or qualname is None:
                continue
            verdict = _classify_global(module, qualname)
            if verdict is None:
                continue
            key = (module, qualname)
            if key in seen:
                continue
            seen.add(key)
            severity, technique, detail = verdict
            loc = f" in {member}" if member else ""
            findings.append(ModelPoisonFinding(
                id=f"LLM04-{_slug(severity)}-{_slug(module + '-' + qualname)}-"
                   f"{_slug(member or Path(model_file).name)}",
                severity=severity, model_file=model_file, member=member,
                technique=technique,
                evidence=f"{detail}{loc}.",
                recommendation="Do not load this artifact; obtain the model from a "
                               "trusted source and verify its hash. Prefer a code-free "
                               "format (safetensors) and load pickles only with "
                               "weights_only=True / a restricted Unpickler.",
            ))
    except Exception:  # noqa: BLE001 — a non-pickle / truncated stream is simply not scannable
        return findings
    return findings


def _looks_like_pickle(data: bytes) -> bool:
    """Cheap sniff: a protocol-2+ pickle starts with ``\\x80`` + a protocol byte."""
    return len(data) >= 2 and data[0] == 0x80 and data[1] <= 5


def _scan_npy(data: bytes, model_file: str, member: str) -> list[ModelPoisonFinding]:
    """Flag a numpy ``.npy`` whose dtype is ``object`` (load needs allow_pickle).

    Also opcode-scans the trailing pickle (object arrays embed one) for the same
    dangerous imports as a raw pickle.
    """
    findings: list[ModelPoisonFinding] = []
    if not data.startswith(b"\x93NUMPY"):
        return findings
    try:
        major = data[6]
        if major == 1:
            hlen = struct.unpack_from("<H", data, 8)[0]
            hstart = 10
        else:  # v2/v3 use a 4-byte header length
            hlen = struct.unpack_from("<I", data, 8)[0]
            hstart = 12
        header = data[hstart:hstart + hlen].decode("latin-1")
        meta = literal_eval(header.strip())
    except Exception:  # noqa: BLE001 — malformed header: nothing to assert
        return findings
    descr = str(meta.get("descr", "")) if isinstance(meta, dict) else ""
    if "O" in descr:  # object dtype → pickled payload, requires allow_pickle on load
        findings.append(ModelPoisonFinding(
            id=f"LLM04-medium-npy-object-array-{_slug(member or Path(model_file).name)}",
            severity="medium", model_file=model_file, member=member,
            technique="numpy object-array requires unpickling on load",
            evidence=f"numpy array dtype is object ({descr!r}{f' in {member}' if member else ''}); "
                     "loading it needs allow_pickle=True and unpickles embedded objects.",
            recommendation="Store numeric arrays with a concrete dtype; never load an "
                           "untrusted object array with allow_pickle=True.",
        ))
        # The embedded pickle follows the header — opcode-scan it too.
        findings.extend(_scan_pickle_bytes(data[hstart + hlen:], model_file,
                                           member or "<embedded-pickle>"))
    return findings


def _scan_zip(path: Path, rel: str) -> list[ModelPoisonFinding]:
    """Scan the pickle members of a ZIP container (PyTorch ≥1.6 .pt / .npz)."""
    findings: list[ModelPoisonFinding] = []
    try:
        with zipfile.ZipFile(path) as zf:
            for info in zf.infolist():
                if info.is_dir() or info.file_size > _MAX_MEMBER_BYTES:
                    continue
                lname = info.filename.lower()
                member_is_npy = lname.endswith(".npy")
                try:
                    with zf.open(info) as fh:
                        blob = fh.read(_MAX_MEMBER_BYTES)
                except Exception:  # noqa: BLE001 — unreadable member, skip
                    continue
                if member_is_npy:
                    findings.extend(_scan_npy(blob, rel, info.filename))
                elif lname.endswith((".pkl", ".pickle")) or _looks_like_pickle(blob):
                    findings.extend(_scan_pickle_bytes(blob, rel, info.filename))
    except (zipfile.BadZipFile, OSError):
        return findings
    return findings


def scan_model_file(path: str | Path, rel: str | None = None) -> list[ModelPoisonFinding]:
    """Scan one model artifact (raw pickle, numpy, or ZIP container)."""
    path = Path(path)
    rel = rel if rel is not None else path.name
    try:
        head = path.open("rb").read(8)
    except OSError:
        return []
    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
        return _scan_zip(path, rel)
    try:
        data = path.read_bytes()
    except OSError:
        return []
    if data.startswith(b"\x93NUMPY"):
        return _scan_npy(data, rel, "")
    # Raw pickle stream (any protocol) — sniff first, but try regardless for an
    # ASCII protocol-0/1 pickle that has no \x80 header.
    return _scan_pickle_bytes(data, rel, "")


def discover_model_files(root: str | Path) -> list[Path]:
    """Find model artifacts under ``root`` (a file or a directory).

    Recurses directories so nested ``models/`` / ``checkpoints/`` trees are
    covered — a top-level-only scan would call a repo whose weights live in a
    subdirectory "clean", a silent gap for a security tool. Vendored/venv trees
    are pruned. A single file path is returned as-is when it has a model
    extension (or is sniffable as a pickle/zip).
    """
    root = Path(root)
    if root.is_file():
        return [root]
    if not root.is_dir():
        return []
    found: set[Path] = set()
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in _PRUNE_DIRS for part in path.relative_to(root).parts[:-1]):
            continue
        if path.suffix.lower() in _MODEL_EXTS:
            found.add(path)
    return sorted(found)


def scan_model_files(root: str | Path) -> list[ModelPoisonFinding]:
    """Scan every model artifact under ``root`` for data/model-poisoning risks.

    Returns findings sorted worst-first (severity, then file). An empty list means
    no dangerous serialization opcode was found in any model file.
    """
    root = Path(root)
    base = root if root.is_dir() else root.parent
    findings: list[ModelPoisonFinding] = []
    for model in discover_model_files(root):
        try:
            rel = str(model.relative_to(base))
        except ValueError:
            rel = model.name
        findings.extend(scan_model_file(model, rel))
    findings.sort(key=lambda f: (SEVERITY_RANK.get(f.severity, 99), f.model_file, f.member))
    return findings
