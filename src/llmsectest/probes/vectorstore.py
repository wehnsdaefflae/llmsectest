"""OWASP LLM08 — embedding-inversion exposure (white-box vector-store scan, offline).

Embedding inversion is the attack where the source text is recovered from the
vectors a RAG system stores. The published work is real (``vec2text`` and its
successors reconstruct a large share of a short passage from its embedding alone,
for embedding spaces whose model is public), but running an inversion is not
something a scanner can ship: it needs a trained inversion model per embedding
space, a GPU, and a corpus to train on. A tool that claimed to invert your
embeddings would be claiming something it cannot do offline in CI.

So this module asks the question inversion asks and answers it from the store:
**how much of the corpus does somebody who reads this directory get?** In most
deployments the answer is *all of it, without inverting anything*, because the
store keeps the plaintext next to the vector it was made from. That result is
worth more than an inversion score. It is exact, it is reproducible without a
model, and the remedy is a deployment change rather than research.

What it flags, per store:

* **plaintext beside vectors** (``high``) — the same file or table holds the
  embeddings and the text they were made from. Inversion is unnecessary: read
  access to the store is read access to the corpus.
* **sensitive text stored** (``high``) — stored text or metadata matches a
  credential or key shape. The corpus itself carries a secret, so the store is
  holding material at a higher classification than a vector index usually gets.
* **embedding model disclosed** (``medium``) — the store records which embedding
  model or space produced the vectors. That is what an inversion attack needs
  first: an attacker holding a vector dump for a *named public* model can obtain
  or train an inverter for exactly that space, where an unlabelled dump costs
  them a guess.
* **metadata identifies the source** (``medium``) — per-vector metadata carries
  file paths, document ids, authors or tenant keys. Recovering *which* document a
  vector came from is often the whole attack, and no inversion is involved.
* **world-readable store** (``medium``) — the store file grants read to group or
  other, so the two findings above are available to every local account.

Formats read, standard library only, no network and no model load:

* **Chroma** — ``chroma.sqlite3``, opened read-only, tables ``embeddings``,
  ``embedding_metadata``, ``collection_metadata``.
* **JSON / JSONL** — LlamaIndex's simple store (``default__vector_store.json``,
  ``docstore.json``) and the generic ``{"embeddings": [...], "documents": [...]}``
  shape written by scripts and notebooks.
* **FAISS sidecar pickles** — ``index.pkl`` beside an ``index.faiss``. **Never
  unpickled.** The opcode stream is walked with :mod:`pickletools` exactly as
  :mod:`llmsectest.probes.modelpoison` walks a weights file, and the string
  constants are read out of it. Loading a pickle to find out whether it holds
  your corpus would run whatever else it holds.

A store that keeps only vectors and ids produces no finding, which is the shape
worth aiming for. Formats needing a third-party reader (LanceDB, Parquet, Qdrant
snapshots) are reported as *unread* by :func:`unreadable_stores` rather than
skipped in silence: a scanner that cannot open a file must not let its caller read
the result as a clean store.
"""

from __future__ import annotations

import json
import pickletools
import re
import sqlite3
import stat
from dataclasses import dataclass
from pathlib import Path

from .models import SEVERITIES

#: Files that are a vector store, by name. Matched case-insensitively on the
#: whole name so a directory of unrelated JSON is not walked as a corpus.
CHROMA_NAMES = ("chroma.sqlite3", "chroma.db")
JSON_NAMES = (
    "default__vector_store.json",
    "docstore.json",
    "index_store.json",
    "vector_store.json",
    "embeddings.json",
)
PICKLE_SIDECAR_NAMES = ("index.pkl",)

#: Keys whose presence in a JSON object means "this object holds vectors".
_VECTOR_KEYS = ("embedding", "embeddings", "vector", "vectors", "embedding_dict")
#: Keys whose presence means "this object holds the text the vectors were made from".
_TEXT_KEYS = ("document", "documents", "text", "page_content", "content", "chunk")
#: Metadata keys that identify where a chunk came from.
_SOURCE_KEYS = (
    "source", "file_path", "filename", "file_name", "path", "url", "doc_id",
    "document_id", "author", "tenant", "tenant_id", "user_id", "owner",
)
#: Keys under which a store records the embedding space or model it used.
_MODEL_KEYS = ("model", "model_name", "embedding_model", "embed_model", "hnsw:space",
               "embedding_function", "space")

#: Credential shapes worth naming in a corpus. Deliberately narrow: a pattern that
#: matches any long token flags every base64 chunk in the store, and a scanner that
#: flags a whole corpus is one nobody reads twice.
_SECRET_PATTERNS = (
    ("private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("OpenAI-style API key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("assigned secret", re.compile(
        r"(?i)\b(?:api[_-]?key|secret|password|passwd|token)\b\s*[:=]\s*\S{8,}")),
)

#: How much stored text to read per store. A vector store is routinely gigabytes,
#: and the question here is "does this store hold plaintext at all", which the
#: first megabyte answers as well as the last.
TEXT_SAMPLE_BYTES = 1_000_000


@dataclass(frozen=True, repr=False)
class VectorStoreFinding:
    """An embedding-inversion exposure found in a persisted vector store."""

    id: str
    severity: str  # one of models.SEVERITIES
    store_file: str  # path of the store, relative to the scanned root
    technique: str
    evidence: str
    recommendation: str

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"unknown severity {self.severity!r}")

    def __repr__(self) -> str:  # compact id-only repr keeps pytest/SARIF output clean
        return f"VectorStoreFinding({self.id})"

    @property
    def location(self) -> str:
        return self.store_file


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:60]


def discover_vector_stores(root: Path) -> list[Path]:
    """Every readable vector store under ``root``, sorted for a stable scan order.

    A single file path is accepted as well as a directory, so ``--vector-store
    chroma.sqlite3`` works without the caller knowing our discovery rules.
    """
    if root.is_file():
        return [root] if _kind(root) else []
    names = {n.lower() for n in CHROMA_NAMES + JSON_NAMES + PICKLE_SIDECAR_NAMES}
    return sorted(p for p in root.rglob("*") if p.is_file() and p.name.lower() in names)


def _kind(path: Path) -> str:
    name = path.name.lower()
    if name in {n.lower() for n in CHROMA_NAMES}:
        return "chroma"
    if name in {n.lower() for n in JSON_NAMES} or name.endswith((".json", ".jsonl")):
        return "json"
    if name in {n.lower() for n in PICKLE_SIDECAR_NAMES}:
        return "pickle"
    return ""


def unreadable_stores(root: Path) -> list[Path]:
    """Store files we recognise by name but cannot open without a third-party reader.

    Returned so the caller can say so. LanceDB, Parquet and Qdrant snapshots hold
    exactly the same plaintext this scan looks for, and reporting nothing about them
    would let a store we never opened read as a store with no findings.
    """
    if root.is_file():
        root = root.parent
    if not root.is_dir():
        return []
    suffixes = (".lance", ".parquet", ".qdrant", ".duckdb")
    return sorted(p for p in root.rglob("*")
                  if p.is_file() and p.suffix.lower() in suffixes)


def _sample_text(values: list[str]) -> str:
    out, size = [], 0
    for v in values:
        out.append(v)
        size += len(v)
        if size >= TEXT_SAMPLE_BYTES:
            break
    return "\n".join(out)


def _read_chroma(path: Path) -> tuple[list[str], list[str], list[str], bool]:
    """(text values, source-key names, model labels, whether vectors are present).

    Opened read-only through a URI so a scan can never write to the store it is
    inspecting, and every table is optional: Chroma has changed its schema between
    releases and a missing table is a different Chroma, never a reason to fail.
    """
    texts: list[str] = []
    sources: set[str] = set()
    models: set[str] = set()
    vectors = False
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    except sqlite3.Error:
        return [], [], [], False
    try:
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        if {"embeddings", "embedding_fulltext_search", "embeddings_queue"} & tables:
            vectors = True
        for table in ("embedding_metadata", "embedding_fulltext_search_content"):
            if table not in tables:
                continue
            cols = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
            if "string_value" in cols and "key" in cols:
                for key, value in conn.execute(
                        f"SELECT key, string_value FROM {table} WHERE string_value IS NOT NULL"):
                    if key in _TEXT_KEYS or key == "chroma:document":
                        texts.append(str(value))
                    elif key in _SOURCE_KEYS:
                        sources.add(str(key))
                    elif key in _MODEL_KEYS:
                        models.add(f"{key}={value}")
            elif "c0" in cols:
                for (value,) in conn.execute(f"SELECT c0 FROM {table}"):
                    if value:
                        texts.append(str(value))
        if "collection_metadata" in tables:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(collection_metadata)")}
            if {"key", "str_value"} <= cols:
                for key, value in conn.execute(
                        "SELECT key, str_value FROM collection_metadata"):
                    if key in _MODEL_KEYS and value:
                        models.add(f"{key}={value}")
    except sqlite3.Error:
        pass
    finally:
        conn.close()
    return texts, sorted(sources), sorted(models), vectors


def _walk_json(node, texts: list[str], sources: set[str], models: set[str],
               state: dict) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            lower = str(key).lower()
            if lower in _VECTOR_KEYS and _looks_like_vectors(value):
                state["vectors"] = True
            elif lower in _TEXT_KEYS and isinstance(value, str):
                texts.append(value)
            elif lower in _TEXT_KEYS and isinstance(value, list):
                texts.extend(v for v in value if isinstance(v, str))
            elif lower in _SOURCE_KEYS:
                sources.add(str(key))
            elif lower in _MODEL_KEYS and isinstance(value, str) and value:
                models.add(f"{key}={value}")
            _walk_json(value, texts, sources, models, state)
    elif isinstance(node, list):
        for item in node:
            _walk_json(item, texts, sources, models, state)


def _looks_like_vectors(value) -> bool:
    """A float list, a list of float lists, or a dict of either."""
    if isinstance(value, dict):
        return any(_looks_like_vectors(v) for v in list(value.values())[:4])
    if not isinstance(value, list) or not value:
        return False
    head = value[0]
    if isinstance(head, (int, float)) and not isinstance(head, bool):
        return len(value) >= 8
    return isinstance(head, list) and _looks_like_vectors(head)


def _read_json(path: Path) -> tuple[list[str], list[str], list[str], bool]:
    texts: list[str] = []
    sources: set[str] = set()
    models: set[str] = set()
    state = {"vectors": False}
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return [], [], [], False
    documents: list = []
    if path.suffix.lower() == ".jsonl":
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                documents.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    else:
        try:
            documents.append(json.loads(raw))
        except json.JSONDecodeError:
            return [], [], [], False
    for doc in documents:
        _walk_json(doc, texts, sources, models, state)
    return texts, sorted(sources), sorted(models), state["vectors"]


def _read_pickle_strings(path: Path) -> tuple[list[str], list[str], list[str], bool]:
    """String constants in a pickle's opcode stream. **Never unpickles.**

    A FAISS sidecar holds the docstore, so its strings are the corpus. Reading them
    by loading the file would execute whatever the file also holds, which is the
    attack :mod:`llmsectest.probes.modelpoison` exists to find.
    """
    texts: list[str] = []
    sources: set[str] = set()
    models: set[str] = set()
    string_ops = {"STRING", "BINSTRING", "SHORT_BINSTRING", "UNICODE", "BINUNICODE",
                  "SHORT_BINUNICODE", "BINUNICODE8"}
    try:
        with path.open("rb") as fh:
            for opcode, arg, _pos in pickletools.genops(fh):
                if opcode.name not in string_ops or not isinstance(arg, (str, bytes)):
                    continue
                value = arg.decode("utf-8", "replace") if isinstance(arg, bytes) else arg
                lower = value.lower()
                if lower in _SOURCE_KEYS:
                    sources.add(value)
                elif lower in _MODEL_KEYS:
                    models.add(value)
                elif len(value) >= 40:
                    texts.append(value)
    except (OSError, ValueError, KeyError, IndexError):
        # A truncated or non-pickle file is not a store we can speak about.
        return [], [], [], False
    faiss = path.with_suffix(".faiss")
    return texts, sorted(sources), sorted(models), faiss.exists()


_READERS = {"chroma": _read_chroma, "json": _read_json, "pickle": _read_pickle_strings}


def _world_readable(path: Path) -> str:
    try:
        mode = path.stat().st_mode
    except OSError:
        return ""
    bits = [name for name, bit in (("group", stat.S_IRGRP), ("other", stat.S_IROTH))
            if mode & bit]
    return ", ".join(bits)


def scan_vector_store(path: Path, root: Path | None = None) -> list[VectorStoreFinding]:
    """Every embedding-inversion exposure in one persisted store."""
    kind = _kind(path)
    reader = _READERS.get(kind)
    if reader is None:
        return []
    base = root if root is not None else (path if path.is_dir() else path.parent)
    try:
        where = str(path.relative_to(base))
    except ValueError:
        where = str(path)
    texts, sources, models, vectors = reader(path)
    findings: list[VectorStoreFinding] = []

    if vectors and texts:
        sample = _sample_text(texts)
        findings.append(VectorStoreFinding(
            id=f"vectorstore-plaintext-{_slug(where)}",
            severity="high",
            store_file=where,
            technique="plaintext beside vectors",
            evidence=(
                f"{len(texts)} stored text value(s) sit in the same store as the "
                f"embeddings, first one begins {sample[:80]!r}. Recovering the corpus "
                f"needs no inversion at all: read access to this file is read access "
                f"to every document that was indexed."
            ),
            recommendation=(
                "Store the vectors and the documents separately, under separate "
                "credentials, and keep only an opaque id in the vector store. If the "
                "text has to stay, treat the store as holding the corpus and give it "
                "the corpus's access controls."
            ),
        ))
        for label, pattern in _SECRET_PATTERNS:
            match = pattern.search(sample)
            if not match:
                continue
            findings.append(VectorStoreFinding(
                id=f"vectorstore-secret-{_slug(label)}-{_slug(where)}",
                severity="high",
                store_file=where,
                technique="sensitive text stored",
                evidence=(
                    f"stored text matches a known credential shape ({label}) at offset "
                    f"{match.start()} of the sampled text. The indexed corpus carries a "
                    f"credential, so the vector store now holds it too."
                ),
                recommendation=(
                    "Take the credential out of the corpus and re-index. Rotate it: "
                    "anything that reached an embedding store has been copied at least "
                    "once more than you intended."
                ),
            ))

    if vectors and models:
        findings.append(VectorStoreFinding(
            id=f"vectorstore-model-disclosed-{_slug(where)}",
            severity="medium",
            store_file=where,
            technique="embedding model disclosed",
            evidence=(
                f"the store records the embedding space it was built with "
                f"({'; '.join(models[:3])}). An attacker who copies the vectors knows "
                f"which inverter to bring, and public inversion models exist for the "
                f"common open embedding models."
            ),
            recommendation=(
                "Classify a vector dump at the same level as the corpus. Naming the "
                "model is useful to your own operators, so the fix is the access "
                "control on the dump rather than hiding the label."
            ),
        ))

    if vectors and sources:
        findings.append(VectorStoreFinding(
            id=f"vectorstore-source-metadata-{_slug(where)}",
            severity="medium",
            store_file=where,
            technique="metadata identifies the source",
            evidence=(
                f"per-vector metadata carries source-identifying key(s): "
                f"{', '.join(sources[:6])}. Knowing which document a vector came from "
                f"is frequently the whole objective, with no reconstruction needed."
            ),
            recommendation=(
                "Keep only the fields retrieval actually filters on. Paths, authors "
                "and tenant ids belong in a table the retrieval layer joins against "
                "after it has checked who is asking."
            ),
        ))

    if findings:
        readable = _world_readable(path)
        if readable:
            findings.append(VectorStoreFinding(
                id=f"vectorstore-world-readable-{_slug(where)}",
                severity="medium",
                store_file=where,
                technique="world-readable store",
                evidence=(
                    f"the store file is readable by {readable}. Every exposure above is "
                    f"available to any local account, not only to the service."
                ),
                recommendation=(
                    "Restrict the store to the service account that owns it "
                    "(`chmod 600`), and check the parent directory's mode too."
                ),
            ))
    return findings


def scan_vector_stores(root: Path) -> list[VectorStoreFinding]:
    """Scan every store under ``root``, ordered by store then severity."""
    order = {s: i for i, s in enumerate(SEVERITIES)}
    findings: list[VectorStoreFinding] = []
    for store in discover_vector_stores(root):
        findings.extend(scan_vector_store(store, root=root if root.is_dir() else root.parent))
    return sorted(findings, key=lambda f: (f.store_file, order[f.severity], f.id))
