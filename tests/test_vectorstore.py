"""Unit tests for the OWASP LLM08 embedding-inversion exposure scanner.

The scanner answers "how much of the corpus does a reader of this store get" from
the store itself, so the fixtures below are real stores built with the standard
library: a Chroma-shaped sqlite file, the JSON store shape LlamaIndex writes, and a
FAISS sidecar pickle. The sidecar case is the one that matters most for safety: the
scanner reads its string constants out of the opcode stream and must never unpickle
it, so the fixture carries a payload that would be visible if it ever did.

Both directions everywhere. A store that keeps only vectors and ids is the shape
worth aiming for, and a scanner that cannot report it clean is a scanner nobody can
use to show they fixed anything.
"""

from __future__ import annotations

import json
import pickletools
import sqlite3
import stat

import pytest

from llmsectest.probes.vectorstore import (
    VectorStoreFinding,
    discover_vector_stores,
    scan_vector_store,
    scan_vector_stores,
    unreadable_stores,
)


def _chroma(path, *, documents=(), metadata=(), collection_meta=(), vectors=True):
    """A Chroma-shaped sqlite store: the tables the reader actually looks at."""
    conn = sqlite3.connect(path)
    if vectors:
        conn.execute("CREATE TABLE embeddings (id INTEGER PRIMARY KEY, vector BLOB)")
        conn.executemany("INSERT INTO embeddings (vector) VALUES (?)",
                         [(b"\x00" * 16,) for _ in range(3)])
    conn.execute("CREATE TABLE embedding_metadata "
                 "(id INTEGER, key TEXT, string_value TEXT)")
    rows = [(i, "chroma:document", d) for i, d in enumerate(documents)]
    rows += [(0, k, v) for k, v in metadata]
    conn.executemany("INSERT INTO embedding_metadata VALUES (?, ?, ?)", rows)
    conn.execute("CREATE TABLE collection_metadata (collection_id TEXT, key TEXT, "
                 "str_value TEXT)")
    conn.executemany("INSERT INTO collection_metadata VALUES ('c', ?, ?)",
                     list(collection_meta))
    conn.commit()
    conn.close()
    return path


def _json_store(path, payload):
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _sidecar(directory, strings):
    """A protocol-4 pickle holding the given strings, beside an index.faiss.

    Built by hand so no real object graph is involved. The strings are what a FAISS
    docstore sidecar carries: the chunks themselves.
    """
    def sbu(s: str) -> bytes:
        b = s.encode()
        if len(b) < 256:
            return b"\x8c" + bytes([len(b)]) + b
        return b"\x8d" + len(b).to_bytes(8, "little") + b

    body = b"\x80\x04]" + b"".join(sbu(s) + b"a" for s in strings) + b"."
    (directory / "index.faiss").write_bytes(b"FAISSfake")
    pkl = directory / "index.pkl"
    pkl.write_bytes(body)
    return pkl


def _ids(findings):
    return {f.technique for f in findings}


# ------------------------------------------------------------------ discovery


def test_a_directory_of_unrelated_json_is_not_walked_as_a_corpus(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "notes.txt").write_text("hello")
    assert discover_vector_stores(tmp_path) == []


def test_a_single_store_file_can_be_passed_directly(tmp_path):
    store = _chroma(tmp_path / "chroma.sqlite3", documents=["a chunk of the corpus"])
    assert discover_vector_stores(store) == [store]


def test_a_store_we_cannot_open_is_named_rather_than_ignored(tmp_path):
    """A recognised file nobody read must not let the caller report a clean store."""
    (tmp_path / "vectors.lance").write_bytes(b"\x00\x01")
    (tmp_path / "chunks.parquet").write_bytes(b"PAR1")
    assert discover_vector_stores(tmp_path) == []
    assert [p.name for p in unreadable_stores(tmp_path)] == ["chunks.parquet",
                                                            "vectors.lance"]


# ------------------------------------------------------------------ chroma


def test_plaintext_beside_vectors_is_the_headline_finding(tmp_path):
    store = _chroma(tmp_path / "chroma.sqlite3",
                    documents=["Board minutes 2026-03: the merger term sheet is signed."])
    findings = scan_vector_store(store, root=tmp_path)
    plaintext = [f for f in findings if f.technique == "plaintext beside vectors"]
    assert len(plaintext) == 1
    assert plaintext[0].severity == "high"
    assert "Board minutes" in plaintext[0].evidence
    assert plaintext[0].store_file == "chroma.sqlite3"


def test_a_store_holding_only_vectors_and_ids_is_clean(tmp_path):
    """The shape worth aiming for has to be reportable as clean."""
    store = _chroma(tmp_path / "chroma.sqlite3")
    assert scan_vector_store(store, root=tmp_path) == []


def test_documents_without_vectors_are_not_an_inversion_finding(tmp_path):
    """A plain document cache is not a vector store, whatever else is wrong with it."""
    store = _chroma(tmp_path / "chroma.sqlite3", documents=["some text"], vectors=False)
    assert scan_vector_store(store, root=tmp_path) == []


def test_the_embedding_space_being_recorded_is_a_medium_finding(tmp_path):
    store = _chroma(tmp_path / "chroma.sqlite3",
                    documents=["a chunk"],
                    collection_meta=[("hnsw:space", "cosine")])
    findings = scan_vector_store(store, root=tmp_path)
    disclosed = [f for f in findings if f.technique == "embedding model disclosed"]
    assert len(disclosed) == 1
    assert disclosed[0].severity == "medium"
    assert "hnsw:space=cosine" in disclosed[0].evidence


def test_a_space_with_a_public_inverter_is_graded_higher(tmp_path):
    """The severity turns on whether an attacker has to train an inverter or call one.

    `vec2text` ships pre-trained correctors for ada-002 and GTR-base and for nothing
    else, checked against its README on 2026-08-31. A store built on one of those is a
    library call from reconstruction; a store on `all-MiniLM-L6-v2` is a training run.
    """
    store = _chroma(tmp_path / "chroma.sqlite3", documents=["a chunk"],
                    collection_meta=[("embedding_model", "text-embedding-ada-002")])
    disclosed = [f for f in scan_vector_store(store, root=tmp_path)
                 if f.technique == "embedding model disclosed"]
    assert len(disclosed) == 1
    assert disclosed[0].severity == "high"
    assert "trains nothing" in disclosed[0].evidence


def test_a_space_with_no_public_inverter_stays_medium(tmp_path):
    """And says the training cost out loud, so nobody reads medium as safe."""
    store = _chroma(tmp_path / "chroma.sqlite3", documents=["a chunk"],
                    collection_meta=[("embedding_model", "all-MiniLM-L6-v2")])
    disclosed = [f for f in scan_vector_store(store, root=tmp_path)
                 if f.technique == "embedding model disclosed"]
    assert len(disclosed) == 1
    assert disclosed[0].severity == "medium"
    assert "training one" in disclosed[0].evidence


def test_source_identifying_metadata_is_reported_separately(tmp_path):
    store = _chroma(tmp_path / "chroma.sqlite3",
                    documents=["a chunk"],
                    metadata=[("file_path", "/srv/hr/salaries.pdf"), ("tenant", "acme")])
    findings = scan_vector_store(store, root=tmp_path)
    source = [f for f in findings if f.technique == "metadata identifies the source"]
    assert len(source) == 1
    assert "file_path" in source[0].evidence and "tenant" in source[0].evidence


@pytest.mark.parametrize("secret,label", [
    ("-----BEGIN RSA PRIVATE KEY-----", "private key block"),
    ("AKIAIOSFODNN7EXAMPLE", "AWS access key id"),
    ("api_key = hunter2hunter2", "assigned secret"),
])
def test_a_credential_in_the_indexed_corpus_is_a_high_finding(tmp_path, secret, label):
    store = _chroma(tmp_path / "chroma.sqlite3",
                    documents=[f"deployment runbook, step 4: {secret}"])
    findings = scan_vector_store(store, root=tmp_path)
    secrets = [f for f in findings if f.technique == "sensitive text stored"]
    assert len(secrets) == 1, findings
    assert label in secrets[0].evidence
    assert secrets[0].severity == "high"


def test_ordinary_prose_is_not_read_as_a_credential(tmp_path):
    """The patterns are narrow on purpose. A scanner that flags a whole corpus is one
    nobody reads twice."""
    store = _chroma(tmp_path / "chroma.sqlite3", documents=[
        "The password policy requires rotation every 90 days. Ask IT for a token.",
        "Our secret sauce is that we answer the phone.",
    ])
    findings = scan_vector_store(store, root=tmp_path)
    assert not [f for f in findings if f.technique == "sensitive text stored"]


def test_file_mode_is_only_reported_when_something_is_exposed(tmp_path):
    """A world-readable store holding nothing recoverable is not a finding."""
    clean = _chroma(tmp_path / "chroma.sqlite3")
    clean.chmod(0o644)
    assert scan_vector_store(clean, root=tmp_path) == []

    (tmp_path / "sub").mkdir()
    leaky = _chroma(tmp_path / "sub" / "chroma.sqlite3", documents=["a chunk"])
    leaky.chmod(0o644)
    modes = [f for f in scan_vector_store(leaky, root=tmp_path)
             if f.technique == "world-readable store"]
    assert len(modes) == 1
    assert "other" in modes[0].evidence


def test_a_store_readable_only_by_its_owner_raises_no_mode_finding(tmp_path):
    store = _chroma(tmp_path / "chroma.sqlite3", documents=["a chunk"])
    store.chmod(stat.S_IRUSR | stat.S_IWUSR)
    assert not [f for f in scan_vector_store(store, root=tmp_path)
                if f.technique == "world-readable store"]


def test_a_store_that_is_not_sqlite_at_all_is_survived(tmp_path):
    """A corrupt or foreign file must not crash a scan of the directory it sits in."""
    (tmp_path / "chroma.sqlite3").write_bytes(b"not a database")
    assert scan_vector_stores(tmp_path) == []


# ------------------------------------------------------------------ json stores


def test_the_llamaindex_json_store_shape_is_read(tmp_path):
    store = _json_store(tmp_path / "default__vector_store.json", {
        "embedding_dict": {"n1": [0.1] * 12, "n2": [0.2] * 12},
        "metadata_dict": {"n1": {"file_name": "q3-forecast.xlsx"}},
        "text_id_to_ref_doc_id": {"n1": "doc-1"},
        "documents": ["Q3 forecast: we miss plan by 14 percent."],
    })
    findings = scan_vector_store(store, root=tmp_path)
    assert "plaintext beside vectors" in _ids(findings)
    assert "metadata identifies the source" in _ids(findings)


def test_a_short_number_list_is_not_mistaken_for_an_embedding(tmp_path):
    """`{"scores": [1, 2, 3]}` beside some text would otherwise be a false positive."""
    store = _json_store(tmp_path / "vector_store.json", {
        "scores": [1, 2, 3],
        "documents": ["some text that is not in any vector store"],
    })
    assert scan_vector_store(store, root=tmp_path) == []


def test_a_json_store_of_vectors_and_ids_only_is_clean(tmp_path):
    store = _json_store(tmp_path / "vector_store.json", {
        "embeddings": [[0.1] * 16, [0.2] * 16], "ids": ["a", "b"]})
    assert scan_vector_store(store, root=tmp_path) == []


def test_a_jsonl_store_is_found_by_a_directory_walk(tmp_path):
    """It was not, until 2026-08-31, while the skip message listed JSONL among the
    formats it had looked for. `.json` stays name-matched, because globbing the most
    common configuration extension would read a `package.json` as a corpus."""
    (tmp_path / "store.jsonl").write_text(
        json.dumps({"embedding": [0.1] * 16,
                    "text": "Q3 forecast: we miss plan by 14 percent.",
                    "source": "/srv/kb/q3.md"}) + "\n", encoding="utf-8")
    assert [p.name for p in discover_vector_stores(tmp_path)] == ["store.jsonl"]
    assert "plaintext beside vectors" in _ids(scan_vector_stores(tmp_path))


def test_an_ordinary_json_config_beside_a_store_is_still_not_walked(tmp_path):
    """The other side of that asymmetry, so the fix cannot widen into the corpus."""
    (tmp_path / "package.json").write_text(
        json.dumps({"embeddings": [[0.1] * 16], "documents": ["not a corpus"]}))
    assert discover_vector_stores(tmp_path) == []


def test_malformed_json_is_survived(tmp_path):
    (tmp_path / "docstore.json").write_text("{not json", encoding="utf-8")
    assert scan_vector_stores(tmp_path) == []


# ------------------------------------------------------------------ faiss sidecar


def test_a_faiss_sidecar_is_read_without_being_unpickled(tmp_path, monkeypatch):
    """The safety property, asserted rather than assumed.

    `pickle.loads` on a sidecar would run whatever the sidecar also holds, which is
    the attack the LLM04 scanner exists to find. Reading a store must never be the
    thing that compromises the machine reading it.
    """
    import pickle as pickle_module

    def refuse(*_a, **_kw):
        raise AssertionError("the scanner unpickled a file it was only meant to read")

    monkeypatch.setattr(pickle_module, "loads", refuse)
    monkeypatch.setattr(pickle_module, "load", refuse)

    _sidecar(tmp_path, [("Internal memo: the Frankfurt office closes in Q1, do not "
                         "circulate this outside the leadership team.")])
    findings = scan_vector_stores(tmp_path)
    assert "plaintext beside vectors" in _ids(findings)


def test_a_sidecar_with_no_faiss_index_beside_it_holds_no_vectors(tmp_path):
    """Without the index there is nothing to invert, so the pickle is just a file."""
    _sidecar(tmp_path, [("Internal memo: the Frankfurt office closes in Q1, and this "
                         "is long enough to be read as a chunk of a corpus.")])
    (tmp_path / "index.faiss").unlink()
    assert scan_vector_stores(tmp_path) == []


def test_a_truncated_sidecar_is_survived(tmp_path):
    (tmp_path / "index.faiss").write_bytes(b"FAISSfake")
    (tmp_path / "index.pkl").write_bytes(b"\x80\x04\x8c\x40trunc")
    assert scan_vector_stores(tmp_path) == []


def test_the_fixture_really_is_a_pickle_carrying_its_strings_as_opcodes(tmp_path):
    """A fixture check, not a guarantee about the reader.

    It was called `test_the_sidecar_reader_walks_opcodes` and said it pinned the
    mechanism, which it cannot: it walks the fixture with `pickletools` inside the test
    and never calls the reader at all, so rewriting `_read_pickle_strings` to use
    `pickle.load` would leave it green. Renamed on 2026-08-31 by a fresh-context reader.
    What it is good for is the other half: if this fails, the sibling test below is
    passing over a file that was never a pickle. **The safety property is pinned by
    `test_a_faiss_sidecar_is_read_without_being_unpickled`**, which makes `pickle.load`
    raise and still expects a finding.
    """
    pkl = _sidecar(tmp_path, ["a" * 50])
    with pkl.open("rb") as fh:
        names = {op.name for op, _arg, _pos in pickletools.genops(fh)}
    assert "SHORT_BINUNICODE" in names


# ------------------------------------------------------------------ aggregation


def test_findings_are_ordered_by_store_then_severity(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    _chroma(tmp_path / "b" / "chroma.sqlite3",
            documents=["a chunk"], collection_meta=[("model", "all-MiniLM-L6-v2")])
    _chroma(tmp_path / "a" / "chroma.sqlite3", documents=["another chunk"])
    findings = scan_vector_stores(tmp_path)
    files = [f.store_file for f in findings]
    assert files == sorted(files)
    order = ["high", "medium"]
    b_sevs = [f.severity for f in findings if f.store_file.startswith("b")]
    assert b_sevs == sorted(b_sevs, key=order.index)


def test_an_unknown_severity_is_refused(tmp_path):
    with pytest.raises(ValueError):
        VectorStoreFinding(id="x", severity="catastrophic", store_file="s",
                           technique="t", evidence="e", recommendation="r")
