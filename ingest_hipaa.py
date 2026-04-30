#!/usr/bin/env python3
"""
ingest_hipaa.py — Embed HIPAA chunks with BGE-M3 and upsert to Qdrant.

Reads:
    out/controls.jsonl   (built by build_chunks.py)
    out/reference.jsonl

Creates two Qdrant collections:
    hipaa_controls   — gap-analysis target
    hipaa_reference  — definitions + procedural + authority

Each chunk is embedded with BGE-M3 (dense 1024-dim + sparse lexical) in one
forward pass. Point IDs are derived deterministically from chunk_id via
UUID5, so re-ingestion replaces existing points instead of duplicating them.

Hybrid retrieval uses Qdrant's native Prefetch + FusionQuery (RRF). An
optional reranker pass (bge-reranker-v2-m3) lifts top-k precision.

Usage:
    python ingest_hipaa.py                     # build collections from JSONL
    python ingest_hipaa.py search "QUERY"      # hybrid search
    python ingest_hipaa.py search "QUERY" --filter rule_category=security \
                                          --filter designation=Required \
                                          --rerank
"""
from __future__ import annotations

import json
import sys
import uuid
from pathlib import Path
from typing import Optional

from FlagEmbedding import BGEM3FlagModel
from qdrant_client import QdrantClient, models

# ---------------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------------

ROOT = Path(__file__).resolve().parent
OUT_DIR = ROOT / "out"
QDRANT_PATH = ROOT / "qdrant_data"

CONTROLS_COLLECTION = "hipaa_controls"
REFERENCE_COLLECTION = "hipaa_reference"

EMBED_MODEL = "BAAI/bge-m3"
RERANK_MODEL = "BAAI/bge-reranker-v2-m3"
DENSE_DIM = 1024
BATCH_SIZE = 16
MAX_LEN = 2048

# Stable namespace for deriving deterministic UUIDs from chunk_ids.
# Re-running ingestion with the same chunk_ids upserts the same points.
CHUNK_ID_NAMESPACE = uuid.UUID("8d5a7c92-6e5b-4f23-a8a7-7d8c5b1f9e2a")

# Payload fields that gap-analysis queries should be able to filter on.
PAYLOAD_INDEXES = [
    ("part", models.PayloadSchemaType.KEYWORD),
    ("subpart", models.PayloadSchemaType.KEYWORD),
    ("section", models.PayloadSchemaType.KEYWORD),
    ("rule_category", models.PayloadSchemaType.KEYWORD),
    ("safeguard_type", models.PayloadSchemaType.KEYWORD),
    ("designation", models.PayloadSchemaType.KEYWORD),
    ("applies_to", models.PayloadSchemaType.KEYWORD),
    ("chunk_type", models.PayloadSchemaType.KEYWORD),
]


# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------

def chunk_uuid(chunk_id: str) -> str:
    """Deterministic UUID5 from a chunk_id string. Same chunk_id always
    produces the same UUID, so upserts are idempotent."""
    return str(uuid.uuid5(CHUNK_ID_NAMESPACE, chunk_id))


def load_chunks(path: Path) -> list[dict]:
    rows = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def to_qdrant_sparse(weights) -> models.SparseVector:
    """BGE-M3 returns lexical_weights as a dict {token_id: weight}.
    Qdrant wants parallel index/value lists. Empty-vector guard avoids
    Qdrant rejecting zero-length sparse points."""
    items = list(weights.items()) if isinstance(weights, dict) else list(weights)
    if not items:
        return models.SparseVector(indices=[0], values=[0.0])
    items = sorted(items, key=lambda x: int(x[0]))
    return models.SparseVector(
        indices=[int(k) for k, _ in items],
        values=[float(v) for _, v in items],
    )


def ensure_collection(client: QdrantClient, name: str) -> None:
    """(Re)create a hybrid collection with named dense + sparse vectors and
    payload indexes for filterable fields. Drops the collection first to
    keep this idempotent."""
    if client.collection_exists(name):
        client.delete_collection(name)
    client.create_collection(
        collection_name=name,
        vectors_config={
            "dense": models.VectorParams(
                size=DENSE_DIM,
                distance=models.Distance.COSINE,
            ),
        },
        sparse_vectors_config={
            "sparse": models.SparseVectorParams(
                index=models.SparseIndexParams(full_scan_threshold=2000),
            ),
        },
    )
    for field, schema in PAYLOAD_INDEXES:
        client.create_payload_index(name, field_name=field, field_schema=schema)


# ---------------------------------------------------------------------------
# INGESTION
# ---------------------------------------------------------------------------

def embed_and_upsert(
    client: QdrantClient,
    model: BGEM3FlagModel,
    chunks: list[dict],
    collection: str,
) -> None:
    total = len(chunks)
    for i in range(0, total, BATCH_SIZE):
        batch = chunks[i : i + BATCH_SIZE]
        texts = [c["text"] for c in batch]
        emb = model.encode(
            texts,
            batch_size=BATCH_SIZE,
            max_length=MAX_LEN,
            return_dense=True,
            return_sparse=True,
        )
        dense = emb["dense_vecs"]
        sparse = emb["lexical_weights"]
        points = []
        for j, c in enumerate(batch):
            points.append(
                models.PointStruct(
                    id=chunk_uuid(c["chunk_id"]),
                    vector={
                        "dense": dense[j].tolist(),
                        "sparse": to_qdrant_sparse(sparse[j]),
                    },
                    # Full chunk dict goes into payload — gives the app
                    # everything (citation, designation, parent standard,
                    # text_raw, etc.) without an extra DB.
                    payload=c,
                )
            )
        client.upsert(collection_name=collection, points=points)
        print(f"  {collection}: {min(i + BATCH_SIZE, total)}/{total}")


def main_ingest() -> int:
    controls_path = OUT_DIR / "controls.jsonl"
    reference_path = OUT_DIR / "reference.jsonl"
    if not controls_path.exists() or not reference_path.exists():
        print(
            "ERROR: run build_chunks.py first to produce the JSONL inputs.",
            file=sys.stderr,
        )
        return 1

    controls = load_chunks(controls_path)
    reference = load_chunks(reference_path)
    print(f"loaded {len(controls)} controls + {len(reference)} reference chunks")

    print(f"loading {EMBED_MODEL} (slow on first run; downloads weights)...")
    model = BGEM3FlagModel(EMBED_MODEL, use_fp16=True)

    client = QdrantClient(path=str(QDRANT_PATH))

    print(f"creating collection: {CONTROLS_COLLECTION}")
    ensure_collection(client, CONTROLS_COLLECTION)
    embed_and_upsert(client, model, controls, CONTROLS_COLLECTION)

    print(f"creating collection: {REFERENCE_COLLECTION}")
    ensure_collection(client, REFERENCE_COLLECTION)
    embed_and_upsert(client, model, reference, REFERENCE_COLLECTION)

    print("done.")
    return 0


# ---------------------------------------------------------------------------
# HYBRID SEARCH
# ---------------------------------------------------------------------------

_model_cache: Optional[BGEM3FlagModel] = None
_reranker_cache = None


def _get_model() -> BGEM3FlagModel:
    global _model_cache
    if _model_cache is None:
        _model_cache = BGEM3FlagModel(EMBED_MODEL, use_fp16=True)
    return _model_cache


def _get_reranker():
    global _reranker_cache
    if _reranker_cache is None:
        from FlagEmbedding import FlagReranker
        _reranker_cache = FlagReranker(RERANK_MODEL, use_fp16=True)
    return _reranker_cache


def _build_filter(filters: dict) -> Optional[models.Filter]:
    if not filters:
        return None
    must = []
    for k, v in filters.items():
        if isinstance(v, list):
            must.append(models.FieldCondition(key=k, match=models.MatchAny(any=v)))
        else:
            must.append(models.FieldCondition(key=k, match=models.MatchValue(value=v)))
    return models.Filter(must=must)


def hybrid_search(
    query: str,
    collection: str = CONTROLS_COLLECTION,
    *,
    filters: Optional[dict] = None,
    prefetch_limit: int = 50,
    final_limit: int = 10,
    rerank: bool = False,
) -> list:
    """True hybrid retrieval: dense + sparse Prefetch fused with RRF.

    Args:
        query: natural-language query string
        collection: hipaa_controls or hipaa_reference
        filters: dict of payload field -> value or list of values
                 (e.g. {"rule_category": "security", "designation": "Required"})
        prefetch_limit: candidates retrieved per vector before fusion
        final_limit: results returned after fusion (and rerank, if enabled)
        rerank: if True, run bge-reranker-v2-m3 over top-30 fused candidates
    """
    client = QdrantClient(path=str(QDRANT_PATH))
    model = _get_model()
    enc = model.encode([query], return_dense=True, return_sparse=True)
    dense_q = enc["dense_vecs"][0].tolist()
    sparse_q = to_qdrant_sparse(enc["lexical_weights"][0])

    qfilter = _build_filter(filters or {})

    # Pull a wider candidate pool when reranking, since cross-encoder will
    # reorder; final_limit is the post-rerank cut.
    candidate_limit = max(final_limit, 30) if rerank else final_limit

    res = client.query_points(
        collection_name=collection,
        prefetch=[
            models.Prefetch(
                query=dense_q,
                using="dense",
                limit=prefetch_limit,
                filter=qfilter,
            ),
            models.Prefetch(
                query=sparse_q,
                using="sparse",
                limit=prefetch_limit,
                filter=qfilter,
            ),
        ],
        query=models.FusionQuery(fusion=models.Fusion.RRF),
        with_payload=True,
        limit=candidate_limit,
    )
    hits = res.points

    if rerank and hits:
        reranker = _get_reranker()
        pairs = [[query, h.payload.get("text_raw") or h.payload["text"]] for h in hits]
        scores = reranker.compute_score(pairs, normalize=True)
        # Attach rerank score as a post-hoc attribute.
        for h, s in zip(hits, scores):
            h.score = float(s)
        hits = sorted(hits, key=lambda h: -h.score)[:final_limit]

    return hits


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

USAGE = (
    "usage:\n"
    "  python ingest_hipaa.py                       # build / re-build collections\n"
    "  python ingest_hipaa.py search \"QUERY\" \\\n"
    "                            [--collection hipaa_controls|hipaa_reference] \\\n"
    "                            [--filter key=value]... [--rerank] [--limit N]\n"
)


def cli_search() -> int:
    args = sys.argv[2:]
    rerank = False
    limit = 10
    collection = CONTROLS_COLLECTION
    filters: dict = {}
    positional: list[str] = []

    i = 0
    while i < len(args):
        a = args[i]
        if a == "--rerank":
            rerank = True
            i += 1
        elif a == "--limit":
            limit = int(args[i + 1])
            i += 2
        elif a == "--collection":
            collection = args[i + 1]
            i += 2
        elif a == "--filter":
            k, v = args[i + 1].split("=", 1)
            # allow comma-separated multi-value
            filters[k] = v.split(",") if "," in v else v
            i += 2
        else:
            positional.append(a)
            i += 1

    if not positional:
        print(USAGE, file=sys.stderr)
        return 1

    query = " ".join(positional)
    hits = hybrid_search(
        query,
        collection=collection,
        filters=filters or None,
        final_limit=limit,
        rerank=rerank,
    )

    print(f"\nQuery: {query!r}")
    print(f"Collection: {collection}")
    if filters:
        print(f"Filters: {filters}")
    print(f"Reranker: {'on' if rerank else 'off'}")
    print()
    if not hits:
        print("(no results)")
        return 0
    for h in hits:
        p = h.payload
        des = p.get("designation") or "—"
        cat = p.get("rule_category") or "—"
        title = p.get("implementation_spec_title") or p.get("term") or p.get("section_title", "")
        print(
            f"[{h.score:.3f}] {p.get('citation',''):32}  "
            f"{cat:20}  {des:11}  {title[:50]}"
        )
        snippet = (p.get("text_raw") or p.get("text") or "")[:240].replace("\n", " ")
        print(f"        {snippet}...\n")
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "search":
        raise SystemExit(cli_search())
    raise SystemExit(main_ingest())
