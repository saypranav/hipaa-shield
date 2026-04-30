# HIPAA Regulation Chunking Design

**Date:** 2026-04-25
**Inputs:** `45 CFR Part 160 (up to date as of 4-23-2026).pdf`, `45 CFR Part 164 (up to date as of 4-23-2026).pdf`
**Downstream consumer:** Gap-analysis HIPAA compliance application (RAG over a Qdrant collection)

## Goal

Produce paragraph-leaf-level chunks of 45 CFR Parts 160 and 164 such that each chunk represents a single, evaluable requirement an organization can be measured against.

## Decisions

| # | Decision | Rationale |
|---|---|---|
| 1 | Primary task is **gap analysis** (flag missing controls in an org's policies) | Drives everything below. |
| 2 | Chunk at **leaf-level** (`(a)(1)(ii)(A)`) | Each Required/Addressable spec becomes independently scorable. |
| 3 | **Two output streams**: `controls.jsonl` and `reference.jsonl` | Keeps the gap-analysis surface tight; preserves definitions and procedural text for citation/lookup. |
| 4 | **Prepend parent breadcrumb to chunk text** | Improves embedding quality; gap analysis depends on the chunk capturing the standard's purpose. |
| 5 | `severity` field reserved as `null` in v1 | Nice-to-have; populated later via separate scoring pass. |

## Outputs

| File | Purpose |
|---|---|
| `controls.jsonl` | Substantive requirements only — the gap-analysis target |
| `reference.jsonl` | Definitions + procedural + authority sections |
| `index.csv` | Flat audit row per chunk for inspection |
| `build_report.txt` | Counts per subpart / designation / safeguard type, plus validation results |

## Section Routing

Whole sections are classified, then their leaves are routed to one file:

| Pattern | Destination | Examples |
|---|---|---|
| § XXX.103 / § XXX.501 (Definitions) | `reference.jsonl` (`definition`) | § 160.103, § 164.501 |
| § XXX.101 / § XXX.102 (Statutory basis) | `reference.jsonl` (`authority`) | § 160.101, § 164.102 |
| Part 160 Subpart D & E (penalties + ALJ hearings) | `reference.jsonl` (`procedural`) | § 160.404, § 160.534 |
| Everything else | `controls.jsonl` (`requirement`) | § 164.308, § 164.404 |

## Leaf Detection

A node becomes a chunk when:

1. It has no nested children, **or**
2. Its children are an enumeration list whose parent intro plus the list together form one coherent requirement (parent ends in colon, children share a predicate), **or**
3. The whole section has no nested paragraphs (e.g., § 164.106 single sentence).

## Metadata Schema (`controls.jsonl`)

```json
{
  "chunk_id": "164.308-a-1-ii-A",
  "citation": "45 CFR 164.308(a)(1)(ii)(A)",
  "part": "164",
  "subpart": "C",
  "subpart_title": "Security Standards for the Protection of ePHI",
  "section": "164.308",
  "section_title": "Administrative safeguards",
  "paragraph_path": ["a", "1", "ii", "A"],

  "rule_category": "security",
  "safeguard_type": "administrative",
  "designation": "Required",
  "implementation_spec_title": "Risk analysis",

  "parent_standard_id": "164.308-a-1-i",
  "parent_standard_title": "Security management process",
  "parent_standard_text": "Implement policies and procedures to prevent, detect, contain, and correct security violations.",

  "applies_to": ["covered_entity", "business_associate"],
  "normative_verbs": ["must", "conduct"],
  "cross_references": ["164.306"],
  "amendments": ["68 FR 8376, Feb. 20, 2003", "78 FR 5694, Jan. 25, 2013"],

  "severity": null,

  "text": "[Subpart C — Security | § 164.308 Administrative safeguards | Standard: Security management process — Implement policies and procedures to prevent, detect, contain, and correct security violations.]\n\n(a)(1)(ii)(A) Risk analysis (Required). Conduct an accurate and thorough assessment of the potential risks and vulnerabilities to the confidentiality, integrity, and availability of electronic protected health information held by the covered entity or business associate.",
  "text_raw": "Risk analysis (Required). Conduct an accurate and thorough assessment...",
  "char_count": 412,
  "token_count_estimate": 95
}
```

`reference.jsonl` reuses the same shape with `chunk_type` set to `"definition"` | `"procedural"` | `"authority"`. Definition chunks add a `term` field.

## Edge Cases Explicitly Handled

- **Definitions** — § 160.103 and § 164.501 each become *N* chunks (one per defined term), not one giant chunk.
- **Security Matrix Appendix** — emitted as a single reference chunk **plus** a structured `appendix_security_matrix.json` for direct lookup.
- **Reproductive-health 2024 amendment** — chunks under § 164.502(a)(5)(iii) and § 164.535 are tagged `amendment_year: 2024`. The "Link to an amendment published at 91 FR 14404, Mar. 24, 2026" marker on § 160.103 is captured in `pending_amendment_note`.
- **OCR artifacts from `pdftotext -layout`** — explicit normalization for `$(1)` / `$(2)` dollar-prefix, "(enhanced display)" footers, repeating "45 CFR Part X (Apr. 23, 2026)" headers, hyphenated line-breaks, wrapped-paragraph rejoin.
- **Cross-reference extraction** — regex `§\s*(16[04])\.\d{3}(\([a-z]\)(\(\d+\))?(\([ivx]+\))?)?` populates `cross_references`.
- **Stable, idempotent chunk IDs** — derived from `section + paragraph_path`, never random UUIDs. Re-runs produce identical IDs so downstream embeddings stay valid.

## Implementation Plan — `build_chunks.py`

**Dependencies:** Python stdlib only (`re`, `json`, `csv`, `dataclasses`, `pathlib`).

**Pipeline stages** (each a separate function):

1. `normalize_text` — strip pdftotext artifacts.
2. `parse_sections` — split by `§ XXX.YYY`, detect Subpart headers, capture FR amendment citations.
3. `parse_paragraphs` — build `(a)/(1)/(i)/(A)` hierarchy tree.
4. `classify_section` — route to controls vs reference per the table above.
5. `extract_definitions` — special-case § 160.103 / § 164.501.
6. `identify_leaves` — apply the three leaf rules.
7. `detect_designation` / `detect_applies_to` / `detect_safeguard_type` / `extract_cross_refs` — metadata extractors.
8. `build_chunk_id` — deterministic ID from section + path.
9. `assemble_breadcrumb` — produces the prepended header.
10. `emit_chunk` — final dict matching schema.
11. `write_jsonl` / `write_csv` / `write_report`.
12. `validate` — coverage and spot-checks (see below).

## Validation (runs at end of `main()`)

The script fails loudly if any of these don't pass:

1. **Coverage check** — every Required/Addressable item from Appendix A Security Matrix maps to exactly one chunk in `controls.jsonl`.
2. **Definition uniqueness** — every term in § 160.103 / § 164.501 appears exactly once in `reference.jsonl`.
3. **Citation round-trip** — ten known cross-references resolve to existing chunks.
4. **Spot-checks** — six hand-picked chunks (e.g., § 164.308(a)(1)(ii)(A) Risk analysis, § 164.404(b) 60-day breach notification) have correct `designation`, `rule_category`, `applies_to`.

`build_report.txt` includes counts by (part, subpart, designation, rule_category, safeguard_type), top 10 longest/shortest chunks, list of any sections that produced zero chunks, and validation results.

## Refactor of `ingest_hipaa.py`

Existing script covers ingestion plumbing (BGE-M3 + Qdrant hybrid) but **none** of the chunking design above. After `build_chunks.py` lands, refactor `ingest_hipaa.py` to:

- Read `controls.jsonl` + `reference.jsonl` directly (drop the PyMuPDF block parsing).
- Use deterministic `chunk_id` instead of `uuid.uuid4()` so re-runs don't bust embeddings.
- Use Qdrant's `Prefetch` + `FusionQuery` for genuine hybrid search (current `hybrid_search_demo` only searches dense and references undefined `QDRANT_HOST`/`QDRANT_PORT`).
- Replace deprecated `recreate_collection`.

## Out of Scope for v1

- `severity` scoring (placeholder field only)
- Cross-reference graph / link resolution (chunks just record references; navigation is downstream concern)
- Live tracking of pending amendments (e.g., 91 FR 14404 Mar. 24, 2026) beyond a static note field
