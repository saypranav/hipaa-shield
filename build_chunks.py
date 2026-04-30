#!/usr/bin/env python3
"""
build_chunks.py — HIPAA regulation chunker for gap-analysis applications.

Reads `part160.txt` and `part164.txt` (produced by `pdftotext -layout` on the
two CFR PDFs) and emits leaf-level paragraph chunks with rich metadata for
downstream RAG / gap-analysis use.

Outputs (under ./out/):
    controls.jsonl   - substantive requirements (gap-analysis target)
    reference.jsonl  - definitions + procedural + authority
    index.csv        - flat audit row per chunk
    build_report.txt - counts, validation results, anomalies

See docs/plans/2026-04-25-hipaa-chunking-design.md for the full design.

Stdlib only: re, json, csv, dataclasses, pathlib.
"""
from __future__ import annotations

import csv
import json
import re
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

# --------------------------------------------------------------------------
# CONFIG
# --------------------------------------------------------------------------

ROOT = Path(__file__).resolve().parent
INPUTS = {
    "160": ROOT / "part160.txt",
    "164": ROOT / "part164.txt",
}
OUT_DIR = ROOT / "out"

# Approximate token count: ~4 chars/token works fine for English regulatory prose.
CHARS_PER_TOKEN = 4


# --------------------------------------------------------------------------
# DATA STRUCTURES
# --------------------------------------------------------------------------

@dataclass
class Section:
    part: str                       # "160" or "164"
    subpart: str                    # "A".."E"
    subpart_title: str
    number: str                     # "164.308"
    title: str                      # "Administrative safeguards"
    body: str                       # full body text after title, before next section
    amendments: list[str] = field(default_factory=list)
    pending_amendment_note: Optional[str] = None


@dataclass
class Node:
    label: str                      # "a", "1", "i", "A", "ROOT"
    indent: int                     # column at which the label begins
    text: str                       # paragraph prose
    children: list["Node"] = field(default_factory=list)
    parent: Optional["Node"] = None
    # Filled later:
    is_standard: bool = False       # paragraph intro starting with "Standard:"
    is_implementation_spec: bool = False  # "Implementation specification..."
    standard_title: Optional[str] = None  # text after "Standard:"

    def path(self) -> list[str]:
        """Hierarchical label path from section root, e.g. ['a','1','ii','A']."""
        out, n = [], self
        while n is not None and n.label != "ROOT":
            out.append(n.label)
            n = n.parent
        return list(reversed(out))


# --------------------------------------------------------------------------
# 1. NORMALIZATION
# --------------------------------------------------------------------------

# Page header / footer artefacts from `pdftotext -layout`.
RE_PAGE_FOOTER = re.compile(
    r"^\s*45 CFR\s+\S.*?\(enhanced display\).*?page \d+ of \d+\s*$",
    re.MULTILINE,
)
RE_PAGE_HEADER_DATE = re.compile(
    r"^\s*45 CFR Part 16[04] \(up to date as of \d+/\d+/\d{4}\)\s*$",
    re.MULTILINE,
)
RE_PAGE_HEADER_REF = re.compile(
    r"^\s*45 CFR (?:Part )?16[04][\.\d\(\)a-zA-Z\s“”\"',\-]*$",
    re.MULTILINE,
)
RE_RUNNING_TITLE = re.compile(
    r"^\s*(?:General Administrative Requirements|Security and Privacy)\s*$",
    re.MULTILINE,
)
RE_DOLLAR_NUMBER = re.compile(r"\$\((\d+)\)")
RE_HYPHEN_BREAK = re.compile(r"(\w)-\s*\n\s*(\w)")
# Disclaimer block at top of each PDF page.
RE_DISCLAIMER = re.compile(
    r"^\s*This content is from the eCFR and is authoritative but unofficial\.\s*$",
    re.MULTILINE,
)


def normalize_text(raw: str) -> str:
    """Strip pdftotext -layout artefacts that appear between pages."""
    text = raw

    # 1. Fix hyphenated line-break before splitting / cleaning so we don't
    #    confuse it with a real paragraph break.
    text = RE_HYPHEN_BREAK.sub(r"\1\2", text)

    # 2. Drop page footers, headers, running titles, disclaimers.
    text = RE_PAGE_FOOTER.sub("", text)
    text = RE_PAGE_HEADER_DATE.sub("", text)
    text = RE_RUNNING_TITLE.sub("", text)
    text = RE_DISCLAIMER.sub("", text)
    # The "45 CFR <citation>" header lines — careful not to nuke real
    # in-paragraph mentions. Match only when on their own line.
    text = re.sub(
        r"^\s*45 CFR\s+(?:Part\s+)?16[04][^\n]*$", "", text, flags=re.MULTILINE
    )

    # 3. pdftotext sometimes prefixes deeper-than-(B) numbered items with $.
    text = RE_DOLLAR_NUMBER.sub(r"(\1)", text)

    # 4. Collapse triple-or-more blank lines into double blank lines so that
    #    we keep paragraph separation but lose page-break gaps.
    text = re.sub(r"\n[ \t]*\n[ \t]*\n+", "\n\n", text)

    return text


# --------------------------------------------------------------------------
# 2. SECTION PARSING
# --------------------------------------------------------------------------

# Matches both "Subpart C—Title" and "Subpart B [Reserved]".
RE_SUBPART = re.compile(
    r"^Subpart\s+([A-Z])(?:\s*[—\-]\s*(.+?)|\s+\[Reserved\])\s*$",
    re.MULTILINE,
)
RE_SECTION_START = re.compile(r"^§\s+(\d+\.\d+)\s+(.+?)$", re.MULTILINE)
RE_BODY_MARKER = re.compile(r"^PART 16[04]\s*[—\-]", re.MULTILINE)
RE_FR_BRACKET = re.compile(r"\[((?:\d+\s*FR\s*\d+[^\]]*?))\]", re.DOTALL)
RE_PENDING_AMENDMENT = re.compile(
    r"^Link to an amendment published at\s+(.+?)\.\s*$", re.MULTILINE
)


def parse_sections(text: str, part: str) -> list[Section]:
    """Find PART body marker, then split into Section objects."""
    body_match = RE_BODY_MARKER.search(text)
    if not body_match:
        raise RuntimeError(f"Cannot locate 'PART 16x—' body marker in part {part}")
    body = text[body_match.end():]

    # Walk subparts and sections together so we can attach subpart context.
    subpart_marks = list(RE_SUBPART.finditer(body))
    section_marks = list(RE_SECTION_START.finditer(body))

    # For each section, find the preceding subpart.
    def subpart_at(pos: int) -> tuple[str, str]:
        sp_letter, sp_title = "", ""
        for m in subpart_marks:
            if m.start() > pos:
                break
            sp_letter = m.group(1)
            sp_title = (m.group(2) or "[Reserved]").strip()
        return sp_letter, sp_title

    sections: list[Section] = []
    for i, m in enumerate(section_marks):
        sp_letter, sp_title = subpart_at(m.start())
        section_no = m.group(1)
        # Title may wrap onto next line(s) until first period at line end.
        title_start = m.start(2)
        end_of_section = (
            section_marks[i + 1].start() if i + 1 < len(section_marks) else len(body)
        )
        # Title region: from the captured title text, possibly extending across
        # one or two more lines until a "." at end of line.
        title_chunk = body[title_start:end_of_section]
        title_lines = []
        body_offset = title_start
        for line in title_chunk.splitlines(keepends=True):
            stripped = line.rstrip()
            title_lines.append(stripped)
            body_offset += len(line)
            if stripped.endswith(".") or stripped.endswith(":"):
                break
        title = " ".join(s.strip() for s in title_lines).rstrip(".").rstrip()

        section_body = body[body_offset:end_of_section]

        # Pull amendment FR citations from bracketed trailers in body.
        amendments: list[str] = []
        for fr in RE_FR_BRACKET.finditer(section_body):
            inner = re.sub(r"\s+", " ", fr.group(1)).strip().rstrip(",;")
            # Each bracketed block can contain multiple semicolon-separated FRs.
            for part_cit in re.split(r";\s*", inner):
                part_cit = part_cit.strip().lstrip(",")
                if re.match(r"\d+\s*FR\s*\d+", part_cit):
                    amendments.append(part_cit)

        pending = None
        pm = RE_PENDING_AMENDMENT.search(section_body)
        if pm:
            pending = pm.group(1).strip()

        sections.append(
            Section(
                part=part,
                subpart=sp_letter,
                subpart_title=sp_title,
                number=section_no,
                title=title,
                body=section_body,
                amendments=sorted(set(amendments), key=amendments.index),
                pending_amendment_note=pending,
            )
        )
    return sections


# --------------------------------------------------------------------------
# 3. PARAGRAPH HIERARCHY
# --------------------------------------------------------------------------

# Single-letter lowercase: (a). Single digit or 2-digit: (1)-(99).
# Lowercase roman: (i), (ii), (iii)...(viii). Uppercase letter: (A).
RE_LABEL_LINE = re.compile(
    r"""
    ^(?P<indent>[ ]*)            # leading spaces
    \((?P<label>
        [a-z]                    # (a)
        |[0-9]{1,2}              # (1)..(99)
        |[ivx]+                  # (i), (ii)
        |[A-Z]                   # (A)
    )\)
    (?:\s+(?P<rest>.+?))?\s*$    # optional rest of line
    """,
    re.VERBOSE,
)
LABEL_KIND_DEPTH_HINT = {
    "lower_letter": 1,
    "digit": 2,
    "lower_roman": 3,
    "upper_letter": 4,
}


def label_kind(label: str) -> str:
    if re.fullmatch(r"[a-z]", label):
        # Could be a letter or a roman numeral 'i'/'v'/'x'.
        if label in {"i", "v", "x"}:
            return "ambiguous"
        return "lower_letter"
    if re.fullmatch(r"[ivx]+", label):
        return "lower_roman"
    if re.fullmatch(r"[0-9]+", label):
        return "digit"
    if re.fullmatch(r"[A-Z]", label):
        return "upper_letter"
    return "unknown"


def parse_paragraphs(section: Section) -> Node:
    """Build hierarchy tree from section body. Uses indent + label-kind."""
    root = Node(label="ROOT", indent=-1, text="")
    stack: list[Node] = [root]

    # First pass: glue continuation lines into paragraph blocks keyed by their
    # label-line indent.
    blocks: list[tuple[int, str, str]] = []  # (indent, label, text)
    leader_text: list[str] = []
    for raw_line in section.body.splitlines():
        line = raw_line.rstrip()
        if not line:
            # blank line — ends current block
            if leader_text:
                blocks[-1] = (
                    blocks[-1][0],
                    blocks[-1][1],
                    " ".join([blocks[-1][2]] + leader_text).strip(),
                )
                leader_text = []
            continue

        m = RE_LABEL_LINE.match(line)
        if m:
            # flush continuation
            if leader_text and blocks:
                blocks[-1] = (
                    blocks[-1][0],
                    blocks[-1][1],
                    " ".join([blocks[-1][2]] + leader_text).strip(),
                )
                leader_text = []
            blocks.append((len(m.group("indent")), m.group("label"), m.group("rest") or ""))
        else:
            # continuation of the current block (or pre-paragraph intro of section)
            stripped = line.lstrip()
            if stripped.startswith("[") and stripped.endswith("]"):
                # FR amendment trailer — ignore for chunk text.
                continue
            if blocks:
                leader_text.append(stripped)
            else:
                # section-level intro before any (a)/(1) — keep on root.
                root.text = (root.text + " " + stripped).strip()
    if leader_text and blocks:
        blocks[-1] = (
            blocks[-1][0],
            blocks[-1][1],
            " ".join([blocks[-1][2]] + leader_text).strip(),
        )

    # Second pass: stack-based tree construction using indent + label-kind.
    for indent, label, text in blocks:
        # Pop stack until we find a parent whose indent < current.
        while stack and stack[-1].indent >= indent:
            stack.pop()
        if not stack:
            stack = [root]
        parent = stack[-1]
        node = Node(label=label, indent=indent, text=text, parent=parent)
        # Mark "Standard:" / "Implementation specification" intros.
        if re.match(r"\s*Standard:\s*", text):
            node.is_standard = True
            mt = re.match(r"\s*Standard:\s*([^.\n]+)\.", text)
            if mt:
                node.standard_title = mt.group(1).strip()
        elif re.match(r"\s*Implementation specifications?\s*[:\-]", text, re.I):
            node.is_implementation_spec = True
        parent.children.append(node)
        stack.append(node)

    return root


# --------------------------------------------------------------------------
# 4. CLASSIFICATION + DEFINITIONS
# --------------------------------------------------------------------------

def classify_section(section: Section) -> str:
    """Return one of: requirement | definition | procedural | authority."""
    n = section.number
    # Definitions
    if n in {"160.103", "160.202", "160.401", "160.502", "164.103", "164.304", "164.402", "164.501"}:
        return "definition"
    # Statutory basis / authority
    if n in {"160.101", "160.201", "164.102"}:
        return "authority"
    # Part 160 Subpart D (penalties) and Subpart E (hearing procedures)
    if section.part == "160" and section.subpart in {"D", "E"}:
        return "procedural"
    # Subpart C of Part 160 (compliance & investigations) is somewhere in
    # between; route as procedural since these govern HHS process.
    if section.part == "160" and section.subpart == "C":
        return "procedural"
    # Section 164.318 (compliance dates) and 164.534 (compliance dates) and
    # 164.532 (transitions): mostly historical — procedural.
    if n in {"164.318", "164.532", "164.534", "164.535"}:
        return "procedural"
    return "requirement"


# Pattern for a definition title line in § 160.103 / § 164.501.
# Title starts at small indent (~3-6 spaces), is followed by "means",
# "stands for", "is defined", or ends with ":" before children.
RE_DEFINITION_TITLE = re.compile(
    r"^(?P<indent>[ ]{2,8})(?P<title>[A-Z][A-Za-z0-9 \-/(),'“”\"]+?)"
    r"(?P<connector>\s+(?:means|stands for|is defined|refers to)\b|:)",
)


def extract_definitions(section: Section) -> list[dict]:
    """Split a definitions section into one chunk per term."""
    lines = section.body.splitlines()
    # We slide through the lines, opening a new definition whenever a
    # title-line indent is encountered.
    defs: list[dict] = []
    current: Optional[dict] = None
    title_indent: Optional[int] = None
    seen_intro = False

    intro_re = re.compile(r"following definitions apply", re.I)
    for line in lines:
        if not line.strip():
            if current:
                current["text"] += "\n"
            continue
        if not seen_intro and intro_re.search(line):
            seen_intro = True
            continue
        # Skip the "Link to an amendment" line — captured at section level.
        if line.lstrip().lower().startswith("link to an amendment"):
            continue
        m = RE_DEFINITION_TITLE.match(line)
        line_indent = len(line) - len(line.lstrip())
        starts_definition = (
            m is not None
            and (title_indent is None or line_indent <= title_indent + 1)
            # Reject lines that are paragraph labels.
            and not RE_LABEL_LINE.match(line)
        )
        if starts_definition:
            if current:
                defs.append(current)
            title = m.group("title").strip().rstrip(":").rstrip()
            current = {"term": title, "text": line.strip()}
            title_indent = line_indent
        else:
            if current is not None:
                current["text"] += " " + line.strip()
    if current:
        defs.append(current)

    # Cleanup: collapse repeated whitespace.
    for d in defs:
        d["text"] = re.sub(r"\s+", " ", d["text"]).strip()
    return defs


# --------------------------------------------------------------------------
# 5. LEAF DETECTION + METADATA EXTRACTORS
# --------------------------------------------------------------------------

def identify_leaves(node: Node) -> list[Node]:
    """Walk tree, return leaf nodes per design rules."""
    leaves: list[Node] = []

    def visit(n: Node):
        if not n.children:
            if n.label != "ROOT":
                leaves.append(n)
            return
        # Rule 2: parent intro ends with colon AND children are all very short
        # enumeration items. Treat parent + children as a single leaf chunk.
        children_short = all(len(c.text) < 120 and not c.children for c in n.children)
        intro_colon = n.text.rstrip().endswith(":")
        if intro_colon and children_short and len(n.children) >= 3 and n.label != "ROOT":
            # Compose a synthetic leaf merging parent + children list.
            joined = n.text + " " + "; ".join(
                f"({c.label}) {c.text}" for c in n.children
            )
            merged = Node(
                label=n.label,
                indent=n.indent,
                text=joined,
                parent=n.parent,
            )
            merged.is_standard = n.is_standard
            merged.is_implementation_spec = n.is_implementation_spec
            merged.standard_title = n.standard_title
            leaves.append(merged)
            return
        for c in n.children:
            visit(c)

    visit(node)
    return leaves


RE_DESIGNATION = re.compile(r"\((Required|Addressable)\)", re.IGNORECASE)
RE_IMPL_SPEC_TITLE = re.compile(r"^([A-Z][A-Za-z0-9 \-]+?)\s*\((?:Required|Addressable)\)")
RE_CROSS_REF = re.compile(r"§+\s*(16[04])\.(\d{3})")
RE_NORMATIVE = re.compile(
    r"\b(must|shall|may not|must not|shall not|may|will|is required to|is prohibited from)\b",
    re.IGNORECASE,
)


def detect_designation(text: str) -> Optional[str]:
    m = RE_DESIGNATION.search(text)
    if not m:
        return None
    return m.group(1).capitalize()


def detect_impl_spec_title(text: str) -> Optional[str]:
    m = RE_IMPL_SPEC_TITLE.match(text)
    if m:
        return m.group(1).strip()
    return None


def detect_applies_to(text: str) -> list[str]:
    out = []
    t = text.lower()
    if "covered entity" in t or "covered health care provider" in t or "health plan" in t:
        out.append("covered_entity")
    if "business associate" in t:
        out.append("business_associate")
    if "group health plan" in t and "group_health_plan" not in out:
        out.append("group_health_plan")
    if "plan sponsor" in t and "plan_sponsor" not in out:
        out.append("plan_sponsor")
    return out or ["covered_entity"]


def detect_safeguard_type(section: Section) -> Optional[str]:
    if section.part != "164" or section.subpart != "C":
        return None
    n = section.number
    if n == "164.308":
        return "administrative"
    if n == "164.310":
        return "physical"
    if n == "164.312":
        return "technical"
    if n in {"164.314", "164.316"}:
        return "organizational"
    return None


def detect_rule_category(section: Section) -> str:
    if section.part == "160":
        return "general"
    if section.subpart == "C":
        return "security"
    if section.subpart == "D":
        return "breach_notification"
    if section.subpart == "E":
        return "privacy"
    return "general"


def extract_cross_refs(text: str, self_section: str) -> list[str]:
    refs = []
    for m in RE_CROSS_REF.finditer(text):
        ref = f"{m.group(1)}.{m.group(2)}"
        if ref != self_section and ref not in refs:
            refs.append(ref)
    return refs


def detect_normative(text: str) -> list[str]:
    return sorted({m.group(1).lower() for m in RE_NORMATIVE.finditer(text)})


# --------------------------------------------------------------------------
# 6. CHUNK EMISSION
# --------------------------------------------------------------------------

def chunk_id_for(section: str, path: list[str], extra: Optional[str] = None) -> str:
    base = f"{section}-{'-'.join(path)}" if path else section
    if extra:
        base = f"{base}-{extra}"
    return base


def citation_for(section: str, path: list[str]) -> str:
    suffix = "".join(f"({p})" for p in path)
    return f"45 CFR {section}{suffix}"


def find_parent_standard(node: Node) -> Optional[Node]:
    """Walk up; at each ancestor look among its children (siblings of the
    branch we came from) for a 'Standard:' node. The standard for an
    implementation-spec leaf typically sits at a sibling-of-ancestor position
    (e.g., leaf (a)(1)(ii)(A) — standard at (a)(1)(i))."""
    came_from = node
    ancestor = node.parent
    while ancestor is not None and ancestor.label != "ROOT":
        for child in ancestor.children:
            if child is came_from:
                continue
            if child.is_standard or child.standard_title:
                return child
        if ancestor.is_standard or ancestor.standard_title:
            return ancestor
        came_from = ancestor
        ancestor = ancestor.parent
    return None


def assemble_breadcrumb(section: Section, leaf: Node, parent_standard: Optional[Node]) -> str:
    parts = [f"Subpart {section.subpart} — {section.subpart_title}".strip()]
    parts.append(f"§ {section.number} {section.title}".strip())
    if parent_standard and parent_standard.standard_title:
        intro = parent_standard.text.split("Standard:", 1)[-1].strip()
        intro = re.sub(r"^[^.]*\.\s*", "", intro, count=1).strip()
        if intro:
            parts.append(
                f"Standard: {parent_standard.standard_title} — {intro}".rstrip()
            )
        else:
            parts.append(f"Standard: {parent_standard.standard_title}")
    return "[" + " | ".join(parts) + "]"


def emit_requirement_chunk(section: Section, leaf: Node) -> dict:
    path = leaf.path()
    parent_std = find_parent_standard(leaf)
    breadcrumb = assemble_breadcrumb(section, leaf, parent_std)
    leaf_text_marker = "(" + ")(".join(path) + ")"
    raw_text = leaf.text.strip()
    text = f"{breadcrumb}\n\n{leaf_text_marker} {raw_text}"

    designation = detect_designation(raw_text)
    impl_title = detect_impl_spec_title(raw_text) if designation else None
    applies = detect_applies_to(raw_text + " " + (parent_std.text if parent_std else ""))
    safeguard = detect_safeguard_type(section)
    category = detect_rule_category(section)
    crossrefs = extract_cross_refs(raw_text, section.number)
    norms = detect_normative(raw_text)

    cid = chunk_id_for(section.number, path)
    chunk = {
        "chunk_id": cid,
        "chunk_type": "requirement",
        "citation": citation_for(section.number, path),
        "part": section.part,
        "subpart": section.subpart,
        "subpart_title": section.subpart_title,
        "section": section.number,
        "section_title": section.title,
        "paragraph_path": path,
        "rule_category": category,
        "safeguard_type": safeguard,
        "designation": designation,
        "implementation_spec_title": impl_title,
        "parent_standard_id": (
            chunk_id_for(section.number, parent_std.path()) if parent_std else None
        ),
        "parent_standard_title": parent_std.standard_title if parent_std else None,
        "parent_standard_text": parent_std.text.strip() if parent_std else None,
        "applies_to": applies,
        "normative_verbs": norms,
        "cross_references": crossrefs,
        "amendments": section.amendments,
        "pending_amendment_note": section.pending_amendment_note,
        "amendment_year": (
            2024 if cid.startswith("164.502-a-5-iii") or section.number == "164.535" else None
        ),
        "severity": None,
        "text": text,
        "text_raw": raw_text,
        "char_count": len(text),
        "token_count_estimate": len(text) // CHARS_PER_TOKEN,
    }
    return chunk


def emit_section_level_chunk(section: Section, ctype: str) -> dict:
    """For sections with no nested paragraphs (or procedural sections we want
    captured wholesale)."""
    text = re.sub(r"\s+", " ", section.body).strip()
    breadcrumb = (
        f"[Subpart {section.subpart} — {section.subpart_title} | "
        f"§ {section.number} {section.title}]"
    )
    full_text = f"{breadcrumb}\n\n{text}"
    cid = chunk_id_for(section.number, [])
    return {
        "chunk_id": cid,
        "chunk_type": ctype,
        "citation": f"45 CFR {section.number}",
        "part": section.part,
        "subpart": section.subpart,
        "subpart_title": section.subpart_title,
        "section": section.number,
        "section_title": section.title,
        "paragraph_path": [],
        "rule_category": detect_rule_category(section),
        "safeguard_type": detect_safeguard_type(section),
        "designation": None,
        "implementation_spec_title": None,
        "parent_standard_id": None,
        "parent_standard_title": None,
        "parent_standard_text": None,
        "applies_to": detect_applies_to(text),
        "normative_verbs": detect_normative(text),
        "cross_references": extract_cross_refs(text, section.number),
        "amendments": section.amendments,
        "pending_amendment_note": section.pending_amendment_note,
        "amendment_year": None,
        "severity": None,
        "text": full_text,
        "text_raw": text,
        "char_count": len(full_text),
        "token_count_estimate": len(full_text) // CHARS_PER_TOKEN,
    }


def emit_definition_chunks(section: Section) -> list[dict]:
    out = []
    for d in extract_definitions(section):
        cid = chunk_id_for(
            section.number, [], extra=re.sub(r"[^a-z0-9]+", "-", d["term"].lower()).strip("-")
        )
        breadcrumb = (
            f"[Subpart {section.subpart} — {section.subpart_title} | "
            f"§ {section.number} {section.title} | Defined term: {d['term']}]"
        )
        full_text = f"{breadcrumb}\n\n{d['text']}"
        out.append(
            {
                "chunk_id": cid,
                "chunk_type": "definition",
                "term": d["term"],
                "citation": f"45 CFR {section.number}",
                "part": section.part,
                "subpart": section.subpart,
                "subpart_title": section.subpart_title,
                "section": section.number,
                "section_title": section.title,
                "paragraph_path": [],
                "rule_category": detect_rule_category(section),
                "safeguard_type": None,
                "designation": None,
                "implementation_spec_title": None,
                "parent_standard_id": None,
                "parent_standard_title": None,
                "parent_standard_text": None,
                "applies_to": [],
                "normative_verbs": [],
                "cross_references": extract_cross_refs(d["text"], section.number),
                "amendments": section.amendments,
                "pending_amendment_note": section.pending_amendment_note,
                "amendment_year": None,
                "severity": None,
                "text": full_text,
                "text_raw": d["text"],
                "char_count": len(full_text),
                "token_count_estimate": len(full_text) // CHARS_PER_TOKEN,
            }
        )
    return out


# --------------------------------------------------------------------------
# 7. WRITERS
# --------------------------------------------------------------------------

def write_jsonl(rows: list[dict], path: Path):
    with path.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


INDEX_FIELDS = [
    "chunk_id",
    "chunk_type",
    "citation",
    "part",
    "subpart",
    "section",
    "rule_category",
    "safeguard_type",
    "designation",
    "implementation_spec_title",
    "applies_to",
    "char_count",
    "token_count_estimate",
]


def write_index_csv(rows: list[dict], path: Path):
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(INDEX_FIELDS)
        for r in rows:
            w.writerow(
                [
                    r.get(k) if not isinstance(r.get(k), list) else "|".join(map(str, r.get(k)))
                    for k in INDEX_FIELDS
                ]
            )


# --------------------------------------------------------------------------
# 8. VALIDATION
# --------------------------------------------------------------------------

# A subset of items from Appendix A Security Matrix that must each map to a
# leaf chunk. Format: (section, paragraph_path_tuple, expected_designation).
SECURITY_MATRIX_SAMPLES = [
    ("164.308", ("a", "1", "ii", "A"), "Required"),     # Risk analysis
    ("164.308", ("a", "1", "ii", "B"), "Required"),     # Risk management
    ("164.308", ("a", "1", "ii", "C"), "Required"),     # Sanction policy
    ("164.308", ("a", "1", "ii", "D"), "Required"),     # Information system activity review
    ("164.308", ("a", "3", "ii", "A"), "Addressable"),  # Authorization and/or supervision
    ("164.308", ("a", "5", "ii", "D"), "Addressable"),  # Password management
    ("164.308", ("a", "7", "ii", "A"), "Required"),     # Data backup plan
    ("164.310", ("d", "2", "i"), "Required"),           # Disposal
    ("164.312", ("a", "2", "i"), "Required"),           # Unique user identification
    ("164.312", ("e", "2", "ii"), "Addressable"),       # Encryption (transmission)
]


SPOT_CHECKS = [
    {
        "chunk_id": "164.308-a-1-ii-A",
        "designation": "Required",
        "rule_category": "security",
        "safeguard_type": "administrative",
    },
    {
        "chunk_id": "164.404-b",
        "rule_category": "breach_notification",
    },
    {
        "chunk_id": "164.502-a-5-iii-A-1",
        "rule_category": "privacy",
    },
    {
        "chunk_id": "164.312-a-2-iv",
        "designation": "Addressable",
        "rule_category": "security",
        "safeguard_type": "technical",
    },
    {
        "chunk_id": "164.310-d-2-i",
        "designation": "Required",
        "rule_category": "security",
        "safeguard_type": "physical",
    },
    {
        "chunk_id": "164.314-a-2-i-A",
        "rule_category": "security",
    },
]


KNOWN_DEFINITIONS = [
    ("160.103", "Business associate"),
    ("160.103", "Covered entity"),
    ("160.103", "Protected health information"),
    ("160.103", "Reproductive health care"),
    ("164.501", "Marketing"),
    ("164.501", "Treatment"),
    ("164.402", "Breach"),
    ("164.304", "Encryption"),
]


def validate(controls: list[dict], reference: list[dict]) -> list[str]:
    issues = []
    by_id_controls = {c["chunk_id"]: c for c in controls}
    by_id_reference = {c["chunk_id"]: c for c in reference}

    # 1. Coverage check vs Security Matrix samples.
    for section, path, expected_des in SECURITY_MATRIX_SAMPLES:
        cid = chunk_id_for(section, list(path))
        if cid not in by_id_controls:
            issues.append(f"COVERAGE: missing chunk for {cid}")
            continue
        actual = by_id_controls[cid].get("designation")
        if actual != expected_des:
            issues.append(
                f"COVERAGE: {cid} designation = {actual!r}, expected {expected_des!r}"
            )

    # 2. Spot checks.
    for sc in SPOT_CHECKS:
        cid = sc["chunk_id"]
        if cid not in by_id_controls:
            issues.append(f"SPOTCHECK: missing chunk {cid}")
            continue
        c = by_id_controls[cid]
        for k, v in sc.items():
            if k == "chunk_id":
                continue
            if c.get(k) != v:
                issues.append(f"SPOTCHECK: {cid} field {k} = {c.get(k)!r}, expected {v!r}")

    # 3. Definition uniqueness / coverage.
    def_terms_by_section: dict[tuple[str, str], int] = {}
    for r in reference:
        if r["chunk_type"] != "definition":
            continue
        key = (r["section"], r["term"].lower())
        def_terms_by_section[key] = def_terms_by_section.get(key, 0) + 1
    for section, term in KNOWN_DEFINITIONS:
        key = (section, term.lower())
        if key not in def_terms_by_section:
            issues.append(f"DEFINITION: missing '{term}' from § {section}")
        elif def_terms_by_section[key] > 1:
            issues.append(
                f"DEFINITION: '{term}' appears {def_terms_by_section[key]}x in § {section}"
            )

    # 4. Citation round-trip — sample of cross-refs.
    sampled = 0
    for c in controls[:200]:
        for ref in c.get("cross_references", [])[:2]:
            if ref not in {x["section"] for x in controls + reference}:
                # Fine if it's a Part 162 reference (out of scope).
                if ref.startswith("162."):
                    continue
                issues.append(
                    f"CROSSREF: {c['chunk_id']} references § {ref}, not found in any chunk"
                )
                sampled += 1
                if sampled > 5:
                    break

    return issues


# --------------------------------------------------------------------------
# 9. REPORT
# --------------------------------------------------------------------------

def write_report(controls: list[dict], reference: list[dict], issues: list[str], path: Path):
    def hist(rows, key):
        out = {}
        for r in rows:
            v = r.get(key)
            v = tuple(v) if isinstance(v, list) else v
            out[v] = out.get(v, 0) + 1
        return out

    lines = []
    lines.append(f"controls.jsonl chunks:    {len(controls)}")
    lines.append(f"reference.jsonl chunks:   {len(reference)}")
    lines.append("")
    lines.append("=== Controls by (part, subpart) ===")
    for k, v in sorted(hist(controls, "subpart").items()):
        lines.append(f"  Subpart {k}: {v}")
    lines.append("")
    lines.append("=== Controls by rule_category ===")
    for k, v in sorted(hist(controls, "rule_category").items(), key=lambda x: -x[1]):
        lines.append(f"  {k}: {v}")
    lines.append("")
    lines.append("=== Controls by designation ===")
    for k, v in sorted(hist(controls, "designation").items(), key=lambda x: -x[1]):
        lines.append(f"  {k}: {v}")
    lines.append("")
    lines.append("=== Controls by safeguard_type ===")
    for k, v in sorted(hist(controls, "safeguard_type").items(), key=lambda x: -x[1]):
        lines.append(f"  {k}: {v}")
    lines.append("")
    lines.append("=== Reference by chunk_type ===")
    for k, v in sorted(hist(reference, "chunk_type").items(), key=lambda x: -x[1]):
        lines.append(f"  {k}: {v}")
    lines.append("")
    longest = sorted(controls, key=lambda r: -r["char_count"])[:10]
    shortest = sorted(controls, key=lambda r: r["char_count"])[:10]
    lines.append("=== Top 10 longest controls ===")
    for r in longest:
        lines.append(f"  {r['char_count']:>5}  {r['chunk_id']}")
    lines.append("")
    lines.append("=== Top 10 shortest controls ===")
    for r in shortest:
        lines.append(f"  {r['char_count']:>5}  {r['chunk_id']}")
    lines.append("")
    lines.append("=== Validation ===")
    if issues:
        for s in issues:
            lines.append(f"  [FAIL] {s}")
    else:
        lines.append("  All checks passed.")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# --------------------------------------------------------------------------
# MAIN
# --------------------------------------------------------------------------

def main() -> int:
    OUT_DIR.mkdir(exist_ok=True)
    all_sections: list[Section] = []
    for part, ipath in INPUTS.items():
        if not ipath.exists():
            print(f"ERROR: input not found: {ipath}", file=sys.stderr)
            return 1
        raw = ipath.read_text(encoding="utf-8")
        text = normalize_text(raw)
        sections = parse_sections(text, part)
        all_sections.extend(sections)
        print(f"parsed part {part}: {len(sections)} sections")

    controls: list[dict] = []
    reference: list[dict] = []

    for section in all_sections:
        ctype = classify_section(section)
        if ctype == "definition":
            reference.extend(emit_definition_chunks(section))
            continue
        if ctype in {"authority", "procedural"}:
            reference.append(emit_section_level_chunk(section, ctype))
            continue
        # requirement: build tree, identify leaves, emit per leaf
        root = parse_paragraphs(section)
        leaves = identify_leaves(root)
        if not leaves:
            controls.append(emit_section_level_chunk(section, "requirement"))
            continue
        for leaf in leaves:
            controls.append(emit_requirement_chunk(section, leaf))

    # De-dup: a few synthesized merged-leaf chunks may collide with their
    # originals. Last-write-wins is fine since merged chunks come second in
    # tree order.
    seen, deduped = {}, []
    for c in controls:
        seen[c["chunk_id"]] = c
    deduped = list(seen.values())
    controls = deduped

    write_jsonl(controls, OUT_DIR / "controls.jsonl")
    write_jsonl(reference, OUT_DIR / "reference.jsonl")
    write_index_csv(controls + reference, OUT_DIR / "index.csv")

    issues = validate(controls, reference)
    write_report(controls, reference, issues, OUT_DIR / "build_report.txt")

    print(f"controls: {len(controls)}  reference: {len(reference)}")
    if issues:
        print(f"VALIDATION: {len(issues)} issue(s) — see out/build_report.txt")
        for s in issues[:10]:
            print(f"  - {s}")
        return 2
    print("All validation checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
