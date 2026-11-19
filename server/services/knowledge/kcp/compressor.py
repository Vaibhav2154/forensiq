"""Auditable, meaning-preserving text compression for KCP."""

from __future__ import annotations

import html
import re

from services.knowledge.models import CompressionAudit, ParsedKnowledgeItem


_HTML_TAG_RE = re.compile(r"<[^>]+>")
_MARKDOWN_LINK_RE = re.compile(r"\[([^\]]+)\]\((https?://[^)\s]+)\)")
_CITATION_RE = re.compile(r"\(Citation:[^)]+\)")
_CODE_FENCE_RE = re.compile(r"<code>(.*?)</code>", re.IGNORECASE | re.DOTALL)
_MULTI_SPACE_RE = re.compile(r"[ \t]+")
_MULTI_NEWLINE_RE = re.compile(r"\n{3,}")
_SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+(?=[A-Z0-9])")


def compress_text(text: str) -> tuple[str, dict[str, int]]:
    """Strip noisy markup and citations without dropping technical meaning."""
    if not text:
        return "", {"stripped_citations": 0, "stripped_html_tags": 0}

    cleaned = html.unescape(text)

    def _replace_code(match: re.Match[str]) -> str:
        return f"`{match.group(1).strip()}`"

    cleaned = _CODE_FENCE_RE.sub(_replace_code, cleaned)

    html_matches = _HTML_TAG_RE.findall(cleaned)
    stripped_html_tags = len(html_matches)
    if stripped_html_tags:
        cleaned = _HTML_TAG_RE.sub(" ", cleaned)

    cleaned = _MARKDOWN_LINK_RE.sub(r"\1", cleaned)

    citation_matches = _CITATION_RE.findall(cleaned)
    stripped_citations = len(citation_matches)
    if stripped_citations:
        cleaned = _CITATION_RE.sub("", cleaned)

    lines = [_MULTI_SPACE_RE.sub(" ", line).strip() for line in cleaned.splitlines()]
    cleaned = "\n".join(line for line in lines if line)
    cleaned = _MULTI_NEWLINE_RE.sub("\n\n", cleaned).strip()

    return cleaned, {
        "stripped_citations": stripped_citations,
        "stripped_html_tags": stripped_html_tags,
    }


def extractive_summary(text: str, max_chars: int = 280) -> str:
    """Create a deterministic 1-2 sentence extractive summary bounded by max_chars."""
    clean = " ".join((text or "").split())
    if not clean:
        return ""
    if len(clean) <= max_chars:
        return clean

    sentences = _SENTENCE_SPLIT_RE.split(clean)
    chosen: list[str] = []
    total = 0
    for sentence in sentences:
        candidate_len = total + len(sentence) + (1 if chosen else 0)
        if candidate_len <= max_chars:
            chosen.append(sentence)
            total = candidate_len
        elif not chosen:
            cut = sentence[: max_chars - 3].rsplit(" ", 1)[0].rstrip(",;:")
            return f"{cut}..."
        else:
            break

    return " ".join(chosen) if chosen else clean[: max_chars - 3].rstrip() + "..."


def compress_item(item: ParsedKnowledgeItem) -> tuple[ParsedKnowledgeItem, CompressionAudit]:
    """Compress textual fields of a ParsedKnowledgeItem and record audit metrics."""
    raw_desc = item.description or ""
    raw_detection = str(item.fields.get("detection") or "")
    raw_chars = len(raw_desc) + len(raw_detection)

    compressed_desc, desc_stats = compress_text(raw_desc)
    compressed_det, det_stats = compress_text(raw_detection)

    fields = dict(item.fields)
    if raw_detection:
        fields["detection"] = compressed_det
    summary = extractive_summary(compressed_desc)
    if summary:
        fields["summary"] = summary

    compressed_chars = len(compressed_desc) + len(compressed_det)
    ratio = round(compressed_chars / raw_chars, 4) if raw_chars > 0 else 1.0

    audit = CompressionAudit(
        raw_chars=raw_chars,
        compressed_chars=compressed_chars,
        compression_ratio=ratio,
        stripped_citations=desc_stats["stripped_citations"] + det_stats["stripped_citations"],
        stripped_html_tags=desc_stats["stripped_html_tags"] + det_stats["stripped_html_tags"],
        omitted_fields=sorted(set(item.omitted_fields)),
    )

    updated = item.model_copy(update={"description": compressed_desc, "fields": fields})
    return updated, audit

