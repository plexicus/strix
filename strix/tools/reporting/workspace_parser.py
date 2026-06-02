from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any


_SEVERITY_PATTERN = re.compile(r"\[(?P<sev>CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL|INFO)\]", re.IGNORECASE)
# Matches both "## 1. " (original) and "## V-01: " / "## V12: " (agent-generated) formats
_HEADING_PATTERN = re.compile(r"^##\s+(?:\d+\.|V-?\d+:)\s+", re.MULTILINE | re.IGNORECASE)


def _normalize_severity(raw: str) -> str:
    mapping = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "informational": "Informational",
        "info": "Informational",
    }
    return mapping.get(raw.lower(), "Medium")


def _extract_section(text: str, *headers: str) -> str:
    for header in headers:
        pattern = re.compile(
            rf"###\s+{re.escape(header)}\s*\n(.*?)(?=\n###|\Z)", re.DOTALL | re.IGNORECASE
        )
        m = pattern.search(text)
        if m:
            return m.group(1).strip()
    return ""


def _extract_preamble(rest: str) -> str:
    """Extract intro text before the first ### subsection (for agent-format reports)."""
    m = re.match(r"(.*?)(?=\n###|\Z)", rest, re.DOTALL)
    if not m:
        return ""
    text = m.group(1).strip()
    # Remove the **Endpoint:** line since it's captured separately
    text = re.sub(r"\*\*Endpoint[^*]*\*\*[^\n]*\n?", "", text).strip()
    return text


def _extract_code_block(text: str) -> str:
    m = re.search(r"```[^\n]*\n(.*?)```", text, re.DOTALL)
    if m:
        return m.group(1).strip()
    return text.strip()


def parse_workspace_markdown(content: str) -> list[dict[str, Any]]:
    """Parse a vulnerability report markdown written by the agent to /workspace/.

    Expected format produced by the agent:
        ## N. [SEVERITY] Title
        **Endpoint:** ...
        ### Description
        ...
        ### Proof of Concept
        ```
        ...
        ```
        ### Impact
        ...
        ### Remediation
        ...
        ---
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    vulns: list[dict[str, Any]] = []

    # Split by top-level vulnerability headings (## N.)
    splits = _HEADING_PATTERN.split(content)
    # The part before the first heading (preamble / title page) is splits[0]; skip it.
    headings = _HEADING_PATTERN.findall(content)

    for idx, heading_prefix in enumerate(headings):
        block = splits[idx + 1]
        # First line of block is the rest of the heading after "## N. "
        first_line, _, rest = block.partition("\n")
        first_line = first_line.strip()

        sev_match = _SEVERITY_PATTERN.search(first_line)
        severity = _normalize_severity(sev_match.group("sev")) if sev_match else "Medium"
        title = _SEVERITY_PATTERN.sub("", first_line).strip(" -[]")

        # Endpoint
        endpoint_match = re.search(r"\*\*Endpoint[:\*]+\*?\*?\s*(.+)", rest)
        endpoint = endpoint_match.group(1).strip() if endpoint_match else ""

        description = _extract_section(rest, "Description") or _extract_preamble(rest)
        poc_raw = _extract_section(rest, "Proof of Concept", "PoC", "Proof-of-Concept")
        poc = _extract_code_block(poc_raw) if poc_raw else ""
        impact = _extract_section(rest, "Impact")
        remediation = _extract_section(rest, "Remediation", "Remediation Steps")

        content_parts = [description]
        if impact:
            content_parts.append(f"Impact: {impact}")
        description_full = "\n\n".join(p for p in content_parts if p)

        vulns.append(
            {
                "title": title,
                "severity": severity,
                "content": description_full,
                "proof_of_concept": poc,
                "mitigation": remediation,
                "endpoint": endpoint,
                "timestamp": now_iso,
                "tags": ["DAST", "AI-Validated"],
            }
        )

    return vulns
