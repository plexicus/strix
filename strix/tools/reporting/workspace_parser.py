from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any


# Matches [CRITICAL], (CRITICAL), or bare CRITICAL in headings
_SEVERITY_PATTERN = re.compile(
    r"[\[(]?(?P<sev>CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL|INFO)[\])]?",
    re.IGNORECASE,
)
_SEVERITY_INLINE = re.compile(r"\b(?P<sev>CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL|INFO)\b", re.IGNORECASE)

# Matches all observed agent heading formats:
#   "## 1. "            → numbered list
#   "## V-01: "         → V-prefixed
#   "## V12: "          → V-prefixed no hyphen
#   "### Finding 1: "   → Finding label
#   "## VULNERABILITY 1:"  → VULNERABILITY label
#   "## FINDING-001: "  → FINDING label
_HEADING_PATTERN = re.compile(
    r"^(?:#{2,3})\s+(?:"
    r"\d+\."
    r"|V-?\d+:"
    r"|(?:Finding|FINDING)[\s\-]+\d+[:\s\-]"
    r"|(?:VULNERABILITY|Vulnerability)\s+\d+:"
    r")\s*",
    re.MULTILINE | re.IGNORECASE,
)


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
    """Extract content under a ### Header or **Header:** bold key."""
    for header in headers:
        # Try ### heading first
        pattern = re.compile(
            rf"###\s+{re.escape(header)}\s*\n(.*?)(?=\n###|\Z)", re.DOTALL | re.IGNORECASE
        )
        m = pattern.search(text)
        if m:
            return m.group(1).strip()
        # Try **Header:** bold key (no leading ###)
        pattern2 = re.compile(
            rf"\*\*{re.escape(header)}[:\*]{{1,3}}\*?\*?\s*\n?(.*?)(?=\n\*\*[A-Z]|\n###|\Z)",
            re.DOTALL | re.IGNORECASE,
        )
        m2 = pattern2.search(text)
        if m2:
            return m2.group(1).strip()
    return ""


def _extract_preamble(rest: str) -> str:
    """Extract intro text before the first ### or **Bold:** subsection."""
    m = re.match(r"(.*?)(?=\n###|\n\*\*[A-Za-z]|\Z)", rest, re.DOTALL)
    if not m:
        return ""
    text = m.group(1).strip()
    # Remove endpoint line captured separately
    text = re.sub(r"\*\*(?:Endpoint|Location)[^*]*\*\*[^\n]*\n?", "", text, flags=re.IGNORECASE).strip()
    return text


def _extract_code_block(text: str) -> str:
    m = re.search(r"```[^\n]*\n(.*?)```", text, re.DOTALL)
    if m:
        return m.group(1).strip()
    return text.strip()


def _extract_severity_from_block(first_line: str, rest: str) -> str:
    """Try multiple strategies to find severity in a vulnerability block."""
    # 1. [CRITICAL] or (CRITICAL) in the heading line
    m = re.search(r"[\[(](?P<sev>CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL|INFO)[\])]", first_line, re.IGNORECASE)
    if m:
        return _normalize_severity(m.group("sev"))
    # 2. Bare word at end of heading like "... (CRITICAL)" already stripped, try inline
    m = _SEVERITY_INLINE.search(first_line)
    if m:
        return _normalize_severity(m.group("sev"))
    # 3. **Severity:** value or **Risk:** value in block body
    m = re.search(
        r"\*\*(?:Severity|Risk|Priority)[:\*]+\*?\*?\s*(?P<sev>CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL|INFO)\b",
        rest, re.IGNORECASE,
    )
    if m:
        return _normalize_severity(m.group("sev"))
    # 4. ### Severity section
    sev_section = _extract_section(rest, "Severity", "Risk")
    if sev_section:
        m = _SEVERITY_INLINE.search(sev_section)
        if m:
            return _normalize_severity(m.group("sev"))
    return "Medium"


def parse_workspace_markdown(content: str) -> list[dict[str, Any]]:
    """Parse vulnerability reports written by the strix agent to /workspace/.

    Handles multiple formats produced by different agent runs:
      ## N. [SEVERITY] Title
      ## V-01: TITLE [SEVERITY]
      ### Finding N: Title
      ## VULNERABILITY N: Title (SEVERITY)
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    vulns: list[dict[str, Any]] = []

    splits = _HEADING_PATTERN.split(content)
    headings = _HEADING_PATTERN.findall(content)

    for idx, heading_prefix in enumerate(headings):
        block = splits[idx + 1]
        first_line, _, rest = block.partition("\n")
        first_line = first_line.strip()

        severity = _extract_severity_from_block(first_line, rest)

        # Clean severity markers and label prefix from title
        title = re.sub(r"[\[(](?:CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL|INFO)[\])]", "", first_line, flags=re.IGNORECASE)
        title = re.sub(r"\s*\((?:CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL|INFO)\)\s*$", "", title, flags=re.IGNORECASE)
        title = title.strip(" -[]:()")

        # Endpoint / Location
        endpoint_match = re.search(r"\*\*(?:Endpoint|Location)[:\*]+\*?\*?\s*(.+)", rest, re.IGNORECASE)
        endpoint = endpoint_match.group(1).strip() if endpoint_match else ""

        description = _extract_section(rest, "Description") or _extract_preamble(rest)
        poc_raw = _extract_section(rest, "Proof of Concept", "PoC", "Proof-of-Concept", "Proof", "Evidence")
        poc = _extract_code_block(poc_raw) if poc_raw else ""
        impact = _extract_section(rest, "Impact")
        remediation = _extract_section(rest, "Remediation", "Remediation Steps", "Fix", "Mitigation")

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
