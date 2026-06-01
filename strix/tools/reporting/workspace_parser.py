"""Parse /workspace/vulnerability_report.md into structured vulnerability dicts."""

import re


_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "INFO": "info",
    "INFORMATIONAL": "info",
}


def parse_workspace_vulnerability_report(content: str) -> list[dict]:
    """
    Parse /workspace/vulnerability_report.md format into list of vulnerability dicts.

    Expected format from agent:
    ## N. [SEVERITY] Title
    **Endpoint:** ... (optional)
    ### Description
    ...
    ### Proof of Concept / ### Impact / ### Remediation
    ...

    Returns a list of dicts with keys:
        title, severity, description, poc_description, poc_script_code,
        impact, remediation_steps, endpoint, target
    Skips entries where title or severity is missing.
    """
    findings: list[dict] = []

    # Split on top-level vulnerability headings: ## N. [SEVERITY] Title
    # The heading pattern: ## followed by optional number+dot+space, then [SEVERITY], then title
    entry_pattern = re.compile(
        r"^##\s+(?:\d+\.\s+)?\[([A-Z]+)\]\s+(.+)$",
        re.MULTILINE,
    )

    matches = list(entry_pattern.finditer(content))
    if not matches:
        return findings

    for i, match in enumerate(matches):
        raw_severity = match.group(1).strip().upper()
        raw_title = match.group(2).strip()

        severity = _SEVERITY_MAP.get(raw_severity)
        if not severity:
            # Unknown severity token — try to keep going but skip
            continue

        title = raw_title
        if not title:
            continue

        # Extract the block for this entry (up to next ## entry or end of content)
        block_start = match.end()
        block_end = matches[i + 1].start() if i + 1 < len(matches) else len(content)
        block = content[block_start:block_end]

        finding: dict = {
            "title": title,
            "severity": severity,
            "description": "",
            "poc_description": "",
            "poc_script_code": "",
            "impact": "",
            "remediation_steps": "",
            "endpoint": "",
            "target": "",
        }

        # Extract **Endpoint:** line (may appear before first ### section)
        endpoint_match = re.search(r"\*\*Endpoint:\*\*\s*(.+)", block)
        if endpoint_match:
            finding["endpoint"] = endpoint_match.group(1).strip()

        # Split block into ### subsections
        section_pattern = re.compile(r"^###\s+(.+)$", re.MULTILINE)
        section_matches = list(section_pattern.finditer(block))

        def _get_section_text(section_name_pattern: str) -> str:
            """Return the text of the first section whose name matches the given pattern."""
            name_re = re.compile(section_name_pattern, re.IGNORECASE)
            for j, sm in enumerate(section_matches):
                if name_re.search(sm.group(1)):
                    sec_start = sm.end()
                    sec_end = (
                        section_matches[j + 1].start()
                        if j + 1 < len(section_matches)
                        else len(block)
                    )
                    return block[sec_start:sec_end].strip()
            return ""

        # Description
        desc_text = _get_section_text(r"description")
        finding["description"] = desc_text

        # Impact
        impact_text = _get_section_text(r"impact")
        finding["impact"] = impact_text

        # Remediation
        remediation_text = _get_section_text(r"remediation")
        finding["remediation_steps"] = remediation_text

        # Proof of Concept — split into prose and code blocks
        poc_text = _get_section_text(r"proof\s+of\s+concept|poc")
        if poc_text:
            # Extract code blocks
            code_blocks: list[str] = []
            prose_parts: list[str] = []
            last_end = 0
            for cb_match in re.finditer(r"```(?:\w+)?\n(.*?)```", poc_text, re.DOTALL):
                prose_before = poc_text[last_end : cb_match.start()].strip()
                if prose_before:
                    prose_parts.append(prose_before)
                code_blocks.append(cb_match.group(1).rstrip())
                last_end = cb_match.end()
            prose_after = poc_text[last_end:].strip()
            if prose_after:
                prose_parts.append(prose_after)

            finding["poc_description"] = "\n\n".join(prose_parts)
            finding["poc_script_code"] = "\n\n".join(code_blocks)

        # Skip if title or description are both missing (title already checked)
        if not finding["description"] and not finding["impact"]:
            continue

        # Remove keys with empty values to keep dict clean for callers
        finding = {k: v for k, v in finding.items() if v}
        # But always keep title and severity
        finding.setdefault("title", title)
        finding.setdefault("severity", severity)

        findings.append(finding)

    return findings
