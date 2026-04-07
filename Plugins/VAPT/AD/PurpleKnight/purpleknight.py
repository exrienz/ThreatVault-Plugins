from __future__ import annotations

import csv
import io
import json
import re

import polars as pl


SUPPORTED_HTML_TYPES = {"html", "text/html", "application/xhtml+xml"}
SUPPORTED_CSV_TYPES = {"csv", "text/csv"}
SUPPORTED_TYPES = SUPPORTED_HTML_TYPES | SUPPORTED_CSV_TYPES
VALID_RISKS = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "warning": "MEDIUM",
    "informational": "LOW",
}


def _decode_bytes(file: bytes) -> str:
    for encoding in ("utf-8", "utf-8-sig", "cp1252", "latin-1"):
        try:
            return file.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    raise ValueError("Failed to decode input with supported encodings.")


def _extract_json_object(content: str, start_idx: int) -> dict | None:
    decoder = json.JSONDecoder()
    obj_start = content.find("{", start_idx)
    if obj_start == -1:
        return None

    try:
        obj, _ = decoder.raw_decode(content[obj_start:])
    except json.JSONDecodeError:
        return None

    if isinstance(obj, dict):
        return obj
    return None


def _normalize_risk(value: str | None) -> str:
    normalized = (value or "").strip().lower()
    return SEVERITY_MAP.get(normalized, normalized.upper() or "LOW")


def _build_description(description: str | None, likelihood: str | None) -> str:
    description = (description or "").strip()
    likelihood = (likelihood or "").strip()

    if description and likelihood:
        return f"{description}\n\nLikelihood of Compromise:\n{likelihood}"
    return description or likelihood


def _append_finding(
    findings: list[dict[str, str]],
    *,
    host: str | None,
    default_host: str,
    indicator_name: str,
    description: str,
    severity: str | None,
    remediation: str | None,
    evidence: str | None,
    vulnerability_id: str | None,
) -> None:
    findings.append(
        {
            "cve": (vulnerability_id or "").strip(),
            "risk": _normalize_risk(severity),
            "host": (host or "").strip() or default_host,
            "port": 0,
            "name": (indicator_name or "").strip(),
            "description": description,
            "remediation": (remediation or "").strip(),
            "evidence": (evidence or "").strip(),
            "vpr_score": "",
        }
    )


def _parse_html_findings(content: str) -> list[dict[str, str]]:
    marker = "window.reportJSON"
    start_idx = content.find(marker)
    report_json = _extract_json_object(content, start_idx) if start_idx != -1 else None
    if not report_json:
        raise ValueError("Could not find Purple Knight report data in the HTML file.")

    results_list = report_json.get("reportResultsList", [])
    default_domain = ""
    if results_list:
        first_result = results_list[0] or {}
        default_domain = first_result.get("ForestName", "") or ""
        if not default_domain:
            selected_domains = first_result.get("SelectedDomains", []) or []
            if selected_domains:
                default_domain = str(selected_domains[0]).strip()

    indicator_metadata: dict[str, dict] = {}
    pattern = r'window\["Category_\d+"\]\["([A-Fa-f0-9\-]+)"\]\s*='
    for match in re.finditer(pattern, content):
        uuid = match.group(1)
        obj = _extract_json_object(content, match.end())
        if obj:
            indicator_metadata[uuid] = obj

    findings: list[dict[str, str]] = []
    processed_indicators: set[str] = set()

    for appendix in report_json.get("Appendices", []) or []:
        indicator_uuid = (appendix or {}).get("IndicatorUUID", "") or ""
        if indicator_uuid:
            processed_indicators.add(indicator_uuid)

        meta = indicator_metadata.get(indicator_uuid, {})
        res_indicator = meta.get("ResIndicator", {}) or {}
        exec_result = meta.get("ExecutionResult", {}) or {}

        indicator_name = res_indicator.get("Name") or appendix.get("Title") or ""
        description = _build_description(
            res_indicator.get("Description"),
            res_indicator.get("LikelihoodOfCompromise"),
        )
        severity = res_indicator.get("Severity")
        remediation = exec_result.get("Remediation")
        default_evidence = exec_result.get("ResultMessage")

        file_info = appendix.get("File", {}) or {}
        csv_content = file_info.get("CsvContent", []) or []

        if len(csv_content) < 2:
            _append_finding(
                findings,
                host=default_domain,
                default_host=default_domain,
                indicator_name=indicator_name,
                description=description,
                severity=severity,
                remediation=remediation,
                evidence=default_evidence,
                vulnerability_id=indicator_uuid,
            )
            continue

        headers = [str(header) for header in csv_content[0]]
        try:
            host_idx = headers.index("DistinguishedName")
        except ValueError:
            host_idx = 0 if headers else None

        for row in csv_content[1:]:
            if not row:
                continue

            host = ""
            if host_idx is not None and host_idx < len(row):
                host = str(row[host_idx])

            evidence_parts = []
            for idx, header in enumerate(headers):
                if idx < len(row):
                    evidence_parts.append(f"{header}: {row[idx]}")

            _append_finding(
                findings,
                host=host,
                default_host=default_domain,
                indicator_name=indicator_name,
                description=description,
                severity=severity,
                remediation=remediation,
                evidence="\n".join(evidence_parts) or default_evidence,
                vulnerability_id=indicator_uuid,
            )

    for indicator_uuid, meta in indicator_metadata.items():
        if indicator_uuid in processed_indicators:
            continue

        report_objects = meta.get("IndicatorReportObjects", []) or []
        exec_result = meta.get("ExecutionResult", {}) or {}
        res_indicator = meta.get("ResIndicator", {}) or {}

        if not report_objects:
            continue

        indicator_name = res_indicator.get("Name", "")
        description = _build_description(
            res_indicator.get("Description"),
            res_indicator.get("LikelihoodOfCompromise"),
        )
        severity = res_indicator.get("Severity")
        remediation = exec_result.get("Remediation")
        default_evidence = exec_result.get("ResultMessage")

        for row in report_objects:
            if not row:
                continue

            parsed_data: dict[str, str] = {}
            for cell in row:
                cell = str(cell)
                if ": " in cell:
                    key, value = cell.split(": ", 1)
                    parsed_data[key] = value

            _append_finding(
                findings,
                host=parsed_data.get("DistinguishedName"),
                default_host=default_domain,
                indicator_name=indicator_name,
                description=description,
                severity=severity,
                remediation=remediation,
                evidence="\n".join(f"{key}: {value}" for key, value in parsed_data.items())
                or default_evidence,
                vulnerability_id=indicator_uuid,
            )

    if not findings:
        raise ValueError("No Purple Knight findings were extracted from the HTML report.")

    return findings


def _parse_csv_findings(content: str) -> list[dict[str, str]]:
    reader = csv.DictReader(io.StringIO(content))
    findings: list[dict[str, str]] = []

    for row in reader:
        if not row:
            continue

        _append_finding(
            findings,
            host=row.get("host"),
            default_host="",
            indicator_name=row.get("name", ""),
            description=row.get("description", ""),
            severity=row.get("severity") or row.get("risk"),
            remediation=row.get("remediation"),
            evidence=row.get("evidence"),
            vulnerability_id=row.get("vulnerability_id") or row.get("cve"),
        )

    if not findings:
        raise ValueError("No data found in CSV file.")

    return findings


def _looks_like_html(content: str) -> bool:
    lowered = content.lower()
    return "window.reportjson" in lowered or "<html" in lowered or "<!doctype html" in lowered


def _looks_like_csv(content: str) -> bool:
    first_line = content.lstrip().splitlines()[0] if content.strip() else ""
    lowered = first_line.lower()
    return "host" in lowered and ("severity" in lowered or "risk" in lowered)


def _to_lazyframe(findings: list[dict[str, str]]) -> pl.LazyFrame:
    df = pl.DataFrame(findings).select(
        [
            pl.col("cve").cast(pl.Utf8).fill_null(""),
            pl.col("risk").cast(pl.Utf8).fill_null("LOW"),
            pl.col("host").cast(pl.Utf8).fill_null(""),
            pl.col("port").cast(pl.Int64, strict=False).fill_null(0),
            pl.col("name").cast(pl.Utf8).fill_null(""),
            pl.col("description")
            .cast(pl.Utf8)
            .fill_null("")
            .str.replace_all(r"\r?\n", " <br/> "),
            pl.col("remediation")
            .cast(pl.Utf8)
            .fill_null("")
            .str.replace_all(r"\r?\n", " <br/> "),
            pl.col("evidence")
            .cast(pl.Utf8)
            .fill_null("")
            .str.replace_all(r"\r?\n", " <br/> "),
            pl.col("vpr_score").cast(pl.Utf8).fill_null(""),
        ]
    )

    return df.filter(pl.col("risk").is_in(sorted(VALID_RISKS))).lazy()


def process(file: bytes, file_type: str) -> pl.LazyFrame:
    normalized_type = (file_type or "").strip().lower()
    content = _decode_bytes(file)

    if normalized_type not in SUPPORTED_TYPES:
        if _looks_like_html(content):
            normalized_type = "html"
        elif _looks_like_csv(content):
            normalized_type = "csv"
        else:
            raise ValueError(
                f"Unsupported file type: {file_type}. Expected HTML or CSV Purple Knight reports."
            )

    if normalized_type in SUPPORTED_HTML_TYPES:
        findings = _parse_html_findings(content)
    else:
        findings = _parse_csv_findings(content)

    return _to_lazyframe(findings)
