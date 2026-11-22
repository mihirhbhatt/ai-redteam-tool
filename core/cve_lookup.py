"""On-demand CVE intelligence from the NVD vulnerability API."""

from datetime import datetime, timedelta, timezone
import os
import re
from typing import Any

import requests

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class CveLookupError(Exception):
    """An NVD query failed or returned an unexpected response."""


def _request(params: dict[str, Any]) -> dict[str, Any]:
    api_key = os.getenv("NVD_API_KEY")
    headers = {"apiKey": api_key} if api_key else {}
    try:
        response = requests.get(NVD_API, params=params, headers=headers, timeout=30)
        response.raise_for_status()
        data = response.json()
    except requests.RequestException as exc:
        raise CveLookupError(f"NVD request failed: {exc}") from exc
    except ValueError as exc:
        raise CveLookupError("NVD returned invalid JSON.") from exc
    if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
        raise CveLookupError("NVD returned an unexpected response format.")
    if not isinstance(data.get("totalResults"), int):
        raise CveLookupError("NVD response is missing its total result count.")
    return data


def lookup_cves(query: str, *, days: int = 30, limit: int = 10) -> tuple[list[dict[str, Any]], int]:
    """Find a CVE ID or the most recently published keyword matches."""
    query = query.strip()
    if not query:
        raise ValueError("A CVE ID or keyword is required.")
    if not 1 <= days <= 120:
        raise ValueError("Days must be between 1 and 120.")
    if not 1 <= limit <= 100:
        raise ValueError("Limit must be between 1 and 100.")
    if re.fullmatch(r"CVE-\d{4}-\d{4,}", query, re.IGNORECASE):
        data = _request({"cveId": query.upper()})
    else:
        if query.upper().startswith("CVE-"):
            raise ValueError("Invalid CVE ID; expected CVE-YYYY-NNNN.")
        now = datetime.now(timezone.utc)
        params: dict[str, Any] = {
            "keywordSearch": query,
            "pubStartDate": (now - timedelta(days=days)).isoformat(timespec="milliseconds"),
            "pubEndDate": now.isoformat(timespec="milliseconds"),
            "resultsPerPage": 1,
        }
        first = _request(params)
        total = first["totalResults"]
        if total == 0:
            return [], 0
        if total == 1:
            data = first
        else:
            params.update(resultsPerPage=limit, startIndex=max(0, total - limit))
            data = _request(params)
    entries = data["vulnerabilities"]
    if any(not isinstance(item, dict) or not isinstance(item.get("cve"), dict) for item in entries):
        raise CveLookupError("NVD response contains an invalid CVE record.")
    records = [item["cve"] for item in entries]
    if any(not isinstance(item.get("id"), str) or not isinstance(item.get("published"), str) for item in records):
        raise CveLookupError("NVD response contains a CVE without an ID or publication date.")
    return sorted(records, key=lambda item: item["published"], reverse=True), data["totalResults"]


def format_cve(cve: dict[str, Any]) -> str:
    descriptions = cve.get("descriptions", [])
    description = next(
        (item.get("value") for item in descriptions if item.get("lang") == "en" and item.get("value")),
        "English description unavailable.",
    )
    metrics = cve.get("metrics") or {}
    score = "Not available"
    for metric_name in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        candidates = metrics.get(metric_name, [])
        if not candidates:
            continue
        metric = next((item for item in candidates if item.get("type") == "Primary"), candidates[0])
        cvss = metric.get("cvssData", {})
        if "baseScore" in cvss:
            severity = cvss.get("baseSeverity") or metric.get("baseSeverity") or "unrated"
            score = f"{cvss['baseScore']} ({severity}), CVSS {cvss.get('version', 'unknown')}"
            break
    references = [item["url"] for item in cve.get("references", []) if item.get("url")]
    lines = [
        f"{cve['id']} | Published: {cve['published']} | Updated: {cve.get('lastModified', 'unknown')}",
        f"Status: {cve.get('vulnStatus', 'unknown')} | CVSS: {score}",
        f"Description: {description}",
        f"NVD: https://nvd.nist.gov/vuln/detail/{cve['id']}",
    ]
    lines.extend(f"Reference: {url}" for url in references)
    return "\n".join(lines)
