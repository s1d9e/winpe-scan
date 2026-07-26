"""
VirusTotal integration -- lookup file hashes against VT database.

Copyright (c) 2026 s1d9e - MIT License
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field

VT_API_URL = "https://www.virustotal.com/api/v3/files/{hash}"


@dataclass
class VTResult:
    """VirusTotal lookup result."""

    found: bool = False
    sha256: str = ""
    detection_ratio: str = "0/0"
    detections: int = 0
    total_engines: int = 0
    malicious: bool = False
    tags: list[str] = field(default_factory=list)
    names: list[str] = field(default_factory=list)
    popularity_rank: int = 0
    error: str | None = None


def lookup_hash(sha256: str, api_key: str | None = None) -> VTResult:
    """
    Look up a SHA256 hash on VirusTotal.

    Requires a VT API key (set via VT_API_KEY env var or api_key param).
    Free tier: 4 requests/minute.
    """
    key = api_key or os.environ.get("VT_API_KEY", "")
    if not key:
        result = VTResult(sha256=sha256)
        result.error = "No API key set (use VT_API_KEY env var)"
        return result

    url = VT_API_URL.format(hash=sha256)
    req = urllib.request.Request(url)  # noqa: S310
    req.add_header("x-apikey", key)
    req.add_header("Accept", "application/json")

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310
            data = json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        result = VTResult(sha256=sha256)
        if exc.code == 404:
            result.found = False
            return result
        result.error = f"HTTP {exc.code}: {exc.reason}"
        return result
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        result = VTResult(sha256=sha256)
        result.error = f"Network error: {exc}"
        return result

    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})

    malicious_count = stats.get("malicious", 0) + stats.get("suspicious", 0)
    total = sum(stats.values())

    result = VTResult(
        found=True,
        sha256=sha256,
        detection_ratio=f"{malicious_count}/{total}",
        detections=malicious_count,
        total_engines=total,
        malicious=malicious_count > 0,
        tags=attrs.get("tags", []),
        names=attrs.get("names", [])[:5],
        popularity_rank=attrs.get("popularit_classification_rank", 0),
    )

    return result
