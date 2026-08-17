"""Persist and load verified PoV artifacts on filesystem."""

import json
from pathlib import Path

from core.config import get_settings
from core.pov.models import VerifiedPoV


def pov_results_path(scan_id: str, artifact_root: str | None = None) -> Path:
    if artifact_root:
        return Path(artifact_root) / "povs" / "verified.json"
    return get_settings().scan_dir(scan_id) / "povs" / "verified.json"


def save_verified_povs(scan_id: str, povs: list[VerifiedPoV], artifact_root: str | None = None) -> Path:
    path = pov_results_path(scan_id, artifact_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = [p.to_api_dict() for p in povs]
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def load_verified_povs(scan_id: str, artifact_root: str | None = None) -> list[VerifiedPoV]:
    path = pov_results_path(scan_id, artifact_root)
    if not path.is_file():
        return []

    raw = json.loads(path.read_text(encoding="utf-8"))
    povs: list[VerifiedPoV] = []
    for item in raw:
        povs.append(
            VerifiedPoV(
                id=item["id"],
                status=item.get("status", "verified"),
                type=item["type"],
                cwe=item["cwe"],
                file=item["file"],
                line=item["line"],
                function=item["function"],
                severity=item.get("severity", "HIGH"),
                signal=item.get("signal", "SIGABRT"),
                return_code=item.get("returnCode", 134),
                confidence=item["confidence"],
                asan_summary=item.get("asanSummary", ""),
                stack_trace=item.get("stackTrace", []),
                reproduced=item.get("reproduced", True),
                dedup_hash=item.get("dedupHash", ""),
                crash_input=item.get("crashInput", ""),
                sanitizer_report=item.get("sanitizerReport", ""),
            )
        )
    return povs
