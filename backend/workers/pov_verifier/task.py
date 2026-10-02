"""Celery task & runner for Stage 3 — Vulnerability-Specific Verification.

Generalizes from ASan-only crash verification to vulnerability-class-appropriate
verification using the strategy registry in core.verifiers.registry.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import select

from core.config import get_settings
from core.cwe_registry import is_supported
from core.events import publish_scan_event
from core.finding import EvidenceItem, VulnerabilityFinding
from core.parsers.asan import classify_sanitizer_output
from core.parsers.stack_trace import extract_stack_trace, normalize_stack_trace, stack_hash
from core.sandbox.docker_runner import run_binary_with_input
from core.scoring.confidence import ConfidenceInputs, calculate_confidence
from core.verifiers.registry import verify_finding
from db.models import Crash, PipelineEvent, PipelineEventLevel, Scan, ScanStatus, VerifiedPoV
from db.session import SessionLocal
from workers.celery_app import celery_app


@dataclass
class PoVVerificationResult:
    scan_id: str
    verified_count: int
    rejected_count: int
    partial_count: int
    duration_sec: float
    findings: list[VulnerabilityFinding]


def run_pov_verifier(scan_id: str, source_root: Path | None = None) -> PoVVerificationResult:
    """
    Execute Stage 3 Vulnerability-Specific Verification.

    For each crash/finding:
    1. Build a normalized VulnerabilityFinding.
    2. Select the appropriate verifier via the strategy registry.
    3. Run the verifier (NOT just crash replay for every CWE).
    4. Persist updated VerifiedPoV records.
    5. Publish real-time events.
    """
    start_time = time.perf_counter()
    scan_uuid = uuid.UUID(scan_id)
    db = SessionLocal()

    try:
        scan = db.get(Scan, scan_uuid)
        if not scan:
            raise ValueError(f"Scan {scan_id} not found")

        _log(db, scan, "Initiating vulnerability-specific verification (strategy dispatch)...")

        # Find compiled binary if source_root provided
        compiled_binary = None
        if source_root and source_root.is_dir():
            bins = list((source_root / "build").glob(f"fuzz_{scan_id[:8]}*"))
            if not bins:
                bins = list(source_root.glob("**/build/*"))
            if bins:
                compiled_binary = bins[0]

        # Query crashes for this scan
        stmt = select(Crash).where(Crash.scan_id == scan_uuid)
        crashes = list(db.scalars(stmt).all())

        # If no runtime ASan crashes exist, generate verified PoV entries from Recon/Static findings
        if not crashes:
            crashes = _synthesize_from_static(db, scan_uuid)

        verified_count = 0
        rejected_count = 0
        partial_count = 0
        seen_dedup_hashes: set[str] = set()
        findings: list[VulnerabilityFinding] = []

        for crash in crashes:
            # Build normalized finding
            finding = VulnerabilityFinding.from_crash_record(crash, scan_id)

            # Log which verifier strategy is being used
            cwe_label = finding.cwe_id if is_supported(finding.cwe_id) else f"{finding.cwe_id} (UNSUPPORTED)"
            _log(db, scan, f"Verifying {cwe_label} in {crash.function}() using {finding.verification_method}")

            # Run the appropriate verifier (strategy dispatch)
            finding = verify_finding(
                finding,
                compiled_binary=compiled_binary,
                source_root=source_root,
                timeout_sec=5,
            )

            # Deduplication
            frames = crash.stack_trace or [crash.function or "unknown"]
            d_hash = stack_hash(frames)
            is_duplicate = d_hash in seen_dedup_hashes
            seen_dedup_hashes.add(d_hash)

            # Persist result
            if finding.verification_status == "VERIFIED" and not is_duplicate:
                crash.status = "verified"
                crash.reproduced = True
                crash.deduplicated = False
                crash.confidence = finding.confidence

                if finding.asan_summary:
                    crash.asan_summary = finding.asan_summary
                if finding.stack_trace:
                    crash.stack_trace = finding.stack_trace

                pov = VerifiedPoV(
                    scan_id=scan_uuid,
                    crash_id=crash.id,
                    confidence=finding.confidence,
                    cwe=finding.cwe_id,
                    sanitizer_report="\n".join(
                        e.raw_data for e in finding.evidence if e.verified
                    )[:2000],
                    dedup_hash=d_hash,
                    reproducible=True,
                )
                db.add(pov)
                verified_count += 1
                _log(
                    db, scan,
                    f"✓ VERIFIED — {finding.cwe_id} ({finding.verification_method}) "
                    f"in {crash.function}() [Confidence: {finding.confidence}%]",
                )

            elif is_duplicate:
                crash.status = "verified"
                crash.deduplicated = True
                _log(db, scan, f"Duplicate finding deduplicated: hash {d_hash[:8]}")

            elif finding.verification_status == "PARTIAL":
                crash.status = "partial"
                crash.confidence = finding.confidence
                partial_count += 1
                _log(db, scan, f"PARTIAL verification — {finding.cwe_id}: {crash.function}()", level=PipelineEventLevel.WARN)

            else:
                crash.status = "rejected"
                rejected_count += 1
                _log(db, scan, f"Rejected — {finding.cwe_id}: {crash.function}()", level=PipelineEventLevel.WARN)

            findings.append(finding)

        db.commit()
        duration = time.perf_counter() - start_time
        _log(
            db, scan,
            f"Verification complete — {verified_count} verified, {partial_count} partial, {rejected_count} rejected",
        )

        return PoVVerificationResult(
            scan_id=scan_id,
            verified_count=verified_count,
            rejected_count=rejected_count,
            partial_count=partial_count,
            duration_sec=duration,
            findings=findings,
        )

    except Exception as exc:
        db.rollback()
        raise
    finally:
        db.close()


def _synthesize_from_static(db, scan_uuid: uuid.UUID) -> list[Crash]:
    """
    Fallback: synthesize a crash candidate from static findings / recon targets
    when no runtime crashes were found (e.g., non-memory CWEs).
    """
    from db.models import ReconTarget, StaticFinding

    static_stmt = select(StaticFinding).where(StaticFinding.scan_id == scan_uuid)
    recon_stmt = select(ReconTarget).where(ReconTarget.scan_id == scan_uuid).order_by(ReconTarget.rank.asc())

    static_findings = list(db.scalars(static_stmt).all())
    recon_targets = list(db.scalars(recon_stmt).all())

    if not static_findings and not recon_targets:
        return []

    top_sf = static_findings[0] if static_findings else None
    top_rt = recon_targets[0] if recon_targets else None

    f_file = top_sf.file if top_sf else (top_rt.file if top_rt else "server.c")
    f_line = top_sf.line if top_sf else (top_rt.line if top_rt else 8)
    f_func = top_rt.function.replace("()", "") if top_rt else "handle_request"

    # Infer CWE from static finding rule name
    f_cwe = "CWE-122"
    if top_sf:
        rule_lower = top_sf.rule.lower()
        if "format" in rule_lower or "printf" in rule_lower:
            f_cwe = "CWE-134"
        elif "command" in rule_lower or "system" in rule_lower:
            f_cwe = "CWE-78"
        elif "path" in rule_lower or "traversal" in rule_lower:
            f_cwe = "CWE-22"
        elif "overflow" in rule_lower:
            f_cwe = "CWE-120"
        elif "strcpy" in rule_lower or "buffer" in rule_lower:
            f_cwe = "CWE-122"

    f_msg = top_sf.message if top_sf else "Static taint analysis identified potential vulnerability"

    fallback_crash = Crash(
        scan_id=scan_uuid,
        status="unverified",
        type=f_cwe,
        cwe=f_cwe,
        file=f_file,
        line=f_line,
        function=f_func,
        severity="HIGH",
        signal="UNKNOWN",
        return_code=0,
        confidence=40,
        asan_summary=f_msg,
        stack_trace=[f"{f_func} ({f_file}:{f_line})"],
        reproduced=False,
        deduplicated=False,
        crash_input="",
        discovery_method="Static Taint + Directed Review",
    )
    db.add(fallback_crash)
    db.commit()
    db.refresh(fallback_crash)
    return [fallback_crash]


@celery_app.task(name="chakravyuh.pov_verifier", bind=True, max_retries=0)
def task_pov_verifier(self, scan_id: str) -> dict:
    from core.config import get_settings
    from core.events import publish_scan_event
    from db.models import Scan, ScanStatus
    from db.session import SessionLocal

    settings = get_settings()
    db = SessionLocal()
    try:
        scan = db.get(Scan, uuid.UUID(scan_id))
        if not scan:
            return {"scan_id": scan_id, "error": "scan not found"}

        scan.status = ScanStatus.STAGE_POV
        scan.current_stage = "verification"
        db.commit()

        publish_scan_event(scan_id, "stage_started", stage="verification")

        source_dir = _resolve_source_dir(scan, settings)
        res = run_pov_verifier(scan_id, source_dir)

        publish_scan_event(
            scan_id,
            "stage_completed",
            stage="verification",
            duration_sec=round(res.duration_sec, 1),
            verified_count=res.verified_count,
            partial_count=res.partial_count,
        )
        return {
            "scan_id": scan_id,
            "verified_count": res.verified_count,
            "partial_count": res.partial_count,
            "duration_sec": res.duration_sec,
        }
    except Exception as exc:
        publish_scan_event(scan_id, "stage_failed", stage="verification", error=str(exc))
        raise
    finally:
        db.close()


def _resolve_source_dir(scan, settings) -> Path:
    if scan.artifact_root:
        root = Path(scan.artifact_root) / "source"
        extracted = root / "extracted"
        if extracted.is_dir():
            return extracted
        if root.is_dir():
            return root
    return settings.scan_source_dir(str(scan.id))


def _log(
    db,
    scan: Scan,
    message: str,
    level: PipelineEventLevel = PipelineEventLevel.INFO,
) -> None:
    event = PipelineEvent(
        scan_id=scan.id,
        stage="verification",
        level=level,
        message=message,
    )
    db.add(event)
    db.commit()
    publish_scan_event(
        str(scan.id),
        "log",
        stage="verification",
        level=level.value,
        message=message,
    )
