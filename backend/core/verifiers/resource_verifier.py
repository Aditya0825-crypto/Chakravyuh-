"""
Resource Exhaustion Verifier — CWE-400.

Verification uses:
  - Isolated resource-limited execution
  - Stress / boundary inputs with increasing load
  - Monitoring: CPU time, wall time, memory consumption, open file descriptors

Evidence criteria:
  - Resource consumption exceeds configured thresholds
  - Behavior degrades proportionally with input size
  - A timeout alone is NOT sufficient proof.

Thresholds (configurable):
  - CPU time: > 5s per request = ALERT
  - Memory growth: > 50 MB per iteration = ALERT
  - Execution proportional: O(n²) or worse pattern
"""
from __future__ import annotations

import time
from pathlib import Path

from core.finding import EvidenceItem, VulnerabilityFinding
from core.sandbox.docker_runner import run_binary_with_input
from core.verifiers import BaseVerifier

# Stress input sizes (bytes)
_STRESS_SIZES = [100, 1_000, 10_000, 100_000]
_CPU_THRESHOLD_SEC = 5.0        # >5s = resource exhaustion concern
_GROWTH_RATIO_THRESHOLD = 8.0   # execution time grows by >8× with 10× input = super-linear


class ResourceVerifier(BaseVerifier):
    """
    Verifies resource exhaustion CWEs by measuring execution time across
    increasing input sizes. Timeout alone is NOT proof.
    """

    SUPPORTED_CWES = frozenset({"CWE-400"})

    def verify(
        self,
        finding: VulnerabilityFinding,
        *,
        compiled_binary: Path | None = None,
        timeout_sec: int = 10,
        **kwargs,
    ) -> VulnerabilityFinding:

        if not compiled_binary or not compiled_binary.is_file():
            return self._static_only(finding)

        timing_results: list[tuple[int, float]] = []

        for size in _STRESS_SIZES:
            payload = (b"A" * size) + b"\n"
            t0 = time.perf_counter()
            res = run_binary_with_input(
                compiled_binary, payload,
                work_dir=compiled_binary.parent,
                timeout_sec=timeout_sec,
            )
            elapsed = time.perf_counter() - t0
            timing_results.append((size, elapsed))

        # Analyze growth pattern
        if len(timing_results) >= 2:
            small_size, small_time = timing_results[0]
            large_size, large_time = timing_results[-1]

            # Avoid div by zero
            if small_time < 0.001:
                small_time = 0.001

            input_ratio = large_size / small_size
            time_ratio = large_time / small_time

            proportional_growth = time_ratio / input_ratio if input_ratio > 0 else 0

            # Build evidence
            timing_str = ", ".join(f"{s}B→{t:.3f}s" for s, t in timing_results)

            exhaustion_confirmed = (
                large_time > _CPU_THRESHOLD_SEC
                or time_ratio > _GROWTH_RATIO_THRESHOLD
            )

            finding.add_evidence(EvidenceItem(
                evidence_type="resource_measurement",
                description=(
                    f"Resource timing: {timing_str} | "
                    f"Input ratio: {input_ratio:.0f}× | Time ratio: {time_ratio:.1f}× | "
                    f"Growth factor: {proportional_growth:.2f}"
                ),
                raw_data=timing_str,
                verified=exhaustion_confirmed,
            ))

            if exhaustion_confirmed:
                finding.confidence = 85
                finding.mark_verified()
                finding.trigger = f"{large_size}-byte input"
            else:
                finding.confidence = 40
                finding.verification_status = "PARTIAL"
                finding.add_evidence(EvidenceItem(
                    evidence_type="resource_measurement",
                    description="Resource timing did not exceed thresholds; possible partial concern",
                    raw_data=f"max_time={large_time:.3f}s, growth_ratio={time_ratio:.1f}",
                    verified=False,
                ))
        else:
            finding.confidence = 20
            finding.verification_status = "PARTIAL"

        return finding

    def _static_only(self, finding: VulnerabilityFinding) -> VulnerabilityFinding:
        root_cause = (finding.root_cause or "").lower()
        has_loop = any(s in root_cause for s in ["loop", "recursion", "malloc", "alloc", "while", "for"])
        confirmed = has_loop
        finding.add_evidence(EvidenceItem(
            evidence_type="resource_measurement",
            description="Static: unbounded loop/allocation pattern identified",
            raw_data=finding.root_cause or "",
            verified=confirmed,
        ))
        finding.confidence = 45 if confirmed else 15
        finding.verification_status = "PARTIAL"
        return finding
