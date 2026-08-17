"""Attack variant generator for patch verification and security testing."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class AttackVariant:
    name: str
    description: str
    payload: bytes


def generate_attack_variants(original_poc_str: str | None = None) -> list[AttackVariant]:
    """
    Generate 9 deterministic attack variants based on the original crashing input.
    """
    base_text = original_poc_str or ("A" * 512 + "\n")
    base_bytes = base_text.encode("utf-8", errors="replace")

    variants: list[AttackVariant] = []

    # 1. Exact original PoV
    variants.append(
        AttackVariant(
            name="original_poc",
            description="Exact original PoV crashing payload",
            payload=base_bytes,
        )
    )

    # 2. Truncated (half length)
    half_len = max(1, len(base_bytes) // 2)
    variants.append(
        AttackVariant(
            name="truncated_half",
            description="Truncated half-length payload",
            payload=base_bytes[:half_len] + b"\n",
        )
    )

    # 3. Single-byte boundary overflow
    variants.append(
        AttackVariant(
            name="boundary_plus_one",
            description="Single-byte off-by-one boundary probe",
            payload=b"A" * 257 + b"\n",
        )
    )

    # 4. Extreme 10k buffer
    variants.append(
        AttackVariant(
            name="extreme_10k_buffer",
            description="Large 10,000-byte flood attack",
            payload=b"A" * 10000 + b"\n",
        )
    )

    # 5. Null-byte prefix / internal nulls
    variants.append(
        AttackVariant(
            name="null_byte_probe",
            description="Leading and internal null byte sequence",
            payload=b"\x00\x00\x00\x00" + b"A" * 512 + b"\n",
        )
    )

    # 6. 0xFF fill buffer
    variants.append(
        AttackVariant(
            name="ff_fill_buffer",
            description="High-byte 0xFF signed/unsigned arithmetic edge case",
            payload=b"\xff" * 512 + b"\n",
        )
    )

    # 7. Format string probe
    variants.append(
        AttackVariant(
            name="format_string_probe",
            description="Format string %s%x%n specifiers",
            payload=b"%s%x%n%s%x%n%s%x%n%s\n",
        )
    )

    # 8. Doubled string payload
    variants.append(
        AttackVariant(
            name="doubled_payload",
            description="Doubled payload repetition",
            payload=(base_bytes.rstrip() * 2) + b"\n",
        )
    )

    # 9. Newline-separated overflow burst
    variants.append(
        AttackVariant(
            name="newline_burst",
            description="Multiple fast newline-delimited command chunks",
            payload=b"PING\n" + (b"A" * 512) + b"\nQUIT\n",
        )
    )

    return variants
