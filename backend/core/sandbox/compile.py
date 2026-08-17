"""Compile C/C++ targets with AddressSanitizer + UBSan."""

import subprocess
from pathlib import Path


SANITIZER_FLAGS = ["-fsanitize=address,undefined", "-g", "-O1", "-fno-omit-frame-pointer"]
DEFAULT_CFLAGS = ["-Wall", "-Wextra"]


def compile_with_sanitizers(
    sources: list[Path],
    output: Path,
    *,
    extra_flags: list[str] | None = None,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess:
    """Compile source files to an ASan-instrumented binary."""
    output.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        "clang",
        *DEFAULT_CFLAGS,
        *SANITIZER_FLAGS,
        *(extra_flags or []),
        *[str(s) for s in sources],
        "-o",
        str(output),
    ]
    return subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        timeout=120,
    )


def compile_project_dir(project_dir: Path, output_name: str = "target") -> tuple[Path, subprocess.CompletedProcess]:
    """Compile all .c files in a directory into one binary."""
    sources = sorted(project_dir.glob("**/*.c"))
    if not sources:
        raise FileNotFoundError(f"No .c sources under {project_dir}")
    out = project_dir / "build" / output_name
    result = compile_with_sanitizers(sources, out, cwd=project_dir)
    return out, result
