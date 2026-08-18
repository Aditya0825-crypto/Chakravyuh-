"""Docker sandbox runner for isolated PoV replay and compile jobs."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from core.config import get_settings

CRASH_RETURN_CODES = {1, 77, 134, 139, -6, -11, -7, -8, -4}


@dataclass
class SandboxResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def crashed(self) -> bool:
        return self.returncode in CRASH_RETURN_CODES


def docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        res = subprocess.run(["docker", "info"], capture_output=True, timeout=2)
        return res.returncode == 0
    except Exception:
        return False


def run_in_sandbox(
    command: list[str],
    *,
    work_dir: Path,
    stdin_data: bytes | None = None,
    timeout_sec: int = 30,
    mount_readonly: bool = True,
) -> SandboxResult:
    """
    Execute a command inside the sandbox Docker image.

    Falls back to local execution when Docker is unavailable (dev/tests).
    """
    settings = get_settings()
    if docker_available() and settings.sandbox_mode != "local":
        return _run_docker(
            command,
            work_dir=work_dir,
            stdin_data=stdin_data,
            timeout_sec=timeout_sec,
            image=settings.sandbox_image,
            mount_readonly=mount_readonly,
        )
    return _run_local(command, work_dir=work_dir, stdin_data=stdin_data, timeout_sec=timeout_sec)


def run_binary_with_input(
    binary: Path,
    crashing_input: bytes,
    *,
    work_dir: Path | None = None,
    timeout_sec: int = 30,
) -> SandboxResult:
    """Run an ASan binary with crash input on stdin."""
    work = (work_dir or binary.parent).resolve()
    binary = binary.resolve()
    if not binary.is_relative_to(work):
        raise ValueError(f"Binary {binary} must live inside work_dir {work} for sandbox runs")
    rel_path = binary.relative_to(work)
    cmd = [f"./{rel_path}"]
    return run_in_sandbox(cmd, work_dir=work, stdin_data=crashing_input, timeout_sec=timeout_sec)


def _run_local(
    command: list[str],
    *,
    work_dir: Path,
    stdin_data: bytes | None,
    timeout_sec: int,
) -> SandboxResult:
    import os
    env = dict(os.environ)
    env["ASAN_OPTIONS"] = "symbolize=0,abort_on_error=1"
    try:
        proc = subprocess.run(
            command,
            cwd=str(work_dir),
            input=stdin_data,
            capture_output=True,
            timeout=timeout_sec,
            env=env,
        )
        return SandboxResult(
            returncode=proc.returncode,
            stdout=proc.stdout.decode("utf-8", errors="replace"),
            stderr=proc.stderr.decode("utf-8", errors="replace"),
        )
    except subprocess.TimeoutExpired as exc:
        return SandboxResult(
            returncode=-1,
            stdout=(exc.stdout or b"").decode("utf-8", errors="replace"),
            stderr=(exc.stderr or b"").decode("utf-8", errors="replace"),
            timed_out=True,
        )


def _run_docker(
    command: list[str],
    *,
    work_dir: Path,
    stdin_data: bytes | None,
    timeout_sec: int,
    image: str,
    mount_readonly: bool,
) -> SandboxResult:
    work_dir = work_dir.resolve()
    stdin_file: Path | None = None

    docker_cmd = [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--memory",
        "512m",
        "--cpus",
        "1",
        "-v",
        f"{work_dir}:/sandbox/work:{'ro' if mount_readonly else 'rw'}",
        "-w",
        "/sandbox/work",
    ]

    if stdin_data is not None:
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".input")
        tmp.write(stdin_data)
        tmp.close()
        stdin_file = Path(tmp.name)
        docker_cmd.extend(["-i", "-v", f"{stdin_file}:{stdin_file}:ro"])

    docker_cmd.extend([image, *command])

    try:
        if stdin_file:
            with open(stdin_file, "rb") as fh:
                proc = subprocess.run(
                    docker_cmd,
                    stdin=fh,
                    capture_output=True,
                    timeout=timeout_sec,
                )
        else:
            proc = subprocess.run(
                docker_cmd,
                capture_output=True,
                timeout=timeout_sec,
            )
        return SandboxResult(
            returncode=proc.returncode,
            stdout=proc.stdout.decode("utf-8", errors="replace"),
            stderr=proc.stderr.decode("utf-8", errors="replace"),
        )
    except subprocess.TimeoutExpired as exc:
        return SandboxResult(
            returncode=-1,
            stdout=(exc.stdout or b"").decode("utf-8", errors="replace"),
            stderr=(exc.stderr or b"").decode("utf-8", errors="replace"),
            timed_out=True,
        )
    finally:
        if stdin_file and stdin_file.exists():
            stdin_file.unlink(missing_ok=True)
