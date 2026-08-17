# CHAKRAVYUH ephemeral scan sandbox — compile, fuzz, PoV replay only.
# API/Celery workers run on WSL host; they invoke `docker run` with this image.
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV AFL_SKIP_CPUFREQ=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang llvm build-essential git patch curl ca-certificates \
    python3 python3-pip python3-venv \
    afl++ \
    && rm -rf /var/lib/apt/lists/*

# Semgrep static analysis (MVP path)
RUN python3 -m pip install --no-cache-dir semgrep

WORKDIR /sandbox
RUN mkdir -p /sandbox/work /sandbox/out

# Default: no network, read-only root except /sandbox/out
ENV PATH="/usr/lib/afl:/usr/bin:${PATH}"
