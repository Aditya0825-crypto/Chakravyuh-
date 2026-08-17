"""Add fuzz_runs, crashes, and verified_povs tables.

Revision ID: 003_bugfinding
Revises: 002_recon
Create Date: 2026-08-17
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "003_bugfinding"
down_revision: Union[str, None] = "002_recon"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "fuzz_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="complete"),
        sa.Column("runtime_sec", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("execs_per_sec", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("total_execs", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("crashes_found", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("unique_crashes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("coverage_pct", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("coverage_gain", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("target_reached", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("escalated", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("seeds_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_fuzz_runs_scan_id", "fuzz_runs", ["scan_id"])

    op.create_table(
        "crashes",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="unverified"),
        sa.Column("type", sa.String(length=128), nullable=False),
        sa.Column("cwe", sa.String(length=32), nullable=False),
        sa.Column("file", sa.String(length=1024), nullable=False),
        sa.Column("line", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("function", sa.String(length=256), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False, server_default="HIGH"),
        sa.Column("signal", sa.String(length=32), nullable=False, server_default="SIGABRT"),
        sa.Column("return_code", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("confidence", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("asan_summary", sa.Text(), nullable=True),
        sa.Column("stack_trace", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("reproduced", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("deduplicated", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("crash_input", sa.Text(), nullable=True),
        sa.Column("discovery_method", sa.String(length=64), nullable=False, server_default="fuzzing"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_crashes_scan_id", "crashes", ["scan_id"])

    op.create_table(
        "verified_povs",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("crash_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("confidence", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("cwe", sa.String(length=32), nullable=False),
        sa.Column("sanitizer_report", sa.Text(), nullable=True),
        sa.Column("dedup_hash", sa.String(length=64), nullable=True),
        sa.Column("reproducible", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["crash_id"], ["crashes.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_verified_povs_scan_id", "verified_povs", ["scan_id"])


def downgrade() -> None:
    op.drop_index("ix_verified_povs_scan_id", table_name="verified_povs")
    op.drop_table("verified_povs")
    op.drop_index("ix_crashes_scan_id", table_name="crashes")
    op.drop_table("crashes")
    op.drop_index("ix_fuzz_runs_scan_id", table_name="fuzz_runs")
    op.drop_table("fuzz_runs")
