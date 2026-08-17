"""Add reports, gate_decisions, and learning_log_entries tables.

Revision ID: 005_report_gate
Revises: 004_patches
Create Date: 2026-08-17
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "005_report_gate"
down_revision: Union[str, None] = "004_patches"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "reports",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("report_id", sa.String(length=64), nullable=False),
        sa.Column("recommendation", sa.String(length=32), nullable=False, server_default="REVIEW"),
        sa.Column("confidence", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("cvss_score", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("root_cause", sa.Text(), nullable=False),
        sa.Column("report_json", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_reports_scan_id", "reports", ["scan_id"])

    op.create_table(
        "gate_decisions",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("decision", sa.String(length=32), nullable=False),
        sa.Column("decided_by", sa.String(length=128), nullable=False, server_default="Security Lead"),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_gate_decisions_scan_id", "gate_decisions", ["scan_id"])

    op.create_table(
        "learning_log_entries",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("entry_id", sa.String(length=64), nullable=False),
        sa.Column("date", sa.String(length=32), nullable=False),
        sa.Column("target", sa.String(length=256), nullable=False),
        sa.Column("cwe", sa.String(length=32), nullable=False),
        sa.Column("crash_type", sa.String(length=128), nullable=False),
        sa.Column("discovery_method", sa.String(length=128), nullable=False),
        sa.Column("winning_agent", sa.String(length=128), nullable=False),
        sa.Column("confidence", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("patch_success", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("top_cve", sa.String(length=64), nullable=True),
        sa.Column("notes", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_learning_log_entries_scan_id", "learning_log_entries", ["scan_id"])


def downgrade() -> None:
    op.drop_index("ix_learning_log_entries_scan_id", table_name="learning_log_entries")
    op.drop_table("learning_log_entries")
    op.drop_index("ix_gate_decisions_scan_id", table_name="gate_decisions")
    op.drop_table("gate_decisions")
    op.drop_index("ix_reports_scan_id", table_name="reports")
    op.drop_table("reports")
