"""Add recon_targets and static_findings tables.

Revision ID: 002_recon
Revises: 001_initial
Create Date: 2026-08-17
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "002_recon"
down_revision: Union[str, None] = "001_initial"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "recon_targets",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("function", sa.String(length=256), nullable=False),
        sa.Column("file", sa.String(length=1024), nullable=False),
        sa.Column("line", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("risk", sa.String(length=32), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("sinks", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("call_path", sa.String(length=1024), nullable=True),
        sa.Column("input_sources", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("rank", sa.Integer(), nullable=False, server_default="0"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_recon_targets_scan_id", "recon_targets", ["scan_id"])

    op.create_table(
        "static_findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("rule", sa.String(length=512), nullable=False),
        sa.Column("file", sa.String(length=1024), nullable=False),
        sa.Column("line", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("code_snippet", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_static_findings_scan_id", "static_findings", ["scan_id"])


def downgrade() -> None:
    op.drop_index("ix_static_findings_scan_id", table_name="static_findings")
    op.drop_table("static_findings")
    op.drop_index("ix_recon_targets_scan_id", table_name="recon_targets")
    op.drop_table("recon_targets")
