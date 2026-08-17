"""Add patch_candidates table.

Revision ID: 004_patches
Revises: 003_bugfinding
Create Date: 2026-08-17
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "004_patches"
down_revision: Union[str, None] = "003_bugfinding"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "patch_candidates",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("agent", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("strategy", sa.Text(), nullable=False),
        sa.Column("diff", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="REJECTED"),
        sa.Column("score_security", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("score_regression", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("score_performance", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("score_rediscovery", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("score_total", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("rejected_reason", sa.Text(), nullable=True),
        sa.Column("lines_changed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("files_changed", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("verification_passed", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("attacks_blocked", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("attacks_total", sa.Integer(), nullable=False, server_default="9"),
        sa.Column("regression_passed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("regression_total", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("performance_overhead", sa.String(length=32), nullable=False, server_default="0.0%"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_patch_candidates_scan_id", "patch_candidates", ["scan_id"])


def downgrade() -> None:
    op.drop_index("ix_patch_candidates_scan_id", table_name="patch_candidates")
    op.drop_table("patch_candidates")
