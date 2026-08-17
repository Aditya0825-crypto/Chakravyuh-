"""Initial scans and pipeline_events tables.

Revision ID: 001_initial
Revises:
Create Date: 2026-08-17
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "scans",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("target_name", sa.String(length=512), nullable=False),
        sa.Column("status", sa.String(length=64), nullable=False),
        sa.Column("current_stage", sa.String(length=64), nullable=True),
        sa.Column("artifact_root", sa.String(length=1024), nullable=True),
        sa.Column("languages", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("file_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_sec", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "pipeline_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("stage", sa.String(length=64), nullable=True),
        sa.Column("level", sa.String(length=16), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_pipeline_events_scan_id", "pipeline_events", ["scan_id"])


def downgrade() -> None:
    op.drop_index("ix_pipeline_events_scan_id", table_name="pipeline_events")
    op.drop_table("pipeline_events")
    op.drop_table("scans")
