"""Add crash_type column to verified_povs.

Revision ID: 006_verified_pov_crash_type
Revises: 005_reports
Create Date: 2026-08-18
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "006_verified_pov_crash_type"
down_revision: Union[str, None] = "005_report_gate"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "verified_povs",
        sa.Column("crash_type", sa.String(length=128), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("verified_povs", "crash_type")
