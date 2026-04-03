"""baseline schema

Revision ID: 20260402_0001
Revises:
Create Date: 2026-04-02 22:40:00
"""
from __future__ import annotations

from alembic import op


revision = "20260402_0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Baseline revision. Existing environments can stamp this revision and
    # continue with explicit migrations instead of bootstrap ALTER TABLE logic.
    pass


def downgrade() -> None:
    pass
