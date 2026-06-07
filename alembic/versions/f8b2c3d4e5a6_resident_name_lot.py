"""add resident.name and make lot_no non-unique

Revision ID: f8b2c3d4e5a6
Revises: e7c1a2b3d4f5
Create Date: 2026-06-07 01:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'f8b2c3d4e5a6'
down_revision: Union[str, None] = 'e7c1a2b3d4f5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('residents', sa.Column('name', sa.String(), nullable=True))
    # lot_no was unique; co-owners can share a lot, so drop the unique index
    # and recreate it as a plain index.
    op.drop_index('ix_residents_lot_no', table_name='residents')
    op.create_index('ix_residents_lot_no', 'residents', ['lot_no'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_residents_lot_no', table_name='residents')
    op.create_index('ix_residents_lot_no', 'residents', ['lot_no'], unique=True)
    op.drop_column('residents', 'name')
