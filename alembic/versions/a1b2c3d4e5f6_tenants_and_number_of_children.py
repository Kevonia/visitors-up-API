"""add tenants table and residents.number_of_children (ported from legacy master)

Re-parents the two legacy migrations (60ff84fac7da number_of_children,
a87120d0920b tenants) onto the revamp's alembic head so the schema applies
linearly on top of the maintained line.

Revision ID: a1b2c3d4e5f6
Revises: f8b2c3d4e5a6
Create Date: 2026-06-16 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, None] = 'f8b2c3d4e5a6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('residents', sa.Column('number_of_children', sa.Integer(), nullable=True))
    op.create_table(
        'tenants',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('email', sa.String(), nullable=True),
        sa.Column('phone_number', sa.String(), nullable=True),
        sa.Column('number_of_children', sa.Integer(), nullable=True),
        sa.Column('resident_id', sa.UUID(), nullable=True),
        sa.Column('created_at', sa.Integer(), nullable=False),
        sa.Column('updated_at', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['resident_id'], ['residents.id'], ),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tenants_email'), 'tenants', ['email'], unique=True)
    op.create_index(op.f('ix_tenants_id'), 'tenants', ['id'], unique=False)
    op.create_index(op.f('ix_tenants_phone_number'), 'tenants', ['phone_number'], unique=True)


def downgrade() -> None:
    op.drop_index(op.f('ix_tenants_phone_number'), table_name='tenants')
    op.drop_index(op.f('ix_tenants_id'), table_name='tenants')
    op.drop_index(op.f('ix_tenants_email'), table_name='tenants')
    op.drop_table('tenants')
    op.drop_column('residents', 'number_of_children')
