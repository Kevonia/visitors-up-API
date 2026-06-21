"""maintenance_requests table (resident "Report Issue")

Revision ID: e4f5a6b7c8d9
Revises: d3e4f5a6b7c8
Create Date: 2026-06-21 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'e4f5a6b7c8d9'
down_revision: Union[str, None] = 'd3e4f5a6b7c8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'maintenance_requests',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('resident_id', sa.UUID(), nullable=True),
        sa.Column('reporter_user_id', sa.UUID(), nullable=True),
        sa.Column('lot_no', sa.String(), nullable=True),
        sa.Column('category', sa.String(), nullable=False),
        sa.Column('title', sa.String(), nullable=False),
        sa.Column('description', sa.String(), nullable=True),
        sa.Column('priority', sa.String(), nullable=False),
        sa.Column('status', sa.String(), nullable=False),
        sa.Column('created_at', sa.Integer(), nullable=False),
        sa.Column('updated_at', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['resident_id'], ['residents.id'], ),
        sa.ForeignKeyConstraint(['reporter_user_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_maintenance_requests_id'), 'maintenance_requests', ['id'], unique=False)
    op.create_index(op.f('ix_maintenance_requests_resident_id'), 'maintenance_requests', ['resident_id'], unique=False)
    op.create_index(op.f('ix_maintenance_requests_status'), 'maintenance_requests', ['status'], unique=False)
    op.create_index(op.f('ix_maintenance_requests_created_at'), 'maintenance_requests', ['created_at'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_maintenance_requests_created_at'), table_name='maintenance_requests')
    op.drop_index(op.f('ix_maintenance_requests_status'), table_name='maintenance_requests')
    op.drop_index(op.f('ix_maintenance_requests_resident_id'), table_name='maintenance_requests')
    op.drop_index(op.f('ix_maintenance_requests_id'), table_name='maintenance_requests')
    op.drop_table('maintenance_requests')
