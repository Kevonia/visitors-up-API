"""incidents table + visitor recurring schedule & share token

Adds the SOS/incident table, recurring-schedule columns and a pre-registration
share token to visitors. See app/models.py (Incident, Visitor).

Revision ID: d3e4f5a6b7c8
Revises: c2d3e4f5a6b7
Create Date: 2026-06-21 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'd3e4f5a6b7c8'
down_revision: Union[str, None] = 'c2d3e4f5a6b7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Visitor: recurring schedule + pre-registration share link.
    op.add_column('visitors', sa.Column('schedule_days', sa.String(), nullable=True))
    op.add_column('visitors', sa.Column('schedule_start', sa.Integer(), nullable=True))
    op.add_column('visitors', sa.Column('schedule_end', sa.Integer(), nullable=True))
    op.add_column('visitors', sa.Column('share_token', sa.String(), nullable=True))
    op.create_index(op.f('ix_visitors_share_token'), 'visitors', ['share_token'], unique=True)

    op.create_table(
        'incidents',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('reported_by', sa.UUID(), nullable=True),
        sa.Column('reporter_role', sa.String(), nullable=True),
        sa.Column('reporter_name', sa.String(), nullable=True),
        sa.Column('lot_no', sa.String(), nullable=True),
        sa.Column('kind', sa.String(), nullable=False),
        sa.Column('status', sa.String(), nullable=False),
        sa.Column('note', sa.String(), nullable=True),
        sa.Column('latitude', sa.Float(), nullable=True),
        sa.Column('longitude', sa.Float(), nullable=True),
        sa.Column('acknowledged_by', sa.UUID(), nullable=True),
        sa.Column('acknowledged_at', sa.Integer(), nullable=True),
        sa.Column('resolved_by', sa.UUID(), nullable=True),
        sa.Column('resolved_at', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['reported_by'], ['users.id'], ),
        sa.ForeignKeyConstraint(['acknowledged_by'], ['users.id'], ),
        sa.ForeignKeyConstraint(['resolved_by'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_incidents_id'), 'incidents', ['id'], unique=False)
    op.create_index(op.f('ix_incidents_reported_by'), 'incidents', ['reported_by'], unique=False)
    op.create_index(op.f('ix_incidents_status'), 'incidents', ['status'], unique=False)
    op.create_index(op.f('ix_incidents_created_at'), 'incidents', ['created_at'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_incidents_created_at'), table_name='incidents')
    op.drop_index(op.f('ix_incidents_status'), table_name='incidents')
    op.drop_index(op.f('ix_incidents_reported_by'), table_name='incidents')
    op.drop_index(op.f('ix_incidents_id'), table_name='incidents')
    op.drop_table('incidents')
    op.drop_index(op.f('ix_visitors_share_token'), table_name='visitors')
    op.drop_column('visitors', 'share_token')
    op.drop_column('visitors', 'schedule_end')
    op.drop_column('visitors', 'schedule_start')
    op.drop_column('visitors', 'schedule_days')
