"""gates + gate_open_events (security-app gate opening)

Revision ID: f1a2b3c4d5e6
Revises: e4f5a6b7c8d9
Create Date: 2026-06-26 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'f1a2b3c4d5e6'
down_revision: Union[str, None] = 'e4f5a6b7c8d9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    gate_driver = sa.Enum('MANUAL', 'HTTP', 'GSM', name='gatedriver')

    op.create_table(
        'gates',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('location', sa.String(), nullable=True),
        sa.Column('driver', gate_driver, nullable=False),
        sa.Column('config', sa.String(), nullable=True),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('created_at', sa.Integer(), nullable=False),
        sa.Column('updated_at', sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_gates_id'), 'gates', ['id'], unique=False)

    op.create_table(
        'gate_open_events',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('gate_id', sa.UUID(), nullable=True),
        sa.Column('opened_by', sa.UUID(), nullable=True),
        sa.Column('visitor_id', sa.UUID(), nullable=True),
        sa.Column('entry_id', sa.UUID(), nullable=True),
        sa.Column('reason', sa.String(), nullable=True),
        sa.Column('source', sa.String(), nullable=False),
        sa.Column('success', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('detail', sa.String(), nullable=True),
        sa.Column('created_at', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['gate_id'], ['gates.id'], ),
        sa.ForeignKeyConstraint(['opened_by'], ['users.id'], ),
        sa.ForeignKeyConstraint(['visitor_id'], ['visitors.id'], ),
        sa.ForeignKeyConstraint(['entry_id'], ['gate_entries.id'], ),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_gate_open_events_id'), 'gate_open_events', ['id'], unique=False)
    op.create_index(op.f('ix_gate_open_events_gate_id'), 'gate_open_events', ['gate_id'], unique=False)
    op.create_index(op.f('ix_gate_open_events_created_at'), 'gate_open_events', ['created_at'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_gate_open_events_created_at'), table_name='gate_open_events')
    op.drop_index(op.f('ix_gate_open_events_gate_id'), table_name='gate_open_events')
    op.drop_index(op.f('ix_gate_open_events_id'), table_name='gate_open_events')
    op.drop_table('gate_open_events')
    op.drop_index(op.f('ix_gates_id'), table_name='gates')
    op.drop_table('gates')
    sa.Enum(name='gatedriver').drop(op.get_bind(), checkfirst=True)
