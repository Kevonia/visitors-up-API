"""visitor lifecycle fields and gate entry log

Revision ID: c7f1a9d4e210
Revises: a133249af276
Create Date: 2026-05-31 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = 'c7f1a9d4e210'
down_revision: Union[str, None] = 'a133249af276'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


visit_type_enum = postgresql.ENUM('ONE_TIME', 'PERMANENT', name='visittype')
visitor_status_enum = postgresql.ENUM('ACTIVE', 'USED', 'EXPIRED', 'REVOKED', name='visitorstatus')


def upgrade() -> None:
    bind = op.get_bind()

    # Create enum types (idempotent)
    visit_type_enum.create(bind, checkfirst=True)
    visitor_status_enum.create(bind, checkfirst=True)

    # New visitor lifecycle columns. Server defaults backfill existing rows;
    # we keep them so inserts that omit the column stay valid.
    op.add_column('visitors', sa.Column(
        'visit_type', visit_type_enum, nullable=False, server_default='ONE_TIME'))
    op.add_column('visitors', sa.Column(
        'status', visitor_status_enum, nullable=False, server_default='ACTIVE'))
    op.add_column('visitors', sa.Column('valid_from', sa.Integer(), nullable=True))
    op.add_column('visitors', sa.Column('valid_until', sa.Integer(), nullable=True))
    op.add_column('visitors', sa.Column('phone', sa.String(), nullable=True))
    op.add_column('visitors', sa.Column('vehicle_plate', sa.String(), nullable=True))

    # Gate entry / exit audit log
    op.create_table(
        'gate_entries',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('visitor_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('visitors.id'), nullable=True),
        sa.Column('resident_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('residents.id'), nullable=True),
        sa.Column('lot_no', sa.String(), nullable=True),
        sa.Column('logged_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('entry_time', sa.Integer(), nullable=False),
        sa.Column('exit_time', sa.Integer(), nullable=True),
        sa.Column('notes', sa.String(), nullable=True),
    )
    op.create_index('ix_gate_entries_id', 'gate_entries', ['id'])
    op.create_index('ix_gate_entries_visitor_id', 'gate_entries', ['visitor_id'])
    op.create_index('ix_gate_entries_resident_id', 'gate_entries', ['resident_id'])
    op.create_index('ix_gate_entries_entry_time', 'gate_entries', ['entry_time'])


def downgrade() -> None:
    op.drop_index('ix_gate_entries_entry_time', table_name='gate_entries')
    op.drop_index('ix_gate_entries_resident_id', table_name='gate_entries')
    op.drop_index('ix_gate_entries_visitor_id', table_name='gate_entries')
    op.drop_index('ix_gate_entries_id', table_name='gate_entries')
    op.drop_table('gate_entries')

    op.drop_column('visitors', 'vehicle_plate')
    op.drop_column('visitors', 'phone')
    op.drop_column('visitors', 'valid_until')
    op.drop_column('visitors', 'valid_from')
    op.drop_column('visitors', 'status')
    op.drop_column('visitors', 'visit_type')

    bind = op.get_bind()
    visitor_status_enum.drop(bind, checkfirst=True)
    visit_type_enum.drop(bind, checkfirst=True)
