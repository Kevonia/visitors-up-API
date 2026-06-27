"""payments table (in-app dues payments via WiPay/DimePay)

Revision ID: a7b8c9d0e1f2
Revises: f1a2b3c4d5e6
Create Date: 2026-06-27 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'a7b8c9d0e1f2'
down_revision: Union[str, None] = 'f1a2b3c4d5e6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'payments',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('resident_id', sa.UUID(), nullable=False),
        sa.Column('invoice_id', sa.String(), nullable=True),
        sa.Column('invoice_number', sa.String(), nullable=True),
        sa.Column('amount', sa.Float(), nullable=False),
        sa.Column('currency', sa.String(), nullable=False, server_default='JMD'),
        sa.Column('status', sa.String(), nullable=False, server_default='PENDING'),
        sa.Column('provider', sa.String(), nullable=False),
        sa.Column('provider_ref', sa.String(), nullable=True),
        sa.Column('provider_status', sa.String(), nullable=True),
        sa.Column('platform_fee_pct', sa.Float(), nullable=False, server_default='0'),
        sa.Column('raw', sa.String(), nullable=True),
        sa.Column('created_at', sa.Integer(), nullable=False),
        sa.Column('updated_at', sa.Integer(), nullable=False),
        sa.Column('paid_at', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['resident_id'], ['residents.id'], ),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_payments_id'), 'payments', ['id'], unique=False)
    op.create_index(op.f('ix_payments_resident_id'), 'payments', ['resident_id'], unique=False)
    op.create_index(op.f('ix_payments_invoice_id'), 'payments', ['invoice_id'], unique=False)
    op.create_index(op.f('ix_payments_provider_ref'), 'payments', ['provider_ref'], unique=False)
    op.create_index(op.f('ix_payments_status'), 'payments', ['status'], unique=False)
    op.create_index(op.f('ix_payments_created_at'), 'payments', ['created_at'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_payments_created_at'), table_name='payments')
    op.drop_index(op.f('ix_payments_status'), table_name='payments')
    op.drop_index(op.f('ix_payments_provider_ref'), table_name='payments')
    op.drop_index(op.f('ix_payments_invoice_id'), table_name='payments')
    op.drop_index(op.f('ix_payments_resident_id'), table_name='payments')
    op.drop_index(op.f('ix_payments_id'), table_name='payments')
    op.drop_table('payments')
