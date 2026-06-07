"""cache Zoho contact/invoice data + resident list category

Revision ID: e7c1a2b3d4f5
Revises: d4e8a1c0f2b3
Create Date: 2026-06-07 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = 'e7c1a2b3d4f5'
down_revision: Union[str, None] = 'd4e8a1c0f2b3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


list_category_enum = postgresql.ENUM('WHITE', 'YELLOW', 'RED', name='listcategory')


def upgrade() -> None:
    bind = op.get_bind()
    list_category_enum.create(bind, checkfirst=True)

    # Cached Zoho contact fields on residents.
    op.add_column('residents', sa.Column('zoho_contact_id', sa.String(), nullable=True))
    op.add_column('residents', sa.Column(
        'list_category', list_category_enum, nullable=False, server_default='WHITE'))
    op.add_column('residents', sa.Column('on_payment_plan', sa.String(), nullable=True))
    op.add_column('residents', sa.Column(
        'outstanding_balance', sa.Float(), nullable=False, server_default='0'))
    op.add_column('residents', sa.Column('customer_status', sa.String(), nullable=True))
    op.add_column('residents', sa.Column('street_name', sa.String(), nullable=True))
    op.add_column('residents', sa.Column('zoho_synced_at', sa.Integer(), nullable=True))
    op.create_index(op.f('ix_residents_zoho_contact_id'), 'residents', ['zoho_contact_id'])

    # Cached invoices table.
    op.create_table(
        'cached_invoices',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('resident_id', sa.UUID(), nullable=True),
        sa.Column('invoice_id', sa.String(), nullable=True),
        sa.Column('invoice_number', sa.String(), nullable=True),
        sa.Column('status', sa.String(), nullable=True),
        sa.Column('total', sa.Float(), nullable=False, server_default='0'),
        sa.Column('balance', sa.Float(), nullable=False, server_default='0'),
        sa.Column('due_date', sa.String(), nullable=True),
        sa.Column('date', sa.String(), nullable=True),
        sa.Column('last_payment_date', sa.String(), nullable=True),
        sa.Column('currency_code', sa.String(), nullable=True),
        sa.Column('company_name', sa.String(), nullable=True),
        sa.Column('invoice_url', sa.String(), nullable=True),
        sa.Column('synced_at', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['resident_id'], ['residents.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_cached_invoices_id'), 'cached_invoices', ['id'])
    op.create_index(op.f('ix_cached_invoices_resident_id'), 'cached_invoices', ['resident_id'])
    op.create_index(op.f('ix_cached_invoices_invoice_id'), 'cached_invoices', ['invoice_id'])


def downgrade() -> None:
    op.drop_index(op.f('ix_cached_invoices_invoice_id'), table_name='cached_invoices')
    op.drop_index(op.f('ix_cached_invoices_resident_id'), table_name='cached_invoices')
    op.drop_index(op.f('ix_cached_invoices_id'), table_name='cached_invoices')
    op.drop_table('cached_invoices')
    op.drop_index(op.f('ix_residents_zoho_contact_id'), table_name='residents')
    for col in ('zoho_synced_at', 'street_name', 'customer_status', 'outstanding_balance',
                'on_payment_plan', 'list_category', 'zoho_contact_id'):
        op.drop_column('residents', col)
    list_category_enum.drop(op.get_bind(), checkfirst=True)
