"""branding_config (white-label name/colors/logo)

Revision ID: c9d0e1f2a3b4
Revises: b8c9d0e1f2a3
Create Date: 2026-06-29 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'c9d0e1f2a3b4'
down_revision: Union[str, None] = 'b8c9d0e1f2a3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'branding_config',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('community_name', sa.String(), nullable=False, server_default='Twickenham Glades'),
        sa.Column('tagline', sa.String(), nullable=True),
        sa.Column('primary_color', sa.String(), nullable=False, server_default='#1e5631'),
        sa.Column('accent_color', sa.String(), nullable=False, server_default='#c9a227'),
        sa.Column('sidebar_color', sa.String(), nullable=False, server_default='#1e5631'),
        sa.Column('sidebar_text_color', sa.String(), nullable=False, server_default='#ffffff'),
        sa.Column('logo_data', sa.LargeBinary(), nullable=True),
        sa.Column('logo_content_type', sa.String(), nullable=True),
        sa.Column('created_at', sa.Integer(), nullable=False),
        sa.Column('updated_at', sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_branding_config_id'), 'branding_config', ['id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_branding_config_id'), table_name='branding_config')
    op.drop_table('branding_config')
