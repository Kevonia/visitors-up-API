"""integration_tokens (QuickBooks OAuth — rotating refresh token)

Revision ID: b8c9d0e1f2a3
Revises: a7b8c9d0e1f2
Create Date: 2026-06-27 01:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'b8c9d0e1f2a3'
down_revision: Union[str, None] = 'a7b8c9d0e1f2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'integration_tokens',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('provider', sa.String(), nullable=False),
        sa.Column('refresh_token', sa.String(), nullable=True),
        sa.Column('realm_id', sa.String(), nullable=True),
        sa.Column('access_token', sa.String(), nullable=True),
        sa.Column('created_at', sa.Integer(), nullable=False),
        sa.Column('updated_at', sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_integration_tokens_id'), 'integration_tokens', ['id'], unique=False)
    op.create_index(op.f('ix_integration_tokens_provider'), 'integration_tokens', ['provider'], unique=True)


def downgrade() -> None:
    op.drop_index(op.f('ix_integration_tokens_provider'), table_name='integration_tokens')
    op.drop_index(op.f('ix_integration_tokens_id'), table_name='integration_tokens')
    op.drop_table('integration_tokens')
