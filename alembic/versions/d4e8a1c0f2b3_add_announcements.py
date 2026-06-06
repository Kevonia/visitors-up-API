"""add announcements table

Revision ID: d4e8a1c0f2b3
Revises: c7f1a9d4e210
Create Date: 2026-06-06 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd4e8a1c0f2b3'
down_revision: Union[str, None] = 'c7f1a9d4e210'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'announcements',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('title', sa.String(), nullable=False),
        sa.Column('body', sa.String(), nullable=False),
        sa.Column('category', sa.String(), nullable=False, server_default='info'),
        sa.Column('published_at', sa.Integer(), nullable=True),
        sa.Column('expires_at', sa.Integer(), nullable=True),
        sa.Column('created_by', sa.UUID(), nullable=True),
        sa.Column('created_at', sa.Integer(), nullable=False),
        sa.Column('updated_at', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['created_by'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_announcements_id'), 'announcements', ['id'], unique=False)
    op.create_index(op.f('ix_announcements_title'), 'announcements', ['title'], unique=False)
    op.create_index(op.f('ix_announcements_published_at'), 'announcements', ['published_at'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_announcements_published_at'), table_name='announcements')
    op.drop_index(op.f('ix_announcements_title'), table_name='announcements')
    op.drop_index(op.f('ix_announcements_id'), table_name='announcements')
    op.drop_table('announcements')
