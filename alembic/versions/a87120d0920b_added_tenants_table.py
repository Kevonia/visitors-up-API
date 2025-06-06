"""Added tenants table

Revision ID: a87120d0920b
Revises: 60ff84fac7da
Create Date: 2025-06-06 22:25:41.378655

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a87120d0920b'
down_revision: Union[str, None] = '60ff84fac7da'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('tenants',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('name', sa.String(), nullable=False),
    sa.Column('email', sa.String(), nullable=True),
    sa.Column('phone_number', sa.String(), nullable=True),
    sa.Column('number_of_children', sa.Integer(), nullable=True),
    sa.Column('resident_id', sa.UUID(), nullable=True),
    sa.ForeignKeyConstraint(['resident_id'], ['residents.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_tenants_email'), 'tenants', ['email'], unique=True)
    op.create_index(op.f('ix_tenants_id'), 'tenants', ['id'], unique=False)
    op.create_index(op.f('ix_tenants_phone_number'), 'tenants', ['phone_number'], unique=True)
    # ### end Alembic commands ###


def downgrade() -> None:
    """Downgrade schema."""
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(op.f('ix_tenants_phone_number'), table_name='tenants')
    op.drop_index(op.f('ix_tenants_id'), table_name='tenants')
    op.drop_index(op.f('ix_tenants_email'), table_name='tenants')
    op.drop_table('tenants')
    # ### end Alembic commands ###
