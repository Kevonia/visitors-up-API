"""Fix relationship

Revision ID: 877364011d07
Revises: 9fac3b94cadf
Create Date: 2025-03-14 03:23:54.440800

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '877364011d07'
down_revision: Union[str, None] = '9fac3b94cadf'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint('residents_user_id_fkey', 'residents', type_='foreignkey')
    op.create_foreign_key(None, 'residents', 'users', ['user_id'], ['id'])
    # ### end Alembic commands ###


def downgrade() -> None:
    """Downgrade schema."""
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint(None, 'residents', type_='foreignkey')
    op.create_foreign_key('residents_user_id_fkey', 'residents', 'roles', ['user_id'], ['id'])
    # ### end Alembic commands ###
