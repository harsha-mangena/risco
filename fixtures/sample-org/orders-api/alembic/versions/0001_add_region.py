"""add region to orders"""

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column("orders", sa.Column("region", sa.String(length=16), nullable=True))


def downgrade():
    op.drop_column("orders", "region")
