"""add primary host/port to scan

Revision ID: b97f82607fd2
Revises: 21c058faa1d9
Create Date: 2020-09-23 22:19:26.161696

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b97f82607fd2'
down_revision = '21c058faa1d9'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("scan") as batch_op:
        batch_op.add_column(
            sa.Column(
                "primary_host",
                sa.types.VARCHAR(255),
                nullable=True,
            )
        )
        batch_op.add_column(
            sa.Column(
                "primary_port",
                sa.Integer(),
                nullable=True,
            )
        )


def downgrade():
    with op.batch_alter_table("scan") as batch_op:
        batch_op.drop_column("primary_host")
        batch_op.drop_column("primary_port")
