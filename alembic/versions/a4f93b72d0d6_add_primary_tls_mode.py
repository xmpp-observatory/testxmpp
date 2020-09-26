"""add primary tls mode

Revision ID: a4f93b72d0d6
Revises: b97f82607fd2
Create Date: 2020-09-25 15:44:39.347092

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a4f93b72d0d6'
down_revision = 'b97f82607fd2'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("scan") as batch_op:
        batch_op.add_column(
            sa.Column(
                "primary_tls_mode",
                sa.Unicode(32),
                nullable=True,
            )
        )


def downgrade():
    with op.batch_alter_table("scan") as batch_op:
        batch_op.drop_column("primary_tls_mode")
