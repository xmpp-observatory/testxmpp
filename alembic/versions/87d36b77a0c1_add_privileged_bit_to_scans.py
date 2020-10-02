"""add privileged bit to scans

Revision ID: 87d36b77a0c1
Revises: 7a499bde9aa5
Create Date: 2020-10-02 16:30:57.279412

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '87d36b77a0c1'
down_revision = '7a499bde9aa5'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("scan") as batch_op:
        batch_op.add_column(
            sa.Column(
                "privileged",
                sa.Boolean(),
                nullable=False,
                default=False,
            )
        )


def downgrade():
    with op.batch_alter_table("scan") as batch_op:
        batch_op.drop_column("privileged")
