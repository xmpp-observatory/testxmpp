"""add task heartbeat

Revision ID: cc0d863459f7
Revises: a4f93b72d0d6
Create Date: 2020-09-25 15:53:03.480751

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'cc0d863459f7'
down_revision = 'a4f93b72d0d6'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("pending_scan_task") as batch_op:
        batch_op.add_column(
            sa.Column(
                "heartbeat",
                sa.DateTime(),
                nullable=True,
            )
        )


def downgrade():
    with op.batch_alter_table("pending_scan_task") as batch_op:
        batch_op.drop_column("heartbeat")
