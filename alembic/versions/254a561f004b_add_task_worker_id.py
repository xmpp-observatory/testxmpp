"""add task worker id

Revision ID: 254a561f004b
Revises: cc0d863459f7
Create Date: 2020-09-25 16:06:25.175108

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '254a561f004b'
down_revision = 'cc0d863459f7'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("pending_scan_task") as batch_op:
        batch_op.add_column(
            sa.Column(
                "assigned_worker",
                sa.Unicode(128),
                nullable=True,
            )
        )


def downgrade():
    with op.batch_alter_table("pending_scan_task") as batch_op:
        batch_op.drop_column("assigned_worker")
