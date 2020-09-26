"""initialise database

Revision ID: 21c058faa1d9
Revises:
Create Date: 2020-09-23 21:59:12.160103

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '21c058faa1d9'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "scan",
        sa.Column("id", sa.Integer,
                  primary_key=True,
                  nullable=False,
                  autoincrement=True),
        sa.Column("domain", sa.types.VARCHAR(1023),
                  nullable=False),
        sa.Column("protocol", sa.Unicode(32),
                  nullable=False),
        sa.Column("created_at", sa.DateTime(),
                  nullable=False),
        sa.Column("state", sa.Unicode(32),
                  nullable=False),
        sa.Column("certificate_score", sa.Integer(),
                  nullable=True),
        sa.Column("kex_score", sa.Integer(),
                  nullable=True),
        sa.Column("protocol_score", sa.Integer(),
                  nullable=True),
        sa.Column("cipher_score", sa.Integer(),
                  nullable=True),
    )

    op.create_table(
        "srv_record",
        sa.Column("id", sa.Integer,
                  primary_key=True,
                  nullable=False,
                  autoincrement=True),
        sa.Column("scan_id", sa.Integer,
                  sa.ForeignKey("scan.id",
                                ondelete="CASCADE",
                                onupdate="CASCADE"),
                  nullable=False),
        sa.Column("service", sa.Unicode(63),
                  nullable=False),
        sa.Column("protocol", sa.Unicode(63),
                  nullable=False),
        sa.Column("port", sa.Integer(),
                  nullable=False),
        sa.Column("host", sa.types.VARCHAR(255),
                  nullable=False),
        sa.Column("priority", sa.Integer(),
                  nullable=False),
        sa.Column("weight", sa.Integer(),
                  nullable=False),
    )

    op.create_table(
        "sasl_mechanism_offering",
        sa.Column("id", sa.Integer,
                  primary_key=True,
                  nullable=False,
                  autoincrement=True),
        sa.Column("scan_id", sa.Integer,
                  sa.ForeignKey("scan.id",
                                ondelete="CASCADE",
                                onupdate="CASCADE"),
                  nullable=False),
        sa.Column("phase", sa.Unicode(32),
                  nullable=False),
        sa.Column("mechanism", sa.Unicode(20),
                  nullable=False),
    )

    op.create_table(
        "pending_scan_task",
        sa.Column("id", sa.Integer,
                  primary_key=True,
                  nullable=False,
                  autoincrement=True),
        sa.Column("scan_id", sa.Integer,
                  sa.ForeignKey("scan.id",
                                ondelete="CASCADE",
                                onupdate="CASCADE"),
                  nullable=False),
        sa.Column("type", sa.Unicode(32),
                  nullable=False),
        sa.Column("parameters", sa.types.VARCHAR(2047),
                  nullable=False),
    )

    op.create_index(
        "scan_ix_recent",
        "scan",
        [
            "domain",
            "created_at",
        ]
    )


def downgrade():
    op.drop_table("pending_scan_task")
    op.drop_table("sasl_mechanism_offering")
    op.drop_table("srv_record")
    op.drop_table("scan")
