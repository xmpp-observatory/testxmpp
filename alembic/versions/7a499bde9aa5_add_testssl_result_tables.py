"""add testssl result tables

Revision ID: 7a499bde9aa5
Revises: 254a561f004b
Create Date: 2020-09-26 13:49:05.418377

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '7a499bde9aa5'
down_revision = '254a561f004b'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "tls_offering",
        sa.Column("scan_id", sa.Integer,
                  sa.ForeignKey("scan.id",
                                ondelete="CASCADE", onupdate="CASCADE"),
                  primary_key=True,
                  nullable=False),
        sa.Column("sslv2", sa.Boolean(),
                  nullable=True),
        sa.Column("sslv3", sa.Boolean(),
                  nullable=True),
        sa.Column("tlsv1", sa.Boolean(),
                  nullable=True),
        sa.Column("tlsv1_1", sa.Boolean(),
                  nullable=True),
        sa.Column("tlsv1_2", sa.Boolean(),
                  nullable=True),
        sa.Column("tlsv1_3", sa.Boolean(),
                  nullable=True),
        sa.Column("server_cipher_order", sa.Boolean(),
                  nullable=True),
    )

    op.create_table(
        "certificate",
        sa.Column("scan_id", sa.Integer(),
                  sa.ForeignKey("scan.id",
                                ondelete="CASCADE", onupdate="CASCADE"),
                  primary_key=True,
                  nullable=False),
        sa.Column("leaf_certificate",
                  sa.types.VARCHAR(4095),
                  nullable=True),
        sa.Column("certificate_chain",
                  sa.types.VARCHAR(8191),
                  nullable=True),
    )

    op.create_table(
        "cipher_metadata",
        sa.Column("id", sa.Integer(),
                  primary_key=True,
                  nullable=False),
        sa.Column("openssl_name",
                  sa.Unicode(255),
                  nullable=True),
        sa.Column("iana_name",
                  sa.Unicode(255),
                  nullable=True),
    )

    op.create_table(
        "cipher_offering",
        sa.Column("scan_id", sa.Integer(),
                  sa.ForeignKey("scan.id",
                                ondelete="CASCADE", onupdate="CASCADE"),
                  primary_key=True,
                  nullable=False),
        sa.Column("cipher_id", sa.Integer(),
                  sa.ForeignKey("cipher_metadata.id",
                                onupdate="CASCADE"),
                  primary_key=True,
                  nullable=False),
        sa.Column("key_exchange_info",
                  sa.Unicode(127),
                  nullable=True),
    )

    op.create_table(
        "cipher_offering_order",
        sa.Column(
            "scan_id",
            sa.Integer(),
            primary_key=True,
            nullable=False,
        ),
        sa.Column(
            "cipher_id",
            sa.Integer(),
            primary_key=True,
            nullable=False,
        ),
        sa.Column(
            "tls_version",
            sa.Unicode(32),
            primary_key=True,
            nullable=False,
        ),
        sa.Column(
            "order",
            sa.Integer(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["scan_id", "cipher_id"],
            ["cipher_offering.scan_id", "cipher_offering.cipher_id"]
        ),
    )
    op.create_index(
        "cipher_offering_order_ix_scan_id",
        "cipher_offering_order",
        ["scan_id"],
    )
    op.create_index(
        "cipher_offering_order_ix_scan_cipher_id",
        "cipher_offering_order",
        ["scan_id", "cipher_id"],
    )


def downgrade():
    op.drop_index("cipher_offering_order_ix_scan_cipher_id")
    op.drop_index("cipher_offering_order_ix_scan_id")
    op.drop_table("cipher_offering_order")

    op.drop_table("cipher_offering")
    op.drop_table("certificate")
    op.drop_table("tls_offering")
