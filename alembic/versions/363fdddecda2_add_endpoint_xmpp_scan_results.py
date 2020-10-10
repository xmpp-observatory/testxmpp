"""add endpoint xmpp scan results

Revision ID: 363fdddecda2
Revises: 87d36b77a0c1
Create Date: 2020-10-10 13:27:37.075602

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '363fdddecda2'
down_revision = '87d36b77a0c1'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "endpoint_scan_result",
        sa.Column(
            "id",
            sa.Integer(),
            primary_key=True,
            nullable=False,
            autoincrement=True,
        ),
        sa.Column(
            "scan_id",
            sa.Integer(),
            sa.ForeignKey("scan.id", ondelete="CASCADE", onupdate="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "hostname",
            sa.types.VARCHAR(255),
            nullable=False,
        ),
        sa.Column(
            "port",
            sa.Integer(),
            nullable=False,
        ),
        sa.Column(
            "tls_mode",
            sa.Unicode(32),
            nullable=False,
        ),
        sa.Column(
            "tls_offered",
            sa.Boolean(),
            nullable=False,
        ),
        sa.Column(
            "tls_negotiated",
            sa.Boolean(),
            nullable=False,
        ),
        sa.Column(
            "sasl_pre_tls",
            sa.Boolean(),
            nullable=False,
        ),
        sa.Column(
            "sasl_post_tls",
            sa.Boolean(),
            nullable=False,
        ),
        sa.Column(
            "errno",
            sa.Integer(),
            nullable=True,
        ),
        sa.Column(
            "error",
            sa.Unicode(1023),
            nullable=True,
        ),
    )
    op.create_index(
        "endpoint_scan_result_ix_unique",
        "endpoint_scan_result",
        ["scan_id", "hostname", "port"],
    )
    op.create_table(
        "sasl_mechanism",
        sa.Column(
            "id",
            sa.Integer(),
            primary_key=True,
            autoincrement=True,
            nullable=False,
        ),
        sa.Column(
            "name",
            sa.Unicode(20),
            nullable=False,
        )
    )
    op.create_index(
        "sasl_mechanism_ix_name",
        "sasl_mechanism",
        ["name"],
        unique=True,
    )
    op.create_table(
        "endpoint_scan_sasl_offering",
        sa.Column(
            "endpoint_scan_result_id",
            sa.Integer(),
            sa.ForeignKey("endpoint_scan_result.id",
                          ondelete="CASCADE",
                          onupdate="CASCADE"),
            nullable=False,
            primary_key=True,
        ),
        sa.Column(
            "sasl_mechanism_id",
            sa.Integer(),
            sa.ForeignKey("sasl_mechanism.id",
                          ondelete="CASCADE",
                          onupdate="CASCADE"),
            nullable=False,
            primary_key=True,
        ),
        sa.Column(
            "phase",
            sa.Unicode(32),
            nullable=False,
            primary_key=True,
        )
    )
    op.create_index(
        "endpoint_scan_sasl_offering_ix_scan_phase",
        "endpoint_scan_sasl_offering",
        ["endpoint_scan_result_id", "phase"],
    )
    op.create_index(
        "endpoint_scan_sasl_offering_ix_scan",
        "endpoint_scan_sasl_offering",
        ["endpoint_scan_result_id"],
    )
    op.create_index(
        "endpoint_scan_sasl_offering_ix_mechanism",
        "endpoint_scan_sasl_offering",
        ["sasl_mechanism_id"],
    )
    op.create_index(
        "endpoint_scan_sasl_offering_ix_mechanism_phase",
        "endpoint_scan_sasl_offering",
        ["sasl_mechanism_id", "phase"],
    )


def downgrade():
    op.drop_index("endpoint_scan_sasl_offering_ix_mechanism_phase")
    op.drop_index("endpoint_scan_sasl_offering_ix_mechanism")
    op.drop_index("endpoint_scan_sasl_offering_ix_scan")
    op.drop_index("endpoint_scan_sasl_offering_ix_scan_phase")
    op.drop_table("endpoint_scan_sasl_offering")
    op.drop_index("sasl_mechanism_ix_name")
    op.drop_table("sasl_mechanism")
    op.drop_table("endpoint_scan_result")
