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
    # GLOBAL DATA
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
    op.create_index(
        "cipher_metadata_ix_openssl_name",
        "cipher_metadata",
        ["openssl_name"],
        unique=True,
    )
    op.create_index(
        "cipher_metadata_ix_iana_name",
        "cipher_metadata",
        ["iana_name"],
        unique=True,
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
        "san_type",
        sa.Column("id", sa.Integer,
                  primary_key=True,
                  nullable=False,
                  autoincrement=True),
        sa.Column("asn1_name", sa.Unicode(128),
                  nullable=False),
    )
    op.create_index(
        "san_type_ix_asn1_name",
        "san_type",
        ["asn1_name"],
        unique=True,
    )

    # PER-SCAN DATA

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
        sa.Column("privileged", sa.Boolean(),
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
        "xmppconnect_record",
        sa.Column("id", sa.Integer,
                  primary_key=True,
                  nullable=False,
                  autoincrement=True),
        sa.Column("scan_id", sa.Integer,
                  sa.ForeignKey("scan.id",
                                ondelete="CASCADE",
                                onupdate="CASCADE"),
                  nullable=False),
        sa.Column("attribute_name", sa.types.VARBINARY(1023),
                  nullable=False),
        sa.Column("attribute_value", sa.types.VARBINARY(1023),
                  nullable=False),
    )

    op.create_table(
        "host_meta_object",
        sa.Column("id", sa.Integer,
                  primary_key=True,
                  nullable=False,
                  autoincrement=True),
        sa.Column("scan_id", sa.Integer,
                  sa.ForeignKey("scan.id",
                                ondelete="CASCADE",
                                onupdate="CASCADE"),
                  nullable=False),
        sa.Column("url", sa.Unicode(1023),
                  nullable=False),
        sa.Column("format", sa.Unicode(32),
                  nullable=False),
    )

    op.create_table(
        "host_meta_link",
        sa.Column("id", sa.Integer,
                  primary_key=True,
                  nullable=False,
                  autoincrement=True),
        sa.Column("object_id", sa.Integer,
                  sa.ForeignKey("host_meta_object.id",
                                ondelete="CASCADE",
                                onupdate="CASCADE"),
                  nullable=False),
        sa.Column("rel", sa.Unicode(1023),
                  nullable=False),
        sa.Column("href", sa.Unicode(32),
                  nullable=False),
    )

    op.create_table(
        "endpoint",
        sa.Column("id", sa.Integer(),
                  primary_key=True, autoincrement=True, nullable=False),
        sa.Column("scan_id", sa.Integer(),
                  sa.ForeignKey("scan.id",
                                ondelete="CASCADE", onupdate="CASCADE"),
                  nullable=False),
        sa.Column("transport", sa.Unicode(32),
                  nullable=False),
        sa.Column("srv_record_id", sa.Integer(),
                  sa.ForeignKey("srv_record.id",
                                ondelete="SET NULL", onupdate="CASCADE")),
        sa.Column("host_meta_link_id", sa.Integer(),
                  sa.ForeignKey("host_meta_link.id",
                                ondelete="SET NULL", onupdate="CASCADE")),
        sa.Column("xmppconnect_record_id", sa.Integer(),
                  sa.ForeignKey("xmppconnect_record.id",
                                ondelete="SET NULL", onupdate="CASCADE")),
    )

    op.create_table(
        "endpoint_tcp",
        sa.Column("endpoint_id", sa.Integer(),
                  sa.ForeignKey("endpoint.id",
                                ondelete="CASCADE", onupdate="CASCADE"),
                  primary_key=True, nullable=False),
        sa.Column("tls_mode", sa.Unicode(32),
                  nullable=False),
        sa.Column("hostname", sa.types.VARBINARY(255),
                  nullable=False),
        sa.Column("port", sa.Integer(),
                  nullable=False),
    )

    op.create_table(
        "endpoint_http",
        sa.Column("endpoint_id", sa.Integer(),
                  sa.ForeignKey("endpoint.id",
                                ondelete="CASCADE", onupdate="CASCADE"),
                  primary_key=True, nullable=False),
        sa.Column("url", sa.Unicode(1023),
                  nullable=False),
        sa.Column("http_mode", sa.Unicode(32),
                  nullable=False),
    )

    op.create_table(
        "tls_offering",
        sa.Column("endpoint_id", sa.Integer,
                  sa.ForeignKey("endpoint.id",
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
        sa.Column("id", sa.Integer,
                  primary_key=True,
                  nullable=False,
                  autoincrement=True),
        sa.Column("fp_sha1", sa.types.VARBINARY(20),
                  nullable=False),
        sa.Column("fp_sha256", sa.types.VARBINARY(32),
                  nullable=False),
        sa.Column("fp_sha512", sa.types.VARBINARY(64),
                  nullable=False),
        sa.Column("raw_der", sa.types.VARBINARY(8192),
                  nullable=False),
        sa.Column("not_before", sa.DateTime(),
                  nullable=False),
        sa.Column("not_after", sa.DateTime(),
                  nullable=False),
        sa.Column("public_key", sa.types.VARBINARY(2048),
                  nullable=False),
        sa.Column("public_key_type", sa.Unicode(128),
                  nullable=False),
        sa.Column("subject", sa.Unicode(1024),
                  nullable=False),
        sa.Column("issuer", sa.Unicode(1024),
                  nullable=False),
    )
    op.create_index(
        "certificate_ix_fingerprint_sha1",
        "certificate",
        ["fp_sha1"],
    )
    op.create_index(
        "certificate_ix_fingerprint_sha256",
        "certificate",
        ["fp_sha256"],
    )
    op.create_index(
        "certificate_ix_fingerprint_sha512",
        "certificate",
        ["fp_sha512"],
    )
    op.create_index(
        "certificate_ix_fp_sha1_2",
        "certificate",
        ["fp_sha1", "fp_sha256", "fp_sha512"],
    )

    op.create_table(
        "san",
        sa.Column("id", sa.Integer(),
                  primary_key=True,
                  nullable=False,
                  autoincrement=True),
        sa.Column("certificate_id",  sa.Integer,
                  sa.ForeignKey("certificate.id",
                                ondelete="CASCADE", onupdate="CASCADE"),
                  nullable=False),
        sa.Column("type_id", sa.Integer,
                  sa.ForeignKey("san_type.id",
                                ondelete="RESTRICT", onupdate="CASCADE"),
                  nullable=False),
        sa.Column("value", sa.Unicode(256),
                  nullable=False),
    )
    op.create_index(
        "san_ix_certificate_san_type",
        "san",
        ["certificate_id", "type_id"],
    )

    op.create_table(
        "certificate_offering",
        sa.Column("endpoint_id", sa.Integer(),
                  sa.ForeignKey("endpoint.id",
                                ondelete="CASCADE", onupdate="CASCADE"),
                  primary_key=True,
                  nullable=False),
        sa.Column("chain_index", sa.Integer(),
                  primary_key=True,
                  nullable=False),
        sa.Column("certificate_id", sa.Integer(),
                  sa.ForeignKey("certificate.id",
                                ondelete="CASCADE", onupdate="CASCADE"),
                  primary_key=False,
                  nullable=False),
    )
    op.create_index(
        "certificate_offering_ix_endpoint_id",
        "certificate_offering",
        ["endpoint_id"],
    )

    op.create_table(
        "cipher_offering",
        sa.Column("endpoint_id", sa.Integer(),
                  sa.ForeignKey("endpoint.id",
                                ondelete="CASCADE", onupdate="CASCADE"),
                  primary_key=True,
                  nullable=False),
        sa.Column("cipher_id", sa.Integer(),
                  sa.ForeignKey("cipher_metadata.id",
                                ondelete="RESTRICT", onupdate="CASCADE"),
                  primary_key=True,
                  nullable=False),
        sa.Column("key_exchange_info",
                  sa.Unicode(127),
                  nullable=True),
    )

    op.create_table(
        "cipher_offering_order",
        sa.Column(
            "endpoint_id",
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
            ["endpoint_id", "cipher_id"],
            ["cipher_offering.endpoint_id", "cipher_offering.cipher_id"]
        ),
    )
    op.create_index(
        "cipher_offering_order_ix_endpoint_id",
        "cipher_offering_order",
        ["endpoint_id"],
    )
    op.create_index(
        "cipher_offering_order_ix_endpoint_cipher_id",
        "cipher_offering_order",
        ["endpoint_id", "cipher_id"],
    )

    op.create_table(
        "scan_task",
        sa.Column("id", sa.types.BINARY(16),
                  primary_key=True, nullable=False),
        sa.Column("scan_id", sa.Integer(),
                  sa.ForeignKey("scan.id",
                                ondelete="CASCADE", onupdate="CASCADE"),
                  nullable=False),
        sa.Column("type", sa.Unicode(32),
                  nullable=False),
        sa.Column("state", sa.Unicode(32),
                  nullable=False),
        sa.Column("fail_reason", sa.Unicode(32),
                  nullable=True),
        sa.Column("endpoint_id", sa.Integer(),
                  sa.ForeignKey("endpoint.id",
                                ondelete="CASCADE", onupdate="CASCADE"),
                  nullable=True),
        sa.Column("heartbeat", sa.DateTime(),
                  nullable=True),
        sa.Column("assigned_worker", sa.types.BINARY(16),
                  nullable=True),
    )

    op.create_table(
        "scan_task_dependency",
        sa.Column("parent_task_id", sa.Integer(),
                  sa.ForeignKey("scan_task.id",
                                ondelete="CASCADE", onupdate="CASCADE"),
                  primary_key=True, nullable=False, autoincrement=False),
        sa.Column("child_task_id", sa.Integer(),
                  sa.ForeignKey("scan_task.id",
                                ondelete="CASCADE", onupdate="CASCADE"),
                  primary_key=True, nullable=False, autoincrement=False),
    )
    op.create_index(
        "scan_task_dependency_ix_parent",
        "scan_task_dependency",
        ["parent_task_id"]
    )
    op.create_index(
        "scan_task_dependency_ix_child",
        "scan_task_dependency",
        ["child_task_id"]
    )

    op.create_table(
        "endpoint_scan_result",
        sa.Column("endpoint_id", sa.Integer(),
                  sa.ForeignKey("endpoint.id",
                                ondelete="CASCADE", onupdate="CASCADE"),
                  nullable=False, primary_key=True),
        sa.Column("tls_offered", sa.Boolean(),
                  nullable=False),
        sa.Column("tls_negotiated", sa.Boolean(),
                  nullable=False),
        sa.Column("sasl_pre_tls", sa.Boolean(),
                  nullable=False),
        sa.Column("sasl_post_tls", sa.Boolean(),
                  nullable=False),
        sa.Column("errno", sa.Integer(),
                  nullable=True),
        sa.Column("error", sa.Unicode(1023),
                  nullable=True),
    )

    op.create_table(
        "endpoint_scan_sasl_offering",
        sa.Column("endpoint_scan_result_id", sa.Integer(),
                  sa.ForeignKey("endpoint_scan_result.endpoint_id",
                                ondelete="CASCADE", onupdate="CASCADE"),
                  nullable=False, primary_key=True),
        sa.Column("sasl_mechanism_id", sa.Integer(),
                  sa.ForeignKey("sasl_mechanism.id",
                                ondelete="RESTRICT", onupdate="CASCADE"),
                  nullable=False, primary_key=True),
        sa.Column("phase", sa.Unicode(32),
                  nullable=False, primary_key=True)
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
    op.drop_index("certificate_offering_ix_endpoint_id")
    op.drop_table("certificate_offering")
    op.drop_index("san_ix_certificate_san_type")
    op.drop_table("san")
    op.drop_index("certificate_ix_fingerprint_sha512")
    op.drop_index("certificate_ix_fingerprint_sha256")
    op.drop_index("certificate_ix_fingerprint_sha1")
    op.drop_table("certificate")

    op.drop_index("endpoint_scan_sasl_offering_ix_mechanism_phase")
    op.drop_index("endpoint_scan_sasl_offering_ix_mechanism")
    op.drop_index("endpoint_scan_sasl_offering_ix_scan")
    op.drop_index("endpoint_scan_sasl_offering_ix_scan_phase")
    op.drop_table("endpoint_scan_sasl_offering")
    op.drop_index("sasl_mechanism_ix_name")
    op.drop_table("sasl_mechanism")
    op.drop_table("endpoint_scan_result")

    op.drop_index("scan_task_dependency_ix_parent")
    op.drop_index("scan_task_dependency_ix_child")
    op.drop_table("scan_task_dependency")
    op.drop_table("scan_task")

    op.drop_table("endpoint_http")
    op.drop_table("endpoint_tcp")
    op.drop_table("endpoint")

    op.drop_index("cipher_offering_order_ix_scan_cipher_id")
    op.drop_index("cipher_offering_order_ix_scan_id")
    op.drop_table("cipher_offering_order")
    op.drop_table("cipher_offering")
    op.drop_table("tls_offering")

    op.drop_table("host_meta_link")
    op.drop_table("host_meta_object")
    op.drop_table("xmppconnect_record")
    op.drop_table("srv_record")
    op.drop_index("scan_ix_recent")
    op.drop_table("scan")

    op.drop_index("san_type_ix_asn1_name")
    op.drop_table("san_type")
    op.drop_index("sasl_mechanism_ix_name")
    op.drop_table("sasl_mechanism")
    op.drop_index("cipher_metadata_ix_iana_name")
    op.drop_index("cipher_metadata_ix_openssl_name")
    op.drop_table("cipher_metadata")
