import contextlib
import enum
import json
import typing

from datetime import datetime

import sqlalchemy
from sqlalchemy import (
    Column,
    Integer,
    Unicode,
    DateTime,
    ForeignKey,
    Boolean,
    ForeignKeyConstraint,
)
from sqlalchemy.orm import (
    relationship,
)
from sqlalchemy.ext.declarative import declarative_base


@contextlib.contextmanager
def session_scope(sessionmaker, allow_autoflush=False):
    """Provide a transactional scope around a series of operations."""
    session = sessionmaker()
    try:
        if allow_autoflush:
            yield session
        else:
            with session.no_autoflush:
                yield session
    except:  # NOQA
        session.rollback()
        raise
    finally:
        session.close()


def mkdir_exist_ok(path):
    try:
        path.mkdir(parents=True)
    except FileExistsError:
        if not path.is_dir():
            raise


def get_generic_engine(uri: str) -> sqlalchemy.engine.Engine:
    engine = sqlalchemy.create_engine(uri)

    if uri.startswith("sqlite://"):
        # https://stackoverflow.com/questions/1654857/
        @sqlalchemy.event.listens_for(engine, "connect")
        def do_connect(dbapi_connection, connection_record):
            # disable pysqlite's emitting of the BEGIN statement entirely.
            # also stops it from emitting COMMIT before any DDL.
            dbapi_connection.isolation_level = None
            # holy smokes, enforce foreign keys!!k
            dbapi_connection.execute('pragma foreign_keys=ON')

        @sqlalchemy.event.listens_for(engine, "begin")
        def do_begin(conn):
            # emit our own BEGIN
            conn.execute("BEGIN")

    return engine


class SimpleEnum(sqlalchemy.types.TypeDecorator):
    cache_ok = True
    impl = sqlalchemy.types.Unicode

    def __init__(self, enum_type):
        super().__init__()
        self.__enum_type = enum_type

    def load_dialect_impl(self, dialect):
        return sqlalchemy.types.Unicode(32)

    def process_bind_param(self, value, dialect):
        if value is None:
            return value
        return value.value

    def process_result_value(self, value, dialect):
        if value is None:
            return value
        return self.__enum_type(value)


class ScanType(enum.Enum):
    C2S = "c2s"
    S2S = "s2s"


class SASLOfferingPhase(enum.Enum):
    PRE_TLS = "pre-tls"
    POST_TLS = "post-tls"


class ScanState(enum.Enum):
    IN_PROGRESS = "in-progress"
    CANCELLED = "cancelled"
    ERROR = "error"
    COMPLETED = "completed"


class TLSMode(enum.Enum):
    STARTTLS = "starttls"
    DIRECT = "direct"


class HostMetaFormat(enum.Enum):
    XML = "xml"
    JSON = "json"


class EndpointSource(enum.Enum):
    FALLBACK = "fallback"
    SRV_RECORD = "srv"
    ALTERNATIVE_METHOD = "altconnect"


class TransportLayer(enum.Enum):
    TCP = "tcp"
    HTTP = "http"


class HTTPMode(enum.Enum):
    XEP0025_POLLING = "polling"
    XEP0206_BOSH = "bosh"
    RFC7395_WEBSOCKETS = "ws"


class TaskType(enum.Enum):
    DISCOVER_ENDPOINTS = "srv-resolve"
    RESOLVE_TLSA = "tlsa-resolve"
    SASL_SCAN = "sasl-scan"
    TLS_SCAN = "tls-scan"
    XMPP_PROBE = "xmpp-probe"
    SELECT_ENDPOINTS = "select-endpoints"


class TaskState(enum.Enum):
    WAITING = "waiting"
    IN_PROGRESS = "in-progress"
    FAILED = "failed"
    DONE = "done"


class FailReason(enum.Enum):
    TIMEOUT = "timeout"
    INTERNAL_ERROR = "internal-error"
    UNSUPPORTED = "unsupported"


class ConnectionPhase(enum.Enum):
    PRE_TLS = "pre-tls"
    POST_TLS = "post-tls"


class Base(declarative_base()):
    __abstract__ = True
    __table_args__ = {}


# GLOBAL DATA


class CipherMetadata(Base):
    __tablename__ = "cipher_metadata"

    id_ = Column(
        "id",
        Integer(),
        primary_key=True,
        nullable=False,
    )

    openssl_name = Column(
        "openssl_name",
        Unicode(255),
        nullable=True,
    )

    iana_name = Column(
        "iana_name",
        Unicode(255),
        nullable=True,
    )


class SASLMechanism(Base):
    __tablename__ = "sasl_mechanism"

    id_ = Column(
        "id",
        Integer(),
        nullable=False,
        primary_key=True,
        autoincrement=True,
    )

    name = Column(
        "name",
        Unicode(20),
        nullable=False,
    )


class SubjectAltNameType(Base):
    __tablename__ = "san_type"

    id_ = Column(
        "id",
        Integer(),
        nullable=False,
        primary_key=True,
        autoincrement=True,
    )

    asn1_name = Column(
        "asn1_name",
        Unicode(128),
        nullable=False,
    )


# PER SCAN DATA


class Scan(Base):
    __tablename__ = "scan"

    id_ = Column(
        "id",
        Integer(),
        primary_key=True,
        nullable=False,
        # TODO: something non-auto-increment maybe?
        autoincrement=True,
    )

    domain = Column(
        "domain",
        sqlalchemy.types.VARCHAR(1023),
        nullable=False,
    )

    protocol = Column(
        "protocol",
        SimpleEnum(ScanType),
        nullable=False,
    )

    created_at = Column(
        "created_at",
        DateTime(),
        nullable=False,
    )

    state = Column(
        "state",
        SimpleEnum(ScanState),
        nullable=False,
    )

    certificate_score = Column(
        "certificate_score",
        Integer(),
        nullable=True,
    )

    kex_score = Column(
        "kex_score",
        Integer(),
        nullable=True,
    )

    protocol_score = Column(
        "protocol_score",
        Integer(),
        nullable=True,
    )

    cipher_score = Column(
        "cipher_score",
        Integer(),
        nullable=True,
    )

    privileged = Column(
        "privileged",
        Boolean(),
        nullable=False,
    )


class SRVRecord(Base):
    __tablename__ = "srv_record"

    id_ = Column(
        "id",
        Integer(),
        primary_key=True,
        nullable=False,
        autoincrement=True,
    )

    scan_id = Column(
        "scan_id",
        Integer(),
        ForeignKey(Scan.id_, ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
    )

    service = Column(
        "service",
        Unicode(63),
        nullable=False,
    )

    protocol = Column(
        "protocol",
        Unicode(63),
        nullable=False,
    )

    port = Column(
        "port",
        Integer(),
        nullable=False,
    )

    host = Column(
        "host",
        sqlalchemy.types.VARCHAR(255),
        nullable=False,
    )

    priority = Column(
        "priority",
        Integer(),
        nullable=False,
    )

    weight = Column(
        "weight",
        Integer(),
        nullable=False,
    )


class XMPPConnectRecord(Base):
    __tablename__ = "xmppconnect_record"

    id_ = Column(
        "id",
        Integer(),
        primary_key=True,
        nullable=False,
        autoincrement=True,
    )

    scan_id = Column(
        "scan_id",
        Integer(),
        ForeignKey(Scan.id_, ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
    )

    attribute_name = Column(
        "attribute_name",
        sqlalchemy.types.VARBINARY(1023),
        nullable=False,
    )

    attribute_value = Column(
        "attribute_value",
        sqlalchemy.types.VARBINARY(1023),
        nullable=True,
    )


class HostMetaObject(Base):
    __tablename__ = "host_meta_object"

    id_ = Column(
        "id",
        Integer(),
        primary_key=True,
        nullable=False,
        autoincrement=True,
    )

    scan_id = Column(
        "scan_id",
        Integer(),
        ForeignKey(Scan.id_,
                   ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
    )

    url = Column(
        "url",
        Unicode(1023),
        nullable=False,
    )

    format_ = Column(
        "format",
        SimpleEnum(HostMetaFormat),
        nullable=False,
    )


class HostMetaLink(Base):
    __tablename__ = "host_meta_link"

    id_ = Column(
        "id",
        Integer(),
        primary_key=True,
        nullable=False,
        autoincrement=True,
    )

    object_id = Column(
        "object_id",
        Integer(),
        ForeignKey(HostMetaObject.id_,
                   ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
    )

    object_ = relationship(HostMetaObject)

    rel = Column(
        "rel",
        Unicode(1023),
        nullable=False,
    )

    href = Column(
        "href",
        Unicode(1023),
        nullable=False,
    )


class Endpoint(Base):
    __tablename__ = "endpoint"

    id_ = Column(
        "id",
        Integer(),
        autoincrement=True,
        primary_key=True,
        nullable=False,
    )

    scan_id = Column(
        "scan_id",
        Integer(),
        ForeignKey(Scan.id_, ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
    )

    transport = Column(
        "transport",
        SimpleEnum(TransportLayer),
        nullable=False,
    )

    # For SRV-sourced endpoints
    srv_record_id = Column(
        "srv_record_id",
        Integer(),
        ForeignKey(SRVRecord.id_, ondelete="SET NULL", onupdate="CASCADE"),
        nullable=True,
    )

    srv_record = relationship(SRVRecord)

    # For xmppconnect endpoints
    xmppconnect_record_id = Column(
        "xmppconnect_record_id",
        Integer(),
        ForeignKey(XMPPConnectRecord.id_,
                   ondelete="SET NULL", onupdate="CASCADE"),
        nullable=True,
    )

    xmppconnect_record = relationship(XMPPConnectRecord)

    # For host-meta-sourced endpoints
    host_meta_link_id = Column(
        "host_meta_link_id",
        Integer(),
        ForeignKey(HostMetaLink.id_, ondelete="SET NULL", onupdate="CASCADE"),
        nullable=True,
    )

    host_meta_link = relationship(HostMetaLink)

    __mapper_args__ = {
        "polymorphic_on": transport
    }


class EndpointTCP(Endpoint):
    __tablename__ = "endpoint_tcp"

    endpoint_id = Column(
        "endpoint_id",
        Integer(),
        ForeignKey(Endpoint.id_, ondelete="CASCADE", onupdate="CASCADE"),
        primary_key=True,
        nullable=False,
    )

    tls_mode = Column(
        "tls_mode",
        SimpleEnum(TLSMode),
        nullable=False,
    )

    hostname = Column(
        "hostname",
        sqlalchemy.types.VARBINARY(255),
        nullable=False,
    )

    port = Column(
        "port",
        Integer(),
        nullable=False,
    )

    __mapper_args__ = {
        "polymorphic_identity": TransportLayer.TCP,
    }

    @property
    def uri(self):
        return "{}:{}".format(self.hostname.decode("idna").rstrip("."),
                              self.port)


class EndpointHTTP(Endpoint):
    __tablename__ = "endpoint_http"

    endpoint_id = Column(
        "endpoint_id",
        Integer(),
        ForeignKey(Endpoint.id_, ondelete="CASCADE", onupdate="CASCADE"),
        primary_key=True,
        nullable=False,
    )

    url = Column(
        "url",
        Unicode(1023),
        nullable=False,
    )

    http_mode = Column(
        "http_mode",
        SimpleEnum(HTTPMode),
        nullable=False,
    )

    @property
    def uri(self):
        return self.url

    __mapper_args__ = {
        "polymorphic_identity": TransportLayer.HTTP,
    }


class TLSOffering(Base):
    __tablename__ = "tls_offering"

    endpoint_id = Column(
        "endpoint_id",
        Integer(),
        ForeignKey(Endpoint.id_, ondelete="CASCADE", onupdate="CASCADE"),
        primary_key=True,
        nullable=False,
    )

    sslv2 = Column("sslv2", Boolean(),
                   nullable=True)
    sslv3 = Column("sslv3", Boolean(),
                   nullable=True)
    tlsv1 = Column("tlsv1", Boolean(),
                   nullable=True)
    tlsv1_1 = Column("tlsv1_1", Boolean(),
                     nullable=True)
    tlsv1_2 = Column("tlsv1_2", Boolean(),
                     nullable=True)
    tlsv1_3 = Column("tlsv1_3", Boolean(),
                     nullable=True)

    server_cipher_order = Column("server_cipher_order", Boolean(),
                                 nullable=True)


class Certificate(Base):
    __tablename__ = "certificate"

    id_ = Column(
        "id",
        Integer(),
        primary_key=True,
        nullable=False,
        # TODO: something non-auto-increment maybe?
        autoincrement=True,
    )

    fingerprint_sha1 = Column(
        "fp_sha1",
        sqlalchemy.types.VARBINARY(20),
        nullable=False,
    )

    fingerprint_sha256 = Column(
        "fp_sha256",
        sqlalchemy.types.VARBINARY(32),
        nullable=False,
    )

    fingerprint_sha512 = Column(
        "fp_sha512",
        sqlalchemy.types.VARBINARY(64),
        nullable=False,
    )

    raw_der = Column(
        "raw_der",
        sqlalchemy.types.VARBINARY(8192),
        nullable=False,
    )

    not_before = Column(
        "not_before",
        DateTime(),
        nullable=False,
    )

    not_after = Column(
        "not_after",
        DateTime(),
        nullable=False,
    )

    public_key = Column(
        "public_key",
        sqlalchemy.types.VARBINARY(2048),
        nullable=False,
    )

    public_key_type = Column(
        "public_key_type",
        Unicode(128),
        nullable=False,
    )

    subject = Column(
        "subject",
        Unicode(1024),
        nullable=False,
    )

    issuer = Column(
        "issuer",
        Unicode(1024),
        nullable=False,
    )


class SubjectAltName(Base):
    __tablename__ = "san"

    # cannot use cert_id + asn1_name as PK because a cert may have multiple
    # SANs of the same type
    id_ = Column(
        "id",
        Integer(),
        autoincrement=True,
        primary_key=True,
        nullable=False,
    )

    certificate_id = Column(
        "certificate_id",
        Integer(),
        ForeignKey(Certificate.id_, ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
    )

    type_id = Column(
        "type_id",
        Integer,
        ForeignKey(SubjectAltNameType.id_,
                   ondelete="RESTRICT", onupdate="CASCADE"),
        nullable=False,
    )

    value = Column(
        "value",
        Unicode(256),
        nullable=False,
    )

    certificate = relationship(Certificate)
    type_ = relationship(SubjectAltNameType)


class CertificateOffering(Base):
    __tablename__ = "certificate_offering"

    endpoint_id = Column(
        "endpoint_id",
        Integer(),
        ForeignKey(Endpoint.id_, ondelete="CASCADE", onupdate="CASCADE"),
        primary_key=True,
        nullable=False,
    )

    chain_index = Column(
        "chain_index",
        Integer(),
        primary_key=True,
        nullable=False,
    )

    certificate_id = Column(
        "certificate_id",
        Integer(),
        ForeignKey(Certificate.id_, ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
    )

    certificate = relationship(Certificate)


class CipherOffering(Base):
    __tablename__ = "cipher_offering"

    endpoint_id = Column(
        "endpoint_id",
        Integer(),
        ForeignKey(Endpoint.id_, ondelete="CASCADE", onupdate="CASCADE"),
        primary_key=True,
        nullable=False,
    )

    cipher_id = Column(
        "cipher_id",
        Integer(),
        ForeignKey(CipherMetadata.id_,
                   onupdate="CASCADE"),
        primary_key=True,
        nullable=False,
    )

    key_exchange_info = Column(
        "key_exchange_info",
        Unicode(127),
        nullable=True,
    )


class CipherOfferingOrder(Base):
    __tablename__ = "cipher_offering_order"

    __table_args__ = (
        ForeignKeyConstraint(
            ["endpoint_id", "cipher_id"],
            ["cipher_offering.endpoint_id", "cipher_offering.cipher_id"]
        ),
    )

    endpoint_id = Column(
        "endpoint_id",
        Integer(),
        primary_key=True,
        nullable=False,
    )

    cipher_id = Column(
        "cipher_id",
        Integer(),
        primary_key=True,
        nullable=False,
    )

    tls_version = Column(
        "tls_version",
        Unicode(32),
        primary_key=True,
        nullable=False,
    )

    order = Column(
        "order",
        Integer(),
        nullable=False,
    )


class ScanTask(Base):
    __tablename__ = "scan_task"

    id_ = Column(
        "id",
        sqlalchemy.types.BINARY(16),
        primary_key=True,
        nullable=False,
    )

    scan_id = Column(
        "scan_id",
        Integer(),
        ForeignKey(Scan.id_, ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
    )

    scan = relationship(Scan)

    type_ = Column(
        "type",
        SimpleEnum(TaskType),
        nullable=False,
    )

    state = Column(
        "state",
        SimpleEnum(TaskState),
        nullable=False,
    )

    fail_reason = Column(
        "fail_reason",
        SimpleEnum(FailReason),
        nullable=True,
    )

    endpoint_id = Column(
        "endpoint_id",
        Integer(),
        ForeignKey(Endpoint.id_, ondelete="CASCADE", onupdate="CASCADE"),
        nullable=True,
    )

    endpoint = relationship(Endpoint)

    heartbeat = Column(
        "heartbeat",
        DateTime(),
        nullable=True,
    )

    assigned_worker = Column(
        "assigned_worker",
        sqlalchemy.types.BINARY(16),
        nullable=True,
    )

    @classmethod
    def available_tasks(cls, session, cutoff: typing.Optional[datetime]):
        q = session.query(
            cls
        ).outerjoin(
            ScanTaskDependency,
            ScanTaskDependency.child_task_id == cls.id_,
        ).filter(
            ScanTaskDependency.parent_task_id == None,  # NOQA
            cls.state != TaskState.FAILED,
            cls.state != TaskState.DONE,
        )
        if cutoff is not None:
            q = q.filter(sqlalchemy.or_(
                cls.heartbeat == None,  # NOQA
                cls.heartbeat < cutoff,
            ))
        return q

    def mark_completed(self, session, state=TaskState.DONE):
        self.state = TaskState.DONE
        session.query(ScanTaskDependency).filter(
            ScanTaskDependency.parent_task_id == self.id_
        ).delete()


class ScanTaskDependency(Base):
    __tablename__ = "scan_task_dependency"

    parent_task_id = Column(
        "parent_task_id",
        Integer(),
        ForeignKey("scan_task.id", ondelete="CASCADE", onupdate="CASCADE"),
        primary_key=True,
    )

    child_task_id = Column(
        "child_task_id",
        Integer(),
        ForeignKey("scan_task.id", ondelete="CASCADE", onupdate="CASCADE"),
        primary_key=True,
    )

    parent_task = relationship(ScanTask, foreign_keys=parent_task_id)

    child_task = relationship(ScanTask, foreign_keys=child_task_id)


class EndpointScanResult(Base):
    __tablename__ = "endpoint_scan_result"

    endpoint_id = Column(
        "endpoint_id",
        Integer(),
        ForeignKey(Endpoint.id_, ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
        primary_key=True,
    )

    endpoint = relationship(Endpoint)

    tls_offered = Column(
        "tls_offered",
        Boolean(),
        nullable=False,
    )

    tls_negotiated = Column(
        "tls_negotiated",
        Boolean(),
        nullable=False,
    )

    sasl_pre_tls = Column(
        "sasl_pre_tls",
        Boolean(),
        nullable=False,
    )

    sasl_post_tls = Column(
        "sasl_post_tls",
        Boolean(),
        nullable=False,
    )

    errno = Column(
        "errno",
        Integer(),
        nullable=True,
    )

    error = Column(
        "error",
        Unicode(1023),
        nullable=True,
    )


class EndpointScanSASLOffering(Base):
    __tablename__ = "endpoint_scan_sasl_offering"

    endpoint_id = Column(
        "endpoint_scan_result_id",
        Integer(),
        ForeignKey(EndpointScanResult.endpoint_id,
                   ondelete="CASCADE",
                   onupdate="CASCADE"),
        nullable=False,
        primary_key=True,
    )

    endpoint_scan_result = relationship(EndpointScanResult)

    sasl_mechanism_id = Column(
        "sasl_mechanism_id",
        Integer(),
        ForeignKey(SASLMechanism.id_,
                   ondelete="CASCADE",
                   onupdate="CASCADE"),
        nullable=False,
        primary_key=True,
    )

    sasl_mechanism = relationship(SASLMechanism)

    phase = Column(
        "phase",
        SimpleEnum(ConnectionPhase),
        nullable=False,
        primary_key=True,
    )
