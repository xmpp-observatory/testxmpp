import contextlib
import enum

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
def session_scope(sessionmaker):
    """Provide a transactional scope around a series of operations."""
    session = sessionmaker()
    try:
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


class TaskType(enum.Enum):
    DISCOVER_ENDPOINTS = "srv-resolve"
    DISCOVER_TLSA = "tlsa-resolve"
    SASL_SCAN = "sasl-scan"
    TLS_SCAN = "tls-scan"


class Base(declarative_base()):
    __abstract__ = True
    __table_args__ = {}


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

    primary_host = Column(
        "primary_host",
        sqlalchemy.types.VARCHAR(255),
        nullable=True,
    )

    primary_port = Column(
        "primary_port",
        Integer(),
        nullable=True,
    )

    primary_tls_mode = Column(
        "primary_tls_mode",
        SimpleEnum(TLSMode),
        nullable=True,
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


class TLSOffering(Base):
    __tablename__ = "tls_offering"

    scan_id = Column(
        "scan_id",
        Integer(),
        ForeignKey(Scan.id_, ondelete="CASCADE", onupdate="CASCADE"),
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

    scan_id = Column(
        "scan_id",
        Integer(),
        ForeignKey(Scan.id_, ondelete="CASCADE", onupdate="CASCADE"),
        primary_key=True,
        nullable=False,
    )

    leaf_certificate = Column(
        "leaf_certificate",
        sqlalchemy.types.VARCHAR(4095),
        nullable=True,
    )

    certificate_chain = Column(
        "certificate_chain",
        sqlalchemy.types.VARCHAR(8191),
        nullable=True,
    )


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


class CipherOffering(Base):
    __tablename__ = "cipher_offering"

    scan_id = Column(
        "scan_id",
        Integer(),
        ForeignKey(Scan.id_, ondelete="CASCADE", onupdate="CASCADE"),
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
            ["scan_id", "cipher_id"],
            ["cipher_offering.scan_id", "cipher_offering.cipher_id"]
        ),
    )

    scan_id = Column(
        "scan_id",
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


class SASLMechanismOffering(Base):
    __tablename__ = "sasl_mechansim_offering"

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

    phase = Column(
        "phase",
        SimpleEnum(SASLOfferingPhase),
        nullable=False,
    )

    mechanism = Column(
        "mechanism",
        Unicode(20),
        nullable=False,
    )


class PendingScanTask(Base):
    __tablename__ = "pending_scan_task"

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

    scan = relationship(Scan)

    type_ = Column(
        "type",
        SimpleEnum(TaskType),
        nullable=False,
    )

    parameters = Column(
        "parameters",
        sqlalchemy.types.VARCHAR(2047),
        nullable=False,
    )

    assigned_worker = Column(
        "assigned_worker",
        Unicode(128),
        nullable=False,
    )

    heartbeat = Column(
        "heartbeat",
        DateTime(),
        nullable=True,
    )
