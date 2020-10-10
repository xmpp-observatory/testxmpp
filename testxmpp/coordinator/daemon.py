import asyncio
import json
import logging
import random
import typing

from datetime import datetime, timedelta

import schema

import dns.resolver

import sqlalchemy.orm

import zmq
import zmq.asyncio

import aioxmpp

from testxmpp import model
from testxmpp.common import RequestProcessor
import testxmpp.dns
import testxmpp.api.common as common_api
import testxmpp.api.coordinator as coordinator_api

from . import tasks


logger = logging.getLogger(__name__)


HEARTBEAT_THRESOHLD = timedelta(minutes=1)


class ExponentialBackOff:
    def __init__(self, base=2, start=1, max_=120):
        super().__init__()
        self.start = start
        self.max_ = max_
        self.base = base
        self._is_failing = False
        self._current = self.start

    def __iter__(self):
        return self

    def __next__(self):
        self._is_failing = True
        val = self._current
        self._current = min(self._current * self.base, self.max_)
        return val

    def next(self):
        return next(self)

    def reset(self):
        self._current = self.start

    @property
    def failing(self):
        return self._is_failing


class RestartingTask:
    def __init__(self, coroutine_function,
                 logger=None,
                 loop=None):
        super().__init__()
        self._func = coroutine_function
        self._task = None
        self._should_run = False
        self.backoff = ExponentialBackOff()
        self._loop = loop or asyncio.get_event_loop()
        self._logger = logger or logging.getLogger(
            ".".join([__name__, type(self).__qualname__, str(id(self))]),
        )

    def start(self):
        self._should_run = True
        self.backoff.reset()
        self._ensure_state()

    def stop(self):
        self._should_run = False
        self._ensure_state()

    def restart(self):
        if not self._should_run:
            return self.start()
        self.backoff.reset()
        if self._task is None:
            self._ensure_state()
        else:
            # cancel the task in order to force an immediate restart
            self._task.cancel()

    def _task_done(self, task):
        assert task is self._task
        try:
            try:
                result = task.result()
            except asyncio.CancelledError:
                self._logger.debug("task stopped after cancellation request")
                if self._should_run:
                    self._logger.info("restarting task immediately because"
                                      " the desired state is up")
                    self._loop.call_soon(self._ensure_state)
                return
            except BaseException as exc:
                delay = next(self.backoff)
                self._logger.error("task crashed! retrying in %s",
                                   delay, exc_info=True)
                self._loop.call_later(delay, self._ensure_state)
                return

            self._logger.info("task exited with result %r, not restarting",
                              result)
            self._should_run = False
        finally:
            self._task = None

    def _ensure_state(self):
        if self._task is None and self._should_run:
            # need to start task
            self._task = self._loop.create_task(self._func())
            self._task.add_done_callback(self._task_done)
        elif self._task is not None and not self._should_run:
            # need to stop task
            self._task.cancel()


async def gather_srv_records(domain, services):
    domain = testxmpp.dns.encode_domain(domain)
    for service in services:
        try:
            records = await testxmpp.dns.lookup_srv(domain, "tcp", service,
                                                    raise_on_no_answer=False)
        except dns.resolver.NXDOMAIN:
            continue

        for record in records:
            yield (service, record)


def normalize_domain(domain: str) -> bytes:
    """
    Normalize and encode a string containing a domain name for matching
    and storage purposes.

    :param domain: A string containing a domain name, either in unicode or in
        IDNA form.
    :type domain: :class:`str`
    :raise ValueError: if `domain` has leading dots.
    :return: The normalised and encoded domain name.
    :rtype: :class:`bytes`

    Given `domain`, any trailing dots are removed. If the string contains an
    IDNA encoded domain name, it is decoded first. The string is then
    normalised using nameprep and afterwards properly encoded as IDNA into a
    :class:`bytes` object.

    Note that even though the `domain` may be IDNA encoded, it must be a
    :class:`str`.
    """

    domain = domain.rstrip(".")
    if domain.startswith("."):
        raise ValueError("domain name must not start with a dot")

    # We want to reverse a possible IDNA encoding.
    try:
        # For this, we first check (the hard way) whether the string contains
        # any non-ascii stuff.
        domain_bytes = domain.encode("ascii")
    except UnicodeEncodeError:
        # If it contains non-ascii stuff, that’s ok -- it clearly is not IDNA
        # encoded.
        pass
    else:
        # Otherwise, let us try to IDNA-decode it to revert it to its unicode
        # form.
        domain = domain_bytes.decode("idna")

    # Now we run stringprep on it and re-encode it as IDNA.
    return aioxmpp.stringprep.nameprep(domain).encode("idna")


def get_or_create_sasl_mechanism(session, name: str):
    try:
        return session.query(model.SASLMechanism).filter(
            model.SASLMechanism.name == name,
        ).one()
    except sqlalchemy.orm.exc.NoResultFound:
        mech = model.SASLMechanism()
        mech.name = name
        session.add(mech)
        return mech


def add_sasl_mechanisms(session,
                        phase: model.ConnectionPhase,
                        mechanisms: typing.List[str],
                        result: model.EndpointScanResult):
    for mech in mechanisms:
        entry = model.EndpointScanSASLOffering()
        entry.endpoint_scan_result = result
        entry.phase = phase
        entry.sasl_mechanism = get_or_create_sasl_mechanism(
            session, mech,
        )
        session.add(entry)


class CoordinatorRequestProcessor(RequestProcessor):
    def __init__(self,
                 logger,
                 task_queue,
                 sessionmaker,
                 scan_ratelimit_unprivileged):
        super().__init__(
            coordinator_api.api_request,
            coordinator_api.api_response,
            coordinator_api.mkv1response(
                coordinator_api.ResponseType.ERROR,
                common_api.mkerror(
                    common_api.ErrorCode.INTERNAL_ERROR,
                    "internal error",
                ),
            ),
            logger,
        )
        self._task_queue = task_queue
        self._sessionmaker = sessionmaker
        self._scan_ratelimit_unprivileged = scan_ratelimit_unprivileged

    async def _discover_endpoints(self, task_id):
        with model.session_scope(self._sessionmaker) as session:
            task = session.query(model.PendingScanTask).filter(
                model.PendingScanTask.id_ == task_id
            ).one()
            scan = task.scan
            scan_id = scan.id_
            scan_domain = scan.domain
            scan_protocol = scan.protocol

        srv_services = {
            model.ScanType.C2S: ["xmpp-client", "xmpps-client"],
            model.ScanType.S2S: ["xmpp-server", "xmpps-server"],
        }[scan_protocol]

        db_records = []
        async for service, record in gather_srv_records(scan_domain,
                                                        srv_services):
            db_record = model.SRVRecord()
            db_record.scan_id = scan_id
            db_record.service = service
            db_record.protocol = "tcp"
            db_record.weight = record.weight
            db_record.port = record.port
            db_record.priority = record.priority
            db_record.host = record.target.to_text().encode("ascii")
            db_records.append(db_record)

        if db_records:
            db_records.sort(key=lambda x: (x.priority, -x.weight))
            primary_record = db_records[0]
            if primary_record.service in ["xmpps-server", "xmpps-client"]:
                primary_tls_mode = model.TLSMode.DIRECT
            else:
                primary_tls_mode = model.TLSMode.STARTTLS
            primary_host = primary_record.host
            primary_port = primary_record.port
        else:
            # fallback to A/AAAA for endpoint selection
            primary_host = scan_domain
            primary_port = {
                model.ScanType.C2S: 5222,
                model.ScanType.S2S: 5269,
            }[scan_protocol]
            primary_tls_mode = model.TLSMode.STARTTLS

        with model.session_scope(self._sessionmaker) as session:
            taskq = session.query(model.PendingScanTask).filter(
                model.PendingScanTask.id_ == task_id
            )
            try:
                task = taskq.one()
            except sqlalchemy.orm.exc.NoResultFound:
                # task has been done by another worker already.
                return

            taskq.delete()

            scan = session.query(model.Scan).filter(
                model.Scan.id_ == task.scan_id,
            ).one()
            scan.primary_host = primary_host
            scan.primary_port = primary_port
            scan.primary_tls_mode = primary_tls_mode

            session.query(model.SRVRecord).filter(
                model.SRVRecord.scan_id == scan_id,
            ).delete()

            for db_record in db_records:
                session.add(db_record)

            tls_task = model.PendingScanTask()
            tls_task.scan_id = scan_id
            tls_task.type_ = model.TaskType.TLS_SCAN
            tls_task.parameters = '{}'
            session.add(tls_task)

            probe_task = model.PendingScanTask()
            probe_task.scan_id = scan_id
            probe_task.type_ = model.TaskType.XMPP_PROBE
            probe_task.parameters = json.dumps(
                {
                    "hostname": scan_domain.decode("ascii"),
                    "port": {
                        model.ScanType.C2S: 5222,
                        model.ScanType.S2S: 5269,
                    }[scan_protocol],
                    "tls_mode": "starttls",
                    "protocol": scan_protocol.value,
                }
            )
            session.add(probe_task)

            for db_record in db_records:
                probe_task = model.PendingScanTask()
                probe_task.scan_id = scan_id
                probe_task.type_ = model.TaskType.XMPP_PROBE
                probe_task.parameters = json.dumps(
                    {
                        "hostname": db_record.host.decode("ascii"),
                        "port": db_record.port,
                        "tls_mode": {
                            "xmpp-client": "starttls",
                            "xmpp-server": "starttls",
                            "xmpps-client": "direct",
                            "xmpps-server": "direct",
                        }[db_record.service],
                        "protocol": scan_protocol.value,
                    }
                )
                session.add(probe_task)

            session.commit()

    async def _discover_tlsa(self, task_id):
        with model.session_scope(self._sessionmaker) as session:
            taskq = session.query(model.PendingScanTask).filter(
                model.PendingScanTask.id_ == task_id
            )
            try:
                task = taskq.one()
            except sqlalchemy.orm.exc.NoResultFound:
                # task has been done by another worker already.
                return

            taskq.delete()
            session.commit()

    def _get_or_create_tls_offering(self, session, scan_id):
        try:
            return session.query(model.TLSOffering).filter(
                model.TLSOffering.scan_id == scan_id,
            ).one()
        except sqlalchemy.orm.exc.NoResultFound:
            tls_offering = model.TLSOffering()
            tls_offering.scan_id = scan_id
            session.add(tls_offering)
            return tls_offering

    def _get_or_create_certificate(self, session, scan_id):
        try:
            return session.query(model.Certificate).filter(
                model.Certificate.scan_id == scan_id,
            ).one()
        except sqlalchemy.orm.exc.NoResultFound:
            cert = model.Certificate()
            cert.scan_id = scan_id
            session.add(cert)
            return cert

    def _lookup_cipher_id_by_name(self, session, openssl_name):
        result = session.query(model.CipherMetadata.id_).filter(
            model.CipherMetadata.openssl_name == openssl_name
        ).one_or_none()
        if result is None:
            return None
        return result[0]

    def _upsert_cipher_metadata(self, session, cipher_id,
                                openssl_name, iana_name):
        try:
            metadata = session.query(model.CipherMetadata).filter(
                model.CipherMetadata.id_ == cipher_id,
            ).one()
        except sqlalchemy.orm.exc.NoResultFound:
            metadata = model.CipherMetadata()
            metadata.id_ = cipher_id
            session.add(metadata)

        if openssl_name and metadata.openssl_name != openssl_name:
            metadata.openssl_name = openssl_name
        if iana_name and metadata.iana_name != iana_name:
            metadata.iana_name = iana_name
        return metadata

    def _upsert_cipher_offering_order(self, session, scan_id, cipher_id,
                                      tls_version, order):
        try:
            offering_order = session.query(model.CipherOfferingOrder).filter(
                model.CipherOfferingOrder.scan_id == scan_id,
                model.CipherOfferingOrder.cipher_id == cipher_id,
                model.CipherOfferingOrder.tls_version == tls_version,
            ).one()
        except sqlalchemy.orm.exc.NoResultFound:
            offering_order = model.CipherOfferingOrder()
            offering_order.scan_id = scan_id
            offering_order.cipher_id = cipher_id
            offering_order.tls_version = tls_version
            session.add(offering_order)

        if offering_order.order != order:
            offering_order.order = order
        return offering_order

    def _get_or_create_cipher_offering(self, session, scan_id, cipher_id):
        try:
            return session.query(model.CipherOffering).filter(
                model.CipherOffering.scan_id == scan_id,
                model.CipherOffering.cipher_id == cipher_id,
            ).one()
        except sqlalchemy.orm.exc.NoResultFound:
            cipher_offering = model.CipherOffering()
            cipher_offering.scan_id = scan_id
            cipher_offering.cipher_id = cipher_id
            session.add(cipher_offering)
            return cipher_offering

    def _handle_testssl_tls_versions_push(
            self,
            session, scan_id, data) -> bool:
        tls_offering = self._get_or_create_tls_offering(session, scan_id)

        # no generic/procedural mapping here to avoid the worker being able to
        # manipulate arbitrary attributes of the object.
        keymap = {
            "SSLv2": "sslv2",
            "SSLv3": "sslv3",
            "TLSv1": "tlsv1",
            "TLSv1.1": "tlsv1_1",
            "TLSv1.2": "tlsv1_2",
            "TLSv1.3": "tlsv1_3",
        }

        for k, v in data["tls_versions"].items():
            setattr(tls_offering, keymap[k], bool(v))

        return True

    def _handle_testssl_cipherlists_push(
            self,
            session, scan_id, data) -> bool:
        # we ignore this push, because we need to access the cipher lists
        # based on the cipher ID, but we only get the OpenSSL name here.
        return True

    def _handle_testssl_cipherlists_complete(
            self,
            session, scan_id, data) -> bool:
        for tls_version, ciphers in data.items():
            for order, openssl_name in enumerate(ciphers):
                cipher_id = self._lookup_cipher_id_by_name(
                    session, openssl_name,
                )
                if cipher_id is None:
                    # ???
                    continue
                cipher_offering = self._get_or_create_cipher_offering(
                    session, scan_id, cipher_id
                )
                self._upsert_cipher_offering_order(
                    session, scan_id, cipher_id, tls_version, order,
                )
        return True

    def _handle_testssl_server_cipher_order_push(
            self,
            session, scan_id, data) -> bool:
        tls_offering = self._get_or_create_tls_offering(session, scan_id)
        tls_offering.server_cipher_order = data["server_cipher_order"]
        return True

    def _handle_testssl_cipher_info_push(
            self,
            session, scan_id, data) -> bool:
        data = data["cipher"]
        cipher_metadata = self._upsert_cipher_metadata(
            session,
            data["id"],
            data["openssl_name"],
            data["iana_name"],
        )
        cipher_offering = self._get_or_create_cipher_offering(
            session,
            scan_id,
            data["id"],
        )
        cipher_offering.key_exchange_info = data["key_exchange"] or None
        return True

    def _handle_testssl_certificate_push(
            self,
            session, scan_id, data) -> bool:
        certificate = self._get_or_create_certificate(session, scan_id)
        certificate.leaf_certificate = data["certificate"]
        return True

    def _handle_testssl_push(self, worker_id, job_id, testssl_data) -> bool:
        data_type = testssl_data["type"]
        handler = {
            "tls_versions": self._handle_testssl_tls_versions_push,
            "cipherlists": self._handle_testssl_cipherlists_push,
            "server_cipher_order":
                self._handle_testssl_server_cipher_order_push,
            "cipher_info": self._handle_testssl_cipher_info_push,
            "certificate": self._handle_testssl_certificate_push,
        }.get(data_type, None)
        if handler is None:
            raise RuntimeError("unhandled testssl push data type: {!r}".format(
                data_type
            ))

        with model.session_scope(self._sessionmaker) as session:
            try:
                task = session.query(model.PendingScanTask).filter(
                    model.PendingScanTask.id_ == job_id,
                ).one()
            except sqlalchemy.orm.exc.NoResultFound:
                return False

            if task.assigned_worker != worker_id:
                # late worker?
                return False

            if not handler(session, task.scan_id, testssl_data):
                # allow immediate rescheduling of the task
                task.heartbeat = None
                return False

            task.heartbeat = datetime.utcnow()
            session.commit()

        return True

    def _handle_testssl_result(self, worker_id, job_id, result):
        with model.session_scope(self._sessionmaker) as session:
            try:
                task = session.query(model.PendingScanTask).filter(
                    model.PendingScanTask.id_ == job_id,
                ).one()
            except sqlalchemy.orm.exc.NoResultFound:
                return

            if task.assigned_worker != worker_id:
                # late worker?
                return

            scan_id = task.scan_id

            self._handle_testssl_tls_versions_push(
                session, scan_id, result,
            )
            self._handle_testssl_certificate_push(
                session, scan_id, result,
            )
            self._handle_testssl_server_cipher_order_push(
                session, scan_id, result,
            )
            for cipher_info in result["ciphers"]:
                self._handle_testssl_cipher_info_push(
                    session, scan_id, {"cipher": cipher_info},
                )
            self._handle_testssl_cipherlists_complete(
                session, scan_id, result["cipherlists"],
            )

            session.delete(task)
            session.commit()

    async def _handle_xmpp_result(self, worker_id, job_id, result):
        with model.session_scope(self._sessionmaker) as session:
            try:
                task = session.query(model.PendingScanTask).filter(
                    model.PendingScanTask.id_ == job_id,
                ).one()
            except sqlalchemy.orm.exc.NoResultFound:
                return False

            if task.assigned_worker != worker_id:
                # late worker?
                return False

            session.delete(task)

            parameters = json.loads(task.parameters)

            scan_id = task.scan_id
            endpoint_result = model.EndpointScanResult()
            endpoint_result.scan_id = scan_id
            endpoint_result.hostname = parameters["hostname"].encode("ascii")
            endpoint_result.port = parameters["port"]
            endpoint_result.tls_mode = model.TLSMode(parameters["tls_mode"])
            endpoint_result.tls_offered = result["tls_offered"]
            endpoint_result.tls_negotiated = result["tls_negotiated"]
            endpoint_result.error = result["error"]
            endpoint_result.errno = result["errno"]
            session.add(endpoint_result)

            if result["pre_tls_sasl_mechanisms"] is not None:
                endpoint_result.sasl_pre_tls = True
                add_sasl_mechanisms(session,
                                    model.ConnectionPhase.PRE_TLS,
                                    result["pre_tls_sasl_mechanisms"],
                                    endpoint_result)
            else:
                endpoint_result.sasl_pre_tls = False

            if result["post_tls_sasl_mechanisms"] is not None:
                endpoint_result.sasl_post_tls = True
                add_sasl_mechanisms(session,
                                    model.ConnectionPhase.POST_TLS,
                                    result["post_tls_sasl_mechanisms"],
                                    endpoint_result)
            else:
                endpoint_result.sasl_post_tls = False

            session.commit()

        return True

    async def _handle_message(self, msg):
        logger.debug("_handle_message(%r)", msg)

        if msg["type"] == coordinator_api.RequestType.PING.value:
            return coordinator_api.mkv1response(
                coordinator_api.ResponseType.PONG,
                msg["payload"],
            )

        elif msg["type"] == coordinator_api.RequestType.SCAN_DOMAIN.value:
            now = datetime.utcnow()
            cutoff = (
                now - timedelta(
                    seconds=self._scan_ratelimit_unprivileged.interval
                )
            )

            try:
                domain = normalize_domain(msg["payload"]["domain"])
            except (ValueError, UnicodeEncodeError):
                return coordinator_api.mkv1response(
                    coordinator_api.ResponseType.ERROR,
                    common_api.mkerror(
                        common_api.ErrorCode.BAD_REQUEST,
                        "invalid domain name"
                    )
                )

            with model.session_scope(self._sessionmaker) as session:
                nscans = session.query(model.Scan.created_at).filter(
                    model.Scan.created_at >= cutoff,
                    model.Scan.domain == domain,
                ).limit(
                    self._scan_ratelimit_unprivileged.burst
                ).count()
                if nscans >= self._scan_ratelimit_unprivileged.burst:
                    return coordinator_api.mkv1response(
                        coordinator_api.ResponseType.ERROR,
                        common_api.mkerror(
                            common_api.ErrorCode.TOO_MANY_REQUESTS,
                            "unprivileged rate limit hit",
                        )
                    )

                scan = model.Scan()
                scan.domain = domain
                scan.created_at = now
                scan.protocol = model.ScanType(msg["payload"]["protocol"])
                scan.state = model.ScanState.IN_PROGRESS
                scan.privileged = False
                session.add(scan)

                ep_task = model.PendingScanTask()
                ep_task.scan = scan
                ep_task.type_ = model.TaskType.DISCOVER_ENDPOINTS
                ep_task.parameters = "{}".encode("utf-8")
                session.add(ep_task)

                session.commit()
                self._task_queue.push(self._discover_endpoints, ep_task.id_)
                return coordinator_api.mkv1response(
                    coordinator_api.ResponseType.SCAN_QUEUED,
                    {
                        "scan_id": scan.id_,
                    },
                )

        elif msg["type"] == coordinator_api.RequestType.GET_TESTSSL_JOB.value:
            cutoff = datetime.utcnow() - HEARTBEAT_THRESOHLD
            worker_id = msg["payload"]["worker_id"]

            with model.session_scope(self._sessionmaker) as session:
                task = session.query(model.PendingScanTask).filter(
                    model.PendingScanTask.type_ == model.TaskType.TLS_SCAN,
                    sqlalchemy.or_(
                        model.PendingScanTask.heartbeat == None,  # NOQA
                        model.PendingScanTask.heartbeat < cutoff,
                    )
                ).order_by(
                    model.PendingScanTask.heartbeat.asc()
                ).limit(1).one_or_none()
                if task is None:
                    return coordinator_api.mkv1response(
                        coordinator_api.ResponseType.NO_TASKS,
                        {
                            "ask_again_after": random.randint(1, 3),
                        },
                    )

                scan = task.scan
                job = {
                    "job_id": str(task.id_),
                    "domain": scan.domain.decode("utf-8"),
                    "hostname": scan.primary_host.decode("ascii"),
                    "port": scan.primary_port,
                    "protocol": scan.protocol.value,
                    "tls_mode": scan.primary_tls_mode.value,
                }

                task.assigned_worker = worker_id
                task.heartbeat = datetime.utcnow()
                session.commit()

                return coordinator_api.mkv1response(
                    coordinator_api.ResponseType.GET_TESTSSL_JOB,
                    job,
                )

        elif msg["type"] == coordinator_api.RequestType.GET_XMPP_JOB.value:
            cutoff = datetime.utcnow() - HEARTBEAT_THRESOHLD
            worker_id = msg["payload"]["worker_id"]

            with model.session_scope(self._sessionmaker) as session:
                task = session.query(model.PendingScanTask).filter(
                    model.PendingScanTask.type_ == model.TaskType.XMPP_PROBE,
                    sqlalchemy.or_(
                        model.PendingScanTask.heartbeat == None,  # NOQA
                        model.PendingScanTask.heartbeat < cutoff,
                    )
                ).order_by(
                    model.PendingScanTask.heartbeat.asc()
                ).limit(1).one_or_none()
                if task is None:
                    return coordinator_api.mkv1response(
                        coordinator_api.ResponseType.NO_TASKS,
                        {
                            "ask_again_after": random.randint(1, 3),
                        },
                    )

                scan = task.scan
                job_description = {
                    "type": "features",
                    "domain": scan.domain.decode("utf-8"),
                }
                job_description.update(json.loads(task.parameters))
                job = {
                    "job_id": str(task.id_),
                    "job": job_description,
                }

                task.assigned_worker = worker_id
                task.heartbeat = datetime.utcnow()
                session.commit()

                return coordinator_api.mkv1response(
                    coordinator_api.ResponseType.GET_XMPP_JOB,
                    job,
                )

        elif msg["type"] == coordinator_api.RequestType.TESTSSL_RESULT_PUSH.value:
            job_id = int(msg["payload"]["job_id"])
            worker_id = msg["payload"]["worker_id"]
            data = msg["payload"]["testssl_data"]

            return coordinator_api.mkv1response(
                coordinator_api.ResponseType.JOB_CONFIRMATION,
                {
                    "continue": self._handle_testssl_push(worker_id,
                                                          job_id,
                                                          data)
                }
            )

        elif msg["type"] == coordinator_api.RequestType.TESTSSL_COMPLETE.value:
            job_id = int(msg["payload"]["job_id"])
            worker_id = msg["payload"]["worker_id"]
            result = msg["payload"]["testssl_result"]

            self._handle_testssl_result(
                worker_id,
                job_id,
                result,
            )
            return coordinator_api.mkv1response(
                coordinator_api.ResponseType.OK,
                {}
            )

        elif msg["type"] == coordinator_api.RequestType.XMPP_COMPLETE.value:
            job_id = int(msg["payload"]["job_id"])
            worker_id = msg["payload"]["worker_id"]
            result = msg["payload"]["xmpp_result"]

            ok = await self._handle_xmpp_result(
                worker_id,
                job_id,
                result,
            )
            if ok:
                return coordinator_api.mkv1response(
                    coordinator_api.ResponseType.OK,
                    {}
                )
            else:
                return coordinator_api.mkv1response(
                    coordinator_api.ResponseType.JOB_CONFIRMATION,
                    {
                        "continue": False,
                    }
                )

        else:
            return coordinator_api.mkv1response(
                coordinator_api.ResponseType.ERROR,
                common_api.mkerror(
                    # not BAD_REQUEST here, because the type was validated
                    # earlier
                    common_api.ErrorCode.INTERNAL_ERROR,
                    "unhandled type",
                )
            )

    async def _handle_schema_error(self, msg, exc):
        return coordinator_api.mkv1response(
            coordinator_api.ResponseType.ERROR,
            common_api.mkerror(
                common_api.ErrorCode.BAD_REQUEST,
                str(exc),
            )
        )


class Coordinator:
    def __init__(self, config):
        super().__init__()
        self._engine = model.get_generic_engine(config.db_uri)
        self._sessionmaker = sqlalchemy.orm.sessionmaker(bind=self._engine)
        self._listen_uri = config.listen_uri
        self._zctx = zmq.asyncio.Context()
        self._task_queue = tasks.TaskQueue()
        self._processor = CoordinatorRequestProcessor(
            logger,
            self._task_queue,
            self._sessionmaker,
            config.unprivileged.ratelimit,
        )

    def _collect_tasks(self):
        with model.session_scope(self._sessionmaker) as session:
            ep_tasks = session.query(model.PendingScanTask.id_).filter(
                model.PendingScanTask.type_ == model.TaskType.DISCOVER_ENDPOINTS
            )
            for task_id, in ep_tasks:
                self._task_queue.push(self._processor._discover_endpoints,
                                      task_id)

    async def run(self):
        worker = RestartingTask(self._task_queue.run, logger=logger)
        worker.start()
        self._collect_tasks()
        try:
            sock = self._zctx.socket(zmq.REP)
            try:
                sock.bind(self._listen_uri)
                await self._processor.run(sock)
            finally:
                sock.close()
        finally:
            worker.stop()
