import asyncio
import binascii
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
import testxmpp.coordinator.endpoints
import testxmpp.coordinator.testssl
import testxmpp.api.common as common_api
import testxmpp.api.coordinator as coordinator_api

from . import tasks
from .common import generate_task_id


logger = logging.getLogger(__name__)


HEARTBEAT_THRESOHLD = timedelta(minutes=1)


def encode_task_id(id_: bytes) -> str:
    return binascii.b2a_hex(id_).decode("ascii")


def decode_task_id(id_: str) -> bytes:
    return binascii.a2b_hex(id_)


def encode_worker_id(id_: bytes) -> str:
    return binascii.b2a_hex(id_).decode("ascii")


def decode_worker_id(id_: str) -> bytes:
    return binascii.a2b_hex(id_)


class ExponentialBackOff:
    def __init__(self, base=2, start=1, max_=120, retry_limit=5):
        super().__init__()
        self.start = start
        self.max_ = max_
        self.base = base
        self.retry_limit = retry_limit
        self._is_failing = False
        self._current = self.start
        self._retry_count = 0

    def __iter__(self):
        return self

    def __next__(self):
        if self._retry_count >= self.retry_limit:
            raise StopIteration
        self._is_failing = True
        val = self._current
        self._current = min(self._current * self.base, self.max_)
        self._retry_count += 1
        return val

    def next(self):
        return next(self)

    def reset(self):
        self._current = self.start
        self._retry_count = 0

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


def get_or_create_sasl_mechanism(
        session,
        name: str,
        *,
        cache: typing.Optional[
            typing.MutableMapping[str, model.SASLMechanism]
        ] = None):
    if cache is not None:
        try:
            return cache[name]
        except KeyError:
            pass

    try:
        result = session.query(model.SASLMechanism).filter(
            model.SASLMechanism.name == name,
        ).one()
    except sqlalchemy.orm.exc.NoResultFound:
        result = model.SASLMechanism()
        result.name = name
        session.add(result)
    if cache is not None:
        cache[name] = result
    return result


def add_sasl_mechanisms(session,
                        phase: model.ConnectionPhase,
                        mechanisms: typing.List[str],
                        result: model.EndpointScanResult,
                        sasl_mechanism_cache: typing.MutableMapping[
                            str, model.SASLMechanism,
                        ],
                        ):
    for mech in mechanisms:
        entry = model.EndpointScanSASLOffering()
        entry.endpoint_scan_result = result
        entry.phase = phase
        entry.sasl_mechanism = get_or_create_sasl_mechanism(
            session, mech,
            cache=sasl_mechanism_cache,
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
            task = session.query(model.ScanTask).filter(
                model.ScanTask.id_ == task_id
            ).one()
            scan = task.scan
            scan_id = scan.id_
            scan_domain = scan.domain
            scan_protocol = scan.protocol

        db_objects = await testxmpp.coordinator.endpoints.discover_endpoints(
            scan_id,
            scan_domain,
            scan_protocol,
        )

        with model.session_scope(self._sessionmaker) as session:
            taskq = session.query(model.ScanTask).filter(
                model.ScanTask.id_ == task_id
            )
            try:
                task = taskq.one()
            except sqlalchemy.orm.exc.NoResultFound:
                # task has been done by another worker already.
                return
            task.mark_completed(session)

            # delete possibly pre-existing tasks
            session.query(model.ScanTask).filter(
                model.ScanTask.type_ == model.TaskType.XMPP_PROBE,
                model.ScanTask.scan_id == scan_id,
            ).delete()
            session.query(model.ScanTask).filter(
                model.ScanTask.type_ == model.TaskType.SELECT_ENDPOINTS,
                model.ScanTask.scan_id == scan_id,
            ).delete()

            # delete endpoints if there exist any
            # this is to handle parallel executions of the same task
            # gracefully
            session.query(model.Endpoint).filter(
                model.Endpoint.scan_id == task.scan_id,
            ).delete()

            selection_task = model.ScanTask()
            selection_task.id_ = generate_task_id()
            selection_task.scan_id = task.scan_id
            selection_task.type_ = model.TaskType.SELECT_ENDPOINTS
            selection_task.state = model.TaskState.WAITING
            session.add(selection_task)

            def add_task(task):
                # XXX: this needs to go if/when we support http probes
                if task.state == model.TaskState.WAITING:
                    dep = model.ScanTaskDependency()
                    dep.parent_task = task
                    dep.child_task = selection_task
                    session.add(dep)
                session.add(task)

            for obj in db_objects:
                session.add(obj)
                if isinstance(obj, model.EndpointTCP):
                    scan_task = model.ScanTask()
                    scan_task.id_ = generate_task_id()
                    scan_task.scan_id = task.scan_id
                    scan_task.endpoint = obj
                    scan_task.type_ = model.TaskType.XMPP_PROBE
                    scan_task.state = model.TaskState.WAITING
                    add_task(scan_task)
                elif isinstance(obj, model.EndpointHTTP):
                    scan_task = model.ScanTask()
                    scan_task.id_ = generate_task_id()
                    scan_task.scan_id = task.scan_id
                    scan_task.endpoint = obj
                    scan_task.type_ = model.TaskType.XMPP_PROBE
                    scan_task.state = model.TaskState.FAILED
                    scan_task.fail_reason = model.FailReason.UNSUPPORTED
                    add_task(scan_task)

            session.commit()

    def _handle_testssl_push(self, worker_id, job_id, testssl_data) -> bool:
        data_type = testssl_data["type"]
        testssl = testxmpp.coordinator.testssl
        handler = {
            "tls_versions": testssl.handle_tls_versions_push,
            "cipherlists": testssl.handle_cipherlists_push,
            "server_cipher_order": testssl.handle_server_cipher_order_push,
            "cipher_info": testssl.handle_cipher_info_push,
            "certificate": testssl.handle_certificate_push,
            "intermediate_certificate": testssl.handle_certificate_push,
        }.get(data_type, None)
        if handler is None:
            raise RuntimeError("unhandled testssl push data type: {!r}".format(
                data_type
            ))

        with model.session_scope(self._sessionmaker) as session:
            try:
                task = session.query(model.ScanTask).filter(
                    model.ScanTask.id_ == job_id,
                ).one()
            except sqlalchemy.orm.exc.NoResultFound:
                return False

            if task.assigned_worker != worker_id:
                # late worker?
                return False

            if not handler(session, task.endpoint_id, testssl_data):
                # allow immediate rescheduling of the task
                task.heartbeat = None
                return False

            task.heartbeat = datetime.utcnow()
            session.commit()

        return True

    def _handle_testssl_result(self, worker_id, job_id, result):
        testssl = testxmpp.coordinator.testssl
        with model.session_scope(self._sessionmaker) as session:
            try:
                task = session.query(model.ScanTask).filter(
                    model.ScanTask.id_ == job_id,
                ).one()
            except sqlalchemy.orm.exc.NoResultFound:
                return

            if task.assigned_worker != worker_id:
                # late worker?
                return

            endpoint_id = task.endpoint_id

            testssl.handle_tls_versions_push(
                session, endpoint_id, result,
            )
            testssl.handle_certificate_push(
                session, endpoint_id, result,
            )
            for intermediate in result["intermediate_certificates"]:
                testssl.handle_certificate_push(
                    session, endpoint_id, {"certificate": intermediate},
                )
            testssl.handle_server_cipher_order_push(
                session, endpoint_id, result,
            )
            for cipher_info in result["ciphers"]:
                testssl.handle_cipher_info_push(
                    session, endpoint_id, {"cipher": cipher_info},
                )
            testssl.handle_cipherlists_complete(
                session, endpoint_id, result["cipherlists"],
            )

            task.mark_completed(session)
            session.commit()

    async def _handle_xmpp_result(self, worker_id, job_id, result):
        with model.session_scope(self._sessionmaker) as session:
            try:
                task = session.query(model.ScanTask).filter(
                    model.ScanTask.id_ == job_id,
                ).one()
            except sqlalchemy.orm.exc.NoResultFound:
                return False

            if task.assigned_worker != worker_id:
                # late worker?
                return False

            task.mark_completed(session)

            # This is needed to avoid conflicts when adding the same SASL
            # mechanism pre- and post-TLS.
            sasl_mech_cache = {}

            scan_id = task.scan_id
            endpoint_result = model.EndpointScanResult()
            endpoint_result.endpoint_id = task.endpoint_id
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
                                    endpoint_result,
                                    sasl_mechanism_cache=sasl_mech_cache)
            else:
                endpoint_result.sasl_pre_tls = False

            if result["post_tls_sasl_mechanisms"] is not None:
                endpoint_result.sasl_post_tls = True
                add_sasl_mechanisms(session,
                                    model.ConnectionPhase.POST_TLS,
                                    result["post_tls_sasl_mechanisms"],
                                    endpoint_result,
                                    sasl_mechanism_cache=sasl_mech_cache)
            else:
                endpoint_result.sasl_post_tls = False

            session.commit()

        return True

    async def _select_endpoints(self, task_id):
        with model.session_scope(self._sessionmaker) as session:
            testxmpp.coordinator.endpoints.select_endpoints(session, task_id)
            session.commit()

    def _poll_local_tasks(self, session=None):
        with model.session_scope(self._sessionmaker) as session:
            open_tasks = model.ScanTask.available_tasks(session, None).filter(
                sqlalchemy.or_(
                    model.ScanTask.type_ == model.TaskType.DISCOVER_ENDPOINTS,
                    model.ScanTask.type_ == model.TaskType.RESOLVE_TLSA,
                    model.ScanTask.type_ == model.TaskType.SELECT_ENDPOINTS,
                ),
            )

            task_handlers = {
                model.TaskType.DISCOVER_ENDPOINTS: self._discover_endpoints,
                model.TaskType.SELECT_ENDPOINTS: self._select_endpoints,
            }

            queue_items = []

            now = datetime.utcnow()
            for task in open_tasks:
                task.heartbeat = now
                queue_items.append((task_handlers[task.type_], task.id_))

            session.commit()

        for func, data in queue_items:
            self._task_queue.push(func, data)

    def _try_poll_local_tasks(self):
        try:
            self._poll_local_tasks()
        except Exception as exc:
            self.logger.error("failed to enqueue local tasks",
                              exc_info=True)

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

                ep_task = model.ScanTask()
                ep_task.id_ = generate_task_id()
                ep_task.scan = scan
                ep_task.type_ = model.TaskType.DISCOVER_ENDPOINTS
                ep_task.state = model.TaskState.WAITING
                session.add(ep_task)

                session.commit()
                scan_id = scan.id_

            self._try_poll_local_tasks()
            return coordinator_api.mkv1response(
                coordinator_api.ResponseType.SCAN_QUEUED,
                {
                    "scan_id": scan_id,
                },
            )

        elif msg["type"] == coordinator_api.RequestType.GET_TESTSSL_JOB.value:
            cutoff = datetime.utcnow() - HEARTBEAT_THRESOHLD
            worker_id = msg["payload"]["worker_id"]

            with model.session_scope(self._sessionmaker) as session:
                task = model.ScanTask.available_tasks(session, cutoff).filter(
                    model.ScanTask.type_ == model.TaskType.TLS_SCAN,
                ).order_by(
                    model.ScanTask.heartbeat.asc()
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
                    "job_id": encode_task_id(task.id_),
                    "domain": scan.domain.decode("utf-8"),
                    "hostname": task.endpoint.hostname.decode("ascii"),
                    "port": task.endpoint.port,
                    "protocol": scan.protocol.value,
                    "tls_mode": task.endpoint.tls_mode.value,
                }

                task.assigned_worker = decode_worker_id(worker_id)
                task.heartbeat = datetime.utcnow()
                session.commit()

                return coordinator_api.mkv1response(
                    coordinator_api.ResponseType.GET_TESTSSL_JOB,
                    job,
                )

        elif msg["type"] == coordinator_api.RequestType.GET_XMPP_JOB.value:
            cutoff = datetime.utcnow() - HEARTBEAT_THRESOHLD
            worker_id = decode_worker_id(msg["payload"]["worker_id"])

            with model.session_scope(self._sessionmaker) as session:
                task = model.ScanTask.available_tasks(session, cutoff).filter(
                    model.ScanTask.type_ == model.TaskType.XMPP_PROBE,
                ).order_by(
                    model.ScanTask.heartbeat.asc()
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
                    "hostname": task.endpoint.hostname.decode("ascii"),
                    "port": task.endpoint.port,
                    "tls_mode": task.endpoint.tls_mode.value,
                    "protocol": scan.protocol.value,
                }
                job = {
                    "job_id": encode_task_id(task.id_),
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
            job_id = decode_task_id(msg["payload"]["job_id"])
            worker_id = decode_worker_id(msg["payload"]["worker_id"])
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
            job_id = decode_task_id(msg["payload"]["job_id"])
            worker_id = decode_worker_id(msg["payload"]["worker_id"])
            result = msg["payload"]["testssl_result"]

            self._handle_testssl_result(
                worker_id,
                job_id,
                result,
            )

            self._try_poll_local_tasks()
            return coordinator_api.mkv1response(
                coordinator_api.ResponseType.OK,
                {}
            )

        elif msg["type"] == coordinator_api.RequestType.XMPP_COMPLETE.value:
            job_id = decode_task_id(msg["payload"]["job_id"])
            worker_id = decode_worker_id(msg["payload"]["worker_id"])
            result = msg["payload"]["xmpp_result"]

            ok = await self._handle_xmpp_result(
                worker_id,
                job_id,
                result,
            )
            self._try_poll_local_tasks()
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

    async def run(self):
        worker = RestartingTask(self._task_queue.run, logger=logger)
        worker.start()
        self._processor._try_poll_local_tasks()
        try:
            sock = self._zctx.socket(zmq.REP)
            try:
                sock.bind(self._listen_uri)
                await self._processor.run(sock)
            finally:
                sock.close()
        finally:
            worker.stop()
