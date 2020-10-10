import abc
import asyncio
import secrets

import schema

import zmq
import zmq.asyncio

import testxmpp.api.coordinator as coordinator_api


class RequestProcessor(metaclass=abc.ABCMeta):
    def __init__(self,
                 request_schema, response_schema,
                 internal_server_error_response,
                 logger):
        super().__init__()
        self._request_schema = request_schema
        self._response_schema = response_schema
        self._ise_response = response_schema.validate(
            internal_server_error_response
        )
        self.logger = logger

    @abc.abstractmethod
    async def _handle_message(self, msg):
        pass

    @abc.abstractmethod
    async def _handle_schema_error(self, msg, exc):
        pass

    async def process_one(self, sock):
        msg = await sock.recv_json()
        try:
            msg = self._request_schema.validate(msg)
        except schema.SchemaError as exc:
            reply = await self._handle_schema_error(
                msg, exc,
            )
        else:
            try:
                reply = await self._handle_message(msg)
            except Exception as exc:
                self.logger.error(
                    "handler failed for message %r",
                    msg,
                    exc_info=True,
                )
                reply = self._ise_response

        try:
            reply = self._response_schema.validate(reply)
        except schema.SchemaError as exc:
            self.logger.error(
                "handler generated invalid response (%s): %r",
                exc, reply,
            )
            reply = self._ise_response

        await sock.send_json(reply)

    async def run(self, sock):
        while True:
            await self.process_one(sock)


class NoJob(Exception):
    def __init__(self, wait_time):
        super().__init__("no jobs available")
        self.wait_time = wait_time


class Worker:
    def __init__(self, coordinator_uri, logger):
        super().__init__()
        self.logger = logger
        self._coordinator_uri = coordinator_uri
        self._worker_id = secrets.token_hex(16)
        self._zctx = zmq.asyncio.Context()
        self.logger.debug("I am %s", self)

    @property
    def worker_id(self):
        return self._worker_id

    def __repr__(self):
        return "<{}.{} id={!r} coordinator_uri={!r}>".format(
            type(self).__module__,
            type(self).__qualname__,
            self._worker_id,
            self._coordinator_uri,
        )

    @abc.abstractmethod
    def _mkjobrequest(self, worker_id):
        pass

    @abc.abstractmethod
    def _decode_job(self, response):
        pass

    async def _get_job(self, sock) -> int:
        await sock.send_json(self._mkjobrequest(self._worker_id))
        resp = coordinator_api.api_response.validate(await sock.recv_json())
        if resp["type"] == coordinator_api.ResponseType.NO_TASKS.value:
            raise NoJob(resp["payload"]["ask_again_after"])

        result = self._decode_job(resp)
        if result is None:
            raise RuntimeError("unexpected server reply: {!r}".format(resp))

        return result

    @abc.abstractmethod
    async def _run_job(self, coordinator_sock, job):
        pass

    async def _get_and_run_job(self, coordinator_sock):
        try:
            job = await self._get_job(coordinator_sock)
        except NoJob as exc:
            self.logger.debug("no job, waiting for %ds", exc.wait_time)
            return exc.wait_time

        await self._run_job(coordinator_sock, job)
        return 1

    async def run(self):
        sleep_interval = 1
        coordinator_sock = self._zctx.socket(zmq.REQ)
        try:
            self.logger.debug("talking to coordinator at %r",
                              self._coordinator_uri)
            coordinator_sock.connect(self._coordinator_uri)
            while True:
                try:
                    sleep_interval = await self._get_and_run_job(
                        coordinator_sock
                    )
                except Exception:
                    sleep_interval = min(sleep_interval * 2, 60)
                    self.logger.error(
                        "failed to get or run job. trying again in %d "
                        "seconds",
                        exc_info=True,
                    )

                await asyncio.sleep(sleep_interval)
        finally:
            coordinator_sock.close()
