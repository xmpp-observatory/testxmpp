import abc

import schema


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
