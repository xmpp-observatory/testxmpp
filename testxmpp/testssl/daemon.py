import asyncio
import csv
import io
import logging
import secrets
import os
import re

import zmq
import zmq.asyncio

import testxmpp.api.coordinator as coordinator_api

from .config import schema as config_schema


logger = logging.getLogger(__name__)


class NoJob(Exception):
    def __init__(self, wait_time):
        super().__init__("no jobs available")
        self.wait_time = wait_time


def decode_line(s):
    f = io.StringIO(s)
    data = list(csv.reader(f))[0]
    return data


ID_TLS_VERSION_RE = re.compile(
    r"^(SSLv2|SSLv3|TLS1(_[0-9]+)?)$"
)
ID_CIPHERLIST_RE = re.compile(
    r"^(cipherorder_(?P<tls_version>TLSv1_[23]))$"
)
ID_CERT_RE = re.compile(
    r"^cert$"
)
ID_CIPHER_RE = re.compile(
    r"^cipher_x(?P<cipher_id>[0-9a-f]+)$"
)
ID_CIPHER_OVERRIDE_RE = re.compile(
    r"^cipher_order$"
)
ID_CLIENTSIMULATION_RE = re.compile(
    r"^clientsimulation-(?P<client_name>.+)$"
)

CIPHER_COLUMN_SEP_RE = re.compile(r"\s\s+")


def interpret_tls_version(id_, severity, finding, id_match):
    supported = "not" not in finding
    if id_.startswith("TLS") and not id_.startswith("TLSv"):
        id_ = "TLSv" + id_[3:]
    return ("tls-version-support", id_.replace("_", "."), supported)


def interpret_cipherlist(id_, severity, finding, id_match):
    data = id_match.groupdict()
    return ("cipherlist",
            data["tls_version"].replace("_", "."),
            finding.split())


def interpret_cert(id_, severity, finding, id_match):
    return ("certificate", finding.replace(" ", "\n"))


def interpret_cipher(id_, severity, finding, id_match):
    data = id_match.groupdict()
    columns = CIPHER_COLUMN_SEP_RE.split(finding)
    _, openssl_name, kex, symm, symm_bits, iana_name = columns
    return ("cipher-offered", {
        "id": int(data["cipher_id"], 16),
        "openssl_name": openssl_name,
        "key_exchange": kex,
        "symmetric_cipher": {
            "name": symm,
            "bits": int(symm_bits),
        },
        "iana_name": iana_name,
    })


def interpret_cipher_override(id_, severity, finding, id_match):
    return ("server-cipher-order", finding.lower() == "server")


def interpret_clientsimulation(id_, severity, finding, id_match):
    data = id_match.groupdict()
    tls_version, cipher, *_ = finding.split()
    return ("client-simulation", data["client_name"], tls_version, cipher)


INTERPRETERS = [
    (ID_TLS_VERSION_RE, interpret_tls_version),
    (ID_CIPHERLIST_RE, interpret_cipherlist),
    (ID_CERT_RE, interpret_cert),
    (ID_CIPHER_RE, interpret_cipher),
    (ID_CIPHER_OVERRIDE_RE, interpret_cipher_override),
    (ID_CLIENTSIMULATION_RE, interpret_clientsimulation),
]


def interpret_line(id_, severity, finding):
    for rx, interpreter in INTERPRETERS:
        m = rx.match(id_)
        if m is None:
            continue
        return interpreter(id_, severity, finding, m)

    logger.debug("no interpreter matched ID %r", id_)


async def line_communicate(proc, reader, writer_fd):
    proc_done = asyncio.ensure_future(proc.wait())
    next_line = asyncio.ensure_future(reader.readline())

    pending = [proc_done, next_line]
    while pending:
        done, pending = await asyncio.wait(
            pending,
            return_when=asyncio.FIRST_COMPLETED,
        )
        if next_line in done:
            yield (await next_line)
        if proc_done in done:
            os.close(writer_fd)
        if not reader.at_eof() and next_line not in pending:
            next_line = asyncio.ensure_future(reader.readline())
            pending = list(pending) + [next_line]


async def run_testssl(testssl, domain, hostname, port, starttls):
    loop = asyncio.get_event_loop()

    piper, pipew = os.pipe()

    pipe_reader = asyncio.StreamReader()
    await loop.connect_read_pipe(
        lambda: asyncio.StreamReaderProtocol(pipe_reader),
        os.fdopen(piper, mode="rb"),
    )

    argv = testssl + [
        "--csvfile", "/proc/self/fd/{}".format(pipew),
        "-p",
        "-e",
        "-S",
        "-P",
        "-c",
        "--xmpphost", domain,
    ]
    if starttls is not None:
        argv.append("--starttls")
        argv.append(starttls)
    argv.append("{}:{}".format(hostname, port))

    logger.debug("spawning testssl with %r", argv)
    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
        pass_fds=[pipew],
    )

    try:
        async for line in line_communicate(proc, pipe_reader, pipew):
            if not line:
                continue
            try:
                id_, _, _, severity, finding, _, _ = decode_line(
                    line.decode("utf-8")
                )
            except (ValueError, IndexError) as exc:
                logger.warning("failed to decode output line %r (%s)",
                               line, exc)
                continue

            msg = interpret_line(id_, severity, finding)
            if msg is not None:
                yield msg

        if proc.returncode != 0:
            logger.info("testssl failed!")
    finally:
        if proc.returncode is None:
            proc.kill()
            await proc.wait()


class TestSSLWorker:
    def __init__(self, config):
        super().__init__()
        config = config_schema.validate(config)
        self._coordinator_url = config["zmq"]["coordinator_url"]
        self._max_parallelism = config["scan"]["parallelism"]
        self._testssl_argv_base = config["scan"]["testssl"]
        self._worker_id = secrets.token_hex(16)

        self._zctx = zmq.asyncio.Context()

    async def _get_job(self, sock):
        await sock.send_json(
            coordinator_api.mkv1request(
                coordinator_api.RequestType.GET_TESTSSL_JOB,
                {
                    "worker_id": self._worker_id,
                }
            )
        )
        resp = coordinator_api.api_response.validate(await sock.recv_json())
        if resp["type"] == coordinator_api.ResponseType.GET_TESTSSL_JOB.value:
            return resp["payload"]
        elif resp["type"] == coordinator_api.ResponseType.NO_TASKS.value:
            raise NoJob(resp["payload"]["ask_again_after"])
        else:
            raise RuntimeError("unexpected server reply: %r".format(resp))

    async def _send_push_update(self, sock, job_id, data):
        msg = coordinator_api.mkv1request(
            coordinator_api.RequestType.TESTSSL_RESULT_PUSH,
            {
                "worker_id": self._worker_id,
                "job_id": job_id,
                "testssl_data": data,
            }
        )

        await sock.send_json(msg)
        response = await sock.recv_json()
        if (response["type"] !=
                coordinator_api.ResponseType.JOB_CONFIRMATION.value):
            raise RuntimeError(
                "unexpected push reply: {!r}".format(response)
            )

        if not response["payload"]["continue"]:
            raise RuntimeError("cancelled job at server request")

    async def _get_and_run_job(self, sock):
        logger.debug("fetching job")
        try:
            job = await self._get_job(sock)
        except NoJob as exc:
            logger.debug("no job, waiting for %d", exc.wait_time)
            return exc.wait_time

        logger.info("got job: %r", job)
        if job["tls_mode"] == "starttls":
            if job["protocol"] == "c2s":
                starttls = "xmpp"
            else:
                starttls = "xmpp-server"
        else:
            starttls = None

        result = {
            "tls_versions": {},
            "cipherlists": {},
            "certificate": None,
            "server_cipher_order": False,
            "ciphers": []
        }

        async for info_blob in run_testssl(self._testssl_argv_base,
                                           job["domain"],
                                           job["hostname"],
                                           job["port"],
                                           starttls):
            type_, *info = info_blob
            if type_ == "tls-version-support":
                tls_version, supported = info
                result["tls_versions"][tls_version] = supported
                await self._send_push_update(sock, job["job_id"], {
                    "type": "tls_versions",
                    "tls_versions": result["tls_versions"],
                })

            elif type_ == "server-cipher-order":
                result["server_cipher_order"] = info[0]
                await self._send_push_update(sock, job["job_id"], {
                    "type": "server_cipher_order",
                    "server_cipher_order": result["server_cipher_order"],
                })

            elif type_ == "cipherlist":
                tls_version, ciphers = info
                result["cipherlists"][tls_version] = ciphers
                await self._send_push_update(sock, job["job_id"], {
                    "type": "cipherlists",
                    "cipherlists": result["cipherlists"],
                })

            elif type_ == "certificate":
                result["certificate"] = info[0]
                await self._send_push_update(sock, job["job_id"], {
                    "type": "certificate",
                    "certificate": result["certificate"],
                })

            elif type_ == "cipher-offered":
                result["ciphers"].append(info[0])
                await self._send_push_update(sock, job["job_id"], {
                    "type": "cipher_info",
                    "cipher": info[0],
                })

        msg = coordinator_api.mkv1request(
            coordinator_api.RequestType.TESTSSL_COMPLETE,
            {
                "worker_id": self._worker_id,
                "job_id": job["job_id"],
                "testssl_result": result,
            }
        )
        await sock.send_json(msg)
        await sock.recv_json()
        # we don’t care about the reply

        return 1

    async def run(self):
        sleep_interval = 1
        coordinator_sock = self._zctx.socket(zmq.REQ)
        try:
            logger.debug("talking to coordinator at %r",
                         self._coordinator_url)
            coordinator_sock.connect(self._coordinator_url)
            while True:
                try:
                    sleep_interval = await self._get_and_run_job(
                        coordinator_sock
                    )
                except Exception:
                    sleep_interval = min(sleep_interval * 2, 60)
                    logger.error(
                        "failed to get or run job. trying again in %d "
                        "seconds",
                        exc_info=True,
                    )

                await asyncio.sleep(sleep_interval)
        finally:
            coordinator_sock.close()
