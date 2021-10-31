import asyncio
import base64
import csv
import io
import logging
import secrets
import os
import re

import zmq
import zmq.asyncio

import pyasn1
import pyasn1_modules

import testxmpp.certutil
import testxmpp.common
import testxmpp.api.coordinator as coordinator_api


logger = logging.getLogger(__name__)


def decode_line(s):
    f = io.StringIO(s)
    data = list(csv.reader(f))[0]
    return data


ID_TLS_VERSION_RE = re.compile(
    r"^(SSLv2|SSLv3|TLS1(_[0-9]+)?)$"
)
ID_CIPHERLIST_RE = re.compile(
    r"^((cipherorder|supportedciphers)_(?P<tls_version>(SSLv2|SSLv3|TLSv1(_[123])?)))$"
)
ID_CERT_RE = re.compile(
    r"^cert$"
)
ID_INTERMEDIATE_RE = re.compile(
    r"^intermediate_cert <#(?P<chain_index>\d+)>$"
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
ID_PFS_CURVES_RE = re.compile(
    r"^PFS_ECDHE_curves$",
)
ID_IGNORE_RE = re.compile(
    r"^(cipher-.*|TLS_.*|sessionresumption_.*|protocol_negotiated|"
    r"cipher_negotiated)$"
)

CIPHER_COLUMN_SEP_RE = re.compile(r"\s\s+")


def unwrap_cert(cert: str) -> str:
    return cert.replace(
        " ", "\n",
    ).replace(
        "\nCERTIFICATE-", " CERTIFICATE-",
    )


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
    return ("certificate", unwrap_cert(finding))


def interpret_intermediate_cert(id_, severity, finding, id_match):
    data = id_match.groupdict()
    return ("intermediate-certificate",
            unwrap_cert(finding),
            int(data["chain_index"]))


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


def interpret_curves(id_, severity, finding, id_match):
    return ("ecdh-curves", finding.split())


def ignore(id_, severity, finding, id_match):
    pass


INTERPRETERS = [
    (ID_TLS_VERSION_RE, interpret_tls_version),
    (ID_CIPHERLIST_RE, interpret_cipherlist),
    (ID_CERT_RE, interpret_cert),
    (ID_INTERMEDIATE_RE, interpret_intermediate_cert),
    (ID_CIPHER_RE, interpret_cipher),
    (ID_CIPHER_OVERRIDE_RE, interpret_cipher_override),
    (ID_CLIENTSIMULATION_RE, interpret_clientsimulation),
    (ID_PFS_CURVES_RE, interpret_curves),
    (ID_IGNORE_RE, ignore),
]


def interpret_line(id_, severity, finding):
    for rx, interpreter in INTERPRETERS:
        m = rx.match(id_)
        if m is None:
            continue
        return interpreter(id_, severity, finding, m)

    logger.debug("no interpreter matched ID %r: %r %r", id_,
                 severity, finding)


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
        # stdout=asyncio.subprocess.DEVNULL,
        # stderr=asyncio.subprocess.DEVNULL,
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


class TestSSLWorker(testxmpp.common.Worker):
    def __init__(self, coordinator_uri, testssl_argv_base,
                 openssl_path):
        super().__init__(coordinator_uri, logger)
        self._testssl_argv_base = testssl_argv_base + [
            "--openssl", openssl_path,
        ]
        logger.debug("I will use %r", self._testssl_argv_base)

    def _mkjobrequest(self, worker_id):
        return coordinator_api.mkv1request(
            coordinator_api.RequestType.GET_TESTSSL_JOB,
            {
                "worker_id": worker_id,
            }
        )

    def _decode_job(self, resp):
        if resp["type"] == coordinator_api.ResponseType.GET_TESTSSL_JOB.value:
            return resp["payload"]

    async def _send_push_update(self, sock, job_id, data):
        msg = coordinator_api.mkv1request(
            coordinator_api.RequestType.TESTSSL_RESULT_PUSH,
            {
                "worker_id": self.worker_id,
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

    async def _run_job(self, sock, job):
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
            "intermediate_certificates": [],
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
                raw_der = testxmpp.certutil.unwrap_pem(info[0])
                result["certificate"] = {
                    "info": testxmpp.certutil.extract_cert_info(
                        testxmpp.certutil.decode_cert_der(raw_der)
                    ).to_json(),
                    "raw_der": base64.b64encode(raw_der).decode("ascii"),
                }
                await self._send_push_update(sock, job["job_id"], {
                    "type": "certificate",
                    "certificate": result["certificate"],
                })

            elif type_ == "intermediate-certificate":
                raw_der = testxmpp.certutil.unwrap_pem(info[0])
                cert_block = {
                    "index": info[1],
                    "info": testxmpp.certutil.extract_cert_info(
                        testxmpp.certutil.decode_cert_der(raw_der)
                    ).to_json(),
                    "raw_der": base64.b64encode(raw_der).decode("ascii"),
                }
                result["intermediate_certificates"].append(cert_block)
                await self._send_push_update(sock, job["job_id"], {
                    "type": "intermediate_certificate",
                    "certificate": cert_block,
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
                "worker_id": self.worker_id,
                "job_id": job["job_id"],
                "testssl_result": result,
            }
        )
        await sock.send_json(msg)
        resp = await sock.recv_json()
        if resp["type"] != coordinator_api.ResponseType.OK.value:
            self.logger.warning(
                "coordinator rejected our result: %r",
                resp
            )
