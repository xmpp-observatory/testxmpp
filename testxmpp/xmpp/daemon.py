import asyncio
import dataclasses
import logging
import typing

from datetime import timedelta

import OpenSSL.SSL

import aioopenssl
import aioxmpp

import testxmpp.common
import testxmpp.api.coordinator as coordinator_api


@dataclasses.dataclass
class ScanResult:
    pre_tls_features: aioxmpp.nonza.StreamFeatures = None
    post_tls_features: aioxmpp.nonza.StreamFeatures = None
    tls_offered: bool = False
    tls_negotiated: bool = False
    errno: int = None
    error: str = None


class CustomNonVerifier(aioxmpp.security_layer.PKIXCertificateVerifier):
    def verify_callback(self, ctx, x509, errno, errdepth, returncode):
        upstream_returncode = super().verify_callback
        return True


async def scan_xmpp(domain: aioxmpp.JID,
                    hostname: str,
                    port: int,
                    protocol: str,
                    tls_mode: str,
                    from_: typing.Optional[str],
                    negotiation_timeout: float):
    loop = asyncio.get_event_loop()

    result = ScanResult()

    namespace = {
        "c2s": "jabber:client",
        "s2s": "jabber:server",
    }[protocol]
    use_starttls = {
        "starttls": True,
        "direct": False,
    }[tls_mode]

    first_features_future = asyncio.Future()
    second_features = None
    stream = aioxmpp.protocol.XMLStream(
        default_namespace=namespace,
        from_=from_,
        to=domain,
        features_future=first_features_future,
    )
    verifier = CustomNonVerifier()

    def context_factory(transport):
        ssl_context = aioxmpp.security_layer.default_ssl_context()
        verifier.setup_context(ssl_context, transport)
        return ssl_context

    stream.deadtime_hard_limit = timedelta(seconds=negotiation_timeout)

    if not use_starttls:
        result.pre_tls_features = None
        result.tls_offered = True
        await verifier.pre_handshake(None, domain, hostname, port)

    try:
        transport, _ = await aioopenssl.create_starttls_connection(
            loop,
            lambda: stream,
            host=hostname,
            port=port,
            peer_hostname=hostname,
            server_hostname=str(domain).encode("idna").decode("ascii"),
            use_starttls=use_starttls,
            ssl_context_factory=context_factory,
            post_handshake_callback=verifier.post_handshake,
        )
    except OpenSSL.SSL.Error as exc:
        result.error = str(exc)
        stream.abort()
        return result
    except OSError as exc:
        result.errno = exc.errno
        result.error = exc.strerror
        stream.abort()
        return result
    except Exception as exc:  # NOQA
        stream.abort()
        raise

    first_features = await first_features_future
    if not use_starttls:
        result.post_tls_features = first_features
        result.tls_negotiated = True
    else:
        result.pre_tls_features = first_features

        try:
            first_features[aioxmpp.nonza.StartTLSFeature]
        except KeyError:
            result.tls_offered = False
        else:
            result.tls_offered = True

        # We always try STARTTLS, even if not offered!

        try:
            response = await aioxmpp.protocol.send_and_wait_for(
                stream,
                [
                    aioxmpp.nonza.StartTLS(),
                ],
                [
                    aioxmpp.nonza.StartTLSFailure,
                    aioxmpp.nonza.StartTLSProceed,
                ]
            )
        except aioxmpp.errors.StreamError as exc:
            result.error = str(exc)
        else:
            if isinstance(response, aioxmpp.nonza.StartTLSFailure):
                result.error = "received <failure/>"
            else:
                await verifier.pre_handshake(None, domain, hostname, port)
                try:
                    await stream.starttls(
                        ssl_context=context_factory(transport),
                        post_handshake_callback=verifier.post_handshake,
                    )
                except OpenSSL.SSL.Error as exc:
                    result.error = str(exc)
                    stream.abort()
                    return result
                else:
                    result.tls_negotiated = True

                    result.post_tls_features = \
                        await aioxmpp.protocol.reset_stream_and_get_features(
                            stream,
                            timeout=negotiation_timeout,
                        )

    try:
        await asyncio.wait_for(stream.close_and_wait(),
                               timeout=negotiation_timeout)
    except asyncio.TimeoutError:
        pass

    return result


def extract_sasl_mechanisms(features: aioxmpp.nonza.StreamFeatures):
    try:
        sasl = features[aioxmpp.security_layer.SASLMechanisms]
    except KeyError:
        return None

    return sasl.get_mechanism_list()


async def scan_features(domain: aioxmpp.JID,
                        hostname: str,
                        port: int,
                        protocol: str,
                        tls_mode: str,
                        from_: typing.Optional[str],
                        timeout: float):
    scan_result = await scan_xmpp(
        domain, hostname, port, protocol, tls_mode, from_,
        timeout,
    )

    result = {
        "tls_offered": scan_result.tls_offered or False,
        "tls_negotiated": scan_result.tls_negotiated or False,
        "error": scan_result.error,
        "errno": scan_result.errno,
        "pre_tls_sasl_mechanisms": None,
        "post_tls_sasl_mechanisms": None,
    }

    if scan_result.pre_tls_features is not None:
        result["pre_tls_sasl_mechanisms"] = extract_sasl_mechanisms(
            scan_result.pre_tls_features,
        )

    if scan_result.post_tls_features is not None:
        result["post_tls_sasl_mechanisms"] = extract_sasl_mechanisms(
            scan_result.post_tls_features,
        )

    return result


class XMPPWorker(testxmpp.common.Worker):
    def __init__(self, coordinator_uri, s2s_from):
        super().__init__(coordinator_uri, logging.getLogger(__name__))
        self._s2s_from = s2s_from

    def _mkjobrequest(self, worker_id):
        return coordinator_api.mkv1response(
            coordinator_api.RequestType.GET_XMPP_JOB,
            {
                "worker_id": worker_id,
            }
        )

    def _decode_job(self, resp):
        if resp["type"] == coordinator_api.ResponseType.GET_XMPP_JOB.value:
            return resp["payload"]

    async def _run_job(self, sock, job):
        job_id = job["job_id"]
        job = job["job"]
        if job["type"] == "features":
            result = await scan_features(
                aioxmpp.JID.fromstr(job["domain"]),
                job["hostname"],
                job["port"],
                job["protocol"],
                job["tls_mode"],
                None if job["protocol"] == "c2s" else self._s2s_from,
                10.0,
            )
            msg = coordinator_api.mkv1request(
                coordinator_api.RequestType.XMPP_COMPLETE,
                {
                    "job_id": job_id,
                    "worker_id": self.worker_id,
                    "xmpp_result": result,
                }
            )
            self.logger.debug("completed job %r: %r", job_id, msg)
            await sock.send_json(msg)
            resp = await sock.recv_json()
            if resp["type"] != coordinator_api.ResponseType.OK.value:
                self.logger.warning(
                    "coordinator rejected our result: %r",
                    resp
                )
