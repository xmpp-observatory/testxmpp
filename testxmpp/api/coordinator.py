import enum

from schema import Schema, Or

from .common import error


def _worker_id(s):
    if not isinstance(s, str):
        return False
    return 32 <= len(s) <= 128


class RequestType(enum.Enum):
    PING = "ping"

    # From the frontend
    SCAN_DOMAIN = "scan_domain"

    # From workers
    JOB_HEARTBEAT = "job-heartbeat"

    # From testssl workers
    GET_TESTSSL_JOB = "get-testssl-job"
    TESTSSL_RESULT_PUSH = "testssl-result-push"
    TESTSSL_COMPLETE = "testssl-complete"

    # From xmpp workers
    GET_XMPP_JOB = "get-xmpp-job"
    XMPP_COMPLETE = "xmpp-complete"


class ResponseType(enum.Enum):
    ERROR = "error"
    PONG = "pong"
    OK = "ok"
    NO_TASKS = "no-tasks"

    SCAN_QUEUED = "scan-queued"

    GET_TESTSSL_JOB = "get-testssl-job"
    GET_XMPP_JOB = "get-xmpp-job"
    JOB_CONFIRMATION = "job-confirmation"


cipher_info = Schema({
    "id": int,
    "openssl_name": str,
    "key_exchange": str,
    "symmetric_cipher": {
        "name": str,
        "bits": int,
    },
    "iana_name": str,
})

cert_name = Schema([
    {
        str: str,
    }
])

certificate_info = Schema({
    "subject": cert_name,
    "issuer": cert_name,
    "subject_alt_names": Or({
        str: [str],
    }, None),
    "not_before": str,
    "not_after": str,
    "public_key": str,
    "public_key_type": str,
    "fingerprints": {
        str: str,
    },
})

gen_echo = Schema({})

req_scan_domain = Schema({
    "domain": str,
    "protocol": Or("c2s", "s2s"),
})

req_get_testssl_job = Schema({
    "worker_id": _worker_id,
})

req_job_heartbeat = Schema({
    "worker_id": _worker_id,
    "job_id": str,
})

_testssl_data = Schema(Or(
    {
        "type": "tls_versions",
        "tls_versions": {
            str: bool,
        },
    },
    {
        "type": "cipherlists",
        "cipherlists": {
            str: [str],
        }
    },
    {
        "type": "server_cipher_order",
        "server_cipher_order": bool,
    },
    {
        "type": "cipher_info",
        "cipher": cipher_info,
    },
    {
        "type": "certificate",
        "certificate": {
            "info": certificate_info,
            "raw_der": str,
        },
    },
    {
        "type": "intermediate_certificate",
        "certificate": {
            "index": int,
            "info": certificate_info,
            "raw_der": str,
        },
    },
))

req_testssl_result_push = Schema({
    "worker_id": _worker_id,
    "job_id": str,
    "testssl_data": _testssl_data,
})

req_testssl_complete = Schema({
    "worker_id": _worker_id,
    "job_id": str,
    "testssl_result": {
        "tls_versions": {str: bool},
        "cipherlists": {str: [str]},
        "certificate": {
            "info": certificate_info,
            "raw_der": str,
        },
        "intermediate_certificates": [{
            "index": int,
            "info": certificate_info,
            "raw_der": str,
        }],
        "server_cipher_order": bool,
        "ciphers": [cipher_info],
    }
})

req_get_xmpp_job = Schema({
    "worker_id": _worker_id,
})

rep_ok = Schema({})

rep_scan_queued = Schema({
    "scan_id": int,
})

rep_get_testssl_job = Schema({
    "job_id": str,
    "domain": str,
    "hostname": str,
    "port": int,
    "protocol": Or("c2s", "s2s"),
    "tls_mode": Or("starttls", "direct"),
})

rep_get_xmpp_job = Schema({
    "job_id": str,
    "job": Schema(Or(
        {
            "type": "features",
            "domain": str,
            "hostname": str,
            "port": int,
            "protocol": Or("c2s", "s2s"),
            "tls_mode": Or("starttls", "direct"),
        },
    )),
})

req_xmpp_complete = Schema({
    "worker_id": str,
    "job_id": str,
    "xmpp_result": {
        "tls_offered": bool,
        "tls_negotiated": bool,
        "error": Or(None, str),
        "errno": Or(None, int),
        "pre_tls_sasl_mechanisms": Or(None, [str]),
        "post_tls_sasl_mechanisms": Or(None, [str]),
    }
})

rep_no_tasks = Schema({
    "ask_again_after": int,
})

rep_job_confirmation = Schema({
    "continue": bool,
})

_V1_API_VERSION = "coordinator/v1"

api_request = Schema(Or(
    {
        "api_version": _V1_API_VERSION,
        "type": RequestType.PING.value,
        "payload": gen_echo,
    },
    {
        "api_version": _V1_API_VERSION,
        "type": RequestType.SCAN_DOMAIN.value,
        "payload": req_scan_domain,
    },
    {
        "api_version": _V1_API_VERSION,
        "type": RequestType.GET_TESTSSL_JOB.value,
        "payload": req_get_testssl_job,
    },
    {
        "api_version": _V1_API_VERSION,
        "type": RequestType.JOB_HEARTBEAT.value,
        "payload": req_job_heartbeat,
    },
    {
        "api_version": _V1_API_VERSION,
        "type": RequestType.TESTSSL_RESULT_PUSH.value,
        "payload": req_testssl_result_push,
    },
    {
        "api_version": _V1_API_VERSION,
        "type": RequestType.TESTSSL_COMPLETE.value,
        "payload": req_testssl_complete,
    },
    {
        "api_version": _V1_API_VERSION,
        "type": RequestType.GET_XMPP_JOB.value,
        "payload": req_get_xmpp_job,
    },
    {
        "api_version": _V1_API_VERSION,
        "type": RequestType.XMPP_COMPLETE.value,
        "payload": req_xmpp_complete,
    },
))

api_response = Schema(Or(
    {
        "api_version": _V1_API_VERSION,
        "type": ResponseType.PONG.value,
        "payload": gen_echo,
    },
    {
        "api_version": _V1_API_VERSION,
        "type": ResponseType.ERROR.value,
        "payload": error,
    },
    {
        "api_version": _V1_API_VERSION,
        "type": ResponseType.SCAN_QUEUED.value,
        "payload": rep_scan_queued,
    },
    {
        "api_version": _V1_API_VERSION,
        "type": ResponseType.OK.value,
        "payload": rep_ok,
    },
    {
        "api_version": _V1_API_VERSION,
        "type": ResponseType.GET_TESTSSL_JOB.value,
        "payload": rep_get_testssl_job,
    },
    {
        "api_version": _V1_API_VERSION,
        "type": ResponseType.NO_TASKS.value,
        "payload": rep_no_tasks,
    },
    {
        "api_version": _V1_API_VERSION,
        "type": ResponseType.JOB_CONFIRMATION.value,
        "payload": rep_job_confirmation,
    },
    {
        "api_version": _V1_API_VERSION,
        "type": ResponseType.GET_XMPP_JOB.value,
        "payload": rep_get_xmpp_job,
    },
))


def mkv1request(type_, payload):
    return {
        "api_version": _V1_API_VERSION,
        "type": type_.value,
        "payload": payload,
    }


def mkv1response(type_, payload):
    return {
        "api_version": _V1_API_VERSION,
        "type": type_.value,
        "payload": payload,
    }
