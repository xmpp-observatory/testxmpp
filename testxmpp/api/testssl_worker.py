import enum

from schema import Schema, Or


class RequestType(enum.Enum):
    PING = "ping"
    SCAN_ENDPOINT = "scan_endpoint"


class ResponseType(enum.Enum):
    ERROR = "error"
    PONG = "pong"
    OK = "ok"


gen_echo = Schema({})

rep_error = Schema({
    "code": int,
    "message": str,
})

req_scan_endpoint = Schema({
    "hostname": str,
    "port": int,
    "protocol": Or("xmpp-client", "xmpp-server", "direct-tls"),
})

rep_ok = Schema({})

api_request = Schema(Or(
    {
        "api_version": "v1/testsslworker",
        "type": RequestType.PING.value,
        "payload": gen_echo,
    },
    {
        "api_version": "v1/testsslworker",
        "type": RequestType.SCAN_ENDPOINT.value,
        "payload": req_scan_endpoint,
    },
))

api_response = Schema(Or(
    {
        "api_version": "v1/testsslworker",
        "type": ResponseType.PONG.value,
        "payload": gen_echo,
    },
    {
        "api_version": "v1/testsslworker",
        "type": ResponseType.ERROR.value,
        "payload": rep_error,
    },
    {
        "api_version": "v1/testsslworker",
        "type": ResponseType.OK.value,
        "payload": rep_ok,
    },
))


def mkv1request(type_, payload):
    return {
        "api_version": "v1/testsslworker",
        "type": type_.value,
        "payload": payload,
    }


def mkv1response(type_, payload):
    return {
        "api_version": "v1/testsslworker",
        "type": type_.value,
        "payload": payload,
    }
