import enum

from schema import Schema, Or


class ErrorCode(enum.Enum):
    BAD_REQUEST = 400
    TOO_MANY_REQUESTS = 429

    INTERNAL_ERROR = 500


error = Schema({
    "code": Or(*(ec.value for ec in ErrorCode)),
    "message": Or(str, None),
})


def mkerror(code, message=None):
    return {
        "code": code.value,
        "message": message or None,
    }
