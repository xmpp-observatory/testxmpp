import base64
import hashlib
import hmac
import secrets

from datetime import datetime


class InvalidSignature(ValueError):
    pass


class ExpiredSignature(ValueError):
    pass


TXT_DATE_FORMAT = "%Y%m%dT%H%M%S"
HMAC_DATE_FORMAT = "%Y%m%dT%H%M%S"


def sign_user_secret(domain: bytes,
                     instance_secret: bytes,
                     user_secret: bytes,
                     valid_until: datetime) -> bytes:
    hash_input = [
        b"\x00",  # version identifier
        valid_until.strftime(HMAC_DATE_FORMAT).encode("ascii"),
        domain,
        b"\x00",  # separator which cannot occur in the domain name
        user_secret,
    ]
    return hmac.digest(
        instance_secret,
        b"".join(hash_input),
        hashlib.sha3_256,
    )


def generate_dnsauth_pair(domain: bytes,
                          instance_secret: bytes,
                          valid_until: datetime) -> (str, str):
    user_secret = secrets.token_bytes(128//8)
    signature = sign_user_secret(
        domain,
        instance_secret,
        user_secret,
        valid_until,
    )

    txt_record = "v0 {} {}".format(
        valid_until.strftime(TXT_DATE_FORMAT),
        base64.b64encode(signature).decode("ascii"),
    )
    return txt_record, base64.urlsafe_b64encode(user_secret)


def validate_dnsauth_pair(txt_record: str,
                          domain: bytes,
                          instance_secret: bytes,
                          user_secret: bytes,
                          now: datetime = None):
    if now is None:
        now = datetime.utcnow()

    version, *data = txt_record.split(" ")
    if version != "v0":
        raise ValueError("unknown signature version: {!r}".format(
            version
        ))

    valid_until_s, signature_b64 = data
    valid_until = datetime.strptime(valid_until_s, TXT_DATE_FORMAT)
    given_signature = base64.b64decode(signature_b64)
    expected_signature = sign_user_secret(
        domain,
        instance_secret,
        user_secret,
        valid_until,
    )

    if not hmac.compare_digest(given_signature, expected_signature):
        raise InvalidSignature(
            "signature is not valid for {!r} with the given key".format(
                domain.decode("ascii"),
            )
        )

    if valid_until < now:
        raise ExpiredSignature(
            "signature is valid but expired at {} "
            "(now is {})".format(valid_until.isoformat(), now.isoformat())
        )
