import base64
import secrets
import unittest

from datetime import datetime, timedelta

from . import auth


class TestSignature(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.instance_secret = secrets.token_bytes(8)

    def setUp(self):
        self.NOW = datetime(2020, 10, 2, 14, 0, 0)
        self.domain = b"chat.example."

    def test_sign_and_validate(self):
        txt, user = auth.generate_dnsauth_pair(
            self.domain,
            self.instance_secret,
            self.NOW + timedelta(seconds=1)
        )
        auth.validate_dnsauth_pair(
            txt,
            self.domain,
            self.instance_secret,
            base64.urlsafe_b64decode(user),
            now=self.NOW,
        )

    def test_reject_domain_mismatch(self):
        txt, user = auth.generate_dnsauth_pair(
            self.domain,
            self.instance_secret,
            self.NOW + timedelta(seconds=1)
        )
        with self.assertRaises(auth.InvalidSignature):
            auth.validate_dnsauth_pair(
                txt,
                b"fnord." + self.domain,
                self.instance_secret,
                base64.urlsafe_b64decode(user),
                now=self.NOW,
            )

    def test_reject_spoofed_valid_until(self):
        txt, user = auth.generate_dnsauth_pair(
            self.domain,
            self.instance_secret,
            self.NOW + timedelta(seconds=1)
        )

        version, valid_until, signature = txt.split(" ")
        valid_until = (
            self.NOW + timedelta(seconds=60)
        ).strftime(auth.TXT_DATE_FORMAT)
        txt = " ".join([version, valid_until, signature])

        with self.assertRaises(auth.InvalidSignature):
            auth.validate_dnsauth_pair(
                txt,
                self.domain,
                self.instance_secret,
                base64.urlsafe_b64decode(user),
                now=self.NOW,
            )

    def test_reject_instance_secret_mismatch(self):
        txt, user = auth.generate_dnsauth_pair(
            self.domain,
            self.instance_secret,
            self.NOW + timedelta(seconds=1)
        )
        with self.assertRaises(auth.InvalidSignature):
            auth.validate_dnsauth_pair(
                txt,
                self.domain,
                self.instance_secret + b"foo",
                base64.urlsafe_b64decode(user),
                now=self.NOW,
            )

    def test_reject_user_secret_mismatch(self):
        txt, user = auth.generate_dnsauth_pair(
            self.domain,
            self.instance_secret,
            self.NOW + timedelta(seconds=1)
        )
        with self.assertRaises(auth.InvalidSignature):
            auth.validate_dnsauth_pair(
                txt,
                self.domain,
                self.instance_secret,
                base64.urlsafe_b64decode(user) + b"foo",
                now=self.NOW,
            )

    def test_reject_expired(self):
        txt, user = auth.generate_dnsauth_pair(
            self.domain,
            self.instance_secret,
            self.NOW + timedelta(seconds=1)
        )
        with self.assertRaises(auth.ExpiredSignature):
            auth.validate_dnsauth_pair(
                txt,
                self.domain,
                self.instance_secret,
                base64.urlsafe_b64decode(user),
                now=self.NOW + timedelta(seconds=2),
            )
