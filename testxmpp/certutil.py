import base64
import dataclasses
import hashlib
import typing
from datetime import datetime

import pyasn1.codec.der.decoder
import pyasn1.codec.der.encoder
import pyasn1.type.base
import pyasn1_modules.rfc5280 as cert_rfc


OID_TO_SHORTNAME = {
    str(cert_rfc.id_at_name): "name",
    str(cert_rfc.id_at_surname): "surname",
    str(cert_rfc.id_at_givenName): "givenName",
    str(cert_rfc.id_at_initials): "initials",
    str(cert_rfc.id_at_generationQualifier): "generationQualifier",
    str(cert_rfc.id_at_commonName): "commonName",
    str(cert_rfc.id_at_localityName): "localityName",
    str(cert_rfc.id_at_stateOrProvinceName): "stateOrProvinceName",
    str(cert_rfc.id_at_organizationName): "organizationName",
    str(cert_rfc.id_at_organizationalUnitName): "organizationalUnitName",
    str(cert_rfc.id_at_title): "title",
    str(cert_rfc.id_at_dnQualifier): "dnQualifier",
    str(cert_rfc.id_at_countryName): "countryName",
    str(cert_rfc.id_at_serialNumber): "serialNumber",
    str(cert_rfc.id_at_pseudonym): "pseudonym",
    str(cert_rfc.id_domainComponent): "domainComponent",
    str(cert_rfc.id_emailAddress): "emailAddress",
}


def get_default_name(nm: typing.Any) -> str:
    return str(nm)


def get_choice_name(cn: typing.Any) -> str:
    for comp in cn.components:
        if comp is pyasn1.type.base.noValue:
            continue
        return str(comp)
    return ""


OID_TO_LOOKUPFN = {
    cert_rfc.id_at_commonName: get_choice_name,
    cert_rfc.id_at_organizationName: get_choice_name,
}


@dataclasses.dataclass
class CertInfo:
    subject: typing.Sequence[typing.Mapping[str, str]]
    issuer: typing.Sequence[typing.Mapping[str, str]]
    subject_alt_names: typing.Optional[
        typing.Mapping[str, typing.Collection[str]]
    ]
    not_before: datetime
    not_after: datetime
    public_key: bytes
    public_key_type: str
    fingerprints: typing.Mapping[str, bytes]

    def to_json(self) -> typing.Mapping[str, typing.Any]:
        return {
            "subject": self.subject,
            "issuer": self.issuer,
            "subject_alt_names": self.subject_alt_names,
            "not_before": self.not_before.isoformat(),
            "not_after": self.not_after.isoformat(),
            "public_key": base64.b64encode(self.public_key).decode("ascii"),
            "public_key_type": self.public_key_type,
            "fingerprints": {
                type_: ":".join("{:02x}".format(octet) for octet in fp)
                for type_, fp in self.fingerprints.items()
            },
        }

    @classmethod
    def from_json(cls, data: typing.Mapping[str, typing.Any]) -> "CertInfo":
        return cls(
            subject=data["subject"],
            issuer=data["issuer"],
            subject_alt_names=data["subject_alt_names"],
            not_before=datetime.fromisoformat(data["not_before"]),
            not_after=datetime.fromisoformat(data["not_after"]),
            public_key=base64.b64decode(data["public_key"]),
            public_key_type=data["public_key_type"],
            fingerprints={
                type_: bytes(
                    int(hexoctet, 16)
                    for hexoctet in hexdigest.split(":")
                )
                for type_, hexdigest in data["fingerprints"].items()
            },
        )


def unwrap_pem(blob: str) -> bytes:
    HEAD = "-----BEGIN CERTIFICATE-----"
    FOOT = "-----END CERTIFICATE-----"
    startidx = blob.find(HEAD)
    if startidx is None:
        raise ValueError("input does not contain a certificate header")
    blob = blob[(startidx+len(HEAD)):]
    endidx = blob.find(FOOT)
    blob = blob[:endidx]
    return base64.b64decode(blob)


def decode_cert_der(blob: bytes) -> cert_rfc.Certificate:
    return pyasn1.codec.der.decoder.decode(
        blob,
        cert_rfc.Certificate(),
    )[0]


def decode_pem(blob: str) -> cert_rfc.Certificate:
    der = unwrap_pem(blob)
    return decode_cert_der(der)


def decode_name(
        name: cert_rfc.Name,
        ) -> typing.Sequence[typing.Mapping[str, str]]:
    result = []
    # A Name is a Choice of just a single option: rdnSequence
    rdn_sequence = name.getComponentByName("rdnSequence")
    # A RDNSequence is a sequence of RelativeDistinguishedNames
    for rdn in rdn_sequence:
        # A RelativeDistinguishedName is a set of AttributeTypeAndValue
        # objects
        kv = {}
        for atav in rdn:
            # An AttributeTypeAndValue is magic.
            type_oidish = atav.getComponentByName("type")
            try:
                type_ = cert_rfc.certificateAttributesMap[type_oidish]
            except KeyError:
                raise ValueError(
                    f"unsupported name attribute type: {type_oidish}",
                )
            lookupfn = OID_TO_LOOKUPFN.get(type_oidish, get_default_name)
            values = pyasn1.codec.der.decoder.decode(
                atav.getComponentByName("value"),
                type_,
            )
            value, _ = values
            kv[str(type_oidish)] = lookupfn(value)
        result.append(kv)
    return result


def get_extension(
        exts: cert_rfc.Extensions,
        oid: cert_rfc.univ.ObjectIdentifier) -> typing.Any:
    for ext in exts:
        if ext.getComponentByName("extnID") != oid:
            continue
        values = pyasn1.codec.der.decoder.decode(
            ext.getComponentByName("extnValue"),
            cert_rfc.certificateExtensionsMap[oid],
        )
        value, _ = values
        return value
    return None


def extract_alt_names(
        names: cert_rfc.GeneralNames,
        ) -> typing.Mapping[str, typing.Collection[str]]:
    result = {}
    for name in names:
        for k in name.keys():
            v = name.getComponentByName(k)
            result.setdefault(k, []).append(str(v))
    return result


def get_subject_alt_names(
        extensions: cert_rfc.Extensions,
        ) -> typing.Optional[typing.Mapping[str, typing.Collection[str]]]:
    san_ext: cert_rfc.SubjectAltName = get_extension(
        extensions, cert_rfc.id_ce_subjectAltName,
    )
    if san_ext is None:
        return None
    return extract_alt_names(san_ext)


def time_to_datetime(t: cert_rfc.Time) -> datetime:
    utc_time = t.getComponentByName("utcTime")
    if utc_time is pyasn1.type.base.noValue:
        return t.getComponentByName("generalTime").asDateTime
    return utc_time.asDateTime


def extract_cert_info(cert: bytes) -> CertInfo:
    cert_bytes = pyasn1.codec.der.encoder.encode(cert)
    fingerprints = {}
    for algo in ["sha1", "sha256", "sha512"]:
        hashfun = hashlib.new(algo)
        hashfun.update(cert_bytes)
        fingerprints[algo] = hashfun.digest()
    tbs = cert.getComponentByName("tbsCertificate")
    subject = decode_name(tbs.getComponentByName("subject"))
    issuer = decode_name(tbs.getComponentByName("issuer"))
    extensions = tbs.getComponentByName("extensions")
    validity = tbs.getComponentByName("validity")
    not_before = time_to_datetime(validity.getComponentByName("notBefore"))
    not_after = time_to_datetime(validity.getComponentByName("notAfter"))
    pk_info = tbs.getComponentByName("subjectPublicKeyInfo")
    pk_algo = str(
        pk_info.getComponentByName("algorithm")
        .getComponentByName("algorithm")
    )
    pk = pk_info.getComponentByName("subjectPublicKey").asOctets()
    return CertInfo(
        subject=subject,
        issuer=issuer,
        subject_alt_names=get_subject_alt_names(extensions),
        not_before=not_before,
        not_after=not_after,
        public_key=pk,
        public_key_type=pk_algo,
        fingerprints=fingerprints,
    )


if __name__ == "__main__":
    import argparse
    import json
    import sys

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "cert",
        type=argparse.FileType("r", encoding="ascii"),
    )

    args = parser.parse_args()

    with args.cert as f:
        cert = decode_pem(f.read())

    json.dump(extract_cert_info(cert).to_json(), sys.stdout, indent=2)
