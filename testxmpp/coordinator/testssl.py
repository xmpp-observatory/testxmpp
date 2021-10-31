import base64
import json

import sqlalchemy.orm

import testxmpp.certutil
import testxmpp.model as model


def get_or_create_tls_offering(session, endpoint_id):
    try:
        return session.query(model.TLSOffering).filter(
            model.TLSOffering.endpoint_id == endpoint_id,
        ).one()
    except sqlalchemy.orm.exc.NoResultFound:
        tls_offering = model.TLSOffering()
        tls_offering.endpoint_id = endpoint_id
        session.add(tls_offering)
        return tls_offering


def get_or_create_san_type(
        session,
        asn1_name: str,
        ) -> model.SubjectAltNameType:
    try:
        return session.query(model.SubjectAltNameType).filter(
            model.SubjectAltNameType.asn1_name == asn1_name,
        ).one()
    except sqlalchemy.orm.exc.NoResultFound:
        san_type = model.SubjectAltNameType()
        san_type.asn1_name = asn1_name
        session.add(san_type)
        return san_type


def get_or_create_certificate(session, certinfo, raw_der):
    fingerprint_sha1 = certinfo.fingerprints["sha1"]
    fingerprint_sha256 = certinfo.fingerprints["sha256"]
    fingerprint_sha512 = certinfo.fingerprints["sha512"]
    certs = session.query(model.Certificate).filter(
        model.Certificate.fingerprint_sha1 == fingerprint_sha1,
        model.Certificate.fingerprint_sha256 == fingerprint_sha256,
        model.Certificate.fingerprint_sha512 == fingerprint_sha512,
    ).all()
    for cert in certs:
        if cert.raw_der == raw_der:
            return cert
    # IS THIS A COLLISION?! OF SHA1 + SHA256 + SHA512? :-O

    san_type_map = {
        asn1_name: get_or_create_san_type(session, asn1_name)
        for asn1_name in (certinfo.subject_alt_names or {}).keys()
    }

    cert = model.Certificate()
    cert.fingerprint_sha1 = fingerprint_sha1
    cert.fingerprint_sha256 = fingerprint_sha256
    cert.fingerprint_sha512 = fingerprint_sha512
    cert.not_before = certinfo.not_before
    cert.not_after = certinfo.not_after
    cert.public_key = certinfo.public_key
    cert.public_key_type = certinfo.public_key_type
    cert.raw_der = raw_der
    cert.subject = json.dumps(certinfo.subject, sort_keys=True)
    cert.issuer = json.dumps(certinfo.issuer, sort_keys=True)
    session.add(cert)

    for asn1_name, values in (certinfo.subject_alt_names or {}).items():
        san_type = san_type_map[asn1_name]
        for value in values:
            san = model.SubjectAltName()
            san.certificate = cert
            san.type_ = san_type
            san.value = value
            session.add(san)

    return cert


def upsert_certificate_offering(
        session,
        endpoint_id,
        certificate,
        chain_index):
    try:
        offering = session.query(model.CertificateOffering).filter(
            model.CertificateOffering.endpoint_id == endpoint_id,
            model.CertificateOffering.chain_index == chain_index,
        ).one()
    except sqlalchemy.orm.exc.NoResultFound:
        offering = model.CertificateOffering()
        offering.endpoint_id = endpoint_id
        offering.chain_index = chain_index
        offering.certificate = certificate
        session.add(offering)
    else:
        offering.certificate = certificate
        session.add(offering)


def lookup_cipher_id_by_name(session, openssl_name):
    result = session.query(model.CipherMetadata.id_).filter(
        model.CipherMetadata.openssl_name == openssl_name
    ).one_or_none()
    if result is None:
        return None
    return result[0]


def upsert_cipher_metadata(session, cipher_id, openssl_name, iana_name):
    try:
        metadata = session.query(model.CipherMetadata).filter(
            model.CipherMetadata.id_ == cipher_id,
        ).one()
    except sqlalchemy.orm.exc.NoResultFound:
        metadata = model.CipherMetadata()
        metadata.id_ = cipher_id
        session.add(metadata)

    if openssl_name and metadata.openssl_name != openssl_name:
        metadata.openssl_name = openssl_name
    if iana_name and metadata.iana_name != iana_name:
        metadata.iana_name = iana_name
    return metadata


def upsert_cipher_offering_order(session,
                                 endpoint_id, cipher_id, tls_version,
                                 order):
    try:
        offering_order = session.query(model.CipherOfferingOrder).filter(
            model.CipherOfferingOrder.endpoint_id == endpoint_id,
            model.CipherOfferingOrder.cipher_id == cipher_id,
            model.CipherOfferingOrder.tls_version == tls_version,
        ).one()
    except sqlalchemy.orm.exc.NoResultFound:
        offering_order = model.CipherOfferingOrder()
        offering_order.endpoint_id = endpoint_id
        offering_order.cipher_id = cipher_id
        offering_order.tls_version = tls_version
        session.add(offering_order)

    if offering_order.order != order:
        offering_order.order = order
    return offering_order


def get_or_create_cipher_offering(session, endpoint_id, cipher_id):
    try:
        return session.query(model.CipherOffering).filter(
            model.CipherOffering.endpoint_id == endpoint_id,
            model.CipherOffering.cipher_id == cipher_id,
        ).one()
    except sqlalchemy.orm.exc.NoResultFound:
        cipher_offering = model.CipherOffering()
        cipher_offering.endpoint_id = endpoint_id
        cipher_offering.cipher_id = cipher_id
        session.add(cipher_offering)
        return cipher_offering


def handle_tls_versions_push(session, endpoint_id, data) -> bool:
    tls_offering = get_or_create_tls_offering(session, endpoint_id)

    # no generic/procedural mapping here to avoid the worker being able to
    # manipulate arbitrary attributes of the object.
    keymap = {
        "SSLv2": "sslv2",
        "SSLv3": "sslv3",
        "TLSv1": "tlsv1",
        "TLSv1.1": "tlsv1_1",
        "TLSv1.2": "tlsv1_2",
        "TLSv1.3": "tlsv1_3",
    }

    for k, v in data["tls_versions"].items():
        setattr(tls_offering, keymap[k], bool(v))

    return True


def handle_cipherlists_push(session, endpoint_id, data) -> bool:
    # we ignore this push, because we need to access the cipher lists
    # based on the cipher ID, but we only get the OpenSSL name here.
    return True


def handle_cipherlists_complete(session, endpoint_id, data) -> bool:
    for tls_version, ciphers in data.items():
        for order, openssl_name in enumerate(ciphers):
            cipher_id = lookup_cipher_id_by_name(
                session, openssl_name,
            )
            if cipher_id is None:
                # ???
                continue
            cipher_offering = get_or_create_cipher_offering(
                session, endpoint_id, cipher_id
            )
            upsert_cipher_offering_order(
                session, endpoint_id, cipher_id, tls_version, order,
            )
    return True


def handle_server_cipher_order_push(session, endpoint_id, data) -> bool:
    tls_offering = get_or_create_tls_offering(session, endpoint_id)
    tls_offering.server_cipher_order = data["server_cipher_order"]
    return True


def handle_cipher_info_push(session, endpoint_id, data) -> bool:
    data = data["cipher"]
    cipher_metadata = upsert_cipher_metadata(
        session,
        data["id"],
        data["openssl_name"],
        data["iana_name"],
    )
    cipher_offering = get_or_create_cipher_offering(
        session,
        endpoint_id,
        data["id"],
    )
    cipher_offering.key_exchange_info = data["key_exchange"] or None
    return True


def handle_certificate_push(
        session,
        endpoint_id,
        data) -> bool:
    data = data["certificate"]
    certinfo_json = data["info"]
    raw_der = base64.b64decode(data["raw_der"])
    index = data.get("index", 0)
    certinfo = testxmpp.certutil.CertInfo.from_json(certinfo_json)
    certificate = get_or_create_certificate(session, certinfo, raw_der)
    upsert_certificate_offering(
        session,
        endpoint_id=endpoint_id,
        certificate=certificate,
        chain_index=index,
    )
    return True
