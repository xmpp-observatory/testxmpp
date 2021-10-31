import json
import os
import socket

from datetime import datetime

from quart import (
    Blueprint,
    render_template,
    request,
    current_app,
    redirect,
    url_for,
    abort,
)

import sqlalchemy
import sqlalchemy.orm

import zmq

import testxmpp.certutil
import testxmpp.api.coordinator as coordinator_api
from testxmpp import model
from .infra import db, zmq_socket

bp = Blueprint('main', __name__)


def _get_recent_scans(protocol):
    subquery = db.session.query(
        model.Scan.domain,
        sqlalchemy.func.max_(model.Scan.created_at).label("newest"),
    ).group_by(
        model.Scan.domain,
    ).filter(
        model.Scan.protocol == protocol,
    ).limit(10).subquery()

    return [
        (id_, domain.decode("idna"), created_at)
        for id_, domain, created_at in db.session.query(
            model.Scan.id_,
            model.Scan.domain,
            model.Scan.created_at,
        ).select_from(
            model.Scan,
        ).join(
            subquery,
            sqlalchemy.and_(
                subquery.c.domain == model.Scan.domain,
                subquery.c.newest == model.Scan.created_at,
            ),
        ).filter(
            model.Scan.protocol == protocol,
        ).order_by(
            model.Scan.created_at.desc(),
        ).limit(10)
    ]


@bp.route("/", methods=["GET"])
async def index():
    recent_scans_c2s = _get_recent_scans(model.ScanType.C2S)
    recent_scans_s2s = _get_recent_scans(model.ScanType.S2S)

    return await render_template(
        "index.html",
        recent_scans=[
            (model.ScanType.C2S, recent_scans_c2s),
            (model.ScanType.S2S, recent_scans_s2s),
        ],
        now=datetime.utcnow(),
    )


@bp.route("/scan/queue", methods=["GET", "POST"])
async def queue_scan():
    form_data = await request.form
    scan_request = coordinator_api.mkv1request(
        coordinator_api.RequestType.SCAN_DOMAIN,
        {
            "domain": form_data["domain"],
            "protocol": form_data["protocol"],
        },
    )

    with zmq_socket(zmq.REQ) as sock:
        sock.connect(current_app.config["COORDINATOR_URI"])
        await sock.send_json(scan_request)
        reply = await sock.recv_json()

    if reply["type"] == coordinator_api.ResponseType.SCAN_QUEUED.value:
        return redirect(url_for(
            "main.scan_result",
            scan_id=reply["payload"]["scan_id"]
        ))
    elif reply["type"] == coordinator_api.ResponseType.ERROR.value:
        return abort(reply["payload"]["code"], reply["payload"]["message"])

    raise RuntimeError("unexpected reply: {!r}".format(reply))


def evaluate_task_and_result(task, result):
    in_progress = task is not None and task.state in [
        model.TaskState.WAITING,
        model.TaskState.IN_PROGRESS
    ]

    passed = (
        result is not None and result.error is None and
        result.errno is None
    )

    if task is not None and task.state == model.TaskState.FAILED:
        error = task.fail_reason.value
    elif result is not None:
        if result.errno is not None and result.errno > 0:
            error = os.strerror(result.errno)
        else:
            error = result.error
    else:
        error = None

    return in_progress, passed, error


def fetch_host_meta_info(session,
                         scan_id: int):
    objects = {
        id_: (format_, url)
        for id_, format_, url in session.query(
            model.HostMetaObject.id_,
            model.HostMetaObject.format_,
            model.HostMetaObject.url,
        ).filter(
            model.HostMetaObject.scan_id == scan_id,
        )
    }
    object_info = sorted(objects.values(), key=lambda x: x[0].value)

    links_collection = {}
    for object_id, rel, href in session.query(
                model.HostMetaLink.object_id,
                model.HostMetaLink.rel,
                model.HostMetaLink.href,
            ).select_from(model.HostMetaLink).join(
                model.HostMetaObject,
            ).filter(
                model.HostMetaObject.scan_id == scan_id,
            ):
        links_collection.setdefault((rel, href), []).append(
            objects[object_id][0]
        )

    links = sorted(
        ((rel, href, formats)
         for (rel, href), formats in links_collection.items()),
        key=lambda x: (x[0], x[1])
    )

    return object_info, links


@bp.route("/scan/result/<int:scan_id>", methods=["GET"])
async def scan_result(scan_id):
    try:
        domain, protocol, created_at = \
            db.session.query(
                model.Scan.domain,
                model.Scan.protocol,
                model.Scan.created_at,
            ).filter(
                model.Scan.id_ == scan_id
            ).one()
    except sqlalchemy.orm.exc.NoResultFound:
        return abort(404)

    srv_records = list(db.session.query(
        model.SRVRecord.priority,
        model.SRVRecord.weight,
        model.SRVRecord.service,
        model.SRVRecord.host,
        model.SRVRecord.port,
    ).filter(
        model.SRVRecord.scan_id == scan_id,
    ).order_by(
        model.SRVRecord.priority.asc(),
        model.SRVRecord.weight.desc(),
        model.SRVRecord.service.asc(),
    ))

    xmppconnect_records = list(db.session.query(
        model.XMPPConnectRecord.attribute_name,
        model.XMPPConnectRecord.attribute_value,
    ).filter(
        model.XMPPConnectRecord.scan_id == scan_id,
    ).order_by(
        model.XMPPConnectRecord.attribute_name.asc(),
    ))

    host_meta_object_info, host_meta_links = fetch_host_meta_info(
        db.session,
        scan_id,
    )

    endpoints = []
    for ep, task, result in db.session.query(
                model.EndpointTCP,
                model.ScanTask,
                model.EndpointScanResult,
            ).select_from(
                model.EndpointTCP,
            ).outerjoin(
                model.ScanTask,
            ).outerjoin(
                model.EndpointScanResult
            ).filter(
                model.EndpointTCP.scan_id == scan_id,
                model.ScanTask.type_ == model.TaskType.XMPP_PROBE,
            ).order_by(
                model.EndpointTCP.endpoint_id.asc()
            ):

        if ep.srv_record_id is not None:
            source = model.EndpointSource.SRV_RECORD.value
        else:
            source = model.EndpointSource.FALLBACK.value

        endpoints.append((
            source, ep.transport.value, ep.uri, ep.tls_mode.value,
            evaluate_task_and_result(task, result),
        ))

    for ep, task, result in db.session.query(
                model.EndpointHTTP,
                model.ScanTask,
                model.EndpointScanResult,
            ).select_from(
                model.EndpointHTTP,
            ).outerjoin(
                model.ScanTask,
            ).outerjoin(
                model.EndpointScanResult
            ).filter(
                model.EndpointHTTP.scan_id == scan_id,
            ).order_by(
                model.EndpointHTTP.endpoint_id.asc()
            ):

        endpoints.append(
            (model.EndpointSource.ALTERNATIVE_METHOD.value,
             ep.transport.value, ep.uri, ep.http_mode.value,
             evaluate_task_and_result(task, result))
        )

    sasl_offerings = {
        v.value: []
        for v in model.ConnectionPhase
    }
    for phase, name in db.session.query(
                model.EndpointScanSASLOffering.phase,
                model.SASLMechanism.name
            ).select_from(model.Endpoint).join(
                model.EndpointScanResult
            ).join(
                model.EndpointScanSASLOffering
            ).join(
                model.SASLMechanism
            ).filter(
                model.Endpoint.scan_id == scan_id,
            ).distinct().order_by(
                model.SASLMechanism.name.asc(),
            ):
        sasl_offerings[phase.value].append(name)

    tls_offering_schema = [
        ("SSL 2", [1, -1]),
        ("SSL 3", [1, -1]),
        ("TLS 1", [1, -1]),
        ("TLS 1.1", [1, 0]),
        ("TLS 1.2", [-1, 1]),
        ("TLS 1.3", [-1, 1]),
    ]

    try:
        *tls_versions, server_cipher_order, endpoint_id = db.session.query(
            model.TLSOffering.sslv2,
            model.TLSOffering.sslv3,
            model.TLSOffering.tlsv1,
            model.TLSOffering.tlsv1_1,
            model.TLSOffering.tlsv1_2,
            model.TLSOffering.tlsv1_3,
            model.TLSOffering.server_cipher_order,
            model.Endpoint.id_,
        ).select_from(model.TLSOffering).join(
            model.Endpoint,
        ).filter(
            model.Endpoint.scan_id == scan_id,
        ).one()
    except sqlalchemy.orm.exc.NoResultFound:
        tls_versions = [None] * len(tls_offering_schema)
        server_cipher_order = None
        tls_scan_uri = None
    else:
        tls_scan_endpoint = db.session.query(
            model.Endpoint,
        ).filter(
            model.Endpoint.id_ == endpoint_id,
        ).one()
        tls_scan_uri = tls_scan_endpoint.uri

    tls_offering_info = [
        (label, scores[offered] if offered is not None else 0, offered)
        for (label, scores), offered in zip(tls_offering_schema, tls_versions)
    ]

    ciphers = list(db.session.query(
        model.CipherOffering.cipher_id,
        model.CipherMetadata.openssl_name,
        model.CipherOffering.key_exchange_info,
    ).select_from(
        model.CipherOffering
    ).join(
        model.CipherMetadata
    ).join(
        model.CipherOfferingOrder
    ).join(
        model.Endpoint
    ).filter(
        model.Endpoint.scan_id == scan_id,
    ).order_by(
        model.CipherOfferingOrder.order.asc(),
    ))

    # TODO: this is not safe with multiple endpoints being testssl'd'
    certs = list(db.session.query(
        model.Certificate.id_,
        model.Certificate.subject,
        model.Certificate.issuer,
        model.Certificate.not_before,
        model.Certificate.not_after,
        model.Certificate.public_key,
        model.Certificate.public_key_type,
        model.Certificate.fingerprint_sha1,
        model.Certificate.fingerprint_sha256,
        model.Certificate.fingerprint_sha512,
    ).select_from(
        model.Endpoint,
    ).join(
        model.CertificateOffering,
    ).join(
        model.Certificate,
    ).filter(
        model.Endpoint.scan_id == scan_id,
    ).order_by(
        model.CertificateOffering.chain_index.asc(),
    ))

    cert_chain = []
    for (cert_id,
         subject, issuer,
         not_before, not_after,
         public_key, public_key_type,
         fp_sha1, fp_sha256, fp_sha512) in certs:
        sans = {}

        for asn1_name, value in db.session.query(
                    model.SubjectAltNameType.asn1_name,
                    model.SubjectAltName.value,
                ).select_from(
                    model.SubjectAltName,
                ).join(
                    model.SubjectAltNameType,
                ).filter(
                    model.SubjectAltName.certificate_id == cert_id,
                ).order_by(
                    model.SubjectAltNameType.asn1_name.asc(),
                ):
            sans.setdefault(asn1_name, []).append(value)

        cert_chain.append(
            testxmpp.certutil.CertInfo(
                subject=json.loads(subject),
                issuer=json.loads(issuer),
                subject_alt_names=sans,
                public_key=public_key,
                public_key_type=public_key_type,
                not_before=not_before,
                not_after=not_after,
                fingerprints={
                    "sha1": fp_sha1,
                    "sha256": fp_sha256,
                    "sha512": fp_sha512,
                },
            )
        )

    return await render_template(
        "scan_result.html",
        scan_id=scan_id,
        scan_info={
            "domain": domain.decode("idna"),
            "protocol": protocol,
            "created_at": created_at,
        },
        srv_records=srv_records,
        xmppconnect_records=xmppconnect_records,
        endpoints=endpoints,
        host_meta_object_info=host_meta_object_info,
        host_meta_links=host_meta_links,
        sasl_offerings=sasl_offerings,
        tls_offering_info=tls_offering_info,
        tls_scan_uri=tls_scan_uri,
        server_cipher_order=server_cipher_order,
        ciphers=ciphers,
        cert_chain=cert_chain,
    )
