import logging
import os

import quart.flask_patch
import quart.logging

from quart import (
    Quart, render_template, abort, request, redirect, url_for,
)

import sqlalchemy
import sqlalchemy.orm

from flask_sqlalchemy import SQLAlchemy

import zmq
import zmq.asyncio

from testxmpp import model
import testxmpp.api.coordinator as coordinator_api


app = Quart(__name__)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ["TESTXMPP_DB_URI"]
app.config["COORDINATOR_URI"] = os.environ.get("TESTXMPP_COORDINATOR_URI",
                                               "tcp://localhost:5001")

db = SQLAlchemy(app, metadata=model.Base.metadata)


@app.route("/", methods=["GET"])
async def index():
    return await render_template("index.html")


@app.route("/scan/queue", methods=["GET", "POST"])
async def queue_scan():
    form_data = await request.form
    scan_request = coordinator_api.mkv1request(
        coordinator_api.RequestType.SCAN_DOMAIN,
        {
            "domain": form_data["domain"],
            "protocol": form_data["protocol"],
        },
    )

    zctx = zmq.asyncio.Context()
    sock = zctx.socket(zmq.REQ)
    try:
        sock.connect(app.config["COORDINATOR_URI"])
        await sock.send_json(scan_request)
        reply = await sock.recv_json()
    finally:
        sock.close()

    if reply["type"] == coordinator_api.ResponseType.SCAN_QUEUED.value:
        return redirect(url_for(
            "scan_result",
            scan_id=reply["payload"]["scan_id"]
        ))
    elif reply["type"] == coordinator_api.ResponseType.ERROR.value:
        return abort(reply["payload"]["code"], reply["payload"]["message"])

    raise RuntimeError("unexpected reply: {!r}".format(reply))


@app.route("/scan/result/<int:scan_id>", methods=["GET"])
async def scan_result(scan_id):
    try:
        domain, protocol, created_at, scan_host, scan_port, scan_tls_mode = \
            db.session.query(
                model.Scan.domain,
                model.Scan.protocol,
                model.Scan.created_at,
                model.Scan.primary_host,
                model.Scan.primary_port,
                model.Scan.primary_tls_mode,
            ).filter(
                model.Scan.id_ == scan_id
            ).one()
    except sqlalchemy.orm.exc.NoResultFound:
        return abort(404)

    tls_offering_schema = [
        ("SSL 2", [1, -1]),
        ("SSL 3", [1, -1]),
        ("TLS 1", [1, -1]),
        ("TLS 1.1", [1, 0]),
        ("TLS 1.2", [-1, 1]),
        ("TLS 1.3", [-1, 1]),
    ]

    try:
        *tls_versions, server_cipher_order = db.session.query(
            model.TLSOffering.sslv2,
            model.TLSOffering.sslv3,
            model.TLSOffering.tlsv1,
            model.TLSOffering.tlsv1_1,
            model.TLSOffering.tlsv1_2,
            model.TLSOffering.tlsv1_3,
            model.TLSOffering.server_cipher_order,
        ).filter(
            model.TLSOffering.scan_id == scan_id,
        ).one()
    except sqlalchemy.orm.exc.NoResultFound:
        tls_versions = [None] * len(tls_offering_schema)
        server_cipher_order = None

    tls_offering_info = [
        (label, scores[offered] if offered is not None else 0, offered)
        for (label, scores), offered in zip(tls_offering_schema, tls_versions)
    ]

    srv_records = [
        (service, priority, weight, host.decode("idna"), port)
        for service, priority, weight, host, port in db.session.query(
            model.SRVRecord.service,
            model.SRVRecord.priority,
            model.SRVRecord.weight,
            model.SRVRecord.host,
            model.SRVRecord.port,
        ).filter(
            model.SRVRecord.scan_id == scan_id,
        ).order_by(
            model.SRVRecord.priority.asc(),
            model.SRVRecord.weight.desc(),
        )
    ]

    ciphers = list(db.session.query(
        model.CipherOffering.cipher_id,
        model.CipherMetadata.openssl_name,
        model.CipherOffering.key_exchange_info,
    ).select_from(model.CipherOffering).join(model.CipherMetadata).join(
        model.CipherOfferingOrder
    ).filter(
        model.CipherOffering.scan_id == scan_id,
    ).order_by(
        model.CipherOfferingOrder.order.asc(),
    ))

    tls_pending = bool(db.session.query(model.PendingScanTask.id_).filter(
        model.PendingScanTask.scan_id == scan_id,
        model.PendingScanTask.type_ == model.TaskType.TLS_SCAN
    ).one_or_none())

    return await render_template(
        "scan_result.html",
        scan_id=scan_id,
        scan_info={
            "domain": domain.decode("idna"),
            "protocol": protocol,
            "created_at": created_at,
            "host": scan_host.decode("idna") if scan_host else None,
            "port": scan_port,
            "tls_mode": scan_tls_mode,
        },
        tls_offering_info=tls_offering_info,
        server_cipher_order=server_cipher_order,
        srv_records=srv_records,
        ciphers=ciphers,
        tls_pending=tls_pending,
    )
