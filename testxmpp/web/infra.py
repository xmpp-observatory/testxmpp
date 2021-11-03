import contextlib

import quart.flask_patch

from quart import current_app, request

from flask_sqlalchemy import SQLAlchemy
import flask_babel
from flask_babel import Babel

import zmq
import zmq.asyncio

import testxmpp.certutil
import testxmpp.model


db = SQLAlchemy(metadata=testxmpp.model.Base.metadata)
babel = Babel()


@babel.localeselector
def selected_locale():
    return request.accept_languages.best_match(
        current_app.config['LANGUAGES']
    )


@contextlib.contextmanager
def zmq_socket(type_):
    zctx = zmq.asyncio.Context()
    try:
        sock = zctx.socket(zmq.REQ)
        try:
            yield sock
        finally:
            sock.close()
    finally:
        zctx.term()


def setup_template_filters(app):
    @app.template_filter(name="format_timedelta")
    def format_timedelta(dt, **kwargs):
        return flask_babel.format_timedelta(dt, **kwargs)

    @app.template_filter(name="decode_domain")
    def decode_domain(d, **kwargs):
        if isinstance(d, str):
            return d
        return d.decode("idna")

    @app.template_filter(name="printable_bytes")
    def printable_bytes(b, **kwargs):
        if isinstance(b, str):
            return b
        return b.decode("utf-8", errors="replace")

    @app.template_filter(name="hexdigest")
    def hexdigest(bs, **kwargs):
        return ":".join("{:02x}".format(b) for b in bs)

    @app.template_filter(name="oidname")
    def oidname(oid, **kwargs):
        return testxmpp.certutil.OID_TO_SHORTNAME.get(oid, oid)
