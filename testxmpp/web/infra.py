import contextlib

import quart.flask_patch

from quart import current_app, request

from flask_sqlalchemy import SQLAlchemy
from flask_babel import Babel

import zmq
import zmq.asyncio

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
