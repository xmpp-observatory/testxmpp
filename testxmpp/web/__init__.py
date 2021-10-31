import logging
import os

import environ

import quart.flask_patch
import quart.logging

from quart import Quart

import flask_babel

from .infra import db, babel
from .main import bp as bp_main


@environ.config(prefix="TESTXMPP")
class AppConfig:
    db_uri = environ.var()
    coordinator_uri = environ.var("tcp://localhost:5001")


def create_app():
    config = environ.to_config(AppConfig)

    app = Quart(__name__)
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SQLALCHEMY_DATABASE_URI"] = config.db_uri
    app.config["COORDINATOR_URI"] = config.coordinator_uri
    app.config["LANGUAGES"] = ["en"]

    db.init_app(app)
    babel.init_app(app)

    app.register_blueprint(bp_main)

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

    return app
