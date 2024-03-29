import argparse
import asyncio
import logging
import os
import pathlib
import sys

import environ

from .daemon import Coordinator


@environ.config
class Ratelimit:
    burst = environ.var(6, converter=int)
    interval = environ.var(3600, converter=int)


@environ.config(prefix="TESTXMPP")
class AppConfig:
    db_uri = environ.var()
    listen_uri = environ.var("tcp://*:5001")

    @environ.config
    class DNSAuth:
        secret = environ.var("")

    @environ.config
    class Unprivileged:
        ratelimit = environ.group(Ratelimit)

    @environ.config
    class Privileged:
        ratelimit = environ.group(Ratelimit)

    unprivileged = environ.group(Unprivileged)
    privileged = environ.group(Privileged)
    dns_auth = environ.group(DNSAuth)


async def amain(config):
    coordinator = Coordinator(config)
    await coordinator.run()


def main():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-v", "--verbose",
        dest="verbosity",
        action="count",
        default=0,
        help="Increase verbosity (up to -vvv)",
    )
    parser.add_argument(
        "--debug-libraries",
        action="store_true",
        default=False,
        help="If enabled, verbosity will also be increased for libraries",
    )

    args = parser.parse_args()

    verbosity_level = {
        0: logging.ERROR,
        1: logging.WARNING,
        2: logging.INFO,
    }.get(args.verbosity, logging.DEBUG)
    if args.debug_libraries:
        global_level = verbosity_level
    else:
        global_level = logging.WARNING

    logging.basicConfig(level=global_level)
    logging.getLogger("testxmpp").setLevel(verbosity_level)

    config = environ.to_config(AppConfig)
    asyncio.run(amain(config))
