import argparse
import asyncio
import logging
import os
import pathlib
import shlex

import environ

from .daemon import XMPPWorker


@environ.config(prefix="TESTXMPP")
class AppConfig:
    coordinator_uri = environ.var("tcp://localhost:5001")
    s2s_from = environ.var()
    s2s_client_cert = environ.var()
    s2s_client_key = environ.var()


async def amain(coordinator_uri, s2s_from, s2s_client_cert, s2s_client_key):
    coordinator = XMPPWorker(coordinator_uri,
                             s2s_from, s2s_client_cert, s2s_client_key)
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
    asyncio.run(amain(config.coordinator_uri,
                      config.s2s_from,
                      config.s2s_client_cert,
                      config.s2s_client_key))
