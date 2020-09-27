import argparse
import asyncio
import logging
import os
import pathlib
import shlex

import toml

from .daemon import TestSSLWorker


async def amain(coordinator_uri, testssl_argv_base, openssl_path):
    coordinator = TestSSLWorker(coordinator_uri, testssl_argv_base,
                                openssl_path)
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

    coordinator_uri = os.environ.get(
        "TESTXMPP_COORDINATOR_URI",
        "tcp://localhost:5001",
    )

    testssl_argv_base = shlex.split(os.environ.get(
        "TESTXMPP_TESTSSL",
        "testssl",
    ))

    openssl_path = os.environ.get(
        "TESTXMPP_OPENSSL_PATH",
        "/usr/bin/openssl",
    )

    asyncio.run(amain(coordinator_uri, testssl_argv_base, openssl_path))
