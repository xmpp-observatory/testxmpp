import argparse
import asyncio
import logging
import os
import pathlib
import sys

import toml

from .daemon import Coordinator


async def amain(db_uri, listen_uri):
    coordinator = Coordinator(db_uri, listen_uri)
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

    try:
        db_uri = os.environ["TESTXMPP_DB_URI"]
        listen_uri = os.environ.get(
            "TESTXMPP_LISTEN_URI",
            "tcp://*:5001"
        )
    except KeyError as exc:
        logging.error("environment variable %s must be set", exc)
        sys.exit(2)
        return 2

    asyncio.run(amain(db_uri, listen_uri))