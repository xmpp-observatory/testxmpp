import argparse
import asyncio
import logging
import pathlib

import toml

from .daemon import TestSSLWorker


async def amain(config):
    coordinator = TestSSLWorker(config)
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
    parser.add_argument(
        "-c", "--config-file",
        default=pathlib.Path("/etc/testxmpp/testssl_worker.toml"),
        type=pathlib.Path,
        help="Path to configuration file",
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

    with args.config_file.open("r") as f:
        config = toml.load(f)

    asyncio.run(amain(config))
