import argparse
import asyncio
import pathlib

import toml

from .daemon import Coordinator


async def amain(config):
    coordinator = Coordinator(config)
    await coordinator.run()


def main():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-c", "--config-file",
        default=pathlib.Path("/etc/testxmpp/coordinator.toml"),
        type=pathlib.Path,
        help="Path to configuration file",
    )

    args = parser.parse_args()

    with args.config_file.open("r") as f:
        config = toml.load(f)

    asyncio.run(amain(config))
