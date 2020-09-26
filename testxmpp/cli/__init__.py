import asyncio
import pprint

import zmq.asyncio

import testxmpp.api.coordinator as coordinator_api


async def do_ping(args, sock):
    await sock.send_json(coordinator_api.mkv1request(
        coordinator_api.RequestType.PING,
        {},
    ))
    resp = await sock.recv_json()
    pprint.pprint(resp)


async def do_scan(args, sock):
    await sock.send_json(coordinator_api.mkv1request(
        coordinator_api.RequestType.SCAN_DOMAIN,
        {
            "domain": args.domain,
            "protocol": args.protocol,
        }
    ))
    resp = await sock.recv_json()
    pprint.pprint(resp)


async def do_get_testssl_job(args, sock):
    await sock.send_json(coordinator_api.mkv1request(
        coordinator_api.RequestType.GET_TESTSSL_JOB,
        {
            "worker_id": args.worker_id,
        }
    ))
    resp = await sock.recv_json()
    pprint.pprint(resp)


async def amain(args):
    zctx = zmq.asyncio.Context()
    sock = zctx.socket(zmq.REQ)
    try:
        sock.connect(args.coordinator_url)
        await args.func(args, sock)
    finally:
        sock.close()


def main():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-C", "--coordinator-url",
        default="tcp://localhost:5001",
    )

    subparsers = parser.add_subparsers()

    subparser = subparsers.add_parser("ping")
    subparser.set_defaults(func=do_ping)

    subparser = subparsers.add_parser("scan")
    subparser.set_defaults(func=do_scan)
    subparser.add_argument(
        "domain",
    )
    subparser.add_argument(
        "protocol",
        choices=("c2s", "s2s"),
    )

    subparser = subparsers.add_parser("get-testssl-job")
    subparser.set_defaults(func=do_get_testssl_job)
    subparser.add_argument(
        "worker_id",
        nargs="?",
        default="cliclientxxxxxxxxxxxxxxxxxxxxxxx",
    )

    args = parser.parse_args()

    asyncio.run(amain(args))
