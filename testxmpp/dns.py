import asyncio
import itertools
import functools
import threading
import typing

import dns.rdataclass
import dns.rdatatype
# NOTE: Not using asyncresolver here because it crashes with InvalidState
# exceptions... may be due to specific python/asyncio versions.
# Using a thread pool seems to be the safer choice.
import dns.resolver

_state = threading.local()


def get_resolver():
    global _state
    if not hasattr(_state, "resolver"):
        reconfigure_resolver()
    return _state.resolver


def reconfigure_resolver():
    global _state
    _state.resolver = dns.resolver.Resolver()
    _state.overridden_resolver = False


def encode_domain(domain: typing.Union[str, bytes]) -> bytes:
    if isinstance(domain, str):
        domain = domain.encode("idna")
    return domain


async def achain(*aws):
    pending = list(map(asyncio.ensure_future, aws))
    try:
        while pending:
            done, pending = await asyncio.wait(
                pending,
                return_when=asyncio.FIRST_COMPLETED,
            )
            for fut in done:
                result = await fut
                for value in result:
                    yield value

    finally:
        for fut in pending:
            if not fut.done():
                fut.cancel()


async def resolve(qname: bytes, rdtype,
                  rdclass=dns.rdataclass.IN,
                  suppress_nxdomain=False,
                  search=False,
                  **kwargs):
    loop = asyncio.get_event_loop()
    resolver = get_resolver()
    try:
        return await loop.run_in_executor(
            None,
            functools.partial(
                resolver.resolve,
                qname.decode("ascii"),
                rdtype=rdtype,
                rdclass=rdclass,
                search=search,
                **kwargs,
            )
        )
    except dns.resolver.NXDOMAIN:
        if suppress_nxdomain:
            return []
        raise


async def lookup_srv(domain: typing.Union[str, bytes],
                     protocol: str,
                     service: str,
                     **kwargs):
    domain = encode_domain(domain)
    qname = b".".join([
        "_{}".format(service).encode("ascii"),
        "_{}".format(protocol).encode("ascii"),
        domain,
    ])
    return await resolve(qname, dns.rdatatype.SRV, **kwargs)


async def lookup_addresses(domain: typing.Union[str, bytes]):
    domain = encode_domain(domain)
    async for record in achain(resolve(domain, dns.rdatatype.A,
                                       raise_on_no_answer=False,
                                       suppress_nxdomain=True),
                               resolve(domain, dns.rdatatype.AAAA,
                                       raise_on_no_answer=False,
                                       suppress_nxdomain=True)):
        yield record
