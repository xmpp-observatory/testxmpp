import asyncio
import logging
import json
import typing

import defusedxml.ElementTree

import sqlalchemy.orm

import aiohttp

import dns
import dns.rdatatype

import testxmpp.dns
import testxmpp.model as model

from .common import generate_task_id


async def gather_srv_records(domain: bytes, services: typing.List[str]):
    domain = testxmpp.dns.encode_domain(domain)
    for service in services:
        try:
            records = await testxmpp.dns.lookup_srv(domain, "tcp", service,
                                                    raise_on_no_answer=False)
        except dns.resolver.NXDOMAIN:
            continue

        for record in records:
            yield (service, record)


async def discover_srv_records(domain: bytes,
                               protocol: model.ScanType):
    srv_services = {
        model.ScanType.C2S: ["xmpp-client", "xmpps-client"],
        model.ScanType.S2S: ["xmpp-server", "xmpps-server"],
    }[protocol]

    async for service, record in gather_srv_records(domain, srv_services):
        db_record = model.SRVRecord()
        db_record.service = service
        db_record.protocol = "tcp"
        db_record.weight = record.weight
        db_record.port = record.port
        db_record.priority = record.priority
        db_record.host = record.target.to_text().encode("ascii")
        yield db_record


async def discover_xmppconnect_records(domain: bytes):
    domain = testxmpp.dns.encode_domain(domain)
    qname = b"_xmppconnect." + domain
    for record in (await testxmpp.dns.resolve(qname, dns.rdatatype.TXT,
                                              suppress_nxdomain=True)):
        for blob in record.strings:
            name, _, value = blob.partition(b"=")
            db_record = model.XMPPConnectRecord()
            db_record.attribute_name = name
            db_record.attribute_value = value
            yield db_record


def interpret_xmppconnect_record(name: bytes, value: bytes, prefix: bytes):
    if not name.startswith(prefix):
        return None

    key = name[len(prefix):]
    try:
        http_mode = {
            b"xbosh": model.HTTPMode.XEP0206_BOSH,
            b"websocket": model.HTTPMode.RFC7395_WEBSOCKETS,
            b"httppoll": model.HTTPMode.XEP0025_POLLING,
        }[key]
    except KeyError:
        return None

    endpoint = model.EndpointHTTP()
    endpoint.http_mode = http_mode
    endpoint.transport = model.TransportLayer.HTTP

    try:
        endpoint.url = value.decode("utf-8")
    except UnicodeDecodeError:
        return None

    return endpoint


def parse_xml_host_meta(data: bytes):
    el = defusedxml.ElementTree.fromstring(data)
    if el.tag != "{http://docs.oasis-open.org/ns/xri/xrd-1.0}XRD":
        raise ValueError("not a valid host-meta file")

    for link in el.iter(
            "{http://docs.oasis-open.org/ns/xri/xrd-1.0}Link"):
        attr = link.attrib
        try:
            rel = attr["rel"]
            href = attr["href"]
        except KeyError as exc:
            continue
        yield rel, href


def parse_json_host_meta(data: bytes, charset: typing.Optional[str]):
    if charset is None:
        charset = "utf-8"

    data_s = data.decode(charset)
    data_j = json.loads(data_s)
    for link in data_j.get("links", []):
        try:
            rel = link["rel"]
            href = link["href"]
        except KeyError:
            continue
        yield rel, href


async def download(session, url: str, max_size: int):
    BLOCK_SIZE = 1024**2
    total_size = 0
    parts = []
    async with session.get(url, raise_for_status=True) as response:
        charset = response.charset
        while total_size < max_size:
            chunk = await response.content.read(BLOCK_SIZE)
            if not chunk:
                break
            parts.append(chunk)
            total_size += len(chunk)
        else:
            raise ValueError("response too large")

    return charset, b"".join(parts)


async def discover_host_meta_links(domain: bytes):
    logger = logging.getLogger(__name__).getChild(
        "discover_host_meta_links:{}".format(domain.decode("ascii"))
    )

    xml_url = "https://{}/.well-known/host-meta".format(
        domain.decode("ascii")
    )
    json_url = "{}.json".format(xml_url)
    db_objects = []
    async with aiohttp.ClientSession() as session:
        xml_data, json_data = await asyncio.gather(
            download(session, xml_url, 1024**2),
            download(session, json_url, 1024**2),
            return_exceptions=True,
        )

        if isinstance(xml_data, tuple):
            _, xml_data = xml_data
            db_object = model.HostMetaObject()
            db_object.url = xml_url
            db_object.format_ = model.HostMetaFormat.XML
            db_objects.append(db_object)

            try:
                for rel, href in parse_xml_host_meta(xml_data):
                    try:
                        db_link = model.HostMetaLink()
                        db_link.object_ = db_object
                        db_link.rel = rel
                        db_link.href = href
                        db_objects.append(db_link)
                    except ValueError as exc:
                        logger.debug("discarding link: %s", exc)
                db_objects.append(db_object)
            except ValueError as exc:
                logger.debug("discarding object: %s", exc)
        else:
            logger.debug("failed to download object from %r: %s",
                         xml_url, xml_data)

        if isinstance(json_data, tuple):
            charset, json_data = json_data

            db_object = model.HostMetaObject()
            db_object.url = json_url
            db_object.format_ = model.HostMetaFormat.JSON
            try:
                for rel, href in parse_json_host_meta(json_data, charset):
                    try:
                        db_link = model.HostMetaLink()
                        db_link.object_ = db_object
                        db_link.rel = rel
                        db_link.href = href
                        db_objects.append(db_link)
                    except ValueError as exc:
                        logger.debug("discarding link: %s", exc)
                db_objects.append(db_object)
            except ValueError as exc:
                logger.debug("discarding object: %s", exc)
        else:
            logger.debug("failed to download object from %r: %s",
                         json_url, json_data)

    return db_objects


def interpret_host_meta_link(rel: str, href: str):
    try:
        http_mode = {
            "urn:xmpp:alt-connections:xbosh":
                model.HTTPMode.XEP0206_BOSH,
            "urn:xmpp:alt-connections:websocket":
                model.HTTPMode.RFC7395_WEBSOCKETS,
            "urn:xmpp:alt-connections:httppoll":
                model.HTTPMode.XEP0025_POLLING,
        }[rel]
    except KeyError:
        return None

    endpoint = model.EndpointHTTP()
    endpoint.http_mode = http_mode
    endpoint.transport = model.TransportLayer.HTTP
    endpoint.url = href

    return endpoint


async def discover_endpoints(scan_id: int,
                             domain: bytes,
                             protocol: model.ScanType):
    altconnect_endpoints = {}

    def get_or_add_altconnect_endpoint(endpoint):
        key = endpoint.http_mode, endpoint.url
        try:
            return altconnect_endpoints[key]
        except KeyError:
            altconnect_endpoints[key] = endpoint
            endpoint.scan_id = scan_id
            db_objects.append(endpoint)
            return endpoint

    db_objects = []
    async for db_record in discover_srv_records(domain, protocol):
        db_record.scan_id = scan_id
        db_objects.append(db_record)
        db_endpoint = model.EndpointTCP()
        db_endpoint.scan_id = scan_id
        db_endpoint.transport = model.TransportLayer.TCP
        db_endpoint.srv_record = db_record
        db_endpoint.tls_mode = {
            "xmpp-client": model.TLSMode.STARTTLS,
            "xmpp-server": model.TLSMode.STARTTLS,
            "xmpps-client": model.TLSMode.DIRECT,
            "xmpps-server": model.TLSMode.DIRECT,
        }[db_record.service]
        db_endpoint.hostname = db_record.host
        db_endpoint.port = db_record.port
        db_objects.append(db_endpoint)

    if protocol == model.ScanType.C2S:
        async for db_record in discover_xmppconnect_records(domain):
            db_record.scan_id = scan_id
            db_objects.append(db_record)

            endpoint = interpret_xmppconnect_record(
                db_record.attribute_name,
                db_record.attribute_value,
                b"_xmpp-client-",
            )
            if endpoint is not None:
                endpoint = get_or_add_altconnect_endpoint(endpoint)
                endpoint.xmppconnect_record = db_record

        for db_object in (await discover_host_meta_links(domain)):
            db_objects.append(db_object)
            if isinstance(db_object, model.HostMetaLink):
                endpoint = interpret_host_meta_link(
                    db_object.rel,
                    db_object.href,
                )
                if endpoint is not None:
                    endpoint = get_or_add_altconnect_endpoint(endpoint)
                    endpoint.host_meta_link = db_object
            if isinstance(db_object, model.HostMetaObject):
                db_object.scan_id = scan_id

    fallback_port = {
        model.ScanType.C2S: 5222,
        model.ScanType.S2S: 5269,
    }[protocol]

    endpoint = model.EndpointTCP()
    endpoint.scan_id = scan_id
    endpoint.transport = model.TransportLayer.TCP
    endpoint.tls_mode = model.TLSMode.STARTTLS
    endpoint.hostname = domain
    endpoint.port = fallback_port
    db_objects.append(endpoint)

    return db_objects


def select_endpoints(session, task_id):
    try:
        task = session.query(model.ScanTask).filter(
            model.ScanTask.id_ == task_id,
        ).one()
    except sqlalchemy.orm.exc.NoResultError:
        return

    endpoint_q = session.query(
        model.Endpoint,
        model.EndpointScanResult,
        model.SRVRecord,
    ).select_from(model.Endpoint).outerjoin(
        model.EndpointScanResult,
    ).outerjoin(model.SRVRecord).filter(
        model.Endpoint.scan_id == task.scan_id
    )

    best_endpoint_score = None
    best_endpoint = None
    for ep, scan_result, srv_record in endpoint_q:
        if isinstance(ep, model.EndpointHTTP):
            # not supported
            continue

        if scan_result is None:
            # no successful scan -> cannot use
            continue

        if scan_result.error or scan_result.errno:
            # also not successful -> cannot use either
            continue

        if srv_record is None:
            score = (0, 0, 0)
        else:
            score = (1, -srv_record.priority, srv_record.weight)

        if best_endpoint_score is None or best_endpoint_score < score:
            best_endpoint = ep
            best_endpoint_score = score

    # TODO: handle case where no best endpoint arrives by marking the scan as
    # bad in some way
    if best_endpoint is None:
        return

    testssl_task = model.ScanTask()
    testssl_task.id_ = generate_task_id()
    testssl_task.type_ = model.TaskType.TLS_SCAN
    testssl_task.endpoint = best_endpoint
    testssl_task.scan_id = task.scan_id
    testssl_task.state = model.TaskState.WAITING
    session.add(testssl_task)

    task.mark_completed(session)
