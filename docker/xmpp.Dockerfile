FROM debian:bullseye-slim

ARG uid=36919

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends --no-install-suggests python3-pip git && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

ARG aioxmpp_branch=devel

RUN cd /tmp && git clone --depth 1 --branch $aioxmpp_branch https://github.com/horazont/aioxmpp && \
    cd aioxmpp/ && \
    pip3 install . && \
    cd / && \
    rm -rf /tmp/aioxmpp

COPY setup.py /src/
COPY MANIFEST.in /src/
COPY testxmpp /src/testxmpp
RUN cd /src && pip3 install .

USER $uid

ENTRYPOINT ["python3", "-m", "testxmpp.xmpp"]
