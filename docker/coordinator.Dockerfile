FROM debian:bullseye-slim

ARG uid=36919

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends --no-install-suggests python3-pip git && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY setup.py MANIFEST.in alembic.ini /src/
COPY testxmpp /src/testxmpp
COPY alembic /src/alembic
RUN cd /src && pip3 install '.[coordinator]' && pip3 install alembic && rm -rf /root/.cache
COPY docker/coordinator.sh /coordinator.sh

USER $uid

ENTRYPOINT ["/coordinator.sh"]
