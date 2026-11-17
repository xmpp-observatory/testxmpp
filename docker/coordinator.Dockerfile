FROM python:3.10-slim-bookworm

ARG uid=36919

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends --no-install-suggests git && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY setup.py MANIFEST.in alembic.ini /src/
COPY testxmpp /src/testxmpp
COPY alembic /src/alembic
RUN python3 -m venv /opt/venv && \
    cd /src && /opt/venv/bin/pip install '.[coordinator]' alembic && \
    rm -rf /root/.cache
ENV PATH="/opt/venv/bin:$PATH"
COPY docker/coordinator.sh /coordinator.sh

USER $uid

ENTRYPOINT ["/coordinator.sh"]
