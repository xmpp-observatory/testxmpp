FROM python:3.10-slim-bookworm

ARG uid=36919

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends --no-install-suggests git && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends --no-install-suggests make && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

ARG uid=36919

COPY setup.py build-requirements.txt MANIFEST.in Makefile /src/
COPY testxmpp /src/testxmpp
RUN python3 -m venv /opt/venv && \
    cd /src && \
    /opt/venv/bin/pip install -r build-requirements.txt && \
    make build_css PYTHON3=/opt/venv/bin/python && \
    /opt/venv/bin/pip install '.[web]' hypercorn && \
    cd / && \
    rm -rf /src /root/.cache
ENV PATH="/opt/venv/bin:$PATH"

USER $uid

ENTRYPOINT ["hypercorn", "-b", "::", "testxmpp.web:create_app()"]
