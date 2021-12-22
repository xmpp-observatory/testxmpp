FROM debian:bullseye-slim

ARG uid=36919

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends --no-install-suggests python3-pip git && \
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
RUN cd /src && \
    pip install -r build-requirements.txt && \
    make build_css && \
    pip install '.[web]' && \
    pip install hypercorn && \
    cd / && \
    rm -rf /src /root/.cache

USER $uid

ENTRYPOINT ["hypercorn", "-b", "::", "testxmpp.web:create_app()"]
