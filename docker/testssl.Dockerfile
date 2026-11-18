FROM python:3.10-slim-bookworm

ARG uid=36919

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends --no-install-suggests git openssl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends --no-install-suggests bsdmainutils dnsutils procps && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

ARG testssl_branch=3.2

RUN cd /tmp && git clone --depth 1 --branch $testssl_branch https://github.com/testssl/testssl.sh && \
    cd testssl.sh/ && git log --oneline | head -n1 && cd .. && \
    mkdir -p /opt/testssl/ && \
    cp -r /tmp/testssl.sh/etc /tmp/testssl.sh/testssl.sh /opt/testssl/ && \
    ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl && \
    cd / && \
    rm -rf /tmp/testssl.sh

ENV TESTSSL_INSTALL_DIR="/opt/testssl"
ENV TESTXMPP_TESTSSL="/usr/local/bin/testssl"
ENV TESTXMPP_OPENSSL_PATH="/usr/bin/openssl"

COPY setup.py /src/
COPY MANIFEST.in /src/
COPY testxmpp /src/testxmpp
RUN python3 -m venv /opt/venv && \
    cd /src && /opt/venv/bin/pip install '.[testssl]' && \
    rm -rf /root/.cache
ENV PATH="/opt/venv/bin:$PATH"

USER $uid

ENTRYPOINT ["python3", "-m", "testxmpp.testssl"]
