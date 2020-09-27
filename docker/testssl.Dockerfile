FROM python:3.8

ARG uid=36919

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y -o Apt::Install-Recommends=0 -o Apt::Install-Suggests=0 bsdmainutils dnsutils && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN cd /tmp && git clone --depth 1 https://github.com/drwetter/testssl.sh && \
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
RUN cd /src && pip install .

USER $uid

ENTRYPOINT ["python", "-m", "testxmpp.testssl"]
