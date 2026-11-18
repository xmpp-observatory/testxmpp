FROM python:3.10-slim-bookworm

ARG uid=36919

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends --no-install-suggests git openssl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

ARG aioxmpp_branch=devel

RUN cd /tmp && git clone --depth 1 --branch $aioxmpp_branch https://github.com/horazont/aioxmpp && \
    cd aioxmpp/ && \
    python3 -m venv /opt/venv && \
    /opt/venv/bin/pip install . && \
    cd / && \
    rm -rf /tmp/aioxmpp

RUN sed -ri 's/SECLEVEL=\d+/SECLEVEL=0/;s/MinProtocol\s*=/MinProtocol = SSLv2/' /etc/ssl/openssl.cnf

COPY setup.py /src/
COPY MANIFEST.in /src/
COPY testxmpp /src/testxmpp
RUN cd /src && /opt/venv/bin/pip install . && rm -rf /root/.cache
ENV PATH="/opt/venv/bin:$PATH"

USER $uid

ENTRYPOINT ["python3", "-m", "testxmpp.xmpp"]
