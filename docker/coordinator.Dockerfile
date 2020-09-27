FROM python:3.8

ARG uid=36919

COPY setup.py /src/
COPY MANIFEST.in /src/
COPY testxmpp /src/testxmpp
RUN cd /src && pip install .

USER $uid

ENTRYPOINT ["python", "-m", "testxmpp.coordinator"]
