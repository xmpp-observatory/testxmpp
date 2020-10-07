# Scans

- SRV Endpoint Discovery

    - Check for CNAMEs
    - Check if all endpoints have the advertised ports open

- TLSA Record Discovery on all endpoints
- TLS Scan: classic testssl.sh
- Trust Check: Validate certificate chain against trust stores
- DANE Check: Validate TLSA records against Certificates of all endpoints
- Stream Features:

    - Scrape SASL pre- and post-TLS
    - With client certificate for s2s to allow discovery of EXTERNAL
    - Maybe even post-Auth if EXTERNAL is possible

- Ping Check:

    - Use two or three accounts to ping

- TLS tolerance checks:

    - Use badxmpp-style stuff and see if pings pass

- Disco#info:

    - Obtain and list features
