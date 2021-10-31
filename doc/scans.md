# Scans

- SRV Endpoint Discovery

    - Check for CNAMEs
    - Check if all endpoints have the advertised ports open

- A/AAAA fallback test (c2s only)

    - Check if :5222 is open and responds to XMPP correctly, to handle weird
      DNS problems

- _xmppconnect TXT check, also the .well-known thing

- TLSA Record Discovery on all endpoints
- TLS Scan: classic testssl.sh
- Trust Check: Validate certificate chain against trust stores
- DANE Check: Validate TLSA records against Certificates of all endpoints
- Stream Features:

    - Scrape SASL pre- and post-TLS
    - With client certificate to allow discovery of EXTERNAL (s2s only)
    - Maybe even post-Auth if EXTERNAL is possible (s2s only)

- Ping Check (s2s only):

    - Use two or three accounts to ping

- TLS tolerance checks (s2s only):

    - Use badxmpp-style stuff and see if pings pass

- Disco#info:

    - Obtain and list features
