# Privileged Scans

## Motivation

- Offer an easy way for server operators to create extended scans
- Vulnerability scanning should not be the default because it might be an attack in some sense of the law

## Properties

- Allow enabling vulnerability scans
- Allow testssl-scanning all endpoints
- Allow scanning more often than every 30 mins (every 5 mins?)

## Authentication

1. XMPP based

  1. Ask for subscription to $jid by one of the JIDs published in the contact info
  2. If subscribed, send message with token (valid for 24h or so)
  3. If token valid, allow privileged scan

2. DNS based

  1. Generate token := HMAC(salt || domain name || '\0' || shared secret || salt)
  2. Ask user to put token in TXT record
  3. On scan, ask for input of shared secret
  4. Validate shared secret against TXT record before creating scan

3. Admin override

  1. Secret admin token
