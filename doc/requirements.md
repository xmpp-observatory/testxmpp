# Requirements

## User Interaction

- MUST accept domain name as well as s2s vs. c2s input for scan
- MUST NOT block until all scans have finished
- MUST show intermediate results
- MAY support live updates (without reload) of results
- MAY offer statistics based on result values
- MUST provide the following results:

    - SRV record listing (RFC and XEP-0368)
    - TLSA record listing
    - TLSA validation
    - TLS OK/NOT OK result for all endpoints
    - TLS versions offered (for one endpoint only)
    - Certificate info: chain, SAN, fingerprint (for one endpoint only)
    - Cipher list and behaviour (for one endpoint only)

- SHOULD offer scanning a specific endpoint as a follow-up scan or with initial
  parameter (NOTE: requires domain and SRV delegation for security)
- MUST support IPv4 and IPv6

## Backend

- SHOULD NOT lose in-flight and queued scans on restart of any component
- MUST NOT require a replicated or network-reachable database, if all
  components live on the same machine
- SHOULD NOT require a replicated or network-reachable database, if frontend
  and queue manager run on the same machine
- SHOULD support multiple workers of each type in separate processes

# Solutions

## SHOULD NOT lose in-flight and queued scans on restart

- State is recorded in database
- On system start, state is synchronised from database to workers

    - Open question: how to prevent multiple workers from taking the same job
      on startup?

- Workers pull jobs and heartbeat that they are working on a job as long as
  they are
- Workers report intermediate results when available
- Workers report completion or abortion of tasks
- Coordinator reassigns tasks on heartbeat timeout
