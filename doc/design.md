# Design

## Overview

### Components

- Web frontend
- testssl.sh backend
- xmpp-blackbox-exporter backend
- database
- coordinator

### Communication

ZeroMQ

### Data flow

#### Web frontend

- Sends scan requests (synchronously) to coordinator
- Reads from database

#### Coordinator

- Receives scan requests from web frontend
- Dispatches steps to backends (asynchronously)
- Receives results from backends (asynchronously)
- Writes results to database

#### testssl.sh backend

- Receives scan requests from coordinator
- Emits results step-by-step

#### xmpp-blackbox-exporter backend

- Receives scan requests from coordinator (possibly directly via HTTP)


## Coordinator

- Central broker between all backends and the database
