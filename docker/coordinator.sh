#!/bin/bash
set -euo pipefail
pushd /src >/dev/null
python3 -m alembic upgrade head
popd >/dev/null
exec python3 -m testxmpp.coordinator "$@"
