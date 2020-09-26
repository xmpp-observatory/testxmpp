from schema import Schema, Or, Optional

schema = Schema({
    "database": {
        "uri": str,
    },
    "zmq": {
        Optional("listen_url", default="tcp://*:5000"): str,
    },
})
