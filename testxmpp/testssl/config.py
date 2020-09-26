from schema import Schema, Or, Optional


def _upcast_list(v):
    if isinstance(v, str):
        return [v]
    return Schema([str]).validate(v)


schema = Schema({
    "zmq": {
        Optional("listen_url", default="tcp://*:5001"): str,
        Optional("coordinator_url", default="tcp://localhost:5000"): str,
    },
    "scan": {
        Optional("parallelism", default=1): int,
        Optional("testssl", default=["testssl"]): _upcast_list,
    },
})
