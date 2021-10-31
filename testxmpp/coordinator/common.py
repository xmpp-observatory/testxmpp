import secrets


def generate_task_id() -> bytes:
    return secrets.token_bytes(16)
