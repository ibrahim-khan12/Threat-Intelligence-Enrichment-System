import hashlib
import secrets


def generate_api_key() -> str:
    return f"tip_{secrets.token_urlsafe(24)}"


def hash_api_key(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def key_prefix(value: str) -> str:
    return value[:16]
