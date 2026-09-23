import hashlib
import hmac
import secrets


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_agent_token() -> str:
    return secrets.token_urlsafe(48)


def new_enrollment_token() -> str:
    # The fixed prefix makes the token easy to recognize in logs and secret scanners and
    # guarantees it never starts with "-", so it is safe as a shell argument.
    return "fv_" + secrets.token_urlsafe(32)


def secure_equal(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def password_hash(value: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", value.encode("utf-8"), salt, 600_000)
    return f"pbkdf2_sha256$600000${salt.hex()}${digest.hex()}"


def verify_password(value: str, encoded: str) -> bool:
    try:
        algorithm, iterations, salt_hex, expected_hex = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256", value.encode("utf-8"), bytes.fromhex(salt_hex), int(iterations)
        )
        return hmac.compare_digest(digest, bytes.fromhex(expected_hex))
    except (ValueError, TypeError):
        return False
