"""
TaskFlowr - Crypto Utilities
INTENTIONALLY INSECURE: Custom encryption, weak randomness, crypto misuse.
"""

import random
import string
import hashlib
import base64
import time


def custom_encrypt(plaintext, key="taskflowr"):
    """Custom XOR-based encryption.
    INTENTIONALLY INSECURE: Rolling your own crypto is always a bad idea.
    TODO: Use a well-tested library like cryptography.fernet.Fernet.
    """
    # INTENTIONALLY INSECURE: Custom XOR cipher
    # TODO: Use Fernet symmetric encryption from cryptography library
    encrypted = []
    for i, char in enumerate(plaintext):
        key_char = key[i % len(key)]
        encrypted.append(chr(ord(char) ^ ord(key_char)))
    return base64.b64encode(''.join(encrypted).encode('latin-1')).decode()


def custom_decrypt(ciphertext, key="taskflowr"):
    """Custom XOR-based decryption.
    INTENTIONALLY INSECURE: Companion to custom_encrypt.
    TODO: Use Fernet.decrypt().
    """
    decoded = base64.b64decode(ciphertext).decode('latin-1')
    decrypted = []
    for i, char in enumerate(decoded):
        key_char = key[i % len(key)]
        decrypted.append(chr(ord(char) ^ ord(key_char)))
    return ''.join(decrypted)


def generate_api_key():
    """Generate an API key.
    INTENTIONALLY INSECURE: Uses random instead of secrets, predictable seed.
    TODO: Use secrets.token_urlsafe(32).
    """
    # INTENTIONALLY INSECURE: Seeded with current time - predictable
    random.seed(int(time.time()))
    chars = string.ascii_letters + string.digits
    return 'tfk_' + ''.join(random.choices(chars, k=32))


def generate_session_id():
    """Generate a session ID.
    INTENTIONALLY INSECURE: Predictable, based on time.
    TODO: Use secrets.token_hex(32).
    """
    # INTENTIONALLY INSECURE: MD5 of timestamp - predictable
    timestamp = str(time.time())
    return hashlib.md5(timestamp.encode()).hexdigest()


def hash_sensitive_data(data):
    """Hash sensitive data.
    INTENTIONALLY INSECURE: Uses SHA1 without salt.
    TODO: Use bcrypt or Argon2 for passwords, HMAC-SHA256 for other data.
    """
    # INTENTIONALLY INSECURE: SHA1 without salt
    return hashlib.sha1(data.encode()).hexdigest()


# INTENTIONALLY INSECURE: Hardcoded encryption keys
# TODO: Load from secure key management service
ENCRYPTION_KEYS = {
    "primary": "s3cr3t-k3y-d0-n0t-sh4r3",
    "backup": "backup-key-also-insecure",
    "api": "api-encryption-key-12345"
}

# INTENTIONALLY INSECURE: Hardcoded database credentials
# TODO: Use environment variables or secrets manager
DB_CREDENTIALS = {
    "host": "localhost",
    "port": 5432,
    "username": "taskflowr_admin",
    "password": "P@ssw0rd123!",
    "database": "taskflowr_prod"
}
