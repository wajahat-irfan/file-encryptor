#!/usr/bin/env python3
"""
File Encryptor
--------------
Encrypt and decrypt files with a password, using Fernet (AES-128 in CBC
mode with HMAC) and a key derived from the password with PBKDF2HMAC.

The encrypted file stores: 16-byte random salt + Fernet token.
Decryption reads the salt back, re-derives the same key from the password,
and decrypts.

Usage:
    python encryptor.py encrypt secret.txt secret.enc
    python encryptor.py decrypt secret.enc secret.txt

You will be prompted for a password (hidden input). The same password is
needed to decrypt. A wrong password fails with an error — the file is
unrecoverable without the correct password.

WARNING: learning/demo tool only — see the README before trusting it with
real sensitive data.
"""

import getpass
import os
import sys

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SALT_SIZE = 16
KDF_ITERATIONS = 480_000


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a Fernet-compatible key from a password + salt."""
    import base64

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def encrypt_file(input_path: str, output_path: str, password: str) -> None:
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt)
    with open(input_path, "rb") as f:
        plaintext = f.read()
    token = Fernet(key).encrypt(plaintext)
    with open(output_path, "wb") as f:
        f.write(salt + token)
    print(f"Encrypted {input_path} -> {output_path} ({len(plaintext)} bytes)")


def decrypt_file(input_path: str, output_path: str, password: str) -> None:
    with open(input_path, "rb") as f:
        data = f.read()
    if len(data) <= SALT_SIZE:
        print("Error: file is too short to be an encrypted file from this tool.")
        sys.exit(1)
    salt, token = data[:SALT_SIZE], data[SALT_SIZE:]
    key = derive_key(password, salt)
    try:
        plaintext = Fernet(key).decrypt(token)
    except InvalidToken:
        print("Error: decryption failed — wrong password or corrupted file.")
        sys.exit(1)
    with open(output_path, "wb") as f:
        f.write(plaintext)
    print(f"Decrypted {input_path} -> {output_path} ({len(plaintext)} bytes)")


def main() -> None:
    if len(sys.argv) != 4 or sys.argv[1] not in ("encrypt", "decrypt"):
        print("Usage:")
        print("  python encryptor.py encrypt <input> <output>")
        print("  python encryptor.py decrypt <input> <output>")
        sys.exit(1)

    action, input_path, output_path = sys.argv[1], sys.argv[2], sys.argv[3]

    if not os.path.exists(input_path):
        print(f"Error: input file not found: {input_path}")
        sys.exit(1)

    password = getpass.getpass("Enter password: ")
    if not password:
        print("Error: empty password not allowed.")
        sys.exit(1)

    if action == "encrypt":
        encrypt_file(input_path, output_path, password)
    else:
        decrypt_file(input_path, output_path, password)


if __name__ == "__main__":
    main()
