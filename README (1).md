# File Protection Utility

A Python command-line utility for protecting sensitive local files using **AES-256-GCM** authenticated encryption and **PBKDF2-HMAC-SHA256** password-based key derivation.

## Objective

Implement standard AES-256 symmetric file encryption with password key derivation using PBKDF2 and a random salt, then decrypt the file while verifying its authentication tag.

## Features

- AES-256-GCM authenticated encryption.
- PBKDF2-HMAC-SHA256 key derivation.
- Random 16-byte salt for every encrypted file.
- Random 12-byte nonce for every encryption operation.
- Authentication tag automatically verifies ciphertext integrity during decryption.
- Command-line encryption and decryption.
- No password is written to the encrypted file or displayed in the execution logs.

## Requirements

Python 3.9+ and the `cryptography` package.

Install the dependency:

```bash
pip install cryptography
```

## Source Code

Save as `file_protection_utility.py`:

```python
import argparse
import base64
import getpass
import hashlib
import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


MAGIC = b"FPU1"
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
ITERATIONS = 600_000


def derive_key(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        ITERATIONS,
        dklen=KEY_SIZE,
    )


def encrypt_file(input_path: Path, output_path: Path, password: str) -> None:
    plaintext = input_path.read_bytes()
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(password, salt)

    # AES-256-GCM provides confidentiality and authenticated integrity.
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)

    output_path.write_bytes(MAGIC + salt + nonce + ciphertext)


def decrypt_file(input_path: Path, output_path: Path, password: str) -> None:
    data = input_path.read_bytes()

    if len(data) < len(MAGIC) + SALT_SIZE + NONCE_SIZE + 16:
        raise ValueError("Invalid or incomplete encrypted file.")
    if data[:len(MAGIC)] != MAGIC:
        raise ValueError("Unsupported encrypted file format.")

    offset = len(MAGIC)
    salt = data[offset:offset + SALT_SIZE]
    offset += SALT_SIZE
    nonce = data[offset:offset + NONCE_SIZE]
    offset += NONCE_SIZE
    ciphertext = data[offset:]

    key = derive_key(password, salt)
    plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
    output_path.write_bytes(plaintext)


def main():
    parser = argparse.ArgumentParser(
        description="AES-256 file encryption/decryption utility"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    enc = sub.add_parser("encrypt", help="Encrypt a file")
    enc.add_argument("input", type=Path)
    enc.add_argument("output", type=Path)

    dec = sub.add_parser("decrypt", help="Decrypt a file")
    dec.add_argument("input", type=Path)
    dec.add_argument("output", type=Path)

    args = parser.parse_args()

    password = getpass.getpass("Enter password: ")

    try:
        if args.command == "encrypt":
            encrypt_file(args.input, args.output, password)
            print(f"Encrypted: {args.input} -> {args.output}")
            print("Algorithm: AES-256-GCM")
            print("Key derivation: PBKDF2-HMAC-SHA256")
            print("Integrity: authentication tag verified during decryption")
        else:
            decrypt_file(args.input, args.output, password)
            print(f"Decrypted: {args.input} -> {args.output}")
            print("Integrity check: PASS")
    except Exception as exc:
        print(f"Error: {exc}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
```

## Usage

### Encrypt a file

```bash
python file_protection_utility.py encrypt sample_secret.txt sample_secret.txt.enc
```

### Decrypt a file

```bash
python file_protection_utility.py decrypt sample_secret.txt.enc sample_secret_decrypted.txt
```

The program asks for the password without displaying it on the terminal.

## Verification Execution Screenshots

### 1. Encryption

![Encryption execution](encryption_execution.png)

### 2. Decryption and Integrity Verification

![Decryption verification](decryption_verification.png)

The demonstration compares the original and decrypted files after decryption. The execution shown in the screenshot reports **Files identical: YES**.

## Cryptography Design

**Password → PBKDF2-HMAC-SHA256 → 256-bit key → AES-256-GCM**

- **PBKDF2:** derives a 256-bit encryption key from the password and random salt.
- **AES-256:** provides symmetric encryption.
- **GCM:** provides authenticated encryption, so tampering with ciphertext causes decryption verification to fail.
- **Salt:** stored with the encrypted file and is not secret.
- **Nonce:** stored with the encrypted file and must be unique for encryption with the same key.

The encrypted file format used here is:

```text
FPU1 | 16-byte salt | 12-byte nonce | ciphertext + authentication tag
```

## Security Notes

- Use a strong, unique password.
- Do not commit real passwords or sensitive files to GitHub.
- The sample files in this repository are demonstration files only.
- Keep backups of important files before encrypting them.
- AES-GCM's authentication tag is used for integrity/authenticity verification; a separate manually implemented MAC is not required.
- This project is intended for coursework and local file protection demonstrations.

## Project Structure

```text
file_protection_utility/
├── file_protection_utility.py
├── sample_secret.txt
├── sample_secret.txt.enc
├── sample_secret_decrypted.txt
├── encryption_execution.png
├── decryption_verification.png
└── README.md
```

## Verification Result

**Encryption:** Successful  
**Decryption:** Successful  
**Integrity verification:** PASS  
**Original/decrypted files:** Identical

## Author

**Sai Nikitha**
