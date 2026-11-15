# File Encryptor

Encrypt and decrypt files with a password, using Fernet (AES + HMAC) with a key derived from the password via PBKDF2HMAC.

**Author:** Wajahat Irfan — BS Computer Science student (7th semester), GPGC No. 1 Abbottabad

> ⚠️ **WARNING — learning/demo tool only. Do NOT use this to protect real sensitive data.**
> It is a student project for learning how password-based encryption works. It has not been audited, has no protection against password guessing beyond PBKDF2 iterations, and a lost password means the file cannot be recovered. For real sensitive data, use a well-tested, maintained encryption tool.

## What it does

- **Encrypt:** derives a key from your password with PBKDF2HMAC (SHA-256, 480,000 iterations, random 16-byte salt), encrypts the file with Fernet, and writes `salt + ciphertext` to the output file
- **Decrypt:** reads the salt back from the file, re-derives the same key from your password, and restores the original file
- Prompts for the password with hidden input; a wrong password fails cleanly with an error

## Setup

```bash
pip install -r requirements.txt
```

## How to run

```bash
python encryptor.py encrypt secret.txt secret.enc
python encryptor.py decrypt secret.enc secret.txt
```

You will be prompted for a password each time — the same password is needed to decrypt.

## Example output

```
$ echo "My secret notes" > test.txt
$ python encryptor.py encrypt test.txt test.enc
Enter password:
Encrypted test.txt -> test.enc (17 bytes)

$ python encryptor.py decrypt test.enc test-decrypted.txt
Enter password:
Decrypted test.enc -> test-decrypted.txt (17 bytes)

$ diff test.txt test-decrypted.txt && echo "Round-trip OK — files match"
Round-trip OK — files match
```

## Skills shown

- Symmetric encryption with the `cryptography` library (Fernet)
- Password-based key derivation (PBKDF2HMAC, salt, iterations)
- Binary file I/O and hidden password input (`getpass`)
- Error handling for wrong passwords / corrupted files
