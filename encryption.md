# OpenSSL --> cryptography toolkit

1. Usually stored in `.pem` (Privacy Enhanced Mail) file,

- A general-purpose container (Base64 + headers).
- Can store private keys, public keys, or certificates.
- Used heavily in OpenSSL, OpenSSH, Apache, Nginx.

2. Provides:

- Encryption algorithms (AES, RSA, ChaCha20, etc.)
- Decryption
- Hash functions (SHA-256, SHA-512, etc.)
- Digital signatures
- TLS/SSL protocols (For HTTPS, stored in `.crt, .cer` format)

## PKI

It stands for Public Key Infrastructure.
It’s basically the ecosystem that makes public-key cryptography usable at scale, especially for the web (HTTPS).
It includes

1. Certificates

- Digital documents that bind a public key to an identity (e.g., example.com).
- Format: usually X.509.
- Stored as .crt, .cer, .der
  > .der → Same as .crt/.cer, but binary format instead of Base64.

2. Certificate Authorities (CAs)

- Trusted organizations that issue certificates after verifying ownership.
- Examples: Let’s Encrypt, DigiCert, GlobalSign.

3. Registration Authorities (RAs)

- Entities that verify the identity of certificate requesters before the CA signs their certificate.

4. Certificate Revocation Lists (CRLs) / OCSP

- Mechanisms to invalidate certificates before they expire (compromised or revoked).
- Root & Intermediate Certificates

## OpenSSH vs OpenSSL

SSH has its own trust model, it doesn't use OpenSSL for cryptographic verification unless specified (like in AWS EC2):

1. The first time you connect, the server’s host key (RSA, ED25519, etc.) is presented.
2. You confirm it (Are you sure you want to continue connecting?) → it gets stored in `~/.ssh/known_hosts`.
3. Next time, OpenSSH checks that the server key matches what’s in known_hosts.
4. If it doesn’t, you get a warning about a possible MITM attack.
5. For dynamic IPs:

- The check is by hostname (or IP) string you typed in the ssh command.
- If the server is reached at example.com, the host key is saved under example.com.
- If you later connect via raw IP (say it changed), that won’t match — you’d get a prompt again.
- To handle dynamic IPs, people often use a DNS name instead of direct IP, or they manually add multiple host key entries in known_hosts.

> `.ppk` → PuTTY’s (Windows SSH client's) proprietary private key format.
> Only PuTTY (and related tools) uses it.
> You can convert between .ppk and .pem using PuTTYgen, but .ppk is not an OpenSSL format.

## Reversible (Decryptable) ones:

Used to read the text later.

- AES (Advanced Encryption Standard) - Symmetric
- RSA - Asymmetric

## Irreversible: (Hashes)

Fixed length, non decryptable
Used for -> Password hashing (with salt); File/Data integrity checks; Digital signatures

> Unsecure

- MD5
- SHA-1 (Output - 160 bits)
- SHA-256 (Output - 256 bits)
- SHA-2

> Secure

- SHA-3
- bcrypt
- scrypt
- Argon2/argon2i/argon2d/argon2id (most recommended for password hashing) - Both CPU-hard and memory-hard (practically difficult to use. Each hash takes up 65MB memory.)

# Our Application

## Argon2ID possible usecases

1. Verify that the person entering the CLI is the same one who set it up.

- Store an Argon2id hash of their passphrase (this is irreversible).
- During login, you run Argon2id again with their entered passphrase, compare to stored hash for authorization.

2. Passphrase to unlock AES encryption:

- Use Argon2id as a Key Derivation Function (KDF):
- Input: user passphrase + random salt
- Output: AES-256 key
- Encrypt the database with AES-256-GCM.
- Store alongside the ciphertext:

Our method --> AES-256-GCM
