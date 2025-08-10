# OpenSSL --> cryptography toolkit — Provides:
* Encryption algorithms (AES, RSA, ChaCha20, etc.)
* Decryption
* Hash functions (SHA-256, SHA-512, etc.)
* Digital signatures
* TLS/SSL protocols

## Reversible (Decryptable) ones:
Used to read the text later.
* AES (Advanced Encryption Standard) - Symmetric
* RSA - Asymmetric

## Irreversible: (Hashes)
Fixed length, non decryptable
Used for -> Password hashing (with salt); File/Data integrity checks; Digital signatures
* SHA-256 (Output is 256 bits)
* SHA-512
* bcrypt
* Argon2/argon2i/argon2d/argon2id (most recommended fro password hashing) - Both CPU-hard and memory-hard (practically difficult to use. Each hash takes up 65MB memory.)

# Our Application
## Argon2ID possible usecases
1. Verify that the person entering the CLI is the same one who set it up.
  * Store an Argon2id hash of their passphrase (this is irreversible).
  * During login, you run Argon2id again with their entered passphrase, compare to stored hash for authorization.
2. Passphrase to unlock AES encryption:
  * Use Argon2id as a Key Derivation Function (KDF):
  * Input: user passphrase + random salt
  * Output: AES-256 key
  * Encrypt the database with AES-256-GCM.
  * Store alongside the ciphertext:

Our method --> AES-256-GCM