// src/auth.h
#ifndef AUTH_H
#define AUTH_H

#include <stddef.h>

#define AUTH_ETC_PATH "/etc/securePass/auth.conf"

/* Argon2id parameters for key derivation. */
#define KDF_T_COST 2
#define KDF_M_COST (1 << 15) /* 32 MiB */
#define KDF_PARALLELISM 1
#define KDF_KEY_LEN 32 /* AES-256 */
#define KDF_SALT_LEN 16

/* For testing with DESTDIR, these will be replaced at compile/install time or you can
   set DESTDIR when installing files and run the executable pointing to DESTDIR paths. */

int cmd_init(const char *etc_path);
int cmd_verify(const char *etc_path);
int derive_key(const char *pass, const unsigned char *salt, unsigned char *key, size_t key_len);
int authenticate();

#endif