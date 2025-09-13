// src/auth.h
#ifndef AUTH_H
#define AUTH_H

#include <stddef.h>

#ifndef AUTH_ETC_PATH
#define AUTH_ETC_PATH "/etc/securePass/auth.conf"
#endif

/* Argon2id parameters for key derivation. */
#define KDF_T_COST 2
#define KDF_M_COST (1 << 15) /* 32 MiB */
#define KDF_PARALLELISM 1
#define KDF_KEY_LEN 32 /* AES-256 */
#define KDF_SALT_LEN 16

int authenticate();

#endif
