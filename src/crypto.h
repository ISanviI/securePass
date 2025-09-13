// src/crypto.h
#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>

/* For testing with DESTDIR, these will be replaced at compile/install time or you may pass alt paths */

int cmd_init(const char *etc_path);
int cmd_verify(const char *etc_path);
int derive_key(const char *pass, const unsigned char *salt, unsigned char *key, size_t key_len);

#endif
