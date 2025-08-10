// src/auth.h
#ifndef AUTH_H
#define AUTH_H

#include <stddef.h>

#define AUTH_ETC_PATH "/etc/securePass/auth.conf"
#define KDF_VAR_PATH "/var/lib/securePass/kdf.json"

/* For testing with DESTDIR, these will be replaced at compile/install time or you can
   set DESTDIR when installing files and run the executable pointing to DESTDIR paths. */

int cmd_init(const char *etc_path, const char *kdf_path);
int cmd_verify(const char *etc_path, const char *kdf_path);
int cmd_derive_key(const char *kdf_path);
int authenticate();

#endif