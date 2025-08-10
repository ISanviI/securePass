// src/auth.c
// static function is a function whose scope is limited to the translation unit (typically, the source file) in which it is defined. This means that the function can only be called from within the same source file and is not visible or accessible from other source files in the program.
#define _GNU_SOURCE
#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include "auth.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include <openssl/rand.h>
#include <openssl/evp.h>

#include <argon2.h>

// PAM (Pluggable Authentication Modules) -> authentication framework used in Linux.
// pam_authenticate() → User Authentication
// pam_acct_mgmt() → User Authorization and user management (expiration, restrictions, account status, etc.)
// pam_start() → Initializes the PAM library and prepares it for use.
// pam_end() → Cleans up the PAM library and releases resources.
// pam_unix.so	-> The actual module present at /usr/lib/security/pam_*.so being used — pam_unix handles standard UNIX password authentication (using /etc/passwd & /etc/shadow).
static struct pam_conv conv = {
    misc_conv,
    NULL};

int authenticate()
{
  pam_handle_t *pamh = NULL;
  int retval = pam_start("securepass", NULL, &conv, &pamh);
  // It loads the file: etc/pam.d/securePass to get authentication configuration details.

  if (retval == PAM_SUCCESS)
    retval = pam_authenticate(pamh, 0);

  if (retval == PAM_SUCCESS)
    retval = pam_acct_mgmt(pamh, 0);

  pam_end(pamh, retval);
  return retval == PAM_SUCCESS ? 1 : 0;
}

/* Utility: hex encode / decode */
static void hex_encode(const unsigned char *in, size_t len, char *out)
{
  static const char hex[] = "0123456789abcdef";
  for (size_t i = 0; i < len; ++i)
  {
    out[i * 2] = hex[(in[i] >> 4) & 0xF];
    out[i * 2 + 1] = hex[in[i] & 0xF];
  }
  out[len * 2] = '\0';
}

static int hex_decode(const char *hexstr, unsigned char *out, size_t outlen)
{
  size_t hexlen = strlen(hexstr);
  if (hexlen != outlen * 2)
    return -1;
  for (size_t i = 0; i < outlen; ++i)
  {
    char a = hexstr[i * 2], b = hexstr[i * 2 + 1];
    int va = (a >= '0' && a <= '9') ? a - '0' : (a >= 'a' && a <= 'f') ? a - 'a' + 10
                                            : (a >= 'A' && a <= 'F')   ? a - 'A' + 10
                                                                       : -1;
    int vb = (b >= '0' && b <= '9') ? b - '0' : (b >= 'a' && b <= 'f') ? b - 'a' + 10
                                            : (b >= 'A' && b <= 'F')   ? b - 'A' + 10
                                                                       : -1;
    if (va < 0 || vb < 0)
      return -1;
    out[i] = (unsigned char)((va << 4) | vb);
  }
  return 0;
}

/* Constant-time comparison */
static int const_time_cmp(const unsigned char *a, const unsigned char *b, size_t len)
{
  unsigned char r = 0;
  for (size_t i = 0; i < len; ++i)
    r |= a[i] ^ b[i];
  return r == 0;
}

/* Ensure dir exists with 0700. Returns 0 on success. */
static int ensure_dir(const char *path)
{
  struct stat st;
  if (stat(path, &st) == 0)
  {
    if (!S_ISDIR(st.st_mode))
      return -1;
    /* optionally set permissions */
    chmod(path, S_IRWXU);
    return 0;
  }
  if (mkdir(path, S_IRWXU) == 0)
    return 0;
  return -1;
}

/* Write buffer atomically with 0600 permissions */
static int write_file_atomic(const char *path, const char *data)
{
  int fd;
  char tmp[PATH_MAX];
  snprintf(tmp, sizeof(tmp), "%s.tmpXXXXXX", path);
  fd = mkstemp(tmp);
  if (fd < 0)
    return -1;
  ssize_t w = write(fd, data, strlen(data));
  if (w < 0 || (size_t)w != strlen(data))
  {
    close(fd);
    unlink(tmp);
    return -1;
  }
  fsync(fd);
  close(fd);
  if (chmod(tmp, S_IRUSR | S_IWUSR) != 0)
  {
    unlink(tmp);
    return -1;
  }
  if (rename(tmp, path) != 0)
  {
    unlink(tmp);
    return -1;
  }
  return 0;
}

/* Create JSON-like auth.conf in etc_path with Argon2 verification data */
int cmd_init(const char *etc_path, const char *kdf_path)
{
  const size_t salt_len = 16;
  const size_t hash_len = 32; /* Argon2 raw output length */
  unsigned char salt[salt_len];
  unsigned char raw[hash_len];

  uint32_t t_cost = 3;
  uint32_t m_cost = 1 << 16; /* 65536 KiB ~ 64 MiB */
  uint32_t parallelism = 1;

  if (RAND_bytes(salt, salt_len) != 1)
  {
    fprintf(stderr, "RAND_bytes failed\n");
    return 1;
  }

  char *pass = getpass("Enter new passphrase: ");
  if (!pass)
    return 1;

  /* Hash for verification */
  if (argon2id_hash_raw(t_cost, m_cost, parallelism,
                        pass, strlen(pass),
                        salt, salt_len,
                        raw, hash_len) != ARGON2_OK)
  {
    fprintf(stderr, "argon2id_hash_raw failed\n");
    return 1;
  }

  char salt_hex[salt_len * 2 + 1];
  char raw_hex[hash_len * 2 + 1];
  hex_encode(salt, salt_len, salt_hex);
  hex_encode(raw, hash_len, raw_hex);

  /* Prepare etc dir and file path */
  char etc_dir[PATH_MAX];
  strncpy(etc_dir, etc_path, sizeof(etc_dir));
  /* etc_path expected to be something like "$(DESTDIR)/etc/securePass/auth.conf" */
  /* We want to ensure directory exists */
  char *last = strrchr(etc_dir, '/');
  if (!last)
    return 1;
  *last = '\0';
  ensure_dir(etc_dir);

  /* Write auth.conf (very simple JSON-like content) */
  char content[4096];
  snprintf(content, sizeof(content),
           "{\n"
           "  \"argon2\": {\n"
           "    \"time_cost\": %u,\n"
           "    \"memory_cost\": %u,\n"
           "    \"parallelism\": %u,\n"
           "    \"salt_hex\": \"%s\",\n"
           "    \"raw_hash_hex\": \"%s\",\n"
           "    \"hash_len\": %u\n"
           "  }\n"
           "}\n",
           (unsigned)t_cost, (unsigned)m_cost, (unsigned)parallelism,
           salt_hex, raw_hex, (unsigned)hash_len);

  if (write_file_atomic(etc_path, content) != 0)
  {
    perror("write_file_atomic etc");
    return 1;
  }

  /* ------- Now create KDF metadata under kdf_path ------- */
  /* kdf salt separate from verification salt (recommended) */
  unsigned char kdf_salt[salt_len];
  if (RAND_bytes(kdf_salt, salt_len) != 1)
  {
    fprintf(stderr, "RAND_bytes failed (kdf)\n");
    return 1;
  }
  char kdf_salt_hex[salt_len * 2 + 1];
  hex_encode(kdf_salt, salt_len, kdf_salt_hex);

  /* Create kdf dir */
  char kdf_dir[PATH_MAX];
  strncpy(kdf_dir, kdf_path, sizeof(kdf_dir));
  char *lk = strrchr(kdf_dir, '/');
  if (!lk)
    return 1;
  *lk = '\0';
  ensure_dir(kdf_dir);

  /* Use slightly different Argon2 params for KDF if desired */
  uint32_t kdf_t = 2;
  uint32_t kdf_m = 1 << 15; /* 32768 KiB */
  uint32_t kdf_p = 1;
  char kdf_content[512];
  snprintf(kdf_content, sizeof(kdf_content),
           "{\n"
           "  \"kdf\": {\n"
           "    \"time_cost\": %u,\n"
           "    \"memory_cost\": %u,\n"
           "    \"parallelism\": %u,\n"
           "    \"salt_hex\": \"%s\",\n"
           "    \"key_len\": %u\n"
           "  }\n"
           "}\n",
           (unsigned)kdf_t, (unsigned)kdf_m, (unsigned)kdf_p,
           kdf_salt_hex, (unsigned)32);

  if (write_file_atomic(kdf_path, kdf_content) != 0)
  {
    perror("write_file_atomic kdf");
    return 1;
  }

  printf("Initialization complete.\nVerification metadata written to: %s\nKDF metadata written to: %s\n", etc_path, kdf_path);
  return 0;
}

/* Very tiny parser to extract values from the simple files we wrote above.
   Not a full JSON parser; it's adequate for this structured output. */
static int extract_field_hex(const char *content, const char *field, char *out, size_t outlen)
{
  const char *p = strstr(content, field);
  if (!p)
    return -1;
  p = strchr(p, ':');
  if (!p)
    return -1;
  p++;
  while (*p == ' ' || *p == '\"')
    p++;
  size_t i = 0;
  while (*p && *p != '\"' && *p != '\n' && i + 1 < outlen)
  {
    out[i++] = *p++;
  }
  out[i] = '\0';
  return 0;
}
static int extract_field_uint(const char *content, const char *field, unsigned *out)
{
  const char *p = strstr(content, field);
  if (!p)
    return -1;
  p = strchr(p, ':');
  if (!p)
    return -1;
  p++;
  while (*p == ' ')
    p++;
  *out = strtoul(p, NULL, 10);
  return 0;
}

static int read_whole_file(const char *path, char **buf_out)
{
  FILE *f = fopen(path, "rb");
  if (!f)
    return -1;
  fseek(f, 0, SEEK_END);
  long sz = ftell(f);
  fseek(f, 0, SEEK_SET);
  char *buf = malloc(sz + 1);
  if (!buf)
  {
    fclose(f);
    return -1;
  }
  if (fread(buf, 1, sz, f) != (size_t)sz)
  {
    free(buf);
    fclose(f);
    return -1;
  }
  buf[sz] = '\0';
  fclose(f);
  *buf_out = buf;
  return 0;
}

int cmd_verify(const char *etc_path, const char *kdf_path)
{
  (void)kdf_path; /* not used here but kept for signature parity */

  char *content = NULL;
  if (read_whole_file(etc_path, &content) != 0)
  {
    fprintf(stderr, "Failed to read %s\n", etc_path);
    return 1;
  }

  char salt_hex[256];
  char raw_hex[1024];
  unsigned time_cost = 0, memory_cost = 0, parallelism = 0;
  unsigned hash_len = 0;

  if (extract_field_hex(content, "salt_hex", salt_hex, sizeof(salt_hex)) != 0 ||
      extract_field_hex(content, "raw_hash_hex", raw_hex, sizeof(raw_hex)) != 0 ||
      extract_field_uint(content, "time_cost", &time_cost) != 0 ||
      extract_field_uint(content, "memory_cost", &memory_cost) != 0 ||
      extract_field_uint(content, "parallelism", &parallelism) != 0 ||
      extract_field_uint(content, "hash_len", &hash_len) != 0)
  {
    fprintf(stderr, "Failed to parse %s\n", etc_path);
    free(content);
    return 1;
  }

  size_t salt_len = strlen(salt_hex) / 2;
  size_t raw_len = strlen(raw_hex) / 2;
  unsigned char *salt = malloc(salt_len);
  unsigned char *stored_raw = malloc(raw_len);
  if (!salt || !stored_raw)
  {
    free(content);
    return 1;
  }
  if (hex_decode(salt_hex, salt, salt_len) != 0 ||
      hex_decode(raw_hex, stored_raw, raw_len) != 0)
  {
    fprintf(stderr, "hex decode failed\n");
    free(content);
    free(salt);
    free(stored_raw);
    return 1;
  }

  char *pass = getpass("Enter passphrase to verify: ");
  if (!pass)
  {
    free(content);
    free(salt);
    free(stored_raw);
    return 1;
  }

  unsigned char raw[raw_len];
  if (argon2id_hash_raw((uint32_t)time_cost, (uint32_t)memory_cost, (uint32_t)parallelism,
                        pass, strlen(pass),
                        salt, salt_len,
                        raw, raw_len) != ARGON2_OK)
  {
    fprintf(stderr, "argon2id_hash_raw failed\n");
    free(content);
    free(salt);
    free(stored_raw);
    return 1;
  }

  int ok = const_time_cmp(raw, stored_raw, raw_len);
  if (ok)
  {
    printf("Passphrase OK ✅\n");
  }
  else
  {
    printf("Passphrase INCORRECT ❌\n");
  }

  free(content);
  free(salt);
  free(stored_raw);
  return ok ? 0 : 2;
}

int cmd_derive_key(const char *kdf_path)
{
  char *content = NULL;
  if (read_whole_file(kdf_path, &content) != 0)
  {
    fprintf(stderr, "Failed to read %s\n", kdf_path);
    return 1;
  }
  char salt_hex[256];
  unsigned t = 0, m = 0, p = 0, key_len = 0;
  if (extract_field_hex(content, "salt_hex", salt_hex, sizeof(salt_hex)) != 0 ||
      extract_field_uint(content, "time_cost", &t) != 0 ||
      extract_field_uint(content, "memory_cost", &m) != 0 ||
      extract_field_uint(content, "parallelism", &p) != 0 ||
      extract_field_uint(content, "key_len", &key_len) != 0)
  {
    fprintf(stderr, "Failed to parse %s\n", kdf_path);
    free(content);
    return 1;
  }

  size_t salt_len = strlen(salt_hex) / 2;
  unsigned char *salt = malloc(salt_len);
  if (!salt)
  {
    free(content);
    return 1;
  }
  if (hex_decode(salt_hex, salt, salt_len) != 0)
  {
    fprintf(stderr, "hex decode failed\n");
    free(content);
    free(salt);
    return 1;
  }

  char *pass = getpass("Enter passphrase to derive key: ");
  if (!pass)
  {
    free(content);
    free(salt);
    return 1;
  }

  unsigned char key[key_len];
  if (argon2id_hash_raw((uint32_t)t, (uint32_t)m, (uint32_t)p,
                        pass, strlen(pass),
                        salt, salt_len,
                        key, key_len) != ARGON2_OK)
  {
    fprintf(stderr, "argon2id_hash_raw (kdf) failed\n");
    free(content);
    free(salt);
    return 1;
  }

  /* Output key in hex for demo — don't do this in production. */
  char key_hex[key_len * 2 + 1];
  hex_encode(key, key_len, key_hex);
  printf("Derived AES-256 key (hex): %s\n", key_hex);

  /* zero sensitive buffers */
  OPENSSL_cleanse(key, key_len);
  OPENSSL_cleanse(pass, strlen(pass));

  free(content);
  free(salt);
  return 0;
}