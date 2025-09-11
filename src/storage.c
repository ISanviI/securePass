// src/storage.c
#include <stdio.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include "storage.h"
#include "auth.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h> // For OPENSSL_cleanse

#ifndef DB_FILE
#define DB_FILE "/var/lib/securepass/securepass.db"
#endif

#define AES_IV_LEN 12
#define AES_TAG_LEN 16

// Helper to calculate decoded/encoded size for Base64
static int b64_decoded_size(const char *in) {
    size_t len = strlen(in);
    size_t padding = 0;
    if (len > 1 && in[len - 1] == '=') padding++;
    if (len > 2 && in[len - 2] == '=') padding++;
    return (len * 3) / 4 - padding;
}

/* Ensure dir exists with 0700. Returns 0 on success. */
static int ensure_dir(const char *path)
{
  struct stat st;
  if (stat(path, &st) == 0)
  {
    if (!S_ISDIR(st.st_mode))
      return -1;
    chmod(path, S_IRWXU);
    return 0;
  }
  if (mkdir(path, S_IRWXU) == 0)
    return 0;
  return -1;
}

static int b64_decode(const char *in, unsigned char *out, size_t *outlen) {
    EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new();
    int ret = EVP_DecodeUpdate(ctx, out, (int*)outlen, (const unsigned char*)in, strlen(in));
    EVP_ENCODE_CTX_free(ctx);
    return ret < 0 ? -1 : 0;
}

static char* b64_encode(const unsigned char *in, size_t len) {
    EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new();
    int max_len = (len + 2) / 3 * 4 + 1;
    char *out = malloc(max_len);
    if (!out) return NULL;
    int outlen = 0;
    EVP_EncodeUpdate(ctx, (unsigned char*)out, &outlen, in, len);
    EVP_EncodeFinal(ctx, (unsigned char*)&out[outlen], &outlen);
    EVP_ENCODE_CTX_free(ctx);
    return out;
}


void save_password(const char *name, const char *password, const char *master_pass)
{
    unsigned char salt[KDF_SALT_LEN];
    unsigned char key[KDF_KEY_LEN];
    unsigned char iv[AES_IV_LEN];
    unsigned char tag[AES_TAG_LEN];

    // 1. Generate new random salt and IV
    if (RAND_bytes(salt, sizeof(salt)) != 1 || RAND_bytes(iv, sizeof(iv)) != 1) {
        fprintf(stderr, "Failed to generate salt/iv\n");
        return;
    }

    // 2. Derive key from master passphrase and salt
    if (derive_key(master_pass, salt, key, sizeof(key)) != 0) {
        fprintf(stderr, "Failed to derive key\n");
        return;
    }

    // 3. Encrypt password
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len;
    int ciphertext_len;
    unsigned char *ciphertext = malloc(strlen(password));

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, (const unsigned char*)password, strlen(password));
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag);
    EVP_CIPHER_CTX_free(ctx);

    // 4. Concatenate salt + iv + tag + ciphertext
    size_t total_len = sizeof(salt) + sizeof(iv) + sizeof(tag) + ciphertext_len;
    unsigned char *combined = malloc(total_len);
    memcpy(combined, salt, sizeof(salt));
    memcpy(combined + sizeof(salt), iv, sizeof(iv));
    memcpy(combined + sizeof(salt) + sizeof(iv), tag, sizeof(tag));
    memcpy(combined + sizeof(salt) + sizeof(iv) + sizeof(tag), ciphertext, ciphertext_len);

    // 5. Base64 encode
    char *encoded_data = b64_encode(combined, total_len);

    // 6. Save to file
    char db_dir[4096];
    strncpy(db_dir, DB_FILE, sizeof(db_dir));
    db_dir[sizeof(db_dir) - 1] = '\0';
    char *last = strrchr(db_dir, '/');
    if (last) {
        *last = '\0';
        if (ensure_dir(db_dir) != 0) {
            fprintf(stderr, "Error: Failed to create database directory: %s\n", db_dir);
            perror("ensure_dir");
            OPENSSL_cleanse(key, sizeof(key));
            free(ciphertext);
            return;
        }
    }

    FILE *file = fopen(DB_FILE, "a");
    if (!file) {
        perror("fopen");
        return;
    }
    fprintf(file, "%s:%s\n", name, encoded_data);
    fclose(file);

    free(ciphertext);
    free(combined);
    free(encoded_data);
    OPENSSL_cleanse(key, sizeof(key));
}

void display_all()
{
    FILE *file = fopen(DB_FILE, "r");
    if (!file) {
        perror("fopen");
        return;
    }
    char line[4096];
    printf("Stored password entries:\n");
    while (fgets(line, sizeof(line), file)) {
        char *sep = strchr(line, ':');
        if (sep) {
            *sep = '\0';
            printf("- %s\n", line);
        }
    }
    fclose(file);
}

void display_password(const char *name, const char *master_pass)
{
    FILE *file = fopen(DB_FILE, "r");
    if (!file) {
        perror("fopen");
        return;
    }

    char line[4096];
    int found = 0;
    while (fgets(line, sizeof(line), file)) {
        char *sep = strchr(line, ':');
        if (sep) {
            *sep = '\0';
            if (strcmp(line, name) == 0) {
                found = 1;
                char *encoded_data = sep + 1;
                // Strip newline if present
                encoded_data[strcspn(encoded_data, "\n")] = 0;

                // 1. Base64 decode
                size_t decoded_len = b64_decoded_size(encoded_data);
                unsigned char *decoded = malloc(decoded_len);
                if (b64_decode(encoded_data, decoded, &decoded_len) != 0) {
                    fprintf(stderr, "Base64 decode failed\n");
                    free(decoded);
                    break;
                }

                // 2. Extract components
                unsigned char *salt = decoded;
                unsigned char *iv = decoded + KDF_SALT_LEN;
                unsigned char *tag = decoded + KDF_SALT_LEN + AES_IV_LEN;
                unsigned char *ciphertext = decoded + KDF_SALT_LEN + AES_IV_LEN + AES_TAG_LEN;
                size_t ciphertext_len = decoded_len - KDF_SALT_LEN - AES_IV_LEN - AES_TAG_LEN;

                // 3. Derive key
                unsigned char key[KDF_KEY_LEN];
                if (derive_key(master_pass, salt, key, sizeof(key)) != 0) {
                    fprintf(stderr, "Failed to derive key\n");
                    free(decoded);
                    break;
                }

                // 4. Decrypt
                unsigned char *plaintext = malloc(ciphertext_len + 1);
                EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
                EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
                int len;
                EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
                int plaintext_len = len;
                EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, sizeof(tag), tag);

                if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) > 0) {
                    plaintext_len += len;
                    plaintext[plaintext_len] = '\0';
                    printf("Password for %s: %s\n", name, plaintext);
                } else {
                    printf("Decryption failed. Master passphrase may be incorrect or data is corrupt.\n");
                }

                EVP_CIPHER_CTX_free(ctx);
                free(decoded);
                free(plaintext);
                OPENSSL_cleanse(key, sizeof(key));
                break;
            }
        }
    }

    if (!found) {
        printf("No entry found for %s\n", name);
    }
    fclose(file);
}
