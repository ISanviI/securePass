#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "auth.h"
#include "storage.h"

/* Default paths; these will be overwritten by the compiled constants or you may pass alt paths */
#ifndef ETC_AUTH_PATH
#define ETC_AUTH_PATH AUTH_ETC_PATH
#endif
#ifndef KDF_META_PATH
#define KDF_META_PATH KDF_VAR_PATH
#endif

static void usage(const char *prog)
{
  printf("Usage: %s <command>\n", prog);
  printf("Commands:\n");
  printf("  init           Create verification and KDF metadata (first-time setup)\n");
  printf("  verify         Verify passphrase against stored argon2 hash\n");
  printf("  derive-key     Derive AES-256 key from passphrase and stored KDF params (prints hex)\n");
  printf("\nPaths (compiled values):\n  etc: %s\n  kdf: %s\n", ETC_AUTH_PATH, KDF_META_PATH);
}

// The shell gives the values for argc and argv... Interesting!!
int main(int argc, char *argv[])
{
  if (argc < 2)
  {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  securePass add <name> <password>\n");
    fprintf(stderr, "  securePass display all\n");
    fprintf(stderr, "  securePass display <name>\n");
    return 1;
  }

  if (!authenticate())
  {
    fprintf(stderr, "Authentication failed.\n");
    return 1;
  }

  const char *cmd = argv[1];

  if (strcmp(cmd, "init") == 0)
  {
    return cmd_init(ETC_AUTH_PATH, KDF_META_PATH);
  }
  else if (strcmp(cmd, "verify") == 0)
  {
    return cmd_verify(ETC_AUTH_PATH, KDF_META_PATH);
  }
  else if (strcmp(cmd, "derive-key") == 0)
  {
    return cmd_derive_key(KDF_META_PATH);
  }
  else
  {
    usage(argv[0]);
    return 1;
  }
  return 0;

  if (strcmp(argv[1], "add") == 0)
  {
    if (argc != 4)
    {
      fprintf(stderr, "Usage: securePass add <name> <password>\n");
      return 1;
    }
    save_password(argv[2], argv[3]);
  }
  else if (strcmp(argv[1], "display") == 0)
  {
    if (argc == 3 && strcmp(argv[2], "all") == 0)
    {
      display_all();
    }
    else if (argc == 3)
    {
      display_password(argv[2]);
    }
    else
    {
      fprintf(stderr, "Usage: securePass display <name>|all\n");
      return 1;
    }
  }
  else
  {
    fprintf(stderr, "Unknown command: %s\n", argv[1]);
    return 1;
  }

  return 0;
}
