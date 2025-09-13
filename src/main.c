#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> // For getpass
#include <openssl/crypto.h> // For OPENSSL_cleanse
#include "auth.h"
#include "crypto.h"
#include "storage.h"

/* Default paths; these will be overwritten by the compiled constants or you may pass alt paths */
#ifndef AUTH_ETC_PATH
#define AUTH_ETC_PATH "/etc/securePass/auth.conf"
#endif

static void usage(const char *prog)
{
  printf("Usage: %s <command> [arguments]\n", prog);
  printf("Commands:\n");
  printf("  init                      Initializes the master passphrase verification data.\n");
  printf("  verify                    Verifies the master passphrase.\n");
  printf("  add <name>                Adds a new password entry interactively.\n");
  printf("  display <name>|all        Displays a specific password or lists all entry names.\n");
  // printf("\nPaths (compiled values):\n  auth.conf: %s\n", AUTH_ETC_PATH);
}

int main(int argc, char *argv[])
{
  if (argc < 2)
  {
    usage(argv[0]);
    return 1;
  }

  fprintf(stderr, "[MAIN_LOG] Calling authenticate()...\n");
  int auth_result = authenticate();
  fprintf(stderr, "[MAIN_LOG] authenticate() returned: %d\n", auth_result);
  if (!auth_result)
  {
    fprintf(stderr, "[MAIN_LOG] Authentication failed. Exiting.\n");
    return 1;
  }

  const char *cmd = argv[1];

  if (strcmp(cmd, "init") == 0)
  {
    return cmd_init(AUTH_ETC_PATH);
  }
  else if (strcmp(cmd, "verify") == 0)
  {
    return cmd_verify(AUTH_ETC_PATH);
  }
  else if (strcmp(cmd, "add") == 0)
  {
    if (argc != 3)
    {
      fprintf(stderr, "Usage: %s add <name>\n", argv[0]);
      return 1;
    }
    char *master_pass = getpass("Enter master passphrase: ");
    if (!master_pass) {
        fprintf(stderr, "Failed to read master passphrase.\n");
        return 1;
    }
    char *new_password = getpass("Enter password for new entry: ");
    if (!new_password) {
        fprintf(stderr, "Failed to read new password.\n");
        OPENSSL_cleanse(master_pass, strlen(master_pass));
        return 1;
    }
    save_password(argv[2], new_password, master_pass);
    // The OPENSSL_cleanse function is used to securely erase sensitive data from memory.
    OPENSSL_cleanse(master_pass, strlen(master_pass));
    OPENSSL_cleanse(new_password, strlen(new_password));
    printf("Entry '%s' added.\n", argv[2]);
  }
  else if (strcmp(cmd, "display") == 0)
  {
    if (argc != 3)
    {
      fprintf(stderr, "Usage: %s display <name>|all\n", argv[0]);
      return 1;
    }
    if (strcmp(argv[2], "all") == 0)
    {
      display_all();
    }
    else
    {
      char *master_pass = getpass("Enter master passphrase: ");
      if (!master_pass) {
        fprintf(stderr, "Failed to read passphrase.\n");
        return 1;
      }
      display_password(argv[2], master_pass);
      OPENSSL_cleanse(master_pass, strlen(master_pass));
    }
  }
  else
  {
    fprintf(stderr, "Unknown command: %s\n", cmd);
    usage(argv[0]);
    return 1;
  }

  return 0;
}