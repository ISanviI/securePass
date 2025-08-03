#include <stdio.h>
#include <string.h>
#include "auth.h"
#include "storage.h"

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
