// src/storage.c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "storage.h"

#define DB_FILE "securepass.db"

void save_password(const char *name, const char *password)
{
  FILE *file = fopen(DB_FILE, "a");
  if (!file)
  {
    perror("fopen");
    return;
  }
  fprintf(file, "%s:%s\n", name, password);
  fclose(file);
}

void display_all()
{
  FILE *file = fopen(DB_FILE, "r");
  if (!file)
  {
    perror("fopen");
    return;
  }
  char line[512];
  while (fgets(line, sizeof(line), file))
    printf("%s", line);
  fclose(file);
}

void display_password(const char *name)
{
  FILE *file = fopen(DB_FILE, "r");
  if (!file)
  {
    perror("fopen");
    return;
  }

  char line[512];
  while (fgets(line, sizeof(line), file))
  {
    char *sep = strchr(line, ':');
    if (sep)
    {
      *sep = '\0';
      if (strcmp(line, name) == 0)
      {
        printf("%s\n", sep + 1);
        fclose(file);
        return;
      }
    }
  }

  printf("No entry found for %s\n", name);
  fclose(file);
}