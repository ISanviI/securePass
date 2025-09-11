// src/storage.h
#ifndef STORAGE_H
#define STORAGE_H

void save_password(const char *name, const char *password, const char *master_pass);
void display_all();
void display_password(const char *name, const char *master_pass);

#endif