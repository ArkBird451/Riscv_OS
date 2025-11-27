#pragma once
#include "common.h"

__attribute__((noreturn)) void exit(void);
void putchar(char ch);
int syscall(int sysno, int arg0, int arg1, int arg2);

// File system system calls
void readfile(const char *filename, char *buf, int size);
void listdir(void);