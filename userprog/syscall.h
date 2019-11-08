#include "threads/synch.h"
#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

typedef int pid_t;
#define MAX 128
#define BUFFER_SIZE 200
void is_valid_string (const char *string);
void is_valid_pointer (void *pointer);

void syscall_init (void);

#endif /* userprog/syscall.h */
