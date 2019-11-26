#include "threads/synch.h"
#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#define MAX 128

void is_valid_string (const char *str);
void is_valid_ptr (void *pointer);

void syscall_init (void);

struct lock file_lock;                      /*lock that systemcall has to protect file reading and writing*/


#endif /* userprog/syscall.h */
