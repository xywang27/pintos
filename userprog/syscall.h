#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "filesys/directory.h"

#define STDOUT 1

struct dir;
int mc;
void syscall_init (void);
#endif /* userprog/syscall.h */
