#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/synch.h"

void syscall_init (void);

struct lock file_lock;                      /*lock that systemcall has to protect file reading and writing*/

#endif /* userprog/syscall.h */
