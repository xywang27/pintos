#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "filesys/directory.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/inode.h"
#include "filesys/cache.h"

/* File descriptor entry */
struct fd_entry
{
  // fd is the only id for a file
  int fd;
  // the file name
  struct file *file; 
  // to store in list
  struct list_elem elem;    
  bool is_dir;     
  struct dir *dir;             
};

static struct fd_entry *
get_fd_entry (int fd)
{
  struct fd_entry *fd_entry = NULL;
  // traverse the running thread's all fd_entry list
  struct list *fd_list = &thread_current()->fd_entry_list;
  struct list_elem *e = list_begin (fd_list);

  while (e != list_end (fd_list))
    {
      struct fd_entry *tmp = list_entry (e, struct fd_entry, elem);
      // found the fd_entry with given fd
      if (tmp->fd == fd) {
        fd_entry = tmp;
        return fd_entry;
      }
      e = list_next (e);
    }

  thread_exit ();
}


tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

#endif /* userprog/process.h */
