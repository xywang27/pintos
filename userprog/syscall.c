#include "userprog/syscall.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "devices/block.h"
#include "filesys/directory.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/inode.h"
#include "filesys/cache.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"



/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful,
   -1 if a segfault occurred. */
static int
get_user (const uint8_t *uaddr)
{
  if (!is_user_vaddr (uaddr))
    return -1;
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));
  return result;
}

static inline bool
put_user (uint8_t *udst, uint8_t byte)
{
  int eax;
  asm ("movl $1f, %%eax; movb %b2, %0; 1:"
       : "=m" (*udst), "=&a" (eax) : "q" (byte));
  return eax != 0;
}

static bool
check_ptr (void * esp, uint8_t size)
{
  // check the highest pointer address is enough
  if (get_user (((uint8_t *)esp)+size-1) == -1)
      return false;
  return true;
}

static bool
check_str (void * str)
{
  char character;
  character = get_user(((uint8_t*)str));
  // if exceed the boundry, return -1
  while (character != '\0' && character!=-1) {
    str++;
    character = get_user(((uint8_t*)str));
  }
  // valid string ends with '\0'
  if ( character == '\0' ){
    return true;
  }
  return false;
}

static void
syscall_handler (struct intr_frame *f)
{
  // first check is esp is in boundary
  if ( !check_ptr (f->esp, 4) ) {
    thread_exit();
    return;
  }
  is_valid_addr (&mc, f->esp, 4);
  // get syscall_num and check if it's valid
  int syscall_num = *((int *)f->esp);
  if ( syscall_num < 0 || syscall_num >= 20 ) {
    thread_exit();
    return;
  }

  switch(syscall_num)
  {
    case SYS_HALT:
    {
      shutdown_power_off();
      return;
    }

    case SYS_EXIT:
    {
      int status;
      // check if arg is in boundary
      if (check_ptr(f->esp + 4, 4)){
        // extract status
        status = *((int*)(f->esp+4));
        thread_current ()->wait_status->status = status;
        thread_exit ();
      }else{
        thread_exit ();
      }
      return;
    }

    case SYS_EXEC:
    {
      if (!check_ptr (f->esp + 4, 4))
      {
        thread_exit ();
        return;
      }
      is_valid_addr (&mc,(uint32_t*)f->esp+1,4);
      
      char *str =is_valid_str(*(char**)(f->esp+4));

      f->eax = process_execute (str);
      return;
    }

    case SYS_WAIT:
    {
      int pid;
      if (check_ptr (f->esp + 4, 4))
      {
        pid = *((int*)f->esp+1);
      } else {
        thread_exit ();
        return;
      }

      f->eax = process_wait(pid);
      return;
    }

    case SYS_CREATE:
    {
      if (!check_ptr (f->esp +4, 4) ||
          !check_str (*(char **)(f->esp + 4)) || !check_ptr (f->esp +8, 4))
      {
        thread_exit ();
        return;
      }
      char *str = is_valid_str(*(char**)(f->esp+4));
      unsigned size = *(int *)(f->esp + 8);
      f->eax = filesys_create (str, size);
      palloc_free_page (str);

      return;
    }

    case SYS_REMOVE:
    { 
      if (!check_ptr (f->esp +4, 4) ||
          !check_str (*(char **)(f->esp + 4)))
      {
        thread_exit();
        return;
      }

      char *str = is_valid_str(*(char**)(f->esp+4));
      f->eax = filesys_remove (str);
      palloc_free_page (str);
      return;
    }

    case SYS_OPEN:
    {
      if (!check_ptr (f->esp +4, 4) ||
          !check_str (*(char **)(f->esp + 4)))
      {
        thread_exit();
        return;
      }

      int retval = -1;
      char *str = is_valid_str(*(char**)(f->esp+4));
      struct fd_entry *fd_entry = malloc(sizeof(struct fd_entry));
      if (fd_entry == NULL) {
        f->eax = -1;
        return;
      }
      if (!is_valid_dir(str)) {
        fd_entry->dir = NULL;
        fd_entry->file = filesys_open(str);
        fd_entry->is_dir = false;

        if (fd_entry->file != NULL) {
          fd_entry->fd = thread_current()->next_fd;
          thread_current()->next_fd++;
          list_push_front(&thread_current()->fd_entry_list, &fd_entry->elem);
          retval = fd_entry->fd;
        }

      } else {
        fd_entry->dir = dir_open_path(str);
        fd_entry->file = NULL;
        fd_entry->is_dir = true;

        if (fd_entry->dir != NULL) {
          fd_entry->fd = thread_current()->next_fd;
          thread_current()->next_fd++;
          list_push_front(&thread_current()->fd_entry_list, &fd_entry->elem);
          retval = fd_entry->fd;
        }
      }
      palloc_free_page (str);
      f->eax = retval;
      return;
    }

    case SYS_FILESIZE:
    {
      if (!check_ptr (f->esp +4, 4))
      {
        thread_exit();
        return;
      }

      int fd = *(int *)(f->esp + 4);

      struct fd_entry *fd_entry = get_fd_entry(fd);
      if (fd_entry) {
        f->eax = file_length(fd_entry->file);
      } else {
        f->eax = -1;
      }

      return;
    }

    case SYS_READ:
    {
      if ( !check_ptr (f->esp + 4, 12) )
      {
        thread_exit();
        return;
      }

      int fd = *(int *)(f->esp + 4);
      void *buffer = *(char**)(f->esp + 8);
      unsigned size = *(unsigned *)(f->esp + 12);
      if ( !check_ptr (buffer, 1) || !check_ptr (buffer + size, 1) )
      {
        thread_exit();
        return;
      }

      struct fd_entry *fd_entry = get_fd_entry (fd);
      if (fd_entry == NULL || fd_entry->dir) {
        f->eax = -1;
        return;
      }

      size_t tmp_size = size;
      void *tmp_buffer = buffer;
      int retval = 0;
      while (tmp_size > 0)
      {
        size_t read_bytes;
        if (tmp_size < PGSIZE - pg_ofs (tmp_buffer)) {
          read_bytes = tmp_size;
        } else {
          read_bytes = PGSIZE - pg_ofs (tmp_buffer);
        }
        
        off_t bytes_read = file_read (fd_entry->file, tmp_buffer, read_bytes);
        retval += bytes_read;

        tmp_size -= bytes_read;
        tmp_buffer += bytes_read;
        
      }

      f->eax = retval;
      return;
    }

    case SYS_WRITE:
    {
      if ( !check_ptr (f->esp + 4, 12) ){
        thread_exit ();
        return;
      }

      int fd = *(int *)(f->esp + 4);
      void *buffer = *(char**)(f->esp + 8);
      unsigned size = *(unsigned *)(f->esp + 12);
      if ( !check_ptr (buffer, 1) || !check_ptr (buffer + size, 1) ) {
        thread_exit ();
        return;
      }

      if (fd == STDOUT) {
        putbuf((char *)buffer, (size_t)size);
        f->eax = size;
        return;
      }

      size_t tmp_size = size;
      void *tmp_buffer = buffer;
      int retval = 0;

      struct fd_entry *fd_entry =fd_entry = get_fd_entry (fd);
      if (fd_entry==NULL || fd_entry->dir) {
        f->eax = -1;
        return;
      }

      while (tmp_size > 0)
      {
        size_t write_bytes;
        if (tmp_size < PGSIZE - pg_ofs (tmp_buffer)) {
          write_bytes = tmp_size;
        } else {
          write_bytes = PGSIZE - pg_ofs (tmp_buffer);
        }

        if (!(tmp_buffer < PHYS_BASE && pagedir_get_page (thread_current ()->pagedir, tmp_buffer) != NULL))
        {
          thread_exit ();
        }

        off_t bytes_written = file_write (fd_entry->file, tmp_buffer, write_bytes);
        if (retval < 0 || (bytes_written != (off_t) write_bytes)){
          f->eax = retval;
          return;
        }
        retval += bytes_written;

        tmp_buffer += bytes_written;
        tmp_size -= bytes_written;
      }

      f->eax = retval;
      return;
    }

    case SYS_SEEK:
    {
      if (!check_ptr (f->esp +4, 8))
      {
        thread_exit();
        return;
      }

      int fd = *(int *)(f->esp + 4);
      unsigned position = *(unsigned *)(f->esp + 8);

      struct fd_entry *fd_entry = get_fd_entry(fd);
      if (fd_entry) {
        file_seek (fd_entry->file, position);
      }
      return;
    }

    case SYS_TELL:
    {
      
      if (!check_ptr (f->esp +4, 4))
      {
        thread_exit();
        return;
      }

      int fd = *(int *)(f->esp + 4);
      struct fd_entry *fd_entry = get_fd_entry (fd);

      f->eax = file_tell (fd_entry->file);

      return;
    }

    case SYS_CLOSE:
    {
      if (!check_ptr (f->esp +4, 4))
      {
        thread_exit();
        return;
      }

      int fd = *(int *)(f->esp + 4);

      struct fd_entry *fd_entry = get_fd_entry (fd);
      file_close (fd_entry->file);
      list_remove (&fd_entry->elem);
      free (fd_entry);

      return;
    }


    case SYS_CHDIR:
    {
      if (!check_ptr (f->esp +4, 4))
      {
        thread_exit();
        return;
      }

      char *dir = *(int *)(f->esp + 4);
      struct dir *directory = get_parent_directory (dir);
      if (!directory) {
        f->eax = false;
        return;
      }
      char *dir_name = malloc (NAME_MAX + 1);
      char *temp;
      temp = extract_next_part (&dir);
      while (temp != NULL) {
        strlcpy (dir_name, temp, strlen (temp) + 1);
        free(temp);
        temp = extract_next_part (&dir);
      }
      struct inode *inode;
      dir_lookup (directory, dir_name, &inode);
      if (inode)
      {
        dir_close (thread_current ()->cwd);
        thread_current ()->cwd = dir_open (inode);
        free (dir_name);
        f->eax = true;
        return;
      }
      dir_close (directory);
      free (dir_name);
      f->eax = false;
      return;
    }

    case SYS_MKDIR:
    {
      if (!check_ptr (f->esp +4, 4))
      {
        thread_exit();
        return;
      }

      char *dir = *(int *)(f->esp + 4);
      struct dir *directory = get_parent_directory (dir);
      if (!directory) {
        f->eax = false;
        return;
      }
      char *dir_name = malloc (NAME_MAX + 1);
      char *temp;
      temp = extract_next_part (&dir);
      while (temp != NULL) {
        strlcpy (dir_name, temp, strlen (temp) + 1);
        free(temp);
        temp = extract_next_part (&dir);
      }
      block_sector_t new_file_sector;
      if (!free_map_allocate (1, &new_file_sector) || !dir_add (directory, dir_name, new_file_sector, true))
      {
        dir_close (directory);
        free (dir_name);
        f->eax = false;
        return;
      } else {
        dir_close (directory);
        free (dir_name);
        f->eax = true;
        return;
      }
    }

    case SYS_READDIR:
    {
      if (!check_ptr (f->esp +4, 8))
      {
        thread_exit();
        return;
      }
      int fd = *(int *)(f->esp + 4);
      char *name = *(char **)(f->esp + 8);
      struct fd_entry *fd_entry = get_fd_entry (fd);
      if (fd_entry->file) {
        f->eax = false;
        return;
      }
      f->eax = dir_readdir (fd_entry->dir, name);
      return;
    }

    case SYS_ISDIR:
    {
      if (!check_ptr (f->esp +4, 4))
      {
        thread_exit();
        return;
      }

      int fd = *(int *)(f->esp + 4);
      struct thread *curr = thread_current ();
      struct list_elem *e = list_begin (&curr->fd_entry_list);
      while (e != list_end (&curr->fd_entry_list))
      {
        struct fd_entry *fd_entry = list_entry (e, struct fd_entry, elem);
        if (fd_entry->fd == fd) {
          f->eax = fd_entry->is_dir;
          return;
        }
        e = list_next(e);
      }
      f->eax = false;
      return;
    }

    case SYS_INUMBER:
    {
      if (!check_ptr (f->esp +4, 4))
      {
        thread_exit();
        return;
      }

      int fd = *(int *)(f->esp + 4);
      int inumber = -1;
      struct thread *curr = thread_current ();
      struct list_elem *e = list_begin (&curr->fd_entry_list);
      while (e != list_end (&curr->fd_entry_list))
      {
        struct fd_entry *fd_entry = list_entry (e, struct fd_entry, elem);
        if (fd_entry->fd == fd) {
          if (fd_entry->is_dir) {
            inumber = inode_get_inumber (fd_entry->dir->inode);
          } else {
            inumber = inode_get_inumber (fd_entry->file->inode);
          }
          f->eax = inumber;
          return;
        }

        e = list_next (e);
      }
      f->eax = inumber;
      return;
    }


  }
}


void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}



