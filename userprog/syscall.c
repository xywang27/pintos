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
syscall_handler (struct intr_frame *f UNUSED)
{
  if ( !check_ptr (f->esp, 4) ) {
    thread_exit();
    return;
  }
  /*is_valid_addr (&mc, f->esp, 4);*/
  // get syscall_num and check if it's valid
  int syscall_num = *((int *)f->esp);
  if ( syscall_num < 0 || syscall_num >= 20 ) {
    thread_exit();
    return;
  }

  switch(syscall_num){
    case SYS_HALT:
    {
      shutdown_power_off();
      return;
    }

    /*case SYS_WRITE:
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

      if (fd == 1) {
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
    }*/
  }
}


void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}
