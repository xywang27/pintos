#include <stdio.h>
#include <syscall-nr.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "userprog/syscall.h"

static void syscall_handler (struct intr_frame *);

static int open (const char *);
static int filesize (int);
static int read (int fd, void *buffer, unsigned size);
static int write (int fd, const void *buffer, unsigned size);
static void seek (int fd, unsigned position);
static unsigned tell (int fd);
static void close (int fd);
static bool is_valid_fd (int fd);

/* Check whether the string is valid. */
void
is_valid_string (const char *string)
{
  /* Check one bit at a time. */
  is_valid_pointer (string);
  is_valid_pointer (string + 1);
  /* Check until the end of a string. */
  while (*string != '\0')
  {
    string = string + 1;
    is_valid_pointer (string + 1);
    is_valid_pointer (string + 2);
  }
}

/* Check whether the pointer is valid. */
void
is_valid_pointer (void *pointer)
{
  /* Check for nullpointer. */
  if (pointer == NULL)
  {
    thread_current ()->exit_code = -1 ;
    thread_exit ();
  }
  /* Check whether it is on a valid user virtual address. */
  if (is_user_vaddr (pointer) == false)
  {
    thread_current ()->exit_code = -1 ;
    thread_exit ();
  }
  /* Check whether the pointer is on the valid page. */
  if (pagedir_get_page (thread_current ()->pagedir, pointer) == NULL)
  {
    thread_current ()->exit_code = -1 ;
    thread_exit ();
  }
}

static int
open (const char *file_name)
{
  struct thread *t = thread_current ();
  struct file *f = filesys_open (file_name);
  if (f == NULL)
    return -1;
  /* Start from 2 , to find next free fd to allocate. */
  int i;
  for (i = 2; i < MAX; i = i + 1)
  {
    if (t->file[i] == NULL)
    {
      t->file[i] = f;
      break;
    }
  }
  /* No fd to allocate. */
  if (i == MAX)
    i = -1;
  return i;
}

static int
filesize (int fd)
{
  int file_size = 0;
  struct thread *t = thread_current ();
  if (is_valid_fd (fd) && t->file[fd] != NULL)
  {
    file_size = file_length (t->file[fd]);
  }
  return file_size;
}


static int
read (int fd, void *buffer, unsigned size)
{
  int bytes_read = 0;
  char *bufferChar = NULL;
  bufferChar = (char *) buffer;
  struct thread *t = thread_current ();
  /* standard input. */
  if (fd == 0)
  {
    for (; size > 0; size = size - 1)
    {
      input_getc ();
      bytes_read = bytes_read + 1;
    }
  }
  /* else */
  else
  {
    if (is_valid_fd (fd) && t->file[fd] != NULL)
      bytes_read = file_read (t->file[fd], buffer, size);
  }
  return bytes_read;
}

static int
write (int fd, const void *buffer, unsigned size)
{
  int buffer_write = 0;
  char *buffChar = NULL;
  buffChar = (char *) buffer;
  struct thread *t = thread_current ();
  /* standard output. */
  if (fd == 1)
  {
    /* avoid boom. */
    while (size > BUFFER_SIZE)
    {
      putbuf (buffChar, BUFFER_SIZE);
      size = size - BUFFER_SIZE;
      buffChar = buffChar + BUFFER_SIZE;
      buffer_write = buffer_write + BUFFER_SIZE;
    }
    putbuf (buffChar, size);
    buffer_write = buffer_write + size;
  }
  /* else */
  else
  {
    if (is_valid_fd (fd) && t->file[fd] != NULL)
      buffer_write = file_write (t->file[fd], buffer, size);
    else
      buffer_write = 0;
  }
  return buffer_write;
}


static void
seek (int fd, unsigned position)
{
  struct thread *t = thread_current ();
  if (is_valid_fd (fd) && t->file[fd] != NULL)
  {
    file_seek (t->file[fd], position);
  }
}

static unsigned
tell (int fd)
{
  unsigned return_value;
  struct thread *t = thread_current ();
  if (is_valid_fd (fd) && t->file[fd] != NULL)
  {
    return_value = file_tell (t->file[fd]);

  }
  else
    return_value = -1;

  return return_value;
}

static void
close (int fd)
{
  struct thread *t = thread_current ();
  if (is_valid_fd (fd) && t->file[fd] != NULL)
  {
    file_close (t->file[fd]);
    t->file[fd] = NULL;
  }
}

/* Check the validality of the fd number. */
static bool
is_valid_fd (int fd)
{
  if (fd >= 0 && fd < MAX)
  {
    return true;
  }
  return false;
}

void
syscall_init (void)
{
  /* Register and initialize the system call handler. */
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED)
{
  void *esp = f->esp;
  int syscall_num;
  is_valid_pointer (esp);
  is_valid_pointer (esp + 4);
  /* Get the name of syscall. */
  syscall_num = *((int *) esp);
  /* Point to the first argument. */
  esp = esp + 4;
  switch(syscall_num) {
    /* Terminates Pintos by calling shutdown_power_off(). */
    case SYS_HALT:
    {
      shutdown_power_off();
      break;
    }
    /* Terminates the current user program, returning status to the kernel. */
    case SYS_EXIT:
    {
      /* Check for validality of the first argument. */
      is_valid_pointer (esp);
      /* Make sure that the whole argument is on valid address. */
      is_valid_pointer (esp + 3);
      int status = *((int *) esp);
      thread_current ()->exit_code = status;
      thread_exit ();
      break;
    }
    /* Runs the executable whose name is given in cmd_line, passing any given
    arguments, and returns the new process's program id (pid). */
    case SYS_EXEC:
    {
      /* Check for validality of the first argument. */
      is_valid_pointer (esp);
      /* Make sure that the whole argument is on valid address. */
      is_valid_pointer (esp + 3);
      const char *file_name = *((char **) esp);
      /* Check for validality of the file_name. */
      is_valid_string (file_name);
      f->eax = process_execute (file_name);
      break;
    }
    /* Waits for a child process pid and retrieves the child's exit status. */
    case SYS_WAIT:
    {
      /* Check for validality of the first argument. */
      is_valid_pointer (esp);
      /* Make sure that the whole argument is on valid address. */
      is_valid_pointer (esp + 3);
      int pid = *((int *) esp);
      f->eax = process_wait (pid);
      break;
    }
    /* Creates a new file called file initially initial_size bytes in size. */
    case SYS_CREATE:
    {
      /* Check for validality of the first argument. */
      is_valid_pointer (esp);
      /* Check for validality of the second argument. */
      is_valid_pointer (esp + 4);
      /* Make sure that the whole argument is on valid address. */
      is_valid_pointer (esp + 7);
      const char *file_name = *((char **) esp);
      /* Check for validality of the file_name. */
      is_valid_string (file_name);
      unsigned size = *((unsigned *) (esp + 4));
      f->eax = filesys_create (file_name, size);
      break;
    }
    /* Deletes the file called file. Returns true if successful, false otherwise. */
    case SYS_REMOVE:
    {
      /* Check for validality of the first argument. */
      is_valid_pointer (esp);
      /* Make sure that the whole argument is on valid address. */
      is_valid_pointer (esp + 3);
      const char *file_name = *((char **) esp);
      /* Check for validality of the file_name. */
      is_valid_string (file_name);
      f->eax = filesys_remove (file_name);
      break;
    }
    /* Opens the file called file. Returns a nonnegative integer handle called
    a "file descriptor" (fd), or -1 if the file could not be opened. */
    case SYS_OPEN:
    {
      /* Check for validality of the first argument. */
      is_valid_pointer (esp);
      /* Make sure that the whole argument is on valid address. */
      is_valid_pointer (esp + 3);
      const char *file_name = *((char **) esp);
      /* Check for validality of the file_name. */
      is_valid_string (file_name);
      f->eax = open (file_name);
      break;
    }
    /* Returns the size, in bytes, of the file open as fd. */
    case SYS_FILESIZE:
    {
      /* Check for validality of the first argument. */
      is_valid_pointer (esp);
      /* Make sure that the whole argument is on valid address. */
      is_valid_pointer (esp + 3);
      int fd = *((int *) esp);
      f->eax = filesize (fd);
      break;
    }
    /* Reads size bytes from the file open as fd into buffer. Returns the number
    of bytes actually read, or -1 if the file could not be read. */
    case SYS_READ:
    {
      /* Check for validality of the first argument. */
      is_valid_pointer (esp);
      /* Check for validality of the second argument. */
      is_valid_pointer (esp + 4);
      /* Check for validality of the third argument. */
      is_valid_pointer (esp + 8);
      /* Make sure that the whole argument is on valid address. */
      is_valid_pointer (esp + 11);
      int fd = *((int *) esp);
      const void *buffer = *((void **) (esp + 4));
      unsigned size = *((unsigned *) (esp + 8));
      /* Check that the given buffer is all valid. */
      is_valid_pointer (buffer);
      is_valid_pointer (buffer + size);
      f->eax= read (fd, buffer, size);
      break;
    }
    /* Writes size bytes from buffer to the open file fd. Returns the number of bytes
    actually written, which may be less than size if some bytes could not be written. */
    case SYS_WRITE:
    {
      /* Check for validality of the first argument. */
      is_valid_pointer (esp);
      /* Check for validality of the second argument. */
      is_valid_pointer (esp + 4);
      /* Check for validality of the third argument. */
      is_valid_pointer (esp + 8);
      /* Make sure that the whole argument is on valid address. */
      is_valid_pointer (esp + 11);
      int fd = *((int *) esp);
      const void *buffer = *((void **) (esp + 4));
      unsigned size = *((unsigned *) (esp + 8));
      /* Check that the given buffer is all valid. */
      is_valid_pointer (buffer);
      is_valid_pointer (buffer + size);
      f->eax = write (fd, buffer, size);
      break;
    }
    /* Changes the next byte to be read or written in open file fd
    to position, expressed in bytes from the beginning of the file */
    case SYS_SEEK:
    {
      /* Check for validality of the first argument. */
      is_valid_pointer (esp);
      /* Check for validality of the first argument. */
      is_valid_pointer (esp + 4);
      /* Make sure that the whole argument is on valid address. */
      is_valid_pointer (esp + 7);
      int fd = *((int *) esp);
      unsigned position = *((unsigned *) (esp + 4));
      seek (fd, position);
      break;
    }
    /* Returns the position of the next byte to be read or written
    in open file fd, expressed in bytes from the beginning of the file. */
    case SYS_TELL:
    {
      /* Check for validality of the first argument. */
      is_valid_pointer (esp);
      /* Make sure that the whole argument is on valid address. */
      is_valid_pointer (esp + 3);
      int fd = *((int *) esp);
      f->eax = tell (fd);
      break;
    }
    /* Closes file descriptor fd. Exiting or terminating a process implicitly closes
    all its open file descriptors, as if by calling this function for each one. */
    case SYS_CLOSE:
    {
      /* Check for validality of the first argument. */
      is_valid_pointer (esp);
      int fd = *((int *) esp);
      close (fd);
      break;
    }
    default:
      break;
  }
}
