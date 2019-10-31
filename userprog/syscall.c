#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include <string.h>
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
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"

static void syscall_handler (struct intr_frame *);

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

static bool
put_user (uint8_t *udst, uint8_t byte)
{
  if(!is_user_vaddr(udst))
    return false;
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
       : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}

static bool
check_ptr (void * esp, uint8_t size)
{
  if (get_user (((uint8_t *)esp)+size-1) == -1)
      return false;
  return true;
}

static bool
check_str (void * str)
{
  char character;
  character = get_user(((uint8_t*)str));
  while (character != '\0' && character!=-1) {
    str++;
    character = get_user(((uint8_t*)str));
  }
  if ( character == '\0' ){
    return true;
  }
  return false;
}

static void
syscall_handler (struct intr_frame *f)
{
  if ( !check_ptr (f->esp, 4) ) {
    thread_exit();
    return;
  }
  is_valid_addr (&mc, f->esp, 4);
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
      if (check_ptr(f->esp + 4, 4)){
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
  }
}


/*typedef int pid_t;
static int (*syscall_array[20])(struct intr_frame*);

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  syscall_array[SYS_HALT] = &my_halt;
  syscall_array[SYS_EXIT] = &my_exit;
  syscall_array[SYS_EXEC] = &my_exec;
  syscall_array[SYS_WAIT] = &my_wait;
  syscall_array[SYS_CREATE] = &my_create;
  syscall_array[SYS_REMOVE] = &my_remove;
  syscall_array[SYS_OPEN] = &my_open;
  syscall_array[SYS_FILESIZE] = &my_filesize;
  syscall_array[SYS_READ] = &my_read;
  syscall_array[SYS_WRITE] = &my_write;
  syscall_array[SYS_SEEK] = &my_seek;
  syscall_array[SYS_CLOSE] = &my_close;
}

static void
syscall_handler (struct intr_frame *f UNUSED)
{
  /*printf ("system call!\n");
  thread_exit ();
  if(!is_user_vaddr(f->esp)){
    thread_current()->exit_code = -1;
    thread_exit();
  }
  call_number = (int*)f->esp;
  if (call_number < 0){
    thread_current()->exit_code = -1;
    thread_exit();
  }
  if (call_number > 20){
    thread_current()->exit_code = -1;
    thread_exit();
  }
  if (syscall_array[call_number] == NULL){
    thread_current()->exit_code = -1;
    thread_exit();
  }
  syscall_array[call_number](f);
}

void my_halt(struct intr_frame *f){
  shutdown_power_off();
}

void my_exit(struct intr_frame *f){
  if(!is_user_vaddr(((int *)f->esp)+2)){
    thread_current()->exit_code = -1;
    thread_exit();
  }
  thread_current()->exit_code = *((int *)f->esp+1);
  thread_exit();
}

void my_exec(struct intr_frame *f){
  if(!is_user_vaddr(((int *)f->esp)+2)){
    thread_current()->exit_code = -1;
    thread_exit();
  }
  const char *file = (char*)*((int *)f->esp+1);
  tid_t tid = -1;
  if(file == NULL){
    f->eax = -1;
    return;
  }
  char *newfile = (char *)malloc(sizeof(char)*(strlen(file)+1));
  memcpy(newfile,file,strlen(file)+1);
  tid=process_execute (newfile);
  struct thread *t=GetThreadFromid(tid);
  sema_down(&t->SemaWaitSuccess);
  f->eax=t->tid;
  t->father->sons++;  
  free(newfile);
  sema_up(&t->SemaWaitSuccess);
}

void my_wait(struct intr_frame *f){
  if(!is_user_vaddr(((int *)f->esp)+2)){
    thread_current()->exit_code = -1;
    thread_exit();
  }
  tid_t tid = *((int *)f->esp+1)
  if(tid != -1){
    f->eax = process_wait(tid);
  }
  else{
    f->eax = -1;
  }
}

void my_create(struct intr_frame *f){
  if(!is_user_vaddr(((int *)f->esp)+2)){
    thread_current()->exit_code = -1;
    thread_exit();
  }
  if((const char *)*((unsigned int *)f->esp+4)==NULL){
    f->eax = -1;
    thread_current()->exit_code = -1;
    thread_exit();
  }
  bool ret = filesys_create((const char *)*((unsigned int *)f->esp+4),*((unsigned int *)f->esp+5));
  f->eax = ret;
}

void my_remove(struct intr_frame *f){
  if(!is_user_vaddr(((int *)f->esp)+2)){
    thread_current()->exit_code = -1;
    thread_exit();
  }
  char *file = (char *)*((int *)f->esp+1);
  f->eax = filesys_remove(file);
}

void my_open(struct intr_frame *f){
  if(!is_user_vaddr(((int *)f->esp)+2)){
    thread_current()->exit_code = -1;
    thread_exit();
  }
  struct thread *cur = thread_current();
  const char *FileName = (char *)*((int *)f->esp+1);
  if (FileName == NULL){
    f->eax = -1;
    thread_current()->exit_code = -1;
    thread_exit();
  }
  struct file_node *fn = (struct file_node *)malloc(sizeof(struct file_node));
  fn->f = filesys_open(FileName);
  if(fn->f == NULL || CUR->fileNum >= MaxFiles){
    fn->fd = -1;
  }
  else{
    fn->fd = ++cur->maxfd;
  }
  f->eax = fn->fd;
  if(fn->fd == -1){
    free(fn);
  }
  else{
    cur->fileNum++;
    list_push_back(&cur->file_list, &fn->elem);
  }
}

void my_filesize(struct intr_frame *f){
  if(!is_user_vaddr(((int *)f->esp)+2)){
    thread_current()->exit_code = -1;
    thread_exit();
  }
  struct thread *cur = thread_current();
  int fd = *((int *)f->esp+1);
  struct file_node *fn = GetFile(cur,fd);
  if(fn == NULL){
    f->eax = -1;
    return;
  }
  f->eax = file_length(fn-f);
}

void my_read(struct intr_frame *f){

}*/
