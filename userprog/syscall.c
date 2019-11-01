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

struct list file_list;

int new_file(struct file* file, bool exec){
  struct thread* t = thread_current();
  struct file_struct* fs = malloc(sizeof(struct file_struct));
  for(int i = 0; i<128; ++i){
    if(t->fd_table[i] == NULL){
      t->fd_table[i] == fs;
      fs->fd = t->fd_max;
      fs->f = file;
      fs->exec = exec;
      t->fd_max ++;
      break;
    }
  }
  return fs->fd;
}

struct file* get_file(int fd, bool modify){
  struct file_struct* fs;
  struct thread* t = thread_current();
  for(int i = 0; i<128;++i){
    fs = t->fd_table[i];
    if(fs!=NULL){
      if(fs->fd == fd){
        if(fs->exec && modify){
          return NULL;
        }
        return fs->f;
      }
    }
  }
  return NULL;
}

void close_file(int fd){
  struct file_struct* fs;
  struct thread* t = thread_current();
  for(int i = 0; i<128;++i){
    fs = t->fd_table[i];
    if(fs!=NULL){
      if(fs->fd == fd){
        file_close(fs->f);
        free(t->fd_table[i]);
        t->fd_table[i] = NULL;
        break;
      }
    }
  }
}

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
  /*if (get_user (((uint8_t *)esp)+size-1) == -1)
      return false;*/
  uint8_t i = 0;
  if(esp == NULL){
    return false;
  }
  for (; i < size; ++i)
  {
    if((!is_user_vaddr(esp))||(pagedir_get_page(thread_current()->pagedir,esp)==NULL)){
      return false;
    }
  }
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

void exit(int status){
  thread_current()->exit_code = status;
  thread_exit();
}

void verify_pointer(void *pointer){
  if (pointer == NULL){
    exit(-1);
  }
  if(!is_user_vaddr(pointer)){
    exit(-1);
  }
  if(pagedir_get_page(thread_current()->pagedir,pointer)==NULL){
    exit(-1);
  }
  if((uint32_t)pointer <= 0x08048000){
    exit(-1);
  }
}



static void
syscall_handler (struct intr_frame *f UNUSED)
{
  // if ( !check_ptr (f->esp, 4) ) {
  //   thread_current ()->exit_code = -1;
  //   thread_exit();
  //   return;
  // }

  verify_pointer(f->esp);
  verify_pointer(f->esp+3);
  uint32_t syscall_num = *(uint32_t*)f->esp;
  int *pointer = (int*)f->esp;

  /*is_valid_addr (&mc, f->esp, 4);*/
  // get syscall_num and check if it's valid
  // int syscall_num = *((int *)f->esp);
  if ( syscall_num < 0 || syscall_num >= 20 ) {
    thread_current ()->exit_code = -1;
    thread_exit();
    return;
  }

  switch(syscall_num){
    case SYS_HALT:
    {
      shutdown_power_off();
      return;
    }

    case SYS_EXIT:
    {
      verify_pointer(pointer+1);
      int status = *(pointer+1);
      thread_current()->exit_code = status;
      thread_exit();
      // int status;
      // // check if arg is in boundary
      // if (check_ptr(f->esp + 4, 4)){
      //   // extract status
      //   status = *((int*)(f->esp+4));
      //   thread_current ()->exit_code = status;
      //   thread_exit ();
      // }else{
      //   thread_current ()->exit_code = -1;
      //   thread_exit ();
      // }
      return;
    }

    case SYS_EXEC:
    {
      verify_pointer(pointer+1);
      char *cmd = (char*) *(pointer+1);
      verify_pointer(cmd);
      verify_pointer(cmd+5);
      if(strlen(cmd)==0){
        f->eax = -1;
      }
      else{
        tid_t cpid = process_execute(cmd);
        f->eax = cpid;
      }
    //   if (!check_ptr (f->esp + 4, 4))
    //   {
    //     thread_current ()->exit_code = -1;
    //     thread_exit ();
    //   }
    //   /*is_valid_addr (&mc,(uint32_t*)f->esp+1,4);*/
    //
    //   if(!check_str(*(char**)(f->esp+4))){
    //     thread_current ()->exit_code = -1;
    //     thread_exit ();
    //   }
    //   char *str =*(char**)(f->esp+4);
    //
    //   /*lock_acquire(&file_lock);*/
    //
    //   f->eax = process_execute (str);
    //   /*lock_release(&file_lock);*/
     return;
    }

    case SYS_WAIT:
    {
      verify_pointer(pointer+1);
      f->eax = process_wait(*(pointer+1));
      // int pid;
      // if (check_ptr (f->esp + 4, 4))
      // {
      //   pid = *((int*)f->esp+1);
      // } else {
      //   thread_current ()->exit_code = -1;
      //   thread_exit ();
      // }
      //
      // f->eax = process_wait(pid);
      // return;
    }

    case SYS_CREATE:
    {
      verify_pointer(pointer+1);
      verify_pointer(pointer+2);
      char *file_name = (char*) *(pointer+1);
      verify_pointer(file_name);
      unsigned size = (unsigned) *(pointer+2);
      f->eax = (uint32_t) filesys_create(file_name, size);
      // if (!check_ptr (f->esp +4, 4) ||
      //     !check_str (*(char **)(f->esp + 4)) || !check_ptr (f->esp +8, 4))
      // {
      //   thread_current ()->exit_code = -1;
      //   thread_exit ();
      // }
      // char *str = *(char**)(f->esp+4);
      // unsigned size = *(int *)(f->esp + 8);
      // f->eax = filesys_create (str, size);
      /*palloc_free_page (str);*/

      return;
    }

    case SYS_REMOVE:
    {
      verify_pointer(pointer+1);
      char *file_name = (char*) *(pointer+1);
      verify_pointer(file_name);
      f->eax = (uint32_t) filesys_remove(file_name);
      // if (!check_ptr (f->esp +4, 4) ||
      //     !check_str (*(char **)(f->esp + 4)))
      // {
      //   thread_current ()->exit_code = -1;
      //   thread_exit ();
      // }
      //
      // char *str = *(char**)(f->esp+4);
      // f->eax = filesys_remove (str);
      /*palloc_free_page (str);*/
      return;
    }

    case SYS_OPEN:{
      verify_pointer(pointer+1);
      char *file_name = (char*) *(pointer+1);
      verify_pointer(file_name);
      struct file* open_file = filesys_open(file_name);
      if (open_file == NULL){
        f->eax = -1;
      }
      else{
        f->eax = new_file(open_file,false);
      }
    }

    case SYS_FILESIZE:
    {
      verify_pointer(pointer+1);
      struct file* cor_file = get_file(*(pointer+1),false);
      if (cor_file == NULL){
        f->eax = -1;
      }
      else{
        f->eax = (uint32_t) file_length(cor_file);
      }
      // if (!check_ptr (f->esp +4, 4))
      // {
      //   thread_current ()->exit_code = -1;
      //   thread_exit ();
      //   return;
      // }
      //
      // int fd = *(int *)(f->esp + 4);
      //
      // struct fd_entry *fd_entry = get_fd_entry(fd);
      // if (fd_entry) {
      //   f->eax = file_length(fd_entry->file);
      // } else {
      //   thread_current ()->exit_code = -1;
      //   thread_exit ();
        /*f->eax = -1;*/

      return;
    }

    case SYS_READ:
    {
      verify_pointer(pointer+1);
      verify_pointer(pointer+2);
      verify_pointer(pointer+3);
      int fd = (int) *(pointer+1);
      void *buffer = (void*) *(pointer+2);
      unsigned size = (unsigned) *(pointer+3);
      verify_pointer(buffer);
      if(fd == 0){
        input_getc();
        f->eax = size;
      }
      else if(fd >= 2){
        struct file* read_file = get_file(fd, false);
        if(read_file == NULL){
          f->eax = -1;
        }
        else{
          f->eax = file_read(read_file, buffer, size);
        }
      }


    //   if ( !check_ptr (f->esp + 4, 12) )
    //   {
    //     thread_current ()->exit_code = -1;
    //     thread_exit ();
    //   }
    //
    //   int fd = *(int *)(f->esp + 4);
    //   void *buffer = *(char**)(f->esp + 8);
    //   unsigned size = *(unsigned *)(f->esp + 12);
    //   if ( !check_ptr (buffer, 1) || !check_ptr (buffer + size, 1) )
    //   {
    //     thread_current ()->exit_code = -1;
    //     thread_exit ();
    //   }
    //
    //   /*lock_acquire(&file_lock);*/
    //   struct fd_entry *fd_entry = get_fd_entry (fd);
    //   /*if (fd_entry == NULL || fd_entry->dir) {
    //     f->eax = -1;
    //     return;
    //   }*/
    //   if(fd_entry->file ==NULL){
    //     f->eax = -1;
    //     return;
    //   }
    //
    //   size_t tmp_size = size;
    //   void *tmp_buffer = buffer;
    //   int retval = 0;
    //   while (tmp_size > 0)
    //   {
    //     size_t read_bytes;
    //     if (tmp_size < PGSIZE - pg_ofs (tmp_buffer)) {
    //       read_bytes = tmp_size;
    //     } else {
    //       read_bytes = PGSIZE - pg_ofs (tmp_buffer);
    //     }
    //
    //     off_t bytes_read = file_read (fd_entry->file, tmp_buffer, read_bytes);
    //     retval += bytes_read;
    //
    //     tmp_size -= bytes_read;
    //     tmp_buffer += bytes_read;
    //
    //   }
    //
    //   f->eax = retval;
    //   /*lock_release(&file_lock);*/
    //   /*if(fd==1){
    //     for(unsigned int i=0;i<length;i++){
    //       *((char **)buffer)[i] = input_getc();
    //     }
    //     f->eax= length;
    //   }else{
    //     struct fd_entry *fd_entry = get_fd_entry (fd);
    //
    //     if(fd_entry->file == NULL){
    //       f->eax = -1;
    //     }
    //     f->eax= file_read(f,buffer,length);
    //   }*/
      return;
    }

    case SYS_WRITE:
    {
      // if ( !check_ptr (f->esp + 4, 12) ){
      //   thread_current ()->exit_code = -1;
      //   thread_exit ();
      // }
      //
      // int fd = *(int *)(f->esp + 4);
      // void *buffer = *(char**)(f->esp + 8);
      // unsigned size = *(unsigned *)(f->esp + 12);
      // if ( !check_ptr (buffer, 1) || !check_ptr (buffer + size, 1) ) {
      //   thread_current ()->exit_code = -1;
      //   thread_exit ();
      // }
      //
      // /*lock_acquire(&file_lock);*/
      //
      // if (fd == 1) {
      //   putbuf((char *)buffer, (size_t)size);
      //   f->eax = size;
      //   return;
      // }
      //
      // size_t tmp_size = size;
      // void *tmp_buffer = buffer;
      // int retval = 0;
      //
      // struct fd_entry *fd_entry = get_fd_entry (fd);
      // /*if (fd_entry==NULL || fd_entry->dir) {
      //   f->eax = -1;
      //   return;
      // }*/
      // if(fd_entry->file == NULL){
      //   thread_current ()->exit_code = -1;
      //   thread_exit ();
      // }
      //
      // while (tmp_size > 0)
      // {
      //   size_t write_bytes;
      //   if (tmp_size < PGSIZE - pg_ofs (tmp_buffer)) {
      //     write_bytes = tmp_size;
      //   } else {
      //     write_bytes = PGSIZE - pg_ofs (tmp_buffer);
      //   }
      //
      //   if (!(tmp_buffer < PHYS_BASE && pagedir_get_page (thread_current ()->pagedir, tmp_buffer) != NULL))
      //   {
      //     thread_exit ();
      //   }
      //
      //   off_t bytes_written = file_write (fd_entry->file, tmp_buffer, write_bytes);
      //   if (retval < 0 || (bytes_written != (off_t) write_bytes)){
      //     f->eax = retval;
      //     return;
      //   }
      //   retval += bytes_written;
      //
      //   tmp_buffer += bytes_written;
      //   tmp_size -= bytes_written;
      // }
      //
      // f->eax = retval;
      /*lock_release(&file_lock);*/
      verify_pointer(pointer+1);
      verify_pointer(pointer+2);
      verify_pointer(pointer+3);
      int fd = (int) *(pointer+1);
      void *buffer = (void*) *(pointer+2);
      unsigned size = (unsigned) *(pointer+3);
      verify_pointer(buffer);
      if(fd == 1){
        putbuf(buffer, size);
        f->eax = size;
      }
      else if(fd >= 2){
        struct file* write_file = get_file(fd, true);
        if(write_file == NULL){
          f->eax = -1;
        }
        else{
          f->eax = file_write(write_file, buffer, size);
        }
      }
      return;
    }

    case SYS_SEEK:
    {
      // if (!check_ptr (f->esp +4, 8))
      // {
      //   thread_current ()->exit_code = -1;
      //   thread_exit ();
      // }
      //
      // int fd = *(int *)(f->esp + 4);
      // unsigned position = *(unsigned *)(f->esp + 8);
      //
      // struct fd_entry *fd_entry = get_fd_entry(fd);
      // if (!fd_entry->file) {
      //   thread_current ()->exit_code = -1;
      //   thread_exit ();
      // }
      // file_seek(fd_entry->file,position);
      verify_pointer(pointer+1);
      verify_pointer(pointer+2);
      struct file* file = get_file(*(pointer+1), false);
      if(file == NULL){
        exit(-1);
      }
      else{
        unsigned pos = (unsigned) *(pointer + 2);
        file_seek(file,pos);
      }
      return;
    }

    case SYS_TELL:
    {

      // if (!check_ptr (f->esp +4, 4))
      // {
      //   thread_current ()->exit_code = -1;
      //   thread_exit ();
      // }
      //
      // int fd = *(int *)(f->esp + 4);
      // struct fd_entry *fd_entry = get_fd_entry (fd);
      //
      // if(!fd_entry->file){
      //   thread_current ()->exit_code = -1;
      //   thread_exit ();
      // }
      //
      // f->eax = file_tell (fd_entry->file);
      verify_pointer(pointer+1);
      struct file* file = get_file(*(pointer+1), false);
      if (file==NULL){
        f->eax = -1;
      }
      else{
        f->eax = file_tell (file);
      }

      return;
    }

    /*case SYS_CLOSE:
    {
      // if (!check_ptr (f->esp +4, 4))
      // {
      //   thread_current ()->exit_code = -1;
      //   thread_exit ();
      // }
      //
      // int fd = *(int *)(f->esp + 4);
      //
      // struct fd_entry *fd_entry = get_fd_entry (fd);
      // file_close (fd_entry->file);
      // list_remove (&fd_entry->elem);
      // free (fd_entry);
      verify_pointer(pointer+1);
      close_file(*(pointer+1));

      return;
    }*/

    default:
    break;
  }
}

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");

  // lock_init(&file_lock);
  // list_init(&file_list);
}
