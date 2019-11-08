#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/malloc.h"
#include "threads/synch.h"

// struct file_element
struct file_element{
  struct file *file;                         /*file's name*/
  struct list_elem elem;                     /*list member to store all the file opened*/
  struct list_elem elem_of_thread;           /*list member to store the file that the particular thread hold*/
  int fd;                                    /*file's id*/
};

static void syscall_handler (struct intr_frame *);
typedef int pid_t;
#define MAX 128
#define BUFFER_SIZE 200

// different kinds of systemcall function that will be used.
void halt (void);
void exit (int status);
pid_t exec (const char *file);
int wait (pid_t);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);
static bool is_valid_fd (int fd);

static struct file *find_file (int fd);

static struct list file_list;       /*list used to store all opened file*/

static temp_fd = 2;                 /*used to generate fd*/

// find the file in the file_list according to fd
static struct file *find_file (int fd){
  struct file_element *f;
  struct list_elem *a;
  for (a = list_begin (&file_list); a != list_end (&file_list); a = list_next (a)){    /*traverse the file_list*/
    f = list_entry (a, struct file_element, elem);
    if(f->fd == fd){                                                                  /*find the file with corresponding fd*/
      if(!f){
        return NULL;                                                                   /*return NULL if file dose not exit*/
      }
      else{
        return f->file;
      }
    }
  }
}

static bool
is_valid_fd (int fd)
{
  if (fd >= 0 && fd < MAX)
  {
    return true;
  }
  return false;
}

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int get_user (const uint8_t *uaddr){
  if(!is_user_vaddr((void *)uaddr)){
    return -1;
  }
  if(pagedir_get_page(thread_current()->pagedir,uaddr)==NULL){
    return -1;
  }
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));
  return result;
}

/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static bool put_user (uint8_t *udst, uint8_t byte){
  if(!is_user_vaddr(udst))
    return false;
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
       : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}

// check if the pointer is valid
void is_valid_ptr (void *pointer){
  if(pointer == NULL){                                                             /*the pointer can not be NULL*/
    exit(-1);
  }
  if(is_kernel_vaddr(pointer)){                                                    /*the pointer can not be kernal address*/
    exit(-1);
  }
  if(!is_user_vaddr(pointer)){                                                     /*the pointer must be user address*/
    exit(-1);
  }
  if(pagedir_get_page (thread_current ()->pagedir, pointer) == NULL){              /*the pointer must be mapped*/
    exit(-1);
  }
}

// check if the string is valid
void is_valid_string(char *str){
  char character = get_user(((uint8_t*)str));
  while (character != '\0' && character!=-1){                                      /*loop until error or reach the end of the string*/
    str++;
    character = get_user(((uint8_t*)str));
  }
  if(character != '\0'){                                                           /*valid string must end with '\0'*/
    exit(-1);
  }
}

// function that call different syscalls
static void syscall_handler (struct intr_frame *f){
  void *ptr = f->esp;
  is_valid_ptr(ptr);                                                    /*check if the head of the pointer is valid*/
  is_valid_ptr(ptr+3);                                                  /*check if the tail of the pointer is valid*/
  int syscall_num = * (int *)f->esp;                                    /*get which systemcall*/
  if(syscall_num<=0||syscall_num>=20){                                  /*check if systemcall is in the boundary*/
    exit(-1);
  }
  if (syscall_num == SYS_HALT){                                         /*sys_halt*/
    halt();
  }

  else if(syscall_num == SYS_EXIT){                                     /*sys_exec*/
    is_valid_ptr(ptr+4);                                                /*check if the head of the pointer is valid*/
    is_valid_ptr(ptr+7);                                                /*check if the tail of the pointer is valid*/
    int status = *(int *)(ptr+4);                                       /*get status*/
    exit(status);
  }

  else if(syscall_num == SYS_EXEC){                                     /*sys_exec*/
    is_valid_ptr(ptr+4);                                                /*check if the head of the pointer is valid*/
    is_valid_ptr(ptr+7);                                                /*check if the tail of the pointer is valid*/
    char *file_name = *(char **)(ptr+4);                                /*get file name*/
    is_valid_string(file_name);                                         /*check if the file name is valid*/
    lock_acquire(&file_lock);
    f->eax = exec(file_name);
    lock_release(&file_lock);
  }

  else if(syscall_num == SYS_WAIT){                                     /*sys_wait*/
    is_valid_ptr(ptr+4);                                                /*check if the head of the pointer is valid*/
    is_valid_ptr(ptr+7);                                                /*check if the tail of the pointer is valid*/
    int pid = *((int*)ptr+4);                                           /*get pid*/
    f->eax = wait(pid);
  }

  else if(syscall_num == SYS_CREATE){                                   /*sys_create*/
    is_valid_ptr (ptr+4);                                               /*check if the head of the pointer is valid*/
    is_valid_ptr (ptr+7);                                               /*check if the tail of the pointer is valid*/
    char* file_name = *(char **)(ptr+4);                                /*get file name*/
    is_valid_string(file_name);                                         /*check if file name is valid*/
    unsigned size = *(int *)(ptr+8);                                    /*get size*/
    f->eax = create(file_name,size);
  }

  else if(syscall_num == SYS_REMOVE){                                   /*sys_remove*/
    is_valid_ptr(ptr+4);                                                /*check if the head of the pointer is valid*/
    is_valid_ptr(ptr+7);                                                /*check if the tail of the pointer is valid*/
    char *file_name = *(char **)(ptr+4);                                /*get file name*/
    is_valid_string(file_name);                                         /*check if file name is valid*/
    f->eax = remove(file_name);
  }

  else if(syscall_num == SYS_OPEN){                                     /*sys_open*/
    is_valid_ptr(ptr+4);                                                /*check if the head of the pointer is valid*/
    is_valid_ptr(ptr+7);                                                /*check if the tail of the pointer is valid*/
    char *file_name = *(char **)(ptr+4);                                /*get file name*/
    is_valid_string(file_name);                                         /*check if file name is valid*/
    lock_acquire(&file_lock);
    f->eax = open(file_name);
    lock_release(&file_lock);
  }

  else if(syscall_num == SYS_FILESIZE){                                /*sys_filesize*/
    is_valid_ptr(ptr+4);                                               /*check if the head of the pointer is valid*/
    is_valid_ptr(ptr+7);                                               /*check if the tail of the pointer is valid*/
    int fd = *(int *)(ptr + 4);                                        /*get fd*/
    f->eax = filesize(fd);
  }

  else if(syscall_num == SYS_READ){                                    /*sys_read*/
    is_valid_ptr(ptr+4);                                               /*check if the head of the pointer is valid*/
    is_valid_ptr(ptr+7);                                               /*check if the tail of the pointer is valid*/
    int fd = *(int *)(ptr + 4);                                        /*get fd*/
    void *buffer = *(char**)(ptr + 8);                                 /*get buffer*/
    unsigned size = *(unsigned *)(ptr + 12);                           /*get size*/
    is_valid_ptr (buffer);                                             /*check if buffer is valid*/
    is_valid_ptr (buffer+size);                                        /*chekc if buffer+size is valid*/
    lock_acquire(&file_lock);
    f->eax = read(fd,buffer,size);
    lock_release(&file_lock);
  }

  else if(syscall_num == SYS_WRITE){                                   /*sys_write*/
    is_valid_ptr(ptr+4);                                               /*check if the head of the pointer is valid*/
    is_valid_ptr(ptr+7);                                               /*check if the tail of the pointer is valid*/
    int fd = *(int *)(ptr + 4);                                        /*get fd*/
    void *buffer = *(char**)(ptr + 8);                                 /*get buffer*/
    unsigned size = *(unsigned *)(ptr + 12);                           /*get size*/
    is_valid_ptr (buffer);                                             /*check if buffer is valid*/
    is_valid_ptr (buffer+size);                                        /*check if buffer+size is valid*/
    lock_acquire(&file_lock);
    f->eax = write(fd,buffer,size);
    lock_release(&file_lock);
  }

  else if(syscall_num == SYS_SEEK){                                    /*sys_seek*/
    is_valid_ptr(ptr+4);                                               /*check if the head of the pointer is valid*/
    is_valid_ptr(ptr+7);                                               /*check if the tail of the pointer is valid*/
    int fd = *(int *)(ptr + 4);                                        /*get fd*/
    unsigned pos = *(unsigned *)(ptr + 8);                             /*get pos*/
    seek(fd,pos);
  }

  else if(syscall_num == SYS_TELL){                                    /*sys_tell*/
    is_valid_ptr(ptr+4);                                               /*check if the head of the pointer is valid*/
    is_valid_ptr(ptr+7);                                               /*check if the tail of the pointer is valid*/
    int fd = *(int *)(ptr + 4);                                        /*get fd*/
    tell(fd);
  }

  else if(syscall_num == SYS_CLOSE){                                   /*sys_close*/
    is_valid_ptr(ptr+4);                                               /*check if the head of the pointer is valid*/
    is_valid_ptr(ptr+7);                                               /*check if the tail of the pointer is valid*/
    int fd = *(int *)(ptr + 4);                                        /*get fd*/
    close(fd);
  }
}

// Terminates Pintos by calling shutdown_power_off()
void halt (void){
  shutdown_power_off();
}

// Terminates the current user program with thestatus giving
void exit(int status){
struct thread *cur = thread_current ();
struct list_elem *a;
while (!list_empty (&cur->fd_list))                                      /*loop if current thread still has files unclosed*/
  {
    a = list_begin (&cur->fd_list);
    close (list_entry (a, struct file_element, elem_of_thread)->fd);     /*close this file*/
  }
cur->exit_status = status;                                                 /*set status to exit_code and exit*/
thread_exit ();
}

//run the excutable with the name given
pid_t exec (const char *file){
  return process_execute(file);
}

// Wait for a child process
int wait (pid_t pid){
  return process_wait(pid);
}

// create a new file
bool create (const char *file, unsigned initial_size){
    return filesys_create(file,initial_size);
}

// remove the particular file
bool remove (const char *file){
  return filesys_remove(file);
}

// Opens the file called file.
int open (const char *file){
    struct file* f = filesys_open(file);
    struct thread *cur = thread_current();
    if(f == NULL){                                                                        /*return -1 if open fails*/
      return -1;
    }
    int i;
    for (i = 2; i < MAX; i = i + 1)
    {
      if (cur->file[i] == NULL)
      {
        cur->file[i] = f;
        break;
      }
    }
  /* No fd to allocate. */
    if (i == MAX)
      i = -1;
    return i;
}

// Returns the size, in bytes, of the file open as fd.
int filesize (int fd){
  int file_size = 0;
  struct thread *t = thread_current ();
  if (is_valid_fd (fd) && t->file[fd] != NULL)
  {
    file_size = file_length (t->file[fd]);
  }
  return file_size;
}

// Reads size bytes from the file open as fd into buffer.
int read (int fd, void *buffer, unsigned size){
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

// Writes size bytes from buffer to the open file fd
int write (int fd, const void *buffer, unsigned size){
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
}

// Changes the next byte to be read or written in open file fd to position, expressed in bytes from the beginning of the file.
void seek (int fd, unsigned position){
  struct thread *t = thread_current ();
  if (is_valid_fd (fd) && t->file[fd] != NULL)
  {
    file_seek (t->file[fd], position);
  }
}

// Returns the position of the next byte to be read or written in open file fd, expressed in bytes from the beginning of the file.
unsigned tell (int fd){
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

// close the file with the corresponding fd
void close (int fd){
  struct thread *t = thread_current ();
  if (is_valid_fd (fd) && t->file[fd] != NULL)
  {
    file_close (t->file[fd]);
    t->file[fd] = NULL;
  }
}

void
syscall_init (void){
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");

  lock_init(&file_lock);
  list_init(&file_list);
}
