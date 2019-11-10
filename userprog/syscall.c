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
#include "devices/input.h"
#include "devices/shutdown.h"
#include "threads/palloc.h"
#include "userprog/pagedir.h"

typedef int pid_t;

static void syscall_handler (struct intr_frame *);

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
void is_valid_string (const char *str){
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
static void syscall_handler (struct intr_frame *f)
{
  void *ptr = f->esp;
  is_valid_ptr(ptr);                                                    /*check if the head of the pointer is valid*/
  is_valid_ptr(ptr+3);                                                  /*check if the tail of the pointer is valid*/
  int syscall_num = * (int *)f->esp;
  void *esp = ptr+4;                                    /*get which systemcall*/
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
    /* Opens the file called file. Returns a nonnegative integer handle called
    a "file descriptor" (fd), or -1 if the file could not be opened. */
  else if(syscall_num == SYS_OPEN)
  {
      /* Check for validality of the first argument. */
    is_valid_ptr (esp);
      /* Make sure that the whole argument is on valid address. */
    is_valid_ptr (esp + 3);
    const char *file_name = *((char **) esp);
      /* Check for validality of the file_name. */
    is_valid_string (file_name);
    lock_acquire(&file_lock);
    f->eax = open(file_name);
    lock_release(&file_lock);
  }
    /* Returns the size, in bytes, of the file open as fd. */
  else if(syscall_num == SYS_FILESIZE)
  {
      /* Check for validality of the first argument. */
    is_valid_ptr (esp);
      /* Make sure that the whole argument is on valid address. */
    is_valid_ptr (esp + 3);
    int fd = *((int *) esp);
    f->eax = filesize (fd);
  }
    /* Reads size bytes from the file open as fd into buffer. Returns the number
    of bytes actually read, or -1 if the file could not be read. */
else if(syscall_num == SYS_READ)
  {
      /* Check for validality of the first argument. */
    is_valid_ptr (esp);
      /* Check for validality of the second argument. */
    is_valid_ptr (esp + 3);
    int fd = *((int *) esp);
    void *buffer = *((char **) (esp + 4));
    unsigned size = *((unsigned *) (esp + 8));
      /* Check that the given buffer is all valid. */
    is_valid_ptr (buffer);
    is_valid_ptr (buffer + size);
    lock_acquire(&file_lock);
    f->eax= read (fd, buffer, size);
    lock_release(&file_lock);
  }
    /* Writes size bytes from buffer to the open file fd. Returns the number of bytes
    actually written, which may be less than size if some bytes could not be written. */
else if(syscall_num == SYS_WRITE)
  {
      /* Check for validality of the first argument. */
    is_valid_ptr (esp);
      /* Check for validality of the second argument. */
    is_valid_ptr (esp + 3);
    int fd = *((int *) esp);
    void *buffer = *((char **) (esp + 4));
    unsigned size = *((unsigned *) (esp + 8));
      /* Check that the given buffer is all valid. */
    is_valid_ptr (buffer);
    is_valid_ptr (buffer + size);
    lock_acquire(&file_lock);
    f->eax = write (fd, buffer, size);
    lock_release(&file_lock);
  }
    /* Changes the next byte to be read or written in open file fd
    to position, expressed in bytes from the beginning of the file */
  else if(syscall_num == SYS_SEEK)
  {
      /* Check for validality of the first argument. */
    is_valid_ptr (esp);
      /* Check for validality of the first argument. */
    is_valid_ptr (esp + 3);
    int fd = *((int *) esp);
    unsigned position = *((unsigned *) (esp + 4));
    seek (fd, position);
  }
    /* Returns the position of the next byte to be read or written
    in open file fd, expressed in bytes from the beginning of the file. */
  else if(syscall_num == SYS_TELL)
  {
      /* Check for validality of the first argument. */
    is_valid_ptr (esp);
      /* Make sure that the whole argument is on valid address. */
    is_valid_ptr (esp + 3);
    int fd = *((int *) esp);
    f->eax = tell (fd);
  }
    /* Closes file descriptor fd. Exiting or terminating a process implicitly closes
    all its open file descriptors, as if by calling this function for each one. */
  else if(syscall_num == SYS_CLOSE)
  {
      /* Check for validality of the first argument. */
    is_valid_ptr (esp);
    is_valid_ptr (esp + 3);
    int fd = *((int *) esp);
    close (fd);
  }
}



// Terminates Pintos by calling shutdown_power_off()
void halt (void){
  shutdown_power_off();
}

// Terminates the current user program with thestatus giving
void exit(int status){
  struct thread *cur = thread_current ();
  cur->exit_code = status;                                                 /*set status to exit_code and exit*/
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

int open (const char *file)
{
  struct file* f = filesys_open(file);
  struct thread *cur = thread_current();
  if (f == NULL)
    return -1;
  /* Start from 2 , to find next free fd to allocate. */
  int i = 2;
  while (i < MAX){
    if (cur->file[i] == NULL){
      cur->file[i] = f;
      break;
    }
    i = i + 1;
    if (i == MAX){
      i = -1;
      break;
    }
  }
  /* No fd to allocate. */
  return i;
}

int filesize (int fd)
{
  struct thread *cur = thread_current ();
  if (is_valid_fd (fd) && cur->file[fd] != NULL)
  {
    return file_length (cur->file[fd]);
  }
  return -1;
}


int read (int fd, void *buffer, unsigned size)
{
  struct thread *cur = thread_current ();
  /* standard input. */
  if (fd == 0)
  {
    input_getc();
    return size;
  }
  /* else */
  else
  {
    if (is_valid_fd (fd) && cur->file[fd] != NULL)
      return file_read (cur->file[fd], buffer, size);
    else{
      return -1;
    }
  }
}

int write (int fd, const void *buffer, unsigned size)
{
  struct thread *cur = thread_current ();
  /* standard output. */
  if (fd == 1)
  {
    putbuf(buffer,size);
    return size;
  }
  /* else */
  else
  {
    if (is_valid_fd (fd) && cur->file[fd] != NULL)
      return file_write (cur->file[fd], buffer, size);
    else{
      return -1;
    }
  }
}


void seek (int fd, unsigned position)
{
  struct thread *cur = thread_current ();
  if (is_valid_fd (fd) && cur->file[fd] != NULL)
  {
    file_seek (cur->file[fd], position);
  }
}

unsigned tell (int fd)
{
  struct thread *cur = thread_current ();
  if (is_valid_fd (fd) && cur->file[fd] != NULL)
  {
    return file_tell (cur->file[fd]);
  }
  else
    return -1;
}

void close (int fd)
{
  struct thread *cur = thread_current ();
  if (is_valid_fd (fd) && cur->file[fd] != NULL)
  {
    file_close (cur->file[fd]);
    cur->file[fd] = NULL;
    return;
  }
  else{
    return -1;
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
  lock_init(&file_lock);
}
