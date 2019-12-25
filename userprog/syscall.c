#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/directory.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
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
bool chdir (const char *pathname);
bool mkdir (const char *pathname);
bool readdir (int fd, char *name);
bool isdir (int fd);
int inumber (int fd);
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
    int pid = *(int*)(ptr+4);                                           /*get pid*/
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

  else if(syscall_num == SYS_CHDIR){                                   /*sys_close*/
    is_valid_ptr(ptr+4);                                               /*check if the head of the pointer is valid*/
    is_valid_ptr(ptr+7);                                               /*check if the tail of the pointer is valid*/
    const char *dir = *(char **)(ptr+4);                                  /*get fd*/
    f->eax = chdir(dir);
  }

  else if(syscall_num == SYS_MKDIR){                                   /*sys_close*/
    is_valid_ptr(ptr+4);                                               /*check if the head of the pointer is valid*/
    is_valid_ptr(ptr+7);                                               /*check if the tail of the pointer is valid*/
    const char *dir = *(char **)(ptr+4);                                  /*get fd*/
    f->eax = mkdir(dir);
  }

  else if(syscall_num == SYS_READDIR){                                   /*sys_close*/
    is_valid_ptr(ptr+4);                                               /*check if the head of the pointer is valid*/
    is_valid_ptr(ptr+7);                                               /*check if the tail of the pointer is valid*/
    char *name = *(char **)(ptr+8);                                  /*get fd*/
    int fd = *(int *)(ptr + 4);
    f->eax = readdir(fd, name);
  }

  else if(syscall_num == SYS_ISDIR){                                   /*sys_close*/
    is_valid_ptr(ptr+4);                                               /*check if the head of the pointer is valid*/
    is_valid_ptr(ptr+7);                                               /*check if the tail of the pointer is valid*/
    int fd = *(int *)(ptr + 4);
    f->eax = isdir(fd);
  }

  else if(syscall_num == SYS_INUMBER){                                   /*sys_close*/
    is_valid_ptr(ptr+4);                                               /*check if the head of the pointer is valid*/
    is_valid_ptr(ptr+7);                                               /*check if the tail of the pointer is valid*/
    int fd = *(int *)(ptr + 4);
    f->eax = inumber(fd);
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

// Opens the file called file.
int open (const char *file){
  struct file* f = filesys_open(file);
  struct thread *cur = thread_current();
  if(f == NULL){                                                                        /*return -1 if open fails*/
      return -1;
  }
  int i = 2;
  while (i < MAX){                                                                      /*loop to find which fd to allocate*/
    if (cur->file[i] == NULL){
      cur->file[i] = f;                                                                 /*allocate fd to the file*/
      break;
    }
    i = i + 1;
    if (i == MAX){                                                                      /*check if fd is too big*/
      i = -1;
      break;
    }
  }
  return i;
}

// Returns the size, in bytes, of the file open as fd.
int filesize (int fd){
  if (fd < 0 || fd >= MAX){                                                             /*check if fd is valid*/
    return -1;
  }
  struct thread *cur = thread_current ();
  if (cur->file[fd] != NULL){                                                           /*the file can not be NULL*/
    return file_length (cur->file[fd]);
  }
  return -1;
}

// Reads size bytes from the file open as fd into buffer.
int read (int fd, void *buffer, unsigned size){
  if (fd < 0 || fd >= MAX){                                                            /*check if fd is valid*/
    return -1;
  }
  struct thread *cur = thread_current ();
  if(fd == 0){                                                                        /*if it is STDIN*/
    input_getc();
    return size;
  }
  else{                                                                               /*if it is not STDIN*/
    if(cur->file[fd] != NULL){
      return file_read (cur->file[fd], buffer, size);
    }
    else{                                                                             /*return -1 if read fails*/
      return -1;
    }
  }
}

// Writes size bytes from buffer to the open file fd
int write (int fd, const void *buffer, unsigned size){
  if (fd < 0 || fd >= MAX){                                                             /*check if fd is valid*/
    return -1;
  }
  struct thread *cur = thread_current ();
  if(fd == 1){                                                                          /*if it is STDOUT*/
      putbuf(buffer,size);
      return size;
  }
  else{                                                                                /*if it is not STDOUT*/
    if (cur->file[fd] != NULL){
      if(inode_is_dir(file_get_inode(cur->file[fd]))){
        return -1;
      }
      return file_write (cur->file[fd], buffer, size);
    }
    else{                                                                              /*return -1 if write fails*/
      return -1;
    }
  }
}

// Changes the next byte to be read or written in open file fd to position, expressed in bytes from the beginning of the file.
void seek (int fd, unsigned position)
{
  if (fd < 0 || fd >= MAX){                                                             /*check if fd is valid*/
    return -1;
  }
  struct thread *cur = thread_current ();
  if (cur->file[fd] != NULL){                                                           /*file can not be NULL*/
    file_seek (cur->file[fd], position);
  }
}

// Returns the position of the next byte to be read or written in open file fd, expressed in bytes from the beginning of the file.
unsigned tell (int fd)
{
  if (fd < 0 || fd >= MAX){                                                             /*check if fd is valid*/
    return -1;
  }
  struct thread *cur = thread_current ();
  if (cur->file[fd] != NULL){                                                           /*file can not be NULL*/
    return file_tell (cur->file[fd]);
  }
  else{
    return -1;
  }
}

// close the file with the corresponding fd
void close (int fd)
{
  if (fd < 0 || fd >= MAX){                                                             /*check if fd is valid*/
    return -1;
  }
  struct thread *cur = thread_current ();
  if (cur->file[fd] != NULL){                                                          /*file can not be NULL*/
    file_close (cur->file[fd]);
    cur->file[fd] = NULL;
    return;
  }
  else{                                                                                /*return -1 if close fail*/
    return -1;
  }
}

bool chdir (const char *pathname){
  struct thread *cur = thread_current();

  struct dir *dir;
  char *filename;
  int result = parse_pathname(pathname, &dir, &filename);
  if (result == -1) {
      return false;
  }
  else if (result == 2) {
      // root directory
      dir_close(cur->cwd);
      cur->cwd = dir_open_root();
      return true;
  }

  struct inode *inode = NULL;
  if (!dir_lookup(dir, filename, &inode) || !inode_is_dir(inode)) {
      dir_close(dir);
      free(filename);
      return false;
  }
  dir_close(dir);
  free(filename);
  dir_close(cur->cwd);
  cur->cwd = dir_open(inode);
  return true;
}

bool mkdir (const char *pathname){
  struct dir *dir;
  char *filename;
  int result = parse_pathname(pathname, &dir, &filename);
  if (result == -1 || result == 2) {
      return false;
  }

  block_sector_t inode_sector = 0;

  bool success = free_map_allocate(1, &inode_sector)
          && dir_create(inode_sector, 16)
          && dir_add(dir, filename, inode_sector, true);

  if (!success && inode_sector != 0) {
      free_map_release(inode_sector, 1);
  }

  if (success) {
      struct dir *newdir = dir_open_sector(inode_sector);
      dir_add(newdir, ".", inode_sector, true);
      dir_add(newdir, "..", inode_get_inumber(dir_get_inode(dir)), true);
      dir_close(newdir);
  }

  dir_close(dir);
  free(filename);
  return success;
}

bool readdir (int fd, char *name){

  struct thread *cur = thread_current ();

  struct file *file = cur->file[fd];
  if (file == NULL){
    return false;
  }
  struct inode *inode = file_get_inode(file);
  if (!inode_is_dir(inode)) {
      return false;
  }
  off_t pos = file_tell(file);
  struct dir *dir = dir_open(inode);
  dir_seek(dir, pos);
  bool result = dir_readdir(dir, name);
  file_seek(file, dir_tell(dir));
  free(dir);
  return result;
}

bool isdir (int fd){
  struct thread *cur = thread_current ();

  struct file *file = cur->file[fd];
  if (file == NULL){
    return false;
  }

  return inode_is_dir(file_get_inode(file));
}

int inumber (int fd){
  struct thread *cur = thread_current ();

  struct file *file = cur->file[fd];
  if (file == NULL){
    return false;
  }

  return inode_get_inumber(file_get_inode(file));
}


void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_lock);
}
