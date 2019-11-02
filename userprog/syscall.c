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
  struct list_elem elem;                     /*used to store in fd_list*/
  struct list_elem thread_elem;
  int fd;                                    /*file's id*/
};

static void syscall_handler (struct intr_frame *);
typedef int pid_t;

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

static struct file *find_file_by_fd (int fd);
static struct file_element *find_file_element_by_fd (int fd);
static struct file_element *find_file_element_by_fd_in_process (int fd);

static struct list file_list;

static temp_fd = 2;                 /*used to generate fd


/*
find file_element in current's thread fd_list
*/
static struct file_element *find_file_element_by_fd_in_process (int fd)
{
  struct file_element *ret;
  struct list_elem *l;
  struct thread *t;

  t = thread_current ();

  for (l = list_begin (&t->fd_list); l != list_end (&t->fd_list); l = list_next (l))
    {
      ret = list_entry (l, struct file_element, thread_elem);
      if (ret->fd == fd)
        return ret;
    }

  return NULL;
}

/*
find file be fd id
*/
static struct file *find_file_by_fd (int fd)
{
  struct file_element *ret;

  ret = find_file_element_by_fd (fd);
  if (!ret)
    return NULL;
  return ret->file;
}

static struct file_element *find_file_element_by_fd (int fd)
{
  struct file_element *ret;
  struct list_elem *l;

  for (l = list_begin (&file_list); l != list_end (&file_list); l = list_next (l))
    {
      ret = list_entry (l, struct file_element, elem);
      if (ret->fd == fd)
        return ret;
    }

  return NULL;
}


void is_valid_ptr (void *pointer)
{
    if ( pointer == NULL)
    {
        exit(-1);
    }
    if (is_kernel_vaddr (pointer))
    {
        exit(-1);
    }
    if(!is_user_vaddr(pointer)){
      exit(-1);
    }
    if (pagedir_get_page (thread_current ()->pagedir, pointer) == NULL)
    {
        exit(-1);
    }
    /* check for end address. */
}

void is_valid_string(char *str)
{
    /* check one bit at a time*/
    is_valid_ptr (str);

    /* check until the end of C style string. */
    while (*str != '\0'){
      str++;
      is_valid_ptr (str);
    }
}
// syscall_init put this function as syscall handler
// switch handler by syscall num
static void syscall_handler (struct intr_frame *f)
{
  //printf ("system call!\n");
  // if(!is_valid_pointer(f->esp,4)){
  //   exit(-1);
  //   return;
  // }
  // void *esp = f->esp;
  void *ptr = f->esp;
  is_valid_ptr(ptr);
  // is_valid_ptr(ptr+4);
  int syscall_num = * (int *)f->esp;
  //printf("system call number %d\n", syscall_num);
  if(syscall_num<=0||syscall_num>=20){
    exit(-1);
  }

  if (syscall_num == SYS_HALT){
    halt();
  }

  else if(syscall_num == SYS_EXIT){
    is_valid_ptr(ptr+4);
    is_valid_ptr(ptr+8);
    int status = *(int *)(ptr+4);
    exit(status);
  }

  else if(syscall_num == SYS_EXEC){
    is_valid_ptr(ptr+4);
    is_valid_ptr(ptr+8);
    char *file_name = *(char **)(ptr+4);
    is_valid_string(file_name);
    lock_acquire(&file_lock);
    f->eax = exec(file_name);
    lock_release(&file_lock);
  }

  else if(syscall_num == SYS_WAIT){
    is_valid_ptr(ptr+4);
    is_valid_ptr(ptr+8);
    int pid = *((int*)ptr+4);
    f->eax = wait(pid);
  }

  else if(syscall_num == SYS_CREATE){
    is_valid_ptr (ptr+4);
    is_valid_ptr (ptr+8);
    is_valid_ptr (ptr+12);
    char* file_name = *(char **)(ptr+4);
    is_valid_string(file_name);
    unsigned size = *(int *)(ptr+8);
    f->eax = create(file_name,size);
  }

  else if(syscall_num == SYS_REMOVE){
    is_valid_ptr(ptr+4);
    is_valid_ptr(ptr+8);
    char *file_name = *(char **)(ptr+4);
    is_valid_string(file_name);
    f->eax = remove(file_name);
  }

  else if(syscall_num == SYS_OPEN){
    is_valid_ptr(ptr+4);
    is_valid_ptr(ptr+8);
    char *file_name = *(char **)(ptr+4);
    is_valid_str(file_name);
    lock_acquire(&file_lock);
    f->eax = open(file_name);
    lock_release(&file_lock);
  }

  else if(syscall_num == SYS_FILESIZE){
    is_valid_ptr(ptr+4);
    is_valid_ptr(ptr+8);
    int fd = *(int *)(ptr + 4);
    f->eax = filesize(fd);
  }

  else if(syscall_num == SYS_READ){
    is_valid_ptr(ptr+4);
    is_valid_ptr(ptr+8);
    is_valid_ptr(ptr+12);
    is_valid_ptr(ptr+16);
    int fd = *(int *)(ptr + 4);
    void *buffer = *(char**)(ptr + 8);
    unsigned size = *(unsigned *)(ptr + 12);
    is_valid_ptr (buffer);
    is_valid_ptr (buffer+size);
    lock_acquire(&file_lock);
    f->eax = read(fd,buffer,size);
    lock_release(&file_lock);
  }

  else if(syscall_num == SYS_WRITE){
    is_valid_ptr(ptr+4);
    is_valid_ptr(ptr+8);
    is_valid_ptr(ptr+12);
    is_valid_ptr(ptr+16);
    int fd = *(int *)(ptr + 4);
    void *buffer = *(char**)(ptr + 8);
    unsigned size = *(unsigned *)(ptr + 12);
    is_valid_ptr (buffer);
    is_valid_ptr (buffer+size);
    lock_acquire(&file_lock);
    f->eax = write(fd,buffer,size);
    lock_release(&file_lock);
  }

  else if(syscall_num == SYS_SEEK){
    is_valid_ptr(ptr+4);
    is_valid_ptr(ptr+8);
    is_valid_ptr(ptr+12);
    int fd = *(int *)(ptr + 4);
    unsigned pos = *(unsigned *)(ptr + 8);
    seek(fd,pos);
  }

  else if(syscall_num == SYS_TELL){
    is_valid_ptr(ptr+4);
    is_valid_ptr(ptr+8);
    int fd = *(int *)(ptr + 4);
    tell(fd);
  }

  else if(syscall_num == SYS_CLOSE){
    is_valid_ptr(ptr+4);
    is_valid_ptr(ptr+8);
    int fd = *(int *)(ptr + 4);
    close(fd);
  }
}

void halt (void){
  shutdown_power_off();
}

/*
exit curret thread with given status
*/
void exit(int status){

  /* Close all the files */
struct thread *t;
struct list_elem *l;

t = thread_current ();
while (!list_empty (&t->fd_list))
  {
    l = list_begin (&t->fd_list);
    close (list_entry (l, struct file_element, thread_elem)->fd);
  }

t->exit_code = status;
thread_exit ();
}

/*
create  a process execute this file
*/
pid_t exec (const char *file){
  return process_execute(file);
}


int wait (pid_t pid){
  return process_wait(pid);
}

bool create (const char *file, unsigned initial_size){
  //printf("call create %s\n",file);
    /*
    TODO: check of file_name valid
    */
    return filesys_create(file,initial_size);
}

bool remove (const char *file){
  //printf("call remove file %s\n",file);
  return filesys_remove(file);
}

int open (const char *file){
    //printf("call open file %s\n",file );  // if (get_user(((uint8_t *)esp)+i) == -1){
  //   return false;
  // }
    /*
    TODO: check valid string
    */
    struct file* f = filesys_open(file);
    // open  fail, kill the process
    if(f == NULL){
      //printf("%s\n","open fails");
      return -1;
    }

    // add file descriptor
    struct file_element *fde = (struct file_element *)malloc(sizeof(struct file_element));
    // malloc fails
    if(fde == NULL){
      file_close(f);
      return -1; // open fail
    }
    struct thread *cur = thread_current();
    fde->fd = temp_fd + 1;
    temp_fd = temp_fd + 1;
    fde->file = f;
    list_push_back(&cur->fd_list,&fde->thread_elem);
    list_push_back(&file_list,&fde->elem);

    return fde->fd;

}

int filesize (int fd){

  struct file *f = find_file_by_fd(fd);
  if(f == NULL){
    exit(-1);
  }
  return file_length(f);

}

int read (int fd, void *buffer, unsigned length){
  // printf("call read %d\n", fd);
  if(fd==0){
    for(unsigned int i=0;i<length;i++){
      *((char **)buffer)[i] = input_getc();
    }
    return length;
  }else{
    struct file *f = find_file_by_fd(fd);

    if(f == NULL){
      return -1;
    }
    return file_read(f,buffer,length);
  }
}

int write (int fd, const void *buffer, unsigned length){
  if(fd==1){ // stdout
      putbuf((char *) buffer,(size_t)length);
      return (int)length;
  }else{
    struct file *f = find_file_by_fd(fd);
    if(f==NULL){
      exit(-1);
    }
    return (int) file_write(f,buffer,length);

  }
}

void seek (int fd, unsigned position){

  struct file *f = find_file_by_fd(fd);
  if(f == NULL){
    exit(-1);
  }
  file_seek(f,position);
}

unsigned tell (int fd){
  struct file *f = find_file_by_fd(fd);
  if(f == NULL){
    exit(-1);
  }
  return file_tell(f);
}

/*
Closes file descriptor fd. Exiting or terminating a process
implicitly closes all its open file descriptors,
 as if by calling this function for each one.
*/
void close (int fd){
  struct file_element *f = find_file_element_by_fd_in_process(fd);

  // close more than once will fail
  if(f == NULL){
    exit(-1);
  }
  file_close (f->file);
  list_remove (&f->elem);
  list_remove (&f->thread_elem);
  free (f);
}





/**
Creates a new file called file initially initial size bytes in size.
Returns true if successful, false otherwise.
Creating a new file does not open it:
opening the new file is a separate operation
which would require a open system call.
@param file: file name
@param
*/


/*
delete the fiile called file.
return true if successful, false otherwise
A file may be removed regardless of whether it is
open or closed. and removing an open file does not
close it
*/


/*
Opens the file called file. Returns a nonnegative integer handle called a “file descriptor” (fd), or -1 if the file could not be opened. File descriptors numbered 0 and 1 are reserved for the console:
fd 0 (STDIN_FILENO) is standard input, fd 1 (STDOUT_FILENO) is standard ouint open (const char *file){
tput.
The open system call will never return either of these file descriptors,
which are valid as system call arguments only as explicitly described below.
Each process has an independent set of file descriptors.
File descriptors are not inherited by child processes.
When a single file is opened more than once,
whether by a single process or different processes, each open returns a new
file descriptor. Different file descriptors for a single file are
closed independently in separate calls to close and they do not share
*/



/*
wait for process with pid
*/

/*
write buffer to stdout or file
*/







/*
Reads size bytes from the file open as fd into buffer.
Returns the number of bytes actually read (0 at end of file),
or -1 if the file could not be read (due to a condition other than end of file).
 Fd 0 reads from the keyboard using input_getc().
*/










void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");

  lock_init(&file_lock);
  list_init (&file_list);
}


/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */

   //uint8_t unsigned char
   //uaddr is a address
// static int
// get_user (const uint8_t *uaddr)
// {
//     //printf("%s\n", "call get user");
//   if(!is_user_vaddr((void *)uaddr)){
//     return -1;
//   }
//   if(pagedir_get_page(thread_current()->pagedir,uaddr)==NULL){
//     return -1;
//   }
//   //printf("%s\n","is_user_vaddr" );
//   int result;
//   asm ("movl $1f, %0; movzbl %1, %0; 1:"
//        : "=&a" (result) : "m" (*uaddr));
//   return result;
// }
//
// /* Writes BYTE to user address UDST.
//    UDST must be below PHYS_BASE.
//    Returns true if successful, false if a segfault occurred. */
// static bool
// put_user (uint8_t *udst, uint8_t byte)
// {
//   if(!is_user_vaddr(udst))
//     return false;
//   int error_code;
//   asm ("movl $1f, %0; movb %b2, %1; 1:"
//        : "=&a" (error_code), "=m" (*udst) : "q" (byte));
//   return error_code != -1;
// }
//
// /*
// check the following address is valid:
// if one of them are not valid, the function will return false
// */
// bool is_valid_pointer(void* esp,uint8_t argc){
//   uint8_t i = 0;
// for (; i < argc; ++i)
// {
//   // if (get_user(((uint8_t *)esp)+i) == -1){
//   //   return false;
//   // }
//   if((!is_user_vaddr(esp))||(pagedir_get_page(thread_current()->pagedir,esp)==NULL)||(is_kernel_vaddr(esp))){
//     return false;
//   }
//   esp = esp + 1;
// }
// return true;
// }
//
// /*
// return true if it is a valid string
// */
// bool is_valid_string(void *str){
//   //return true;
//   char character;
//   character = get_user(((uint8_t*)str));
//   // if exceed the boundry, return -1
//   while (character != '\0' && character!=-1) {
//     str++;
//     character = get_user(((uint8_t*)str));
//   }
//   // valid string ends with '\0'
//   if ( character == '\0' ){
//     return true;
//   }
//   return false;
// }
//
//
//
// /* Halt the operating system. */
// void sys_halt(struct intr_frame* f){
//   shutdown();
// };
//
// /* Terminate this process. */
// void sys_exit(struct intr_frame* f){
//   // if(!is_valid_pointer(f->esp+4,4)){
//   //   exit(-1);
//   // }
//   void *esp = f->esp;
//   esp = esp + 4;
//   is_valid (esp);
//   is_valid (esp+4);
//   int status = *(int *)(f->esp +4);
//   exit(status);
// };
//
// /* Start another process. */
// void sys_exec(struct intr_frame* f){
//   void *esp = f->esp;
//   esp = esp + 4;
//   // max name char[16]
//   if(!is_valid_pointer(f->esp+4,4)||!is_valid_string(*(char **)(f->esp + 4))){
//     exit(-1);
//   }
//   is_valid (esp);
//   is_valid (esp+4);
//   char *file_name = *(char **)(f->esp+4);
//   lock_acquire(&file_lock);
//   f->eax = exec(file_name);
//   lock_release(&file_lock);
// };
//
// /* Wait for a child process to die. */
// void sys_wait(struct intr_frame* f){
//   void *esp = f->esp;
//   esp = esp + 4;
//   is_valid (esp);
//   is_valid (esp+4);
//   pid_t pid;
//   if(!is_valid_pointer(f->esp+4,4)){
//     exit(-1);
//   }
//   pid = *((int*)f->esp+1);
//   f->eax = wait(pid);
// };
//
//
// void sys_create(struct intr_frame* f){
//   void *esp = f->esp;
//   esp = esp + 4;
//   is_valid (esp);
//   is_valid (esp+4);
//   is_valid (esp+8);
// if(!is_valid_pointer(f->esp+4,4)){
//   exit(-1);
// }
// char* file_name = *(char **)(f->esp+4);
// if(!is_valid_string(file_name)){
//   exit(-1);
// }
// unsigned size = *(int *)(f->esp+8);
// f->eax = create(file_name,size);
//
// }; /* Create a file. */
//
// void sys_remove(struct intr_frame* f){
//   void *esp = f->esp;
//   esp = esp + 4;
//   is_valid (esp);
//   is_valid (esp+4);
//   if (!is_valid_pointer(f->esp +4, 4) || !is_valid_string(*(char **)(f->esp + 4))){
//     exit(-1);
//   }
//   char *file_name = *(char **)(f->esp+4);
//   f->eax = remove(file_name);
//
// };/* Create a file. */
// void sys_open(struct intr_frame* f){
//   void *esp = f->esp;
//   esp = esp + 4;
//   is_valid (esp);
//   is_valid (esp+4);
//
//   if (!is_valid_pointer(f->esp +4, 4)){
//     exit(-1);
//   }
//   if (!is_valid_string(*(char **)(f->esp + 4))){
//     exit(-1);
//   }
//   char *file_name = *(char **)(f->esp+4);
//   lock_acquire(&file_lock);
//   f->eax = open(file_name);
//   lock_release(&file_lock);
//
//
// }; /*Open a file. */
//
// void sys_filesize(struct intr_frame* f){
//   void *esp = f->esp;
//   esp = esp + 4;
//   is_valid (esp);
//   is_valid (esp+4);
//   if (!is_valid_pointer(f->esp +4, 4)){
//     exit(-1);
//   }
//   int fd = *(int *)(f->esp + 4);
//
//   f->eax = filesize(fd);
//
//
// };/* Obtain a file's size. */
// void sys_read(struct intr_frame* f){
//   void *esp = f->esp;
//   esp = esp + 4;
//   is_valid (esp);
//   is_valid (esp+4);
//   is_valid(esp+8);
//   is_valid (esp+12);
//   if (!is_valid_pointer(f->esp + 4, 12)){
//     exit(-1);
//   }
//   int fd = *(int *)(f->esp + 4);
//   void *buffer = *(char**)(f->esp + 8);
//   unsigned size = *(unsigned *)(f->esp + 12);
//   if (!is_valid_pointer(buffer, 1) || !is_valid_pointer(buffer + size,1)){
//     exit(-1);
//   }
//   is_valid (buffer);
//   is_valid (buffer+size);
//   lock_acquire(&file_lock);
//   f->eax = read(fd,buffer,size);
//   lock_release(&file_lock);
//
// };
//
// /* Read from a file. */
// void sys_write(struct intr_frame* f){
//   void *esp = f->esp;
//   esp = esp + 4;
//   is_valid (esp);
//   is_valid (esp+4);
//   is_valid (esp+8);
//   is_valid (esp+12);
//   if(!is_valid_pointer(f->esp+4,12)){
//     exit(-1);
//   }
//   int fd = *(int *)(f->esp +4);
//   void *buffer = *(char**)(f->esp + 8);
//   unsigned size = *(unsigned *)(f->esp + 12);
//   is_valid (buffer);
//   is_valid (buffer+size);
//   if (!is_valid_pointer(buffer, 1) || !is_valid_pointer(buffer + size,1)){
//     exit(-1);
// }
//   lock_acquire(&file_lock);
//   f->eax = write(fd,buffer,size);
//   lock_release(&file_lock);
//   return;
// }; /* Write to a file. */
//
// void sys_seek(struct intr_frame* f){
//   void *esp = f->esp;
//   esp = esp + 4;
//   is_valid (esp);
//   is_valid (esp+4);
//   is_valid (esp+8);
//   if (!is_valid_pointer(f->esp +4, 8)){
//     exit(-1);
//   }
//   int fd = *(int *)(f->esp + 4);
//   unsigned pos = *(unsigned *)(f->esp + 8);
//   seek(fd,pos);
// }; /* Change position in a file. */
//
// void sys_tell(struct intr_frame* f){
//   void *esp = f->esp;
//   esp = esp + 4;
//   is_valid (esp);
//   is_valid (esp+4);
//   if (!is_valid_pointer(f->esp +4, 4)){
//     exit(-1);
//   }
//     int fd = *(int *)(f->esp + 4);
//     f->eax = tell(fd);
// }; /* Report current position in a file. */
//
// void sys_close(struct intr_frame* f){
//   void *esp = f->esp;
//   esp = esp + 4;
//   is_valid (esp);
//   is_valid (esp+4);
//   if (!is_valid_pointer(f->esp +4, 4)){
//     return exit(-1);
//   }
//   int fd = *(int *)(f->esp + 4);
//
//   close(fd);
//
// }; /* Close a file. */
