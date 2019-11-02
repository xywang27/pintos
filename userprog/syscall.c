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
  struct list_elem elem_of_thread;           /*list member tp store the file that the particular thread hold*/
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
t->exit_code = status;                                                   /*set status to exit_code and exit*/
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
    struct thread *cur = thread_current();
    // open  fail, kill the process
    if(f == NULL){
      //printf("%s\n","open fails");
      return -1;
    }

    // add file descriptor
    struct file_element *a = (struct file_element*)malloc(sizeof(struct file_element));
    list_push_back(&file_list,&a->elem);
    list_push_back(&cur->fd_list,&a->elem_of_thread);
    // malloc fails
    // if(fde == NULL){
    //   file_close(f);
    //   return -1; // open fail
    // }
    a->file = f;
    a->fd = temp_fd + 1;
    temp_fd = temp_fd + 1;




    return a->fd;

}

int filesize (int fd){

  struct file *f = find_file(fd);
  // if(f == NULL){
  //   exit(-1);
  // }
  return file_length(f);

}

int read (int fd, void *buffer, unsigned size){
  // printf("call read %d\n", fd);
  if(fd==0){
    // for(unsigned int i=0;i<size;i++){
    //   *((char **)buffer)[i] = input_getc();
    // }
    input_getc();
    return size;
  }else{
    struct file *f = find_file(fd);

    if(f != NULL){
      return file_read(f,buffer,size);
    }
    else{
      return -1;
    }
  }
}

int write (int fd, const void *buffer, unsigned size){
  if(fd==1){ // stdout
      putbuf(buffer,size);
      return size;
  }else{
    struct file *f = find_file(fd);
    if(f!=NULL){
      return file_write(f,buffer,size);
    }
    else{
      return -1;
    }


  }
}

void seek (int fd, unsigned position){

  struct file *f = find_file(fd);
  // if(f == NULL){
  //   exit(-1);
  // }
  file_seek(f,position);
}

unsigned tell (int fd){
  struct file *f = find_file(fd);
  // if(f == NULL){
  //   exit(-1);
  // }
  return file_tell(f);
}

/*
Closes file descriptor fd. Exiting or terminating a process
implicitly closes all its open file descriptors,
 as if by calling this function for each one.
*/
void close (int fd){
  struct file_element *f;
  f = NULL;
  struct file_element *f_temp;
  struct list_elem *a;
  struct thread *t = thread_current ();

  for (a = list_begin (&t->fd_list); a != list_end (&t->fd_list); a = list_next (a))
    {
      f_temp = list_entry (a, struct file_element, elem_of_thread);
      if (f_temp->fd == fd)
        f = f_temp;
        file_close (f->file);
        list_remove (&f->elem);
        list_remove (&f->elem_of_thread);
        free (f);
        return;
    }
  return -1;
}

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");

  lock_init(&file_lock);
  list_init (&file_list);
}
