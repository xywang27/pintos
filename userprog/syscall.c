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
#include "vm/frame.h"
#include "vm/page.h"

typedef int pid_t;

static void syscall_handler (struct intr_frame *);
static int mapid=1;

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
static void syscall_handler (struct intr_frame *f){
  void *ptr = f->esp;
  uint32_t *pp = f->esp;
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
    // #ifdef VM
    //         struct list_elem *se;
    //         struct spt_elem *spte;
    //         bool deny;
    // 		deny=false;
    // 		for(se=list_begin(&thread_current()->spt);
    // 		se!=list_end(&thread_current()->spt);se=list_next(se))
    // 		{
    // 			spte=(struct spt_elem *)list_entry (se, struct spt_elem, elem);
    // 			if(spte->fileptr==*(pp+1))
    // 			{
    // 				//暂时不关闭
    // 				spte->needremove=true;
    // 				deny=true;
    // 				break;
    // 			}
    // 		}
    // #endif
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
    // #ifdef VM
    //       bool deny;
    //       struct list_elem *e;
    //       struct list_elem *se;
    //       struct file_desc *file_d;
    //       struct spt_elem *spte;
    // 			deny=false;
    // 			for(se=list_begin(&thread_current()->spt);
    // 			se!=list_end(&thread_current()->spt);se=list_next(se))
    // 			{
    // 				spte=(struct spt_elem *)list_entry (se, struct spt_elem, elem);
    // 				if(spte->fileptr==file_d->file)
    // 				{
    // 					//暂时不关闭
    // 					spte->needclose=true;
    // 					deny=true;
    // 					break;
    // 				}
    // 			}
    // #endif
    close(fd);
  }
  else if(syscall_num == SYS_MMAP){
    struct list_elem *e;
    struct list_elem *se;
    struct list_elem *te;
    struct file_desc *file_d;
    struct list* fd_list = &thread_current()->fd_list;
    bool findornot=false;
    // [X]spt指针
    struct spt_elem *spte;
    struct spt_elem *spte2;
    off_t filesize;
    for (e = list_begin (fd_list); e != list_end (fd_list);
        e = list_next (e))
        {
        file_d = list_entry (e, struct file_desc, elem);
        //[X]找到文件描述符为fd的文件
        if (file_d->fd == *(pp+1)){
     findornot=true;
           filesize= file_length (file_d->file);
           //[X]因为一个文件可能占有多个
           int mapped_page=0;
     off_t fileoff=0;
     //检查了测试，初始地址都是页面对齐的，所以不用处理第一次映射的不对齐问题
     uint32_t upage=*(pp+2);
     //[X]不合要求的虚存地址不能被映射
     if(upage==0||(pg_round_down(upage)!=upage)||upage+PGSIZE>f->esp
     ||upage<0x08050000)
    {
        f->eax=-1;
        return;
    }
    lock_acquire(&thread_current()->spt_list_lock);
           while(filesize>0)
           {
      spte=(struct spt_elem *)malloc(sizeof(struct spt_elem));
      spte->upage=upage;
      for (se = list_begin (&thread_current()->spt); se != list_end (&thread_current()->spt);
      se = list_next (se))
      {
        spte2=(struct spt_elem *)list_entry (se, struct spt_elem, elem);
        //[X]不能重叠映射
        if(spte2->upage==spte->upage)
        {
          f->eax=-1;
          return;
        }
      }
      //[X]虚存空间的下一页
      upage=upage+(uint32_t)PGSIZE;
      spte->fileptr=file_d->file;
      //[X]修改文件指针使
      spte->ofs=mapped_page * (uint32_t)PGSIZE;
      mapped_page++;
      //[X]标记mapid
      spte->mapid=mapid;
      //[X]处理边界的最后一页
      if(filesize>=PGSIZE)
      {
        spte->read_bytes=PGSIZE;
        spte->zero_bytes=0;
      }
      else
      {
        spte->read_bytes=filesize;
        spte->zero_bytes=PGSIZE-filesize;
      }
      spte->writable=true;
      list_push_back (&thread_current()->spt, &spte->elem);
      //表示一段已经映射进去了
      filesize=filesize-PGSIZE;
    }
    lock_release(&thread_current()->spt_list_lock);
    //[X]退出for循环
    break;
         }
  }
  //[X]mapid作为返回值
  if(findornot)
  {
  f->eax=mapid;
  mapid++;
  }
  else
  f->eax=-1;
  }
  else if(syscall_num == SYS_MUNMAP){
    int mip=*(pp+1);
		struct thread* t=thread_current();
		struct spt_elem *spte;
		struct list_elem *e;
		struct list_elem *e2;
		//[X]找到相应mip的对应的页面表项spte
		lock_acquire(&thread_current()->spt_list_lock);
          e = list_begin (&t->spt);
          while(e!=list_end(&t->spt))
          {
			  spte=(struct spt_elem *)list_entry (e, struct spt_elem, elem);
			  if(spte->mapid==mip)
			  {
				  //[X]该页是目标页,脏页面要写回
				  if(pagedir_is_dirty(t->pagedir,spte->upage))
				  {
					file_write_at(spte->fileptr,spte->upage,PGSIZE,spte->ofs);
				  }
				  e2=e;
				  e = list_next (e);
				  list_remove(e2);
			  }
			  else
				e = list_next (e);
		  }
		lock_release(&thread_current()->spt_list_lock);
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

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_lock);
}
