#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/input.h"
#include "process.h"
#include <string.h>
#include "devices/shutdown.h"
#define MAXCALL 21
#define MaxFiles 200
#define stdin 1

static void syscall_handler (struct intr_frame *);

typedef void(*CALL_PROC)(struct intr_frame *);
CALL_PROC syscall_array[MAXCALL];
void my_halt(struct intr_frame *f)
void my_exit(struct intr_frame *f)
void my_exec(struct intr_frame *f)
void my_wait(struct intr_frame *f)
void my_create(struct intr_frame *f)
void my_remove(struct intr_frame *f)
void my_open(struct intr_frame *f)
void my_filesize(struct intr_frame *f)
void my_read(struct intr_frame *f)
void my_write(struct intr_frame *f)
void my_seek(struct intr_frame *f)
void my_tell(struct intr_frame *f)
void my_close(struct intr_frame *f)
struct file_node *GetFile(struct thread *t, int fd);

struct file_node{
  int fd;
  struct list_elem elem;
  sturct file *f;
}

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
  syscall_array[SYS_TELL] = &my_tell;
  syscall_array[SYS_CLOSE] = &my_close;
}

static void
syscall_handler (struct intr_frame *f UNUSED)
{
  /*printf ("system call!\n");
  thread_exit ();*/
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
  f->eax=0;
}

void my_exit(struct intr_frame *f){
  if(!is_user_vaddr(((int *)f->esp)+2)){
    thread_current()->exit_code = -1;
    thread_exit();
  }
  thread_current()->exit_code = *((int *)f->esp+1);
  f->eax=0;
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
  if(!is_user_vaddr(((int *)f->esp)+7)){
    thread_current()->exit_code = -1;
    thread_exit();
  }
  int *esp = (int *)f->esp;
  int fd = *(esp+2);
  char *buffer = (char *)*(esp+6);
  unsigned size = *(esp+3);
  if(buffer == NULL || !is_user_vaddr(buffer+size)){
    f->eax = -1;
    thread_current()->exit_code = -1;
    thread_exit();
  }
  struct thread *cur = thread_current();
  struct file_node *fn = NULL;
  unsigned int i;
  if (fd == STDIN_FILENO){
    for (i = 0;i<size;i++){
      buffer[i] = input_getc();
    }
  }
  else{
    fn = GetFile(cur,fd);
    if(fn == NULL){
      f->eax = -1;
      return;
    }
    f->eax = file_read(fn->f,buffer,size);
  }
}

struct file_node *GetFile(struct thread *t, int fd){
  struct list_elem *e;
  for(e = list_begin(&t->file_list);e!=list_end(&t->file_list);e=list_next(e)){
    struct file_node *fn = list_entry(e,struct file_node, elem);
    if (fn->fd==fd){
      return fn;
    }
  }
  return NULL;
}

void my_write(struct intr_frame *f){
  int *esp = (int *)f->esp;
  if(!is_user_vaddr(((int *)f->esp)+7)){
    thread_current()->exit_code = -1;
    thread_exit();
  }
  int fd = *(esp+2);
  char *buffer = (char*)*(esp+6);
  unsigned size = *(esp+3);
  if (fd == STDIN_FILENO){
    putbuf(buffer,size);
    f->eax=0;
  }
  else{
    struct thread *cur = thread_current();
    struct file_node *fn = GetFile(cur,fd);
    if(fn==NULL){
      f->eax=0;
      return;
    }
    f->eax = file_write(fn->f,buffer,size);
  }
}

void my_seed(struct intr_frame *f){
  if(!is_user_vaddr(((int *)f->esp)+6)){
    thread_current()->exit_code = -1;
    thread_exit();
  }
  int fd = *((int*)f->esp+4);
  unsigned int pos=*((unsigned int *)f->esp+5);
  struct file_node *fl = GetFile(thread_current(),fd);
  file_seek(fl->f,pos);
}

void my_tell(struct intr_frame *f){
  if(!is_user_vaddr(((int *)f->esp)+2)){
    thread_current()->exit_code = -1;
    thread_exit();
  }
  int fd = *((int*)f->esp+1);
  struct file_node *fl = GetFile(thread_current(),fd);
  if(fl==NULL||fl->f == NULL){
    f->eax = -1;
    return;
  }
  f->eax = file_tell(fl->f);
}

void my_close(struct intr_frame *f){
  if(!is_user_vaddr(((int *)f->esp)+2)){
    thread_current()->exit_code = -1;
    thread_exit();
  }
  struct thread *cur = thread_current();
  int fd=*((int*)f->esp+1);
  f->eax = CloseFile(cur,fd,false);
}

int CloseFile(struct thread *t,int fd, int bAll){
  struct list_elem *e, *p;
  if(bAll){
    while(!list_empty(&t->file_list)){
      struct file_node *fn = list_entry(list_pop_front(&t->file_list),struct file_node, elem);
      file_close(fn->f);
      free(fn);
    }
    t->FileNum=0;
    return 0;
  }
  for(e=list_begin(&t->file_list);e!=list_end(&t->file_list);){
    struct file_node *fn = list_entry(e, struct file_node, elem);
    if(fn->fd==fd){
      list_remove(e);
      if(fd==t->maxfd){
        t->maxfd--;
      }
      t->FileNum--;
      file_close(fn->f);
      free(fn);
      return 0;
    }
  }
}
