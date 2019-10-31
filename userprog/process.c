#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"




static thread_func start_process NO_RETURN;
static bool load (const char *cmd_line, void (**eip) (void), void **esp);


// process_entry is either a parent process which is waiting for its child process to exit
// or a child process which is already dead
struct process_entry {
    struct list_elem elem;
    int pid;
    struct semaphore sema;
    int child_pid;
    int parent_pid;
    bool status;
    const char *file_name;                    
    struct wait_status *wait_status;                          
    struct dir *cwd;                    
};


// waiting_list is the list used in wait and exit, parent process waits for its child
static struct list waiting_list;
// dead_list is the list storing exited child process, as we need to fetch the child's status in wait()
static struct list dead_list;

// init waiting_list and dead_list
void waiting_dead_init(void)
{
  list_init(&waiting_list);
  list_init(&dead_list);
}




/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */




tid_t
process_execute (const char *file_name)
{
  
  char *fn_copy;
  tid_t tid;
  char *save_ptr;

  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  // get the programme name from the command line input
  char *prog_name = malloc (sizeof(char)*(strlen(fn_copy)+1));
  strlcpy (prog_name, fn_copy, PGSIZE);
  // strtok_r instead of strtok
  prog_name = strtok_r(prog_name, " ", &save_ptr);


  // assign three agrs to be exexuted in start_process
  struct semaphore sema;
  // sema is for synchronization.  the parent process cannot return from the exec 
  // until it knows whether the child process successfully loaded its executable
  sema_init (&sema, 0);
  // new_tid is the tid of the new thread, return value
  int new_tid = 0;
  void *args[3];

  struct process_entry exec;
  exec.file_name = file_name;
  sema_init (&exec.sema, 0);
  exec.cwd = thread_current ()->cwd;
  args[0] = fn_copy;
  args[1] = &exec;
  args[2] = &new_tid;

  // create a new thread to execute this program
  tid = thread_create (prog_name, PRI_DEFAULT, start_process, args);
  if (tid == TID_ERROR){
    palloc_free_page (fn_copy);
    free(prog_name);
    return tid;
  }
  // if successfully created this new thread, assign necessart attributes to it
  struct thread *curr = thread_current();
  // occpuy the resources now
  sema_down (&exec.sema);
  if (exec.status == false) {
    return TID_ERROR;
  }
  list_push_back(&curr->children, &exec.wait_status->elem);

  return tid;
}

/* A thread function that loads a user process and starts it
   running. */

static void
start_process (void *args)
{
  // extract the three args
  char *file_name = ((char **)args)[0];
  struct process_entry *exec = ((struct process_entry **)args)[1];
  int *new_tid = ((int **)args)[2];

  struct intr_frame if_;
  bool success;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (exec->file_name, &if_.eip, &if_.esp);

  struct thread *curr = thread_current();
  if (success) {
    curr->wait_status = malloc (sizeof *exec->wait_status);
    exec->wait_status = curr->wait_status;
    struct wait_status *wait = exec->wait_status;
    lock_init (&wait->lock);
    wait->ref_cnt = 2;
    wait->tid = curr->tid;
    wait->status = -1;
    sema_init (&wait->dead, 0);
  }


  curr->cwd = (exec->cwd != NULL) ? dir_reopen (exec->cwd) : dir_open_root ();
  exec->status = success;

  /* If load failed, quit. */
  // release the resources
  sema_up (&exec->sema);
  if (!success) {
    *new_tid = -1;
    thread_exit ();
  }
  // if success, get the new thread's id -- runnning thread
  *new_tid = thread_tid ();
  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting. */
int
process_wait (tid_t child_tid)
{
  // get the thread with child_tid from all_list
  struct thread *t = thread_get (child_tid);
  // if there is no alive thread with child_tid, look up the dead list to find
  if (t != NULL)
    {
      // if current thread is not the child process's parent, it's invalid, return -1
      if (t->parent_tid != thread_tid()) {
        // return -1;
      }

      // push the parent process to the waiting list
      struct process_entry *parent = malloc(sizeof(struct process_entry));
      parent->pid = thread_tid();
      sema_init(&parent->sema, 0);
      parent->child_pid = child_tid;
      // parent_tid and status doesn't matter
      parent->parent_pid = -1;
      parent->status = -1;
      list_push_back(&waiting_list, &parent->elem);
      // waiting until its child exits and sema_up
      // sema_down(&parent->sema);
    }


    // the child process has now been executed ot not found in all_list
    // look up dead_list to find the child, if found, return its status
    struct list *l = &(thread_current ()->children);
    for (struct list_elem *e = list_begin (l); e != list_end (l); e = list_next (e)) {
        struct wait_status *child = list_entry (e, struct wait_status, elem);
        if (child->tid == child_tid) 
          {
            // we do not this thread 
            list_remove (e);
            sema_down (&child->dead);
            return child->status;
          }
      }

    return -1;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  
  // generate a child process to push into the dead list(exited and release its sources)
  struct process_entry *child = malloc(sizeof(struct process_entry));
  child->pid = cur->tid;
  // child->sema child_pid don't matter
  sema_init(&child->sema, 0);
  child->child_pid = -1;
  child->parent_pid = cur->parent_tid;
  // child->status = status;
  // child process has already finished, keep it's status for fetching in wait()
  list_push_back(&dead_list, &child->elem);


  // now release the resource and let its parent run
  for (struct list_elem *e = list_begin (&waiting_list); e != list_end (&waiting_list); e = list_next (e)) {
    struct process_entry * parent = list_entry(e, struct process_entry, elem);
    // if found the exited child process's parent
    if (parent->child_pid == thread_tid())
      {
        // let parent process run
        // sema_up (&(parent->sema));
        list_remove(e);
        break;
      }
  }
  
  // release the resources: close all the files it opened
    struct list *fd_list = &thread_current()->fd_entry_list;
    struct list_elem *ee = list_begin (&cur->children);
    // for all the entry in its chilren, remove the entry as it has already exited
    while (ee != list_end (&cur->children)) {
      list_remove (ee);
      ee = list_next (ee);
    }

  // // close the executable file
  file_close (thread_current ()->executable);


  printf ("%s: exit(%d)\n", cur->name, cur->wait_status->status);
  sema_up (&(cur->wait_status->dead));

  uint32_t *pd;

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL)
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp, char **argv, int argc);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp)
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  // create a copy of file_name and operate on it (modifying it)
  char file_name_copy[100];
  strlcpy(file_name_copy, file_name, 100);

  char *argv[100];
  int argc = 1;
  char *save_ptr;
  char *token;

  // get the program's name
  argv[0] = strtok_r(file_name_copy, " ", &save_ptr);
  // get the program's arguments
  while( ( token = strtok_r (NULL, " ", &save_ptr ) ) != NULL ) {
    argv[argc++] = token;
  }
    

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL)
    goto done;
  process_activate ();

  /* Open executable file. */
  file = filesys_open (argv[0]);
  if (file == NULL)
    {
      printf ("load: %s: open failed\n", argv[0]);
      goto done;
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024)
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done;
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++)
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type)
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file))
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }
  /* Set up stack. */
  if (!setup_stack (esp, argv, argc))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

  done:
  /* We arrive here whether the load is successful or not. */
  /*if we load success then we have to deny the write to executables*/
  if (success)
    {
      thread_current()->executable = file;
      file_deny_write(file);
    }
  else
    file_close(file);

  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file)
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0)
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false;
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable))
        {
          palloc_free_page (kpage);
          return false;
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp, char **argv, int argc)
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL)
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        {
          *esp = PHYS_BASE;

          uint32_t * stack[argc];
          /* pass args into stack in reverse order*/
          for (int i = argc-1; i >= 0; i--) {
              /*strlen returns length of string excluding '\0'
               so add one to include it*/
              *esp = *esp - ( strlen (argv[i]) + 1 ) * sizeof (char);
              /*arr[i] stores pointer to the corresponding args*/
              stack[i] = (uint32_t *)*esp;
              /*memcpy starts from lower addr to higher addr
              however stack grows from higher addr to lower higher
              so we first minus the length than use the function */
              memcpy (*esp, argv[i], strlen (argv[i]) + 1);
          }
          // word-aligned
          *esp = *esp - 4;
          *(int *)(*esp) = 0;

          // push args to stack, in reverse order
          for (int i = argc-1; i>=0; i--) {
              *esp -= 4;
              *(uint32_t **)(*esp) = stack[i];
          }

          // store argv
          *esp -= 4;
          *(uint32_t **)(*esp) = (*esp + 4);

          // store argc
          *esp -= 4;
          *(int*)(*esp) = argc;

          // return address 0
          *esp -= 4;
          *(int*)(*esp) = 0;

         }
      else
        palloc_free_page (kpage);
    }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
