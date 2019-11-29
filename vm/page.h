#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <list.h>
#include "filesys/file.h"
#include "vm/frame.h"
#include "vm/swap.h"

/* a new struct to realize spt */
struct spt_elem{
  struct thread* owner;                                       /*the thread who holds this spt_elem*/
  uint8_t *upage;                                              /*the upage the spt stands for*/

  struct file *fileptr;                                           /*in order to track the file*/
  off_t ofs;
  uint32_t read_bytes;
  uint32_t zero_bytes;
  bool writable;                                               /*if it if writable*/
  // void *kpage;

  bool needclose;
  bool needremove;
  int mapid;


  /* a swap slot */

  /* a list elem */
  struct list_elem elem;
};

/* L: look up the spt to find a entry or return null */
struct list_elem *page_find (void *upage);
#endif /* vm/page.h */
