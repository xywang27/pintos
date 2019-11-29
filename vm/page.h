#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <list.h>
#include "filesys/file.h"
#include "vm/frame.h"
#include "vm/swap.h"

/* a new struct to realize spt */
struct spt_elem{
  struct thread* holder;                                       /*the thread who holds this spt_elem*/
  uint8_t *upage;                                              /*the upage the spt stands for*/

  struct file *file;                                           /*in order to track the file*/
  off_t ofs;                                                   /*offset*/
  uint32_t read_bytes;
  uint32_t zero_bytes;
  bool writable;                                               /*if it is writable*/
  bool needclose;                                              /*record if it needs close after unmapped*/
  bool needremove;                                             /*record if it needs remove after unmapped*/
  int mapid;                                                   /*corresponding map id*/
  struct list_elem elem;                                       /*list element*/
};

struct list_elem *find_page (void *upage);
#endif /* vm/page.h */
