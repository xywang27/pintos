#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <list.h>
#include "vm/frame.h"
#include "filesys/file.h"

typedef int mapid_t;

/* a new struct to realize spt */
struct spt_elem{
  struct thread* holder;                                       /*the thread who holds this spt_elem*/
  uint8_t *upage;                                              /*the upage the spt stands for*/
  struct file *file;                                           /*in order to track the file*/
  off_t ofs;                                                   /*offset*/
  bool writable;                                               /*if it is writable*/
  bool close;                                                  /*record if it needs close after unmapped*/
  bool remove;                                                 /*record if it needs remove after unmapped*/
  int mapid;                                                   /*corresponding map id*/
  size_t read_bytes;
  size_t zero_bytes;
  struct list_elem elem;                                       /*list element*/
};

struct list_elem *find_page (void *upage);

struct list_elem *find_mapid (mapid_t mapping);

#endif /* vm/page.h */
