#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "threads/thread.h"
#include <list.h>


/*a new structure to realize frame table*/
struct frame{
  void* paddr;                                          /*physical address*/
  void* upage;                                          /*virtual address*/
  struct thread* holder;                                /*the thread that holds the frame*/
  struct list_elem elem;                                /*list element*/
};

struct list frame_table;                                /*frame table*/

void frame_table_init(void);
void* frame_get_page (void* upage);
void frame_free_page (void *);
struct frame *find_frame (void *kpage);


#endif /* vm/frame.h */
