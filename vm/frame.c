#include "vm/frame.h"
#include "vm/page.h"

#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/synch.h"


 /*initialize the frame table*/
void frame_table_init(void){
  list_init (&frame_table);
}

/* a little change from palloc get page */
void* frame_get_page(void* upage){
  void *kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  struct frame* frame = (struct frame *) malloc (sizeof(struct frame));
  if(frame == NULL){
    palloc_free_page(kpage);
    return NULL;
  }
  frame->paddr=kpage;
  frame->upage=upage;
  frame->holder=thread_current();
  list_push_front(&frame_table, &f->elem);
  return kpage;
}
/* L:free a frame.
   frame table entry & page must both be freed. */
void frame_free_page (void *kpage){
  struct frame* f;
  struct list_elem *e = find_frame (kpage);
  palloc_free_page(kpage);
  f = list_entry(e, struct frame, elem);
  list_remove (&f->elem);
}

struct list_elem *find_frame (void *kpage){
  struct frame* f;
  struct list_elem *e;
  struct list *l = &frame_table;
  for(e=list_begin(l); e!=list_end(l); e=list_next(e)){
    f = list_entry(e, struct frame, elem);
    if(kpage==f->paddr){
      return e;
    }
  }
  return 0;
}
