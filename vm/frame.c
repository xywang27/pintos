#include "vm/frame.h"
#include "vm/page.h"

#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/synch.h"


 /*initialize the frame table*/
void frame_table_init(void){
  list_init (&frame_table);
  lock_init(&frame_lock);
}

/* a little change from palloc get page */
void* frame_get_page(void* upage){
  lock_acquire (&frame_lock);
  void *kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  struct frame* frame = (struct frame *) malloc (sizeof(struct frame));
  if(frame == NULL){
    palloc_free_page(kpage);
    return NULL;
  }
  frame->paddr=kpage;
  frame->upage=upage;
  frame->holder=thread_current();
  list_push_back(&frame_table, &frame->elem);                                    /*push the frame into frame table*/
  lock_release (&frame_lock);
  return kpage;
}

/* a litle change from palloc free page */
void frame_free_page (void *kpage){
  struct frame* frame = find_frame(kpage);                                       /*find the corresponding frame*/
  palloc_free_page(kpage);
  list_remove (&frame->elem);                                                    /*remove the frame from frame table*/
}

/* find the frame with given kpage*/
struct frame *find_frame (void *kpage){
  struct frame* frame;
  struct list_elem *e;
  for(e=list_begin(&frame_table); e!=list_end(&frame_table); e=list_next(e)){
    frame = list_entry(e, struct frame, elem);
    if(frame->paddr == kpage){
      return frame;
    }
  }
  return 0;
}
