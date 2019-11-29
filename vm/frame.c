#include "vm/frame.h"
#include "vm/page.h"

#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/synch.h"

struct lock frame_lock;

 /*initialize the frame table*/
void frame_table_init(void){
  list_init (&frame_table);
  lock_init(&frame_lock);
}

/* L:this func is just like a normal palloc */
void* frame_get_page(void* upage){
  /* L;sync */
  lock_acquire(&frame_lock);
  void *kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  struct frame* f = (struct frame *) malloc (sizeof(struct frame));
  if(!f){
    palloc_free_page(kpage);
    return NULL;
  }
  f->paddr=kpage;
  f->upage=upage;
  f->holder=thread_current();
  list_push_front(&frame_table, &f->elem);

  lock_release (&frame_lock);
  return kpage;
}
/* L:free a frame.
   frame table entry & page must both be freed. */
void frame_free_page (void *kpage){
  struct frame* f;
  lock_acquire(&frame_lock);
  struct list_elem *e = find_frame (kpage);
  palloc_free_page(kpage);
  f = list_entry(e, struct frame, elem);
  list_remove (&f->elem);
  lock_release (&frame_lock);
  // ASSERT(0);
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
