#include "vm/frame.h"
#include "vm/page.h"

#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/synch.h"

static struct list frame_list;
/* L: try to solve some sync problems */
static struct lock frame_list_lock;


void frame_table_init(void){
  list_init (&frame_list);
  lock_init(&frame_list_lock);
}

/* L:this func is just like a normal palloc */
void* frame_get_page(void* upage){
  /* L;sync */
  lock_acquire(&frame_list_lock);
  void *kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  struct frame* f = (struct frame *) malloc (sizeof(struct frame));
  if(!f){
    palloc_free_page(kpage);
    return NULL;
  }
  f->recent=0;
  f->paddr=kpage;
  f->upage=upage;
  f->owner=thread_current();
  list_push_front(&frame_list, &f->elem);

  lock_release (&frame_list_lock);
  return kpage;
}
/* L:free a frame.
   frame table entry & page must both be freed. */
void frame_free_page (void *kpage){
  struct frame* f;
  lock_acquire(&frame_list_lock);
  struct list_elem *e = find_frame (kpage);
  palloc_free_page(kpage);
  f = list_entry(e, struct frame, elem);
  list_remove (&f->elem);
  lock_release (&frame_list_lock);
  // ASSERT(0);
}

struct list_elem *find_frame (void *kpage){
  struct frame* f;
  struct list_elem *e;
  struct list *l = &frame_list;
  for(e=list_begin(l); e!=list_end(l); e=list_next(e)){
    f = list_entry(e, struct frame, elem);
    if(kpage==f->paddr){
      return e;
    }
  }
  return 0;
}

// struct frame* frame_find (void *kpage){
//   struct list *l = &frame_list;
//   struct list_elem *e;
//   struct frame *f = NULL;
//   lock_acquire(&frame_list_lock);
//   for(e=list_begin(l); e!=list_end(l); e=list_next(e))
//   {
//     f = list_entry(e, struct frame, elem);
//     if(kpage==f->paddr)
//     {
// 	  lock_release (&frame_list_lock);
//       return f;
// 	}
//   }
//   lock_release (&frame_list_lock);
//   return NULL;
// }
//
// bool frame_table_full (void){
//   size_t s=list_size(&frame_list);
//   return s;
// }

//[X]随时间改变recent的值
// void changerec(void)
// {
//   if(full)
//   {
//   struct list_elem *e;
//   struct frame* fp;
//   for (e = list_begin (&frame_list); e != list_end (&frame_list);
// 				e = list_next (e))
//   {
// 	fp=list_entry (e, struct frame, elem);
// 	if(fp->owner->pagedir!=NULL)
// 	{
// 	if(pagedir_is_accessed (fp->owner->pagedir, fp->upage))
// 	{
// 	  pagedir_set_accessed (fp->owner->pagedir, fp->upage, false);
// 	  fp->recent=0;
// 	}
// 	else
// 	   fp->recent++;
//    }
//   }
//   }
// }
//
// //[X]替换算法
// struct frame* LRU(void)
// {
//     struct list_elem *e;
//     struct frame* fp;
//     struct frame* tar;
//     int max=-1;
//     for(e=list_begin(&frame_list);e!=list_end(&frame_list);e=list_next(e))
//     {
// 		fp=list_entry (e, struct frame, elem);
// 		//printf("%d ",fp->recent);
// 		if(max<fp->recent)
// 		{
// 			max=fp->recent;
// 			tar=fp;
// 		}
// 	}
// 	tar->recent=0;
//     return tar;
//     /*
//     e=list_begin(&frame_list);
// 	return list_entry(e,struct frame,elem);
// 	*/
// }
