#include "vm/page.h"
#include "threads/thread.h"





/*find the corresponding spt with the given upage*/
struct list_elem *find_page (void *upage){
  struct thread* cur=thread_current();
  struct spt_elem* a;
  struct list_elem *e;
  for (e = list_begin (&cur->spt); e != list_end (&cur->spt);e = list_next (e)){
    a = (struct spt_elem *)list_entry (e, struct spt_elem, elem);
    if(upage==a->upage){
      return e;
    }
  }
  return 0;
}
