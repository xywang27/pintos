#include "threads/thread.h"
#include "vm/page.h"



/*find the corresponding spt with the given upage*/
struct list_elem *find_page (void *upage){
  struct thread* cur=thread_current();
  struct spt_elem* a;
  struct list_elem *e;
  for (e = list_begin (&cur->spt); e != list_end (&cur->spt);e = list_next (e)){    /*traverse the spt list*/
    a = (struct spt_elem *)list_entry (e, struct spt_elem, elem);
    if(upage==a->upage){
      return e;
    }
  }
  return 0;
}

//find the spt_elem with the given mapping
struct list_elem *find_mapid (mapid_t mapping){
  struct thread* cur=thread_current();
  struct spt_elem* a;
  struct list_elem *e;
  for (e = list_begin (&cur->spt); e != list_end (&cur->spt);e = list_next (e)){    /*traverse the spt list*/
    a = (struct spt_elem *)list_entry (e, struct spt_elem, elem);
    if(a->mapid == mapping){
      return e;
    }
  }
  return 0;
}

int wait_to_remove(char *file_name){
  struct list_elem *e;
  struct spt_elem *a;
  for(e = list_begin(&thread_current()->spt);e != list_end(&thread_current()->spt); e = list_next(e)){
    a = (struct spt_elem *)list_entry (e, struct spt_elem, elem);
    if(a->file==file_name){
      a->remove = true;
      return 1;
    }
  }
  return 0;
}
