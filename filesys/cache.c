#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include "devices/block.h"
#include "devices/timer.h"
#include "threads/thread.h"
// #include "threads/synch.h"
#include "threads/malloc.h"
#include "filesys/filesys.h"
#include "filesys/cache.h"

// #define 64 64
// #define CACHE_WRITE_INTV (1 * TIMER_FREQ)


// static struct list ahead_queue;
// static struct lock ahead_lock;
// static struct condition ahead_cond;

// struct ahead_entry {
//     block_sector_t sector;
//     struct list_elem elem;
// };


static struct cache_entry buffer_cache[64];

static struct lock cache_lock;

// struct cache_entry *find_cache_by_sector(block_sector_t sector);
// struct cache_entry *LRU(void);
// static void cache_write_behind(void *aux UNUSED);
// static void cache_read_ahead(void *aux UNUSED);

void cache_init(void){
  lock_init(&cache_lock);
  int i = 0;
  struct cache_entry *a = &buffer_cache[i];
  while (i < 64){
    a = &buffer_cache[i];
    lock_init(&a->cache_entry_lock);
    a->dirty = false;
    a->be_used = 0;
    a->lru = 0;
    i = i + 1;
  }
    // list_init(&ahead_queue);
    // lock_init(&ahead_lock);
    // cond_init(&ahead_cond);
    // thread_create("write_behind", PRI_DEFAULT, cache_write_behind, NULL);
    // thread_create("read_ahead", PRI_DEFAULT, cache_read_ahead, NULL);
}

// void cache_refresh(void){
//   int i = 0;
//   struct cache_entry *a = &buffer_cache[i];
//   while (i < 64){
//     a = &buffer_cache[i];
//     lock_acquire(&a->cache_entry_lock);
//     if (a->be_used == 1){
//       if (!a->dirty){
//         lock_release(&a->cache_entry_lock);
//       }
//       else{
//         a->dirty = false;
//         block_write(fs_device, a->sector_number, a->buffer);
//         lock_release(&a->cache_entry_lock);
//       }
//     }
//     else{
//       lock_release(&a->cache_entry_lock);
//     }
//     i = i + 1;
//   }




    // for (i = 0; i < 64; ++ i) {
    //     struct cache_entry *ce = cache + i;
    //     lock_acquire(&ce->cache_entry_lock);
    //     if (ce->be_used && ce->dirty) {
    //         block_write(fs_device, ce->sector_number, ce->buffer);
    //         ce->dirty = false;
    //     }
    //     lock_release(&ce->cache_entry_lock);
    // }
// }

struct cache_entry *find_cache_by_sector(block_sector_t sector){
  int i = 0;
  struct cache_entry *a = &buffer_cache[i];
  while (i < 64){
    a = &buffer_cache[i];
    lock_acquire(&a->cache_entry_lock);
    if (a->sector_number == sector){
      if (a->be_used == 1){
        return a;
      }
    }
    lock_release(&a->cache_entry_lock);
    i = i + 1;
  }
  return NULL;
    // size_t i;
    // for (i = 0; i < 64; ++ i) {
    //     struct cache_entry *ce = cache + i;
    //     lock_acquire(&ce->cache_entry_lock);
    //     if (ce->be_used && ce->sector_number == sector) {
    //         return ce;
    //     }
    //     lock_release(&ce->cache_entry_lock);
    // }
    // return NULL;
}

struct cache_entry *LRU(void){
  // int i = 0;
  // struct cache_entry *a = &buffer_cache[i];
  // while (i < 64) {
  //   a = &buffer_cache[i];
  //   if(lock_try_acquire(&a->cache_entry_lock)){
  //     if(a->be_used == 0){
  //       a->be_used = 1;
  //       return a;
  //     }
  //     else{
  //       if(a->dirty){
  //         a->dirty = false;
  //         block_write(fs_device, a->sector_number, a->buffer);
  //       }
  //       return a;
  //     }
  //   }
  //   else{
  //     if(i == 63){
  //       i = 0;
  //     }
  //     else{
  //       i = i + 1;
  //     }
  //     continue;
  //   }
  // }


  //   if (!succ) {
  //       hand = (hand + 1) % 64;
  //       continue;
  //   }
  //   if (!ce->be_used) {
  //       ce->be_used = 1;
  //       return ce;
  //   }
  //   // if (ce->accessed) {
  //   //     ce->accessed = false;
  //   // }
  //   else {
  //       // evict him! lol
  //       if (ce->dirty) {
  //           block_write(fs_device, ce->sector_number, ce->buffer);
  //           ce->dirty = false;
  //       }
  //       return ce;
  //   }
  //   lock_release(&ce->cache_entry_lock);
  //   hand = (hand + 1) % 64;
  // }
  // NOT_REACHED();



    int min = 0;
    int i = 0;
    struct cache_entry *temp;
    while (i < 64){
      struct cache_entry *a = &buffer_cache[i];
      bool succ = lock_try_acquire(&a->cache_entry_lock);
      if (!succ) {
        i = i + 1;
        continue;
      }
      if (!a->be_used){
        a->be_used = 1;
        return a;
      }
      else{
        if (a->lru > min){
          min = a->lru;
          temp = a;
        }
      }
      lock_release(&a->cache_entry_lock);
      i = i + 1;
    }
    lock_acquire(&temp->cache_entry_lock);
    if (temp->dirty){
      block_write(fs_device, temp->sector_number, temp->buffer);
      temp->dirty = false;
      temp->lru = 0;
      temp->be_used = 1;
    }
    return temp;

}

// void cache_read(block_sector_t sector, void *buffer) {
//     cache_read_at(sector, buffer, BLOCK_SECTOR_SIZE, 0);
// }

void cache_read_at(block_sector_t sector, void *buffer,off_t size, off_t offset){
    lock_acquire(&cache_lock);
    int i;
    struct cache_entry *a = find_cache_by_sector(sector);
    if (!a) {
        // miss!
        a = LRU();
        a->sector_number = sector;
        for (i = 0; i < 64; ++ i) {
            struct cache_entry *c = &buffer_cache[i];
            if (c != a && c->be_used == 1) {
                lock_acquire(&c->cache_entry_lock);
                c->lru = c->lru + 1;
                lock_release(&c->cache_entry_lock);
            }
        }
        lock_release(&cache_lock);
        // ASSERT(a);
        block_read(fs_device, sector, a->buffer);
        memcpy(buffer, a->buffer + offset, (size_t) size);
        lock_release(&a->cache_entry_lock);
    } else {
      for (i = 0; i < 64; ++ i) {
          struct cache_entry *c = &buffer_cache[i];
          if (c != a && c->be_used == 1) {
            lock_acquire(&c->cache_entry_lock);
            c->lru = c->lru + 1;
            lock_release(&c->cache_entry_lock);
          }
          else{
            c->lru = 0;
          }
      }
      lock_release(&cache_lock);
      memcpy(buffer, a->buffer + offset, (size_t) size);
      lock_release(&a->cache_entry_lock);
    }
    // ce->accessed = true;

}

// void cache_write(block_sector_t sector, const void *buffer) {
//     cache_write_at(sector, buffer, BLOCK_SECTOR_SIZE, 0);
// }

void cache_write_at(block_sector_t sector, const void *buffer,off_t size, off_t offset) {
    // ASSERT(buffer);
    lock_acquire(&cache_lock);
    int i;
    struct cache_entry *a = find_cache_by_sector(sector);
    if (!a) {
        // miss!
        a = LRU();
        a->sector_number = sector;
        a->dirty = true;
        for (i = 0; i < 64; ++ i) {
            struct cache_entry *c = &buffer_cache[i];
            if (c != a && c->be_used == 1) {
                lock_acquire(&c->cache_entry_lock);
                c->lru = c->lru + 1;
                lock_release(&c->cache_entry_lock);
            }
        }
        lock_release(&cache_lock);
        // ASSERT(a);
        // if (size != BLOCK_SECTOR_SIZE)
        block_read(fs_device, sector, a->buffer);
        memcpy(a->buffer + offset, buffer, (size_t) size);
        lock_release(&a->cache_entry_lock);
    } else {
      a->dirty = true;
      for (i = 0; i < 64; ++ i) {
          struct cache_entry *c = &buffer_cache[i];
          if (c != a && c->be_used == 1) {
            lock_acquire(&c->cache_entry_lock);
            c->lru = c->lru + 1;
            lock_release(&c->cache_entry_lock);
          }
          else{
            c->lru = 0;
          }
      }
      lock_release(&cache_lock);
      memcpy(a->buffer + offset, buffer, (size_t) size);
      lock_release(&a->cache_entry_lock);
    }
    // ce->accessed = true;

}

// static void cache_write_behind(void *aux UNUSED) {
//     while (true) {
//         timer_sleep(CACHE_WRITE_INTV);
//         cache_refresh();
//     }
//     NOT_REACHED();
// }

// static void cache_read_ahead(void *aux UNUSED) {
//     while (true) {
//         lock_acquire(&ahead_lock);
//         while (list_empty(&ahead_queue))
//             cond_wait(&ahead_cond, &ahead_lock);
//         struct ahead_entry *ae = list_entry(list_pop_front(&ahead_queue),
//                 struct ahead_entry, elem);
//         lock_release(&ahead_lock);
//         block_sector_t sector = ae->sector;
//         free(ae);
//         cache_read(sector, NULL);
//     }
//     NOT_REACHED();
// }
//
// void cache_read_ahead_put(block_sector_t sector) {
//     lock_acquire(&ahead_lock);
//     struct ahead_entry *ae = malloc(sizeof(struct ahead_entry));
//     ae->sector = sector;
//     list_push_back(&ahead_queue, &ae->elem);
//     cond_signal(&ahead_cond, &ahead_lock);
//     lock_release(&ahead_lock);
// }
