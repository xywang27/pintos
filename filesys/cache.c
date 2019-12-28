#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include "devices/block.h"
#include "devices/timer.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "filesys/filesys.h"
#include "filesys/cache.h"


static struct cache_entry buffer_cache[64];                        /*the buffer_cache containing cache_entry*/


/*initialize the buffer cache*/
void cache_init(void){
  lock_init(&cache_lock);                                          /*initialize the buffer cache lock*/
  int i = 0;
  struct cache_entry *a = &buffer_cache[i];
  while (i < 64){
    a = &buffer_cache[i];
    lock_init(&a->cache_entry_lock);                               /*initialize the buffer cache entry lock*/
    a->dirty = false;                                              /*dirty is false*/
    a->be_used = 0;                                                /*not used now*/
    a->lru = 0;                                                    /*lru = 0*/
    i = i + 1;
  }
}


/*find the corresponding buffer cache entry in the buffer cache according to the given sector number*/
struct cache_entry *find_cache_by_sector(block_sector_t sector){
  int i = 0;
  struct cache_entry *a = &buffer_cache[i];
  while (i < 64){                                                 /*traverse the whole buffer cache*/
    a = &buffer_cache[i];
    lock_acquire(&a->cache_entry_lock);                           /*get the buffer cache lock*/
    if (a->sector_number == sector){                              /*if find*/
      if (a->be_used == 1){                                       /*if this found buffer cache_entry is actually used before*/
        return a;                                                 /*find!*/
      }
    }
    lock_release(&a->cache_entry_lock);                           /*release the lock*/
    i = i + 1;
  }
  return NULL;                                                    /*not find!*/
}


/*the LRU replacement policy*/
struct cache_entry *LRU(void){
  int max = 0;                                                      /*the max lru value*/
  int i = 0;
  struct cache_entry *temp;
  while (i < 64){
    struct cache_entry *a = &buffer_cache[i];
    lock_acquire(&a->cache_entry_lock);                             /*get the buffer cache lock*/
    if (!a->be_used){                                               /*if this buffer cache_entry is not used before, choose it*/
      a->be_used = 1;                                               /*set be_used to 1*/
      return a;
    }
    else{
      if (a->lru > max){                                            /*if this buffer cache_entry is used before, compare it lru value*/
        max = a->lru;                                               /*set max to the bigger value in a->lru and previous max*/
        temp = a;
      }
    }
    lock_release(&a->cache_entry_lock);                             /*release the lock*/
    i = i + 1;
  }
  lock_acquire(&temp->cache_entry_lock);                            /*get the lock of the cache_buffer_entry with the biggest lru value*/
  if (temp->dirty){                                                 /*if it is dirty*/
    block_write(fs_device, temp->sector_number, temp->buffer);      /*write back before evict*/
    temp->dirty = false;                                            /*set dirty to false*/
    temp->lru = 0;                                                  /*set lru to 0*/
    temp->be_used = 1;                                              /*set be_used to 1*/
  }
  return temp;
}


/*read data from buffer cache*/
void cache_read_at(block_sector_t sector, void *buffer,off_t size, off_t offset){
  lock_acquire(&cache_lock);                                         /*get the lock of the buffer cache*/
  int i;
  struct cache_entry *a = find_cache_by_sector(sector);              /*first find if it is cache hit*/
  if (a == NULL){                                                    /*cache miss!*/
    a = LRU();                                                       /*find the cache_entry to evict*/
    a->sector_number = sector;                                       /*set sector number*/
    for (i = 0; i < 64; ++ i){                                       /*iterate to update the lru value*/
      struct cache_entry *c = &buffer_cache[i];
      if (c != a && c->be_used == 1) {                               /*only update the lru value of the used cache buffer entry*/
          lock_acquire(&c->cache_entry_lock);
          c->lru = c->lru + 1;                                       /*add one*/
          lock_release(&c->cache_entry_lock);
      }
    }
    lock_release(&cache_lock);                                      /*release the lock of the buffer cache*/
    block_read(fs_device, sector, a->buffer);                       /*read the data from disk into the cache buffer*/
    memcpy(buffer, a->buffer + offset, size);                       /*copy data to buffer from buffer cache*/
    lock_release(&a->cache_entry_lock);                             /*release the lock of the buffer cache entry*/
  }
  else{                                                             /*cache hit*/
    for (i = 0; i < 64; ++ i){                                      /*iterate to update the lru value*/
      struct cache_entry *c = &buffer_cache[i];
      if (c != a && c->be_used == 1){                               /*only update the lru value of the used cache buffer entry*/
        lock_acquire(&c->cache_entry_lock);
        c->lru = c->lru + 1;                                        /*add one*/
        lock_release(&c->cache_entry_lock);
      }
      else{
        c->lru = 0;
      }
    }
    lock_release(&cache_lock);                                      /*release the buffer cache lock*/
    memcpy(buffer, a->buffer + offset, size);                       /*copy data to buffer from buffer cache*/
    lock_release(&a->cache_entry_lock);                             /*release the lock of the buffer cache entry*/
  }
}


/*write data from buffer cache to disk*/
void cache_write_at(block_sector_t sector, const void *buffer,off_t size, off_t offset){
  lock_acquire(&cache_lock);                                      /*get the lock of the buffer cache*/
  int i;
  struct cache_entry *a = find_cache_by_sector(sector);           /*first find if it is cache hit*/
  if (a == NULL){                                                 /*cache miss!*/
    a = LRU();                                                    /*find the cache_entry to evict*/
    a->sector_number = sector;                                    /*set sector number*/
    a->dirty = true;                                              /*set dirty to true*/
    for (i = 0; i < 64; ++ i) {                                   /*iterate to update the lru value*/
        struct cache_entry *c = &buffer_cache[i];
        if (c != a && c->be_used == 1) {                          /*only update the lru value of the used cache buffer entry*/
            lock_acquire(&c->cache_entry_lock);
            c->lru = c->lru + 1;                                  /*add one*/
            lock_release(&c->cache_entry_lock);
        }
    }
    lock_release(&cache_lock);                                    /*release the lock of the buffer cache*/
    block_read(fs_device, sector, a->buffer);                     /*read the data from disk into the cache buffer*/
    memcpy(a->buffer + offset, buffer, size);                     /*copy data from buffer to buffer cache*/
    lock_release(&a->cache_entry_lock);                           /*release the lock of the buffer cache entry*/
  }
  else{                                                           /*cache hit*/
    a->dirty = true;                                              /*set dirty to true*/
    for (i = 0; i < 64; ++ i){                                    /*iterate to update the lru value*/
      struct cache_entry *c = &buffer_cache[i];
      if (c != a && c->be_used == 1) {                            /*only update the lru value of the used cache buffer entry*/
        lock_acquire(&c->cache_entry_lock);
        c->lru = c->lru + 1;                                      /*add one*/
        lock_release(&c->cache_entry_lock);
      }
      else{
        c->lru = 0;
      }
    }
    lock_release(&cache_lock);                                    /*release the buffer cache lock*/
    memcpy(a->buffer + offset, buffer, size);                     /*copy data from buffer to buffer cache*/
    lock_release(&a->cache_entry_lock);                           /*release the lock of the buffer cache entry*/
  }
}
