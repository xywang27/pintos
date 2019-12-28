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
}

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
}

struct cache_entry *LRU(void){
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
}

void cache_write_at(block_sector_t sector, const void *buffer,off_t size, off_t offset) {
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
}
