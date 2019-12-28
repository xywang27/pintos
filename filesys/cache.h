#ifndef FILESYS_CACHE_H
#define FILESYS_CACHE_H


#include "devices/block.h"
#include "threads/synch.h"


/*buffer cache entry*/
struct cache_entry {
  uint8_t buffer[BLOCK_SECTOR_SIZE];  /*the data of the each buffer cache entry*/
  struct lock cache_entry_lock;       /*buffer cache entry lock*/
  bool dirty;                         /*dirty bit of the buffer cache entry*/
  int be_used;                        /*if the buffer cache entry is empty:0, otherwise, 1*/
  int lru;                            /*used in lru replacement policy*/
  block_sector_t sector_number;       /*the sector number of the cache_entry*/
};

struct lock cache_lock;               /*the lock for the buffer_cache*/

void cache_init(void);
struct cache_entry *find_cache_by_sector(block_sector_t sector);
struct cache_entry *LRU(void);
void cache_read_at(block_sector_t sector, void *buffer, off_t size, off_t offset);
void cache_write_at(block_sector_t sector, const void *buffer, off_t size, off_t offset);

#endif /* filesys/cache.h */
