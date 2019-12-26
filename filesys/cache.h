#ifndef FILESYS_CACHE_H
#define FILESYS_CACHE_H

#include "off_t.h"
#include "devices/block.h"

struct cache_entry {
  uint8_t buffer[BLOCK_SECTOR_SIZE];
  struct lock cache_entry_lock;
  bool dirty;
  int be_used;
  // bool accessed;
  // int lru;
  block_sector_t sector_number;
};

void cache_init(void);
void cache_refresh(void);
struct cache_entry *find_cache_by_sector(block_sector_t sector);
struct cache_entry *clock(void);
void cache_read(block_sector_t sector, void *buffer);
void cache_read_at(block_sector_t sector, void *buffer, off_t size, off_t offset);
void cache_write(block_sector_t sector, const void *buffer);
void cache_write_at(block_sector_t sector, const void *buffer, off_t size, off_t offset);
// void cache_read_ahead_put(block_sector_t sector);

#endif /* filesys/cache.h */
