#ifndef FILESYS_CACHE_H
#define FILESYS_CACHE_H
#include <stdbool.h>
#include "filesys/off_t.h"
#include "devices/block.h"
#include "lib/kernel/list.h"
#include "threads/synch.h"
#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"

struct cache_entry
  {
    bool dirty;
    bool valid;
    int reference;
    block_sector_t sector; 
    struct semaphore sector_lock;
    void *block; 
  };

int clock_hand; 
struct lock cache_lock; 

void cache_init (void);
void cache_write_to_disk (void);
void cache_clean (void);
void cache_write_to_sector (block_sector_t sector, void *buffer);
void cache_get_sector (block_sector_t sector, void *buffer);

#endif