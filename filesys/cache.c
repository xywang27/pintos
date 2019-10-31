#include "filesys/cache.h"
#include "filesys/inode.h"

extern struct cache_entry *cache_buffer[];

void
cache_init (void)
{
  lock_init (&cache_lock);
  clock_hand = -1;
}

void
cache_write_to_disk (void)
{
  lock_acquire (&cache_lock);
  for(int i = 0; i < 64; i++)
  {
    struct cache_entry *Cache = cache_buffer[i];
    if (Cache)
    {
      sema_down (&Cache->sector_lock);
      if (Cache->valid == true && Cache->dirty == true)
        block_write (fs_device, Cache->sector, Cache->block);
      Cache->dirty = false;
      sema_up (&Cache->sector_lock);
    }
  }
  lock_release (&cache_lock);
}

void
cache_clean (void)
{
  lock_acquire (&cache_lock);
  for(int i = 0; i < 64; i++)
  {
    struct cache_entry * Cache = cache_buffer[i];
    if(Cache)
    {
      sema_down(&Cache->sector_lock);
      if (Cache->valid == true && Cache->dirty == true)
        block_write (fs_device, Cache->sector, Cache->block);
      free (Cache->block);
      free (Cache);
      cache_buffer[i] = NULL;
    }
  }
  lock_release (&cache_lock);
  clock_hand = 0;
}

int
cache_next_to_remove (void)
{
  for( ; ;clock_hand++)
  {
    clock_hand %= 64;
    if (cache_buffer[clock_hand])
    {
      if (cache_buffer[clock_hand]->sector_lock.value)
      {
        if (cache_buffer[clock_hand]->reference)
        {
          cache_buffer[clock_hand]->reference = 0;
        }
        else
        {
          break;
        }
      }
      continue;
    }
    return clock_hand;
  }
}

void
cache_get_sector (block_sector_t sector, void *buffer)
{
  lock_acquire (&cache_lock);
  int i = 0;
  while (i < 64)
  {
    struct cache_entry *Cache = cache_buffer[i];
    if (Cache)
    {
      if (Cache->sector == sector)
      {
        sema_down (&Cache->sector_lock);
        Cache->reference = 1;
        memcpy (buffer, Cache->block, BLOCK_SECTOR_SIZE);
        sema_up (&Cache->sector_lock);
        lock_release (&cache_lock);
        return;
      }
    }
    i++;
  }

  int index = cache_next_to_remove ();
  if (cache_buffer[index])
  {
    sema_down (&cache_buffer[index]->sector_lock);
    if (cache_buffer[index]->dirty == true)
    {
      block_write (fs_device, cache_buffer[index]->sector, cache_buffer[index]->block);
    }
  }
  else
  {
    cache_buffer[index] = malloc (sizeof(struct cache_entry));
    cache_buffer[index]->block = malloc (BLOCK_SECTOR_SIZE);
    sema_init (&cache_buffer[index]->sector_lock, 0);
  }
  cache_buffer[index]->dirty = 0;
  cache_buffer[index]->valid = 1;
  cache_buffer[index]->reference = 1;
  cache_buffer[index]->sector = sector;
  block_read (fs_device, sector, cache_buffer[index]->block);
  sema_up (&cache_buffer[index]->sector_lock);
  memcpy (buffer, cache_buffer[index]->block, BLOCK_SECTOR_SIZE);
  lock_release (&cache_lock);
  return;
}

void
cache_write_to_sector (block_sector_t sector, void *buffer)
{
  lock_acquire (&cache_lock);
  int i = 0;
  while (i < 64)
    {
      struct cache_entry *Cache = cache_buffer[i];
      if (Cache)
      {
        if (Cache->sector == sector)
        {
          sema_down (&Cache->sector_lock);
          Cache->reference = 1;
          lock_release (&cache_lock);
          memcpy (Cache->block, buffer, BLOCK_SECTOR_SIZE);
          Cache->dirty = 1;
          sema_up (&Cache->sector_lock);
          return;
        }
      }
      i++;
    }
  int index = cache_next_to_remove ();
  if (cache_buffer[index])
    {
      sema_down (&cache_buffer[index]->sector_lock);
      lock_release (&cache_lock);
      if (cache_buffer[index]->dirty)
      {
        block_write (fs_device, cache_buffer[index]->sector, cache_buffer[index]->block);
      }
    }
  else
    {
      cache_buffer[index] = malloc (sizeof(struct cache_entry));
      cache_buffer[index]->block = malloc (BLOCK_SECTOR_SIZE);
      sema_init (&cache_buffer[index]->sector_lock, 0);
      lock_release (&cache_lock);
    }
  cache_buffer[index]->dirty = 1;
  cache_buffer[index]->valid = 1;
  cache_buffer[index]->reference = 1;
  cache_buffer[index]->sector = sector;
  memcpy (cache_buffer[index]->block, buffer, BLOCK_SECTOR_SIZE);
  sema_up (&cache_buffer[index]->sector_lock);
}