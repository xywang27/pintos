#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "threads/synch.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

int cache_next_to_remove (void);

bool inode_resize (struct inode_disk *id, off_t size);

block_sector_t inode_get_sector (struct inode *inode, uint32_t sector);

struct cache_entry *cache_buffer[64]; 



/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector (const struct inode *inode, off_t pos)
{
  ASSERT (inode != NULL);
  return inode_get_sector (inode, pos / BLOCK_SECTOR_SIZE);
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;
struct lock *inode_list_lock;

/* Initializes the inode module. */
void
inode_init (void)
{
  list_init (&open_inodes);
  cache_init();
  memset(cache_buffer, NULL, 64*sizeof(struct cache_entry*));
  lock_init (&inode_list_lock);
  
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length, bool is_dir)
{
  struct inode_disk *disk_inode = NULL;
  ASSERT (length >= 0);
  
  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (!disk_inode)
    return false;

  size_t sectors = bytes_to_sectors (length);
  disk_inode->doubly_indirect = 0;
  disk_inode->is_dir = is_dir;
  disk_inode->length = 0;
  disk_inode->magic = INODE_MAGIC;
  memset (disk_inode->start, 0, 100 * sizeof(block_sector_t));
  bool success = inode_resize (disk_inode, length);
  if (success)
  {
    cache_write_to_sector (sector, disk_inode);
    free (disk_inode);
    return true;
  }
  else
  {
    free (disk_inode);
    return false;  
  }
}


block_sector_t
inode_get_sector (struct inode *inode, uint32_t sector)
{
  sema_down (&inode->inode_lock);
  int size = inode->data.length / BLOCK_SECTOR_SIZE;
  if (sector > size)
    {
      sema_up (&inode->inode_lock);
      return -1;
    }
  if (sector < 100)
    {
      sema_up (&inode->inode_lock);
      return inode->data.start[sector];
    }
  block_sector_t buffer[128];
  block_sector_t buffer2[128];

  cache_get_sector (inode->data.doubly_indirect, buffer);
  cache_get_sector (buffer[(uint32_t) (sector - 100) / 128], buffer2);
  sema_up (&inode->inode_lock);
  return buffer2[(sector - 100) % 128];
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  lock_acquire (&inode_list_lock);
  e = list_begin (&open_inodes);
  while (e != list_end (&open_inodes))
    {
      inode = list_entry (e, struct inode, elem);
      sema_down (&inode->inode_lock);
      if (inode->sector == sector)
        {
          inode->open_cnt++;
          lock_release (&inode_list_lock);
          sema_up (&inode->inode_lock);
          return inode;
        }
      sema_up (&inode->inode_lock);
      e = list_next (e);
    }

  /* Allocate memory. */
  inode = malloc (sizeof (struct inode));
  if (inode == NULL)
    {
      lock_release (&inode_list_lock);
      return NULL;
    }

  /* Initialize. */
  sema_init (&inode->inode_lock, 0);
  list_push_front (&open_inodes, &inode->elem);
  lock_release (&inode_list_lock);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  cache_get_sector (inode->sector, &inode->data);
  sema_up (&inode->inode_lock);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    {
      sema_down (&inode->inode_lock);
      inode->open_cnt++;
      sema_up (&inode->inode_lock);
    }
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  sema_down (&inode->inode_lock);
  block_sector_t sector = inode->sector;
  sema_up (&inode->inode_lock);
  return sector;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode)
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  sema_down (&inode->inode_lock);
  if (--inode->open_cnt == 0)
  {
    /* Remove from inode list and release lock. */
    lock_acquire (&inode_list_lock);
    list_remove (&inode->elem);
    lock_release (&inode_list_lock);
    /* Deallocate blocks if removed. */
    if (inode->removed)
      {
        inode_resize (&inode->data, 0);
        free_map_release (inode->sector, 1);
      }
    sema_up (&inode->inode_lock);
    free (inode);
    return;
  }
  sema_up (&inode->inode_lock);
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode)
{
  ASSERT (inode != NULL);
  sema_down (&inode->inode_lock);
  inode->removed = true;
  sema_up (&inode->inode_lock);
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset)
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t *bounce = NULL;

  while (size > 0)
    {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Read full sector directly into caller's buffer. */
          cache_get_sector (sector_idx, (void *) (buffer + bytes_read));
        }
      else
        {
          /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
          if (bounce == NULL)
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }
          cache_get_sector (sector_idx, (void *) bounce);
          memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
        }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
  free (bounce);

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset)
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t *bounce = NULL;
  sema_down (&inode->inode_lock);
  if (inode->deny_write_cnt)
    {
      sema_up (&inode->inode_lock);
      return 0;
    }
  sema_up (&inode->inode_lock);

  if (inode->data.length < offset + size)
    {
      if (inode_resize (&inode->data, offset + size))
        cache_write_to_sector (inode->sector, &inode->data);
      else
        return 0;
    }

  while (size > 0)
    {
      /* Sector to write, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Write full sector directly to disk. */
          cache_write_to_sector (sector_idx, (void *) (buffer + bytes_written));
        }
      else
        {
          /* We need a bounce buffer. */
          if (bounce == NULL)
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }
          /* If the sector contains data before or after the chunk
           we're writing, then we need to read in the sector
           first.  Otherwise we start with a sector of all zeros. */
          if (sector_ofs > 0 || chunk_size < sector_left)
            cache_get_sector(sector_idx, bounce);
          else
            memset (bounce, 0, BLOCK_SECTOR_SIZE);
          memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
          cache_write_to_sector(sector_idx, bounce);
        }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }
  free (bounce);

  return bytes_written;
}


void
inode_truncate_blocks (struct inode_disk *id, off_t size)
{
  int i = 0;
  int pos1 = size % BLOCK_SECTOR_SIZE ? size / BLOCK_SECTOR_SIZE + 1 : size / BLOCK_SECTOR_SIZE;
  while (i < 100 && size <= pos1)
  {
    if (id->start[i])
    {
      free_map_release (id->start[i], 1);
      id->start[i] = 0;
    }
    i++;
  }

  if (id->doubly_indirect)
    {
      block_sector_t doubly[128];
      block_sector_t singly[128];
      cache_get_sector (id->doubly_indirect, doubly);
      int k = 0;
      while (k < 128)
        {
          if (doubly[k])
            {
              cache_get_sector (doubly[k], singly);
              int j = 0;
              while (j < 128)
                {
                  int pos2 = BLOCK_SECTOR_SIZE * 100 + k * BLOCK_SECTOR_SIZE * 128 + j * BLOCK_SECTOR_SIZE;
                  if (size <= pos2 && singly[j] != 0)
                    {
                      free_map_release (singly[j], 1);
                      singly[j] = 0;
                    }
                  j++;
                }
              cache_write_to_sector (doubly[k], singly);
              int pos3 = BLOCK_SECTOR_SIZE * 100 + k * BLOCK_SECTOR_SIZE * 128;
              if (size <= pos3)
                {
                  free_map_release (doubly[k], 1);
                  doubly[k] = 0;
                }
            }
          k++;
        }
      cache_write_to_sector (id->doubly_indirect, doubly);
      if (pos1 <= 100)
        {
          free_map_release (id->doubly_indirect, 1);
          id->doubly_indirect = 0;
        }
    }
}


bool
inode_resize (struct inode_disk *id, off_t size)
{
  int i = 0;
  block_sector_t sector;
  char zeros[BLOCK_SECTOR_SIZE];
  memset (zeros, 0, BLOCK_SECTOR_SIZE);
  while (i < 100 && size > BLOCK_SECTOR_SIZE * i)
  {
    if (id->start[i] == 0)
    {
      bool success = free_map_allocate (1, &sector);
      if (success)
      {
        id->start[i] = sector;
        cache_write_to_sector (sector, zeros);
      }
      else
      {
        inode_resize (id, id->length);
        return false;
      }
    }
    i++;
  }
  
  int pos1 = BLOCK_SECTOR_SIZE * 100;
  if (size > pos1)
    {
      block_sector_t doubly[128];
      memset (doubly, 0, 512);
      if (id->doubly_indirect == 0)
      {
        memset (doubly, 0, 512);
        bool success = free_map_allocate (1, &sector);
        if (success)
          id->doubly_indirect = sector;
        else
        {
          inode_resize (id, id->length);
          return false;
        }
      }
      else
      {
        cache_get_sector (id->doubly_indirect, doubly);
      }

      int k = 0;
      block_sector_t singly[128];
      while(k < 128 && pos1 + k * BLOCK_SECTOR_SIZE * 128 < size)
      {
        if (doubly[k] == 0)
        {
          memset (singly, 0, 512);
          bool success = free_map_allocate (1, &sector);
          if (success)
            doubly[k] = sector;
          else
          {
            inode_resize (id, id->length);
            return false;
          }  
        }
        else
          {
            cache_get_sector (doubly[k], singly);
          }
        int j = 0;
        while (j < 128 && size > pos1 + (k * BLOCK_SECTOR_SIZE * 128) + (j * BLOCK_SECTOR_SIZE))
        {
          if (singly[j] == 0)
          {
            bool success = free_map_allocate (1, &sector);
            if (success)
              singly[j] = sector;
            else
            {
              inode_resize (id, id->length);
              return false;
            }
            cache_write_to_sector (sector, zeros);
          }
          j++;
        }
        cache_write_to_sector (doubly[k], singly);
        k++;
      }
      cache_write_to_sector (id->doubly_indirect, doubly);
    }
  id->length = size;
  inode_truncate_blocks (id, size);
  return true;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode)
{
  sema_down (&inode->inode_lock);
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  sema_up (&inode->inode_lock);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode)
{
  sema_down (&inode->inode_lock);
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
  sema_up (&inode->inode_lock);
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  sema_down (&inode->inode_lock);
  off_t length = inode->data.length;
  sema_up (&inode->inode_lock);
  return length;
}
