#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "filesys/cache.h"

static struct lock inode_open_lock;

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
{
    block_sector_t used[124];
    int level;
    bool is_dir;                    /* Is a directory or not. */
    off_t length;                       /* File size in bytes. */
    unsigned magic;                     /* Magic number. */
};


/* In-memory inode. */
struct inode
{
    struct list_elem elem;              /* Element in inode list. */
    struct lock inode_lock;             /* Lock */
    block_sector_t sector;              /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    struct inode_disk data;             /* Inode content. */
};

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
    return (size_t) DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

static bool inode_extend_level1(block_sector_t *block, size_t sectors) {
  static char zeros[BLOCK_SECTOR_SIZE];
  block_sector_t iid[128];
  cache_read_at(*block, iid, BLOCK_SECTOR_SIZE, 0);
  int i = 0;
  while(i < sectors) {
    if (iid[i] == 0) {
        if (!free_map_allocate(1, &iid[i])) {
            return false;
        }
        cache_write_at(iid[i], zeros, BLOCK_SECTOR_SIZE, 0);
    }
    i = i + 1;
  }

  cache_write_at(*block, iid, BLOCK_SECTOR_SIZE, 0);

  return true;
}

static bool inode_extend_level2(block_sector_t *block, size_t sectors){
  static char zeros[BLOCK_SECTOR_SIZE];
  block_sector_t iid[128];
  cache_read_at(*block, iid, BLOCK_SECTOR_SIZE, 0);
  size_t i = 0;
  while(i < sectors) {
      if (iid[i] == 0){
        if (!inode_extend_level1(&iid[i], 128))
            return false;
    }
    i = i + 1;
  }

  cache_write_at(*block, iid, BLOCK_SECTOR_SIZE, 0);

  return true;
}

static bool inode_extend(struct inode_disk *disk_inode, off_t length){
  static char zeros[BLOCK_SECTOR_SIZE];
  if (length <= disk_inode->length){
    return true;
  }
  size_t sectorsneed = bytes_to_sectors(length);
  size_t sectorsnow = bytes_to_sectors(disk_inode->length);
  int i = sectorsnow;
  if (sectorsneed <= 122){
    while(i < sectorsneed){
      if (!free_map_allocate (1, &disk_inode->used[i])){
        return false;
      }
      else{
        cache_write_at(disk_inode->used[i], zeros, BLOCK_SECTOR_SIZE, 0);
      }
      i = i + 1;
    }
    return true;
  }
  else if(122 < sectorsneed <= 122+128){
    while(i < 122){
      if (!free_map_allocate (1, &disk_inode->used[i])){
        return false;
      }
      else{
        cache_write_at(disk_inode->used[i], zeros, BLOCK_SECTOR_SIZE, 0);
      }
      i = i + 1;
    }
    sectorsneed -= 122;
    if (disk_inode->used[122] == 0) {
        if (!free_map_allocate(1, &disk_inode->used[122])) {
            return false;
        }
        cache_write_at(disk_inode->used[122], zeros, BLOCK_SECTOR_SIZE, 0);
    }
    if (!inode_extend_level1(&disk_inode->used[122], sectorsneed)){
      return false;
    }
    return true;
  }
  else if (122+128 < sectorsneed <= 122+128+128*128){
    while(i < 122){
      if (!free_map_allocate (1, &disk_inode->used[i])){
        return false;
      }
      else{
        cache_write_at(disk_inode->used[i], zeros, BLOCK_SECTOR_SIZE, 0);
      }
      i = i + 1;
    }
    sectorsneed -= 122;
    if (disk_inode->used[122] == 0) {
        if (!free_map_allocate(1, &disk_inode->used[122])) {
            return false;
        }
        cache_write_at(disk_inode->used[122], zeros, BLOCK_SECTOR_SIZE, 0);
    }
    if (!inode_extend_level1(&disk_inode->used[122], sectorsneed)){
      return false;
    }
    sectorsneed -= 128;
    sectorsneed = sectorsneed/128;
    if (disk_inode->used[123] == 0) {
        if (!free_map_allocate(1, &disk_inode->used[123])) {
            return false;
        }
        cache_write_at(disk_inode->used[123], zeros, BLOCK_SECTOR_SIZE, 0);
    }
    if (!inode_extend_level2(&disk_inode->used[123], sectorsneed)){
      return false;
    }
    return true;
  }
  else{
    return false;
  }
}

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */

static block_sector_t
byte_to_sector (struct inode *inode, off_t pos)
{
  ASSERT (inode != NULL);
  // off_t ofs = pos / BLOCK_SECTOR_SIZE;
  if (pos < 122*512){
    inode->data.level = 0;
    return inode->data.used[pos/512];
  }
  else if (pos < 122*512 + 128*512){
    inode->data.level = 1;
    block_sector_t indirect[128];
    cache_read_at(inode->data.used[122], indirect, BLOCK_SECTOR_SIZE, 0);
    return indirect[(pos-122*512)/512];
  }
  else if (pos < 122*512 + 128*512 + 128*128*512){
    inode->data.level = 2;
    block_sector_t indirect[128];
    block_sector_t doubly_indirect[128];
    cache_read_at(inode->data.used[123], indirect, BLOCK_SECTOR_SIZE, 0);
    cache_read_at(indirect[((pos-122*512-128*512)/512)/128], doubly_indirect, BLOCK_SECTOR_SIZE, 0);
    return doubly_indirect[((pos-122*512-128*512)/512)%128];
  }
  else{
    return -1;
  }
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void)
{
    list_init(&open_inodes);
    lock_init(&inode_open_lock);
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
 bool success = false;

 ASSERT (length >= 0);

 /* If this assertion fails, the inode structure is not exactly
    one sector in size, and you should fix that. */
 ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

 disk_inode = calloc (1, sizeof *disk_inode);
 if (disk_inode != NULL)
   {
     size_t sectors = bytes_to_sectors (length);
     disk_inode->is_dir = is_dir;
     disk_inode->length = 0;
     disk_inode->level = 0;
     disk_inode->magic = INODE_MAGIC;
     int i = 0;
     for (i = 0; i < 124; i++){
       disk_inode->used[i] = 0;
     }
     if (inode_extend(disk_inode, length)){
       disk_inode->length = length;
       cache_write_at(sector, disk_inode, BLOCK_SECTOR_SIZE, 0);
       success = true;
     }
     free (disk_inode);
   }
 return success;
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
 for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
      e = list_next (e))
   {
     inode = list_entry (e, struct inode, elem);
     if (inode->sector == sector)
       {
         inode_reopen (inode);
         return inode;
       }
   }

 /* Allocate memory. */
 inode = malloc (sizeof *inode);
 if (inode == NULL)
   return NULL;

 /* Initialize. */
 list_push_front (&open_inodes, &inode->elem);
 inode->sector = sector;
 inode->open_cnt = 1;
 inode->deny_write_cnt = 0;
 inode->removed = false;
 lock_init(&inode->inode_lock);
 cache_read_at(inode->sector, &inode->data, BLOCK_SECTOR_SIZE, 0);
 return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
    if (inode != NULL)
        inode->open_cnt++;
    return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
    return inode->sector;
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
 if (--inode->open_cnt == 0)
   {
     /* Remove from inode list and release lock. */
     list_remove (&inode->elem);

     /* Deallocate blocks if removed. */
     if (inode->removed)
       {
         free_map_release (inode->sector, 1);
       }
     free (inode);
   }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode)
{
    ASSERT (inode != NULL);
    lock_acquire(&inode->inode_lock);
    inode->removed = true;
    lock_release(&inode->inode_lock);
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset)
{
 uint8_t *buffer = buffer_;
 off_t bytes_read = 0;

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
     cache_read_at(sector_idx, buffer + bytes_read, chunk_size, sector_ofs);

     /* Advance. */
     size -= chunk_size;
     offset += chunk_size;
     bytes_read += chunk_size;
   }

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
 bool extended = false;

 if (inode->deny_write_cnt){
   return 0;
 }


 if (offset + size > inode->data.length) {
        extended = true;
        if (!inode_extend(&inode->data, offset + size)) {
            return 0;
        }
        inode->data.length = offset + size;
        cache_write_at(inode->sector, &inode->data, BLOCK_SECTOR_SIZE, 0);
    }

 while (size > 0)
   {
     /* Sector to write, starting byte offset within sector. */
     block_sector_t sector_idx = byte_to_sector (inode, offset);
     int sector_ofs = offset % BLOCK_SECTOR_SIZE;

     /* Bytes left in inode, bytes left in sector, lesser of the two. */
     // off_t inode_left = inode_length (inode) - offset;
     int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
     // int min_left = inode_left < sector_left ? inode_left : sector_left;

     /* Number of bytes to actually write into this sector. */
     int chunk_size = size < sector_left ? size : sector_left;
     if (chunk_size <= 0)
       break;

     cache_write_at(sector_idx, buffer + bytes_written, chunk_size, sector_ofs);

     /* Advance. */
     size -= chunk_size;
     offset += chunk_size;
     bytes_written += chunk_size;
   }

 return bytes_written;
}


/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode)
{
    lock_acquire(&inode->inode_lock);
    inode->deny_write_cnt++;
    lock_release(&inode->inode_lock);
    ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode)
{
    ASSERT (inode->deny_write_cnt > 0);
    ASSERT (inode->deny_write_cnt <= inode->open_cnt);
    lock_acquire(&inode->inode_lock);
    inode->deny_write_cnt--;
    lock_release(&inode->inode_lock);
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
    return inode->data.length;
}
