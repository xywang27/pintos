#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "filesys/cache.h"
#include "threads/synch.h"

static bool inode_extend_to_indirect_blocks(block_sector_t *sector, size_t sectorsneed);
static bool inode_extend_to_doubly_indirect_blocks(block_sector_t *sector, size_t sectorsneed);


/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    off_t length;                       /* File size in bytes. */
    unsigned magic;                     /* Magic number. */
    block_sector_t used[124];           /* we used 124 space to implement blocks */
    int level;                          /* the offset is in direct blocks, indirect blocks or doubly indirect blocks*/
    bool is_dir;                        /* If this inode_disk represents a directory or not. */
  };

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

/* In-memory inode. */
struct inode
  {
    struct list_elem elem;              /* Element in inode list. */
    block_sector_t sector;              /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    struct inode_disk data;             /* Inode content. */
    struct lock inode_lock;             /* lock for the inode */
  };

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector (struct inode *inode, off_t pos)
{
  ASSERT (inode != NULL);                                                                                 /*the inode can not be NULL*/
  if (pos < 122*512){                                                                                     /*the pos is in direct block*/
    inode->data.level = 0;                                                                                /*the level is 0*/
    return inode->data.used[pos/512];                                                                     /*return the correspond sector*/
  }
  else if (pos < 122*512 + 128*512){                                                                      /*the pos is in indirect block*/
    inode->data.level = 1;                                                                                /*the level is 1*/
    block_sector_t indirect[128];                                                                         /*a list to represent indirect block*/
    cache_read_at(inode->data.used[122], indirect, BLOCK_SECTOR_SIZE, 0);                                 /*read data into indirect*/
    return indirect[(pos-122*512)/512];                                                                   /*return the correspond sector*/
  }
  else if (pos < 122*512 + 128*512 + 128*128*512){                                                        /*the pos is in doubly indirect block*/
    inode->data.level = 2;                                                                                /*the level is 2*/
    block_sector_t indirect[128];                                                                         /*a list to represent indirect block*/
    block_sector_t doubly_indirect[128];                                                                  /*a list to represent doubly indirect block*/
    cache_read_at(inode->data.used[123], indirect, BLOCK_SECTOR_SIZE, 0);                                 /*read data into indirect*/
    cache_read_at(indirect[((pos-122*512-128*512)/512)/128], doubly_indirect, BLOCK_SECTOR_SIZE, 0);      /*read data into doubly indirect*/
    return doubly_indirect[((pos-122*512-128*512)/512)%128];                                              /*return the correspond sector*/
  }
  else{
    return -1;
  }
}


/*extend the disk_inode length to length*/
static bool inode_extend(struct inode_disk *disk_inode, off_t length){
  static char zeros[BLOCK_SECTOR_SIZE];                                       /*define a zeros char with BLOCK_SECTOR_SIZE length*/
  if (length <= disk_inode->length){                                          /*if extend does not need*/
    return true;
  }
  size_t sectorsneed = bytes_to_sectors(length);                              /*number of sectors need */
  size_t sectorsnow = bytes_to_sectors(disk_inode->length);                   /*number of sectors already have*/
  int i = sectorsnow;
  /*only need direct blocks*/
  if (sectorsneed <= 122){
    while(i < sectorsneed){
      if (free_map_allocate (1, &disk_inode->used[i])){                       /*if allocate is success*/
        cache_write_at(disk_inode->used[i], zeros, BLOCK_SECTOR_SIZE, 0);     /*write data back to the disk corresponding place*/
      }
      else{                                                                   /*if allocate is fail*/
        return false;
      }
      i = i + 1;
    }
    return true;
  }
  /*need indirect blocks*/
  else if(122 < sectorsneed <= 122+128){
    /*first deal with direct part*/
    while(i < 122){
      if (free_map_allocate (1, &disk_inode->used[i])){                      /*if allocate is success*/
        cache_write_at(disk_inode->used[i], zeros, BLOCK_SECTOR_SIZE, 0);    /*write data back to the disk corresponding place*/
      }
      else{
        return false;                                                        /*if allocate is fail*/
      }
      i = i + 1;
    }
    /*then indirect part*/
    sectorsneed = sectorsneed - 122;                                          /*number of sectors need in indirect blocks*/
    if (disk_inode->used[122] == 0) {                                        /*if it has not been allocated, first put zeros in it*/
        if (free_map_allocate(1, &disk_inode->used[122])) {                  /*if allocate is success*/
            cache_write_at(disk_inode->used[122], zeros, BLOCK_SECTOR_SIZE, 0);/*write data back to the disk corresponding place*/
        }
        else{
          return false;
        }
    }
    if (inode_extend_to_indirect_blocks(&disk_inode->used[122], sectorsneed)){/*allocate the indirect blocks*/
      return true;
    }
    return false;
  }
  /*need doubly indirect blocks*/
  else if (122+128 < sectorsneed <= 122+128+128*128){
    /*first deal with direct part*/
    while(i < 122){
      if (free_map_allocate (1, &disk_inode->used[i])){                      /*if allocate is success*/
        cache_write_at(disk_inode->used[i], zeros, BLOCK_SECTOR_SIZE, 0);    /*write data back to the disk corresponding place*/
      }
      else{
        return false;                                                        /*if allocate is fail*/
      }
      i = i + 1;
    }
    /*then indirect part*/
    sectorsneed = sectorsneed - 122;                                          /*number of sectors need in indirect blocks*/
    if (disk_inode->used[122] == 0) {                                        /*if it has not been allocated, first put zeros in it*/
        if (free_map_allocate(1, &disk_inode->used[122])) {                  /*if allocate is success*/
            cache_write_at(disk_inode->used[122], zeros, BLOCK_SECTOR_SIZE, 0);/*write data back to the disk corresponding place*/
        }
        else{
          return false;
        }
    }
    if (!inode_extend_to_indirect_blocks(&disk_inode->used[122], sectorsneed)){/*allocate the indirect blocks*/
      return false;
    }
    /*then doubly indirect blocks*/
    sectorsneed = sectorsneed - 128;                                           /*number of sectors need in doubly indirect blocks*/
    sectorsneed = sectorsneed / 128;                                           /*caculate number of sectors in direct blocks*/
    if (disk_inode->used[123] == 0) {                                          /*if it has not been allocated, first put zeros in it*/
        if (free_map_allocate(1, &disk_inode->used[123])) {                    /*if allocate is success*/
            cache_write_at(disk_inode->used[123], zeros, BLOCK_SECTOR_SIZE, 0);/*write data back to the disk corresponding place*/
        }
        else{
          return false;
        }
    }
    if (inode_extend_level2(&disk_inode->used[123], sectorsneed)){             /*allocate the doubly_indirect blocks*/
      return true;
    }
    return false;
  }
  else{
    return false;
  }
}


/*allocate for indirect blocks*/
static bool inode_extend_to_indirect_blocks(block_sector_t *sector, size_t sectorsneed){
  static char zeros[BLOCK_SECTOR_SIZE];                                        /*define a zeros char with BLOCK_SECTOR_SIZE length*/
  block_sector_t indirect[128];                                                /*a list to represent indirect block*/
  cache_read_at(*sector, indirect, BLOCK_SECTOR_SIZE, 0);                      /*read data from sector into indirect*/
  int i = 0;
  while(i < sectorsneed) {
    if (indirect[i] == 0) {                                                   /*we need to allocate here*/
        if (free_map_allocate(1, &indirect[i])) {                             /*if allocate is success*/
            cache_write_at(indirect[i], zeros, BLOCK_SECTOR_SIZE, 0);         /*write data back to the indirect block corresponding place*/
        }
        else{
          return false;
        }
    }
    i = i + 1;
  }

  cache_write_at(*sector, indirect, BLOCK_SECTOR_SIZE, 0);                    /*write data back to the disk corresponding place*/

  return true;
}


/*allocate for doubly indirect blocks*/
static bool inode_extend_to_doubly_indirect_blocks(block_sector_t *sector, size_t sectorsneed){
  static char zeros[BLOCK_SECTOR_SIZE];                                       /*define a zeros char with BLOCK_SECTOR_SIZE length*/
  block_sector_t doubly_indirect[128];                                        /*a list to represent doubly_indirect block*/
  cache_read_at(*sector, doubly_indirect, BLOCK_SECTOR_SIZE, 0);               /*read data from sector into doubly_indirect*/
  int i = 0;
  while(i < sectorsneed) {
      if (doubly_indirect[i] == 0){                                           /*we need to allocate here*/
        if (!inode_extend_level1(&doubly_indirect[i], 128))                   /*allocate indirect blocks*/
            return false;
    }
    i = i + 1;
  }

  cache_write_at(*sector, doubly_indirect, BLOCK_SECTOR_SIZE, 0);             /*write data back to the disk corresponding place*/

  return true;
}


/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void)
{
  list_init (&open_inodes);
  lock_init(&open_inodes_lock);
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
      for (i = 0; i < 124; i++){                                                   /*initialize the used to all zeros*/
        disk_inode->used[i] = 0;
      }
      if (inode_extend(disk_inode, length)){
        disk_inode->length = length;                                              /*extend the file length to length*/
        cache_write_at(sector, disk_inode, BLOCK_SECTOR_SIZE, 0);                 /*write the new inode to sector*/
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
  lock_init(&inode->inode_lock);                                                /*initialize the inode_lock*/
  cache_read_at(inode->sector, &inode->data, BLOCK_SECTOR_SIZE, 0);             /*read the data to sector after open the inode*/
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
  lock_acquire(&inode->inode_lock);                                            /*add lock to remove operation*/
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

      cache_read_at(sector_idx, buffer + bytes_read, chunk_size, sector_ofs);   /*read data to the caller's buffer*/

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

  if (inode->deny_write_cnt)
    return 0;

  if (inode->data.length < offset + size){                                    /*check if it needs to extend the file length*/
    int newlength = offset + size;                                            /*the new length of the file*/
    if (inode_extend(&inode->data, newlength)){                               /*if the extend is success*/
      inode->data.length = offset + size;                                     /*reset the file length*/
      cache_write_at(inode->sector, &inode->data, BLOCK_SECTOR_SIZE, 0);      /*write data to the sector*/
    }
    else{
      return 0;                                                               /*the extend is fail*/
    }
  }

  while (size > 0)
    {
      /* Sector to write, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < sector_left ? size : sector_left;
      if (chunk_size <= 0)
        break;

      cache_write_at(sector_idx, buffer + bytes_written, chunk_size, sector_ofs);  /*write data to the disk*/

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
  lock_acquire(&inode->inode_lock);                                      /*add lock to deny_write operation*/
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
  lock_acquire(&inode->inode_lock);                                      /*add lock to allow_write operation*/
  inode->deny_write_cnt--;
  lock_release(&inode->inode_lock);
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  return inode->data.length;
}
