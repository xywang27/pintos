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

static const char zeros[BLOCK_SECTOR_SIZE];
static struct lock inode_open_lock;

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44
// #define BLOCK_SECTOR_ERROR ((block_sector_t) -1)

// #define DIRECT_COUNT 122
// #define INDIRECT_PER_SECTOR (BLOCK_SECTOR_SIZE / 4)
// #define INDEX0_CAP 122
// #define INDEX1_CAP 128
// #define INDEX2_CAP (128 * 128)
#define MIN(a, b) ((a) < (b) ? (a) : (b))

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
{
    block_sector_t index0[124];
    // block_sector_t index1;
    // block_sector_t index2;
    int level;
    bool is_dir;                    /* Is a directory or not. */
    off_t length;                       /* File size in bytes. */
    unsigned magic;                     /* Magic number. */
};

// struct inode_indirect {
//     block_sector_t blocks[128];
// };

/* In-memory inode. */
struct inode
{
    struct list_elem elem;              /* Element in inode list. */
    struct lock inode_lock;             /* Lock */
    // struct lock dir_lock;
    block_sector_t sector;              /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    // bool is_dir;
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

// a pseudo-pow that only works for b <= 1 :)
static inline size_t size_pow(size_t a, unsigned b) {
    return b == 0 ? 1 : a;
}

static bool inode_extend_level(block_sector_t *block,
        size_t sectors, unsigned level) {
    if (*block == 0) {
        if (!free_map_allocate(1, block)) {
            return false;
        }
        cache_write_at(*block, zeros, BLOCK_SECTOR_SIZE, 0);
    }
    if (level == 0)
        return true;

    // struct inode_indirect *iid = malloc(BLOCK_SECTOR_SIZE);
    block_sector_t iid[128];

    // if (!iid)
    //     return false;
    cache_read_at(*block, iid, BLOCK_SECTOR_SIZE, 0);

    size_t i;
    size_t next_level = size_pow(128, level - 1);
    size_t max_sector = sectors / next_level;

    // find the first i that probably needs allocating
    for (i = 0; i < max_sector; ++i) {
        if (iid[i] == 0)
            break;
    }
    // i = i == 0 ? 0 : i - 1;

    for (; i < max_sector; ++i) {
        if (!inode_extend_level(&iid[i], next_level, level - 1))
            return false;
    }

    cache_write_at(*block, iid, BLOCK_SECTOR_SIZE, 0);
    // free(iid);

    return true;
}

static bool inode_extend_level1(block_sector_t *block, size_t sectors) {
  if (*block == 0) {
      if (!free_map_allocate(1, block)) {
          return false;
      }
      cache_write_at(*block, zeros, BLOCK_SECTOR_SIZE, 0);
  }
  block_sector_t iid[128];
  cache_read_at(*block, iid, BLOCK_SECTOR_SIZE, 0);
  size_t i;
  size_t next_level = 1;
  // size_t max_sector = DIV_ROUND_UP(sectors, next_level);

  // find the first i that probably needs allocating
  for (i = 0; i < sectors; ++i) {
      if (iid[i] == 0)
          break;
  }
  i = i == 0 ? 0 : i - 1;

  for (; i < sectors; ++i) {
    if (iid[i] == 0) {
        if (!free_map_allocate(1, &iid[i])) {
            return false;
        }
        cache_write_at(*block, zeros, BLOCK_SECTOR_SIZE, 0);
    }
  }

  cache_write_at(*block, iid, BLOCK_SECTOR_SIZE, 0);
  // free(iid);

  return true;
}

// static bool inode_extend_level2(block_sector_t *block, size_t sectors){
//   if (*block == 0) {
//       if (!free_map_allocate(1, block)) {
//           return false;
//       }
//       cache_write_at(*block, zeros, BLOCK_SECTOR_SIZE, 0);
//   }
//   // struct inode_indirect *iid = malloc(BLOCK_SECTOR_SIZE);
//   block_sector_t iid[128];
//
//   // if (!iid)
//   //     return false;
//   cache_read_at(*block, iid, BLOCK_SECTOR_SIZE, 0);
//
//   size_t i;
//   size_t next_level = 128;
//   size_t max_sector = sectors / next_level;
//
//   // find the first i that probably needs allocating
//   for (i = 0; i < max_sector; ++i) {
//       if (iid[i] == 0)
//           break;
//   }
//   // i = i == 0 ? 0 : i - 1;
//
//   for (; i < max_sector; ++i) {
//       if (!inode_extend_level1(&iid[i], 128){
//         return false;
//       }
//   }
//
//   cache_write_at(*block, iid, BLOCK_SECTOR_SIZE, 0);
//   // free(iid);
//
//   return true;
// }

static bool inode_extend(struct inode_disk *disk_inode, off_t length){
  if (length <= disk_inode->length){
    return true;
  }
  size_t sectorsneed = bytes_to_sectors(length);
  size_t sectorsnow = bytes_to_sectors(disk_inode->length);
  int i = sectorsnow;
  if (sectorsneed <= 122){
    while(i < sectorsneed){
      if (!free_map_allocate (1, &disk_inode->index0[i])){
        return false;
      }
      else{
        cache_write_at(disk_inode->index0[i], zeros, BLOCK_SECTOR_SIZE, 0);
      }
      i = i + 1;
    }
    return true;
  }
  else if(122 < sectorsneed <= 122+128){
    while(i < 122){
      if (!free_map_allocate (1, &disk_inode->index0[i])){
        return false;
      }
      else{
        cache_write_at(disk_inode->index0[i], zeros, BLOCK_SECTOR_SIZE, 0);
      }
      i = i + 1;
    }
    sectorsneed -= 122;
    // if (sectorsnow < 122){
    //   if (!free_map_allocate (1, &disk_inode->index0[122])){
    //     return false;
    //   }
    //   else{
    //     cache_write_at(disk_inode->index0[122], zeros, BLOCK_SECTOR_SIZE, 0);
    //   }
    // }
    if (!inode_extend_level1(&disk_inode->index0[122], sectorsneed)){
      return false;
    }
    return true;
  }
  else if (122+128 < sectorsneed <= 122+128+128*128){
    while(i < 122){
      if (!free_map_allocate (1, &disk_inode->index0[i])){
        return false;
      }
      else{
        cache_write_at(disk_inode->index0[i], zeros, BLOCK_SECTOR_SIZE, 0);
      }
      i = i + 1;
    }
    sectorsneed -= 122;
    // if (sectorsnow < 122){
    //   if (!free_map_allocate (1, &disk_inode->index0[122])){
    //     return false;
    //   }
    //   else{
    //     cache_write_at(disk_inode->index0[122], zeros, BLOCK_SECTOR_SIZE, 0);
    //   }
    // }
    if (!inode_extend_level1(&disk_inode->index0[122], sectorsneed)){
      return false;
    }
    sectorsneed -= 128;
    // if (sectorsnow < 122+128){
    //   if (!free_map_allocate (1, &disk_inode->index0[123])){
    //     return false;
    //   }
    //   else{
    //     cache_write_at(disk_inode->index0[123], zeros, BLOCK_SECTOR_SIZE, 0);
    //   }
    // }
    if (!inode_extend_level(&disk_inode->index0[123], sectorsneed, 2)){
      return false;
    }
    return true;
  }
  else{
    return false;
  }
}





// static bool inode_extend(struct inode_disk *disk_inode, off_t length) {
//     if (length < 0)
//         return false;
//
//     size_t sectors = bytes_to_sectors(length);
//     size_t old_sectors = bytes_to_sectors(disk_inode->length);
//
//     if (sectors <= old_sectors)
//         return true;
//
//     size_t i, min_sectors;
//
//     // direct
//     min_sectors = MIN(sectors, INDEX0_CAP);
//     for (i = 0; i < min_sectors; ++i) {
//         if (disk_inode->index0[i] > 0)
//             continue;
//         if (!free_map_allocate(1, &disk_inode->index0[i])) {
//             return false;
//         }
//         cache_write(disk_inode->index0[i], zeros);
//     }
//     if (sectors <= INDEX0_CAP)
//         return true;
//
//     // indirect
//     sectors -= INDEX0_CAP;
//     min_sectors = MIN(sectors, INDEX1_CAP);
//     if (!inode_extend_level(&disk_inode->index1, min_sectors, 1))
//         return false;
//     if (sectors <= INDEX1_CAP)
//         return true;
//
//     sectors -= INDEX1_CAP;
//     min_sectors = MIN(sectors, INDEX2_CAP);
//     if (!inode_extend_level(&disk_inode->index2, min_sectors, 2))
//         return false;
//     if (sectors <= INDEX2_CAP)
//         return true;
//
//     // shouldn't happen
//     return false;
// }

// static void inode_release_level(block_sector_t block, unsigned level) {
//     if (level == 0) {
//         free_map_release(block, 1);
//         return;
//     }
//
//     struct inode_indirect *iid = malloc(BLOCK_SECTOR_SIZE);
//     ASSERT(iid);
//     cache_read_at(block, iid, BLOCK_SECTOR_SIZE, 0);
//
//     size_t i;
//     for (i = 0; i < 128; ++i) {
//         if (iid->blocks[i] == 0)
//             break;
//         inode_release_level(iid->blocks[i], level - 1);
//     }
//
//     free(iid);
// }

// static void inode_release(struct inode_disk *disk_inode) {
//     size_t sectors = bytes_to_sectors(disk_inode->length);
//     size_t i, min_sectors;
//
//     // direct
//     min_sectors = MIN(sectors, INDEX0_CAP);
//     for (i = 0; i < min_sectors; ++i) {
//         if (disk_inode->index0[i] == 0)
//             break;
//         free_map_release(disk_inode->index0[i], 1);
//     }
//     if (sectors <= INDEX0_CAP)
//         return;
//
//     // indirect
//     sectors -= INDEX0_CAP;
//     inode_release_level(disk_inode->index1, 1);
//     if (sectors <= INDEX1_CAP)
//         return;
//
//     sectors -= INDEX1_CAP;
//     inode_release_level(disk_inode->index2, 2);
//     if (sectors <= INDEX2_CAP)
//         return;
//
//     // shouldn't happen
//     NOT_REACHED();
// }

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
    return inode->data.index0[pos/512];
  }
  else if (pos < 122*512 + 128*512){
    inode->data.level = 1;
    block_sector_t indirect[128];
    // struct inode_indirect *indirect = malloc(sizeof(struct inode_indirect));
    // if(!indirect){
    //   return -1;
    // }
    cache_read_at(inode->data.index0[122], indirect, BLOCK_SECTOR_SIZE, 0);
    return indirect[(pos-122*512)/512];
    // free(indirect);
  }
  else if (pos < 122*512 + 128*512 + 128*128*512){
    inode->data.level = 2;
    block_sector_t indirect[128];
    block_sector_t doubly_indirect[128];
    // struct inode_indirect *indirect = malloc(sizeof(struct inode_indirect));
    // struct inode_indirect *doubly_indirect = malloc(sizeof(struct inode_indirect));
    // if(!indirect){
    //   return -1;
    // }
    // if(!doubly_indirect){
    //   return -1;
    // }
    cache_read_at(inode->data.index0[123], indirect, BLOCK_SECTOR_SIZE, 0);
    cache_read_at(indirect[((pos-122*512-128*512)/512)/128], doubly_indirect, BLOCK_SECTOR_SIZE, 0);
    return doubly_indirect[((pos-122*512-128*512)/512)%128];
    // free(indirect);
    // free(doubly_indirect);
  }
  else{
    return -1;
  }
}


// static block_sector_t
// byte_to_sector (const struct inode *inode, off_t pos)
// {
//     ASSERT (inode != NULL);
//
//     // direct
//     off_t ofs = pos / BLOCK_SECTOR_SIZE;
//     if (ofs < INDEX0_CAP) {
//         return inode->data.index0[ofs];
//     }
//
//     // indirect
//     ofs -= INDEX0_CAP;
//     if (ofs < INDEX1_CAP) {
//         struct inode_indirect *iid =
//                 malloc(sizeof(struct inode_indirect));
//         if (!iid)
//             return BLOCK_SECTOR_ERROR;
//         cache_read(inode->data.index1, iid);
//         block_sector_t blk = iid->blocks[ofs];
//         free(iid);
//         return blk;
//     }
//
//     // doubly indirect
//     ofs -= INDEX1_CAP;
//     if (ofs < INDEX2_CAP) {
//         off_t ofs_ind1 = ofs / INDIRECT_PER_SECTOR;
//         off_t ofs_ind2 = ofs % INDIRECT_PER_SECTOR;
//         struct inode_indirect *iid =
//                 malloc(sizeof(struct inode_indirect));
//         if (!iid)
//             return BLOCK_SECTOR_ERROR;
//         cache_read(inode->data.index2, iid);
//         cache_read(iid->blocks[ofs_ind1], iid);
//         block_sector_t blk = iid->blocks[ofs_ind2];
//         free(iid);
//         return blk;
//     }
//
//     // shouldn't happen
//     return BLOCK_SECTOR_ERROR;
// }

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
       disk_inode->index0[i] = 0;
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



// bool
// inode_create (block_sector_t sector, off_t length, bool is_dir)
// {
//     struct inode_disk *disk_inode = NULL;
//
//     ASSERT (length >= 0);
//
//     /* If this assertion fails, the inode structure is not exactly
//        one sector in size, and you should fix that. */
//     ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);
//
//     disk_inode = calloc(1, sizeof *disk_inode);
//     if (!disk_inode)
//         return false;
//     disk_inode->is_dir = is_dir ? 1 : 0;
//     disk_inode->length = 0;
//     disk_inode->level = 0;
//     disk_inode->magic = INODE_MAGIC;
//     if (!inode_extend(disk_inode, length)) {
//         free(disk_inode);
//         return false;
//     }
//     disk_inode->length = length;
//     cache_write(sector, disk_inode);
//     free(disk_inode);
//     return true;
// }

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
 // inode->is_dir = (bool) inode->data.is_dir;
 // if (inode->is_dir) {
 //     lock_init(&inode->dir_lock);
 // }
 return inode;
}


// struct inode *
// inode_open (block_sector_t sector)
// {
//     struct list_elem *e;
//     struct inode *inode;
//
//     lock_acquire(&inode_open_lock);
//
//     /* Check whether this inode is already open. */
//     for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
//          e = list_next (e))
//     {
//         inode = list_entry (e, struct inode, elem);
//         if (inode->sector == sector)
//         {
//             lock_release(&inode_open_lock);
//             inode_reopen (inode);
//             return inode;
//         }
//     }
//
//     /* Allocate memory. */
//     inode = malloc (sizeof *inode);
//     if (inode == NULL) {
//         lock_release(&inode_open_lock);
//         return NULL;
//     }
//
//     /* Initialize. */
//     list_push_front (&open_inodes, &inode->elem);
//     lock_release(&inode_open_lock);
//     inode->sector = sector;
//     inode->open_cnt = 1;
//     inode->deny_write_cnt = 0;
//     inode->removed = false;
//     lock_init(&inode->inode_lock);
//     cache_read(inode->sector, &inode->data);
//     inode->is_dir = (bool) inode->data.is_dir;
//     ASSERT(inode->data.magic == INODE_MAGIC);
//     if (inode->is_dir) {
//         lock_init(&inode->dir_lock);
//     }
//     return inode;
// }

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

// bool
// inode_is_dir (const struct inode *inode)
// {
//     return inode->is_dir;
// }
//
// bool
// inode_removed (const struct inode *inode)
// {
//     return inode->removed;
// }
//
// void
// inode_lock_dir_acquire (struct inode *inode)
// {
//     return lock_acquire(&inode->dir_lock);
// }
//
// void
// inode_lock_dir_release (struct inode *inode)
// {
//     return lock_release(&inode->dir_lock);
// }

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


// void
// inode_close (struct inode *inode)
// {
//     /* Ignore null pointer. */
//     if (inode == NULL)
//         return;
//
//     lock_acquire(&inode->inode_lock);
//
//     /* Release resources if this was the last opener. */
//     if(--inode->open_cnt == 0) {
//         lock_acquire(&inode_open_lock);
//         /* Remove from inode list and release lock. */
//         list_remove(&inode->elem);
//         lock_release(&inode_open_lock);
//
//         /* Deallocate blocks if removed. */
//         if (inode->removed) {
//             free_map_release (inode->sector, 1);
//             inode_release(&inode->data);
//         }
//
//         lock_release(&inode->inode_lock);
//         free (inode);
//     } else {
//         lock_release(&inode->inode_lock);
//     }
// }

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

     // if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
     //   {
     //     /* Read full sector directly into caller's buffer. */
     //    cache_read_at(sector_idx, buffer + bytes_read, BLOCK_SECTOR_SIZE, 0);
     //   }
     // else
     //   {
     //     /* Read sector into bounce buffer, then partially copy
     //        into caller's buffer. */
     //    cache_read_at(sector_idx, buffer + bytes_read, chunk_size, sector_ofs);
     //   }

     /* Advance. */
     size -= chunk_size;
     offset += chunk_size;
     bytes_read += chunk_size;
   }

 return bytes_read;
}

// off_t
// inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset)
// {
//     uint8_t *buffer = buffer_;
//     off_t bytes_read = 0;
//     struct inode_disk *disk_inode = &inode->data;
//     ASSERT(disk_inode->magic == INODE_MAGIC);
//
//     while (size > 0)
//     {
//         /* Disk sector to read, starting byte offset within sector. */
//         int sector_ofs = offset % BLOCK_SECTOR_SIZE;
//
//         /* Bytes left in inode, bytes left in sector, lesser of the two. */
//         off_t inode_left = disk_inode->length - offset;
//         int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
//         int min_left = inode_left < sector_left ? inode_left : sector_left;
//
//         /* Number of bytes to actually copy out of this sector. */
//         int chunk_size = size < min_left ? size : min_left;
//         if (chunk_size <= 0) {
//             break;
//         }
//
//         block_sector_t sector_idx = byte_to_sector (inode, offset);
//         if (offset + BLOCK_SECTOR_SIZE < disk_inode->length) {
//             block_sector_t sector =
//                     byte_to_sector(inode, offset + BLOCK_SECTOR_SIZE);
//             // cache_read_ahead_put(sector);
//         }
//
//         if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE) {
//             /* Read full sector directly into caller's buffer. */
//             cache_read(sector_idx, buffer + bytes_read);
//         } else {
//             cache_read_at(sector_idx, buffer + bytes_read,
//                     chunk_size, sector_ofs);
//         }
//
//         /* Advance. */
//         size -= chunk_size;
//         offset += chunk_size;
//         bytes_read += chunk_size;
//     }
//
//     return bytes_read;
// }

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

 // lock_acquire(&inode->inode_lock);

 if (inode->deny_write_cnt){
   // lock_release(&inode->inode_lock);
   return 0;
 }


 if (offset + size > inode->data.length) {
        extended = true;
        if (!inode_extend(&inode->data, offset + size)) {
            // lock_release(&inode->inode_lock);
            return 0;
        }
    //     else {
    //     // lock_release(&inode->inode_lock);
    // }
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
     if (inode->data.length < offset) {
            inode->data.length = offset;
        }
   }
 if (extended) {
        cache_write_at(inode->sector, &inode->data, BLOCK_SECTOR_SIZE, 0);
        // lock_release(&inode->inode_lock);
 }


 return bytes_written;
}

// off_t
// inode_write_at (struct inode *inode, const void *buffer_, off_t size,
//                 off_t offset)
// {
//     struct inode_disk *disk_inode = &inode->data;
//     ASSERT(disk_inode->magic == INODE_MAGIC);
//     const uint8_t *buffer = buffer_;
//     off_t bytes_written = 0;
//     bool extended = false;
//
//     lock_acquire(&inode->inode_lock);
//
//     if (inode->deny_write_cnt) {
//         lock_release(&inode->inode_lock);
//         return 0;
//     }
//
//     if (offset + size > disk_inode->length) {
//         extended = true;
//         if (!inode_extend(&inode->data, offset + size)) {
//             lock_release(&inode->inode_lock);
//             return 0;
//         }
//     } else {
//         lock_release(&inode->inode_lock);
//     }
//
//     while (size > 0)
//     {
//         /* Sector to write, starting byte offset within sector. */
//         int sector_ofs = offset % BLOCK_SECTOR_SIZE;
//         int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
//
//         /* Number of bytes to actually write into this sector. */
//         int chunk_size = size < sector_left ? size : sector_left;
//         if (chunk_size <= 0)
//             break;
//
//         block_sector_t sector_idx = byte_to_sector (inode, offset);
//
//         if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE) {
//             /* Write full sector directly to disk. */
//             cache_write(sector_idx, buffer + bytes_written);
//         } else {
//             cache_write_at(sector_idx, buffer + bytes_written,
//                     chunk_size, sector_ofs);
//         }
//
//         /* Advance. */
//         size -= chunk_size;
//         offset += chunk_size;
//         bytes_written += chunk_size;
//         if (disk_inode->length < offset) {
//             disk_inode->length = offset;
//         }
//     }
//
//     if (extended) {
//         cache_write(inode->sector, &inode->data);
//         lock_release(&inode->inode_lock);
//     }
//
//     return bytes_written;
// }

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
