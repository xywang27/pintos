#include "filesys/directory.h"
#include <stdio.h>
#include <string.h>
#include <list.h>
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "filesys/cache.h"
#include "threads/malloc.h"
#include "threads/thread.h"


bool
is_valid_dir (const char *dir)
{
  struct dir *directory = get_parent_directory (dir);
  if (!directory) 
  {
    return false;
  }

  if (strcmp (dir, "/")==0)
  {
    return true;
  }

  struct inode *inode;
  struct dir_entry e;
  size_t ofs = 0;
  char *dir_name = copy_name(dir);
  bool valid = false;
  while(inode_read_at (directory->inode, &e, sizeof e, ofs) == sizeof e)
  {
    if (e.in_use && strcmp (dir_name, e.name)==0)
      {
        valid = e.is_dir;
        break;
      }
    ofs += sizeof e;
  }
  dir_close (directory);
  free (dir_name);
  return valid;
}

/* Creates a directory with space for ENTRY_CNT entries in the
   given SECTOR.  Returns true if successful, false on failure. */
bool
dir_create (block_sector_t sector, size_t entry_cnt)
{
  return inode_create (sector, entry_cnt * sizeof (struct dir_entry), true);
}

/* Opens and returns the directory for the given INODE, of which
   it takes ownership.  Returns a null pointer on failure. */
struct dir *
dir_open (struct inode *inode)
{
  struct dir *dir = calloc (1, sizeof *dir);
  if (inode != NULL && dir != NULL && inode->data.is_dir)
    {
      dir->inode = inode;
      dir->pos = 0;
      return dir;
    }
  else
    {
      inode_close (inode);
      free (dir);
      return NULL;
    }
}


struct dir *
dir_open_path (const char *dir)
{
  struct dir *directory = get_parent_directory (dir);
  if (!directory) {
    return false;
  }
  if (strcmp (dir, "/")==0)
    {
      dir_close (directory);
      return dir_open_root ();
    }
  else
  {
    struct inode *inode;
    char *dir_name = copy_name(dir);
    dir_lookup (directory, dir_name, &inode);
    free (dir_name);
    dir_close (directory);
    return dir_open (inode);
  }
}

/* Opens the root directory and returns a directory for it.
   Return true if successful, false on failure. */
struct dir *
dir_open_root (void)
{
  return dir_open (inode_open (ROOT_DIR_SECTOR));
}

/* Opens and returns a new directory for the same inode as DIR.
   Returns a null pointer on failure. */
struct dir *
dir_reopen (struct dir *dir)
{
  return dir_open (inode_reopen (dir->inode));
}

/* Destroys DIR and frees associated resources. */
void
dir_close (struct dir *dir)
{
  if (dir != NULL)
    {
      inode_close (dir->inode);
      free (dir);
    }
}

/* Returns the inode encapsulated by DIR. */
struct inode *
dir_get_inode (struct dir *dir)
{
  return dir->inode;
}

/* Searches DIR for a file with the given NAME.
   If successful, returns true, sets *EP to the directory entry
   if EP is non-null, and sets *OFSP to the byte offset of the
   directory entry if OFSP is non-null.
   otherwise, returns false and ignores EP and OFSP. */
static bool
lookup (const struct dir *dir, const char *name,
        struct dir_entry *ep, off_t *ofsp)
{
  struct dir_entry e;
  size_t ofs;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e)
    if (e.in_use && !strcmp (name, e.name))
      {
        if (ep != NULL)
          *ep = e;
        if (ofsp != NULL)
          *ofsp = ofs;
        return true;
      }
  return false;
}

/* Searches DIR for a file with the given NAME
   and returns true if one exists, false otherwise.
   On success, sets *INODE to an inode for the file, otherwise to
   a null pointer.  The caller must close *INODE. */
bool
dir_lookup (const struct dir *dir, const char *name,
            struct inode **inode)
{
  struct dir_entry e;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  if (lookup (dir, name, &e, NULL))
    *inode = inode_open (e.inode_sector);
  else
    *inode = NULL;

  return *inode != NULL;
}

/* Adds a file named NAME to DIR, which must not already contain a
   file by that name.  The file's inode is in sector
   INODE_SECTOR.
   Returns true if successful, false on failure.
   Fails if NAME is invalid (i.e. too long) or a disk or memory
   error occurs. */
bool
dir_add (struct dir *dir, const char *name, block_sector_t inode_sector, bool is_dir)
{
  struct dir_entry e;
  off_t ofs;
  bool success = false;
  bool found_empty_spot = false;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  /* Check NAME for validity. */
  if (*name == '\0' || strlen (name) > NAME_MAX)
    return false;

  /* Check that NAME is not in use. */
  if (lookup (dir, name, NULL, NULL))
    goto done;

  /* Set OFS to offset of free slot.
     If there are no free slots, then it will be set to the
     current end-of-file.

     inode_read_at() will only return a short read at end of file.
     Otherwise, we'd need to verify that we didn't get a short
     read due to something intermittent such as low memory. */
  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e)
  { 
    if (!e.in_use)
    {
      found_empty_spot = true;
      break;
    }
  }


  if (!found_empty_spot)
    {
      int new_size = dir->inode->data.length + sizeof e - (dir->inode->data.length % sizeof e);
      new_size += BLOCK_SECTOR_SIZE - (new_size % BLOCK_SECTOR_SIZE);
      sema_down (&dir->inode->inode_lock);
      bool resized = inode_resize (&dir->inode->data, new_size);
      sema_up (&dir->inode->inode_lock);
      if (resized)
      {
        cache_write_to_sector (dir->inode->sector, &dir->inode->data);
      }
      else
      {
        return false;
      }

    }
  /* Write slot. */
  e.in_use = true;
  e.is_dir = is_dir;
  struct inode *inode;
  struct dir *new_dir;
  if (is_dir)
    {
      if (!dir_create (inode_sector, BLOCK_SECTOR_SIZE / sizeof (struct dir_entry))
        || !(inode = inode_open (inode_sector)) || !(new_dir = dir_open (inode))
        || !add_default_directories (new_dir, dir))
      {
        return false;
      }
      dir_close (new_dir);
    }
  strlcpy (e.name, name, sizeof e.name);
  e.inode_sector = inode_sector;
  success = inode_write_at (dir->inode, &e, sizeof e, ofs) == sizeof e;

 done:
  return success;
}

/* Removes any entry for NAME in DIR.
   Returns true if successful, false on failure,
   which occurs only if there is no file with the given NAME. */
bool
dir_remove (struct dir *dir, const char *name)
{
  struct dir_entry e;
  struct inode *inode = NULL;
  bool success = false;
  off_t ofs;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  /* Find directory entry. */
  if (!lookup (dir, name, &e, &ofs))
    goto done;

  /* Open inode. */
  inode = inode_open (e.inode_sector);
  if (inode == NULL)
    goto done;

  if (e.is_dir)
    {
      struct dir *dir_check = dir_open (inode);
      char tmp[NAME_MAX + 1];
      struct dir *directory = dir_reopen(dir_check);
      bool empty = !dir_readdir (directory, tmp);
      if (empty)
      {
        dir_close (dir_check);
      }
      else
      {
        dir_close (dir_check);
        return false;
      }
    }

  /* Erase directory entry. */
  e.in_use = false;
  if (inode_write_at (dir->inode, &e, sizeof e, ofs) != sizeof e)
    goto done;

  /* Remove inode. */
  inode_remove (inode);
  success = true;

 done:
  inode_close (inode);
  return success;
}

/* Reads the next directory entry in DIR and stores the name in
   NAME.  Returns true if successful, false if the directory
   contains no more entries. */
bool
dir_readdir (struct dir *dir, char name[NAME_MAX + 1])
{
  struct dir_entry e;

  while (inode_read_at (dir->inode, &e, sizeof e, dir->pos) == sizeof e)
    {
      dir->pos += sizeof e;
      if (e.in_use && strcmp (e.name, "..") && strcmp (e.name, "."))
        {
          strlcpy (name, e.name, NAME_MAX + 1);
          return true;
        }
    }
  return false;
}


bool
add_default_directories (struct dir *dir, struct dir *parent_dir)
{
  struct dir_entry e;
  sema_down (&parent_dir->inode->inode_lock);
  block_sector_t parent_sector = parent_dir->inode->sector;
  sema_up (&parent_dir->inode->inode_lock);

  struct dir_entry new_dirs[2];

  e.inode_sector = parent_sector;
  off_t original_offset = dir->pos;
  strlcpy (e.name, "..", NAME_MAX + 1);
  e.is_dir = true;
  e.in_use = !parent_dir->inode->removed;
  dir->pos += sizeof (e);
  new_dirs[0] = e;

  sema_down (&dir->inode->inode_lock);
  e.inode_sector = dir->inode->sector;
  e.in_use = !dir->inode->removed;
  sema_up (&dir->inode->inode_lock);
  strlcpy (e.name, ".", NAME_MAX + 1);
  e.is_dir = true;
  new_dirs[1] = e;

  if (inode_write_at (dir->inode, new_dirs, 2 * sizeof (e), original_offset))
    {
      dir->pos += sizeof (e);
      return true;
    }
  return false;
}


struct dir *
get_parent_directory (const char *path) {
  struct dir *directory = NULL;
  if (!path || strcmp(path, "") == 0) {
    return directory;
  }
  struct thread *curr = thread_current ();
  if (curr->cwd == NULL) {
    curr->cwd = dir_open_root ();
  }
  if (*path == '/') {
    directory = get_parent_directory_absolute (path);
  }
  else {
    directory = get_parent_directory_relative (path);
  }
  return directory;
}


struct dir *
get_parent_directory_absolute (const char *path) {
  if (!path || strcmp(path, "") == 0)
    return NULL;
  char *part = malloc (NAME_MAX + 1);
  char *temp;
  struct dir *dir;
  temp = extract_next_part(&path);
  if (temp == NULL) {
    free(temp);
    free (part);
    return dir_open_root ();
  } else {
    strlcpy (part, temp, strlen (temp) + 1);
    free(temp);
  }
  
  dir = dir_open_root ();
  struct dir *prev = dir_reopen (dir);
  struct inode *inode;
  while (part != NULL) {  
    if (dir_lookup (dir, part, &inode))
    {
      temp = extract_next_part(&path);
      if (temp == NULL) {
        part = NULL;
      } else {
        strlcpy (part, temp, strlen (temp) + 1);
      }
      free(temp);
      dir_close (prev);
      prev = dir;
      dir = dir_open(inode);
    }
    else
    {
      temp = extract_next_part(&path);
      if (temp == NULL) {
        part = NULL;
      } else {
        strlcpy (part, temp, strlen (temp) + 1);
      }
      free(temp);
      if (part == NULL)
      {
        dir_close (prev);
        prev = dir_reopen (dir);
        break;
      }
      else
      {
        free (part);
        dir_close (dir);
        dir_close (prev);
        return NULL;
      }
    }
  }
  dir_close (dir);
  free (part);
  return prev;
}


struct dir *
get_parent_directory_relative (const char *path)
{
  if (!path || strcmp(path, "") == 0) {
    return NULL;
  }
  char *part = malloc (NAME_MAX + 1);
  char *temp;

  temp = extract_next_part(&path);
  if (temp == NULL) {
    free(temp);
    free (part);
    return thread_current ()->cwd;
  } else {
    strlcpy (part, temp, strlen (temp) + 1);
    free(temp);
  }
  struct dir *dir = dir_reopen (thread_current ()->cwd);
  struct dir *prev = dir_reopen (thread_current ()->cwd);
  struct inode *inode = dir->inode;;
  struct inode *prev_inode = prev->inode;
  while (part != NULL)
  {
    bool found = false;
    struct dir_entry e;
    for (size_t ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
         ofs += sizeof e) {
      if (!strcmp (part, e.name))
      {
        if (e.is_dir) {
          dir_close (prev);
          prev = dir;
          prev_inode = prev->inode;
          inode = inode_open (e.inode_sector);
          dir = dir_open (inode);
          found = true;
        }
        break;
      }
    }
      
    temp = extract_next_part(&path);
    if (temp == NULL) {
      part = NULL;
    } else {
      strlcpy (part, temp, strlen (temp) + 1);
    }
    free(temp);
    if (part == NULL)
    {
      if (!found)
      {
        dir_close (prev);
        prev = dir_reopen (dir);
      }
      break;
    } 
    else 
    {
      if (!found)
      {
        free (part);
        dir_close (prev);
        dir_close (dir);
        return NULL;
      }
    }
  }
  dir_close (dir);
  free (part);
  if (!prev_inode->removed) {
    return prev;
  } else {
    return NULL;
  }
}


char *
extract_next_part(const char **srcp) {
  char *dst = malloc (NAME_MAX + 1);
  char *ret = dst;
  char *src = *srcp;
  int cnt = 0;
  while (*src == '/') {
    src++;
  }
  if (*src == '\0') {
    free(ret);
    return NULL;
  }
  while (*src != '\0' && *src != '/') {
    if (dst >= ret + NAME_MAX) {
      free(ret);
      return NULL;
    }
    *dst = *src;
    dst++;
    src++;
    cnt++;
  }
  *dst = '\0';
  *srcp = src;
  return ret;
}

char *
copy_name(const char *name)
{
  char *file_name = malloc (NAME_MAX + 1);
  char *temp;
  temp = extract_next_part (&name);
  while (temp != NULL) {
    strlcpy (file_name, temp, strlen (temp) + 1);
    free(temp);
    temp = extract_next_part (&name);
  }
  return file_name;
}