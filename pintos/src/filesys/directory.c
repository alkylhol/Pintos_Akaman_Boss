#include "filesys/directory.h"
#include <stdio.h>
#include <string.h>
#include <list.h>
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/synch.h"
/* A directory. */
struct dir
{
  struct inode *inode; /* Backing store. */
  off_t pos;           /* Current position. */
};

/* A single directory entry. */
struct dir_entry
{
  block_sector_t inode_sector; /* Sector number of header. */
  char name[NAME_MAX + 1];     /* Null terminated file name. */
  bool in_use;                 /* In use or free? */
};

/* Separates path from filename for a full path name */
// Joshua drove here
void separate_path (const char *full, char *path_pt, char *file_pt)
{
  uint32_t length = strlen (full);
  char *end = (char *) full + length - 1;
  uint32_t file_length = 0;
  while (*end != '/' && file_length < length)
    {
      end--;
      file_length++;
    }

  if (end != full)
    {
      uint32_t path_length = length - file_length;
      path_length = path_length == 0 ? 1 : path_length;

      strlcpy (path_pt, full, path_length);
    }
  else
    {
      *path_pt = '/';
      *(path_pt + 1) = '\0';
    }
  strlcpy (file_pt, end + 1, file_length + 1);
}

/* Opens a directory from a specified path by searching through
   directory hierarchy */
// Avi drove here
struct dir *open_dir (char *path)
{
  struct dir *cd;

  char copy[strlen (path) + 1];
  if (*path == '/')
    {
      // start at root
      cd = dir_open_root ();
      strlcpy (copy, path + 1, strlen (path));
    }
  else
    {
      struct dir *temp = thread_current ()->curr_dir;
      if (temp == NULL)
        {
          cd = dir_open_root ();
        }
      else
        {
          cd = dir_reopen (temp);
        }
      strlcpy (copy, path, strlen (path) + 1);
    }

  char *save_ptr = NULL;
  char *next_path = strtok_r (copy, "/", &save_ptr);
  while (next_path != NULL)
    {
      struct inode *next_path_inode;
      if (!dir_lookup (cd, next_path, &next_path_inode))
        {
          dir_close (cd);
          return NULL;
        }
      struct dir *n_dir = dir_open (next_path_inode);
      dir_close (cd);
      cd = n_dir;

      next_path = strtok_r (NULL, "/", &save_ptr);

      if (!is_directory (cd->inode))
        {
          dir_close (cd);
          return NULL;
        }
    }
  if (is_removed (cd->inode))
    {
      dir_close (cd);
      return NULL;
    }

  return cd;
}
/* Creates a directory with space for ENTRY_CNT entries in the
   given SECTOR.  Returns true if successful, false on failure. */
bool dir_create (block_sector_t sector, size_t entry_cnt)
{
  return inode_create (sector, entry_cnt * sizeof (struct dir_entry), true);
}

/* Opens and returns the directory for the given INODE, of which
   it takes ownership.  Returns a null pointer on failure. */
struct dir *dir_open (struct inode *inode)
{
  struct dir *dir = calloc (1, sizeof *dir);
  if (inode != NULL && dir != NULL)
    {
      dir->inode = inode;
      // Akshat drove here
      dir->pos = sizeof (struct dir_entry) * 2;
      return dir;
    }
  else
    {
      inode_close (inode);
      free (dir);
      return NULL;
    }
}

/* Opens the root directory and returns a directory for it.
   Return true if successful, false on failure. */
struct dir *dir_open_root (void)
{
  return dir_open (inode_open (ROOT_DIR_SECTOR));
}

/* Opens and returns a new directory for the same inode as DIR.
   Returns a null pointer on failure. */
struct dir *dir_reopen (struct dir *dir)
{
  return dir_open (inode_reopen (dir->inode));
}

/* Destroys DIR and frees associated resources. */
void dir_close (struct dir *dir)
{
  if (dir != NULL)
    {
      inode_close (dir->inode);
      free (dir);
    }
}

/* Returns the inode encapsulated by DIR. */
struct inode *dir_get_inode (struct dir *dir) { return dir->inode; }

/* Searches DIR for a file with the given NAME.
   If successful, returns true, sets *EP to the directory entry
   if EP is non-null, and sets *OFSP to the byte offset of the
   directory entry if OFSP is non-null.
   otherwise, returns false and ignores EP and OFSP. */
static bool lookup (const struct dir *dir, const char *name,
                    struct dir_entry *ep, off_t *ofsp)
{
  struct dir_entry e;
  size_t ofs;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e)
    {
      if (e.in_use && !strcmp (name, e.name))
        {
          if (ep != NULL)
            *ep = e;
          if (ofsp != NULL)
            *ofsp = ofs;
          return true;
        }
    }
  return false;
}

/* Searches DIR for a file with the given NAME
   and returns true if one exists, false otherwise.
   On success, sets *INODE to an inode for the file, otherwise to
   a null pointer.  The caller must close *INODE. */
bool dir_lookup (const struct dir *dir, const char *name, struct inode **inode)
{
  struct dir_entry e;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);
  // Akshat drove here
  lock_acquire (get_dir_lock (dir->inode));
  if (lookup (dir, name, &e, NULL))
    *inode = inode_open (e.inode_sector);
  else
    *inode = NULL;
  lock_release (get_dir_lock (dir->inode));
  return *inode != NULL;
}

/* Adds a file named NAME to DIR, which must not already contain a
   file by that name.  The file's inode is in sector
   INODE_SECTOR.
   Returns true if successful, false on failure.
   Fails if NAME is invalid (i.e. too long) or a disk or memory
   error occurs. */
bool dir_add (struct dir *dir, const char *name, block_sector_t inode_sector,
              bool isdir)
{
  struct dir_entry e;
  off_t ofs;
  bool success = false;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  /* Check NAME for validity. */
  if (*name == '\0' || strlen (name) > NAME_MAX)
    return false;

  /* Check that NAME is not in use. */
  lock_acquire (get_dir_lock (dir->inode));
  if (lookup (dir, name, NULL, NULL))
    goto done;

  // Joshua drove here
  if (isdir)
    {
      // create child parent relation
      struct dir *child = dir_open (inode_open (inode_sector));
      struct dir_entry child_entry;
      strlcpy (child_entry.name, ".", 2);
      child_entry.inode_sector = inode_sector;
      child_entry.in_use = true;
      inode_write_at (child->inode, &child_entry, sizeof 
              (struct dir_entry), 0);

      struct dir_entry parent_entry;
      strlcpy (parent_entry.name, "..", 3);
      parent_entry.inode_sector = inode_get_inumber (dir->inode);
      parent_entry.in_use = true;
      inode_write_at (child->inode, &parent_entry, sizeof (struct dir_entry),
                      sizeof (struct dir_entry));

      dir_close (child);
    }
  /* Set OFS to offset of free slot.
     If there are no free slots, then it will be set to the
     current end-of-file.

     inode_read_at() will only return a short read at end of file.
     Otherwise, we'd need to verify that we didn't get a short
     read due to something intermittent such as low memory. */
  for (ofs = sizeof (struct dir_entry) * 2;
       inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e)
    if (!e.in_use)
      break;

  /* Write slot. */
  e.in_use = true;
  strlcpy (e.name, name, sizeof e.name);
  e.inode_sector = inode_sector;
  success = inode_write_at (dir->inode, &e, sizeof e, ofs) == sizeof e;

done:
  // Joshua drove here
  lock_release (get_dir_lock (dir->inode));
  return success;
}

/* Removes any entry for NAME in DIR.
   Returns true if successful, false on failure,
   which occurs only if there is no file with the given NAME. */
bool dir_remove (struct dir *dir, const char *name)
{
  struct dir_entry e;
  struct inode *inode = NULL;
  bool success = false;
  off_t ofs;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  // Akshat drove here
  lock_acquire (get_dir_lock (dir->inode));
  /* Find directory entry. */
  if (!lookup (dir, name, &e, &ofs))
    goto done;

  /* Open inode. */
  inode = inode_open (e.inode_sector);
  if (inode == NULL)
    goto done;

  /* Verify dir is empty */
  if (is_directory (inode))
    {
      struct dir *curr_dir = dir_open (inode);
      uint32_t counter = sizeof (e) * 2;
      while (inode_read_at (curr_dir->inode, &e, sizeof (e), counter) ==
             sizeof (e))
        {
          if (e.in_use)
            {
              dir_close (curr_dir);
              goto done;
            }
          dir_close (curr_dir);
          counter += sizeof (e);
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
  lock_release (get_dir_lock (dir->inode));
  return success;
}

/* Reads the next directory entry in DIR and stores the name in
   NAME.  Returns true if successful, false if the directory
   contains no more entries. */
bool dir_readdir (struct dir *dir, char name[NAME_MAX + 1])
{
  // Joshua drove here
  lock_acquire (get_dir_lock (dir->inode));
  struct dir_entry e;

  while (inode_read_at (dir->inode, &e, sizeof e, dir->pos) == sizeof e)
    {
      dir->pos += sizeof e;
      if (e.in_use)
        {
          strlcpy (name, e.name, NAME_MAX + 1);
          lock_release (get_dir_lock (dir->inode));
          return true;
        }
    }
  lock_release (get_dir_lock (dir->inode));
  return false;
}
