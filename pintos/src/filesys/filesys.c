#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"

/* Partition that contains the file system. */
struct block *fs_device;

static void do_format (void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void filesys_init (bool format)
{
  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");
  inode_init ();
  free_map_init ();

  if (format)
    do_format ();

  free_map_open ();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void filesys_done (void) { free_map_close (); }

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool filesys_create (const char *name, off_t initial_size, bool isdir)
{
  block_sector_t inode_sector = 0;
  char path_pt[strlen (name) + 1];
  char file_pt[strlen (name) + 1];
  /* Akshat drove here */
  separate_path (name, path_pt, file_pt);
  struct dir *dir = open_dir (path_pt);

  /* Joshua drove here */
  bool success = (dir != NULL && free_map_allocate (1, &inode_sector) &&
                  inode_create (inode_sector, initial_size, isdir) &&
                  dir_add (dir, file_pt, inode_sector, isdir));
  if (!success && inode_sector != 0)
    {
      free_map_release (inode_sector, 1);
    }
  dir_close (dir);
  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *filesys_open (const char *name)
{
  if (strcmp (name, "/") == 0)
    {
      return file_open (dir_get_inode (dir_open_root ()));
    }
  char path_pt[strlen (name) + 1];
  char file_pt[strlen (name) + 1];
  /* Aksha drove here */
  separate_path (name, path_pt, file_pt);
  struct dir *dir = open_dir (path_pt);
  struct inode *inode = NULL;

  if (dir != NULL)
    dir_lookup (dir, file_pt, &inode);
  dir_close (dir);
  struct file *f = file_open (inode);
  return f;
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool filesys_remove (const char *name)
{
  if (strcmp (name, "/") == 0)
    {
      return false;
    }
  /* Akshat drove here */
  char path_pt[strlen (name) + 1];
  char file_pt[strlen (name) + 1];
  separate_path (name, path_pt, file_pt);
  if (strcmp (file_pt, ".") == 0 || strcmp (file_pt, "..") == 0)
    {
      return false;
    }

  struct dir *dir = open_dir (path_pt);
  bool success = dir != NULL && dir_remove (dir, file_pt);
  dir_close (dir);

  return success;
}

/* Formats the file system. */
static void do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR, 16))
    PANIC ("root directory creation failed");
  free_map_close ();
  printf ("done.\n");
}
