#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "inode.h"
#include <stdio.h>
/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44
#define PTR_IN_BLOCK 128 /* BLOCK_SIZE / PTR_SIZE. (512 / 4 = 128)*/
#define NUM_DIRECT 8

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
{
  off_t length;
  unsigned magic; /* Magic number. */
  // Joshua drove here
  block_sector_t
      direct[NUM_DIRECT]; /* Inode content. 8 direct, 1 indirect, 1 sec*/
  block_sector_t indirect;
  block_sector_t second_indirect;
  uint32_t isdir;
  uint32_t unused[115];
};

bool allocate_sectors (struct inode_disk *data, uint32_t offset, uint32_t size,
                       block_sector_t sector);

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

/* In-memory inode. */
struct inode
{
  struct list_elem elem; /* Element in inode list. */
  block_sector_t sector; /* Sector number of disk location. */
  int open_cnt;          /* Number of openers. */
  bool removed;          /* True if deleted, false otherwise. */
  int deny_write_cnt;    /* 0: writes ok, >0: deny writes. */
  struct inode_disk data;

  // Joshua drove here
  uint32_t actual_data_held;

  // Avi drove here
  struct lock grow_file;
  struct lock dir_lock;
};

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t byte_to_sector (const struct inode *inode, off_t pos)
{
  ASSERT (inode != NULL);

  if (pos > inode->data.length)
    {
      return -1;
    }
  // if in first 8 direct
  // Akshat drove here
  if (pos < BLOCK_SECTOR_SIZE * NUM_DIRECT)
    {
      return inode->data.direct[pos / BLOCK_SECTOR_SIZE];
    }
  pos -= BLOCK_SECTOR_SIZE * NUM_DIRECT;
  if (pos < BLOCK_SECTOR_SIZE * PTR_IN_BLOCK)
    {
      block_sector_t ptr_block = inode->data.indirect;
      block_sector_t buffer[PTR_IN_BLOCK];
      block_read (fs_device, ptr_block, &buffer);
      unsigned index = pos / BLOCK_SECTOR_SIZE;
      return buffer[index];
    }
  pos -= BLOCK_SECTOR_SIZE * PTR_IN_BLOCK;
  if (pos < BLOCK_SECTOR_SIZE * (PTR_IN_BLOCK * PTR_IN_BLOCK))
    {
      block_sector_t ptr_block = inode->data.second_indirect;
      block_sector_t buffer[PTR_IN_BLOCK];
      block_read (fs_device, ptr_block, &buffer);
      block_sector_t index = (pos / BLOCK_SECTOR_SIZE) / PTR_IN_BLOCK;
      block_sector_t index2 = (pos / BLOCK_SECTOR_SIZE) % PTR_IN_BLOCK;
      block_sector_t buffer2[PTR_IN_BLOCK];
      block_read (fs_device, buffer[index], &buffer2);
      return buffer2[index2];
    }
  return -1;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void inode_init (void) { list_init (&open_inodes); }

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool inode_create (block_sector_t sector, off_t length, bool isdir)
{
  struct inode_disk *disk_inode = NULL;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
    {
      // Joshua drove here
      disk_inode->length = 0;
      disk_inode->magic = INODE_MAGIC;
      disk_inode->second_indirect = 0;
      disk_inode->indirect = 0;
      disk_inode->isdir = isdir;
      if (!allocate_sectors (disk_inode, 0, length, sector))
        {
          free (disk_inode);
          return false;
        }
    }
  return true;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *inode_open (block_sector_t sector)
{
  struct list_elem *elem;
  struct inode *inode;

  /* check if need to reopen inode */
  for (elem = list_begin (&open_inodes); elem != list_end (&open_inodes);
       elem = list_next (elem))
    {
      inode = list_entry (elem, struct inode, elem);
      if (inode->sector == sector)
        {
          inode_reopen (inode);
          return inode;
        }
    }

  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  // printf("\nopen sector: %d", sector);
  /* create inode to return */
  list_push_front (&open_inodes, &inode->elem);

  inode->sector = sector;
  inode->removed = false;
  inode->deny_write_cnt = 0;
  inode->open_cnt = 1;
  block_read (fs_device, inode->sector, &inode->data);

  // Avi drove here
  lock_init (&inode->grow_file);
  lock_init (&inode->dir_lock);
  inode->actual_data_held = inode->data.length;
  return inode;
}

/* Reopens and returns INODE. */
struct inode *inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk. (Does it?  Check code.)
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void inode_close (struct inode *inode)
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
          // Joshua drove here
          free_map_release (inode->sector, 1);
          off_t size = inode->data.length;
          uint32_t counter = 0;
          while (size > 0 && counter < 8)
            {
              free_map_release (inode->data.direct[counter], 1);
              size -= BLOCK_SECTOR_SIZE;
              counter++;
            }
          counter = 0;
          if (size > 0)
            {
              block_sector_t buffer[PTR_IN_BLOCK];
              block_write (fs_device, inode->data.indirect, &buffer);
              while (size > 0 && counter < PTR_IN_BLOCK)
                {
                  free_map_release (buffer[counter], 1);
                  size -= BLOCK_SECTOR_SIZE;
                  counter++;
                }
              counter = 0;
              if (size > 0)
                {
                  block_write (fs_device, inode->data.second_indirect, 
                          &buffer);
                  while (size > 0 && counter < PTR_IN_BLOCK)
                    {
                      block_sector_t buffer2[PTR_IN_BLOCK];
                      block_write (fs_device, buffer[counter], &buffer2);
                      int counter2 = 0;
                      while (size > 0 && counter2 < PTR_IN_BLOCK)
                        {
                          free_map_release (buffer2[counter2], 1);
                          size -= BLOCK_SECTOR_SIZE;
                          counter2++;
                        }
                      counter++;
                    }
                }
            }
        }

      free (inode);
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void inode_remove (struct inode *inode)
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t inode_read_at (struct inode *inode, void *buffer_, off_t size,
                     off_t offset)
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
      // Joshua drove here
      off_t inode_left = inode->actual_data_held - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Read full sector directly into caller's buffer. */
          block_read (fs_device, sector_idx, buffer + bytes_read);
        }
      else
        {
          /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
          if (bounce == NULL)
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                // ASSERT(0);
                break;
            }
          block_read (fs_device, sector_idx, bounce);
          memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
        }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
  free (bounce);
  // ASSERT(bytes_read != 0);
  return bytes_read;
}

/* Allocates a given amount of sectors as defined by size from offset.
  Akshat, Joshua, and Avi drove here */
bool allocate_sectors (struct inode_disk *data, uint32_t offset, uint32_t size,
                       block_sector_t sector)
{
  static char zeros[BLOCK_SECTOR_SIZE];
  for (int i = 0; i < BLOCK_SECTOR_SIZE; i++)
    {
      zeros[i] = 0;
    }
  block_sector_t curr_sector = bytes_to_sectors (data->length);
  uint32_t blocks_needed = bytes_to_sectors (offset + size) - curr_sector;

  while (blocks_needed > 0)
    {
      if (curr_sector < NUM_DIRECT)
        {
          /* allocate a direct */
          block_sector_t new;
          if (!free_map_allocate (1, &new))
            {
              return false;
            }
          block_write (fs_device, new, &zeros);
          data->direct[curr_sector] = new;
        }
      else if (curr_sector < NUM_DIRECT + PTR_IN_BLOCK)
        {
          /* allocate indirect */
          if (data->indirect == 0)
            {
              if (!free_map_allocate (1, &data->indirect))
                {
                  return false;
                }
              block_write (fs_device, data->indirect, &zeros);
            }
          block_sector_t buffer1[PTR_IN_BLOCK];
          block_read (fs_device, data->indirect, &buffer1);
          uint32_t index = curr_sector - NUM_DIRECT;
          free_map_allocate (1, &buffer1[index]);
          block_write (fs_device, buffer1[index], &zeros);
          block_write (fs_device, data->indirect, &buffer1);
        }
      else if (curr_sector <
               NUM_DIRECT + PTR_IN_BLOCK + PTR_IN_BLOCK * PTR_IN_BLOCK)
        {
          /* allocate second indirect */
          if (data->second_indirect == 0)
            {
              if (!free_map_allocate (1, &data->second_indirect))
                {
                  return false;
                }
              block_write (fs_device, data->second_indirect, &zeros);
            }
          uint32_t first_index =
              (curr_sector - NUM_DIRECT - PTR_IN_BLOCK) / PTR_IN_BLOCK;
          uint32_t second_index =
              (curr_sector - NUM_DIRECT - PTR_IN_BLOCK) % PTR_IN_BLOCK;
          block_sector_t buffer1[PTR_IN_BLOCK];
          block_read (fs_device, data->second_indirect, &buffer1);
          if (buffer1[first_index] == 0)
            {
              if (!free_map_allocate (1, &buffer1[first_index]))
                {
                  return false;
                }
              block_write (fs_device, buffer1[first_index], &zeros);
            }
          block_sector_t buffer2[PTR_IN_BLOCK];
          block_read (fs_device, buffer1[first_index], &buffer2);
          if (!free_map_allocate (1, &buffer2[second_index]))
            {
              return false;
            }
          block_write (fs_device, buffer2[second_index], &zeros);
          block_write (fs_device, buffer1[first_index], &buffer2);
          block_write (fs_device, data->second_indirect, &buffer1);
        }
      else
        {
          // should never get here
          PANIC ("out of inode space");
        }
      curr_sector++;
      blocks_needed--;
    }

  data->length = offset + size;
  block_write (fs_device, sector, data);
  return true;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                      off_t offset)
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t *bounce = NULL;

  if (inode->deny_write_cnt)
    return 0;

  /* if file extention needed */

  // Akshat drove here
  lock_acquire (&inode->grow_file);
  if (offset + size > inode->data.length &&
      !allocate_sectors (&inode->data, offset, size, inode->sector))
    {
      lock_release (&inode->grow_file);
      return false;
    }
  lock_release (&inode->grow_file);
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
          block_write (fs_device, sector_idx, buffer + bytes_written);
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
            block_read (fs_device, sector_idx, bounce);
          else
            memset (bounce, 0, BLOCK_SECTOR_SIZE);
          memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
          block_write (fs_device, sector_idx, bounce);
        }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }
  free (bounce);
  // Joshua drove here
  inode->actual_data_held = inode->data.length;
  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void inode_deny_write (struct inode *inode)
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void inode_allow_write (struct inode *inode)
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t inode_length (const struct inode *inode) { return inode->data.length; }

bool is_removed (struct inode *fnode)
{
  return fnode->removed;
} // why is this called fnode bruh

// Joshua drove here
/* Returns whether this inode is a directory */
bool is_directory (struct inode *inode)
{
  if (inode == NULL)
    {
      return false;
    }
  return inode->data.isdir;
}

// Joshua drove here
/* Returns directory lock for this inode. Used in directory.c for synch */

struct lock *get_dir_lock (struct inode *inode) { return &inode->dir_lock; }