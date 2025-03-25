#ifndef __LIB_SYSCALL_NR_H
#define __LIB_SYSCALL_NR_H

/* System call numbers. */
enum
{
  /* Projects 2 and later. */
  SYS_HALT,     /* Halt the operating system. (0 args)*/
  SYS_EXIT,     /* Terminate this process. (1 args)*/
  SYS_EXEC,     /* Start another process. (1 args)*/
  SYS_WAIT,     /* Wait for a child process to die. (1 args)*/
  SYS_CREATE,   /* Create a file. (2 args)*/
  SYS_REMOVE,   /* Delete a file. (1 args)*/
  SYS_OPEN,     /* Open a file. (1 args)*/
  SYS_FILESIZE, /* Obtain a file's size. (1 args)*/
  SYS_READ,     /* Read from a file. (3 args)*/
  SYS_WRITE,    /* Write to a file. (3 args)*/
  SYS_SEEK,     /* Change position in a file. (2 args)*/
  SYS_TELL,     /* Report current position in a file. (1 args)*/
  SYS_CLOSE,    /* Close a file. (1 args)*/

  /* Not needed in UTCS Pintos project */
  SYS_MMAP,   /* Map a file into memory. */
  SYS_MUNMAP, /* Remove a memory mapping. */

  /* Project 4 only. */
  SYS_CHDIR,   /* Change the current directory. */
  SYS_MKDIR,   /* Create a directory. */
  SYS_READDIR, /* Reads a directory entry. */
  SYS_ISDIR,   /* Tests if a fd represents a directory. */
  SYS_INUMBER  /* Returns the inode number for a fd. */
};

#endif /* lib/syscall-nr.h */
