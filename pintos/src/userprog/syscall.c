#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "pagedir.h"
#include "userprog/process.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
// joshua drove here
#include "devices/shutdown.h"
#include "lib/user/syscall.h"
#include "filesys/filesys.h"
static void syscall_handler (struct intr_frame*);
void syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/* Akshat drove here */
static void* get_val (void* addr)
{

  void* addr2 = (void*) ((char*) addr + 3);
  if (addr == NULL)
    {
      thread_exit (-1);
    }
  /*bad arg*/
  if (!is_user_vaddr (addr))
    {
      thread_exit (-1);
    }
  if (!pagedir_get_page (thread_current ()->pagedir, addr))
    {
      thread_exit (-1);
    }
  if (addr2 == NULL)
    {
      thread_exit (-1);
    }
  if (!is_user_vaddr (addr2))
    {
      thread_exit (-1);
    }
  if (!pagedir_get_page (thread_current ()->pagedir, addr2))
    {
      thread_exit (-1);
    }

  return addr;
}

static void syscall_handler (struct intr_frame* f)
{
  uint32_t* myEsp = f->esp;
  uint32_t* sys_num = (uint32_t*) get_val (myEsp);
  uint32_t argc = 0;
  switch (*sys_num)
    {
      case SYS_HALT:
        argc = 0;
        break;
      case SYS_EXIT:
      case SYS_EXEC:
      case SYS_WAIT:
      case SYS_REMOVE:
      case SYS_OPEN:
      case SYS_FILESIZE:
      case SYS_TELL:
      case SYS_CLOSE:
      case SYS_CHDIR:
      case SYS_MKDIR:
      case SYS_ISDIR:
      case SYS_INUMBER:
        argc = 1;
        break;
      case SYS_CREATE:
      case SYS_SEEK:
      case SYS_READDIR:
        argc = 2;
        break;
      case SYS_READ:
      case SYS_WRITE:
        argc = 3;
        break;
      default:
        ASSERT (0);
        break;
    }
  uint32_t argv[argc];
  uint32_t i = 0;
  // printf ("system call!\n");
  while (i < argc)
    {

      myEsp++;
      uint32_t* temp = (uint32_t*) get_val (myEsp);
      argv[i] = *temp;
      i++;
    }

  switch (*sys_num)
    {
      case SYS_HALT:
        shutdown_power_off ();
        break;
      case SYS_EXIT:
        thread_exit ((int) argv[0]);
        break;
      case SYS_EXEC:
        char* file_name = (char*) argv[0];
        int temp = 0;

        while (is_valid (file_name + temp) && *(file_name + temp) != '\0')
          {
            if (temp > 200)
              {
                thread_exit (-1);
              }
            temp++;
          }
        if (!is_valid (file_name + temp))
          {
            thread_exit (-1);
          }
        tid_t tid = process_execute ((char*) argv[0]);

        // look for child tid
        struct list children = thread_current ()->children;
        struct list_elem* current_child = list_head (&children);
        struct thread* child;
        int found = 0;
        while (current_child->next != NULL)
          {
            child = list_entry (current_child, struct thread, child_elem);
            if (tid == child->tid)
              {
                found = 1;
                break;
              }
            current_child = current_child->next;
          }
        if (!found)
          {
            thread_exit (-1);
          }
        sema_down (&child->execute_sema);

        if (!child->load_success)
          {
            f->eax = -1;
          }
        else
          {
            f->eax = tid;
          }
        break;
      case SYS_REMOVE:
        f->eax = process_remove ((char*) argv[0]);
        break;
      case SYS_OPEN:
        f->eax = process_open ((char*) argv[0]);
        break;
      case SYS_FILESIZE:
        f->eax = process_filesize ((int) argv[0]);
        break;
      case SYS_TELL:
        f->eax = process_tell ((int) argv[0]);
        break;
      case SYS_CLOSE:
        process_close ((int) argv[0]);
        break;
      case SYS_CREATE:
        f->eax = process_create ((char*) argv[0], (unsigned) argv[1]);
        break;
      case SYS_SEEK:
        process_seek ((int) argv[0], (unsigned) argv[1]);
        break;
      case SYS_WRITE:
        f->eax =
            process_write ((int) argv[0], (void*) argv[1], (unsigned) argv[2]);
        break;
      case SYS_READ:
        f->eax =
            process_read ((int) argv[0], (void*) argv[1], (unsigned) argv[2]);
        break;
      case SYS_WAIT:
        f->eax = process_wait ((tid_t) argv[0]);
        break;

      case SYS_CHDIR:
        // Avi drove here
        struct dir* dir = open_dir ((char*) argv[0]);
        if (dir == NULL)
          f->eax = false;
        else
          {
            dir_close (thread_current ()->curr_dir);
            thread_current ()->curr_dir = dir;
            f->eax = true;
          }
        break;
      case SYS_MKDIR:
        // Avi drove here
        char* string = (char*) argv[0];
        if (!string || !is_valid (string))
          {
            thread_exit (-1);
          }
        while (*string != '\0')
          {
            string++;
            if (!is_valid (string))
              {
                thread_exit (-1);
              }
          }
        f->eax = filesys_create ((char*) argv[0], 1, true);
        break;
      case SYS_ISDIR:
        // Joshua drove here
        if (argv[0] < 2 || argv[0] > MAX_OPENED_FILES)
          {
            thread_exit (-1);
          }
        if (thread_current ()->files[(int) argv[0]] == NULL)
          {
            f->eax = -1;
          }
        else
          {
            f->eax = get_is_directory (thread_current ()->files[(int) argv[0]]);
          }
        break;
      case SYS_INUMBER:
        // Akshat drove here
        if (argv[0] < 2 || argv[0] > MAX_OPENED_FILES)
          {
            thread_exit (-1);
          }
        if (thread_current ()->files[(int) argv[0]] == NULL)
          {
            f->eax = -1;
          }
        else
          {
            f->eax =
                get_sector_number (thread_current ()->files[(int) argv[0]]);
          }
        break;
      case SYS_READDIR:
        // Joshua drove here
        char* string1 = (char*) argv[1];
        if (!string1 || !is_valid (string1))
          {
            thread_exit (-1);
          }

        int count = 0;
        while (*(string1 + count) != '\0')
          {
            count++;
            if (!is_valid ((string1 + count)))
              {
                thread_exit (-1);
              }
          }
        if (argv[0] < 2 || argv[0] > MAX_OPENED_FILES)
          {
            thread_exit (-1);
          }
        struct file* this_file = thread_current ()->files[argv[0]];
        if (this_file == NULL || !get_is_directory (this_file))
          {
            f->eax = -1;
          }
        else
          {
            f->eax = dir_readdir (get_dir (this_file), (char*) argv[1]);
          }
        break;
      default:
        thread_exit (-1);
        break;
    }
}
