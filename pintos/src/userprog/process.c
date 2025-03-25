


#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

/* Joshua drove here*/
#include "userprog/syscall.h"
#include "devices/input.h"


static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);


/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t process_execute (const char *file_name)
{
  char *fn_copy;
  //char *fn_copy2;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL){
    return TID_ERROR;
  }

  strlcpy (fn_copy, file_name, PGSIZE);

  /* Avi drove here */
  int strlen = 0;
  while(*(fn_copy + strlen) != ' ' && *(fn_copy + strlen) != '\0'){
    strlen++;
  }
  strlen++;

  char exec_name[strlen];
  for(int i = 0; i < strlen; i++){
    exec_name[i] = *(fn_copy + i);
  }
  /* Joshua drove here */
  exec_name[strlen-1] = '\0';
   // printf("FILE NAME IS: d%sd\n", args[0]);
  tid = thread_create (exec_name, PRI_DEFAULT, start_process, fn_copy);
  if (tid == TID_ERROR){
   palloc_free_page (fn_copy);
  }
  
  return tid;
}


/* A thread function that loads a user process and starts it
   running. */
static void start_process (void* file_name_)
{

  char* file_name = file_name_;
  struct intr_frame if_;
  bool success;
  
  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (file_name, &if_.eip, &if_.esp);

  sema_up(&thread_current()->execute_sema);
  /* If load failed, quit. */
  palloc_free_page (file_name); 
  if (!success) {
    thread_exit (-1);
  }
  //sema_init(&wait_sema, 0);

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int process_wait (tid_t child_tid) {
  // TO DO: IMPLEMENT -1 RETURN ON KERNEL EXIT
  /*Child list is empty*/
  /* Avi drove here */
  if (child_tid == -1){
    return -1;
  }
  if(list_empty(&thread_current()->children)) {
    return -1;
  }
  int found = 0;
  struct list_elem* current_child = list_head(&thread_current()->children);
  struct thread *child;
  
  while (current_child->next != NULL){
   /* Joshua drove here */
    child = list_entry(current_child, struct thread, child_elem);
    if(child_tid == child->tid){
      sema_down(&child->wait_sema);
      found = 1;
      break;
    }

    current_child = current_child->next;
  }
  if (found == 0) {
    return -1; /* child is not found in child list */
  }
  /* Avi drove here */
  int exit_status = child->exit_status;
  list_remove(&child->child_elem);
  sema_up(&child->zombie_sema);
  return exit_status;
}

/* Free the current process's resources. */
void process_exit (int exit_status)
{
  // if (exit_status == -1) {
  //   printf("thread name: %s", thread_current()->name);
  // }
  /* Akshat drove here */
  printf ("%s: exit(%d)\n", thread_current()->name, exit_status);
  struct thread *cur = thread_current ();
  thread_current()->exit_status = exit_status;
  uint32_t *pd;

  /* Joshua drove here */
  if(!list_empty(&thread_current()->children)){
    struct list_elem* curr_child = list_front(&thread_current()->children);
    while(curr_child->next != NULL){
      struct thread* child = list_entry(curr_child, struct thread, child_elem);
      //printf("RELEASE %s\n", child->name);
      curr_child = curr_child->next;
      sema_up(&child->zombie_sema);
    }
  }

  /* Akshat drove here */
  if(thread_current()->files[0] != NULL){
    //lock_acquire(get_file_lock());
    file_allow_write(thread_current()->files[0]);
    file_close(thread_current()->files[0]);
    //lock_release(get_file_lock());
    thread_current()->files[0] = NULL;
  }
  
  for(int i = 2; i < MAX_OPENED_FILES; i++){
    if(thread_current()->files[i] != NULL){
      process_close(i);
    }
  }

  sema_up(&thread_current()->wait_sema);
  sema_down(&thread_current()->zombie_sema);
  
  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL)
  {
    /* Correct ordering here is crucial.  We must set
        cur->pagedir to NULL before switching page directories,
        so that a timer interrupt can't switch back to the
        process page directory.  We must activate the base page
        directory before destroying the process's page
        directory, or our active page directory will be one
        that's been freed (and cleared). */
    cur->pagedir = NULL;
    pagedir_activate (NULL);
    pagedir_destroy (pd);
  }
}

/* Returns whether a certain address is valid (not null, user address, and 
on an existing page) */
bool is_valid(const void *addr) {
  /* Joshua drove here */
    return addr != NULL && is_user_vaddr(addr) && pagedir_get_page(thread_current()->pagedir, addr); 
}


/* Deletes the file called file. Returns true if successful, false otherwise. 
   A file may be removed regardless of whether it is open or closed, and 
   removing an open file does not close it */
bool process_remove(const char *file){
  /* Joshua drove here */
  if(file == NULL || !is_valid(file)){
    thread_exit(-1);
  }
  int ctr = 0;
  while(*(file + ctr) != '\0'){
    ctr++;
    if (!is_valid((file)+ctr)) {
      thread_exit(-1);
    }
  }
  //lock_acquire(get_file_lock());
  bool ret = filesys_remove(file);
  //lock_release(get_file_lock());

  return ret;
}

/* Opens the file called file. Returns a nonnegative integer handle called a 
   "file descriptor" (fd) or -1 if the file could not be opened. */
int process_open(const char *file){
  /* Avi drove here */
  if(file == NULL){
    thread_exit(-1);
  } 
  if (!is_valid((file))) {
    thread_exit(-1);
  }
  int ctr = 0;
  while(*(file + ctr) != '\0'){
    if (!is_valid((file)+ctr)) {
      thread_exit(-1);
    }
      ctr++;
  }
  //check if too many files open
  /* Akshat drove here */
  struct file **file_list = thread_current()->files;
  struct file* curr = filesys_open(file);
  if (curr == NULL) {
        return -1;
      }
  int index = 2;
  while(index < MAX_OPENED_FILES) {
    if (file_list[index] == NULL) {
      file_list[index] = curr;
      return index;
    }
    index++;
  }
  file_close(curr);
  //check if list is empty
  return -1;
}

/* Returns the size, in bytes, of the file open as fd. */
int process_filesize(int fd){
  /* Joshua drove here */
  if(fd < 2 || fd >= MAX_OPENED_FILES){
    thread_exit(-1);
  }
  struct file* file = thread_current()->files[fd];
  //lock_acquire(get_file_lock());
  int ret = file_length(file);
  //lock_release(get_file_lock());

  return ret;
}

/* Returns the position of the next byte to be read or written in open file 
   fd, expressed in bytes from the beginning of the file. */
unsigned process_tell(int fd){
  /* Joshua drove here */
  if(fd < 2 || fd >= MAX_OPENED_FILES){
    thread_exit(-1);
  }
  struct file* file = thread_current()->files[fd];
  if(file == NULL){
    thread_exit(-1);
  }
  //lock_acquire(get_file_lock());
  int ret = file_tell(file);
  //lock_release(get_file_lock());

  return ret;
}

/* Closes file descriptor fd. Exiting or terminating a process implicitly 
   closes all its open file descriptors, as if by calling this function for 
   each one. */
void process_close(int fd){
  /* Avi drove here */
  if(fd < 2 || fd >= MAX_OPENED_FILES){
    thread_exit(-1);
  }
  struct file* file = thread_current()->files[fd];
  if(file == NULL){
    thread_exit(-1);
  }
  //lock_acquire(get_file_lock());
  file_close(file);
  //lock_release(get_file_lock());
  thread_current()->files[fd] = NULL;
  return;
}

/* Creates a new file called file initially initial_size bytes in size. 
   Returns true if successful, false otherwise. Creating a new file does not 
   open it: opening the new file is a separate operation which would require 
   a open system call. */
bool process_create(const char *file, unsigned initial_size){
  /* Avi drove here */
  if(file == NULL || !is_valid((void*)file) ||  *file == '\0'){
    thread_exit(-1); 
  }
  for(int i = 0; *(file + i) != '\0'; i++){
    if(i > 14){
      return false;
    }
    if(!is_valid((void*)(file + i))){
      thread_exit(-1);
    }
  }
  //lock_acquire(get_file_lock());
  bool out = filesys_create(file, initial_size, false);
  //lock_release(get_file_lock());

  return out;
}

/* Changes the next byte to be read or written in open file fd to position, 
   expressed in bytes from the beginning of the file. (Thus, a position of 
   0 is the file's start.) */
void process_seek(int fd, unsigned position) {
  /* Akshat drove here */
  if(fd < 2 || fd >= MAX_OPENED_FILES) {
    thread_exit(-1);
  }
  struct file* file = thread_current()->files[fd];
  if(file == NULL) {
    thread_exit(-1);
  }
  //ock_acquire(get_file_lock());
  file_seek(file, position);
  //lock_release(get_file_lock());
  return;
}

/* Writes size bytes from buffer to the open file fd. 
   Returns the number of bytes actually written, which may be less than size 
   if some bytes could not be written.
   Writing past end-of-file would normally extend the file, but file growth is 
   not implemented by the basic file system. The expected behavior is to write 
   as many bytes as possible up to end-of-file and return the actual number 
   written, or 0 if no bytes could be written at all. */

int process_write(int fd, const void *buffer, unsigned size){
  /* Joshua drove here */
  if(fd < 1 || fd >= MAX_OPENED_FILES){
    thread_exit(-1);
  }
  // if(!is_valid(buffer) || !is_valid((void*)((char*)buffer + size))){
  //   thread_exit(-1);
  // }
  for (unsigned i = 0; i < size; i += PGSIZE) {
    if (!is_valid((void*)((char*)buffer + i))){
      thread_exit(-1);
    }
  }
  if(fd == 1){
    putbuf(buffer, size);
    return size;
  } else{
    /* Akshat drove here */
    struct file* this_file;
    this_file = thread_current()->files[fd];
    if(this_file == NULL){
      thread_exit(-1);
    }
    // Joshua drove here
    if(get_is_directory(this_file)){
      return -1;
    }
    //lock_acquire(get_file_lock());
    int ret = file_write(this_file, buffer, size);
    //lock_release(get_file_lock());
    return ret;
  }
  
}

/* Reads size bytes from the file open as fd into buffer. Returns the number 
   of bytes actually read (0 at end of file), or -1 if the file could not be 
   read (due to a condition other than end of file). fd 0 reads from the 
   keyboard using input_getc().*/
int process_read(int fd, void *buffer, unsigned size){
  /* Akshat drove here */
  if(fd < 0 || fd == 1 || fd >= MAX_OPENED_FILES){
    thread_exit(-1);
  }
  if(!is_valid(buffer) || !is_valid((void*)((char*)buffer + size))){
    thread_exit(-1);
  }
  struct file* this_file = NULL;
  if(fd == 0){
  unsigned counter = 0;
  while(counter < size){
    input_getc();
    counter++;
  }
  return size;
  }  else{
    this_file = thread_current()->files[fd];
    if(this_file == NULL){
      thread_exit(-1);
    }
  } 
  //lock_acquire(get_file_lock());
  int ret = file_read(this_file, buffer, size);
  //lock_release(get_file_lock());
  return ret;
  
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32 /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32 /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32 /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16 /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
{
  unsigned char e_ident[16];
  Elf32_Half e_type;
  Elf32_Half e_machine;
  Elf32_Word e_version;
  Elf32_Addr e_entry;
  Elf32_Off e_phoff;
  Elf32_Off e_shoff;
  Elf32_Word e_flags;
  Elf32_Half e_ehsize;
  Elf32_Half e_phentsize;
  Elf32_Half e_phnum;
  Elf32_Half e_shentsize;
  Elf32_Half e_shnum;
  Elf32_Half e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
{
  Elf32_Word p_type;
  Elf32_Off p_offset;
  Elf32_Addr p_vaddr;
  Elf32_Addr p_paddr;
  Elf32_Word p_filesz;
  Elf32_Word p_memsz;
  Elf32_Word p_flags;
  Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL 0           /* Ignore. */
#define PT_LOAD 1           /* Loadable segment. */
#define PT_DYNAMIC 2        /* Dynamic linking info. */
#define PT_INTERP 3         /* Name of dynamic loader. */
#define PT_NOTE 4           /* Auxiliary info. */
#define PT_SHLIB 5          /* Reserved. */
#define PT_PHDR 6           /* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

static bool setup_stack (void **esp, char *file_name);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool load (const char *file_name, void (**eip) (void), void **esp)
{

  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  int strlen = 0;
  while(*(file_name + strlen) != ' ' && *(file_name + strlen) != '\0'){
    strlen++;
  }
  strlen++;

  char exec_name[strlen];
  for(int i = 0; i < strlen; i++){
    exec_name[i] = *(file_name + i);
  }
  /* Joshua drove here */
  exec_name[strlen-1] = '\0';


  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL)
    goto done;
  process_activate ();

  /* Open executable file. */

  /* Avi drove here */
 // lock_acquire(get_file_lock());
  file = filesys_open (exec_name);
 // lock_release(get_file_lock());

  if (file == NULL)
    {
      printf ("load: %s: open failed\n", exec_name);
      goto done;
    }

  /* Joshua drove here */
  thread_current()->files[0] = file;
 // lock_acquire(get_file_lock());
  file_deny_write(file);
 // lock_release(get_file_lock());

  /* Read and verify executable header. */
  /* Joshua drove here */
  //lock_acquire(get_file_lock());
  int off = file_read (file, &ehdr, sizeof ehdr);
  //lock_release(get_file_lock());
  if (off != sizeof ehdr ||
      memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7) || ehdr.e_type != 2 ||
      ehdr.e_machine != 3 || ehdr.e_version != 1 ||
      ehdr.e_phentsize != sizeof (struct Elf32_Phdr) || ehdr.e_phnum > 1024)
    {
      printf ("load: %s: error loading executable\n", exec_name);
      goto done;
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++)
    {
      struct Elf32_Phdr phdr;

      /* Joshua drove here */
      //lock_acquire(get_file_lock());
      int filesize = file_length (file);
      //lock_release(get_file_lock());
      if (file_ofs < 0 || file_ofs > filesize)
        goto done;

      /* Joshua drove here */
     // lock_acquire(get_file_lock());
      file_seek (file, file_ofs);
     // lock_release(get_file_lock());

      /* Joshua drove here */
     // lock_acquire(get_file_lock());
      int off2 = file_read (file, &phdr, sizeof phdr);
    // lock_release(get_file_lock());
      if (off2 != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type)
        {
          case PT_NULL:
          case PT_NOTE:
          case PT_PHDR:
          case PT_STACK:
          default:
            /* Ignore this segment. */
            break;
          case PT_DYNAMIC:
          case PT_INTERP:
          case PT_SHLIB:
            goto done;
          case PT_LOAD:
            if (validate_segment (&phdr, file))
              {
                bool writable = (phdr.p_flags & PF_W) != 0;
                uint32_t file_page = phdr.p_offset & ~PGMASK;
                uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
                uint32_t page_offset = phdr.p_vaddr & PGMASK;
                uint32_t read_bytes, zero_bytes;
                if (phdr.p_filesz > 0)
                  {
                    /* Normal segment.
                       Read initial part from disk and zero the rest. */
                    read_bytes = page_offset + phdr.p_filesz;
                    zero_bytes =
                        (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE) -
                         read_bytes);
                  }
                else
                  {
                    /* Entirely zero.
                       Don't read anything from disk. */
                    read_bytes = 0;
                    zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                  }
                if (!load_segment (file, file_page, (void *) mem_page,
                                   read_bytes, zero_bytes, writable))
                  goto done;
              }
            else
              goto done;
            break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp, (char*)file_name))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;
done:
  /* We arrive here whether the load is successful or not. */
    t->load_success = success;
  //file_close (file);
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool validate_segment (const struct Elf32_Phdr *phdr, struct file *file)
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable)
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  /* Joshua drove here */
  //lock_acquire(get_file_lock());
  file_seek (file, ofs);
 //lock_release(get_file_lock());
  while (read_bytes > 0 || zero_bytes > 0)
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      /* Joshua drove here */     
      //lock_acquire(get_file_lock());
      int off = file_read (file, kpage, page_read_bytes);
      //lock_release(get_file_lock());
      if (off != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false;
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable))
        {
          palloc_free_page (kpage);
          return false;
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}


/* Checks if esp is less than PHYS_BASE - PGSIZE, which indicates stack overflow
   In the case of stack overflow, exits and frees args*/
static void check_stack_overflow(void **esp){
  /* Avi drove here */
  if (*esp < (void*)((char*)PHYS_BASE - PGSIZE)) {
    //stack overflow
    //palloc_free_page(args);
    thread_exit(-1);
  } 
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool setup_stack (void **esp, char* file_name)
{
  // TODO: CHECK FOR STACK OVERFLOW
  // ASSERT(false);
  uint8_t *kpage;
  bool success = false;

  /* Akshat drove here */
  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL)
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success){ 

        //count args
       // printf("File s : %s", file_name);
        int argc = 0;
        char* line = file_name;
        bool notdelim = false;
        while(*line != '\0'){
          if(*line == ' ' || *line == '\t'){
            if(notdelim){
                argc++;
            }
              notdelim = false;
          } else {
              notdelim = true;
          }
          line = line + 1;
        }
        if(notdelim){
          argc++;
        }

        char* save_ptr;
        char* cur = strtok_r(file_name, " \t", &save_ptr);
        int arg_counter = 0;

        *esp = PHYS_BASE;
        uint32_t pointers[argc + 1];
        while (cur != NULL) {
          int length = strlen(cur) + 1;
          *esp = (void*)((char*) *esp - length);
          check_stack_overflow(esp);
          strlcpy((char*)*esp, cur, length);
          pointers[arg_counter] = (uint32_t) *esp;
          cur = strtok_r(NULL, " \t", &save_ptr);
          arg_counter++;

        }

        
        /* Joshua drove here */
        // add uint8_t 0 word align
        *esp = (void*)((char*) *esp - ((uint32_t)*esp %4));
        check_stack_overflow(esp);
        char *null_sentinel = NULL;
        *esp = (void*) ((char*) *esp - sizeof(char *));
        check_stack_overflow(esp);
        memcpy(*esp, &null_sentinel, sizeof(char *));



        // add the list of pointers 
        //i--;
        
        int i = argc - 1;
        /* Akshat drove here */
        while (i >= 0) {
          
          *esp = (void*)((uint32_t*) *esp - 1);
          check_stack_overflow(esp);
          memcpy((uint32_t*)*esp, &pointers[i], sizeof(uint32_t));
          i--;
        }
        pointers[argc] = (uint32_t)*esp;

        //add pointer to arg list
        *esp = (void*)((uint32_t*) *esp - 1);
        check_stack_overflow(esp);
        memcpy((uint32_t*)*esp, &pointers[argc], sizeof(int));
        
        //add argc (i - 1)
        *esp = (void*)((int*) *esp - 1);
        check_stack_overflow(esp);
        memcpy((int*)*esp, &argc, sizeof(int));

        //add return address
        *esp = (void*) ((uint32_t*) *esp - 1);
        check_stack_overflow(esp);
        //hex_dump((uintptr_t) *esp, *esp,(char*)PHYS_BASE - (char*)*esp, true);
        //objdump80x86();
      }
      else
        palloc_free_page (kpage);
    }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL &&
          pagedir_set_page (t->pagedir, upage, kpage, writable));
}
