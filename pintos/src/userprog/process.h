#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (int exit_status);
void process_activate (void);
bool is_valid(const void *addr);
bool process_remove(const char *file);
int process_open(const char *file);
int process_filesize(int fd);
unsigned process_tell(int fd);
void process_close(int fd);
bool process_create(const char *file, unsigned initial_size);
void process_seek(int fd, unsigned position);
int process_write(int fd, const void *buffer, unsigned size);
int process_read(int fd, void *buffer, unsigned size);
#endif /* userprog/process.h */
