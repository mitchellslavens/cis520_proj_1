#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "threads/thread.h"

void syscall_init (void);
void term_process (int);
void verify_ptr (const void *);
void close_file(struct list*, int);

struct proc_file
{
  struct file* proc_file_ptr;
  int fd;
  struct list_elem elem;
};

#endif /* userprog/syscall.h */
