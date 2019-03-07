#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);
void term_process (int);
void verify_ptr (const void *);

#endif /* userprog/syscall.h */
