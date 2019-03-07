#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "process.h"

#define USER_VADDR_START ((void *) 0x08084000)

static void syscall_handler (struct intr_frame *);

struct lock file_system_lock;

void
syscall_init (void)
{
  lock_init(&file_system_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/* Call this to make sure that the pointer is valid. That is, in the right
address range and that a page exists at the pointer location. */
void verify_ptr(const void * vaddr)
{
  if (!is_user_vaddr(vaddr))
  {
    term_process(-1);
  }
  void *ptr = pagedir_get_page(thread_current()->pagedir, vaddr);
  if(!ptr)
  {
    term_process(-1);
  }
}

/* Call this to forcefully terminate a process */
void term_process(int code)
{
  struct list_elem *child_elem = list_begin(&thread_current()->parent->child_list);
  do
  {
    struct thread *child_thread = list_entry(child_elem, struct thread, elem);
    if (child_thread->tid == thread_current()->tid)
    {
      child_thread->has_parent = true;
    }
  } while(child_elem != list_end(&thread_current()->parent->child_list));
  thread_current()->exit_code = code;
  if(thread_current()->parent->wait_thread == thread_current()->tid)
  {
    sema_up(&thread_current()->parent->child_sema);
  }
  thread_exit();
}

static void
syscall_handler (struct intr_frame *f UNUSED)
{
  int * ptr = f->esp;
  verify_ptr(ptr);
  int sys_call = *ptr;
  switch(sys_call)
  {
    case SYS_HALT:
      break;
    case SYS_EXIT:
      break;
    case SYS_EXEC:
      printf("In SYS_EXEC\n");
      break;
    case SYS_WAIT:
      break;
    case SYS_CREATE:
      break;
    case SYS_REMOVE:
      break;
    case SYS_OPEN:
      break;
    case SYS_FILESIZE:
      break;
    case SYS_READ:
      printf("in read\n");
      break;
    case SYS_WRITE:
      printf("in write\n");
      break;
    case SYS_SEEK:
      break;
    case SYS_TELL:
      break;
    case SYS_CLOSE:
      break;
    default:
      break;




  }

  /*
  if(f == NULL)
    return;
  printf ("system call!\n");
  thread_exit ();
  */
}
