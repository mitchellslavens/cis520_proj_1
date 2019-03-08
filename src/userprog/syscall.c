#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "process.h"
#include "list.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

#define USER_VADDR_START ((void *) 0x08084000)

static void syscall_handler (struct intr_frame *);

//struct lock file_system_lock;

void syscall_init (void)
{
  //lock_init(&file_system_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/* Call this to make sure that the pointer is valid. That is, in the right
address range and that a page exists at the pointer location. */
void verify_ptr(const void * vaddr)
{
  if (!is_user_vaddr(vaddr))
  {
    printf("not a valid vaddr\n");
    term_process(-1);
  }
  void *ptr = pagedir_get_page(thread_current()->pagedir, vaddr);
  if(!ptr)
  {
    printf("get page is screwed up\n");
    term_process(-1);
  }
}

/* Call this to forcefully terminate a process */
void term_process(int code)
{
  struct list_elem *child_elem ;
  printf("in term_process\n");
  // TODO: is head.next the tail or null for an empty list?
  for(child_elem = list_begin(&thread_current()->parent->child_list); child_elem != list_end(&thread_current()->parent->child_list); child_elem = list_next(child_elem))
  {
    // TODO: Do we need a check to make sure we actually have an element?
    struct child *child_thread = list_entry(child_elem, struct child, elem);
    if (child_thread->tid == thread_current()->tid)
    {
      child_thread->dead = true;
      child_thread->exit_code = code;
    }
  }

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
      shutdown_power_off();
      break;
    case SYS_EXIT:
    {
      verify_ptr(ptr+2);
      term_process(*(ptr+2));
      break;
    }
    case SYS_EXEC:
    {
      //printf("In SYS_EXEC\n");
      verify_ptr(ptr + 2);
      verify_ptr(*(ptr + 2));
      f->eax = execute_process(*(ptr + 2));
      break;
    }
    case SYS_WAIT:
    {
      verify_ptr(ptr+2);
      f->eax = process_wait(*(ptr+2));
      break;
    }
    case SYS_CREATE:
    {
      verify_ptr(ptr + 6);
      verify_ptr(*(ptr + 5));
      acquire_file_lock();
      f->eax = filesys_create(*(ptr+5), *(ptr+6));
      release_file_lock();
      break;
    }
    case SYS_REMOVE:
    {
      verify_ptr(ptr + 2);
      verify_ptr(*(ptr + 2));
      acquire_file_lock();
      if(filesys_remove(*(ptr + 2)) == NULL)
      {
        f->eax = false;
      }
      else
      {
        f->eax = true;
      }
      release_file_lock();
      break;
    }
    case SYS_OPEN:
    {
      verify_ptr(ptr + 2);
      verify_ptr(*(ptr + 2));
      acquire_file_lock();
      struct file * file_ptr = filesys_open(*(p + 2));
      release_file_lock();
      if(file_ptr == NULL)
      {
        f->eax = -1;
      }
      else
      {
        //struct proc_file *process_file = malloc(sizeof(*process_file));
        //process_file->ptr = 
      }
      break;
    }
    case SYS_FILESIZE:
      break;
    case SYS_READ:
      printf("in read\n");
      break;
    case SYS_WRITE:
    {
      verify_ptr(ptr + 8); // checks that the 'size' param is there
      verify_ptr(*(ptr + 7)); // goes to the address of the buffer and checks it's validity
      if(*(ptr + 6) == 1) // if the 'fd' is 1 it writes to console
      {
        // defined in lib/kernel/console.c
        // void putbuf (const char *buffer, size_t n)
        putbuf(*(ptr + 7), *(ptr+8));
        f->eax = *(ptr+8);
      }


      break;
    }
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


/* Runs the process passed to the cmd_line.
   Checks
*/
int execute_process(const char* cmd_line)
{
  acquire_file_lock();

  char *rest;
  char *filename_copy = malloc(strlen(cmd_line) + 1);
  strlcpy(filename_copy, cmd_line, strlen(cmd_line) + 1);

  filename_copy = strtok_r(filename_copy, " ", &rest);

  // If filename_copy doesn't exist it fails
  struct file* open_file = filesys_open(filename_copy);

  if(open_file==NULL)
  {
    release_file_lock();
    return -1;
  }
  else
  {
    file_close(open_file);
    release_file_lock();
    return process_execute(cmd_line);
  }
}
