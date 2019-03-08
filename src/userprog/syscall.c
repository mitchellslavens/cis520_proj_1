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
#include "threads/malloc.h"
#include <string.h>
#include "devices/shutdown.h"
#include "devices/input.h"

#define USER_VADDR_START ((void *) 0x08084000)

static void syscall_handler (struct intr_frame *);
struct proc_file *list_search(struct list* file_list, int fd);
int execute_process(const char* cmd_line);

//struct lock file_system_lock;

extern bool running;

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
    //printf("not a valid vaddr\n");
    term_process(-1);
  }
  void *ptr = pagedir_get_page(thread_current()->pagedir, vaddr);
  if(!ptr)
  {
    //printf("get page is screwed up\n");
    term_process(-1);
  }
}

/* Call this to forcefully terminate a process */
void term_process(int code)
{
  //printf("%d\n", code);
  struct list_elem *child_elem ;
  //printf("in term_process\n");
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
    //  printf("IN SYS_HALT\n");
      shutdown_power_off();
      break;
    case SYS_EXIT:
    {
      //printf("IN SYS_EXIT\n");
      verify_ptr(ptr+1);
      term_process(*(ptr+1));
      break;
    }
    case SYS_EXEC:
    {
      //printf("In SYS_EXEC\n");
      verify_ptr(ptr + 1);
      verify_ptr(*(ptr + 1));
      f->eax = execute_process(*(ptr + 1));
      break;
    }
    case SYS_WAIT:
    {
      //printf("IN SYS_WAIT\n");
      verify_ptr(ptr+1);
      f->eax = process_wait(*(ptr+1));
      break;
    }
    case SYS_CREATE:
    {
      //printf("IN SYS_CREATE\n");
      verify_ptr(ptr + 6);
      verify_ptr(*(ptr + 5));
      acquire_file_lock();
      f->eax = filesys_create(*(ptr+5), *(ptr+6));
      release_file_lock();
      break;
    }
    case SYS_REMOVE:
    {
      //printf("IN SYS_REMOVE\n");
      verify_ptr(ptr + 1);
      verify_ptr(*(ptr + 1));
      acquire_file_lock();
      if(filesys_remove(*(ptr + 1)) == NULL)
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
      //printf("IN SYS_OPEN\n");
      verify_ptr(ptr + 1);
      verify_ptr(*(ptr + 1));
      acquire_file_lock();
      struct file * file_ptr = filesys_open(*(ptr + 1));
      release_file_lock();
      if(file_ptr == NULL)
      {
        f->eax = -1;
      }
      else
      {
        struct proc_file *process_file = malloc(sizeof(*process_file));
        process_file->proc_file_ptr = file_ptr;
        process_file->fd = thread_current()->open_file_count;
        thread_current()->open_file_count++;
        list_push_back(&thread_current()->file_list, &process_file->elem);
        f->eax = process_file->fd;
      }
      break;
    }
    case SYS_FILESIZE:
    {
      //printf("IN SYS_FILESIZE\n");
      verify_ptr(ptr + 1);
      acquire_file_lock();
      f->eax = file_length(list_search(&thread_current()->file_list, *(ptr + 1))->proc_file_ptr);
      release_file_lock();
      break;
    }
    case SYS_READ:
    {
      //printf("IN SYS_READ\n");
      verify_ptr(ptr + 8);
      verify_ptr(*(ptr + 7));
      if(*(ptr + 6) == 0)
      {
        uint8_t* buffer = *(ptr + 6);
        for(int i = 0; i < *(ptr + 8); i++)
        {
          buffer[i] = input_getc();
        }
        f->eax = *(ptr + 8);
      }
      else
      {
        struct proc_file * file_ptr = list_search(&thread_current()->file_list, *(ptr + 6));

        if(file_ptr == NULL)
        {
          f->eax = 1;
        }
        else
        {
          acquire_file_lock();
          f->eax = file_read(file_ptr->proc_file_ptr, *(ptr + 7), *(ptr + 8));
          release_file_lock();
        }
      }
      break;
    }
    case SYS_WRITE:
    {
      //printf("IN SYS_WRITE\n");
      verify_ptr(ptr + 8); // checks that the 'size' param is there
      verify_ptr(*(ptr + 7)); // goes to the address of the buffer and checks it's validity
      if(*(ptr + 6) == 1) // if the 'fd' is 1 it writes to console
      {
        // defined in lib/kernel/console.c
        // void putbuf (const char *buffer, size_t n)
        putbuf(*(ptr + 7), *(ptr+8));
        f->eax = *(ptr+8);
      }
      else
      {
        struct proc_file *fptr = list_search(&thread_current()->file_list, *(ptr+6));
        if(fptr==NULL)
        f->eax=-1;
        else
        {
          acquire_file_lock();
          f->eax = file_write (fptr->proc_file_ptr, *(ptr+7), *(ptr+8));
          release_file_lock();
        }
      }
      break;
    }
    case SYS_SEEK:
    {
      //printf("IN SYS_SEEK\n");
      verify_ptr(ptr + 6);
      acquire_file_lock();
      file_seek(list_search(&thread_current()->file_list, *(ptr + 5))->proc_file_ptr, *(ptr + 6));
      release_file_lock();
      break;
    }
    case SYS_TELL:
    {
      //printf("IN SYS_TELL\n");
      verify_ptr(ptr + 1);
      acquire_file_lock();
      f->eax = file_tell(list_search(&thread_current()->file_list, *(ptr + 1))->proc_file_ptr);
      release_file_lock();
      break;
    }
    case SYS_CLOSE:
    {
      //printf("IN SYS_CLOSE\n");
      verify_ptr(ptr + 1);
      acquire_file_lock();
      close_file(&thread_current()->file_list, *(ptr + 1));
      release_file_lock();
      break;
    }
    default:
      printf("The default case %d\n", *ptr);
  }

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

/* Searches list until it finds the matching 'fd' and returns the file.
*/
struct proc_file* list_search(struct list* file_list, int fd)
{
  struct list_elem * file_list_elem;

  for(file_list_elem = list_begin(file_list); file_list_elem != list_end(file_list); file_list_elem = list_next(file_list_elem))
  {
    struct proc_file *single_file = list_entry(file_list_elem, struct proc_file, elem);

    if(single_file->fd == fd)
    {
      return single_file;
    }
  }

  return NULL;
}


void close_file(struct list* file_list, int fd)
{
  struct list_elem *elem;
  struct proc_file *process_file = NULL;

  for(elem = list_begin(file_list); elem != list_end(file_list); elem = list_next(elem))
  {
    process_file = list_entry(elem, struct proc_file, elem);
    if(process_file->fd == fd)
    {
      file_close(process_file->proc_file_ptr);
      list_remove(elem);
    }
  }

  free(process_file);
}
