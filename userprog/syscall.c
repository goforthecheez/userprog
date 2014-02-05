#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "devices/shutdown.h"
#include "lib/user/syscall.h"
#include "threads/interrupt.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "userprog/process.h"

void exit (int);
pid_t exec (const char *);
int write (int, const void*, unsigned);

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  switch (*(int *)f->esp)
    {
      case SYS_HALT:
        shutdown_power_off ();
        break;
      case SYS_EXIT:
        exit (*((int *)f->esp + 1));
        break;
      case SYS_EXEC:
        exec (*(char **)((int *)f->esp + 1));
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
        break;
      case SYS_WRITE:
	write (*((int *)f->esp + 1), *(char **)((int *)f->esp + 2),
	       *(unsigned *)((int *)f->esp + 3));
        break;
      case SYS_TELL:
        break;
      case SYS_SEEK:
        break;
      case SYS_CLOSE:
        break;
    }
}

void exit (int status)
{
  lock_acquire (&thread_current ()->parent->wait_lock);
  struct child c;
  c.tid = thread_current ()->tid;

  struct hash_elem *e = hash_find (thread_current ()->parent->children,
                                   &c.elem);
  struct child *found_child = hash_entry (e, struct child, elem);
  found_child->done = true;
  found_child->exit_status = status;
  cond_signal (&thread_current ()->parent->wait_cond,
               &thread_current ()->parent->wait_lock);
  lock_release (&thread_current ()->parent->wait_lock);
  thread_exit ();
}

pid_t exec (const char *cmd_line)
{
  struct thread *t = thread_current ();

  lock_acquire (&t->wait_lock);
  pid_t pid = process_execute (cmd_line);
  cond_wait (&t->wait_cond, &t->wait_lock);
  lock_release (&t->wait_lock);

  return pid;
}

int write (int fd, const void *buffer, unsigned size)
{
  if (fd == STDOUT_FILENO)
    putbuf (buffer, size);
  return size;    // TODO: fix
}
