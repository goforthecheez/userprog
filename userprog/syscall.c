#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "lib/user/syscall.h"
#include "threads/interrupt.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"

void halt (void);
void exit (int status);
pid_t exec (const char *cmd_line);
int wait (pid_t pid);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int, const void*, unsigned);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);
struct file *lookup_file (int fd);


static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  if (pagedir_get_page (thread_current ()->pagedir, f->esp) == NULL)
    exit (-1);

  switch (*(int *)f->esp)
    {
      case SYS_HALT:
        shutdown_power_off ();
        break;
      case SYS_EXIT:
        if (pagedir_get_page (thread_current ()->pagedir, (int *)f->esp + 1) == NULL)
          exit (-1);
        exit (*((int *)f->esp + 1));
        break;
      case SYS_EXEC:
        f->eax = exec (*(char **)((int *)f->esp + 1));
        break;
      case SYS_WAIT:
        f->eax = wait (*(unsigned *)((int *)f->esp + 1));
        break;
      case SYS_CREATE:
        f->eax = create (*(char **)((int *)f->esp + 1), *(unsigned *)((int *)f->esp + 2));
        break;
    case SYS_REMOVE:
        f->eax = remove (*(char **)((int *)f->esp + 1));
        break;
      case SYS_OPEN:
	f->eax = open (*(char **)((int *)f->esp + 1));
        break;
      case SYS_FILESIZE:
        f->eax = filesize (*((int *)f->esp + 1));
        break;
      case SYS_READ:
	f->eax = read (*((int *)f->esp + 1), *(char **)((int *)f->esp + 2),
	       *(unsigned *)((int *)f->esp + 3));
        break;
      case SYS_WRITE:
	f->eax = write (*((int *)f->esp + 1), *(char **)((int *)f->esp + 2),
	       *(unsigned *)((int *)f->esp + 3));
        break;
      case SYS_TELL:
        f->eax = tell (*((int *)f->esp + 1));
        break;
      case SYS_SEEK:
        seek (*((int *)f->esp + 1), *(unsigned *)((int *)f->esp + 2));
        break;
      case SYS_CLOSE:
        close (*((int *)f->esp + 1));
        break;
      default:
        exit (-1);
    }
}

void exit (int status)
{
  lock_acquire (&thread_current ()->parent->wait_lock);
  struct child c;
  c.tid = thread_current ()->tid;
  //  printf ("exit() is looking for thread %d", c.tid);

  struct hash_elem *e = hash_find (thread_current ()->parent->children,
                                   &c.elem);
  struct child *found_child = hash_entry (e, struct child, elem);
  //  printf ("exit() found found_child %d", found_child->tid);
  found_child->done = true;
  found_child->exit_status = status;
  //  printf ("exit() return value is %d", found_child->exit_status);
  cond_signal (&thread_current ()->parent->wait_cond,
               &thread_current ()->parent->wait_lock);
  lock_release (&thread_current ()->parent->wait_lock);
  thread_exit ();
}

pid_t exec (const char *cmd_line)
{
  // TODO: check that file is within userspace
  if (pagedir_get_page (thread_current ()->pagedir, cmd_line) == NULL)
    exit (-1);

  struct thread *t = thread_current ();

  lock_acquire (&t->wait_lock);
  pid_t pid = process_execute (cmd_line);
  cond_wait (&t->wait_cond, &t->wait_lock);
  thread_current ()->child_ready = false;
  
  struct child c;
  c.tid = pid;
  struct hash_elem *e = hash_find (thread_current ()->children, &c.elem);
  struct child *found_child = hash_entry (e, struct child, elem);
  if (found_child->exit_status == -1)
    {
      lock_release (&t->wait_lock);
      return -1;
    }

  lock_release (&t->wait_lock);

  return pid;
}

int wait (pid_t pid)
{
  int ret_val = process_wait (pid);

  struct thread *t = thread_current ();
  struct child c;
  c.tid = pid;
  hash_delete (t->children, &c.elem);

  return ret_val;   //TODO WHAT IS THIS?
}

bool create (const char *file, unsigned initial_size)
{
  // TODO: check that file is within usespace
  if (pagedir_get_page (thread_current ()->pagedir, file) == NULL)
    exit (-1);

  bool success = filesys_create (file, initial_size);

  if (!success)
    return false;

  return success;
}

bool remove (const char *file)
{
  // TODO: check that file is within userspace
  if (pagedir_get_page (thread_current ()->pagedir, file) == NULL)
    exit (-1);
  
  return filesys_remove (file);
}

int open (const char *file)
{
  // TODO: check that file is within userspace
  if (pagedir_get_page (thread_current ()->pagedir, file) == NULL)
    exit (-1);

  struct thread *t = thread_current ();
  lock_acquire (&t->filesys_lock);
  struct file *f = filesys_open (file);
  lock_release (&t->filesys_lock);

  if (f == NULL)
    return -1;

  lock_acquire (&t->filesys_lock);
  hash_insert (t->open_files, &f->elem);
  lock_release (&t->filesys_lock);
  return f->fd;
}

int filesize (int fd)
{
  struct file *f = lookup_file (fd);
  if (f == NULL)
    {
      exit (-1);
    }
  return file_length (f);
}

int read (int fd, void *buffer, unsigned size)
{
  if (pagedir_get_page (thread_current ()->pagedir, buffer) == NULL ||
      pagedir_get_page (thread_current ()->pagedir, (char *)buffer + size) == NULL)
    exit (-1);

  struct file *f = lookup_file (fd);

  // TODO: prototypical example
  if (f == NULL)
    exit (-1);


  // TODO: handle reading from stdin

  lock_acquire (&thread_current ()->filesys_lock);
  int bytes_read = file_read (f, buffer, size);
  lock_release (&thread_current ()->filesys_lock);
  return bytes_read;

}

int write (int fd, const void *buffer, unsigned size)
{
  if (pagedir_get_page (thread_current ()->pagedir, buffer) == NULL ||
      pagedir_get_page (thread_current ()->pagedir, (char *)buffer + size) == NULL)
    exit (-1);

  if (fd == STDOUT_FILENO)
    {
      putbuf (buffer, size);
      return size;
    }

  struct file *f = lookup_file (fd);
  if (f == NULL)
    exit (-1);

  lock_acquire (&thread_current ()->filesys_lock);
  int bytes_written = file_write (f, buffer, size);
  lock_release (&thread_current ()->filesys_lock);

  return bytes_written;
}

void seek (int fd, unsigned position)
{
  struct file *f = lookup_file (fd);

  if (f == NULL)
    exit (-1);

  return file_seek (f, position);
}

unsigned tell (int fd)
{
  struct file *f = lookup_file (fd);

  if (f == NULL)
    exit (-1);

  return file_tell (f);
}

void close (int fd)
{
  struct file *f = lookup_file (fd);

  if (f == NULL)
    exit (-1);

  struct thread *t = thread_current ();
  lock_acquire (&t->filesys_lock);
  struct file lookup;
  lookup.fd = fd;
  hash_delete (t->open_files, &lookup.elem);  
  lock_release (&t->filesys_lock);
  file_close (f);
}

struct file *
lookup_file (int fd)
{
  struct thread *t = thread_current ();
  lock_acquire (&t->filesys_lock);

  struct file lookup;
  lookup.fd = fd;

  struct hash_elem *e = hash_find (t->open_files, &lookup.elem);
  lock_release (&t->filesys_lock);
  if (e == NULL)
    return NULL;

  struct file *f = hash_entry (e, struct file, elem);

  return f;
}
