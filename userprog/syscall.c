#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

void exit (int);
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
      case SYS_EXIT:
        printf ("exiting");
        exit (*((int *)f->esp + 1));
	break;
      case SYS_WRITE:
	write (*((int *)f->esp + 1), *(char **)((int *)f->esp + 2),
	       *(unsigned *)((int *)f->esp + 3));
        break;
    }
}

/* Terminates the current user program, returning status to the kernel. If
the process's parent waits for it (see below), this is the status that will
be returned. Conventionally, a status of 0 indicates success and nonzero
values indicate errors. */
void exit (int status)
{
  thread_exit ();  //TODO: use process_exit()
  // TODO: do something with status
}

/* Writes size bytes from buffer to the open file fd. Returns the number of
bytes actually written, which may be less than size if some bytes could not
be written.

Writing past end-of-file would normally extend the file, but file growth is
not implemented by the basic file system. The expected behavior is to write
as many bytes as possible up to end-of-file and return the actual number
written, or 0 if no bytes could be written at all.

Fd 1 writes to the console. Your code to write to the console should write
all of buffer in one call to putbuf(), at least as long as size is not bigger
than a few hundred bytes. (It is reasonable to break up larger buffers.)
Otherwise, lines of text output by different processes may end up interleaved
on the console, confusing both human readers and our grading scripts.*/
int write (int fd, const void *buffer, unsigned size)
{
  if (fd == STDOUT_FILENO)
    putbuf (buffer, size);
  return size;    // TODO: fix
}
