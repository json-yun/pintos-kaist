#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/palloc.h"
#include <string.h>
#include "threads/synch.h"

typedef int pid_t;

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
void check_address (void *addr);
int add_file_fd (struct file *file);
struct file *find_fd_file (int fd);
struct lock file_sema;

void halt (void);
void exit (int status);
pid_t fork (const char *thread_name, struct intr_frame *f);
int exec (const char *cmd_line);
int wait (pid_t pid);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
	
	lock_init (&file_sema);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {

	struct thread *curr = thread_current ();
	curr->is_user = true;

	switch (f->R.rax) {
		case SYS_HALT :
			halt ();
			break;
		case SYS_EXIT :
			exit (f->R.rdi);
			break;
		case SYS_FORK :
			f->R.rax = fork (f->R.rdi, f);
			break;
		case SYS_EXEC :
			f->R.rax = exec (f->R.rdi);
			break;
		case SYS_WAIT :
			f->R.rax = wait (f->R.rdi);
			break;
		case SYS_CREATE :
			f->R.rax = create (f->R.rdi, f->R.rsi);
			break;
		case SYS_REMOVE :
			f->R.rax = remove (f->R.rdi);
			break;
		case SYS_OPEN :
			f->R.rax = open (f->R.rdi);
			break;
		case SYS_FILESIZE :
			f->R.rax = filesize(f->R.rdi);
			break;
		case SYS_READ :
			f->R.rax = read (f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_WRITE :
			f->R.rax = write (f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_SEEK :
			seek (f->R.rdi, f->R.rsi);
			break;
		case SYS_TELL :
			f->R.rax = tell (f->R.rdi);
			break;
		case SYS_CLOSE :
			close (f->R.rdi);
			break;
		default:
			break;
	}

}

void
halt (void) {
	power_off ();
}

void
exit (int status) {
	struct thread *curr = thread_current ();
	curr->exit_status = status;
	if (curr->exec_file != NULL) {
		file_close(curr->exec_file);
		// file_allow_write(curr->exec_file);
	}
	thread_exit ();
}

pid_t
fork (const char *thread_name, struct intr_frame *f) {
	return process_fork (thread_name, f);
}

int
exec (const char *cmd_line) {
	check_address(cmd_line);
    char *fn_copy = palloc_get_page(PAL_ZERO);
    if (fn_copy == NULL) {
        exit(-1);
    }
    strlcpy(fn_copy, cmd_line, PGSIZE);

	struct thread *curr = thread_current ();

    if (process_exec(fn_copy) == -1)
    {
        exit(-1);
    }

	if (curr->exec_file != NULL) {
		file_allow_write(curr->exec_file);
		// file_close (curr->exec_file);
	}

    return 0;
}

int
wait (pid_t pid) {
	return process_wait (pid);
}

bool
create (const char *file, unsigned initial_size) {
	check_address (file);
	return filesys_create (file, initial_size);
}

bool
remove (const char *file) {
	check_address (file);
	return filesys_remove (file);
}

int
open (const char *file) {
	check_address (file);
	struct file *open_file = filesys_open (file);
	if (open_file == NULL) {
		return -1;
	}
	int fd = add_file_fd (open_file);
	if (fd == -1) file_close (open_file);
	return fd;
}

int
filesize (int fd) {
	struct thread *curr = thread_current ();

	struct file *cur_file = find_fd_file (fd);

	if (cur_file == NULL) return -1;

	return file_length (cur_file);
}

int
read (int fd, void *buffer, unsigned size) {
	struct thread *curr = thread_current ();

	check_address (buffer);

	if (fd == 0 && buffer != NULL) {
		return input_getc ();
	}

	struct file *cur_file = find_fd_file (fd);

	if (cur_file == NULL || buffer == NULL) return -1;

	lock_acquire (&file_sema);
	int temp = file_read (cur_file, buffer, size);
	lock_release (&file_sema);

	return temp;
}

int
write (int fd, const void *buffer, unsigned size) {
	check_address (buffer);

	lock_acquire (&file_sema);
	if (fd == 1) {
		putbuf (buffer, size);
		lock_release (&file_sema);
		return size;
	}

	struct file *cur_file = find_fd_file (fd);

	if (cur_file == NULL) {
		lock_release (&file_sema);
		return -1;
	}

	lock_release (&file_sema);
	return file_write(cur_file, buffer, size);
}

void
seek (int fd, unsigned position) {
	struct file *cur_file = find_fd_file (fd);
	if (cur_file == NULL) return;
	file_seek (cur_file, position);
}

unsigned
tell (int fd) {
	struct file *cur_file = find_fd_file (fd);
	if (cur_file == NULL) return -1;
	return file_tell (cur_file);
}

void
close (int fd) {
	struct file *cur_file = find_fd_file (fd);
	if (cur_file == NULL) return;
	struct thread *curr = thread_current ();
	file_close (cur_file);
	curr->fd_table[fd] = NULL;
}

void
check_address (void *addr) {
	struct thread *curr = thread_current ();
	if (is_kernel_vaddr (addr) || pml4_get_page (curr->pml4, addr) == NULL || addr == NULL) {
		exit (-1);		
	}
}

int
add_file_fd (struct file *file) {
	struct thread *curr = thread_current ();

	while (curr->fd_table[curr->fd_idx] && curr->fd_idx < FDMAXSIZE) {
		curr->fd_idx++;
	}
	if (curr->fd_idx >= FDMAXSIZE) return -1;

	curr->fd_table[curr->fd_idx] = file;
	int temp = curr->fd_idx;
	curr->fd_idx = 3; 
	return temp;
}

struct file
*find_fd_file (int fd) {
	struct thread *curr = thread_current ();

	if (fd < 3 || fd >= FDMAXSIZE) return NULL;

	return curr->fd_table[fd];
}