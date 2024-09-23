#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "userprog/process.h"
#include "filesys/inode.h"
#include "threads/palloc.h"
#include <string.h>
typedef int pid_t;

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
void halt (void);
void exit (int status);
pid_t fork (const char *thread_name, struct thread *f);
int exec (const char *file);
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
int dup2 (int oldfd, int newfd);
void * mmap (void *addr, size_t length, int writable, int fd, off_t offset);
void munmap (void *addr);
bool chdir (const char *dir);
bool mkdir (const char *dir);
bool readdir (int fd, char name[]);
bool isdir (int fd);
int inumber (int fd);
int symlink (const char* target, const char* linkpath);
int mount (const char *path, int chan_no, int dev_no);
int umount (const char *path);
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
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f) {
    switch(f->R.rax) {
		case SYS_HALT:
			halt();
            break;
		case SYS_EXIT:
			exit(f->R.rdi);
            break;
		case SYS_FORK:
			f->R.rax = fork(f->R.rdi, f);		
            break;
		case SYS_EXEC:
			f->R.rax = exec(f->R.rdi);
            break;
		case SYS_WAIT:
			f->R.rax = wait(f->R.rdi);
            break;
		case SYS_CREATE:
			f->R.rax = create(f->R.rdi, f->R.rsi);	
            break;
		case SYS_REMOVE:
			f->R.rax = remove(f->R.rdi);		
            break;
		case SYS_OPEN:
			f->R.rax = open(f->R.rdi);		
            break;
		case SYS_FILESIZE:
			f->R.rax = filesize(f->R.rdi);
            break;
		case SYS_READ:
			f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
            break;
		case SYS_WRITE:
			f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);		
            break;
		case SYS_SEEK:
			seek(f->R.rdi, f->R.rsi);		
            break;
		case SYS_TELL:
			f->R.rax = tell(f->R.rdi);		
            break;
		case SYS_CLOSE:
			close(f->R.rdi);
            break;
    }
}

// 유저 프로세스가 시스템 콜을 하면서 인자로 유효하지 않은 주소를 전달한 경우
// 커널은 프로세스를 종료시켜야 한다.
// 유효하지 않은 주소: 할당되지 않은 페이지의 주소 or 커널 영역 주소
void
check_addr_validity(void *addr) {
    struct thread *t = thread_current();

    if (is_kernel_vaddr(addr) || 
    addr == NULL || 
    pml4_get_page(t->pml4, addr) == NULL) {
        exit(-1);
    }
}

int add_file_to_fdt(struct file *file) {
    struct thread *t = thread_current();
    int fd;

    // 빈 fd 탐색(중간이 비어있을 수도 있음)
    // 0: stdin, 1: stdout, 2: stderr
    for (fd = 2; fd < FD_LIMIT && t->fdt[fd] != NULL; fd++);

    if (fd >= FD_LIMIT) return -1;

    t->fdt[fd] = file;
    return fd;
}

struct file *fd_to_file (int fd) {
    if (!(1 < fd && fd < FD_LIMIT)) return NULL;
    else {
        struct thread *t = thread_current();
        struct file *file = t->fdt[fd];
        return file;
    }
}

void
halt (void) {
    power_off();
}

void
exit (int status) {
    thread_current()->exit_status = status;
    thread_exit();
}

pid_t
fork (const char *thread_name, struct thread *f){
    check_addr_validity(thread_name);
    return process_fork(thread_name, f);
}

int
exec (const char *file) {
    check_addr_validity(file);
    void *safe_file = palloc_get_page(PAL_ZERO);
    memcpy(safe_file, file, strlen(file)+1);
    process_exec(safe_file); // never return if successful.
    exit(-1); // if failed.
}

int
wait (pid_t pid) {
    return process_wait(pid);
}

bool
create (const char *file, unsigned initial_size) {
    check_addr_validity(file);
    return filesys_create(file, initial_size);
}

bool
remove (const char *file) {
    check_addr_validity(file);
    return filesys_remove(file);
}

int
open (const char *filename) {
    check_addr_validity(filename);
    struct file *file;
    int fd;

    if ((file = filesys_open(filename)) == NULL)
        return -1;

    if ((fd = add_file_to_fdt(file)) == -1)
        file_close(file);

    return fd;
}

int
filesize (int fd) {
    struct file *file = fd_to_file(fd);

    if (file == NULL) return -1;
    return file_length(file);
}

int
read (int fd, void *buffer, unsigned size) {
    check_addr_validity(buffer);

    if (fd == STDIN_FILENO) {
        int readsize;
        char c;
        unsigned char *buf;
        for (readsize = 0; readsize < size; readsize++) {
            *buf = input_getc();

            if (*buf == '\n') break;
            else buf++;
        }
        return readsize;
    }

    else if (fd == STDOUT_FILENO)
        return -1;

    else {
        struct file *file = fd_to_file(fd);
        if (file == NULL) return -1;
        return file_read(file, buffer, size);
    }

}

int
write (int fd, const void *buffer, unsigned size) {
    check_addr_validity(buffer);
    if (fd == STDOUT_FILENO) {
        putbuf(buffer, size);
        return size;
    }

    else if (fd == STDIN_FILENO)
        return -1;

    else {
        struct file *file = fd_to_file(fd);
        if (file == NULL) return -1;
    	return file_write(file, buffer, size);
    }
}

void
seek (int fd, unsigned position) {
    struct file *file = fd_to_file(fd);
    if (file == NULL) return;
    file_seek(file, position);
}

unsigned
tell (int fd) {
    struct file *file = fd_to_file(fd);
    if (file == NULL) return 0;
    return file_tell(file);
}

void
close (int fd) {
    if (!(1 < fd && fd < FD_LIMIT)) {
        return;
    }

    struct thread *t = thread_current();
    struct file *file = t->fdt[fd];

    if (file == NULL) return;
    file_close(file);
    t->fdt[fd] = NULL;
}