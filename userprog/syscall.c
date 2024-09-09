#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "../include/threads/init.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
static void halt (void);

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
/* 인터럽트 핸들러에 의해 호출됨.
 * 인터럽트 당시 스레드 상태를 담은 인터럽트 프레임 포인터를 인자로 받음 */
void
syscall_handler (struct intr_frame *f) {
	// TODO: Your implementation goes here.
    uint64_t num = f->R.rax;
    uint64_t arg1 = f->R.rdi;
    uint64_t arg2 = f->R.rsi;
    uint64_t arg3 = f->R.rdx;
    uint64_t arg4 = f->R.r10;
    uint64_t arg5 = f->R.r8;
    uint64_t arg6 = f->R.r9;

    // switch (num) {
    // case SYS_HALT:
    //     halt ();
    //     break;
    // case SYS_EXIT:
    //     exit (arg1);
    //     break;
    // // case SYS_FORK:
    // case SYS_EXEC:
    // case SYS_WAIT:
    // case SYS_CREATE:
    // case SYS_REMOVE:
    // case SYS_OPEN:
    // case SYS_FILESIZE:
    // case SYS_READ:
    // case SYS_WRITE:
    // case SYS_SEEK:
    // case SYS_TELL:
    // case SYS_CLOSE:
    // }
}

static void
halt (void) {
    power_off();
}

static void
exit (int status) {
    // terminates the current process
    process_exit();
    // returns status to the kernel
    // if parent wait, status will be returned
}