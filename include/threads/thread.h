#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include "threads/interrupt.h"
#include "threads/synch.h"
#ifdef VM
#include "vm/vm.h"
#endif


/* States in a thread's life cycle. */
enum thread_status {
	THREAD_RUNNING,     /* Running thread. */
	THREAD_READY,       /* Not running but ready to run. */
	THREAD_BLOCKED,     /* Waiting for an event to trigger. */
	THREAD_DYING        /* About to be destroyed. */
};

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) -1)          /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0                       /* Lowest priority. */
#define PRI_DEFAULT 31                  /* Default priority. */
#define PRI_MAX 63                      /* Highest priority. */

#define OFFSET_THREAD(MEMBER) (offsetof(struct thread, MEMBER) - offsetof(struct thread, elem))

// Fixed_point Real Arithmetic
#define F_SCALE (1 << 14)                                                // 고정소수점의 스케일(여기서는 2^14를 사용)
#define INT_TO_FP(n) ((n) * F_SCALE)                                       // Convert n to fixed point: n * f
#define FP_TO_INT_ZERO(x) ((x) / F_SCALE)                                    // Convert x to integer (rounding toward zero): x / f
#define FP_TO_INT_NEAREST(x) ((x) >= 0 ? ((x) + F_SCALE / 2) / F_SCALE : ((x) - F_SCALE / 2) / F_SCALE) // Convert x to integer (rounding to nearest)
#define FP_ADD(x, y) ((x) + (y))                                    // Add x and y: x + y
#define FP_SUB(x, y) ((x) - (y))                                    // Subtract y from x: x - y
#define FP_ADD_INT(x, n) ((x) + (n) * F_SCALE)                              // Add x and n: x + n * f
#define FP_SUB_INT(x, n) ((x) - (n) * F_SCALE)                              // Subtract n from x: x - n * f
#define FP_MUL(x, y) (((int64_t)(x)) * (y) / F_SCALE)                           // Multiply x by y: ((int64_t) x) * y / f
#define FP_MUL_INT(x, n) ((x) * (n))                                 // Multiply x by n: x * n
#define FP_DIV(x, y) (((int64_t)(x)) * F_SCALE / (y))                           // Divide x by y: ((int64_t) x) * f / y
#define FP_DIV_INT(x, n) ((x) / (n))                                 // Divide x by n: x / n
#define USERPROG

#ifdef USERPROG
#define FD_LIMIT 1 << 9
#endif

/* A kernel thread or user process.
 *
 * Each thread structure is stored in its own 4 kB page.  The
 * thread structure itself sits at the very bottom of the page
 * (at offset 0).  The rest of the page is reserved for the
 * thread's kernel stack, which grows downward from the top of
 * the page (at offset 4 kB).  Here's an illustration:
 *
 *      4 kB +---------------------------------+
 *           |          kernel stack           |
 *           |                |                |
 *           |                |                |
 *           |                V                |
 *           |         grows downward          |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           +---------------------------------+
 *           |              magic              | <- magic이 스레드 자료구조의 최상단에 위치한다.
 *           |            intr_frame           |
 *           |                :                |
 *           |                :                |
 *           |               name              |
 *           |              status             |
 *      0 kB +---------------------------------+
 *
 * The upshot of this is twofold:
 *
 *    1. First, `struct thread' must not be allowed to grow too
 *       big.  If it does, then there will not be enough room for
 *       the kernel stack.  Our base `struct thread' is only a
 *       few bytes in size.  It probably should stay well under 1
 *       kB.
 *
 *    2. Second, kernel stacks must not be allowed to grow too
 *       large.  If a stack overflows, it will corrupt the thread
 *       state.  Thus, kernel functions should not allocate large
 *       structures or arrays as non-static local variables.  Use
 *       dynamic allocation with malloc() or palloc_get_page()
 *       instead.
 *
 * The first symptom of either of these problems will probably be
 * an assertion failure in thread_current(), which checks that
 * the `magic' member of the running thread's `struct thread' is
 * set to THREAD_MAGIC.  Stack overflow will normally change this
 * value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
 * the run queue (thread.c), or it can be an element in a
 * semaphore wait list (synch.c).  It can be used these two ways
 * only because they are mutually exclusive: only a thread in the
 * ready state is on the run queue, whereas only a thread in the
 * blocked state is on a semaphore wait list. */
struct thread {
	/* Owned by thread.c. */
	tid_t tid;                          /* Thread identifier. */
	enum thread_status status;          /* Thread state. */
	char name[16];                      /* Name (for debugging purposes). */
	int priority;                       /* Priority. */
    int original_priority;
    int nice;
    int recent_cpu;

	/* Shared between thread.c and synch.c. */
	struct list_elem elem;              /* List element. */
    int64_t sleep_until;                /* Time to wake up(Ticks)*/
    struct list lock_list;              /* List lock the thread has */
    struct lock *waiting_for;      /* semaphore which thread is waiting for */
    struct list_elem all_elem;

#ifdef USERPROG
	/* Owned by userprog/process.c. */
	uint64_t *pml4;                     /* Page map level 4 */
    int exit_status;
    bool is_kernel;
    struct file **fdt;
    int fd_idx;
    struct semaphore wait_sema;
    struct list child_list;
    struct thread *parent;
    struct list_elem child_elem;
    struct semaphore *fork_sema;

    struct intr_frame *if_;
#endif
#ifdef VM
	/* Table for whole virtual memory owned by thread. */
	struct supplemental_page_table spt;
#endif

	/* Owned by thread.c. */
	struct intr_frame tf;               /* Information for switching */
	unsigned magic;                     /* Detects stack overflow. */
};

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

int load_avg;

void thread_init (void);
void thread_start (void);

void thread_tick (void);
void thread_print_stats (void);

typedef void thread_func (void *aux);
tid_t thread_create (const char *name, int priority, thread_func *, void *);

void thread_sleep (int64_t time);
void thread_block (void);
void thread_unblock (struct thread *);
void thread_awake (int64_t ticks);

struct thread *thread_current (void);
tid_t thread_tid (void);
const char *thread_name (void);

void thread_exit (void) NO_RETURN;
void thread_yield (void);
void thread_preempt (void);

int thread_get_priority (void);
void thread_set_priority (int);

int thread_get_nice (void);
void thread_set_nice (int);
int thread_get_recent_cpu (void);
int thread_get_load_avg (void);

void do_iret (struct intr_frame *tf);

bool compare_value (const struct list_elem *elem, 
                const struct list_elem *other_elem, 
                void* offset);
bool compare_rvalue (const struct list_elem *elem, 
                const struct list_elem *other_elem, 
                void* offset);

bool
compare_priority (const struct list_elem *elem, 
                const struct list_elem *other_elem, 
                void* aux UNUSED);

#endif /* threads/thread.h */
