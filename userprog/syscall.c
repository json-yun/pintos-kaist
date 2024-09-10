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

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

// static struct file *find_file_by_fd(int fd);
// void exit (int status);
// void halt (void);
// bool create (const char *file, unsigned initial_size);
// bool remove (const char *file);
// int filesize (int fd);
// int write (int fd, const void *buffer, unsigned size);
// unsigned tell (int fd);
// void seek (int fd, unsigned position) ;
// static struct file *find_file_by_fd(int fd) ;
// void close (int fd) ;
// void fdt_remove_fd(int fd);

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
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	printf ("system call!\n");
	thread_exit ();
}


/* The main system call interface */
// void
// syscall_handler (struct intr_frame *f) {
	// 함수 리턴 값을 위한 x86-64의 관례는 그 값을 RAX 레지스터에 넣는 것
	// 값을 리턴하는 시스템 콜도 struct intr_frame의  rax 멤버를 수정하는 식으로 
	// 이 관례를 따를 수 있습니다.
	//printf ("system call!\n");
	//User-level applications use as integer registers 
	//for passing the sequence 
	//%rdi, %rsi, %rdx, %rcx, %r8 and %r9.
	

	// switch (f->R.rax) { //rax는 시스템 콜 번호
	// 	case SYS_HALT:
	// 		printf("halt\n");
	// 		halt();  
	// 		break; 

	// 	case SYS_EXIT:
	// 		printf("exit\n");
	// 		exit(f->R.rdi);
	// 		break; 

	// 	case SYS_FORK: 
	// 		printf("fork\n"); 
	// 		//f->R.rax = fork(f->R.rdi, f);
	// 		break;      

	// 	case SYS_EXEC:  
	// 		printf("exec\n");
	// 		//exec(f->R.rdi);
	// 		break;

	// 	case SYS_WAIT: 
	// 		printf("wait\n");
	// 		//f->R.rax = process_wait(f->R.rdi);
	// 		break;

	// 	case SYS_CREATE:
	// 		printf("create\n");
	// 		f->R.rax = create(f->R.rdi, f->R.rsi);
	// 		break;  

	// 	case SYS_REMOVE:
	// 		printf("remove\n");
	// 		f->R.rax = remove(f->R.rdi);
	// 		break;

	// 	case SYS_OPEN:
	// 		printf("open\n");
	// 		//f->R.rax = open(f->R.rdi);
	// 		break;    

	// 	case SYS_FILESIZE:
	// 		printf("filesize\n");
	// 		f->R.rax = filesize(f->R.rdi);
	// 		break;   

	// 	case SYS_READ:
	// 		printf("read\n");
	// 		//f->R.rdx = read(f->R.rdi, f->R.rsi, f->R.rdx);
	// 		break;    

	// 	case SYS_WRITE:
	// 		printf("write\n");
	// 		f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
	// 		break;       

	// 	case SYS_SEEK:
	// 		printf("seek\n");
	// 		seek(f->R.rdi, f->R.rsi);
	// 		break;    

	// 	case SYS_TELL:
	// 		printf("tell\n");
	// 		f->R.rax = tell(f->R.rdi);
	// 		break;   

	// 	case SYS_CLOSE: 
	// 		printf("close\n");
	// 		close(f->R.rdi);
	// 		break;   
	// 	default:
	// 		thread_exit();
	// 		break;  

	// }

	//thread_exit ();
//}


// void check_address(void *addr) {
// 	//first check pointer of filename
// 	//포인터가 가리키는 주소가 유저영역의 주소인지 확인
// 	//잘못된 접근일 경우 프로세스 종료
// 	/* Returns true if VADDR is a user virtual address. */
//     //#define is_user_vaddr(vaddr) (!is_kernel_vaddr((vaddr)))
// 	struct thread *cur = thread_current();
// 	//유효한 주소 공간이 아니거나 NULL포인터일 경우
// 	if (!is_user_vaddr(addr) || addr == NULL ||
// 	//주소가 유저 영역 내에 있지만 페이지로 할당하지 않은 영역일 수도 있다
// 	pml4_get_page(cur->pml4, addr) == NULL) {
// 		exit(-1);
// 	}
// }
// 주소값이 유저 영역(0x8048000~0xc0000000)에서 사용하는 주소값인지 확인하는 함수
// void check_address(const uint64_t *addr)	
// {
// 	struct thread *cur = thread_current();
// 	if (addr == NULL || !(is_user_vaddr(addr)) || pml4_get_page(cur->pml4, addr) == NULL) {
// 		exit(-1);
// 	}
// }



// void halt (void) {
// 	//power_off()[Src/include/threads/init.h]를 호출해서 pintos를 종료한다
// 	/* Powers down the machine we're running on,
//    as long as we're running on Bochs or QEMU. */
//    power_off();
	
// }




// void exit (int status) {
// 	//현재 동작중인 유저 프로그램 종료, 커널의 상태를 리턴하면서.
// 	//부모 프로세스가 현재 유저 프로그램의 종료를 기다리던 중이라면, 
// 	//종료되면서 리턴될 상태를 기다린다는 것. 상태 0 성공, 0 이 아니면 에러
// 	struct thread *cur = thread_current();
// 	cur->exit_status = status;

// 	printf("%s : exit (%d)\n", cur->name, status);//0은 성공
// 	thread_exit();
// }

// pid_t fork (const char *thread_name) {
// 	//자식 프로세스를 생성하고 프로그램을 실행
// 	//아예 새로 만드는 것보다 기존에 생성된 프로세스의 자료구조를 복사하는 것이 더 효율적
// 	//tid_t process_fork (const char *name, struct intr_frame *if_);
// 	return process_fork(thread_name, if_);

// }

// int exec (const char *cmd_line) {
// 	//create child process and execute program corresponds to cmd_line on it
// 	//similar to fork(), exec()
// }

// int wait (pid_t pid) {
// 	//wait for temination of child process whode process id is pid
// 	process_wait(pid);


// }


// bool create (const char *file, unsigned initial_size) {
// 	//file(첫번째인자), initial_size(두번째인자)를 만듬
// 	//open 할필요 없음
// 	check_address(file);
// 	return filesys_create(file, initial_size);
// }

// bool remove (const char *file) {
// 	check_address(file);
// 	return filesys_remove(file);
// }


// int open (const char *file) {
// 	//프로세스가 파일에 접근하기 위해 요청


// }

// int filesize (int fd) {
// 	struct file *open_file = find_file_by_fd(fd);
// 	if (open_file == NULL) {
// 		return -1;
// 	}
// 	return file_length(open_file);
// }

// // int read (int fd, void *buffer, unsigned length) {

// // }


// int write (int fd, const void *buffer, unsigned size) {
// 	if (fd == STDOUT_FILENO)
// 		putbuf(buffer, size);
// 	return size;
// }

// // struct file {
// // 	struct inode *inode;        /* File's inode. */
// // 	off_t pos;                  /* Current position. */
// // 	bool deny_write;            /* Has file_deny_write() been called? */
// // };
// void seek (int fd, unsigned position) {
// 	//열린 파일으 위치offset를 이동하는 시스템 콜
// 	struct file *seek_file = find_file_by_fd(fd);
// 	if (seek_file <= 2) {
// 		return;
// 	}
// 	return file_seek(seek_file, position);

// }

// unsigned tell (int fd) {
// 	//열린 파일의 위치를 알려주는 시스템콜
// 	struct file *tell_file = find_file_by_fd(fd);
// 	if (tell_file <= 2) {
// 		return;
// 	}
// 	return file_tell(tell_file);
// }


// void fdt_remove_fd(int fd) {
// 	//fd테이블에서 인자로 들어온 fd를 제거한다
// 	//fd테이블의 fd번째의 fd_table에 저장된 값을 NULL로 초기화
// 	struct thread *cur = thread_current();
// 	if (fd < 0 || fd >= FDCOUNT_LIMIT) {
// 		return;
// 	}
// 	cur->fd_table[fd] = NULL;
// }

// void close (int fd) {
// 	//파일 식별자 fd를 닫는다. 열려있는 파일 식별자를 닫는다
// 	struct file *close_file = find_file_by_fd(fd);
// 	if (close_file == NULL) {
// 		return;
// 	}
// 	fdt_remove_fd(fd);
// 	file_close(close_file);
// }

// static struct file *find_file_by_fd(int fd) {
// //fdtable 리스트에 fd 번째에 (fdTable[fd]) file 주소가 저장되어있기에 이를 return 해준다.
// 	struct thread *cur = thread_current();
// 	if (fd < 0 || fd >= FDCOUNT_LIMIT) {
// 		return NULL;
// 	}
// 	return cur->fd_table[fd];
// }

// int dup2(int oldfd, int newfd) {

// }