#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <string.h>
#include <stdint.h>
#include <linux/kvm.h>

/* CR0 bits */
#define CR0_PE 1u
#define CR0_MP (1U << 1)
#define CR0_EM (1U << 2)
#define CR0_TS (1U << 3)
#define CR0_ET (1U << 4)
#define CR0_NE (1U << 5)
#define CR0_WP (1U << 16)
#define CR0_AM (1U << 18)
#define CR0_NW (1U << 29)
#define CR0_CD (1U << 30)
#define CR0_PG (1U << 31)

/* CR4 bits */
#define CR4_VME 1
#define CR4_PVI (1U << 1)
#define CR4_TSD (1U << 2)
#define CR4_DE (1U << 3)
#define CR4_PSE (1U << 4)
#define CR4_PAE (1U << 5)
#define CR4_MCE (1U << 6)
#define CR4_PGE (1U << 7)
#define CR4_PCE (1U << 8)
#define CR4_OSFXSR (1U << 8)
#define CR4_OSXMMEXCPT (1U << 10)
#define CR4_UMIP (1U << 11)
#define CR4_VMXE (1U << 13)
#define CR4_SMXE (1U << 14)
#define CR4_FSGSBASE (1U << 16)
#define CR4_PCIDE (1U << 17)
#define CR4_OSXSAVE (1U << 18)
#define CR4_SMEP (1U << 20)
#define CR4_SMAP (1U << 21)

#define EFER_SCE 1
#define EFER_LME (1U << 8)
#define EFER_LMA (1U << 10)
#define EFER_NXE (1U << 11)

/* 32-bit page directory entry bits */
#define PDE32_PRESENT 1
#define PDE32_RW (1U << 1)
#define PDE32_USER (1U << 2)
#define PDE32_PS (1U << 7)

/* 64-bit page * entry bits */
#define PDE64_PRESENT 1
#define PDE64_RW (1U << 1)
#define PDE64_USER (1U << 2)
#define PDE64_ACCESSED (1U << 5)
#define PDE64_DIRTY (1U << 6)
#define PDE64_PS (1U << 7)
#define PDE64_G (1U << 8)

//file macros
#define INIT_FILE_TABLE_PORT 0x40
#define OPEN_FILE_PORT 0x41
#define READ_FILE_PORT 0x42
#define WRITE_FILE_PORT 0x43

#define MAX_FD_NO 255

struct vm {
	int sys_fd;
	int fd;
	char *mem;
};

typedef struct fd_struct{
	int fd;
	int is_open;
} fd_struct;

//fd table created
fd_struct fd_table[MAX_FD_NO];

//open stucture used to open file from guest
typedef struct open_struct{
	const char* filename;
	int rd;
	int wr;
	int rdwr;
	int cr;
	int ex;
} open_struct;

int initialize_fd_table() {

	static int is_init_before = 0;
	if(is_init_before==0)
	{
		fd_table[0].fd = 0;  //stdin
		fd_table[0].is_open = 1; 

		fd_table[1].fd = 1;  //stdout
		fd_table[1].is_open = 1;

		fd_table[2].fd = 2; //stderr
		fd_table[2].is_open = 1;

		for(int i = 3; i < MAX_FD_NO; i++)
			fd_table[i].is_open = 0;

		is_init_before=1;
		return 1;
	}
	return 0;
}

int guest_open_file(open_struct* ops)
{
	int min_fd;
    for(min_fd = 0; min_fd <= MAX_FD_NO; min_fd++)
      if(fd_table[min_fd].is_open == 0) break;
    if(min_fd > MAX_FD_NO)
	{ 
		printf("\nreached maximum file limit!!!");
		return -1;
	}
    else 
	{
		int flags= 0 ;
		//flags= flag;
		if(ops->rd==1)
			flags = flags | O_RDONLY;

		if(ops->wr==1)
			flags = flags | O_WRONLY; 
		
		if(ops->cr==1)
			flags = flags | O_CREAT; 
		
		if(ops->ex==1)
			flags = flags | O_EXCL; 
		
		if(ops->rdwr==1)
			flags = flags | O_RDWR; 
		
		int fd = open(ops->filename, flags, 0777);  
		
		printf("\nfd = %d\n", fd); 
		
		if (fd ==-1) 
		{ 
			printf("\nError Occurred!!!\n");  
			return -1;              
		} 
        fd_table[min_fd].fd = fd;
        fd_table[min_fd].is_open = 1;
        return min_fd;
    } 
	
}

int guest_close_file(int fd)
{
	if(fd<0 || fd>=MAX_FD_NO)
	{
		printf("\ninvalid fd!!!");
		return -1;
	}
	if (close(fd_table[fd].fd) < 0)  
    { 
		for(int i=0;i<MAX_FD_NO;i++)
		{
			if(i==fd)
				fd_table[fd].is_open=0;
		}
        printf("\nerror while closing the file !!!"); 
        return -1; 
    }  
    printf("closed the fd.\n");
	return 1; 
}

typedef struct write_fd_struct
{
	int fd;
	char* str;
	int offset;
} write_fd_struct;

int guest_write_file(write_fd_struct* wfs )
{
	if(wfs->fd < 0 || wfs->fd >= MAX_FD_NO)
	{
		printf("\ninvalid fd!!!");
		return -1;
	}
	if(fd_table[wfs->fd].is_open)
	{
		int rfd=fd_table[wfs->fd].fd;

		return(write(rfd, wfs->str , wfs->offset));

	}
	printf("file not opened");
	return -1;
}

int guest_read_file(write_fd_struct* wfs )
{
	if(wfs->fd < 0 || wfs->fd >= MAX_FD_NO)
	{
		printf("\ninvalid fd!!!");
		return -1;
	}
	if(fd_table[wfs->fd].is_open)
	{
		int rfd=fd_table[wfs->fd].fd;

		return(read(rfd, wfs->str , wfs->offset));

	}
	printf("file not opened");
	return -1;
}

typedef struct lseek_fd_struct{
	int fd;
	int offset;
	int wench_seek_set;
	int wench_seek_cur;
	int wench_seek_end;
} lseek_fd_struct;

int guest_lseek_file(lseek_fd_struct* lfs )
{
	if(lfs->fd < 0 || lfs->fd >= MAX_FD_NO)
	{
		printf("\ninvalid fd!!!");
		return -1;
	}
	if(fd_table[lfs->fd].is_open)
	{
		int rfd=fd_table[lfs->fd].fd;
		int flag= 0 ;
		if(lfs->wench_seek_cur)
			flag = flag | SEEK_CUR;
		if(lfs->wench_seek_end)
			flag = flag | SEEK_END;
		if(lfs->wench_seek_set)
			flag = flag | SEEK_SET;

		return(lseek(rfd, lfs->offset ,flag));

	}
	printf("file not opened");
	return -1;
}

//same function as in guest to send the data to the guest through port
static inline void outb(uint16_t port, uint32_t value) {
  asm("out %0,%1" : /* empty */ : "a" (value), "Nd" (port) : "memory");
}

void vm_init(struct vm *vm, size_t mem_size)
{
	int api_ver;
	struct kvm_userspace_memory_region memreg;
	
	//system fd created from opening /dev/kvm and used to create VM
	vm->sys_fd = open("/dev/kvm", O_RDWR);
	if (vm->sys_fd < 0) {
		perror("open /dev/kvm");
		exit(1);
	}

	//checking KVM API version
	api_ver = ioctl(vm->sys_fd, KVM_GET_API_VERSION, 0);
	if (api_ver < 0) {
		perror("KVM_GET_API_VERSION");
		exit(1);
	}

	if (api_ver != KVM_API_VERSION) {
		fprintf(stderr, "Got KVM api version %d, expected %d\n",
			api_ver, KVM_API_VERSION);
		exit(1);
	}
	//VM_fd can be used to manage vm(like allocating memory,cpu etc)
	vm->fd = ioctl(vm->sys_fd, KVM_CREATE_VM, 0);
	if (vm->fd < 0) {
		perror("KVM_CREATE_VM");
		exit(1);
	}

        if (ioctl(vm->fd, KVM_SET_TSS_ADDR, 0xfffbd000) < 0) {
                perror("KVM_SET_TSS_ADDR");
		exit(1);
	}

	//printing memory allocated to VM
	//******
	printf("Inside vm_init,memory allocated to VM : %ld B , %ld KB ,%ld MB \n",mem_size,mem_size/1024,(mem_size/1024)/1024);
	//******
	// using mmap physical mem for guest is allocated and ptr is stored in vm->mem
	vm->mem = mmap(NULL, mem_size, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
	if (vm->mem == MAP_FAILED) {
		perror("mmap mem");
		exit(1);
	}
	//************
	printf("memory mapped into the virtual address space of this simple hypervisor at virtual address : %p\n",vm->mem);
	//**************
	//advise of kernel how to use memory efficiently
	madvise(vm->mem, mem_size, MADV_MERGEABLE);

	memreg.slot = 0; //The slot field provides an integer index identifying each region of memory we hand to KVM
	// calling KVM_SET_USER_MEMORY_REGION again with the same slot will replace this mapping, while calling it with a new slot will create a separate mapping.
	memreg.flags = 0;
	memreg.guest_phys_addr = 0; //guest_phys_addr specifies the base "physical" address as seen from the guest
	memreg.memory_size = mem_size;//memory_size specifies how much memory to map: one page, 0x1000 bytes.
	memreg.userspace_addr = (unsigned long)vm->mem; //userspace_addr points to the backing memory in our process that we allocated with mmap(); note that these always use 64-bit values, even on 32-bit platforms. 

    if (ioctl(vm->fd, KVM_SET_USER_MEMORY_REGION, &memreg) < 0) {
		perror("KVM_SET_USER_MEMORY_REGION");
                exit(1);
	}
}

struct vcpu {
	int fd;
	struct kvm_run *kvm_run;
};

void vcpu_init(struct vm *vm, struct vcpu *vcpu)
{
	int vcpu_mmap_size;
	//KVM gives us a handle to this VCPU in the form of a file descriptor .The 0 here represents a sequential virtual CPU index.
	vcpu->fd = ioctl(vm->fd, KVM_CREATE_VCPU, 0);
        if (vcpu->fd < 0) {
		perror("KVM_CREATE_VCPU");
                exit(1);
	}
	//for allocating memory for vcpu_run DS we have to know what size to be allocated which KVM tells using below code
	vcpu_mmap_size = ioctl(vm->sys_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
        if (vcpu_mmap_size <= 0) {
		perror("KVM_GET_VCPU_MMAP_SIZE");
                exit(1);
	}
	//**************
	printf("memory allocated to vcpu_run ds : %d B , %d KB \n",vcpu_mmap_size,vcpu_mmap_size/1024);
	//**************
	//allocating memory using mmap for kvm_run
	vcpu->kvm_run = mmap(NULL, vcpu_mmap_size, PROT_READ | PROT_WRITE,
			     MAP_SHARED, vcpu->fd, 0);
	//**************
	printf("memory allocated to vcpu_run is located in the virutal address space of the hypervisor at : %p\n",vcpu->kvm_run);
	//**************
	if (vcpu->kvm_run == MAP_FAILED) {
		perror("mmap kvm_run");
		exit(1);
	}
}

int run_vm(struct vm *vm, struct vcpu *vcpu, size_t sz)
{
	struct kvm_regs regs;
	uint64_t memval = 0;
	int cnt_calls=0;
	static int cur_open_fd=0;
	static int cur_close_fd=0;
	static int no_of_byte=0;
	for (;;) 
	{
		if (ioctl(vcpu->fd, KVM_RUN, 0) < 0) {
			perror("KVM_RUN");
			exit(1);
		}
		cnt_calls++;

		switch (vcpu->kvm_run->exit_reason) 
		{
			case KVM_EXIT_HLT:
			{
				printf("\nKVM_EXIT_HLT called !");
				goto check;
			}
			case KVM_EXIT_IO:
			{

				printf("\nKVM_EXIT_IO called !");
				if (vcpu->kvm_run->io.direction == KVM_EXIT_IO_OUT
					&& vcpu->kvm_run->io.port == 0xE9)
				{
					
					//printf("port 0xE9");	
					//printf("\nvcpu->kvm_run->io.data_offset  : %lld",vcpu->kvm_run->io.data_offset);
					//printf("\nvcpu->kvm_run->io.size  : %d",vcpu->kvm_run->io.size);

					char *p = (char *)vcpu->kvm_run;
					fwrite(p + vcpu->kvm_run->io.data_offset,vcpu->kvm_run->io.size, 1, stdout);
					fflush(stdout);
					continue;
				}
				else if(vcpu->kvm_run->io.direction == KVM_EXIT_IO_OUT
					&& vcpu->kvm_run->io.port == (uint16_t)0x10)
				{	

					printf("port 0x10");
					//printf("\nvcpu->kvm_run->io.data_offset  : %lld",vcpu->kvm_run->io.data_offset);
					//printf("\nvcpu->kvm_run->io.size  : %d",vcpu->kvm_run->io.size);

					char *p = (char *)vcpu->kvm_run;
					//fwrite((int*)(p + vcpu->kvm_run->io.data_offset),vcpu->kvm_run->io.size, 1, stdout);
					
					printf("\nval : %d",*(uint32_t*)(p + vcpu->kvm_run->io.data_offset));
					fflush(stdout);
					continue;
				}
				else if(vcpu->kvm_run->io.direction == KVM_EXIT_IO_IN
					&& vcpu->kvm_run->io.port == (uint16_t)0x20)
				{
					printf("port 0x20");
					//printf("\nvcpu->kvm_run->io.data_offset  : %lld",vcpu->kvm_run->io.data_offset);
					//printf("\nvcpu->kvm_run->io.size  : %d",vcpu->kvm_run->io.size);
			
					//printf("\ncnt_calls %d",cnt_calls);

					//printf("\ncnt %d",*cnt);
					//printf("\ncnt_calls2 %d",*(uint32_t*)(p + vcpu->kvm_run->io.data_offset));
					*(uint32_t*)((uint8_t*)vcpu->kvm_run + vcpu->kvm_run->io.data_offset) = cnt_calls;

					fflush(stdout);
					continue;
				}
				else if(vcpu->kvm_run->io.direction == KVM_EXIT_IO_OUT
					&& vcpu->kvm_run->io.port == 0x30)
				{	

					printf("port 0x30");
					//printf("\nvcpu->kvm_run->io.data_offset  : %lld",vcpu->kvm_run->io.data_offset);
					//printf("\nvcpu->kvm_run->io.size  : %d",vcpu->kvm_run->io.size);

					int ptr = *(int*)((char*)vcpu->kvm_run + vcpu->kvm_run->io.data_offset);
					char *str = (char*) vm->mem + ptr;
					
					printf("\ndisplay : %s",str);
					fflush(stdout);
					continue;
				}
				//this block initializes the fd_table for guest
				else if(vcpu->kvm_run->io.direction == KVM_EXIT_IO_IN
					&& vcpu->kvm_run->io.port == 0x40)
				{	

					printf("port 0x40");
					//printf("\nvcpu->kvm_run->io.data_offset  : %lld",vcpu->kvm_run->io.data_offset);
					//printf("\nvcpu->kvm_run->io.size  : %d",vcpu->kvm_run->io.size);
					//printf("\nfd table init");
					*(uint32_t*)((uint8_t*)vcpu->kvm_run + vcpu->kvm_run->io.data_offset) = initialize_fd_table();
					fflush(stdout);
					continue;
				}
				//this block handles the open hypercall and send its fd to the guests
				else if(vcpu->kvm_run->io.port == 0x41)
				{	
					if(vcpu->kvm_run->io.direction == KVM_EXIT_IO_OUT)
					{
						printf("port 0x41");
						// printf("\nvcpu->kvm_run->io.data_offset  : %lld",vcpu->kvm_run->io.data_offset);
						// printf("\nvcpu->kvm_run->io.size  : %d",vcpu->kvm_run->io.size);
						// printf("\nopen file");
						int ptr = *(int*)((char*)vcpu->kvm_run + vcpu->kvm_run->io.data_offset);
						char *str = (char*) vm->mem + ptr;
						open_struct* tp = (open_struct*)str;
						//int ptr = *(int*)((char*)vcpu->kvm_run + vcpu->kvm_run->io.data_offset);
						//open_struct *str = (open_struct*)((char*) vm->mem + ptr);
						tp->filename = (char*)vm->mem+(uintptr_t)tp->filename;
						// printf("\ndisplay : %s",tp->filename);
						
						cur_open_fd = guest_open_file(tp);
						//printf("value written!!");
						fflush(stdout);
						continue;
					}
					else
					{
						printf("port 0x41 return");
						// printf("\nvcpu->kvm_run->io.data_offset  : %lld",vcpu->kvm_run->io.data_offset);
						// printf("\nvcpu->kvm_run->io.size  : %d",vcpu->kvm_run->io.size);
						// printf("\nfd return");
						*(uint32_t*)((uint8_t*)vcpu->kvm_run + vcpu->kvm_run->io.data_offset) = cur_open_fd;
						fflush(stdout);
						continue;
					}
				}
				//this block will handle to close the file
				else if(vcpu->kvm_run->io.port == 0x43)
				{	
					if(vcpu->kvm_run->io.direction == KVM_EXIT_IO_OUT)
					{
						printf("port 0x43");
						//printf("\nvcpu->kvm_run->io.data_offset  : %lld",vcpu->kvm_run->io.data_offset);
						//printf("\nvcpu->kvm_run->io.size  : %d",vcpu->kvm_run->io.size);

						char *p = (char *)vcpu->kvm_run;
						//fwrite((int*)(p + vcpu->kvm_run->io.data_offset),vcpu->kvm_run->io.size, 1, stdout);
						
						int fd = *(int*)(p + vcpu->kvm_run->io.data_offset);
						
						cur_close_fd=guest_close_file(fd);
						fflush(stdout);
						continue;
					}
					else
					{
						printf("port 0x43 return");
						// printf("\nvcpu->kvm_run->io.data_offset  : %lld",vcpu->kvm_run->io.data_offset);
						// printf("\nvcpu->kvm_run->io.size  : %d",vcpu->kvm_run->io.size);
						// printf("\nfd return");
						*(uint32_t*)((uint8_t*)vcpu->kvm_run + vcpu->kvm_run->io.data_offset) = cur_close_fd;
						fflush(stdout);
						continue;
					}
				}
				//this block will handle to write to the file
				else if(vcpu->kvm_run->io.port == 0x44)
				{	
					if(vcpu->kvm_run->io.direction == KVM_EXIT_IO_OUT)
					{
						printf("port 0x44");
						// printf("\nvcpu->kvm_run->io.data_offset  : %lld",vcpu->kvm_run->io.data_offset);
						// printf("\nvcpu->kvm_run->io.size  : %d",vcpu->kvm_run->io.size);
						// printf("\nopen file");
						int ptr = *(int*)((char*)vcpu->kvm_run + vcpu->kvm_run->io.data_offset);
						char *str = (char*) vm->mem + ptr;
						write_fd_struct* tp = (write_fd_struct*)str;
						// printf("\nfd you want to write : %d",tp->fd);
						tp->str = (char*)vm->mem+(uintptr_t)tp->str;
						// printf("\nmsg : %s",tp->str);
						
						no_of_byte = guest_write_file(tp);
						// printf("value written!!");
						fflush(stdout);
						continue;
					}
					else
					{
						printf("port 0x44 return");
						// printf("\nvcpu->kvm_run->io.data_offset  : %lld",vcpu->kvm_run->io.data_offset);
						// printf("\nvcpu->kvm_run->io.size  : %d",vcpu->kvm_run->io.size);
						// printf("\nno of byte written return");
						*(uint32_t*)((uint8_t*)vcpu->kvm_run + vcpu->kvm_run->io.data_offset) = no_of_byte;
						fflush(stdout);
						continue;
					}
				}
				//this block will handle to read the data from the file
				else if(vcpu->kvm_run->io.port == 0x42)
				{	
					if(vcpu->kvm_run->io.direction == KVM_EXIT_IO_OUT)
					{
						printf("port 0x42");
						// printf("\nvcpu->kvm_run->io.data_offset  : %lld",vcpu->kvm_run->io.data_offset);
						// printf("\nvcpu->kvm_run->io.size  : %d",vcpu->kvm_run->io.size);
						
						int ptr = *(int*)((char*)vcpu->kvm_run + vcpu->kvm_run->io.data_offset);
						char *str = (char*) vm->mem + ptr;
						write_fd_struct* tp = (write_fd_struct*)str;
						// printf("\nfd you want to read : %d",tp->fd);
						tp->str = (char*)vm->mem+(uintptr_t)tp->str;
						//printf("\nmsg : %s",tp->str);
						
						no_of_byte = guest_read_file(tp);
						// printf("value readed!!");
						fflush(stdout);
						continue;
					}
					else
					{
						printf("port 0x42 return");
						// printf("\nvcpu->kvm_run->io.data_offset  : %lld",vcpu->kvm_run->io.data_offset);
						// printf("\nvcpu->kvm_run->io.size  : %d",vcpu->kvm_run->io.size);
						// printf("\nno of byte readed return");
						*(uint32_t*)((uint8_t*)vcpu->kvm_run + vcpu->kvm_run->io.data_offset) = no_of_byte;
						fflush(stdout);
						continue;
					}
				}
				//this block will handle to reposition file offset using lseek
				else if(vcpu->kvm_run->io.port == 0x45)
				{	
					if(vcpu->kvm_run->io.direction == KVM_EXIT_IO_OUT)
					{
						printf("port 0x45");
						// printf("\nvcpu->kvm_run->io.data_offset  : %lld",vcpu->kvm_run->io.data_offset);
						// printf("\nvcpu->kvm_run->io.size  : %d",vcpu->kvm_run->io.size);
						
						int ptr = *(int*)((char*)vcpu->kvm_run + vcpu->kvm_run->io.data_offset);
						char *str = (char*) vm->mem + ptr;
						lseek_fd_struct* tp = (lseek_fd_struct*)str;
						// printf("\nfd you want to lseek : %d",tp->fd);
						//printf("\nmsg : %s",tp->str);
						
						no_of_byte = guest_lseek_file(tp);
						// printf("offset repositioned!!");
						fflush(stdout);
						continue;
					}
					else
					{
						printf("port 0x45 return");
						// printf("\nvcpu->kvm_run->io.data_offset  : %lld",vcpu->kvm_run->io.data_offset);
						// printf("\nvcpu->kvm_run->io.size  : %d",vcpu->kvm_run->io.size);
						// printf("\noffset changed return");
						*(uint32_t*)((uint8_t*)vcpu->kvm_run + vcpu->kvm_run->io.data_offset) = no_of_byte;
						fflush(stdout);
						continue;
					}
				}
				
			}
				/* fall through */
			default:
				cnt_calls=0;
				fprintf(stderr,	"Got exit_reason %d,"
					" expected KVM_EXIT_HLT (%d)\n",
					vcpu->kvm_run->exit_reason, KVM_EXIT_HLT);
				exit(1);
		}
	}

 check:
 	cnt_calls=0;
	if (ioctl(vcpu->fd, KVM_GET_REGS, &regs) < 0) {
		perror("KVM_GET_REGS");
		exit(1);
	}

	if (regs.rax != 42) {
		printf("Wrong result: {E,R,}AX is %lld\n", regs.rax);
		return 0;
	}

	memcpy(&memval, &vm->mem[0x400], sz);
	if (memval != 42) {
		printf("Wrong result: memory at 0x400 is %lld\n",
		       (unsigned long long)memval);
		return 0;
	}

	return 1;
}

extern const unsigned char guest16[], guest16_end[];

int run_real_mode(struct vm *vm, struct vcpu *vcpu)
{
	struct kvm_sregs sregs;
	struct kvm_regs regs;

	printf("Testing real mode\n");

        if (ioctl(vcpu->fd, KVM_GET_SREGS, &sregs) < 0) {
		perror("KVM_GET_SREGS");
		exit(1);
	}

	sregs.cs.selector = 0;
	sregs.cs.base = 0;

        if (ioctl(vcpu->fd, KVM_SET_SREGS, &sregs) < 0) {
		perror("KVM_SET_SREGS");
		exit(1);
	}

	memset(&regs, 0, sizeof(regs));
	/* Clear all FLAGS bits, except bit 1 which is always set. */
	regs.rflags = 2;
	regs.rip = 0;

	if (ioctl(vcpu->fd, KVM_SET_REGS, &regs) < 0) {
		perror("KVM_SET_REGS");
		exit(1);
	}

	memcpy(vm->mem, guest16, guest16_end-guest16);
	return run_vm(vm, vcpu, 2);
}

static void setup_protected_mode(struct kvm_sregs *sregs)
{
	struct kvm_segment seg = {
		.base = 0,
		.limit = 0xffffffff,
		.selector = 1 << 3,
		.present = 1,
		.type = 11, /* Code: execute, read, accessed */
		.dpl = 0,
		.db = 1,
		.s = 1, /* Code/data */
		.l = 0,
		.g = 1, /* 4KB granularity */
	};

	sregs->cr0 |= CR0_PE; /* enter protected mode */

	sregs->cs = seg;

	seg.type = 3; /* Data: read/write, accessed */
	seg.selector = 2 << 3;
	sregs->ds = sregs->es = sregs->fs = sregs->gs = sregs->ss = seg;
}

extern const unsigned char guest32[], guest32_end[];

int run_protected_mode(struct vm *vm, struct vcpu *vcpu)
{
	struct kvm_sregs sregs;
	struct kvm_regs regs;

	printf("Testing protected mode\n");

        if (ioctl(vcpu->fd, KVM_GET_SREGS, &sregs) < 0) {
		perror("KVM_GET_SREGS");
		exit(1);
	}

	setup_protected_mode(&sregs);

        if (ioctl(vcpu->fd, KVM_SET_SREGS, &sregs) < 0) {
		perror("KVM_SET_SREGS");
		exit(1);
	}

	memset(&regs, 0, sizeof(regs));
	/* Clear all FLAGS bits, except bit 1 which is always set. */
	regs.rflags = 2;
	regs.rip = 0;

	if (ioctl(vcpu->fd, KVM_SET_REGS, &regs) < 0) {
		perror("KVM_SET_REGS");
		exit(1);
	}

	memcpy(vm->mem, guest32, guest32_end-guest32);
	return run_vm(vm, vcpu, 4);
}

static void setup_paged_32bit_mode(struct vm *vm, struct kvm_sregs *sregs)
{
	uint32_t pd_addr = 0x2000;
	uint32_t *pd = (void *)(vm->mem + pd_addr);

	/* A single 4MB page to cover the memory region */
	pd[0] = PDE32_PRESENT | PDE32_RW | PDE32_USER | PDE32_PS;
	/* Other PDEs are left zeroed, meaning not present. */

	sregs->cr3 = pd_addr;
	sregs->cr4 = CR4_PSE;
	sregs->cr0
		= CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_WP | CR0_AM | CR0_PG;
	sregs->efer = 0;
}

int run_paged_32bit_mode(struct vm *vm, struct vcpu *vcpu)
{
	struct kvm_sregs sregs;
	struct kvm_regs regs;

	printf("Testing 32-bit paging\n");

        if (ioctl(vcpu->fd, KVM_GET_SREGS, &sregs) < 0) {
		perror("KVM_GET_SREGS");
		exit(1);
	}

	setup_protected_mode(&sregs);
	setup_paged_32bit_mode(vm, &sregs);

        if (ioctl(vcpu->fd, KVM_SET_SREGS, &sregs) < 0) {
		perror("KVM_SET_SREGS");
		exit(1);
	}

	memset(&regs, 0, sizeof(regs));
	/* Clear all FLAGS bits, except bit 1 which is always set. */
	regs.rflags = 2;
	regs.rip = 0;

	if (ioctl(vcpu->fd, KVM_SET_REGS, &regs) < 0) {
		perror("KVM_SET_REGS");
		exit(1);
	}

	memcpy(vm->mem, guest32, guest32_end-guest32);
	return run_vm(vm, vcpu, 4);
}

extern const unsigned char guest64[], guest64_end[];

static void setup_64bit_code_segment(struct kvm_sregs *sregs)
{
	struct kvm_segment seg = {
		.base = 0,
		.limit = 0xffffffff,
		.selector = 1 << 3,
		.present = 1,
		.type = 11, /* Code: execute, read, accessed */
		.dpl = 0,
		.db = 0,
		.s = 1, /* Code/data */
		.l = 1,
		.g = 1, /* 4KB granularity */
	};

	sregs->cs = seg;

	seg.type = 3; /* Data: read/write, accessed */
	seg.selector = 2 << 3;
	sregs->ds = sregs->es = sregs->fs = sregs->gs = sregs->ss = seg;
}

static void setup_long_mode(struct vm *vm, struct kvm_sregs *sregs)
{
	// 0x2000 = 8K 
	uint64_t pml4_addr = 0x2000;
	uint64_t *pml4 = (void *)(vm->mem + pml4_addr);

	// 0X3000= 12K
	uint64_t pdpt_addr = 0x3000;
	uint64_t *pdpt = (void *)(vm->mem + pdpt_addr);

	// 0x4000 = 16k
	uint64_t pd_addr = 0x4000;
	uint64_t *pd = (void *)(vm->mem + pd_addr);

	pml4[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pdpt_addr;
	pdpt[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pd_addr;
	pd[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | PDE64_PS;

	sregs->cr3 = pml4_addr;
	sregs->cr4 = CR4_PAE;
	sregs->cr0
		= CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_WP | CR0_AM | CR0_PG;
	sregs->efer = EFER_LME | EFER_LMA;

	setup_64bit_code_segment(sregs);
}

int run_long_mode(struct vm *vm, struct vcpu *vcpu)
{
	struct kvm_sregs sregs;
	struct kvm_regs regs;

	printf("Testing 64-bit mode\n");
		//Reads special registers from the vcpu.
        if (ioctl(vcpu->fd, KVM_GET_SREGS, &sregs) < 0) {
		perror("KVM_GET_SREGS");
		exit(1);
	}

	setup_long_mode(vm, &sregs);

        if (ioctl(vcpu->fd, KVM_SET_SREGS, &sregs) < 0) {
		perror("KVM_SET_SREGS");
		exit(1);
	}

	memset(&regs, 0, sizeof(regs));
	/* Clear all FLAGS bits, except bit 1 which is always set. */
	regs.rflags = 2;
	regs.rip = 0;
	/* Create stack at top of 2 MB page and grow down. */
	regs.rsp = 2 << 20;

	if (ioctl(vcpu->fd, KVM_SET_REGS, &regs) < 0) {
		perror("KVM_SET_REGS");
		exit(1);
	}

	memcpy(vm->mem, guest64, guest64_end-guest64);
	return run_vm(vm, vcpu, 8);
}


int main(int argc, char **argv)
{
	struct vm vm;
	struct vcpu vcpu;
	enum {
		REAL_MODE,
		PROTECTED_MODE,
		PAGED_32BIT_MODE,
		LONG_MODE,
	} mode = REAL_MODE;
	int opt;

	while ((opt = getopt(argc, argv, "rspl")) != -1) {
		switch (opt) {
		case 'r':
			mode = REAL_MODE;
			break;

		case 's':
			mode = PROTECTED_MODE;
			break;

		case 'p':
			mode = PAGED_32BIT_MODE;
			break;

		case 'l':
			mode = LONG_MODE;
			break;

		default:
			fprintf(stderr, "Usage: %s [ -r | -s | -p | -l ]\n",
				argv[0]);
			return 1;
		}
	}

	vm_init(&vm, 0x200000);
	vcpu_init(&vm, &vcpu);

	switch (mode) {
	case REAL_MODE:
		return !run_real_mode(&vm, &vcpu);

	case PROTECTED_MODE:
		return !run_protected_mode(&vm, &vcpu);

	case PAGED_32BIT_MODE:
		return !run_paged_32bit_mode(&vm, &vcpu);

	case LONG_MODE:
		return !run_long_mode(&vm, &vcpu);
	}

	return 1;
}
