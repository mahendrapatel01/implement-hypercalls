#include <stddef.h>
#include <stdint.h>

#define PRINT_VAL_PORT 0x10
#define GET_NUM_EXIT_PORT 0x20
#define DISPLAY_PORT 0x30

//file macros
#define INIT_FILE_TABLE_PORT 0x40
#define OPEN_FILE_PORT 0x41
#define READ_FILE_PORT 0x42
#define WRITE_FILE_PORT 0x44
#define CLOSE_FILE_PORT 0x43
#define LSEEK_FILE_PORT 0x45
//static void outb(uint16_t port, uint8_t value) {
//	asm("outb %0,%1" : /* empty */ : "a" (value), "Nd" (port) : "memory");
//}

typedef struct open_struct{
	const char* filename;
	int rd;
	int wr;
	int rdwr;
	int cr;
	int ex;
} open_struct;

static inline void outb(uint16_t port, uint32_t value) {
  asm("out %0,%1" : /* empty */ : "a" (value), "Nd" (port) : "memory");
}

static inline uint32_t inb(uint16_t port) {
  uint32_t ret;
  asm("in %1, %0" : "=a"(ret) : "Nd"(port) : "memory" );
  return ret;
}

// static inline void outb2(uint16_t port, uint32_t* value) {
//   asm("out %0,%1" : /* empty */ : "a" (value), "Nd" (port) : "memory");
// }

static inline void printVal(uint32_t val)
{
	outb(PRINT_VAL_PORT,val);
}

static inline uint32_t getNumExits()
{
	return inb(GET_NUM_EXIT_PORT);
}

static inline void display(const char *str)
{
	outb(DISPLAY_PORT,(uintptr_t)str);
}

static inline uint32_t init_fd_table()
{
	return inb(INIT_FILE_TABLE_PORT);
}

static inline int open(char* filename,int rd,int wr,int rdwr,int cr,int ex)
{
	open_struct open_det={filename,rd,wr,rdwr,cr,ex};
	open_struct* ptr = &open_det; 
	outb(OPEN_FILE_PORT,(uintptr_t)ptr);
	return inb(OPEN_FILE_PORT);
}

static inline int close(int fd)
{
	outb(CLOSE_FILE_PORT,fd);
	return inb(CLOSE_FILE_PORT);
}

typedef struct write_fd_struct
{
	int fd;
	char* str;
	int offset;
} write_fd_struct;

static inline int write(int fd, char* str, int offset)
{
	write_fd_struct write_fd = {fd,str,offset};
	write_fd_struct* wfd = &write_fd;
	outb(WRITE_FILE_PORT,(uintptr_t)wfd);
	return inb(WRITE_FILE_PORT);
}

static inline int read(int fd, char* str, int offset)
{
	write_fd_struct write_fd = {fd,str,offset};
	write_fd_struct* rfd = &write_fd;
	outb(READ_FILE_PORT,(uintptr_t)rfd);
	return inb(READ_FILE_PORT);
}

typedef struct lseek_fd_struct{
	int fd;
	int offset;
	int wench_seek_set;
	int wench_seek_cur;
	int wench_seek_end;
} lseek_fd_struct;

static inline int lseek(int fd,int offset,int seek_set,int seek_cur,int seek_end)
{
	lseek_fd_struct lseek_fd = {fd,offset,seek_set,seek_cur,seek_end};
	lseek_fd_struct* lfd = &lseek_fd;
	outb(LSEEK_FILE_PORT,(uintptr_t)lfd);
	return inb(LSEEK_FILE_PORT);
}


void
__attribute__((noreturn))
__attribute__((section(".start")))
_start(void) {
	const char *p;

	//using simple outb func
	for (p = "Hello, world!\n"; *p; ++p)
		outb(0xE9, *p);

	//use of printVal func
	//uint32_t cr= 10000;
	//printVal(cr);

	//use of getnumexits function
	uint32_t cnt=getNumExits();
	printVal(cnt);


	printVal(getNumExits());
	display("this is a display func!!!");
	printVal(getNumExits());


	printVal(init_fd_table());


	int fd;
	char* filename="test5.txt";
	fd = open(filename,0,1,0,1,0);

	//printVal(close(fd));

	char *msg= "hello writing to file!!!";
	int offset = 0;
	while(msg[offset]!='\0')
		offset++;
	printVal(write( fd, msg,offset));

	char *rd_msg="";
	printVal(read(fd,rd_msg,offset));

	display(rd_msg);

	printVal(lseek(fd,4,1,0,0));

	char *rd_msg2="";

	printVal(read(fd,rd_msg2,offset-5));

	display(rd_msg2);
	


	//use of display function
	//const char* str="rgdgdsdvdv sf dsf";
	//display(str);

	//file hypercalls test
	//const char* filename="test1.txt";

	*(long *) 0x400 = 42;	

	for (;;)
		asm("hlt" : /* empty */ : "a" (42) : "memory");
}
