#ifndef OFFLOAD_COMMON_H
#define OFFLOAD_COMMON_H

#include <stdint.h>
#include <pthread.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#define PORT_BASE 12345

#define NET_BUFFER_SIZE 3000000
#define MAX_OFFLOAD_NUM 100

#define IDX_CLIENT 0
extern __thread char *p;
extern int g_false_sharing_flag;
int client_port_of(int idx);


int server_port_of(int idx);

struct tcp_msg_header
{
	uint32_t magic_nr;  /* magic number */
	uint32_t size;  /* payload size */
	uint32_t tag;   /* tag */
	uint32_t counter;
};


extern int global_counter;
extern pthread_mutex_t global_counter_mutex;
#define COMM_MAGIC_NR   0x41824182
#define TCP_HEADER_SIZE (sizeof(struct tcp_msg_header))

#define fill_tcp_header(__header, __size, __tag)    \
	do {                                            \
	(__header)->magic_nr = COMM_MAGIC_NR;       \
	(__header)->size     = __size;              \
	(__header)->tag      = __tag;               \
	pthread_mutex_lock(&global_counter_mutex);	\
	(__header)->counter      = ++global_counter;   \
	fprintf(stderr, "SSSSSSSSSSSending package number %d\n", global_counter); \
	pthread_mutex_unlock(&global_counter_mutex);	\
} while (0)



enum
{
	TAG_INVALID = 0,
	TAG_OFFLOAD_START,
	TAG_OFFLOAD_PAGE_REQUEST,
	TAG_OFFLOAD_PAGE_CONTENT,
	TAG_OFFLOAD_PAGE_ACK,
	TAG_OFFLOAD_PAGE_PERM,
	TAG_OFFLOAD_PAGE_UPGRADE,
	TAG_OFFLOAD_SYSCALL_REQUEST,
	TAG_OFFLOAD_SYSCALL_RESULT,
	TAG_OFFLOAD_END,
	TAG_OFFLOAD_CMPXCHG_START,
	TAG_OFFLOAD_CMPXCHG_END,
	TAG_OFFLOAD_CMPXCHG_ACK,
	TAG_OFFLOAD_FUTEX_WAIT_REQUEST,
	TAG_OFFLOAD_FUTEX_WAIT_RESULT,
	TAG_OFFLOAD_FUTEX_WAKE_REQUEST,
	TAG_OFFLOAD_FUTEX_WAKE_RESULT,
	TAG_OFFLOAD_CMPXCHG_REQUEST,
	TAG_OFFLOAD_CMPXCHG_VERYFIED,
	TAG_OFFLOAD_CMPXCHG_DONE,
	TAG_OFFLOAD_SYSCALL_REQ,
	TAG_OFFLOAD_SYSCALL_RES,
	TAG_OFFLOAD_YOUR_TID,
	TAG_OFFLOAD_FORK_INFO,
	TAG_OFFLOAD_PAGE_WAKEUP,
	TAG_OFFLOAD_FS_PAGE

};


extern void offload_log(FILE*, const char*, ...);

extern pthread_mutex_t master_mprotect_mutex;
extern __thread int offload_mode;

static uint32_t get_tag(void);
/* same as PROT_xxx */
#define PAGE_NONE   0x0000
#define PAGE_READ   0x0001
#define PAGE_WRITE  0x0002
#define PAGE_EXEC   0x0004
#define PAGE_VALID  0x0008

#define VIRT_ADDR_SPACE_BITS 32
#define PAGE_SIZE 0x1000

#define PAGE_MASK 0xfffff000
#define PAGE_ALIGN(addr) (((addr) + PAGE_SIZE - 1) & PAGE_MASK)


#define PAGE_OF(addr) ((addr >> 10) << 10)
/*
 * Currently, we only support offloading 32 bit ARM app to x86-64 server.
 * Both of them use 4K page size (normal), so we only need two level mapping tables.
 */
#define L1_MAP_TABLE_BITS 10
#define L1_MAP_TABLE_SIZE (1 << L1_MAP_TABLE_BITS)

#define L2_MAP_TABLE_BITS 10
#define L2_MAP_TABLE_SIZE (1 << L2_MAP_TABLE_BITS)

#define L1_MAP_TABLE_SHIFT (VIRT_ADDR_SPACE_BITS - 12 - L1_MAP_TABLE_BITS)

#endif
