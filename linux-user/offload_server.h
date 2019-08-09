#ifndef OFFLOAD_SERVER_H
#define OFFLOAD_SERVER_H


#include "qemu/osdep.h"
#include "qemu/units.h"
#include "qemu-version.h"
#include <sys/syscall.h>
#include <sys/resource.h>

#include "qapi/error.h"
#include "qemu.h"
#include "qemu/path.h"
#include "qemu/config-file.h"
#include "qemu/cutils.h"
#include "qemu/help_option.h"
#include "cpu.h"
#include "exec/exec-all.h"
#include "tcg.h"
#include "qemu/timer.h"
#include "qemu/envlist.h"
#include "elf.h"
#include "trace/control.h"
#include "target_elf.h"
#include "cpu_loop-common.h"

#include <sys/socket.h>
#include "offload_common.h"
#include <sys/timeb.h>
#define MAP_PAGE_BITS 12
void offload_send_page_request_and_wait(uint32_t page_addr, int perm);
void* offload_server_start_thread(void* arg);
typedef struct PageMapDesc_server {
	int cur_perm;
	int is_false_sharing;
	uint32_t shadow_page_addr;
} PageMapDesc_server;
PageMapDesc_server page_map_table_s[L1_MAP_TABLE_SIZE][L2_MAP_TABLE_SIZE] __attribute__ ((section (".page_table_section_server"))) __attribute__ ((aligned(4096))) = {0};
PageMapDesc_server *get_pmd_s(uint32_t page_addr);
/* Wake up main exec thread. */
extern pthread_mutex_t main_exec_mutex;
extern pthread_cond_t main_exec_cond;
extern int main_exec_flag;
void offload_page_recv_wake_up_thread(uint32_t page_addr, int perm);
static void try_recv(int);
int sktfd;
int client_socket;
extern int offload_server_idx;
static char net_buffer[NET_BUFFER_SIZE];
static pthread_mutex_t socket_mutex;
#define BUFFER_PAYLOAD_P (net_buffer + TCP_HEADER_SIZE)
#define fprintf offload_log
extern CPUArchState *env;
uint32_t stack_end, stack_start;
extern pthread_mutex_t cmpxchg_mutex;
extern __thread int offload_thread_idx;
int futex_result;
static int autoSend(int,char*,int,int);
static void offload_server_init(void);
static void offload_server_daemonize(void);
static void offload_process_start(void);
static void load_cpu(void);
static void load_binary(void);
static void load_brk(void);
static void load_memory_region(void);
void exec_func(void);
static void offload_server_process_futex_wait_result(void);
static void offload_process_fork_info(void);
static void offload_server_send_futex_wait_request(target_ulong uaddr, int op, int val, target_ulong timeout, target_ulong uaddr2, int val3);
int offload_server_futex_wait(target_ulong uaddr, int op, int val, target_ulong timeout, target_ulong uaddr2, int val3);
static void offload_server_send_page_request(target_ulong page_addr, uint32_t perm);
int offload_segfault_handler_positive(uint32_t page_addr, int perm);
void offload_server_send_mutex_request(uint32_t mutex_addr, uint32_t, uint32_t, uint32_t);
static void offload_process_page_request(void);
static void offload_process_page_content(void);
static void offload_send_page_content(target_ulong page_addr, uint32_t perm,int);
static void offload_send_page_ack(target_ulong page_addr, uint32_t perm);
int offload_segfault_handler(int host_signum, siginfo_t *pinfo, void *puc);
static void offload_process_page_perm(void);
void offload_server_start(void);
void* offload_center_server_start(void*);
static void offload_server_process_futex_wake_result(void);
void offload_server_send_cmpxchg_start(uint32_t, uint32_t, uint32_t, uint32_t);
void offload_server_send_cmpxchg_end(uint32_t, uint32_t);
extern void offload_server_qemu_init(void);
extern void offload_server_extra_init(void);
abi_long pass_syscall(void *cpu_env, int num, abi_long arg1,
					  abi_long arg2, abi_long arg3, abi_long arg4,
					  abi_long arg5, abi_long arg6, abi_long arg7,
					  abi_long arg8);
int offload_server_futex_wake(target_ulong uaddr, int op, int val, target_ulong timeout, target_ulong uaddr2, int val3);
static void offload_server_process_syscall_result(void);
static void offload_process_tid(void);
extern void fork_start(void);
extern void fork_end(int);
extern void start_exclusive(void);
extern void end_exclusive(void);

#endif
