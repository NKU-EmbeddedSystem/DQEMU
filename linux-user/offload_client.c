



#define MAP_PAGE_BITS 12
// prefetch
#define MAX_WORKER 16
#define PREFETCH_PAGE_MAX 1000
#define PREFETCH_LAUNCH_VALVE 4
#define PREFETCH_LIFE 80
#define PREFETCH_BEGIN_PAGE_COUNT 10
#define ONLINE_SERVER 2


//#define PAGE_SEGMENT (PAGE_SIZE/MIN_PAGE_GRAIN)

//#define _ATFILE_SOURCE
#include "qemu/osdep.h"
#include "qemu/cutils.h"
#include "qemu/path.h"
#include <elf.h>
#include <endian.h>
#include <grp.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/file.h>
#include <sys/fsuid.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/swap.h>
#include <linux/capability.h>
#include <sched.h>
#include <sys/timex.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <poll.h>
#include <sys/times.h>
#include <sys/shm.h>
#include <sys/sem.h>
#include <sys/statfs.h>
#include <utime.h>
#include <sys/sysinfo.h>
#include <sys/signalfd.h>
//#include <sys/user.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/wireless.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/errqueue.h>
#include <linux/random.h>
#include "qemu-common.h"
#ifdef CONFIG_TIMERFD
#include <sys/timerfd.h>
#endif
#ifdef TARGET_GPROF
#include <sys/gmon.h>
#endif
#ifdef CONFIG_EVENTFD
#include <sys/eventfd.h>
#endif
#ifdef CONFIG_EPOLL
#include <sys/epoll.h>
#endif
#ifdef CONFIG_ATTR
#include "qemu/xattr.h"
#endif
#ifdef CONFIG_SENDFILE
#include <sys/sendfile.h>
#endif
#define termios host_termios
#define winsize host_winsize
#define termio host_termio
#define sgttyb host_sgttyb /* same as target */
#define tchars host_tchars /* same as target */
#define ltchars host_ltchars /* same as target */
#include <linux/termios.h>
#include <linux/unistd.h>
#include <linux/cdrom.h>
#include <linux/hdreg.h>
#include <linux/soundcard.h>
#include <linux/kd.h>
#include <linux/mtio.h>
#include <linux/fs.h>
#if defined(CONFIG_FIEMAP)
#include <linux/fiemap.h>
#endif
#include <linux/fb.h>
#include <linux/vt.h>
#include <linux/dm-ioctl.h>
#include <linux/reboot.h>
#include <linux/route.h>
#include <linux/filter.h>
#include <linux/blkpg.h>
#include <netpacket/packet.h>
#include <linux/netlink.h>
#ifdef CONFIG_RTNETLINK
#include <linux/rtnetlink.h>
#include <linux/if_bridge.h>
#endif
#include <linux/audit.h>
#include "linux_loop.h"
#include "uname.h"
#include "qemu.h"
#include "offload_client.h"
#define DQEMU_PAGE_BITS
#define DQEMU_PAGE_NONE			0x0		/* NONE. READ, WRITE **in local** */
#define DQEMU_PAGE_READ			0x1
#define DQEMU_PAGE_WRITE		0x2
#define DQEMU_PAGE_PROCESS_FS	0x4		/* Generating shadow pages. */
#define DQEMU_PAGE_FS			0x8		/* False sharing page in use. */
#define DQEMU_PAGE_SHADOW		0x10	/* Shadow page */
#define DQEMU_PAGE_FS_LOCK		0x16	/* A well done fs page, should never be used again. */
#define TARGET_PAGE_SIZE PAGE_SIZE

extern int offload_server_idx;

target_ulong shadow_page_base = 0xa0000000;
static void offload_send_mutex_verified(int);

static void offload_send_page_wakeup(int idx, target_ulong page_addr);
static void offload_process_mutex_done(void);
static void offload_send_syscall_result(int,abi_long,int);
static void offload_process_syscall_request(void);
static void offload_send_tid(int idx, uint32_t tid);
//futexes
static void futex_table_wake(uint32_t futex_addr, int num, int idx, int thread_id);
static void print_futex_table();
static void futex_table_add(uint32_t futex_addr, int idx, int thread_id);
static int try_recv(int);
static int communication_send_sum, communication_recv_sum;
static pthread_mutex_t g_cas_mutex = PTHREAD_MUTEX_INITIALIZER;
extern int offload_segfault_handler_positive(uint32_t page_addr, int perm);
extern int gst_thrd_plc[32];
int syscall_started_flag;
int futex_table_cmp_requeue(uint32_t uaddr, int futex_op, int val, uint32_t val2,
							uint32_t uaddr2, int val3, int idx, int thread_id);
void offload_connect_online_server(int idx);
int false_sharing_flag = 0;
__thread char buf[TARGET_PAGE_SIZE * 2];

extern PageMapDesc_server page_map_table_s[L1_MAP_TABLE_SIZE][L2_MAP_TABLE_SIZE];
extern PageMapDesc_server *get_pmd_s(uint32_t page_addr);

//int requestor_idx, target_ulong addr, int perm
struct info
{
	int requestor_idx,perm;
	target_ulong addr;
};
/* Guest thread placement information. */
typedef struct {
    int server_idx;
    int thread_idx;
} gst_thrd_info_t;
extern gst_thrd_info_t gst_thrd_info[32];
/* In syscall.c, to determine which thread is being creating. */
extern int thread_count;

struct syscall_param
{
	void* cpu_env;
	int num;
	abi_long arg1;
	abi_long arg2;
	abi_long arg3;
	abi_long arg4;
	abi_long arg5;
	abi_long arg6;
	abi_long arg7;
	abi_long arg8;
	int idx;
	int thread_id;
};

struct syscall_param* syscall_global_pointer;
static pthread_mutex_t clone_syscall_mutex;
static int testint = 233;
struct Node
{
	int val;
	int thread_id;
	struct Node * next;
};
struct futex_record
{
	uint32_t futex_addr;
	int isInUse;
	struct Node * head;
};
struct pgft_record
{
	uint32_t page_addr;
	uint32_t wait_addr;
	uint32_t fetch_beg_addr;
	int life;
	int wait_hit_count;// for correctly pre
	int pref_count;// how many is beging prefetching
	int page_hit_count;// for conflicting pages
	struct pgft_record *next;
};

static struct futex_record * futex_table;
static struct pgft_record prefetch_table[MAX_WORKER];
static int prefetch_handler(uint32_t page_addr, int idx);
static int prefetch_check(uint32_t page_addr, int idx);
static void show_prefetch_list(int idx);

#include "set.h"
#include "offload_common.h"


#define fprintf offload_log

//#define MUTEX_LIST_MAX 32
#define FUTEX_RECORD_MAX 16

//#define FUTEX_RECORD_MAX 32

static __thread char net_buffer[NET_BUFFER_SIZE];

static target_ulong mutex_list[FUTEX_RECORD_MAX] = {0};

// |mutex address|holder|requestor list|pending flag|
struct MutexTuple
{
	uint32_t mutexAddr;
	uint32_t holderId;
	bool hasPending;
	uint32_t pendingList[FUTEX_RECORD_MAX];	//TODO: SHOULD BE INT!!! BECAUSE CLIENT STARTS WITH #0!!!!!!
	int tail;	// behave as a list
	int head;
};

static struct MutexTuple MutexList[FUTEX_RECORD_MAX];
FILE *log;
typedef struct cas_record
{
	uint32_t cas_addr;
	uint32_t cas_value;
	int user;
	struct cas_record *next;
	struct cas_node *req_list;
} cas_record;

typedef struct cas_node
{
	uint32_t cmpv;
	uint32_t newv;
	uint32_t strv;
	int idx;
	struct cas_node *next;
} cas_node;

cas_record cas_list = {0, 0, 0, 0, 0};

static int autoSend(int Fd,char* buf, int length, int flag);

extern __thread int offload_client_idx;
extern abi_ulong target_brk;
extern abi_ulong target_original_brk;
extern int offload_count;
pthread_mutex_t offload_count_mutex = PTHREAD_MUTEX_INITIALIZER;
static __thread pthread_mutex_t send_mutex[MAX_WORKER];
static __thread pthread_cond_t send_cond[MAX_WORKER];
__thread CPUArchState *client_env;
int skt[MAX_OFFLOAD_NUM];
#define BUFFER_PAYLOAD_P (net_buffer + TCP_HEADER_SIZE)
int got_page = 0;

target_ulong binary_start_address;
target_ulong binary_end_address;

int last_flag_recv = 1; // whether we received something.
int last_flag_pending = 1; // whether we had a pending request.

static __thread int cmpxchg_flag;

static pthread_mutex_t count_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t socket_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t do_syscall_mutex; static pthread_cond_t do_syscall_cond; int do_syscall_flag;
static int is_first_do_syscall_thread;





typedef struct req_node {
	int idx;
	int perm;
	struct req_node *next;
} req_node;

typedef struct PageMapDesc {
	int on_master;						/* if this page is on master side */
	int requestor;
	set_t owner_set;
	pthread_mutex_t owner_set_mutex;	/* We lock the mutex when start fetching for it, until receives ack */
	int mutex_holder;					/* Not very useful unless for debugging */
	int invalid_count;					/* How many we should tell to invalidate */
	int cur_perm;
	req_node list_head; 				/* to record request list */
	uint32_t flag;
	uint32_t shadow_page_addr;
	int fs_notice_count;				/* for the last time use of fs page */
} PageMapDesc;

PageMapDesc page_map_table[L1_MAP_TABLE_SIZE][L2_MAP_TABLE_SIZE] __attribute__ ((section (".page_table_section"))) __attribute__ ((aligned(4096))) = {0};
PageMapDesc *get_pmd(uint32_t page_addr);
static int fetch_page_func(int requestor_idx, target_ulong addr, int perm);
static uint32_t get_number(void)
{
	struct tcp_msg_header tmh = *((struct tcp_msg_header *) net_buffer);
	return tmh.counter;
}
static uint32_t get_tag(void)
{
	struct tcp_msg_header tmh = *((struct tcp_msg_header *) net_buffer);
	return tmh.tag;
}
// used along with pthread_cond, indicate whether the page required by the execution thread is received.
static __thread int page_recv_flag; static __thread pthread_mutex_t page_recv_mutex; static __thread pthread_cond_t page_recv_cond;


void close_network(void);

static void dump_cpu(void);

static int dump_self_maps(void);
static void dump_brk(void);
static void dump_code(void);
static void offload_send_start(int);
static void offload_send_page_upgrade(int idx, target_ulong page_addr, int);

static void offload_process_page_request(void);
void* offload_client_daemonize(void);
static void offload_client_send_futex_wake_result(int result);
//int client_segfault_handler(int host_signum, siginfo_t *pinfo, void *puc);

int offload_client_start(CPUArchState *the_env);
void* offload_center_client_start(void*);
static void offload_send_page_request(int idx, target_ulong guest_addr, uint32_t perm,int);
static void offload_send_page_content(int idx, target_ulong guest_addr, uint32_t perm, char *content);

static void offload_client_send_cmpxchg_ack(target_ulong);
static void offload_process_page_ack(void);
static void offload_send_page_perm(int idx, target_ulong page_addr, int perm);
static int offload_client_fetch_page(int requestor_idx, uint32_t page_addr, int is_write);
static void offload_process_page_content(void);
void offload_client_pmd_init(void);



static int offload_client_futex_prelude(target_ulong page_addr);
static void offload_client_futex_epilogue(target_ulong page_addr);




void offload_client_pmd_init(void)
{
	pthread_mutexattr_t tmp;
	/*pthread_mutexattr_init(&tmp);
	pthread_mutexattr_settype(&tmp, PTHREAD_MUTEX_RECURSIVE);*/

	for (int i = 0; i < L1_MAP_TABLE_SIZE; i++)
	{
		for (int j = 0; j < L2_MAP_TABLE_SIZE; j++)
		{
			memset(&page_map_table[i][j], 0, sizeof(PageMapDesc));
			pthread_mutex_init(&page_map_table[i][j].owner_set_mutex, NULL);
			clear(&page_map_table[i][j].owner_set);
			insert(&page_map_table[i][j].owner_set, 0);
			
			//fprintf(stderr, "%d", page_map_table[i][j].owner_set.size);
		}
	}
}

extern void offload_server_qemu_init(void);

/* Connect the target server. */
void offload_connect_online_server(int idx)
{
	skt[idx] = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	struct sockaddr_in server_addr, client_addr;
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(server_port_of(idx));
	char* ip_addr;
	switch (idx)
	{
		case 0:
			ip_addr = "127.0.0.1";
			break;
		case 1:
		case 2:
		default:
			ip_addr = "10.134.101.9";
			break;
	}
	ip_addr = "127.0.0.1";

	//检索服务器的ip地址
	unsigned long dst_ip;
	fprintf(stderr,"ip_addr: %s\n", ip_addr);
	if((dst_ip=inet_addr(ip_addr))){
		struct hostent *he;  //主机信息

		if((he=gethostbyname(ip_addr))==NULL){
		fprintf(stderr,"gethostbyname error\n");
		exit(-2);
		}
		fprintf(stderr, "[offload_connect_online_server]\tgot host name %s, h_addrtype %d, h_addr: %p\n", he->h_name, he->h_addrtype, he->h_addr);
		memcpy((char *)&dst_ip,(char *)he->h_addr,sizeof(he->h_addr));
	}
	//server_addr.sin_addr.s_addr = inet_addr(ip_addr);
	server_addr.sin_addr.s_addr=dst_ip;

	bzero(&(server_addr.sin_zero), 8);
	int struct_len = sizeof(struct sockaddr_in);
	//static int ncount = 0;
	//if (ncount < 2) {
		//fprintf(stderr, "[client]\toffload index: %d\n", idx);
		fprintf(stderr, "[offload_connect_online_server]\tconnecting to server, port# %d\n"
						, server_port_of(idx));
		if (connect(skt[idx],(struct sockaddr*) &server_addr, struct_len) == -1)
		{
			fprintf(stderr, "[offload_connect_online_server]\tconnect port# %d failed, errno: %d\n"
							, server_port_of(idx), errno);
			perror("connect");
			exit(1);
		}
	//	ncount ++;
	//}

	fprintf(stderr,"[offload_connect_online_server]\tconnecting succeed, "
					"client index# %d, skt: %d\n", idx, skt[idx]);

#ifdef NONBLOCK_RECEIVE
	NONBLOCK receive
	fcntl(skt[idx], F_SETFL, fcntl(skt[idx], F_GETFL) | O_NONBLOCK);
	struct timeval timeout={1, 0};
	int ret = setsockopt(skt[idx], SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
#endif
}
static void offload_client_init(void)
{
	pthread_mutex_lock(&offload_count_mutex);
	offload_count++;
	assert(offload_count == offload_client_idx);
	offload_client_idx = offload_count;
	pthread_mutex_unlock(&offload_count_mutex);

	fprintf(stderr, "[offload_client_init]\tindex: %d\n", offload_client_idx);
	pthread_mutex_init(&page_recv_mutex, NULL);
	pthread_cond_init(&page_recv_cond, NULL);
	pthread_mutex_init(&send_mutex[offload_client_idx], NULL);
	pthread_cond_init(&send_cond[offload_client_idx], NULL);
	communication_send_sum = 0;
	communication_recv_sum = 0;
	// List[i] is the list for worker#i
	show_prefetch_list(offload_client_idx);
	return;
}


void close_network(void)
{
	close(skt[offload_client_idx]);
}

static int dump_self_maps(void)
{

	CPUState *cpu = ENV_GET_CPU((CPUArchState *)client_env);

	TaskState *ts = cpu->opaque;
	FILE *fp;
	char *line = NULL;
	size_t len = 0;
	size_t read;

	fp = fopen("/proc/self/maps", "r");


	if (fp == NULL) {
		return -1;
	}

	int section_count = 0;
	int line_count = 0;
	// static int has_read = 0;

	int num = 0;
	uint32_t *p_num = (uint32_t *)p;
	p += sizeof(uint32_t);

	// heap_end
	*((uint32_t *) p) = target_brk;
	p += sizeof(uint32_t);

	uint32_t *p_stack_start = (uint32_t *)p;
	p += sizeof(uint32_t);

	uint32_t *p_stack_end = (uint32_t *)p;
	p += sizeof(uint32_t);

	while ((read = getline(&line, &len, fp)) != -1) {

		int fields, dev_maj, dev_min, inode;
		uint64_t min, max, offset;
		char flag_r, flag_w, flag_x, flag_p;
		char path[512] = "";
		fields = sscanf(line, "%"PRIx64"-%"PRIx64" %c%c%c%c %"PRIx64" %x:%x %d"
						" %512s", &min, &max, &flag_r, &flag_w, &flag_x,
						&flag_p, &offset, &dev_maj, &dev_min, &inode, path);

		line_count ++;

		//printf("#%d: %s", line_count, line);
		if ((fields < 10) || (fields > 11)) {
			continue;
		}
		if (h2g_valid(min)) {

			int flags = page_get_flags(h2g(min));
			max = h2g_valid(max - 1) ? max : (uintptr_t)g2h(GUEST_ADDR_MAX);
			if (page_check_range(h2g(min), max - min, flags) == -1) {
				continue;
			}

			// question: Why the guest stack is not on the host stack?
			// actually what is the difference between the OS stack and the other sections?
			// can a program itself create a new section?

			uint32_t start = h2g(min);
			uint32_t end = h2g(max - 1) + 1;


			if (h2g(min) == ts->info->stack_limit) {
				pstrcpy(path, sizeof(path), "	   [stack]");
				*p_stack_start = start;
				*p_stack_end = end;
			}

			section_count ++;

			/*fprintf(fd, TARGET_ABI_FMT_lx "-" TARGET_ABI_FMT_lx
					" %c%c%c%c %08" PRIx64 " %02x:%02x %d %s%s\n",
					h2g(min), h2g(max - 1) + 1, flag_r, flag_w,
					flag_x, flag_p, offset, dev_maj, dev_min, inode,
					path[0] ? "			" : "", path);*/


			uint32_t flag = 0;


			if (flag_w == 'w')
			{
				flag = flag | PROT_WRITE;
			}
			if (flag_r == 'r')
			{
				flag = flag | PROT_READ;
			}


			if (flag_x == 'x')
			{
				flag = flag | PROT_EXEC;
				binary_start_address = start;
				binary_end_address = end;
			}

			fprintf(stderr, "memory region: %x to %x, host: %x to %x, %c%c%c\n", start, end, g2h(start), g2h(end), flag_r, flag_w, flag_x);
			//fprintf(stderr, "[DEBUGGG]\t%lx", g2h(8e568));
			*(uint32_t *)p = start;
			p += sizeof(uint32_t);

			*(uint32_t *)p = (end - start) / PAGE_SIZE;;
			p += sizeof(uint32_t);


			*(uint32_t *)p = flag;
			p += sizeof(uint32_t);

			*(uint32_t *)p = (uint32_t)(end - start);
			p += sizeof(uint32_t);


			num++;
		}
	}


	*((uint32_t *) p_num) = num;


	fprintf(stderr, "[client]\tmemory region of %d\n", *((uint32_t *) p_num));
	free(line);
	fclose(fp);
	return 0;
}






static void dump_brk(void)
{
	// question: what is the difference between the target_original_brk and the target_brk ?
	// are they old brk and brk dedicated by the CSBT client?
	// what is the difference between brk and heap_end
	*(uint32_t *)p = 0;
	p += sizeof(uint32_t);
	*(uint32_t *)p = target_brk;
	p += sizeof(uint32_t);
}


static void dump_code(void)
{
	*(uint32_t *)p = binary_start_address;
	p += sizeof(uint32_t);


	*(uint32_t *)p = binary_end_address;
	p += sizeof(uint32_t);

	//printf("socket fd address: %p\n", (void*)&skt);
	fprintf(stderr, "[dump_code]\tbinary start: %x end: %x, pc: %x\n", binary_start_address, binary_end_address, client_env->regs[15]);
	int tmp[1];
	cpu_memory_rw_debug(ENV_GET_CPU(client_env), 0x10324, tmp, 4, 1);
	//fprintf(stderr, "[dump_code]\t0x10324 is at host %x. = %x = %x\n", g2h(0x10324), *((uint32_t *) g2h(0x10324)), tmp[0]);
	target_disas(stderr, ENV_GET_CPU(client_env), client_env->regs[15], 10);
	// why segmentation fault???????????????
	//mprotect(g2h(binary_start_address), (unsigned int)binary_end_address - binary_start_address, PROT_READ);
	memcpy((void *)p, (void *)(g2h(binary_start_address )), (unsigned int)binary_end_address - binary_start_address);
	//fprintf(stderr, "here: %d %d %d\n", );
	p += (uint32_t)binary_end_address - binary_start_address;
	//fprintf(stderr, "first code: %x", *((uint32_t *) g2h(client_env->regs[15])));
}

static void dump_cpu(void)
{
	*((CPUARMState *) p) = *client_env;
	p += sizeof(CPUARMState);
	fprintf(stderr,"[dump_cpu]\tenv: %p\n", client_env);
	CPUState *cpu = ENV_GET_CPU((CPUArchState *)client_env);
	fprintf(stderr,"[dump_cpu]\tcpu: %p\n", cpu);
	TaskState *ts;
	fprintf(stderr,"[dump_cpu]\topaque: %p\n", cpu->opaque);
	ts = cpu->opaque;
	fprintf(stderr,"[dump_cpu]\tNOW child_tidptr: %p\n", ts->child_tidptr);
	*((TaskState*)p) = *ts;
	p += sizeof(TaskState);
}

/* Offload the following guest thread to slave node. */
static void offload_send_extra_start(int idx)
{

}
/* Dump the informations and send to slave QEMU. */
static void offload_send_start(int first)
{
	fprintf(stderr, "[client]\tsending offload start request\n");
	int res;
	p = BUFFER_PAYLOAD_P;
	fprintf(stderr, "[client]\tdumping cpu\n");
	dump_cpu();
	fprintf(stderr, "[offload_send_start]\tregisters:\n");
	for (int i = 0; i < 16; i++)
	{
		fprintf(stderr, "%p\n", client_env->regs[i]);
	}
	fprintf(stderr, "first = %d\n", first);
	if (first) {
		dump_self_maps();
		dump_brk();
		dump_code();
	}
	fprintf(stderr, "[client]\tPC: %d\n", client_env->regs[15]);
	struct tcp_msg_header *tcp_header = (struct tcp_msg_header *) net_buffer;
	fill_tcp_header(tcp_header, p - net_buffer - sizeof(struct tcp_msg_header), TAG_OFFLOAD_START);
	fprintf(stderr, "sending buffer len without header: %lx\n", p - net_buffer - sizeof(struct tcp_msg_header));
	fprintf(stderr, "sending buffer len: %ld\n", p - net_buffer);
	if (offload_client_idx != 1 && 0) {
		res = autoSend(1, net_buffer, (p - net_buffer), 0);
		//pthread_exit(0);
		return;
	}
	res = autoSend(offload_client_idx, net_buffer, (p - net_buffer), 0);
	fprintf(stderr, "[send]\tsent %d bytes\n", res);
}

static int autoSend(int idx,char* buf, int length, int flag)
{
	int Fd = skt[idx];
	char* ptr = buf;
	int nleft = length, res;
	pthread_mutex_lock(&send_mutex[idx]);
	while (nleft > 0)
	{
		fprintf(stderr, "[autoSend]\tsendding left: %d\n", nleft);

		if ((res = send(Fd, ptr, nleft, flag)) < 0)
		{
			if (res == -1)
			{
				sleep(0.001);
				fprintf(stderr, "[autoSend]\tsend EAGAIN\n");
				perror("autoSend");
				exit(233);
				continue;
			}
			else
			{
				fprintf(stderr, "[autoSend]\tsend failed, errno: %d\n", res);
				perror("autoSend");
				exit(0);
			}
		}
		nleft -= res;
		ptr += res;
	}
	pthread_mutex_unlock(&send_mutex[idx]);
	communication_send_sum += length;
	fprintf(stderr, "[autoSend]\tnow communication_send_sum is %d\n", communication_send_sum);
	return length;
}


//pthread_mutex_t page_request_map1_mutex, page_result_map2_mutex;
pthread_mutex_t page_request_map_mutex;

/* upgrade page permission */
static void offload_send_page_upgrade(int idx, target_ulong page_addr, int perm)
{
	//pthread_mutex_lock(&socket_mutex);
	p = BUFFER_PAYLOAD_P;
	*((target_ulong *) p) = page_addr;
	p += sizeof(target_ulong);
	*((int*) p) = perm;
	p += sizeof(int);
	struct tcp_msg_header *tcp_header = (struct tcp_msg_header *)net_buffer;
	fill_tcp_header(tcp_header, p - net_buffer - sizeof(struct tcp_msg_header), TAG_OFFLOAD_PAGE_UPGRADE);
	fprintf(stderr, "[offload_send_page_upgrade]\tsending upgrade to perm: %d in page %p to #%d\n", perm, page_addr, idx);
	int res;
	if (res = autoSend(idx, net_buffer, p - net_buffer, 0) < 0)
	{
		fprintf(stderr, "page upgrade sending failed\n");
	}
	//pthread_mutex_unlock(&socket_mutex);
}


void print_holder(uint32_t page_addr)
{
	PageMapDesc *pmd = get_pmd(page_addr);
	fprintf(stderr,"[print_holder]\taddr: %p\n",page_addr);
	for (int i = 0; i < pmd->owner_set.size; i++)
	{
		int idx = pmd->owner_set.element[i];

		fprintf(stderr, "\tnode: %d", idx);
	//	if (idx != 0&&page_addr == 0xffe00000) exit(-1);
	}
	fprintf(stderr,"\n");
}

static int fetch_page_func(int requestor_idx, target_ulong addr, int perm)
{
	fprintf(stderr, "[fetch_page_func]\t addr:%p, idx:%d, perm:%d\n", addr, requestor_idx, perm);
	target_ulong page_addr = PAGE_OF(addr);
	PageMapDesc *pmd = get_pmd(addr);
	/* pmd->owner_set_mutex must be locked before. */
	pmd->mutex_holder = requestor_idx;
	//offload_log(stderr, "[fetch_page_func]\tpending lock succeed, holder: %d, perm: %d, mutex:%p\n", pmd->mutex_holder, perm, &pmd->owner_set_mutex);
	pmd->requestor = requestor_idx;
	print_holder(page_addr);
	if (perm == 2)
	{
			pmd->invalid_count = 0;
			/* only one */
			if ((pmd->owner_set.size == 1) && (pmd->owner_set.element[0] == requestor_idx))
			{
				fprintf(stderr, "[offload_client_fetch_page]\tthe only one who has it. size == %d, holder == #%d\n", pmd->owner_set.size, pmd->owner_set.element[0]);
				offload_send_page_upgrade(requestor_idx, page_addr, 2);
				print_holder(page_addr);
			}
			else {				
				/* invalid_count = the number of sharing copies to invalidate */
				pmd->invalid_count = pmd->owner_set.size;
				for (int i = 0; i < pmd->owner_set.size; i++)
				{
					offload_send_page_request(pmd->owner_set.element[i], page_addr, 2, requestor_idx);
				}
			}
	}
	else if (perm == 1)
	{
		if (pmd->owner_set.size == 0)
		{
			offload_log(stderr, "[fetch_page_func]\terror: no one has the page\n");
			exit(-1);
		}
		/* check if it already has the page */
		if ((find(&(pmd->owner_set), requestor_idx) >= 0)) {
			/* do nothing */
			offload_log(stderr, "[fetch_page_func]\terror: It alreay has. returning...\n");

			return -3;
		}
		else 
		/* check if node 0 has the page */
		if ((find(&(pmd->owner_set), 0) >= 0)) {
			offload_master_send_page(page_addr, perm, requestor_idx);
		} else {
		/* revoke page as shared page */
		offload_send_page_request(pmd->owner_set.element[0], page_addr, 1, requestor_idx);
		}

	}
	else {

		offload_log(stderr, "[fetch_page_func]\terror: EINVAL\n");
		exit(222);
	}
	fprintf(stderr, "[fetch_page_func]\t sent\n");
	return 0;
}

/* This is a backup of former version. */
// void *offload_client_fetch_page_thread(void *param)
// {
// 	offload_mode = 5;

// 	struct info *info = (struct info *)param;
// 	int requestor_idx = info->requestor_idx;
// 	target_ulong addr = info->addr;
// 	int perm = info->perm;
// 	offload_client_idx = requestor_idx;
// 	free(info);
// 	fprintf(stderr, "[offload_fetch_page_thread]\tpending request working, addr:%p, idx:%d, perm:%d\n", addr, requestor_idx, perm);
// 	target_ulong page_addr = PAGE_OF(addr);

// 	PageMapDesc *pmd = get_pmd(addr);
// 	pthread_mutex_lock(&pmd->owner_set_mutex);
// 	/* trylock succeed, fetching page */
// 	pmd->mutex_holder = requestor_idx;
// 	offload_log(stderr, "[offload_client_fetch_page_thread]\tpending lock succeed, holder: %d, perm: %d, mutex:%p\n", pmd->mutex_holder, perm, &pmd->owner_set_mutex);

// 	pmd->requestor = requestor_idx;
// 	print_holder(page_addr);
// 	if (perm == 2)
// 	{
// 		pmd->invalid_count = 0;
// 		/* only one */
// 		if ((pmd->owner_set.size == 1) && (pmd->owner_set.element[0] == requestor_idx))
// 		{
// 			fprintf(stderr, "[offload_client_fetch_page]\tthe only one who has it. size == %d, holder == #%d\n", pmd->owner_set.size, pmd->owner_set.element[0]);
// 			offload_send_page_upgrade(requestor_idx, page_addr, 2);
// 			print_holder(page_addr);
// 			//fprintf(stderr, "[offload_client_fetch_page_thread]\tunlocking...%p\n", &pmd->owner_set_mutex);
// 			//pthread_mutex_unlock(&pmd->owner_set_mutex);
// 		}
// 		else
// 		{
// 			/* invalid_count = the number of sharing copies to invalidate */
// 			pmd->invalid_count = pmd->owner_set.size;
// 			for (int i = 0; i < pmd->owner_set.size; i++)
// 			{
// 				offload_send_page_request(pmd->owner_set.element[i], page_addr, 2, requestor_idx);
// 			}
// 		}
// 	}
// 	else if (perm == 1)
// 	{
// 		if (pmd->owner_set.size == 0)
// 		{
// 			offload_log(stderr, "[offload_client_fetch_page_thread]\terror: no one has the page\n");
// 			exit(-1);
// 		}
// 		/* revoke page as shared page */
// 		offload_send_page_request(pmd->owner_set.element[0], page_addr, 1, requestor_idx);
// 	}
// 	fprintf(stderr, "[offload_client_fetch_page_thread]\t sent\n");
// 	return 0;
// }

inline PageMapDesc* get_pmd(uint32_t page_addr)
{
	page_addr = PAGE_OF(page_addr);
	page_addr = page_addr >> MAP_PAGE_BITS;
	int index1 = (page_addr >> L1_MAP_TABLE_SHIFT) & (L1_MAP_TABLE_SIZE - 1);
	int index2 = page_addr & (L2_MAP_TABLE_SIZE - 1);
	PageMapDesc *pmd = &page_map_table[index1][index2];
	return pmd;
}

static inline void show_pmd_list(req_node *p)
{
	while (p) {
		fprintf(stderr, "[show_pmd_list]\tidx %d perm %d\n", p->idx, p->perm);
		p = p->next;
	}
}
static void wake_pmd_list(uint32_t page_addr)
{
	fprintf(stderr, "[process_pmd]\twake pmd list! %p\n", page_addr);
	PageMapDesc *pmd = get_pmd(page_addr);
	/* Make sure its a fs page and is processes already. */

	fprintf(stderr, "[process_pmd]\tbits %p, c1 %d, c2 %d\n", pmd->flag, 
				(pmd->flag & DQEMU_PAGE_FS),!(pmd->flag & DQEMU_PAGE_PROCESS_FS));
	int is_fs_page = (pmd->flag & DQEMU_PAGE_FS) && !(pmd->flag & DQEMU_PAGE_PROCESS_FS);
	assert(is_fs_page == 1);
	req_node *p = pmd->list_head.next, *tmp;
	show_pmd_list(p);
	while (p) {
		offload_send_page_wakeup(p->idx, page_addr);
		tmp = p;
		p = p->next;
		free(tmp);
	}
	pmd->list_head.next = NULL;
}
static int process_pmd(uint32_t page_addr)
{
	PageMapDesc *pmd = get_pmd(page_addr);
	// TODO: This is just a naive fetch. Let readers go if there are multiple readers. */
	int ret = pthread_mutex_trylock(&pmd->owner_set_mutex);
	if (ret != 0) {
		fprintf(stderr, "[process_pmd]\tGet lock failed, ret = %d. Holder: #%d, returning...\n", ret, pmd->mutex_holder);
		return -1;
	}
	
	/* Deal with the pending request in queue. */
	req_node *p = pmd->list_head.next;
	while (1) {
		if (p) {
			show_pmd_list(p);
			//if (find(&(pmd->owner_set), p->idx))
			ret = fetch_page_func(p->idx, page_addr, p->perm);
			fprintf(stderr, "fetch page ret == %d\n", ret);
			if (ret == 0) {
				break;
			}
			else if (ret == -3) {
				pmd->list_head.next = p->next;
				free(p);
				p = pmd->list_head.next;
			}
			else {
				exit(111);
			}
		}
		else {
			pthread_mutex_unlock(&pmd->owner_set_mutex);
			break;
		}
	}
	return 0;
	
}
/* Add the request to list and process it if we can */
static int offload_client_fetch_page(int requestor_idx, uint32_t addr, int perm)
{

	offload_log(stderr, "[offload_client_fetch_page]\tadding to list page address %p, perm %d\n", addr, perm);
	/* get the PageMapDesc pointer */
	PageMapDesc *pmd = get_pmd(addr);
	req_node *pnode = pmd->list_head.next;
	while (pnode) {
		if ((pnode->idx == requestor_idx)
			&& (pnode->perm == perm)) {
				return -1;
			}
		pnode = pnode->next;
	}
	req_node *p = (req_node *)malloc(sizeof(req_node));
	p->idx = requestor_idx;
	p->perm = perm;
	p->next = NULL;
	pnode = &(pmd->list_head);
	while (pnode->next != NULL) {
		pnode = pnode->next;
	}
	pnode->next = p;
	process_pmd(addr);
	// struct info* param = (struct info*)malloc(sizeof(struct info));
	// param->requestor_idx = requestor_idx;
	// param->addr = addr;
	// param->perm = perm;
	// pthread_t pender;
	// pthread_create(&pender, NULL, offload_client_fetch_page_thread, param);
	// offload_log(stderr, "[offload_client_fetch_page]\tthread created.id:%d, addr:%p, perm:%d sent\n", requestor_idx, addr, perm);
	return 0;
}

// show MutexList
static void offload_show_mutex_list(void)
{
	char buf[1024];
	int i = 0;
	for (;i<FUTEX_RECORD_MAX;i++)
	{
		sprintf(buf, "%smutex %d: %p holder: #%d %s\n",buf, i, MutexList[i].mutexAddr, MutexList[i].holderId, MutexList[i].hasPending?"pending":"free");
		int j = 0;
		if (MutexList[i].hasPending)
		{
			sprintf(buf, "%shead: %d, tail: %d", buf, MutexList[i].head, MutexList[i].tail);
			for (; j < FUTEX_RECORD_MAX; j++)
			{
				sprintf(buf, "%s\t%d", buf, MutexList[i].pendingList[j]);
			}
			if (j == MutexList[i].head)
			{
				sprintf(buf, "%s%s", buf, "(head)");
			}
			else if (j == MutexList[i].tail)
			{
				sprintf(buf, "%s%s", buf, "(tail)");
			}
			sprintf(buf, "%s\n", buf);
		}
	}
	fprintf(stderr, "[offload_show_mutex_list]: showing MutexList...\n%s", buf);
}


static void show_cas_list()
{
	return;
	cas_record *tmp = cas_list.next;
	cas_node *p;
	char buff[1024];
	memset(buff, 0, sizeof(buff));
	fprintf(stderr, "[show_cas_list]\tShowing cas list...\n");
	sprintf(buff, "\n");
	while (tmp)
	{
		//fprintf(stderr, "[show_cas_list]\tDEBUG 1\n");
		sprintf(buff, "%s\t\t\tcas_addr %p, cas_user %d, cas_val %x | list:",
						buff, tmp->cas_addr, tmp->user, tmp->cas_value);
		/* show the pending list */
		p = tmp->req_list;
		while (p)
		{
			//fprintf(stderr, "[show_cas_list]\tDEBUG 2\n");
			sprintf(buff, "%s, id %d, cmpv %x, newv %x, strv %x",
							buff, p->idx, p->cmpv, p->newv, p->strv);
			p = p->next;
		}
		sprintf(buff, "%s\n", buff);
		tmp = tmp->next;
	}
	fprintf(stderr, "[show_cas_list]\t%s\n", buff);
}
/* Search cas list and return the address of the cas_record.
	NULL on not found.
*/
static cas_record* cas_list_lookup(uint32_t cas_addr)
{
	fprintf(stderr, "[cas_list_lookup]\tlooking up for cas_addr %p\n", cas_addr);
	cas_record *tmp = cas_list.next;
	while (tmp)
	{
		if (tmp->cas_addr == cas_addr)
			break;
		tmp = tmp->next;
	}
	return tmp;
}


/* add a record to cas list and return its address */
static cas_record* cas_list_add_record(uint32_t cas_addr, uint32_t cas_val)
{
	fprintf(stderr, "[cas_list_add_record]\tadding record cas_addr %p, cas_val %x\n", cas_addr, cas_val);
	cas_record *tmp = &cas_list;
	while (tmp->next)
	{
		tmp = tmp->next;
	}
	tmp->next = (cas_record *)malloc(sizeof(cas_record));
	tmp->next->cas_addr = cas_addr;
	tmp->next->cas_value = cas_val;
	tmp->next->next = NULL;
	tmp->next->user = -1;
	tmp->next->req_list = NULL;
	return tmp->next;
}
/* add a pending request
 * return 1 if it is a valid request and no one's using the cas -- it is good to go
 * else return 0
 */ 
static int cas_list_add_request(cas_record *record, int idx, uint32_t cmpv, uint32_t newv, uint32_t strv)
{
	fprintf(stderr, "[cas_list_add_request]\tnew request cas_addr %p, idx %d, cmpv %x, newv %x, strv %x\n"
															,record->cas_addr, idx, cmpv, newv, strv);
	int is_first = (record->req_list == NULL) ? 1 : 0;
	cas_node *p = (cas_node *)malloc(sizeof(cas_node));
	p->idx = idx;
	p->cmpv = cmpv;
	p->newv = newv;
	p->strv = strv;
	p->next = NULL;
	fprintf(stderr, "[cas_list_add_request]\tadding to pending list...\n");
	if (is_first) {
		fprintf(stderr, "[cas_list_add_request]\tthe first one!\n");
		record->req_list = p;
	}
	else {
		cas_node *tmp = record->req_list;
		while (tmp->next) {
			tmp = tmp->next;
		}
		tmp->next = p;
	}
	/* strv, the current value in slave, SHOULD equal to our value in center,
	 * if not, what happened?
	 */ 
	if (strv != record->cas_value) {
		fprintf(stderr, "[cas_list_add_request]\tThink I just saved you.\n");
		/* We should invalidate its page now since it is inconsistent due to 
		 * the race. However, if the former one has done cmpxchg, the page should
		 * have been invalidated. Currently, we do nothing and double check if it
		 * succeeds later.
		 */
	}
	int good_to_go = 0;
	/* Is it a valid request in proper time? */
	if ((record->user == -1) && (cmpv == record->cas_value)) {
		fprintf(stderr, "[cas_list_add_request]\tyou are good to go!\n");
		good_to_go = 1;
	}
	else {
		good_to_go = 0;
	}
	return good_to_go;
}
/* Add a new request and see if it is good to go */
static void offload_process_mutex_request(void)
{

	p = net_buffer;
	target_ulong cas_addr = *(target_ulong *) p;
	p += sizeof(target_ulong);
	uint32_t requestorId = *(uint32_t *) p;
	p += sizeof(uint32_t);
	uint32_t cmpv = *(uint32_t*)p;
	p += sizeof(uint32_t);
	uint32_t newv = *(uint32_t*)p;
	p += sizeof(uint32_t);
	uint32_t strv = *(uint32_t*)p;
	fprintf(stderr, "[offload_process_mutex_request client#%d]\trequested mutex address: %p from %d, cmpv %x, newv %x, strv %x\n", 
					offload_client_idx, cas_addr, requestorId, cmpv, newv, strv);
	pthread_mutex_lock(&g_cas_mutex);
	show_cas_list();
	cas_record *record = cas_list_lookup(cas_addr);
	if (!record)
	{
		/* the first one should success. */
		assert(cmpv == strv);
		record = cas_list_add_record(cas_addr, strv);
	}
	int good_to_go = cas_list_add_request(record, requestorId, cmpv, newv, strv);
	show_cas_list();
	if (good_to_go == 1) {
		record->user = requestorId;
		offload_send_mutex_verified(requestorId);
	}
	show_cas_list();
	pthread_mutex_unlock(&g_cas_mutex);
}


static inline void dqemu_set_page_bit(uint32_t page_addr, uint32_t page_bit)
{
	PageMapDesc *pmd = get_pmd(page_addr);
	pmd->flag = page_bit;
	fprintf(stderr, "[dqemu_set_page_bit]\tnow %p page bit = %p\n", page_addr, page_bit);
}

static void offload_broadcast_fs_page(uint32_t page_addr, uint32_t shadow_page_addr)
{
	char *pp = buf + sizeof(struct tcp_msg_header);
	*((target_ulong *) pp) = page_addr;
	pp += sizeof(target_ulong);
	*((uint32_t*)pp) = shadow_page_addr;
	pp += sizeof(uint32_t);
	struct tcp_msg_header *tcp_header = (struct tcp_msg_header *)buf;
	fill_tcp_header(tcp_header, pp - buf - sizeof(struct tcp_msg_header), TAG_OFFLOAD_FS_PAGE);
	/* Broadcast message. */
	for (int i = 0; i <= ONLINE_SERVER; i++) {
		autoSend(i, buf, pp - buf, 0);
		fprintf(stderr, "[offload_broadcast_fs_page]\tsent fs page %p"
				"shadow page %p to #%d\n", page_addr, shadow_page_addr, i);
	}
}
/* Process and broadcast false sharing page. */
/* Clean up the left */
uint32_t offload_client_process_false_sharing_page(uint32_t page_addr)
{
	fprintf(stderr, "[offload_client_process_false_sharing_page]\t"
					"page addr = %p\n",
					page_addr);
	PageMapDesc *pmd = get_pmd(page_addr);
	/* Create shadow page mapping. */
	uint32_t shadow_page_addr = shadow_page_base;
	shadow_page_base += MAX_PAGE_SPLIT * PAGE_SIZE;
	assert(shadow_page_base < 0xd0000000);
	uint32_t ret = target_mmap(shadow_page_addr, 
						MAX_PAGE_SPLIT*PAGE_SIZE, PROT_READ|PROT_WRITE,
						MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
	assert(ret == shadow_page_addr);
	//shadow_page_addr = mmap(g2h(shadow_page_addr), 
	//					64*PAGE_SIZE, PROT_READ|PROT_WRITE,
	//					MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
	fprintf(stderr, "[offload_client_process_false_sharing_page]\t"
					"Created shadow pages for %p, shadow page base = %p, setting to zeros\n", 
					page_addr, shadow_page_addr);
	memset(g2h(shadow_page_addr), 0, MAX_PAGE_SPLIT*PAGE_SIZE);
	uint32_t step = MIN_PAGE_GRAIN;
	uint32_t start = shadow_page_addr, o_start = page_addr;
	for (int i = 0; i < MAX_PAGE_SPLIT; i++) {
		fprintf(stderr, "[offload_client_process_false_sharing_page]\t"
						"%d: copying to %p - %p from %p - %p, step %p\n", i,
						start, start + step,
						o_start, o_start + step, step);

		memcpy(g2h(start), g2h(o_start), step);
		dqemu_set_page_bit(start & 0xfffff000, DQEMU_PAGE_NONE| DQEMU_PAGE_SHADOW);
		start += (step + PAGE_SIZE);
		o_start += step;
		// TODO check SHADOW and FS bit when receive request
		// TODO don't split shadow page
	}
	fprintf(stderr, "[offload_client_process_false_sharing_page]\tCopy done.\n");

	pmd->shadow_page_addr = shadow_page_addr;
	dqemu_set_page_bit(page_addr, DQEMU_PAGE_NONE| DQEMU_PAGE_FS);
	fprintf(stderr, "[offload_client_process_false_sharing_page]\tNow page %p bit %p.\n",
					page_addr, pmd->flag);

	offload_broadcast_fs_page(page_addr, shadow_page_addr);

	// TODO wake up pmd list to let them rethink.
	/* Mark as master got the page. */
	clear(&pmd->owner_set);
	insert(&pmd->owner_set, 0);
	fprintf(stderr, "[offload_client_process_false_sharing_page]\tclean set and unlock.\n");
	pthread_mutex_unlock(&pmd->owner_set_mutex);
	wake_pmd_list(page_addr);
}

/* fetch page */
static void offload_process_page_request(void)
{
	//pthread_mutex_lock(&socket_mutex);
	p = net_buffer;
	target_ulong page_addr = *(target_ulong *) p;
	p += sizeof(target_ulong);
	int perm = *(uint32_t *) p;
	p += sizeof(uint32_t);

	PageMapDesc *pmd = get_pmd(page_addr);
	/*uint32_t got_flag = *(uint32_t *)p;
	p += sizeof(uint32_t);*/
	fprintf(stderr, "[offload_process_page_request client#%d]\trequested address: %x, perm: %d\n", offload_client_idx, page_addr, perm);
	fprintf(log, "%d\t%p\t%d\n", offload_client_idx, page_addr, perm);
	/* Check if already in prefetch list */
	int isInPrefetch = prefetch_check(page_addr, offload_client_idx);
	isInPrefetch = 0;
	/* Hit already splited false sharing page. */
	fprintf(stderr, "[offload_process_page_request client#%d]\tpage flag %p\n", pmd->flag);
	//if (pmd->flag & DQEMU_PAGE_FS) {
	//	offload_send_page_wakeup(offload_client_idx, page_addr);
	//}
	if (perm == 2) {
			offload_client_fetch_page(offload_client_idx, page_addr, 2);
			
			//uint32_t start	= page_addr & 0xffff0000;
			//for (int i = 0; i < 0x10; i++) {
			//	offload_client_fetch_page(offload_client_idx, start + i * PAGE_SIZE, 2);
			//}
		if (isInPrefetch < 0)
		{
			fprintf(stderr, "[offload_process_page_request client#%d]\tIn list, prefetch stops\n", offload_client_idx);
			return;
		}
		else {
			int prefetch_count = prefetch_handler(page_addr, offload_client_idx);
			if (prefetch_count < 0) {
			/* False sharing page. */
			//	fprintf(stderr, "[offload_process_page_request client#%d]\t"
			//			"Prefetch count = %d, false sharing page!\n", offload_client_idx, 
			//			prefetch_count);
			//	/* Mark the page in false sharing process. */
			//	if (pmd->flag & DQEMU_PAGE_SHADOW) {
			//		fprintf(stderr, "[offload_process_page_request client#%d]\t"
			//				"already is shadow page! wo to le! %p\n", offload_client_idx, 
			//				page_addr);
			//		//exit(2);
			//	}
			//	if (!(pmd->flag & DQEMU_PAGE_FS) && !(pmd->flag & DQEMU_PAGE_PROCESS_FS) 
			//		&& !(pmd->flag & DQEMU_PAGE_SHADOW))
			//		dqemu_set_page_bit(page_addr, DQEMU_PAGE_PROCESS_FS);
			//	//exit(3);
			}
			else if (prefetch_count > 0) {
				fprintf(stderr, "[offload_process_page_request client#%d]\tPrefetching for next %d pages\n", offload_client_idx, prefetch_count);
				for (int i = 0; i < prefetch_count; i++) {
					offload_client_fetch_page(offload_client_idx, page_addr + (i+1)*PAGE_SIZE, 2);
				}
			}
		}
	}
	else {
		if (page_addr > 0xff000000) {
			uint32_t start	= page_addr & 0xffff0000;
			for (int i = 0; i < 0x10; i++) {
				offload_client_fetch_page(offload_client_idx, start + i * PAGE_SIZE, 1);
			}
		}
		else {
			for (int i = -50; i < 50; i++) {
				offload_client_fetch_page(offload_client_idx, page_addr + i * PAGE_SIZE, 1);
			}

		}
	}
	
}

static int try_recv(int size)
{
	int res;
	int nleft = size;
	char* ptr = net_buffer;
	while (nleft > 0)
	{
		res = recv(skt[offload_client_idx], ptr, nleft, 0);
		fprintf(stderr, "[try_recv]\treceived %d\n", res);
		if (res == -1)//Resource temporarily unavailable
		{
			//fprintf(stderr, "[try_recv]\twait a sec\n");
			//sleep(0.01);
			continue;
		}
		else if (res < 0)
		{
			fprintf(stderr, "[try_recv]\terrno: %d\n", res);
			perror("try_recv");
			exit(-1);
		}
		else if (res == 0)
		{
			fprintf(stderr, "[try_recv]\tconnection closed.\n");
			exit(0);
		}
		else
		{

			nleft -= res;
			ptr += res;

			fprintf(stderr, "[try_recv]\treceived %d B, %d left.\n", res, nleft);
		}

	}
	if (size > 0)
	{
		communication_recv_sum += size;
		fprintf(stderr, "[try_recv]\tnow communication_recv_sum = %d\n", communication_recv_sum);
	}

	return size;
}

void* offload_client_daemonize(void)
{
	offload_mode = 2;
	int res;
	last_flag_recv = 1;
	last_flag_pending = 1;
	fprintf(stderr, ">>>>>>>>>>> client# %d guest_base: %x\n", offload_client_idx, guest_base);
	while (1)
	{
		if (last_flag_recv == 1)
		{
			fprintf(stderr, "[offload_client_daemonize]\twaiting for new message\n");
		}

		res = try_recv(sizeof(struct tcp_msg_header));
		if (res == -2)
		{
			fprintf(stderr, "[offload_client_daemonize]\tconnection closed, terminiting...\n");
			return -2;
		}

		if (res == sizeof(struct tcp_msg_header))
		{
			fprintf(stderr, "[offload_client_daemonize]\tgot new message #%d\n", get_number());

			fprintf(stderr, "[offload_client_daemonize]\tthread_cpu: %p\n", thread_cpu);
			last_flag_recv = 1;
			struct tcp_msg_header *tcp_header = (struct tcp_msg_header *)net_buffer;
			if (tcp_header->magic_nr!=COMM_MAGIC_NR)
			{
				fprintf(stderr, "[offload_client_daemonize]\ttcp_header->magic_nr == %p??\n", tcp_header->magic_nr);
				exit(3);
			}
			switch (tcp_header->tag)
			{
				case TAG_OFFLOAD_PAGE_REQUEST:
					fprintf(stderr, "[offload_client_daemonize]\tpage request, size: %d\n",tcp_header->size);

					try_recv(tcp_header->size);
					offload_process_page_request();
					break;

				case TAG_OFFLOAD_PAGE_CONTENT:
					fprintf(stderr, "[offload_client_daemonize]\tpage content, size: %d\n", tcp_header->size);
					try_recv(tcp_header->size);
					offload_process_page_content();
					break;

				case TAG_OFFLOAD_PAGE_ACK:
					fprintf(stderr, "[offload_client_daemonize]\ttag: page ack\n");
					try_recv(tcp_header->size);
					offload_process_page_ack();
					break;

				case TAG_OFFLOAD_CMPXCHG_REQUEST:
					fprintf(stderr, "[offload_client_daemonize]\ttag: cmpxchg request\n");
					try_recv(tcp_header->size);
					offload_process_mutex_request();
					break;

				case TAG_OFFLOAD_CMPXCHG_VERYFIED:
					fprintf(stderr, "[offload_client_daemonize]\ttag: cmpxchg verified\n");
					try_recv(tcp_header->size);
					exit(3);
					break;

				case TAG_OFFLOAD_CMPXCHG_DONE:
					fprintf(stderr, "[offload_client_daemonize]\ttag: cmpxchg done\n");
					try_recv(tcp_header->size);
					offload_process_mutex_done();
					break;

				case TAG_OFFLOAD_SYSCALL_REQ:
					fprintf(stderr, "[offload_client_daemonize]\ttag: syscall request with size = %d\n", tcp_header->size);
					try_recv(tcp_header->size);
					fprintf(stderr, "[offload_client_daemonize]\treceived.\n");
					offload_process_syscall_request();
					break;

				default:
					fprintf(stderr, "[offload_client_daemonize]\tunknown tag:%d\n", tcp_header->tag);
					exit(0);
					break;

			}
		}//daemonize
		else
		{
			last_flag_recv = 0;
		}
	}
}
extern pthread_mutex_t offload_center_init_mutex; extern pthread_cond_t offload_center_init_cond;


void* offload_center_client_start(void *arg)
{
	offload_mode = 2;
	/*TaskState *ts;
	CPUArchState *new_env = (CPUArchState *) arg;
	CPUState *new_cpu = ENV_GET_CPU(new_env);
	rcu_register_thread();
	tcg_register_thread();
	thread_cpu = new_cpu;
	ts = (TaskState *) new_cpu->opaque;*/
	//info->tid = gettid();
	//task_settid(ts);


	//sigprocmask(SIG_SETMASK, &info->sigmask, NULL);
	//CPUArchState *env = (CPUArchState *) arg;
	log = fopen("pageReqLog.txt", "w");
	offload_connect_online_server(0);
	offload_client_init();
	pthread_mutex_lock(&offload_center_init_mutex);
	pthread_cond_signal(&offload_center_init_cond);
	pthread_mutex_unlock(&offload_center_init_mutex);
	futex_table = (struct futex_record*)malloc(FUTEX_RECORD_MAX*sizeof(struct futex_record));
	memset(futex_table, 0, FUTEX_RECORD_MAX * sizeof(struct futex_record));
	offload_client_daemonize();
	close_network();
	return NULL;
}

static void futex_table_add(uint32_t futex_addr, int idx, int thread_id)
{
	fprintf(stderr, "[futex_table_add]\tadding futex_addr = %p, idx = %d\n", futex_addr, idx);

	print_futex_table();
	struct Node * p = (struct Node*)malloc(sizeof(struct Node));
	memset(p, 0, sizeof(struct Node));
	p->val = idx;
	p->thread_id = thread_id;
	int i = 0;
	//int j = 0;
	fprintf(stderr, "[futex_table_add]\ttest point1\n");
	/* Find a matching record. */
	for (; i < FUTEX_RECORD_MAX; i++)
	{
		if ((futex_table[i].isInUse==1)&&(futex_table[i].futex_addr==futex_addr))
			break;
	}
	/* If no matching record, find a new position. */
	if (i == FUTEX_RECORD_MAX) {
		/* find a spare position */
		i = 0;
		while (futex_table[i].isInUse)
		{
			i++;
			if (i == FUTEX_RECORD_MAX)
			{
				fprintf(stderr, "[futex_table_add]\tFatal error: futex_table full! Please add more space.\n");
				exit(232);
			}
		}
	}	
	// make sure list is not full

	// insert
	if (futex_table[i].isInUse != 1)
	{
		futex_table[i].isInUse = 1;
		futex_table[i].futex_addr = futex_addr;
		futex_table[i].head = p;
	}
	else
	{
		p->next = futex_table[i].head;
		futex_table[i].head = p;
	}

	// wakeup all??
	print_futex_table();
}

static void print_futex_table()
{
	fprintf(stderr, "[print_futex_table]\tshowing futex table...\n");
	int i = 0;
	char buf[4096];
	char tmp[200];
	struct futex_record * p;
	struct Node * pnode;
	memset(buf, 0, sizeof(buf));
	for (; i < FUTEX_RECORD_MAX; i++)
	{
		p = &futex_table[i];
		//fprintf(stderr, "[print_futex_table]\ttest point1\n");
		sprintf(tmp, "\n[%d]futex_addr: %p, isInUse: %s", i, p->futex_addr, (p->isInUse) ? "Yes" : "No");
		strcat(buf, tmp);
		//fprintf(stderr, "[print_futex_table]\ttest point2\n");
		if (p->isInUse)
		{
			pnode = p->head;
			//fprintf(stderr, "[print_futex_table]\ttest point3.1, val = %d, next\n", pnode->val);
			while (pnode)
			{
				sprintf(tmp, "  %d->%d", pnode->val, pnode->thread_id);
				strcat(buf, tmp);
				pnode = pnode->next;
			}
			//fprintf(stderr, "[print_futex_table]\ttest point4\n");
		}
		strcat(buf, "\n");
	}
	fprintf(stderr, "[print_futex_table]\tshowing futex table%s", buf);

}

/*	Return pointer to the futex_record containing futex_addr
	in the futex_table
	NULL for not found
*/
static struct futex_record * futex_table_find(uint32_t futex_addr)
{
	int i = 0;
	struct futex_record *pr = futex_table;
	// find the record
	while (pr->futex_addr != futex_addr || pr->isInUse == 0)
	{
		i++;
		pr = &futex_table[i];
		if (i == FUTEX_RECORD_MAX)
		{
			fprintf(stderr, "[futex_table_find]\tfutex doesn't exist.\n");
			return NULL;
		}
	}

	fprintf(stderr, "[futex_table_find]\tfound futex record %d matched\n", i);
	return pr;
}

static void futex_table_wake(uint32_t futex_addr, int num, int idx, int thread_id)
{
	fprintf(stderr, "[futex_table_wake]\tWaking up futex on %p, num = %d\n", futex_addr, num);
	print_futex_table();

	struct futex_record *pr = futex_table_find(futex_addr);
	if (!pr) {
		offload_send_syscall_result(idx, 0, thread_id);
		return;
	}
	// wake up all servers
	struct Node *pnode = pr->head, *tmp;
	int count = 0;
	while (pnode)
	{
		// wasn't woken up by timer
		if (pnode->val>=0) {
			count++;
			offload_send_syscall_result(pnode->val, 0, pnode->thread_id);
		}
		tmp = pnode;
		pnode = pnode->next;
		free(tmp);
		if (count == num) break;
	}
	// Clean up
	if (pnode)	//if num < number of waiters == there is someone left, fix the list
	{
		pr->head = pnode;
	}
	else	// there is no one left, cleanup
	{
		// cleanup
		pr->isInUse = 0;
		pr->futex_addr = 0;
		pr->head = NULL;
	}
	print_futex_table();
	offload_send_syscall_result(idx, count, thread_id);
}

/*        FUTEX_CMP_REQUEUE (since Linux 2.6.7)
		This operation first checks whether the location uaddr still
		contains the value val3.  If not, the operation fails with the
		error EAGAIN.  Otherwise, the operation wakes up a maximum of
		val waiters that are waiting on the futex at uaddr.  If there
		are more than val waiters, then the remaining waiters are
		removed from the wait queue of the source futex at uaddr and
		added to the wait queue of the target futex at uaddr2.  The
		val2 argument specifies an upper limit on the number of
		waiters that are requeued to the futex at uaddr2.

		The load from uaddr is an atomic memory access (i.e., using
		atomic machine instructions of the respective architecture).
		This load, the comparison with val3, and the requeueing of any
		waiters are performed atomically and totally ordered with
		respect to other operations on the same futex word.

		Typical values to specify for val are 0 or 1.  (Specifying
		INT_MAX is not useful, because it would make the
		FUTEX_CMP_REQUEUE operation equivalent to FUTEX_WAKE.)  The
		limit value specified via val2 is typically either 1 or
		INT_MAX.  (Specifying the argument as 0 is not useful, because
		it would make the FUTEX_CMP_REQUEUE operation equivalent to
		FUTEX_WAIT.)

		RETURN VALUE
		Returns the total number of waiters that were woken up or
		requeued to the futex for the futex word at uaddr2.  If this
		value is greater than val, then the difference is the number
		of waiters requeued to the futex for the futex word at uaddr2.

*/
int futex_table_cmp_requeue(uint32_t uaddr, int futex_op, int val, uint32_t val2,
							uint32_t uaddr2, int val3, int idx, int thread_id)
{
	fprintf(stderr, "[futex_table_cmp_requeue]\tuaddr %p, futex_op %p, val %p, val2 %p, uaddr2 %p, val3 %p of idx %d->%d\n",
			uaddr, futex_op, val, val2, uaddr2, val3, idx, thread_id);
	print_futex_table();
	offload_segfault_handler_positive(uaddr, 1);
	if (*(int *)(g2h(uaddr)) != val3)
	{
		fprintf(stderr, "[futex_table_cmp_requeue]\t*(int*)(futex_addr) == %d != cmpval, returning with EAGAIN...%p\n", *(int *)(g2h(uaddr)), TARGET_EAGAIN);
		offload_send_syscall_result(idx, TARGET_EAGAIN, thread_id);
		return TARGET_EAGAIN;
	}
	struct futex_record *pr = futex_table_find(uaddr);
	/* If there is not a matching record, return 0. */
	if (!pr) {
		fprintf(stderr, "[futex_table_cmp_requeue]\tpr == %p, returning...\n", pr);
		offload_send_syscall_result(idx, 0, thread_id);
		return 0;
	}
	/* wake up all threads */
	struct Node *pnode = pr->head, *tmp;
	int count_wake = 0;
	int count_requeue = 0;
	while (pnode)
	{
		fprintf(stderr, "[futex_table_cmp_requeue]\twaking up #%d->%d\n", pnode->val, pnode->thread_id);
		/* It isn't woken up by timer, so count ++ */
		if (pnode->val >= 0)
		{
			count_wake++;
			offload_send_syscall_result(pnode->val, 0, pnode->thread_id);
		}
		tmp = pnode;
		pnode = pnode->next;
		free(tmp);
		if (count_wake == val)
			break;
	}
	// Clean up
	if (pnode) /* If val is less than the number of waiters, then there is someone left, move it to new queue */
	{
		pr->head = pnode;
		struct futex_record *dup = futex_table_find(uaddr2);
		if (!dup) {
			fprintf(stderr, "[futex_table_cmp_requeue]\treplacing futex_record of %p\n", uaddr);
			pr->futex_addr = uaddr2;
		}
		// add to addr2 queue
		else {
			fprintf(stderr, "[futex_table_cmp_requeue]\tadding to new queue at %p\n", uaddr2);
			struct Node *save, *begin, *end;
			begin = pr->head;
			pnode = begin;
			while (pnode) {
				count_requeue++;
				if (count_requeue == val2)
					break;
				pnode = pnode->next;
			}
			end = pnode;
			// move `begin to end` to dup
			if (end->next == NULL) {
				// there is nothing left at uaddr, clean up
				pr->isInUse = 0;
				pr->futex_addr = 0;
				pr->head = NULL;
			}
			else {
				/* Move the `begin to end` from uaddr1 to uaddr2 */
				pr->head = end->next;
				end->next = dup->head;
				dup->head = begin;
			}

		}
	}
	else // there is no one left, cleanup
	{
		// cleanup
		pr->isInUse = 0;
		pr->futex_addr = 0;
		pr->head = NULL;
	}
	print_futex_table();
	int res = count_wake > count_requeue ? count_wake : count_requeue;
	offload_send_syscall_result(idx, res, thread_id);
	return res;
}

/* Set a timer to wake up Futex_waiter */
void* futex_timer(const struct timespec * timeout, void* p)
{

}


void syscall_daemonize(void)
{
	offload_mode = 4;



	pthread_mutex_lock(&do_syscall_mutex);
	do_syscall_flag = 0;
	syscall_global_pointer = NULL;
	pthread_mutex_unlock(&do_syscall_mutex);
	while (1)
	{

		fprintf(stderr, "[syscall_daemonize]\twaiting for new syscall...\n");
		pthread_mutex_lock(&do_syscall_mutex);
		while (do_syscall_flag == 0|| syscall_global_pointer == NULL)
		{
			pthread_cond_wait(&do_syscall_cond,&do_syscall_mutex);
			fprintf(stderr,"[syscall_daemonize]\twaiting!\n");
		}
		struct syscall_param* syscall_p = syscall_global_pointer;
		if (syscall_p == NULL)
		{
			fprintf(stderr,"[syscall_daemonize]\tNULLptr0!\n");
			do_syscall_flag = 0;
			pthread_mutex_unlock(&do_syscall_mutex);
			continue;
		}
		pthread_mutex_unlock(&do_syscall_mutex);
		fprintf(stderr, "[syscall_daemonize]\tgot new syscall!\n");


		pthread_mutex_lock(&do_syscall_mutex);
		syscall_p = syscall_global_pointer;
		if (syscall_p == NULL)
		{
			fprintf(stderr,"[syscall_daemonize]\tNULLptr!\n");
			do_syscall_flag = 0;
			pthread_mutex_unlock(&do_syscall_mutex);
			continue;
		}
		CPUARMState* cpu_env = (CPUARMState*)syscall_p->cpu_env;
		int num = syscall_p->num;
		abi_long arg1 = syscall_p->arg1;
		abi_long arg2 = syscall_p->arg2;
		abi_long arg3 = syscall_p->arg3;
		abi_long arg4 = syscall_p->arg4;
		abi_long arg5 = syscall_p->arg5;
		abi_long arg6 = syscall_p->arg6;
		abi_long arg7 = syscall_p->arg7;
		abi_long arg8 = syscall_p->arg8;
		int idx = syscall_p->idx;
		int thread_id = syscall_p->thread_id;
		fprintf(stderr, "[syscall_daemonize]\tprocessing passed syscall from %d->%d, arg1: %p, arg2:%p, arg3:%p\n", idx, thread_id, arg1, arg2, arg3);
		extern void print_syscall(int num,
				abi_long arg1, abi_long arg2, abi_long arg3,
				abi_long arg4, abi_long arg5, abi_long arg6);
		print_syscall(num,
				arg1, arg2, arg3,
				arg4, arg5, arg6);
		fprintf(stderr, "[syscall_daemonize]\teabi:%p\n",((CPUARMState *)cpu_env)->eabi);
		// futex wait
		/*       int futex(int *uaddr, int futex_op, int val,
                 const struct timespec *timeout,   or: uint32_t val2
				 int *uaddr2, int val3);
				 arg1: uaddr, arg2: futex_op, arg3: val, 
				 arg4: timeout/val2 ,arg5: uaddr2, arg6: val3.
		*/
		/*       FUTEX_WAIT (since Linux 2.6.0)
              This operation tests that the value at the futex word pointed
              to by the address uaddr still contains the expected value val,
              and if so, then sleeps waiting for a FUTEX_WAKE operation on
              the futex word.  The load of the value of the futex word is an
              atomic memory access (i.e., using atomic machine instructions
              of the respective architecture).  This load, the comparison
              with the expected value, and starting to sleep are performed
              atomically and totally ordered with respect to other futex
              operations on the same futex word.  If the thread starts to
              sleep, it is considered a waiter on this futex word.  If the
              futex value does not match val, then the call fails
              immediately with the error EAGAIN.

				If the timeout is not NULL, the structure it points to
              specifies a timeout for the wait.  (This interval will be
              rounded up to the system clock granularity, and is guaranteed
              not to expire early.)  The timeout is by default measured
              according to the CLOCK_MONOTONIC clock, but, since Linux 4.5,
              the CLOCK_REALTIME clock can be selected by specifying
              FUTEX_CLOCK_REALTIME in futex_op.  If timeout is NULL, the
              call blocks indefinitely.

              The arguments uaddr2 and val3 are ignored.
		*/
		if ((num == TARGET_NR_futex)
			&& ((arg2 == (FUTEX_PRIVATE_FLAG|FUTEX_WAIT)) || (arg2 == FUTEX_WAIT)))
		{
			fprintf(stderr, "[syscall_daemonize]\treceived FUTEX_PRIVATE_FLAG|FUTEX_WAIT\n");
			void* futex_addr = arg1;
			int cmpval = arg3;
			fprintf(stderr, "[syscall_daemonize]\tfetching\n");
			offload_segfault_handler_positive(futex_addr, 1);
			if (*(int*)(g2h(futex_addr)) == cmpval)
			{
				fprintf(stderr, "[syscall_daemonize]\t*(int*)(futex_addr) == cmpval == %p, adding to futex table\n", *(int*)(g2h(futex_addr)));
				futex_table_add(futex_addr, idx, thread_id);
				// // DEBUG
				// sleep(1);
				// offload_send_syscall_result(idx, 0);
				// TODO implement time wait
				if (arg4 != NULL) {
					fprintf(stderr, "[syscall_daemonize]\ttime FUTEX_WAIT not implemented!\n");
					exit(122);
				}
			}
			else
			{
				fprintf(stderr, "[syscall_daemonize]\t*(int*)(futex_addr = %p)!= cmpval = %p, ignoring...\n", *(int *)(g2h(futex_addr)), cmpval);
				offload_send_syscall_result(idx, TARGET_EAGAIN, thread_id);
			}
		}
		// futex_wake
		/*        FUTEX_WAKE (since Linux 2.6.0)
              This operation wakes at most val of the waiters that are
              waiting (e.g., inside FUTEX_WAIT) on the futex word at the
              address uaddr.  Most commonly, val is specified as either 1
              (wake up a single waiter) or INT_MAX (wake up all waiters).
              No guarantee is provided about which waiters are awoken (e.g.,
              a waiter with a higher scheduling priority is not guaranteed
              to be awoken in preference to a waiter with a lower priority).

              The arguments timeout, uaddr2, and val3 are ignored.
		*/
		else if ((num == TARGET_NR_futex)
			&& ((arg2 == (FUTEX_PRIVATE_FLAG|FUTEX_WAKE)) || (arg2 == FUTEX_WAKE)))
		{
			fprintf(stderr, "[syscall_daemonize]\treceived FUTEX_PRIVATE_FLAG|FUTEX_WAKE, %p, %p, %d, arg8: %d\n", FUTEX_PRIVATE_FLAG | FUTEX_WAKE, arg2, arg2 == 0x81 ? 1 : 0, arg8);
			uint32_t futex_addr = arg1;
			int wakeup_num = arg3;
			int isChildEnd = arg8;
			if (isChildEnd == 1)
			{
				fprintf(stderr, "[syscall_daemonize]\tChild End!\n");
				offload_segfault_handler_positive(futex_addr, 2);
				*(int*)g2h(futex_addr) = 0;
			}
			futex_table_wake(futex_addr, wakeup_num, idx, thread_id);
		}
		/*        FUTEX_CMP_REQUEUE (since Linux 2.6.7)
		*/
		else if ((num == TARGET_NR_futex)
			&& ((arg2 == (FUTEX_PRIVATE_FLAG|FUTEX_CMP_REQUEUE)) || (arg2 ==FUTEX_CMP_REQUEUE)))
		{
			fprintf(stderr, "[syscall_daemonize]\treceived FUTEX_PRIVATE_FLAG|FUTEX_CMP_REQUEUE, %p, %p, %d, arg8: %d\n", FUTEX_PRIVATE_FLAG | FUTEX_WAKE, arg2, arg2 == 0x81 ? 1 : 0, arg8);
			futex_table_cmp_requeue(arg1, arg2, arg3, arg4, arg5, arg6, idx, thread_id);
		}
		else
		{
			/* Common syscalls. */
			if ((num == TARGET_NR_write)) {
				offload_segfault_handler_positive(arg2, 1);
				fprintf(stderr, "[syscall_daemonize]\tfetching write, %d %c %d\n", arg1, *(char*)g2h(arg2), arg3);
			}
			print_futex_table();
			extern abi_long do_syscall(void *cpu_env, int num, abi_long arg1,
							abi_long arg2, abi_long arg3, abi_long arg4,
							abi_long arg5, abi_long arg6, abi_long arg7,
							abi_long arg8);
			abi_long ret = do_syscall(cpu_env,
						num,
						arg1,
						arg2,
						arg3,
						arg4,
						arg5,
						arg6,
						0, 0);
			offload_send_syscall_result(idx, ret, thread_id);
		}
		free(syscall_p->cpu_env);
		free(syscall_p);

		fprintf(stderr, "[syscall_daemonize]\tcleaning up\n");
		do_syscall_flag = 0;
		if (do_syscall_flag == 1)
			fprintf(stderr, "[syscall_daemonize]\tstill 1??\n");
		syscall_global_pointer = NULL;
		if (syscall_global_pointer)
			fprintf(stderr, "[syscall_daemonize]\tstill exists??\n");
		pthread_cond_broadcast(&do_syscall_cond);
		pthread_mutex_unlock(&do_syscall_mutex);
	}
}

void* thread_end_cleanup(CPUArchState *the_env)
{
	fprintf(stderr, "[thread_end_cleanup]\tcleaning up\n");
	CPUState *cpu = ENV_GET_CPU((CPUArchState *)the_env);
	TaskState *ts;
	ts = cpu->opaque;
	fprintf(stderr,"[thread_end_cleanup]\tchild_tidptr: %p\n", ts->child_tidptr);
	put_user_u32(0, ts->child_tidptr);
	//do_syscall(g2h(ts->child_tidptr), FUTEX_WAKE, INT_MAX,
	//			NULL, NULL, 0);
}

/* Initiate client daemonize. 
 * Return value 
 * 0: this is the first thread in a server, keep it as daemonize;
 * 1: this is not the first. */
int offload_client_start(CPUArchState *the_env)
{
	assert(thread_count >= 0);
	int server_idx = gst_thrd_info[thread_count].server_idx,
	    thread_idx = gst_thrd_info[thread_count].thread_idx;
	offload_mode = 2;
	offload_client_idx = server_idx;
	client_env = the_env;
	fprintf(stderr, "[offload_client_start]\tguest thread %d : %d->%d\n",
	                thread_count, server_idx, thread_idx);
	p = BUFFER_PAYLOAD_P;
	/* The first need to build the connection to a server. */
	if (thread_idx == 0) {
		fprintf(stderr, "[offload_client_start]\tinitialize\n");
		offload_client_init();
		offload_send_start(1);
	}
	else {
		offload_send_start(0);
	}
	fprintf(stderr, "[offload_client_start]\tSent. returning..\n");
	return (thread_idx == 0) ? 0 : 1;
}

void offload_syscall_daemonize_start(CPUArchState *the_env)
{
	syscall_started_flag = 1;
	offload_mode = 4;
	pthread_mutex_lock(&offload_count_mutex);
	if (is_first_do_syscall_thread == 0)
		is_first_do_syscall_thread = 1;
	else
	{

		fprintf(stderr, "[syscall_daemonize]\tI am not the first. 1 thread is enough, returning...\n");
		pthread_mutex_unlock(&offload_count_mutex);
		return;

	}
	pthread_mutex_unlock(&offload_count_mutex);

	p = BUFFER_PAYLOAD_P;

	//pthread_mutex_init(&page_request_map_mutex[offload_client_idx], NULL);


	fprintf(stderr, "[offload_syscall_daemonize_start]\tinitialize");

	pthread_mutex_init(&do_syscall_mutex,NULL);
	pthread_cond_init(&do_syscall_cond,NULL);
	int res;
	//pthread_t syscall_daemonize_thread;
	//pthread_create(&syscall_daemonize_thread, NULL, syscall_daemonize, NULL);
	//pthread_t daemonize;
	//pthread_create(&daemonize,NULL,offload_client_daemonize,NULL);
	syscall_daemonize();
	fprintf(stderr, "[offload_syscall_daemonize_start]\tkilled myself.\n");

	return;
}


/* Send page request. 
 * guest page address 	: 4
 * permission			: 4
 * who sent this		: 4
 * page for who			: 4
 * is false sharing		: 4
 */
static void offload_send_page_request(int idx, target_ulong page_addr, uint32_t perm, int forwho)
{
	p = BUFFER_PAYLOAD_P;

	*((target_ulong *) p) = page_addr;
	p += sizeof(target_ulong);
	*((uint32_t *) p) = perm;
	p += sizeof(uint32_t);
	*((int*) p) = offload_client_idx;
	p += sizeof(int);
	*((int*) p) = forwho;
	p += sizeof(int);

	struct tcp_msg_header *tcp_header = (struct tcp_msg_header *)net_buffer;
	fill_tcp_header(tcp_header, p - net_buffer - sizeof(struct tcp_msg_header), TAG_OFFLOAD_PAGE_REQUEST);

	int res = autoSend(idx, net_buffer, p - net_buffer, 0);
	if (res < 0)
	{
		fprintf(stderr, "[offload_send_page_request]\tpage request %x sending to %d failed\n", g2h(page_addr), idx);
		exit(0);
	}
	else if (res != p - net_buffer)
	{
		fprintf(stderr, "[offload_send_page_request]\tsent page %x request shorter than expected, %d of %d\n", page_addr, res, p - net_buffer);
		exit(0);
	}
	fprintf(stderr, "[offload_send_page_request]\tsent page %x request to node# %d, perm: %d, packet#%d\n", page_addr, idx, perm, get_number());
	//pthread_mutex_unlock(&socket_mutex);
}

static void offload_send_page_wakeup(int idx, target_ulong page_addr)
{
	char *pp = buf + sizeof(struct tcp_msg_header);
	*((target_ulong *) pp) = page_addr;
	pp += sizeof(target_ulong);
	struct tcp_msg_header *tcp_header = (struct tcp_msg_header *)buf;
	fill_tcp_header(tcp_header, pp - buf - sizeof(struct tcp_msg_header), TAG_OFFLOAD_PAGE_WAKEUP);
	autoSend(idx, buf, pp - buf, 0);
	fprintf(stderr, "[offload_send_page_wakeup]\tsent page wakeup %x to #%d, packet#%d\n", page_addr, idx, get_number());
}
static void offload_send_page_content(int idx, target_ulong page_addr, uint32_t perm, char *content)
{
	//PageMapDesc *pmd = get_pmd(page_addr);
	///* If this is a fs page need to be processed and no one but us has the page now. */
	//fprintf(stderr, "[offload_send_page_content]\t%p page bit = %p perm = %d, c1 %d c2 %d\n", 
	//					page_addr, pmd->flag, perm, pmd->flag & DQEMU_PAGE_PROCESS_FS,
	//					perm==2);
	//if ((pmd->flag & DQEMU_PAGE_PROCESS_FS) && (perm == 2)) {
	//	/* perm == 2: at this time this is the only copy. */
	//	pthread_mutex_lock(&master_mprotect_mutex);
	//	mprotect(g2h(page_addr), TARGET_PAGE_SIZE, PROT_READ | PROT_WRITE);
	//	fprintf(stderr, "[offload_send_page_content]\tcopying to %p\n", page_addr);
	//	memcpy(g2h(page_addr), content, TARGET_PAGE_SIZE);
	//	offload_client_process_false_sharing_page(page_addr);
	//	pthread_mutex_unlock(&master_mprotect_mutex);
	//	offload_send_page_wakeup(idx, page_addr);
	//	return;
	//}
	char *pp = buf + sizeof(struct tcp_msg_header);
	//fprintf(stderr, "[offload_send_page_content]\tp: %p, net_buffer: %p\n", p, net_buffer);
	*((target_ulong *) pp) = page_addr;
	pp += sizeof(target_ulong);
	//fprintf(stderr, "[offload_send_page_content]\t%d\n", p - net_buffer);
	*((uint32_t *) pp) = perm;
	pp += sizeof(uint32_t);
	//fprintf(stderr, "[offload_send_page_content]\t%d\n", p - net_buffer);
	memcpy(pp, content, TARGET_PAGE_SIZE);
	pp += TARGET_PAGE_SIZE;
	//fprintf(stderr, "[offload_send_page_content]\t%d\n", p - net_buffer);
	struct tcp_msg_header *tcp_header = (struct tcp_msg_header *)buf;
	fill_tcp_header(tcp_header, pp - buf - sizeof(struct tcp_msg_header), TAG_OFFLOAD_PAGE_CONTENT);

	autoSend(idx, buf, pp - buf, 0);

	fprintf(stderr, "[offload_send_page_content]\tsent page content %x to #%d, perm %d, packet#%d\n", page_addr, idx, perm, get_number());
}

// get the imformation of mutex-done sender and remove it from MutexList
static void offload_process_mutex_done(void)
{

	p = net_buffer;
	uint32_t cas_addr = *(uint32_t *) p;
	p += sizeof(uint32_t);
	uint32_t idx = *(uint32_t *)p;
	p += sizeof(uint32_t);
	uint32_t nowv = *(uint32_t *)p;
	fprintf(stderr, "[offload_process_mutex_done]\tcas done signal %p from #%d, nowv %x\n", cas_addr, idx, nowv);
	pthread_mutex_lock(&g_cas_mutex);
	show_cas_list();
	cas_record *record = cas_list_lookup(cas_addr);
	assert(record != NULL);
	assert(record->user == idx);
	cas_node *tmp = record->req_list, *tmp2;
	assert(tmp != NULL);
	fprintf(stderr, "[offload_process_mutex_done]\tRemoving pending request...\n");
	/* Remove the pending request. shitty things to do if there's not a head in list */
	if (tmp->idx == idx) {
		/* It should not fail. */
		assert(tmp->newv == nowv);
		record->req_list = tmp->next;
		free(tmp);
	}
	else {
		while (tmp->next && tmp->next->idx != idx) {
			tmp = tmp->next;
		}
		/* there must be a pending request! */
		assert(tmp->next != NULL);
		/* It should not fail. */
		assert(tmp->next->newv == nowv);
		tmp2 = tmp->next;
		tmp->next = tmp->next->next;
		free(tmp2);
	}
	record->user = -1;
	record->cas_value = nowv;
	show_cas_list();
	/* look up valid pending request */
	fprintf(stderr, "[offload_process_mutex_done]\tLooking up valid user...\n");
	tmp = record->req_list;
	while (tmp) {
		if (tmp->cmpv == record->cas_value)
			break;
		tmp = tmp->next;
	}
	if (tmp) {
		record->user = tmp->idx;
		offload_send_mutex_verified(tmp->idx);
	}
	else {
		fprintf(stderr, "[offload_process_mutex_done]\tno valid user!\n");
	}
	show_cas_list();
	pthread_mutex_unlock(&g_cas_mutex);
}

static void offload_send_mutex_verified(int idx)
{
	char buf[TARGET_PAGE_SIZE * 2];
	char *pp = buf + sizeof(struct tcp_msg_header);
	struct tcp_msg_header *tcp_header = (struct tcp_msg_header *)buf;
	fill_tcp_header(tcp_header, pp - buf - sizeof(struct tcp_msg_header), TAG_OFFLOAD_CMPXCHG_VERYFIED);
	autoSend(idx, buf, pp - buf, 0);
	fprintf(stderr, "[offload_send_cmpxchg_verified]\tsent cmpxchg verified to #%d packet#%d\n", idx, get_number());
}

static void offload_send_tid(int idx, uint32_t tid)
{
	char buf[TARGET_PAGE_SIZE * 2];
	char *pp = buf + sizeof(struct tcp_msg_header);
	*((uint32_t*)pp) = tid;
	fprintf(stderr, "[offload_send_tid]\tsent tid = %p to #%d packet#%d\n", *(uint32_t*)pp, idx, get_number());
	pp += sizeof(uint32_t);

	struct tcp_msg_header *tcp_header = (struct tcp_msg_header *)buf;
	fill_tcp_header(tcp_header, pp - buf - sizeof(struct tcp_msg_header), TAG_OFFLOAD_YOUR_TID);


	autoSend(idx, buf, pp - buf, 0);
	fprintf(stderr, "[offload_send_tid]\tsent tid = %p to #%d packet#%d\n", tid, idx, get_number());
}

static void offload_process_page_ack(void)
{
	p = net_buffer;
	uint32_t page_addr = *(uint32_t *) p;
	p += sizeof(uint32_t);
	uint32_t perm = *(uint32_t *) p;
	p += sizeof(uint32_t);

	PageMapDesc *pmd = get_pmd(page_addr);

	fprintf(stderr, "[offload_process_page_ack]\tprocessed page %x ack, perm: %d\n", page_addr, perm);
	//pthread_mutex_lock(&pmd->owner_set_mutex);
	if (perm == 1)
	{
	}
	else if (perm == 2)
	{
		clear(&pmd->owner_set);
	}
	insert(&pmd->owner_set, offload_client_idx);

	req_node *pnode = pmd->list_head.next;
	pmd->list_head.next = pnode->next;
	free(pnode);
	fprintf(stderr, "[offload_process_page_ack]\tunlocking...%p\n", &pmd->owner_set_mutex);
	pthread_mutex_unlock(&pmd->owner_set_mutex);

	offload_log(stderr, "[offload_process_page_ack]\tpage %x, unlock\n", page_addr);
	print_holder(page_addr);
	process_pmd(page_addr);
}


static void offload_send_page_perm(int idx, target_ulong page_addr, int perm)
{


	p = BUFFER_PAYLOAD_P;

	*((target_ulong *) p) = page_addr;
	p += sizeof(target_ulong);

	*((int *) p) = perm;
	p += sizeof(int);

	struct tcp_msg_header *tcp_header = (struct tcp_msg_header *)net_buffer;
	fill_tcp_header(tcp_header, p - net_buffer - sizeof(struct tcp_msg_header), TAG_OFFLOAD_PAGE_PERM);

	int res = autoSend(idx, net_buffer, p - net_buffer, 0);
	if (res < 0)
	{
		fprintf(stderr, "[offload_send_page_perm]\tpage %x perm to %d sent failed res: %d errno: %d\n", page_addr, idx, res, errno);
		exit(0);
	}

	return;
}



/*	revoke pages from worker
 *	1. READ - simply send page_content
 *	2. WRITE - invalid_count == 1, send page_content
 */
static void offload_process_page_content(void)
{
	p = net_buffer;
	uint32_t page_addr = *(uint32_t *) p;
	p += sizeof(uint32_t);
	uint32_t perm = *(uint32_t *) p;
	p += sizeof(uint32_t);
	int forwho = *((int*) p);
	p += sizeof(int);

	PageMapDesc *pmd = get_pmd(page_addr);

	int requestor_idx = pmd->requestor;

	fprintf(stderr, "[offload_process_page_content]\tpage %x, perm %d, for #%d, actually forwho:%d\n", page_addr, perm, requestor_idx, forwho);
	if (forwho != requestor_idx)
	{
		exit(0);
	}
	if (perm == 2)
	{
		if (pmd->invalid_count - 1 <= 0)
		{
			/* a normal CONTENT request, -1 for futex */
			if (requestor_idx >= 0)
			{
				/* if this is the last retrieved page, send to worker.
				 * pmd is globally shared between all client daemonizes.
				 */
				pmd->invalid_count--;
				if (pmd->invalid_count<0)
				{
					fprintf(stderr, "[offload_process_page_content]\tWTHE HELL IS happening??invalid_cound = %d\n", pmd->invalid_count);
					exit(-2);
				}
				offload_send_page_content(requestor_idx, page_addr, perm, p);

			}

			else if (requestor_idx == -1)
			{
				fprintf(stderr, "[offload_process_page_content]\tWTHE HELL IS happening??\n", page_addr, perm);
				exit(123);
			}
		}
		else
		{
			/* wait until all of the workers have invalidated their pages */
			pmd->invalid_count--;
			fprintf(stderr, "[offload_process_page_content]\t invalid_count: %d left\n", pmd->invalid_count);

		}
	}
	else if (perm == 1)
	{
		/* perm == 1 means a worker requests shared page
		 * 1. if write->read, only one worker has the page
		 * 2. if read->read, each of their page is the same
		 * So we just send to our worker the page
		 */
		offload_send_page_content(requestor_idx, page_addr, perm, p);
	}
	fprintf(stderr, "[offload_process_page_content]\treturning...\n");

}

void* process_syscall_thread(void* syscall_pp)
{

	pthread_mutex_lock(&do_syscall_mutex);
	fprintf(stderr, "[process_syscall_thread]\tgot lock, waking up\n");
	while (do_syscall_flag == 1)
	{
		pthread_cond_wait(&do_syscall_cond,&do_syscall_mutex);
		fprintf(stderr,"[process_syscall_thread]\twaiting!\n");
	}
	struct syscall_param* syscall_p = (struct syscall_param*)syscall_pp;
	CPUARMState* cpu_env = (CPUARMState*)syscall_p->cpu_env;
	int num = syscall_p->num;
	abi_long arg1 = syscall_p->arg1;
	abi_long arg2 = syscall_p->arg2;
	abi_long arg3 = syscall_p->arg3;
	abi_long arg4 = syscall_p->arg4;
	abi_long arg5 = syscall_p->arg5;
	abi_long arg6 = syscall_p->arg6;
	abi_long arg7 = syscall_p->arg7;
	abi_long arg8 = syscall_p->arg8;
	int idx = syscall_p->idx;
	int thread_id = syscall_p->thread_id;

	syscall_global_pointer = syscall_p;
	do_syscall_flag = 1;
    fprintf(stderr,
            "[process_syscall_thread]\t I am thread. processing passed syscall from %d->%d, arg1: %p, arg2:%p, arg3:%p\n",
            idx, thread_id, arg1, arg2, arg3);

	fprintf(stderr, "[process_syscall_thread]\twaking up &locking syscall_thread\n");
	pthread_cond_signal(&do_syscall_cond);
	fprintf(stderr, "[process_syscall_thread]\texiting mutex\n");
	pthread_mutex_unlock(&do_syscall_mutex);
	fprintf(stderr, "[process_syscall_thread]\twoke up, done.\n");
	return NULL;
}

static void offload_process_syscall_request(void)
{
	p = net_buffer;
	CPUARMState* env = (CPUARMState*)malloc(sizeof(CPUARMState));
	*env = *((CPUARMState*)p);
	//void* cpu_env = *(void**) p;
	p += sizeof(CPUARMState);

	int num = *(int *)p;
	p += sizeof(int);
	uint32_t arg1 = *((uint32_t*) p);
	p += sizeof(uint32_t);
	uint32_t arg2 = *((uint32_t*) p);
	p += sizeof(uint32_t);
	uint32_t arg3 = *((uint32_t*) p);
	p += sizeof(uint32_t);
	abi_long arg4 = *((uint32_t*) p);
	p += sizeof(abi_long);
	abi_long arg5 = *((uint32_t*) p);
	p += sizeof(abi_long);
	abi_long arg6 = *((uint32_t*) p);
	p += sizeof(abi_long);
	abi_long arg7 = *((uint32_t*) p);
	p += sizeof(abi_long);
	abi_long arg8 = *((uint32_t*) p);
	p += sizeof(abi_long);
	int idx = *(int*) p;
	p += sizeof(int);
	int thread_id = *(int*)p;
	p += sizeof(int);
	struct syscall_param* syscall_p = (struct syscall_param*)malloc(sizeof(struct syscall_param));
	syscall_p->cpu_env = env;
	syscall_p->num = num;
	syscall_p->arg1 = arg1;
	syscall_p->arg2 = arg2;
	syscall_p->arg3 = arg3;
	syscall_p->arg4 = arg4;
	syscall_p->arg5 = arg5;
	syscall_p->arg6 = arg6;
	syscall_p->arg7 = arg7;
	syscall_p->arg8 = arg8;
	syscall_p->idx = idx;
	syscall_p->thread_id = thread_id;

    fprintf(stderr,
            "[offload_process_syscall_request]\treceived passed syscall to center from %d->%d, arg1: %p, arg2:%p, arg3:%p,CREATING THREAD\n",
            idx, thread_id, arg1, arg2, arg3);


	pthread_t syscall_thread;
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	if (pthread_create(&syscall_thread,&attr,process_syscall_thread,(void*)syscall_p) != 0) {
		perror("pthread_create");
		exit(19);
	}
}

static void offload_send_syscall_result(int idx, abi_long result, int thread_id)
{
	fprintf(stderr, "[offload_send_syscall_result]\tsending syscall result to #%d->%d with ret=%p\n", idx, thread_id, result);
	char buf[TARGET_PAGE_SIZE * 2];
	char *pp = buf + sizeof(struct tcp_msg_header);
	*((abi_long*)pp) = result;
	pp += sizeof(abi_long);
	*((int*)pp) = thread_id;
	pp += sizeof(int);
	struct tcp_msg_header *tcp_header = (struct tcp_msg_header *)buf;
	fill_tcp_header(tcp_header, pp - buf - sizeof(struct tcp_msg_header), TAG_OFFLOAD_SYSCALL_RES);
	autoSend(idx, buf, pp - buf, 0);
    fprintf(stderr, "[offload_send_syscall_result]\tsent syscall result to #%d->%d\n", idx,
            thread_id);
}

/* do_fork information */
/* static int do_fork_remote(CPUArchState *env, unsigned int flags, abi_ulong newsp,
                   abi_ulong parent_tidptr, target_ulong newtls,
                   abi_ulong child_tidptr)
*/
void offload_send_do_fork_info(int idx, unsigned int flags, abi_ulong newsp,
                   abi_ulong parent_tidptr, target_ulong newtls,
                   abi_ulong child_tidptr)
{
	fprintf(stderr, "[offload_send_do_fork_info]\tsending do fork info to #%d\n", idx);
	char buf[TARGET_PAGE_SIZE * 2];
	char *pp = buf + sizeof(struct tcp_msg_header);
	*((unsigned int*)pp) = flags;
	pp += sizeof(unsigned int);
	*((abi_ulong*)pp) = newsp;
	pp += sizeof(abi_ulong);
	*((abi_ulong*)pp) = parent_tidptr;
	pp += sizeof(abi_ulong);
	*((target_ulong*)pp) = newtls;
	pp += sizeof(target_ulong);
	*((abi_ulong*)pp) = child_tidptr;
	pp += sizeof(abi_ulong);
	    fprintf(stderr, "[do_fork_server_local]\t flags %p, newsp %p, parent_tidptr %p, newtls %p, child_tidptr %p\n",
                                                 flags, newsp, parent_tidptr, newtls, child_tidptr);
	struct tcp_msg_header *tcp_header = (struct tcp_msg_header *)buf;
	fill_tcp_header(tcp_header, pp - buf - sizeof(struct tcp_msg_header), TAG_OFFLOAD_FORK_INFO);
	autoSend(idx, buf, pp - buf, 0);
    fprintf(stderr, "[offload_send_do_fork_info]\tsent do fork info to #%d\n", idx);
}

static void show_prefetch_list(int idx)
{
	fprintf(stderr, "[show_prefetch_list]\tShowing for %d\n", idx);
    struct pgft_record *p = &prefetch_table[idx];	//pagefault node
	while (p) {
		fprintf(stderr, "page_addr %p\t|life %d\t|wait_addr %p\t|wait_hit_count %d\t|page_hit_count %d\t|pref_count %d|pref_beg_addr %p\n",
				p->page_addr, p->life, p->wait_addr, p->wait_hit_count, p->page_hit_count, p->pref_count, p->fetch_beg_addr);
		p = p->next;
	}
}

/* check if page_addr already in prefetching 
 * if so, return -1
 * else return 0
 */
static int prefetch_check(uint32_t page_addr, int idx)
{
	fprintf(stderr, "[prefetch_check]\tchecking..page_addr %p\n", page_addr);
	show_prefetch_list(idx);
	struct pgft_record *p = prefetch_table[idx].next; //pagefault node
	uint32_t beg, end;
	int i = 0;
	while (p)
	{
		if (p->pref_count !=0) {
			beg = p->fetch_beg_addr;
			end = beg + p->pref_count * 0x1000;
			if ((page_addr>=beg) && (page_addr<=end)){
				fprintf(stderr, "[prefetch_check]\talready in list, pos: %d\n", i);				
				return -1;
			}
		}
		i++;
		p = p->next;
	}
	return 0;
}

// for prefetch page for server
//TODO weight how much does this cost
//TODO exclusive send test & how much would it cost(mutex)
static int prefetch_handler(uint32_t page_addr, int idx)
{
	show_prefetch_list(idx);
    struct pgft_record *p = prefetch_table[idx].next;	//pagefault node
	struct pgft_record *pre = &prefetch_table[idx];		//previous node for deleting p
	struct pgft_record *psave = NULL;
	int ret = 0;
	int alread_exist = 0;
    // search **all** for wait_addr and dec others' life
    while (p)
	{
		// Hit page_addr, regard it as conflict page
		if (p->page_addr == page_addr) {
			p->life += PREFETCH_LIFE;
			if (++p->page_hit_count >= 10) {
				fprintf(stderr, "[prefetch_handler]\tConflict page %p found!\n", page_addr);
				ret = -1;
			}
			pre = p;
			p = p->next;
			alread_exist = 1;
		}
		else
		// search **all** for wait_addr and dec others' life
		// Miss
		if (p->wait_addr != page_addr) {
			p->life--;
			/* 1. If `life == 0` then remove it.
			 * 2. Forward to next node */
			if (p->life == 0) {
				fprintf(stderr, "[prefetch_handler]\tNode %p is dead. Deleting from list.\n", p->page_addr);
				pre->next = p->next;
				free(p);
				p = pre->next;
				continue;
			}
			pre = p;
			p = p->next;
		} 
		// hit predicted address, save it to psave
		else {
			fprintf(stderr, "[prefetch_handler]\tfound hit wait_addr! of page %p\n", p->page_addr);
			psave = p;
			pre = p;
			p = p->next;
		}
	}
	if (psave)// found
    {
		p = psave;
        fprintf(stderr, "[prefetch_handler]\tWait addr %p of page %p found!\n", page_addr, p->page_addr);
        p->wait_hit_count++;
		if (p->wait_hit_count < 2)  				// not started
        {
			p->wait_addr = page_addr + PAGE_SIZE;		// wait at next page
            p->life = 100;
        } 
		else {    // >=4 , launched
			
			if (p->pref_count == 0) p->pref_count = PREFETCH_BEGIN_PAGE_COUNT;
            else  p->pref_count *= 2;
			if (p->pref_count > PREFETCH_PAGE_MAX)
				p->pref_count = PREFETCH_PAGE_MAX;
			ret = p->pref_count;
			/* wait at next page */
            p->wait_addr = page_addr + (p->pref_count + 1)*PAGE_SIZE;
			p->fetch_beg_addr = page_addr;
			p->life += ret;
			fprintf(stderr, "[prefetch_handler]\tPrefetching for %p for %d pages, waiting at %p\n", page_addr, p->pref_count, p->wait_addr);
		}

	}
	else if (!alread_exist) {	
		// add new node
        fprintf(stderr, "[prefetch_handler]\tAdd new node %p!\n", page_addr);
		p = (struct pgft_record*)malloc(sizeof(struct pgft_record));
		memset(p, 0, sizeof(struct pgft_record));
		p->page_addr = page_addr;
		p->life = PREFETCH_LIFE;
		p->wait_addr = page_addr + PAGE_SIZE;
		pre->next = p;
        fprintf(stderr, "[prefetch_handler]\tAdded new node %p!\n", page_addr);
		ret = 0;
	}
	show_prefetch_list(idx);
	
	return ret;
}

void offload_master_send_page(uint32_t page_addr, int perm, int idx)
{
	PageMapDesc_server *pmd = get_pmd_s(page_addr);
	fprintf(stderr, "[offload_master_send_page]\tpage %x, perm %d, for %d\n", page_addr, perm, idx);
	pmd->cur_perm = 1;
		pthread_mutex_lock(&master_mprotect_mutex);
	mprotect(g2h(page_addr), TARGET_PAGE_SIZE, PROT_READ);//prevent writing at this time!!

	char buf[TARGET_PAGE_SIZE * 2];
	char *p = buf + sizeof(struct tcp_msg_header);
	/* fill addr and perm */
	*((uint32_t *) p) = page_addr;
    p += sizeof(uint32_t);
	*((uint32_t *) p) = perm;
	p += sizeof(uint32_t);
    /* followed by page content (size = TARGET_PAGE_SIZE) */
	fprintf(stderr, "[offload_master_send_pageDEBUG]\tPOINT1\n");
	//TODO: 如果是2就直接disable了 如果是1就發送。
	//mprotect(g2h(page_addr), TARGET_PAGE_SIZE, PROT_READ | PROT_WRITE);
	fprintf(stderr, "[offload_master_send_pageDEBUG]\tPOINT1.5\n");
	memcpy(p, g2h(page_addr), TARGET_PAGE_SIZE);
	fprintf(stderr, "[offload_master_send_pageDEBUG]\tPOINT2\n");
    p += PAGE_SIZE;
	/* fill head */
	struct tcp_msg_header *tcp_header = (struct tcp_msg_header *) buf;
	fill_tcp_header(tcp_header, p - buf - sizeof(struct tcp_msg_header), TAG_OFFLOAD_PAGE_CONTENT);
	fprintf(stderr, "[offload_master_send_pageDEBUG]\tPOINT3\n");
	int res = autoSend(idx, buf, p - buf, 0);
	if (res < 0)
	{
		fprintf(stderr, "[offload_master_send_page]\tsent page %x content failed\n", page_addr);
		exit(0);
	}
	fprintf(stderr, "[offload_master_send_page]\tsent page %x content, perm%d, packet#%d\n", page_addr, perm, get_number());
	fprintf(stderr, "[offload_master_send_page]\tsent content\n", page_addr, perm);
	/*	if required permission is WRITE|READ,
	*	we won't be able to use it (invalidate)
	*	otherwise it is a shared page (shared)
	*/
	
	if (perm == 2)
	{
		mprotect(g2h(page_addr), PAGE_SIZE, PROT_NONE);
		pmd->cur_perm = 0;
	}
	else if (perm == 1)
	{
		mprotect(g2h(page_addr), PAGE_SIZE, PROT_READ);
		pmd->cur_perm = 1;
	}
		pthread_mutex_unlock(&master_mprotect_mutex);
}