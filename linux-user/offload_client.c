



#define MAP_PAGE_BITS 12
// prefetch
#define MAX_WORKER 20
#define PREFETCH_PAGE_MAX 1000
#define PREFETCH_LAUNCH_VALVE 4
#define PREFETCH_LIFE 20

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
static void offload_send_mutex_verified(int);
static void offload_process_mutex_done(void);
static void offload_send_syscall_result(int,abi_long);
static void offload_process_syscall_request(void);
static void offload_send_tid(int idx, uint32_t tid);
//futexes
static void futex_table_wake(uint32_t futex_addr, int num, int);
static void print_futex_table();
static void futex_table_add(uint32_t futex_addr, int idx);
static int try_recv(int);
static int communication_send_sum, communication_recv_sum;
int syscall_started_flag;
//int requestor_idx, target_ulong addr, int perm
struct info
{
	int requestor_idx,perm;
	target_ulong addr;
};

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
};

struct syscall_param* syscall_global_pointer;

static pthread_mutex_t clone_syscall_mutex;
static int testint = 233;
struct Node
{
	int val;
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
	int life;
	int wait_hit_count;// for correctly pre
	int pref_count;// how many is beging prefetching
	int page_hit_count;// for conflicting pages
	struct pgft_record *next;
};

static struct futex_record * futex_table;
static struct pgft_record prefetch_table[MAX_WORKER];
static int prefetch_handler(uint32_t page_addr, int idx);
static void show_prefetch_list(int idx);




#include "set.h"
#include "offload_common.h"


#define fprintf offload_log

#define MUTEX_LIST_MAX 10

#define WORKER_COUNT 10

static __thread char net_buffer[NET_BUFFER_SIZE];

static int __thread has_pending_request;

static target_ulong mutex_list[MUTEX_LIST_MAX] = {0};

// |mutex address|holder|requestor list|pending flag|
struct MutexTuple
{
	uint32_t mutexAddr;
	uint32_t holderId;
	bool hasPending;
	uint32_t pendingList[WORKER_COUNT];	//TODO: SHOULD BE INT!!! BECAUSE CLIENT STARTS WITH #0!!!!!!
	int tail;	// behave as a list
	int head;
};

static struct MutexTuple MutexList[MUTEX_LIST_MAX];

/*
static int __thread pending_request_addr;
static int __thread pending_futex_addr;
static int __thread pending_requestor;
static int __thread pending_page_request_perm;
*/

struct request_t
{

	enum
	{
		PAGE, FUTEX,
	} type;

	int addr;

	int requestor;

	int perm;


	target_ulong uaddr;
	int op;
	int val;
	target_ulong timeout;
	target_ulong uaddr2;
	int val3;
};

static __thread struct request_t pending_request;

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
int last_flag_lock = 1; // whether we succeeded on try_lock

static __thread int cmpxchg_flag;

static pthread_mutex_t count_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t socket_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t do_syscall_mutex; static pthread_cond_t do_syscall_cond; int do_syscall_flag;
static int is_first_do_syscall_thread;






typedef struct PageMapDesc {
	uint32_t oflags;	/* original flags */
	uint32_t flags;		/* current flags */

	/* Used to sync with server */
	int on_server;		/* if this page is on server side */

	int requestor;
	//std::set<int> owner_set;

	set_t owner_set;

	pthread_mutex_t owner_set_mutex;

	int mutex_count;
	int mutex_holder;
	//int cur_idx;
	//pthread_mutex_t cmpxchg_mutex;
	int invalid_count;



	int recv_flag;
	pthread_cond_t recv_cond;
	pthread_mutex_t recv_mutex;

} PageMapDesc;




PageMapDesc page_map_table[L1_MAP_TABLE_SIZE][L2_MAP_TABLE_SIZE] __attribute__ ((section (".page_table_section"))) __attribute__ ((aligned(4096))) = {0};


pthread_once_t pmd_init_once = PTHREAD_ONCE_INIT;

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
static void offload_send_start(void);
static void offload_send_page_upgrade(int idx, target_ulong page_addr, int);

static void offload_process_page_request(void);
void* offload_client_daemonize(void);
static void offload_client_send_futex_wake_result(int result);
//int client_segfault_handler(int host_signum, siginfo_t *pinfo, void *puc);

void offload_client_start(CPUArchState *the_env);
void* offload_center_client_start(void*);
static void offload_send_page_request(int idx, target_ulong guest_addr, uint32_t perm,int );
static void offload_send_page_content(int idx, target_ulong guest_addr, uint32_t perm, char *content);

static void offload_client_send_cmpxchg_ack(target_ulong);
static void offload_process_page_ack(void);
static void offload_send_page_perm(int idx, target_ulong page_addr, int perm);
static int offload_client_fetch_page(int requestor_idx, uint32_t page_addr, int is_write);
static void offload_client_send_futex_wait_result(int result);
static void offload_client_process_futex_wait_request(void);
static void offload_process_page_content(void);
static void offload_client_process_futex_wake_request(void);
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

			pthread_mutex_init(&page_map_table[i][j].owner_set_mutex, NULL);
			pthread_mutex_init(&page_map_table[i][j].recv_mutex, NULL);
			pthread_cond_init(&page_map_table[i][j].recv_cond, NULL);
			clear(&page_map_table[i][j].owner_set);
			insert(&page_map_table[i][j].owner_set, 0);
			page_map_table[i][j].mutex_count = 0;
			//fprintf(stderr, "%d", page_map_table[i][j].owner_set.size);
		}
	}
}

extern void offload_server_qemu_init(void);

static void offload_client_init(void)
{
	//offload_server_qemu_init();	//hack, using this func without changing its name
	pthread_mutex_lock(&offload_count_mutex);
	offload_count++;
	offload_client_idx = offload_count;

	pthread_mutex_unlock(&offload_count_mutex);

	fprintf(stderr, "[offload_client_init]\tindex: %d\n", offload_client_idx);


	skt[offload_client_idx] = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	struct sockaddr_in server_addr, client_addr;
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(server_port_of(offload_client_idx));
	char* ip_addr;
	switch (offload_client_idx)
	{
		case 0:
			ip_addr = "127.0.0.1";
			break;
		case 1:
		case 2:
			//ip_addr = "192.168.1.101";
			ip_addr = "127.0.0.1";
			break;
		//case 2:
		case 3:
		case 4:
			ip_addr = "127.0.0.1";
			break;
		case 5:
		case 6:
		case 7:
		case 8:
			ip_addr = "10.134.76.146";
			break;
		case 9:
		case 10:
		case 11:
		case 12:
			ip_addr = "10.134.43.199";
			break;
		default:
			ip_addr = "10.134.101.9";
			break;
	}
	//ip_addr = "127.0.0.1";
	// if (offload_client_idx == 0)
	// {
	// 	ip_addr = "192.168.1.107";
	// }
	// else if (offload_client_idx<=3)
	// {
	// 	ip_addr = "10.134.83.158";
	// }
	// else if (offload_client_idx<=6)
	// {
	// 	ip_addr = "192.168.1.100";
	// }
	// else if (offload_client_idx<=16)
	// {
	// 	ip_addr = "192.168.1.107";
	// }
	// else if (offload_client_idx<=7+2)
	// {

	// }
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
		fprintf(stderr, "[offload_client_init]\tgot host name %s, h_addrtype %d, h_addr: %p\n", he->h_name, he->h_addrtype, he->h_addr);
		memcpy((char *)&dst_ip,(char *)he->h_addr,sizeof(he->h_addr));
	}
	//server_addr.sin_addr.s_addr = inet_addr(ip_addr);
	server_addr.sin_addr.s_addr=dst_ip;

	bzero(&(server_addr.sin_zero), 8);
	int struct_len = sizeof(struct sockaddr_in);

	//fprintf(stderr, "[client]\toffload index: %d\n", offload_client_idx);
	fprintf(stderr, "[offload_client_init]\tconnecting to server, port# %d\n", server_port_of(offload_client_idx));
	if (connect(skt[offload_client_idx],(struct sockaddr*) &server_addr, struct_len) == -1)
	{
		fprintf(stderr, "[offload_client_init]\tconnect port# %d failed, errno: %d\n", server_port_of(offload_client_idx), errno);
		perror("connect");
		exit(0);
	}

	fprintf(stderr,"[offload_client_init]\tconnecting succeed, client index# %d, skt: %d\n", offload_client_idx, skt[offload_client_idx]);

	//NONBLOCK receive
	//fcntl(skt[offload_client_idx], F_SETFL, fcntl(skt[offload_client_idx], F_GETFL) | O_NONBLOCK);
	//struct timeval timeout={1, 0};
	//int ret = setsockopt(skt[offload_client_idx], SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));

	futex_table = (struct futex_record*)malloc(10*sizeof(struct futex_record));
	memset(futex_table, 0, 10*sizeof(struct futex_record));

	pthread_mutex_init(&page_recv_mutex, NULL);
	pthread_cond_init(&page_recv_cond, NULL);
	pthread_mutex_init(&send_mutex[offload_client_idx], NULL);
	pthread_cond_init(&send_cond[offload_client_idx], NULL);
	communication_send_sum = 0;
	communication_recv_sum = 0;
	has_pending_request = 0;
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

			fprintf(stderr, "memory region: %x to %x, host: %x to %x\n", start, end, g2h(start), g2h(end));
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
	fprintf(stderr, "[dump_code]\t0x10324 is at host %x. = %x = %x\n", g2h(0x10324), *((uint32_t *) g2h(0x10324)), tmp[0]);
	target_disas(stderr, ENV_GET_CPU(client_env), client_env->regs[15], 10);
	memcpy((void *)p, (void *)(g2h(binary_start_address )), (unsigned int)binary_end_address - binary_start_address);
	//fprintf(stderr, "here: %d %d %d\n", );
	p += (uint32_t)binary_end_address - binary_start_address;
	fprintf(stderr, "first code: %x", *((uint32_t *) g2h(client_env->regs[15])));
}

static void dump_cpu(void)
{
	//offload_center_clone_mutex;
	//pthread_mutex_lock(&offload_center_clone_mutex);
	*((CPUARMState *) p) = *client_env;



	p += sizeof(CPUARMState);

	fprintf(stderr,"[dump_cpu]\tenv: %p\n", client_env);
	CPUState *cpu = ENV_GET_CPU((CPUArchState *)client_env);
	fprintf(stderr,"[dump_cpu]\tcpu: %p\n", cpu);
	TaskState *ts;
	fprintf(stderr,"[load_cpu]\topaque: %p\n", cpu->opaque);
	ts = cpu->opaque;
	fprintf(stderr,"[dump_cpu]\tNOW child_tidptr: %p\n", ts->child_tidptr);
	*((TaskState*)p) = *ts;
	p += sizeof(TaskState);
	//pthread_mutex_unlock(&offload_center_clone_mutex);
	/**((uint32_t*)p) = (uint32_t)vfp_get_fpscr(env);
	p += sizeof(uint32_t);


	// cp15, don't know what it's used for
	// the QEMU variable is 64 bit,
	// but the CSBT transfer it in 32 bit
	// don't know why either.
	*((uint64_t*)p) = (uint64_t)(env->cp15.tpidrro_el[0]);
	p += sizeof(uint64_t);


	*((uint32_t*)p) = (uint32_t)cpsr_read(env);
	p += sizeof(uint32_t);

	memcpy(p, env->vfp.regs, sizeof(env->vfp.regs));
	p += sizeof(env->vfp.regs);


	memcpy(p, env->regs, sizeof(env->regs));
	p += sizeof(env->regs);*/
}
static void offload_send_start(void)
{
	//pthread_mutex_lock(&socket_mutex);
	fprintf(stderr, "[client]\tsending offload start request\n");
	int res;

	p = BUFFER_PAYLOAD_P;



	//printf(">>>>>>>>>>\n");
	fprintf(stderr, "[client]\tdumping cpu\n");
	dump_cpu();
	fprintf(stderr, "[offload_send_start]\tregisters:\n");

	for (int i = 0; i < 16; i++)
	{
		fprintf(stderr, "%d\n", client_env->regs[i]);
	}
	//dump_function_address();
	dump_self_maps();

	dump_brk();


	dump_code();
	fprintf(stderr, "[client]\tPC: %d\n", client_env->regs[15]);
	//target_disas(stderr, ENV_GET_CPU(client_env), client_env->regs[15], 100);
	struct tcp_msg_header *tcp_header = (struct tcp_msg_header *) net_buffer;
	fill_tcp_header(tcp_header, p - net_buffer - sizeof(struct tcp_msg_header), TAG_OFFLOAD_START);
	fprintf(stderr, "sending buffer len without header: %lx\n", p - net_buffer - sizeof(struct tcp_msg_header));
	fprintf(stderr, "sending buffer len: %ld\n", p - net_buffer);
	res = autoSend(offload_client_idx, net_buffer, (p - net_buffer), 0);
	fprintf(stderr, "[send]\tsent %d bytes\n", res);
	//pthread_mutex_unlock(&socket_mutex);
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
	int index = page_addr >> MAP_PAGE_BITS;
	int index1 = (index >> L1_MAP_TABLE_SHIFT) & (L1_MAP_TABLE_SIZE - 1);
	int index2 = index & (L2_MAP_TABLE_SIZE - 1);

	fprintf(stderr,"[print_holder]\taddr: %p index:%p index1:%p index2:%p\n",page_addr,index,index1,index2);
	PageMapDesc *pmd = &page_map_table[index1][index2];
	for (int i = 0; i < pmd->owner_set.size; i++)
	{
		int idx = pmd->owner_set.element[i];

		fprintf(stderr, "\tnode: %d", idx);
	//	if (idx != 0&&page_addr == 0xffe00000) exit(-1);
	}
	fprintf(stderr,"\n");
}

void* offload_client_fetch_page_thread(void* param)
{
	offload_mode = 5;

	struct info* info = (struct info*)param;
	int requestor_idx = info->requestor_idx;
	target_ulong addr = info->addr;
	int perm = info->perm;
	offload_client_idx = requestor_idx;
	free(info);
	fprintf(stderr, "[offload_fetch_page_thread]\tpending request working, addr:%p, idx:%d, perm:%d\n", addr, requestor_idx, perm);
	target_ulong page_addr = PAGE_OF(addr);

	int index = addr >> MAP_PAGE_BITS;
	int index1 = (index >> L1_MAP_TABLE_SHIFT) & (L1_MAP_TABLE_SIZE - 1);
	int index2 = index & (L2_MAP_TABLE_SIZE - 1);
	PageMapDesc *pmd = &page_map_table[index1][index2];
	if (last_flag_lock == 1)
	{
		fprintf(stderr, "[offload_fetch_page_thread]\tfetching page %x, locking\n", page_addr);
	}
	else
	{
		fprintf(stderr, "[offload_fetch_page_thread]\tzhebujiu liang le???\n");
		exit(-1);
	}
	pthread_mutex_lock(&pmd->owner_set_mutex);
	/* trylock succeed, fetching page */
	pmd->mutex_holder = requestor_idx;
	pmd->mutex_count++;
	offload_log(stderr, "[offload_client_fetch_page_thread]\tpending lock succeed, count: %d, holder: %d, perm: %d, mutex:%p\n", pmd->mutex_count, pmd->mutex_holder, perm, &pmd->owner_set_mutex);

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
				//fprintf(stderr, "[offload_client_fetch_page_thread]\tunlocking...%p\n", &pmd->owner_set_mutex);
				//pthread_mutex_unlock(&pmd->owner_set_mutex);
			}
			else
			/* invalid_count = the number of sharing copies to invalidate */
			for (int i = 0; i < pmd->owner_set.size; i++)
			{
				if (i == 0)
				{
					pmd->invalid_count = 1;//wait for the page content of element[0]
					offload_send_page_request(pmd->owner_set.element[0], page_addr, 2, requestor_idx);
					continue;
				}
				int idx = pmd->owner_set.element[i];
				/* if read->write, donnot ask itself to send the page!!!!! */

				if (idx == requestor_idx)
				{
					continue;
				}


				/* invalidate pages on other threads, retrieve the permission */
				offload_send_page_upgrade(idx, page_addr, 0);
			}


			// ask 0 to send the page
			// offload_send_page_request(pmd->owner_set.element[0], page_addr, 2, requestor_idx);
			// // invalidate others' page
			// for (int i = 1; i < pmd->owner_set.size; i++)
			// {

			// 	int idx = pmd->owner_set.element[i];
			// 	if (idx == requestor_idx)
			// 	{
			// 		continue;
			// 	}

			// 	/* invalidate pages on other threads, retrieve the permission */
			// 	//offload_send_page_request(idx, page_addr, 2, requestor_idx);
			// 	offload_send_page_upgrade(idx, page_addr, 0);
			// }


	}
	else if (perm == 1)
	{
		if (pmd->owner_set.size == 0)
		{
			offload_log(stderr, "[offload_client_fetch_page_thread]\terror: no one has the page\n");
			exit(-1);
		}
		/* revoke page as shared page */
		offload_send_page_request(pmd->owner_set.element[0], page_addr, 1, requestor_idx);
	}
	fprintf(stderr, "[offload_client_fetch_page_thread]\t sent\n");
	last_flag_lock = 1;

	return 0;


}

static int offload_client_fetch_page(int requestor_idx, target_ulong addr, int perm)
{

	target_ulong page_addr = PAGE_OF(addr);

	int index = addr >> MAP_PAGE_BITS;
	int index1 = (index >> L1_MAP_TABLE_SHIFT) & (L1_MAP_TABLE_SIZE - 1);
	int index2 = index & (L2_MAP_TABLE_SIZE - 1);
	PageMapDesc *pmd = &page_map_table[index1][index2];
	if (last_flag_lock == 1)
	{
		fprintf(stderr, "[offload_fetch_page]\tfetching page %x, lock\n", page_addr);
	}
	else
	{
		fprintf(stderr, "[offload_fetch_page]\tzhebujiu liang le???\n");
		exit(-1);
	}

	//pthread_mutex_lock(&pmd->owner_set_mutex);
	int res = 1;//pthread_mutex_trylock(&pmd->owner_set_mutex);

	if ((res != 0 )||1)//we throw a thread.
	{
		/* trylock failed, someone is asking for the page */
		offload_log(stderr, "[offload_client_fetch_page]\tlock failed, count: %d, holder: %d throwing new thread...\n", pmd->mutex_count, pmd->mutex_holder);
		struct info* param = (struct info*)malloc(sizeof(struct info));
		param->requestor_idx = requestor_idx;
		param->addr = addr;
		param->perm = perm;
		pthread_t pender;
		pthread_create(&pender, NULL, offload_client_fetch_page_thread, param);
		offload_log(stderr, "[offload_client_fetch_page]\tthread created.id:%d, addr:%p, perm:%d sent\n", requestor_idx, addr, perm);
		return 0;
		has_pending_request = 1;

		pending_request.requestor = requestor_idx;
		pending_request.addr = addr;
		pending_request.perm = perm;
		last_flag_lock = 0;

		return -1;
	}
	else
	{
		fprintf(stderr, "[offload_client_fetch_page]\twhat happened?\n");
		exit(0);
	}

}

// show MutexList
static void offload_show_mutex_list(void)
{
	char buf[1024];
	int i = 0;
	for (;i<MUTEX_LIST_MAX;i++)
	{
		sprintf(buf, "%smutex %d: %p holder: #%d %s\n",buf, i, MutexList[i].mutexAddr, MutexList[i].holderId, MutexList[i].hasPending?"pending":"free");
		int j = 0;
		if (MutexList[i].hasPending)
		{
			sprintf(buf, "%shead: %d, tail: %d", buf, MutexList[i].head, MutexList[i].tail);
			for (; j < WORKER_COUNT; j++)
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

// mutex start, record requestor 
static void offload_process_mutex_request(void)
{

	p = net_buffer;
	target_ulong mutex_addr = *(target_ulong *) p;
	p += sizeof(target_ulong);
	uint32_t requestorId = *(uint32_t *) p;
	fprintf(stderr, "[offload_process_mutex_request client#%d]\trequested mutex address: %p from %d\n", offload_client_idx, mutex_addr, requestorId);

	//static
	//static mutex_count = 0;
	//check if exists
	int i = 0;
	int spare = -1;
	int queue_flag = 0;
	int index = -1;
	// find spare & check
	for (;i < MUTEX_LIST_MAX;i++)
	{
		// nothing here: save spare
		if (MutexList[i].mutexAddr == 0)
		{
			if (spare < 0) spare = i;
			continue;
		}
		// something here: check if in use
		if (MutexList[i].mutexAddr == mutex_addr)
		{
			fprintf(stderr, "[offload_process_mutex_request client#%d]\tmutex addr %p in use, queuing\n", offload_client_idx, mutex_addr);
			queue_flag = 1;
			index = i;
		}
	}


	// 1st to request, add mutex, verified
	if (queue_flag == 0)
	{
		if (spare < 0)
		{
			fprintf(stderr, "[offload_process_mutex_request client#%d]\tmutex full\n", offload_client_idx);
			exit(0);
		}
		MutexList[spare].mutexAddr = mutex_addr;
		MutexList[spare].holderId = requestorId;
		offload_send_mutex_verified(requestorId);
	}
	// if it is the same requestor
	else if (MutexList[index].holderId == requestorId)
	{
		offload_send_mutex_verified(requestorId);
		fprintf(stderr, "[offload_process_mutex_request client#%d]\tsame requestor, waking...\n", offload_client_idx);
	}
	// already in use, thus queueflag == 1, queue
	else
	{


		// TODO: mutex锁
		fprintf(stderr, "[offload_process_mutex_request client#%d]\tadd mutex %p\n", offload_client_idx, mutex_addr);

		// pendingList full, should not happen
		int tail = MutexList[index].tail;
		int head = MutexList[index].head;
		if (MutexList[index].hasPending && (tail == head))
		{
			int j = 0;

			for (;j<WORKER_COUNT; j++)
			{
				fprintf(stderr, "%d\n", MutexList[index].pendingList[j]);
			}
			fprintf(stderr, "[offload_process_mutex_request client#%d]\t mutex %p !!MORE THAN WOEKER_COUNT!!\n", offload_client_idx, mutex_addr);
			exit(0);
		}
		// queue
		MutexList[index].pendingList[tail] = requestorId;
		MutexList[index].hasPending = 1;
		MutexList[index].tail = (tail + 1) % WORKER_COUNT;

		//debug
		// for (;head != tail; head++)
		// {
		//	fprintf(stderr, "pending: %d\n", MutexList[index].pendingList[head]);
		//	head %= WORKER_COUNT;
		// }
	}
	offload_show_mutex_list();
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

	/*uint32_t got_flag = *(uint32_t *)p;
	p += sizeof(uint32_t);*/
	fprintf(stderr, "[offload_process_page_request client#%d]\trequested address: %x, perm: %d\n", offload_client_idx, page_addr, perm);
	offload_client_fetch_page(offload_client_idx, page_addr, perm);
	int prefetch_count = prefetch_handler(page_addr, offload_client_idx);
	if (prefetch_count > 0) {
		fprintf(stderr, "[offload_process_page_request client#%d]\tPrefetching for next %d pages\n", offload_client_idx, prefetch_count);
		for (int i = 0; i < prefetch_count; i++) {
			offload_client_fetch_page(offload_client_idx, page_addr + (i+1)*PAGE_SIZE, perm);
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

/*
int try_recv(int size)
{
	int res;
	int sum = 0;
	int is_first = 1;
	//offload_log(stderr, "[try_recv]\treceiving\n");

	while (1)
	{
		//offload_log(stderr, "[try_recv]\treceiving\n");
		res = recv(skt[offload_client_idx], net_buffer + sum, size - sum, 0);
		//offload_log(stderr, "[try_recv]\treceiving done, calculating\n");
		sum += res;
		if (res == 0)
		{
			// connection closed
			offload_log(stderr, "[try_recv]\tconnection closed\n");
			
			exit(0);
			return -2;
		}
		else if (res < 0)
		{
			// error:
			if (errno == EAGAIN || errno == EWOULDBLOCK)
			{

				if (is_first == 1)
				{
					// no packet availiable, return
					return 0;
				}
				else
				{
					// though we didn't see the rest of the packet, but we've already received parts of it, we have to wait and finish receiving entirely.
					continue;
				}
			}
			else
			{
				// other erors that we wouldn't like to see:
				offload_log(stderr, "[try_recv]\terror#%d\n", errno);
				exit(0);
			}

		}
		else
		{
			// got something

			if (sum == size)
			{
				// wish fulfilled:
				return size;
			}
			else if (sum < size)
			{
				// haven't got the whole packet yet, have to recv again:
				offload_log(stderr, "[try_recv]\tsum: %d, size: %d, continuing...\n", sum, size);
				continue;
			}
			else
			{
				// could this be happening?
				offload_log(stderr, "[try_recv]\trecv more than expected\n");
				exit(0);
			}
		}
	}

}
*/
static void offload_client_routine(void)
{



	//forward_page_request();

	//send_page_result();
}

void* offload_client_daemonize(void)
{
	offload_mode = 2;
	int res;
	last_flag_recv = 1;
	last_flag_pending = 1;
	last_flag_lock = 1;
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

				case TAG_OFFLOAD_FUTEX_WAIT_REQUEST:
					fprintf(stderr, "[offload_client_daemonize]\ttag: futex wait request\n");
					try_recv(tcp_header->size);
					offload_client_process_futex_wait_request();
					break;

				case TAG_OFFLOAD_FUTEX_WAKE_REQUEST:
					fprintf(stderr, "[offload_client_daemonize]\ttag: futex wake request\n");
					try_recv(tcp_header->size);
					offload_client_process_futex_wake_request();
					break;

				case TAG_OFFLOAD_CMPXCHG_REQUEST:
					fprintf(stderr, "[offload_client_daemonize]\ttag: cmpxchg request\n");
					try_recv(tcp_header->size);
					offload_process_mutex_request();
					break;

				case TAG_OFFLOAD_CMPXCHG_VERYFIED:
					fprintf(stderr, "[offload_client_daemonize]\ttag: cmpxchg verified\n");
					try_recv(tcp_header->size);
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


		if (has_pending_request == 1)
		{
			fprintf(stderr, "[offload_client_daemonize]\thas pending request\n");



			last_flag_pending = 1;
			target_ulong addr = pending_request.addr;
			int perm = pending_request.perm;
			int requestor = pending_request.requestor;

			offload_client_fetch_page(requestor, addr, perm);
			offload_log(stderr, "[offload_client_daemonize]\tdealt pending request\n");
			has_pending_request = 0;

			if (requestor == -1)
			{
				// will not happen
				exit(0);
				// futex
				offload_log(stderr, "[offload_client_daemonize]\tpending request is a futex request\n");
				int index = addr >> MAP_PAGE_BITS;
				int index1 = (index >> L1_MAP_TABLE_SHIFT) & (L1_MAP_TABLE_SIZE - 1);
				int index2 = index & (L2_MAP_TABLE_SIZE - 1);
				PageMapDesc *pmd = &page_map_table[index1][index2];
				pthread_mutex_lock(&pmd->recv_mutex);
				while (pmd->invalid_count != 0)
				{
					pthread_cond_wait(&pmd->recv_mutex, &pmd->recv_cond);
				}
				pthread_mutex_unlock(&pmd->recv_mutex);

				int ret = offload_client_futex_wake(pending_request.uaddr,
					pending_request.op, pending_request.val,
					pending_request.timeout, pending_request.uaddr2,
					pending_request.val3);
				offload_client_futex_epilogue(PAGE_OF(addr));
				offload_client_send_futex_wake_result(ret);
			}
			else if (requestor >= 0)
			{
				// a page request
				offload_log(stderr, "[offload_client_daemonize]\tpending request is a page request\n");
			}




		}
		else
		{
			// if (last_flag_pending == 1)
			// {
			//	fprintf(stderr, "[offload_client_daemonize]\tno pending request\n");
			// }

			last_flag_pending = 0;
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

	offload_client_init();
	pthread_mutex_lock(&offload_center_init_mutex);
	pthread_cond_signal(&offload_center_init_cond);
	pthread_mutex_unlock(&offload_center_init_mutex);
	offload_client_daemonize();
	close_network();
	return NULL;
}

static void futex_table_add(uint32_t futex_addr, int idx)
{
	fprintf(stderr, "[futex_table_add]\tadding futex_addr = %p, idx = %d\n", futex_addr, idx);

	print_futex_table();
	struct Node * p = (struct Node*)malloc(sizeof(struct Node));
	memset(p, 0, sizeof(struct Node));
	p->val = idx;
	int i = 0;
	fprintf(stderr, "[futex_table_add]\ttest point1\n");
	// find a
	while ((futex_table[i].isInUse) && (futex_table[i].futex_addr != futex_addr))
	{
		i++;
		if (i == 10)
		{
			fprintf(stderr, "[futex_table_add]\tFatal error: futex_table full! Please add more space.\n");
			exit(-1);
		}
	}
	fprintf(stderr, "[futex_table_add]\ttest point2\n");
	// make sure list is not full

	fprintf(stderr, "[futex_table_add]\ttest point3\n");
	// insert
	if (futex_table[i].isInUse != 1)
	{
		futex_table[i].isInUse = 1;
		futex_table[i].futex_addr = futex_addr;
		fprintf(stderr, "[futex_table_add]\ttest point3.1\n");
		futex_table[i].head = p;
		fprintf(stderr, "[futex_table_add]\ttest point3.11\n");
	}
	else
	{
		p->next = futex_table[i].head;
		fprintf(stderr, "[futex_table_add]\ttest point3.2\n");
		futex_table[i].head = p;
		fprintf(stderr, "[futex_table_add]\ttest point3.21\n");
	}

	// wakeup all??
	print_futex_table();
}

static void print_futex_table()
{
	fprintf(stderr, "[print_futex_table]\tshowing futex table...\n");
	int i = 0;
	char buf[1024];
	char tmp[200];
	struct futex_record * p;
	struct Node * pnode;
	for (; i < 10; i++)
	{
		p = &futex_table[i];
		//fprintf(stderr, "[print_futex_table]\ttest point1\n");
		sprintf(tmp, "\n[%d]futex_addr: %p, isInUse: %d", i, p->futex_addr, p->isInUse);
		strcat(buf, tmp);
		//fprintf(stderr, "[print_futex_table]\ttest point2\n");
		if (p->isInUse)
		{
			fprintf(stderr, "[print_futex_table]\ttest point3, head= %p\n", p->head);
			pnode = p->head;
			//fprintf(stderr, "[print_futex_table]\ttest point3.1, val = %d, next\n", pnode->val);
			while (pnode)
			{
				sprintf(tmp, "  %d", pnode->val);
				strcat(buf, tmp);
				pnode = pnode->next;
			}
			//fprintf(stderr, "[print_futex_table]\ttest point4\n");
		}
		strcat(buf, "\n");
	}
	fprintf(stderr, "[print_futex_table]\tshowing futex table%s", buf);

}

static void futex_table_wake(uint32_t futex_addr, int num, int idx)
{
	if ((num < INT_MAX) && (num > 1))
	{
		fprintf(stderr, "[futex_table_wake]\tnum < INT_MAX and >1 not implemented!\n");
		exit(-1);
	}
	fprintf(stderr, "[futex_table_wake]\tWaking up futex on %p, num = %d\n", futex_addr, num);
	print_futex_table();
	//TODO num<int_max
	int i = 0;
	struct futex_record * pr = futex_table;
	// find the record
	fprintf(stderr, "[futex_table_wake]\ttest point1\n");
	while (pr->futex_addr != futex_addr || pr->isInUse == 0)
	{
		i++;
		pr = &futex_table[i];
		if (i == 10)
		{
			fprintf(stderr, "[futex_table_wake]\tfutex doesn't exist.\n");
			offload_send_syscall_result(idx, 0);
			return;
		}
	}
	// may not exist!!
	fprintf(stderr, "[futex_table_wake]\ttest point2\n");

	// wake up all servers
	fprintf(stderr, "[futex_table_wake]\tfound futex record %d matched\n", i);
	struct Node *pnode = pr->head, *tmp;
	int count = 0;
	while (pnode)
	{
		fprintf(stderr, "[futex_table_wake]\ttest point3.1\n");
		fprintf(stderr, "[futex_table_wake]\ttest point3.1, pnode = %p\n", pnode);
		fprintf(stderr, "[futex_table_wake]\ttest point3.1, pnode->val = %p\n", pnode->val);
		offload_send_syscall_result(pnode->val, 0);
		fprintf(stderr, "[futex_table_wake]\ttest point3.11\n");
		tmp = pnode;
		fprintf(stderr, "[futex_table_wake]\ttest point3.12\n");
		pnode = pnode->next;
		fprintf(stderr, "[futex_table_wake]\ttest point3.2\n");
		free(tmp);
		fprintf(stderr, "[futex_table_wake]\ttest point3.3\n");
		count++;
		if (--num == 0) break;
	}
	fprintf(stderr, "[futex_table_wake]\ttest point4\n");
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
	offload_send_syscall_result(idx, count);
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
		fprintf(stderr, "[syscall_daemonize]\tprocessing passed syscall from %d, arg1: %p, arg2:%p, arg3:%p\n", idx, arg1, arg2, arg3);
		extern void print_syscall(int num,
				abi_long arg1, abi_long arg2, abi_long arg3,
				abi_long arg4, abi_long arg5, abi_long arg6);
		print_syscall(num,
				arg1, arg2, arg3,
				arg4, arg5, arg6);
		fprintf(stderr, "[syscall_daemonize]\teabi:%p\n",((CPUARMState *)cpu_env)->eabi);
		//futex mark
		// futex wait
		if ((num == TARGET_NR_futex)
			&& ((arg2 == (FUTEX_PRIVATE_FLAG|FUTEX_WAIT)) || (arg2 == FUTEX_WAIT)))
		{
			fprintf(stderr, "[syscall_daemonize]\treceived FUTEX_PRIVATE_FLAG|FUTEX_WAIT\n");
			void* futex_addr = arg1;
			int cmpval = arg3;
			fprintf(stderr, "[syscall_daemonize]\tfetching\n");
			if (*(int*)(g2h(futex_addr)) == cmpval)
			{
				fprintf(stderr, "[syscall_daemonize]\t*(int*)(futex_addr) == cmpval, adding to futex table\n");
				futex_table_add(futex_addr, idx);
			}
			else
			{
				fprintf(stderr, "[syscall_daemonize]\t*(int*)(futex_addr)== != cmpval, ignoring...\n");
				offload_send_syscall_result(idx, 0);
			}
		}// futex_wake
		else if ((num == TARGET_NR_futex)
			&& ((arg2 == (FUTEX_PRIVATE_FLAG|FUTEX_WAKE)) || (arg2 == FUTEX_WAKE)))
		{
			fprintf(stderr, "[syscall_daemonize]\treceived FUTEX_PRIVATE_FLAG|FUTEX_WAKE, %p, %p, %d, arg8: %d\n", FUTEX_PRIVATE_FLAG|FUTEX_WAKE, arg2, arg2 == 0x81?1:0, arg8);
			uint32_t futex_addr = arg1;
			int wakeup_num = arg3;
			int isChildEnd = arg8;
			if (isChildEnd == 1)
			{
				fprintf(stderr, "[syscall_daemonize]\tChild End!\n");
				*(int*)g2h(futex_addr) = 0;
			}
			futex_table_wake(futex_addr, wakeup_num, idx);
		}
		else
		{
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
			offload_send_syscall_result(idx, ret);
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

void offload_client_start(CPUArchState *the_env)
{

	offload_mode = 2;

	p = BUFFER_PAYLOAD_P;

	//pthread_mutex_init(&page_request_map_mutex[offload_client_idx], NULL);


	fprintf(stderr, "[offload_client_start]\tinitialize\n");
	offload_client_init();


	int res;




	client_env = the_env;
	//pthread_mutex_lock(&clone_syscall_mutex);
	offload_send_start();
	//pthread_mutex_unlock(&clone_syscall_mutex);
	//pthread_t syscall_daemonize_thread;
	//pthread_create(&syscall_daemonize_thread, NULL, syscall_daemonize, NULL);
	//pthread_t daemonize;
	//pthread_create(&daemonize,NULL,offload_client_daemonize,NULL);

	/* send server its tid */
	/*
	CPUState *cpu = ENV_GET_CPU((CPUArchState *)the_env);
	TaskState *ts;
	ts = cpu->opaque;
	fprintf(stderr,"[offload_client_start]\tsending child_tidptr: %p\n", ts->child_tidptr);
	*/
	//offload_send_tid(offload_client_idx, ts->child_tidptr);



	return;
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
	//offload_client_init();

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


/*
int client_segfault_handler(int host_signum, siginfo_t *pinfo, void *puc)
{
	siginfo_t *info = pinfo;
	ucontext_t *uc = (ucontext_t *)puc;
	unsigned long host_addr = (unsigned long)info->si_addr;
	//TODO ... do h2g on the host_addr to get the address of the segfault

	unsigned long  guest_addr = h2g(host_addr);

	//fprintf(stderr, "host adr: %p, guest adr: %p\n", host_addr, guest_addr);

	target_ulong guest_page = guest_addr & TARGET_PAGE_MASK;
	//fprintf(stderr, "Accessed guest addr %lx\n", guest_addr);
	fprintf(stderr, "[client]\tpage fault on %x\n", guest_addr);

	if (guest_page == got_page){
		fprintf(stderr, "Accessed .got or .data address %lx\n", guest_addr);
	}


	int is_write = ((uc->uc_mcontext.gregs[REG_ERR] & 0x2) != 0);



	if (guest_page == 0) {
		fprintf(stderr, "Something is wrong, page addr is 0!\n");
		//sleep(20);
	}
	page_recv_flag = 0;
	offload_fetch_page(guest_page, is_write + 1);
	pthread_mutex_lock(&page_recv_mutex);
	while (page_recv_flag == 0)
	{
		pthread_cond_wait(&page_recv_cond, &page_recv_mutex);
	}
	pthread_mutex_unlock(&page_recv_mutex);



	return 1;
}
*/

static void offload_send_page_request(int idx, target_ulong page_addr, uint32_t perm, int forwho)
{

	//pthread_mutex_lock(&socket_mutex);
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
__thread char buf[TARGET_PAGE_SIZE * 2];

static void offload_send_page_content(int idx, target_ulong page_addr, uint32_t perm, char *content)
{
	//pthread_mutex_lock(&socket_mutex);
	//char buf[TARGET_PAGE_SIZE * 2];
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
	//pthread_mutex_unlock(&socket_mutex);
}

// get the imformation of mutex-done sender and remove it from MutexList
static void offload_process_mutex_done(void)
{

	p = net_buffer;
	uint32_t mutex_addr = *(uint32_t *) p;
	p += sizeof(uint32_t);
	uint32_t doneId = *(uint32_t *)p;
	p += sizeof(uint32_t);
	fprintf(stderr, "[offload_process_mutex_done]\tmutex done signal %p from #%d\n", mutex_addr, doneId);
	int i = 0;
	while ((i<MUTEX_LIST_MAX) && (MutexList[i].mutexAddr != mutex_addr)) i++;
	if (i == MUTEX_LIST_MAX)
	{
		fprintf(stderr, "[offload_process_mutex_done]\tONE NOT EXISTING MUTEX DONE\n");
		return;
	}
	// the last one, clear mutex
	if (!MutexList[i].hasPending)
	{
		MutexList[i].mutexAddr = 0;
		MutexList[i].head = 0;
		MutexList[i].tail = 0;
		fprintf(stderr, "[offload_process_mutex_done]\tmutex %p from #%d removed\n", mutex_addr, doneId);
		offload_show_mutex_list();
		return;
	}
	// wake up next one in the pending list

	uint32_t nextOne = MutexList[i].pendingList[MutexList[i].head];
	MutexList[i].head++;
	MutexList[i].head %= WORKER_COUNT;
	MutexList[i].holderId = nextOne;
	// head == tail, list free
	if (MutexList[i].head == MutexList[i].tail)
	{
		MutexList[i].hasPending = 0;
		fprintf(stderr, "[offload_process_mutex_done]\tmutex %p from #%d removed, pending list free!\n", mutex_addr, doneId);
	}
	// tell the nextOne
	fprintf(stderr, "[offload_process_mutex_done]\tmutex %p from #%d, next one is: %d\n", mutex_addr, doneId, nextOne);

	offload_send_mutex_verified(nextOne);
	//pthread_mutex_unlock(&socket_mutex);
	offload_show_mutex_list();
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

	int index = page_addr >> MAP_PAGE_BITS;
	int index1 = (index >> L1_MAP_TABLE_SHIFT) & (L1_MAP_TABLE_SIZE - 1);
	int index2 = index & (L2_MAP_TABLE_SIZE - 1);
	PageMapDesc *pmd = &page_map_table[index1][index2];

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

	//print_holder(0xffe00000);
	pmd->mutex_count--;
	fprintf(stderr, "[offload_process_page_ack]\tunlocking...%p\n", &pmd->owner_set_mutex);
	pthread_mutex_unlock(&pmd->owner_set_mutex);

	offload_log(stderr, "[offload_process_page_ack]\tpage %x, unlock, count: %d\n", page_addr, pmd->mutex_count);
	print_holder(page_addr);


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

	int index = page_addr >> MAP_PAGE_BITS;
	int index1 = (index >> L1_MAP_TABLE_SHIFT) & (L1_MAP_TABLE_SIZE - 1);
	int index2 = index & (L2_MAP_TABLE_SIZE - 1);
	PageMapDesc *pmd = &page_map_table[index1][index2];

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

extern int
offload_client_futex_wait(target_ulong uaddr, int op, int val, target_ulong timeout, target_ulong uaddr2, int val3);

extern int
offload_client_futex_wake(target_ulong uaddr, int op, int val, target_ulong timeout, target_ulong uaddr2, int val3);

static void offload_client_process_futex_wait_request()
{
	target_ulong uaddr, uaddr2, timeout;
	int op, val, val3;


	p = BUFFER_PAYLOAD_P;

	uaddr = *((target_ulong *) p);


	offload_log(stderr, "futex uaddr: %x, thread_cpu: %p\n", uaddr, thread_cpu);
	p += sizeof(target_ulong);

	op = *((uint32_t *) p);
	offload_log(stderr, "futex op: %d\n", op);
	p += sizeof(uint32_t);

	val = *((uint32_t *) p);
	p += sizeof(uint32_t);

	timeout = *((target_ulong *) p);
	p += sizeof(target_ulong);

	uaddr2 = *((target_ulong *) p);
	p += sizeof(target_ulong);

	val3 = *((uint32_t *) p);
	p += sizeof(uint32_t);


	target_ulong page_addr = (uaddr >> 12) << 12;

	int ret = offload_client_futex_prelude(page_addr);

	if (ret == 0)	// if the page mutex is successfully locked
	{
		offload_log(stderr, "[offload_client_process_futex_wait_request]\tfutex prelude got the lock, continue\n");
		ret = offload_client_futex_wait(uaddr, op, val, timeout, uaddr2, val3);
		offload_client_futex_epilogue(page_addr);
		offload_client_send_futex_wait_result(ret);
	}
	else if (ret < 0)
	{
		offload_log(stderr, "futex prelude didn't get the lock, pend\n");
		pending_request.uaddr = uaddr;
		pending_request.uaddr2 = uaddr2;
		pending_request.timeout = timeout;
		pending_request.op = op;
		pending_request.val = val;
		pending_request.val3 = val3;
	}

}

static void offload_client_process_futex_wake_request()
{
	target_ulong uaddr, uaddr2, timeout;
	int op, val, val3;


	p = BUFFER_PAYLOAD_P;

	uaddr = *((target_ulong *) p);

	p += sizeof(target_ulong);

	op = *((uint32_t *) p);
	p += sizeof(uint32_t);

	val = *((uint32_t *) p);
	p += sizeof(uint32_t);

	timeout = *((target_ulong *) p);
	p += sizeof(target_ulong);

	uaddr2 = *((target_ulong *) p);
	p += sizeof(target_ulong);

	val3 = *((uint32_t *) p);
	p += sizeof(uint32_t);


	target_ulong page_addr = (uaddr >> 12) << 12;

	int ret;

	ret = offload_client_futex_prelude(page_addr);

	if (ret == 0)
	{

		offload_log(stderr, "[offload_client_process_futex_wake_request]\tfutex prelude got the lock, continue\n");
		ret = offload_client_futex_wake(uaddr, op, val, timeout, uaddr2, val3);
		offload_client_futex_epilogue(page_addr);
		offload_client_send_futex_wake_result(ret);
	}
	else if (ret < 0)
	{
		offload_log(stderr, "futex prelude didn't get the lock, pend\n");
		pending_request.uaddr = uaddr;
		pending_request.uaddr2 = uaddr2;
		pending_request.timeout = timeout;
		pending_request.op = op;
		pending_request.val = val;
		pending_request.val3 = val3;
	}
}

static void offload_client_send_futex_wait_result(int result)
{
	p = BUFFER_PAYLOAD_P;

	*((int *) p) = result;
	p += sizeof(int);


	struct tcp_msg_header *tcp_header = (struct tcp_msg_header *)net_buffer;
	fill_tcp_header(tcp_header, p - net_buffer - sizeof(struct tcp_msg_header), TAG_OFFLOAD_FUTEX_WAIT_RESULT);

	int res = autoSend(offload_client_idx, net_buffer, p - net_buffer, 0);
	if (res < 0)
	{
		fprintf(stderr, "[offload_client_send_futex_wait_result]\tsent futex wait result failed\n");
		exit(0);
	}
	fprintf(stderr, "[offload_client_send_futex_wait_result]\tsent futex wait result\n");
	return;
}

static void offload_client_send_futex_wake_result(int result)
{
	p = BUFFER_PAYLOAD_P;

	*((int *) p) = result;
	p += sizeof(int);


	struct tcp_msg_header *tcp_header = (struct tcp_msg_header *)net_buffer;
	fill_tcp_header(tcp_header, p - net_buffer - sizeof(struct tcp_msg_header), TAG_OFFLOAD_FUTEX_WAKE_RESULT);

	int res = autoSend(offload_client_idx, net_buffer, p - net_buffer, 0);
	if (res < 0)
	{
		fprintf(stderr, "[offload_client_send_futex_wake_result]\tsent futex wake result failed\n");
		exit(0);
	}
	fprintf(stderr, "[offload_client_send_futex_wake_result]\tsent futex wake result\n");
	return;
}

static int offload_client_futex_prelude(target_ulong page_addr)
{
	int index = page_addr >> MAP_PAGE_BITS;
	int index1 = (index >> L1_MAP_TABLE_SHIFT) & (L1_MAP_TABLE_SIZE - 1);
	int index2 = index & (L2_MAP_TABLE_SIZE - 1);
	PageMapDesc *pmd = &page_map_table[index1][index2];
	pmd->recv_flag = 0;
	int ret = offload_client_fetch_page(-1, page_addr, 2);

	if (ret == 0)
	{
		// if the page mutex was successfully locked, request was sent
		// we can wait here.
		pthread_mutex_lock(&pmd->recv_mutex);
		while (pmd->invalid_count != 0)
		{
			pthread_cond_wait(&pmd->recv_mutex, &pmd->recv_cond);
		}
		pthread_mutex_unlock(&pmd->recv_mutex);

		return ret;
	}
	else if (ret < 0)
	{
		// otherwise just return immediately.
		return ret;
	}




}

static void offload_client_futex_epilogue(target_ulong page_addr)
{
	fprintf(stderr, "[offload_client_futex_epilogue]\twhat the hell?\n");
	exit(-1);
	/* epilogue */
	//target_ulong page_addr = (uaddr >> 12) << 12;
	int index = page_addr >> MAP_PAGE_BITS;
	int index1 = (index >> L1_MAP_TABLE_SHIFT) & (L1_MAP_TABLE_SIZE - 1);
	int index2 = index & (L2_MAP_TABLE_SIZE - 1);
	PageMapDesc *pmd = &page_map_table[index1][index2];
	fprintf(stderr, "[offload_client_futex_epilogue]\tunlocking...%p\n", &pmd->owner_set_mutex);
	pthread_mutex_unlock(&pmd->owner_set_mutex);
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

	syscall_global_pointer = syscall_p;
	do_syscall_flag = 1;
    fprintf(stderr,
            "[process_syscall_thread]\t I am thread. processing passed syscall from %d, arg1: %p, arg2:%p, arg3:%p\n",
            idx, arg1, arg2, arg3);

	fprintf(stderr, "[process_syscall_thread]\twaking up &locking syscall_thread\n");
	pthread_cond_signal(&do_syscall_cond);
	fprintf(stderr, "[process_syscall_thread]\texiting mutex\n");
	pthread_mutex_unlock(&do_syscall_mutex);


	fprintf(stderr, "[process_syscall_thread]\twoke up, done.\n");
	/*
	extern void print_syscall(int num,
              abi_long arg1, abi_long arg2, abi_long arg3,
              abi_long arg4, abi_long arg5, abi_long arg6);
	print_syscall(num,
              arg1, arg2, arg3,
              arg4, arg5, arg6);
	fprintf(stderr, "[process_syscall_thread]\teabi:%p\n",((CPUARMState *)cpu_env)->eabi);
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
	offload_send_syscall_result(idx, ret);
	//free(cpu_env);
	*/
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


    fprintf(stderr,
            "[offload_process_syscall_request]\treceived passed syscall to center from %d, arg1: %p, arg2:%p, arg3:%p,CREATING THREAD\n",
            idx, arg1, arg2, arg3);


	pthread_t syscall_thread;
	// if ((num == TARGET_NR_futex)
	// 	&& (arg2 == FUTEX_PRIVATE_FLAG|FUTEX_WAIT))
	// {
	// 	fprintf(stderr, "[offload_process_syscall_request]\treceived FUTEX_PRIVATE_FLAG|FUTEX_WAIT\n");
	// 	//exit(-2);
	// 	//return;
	// 	//TODO futex



	// }
	// if ((num == TARGET_NR_futex)
	// 	&& (arg2 == FUTEX_PRIVATE_FLAG|FUTEX_WAKE))
	// {
	// 	fprintf(stderr, "[offload_process_syscall_request]\treceived FUTEX_PRIVATE_FLAG|FUTEX_WAKE %p\n", FUTEX_PRIVATE_FLAG|FUTEX_WAKE);

	// }
	// if ((num == TARGET_NR_futex)
	// 	&& (arg2 == FUTEX_PRIVATE_FLAG|FUTEX_WAKE))
	// {
	// 	fprintf(stderr, "[offload_process_syscall_request]\treceived futex_WAKE!!!, ignore...\n");
	// 	exit(1);
	// 	return;
	// }
	pthread_create(&syscall_thread,NULL,process_syscall_thread,(void*)syscall_p);
	/*
	fprintf(stderr, "[process_syscall_thread]\tprocessing passed syscall from %d, arg1: %p, arg2:%p, arg3:%p\n", idx, arg1, arg2, arg3);
	extern void print_syscall(int num,
              abi_long arg1, abi_long arg2, abi_long arg3,
              abi_long arg4, abi_long arg5, abi_long arg6);
	print_syscall(num,
              arg1, arg2, arg3,
              arg4, arg5, arg6);
	fprintf(stderr, "[process_syscall_thread]\teabi:%p\n",((CPUARMState *)env)->eabi);
	extern abi_long do_syscall(void *cpu_env, int num, abi_long arg1,
                    abi_long arg2, abi_long arg3, abi_long arg4,
                    abi_long arg5, abi_long arg6, abi_long arg7,
                    abi_long arg8);
	abi_long ret = do_syscall(env,
				num,
				arg1,
				arg2,
				arg3,
				arg4,
				arg5,
				arg6,
				0, 0);
	offload_send_syscall_result(idx, ret);
	*/
	//pthread_mutex_unlock(&socket_mutex);
	//offload_show_mutex_list();
}

static void offload_send_syscall_result(int idx, abi_long result)
{
	fprintf(stderr, "[offload_send_syscall_result]\tsending syscall result to #%d with ret=%p\n", idx, result);
	char buf[TARGET_PAGE_SIZE * 2];
	char *pp = buf + sizeof(struct tcp_msg_header);
	*((abi_long*)pp) = result;
	pp += sizeof(abi_long);
	struct tcp_msg_header *tcp_header = (struct tcp_msg_header *)buf;
	fill_tcp_header(tcp_header, pp - buf - sizeof(struct tcp_msg_header), TAG_OFFLOAD_SYSCALL_RES);
	autoSend(idx, buf, pp - buf, 0);
    fprintf(stderr, "[offload_send_syscall_result]\tsent syscall result to #%d packet#%d with ret=%p\n", idx,
            get_number(), result);
}

static void show_prefetch_list(int idx)
{
	fprintf(stderr, "[show_prefetch_list]\tShowing for %d\n", idx);
    struct pgft_record *p = &prefetch_table[idx];	//pagefault node
	while (p) {
		fprintf(stderr, "page_addr %p\t|life %d\t|wait_addr %p\t|wait_hit_count %d\t|page_hit_count %d\t|pref_count %d|\n",
				p->page_addr, p->life, p->wait_addr, p->wait_hit_count, p->page_hit_count, p->pref_count);
		p = p->next;
	}
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
    // search **all** for wait_addr and dec others' life
    while (p)
	{
		// Hit page_addr, regard it as conflict page
		if (p->page_addr == page_addr) {
			p->life += PREFETCH_LIFE;
			if (++p->page_hit_count >= 10) {
				fprintf(stderr, "[prefetch_handler]\tConflict page %p found! Not implemented!\n", page_addr);
			}
			pre = p;
			p = p->next;
			return 0;
		}
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
		if (p->wait_hit_count < 4)  				// not started
        {
			p->wait_addr = page_addr + PAGE_SIZE;		// wait at next page
            p->life = PREFETCH_LIFE;
        } 
		else {    // >=4 , launched
			if (p->pref_count == 0) p->pref_count = 100;
            else  p->pref_count *= 2;
			ret = p->pref_count;
			/* wait at next page */
            p->wait_addr = page_addr + (p->pref_count + 1)*PAGE_SIZE;
            fprintf(stderr, "[prefetch_handler]\tPrefetching for %p for %d pages, waiting at %p\n", page_addr, p->pref_count, p->wait_addr);
		}

	}
	else {		// add new node
        fprintf(stderr, "[prefetch_handler]\tAdd new node %p!\n", page_addr);
		p = (struct pgft_record*)malloc(sizeof(struct pgft_record));
		memset(p, 0, sizeof(struct pgft_record));
		p->page_addr = page_addr;
		p->life = PREFETCH_LIFE;
		p->wait_addr = page_addr + PAGE_SIZE;
		pre->next = p;
        fprintf(stderr, "[prefetch_handler]\tAdded new node %p!\n", page_addr);
	}
	show_prefetch_list(idx);
	return ret;
}
