








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


extern __thread int offload_client_idx;
extern abi_ulong target_brk;
extern abi_ulong target_original_brk;
extern int offload_count;
pthread_mutex_t offload_count_mutex = PTHREAD_MUTEX_INITIALIZER;
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








typedef struct PageMapDesc {
    uint32_t oflags;    /* original flags */
    uint32_t flags;     /* current flags */

    /* Used to sync with server */
    int on_server;      /* if this page is on server side */

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


static void close_network(void);

static void dump_cpu(void);

static int dump_self_maps(void);
static void dump_brk(void);
static void dump_code(void);
static void offload_send_start(void);
static void offload_send_page_upgrade(target_ulong page_addr);

static void offload_process_page_request(void);
static void offload_client_daemonize(void);
static void offload_client_send_futex_wake_result(int result);
//int client_segfault_handler(int host_signum, siginfo_t *pinfo, void *puc);

void offload_client_start(CPUArchState *the_env);
void* offload_center_client_start(void*);
static void offload_send_page_request(int idx, target_ulong guest_addr, uint32_t perm);
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
	server_addr.sin_addr.s_addr = inet_addr("127.0.0.1") ;


	bzero(&(server_addr.sin_zero), 8);
	int struct_len = sizeof(struct sockaddr_in);
	//fprintf(stderr, "[client]\toffload index: %d\n", offload_client_idx);
	fprintf(stderr, "[client]\tconnecting to server, port# %d\n", server_port_of(offload_client_idx));
	if (connect(skt[offload_client_idx],(struct sockaddr*) &server_addr, struct_len) == -1)
	{
		fprintf(stderr, "[offload_client_init]\tconnect port# server_port_of(offload_client_idx) failed, errno: %d\n", errno);
		exit(0);
	}

	printf("[client]\tconnecting succeed, client index# %d, skt: %d\n", offload_client_idx, skt[offload_client_idx]);


	fcntl(skt[offload_client_idx], F_SETFL, fcntl(skt[offload_client_idx], F_GETFL) | O_NONBLOCK);
	//struct timeval timeout={1, 0};
    //int ret = setsockopt(skt[offload_client_idx], SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));

	pthread_mutex_init(&page_recv_mutex, NULL);
	pthread_cond_init(&page_recv_cond, NULL);
	has_pending_request = 0;
	#if 0
	uint32_t tmp[1];
	mprotect(g2h(0x10324), TARGET_PAGE_SIZE, PROT_READ);
	cpu_memory_rw_debug(ENV_GET_CPU(client_env), 0x10324, tmp, 4, 1);
	fprintf(stderr, "[0x10324]: %x\n", tmp[0]);


	fprintf(stderr, "valid: %d\n", guest_addr_valid(0x10324));
	fprintf(stderr, "guest base: %d\n", guest_base);

	fprintf(stderr, "%x\n", g2h(0x10324));
	fprintf(stderr, "[0x10324]: %x\n", *((uint32_t *) g2h(0x10324)));
	#endif
	return;
}


static void close_network(void)
{
	// todo: when a worker finished, should he flushes all his pages back to the center?
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
                pstrcpy(path, sizeof(path), "      [stack]");
				*p_stack_start = start;
				*p_stack_end = end;
            }

			section_count ++;

            /*fprintf(fd, TARGET_ABI_FMT_lx "-" TARGET_ABI_FMT_lx
                    " %c%c%c%c %08" PRIx64 " %02x:%02x %d %s%s\n",
                    h2g(min), h2g(max - 1) + 1, flag_r, flag_w,
                    flag_x, flag_p, offset, dev_maj, dev_min, inode,
                    path[0] ? "         " : "", path);*/


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
	*((CPUARMState *) p) = *client_env;



	p += sizeof(CPUARMState);

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

	/*for (int i = 0; i < 2000; i++)
	{
		fprintf(stderr, "%d ", (uint32_t *)(net_buffer + i));
	}*/

	res = send(skt[offload_client_idx], net_buffer, (p - net_buffer), 0);

	//pthread_mutex_unlock(&socket_mutex);
}





//pthread_mutex_t page_request_map1_mutex, page_result_map2_mutex;
pthread_mutex_t page_request_map_mutex;

/* upgrade page permission */
static void offload_send_page_upgrade(target_ulong page_addr)
{
	//pthread_mutex_lock(&socket_mutex);
    p = BUFFER_PAYLOAD_P;

	*((target_ulong *) p) = page_addr;
	p += sizeof(target_ulong);



	struct tcp_msg_header *tcp_header = (struct tcp_msg_header *)net_buffer;
    fill_tcp_header(tcp_header, p - net_buffer - sizeof(struct tcp_msg_header), TAG_OFFLOAD_PAGE_UPGRADE);

	int res;
	if (res = send(skt[offload_client_idx], net_buffer, p - net_buffer, 0) < 0)
	{
		fprintf(stderr, "page upgrade sending failed\n");
	}
	//pthread_mutex_unlock(&socket_mutex);
}

void print_holder(uint32_t page_addr)
{
	int index = page_addr >> PAGE_BITS;
	int index1 = (index >> L1_MAP_TABLE_SHIFT) & (L1_MAP_TABLE_SIZE - 1);
	int index2 = index & (L2_MAP_TABLE_SIZE - 1);

	PageMapDesc *pmd = &page_map_table[index1][index2];
	for (int i = 0; i < pmd->owner_set.size; i++)
	{
		int idx = pmd->owner_set.element[i];

		fprintf(stderr, "holder: %d\n", idx);
	}
}


static int offload_client_fetch_page(int requestor_idx, target_ulong addr, int perm)
{

    target_ulong page_addr = PAGE_OF(addr);

	int index = addr >> PAGE_BITS;
	int index1 = (index >> L1_MAP_TABLE_SHIFT) & (L1_MAP_TABLE_SIZE - 1);
	int index2 = index & (L2_MAP_TABLE_SIZE - 1);
	PageMapDesc *pmd = &page_map_table[index1][index2];
    if (last_flag_lock != 0)
    {
        fprintf(stderr, "[offload_fetch_page]\tfetching page %x, lock\n", page_addr);
    }

	//pthread_mutex_lock(&pmd->owner_set_mutex);
	int res = pthread_mutex_trylock(&pmd->owner_set_mutex);

	if (res != 0)
	{
		
		if (last_flag_lock == 1)
		{
			offload_log(stderr, "[offload_client_fetch_page]\tlock failed, count: %d, holder: %d\n", pmd->mutex_count, pmd->mutex_holder);
		}

		has_pending_request = 1;

        pending_request.requestor = requestor_idx;
        pending_request.addr = addr;
        pending_request.perm = perm;

		/*pending_requestor = requestor_idx;
		pending_request_addr = addr;
		pending_page_request_perm = perm;*/

		last_flag_lock = 0;

        return -1;
	}
	else
	{
		pmd->mutex_holder = requestor_idx;
		pmd->mutex_count++;
		offload_log(stderr, "[offload_client_fetch_page]\tlock succeed, count: %d, holder: %d\n", pmd->mutex_count, pmd->mutex_holder);

		pmd->requestor = requestor_idx;
		if (perm == 2)
		{
			pmd->invalid_count = 0;
			/* invalid_count = the number of sharing copies to invalidate */
			for (int i = 0; i < pmd->owner_set.size; i++)
			{
				int idx = pmd->owner_set.element[i];

				/*if (idx == 0 && requestor_idx == -1)
				{
					continue;
				}*/
				pmd->invalid_count++;
				/* invalidate pages on other threads, retrieve the permission */
				offload_send_page_request(idx, page_addr, 2);
			}
		}
		else if (perm == 1)
		{
			/* revoke page as shared page */
			offload_send_page_request(pmd->owner_set.element[0], page_addr, 1);
		}
		fprintf(stderr, "[offload_client_fetch_page]\t sent\n");
		last_flag_lock = 1;

        return 0;
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
		// 	fprintf(stderr, "pending: %d\n", MutexList[index].pendingList[head]);
		// 	head %= WORKER_COUNT;
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
}

static int try_recv(int size)
{
	int res;
	int sum = 0;
	int is_first = 1;


	while (1)
	{
		res = recv(skt[offload_client_idx], net_buffer + sum, size - sum, 0);
		sum += res;
		if (res == 0)
		{
			// connection closed
			offload_log(stderr, "[try_recv]\tconnection closed\n");
			exit(0);
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

static void offload_client_routine(void)
{



	//forward_page_request();

	//send_page_result();
}

static void offload_client_daemonize(void)
{

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

		if (res == sizeof(struct tcp_msg_header))
		{
			fprintf(stderr, "[offload_client_daemonize]\tgot new message #%d\n", get_number());

			fprintf(stderr, "[offload_client_daemonize]\tthread_cpu: %p\n", thread_cpu);
			last_flag_recv = 1;
			struct tcp_msg_header *tcp_header = (struct tcp_msg_header *)net_buffer;
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

				default:
					fprintf(stderr, "[offload_client_daemonize]\tunknown tag\n");
					exit(0);
					break;

			}
		}//daemonize
		else
		{
			last_flag_recv = 0;
		}


		if (has_pending_request != 0)
		{
			if (last_flag_lock == 1)
			{
				fprintf(stderr, "[offload_client_daemonize]\thas pending request\n");
			}



			last_flag_pending = 1;
			target_ulong addr = pending_request.addr;
			int perm = pending_request.perm;
            int requestor = pending_request.requestor;


			if (has_pending_request == 1)
			{
				offload_client_fetch_page(requestor, addr, perm);
			}

			if (last_flag_lock == 1)
			{
                offload_log(stderr, "[offload_client_daemonize]\tpending request got the lock\n");
				has_pending_request = 0;

                if (requestor == -1)
                {
					exit(0);
                    // futex
                    offload_log(stderr, "[offload_client_daemonize]\tpending request is a futex request\n");
                    int index = addr >> PAGE_BITS;
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
                    offload_log(stderr, "[offload_client_daemonize]\tpending request is a page request\n");
                }
			}



		}
		else
		{
			// if (last_flag_pending == 1)
			// {
			// 	fprintf(stderr, "[offload_client_daemonize]\tno pending request\n");
			// }

			last_flag_pending = 0;
		}
	}
}
extern pthread_mutex_t offload_center_init_mutex; extern pthread_cond_t offload_center_init_cond;


void* offload_center_client_start(void *arg)
{
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

	offload_mode = 2;
	offload_client_init();
	pthread_mutex_lock(&offload_center_init_mutex);
	pthread_cond_signal(&offload_center_init_cond);
	pthread_mutex_unlock(&offload_center_init_mutex);
	offload_client_daemonize();
	close_network();
	return NULL;
}
void offload_client_start(CPUArchState *the_env)
{

	offload_mode = 2;

	p = BUFFER_PAYLOAD_P;

	//pthread_mutex_init(&page_request_map_mutex[offload_client_idx], NULL);


	fprintf(stderr, "[offload_client_start]\tinitialize");
	offload_client_init();


	int res;




	client_env = the_env;
	offload_send_start();

	offload_client_daemonize();

	fprintf(stderr, "[offload_client_start]\tready to close network\n");

	close_network();


	printf("[offload_client_start]\toffloading finished\n");
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

static void offload_send_page_request(int idx, target_ulong page_addr, uint32_t perm)
{

	//pthread_mutex_lock(&socket_mutex);
	p = BUFFER_PAYLOAD_P;

	*((target_ulong *) p) = page_addr;
	p += sizeof(target_ulong);

	*((uint32_t *) p) = perm;
	p += sizeof(uint32_t);



	struct tcp_msg_header *tcp_header = (struct tcp_msg_header *)net_buffer;
    fill_tcp_header(tcp_header, p - net_buffer - sizeof(struct tcp_msg_header), TAG_OFFLOAD_PAGE_REQUEST);

	int res = send(skt[idx], net_buffer, p - net_buffer, 0);
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

	send(skt[idx], buf, pp - buf, 0);

	fprintf(stderr, "[offload_send_page_content]\tsent page content %x, perm %d, packet#%d\n", page_addr, perm, get_number());
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
	send(skt[idx], buf, pp - buf, 0);
	fprintf(stderr, "[offload_send_cmpxchg_verified]\tsent cmpxchg verified to #%d packet#%d\n", idx, get_number());
}

static void offload_process_page_ack(void)
{
	
	//pthread_mutex_lock(&socket_mutex);
    p = net_buffer;



	uint32_t page_addr = *(uint32_t *) p;
    p += sizeof(uint32_t);

	uint32_t perm = *(uint32_t *) p;
	p += sizeof(uint32_t);

	int index = page_addr >> PAGE_BITS;
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


	pthread_mutex_unlock(&pmd->owner_set_mutex);
	pmd->mutex_count--;
	offload_log(stderr, "[offload_process_page_ack]\tpage %x, unlock, count: %d\n", page_addr, pmd->mutex_count);



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

	int res = send(skt[idx], net_buffer, p - net_buffer, 0);
	if (res < 0)
	{
		fprintf(stderr, "[offload_send_page_perm]\tpage %x perm to %d sent failed res: %d errno: %d\n", page_addr, idx, res, errno);
		exit(0);
	}

	return;
}



/*	revoke pages from worker
*	1. READ - simply send page_content
*	2. WRITE - 
			2.1 invalid_count == 1, send page_content
			2.2 idx == -1, for futex using, copy content??? invalid_count --??
*/
static void offload_process_page_content(void)
{
    //fprintf(stderr, "a page response\n");

   // char *payload = net_buffer + sizeof(struct tcp_msg_header);
    p = net_buffer;
    uint32_t page_addr = *(uint32_t *) p;
    p += sizeof(uint32_t);
    //fprintf(stderr, "response address : %lx  \n", page_addr);

	uint32_t perm = *(uint32_t *) p;
	p += sizeof(uint32_t);


	fprintf(stderr, "[offload_process_page_content]\tpage %x, perm %d\n", page_addr, perm);
	int index = page_addr >> PAGE_BITS;
	int index1 = (index >> L1_MAP_TABLE_SHIFT) & (L1_MAP_TABLE_SIZE - 1);
	int index2 = index & (L2_MAP_TABLE_SIZE - 1);
	PageMapDesc *pmd = &page_map_table[index1][index2];

	int requestor_idx = pmd->requestor;
	if (perm == 2)
	{

		if (pmd->invalid_count - 1 == 0)
		{
			/* a normal CONTENT request, -1 for futex */
			if (requestor_idx >= 0)
			{

				offload_send_page_content(requestor_idx, page_addr, perm, p);
                pmd->invalid_count--;
				/*p += TARGET_PAGE_SIZE;
				int res = send(skt[requestor_idx], net_buffer, p - net_buffer, 0);
				if (res < 0)
				{
					fprintf(stderr, "[offload_process_page_content]\tpage %x sending to %d failed res: %d errno: %d\n", page_addr, requestor_idx, res, errno);
					exit(0);
				}*/
			}

			else if (requestor_idx == -1)
			{
				fprintf(stderr, "[offload_process_page_content]\tpage %x, perm %d  WTHE HELL IS happening??\n", page_addr, perm);
				exit(123);
				// this page is requested by a client thread on the center, for futex using.
				mprotect(g2h(page_addr), TARGET_PAGE_SIZE, PROT_READ | PROT_WRITE /* why PROT_SEM  */);
				memcpy(g2h(page_addr), p, TARGET_PAGE_SIZE);
				clear(&pmd->owner_set);
				insert(&pmd->owner_set, 0);


				pthread_mutex_lock(&pmd->recv_mutex);
				pmd->recv_flag = 1;
                pmd->invalid_count--;
				pthread_cond_signal(&pmd->recv_cond);
				pthread_mutex_unlock(&pmd->recv_mutex);

			}

		}
        else
        {
            pmd->invalid_count--;
        }

	}
	else if (perm == 1)
	{
		//fprintf(stderr, "[offload_process_page_content]\tpage %x, perm %d send to server#%d\n", page_addr, perm, requestor_idx);
		/*p += TARGET_PAGE_SIZE;
		int res = send(skt[requestor_idx], net_buffer, p - net_buffer, 0);
		if (res < 0)
		{
			fprintf(stderr, "[offload_process_page_content]\tpage %x sending to %d failed res: %d errno: %d\n", page_addr, requestor_idx, res, errno);
			exit(0);
		}*/
		offload_send_page_content(requestor_idx, page_addr, perm, p);
		//int res = send(skt[requestor_idx], net_buffer, PAGE_SIZE + sizeof(target_ulong) + sizeof(uint32_t), 0);

	}


}

extern int offload_client_futex_wait(target_ulong uaddr, int op, int val, target_ulong timeout, target_ulong uaddr2, int val3);

extern int offload_client_futex_wake(target_ulong uaddr, int op, int val, target_ulong timeout, target_ulong uaddr2, int val3);

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

    if (ret == 0)   // if the page mutex is successfully locked
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

	int res = send(skt[offload_client_idx], net_buffer, p - net_buffer, 0);
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

	int res = send(skt[offload_client_idx], net_buffer, p - net_buffer, 0);
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
	int index = page_addr >> PAGE_BITS;
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
	/* epilogue */
	//target_ulong page_addr = (uaddr >> 12) << 12;
	int index = page_addr >> PAGE_BITS;
	int index1 = (index >> L1_MAP_TABLE_SHIFT) & (L1_MAP_TABLE_SIZE - 1);
	int index2 = index & (L2_MAP_TABLE_SIZE - 1);
	PageMapDesc *pmd = &page_map_table[index1][index2];
	pthread_mutex_unlock(&pmd->owner_set_mutex);
}
