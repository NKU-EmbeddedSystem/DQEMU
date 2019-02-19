
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
int sktfd;
int client_socket;
extern int offload_server_idx;
static char net_buffer[NET_BUFFER_SIZE];
static pthread_mutex_t socket_mutex;
#define BUFFER_PAYLOAD_P (net_buffer + TCP_HEADER_SIZE)

extern CPUArchState *env;
uint32_t stack_end, stack_start;

static void offload_server_init(void);
static void offload_server_daemonize(void);
static void offload_process_start(void);
static void load_cpu(void);
static void load_binary(void);
static void load_brk(void);
static void load_memory_region(void);
static void* exec_func(void *arg);

static void offload_send_page_request(target_ulong page_addr, uint32_t perm);
static void offload_process_page_request(void);
static void offload_process_page_content(void);
static void offload_send_page_content(target_ulong page_addr, uint32_t perm);
static void offload_send_page_ack(target_ulong page_addr, uint32_t perm);
int offload_segfault_handler(int host_signum, siginfo_t *pinfo, void *puc);
static void offload_process_page_perm(void);
void offload_server_start(void);
void* offload_center_server_start(void*);
static void try_recv(int length);

extern void offload_server_qemu_init(void);
// used along with pthread_cond, indicate whether the page required by the execution thread is received.
static int page_recv_flag; static pthread_mutex_t page_recv_mutex; static pthread_cond_t page_recv_cond;

static uint32_t get_tag(void)
{
	struct tcp_msg_header tmh = *((struct tcp_msg_header *) net_buffer);
	
	return tmh.tag;
}

static uint32_t get_size(void)
{
	struct tcp_msg_header tmh = *((struct tcp_msg_header *) net_buffer);
	return tmh.size;
}

static void offload_server_init(void)
{
	fprintf(stderr, "[offload_server_init]\tindex: %d\n", offload_server_idx);
	sktfd = socket(AF_INET,SOCK_STREAM, 0);
	struct sockaddr_in sockaddr;
	sockaddr.sin_family = AF_INET;
	sockaddr.sin_port = htons(server_port_of(offload_server_idx));
	

	sockaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
	pthread_mutex_init(&socket_mutex, NULL);
	int tmp = 1;
	setsockopt(sktfd, SOL_SOCKET, SO_REUSEADDR, &tmp, sizeof(tmp));
	if(bind(sktfd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) == -1)
	{
		fprintf(stderr, "[offload_server_init]\tbind socket failed, at port# %d, errno:%d\n", server_port_of(offload_server_idx), errno);
		exit(0);
	}
	
	fprintf(stderr, "[offload_server_init]\tbind socket, port# %d\n", server_port_of(offload_server_idx));
	listen(sktfd, 100);
	pthread_mutex_init(&page_recv_mutex, NULL);
	pthread_cond_init(&page_recv_cond, NULL);
	
}

static void load_cpu(void)
{
	// copy the CPU struct
	
	
	//memcpy(env, p, sizeof(CPUARMState));
	*((CPUARMState *) env) = *((CPUARMState *) p);
	p += sizeof(CPUARMState);

	/*vfp_set_fpscr(env, *((uint32_t*) p));
	fprintf(stderr, "fpscr: %d\n", *((uint32_t*) p));
	p += sizeof(uint32_t);
	
    //env->cp15.tpidrro_el0 = client_regs[1] & 0xffffffff;
    env->cp15.tpidrro_el[0] = *((uint64_t*) p);
	fprintf(stderr, "cp15: %ld\n", *((uint64_t*) p));
	p += sizeof(uint64_t);
	
    //cpsr_write(env, client_regs[2], 0xffffffff);	
    cpsr_write(env, *((uint32_t*) p), 0xffffffff);
	fprintf(stderr, "cpsr: %d\n", *((uint32_t*) p));
	p += sizeof(uint32_t);
	
	
	memcpy(env->vfp.regs, p, sizeof(env->vfp.regs));
	p +=  sizeof(env->vfp.regs);
	
	memcpy(env->regs, p, sizeof(env->regs));
	p +=  sizeof(env->regs);
	fprintf(stderr, "pc: %x\n",env->regs[15]);*/

	fprintf(stderr, "[load_cpu server#%d]\tr0: %d\n", offload_server_idx, env->regs[0]);
}

static void load_memory_region(void)
{
	// map the memory region:
	
	
	uint32_t num = *(uint32_t *)p;
    p += sizeof(uint32_t);
	fprintf(stderr, "[server]\tmemory region of 0%d\n", num);
	
	
	
    if (num != 0) 
	{
        target_ulong heap_end = *(target_ulong *)p;
        p += sizeof(target_ulong);

        /* initialize heap end */
		
        target_set_brk(heap_end);
		
        stack_start = *(target_ulong *)p;
        p += sizeof(target_ulong);

        stack_end = *(target_ulong *)p;
        p += sizeof(target_ulong);
    }

    for (uint32_t i = 0; i < num; i++) 
	{
        uint32_t addr = *(uint32_t *)p;
        p += sizeof(uint32_t);
        uint32_t page_num = *(uint32_t *)p;
        p += sizeof(uint32_t);
		uint32_t flags = *(uint32_t *)p;
        p += sizeof(uint32_t);
		uint32_t len = *(uint32_t *)p;
        p += sizeof(uint32_t);
        
		fprintf(stderr, "memory region: %x to %x,  host: %x to %x\n", addr, addr + len, g2h(addr), g2h(addr) + len);
		
		
		int ret = target_mmap(addr, page_num * TARGET_PAGE_SIZE, PROT_NONE,
							  MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
		//mprotect(g2h(addr), page_num * TARGET_PAGE_SIZE, PROT_NONE);
    }
}

static void load_brk(void)
{
	// copy the brk
	uint32_t old_brk = *(uint32_t *)p;
    p += sizeof(uint32_t);
    uint32_t current_brk = *(uint32_t *)p;
    p += sizeof(uint32_t);
	
    int target_mmap_return;
    if(old_brk != 0)
	{
		if(current_brk > old_brk)
		{
			target_mmap_return = target_mmap(old_brk, (unsigned int)current_brk - old_brk,
											 PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
			mprotect(g2h(old_brk), (unsigned int)current_brk - old_brk, PROT_NONE);
			if (target_mmap_return != old_brk)
				fprintf(stderr, "target_mmap  failed at start of ProcessOffloadStart, returns %x\n", target_mmap_return);
		}
		else
		{
			int ret = target_munmap(current_brk, (unsigned int) old_brk - current_brk);
			if (ret) 
			{
				fprintf(stderr, "The munmap failed at the start of ProcessOffloadStart : %d \n", ret);
			}
		}
    }
}

static void load_binary(void)
{
	uint32_t binary_start_address, binary_end_address;
	binary_start_address= *(uint32_t *)p;
	p += sizeof(uint32_t);
	binary_end_address= *(uint32_t *)p;
	p += sizeof(uint32_t);
	fprintf(stderr, "[server]\tmap binary from %p to %x\n", binary_start_address, binary_end_address);
	fprintf(stderr, "here: %x %x %x\n", g2h(binary_start_address), g2h(binary_end_address), g2h((env->regs[15])));
	
	mprotect(g2h(binary_start_address), (unsigned int)binary_end_address - binary_start_address, PROT_READ | PROT_WRITE);
	
	memcpy(g2h(binary_start_address), p, (unsigned int)binary_end_address - binary_start_address);
	
	fprintf(stderr, "here: %d\n", *(uint32_t *) g2h(env->regs[15]));
	disas(stderr, g2h(env->regs[15]), 10);

	fprintf(stderr, "code: %x", *((uint32_t *) g2h(0x102fa)));
	mprotect(g2h(binary_start_address), (unsigned int)binary_end_address - binary_start_address, PROT_READ | PROT_WRITE | PROT_EXEC);
	p += (unsigned int)binary_end_address-binary_start_address;
}
static void* exec_func(void *arg)
{
	//pthread_mutex_lock(&socket_mutex);
	offload_server_qemu_init();
	
	
	fprintf(stderr, "guest_base: %x\n", guest_base);
	p = net_buffer;
	fprintf(stderr, "[exec_func]\tin exec func\n");
	load_cpu();
	// copy the start function address
	;
	load_memory_region();
	load_brk();
	load_binary();
	// it's go time!
	//fprintf(stderr, "this address: %x\n", g2h(0x10324));
	fprintf(stderr, "[exec_func]\tready to CPU_LOOP\n");

	fprintf(stderr, "[exec_func]\tPC: %d\n", env->regs[15]);
	
	
	fprintf(stderr, "[exec_func]\tregisters:\n");
	
	for (int i = 0; i < 16; i++)
	{
		fprintf(stderr, "%d\n", env->regs[i]);
	}
	//target_disas(stderr, ENV_GET_CPU(env), env->regs[15], 100);
	//while (1) {;}


	//pthread_mutex_unlock(&socket_mutex);
	cpu_loop(env);

	return NULL;
	 
}

static void offload_process_start(void)
{
	

	pthread_t exec_thread;
	fprintf(stderr, "[server]\tcreate exec thread\n");
	pthread_create(&exec_thread, NULL, exec_func, NULL);
	fprintf(stderr, "[server]\texec thread created\n");
	
	//pthread_join(exec_thread, NULL);
	
}



static void offload_send_page_request(target_ulong page_addr, uint32_t perm)
{
	//pthread_mutex_lock(&socket_mutex);


	fprintf(stderr, ">>>>>>>>> exec# %d guest_base: %x\n", offload_server_idx, guest_base);

	char buf[TARGET_PAGE_SIZE * 2];
	char *pp = buf + sizeof(struct tcp_msg_header);
	

	*((target_ulong *) pp) = page_addr;
    pp += sizeof(target_ulong);
	
	
	
	*((uint32_t *) pp) = perm;
	pp += sizeof(uint32_t);
	
	struct tcp_msg_header *tcp_header = (struct tcp_msg_header *) buf;
	fill_tcp_header(tcp_header, pp - buf - sizeof(struct tcp_msg_header), TAG_OFFLOAD_PAGE_REQUEST);
	int res = send(client_socket, buf, pp - buf, 0);
	if (res < 0)
	{
		fprintf(stderr, "[offload_send_page_request]\tsent page %x request failed\n", page_addr);
		exit(0);
	}
	fprintf(stderr, "[offload_send_page_request]\tsent page %x request, perm: %d, size: %d of (%d + %d = %d)\n", page_addr, perm, res, sizeof(struct tcp_msg_header), tcp_header->size, pp - buf);
	//pthread_mutex_unlock(&socket_mutex);
}


static void offload_process_page_request(void)
{
	//pthread_mutex_lock(&socket_mutex);
	p = net_buffer;
	
	target_ulong page_addr = *((target_ulong *) p);
    p += sizeof(target_ulong);
	
	uint32_t perm = *((uint32_t *) p);
	p += sizeof(uint32_t);
	
	fprintf(stderr, "[offload_process_page_request server#%d]\tpage %x, perm %d\n", offload_server_idx, page_addr, perm);
	offload_send_page_content(page_addr, perm);
	if (perm == 2)
	{
		mprotect(g2h(page_addr), TARGET_PAGE_SIZE, PROT_NONE);
	}
	else if (perm == 1)
	{
		mprotect(g2h(page_addr), TARGET_PAGE_SIZE, PROT_READ);
	}
	//pthread_mutex_unlock(&socket_mutex);
	//pthread_mutex_unlock(&socket_mutex);
	// #todo: if the worker can know that this page is during a perm change from exclusive to shared, 
	// then should he at this moment protect this page with PROT_NONE, or wait till the center sends a PAGE_PERM ?
	// mprotect(g2h(page_addr), TARGET_PAGE_SIZE, PROT_NONE);
}

static void offload_process_page_content(void)
{
	//pthread_mutex_lock(&socket_mutex);
	p = net_buffer;
	
	target_ulong page_addr = *((target_ulong *) p);
    p += sizeof(target_ulong);
	
	uint32_t perm = *((uint32_t *) p);
	p += sizeof(uint32_t);
	fprintf(stderr, "content: %d %d\n", *((uint64_t *) p), *((uint64_t *) p + 555));
	mprotect(g2h(page_addr), TARGET_PAGE_SIZE, PROT_READ | PROT_WRITE);
	memcpy(g2h(page_addr), p, TARGET_PAGE_SIZE);
	p += TARGET_PAGE_SIZE;
	
	
	if (perm == 2)
	{
		mprotect(g2h(page_addr), TARGET_PAGE_SIZE, PROT_READ | PROT_WRITE);
	}
	else if (perm == 1)
	{
		mprotect(g2h(page_addr), TARGET_PAGE_SIZE, PROT_READ);
	}
	fprintf(stderr, "[offload_process_page_content]\tpage %x perm to %d\n", page_addr, perm);
	// wake up the execution thread upon this required page.
	pthread_mutex_lock(&page_recv_mutex);
	page_recv_flag = 1;
	pthread_cond_signal(&page_recv_cond);
	pthread_mutex_unlock(&page_recv_mutex);
	//pthread_mutex_unlock(&socket_mutex);
	offload_send_page_ack(page_addr, perm);

}

static void offload_send_page_content(target_ulong page_addr, uint32_t perm)
{
	//pthread_mutex_lock(&socket_mutex);
	p = BUFFER_PAYLOAD_P;
	
	
	*((target_ulong *) p) = page_addr;
    p += sizeof(target_ulong);

	
	*((uint32_t *) p) = perm;
	p += sizeof(uint32_t);
	//fprintf(stderr, "content: %d %d\n", *((uint64_t *) g2h(page_addr)), *((uint64_t *) g2h(page_addr) + 555));
    memcpy(p, g2h(page_addr), TARGET_PAGE_SIZE);
    p += TARGET_PAGE_SIZE;
	
	struct tcp_msg_header *tcp_header = (struct tcp_msg_header *) net_buffer;
	fill_tcp_header(tcp_header, p - net_buffer - sizeof(struct tcp_msg_header), TAG_OFFLOAD_PAGE_CONTENT);
	
	int res = send(client_socket, net_buffer, p - net_buffer, 0);
	if (res < 0)
	{
		fprintf(stderr, "[offload_send_page_content]\tsent page %x content failed\n", page_addr);
		exit(0);
	}
	fprintf(stderr, "[offload_send_page_content server#%d]\tsent page %x content, perm%d\n", offload_server_idx, page_addr, perm);
	//pthread_mutex_unlock(&socket_mutex);
}



static void offload_send_page_ack(target_ulong page_addr, uint32_t perm)
{
	//pthread_mutex_lock(&socket_mutex);
	p = BUFFER_PAYLOAD_P;
	
	*((target_ulong *) p) = page_addr;
    p += sizeof(target_ulong);
	
	*((uint32_t *) p) = perm;
	p += sizeof(uint32_t);
	
	struct tcp_msg_header *tcp_header = (struct tcp_msg_header *) net_buffer;
	fill_tcp_header(tcp_header, p - net_buffer - sizeof(struct tcp_msg_header), TAG_OFFLOAD_PAGE_ACK);
	int res = send(client_socket, net_buffer, p - net_buffer, 0);
	if (res < 0)
	{
		fprintf(stderr, "[offload_send_page_ack]\tsent page %x ack failed\n", page_addr);
		exit(0);
	}
	fprintf(stderr, "[offload_send_page_ack]\tsent page %x ack\n", page_addr);
	//pthread_mutex_unlock(&socket_mutex);
}


int offload_segfault_handler(int host_signum, siginfo_t *pinfo, void *puc)
{
    siginfo_t *info = pinfo;
    ucontext_t *uc = (ucontext_t *)puc;
    unsigned long host_addr = (unsigned long)info->si_addr;
    //TODO ... do h2g on the host_addr to get the address of the segfault
	
    unsigned long  guest_addr = h2g(host_addr);
	
	
	
    target_ulong page_addr = guest_addr & TARGET_PAGE_MASK;
    //fprintf(stderr, "Accessed guest addr %lx\n", guest_addr);
	
    //fprintf(stderr, "\nHost instruction address is %p\n", uc->uc_mcontext.gregs[REG_RIP]);


    int is_write = ((uc->uc_mcontext.gregs[REG_ERR] & 0x2) != 0);
    
	fprintf(stderr, "[offload_segfault_handler]\tsegfault on page addr: %x, is_write: %d\n", page_addr, is_write);
	//get_client_page(is_write, guest_page);
	
	// send the page request, then sleep until the content is sent back.
	page_recv_flag = 0;
	offload_send_page_request(page_addr, is_write + 1); // easy way to convert is_write to perm
	fprintf(stderr, "[offload_segfault_handler]\tsent page request %x, wait\n", page_addr);
	pthread_mutex_lock(&page_recv_mutex);
	while (page_recv_flag == 0)
	{
		pthread_cond_wait(&page_recv_cond, &page_recv_mutex);
	}
	pthread_mutex_unlock(&page_recv_mutex);
	
	fprintf(stderr, "[offload_segfault_handler]\tawake\n");


	
    return 1;
}


static void offload_process_page_perm(void)
{
	//pthread_mutex_lock(&socket_mutex);
	p = net_buffer;
	
	target_ulong page_addr = *((target_ulong *) p);
    p += sizeof(target_ulong);
	
	uint32_t perm = *((uint32_t *) p);
	p += sizeof(uint32_t);
	
	if (perm == 1)
	{
		mprotect(g2h(page_addr), TARGET_PAGE_SIZE, PROT_READ);
	}
	else if (perm == 2)
	{
		mprotect(g2h(page_addr), TARGET_PAGE_SIZE, PROT_READ | PROT_WRITE);
	}
	else if (perm == 0)
	{
		mprotect(g2h(page_addr), TARGET_PAGE_SIZE, PROT_NONE);
	}
	fprintf(stderr, "[offload_process_page_perm]\tpage %x perm to %d\n", page_addr, perm);
	//pthread_mutex_unlock(&socket_mutex);
}

static void offload_process_page_upgrade(void)
{
	//pthread_mutex_lock(&socket_mutex);
	p = net_buffer;
	
	target_ulong page_addr = *((target_ulong *) p);
    p += sizeof(target_ulong);
	mprotect(g2h(page_addr), TARGET_PAGE_SIZE, PROT_READ | PROT_WRITE);
	pthread_mutex_lock(&page_recv_mutex);
	page_recv_flag = 1;
	pthread_cond_signal(&page_recv_cond);
	pthread_mutex_unlock(&page_recv_mutex);

	fprintf(stderr, "[offload_process_page_upgrade]\tpage %x upgrade\n", page_addr);
	//pthread_mutex_unlock(&socket_mutex);
}



static void offload_server_daemonize(void)
{
	fprintf(stderr, "[offload_server_daemonize]\tstart to daemonize\n");
	
	fprintf(stderr, ">>>>>>>>>>>> server# %d guest_base: %x\n", offload_server_idx, guest_base);
	struct sockaddr_in client_addr;
	socklen_t client_addr_size = sizeof(client_addr);
	client_socket = accept(sktfd, (struct sockaddr*)&client_addr, &client_addr_size);
	while (1)
	{
		
		/*if (offload_server_idx == 0)
		{
			int res = recv(client_socket, net_buffer, 9999, 0);
			fprintf(stderr, "\nrecv: %d\n", res);
			exit(0);
		}*/
		fprintf(stderr, "[offload_server_daemonize server#%d]\twaiting for new message\n", offload_server_idx);
		
		fprintf(stderr, "count addr: %x\n", g2h(0x7ae34));

		//int res = recv(client_socket, net_buffer, sizeof(struct tcp_msg_header), MSG_WAITALL);
		try_recv(sizeof(struct tcp_msg_header));
		fprintf(stderr, "[offload_server_daemonize server#%d]\tgot a new message\n", offload_server_idx);
		int tag = get_tag();
		int size = get_size();

		fprintf(stderr, "[offload_server_daemonize server#%d]\tsize: %d + %d\n", offload_server_idx, sizeof(struct tcp_msg_header), size);
		switch (tag)
		{
			case TAG_OFFLOAD_START:

				fprintf(stderr, "[offload_server_daemonize]\ttag: offload start size: %d\n", size);
				try_recv(size);
				offload_process_start();
				//fprintf(stderr, "AAAAAAAAAAAAA\n");
				break;
			
			case TAG_OFFLOAD_PAGE_REQUEST:
				fprintf(stderr, "[offload_server_daemonize]\ttag: page request, size: %d\n", size);
				try_recv(size);
				offload_process_page_request();
				break;
			case TAG_OFFLOAD_PAGE_CONTENT:
				fprintf(stderr, "[offload_server_daemonize]\ttag: page content, size: %d\n", size);

				

				try_recv(size);
				offload_process_page_content();
				break;
			
			case TAG_OFFLOAD_PAGE_PERM:
				fprintf(stderr, "[offload_server_daemonize]\ttag: page perm\n");
				try_recv(size);
				offload_process_page_perm();
				break;
			
			case TAG_OFFLOAD_PAGE_UPGRADE:
				fprintf(stderr, "[offload_server_daemonize]\ttag: page upgrade\n");
				try_recv(size);
				offload_process_page_upgrade();
				break;
				
			default:
				fprintf(stderr, "[offload_server_daemonize]\tunkown tag\n");
				exit(0);
				break;
				
		}
	}
}

extern void* offload_center_client_start(void *arg);
void* offload_center_server_start(void *arg)
{
	offload_server_init();
	fprintf(stderr, "center server guest_base: %x\n", guest_base);
	pthread_t offload_center_client_thread;



	pthread_create(&offload_center_client_thread, NULL, offload_center_client_start, NULL);	


	
	offload_server_daemonize();
	return NULL;
}
void offload_server_start(void)
{
	fprintf(stderr, "[offload_server_start]\tstart offload server\n");
	//env = _env;
	offload_server_init();
	offload_server_daemonize();
	
}



static void try_recv(int length)
{

	//fprintf(stderr, "trying recv size of %d, skt: %d\n", length, client_socket);
	int res = recv(client_socket, net_buffer, length, MSG_WAITALL);
	//int res = recv(client_socket, net_buffer, length, 0);
	if (res == length)
	{
		return;
	}
	else if (res < 0)
	{
		fprintf(stderr, "[try_recv]\trecv failed: errno: %d\n", errno);
	}
	else if (res != length)
	{
		fprintf(stderr, "[try_recv]\trecv failed: shorter than expected\n");
	}
	exit(0);
}
