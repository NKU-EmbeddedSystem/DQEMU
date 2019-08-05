

#include "offload_server.h"
extern __thread CPUArchState *thread_env;


// used along with pthread_cond, indicate whether the page required by the execution thread is received.
static int page_recv_flag; static pthread_mutex_t page_recv_mutex; static pthread_cond_t page_recv_cond;
static uint32_t page_recv_addr;
static int page_syscall_recv_flag; static pthread_mutex_t page_syscall_recv_mutex; static pthread_cond_t page_syscall_recv_cond;
static int mutex_ready_flag; static pthread_mutex_t mutex_recv_mutex; static pthread_cond_t mutex_recv_cond;
static int cpu_exit_flag; static pthread_mutex_t exit_recv_mutex; static pthread_cond_t exit_recv_cond;
static int syscall_ready_flag; static pthread_mutex_t syscall_recv_mutex; static pthread_cond_t syscall_recv_cond;
int syscall_clone_done;
pthread_mutex_t syscall_clone_mutex;
pthread_cond_t syscall_clone_cond;
static int futex_uaddr_changed_flag; static pthread_mutex_t futex_mutex; static pthread_cond_t futex_cond;
static int exec_ready_to_init; static pthread_mutex_t exec_func_init_mutex; static pthread_cond_t exec_func_init_cond;
static void* exec_segfault_addr; static void* syscall_segfault_addr;
static int pgfault_time_sum;
static int syscall_time_sum;
abi_long result_global;


/* get packet_counter of net_buffer */
static uint32_t get_number(void)
{
	struct tcp_msg_header tmh = *((struct tcp_msg_header *) net_buffer);
	return tmh.counter;
}

/* get tag of net_buffer */
static uint32_t get_tag(void)
{
	struct tcp_msg_header tmh = *((struct tcp_msg_header *) net_buffer);
	
	return tmh.tag;
}

/* get payloadsize of net_buffer */
static uint32_t get_size(void)
{
	struct tcp_msg_header tmh = *((struct tcp_msg_header *) net_buffer);
	return tmh.size;
}

/* Initialize socket, socket_mutex, page_recv_cond, page_recv_mutex */
static void offload_server_init(void)
{
	fprintf(stderr, "[offload_server_init]\tindex: %d\n", offload_server_idx);
	sktfd = socket(AF_INET,SOCK_STREAM, 0);
	struct sockaddr_in sockaddr;
	sockaddr.sin_family = AF_INET;
	sockaddr.sin_port = htons(server_port_of(offload_server_idx));
	
	//ip_addr
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
	pthread_mutex_init(&page_syscall_recv_mutex,NULL);
	pthread_cond_init(&page_syscall_recv_cond,NULL);
	pthread_mutex_init(&mutex_recv_mutex, NULL);
	pthread_cond_init(&mutex_recv_cond, NULL);
	pthread_mutex_init(&exit_recv_cond,NULL);
	pthread_cond_init(&exit_recv_mutex,NULL);
	pthread_mutex_init(&syscall_recv_mutex,NULL);
	pthread_mutex_init(&syscall_recv_cond,NULL);
	pthread_mutex_init(&futex_mutex, NULL);
	pthread_cond_init(&futex_cond, NULL);
	pthread_mutex_init(&exec_func_init_mutex, NULL);
	pthread_cond_init(&exec_func_init_cond, NULL);
	pgfault_time_sum = 0;

}

static void load_cpu(void)
{
	// copy the CPU struct
	
	static int count_n = 0;

	//memcpy(thread_env, p, sizeof(CPUARMState));
	extern CPUArchState *env_bak;
	extern __thread CPUArchState *thread_env;
	// if (count_n != 0) {
	// 	thread_env = cpu_copy(env_bak);
	// 	assert(thread_env);
	// }
	// count_n++;
	assert(thread_env);
	*((CPUARMState *) thread_env) = *((CPUARMState *) p);

	p += sizeof(CPUARMState);
	

	fprintf(stderr,"[load_cpu]\tenv: %p\n", thread_env);
	CPUState *cpu = ENV_GET_CPU(thread_env);
	// extern CPUArchState *thread_cpu;
	extern __thread CPUState *thread_cpu;
	thread_cpu = cpu;
	thread_cpu->env_ptr = thread_env;
	fprintf(stderr,"[load_cpu]\tcpu: %p\n", cpu);
	TaskState *ts1;

	fprintf(stderr,"[load_cpu]\topaque: %p\n", cpu->opaque);
	ts1 = cpu->opaque;
	fprintf(stderr,"[load_cpu]\tNOW child_tidptr: %p\n", ts1->child_tidptr);
	/* TaskState is a void*, we've to set it mannually */
	TaskState *ts = g_new0(TaskState, 1);
	*ts = *((TaskState*) p);
	p += sizeof(TaskState);
	cpu->opaque = ts;
	fprintf(stderr,"[load_cpu]\tNOW child_tidptr: %p\n", ts->child_tidptr);
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

	fprintf(stderr, "[load_cpu]\tr0: %d\n", thread_env->regs[0]);
}

static void load_memory_region(void)
{
	// map the memory region:
	
	
	uint32_t num = *(uint32_t *)p;
    p += sizeof(uint32_t);
	
	
	fprintf(stderr, "[load_memory_region]\tmemory region of 0%d\n", num);
	
	
	
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
	static int mapped[50] = {0}, mapped_count = 0, first = 1;
	int mapped_flag = 0;
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
		/* Check if we already mapped */
		mapped_flag = 0;
		for (int j = 0; j < 50; j++) {
			if (mapped[j] == addr) {
				mapped_flag = 1;
				break;
			}
		}
		if (mapped_flag)
			continue;
		if (first)
		{
			/* Now we map the region. */
			fprintf(stderr, "[load_memory_region]\tmemory region: %x to %x,  host: %x to %x\n", addr, addr + len, g2h(addr), g2h(addr) + len);
			mapped[mapped_count++] = addr;

			int ret = target_mmap(addr, page_num * TARGET_PAGE_SIZE, PROT_NONE,
								MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
			fprintf(stderr, "[load_memory_region]\tReturn mem addr = %p\n", ret);
			//mprotect(g2h(addr), page_num * TARGET_PAGE_SIZE, PROT_NONE);
		}
    }
	first = 0;
}

static void load_brk(void)
{
	// copy the brk
	uint32_t old_brk = *(uint32_t *)p;
    p += sizeof(uint32_t);
    uint32_t current_brk = *(uint32_t *)p;
    p += sizeof(uint32_t);
	
    int target_mmap_return;
	static int first = 1;
	if (first) {
		if(old_brk != 0)
		{
			if(current_brk > old_brk)
			{
				target_mmap_return = target_mmap(old_brk, (unsigned int)current_brk - old_brk,
												PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
				mprotect(g2h(old_brk), (unsigned int)current_brk - old_brk, PROT_NONE);
				if (target_mmap_return != old_brk)
					fprintf(stderr, "[load_brk]\ttarget_mmap  failed at start of ProcessOffloadStart, returns %x\n", target_mmap_return);
			}
			else
			{
				int ret = target_munmap(current_brk, (unsigned int) old_brk - current_brk);
				if (ret) 
				{
					fprintf(stderr, "[load_brk]\tThe munmap failed at the start of ProcessOffloadStart : %d \n", ret);
				}
			}
		}
	}
	first = 0;
}

static void load_binary(void)
{
	uint32_t binary_start_address, binary_end_address;
	binary_start_address= *(uint32_t *)p;
	p += sizeof(uint32_t);
	binary_end_address= *(uint32_t *)p;
	p += sizeof(uint32_t);
	static first = 1;
	if (first) {
		fprintf(stderr, "[load_binary]\tmap binary from %p to %x\n", binary_start_address, binary_end_address);
		fprintf(stderr, "[load_binary]\there: %x %x %x\n", g2h(binary_start_address), g2h(binary_end_address), g2h((thread_env->regs[15])));
		int ret;
		ret = mprotect(g2h(binary_start_address), (unsigned int)binary_end_address - binary_start_address, PROT_READ | PROT_WRITE);
		fprintf(stderr, "[load_binary]\tRet = %p\n", ret);
		memcpy(g2h(binary_start_address), p, (unsigned int)binary_end_address - binary_start_address);
		
		fprintf(stderr, "[load_binary]\there: %p\n", *(uint32_t *) g2h(thread_env->regs[15]));
		disas(stderr, g2h(thread_env->regs[15]), 10);

		fprintf(stderr, "[load_binary]\tcode: %x", *((uint32_t *) g2h(0x102fa)));
		mprotect(g2h(binary_start_address), (unsigned int)binary_end_address - binary_start_address, PROT_READ | PROT_WRITE | PROT_EXEC);
		first = 0;
	}
	else {
		
	}
	p += (unsigned int)binary_end_address-binary_start_address;
}

/* Initialize execution thread and go to cpu loop */
void exec_func(void)
{
	
	offload_mode = 3;
	static int count_n = 0;
	
	//pthread_mutex_lock(&socket_mutex);
	// static int first = 1;
	// if (first == 1) {
	// 	offload_server_qemu_init();
	// 	first++;
	// }	
	// else {
	// 	//offload_server_extra_init();
	// 	offload_server_idx = first-1;
	// }
	
	fprintf(stderr, "[exec_func]\tguest_base: %x count_n\n", guest_base, count_n);
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

	fprintf(stderr, "[exec_func]\tPC: %p\n", thread_env->regs[15]);
	
	
	fprintf(stderr, "[exec_func]\tregisters:\n");
	
	for (int i = 0; i < 16; i++)
	{
		fprintf(stderr, "[exec_func]\t%p\n", thread_env->regs[i]);
	}
	//target_disas(stderr, ENV_GET_CPU(env), env->regs[15], 100);
	//while (1) {;}

	if (count_n != 0) {
		fprintf(stderr, "[exec_func]\tAnother thread!!\n");
		rcu_register_thread();
		tcg_register_thread();
		//sleep(99999);
		cpu_loop(thread_env);
	}
	//pthread_mutex_unlock(&socket_mutex);
	
	count_n++;
	//!! Just debugs
	//sleep(199999);
	cpu_loop(thread_env);
	// here this thread reaches an end
		
	return NULL;
	 
}

// void *extra_exec_thread(void)
// {
// 	extern CPUArchState *env;
// 	/* we create a new CPU instance. */
// 	new_env = cpu_copy(env);
// 	/* Init regs that differ from the parent.  */
// 	cpu_clone_regs(new_env, newsp);
// 	new_cpu = ENV_GET_CPU(new_env);
// 	offload_mode = 6;
// 	extern __thread int offload_thread_idx;
// 	offload_thread_idx = 3;
// 	fprintf(stderr, "[exec_func_init]\tWaiting for informations...\n");
// 	fprintf(stderr, "[exec_func_init]\tStart Initializing... guest_base: %x\n", guest_base);
// 	p = net_buffer;
// 	fprintf(stderr, "[exec_func_init]\tin exec func\n");
// 	load_cpu();
// 	load_memory_region();
// 	load_brk();
// 	load_binary();
// 	// it's go time!
// 	//fprintf(stderr, "this address: %x\n", g2h(0x10324));
// 	fprintf(stderr, "[exec_func_init]\tready to CPU_LOOP\n");
// 	fprintf(stderr, "[exec_func_init]\tPC: %p\n", env->regs[15]);	
// 	fprintf(stderr, "[exec_func_init]\tregisters:\n");	
// 	for (int i = 0; i < 16; i++)
// 	{
// 		fprintf(stderr, "[exec_func_init]\t%p\n", env->regs[i]);
// 	}
// 	//target_disas(stderr, ENV_GET_CPU(env), env->regs[15], 100);
// 	//while (1) {;}
// 	rcu_register_thread();
// 	tcg_register_thread();
// 	//pthread_mutex_unlock(&socket_mutex);
// 	cpu_loop(env);
// 	// here this thread reaches an end
// 	return NULL;
// }
/* For extra exec. */
void exec_func_init(void)
{
	//exec_func();
	//guest_base = 0x3c00f000;
	offload_mode = 6;
	extern __thread int offload_thread_idx;
	offload_thread_idx = 3;
	fprintf(stderr, "[exec_func_init]\tWaiting for informations...\n");
	/* Once the thread reaches here, set the exec_read_to_init to 1.
	 * wait the flag to be 2 indicating initialization info is ready. */
	pthread_mutex_lock(&exec_func_init_mutex);
	exec_ready_to_init = 1;
	pthread_cond_broadcast(&exec_func_init_cond);
	while (exec_ready_to_init != 2) {
		fprintf(stderr, "[exec_func_init]\tWaiting for informations...NOT READY%d\n", exec_ready_to_init);
		pthread_cond_wait(&exec_func_init_cond, &exec_func_init_mutex);
	}
	pthread_mutex_unlock(&exec_func_init_mutex);
	//guest_base = 0x3c00000;

	fprintf(stderr, "[exec_func_init]\tStart Initializing... guest_base: %x\n", guest_base);

	
	
	p = net_buffer;
	fprintf(stderr, "[exec_func_init]\tin exec func\n");
	load_cpu();
	//sleep(100000);
	// copy the start function address
	// load_memory_region();
	// load_brk();
	// load_binary();
	// it's go time!
	//fprintf(stderr, "this address: %x\n", g2h(0x10324));
	fprintf(stderr, "[exec_func_init]\tready to CPU_LOOP\n");

	fprintf(stderr, "[exec_func_init]\tPC: %p\n", thread_env->regs[15]);
	
	
	fprintf(stderr, "[exec_func_init]\tregisters:\n");
	
	for (int i = 0; i < 16; i++)
	{
		fprintf(stderr, "[exec_func_init]\t%p\n", thread_env->regs[i]);
	}
	//target_disas(stderr, ENV_GET_CPU(env), env->regs[15], 100);
	//while (1) {;}

	rcu_register_thread();
	tcg_register_thread();

	//pthread_mutex_unlock(&socket_mutex);
	cpu_loop(thread_env);
	// here this thread reaches an end
	
		
	return NULL;
	 
}

// this happens when exec reaches exit
void cpu_exit_signal(void)
{
	fprintf(stderr,"[cpu_exit_signal]\tSSSSSSSSSSSSSSSSSIGNAL...\n");
	pthread_mutex_lock(&exit_recv_mutex);
	cpu_exit_flag=1;
	pthread_cond_signal(&exit_recv_cond);
	pthread_mutex_unlock(&exit_recv_mutex);
	fprintf(stderr,"[cpu_exit_signal]\texiting...\n");
}

// to kill exec
void * cpu_killer(void* param)
{
	pthread_t exec_thread = *(pthread_t*) param;
	fprintf(stderr, "[cpu_killer]\tKiller ready\n");
	cpu_exit_flag = 0;
	pthread_mutex_lock(&exit_recv_mutex);
	while (cpu_exit_flag==0)
	{
		pthread_cond_wait(&exit_recv_cond,&exit_recv_mutex);	
	}	
	pthread_mutex_unlock(&exit_recv_mutex);	
	fprintf(stderr, "[cpu_killer]\tTerminiting exec_cpu...:\n");
	//pthread_kill(exec_thread,NULL);
	return NULL;
}

/* create execution thread */
static void offload_process_start(void)
{
	
	static int count = 0;
	pthread_t exec_thread;
	fprintf(stderr, "[offload_process_start]\tcreate exec thread\n");
	if (count == 0) {
		// pthread_create(&exec_thread, NULL, exec_func, NULL);
		pthread_mutex_lock(&main_exec_mutex);
		main_exec_flag = 1;
		pthread_cond_broadcast(&main_exec_cond);
		pthread_mutex_unlock(&main_exec_mutex);
		count++;
	}
	else {
		pthread_mutex_lock(&exec_func_init_mutex);
		while (exec_ready_to_init != 1) {
			pthread_cond_wait(&exec_func_init_cond, &exec_func_init_mutex);
		}
		exec_ready_to_init = 2;
		pthread_cond_broadcast(&exec_func_init_cond);
		fprintf(stderr, "[offload_process_start]\tWake up please! %d\n", exec_ready_to_init);
		pthread_mutex_unlock(&exec_func_init_mutex);
		// pthread_create(&exec_thread, NULL, &extra_exec_thread, NULL);
		
	}
	fprintf(stderr, "[offload_process_start]\texec thread created\n");
	/*
	pthread_t killer_thread;
	pthread_create(&exec_thread, NULL, cpu_killer, (void*)&exec_thread);
	*/
	//pthread_join(exec_thread, NULL);
	
}

/* send mutex request in order to fetch a free lock 
	|MUTEX_REQUEST|mutex_addr|					*/
void offload_server_send_mutex_request(uint32_t mutex_addr, uint32_t cmpv, uint32_t newv, uint32_t strv)
{
	//!!!
	//mutex_addr = h2g(mutex_addr);

	char buf[TARGET_PAGE_SIZE * 2];
	char *pp = buf + sizeof(struct tcp_msg_header);
	*((target_ulong *)pp) = (target_ulong)mutex_addr;
	pp += sizeof(target_ulong);
	*((uint32_t *)pp) = (uint32_t) offload_server_idx;
	pp += sizeof(uint32_t);
	*((uint32_t *)pp) = cmpv;
	pp += sizeof(uint32_t);
	*((uint32_t *)pp) = newv;
	pp += sizeof(uint32_t);
	*((uint32_t *)pp) = strv;
	pp += sizeof(uint32_t);
	struct tcp_msg_header *tcp_header = (struct tcp_msg_header *) buf;
	fill_tcp_header(tcp_header, pp - buf - sizeof(struct tcp_msg_header), TAG_OFFLOAD_CMPXCHG_REQUEST);
	/* we should lock first in case verified returns before we sleep!!!!!! */
	pthread_mutex_lock(&mutex_recv_mutex);
	
	int res = autoSend(client_socket, buf, pp - buf, 0);
	if (res < 0)
	{
		fprintf(stderr, "[cmpxchg_request]\tsent mutex request %p failed\n", mutex_addr);
		exit(0);
	}
	fprintf(stderr, "[cmpxchg_request]\tsent mutex request, mutex addr: %p, packet %d, waiting...offload_server_idx=%d\n", mutex_addr, get_number(), offload_server_idx);
	fprintf(stderr, "[cmpxchg_request]\tcas addr %p, idx %d, cmpv %x, newv %x, strv %x\n", mutex_addr, offload_server_idx, cmpv, newv, strv);
	mutex_ready_flag = 0;
	while (mutex_ready_flag == 0)
	{
		pthread_cond_wait(&mutex_recv_cond, &mutex_recv_mutex);
	}
	pthread_mutex_unlock(&mutex_recv_mutex);
	fprintf(stderr, "[cmpxchg_request]\tsent mutex request, mutex addr: %p, packet %d, I'm awake!\n", mutex_addr, get_number());

}

static void offload_server_process_mutex_verified(void)
{
		//pthread_mutex_lock(&socket_mutex);
	fprintf(stderr, "[offload_server_process_mutex_verified]\twaking up thread\n");
	pthread_mutex_lock(&mutex_recv_mutex);
	mutex_ready_flag = 1;
	pthread_cond_signal(&mutex_recv_cond);
	pthread_mutex_unlock(&mutex_recv_mutex);
	//if (mutex_ready_flag == 0) offload_server_process_mutex_verified();
}

/* send page request |REQUEST|page_addr|perm| */
static void offload_server_send_page_request(target_ulong page_addr, uint32_t perm)
{
	//pthread_mutex_lock(&socket_mutex);
	fprintf(stderr, ">>>>>>>>> exec# %d guest_base: %x\n", offload_server_idx, guest_base);
	char buf[TARGET_PAGE_SIZE * 2];
	/* prepare space for head */
	char *pp = buf + sizeof(struct tcp_msg_header);
	/* page_addr and perm */
	*((target_ulong *) pp) = page_addr;
    pp += sizeof(target_ulong);	
	*((uint32_t *) pp) = perm;
	pp += sizeof(uint32_t);
	// fill head with payloadsize and tag
	struct tcp_msg_header *tcp_header = (struct tcp_msg_header *) buf;
	fill_tcp_header(tcp_header, pp - buf - sizeof(struct tcp_msg_header), TAG_OFFLOAD_PAGE_REQUEST);
	
	int res = autoSend(client_socket, buf, pp - buf, 0);
	if (res < 0)
	{
		fprintf(stderr, "[offload_server_send_page_request]\tsent page %x request failed\n", page_addr);
		exit(0);
	}
	fprintf(stderr, "[offload_server_send_page_request]\tsent page %x request, perm: %s, packet#%d\n", page_addr, perm==1?"READ":"READ|WRITE", get_number());
	//pthread_mutex_unlock(&socket_mutex);
}

/* send page and modify permission to invalidate or shared */
static void offload_process_page_request(void)
{
	//pthread_mutex_lock(&socket_mutex);
	pthread_mutex_lock(&cmpxchg_mutex);
	p = net_buffer;
	
	target_ulong page_addr = *((target_ulong *) p);
    p += sizeof(target_ulong);
	
	uint32_t perm = *((uint32_t *) p);
	p += sizeof(uint32_t);
	int client_idx = *((int*) p);
	p += sizeof(int);
	int forwho = *((int*) p);
	p += sizeof(int);
	fprintf(stderr, "[offload_process_page_request]\tpage %x, perm %d, from %d, for %d\n", page_addr, perm, client_idx, forwho);
	// when debug, erase this.
	mprotect(g2h(page_addr), TARGET_PAGE_SIZE, PROT_READ);//prevent writing at this time!!
	if (page_addr == 0x78000)
	{
		fprintf(stderr, "[offload_process_page_request]\tdebug\t0x78f4c = %d", *(int *)(g2h(0x78f4c)));
	}
	/* debug pthread_mutex_struct */
	if (page_addr == 0x78000)
	{
		fprintf(stderr, "[offload_process_page_request]\tdebug\t__lock0x77f34 = %d", *(int *)(g2h(0x78f34)));
		fprintf(stderr, "[offload_process_page_request]\tdebug\t__count0x77f38 = %d", *(int *)(g2h(0x78f38)));
		fprintf(stderr, "[offload_process_page_request]\tdebug\t__owner0x77f40 = %d", *(int *)(g2h(0x78f3C)));
	}
	offload_send_page_content(page_addr, perm, forwho);
	fprintf(stderr, "[offload_process_page_request]\tsent content\n", page_addr, perm);
	/*	if required permission is WRITE|READ,
	*	we won't be able to use it (invalidate)
	*	otherwise it is a shared page (shared)
	*/
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
	pthread_mutex_unlock(&cmpxchg_mutex);
}

/* copy content to page and send ack? */
static void offload_process_page_content(void)
{
	//pthread_mutex_lock(&socket_mutex);
	p = net_buffer;
	
	target_ulong page_addr = *((target_ulong *) p);
    p += sizeof(target_ulong);
	
	uint32_t perm = *((uint32_t *) p);
	p += sizeof(uint32_t);
	fprintf(stderr, "[offload_process_page_content]\tcontent: %d %d\n", *((uint64_t *) p), *((uint64_t *) p + 555));

	/* protect page and copy content to page */
	mprotect(g2h(page_addr), TARGET_PAGE_SIZE, PROT_READ | PROT_WRITE);
	memcpy(g2h(page_addr), p, TARGET_PAGE_SIZE);
	/* debug pthread_mutex_t */
	if (page_addr == 0x78000)
	{
		fprintf(stderr, "[offload_process_page_content]\tdebug\t__lock0x77f34 = %d", *(int *)(g2h(0x78f34)));
		fprintf(stderr, "[offload_process_page_content]\tdebug\t__count0x77f38 = %d", *(int *)(g2h(0x78f38)));
		fprintf(stderr, "[offload_process_page_content]\tdebug\t__owner0x77f40 = %d", *(int *)(g2h(0x78f3C)));
	}
	p += TARGET_PAGE_SIZE;
	if (perm == 2)
	{
		mprotect(g2h(page_addr), TARGET_PAGE_SIZE, PROT_READ | PROT_WRITE);
	}
	else if (perm == 1)
	{
		mprotect(g2h(page_addr), TARGET_PAGE_SIZE, PROT_READ);
	}
	fprintf(stderr, "[offload_process_page_content]\tpage %x perm: %s\n", page_addr, perm==1?"READ":"WRITE|READ");
	// wake up the execution thread upon this required page.
	if (page_addr == exec_segfault_addr)
	{
		fprintf(stderr, "[offload_process_page_content]\twaking up exec\n");
		pthread_mutex_lock(&page_recv_mutex);
		page_recv_flag = 1;
		pthread_cond_broadcast(&page_recv_cond);
		pthread_mutex_unlock(&page_recv_mutex);
	}
	if (page_addr == syscall_segfault_addr)
	{
		fprintf(stderr, "[offload_process_page_content]\twaking up syscall\n");
		pthread_mutex_lock(&page_syscall_recv_mutex);
		page_syscall_recv_flag = 1;
		pthread_cond_broadcast(&page_syscall_recv_cond);
		pthread_mutex_unlock(&page_syscall_recv_mutex);
	}
	//pthread_mutex_unlock(&socket_mutex);
	/* ? */
	offload_send_page_ack(page_addr, perm);
}

/* send |CONTENT|page|perm|content| */
static void offload_send_page_content(target_ulong page_addr, uint32_t perm, int forwho)
{
	/* prepare space for head */
	char buf[TARGET_PAGE_SIZE * 2];
	char *p = buf + sizeof(struct tcp_msg_header);
	/* fill addr and perm */
	*((target_ulong *) p) = page_addr;
    p += sizeof(target_ulong);
	*((uint32_t *) p) = perm;
	p += sizeof(uint32_t);
	*((int*) p) = forwho;
	p += sizeof(int);
    /* followed by page content (size = TARGET_PAGE_SIZE) */
	fprintf(stderr, "[DEBUG]\tPOINT1\n");
	//TODO: 如果是2就直接disable了 如果是1就發送。
	//mprotect(g2h(page_addr), TARGET_PAGE_SIZE, PROT_READ | PROT_WRITE);
	fprintf(stderr, "[DEBUG]\tPOINT1.5\n");
	memcpy(p, g2h(page_addr), TARGET_PAGE_SIZE);
	fprintf(stderr, "[DEBUG]\tPOINT2\n");
    p += TARGET_PAGE_SIZE;
	/* fill head */
	struct tcp_msg_header *tcp_header = (struct tcp_msg_header *) buf;
	fill_tcp_header(tcp_header, p - buf - sizeof(struct tcp_msg_header), TAG_OFFLOAD_PAGE_CONTENT);
	fprintf(stderr, "[DEBUG]\tPOINT3\n");
	int res = autoSend(client_socket, buf, p - buf, 0);
	if (res < 0)
	{
		fprintf(stderr, "[offload_send_page_content]\tsent page %x content failed\n", page_addr);
		exit(0);
	}
	fprintf(stderr, "[offload_send_page_content]\tsent page %x content, perm%d, packet#%d\n", page_addr, perm, get_number());
}


/* send |ACK|page|perm| */
static void offload_send_page_ack(target_ulong page_addr, uint32_t perm)
{
	//pthread_mutex_lock(&socket_mutex);
	/* prepare space for head */
	p = BUFFER_PAYLOAD_P;
	/* fill addr and perm */
	*((target_ulong *) p) = page_addr;
    p += sizeof(target_ulong);
	*((uint32_t *) p) = perm;
	p += sizeof(uint32_t);
	/* fill head, tag = ack */
	struct tcp_msg_header *tcp_header = (struct tcp_msg_header *) net_buffer;
	fill_tcp_header(tcp_header, p - net_buffer - sizeof(struct tcp_msg_header), TAG_OFFLOAD_PAGE_ACK);
	int res = autoSend(client_socket, net_buffer, p - net_buffer, 0);
	if (res < 0)
	{
		fprintf(stderr, "[offload_send_page_ack]\tsent page %x ack failed\n", page_addr);
		exit(0);
	}
	fprintf(stderr, "[offload_send_page_ack]\tsent page %x ack with perm: %s\n", page_addr, perm==1?"READ":"WRITE|READ");
	//pthread_mutex_unlock(&socket_mutex);
}

#define PAGE_SHIFT 12
#define VPTPTR 0xfffffffe00000000UL
static inline unsigned long
pt_index(unsigned long addr, int level)
{
	return (addr >> (PAGE_SHIFT + (10 * level))) & 0x3ff;
}

/* send page request; sleep until page is sent back */
int offload_segfault_handler(int host_signum, siginfo_t *pinfo, void *puc)
{
	struct timeb t, tend;
    ftime(&t);
    siginfo_t *info = pinfo;
    ucontext_t *uc = (ucontext_t *)puc;
    void* host_addr = info->si_addr;
    //TODO ... do h2g on the host_addr to get the address of the segfault
	
    unsigned long  guest_addr = h2g(host_addr);
	fprintf(stderr, "[offload_segfault_handler]\tguest addr is %p, host_addr is %lp, pte-0 %p, pte-1 %p, pte-2 %p, VP-2 %p, VP-1%p\n", 
			guest_addr, host_addr, pt_index(host_addr, 0), pt_index(host_addr, 1), pt_index(host_addr, 2), pt_index(VPTPTR, 2), pt_index(VPTPTR, 1));

	target_ulong page_addr = guest_addr & TARGET_PAGE_MASK;
    //fprintf(stderr, "Accessed guest addr %lx\n", guest_addr);
	
    //fprintf(stderr, "\nHost instruction address is %p\n", uc->uc_mcontext.gregs[REG_RIP]);


    int is_write = ((uc->uc_mcontext.gregs[REG_ERR] & 0x2) != 0);
	//TODO !!!!!!!!!!!!!!!DEBUG
	//is_write = 1;
	fprintf(stderr, "[offload_segfault_handler]\tsegfault on page addr: %x, perm: %s\n", page_addr, is_write?"WRITE|READ":"READ");
	// sum time on pagefault
	
	//get_client_page(is_write, guest_page);
	
	// send page request, sleep until content is sent back.
	
	if (offload_mode != 4)
	{
		exec_segfault_addr = page_addr;
		pthread_mutex_lock(&page_recv_mutex);
		page_recv_flag = 0;
		offload_server_send_page_request(page_addr, is_write + 1); // easy way to convert is_write to perm
		fprintf(stderr, "[offload_segfault_handler]\tsent page REQUEST %x, wait, sleeping\n", page_addr);
		//TODO check if 
		while (page_recv_flag == 0)
		{
			pthread_cond_wait(&page_recv_cond, &page_recv_mutex);
		}
		pthread_mutex_unlock(&page_recv_mutex);
		
		fprintf(stderr, "[offload_segfault_handler]\tawake\n");
	}
	/* for syscall#0's segfault */
	else
	{
		syscall_segfault_addr = page_addr;
		fprintf(stderr, "[offload_segfault_handler]\tin syscall segfault\n");
		pthread_mutex_lock(&page_syscall_recv_mutex);
		page_syscall_recv_flag = 0;
		offload_server_send_page_request(page_addr, is_write + 1); // easy way to convert is_write to perm
		//offload_server_send_page_request(page_addr, 2);
		fprintf(stderr, "[offload_segfault_handler]\tsent page REQUEST %x, wait, sleeping\n", page_addr);
		while (page_syscall_recv_flag == 0)
		{
			pthread_cond_wait(&page_syscall_recv_cond, &page_syscall_recv_mutex);
		}
		pthread_mutex_unlock(&page_syscall_recv_mutex);
		fprintf(stderr, "[offload_segfault_handler]\tsyscall segfault awake\n");
	}
	//fprintf(stderr, "[offload_segfault_handler]\t%p value is %p\n", guest_addr, *(uint32_t*)(g2h(guest_addr)));
	ftime(&tend);
	int secDiff = tend.time - t.time;
	secDiff *= 1000;
	secDiff += (tend.millitm - t.millitm);
	pgfault_time_sum += secDiff;
	fprintf(stderr, "[offload_segfault_handler]\tbegin: %d:%d; end: %d:%d, used: %dms, now total is: %dms", t.time, t.millitm, tend.time, tend.millitm, secDiff, pgfault_time_sum);

    return 1;
}
/* send page request; sleep until page is sent back */
int offload_segfault_handler_positive(uint32_t page_addr, int perm)
{
	struct timeb t, tend;
	ftime(&t);
	page_addr &= TARGET_PAGE_MASK;
	fprintf(stderr, "[offload_segfault_handler_positive]\tguest addr is %p\n",
			page_addr);


	int is_write = perm - 1;
	//TODO !!!!!!!!!!!!!!!DEBUG
	//is_write = 1;
	fprintf(stderr, "[offload_segfault_handler_positive]\tsegfault on page addr: %x, perm: %s\n", page_addr, is_write ? "WRITE|READ" : "READ");


	if (offload_mode != 4)
	{
		exec_segfault_addr = page_addr;
		pthread_mutex_lock(&page_recv_mutex);
		page_recv_flag = 0;
		offload_server_send_page_request(page_addr, is_write + 1); // easy way to convert is_write to perm
		fprintf(stderr, "[offload_segfault_handler_positive]\tsent page REQUEST %x, wait, sleeping\n", page_addr);
		//TODO check if
		while (page_recv_flag == 0)
		{
			pthread_cond_wait(&page_recv_cond, &page_recv_mutex);
		}
		pthread_mutex_unlock(&page_recv_mutex);

		fprintf(stderr, "[offload_segfault_handler_positive]\tawake\n");
	}
	/* for syscall#0's segfault */
	else
	{
		syscall_segfault_addr = page_addr;
		fprintf(stderr, "[offload_segfault_handler_positive]\tin syscall segfault\n");
		pthread_mutex_lock(&page_syscall_recv_mutex);
		page_syscall_recv_flag = 0;
		offload_server_send_page_request(page_addr, is_write + 1); // easy way to convert is_write to perm
		//offload_server_send_page_request(page_addr, 2);
		fprintf(stderr, "[offload_segfault_handler_positive]\tsent page REQUEST %x, wait, sleeping\n", page_addr);
		while (page_syscall_recv_flag == 0)
		{
			pthread_cond_wait(&page_syscall_recv_cond, &page_syscall_recv_mutex);
		}
		pthread_mutex_unlock(&page_syscall_recv_mutex);
		fprintf(stderr, "[offload_segfault_handler_positive]\tsyscall segfault awake\n");
	}
	//fprintf(stderr, "[offload_segfault_handler_positive]\t%p value is %d\n", page_addr, *(uint32_t *)(g2h(page_addr)));
	ftime(&tend);
	int secDiff = tend.time - t.time;
	secDiff *= 1000;
	secDiff += (tend.millitm - t.millitm);
	pgfault_time_sum += secDiff;
	fprintf(stderr, "[offload_segfault_handler_positive]\tbegin: %d:%d; end: %d:%d, used: %dms, now total is: %dms", t.time, t.millitm, tend.time, tend.millitm, secDiff, pgfault_time_sum);

	return 1;
}
/* change permission of page_addr */
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
	fprintf(stderr, "[offload_process_page_perm]\tCHANGE page %x perm to %d\n", page_addr, perm);
	//pthread_mutex_unlock(&socket_mutex);
}

/* wake up exec; change permission to READ|WRITE?? */
static void offload_process_page_upgrade(void)
{
	//pthread_mutex_lock(&socket_mutex);
	p = net_buffer;
	
	target_ulong page_addr = *((target_ulong *) p);
    p += sizeof(target_ulong);
	int perm = *((int*) p);
	p += sizeof(int);
	if (perm ==2)
		mprotect(g2h(page_addr), TARGET_PAGE_SIZE, PROT_READ | PROT_WRITE);
	else if(perm == 1)
		mprotect(g2h(page_addr), TARGET_PAGE_SIZE, PROT_READ);
	else if(perm == 0)
		mprotect(g2h(page_addr), TARGET_PAGE_SIZE, PROT_NONE);
	
	// pthread_mutex_lock(&page_recv_mutex);
	// page_recv_flag = 1;
	// pthread_cond_signal(&page_recv_cond);
	// pthread_mutex_unlock(&page_recv_mutex);
	fprintf(stderr, "[offload_process_page_upgrade]\tpage %x perm: %s\n", page_addr, perm == 1 ? "READ" : "WRITE|READ");
	// wake up the execution thread upon this required page.
	if (page_addr == exec_segfault_addr)
	{
		fprintf(stderr, "[offload_process_page_upgrade]\twaking up exec\n");
		pthread_mutex_lock(&page_recv_mutex);
		page_recv_flag = 1;
		pthread_cond_broadcast(&page_recv_cond);
		pthread_mutex_unlock(&page_recv_mutex);
	}
	if (page_addr == syscall_segfault_addr)
	{
		fprintf(stderr, "[offload_process_page_upgrade]\twaking up syscall\n");
		pthread_mutex_lock(&page_syscall_recv_mutex);
		page_syscall_recv_flag = 1;
		pthread_cond_broadcast(&page_syscall_recv_cond);
		pthread_mutex_unlock(&page_syscall_recv_mutex);
	}
	fprintf(stderr, "[offload_process_page_upgrade]\tpage %x upgrade to %d\n", page_addr, perm);
	if (perm > 0)
	{

		offload_send_page_ack(page_addr, perm);
	}
	//pthread_mutex_unlock(&socket_mutex);
}


static void offload_server_daemonize(void)
{
	fprintf(stderr, "[offload_server_daemonize]\tstart to daemonize\n");
	
	//fprintf(stderr, ">>>>>>>>>>>> server# %d guest_base: %x\n", offload_server_idx, guest_base);
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
		fprintf(stderr, "[offload_server_daemonize]\twaiting for new message\n");
		
		//fprintf(stderr, "count addr: %x\n", g2h(0x7ae34));

		//int res = recv(client_socket, net_buffer, sizeof(struct tcp_msg_header), MSG_WAITALL);
		try_recv(sizeof(struct tcp_msg_header));
		fprintf(stderr, "[offload_server_daemonize]\tgot a new message #%d\n", get_number());
		int tag = get_tag();
		int size = get_size();
		int packet_counter = get_number();
		fprintf(stderr, "[offload_server_daemonize]\tsize: %d + %d\n", sizeof(struct tcp_msg_header), size);
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
				
				
			case TAG_OFFLOAD_FUTEX_WAIT_RESULT:
				fprintf(stderr, "[offload_server_daemonize]\ttag: futex wait result\n");
				try_recv(size);
				exit(0);
				offload_server_process_futex_wait_result();
				
				break;
				
			case TAG_OFFLOAD_FUTEX_WAKE_RESULT:
				
				fprintf(stderr, "[offload_server_daemonize]\ttag: futex wake result\n");
				try_recv(size);
				exit(0);
				offload_server_process_futex_wake_result();
				break;

			case TAG_OFFLOAD_CMPXCHG_REQUEST:
				fprintf(stderr, "[offload_server_daemonize]\ttag: cmpxchg request\n");
				try_recv(size);
				//offload_process_mutex_request();
				break;

			case TAG_OFFLOAD_CMPXCHG_VERYFIED:
				fprintf(stderr, "[offload_server_daemonize]\ttag: cmpxchg verified, size = %d(should be 0)\n", size);
				//try_recv(size);
				offload_server_process_mutex_verified();
				break;

			case TAG_OFFLOAD_SYSCALL_RES:
				fprintf(stderr, "[offload_server_daemonize]\ttag: syscall result, size = %d\n", size);
				try_recv(size);
				//fprintf(stderr, "[offload_server_daemonize]\treceived.\n");
				offload_server_process_syscall_result();
				break;

			case TAG_OFFLOAD_YOUR_TID:
				fprintf(stderr, "[offload_server_daemonize]\ttag: TID, size = %d\n", size);
				try_recv(size);
				offload_process_tid();
				break;

			case TAG_OFFLOAD_FORK_INFO:
				fprintf(stderr, "[offload_server_daemonize]\ttag: FORK INFO, size = %d\n", size);
				try_recv(size);
				offload_process_fork_info();
				break;
			default:
				fprintf(stderr, "[offload_server_daemonize]\tunkown tag: %d\n", tag);
				try_recv(size);
				exit(0);
				break;
				
		}
	}
}

extern void* offload_center_client_start(void *arg);
void* offload_center_server_start(void *arg)
{
	
	offload_mode = 1;
	offload_server_init();
	fprintf(stderr, "[offload_center_server_start]\tcenter server guest_base: %x\n", guest_base);
	pthread_t offload_center_client_thread;



	pthread_create(&offload_center_client_thread, NULL, offload_center_client_start, arg);	


	
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

void* offload_server_start_thread(void* arg)
{
	offload_mode = 1;
	fprintf(stderr, "[offload_server_start]\tstart offload server\n");
	//env = _env;
	offload_server_init();
	offload_server_daemonize();
	
}

void offload_server_send_cmpxchg_start(uint32_t cas_addr, uint32_t cmpv, uint32_t newv, uint32_t strv)
{
	offload_server_send_mutex_request(cas_addr, cmpv, newv, strv);
}

/* send |MUTEX_DONE|mutex_addr|idx| */
static void offload_send_mutex_done(uint32_t mutex_addr, uint32_t nowv)
{
	//pthread_mutex_lock(&socket_mutex);
	/* prepare space for head */
	//p = BUFFER_PAYLOAD_P;
	char buf[TARGET_PAGE_SIZE * 2];
	char *p = buf + sizeof(struct tcp_msg_header);
	*((uint32_t *) p) = mutex_addr;
    p += sizeof(uint32_t);
	*((uint32_t *) p) = offload_server_idx;
	p += sizeof(uint32_t);
	*((uint32_t *)p) = nowv;
	p += sizeof(uint32_t);
	/* fill head, tag = MUTEX_DONE */
	struct tcp_msg_header *tcp_header = (struct tcp_msg_header *) buf;
	fill_tcp_header(tcp_header, p - buf - sizeof(struct tcp_msg_header), TAG_OFFLOAD_CMPXCHG_DONE);
	int res = autoSend(client_socket, buf, p - buf, 0);
	if (res < 0)
	{
		fprintf(stderr, "[offload_send_mutex_done]\tsent mutex %p done failed\n", mutex_addr);
		exit(0);
	}
	fprintf(stderr, "[offload_send_mutex_done]\tsent mutex %p done, nowv %x from server #%d\n", mutex_addr, nowv, offload_server_idx);
	//pthread_mutex_unlock(&socket_mutex);
}

void offload_server_send_cmpxchg_end(uint32_t cas_addr, uint32_t nowv)
{
	offload_send_mutex_done(cas_addr, nowv);
}

static void offload_server_send_futex_wake_request(target_ulong uaddr, int op, int val, target_ulong timeout, target_ulong uaddr2, int val3)
{
	p = BUFFER_PAYLOAD_P;
	
	*((target_ulong *) p) = uaddr;
    p += sizeof(target_ulong);
	
	*((int *) p) = op;
	p += sizeof(int);
	
	*((int *) p) = val;
	p += sizeof(int);
	
	*((target_ulong *) p) = timeout;
    p += sizeof(target_ulong);
	
	*((target_ulong *) p) = uaddr2;
    p += sizeof(target_ulong);
	
	*((int *) p) = val3;
	p += sizeof(int);
	
	struct tcp_msg_header *tcp_header = (struct tcp_msg_header *) net_buffer;
	fill_tcp_header(tcp_header, p - net_buffer - sizeof(struct tcp_msg_header), TAG_OFFLOAD_FUTEX_WAKE_REQUEST);
	int res = autoSend(client_socket, net_buffer, p - net_buffer, 0);
	if (res < 0)
	{
		fprintf(stderr, "[offload_server_send_futex_wake_request]\tsent futex wake request failed\n");
		exit(0);
	}
	fprintf(stderr, "[offload_server_send_futex_wake_request]\tsent futex wake request, packet# %d, uaddr: %x\n", get_number(), uaddr);
}
static void offload_server_send_futex_wait_request(target_ulong guest_addr, int op, int val, target_ulong timeout, target_ulong uaddr2, int val3)
{
	p = BUFFER_PAYLOAD_P;
	
	*((target_ulong *) p) = guest_addr;
    p += sizeof(target_ulong);
	
	*((int *) p) = op;
	p += sizeof(int);
	offload_log(stderr, "futex op: %d\n", op);
	*((int *) p) = val;
	p += sizeof(int);
	
	*((target_ulong *) p) = timeout;
    p += sizeof(target_ulong);
	
	*((target_ulong *) p) = uaddr2;
    p += sizeof(target_ulong);
	
	*((int *) p) = val3;
	p += sizeof(int);
	
	struct tcp_msg_header *tcp_header = (struct tcp_msg_header *) net_buffer;
	fill_tcp_header(tcp_header, p - net_buffer - sizeof(struct tcp_msg_header), TAG_OFFLOAD_FUTEX_WAIT_REQUEST);
	int res = autoSend(client_socket, net_buffer, p - net_buffer, 0);
	if (res < 0)
	{
		fprintf(stderr, "[offload_server_send_futex_wait]\tsent futex wait request failed\n");
		exit(0);
	}
	fprintf(stderr, "[offload_server_send_futex_wake_request]\tsent futex wait request, packet# %d, uaddr: %x\n", get_number(), guest_addr);
}

 int offload_server_futex_wait(target_ulong guest_addr, int op, int val, target_ulong timeout, target_ulong uaddr2, int val3)
{
	// can we assume that by the time we encounter a futex syscall,
	// there will be no page request in process?
	// I will take this for now.
	//futex_result = 0;
	
	//page_recv_flag = 0;
	//offload_server_send_futex_wait_request(guest_addr, op, val, timeout, uaddr2, val3);
	fprintf(stderr, "[offload_server_futex_wait]\t[*(uint32_t*)g2h(guest_addr) %d ！= val %d, sleeping...]\n", *(uint32_t*)g2h(guest_addr), val);
	pthread_mutex_lock(&futex_mutex);
	futex_uaddr_changed_flag = 0;
	while (futex_uaddr_changed_flag == 0)
	{
		pthread_cond_wait(&futex_cond, &futex_mutex);
	}
	pthread_mutex_unlock(&futex_mutex);
	fprintf(stderr, "[offload_server_futex_wait]\tawake");
	
	return 0;
}


static void offload_server_process_futex_wait_result()
{
	p = net_buffer;
	
	int result = *((target_ulong *) p);
    p += sizeof(target_ulong);
	
	
	
	pthread_mutex_lock(&page_recv_mutex);
	
	futex_result = result;
	page_recv_flag = 1;
	pthread_cond_signal(&page_recv_cond);
	pthread_mutex_unlock(&page_recv_mutex);
}


int offload_server_futex_wake(target_ulong uaddr, int op, int val, target_ulong timeout, target_ulong uaddr2, int val3)
{
	//futex_result = 0;
	//page_recv_flag = 0;
	//offload_server_send_futex_wake_request(uaddr, op, val, timeout, uaddr2, val3);
	 
	fprintf(stderr, "[offload_server_futex_wake]\t[*(uint32_t*)g2h(uaddr) %d == val %d, sleeping...]\n", *(uint32_t*)g2h(uaddr), val);
	pthread_mutex_lock(&futex_mutex);
	futex_uaddr_changed_flag = 1;
	pthread_cond_broadcast(&futex_cond);
	pthread_mutex_unlock(&futex_mutex);

	
	return 0;
}
static void offload_server_process_futex_wake_result(void)
{
	p = net_buffer;
	
	int result = *((target_ulong *) p);
    p += sizeof(target_ulong);
	
	
	
	pthread_mutex_lock(&page_recv_mutex);
	
	futex_result = result;
	page_recv_flag = 1;
	pthread_cond_signal(&page_recv_cond);
	pthread_mutex_unlock(&page_recv_mutex);
}

abi_long pass_syscall(void *cpu_env, int num, abi_long arg1,
                    abi_long arg2, abi_long arg3, abi_long arg4,
                    abi_long arg5, abi_long arg6, abi_long arg7,
                    abi_long arg8)
{
	// if ((num == TARGET_NR_futex)&&
	// 	(arg2 == FUTEX_PRIVATE_FLAG|FUTEX_WAIT) && 
	// 	(offload_server_idx > 0))// futex wait from server, ignore
	// {
	// 	fprintf(stderr, "[arm-cpu]\tI am #%d ignoring..futex\n", offload_server_idx);
	// 	return 0;
	// 	exit(-1);
	// }
	// fprintf(stderr, "[pass_syscall]\targ2 = %d\n",arg2);
	fprintf(stderr, "[pass_syscall]\tpassing syscall to center\n");
	// mark1 syscall time sum
	struct timeb t, tend;
    ftime(&t);
	extern void print_syscall(int num,
              abi_long arg1, abi_long arg2, abi_long arg3,
              abi_long arg4, abi_long arg5, abi_long arg6);
	print_syscall(num,
              arg1, arg2, arg3,
              arg4, arg5, arg6);
	
	char buf[TARGET_PAGE_SIZE*2];
	char *pp = buf + sizeof(struct tcp_msg_header);
	CPUARMState env = *((CPUARMState*)cpu_env);
	*((CPUARMState*)pp) = (CPUARMState)env;
	pp += sizeof(CPUARMState);
	fprintf(stderr, "[pass_syscall]\teabi:%p\n",((CPUARMState *)cpu_env)->eabi);
	*((int *)pp) = (int) num;
	pp += sizeof(int);
	*((uint32_t*)pp) = (uint32_t)(arg1);
	pp += sizeof(uint32_t);
	*((uint32_t*)pp) = (uint32_t)(arg2);
	pp += sizeof(uint32_t);
	*((uint32_t*)pp) = (uint32_t)(arg3);
	pp += sizeof(uint32_t);
	*((abi_long*)pp) = (abi_long)arg4;
	pp += sizeof(abi_long);
	*((abi_long*)pp) = (abi_long)arg5;
	pp += sizeof(abi_long);
	*((abi_long*)pp) = (abi_long)arg6;
	pp += sizeof(abi_long);
	*((abi_long*)pp) = (abi_long)arg7;
	pp += sizeof(abi_long);
	*((abi_long*)pp) = (abi_long)arg8;
	pp += sizeof(abi_long);
	*((int*)pp) = (int)offload_server_idx;
	pp += sizeof(int);
	fprintf(stderr, "[pass_syscall]\targ1: %p, arg2:%p, arg3:%p\n", arg1, arg2, arg3);
	struct tcp_msg_header *tcp_header = (struct tcp_msg_header *) buf;
	fill_tcp_header(tcp_header, pp - buf - sizeof(struct tcp_msg_header), TAG_OFFLOAD_SYSCALL_REQ);

	int res = autoSend(client_socket, buf, pp - buf, 0);
	if (res < 0)
	{
		fprintf(stderr, "[pass_syscall]\tpassing syscall failed\n");
		exit(0);
	}
	fprintf(stderr, "[pass_syscall]\tpassed syscall, packet %d, waiting...\n", get_number());
	syscall_ready_flag = 0;
	pthread_mutex_lock(&syscall_recv_mutex);
	while (syscall_ready_flag == 0)
	{
		pthread_cond_wait(&syscall_recv_cond, &syscall_recv_mutex);
	}
	pthread_mutex_unlock(&syscall_recv_mutex);
	fprintf(stderr, "[pass_syscall]\tI'm awake!\n");
	abi_long result = result_global;
	fprintf(stderr, "[pass_syscall]\returning result %p!\n", result);
	// calculate time diff
	ftime(&tend);
	int secDiff = tend.time - t.time;
	secDiff *= 1000;
	secDiff += (tend.millitm - t.millitm);
	syscall_time_sum += secDiff;
	fprintf(stderr, "[pass_syscall]\tbegin: %d:%d; end: %d:%d, used: %dms, now total is: %dms", t.time, t.millitm, tend.time, tend.millitm, secDiff, syscall_time_sum);
	fprintf(stderr, "[pass_syscall]\returning result %p!\n", result);
	return result;

}

static void offload_server_process_syscall_result(void)
{
	p = net_buffer;
	abi_long result = *((abi_long *) p);
    p += sizeof(abi_long);
	result_global = result;
	fprintf(stderr, "[offload_server_process_syscall_result]\tgot syscall ret = %p, waking up thread\n", result);
	pthread_mutex_lock(&syscall_recv_mutex);
	syscall_ready_flag = 1;
	pthread_cond_signal(&syscall_recv_cond);
	pthread_mutex_unlock(&syscall_recv_mutex);
	//if (mutex_ready_flag == 0) offload_server_process_mutex_verified();
}

static void offload_process_tid(void)
{
	p = net_buffer;
	uint32_t tid = *((uint32_t*)p);	
	p += sizeof(uint32_t);
	fprintf(stderr,"[offload_process_tid]\treceived child_tidptr: %p\n", tid);
	return ;
	extern __thread CPUArchState *thread_env;
	if (!thread_env)
	{
		fprintf(stderr,"[offload_process_tid]\tenv: %p\n", thread_env);
		assert(thread_env);
	}
	CPUState *cpu = ENV_GET_CPU((CPUArchState *)thread_env);
	if (!cpu)
	{
		fprintf(stderr,"[offload_process_tid]\tcpu: %p\n", cpu);
		assert(cpu);
	}
	TaskState *ts;
	assert(cpu->opaque);
	ts = cpu->opaque;
	ts->child_tidptr = tid;
	fprintf(stderr,"[offload_process_tid]\tNOW child_tidptr: %p\n", ts->child_tidptr);
}


static void offload_process_fork_info(void)
{
	p = net_buffer;
	unsigned int flags = *((unsigned int*)p);
	p += sizeof(unsigned int);
	abi_ulong newsp = *((abi_ulong*)p);
	p += sizeof(abi_ulong);
	abi_ulong parent_tidptr = *((abi_ulong*)p);
	p += sizeof(abi_ulong);
	target_ulong newtls = *((target_ulong*)p);
	p += sizeof(target_ulong);
	abi_ulong child_tidptr = *((abi_ulong*)p);
	p += sizeof(abi_ulong);

	fprintf(stderr,"[offload_process_fork_info]\tdoing fork local\n");
	extern int do_fork_server_local(CPUArchState *env, unsigned int flags, abi_ulong newsp,
                   abi_ulong parent_tidptr, target_ulong newtls,
                   abi_ulong child_tidptr);
	extern CPUArchState *env_bak;
	do_fork_server_local( env_bak,   flags,  newsp,
                    parent_tidptr,  newtls,
                    child_tidptr);
	fprintf(stderr,"[offload_process_fork_info]\tDone.\n");

}


static void try_recv(int size)
{
	int res;
	int nleft = size;
	char* ptr = net_buffer;
	while (nleft > 0)
	{
		res = recv(client_socket, ptr, nleft, 0);
		fprintf(stderr, "[try_recv]\treceived %d\n", res);
		if (res < 0)
		{
			fprintf(stderr, "[try_recv]\terrno: %d\n", res);
			perror("try_recv");
			exit(-1);
		}
		else if (res == 0)
		{
			fprintf(stderr, "[try_recv]\tconnection closed.\n");
			fprintf(stderr, "[try_recv]\tnow pagefault total time = %d, syscall total time = %d\n", pgfault_time_sum, syscall_time_sum);
			exit(0);
		}
		else
		{
			
			nleft -= res;
			ptr += res;
			if (nleft)
				fprintf(stderr, "[try_recv]\treceived %d B, %d left.\n", res, nleft);
		}
		
	}
	
	return size;
}


static int autoSend(int Fd,char* buf, int length, int flag)
{
	char* ptr = buf;
	int nleft = length, res;
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
	return length;
}
