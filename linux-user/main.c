/*
 *  qemu user main
 *
 *  Copyright (c) 2003-2008 Fabrice Bellard
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */
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

char *exec_path;

int singlestep;
static const char *filename;
static const char *argv0;
static int gdbstub_port;
static envlist_t *envlist;
static const char *cpu_model;
static const char *cpu_type;
unsigned long mmap_min_addr;
unsigned long guest_base;
int have_guest_base;
typedef struct gst_thrd_info_t{
    int server_idx;
    int thread_idx;
} gst_thrd_info_t;
int cas_count = 0;
int ldex_count = 0;
int stex_count = 0;

extern __thread int offload_mode; /* 1: server, 2: client  3: exec*/
extern void exec_func(void);
static void handler_arg_nodenumber(const char * arg);
static void handler_arg_threadgroup(const char*);



/*
 * When running 32-on-64 we should make sure we can fit all of the possible
 * guest address space into a contiguous chunk of virtual host memory.
 *
 * This way we will never overlap with our own libraries or binaries or stack
 * or anything else that QEMU maps.
 *
 * Many cpus reserve the high bit (or more than one for some 64-bit cpus)
 * of the address for the kernel.  Some cpus rely on this and user space
 * uses the high bit(s) for pointer tagging and the like.  For them, we
 * must preserve the expected address space.
 */
#ifndef MAX_RESERVED_VA
# if HOST_LONG_BITS > TARGET_VIRT_ADDR_SPACE_BITS
#  if TARGET_VIRT_ADDR_SPACE_BITS == 32 && \
      (TARGET_LONG_BITS == 32 || defined(TARGET_ABI32))
/* There are a number of places where we assign reserved_va to a variable
   of type abi_ulong and expect it to fit.  Avoid the last page.  */
#   define MAX_RESERVED_VA  (0xfffffffful & TARGET_PAGE_MASK)
#  else
#   define MAX_RESERVED_VA  (1ul << TARGET_VIRT_ADDR_SPACE_BITS)
#  endif
# else
#  define MAX_RESERVED_VA  0
# endif
#endif

unsigned long reserved_va;

static void usage(int exitcode);

static const char *interp_prefix = CONFIG_QEMU_INTERP_PREFIX;
const char *qemu_uname_release;

/* XXX: on x86 MAP_GROWSDOWN only works if ESP <= address + 32, so
   we allocate a bigger stack. Need a better solution, for example
   by remapping the process stack directly at the right place */
unsigned long guest_stack_size = 8 * 1024 * 1024UL;

void gemu_log(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

#if defined(TARGET_I386)
int cpu_get_pic_interrupt(CPUX86State *env)
{
    return -1;
}
#endif

/***********************************************************/
/* Helper routines for implementing atomic operations.  */

/* Make sure everything is in a consistent state for calling fork().  */
void fork_start(void)
{
    start_exclusive();
    mmap_fork_start();
    cpu_list_lock();
}

void fork_end(int child)
{
    mmap_fork_end(child);
    if (child) {
        CPUState *cpu, *next_cpu;
        /* Child processes created by fork() only have a single thread.
           Discard information about the parent threads.  */
        CPU_FOREACH_SAFE(cpu, next_cpu) {
            if (cpu != thread_cpu) {
                QTAILQ_REMOVE(&cpus, cpu, node);
            }
        }
        qemu_init_cpu_list();
        gdbserver_fork(thread_cpu);
        /* qemu_init_cpu_list() takes care of reinitializing the
         * exclusive state, so we don't need to end_exclusive() here.
         */
    } else {
        cpu_list_unlock();
        end_exclusive();
    }
}

__thread CPUState *thread_cpu;

bool qemu_cpu_is_self(CPUState *cpu)
{
    return thread_cpu == cpu;
}

void qemu_cpu_kick(CPUState *cpu)
{
    cpu_exit(cpu);
}

void task_settid(TaskState *ts)
{
    if (ts->ts_tid == 0) {
        ts->ts_tid = (pid_t)syscall(SYS_gettid);
    }
}

void stop_all_tasks(void)
{
    /*
     * We trust that when using NPTL, start_exclusive()
     * handles thread stopping correctly.
     */
    start_exclusive();
}

/* Assumes contents are already zeroed.  */
void init_task_state(TaskState *ts)
{
    ts->used = 1;
}

CPUArchState *cpu_copy(CPUArchState *env)
{
    CPUState *cpu = ENV_GET_CPU(env);
    CPUState *new_cpu = cpu_create(cpu_type);
    CPUArchState *new_env = new_cpu->env_ptr;
    CPUBreakpoint *bp;
    CPUWatchpoint *wp;

    /* Reset non arch specific state */
    cpu_reset(new_cpu);

    memcpy(new_env, env, sizeof(CPUArchState));

    /* Clone all break/watchpoints.
       Note: Once we support ptrace with hw-debug register access, make sure
       BP_CPU break/watchpoints are handled correctly on clone. */
    QTAILQ_INIT(&new_cpu->breakpoints);
    QTAILQ_INIT(&new_cpu->watchpoints);
    QTAILQ_FOREACH(bp, &cpu->breakpoints, entry) {
        cpu_breakpoint_insert(new_cpu, bp->pc, bp->flags, NULL);
    }
    QTAILQ_FOREACH(wp, &cpu->watchpoints, entry) {
        cpu_watchpoint_insert(new_cpu, wp->vaddr, wp->len, wp->flags, NULL);
    }

    return new_env;
}

static void handle_arg_help(const char *arg)
{
    usage(EXIT_SUCCESS);
}

static void handle_arg_log(const char *arg)
{
    int mask;

    mask = qemu_str_to_log_mask(arg);
    if (!mask) {
        qemu_print_log_usage(stdout);
        exit(EXIT_FAILURE);
    }
    qemu_log_needs_buffers();
    qemu_set_log(mask);
}

static void handle_arg_dfilter(const char *arg)
{
    qemu_set_dfilter_ranges(arg, NULL);
}

static void handle_arg_log_filename(const char *arg)
{
    qemu_set_log_filename(arg, &error_fatal);
}

static void handle_arg_set_env(const char *arg)
{
    char *r, *p, *token;
    r = p = strdup(arg);
    while ((token = strsep(&p, ",")) != NULL) {
        if (envlist_setenv(envlist, token) != 0) {
            usage(EXIT_FAILURE);
        }
    }
    free(r);
}

static void handle_arg_unset_env(const char *arg)
{
    char *r, *p, *token;
    r = p = strdup(arg);
    while ((token = strsep(&p, ",")) != NULL) {
        if (envlist_unsetenv(envlist, token) != 0) {
            usage(EXIT_FAILURE);
        }
    }
    free(r);
}

static void handle_arg_argv0(const char *arg)
{
    argv0 = strdup(arg);
}

static void handle_arg_stack_size(const char *arg)
{
    char *p;
    guest_stack_size = strtoul(arg, &p, 0);
    if (guest_stack_size == 0) {
        usage(EXIT_FAILURE);
    }

    if (*p == 'M') {
        guest_stack_size *= MiB;
    } else if (*p == 'k' || *p == 'K') {
        guest_stack_size *= KiB;
    }
}

static void handle_arg_ld_prefix(const char *arg)
{
    interp_prefix = strdup(arg);
}

static void handle_arg_pagesize(const char *arg)
{
    qemu_host_page_size = atoi(arg);
    if (qemu_host_page_size == 0 ||
        (qemu_host_page_size & (qemu_host_page_size - 1)) != 0) {
        fprintf(stderr, "page size must be a power of two\n");
        exit(EXIT_FAILURE);
    }
}

static void handle_arg_randseed(const char *arg)
{
    unsigned long long seed;

    if (parse_uint_full(arg, &seed, 0) != 0 || seed > UINT_MAX) {
        fprintf(stderr, "Invalid seed number: %s\n", arg);
        exit(EXIT_FAILURE);
    }
    srand(seed);
}

static void handle_arg_gdb(const char *arg)
{
    gdbstub_port = atoi(arg);
}

static void handle_arg_uname(const char *arg)
{
    qemu_uname_release = strdup(arg);
}

static void handle_arg_cpu(const char *arg)
{
    cpu_model = strdup(arg);
    if (cpu_model == NULL || is_help_option(cpu_model)) {
        /* XXX: implement xxx_cpu_list for targets that still miss it */
#if defined(cpu_list)
        cpu_list(stdout, &fprintf);
#endif
        exit(EXIT_FAILURE);
    }
}

static void handle_arg_guest_base(const char *arg)
{
    guest_base = strtol(arg, NULL, 0);
    have_guest_base = 1;
}

static void handle_arg_reserved_va(const char *arg)
{
    char *p;
    int shift = 0;
    reserved_va = strtoul(arg, &p, 0);
    switch (*p) {
    case 'k':
    case 'K':
        shift = 10;
        break;
    case 'M':
        shift = 20;
        break;
    case 'G':
        shift = 30;
        break;
    }
    if (shift) {
        unsigned long unshifted = reserved_va;
        p++;
        reserved_va <<= shift;
        if (reserved_va >> shift != unshifted
            || (MAX_RESERVED_VA && reserved_va > MAX_RESERVED_VA)) {
            fprintf(stderr, "Reserved virtual address too big\n");
            exit(EXIT_FAILURE);
        }
    }
    if (*p) {
        fprintf(stderr, "Unrecognised -R size suffix '%s'\n", p);
        exit(EXIT_FAILURE);
    }
}

static void handle_arg_singlestep(const char *arg)
{
    singlestep = 1;
}

static void handle_arg_strace(const char *arg)
{
    do_strace = 1;
}

static void handle_arg_version(const char *arg)
{
    printf("qemu-" TARGET_NAME " version " QEMU_FULL_VERSION
           "\n" QEMU_COPYRIGHT "\n");
    exit(EXIT_SUCCESS);
}

static char *trace_file;
static void handle_arg_trace(const char *arg)
{
    g_free(trace_file);
    trace_file = trace_opt_parse(arg);
}

static void handle_arg_offloadmode(const char *arg)
{
	
	if (strcmp(arg, "server") == 0)
	{
		offload_mode = 1;
	}
	else if (strcmp(arg, "client") == 0)
	{
		offload_mode = 2;
	}
	return;
}
int nodes = 1;
static void handle_arg_nodenumber(const char *arg)
{
    nodes = atoi(arg);
}
#define GUEST_THREAD_MAX 128
int gst_thrd_plc[GUEST_THREAD_MAX] = //{0,0,1,1,2,2,3,3,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1};
            //{0,1,2,3,4,5,6,7,8,9,10,11};
{

};
gst_thrd_info_t gst_thrd_info[GUEST_THREAD_MAX];
int group = 1;
static void handle_arg_threadgroup(const char *arg)
{
    fprintf(stderr, "nodes %d\n", nodes);
    int group = atoi(arg);
    if(nodes == 1)
        return;
    if(nodes <=0)
    {
        printf(stderr, "node must be greater than 0");
    }
for (int i = 0; i < GUEST_THREAD_MAX; i += group)
        {
            for (int j = i; j < i + group && j < GUEST_THREAD_MAX; j++)
            {
                gst_thrd_plc[j] = (i / group)  % (nodes-1) +1;
            }
        }
/*
        for (int i = 0; i < GUEST_THREAD_MAX; i++)
        {
            printf("%d ", gst_thrd_plc[i]);
        }
        fprintf(stderr, "\n");
        */

    }

extern int offload_server_idx;
extern __thread int offload_client_idx;
static void handle_arg_offloadidx(const char *arg)
{
	offload_server_idx = atoi(arg);
}


struct qemu_argument {
    const char *argv;
    const char *env;
    bool has_arg;
    void (*handle_opt)(const char *arg);
    const char *example;
    const char *help;
};

static const struct qemu_argument arg_table[] = {
    {"h",          "",                 false, handle_arg_help,
     "",           "print this help"},
    {"help",       "",                 false, handle_arg_help,
     "",           ""},
    {"g",          "QEMU_GDB",         true,  handle_arg_gdb,
     "port",       "wait gdb connection to 'port'"},
    {"L",          "QEMU_LD_PREFIX",   true,  handle_arg_ld_prefix,
     "path",       "set the elf interpreter prefix to 'path'"},
    {"s",          "QEMU_STACK_SIZE",  true,  handle_arg_stack_size,
     "size",       "set the stack size to 'size' bytes"},
    {"cpu",        "QEMU_CPU",         true,  handle_arg_cpu,
     "model",      "select CPU (-cpu help for list)"},
    {"E",          "QEMU_SET_ENV",     true,  handle_arg_set_env,
     "var=value",  "sets targets environment variable (see below)"},
    {"U",          "QEMU_UNSET_ENV",   true,  handle_arg_unset_env,
     "var",        "unsets targets environment variable (see below)"},
    {"0",          "QEMU_ARGV0",       true,  handle_arg_argv0,
     "argv0",      "forces target process argv[0] to be 'argv0'"},
    {"r",          "QEMU_UNAME",       true,  handle_arg_uname,
     "uname",      "set qemu uname release string to 'uname'"},
    {"B",          "QEMU_GUEST_BASE",  true,  handle_arg_guest_base,
     "address",    "set guest_base address to 'address'"},
    {"R",          "QEMU_RESERVED_VA", true,  handle_arg_reserved_va,
     "size",       "reserve 'size' bytes for guest virtual address space"},
    {"d",          "QEMU_LOG",         true,  handle_arg_log,
     "item[,...]", "enable logging of specified items "
     "(use '-d help' for a list of items)"},
    {"dfilter",    "QEMU_DFILTER",     true,  handle_arg_dfilter,
     "range[,...]","filter logging based on address range"},
    {"D",          "QEMU_LOG_FILENAME", true, handle_arg_log_filename,
     "logfile",     "write logs to 'logfile' (default stderr)"},
    {"p",          "QEMU_PAGESIZE",    true,  handle_arg_pagesize,
     "pagesize",   "set the host page size to 'pagesize'"},
    {"singlestep", "QEMU_SINGLESTEP",  false, handle_arg_singlestep,
     "",           "run in singlestep mode"},
    {"strace",     "QEMU_STRACE",      false, handle_arg_strace,
     "",           "log system calls"},
    {"seed",       "QEMU_RAND_SEED",   true,  handle_arg_randseed,
     "",           "Seed for pseudo-random number generator"},
    {"trace",      "QEMU_TRACE",       true,  handle_arg_trace,
     "",           "[[enable=]<pattern>][,events=<file>][,file=<file>]"},
    {"version",    "QEMU_VERSION",     false, handle_arg_version,
     "",           "display version information and exit"},
	 {"offloadmode",	"OFFLOAD_MODE",		true, handle_arg_offloadmode,
	 "client",		"set offload mode, client/server"},
	 {"offloadindex",	"OFFLOAD_IDX",		true, handle_arg_offloadidx,
	 "1",		"set offload server index"},
     {"n", "node number" , true , handle_arg_nodenumber, "1", "set node number"},
     {"threadgroup", "thread number of a group", true, handle_arg_threadgroup, "1" , "set the thread number of a group"},
	 
    {NULL, NULL, false, NULL, NULL, NULL}
};

static void usage(int exitcode)
{
    const struct qemu_argument *arginfo;
    int maxarglen;
    int maxenvlen;

    printf("usage: qemu-" TARGET_NAME " [options] program [arguments...]\n"
           "Linux CPU emulator (compiled for " TARGET_NAME " emulation)\n"
           "\n"
           "Options and associated environment variables:\n"
           "\n");

    /* Calculate column widths. We must always have at least enough space
     * for the column header.
     */
    maxarglen = strlen("Argument");
    maxenvlen = strlen("Env-variable");

    for (arginfo = arg_table; arginfo->handle_opt != NULL; arginfo++) {
        int arglen = strlen(arginfo->argv);
        if (arginfo->has_arg) {
            arglen += strlen(arginfo->example) + 1;
        }
        if (strlen(arginfo->env) > maxenvlen) {
            maxenvlen = strlen(arginfo->env);
        }
        if (arglen > maxarglen) {
            maxarglen = arglen;
        }
    }

    printf("%-*s %-*s Description\n", maxarglen+1, "Argument",
            maxenvlen, "Env-variable");

    for (arginfo = arg_table; arginfo->handle_opt != NULL; arginfo++) {
        if (arginfo->has_arg) {
            printf("-%s %-*s %-*s %s\n", arginfo->argv,
                   (int)(maxarglen - strlen(arginfo->argv) - 1),
                   arginfo->example, maxenvlen, arginfo->env, arginfo->help);
        } else {
            printf("-%-*s %-*s %s\n", maxarglen, arginfo->argv,
                    maxenvlen, arginfo->env,
                    arginfo->help);
        }
    }

    printf("\n"
           "Defaults:\n"
           "QEMU_LD_PREFIX  = %s\n"
           "QEMU_STACK_SIZE = %ld byte\n",
           interp_prefix,
           guest_stack_size);

    printf("\n"
           "You can use -E and -U options or the QEMU_SET_ENV and\n"
           "QEMU_UNSET_ENV environment variables to set and unset\n"
           "environment variables for the target process.\n"
           "It is possible to provide several variables by separating them\n"
           "by commas in getsubopt(3) style. Additionally it is possible to\n"
           "provide the -E and -U options multiple times.\n"
           "The following lines are equivalent:\n"
           "    -E var1=val2 -E var2=val2 -U LD_PRELOAD -U LD_DEBUG\n"
           "    -E var1=val2,var2=val2 -U LD_PRELOAD,LD_DEBUG\n"
           "    QEMU_SET_ENV=var1=val2,var2=val2 QEMU_UNSET_ENV=LD_PRELOAD,LD_DEBUG\n"
           "Note that if you provide several changes to a single variable\n"
           "the last change will stay in effect.\n"
           "\n"
           QEMU_HELP_BOTTOM "\n");

    exit(exitcode);
}

static int parse_args(int argc, char **argv)
{
    const char *r;
    int optind;
    const struct qemu_argument *arginfo;

    for (arginfo = arg_table; arginfo->handle_opt != NULL; arginfo++) {
        if (arginfo->env == NULL) {
            continue;
        }

        r = getenv(arginfo->env);
        if (r != NULL) {
            arginfo->handle_opt(r);
        }
    }

    optind = 1;
    for (;;) {
        if (optind >= argc) {
            break;
        }
        r = argv[optind];
		
        if (r[0] != '-') {
            break;
        }
        optind++;
        r++;
        if (!strcmp(r, "-")) {
            break;
        }
        /* Treat --foo the same as -foo.  */
        if (r[0] == '-') {
            r++;
        }
		
        for (arginfo = arg_table; arginfo->handle_opt != NULL; arginfo++) {
			
			
            if (!strcmp(r, arginfo->argv)) {
                if (arginfo->has_arg) {
                    if (optind >= argc) {
                        (void) fprintf(stderr,
                            "qemu: missing argument for option '%s'\n", r);
                        exit(EXIT_FAILURE);
                    }
                    arginfo->handle_opt(argv[optind]);
                    optind++;
                } else {
                    arginfo->handle_opt(NULL);
                }
                break;
            }
        }

        /* no option matched the current argv */
        if (arginfo->handle_opt == NULL) {
            (void) fprintf(stderr, "qemu: unknown option '%s'\n", r);
            exit(EXIT_FAILURE);
        }
    }

    if (optind >= argc) {
        (void) fprintf(stderr, "qemu: no user program specified\n");
        exit(EXIT_FAILURE);
    }

    filename = argv[optind];
    exec_path = argv[optind];

    return optind;
}

CPUArchState *env_bak;
__thread CPUArchState *thread_env;
//CPUState cpu_backup;
extern void offload_server_start(void);
int offload_count;
extern void* offload_center_server_start(void*);
extern void* offload_center_client_start(void*);
pthread_mutex_t main_exec_mutex;
pthread_cond_t main_exec_cond;
int main_exec_flag;
int g_false_sharing_flag;
pthread_mutex_t master_mprotect_mutex;

pthread_mutex_t offload_center_init_mutex; pthread_cond_t offload_center_init_cond;
void offload_server_extra_init(void);
void offload_server_qemu_init(void);
void offload_server_qemu_init(void)
{
	struct target_pt_regs regs1, *regs = &regs1;
    struct image_info info1, *info = &info1;
    struct linux_binprm bprm;
    TaskState *ts;
    CPUArchState *env;
    CPUState *cpu;

    char **target_environ, **wrk;

	
    int execfd;
	
    module_call_init(MODULE_INIT_TRACE);
    qemu_init_cpu_list();
    module_call_init(MODULE_INIT_QOM);

    envlist = envlist_create();

    /* add current environment into the list */
    for (wrk = environ; *wrk != NULL; wrk++) {
        (void) envlist_setenv(envlist, *wrk);
    }

    /* Read the stack limit from the kernel.  If it's "unlimited",
       then we can do little else besides use the default.  */
    {
        struct rlimit lim;
        if (getrlimit(RLIMIT_STACK, &lim) == 0
				&& lim.rlim_cur != RLIM_INFINITY
				&& lim.rlim_cur == (target_long)lim.rlim_cur) {
            guest_stack_size = lim.rlim_cur;
        }
    }

    cpu_model = NULL;

    srand(time(NULL));

    qemu_add_opts(&qemu_trace_opts);

	

    if (!trace_init_backends()) {
        exit(1);
    }
    trace_init_file(trace_file);

    /* Zero out regs */
    memset(regs, 0, sizeof(struct target_pt_regs));

    /* Zero out image_info */
    memset(info, 0, sizeof(struct image_info));

    memset(&bprm, 0, sizeof (bprm));

    
    execfd = qemu_getauxval(AT_EXECFD);
    if (execfd == 0) {
        execfd = open(filename, O_RDONLY);
        if (execfd < 0) {
            printf("Error while loading %s: %s\n", filename, strerror(errno));
            _exit(EXIT_FAILURE);
        }
    }
    if (cpu_model == NULL) {
        cpu_model = cpu_get_model(get_elf_eflags(execfd));
    }
    cpu_type = parse_cpu_model(cpu_model);

    /* init tcg before creating CPUs and to get qemu_host_page_size */
    tcg_exec_init(0);

    /* Reserving *too* much vm space via mmap can run into problems
       with rlimits, oom due to page table creation, etc.  We will still try it,
       if directed by the command-line option, but not by default.  */
    if (HOST_LONG_BITS == 64 &&
			TARGET_VIRT_ADDR_SPACE_BITS <= 32 &&
			reserved_va == 0) {
        /* reserved_va must be aligned with the host page size
         * as it is used with mmap()
         */
        reserved_va = MAX_RESERVED_VA & qemu_host_page_mask;
    }

    cpu = cpu_create(cpu_type);
    env = cpu->env_ptr;
    cpu_reset(cpu);
	
    thread_cpu = cpu;
	
    if (getenv("QEMU_STRACE")) {
        do_strace = 1;
    }

    if (getenv("QEMU_RAND_SEED")) {
        handle_arg_randseed(getenv("QEMU_RAND_SEED"));
    }

    target_environ = envlist_to_environ(envlist, NULL);
    envlist_free(envlist);

    /*
     * Now that page sizes are configured in tcg_exec_init() we can do
     * proper page alignment for guest_base.
     */
	
	guest_base = 0x3c00f000;
    guest_base = HOST_PAGE_ALIGN(guest_base);

    if (reserved_va || have_guest_base) {
        guest_base = init_guest_space(guest_base, reserved_va, 0,
                                      have_guest_base);
        if (guest_base == (unsigned long)-1) {
            fprintf(stderr, "Unable to reserve 0x%lx bytes of virtual address "
                    "space for use as guest address space (check your virtual "
                    "memory ulimit setting or reserve less using -R option)\n",
                    reserved_va);
            exit(EXIT_FAILURE);
        }

        if (reserved_va) {
            mmap_next_start = reserved_va;
        }
    }

    /*
     * Read in mmap_min_addr kernel parameter.  This value is used
     * When loading the ELF image to determine whether guest_base
     * is needed.  It is also used in mmap_find_vma.
     */
    {
        FILE *fp;

        if ((fp = fopen("/proc/sys/vm/mmap_min_addr", "r")) != NULL) {
            unsigned long tmp;
            if (fscanf(fp, "%lu", &tmp) == 1) {
                mmap_min_addr = tmp;
                qemu_log_mask(CPU_LOG_PAGE, "host mmap_min_addr=0x%lx\n", mmap_min_addr);
            }
            fclose(fp);
        }
    }

    /*
     * Prepare copy of argv vector for target.
     */
   

    /*
     * If argv0 is specified (using '-0' switch) we replace
     * argv[0] pointer with the given one.
     */

    ts = g_new0(TaskState, 1);
    init_task_state(ts);
    /* build Task State */
    ts->info = info;
    ts->bprm = &bprm;
    cpu->opaque = ts;
    task_settid(ts);

	
	
    for (wrk = target_environ; *wrk; wrk++) {
        g_free(*wrk);
    }

    g_free(target_environ);

    if (qemu_loglevel_mask(CPU_LOG_PAGE)) {
        qemu_log("guest_base  0x%lx\n", guest_base);
        log_page_dump();

        qemu_log("start_brk   0x" TARGET_ABI_FMT_lx "\n", info->start_brk);
        qemu_log("end_code    0x" TARGET_ABI_FMT_lx "\n", info->end_code);
        qemu_log("start_code  0x" TARGET_ABI_FMT_lx "\n", info->start_code);
        qemu_log("start_data  0x" TARGET_ABI_FMT_lx "\n", info->start_data);
        qemu_log("end_data    0x" TARGET_ABI_FMT_lx "\n", info->end_data);
        qemu_log("start_stack 0x" TARGET_ABI_FMT_lx "\n", info->start_stack);
        qemu_log("brk         0x" TARGET_ABI_FMT_lx "\n", info->brk);
        qemu_log("entry       0x" TARGET_ABI_FMT_lx "\n", info->entry);
        qemu_log("argv_start  0x" TARGET_ABI_FMT_lx "\n", info->arg_start);
        qemu_log("env_start   0x" TARGET_ABI_FMT_lx "\n",
                 info->arg_end + (abi_ulong)sizeof(abi_ulong));
        qemu_log("auxv_start  0x" TARGET_ABI_FMT_lx "\n", info->saved_auxv);
    }

    target_set_brk(info->brk);
    syscall_init();
    signal_init();

    /* Now that we've loaded the binary, GUEST_BASE is fixed.  Delay
       generating the prologue until now so that the prologue can take
       the real value of GUEST_BASE into account.  */
    tcg_prologue_init(tcg_ctx);
    tcg_region_init();

    target_cpu_copy_regs(env, regs);

    if (gdbstub_port) {
        if (gdbserver_start(gdbstub_port) < 0) {
            fprintf(stderr, "qemu: could not open gdbserver on port %d\n",
                    gdbstub_port);
            exit(EXIT_FAILURE);
        }
        gdb_handlesig(cpu, 0);
    }
	
	
    return;
}
void offload_server_extra_init(void)
{
    // struct target_pt_regs regs1, *regs = &regs1;
    struct image_info info1, *info = &info1;
    struct linux_binprm bprm;
    TaskState *ts;
    CPUArchState *env;
    CPUState *cpu;

    
    cpu = cpu_create(cpu_type);
    cpu_reset(cpu);

    thread_cpu = cpu;

    return;
}
/* To manipulate guest thread's server. 
 * Short for guest thread place*/
int max_server_in_use;

pthread_t center_server_thread;
extern void offload_client_pmd_init(void);
int main(int argc, char **argv, char **envp)
{
    struct target_pt_regs regs1, *regs = &regs1;
    struct image_info info1, *info = &info1;
    struct linux_binprm bprm;
    TaskState *ts;
    CPUArchState *env;
    CPUState *cpu;
    int optind;
    char **target_environ, **wrk;
    char **target_argv;
    int target_argc;
    int i;
    int ret;
    int execfd;
	
	offload_count = -1;
	offload_server_idx = 0;
	optind = parse_args(argc, argv);
	
    if (offload_mode == 1)
	{
		guest_base = 0x3c00f000;
        fprintf(stderr, ">>>>>>>>>>>> server# %d guest_base: %x\n", offload_server_idx, guest_base);
		// offload_server_start();
		// return 0;
	}
	else if (offload_mode == 2)
	{
        /* Process guest thread info, format: [server idx -> thread idx]. */
		fprintf(stderr, ">>>>>>>>>>>> [Master]. Guest thread placement:\n");
        /* Note that 0->0 is the main thread. */
        int server_thread_count[GUEST_THREAD_MAX] = {1, 0};
        int server_idx = 0;
        
        for (int i = 0; i < GUEST_THREAD_MAX; i++) {
            server_idx = gst_thrd_plc[i];
            max_server_in_use = (server_idx > max_server_in_use) ? server_idx : max_server_in_use;
            gst_thrd_info[i].server_idx = server_idx;
            gst_thrd_info[i].thread_idx = server_thread_count[server_idx]++;
            //fprintf(stderr, "Thread %d --> [%d->%d]\n", 
            //            i, gst_thrd_info[i].server_idx, 
            //            gst_thrd_info[i].thread_idx);
            fprintf(stderr, "%d,", gst_thrd_info[i].server_idx);
        }        
        printf("\n");
	}
	else
	{
		fprintf(stderr, "invalid offload mode\n");
		exit(0);
	}

	
    module_call_init(MODULE_INIT_TRACE);
    qemu_init_cpu_list();
    module_call_init(MODULE_INIT_QOM);

    envlist = envlist_create();

    /* add current environment into the list */
    for (wrk = environ; *wrk != NULL; wrk++) {
        (void) envlist_setenv(envlist, *wrk);
    }

    /* Read the stack limit from the kernel.  If it's "unlimited",
       then we can do little else besides use the default.  */
    {
        struct rlimit lim;
        if (getrlimit(RLIMIT_STACK, &lim) == 0
            && lim.rlim_cur != RLIM_INFINITY
            && lim.rlim_cur == (target_long)lim.rlim_cur) {
            guest_stack_size = lim.rlim_cur;
        }
    }

    cpu_model = NULL;

    srand(time(NULL));

    qemu_add_opts(&qemu_trace_opts);

	
	

    if (!trace_init_backends()) {
        exit(1);
    }
    trace_init_file(trace_file);

    /* Zero out regs */
    memset(regs, 0, sizeof(struct target_pt_regs));

    /* Zero out image_info */
    memset(info, 0, sizeof(struct image_info));

    memset(&bprm, 0, sizeof (bprm));

    /* Scan interp_prefix dir for replacement files. */
    init_paths(interp_prefix);

    init_qemu_uname_release();

    execfd = qemu_getauxval(AT_EXECFD);
    if (execfd == 0) {
        execfd = open(filename, O_RDONLY);
        if (execfd < 0) {
            printf("Error while loading %s: %s\n", filename, strerror(errno));
            _exit(EXIT_FAILURE);
        }
    }
    if (cpu_model == NULL) {
        cpu_model = cpu_get_model(get_elf_eflags(execfd));
    }
    cpu_type = parse_cpu_model(cpu_model);

    /* init tcg before creating CPUs and to get qemu_host_page_size */
    tcg_exec_init(0);

    /* Reserving *too* much vm space via mmap can run into problems
       with rlimits, oom due to page table creation, etc.  We will still try it,
       if directed by the command-line option, but not by default.  */
    if (HOST_LONG_BITS == 64 &&
        TARGET_VIRT_ADDR_SPACE_BITS <= 32 &&
        reserved_va == 0) {
        /* reserved_va must be aligned with the host page size
         * as it is used with mmap()
         */
        reserved_va = MAX_RESERVED_VA & qemu_host_page_mask;
    }

    cpu = cpu_create(cpu_type);
    env = cpu->env_ptr;
    cpu_reset(cpu);
	
    thread_cpu = cpu;
	
    if (getenv("QEMU_STRACE")) {
        do_strace = 1;
    }

    if (getenv("QEMU_RAND_SEED")) {
        handle_arg_randseed(getenv("QEMU_RAND_SEED"));
    }

    target_environ = envlist_to_environ(envlist, NULL);
    envlist_free(envlist);

    /*
     * Now that page sizes are configured in tcg_exec_init() we can do
     * proper page alignment for guest_base.
     */
	
	guest_base = 0x3c00f000;
    guest_base = HOST_PAGE_ALIGN(guest_base);

    if (reserved_va || have_guest_base) {
        guest_base = init_guest_space(guest_base, reserved_va, 0,
                                      have_guest_base);
        if (guest_base == (unsigned long)-1) {
            fprintf(stderr, "Unable to reserve 0x%lx bytes of virtual address "
                    "space for use as guest address space (check your virtual "
                    "memory ulimit setting or reserve less using -R option)\n",
                    reserved_va);
            exit(EXIT_FAILURE);
        }

        if (reserved_va) {
            mmap_next_start = reserved_va;
        }
    }
    /*
     * Read in mmap_min_addr kernel parameter.  This value is used
     * When loading the ELF image to determine whether guest_base
     * is needed.  It is also used in mmap_find_vma.
     */
    {
        FILE *fp;

        if ((fp = fopen("/proc/sys/vm/mmap_min_addr", "r")) != NULL) {
            unsigned long tmp;
            if (fscanf(fp, "%lu", &tmp) == 1) {
                mmap_min_addr = tmp;
                qemu_log_mask(CPU_LOG_PAGE, "host mmap_min_addr=0x%lx\n", mmap_min_addr);
            }
            fclose(fp);
        }
    }

    /*
     * Prepare copy of argv vector for target.
     */
    target_argc = argc - optind;
    target_argv = calloc(target_argc + 1, sizeof (char *));
    if (target_argv == NULL) {
	(void) fprintf(stderr, "Unable to allocate memory for target_argv\n");
	exit(EXIT_FAILURE);
    }

    /*
     * If argv0 is specified (using '-0' switch) we replace
     * argv[0] pointer with the given one.
     */
    i = 0;
    if (argv0 != NULL) {
        target_argv[i++] = strdup(argv0);
    }
    for (; i < target_argc; i++) {
        target_argv[i] = strdup(argv[optind + i]);
    }
    target_argv[target_argc] = NULL;

    ts = g_new0(TaskState, 1);
    init_task_state(ts);
    /* build Task State */
    ts->info = info;
    ts->bprm = &bprm;
    cpu->opaque = ts;
    task_settid(ts);

    ret = loader_exec(execfd, filename, target_argv, target_environ, regs,
        info, &bprm);
    if (ret != 0) {
        printf("Error while loading %s: %s\n", filename, strerror(-ret));
        _exit(EXIT_FAILURE);
    }

    for (wrk = target_environ; *wrk; wrk++) {
        g_free(*wrk);
    }
    g_free(target_environ);

    if (qemu_loglevel_mask(CPU_LOG_PAGE)) {
        qemu_log("guest_base  0x%lx\n", guest_base);
        log_page_dump();

        qemu_log("start_brk   0x" TARGET_ABI_FMT_lx "\n", info->start_brk);
        qemu_log("end_code    0x" TARGET_ABI_FMT_lx "\n", info->end_code);
        qemu_log("start_code  0x" TARGET_ABI_FMT_lx "\n", info->start_code);
        qemu_log("start_data  0x" TARGET_ABI_FMT_lx "\n", info->start_data);
        qemu_log("end_data    0x" TARGET_ABI_FMT_lx "\n", info->end_data);
        qemu_log("start_stack 0x" TARGET_ABI_FMT_lx "\n", info->start_stack);
        qemu_log("brk         0x" TARGET_ABI_FMT_lx "\n", info->brk);
        qemu_log("entry       0x" TARGET_ABI_FMT_lx "\n", info->entry);
        qemu_log("argv_start  0x" TARGET_ABI_FMT_lx "\n", info->arg_start);
        qemu_log("env_start   0x" TARGET_ABI_FMT_lx "\n",
                 info->arg_end + (abi_ulong)sizeof(abi_ulong));
        qemu_log("auxv_start  0x" TARGET_ABI_FMT_lx "\n", info->saved_auxv);
    }

    target_set_brk(info->brk);
    syscall_init();
    signal_init();

    /* Now that we've loaded the binary, GUEST_BASE is fixed.  Delay
       generating the prologue until now so that the prologue can take
       the real value of GUEST_BASE into account.  */
    tcg_prologue_init(tcg_ctx);
    tcg_region_init();

    target_cpu_copy_regs(env, regs);

    if (gdbstub_port) {
        if (gdbserver_start(gdbstub_port) < 0) {
            fprintf(stderr, "qemu: could not open gdbserver on port %d\n",
                    gdbstub_port);
            exit(EXIT_FAILURE);
        }
        gdb_handlesig(cpu, 0);
    }
    env_bak = env;
    thread_env = env;
    if (offload_mode == 2) {

        if (!parallel_cpus) {
            parallel_cpus = true;
            tb_flush(cpu);
        }
        fprintf(stderr, "offload client mode\n");
        
        //fprintf(stderr, "size: %x, mask: %x\n", qemu_host_page_size, qemu_host_page_mask);
        offload_server_idx = 0;
        offload_client_idx = 0;
        offload_client_pmd_init();
        
        // if this is center, we need 2 more threads to play as worker/shadow.
        
        //new_thread_info new_info;
        /*CPUArchState new_env;
        offload_get_new_thread_info(env, &new_env);*/
        //pthread_mutex_init(&offload_center_clone_mutex, NULL);


        pthread_mutex_init(&offload_center_init_mutex, NULL);
        pthread_mutex_init(&master_mprotect_mutex, NULL);
        pthread_cond_init(&offload_center_init_cond, NULL);
        
        pthread_create(&center_server_thread, NULL, offload_center_server_start, (void *) NULL);
        
        pthread_mutex_lock(&offload_center_init_mutex);
        pthread_cond_wait(&offload_center_init_cond, &offload_center_init_mutex);
        pthread_mutex_unlock(&offload_center_init_mutex);
        fprintf(stderr, "Connecting online server from 1 to %d\n", max_server_in_use);
        for (int i = 1; i <= max_server_in_use; i++) {
            extern void offload_connect_online_server(int idx);
            offload_connect_online_server(i);
        
        }
    }
    if (offload_mode == 1)
	{
		guest_base = 0x3c00f000;
        fprintf(stderr, ">>>>>>>>>>>> server# %d guest_base: %x "
                        "sizeof envCPUArchState %d sizeof cpu CPUState %d\n", 
                        offload_server_idx, guest_base, sizeof(CPUArchState), sizeof(CPUState));
		
        /* Create daemonize thread and wait to be ready. */
        pthread_mutex_init(&main_exec_mutex, NULL);
        pthread_cond_init(&main_exec_cond, NULL);
        /* If this is our first additional thread, we need to ensure we
         * generate code for parallel execution and flush old translations.
         */
        if (!parallel_cpus) {
            parallel_cpus = true;
            tb_flush(cpu);
        }
        main_exec_flag = 0;
        pthread_t server_t;
        extern void *offload_server_start_thread(void*);
        pthread_create(&server_t, NULL, offload_server_start_thread, NULL);
        pthread_mutex_lock(&main_exec_mutex);
        while (main_exec_flag == 0) {
            pthread_cond_wait(&main_exec_cond, &main_exec_mutex);
        }
        pthread_mutex_unlock(&main_exec_mutex);
        /* Never reaches here. */
        exit(56);
		exec_func();
	}
	offload_mode = 3;
	
    //sleep(1000000000);
    cpu_loop(env);
    /* never exits */
    return 0;
}

