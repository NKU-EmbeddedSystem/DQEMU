#include "offload_common.h"
#include <sys/timeb.h>
#define MUTEX_LIST_MAX 10

__thread char *p;

pthread_mutex_t global_counter_mutex = PTHREAD_MUTEX_INITIALIZER;
int global_counter;
int client_port_of(int idx)
{
	return PORT_BASE + idx * 2;
}


int server_port_of(int idx)
{
	return PORT_BASE + idx * 2 + 1;
}

__thread int offload_mode;
int offload_server_idx;
__thread int offload_client_idx;
__thread int offload_thread_idx;



#define PRTCTRL_NONE "\e[0;0m"
#define PRTCTRL_RED "\e[0;31m"
#define PRTCTRL_GREEN "\e[0;32m"
#define PRTCTRL_YELLO "\e[0;33m"
#define PRTCTRL_BLUE "\e[0;34m"
#define PRTCTRL_CYN "\e[0;36m"
#define PRTCTRL_PURPLE "\e[0;35m"
#define DEBUG 0
extern FILE* qemu_logfile;
void offload_log(FILE *f, const char *c, ...)
{

    if (!qemu_logfile) {
        return;
    }
	struct timeb t;
    ftime(&t);
	char tmp[1000] = "";
	int timeSec = t.time % 60;
	t.time /= 60;
	int timeMin = t.time % 60;
	if (offload_mode == 1)
	{
		sprintf(tmp, PRTCTRL_RED "[server #%d]%d:%d:%d\t", offload_server_idx, timeMin, timeSec, t.millitm);
	}
	else if (offload_mode == 2)
	{
		sprintf(tmp, PRTCTRL_GREEN "[client #%d]%d:%d:%d\t", offload_client_idx, timeMin, timeSec, t.millitm);
	}
	else if (offload_mode == 3)
	{
		sprintf(tmp, PRTCTRL_YELLO "[exec #%d->%d]%d:%d:%d\t", offload_server_idx, offload_thread_idx, timeMin, timeSec, t.millitm);
	}
	else if (offload_mode == 4)
	{
		sprintf(tmp, PRTCTRL_BLUE "[syscall #%d]%d:%d:%d\t", offload_client_idx, timeMin, timeSec, t.millitm);
	}
	else if (offload_mode == 5)
	{
		sprintf(tmp, PRTCTRL_CYN "[client thread #%d]%d:%d:%d\t", offload_client_idx, timeMin, timeSec, t.millitm);
	}
	else if (offload_mode == 6)
	{
		sprintf(tmp, PRTCTRL_PURPLE "[exec #%d->%d]%d:%d:%d\t", offload_server_idx, offload_thread_idx, timeMin, timeSec, t.millitm);
	}
	strcat(tmp, c);
	strcat(tmp, PRTCTRL_NONE);
    va_list args;
    va_start(args, tmp);
    vfprintf(f, tmp, args);
    va_end(args);
}
