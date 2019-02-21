#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <signal.h>
#include "utility.h"

#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <syslog.h>
#include <fcntl.h>
#include <ctype.h>
#include <rtk/utility.h>
#include "signal.h"
#include <arpa/inet.h>
#include <pthread.h>

static int dslite_thread_enabled = 0;
static pthread_t id = 0;
static int debug = 1;

static void log_pid()
{
	FILE *f;
	pid_t pid;
	pid = getpid();

	if((f = fopen("/var/run/autoSimu.pid", "w")) == NULL)
		return;
	fprintf(f, "%d\n", pid);
	fclose(f);
}

static void setup_dnsmasq(int signo)
{
#if defined(CONFIG_USER_DNSMASQ_DNSMASQ) || defined(CONFIG_USER_DNSMASQ_DNSMASQ245)
	cmd_set_dns_config(NULL);	
	restart_dnsrelay();
#endif
}

void exit_Thread()
{
	if(debug)
		printf("[%s:%d][SIMU]Exit thread[%lu]\n",__func__,__LINE__, id);
    dslite_thread_enabled = 0;
    id = 0;
	pthread_exit("Exit");
}

void* thread_setup_dslite(void *data)
{
	MIB_CE_ATM_VC_T Entry;
	int i,entryNum,entry_index;
	int retry_count=0;
	char cmd[100];
	char filename[64];
	char dns[64]={0}, aftr[64]={0};
	char aftr_addr_str[40]={0},tmpBuf[64]={0};
	unsigned int ret=0;
    struct ipv6_ifaddr ip6_addr;
	//sigset_t newmask;
	
	dslite_thread_enabled = 1;

	signal(SIGALRM, exit_Thread);
	//sigemptyset(&newmask);
	//sigaddset(&newmask, SIGUSR1);
	//pthread_sigmask(SIG_BLOCK, &newmask, NULL);
	
	entryNum = mib_chain_total(MIB_SIMU_ATM_VC_TBL);
	for (i=0; i<entryNum; i++) 
	{
		mib_chain_get(MIB_SIMU_ATM_VC_TBL, i, &Entry);
		if(Entry.dslite_enable==1)
		{
			entry_index = i;
			break;
		}
	}

	if(i==entryNum)
	{
		if(debug)
			printf("[SIMU]No SIMU_ATM_VC_TBL interface enable dslite.\n");
		goto leave;
	}

	snprintf(filename, 64, "/var/%sppp7.leases", DHCPCV6STR);
	do{
		ret = getOptionFromleases(filename, NULL, dns, aftr);
		if(0==Entry.dslite_aftr_mode)
		{
			if(0x4==(ret&0x4))
			{
				memcpy(Entry.dslite_aftr_hostname, aftr, 64);
			}
			else
			{
				retry_count++;
                if(debug)
				    printf("[SIMU]no aftr got, retry_count=%d\n", retry_count);
				if(retry_count > 2)
					break;
				sleep(2);
				continue;
			}
		}

        if(inet_pton(AF_INET6, Entry.dslite_aftr_hostname, &ip6_addr)==1)
        {
            //aftr is a IPv6 Address, no need to query dns.
            memcpy(Entry.dslite_aftr_addr, &ip6_addr, sizeof(struct in6_addr));
            mib_chain_update(MIB_SIMU_ATM_VC_TBL, &Entry, entry_index);
            goto leave;
        }
		if(0x0==(ret&0x2))
		{
			retry_count++;
            if(debug)
			    printf("[SIMU]no dns got, retry_count=%d\n", retry_count);
			if(retry_count > 2)
				break;
			sleep(2);
			continue;
		}
        if(debug)
			printf("[SIMU]Entry.dslite_aftr_hostname=%s\n", Entry.dslite_aftr_hostname);
		setup_dnsmasq(0);
		//mib_chain_get(MIB_SIMU_ATM_VC_TBL, i, &Entry);
		if((Entry.dslite_aftr_hostname[0]!=0)){
			if(debug)
				printf("[SIMU]Aftr_Host[%s] , Do DNS Query for it!\n", Entry.dslite_aftr_hostname);
			query_aftr(Entry.dslite_aftr_hostname,Entry.dslite_aftr_addr, aftr_addr_str);
		}
		else
		{
			if(debug)
				printf("[SIMU]Entry.dslite_aftr_hostname==NULL\n");
			break;
		}

		if((strcasecmp(aftr_addr_str, tmpBuf)==0)||(strcasecmp(aftr_addr_str, "fe80::1")==0)){
			if(debug)
				printf("[SIMU]Query %s, result is %s, dns not ready!\n",Entry.dslite_aftr_hostname,aftr_addr_str);
			break;
		}
		else
		{
			if(debug)
				printf("[SIMU]DNS OK, Host[%s], Addr=%s\n",Entry.dslite_aftr_hostname, aftr_addr_str);
			mib_chain_update(MIB_SIMU_ATM_VC_TBL, &Entry, entry_index);
			break;
		}

		retry_count++;
	}while(retry_count<3);
	//printf("[SIMU]Finish set DS-Lite.\n");
	//inet_ntop(AF_INET6, (const void *) pEntry.Ipv6Addr, str_ip, 64);
	//inet_ntop(AF_INET6, (const void *) pEntry.dslite_aftr_addr, str_gateway, 64);

leave:
	dslite_thread_enabled = 0;
    id = 0;
	if(debug)
		printf("[%s:%d][SIMU] Leaving thread.. for dslite\n",__func__,__LINE__);

	return NULL;
}

void setup_dslite()
{
	sigset_t newmask;
	if(dslite_thread_enabled==0){
		sigemptyset(&newmask);
		sigprocmask(SIG_BLOCK, &newmask, NULL);
		pthread_create(&id, NULL, thread_setup_dslite, NULL);
		if(debug)
			printf("[%s:%d][SIMU]Create new theread[%lu] for dslite\n",__func__,__LINE__, id);
		sigemptyset(&newmask);
		sigaddset(&newmask, SIGALRM);
		sigprocmask(SIG_BLOCK, &newmask, NULL);
	}
	else{
		printf("[%s:%d][SIMU]dslite thread already existed!!!! Should not entry here again!\n",__func__,__LINE__);
		return;
	}
	
	pthread_detach(id);
}

void kill_Thread()
{
	if(debug)
		printf("[SIMU]---->Kill Thread[%lu]<----\n", id);

	if(1==dslite_thread_enabled)
		pthread_kill(id, SIGALRM);
}

int main(int argc, char **argv)
{
	int i = 0;
	//sigset_t newmask, oldmask;
	int autoBridgePPPfifo;
	
	printf("[%s %d]Process start.\n", __FILE__, __LINE__);

	log_pid();
	signal(SIGUSR1, kill_Thread);
	signal(SIGUSR2, setup_dslite);
	
	//sigemptyset(&newmask);
	//sigaddset(&newmask, SIGALRM);
	//sigprocmask(SIG_BLOCK, &newmask, &oldmask);

	autoBridgePPPfifo = initAutoBridgeFIFO();

	while(1)
	{
		calltimeout();
		
		if(poll_msg(autoBridgePPPfifo))
		{
			int i, read_res, aargc=0;
			char aargv[7][32+1];
			char buff[256];
			char *arg_ptr;

			read_res = read(autoBridgePPPfifo, buff, sizeof(buff));
			if(read_res > 0)
			{
				int arg_idx = 0;
				arg_ptr = buff;
				for(i=0; arg_ptr[i]!='\0'; i++) 
				{
					if(arg_ptr[i]==' ')
					{
						aargv[aargc][arg_idx]='\0';
						aargc++;
						arg_idx=0;
					}
					else 
					{
						if(arg_idx<32) 
						{
							aargv[aargc][arg_idx]=arg_ptr[i];
							arg_idx++;
						}
					}
				}
				aargv[aargc][arg_idx]='\0';
			}
			if(!strcmp(aargv[0],"start"))
			{
				if(debug)
					printf("[%s %d]Get a start, --->autoSimulation<----\n", __func__, __LINE__);
                if(aargc < 2)
                {
                    //start all bridge interface
				    startAutoBridgePppoeSimulation(NULL);
                }
                else
                {
                    // start one interface
                    startAutoBridgePppoeSimulation(aargv[1]);
                }
			}
			else if(!strcmp(aargv[0],"stop"))
			{
				if(debug)
					printf("[%s %d]Get a stop, --->autoSimulation<----\n", __func__, __LINE__);
                if(aargc < 2)
                {
				    stopAutoBridgePppoeSimulation(NULL);
                }
                else
                {
                    stopAutoBridgePppoeSimulation(aargv[1]);
                }
			}
			else if(!strcmp(aargv[0],"restart"))
			{
				if(debug)
					printf("[%s %d]Get a restart, --->autoSimulation<----\n", __func__, __LINE__);
				stopAutoBridgePppoeSimulation(NULL);
				startAutoBridgePppoeSimulation(NULL);
			}
			else if(!strcmp(aargv[0],"omci"))
			{
				if(debug)
					printf("[%s %d]Get a omci, --->omci success<----\n", __func__, __LINE__);
				setOmciState(1);
			}
			else if(!strcmp(aargv[0],"setdebug"))
			{
				printf("[%s %d][SIMU]Start Debug\n", __func__, __LINE__);
				debug = 1;
				setSimuDebug(1);
			}
			else if(!strcmp(aargv[0],"canceldebug"))
			{
				printf("[%s %d][SIMU]Cancel Debug\n", __func__, __LINE__);
				debug = 0;
				setSimuDebug(0);
			}
			else
			{
				printf("[%s %d][SIMU]Command %s not supported yet.\n", __FILE__, __LINE__, buff);
			}
		}

		sleep(1);
	}

	return 0;
}


