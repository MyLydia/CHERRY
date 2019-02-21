#include <stdio.h>
#include <wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <mib.h>
#include <string.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <errno.h>
#include <pthread.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <unistd.h>
#include <sys/msg.h>
#include "utility.h"


#define PING_CMD_LEN 256
#define LAN_PING_RESULT_FILE "/tmp/lan_ping_result"
#define LAN_DEVICE_PKT_LOSS_LOCKFILE	"/var/run/lan_device_pkt_losss.lock"//duplicate from utility.c

FILE *fp_local=NULL, *fp_output = NULL;
int lockfd = 0;
lanHostInfo_t *pLanNetInfo=NULL;

pthread_mutex_t autoPingMutex ; 


int cleanFdLock(void)
{
	if(fp_output)
	{
		fclose(fp_output);
		fp_output = NULL;
	}

	if(fp_local)
	{
		fclose(fp_local);
		fp_local = NULL;
	}

	if(-1 != lockfd)
	{
		//printf("AUTOPING==============unlock file=======================\n");
		unlock_file_by_flock(lockfd);	
		lockfd = -1;
	}

	if(access(LAN_PING_RESULT_FILE, F_OK) != -1)
	{
		unlink("tmp/lan_ping_result");
	}

	return 0;
}

int cleanLanNetInfo(void)
{
	if(pLanNetInfo)
	{
		//printf("%s: free pLanNetInfo\n", __FUNCTION__);
		free(pLanNetInfo);
		pLanNetInfo = NULL;
	}

	return 0;
}

void autoPingClean(void *arg)
{
	cleanLanNetInfo();
	cleanFdLock();

	pthread_mutex_unlock(&autoPingMutex); 

	//printf("pthread detach\n");
	pthread_detach(pthread_self());
	
	return;
}

static int parseLanPingResult(int add)
{
	char line[1024+1];
	char *postion = NULL;
	unsigned int pktsRx = 0;
	int pktsLoss = 0,  delay_s = 0;
	float delay_ms = 0, delay_all = 0;
	unsigned int all_cnt = 0;
	unsigned short reserved = 0;

	line[1025] = 0;

	if(NULL == pLanNetInfo)
		return -1;

	//printf("AUTOPING==============lock file=======================\n");
	if ((lockfd = lock_file_by_flock(LAN_DEVICE_PKT_LOSS_LOCKFILE, 1)) == -1)
	{
		printf("%s, the file %s have been locked\n", __FUNCTION__, LAN_DEVICE_PKT_LOSS_LOCKFILE);
		return -1;
	}

   	if ((fp_local = fopen(LAN_PING_RESULT_FILE, "r")) == NULL){			
		goto err;
	}
	
   	if ((fp_output = fopen(LAN_DEVICE_PKT_LOSS_FILENAME, add?"a":"w")) == NULL){			
		goto err;
	}	

	while(fgets(line,sizeof(line)-1,fp_local)){
		postion = line;
		while(1)
		{
			if(postion = strstr(postion,"time="))
			{
				sscanf(postion,"time=%f ms%*s\n", &delay_ms);
				postion += 5;
				//printf("delay time is %.3f\n", delay_ms);

				delay_all += delay_ms;
				all_cnt++;
			}
			else
				break;
		}
		
		if(postion = strstr(line,"packets transmitted"))
		{
			sscanf(postion,"packets transmitted, %u packets received, %*s\n", &pktsRx);
			break;
		}
	}

	if(0 == all_cnt)
	{
		delay_s = -1;
		pktsLoss = -1;
	}
	else
	{
		delay_ms = delay_all/all_cnt;
		pktsLoss = 10 - pktsRx;

		if((delay_ms > 500) && (delay_ms < 1000))
			delay_s = 1;
		else
			delay_s = (int)(delay_ms/1000);
	}

	printf("pkt rx is %d, loss is %d, average delay is %d\n", pktsRx, pktsLoss, delay_s);

	//output should follow struct stLanDevicePktLoss.
	fwrite(&(pLanNetInfo[add].ip), 4, 1, fp_output);
	fwrite(&pktsLoss, 4, 1, fp_output);
	fwrite(&delay_s, 4, 1, fp_output);
	fwrite(&(pLanNetInfo[add].mac), 6, 1, fp_output);
	fwrite(&reserved, 2, 1, fp_output);

	
	//printf("unlock normally\n");
	cleanFdLock();

	return 0;

err:
	cleanFdLock();

	return -1;
}

void *startWork(void *arg){
	unsigned int count=0;
	char strIp[16] = {0};
	int  offset = 0;
	pid_t wpid;
	int status = -1;
	char * argv[14];
	int idx = 0;
	struct in_addr addr;
	int i = 0;
	int ret = 0;

	pthread_mutex_lock(&autoPingMutex); 

	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

	pthread_cleanup_push(autoPingClean, NULL);
	
	argv[idx++] = "/bin/ping";
	argv[idx++] = "-c";
	argv[idx++] = "10";
	argv[idx++] = "-W";
	argv[idx++] = "1";
	argv[idx++] = strIp;
	argv[idx++] = NULL;

	//if(IS_PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_ON(_PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_PacketLostEnable_BIT))
	{
		get_lan_net_info(&pLanNetInfo, &count);
		if(count > 0)
		{
			printf("%s, find device count is %d\n", __FUNCTION__, count);
			
			for(i = 0; i < count; i++)
			{
				addr.s_addr = pLanNetInfo[i].ip;
				strncpy(strIp, inet_ntoa(addr), sizeof(strIp));
				printf("%s, device IP %s\n", __FUNCTION__, strIp);

				pid_t ping_pid = fork();
				if(ping_pid == 0)
				{
					int pingout = open(LAN_PING_RESULT_FILE, O_RDWR|O_CREAT|O_TRUNC, 0600);
					if (-1 == pingout) { 
						exit(-1);
					}
					if (-1 == dup2(pingout, fileno(stdout))) {
						exit(-1);
					}
					execv("/bin/ping", argv);
					fflush(stdout);
					close(pingout);
					exit(-1);
				}
				else if(ping_pid > 0)
				{
					/* parent, wait till ping process end */
					while ((wpid = wait(&status)) != ping_pid)
					{
						if (wpid == -1 && errno == ECHILD)	/* see wait(2) manpage */
							break;
					}
				
					if(WIFSIGNALED(status))
						status = 0;
					else
						status = WEXITSTATUS(status);
					
					parseLanPingResult(i);
				}

				if(access(LAN_PING_RESULT_FILE, F_OK) != -1)
				{
					unlink("tmp/lan_ping_result");
				}
			}
		}
	}

	pthread_cleanup_pop(0); 	
	
	autoPingClean(NULL);
		
	pthread_exit(NULL);
}

int msgFromCwmpPerformanceQId=0;

static int createMsgForCwmpPerformance(){
	key_t msgQKey = ftok("/bin/cwmpClient", 't');
	unsigned int permits = 00666;
	int ret = 0;
	permits |= IPC_CREAT;
	if(!msgFromCwmpPerformanceQId){
		msgFromCwmpPerformanceQId = msgget(msgQKey, permits);
		if(-1 == msgFromCwmpPerformanceQId){
			return -1;
		}
	}
}

void processMsgFromCwmpPerformance(){
	int ret=0;
	cwmp_msg2ClientData_t eventData;
	int i = 0;	
    pthread_t thread;
	
	while(1){
		int msg_ret = msgrcv(msgFromCwmpPerformanceQId, (void *) &eventData, sizeof(eventData.msgqData), 0, IPC_NOWAIT); 
		if(-1 == msg_ret){
			if(EINTR == errno)
				continue;
			else// if(ENOMSG==errno)
			{
				break;
			}
		}	

		switch(eventData.mtype)
		{ 
			case 1:	
				printf("%s %d trigger ping function\n",__FUNCTION__,__LINE__);
			    ret = pthread_create(&thread, NULL, startWork, NULL);
			    if (ret != 0) 
				{
			        perror("Thread creation failed");
			    }
       			break;
			case 2:
				ret = pthread_cancel(thread);
				if (ret != 0)
				{
					perror("Thread cancel failed");
				}
			default:
			break;
		}
		break;
	}
	
	return;
}

int main(void)
{
	createMsgForCwmpPerformance();	

	//just for debug;
	//sleep(20);
	//startWork();

	pthread_mutex_init(&autoPingMutex,NULL);
	
	while(1)
	{ 
		processMsgFromCwmpPerformance();	
		sleep(1); 
	}

	pthread_mutex_destroy(&autoPingMutex); 

	return 0;
}
