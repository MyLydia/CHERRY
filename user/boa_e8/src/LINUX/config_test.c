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
#include <rtk/mib.h>
#include "signal.h"

static void startSimulation(char* devname, char* username, char* password, int v6mode)
{
	int ret;
	
	printf("[%s %d]dev=%s, user=%s, pwd=%s, v6mode=%d\n", __func__, __LINE__, devname, username, password, v6mode);
	ret = pppoeSimulationStart(devname, username, password, v6mode);
	if(ret==0)
		printf("[%s %d]start success\n", __func__, __LINE__);
	else if(ret == -1)
		printf("[%s %d]function disabled\n", __func__, __LINE__);
	else if(ret == -2)
		printf("[%s %d]mib operator failed\n", __func__, __LINE__);
	else if(ret == -3)
		printf("[%s %d]devname invalid(null or not exist)\n", __func__, __LINE__);
	
	return;	
}

#ifdef _PRMT_X_CMCC_IPOEDIAGNOSTICS_
static void startIPoESimulation(int ifIndex, char* mac_str, char *ping_host, unsigned int rep, unsigned int timeout)
{
	int ret;
	char mac[MAC_ADDR_LEN] = {0};

	printf("[%s %d]ifIndex=%x, mac=%s, ping_host=%s, rep=%d, timeout=%d\n", __func__, __LINE__, ifIndex, mac_str, ping_host, rep, timeout);

	sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
	ret = ipoeSimulationStart(ifIndex, mac, ping_host, rep, timeout);
	if(ret==0)
		printf("[%s %d]start success\n", __func__, __LINE__);
	else if(ret == -1)
		printf("[%s %d]function disabled\n", __func__, __LINE__);
	else if(ret == -2)
		printf("[%s %d]mib operator failed\n", __func__, __LINE__);
	else if(ret == -3)
		printf("[%s %d]devname invalid(null or not exist)\n", __func__, __LINE__);
	
	return;	
}
#endif

static void getSimulationInfo(char* devname)
{
	int ret;
	struct DIAG_RESULT_T p;
	
	printf("[%s %d]start.\n", __func__, __LINE__);
	memset(&p, 0, sizeof(struct DIAG_RESULT_T));
	while((ret = getSimulationResult(devname, &p))!=0)
	{
		printf("[%s %d]ret=%d\n", __func__, __LINE__, ret);
		if(ret == -1)
			printf("[%s %d]devname invalid\n", __func__, __LINE__);
		else if(ret == -2)
			printf("[%s %d]mib operator failed.\n", __func__, __LINE__);	
		else if(ret == -3)
		{
			printf("[%s %d]time-out!\n", __func__, __LINE__);
			return;
		}
		else if(ret == -4)
			printf("[%s %d]result file not exist.\n", __func__, __LINE__);
		else if(ret == -5)
			printf("[%s %d]In Process.\n", __func__, __LINE__);	
		sleep(3);	
	}

	printf("[%s %d]get success\n", __func__, __LINE__);
	//debug
	printf("[%s %d]result=%s\n", __func__, __LINE__, p.result);
	printf("[%s %d]errCode=%d\n", __func__, __LINE__, p.errCode);
	printf("[%s %d]ipt=%d\n", __func__, __LINE__, p.ipType);
	printf("[%s %d]sessionId=%d\n", __func__, __LINE__, p.sessionId);
	printf("[%s %d]ipAddr=%s\n", __func__, __LINE__, p.ipAddr);
	printf("[%s %d]gateWay=%s\n", __func__, __LINE__, p.gateWay);
	printf("[%s %d]dns=%s\n", __func__, __LINE__, p.dns);
	printf("[%s %d]ipv6Addr=%s\n", __func__, __LINE__, p.ipv6Addr);
	printf("[%s %d]ipv6Prefix=%s\n", __func__, __LINE__, p.ipv6Prefix);
	printf("[%s %d]ipv6GW=%s\n", __func__, __LINE__, p.ipv6GW);
	printf("[%s %d]ipv6LANPrefix=%s\n", __func__, __LINE__, p.ipv6LANPrefix);	
	printf("[%s %d]ipv6DNS=%s\n", __func__, __LINE__, p.ipv6DNS);	
	printf("[%s %d]Aftr=%s\n", __func__, __LINE__, p.aftr);	
	printf("[%s %d]authMSG=%s\n", __func__, __LINE__, p.authMSG);	
	//end

	return;	
}

#ifdef CONFIG_RG_BRIDGE_PPP_STATUS
static void getWanState(char* devname)
{
	int state = 0;
	int ret;
	
	ret = getWanPPPstate(devname, &state);
	if(ret==0)
	{
		printf("[%s %d]get state of %s = %d\n", __func__, __LINE__, devname, state);
	}
	else
	{
		printf("[%s %d]get state failed,ret=%d\n", __func__, __LINE__, ret);
	}
	return;	
}
#endif

static void autoBridgeTest(int start)
{
	int autobrg_fifo_fd;
	char buff[32];
	
	printf("[%s %d]enter\n", __func__, __LINE__);

	autobrg_fifo_fd = open("/tmp/autoBridgePPP_fifo", O_WRONLY|O_NONBLOCK);
	if(autobrg_fifo_fd != -1) 
	{
		if(start == 0)
			snprintf(buff, 32, "stop");
		else if(start == 1)
			snprintf(buff, 32, "start");
		else if(start == 2)
			snprintf(buff, 32, "restart");
		else if(start == 3)
			snprintf(buff, 32, "setdebug");
		else if(start == 4)
			snprintf(buff, 32, "canceldebug");
		printf("[%s %d]buff=%s\n", __func__, __LINE__, buff);
		write(autobrg_fifo_fd, buff, sizeof(buff));
		close(autobrg_fifo_fd);
	}
	else
	{
		printf("no autobridge_fifo\n");
	}
}

int main(int argc, char **argv)
{
	int i = 0;
	
	if(argc<3)
	{
		printf("Error input\n");
		return 0;
	}

	printf("Arg: ");
	while(i<argc)
	{
		printf("%s ", argv[i++]);
	}
	printf("\n\n");
	if(!strcmp(argv[1],"start")){
		char * username = NULL;
		char * password = NULL;
		int v6mode;

		if(argc < 6)
		{
			printf("Error input\n");
			return 0;
		}
		username = argv[3];
		password = argv[4];
		v6mode = atoi(argv[5]);
		startSimulation(argv[2], username, password, v6mode);
	}
#ifdef _PRMT_X_CMCC_IPOEDIAGNOSTICS_
	else if(!strcmp(argv[1],"ipoe_start")){
		char *mac_str = NULL;
		char *ping_host = NULL;
		int rep;
		int timeout;
		int total = mib_chain_total(MIB_ATM_VC_TBL);
		int i;
		MIB_CE_ATM_VC_T entry;
		char ifname[16] = {0};

		if(argc < 7)
		{
			printf("Error input\n");
			return 0;
		}
		for(i = 0 ; i < total ; i++)
		{
			mib_chain_get(MIB_ATM_VC_TBL, i, &entry);

			ifGetName(PHY_INTF(entry.ifIndex), ifname, 16);
			if(strcmp(ifname, argv[2]) == 0)
				break;
		}
		if(i == total)
			exit(-1);
		mac_str = argv[3];
		ping_host = argv[4];
		rep = atoi(argv[5]);
		timeout = atoi(argv[6]);
		startIPoESimulation(entry.ifIndex, mac_str, ping_host, rep, timeout);
	}
#endif
	else if(!strcmp(argv[1],"state")){
		getSimulationInfo(argv[2]);
	}
#ifdef CONFIG_RG_BRIDGE_PPP_STATUS
	else if(!strcmp(argv[1],"pppstate")){
		getWanState(argv[2]);
	}
#endif
	else if(!strcmp(argv[1],"auto")){
		if(!strcmp(argv[2],"stop"))
		{
			autoBridgeTest(0);
		}
		else if(!strcmp(argv[2],"start"))
		{
			autoBridgeTest(1);
		}
		else if(!strcmp(argv[2],"restart"))
		{
			autoBridgeTest(2);
		}
		else{
			printf("Error input\n");
		}
	}
	else if(!strcmp(argv[1],"debug")){
		if(!strcmp(argv[2],"on"))
		{
			autoBridgeTest(3);
		}
		else if(!strcmp(argv[2],"off"))
		{
			autoBridgeTest(4);
		}
		else{
			printf("Error input\n");
		}
	}
	else{
		printf("Error input\n");
	}

	return 0;
}


