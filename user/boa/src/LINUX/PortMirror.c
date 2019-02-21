#include <sys/ioctl.h>
#include <netinet/if_ether.h>
#include <linux/if.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <memory.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/config.h>
#include <rtk_rg_struct.h>
#include "utility.h"

#define MAX_PORT_NUM	11
void usage(void);

int pboDisable(unsigned int toPort)
{
	rtk_enable_t pboEnable;
	rtk_enable_t pboAutoConfEnable;
	int ret;
	
	ret=rtk_swPbo_portState_get(toPort, &pboEnable);
	if(ret==RT_ERR_OK && pboEnable==ENABLED)
	{
		char cmd[128] = {0};
		sprintf(cmd, "echo 1 > /tmp/PortMirrorPboEnabledPort%d", toPort);
		system(cmd);
		ret=rtk_swPbo_portAutoConf_get(toPort, &pboAutoConfEnable);
		if(ret==RT_ERR_OK)
		{
			if(pboAutoConfEnable==ENABLED)
				sprintf(cmd, "echo 1 > /tmp/PortMirrorPboAutoConfEnabledPort%d", toPort);
			else
				sprintf(cmd, "echo 1 > /tmp/PortMirrorPboAutoConfDisabledPort%d", toPort);
			system(cmd);
		}
		pboEnable = DISABLED;
		ret=rtk_swPbo_portState_set(toPort, pboEnable);
		pboAutoConfEnable = DISABLED;
		ret=rtk_swPbo_portAutoConf_set(toPort, pboAutoConfEnable);
	}
}

int pboRestore(void)
{
	rtk_enable_t pboEnable;
	rtk_enable_t pboAutoConfEnable;
	char dirPbo[128] = {0};
	char dirPboAutoConf[128] = {0};
	int i, ret;

	for(i=0 ; i<CONFIG_LAN_PORT_NUM ; i++)
	{
		sprintf(dirPbo, "/tmp/PortMirrorPboEnabledPort%d", RG_get_lan_phyPortId(i));
		if(!access(dirPbo, F_OK)) 
		{
			pboEnable = ENABLED;
			ret=rtk_swPbo_portState_set(RG_get_lan_phyPortId(i), pboEnable);
			unlink(dirPbo);
		}
		sprintf(dirPboAutoConf, "/tmp/PortMirrorPboAutoConfEnabledPort%d", RG_get_lan_phyPortId(i));
		if(!access(dirPboAutoConf, F_OK)) 
		{
			pboAutoConfEnable = ENABLED;
			ret=rtk_swPbo_portAutoConf_set(RG_get_lan_phyPortId(i), pboAutoConfEnable);
			unlink(dirPboAutoConf);
		}
		sprintf(dirPboAutoConf, "/tmp/PortMirrorPboAutoConfDisabledPort%d", RG_get_lan_phyPortId(i));
		if(!access(dirPboAutoConf, F_OK)) 
		{
			pboAutoConfEnable = DISABLED;
			ret=rtk_swPbo_portAutoConf_set(RG_get_lan_phyPortId(i), pboAutoConfEnable);
			unlink(dirPboAutoConf);
		}
	}
}

int dumpPortMirror(void)
{
	rtk_rg_portMirrorInfo_t portMirrorInfo = {0};
	unsigned char re_map_tbl[4];
	int phyPortId, remapped;
	int ret, i, j;
	
	ret = rtk_rg_portMirror_get(&portMirrorInfo);
	if(ret == RT_ERR_OK)
	{
		printf("You have ");
		if(portMirrorInfo.direct==RTK_RG_MIRROR_TX_RX_BOTH) {
			printf("mirror rtx from ");
		} else if(portMirrorInfo.direct==RTK_RG_MIRROR_RX_ONLY) {
			printf("mirror rx from ");
		} else if(portMirrorInfo.direct==RTK_RG_MIRROR_TX_ONLY) {
			printf("mirror tx from ");
		} else {
			printf("not set any port mirror.\n");
			return ret;
		}

		mib_get(MIB_PORT_REMAPPING, (void *)re_map_tbl);
		if(portMirrorInfo.enabledPortMask.portmask) {
			for(i=0 ; i<MAX_PORT_NUM ; i++) {
				if(portMirrorInfo.enabledPortMask.portmask & (1<<i)) {
					remapped = 0;
					for(j=0 ; j<SW_LAN_PORT_NUM ; j++) {						
						rtk_rg_switch_phyPortId_get(re_map_tbl[j], &phyPortId);
						if(phyPortId == i) {
							remapped = 1;
							printf("port%d ", (j+1));
						}
					}
					if(!remapped) {
						if(i==5) {
							printf("pon ");
						} else if(i==9) {
							printf("cpu ");
						} else
							printf("port%d ", i);
					}
				}
			}
		} else {
			printf("no port ");
		}

		remapped = 0;
		for(j=0 ; j<SW_LAN_PORT_NUM ; j++) {						
			rtk_rg_switch_phyPortId_get(re_map_tbl[j], &phyPortId);
			if(phyPortId == portMirrorInfo.monitorPort) {
				remapped = 1;
				printf("to port%d.\n", j+1);
			}
		}
		if(!remapped) {
			if(portMirrorInfo.monitorPort==5) {
				printf("to pon.\n");
			} else if(portMirrorInfo.monitorPort==9) {
				printf("to cpu\n");
			} else
			printf("to port%d.\n", portMirrorInfo.monitorPort);
		}
	}
	
	return ret;
}

int setPortMirror(unsigned char *fromPort, unsigned char *toPort, unsigned char *direction)
{
	rtk_rg_portMirrorInfo_t portMirrorInfo = {0};
	unsigned char re_map_tbl[4];
	unsigned int phyPortId;
	char tempFromPort[256] = {0};

	char *dot = ",";
	char * pch;

	//printf ("Splitting fromPort \"%s\" into tokens:\n",fromPort);

	if(!fromPort)
		return -1;

	sprintf(tempFromPort, "%s", fromPort);
	pch = strtok(fromPort, dot);
	while (pch != NULL)
	{
		//printf ("%s\n",pch);
		if(atoi(pch)-1 >= 0 && atoi(pch)-1 < MAX_PORT_NUM) {
			if(atoi(pch) <= SW_LAN_PORT_NUM) {
				mib_get(MIB_PORT_REMAPPING, (void *)re_map_tbl);
				rtk_rg_switch_phyPortId_get(re_map_tbl[atoi(pch)-1], &phyPortId);
				portMirrorInfo.enabledPortMask.portmask |= (1<<phyPortId);
			} else {
				portMirrorInfo.enabledPortMask.portmask |= (1<<atoi(pch));
			}
		} else if(!strcmp(pch, "pon")) {
			portMirrorInfo.enabledPortMask.portmask |= (1<<5);
		} else if(!strcmp(pch, "cpu")) {
			portMirrorInfo.enabledPortMask.portmask |= (1<<9);
		} else {
			printf("Invalid fromPort(%d).\n", atoi(pch));
			return -1;
		}
		
		pch = strtok (NULL, dot);
	} 
	
	if(atoi(toPort)-1 >= 0 && atoi(toPort)-1 < MAX_PORT_NUM) {
		if(atoi(toPort) <= SW_LAN_PORT_NUM) {
			mib_get(MIB_PORT_REMAPPING, (void *)re_map_tbl);
			rtk_rg_switch_phyPortId_get(re_map_tbl[atoi(toPort)-1], &phyPortId);
			portMirrorInfo.monitorPort = phyPortId;
		} else {
			portMirrorInfo.monitorPort = atoi(toPort);
		}
	} else if(!strcmp(toPort, "pon")) {
		portMirrorInfo.monitorPort = 5;
	} else if(!strcmp(toPort, "cpu")) {
		portMirrorInfo.monitorPort = 9;
	} else {
		printf("Invalid toPort(%d).\n", atoi(toPort));
		return -1;
	}

	if(!strcmp(direction, "rx")) {
		portMirrorInfo.direct = RTK_RG_MIRROR_RX_ONLY;
	} else if(!strcmp(direction, "tx")) {
		portMirrorInfo.direct = RTK_RG_MIRROR_TX_ONLY;
	} else if(!strcmp(direction, "rtx")) {
		portMirrorInfo.direct = RTK_RG_MIRROR_TX_RX_BOTH;
	} else {
		printf("Invalid direction(%s).\n", direction);
		return -1;
	}

	pboDisable(atoi(toPort));
	printf("Set port mirror direction:%s from port %s to port %s.\n", direction, tempFromPort, toPort);
#if 0
	printf("	portMirrorInfo.direct=%d\n", portMirrorInfo.direct);
	printf("	portMirrorInfo.enabledPortMask.portmask=0x%x\n", portMirrorInfo.enabledPortMask.portmask);
	printf("	portMirrorInfo.monitorPort=%d\n", portMirrorInfo.monitorPort);
#endif
	if(rtk_rg_portMirror_set(portMirrorInfo) == RT_ERR_OK) 
		return 0;
	else 
		return -1;
}

int clearPortMirror(void)
{
	rtk_rg_portMirrorInfo_t portMirrorInfo = {0};

	portMirrorInfo.direct = RTK_RG_MIRROR_TX_RX_BOTH;
	portMirrorInfo.enabledPortMask.portmask = 0x0;
	portMirrorInfo.monitorPort = 9;
	if(rtk_rg_portMirror_set(portMirrorInfo) == RT_ERR_OK) {
		printf("Port mirror cleared.\n");
		return 0;
	} else 
		return -1;	
}

int main(int argc, char *argv[])
{
	int argIdx=1;
	

	if (argc<=1)
		goto arg_err_rtn;

	if(!strcmp(argv[argIdx], "dump"))
	{
		dumpPortMirror();
	}
	else if(!strcmp(argv[argIdx], "set"))
	{
		if (argc<=4)
			goto arg_err_rtn;

		pboRestore();
		if(setPortMirror(argv[argIdx+1], argv[argIdx+2], argv[argIdx+3]) == -1)
			printf("Set FAIL!\n");
		else
			printf("DONE.\n");
	}
	else if(!strcmp(argv[argIdx], "clear"))
	{
		pboRestore();
		clearPortMirror();
	}
	else
	{
		if(strcmp(argv[argIdx], "--help") && strcmp(argv[argIdx], "?"))
			printf("Invalid parameter!\n");
		goto arg_err_rtn;
	}

	return 0;

arg_err_rtn:
	usage();
	exit(1);
	
}

void usage(void)
{
	printf("Usage:\n");
	printf("	PortMirror dump\n");
	printf("	PortMirror set [fromPorts] [toPort] [rtx/rx/tx]\n");
	printf("	- ex. PortMirror set pon,cpu 1 rtx\n");
	printf("	- fromPorts: 1 means LAN1, 2 means LAN2, ... , pon means PON port, cpu means CPU port\n");
	printf("	PortMirror clear\n");
}

