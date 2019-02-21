/*
 *      Web server handler routines for Tracert diagnostic stuffs
 *
 */


/*-- System inlcude files --*/
#include <string.h>
#include <sys/socket.h>
#include <sys/signal.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <rtk/utility.h>

/*-- Local inlcude files --*/
#include "../webs.h"
#include "webform.h"
#include "../defs.h"

#ifdef CONFIG_ADV_SETTING
#include <sys/mman.h>  
#include <sys/types.h>  
#include <fcntl.h>  
#include <unistd.h>  
#include <stdio.h>  
#include <stdlib.h> 
#endif

void formTracert(request * wp, char *path, char *query)
{
	char *domainaddr;
	char line[512] = {0}, cmd[512] = {0};
	FILE *pf = NULL;
	char *str;

	va_cmd("/bin/killall", 1, 1, "traceroute");
	unlink("/tmp/tracert.tmp");
	domainaddr = boaGetVar(wp, "traceAddr", "");
	if (!domainaddr[0]) {
		ERR_MSG("wrong domain name!");
		return;
	}
#ifdef CONFIG_ADV_SETTING
	snprintf(cmd, sizeof(cmd), "traceroute -I");
#else
	snprintf(cmd, sizeof(cmd), "traceroute ");
#endif
	str = boaGetVar(wp, "trys", "");
	if(str[0])
	{
		snprintf(cmd, sizeof(cmd), "%s -q %s", cmd, str);
	}
	str = boaGetVar(wp, "timeout", "");
	if(str[0])
	{
		snprintf(cmd, sizeof(cmd), "%s -w %s", cmd, str);
	}
	str = boaGetVar(wp, "dscp", "");
	if(str[0])
	{
		unsigned char dscp_val = atoi(str);
		snprintf(cmd, sizeof(cmd), "%s -t %d", cmd, (dscp_val&0x3f)<<2);
	}
	str = boaGetVar(wp, "maxhop", "");
	if(str[0])
	{
		snprintf(cmd, sizeof(cmd), "%s -m %s", cmd, str);
	}
	str = boaGetVar(wp, "wanif", "");
	if(str[0])
	{
		unsigned int wan_ifindex = atoi(str);
		char wanifname[IFNAMSIZ] = {0};

		ifGetName(wan_ifindex, wanifname, sizeof(wanifname));
		if(wanifname[0])
			snprintf(cmd, sizeof(cmd), "%s -i %s", cmd, wanifname);
	}
	snprintf(cmd, sizeof(cmd), "%s %s", cmd, domainaddr);
	str = boaGetVar(wp, "datasize", "");
	if(str[0])
	{
		snprintf(cmd, sizeof(cmd), "%s %s", cmd, str);
	}
	snprintf(cmd, sizeof(cmd), "%s > /tmp/tracert.tmp 2>&1", cmd);

	va_cmd("/bin/sh", 2, 0, "-c", cmd);

	boaRedirect(wp, "/tracert_result.asp");

	return;
}

int dumpTraceInfo(int eid, request * wp, int argc, char **argv)
{
	char line[512] = {0};
	FILE *pf = NULL;
	int nBytesSent=0;

	pf = fopen("/tmp/tracert.tmp", "r");
	if(!pf) {
		//printf("open /tmp/tracert.tmp fail.\n");
		return 0;
	}
	while (fgets(line, sizeof(line), pf)) {
		//printf("%s\n", line);
		nBytesSent += boaWrite(wp, "<tr><td class=\"intro_content\">%s</td></tr>", line);
	}
	fclose(pf);

	return nBytesSent;
}

void formTracert6(request * wp, char *path, char *query)
{
	char *domainaddr;
	char line[512] = {0}, cmd[512] = {0};
	FILE *pf = NULL;
	char *str;

	va_cmd("/bin/killall", 1, 1, "traceroute6");
	unlink("/tmp/tracert.tmp");
	domainaddr = boaGetVar(wp, "traceAddr", "");
	if (!domainaddr[0]) {
		ERR_MSG("wrong domain name!");
		return;
	}
	//printf("%s domain %s\n", __func__, domainaddr);
	snprintf(cmd, sizeof(cmd), "traceroute6");
	str = boaGetVar(wp, "trys", "");
	if(str[0])
	{
		snprintf(cmd, sizeof(cmd), "%s -q %s", cmd, str);
	}
	str = boaGetVar(wp, "timeout", "");
	if(str[0])
	{
		snprintf(cmd, sizeof(cmd), "%s -w %s", cmd, str);
	}
	str = boaGetVar(wp, "maxhop", "");
	if(str[0])
	{
		snprintf(cmd, sizeof(cmd), "%s -m %s", cmd, str);
	}
	str = boaGetVar(wp, "wanif", "");
	if(str[0])
	{
		unsigned int wan_ifindex = atoi(str);
		char wanifname[IFNAMSIZ] = {0};

		ifGetName(wan_ifindex, wanifname, sizeof(wanifname));
		if(wanifname[0])
			snprintf(cmd, sizeof(cmd), "%s -i %s", cmd, wanifname);
	}
	snprintf(cmd, sizeof(cmd), "%s %s", cmd, domainaddr);
	str = boaGetVar(wp, "datasize", "");
	if(str[0])
	{
		snprintf(cmd, sizeof(cmd), "%s %s", cmd, str);
	}
	snprintf(cmd, sizeof(cmd), "%s > /tmp/tracert.tmp 2>&1", cmd);

	va_cmd("/bin/sh", 2, 0, "-c", cmd);
	boaRedirect(wp, "/tracert6_result.asp");

	return;
}

