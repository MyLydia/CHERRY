/*
 *      Web server handler routines for Bridge stuffs
 *
 */


/*-- System inlcude files --*/
#include <string.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_bridge.h>

/*-- Local inlcude files --*/
#include "../webs.h"
#include "webform.h"
#include "mib.h"
#include "utility.h"
#include "debug.h"
#include "../defs.h"
#include "multilang.h"

#define BRCTL_GET_FDB_ENTRIES 18
struct bridge;
//struct bridge_info;
struct port;
int br_socket_fd;

struct bridge
{
	struct bridge *next;

	int ifindex;
	char ifname[IFNAMSIZ];
	struct port *firstport;
	struct port *ports[256];
//	struct bridge_info info;
};

#ifdef __i386__
#define _LITTLE_ENDIAN_
#endif

/*-- Macro declarations --*/
#ifdef _LITTLE_ENDIAN_
#define ntohdw(v) ( ((v&0xff)<<24) | (((v>>8)&0xff)<<16) | (((v>>16)&0xff)<<8) | ((v>>24)&0xff) )

#else
#define ntohdw(v) (v)
#endif

#ifdef CONFIG_USER_RTK_LAN_USERLIST
#include <signal.h>
#define DHCPUPDATETIME 	30

struct host_obj_data
{
	char *addr;
	unsigned char source;	//0: DHCP, 1:STATIC
	int lease;
	char *mac;
	char *lan_ifname;
	unsigned char active;
	unsigned char InterfaceType;
	char *HostName;
	struct host_obj_data *next;
};

struct dhcpOfferedAddr {
	u_int8_t chaddr[16];
	u_int32_t yiaddr;       /* network order */
	u_int32_t expires;      /* host order */
	u_int32_t interfaceType;
	u_int8_t hostName[64];
};

static struct host_obj_data *front=NULL;
static struct host_obj_data *rear=NULL;

static char *gDHCPHosts = NULL;
static time_t gDHCPUpdateTime = 0;
unsigned int gDHCPTotalHosts = 0;

int get_host_connected_interface(const char *brname, unsigned char *macaddr, char *ifname)
{
	struct __fdb_entry fdb[256];
	int offset = 0;
	unsigned long args[4];
	struct ifreq ifr;
	int br_socket_fd = -1;

	args[0] = BRCTL_GET_FDB_ENTRIES;
	args[1] = (unsigned long)fdb;
	args[2] = 256;
	if ((br_socket_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		return -1;
	}
	else
	{
		memcpy(ifr.ifr_name, brname, IFNAMSIZ);
		((unsigned long *)(&ifr.ifr_data))[0] = (unsigned long)args;
		while (1)
		{
			int i = 0;
			int num = 0;

			args[3] = offset;
			num = ioctl(br_socket_fd, SIOCDEVPRIVATE, &ifr);

			if (!num)
				break;

			for (i = 0; i < num; i++) {
				struct __fdb_entry *f = fdb + i;

				if (memcmp(f->mac_addr, macaddr, 6) == 0) {
					int ifindices[256];
					int list_num = 0;
					unsigned long list_args[4] = { BRCTL_GET_PORT_LIST, (unsigned long)ifindices, 256, 0 };
					struct ifreq list_ifr;

					memset(ifindices, 0, sizeof(ifindices));
					strncpy(list_ifr.ifr_name, brname, IFNAMSIZ);
					list_ifr.ifr_data = (char *) &list_args;

					list_num = ioctl(br_socket_fd, SIOCDEVPRIVATE, &list_ifr);
					if (list_num < 0) {
						close(br_socket_fd);
						return -1;
					}

					if_indextoname(ifindices[f->port_no], ifname);
					break;
				}
			}

			offset += num;
		}
		close(br_socket_fd);
	}
	return 1;
}

int updateDHCPList()
{
	time_t c_time=0;
	int 	pid;
	FILE 	*fp;
	struct stat status;

	c_time = time(NULL);
	if( c_time >= gDHCPUpdateTime+DHCPUPDATETIME )
	{
		// siganl DHCP server to update lease file
		pid = read_pid(DHCPSERVERPID);
		if( pid > 0) kill(pid, SIGUSR1);

		usleep(1000);

		if ( stat(DHCPD_LEASE, &status) < 0 )
			goto err;

		gDHCPHosts = realloc(gDHCPHosts, status.st_size);		
		if(gDHCPHosts==NULL) goto err;

		fp = fopen(DHCPD_LEASE, "r");
		if ( fp == NULL ) goto err;
		fread(gDHCPHosts, 1, status.st_size, fp);
		fclose(fp);

		gDHCPTotalHosts = status.st_size / sizeof( struct dhcpOfferedAddr );
		gDHCPUpdateTime = c_time;
	}
	return 0;

err:
	if(gDHCPHosts)
	{
		free(gDHCPHosts);
		gDHCPHosts=NULL;
	}
	gDHCPTotalHosts=0;
	return -1;
}


int getDHCPClient( int id,  char *ip, char *mac, int *liveTime, int *InterfaceType, char *HostName, char *ifname)
{
	struct dhcpOfferedAddr *p = NULL;
	//id starts from 0
	if( (id<0) || (id>=gDHCPTotalHosts) ) return -1;
	if( (ip==NULL) || (mac==NULL) || (liveTime)==0 || (InterfaceType)==0 || (HostName)==NULL ) return -1;
	if( (gDHCPHosts==NULL) || (gDHCPTotalHosts==0) ) return -1;

	p = (struct dhcpOfferedAddr *) (gDHCPHosts + id * sizeof( struct dhcpOfferedAddr ));
	strcpy(ip, inet_ntoa(*((struct in_addr *)&p->yiaddr)) );
	sprintf(mac, "%02x:%02x:%02x:%02x:%02x:%02x",
			p->chaddr[0],p->chaddr[1],p->chaddr[2],
			p->chaddr[3],p->chaddr[4],p->chaddr[5]);

	get_host_connected_interface("br0", p->chaddr, ifname);

	*liveTime = (int)p->expires;
	*InterfaceType = (int)p->interfaceType;
	strcpy(HostName, p->hostName);	
	return 0;
}

int freeHost()
{
	struct host_obj_data *ptr;
	ptr = front;
	
	while(ptr != NULL)
	{
		//printf("free [%s] ",ptr->addr);
		if(ptr->addr) free(ptr->addr);
		if(ptr->mac) free(ptr->mac);
		if(ptr->lan_ifname) free(ptr->lan_ifname);
		if(ptr->HostName) free(ptr->HostName);
		free(ptr);
		ptr = ptr->next;
	}
	//printf("\n");
	front=NULL;
	rear=NULL;
	return 0;
}

static struct host_obj_data* get_host_data(char *ip)
{
	struct host_obj_data *ptr;
	ptr = front;
	
	if(ip == NULL)
		return NULL;

	while(ptr != NULL)
	{
		if(ptr->addr && strcmp(ip, ptr->addr) == 0)
			return ptr;
		ptr = ptr->next;
	}

	return NULL;
}

static int updateARPHosts()
{	
	FILE *farp;
	char line[256] = {0};
	char ip[64] = {0};
	char mask[64] = {0};
	char dev[32] = {0};
	int type, flags;
	char mac[32];
	char ifname[IFNAMSIZ] = {0};
	int num;
	char cmd[512] = {0};
	
	farp = fopen("/proc/net/arp", "r");
	if(farp == NULL)
		return -1;		
	
	snprintf(cmd, sizeof(cmd), "ip neighbor show > /tmp/arp.tmp 2>&1");
	va_cmd("/bin/sh", 2, 1, "-c", cmd);
		
	//bypass header
	fgets(line, sizeof(line), farp);

	while(fgets(line, sizeof(line), farp))
	{
		unsigned int instNum = 0;
		num = sscanf(line, "%s 0x%x 0x%x %32s %64s %32s\n",
			ip, &type, &flags, mac, mask, dev);

		if(num < 4)
			break;

		if(strcmp(dev, "br0")) // Skip WAN interfaces.
			continue;
		
		if(flags==0x0)       // This arp entry is incomplete, It is not invalid on ARP Cache.
			continue;		
							
		{
			struct host_obj_data *host = NULL;
			unsigned char mac_addr[6];
			int ret;
			char line2[256] = {0};
			FILE *pf = NULL;
			char ip2[64] = {0};
			char status[64] = {0};
			int found=0;			
			
			pf = fopen("/tmp/arp.tmp", "r");
			if(!pf) {
				printf("open /tmp/arp.tmp fail.\n");
				return -1;
			}
			
			while (fgets(line2, sizeof(line2), pf)) {
				//printf("%s\n", line2);				
				if(sscanf(line2, "%s %*s %*s %*s %*s %s",
					ip2, status)!=2) {
					//printf("This is not correct format which we need !!\n");
					continue;
				}
				
				if (!strcmp(ip,ip2)) {
					if (!strcmp(status, "STALE")) {
						found = 1;
						//printf("Found STALE device\n");
					}					
					break;					
				}				
			}
			fclose(pf);			
			if (found) continue;
			
			host = malloc(sizeof(struct host_obj_data));
			if(host == NULL)
			{
				fprintf(stderr, "<%s:%d> malloc failed!\n", __FUNCTION__, __LINE__);
				return -1;
			}				
			memset(host, 0, sizeof(struct host_obj_data));
		
			host->active = 1;
			host->source = 1;	//static by default
			host->addr = strdup(ip);
			host->mac = strdup(mac);
			ret = sscanf(mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac_addr[0], &mac_addr[1], &mac_addr[2], &mac_addr[3], &mac_addr[4], &mac_addr[5]);
			ret = get_host_connected_interface("br0", mac_addr, ifname);
			host->lan_ifname = strdup(ifname);

			if (rear == NULL)
			{
				front = host;
				rear = host;
			}
			else
			{
				rear->next = host;
				rear = host;
			}
		}
	}
	fclose(farp);			
	
	return 0;
}

static int updateDHCPHosts()
{
	int i = 0;
	char ip[64], mac[64], hostName[64] = {0}, ifname[IFNAMSIZ];
	int lease;
	int InterfaceType = 0;
	struct host_obj_data *host = NULL;
	
	updateDHCPList();

	for(i = 0 ; i < gDHCPTotalHosts ; i++)
	{
		if(getDHCPClient(i, ip, mac, &lease, &InterfaceType, hostName, ifname) != 0)
			continue;

		host = get_host_data(ip);
		if(host)
		{
			//printf("Get %s host from ARP Table\n", ip);
			host->source = 0;	//DHCP
			host->lease = lease;
			host->InterfaceType = InterfaceType;
			host->HostName = (strlen(hostName) > 0) ? strdup(hostName) : strdup("");
		}
		//add a new inactive node
		/*
		else
		{			
			struct host_obj_data *host = NULL;
			host = malloc(sizeof(struct host_obj_data));
			if(host == NULL)
			{
				fprintf(stderr, "<%s:%d> malloc failed!\n", __FUNCTION__, __LINE__);
				return -1;
			}						
			memset(host, 0, sizeof(struct host_obj_data));

			host->active = 0;
			host->source = 0;
			host->addr = strdup(ip);
			host->mac = strdup(mac);
			host->lan_ifname = strdup(ifname);
			host->lease = lease;
			host->InterfaceType = InterfaceType;
			host->HostName = (strlen(hostName) > 0) ? strdup(hostName) : strdup("");

			if (rear == NULL)
			{
				front = host;
				rear = host;
			}
			else
			{
				rear->next = host;
				rear = host;
			}			
		}
		*/
	}
	
	return 0;
}

int LanUserTableList(int eid, request * wp, int argc, char **argv)
{
	struct host_obj_data *ptr;
	
	updateARPHosts();
	updateDHCPHosts();
	ptr = front;
	while(ptr != NULL)
	{		
#ifndef CONFIG_GENERAL_WEB
		boaWrite(wp, "<tr bgcolor=#b7b7b7><td><font size=2>%s\t</td>"
			"<td><font size=2>%s\t</td>"
			"<td><font size=2>%s\t</td>"
			"<td><font size=2>%s\t</td>",	
#else
		boaWrite(wp, "<tr><td>%s\t</td>"
			"<td>%s\t</td>"
			"<td>%s\t</td>"
			"<td>%s\t</td></tr>",
#endif
			ptr->addr, ptr->mac,
			(((ptr->HostName) !=NULL) ? ptr->HostName : ""),
			(((ptr->lan_ifname) !=NULL) ? ptr->lan_ifname : ""));
		
		ptr = ptr->next;
	}
	freeHost();
	return 0;
}

void formRefleshLanUserTbl(request * wp, char *path, char *query)
{
	char *submitUrl;
	char *strSubmit;	
		
	submitUrl = boaGetVar(wp, "submit-url", "");

	strSubmit = boaGetVar(wp, "refresh", "");
	if (strSubmit[0]) {
		boaRedirect(wp, submitUrl);
		return;
	}	
	
ERR:
	boaRedirect(wp, submitUrl);
}
#endif

///////////////////////////////////////////////////////////////////
void formBridge(request * wp, char *path, char *query)
{
	char	*str, *submitUrl;
	char tmpBuf[100];
#ifndef NO_ACTION
	int pid;
#endif
	unsigned char stp;
#ifdef APPLY_CHANGE
	char *argv[5];
#endif

	// Set Ageing Time
	str = boaGetVar(wp, "ageingTime", "");
	if (str[0]) {
		unsigned short time;
		time = (unsigned short) strtol(str, (char**)NULL, 10);
		if ( mib_set(MIB_BRCTL_AGEINGTIME, (void *)&time) == 0) {
			sprintf(tmpBuf, " %s (bridge ageing time).",Tset_mib_error);
			goto setErr_bridge;
		}
#ifdef APPLY_CHANGE
		argv[1]="setageing";
		argv[2]=(char*)BRIF;
		argv[3]=str;
		argv[4]=NULL;
		TRACE(STA_SCRIPT, "%s %s %s %s\n", BRCTL, argv[1],
		argv[2], argv[3]);
		do_cmd(BRCTL, argv, 1);
#endif
	}

	// Set STP
	str = boaGetVar(wp, "stp", "");
	if (str[0]) {
		if (str[0] == '0')
			stp = 0;
		else
			stp = 1;
		if ( !mib_set(MIB_BRCTL_STP, (void *)&stp)) {
			sprintf(tmpBuf, " %s (STP).",Tset_mib_error);
			goto setErr_bridge;
		}

#ifdef APPLY_CHANGE
		if (stp == 1)	// on
		{	// brctl setfd br0 20
			argv[1]="setfd";
			argv[2]=(char*)BRIF;
			argv[3]="20";
			argv[4]=NULL;
			TRACE(STA_SCRIPT, "%s %s %s %s\n", BRCTL, argv[1], argv[2], argv[3]);
			do_cmd(BRCTL, argv, 1);
		}

		argv[1]="stp";
		argv[2]=(char*)BRIF;

		if (stp == 0)
			argv[3]="off";
		else
			argv[3]="on";

		argv[4]=NULL;
		TRACE(STA_SCRIPT, "%s %s %s %s\n", BRCTL, argv[1], argv[2], argv[3]);
		do_cmd(BRCTL, argv, 1);
#endif
	}

// Magician: Commit immediately
#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif

#ifndef NO_ACTION
	pid = fork();
	if (pid)
		waitpid(pid, NULL, 0);
	else if (pid == 0) {
		snprintf(tmpBuf, 100, "%s/%s", _CONFIG_SCRIPT_PATH, _CONFIG_SCRIPT_PROG);
#ifdef HOME_GATEWAY
		execl( tmpBuf, _CONFIG_SCRIPT_PROG, "gw", "bridge", NULL);
#else
		execl( tmpBuf, _CONFIG_SCRIPT_PROG, "ap", "bridge", NULL);
#endif
		exit(1);
	}
#endif

	submitUrl = boaGetVar(wp, "submit-url", "");
	OK_MSG(submitUrl);
	return;

setErr_bridge:
	ERR_MSG(tmpBuf);
}

static void __dump_fdb_entry(request * wp, struct __fdb_entry *f)
{
	unsigned long long tvusec;
	int sec,usec;

	// jiffies to tv
	tvusec = (1000000ULL*f->ageing_timer_value)/HZ;
	sec = tvusec/1000000;
	usec = tvusec - 1000000 * sec;

	if (f->is_local)
#ifndef CONFIG_GENERAL_WEB
		boaWrite(wp, "<tr bgcolor=#b7b7b7><td><font size=2>%3i\t</td>"
			"<td><font size=2>%.2x-%.2x-%.2x-%.2x-%.2x-%.2x\t</td>"
			"<td><font size=2>%s\t\t</td>"
			"<td><font size=2>%s\t</td></tr>",
#else
		boaWrite(wp, "<tr><td>%3i\t</td>"
			"<td>%.2x-%.2x-%.2x-%.2x-%.2x-%.2x\t</td>"
			"<td>%s\t\t</td>"
			"<td>%s\t</td></tr>",
#endif
			f->port_no, f->mac_addr[0], f->mac_addr[1], f->mac_addr[2],
			f->mac_addr[3], f->mac_addr[4], f->mac_addr[5],
			Tyes, "---");
	else
#ifndef CONFIG_GENERAL_WEB
		boaWrite(wp, "<tr bgcolor=#b7b7b7><td><font size=2>%3i\t</td>"
			"<td><font size=2>%.2x-%.2x-%.2x-%.2x-%.2x-%.2x\t</td>"
			"<td><font size=2>%s\t\t</td>"
			"<td><font size=2>%4i.%.2i\t</td></tr>",
#else
		boaWrite(wp, "<tr><td>%3i\t</td>"
			"<td>%.2x-%.2x-%.2x-%.2x-%.2x-%.2x\t</td>"
			"<td>%s\t\t</td>"
			"<td>%4i.%.2i\t</td></tr>",
#endif
			f->port_no, f->mac_addr[0], f->mac_addr[1], f->mac_addr[2],
			f->mac_addr[3], f->mac_addr[4], f->mac_addr[5],
			f->is_local?Tyes:Tno, sec, usec/10000);
}

int bridgeFdbList(int eid, request * wp, int argc, char **argv)
{
	struct bridge *br;
	struct __fdb_entry fdb[256];
	int offset;
	unsigned long args[4];
	struct ifreq ifr;

/*
	br = bridge_list;
	while (br != NULL) {
		if (!strcmp(br->ifname, BRIF))
			break;

		br = br->next;
	}

	if (br == NULL)
	{
		boaWrite(wp, "%s", "br0 interface not exists !!");
		return 0;
	}
*/

	offset = 0;
	args[0] = BRCTL_GET_FDB_ENTRIES;
	args[1] = (unsigned long)fdb;
	args[2] = 256;
	if ((br_socket_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		boaWrite(wp, "%s", "socket not avaiable !!");
		return -1;
	}
//	memcpy(ifr.ifr_name, br->ifname, IFNAMSIZ);
	memcpy(ifr.ifr_name, BRIF, IFNAMSIZ);
	((unsigned long *)(&ifr.ifr_data))[0] = (unsigned long)args;
	while (1) {
		int i;
		int num;

		args[3] = offset;
		num = ioctl(br_socket_fd, SIOCDEVPRIVATE, &ifr);

		if (num <= 0)
		{
			if (num < 0)
				boaWrite(wp, "%s", Tbrg_not_exist);
			break;
		}

		for (i=0;i<num;i++)
			__dump_fdb_entry(wp, fdb+i);

		offset += num;
	}
	close(br_socket_fd);

	return 0;
}

int ARPTableList(int eid, request * wp, int argc, char **argv)
{
	FILE *fp;
	char  buf[256];
	char arg1[20],arg2[20],arg4[20];
	int arg3;
	int nBytesSent=0;
	int enabled;

	fp = fopen("/proc/net/arp", "r");
	if (fp == NULL){
		printf("read arp file fail!\n");
		goto err1;
	}
    fgets(buf,256,fp);
	while(fgets(buf,256,fp)){
		sscanf(buf,"%s	%s	0x%x	%s",arg1,arg2,&arg3,arg4);
		if (!arg3) {
			continue;
		}
		#ifdef CONFIG_LUNA_DUAL_LINUX
		if(strcmp(arg1, "10.253.253.2") == 0 && strcasecmp(arg4,CONFIG_DEFAULT_SLAVE_IPC_MAC_ADDRESS) == 0 )
                        continue;
		#endif
		#ifdef APPLY_CHANGE
		int i=0;
		for(i=0;i<strlen(arg4);i++)
			{
			  if(arg4[i]==':')
			  	arg4[i]='-';
			}
		#endif
#ifndef CONFIG_GENERAL_WEB
		boaWrite(wp, "<tr bgcolor=#b7b7b7><td><font size=2>%s\t</td>"
		"<td><font size=2>%s\t</td>",
		arg1,arg4);
#else
		boaWrite(wp, "<tr><td>%s\t</td>"
		"<td>%s\t</td>",
		arg1,arg4);
#endif
	}

	fclose(fp);
err1:
	return nBytesSent;
}


/////////////////////////////////////////////////////////////////////////////
void formRefleshFdbTbl(request * wp, char *path, char *query)
{
	char *submitUrl;
	char *strSubmit;
	FILE *fp;
	char  buf[256];
	char arg1[20],arg2[20],arg3[20],arg4[20];
	
	submitUrl = boaGetVar(wp, "submit-url", "");

	strSubmit = boaGetVar(wp, "refresh", "");
	if (strSubmit[0]) {
		boaRedirect(wp, submitUrl);
		return;
	}

	strSubmit = boaGetVar(wp, "clear", "");
	if (strSubmit[0]) {//clear arp table
		fp = fopen("/proc/net/arp", "r");
		if (fp == NULL){
			printf("read arp file fail!\n");
			goto ERR;
		}
		fgets(buf,256, fp);

		while(fgets(buf,256,fp)){
			memset(arg1, 0, 20);
			sscanf(buf,"%s	%s	%s	%s", arg1,arg2,arg3,arg4);
			va_cmd("/bin/arp", 2, 1, "-d", arg1);
		}
		fclose(fp);
	}	
ERR:
	boaRedirect(wp, submitUrl);
}

