#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/sysinfo.h>
#include <ctype.h>

#include "mib.h"
#include "sysconfig.h"
#include "mibtbl.h"
#include "utility.h"

#include <time.h>
#include "cJSON.h"
#include <sys/types.h>
#include <regex.h>
#include <fcntl.h>
#include <form_src/list.h>

#include <arpa/inet.h>
#include "rtusr_rg_api.h"
#include <openssl/des.h>
#include <openssl/md5.h>
#include <sys/file.h>
#include <pthread.h>

/*
	Macros defined here
*/
#define MAX_VPN_CRE_PARA_NUM	19
#define VPN_ACCPXY_PARAM_NUM	13
#define VPN_DBG_PRT(enable, fmt, args...) \
	do{if(enable){AUG_PRT(fmt, ## args);}}while(0)

#define ConfigVpnLock "/var/run/configVpnLock"
#define LOCK_VPN()	\
		do {	\
			if ((lockfd = open(ConfigVpnLock, O_RDWR)) == -1) { \
				perror("open wlan lockfile");	\
				return 0;	\
			}	\
			while (flock(lockfd, LOCK_EX)) { \
				if (errno != EINTR) \
					break; \
			}	\
		} while (0)
		
#define UNLOCK_VPN()	\
		do {	\
			flock(lockfd, LOCK_UN); \
			close(lockfd);	\
		} while (0)
	
typedef enum { VPN_REQ_ADD_VPN=0, VPN_REQ_REM_VPN=1} VPN_REQ_T;
struct VPN_REQUEST_DATA {
		void *request_data;
		VPN_REQ_T request_type;
		struct list_head list;
};

/*
	Prototype declared here
*/
void usage(void);

/*
	Globals defined here
*/
extern const char FW_VPNGRE[];
unsigned char debug_on=0;
unsigned char *valid_vpn_parameters[MAX_VPN_CRE_PARA_NUM] =
{
	"vpn_mode",
	"vpn_priority",
	"vpn_type",
	"vpn_enable",
	"authtype",
	"enctype",
	"account_proxy",
	"vpn_port",
	"vpn_idletime",
	"serverIP",
	"userName",
	"passwd",
	"tunnelName",
	"userID",
	"attach_mode",
	"ips",
	"domains",
	"terminal_mac",
	"debug"
};

char *vpn_accpxy_params[VPN_ACCPXY_PARAM_NUM]=
{
	"Result",
	"ID",
	"Parameter",
	"CmdType",
	"SequenceId",
	"Status",
	"FailReason",
	"data",
	"vpn_addr",
	"vpn_port",
	"vpn_user",
	"vpn_pwd",
	"account_timeout"	
};

int is_valid_parameter(unsigned char *para) 
{
	int i;


	for(i=0 ; i<MAX_VPN_CRE_PARA_NUM ; i++)
	{
		if(!strcmp(valid_vpn_parameters[i], para))
			return i;
	}

	return -1;
}

void set_parameter(gdbus_vpn_connection_info_t *vpn_connection_info, int parameter_idx, char *value)
{
	int i;

	
	switch(parameter_idx) {
		case 0:
			vpn_connection_info->vpn_tunnel_info.vpn_mode = atoi(value);
			break;
		case 1:
			vpn_connection_info->vpn_tunnel_info.vpn_priority = atoi(value);
			break;
		case 2:
			vpn_connection_info->vpn_tunnel_info.vpn_type = atoi(value);
			break;
		case 3:
			vpn_connection_info->vpn_tunnel_info.vpn_enable = atoi(value);
			break;
		case 4:
			vpn_connection_info->vpn_tunnel_info.authtype = atoi(value);
			break;
		case 5:
			vpn_connection_info->vpn_tunnel_info.enctype = atoi(value);
			break;
		case 6:
			snprintf(vpn_connection_info->vpn_tunnel_info.account_proxy
					, sizeof(vpn_connection_info->vpn_tunnel_info.account_proxy)
					, "%s", value);
			break;
		case 7:
			vpn_connection_info->vpn_tunnel_info.vpn_port = atoi(value);
			break;
		case 8:
			vpn_connection_info->vpn_tunnel_info.vpn_idletime = atoi(value);
			break;
		case 9:
			snprintf(vpn_connection_info->vpn_tunnel_info.serverIP
					, sizeof(vpn_connection_info->vpn_tunnel_info.serverIP)
					, "%s", value);
			break;
		case 10:
			snprintf(vpn_connection_info->vpn_tunnel_info.userName
					, sizeof(vpn_connection_info->vpn_tunnel_info.userName)
					, "%s", value);
			break;
		case 11:
			snprintf(vpn_connection_info->vpn_tunnel_info.passwd
					, sizeof(vpn_connection_info->vpn_tunnel_info.passwd)
					, "%s", value);
			break;
		case 12:
			snprintf(vpn_connection_info->vpn_tunnel_info.tunnelName
					, sizeof(vpn_connection_info->vpn_tunnel_info.tunnelName)
					, "%s", value);
			break;
		case 13:
			snprintf(vpn_connection_info->vpn_tunnel_info.userID
					, sizeof(vpn_connection_info->vpn_tunnel_info.userID)
					, "%s", value);
			break;
		case 14:
			vpn_connection_info->attach_mode= atoi(value);
			break;
		case 15:
			i=0;
			while(vpn_connection_info->ips[i]) {
				i++;
			}
			vpn_connection_info->ips[i] = malloc(strlen(value));
			sprintf(vpn_connection_info->ips[i], "%s", value);
			break;
		case 16:
			i=0;
			while(vpn_connection_info->domains[i]) {
				i++;
			}
			vpn_connection_info->domains[i] = malloc(strlen(value));
			sprintf(vpn_connection_info->domains[i], "%s", value);
			break;
		case 17:
			i=0;
			while(vpn_connection_info->terminal_mac[i]) {
				i++;
			}
			vpn_connection_info->terminal_mac[i] = malloc(strlen(value));
			sprintf(vpn_connection_info->terminal_mac[i], "%s", value);
			break;
		case 18:
			debug_on = atoi(value);
			break;
		default:
			printf(" %s %d Invalid parameter index !", __func__, __LINE__);
	}
	
}

void parse_parameter(gdbus_vpn_connection_info_t *vpn_connection_info_ptr, unsigned char *para, unsigned char *value)
{
	int para_idx;
	
	
	para_idx=is_valid_parameter(para);
	if(para_idx != -1) {
		set_parameter(vpn_connection_info_ptr, para_idx, value);
	}
}

void dump_parameter( gdbus_vpn_connection_info_t *vpn_connection_info_ptr )
{
	int i;

	
	AUG_PRT("%s \n", __func__);
	AUG_PRT("===============================\n");
	AUG_PRT("	 vpn_type = %s\n", vpn_connection_info_ptr->vpn_tunnel_info.vpn_type==VPN_TYPE_L2TP ? "VPN_TYPE_L2TP" : "VPN_TYPE_PPTP");
	AUG_PRT("	 vpn_mode = %s\n", (vpn_connection_info_ptr->vpn_tunnel_info.vpn_mode==VPN_MODE_RANDOM)?"VPN_MODE_RANDOM":"VPN_MODE_STEADY");
	AUG_PRT("	 vpn_priority = %d\n", vpn_connection_info_ptr->vpn_tunnel_info.vpn_priority);
	AUG_PRT("	 account_proxy = %s\n", vpn_connection_info_ptr->vpn_tunnel_info.account_proxy);
	AUG_PRT("	 vpn_port = %d\n", vpn_connection_info_ptr->vpn_tunnel_info.vpn_port);
	AUG_PRT("	 vpn_idletime = %d\n", vpn_connection_info_ptr->vpn_tunnel_info.vpn_idletime);
	AUG_PRT("	 serverIP = %s\n", vpn_connection_info_ptr->vpn_tunnel_info.serverIP);
	AUG_PRT("	 userName = %s\n", vpn_connection_info_ptr->vpn_tunnel_info.userName);
	AUG_PRT("	 passwd = %s\n", vpn_connection_info_ptr->vpn_tunnel_info.passwd);
	AUG_PRT("	 authtype = %d\n", vpn_connection_info_ptr->vpn_tunnel_info.authtype);
	AUG_PRT("	 enctype = %d\n", vpn_connection_info_ptr->vpn_tunnel_info.enctype);
	AUG_PRT("	 tunnelName = %s\n", vpn_connection_info_ptr->vpn_tunnel_info.tunnelName);
	AUG_PRT("	 userID = %s\n", vpn_connection_info_ptr->vpn_tunnel_info.userID);
	AUG_PRT("	 attach_mode = %s\n", (vpn_connection_info_ptr->attach_mode==ATTACH_MODE_NONE)?"ATTACH_MODE_NONE":((vpn_connection_info_ptr->attach_mode==ATTACH_MODE_DIP)?"ATTACH_MODE_DIP":"ATTACH_MODE_SMAC"));
	i=0;
	while(vpn_connection_info_ptr->domains[i] != NULL){		
		AUG_PRT("	 domains[%d] = %s\n", i, vpn_connection_info_ptr->domains[i]);
		i++;
	}
	i=0;
	while(vpn_connection_info_ptr->ips[i] != NULL){		
		AUG_PRT("	 ips[%d] = %s\n", i, vpn_connection_info_ptr->ips[i]);
		i++;
	}
	i=0;
	while(vpn_connection_info_ptr->terminal_mac[i] != NULL){		
		AUG_PRT("	 terminal_mac[%d] = %s\n", i, vpn_connection_info_ptr->terminal_mac[i]);
		i++;
	}	
	AUG_PRT("===============================\n");
}

#ifdef CONFIG_USER_PPTP_CLIENT_PPTP
int CreateWanPPTPTunnel(gdbus_vpn_tunnel_info_t *vpn_tunnel_info, ATTACH_MODE_T attach_mode, unsigned char *reason)
{
	MIB_PPTP_T entry;
	unsigned char vpn_mode=VPN_MODE_STEADY;
	unsigned char priority = VPN_PRIO_NONE;
	int status = 0, is_exist=-1, enable;
	unsigned int pptpEntryNum, i;//, j;
	char tmpBuf[100];
	int map=0, ret=0;
	

	if(vpn_tunnel_info==NULL || reason==NULL){
		status=1;
		strcpy(reason, "vpn_tunnel_info or reason is NULL pointer!");
		goto CreatePPTPDone;
	}

	vpn_mode = (vpn_tunnel_info->vpn_mode==VPN_MODE_RANDOM)?VPN_MODE_RANDOM:VPN_MODE_STEADY;

	if( vpn_mode==VPN_MODE_RANDOM ) {
		if( request_vpn_accpxy_server(vpn_tunnel_info, reason)==-1 ) {
			status = 1;
			//goto CreatePPTPDone;
		}
	} else {
		if(vpn_tunnel_info->serverIP[0]=='\0' || vpn_tunnel_info->userName[0]=='\0' ||
			vpn_tunnel_info->passwd[0]=='\0' || vpn_tunnel_info->userID[0]=='\0') {
			status=1;
			strcpy(reason, "serverIP or passwd is NULL string!");
			//goto CreatePPTPDone;
		}
	}

	if(vpn_tunnel_info->vpn_enable == VPN_ENABLE) {
		enable = 1;		
		if ( !mib_set(MIB_PPTP_ENABLE, (void *)&enable) ) {
			strcpy(reason, "set MIB_PPTP_ENABLE fail");
			status=1;
			//goto CreatePPTPDone;
		}
	} else {
		if ( !mib_get(MIB_PPTP_ENABLE, (void *)&enable) ) {
			strcpy(reason, "MIB_PPTP_ENABLE not exist");
			status=1;
			//goto CreatePPTPDone;
		}
	}

	VPN_DBG_PRT(debug_on, "serverIP=%s,userName=%s,passwd=%s\n",vpn_tunnel_info->serverIP,vpn_tunnel_info->userName,vpn_tunnel_info->passwd);

	/*gateway PPTP feature is disable*/
	if(!enable){
		status=1;
		//reason = "PPTP is Disable"
		strcpy(reason, "MIB_PPTP_ENABLE is Disable");
		//goto CreatePPTPDone;
	}

	pptpEntryNum = mib_chain_total(MIB_PPTP_TBL); /* get chain record size */

	VPN_DBG_PRT(debug_on, "pptpEntryNum=%d eable=%d\n", pptpEntryNum, enable);

	if (enable) {
		//check input serverIP
		for (i=0; i<pptpEntryNum; i++)
		{
			if ( !mib_chain_get(MIB_PPTP_TBL, i, (void *)&entry) )
				continue;

			if (!strcmp(vpn_tunnel_info->tunnelName, entry.tunnelName))
			{
				is_exist=i;
				break;
			}
			else
				map |= (1<<entry.idx);
		}
		VPN_DBG_PRT(debug_on, "pptpEntryNum=%d is_exist=%d\n",pptpEntryNum, is_exist);

		if(pptpEntryNum >= MAX_PPTP_NUM && is_exist<0)
		{
			status=1;
			strcpy(reason, "PPTP SW table Full!");
			//goto CreatePPTPDone;
		}

		VPN_DBG_PRT(debug_on, "map=%d\n", map);

		if(is_exist==-1) {
			memset(&entry, 0, sizeof(entry));
			for (i=0; i<MAX_PPTP_NUM; i++) {
				if (!(map & (1<<i))) {
					entry.idx = i;
					break;
				}
			}
		}

		entry.vpn_type = vpn_tunnel_info->vpn_type;

		//printf("***** PPTP: entry.ifIndex=0x%x\n", entry.ifIndex);
		strcpy(entry.server, vpn_tunnel_info->serverIP);
		strcpy(entry.username, vpn_tunnel_info->userName);
		strcpy(entry.password, vpn_tunnel_info->passwd);

		VPN_DBG_PRT(debug_on, "map=%d entry.idx=%d\n", map,entry.idx);

		if(vpn_tunnel_info->tunnelName[0] != '\0')			
			sprintf(entry.tunnelName, "%s", vpn_tunnel_info->tunnelName);
		else
			sprintf(entry.tunnelName, "PPTP-VPN%d", entry.idx+1);

		VPN_DBG_PRT(debug_on, "userID=%s entry.tunnelName=%s\n",vpn_tunnel_info->userID,entry.tunnelName);

		/*dbus will give us a userID, we record it into our PPTP table.*/
		strcpy(entry.userID, vpn_tunnel_info->userID);

		/*dbus need to feedback tunnel name!*/
		strcpy(vpn_tunnel_info->tunnelName, entry.tunnelName);

		if(is_exist<0)
			entry.authtype = vpn_tunnel_info->authtype;

		entry.conntype = CONNECT_ON_PKT_COUNT;
		entry.idletime = vpn_tunnel_info->vpn_idletime;
		entry.vpn_mode = vpn_mode;
		entry.attach_mode = attach_mode;

		if( vpn_mode==VPN_MODE_RANDOM ){
			sprintf(entry.account_proxy, "%s", vpn_tunnel_info->account_proxy);
			sprintf(entry.account_proxy_msg, "%s", vpn_tunnel_info->account_proxy_msg);
			entry.account_proxy_result = vpn_tunnel_info->account_proxy_result;
		}

		if(vpn_tunnel_info->vpn_port)
			entry.vpn_port = vpn_tunnel_info->vpn_port;

		priority = vpn_tunnel_info->vpn_priority;
		if(VPN_PRIO_0<=priority && priority<=VPN_PRIO_7)
			entry.priority = priority-1;

		entry.vpn_enable = vpn_tunnel_info->vpn_enable;

		if(is_exist<0)
			entry.enctype = vpn_tunnel_info->enctype;

		VPN_DBG_PRT(debug_on, "serverIP=%s,userName=%s,passwd=%s,authtype=%d enctype=%d\n", vpn_tunnel_info->serverIP, vpn_tunnel_info->userName, vpn_tunnel_info->passwd, vpn_tunnel_info->authtype, vpn_tunnel_info->enctype);
		//entry.authtype = 2; //david-test, my server only support chap!

		// Mason Yu. Add VPN ifIndex
		// unit declarations for ppp  on if_sppp.h
		// (1) 0 ~ 7: pppoe/pppoa, (2) 8: 3G, (3) 9 ~ 10: PPTP, (4) 11 ~12: L2TP
		entry.ifIndex = TO_IFINDEX(MEDIA_PPTP, (entry.idx+9), PPTP_INDEX(entry.idx));
		
		if(is_exist>=0){
			if(!mib_chain_update(MIB_PPTP_TBL, &entry, is_exist)) {
				strcpy(reason, "Error! Update chain record.");
				status=1;
				//goto CreatePPTPDone;
			}
		}
		else{
			ret = mib_chain_add(MIB_PPTP_TBL, (void *)&entry);
			if (ret == 0) {
				strcpy(reason, "Error! Add chain record.");
				status=1;
				//goto CreatePPTPDone;
			}
			else if (ret == -1) {
				status=1;
				strcpy(reason, "PPTP SW table Full!");
				//goto CreatePPTPDone;
			}
		}
		if(status == 0){
		pptpEntryNum = mib_chain_total(MIB_PPTP_TBL); /* get chain record size */
		VPN_DBG_PRT(debug_on, "pptpEntryNum=%d\n", __func__, __LINE__, pptpEntryNum);
		if(is_exist>=0){
			AUG_PRT("VPN tunnel is updated !\n");
			applyPPtP(&entry, 3, is_exist);
			applyPPtP(&entry, 2, is_exist);
		}
		else{
			AUG_PRT("VPN tunnel is added (Without add RG Wan needed ..)!\n");
			applyPPtP(&entry, 2, pptpEntryNum-1);
			NF_Init_VPN_Policy_Route(entry.tunnelName);
		}
	}
	}

CreatePPTPDone:
#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif

	return status;
}

void SyncPPTPRouteEntryByMode(unsigned char *tunnelName, ATTACH_MODE_T attach_mode) {
	MIB_CE_PPTP_ROUTE_T pptp_r_entry;
	int i, total_route_entry;

	total_route_entry = mib_chain_total(MIB_PPTP_ROUTE_TBL);
	for(i=(total_route_entry-1) ; i>=0 ; i--) {
		if (!mib_chain_get(MIB_PPTP_ROUTE_TBL, i, (void *)&pptp_r_entry))
			continue;

		if(strcmp(tunnelName, pptp_r_entry.tunnelName))
			continue;
		
		if(pptp_r_entry.attach_mode != attach_mode)
			mib_chain_delete(MIB_PPTP_ROUTE_TBL, i);		
	}
}

int AttachWanPPTPTunnel(gdbus_vpn_tunnel_info_t *vpn_tunnel_info, unsigned char *ipDomainNameAddr[], unsigned char *reason)
{
	int findTunnel=-1, findRouteIdx=-1;
	unsigned int pptpEntryNum, i=0;
	unsigned int pptpRouteEntryNum;
	MIB_CE_PPTP_ROUTE_T route_entry;
	ATTACH_MODE_T attach_mode;
	MIB_PPTP_T entry;
	int status=0,ret;	
	int enable=0;
	int j;
	

	if(vpn_tunnel_info==NULL || ipDomainNameAddr==NULL || reason==NULL){
		status=1;
		strcpy(reason, "some parameter(s) exist NULL pointer!");
		goto AttachVPNDone;
	}

	if(vpn_tunnel_info->tunnelName[0]=='\0' || vpn_tunnel_info->userID[0]=='\0'){
		status=1;
		strcpy(reason, "some parameter(s) is NULL string!");
		goto AttachVPNDone;
	} else {
		pptpRouteEntryNum = mib_chain_total(MIB_PPTP_ROUTE_TBL);
		for(j=(pptpRouteEntryNum-1) ; j>=0 ; j--) {
			if (!mib_chain_get(MIB_PPTP_ROUTE_TBL, j, (void *)&route_entry))
				continue;

			if(strcmp(vpn_tunnel_info->tunnelName, route_entry.tunnelName))
				continue;
			
			mib_chain_delete(MIB_PPTP_ROUTE_TBL, j);
		}
		RG_Flush_PPTP_Route(vpn_tunnel_info->tunnelName);
		RG_Flush_PPTP_Dynamic_URL_Route(vpn_tunnel_info->tunnelName);
	}

	VPN_DBG_PRT(debug_on, "tunnelName=%s\n",vpn_tunnel_info->tunnelName);

	if ( !mib_get(MIB_PPTP_ENABLE, (void *)&enable) ){
		strcpy(reason, "MIB_PPTP_ENABLE is not exist!");
		status=1;
		goto AttachVPNDone;
	}
	/*gateway PPTP feature is disable*/
	if(!enable){
		status=1;
		//reason = "PPTP is Disable"
		strcpy(reason, "MIB_PPTP_ENABLE is Disable");
		goto AttachVPNDone;
	}
	pptpEntryNum = mib_chain_total(MIB_PPTP_TBL); /* get chain record size */

	VPN_DBG_PRT(debug_on, "pptpEntryNum=%d\n",pptpEntryNum);

	if(pptpEntryNum == 0){
		status=2;
		//reason = "PPTP is Disable"
		strcpy(reason, "VPN is not exist!");
		goto AttachVPNDone;
	}

	for (i=0; i<pptpEntryNum; i++)
	{
		if ( !mib_chain_get(MIB_PPTP_TBL, i, (void *)&entry) )
			continue;
		
		if(!strcmp(vpn_tunnel_info->tunnelName,entry.tunnelName))
		{
			findTunnel=i;
			attach_mode = entry.attach_mode;
			break;
		}
	}

	VPN_DBG_PRT(debug_on, "findTunnel=%d\n",findTunnel);

	if(findTunnel==-1)
	{
		status=2;
		strcpy(reason, "VPN tunnel is not exist!");
		goto AttachVPNDone;
	}

	i=0;
	while(ipDomainNameAddr[i] != NULL)
	{
		unsigned char *ipaddr1,*ipaddr2,*netmask;
		unsigned char sMac[MAC_ADDR_LEN];
		unsigned char ip[100];
		char *p;
		int c;
		unsigned int mask_inver;
		unsigned int mask;
		int ipv4_addr1,ipv4_addr2;

		VPN_DBG_PRT(debug_on, "i=%d\n", i);

		strcpy(ip,ipDomainNameAddr[i]);
		
		AUG_PRT("ip=%s\n",ip);
		
		if(strstr(ip,"/"))
		{
			if(ATTACH_MODE_DIP != attach_mode) {
				i++;
				continue;
			}
			
			/*ip/mask =  192.168.1.1/24*/
			VPN_DBG_PRT(debug_on, "%s-%d \n",__func__,__LINE__);
			ipaddr1 = strtok(ip,"/");
			ipv4_addr1 = inet_addr(ipaddr1);
			if(ipv4_addr1==-1){
				printf("%s-%d set ip start error!\n",__func__,__LINE__);
				i++;
				continue;
			}
			netmask = strtok(NULL,"/");
			c=atoi(netmask);
			mask_inver = 32 - c;
			mask = ~((1<<mask_inver)-1);			
			ipv4_addr1 &= mask;
			ipv4_addr2 = (ipv4_addr1 | ~mask);
			if(ipv4_addr2==-1){
				printf("%s-%d set ip end error!\n",__func__,__LINE__);
				i++;
				continue;
			}
			VPN_DBG_PRT(debug_on, "ipv4_addr1=%x, ipv4_addr2=%x mask=%x\n",ipv4_addr1,ipv4_addr2,mask);
			VPN_DBG_PRT(debug_on, "vpn_tunnel_info->tunnelName = %s\n",vpn_tunnel_info->tunnelName);
			if(!Check_PPTP_Route_DIP(vpn_tunnel_info->tunnelName,ipv4_addr1,ipv4_addr2))
			{
				VPN_DBG_PRT(debug_on, "ipv4_addr1=%x, ipv4_addr2=%x mask=%x\n",ipv4_addr1,ipv4_addr2,mask);
				/*add it into pptp route mib chain!*/
				memset(&route_entry, 0, sizeof(route_entry));
				route_entry.Enable = 1;
				strcpy(route_entry.tunnelName,vpn_tunnel_info->tunnelName);
				route_entry.ipv4_src_start=ipv4_addr1;
				route_entry.ipv4_src_end=ipv4_addr2;
				route_entry.rg_wan_idx = entry.rg_wan_idx;
				route_entry.ifIndex = entry.ifIndex;
				route_entry.attach_mode = ATTACH_MODE_DIP;
				ret = mib_chain_add(MIB_PPTP_ROUTE_TBL, (void *)&route_entry);
				if (ret == 0) {
					strcpy(reason, "add pptp route chain error!");
					status=1;
					goto AttachVPNDone;
				}
				else if (ret == -1) {
					strcpy(reason, "pptp route table full!");
					status=1;
					goto AttachVPNDone;
				}
			}
		}
		else if (strstr(ip,"-"))
		{
			if(ATTACH_MODE_DIP != attach_mode) {
				i++;
				continue;
			}
			
			VPN_DBG_PRT(debug_on, "%s-%d \n",__func__,__LINE__);
			/*ip range =  192.168.1.1-192.168.1.10*/
			ipaddr1 = strtok(ip,"-");
			ipv4_addr1 = inet_addr(ipaddr1);
			if(ipv4_addr1==-1){
				printf("%s-%d set ip start error!\n",__func__,__LINE__);
				i++;
				continue;
			}
			ipaddr2 = strtok(NULL,"-");
			ipv4_addr2 = inet_addr(ipaddr2);
			if(ipv4_addr2==-1){
				printf("%s-%d set ip end error!\n",__func__,__LINE__);
				i++;
				continue;
			}
			printf("ipaddr1=%s ipaddr2=%s\n",ipaddr1,ipaddr2);
			printf("ipv4_addr1=%x ipv4_addr2=%x\n",ipv4_addr1,ipv4_addr2);
			if(!Check_PPTP_Route_DIP(vpn_tunnel_info->tunnelName,ipv4_addr1,ipv4_addr2))
			{
				/*add it into pptp route mib chain!*/
				VPN_DBG_PRT(debug_on, "ipv4_addr1=%x, ipv4_addr2=%x mask=%x\n",ipv4_addr1,ipv4_addr2,mask);
				memset(&route_entry, 0, sizeof(route_entry));
				route_entry.Enable = 1;
				strcpy(route_entry.tunnelName,vpn_tunnel_info->tunnelName);
				route_entry.ipv4_src_start=ipv4_addr1;
				route_entry.ipv4_src_end=ipv4_addr2;
				route_entry.rg_wan_idx = entry.rg_wan_idx;
				route_entry.ifIndex = entry.ifIndex;
				route_entry.attach_mode = ATTACH_MODE_DIP;
				ret = mib_chain_add(MIB_PPTP_ROUTE_TBL, (void *)&route_entry);
				if (ret == 0) {
					strcpy(reason, "add pptp route chain error!");
					status=1;
					goto AttachVPNDone;
				}
				else if (ret == -1) {
					strcpy(reason, "pptp route table full!");
					status=1;
					goto AttachVPNDone;
				}
			}
		}
		else if (strstr(ip,":"))
		{
			if(ATTACH_MODE_SMAC != attach_mode) {
				i++;
				continue;
			}
			
			sscanf(ip, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &sMac[0], &sMac[1], &sMac[2], &sMac[3], &sMac[4], &sMac[5]);

			if(!Check_PPTP_Route_SMAC(vpn_tunnel_info->tunnelName, sMac))
			{
				memset(&route_entry, 0, sizeof(route_entry));
				route_entry.Enable = 1;
				strcpy(route_entry.tunnelName,vpn_tunnel_info->tunnelName);
				memcpy(route_entry.sMAC, sMac, MAC_ADDR_LEN);
				route_entry.rg_wan_idx = entry.rg_wan_idx;
				route_entry.ifIndex = entry.ifIndex;
				route_entry.attach_mode = ATTACH_MODE_SMAC;
				ret = mib_chain_add(MIB_PPTP_ROUTE_TBL, (void *)&route_entry);
				if (ret == 0) {
					strcpy(reason, "add pptp route chain error!");
					status=1;
					goto AttachVPNDone;
				}
				else if (ret == -1) {
					strcpy(reason, "pptp route table full!");
					status=1;
					goto AttachVPNDone;
				}
			}
		}
		else
		{
			if(ATTACH_MODE_DIP != attach_mode) {
				i++;
				continue;
			}
			
			VPN_DBG_PRT(debug_on, "%s-%d \n",__func__,__LINE__);
			/*add it into pptp route mib chain!*/
			if(!Check_PPTP_Route_URL(vpn_tunnel_info->tunnelName,ip)){
				memset(&route_entry, 0, sizeof(route_entry));
				route_entry.Enable = 1;
				strcpy(route_entry.tunnelName,vpn_tunnel_info->tunnelName);
				route_entry.ipv4_src_start=0;
				route_entry.ipv4_src_end=0;
				route_entry.rg_wan_idx = entry.rg_wan_idx;
				route_entry.ifIndex = entry.ifIndex;
				strcpy(route_entry.url,ip);
				route_entry.attach_mode = ATTACH_MODE_DIP;
				ret = mib_chain_add(MIB_PPTP_ROUTE_TBL, (void *)&route_entry);
				if (ret == 0) {
					strcpy(reason, "add pptp route chain error!");
					status=1;
					goto AttachVPNDone;
				}
				else if (ret == -1) {
					strcpy(reason, "pptp route table full!");
					status=1;
					goto AttachVPNDone;
				}
				strcpy(reason, "Set URL OK!");
			}
		}

		i++;

	}

	VPN_DBG_PRT(debug_on, " Done ! \n");

AttachVPNDone:
	// Avoid someone attach DIP mode first then attach sMAC mode
	SyncPPTPRouteEntryByMode(vpn_tunnel_info->tunnelName, attach_mode);
#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif

	return status;
}

int DetachWanPPTPTunnel(gdbus_vpn_tunnel_info_t *vpn_tunnel_info, ATTACH_MODE_T attach_mode, unsigned char *ipDomainNameAddr[], unsigned char *reason)
{
	int status=0;
	unsigned int pptpEntryNum, i;
	unsigned int findTunnel=0, totalnum;
	int enable=0;
	int entryNum;
	MIB_PPTP_T entry;

	if(vpn_tunnel_info==NULL || ipDomainNameAddr==NULL || reason==NULL){
		status=1;
		strcpy(reason, "some parameter(s) exist NULL pointer!");
		goto DetachVPNDone;
	}

	if(vpn_tunnel_info->tunnelName[0]=='\0' || vpn_tunnel_info->userID[0]=='\0'){
		status=1;
		strcpy(reason, "some parameter(s) is NULL string!");
		goto DetachVPNDone;
	}

	VPN_DBG_PRT(debug_on, "tunnelName=%s \n",vpn_tunnel_info->tunnelName);

	if ( !mib_get(MIB_PPTP_ENABLE, (void *)&enable) ){
		strcpy(reason, "MIB_PPTP_ENABLE is not exist!");
		status=1;
		goto DetachVPNDone;
	}

	/*gateway PPTP feature is disable*/
	if(!enable){
		status=1;
		strcpy(reason, "MIB_PPTP_ENABLE is Disable");
		goto DetachVPNDone;
	}

	pptpEntryNum = mib_chain_total(MIB_PPTP_TBL); /* get chain record size */
	VPN_DBG_PRT(debug_on, "pptpEntryNum=%d\n",pptpEntryNum);

	if(pptpEntryNum == 0){
		status=2;
		strcpy(reason, "VPN is not exist!");
		goto DetachVPNDone;
	}

	for (i=0; i<pptpEntryNum; i++)
	{
		if ( !mib_chain_get(MIB_PPTP_TBL, i, (void *)&entry) )
			continue;
		if(!strcmp(vpn_tunnel_info->tunnelName,entry.tunnelName))
		{
			findTunnel=1;
		}
	}
	VPN_DBG_PRT(debug_on, "findTunnel=%d\n",findTunnel);

	if(!findTunnel)
	{
		status=2;
		strcpy(reason, "VPN tunnel is not exist!");
		goto DetachVPNDone;
	}
	VPN_DBG_PRT(debug_on, "%s-%d\n");

	totalnum = mib_chain_total(MIB_PPTP_ROUTE_TBL); /* get chain record size */
	if(totalnum == 0)
	{
		status=1;
		strcpy(reason, "PPTP route table is not exist!");
		goto DetachVPNDone;
	}

	i=0;
	while(ipDomainNameAddr[i] != NULL)
	{
		unsigned char *ipaddr1,*ipaddr2,*netmask;
		unsigned char sMac[MAC_ADDR_LEN];
		unsigned char ip[100];
		char *p;
		int c;
		unsigned int mask_inver;
		unsigned int mask;
		unsigned int ipv4_addr1,ipv4_addr2;

		VPN_DBG_PRT(debug_on, "i=%d\n",i);
		strcpy(ip,ipDomainNameAddr[i]);
		//ip = ipDomainNameAddr[i];
		VPN_DBG_PRT(debug_on, "ip=%s\n",ip);
		if(strstr(ip,"/"))
		{
			/*ip/mask =  192.168.1.1/24*/
			VPN_DBG_PRT(debug_on, "%s-%d \n");
			ipaddr1 = strtok(ip,"/");
			ipv4_addr1 = inet_addr(ipaddr1);
			netmask = strtok(NULL,"/");
			c=atoi(netmask);
			mask_inver = 32 - c;
			mask = ~((1<<mask_inver)-1);			
			ipv4_addr1 &= mask;
			ipv4_addr2 = (ipv4_addr1 | ~mask);
			VPN_DBG_PRT(debug_on, "ipv4_addr1=%x, ipv4_addr2=%x mask=%x\n",ipv4_addr1,ipv4_addr2,mask);
			if(Del_PPTP_Route_DIP(vpn_tunnel_info->tunnelName,ipv4_addr1,ipv4_addr2))
			{
				//match pptp route table.
				status=0;
				strcpy(reason, "PPTP route del OK!");
				VPN_DBG_PRT(debug_on, "%s-%d ipv4_addr1=%x, ipv4_addr2=%x exist!\n",ipv4_addr1,ipv4_addr2);
			}
			else{
				status=1;
				strcpy(reason, "PPTP route table is not exist!");
				VPN_DBG_PRT(debug_on, "%s-%d ipv4_addr1=%x, ipv4_addr2=%x not exist!\n",ipv4_addr1,ipv4_addr2);
				goto DetachVPNDone;
			}
		}
		else if (strstr(ip,"-"))
		{
			VPN_DBG_PRT(debug_on, "%s-%d \n",__func__,__LINE__);
			/*ip range =  192.168.1.1-192.168.1.10*/
			ipaddr1 = strtok(ip,"-");
			ipv4_addr1 = inet_addr(ipaddr1);
			ipaddr2 = strtok(NULL,"-");
			ipv4_addr2 = inet_addr(ipaddr2);
			VPN_DBG_PRT(debug_on, "ipaddr1=%s ipaddr2=%s\n",ipaddr1,ipaddr2);
			VPN_DBG_PRT(debug_on, "ipv4_addr1=%x ipv4_addr2=%x\n",ipv4_addr1,ipv4_addr2);
			if(Del_PPTP_Route_DIP(vpn_tunnel_info->tunnelName,ipv4_addr1,ipv4_addr2))
			{
				//match pptp route table.
				status=0;
				strcpy(reason, "PPTP route del OK!");
				VPN_DBG_PRT(debug_on, "%s-%d ipv4_addr1=%x, ipv4_addr2=%x exist!\n",ipv4_addr1,ipv4_addr2);
			}
			else{
				status=1;
				strcpy(reason, "PPTP route table is not exist!");
				VPN_DBG_PRT(debug_on, "ipv4_addr1=%x, ipv4_addr2=%x not exist!\n",ipv4_addr1,ipv4_addr2);
				goto DetachVPNDone;
			}
		}
		else if (strstr(ip,":"))
		{
			sscanf(ip, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &sMac[0], &sMac[1], &sMac[2], &sMac[3], &sMac[4], &sMac[5]);
			if(Check_PPTP_Route_SMAC(vpn_tunnel_info->tunnelName, sMac))
			{
				if(Del_PPTP_Route_SMAC(vpn_tunnel_info->tunnelName,sMac))
				{
					//match pptp route table.
					status=0;
					strcpy(reason, "PPTP route del OK!");
					VPN_DBG_PRT(debug_on, "sMac=%x:%x:%x:%x:%x:%x exist!\n", sMac[0], sMac[1], sMac[2], sMac[3], sMac[4], sMac[5]);
				}
				else{
					status=1;
					strcpy(reason, "PPTP route table is not exist!");
					VPN_DBG_PRT(debug_on, "sMac=%x:%x:%x:%x:%x:%x not exist!\n", sMac[0], sMac[1], sMac[2], sMac[3], sMac[4], sMac[5]);
					goto DetachVPNDone;
				}
			}
		}
		else
		{
			/*URL*/
			VPN_DBG_PRT(debug_on, "%s-%d \n",__func__,__LINE__);
			if(Del_PPTP_Route_URL(vpn_tunnel_info->tunnelName,ip))
			{
				//match pptp route table.
				status=0;
				strcpy(reason, "PPTP route del OK!");
				VPN_DBG_PRT(debug_on, "ip=%s exist!\n",ip);
				RG_Flush_PPTP_Dynamic_URL_Route(vpn_tunnel_info->tunnelName);
				NF_Flush_PPTP_Dynamic_URL_Route(vpn_tunnel_info->tunnelName);
			}
			else{
				status=1;
				strcpy(reason, "PPTP route table is not exist!");
				VPN_DBG_PRT(debug_on, "%s not exist!\n",ip);
				goto DetachVPNDone;
			}
		}

		i++;
	}

	VPN_DBG_PRT(debug_on, " Done ! \n");

DetachVPNDone:
#ifdef CONFIG_RTK_L34_ENABLE
    RG_Flush_PPTP_Route(vpn_tunnel_info->tunnelName);
	NF_Flush_PPTP_Route(vpn_tunnel_info->tunnelName);
    RG_Set_PPTP_Acl_Policy_Route(vpn_tunnel_info->tunnelName, attach_mode);
	NF_Set_PPTP_Policy_Route(vpn_tunnel_info->tunnelName, attach_mode);
#endif
#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif
	return status;
}

int GetWanPPTPTunnelStatus(gdbus_vpn_tunnel_info_t *vpn_tunnel_info, unsigned char *reason, PPTP_Status_Tp pptp_list, int *num)
{
	int status=0;
	unsigned int pptpEntryNum, i;
	unsigned int findUser=0, findTunnel=0;
	//unsigned int decisionCase=0;
	char ifname[IFNAMSIZ];
	int flags, flags_found, isPPTPup;
	int enable=0;
	MIB_PPTP_T entry;

	if(vpn_tunnel_info==NULL || reason==NULL || pptp_list==NULL || num==NULL){
		status=1;
		strcpy(reason, "some parameter(s) exist NULL pointer!");
		goto GetTunnelStatusDone;
	}

	if(vpn_tunnel_info->tunnelName[0]=='\0' || vpn_tunnel_info->userID[0]=='\0'){
		status=1;
		strcpy(reason, "some parameter(s) is NULL string!");
		goto GetTunnelStatusDone;
	}

	AUG_PRT("%s-%d \n",__func__,__LINE__);
	*num=0;
	if ( !mib_get(MIB_PPTP_ENABLE, (void *)&enable) ){
		strcpy(reason, "MIB_PPTP_ENABLE is not exist!");
		status=1;
		goto GetTunnelStatusDone;
	}
	/*gateway PPTP feature is disable*/
	if(!enable){
		status=1;
		//reason = "PPTP is Disable"
		strcpy(reason, "MIB_PPTP_ENABLE is Disable");
		goto GetTunnelStatusDone;
	}
	pptpEntryNum = mib_chain_total(MIB_PPTP_TBL); /* get chain record size */

	if(pptpEntryNum == 0){
		status=2;
		//reason = "PPTP is Disable"
		strcpy(reason, "VPN is not exist!");
		goto GetTunnelStatusDone;
	}
	//case 1: tunnelName!=all, userID=0, not legal
	if(strcmp(vpn_tunnel_info->tunnelName,"all") && !strcmp(vpn_tunnel_info->userID,"0")){
		/*userID =0, but tunnelName!=all*/
		status=1;
		strcpy(reason, "userId=0, but tunnelName!=all!");
		goto GetTunnelStatusDone;
	}
	//case 2: tunnelName=all, userID=0
	if(!strcmp(vpn_tunnel_info->tunnelName,"all") && !strcmp(vpn_tunnel_info->userID,"0")){
		/*it means check all VPN tunnel status*/
		for (i=0; i<pptpEntryNum; i++)
		{
			if ( !mib_chain_get(MIB_PPTP_TBL, i, (void *)&entry) )
				continue;
			ifGetName(entry.ifIndex, ifname, sizeof(ifname));
			AUG_PRT("%s-%d entry.ifIndex=%x, ifname=%s\n",__func__,__LINE__,entry.ifIndex,ifname);
			flags_found = getInFlags(ifname, &flags);
			AUG_PRT("%s-%d flags_found=%d\n",__func__,__LINE__,flags_found);
			if (flags_found)
			{
				if (flags & IFF_UP)
				{
					#if 0//def CONFIG_GPON_FEATURE
					if (onu == 5)
						isPPTPup = 1;
					#else
						isPPTPup = 1;
					#endif
				}
			}
			strcpy(pptp_list[i].tunnelName,entry.tunnelName);
			if(isPPTPup)
				strcpy(pptp_list[i].tunnelStatus,"0");
			else
				strcpy(pptp_list[i].tunnelStatus,"1");
			*num +=1;
			AUG_PRT("%s-%d isPPTPup=%d tunnelName=%s, tunnelStatus=%s num=%d\n",__func__,__LINE__,isPPTPup,pptp_list[i].tunnelName,pptp_list[i].tunnelStatus,*num);

			strcpy(reason, "userID=0, tunnelName=all, check all!");
		}
		status=0;
		goto GetTunnelStatusDone;
	}
	//case 3: userID=XXX, tunnelName=all, check all userID's tunnel
	//case 4: userID=XXX, tunnelName=XXX, check userID's, tunnelName Status
	for (i=0; i<pptpEntryNum; i++)
	{
		if ( !mib_chain_get(MIB_PPTP_TBL, i, (void *)&entry) )
			continue;
		if(!strcmp(vpn_tunnel_info->userID,entry.userID))
		{
			findUser=1;
			/*check specified userID VPN*/
			if(!strcmp(vpn_tunnel_info->tunnelName,"all"))
			{
				/*check userID's all VPN*/
				findTunnel=1;
				ifGetName(entry.ifIndex, ifname, sizeof(ifname));
				AUG_PRT("%s-%d entry.ifIndex=%x, ifname=%s\n",__func__,__LINE__,entry.ifIndex,ifname);
				flags_found = getInFlags(ifname, &flags);
				AUG_PRT("%s-%d flags_found=%d\n",__func__,__LINE__,flags_found);
				if (flags_found)
				{
					if (flags & IFF_UP)
					{
						#if 0//def CONFIG_GPON_FEATURE
						if (onu == 5)
							isPPTPup = 1;
						#else
							isPPTPup = 1;
						#endif
					}
				}
				strcpy(pptp_list[i].tunnelName,entry.tunnelName);
				if(isPPTPup)
					strcpy(pptp_list[i].tunnelStatus,"0");
				else
					strcpy(pptp_list[i].tunnelStatus,"1");
				*num += 1;;
				AUG_PRT("%s-%d isPPTPup=%d tunnelName=%s, tunnelStatus=%s num=%d\n",__func__,__LINE__,isPPTPup,pptp_list[i].tunnelName,pptp_list[i].tunnelStatus,*num);

			}
			else if(!strcmp(vpn_tunnel_info->tunnelName,entry.tunnelName))
			{
				/*check specified tunnelName VPN*/
				findTunnel=2;
				ifGetName(entry.ifIndex, ifname, sizeof(ifname));
				AUG_PRT("%s-%d entry.ifIndex=%x, ifname=%s\n",__func__,__LINE__,entry.ifIndex,ifname);
				flags_found = getInFlags(ifname, &flags);
				AUG_PRT("%s-%d flags_found=%d\n",__func__,__LINE__,flags_found);
				if (flags_found)
				{
					if (flags & IFF_UP)
					{
						#if 0//def CONFIG_GPON_FEATURE
						if (onu == 5)
							isPPTPup = 1;
						#else
							isPPTPup = 1;
						#endif
					}
				}
				strcpy(pptp_list[i].tunnelName,entry.tunnelName);
				if(isPPTPup)
					strcpy(pptp_list[i].tunnelStatus,"0");
				else
					strcpy(pptp_list[i].tunnelStatus,"1");
				*num += 1;
				AUG_PRT("%s-%d isPPTPup=%d tunnelName=%s, tunnelStatus=%s num=%d\n",__func__,__LINE__,isPPTPup,pptp_list[i].tunnelName,pptp_list[i].tunnelStatus,*num);

			}
		}
	}
	if(findUser==1)
	{
		if(findTunnel==1)
		{
			strcpy(reason, "match userID and tunnelName 'all'!");
			status = 0;
		}
		else if(findTunnel==2)
		{
			strcpy(reason, "match userID and tunnelName!");
			status = 0;
		}
		else{
			/*findTunnel==0*/
			/*match userID but match tunnelName fail!*/
			status = 2;
			strcpy(reason, "match tunnelName fail!");
		}
	}
	else
	{
		/*findUser=0*/
		status = 3;
		strcpy(reason, "userID is not exist!");
	}

GetTunnelStatusDone:
	return status;
}

void dump_mib_pptp( void )
{
	MIB_PPTP_T entry;
	MIB_CE_PPTP_ROUTE_T r_entry;
	unsigned int entrynum, i;

	printf(" #######################MIB_PPTP_TBL####################### \n", __func__);

	entrynum = mib_chain_total(MIB_PPTP_TBL);
	for (i=0; i<entrynum; i++)
	{
		if ( !mib_chain_get(MIB_PPTP_TBL, i, (void *)&entry) )
			return;

		printf(" =======================[%d]===================== \n", i);

		printf("  server=%s \n", entry.server);
		printf("  username=%s \n", entry.username);
		printf("  password=%s \n", entry.password);
		printf("  tunnelName=%s \n", entry.tunnelName);
		printf("  userID=%s \n", entry.userID);
		printf("  rg_wan_idx=%d \n", entry.rg_wan_idx);
		printf("  conntype=%d \n", entry.conntype);
		printf("  idletime=%d \n", entry.idletime);
	}

	printf(" #######################MIB_PPTP_ROUTE_TBL####################### \n", __func__);

	entrynum = mib_chain_total(MIB_PPTP_ROUTE_TBL); /* get chain record size */
	for( i=0; i<entrynum; i++)
	{
		if ( !mib_chain_get(MIB_PPTP_ROUTE_TBL, i, (void *)&r_entry) )
			continue;

		printf(" =======================[%d]===================== \n", i);

		printf("  Enable=%d \n", r_entry.Enable);
		printf("  tunnelName=%s \n", r_entry.tunnelName);
		printf("  url=%s \n", r_entry.url);
		printf("  ipv4_src_start=0x%x \n", r_entry.ipv4_src_start);
		printf("  ipv4_src_end=0x%x \n", r_entry.ipv4_src_end);
		printf("  sMAC=%x:%x:%x:%x:%x:%x \n", r_entry.sMAC[0], r_entry.sMAC[1], r_entry.sMAC[2], r_entry.sMAC[3], r_entry.sMAC[4], r_entry.sMAC[5]);
		printf("  ifIndex=%d \n", r_entry.ifIndex);
		printf("  rg_wan_idx=%d \n", r_entry.rg_wan_idx);
	}
}
#endif
#ifdef CONFIG_USER_L2TPD_L2TPD
/*return status: 0:create l2tp wan success, 1:create wan fail.*/
int CreateWanL2TPTunnel(gdbus_vpn_tunnel_info_t *vpn_tunnel_info, ATTACH_MODE_T attach_mode, unsigned char *reason)
{
	MIB_L2TP_T entry;
	unsigned char vpn_mode=VPN_MODE_STEADY;
	unsigned char priority = VPN_PRIO_NONE;
	int status = 0, is_exist=-1, enable;
	unsigned int l2tpEntryNum, i;//, j;
	char tmpBuf[100];
	int map=0, ret=0;
	

	if(vpn_tunnel_info==NULL || reason==NULL){
		status=1;
		strcpy(reason, "vpn_tunnel_info or reason is NULL pointer!");
		goto CreateL2TPDone;
	}

	vpn_mode = (vpn_tunnel_info->vpn_mode==VPN_MODE_RANDOM)?VPN_MODE_RANDOM:VPN_MODE_STEADY;

	if( vpn_mode==VPN_MODE_RANDOM ) {
		if( request_vpn_accpxy_server(vpn_tunnel_info, reason)==-1 ) {
			status = 1;
			//goto CreateL2TPDone;
		}
	} else {
		if(vpn_tunnel_info->serverIP[0]=='\0' || vpn_tunnel_info->userName[0]=='\0' ||
			vpn_tunnel_info->passwd[0]=='\0' || vpn_tunnel_info->userID[0]=='\0') {
			status=1;
			strcpy(reason, "some parameter(s) is NULL string!");
			//goto CreateL2TPDone;
		}
	}

	if(vpn_tunnel_info->vpn_enable == VPN_ENABLE) {
		enable = 1;	
		if ( !mib_set(MIB_L2TP_ENABLE, (void *)&enable) ) {
			strcpy(reason, "set MIB_L2TP_ENABLE fail");
			status=1;
			//goto CreateL2TPDone;
		}
	} else {
		if ( !mib_get(MIB_L2TP_ENABLE, (void *)&enable) ) {
			strcpy(reason, "MIB_L2TP_ENABLE fail");
			status=1;
			//goto CreateL2TPDone;
		}
	}
	
	VPN_DBG_PRT(debug_on, "serverIP=%s,userName=%s,passwd=%s\n",vpn_tunnel_info->serverIP,vpn_tunnel_info->userName,vpn_tunnel_info->passwd);

	/*gateway L2TP feature is disable*/
	if(!enable){
		status=1;
		//reason = "L2TP is Disable"
		strcpy(reason, "MIB_L2TP_ENABLE is Disable");
		//goto CreateL2TPDone;
	}
	
	l2tpEntryNum = mib_chain_total(MIB_L2TP_TBL); /* get chain record size */
	VPN_DBG_PRT(debug_on, "l2tpEntryNum=%d eable=%d tunnelName=%s\n",l2tpEntryNum,enable,vpn_tunnel_info->tunnelName);
	
	if (enable) {
		//check input serverIP
		for (i=0; i<l2tpEntryNum; i++)
		{
			if ( !mib_chain_get(MIB_L2TP_TBL, i, (void *)&entry) )
				continue;
VPN_DBG_PRT(debug_on, "tunnelName=%s %s\n",vpn_tunnel_info->tunnelName,entry.tunnelName);			
			if (!strcmp(vpn_tunnel_info->tunnelName, entry.tunnelName))
			{
				is_exist=i;
				break;
			}
			else
				map |= (1<<entry.idx);
		}
		VPN_DBG_PRT(debug_on, "is_exist=%d\n", is_exist);

		if(l2tpEntryNum >= MAX_L2TP_NUM && is_exist<0)
		{
			status=1;
			strcpy(reason, "L2TP SW table Full!");
			//goto CreateL2TPDone;
		}

		VPN_DBG_PRT(debug_on, "map=%d\n", map);

		if(is_exist==-1) {
			memset(&entry, 0, sizeof(entry));
			for (i=0; i<MAX_L2TP_NUM; i++) {
				if (!(map & (1<<i))) {
					entry.idx = i;
					break;
				}
			}
		}

#ifdef CONFIG_RTK_L34_ENABLE
		{
			int remained;
			remained = Check_RG_Intf_Count();
			if(remained == 0 && is_exist<0){
				/*RG HW Table FULL*/
				strcpy(reason, "RG HW table Full!");
				status=1;
				//goto CreateL2TPDone;
			}
		}
#endif

		entry.vpn_type = vpn_tunnel_info->vpn_type;

		// Mason Yu. Add VPN ifIndex
		// unit declarations for ppp  on if_sppp.h
		// (1) 0 ~ 7: pppoe/pppoa, (2) 8: 3G, (3) 9 ~ 10: PPTP, (4) 11 ~12: L2TP
		entry.ifIndex = TO_IFINDEX(MEDIA_L2TP, (entry.idx+11), L2TP_INDEX(entry.idx));
		//printf("***** L2TP: entry.ifIndex=0x%x\n", entry.ifIndex);
		strcpy(entry.server, vpn_tunnel_info->serverIP);
		strcpy(entry.username, vpn_tunnel_info->userName);
		strcpy(entry.password, vpn_tunnel_info->passwd);

		VPN_DBG_PRT(debug_on, "map=%d entry.idx=%d\n",map,entry.idx);

		if(vpn_tunnel_info->tunnelName[0] != '\0')			
			sprintf(entry.tunnelName, "%s", vpn_tunnel_info->tunnelName);
		else
			sprintf(entry.tunnelName, "L2TP-VPN%d", entry.idx+1);

		VPN_DBG_PRT(debug_on, "userID=%s entry.tunnelName=%s\n",vpn_tunnel_info->userID,entry.tunnelName);

		/*dbus will give us a userID, we record it into our L2TP table.*/
		strcpy(entry.userID, vpn_tunnel_info->userID);

		/*dbus need to feedback tunnel name!*/
		strcpy(vpn_tunnel_info->tunnelName, entry.tunnelName);
		entry.mtu = 1458;
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		entry.conntype = CONTINUOUS;
#else
		entry.conntype = CONNECT_ON_PKT_COUNT;
#endif
		entry.idletime = vpn_tunnel_info->vpn_idletime;
		entry.vpn_mode = vpn_mode;
		entry.attach_mode = attach_mode;

		if( vpn_mode==VPN_MODE_RANDOM ){
			sprintf(entry.account_proxy, "%s", vpn_tunnel_info->account_proxy);
			sprintf(entry.account_proxy_msg, "%s", vpn_tunnel_info->account_proxy_msg);
			entry.account_proxy_result = vpn_tunnel_info->account_proxy_result;
		}

		if(vpn_tunnel_info->vpn_port)
			entry.vpn_port = vpn_tunnel_info->vpn_port;

		priority = vpn_tunnel_info->vpn_priority;
		if(VPN_PRIO_0<=priority && priority<=VPN_PRIO_7)
			entry.priority = priority-1;

		entry.vpn_enable = vpn_tunnel_info->vpn_enable;

		entry.enctype = vpn_tunnel_info->enctype;
		if(entry.enctype != VPN_ENCTYPE_NONE)
		{
			entry.authtype = AUTH_CHAPMSV2;
		}

		VPN_DBG_PRT(debug_on, "serverIP=%s,userName=%s,passwd=%s,tunnelName=%s mtu=%d\n",vpn_tunnel_info->serverIP,vpn_tunnel_info->userName,vpn_tunnel_info->passwd,vpn_tunnel_info->tunnelName,entry.mtu);
		//entry.authtype = 2; //david-test, my server only support chap!

		if(is_exist>=0){
			AUG_PRT("VPN tunnel is updated !\n");
			if(!mib_chain_update(MIB_L2TP_TBL, &entry, is_exist)) {
				strcpy(reason, "Error! Update chain record.");
				status=1;
				//goto CreateL2TPDone;
			}
		}
		else{
			AUG_PRT("VPN tunnel is added!\n");
			ret = mib_chain_add(MIB_L2TP_TBL, (void *)&entry);
			if (ret == 0) {
				strcpy(reason, "Error! Add chain record.");
				status=1;
				//goto CreateL2TPDone;
			}
			else if (ret == -1) {
				status=1;
				strcpy(reason, "L2TP SW table Full!");
				//goto CreateL2TPDone;
			}
		}

		l2tpEntryNum = mib_chain_total(MIB_L2TP_TBL); /* get chain record size */
		VPN_DBG_PRT(debug_on, "l2tpEntryNum=%d\n",l2tpEntryNum);
		if(status == 0){
		if(is_exist>=0){
			applyL2TP(&entry, 5, is_exist);
			applyL2TP(&entry, 4, is_exist);
		}
		else{
			applyL2TP(&entry, 1, l2tpEntryNum-1);
			NF_Init_VPN_Policy_Route(entry.tunnelName);
		}
	}
	}

CreateL2TPDone:
#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif

	return status;
}

void SyncL2TPRouteEntryByMode(unsigned char *tunnelName, ATTACH_MODE_T attach_mode) {
	MIB_CE_L2TP_ROUTE_T l2tp_r_entry;
	int i, total_route_entry;

	total_route_entry = mib_chain_total(MIB_L2TP_ROUTE_TBL);
	for(i=(total_route_entry-1) ; i>=0 ; i--) {
		if (!mib_chain_get(MIB_L2TP_ROUTE_TBL, i, (void *)&l2tp_r_entry))
			continue;

		if(strcmp(tunnelName, l2tp_r_entry.tunnelName))
			continue;
		
		if(l2tp_r_entry.attach_mode != attach_mode)
			mib_chain_delete(MIB_L2TP_ROUTE_TBL, i);
	}
}

int AttachWanL2TPTunnel(gdbus_vpn_tunnel_info_t *vpn_tunnel_info, unsigned char *ipDomainNameAddr[], unsigned char *reason)
{
	int findTunnel=-1, findRouteIdx=-1;
	unsigned int l2tpEntryNum, i;
	unsigned int l2tpRouteEntryNum;
	MIB_CE_L2TP_ROUTE_T route_entry;
	ATTACH_MODE_T attach_mode;
	MIB_L2TP_T entry;
	int status=0,ret;	
	int enable=0;
	int j;
	

	if(vpn_tunnel_info==NULL || ipDomainNameAddr==NULL || reason==NULL){
		status=1;
		strcpy(reason, "some parameter(s) exist NULL pointer!");
		goto AttachVPNDone;
	}

	if(vpn_tunnel_info->tunnelName[0]=='\0' || vpn_tunnel_info->userID[0]=='\0'){
		status=1;
		strcpy(reason, "some parameter(s) is NULL string!");
		goto AttachVPNDone;
	} else {
		l2tpRouteEntryNum = mib_chain_total(MIB_L2TP_ROUTE_TBL);
		for(j=(l2tpRouteEntryNum-1) ; j>=0 ; j--) {
			if (!mib_chain_get(MIB_L2TP_ROUTE_TBL, j, (void *)&route_entry))
				continue;

			if(strcmp(vpn_tunnel_info->tunnelName, route_entry.tunnelName))
				continue;

			mib_chain_delete(MIB_L2TP_ROUTE_TBL, j);
		}
		RG_Flush_L2TP_Route(vpn_tunnel_info->tunnelName, 0);
		RG_Flush_L2TP_Dynamic_URL_Route(vpn_tunnel_info->tunnelName);
	}

	VPN_DBG_PRT(debug_on, "tunnelName=%s\n",vpn_tunnel_info->tunnelName);

	if ( !mib_get(MIB_L2TP_ENABLE, (void *)&enable) ){
		strcpy(reason, "MIB_L2TP_ENABLE is not exist!");
		status=1;
		goto AttachVPNDone;
	}
	/*gateway L2TP feature is disable*/
	if(!enable){
		status=1;
		//reason = "L2TP is Disable"
		strcpy(reason, "MIB_L2TP_ENABLE is Disable");
		goto AttachVPNDone;
	}
	l2tpEntryNum = mib_chain_total(MIB_L2TP_TBL); /* get chain record size */
	VPN_DBG_PRT(debug_on, "l2tpEntryNum=%d\n",l2tpEntryNum);

	if(l2tpEntryNum == 0){
		status=2;
		//reason = "L2TP is Disable"
		strcpy(reason, "VPN is not exist!");
		goto AttachVPNDone;
	}
	for (i=0; i<l2tpEntryNum; i++)
	{
		if ( !mib_chain_get(MIB_L2TP_TBL, i, (void *)&entry) )
			continue;
		
		if(!strcmp(vpn_tunnel_info->tunnelName,entry.tunnelName))
		{
			findTunnel=i;
			attach_mode = entry.attach_mode;
			break;
		}
	}
	VPN_DBG_PRT(debug_on, "findTunnel=%d\n",findTunnel);

	if(findTunnel==-1)
	{
		status=2;
		strcpy(reason, "VPN tunnel is not exist!");
		goto AttachVPNDone;
	}	
	VPN_DBG_PRT(debug_on, "%s-%d\n",__func__,__LINE__);

	i=0;
	while(ipDomainNameAddr[i] != NULL)
	{
		unsigned char *ipaddr1,*ipaddr2,*netmask;
		unsigned char sMac[MAC_ADDR_LEN];
		unsigned char ip[100];
		char *p;
		int c;
		unsigned int mask_inver;
		unsigned int mask;
		int ipv4_addr1,ipv4_addr2;
		char str_ipaddr1[64]={0}, str_ipaddr2[64] ={0};
		VPN_DBG_PRT(debug_on, "i=%d\n",i);
		strcpy(ip,ipDomainNameAddr[i]);
		//ip = ipDomainNameAddr[i];
		VPN_DBG_PRT(debug_on, "ip=%s\n",ip);
		if(strstr(ip,"/"))
		{
			if(ATTACH_MODE_DIP != attach_mode) {
				i++;
				continue;
			}
		
			/*ip/mask =  192.168.1.1/24*/
			VPN_DBG_PRT(debug_on, "%s-%d \n",__func__,__LINE__);
			ipaddr1 = strtok(ip,"/");
			//printf("ipaddr1=%s\n",ipaddr1);
			ipv4_addr1 = inet_addr(ipaddr1);
			if(ipv4_addr1==-1){
				printf("%s-%d set ip start error!\n",__func__,__LINE__);
				i++;
				continue;
			}
			netmask = strtok(NULL,"/");
			//printf("netmask=%s\n",netmask);
			c=atoi(netmask);
			mask_inver = 32 - c;
			mask = ~((1<<mask_inver)-1);			
			ipv4_addr1 &= mask;
			ipv4_addr2 = (ipv4_addr1 | ~mask);
			if(ipv4_addr2==-1){
				printf("%s-%d set ip end error!\n",__func__,__LINE__);
				i++;
				continue;
			}
			VPN_DBG_PRT(debug_on, "ipv4_addr1=%x, ipv4_addr2=%x mask=%x\n",ipv4_addr1,ipv4_addr2,mask);
			if(!Check_L2TP_Route_DIP(vpn_tunnel_info->tunnelName,ipv4_addr1,ipv4_addr2))
			{
				VPN_DBG_PRT(debug_on, "ipv4_addr1=%x, ipv4_addr2=%x mask=%x\n",ipv4_addr1,ipv4_addr2,mask);
				/*add it into l2tp route mib chain!*/
				memset(&route_entry, 0, sizeof(route_entry));
				route_entry.Enable = 1;
				strcpy(route_entry.tunnelName,vpn_tunnel_info->tunnelName);
				route_entry.ipv4_src_start=ipv4_addr1;
				route_entry.ipv4_src_end=ipv4_addr2;
				route_entry.rg_wan_idx = entry.rg_wan_idx;
				route_entry.ifIndex = entry.ifIndex;
				if(entry.priority > 0)
					route_entry.priority = entry.priority;
				route_entry.attach_mode = ATTACH_MODE_DIP;
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
				strcpy(route_entry.org_ips,ip);
#endif
				ret = mib_chain_add(MIB_L2TP_ROUTE_TBL, (void *)&route_entry);
				if (ret == 0) {
					strcpy(reason, "add l2tp route chain error!");
					status=1;
					goto AttachVPNDone;
				}
				else if (ret == -1) {
					strcpy(reason, "l2tp route table full!");
					status=1;
					goto AttachVPNDone;
				}
			}
		}
		else if (strstr(ip,"-"))
		{
			if(ATTACH_MODE_DIP != attach_mode) {
				i++;
				continue;
			}
			
			VPN_DBG_PRT(debug_on, "%s-%d \n",__func__,__LINE__);
			/*ip range =  192.168.1.1-192.168.1.10*/
			ipaddr1 = strtok(ip,"-");
			ipv4_addr1 = inet_addr(ipaddr1);
			if(ipv4_addr1==-1){
				printf("%s-%d set ip start error!\n",__func__,__LINE__);
				i++;
				continue;
			}
			ipaddr2 = strtok(NULL,"-");
			ipv4_addr2 = inet_addr(ipaddr2);
			if(ipv4_addr2==-1){
				printf("%s-%d set ip end error!\n",__func__,__LINE__);
				i++;
				continue;
			}
			printf("ipaddr1=%s ipaddr2=%s\n",ipaddr1,ipaddr2);
			printf("ipv4_addr1=%x ipv4_addr2=%x\n",ipv4_addr1,ipv4_addr2);
			if(!Check_L2TP_Route_DIP(vpn_tunnel_info->tunnelName,ipv4_addr1,ipv4_addr2))
			{
				/*add it into l2tp route mib chain!*/
				VPN_DBG_PRT(debug_on, "ipv4_addr1=%x, ipv4_addr2=%x mask=%x\n",ipv4_addr1,ipv4_addr2,mask);
				memset(&route_entry, 0, sizeof(route_entry));
				route_entry.Enable = 1;
				strcpy(route_entry.tunnelName,vpn_tunnel_info->tunnelName);
				route_entry.ipv4_src_start=ipv4_addr1;
				route_entry.ipv4_src_end=ipv4_addr2;
				route_entry.rg_wan_idx = entry.rg_wan_idx;
				route_entry.ifIndex = entry.ifIndex;
				if(entry.priority > 0)
					route_entry.priority = entry.priority;
				route_entry.attach_mode = ATTACH_MODE_DIP;
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
				strcpy(route_entry.org_ips,ip);
#endif
				ret = mib_chain_add(MIB_L2TP_ROUTE_TBL, (void *)&route_entry);
				if (ret == 0) {
					strcpy(reason, "add l2tp route chain error!");
					status=1;
					goto AttachVPNDone;
				}
				else if (ret == -1) {
					strcpy(reason, "l2tp route table full!");
					status=1;
					goto AttachVPNDone;
				}
			}
		}
		else if (strstr(ip,":"))
		{			
			if(ATTACH_MODE_SMAC != attach_mode) {
				i++;
				continue;
			}
			
			sscanf(ip, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &sMac[0], &sMac[1], &sMac[2], &sMac[3], &sMac[4], &sMac[5]);

			if(!Check_L2TP_Route_SMAC(vpn_tunnel_info->tunnelName, sMac))
			{
				memset(&route_entry, 0, sizeof(route_entry));
				route_entry.Enable = 1;
				strcpy(route_entry.tunnelName,vpn_tunnel_info->tunnelName);
				memcpy(route_entry.sMAC, sMac, MAC_ADDR_LEN);
				route_entry.rg_wan_idx = entry.rg_wan_idx;
				route_entry.ifIndex = entry.ifIndex;
				if(entry.priority > 0)
					route_entry.priority = entry.priority;
				route_entry.attach_mode = ATTACH_MODE_SMAC;
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
				strcpy(route_entry.org_ips,ip);
#endif
				ret = mib_chain_add(MIB_L2TP_ROUTE_TBL, (void *)&route_entry);
				if (ret == 0) {
					strcpy(reason, "add l2tp route chain error!");
					status=1;
					goto AttachVPNDone;
				}
				else if (ret == -1) {
					strcpy(reason, "l2tp route table full!");
					status=1;
					goto AttachVPNDone;
				}
			}
		}
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		else if (getIpRange(ip, str_ipaddr1, str_ipaddr2) > 0){
			if(ATTACH_MODE_DIP != attach_mode) {
				i++;
				continue;
			}
			
			VPN_DBG_PRT(debug_on, "%s-%d \n",__func__,__LINE__);
			/*ip range =  192.168.1.0*/
			inet_pton(AF_INET, str_ipaddr1, &ipv4_addr1);
			inet_pton(AF_INET, str_ipaddr2, &ipv4_addr2);
			printf("ipv4_addr1=%x ipv4_addr2=%x\n",ipv4_addr1,ipv4_addr2);
			if(!Check_L2TP_Route_DIP(vpn_tunnel_info->tunnelName,ipv4_addr1,ipv4_addr2))
			{
				/*add it into l2tp route mib chain!*/
				VPN_DBG_PRT(debug_on, "ipv4_addr1=%x, ipv4_addr2=%x mask=%x\n",ipv4_addr1,ipv4_addr2,mask);
				memset(&route_entry, 0, sizeof(route_entry));
				route_entry.Enable = 1;
				strcpy(route_entry.tunnelName,vpn_tunnel_info->tunnelName);
				route_entry.ipv4_src_start=ipv4_addr1;
				route_entry.ipv4_src_end=ipv4_addr2;
				route_entry.rg_wan_idx = entry.rg_wan_idx;
				route_entry.ifIndex = entry.ifIndex;
				if(entry.priority > 0)
					route_entry.priority = entry.priority;
				route_entry.attach_mode = ATTACH_MODE_DIP;
				strcpy(route_entry.org_ips,ip);
				ret = mib_chain_add(MIB_L2TP_ROUTE_TBL, (void *)&route_entry);
				if (ret == 0) {
					strcpy(reason, "add l2tp route chain error!");
					status=1;
					goto AttachVPNDone;
				}
				else if (ret == -1) {
					strcpy(reason, "l2tp route table full!");
					status=1;
					goto AttachVPNDone;
				}
			}
		}
#endif
		else
		{
			if(ATTACH_MODE_DIP != attach_mode) {
				i++;
				continue;
			}
			
			VPN_DBG_PRT(debug_on, "%s-%d \n",__func__,__LINE__);
			/*add it into l2tp route mib chain!*/
			if(!Check_L2TP_Route_URL(vpn_tunnel_info->tunnelName,ip)){
				memset(&route_entry, 0, sizeof(route_entry));
				route_entry.Enable = 1;
				strcpy(route_entry.tunnelName,vpn_tunnel_info->tunnelName);
				route_entry.ipv4_src_start=0;
				route_entry.ipv4_src_end=0;
				route_entry.rg_wan_idx = entry.rg_wan_idx;
				route_entry.ifIndex = entry.ifIndex;
				if(entry.priority > 0)
					route_entry.priority = entry.priority;
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
				//for keeping the original url string
				domain_to_regular_expression_cmcc(ip, route_entry.url);
#else
				strcpy(route_entry.url,ip);
#endif
				route_entry.attach_mode = ATTACH_MODE_DIP;
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
				strcpy(route_entry.org_ips,ip);
#endif
				ret = mib_chain_add(MIB_L2TP_ROUTE_TBL, (void *)&route_entry);
				if (ret == 0) {
					strcpy(reason, "add l2tp route chain error!");
					status=1;
					goto AttachVPNDone;
				}
				else if (ret == -1) {
					strcpy(reason, "l2tp route table full!");
					status=1;
					goto AttachVPNDone;
				}
				strcpy(reason, "Set URL OK!");
			}
		}

		i++;
	}

	VPN_DBG_PRT(debug_on, " Done ! \n");

AttachVPNDone:
	// Avoid someone attach DIP mode first then attach sMAC mode
	SyncL2TPRouteEntryByMode(vpn_tunnel_info->tunnelName, attach_mode);
#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif

	return status;
}

int DetachWanL2TPTunnel(gdbus_vpn_tunnel_info_t *vpn_tunnel_info, ATTACH_MODE_T attach_mode, unsigned char *ipDomainNameAddr[], unsigned char *reason)
{
	int status=0;
	unsigned int l2tpEntryNum, i;
	unsigned int findTunnel=0, totalnum;
	int enable=0;
	int entryNum;
	MIB_L2TP_T entry;
	
	if(vpn_tunnel_info==NULL || ipDomainNameAddr==NULL || reason==NULL){
		status=1;
		strcpy(reason, "some parameter(s) exist NULL pointer!");
		goto DetachVPNDone;
	}

	if(vpn_tunnel_info->tunnelName[0]=='\0' || vpn_tunnel_info->userID[0]=='\0'){
		status=1;
		strcpy(reason, "some parameter(s) is NULL string!");
		goto DetachVPNDone;
	}

	VPN_DBG_PRT(debug_on, "tunnelName=%s \n",vpn_tunnel_info->tunnelName);

	if ( !mib_get(MIB_L2TP_ENABLE, (void *)&enable) ){
		strcpy(reason, "MIB_L2TP_ENABLE is not exist!");
		status=1;
		goto DetachVPNDone;
	}
	/*gateway L2TP feature is disable*/
	if(!enable){
		status=1;
		//reason = "L2TP is Disable"
		strcpy(reason, "MIB_L2TP_ENABLE is Disable");
		goto DetachVPNDone;
	}
	l2tpEntryNum = mib_chain_total(MIB_L2TP_TBL); /* get chain record size */
	VPN_DBG_PRT(debug_on, "l2tpEntryNum=%d\n",l2tpEntryNum);

	if(l2tpEntryNum == 0){
		status=2;
		//reason = "L2TP is Disable"
		strcpy(reason, "VPN is not exist!");
		goto DetachVPNDone;
	}
	for (i=0; i<l2tpEntryNum; i++)
	{
		if ( !mib_chain_get(MIB_L2TP_TBL, i, (void *)&entry) )
			continue;
		if(!strcmp(vpn_tunnel_info->tunnelName,entry.tunnelName))
		{
			findTunnel=1;
			break;
		}
	}
	VPN_DBG_PRT(debug_on, "findTunnel=%d\n",findTunnel);

	if(!findTunnel)
	{
		status=2;
		strcpy(reason, "VPN tunnel is not exist!");
		goto DetachVPNDone;
	}
	
	VPN_DBG_PRT(debug_on, "%s-%d\n",__func__,__LINE__);
	
	totalnum = mib_chain_total(MIB_L2TP_ROUTE_TBL); /* get chain record size */
	if(totalnum == 0)
	{
		status=1;
		strcpy(reason, "L2TP route table is not exist!");
		goto DetachVPNDone;
	}

	i=0;
	while(ipDomainNameAddr[i] != NULL)
	{
		unsigned char *ipaddr1,*ipaddr2,*netmask;
		unsigned char sMac[MAC_ADDR_LEN];
		unsigned char ip[100];
		char *p;
		int c;
		unsigned int mask_inver;
		unsigned int mask;
		unsigned int ipv4_addr1,ipv4_addr2;
		VPN_DBG_PRT(debug_on, "i=%d\n",i);
		strcpy(ip,ipDomainNameAddr[i]);
		//ip = ipDomainNameAddr[i];
		VPN_DBG_PRT(debug_on, "ip=%s\n",ip);
		if(strstr(ip,"/"))
		{
			/*ip/mask =  192.168.1.1/24*/
			VPN_DBG_PRT(debug_on, "%s-%d \n",__func__,__LINE__);
			ipaddr1 = strtok(ip,"/");
			//printf("ipaddr1=%s\n",ipaddr1);
			ipv4_addr1 = inet_addr(ipaddr1);
			netmask = strtok(NULL,"/");
			//printf("netmask=%s\n",netmask);
			c=atoi(netmask);
			mask_inver = 32 - c;
			mask = ~((1<<mask_inver)-1);			
			ipv4_addr1 &= mask;
			ipv4_addr2 = (ipv4_addr1 | ~mask);
			VPN_DBG_PRT(debug_on, "ipv4_addr1=%x, ipv4_addr2=%x mask=%x\n",ipv4_addr1,ipv4_addr2,mask);
			if(Del_L2TP_Route_DIP(vpn_tunnel_info->tunnelName,ipv4_addr1,ipv4_addr2))
			{
				//match l2tp route table.
				status=0;
				strcpy(reason, "L2TP route del OK!");
				VPN_DBG_PRT(debug_on, "ipv4_addr1=%x, ipv4_addr2=%x exist!\n",ipv4_addr1,ipv4_addr2);
			}
			else{
				status=1;
				strcpy(reason, "L2TP route table is not exist!");
				VPN_DBG_PRT(debug_on, "ipv4_addr1=%x, ipv4_addr2=%x not exist!\n",ipv4_addr1,ipv4_addr2);
				goto DetachVPNDone;
			}
		}
		else if (strstr(ip,"-"))
		{
			VPN_DBG_PRT(debug_on, "%s-%d \n",__func__,__LINE__);
			/*ip range =  192.168.1.1-192.168.1.10*/
			ipaddr1 = strtok(ip,"-");
			ipv4_addr1 = inet_addr(ipaddr1);
			ipaddr2 = strtok(NULL,"-");
			ipv4_addr2 = inet_addr(ipaddr2);
			printf("ipaddr1=%s ipaddr2=%s\n",ipaddr1,ipaddr2);
			printf("ipv4_addr1=%x ipv4_addr2=%x\n",ipv4_addr1,ipv4_addr2);
			if(Del_L2TP_Route_DIP(vpn_tunnel_info->tunnelName,ipv4_addr1,ipv4_addr2))
			{
				//match l2tp route table.
				status=0;
				strcpy(reason, "L2TP route del OK!");
				VPN_DBG_PRT(debug_on, "ipv4_addr1=%x, ipv4_addr2=%x exist!\n",ipv4_addr1,ipv4_addr2);
			}
			else{
				status=1;
				strcpy(reason, "L2TP route table is not exist!");
				VPN_DBG_PRT(debug_on, "ipv4_addr1=%x, ipv4_addr2=%x not exist!\n",ipv4_addr1,ipv4_addr2);
				goto DetachVPNDone;
			}
		}
		else if (strstr(ip,":")){

			sscanf(ip, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &sMac[0], &sMac[1], &sMac[2], &sMac[3], &sMac[4], &sMac[5]);

			if(Check_L2TP_Route_SMAC(vpn_tunnel_info->tunnelName, sMac))
			{
				if(Del_L2TP_Route_SMAC(vpn_tunnel_info->tunnelName,sMac))
				{
					//match l2tp route table.
					status=0;
					strcpy(reason, "L2TP route del OK!");
					VPN_DBG_PRT(debug_on, "sMac=%x:%x:%x:%x:%x:%x exist!\n", sMac[0], sMac[1], sMac[2], sMac[3], sMac[4], sMac[5]);
				}
				else{
					status=1;
					strcpy(reason, "L2TP route table is not exist!");
					VPN_DBG_PRT(debug_on, "sMac=%x:%x:%x:%x:%x:%x not exist!\n", sMac[0], sMac[1], sMac[2], sMac[3], sMac[4], sMac[5]);
					goto DetachVPNDone;
				}
			}
		}
		else
		{
			/*URL*/
			VPN_DBG_PRT(debug_on, "%s-%d \n",__func__,__LINE__);
			if(Del_LT2P_Route_URL(vpn_tunnel_info->tunnelName,ip))
			{
				//match l2tp route table.
				status=0;
				strcpy(reason, "L2TP route del OK!");
				VPN_DBG_PRT(debug_on, "ip=%s exist!\n",ip);
				RG_Flush_L2TP_Dynamic_URL_Route(vpn_tunnel_info->tunnelName);
				NF_Flush_L2TP_Dynamic_URL_Route(vpn_tunnel_info->tunnelName);
			}
			else{
				status=1;
				strcpy(reason, "L2TP route table is not exist!");
				VPN_DBG_PRT(debug_on, "%s not exist!\n",ip);
				goto DetachVPNDone;
			}
		}

		i++;
	}

	VPN_DBG_PRT(debug_on, " Done ! \n");

DetachVPNDone:
#ifdef CONFIG_RTK_L34_ENABLE
    RG_Flush_L2TP_Route(vpn_tunnel_info->tunnelName, 0);
    RG_Set_L2TP_Acl_Policy_Route(vpn_tunnel_info->tunnelName, attach_mode);
#endif
#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif
	return status;
}

int GetWanL2TPTunnelStatus(gdbus_vpn_tunnel_info_t *vpn_tunnel_info, unsigned char *reason, L2TP_Status_Tp l2tp_list, int *num)
{
	int status=0;
	unsigned int l2tpEntryNum, i;
	unsigned int findUser=0, findTunnel=0;
	//unsigned int decisionCase=0;
	char ifname[IFNAMSIZ];
	int flags, flags_found, isL2TPup;
	int enable=0;
	MIB_L2TP_T entry;

	if(vpn_tunnel_info==NULL || reason==NULL || l2tp_list==NULL || num==NULL){
		status=1;
		strcpy(reason, "some parameter(s) exist NULL pointer!");
		goto GetTunnelStatusDone;
	}

	if(vpn_tunnel_info->tunnelName[0]=='\0' || vpn_tunnel_info->userID[0]=='\0'){
		status=1;
		strcpy(reason, "some parameter(s) is NULL string!");
		goto GetTunnelStatusDone;
	}

	AUG_PRT("%s-%d \n",__func__,__LINE__);
	*num=0;
	if ( !mib_get(MIB_L2TP_ENABLE, (void *)&enable) ){
		strcpy(reason, "MIB_L2TP_ENABLE is not exist!");
		status=1;
		goto GetTunnelStatusDone;
	}
	/*gateway L2TP feature is disable*/
	if(!enable){
		status=1;
		//reason = "L2TP is Disable"
		strcpy(reason, "MIB_L2TP_ENABLE is Disable");
		goto GetTunnelStatusDone;
	}
	l2tpEntryNum = mib_chain_total(MIB_L2TP_TBL); /* get chain record size */

	if(l2tpEntryNum == 0){
		status=2;
		//reason = "L2TP is Disable"
		strcpy(reason, "VPN is not exist!");
		goto GetTunnelStatusDone;
	}
	//case 1: tunnelName!=all, userID=0, not legal
	if(strcmp(vpn_tunnel_info->tunnelName,"all") && !strcmp(vpn_tunnel_info->userID,"0")){
		/*userID =0, but tunnelName!=all*/
		status=1;
		strcpy(reason, "userId=0, but tunnelName!=all!");
		goto GetTunnelStatusDone;
	}
	//case 2: tunnelName=all, userID=0
	if(!strcmp(vpn_tunnel_info->tunnelName,"all") && !strcmp(vpn_tunnel_info->userID,"0")){
		/*it means check all VPN tunnel status*/
		for (i=0; i<l2tpEntryNum; i++)
		{
			if ( !mib_chain_get(MIB_L2TP_TBL, i, (void *)&entry) )
				continue;
			ifGetName(entry.ifIndex, ifname, sizeof(ifname));
			AUG_PRT("%s-%d entry.ifIndex=%x, ifname=%s\n",__func__,__LINE__,entry.ifIndex,ifname);
			flags_found = getInFlags(ifname, &flags);
			AUG_PRT("%s-%d flags_found=%d\n",__func__,__LINE__,flags_found);
			if (flags_found)
			{
				if (flags & IFF_UP)
				{
					#if 0//def CONFIG_GPON_FEATURE
					if (onu == 5)
						isL2TPup = 1;
					#else
						isL2TPup = 1;
					#endif
				}
			}
			strcpy(l2tp_list[i].tunnelName,entry.tunnelName);
			if(isL2TPup)
				strcpy(l2tp_list[i].tunnelStatus,"0");
			else
				strcpy(l2tp_list[i].tunnelStatus,"1");
			*num +=1;
			AUG_PRT("%s-%d isL2TPup=%d tunnelName=%s, tunnelStatus=%s num=%d\n",__func__,__LINE__,isL2TPup,l2tp_list[i].tunnelName,l2tp_list[i].tunnelStatus,*num);

			strcpy(reason, "userID=0, tunnelName=all, check all!");
		}
		status=0;
		goto GetTunnelStatusDone;
	}
	//case 3: userID=XXX, tunnelName=all, check all userID's tunnel
	//case 4: userID=XXX, tunnelName=XXX, check userID's, tunnelName Status
	for (i=0; i<l2tpEntryNum; i++)
	{
		if ( !mib_chain_get(MIB_L2TP_TBL, i, (void *)&entry) )
			continue;
		if(!strcmp(vpn_tunnel_info->userID,entry.userID))
		{
			findUser=1;
			/*check specified userID VPN*/
			if(!strcmp(vpn_tunnel_info->tunnelName,"all"))
			{
				/*check userID's all VPN*/
				findTunnel=1;
				ifGetName(entry.ifIndex, ifname, sizeof(ifname));
				AUG_PRT("%s-%d entry.ifIndex=%x, ifname=%s\n",__func__,__LINE__,entry.ifIndex,ifname);
				flags_found = getInFlags(ifname, &flags);
				AUG_PRT("%s-%d flags_found=%d\n",__func__,__LINE__,flags_found);
				if (flags_found)
				{
					if (flags & IFF_UP)
					{
						#if 0//def CONFIG_GPON_FEATURE
						if (onu == 5)
							isL2TPup = 1;
						#else
							isL2TPup = 1;
						#endif
					}
				}
				strcpy(l2tp_list[i].tunnelName,entry.tunnelName);
				if(isL2TPup)
					strcpy(l2tp_list[i].tunnelStatus,"0");
				else
					strcpy(l2tp_list[i].tunnelStatus,"1");
				*num += 1;;
				AUG_PRT("%s-%d isL2TPup=%d tunnelName=%s, tunnelStatus=%s num=%d\n",__func__,__LINE__,isL2TPup,l2tp_list[i].tunnelName,l2tp_list[i].tunnelStatus,*num);

			}
			else if(!strcmp(vpn_tunnel_info->tunnelName,entry.tunnelName))
			{
				/*check specified tunnelName VPN*/
				findTunnel=2;
				ifGetName(entry.ifIndex, ifname, sizeof(ifname));
				AUG_PRT("%s-%d entry.ifIndex=%x, ifname=%s\n",__func__,__LINE__,entry.ifIndex,ifname);
				flags_found = getInFlags(ifname, &flags);
				AUG_PRT("%s-%d flags_found=%d\n",__func__,__LINE__,flags_found);
				if (flags_found)
				{
					if (flags & IFF_UP)
					{
						#if 0//def CONFIG_GPON_FEATURE
						if (onu == 5)
							isL2TPup = 1;
						#else
							isL2TPup = 1;
						#endif
					}
				}
				strcpy(l2tp_list[i].tunnelName,entry.tunnelName);
				if(isL2TPup)
					strcpy(l2tp_list[i].tunnelStatus,"0");
				else
					strcpy(l2tp_list[i].tunnelStatus,"1");
				*num += 1;
				AUG_PRT("%s-%d isL2TPup=%d tunnelName=%s, tunnelStatus=%s num=%d\n",__func__,__LINE__,isL2TPup,l2tp_list[i].tunnelName,l2tp_list[i].tunnelStatus,*num);

			}
		}
	}
	if(findUser==1)
	{
		if(findTunnel==1)
		{
			strcpy(reason, "match userID and tunnelName 'all'!");
			status = 0;
		}
		else if(findTunnel==2)
		{
			strcpy(reason, "match userID and tunnelName!");
			status = 0;
		}
		else{
			/*findTunnel==0*/
			/*match userID but match tunnelName fail!*/
			status = 2;
			strcpy(reason, "match tunnelName fail!");
		}
	}
	else
	{
		/*findUser=0*/
		status = 3;
		strcpy(reason, "userID is not exist!");
	}

	GetTunnelStatusDone:
	return status;
}

void dump_mib_l2tp( void )
{
	MIB_L2TP_T entry;
	MIB_CE_L2TP_ROUTE_T r_entry;
	unsigned int entrynum, i;

	printf(" #######################MIB_L2TP_TBL####################### \n", __func__);

	entrynum = mib_chain_total(MIB_L2TP_TBL);
	for (i=0; i<entrynum; i++)
	{
		if ( !mib_chain_get(MIB_L2TP_TBL, i, (void *)&entry) )
			return;

		printf(" =======================[%d]===================== \n", i);

		printf("  server=%s \n", entry.server);
		printf("  username=%s \n", entry.username);
		printf("  password=%s \n", entry.password);
		printf("  tunnelName=%s \n", entry.tunnelName);
		printf("  userID=%s \n", entry.userID);
		printf("  rg_wan_idx=%d \n", entry.rg_wan_idx);
		printf("  conntype=%d \n", entry.conntype);
		printf("  idletime=%d \n", entry.idletime);
	}

	printf(" #######################MIB_L2TP_ROUTE_TBL####################### \n", __func__);

	entrynum = mib_chain_total(MIB_L2TP_ROUTE_TBL); /* get chain record size */
	for( i=0; i<entrynum; i++)
	{
		if ( !mib_chain_get(MIB_L2TP_ROUTE_TBL, i, (void *)&r_entry) )
			continue;

		printf(" =======================[%d]===================== \n", i);

		printf("  Enable=%d \n", r_entry.Enable);
		printf("  tunnelName=%s \n", r_entry.tunnelName);
		printf("  url=%s \n", r_entry.url);
		printf("  ipv4_src_start=0x%x \n", r_entry.ipv4_src_start);
		printf("  ipv4_src_end=0x%x \n", r_entry.ipv4_src_end);
		printf("  sMAC=%x:%x:%x:%x:%x:%x \n", r_entry.sMAC[0], r_entry.sMAC[1], r_entry.sMAC[2], r_entry.sMAC[3], r_entry.sMAC[4], r_entry.sMAC[5]);
		printf("  ifIndex=%d \n", r_entry.ifIndex);
		printf("  rg_wan_idx=%d \n", r_entry.rg_wan_idx);
	}
}
#endif

void update_fw_vpngre(void)
{
	int total, i;
	MIB_PPTP_T PPTPEntry;
	MIB_L2TP_T L2TPEntry;

	va_cmd(IPTABLES, 2, 1, "--flush", (char *)FW_VPNGRE);

	total = mib_chain_total(MIB_PPTP_TBL);
	for (i = 0; i < total; i++)
	{
		if (!mib_chain_get(MIB_PPTP_TBL, i, (void *)&PPTPEntry))
			return;

		if( PPTPEntry.vpn_port )
			va_cmd(IPTABLES, 6, 1, "-A", (char *)FW_VPNGRE, "-s", PPTPEntry.server, "-j", (char *)FW_ACCEPT);
	}

	total = mib_chain_total(MIB_L2TP_TBL);
	for (i = 0; i < total; i++)
	{
		if (!mib_chain_get(MIB_L2TP_TBL, i, (void *)&L2TPEntry))
			return;

		if( L2TPEntry.vpn_port )
			va_cmd(IPTABLES, 6, 1, "-A", (char *)FW_VPNGRE, "-s", L2TPEntry.server, "-j", (char *)FW_ACCEPT);
	}
}

int is_valid_accpxy_parameter(char *parameter)
{
	int i;

	if(parameter==NULL)
		return -1;

	for(i=0 ; i<VPN_ACCPXY_PARAM_NUM ; i++) {
		if(!strcmp(vpn_accpxy_params[i], parameter) && strlen(vpn_accpxy_params[i])==strlen(parameter)) {
			return i;
		}
	}

	return -1;
}

void set_accpxy_parameter(char *name, char *value, gdbus_vpn_tunnel_info_t *vpn_tunnel_info_ptr)
{
	int ret;

	if(name==NULL || value==NULL || vpn_tunnel_info_ptr==NULL)
		return;

	ret=is_valid_accpxy_parameter(name);
	if(ret==-1)
		return;

	if(value[0] == '\0') {
		return;
	}

	switch(ret)
	{
		case 0:
			vpn_tunnel_info_ptr->account_proxy_result=atoi(value);
			break;

		case 5:
			vpn_tunnel_info_ptr->account_proxy_param_status=atoi(value);
			break;

		case 6:
			snprintf(vpn_tunnel_info_ptr->account_proxy_msg, sizeof(vpn_tunnel_info_ptr->account_proxy_msg), "%s", value);
			break;

		case 8:
			if(!strstr(value,"."))
				printf("%s %d Server IP is wrong format \n", __func__, __LINE__);
			else
				snprintf(vpn_tunnel_info_ptr->serverIP, sizeof(vpn_tunnel_info_ptr->serverIP), "%s", value);
			break;

		case 9:
			if(!atoi(value))
				printf("%s %d VPN port is wrong format \n", __func__, __LINE__);
			else
				vpn_tunnel_info_ptr->vpn_port=atoi(value);
			break;

		case 10:
			snprintf(vpn_tunnel_info_ptr->userName, sizeof(vpn_tunnel_info_ptr->userName), "%s", value);
			break;

		case 11:
			snprintf(vpn_tunnel_info_ptr->passwd, sizeof(vpn_tunnel_info_ptr->passwd), "%s", value);
			break;

		case 12:
			// We do not use account timeout value which received from account proxy server
			break;

		default:
			break;
	}
}

void trace_accpxy_json_struct(cJSON *root, gdbus_vpn_tunnel_info_t *vpn_tunnel_info_ptr)
{
	unsigned char key[128];
	unsigned char value[128];

	if(!root)
		return;

	snprintf(key, sizeof(key), "%s", root->string);

	switch(root->type)
	{

		case cJSON_Number:

			if(is_valid_accpxy_parameter(key)>=0){
				VPN_DBG_PRT(debug_on, "Get parameter:[%s = %d]\n", key, root->valueint);
				snprintf(value, sizeof(value), "%d", root->valueint);
				set_accpxy_parameter(key, value, vpn_tunnel_info_ptr);
			}
			else
				VPN_DBG_PRT(debug_on, "Wrong parameter: %s\n", key);

			break;

		case cJSON_String:

			if(is_valid_accpxy_parameter(key)>=0){
				VPN_DBG_PRT(debug_on, "Get parameter:[%s = %s]\n", key, root->valuestring);
				snprintf(value, sizeof(value), "%s", root->valuestring);
				set_accpxy_parameter(key, value, vpn_tunnel_info_ptr);
			}
			else
				VPN_DBG_PRT(debug_on, "Wrong parameter: %s\n", key);

			break;

		case cJSON_Object:

			VPN_DBG_PRT(debug_on, "Get object name: %s\n", key);
			break;

		case cJSON_False:
		case cJSON_True:
		case cJSON_Array:
		default:
			AUG_PRT("Invalid type !: %s\n");
			break;
	}

	trace_accpxy_json_struct(root->next, vpn_tunnel_info_ptr);
	trace_accpxy_json_struct(root->child, vpn_tunnel_info_ptr);
}

int parse_accpxy_response_line(char* str, gdbus_vpn_tunnel_info_t *vpn_tunnel_info_ptr)
{
	int i, is_param_exist=0;
	char *json_str_value=NULL, *tmp_str_ptr=NULL;
	char json_str_key_head[32]={0};
	char str_key_tuple[128]={0};
	char tmp_str[256]={0};
	

	if(str==NULL || str[0]=='\0')
		return -1;

	sprintf(tmp_str, "%s", str);

	cJSON cjson_param = {0};
	if(tmp_str_ptr=strstr(tmp_str, "{"))
	{
		if(parse_object(&cjson_param, tmp_str_ptr))
			trace_accpxy_json_struct(&cjson_param, vpn_tunnel_info_ptr);
	}

	return 0;
}

void generate_json_to_request_accpxy( gdbus_vpn_tunnel_info_t *vpn_tunnel_info_ptr, char *json_ptr )
{
	time_t tm;
	struct tm tm_time;
	char *time_str[64];
	unsigned int base64_message_len;
	unsigned char message[512]; 
	unsigned char en_base64_message[512];
	unsigned char de_base64_message[512];
	unsigned char *mac[32];
	unsigned char tmp[256], md5[64], md5_str[64];
	unsigned char *cur = tmp;	
	char tmp_json_ptr[1024];

	time(&tm);
	memcpy(&tm_time, localtime(&tm), sizeof(tm_time));
	strftime((char*)time_str, 200, "%Y%m%d%H%M%S", &tm_time);
	VPN_DBG_PRT(debug_on, "time=%s \n", time_str);

	sprintf(message, "{\"CmdType\":\"GET_VPN_ACCOUNT\",\"tunnelName\":\"%s\",\"userId\":\"%s\"}"
			, vpn_tunnel_info_ptr->tunnelName
			, vpn_tunnel_info_ptr->userID);

	VPN_DBG_PRT(debug_on, "message=%s \n", message);
	
	base64_encode(message, en_base64_message, strlen(message));

	if(en_base64_message){
		VPN_DBG_PRT(debug_on, "en_base64_message=%s \n", en_base64_message);
	}

	base64_decode(de_base64_message, en_base64_message, sizeof(de_base64_message));

	if(de_base64_message){
		VPN_DBG_PRT(debug_on, "de_base64_message=%s \n", de_base64_message);
	}

	sprintf((char*)mac, "%02X%02X%02X%02X%02X%02X",  vpn_tunnel_info_ptr->account_proxy_mac[0], vpn_tunnel_info_ptr->account_proxy_mac[1], vpn_tunnel_info_ptr->account_proxy_mac[2], vpn_tunnel_info_ptr->account_proxy_mac[3], vpn_tunnel_info_ptr->account_proxy_mac[4], vpn_tunnel_info_ptr->account_proxy_mac[5]);
	VPN_DBG_PRT(debug_on, "mac=%s \n", mac);

	///--memcpy(cur, time_str, strlen(time_str));
	sprintf(cur, "%s", time_str);
	cur += strlen((char*)time_str);

	///--memcpy(cur, message, strlen(message));
	sprintf(cur, "%s", en_base64_message);
	cur += strlen(en_base64_message);

	///--memcpy(cur, mac, strlen(mac));
	sprintf(cur, "%s", mac);
	cur += strlen((char*)mac);
	VPN_DBG_PRT(debug_on, "MD5(%s,%d) \n", tmp, strlen(tmp));
	MD5(tmp, strlen(tmp), md5);
	VPN_DBG_PRT(debug_on, "md5'%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x \n"
		, md5[0], md5[1], md5[2], md5[3], md5[4], md5[5], md5[6], md5[7], md5[8], md5[9], md5[10], md5[11], md5[12], md5[13], md5[14], md5[15]);
	snprintf(md5_str, sizeof(md5_str), "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", md5[0], md5[1], md5[2], md5[3], md5[4], md5[5], md5[6], md5[7], md5[8], md5[9], md5[10], md5[11], md5[12], md5[13], md5[14], md5[15]);

	sprintf(json_ptr, "{\"RPCMethod\":\"Post\",\"Plugin_Name\":\"\",\"MD5\":\"%s\",\"time\":\"%s\",\"mac\":\"%s\",\"Message\":\"%s\"}"
		, md5_str
		, time_str
		, mac
		, en_base64_message);
}

int get_vpn_accpw_via_tcpconnect( gdbus_vpn_tunnel_info_t *vpn_tunnel_info_ptr, char *reason )
{
	unsigned char temp_account_proxy[MAX_DOMAIN_LENGTH];
	unsigned char *accpxy_domain, *accpxy_port;
	struct sockaddr_in serv_addr;
	struct hostent *h;
	int sockfd = 0, n = 0;
	char json[1024], recvBuff[1024], sendBuff[1024], *sendBuff_ptr;
	struct timeval tv;
	int json_len;
	int recvBuff_idx;


	if( vpn_tunnel_info_ptr->account_proxy[0] == '\0' )
	{
		printf("\n account_proxy is a NULL string! \n");
		goto setErr_getVPNaccount2;
	}

	vpn_tunnel_info_ptr->account_proxy_result = ACCPXY_RESULT_FAIL;
	vpn_tunnel_info_ptr->account_proxy_param_status = ACCPXY_STATUS_FAIL;

	generate_json_to_request_accpxy(vpn_tunnel_info_ptr, json);

	snprintf(temp_account_proxy, sizeof(temp_account_proxy), "%s", vpn_tunnel_info_ptr->account_proxy);
	if(accpxy_domain = strstr(temp_account_proxy, ":")){
		accpxy_domain = strtok(temp_account_proxy, ":");
		accpxy_port = strtok(NULL,":");
	}
	VPN_DBG_PRT(debug_on, "accpxy_domain=%s accpxy_port=%s \n", accpxy_domain, accpxy_port);

	if ((h = gethostbyname(accpxy_domain)) == NULL) {
		goto setErr_getVPNaccount2;
	}

	if (h->h_addrtype != AF_INET) {
		//strcpy(tmpBuf, "unknown address type; only AF_INET is currently supported.");
		goto setErr_getVPNaccount2;
	}

	memset(recvBuff, '0',sizeof(recvBuff));
	if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("\n Error : Could not create socket \n");
        goto setErr_getVPNaccount1;
    }

	memcpy(&serv_addr.sin_addr, h->h_addr, sizeof(serv_addr.sin_addr));
	serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(atoi(accpxy_port));

	AUG_PRT("connect socket: ip=%s port=%d \n", inet_ntoa(serv_addr.sin_addr), atoi(accpxy_port));
	if( connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
		printf("\n Error : Connect Failed \n");
		goto setErr_getVPNaccount1;
    }
	//AUG_PRT("None Block by Connect ip=%s port=%d\n", inet_ntoa(serv_addr.sin_addr), atoi(accpxy_port));
	
	json_len = strlen(json);
	int tmp = htonl((uint32_t)json_len);
	sendBuff_ptr = &sendBuff[0];
	memcpy(sendBuff_ptr, &tmp, sizeof(int));
	sendBuff_ptr += sizeof(int);
	memcpy(sendBuff_ptr, json, strlen(json));
	sendBuff_ptr += strlen(json);

	n = write(sockfd, sendBuff, sizeof(int)+strlen(json));
	if (n < 0)
	{
		printf("\n writing to socket error \n");
		goto setErr_getVPNaccount1;
	}
	//AUG_PRT("\n");
	tv.tv_sec = 1;  /* 1 Secs Timeout */
	tv.tv_usec = 0;
	setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(struct timeval));

	bzero(recvBuff, 1024);
	while ( (n = read(sockfd, recvBuff, sizeof(recvBuff)-1)) > 0)
	{
		if(n < 1024) {
	        recvBuff[n] = 0;
			recvBuff_idx = 0;
			while( recvBuff_idx < n && recvBuff[recvBuff_idx] != '{'){
				recvBuff_idx++;
			}

			if(recvBuff_idx >= 1024)
				goto setErr_getVPNaccount1;

			parse_accpxy_response_line(&recvBuff[recvBuff_idx], vpn_tunnel_info_ptr);
		}
	}
	//AUG_PRT("\n");
	
	switch(vpn_tunnel_info_ptr->account_proxy_result)
	{
		case ACCPXY_RESULT_FAIL:
			AUG_PRT("Get VPN account FAIL !!!\n");
			goto setErr_getVPNaccount1;

		case ACCPXY_RESULT_SUCCESS:
			AUG_PRT("Get VPN result success !!!\n");

			if(ACCPXY_STATUS_SUCCESS==vpn_tunnel_info_ptr->account_proxy_param_status)
				AUG_PRT("Get VPN account status success !!!\n");
			else
				AUG_PRT("Get VPN account status FAIL !!!\n");

			close(sockfd);
    		return 0;

		default:
			AUG_PRT("FAIL to request HTTP POST !!!\n");
			strcpy(reason, "FAIL to request HTTP POST.");
			goto setErr_getVPNaccount1;
	}
	//AUG_PRT("\n");
setErr_getVPNaccount1:
	//AUG_PRT("\n");
	close(sockfd);
setErr_getVPNaccount2:
	//AUG_PRT("\n");
	return -1;

}

int get_vpn_accpw_via_httppost( gdbus_vpn_tunnel_info_t *vpn_tunnel_info_ptr, char *reason )
{
	char sysbuf[512];
	char content[256];
	FILE *fp;
	char response[512] = {0};
	int status=-1;
	unsigned char *accpxy_domain, *accpxy_port;

	unsigned char *mac[32];

	time_t tm;
	struct tm tm_time;
	char *time_str[64];

	unsigned char message[512];

	unsigned char tmp[256], md5[64], md5_str[64];
	unsigned char *cur = tmp;


	// get IP of proxy server from mib
	if(vpn_tunnel_info_ptr->account_proxy[0]=='\0')
	{
		return -1;
	}

	time(&tm);
	memcpy(&tm_time, localtime(&tm), sizeof(tm_time));
	strftime((char*)time_str, 200, "%Y%m%d%H%M%S", &tm_time);
	VPN_DBG_PRT(debug_on, "time=%s \n", time_str);

	if(accpxy_domain = strstr(vpn_tunnel_info_ptr->account_proxy, ":")){
		sprintf(message, "{\"CmdType\":\"GET_VPN_ACCOUNT\",\"tunnelName\":\"%s\",\"userId\":\"%s\"}"
			, vpn_tunnel_info_ptr->userID
			, vpn_tunnel_info_ptr->userID);
	}
	else{
		sprintf(message, "{\"CmdType\":\"GET_VPN_ACCOUMT\",\"tunnelName\":\"%s\",\"userId\":\"%s\"}"
			, vpn_tunnel_info_ptr->tunnelName
			, vpn_tunnel_info_ptr->userID);
	}

	VPN_DBG_PRT(debug_on, "message=%s \n", message);

	sprintf((char*)mac, "%02X%02X%02X%02X%02X%02X",  vpn_tunnel_info_ptr->account_proxy_mac[0], vpn_tunnel_info_ptr->account_proxy_mac[1], vpn_tunnel_info_ptr->account_proxy_mac[2], vpn_tunnel_info_ptr->account_proxy_mac[3], vpn_tunnel_info_ptr->account_proxy_mac[4], vpn_tunnel_info_ptr->account_proxy_mac[5]);
	VPN_DBG_PRT(debug_on, "mac=%s \n", mac);

	///--memcpy(cur, time_str, strlen(time_str));
	sprintf(cur, "%s", time_str);
	cur += strlen((char*)time_str);

	///--memcpy(cur, message, strlen(message));
	sprintf(cur, ",%s", message);
	cur += strlen(message)+1;

	///--memcpy(cur, mac, strlen(mac));
	sprintf(cur, ",%s", mac);
	cur += strlen((char*)mac)+1;
	VPN_DBG_PRT(debug_on, "MD5(%s,%d) \n", tmp, strlen(tmp));
	MD5(tmp, strlen(tmp), md5);
	VPN_DBG_PRT(debug_on, "md5'%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x \n"
		, md5[0], md5[1], md5[2], md5[3], md5[4], md5[5], md5[6], md5[7], md5[8], md5[9], md5[10], md5[11], md5[12], md5[13], md5[14], md5[15]);
	snprintf(md5_str, sizeof(md5_str), "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", md5[0], md5[1], md5[2], md5[3], md5[4], md5[5], md5[6], md5[7], md5[8], md5[9], md5[10], md5[11], md5[12], md5[13], md5[14], md5[15]);

	sprintf(content, "{\"RPCMethod\":\"Post\",\"Plugin_Name\":\"\",\"MD5\":\"%s\",\"time\":\"%s\",\"mac\":\"%s\",\"Message\":\"%s\"}"
		, md5_str
		, time_str
		, mac
		, message);

#if 0
	if(accpxy_domain = strstr(vpn_tunnel_info_ptr->account_proxy, ":")){
		accpxy_domain = strtok(vpn_tunnel_info_ptr->account_proxy,":");
		accpxy_port = strtok(NULL,":");
		sprintf(sysbuf, "echo -ne \"POST / HTTP/1.1\\r\\nContent-Type: application/json; charset=utf-8\\r\\nContent-Length: %d\\r\\n%s\\r\\n\\r\\n\" | nc %s %s > /tmp/vpn_acc_pxy1", strlen(content), content, accpxy_domain, accpxy_port);
		printf("system(): %s\n",sysbuf);
	}

	sprintf(sysbuf, "echo -ne \"POST / HTTP/1.1\\r\\nContent-Type: application/json; charset=utf-8\\r\\nContent-Length: %d\\r\\n%s\\r\\n\\r\\n\" | nc 101.95.49.53 6890 > /tmp/vpn_acc_pxy2", strlen(content), content);
	printf("system(): %s\n",sysbuf);
#endif
	sprintf(sysbuf, "echo -ne \"%s\" > /tmp/vpn_json_data", content);
	printf("system(): %s\n",sysbuf);
	system(sysbuf);
	sprintf(sysbuf, "cat /tmp/vpn_json_data -| nc 101.95.49.53 6890", content);
	printf("system(): %s\n",sysbuf);
	system(sysbuf);

	vpn_tunnel_info_ptr->account_proxy_result = ACCPXY_RESULT_FAIL;
	vpn_tunnel_info_ptr->account_proxy_param_status = ACCPXY_STATUS_FAIL;

	fp = fopen("/tmp/vpn_acc_pxy", "r");

	if(NULL == fp)
	{
		AUG_PRT("%s-%d Cannot open file!\n",__func__,__LINE__);
		status=1;
		return -1;
	}

	while(fgets(response, 512, fp) != NULL)
	{
		parse_accpxy_response_line(response, vpn_tunnel_info_ptr);
	}

	fclose(fp);

	switch(vpn_tunnel_info_ptr->account_proxy_result)
	{
		case ACCPXY_RESULT_FAIL:
			AUG_PRT("%s-%d Get VPN account FAIL !!!\n",__func__,__LINE__);
			status=1;
			break;

		case ACCPXY_RESULT_SUCCESS:
			AUG_PRT("%s-%d Get VPN result success !!!\n",__func__,__LINE__);

			if(ACCPXY_STATUS_SUCCESS==vpn_tunnel_info_ptr->account_proxy_param_status)
				AUG_PRT("%s-%d Get VPN account status success !!!\n",__func__,__LINE__);
			else
				AUG_PRT("%s-%d Get VPN account status FAIL !!!\n",__func__,__LINE__);

			status=0;
			break;

		default:
			AUG_PRT("%s-%d FAIL to request HTTP POST !!!\n",__func__,__LINE__);
			strcpy(reason, "FAIL to request HTTP POST.");
			status=1;
			break;
	}

GetVPNAccDone:
	return status;
}

int request_vpn_accpxy_server( gdbus_vpn_tunnel_info_t *vpn_tunnel_info, char *reason )
{
	MIB_CE_ATM_VC_T atmvc_Entry;
	int i, mib_atmvc_total, dwg_find = -1;
	int status=-1;


	if(vpn_tunnel_info==NULL || reason==NULL) {
		status=1;
		strcpy(reason, "some parameter(s) exist NULL pointer!");
		goto RqstVPNAccDone;
	}

	if(vpn_tunnel_info->account_proxy[0] == '\0') {
		status=1;
		strcpy(reason, "some parameter(s) exist NULL string!");
		goto RqstVPNAccDone;
	}

	mib_get(MIB_ELAN_MAC_ADDR, (void *)vpn_tunnel_info->account_proxy_mac);

	//status=get_vpn_accpw_via_httppost(vpn_tunnel_info, reason);
	status=get_vpn_accpw_via_tcpconnect(vpn_tunnel_info, reason);

RqstVPNAccDone:
	return status;

}

int searchVpnTunnelAndRemove(gdbus_vpn_tunnel_info_t *vpn_tunnel_info)
{
	unsigned int pptpEntryNum, l2tpEntryNum, i;
	VPN_TYPE_T org_vpn_type;
	MIB_PPTP_T PPTPEntry;
	MIB_L2TP_T L2TPEntry;
	char reason[256];
		
	if(vpn_tunnel_info == NULL)
		return -1;
	
	if(vpn_tunnel_info->vpn_type == VPN_TYPE_L2TP)
	{
		pptpEntryNum = mib_chain_total(MIB_PPTP_TBL); /* get chain record size */
		for (i=0; i<pptpEntryNum; i++)
		{
			if ( !mib_chain_get(MIB_PPTP_TBL, i, (void *)&PPTPEntry) )
				continue;

			if (!strcmp(vpn_tunnel_info->tunnelName, PPTPEntry.tunnelName))
			{
				AUG_PRT(" VPN type got to be changed from PPTP to L2TP\n");
				RemoveWanPPTPTunnel(vpn_tunnel_info, reason);
				return 0;
			}
		}
	}
	else if(vpn_tunnel_info->vpn_type == VPN_TYPE_PPTP)
	{
		l2tpEntryNum = mib_chain_total(MIB_L2TP_TBL); /* get chain record size */
		for (i=0; i<l2tpEntryNum; i++)
		{
			if ( !mib_chain_get(MIB_L2TP_TBL, i, (void *)&L2TPEntry) )
				continue;

			if (!strcmp(vpn_tunnel_info->tunnelName, L2TPEntry.tunnelName))
			{
				AUG_PRT(" VPN type got to be changed from L2TP to PPTP\n");
				RemoveWanL2TPTunnel(vpn_tunnel_info, reason);
				return 0;
			}
		}
	} 
	else 
	{
		AUG_PRT(" Invalid vpn_type=%d \n", vpn_tunnel_info->vpn_type);
		return -1;
	}
}

int WanVPNCreate(gdbus_vpn_connection_info_t *vpn_connection_info_ptr, unsigned char *reason)
{
	int ret=0;

	searchVpnTunnelAndRemove(&vpn_connection_info_ptr->vpn_tunnel_info);
	if(vpn_connection_info_ptr->vpn_tunnel_info.vpn_type == VPN_TYPE_PPTP) {
		ret=CreateWanPPTPTunnel(&vpn_connection_info_ptr->vpn_tunnel_info, vpn_connection_info_ptr->attach_mode, reason);
	} else if (vpn_connection_info_ptr->vpn_tunnel_info.vpn_type == VPN_TYPE_L2TP) {
		ret=CreateWanL2TPTunnel(&vpn_connection_info_ptr->vpn_tunnel_info, vpn_connection_info_ptr->attach_mode, reason);
	} else {
		printf(" %s %d Invalid VPN type ! \n");
		ret=-1;
	}

	return ret;
}

int DialWanVPNUp(VPN_TYPE_T vpn_type)
{
	int i, vpn_entry_num;
	MIB_L2TP_T l2tp_entry;
	MIB_PPTP_T pptp_entry;
	struct data_to_pass_st msg;

	
	if(VPN_TYPE_L2TP==vpn_type){
		vpn_entry_num = mib_chain_total(MIB_L2TP_TBL);
		for(i=0 ; i<vpn_entry_num ; i++) {
			if (!mib_chain_get(MIB_L2TP_TBL, i, (void *)&l2tp_entry))
				continue;

			if( pptp_entry.conntype==CONNECT_ON_DEMAND ) {
				snprintf(msg.data, BUF_SIZE,
					"spppctl up %d", l2tp_entry.idx+11);
				printf("%s: %s\n", __func__, msg.data);
				write_to_pppd(&msg);
			}
		}
	} else if(VPN_TYPE_PPTP==vpn_type) {
		vpn_entry_num = mib_chain_total(MIB_PPTP_TBL);
		for(i=0 ; i<vpn_entry_num ; i++) {
			if (!mib_chain_get(MIB_PPTP_TBL, i, (void *)&pptp_entry))
				continue;

			if( pptp_entry.conntype==CONNECT_ON_DEMAND ) {
				snprintf(msg.data, BUF_SIZE,
					"spppctl up %d", pptp_entry.idx+9);
				printf("%s: %s\n", __func__, msg.data);
				write_to_pppd(&msg);
			}
		}
	} else {
		AUG_PRT("%s-%d	Invalid vpn_type=%d \n", __func__, __LINE__, vpn_type);
		return -1;
	}

	return 0;
}

int DialWanVPNDown(int if_index)
{
	struct data_to_pass_st msg;

	
	snprintf(msg.data, BUF_SIZE,
					"spppctl down %d", if_index);
	printf("%s: %s\n", __func__, msg.data);
	write_to_pppd(&msg);
}

void AllVPNDown( void )
{
	int pptpenable, l2tpenable;
	int total_pptp_entry;
	int total_l2tp_entry;
	MIB_PPTP_T pptpEntry;
	MIB_L2TP_T l2tpEntry;
	int i;
	

	mib_get(MIB_PPTP_ENABLE, (void *)&pptpenable);
	if(pptpenable) {
		total_pptp_entry = mib_chain_total(MIB_PPTP_TBL);
		for(i=0 ; i<total_pptp_entry ; i++) {
			if (!mib_chain_get(MIB_PPTP_TBL, i, (void *)&pptpEntry))
				continue;

			DialWanVPNDown(pptpEntry.idx+9);
		}
	}
	
	mib_get(MIB_L2TP_ENABLE, (void *)&l2tpenable);	
	if(l2tpenable) {
		total_l2tp_entry = mib_chain_total(MIB_L2TP_TBL);
		for(i=0 ; i<total_l2tp_entry ; i++) {
			if (!mib_chain_get(MIB_L2TP_TBL, i, (void *)&l2tpEntry))
				continue;

			DialWanVPNDown(l2tpEntry.idx+11);
			RG_release_l2tp(l2tpEntry.rg_wan_idx);
		}
	}
}

int L2TPVPNShutdown( char *srvIP )
{
	int l2tpenable;
	int total_l2tp_entry;
	MIB_L2TP_T l2tpEntry;
	int i;

	if(srvIP == NULL)
		return 1;

	printf("%s:%d srvIP %s\n", __FUNCTION__, __LINE__, srvIP);
	mib_get(MIB_L2TP_ENABLE, (void *)&l2tpenable);	
	if(l2tpenable) {
		total_l2tp_entry = mib_chain_total(MIB_L2TP_TBL);
		for(i=0 ; i<total_l2tp_entry ; i++) {
			if (!mib_chain_get(MIB_L2TP_TBL, i, (void *)&l2tpEntry))
				continue;

			if(!strcmp(l2tpEntry.server, srvIP)){
				applyL2TP(&l2tpEntry, 0, l2tpEntry.rg_wan_idx);
				return 0;
			}
		}
	}

	return 1;
}


int SetWANVPNPrio(int vpn_type)
{
	return RG_Set_WanVPN_QoS(vpn_type);
}

int AttachWanVPN
(
	gdbus_vpn_tunnel_info_t *vpn_tunnel_info,
	unsigned char *ipDomainNameAddr[], 
	unsigned char *reason
)
{
	int status=0;
	int ret=0;

	
	switch( vpn_tunnel_info->vpn_type )
	{
		case VPN_TYPE_L2TP:
			status=AttachWanL2TPTunnel(vpn_tunnel_info, 
										ipDomainNameAddr, 
										reason);
			if( status )
				ret = VPN_STATUS_NG;

			AUG_PRT("AttachWanL2TPTunnel status=%d reason=%s \n", status, reason);

			break;

		case VPN_TYPE_PPTP:
			status=AttachWanPPTPTunnel(vpn_tunnel_info, 
										ipDomainNameAddr, 
										reason);
			
			if( status )
				ret = VPN_STATUS_NG;

			AUG_PRT("AttachWanPPTPTunnel status=%d reason=%s \n", status, reason);

			break;

		default:
			ret = VPN_STATUS_NG;
			strcpy(reason, "Invalid VPN type!");
	}

	return ret;
}

void Delete_Vpn_Attach( VPN_TYPE_T vpn_type ) {
	int i, totall2tp, totalpptp;
	MIB_CE_L2TP_ROUTE_T l2tp_r_entry;
	MIB_CE_PPTP_ROUTE_T pptp_r_entry;
	

	if(vpn_type==VPN_TYPE_NONE || vpn_type==VPN_TYPE_L2TP) {
		printf("Deatach all L2TP VPN attachment. \n");
		totall2tp = mib_chain_total(MIB_L2TP_ROUTE_TBL);
		for(i=0 ; i<totall2tp ; i++) {
			if (!mib_chain_get(MIB_L2TP_ROUTE_TBL, i, (void *)&l2tp_r_entry))
					continue;

			RG_Flush_L2TP_Route(l2tp_r_entry.tunnelName, 0);
			RG_Flush_L2TP_Dynamic_URL_Route(l2tp_r_entry.tunnelName);
			NF_Flush_L2TP_Route(l2tp_r_entry.tunnelName);
			NF_Flush_L2TP_Dynamic_URL_Route(l2tp_r_entry.tunnelName);
		}
		mib_chain_clear(MIB_L2TP_ROUTE_TBL);
	}

	if(vpn_type==VPN_TYPE_NONE || vpn_type==VPN_TYPE_PPTP) {
		printf("Deatach all PPTP VPN attachment. \n");
		totalpptp = mib_chain_total(MIB_PPTP_ROUTE_TBL);
		for(i=0 ; i<totalpptp ; i++) {
			if (!mib_chain_get(MIB_PPTP_ROUTE_TBL, i, (void *)&pptp_r_entry))
					continue;

			RG_Flush_PPTP_Route(pptp_r_entry.tunnelName);
			RG_Flush_PPTP_Dynamic_URL_Route(pptp_r_entry.tunnelName);
			NF_Flush_PPTP_Route(pptp_r_entry.tunnelName);
			NF_Flush_PPTP_Dynamic_URL_Route(pptp_r_entry.tunnelName);
		}
		mib_chain_clear(MIB_PPTP_ROUTE_TBL);
	}

#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif
}

void Remove_Vpn_Tunnel( VPN_TYPE_T vpn_type ) {
	int i, totall2tp, totalpptp;
	MIB_L2TP_T l2tp_entry;
	MIB_PPTP_T pptp_entry;
	

	if(vpn_type==VPN_TYPE_NONE || vpn_type==VPN_TYPE_L2TP) {
		printf("Remove all L2TP VPN Tunnel. \n");
		totall2tp = mib_chain_total(MIB_L2TP_TBL);
		for(i=0 ; i<totall2tp ; i++) {
			if (!mib_chain_get(MIB_L2TP_TBL, i, (void *)&l2tp_entry))
					continue;

			applyL2TP(&l2tp_entry, 0, l2tp_entry.rg_wan_idx);
		}
		mib_chain_clear(MIB_L2TP_TBL);
	}

	if(vpn_type==VPN_TYPE_NONE || vpn_type==VPN_TYPE_PPTP) {
		printf("Remove all PPTP VPN Tunnel. \n");
		totalpptp = mib_chain_total(MIB_PPTP_TBL);
		for(i=0 ; i<totalpptp ; i++) {
			if (!mib_chain_get(MIB_PPTP_TBL, i, (void *)&pptp_entry))
					continue;

			applyPPtP(&pptp_entry, 0, pptp_entry.rg_wan_idx);
		}
		mib_chain_clear(MIB_PPTP_TBL);
	}

#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif
}

void Dump_Vpn_Info( VPN_TYPE_T vpn_type ) {

	if(vpn_type==VPN_TYPE_NONE || vpn_type==VPN_TYPE_L2TP) {
		dump_mib_l2tp();
	}

	if(vpn_type==VPN_TYPE_NONE || vpn_type==VPN_TYPE_PPTP) {
		dump_mib_pptp();
	}
}

void Preset_VPN_Napt_Rule( gdbus_vpn_tunnel_info_t *vpn_tunnel_info ) {
	if(vpn_tunnel_info->vpn_type==VPN_TYPE_L2TP) {
		RG_Flush_L2TP_Route_All();
		RG_Preset_L2TP_Napt_Rule();
	} else if(vpn_tunnel_info->vpn_type==VPN_TYPE_PPTP) {
		RG_Flush_PPTP_Route_All();
		RG_Preset_PPTP_Napt_Rule();
	}
}

void *VPNConnectionThread(void *arg)
{
	int i = 0, ret = 0;
	unsigned char *attach_pattern[20] = {0};
	gdbus_vpn_connection_info_t *vpn_connection_info_ptr;
	gdbus_vpn_tunnel_info_t *gdbus_vpn_tunnel_info_ptr;
	char reason[100] = {0};
	int lockfd;

	LOCK_VPN();
	vpn_connection_info_ptr = (gdbus_vpn_connection_info_t *) arg;
	gdbus_vpn_tunnel_info_ptr = &(vpn_connection_info_ptr->vpn_tunnel_info);
	dump_parameter(vpn_connection_info_ptr);
	ret = WanVPNCreate(vpn_connection_info_ptr, reason);
	if (ret == 0)
	{
		//SetWANVPNPrio(gdbus_vpn_tunnel_info_ptr->vpn_type);
		update_fw_vpngre();

		if (!get_attach_pattern_by_mode(vpn_connection_info_ptr, attach_pattern, reason))
		{
			ret = AttachWanVPN(gdbus_vpn_tunnel_info_ptr,
							attach_pattern,
							reason);
			if (!ret)
				Preset_VPN_Napt_Rule(gdbus_vpn_tunnel_info_ptr);
		}
	}
	for (i = 0; i < 20; i++)
	{
		if (attach_pattern[i] != NULL)
		{
			free(attach_pattern[i]);
		}
	}
	UNLOCK_VPN();
	
	return 0;
}

void *RemoveWanPPTPTunnelThread(void *arg)
{
	int status=0;
	MIB_PPTP_T entry;
	MIB_CE_PPTP_ROUTE_T pptp_r_entry;
	unsigned int pptpEntryNum, i, pptpRouteEntryNum;	
	unsigned int findUser=0, findTunnel=0;
	gdbus_vpn_tunnel_info_t *vpn_tunnel_info;
	char reason[100] = {0};
	int enable=0;	
	int j;
	int lockfd;

	LOCK_VPN();
	vpn_tunnel_info = (gdbus_vpn_tunnel_info_t *) arg;	
	if(vpn_tunnel_info==NULL || reason==NULL){
		status=1;
		strcpy(reason, "some parameter(s) exist NULL pointer!");
		goto RemovePPTPDone;
	}

	if(vpn_tunnel_info->tunnelName[0] == '\0' || vpn_tunnel_info->userID[0] == '\0'){
		status=1;
		strcpy(reason, "some parameter(s) is NULL string!");
		goto RemovePPTPDone;
	}

	if(strcmp(vpn_tunnel_info->tunnelName, "all") && !strcmp(vpn_tunnel_info->userID, "0")){
		/*userID =0, but tunnelName!=all*/
		status=1;
		strcpy(reason, "userId=0, but tunnelName!=all!");
		goto RemovePPTPDone;
	}

	if ( !mib_get(MIB_PPTP_ENABLE, (void *)&enable) ){
		strcpy(reason, "MIB_PPTP_ENABLE is not exist!");
		status=1;
		goto RemovePPTPDone;
	}

	/*gateway PPTP feature is disable*/
	if(!enable){
		status=1;
		//reason = "PPTP is Disable"
		strcpy(reason, "MIB_PPTP_ENABLE is Disable");
		goto RemovePPTPDone;
	}

	pptpEntryNum = mib_chain_total(MIB_PPTP_TBL); /* get chain record size */
	if(pptpEntryNum == 0){
		status=2;
		//reason = "PPTP is Disable"
		strcpy(reason, "VPN is not exist!");
		goto RemovePPTPDone;
	}

	for (i=0; i<pptpEntryNum; i++)
	{
		if ( !mib_chain_get(MIB_PPTP_TBL, i, (void *)&entry) )
			continue;

		if(!strcmp(vpn_tunnel_info->tunnelName, "all"))
		{
			findTunnel=1;
			/*Specific userID tunnel || all VPN tunnel*/
			if(!strcmp(vpn_tunnel_info->userID, entry.userID) || !strcmp(vpn_tunnel_info->userID,"0")){
				applyPPtP(&entry, 0, i);
				RG_Del_WanVPN_QoS(entry.acl_idx);
				if(mib_chain_delete(MIB_PPTP_TBL, i) != 1) {
					status=1;
					strcpy(reason, "remove VPN fail!");
					goto RemovePPTPDone;
				} else {				
					pptpRouteEntryNum = mib_chain_total(MIB_PPTP_ROUTE_TBL);
					for(j=(pptpRouteEntryNum-1) ; j>=0 ; j--) {	
						if (!mib_chain_get(MIB_PPTP_ROUTE_TBL, j, (void *)&pptp_r_entry))
							continue;

						if(strcmp(entry.tunnelName, pptp_r_entry.tunnelName))
							continue;

						mib_chain_delete(MIB_PPTP_ROUTE_TBL, j);
					}
					RG_Flush_PPTP_Route(entry.tunnelName);
					RG_Flush_PPTP_Dynamic_URL_Route(entry.tunnelName);
				}
				findUser=1;
			}
		}
		else if(!strcmp(vpn_tunnel_info->tunnelName,entry.tunnelName))
		{
			findTunnel=2;
			/*delete specified tunnelName & userID VPN*/
			if(!strcmp(vpn_tunnel_info->userID, entry.userID)){
				applyPPtP(&entry, 0, i);
				RG_Del_WanVPN_QoS(entry.acl_idx);
				if(mib_chain_delete(MIB_PPTP_TBL, i) != 1) {
					status=1;
					strcpy(reason, "remove VPN fail!");
					goto RemovePPTPDone;
				} else {				
					pptpRouteEntryNum = mib_chain_total(MIB_PPTP_ROUTE_TBL);
					for(j=(pptpRouteEntryNum-1) ; j>=0 ; j--) {
						if (!mib_chain_get(MIB_PPTP_ROUTE_TBL, j, (void *)&pptp_r_entry))
							continue;

						if(strcmp(entry.tunnelName, pptp_r_entry.tunnelName))
							continue;

						mib_chain_delete(MIB_PPTP_ROUTE_TBL, j);
					}
					RG_Flush_PPTP_Route(entry.tunnelName);
					RG_Flush_PPTP_Dynamic_URL_Route(entry.tunnelName);
				}
				findUser=1;
			}
		}
	}

	if(findTunnel==1 || findTunnel==2){
		if(findUser==1)	{
			status = 0;
			sprintf(reason, "match userID(%s) and tunnelName(%s)!", vpn_tunnel_info->userID, (findTunnel==1) ? "all":(char*)vpn_tunnel_info->tunnelName);
		}
		else{
			/*findUser=0*/
			status = 3;
			strcpy(reason, "userID is not exist!");
		}
	}
	else{
		/*findTunnel==0*/
		/*match userID but match tunnelName fail!*/
		status = 2;
		strcpy(reason, "match tunnelName fail!");
	}

RemovePPTPDone:
#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif
	free(vpn_tunnel_info);
	UNLOCK_VPN();
	return (void*)(intptr_t)status;
}

/*status: 0:success, 1:remove fail 2:VPN tunnel not exist, 3:USER ID not exist.*/
void *RemoveWanL2TPTunnelThread(void *arg)
{
	int status=0;
	unsigned int l2tpEntryNum, i, l2tpRouteEntryNum;
	unsigned int findUser=0, findTunnel=0;	
	MIB_CE_PPTP_ROUTE_T l2tp_r_entry;
	gdbus_vpn_tunnel_info_t *vpn_tunnel_info;
	char reason[100] = {0};
	MIB_L2TP_T entry;
	//unsigned int decisionCase=0;
	int enable=0;
	int j;
	int lockfd;

	LOCK_VPN();
	vpn_tunnel_info = (gdbus_vpn_tunnel_info_t *) arg;
	if(vpn_tunnel_info==NULL || reason==NULL){
		status=1;
		strcpy(reason, "some parameter(s) exist NULL pointer!");
		goto RemoveL2TPDone;
	}

	if(vpn_tunnel_info->tunnelName[0] == '\0' || vpn_tunnel_info->userID[0] == '\0'){
		status=1;
		strcpy(reason, "some parameter(s) is NULL string!");
		goto RemoveL2TPDone;
	}

	if ( !mib_get(MIB_L2TP_ENABLE, (void *)&enable) ){
		strcpy(reason, "MIB_L2TP_ENABLE is not exist!");
		status=1;
		goto RemoveL2TPDone;
	}
	/*gateway L2TP feature is disable*/
	if(!enable){
		status=1;
		//reason = "L2TP is Disable"
		strcpy(reason, "MIB_L2TP_ENABLE is Disable");
		goto RemoveL2TPDone;
	}
	l2tpEntryNum = mib_chain_total(MIB_L2TP_TBL); /* get chain record size */

	if(l2tpEntryNum == 0){
		status=2;
		//reason = "L2TP is Disable"
		strcpy(reason, "VPN is not exist!");
		goto RemoveL2TPDone;
	}
	if(!strcmp(vpn_tunnel_info->tunnelName,"all") && !strcmp(vpn_tunnel_info->userID,"0")){
		/*it means delete all VPN tunnel*/
		for (i=0; i<l2tpEntryNum; i++)
		{
			if ( !mib_chain_get(MIB_L2TP_TBL, i, (void *)&entry) )
				continue;
			applyL2TP(&entry, 0, i);
			RG_Del_WanVPN_QoS(entry.acl_idx);
			if(mib_chain_delete(MIB_L2TP_TBL, i) != 1) {
				status=1;
				strcpy(reason, "remove VPN fail!");
				goto RemoveL2TPDone;
			} else {				
				l2tpRouteEntryNum = mib_chain_total(MIB_L2TP_ROUTE_TBL);
				for(j=(l2tpRouteEntryNum-1) ; j>=0 ; j--) {
					if (!mib_chain_get(MIB_L2TP_ROUTE_TBL, j, (void *)&l2tp_r_entry))
							continue;

					if(strcmp(entry.tunnelName, l2tp_r_entry.tunnelName))
							continue;

					mib_chain_delete(MIB_L2TP_ROUTE_TBL, j);
				}
				RG_Flush_L2TP_Route(entry.tunnelName, 0);
				RG_Flush_L2TP_Dynamic_URL_Route(entry.tunnelName);
			}
		}
		strcpy(reason, "userID=0, tunnelName=all, kill all!");
		status=0;
		goto RemoveL2TPDone;
	}
	if(strcmp(vpn_tunnel_info->tunnelName,"all") && !strcmp(vpn_tunnel_info->userID,"0")){
		/*userID =0, but tunnelName!=all*/
		status=1;
		strcpy(reason, "userId=0, but tunnelName!=all!");
		goto RemoveL2TPDone;
	}
#if 1
	for (i=0; i<l2tpEntryNum; i++)
	{
		if ( !mib_chain_get(MIB_L2TP_TBL, i, (void *)&entry) )
			continue;
		
		VPN_DBG_PRT(debug_on, "\n tunnelName=%s, userID=%s",entry.tunnelName,entry.userID);
		VPN_DBG_PRT(debug_on, "\n tunnelNameIN=%s, userIDIN=%s",vpn_tunnel_info->tunnelName,vpn_tunnel_info->userID);

		if (!strcmp(vpn_tunnel_info->userID, entry.userID))
		{
			findUser=1;
			/*delete specified userID VPN*/
			if(!strcmp(vpn_tunnel_info->tunnelName,"all"))
			{
				findTunnel=1;
				/*delete specified all userID VPN*/
				applyL2TP(&entry, 0, i);
				RG_Del_WanVPN_QoS(entry.acl_idx);
				if(mib_chain_delete(MIB_L2TP_TBL, i) != 1) {
					status=1;
					strcpy(reason, "remove VPN fail!");
					goto RemoveL2TPDone;
				} else {				
					l2tpRouteEntryNum = mib_chain_total(MIB_L2TP_ROUTE_TBL);
					for(j=(l2tpRouteEntryNum-1) ; j>=0 ; j--) {
						if (!mib_chain_get(MIB_L2TP_ROUTE_TBL, j, (void *)&l2tp_r_entry))
								continue;

						if(strcmp(entry.tunnelName, l2tp_r_entry.tunnelName))
							continue;

						mib_chain_delete(MIB_L2TP_ROUTE_TBL, j);
					}
					RG_Flush_L2TP_Route(entry.tunnelName, 0);
					RG_Flush_L2TP_Dynamic_URL_Route(entry.tunnelName);
				}
			}
			else if(!strcmp(vpn_tunnel_info->tunnelName,entry.tunnelName))
			{
				findTunnel=2;
				/*delete specified tunnelName VPN*/
				applyL2TP(&entry, 0, i);
				RG_Del_WanVPN_QoS(entry.acl_idx);
				if(mib_chain_delete(MIB_L2TP_TBL, i) != 1) {
					status=1;
					strcpy(reason, "remove VPN fail!");
					goto RemoveL2TPDone;
				} else {				
					l2tpRouteEntryNum = mib_chain_total(MIB_L2TP_ROUTE_TBL);
					for(j=(l2tpRouteEntryNum-1) ; j>=0 ; j--) {
						if (!mib_chain_get(MIB_L2TP_ROUTE_TBL, j, (void *)&l2tp_r_entry))
								continue;

						if(strcmp(entry.tunnelName, l2tp_r_entry.tunnelName))
							continue;

						mib_chain_delete(MIB_L2TP_ROUTE_TBL, j);
					}
					RG_Flush_L2TP_Route(entry.tunnelName, 0);
					RG_Flush_L2TP_Dynamic_URL_Route(entry.tunnelName);
				}
			}
		}
	}
#endif
	if(findUser==1)
	{
		if(findTunnel==1)
		{
			strcpy(reason, "match userID and tunnelName 'all'!");
			status = 0;
		}
		else if(findTunnel==2)
		{
			strcpy(reason, "match userID and tunnelName!");
			status = 0;
		}
		else{
			/*findTunnel==0*/
			/*match userID but match tunnelName fail!*/
			status = 2;
			strcpy(reason, "match tunnelName fail!");
		}
	}
	else
	{
		/*findUser=0*/
		status = 3;
		strcpy(reason, "userID is not exist!");
	}

RemoveL2TPDone:
#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif	
	free(vpn_tunnel_info);
	UNLOCK_VPN();
	return (void*)(intptr_t)status;
}

int RemoveWanPPTPTunnel(gdbus_vpn_tunnel_info_t *vpn_tunnel_info, unsigned char *reason)
{
	gdbus_vpn_tunnel_info_t *vpn_tunnel_info_tmp;
	pthread_t ntid = 0;
	int err = 0;

	vpn_tunnel_info_tmp = malloc(sizeof(gdbus_vpn_tunnel_info_t));
	memcpy(vpn_tunnel_info_tmp, vpn_tunnel_info, sizeof(gdbus_vpn_tunnel_info_t));
	err = pthread_create(&ntid, NULL, RemoveWanPPTPTunnelThread, vpn_tunnel_info_tmp);
	if (err != 0) {
		printf("can't create thread: %s\n", strerror(err));
		sleep(1);
		free(vpn_tunnel_info);
		return 0;
	}
	pthread_detach(ntid);
	return 0;
}

int RemoveWanL2TPTunnel(gdbus_vpn_tunnel_info_t *vpn_tunnel_info, unsigned char *reason)
{
	gdbus_vpn_tunnel_info_t *vpn_tunnel_info_tmp;
	pthread_t ntid = 0;
	int err = 0;

	vpn_tunnel_info_tmp = malloc(sizeof(gdbus_vpn_tunnel_info_t));
	memcpy(vpn_tunnel_info_tmp, vpn_tunnel_info, sizeof(gdbus_vpn_tunnel_info_t));
	err = pthread_create(&ntid, NULL, RemoveWanL2TPTunnelThread, vpn_tunnel_info_tmp);
	if (err != 0) {
		printf("can't create thread: %s\n", strerror(err));
		sleep(1);
		free(vpn_tunnel_info);
		return 0;
	}
	pthread_detach(ntid);
	return 0;
}

int main(int argc, char *argv[])
#if 1
	{
		int idx, ret;
		unsigned char *attach_pattern[20] = {0};
		gdbus_vpn_connection_info_t vpn_connection_info;
		gdbus_vpn_tunnel_info_t *gdbus_vpn_tunnel_info_ptr=&vpn_connection_info.vpn_tunnel_info;
		char reason[100];
		int i, is_debug_cmd=0;
		
		
		printf("ApplyVPNConnection: %s", argv[0]);
		for(idx=1 ; idx<argc ; idx++) {
			printf(" %s", argv[idx]);
		}
		printf("\n");
	
		if( argc > 1 && (!strcmp(argv[1], "-h") || !strcmp(argv[1], "?")) ) {
			goto arg_err_rtn;
		}
		
		if ( argc == 2 ) {
			if(!strcmp(argv[1], "debugDeattachAll")) {		
				Delete_Vpn_Attach(VPN_TYPE_NONE);
				is_debug_cmd=1;
			} else if(!strcmp(argv[1], "debugDeattachL2TP")) {
				Delete_Vpn_Attach(VPN_TYPE_L2TP);
				is_debug_cmd=1;
			} else if(!strcmp(argv[1], "debugDeattachPPTP")) {
				Delete_Vpn_Attach(VPN_TYPE_PPTP);
				is_debug_cmd=1;
			} else if(!strcmp(argv[1], "debugRemoveAll")) {
				Remove_Vpn_Tunnel(VPN_TYPE_NONE);
				is_debug_cmd=1;
			} else if(!strcmp(argv[1], "debugRemoveL2TP")) {
				Remove_Vpn_Tunnel(VPN_TYPE_L2TP);
				is_debug_cmd=1;
			} else if(!strcmp(argv[1], "debugRemovePPTP")) {
				Remove_Vpn_Tunnel(VPN_TYPE_PPTP);
				is_debug_cmd=1;
			} else if(!strcmp(argv[1], "debugDumpAll")) {
				Dump_Vpn_Info(VPN_TYPE_NONE);
				is_debug_cmd=1;
			} else if(!strcmp(argv[1], "debugDumpL2TP")) {
				Dump_Vpn_Info(VPN_TYPE_L2TP);
				is_debug_cmd=1;
			} else if(!strcmp(argv[1], "debugDumpPPTP")) {
				Dump_Vpn_Info(VPN_TYPE_PPTP);
				is_debug_cmd=1;
			} 
	
			if(is_debug_cmd)
				goto goto_return;
		}
	
		memset(&vpn_connection_info, 0, sizeof(gdbus_vpn_connection_info_t));
		for(idx=1 ; idx<(argc-1) ; idx+=2) {		
			parse_parameter(&vpn_connection_info, argv[idx], argv[idx+1]);
		}
	
		if(debug_on) {
			dump_parameter(&vpn_connection_info);
		}
	
		ret = WanVPNCreate(&vpn_connection_info, reason);
		AUG_PRT("ret =%d reason=%s\n",ret, reason);
		//DialWanVPNUp(gdbus_vpn_tunnel_info_ptr->vpn_type);
		//SetWANVPNPrio(gdbus_vpn_tunnel_info_ptr->vpn_type);
		if (ret == 0){
		update_fw_vpngre();
	
		if( !get_attach_pattern_by_mode(&vpn_connection_info, attach_pattern, reason)) 
		{
			ret = AttachWanVPN( gdbus_vpn_tunnel_info_ptr, 
							attach_pattern, 
							reason);
			if(!ret)
				Preset_VPN_Napt_Rule(gdbus_vpn_tunnel_info_ptr);
		}
		}
	SetupVPNConnectionDone:
		i=0;
		while(attach_pattern[i]!=NULL) {
			free(attach_pattern[i]);
			i++;
		}
	
		i=0;
		while(vpn_connection_info.ips[i]!=NULL) {
			free(vpn_connection_info.ips[i]);
			i++;
		}
	
		i=0;
		while(vpn_connection_info.domains[i]!=NULL) {
			free(vpn_connection_info.domains[i]);
			i++;
		}
	
		i=0;
		while(vpn_connection_info.terminal_mac[i]!=NULL) {
			free(vpn_connection_info.terminal_mac[i]);
			i++;
		}
	
		if(ret) {
			goto arg_err_rtn;
		}
	
	goto_return:
		return 0;
	
	arg_err_rtn:	
		usage();
		exit(1);
	}
#else
	{
		int idx, ret;
		unsigned char *attach_pattern[20] = {0};
		gdbus_vpn_connection_info_t vpn_connection_info;
		gdbus_vpn_tunnel_info_t *gdbus_vpn_tunnel_info_ptr=&vpn_connection_info.vpn_tunnel_info;
		char reason[100];
		int i, is_debug_cmd=0;
		LIST_HEAD(HEAD);
		struct list_head *head = &HEAD;
		struct list_head *listptr;
		struct VPN_REQUEST_DATA *entry;
		
		
		printf("ApplyVPNConnection: %s", argv[0]);
		for(idx=1 ; idx<argc ; idx++) {
			printf(" %s", argv[idx]);
		}
		printf("\n");
	
		if( argc > 1 && (!strcmp(argv[1], "-h") || !strcmp(argv[1], "?")) ) {
			goto arg_err_rtn;
		}
		
		if ( argc == 2 ) {
			if(!strcmp(argv[1], "debugDeattachAll")) {		
				Delete_Vpn_Attach(VPN_TYPE_NONE);
				is_debug_cmd=1;
			} else if(!strcmp(argv[1], "debugDeattachL2TP")) {
				Delete_Vpn_Attach(VPN_TYPE_L2TP);
				is_debug_cmd=1;
			} else if(!strcmp(argv[1], "debugDeattachPPTP")) {
				Delete_Vpn_Attach(VPN_TYPE_PPTP);
				is_debug_cmd=1;
			} else if(!strcmp(argv[1], "debugRemoveAll")) {
				Remove_Vpn_Tunnel(VPN_TYPE_NONE);
				is_debug_cmd=1;
			} else if(!strcmp(argv[1], "debugRemoveL2TP")) {
				Remove_Vpn_Tunnel(VPN_TYPE_L2TP);
				is_debug_cmd=1;
			} else if(!strcmp(argv[1], "debugRemovePPTP")) {
				Remove_Vpn_Tunnel(VPN_TYPE_PPTP);
				is_debug_cmd=1;
			} else if(!strcmp(argv[1], "debugDumpAll")) {
				Dump_Vpn_Info(VPN_TYPE_NONE);
				is_debug_cmd=1;
			} else if(!strcmp(argv[1], "debugDumpL2TP")) {
				Dump_Vpn_Info(VPN_TYPE_L2TP);
				is_debug_cmd=1;
			} else if(!strcmp(argv[1], "debugDumpPPTP")) {
				Dump_Vpn_Info(VPN_TYPE_PPTP);
				is_debug_cmd=1;
			} else if(!strcmp(argv[1], "start")) {
				goto start;
			} 
			if(is_debug_cmd)
				goto goto_return;
		}
	
		memset(&vpn_connection_info, 0, sizeof(gdbus_vpn_connection_info_t));
		for(idx=1 ; idx<(argc-1) ; idx+=2) {		
			parse_parameter(&vpn_connection_info, argv[idx], argv[idx+1]);
		}
		if(debug_on) {
			dump_parameter(&vpn_connection_info);
		}
		struct VPN_REQUEST_DATA *request_data = malloc(sizeof(struct VPN_REQUEST_DATA));
		list_add_tail(&request_data->list, head);
		if(!strcmp(argv[1], "delete")) { // delete VPN tunnel
			request_data->request_data = (void *) &(vpn_connection_info.vpn_tunnel_info);
			request_data->request_type = VPN_REQ_REM_VPN;
		} else { // add VPN tunnel
			request_data->request_data = (void *) &(vpn_connection_info);
			request_data->request_type = VPN_REQ_ADD_VPN;
		}
		goto goto_return;
	start:
		while(1) {
			if(!list_empty(head)) {
				//list_for_each(listptr, head) {
					entry = list_entry(listptr, struct VPN_REQUEST_DATA, list);
					printf(" SAMDBG> %s %d request_type=%d\n", __func__, __LINE__, entry->request_type);
					entry=NULL;
				//}
			}
			sleep(1);
		}
	goto_return:
		return 0;
	
	arg_err_rtn:	
		usage();
		exit(1);
	}
#endif
	
void usage(void)
{
	printf("VPNConnection\n");
	printf("	vpn_mode\n");
	printf("		0: STEADY,\n		1: RANDOM.\n");
	printf("	vpn_priority\n");
	printf("		0: No priority,\n		1~8: High to Low.\n");
	printf("	vpn_type\n");
	printf("		0: No type,\n		1: L2TP,\n		2: PPTP.\n");
	printf("	vpn_enable\n");
	printf("		0: Enable,\n		1: Disable.\n");
	printf("	authtype\n");
	printf("		0: Auto,\n		1: PAP,\n		2: CHAP,\n		3: CHAPMS-V2.\n");
	printf("	enctype\n");
	printf("		0: None,\n		1: MPPE,\n		2: MPPC,\n");
	printf("	account_proxy\n");
	printf("		<DomainName>:<TCPPortNum>\n");
	printf("	vpn_port\n");
	printf("		0: PPTP is 1723, L2TP is 1701 default\n 	others: <PortNumber>\n");
	printf("	vpn_idletime\n");
	printf("		<NumOfSeconds>\n");
	printf("	serverIP\n");
	printf("		<xx.xx.xx.xx>\n");
	printf("	userName\n");
	printf("		<UserNameString>\n");
	printf("	passwd\n");
	printf("		<PassWordString>\n");
	printf("	tunnelName\n");
	printf("		<TunnelNameString>\n");
	printf("	userID\n");
	printf("		<UserIdString>\n");
	printf("	ips\n");
	printf("		<xx.xx.xx.xx>\n");
	printf("	domains\n");
	printf("		<RegularExpressionOfDomainName>\n");
	printf("	terminal_mac\n");
	printf("		<xx:xx:xx:xx:xx:xx>\n");
	printf("	debug\n");
	printf("		1: on\n 	others: off\n");
	printf("--The following commands is used only for debug.--\n");
	printf("	debugDeattachAll\n");
	printf("		Deattach all for debug\n");
	printf("	debugDeattachL2TP\n");
	printf("		Deattach all L2TP for debug\n");
	printf("	debugDeattachPPTP\n");
	printf("		Deattach all PPTP for debug\n");
	printf("	debugRemoveAll\n");
	printf("		Remove all VPN tunnel for debug\n");
	printf("	debugRemoveL2TP\n");
	printf("		Remove all L2TP VPN tunnel for debug\n");
	printf("	debugRemovePPTP\n");
	printf("		Remove all PPTP VPN tunnel for debug\n");
	printf("	debugDumpAll\n");
	printf("		Dump all VPN configs\n");
	printf("	debugDumpL2TP\n");
	printf("		Dump all L2TP VPN configs\n");
	printf("	debugDumpPPTP\n");
	printf("		Dump all PPTP VPN configs\n");
	
}

