/*
 *      Web server handler routines for Status
 *      Authors:
 *
 */

/*-- System inlcude files --*/
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/wait.h>
#include <semaphore.h>
#ifdef EMBED
#include <linux/config.h>
#else
#include "autoconf.h"
#endif

/* for ioctl */

#include "../webs.h"
#include "webform.h"
#include "mib.h"
#include "utility.h"
#include "debug.h"
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_bridge.h>
#include <stdio.h>
#include <fcntl.h>
#include "signal.h"
#include "../defs.h"
#include "../boa.h"
#include "fmdefs.h"
#if defined(CONFIG_RTK_L34_ENABLE)
#include <rtk_rg_liteRomeDriver.h>
#else
#ifdef CONFIG_GPON_FEATURE	
#include "rtk/ponmac.h"
#include "rtk/gpon.h"
#include "rtk/epon.h"
#include "hal/chipdef/chip.h"
#endif
#endif

#include "../ipv6_info.h"
#include "../rtusr_rg_api.h"

#ifdef CONFIG_RTK_L34_ENABLE
extern int RG_get_phyPort_status(unsigned int portIndex, rtk_rg_portStatusInfo_t *portInfo);
#endif

static const char IF_UP[] = "up";
static const char IF_DOWN[] = "down";
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
static const char IF_CONNET[] = "connecting";
#endif
static const char IF_NA[] = "n/a";

#define __PME(entry,name)               #name, entry.name

struct wan_status_info {
	char protocol[10];
	char ipAddr[INET_ADDRSTRLEN];
	char *strStatus;
	char servName[MAX_WAN_NAME_LEN];
	unsigned short vlanId;
	unsigned char igmpEnbl;
	char qosEnbl;
	char servType[20];
	char encaps[8];
	char netmask[INET_ADDRSTRLEN];
	char gateway[INET_ADDRSTRLEN];
	char dns1[INET_ADDRSTRLEN];
	char dns2[INET_ADDRSTRLEN];
	char ipv6Addr[64];	/* With Prefix Length */
	char ipv6Prefix[64];	/* With Prefix Length */
	char ipv6Gateway[INET6_ADDRSTRLEN];
	char ipv6Dns1[INET6_ADDRSTRLEN];
	char ipv6Dns2[INET6_ADDRSTRLEN];
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	unsigned char ipv6PrefixOrigin;
	unsigned char addrMode;
#endif
};
#ifdef CONFIG_MCAST_VLAN
struct iptv_mcast_info {
	unsigned int ifIndex;
	char servName[MAX_WAN_NAME_LEN];
	unsigned short vlanId;
	unsigned char enable;
};

int listWanName(int eid, request * wp, int argc, char **argv)
{
	char ifname[IFNAMSIZ];
	int i, entryNum;
	MIB_CE_ATM_VC_T entry;
	struct iptv_mcast_info mEntry[MAX_VC_NUM + MAX_PPP_NUM] = { 0 };

	entryNum = mib_chain_total(MIB_ATM_VC_TBL);
	for (i = 0; i < entryNum; i++) {
		if (!mib_chain_get(MIB_ATM_VC_TBL, i, &entry)) {
			printf("get MIB chain error\n");
			return -1;
		}
		ifGetName(entry.ifIndex, ifname, sizeof(ifname));
		getWanName(&entry, mEntry[i].servName);
		mEntry[i].vlanId = entry.mVid;
		boaWrite(wp,
			 "links.push(new it_nr(\"%d\"" _PTS _PTI "));\n", i,
			 __PME(mEntry[i], servName), __PME(mEntry[i], vlanId));
	}


}
#endif

#ifdef TERMINAL_INSPECTION_SC
//get IP of tro69-wan, voip-wan, internet-wan for terminal self-inspection. If there have more than one IP of tro69/voip/internet , only select one IP.
int terminalInspectionShow(int eid, request * wp, int argc, char **argv)
{
	char ifname[IFNAMSIZ], *str_ipv4;
	int flags, flags_found,i, entryNum, ipfound=0,wanfound=0,var1,var2;
	MIB_CE_ATM_VC_T entry;
	struct in_addr inAddr;
	unsigned int CPURate, MemRate;
	
	entryNum = mib_chain_total(MIB_ATM_VC_TBL);
	for (i = 0; i < entryNum; i++) {
		if (!mib_chain_get(MIB_ATM_VC_TBL, i, &entry)) {
			continue;
		}

		if((strcmp(argv[0], "VoiceIPAdd")==0) && (entry.applicationtype & X_CT_SRV_VOICE))
		{	
			ifGetName(entry.ifIndex,ifname,sizeof(ifname));
			flags_found = getInFlags(ifname, &flags);
			if (flags_found && getInAddr(ifname, IP_ADDR, &inAddr) == 1)
			{
				str_ipv4 = inet_ntoa(inAddr);
				if (strcmp(str_ipv4, "0.0.0.0"))
				{
					boaWrite(wp, "<td>%s</td>",str_ipv4);
					ipfound = 1;
					break;
				}
			}
		}
		else if((strcmp(argv[0], "tr069IPAdd")==0) && (entry.applicationtype & X_CT_SRV_TR069))
		{
			ifGetName(entry.ifIndex,ifname,sizeof(ifname));
			flags_found = getInFlags(ifname, &flags);
			if (flags_found && getInAddr(ifname, IP_ADDR, &inAddr) == 1)
			{
				str_ipv4 = inet_ntoa(inAddr);
				if (strcmp(str_ipv4, "0.0.0.0"))
				{
					boaWrite(wp, "<td>%s</td>",str_ipv4);
					ipfound = 1;
					break;
				}
			}
		}
		else if((strcmp(argv[0], "InterIPAdd")==0) && (entry.applicationtype & X_CT_SRV_INTERNET))
		{
			ifGetName(entry.ifIndex,ifname,sizeof(ifname));
			flags_found = getInFlags(ifname, &flags);
			if (flags_found && getInAddr(ifname, IP_ADDR, &inAddr) == 1)
			{
				str_ipv4 = inet_ntoa(inAddr);
				if (strcmp(str_ipv4, "0.0.0.0"))
				{
					boaWrite(wp, "<td>%s</td>",str_ipv4);
					ipfound = 1;
					break;
				}
			}
		}	
		else if((strcmp(argv[0], "SCWANState")==0) && (entry.applicationtype & X_CT_SRV_INTERNET))
		{
			if(entry.cmode == CHANNEL_MODE_BRIDGE)
			{
				boaWrite(wp, "<td>%s</td>","桥接模式");
				wanfound = 1;
				break;
			}
			else
			{
				ifGetName(entry.ifIndex,ifname,sizeof(ifname));
				flags_found = getInFlags(ifname, &flags);
				if (flags_found && getInAddr(ifname, IP_ADDR, &inAddr) == 1)
				{
					boaWrite(wp, "<td>%s</td>","路由模式-拨号成功");
					wanfound = 1;
					break;
				}
				else
				{
					boaWrite(wp, "<td>%s</td>","路由模式-拨号失败");
					wanfound = 1;
					break;
				}
			}						
		}
	}
	if(((strcmp(argv[0], "VoiceIPAdd")==0)||(strcmp(argv[0], "tr069IPAdd")==0)||(strcmp(argv[0], "InterIPAdd")==0) )&& !ipfound)
	{
		boaWrite(wp, "<td>%s</td>", "未获取宽带地址");
	}
	if((strcmp(argv[0], "SCWANState")==0) && !wanfound)
	{
		boaWrite(wp, "<td>%s</td>", "未配置");
	}	
	if(strcmp(argv[0], "SCCPURate")==0)
	{
#ifdef  _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_CPURateEnable_
		var1 = getCPURate(&CPURate);
		if(var1 < 0)
		{
			boaWrite(wp, "<td>%s</td>", "异常");
		}
		else
		{
			boaWrite(wp, "<td>%s</td>", "正常");
		}
#endif
	}
	if(strcmp(argv[0], "SCMemRate")==0)
	{
#ifdef  _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_MemRateEnable_
		var2 = getMemRate(&MemRate);
		if(var2 < 0)
		{
			boaWrite(wp, "<td>%s</td>", "异常");
		}
		else
		{
			boaWrite(wp, "<td>%s</td>", "正常");
		}
#endif
	}
	if(strcmp(argv[0], "LANPorts")==0)
	{
#ifdef TERMINAL_INSPECTION_SC
//		char status[128] = {0};
//		getLANxStateTerminal(status, sizeof(status));
//		boaWrite(wp, "<td>%s</td>", status);
#endif
	}
#ifdef STB_L2_FRAME_LOSS_RATE
			char rate[256] = {};
			char delay[256] = {};
			char term[256] = {};
			char line[256] = {};
			char *tmp;
			int res = 0;
			FILE *fp;
			if(strcmp(argv[0], "stbRate")==0)
			{
				if((access(STB_L2_DIAG_RESULT,F_OK))!=-1)	
				{	
					res = 1;
					//printf("%s %d: file exist!\n", __FUNCTION__, __LINE__);	
				}
				if(res)
				{
					
					if ((fp = fopen(STB_L2_DIAG_RESULT, "r")) == 0) {
						printf("%s can not open %s\n", __func__,STB_L2_DIAG_RESULT);
						return -1;
					}
					while(fgets(line, sizeof(line), fp))
					{
						if(tmp = strstr(line, "rate:"))
						{
							sscanf(tmp, "rate:%s", rate);
						}
					}
					fclose(fp);
					boaWrite(wp, "%s", strlen(rate)?rate:"未检测到机顶盒");
					//printf("rate:%s\n", rate);
				}
				else
				{
					boaWrite(wp, "%s", "未检测到机顶盒");
				}
			}
			if(strcmp(argv[0], "stbDelay")==0)
			{
				if((access(STB_L2_DIAG_RESULT,F_OK))!=-1)	
				{	
					res = 1;
					//printf("%s %d: file exist!\n", __FUNCTION__, __LINE__);	
				}
				if(res)
				{
					
					if ((fp = fopen(STB_L2_DIAG_RESULT, "r")) == 0) {
						printf("%s can not open %s\n", __func__,STB_L2_DIAG_RESULT);
						return -1;
					}
					while(fgets(line, sizeof(line), fp))
					{
						if(tmp = strstr(line, "delay:"))
						{
							sscanf(tmp, "delay:%s", delay);
						}
					}
					fclose(fp);
					boaWrite(wp, "%s", strlen(delay)?delay:"未检测到机顶盒");
					//printf("delay:%s\n", delay);
				}
				else
				{
					boaWrite(wp, "%s", "未检测到机顶盒");
				}
			}
			if(strcmp(argv[0], "stbTerm")==0)
			{
				if((access(STB_L2_DIAG_RESULT,F_OK))!=-1)	
				{	
					res = 1;
					//printf("%s %d: file exist!\n", __FUNCTION__, __LINE__);	
				}
				if(res)
				{
					
					if ((fp = fopen(STB_L2_DIAG_RESULT, "r")) == 0) {
						printf("%s can not open %s\n", __func__,STB_L2_DIAG_RESULT);
						return -1;
					}
					while(fgets(line, sizeof(line), fp))
					{
						if(tmp = strstr(line, "term:"))
						{
							sscanf(tmp, "term:%s", term);
						}
					}
					fclose(fp);
					boaWrite(wp, "%s", strlen(term)?term:"未检测到机顶盒");
					//printf("term:%s\n", term);
				}
				else
				{
					boaWrite(wp, "%s", "未检测到机顶盒");
				}
			}
#endif
	return 0;
}
#endif


int listWanConfig(int eid, request * wp, int argc, char **argv)
{
	char ifname[IFNAMSIZ], *str_ipv4;
	char vprio_str[20];
	char MacAddr[20];
	char cmode_str[20];
	int flags, i, k, entryNum, flags_found, isPPP;
#ifdef EMBED
	int spid;
#endif
	MIB_CE_ATM_VC_T entry;
	struct in_addr inAddr;
	int pon_mode = 0;
	FILE * pFile;
	char tmpFile[32], dhcpState[1024];

	struct wan_status_info sEntry[MAX_VC_NUM + MAX_PPP_NUM] = { 0 };

#if defined(CONFIG_GPON_FEATURE) || defined(CONFIG_EPON_FEATURE)
	mib_get(MIB_PON_MODE, &pon_mode);
#endif

#ifdef CONFIG_GPON_FEATURE
	rtk_gpon_fsm_status_t onu;
	#if defined(CONFIG_RTK_L34_ENABLE)
		rtk_rg_gpon_ponStatus_get(&onu);
	#else
		rtk_gpon_ponStatus_get(&onu);
	#endif
#endif

		int ret;
#ifdef CONFIG_EPON_FEATURE
		if(pon_mode == EPON_MODE){
			rtk_epon_llid_entry_t llid_entry;
			llid_entry.llidIdx = 0;
#if defined(CONFIG_RTK_L34_ENABLE)
			rtk_rg_epon_llid_entry_get(&llid_entry);
#else
			rtk_epon_llid_entry_get(&llid_entry);
#endif
			if (llid_entry.valid)	
				ret = epon_getAuthState(llid_entry.llidIdx);
		}
#endif

#ifdef EMBED
	if ((spid = read_pid(PPP_PID)) > 0)
		kill(spid, SIGUSR2);
	else
		fprintf(stderr, "spppd pidfile not exists\n");
#endif

	entryNum = mib_chain_total(MIB_ATM_VC_TBL);
	for (i = 0; i < entryNum; i++) {
		if (!mib_chain_get(MIB_ATM_VC_TBL, i, &entry)) {
			printf("get MIB chain error\n");
			return -1;
		}
#ifdef CONFIG_IPV6
		if ((entry.IpProtocol & IPVER_IPV4) == 0)
			continue;	// not IPv4 capable
#endif
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		if (entry.omci_configured==1 && entry.applicationtype&X_CT_SRV_VOICE)
			continue;   
#endif
		ifGetName(entry.ifIndex, ifname, sizeof(ifname));
		flags_found = getInFlags(ifname, &flags);

		switch (entry.cmode) {
		case CHANNEL_MODE_BRIDGE:
			strcpy(sEntry[i].protocol, "br1483");
			isPPP = 0;
			break;
		case CHANNEL_MODE_IPOE:
			#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
				if(entry.ipDhcp == 0){
					strcpy(sEntry[i].protocol, "Static");
					}
				else{
					strcpy(sEntry[i].protocol, "DHCP");
					}
			#else
				strcpy(sEntry[i].protocol, "IPoE");
				
			#endif			
			isPPP = 0;			
			break;
		case CHANNEL_MODE_PPPOE:	//patch for pppoe proxy
			strcpy(sEntry[i].protocol, "PPPoE");
			isPPP = 1;
			break;
		case CHANNEL_MODE_PPPOA:
			strcpy(sEntry[i].protocol, "PPPoA");
			isPPP = 1;
			break;
		default:
			isPPP = 0;
			break;
		}

		strcpy(sEntry[i].ipAddr, "");
#ifdef EMBED
		if (flags_found && getInAddr(ifname, IP_ADDR, &inAddr) == 1) {
			str_ipv4 = inet_ntoa(inAddr);
			// IP Passthrough or IP unnumbered
			if (flags & IFF_POINTOPOINT && (strcmp(str_ipv4, "10.0.0.1") == 0))
				strcpy(sEntry[i].ipAddr, STR_UNNUMBERED);
			else
				strcpy(sEntry[i].ipAddr, str_ipv4);
		}
#endif

		strcpy(sEntry[i].netmask, "");
		if (flags_found && getInAddr(ifname, SUBNET_MASK, &inAddr) == 1) {
			strcpy(sEntry[i].netmask, inet_ntoa(inAddr));
		}

		k = getInAddr(ifname, IP_ADDR, &inAddr);
		// set status flag
		if (flags_found) {
			if ((flags & IFF_UP)&& (flags&IFF_RUNNING)) {
#if defined(CONFIG_GPON_FEATURE) || defined(CONFIG_EPON_FEATURE)
					if ( getInAddr(ifname, IP_ADDR, &inAddr) == 1
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
					&&((pon_mode == GPON_MODE && onu == 5)|| (pon_mode == EPON_MODE && ret==1))
#endif
#ifdef CONFIG_GPON_FEATURE
						|| (pon_mode == GPON_MODE && onu == 5 && strcmp(sEntry[i].protocol, "br1483") == 0)
#endif
#ifdef CONFIG_EPON_FEATURE
					    || (pon_mode == EPON_MODE && ret==1 && strcmp(sEntry[i].protocol, "br1483") == 0)
#endif
						)
#else
					if (strcmp(sEntry[i].protocol, "br1483") == 0
						|| getInAddr(ifname, IP_ADDR, &inAddr) == 1)
#endif
						sEntry[i].strStatus =
						    (char *)IF_UP;
					
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
#if defined(CONFIG_GPON_FEATURE) || defined(CONFIG_EPON_FEATURE)
					else if ((pon_mode == GPON_MODE && onu == 5)|| (pon_mode == EPON_MODE && ret==1))
						sEntry[i].strStatus =
							(char *)IF_CONNET;
#endif
#endif
					else
						sEntry[i].strStatus =
						    (char *)IF_DOWN;

			}
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
#if defined(CONFIG_GPON_FEATURE) || defined(CONFIG_EPON_FEATURE)
			else if ((pon_mode == GPON_MODE && onu == 5)|| (pon_mode == EPON_MODE && ret==1))
				sEntry[i].strStatus =
					(char *)IF_CONNET;
#endif
#endif
			else
				sEntry[i].strStatus = (char *)IF_DOWN;
		} else
			sEntry[i].strStatus = (char *)IF_NA;

		sEntry[i].gateway[0]='\0';
		sEntry[i].dns1[0]='\0';
		sEntry[i].dns2[0]='\0';
		if(sEntry[i].strStatus == IF_UP)
		{
			if (flags_found)
			{
				if(isPPP)
				{
					if(getInAddr(ifname, DST_IP_ADDR, &inAddr) == 1)
						strcpy(sEntry[i].gateway, inet_ntoa(inAddr));
				}
				else
				{
					if(entry.ipDhcp == (char)DHCP_CLIENT)
					{
						FILE *fp = NULL;
						char fname[128] = {0};

						sprintf(fname, "%s.%s", MER_GWINFO, ifname);

						if(fp = fopen(fname, "r"))
						{
						fscanf(fp, "%s", sEntry[i].gateway);
						fclose(fp);
					}
					}
					else
					{
						unsigned char zero[IP_ADDR_LEN] = {0};
						if(memcmp(entry.remoteIpAddr, zero, IP_ADDR_LEN))
							strcpy(sEntry[i].gateway, inet_ntoa(*((struct in_addr *)entry.remoteIpAddr)));
					}
				}
			}

			get_dns_by_wan(&entry, sEntry[i].dns1, sEntry[i].dns2);
		}

		if (isPPP && strcmp(sEntry[i].strStatus, (char *)IF_UP)) {
			sEntry[i].ipAddr[0] = '\0';
		}

		getWanName(&entry, sEntry[i].servName);

#if defined(CONFIG_EXT_SWITCH) || defined(CONFIG_RTL_MULTI_ETH_WAN) || (defined(ITF_GROUP_1P) && defined(ITF_GROUP))
		sEntry[i].vlanId = entry.vid;
#endif

#ifdef CONFIG_IGMPPROXY_MULTIWAN
		sEntry[i].igmpEnbl = entry.enableIGMP;
#endif

#if defined(IP_QOS) || defined(NEW_IP_QOS_SUPPORT)
		sEntry[i].qosEnbl = entry.enableIpQos;
#endif

		if (entry.qos == 0) {
			if (entry.svtype == 0) {
				strcpy(sEntry[i].servType, "UBR Without PCR");
			} else {
				strcpy(sEntry[i].servType, "UBR With PCR");
			}
		} else if (entry.qos == 1) {
			strcpy(sEntry[i].servType, "CBR");
		} else if (entry.qos == 2) {
			strcpy(sEntry[i].servType, "Non Realtime VBR");
		} else if (entry.qos == 3) {
			strcpy(sEntry[i].servType, "Realtime VBR");
		}

		if (entry.encap == 1) {
			strcpy(sEntry[i].encaps, "LLC");
		} else {
			strcpy(sEntry[i].encaps, "VCMUX");
		}
		//found in mit

#ifdef BR_ROUTE_ONEPVC
		if (entry.cmode == CHANNEL_MODE_BRIDGE && entry.br_route_flag == 1) {
			strcpy(sEntry[i].protocol, "br1483");
			sEntry[i].igmpEnbl = 0;
			strcpy(sEntry[i].ipAddr, "");
		}
#endif

		if (entry.cmode == CHANNEL_MODE_IPOE && entry.ipDhcp == DHCP_CLIENT) {
			if(strlen(sEntry[i].ipAddr) < 2) {
				ifGetName(entry.ifIndex, ifname, sizeof(ifname));
				sprintf(tmpFile, "%s.%s", DEFAULT_STATE_FILE, ifname);
				pFile = fopen (tmpFile,"r");
				if (pFile!=NULL)
				{
					memset(dhcpState,0,sizeof(dhcpState));
					fgets(dhcpState, sizeof(dhcpState), pFile);
					sprintf(sEntry[i].ipAddr, "%s", dhcpState);
					fclose (pFile);
				}
			}
		}
	
		#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		if(strcmp(sEntry[i].strStatus, "down") == 0){
			sEntry[i].strStatus = "未连接";
		}
		else if(strcmp(sEntry[i].strStatus, "up") == 0){
			sEntry[i].strStatus = "已连接";	
		}
		else
			sEntry[i].strStatus = "连接中";	
		
		if(entry.cmode == CHANNEL_MODE_IPOE && entry.ipDhcp == 0){
				snprintf(cmode_str,20,"%s", "手动");	
			}
		else{
			snprintf(cmode_str,20,"%s", "自动");
		}
		
		   //transfer format
		if(entry.vprio>0)
		snprintf(vprio_str,20,"%d",(entry.vprio-1));
		else
		snprintf(vprio_str,20,"%d",0);
		
		snprintf(MacAddr, 20, "%02x:%02x:%02x:%02x:%02x:%02x",
			entry.MacAddr[0],entry.MacAddr[1],entry.MacAddr[2],entry.MacAddr[3],entry.MacAddr[4],entry.MacAddr[5]);

		boaWrite(wp,
			 "links.push(new it_nr(\"%d\"" _PTS _PTS _PTS _PTS
			 _PTS _PTI _PTI _PTI _PTS _PTS _PTS _PTS _PTS _PTS _PTS _PTS "));\n", i,
			 __PME(sEntry[i], servName), __PME(sEntry[i], encaps),
			 __PME(sEntry[i], servType), __PME(sEntry[i], protocol),
			 __PME(sEntry[i], ipAddr), __PME(sEntry[i], vlanId),
			 __PME(sEntry[i], igmpEnbl), __PME(sEntry[i], qosEnbl),
			 __PME(sEntry[i], strStatus), __PME(sEntry[i], netmask),
			 __PME(sEntry[i], dns1), __PME(sEntry[i], dns2),
			 __PME(sEntry[i], gateway), "vprio",vprio_str, "MacAddr", MacAddr, "cmode",cmode_str
		    );
		#else
			boaWrite(wp,
			 "links.push(new it_nr(\"%d\"" _PTS _PTS _PTS _PTS
			 _PTS _PTI _PTI _PTI _PTS _PTS _PTS _PTS _PTS "));\n", i,
			 __PME(sEntry[i], servName), __PME(sEntry[i], encaps),
			 __PME(sEntry[i], servType), __PME(sEntry[i], protocol),
			 __PME(sEntry[i], ipAddr), __PME(sEntry[i], vlanId),
			 __PME(sEntry[i], igmpEnbl), __PME(sEntry[i], qosEnbl),
			 __PME(sEntry[i], strStatus), __PME(sEntry[i], netmask),
			 __PME(sEntry[i], dns1), __PME(sEntry[i], dns2),
			 __PME(sEntry[i], gateway)
		    );
		#endif
	}

	return 0;
}

#ifdef CONFIG_IPV6
static void get_dns6_by_wan(MIB_CE_ATM_VC_T *pEntry, char *dns1, char *dns2)
{
	if ( (pEntry->Ipv6Dhcp == 1) || ((pEntry->Ipv6DhcpRequest & 0x2) == 0x2)
			|| pEntry->AddrMode == IPV6_WAN_STATIC)
	{
		FILE* infdns;
		char file[64] = {0};
		char line[128] = {0};
		char ifname[IFNAMSIZ] = {0};

		ifGetName(pEntry->ifIndex,ifname,sizeof(ifname));

		snprintf(file, 64, "%s.%s", (char *)DNS6_RESOLV, ifname);

		infdns=fopen(file,"r");
		if(infdns)
		{
			int cnt = 0;

			while(fgets(line,sizeof(line),infdns) != NULL)
			{
				char *new_line = NULL;

				new_line = strrchr(line, '\n');
				if(new_line)
					*new_line = '\0';

				if((strlen(line)==0))
					continue;

				if(cnt == 0)
					strcpy(dns1, line);
				else
				{
					strcpy(dns2, line);
					break;
				}

				cnt++;
			}
			fclose(infdns);
		}
	}
}


int listWanConfigIpv6(int eid, request * wp, int argc, char ** argv)
{
	char ifname[IFNAMSIZ], str_ipv6[INET6_ADDRSTRLEN];
	char vprio_str[20],MacAddr[20], aftr_str[INET6_ADDRSTRLEN];
	int flags, i, j, k, entryNum, flags_found, isPPP;
#ifdef EMBED
	int spid;
#endif
	struct ipv6_ifaddr ipv6_addr[6];
	MIB_CE_ATM_VC_T entry;
	struct in_addr inAddr;
	int pon_mode = 0;
	char ipv6Addr[64]={0};

	struct wan_status_info sEntry[MAX_VC_NUM + MAX_PPP_NUM] = { 0 };

#if defined(CONFIG_GPON_FEATURE) || defined(CONFIG_EPON_FEATURE)
	mib_get(MIB_PON_MODE, &pon_mode);
#endif

#ifdef CONFIG_GPON_FEATURE
	rtk_gpon_fsm_status_t onu;
	#if defined(CONFIG_RTK_L34_ENABLE)
		rtk_rg_gpon_ponStatus_get(&onu);
	#else
		rtk_gpon_ponStatus_get(&onu);
	#endif
#endif

			int ret;
#ifdef CONFIG_EPON_FEATURE
			if(pon_mode == EPON_MODE){
				rtk_epon_llid_entry_t llid_entry;
				llid_entry.llidIdx = 0;
#if defined(CONFIG_RTK_L34_ENABLE)
				rtk_rg_epon_llid_entry_get(&llid_entry);
#else
				rtk_epon_llid_entry_get(&llid_entry);
#endif
				if (llid_entry.valid)	
					ret = epon_getAuthState(llid_entry.llidIdx);
			}
#endif

#ifdef EMBED
	if ((spid = read_pid(PPP_PID)) > 0)
		kill(spid, SIGUSR2);
	else
		fprintf(stderr, "spppd pidfile not exists\n");
#endif


	entryNum = mib_chain_total(MIB_ATM_VC_TBL);

	for (i = 0; i < entryNum; i++) {
		if (!mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&entry)) {
			printf("get MIB chain error\n");
			return -1;
		}

		if ((entry.IpProtocol & IPVER_IPV6) == 0)
			continue;	// not IPv6 capable

#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		if (entry.omci_configured==1 && entry.applicationtype&X_CT_SRV_VOICE)
			continue;  

			//debug
			sEntry[i].addrMode = entry.AddrMode;
			printf("entry.Ipv6Dhcp=%d",entry.Ipv6Dhcp);
			printf("entry.AddrMode=%d",entry.AddrMode);
#endif

		ifGetName(entry.ifIndex, ifname, sizeof(ifname));

		switch (entry.cmode) {
		case CHANNEL_MODE_BRIDGE:
			strcpy(sEntry[i].protocol, "br1483");
			isPPP = 0;
			break;
		case CHANNEL_MODE_IPOE:
		#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
			if((entry.Ipv6Dhcp == 0) &&(entry.AddrMode ==2))
				strcpy(sEntry[i].protocol, "Static");
			else
				strcpy(sEntry[i].protocol, "DHCP");
		#else
			strcpy(sEntry[i].protocol, "IPoE");
		#endif
			isPPP = 0;
			break;
		case CHANNEL_MODE_PPPOE:	//patch for pppoe proxy
			strcpy(sEntry[i].protocol, "PPPoE");
			isPPP = 1;
			break;
		case CHANNEL_MODE_PPPOA:
			strcpy(sEntry[i].protocol, "PPPoA");
			isPPP = 1;
			break;
		default:
			isPPP = 0;
			break;
		}

		k = getifip6(ifname, IPV6_ADDR_UNICAST, ipv6_addr, 6);
		sEntry[i].ipv6Addr[0] = 0;
		if (k) {
			for (j = 0; j < k; j++) {
				inet_ntop(AF_INET6, &ipv6_addr[j].addr, str_ipv6,
					  INET6_ADDRSTRLEN);
				if (j == 0)
					sprintf(sEntry[i].ipv6Addr, "%s/%d",
						str_ipv6,
						ipv6_addr[j].prefix_len);
				else
					sprintf(sEntry[i].ipv6Addr, "%s, %s/%d",
						ipv6Addr, str_ipv6,
						ipv6_addr[j].prefix_len);
				strncpy(ipv6Addr,sEntry[i].ipv6Addr,sizeof(ipv6Addr));				
			}
		}

		sEntry[i].ipv6Prefix[0] = 0;
		if(entry.cmode != CHANNEL_MODE_BRIDGE && entry.IpProtocol & IPVER_IPV6)
		{
			if(entry.AddrMode & IPV6_WAN_STATIC)
			{
				struct in6_addr prefix = {0};
				char *dst;

				ip6toPrefix(entry.Ipv6Addr, entry.Ipv6AddrPrefixLen, &prefix);
				dst = (char *)inet_ntop(AF_INET6, &prefix, sEntry[i].ipv6Prefix, sizeof(sEntry[i].ipv6Prefix));

				if(dst)
					sprintf(sEntry[i].ipv6Prefix, "%s/%d", dst, entry.Ipv6AddrPrefixLen);
			}
			else
			{
				DLG_INFO_T dlg_info;
				char fname[256] = {0};
				int ret;
				char *dst;

#define LEASE_FNAME_FMT "/var/dhcpcV6%s.leases"
				memset(&dlg_info, 0, sizeof(dlg_info));
				snprintf(fname, 256, LEASE_FNAME_FMT, ifname);
				ret = getLeasesInfo(fname, &dlg_info);
				dst = (char *)inet_ntop(AF_INET6, dlg_info.prefixIP, sEntry[i].ipv6Prefix, sizeof(sEntry[i].ipv6Prefix));

				if(ret && dst)
					sprintf(sEntry[i].ipv6Prefix, "%s/%d", dst, dlg_info.prefixLen);
			}

			#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
			if(strcmp(sEntry[i].ipv6Prefix, "::") == 0)
				strcpy(sEntry[i].ipv6Prefix, "-");
			#endif

			unsigned char zero[IP6_ADDR_LEN] = {0};
			sEntry[i].ipv6Gateway[0] = 0;
			if(memcmp(entry.RemoteIpv6Addr, zero, IP6_ADDR_LEN))
				inet_ntop(AF_INET6, &entry.RemoteIpv6Addr, sEntry[i].ipv6Gateway, INET6_ADDRSTRLEN);

			get_dns6_by_wan(&entry, sEntry[i].ipv6Dns1, sEntry[i].ipv6Dns2);
		}

		// set status flag
		if (getInFlags(ifname, &flags) == 1) {
			if ((flags & IFF_UP) && (flags&IFF_RUNNING)) {
#if defined(CONFIG_GPON_FEATURE) || defined(CONFIG_EPON_FEATURE)
					if ( k!=0
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
					&&((pon_mode == GPON_MODE && onu == 5)|| (pon_mode == EPON_MODE && ret==1)) 			
#endif
#ifdef CONFIG_GPON_FEATURE
						|| (pon_mode == GPON_MODE && onu == 5 && strcmp(sEntry[i].protocol, "br1483") == 0)
#endif
#ifdef CONFIG_EPON_FEATURE
					    || (pon_mode == EPON_MODE && ret==1 && strcmp(sEntry[i].protocol, "br1483") == 0)
#endif
						)
#else
					if (strcmp(sEntry[i].protocol, "br1483") == 0
						|| k!=0)
#endif
						sEntry[i].strStatus =
						    (char *)IF_UP;
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
#if defined(CONFIG_GPON_FEATURE) || defined(CONFIG_EPON_FEATURE)
					else if ((pon_mode == GPON_MODE && onu == 5)|| (pon_mode == EPON_MODE && ret==1))			
						sEntry[i].strStatus =
							(char *)IF_CONNET;
#endif
#endif
					else
						sEntry[i].strStatus =
						    (char *)IF_DOWN;
			}
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
#if defined(CONFIG_GPON_FEATURE) || defined(CONFIG_EPON_FEATURE)
			else if ((pon_mode == GPON_MODE && onu == 5)|| (pon_mode == EPON_MODE && ret==1))			
				sEntry[i].strStatus =
					(char *)IF_CONNET;
#endif
#endif
			else
				sEntry[i].strStatus = (char *)IF_DOWN;
		} else
			sEntry[i].strStatus = (char *)IF_NA;
		
		sEntry[i].ipv6Gateway[0]='\0';
		sEntry[i].ipv6Dns1[0]='\0';
		sEntry[i].ipv6Dns2[0]='\0';
		if(sEntry[i].strStatus == IF_UP)
		{
			get_dns6_by_wan(&entry, sEntry[i].ipv6Dns1, sEntry[i].ipv6Dns2);
			
			unsigned char zero[IP6_ADDR_LEN] = {0};
			if(memcmp(entry.RemoteIpv6Addr, zero, IP6_ADDR_LEN))
				inet_ntop(AF_INET6, &entry.RemoteIpv6Addr, sEntry[i].ipv6Gateway, INET6_ADDRSTRLEN);
		}
		
		if (isPPP && strcmp(sEntry[i].strStatus, (char *)IF_UP)) {
			sEntry[i].ipv6Addr[0] = '\0';
		}
		getWanName(&entry, sEntry[i].servName);

#if defined(CONFIG_EXT_SWITCH) || defined(CONFIG_RTL_MULTI_ETH_WAN) || (defined(ITF_GROUP_1P) && defined(ITF_GROUP))
		sEntry[i].vlanId = entry.vid;
#endif

#ifdef CONFIG_IGMPPROXY_MULTIWAN
		sEntry[i].igmpEnbl = entry.enableIGMP;
#endif

#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		sEntry[i].ipv6PrefixOrigin = entry.IPv6PrefixOrigin;
		sEntry[i].addrMode = entry.AddrMode;
#endif

#if defined(IP_QOS) || defined(NEW_IP_QOS_SUPPORT)
		sEntry[i].qosEnbl = entry.enableIpQos;
#endif

		if (entry.qos == 0) {
			if (entry.svtype == 0) {
				strcpy(sEntry[i].servType, "UBR Without PCR");
			} else {
				strcpy(sEntry[i].servType, "UBR With PCR");
			}
		} else if (entry.qos == 1) {
			strcpy(sEntry[i].servType, "CBR");
		} else if (entry.qos == 2) {
			strcpy(sEntry[i].servType, "Non Realtime VBR");
		} else if (entry.qos == 3) {
			strcpy(sEntry[i].servType, "Realtime VBR");
		}

		if (entry.encap == 1) {
			strcpy(sEntry[i].encaps, "LLC");
		} else {
			strcpy(sEntry[i].encaps, "VCMUX");
		}

		//found in mit
#ifdef BR_ROUTE_ONEPVC
		if (entry.cmode == CHANNEL_MODE_BRIDGE && entry.br_route_flag == 1) {
			strcpy(sEntry[i].protocol, "br1483");
			sEntry[i].igmpEnbl = 0;
			strcpy(sEntry[i].ipv6Addr, "");
		}
#endif
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		if(entry.vprio>0)
		snprintf(vprio_str,20,"%d",(entry.vprio-1));
		else
		snprintf(vprio_str,20,"%d",0);
#endif

		if(entry.dslite_enable==1 && entry.dslite_aftr_hostname[0]!=0){
			snprintf(aftr_str,INET6_ADDRSTRLEN,"%s",entry.dslite_aftr_hostname);
		}
		else{
			snprintf(aftr_str,INET6_ADDRSTRLEN,"");
		}
		
		snprintf(MacAddr,20,"%02x:%02x:%02x:%02x:%02x:%02x",entry.MacAddr[0],entry.MacAddr[1],entry.MacAddr[2],entry.MacAddr[3],entry.MacAddr[4],entry.MacAddr[5]);
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		if(strcmp(sEntry[i].strStatus, "down") == 0){
			sEntry[i].strStatus = "未连接";
			}
		else if(strcmp(sEntry[i].strStatus, "up")==0){
			sEntry[i].strStatus = "已连接";	
			}
		else
			sEntry[i].strStatus = "连接中";	
			
		boaWrite(wp,
			  "links.push(new it_nr(\"%d\"" _PTS _PTS _PTS _PTS
			    _PTS _PTI _PTI _PTI _PTS _PTS _PTS _PTS _PTS _PTI _PTI _PTS _PTS _PTS"));\n", i,
			  __PME(sEntry[i], servName), __PME(sEntry[i], encaps),
			  __PME(sEntry[i], servType), __PME(sEntry[i], protocol),
			  __PME(sEntry[i], ipv6Addr), __PME(sEntry[i], vlanId),
			  __PME(sEntry[i], igmpEnbl), __PME(sEntry[i], qosEnbl),
			  __PME(sEntry[i], strStatus), __PME(sEntry[i], ipv6Prefix),
			  __PME(sEntry[i], ipv6Gateway), __PME(sEntry[i], ipv6Dns1),
			  __PME(sEntry[i], ipv6Dns2), __PME(sEntry[i], addrMode),
			  __PME(sEntry[i], ipv6PrefixOrigin),"vprio",vprio_str,"MacAddr",MacAddr,
			  "aftr", aftr_str
		    );
#else
		boaWrite(wp,
			  "links.push(new it_nr(\"%d\"" _PTS _PTS _PTS _PTS
			    _PTS _PTI _PTI _PTI _PTS _PTS _PTS _PTS _PTS "));\n", i,
			  __PME(sEntry[i], servName), __PME(sEntry[i], encaps),
			  __PME(sEntry[i], servType), __PME(sEntry[i], protocol),
			  __PME(sEntry[i], ipv6Addr), __PME(sEntry[i], vlanId),
			  __PME(sEntry[i], igmpEnbl), __PME(sEntry[i], qosEnbl),
			  __PME(sEntry[i], strStatus), __PME(sEntry[i], ipv6Prefix),
			  __PME(sEntry[i], ipv6Gateway), __PME(sEntry[i], ipv6Dns1),
			  __PME(sEntry[i], ipv6Dns2)
		    );
#endif
	}

	return 0;
}
#endif

#ifdef SUPPORT_WAN_BANDWIDTH_INFO
int listWanBandwidth(int eid, request * wp, int argc, char **argv)
{
	char ifname[IFNAMSIZ];
	int i, entryNum;
	MIB_CE_ATM_VC_T entry;
	char servName[MAX_WAN_NAME_LEN];
	int uploadRate, downloadRate;
	unsigned int chipId;
	unsigned int rev;
	unsigned int subType;

	#ifdef CONFIG_RTK_L34_ENABLE
	rtk_rg_switch_version_get(&chipId, &rev, &subType);
	#else
	rtk_switch_version_get(&chipId, &rev, &subType);
	#endif

	entryNum = mib_chain_total(MIB_ATM_VC_TBL);

	for (i = 0; i < entryNum; i++) {
		if (!mib_chain_get(MIB_ATM_VC_TBL, i, &entry)) {
			printf("get MIB chain error\n");
			return -1;
		}

		if((chipId != RTL9602C_CHIP_ID) && (entry.applicationtype != X_CT_SRV_INTERNET))
			continue;

		ifGetName(entry.ifIndex, ifname, sizeof(ifname));

		getWanName(&entry, servName);
		
		#ifdef CONFIG_RTK_L34_ENABLE
		if(wan_bandwidth_get(entry.rg_wan_idx, &uploadRate, &downloadRate) < 0)
		#else
		if(wan_bandwidth_get(entry.ifIndex, &uploadRate, &downloadRate) < 0)
		#endif
		{
			uploadRate = -1;
			downloadRate = -1;
		}

		boaWrite(wp,
			 "links.push(new it_nr('%d',new it('servName', '%s'), new it('upload', '%d'), new it('download', '%d')));\n",
			 i,servName, uploadRate, downloadRate);
	}
}
#endif

/*****************************
** ethers stats list
*/
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
int show_LAN_status_cmcc(int eid, request * wp, int argc, char **argv)
{	
	int i = 0 , nBytesSent = 0;
#ifdef CONFIG_RTK_L34_ENABLE
	rtk_rg_portStatusInfo_t portInfo[ELANVIF_NUM];
	memset(portInfo, 0x0, sizeof(rtk_rg_portStatusInfo_t) *ELANVIF_NUM);

	for (i = 0; i < ELANVIF_NUM; i++) 
	{
		int ret = RG_get_phyPort_status(i, &(portInfo[i]));
		if(ret != 1) // get fail
		{
			printf("%s get port %d status failed!\n", __FUNCTION__, i);
			return;
		}
		
	}		
	nBytesSent += boaWrite(wp, "<table class=\"flat\" border=\"1\" cellpadding=\"1\" cellspacing=\"1\" width=\"100%\">");
	nBytesSent += boaWrite(wp, "<tr class=\"hdb\" align=\"center\" nowrap> <td></td>");
	for(i = 0 ; i < ELANVIF_NUM ; i++)
	{
		nBytesSent += boaWrite(wp, "<td>LAN-%d</td>", (i+1));
	}
	nBytesSent += boaWrite(wp, "</tr>");
	
	nBytesSent += boaWrite(wp, "<tr align=\"center\">");
	nBytesSent += boaWrite(wp, "<td>连接状态</td>");
	for(i = 0 ; i < ELANVIF_NUM ; i++)
	{
		nBytesSent += boaWrite(wp, "<td>%s</td>",(portInfo[i].linkStatus == RTK_RG_PORT_LINKUP)?"连接上":"未连接");
	}
	nBytesSent += boaWrite(wp, "</tr>");
	
	nBytesSent += boaWrite(wp, "<tr align=\"center\">");
	nBytesSent += boaWrite(wp, "<td>工作模式</td>");
	for(i = 0 ; i < ELANVIF_NUM ; i++)
	{
		nBytesSent += boaWrite(wp, "<td>%s</td>",(portInfo[i].linkDuplex == RTK_RG_PORT_HALF_DUPLEX)?"半双工":"全双工");
	}
	nBytesSent += boaWrite(wp, "</tr>");
	
	nBytesSent += boaWrite(wp, "<tr align=\"center\">");
	nBytesSent += boaWrite(wp, "<td>速率</td>");
	for(i = 0 ; i < ELANVIF_NUM ; i++)
	{
		int speed = 0;
		switch(portInfo[i].linkSpeed)
		{
			case RTK_RG_PORT_SPEED_1000M:
				speed = 1000;
				break;
			case RTK_RG_PORT_SPEED_100M:
				speed = 100;
				break;
			case RTK_RG_PORT_SPEED_10M:
				speed = 10;
				break;
			default:
				speed = 0;
				break;
		}
		nBytesSent += boaWrite(wp, "<td>%dM</td>",speed);
	}
	nBytesSent += boaWrite(wp, "</tr>");
	
	nBytesSent += boaWrite(wp, "</tr></table>");
#endif
	return nBytesSent;
}
#else
int show_LAN_status(int eid, request * wp, int argc, char **argv)
{	
	int i = 0 , nBytesSent = 0;;
#ifdef CONFIG_RTK_L34_ENABLE
	rtk_rg_portStatusInfo_t portInfo[ELANVIF_NUM];
	memset(portInfo, 0x0, sizeof(rtk_rg_portStatusInfo_t) *ELANVIF_NUM);
	for (i = 0; i < ELANVIF_NUM; i++) 
	{
		int ret = RG_get_phyPort_status(i, &(portInfo[i]));
		if(ret != 1) // get fail
		{
			printf("%s get port %d status failed!\n", __FUNCTION__, i);
			return 0;
		}
		
	}		
	nBytesSent += boaWrite(wp, "<div align=\"left\"><b>LAN接口连接状态信息：</b></div>");
	nBytesSent += boaWrite(wp, "<table class=\"flat\" border=\"1\" cellpadding=\"1\" cellspacing=\"1\" width=\"100%\">");
	nBytesSent += boaWrite(wp, "<tr class=\"hdb\" align=\"center\" nowrap> <td>接口</td> <td>连接状态</td> <td>工作模式</td><td>速率</td> </tr>");
	
	for(i = 0 ; i < ELANVIF_NUM ; i++)
	{
		nBytesSent += boaWrite(wp, "<tr align=\"center\">");
		nBytesSent += boaWrite(wp, "<td>端口_%d</td>",(i+1));
		nBytesSent += boaWrite(wp, "<td>%s</td>",(portInfo[i].linkStatus == RTK_RG_PORT_LINKUP)?"连接上":"未连接");		
		nBytesSent += boaWrite(wp, "<td>%s</td>",(portInfo[i].linkDuplex == RTK_RG_PORT_HALF_DUPLEX)?"半双工":"全双工");
		int speed = 0;
		switch(portInfo[i].linkSpeed)
		{
			case RTK_RG_PORT_SPEED_1000M:
				speed = 1000;
				break;
			case RTK_RG_PORT_SPEED_100M:
				speed = 100;
				break;
			case RTK_RG_PORT_SPEED_10M:
				speed = 10;
				break;
			default:
				speed = 0;
				break;
		}
		nBytesSent += boaWrite(wp, "<td>%dM</td>",speed);
		nBytesSent += boaWrite(wp, "</tr>");
	}
	
	nBytesSent += boaWrite(wp, "</tr></table>");
#endif
	return nBytesSent;
}
#endif

int E8BPktStatsList(int eid, request * wp, int argc, char ** argv)
{
	int i, nBytesSent = 0;
	struct net_device_stats nds;

#ifndef CONFIG_RTK_L34_ENABLE
	for (i = 0; i < ELANVIF_NUM; i++) {
		get_net_device_stats(ELANVIF[i], &nds);
		nBytesSent += boaWrite(wp, "ethers.push(new it_nr(\"%d\""
				", new it(\"%s\", \"端口_%d\")" _PTUL _PTUL
				_PTUL _PTUL _PTUL
				_PTUL _PTUL _PTUL "));\n",
			  i, "ifname", i+1,
			  "rx_packets", nds.rx_packets,
			  "rx_bytes", nds.rx_bytes,
			  "rx_errors", nds.rx_errors,
			  "rx_dropped", nds.rx_dropped,
			  "tx_packets", nds.tx_packets,
			  "tx_bytes", nds.tx_bytes,
			  "tx_errors", nds.tx_errors,
			  "tx_dropped", nds.tx_dropped);
	}
#else // use rg api to retrive switch level packet counter
	unsigned long tx_pkts,tx_drops,tx_errs,rx_pkts,rx_drops,rx_errs;
	unsigned long long int tx_bytes,rx_bytes;

#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	unsigned long total_tx_pkts=0,total_tx_drops=0,total_tx_errs=0,total_rx_pkts=0,total_rx_drops=0,total_rx_errs=0;
	unsigned long long int total_tx_bytes=0,total_rx_bytes=0;
#endif
	for(i = 0 ; i < ELANVIF_NUM; i++)
	{
		if(RG_get_portCounter(i,&tx_bytes,&tx_pkts,&tx_drops,&tx_errs,&rx_bytes,&rx_pkts,&rx_drops,&rx_errs) == 0 ){
			// get fail , assign all counter to 0
			tx_pkts = tx_drops = tx_errs = rx_pkts = rx_drops = rx_errs = 0;
			tx_bytes = rx_bytes = 0;
		}
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		total_tx_pkts += tx_pkts;
		total_tx_drops += tx_drops;
		total_tx_errs += tx_errs;
		total_rx_pkts += rx_pkts;
		total_rx_drops += rx_drops;
		total_rx_errs += rx_errs;
		total_tx_bytes += tx_bytes;
		total_rx_bytes += rx_bytes;
#else
		nBytesSent += boaWrite(wp, "ethers.push(new it_nr(\"%d\""
				", new it(\"%s\", \"端口_%d\")" _PTUL _PTULL
				_PTUL _PTUL _PTUL
				_PTULL _PTUL _PTUL "));\n",
			  i, "ifname", i+1,
			  "rx_packets", rx_pkts,
			  "rx_bytes", rx_bytes,
			  "rx_errors", rx_errs,
			  "rx_dropped", rx_drops,
			  "tx_packets", tx_pkts,
			  "tx_bytes", tx_bytes,
			  "tx_errors", tx_errs,
			  "tx_dropped", tx_drops);
#endif
	}
#endif

#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	i=0;
	nBytesSent += boaWrite(wp, "ethers.push(new it_nr(\"%d\""
				", new it(\"%s\", \"%s\")" _PTUL _PTULL
				_PTUL _PTUL _PTUL
				_PTULL _PTUL _PTUL "));\n",
			  i, "ifname", "Ethernet",
			  "rx_packets", total_rx_pkts,
			  "rx_bytes", total_rx_bytes,
			  "rx_errors", total_rx_errs,
			  "rx_dropped", total_rx_drops,
			  "tx_packets", total_tx_pkts,
			  "tx_bytes", total_tx_bytes,
			  "tx_errors", total_tx_errs,
			  "tx_dropped", total_tx_drops);
#endif

	return nBytesSent;
}

#if  defined(CONFIG_USER_LAN_BANDWIDTH_MONITOR) && defined(CONFIG_USER_LANNETINFO)
int initPageLanBandwidthMonitor(int eid, request * wp, int argc, char ** argv)
{
	lanHostInfo_t *pLanNetInfo=NULL;
	unsigned char macString[32]={0};
	unsigned int count=0;
	int ret=-1, idx;

	ret = get_lan_net_info(&pLanNetInfo, &count);
	if(ret<0)
		goto end;

	for(idx=0; idx<count; idx++)
	{
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		get_attach_device_name(pLanNetInfo[idx].mac, pLanNetInfo[idx].devName);
#endif

		memset(macString, 0, 32);
		changeMacToString(pLanNetInfo[idx].mac, macString);
		fillcharZeroToMacString(macString);

		boaWrite (wp, "push(new it_nr(\"%d\"" _PTS _PTI _PTI"));\n", idx,
			"mac", macString, "cur_usBand", pLanNetInfo[idx].upRate, "cur_dsBand", pLanNetInfo[idx].downRate);
	}

end:
	if(pLanNetInfo)
		free(pLanNetInfo);

	return ret;
}

#endif

unsigned char *ipAssignChineseString[2] = {
	"静态分配",
	"动态分配"
};

#ifdef CONFIG_USER_LANNETINFO

#define LANNETINFOFILE	"/var/lannetinfo"
#define LANNETINFO_RUNFILE	"/var/run/lannetinfo.pid"


unsigned char *devTypeString[5] = {
	"OTHER",
	"Phone",
	"PC",
	"Pad",
	"STB",
};

unsigned char *connectionTypeString[2] = {
	"Ethernet",
	"Wifi"
};

unsigned char *connectionTypeChineseString[2] = {
	"有线",
	"无线"
};

int initPageLanNetInfo(int eid, request * wp, int argc, char ** argv)
{
	lanHostInfo_t *pLanNetInfo=NULL;
	unsigned char macString[32]={0};
	struct in_addr lanIP;
	unsigned int count=0;
	int ret=-1, idx;

	ret = get_lan_net_info(&pLanNetInfo, &count);
	if(ret<0)
		goto end;

	for(idx=0; idx<count; idx++)
	{
		memset(macString, 0, 32);
		changeMacToString(pLanNetInfo[idx].mac, macString);
		fillcharZeroToMacString(macString);
		lanIP.s_addr = pLanNetInfo[idx].ip;

		boaWrite (wp, "push(new it_nr(\"%d\""_PTS _PTS _PTS _PTS _PTS _PTI _PTS _PTS _PTS _PTI _PTS _PTS"));\n", idx,
			"devName", pLanNetInfo[idx].devName, "devType", devTypeString[pLanNetInfo[idx].devType],"brand", pLanNetInfo[idx].brand, "model", pLanNetInfo[idx].model,
			"OS", pLanNetInfo[idx].os, "port", pLanNetInfo[idx].port, "mac", macString, "ip", inet_ntoa(lanIP), "connectionType", connectionTypeString[pLanNetInfo[idx].connectionType],
			"onlineTime", pLanNetInfo[idx].onLineTime, "latestActiveTime", pLanNetInfo[idx].latestActiveTime,
			"latestInactiveTime", pLanNetInfo[idx].latestInactiveTime);
	}

end:
	if(pLanNetInfo)
		free(pLanNetInfo);

	return ret;
}

#endif

#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
/*****************************
** devices list
*/
int E8BLanDevList(int eid, request * wp, int argc, char ** argv)
{
#ifdef EMBED
	char ipAddr[INET_ADDRSTRLEN], tmpipAddr[INET_ADDRSTRLEN], macAddr[20], liveTime[80], devname[MAX_NAME_LEN], conType[10], ipAssign[20], *buf = NULL, *ptr;
#if (defined (CONFIG_YUEME) || defined (CONFIG_CMCC) || defined(CONFIG_CU)) && defined (CONFIG_USER_LANNETINFO)
	lanHostInfo_t *pLanNetInfo=NULL;
#else
	DHCPS_SERVING_POOL_T dhcppoolentry;
#endif
	char lanHostMac[20];
	FILE *fp;
	int i, entryNum, ret, pid, cnt;
	struct stat status;
	unsigned int ipVal = 0;
	unsigned long leaseFileSize;
	unsigned long FileSize;

	// siganl DHCP server to update lease file
	pid = read_pid(DHCPSERVERPID);
	if (pid > 0) {
		kill(pid, SIGUSR1);
		usleep(1000);
	}

	if (stat(DHCPD_LEASE, &status) < 0)
		goto err;

	// read DHCP server lease file
	leaseFileSize = (unsigned long)(status.st_size);
	buf = malloc(leaseFileSize);
	if (buf == NULL)
		goto err;

	fp = fopen(DHCPD_LEASE, "r");

	if (fp == NULL)
		goto err;

	fread(buf, leaseFileSize, 1, fp);
	fclose(fp);

#if (defined (CONFIG_YUEME) || defined (CONFIG_CMCC) || defined(CONFIG_CU)) && defined (CONFIG_USER_LANNETINFO)
	ret = get_lan_net_info(&pLanNetInfo, &entryNum);
	if(ret<0)
			goto err;
#else
	entryNum = mib_chain_total(MIB_DHCPS_SERVING_POOL_TBL);
#endif

	cnt = 0;

	for(i=0; i < entryNum; i++){
#if (defined (CONFIG_YUEME) || defined (CONFIG_CMCC) || defined(CONFIG_CU)) && defined (CONFIG_USER_LANNETINFO)
		snprintf(macAddr, 20, "%02x:%02x:%02x:%02x:%02x:%02x",
				pLanNetInfo[i].mac[0], pLanNetInfo[i].mac[1],pLanNetInfo[i].mac[2],pLanNetInfo[i].mac[3],
				pLanNetInfo[i].mac[4], pLanNetInfo[i].mac[5]);
		get_attach_device_name(pLanNetInfo[i].mac, pLanNetInfo[i].devName);
		strcpy(devname, pLanNetInfo[i].devName);
		inet_ntop(AF_INET, &(pLanNetInfo[i].ip), ipAddr, INET_ADDRSTRLEN);
		sprintf(conType, connectionTypeChineseString[pLanNetInfo[i].connectionType]);
#endif

		strcpy(ipAssign, ipAssignChineseString[0]);
		ptr = buf;
		FileSize = leaseFileSize;
		while (1) {
			ret = getOneDhcpClient(&ptr, &FileSize, tmpipAddr, lanHostMac, liveTime);
			/* lijian: 20080904 END */
			//printf("%s:%d macAddr %s, lanHostMac %s\n", __FUNCTION__, __LINE__, macAddr, lanHostMac);
			if (ret < 0)
				break;
			if (ret == 0)
				continue;

			//printf("%s:%d macAddr %s, lanHostMac %s\n", __FUNCTION__, __LINE__, macAddr, lanHostMac);
			if( 0 == strcmp(macAddr, lanHostMac) ){
				//printf("%s:%d macAddr %s is dynamic\n", __FUNCTION__, __LINE__, macAddr);
				strcpy(ipAssign, ipAssignChineseString[1]);
				break;
			}
			else
				snprintf(liveTime, 10, "%lu", 0);
		}
		boaWrite(wp, "clts.push(new it_nr(\"%d\"" _PTS _PTS _PTS _PTS _PTS _PTS "));\n",
			  i, _PMEX(devname), _PMEX(macAddr), _PMEX(ipAddr), _PMEX(liveTime), _PMEX(conType), _PMEX(ipAssign));
	}

err:
#if (defined (CONFIG_YUEME) || defined (CONFIG_CMCC) || defined(CONFIG_CU)) && defined (CONFIG_USER_LANNETINFO)
	if(pLanNetInfo)
		free(pLanNetInfo);
#endif
	if (buf)
		free(buf);

	return 0;
#else
	return 0;
#endif
}
#else
/*****************************
** devices list
*/
int E8BDhcpClientList(int eid, request * wp, int argc, char ** argv)
{
#ifdef EMBED
	char ipAddr[INET_ADDRSTRLEN], macAddr[20], liveTime[10], devname[MAX_NAME_LEN], *buf = NULL, *ptr;
#if defined (CONFIG_YUEME) && defined (CONFIG_USER_LANNETINFO)
	lanHostInfo_t *pLanNetInfo=NULL;
	char lanHostMac[20];
#else
	DHCPS_SERVING_POOL_T dhcppoolentry;
#endif
	FILE *fp;
	int i, entryNum, ret, pid, cnt;
	struct stat status;
	unsigned int ipVal = 0;
	unsigned long leaseFileSize;
	int lockfd = -1;

	// siganl DHCP server to update lease file
	pid = read_pid(DHCPSERVERPID);
	if (pid > 0) {
		kill(pid, SIGUSR1);
		usleep(1000);
	}

	if ((lockfd = lock_file_by_flock(DHCPSERVERPID, 0)) == -1)
	{
		printf("%s, the file have been locked\n", __FUNCTION__);
		goto err;
	}

	if (stat(DHCPD_LEASE, &status) < 0)
		goto err;

	// read DHCP server lease file
	leaseFileSize = (unsigned long)(status.st_size);
	buf = malloc(leaseFileSize);
	if (buf == NULL)
		goto err;

	fp = fopen(DHCPD_LEASE, "r");

	if (fp == NULL)
		goto err;

	fread(buf, leaseFileSize, 1, fp);
	fclose(fp);
	ptr = buf;

#if defined (CONFIG_YUEME) && defined (CONFIG_USER_LANNETINFO)
	ret = get_lan_net_info(&pLanNetInfo, &entryNum);
	if(ret<0)
			goto err;
#else
	entryNum = mib_chain_total(MIB_DHCPS_SERVING_POOL_TBL);
#endif

	cnt = 0;

	while (1) {
		ret = getOneDhcpClient(&ptr, &leaseFileSize, ipAddr, macAddr, liveTime);
		/* lijian: 20080904 END */

		if (ret < 0)
			break;
		if (ret == 0)
			continue;

		inet_aton(ipAddr, (struct in_addr *)&ipVal);

		for (i = 0; i < entryNum; i++) {
			memset(&devname, 0, sizeof(devname));
#if defined (CONFIG_YUEME) && defined (CONFIG_USER_LANNETINFO)
			memset(lanHostMac, 0, 20);
			snprintf(lanHostMac, 20, "%02x:%02x:%02x:%02x:%02x:%02x",
				pLanNetInfo[i].mac[0], pLanNetInfo[i].mac[1],pLanNetInfo[i].mac[2],pLanNetInfo[i].mac[3],
				pLanNetInfo[i].mac[4], pLanNetInfo[i].mac[5]);

			if( 0 == strcmp(macAddr, lanHostMac) )
			{
				strcpy(devname, devTypeString[pLanNetInfo[i].devType]);
				break;
			}
#else
			if (!mib_chain_get
				(MIB_DHCPS_SERVING_POOL_TBL, i,
				(void *)&dhcppoolentry))
				continue;
			
			if (ipVal >= *(unsigned int *)dhcppoolentry.startaddr
			&& ipVal <=
			*(unsigned int *)dhcppoolentry.endaddr) {
			strcpy(devname, dhcppoolentry.poolname);
				break;
			}
#endif
		}//end of for
		
		boaWrite(wp, "clts.push(new it_nr(\"%d\"" _PTS _PTS _PTS _PTS "));\n",
			  cnt, _PMEX(devname), _PMEX(macAddr), _PMEX(ipAddr), _PMEX(liveTime));
		cnt++;
	}

err:
#if defined (CONFIG_YUEME) && defined (CONFIG_USER_LANNETINFO)
	if(pLanNetInfo)
		free(pLanNetInfo);
#endif
	if (buf)
		free(buf);

	if(-1 != lockfd)
		unlock_file_by_flock(lockfd);

	return 0;
#else
	return 0;
#endif
}
#endif
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
int getWANItfArray(int eid, request * wp, int argc, char **argv){

	MIB_CE_ATM_VC_T entry;
	int entryNum = 0;
	int i=0;
	struct wan_status_info sEntry[MAX_VC_NUM + MAX_PPP_NUM] = { 0 };

	entryNum = mib_chain_total(MIB_ATM_VC_TBL);
	for (i = 0; i < entryNum; i++) {
		if (!mib_chain_get(MIB_ATM_VC_TBL, i, &entry)) {
			printf("get MIB chain error\n");
			return -1;
		}

		getWanName(&entry, sEntry[i].servName);
		boaWrite(wp,"[%u,\"%s\",0,0]",entry.ifIndex, sEntry[i].servName);
		if(i!=(entryNum-1)){
			boaWrite(wp,",",entry.ifIndex, sEntry[i].servName);
		}

	}
	return 0;
}
#endif

