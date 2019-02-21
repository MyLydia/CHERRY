/*
 *      Web server handler routines for IP QoS
 *
 */

/*-- System inlcude files --*/
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/wait.h>

#include "../webs.h"
#include "webform.h"
#include "mib.h"
#include "utility.h"

#ifdef EMBED
#include <linux/config.h>
#else
#include "../../../uClibc/include/linux/autoconf.h"
#endif

#undef QOS_DEBUG
static int function_print = 1;
static int debug_print    = 1;

#define QUEUE_RULE_NUM_MAX     256
#define TRAFFICTL_RULE_NUM_MAX 256
#define INF_NAME_MAX           32

#define DELIM      '&'
#define SUBDELIM   '|'
#define SUBDELIM1  "|"

//print debug information
#ifdef QOS_DEBUG
#define PRINT_FUNCTION do{ if(function_print) printf("%s: %s\n", __FILE__, __FUNCTION__);}while(0);
#define QOS_DEBUG(fmt, args...) do{if(debug_print) printf("QOS DEBUG: " fmt, ##args);}while(0)

#define  PRINT_QUEUE(pEntry)  \
    printf("[QUEUE]: ifIndex:%d, ifname:%s, desc:%s, prio:%d, queueKey:%d, enable:%d\n",  \
	    pEntry->ifIndex, pEntry->ifname, pEntry->desc, pEntry->prio, pEntry->queueKey, pEntry->enable);

#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
#define PRINT_QUEUE_RULE(pEntry)  \
   printf("[QUEUE RULE]: ifidx:0x%x, name:%s, state:%d, prio:%d, mark dscp:0x%02x,\n"      \
	"mark 8021p:%d, dscp:0x%02x, tos:0x%02x, vlan 8021p:%d, phyPort:%d, prototype:%d, "	\
	  "srcip:%s, smaskbits:%d, dstip:%s, dmaskbits:%d, src port:%d-%d, dst port:%d-%d, connection_type:%d\n", 			\
	   pEntry->outif, pEntry->RuleName, pEntry->enable, pEntry->prior, \
	   pEntry->m_dscp, pEntry->m_1p, pEntry->qosDscp, pEntry->tos,pEntry->vlan1p, pEntry->phyPort, pEntry->protoType,  \
	   inet_ntoa(*((struct in_addr*)&pEntry->sip)), pEntry->smaskbit, \
	   inet_ntoa(*((struct in_addr*)&pEntry->dip)), pEntry->dmaskbit, pEntry->sPort,          \
	   pEntry->sPortRangeMax, pEntry->dPort, pEntry->dPortRangeMax, pEntry->applicationtype);
#else
#define PRINT_QUEUE_RULE(pEntry)  \
   printf("[QUEUE RULE]: ifidx:0x%x, name:%s, state:%d, prio:%d, mark dscp:0x%02x,\n"      \
	  "mark 8021p:%d, dscp:0x%02x, vlan 8021p:%d, phyPort:%d, prototype:%d, "    \
	  "srcip:%s, smaskbits:%d, dstip:%s, dmaskbits:%d, src port:%d-%d, dst port:%d-%d, connection_type:%d\n", 			\
	   pEntry->outif, pEntry->RuleName, pEntry->enable, pEntry->prior, \
	   pEntry->m_dscp, pEntry->m_1p, pEntry->qosDscp, pEntry->vlan1p, pEntry->phyPort, pEntry->protoType,  \
	   inet_ntoa(*((struct in_addr*)&pEntry->sip)), pEntry->smaskbit, \
	   inet_ntoa(*((struct in_addr*)&pEntry->dip)), pEntry->dmaskbit, pEntry->sPort,          \
	   pEntry->sPortRangeMax, pEntry->dPort, pEntry->dPortRangeMax, pEntry->applicationtype);
#endif

#define PRINT_TRAFFICTL_RULE(pEntry) \
    printf("[TRAFFIC CONTROL]: entryid:%d, ifIndex:%d, srcip:%s, smaskbits:%d, dstip:%s, dmaskbits:%d,"  \
	   "sport:%d, dport%d, protoType:%d, limitspeed:%d\n",                                                      \
	    pEntry->entryid, pEntry->ifIndex, inet_ntoa(*((struct in_addr*)&pEntry->srcip)),        \
	    pEntry->smaskbits, inet_ntoa(*((struct in_addr*)&pEntry->dstip)), pEntry->dmaskbits,                    \
	    pEntry->sport, pEntry->dport, pEntry->protoType, pEntry->limitSpeed);

#else

#define PRINT_FUNCTION do{}while(0);
#define QOS_DEBUG(fmt, args...) do{}while(0)
#define PRINT_QUEUE(pEntry)
#define PRINT_QUEUE_RULE(pEntry)
#define PRINT_TRAFFICTL_RULE(pEntry)

#endif

//show the wan interface list, using js code, must have waniflist array in js code
int ifWanList_tc(int eid, request * wp, int argc, char **argv)
{
	MIB_CE_ATM_VC_T entry;
	int entryNum = 0, i=0, nBytes = 0;
	char wanif[IFNAMSIZ] = {0};

	PRINT_FUNCTION

	entryNum = mib_chain_total(MIB_ATM_VC_TBL);
	QOS_DEBUG("Total entry num:%d\n", entryNum);

	//default
	nBytes += boaWrite(wp, "waniflst.add(new it(\" \", \" \"));");

	for(i=0;i<entryNum;i++)
	{
		// Kaohj --- E8 don't care enableIpQos.
		if(!mib_chain_get(MIB_ATM_VC_TBL, i, &entry)||!entry.enableIpQos)
		//if(!mib_chain_get(MIB_ATM_VC_TBL, i, &entry))
		    continue;

		//getWanName(&entry, wanif);
		ifGetName(entry.ifIndex, wanif, sizeof(wanif));
#ifndef BR_ROUTE_ONEPVC
		nBytes += boaWrite(wp, "waniflst.add(new it(\"%d|%s\", \"%s\"));",
			entry.ifIndex, wanif, wanif);
#else
		nBytes += boaWrite(wp, "waniflst.add(new it(\"%d|%d|%s\", \"%s\"));",
			entry.ifIndex, entry.cmode, wanif, wanif);
#endif
	}

	return nBytes;
}

int initQosLanif(int eid, request * wp, int argc, char **argv)
{
	int i;
	int nBytes = 0;
	
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
#ifdef WLAN_SUPPORT
	MIB_CE_MBSSIB_T entry;
#ifdef WLAN_DUALBAND_CONCURRENT
	int orig_idx = wlan_idx;
#endif
#endif	

	for (i=0; i < SW_LAN_PORT_NUM; i++) {
		nBytes += boaWrite(wp, "iffs.add(new it(\"%d\", \"LAN%d\"));\n", i+1, i+1);
	}
#ifdef WLAN_SUPPORT
	for(i=1; i<=WLAN_SSID_NUM; i++){
#ifdef WLAN_DUALBAND_CONCURRENT
		wlan_idx = 0;
#endif
		mib_chain_get(MIB_MBSSIB_TBL, i-1, &entry);
		if(entry.wlanDisabled==0)
			nBytes += boaWrite(wp, "iffs.add(new it(\"%d\", \"SSID%d\"));\n", SW_LAN_PORT_NUM+i,i);
	}
#ifdef WLAN_DUALBAND_CONCURRENT
	for(i=1; i<=WLAN_SSID_NUM; i++){
		wlan_idx = 1;
		mib_chain_get(MIB_MBSSIB_TBL, i-1, &entry);
		if(entry.wlanDisabled==0)
			nBytes += boaWrite(wp, "iffs.add(new it(\"%d\", \"SSID%d\"));\n", SW_LAN_PORT_NUM+i+WLAN_SSID_NUM ,i+WLAN_SSID_NUM);
	}
	wlan_idx = orig_idx;	
#endif
#endif
#else	
	for (i=0; i < SW_LAN_PORT_NUM; i++) {
		nBytes += boaWrite(wp, "iffs.add(new it(%d, \"LAN_%d\"));\n", i+1, i+1);
	}
#endif
	return nBytes;
}

#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
int initQosTypeLanif(int eid, request * wp, int argc, char **argv)
{
	int i;
	int nBytes = 0;
	
#ifdef WLAN_SUPPORT
	MIB_CE_MBSSIB_T entry;
#ifdef WLAN_DUALBAND_CONCURRENT
	int orig_idx = wlan_idx;
#endif
#endif	
	int lanItfNum = 0;
	for (i=0; i < SW_LAN_PORT_NUM; i++) {
		nBytes += boaWrite(wp, "LanList[%d]=new stLan(\"%d\", \"LAN%d\");\n", lanItfNum++,i+1, i+1);
	}
#ifdef WLAN_SUPPORT
	for(i=1; i<=WLAN_SSID_NUM; i++){
#ifdef WLAN_DUALBAND_CONCURRENT
		wlan_idx = 0;
#endif
		mib_chain_get(MIB_MBSSIB_TBL, i-1, &entry);
		if(entry.wlanDisabled==0)
			nBytes += boaWrite(wp, "LanList[%d]=new stLan(\"%d\", \"SSID%d\");\n", lanItfNum++,SW_LAN_PORT_NUM+i,i);
	}
#ifdef WLAN_DUALBAND_CONCURRENT
	for(i=1; i<=WLAN_SSID_NUM; i++){
		wlan_idx = 1;
		mib_chain_get(MIB_MBSSIB_TBL, i-1, &entry);
		if(entry.wlanDisabled==0)
			nBytes += boaWrite(wp, "LanList[%d]=new stLan(\"%d\", \"SSID%d\");\n", lanItfNum++,SW_LAN_PORT_NUM+i+WLAN_SSID_NUM ,i+WLAN_SSID_NUM);
	}
	wlan_idx = orig_idx;	
#endif
#endif
	return nBytes;
}

#endif
int initOutif(int eid, request * wp, int argc, char **argv)
{
	MIB_CE_ATM_VC_T vcEntry;
	int entryNum, i, j, nBytes = 0;
	//char wanif[MAX_WAN_NAME_LEN]={0};
	char wanif[IFNAMSIZ]={0};
#ifdef BR_ROUTE_ONEPVC
	unsigned char pvcmode;
#endif
	PRINT_FUNCTION

	entryNum = mib_chain_total(MIB_ATM_VC_TBL);

	for(i=0; i<entryNum; i++)
	{
		// Kaohj --- E8 don't care enableIpQos.
		//if(!mib_chain_get(MIB_ATM_VC_TBL, i, &vcEntry)||!vcEntry.enableIpQos)
		if(!mib_chain_get(MIB_ATM_VC_TBL, i, &vcEntry))
			continue;

		//getWanName(&vcEntry, wanif);
		ifGetName(vcEntry.ifIndex, wanif, sizeof(wanif));
#ifdef BR_ROUTE_ONEPVC
		pvcmode = vcEntry.cmode;
#endif

#ifdef BR_ROUTE_ONEPVC
		nBytes += boaWrite(wp, "oifkeys.add(new it(\"%d|%d\", \"%s\"));\n",
			vcEntry.ifIndex, pvcmode, wanif);
#else
		nBytes += boaWrite(wp, "oifkeys.add(new it(\"%d\", \"%s\"));\n",
			vcEntry.ifIndex, wanif);
#endif
	}
	return nBytes;
}

int initConnType(int eid, request * wp, int argc, char **argv)
{
	int nBytes = 0;

	PRINT_FUNCTION

#ifdef CONFIG_YUEME
	nBytes += boaWrite(wp, "connTypes.push(\"\");");
	nBytes += boaWrite(wp, "connTypes.push(\"TR069_INTERNET\");");
	nBytes += boaWrite(wp, "connTypes.push(\"INTERNET\");");
	nBytes += boaWrite(wp, "connTypes.push(\"TR069\");");
	nBytes += boaWrite(wp, "connTypes.push(\"Other\");");
	nBytes += boaWrite(wp, "connTypes.push(\"VOICE\");");
	nBytes += boaWrite(wp, "connTypes.push(\"TR069_VOICE\");");
	nBytes += boaWrite(wp, "connTypes.push(\"VOICE_INTERNET\");");
	nBytes += boaWrite(wp, "connTypes.push(\"TR069_VOICE_INTERNET\");");
	nBytes += boaWrite(wp, "connTypes.push(\"SPECIAL_SERVICE_1\");");
	nBytes += boaWrite(wp, "connTypes.push(\"SPECIAL_SERVICE_2\");");
	nBytes += boaWrite(wp, "connTypes.push(\"SPECIAL_SERVICE_3\");");
	nBytes += boaWrite(wp, "connTypes.push(\"SPECIAL_SERVICE_4\");");
#else
	nBytes += boaWrite(wp, "connTypes.push(\"\");");
	nBytes += boaWrite(wp, "connTypes.push(\"TR069_INTERNET\");");
	nBytes += boaWrite(wp, "connTypes.push(\"INTERNET\");");
	nBytes += boaWrite(wp, "connTypes.push(\"TR069\");");
	nBytes += boaWrite(wp, "connTypes.push(\"Other\");");
	nBytes += boaWrite(wp, "connTypes.push(\"VOICE\");");
	nBytes += boaWrite(wp, "connTypes.push(\"TR069_VOICE\");");
	nBytes += boaWrite(wp, "connTypes.push(\"VOICE_INTERNET\");");
	nBytes += boaWrite(wp, "connTypes.push(\"TR069_VOICE_INTERNET\");");
#endif

	return nBytes;
}

int initRulePriority(int eid, request * wp, int argc, char **argv)
{
	int j, nBytes = 0;

	PRINT_FUNCTION
	int qEntryNum = mib_chain_total(MIB_IP_QOS_QUEUE_TBL);
    // only show priority. The entryNum +1 is priority.
	for (j=1; j<=qEntryNum; j++)
		nBytes += boaWrite(wp, "quekeys.add(new it(\"%d\", \"Queue %d\"));\n", j , j);
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	if(qEntryNum<8){
		for (j=qEntryNum; j<=8; j++)
			nBytes += boaWrite(wp, "quekeys.add(new it(\"%d\", \"Queue %d\"));\n", j , j);
	}
#endif
	return nBytes;
}

char* netmaskbits2str(const int netmaskbit, char* netmaskstr, int strlen)
{
	unsigned int netmaskaddr = 0, i=0;

	if(!netmaskstr || !netmaskbit)
		return NULL;
	for(i=0;i<netmaskbit;i++)
		netmaskaddr = netmaskaddr|(0x80000000>>i);
	netmaskaddr = htonl(netmaskaddr);//host byte order to network byte order
	strncpy(netmaskstr, inet_ntoa(*(struct in_addr*)&netmaskaddr), strlen );

	return netmaskstr;
}

int generateAppTypeStr(unsigned int apptype, char* wanname)
{
	unsigned int tmp_apptype;
	
	if(wanname==NULL)
		return -1;

	if(!apptype){
		sprintf(wanname, "none");
		return 0;
	}

	tmp_apptype = apptype;

	if (tmp_apptype&X_CT_SRV_TR069){
		strcat(wanname, "TR069");
		tmp_apptype &= ~X_CT_SRV_TR069;
		if(tmp_apptype)
			strcat(wanname, "_");
	}	
	
	
#ifdef CONFIG_USER_RTK_VOIP
	if (tmp_apptype&X_CT_SRV_VOICE){
		strcat(wanname, "VOICE");
		tmp_apptype &= ~X_CT_SRV_VOICE;
		if(tmp_apptype)
			strcat(wanname, "_");
	}	
	
#endif

#ifdef CONFIG_YUEME
	if (tmp_apptype&X_CT_SRV_INTERNET)
		strcat(wanname, "INTERNET");
	if (tmp_apptype&X_CT_SRV_OTHER)
		strcat(wanname, "Other");
	if (tmp_apptype&X_CT_SRV_SPECIAL_SERVICE_1)
		strcat(wanname, "SPECIAL_SERVICE_1");
	if (tmp_apptype&X_CT_SRV_SPECIAL_SERVICE_2)
		strcat(wanname, "SPECIAL_SERVICE_2");
	if (tmp_apptype&X_CT_SRV_SPECIAL_SERVICE_3)
		strcat(wanname, "SPECIAL_SERVICE_3");
	if (tmp_apptype&X_CT_SRV_SPECIAL_SERVICE_4)
		strcat(wanname, "SPECIAL_SERVICE_4");
#endif

	return 0;
}

unsigned int getMibApplicationType(unsigned int web_apptype)
{
	unsigned int mib_apptype=0;
	
	switch( web_apptype )
	{
		//("", "TR069_INTERNET", "INTERNET", "TR069", "Other", "Voice", "TR069_Voice", "Voice_INTERNET", "TR069_Voice_INTERNET", "SPECIAL_SERVICE_1", "SPECIAL_SERVICE_2", "SPECIAL_SERVICE_3", "SPECIAL_SERVICE_4")
		//TR069(1), INTERNET(2), IPTV(4), VOICE(8), SPECIAL_SERVICE_1(16), SPECIAL_SERVICE_2(32), SPECIAL_SERVICE_3(64), SPECIAL_SERVICE_4(128)
		case 0:
			mib_apptype = 0;
			break;
		case 1:
			mib_apptype = (X_CT_SRV_TR069|X_CT_SRV_INTERNET);
			break;
		case 2:
			mib_apptype = X_CT_SRV_INTERNET;
			break;
		case 3:
			mib_apptype = X_CT_SRV_TR069;
			break;
		case 4:
			mib_apptype = (X_CT_SRV_OTHER);
			break;
		case 5:
			mib_apptype = (X_CT_SRV_VOICE);
			break;
		case 6:
			mib_apptype = (X_CT_SRV_TR069|X_CT_SRV_VOICE);
			break;
		case 7:
			mib_apptype = (X_CT_SRV_VOICE|X_CT_SRV_INTERNET);
			break;
		case 8:
			mib_apptype = (X_CT_SRV_TR069|X_CT_SRV_VOICE|X_CT_SRV_INTERNET);
			break;
#ifdef CONFIG_YUEME
		case 9:
			mib_apptype = X_CT_SRV_SPECIAL_SERVICE_1;
			break;
		case 10:
			mib_apptype = X_CT_SRV_SPECIAL_SERVICE_2;
			break;
		case 11:
			mib_apptype = X_CT_SRV_SPECIAL_SERVICE_3;
			break;
		case 12:
			mib_apptype = X_CT_SRV_SPECIAL_SERVICE_4;
			break;
#endif
		default:
			mib_apptype = 0;
	}

	return mib_apptype;
}

unsigned int getWebApplicationType(unsigned int mib_apptype)
{
	int i;

	for(i=0 ; i<=12 ; i++)
	{
		if(mib_apptype == getMibApplicationType(i)){
			return i;
		}
	}

	return 0;
}

/******************************************************************
 * NAME:    intPageQosRule
 * DESC:    initialize the qos rules by reading mib setting and
 *          format them to send them to webs to dispaly
 * ARGS:
 * RETURN:
 ******************************************************************/
int initQosRulePage(int eid, request * wp, int argc, char **argv)
{
	MIB_CE_IP_QOS_T qEntry;
	MIB_CE_ATM_VC_T       vcEntry;
	char saddr[16]={0}, daddr[16]={0}, smask[16]={0}, dmask[16]={0};
	char smacaddr[20], dmacaddr[20];
	int i=0, qEntryNum = 0, vcEntryNum = 0, nBytes = 0;
	char wanifname[16]={0};
#ifdef CONFIG_IPV6
	unsigned char 	sip6Str[48]={0}, dip6Str[48]={0};
#endif

#ifdef CONFIG_BRIDGE_EBT_DHCP_OPT
	char duid_mac[20]={0};
#endif
	char apptypestr[48]={0};
	unsigned int apptype = 0;
	unsigned char phyPort=0;

	PRINT_FUNCTION

	//get number of  ip qos queue rules, if none, or cannot get, return
	if((qEntryNum=mib_chain_total(MIB_IP_QOS_TBL)) <=0)
		return -1;

	if((vcEntryNum=mib_chain_total(MIB_ATM_VC_TBL)) <=0)
		return -1;

	for(i=0;i<qEntryNum; i++)
	{
		char phyportName[8] = {0};
		if(!mib_chain_get(MIB_IP_QOS_TBL, i, (void*)&qEntry))
			continue;

		if(qEntry.modeTr69 == MODEVOIP || qEntry.modeTr69 == MODETR069)
			continue;

		//src addr
		snprintf(saddr, 16, "%s", inet_ntoa(*((struct in_addr*)&(qEntry.sip))));

		//src subnet mask
		if(!netmaskbits2str(qEntry.smaskbit, smask, 16))
		{
			smask[0] = '\0';
		}

		//dst addr
		snprintf(daddr, 16, "%s", inet_ntoa(*((struct in_addr*)&(qEntry.dip))));
		//dst subnet mask
		if(!netmaskbits2str(qEntry.dmaskbit, dmask, 16))
		{
			dmask[0] = '\0';
		}

#ifdef CONFIG_IPV6
		inet_ntop(PF_INET6, (struct in6_addr *)qEntry.sip6, sip6Str, sizeof(sip6Str));
		inet_ntop(PF_INET6, (struct in6_addr *)qEntry.dip6, dip6Str, sizeof(dip6Str));
#endif

		// src mac
		snprintf(smacaddr, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
			qEntry.smac[0], qEntry.smac[1],
			qEntry.smac[2], qEntry.smac[3],
			qEntry.smac[4], qEntry.smac[5]);

		// dst mac
		snprintf(dmacaddr, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
			qEntry.dmac[0], qEntry.dmac[1],
			qEntry.dmac[2], qEntry.dmac[3],
			qEntry.dmac[4], qEntry.dmac[5]);

#ifdef CONFIG_BRIDGE_EBT_DHCP_OPT
		//ifdef DHCPOPT
		// duid mac
		snprintf(duid_mac, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
			qEntry.duid_mac[0], qEntry.duid_mac[1],
			qEntry.duid_mac[2], qEntry.duid_mac[3],
			qEntry.duid_mac[4], qEntry.duid_mac[5]);
#endif

		if(qEntry.outif==65535)
			strcpy(wanifname,"Any");
		else
			ifGetName(qEntry.outif,wanifname,sizeof(wanifname));
		
		sprintf(apptypestr, "");
		if(generateAppTypeStr(qEntry.applicationtype, apptypestr)){
			sprintf(apptypestr, "none");
		}

		apptype = getWebApplicationType(qEntry.applicationtype);

#if (defined(CONFIG_YUEME) || defined(CONFIG_CMCC) || defined(CONFIG_CU))&& defined(CONFIG_LUNA_DUAL_LINUX)
		if(qEntry.phyPort <= SW_LAN_PORT_NUM)
			phyPort = qEntry.phyPort;
		else if(qEntry.phyPort > SW_LAN_PORT_NUM && qEntry.phyPort <= (SW_LAN_PORT_NUM + WLAN_SSID_NUM) )
			phyPort = qEntry.phyPort + WLAN_SSID_NUM;
		else if(qEntry.phyPort > (SW_LAN_PORT_NUM + WLAN_SSID_NUM) && qEntry.phyPort <= (SW_LAN_PORT_NUM + 2*WLAN_SSID_NUM) )
			phyPort = qEntry.phyPort - WLAN_SSID_NUM; 
#else
		phyPort = qEntry.phyPort;
#endif

		//now write into webs using boaWrite function
		nBytes += boaWrite(wp, "rules.push(\n"
			"new it_nr(\"%s\",    \n"  //qos queue rule name
			"new it(\"index\",%d),\n"  //index of queue rule(identifier)
			"new it(\"state\",%d),\n"  //enable or disable
			"new it(\"prio\", \"%d\"),\n"  //queue priority, queueKey
#ifndef BR_ROUTE_ONEPVC
			"new it(\"outif\", \"%d\"),\n"  //queue priority, queueKey
#else
			"new it(\"outif\", \"%d|%d\"),\n"  //queue priority, queueKey
#endif
			"new it(\"wanifname\",  \"%s\"),\n" //source ip6
#ifdef CONFIG_IPV6
			//"new it(\"ipversion\",%d),\n"  //ipv4 or ipv6
			"new it(\"IpProtocolType\",%d),\n"  //ipv4 or ipv6
			"new it(\"sip6\",  \"%s\"),\n" //source ip6
			"new it(\"dip6\",  \"%s\"),\n" //dst ip6
			"new it(\"sip6PrefixLen\",%d),\n"  //source ip6 Prefix Len
			"new it(\"dip6PrefixLen\",%d),\n"  //dst ip6 Prefix Len
#endif
			"new it(\"mvid\",%d),\n"   //VLAN ID
			"new it(\"mdscp\",%d),\n"   //dscp mark
			"new it(\"m1p\",  %d),\n"     //802.1p mark for wan interface
			"new it(\"vlan1p\",%d),\n"    //802.1p match for packet
			"new it(\"ethType\",\"%04x\"),\n"    //Ethernet Type match for packet
			"new it(\"phypt\", %d),\n"    //Lan phy port number
			"new it(\"proto\",%d),\n"     //protocol index, reference to mib.h
			"new it(\"dscp\", %d),\n"     //dscp
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
			"new it(\"tos\", %d),\n"	  //tos
#endif
			"new it(\"sip\",  \"%s\"),\n" //source ip, if stype=1, it is DHCP OPT 60
			"new it(\"smsk\", \"%s\"),\n" //source ip subnet mask
			"new it(\"dip\",  \"%s\"),\n"
			"new it(\"dmsk\", \"%s\"),\n"
			"new it(\"spts\", %d),\n"     //source port start
			"new it(\"spte\", %d),\n"     //source port end
			"new it(\"dpts\", %d),\n"
			"new it(\"dpte\", %d),\n"
			"new it(\"dhcpopt_type_select\", \"%d\"),\n"
			"new it(\"opt60_vendorclass\", \"%s\"),\n"
			"new it(\"opt61_iaid\", \"%d\"),\n"
			"new it(\"dhcpopt61_DUID_select\", \"%d\"),\n"
			"new it(\"duid_hw_type\", \"%d\"),\n"
			"new it(\"duid_mac\", \"%s\"),\n"
			"new it(\"duid_time\", \"%d\"),\n"
			"new it(\"duid_ent_num\", \"%d\"),\n"
			"new it(\"duid_ent_id\", \"%s\"),\n"
			"new it(\"opt125_ent_num\", \"%d\"),\n"
			"new it(\"opt125_manufacturer\", \"%s\"),\n"
			"new it(\"opt125_product_class\", \"%s\"),\n"
			"new it(\"opt125_model\", \"%s\"),\n"
			"new it(\"opt125_serial\", \"%s\"),\n"
			"new it(\"smac\", \"%s\"), \n"  //source mac address,now supported now, always 00:00:00:00:00:00
			"new it(\"smacw\",\"%s\"), \n"  //source mac address wildword
			"new it(\"dmac\", \"%s\"), \n"
			"new it(\"dmacw\",\"%s\"), \n"
			"new it(\"conntypeStr\",\"%s\"), \n"
			"new it(\"conntype\",\"%d\"), \n"
			"new it(\"classtype\",\"%d\"))); \n",
			qEntry.RuleName,  i, !!(qEntry.enable),
			qEntry.prior,
#ifndef BR_ROUTE_ONEPVC
			qEntry.outif,
#else
			qEntry.outif, qEntry.cmode,
#endif
			wanifname,
#ifdef CONFIG_IPV6
			qEntry.IpProtocol, sip6Str, dip6Str, qEntry.sip6PrefixLen, qEntry.dip6PrefixLen,
#endif
			qEntry.m_vid,qEntry.m_dscp, qEntry.m_1p, qEntry.vlan1p, *(unsigned short *)&(qEntry.ethType), qEntry.phyPort, qEntry.protoType, qEntry.qosDscp,
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
			qEntry.tos,
#endif
			saddr, smask, daddr, dmask, qEntry.sPort,
			qEntry.sPortRangeMax, qEntry.dPort, qEntry.dPortRangeMax,
#ifdef CONFIG_BRIDGE_EBT_DHCP_OPT
			qEntry.dhcpopt_type,qEntry.opt60_vendorclass,qEntry.opt61_iaid,
			qEntry.opt61_duid_type,qEntry.duid_hw_type,duid_mac,
			qEntry.duid_time,qEntry.duid_ent_num,qEntry.duid_ent_id,
			qEntry.opt125_ent_num,qEntry.opt125_manufacturer,
			qEntry.opt125_product_class,qEntry.opt125_model,qEntry.opt125_serial,
#else
			0,"",0,
			0,0,"",
			0,0,"",
			0,"",
			"","","",
#endif
			smacaddr, "00:00:00:00:00:00", dmacaddr, "00:00:00:00:00:00",
			apptypestr, apptype, qEntry.classtype);
	}

	return nBytes;
}

//Used to get subnet mask bit number
static int getNetMaskBit(char* netmask)
{
	unsigned int bits = 0, mask = 0;
	int i=0, flag = 0;

	if(!netmask||strlen(netmask)>15)
		return 0;
	mask = inet_network(netmask);
	for(;i<32;i++)
	{
		if(mask&(0x80000000>>i)) {
			if(flag)
				return 0;
			else
				bits++;
		}
		else {
	    		flag = 1;
		}
	}
	return bits;
}

/*
 * Return index of this rule
 * -1 on fail
 */
static int parseRuleArgs(char* args, MIB_CE_IP_QOS_Tp pEntry)
{
	char* p=NULL, *tmp=NULL, buff[32] = {0};
	int idx = 0;
	int ret;
#ifdef CONFIG_IPV6
	char buff2[48+1] = {0};
	struct in6_addr ip6Addr;
#endif

	p = strstr(args, "conntype=");
	p +=strlen("conntype=");
	if(*p == DELIM)//default
		pEntry->applicationtype= 0;
	else {		
		pEntry->applicationtype = getMibApplicationType(strtol(p, &tmp, 10));
		if(*tmp != DELIM) return -1;
	}

	p = strstr(args, "classtype=");
	p +=strlen("classtype=");
	if(*p == DELIM)//default
		pEntry->classtype= 0;
	else {		
		pEntry->classtype= strtol(p, &tmp, 10);
		if(*tmp != DELIM) return -1;
	}

	//get index
	p = strstr(args, "index=");
	p +=strlen("index=");
	if(*p == DELIM) {
		//pEntry->index = 0;
		ret = 0;
	} else {
		//pEntry->index = strtol(p, &tmp, 0);
		ret = strtol(p, &tmp, 0);
		if(*tmp != DELIM) return -1;
	}

	//get RuleName
	p = strstr(args, "name=");
	for(p+=strlen("name="); *p!=DELIM&&idx<INF_NAME_MAX;p++)
		pEntry->RuleName[idx++] = *p;

	//state
#if 1 // always enabled
	pEntry->enable = 1;
#else
	p = strstr(args, "state=");
	p += strlen("state=");
	if(*p != DELIM) {
		pEntry->enable = strtol(p, &tmp, 0);
		if(*tmp != DELIM)
			pEntry->enable = 1;//default
	} else {
		pEntry->enable = 1;//default
	}
#endif

	//get prio
	p = strstr(args, "prio=");
	p += strlen("prio=");
	if(*p==DELIM) return 1;
	pEntry->prior = strtol(p, &tmp, 0);
	if(*tmp != DELIM) return -1;//invalid dscp value

/* Remove WANInterface
	//get ifIndex, cmode
	p = strstr(args, "outif=");
	p += strlen("outif=");
	if(*p==SUBDELIM||*p==DELIM) return 1;
	//ifIndex
	pEntry->outif = strtol(p, &tmp, 0);
	// Mason Yu. t123
	//if(*tmp != SUBDELIM) return -1;
#ifdef BR_ROUTE_ONEPVC
	if(*tmp != SUBDELIM) return -1;
	pEntry->cmode = strtol(++tmp, &p, 0);
	if (*p != DELIM) return -1;
#else
	if(*tmp != DELIM) return -1;
#endif
*/

	/*
	   printf("[%s:%d]\n",__func__,__LINE__);
	//get vid
	p = strstr(args, "markvid=");
	p += strlen("markvid=");
	if(*p == DELIM)//default
	pEntry->m_vid = 0;
	else {
	pEntry->m_vid = strtol(p, &tmp, 10);
	if(*tmp != DELIM) return -1;//invalid vid value
	}
	*/
	//mark 802.1p
	p = strstr(args, "mark1p=");
	p += strlen("mark1p=");
	if(*p == DELIM)//default
		pEntry->m_1p = 0;
	else {
		pEntry->m_1p = strtol(p, &tmp, 16);
		if(*tmp != DELIM) return -1;//invalid 802.1p value
	}

	//mark dscp
	p = strstr(args, "markdscp=");
	p += strlen("markdscp=");
	if(*p == DELIM)//default
		pEntry->m_dscp = 0;
	else {
		pEntry->m_dscp = strtol(p, &tmp, 0);
		if(*tmp != DELIM) return -1;//invalid dscp value
	}

	//protocol
	p = strstr(args, "proto=");
	p += strlen("proto=");
	if(*p == DELIM) {//default, none
		pEntry->protoType = 0;
	} else {
		pEntry->protoType = strtol(p, &tmp, 0);
		if(*tmp != DELIM) return -1;
	}

	//smac
	p = strstr(args, "smac=");
	p += strlen("smac=");
	if (*p==DELIM) {//default
		memset(pEntry->smac, 0, MAC_ADDR_LEN);
	} else {
		for(idx=0; *p != DELIM&&idx<32; ++p) {
			if (*p!=':')
				buff[idx++] = *p;
		}
		string_to_hex(buff, pEntry->smac, 12);
	}

	//dmac
	p = strstr(args, "dmac=");
	p += strlen("dmac=");
	if (*p==DELIM) {//default
		memset(pEntry->dmac, 0, MAC_ADDR_LEN);
	} else {
		for(idx=0; *p != DELIM&&idx<32; ++p) {
			if (*p!=':')
				buff[idx++] = *p;
		}
		string_to_hex(buff, pEntry->dmac, 12);
	}

	//vlan 802.1p match
	p = strstr(args, "vlan1p=");
	p += strlen("vlan1p=");
	if(*p=='\0') {//default
		pEntry->vlan1p =0;
	} else {
		pEntry->vlan1p = strtol(p, &tmp, 0);
		if(*tmp != '\0') return -1;
	}

#ifdef CONFIG_IPV6
	//IPVersion
	p = strstr(args, "IPversion=");
	p += strlen("IPversion=");
	if(*p == DELIM)//default
		pEntry->IpProtocol = IPVER_IPV4_IPV6;
	else {
		pEntry->IpProtocol = strtol(p, &tmp, 0);
		if(*tmp != DELIM) return -1;//invalid dscp value
	}

	// If this is a IPv4 rule
	if ( pEntry->IpProtocol == IPVER_IPV4) {
#endif
		//ip source address
		p = strstr(args, "sip=");
		p += strlen("sip=");
		if(*p==DELIM) {//default
			memset(pEntry->sip, 0, IP_ADDR_LEN);
		} else {
			for(idx=0; *p != DELIM&&idx<32; ++p)
				buff[idx++] = *p;
			buff[idx] = '\0';
			{//ip address
				inet_aton(buff, (struct in_addr *)&pEntry->sip);
			}
		}

		//source ip netmaskbit
		p = strstr(args, "smask=");
		p += strlen("smask=");
		if(*p==DELIM) {//default
			pEntry->smaskbit =0;
		} else {
			for(idx=0; *p != DELIM&&idx<32; ++p)
				buff[idx++] = *p;
			buff[idx] = '\0';
			pEntry->smaskbit = getNetMaskBit(buff);
		}

		//ip dest address
		p = strstr(args, "dip=");
		p += strlen("dip=");
		if(*p==DELIM) {//default
			memset(pEntry->dip, 0, IP_ADDR_LEN);
		} else {
			for(idx=0; *p != DELIM&&idx<32; ++p)
				buff[idx++] = *p;
			buff[idx] = '\0';
			{//ip address
				inet_aton(buff, (struct in_addr *)&pEntry->dip);
			}
		}

		//destination ip netmaskbit
		p = strstr(args, "dmask=");
		p += strlen("dmask=");
		if(*p==DELIM) {//default
			pEntry->dmaskbit =0;
		} else {
			for(idx=0; *p != DELIM&&idx<32; ++p)
				buff[idx++] = *p;
			buff[idx] = '\0';
			pEntry->dmaskbit = getNetMaskBit(buff);
		}
#ifdef CONFIG_IPV6
	}
#endif

#ifdef CONFIG_IPV6
	// If it is a IPv6 rule.
	if ( pEntry->IpProtocol == IPVER_IPV6 )
	{
		//ip6 source address
		p = strstr(args, "sip6=");
		p += strlen("sip6=");
		if(*p==DELIM) {//default
			memset(pEntry->sip6, 0, IP6_ADDR_LEN);
		} else {
			for(idx=0; *p != DELIM&&idx<48; ++p)
				buff2[idx++] = *p;
			buff2[idx] = '\0';
			{//ip address
				inet_pton(PF_INET6, buff2, &ip6Addr);
				memcpy(pEntry->sip6, &ip6Addr, sizeof(pEntry->sip6));
			}
		}

		//ip6 dest address
		p = strstr(args, "dip6=");
		p += strlen("dip6=");
		if(*p==DELIM) {//default
			memset(pEntry->dip6, 0, IP6_ADDR_LEN);
		} else {
			for(idx=0; *p != DELIM&&idx<48; ++p)
				buff2[idx++] = *p;
			buff2[idx] = '\0';
			{//ip address
				inet_pton(PF_INET6, buff2, &ip6Addr);
				memcpy(pEntry->dip6, &ip6Addr, sizeof(pEntry->dip6));
			}
		}

		// ip6 src IP prefix Len
		p = strstr(args, "sip6PrefixLen=");
		p += strlen("sip6PrefixLen=");
		if(*p == DELIM)//default
			pEntry->sip6PrefixLen = 0;
		else {
			pEntry->sip6PrefixLen = strtol(p, &tmp, 0);
			if(*tmp != DELIM) return -1;//invalid dscp value
		}

		// ip6 dst IP prefix Len
		p = strstr(args, "dip6PrefixLen=");
		p += strlen("dip6PrefixLen=");
		if(*p == DELIM)//default
			pEntry->dip6PrefixLen = 0;
		else {
			pEntry->dip6PrefixLen = strtol(p, &tmp, 0);
			if(*tmp != DELIM) return -1;//invalid dscp value
		}
	}
#endif
	//src port start
	p = strstr(args, "spts=");
	p += strlen("spts=");
	if(*p==DELIM) {//default
		pEntry->sPort =0;
	} else {
		pEntry->sPort = strtol(p, &tmp, 0);
		if(*tmp != DELIM) return -1;
	}

	//src port end
	p = strstr(args, "spte=");
	p += strlen("spte=");
	if(*p==DELIM) {//default
		pEntry->sPortRangeMax =0;
	} else {
		pEntry->sPortRangeMax = strtol(p, &tmp, 0);
		if(*tmp != DELIM) return -1;
	}


	//dst port start
	p = strstr(args, "dpts=");
	p += strlen("dpts=");
	if(*p==DELIM) {//default
		pEntry->dPort =0;
	} else {
		pEntry->dPort = strtol(p, &tmp, 0);
		if(*tmp != DELIM) return -1;
	}

	//dst port end
	p = strstr(args, "dpte=");
	p += strlen("dpte=");
	if(*p==DELIM) {//default
		pEntry->dPortRangeMax =0;
	} else {
		pEntry->dPortRangeMax = strtol(p, &tmp, 0);
		if(*tmp != DELIM) return -1;
	}	
	//dscp match
	p = strstr(args, "matchdscp=");
	p += strlen("matchdscp=");
	if(*p == DELIM) {//default
		pEntry->qosDscp = 0;
	} else {
		pEntry->qosDscp = strtol(p, &tmp, 0);
		if(*tmp != DELIM) return -1;
	}
	//phy port num
	p = strstr(args, "phyport=");
	p +=strlen("phyport=");
	if(*p == DELIM) {
		pEntry->phyPort = 0;//default phy port, none
	} else {
		pEntry->phyPort = strtol(p, &tmp, 0);
		if(*tmp != DELIM) return 1;
	}
	return ret;
}
//parse formated string recieved from web client:
//inf=VAL&proto=VAL&srcip=VAL&srcnetmask=VAL&dstip=VAL&dstnetmask=VAL&sport=VAL&dport=VAL&uprate=VAL(old).
//where VAL is the value of the corresponding item. if none, VAL is ignored but the item name cannot be
//The argument action is not modified by the function, so it can be a const string or non-const string.
static int parseArgs(char* action, MIB_CE_IP_TC_Tp pEntry)
{
	char* p = NULL, *tmp = NULL;
	int i = 0;
#ifdef CONFIG_IPV6
	int idx = 0;
	char buff2[48] = {0};
	struct in6_addr ip6Addr;
#endif

	PRINT_FUNCTION

	//ifIndex
	tmp = strstr(action, "inf=");
	tmp += strlen("inf=");
	pEntry->ifIndex = strtol(tmp, &p,0);	
	
	if(*p != SUBDELIM)
	//if(*p != DELIM)
		return 1;
#ifdef BR_ROUTE_ONEPVC
	pEntry->cmode = strtol(++p, &tmp, 0);
	if (*tmp != DELIM)
	//if(*p != DELIM)
	{
		return 1;
	}
#endif

	//protocol
	tmp =strstr(action, "proto=");
	tmp += strlen("proto=");
	if(!tmp||*tmp == DELIM)//not set protocol, set it to default,none
		pEntry->protoType = 0;
	else
	{
		pEntry->protoType = strtol(tmp, &p, 0);
		if(*p != DELIM)
			return 1;
	}

#ifdef CONFIG_IPV6
	//IPVersion
	tmp = strstr(action, "IPversion=");
	tmp += strlen("IPversion=");
	if(*tmp == DELIM)//default
		pEntry->IpProtocol = IPVER_IPV4_IPV6;
	else {
		pEntry->IpProtocol = strtol(tmp, &p, 0);
		if(*p != DELIM) return -1;//invalid dscp value
	}

	// If this is a IPv4 rule
	if ( pEntry->IpProtocol == IPVER_IPV4) {
#endif
		//source ip
		tmp = strstr(action, "srcip=");
		tmp += strlen("srcip=");
		if(!tmp||*tmp == DELIM)//noet set, set default
			memset(pEntry->srcip, 0, IP_ADDR_LEN);
		else
		{
			char sip[16]={0};
			p = strchr(tmp, DELIM);
			if(p&&p-tmp>15)
				return 1;
			strncpy(sip, tmp, p-tmp);
			inet_aton(sip, (struct in_addr *)&pEntry->srcip);
		}

		//source ip address netmask
		tmp = strstr(action, "srcnetmask=");
		tmp += strlen("srcnetmask=");
		if(!tmp||*tmp==DELIM)
			pEntry->smaskbits = 0;
		else
		{
			char smask[16]={0};
			p = strchr(tmp, DELIM);
			if(p&&p-tmp>15) return 1;
			strncpy(smask, tmp, p-tmp);
			pEntry->smaskbits = getNetMaskBit(smask);
		}

		//destination ip
		tmp = strstr(action, "dstip=");
		tmp += strlen("dstip=");
		if(!tmp||*tmp == DELIM)//noet set, set default
			memset(pEntry->dstip, 0, IP_ADDR_LEN);
		else
		{
			char dip[16]={0};
			p = strchr(tmp, DELIM);
			if(p&&p-tmp>15)
				return 1;
			strncpy(dip, tmp, p-tmp);
			inet_aton(dip, (struct in_addr *)&pEntry->dstip);
		}

		//destination ip address netmask
		tmp = strstr(action, "dstnetmask=");
		tmp += strlen("dstnetmask=");
		if(!tmp||*tmp==DELIM)
			pEntry->dmaskbits = 0;
		else
		{
			char dmask[16]={0};
			p = strchr(tmp, DELIM);
			if(p&&p-tmp>15)
				return 1;
			strncpy(dmask, tmp, p-tmp);
			pEntry->dmaskbits = getNetMaskBit(dmask);

		}
#ifdef CONFIG_IPV6
	}
#endif

#ifdef CONFIG_IPV6
	// If it is a IPv6 rule.
	if ( pEntry->IpProtocol == IPVER_IPV6 )
	{
		//ip6 source address
		tmp = strstr(action, "sip6=");
		tmp += strlen("sip6=");
		if(*tmp==DELIM) {//default
			memset(pEntry->sip6, 0, IP6_ADDR_LEN);
		} else {
			for(idx=0; *tmp != DELIM&&idx<48; ++tmp)
				buff2[idx++] = *tmp;
			buff2[idx] = '\0';
			{//ip address
				inet_pton(PF_INET6, buff2, &ip6Addr);
				memcpy(pEntry->sip6, &ip6Addr, sizeof(pEntry->sip6));
			}
		}

		// ip6 src IP prefix Len
		tmp = strstr(action, "sip6PrefixLen=");
		tmp += strlen("sip6PrefixLen=");
		if(*tmp == DELIM)//default
			pEntry->sip6PrefixLen = 0;
		else {
			pEntry->sip6PrefixLen = strtol(tmp, &p, 0);
			if(*p != DELIM) return -1;//invalid dscp value
		}

		//ip6 dest address
		tmp = strstr(action, "dip6=");
		tmp += strlen("dip6=");
		if(*tmp==DELIM) {//default
			memset(pEntry->dip6, 0, IP6_ADDR_LEN);
		} else {
			for(idx=0; *tmp != DELIM&&idx<48; ++tmp)
				buff2[idx++] = *tmp;
			buff2[idx] = '\0';
			{//ip address
				inet_pton(PF_INET6, buff2, &ip6Addr);
				memcpy(pEntry->dip6, &ip6Addr, sizeof(pEntry->dip6));
			}
		}

		// ip6 dst IP prefix Len
		tmp = strstr(action, "dip6PrefixLen=");
		tmp += strlen("dip6PrefixLen=");
		if(*tmp == DELIM)//default
			pEntry->dip6PrefixLen = 0;
		else {
			pEntry->dip6PrefixLen = strtol(tmp, &p, 0);
			if(*p != DELIM) return -1;//invalid dscp value
		}
	}
#endif

	//source port
	tmp = strstr(action, "sport=");
	tmp += strlen("sport=");
	if(!tmp||*tmp==DELIM)
		pEntry->sport = 0;
	else
	{
		pEntry->sport = strtol(tmp, &p, 0);
		if(*p != DELIM)
			return 1;
	}

	//destination port
	tmp = strstr(action, "dport=");
	tmp += strlen("dport=");
	if(!tmp||*tmp==DELIM)
		pEntry->dport = 0;
	else
	{
		pEntry->dport = strtol(tmp, &p, 0);
		if(*p != DELIM)
			return 1;
	}

	//rate limit
	tmp = strstr(action, "rate=");
	tmp += strlen("rate=");
	if(!tmp||*tmp=='\0')
		pEntry->limitSpeed = 0;
	else
	{
		pEntry->limitSpeed = strtol(tmp, &p, 0);
		if(*p != DELIM)
			return 1;
	}

	//direction limit
	tmp = strstr(action, "direction=");
	tmp += strlen("direction=");
	if(!tmp||*tmp=='\0')
		pEntry->direction = 0;
	else
	{
		pEntry->direction = strtol(tmp, &p, 0);
		if(*p != '\0')
			return 1;
	}
	return 0;
}

void formQosRuleEdit(request * wp, char* path, char* query)
{
	MIB_CE_IP_QOS_T entry;
	char* action = NULL, args[256]={0}, *p = NULL, *tmp=NULL;
	char* act1="addrule", *act2="editrule", *url = NULL;
	int entryNum = 0, index=0,i=0;
	int j;

	PRINT_FUNCTION

	action = boaGetVar(wp, "lst", "");
	if(action[0])
	{
		entryNum = mib_chain_total(MIB_IP_QOS_TBL);

		if(!strncmp(action, act1, strlen(act1)))
		{//add new one
			if( entryNum>=QUEUE_RULE_NUM_MAX)
			{
				ERR_MSG("伫列规则数目已达上限."); //You cannot add one new rule when queue is full.
				return;
			}

			//reset to zero
			bzero(&entry, sizeof(MIB_CE_IP_QOS_T));

			index = parseRuleArgs(action, &entry);
			if (index >= 0)
			{
				PRINT_QUEUE_RULE((&entry));

#ifdef _PRMT_X_CT_COM_QOS_
				// Mason Yu. 
				entry.modeTr69 = MODEOTHER;
				for(j=0;j<CT_TYPE_NUM;j++)
					entry.cttypemap[j]=0;
				updatecttypevalue(&entry);				
#endif

				if(!mib_chain_add(MIB_IP_QOS_TBL, &entry))
				{
					ERR_MSG("mib Error: qos规则加入失败"); //mib Error: Cannot add new one qos rule.
					return;
				}
			}
			else
			{
				ERR_MSG("AddQosRule:错误的格式!"); //AddQosRule:Wrong argument format!
				return;
			}

		} else if(!strncmp(action, act2, strlen(act2))) {//update old one
			MIB_CE_IP_QOS_T oldEntry;

			//reset to zero
			bzero(&entry, sizeof(MIB_CE_IP_QOS_T));

			index = parseRuleArgs(action, &entry);
			if(index<0)
			{
				ERR_MSG("UpdateQosRule: 错误的格式!"); //UpdateQosRule: Wrong argument format!
				return;
			}

			PRINT_QUEUE_RULE((&entry));

			mib_chain_get(MIB_IP_QOS_TBL, index, &oldEntry);
#ifdef _CWMP_MIB_
			entry.InstanceNum=oldEntry.InstanceNum;
#endif

#ifdef _PRMT_X_CT_COM_QOS_
			entry.modeTr69=oldEntry.modeTr69;
			entry.minphyPort=oldEntry.minphyPort;			
			for(j=0;j<CT_TYPE_NUM;j++)
				entry.cttypemap[j]=oldEntry.cttypemap[j];
			updatecttypevalue(&entry);
#endif
			if(!mib_chain_update(MIB_IP_QOS_TBL, &entry, index))
			{
				ERR_MSG("qos规则更新失败!"); //Updating qos rule into mib is wrong!
				return;
			}
		} else {//undefined operation
			ERR_MSG("错误的操作! 你只能新增或编辑qos规则!"); //Wrong operation happened! you only and add or edit qos rule in this page!
			return;
		}
	}
#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif
	//redirect
	url = boaGetVar(wp, "submit-url","");
	if(url[0])
	{
		boaRedirect(wp, url);
	}

	return;
}
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
#if 0
static int parseQosClassficationRuleArgs(char* args, MIB_CE_IP_QOS_CLASSFICATION_Tp pEntry){

		char* p=NULL, *tmp=NULL, buff[32] = {0};
		int idx = 0;
		int ret;
	
		p = strstr(args, "ClsQueueValueFlag=");
		p +=strlen("ClsQueueValueFlag=");
		if(*p == DELIM)//default
			pEntry->queue= 0;
		else {		
			pEntry->queue =strtol(p, &tmp, 10);
			if(*tmp != DELIM) return -1;
		}
	
		p = strstr(args, "DSCPMarkValue=");
		p +=strlen("DSCPMarkValue=");
		if(*p == DELIM)//default
			pEntry->dscp= 0;
		else {		
			pEntry->dscp= strtol(p, &tmp, 10);
			if(*tmp != DELIM) return -1;
		}
		p = strstr(args, "v8021pValue=");
		p +=strlen("v8021pValue=");
		if(*p == DELIM)//default
			pEntry->dot1p= 0;
		else {		
			pEntry->dot1p= strtol(p, &tmp, 10);
			if(*tmp != DELIM) return -1;
		}
		return 0;
}
#endif
void formQosVlan(request * wp, char* path, char* query){
	char* url=NULL;
	url = boaGetVar(wp, "submit-url","");
	if(url[0])
		{
			boaRedirect(wp, url);
		}
	return;

}


void formQosClassficationRuleEdit(request * wp, char* path, char* query){
	MIB_CE_IP_QOS_CLASSFICATION_T entry;
	char* action = NULL, args[256]={0}, *p = NULL, *tmp=NULL;
	char* act1="addrule", *act2="editrule", *url = NULL;
	int entryNum = 0, index=0,i=0;
	int j;
	char *ClsQueueValueFlag,*DSCPMarkValue,*v8021pValue;
	
	action = boaGetVar(wp, "lst", "");
	
	if(!action)
		goto end;
	printf("action=%s\n",action);
	if(!strncmp(action,"addQosClsRule",strlen("addQosClsRule")))
	{
		char *EditClsIndexStr=boaGetVar(wp, "EditClsIndex", "-1");
		printf("EditClsIndexStr=%s\n",EditClsIndexStr);
		if(!strcmp(EditClsIndexStr,"-1")||!strlen(EditClsIndexStr)){
			//add classfication rule
			entryNum = mib_chain_total(MIB_IP_QOS_CLASSFICATION_TBL);
			
			if( entryNum>=MAX_QOS_CLASSFICATION_NUM)
			{
				ERR_MSG("规则数目已达上限."); //You cannot add one new rule when queue is full.
				return;
			}
			bzero(&entry, sizeof(MIB_CE_IP_QOS_CLASSFICATION_T));
			ClsQueueValueFlag=boaGetVar(wp, "ClsQueueValueFlag", "1");
			//printf("ClsQueueValueFlag=%s\n",ClsQueueValueFlag);
			entry.queue =atoi(ClsQueueValueFlag);
			DSCPMarkValue=boaGetVar(wp, "DSCPMarkValue", "0");
			//printf("DSCPMarkValue=%s\n",DSCPMarkValue);
			entry.m_dscp =atoi(DSCPMarkValue);
			v8021pValue=boaGetVar(wp, "v8021pValue", "0");
			//printf("v8021pValue=%s\n",v8021pValue);
			entry.m_1p =atoi(v8021pValue);
			entry.cls_id=getValidClsID();
			//printf("entry.cls_id=%d entryNum=%d\n",entry.cls_id,entryNum);
			if(!mib_chain_add(MIB_IP_QOS_CLASSFICATION_TBL, &entry)){
					ERR_MSG("mib Error: qos规则加入失败"); //mib Error: Cannot add new one qos rule.
					return;
			}	
			//printf("entry.cls_id=%d entryNum=%d\n",entry.cls_id,mib_chain_total(MIB_IP_QOS_CLASSFICATION_TBL));
		}else{
			//edit classfication rule
			int EditClsIndex = atoi(EditClsIndexStr);
			//find the cls postion
			int pos=EditClsIndex;
			bzero(&entry, sizeof(MIB_CE_IP_QOS_CLASSFICATION_T));
			ClsQueueValueFlag=boaGetVar(wp, "ClsQueueValueFlag", "0");
			//printf("ClsQueueValueFlag=%s\n",ClsQueueValueFlag);
			entry.queue =atoi(ClsQueueValueFlag);
			DSCPMarkValue=boaGetVar(wp, "DSCPMarkValue", "0");
			//printf("DSCPMarkValue=%s\n",DSCPMarkValue);
			entry.m_dscp =atoi(DSCPMarkValue);
			v8021pValue=boaGetVar(wp, "v8021pValue", "0");
			//printf("v8021pValue=%s\n",v8021pValue);
			entry.m_1p =atoi(v8021pValue);
			entry.cls_id=getClsIDInMib(pos);
			if(!mib_chain_update(MIB_IP_QOS_CLASSFICATION_TBL, &entry,pos)){
					ERR_MSG("mib Error: qos规则编辑失败"); //mib Error: Cannot add new one qos rule.
					return;
			}	
			QosClassficationToQosRule(QOSCLASSFICATION_TO_QOSRULE_ACTION_MODIFY,entry.cls_id);
		}
	}else if(!strncmp(action,"delQosClsRule",strlen("delQosClsRule"))){
		/*from ClsDelNo9 to ClsDelNo0*/
		int i=MAX_QOS_CLASSFICATION_NUM-1;
		for(;i>=0;i--){
			char clsdelstr[16]={0};
			sprintf(clsdelstr,"ClsDelNo%d",i);
			char* delNoStr = boaGetVar(wp, clsdelstr, "-1");
			printf("clsdelstr=%s delNoStr=%s\n",clsdelstr,delNoStr);
			if(!strcmp(delNoStr,"Yes")){
				int delNo = i;
				printf("delNo=%d \n",delNo);
				//clean up the clstype rule in this cls
				int totalQosRuleNums=mib_chain_total(MIB_IP_QOS_CLASSFICATIONTYPE_TBL);
				int qosRuleIdx = 0;
				int ClsIndexOfClassQueue =delNo ;
				for(qosRuleIdx=(totalQosRuleNums-1);qosRuleIdx>=0;qosRuleIdx--){
						MIB_CE_IP_QOS_CLASSFICATIONTYPE_T qosentry;
						mib_chain_get(MIB_IP_QOS_CLASSFICATIONTYPE_TBL,qosRuleIdx,&qosentry);						
						if(qosentry.cls_id==ClsIndexOfClassQueue){
							mib_chain_delete(MIB_IP_QOS_CLASSFICATIONTYPE_TBL,qosRuleIdx);
						}
					
				}
				
				int totalClsRuleNums=mib_chain_total(MIB_IP_QOS_CLASSFICATION_TBL);
				int clsRuleIdx=0;
				for(clsRuleIdx=0;clsRuleIdx<totalClsRuleNums;clsRuleIdx++){
						MIB_CE_IP_QOS_CLASSFICATION_T clsentry;
						mib_chain_get(MIB_IP_QOS_CLASSFICATION_TBL,clsRuleIdx,&clsentry);						
						if(clsentry.cls_id==ClsIndexOfClassQueue){
							mib_chain_delete(MIB_IP_QOS_CLASSFICATION_TBL,clsRuleIdx);
							break;
						}
				}
				//MIB_CE_IP_QOS_CLASSFICATION_T cls_entry;
				//mib_chain_get(MIB_IP_QOS_CLASSFICATION_TBL,delNo,&cls_entry);
				//cls_entry.cls_id = 0xff;
				//mib_chain_update(MIB_IP_QOS_CLASSFICATION_TBL,&cls_entry, delNo);
				////mib_chain_d
				QosClassficationToQosRule(QOSCLASSFICATION_TO_QOSRULE_ACTION_DEL,ClsIndexOfClassQueue);
			}
		}
	}else if(!strncmp(action,"addQosTypeRule",strlen("addQosTypeRule"))||!strncmp(action,"editQosTypeRule",strlen("editQosTypeRule"))){
			char *MinStr,*MaxStr,*TypeStr,*ProtocolListStr;
			int ClsIndexOfClassQueue;
			char *ClsIndexOfClassQueueStr ;
			TypeStr = boaGetVar(wp, "Type", "-1");
			char* EditClsTypeIndexStr;
			
			
			ClsIndexOfClassQueueStr = boaGetVar(wp, "ClsIndexOfClassQueue", NULL);
			if(ClsIndexOfClassQueueStr)
				ClsIndexOfClassQueue =atoi(ClsIndexOfClassQueueStr);
			if(!strncmp(action,"editQosTypeRule",strlen("editQosTypeRule"))){
				//on do in edit mode
				EditClsTypeIndexStr = boaGetVar(wp, "EditClsTypeIndex",NULL);
				if(EditClsTypeIndexStr){
					int EditClsTypeIndex=atoi(EditClsTypeIndexStr);
					EditClsTypeIndex=EditClsTypeIndex%MAX_QOS_RULE_NUM_ONE_CLASSFICATION;
					printf("%s %d EditClsTypeIndex=%d ClsIndexOfClassQueue=%d\n",__FUNCTION__,__LINE__,EditClsTypeIndex,ClsIndexOfClassQueue);
					//deletet the old clstype rule
					int totalQosRuleNums=mib_chain_total(MIB_IP_QOS_CLASSFICATIONTYPE_TBL);
					int qosRuleIdx = 0;
					int qosentryno=-1;
					for(qosRuleIdx=0;qosRuleIdx<totalQosRuleNums;qosRuleIdx++){
							MIB_CE_IP_QOS_CLASSFICATIONTYPE_T qosentry;
							mib_chain_get(MIB_IP_QOS_CLASSFICATIONTYPE_TBL,qosRuleIdx,&qosentry);						
							if(qosentry.cls_id==ClsIndexOfClassQueue){
								qosentryno++;
								if(qosentryno==EditClsTypeIndex){													
									mib_chain_delete(MIB_IP_QOS_CLASSFICATIONTYPE_TBL,qosRuleIdx);
									break;
								}
					
						}
					}
						
				}
			}
			
			MIB_CE_IP_QOS_CLASSFICATIONTYPE_T entry;
			bzero(&entry, sizeof(MIB_CE_IP_QOS_CLASSFICATIONTYPE_T));
			entry.cls_id =ClsIndexOfClassQueue;
			ProtocolListStr = boaGetVar(wp, "ProtocolList", NULL);
			if(ProtocolListStr)
				entry.protoType = getProtoType(ProtocolListStr);
			entry.classficationType =1<<getQosClassficationType(TypeStr); 
			entryNum = mib_chain_total(MIB_IP_QOS_CLASSFICATIONTYPE_TBL);
	
			if( entryNum>=MAX_QOS_CLASSFICATIONTYPE_NUM)
			{
				ERR_MSG("伫列规则数目已达上限."); //You cannot add one new rule when queue is full.
				return;
			}
			
			if(!strcmp(TypeStr,"SIP")||!strcmp(TypeStr,"DIP")||!strcmp(TypeStr,"SMAC")||!strcmp(TypeStr,"DMAC")||
			   !strcmp(TypeStr,"8021P")||!strcmp(TypeStr,"SPORT")||!strcmp(TypeStr,"DPORT")||!strcmp(TypeStr,"DSCP")||
#ifdef CONFIG_IPV6
				!strcmp(TypeStr,"SIP6")||!strcmp(TypeStr,"DIP6")||!strcmp(TypeStr,"SPORT6")||!strcmp(TypeStr,"DPORT6")||!strcmp(TypeStr,"TrafficClass")||
#endif
				!strcmp(TypeStr,"EtherType")){
					printf("%s %d\n",__FUNCTION__,__LINE__);
					MinStr = boaGetVar(wp, "Min", NULL);
					MaxStr = boaGetVar(wp, "Max", NULL);
					if(!MinStr||!MaxStr)
					{
						ERR_MSG("参数错误."); //You cannot add one new rule when queue is full.
						return;
					}				
					//reset to zero
					switch(entry.classficationType){
						case (1<<IP_QOS_CLASSFICATIONTYPE_SMAC):	
							{
								int idx = 0;
								char buff[32]={0};
								char* p=MinStr;
								for(idx=0; *p != '\0'&&idx<32; ++p) {
									if (*p!=':')
										buff[idx++] = *p;
								}
								string_to_hex(buff, entry.smac, 12);
								printf("%s %d##################\n",__FUNCTION__,__LINE__);
								p=MaxStr;
								for(idx=0; *p != '\0'&&idx<32; ++p) {
									if (*p!=':')
										buff[idx++] = *p;
								}
								string_to_hex(buff, entry.smac_end, 12);
							}
		
							break;
						case (1<<IP_QOS_CLASSFICATIONTYPE_DMAC):
							{
								int idx = 0;
								char buff[32]={0};
								char* p=MinStr;
								for(idx=0; *p != '\0'&&idx<32; ++p) {
									if (*p!=':')
										buff[idx++] = *p;
								}
								string_to_hex(buff, entry.dmac, 12);
								printf("%s %d##################\n",__FUNCTION__,__LINE__);
								p=MaxStr;
								for(idx=0; *p != '\0'&&idx<32; ++p) {
									if (*p!=':')
										buff[idx++] = *p;
								}
								string_to_hex(buff, entry.dmac_end, 12);
							}
							break;
						case (1<<IP_QOS_CLASSFICATIONTYPE_8021P):
							entry.vlan1p = atoi(MinStr);
							entry.vlan1p_end = atoi(MaxStr);
							break;
						case (1<<IP_QOS_CLASSFICATIONTYPE_SIP):						
							inet_aton(MinStr, (struct in_addr *)&entry.sip);
							inet_aton(MaxStr, (struct in_addr *)&entry.sip_end);
							break;
						case (1<<IP_QOS_CLASSFICATIONTYPE_DIP):						
							inet_aton(MinStr, (struct in_addr *)&entry.dip);
							inet_aton(MaxStr, (struct in_addr *)&entry.dip_end);
							break;
						case (1<<IP_QOS_CLASSFICATIONTYPE_SPORT):
							entry.sPort = atoi(MinStr);
							entry.sPortRangeMax = atoi(MaxStr);
							break;
						case (1<<IP_QOS_CLASSFICATIONTYPE_DPORT):
							entry.dPort = atoi(MinStr);
							entry.dPortRangeMax = atoi(MaxStr);
							break;
						case (1<<IP_QOS_CLASSFICATIONTYPE_TOS):	
							break;
						case (1<<IP_QOS_CLASSFICATIONTYPE_DSCP):
							entry.qosDscp = atoi(MinStr);
							entry.qosDscp_end= atoi(MaxStr);
							break;
#ifdef CONFIG_IPV6
						case (1<<IP_QOS_CLASSFICATIONTYPE_SIP6):						
							inet_pton(AF_INET6, MinStr, (void *)&entry.sip6);
							break;
						case (1<<IP_QOS_CLASSFICATIONTYPE_DIP6):						
							inet_pton(AF_INET6, MinStr, (void *)&entry.dip6);
							break;
						case (1<<IP_QOS_CLASSFICATIONTYPE_SPORT6):
							entry.sPort6 = atoi(MinStr);
							entry.sPort6RangeMax = atoi(MaxStr);
							break;
						case (1<<IP_QOS_CLASSFICATIONTYPE_DPORT6):
							entry.dPort6 = atoi(MinStr);
							entry.dPort6RangeMax = atoi(MaxStr);
							break;
						case (1<<IP_QOS_CLASSFICATIONTYPE_TrafficClass):
							entry.tc = atoi(MinStr);
							entry.tc_end= atoi(MaxStr);
							break;
#endif
						case (1<<IP_QOS_CLASSFICATIONTYPE_WANINTERFACE):
							break;
						case (1<<IP_QOS_CLASSFICATIONTYPE_LANINTERFACE):
							break;
						case (1<<IP_QOS_CLASSFICATIONTYPE_ETHERTYPE):
							if(!strcmp(MinStr,"IPv4"))
								entry.ethType=0x0800;
							else if(!strcmp(MinStr,"IPv6"))
								entry.ethType=0x86dd;
							break;
						default:
							break;			
			
					}
				}else if(!strcmp(TypeStr,"TOS")){
						char* tosStr = boaGetVar(wp, "Tos", NULL);
						if(tosStr)
							entry.tos = atoi(tosStr);
				}else if(!strcmp(TypeStr,"WANInterface")){
						char* TypeWanInterFaceMinStr = boaGetVar(wp, "TypeWanInterFaceMin", NULL);						
						if(TypeWanInterFaceMinStr)
							entry.wanitf = atoi(TypeWanInterFaceMinStr);
				}else if(!strcmp(TypeStr,"LANInterface")){
						char* TypeLanInterFaceMinStr = boaGetVar(wp, "TypeLanInterFaceMin", NULL);										
						if(TypeLanInterFaceMinStr)
								entry.phyPort = atoi(TypeLanInterFaceMinStr);
						char* TypeLanInterFaceMaxStr = boaGetVar(wp, "TypeLanInterFaceMax", NULL);										
						if(TypeLanInterFaceMaxStr)
								entry.phyPort_end = atoi(TypeLanInterFaceMaxStr);
				}
				

				if(!mib_chain_add(MIB_IP_QOS_CLASSFICATIONTYPE_TBL, &entry))
				{
					ERR_MSG("mib Error: qos规则加入失败"); //mib Error: Cannot add new one qos rule.
					return;
				}
			
				QosClassficationToQosRule(QOSCLASSFICATION_TO_QOSRULE_ACTION_MODIFY,ClsIndexOfClassQueue);
			
	}else if(!strncmp(action,"delQosTypeRule",strlen("delQosTypeRule"))){
			char* ClsIndexOfClassQueueStr;
			int ClsIndexOfClassQueue=0;
			ClsIndexOfClassQueueStr = boaGetVar(wp, "ClsIndexOfClassQueue", NULL);
			if(ClsIndexOfClassQueueStr)
				ClsIndexOfClassQueue =atoi(ClsIndexOfClassQueueStr);
			int delNo=0;
			for(delNo=MAX_QOS_RULE_NUM_ONE_CLASSFICATION-1;delNo>=0;delNo--){
				char delflags[32]={0};
				sprintf(delflags,"TypeDelFlag%d",delNo);
				char* TypeDelFlagStr = boaGetVar(wp, delflags, NULL);
				if(TypeDelFlagStr&&!strcmp(TypeDelFlagStr,"Yes")){
					printf("%s=TypeDelFlagStr=%s\n",delflags,TypeDelFlagStr);
					int totalQosRuleNums=mib_chain_total(MIB_IP_QOS_CLASSFICATIONTYPE_TBL);
					int qosRuleIdx = 0;
					int qosentryno=-1;
					for(qosRuleIdx=0;qosRuleIdx<totalQosRuleNums;qosRuleIdx++){
						MIB_CE_IP_QOS_CLASSFICATIONTYPE_T qosentry;
						mib_chain_get(MIB_IP_QOS_CLASSFICATIONTYPE_TBL,qosRuleIdx,&qosentry);						
						if(qosentry.cls_id==ClsIndexOfClassQueue){
							qosentryno++;
							if(qosentryno==delNo){
								printf("%s %d delete MIB_IP_QOS_CLASSFICATIONTYPE_TBL \n",__FUNCTION__,__LINE__);
								mib_chain_delete(MIB_IP_QOS_CLASSFICATIONTYPE_TBL,qosRuleIdx);								
								break;
							}
							
						}
					}
				}
				
			}
			QosClassficationToQosRule(QOSCLASSFICATION_TO_QOSRULE_ACTION_MODIFY,ClsIndexOfClassQueue);
	}
	
end:
#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif

	//redirect
	printf("%s %d\n",__FUNCTION__,__LINE__);
	url = boaGetVar(wp, "submit-url","");
	if(url[0])
	{
		boaRedirect(wp, url);
	}
	take_qos_effect_v3();
	return;
}
#endif
////////////////////////////////////////////////////////////////////////////////////////////
//Qos Traffic control code

//now the problem is that the ifIndex is used in c code, and ifname is used for displaying,
//how can i get the ifname or ifIndex
int initTraffictlPage(int eid, request * wp, int argc, char **argv)
{
	MIB_CE_IP_TC_T entry;
	int entryNum = 0, i=0, nBytes = 0;
	char sip[20], dip[20], wanname[IFNAMSIZ], *p = NULL;
	unsigned int total_bandwidth = 0;
	unsigned char totalBandWidthEn = 0;
#ifdef CONFIG_IPV6
	unsigned char 	sip6Str[55], dip6Str[55];
#endif

	PRINT_FUNCTION

	entryNum = mib_chain_total(MIB_IP_QOS_TC_TBL);

	if(mib_get(MIB_TOTAL_BANDWIDTH, &total_bandwidth))
	{
		nBytes += boaWrite(wp, "totalBandwidth=%u;\n", total_bandwidth);
	}
	else
	{
		nBytes += boaWrite(wp, "totalBandwidth=1024;\n");
	}

	if (mib_get(MIB_TOTAL_BANDWIDTH_LIMIT_EN, &totalBandWidthEn))
		nBytes += boaWrite(wp, "totalBandWidthEn=%d;\n", totalBandWidthEn);
	else
		nBytes += boaWrite(wp, "totalBandWidthEn=0;\n");

	for(;i<entryNum; i++)
	{
		MIB_CE_ATM_VC_T       vcEntry;

		if(!mib_chain_get(MIB_IP_QOS_TC_TBL, i, &entry))
			continue;
		wanname[0]='\0';
		//if (!getWanEntrybyindex(&vcEntry, entry.ifIndex)) {
		//	getWanName(&vcEntry, wanname);
		//}
		ifGetName(entry.ifIndex, wanname, sizeof(wanname));
		strncpy(sip, inet_ntoa(*((struct in_addr*)&entry.srcip)), INET_ADDRSTRLEN);
		strncpy(dip, inet_ntoa(*((struct in_addr*)&entry.dstip)), INET_ADDRSTRLEN);
		if(entry.smaskbits)
		{
			p = sip + strlen(sip);
			snprintf(p,sizeof(sip)-strlen(sip), "/%d", entry.smaskbits );
		}

		if(entry.dmaskbits)
		{
			p = dip + strlen(dip);
			snprintf(p,sizeof(dip)-strlen(dip), "/%d", entry.dmaskbits );
		}

#ifdef CONFIG_IPV6
		inet_ntop(PF_INET6, (struct in6_addr *)entry.sip6, sip6Str, sizeof(sip6Str));
		if(entry.sip6PrefixLen)
		{
			p = sip6Str + strlen(sip6Str);
			snprintf(p,sizeof(sip6Str)-strlen(sip6Str), "/%d", entry.sip6PrefixLen );
		}

		inet_ntop(PF_INET6, (struct in6_addr *)entry.dip6, dip6Str, sizeof(dip6Str));
		if(entry.dip6PrefixLen)
		{
			p = dip6Str + strlen(dip6Str);
			snprintf(p,sizeof(dip6Str)-strlen(dip6Str), "/%d", entry.dip6PrefixLen );
		}
#endif

		nBytes += boaWrite(wp, "traffictlRules.push(new it_nr(\"\",\n"
#ifdef CONFIG_IPV6
			//"new it(\"ipversion\",%d),\n"  //ipv4 or ipv6
			"new it(\"IpProtocolType\",%d),\n"  //ipv4 or ipv6
			"new it(\"sip6\",  \"%s\"),\n" //source ip6
			"new it(\"dip6\",  \"%s\"),\n" //dst ip6
#endif
			"new it(\"id\",         %d),\n"
			"new it(\"inf\",    \"%s\"),\n"
			"new it(\"proto\",      %d),\n"
			"new it(\"sport\",      %d),\n"
			"new it(\"dport\",      %d),\n"
			"new it(\"srcip\",  \"%s\"),\n"
			"new it(\"dstip\",  \"%s\"),\n"
			"new it(\"rate\",  \"%d\"),\n"
			"new it(\"direction\",   %d)));\n",
#ifdef CONFIG_IPV6
			entry.IpProtocol, sip6Str, dip6Str,
#endif
			entry.entryid, wanname, entry.protoType, entry.sport,
			entry.dport, sip, dip, entry.limitSpeed,entry.direction);
	}

	return nBytes;
}

void formQosTraffictl(request * wp, char *path, char *query)
{
	char *action = NULL, *url = NULL;
	char *act1="applybandwidth", *act2 = "applysetting";
	char *act4="cancelbandwidth";
	int entryNum = 0;

	PRINT_FUNCTION

	action = boaGetVar(wp, "lst", "");

	entryNum = mib_chain_total(MIB_IP_QOS_TC_TBL);

	if(action[0])
	{
		if( !strncmp(action, act1, strlen(act1)) )
		{//set total bandwidth
			unsigned int totalbandwidth = 0;
			unsigned char totalbandwidthEn=0;
			char* strbandwidth = NULL;
			strbandwidth = strstr(action, "bandwidth=");
			strbandwidth += strlen("bandwidth=");
			if(strbandwidth)//found it
			{
				totalbandwidth = strtoul(strbandwidth, NULL, 0);

				totalbandwidthEn = 1;
				if (!mib_set(MIB_TOTAL_BANDWIDTH_LIMIT_EN, (void *)&totalbandwidthEn)) {
					ERR_MSG("无法启用整体频宽限制!\n"); //Cannot set total bandwidth Enable into mib setting!
					return;
				}

				if(!mib_set(MIB_TOTAL_BANDWIDTH, (void*)&totalbandwidth))
				{
					ERR_MSG("无法设定整体频宽!\n"); //Cannot set total bandwidth into mib setting!
					return;
				}

				//take effect
				take_qos_effect_v3();
			}
			else {
				totalbandwidthEn = 0;
				if (!mib_set(MIB_TOTAL_BANDWIDTH_LIMIT_EN, (void *)&totalbandwidthEn)) {
					ERR_MSG("无法关闭整体频宽限制!\n"); //Cannot set total bandwidth Disable into mib setting!
					return;
				}
			}
		}
		else if ( !strncmp(action, act4, strlen(act4)) )
		{//cancel total bandwidth restrict
			unsigned char totalbandwidthEn=0;
			if (!mib_set(MIB_TOTAL_BANDWIDTH_LIMIT_EN, (void *)&totalbandwidthEn)) {
				ERR_MSG("无法关闭整体频宽限制!\n"); //Cannot disable total bandwidth restrict into mib setting!
				return;
			}

			//take effect
			take_qos_effect_v3();
		}
		else if( !strncmp(action, act2, strlen(act2)) )
		{//delete some
			int idlst[TRAFFICTL_RULE_NUM_MAX+1] = {0};
			int  i=0, j=0, index=1;
			char stridlst[256],err_msg[256], *p = NULL;
			MIB_CE_IP_TC_T entry;

			p = strstr(action, "id=");
			p += strlen("id=");
			if(*p == '\0') {//delete none
				goto done;
			}

			stridlst[0] = '\0';

			strncpy(stridlst, p, 256);

			//convert the id list, store them in idlst,
			//you can delete most 10 rules at one time
			p = strtok(stridlst, SUBDELIM1);
			if(p) index = atoi(p);
			if(index>0&&index<=TRAFFICTL_RULE_NUM_MAX) idlst[index]=1;
			while((p = strtok(NULL, SUBDELIM1)) != NULL)
			{
				index = atoi(p);
				idlst[index]=1;
				if(index > TRAFFICTL_RULE_NUM_MAX )
					break;
			}

			for(i=entryNum-1; i>=0; i--)
			{
				if(!mib_chain_get(MIB_IP_QOS_TC_TBL, i, &entry))
					continue;

				if( 1 == idlst[entry.entryid]) //delete it
				{
					//delete rules of  tc and iptables
					if(1 != mib_chain_delete(MIB_IP_QOS_TC_TBL, i)) {
						snprintf(err_msg, 256, "删除规则%d错误", entry.entryid); //Error happened when deleting rule
						ERR_MSG(err_msg);
						return;
					}
				}
			}

done:
			take_qos_effect_v3();
		}
	}
#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif

	//well, go back
	url = boaGetVar(wp, "submit-url", "");
	if(url[0])
		boaRedirect(wp, url);
	return;
}

//add traffic controlling rules's main function
void formQosTraffictlEdit(request * wp, char *path, char *query)
{
	MIB_CE_IP_TC_T entry;
	char* action=NULL, *url = NULL;
	int entryNum = 0, entryid = 1;
	unsigned char map[TRAFFICTL_RULE_NUM_MAX+1]={0};

	PRINT_FUNCTION

	entryNum = mib_chain_total(MIB_IP_QOS_TC_TBL);

	//You are allowed to have TRAFFICTL_RULE_NUM_MAX rules
	if(entryNum>=TRAFFICTL_RULE_NUM_MAX)
	{
		ERR_MSG("流量控制伫列已满,请删除规则!"); //Traffic controlling queue is full, you must delete some one!
		return;
	}

	action = boaGetVar(wp, "lst", "");

	if(action[0])
	{
		//allocate a free rule id for new entry
		{
			int i = 0;
			for(;i<entryNum;i++)
			{
				if(!mib_chain_get(MIB_IP_QOS_TC_TBL, i, &entry))
					continue;

				map[entry.entryid] = 1;
			}
			for(i=1;i<=TRAFFICTL_RULE_NUM_MAX;i++)
			{
				if(!map[i])
				{
					entryid = i;
					break;
				}
				else if(i==TRAFFICTL_RULE_NUM_MAX)
				{
					ERR_MSG("流量控制伫列已满,请删除规则!"); //Traffic controlling queue is full, you must delete some one!
					return;
				}
			}
		}

		memset(&entry, 0, sizeof(MIB_CE_IP_TC_T));

		entry.entryid = entryid;

		if(parseArgs(action, &entry))
		{//some arguments are wrong
			ERR_MSG("设定错误!"); //Wrong setting is found!
			return;
		}

		PRINT_TRAFFICTL_RULE((&entry));

		#if 0
		/*ql:20080814 START: patch for TnW - while one acl contain other acl, we should change the rule
		* order to enable CAR function.
		*/
		if (entryNum!=0 && !isTraffictlRuleWithPort(&entry)) {
			if (!mib_chain_insert(MIB_IP_QOS_TC_TBL, 0, &entry))
			{
				ERR_MSG("Cannot insert setting into mib!");
				return;
			}
		} else
		#endif
		/*ql:20080814 END*/
		if(!mib_chain_add(MIB_IP_QOS_TC_TBL, &entry))
		{//adding mib setting is wrong
			ERR_MSG("加入失败!"); //Cannot add setting into mib
			return;
		}
	}
#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif
	//redirect
	url = boaGetVar(wp, "submit-url", "");
	if(url[0])
	boaRedirect(wp, url);
	return;
}

/******************************************************************
 * NAME:     formQosRule
 * DESC:     main function deal with qos rules, delete and change
 * ARGS:
 * RETURN:
 ******************************************************************/
void formQosRule(request * wp, char* path, char* query)
{
	MIB_CE_IP_QOS_T entry;
	int entryNum=0, i=0, id = 0;
	unsigned char statuslist[QUEUE_RULE_NUM_MAX+1] = {0}, dellist[QUEUE_RULE_NUM_MAX+1]= {0};
	char* action = NULL, *p=NULL, *url = NULL;

	PRINT_FUNCTION

	//abstract args from string
	action = boaGetVar(wp, "lst", "");
	entryNum = mib_chain_total(MIB_IP_QOS_TBL);

	//printf("action=%s\n", action);
	p = strtok(action, ",&");
	if(p) id = atoi(p);
	if(id<0||id>QUEUE_RULE_NUM_MAX)
		goto END;
	p = strtok(NULL, ",&");
	if(p) statuslist[id] = !!atoi(p);
	p = strtok(NULL, ",&");
	if(p) dellist[id] = !!atoi(p);

	while( (p = strtok(NULL, ",&")) != NULL )
	{
		id = atoi(p);
		if(id<0||id>QUEUE_RULE_NUM_MAX) continue;
		p = strtok(NULL, ",&");
		if(p) statuslist[id] = !!atoi(p);
		p = strtok(NULL, ",&");
		if(p) dellist[id] = !!atoi(p);
	}

	//change status of rules if neccessary
	//printf("check statuslist\n");
	for(i=0;i<entryNum;i++)
	{
		if(!mib_chain_get(MIB_IP_QOS_TBL, i, &entry))
			continue;

		if(statuslist[i] != entry.enable)
		{
			//printf("entry %d status changed\n", i);
			entry.enable = statuslist[i];
			if(!mib_chain_update(MIB_IP_QOS_TBL, &entry, i))
			{
				ERR_MSG("更新规则失败!"); //updating rule error!
				return;
			}
		}
	}

	//printf("check deletelist!\n");
	//delete some one
	for(i=entryNum-1;i>=0;i--)
	{
		if(!mib_chain_get(MIB_IP_QOS_TBL, i, &entry))
			continue;
		if(i<=QUEUE_RULE_NUM_MAX&&dellist[i])
		{
			//printf("entry %d deleted\n", i);
			if(1 != mib_chain_delete(MIB_IP_QOS_TBL, i))
			{
				ERR_MSG("删除规则失败!"); //Delete rule error!
				return;
			}
		}
	}

	//take effect
	take_qos_effect_v3();

#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif

END:
	//redirect to show page
	url = boaGetVar(wp, "submit-url", "");
	if(url[0])
	{
		boaRedirect(wp, url);
	}
	return;
}
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
#if MAX_QOS_QUEUE_NUM==8
char* priorityQueueName[8]={"最高","较高","高","次高","中","次中","低","最低"};
#elif MAX_QOS_QUEUE_NUM==4
char* priorityQueueName[4]={"最高","高","中","低"};
#else
#error "please define MAX_QOS_QUEUE_NUM as 4 or 8"
#endif

int getQosClassficaitonQueueArray(int eid, request * wp, int argc, char **argv){
	MIB_CE_IP_QOS_CLASSFICATION_T entry;
	int entryNum = 0;
	int i=0;	

	entryNum = mib_chain_total(MIB_IP_QOS_CLASSFICATION_TBL);
	for (i = 0; i < entryNum; i++) {
		if (!mib_chain_get(MIB_IP_QOS_CLASSFICATION_TBL, i, &entry)) {
			boaWrite(wp,"[\"N/A\",\"N/A\",\"N/A\",\"N/A\"]");
		}else{	
			boaWrite(wp,"[\"%d\",\"%d\",\"%d\",\"%d\"]\n", entry.cls_id, entry.queue,entry.m_dscp,entry.m_1p);
		}
		if(i!=(MAX_QOS_CLASSFICATION_NUM-1))
			boaWrite(wp,",");
		boaWrite(wp,"\n");
	}
	for(;entryNum<MAX_QOS_CLASSFICATION_NUM;entryNum++){
		boaWrite(wp,"[\"N/A\",\"N/A\",\"N/A\",\"N/A\"]");
		if(entryNum!=(MAX_QOS_CLASSFICATION_NUM-1))
			boaWrite(wp,",");
		boaWrite(wp,"\n");
	}
	return 0;

}


int getQosTypeQueueArray(int eid, request * wp, int argc, char **argv){
	MIB_CE_IP_QOS_CLASSFICATION_T entry;
	int entryNum = 0;
	int i=0;	
	int qos_classfication_index = 0;
	entryNum = mib_chain_total(MIB_IP_QOS_CLASSFICATION_TBL);
	for (qos_classfication_index = IP_QOS_CLASSFICATION_ID_START; qos_classfication_index < entryNum; qos_classfication_index++) {
		int totalQosRuleNum = mib_chain_total(MIB_IP_QOS_CLASSFICATIONTYPE_TBL);
		MIB_CE_IP_QOS_CLASSFICATIONTYPE_T qosentry;
		int j = 0;
		int totalQosRuleNumInOneClassfication = 0;
		MIB_CE_IP_QOS_CLASSFICATION_T clsentry;
		mib_chain_get(MIB_IP_QOS_CLASSFICATION_TBL,qos_classfication_index,&clsentry);
		for(j=0;j<totalQosRuleNum;j++){
			mib_chain_get(MIB_IP_QOS_CLASSFICATIONTYPE_TBL,j,&qosentry);
			if(qosentry.cls_id==clsentry.cls_id){
				boaWrite(wp,"vActObj[ClsCnttemp++] = new QosTypeConstruction(\"%d\",\"%s\",",qos_classfication_index,ip_qos_classficationtype_str[getBitPos(qosentry.classficationType)]);
				switch(qosentry.classficationType){
					case (1<<IP_QOS_CLASSFICATIONTYPE_SMAC):	
						{
							char smacaddr_end[32]={0};
							snprintf(smacaddr_end, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
							qosentry.smac_end[0],qosentry.smac_end[1],
							qosentry.smac_end[2], qosentry.smac_end[3],
							qosentry.smac_end[4], qosentry.smac_end[5]);
							boaWrite(wp,"\"%s\",",smacaddr_end);
							
							char smacaddr[32]={0};
							snprintf(smacaddr, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
							qosentry.smac[0],qosentry.smac[1],
							qosentry.smac[2], qosentry.smac[3],
							qosentry.smac[4], qosentry.smac[5]);
							boaWrite(wp,"\"%s\",",smacaddr);
						}
						break;
					case (1<<IP_QOS_CLASSFICATIONTYPE_DMAC):
						{
							char dmacaddr_end[32]={0};
							snprintf(dmacaddr_end, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
							qosentry.dmac_end[0],qosentry.dmac_end[1],
							qosentry.dmac_end[2], qosentry.dmac_end[3],
							qosentry.dmac_end[4], qosentry.dmac_end[5]);
							boaWrite(wp,"\"%s\",",dmacaddr_end);
							
							char dmacaddr[32]={0};
							snprintf(dmacaddr, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
							qosentry.dmac[0],qosentry.dmac[1],
							qosentry.dmac[2], qosentry.dmac[3],
							qosentry.dmac[4], qosentry.dmac[5]);
							boaWrite(wp,"\"%s\",",dmacaddr);
						}
						break;
					case (1<<IP_QOS_CLASSFICATIONTYPE_8021P):
						boaWrite(wp,"\"%d\",",qosentry.vlan1p_end);
						boaWrite(wp,"\"%d\",",qosentry.vlan1p);
						break;
					case (1<<IP_QOS_CLASSFICATIONTYPE_SIP):						
						boaWrite(wp,"\"%s\",",inet_ntoa(*((struct in_addr*)&(qosentry.sip_end))));
						boaWrite(wp,"\"%s\",",inet_ntoa(*((struct in_addr*)&(qosentry.sip))));
						break;
					case (1<<IP_QOS_CLASSFICATIONTYPE_DIP):						
						boaWrite(wp,"\"%s\",",inet_ntoa(*((struct in_addr*)&(qosentry.dip_end))));
						boaWrite(wp,"\"%s\",",inet_ntoa(*((struct in_addr*)&(qosentry.dip))));
						break;
					case (1<<IP_QOS_CLASSFICATIONTYPE_SPORT):
						boaWrite(wp,"\"%d\",",qosentry.sPortRangeMax);
						boaWrite(wp,"\"%d\",",qosentry.sPort);
						break;
					case (1<<IP_QOS_CLASSFICATIONTYPE_DPORT):
						boaWrite(wp,"\"%d\",",qosentry.dPortRangeMax);
						boaWrite(wp,"\"%d\",",qosentry.dPort);
						break;
					case (1<<IP_QOS_CLASSFICATIONTYPE_TOS):
						boaWrite(wp,"\"%d\",",qosentry.tos);
						boaWrite(wp,"\"%d\",",qosentry.tos);
						break;
					case (1<<IP_QOS_CLASSFICATIONTYPE_DSCP):
						boaWrite(wp,"\"%d\",",qosentry.qosDscp_end);
						boaWrite(wp,"\"%d\",",qosentry.qosDscp);
						break;
#ifdef CONFIG_IPV6
					case (1<<IP_QOS_CLASSFICATIONTYPE_SIP6):					
						{
							char sip6Str[INET6_ADDRSTRLEN] = "";
							inet_ntop(AF_INET6, (const void *)&(qosentry.sip6), sip6Str, INET6_ADDRSTRLEN);
							boaWrite(wp,"\"%s\",", sip6Str);
							boaWrite(wp,"\"%s\",", sip6Str);
						}
						break;
					case (1<<IP_QOS_CLASSFICATIONTYPE_DIP6):					
						{
							char dip6Str[INET6_ADDRSTRLEN] = "";
							inet_ntop(AF_INET6, (const void *)&(qosentry.dip6), dip6Str, INET6_ADDRSTRLEN);
							boaWrite(wp,"\"%s\",", dip6Str);
							boaWrite(wp,"\"%s\",", dip6Str);
						}
						break;
					case (1<<IP_QOS_CLASSFICATIONTYPE_SPORT6):
						boaWrite(wp,"\"%d\",",qosentry.sPort6RangeMax);
						boaWrite(wp,"\"%d\",",qosentry.sPort6);
						break;
					case (1<<IP_QOS_CLASSFICATIONTYPE_DPORT6):
						boaWrite(wp,"\"%d\",",qosentry.dPort6RangeMax);
						boaWrite(wp,"\"%d\",",qosentry.dPort6);
						break;
					case (1<<IP_QOS_CLASSFICATIONTYPE_TrafficClass):
						boaWrite(wp,"\"%d\",",qosentry.tc_end);
						boaWrite(wp,"\"%d\",",qosentry.tc);
						break;
#endif
					case (1<<IP_QOS_CLASSFICATIONTYPE_WANINTERFACE):
						{
							MIB_CE_ATM_VC_T entry;
							int i=0;				
							int totalWanItfNum = mib_chain_total(MIB_ATM_VC_TBL);
							for (i = 0; i < totalWanItfNum; i++) {
								if (mib_chain_get(MIB_ATM_VC_TBL, i, &entry)) {
									if(entry.ifIndex!=qosentry.wanitf)
										continue;
								}
								char wanItfName[MAX_WAN_NAME_LEN]={0};
								getWanName(&entry, wanItfName);
								boaWrite(wp,"\"%s\",",wanItfName);
								boaWrite(wp,"\"%s\",",wanItfName);
								break;
							}							
							
						}
						break;
					case (1<<IP_QOS_CLASSFICATIONTYPE_LANINTERFACE):
						boaWrite(wp,"\"%d\",",qosentry.phyPort_end);
						boaWrite(wp,"\"%d\",",qosentry.phyPort);
						break;
					case (1<<IP_QOS_CLASSFICATIONTYPE_ETHERTYPE):
						if(qosentry.ethType==0x0800){
							boaWrite(wp,"\"IPv4\",");
							boaWrite(wp,"\"IPv4\",");
						}else if(qosentry.ethType==0x86dd){
							boaWrite(wp,"\"IPv6\",");
							boaWrite(wp,"\"IPv6\",");
						}
						break;
					default:
						break;

				}

				boaWrite(wp,"\"%s\");\n",ip_qos_protocol_str[qosentry.protoType]);
				totalQosRuleNumInOneClassfication++;
			}
		
		}
		while(totalQosRuleNumInOneClassfication<MAX_QOS_RULE_NUM_ONE_CLASSFICATION){
			boaWrite(wp,"vActObj[ClsCnttemp++] = new QosTypeConstruction(\"%d\",\"N/A\",\"N/A\",\"N/A\",\"N/A\");\n",clsentry.cls_id);
			totalQosRuleNumInOneClassfication++;
		}
	}
#if 0	
	for(;entryNum<MAX_QOS_CLASSFICATION_NUM;entryNum++){
		int j = 0;
		for(j=0;j<MAX_QOS_RULE_NUM_ONE_CLASSFICATION;j++){
			boaWrite(wp,"vActObj[ClsCnttemp++] = new QosTypeConstruction(\"%d\",\"N/A\",\"N/A\",\"N/A\",\"N/A\");\n",entryNum);
		}
	}
#endif	
	return 0;

}



#endif

int initQueuePolicy(int eid, request * wp, int argc, char **argv)
{
	unsigned char policy = 0;
	char wanname[32];
	int nBytes=0;
	MIB_CE_IP_QOS_QUEUE_T qEntry;
	int qEntryNum, i;
	unsigned int total_bandwidth = 0;
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	unsigned char m_dscp_enable = 0;
	unsigned char m_1p_enable = 0;
	unsigned char m_ip_qos_mandatory_bandwidth_en = 0;
#endif
	PRINT_FUNCTION

	if(mib_get(MIB_TOTAL_BANDWIDTH, &total_bandwidth))
	{
		nBytes += boaWrite(wp, "totalBandwidth=%u;\n", total_bandwidth);
	}
	else
	{
		nBytes += boaWrite(wp, "totalBandwidth=1024;\n");
	}

	if(!mib_get(MIB_QOS_ENABLE_QOS, &policy)|| (policy !=0&&policy!=1))
		policy = 0;
	nBytes = boaWrite(wp, "qosEnable=%d;\n", policy);
	if(!mib_get(MIB_QOS_POLICY, &policy)|| (policy !=0&&policy!=1))
		policy = 0;
	nBytes += boaWrite(wp, "policy=%d;\n", policy);
	
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	if(!mib_get(MIB_QOS_ENABLE_DSCP_MARK, &m_dscp_enable))
			m_dscp_enable = 0;
	nBytes += boaWrite(wp, "m_dscp_enable=%d;\n", m_dscp_enable);
	if(!mib_get(MIB_QOS_ENABLE_1P, &m_1p_enable))
			m_1p_enable = 0;
	nBytes += boaWrite(wp, "m_1p_enable=%d;\n", m_1p_enable);
	
	if(!mib_get(MIB_IP_QOS_MANDATORY_BANDWIDTH_EN, &m_ip_qos_mandatory_bandwidth_en))
				m_ip_qos_mandatory_bandwidth_en = 0;	
	nBytes += boaWrite(wp, "m_ip_qos_mandatory_bandwidth_en=%d;\n", m_ip_qos_mandatory_bandwidth_en);
#endif


	if((qEntryNum=mib_chain_total(MIB_IP_QOS_QUEUE_TBL)) <=0)
		return nBytes;
	for(i=0;i<qEntryNum; i++)
	{
		if(!mib_chain_get(MIB_IP_QOS_QUEUE_TBL, i, (void*)&qEntry))
			continue;
		nBytes += boaWrite(wp, "queues.push("
			"new it_nr(\"%d\","  //qos queue name
			"new it(\"qname\",\"Q%d\"),"  // name
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)		
			"new it(\"prio\",\"%s\"),"  // priority
#else
			"new it(\"prio\",%d),"  // priority
#endif			
			"new it(\"weight\", %d),"  // weight
			"new it(\"enable\", %d)));\n",
			i, i+1,
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)	
			//priorityQueueName[(i>4)?4:i]
			priorityQueueName[i]
#else
			i+1
#endif			
			, qEntry.weight, qEntry.enable);
	}
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	unsigned char up_mode;
	//UP
	mib_get(MIB_DATA_SPEED_LIMIT_UP_MODE, &up_mode);
	nBytes += boaWrite(wp, "var up_mode=%d;\n",up_mode);
#endif
	return nBytes;
}

void formQosPolicy(request * wp, char *path, char *query)
{
	char *action=NULL,*url=NULL, *p=NULL, *tmp=NULL;
	unsigned char policy = 0, modeflag = 0, old_modeflag = 0;
	int num = 0, ret;
	MIB_CE_IP_QOS_QUEUE_T qEntry;

	PRINT_FUNCTION

#if defined(CONFIG_USER_IP_QOS) && defined(_PRMT_X_CT_COM_QOS_)
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	char *qosmode = NULL;
	char old_mode[32] = {0};
	mib_get(CTQOS_MODE, old_mode);

	qosmode = boaGetVar(wp, "TemplateString", "");
	//printf("old_mode = %s, qosmode = %s\n", old_mode, qosmode);
	if (qosmode[0] && strcmp(old_mode, qosmode)) {
		mib_set(CTQOS_MODE, qosmode);
		setMIBforQosMode(qosmode);
	}
#else
	mib_get(CTQOS_MODE, &old_modeflag);
	action = boaGetVar(wp, "qosmode", "");
	if(action[0])
		modeflag = (unsigned char)atoi(action);
	else
		modeflag = OTHERMODE;			

/* TODO: UI should change setting according to the mode and template setting.
 *		 However, current UI is not ready for this. So, just read user setting
 *		 about force_weight/dscp_remark/1p_remark
 *
	if ( !((old_modeflag == OTHERMODE) && (modeflag == OTHERMODE))) {
		ret = setMIBforQosMode(modeflag);	
		if (ret < 0){
			ERR_MSG("Failed to setMIB for QoSMode.\n");
			return;
		}		
	}
*/
#endif

	action = boaGetVar(wp, "enable_force_weight", "");
	if (action[0]) {
		unsigned char value = atoi(action);
		if(!mib_set(MIB_QOS_ENABLE_FORCE_WEIGHT, (void *)&value)){
			ERR_MSG("qos force weight启用/关闭设定失败\n"); //Failed to set qos enable/disable force weight.
			return;
		}
	}

	action = boaGetVar(wp, "enable_dscp_remark", "0");
	if (action[0]) {
		unsigned char value = atoi(action);
		if(!mib_set(MIB_QOS_ENABLE_DSCP_MARK, (void *)&value)){
			ERR_MSG("qos差分服务代码点重标记启用/关闭设定失败\n"); //Failed to set qos enable/disable dscp remark.
			return;
		}
	}

	action = boaGetVar(wp, "enable_1p_remark", "");
	if (action[0]) {
		unsigned char value = atoi(action);
		if(!mib_set(MIB_QOS_ENABLE_1P, (void *)&value)){
		ERR_MSG("qos 1p重标记启用/关闭设定失败\n"); //Failed to set qos enable/disable 1p remark.
		return;
		}
	}

#endif

	action = boaGetVar(wp, "qosen", "");
	if (action[0]) {
		policy = (action[0]=='0') ? 0 : 1;
		mib_set(MIB_QOS_ENABLE_QOS, &policy);
	}
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	else{
		policy =0;
		mib_set(MIB_QOS_ENABLE_QOS, &policy);
	}
#endif

	action = boaGetVar(wp, "lst", "");
	printf("policy: %s\n", action);
	if(action[0])
	{
		//policy
		p = strstr(action, "policy=");
		if(p)
		{
			p+=strlen("policy=");
			num = strtol(p, &tmp, 0);
			//if(tmp && tmp !=p && *tmp == DELIM)
			{
				printf("num=%d\n",num);
				policy = !!num;
				printf("policy=%d\n",policy);
				stopIPQ();
				if(!mib_set(MIB_QOS_POLICY, &policy)) {
					ERR_MSG("qos伫列法则设定失败\n"); //Failed to set qos queue policy.
					return;
				}
			}
		}
	}
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	for (num=0; num<MAX_QOS_QUEUE_NUM; num++) 
#else
	for (num=0; num<4; num++) 
#endif		
	{
		char wstr[]="w0";
		char qenstr[]="qen0";
		if(!mib_chain_get(MIB_IP_QOS_QUEUE_TBL, num, (void*)&qEntry))
			continue;
		if (policy == 1) { // WRR
			wstr[1] += num;
			p = boaGetVar(wp, wstr, "");
			if (p && p[0])
				qEntry.weight = atoi(p);
		}
		qenstr[3] += num;
		p = boaGetVar(wp, qenstr, "");
		if (p && p[0]){
			qEntry.enable = 1;
			//ramen 20171016 avoid the weight 0 cause crash
			if (policy == 1&&qEntry.weight ==0) { // WRR
				qEntry.enable = 0;
			}
		}else
			qEntry.enable = 0;
		mib_chain_update(MIB_IP_QOS_QUEUE_TBL, (void *)&qEntry, num);
	}
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	action = boaGetVar(wp, "total_bandwidth", "0");
#else
	action = boaGetVar(wp, "totalbandwidth", "");
#endif
	if (action[0]) {
		unsigned int totalbandwidth = 0;
		totalbandwidth = strtoul(action, NULL, 0);
		if(!mib_set(MIB_TOTAL_BANDWIDTH, (void*)&totalbandwidth))
		{
			ERR_MSG("formQosPolicy: 整体频宽设定失败!\n"); //formQosPolicy: Cannot set total bandwidth into mib setting!
			return;
		}
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		unsigned char totalBandWidthEn = totalbandwidth?1:0;
		mib_set(MIB_TOTAL_BANDWIDTH_LIMIT_EN, (void *)&totalBandWidthEn);			
#endif

	}
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)	
	mib_get(MIB_QOS_POLICY, &policy);
	if(policy==0){
		//PRQ
		//action = boaGetVar(wp, "ip_qos_mandatory_bandwith_en", "");
		action = "";
	}else{
		action = boaGetVar(wp, "ip_qos_mandatory_bandwith_en", "0");
	}
	//printf("policy=%d\n",policy);
	if (action[0]) {
		policy = (action[0]=='0') ? 0 : 1;
		mib_set(MIB_IP_QOS_MANDATORY_BANDWIDTH_EN, &policy);
		//printf("ip_qos_mandatory_bandwith_en=%d\n",policy);
		unsigned int totalbandwidth = 0;
		uint queue_weight[MAX_QOS_QUEUE_NUM]={0};
		int totalweight = 0;
		if(mib_get(MIB_TOTAL_BANDWIDTH, (void*)&totalbandwidth)){
			if(!policy)
				totalbandwidth = 0;
			totalbandwidth = totalbandwidth/1024;
			printf("totalbandwidth=%d\n",totalbandwidth);
			for (num=0; num<MAX_QOS_QUEUE_NUM; num++) {
				if(!mib_chain_get(MIB_IP_QOS_QUEUE_TBL, num, (void*)&qEntry))
					continue;
				queue_weight[num]=qEntry.weight;
				totalweight+=queue_weight[num];
			}
			//calc the uprate for each queue according with weight
						
			for (num=0; num<MAX_QOS_QUEUE_NUM; num++) {
				if(!mib_chain_get(MIB_IP_QOS_QUEUE_TBL, num, (void*)&qEntry))
					continue;
				qEntry.upmaxrate=totalbandwidth*queue_weight[num]/totalweight;
				printf("qEntry.upmaxrate=%d\n",qEntry.upmaxrate);
				mib_chain_update(MIB_IP_QOS_QUEUE_TBL,&qEntry,num);
			}
		}
	}else{
			for (num=0; num<MAX_QOS_QUEUE_NUM; num++) {
				if(!mib_chain_get(MIB_IP_QOS_QUEUE_TBL, num, (void*)&qEntry))
					continue;
				qEntry.upmaxrate=0;
				mib_chain_update(MIB_IP_QOS_QUEUE_TBL,&qEntry,num);
			}
	}
#endif



done:

#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif

	//take effect
	take_qos_effect_v3();

	//redirect web page
	url = boaGetVar(wp, "submit-url", "");
	if(url[0])
	{
		boaRedirect(wp, url);
	}
	return;
}

#ifdef _PRMT_X_CT_COM_DATA_SPEED_LIMIT_
int initQosSpeedLimitRule(int eid, request * wp, int argc, char **argv)
{
	int nBytes = 0;
	unsigned char mode = 0;
	int i = 0, totalNum = 0;
	MIB_CE_DATA_SPEED_LIMIT_IF_T if_entry;
	MIB_CE_DATA_SPEED_LIMIT_VLAN_T vlan_entry;
	MIB_CE_DATA_SPEED_LIMIT_IP_T ip_entry;

	mib_get(MIB_DATA_SPEED_LIMIT_UP_MODE, &mode);
	nBytes += boaWrite(wp, "rule_mode_up = %u;\n", mode);

	mib_get(MIB_DATA_SPEED_LIMIT_DOWN_MODE, &mode);
	nBytes += boaWrite(wp, "rule_mode_down = %u;\n", mode);


	totalNum = mib_chain_total(MIB_DATA_SPEED_LIMIT_UP_IF_TBL);
	for (i = 0; i < totalNum; i++)
	{
		if (!mib_chain_get(MIB_DATA_SPEED_LIMIT_UP_IF_TBL, i, (void*)&if_entry))
			continue;

		nBytes += boaWrite(wp, "rule_intf_up.push("
								"new it_nr(\"%d\","
								"new it(\"idx\", %d),"
								"new it(\"if_id\", \"%d\"),"
								"new it(\"speed_unit\", %d)));\n",
								i,
								i,
								if_entry.if_id,
								if_entry.speed_unit);
	}

	totalNum = mib_chain_total(MIB_DATA_SPEED_LIMIT_DOWN_IF_TBL);
	for (i = 0; i < totalNum; i++)
	{
		if (!mib_chain_get(MIB_DATA_SPEED_LIMIT_DOWN_IF_TBL, i, (void*)&if_entry))
			continue;

		nBytes += boaWrite(wp, "rule_intf_down.push("
								"new it_nr(\"%d\","
								"new it(\"idx\", %d),"
								"new it(\"if_id\", \"%d\"),"
								"new it(\"speed_unit\", %d)));\n",
								i,
								i,
								if_entry.if_id,
								if_entry.speed_unit);
	}

	totalNum = mib_chain_total(MIB_DATA_SPEED_LIMIT_UP_VLAN_TBL);
	for (i = 0; i < totalNum; i++)
	{
		if (!mib_chain_get(MIB_DATA_SPEED_LIMIT_UP_VLAN_TBL, i, (void*)&vlan_entry))
			continue;

		if(vlan_entry.vlan == -1)
		{
			nBytes += boaWrite(wp, "rule_vlan_up.push("
								"new it_nr(\"%d\","
								"new it(\"idx\", %d),"
								"new it(\"vlan\", \"untagged\"),"
								"new it(\"speed_unit\", %d)));\n",
								i,
								i,
								vlan_entry.speed_unit);
		}
		else
		{
			nBytes += boaWrite(wp, "rule_vlan_up.push("
								"new it_nr(\"%d\","
								"new it(\"idx\", %d),"
								"new it(\"vlan\", \"%d\"),"
								"new it(\"speed_unit\", %d)));\n",
								i,
								i,
								vlan_entry.vlan,
								vlan_entry.speed_unit);
		}
	}

	totalNum = mib_chain_total(MIB_DATA_SPEED_LIMIT_DOWN_VLAN_TBL);
	for (i = 0; i < totalNum; i++)
	{
		if (!mib_chain_get(MIB_DATA_SPEED_LIMIT_DOWN_VLAN_TBL, i, (void*)&vlan_entry))
			continue;

		nBytes += boaWrite(wp, "rule_vlan_down.push("
								"new it_nr(\"%d\","
								"new it(\"idx\", %d),"
								"new it(\"vlan\", %d),"
								"new it(\"speed_unit\", %d)));\n",
								i,
								i,
								vlan_entry.vlan,
								vlan_entry.speed_unit);
	}

	totalNum = mib_chain_total(MIB_DATA_SPEED_LIMIT_UP_IP_TBL);
	for (i = 0; i < totalNum; i++)
	{
		if (!mib_chain_get(MIB_DATA_SPEED_LIMIT_UP_IP_TBL, i, (void*)&ip_entry))
			continue;

		nBytes += boaWrite(wp, "rule_ip_up.push("
								"new it_nr(\"%d\","
								"new it(\"idx\", %d),"
								"new it(\"ip_start\", \"%s\"),"
								"new it(\"ip_end\", \"%s\"),"
								"new it(\"speed_unit\", %d)));\n",
								i,
								i,
								ip_entry.ip_start,
								ip_entry.ip_end,
								ip_entry.speed_unit);
	}

	totalNum = mib_chain_total(MIB_DATA_SPEED_LIMIT_DOWN_IP_TBL);
	for (i = 0; i < totalNum; i++)
	{
		if (!mib_chain_get(MIB_DATA_SPEED_LIMIT_DOWN_IP_TBL, i, (void*)&ip_entry))
			continue;

		nBytes += boaWrite(wp, "rule_ip_down.push("
								"new it_nr(\"%d\","
								"new it(\"idx\", %d),"
								"new it(\"ip_start\", \"%s\"),"
								"new it(\"ip_end\", \"%s\"),"
								"new it(\"speed_unit\", %d)));\n",
								i,
								i,
								ip_entry.ip_start,
								ip_entry.ip_end,
								ip_entry.speed_unit);
	}

	return nBytes;
}

void formQosSpeedLimit(request * wp, char *path, char *query)
{
	char *action = NULL, *url = NULL;
	char Mode_up = 0, Mode_down = 0;
	int chain_id = 0, chain_index = -1, chain_action = 0;

	enum
	{
		CHAIN_ACTION_NONE = 0,
		CHAIN_ACTION_ADD,
		CHAIN_ACTION_EDIT,
		CHAIN_ACTION_DEL
	};

	action = boaGetVar(wp, "ModeSwitch_up", "");
	if (action[0]) {
		printf("ModeSwitch_up = %s\n", action);
		Mode_up = atoi(action);
	}
	
	action = boaGetVar(wp, "ModeSwitch_down", "");
	if (action[0]) {
		printf("ModeSwitch_down = %s\n", action);
		Mode_down = atoi(action);
	}

	action = boaGetVar(wp, "submitAction", "");
	if (action[0]) {
		printf("submitAction = %s\n", action);
		if (strcmp(action, "mode") == 0) {
			mib_set(MIB_DATA_SPEED_LIMIT_UP_MODE, &Mode_up);
			mib_set(MIB_DATA_SPEED_LIMIT_DOWN_MODE, &Mode_down);
		}
		else if (strcmp(action, "rule") == 0) {
			action = boaGetVar(wp, "ruleDirection", "");
			if (action[0]) {
				printf("ruleDirection = %s\n", action);
				if (strcmp(action, "up") == 0) {
					action = boaGetVar(wp, "ruleIndex_up", "");
					if (action[0]) {
						printf("ruleIndex_up = %s\n", action);
						chain_index = atoi(action);
					}

					action = boaGetVar(wp, "ruleAction_up", "");
					if (action[0]) {
						printf("ruleAction_up = %s\n", action);
						if (strcmp(action, "add") == 0) {
							chain_action = CHAIN_ACTION_ADD;
						}
						else if (strcmp(action, "edit") == 0) {
							chain_action = CHAIN_ACTION_EDIT;
						}
						else if (strcmp(action, "del") == 0) {
							chain_action = CHAIN_ACTION_DEL;
						}
					}

					if (Mode_up == 1) { // Interface
						MIB_CE_DATA_SPEED_LIMIT_IF_T entry;
						chain_id = MIB_DATA_SPEED_LIMIT_UP_IF_TBL;

						action = boaGetVar(wp, "InterfaceName_up", "");
						if (action[0]) {
							printf("InterfaceName_up = %s\n", action);
							entry.if_id = atoi(action);
						}

						action = boaGetVar(wp, "InterfaceSpeed_up", "");
						if (action[0]) {
							printf("InterfaceSpeed_up = %s\n", action);
							entry.speed_unit = atoi(action);
						}

						switch (chain_action)
						{
							case CHAIN_ACTION_ADD:
								mib_chain_add(chain_id, (void *)&entry);
								break;

							case CHAIN_ACTION_EDIT:
								if (chain_index >= 0) {
									mib_chain_update(chain_id, (void *)&entry, chain_index);
								}
								break;

							case CHAIN_ACTION_DEL:
								if (chain_index >= 0) {
									mib_chain_delete(chain_id, chain_index);
								}
								break;

							default:
								break;
						}
					}
					else if (Mode_up == 2) { // VlanTag
						MIB_CE_DATA_SPEED_LIMIT_VLAN_T entry;
						chain_id = MIB_DATA_SPEED_LIMIT_UP_VLAN_TBL;

						action = boaGetVar(wp, "VlanTagValue_up", "");
						if (action[0]) {
							printf("VlanTagValue_up = %s\n", action);
							if (strcasecmp(action, "untagged") == 0) {
								entry.vlan = -1;
							}
							else {
								entry.vlan = atoi(action);
							}
						}

						action = boaGetVar(wp, "VlanTagSpeed_up", "");
						if (action[0]) {
							printf("VlanTagSpeed_up = %s\n", action);
							entry.speed_unit = atoi(action);
						}

						switch (chain_action)
						{
							case CHAIN_ACTION_ADD:
								mib_chain_add(chain_id, (void *)&entry);
								break;

							case CHAIN_ACTION_EDIT:
								if (chain_index >= 0) {
									mib_chain_update(chain_id, (void *)&entry, chain_index);
								}
								break;

							case CHAIN_ACTION_DEL:
								if (chain_index >= 0) {
									mib_chain_delete(chain_id, chain_index);
								}
								break;

							default:
								break;
						}
					}
					else if (Mode_up == 3) { // IP
						MIB_CE_DATA_SPEED_LIMIT_IP_T entry;
						chain_id = MIB_DATA_SPEED_LIMIT_UP_IP_TBL;
						char ip_start[64] = {0}, ip_end[64] = {0};
						struct addrinfo hint, *res_start = NULL, *res_end = NULL;
						int ret = 0;

						action = boaGetVar(wp, "IP_Start_up", "");
						if (action[0]) {
							printf("IP_Start_up = %s\n", action);
							strncpy(ip_start, action, sizeof(ip_start));
						}

						action = boaGetVar(wp, "IP_End_up", "");
						if (action[0]) {
							printf("IP_End_up = %s\n", action);
							strncpy(ip_end, action, sizeof(ip_end));
						}

						memset(&hint, 0, sizeof(hint));

						hint.ai_family = PF_UNSPEC;
						hint.ai_flags = AI_NUMERICHOST;

						ret = getaddrinfo(ip_start, NULL, &hint, &res_start);
						if (ret) {
							printf("Invalid start address %s: %s\n", ip_start, gai_strerror(ret));
							ERR_MSG("Invalid start address");
							return;
						}

						ret = getaddrinfo(ip_end, NULL, &hint, &res_end);
						if (ret) {
							printf("Invalid end address %s: %s\n", ip_end, gai_strerror(ret));
							ERR_MSG("Invalid end address");
							return;
						}

						if (res_start->ai_family != res_end->ai_family) {
							printf("start address family != end address family\n");
							ERR_MSG("Invalid start or end address");
							return;
						}

						if(res_start->ai_family == AF_INET) {
							entry.ip_ver = IPVER_IPV4;
						}
						else if (res_start->ai_family == AF_INET6) {
							entry.ip_ver = IPVER_IPV6;
						}
						else {
							printf("%s is an is unknown address format %d\n", ip_start, res_start->ai_family);
							ERR_MSG("Unknown address format");
							return;
						}

						strcpy(entry.ip_start, ip_start);
						strcpy(entry.ip_end, ip_end);
						freeaddrinfo(res_start);
						freeaddrinfo(res_end);

						action = boaGetVar(wp, "IPSpeed_up", "");
						if (action[0]) {
							printf("IPSpeed_up = %s\n", action);
							entry.speed_unit = atoi(action);
						}

						switch (chain_action)
						{
							case CHAIN_ACTION_ADD:
								mib_chain_add(chain_id, (void *)&entry);
								break;

							case CHAIN_ACTION_EDIT:
								if (chain_index >= 0) {
									mib_chain_update(chain_id, (void *)&entry, chain_index);
								}
								break;

							case CHAIN_ACTION_DEL:
								if (chain_index >= 0) {
									mib_chain_delete(chain_id, chain_index);
								}
								break;

							default:
								break;
						}
					}
				}
				else if (strcmp(action, "down") == 0) {
					action = boaGetVar(wp, "ruleIndex_down", "");
					if (action[0]) {
						printf("ruleIndex_down = %s\n", action);
						chain_index = atoi(action);
					}
					
					action = boaGetVar(wp, "ruleAction_down", "");
					if (action[0]) {
						printf("ruleAction_down = %s\n", action);
						if (strcmp(action, "add") == 0) {
							chain_action = CHAIN_ACTION_ADD;
						}
						else if (strcmp(action, "edit") == 0) {
							chain_action = CHAIN_ACTION_EDIT;
						}
						else if (strcmp(action, "del") == 0) {
							chain_action = CHAIN_ACTION_DEL;
						}
					}

					if (Mode_down == 1) { // Interface
						MIB_CE_DATA_SPEED_LIMIT_IF_T entry;
						chain_id = MIB_DATA_SPEED_LIMIT_DOWN_IF_TBL;

						action = boaGetVar(wp, "InterfaceName_down", "");
						if (action[0]) {
							printf("InterfaceName_down = %s\n", action);
							entry.if_id = atoi(action);
						}

						action = boaGetVar(wp, "InterfaceSpeed_down", "");
						if (action[0]) {
							printf("InterfaceSpeed_down = %s\n", action);
							entry.speed_unit = atoi(action);
						}

						switch (chain_action)
						{
							case CHAIN_ACTION_ADD:
								mib_chain_add(chain_id, (void *)&entry);
								break;

							case CHAIN_ACTION_EDIT:
								if (chain_index >= 0) {
									mib_chain_update(chain_id, (void *)&entry, chain_index);
								}
								break;

							case CHAIN_ACTION_DEL:
								if (chain_index >= 0) {
									mib_chain_delete(chain_id, chain_index);
								}
								break;

							default:
								break;
						}
					}
					else if (Mode_down == 2) { // VlanTag
						MIB_CE_DATA_SPEED_LIMIT_VLAN_T entry;
						chain_id = MIB_DATA_SPEED_LIMIT_DOWN_VLAN_TBL;

						action = boaGetVar(wp, "VlanTagValue_down", "");
						if (action[0]) {
							printf("VlanTagValue_down = %s\n", action);
							if (strcasecmp(action, "untagged") == 0) {
								entry.vlan = -1;
							}
							else {
								entry.vlan = atoi(action);
							}
						}

						action = boaGetVar(wp, "VlanTagSpeed_down", "");
						if (action[0]) {
							printf("VlanTagSpeed_down = %s\n", action);
							entry.speed_unit = atoi(action);
						}

						switch (chain_action)
						{
							case CHAIN_ACTION_ADD:
								mib_chain_add(chain_id, (void *)&entry);
								break;

							case CHAIN_ACTION_EDIT:
								if (chain_index >= 0) {
									mib_chain_update(chain_id, (void *)&entry, chain_index);
								}
								break;

							case CHAIN_ACTION_DEL:
								if (chain_index >= 0) {
									mib_chain_delete(chain_id, chain_index);
								}
								break;

							default:
								break;
						}
					}
					else if (Mode_down == 3) { // IP
						MIB_CE_DATA_SPEED_LIMIT_IP_T entry;
						chain_id = MIB_DATA_SPEED_LIMIT_DOWN_IP_TBL;
						char ip_start[64] = {0}, ip_end[64] = {0};
						struct addrinfo hint, *res_start = NULL, *res_end = NULL;
						int ret = 0;

						action = boaGetVar(wp, "IP_Start_down", "");
						if (action[0]) {
							printf("IP_Start_down = %s\n", action);
							strncpy(ip_start, action, sizeof(ip_start));
						}

						action = boaGetVar(wp, "IP_End_down", "");
						if (action[0]) {
							printf("IP_End_down = %s\n", action);
							strncpy(ip_end, action, sizeof(ip_end));
						}

						memset(&hint, 0, sizeof(hint));
						hint.ai_family = PF_UNSPEC;
						hint.ai_flags = AI_NUMERICHOST;

						ret = getaddrinfo(ip_start, NULL, &hint, &res_start);
						if (ret) {
							printf("Invalid start address %s: %s\n", ip_start, gai_strerror(ret));
							ERR_MSG("Invalid start address");
							return;
						}

						ret = getaddrinfo(ip_end, NULL, &hint, &res_end);
						if (ret) {
							printf("Invalid end address %s: %s\n", ip_end, gai_strerror(ret));
							ERR_MSG("Invalid end address");
							return;
						}

						if (res_start->ai_family != res_end->ai_family) {
							printf("start address family != end address family\n");
							ERR_MSG("Invalid start or end address");
							return;
						}

						if(res_start->ai_family == AF_INET) {
							entry.ip_ver = IPVER_IPV4;
						}
						else if (res_start->ai_family == AF_INET6) {
							entry.ip_ver = IPVER_IPV6;
						}
						else {
							printf("%s is an is unknown address format %d\n", ip_start, res_start->ai_family);
							ERR_MSG("Unknown address format");
							return;
						}

						strcpy(entry.ip_start, ip_start);
						strcpy(entry.ip_end, ip_end);
						freeaddrinfo(res_start);
						freeaddrinfo(res_end);

						action = boaGetVar(wp, "IPSpeed_down", "");
						if (action[0]) {
							printf("IPSpeed_down = %s\n", action);
							entry.speed_unit = atoi(action);
						}

						switch (chain_action)
						{
							case CHAIN_ACTION_ADD:
								mib_chain_add(chain_id, (void *)&entry);
								break;

							case CHAIN_ACTION_EDIT:
								if (chain_index >= 0) {
									mib_chain_update(chain_id, (void *)&entry, chain_index);
								}
								break;

							case CHAIN_ACTION_DEL:
								if (chain_index >= 0) {
									mib_chain_delete(chain_id, chain_index);
								}
								break;

							default:
								break;
						}
					}
				}
			}
		}
	}

#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif
	//take effect
	take_qos_effect_v3();

	//redirect web page
	url = boaGetVar(wp, "submit-url", "");
	if (url[0]) {
		boaRedirect(wp, url);
	}
	return;
}
#endif

int ipqos_dhcpopt(int eid, request * wp, int argc, char **argv)
{
	int nBytes = 0;

#ifdef CONFIG_BRIDGE_EBT_DHCP_OPT
	nBytes += boaWrite(wp, " <td><font size=2><input type=\"radio\"  name=qos_rule_type value=4 onClick=ruleType_click();> DHCP Option</td>");	
#endif

	return nBytes;
}


int ipqos_dhcpopt_getoption60(int eid, request * wp, int argc, char **argv)
{
	int nBytes = 0, index=0;
	MIB_CE_IP_QOS_T entry;
	int start=0,end=0,len=0;
	char index_buf[3]={0};

#ifdef CONFIG_BRIDGE_EBT_DHCP_OPT
	if(wp->query_string)
	{
		start = strstr(wp->query_string,"rule_index=")+sizeof("rule_index=")-1;
		end = strstr(wp->query_string,"&rule");
		len=end-start;
		if(start&&end&&(len>0))
		{
			memcpy(index_buf,start,len);

			index= atoi(index_buf);
	if(!mib_chain_get(MIB_IP_QOS_TBL, index, &entry))
			return;
	nBytes += boaWrite(wp, "%s", entry.opt60_vendorclass);	
		}
	}
#endif

	return nBytes;

}
