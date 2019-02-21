/*
 *      System routines for IP QoS
 *
 */

#define _GNU_SOURCE

#include "debug.h"
#include "utility.h"
#include <signal.h>
#include <string.h>
#include <netdb.h>
#include "rtusr_rg_api.h"
#include <arpa/inet.h>
#include <stdlib.h>

#define QOS_SETUP_DEBUG   1// for qos debug
#define MAX_PORT(val1, val2) (val1>val2?val1:val2)
#define MIN_PORT(val1, val2) (val1<val2?val1:val2)
const char QOS_IP_CHAIN[] =  "qos_ip_rules";
const char QOS_EB_CHAIN[] =  "qos_eb_rules";
const char QOS_RTP_CHAIN[] =  "qos_rtp_rules";
const char CAR_FILTER_CHAIN[] =  "car_filter";
const char CAR_TRAFFIC_CHAIN[] =  "car_traffic_qos";
static unsigned int qos_setup_debug = 3;


#ifdef QOS_SETUP_DEBUG
#define QOS_SETUP_PRINT_FUNCTION                    \
    do{if(qos_setup_debug&0x1) fprintf(stderr,"%s: %s  %d\n", __FILE__, __FUNCTION__,__LINE__);}while(0);

#define QOS_SETUP_PRINT(fmt, args...)        \
    do{if(qos_setup_debug&0x2) fprintf(stderr,fmt, ##args);}while(0)
#else
#define QOS_SETUP_PRINT_FUNCTION do{}while(0);
#define QOS_SETUP_PRINT(fmt, args...) do{}while(0)
#endif

#define RTP_RULE_NUM_MAX     256

#define QOS_WAN_ENABLE		0x01
#define QOS_WAN_VLAN_ENABLE	0x02
#define QOS_WAN_BRIDGE		0x04
#define QOS_WAN_TR069		0x08

#define QOS_MARK_MASK		0x1FFFF
#define QOS_8021P_MASK		0xFF

#ifdef QOS_SUPPORT_RTP
#define RTP_PORT_FILE	"/proc/net/ip_qos_rtp"
#endif

static char* proto2str[] = {
    [0]" ",
    [1]"-p TCP",
    [2]"-p UDP",
	[3]"-p ICMP",
};

static char* proto2str2layer[] = {
    [0]" ",
    [1]"--ip-proto 6",
    [2]"--ip-proto 17",
	[3]"--ip-proto 1",
};

#ifdef CONFIG_IPV6
static char* proto2str_v6[] = {
    [0]" ",
    [1]"-p TCP",
    [2]"-p UDP",
	[3]"-p ICMPV6",
};

static char* proto2str2layer_v6[] = {
    [0]" ",
    [1]"--ip6-proto 6",
    [2]"--ip6-proto 17",
	[3]"--ip6-proto 58",
};
#endif

static unsigned int current_uprate;

static int hwnat_qos_translate_rule(MIB_CE_IP_QOS_Tp qEntry){
        return 0;
}



int findQueueMinWeigh()
{
	int nBytes=0;
	MIB_CE_IP_QOS_QUEUE_T qEntry;
	int qEntryNum, i;

	if((qEntryNum=mib_chain_total(MIB_IP_QOS_QUEUE_TBL)) <=0)
		return nBytes;
	for(i=0;i<qEntryNum; i++)
	{
		if(!mib_chain_get(MIB_IP_QOS_QUEUE_TBL, i, (void*)&qEntry))
			continue;
		if ( !qEntry.enable)
			continue;

		if(nBytes==0)
			nBytes = qEntry.weight;

		if(qEntry.weight < nBytes)
			nBytes = qEntry.weight;
	}
	return nBytes;
}

int ifSumWeighIs100()
{
	int sum=0;
	MIB_CE_IP_QOS_QUEUE_T qEntry;
	int qEntryNum, i;

	if((qEntryNum=mib_chain_total(MIB_IP_QOS_QUEUE_TBL)) <=0)
		return 0;
	for(i=0;i<qEntryNum; i++)
	{
		if(!mib_chain_get(MIB_IP_QOS_QUEUE_TBL, i, (void*)&qEntry))
			continue;
		if ( !qEntry.enable)
			continue;
		sum += qEntry.weight;
	}

	if (sum == 100)
		return 1;
	else
		return 0;
}

int isQueneEnableForRule(unsigned char prior)
{
	MIB_CE_IP_QOS_QUEUE_T qEntry;
	int qEntryNum, j;

	if((qEntryNum=mib_chain_total(MIB_IP_QOS_QUEUE_TBL)) <=0)
		return 0;
	for(j=0;j<qEntryNum; j++)
	{
		if(!mib_chain_get(MIB_IP_QOS_QUEUE_TBL, j, (void*)&qEntry))
			continue;
		if (j == (prior-1))
		{
			if (qEntry.enable)
				return 1;
			break;
		}
	}
	return 0;
}

int set_wrr_class_qdisc()
{
	MIB_CE_IP_QOS_QUEUE_T qEntry;
	int qEntryNum, minWeigh, j;
	char *devname="imq0";
	char s_classid[16], s_handle[16], s_qlen[16];

	if((qEntryNum=mib_chain_total(MIB_IP_QOS_QUEUE_TBL)) <=0)
		return 0;
	for(j=0;j<qEntryNum; j++)
	{
		if(!mib_chain_get(MIB_IP_QOS_QUEUE_TBL, j, (void*)&qEntry))
			continue;
		if ( !qEntry.enable)
			continue;

		snprintf(s_classid, 16, "1:%d00", j+1);
		snprintf(s_handle, 16, "%d00:", j+1);
		minWeigh = findQueueMinWeigh();
		snprintf(s_qlen, 16, "%d", 30*qEntry.weight/100);
		//printf("set_wrr_class_qdisc: s_qlen=%s\n", s_qlen);

		va_cmd(TC, 11, 1, "qdisc", (char *)ARG_ADD, "dev", devname,
		"parent", s_classid, "handle", s_handle, "pfifo", "limit", s_qlen);

	}
	return 1;
}

//get state about qos from pvc interface, 0: false, 1: true
#ifdef BR_ROUTE_ONEPVC
static unsigned int get_pvc_qos_state(unsigned int ifIndex, unsigned char cmode)
#else
static unsigned int get_pvc_qos_state(unsigned int ifIndex)
#endif
{
	MIB_CE_ATM_VC_T entry;
	int i, entryNum = 0;
	unsigned int ret = 0;

	// Mason Yu.
	if ( ifIndex == DUMMY_IFINDEX )
		return QOS_WAN_VLAN_ENABLE;

	entryNum = mib_chain_total(MIB_ATM_VC_TBL);
	for(i = 0; i< entryNum; i++)
	{
		if(!mib_chain_get(MIB_ATM_VC_TBL, i, &entry))
			continue;

#ifdef BR_ROUTE_ONEPVC
		if (entry.cmode != cmode)
			continue;
#endif
		if(entry.ifIndex == ifIndex)
		{
			if(entry.enableIpQos)
				ret |= QOS_WAN_ENABLE;
			if(entry.vlan)
				ret |= QOS_WAN_VLAN_ENABLE;
#ifndef BR_ROUTE_ONEPVC
			if (entry.cmode == CHANNEL_MODE_BRIDGE)
				ret |= QOS_WAN_BRIDGE;
#endif
			// Mason Yu.
#if 0
			/*ql:20080825 START: for tr069 pvc, just set priority according to wanport*/
			if (entry.applicationtype&X_CT_SRV_TR069)
			//if (entry.applicationtype == APPTYPE_TR069)//tr069
				ret |= QOS_WAN_TR069;
			/*ql:20080825 END*/
#endif
			break;
		}
	}

	return ret;
}

unsigned int getUpLinkRate()
{
	unsigned int total_bandwidth = 1024;//default to be 1Mbps

	//  Because we can not distinguish total bandwidth. It is for total bandwidth limit. Let user to input total bandwidth.
	if(mib_get(MIB_TOTAL_BANDWIDTH, &total_bandwidth))
	{
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		total_bandwidth = total_bandwidth/1024;
#endif
		return total_bandwidth;
	}
	else
		return 1024;
}

// QoS Enable

#ifdef BR_ROUTE_ONEPVC
static int isPvcQosEnable(MIB_CE_ATM_VC_Tp brgEntry)
{
	MIB_CE_ATM_VC_T vcEntry;
	int i, entryNum;

	entryNum = mib_chain_total(MIB_ATM_VC_TBL);
	for(i=0; i<entryNum; i++)
	{
		if(!mib_chain_get(MIB_ATM_VC_TBL, i, (void*)&vcEntry)||!vcEntry.br_route_flag)
			continue;

		if ((vcEntry.vpi==brgEntry->vpi) && (vcEntry.vci==brgEntry->vci))
		{
			if (vcEntry.cmode == CHANNEL_MODE_IPOE)
			{
				if (vcEntry.enableIpQos)
					return 1;
				else
					return 0;
			}
		}
	}

	return 0;
}
#endif


int getQosEnable()
{
	unsigned char qosEnable;

	mib_get(MIB_QOS_ENABLE_QOS, (void*)&qosEnable);
	return (int)qosEnable;
}

int getQosRuleNum()
{
	MIB_CE_IP_QOS_T entry;
	int i, ruleNum;
	int sum=0;

	ruleNum = mib_chain_total(MIB_IP_QOS_TBL);
	if (0 == ruleNum)
		return 0;

	for (i=0; i<ruleNum; i++)
	{
		if (!mib_chain_get(MIB_IP_QOS_TBL, i, (void *)&entry) || !entry.enable)
			continue;

		sum++;
	}

	return(sum);
}

static int isQosMacRule(MIB_CE_IP_QOS_Tp pEntry)
{
	if (pEntry->protoType || pEntry->sip || pEntry->dip || pEntry->sPort ||
		pEntry->dPort
#ifdef QOS_DIFFSERV
		|| pEntry->qosDscp
#endif
		)
		return 0;
	return 1;
}

static int mac_hex2string(unsigned char *hex, char *str)
{
	snprintf(str, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
		hex[0], hex[1],	hex[2], hex[3],	hex[4], hex[5]);
	return 0;
}

static int setupCarChain(unsigned int enable)
{
	QOS_SETUP_PRINT_FUNCTION

	if (enable)
	{
		va_cmd(IPTABLES, 2, 1, "-N", CAR_FILTER_CHAIN);
		va_cmd(IPTABLES, 5, 1, "-I", "FORWARD", "1", "-j", CAR_FILTER_CHAIN);

		va_cmd(IPTABLES, 4, 1, "-t", "mangle", "-N", CAR_TRAFFIC_CHAIN);
		va_cmd(IPTABLES, 6, 1, "-t", "mangle", "-A", "POSTROUTING", "-j", CAR_TRAFFIC_CHAIN);

		va_cmd(IPTABLES, 4, 1, "-t", "mangle", "-N", "pvc_mark");
		va_cmd(IPTABLES, 6, 1, "-t", "mangle", "-A", "POSTROUTING", "-j", "pvc_mark");

		#ifdef CONFIG_IPV6
		va_cmd(IP6TABLES, 2, 1, "-N", CAR_FILTER_CHAIN);
		va_cmd(IP6TABLES, 5, 1, "-I", "FORWARD", "1", "-j", CAR_FILTER_CHAIN);

		va_cmd(IP6TABLES, 4, 1, "-t", "mangle", "-N", CAR_TRAFFIC_CHAIN);
		va_cmd(IP6TABLES, 6, 1, "-t", "mangle", "-A", "POSTROUTING", "-j", CAR_TRAFFIC_CHAIN);

		va_cmd(IP6TABLES, 4, 1, "-t", "mangle", "-N", "pvc_mark");
		va_cmd(IP6TABLES, 6, 1, "-t", "mangle", "-A", "POSTROUTING", "-j", "pvc_mark");
		#endif
	} else {
		va_cmd(IPTABLES, 2, 1, "-F", CAR_FILTER_CHAIN);
		va_cmd(IPTABLES, 4, 1, "-t", "mangle", "-F", "pvc_mark");
		va_cmd(IPTABLES, 4, 1, "-t", "mangle", "-F", CAR_TRAFFIC_CHAIN);

		va_cmd(IPTABLES, 4, 1, "-D", "FORWARD", "-j", CAR_FILTER_CHAIN);
		va_cmd(IPTABLES, 6, 1, "-t", "mangle", "-D", "POSTROUTING", "-j", "pvc_mark");
		va_cmd(IPTABLES, 6, 1, "-t", "mangle", "-D", "POSTROUTING", "-j", CAR_TRAFFIC_CHAIN);

		va_cmd(IPTABLES, 2, 1, "-X", CAR_FILTER_CHAIN);
		va_cmd(IPTABLES, 4, 1, "-t", "mangle", "-X", "pvc_mark");
		va_cmd(IPTABLES, 4, 1, "-t", "mangle", "-X", CAR_TRAFFIC_CHAIN);

		#ifdef CONFIG_IPV6
		va_cmd(IP6TABLES, 2, 1, "-F", CAR_FILTER_CHAIN);
		va_cmd(IP6TABLES, 4, 1, "-t", "mangle", "-F", "pvc_mark");
		va_cmd(IP6TABLES, 4, 1, "-t", "mangle", "-F", CAR_TRAFFIC_CHAIN);

		va_cmd(IP6TABLES, 4, 1, "-D", "FORWARD", "-j", CAR_FILTER_CHAIN);
		va_cmd(IP6TABLES, 6, 1, "-t", "mangle", "-D", "POSTROUTING", "-j", "pvc_mark");
		va_cmd(IP6TABLES, 6, 1, "-t", "mangle", "-D", "POSTROUTING", "-j", CAR_TRAFFIC_CHAIN);

		va_cmd(IP6TABLES, 2, 1, "-X", CAR_FILTER_CHAIN);
		va_cmd(IP6TABLES, 4, 1, "-t", "mangle", "-X", "pvc_mark");
		va_cmd(IP6TABLES, 4, 1, "-t", "mangle", "-X", CAR_TRAFFIC_CHAIN);
		#endif
	}

	return 1;
}

/*
 *                              HTB(root qdisc, handle 10:)
 *                               |
 *                              HTB(root class, classid 10:1)
 *            ___________________|_____________________
 *            |         |        |          |          |
 *           HTB       HTB      HTB        HTB        HTB
 *(subclass id 10:10 rate Xkbit)........       (sub class id 10:N0 rate Ykbit)
 */
static int setupCarQdisc(unsigned int enable)
{
	MIB_CE_ATM_VC_T vcEntry;
	int i, vcEntryNum;
	char ifname[IFNAMSIZ];
	char s_rate[16], s_ceil[16];
	unsigned char totalBandWidthEn;
	unsigned int bandwidth;
	unsigned int rate, ceil;

	QOS_SETUP_PRINT_FUNCTION;

	mib_get(MIB_TOTAL_BANDWIDTH_LIMIT_EN, (void *)&totalBandWidthEn);

	if (totalBandWidthEn) {
		mib_get(MIB_TOTAL_BANDWIDTH, &bandwidth);
	}
	else
		bandwidth = getUpLinkRate();

	vcEntryNum = mib_chain_total(MIB_ATM_VC_TBL);
	for(i=0;i<vcEntryNum; i++)
	{
		if(!mib_chain_get(MIB_ATM_VC_TBL, i, (void*)&vcEntry)||!vcEntry.enableIpQos)
			continue;

		ifGetName(vcEntry.ifIndex, ifname, sizeof(ifname));

		if (!enable) {
			va_cmd(TC, 5, 1, "qdisc", (char *)ARG_DEL, "dev", ifname, "root");
			continue;
		}
#ifdef BR_ROUTE_ONEPVC
		if (vcEntry.br_route_flag)
		{
			if (vcEntry.cmode == CHANNEL_MODE_BRIDGE)
			{//check if route itf has enabled qos
				if (isPvcQosEnable(&vcEntry))
					continue;
			}
		}
#endif
		//patch: actual bandwidth maybe a little greater than configured limit value, so I minish 7% of the configured limit value ahead.
		if (totalBandWidthEn)
			//ceil = bandwidth/100 * 93;
			ceil = bandwidth*93/100;
		else
			ceil = bandwidth;

		//tc qdisc add dev $DEV root handle 1: htb default 2 r2q 1
		va_cmd(TC, 12, 1, "qdisc", (char *)ARG_ADD, "dev", ifname,
			"root", "handle", "1:", "htb", "default", "2", "r2q", "1");

		// root class
		snprintf(s_rate, 16, "%dKbit", ceil);
		//tc class add dev $DEV parent 1: classid 1:1 htb rate $RATE ceil $CEIL
		va_cmd(TC, 17, 1, "class", (char *)ARG_ADD, "dev", ifname,
			"parent", "1:", "classid", "1:1", "htb", "rate", s_rate, "ceil", s_rate,
			"mpu", "64", "overhead", "4");

		//patch with above
		rate = (ceil>10)?10:ceil;

		// default class
		snprintf(s_rate, 16, "%dKbit", rate);
		snprintf(s_ceil, 16, "%dKbit", ceil);
		//tc class add dev $DEV parent 1:1 classid 1:2 htb rate $RATE ceil $CEIL
		va_cmd(TC, 17, 1, "class", (char *)ARG_ADD, "dev", ifname,
			"parent", "1:1", "classid", "1:2", "htb", "rate",
			s_rate, "ceil", s_ceil, "mpu", "64", "overhead", "4");

		va_cmd(TC, 11, 1, "qdisc", (char *)ARG_ADD, "dev", ifname,
			"parent", "1:2", "handle", "2:", "pfifo", "limit", "10");
	}

	return 0;
}

#ifdef _PRMT_X_CT_COM_DATA_SPEED_LIMIT_
static int setup_data_speed_limit_if(int dir)
{
	MIB_CE_DATA_SPEED_LIMIT_IF_T entry;
	int mib_id = MIB_DATA_SPEED_LIMIT_UP_IF_TBL + dir;
	int total = mib_chain_total(mib_id);
	int i;

	for(i = 0 ; i < total ; i++)
	{
		if(mib_chain_get(mib_id, i, &entry) == 0)
			continue;

		if(entry.if_id < 1 || entry.if_id >12)
			continue;

		if(entry.speed_unit == 0)
			continue;

#ifdef CONFIG_RTK_L34_ENABLE
		RTK_RG_data_speed_limit_if_set(dir, i, &entry);
#endif
	}
}

static int setup_data_speed_limit_vlan(int dir)
{
	MIB_CE_DATA_SPEED_LIMIT_VLAN_T entry;
	int mib_id = MIB_DATA_SPEED_LIMIT_UP_VLAN_TBL + dir;
	int total = mib_chain_total(mib_id);
	int i;

	for(i = 0 ; i < total ; i++)
	{
		if(mib_chain_get(mib_id, i, &entry) == 0)
			continue;

		if(entry.speed_unit == 0)
			continue;

#ifdef CONFIG_RTK_L34_ENABLE
		RTK_RG_data_speed_limit_vlan_set(dir, i, &entry);
#endif
	}
}

static int setup_data_speed_limit_ip(int dir)
{
	MIB_CE_DATA_SPEED_LIMIT_IP_T entry;
	int mib_id = MIB_DATA_SPEED_LIMIT_UP_IP_TBL + dir;
	int total = mib_chain_total(mib_id);
	int i;

	for(i = 0 ; i < total ; i++)
	{
		if(mib_chain_get(mib_id, i, &entry) == 0)
			continue;

		if(entry.speed_unit == 0)
			continue;

#ifdef CONFIG_RTK_L34_ENABLE
		RTK_RG_data_speed_limit_ip_set(dir, i, &entry);
#endif
	}
}

static int setup_data_speed_limit()
{
	unsigned char mode;

	//UP
	mib_get(MIB_DATA_SPEED_LIMIT_UP_MODE, &mode);

	switch(mode)
	{
	case DATA_SPEED_LIMIT_MODE_IF:
		setup_data_speed_limit_if(QOS_DIRECTION_UPSTREAM);
		break;
	case DATA_SPEED_LIMIT_MODE_VLAN:
		setup_data_speed_limit_vlan(QOS_DIRECTION_UPSTREAM);
		break;
	case DATA_SPEED_LIMIT_MODE_IP:
		setup_data_speed_limit_ip(QOS_DIRECTION_UPSTREAM);
		break;
	default:
		fprintf(stderr, "<%s:%d> Unknown data speed limit mode: %d\n", __func__, __LINE__, mode);
	case DATA_SPEED_LIMIT_MODE_DISABLE:
		break;
	}

	//DOWN
	mib_get(MIB_DATA_SPEED_LIMIT_DOWN_MODE, &mode);

	switch(mode)
	{
	case DATA_SPEED_LIMIT_MODE_IF:
		setup_data_speed_limit_if(QOS_DIRECTION_DOWNSTREAM);
		break;
	case DATA_SPEED_LIMIT_MODE_VLAN:
		setup_data_speed_limit_vlan(QOS_DIRECTION_DOWNSTREAM);
		break;
	case DATA_SPEED_LIMIT_MODE_IP:
		setup_data_speed_limit_ip(QOS_DIRECTION_DOWNSTREAM);
		break;
	default:
		fprintf(stderr, "<%s:%d> Unknown data speed limit mode: %d\n", __func__, __LINE__, mode);
	case DATA_SPEED_LIMIT_MODE_DISABLE:
		break;
	}

	return 0;
}

#else
static int setupCarRule_one(MIB_CE_IP_TC_Tp entry)
{
	char ifname[IFNAMSIZ]={0};
	char* tc_act = NULL, *fw_act=NULL;
	char* proto1 = NULL, *proto2 = NULL;
	char wanPort[16]={0};
	char  saddr[55], daddr[55], sport[16], dport[16];
	char tmpstr[48];
	int upLinkRate=0, childRate=0;
	int mark;
	char *iptables_cmd=NULL, *tc_protocol=NULL;
	DOCMDINIT;

	QOS_SETUP_PRINT_FUNCTION;

	tc_act = (char*)ARG_ADD;
	fw_act = (char*)FW_ADD;

	if(NULL == entry) {
		printf("Null traffic contolling rule!\n");
		return 1;
	}

#ifndef CONFIG_RTK_L34_ENABLE //In RG platform,no specify interface
	ifGetName(entry->ifIndex, ifname, sizeof(ifname));
	//wan interface
	if (ifname[0] != '\0')
		snprintf(wanPort, 16, "-o %s", ifname);
#endif

#ifdef CONFIG_IPV6
	// This is a IPv4 rule
	if ( entry->IpProtocol == IPVER_IPV4 ) {
		//source address and netmask
		//snprintf(tmpstr, 16, "%s", inet_ntoa(*((struct in_addr *)entry->srcip)));
		//convertIPAddrToString(*((unsigned int*)(entry->srcip)),tmpstr);
		inet_ntop(AF_INET, entry->srcip, tmpstr, sizeof(tmpstr));
		if (strcmp(tmpstr, ARG_0x4)) {
			if(0 != entry->smaskbits) {
				snprintf(saddr, 24, "-s %s/%d", tmpstr, entry->smaskbits);
			} else {
				snprintf(saddr, 24, "-s %s", tmpstr);
			}
		}
		else {//if not specify the source ip
			saddr[0] = '\0';
		}
	}
	// This is a IPv6 rule
	else if ( entry->IpProtocol == IPVER_IPV6 ) {
		//source address and netmask
		inet_ntop(PF_INET6, (struct in6_addr *)entry->sip6, tmpstr, sizeof(tmpstr));
		if (strcmp(tmpstr, "::")) {
			if(0 != entry->sip6PrefixLen) {
				snprintf(saddr, 55, "-s %s/%d", tmpstr, entry->sip6PrefixLen);
			} else {
				snprintf(saddr, 55, "-s %s", tmpstr);
			}
		}
		else {//if not specify the source ip
			saddr[0] = '\0';
		}
	}
#else
	//source address and netmask
	//snprintf(tmpstr, 16, "%s", inet_ntoa(*((struct in_addr *)entry->srcip)));
	//convertIPAddrToString(*((unsigned int*)(entry->srcip)),tmpstr);
	inet_ntop(AF_INET, entry->srcip, tmpstr, sizeof(tmpstr));

	if (strcmp(tmpstr, ARG_0x4)) {
		if(0 != entry->smaskbits) {
			snprintf(saddr, 24, "-s %s/%d", tmpstr, entry->smaskbits);
		} else {
			snprintf(saddr, 24, "-s %s", tmpstr);
		}
	}
	else {//if not specify the source ip
		saddr[0] = '\0';
	}
#endif

#ifdef CONFIG_IPV6
	// This is a IPv4 rule
	if ( entry->IpProtocol == IPVER_IPV4 ) {
		//destination address and netmask
		//snprintf(tmpstr, 16, "%s", inet_ntoa(*((struct in_addr *)entry->dstip)));
		//convertIPAddrToString(*((unsigned int*)(entry->dstip)),tmpstr);
		inet_ntop(AF_INET, entry->dstip, tmpstr, sizeof(tmpstr));
		if (strcmp(tmpstr, ARG_0x4)) {
			if(0 != entry->dmaskbits) {
				snprintf(daddr, 24, "-d %s/%d", tmpstr, entry->dmaskbits);
			} else {
				snprintf(daddr, 24, "-d %s", tmpstr);
			}
		} else {//if not specify the dest ip
			daddr[0] = '\0';
		}
	}
	// This is a IPv6 rule
	else if ( entry->IpProtocol == IPVER_IPV6 ) {
		//destination address and netmask
		inet_ntop(PF_INET6, (struct in6_addr *)entry->dip6, tmpstr, sizeof(tmpstr));
		if (strcmp(tmpstr, "::")) {
			if(0 != entry->dip6PrefixLen) {
				snprintf(daddr, 55, "-d %s/%d", tmpstr, entry->dip6PrefixLen);
			} else {
				snprintf(daddr, 55, "-d %s", tmpstr);
			}
		} else {//if not specify the dest ip
			daddr[0] = '\0';
		}
	}
#else
	//destination address and netmask
	//snprintf(tmpstr, 16, "%s", inet_ntoa(*((struct in_addr *)entry->dstip)));
	//convertIPAddrToString(*((unsigned int*)(entry->dstip)),tmpstr);
	inet_ntop(AF_INET, entry->dstip, tmpstr, sizeof(tmpstr));
	if (strcmp(tmpstr, ARG_0x4)) {
		if(0 != entry->dmaskbits) {
			snprintf(daddr, 24, "-d %s/%d", tmpstr, entry->dmaskbits);
		} else {
			snprintf(daddr, 24, "-d %s", tmpstr);
		}
	} else {//if not specify the dest ip
		daddr[0] = '\0';
	}
#endif

	//source port
	if(0 != entry->sport) {
		snprintf(sport, 16, "--sport %d", entry->sport);
	} else {
		sport[0] = '\0';
	}

	//destination port
	if(0 != entry->dport) {
		snprintf(dport, 16, "--dport %d", entry->dport);
	} else {
		dport[0] = '\0';
	}

	//protocol
	//if (((0 != entry->sport) || (0 != entry->dport)) &&
	//	(entry->protoType < 2))
	//	entry->protoType = 4;

	if(entry->protoType>4)//wrong protocol index
	{
		printf("Wrong protocol\n");
		return 1;
	} else {
		switch(entry->protoType)
		{
			case PROTO_NONE://NONE
				proto1 = " ";
				break;
			case PROTO_ICMP://ICMP
				#ifdef CONFIG_IPV6
				// This is a IPv4 rule
				if ( entry->IpProtocol == IPVER_IPV4 )
					proto1 = "-p ICMP";
				// This is a IPv6 rule
				else if ( entry->IpProtocol == IPVER_IPV6 )
					proto1 = "-p ICMPV6";
				#else
				proto1 = "-p ICMP";
				#endif
				break;
			case PROTO_TCP://TCP
				proto1 = "-p TCP";
				break;
			case PROTO_UDP://UDP
				proto1 = "-p UDP";
				break;
			case PROTO_UDPTCP://TCP/UDP
				proto1 = "-p TCP";
				proto2 = "-p UDP";
				break;
		}
	}

#ifdef CONFIG_IPV6
		// This is a IPv4 rule
		if ( entry->IpProtocol == IPVER_IPV4 ) {
			iptables_cmd = "/bin/iptables";
			tc_protocol = "protocol ip";
		}
		// This is a IPv6 rule
		else {
			iptables_cmd = "/bin/ip6tables";
			tc_protocol = "protocol ipv6";
		}
#else
		// This is a IPv4 rule
		iptables_cmd = "/bin/iptables";
		tc_protocol = "protocol ip";
#endif

	upLinkRate = entry->limitSpeed;
	if(0 != upLinkRate)
	{
		//get mark
		mark = (entry->entryid<<12);

		//patch: true bandwidth will be a little greater than limit value, so I minish 7% of set limit value ahead.
		int ceil;
		//ceil = upLinkRate/100 * 93;
		ceil = upLinkRate*93/100;

		childRate = (10>ceil)?ceil:10;
		//childRate = ceil;

		DOCMDARGVS(TC, DOWAIT, "class %s dev %s parent 1:1 classid 1:%d0 htb rate %dkbit ceil %dkbit mpu 64 overhead 4",
			tc_act, ifname, entry->entryid, childRate, ceil);

		DOCMDARGVS(TC, DOWAIT, "qdisc %s dev %s parent 1:%d0 handle %d1: pfifo limit 10",
			tc_act, ifname, entry->entryid, entry->entryid);

		//DOCMDARGVS(TC, DOWAIT, "filter %s dev %s parent 1: protocol ip prio 0 handle 0x%x fw flowid 1:%d0",
		//	tc_act, ifname, mark, entry->entryid);
		DOCMDARGVS(TC, DOWAIT, "filter %s dev %s parent 1: %s prio 0 handle 0x%x fw flowid 1:%d0",
			tc_act, ifname, tc_protocol, mark, entry->entryid);

		DOCMDARGVS(iptables_cmd, DOWAIT,  "-t mangle %s %s %s %s %s %s %s %s -j MARK --set-mark 0x%x",
			fw_act, CAR_TRAFFIC_CHAIN, wanPort, proto1, saddr, daddr, sport, dport, mark);

		/*TCP/UDP?*/
		if(proto2)//setup the other protocol
		{
			DOCMDARGVS(iptables_cmd, DOWAIT, "-t mangle %s %s %s %s %s %s %s %s -j MARK --set-mark 0x%x",
				fw_act, CAR_TRAFFIC_CHAIN, wanPort, proto2, saddr, daddr, sport, dport, mark);
		}
	}
	else
	{//if uprate=0, forbid traffic matching the rules
		DOCMDARGVS(iptables_cmd, DOWAIT, "-t filter %s %s %s %s %s %s %s %s -j DROP",
			fw_act, CAR_FILTER_CHAIN, wanPort, proto1, saddr, daddr, sport, dport);

		/*TCP/UDP again*/
		if(proto2)
		{
			DOCMDARGVS(iptables_cmd, DOWAIT, "-t filter %s %s %s %s %s %s %s %s -j DROP",
				fw_act, CAR_FILTER_CHAIN, wanPort, proto2, saddr, daddr, sport, dport);
		}
	}

#ifdef CONFIG_RTK_L34_ENABLE
	RTK_RG_QoS_Car_Rule_Set(entry);
#endif
	return 0;
}

static int setupCarRule()
{
	int entry_num, i;
	MIB_CE_IP_TC_T  entry;

	entry_num = mib_chain_total(MIB_IP_QOS_TC_TBL);

	for(i=0; i<entry_num; i++)
	{
		if(!mib_chain_get(MIB_IP_QOS_TC_TBL, i, (void*)&entry))
			continue;

		if (setupCarRule_one(&entry))
			return 1;
	}

	return 0;
}
#endif

/*********************************************************************
 * NAME:    setup_qos_rules
 * DESC:    Using iptables to setup rules for queue, including packet
 *          marking(dscp, 802.1p). This function doesn't affect traffic
 *          controlling, just for priority and weighted round robin
 *          queue. Suppose that the mib setting is well-formated and right.
 * ARGS:    none
 * RETURN:  0 success, others fail
 *********************************************************************/
 #if defined(CONFIG_CMCC) || defined(CONFIG_CU)
 static int setup_qos_rules(unsigned char policy){
	MIB_CE_IP_QOS_T entry;
	MIB_CE_ATM_VC_T vcEntry;
	int i, j, EntryNum = 0, vcEntryNum = 0;
	unsigned char enableDscpMark=1;
	unsigned char enableQos1p=2;  // enableQos1p=0: not use, enableQos1p=1: use old value, enableQos1p=2: mark new value
#ifdef QOS_SUPPORT_RTP
	FILE *fp;
	char buff[100];
	unsigned int rtp_dip;
	unsigned int rtp_dpt;
	unsigned int rtpCnt=0, rtpRuleCnt=0;
	struct rtp_struct {
		unsigned int dip;
		unsigned int dport;
	} __PACK__;
	struct rtp_rule_st {
		char daddr[48];
		char dport[48];
	} __PACK__;

	struct rtp_struct rtp_entry[RTP_RULE_NUM_MAX];
	struct rtp_rule_st rtp_rule_entry[RTP_RULE_NUM_MAX];
#endif
	printf("%s %d#######################################\n",__FUNCTION__,__LINE__);
	DOCMDINIT

	QOS_SETUP_PRINT_FUNCTION

	if(PLY_WRR==policy)//weighted round robin
	{
		if (!ifSumWeighIs100())
			return 1;
	}

	//get current RTP stream info
#ifdef QOS_SUPPORT_RTP
	if (!(fp=fopen(RTP_PORT_FILE, "r"))) {
		printf("no RTP connection!\n");
	} else {
		while ( fgets(buff, sizeof(buff), fp) != NULL ) {
			if(sscanf(buff, "dip=%d dport=%d", &rtp_dip, &rtp_dpt)!=2) {
				printf("Unsuported rtp format\n");
				break;
			}
			else {
				rtpCnt++;
				rtp_entry[rtpCnt-1].dip = rtp_dip;
				rtp_entry[rtpCnt-1].dport = rtp_dpt;
			}
		}
		fclose(fp);
	}
#endif
	mib_get(MIB_QOS_ENABLE_DSCP_MARK, (void *)&enableDscpMark);
	mib_get(MIB_QOS_ENABLE_1P, (void *)&enableQos1p);

	EntryNum = mib_chain_total(MIB_IP_QOS_TBL);
	for(i=0; i<EntryNum; i++)
	{
		char ifname[IFNAMSIZ], phyPort[16]={0};
		char phyPort1[16]={0};
		char wanPort[16]={0};
		char sport[48], dport[48], saddr[75], daddr[75], strmark[48];
		char tmpstr[48];
		char *proto1=NULL, *proto2 = NULL, *eth_proto = NULL;
		char *iptables_cmd=NULL, *tc_protocol=NULL;
		char dscp[24] = {0};
		unsigned int mark=0;
		char smac[48], dmac[48];
		//ql
		unsigned int wan_qos_state = 0;
		unsigned int wan_vlan_enable = 0;
		/*ql:20080825 START: for tr069 pvc, just set priority according to wanport*/
		unsigned int wan_tr069=0;
		/*ql:20080825 END*/
		unsigned int ebtable=0;

		if(!mib_chain_get(MIB_IP_QOS_TBL, i, (void*)&entry)||!entry.enable)
		    continue;

		if(!isQueneEnableForRule(entry.prior) && !entry.classtype)
			continue;

#ifdef BR_ROUTE_ONEPVC
		wan_qos_state = get_pvc_qos_state(entry.outif, entry.cmode);
#else
		wan_qos_state = get_pvc_qos_state(entry.outif);
#endif
		wan_vlan_enable = wan_qos_state&QOS_WAN_VLAN_ENABLE;
		/*ql:20080825 START: for tr069 pvc, just set priority according to wanport*/
		wan_tr069 = wan_qos_state&QOS_WAN_TR069;
		/*ql:20080825 END*/
#ifdef BR_ROUTE_ONEPVC
		if ((entry.outif != DUMMY_IFINDEX) && (entry.cmode == CHANNEL_MODE_BRIDGE))
			ebtable = 1;
#else
		ebtable = wan_qos_state&QOS_WAN_BRIDGE;
#endif
		// If this rule is for All WAN interface(DUMMY_IFINDEX), use ebtables to set rule.
	    if ( entry.outif == DUMMY_IFINDEX ) {
			ebtable = 1;
		}

		//interface
		if ( entry.outif != DUMMY_IFINDEX ) {
			ifGetName(entry.outif, ifname, sizeof(ifname));

			//wan port
			snprintf(wanPort, 16, "-o %s", ifname);
		}

		if (memcmp(entry.smac, EMPTY_MAC, MAC_ADDR_LEN)) {
			mac_hex2string(entry.smac, tmpstr);
			snprintf(smac, 48, "-s %s", tmpstr);
		}
		else
			smac[0] = '\0';

		if (memcmp(entry.dmac, EMPTY_MAC, MAC_ADDR_LEN)) {
			mac_hex2string(entry.dmac, tmpstr);
			snprintf(dmac, 48, "-d %s", tmpstr);
		}
		else
			dmac[0] = '\0';

		if ((smac[0] != '\0') || (dmac[0] != '\0'))
			ebtable = 1;

		//phy port, 0: none, range:1-4
		if (entry.phyPort>=1 && entry.phyPort<=SW_LAN_PORT_NUM)
			snprintf(phyPort, 16, "-i %s", SW_LAN_PORT_IF[entry.phyPort-1]);
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
#ifdef WLAN_SUPPORT
		//range: 5-8 wlan0
		else if(entry.phyPort>SW_LAN_PORT_NUM && entry.phyPort<=(SW_LAN_PORT_NUM + WLAN_SSID_NUM)){
			if(entry.phyPort == (SW_LAN_PORT_NUM +1))
				snprintf(phyPort, 16, "-i wlan0");
			else
				snprintf(phyPort, 16, "-i wlan0-vap%d", entry.phyPort - SW_LAN_PORT_NUM - 2);
		}
#ifdef WLAN_DUALBAND_CONCURRENT
		//range: 9-12 wlan1
		else if(entry.phyPort>(SW_LAN_PORT_NUM + WLAN_SSID_NUM) && entry.phyPort<=(SW_LAN_PORT_NUM + 2*WLAN_SSID_NUM)){
			if(entry.phyPort == (SW_LAN_PORT_NUM + WLAN_SSID_NUM +1))
				snprintf(phyPort, 16, "-i wlan1");
			else
				snprintf(phyPort, 16, "-i wlan1-vap%d", entry.phyPort - SW_LAN_PORT_NUM - WLAN_SSID_NUM - 2);
		}
#endif
#endif
#endif
		else {
			if (ebtable)
				phyPort[0] = '\0';
			else
#ifdef CONFIG_PPPOE_PROXY_IF_NAME
				/*ql:20080805 START: qos enable for ppp proxy*/
				snprintf(phyPort, 16, "-i br+");
				/*ql: 20080805 END*/
#else
				snprintf(phyPort, 16, "-i br0");
#endif
		}

#ifdef QOS_DIFFSERV
		//dscp match
		if(0 != entry.qosDscp)
		{
#ifdef CONFIG_IPV6
			if (ebtable) {
				// This is a IPv4 rule
				if ( entry.IpProtocol == IPVER_IPV4 )
					snprintf(dscp, 24, "--ip-tos 0x%x", (entry.qosDscp-1)&0xFF);
				// This is a IPv6 rule
				else if ( entry.IpProtocol == IPVER_IPV6 )
					snprintf(dscp, 24, "--ip6-tclass 0x%x", (entry.qosDscp-1)&0xFF);
			}
#else
			if (ebtable)
				snprintf(dscp, 24, "--ip-tos 0x%x", (entry.qosDscp-1)&0xFF);
#endif
			else
				snprintf(dscp, 24, "-m dscp --dscp 0x%x", (entry.qosDscp-1)>>2);
		}else{
		    dscp[0]='\0';
		}
#endif

#ifdef CONFIG_RTK_L34_ENABLE
		if(entry.protoType==PROTO_RTP) {
			RTK_RG_QoS_Rule_Set(&entry);
			continue;
		}

#endif
		//protocol
#ifdef QOS_SUPPORT_RTP
		if(entry.protoType>PROTO_RTP)//invalid protocol index
			return 1;
#else
		if(entry.protoType>PROTO_UDPTCP)//invalid protocol index
			return 1;
#endif

		//source port (range)
		if(PROTO_NONE == entry.protoType||PROTO_TCP == entry.protoType||0 == entry.sPort)
		{//if protocol is icmp or none or port not set, ignore the port
		    sport[0] = '\0';
		}
		else
		{
#ifdef CONFIG_IPV6
			// This is a IPv4 rule
			if ( entry.IpProtocol == IPVER_IPV4 && ebtable) {
					if(0 != entry.sPortRangeMax)
						snprintf(sport, 48, "--ip-source-port %d:%d", MIN_PORT(entry.sPort, entry.sPortRangeMax),
							MAX_PORT(entry.sPort, entry.sPortRangeMax));
					else
						snprintf(sport, 48, "--ip-source-port %d", entry.sPort);
			}
			// This is a IPv6 rule
			else if ( entry.IpProtocol == IPVER_IPV6 && ebtable) {
					if(0 != entry.sPortRangeMax)
						snprintf(sport, 48, "--ip6-source-port %d:%d", MIN_PORT(entry.sPort, entry.sPortRangeMax),
							MAX_PORT(entry.sPort, entry.sPortRangeMax));
					else
						snprintf(sport, 48, "--ip6-source-port %d", entry.sPort);
			}
#else
			if (ebtable) {
				if(0 != entry.sPortRangeMax)
					snprintf(sport, 48, "--ip-source-port %d:%d", MIN_PORT(entry.sPort, entry.sPortRangeMax),
						MAX_PORT(entry.sPort, entry.sPortRangeMax));
				else
					snprintf(sport, 48, "--ip-source-port %d", entry.sPort);
			}
#endif
			else {
				if(0 != entry.sPortRangeMax)
					snprintf(sport, 48, "--sport %d:%d", MIN_PORT(entry.sPort, entry.sPortRangeMax),
						MAX_PORT(entry.sPort, entry.sPortRangeMax));
				else
					snprintf(sport, 48, "--sport %d", entry.sPort);
			}
		}

#ifdef CONFIG_IPV6
		// This is a IPv4 rule
		if ( entry.IpProtocol == IPVER_IPV4 ) {
			//source address
			//snprintf(tmpstr, 16, "%s", inet_ntoa(*((struct in_addr *)entry.sip)));
			//convertIPAddrToString(*((unsigned int*)(entry.sip)),tmpstr);
			inet_ntop(AF_INET, entry.sip, tmpstr, sizeof(tmpstr));
			if (strcmp(tmpstr, ARG_0x4)) {
				if (ebtable) {
					if(0 != entry.smaskbit)
						snprintf(saddr, 48, "--ip-source %s/%d",
							tmpstr, entry.smaskbit );
					else
						snprintf(saddr, 48, "--ip-source %s", tmpstr);
				}
				else {
					if(0 != entry.smaskbit)
						snprintf(saddr, 48, "-s %s/%d",
							tmpstr, entry.smaskbit );
					else
						snprintf(saddr, 48, "-s %s", tmpstr);
				}
			}
			else
				saddr[0]='\0';
		}
		// This is a IPv6 rule
		else if ( entry.IpProtocol == IPVER_IPV6 ) {
			//source address
			inet_ntop(PF_INET6, (struct in6_addr *)entry.sip6, tmpstr, sizeof(tmpstr));
			if (strcmp(tmpstr, "::")) {
				if (ebtable) {
					if(0 != entry.sip6PrefixLen)
						snprintf(saddr, 75, "--ip6-source %s/%d",
							tmpstr, entry.sip6PrefixLen );
					else
						snprintf(saddr, 75, "--ip6-source %s", tmpstr);
				}
				else {
					if(0 != entry.sip6PrefixLen)
						snprintf(saddr, 75, "-s %s/%d",
							tmpstr, entry.sip6PrefixLen );
					else
						snprintf(saddr, 75, "-s %s", tmpstr);
				}
			}
			else
				saddr[0]='\0';
		}
#else
		//source address
		//snprintf(tmpstr, 16, "%s", inet_ntoa(*((struct in_addr *)entry.sip)));
		//convertIPAddrToString(*((unsigned int*)(entry.sip)),tmpstr);
		inet_ntop(AF_INET, entry.sip, tmpstr, sizeof(tmpstr));
		if (strcmp(tmpstr, ARG_0x4)) {
			if (ebtable) {
				if(0 != entry.smaskbit)
					snprintf(saddr, 48, "--ip-source %s/%d",
						tmpstr, entry.smaskbit );
				else
					snprintf(saddr, 48, "--ip-source %s", tmpstr);
			}
			else {
				if(0 != entry.smaskbit)
					snprintf(saddr, 48, "-s %s/%d",
						tmpstr, entry.smaskbit );
				else
					snprintf(saddr, 48, "-s %s", tmpstr);
			}
		}
		else
			saddr[0]='\0';
#endif

#ifdef QOS_SUPPORT_RTP
		if (entry.protoType == PROTO_RTP)//RTP
		{
			if (0 == rtpCnt)//no rtp stream found
				continue;

			if (ebtable)
				continue;//don't process such rule
			else
				proto1 = "-p UDP";

			rtpRuleCnt = 0;
/*star:20090407 START only parse rtp src port*/
			//snprintf(tmpstr, 16, "%s", inet_ntoa(*((struct in_addr *)entry.dip)));
			//convertIPAddrToString(*((unsigned int*)(entry.dip)),tmpstr);
			inet_ntop(AF_INET, entry.dip, tmpstr, sizeof(tmpstr));
			if (strcmp(tmpstr, ARG_0x4)) {
				for (j=0; j<rtpCnt; j++) {
					rtpRuleCnt++;

					if(0 != entry.dmaskbit)
						snprintf(rtp_rule_entry[rtpRuleCnt-1].daddr, 26, "-d %s/%d",
							tmpstr, entry.dmaskbit );
					else
						snprintf(rtp_rule_entry[rtpRuleCnt-1].daddr, 26, "-d %s", tmpstr);

					snprintf(rtp_rule_entry[rtpRuleCnt-1].dport, 24, "--sport %d", rtp_entry[j].dport);
				}
				if (rtpRuleCnt==0)//not found .
					continue;
			} else {
				for (j=0; j<rtpCnt; j++) {
					rtpRuleCnt++;
					//snprintf(rtp_rule_entry[rtpRuleCnt-1].daddr, 26, "-d %s", inet_ntoa(*((struct in_addr*)(&rtp_entry[j].dip))));
					rtp_rule_entry[rtpRuleCnt-1].daddr[0]=0;
					snprintf(rtp_rule_entry[rtpRuleCnt-1].dport, 24, "--sport %d", rtp_entry[j].dport);
				}
			}
		}
		else
		{
#endif
			if(entry.protoType == PROTO_UDPTCP)//add by penggenyao, support two protos at the same time
			{
#ifdef CONFIG_IPV6
				if (ebtable) {
					// This is a IPv4 rule
					if ( entry.IpProtocol == IPVER_IPV4 ) {
						proto1 = "--ip-proto 6";
						proto2 = "--ip-proto 17";
					}
					// This is a IPv6 rule
					else if ( entry.IpProtocol == IPVER_IPV6 ) {
						proto1 = "--ip6-proto 6";
						proto2 = "--ip6-proto 17";
					}
				}
#else
				if (ebtable) {
					proto1 = "--ip-proto 6";
					proto2 = "--ip-proto 17";
				}
#endif
				else {
				    proto1 = "-p TCP";
				    proto2 = "-p UDP";
				}
			}
			else {
#ifdef CONFIG_IPV6
				if (ebtable) {
					// This is a IPv4 rule
					if ( entry.IpProtocol == IPVER_IPV4 )
						proto1 = proto2str2layer[entry.protoType];
					// This is a IPv6 rule
					else if ( entry.IpProtocol == IPVER_IPV6 )
						proto1 = proto2str2layer_v6[entry.protoType];
				}
				else {
					// This is a IPv4 rule
					if ( entry.IpProtocol == IPVER_IPV4 )
						proto1 = proto2str[entry.protoType];
					// This is a IPv6 rule
					else if ( entry.IpProtocol == IPVER_IPV6 )
						proto1 = proto2str_v6[entry.protoType];
				}
#else
				if (ebtable)
					proto1 = proto2str2layer[entry.protoType];
				else
					proto1 = proto2str[entry.protoType];
#endif

			}

			//dest port (range)
			if(PROTO_NONE == entry.protoType||PROTO_TCP == entry.protoType||PROTO_UDP == entry.dPort)
			{//if protocol is icmp or none or port not set, ignore the port
			    dport[0] = '\0';
			}
			else
			{
#ifdef CONFIG_IPV6
				// This is a IPv4 rule
				if ( entry.IpProtocol == IPVER_IPV4 && ebtable) {
						if(0 != entry.dPortRangeMax)
							snprintf(dport, 48, "--ip-destination-port %d:%d", MIN_PORT(entry.dPort, entry.dPortRangeMax),
								MAX_PORT(entry.dPort, entry.dPortRangeMax));
						else
							snprintf(dport, 48, "--ip-destination-port %d", entry.dPort);
				}
				// This is a IPv6 rule
				else if ( entry.IpProtocol == IPVER_IPV6 && ebtable) {
						if(0 != entry.dPortRangeMax)
							snprintf(dport, 48, "--ip6-destination-port %d:%d", MIN_PORT(entry.dPort, entry.dPortRangeMax),
								MAX_PORT(entry.dPort, entry.dPortRangeMax));
						else
							snprintf(dport, 48, "--ip6-destination-port %d", entry.dPort);
				}
#else
				if (ebtable) {
					if(0 != entry.dPortRangeMax)
						snprintf(dport, 48, "--ip-destination-port %d:%d", MIN_PORT(entry.dPort, entry.dPortRangeMax),
							MAX_PORT(entry.dPort, entry.dPortRangeMax));
					else
						snprintf(dport, 48, "--ip-destination-port %d", entry.dPort);
				}
#endif
				else {
				    if(0 != entry.dPortRangeMax)
						snprintf(dport, 48, "--dport %d:%d", MIN_PORT(entry.dPort, entry.dPortRangeMax),
							MAX_PORT(entry.dPort, entry.dPortRangeMax));
				    else
						snprintf(dport, 48, "--dport %d", entry.dPort);
				}
			}

#ifdef CONFIG_IPV6
			// This is a IPv4 rule
			if ( entry.IpProtocol == IPVER_IPV4 ) {
				//dest address
				//snprintf(tmpstr, 16, "%s", inet_ntoa(*((struct in_addr *)entry.dip)));
				//convertIPAddrToString(*((unsigned int*)(entry.dip)),tmpstr);
				inet_ntop(AF_INET, entry.dip, tmpstr, sizeof(tmpstr));
				if (strcmp(tmpstr, ARG_0x4)) {
					if (ebtable) {
						if(0 != entry.dmaskbit)
							snprintf(daddr, 48, "--ip-destination %s/%d",
								tmpstr, entry.dmaskbit );
						else
							snprintf(daddr, 48, "--ip-destination %s", tmpstr);
					} else {
						if(0 != entry.dmaskbit)
							snprintf(daddr, 48, "-d %s/%d",
								tmpstr, entry.dmaskbit );
						else
							snprintf(daddr, 48, "-d %s", tmpstr);
					}
				}
				else
					daddr[0]='\0';
			}
			// This is a IPv6 rule
			else if ( entry.IpProtocol == IPVER_IPV6 ){
				//dest address
				inet_ntop(PF_INET6, (struct in6_addr *)entry.dip6, tmpstr, sizeof(tmpstr));
				if (strcmp(tmpstr, "::")) {
					if (ebtable) {
						if(0 != entry.dip6PrefixLen)
							snprintf(daddr, 75, "--ip6-destination %s/%d",
								tmpstr, entry.dip6PrefixLen );
						else
							snprintf(daddr, 75, "--ip6-destination %s", tmpstr);
					}
					else {
						if(0 != entry.dip6PrefixLen)
							snprintf(daddr, 75, "-d %s/%d",
								tmpstr, entry.dip6PrefixLen );
						else
							snprintf(daddr, 75, "-d %s", tmpstr);
					}
				}
				else {
					daddr[0]='\0';
				}
			}
#else
			//dest address
			//snprintf(tmpstr, 16, "%s", inet_ntoa(*((struct in_addr *)entry.dip)));
			//convertIPAddrToString(*((unsigned int*)(entry.dip)),tmpstr);
			inet_ntop(AF_INET, entry.dip, tmpstr, sizeof(tmpstr));
			if (strcmp(tmpstr, ARG_0x4)) {
				if (ebtable) {
					if(0 != entry.dmaskbit)
						snprintf(daddr, 48, "--ip-destination %s/%d",
							tmpstr, entry.dmaskbit );
					else
						snprintf(daddr, 48, "--ip-destination %s", tmpstr);
				} else {
					if(0 != entry.dmaskbit)
						snprintf(daddr, 48, "-d %s/%d",
							tmpstr, entry.dmaskbit );
					else
						snprintf(daddr, 48, "-d %s", tmpstr);
				}
			}
			else
				daddr[0]='\0';
#endif

#ifdef QOS_SUPPORT_RTP
		}
#endif

		//lan 802.1p mark, 0-7 bit(match)
		if(0 != entry.vlan1p) {
			if (ebtable)
				snprintf(strmark, 48, "--vlan-prio %d", (entry.vlan1p-1)&0xff);
			else
				snprintf(strmark, 48, "-m mark --mark 0x%x/0x%x", entry.vlan1p&QOS_8021P_MASK, QOS_8021P_MASK);
		} else
			strmark[0] = '\0';

		if (ebtable) {
			if(strmark[0] != '\0')//vlan 802.1p priority, use 802.1Q ethernet protocol
			{
				eth_proto = "-p 0x8100";
			}
			else {//use ipv4 for ethernet protocol
#ifdef CONFIG_IPV6
				// This is a IPv4 rule
				if ( entry.IpProtocol == IPVER_IPV4 )
					eth_proto = "-p 0x0800";
				// This is a IPv6 rule
				else if ( entry.IpProtocol == IPVER_IPV6 )
					eth_proto = "-p 0x86dd";
				else
					eth_proto = " ";
#else
				if (!isQosMacRule(&entry))
					eth_proto = "-p 0x0800";
				else
					eth_proto = " ";
#endif
			}
		}

		//wan 802.1p mark 0-7 bit: 802.1p, 8-15 bit: queue id
		// We can not use 0 to as tc handle. So we use (i+1).
		// enableQos1p=0: not use, enableQos1p=1: use old value, enableQos1p=2: mark new value
		if (2 != enableQos1p) {
			mark |= ((i+1)<<8);
		} else {
			if((0 != entry.m_1p) && wan_vlan_enable) {
			    mark = (entry.m_1p-1)&0xff;
				//ql 20090106 START: set bit 16 of nfmark when tag 802.1p
				mark |= (((i+1)<<8) | (1<<16));
			}
			else {
				mark |= ((i+1)<<8);
			}
		}//else if enableQos1p==0, mark=0
		//ql 20090106 START: set bit 16 of nfmark when tag 802.1p
		//mark |= ((entry.index<<12) | (1<<24));
		//ql 20090106 END

#ifdef CONFIG_IPV6
		// This is a IPv4 rule
		if ( entry.IpProtocol == IPVER_IPV4 ) {
			iptables_cmd = "/bin/iptables";
			tc_protocol = "protocol ip";
		}
		// This is a IPv6 rule
		else {
			iptables_cmd = "/bin/ip6tables";
			tc_protocol = "protocol ipv6";
		}
#else
		// This is a IPv4 rule
		iptables_cmd = "/bin/iptables";
		tc_protocol = "protocol ip";
#endif

		//set the mark
#ifdef QOS_SUPPORT_RTP
		if (entry.protoType != PROTO_RTP)//RTP
		{
#endif
			if (!ebtable) {
				/*ql:20080825 START: for tr069 pvc, just set priority according to wanport*/
				if (wan_tr069)
				{
					DOCMDARGVS(iptables_cmd, DOWAIT, "-t mangle -A qos_rule_output %s -j MARK --set-mark 0x%x/0x%x",
						wanPort, mark, QOS_MARK_MASK);
				} else {
				/*ql:20080825 END*/
					//forward chain
					DOCMDARGVS(iptables_cmd, DOWAIT, "-t mangle -A %s %s %s %s %s %s %s %s %s %s -j MARK --set-mark 0x%x/0x%x",
						QOS_IP_CHAIN, phyPort, wanPort, proto1, saddr, sport, daddr, dport, dscp, strmark, mark, QOS_MARK_MASK);
					//output chain
					if (!entry.phyPort && !saddr[0] && !strmark[0] && !dscp[0] && (daddr[0] || dport[0])) {
						DOCMDARGVS(iptables_cmd, DOWAIT, "-t mangle -A qos_rule_output %s %s %s %s %s -j MARK --set-mark 0x%x/0x%x",
							wanPort, proto1, sport, daddr, dport, mark, QOS_MARK_MASK);
					}

					if(proto2) /*OK, Here it comes again. TCP/UDP*/
					{
						//forward chain
						DOCMDARGVS(iptables_cmd, DOWAIT, "-t mangle -A %s %s %s %s %s %s %s %s %s %s -j MARK --set-mark 0x%x/0x%x",
							QOS_IP_CHAIN, phyPort, wanPort, proto2, saddr, sport, daddr, dport, dscp, strmark, mark, QOS_MARK_MASK);
						//output chain
						if (!entry.phyPort && !saddr[0] && !strmark[0] && !dscp[0] && (daddr[0] || dport[0])) {
							DOCMDARGVS(iptables_cmd, DOWAIT, "-t mangle -A qos_rule_output %s %s %s %s %s -j MARK --set-mark 0x%x/0x%x",
								wanPort, proto2, sport, daddr, dport, mark, QOS_MARK_MASK);
						}
					}
				/*ql:20080825 START: for tr069 pvc, just set priority according to wanport*/
				}
				/*ql:20080825 END*/
			} else {
				// Mason Yu. match IN interface error
				//if (phyPort[0]) {
					DOCMDARGVS(EBTABLES, DOWAIT, "-t %s -A %s %s %s %s %s %s %s %s %s %s %s %s -j mark --mark-or 0x%x", "broute",
						QOS_EB_CHAIN, phyPort, eth_proto, proto1, smac, dmac, saddr, sport, daddr, dport, dscp, strmark, mark);
					if(proto2) /*OK, Here it comes again. TCP/UDP*/
					{
						DOCMDARGVS(EBTABLES, DOWAIT, "-t %s -A %s %s %s %s %s %s %s %s %s %s %s %s -j mark --mark-or 0x%x", "broute",
							QOS_EB_CHAIN, phyPort, eth_proto, proto2, smac, dmac, saddr, sport, daddr, dport, dscp, strmark, mark);
					}
				#if 0
				} else {
					snprintf(phyPort1, 16, "-i eth0");
					DOCMDARGVS(EBTABLES, DOWAIT, "-t %s -A %s %s %s %s %s %s %s %s %s %s %s %s -j mark --mark-or 0x%x", "broute",
						QOS_EB_CHAIN, phyPort1, eth_proto, proto1, smac, dmac, saddr, sport, daddr, dport, dscp, strmark, mark);
					if(proto2)
					{
						DOCMDARGVS(EBTABLES, DOWAIT, "-t %s -A %s %s %s %s %s %s %s %s %s %s %s %s -j mark --mark-or 0x%x", "broute",
							QOS_EB_CHAIN, phyPort1, eth_proto, proto2, smac, dmac, saddr, sport, daddr, dport, dscp, strmark, mark);
					}

					snprintf(phyPort1, 16, "-i wlan0");
					DOCMDARGVS(EBTABLES, DOWAIT, "-t %s -A %s %s %s %s %s %s %s %s %s %s %s %s -j mark --mark-or 0x%x", "broute",
						QOS_EB_CHAIN, phyPort1, eth_proto, proto1, smac, dmac, saddr, sport, daddr, dport, dscp, strmark, mark);
					if(proto2)
					{
						DOCMDARGVS(EBTABLES, DOWAIT, "-t %s -A %s %s %s %s %s %s %s %s %s %s %s %s -j mark --mark-or 0x%x", "broute",
							QOS_EB_CHAIN, phyPort1, eth_proto, proto2, smac, dmac, saddr, sport, daddr, dport, dscp, strmark, mark);
					}
				}
				#endif
			}
#ifdef QOS_SUPPORT_RTP
		} else {
			if (!ebtable) {
				for (j=0; j<rtpRuleCnt; j++) {
					DOCMDARGVS(iptables_cmd, DOWAIT, "-t mangle -A %s %s %s %s %s %s %s %s %s %s -j MARK --set-mark 0x%x/0x%x",
						QOS_RTP_CHAIN, phyPort, wanPort, proto1, saddr, sport, rtp_rule_entry[j].daddr, rtp_rule_entry[j].dport, dscp, strmark, mark, QOS_MARK_MASK);
				}
			}
		}
#endif

		//set dscp
		if( enableDscpMark && (0 != entry.m_dscp))
		{
#ifdef QOS_SUPPORT_RTP
			if (entry.protoType != 5)//RTP
			{
#endif
				if (!ebtable) {
					if (!ebtable) {
						//forward chain
						DOCMDARGVS(iptables_cmd, DOWAIT, "-t mangle -A %s %s %s %s %s %s %s %s %s %s -j DSCP --set-dscp 0x%x",
							QOS_IP_CHAIN, phyPort, wanPort, proto1, saddr, sport, daddr, dport, dscp, strmark, (entry.m_dscp-1)>>2);
						//output chain
						if (!entry.phyPort && !saddr[0] && !strmark[0] && !dscp[0] && (daddr[0] || dport[0])) {
							DOCMDARGVS(iptables_cmd, DOWAIT, "-t mangle -A qos_rule_output %s %s %s %s %s -j DSCP --set-dscp 0x%x",
								wanPort, proto1, sport, daddr, dport, (entry.m_dscp-1)>>2);
						}

						if(proto2)/* TCP/UDP, bored, why not set twice, any other wise idea? */
						{
							//forward chain
							DOCMDARGVS(iptables_cmd, DOWAIT, "-t mangle -A %s %s %s %s %s %s %s %s %s %s -j DSCP --set-dscp 0x%x",
								QOS_IP_CHAIN, phyPort, wanPort, proto2, saddr, sport, daddr, dport, dscp, strmark, (entry.m_dscp-1)>>2);
							//output chain
							if (!entry.phyPort && !saddr[0] && !strmark[0] && !dscp[0] && (daddr[0] || dport[0])) {
								DOCMDARGVS(iptables_cmd, DOWAIT, "-t mangle -A qos_rule_output %s %s %s %s %s -j DSCP --set-dscp 0x%x",
									wanPort, proto2, sport, daddr, dport, (entry.m_dscp-1)>>2);
							}
						}
					}
				} else {
					// Mason Yu. match IN interface error
					//if (phyPort[0]) {
						DOCMDARGVS(EBTABLES, DOWAIT, "-t %s -A %s %s %s %s %s %s %s %s %s %s %s %s -j ftos --set-ftos 0x%x", "broute",
							QOS_EB_CHAIN, phyPort, eth_proto, proto1, smac, dmac, saddr, sport, daddr, dport, dscp, strmark, (entry.m_dscp-1)&0xFF);

						if(proto2)/* TCP/UDP, bored, why not set twice, any other wise idea? */
						{
							DOCMDARGVS(EBTABLES, DOWAIT, "-t %s -A %s %s %s %s %s %s %s %s %s %s %s %s -j ftos --set-ftos 0x%x", "broute",
								QOS_EB_CHAIN, phyPort, eth_proto, proto2, smac, dmac, saddr, sport, daddr, dport, dscp, strmark, (entry.m_dscp-1)&0xFF);
						}
					#if 0
					} else {
						snprintf(phyPort1, 16, "-i eth0");
						DOCMDARGVS(EBTABLES, DOWAIT, "-t %s -A %s %s %s %s %s %s %s %s %s %s %s %s -j ftos --set-ftos 0x%x", "broute",
							QOS_EB_CHAIN, phyPort1, eth_proto, proto1, smac, dmac, saddr, sport, daddr, dport, dscp, strmark, (entry.m_dscp-1)&0xFF);

						if(proto2)
						{
							DOCMDARGVS(EBTABLES, DOWAIT, "-t %s -A %s %s %s %s %s %s %s %s %s %s %s %s -j ftos --set-ftos 0x%x", "broute",
								QOS_EB_CHAIN, phyPort1, eth_proto, proto2, smac, dmac, saddr, sport, daddr, dport, dscp, strmark, (entry.m_dscp-1)&0xFF);
						}

						snprintf(phyPort1, 16, "-i wlan0");
						DOCMDARGVS(EBTABLES, DOWAIT, "-t %s -A %s %s %s %s %s %s %s %s %s %s %s %s -j ftos --set-ftos 0x%x", "broute",
							QOS_EB_CHAIN, phyPort1, eth_proto, proto1, smac, dmac, saddr, sport, daddr, dport, dscp, strmark, (entry.m_dscp-1)&0xFF);

						if(proto2)
						{
							DOCMDARGVS(EBTABLES, DOWAIT, "-t %s -A %s %s %s %s %s %s %s %s %s %s %s %s -j ftos --set-ftos 0x%x", "broute",
								QOS_EB_CHAIN, phyPort1, eth_proto, proto2, smac, dmac, saddr, sport, daddr, dport, dscp, strmark, (entry.m_dscp-1)&0xFF);
						}
					}
					#endif
				}
#ifdef QOS_SUPPORT_RTP
			} else {
				if (!ebtable) {
					for (j=0; j<rtpRuleCnt; j++) {
						DOCMDARGVS(iptables_cmd, DOWAIT, "-t mangle -A %s %s %s %s %s %s %s %s %s %s -j DSCP --set-dscp 0x%x",
							QOS_RTP_CHAIN, phyPort, wanPort, proto1, saddr, sport, rtp_rule_entry[j].daddr, rtp_rule_entry[j].dport, dscp, strmark, (entry.m_dscp-1)>>2);
					}
				}
			}
#endif
	}
 vcEntryNum = mib_chain_total(MIB_ATM_VC_TBL);

#ifndef QOS_SETUP_IMQ
		if(PLY_PRIO==policy)//priority queue
		{
			//DOCMDARGVS(TC, DOWAIT, "filter add dev %s parent 1: prio %d protocol ip handle 0x%x/0x%x fw flowid 1:%d",
			//	ifname, entry.prior, mark, QOS_MARK_MASK, entry.prior);
			for(j=0; j<vcEntryNum; j++)
			{
				if(!mib_chain_get(MIB_ATM_VC_TBL, j, &vcEntry))
					continue;

				ifGetName(vcEntry.ifIndex, ifname, sizeof(ifname));
				DOCMDARGVS(TC, DOWAIT, "filter add dev %s parent 1: prio %d %s handle 0x%x/0x%x fw flowid 1:%d",
					ifname, entry.prior, tc_protocol, mark, QOS_MARK_MASK, entry.prior);
			}
		}
		else if(PLY_WRR==policy)//weighted round robin
		{
			for(j=0; j<vcEntryNum; j++)
			{
				if(!mib_chain_get(MIB_ATM_VC_TBL, j, &vcEntry))
					continue;

				ifGetName(vcEntry.ifIndex, ifname, sizeof(ifname));

				DOCMDARGVS(TC, DOWAIT, "filter add dev %s parent 1: prio 1 %s handle 0x%x/0x%x fw flowid 1:%d00",
					ifname, tc_protocol, mark, QOS_MARK_MASK, entry.prior);
			}
		}
#else
		if(PLY_PRIO==policy)//priority queue
		{
			// Mason Yu. Use device name not imq0
			//DOCMDARGVS(TC, DOWAIT, "filter add dev imq0 parent 1: prio %d %s handle 0x%x/0x%x fw flowid 1:%d",
			for(j=0; j<vcEntryNum; j++)
			{
				if(!mib_chain_get(MIB_ATM_VC_TBL, j, &vcEntry))
					continue;

				ifGetName(vcEntry.ifIndex, ifname, sizeof(ifname));
				DOCMDARGVS(TC, DOWAIT, "filter add dev %s parent 1: prio %d %s handle 0x%x/0x%x fw flowid 1:%d",
					ifname, entry.prior, tc_protocol, mark, QOS_MARK_MASK, entry.prior);
			}
		}
		else if(PLY_WRR==policy)//weighted round robin
		{
			DOCMDARGVS(TC, DOWAIT, "filter add dev imq0 parent 1: prio 1 %s handle 0x%x/0x%x fw flowid 1:%d00",
				tc_protocol, mark, QOS_MARK_MASK, entry.prior);

			// Mason Yu.
			// If the vc is bridge mode , set tc action mirred and redirect to img0
			if (ebtable) {
				for(j=0; j<vcEntryNum; j++)
				{
					if(!mib_chain_get(MIB_ATM_VC_TBL, j, &vcEntry))
						continue;

					ifGetName(vcEntry.ifIndex, ifname, sizeof(ifname));
					DOCMDARGVS(TC, DOWAIT, "filter add dev %s parent 1: prio 1 %s handle 0x%x/0x%x fw flowid 1:1 action mirred egress redirect dev imq0",
						ifname, tc_protocol, mark, QOS_MARK_MASK);
				}
			}
		}
#endif

#ifndef CONFIG_RTK_L34_ENABLE
		//if ( (wan_qos_state&QOS_WAN_BRIDGE) != QOS_WAN_BRIDGE) {
			// hwnat qos
			hwnat_qos_translate_rule(&entry);
		//}
#else
		printf("%s %d#######################################\n",__FUNCTION__,__LINE__);
		RTK_RG_QoS_Rule_Set(&entry);
#endif
	}
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	RTK_RG_QoS_Rule_Set_defaultUSRule();
#endif

    return 0;
}
 #else
static int setup_qos_rules(unsigned char policy)
{
	MIB_CE_IP_QOS_T entry;
	MIB_CE_ATM_VC_T vcEntry;
	int i, j, EntryNum = 0, vcEntryNum = 0;
	unsigned char enableDscpMark=1;
	unsigned char enableQos1p=2;  // enableQos1p=0: not use, enableQos1p=1: use old value, enableQos1p=2: mark new value
#ifdef QOS_SUPPORT_RTP
	FILE *fp;
	char buff[100];
	unsigned int rtp_dip;
	unsigned int rtp_dpt;
	unsigned int rtpCnt=0, rtpRuleCnt=0;
	struct rtp_struct {
		unsigned int dip;
		unsigned int dport;
	} __PACK__;
	struct rtp_rule_st {
		char daddr[48];
		char dport[48];
	} __PACK__;

	struct rtp_struct rtp_entry[RTP_RULE_NUM_MAX];
	struct rtp_rule_st rtp_rule_entry[RTP_RULE_NUM_MAX];
#endif

	DOCMDINIT

	QOS_SETUP_PRINT_FUNCTION

	if(PLY_WRR==policy)//weighted round robin
	{
		if (!ifSumWeighIs100())
			return 1;
	}

	//get current RTP stream info
#ifdef QOS_SUPPORT_RTP
	if (!(fp=fopen(RTP_PORT_FILE, "r"))) {
		printf("no RTP connection!\n");
	} else {
		while ( fgets(buff, sizeof(buff), fp) != NULL ) {
			if(sscanf(buff, "dip=%d dport=%d", &rtp_dip, &rtp_dpt)!=2) {
				printf("Unsuported rtp format\n");
				break;
			}
			else {
				rtpCnt++;
				rtp_entry[rtpCnt-1].dip = rtp_dip;
				rtp_entry[rtpCnt-1].dport = rtp_dpt;
			}
		}
		fclose(fp);
	}
#endif
#if defined(CONFIG_USER_IP_QOS) && defined(_PRMT_X_CT_COM_QOS_)
	mib_get(MIB_QOS_ENABLE_DSCP_MARK, (void *)&enableDscpMark);
	mib_get(MIB_QOS_ENABLE_1P, (void *)&enableQos1p);
#endif

	EntryNum = mib_chain_total(MIB_IP_QOS_TBL);
	for(i=0; i<EntryNum; i++)
	{
		char ifname[IFNAMSIZ], phyPort[16]={0};
		char phyPort1[16]={0};
		char wanPort[16]={0};
		char sport[48], dport[48], saddr[75], daddr[75], strmark[48];
		char tmpstr[48];
		char *proto1=NULL, *proto2 = NULL, *eth_proto = NULL;
		char *iptables_cmd=NULL, *tc_protocol=NULL;
		char dscp[24] = {0};
		unsigned int mark=0;
		char smac[48], dmac[48];
		//ql
		unsigned int wan_qos_state = 0;
		unsigned int wan_vlan_enable = 0;
		/*ql:20080825 START: for tr069 pvc, just set priority according to wanport*/
		unsigned int wan_tr069=0;
		/*ql:20080825 END*/
		unsigned int ebtable=0;

		if(!mib_chain_get(MIB_IP_QOS_TBL, i, (void*)&entry)||!entry.enable)
		    continue;

		if(!isQueneEnableForRule(entry.prior) && !entry.classtype)
			continue;

#ifdef BR_ROUTE_ONEPVC
		wan_qos_state = get_pvc_qos_state(entry.outif, entry.cmode);
#else
		wan_qos_state = get_pvc_qos_state(entry.outif);
#endif
		wan_vlan_enable = wan_qos_state&QOS_WAN_VLAN_ENABLE;
		/*ql:20080825 START: for tr069 pvc, just set priority according to wanport*/
		wan_tr069 = wan_qos_state&QOS_WAN_TR069;
		/*ql:20080825 END*/
#ifdef BR_ROUTE_ONEPVC
		if ((entry.outif != DUMMY_IFINDEX) && (entry.cmode == CHANNEL_MODE_BRIDGE))
			ebtable = 1;
#else
		ebtable = wan_qos_state&QOS_WAN_BRIDGE;
#endif
		// If this rule is for All WAN interface(DUMMY_IFINDEX), use ebtables to set rule.
	    if ( entry.outif == DUMMY_IFINDEX ) {
			ebtable = 1;
		}

		//interface
		if ( entry.outif != DUMMY_IFINDEX ) {
			ifGetName(entry.outif, ifname, sizeof(ifname));

			//wan port
			snprintf(wanPort, 16, "-o %s", ifname);
		}

		if (memcmp(entry.smac, EMPTY_MAC, MAC_ADDR_LEN)) {
			mac_hex2string(entry.smac, tmpstr);
			snprintf(smac, 48, "-s %s", tmpstr);
		}
		else
			smac[0] = '\0';

		if (memcmp(entry.dmac, EMPTY_MAC, MAC_ADDR_LEN)) {
			mac_hex2string(entry.dmac, tmpstr);
			snprintf(dmac, 48, "-d %s", tmpstr);
		}
		else
			dmac[0] = '\0';

		if ((smac[0] != '\0') || (dmac[0] != '\0'))
			ebtable = 1;

		//phy port, 0: none, range:1-4
		if (entry.phyPort>=1 && entry.phyPort<=SW_LAN_PORT_NUM)
			snprintf(phyPort, 16, "-i %s", SW_LAN_PORT_IF[entry.phyPort-1]);
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
#ifdef WLAN_SUPPORT
		//range: 5-8 wlan0
		else if(entry.phyPort>SW_LAN_PORT_NUM && entry.phyPort<=(SW_LAN_PORT_NUM + WLAN_SSID_NUM)){
			if(entry.phyPort == (SW_LAN_PORT_NUM +1))
				snprintf(phyPort, 16, "-i wlan0");
			else
				snprintf(phyPort, 16, "-i wlan0-vap%d", entry.phyPort - SW_LAN_PORT_NUM - 2);
		}
#ifdef WLAN_DUALBAND_CONCURRENT
		//range: 9-12 wlan1
		else if(entry.phyPort>(SW_LAN_PORT_NUM + WLAN_SSID_NUM) && entry.phyPort<=(SW_LAN_PORT_NUM + 2*WLAN_SSID_NUM)){
			if(entry.phyPort == (SW_LAN_PORT_NUM + WLAN_SSID_NUM +1))
				snprintf(phyPort, 16, "-i wlan1");
			else
				snprintf(phyPort, 16, "-i wlan1-vap%d", entry.phyPort - SW_LAN_PORT_NUM - WLAN_SSID_NUM - 2);
		}
#endif
#endif
#endif
		else {
			if (ebtable)
				phyPort[0] = '\0';
			else
#ifdef CONFIG_PPPOE_PROXY_IF_NAME
				/*ql:20080805 START: qos enable for ppp proxy*/
				snprintf(phyPort, 16, "-i br+");
				/*ql: 20080805 END*/
#else
				snprintf(phyPort, 16, "-i br0");
#endif
		}

#ifdef QOS_DIFFSERV
		//dscp match
		if(0 != entry.qosDscp)
		{
			#ifdef CONFIG_IPV6
			if (ebtable) {
				// This is a IPv4 rule
				if ( entry.IpProtocol == IPVER_IPV4 )
					snprintf(dscp, 24, "--ip-tos 0x%x", (entry.qosDscp-1)&0xFF);
				// This is a IPv6 rule
				else if ( entry.IpProtocol == IPVER_IPV6 )
					snprintf(dscp, 24, "--ip6-tclass 0x%x", (entry.qosDscp-1)&0xFF);
			}
			#else
			if (ebtable)
				snprintf(dscp, 24, "--ip-tos 0x%x", (entry.qosDscp-1)&0xFF);
			#endif
			else
				snprintf(dscp, 24, "-m dscp --dscp 0x%x", (entry.qosDscp-1)>>2);
		}else{
		    dscp[0]='\0';
		}
#endif

#ifdef CONFIG_RTK_L34_ENABLE
		if(entry.protoType==5) {
			RTK_RG_QoS_Rule_Set(&entry);
			continue;
		}

#endif
		//protocol
#ifdef QOS_SUPPORT_RTP
		if(entry.protoType>5)//invalid protocol index
			return 1;
#else
		if(entry.protoType>4)//invalid protocol index
			return 1;
#endif

		//source port (range)
		if(0 == entry.protoType||1 == entry.protoType||0 == entry.sPort)
		{//if protocol is icmp or none or port not set, ignore the port
		    sport[0] = '\0';
		}
		else
		{
			#ifdef CONFIG_IPV6
			// This is a IPv4 rule
			if ( entry.IpProtocol == IPVER_IPV4 && ebtable) {
					if(0 != entry.sPortRangeMax)
						snprintf(sport, 48, "--ip-source-port %d:%d", MIN_PORT(entry.sPort, entry.sPortRangeMax),
							MAX_PORT(entry.sPort, entry.sPortRangeMax));
					else
						snprintf(sport, 48, "--ip-source-port %d", entry.sPort);
			}
			// This is a IPv6 rule
			else if ( entry.IpProtocol == IPVER_IPV6 && ebtable) {
					if(0 != entry.sPortRangeMax)
						snprintf(sport, 48, "--ip6-source-port %d:%d", MIN_PORT(entry.sPort, entry.sPortRangeMax),
							MAX_PORT(entry.sPort, entry.sPortRangeMax));
					else
						snprintf(sport, 48, "--ip6-source-port %d", entry.sPort);
			}
			#else
			if (ebtable) {
				if(0 != entry.sPortRangeMax)
					snprintf(sport, 48, "--ip-source-port %d:%d", MIN_PORT(entry.sPort, entry.sPortRangeMax),
						MAX_PORT(entry.sPort, entry.sPortRangeMax));
				else
					snprintf(sport, 48, "--ip-source-port %d", entry.sPort);
			}
			#endif
			else {
				if(0 != entry.sPortRangeMax)
					snprintf(sport, 48, "--sport %d:%d", MIN_PORT(entry.sPort, entry.sPortRangeMax),
						MAX_PORT(entry.sPort, entry.sPortRangeMax));
				else
					snprintf(sport, 48, "--sport %d", entry.sPort);
			}
		}

#ifdef CONFIG_IPV6
		// This is a IPv4 rule
		if ( entry.IpProtocol == IPVER_IPV4 ) {
			//source address
			//snprintf(tmpstr, 16, "%s", inet_ntoa(*((struct in_addr *)entry.sip)));
			//convertIPAddrToString(*((unsigned int*)(entry.sip)),tmpstr);
			inet_ntop(AF_INET, entry.sip, tmpstr, sizeof(tmpstr));
			if (strcmp(tmpstr, ARG_0x4)) {
				if (ebtable) {
					if(0 != entry.smaskbit)
						snprintf(saddr, 48, "--ip-source %s/%d",
							tmpstr, entry.smaskbit );
					else
						snprintf(saddr, 48, "--ip-source %s", tmpstr);
				}
				else {
					if(0 != entry.smaskbit)
						snprintf(saddr, 48, "-s %s/%d",
							tmpstr, entry.smaskbit );
					else
						snprintf(saddr, 48, "-s %s", tmpstr);
				}
			}
			else
				saddr[0]='\0';
		}
		// This is a IPv6 rule
		else if ( entry.IpProtocol == IPVER_IPV6 ) {
			//source address
			inet_ntop(PF_INET6, (struct in6_addr *)entry.sip6, tmpstr, sizeof(tmpstr));
			if (strcmp(tmpstr, "::")) {
				if (ebtable) {
					if(0 != entry.sip6PrefixLen)
						snprintf(saddr, 75, "--ip6-source %s/%d",
							tmpstr, entry.sip6PrefixLen );
					else
						snprintf(saddr, 75, "--ip6-source %s", tmpstr);
				}
				else {
					if(0 != entry.sip6PrefixLen)
						snprintf(saddr, 75, "-s %s/%d",
							tmpstr, entry.sip6PrefixLen );
					else
						snprintf(saddr, 75, "-s %s", tmpstr);
				}
			}
			else
				saddr[0]='\0';
		}
#else
		//source address
		//snprintf(tmpstr, 16, "%s", inet_ntoa(*((struct in_addr *)entry.sip)));
		//convertIPAddrToString(*((unsigned int*)(entry.sip)),tmpstr);
		inet_ntop(AF_INET, entry.sip, tmpstr, sizeof(tmpstr));
		if (strcmp(tmpstr, ARG_0x4)) {
			if (ebtable) {
				if(0 != entry.smaskbit)
					snprintf(saddr, 48, "--ip-source %s/%d",
						tmpstr, entry.smaskbit );
				else
					snprintf(saddr, 48, "--ip-source %s", tmpstr);
			}
			else {
				if(0 != entry.smaskbit)
					snprintf(saddr, 48, "-s %s/%d",
						tmpstr, entry.smaskbit );
				else
					snprintf(saddr, 48, "-s %s", tmpstr);
			}
		}
		else
			saddr[0]='\0';
#endif

#ifdef QOS_SUPPORT_RTP
		if (entry.protoType == 5)//RTP
		{
			if (0 == rtpCnt)//no rtp stream found
				continue;

			if (ebtable)
				continue;//don't process such rule
			else
				proto1 = "-p UDP";

			rtpRuleCnt = 0;
/*star:20090407 START only parse rtp src port*/
			//snprintf(tmpstr, 16, "%s", inet_ntoa(*((struct in_addr *)entry.dip)));
			//convertIPAddrToString(*((unsigned int*)(entry.dip)),tmpstr);
			inet_ntop(AF_INET, entry.dip, tmpstr, sizeof(tmpstr));
			if (strcmp(tmpstr, ARG_0x4)) {
				for (j=0; j<rtpCnt; j++) {
					rtpRuleCnt++;

					if(0 != entry.dmaskbit)
						snprintf(rtp_rule_entry[rtpRuleCnt-1].daddr, 26, "-d %s/%d",
							tmpstr, entry.dmaskbit );
					else
						snprintf(rtp_rule_entry[rtpRuleCnt-1].daddr, 26, "-d %s", tmpstr);

					snprintf(rtp_rule_entry[rtpRuleCnt-1].dport, 24, "--sport %d", rtp_entry[j].dport);
				}
				if (rtpRuleCnt==0)//not found .
					continue;
			} else {
				for (j=0; j<rtpCnt; j++) {
					rtpRuleCnt++;
					//snprintf(rtp_rule_entry[rtpRuleCnt-1].daddr, 26, "-d %s", inet_ntoa(*((struct in_addr*)(&rtp_entry[j].dip))));
					rtp_rule_entry[rtpRuleCnt-1].daddr[0]=0;
					snprintf(rtp_rule_entry[rtpRuleCnt-1].dport, 24, "--sport %d", rtp_entry[j].dport);
				}
			}
		}
		else
		{
#endif
			if(entry.protoType == 4)//add by penggenyao, support two protos at the same time
			{
				#ifdef CONFIG_IPV6
				if (ebtable) {
					// This is a IPv4 rule
					if ( entry.IpProtocol == IPVER_IPV4 ) {
						proto1 = "--ip-proto 6";
						proto2 = "--ip-proto 17";
					}
					// This is a IPv6 rule
					else if ( entry.IpProtocol == IPVER_IPV6 ) {
						proto1 = "--ip6-proto 6";
						proto2 = "--ip6-proto 17";
					}
				}
				#else
				if (ebtable) {
					proto1 = "--ip-proto 6";
					proto2 = "--ip-proto 17";
				}
				#endif
				else {
				    proto1 = "-p TCP";
				    proto2 = "-p UDP";
				}
			}
			else {
				#ifdef CONFIG_IPV6
				if (ebtable) {
					// This is a IPv4 rule
					if ( entry.IpProtocol == IPVER_IPV4 )
						proto1 = proto2str2layer[entry.protoType];
					// This is a IPv6 rule
					else if ( entry.IpProtocol == IPVER_IPV6 )
						proto1 = proto2str2layer_v6[entry.protoType];
				}
				else {
					// This is a IPv4 rule
					if ( entry.IpProtocol == IPVER_IPV4 )
						proto1 = proto2str[entry.protoType];
					// This is a IPv6 rule
					else if ( entry.IpProtocol == IPVER_IPV6 )
						proto1 = proto2str_v6[entry.protoType];
				}
				#else
				if (ebtable)
					proto1 = proto2str2layer[entry.protoType];
				else
					proto1 = proto2str[entry.protoType];
				#endif

			}

			//dest port (range)
			if(0 == entry.protoType||1 == entry.protoType||0 == entry.dPort)
			{//if protocol is icmp or none or port not set, ignore the port
			    dport[0] = '\0';
			}
			else
			{
				#ifdef CONFIG_IPV6
				// This is a IPv4 rule
				if ( entry.IpProtocol == IPVER_IPV4 && ebtable) {
						if(0 != entry.dPortRangeMax)
							snprintf(dport, 48, "--ip-destination-port %d:%d", MIN_PORT(entry.dPort, entry.dPortRangeMax),
								MAX_PORT(entry.dPort, entry.dPortRangeMax));
						else
							snprintf(dport, 48, "--ip-destination-port %d", entry.dPort);
				}
				// This is a IPv6 rule
				else if ( entry.IpProtocol == IPVER_IPV6 && ebtable) {
						if(0 != entry.dPortRangeMax)
							snprintf(dport, 48, "--ip6-destination-port %d:%d", MIN_PORT(entry.dPort, entry.dPortRangeMax),
								MAX_PORT(entry.dPort, entry.dPortRangeMax));
						else
							snprintf(dport, 48, "--ip6-destination-port %d", entry.dPort);
				}
				#else
				if (ebtable) {
					if(0 != entry.dPortRangeMax)
						snprintf(dport, 48, "--ip-destination-port %d:%d", MIN_PORT(entry.dPort, entry.dPortRangeMax),
							MAX_PORT(entry.dPort, entry.dPortRangeMax));
					else
						snprintf(dport, 48, "--ip-destination-port %d", entry.dPort);
				}
				#endif
				else {
				    if(0 != entry.dPortRangeMax)
						snprintf(dport, 48, "--dport %d:%d", MIN_PORT(entry.dPort, entry.dPortRangeMax),
							MAX_PORT(entry.dPort, entry.dPortRangeMax));
				    else
						snprintf(dport, 48, "--dport %d", entry.dPort);
				}
			}

#ifdef CONFIG_IPV6
			// This is a IPv4 rule
			if ( entry.IpProtocol == IPVER_IPV4 ) {
				//dest address
				//snprintf(tmpstr, 16, "%s", inet_ntoa(*((struct in_addr *)entry.dip)));
				//convertIPAddrToString(*((unsigned int*)(entry.dip)),tmpstr);
				inet_ntop(AF_INET, entry.dip, tmpstr, sizeof(tmpstr));
				if (strcmp(tmpstr, ARG_0x4)) {
					if (ebtable) {
						if(0 != entry.dmaskbit)
							snprintf(daddr, 48, "--ip-destination %s/%d",
								tmpstr, entry.dmaskbit );
						else
							snprintf(daddr, 48, "--ip-destination %s", tmpstr);
					} else {
						if(0 != entry.dmaskbit)
							snprintf(daddr, 48, "-d %s/%d",
								tmpstr, entry.dmaskbit );
						else
							snprintf(daddr, 48, "-d %s", tmpstr);
					}
				}
				else
					daddr[0]='\0';
			}
			// This is a IPv6 rule
			else if ( entry.IpProtocol == IPVER_IPV6 ){
				//dest address
				inet_ntop(PF_INET6, (struct in6_addr *)entry.dip6, tmpstr, sizeof(tmpstr));
				if (strcmp(tmpstr, "::")) {
					if (ebtable) {
						if(0 != entry.dip6PrefixLen)
							snprintf(daddr, 75, "--ip6-destination %s/%d",
								tmpstr, entry.dip6PrefixLen );
						else
							snprintf(daddr, 75, "--ip6-destination %s", tmpstr);
					}
					else {
						if(0 != entry.dip6PrefixLen)
							snprintf(daddr, 75, "-d %s/%d",
								tmpstr, entry.dip6PrefixLen );
						else
							snprintf(daddr, 75, "-d %s", tmpstr);
					}
				}
				else {
					daddr[0]='\0';
				}
			}
#else
			//dest address
			//snprintf(tmpstr, 16, "%s", inet_ntoa(*((struct in_addr *)entry.dip)));
			//convertIPAddrToString(*((unsigned int*)(entry.dip)),tmpstr);
			inet_ntop(AF_INET, entry.dip, tmpstr, sizeof(tmpstr));
			if (strcmp(tmpstr, ARG_0x4)) {
				if (ebtable) {
					if(0 != entry.dmaskbit)
						snprintf(daddr, 48, "--ip-destination %s/%d",
							tmpstr, entry.dmaskbit );
					else
						snprintf(daddr, 48, "--ip-destination %s", tmpstr);
				} else {
					if(0 != entry.dmaskbit)
						snprintf(daddr, 48, "-d %s/%d",
							tmpstr, entry.dmaskbit );
					else
						snprintf(daddr, 48, "-d %s", tmpstr);
				}
			}
			else
				daddr[0]='\0';
#endif

#ifdef QOS_SUPPORT_RTP
		}
#endif

		//lan 802.1p mark, 0-7 bit(match)
		if(0 != entry.vlan1p) {
			if (ebtable)
				snprintf(strmark, 48, "--vlan-prio %d", (entry.vlan1p-1)&0xff);
			else
				snprintf(strmark, 48, "-m mark --mark 0x%x/0x%x", entry.vlan1p&QOS_8021P_MASK, QOS_8021P_MASK);
		} else
			strmark[0] = '\0';

		if (ebtable) {
			if(strmark[0] != '\0')//vlan 802.1p priority, use 802.1Q ethernet protocol
			{
				eth_proto = "-p 0x8100";
			}
			else {//use ipv4 for ethernet protocol
#ifdef CONFIG_IPV6
				// This is a IPv4 rule
				if ( entry.IpProtocol == IPVER_IPV4 )
					eth_proto = "-p 0x0800";
				// This is a IPv6 rule
				else if ( entry.IpProtocol == IPVER_IPV6 )
					eth_proto = "-p 0x86dd";
				else
					eth_proto = " ";
#else
				if (!isQosMacRule(&entry))
					eth_proto = "-p 0x0800";
				else
					eth_proto = " ";
#endif
			}
		}

		//wan 802.1p mark 0-7 bit: 802.1p, 8-15 bit: queue id
		// We can not use 0 to as tc handle. So we use (i+1).
		// enableQos1p=0: not use, enableQos1p=1: use old value, enableQos1p=2: mark new value
		if (2 != enableQos1p) {
			mark |= ((i+1)<<8);
		} else {
			if((0 != entry.m_1p) && wan_vlan_enable) {
			    mark = (entry.m_1p-1)&0xff;
				//ql 20090106 START: set bit 16 of nfmark when tag 802.1p
				mark |= (((i+1)<<8) | (1<<16));
			}
			else {
				mark |= ((i+1)<<8);
			}
		}//else if enableQos1p==0, mark=0
		//ql 20090106 START: set bit 16 of nfmark when tag 802.1p
		//mark |= ((entry.index<<12) | (1<<24));
		//ql 20090106 END

#ifdef CONFIG_IPV6
		// This is a IPv4 rule
		if ( entry.IpProtocol == IPVER_IPV4 ) {
			iptables_cmd = "/bin/iptables";
			tc_protocol = "protocol ip";
		}
		// This is a IPv6 rule
		else {
			iptables_cmd = "/bin/ip6tables";
			tc_protocol = "protocol ipv6";
		}
#else
		// This is a IPv4 rule
		iptables_cmd = "/bin/iptables";
		tc_protocol = "protocol ip";
#endif

		//set the mark
#ifdef QOS_SUPPORT_RTP
		if (entry.protoType != 5)//RTP
		{
#endif
			if (!ebtable) {
				/*ql:20080825 START: for tr069 pvc, just set priority according to wanport*/
				if (wan_tr069)
				{
					DOCMDARGVS(iptables_cmd, DOWAIT, "-t mangle -A qos_rule_output %s -j MARK --set-mark 0x%x/0x%x",
						wanPort, mark, QOS_MARK_MASK);
				} else {
				/*ql:20080825 END*/
					//forward chain
					DOCMDARGVS(iptables_cmd, DOWAIT, "-t mangle -A %s %s %s %s %s %s %s %s %s %s -j MARK --set-mark 0x%x/0x%x",
						QOS_IP_CHAIN, phyPort, wanPort, proto1, saddr, sport, daddr, dport, dscp, strmark, mark, QOS_MARK_MASK);
					//output chain
					if (!entry.phyPort && !saddr[0] && !strmark[0] && !dscp[0] && (daddr[0] || dport[0])) {
						DOCMDARGVS(iptables_cmd, DOWAIT, "-t mangle -A qos_rule_output %s %s %s %s %s -j MARK --set-mark 0x%x/0x%x",
							wanPort, proto1, sport, daddr, dport, mark, QOS_MARK_MASK);
					}

					if(proto2) /*OK, Here it comes again. TCP/UDP*/
					{
						//forward chain
						DOCMDARGVS(iptables_cmd, DOWAIT, "-t mangle -A %s %s %s %s %s %s %s %s %s %s -j MARK --set-mark 0x%x/0x%x",
							QOS_IP_CHAIN, phyPort, wanPort, proto2, saddr, sport, daddr, dport, dscp, strmark, mark, QOS_MARK_MASK);
						//output chain
						if (!entry.phyPort && !saddr[0] && !strmark[0] && !dscp[0] && (daddr[0] || dport[0])) {
							DOCMDARGVS(iptables_cmd, DOWAIT, "-t mangle -A qos_rule_output %s %s %s %s %s -j MARK --set-mark 0x%x/0x%x",
								wanPort, proto2, sport, daddr, dport, mark, QOS_MARK_MASK);
						}
					}
				/*ql:20080825 START: for tr069 pvc, just set priority according to wanport*/
				}
				/*ql:20080825 END*/
			} else {
				// Mason Yu. match IN interface error
				//if (phyPort[0]) {
					DOCMDARGVS(EBTABLES, DOWAIT, "-t %s -A %s %s %s %s %s %s %s %s %s %s %s %s -j mark --mark-or 0x%x", "broute",
						QOS_EB_CHAIN, phyPort, eth_proto, proto1, smac, dmac, saddr, sport, daddr, dport, dscp, strmark, mark);
					if(proto2) /*OK, Here it comes again. TCP/UDP*/
					{
						DOCMDARGVS(EBTABLES, DOWAIT, "-t %s -A %s %s %s %s %s %s %s %s %s %s %s %s -j mark --mark-or 0x%x", "broute",
							QOS_EB_CHAIN, phyPort, eth_proto, proto2, smac, dmac, saddr, sport, daddr, dport, dscp, strmark, mark);
					}
				#if 0
				} else {
					snprintf(phyPort1, 16, "-i eth0");
					DOCMDARGVS(EBTABLES, DOWAIT, "-t %s -A %s %s %s %s %s %s %s %s %s %s %s %s -j mark --mark-or 0x%x", "broute",
						QOS_EB_CHAIN, phyPort1, eth_proto, proto1, smac, dmac, saddr, sport, daddr, dport, dscp, strmark, mark);
					if(proto2)
					{
						DOCMDARGVS(EBTABLES, DOWAIT, "-t %s -A %s %s %s %s %s %s %s %s %s %s %s %s -j mark --mark-or 0x%x", "broute",
							QOS_EB_CHAIN, phyPort1, eth_proto, proto2, smac, dmac, saddr, sport, daddr, dport, dscp, strmark, mark);
					}

					snprintf(phyPort1, 16, "-i wlan0");
					DOCMDARGVS(EBTABLES, DOWAIT, "-t %s -A %s %s %s %s %s %s %s %s %s %s %s %s -j mark --mark-or 0x%x", "broute",
						QOS_EB_CHAIN, phyPort1, eth_proto, proto1, smac, dmac, saddr, sport, daddr, dport, dscp, strmark, mark);
					if(proto2)
					{
						DOCMDARGVS(EBTABLES, DOWAIT, "-t %s -A %s %s %s %s %s %s %s %s %s %s %s %s -j mark --mark-or 0x%x", "broute",
							QOS_EB_CHAIN, phyPort1, eth_proto, proto2, smac, dmac, saddr, sport, daddr, dport, dscp, strmark, mark);
					}
				}
				#endif
			}
#ifdef QOS_SUPPORT_RTP
		} else {
			if (!ebtable) {
				for (j=0; j<rtpRuleCnt; j++) {
					DOCMDARGVS(iptables_cmd, DOWAIT, "-t mangle -A %s %s %s %s %s %s %s %s %s %s -j MARK --set-mark 0x%x/0x%x",
						QOS_RTP_CHAIN, phyPort, wanPort, proto1, saddr, sport, rtp_rule_entry[j].daddr, rtp_rule_entry[j].dport, dscp, strmark, mark, QOS_MARK_MASK);
				}
			}
		}
#endif

		//set dscp
		if( enableDscpMark && (0 != entry.m_dscp))
		{
#ifdef QOS_SUPPORT_RTP
			if (entry.protoType != 5)//RTP
			{
#endif
				if (!ebtable) {
					if (!ebtable) {
						//forward chain
						DOCMDARGVS(iptables_cmd, DOWAIT, "-t mangle -A %s %s %s %s %s %s %s %s %s %s -j DSCP --set-dscp 0x%x",
							QOS_IP_CHAIN, phyPort, wanPort, proto1, saddr, sport, daddr, dport, dscp, strmark, (entry.m_dscp-1)>>2);
						//output chain
						if (!entry.phyPort && !saddr[0] && !strmark[0] && !dscp[0] && (daddr[0] || dport[0])) {
							DOCMDARGVS(iptables_cmd, DOWAIT, "-t mangle -A qos_rule_output %s %s %s %s %s -j DSCP --set-dscp 0x%x",
								wanPort, proto1, sport, daddr, dport, (entry.m_dscp-1)>>2);
						}

						if(proto2)/* TCP/UDP, bored, why not set twice, any other wise idea? */
						{
							//forward chain
							DOCMDARGVS(iptables_cmd, DOWAIT, "-t mangle -A %s %s %s %s %s %s %s %s %s %s -j DSCP --set-dscp 0x%x",
								QOS_IP_CHAIN, phyPort, wanPort, proto2, saddr, sport, daddr, dport, dscp, strmark, (entry.m_dscp-1)>>2);
							//output chain
							if (!entry.phyPort && !saddr[0] && !strmark[0] && !dscp[0] && (daddr[0] || dport[0])) {
								DOCMDARGVS(iptables_cmd, DOWAIT, "-t mangle -A qos_rule_output %s %s %s %s %s -j DSCP --set-dscp 0x%x",
									wanPort, proto2, sport, daddr, dport, (entry.m_dscp-1)>>2);
							}
						}
					}
				} else {
					// Mason Yu. match IN interface error
					//if (phyPort[0]) {
						DOCMDARGVS(EBTABLES, DOWAIT, "-t %s -A %s %s %s %s %s %s %s %s %s %s %s %s -j ftos --set-ftos 0x%x", "broute",
							QOS_EB_CHAIN, phyPort, eth_proto, proto1, smac, dmac, saddr, sport, daddr, dport, dscp, strmark, (entry.m_dscp-1)&0xFF);

						if(proto2)/* TCP/UDP, bored, why not set twice, any other wise idea? */
						{
							DOCMDARGVS(EBTABLES, DOWAIT, "-t %s -A %s %s %s %s %s %s %s %s %s %s %s %s -j ftos --set-ftos 0x%x", "broute",
								QOS_EB_CHAIN, phyPort, eth_proto, proto2, smac, dmac, saddr, sport, daddr, dport, dscp, strmark, (entry.m_dscp-1)&0xFF);
						}
					#if 0
					} else {
						snprintf(phyPort1, 16, "-i eth0");
						DOCMDARGVS(EBTABLES, DOWAIT, "-t %s -A %s %s %s %s %s %s %s %s %s %s %s %s -j ftos --set-ftos 0x%x", "broute",
							QOS_EB_CHAIN, phyPort1, eth_proto, proto1, smac, dmac, saddr, sport, daddr, dport, dscp, strmark, (entry.m_dscp-1)&0xFF);

						if(proto2)
						{
							DOCMDARGVS(EBTABLES, DOWAIT, "-t %s -A %s %s %s %s %s %s %s %s %s %s %s %s -j ftos --set-ftos 0x%x", "broute",
								QOS_EB_CHAIN, phyPort1, eth_proto, proto2, smac, dmac, saddr, sport, daddr, dport, dscp, strmark, (entry.m_dscp-1)&0xFF);
						}

						snprintf(phyPort1, 16, "-i wlan0");
						DOCMDARGVS(EBTABLES, DOWAIT, "-t %s -A %s %s %s %s %s %s %s %s %s %s %s %s -j ftos --set-ftos 0x%x", "broute",
							QOS_EB_CHAIN, phyPort1, eth_proto, proto1, smac, dmac, saddr, sport, daddr, dport, dscp, strmark, (entry.m_dscp-1)&0xFF);

						if(proto2)
						{
							DOCMDARGVS(EBTABLES, DOWAIT, "-t %s -A %s %s %s %s %s %s %s %s %s %s %s %s -j ftos --set-ftos 0x%x", "broute",
								QOS_EB_CHAIN, phyPort1, eth_proto, proto2, smac, dmac, saddr, sport, daddr, dport, dscp, strmark, (entry.m_dscp-1)&0xFF);
						}
					}
					#endif
				}
#ifdef QOS_SUPPORT_RTP
			} else {
				if (!ebtable) {
					for (j=0; j<rtpRuleCnt; j++) {
						DOCMDARGVS(iptables_cmd, DOWAIT, "-t mangle -A %s %s %s %s %s %s %s %s %s %s -j DSCP --set-dscp 0x%x",
							QOS_RTP_CHAIN, phyPort, wanPort, proto1, saddr, sport, rtp_rule_entry[j].daddr, rtp_rule_entry[j].dport, dscp, strmark, (entry.m_dscp-1)>>2);
					}
				}
			}
#endif
		}

		vcEntryNum = mib_chain_total(MIB_ATM_VC_TBL);

#ifndef QOS_SETUP_IMQ
		if(PLY_PRIO==policy)//priority queue
		{
			//DOCMDARGVS(TC, DOWAIT, "filter add dev %s parent 1: prio %d protocol ip handle 0x%x/0x%x fw flowid 1:%d",
			//	ifname, entry.prior, mark, QOS_MARK_MASK, entry.prior);
			for(j=0; j<vcEntryNum; j++)
			{
				if(!mib_chain_get(MIB_ATM_VC_TBL, j, &vcEntry))
					continue;

				ifGetName(vcEntry.ifIndex, ifname, sizeof(ifname));
				DOCMDARGVS(TC, DOWAIT, "filter add dev %s parent 1: prio %d %s handle 0x%x/0x%x fw flowid 1:%d",
					ifname, entry.prior, tc_protocol, mark, QOS_MARK_MASK, entry.prior);
			}
		}
		else if(PLY_WRR==policy)//weighted round robin
		{
			for(j=0; j<vcEntryNum; j++)
			{
				if(!mib_chain_get(MIB_ATM_VC_TBL, j, &vcEntry))
					continue;

				ifGetName(vcEntry.ifIndex, ifname, sizeof(ifname));

				DOCMDARGVS(TC, DOWAIT, "filter add dev %s parent 1: prio 1 %s handle 0x%x/0x%x fw flowid 1:%d00",
					ifname, tc_protocol, mark, QOS_MARK_MASK, entry.prior);
			}
		}
#else
		if(PLY_PRIO==policy)//priority queue
		{
			// Mason Yu. Use device name not imq0
			//DOCMDARGVS(TC, DOWAIT, "filter add dev imq0 parent 1: prio %d %s handle 0x%x/0x%x fw flowid 1:%d",
			for(j=0; j<vcEntryNum; j++)
			{
				if(!mib_chain_get(MIB_ATM_VC_TBL, j, &vcEntry))
					continue;

				ifGetName(vcEntry.ifIndex, ifname, sizeof(ifname));
				DOCMDARGVS(TC, DOWAIT, "filter add dev %s parent 1: prio %d %s handle 0x%x/0x%x fw flowid 1:%d",
					ifname, entry.prior, tc_protocol, mark, QOS_MARK_MASK, entry.prior);
			}
		}
		else if(PLY_WRR==policy)//weighted round robin
		{
			DOCMDARGVS(TC, DOWAIT, "filter add dev imq0 parent 1: prio 1 %s handle 0x%x/0x%x fw flowid 1:%d00",
				tc_protocol, mark, QOS_MARK_MASK, entry.prior);

			// Mason Yu.
			// If the vc is bridge mode , set tc action mirred and redirect to img0
			if (ebtable) {
				for(j=0; j<vcEntryNum; j++)
				{
					if(!mib_chain_get(MIB_ATM_VC_TBL, j, &vcEntry))
						continue;

					ifGetName(vcEntry.ifIndex, ifname, sizeof(ifname));
					DOCMDARGVS(TC, DOWAIT, "filter add dev %s parent 1: prio 1 %s handle 0x%x/0x%x fw flowid 1:1 action mirred egress redirect dev imq0",
						ifname, tc_protocol, mark, QOS_MARK_MASK);
				}
			}
		}
#endif

#ifndef CONFIG_RTK_L34_ENABLE
		//if ( (wan_qos_state&QOS_WAN_BRIDGE) != QOS_WAN_BRIDGE) {
			// hwnat qos
			hwnat_qos_translate_rule(&entry);
		//}
#else
		RTK_RG_QoS_Rule_Set(&entry);
#endif
	}

    return 0;
}
#endif
static int setupQosRuleChain(unsigned int enable)
{
	QOS_SETUP_PRINT_FUNCTION;

	if (enable)
	{
		va_cmd(EBTABLES, 4, 1, "-t", "broute", "-N", QOS_EB_CHAIN);
		va_cmd(EBTABLES, 5, 1, "-t", "broute", "-P", QOS_EB_CHAIN, "RETURN");
		va_cmd(EBTABLES, 6, 1, "-t", "broute", "-A", "BROUTING", "-j", QOS_EB_CHAIN);

		va_cmd(IPTABLES, 4, 1, "-t", "mangle", "-N", QOS_IP_CHAIN);
		va_cmd(IPTABLES, 6, 1, "-t", "mangle", "-A", "FORWARD", "-j", QOS_IP_CHAIN);

		//for rtp qos
		va_cmd(IPTABLES, 4, 1, "-t", "mangle", "-N", QOS_RTP_CHAIN);
		va_cmd(IPTABLES, 6, 1, "-t", "mangle", "-A", "FORWARD", "-j", QOS_RTP_CHAIN);

		va_cmd(IPTABLES, 4, 1, "-t", "mangle", "-N", "pvc_mark");
		va_cmd(IPTABLES, 6, 1, "-t", "mangle", "-A", "FORWARD", "-j", "pvc_mark");

		va_cmd(IPTABLES, 4, 1, "-t", "mangle", "-N", "qos_rule_output");
		va_cmd(IPTABLES, 6, 1, "-t", "mangle", "-A", "OUTPUT", "-j", "qos_rule_output");

		va_cmd(IPTABLES, 4, 1, "-t", "mangle", "-N", "pvc_mark_output");
		va_cmd(IPTABLES, 6, 1, "-t", "mangle", "-A", "OUTPUT", "-j", "pvc_mark_output");

#ifdef CONFIG_IPV6
		va_cmd(IP6TABLES, 4, 1, "-t", "mangle", "-N", QOS_IP_CHAIN);
		va_cmd(IP6TABLES, 6, 1, "-t", "mangle", "-A", "FORWARD", "-j", QOS_IP_CHAIN);

		//for rtp qos
		va_cmd(IP6TABLES, 4, 1, "-t", "mangle", "-N", QOS_RTP_CHAIN);
		va_cmd(IP6TABLES, 6, 1, "-t", "mangle", "-A", "FORWARD", "-j", QOS_RTP_CHAIN);

		va_cmd(IP6TABLES, 4, 1, "-t", "mangle", "-N", "pvc_mark");
		va_cmd(IP6TABLES, 6, 1, "-t", "mangle", "-A", "FORWARD", "-j", "pvc_mark");

		va_cmd(IP6TABLES, 4, 1, "-t", "mangle", "-N", "qos_rule_output");
		va_cmd(IP6TABLES, 6, 1, "-t", "mangle", "-A", "OUTPUT", "-j", "qos_rule_output");

		va_cmd(IP6TABLES, 4, 1, "-t", "mangle", "-N", "pvc_mark_output");
		va_cmd(IP6TABLES, 6, 1, "-t", "mangle", "-A", "OUTPUT", "-j", "pvc_mark_output");
#endif
	} else {
		va_cmd(EBTABLES, 4, 1, "-t", "broute", "-F", QOS_EB_CHAIN);
		va_cmd(EBTABLES, 6, 1, "-t", "broute", "-D", "BROUTING", "-j", QOS_EB_CHAIN);
		va_cmd(EBTABLES, 4, 1, "-t", "broute", "-X", QOS_EB_CHAIN);

		va_cmd(IPTABLES, 4, 1, "-t", "mangle", "-F", "pvc_mark");
		va_cmd(IPTABLES, 4, 1, "-t", "mangle", "-F", QOS_IP_CHAIN);
		va_cmd(IPTABLES, 4, 1, "-t", "mangle", "-F", QOS_RTP_CHAIN);	//for rtp qos
		va_cmd(IPTABLES, 4, 1, "-t", "mangle", "-F", "pvc_mark_output");
		va_cmd(IPTABLES, 4, 1, "-t", "mangle", "-F", "qos_rule_output");

		va_cmd(IPTABLES, 6, 1, "-t", "mangle", "-D", "FORWARD", "-j", "pvc_mark");
		va_cmd(IPTABLES, 6, 1, "-t", "mangle", "-D", "FORWARD", "-j", QOS_IP_CHAIN);
		va_cmd(IPTABLES, 6, 1, "-t", "mangle", "-D", "FORWARD", "-j", QOS_RTP_CHAIN);
		va_cmd(IPTABLES, 6, 1, "-t", "mangle", "-D", "OUTPUT", "-j", "pvc_mark_output");
		va_cmd(IPTABLES, 6, 1, "-t", "mangle", "-D", "OUTPUT", "-j", "qos_rule_output");

		va_cmd(IPTABLES, 4, 1, "-t", "mangle", "-X", "pvc_mark");
		va_cmd(IPTABLES, 4, 1, "-t", "mangle", "-X", QOS_IP_CHAIN);
		va_cmd(IPTABLES, 4, 1, "-t", "mangle", "-X", QOS_RTP_CHAIN);
		va_cmd(IPTABLES, 4, 1, "-t", "mangle", "-X", "pvc_mark_output");
		va_cmd(IPTABLES, 4, 1, "-t", "mangle", "-X", "qos_rule_output");

#ifdef CONFIG_IPV6
		va_cmd(IP6TABLES, 4, 1, "-t", "mangle", "-F", "pvc_mark");
		va_cmd(IP6TABLES, 4, 1, "-t", "mangle", "-F", QOS_IP_CHAIN);
		va_cmd(IP6TABLES, 4, 1, "-t", "mangle", "-F", QOS_RTP_CHAIN);	//for rtp qos
		va_cmd(IP6TABLES, 4, 1, "-t", "mangle", "-F", "pvc_mark_output");
		va_cmd(IP6TABLES, 4, 1, "-t", "mangle", "-F", "qos_rule_output");

		va_cmd(IP6TABLES, 6, 1, "-t", "mangle", "-D", "FORWARD", "-j", "pvc_mark");
		va_cmd(IP6TABLES, 6, 1, "-t", "mangle", "-D", "FORWARD", "-j", QOS_IP_CHAIN);
		va_cmd(IP6TABLES, 6, 1, "-t", "mangle", "-D", "FORWARD", "-j", QOS_RTP_CHAIN);
		va_cmd(IP6TABLES, 6, 1, "-t", "mangle", "-D", "OUTPUT", "-j", "pvc_mark_output");
		va_cmd(IP6TABLES, 6, 1, "-t", "mangle", "-D", "OUTPUT", "-j", "qos_rule_output");

		va_cmd(IP6TABLES, 4, 1, "-t", "mangle", "-X", "pvc_mark");
		va_cmd(IP6TABLES, 4, 1, "-t", "mangle", "-X", QOS_IP_CHAIN);
		va_cmd(IP6TABLES, 4, 1, "-t", "mangle", "-X", QOS_RTP_CHAIN);
		va_cmd(IP6TABLES, 4, 1, "-t", "mangle", "-X", "pvc_mark_output");
		va_cmd(IP6TABLES, 4, 1, "-t", "mangle", "-X", "qos_rule_output");
#endif
	}

	return 1;
}

static int setup_prio_queue(int enable)
{
	// Mason Yu. Use device name not imq0
	//char *devname="imq0";
	char devname[IFNAMSIZ];
	MIB_CE_ATM_VC_T vcEntry;
	int i, vcEntryNum;

	char tc_cmd[100];

	QOS_SETUP_PRINT_FUNCTION;

	// Mason Yu. Use device name not imq0. Start
	vcEntryNum = mib_chain_total(MIB_ATM_VC_TBL);
	for(i=0;i<vcEntryNum; i++)
	{
		if(!mib_chain_get(MIB_ATM_VC_TBL, i, (void*)&vcEntry)||!vcEntry.enableIpQos)
			continue;

		ifGetName(vcEntry.ifIndex, devname, sizeof(devname));

		if (!enable) {
			va_cmd(TC, 5, 1, "qdisc", (char *)ARG_DEL, "dev", devname, "root");
			continue;
		}
		// Mason Yu. Use device name not imq0. END

		snprintf(tc_cmd, 100, "tc qdisc add dev %s root handle 1: prio bands 4 priomap %s", devname, "3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3");
		TRACE(STA_SCRIPT,"%s\n",tc_cmd);
		system(tc_cmd);
		va_cmd(TC, 11, 1, "qdisc", (char *)ARG_ADD, "dev", devname,
			"parent", "1:1", "handle", "2:", "pfifo", "limit", "10");
		va_cmd(TC, 11, 1, "qdisc", (char *)ARG_ADD, "dev", devname,
			"parent", "1:2", "handle", "3:", "pfifo", "limit", "10");
		va_cmd(TC, 11, 1, "qdisc", (char *)ARG_ADD, "dev", devname,
			"parent", "1:3", "handle", "4:", "pfifo", "limit", "10");
		va_cmd(TC, 11, 1, "qdisc", (char *)ARG_ADD, "dev", devname,
			"parent", "1:4", "handle", "5:", "pfifo", "limit", "10");
	}

	// Mason Yu. Use device name not imq0
	if (!enable) {
			// disable IPQoS
			__dev_setupIPQoS(0);
	}
	else {
		// enable IPQoS
		__dev_setupIPQoS(1);
	}
	return 0;
}

/*
 *	action:
 *	0: Add
 *	1: Change
 */
static int setup_htb_class(int action, unsigned int upRate)
{
	char *devname="imq0";
	char s_rate[16], s_ceil[16], s_classid[16], s_quantum[16];
	const char *pAction;
	int j;
	int rate, ceil, quantum;
	unsigned char enableForceWeight=0;
	MIB_CE_IP_QOS_QUEUE_T qEntry;
	int qEntryNum, minWeigh;

	if (action == 0)
		pAction = ARG_ADD;
	else
		pAction = ARG_CHANGE;
	snprintf(s_rate, 16, "%dKbit", upRate);
	snprintf(s_ceil, 16, "%dKbit", upRate);
	//tc class add dev $DEV parent 1: classid 1:1 htb rate $RATE ceil $CEIL
	va_cmd(TC, 13, 1, "class", pAction, "dev", devname,
		"parent", "1:", "classid", "1:1", "htb", "rate", s_rate, "ceil", s_ceil);

#if defined(CONFIG_USER_IP_QOS) && defined(_PRMT_X_CT_COM_QOS_)
	mib_get(MIB_QOS_ENABLE_FORCE_WEIGHT, (void *)&enableForceWeight);
#endif

	if((qEntryNum=mib_chain_total(MIB_IP_QOS_QUEUE_TBL)) <=0)
		return 0;
	for(j=0;j<qEntryNum; j++)
	{
		if(!mib_chain_get(MIB_IP_QOS_QUEUE_TBL, j, (void*)&qEntry))
			continue;
		if ( !qEntry.enable)
			continue;

		snprintf(s_classid, 16, "1:%d00", j+1);
		minWeigh = findQueueMinWeigh();
		// Quantum should be bigger then MTU (1500) so you can send the maximum packet in 1 turn and smaller then 60000
		quantum = (1500*qEntry.weight)/minWeigh;
		if (quantum > 60000)
			quantum = 60000;
		snprintf(s_quantum, 16, "%d", quantum);
		//printf("s_quantum=%s\n", s_quantum);
		rate = qEntry.weight;
		//if enableForceWeight, then send rate should not larger than wrr proportion
		ceil = enableForceWeight?(upRate*qEntry.weight/100):upRate;
		snprintf(s_ceil, 16, "%dKbit", ceil);
		if (rate > ceil)
		{
			if (enableForceWeight) rate = ceil;
			else rate = ceil*qEntry.weight/100;
		}
		snprintf(s_rate, 16, "%dKbit", rate);

		//tc class add dev $DEV parent 10:1 classid 10:$SUBID htb rate $RATE ceil $RATE prio $PRIO
		va_cmd(TC, 15, 1, "class", pAction, "dev", devname,
			"parent", "1:1", "classid", s_classid, "htb", "rate",
			s_rate, "ceil", s_ceil, "quantum", s_quantum);
	}

}

static int setup_wrr_queue(int enable)
{
	int j;
	char *devname="imq0";
	char s_rate[16], s_ceil[16], s_classid[16], s_quantum[16];
	unsigned int total_bandwidth = 0;

	MIB_CE_ATM_VC_T vcEntry;
	int i, vcEntryNum;
	char tc_cmd[100];
	char devname2[IFNAMSIZ];

	QOS_SETUP_PRINT_FUNCTION;

	if (!enable) {
		va_cmd(TC, 5, 1, "qdisc", (char *)ARG_DEL, "dev", devname, "root");
		//return 0;
		goto SETVCQDISC;
	}

	if (!ifSumWeighIs100())
		return 0;

	total_bandwidth = getUpLinkRate();
	current_uprate = total_bandwidth;

	snprintf(s_rate, 16, "%dKbit", total_bandwidth);
	snprintf(s_ceil, 16, "%dKbit", total_bandwidth);
	//tc qdisc add dev $DEV root handle 1: htb default 400
	va_cmd(TC, 10, 1, "qdisc", (char *)ARG_ADD, "dev", devname,
		"root", "handle", "1:", "htb", "default", "400");

	setup_htb_class(0, total_bandwidth);
	//set queue len
	set_wrr_class_qdisc();

SETVCQDISC:
	// Mason Yu.
	// If the vc is bridge mode , set root qdisc for tc action mirred
	vcEntryNum = mib_chain_total(MIB_ATM_VC_TBL);
	for(i=0;i<vcEntryNum; i++)
	{
		if(!mib_chain_get(MIB_ATM_VC_TBL, i, (void*)&vcEntry)||!vcEntry.enableIpQos)
			continue;

		if (vcEntry.cmode != CHANNEL_MODE_BRIDGE)
			continue;

		ifGetName(vcEntry.ifIndex, devname2, sizeof(devname2));

		if (!enable) {
			va_cmd(TC, 5, 1, "qdisc", (char *)ARG_DEL, "dev", devname2, "root");
			continue;
		}

		snprintf(tc_cmd, 100, "tc qdisc add dev %s root handle 1: prio bands 4 priomap %s", devname2, "3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3");
		TRACE(STA_SCRIPT,"%s\n",tc_cmd);
		system(tc_cmd);
	}
	return 0;
}

static int setupQdisc(int enable)
{
	unsigned char policy;

	QOS_SETUP_PRINT_FUNCTION;
	mib_get(MIB_QOS_POLICY, (void*)&policy);

	if (policy == PLY_PRIO)
		setup_prio_queue(enable);
	else
		setup_wrr_queue(enable);
	return 0;
}

static void clear_ip_qos_app_rules()
{
	MIB_CE_IP_QOS_T entry;
	int total = mib_chain_total(MIB_IP_QOS_TBL);
	int i = total - 1;

	for(; i >= 0 ; i--)
	{
		if(!mib_chain_get(MIB_IP_QOS_TBL, i, (void*)&entry))
			continue;

		if(entry.modeTr69 == MODETR069 || entry.modeTr69 == MODEVOIP)
			mib_chain_delete(MIB_IP_QOS_TBL, i);
	}
}

static int setup_ip_qos_app_rules()
{
	MIB_CE_IP_QOS_APP_T entry;
	MIB_CE_IP_QOS_T qos_entry;
	MIB_CE_IP_QOS_Tp p = &qos_entry;
	int i, j, total = 0, vcEntryNum = 0;

	clear_ip_qos_app_rules();

	total = mib_chain_total(MIB_IP_QOS_APP_TBL);
	for(i=0; i<total; i++)
	{
		if(!mib_chain_get(MIB_IP_QOS_APP_TBL, i, (void*)&entry))
			continue;

		if(entry.appName == IP_QOS_APP_VOIP && entry.prior)
		{
			memset(p, 0, sizeof(MIB_CE_IP_QOS_T));
			strcpy(p->RuleName, "rule_VOIP_1");
			p->enable = 1;
#ifdef CONFIG_IPV6
			p->IpProtocol = IPVER_IPV4;	/* IPv4 */
#endif
			// local source port: 5060
			// protocol is UDP
			p->sPort = 5060;
			p->sPortRangeMax=5060;
			p->protoType = PROTO_UDP;
			p->prior = entry.prior;
			p->cttypemap[0] = 5; //SPORT
			p->modeTr69 = MODEVOIP; //hide from web gui and TR-069
			p->InstanceNum = 0;
			mib_chain_add(MIB_IP_QOS_TBL, p);
	
			memset(p, 0, sizeof(MIB_CE_IP_QOS_T));
			strcpy(p->RuleName, "rule_VOIP_2");
			p->enable = 1;
#ifdef CONFIG_IPV6
			p->IpProtocol = IPVER_IPV4; /* IPv4 */
#endif
			// local source port: 9000 ~ 9010 ( rtp + t.38),
			p->sPort = 9000;
			p->sPortRangeMax=9010;
			p->prior = entry.prior;
			p->cttypemap[0] = 5; //SPORT
			p->modeTr69 = MODEVOIP; //hide from web gui and TR-069
			p->InstanceNum = 0;
			mib_chain_add(MIB_IP_QOS_TBL, p);
		}
		else if(entry.appName == IP_QOS_APP_TR069 && entry.prior)
		{
			char acsurl[256+1]={0}, vStr[256+1]={0};
			struct addrinfo *servinfo = NULL;
			char dst_ip[20]={0};
			
	
			memset(p, 0, sizeof(MIB_CE_IP_QOS_T));
			sprintf(p->RuleName, "%s", "rule_TR069");
			p->enable = 1;
#ifdef CONFIG_IPV6
			p->IpProtocol = IPVER_IPV4; /* IPv4 */
#endif
			p->prior = entry.prior;
			p->cttypemap[0] = 4; //DIP
			p->modeTr69 = MODETR069;	//hide from web gui and TR-069
			p->InstanceNum = 0;
	
			//get ACS URL, found the IP
#ifdef CONFIG_TR142_MODULE
			if(!mib_get(RS_CWMP_USED_ACS_URL, (void*)vStr))
#else
			if(!mib_get(CWMP_ACS_URL, (void*)vStr))
#endif
			{
				fprintf(stderr, "Get mib value RS_CWMP_USED_ACS_URL failed!\n");
			}
			else
			{
				if (vStr[0])
				{
					set_endpoint(acsurl, vStr);
					servinfo = hostname_to_ip(acsurl, IPVER_IPV4);

					if (!servinfo)
					{
						fprintf(stderr, "failed to get HOST address\n");
						return -1;
					}

				 	struct sockaddr_in *sin;
					sin = (struct sockaddr_in *)servinfo->ai_addr;
					memcpy(&p->dip, &(sin->sin_addr), sizeof(struct in_addr));

					mib_chain_add(MIB_IP_QOS_TBL, p);
					freeaddrinfo(servinfo);
				}
			}
		}
	}
}

static int setupQRule()
{
	unsigned char policy;

	QOS_SETUP_PRINT_FUNCTION;
	setup_ip_qos_app_rules();
	mib_get(MIB_QOS_POLICY, (void*)&policy);
	setup_qos_rules(policy);
	return 0;
}

int enableIMQ(int enable)
{
	MIB_CE_ATM_VC_T vcEntry;
	int i, entryNum;
	char ifname[IFNAMSIZ];

	QOS_SETUP_PRINT_FUNCTION;

	if (!enable) {
		va_cmd(IPTABLES, 4, 1, "-t", "mangle", "-F", "IMQ_CHAIN");
		va_cmd(IPTABLES, 6, 1, "-t", "mangle", "-D", "POSTROUTING", "-j", "IMQ_CHAIN");
		va_cmd(IPTABLES, 4, 1, "-t", "mangle", "-X", "IMQ_CHAIN");
#ifdef CONFIG_IPV6
		va_cmd(IP6TABLES, 4, 1, "-t", "mangle", "-F", "IMQ_CHAIN");
		va_cmd(IP6TABLES, 6, 1, "-t", "mangle", "-D", "POSTROUTING", "-j", "IMQ_CHAIN");
		va_cmd(IP6TABLES, 4, 1, "-t", "mangle", "-X", "IMQ_CHAIN");
#endif
		va_cmd(IFCONFIG, 2, 1, "imq0", "down");
		return 0;
	}

	va_cmd(IFCONFIG, 3, 1, "imq0", "txqueuelen", "100");
	va_cmd(IFCONFIG, 2, 1, "imq0", "up");

	va_cmd(IPTABLES, 4, 1, "-t", "mangle", "-N", "IMQ_CHAIN");
	va_cmd(IPTABLES, 6, 1, "-t", "mangle", "-A", "POSTROUTING", "-j", "IMQ_CHAIN");
#ifdef CONFIG_IPV6
	va_cmd(IP6TABLES, 4, 1, "-t", "mangle", "-N", "IMQ_CHAIN");
	va_cmd(IP6TABLES, 6, 1, "-t", "mangle", "-A", "POSTROUTING", "-j", "IMQ_CHAIN");
#endif

	entryNum = mib_chain_total(MIB_ATM_VC_TBL);

	for(i=0; i<entryNum; i++)
	{
		if(!mib_chain_get(MIB_ATM_VC_TBL, i, (void*)&vcEntry))
			continue;

		if (vcEntry.cmode == CHANNEL_MODE_BRIDGE)
			continue;

		ifGetName(vcEntry.ifIndex, ifname, sizeof(ifname));
		va_cmd(IPTABLES, 10, 1, "-t", "mangle", "-A", "IMQ_CHAIN",
			"-o", ifname, "-j", "IMQ", "--todev", "0");
#ifdef CONFIG_IPV6
		va_cmd(IP6TABLES, 10, 1, "-t", "mangle", "-A", "IMQ_CHAIN",
			"-o", ifname, "-j", "IMQ", "--todev", "0");
#endif
	}

	return 0;
}

/*
 * Make sure we have 4 QoS Queues.
 */
static void checkQosQueue()
{
	MIB_CE_IP_QOS_QUEUE_T qEntry;
	int i;
	
	if(mib_chain_total(MIB_IP_QOS_QUEUE_TBL) >= 4)
		return;
	
	// Flush table
	mib_chain_clear(MIB_IP_QOS_QUEUE_TBL);

	// Add MAX_QOS_QUEUE_NUM of default Qos Queues
	for (i=0; i<4; i++) {
		qEntry.enable = 0;
		qEntry.weight = 10*(4-i);
		qEntry.QueueInstNum = i+1;
		mib_chain_add(MIB_IP_QOS_QUEUE_TBL, &qEntry);
	}
	mib_update(CURRENT_SETTING, CONFIG_MIB_ALL);
}


int setupIPQ(void)
{
	unsigned int qosEnable;
	unsigned int qosRuleNum;
	unsigned char do_traffic_shapping;
	unsigned char totalBandWidthEn;

	QOS_SETUP_PRINT_FUNCTION;
	checkQosQueue();
	UpdateIpFastpathStatus(); // need to disable upstream IPQoS for IPQoS

#ifdef CONFIG_YUEME
	// Update QoS rules by CTQOS_MODE
	char qos_mode[MAX_NAME_LEN]={0};
	if(mib_get(CTQOS_MODE, qos_mode))
		updateMIBforQosMode(qos_mode);
#endif

	qosEnable = getQosEnable();
	qosRuleNum = getQosRuleNum();
	mib_get(MIB_TOTAL_BANDWIDTH_LIMIT_EN, (void *)&totalBandWidthEn);

#ifdef _PRMT_X_CT_COM_DATA_SPEED_LIMIT_
	do_traffic_shapping = 1;
#else
	do_traffic_shapping = (unsigned char)mib_chain_total(MIB_IP_QOS_TC_TBL);
#endif
	//printf("[%s %d]qosEnable=%d, totalBandWidthEn=%d, qosRuleNum=%d, do_traffic_shapping=%d\n", __func__, __LINE__, qosEnable, totalBandWidthEn, qosRuleNum, do_traffic_shapping);

#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	unsigned char up_mode;
	//UP
	mib_get(MIB_DATA_SPEED_LIMIT_UP_MODE, &up_mode);
	if(up_mode== DATA_SPEED_LIMIT_MODE_DISABLE){
#endif	
		if (qosEnable && qosRuleNum) { // ip qos
			setupQosRuleChain(1);
#ifdef CONFIG_TR142_MODULE
			RTK_RG_QoS_Queue_Set();
#endif
			setupQdisc(1);
			setupQRule();
			enableIMQ(1);
		}
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)	
	}
#endif	

#ifdef CONFIG_RTK_L34_ENABLE  //Apollo HW have rate limit and QoS marking/rules co-exist capability.
	if (totalBandWidthEn || do_traffic_shapping) { // traffic shapping
#else
	else if (totalBandWidthEn || do_traffic_shapping) { // traffic shapping
#endif
		setupCarChain(1);
		setupCarQdisc(1);
#ifdef _PRMT_X_CT_COM_DATA_SPEED_LIMIT_
		setup_data_speed_limit();
#else
		setupCarRule();
#endif
	}

#ifdef CONFIG_RTK_L34_ENABLE
	if (totalBandWidthEn){
		unsigned int bandwidth = getUpLinkRate();

		printf("Config RG QoS total bandwidth %d Kbps\n",bandwidth);
		RTK_RG_QoS_TotalBandwidth_Set(bandwidth);
	}
#endif

	//setupUserIPQoSRule(1);
}

int stopIPQ(void)
{
	setupQosRuleChain(0);
	setupQdisc(0);
	enableIMQ(0);

	setupCarChain(0);
	setupCarQdisc(0);


#ifdef CONFIG_RTK_L34_ENABLE
	FlushRTK_RG_QoS_Rules();
	RTK_RG_QoS_Queue_Remove();
	clean_special_handle_RTP();
	printf("Reset RG QoS total bandwidth to unlimit.\n");
	RTK_RG_QoS_TotalBandwidth_Set(0);
#endif
	return 0;
}

/* this func is only for speedtest */
int restore_hw_queue(void)
{
        unsigned int qosEnable;
        unsigned int qosRuleNum;

        qosEnable = getQosEnable();
        qosRuleNum = getQosRuleNum();

        if (qosEnable && qosRuleNum)
        { // ip qos
		#ifdef CONFIG_TR142_MODULE
                RTK_RG_QoS_Queue_Set();
		#endif
        }

        return 0;
}

void take_qos_effect_v3(void)
{
	stopIPQ();
	setupIPQ();
}


#ifdef _PRMT_X_CT_COM_QOS_
#define ETH_ALEN	6		/* Octets in one ethernet addr	 */
const char *ct_typename[CT_TYPE_NUM + 1] = {
	"", "SMAC", "8021P", "SIP", "DIP", "SPORT", "DPORT", "TOS", "DSCP",
	    "WANInterface", "LANInterface",
};

const char *LANString[4] = {
	"InternetGatewayDevice.LANDevice.1.LANEthernetInterfaceConfig.1",	//eth0_sw0
	"InternetGatewayDevice.LANDevice.1.LANEthernetInterfaceConfig.2",	//eth0_sw1
	"InternetGatewayDevice.LANDevice.1.LANEthernetInterfaceConfig.3",	//eth0_sw2
	"InternetGatewayDevice.LANDevice.1.LANEthernetInterfaceConfig.4",	//eth0_sw3
};

static int findcttype(MIB_CE_IP_QOS_T *p, unsigned char typenum)
{
	int i;

	for (i = 0; i < CT_TYPE_NUM; i++) {
		if (p->cttypemap[i] == typenum)
			return i;
	}

	return -1;
}

static int gettypeinst(MIB_CE_IP_QOS_T *p)
{
	int i;

	for (i = 0; i < CT_TYPE_NUM; i++) {
		if (p->cttypemap[i] == 0 || p->cttypemap[i] == 0xf)
			return i;
	}

	return 0;
}

static unsigned int getIPTVIndex()
{
	MIB_CE_ATM_VC_T entry;
	int i, total;

	total = mib_chain_total(MIB_ATM_VC_TBL);
	for (i = 0; i < total; i++) {
		if (!mib_chain_get(MIB_ATM_VC_TBL, i, &entry))
			continue;
		if ((entry.applicationtype == X_CT_SRV_OTHER || entry.applicationtype == X_CT_SRV_INTERNET) && entry.cmode == CHANNEL_MODE_BRIDGE && entry.enable == 1)	//OTHER or INTERNET
			return entry.ifIndex;
	}

	return DUMMY_IFINDEX;
}


int updatecttypevalue(MIB_CE_IP_QOS_T *p)
{
	unsigned char i;
	unsigned char typenum = 0;
	struct in_addr addr;
	int intvalue;
	int typeinst;
	int tmpinst;

	if (p->modeTr69 != MODEIPTV && p->modeTr69 != MODEOTHER)
		return -1;

	for (i = 1; i <= CT_TYPE_NUM; i++) {
		tmpinst = findcttype(p, i);
		switch (i) {
		case 1:	//SMAC
			break;
		case 2:	//8021P
			if (p->vlan1p > 0) {
				if (tmpinst < 0) {	//web add this type
					typeinst = gettypeinst(p);
					p->cttypemap[typeinst] = i;
				}
			} else {
				if (tmpinst >= 0)	//web del this type
					p->cttypemap[tmpinst] = 0;
			}
			break;
		case 3:	//SIP
			if (p->sip[0] != 0) {
				if (tmpinst < 0) {	//web add this type
					typeinst = gettypeinst(p);
					p->cttypemap[typeinst] = i;
				}
			} else {
				if (tmpinst >= 0)	//web del this type
					p->cttypemap[tmpinst] = 0;
			}
			break;
		case 4:	//DIP
			if (p->dip[0] != 0) {
				if (tmpinst < 0) {	//web add this type
					typeinst = gettypeinst(p);
					p->cttypemap[typeinst] = i;
				}
			} else {
				if (tmpinst >= 0)	//web del this type
					p->cttypemap[tmpinst] = 0;
			}
			break;
		case 5:	//SPORT
			if (p->sPort != 0 || p->sPortRangeMax != 0) {
				if (tmpinst < 0) {	//web add this type
					typeinst = gettypeinst(p);
					p->cttypemap[typeinst] = i;
				}
			} else {
				if (tmpinst >= 0)	//web del this type
					p->cttypemap[tmpinst] = 0;
			}
			break;
		case 6:	//DPORT
			if (p->dPort != 0 || p->dPortRangeMax != 0) {
				if (tmpinst < 0) {	//web add this type
					typeinst = gettypeinst(p);
					p->cttypemap[typeinst] = i;
				}
			} else {
				if (tmpinst >= 0)	//web del this type
					p->cttypemap[tmpinst] = 0;
			}
			break;
		case 7:	//TOS
			if (p->tos != 0) {
				if (tmpinst < 0) {	//web add this type
					typeinst = gettypeinst(p);
					p->cttypemap[typeinst] = i;
				}
			} else {
				if (tmpinst >= 0)	//web del this type
					p->cttypemap[tmpinst] = 0;
			}
			break;
		case 8:	//DSCP
			if (p->qosDscp != 0) {
				if (tmpinst < 0) {	//web add this type
					typeinst = gettypeinst(p);
					p->cttypemap[typeinst] = i;
				}
			} else {
				if (tmpinst >= 0)	//web del this type
					p->cttypemap[tmpinst] = 0;
			}
			break;
		case 9:	//WANInterface
			break;
		case 10:	//LANInterface
			if (p->phyPort > 0 || p->minphyPort > 0) {
				if (tmpinst < 0) {	//web add this type
					typeinst = gettypeinst(p);
					p->cttypemap[typeinst] = i;
				}
			} else {
				if (tmpinst >= 0)	//web del this type
					p->cttypemap[tmpinst] = 0;
			}
			break;
		default:
			break;
		}
	}
	return 0;
}

static void calculate_ip(struct in_addr *ip, unsigned char mask, int maxflag, struct in_addr *result)
{
	struct in_addr mask_ip = {0};
	int i;

	for(i = 0 ; i < mask ;i++)
		mask_ip.s_addr |= (1 << (32-i));

	memcpy(result, ip, sizeof(struct in_addr));
	result->s_addr &= mask_ip.s_addr;

	if(maxflag)
	{
		mask_ip.s_addr = 0;
		for(i = 0 ; i < (32 - mask) ;i++)
			mask_ip.s_addr |= (1 << i);

		result->s_addr |= mask_ip.s_addr;
	}
}

int getcttypevalue(char *typevalue, MIB_CE_IP_QOS_T *p, int typeinst,
		   int maxflag)
{
	unsigned char typenum;

	typenum = p->cttypemap[typeinst];
	if (typenum <= 0 || typenum > CT_TYPE_NUM)
		return -1;

	switch (typenum) {
	case 1:		//SMAC
		mac_hex2string(p->smac, typevalue);
		return 0;
	case 2:		//8021P
		sprintf(typevalue, "%hhu", p->vlan1p - 1);
		return 0;
	case 3: 	//SIP
		{
			struct in_addr ip_result = {0};
			calculate_ip((struct in_addr *)p->sip, p->smaskbit, maxflag, &ip_result);
			//strcpy(typevalue, inet_ntoa(ip_result));
			//convertIPAddrToString(*((unsigned int*)(&ip_result)),typevalue);
			inet_ntop(AF_INET, &ip_result, typevalue, INET_ADDRSTRLEN);
			return 0;
		}
	case 4: 	//DIP
		{
			struct in_addr ip_result = {0};
			calculate_ip((struct in_addr *)p->dip, p->dmaskbit, maxflag, &ip_result);
			//strcpy(typevalue, inet_ntoa(ip_result));
			//convertIPAddrToString(*((unsigned int*)(&ip_result)),typevalue);
			inet_ntop(AF_INET, &ip_result, typevalue, INET_ADDRSTRLEN);
			return 0;
		}

	case 5:		//SPORT
		sprintf(typevalue, "%hu",
			maxflag ? p->sPortRangeMax : p->sPort);
		return 0;
	case 6:		//DPORT
		sprintf(typevalue, "%hu",
			maxflag ? p->dPortRangeMax : p->dPort);
		return 0;
	case 7:		//TOS
		sprintf(typevalue, "%hhu", p->tos);
		return 0;
	case 8:		//DSCP
		sprintf(typevalue, "%hhu", (p->qosDscp - 1) >> 2);
		return 0;
	case 9:		//WANInterface
		return 0;
	case 10:		//LANInterface
		if (maxflag == 1) {
			if (p->phyPort > 0 && p->phyPort < 5) {
				strcpy(typevalue, LANString[p->phyPort - 1]);
				return 0;
			} else
				return -1;
		} else {
			if (p->minphyPort > 0 && p->minphyPort < 5) {
				strcpy(typevalue, LANString[p->minphyPort - 1]);
				return 0;
			} else
				return -1;
		}
	default:
		return -1;
	}
}

int setcttypevalue(char *typevalue, MIB_CE_IP_QOS_T * p, int typeinst,
		   int maxflag)
{
	unsigned char typenum;
	int i;

	typenum = p->cttypemap[typeinst];
	if (typenum <= 0 || typenum > CT_TYPE_NUM)
		return -1;

	switch (typenum) {
	case 1:		//SMAC
		for(i = 0; i < ETH_ALEN; i++) {
			p->smac[i] = hex(typevalue[i * 3]) * 16 + hex(typevalue[i * 3 + 1]);
		}
		return 0;
	case 2:		//8021P
		sscanf(typevalue, "%hhu", &p->vlan1p);
		p->vlan1p = p->vlan1p + 1;
		return 0;
	case 3:		//SIP
		if (!inet_aton(typevalue, (struct in_addr *)p->sip))
			return -1;
		p->smaskbit = 32;
		return 0;
	case 4:		//DIP
		if (!inet_aton(typevalue, (struct in_addr *)p->dip))
			return -1;
		p->smaskbit = 32;
		return 0;
	case 5:		//SPORT
		sscanf(typevalue, "%hu", maxflag ? &p->sPortRangeMax : &p->sPort);
		return 0;
	case 6:		//DPORT
		sscanf(typevalue, "%hu", maxflag ? &p->dPortRangeMax : &p->dPort);
		return 0;
	case 7:		//TOS
		sscanf(typevalue, "%hhu", &p->tos);
		return 0;
	case 8:		//DSCP
		sscanf(typevalue, "%hhu", &p->qosDscp);
		p->qosDscp = p->qosDscp >> 2 + 1;
		return 0;
	case 9:		//WANInterface
		return 0;
	case 10:		//LANInterface
		for (i = 0; i < 4; i++) {
			if (strstr(typevalue, LANString[i]) != 0)
				break;
		}
		if (i <= 4) {
			if (maxflag == 1)
				p->phyPort = i + 1;
			else
				p->minphyPort = i + 1;
		} else
			return -1;
		return 0;
	default:
		return 0;
	}
}

int getcttype(char *typename, MIB_CE_IP_QOS_T *p, int typeinst)
{
	unsigned char typenum;

	typenum = p->cttypemap[typeinst];
	if (typenum <= 0 || typenum > CT_TYPE_NUM)
		return -1;

	strcpy(typename, ct_typename[typenum]);
	return 0;
}

int setcttype(char *typename, MIB_CE_IP_QOS_T *p, int typeinst)
{
	int i;

	for (i = 1; i <= CT_TYPE_NUM; i++) {
		if (!strcmp(typename, ct_typename[i])) {
			delcttypevalue(p, typeinst);
			p->cttypemap[typeinst] = i;

			return 0;
		}
	}

	return -1;
}

int delcttypevalue(MIB_CE_IP_QOS_T *p, int typeinst)
{
	unsigned char typenum;

	typenum = p->cttypemap[typeinst];
	if (typenum <= 0 || (typenum > CT_TYPE_NUM && typenum != 0xf))
		return -1;
	p->cttypemap[typeinst] = 0;

	switch (typenum) {
	case 1:		//SMAC
		memset(p->smac, 0, sizeof(p->smac));
		return 0;
	case 2:		//8021P
		p->vlan1p = 0;
		return 0;
	case 3:		//SIP
		memset(p->sip, 0, sizeof(p->sip));
		return 0;
	case 4:		//DIP
		memset(p->dip, 0, sizeof(p->dip));
		return 0;
	case 5:		//SPORT
		p->sPort = 0;
		p->sPortRangeMax = 0;
		return 0;
	case 6:		//DPORT
		p->dPort = 0;
		p->dPortRangeMax = 0;
		return 0;
	case 7:		//TOS
		p->tos = 0;
		return 0;
	case 8:		//DSCP
		p->qosDscp = 0;
		return 0;
	case 9:		//WANInterface
		return 0;
	case 10:		//LANInterface
		p->phyPort = 0;
		p->minphyPort = 0;
		return 0;
	default:
		return 0;
	}
}

enum {
	QOS_PRIO_INTERNET = 0,
	QOS_PRIO_TR069,
	QOS_PRIO_VOIP,
	QOS_PRIO_IPTV,
};

static int qos_mode_prio[4]={0};

static int parsePriorityByQosMode(unsigned char *qosMode)
{
	char *delim=",";
	char *token,*saveptr1,*str1;
	int prio=0,total_queue_need=0;
	char buf[60]={0};

	if ( !qosMode || qosMode[0]=='\0' )
		return 0;

	strcpy(buf,qosMode);
	for (prio = 1,str1 = buf ; prio<=sizeof(qos_mode_prio) ; prio++,str1 = NULL){
		token = strtok_r(str1,delim,&saveptr1);
		if(token){
			printf("%s: %d\n",token, prio);
			total_queue_need++;

			if(strcasecmp("INTERNET",token)==0)
				qos_mode_prio[QOS_PRIO_INTERNET]=prio;
			else if(strcasecmp("TR069",token)==0)
				qos_mode_prio[QOS_PRIO_TR069]=prio;
			else if(strcasecmp("VOIP",token)==0)
				qos_mode_prio[QOS_PRIO_VOIP]=prio;
			else if(strcasecmp("IPTV",token)==0)
				qos_mode_prio[QOS_PRIO_IPTV]=prio;
		}
		else
			break;
	}

	return total_queue_need;
}

static unsigned int getIfIndex_byConnectionType(int type)
{
	unsigned int entryNum, i;
	char ifname[IFNAMSIZ];
	MIB_CE_ATM_VC_T Entry, *pEntry = &Entry;

	printf("Finding WAN inferface for type %d\n",type);
	entryNum = mib_chain_total(MIB_ATM_VC_TBL);
	for (i=0; i<entryNum; i++) {
		if (!mib_chain_get(MIB_ATM_VC_TBL, i, (void *)pEntry))
		{
  			printf("Get chain record error!\n");
			return -1;
		}

		if (pEntry->enable == 0)
			continue;

		if(pEntry->applicationtype & type){
			printf("Found WAN inferface %d\n",pEntry->ifIndex);
			return pEntry->ifIndex;
		}
	}

	printf("Error!!!! Not Found WAN inferface for type %d\n",type);
	return 0xffffffff;
}

static unsigned int find_max_CT_Class_instanNum()
{
	int total = mib_chain_total(MIB_IP_QOS_TBL);
	int i = 0, max = 0;
	MIB_CE_IP_QOS_T qos_entity;

	for(i = 0 ; i < total ; i++)
	{
		if(!mib_chain_get(MIB_IP_QOS_TBL, i, &qos_entity))
			continue;

		if (qos_entity.modeTr69 == MODEINTERNET)
			continue;

		if(qos_entity.InstanceNum > max)
			max = qos_entity.InstanceNum;
	}

	return max;
}

int delQoSRuleByMode(unsigned char *sub_qosMode)
{
	MIB_CE_IP_QOS_T Entry, *pEntry=&Entry;
	int  i,entryNum;

	printf("%s for mode %s\n",__func__,sub_qosMode);
	if ( !sub_qosMode || sub_qosMode[0]=='\0' )
		return -1;

	if((entryNum=mib_chain_total(MIB_IP_QOS_TBL)) <=0)
		return -1;

	for (i = entryNum - 1; i >= 0; i--) {
		if (!mib_chain_get(MIB_IP_QOS_TBL, i, (void *)pEntry)) {
			printf("Get chain record error!\n");
			return -1;
		}

		if (strcasestr(pEntry->RuleName, sub_qosMode)) {
			printf("delete entry %s\n", pEntry->RuleName);
			mib_chain_delete(MIB_IP_QOS_TBL, i);
		}
	}

	return 0;
}

#if CONFIG_YUEME
int updateMIBforQosMode(unsigned char *qosMode)
{
	MIB_CE_IP_QOS_T qos_entity[4], *p=NULL;
	int need_queue_num;
	MIB_CE_IP_QOS_QUEUE_T qEntry;
	int qEntryNum, i;
	unsigned char vUChar;
	unsigned int vUInt;

	if ( !qosMode || qosMode[0]=='\0' )
		return -1;

	printf("%s: qosMode=%s\n",__func__,qosMode);
	memset(qos_mode_prio,0,sizeof(qos_mode_prio));

	//Now parsing the priority by qosMode
	need_queue_num = parsePriorityByQosMode(qosMode);
	printf("total need %d QoS queues %d\n",need_queue_num);

	update_appbased_qos_tbl();
}

int setMIBforQosMode(unsigned char *qosMode)
{
	MIB_CE_IP_QOS_T qos_entity[4], *p=NULL;
	int need_queue_num;
	MIB_CE_IP_QOS_QUEUE_T qEntry;
	int qEntryNum, i;
	unsigned char vUChar;
	unsigned int vUInt;

	if ( !qosMode || qosMode[0]=='\0' )
		return -1;

	printf("%s: qosMode=%s\n",__func__,qosMode);
	memset(qos_mode_prio,0,sizeof(qos_mode_prio));

	/* InternetGatewayDevice.X_CT-COM_UplinkQoS.Enable = false */
	vUChar = 0;
	mib_set(MIB_QOS_ENABLE_QOS, &vUChar);

	/* InternetGatewayDevice.X_CT-COM_UplinkQoS.Bandwidth = 0 */
	vUInt = 0;
	mib_set(MIB_TOTAL_BANDWIDTH, &vUInt);
	vUChar = 0;
	mib_set(MIB_TOTAL_BANDWIDTH_LIMIT_EN, &vUChar);

	/* InternetGatewayDevice.X_CT-COM_UplinkQoS.Plan = priority */
	vUChar = 0;
	mib_set(MIB_QOS_POLICY, &vUChar);

#if defined(CONFIG_USER_IP_QOS) && defined(_PRMT_X_CT_COM_QOS_)
	/* InternetGatewayDevice.X_CT-COM_UplinkQoS.EnableForceWeight = 0 */
	vUChar = 0;
	mib_set(MIB_QOS_ENABLE_FORCE_WEIGHT, &vUChar);

	/* InternetGatewayDevice.X_CT-COM_UplinkQoS.EnableDSCPMark = 0 */
	vUChar = 0;
	mib_set(MIB_QOS_ENABLE_DSCP_MARK, &vUChar);
#endif

	/* InternetGatewayDevice.X_CT-COM_UplinkQoS.Enable802-1_P = 0 */
	vUChar = 0;
	mib_set(MIB_QOS_ENABLE_1P, &vUChar);

	//Now parsing the priority by qosMode
	need_queue_num = parsePriorityByQosMode(qosMode);
	printf("total need %d QoS queues %d\n",need_queue_num);

	if((qEntryNum=mib_chain_total(MIB_IP_QOS_QUEUE_TBL)) <=0)
		return -1;

	for(i=0;i<qEntryNum; i++)
	{
		if(!mib_chain_get(MIB_IP_QOS_QUEUE_TBL, i, (void*)&qEntry))
			continue;

		if(i >= sizeof(qos_mode_prio))
			break;

		//Now enable or disable the queues according QoS Mode
		if(i<need_queue_num)
			qEntry.enable = 1;
		else
			qEntry.enable = 0;

		mib_chain_update(MIB_IP_QOS_QUEUE_TBL, (void *)&qEntry, i);
		printf("Q%d enabled flag %d!\n",i+1, qEntry.enable);
	}

	/* delete old IP QoS classification rules */
	mib_chain_clear(MIB_IP_QOS_TBL);

	update_appbased_qos_tbl();
}
#else
int updateMIBforQosMode(unsigned char *qosMode)
{
	MIB_CE_IP_QOS_T qos_entity[4], *p=NULL;
	int need_queue_num;
	MIB_CE_IP_QOS_QUEUE_T qEntry;
	int qEntryNum, i;
	unsigned char vUChar;
	unsigned int vUInt;
	unsigned int app_inst_num = 1;

	if ( !qosMode || qosMode[0]=='\0' )
		return -1;

	printf("%s: qosMode=%s\n",__func__,qosMode);
	memset(qos_mode_prio,0,sizeof(qos_mode_prio));

	//Now parsing the priority by qosMode
	need_queue_num = parsePriorityByQosMode(qosMode);
	printf("total need %d QoS queues %d\n",need_queue_num);

	/* delete old IP QoS classification rules */
	mib_chain_clear(MIB_IP_QOS_TBL);
	mib_chain_clear(MIB_IP_QOS_APP_TBL);

	//Now according to the Priority to set IP QoS Rules
	//IPTV
	if(strcasestr(qosMode,"IPTV")){
		p = &qos_entity[QOS_PRIO_IPTV];
		memset(p, 0, sizeof(MIB_CE_IP_QOS_T));
		sprintf(p->RuleName, "%s", "rule_IPTV");
#ifdef CONFIG_IPV6
		p->IpProtocol = IPVER_IPV4;	/* IPv4 */
#endif
		p->prior = qos_mode_prio[QOS_PRIO_IPTV] ;
		p->enable = 1;
		p->phyPort = 2;
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		p->phyPort_end=2;
#endif

		p->cttypemap[0] = 10; //LANInterface
		p->modeTr69 = MODEOTHER;
		p->InstanceNum = find_max_CT_Class_instanNum() + 1;
		printf("Add QoS rule for %s, prio=%d, phy port=%d\n",p->RuleName, p->prior, p->phyPort);
		mib_chain_add(MIB_IP_QOS_TBL, p);
	}

	//INTERNET, VOIP, TR069, find corresponding WAN Interface

	if(strcasestr(qosMode,"VOIP"))
	{
		MIB_CE_IP_QOS_APP_T app_entry;

		app_entry.appName = IP_QOS_APP_VOIP;
		app_entry.prior = qos_mode_prio[QOS_PRIO_VOIP];
		app_entry.InstanceNum = app_inst_num;
		app_inst_num++;

		mib_chain_add(MIB_IP_QOS_APP_TBL, &app_entry);
	}

	if(strcasestr(qosMode,"TR069"))
	{
		MIB_CE_IP_QOS_APP_T app_entry;

		app_entry.appName = IP_QOS_APP_TR069;
		app_entry.prior = qos_mode_prio[QOS_PRIO_TR069];
		app_entry.InstanceNum = app_inst_num;
		app_inst_num++;

		mib_chain_add(MIB_IP_QOS_APP_TBL, &app_entry);
	}

	//NOTE: INTERNET be put on the last one, let ACL be added in that last. or not hit incorrectly.
	//      Better solution will let QoS in ACL has different weight
	if(strcasestr(qosMode,"INTERNET")){
		p = &qos_entity[QOS_PRIO_INTERNET];
		memset(p, 0, sizeof(MIB_CE_IP_QOS_T));
		sprintf(p->RuleName, "%s", "rule_INTERNET");
		p->enable = 1;
#ifdef CONFIG_IPV6
		p->IpProtocol = IPVER_IPV4;	/* IPv4 */
#endif
		p->prior = qos_mode_prio[QOS_PRIO_INTERNET] ;
		//p->cttypemap[0] = 9; //WANInterface
		p->modeTr69 = MODEOTHER;
		p->InstanceNum = find_max_CT_Class_instanNum() + 1;
		p->outif = getIfIndex_byConnectionType(X_CT_SRV_INTERNET);
		printf("[%s:%d] prior=%d, ifIndex=0x%x\n",__func__,__LINE__,p->prior,p->outif);

		if(p->outif==0xffffffff){
			printf("Error! Need INTERNET QoS support, but don't have WAN interface for this connection type!\n");
		}
		else{
			printf("Add QoS rule for %s, prio=%d, WAN ifIndex=%d\n",p->RuleName, p->prior, p->ifIndex);
			mib_chain_add(MIB_IP_QOS_TBL, p);
		}
	}
	printf("Finish config for QoS template %s\n",qosMode);
	return 0;

error:
	printf("Error! Set config for QoS template %s Fail!\n",qosMode);
	return -1;
}

int setMIBforQosMode(unsigned char *qosMode)
{
	MIB_CE_IP_QOS_T qos_entity[4], *p=NULL;
	int need_queue_num;
	MIB_CE_IP_QOS_QUEUE_T qEntry;
	int qEntryNum, i;
	unsigned char vUChar;
	unsigned int vUInt;
	char *qosMode_bk = NULL;
	if ( !qosMode || qosMode[0]=='\0' )
		return -1;

	qosMode_bk = strdup(qosMode);
	if(qosMode_bk == NULL)
		return -1;

	printf("%s: qosMode=%s\n",__func__,qosMode);
	memset(qos_mode_prio,0,sizeof(qos_mode_prio));

#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	/* InternetGatewayDevice.X_CT-COM_UplinkQoS.Enable = true */
	vUChar = 1;
#else
	/* InternetGatewayDevice.X_CT-COM_UplinkQoS.Enable = false */
	vUChar = 0;
#endif
	mib_set(MIB_QOS_ENABLE_QOS, &vUChar);

	/* InternetGatewayDevice.X_CT-COM_UplinkQoS.Bandwidth = 0 */
	vUInt = 0;
	mib_set(MIB_TOTAL_BANDWIDTH, &vUInt);
	vUChar = 0;
	mib_set(MIB_TOTAL_BANDWIDTH_LIMIT_EN, &vUChar);

	/* InternetGatewayDevice.X_CT-COM_UplinkQoS.Plan = priority */
	vUChar = 0;
	mib_set(MIB_QOS_POLICY, &vUChar);

#if defined(CONFIG_USER_IP_QOS) && defined(_PRMT_X_CT_COM_QOS_)
	/* InternetGatewayDevice.X_CT-COM_UplinkQoS.EnableForceWeight = 0 */
	vUChar = 0;
	mib_set(MIB_QOS_ENABLE_FORCE_WEIGHT, &vUChar);

	/* InternetGatewayDevice.X_CT-COM_UplinkQoS.EnableDSCPMark = 0 */
	vUChar = 0;
	mib_set(MIB_QOS_ENABLE_DSCP_MARK, &vUChar);
#endif

	/* InternetGatewayDevice.X_CT-COM_UplinkQoS.Enable802-1_P = 0 */
	vUChar = 0;
	mib_set(MIB_QOS_ENABLE_1P, &vUChar);

	//Now parsing the priority by qosMode
	need_queue_num = parsePriorityByQosMode(qosMode);
	printf("total need %d QoS queues %d\n",need_queue_num);

	if((qEntryNum=mib_chain_total(MIB_IP_QOS_QUEUE_TBL)) <=0)
		return -1;

	for(i=0;i<qEntryNum; i++)
	{
		if(!mib_chain_get(MIB_IP_QOS_QUEUE_TBL, i, (void*)&qEntry))
			continue;

		if(i >= sizeof(qos_mode_prio))
			break;

		//Now enable or disable the queues according QoS Mode
		if(i<need_queue_num)
			qEntry.enable = 1;
		else
			qEntry.enable = 0;

		mib_chain_update(MIB_IP_QOS_QUEUE_TBL, (void *)&qEntry, i);
		printf("Q%d enabled flag %d!\n",i+1, qEntry.enable);
	}

	updateMIBforQosMode(qosMode_bk);
	free(qosMode_bk);

	printf("Finish config for QoS template %s\n",qosMode);
	return 0;

error:
	printf("Error! Set config for QoS template %s Fail!\n",qosMode);
	return -1;
}
#endif	//#if 1
#endif

#ifdef CONFIG_E8B //Iulian Wu, add API let TR069 can setup QOS immediately
#ifdef _PRMT_X_CT_COM_QOS_
int setup_tr069Qos(struct in_addr *qos_addr)
{
        int entry_num, i=0;
        MIB_CE_IP_QOS_T entry;

        if(qos_addr == NULL){
                printf("Error! %s: qos_addr is NULL\n", __FUNCTION__);
                return -1; //IP is invalid
        }

        entry_num = mib_chain_total(MIB_IP_QOS_TBL);

        for(i=0; i<entry_num; i++)
        {
                if(!mib_chain_get(MIB_IP_QOS_TBL, i, (void*)&entry))
                    continue;
                if (strcmp(entry.RuleName, "rule_TR069") == 0) {
                        //printf("enter ip  %x\n", ((struct in_addr *)qos_addr->s_addr));
                        //printf("qEntry->dip %x\n", ((struct in_addr *)entry.dip)->s_addr);

                        if ((qos_addr->s_addr ==  ((struct in_addr *)entry.dip)->s_addr)) {
                                /* do nothing, ip & port is the same */
                                return 0;
                        }
                        else {
                                memcpy(&(entry.dip),&(qos_addr->s_addr),IP_ADDR_LEN);

                                if(!mib_chain_update(MIB_IP_QOS_TBL, (void *)&entry, i))
                                        printf("Error! %s: update %s failed \n", __FUNCTION__, MIB_IP_QOS_TBL);

                                stopIPQ();
                                setupIPQ();

	                            return 0;
                        }

                }
        }
        return -1; //can't found TR069 WAN
}

int add_appbased_qos_rule(MIB_CE_ATM_VC_Tp atm_entry)
{
	int i;
	int qEntryNum = 0;
	char apptypestr[48]={0};
	MIB_CE_IP_QOS_T qos_entry;


	if(!atm_entry)
		return -1;

	if((qEntryNum=mib_chain_total(MIB_IP_QOS_TBL)) < 0)
		return -1;

	generateWanName(atm_entry, apptypestr);
	for(i=0 ; i<qEntryNum ; i++)
	{
		if(!mib_chain_get(MIB_IP_QOS_TBL, i, (void*)&qos_entry))
			continue;

		if(qos_entry.applicationtype==atm_entry->applicationtype
			&& !memcmp(qos_entry.RuleName, apptypestr, sizeof(qos_entry.RuleName)-1))
			{
				return 0;
			}
	}

	memset(&qos_entry, 0, sizeof(MIB_CE_IP_QOS_T));
	qos_entry.enable = 1;

	switch(atm_entry->IpProtocol)
	{
		case IPVER_IPV4:
		case IPVER_IPV4_IPV6:
			qos_entry.IpProtocol = 1;
			break;
		case IPVER_IPV6:
			qos_entry.IpProtocol = 2;
			break;
		default:
			qos_entry.IpProtocol = 1;
			break;
	}

	snprintf(qos_entry.RuleName, sizeof(qos_entry.RuleName), "%s", apptypestr);

	if(atm_entry->applicationtype & X_CT_SRV_TR069){
		qos_entry.prior = qos_mode_prio[QOS_PRIO_TR069];
	}
	else if(atm_entry->applicationtype & X_CT_SRV_VOICE){
		qos_entry.prior = qos_mode_prio[QOS_PRIO_VOIP];
	}
	else if(atm_entry->applicationtype & X_CT_SRV_OTHER){
		qos_entry.prior = qos_mode_prio[QOS_PRIO_IPTV];
	}
	else if(atm_entry->applicationtype & X_CT_SRV_SPECIAL_SERVICE_ALL){
		//No special service type for QoS template
		//FIX ME if spec is updated or clarified.
		qos_entry.prior = qos_mode_prio[QOS_PRIO_INTERNET];
	}
	else{ // INTERNET
		qos_entry.prior = qos_mode_prio[QOS_PRIO_INTERNET];
	}

	qos_entry.enable = 1;
	qos_entry.classtype = 1;
	qos_entry.applicationtype = atm_entry->applicationtype;

	if(!mib_chain_add(MIB_IP_QOS_TBL, &qos_entry))
	{
		return -1;
	}

	return 0;
}

int update_appbased_qos_tbl(void)
{
	int i;
	int qEntryNum = 0;
	MIB_CE_IP_QOS_T qos_entry;
	MIB_CE_ATM_VC_T atm_entry;


	if((qEntryNum=mib_chain_total(MIB_IP_QOS_TBL)) <0)
		return -1;

	for (i = qEntryNum - 1; i >= 0; i--) {
		if (!mib_chain_get(MIB_IP_QOS_TBL, i, (void *)&qos_entry))
			continue;

		if (qos_entry.classtype == 1) {
			if (1 != mib_chain_delete(MIB_IP_QOS_TBL, i)) {
				return -1;
			}
		}
	}

	if((qEntryNum=mib_chain_total(MIB_ATM_VC_TBL)) <0)
		return -1;

	for(i=0 ; i<qEntryNum ; i++)
	{
		if(!mib_chain_get(MIB_ATM_VC_TBL, i, (void*)&atm_entry))
			continue;

		add_appbased_qos_rule(&atm_entry);
	}

	return 0;
}

#endif
#endif
