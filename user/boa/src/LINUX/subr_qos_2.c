/*
 *      System routines for IP QoS (NEW_IP_QOS_SUPPORT)
 *
 */

#include "utility.h"

#ifdef NEW_IP_QOS_SUPPORT
#ifdef CONFIG_8021P_PRIO
const char *setpredtable[]={"setpredtbl0", "setpredtbl1", "setpredtbl2", "setpredtbl3", "setpredtbl4", "setpredtbl5", "setpredtbl6", "setpredtbl7"};
#endif
const char ARG_TCPUDP[] = "TCP/UDP";
/*ql: 20081114 START: new IP QoS*/
#define QOS_SETUP_DEBUG
static unsigned int qos_setup_debug = 3;

#ifdef QOS_SETUP_DEBUG
#define QOS_SETUP_PRINT_FUNCTION                    \
    do{if(qos_setup_debug&0x1) fprintf(stderr,"%s: %s  %d\n", __FILE__, __FUNCTION__,__LINE__);}while(0)
#else
#define QOS_SETUP_PRINT_FUNCTION do{}while(0)
#endif

enum qos_mode_t
{
	QOS_NONE=0,
	QOS_RULE,
	QOS_TC
};

static char* proto2str2layer[] = {
    [0]" ",
    [1]"--ip-proto 6",
    [2]"--ip-proto 17",
    [3]"--ip-proto 1",
};

static char* proto2str[] = {
    [0]" ",
    [1]"-p TCP",
    [2]"-p UDP",
    [3]"-p ICMP",
};

static const char QOS_CHAIN_EBT[] =  "ebt_rule";
static const char QOS_CHAIN_IPT[] =  "ipt_rule";

/****************************************
* getUpLinkRate:
* DESC: get upstream link rate.
****************************************/
static unsigned int getUpLinkRate(void)
{
#ifdef CONFIG_DEV_xDSL
	Modem_LinkSpeed vLs;
	unsigned char ret = 0;
	unsigned int total_bandwidth = 1024;//default to be 1Mbps

	ret = adsl_drv_get(RLCM_GET_LINK_SPEED, (void *)&vLs, RLCM_GET_LINK_SPEED_SIZE);
	if (ret) {
		if(0 != vLs.upstreamRate)
			total_bandwidth = vLs.upstreamRate;
	}

	mib_set(MIB_QOS_UPRATE, (void *)&total_bandwidth);

	return total_bandwidth;
#else
	// Ethernet upLink: 100Mbps
	return 102400;
#endif
}

/************************************************************
* NAME: setupQosChain
* DESC: setup user defined chain in iptable tables or ebtables table
* RETURN: 0 - success; 1 - fail
************************************************************/
static int setupQoSChain(int enable)
{
	QOS_SETUP_PRINT_FUNCTION;

	if (enable) {
		va_cmd(EBTABLES, 4, 1, "-t", "broute", "-N", "ebt_rule");
		va_cmd(EBTABLES, 5, 1, "-t", "broute", "-P", "ebt_rule", "RETURN");
		va_cmd(EBTABLES, 6, 1, "-t", "broute", "-A", "BROUTING", "-j", "ebt_rule");
#if defined(CONFIG_IMQ) || defined(CONFIG_IMQ_MODULE)
		va_cmd(IPTABLES, 4, 1, "-t", "mangle", "-N", "ipt_rule");
		va_cmd(IPTABLES, 6, 1, "-t", "mangle", "-A", "PREROUTING", "-j", "ipt_rule");
#else
		va_cmd(IPTABLES, 4, 1, "-t", "mangle", "-N", "ipt_rule");
		va_cmd(IPTABLES, 6, 1, "-t", "mangle", "-A", "FORWARD", "-j", "ipt_rule");
#endif
		//va_cmd(IPTABLES, 4, 1, "-t", "mangle", "-N", "qos_rule");
		//va_cmd(IPTABLES, 6, 1, "-t", "mangle", "-A", "FORWARD", "-j", "qos_rule");
	} else {
		va_cmd(EBTABLES, 4, 1, "-t", "broute", "-F", "ebt_rule");
		va_cmd(EBTABLES, 6, 1, "-t", "broute", "-D", "BROUTING", "-j", "ebt_rule");
		va_cmd(EBTABLES, 4, 1, "-t", "broute", "-X", "ebt_rule");

#if defined(CONFIG_IMQ) || defined(CONFIG_IMQ_MODULE)
		va_cmd(IPTABLES, 4, 1, "-t", "mangle", "-F", "ipt_rule");
		va_cmd(IPTABLES, 6, 1, "-t", "mangle", "-D", "PREROUTING", "-j", "ipt_rule");
		va_cmd(IPTABLES, 4, 1, "-t", "mangle", "-X", "ipt_rule");
#else
		va_cmd(IPTABLES, 4, 1, "-t", "mangle", "-F", "ipt_rule");
		va_cmd(IPTABLES, 6, 1, "-t", "mangle", "-D", "FORWARD", "-j", "ipt_rule");
		va_cmd(IPTABLES, 4, 1, "-t", "mangle", "-X", "ipt_rule");
#endif
	}
	return 0;
}

/********************************************************************
* NAME: setupQosTcChain
* DESC: setup user defined chain in iptable tables or ebtables table for tc shaping
* RETURN: 0 - success; 1 - fail
********************************************************************/
static int setupQosTcChain(unsigned int enable)
{
	QOS_SETUP_PRINT_FUNCTION;

	if (enable)
	{
		va_cmd(EBTABLES, 4, 1, "-t", "broute", "-N", "ebt_rule");
		va_cmd(EBTABLES, 6, 1, "-t", "broute", "-A", "BROUTING", "-j", "ebt_rule");

		va_cmd(IPTABLES, 4, 1, "-t", "filter", "-N", "qos_filter");
		va_cmd(IPTABLES, 7, 1, "-t", "filter", "-I", "FORWARD", "1", "-j", "qos_filter");

		va_cmd(IPTABLES, 4, 1, "-t", "mangle", "-N", "qos_traffic");
		va_cmd(IPTABLES, 6, 1, "-t", "mangle", "-A", "POSTROUTING", "-j", "qos_traffic");
	} else {
		va_cmd(EBTABLES, 4, 1, "-t", "broute", "-F", "ebt_rule");
		va_cmd(EBTABLES, 6, 1, "-t", "broute", "-D", "BROUTING", "-j", "ebt_rule");
		va_cmd(EBTABLES, 4, 1, "-t", "broute", "-X", "ebt_rule");

		va_cmd(EBTABLES, 4, 1, "-t", "filter", "-F", "INPUT");

		va_cmd(IPTABLES, 4, 1, "-t", "filter", "-F", "qos_filter");
		va_cmd(IPTABLES, 6, 1, "-t", "filter", "-D", "FORWARD", "-j", "qos_filter");
		va_cmd(IPTABLES, 4, 1, "-t", "filter", "-X", "qos_filter");

		va_cmd(IPTABLES, 4, 1, "-t", "mangle", "-F", "qos_traffic");
		va_cmd(IPTABLES, 6, 1, "-t", "mangle", "-D", "POSTROUTING", "-j", "qos_traffic");
		va_cmd(IPTABLES, 4, 1, "-t", "mangle", "-X", "qos_traffic");
	}

	return 1;
}

/*******************************************************
* enableIMQ:
* DESC: setup IMQ device and redirect all packet to IMQ queue.
********************************************************/
static int enableIMQ(void)
{
	DOCMDINIT;

	QOS_SETUP_PRINT_FUNCTION;

	DOCMDARGVS(IFCONFIG, DOWAIT, "imq0 txqueuelen 100");
	DOCMDARGVS(IFCONFIG, DOWAIT, "imq0 up");

	DOCMDARGVS(IPTABLES, DOWAIT, "-t mangle -A PREROUTING -i br+ -j IMQ --todev 0");

	return 0;
}

/*******************************************************
* cleanup_qos_setting:
* DESC: clean all tc rule and relevant iptables/ebtables rules.
********************************************************/
static void cleanupQdiscRule(void)
{
	MIB_CE_ATM_VC_T pvcEntry;
	int i = 0, vcNum = 0;
	char ifname[IFNAMSIZ];
	DOCMDINIT;

	//clear all tc rule on pvc...
	vcNum = mib_chain_total(MIB_ATM_VC_TBL);
	for (i=0; i<vcNum; i++)
	{
		if (!mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&pvcEntry) || !pvcEntry.enable)
			continue;
		if (!pvcEntry.enableIpQos)
			continue;

		//interface
		ifGetName(pvcEntry.ifIndex, ifname, sizeof(ifname));

		DOCMDARGVS(TC, DOWAIT, "qdisc del dev %s root", ifname);
	}
}

static void cleanup_qos_setting(void)
{
	unsigned char qosmode;
	DOCMDINIT;

	QOS_SETUP_PRINT_FUNCTION;

	mib_get(MIB_QOS_MODE, (void *)&qosmode);
	if (qosmode == QOS_NONE)
		return;
	else if (qosmode == QOS_TC) {
		setupQosTcChain(0);
		cleanupQdiscRule();
	}
	else if (qosmode == QOS_RULE) {
#if defined(CONFIG_IMQ) || defined(CONFIG_IMQ_MODULE)
		DOCMDARGVS(IPTABLES, DOWAIT, "-t mangle -D PREROUTING -i br+ -j IMQ --todev 0");
		DOCMDARGVS(IFCONFIG, DOWAIT, "imq0 down");
#endif

		setupQoSChain(0);

		//clear all tc rule on imq0.
#if defined(CONFIG_IMQ) || defined(CONFIG_IMQ_MODULE)
		DOCMDARGVS(TC, DOWAIT, "qdisc del dev imq0 root");
#else
		cleanupQdiscRule();
#endif
	}
}

/******************************************************
* NAME: setup_filter_rule
* DESC: setup filter rule for relevant qdisc, and tag packet
                   according to qos rule.
* ARGS: policy 0 - PRIO; 1 - WRR
* RETURN: 0 - success; 1 - fail
******************************************************/
static int setup_filter_rule(unsigned char policy)
{
    MIB_CE_IP_QOS_T entry;
    int i = 0, EntryNum = 0;
	MIB_CE_ATM_VC_T pvcEntry;
	int j = 0, vcNum = 0;
    DOCMDINIT;

    EntryNum = mib_chain_total(MIB_IP_QOS_TBL);
	vcNum = mib_chain_total(MIB_ATM_VC_TBL);
    for(i=0; i<EntryNum; i++)
	{
		unsigned int mark=0;

		if(!mib_chain_get(MIB_IP_QOS_TBL, i, (void*)&entry)||!entry.enable)
		    continue;

		for (j=0; j<vcNum; j++)
		{
			char ifname[IFNAMSIZ];
			char phyPort[16]={0};
			char sport[48], dport[48], saddr[48], daddr[48], strmark[48];
			char strdscp[24] = {0};
			char *proto=NULL;
			char *eth_proto = NULL;
			unsigned int bridge=0;
			unsigned char tos=0, dscp=0;

			if (!mib_chain_get(MIB_ATM_VC_TBL, j, (void *)&pvcEntry))
				continue;

			if (!pvcEntry.enable)
				continue;
			if (!pvcEntry.enableIpQos || pvcEntry.ifIndex != entry.outif)
				continue;
			if (pvcEntry.cmode == CHANNEL_MODE_BRIDGE)
				bridge = 1;

			//interface
			ifGetName(pvcEntry.ifIndex, ifname, sizeof(ifname));

			//dscp match
#ifdef QOS_DSCP_MATCH
			if(0 != entry.qosDscp)
			{
				if (bridge)
					snprintf(strdscp, 24, "--ip-tos 0x%x", (entry.qosDscp-1)&0xFF);
				else
					snprintf(strdscp, 24, "-m dscp --dscp 0x%x", entry.qosDscp>>2);
			}else{
				strdscp[0]='\0';
			}
#endif

			//source address
			if(0 != entry.sip[0]) {
				if(0 != entry.smaskbit) {
					if (bridge)
						snprintf(saddr, 48, "--ip-source %s/%d",
							inet_ntoa(*(struct in_addr*)entry.sip), entry.smaskbit);
					else
						snprintf(saddr, 48, "-s %s/%d",
							inet_ntoa(*(struct in_addr*)entry.sip), entry.smaskbit);
				} else {
					if (bridge)
						snprintf(saddr, 48, "--ip-source %s", inet_ntoa(*(struct in_addr*)entry.sip));
					else
						snprintf(saddr, 48, "-s %s", inet_ntoa(*(struct in_addr*)entry.sip));
				}
			} else
				saddr[0]='\0';

			//dest address
			if(0 != entry.dip[0]) {
				if(0 != entry.dmaskbit) {
					if (bridge)
						snprintf(daddr, 48, "--ip-destination %s/%d",
							inet_ntoa(*(struct in_addr*)entry.dip), entry.dmaskbit);
					else
						snprintf(daddr, 48, "-d %s/%d",
							inet_ntoa(*(struct in_addr*)entry.dip), entry.dmaskbit);
				} else {
					if (bridge)
						snprintf(daddr, 48, "--ip-destination %s", inet_ntoa(*(struct in_addr*)entry.dip));
					else
						snprintf(daddr, 48, "-d %s", inet_ntoa(*(struct in_addr*)entry.dip));
				}
			} else
				daddr[0]='\0';

			//protocol
			if (bridge)
				proto = proto2str2layer[entry.protoType];//for ebtables
			else
				proto = proto2str[entry.protoType];//for iptables

			//source port (range)
			if((PROTO_NONE == entry.protoType) ||
				(PROTO_ICMP == entry.protoType) ||
				(0 == entry.sPort))
			{//if protocol is icmp or none or port not set, ignore the port
				sport[0] = '\0';
			}
			else
			{
				if (bridge)
					snprintf(sport, 48, "--ip-source-port %d", entry.sPort);
				else
					snprintf(sport, 48, "--sport %d", entry.sPort);
			}

			//dest port (range)
			if((PROTO_NONE == entry.protoType) ||
				(PROTO_ICMP == entry.protoType) ||
				(0 == entry.dPort))
			{//if protocol is icmp or none or port not set, ignore the port
				dport[0] = '\0';
			}
			else
			{
				if (bridge)
					snprintf(dport, 48, "--ip-destination-port %d", entry.dPort);
				else
					snprintf(dport, 48, "--dport %d", entry.dPort);
			}

			//lan port, USB, eth0_sw0-eth0_sw3, wlan
			if (entry.phyPort != 0xff) {
#if defined (IP_QOS_VPORT)
				if (entry.phyPort < SW_LAN_PORT_NUM)
					snprintf(phyPort, 16, "-i %s", SW_LAN_PORT_IF[entry.phyPort]);
#else
				if (entry.phyPort == 0)
					snprintf(phyPort, 16, "-i %s", ELANIF);
#endif
#ifdef CONFIG_USB_ETH
				else if (entry.phyPort == IFUSBETH_PHYNUM)
					snprintf(phyPort, 16, "-i %s", USBETHIF);
#endif
#ifdef WLAN_SUPPORT
				else {
					snprintf(phyPort, 16, "-i %s", getWlanIfName());
				}
#endif
			} else {
				if (bridge)
					phyPort[0] = '\0';
				else
					snprintf(phyPort, 16, "-i br0");
			}

			//lan 802.1p mark, 0-7 bit
			if(0 != entry.vlan1p) {
				if (bridge)
					snprintf(strmark, 48, "--vlan-prio %d", (entry.vlan1p-1)&0xff);
				else
					snprintf(strmark, 48, "-m mark --mark 0x%x", (entry.vlan1p-1)&0xff);
			} else
				strmark[0] = '\0';

			if (bridge) {
				if(strmark[0] != '\0')//vlan 802.1p priority, use 802.1Q ethernet protocol
				{
					eth_proto = "-p 0x8100";
				}else {//use ipv4 for ethernet protocol
					eth_proto = "-p 0x0800";
				}
			}

			//wan 802.1p mark
			if (0 != entry.m_1p)
			mark = (entry.m_1p-1)&0x7;
			mark |= (i+1) << 8;

			//set the mark
			if (bridge) {
				DOCMDARGVS(EBTABLES, DOWAIT, "-t broute -A %s %s %s %s %s %s %s %s %s %s -j mark --set-mark 0x%x",
					QOS_CHAIN_EBT, phyPort, eth_proto, proto, saddr, sport, daddr, dport, strdscp, strmark, mark);
			} else {
				DOCMDARGVS(IPTABLES, DOWAIT, "-t mangle -A %s %s %s %s %s %s %s %s %s -j MARK --set-mark 0x%x",
					QOS_CHAIN_IPT, phyPort, proto, saddr, sport, daddr, dport, strdscp, strmark, mark);
			}

			//reset match_mark
			if(strmark[0] != '\0') {
				if (bridge)
					snprintf(strmark, 48, "--vlan-prio %d", mark);
				else
					snprintf(strmark, 48, "-m mark --mark 0x%x", mark);
			}

			//set dscp
#ifdef QOS_DSCP
			if (entry.dscp) {//dscp target
				if (entry.m_dscp != 0) {
					if (bridge) {
						DOCMDARGVS(EBTABLES, DOWAIT, "-t broute -A %s %s %s %s %s %s %s %s %s %s -j ftos --set-ftos 0x%x",
							QOS_CHAIN_EBT, phyPort, eth_proto, proto, saddr, sport, daddr, dport, strdscp, strmark, (entry.m_dscp-1)&0xff);
					} else {
						DOCMDARGVS(IPTABLES, DOWAIT, "-t mangle -A %s %s %s %s %s %s %s %s %s -j DSCP --set-dscp 0x%x",
							QOS_CHAIN_IPT, phyPort, proto, saddr, sport, daddr, dport, strdscp, strmark, entry.m_dscp>>2);
					}
				}
			} else  {
#endif
			if ((entry.m_ipprio != 0) || (entry.m_iptos != 0xff)) {
				if (entry.m_ipprio != 0)
					tos = (entry.m_ipprio-1) << 5;
				if (entry.m_iptos != 0xff)
					tos |= entry.m_iptos;

				if (bridge) {
					DOCMDARGVS(EBTABLES, DOWAIT, "-t broute -A %s %s %s %s %s %s %s %s %s %s -j ftos --set-ftos 0x%x",
						QOS_CHAIN_EBT, phyPort, eth_proto, proto, saddr, sport, daddr, dport, strdscp, strmark, tos);
				} else {
					DOCMDARGVS(IPTABLES, DOWAIT, "-t mangle -A %s %s %s %s %s %s %s %s %s -j TOS --set-tos 0x%x",
						QOS_CHAIN_IPT, phyPort, proto, saddr, sport, daddr, dport, strdscp, strmark, tos);
				}
			}
#ifdef QOS_DSCP
			}
#endif

#if !defined(CONFIG_IMQ) && !defined(CONFIG_IMQ_MODULE)
			if(PLY_WRR == policy)//weighted round robin
			{
				DOCMDARGVS(TC, DOWAIT, "filter add dev %s parent 1: prio 1 protocol ip handle 0x%x fw flowid 1:%d00",
					ifname, mark, entry.prior+1);
			}
			else if (PLY_PRIO == policy)//priority queue
			{
				DOCMDARGVS(TC, DOWAIT, "filter add dev %s parent 1: prio %d protocol ip handle 0x%x fw flowid 1:%d",
					ifname, entry.prior+1, mark, entry.prior+1);
			}
#endif
		}

#if defined(CONFIG_IMQ) || defined(CONFIG_IMQ_MODULE)
		if(PLY_WRR == policy)//weighted round robin
		{
			DOCMDARGVS(TC, DOWAIT, "filter add dev imq0 parent 1: prio 1 protocol ip handle 0x%x fw flowid 1:%d00",
				mark, entry.prior+1);
		}
		else if (PLY_PRIO == policy)//priority queue
		{
			DOCMDARGVS(TC, DOWAIT, "filter add dev imq0 parent 1: prio %d protocol ip handle 0x%x fw flowid 1:%d",
				entry.prior+1, mark, entry.prior+1);
		}
#endif
	}

    return 0;
}

/****************************************************************
 *NAME:      setup_traffic_rule
 *DESC:      tc class add dev $DEV parent 10:1 handle 10:$SUBID htb rate $RATE ceil $CEIL
 *           tc filter add dev $DEV parent 10: protocol ip prio 0 handle $HANDLE fw classid 10:$SUBID
 *           iptables -p $PROTO -s $SADDR -d $DADDR --sport $SPORT --dport $DPORT -j MARK --set-mark $HANDLE
 *           setup traffic control for every configuration
 *ARGS:      index, start from 1
 *RETURN:    0 success, others  fail
 ****************************************************************/
static int setup_traffic_rule(MIB_CE_IP_TC_Tp entry)
{
	char ifname[IFNAMSIZ];
	char* tc_act = NULL, *fw_act=NULL;
	char* proto1 = NULL, *proto2 = NULL;
	char wanPort[16]={0};
	char  saddr[24], daddr[24], sport[16], dport[16];
	int upLinkRate=0, childRate=0;
	int mark;
	DOCMDINIT;

	QOS_SETUP_PRINT_FUNCTION;

	tc_act = (char*)ARG_ADD;
	fw_act = (char*)FW_ADD;

	if(NULL == entry) {
		printf("Invalid traffic contolling rule!\n");
		goto ERROR;
	}

	ifGetName(entry->ifIndex, ifname, sizeof(ifname));

	//wan interface
	snprintf(wanPort, 16, "-o %s", ifname);

	//source address and netmask
	if(0 != entry->srcip)
	{
		if(0 != entry->smaskbits) {
			snprintf(saddr, 24, "-s %s/%d", inet_ntoa(*((struct in_addr*)(&entry->srcip))), entry->smaskbits);
		} else {
			snprintf(saddr, 24, "-s %s", inet_ntoa(*((struct in_addr*)(&entry->srcip))));
		}
	}
	else {//if not specify the source ip
		saddr[0] = '\0';
	}

	//destination address and netmask
	if(0 != entry->dstip) {
		if(0 != entry->dmaskbits) {
			snprintf(daddr, 24, "-d %s/%d", inet_ntoa(*((struct in_addr*)(&entry->dstip))), entry->dmaskbits);
		} else {
			snprintf(daddr, 24, "-d %s", inet_ntoa(*((struct in_addr*)(&entry->dstip))));
		}
	} else {//if not specify the dest ip
		daddr[0] = '\0';
	}

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
	if (((0 != entry->sport) || (0 != entry->dport)) &&
		(entry->protoType < 2))
		entry->protoType = 4;

	if(entry->protoType>4)//wrong protocol index
	{
		printf("Wrong protocol\n");
		goto ERROR;
	} else {
		switch(entry->protoType)
		{
			case 0://NONE
				proto1 = " ";
				//filt_proto1 = " ";
				break;
			case 1://ICMP
				proto1 = "-p ICMP";
				//filt_proto1 = "match ip ptotocol 1 0xff";
				break;
			case 2://TCP
				proto1 = "-p TCP";
				//filt_proto1 = "match ip protocol 6 0xff";
				break;
			case 3://UDP
				proto1 = "-p UDP";
				//filt_proto1 = "match ip protocol 17 0xff";
				break;
			case 4://TCP/UDP
				proto1 = "-p TCP";
				proto2 = "-p UDP";
				//filt_proto1 = "match ip protocol 6 0xff";
				//filt_proto2 = "match ip protocol 17 0xff";
				break;
		}
	}

	upLinkRate = entry->limitSpeed;
	if(0 != upLinkRate)
	{
		//get mark
		mark = (entry->entryid<<12);

		//patch: true bandwidth will be a little greater than limit value, so I minish 7% of set limit value ahead.
		int ceil;
		ceil = upLinkRate/100 * 93;

		//childRate = (10 > upLinkRate)?upLinkRate:10;
		childRate = (10>ceil)?ceil:10;

		DOCMDARGVS(TC, DOWAIT, "class %s dev %s parent 1:1 classid 1:%d0 htb rate %dkbit ceil %dkbit mpu 64 overhead 4",
			tc_act, ifname, entry->entryid, childRate, ceil);

		DOCMDARGVS(TC, DOWAIT, "qdisc %s dev %s parent 1:%d0 handle %d1: pfifo",
			tc_act, ifname, entry->entryid, entry->entryid);

		DOCMDARGVS(TC, DOWAIT, "filter %s dev %s parent 1: protocol ip prio 0 handle 0x%x fw flowid 1:%d0",
			tc_act, ifname, mark, entry->entryid);

		DOCMDARGVS(IPTABLES, DOWAIT,  "-t mangle %s qos_traffic %s %s %s %s %s %s -j MARK --set-mark 0x%x",
			fw_act, wanPort, proto1, saddr, daddr, sport, dport, mark);

		/*TCP/UDP?*/
		if(proto2)//setup the other protocol
		{
			DOCMDARGVS(IPTABLES, DOWAIT, "-t mangle %s qos_traffic %s %s %s %s %s %s -j MARK --set-mark 0x%x",
				fw_act, wanPort, proto2, saddr, daddr, sport, dport, mark);
		}
	}
	else
	{//if uprate=0, forbid traffic matching the rules
		DOCMDARGVS(IPTABLES, DOWAIT, "-t filter %s qos_filter %s %s %s %s %s %s -j DROP",
			fw_act, wanPort, proto1, saddr, daddr, sport, dport);

		/*TCP/UDP again*/
		if(proto2)
		{
			DOCMDARGVS(IPTABLES, DOWAIT, "-t filter %s qos_filter %s %s %s %s %s %s -j DROP",
				fw_act, wanPort, proto2, saddr, daddr, sport, dport);
		}
	}

	return 0;
ERROR:
	return 1;
}


/**************************************************************************
 * NAME:    setup_wrr_queue
 * DESC:    Using the htb qdisc to implement the wrr qdisc(surprised?), not
 *          CBQ, because the CBQ qdisc is so complicated and not very accurate.
 *          The skeleton of wrr(htb):
 *                                     HTB(root qdisc,1:)
 *                                      |
 *                                     HTB(root class,1:1)
 *                  ____________________|________________
 *                 |            |            |           |
 *                HTB          HTB          HTB         HTB
 *         (sub-cls,1:10) (sub-cls,1:20)(sub-cls,1:30)(sub-cls,1:40)
 *
 *         for example, bandwidth is 1024Kbit/s, there are three queues with
 *         priority 3:2:1, then these queues are allocated rate and ceil is
 *         1/2, 1/3, 1/6 of total bandwidth.
 *         This function is called when dsl synchronization is completed.
 *ARGS:
 *RETURN:  0 success, 1 fail.
**************************************************************************/
static int setup_wrr_queue(void)
{
#if !defined(CONFIG_IMQ) && !defined(CONFIG_IMQ_MODULE)
	MIB_CE_ATM_VC_T vcEntry;
	int i, EntryNum;
	char ifname[IFNAMSIZ];
#endif
    int j, quantum;
	int rate = 0;
	unsigned int total_bandwidth = 0;
	DOCMDINIT;

	QOS_SETUP_PRINT_FUNCTION;

	total_bandwidth = getUpLinkRate();

#if defined(CONFIG_IMQ) || defined(CONFIG_IMQ_MODULE)
	//tc qdisc add dev $DEV root handle 1: htb default 400
	DOCMDARGVS(TC,DOWAIT, "qdisc add dev imq0 root handle 1: htb default 400");

	//tc class add dev $DEV parent 1: classid 1:1 htb rate $RATE ceil $CEIL
	DOCMDARGVS(TC, DOWAIT, "class add dev imq0 parent 1: classid 1:1 htb rate %uKbit ceil %uKbit burst 15k",
		total_bandwidth, total_bandwidth);

	for(j=1; j<=4; j++)
	{
		/*ql:20080821 START: when line rate is low than 1Mbps, rate should be smaller...*/
		//rate = 700 * (5-j)/10;
		if (total_bandwidth > 950)
			rate = 70 * (5-j);
		else if (total_bandwidth > 790)
			rate = 60 * (5-j);
		else if (total_bandwidth > 650)
			rate = 50 * (5-j);
		else if (total_bandwidth > 540)
			rate = 40 * (5-j);
		else if (total_bandwidth > 300)
			rate = 30 * (5-j);
		else
			rate = 10 * (5-j);
		/*ql:20080821 END*/
		quantum = 1250 *(5-j);

		//if total bandwidth is too small, then reduce rate value
		/*ql:20080821 START: modify rate according to ceil*/
		//rate = (rate>=ceil)?(10*(5-j)):rate;
		if (rate > total_bandwidth)
		{
			rate = total_bandwidth * (5-j)/10;
		}
		/*ql:20080821 END*/
		//tc class add dev $DEV parent 10:1 classid 10:$SUBID htb rate $RATE ceil $RATE prio $PRIO
		DOCMDARGVS(TC, DOWAIT, "class add dev imq0 parent 1:1 classid 1:%d00 htb rate %dKbit ceil %uKbit prio 0 quantum %d",
			j, rate, total_bandwidth, quantum);
	}

	//set queue len
	DOCMDARGVS(TC, DOWAIT, "qdisc add dev imq0 parent 1:100 handle 100: pfifo limit 12");
	DOCMDARGVS(TC, DOWAIT, "qdisc add dev imq0 parent 1:200 handle 200: pfifo limit 9");
	DOCMDARGVS(TC, DOWAIT, "qdisc add dev imq0 parent 1:300 handle 300: pfifo limit 6");
	DOCMDARGVS(TC, DOWAIT, "qdisc add dev imq0 parent 1:400 handle 400: pfifo limit 3");
#else
	EntryNum = mib_chain_total(MIB_ATM_VC_TBL);
	for (i=0; i<EntryNum; i++)
	{
		if(!mib_chain_get(MIB_ATM_VC_TBL, i, (void*)&vcEntry)||!vcEntry.enable)
			continue;

		//get the interface name(?)
		ifGetName(vcEntry.ifIndex, ifname, sizeof(ifname));

		//tc qdisc add dev $DEV root handle 1: htb default 400
		DOCMDARGVS(TC,DOWAIT, "qdisc add dev %s root handle 1: htb default 400",ifname);

		//tc class add dev $DEV parent 1: classid 1:1 htb rate $RATE ceil $CEIL
		DOCMDARGVS(TC, DOWAIT, "class add dev %s parent 1: classid 1:1 htb rate %uKbit ceil %uKbit burst 15k",
			ifname, total_bandwidth, total_bandwidth);

		for(j=1; j<=4; j++)
		{
			/*ql:20080821 START: when line rate is low than 1Mbps, rate should be smaller...*/
			//rate = 700 * (5-j)/10;
			if (total_bandwidth > 950)
				rate = 70 * (5-j);
			else if (total_bandwidth > 790)
				rate = 60 * (5-j);
			else if (total_bandwidth > 650)
				rate = 50 * (5-j);
			else if (total_bandwidth > 540)
				rate = 40 * (5-j);
			else if (total_bandwidth > 300)
				rate = 30 * (5-j);
			else
				rate = 10 * (5-j);
			/*ql:20080821 END*/
			quantum = 1250 *(5-j);

			//if total bandwidth is too small, then reduce rate value
			/*ql:20080821 START: modify rate according to ceil*/
			//rate = (rate>=ceil)?(10*(5-j)):rate;
			if (rate > total_bandwidth)
			{
				rate = total_bandwidth * (5-j)/10;
			}
			/*ql:20080821 END*/
			//tc class add dev $DEV parent 10:1 classid 10:$SUBID htb rate $RATE ceil $RATE prio $PRIO
			DOCMDARGVS(TC, DOWAIT, "class add dev %s parent 1:1 classid 1:%d00 htb rate %dKbit ceil %uKbit prio 0 quantum %d",
				ifname, j, rate, total_bandwidth, quantum);
		}

		//set queue len
		DOCMDARGVS(TC, DOWAIT, "qdisc add dev %s parent 1:100 handle 100: pfifo limit 12", ifname);
		DOCMDARGVS(TC, DOWAIT, "qdisc add dev %s parent 1:200 handle 200: pfifo limit 9", ifname);
		DOCMDARGVS(TC, DOWAIT, "qdisc add dev %s parent 1:300 handle 300: pfifo limit 6", ifname);
		DOCMDARGVS(TC, DOWAIT, "qdisc add dev %s parent 1:400 handle 400: pfifo limit 3", ifname);
	}
#endif

	//now, setup queue rules for wrr qdisc
	setup_filter_rule(PLY_WRR);

    return 0;
}

/*******************************************************************************
 *NAME:    setup_prio_queue
 *DESC:    if configurating policy to priority queue,
 *         create priority queues based on struct MIB_CE_IP_QUEUE_CFG_T setting,
 *         The default number of queue is four,1-4.
 *ARGS:    None
 *RETURN:  0 success, others fail
 *******************************************************************************/
static int setup_prio_queue(void)
{
#if !defined(CONFIG_IMQ) && !defined(CONFIG_IMQ_MODULE)
	MIB_CE_ATM_VC_T vcEntry;
    int i, EntryNum;
	char ifname[IFNAMSIZ];
#endif
	DOCMDINIT;

    QOS_SETUP_PRINT_FUNCTION;

#if defined(CONFIG_IMQ) || defined(CONFIG_IMQ_MODULE)
	//setup basic config for imq0
	DOCMDARGVS(TC,DOWAIT, "qdisc add dev imq0 root handle 1: prio bands 4 priomap 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3");

	//set queue len
	DOCMDARGVS(TC, DOWAIT, "qdisc add dev imq0 parent 1:1 handle 100: pfifo limit 10");
	DOCMDARGVS(TC, DOWAIT, "qdisc add dev imq0 parent 1:2 handle 200: pfifo limit 10");
	DOCMDARGVS(TC, DOWAIT, "qdisc add dev imq0 parent 1:3 handle 300: pfifo limit 10");
	DOCMDARGVS(TC, DOWAIT, "qdisc add dev imq0 parent 1:4 handle 400: pfifo limit 10");
#else
	EntryNum = mib_chain_total(MIB_ATM_VC_TBL);
	for (i=0; i<EntryNum; i++)
	{
		if(!mib_chain_get(MIB_ATM_VC_TBL, i, (void*)&vcEntry) || !vcEntry.enable)
			continue;

		//get the interface name(?)
		ifGetName(vcEntry.ifIndex, ifname, sizeof(ifname));

		DOCMDARGVS(TC,DOWAIT, "qdisc add dev %s root handle 1: prio bands 4 priomap 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3",ifname);

		//set queue len
		DOCMDARGVS(TC, DOWAIT, "qdisc add dev %s parent 1:1 handle 100: pfifo limit 10", ifname);
		DOCMDARGVS(TC, DOWAIT, "qdisc add dev %s parent 1:2 handle 200: pfifo limit 10", ifname);
		DOCMDARGVS(TC, DOWAIT, "qdisc add dev %s parent 1:3 handle 300: pfifo limit 10", ifname);
		DOCMDARGVS(TC, DOWAIT, "qdisc add dev %s parent 1:4 handle 400: pfifo limit 10", ifname);
	}
#endif

	//setup ip qos queue rules for pq
	setup_filter_rule(PLY_PRIO);

	return 0;
}

/*******************************************************************************
 * NAME:    setup_traffic_control
 * DESC:    main function to complte trafice controlling,
 *          setup the basic setting by calling setup_traffic_basic,
 *          and for every configuration by calling setup_traffic_cfg(),
 *          the basic setting includes one root qdisc and root
 *          class, the setting looks like below:
 *                              HTB(root qdisc, handle 10:)
 *                               |
 *                              HTB(root class, classid 10:1)
 *            ___________________|_____________________
 *            |         |        |          |          |
 *           HTB       HTB      HTB        HTB        HTB
 *(subclass id 10:10 rate Xkbit)........       (sub class id 10:N0 rate Ykbit)
 *ARGS:    none
 *RETURN:  0 success, others fail
 *******************************************************************************/
static int setup_traffic_control(void)
{
	MIB_CE_IP_TC_T  entry;
	MIB_CE_ATM_VC_T vcEntry;
	int i, entry_num =0, vcEntryNum = 0;
	char ifname[IFNAMSIZ];
	unsigned char totalBandWidthEn = 0;
	unsigned int bandwidth;
	unsigned short rate, ceil;
	DOCMDINIT;

	QOS_SETUP_PRINT_FUNCTION;

	mib_get(MIB_TOTAL_BANDWIDTH_LIMIT_EN, (void *)&totalBandWidthEn);
	entry_num = mib_chain_total(MIB_IP_QOS_TC_TBL);

	if (!totalBandWidthEn && (0==entry_num))
		return 1;

	if (totalBandWidthEn)
		mib_get(MIB_TOTAL_BANDWIDTH, (void *)&bandwidth);
	else
		bandwidth = getUpLinkRate();

	vcEntryNum = mib_chain_total(MIB_ATM_VC_TBL);
	for(i=0;i<vcEntryNum; i++)
	{
		if(!mib_chain_get(MIB_ATM_VC_TBL, i, (void*)&vcEntry)||!vcEntry.enable)
			continue;

		//patch: actual bandwidth maybe a little greater than configured limit value, so I minish 7% of the configured limit value ahead.
		if (totalBandWidthEn)
			ceil = bandwidth/100 * 93;
		else
			ceil = bandwidth;

		ifGetName(vcEntry.ifIndex, ifname, sizeof(ifname));

		//tc qdisc add dev $DEV root handle 1: htb default 2
		DOCMDARGVS(TC,DOWAIT, "qdisc add dev %s root handle 1: htb default 2 r2q 1", ifname);

		//tc class add dev $DEV parent 1: classid 1:1 htb rate $RATE ceil $CEIL
		DOCMDARGVS(TC, DOWAIT, "class add dev %s parent 1: classid 1:1 htb rate %dKbit ceil %dKbit mpu 64 overhead 4 burst 15k",
			ifname, ceil, ceil);

		//patch with above
		rate = (ceil>10)?10:ceil;

		//tc class add dev $DEV parent 1:1 classid 1:2 htb rate $RATE ceil $CEIL
		DOCMDARGVS(TC, DOWAIT, "class add dev %s parent 1:1 classid 1:2 htb rate %dKbit ceil %dKbit mpu 64 overhead 4",
			ifname, rate, ceil);

		//DOCMDARGVS(TC, DOWAIT, "qdisc add dev %s parent 1:2 handle 2: tbf rate %ukbit latency 50ms burst 1540 mpu 64",
		//	ifname, total_bandwidth);
		DOCMDARGVS(TC, DOWAIT, "qdisc add dev %s parent 1:2 handle 2: pfifo limit 10", ifname);
	}

	for(i=0; i<entry_num; i++)
	{
		if(!mib_chain_get(MIB_IP_QOS_TC_TBL, i, (void*)&entry))
			continue;

		if (setup_traffic_rule(&entry))
			return 1;
	}

	return 0;
}

static void setup_default_rule(void)
{
#if !defined(CONFIG_IMQ) && !defined(CONFIG_IMQ_MODULE)
	MIB_CE_ATM_VC_T vcEntry;
	int i, vcnum;
	char ifname[IFNAMSIZ];
#endif
	int k;
	unsigned char vChar, policy;
	DOCMDINIT;

	QOS_SETUP_PRINT_FUNCTION;

	mib_get(MIB_QOS_DOMAIN, (void *)&vChar);
	mib_get(MIB_QOS_POLICY, (void*)&policy);

#if !defined(CONFIG_IMQ) && !defined(CONFIG_IMQ_MODULE)
	vcnum = mib_chain_total(MIB_ATM_VC_TBL);
	for (i=0; i<vcnum; i++) {
		if(!mib_chain_get(MIB_ATM_VC_TBL, i, (void*)&vcEntry)||!vcEntry.enable)
			continue;

		//get the interface name(?)
		ifGetName(vcEntry.ifIndex, ifname, sizeof(ifname));

		if (vChar == (char)PRIO_IP) {
#ifdef CONFIG_8021P_PRIO
			unsigned char value[IPQOS_NUM_PKT_PRIO];
			if(mib_get(MIB_PRED_PRIO, (void *)value)== 0)
			{
				printf("Get 8021P_PROI  error!\n");
				return 0;
			}
#endif
			for (k=0; k<=(IPQOS_NUM_PKT_PRIO-1); k++) {
				char pattern[]="0x00";
				int prio, flowid;

				prio = k<<1;
				if (prio<=9)
					pattern[2] += prio; // highest 3 bits
				else
					pattern[2] = 'a'+(prio-10);

#ifdef CONFIG_8021P_PRIO
				flowid = value[k]+1;
#else
				flowid = priomap[k];
#endif

				// match ip tos PATTERN MASK
				if(PLY_WRR == policy)//weighted round robin
				{
					DOCMDARGVS(TC, DOWAIT, "filter add dev %s parent 1: prio 2 protocol ip u32 match ip tos %s 0xe0 flowid 1:%d00",
						ifname, pattern, flowid);
				}
				else if (PLY_PRIO == policy)//priority queue
				{
					DOCMDARGVS(TC, DOWAIT, "filter add dev %s parent 1: prio 5 protocol ip u32 match ip tos %s 0xe0 flowid 1:%d",
						ifname, pattern, flowid);
				}
			}
		}
		else if(vChar == (char)PRIO_802_1p){ // PRIO_802_1p
#ifdef CONFIG_8021P_PRIO
			unsigned char value[IPQOS_NUM_PKT_PRIO];
			if(mib_get(MIB_8021P_PRIO, (void *)value)== 0)
			{
				printf("Get 8021P_PRIO  error!\n");
				return 0;
			}
#endif
			for (k=0; k<=(IPQOS_NUM_PKT_PRIO-1); k++) {
				int flowid;

#ifdef CONFIG_8021P_PRIO
				flowid = value[k]+1;
#else
				flowid = priomap[k];
#endif

				if(PLY_WRR == policy)//weighted round robin
				{
					DOCMDARGVS(TC, DOWAIT, "filter add dev %s parent 1: prio 2 protocol ip handle %d fw flowid 1:%d00",
						ifname, k+1, flowid);
				}
				else if (PLY_PRIO == policy)//priority queue
				{
					DOCMDARGVS(TC, DOWAIT, "filter add dev %s parent 1: prio 5 protocol ip handle %d fw flowid 1:%d",
						ifname, k+1, flowid);
				}
			}
		}
	}
#else
	if (vChar == (char)PRIO_IP) {
#ifdef CONFIG_8021P_PRIO
		unsigned char value[IPQOS_NUM_PKT_PRIO];
		if(mib_get(MIB_PRED_PRIO, (void *)value)== 0)
		{
			printf("Get 8021P_PROI  error!\n");
			return 0;
		}
#endif
		for (k=0; k<=(IPQOS_NUM_PKT_PRIO-1); k++) {
			char pattern[]="0x00";
			int prio, flowid;

			prio = k<<1;
			if (prio<=9)
				pattern[2] += prio; // highest 3 bits
			else
				pattern[2] = 'a'+(prio-10);

#ifdef CONFIG_8021P_PRIO
			flowid = value[k]+1;
#else
			flowid = priomap[k];
#endif
			// match ip tos PATTERN MASK
			if(PLY_WRR == policy)//weighted round robin
			{
				DOCMDARGVS(TC, DOWAIT, "filter add dev imq0 parent 1: prio 2 protocol ip u32 match ip tos %s 0xe0 flowid 1:%d00",
					pattern, flowid);
			}
			else if (PLY_PRIO == policy)//priority queue
			{
				DOCMDARGVS(TC, DOWAIT, "filter add dev imq0 parent 1: prio 5 protocol ip u32 match ip tos %s 0xe0 flowid 1:%d",
					pattern, flowid);
			}
		}
	}
	else if(vChar == (char)PRIO_802_1p){ // PRIO_802_1p
#ifdef CONFIG_8021P_PRIO
		unsigned char value[IPQOS_NUM_PKT_PRIO];
		if(mib_get(MIB_8021P_PRIO, (void *)value)== 0)
		{
			printf("Get 8021P_PRIO  error!\n");
			return 0;
		}
#endif
		for (k=0; k<=(IPQOS_NUM_PKT_PRIO-1); k++) {
			int flowid;

#ifdef CONFIG_8021P_PRIO
			flowid = value[k]+1;
#else
			flowid = priomap[k];
#endif

			if(PLY_WRR == policy)//weighted round robin
			{
				DOCMDARGVS(TC, DOWAIT, "filter add dev imq0 parent 1: prio 2 protocol ip handle %d fw flowid 1:%d00",
					k+1, flowid);
			}
			else if (PLY_PRIO == policy)//priority queue
			{
				DOCMDARGVS(TC, DOWAIT, "filter add dev imq0 parent 1: prio 5 protocol ip handle %d fw flowid 1:%d",
					k+1, flowid);
			}
		}
	}
#endif
}

int setup_qos_setting(void)
{
	unsigned char policy;
	unsigned char vChar, qosmode;

	__dev_setupIPQoS(1);

	mib_get(MIB_MPMODE, (void *)&vChar);
	if (vChar & MP_IPQ_MASK)//qos priority
	{
		qosmode = QOS_RULE;

		//enable IP QoS on IMQ
		va_cmd("/bin/sarctl", 2, 1, "qos_imq", "1");

		mib_get(MIB_QOS_POLICY, (void *)&policy);

		setupQoSChain(1);

		if (policy == PLY_PRIO) {//for PRIO
			setup_prio_queue();
		}
		else if (policy == PLY_WRR) {//for WFQ
			setup_wrr_queue();
		}
		setup_default_rule();

#if defined(CONFIG_IMQ) || defined(CONFIG_IMQ_MODULE)
		enableIMQ();
#endif
	}//traffic shaping
	else
	{
		qosmode = QOS_TC;

		//disable IMQ
		va_cmd("/bin/sarctl", 2, 1, "qos_imq", "0");

		setupQosTcChain(1);

		if (setup_traffic_control()) {
			qosmode = QOS_NONE;
			setupQosTcChain(0);
			cleanupQdiscRule();
		}
	}
	mib_set(MIB_QOS_MODE, (void *)&qosmode);

	return 0;
}

void take_qos_effect(void)
{
    //clean up old setting
    cleanup_qos_setting();
    //setup new one
    setup_qos_setting();
}

/******************************************************
* NAME: stop_IPQoS
* DESC: when IP QoS stopped, traffic control will be effective.
******************************************************/
void stop_IPQoS(void)
{
	unsigned char mode=0;

	mib_get(MIB_MPMODE, (void *)&mode);
	mode &= ~MP_IPQ_MASK;
	mib_set(MIB_MPMODE, (void *)&mode);

	take_qos_effect();
}

#ifdef CONFIG_DEV_xDSL
static int change_queue(unsigned int upLinkRate)
{
    MIB_CE_ATM_VC_T entry;
    int i, j, vcnum=0;
	int rate, quantum;
    char ifname[IFNAMSIZ] = {0};
	unsigned char qosmode;
	DOCMDINIT;

	mib_get(MIB_QOS_MODE, (void *)&qosmode);

	if (qosmode == QOS_RULE)
	{
#if !defined(CONFIG_IMQ) && !defined(CONFIG_IMQ_MODULE)
	    vcnum = mib_chain_total(MIB_ATM_VC_TBL);
	    for(i=0; i<vcnum; i++)
	    {
			if((!mib_chain_get(MIB_ATM_VC_TBL, i, (void*)&entry)) || (!entry.enable))
			    continue;

			ifGetName(entry.ifIndex, ifname, sizeof(ifname));

			//tc class change dev $DEV parent 10: classid 10:1 htb rate $RATE ceil $CEIL prio 10
			DOCMDARGVS(TC, UNDOWAIT, "class change dev %s parent 1: classid 1:1 htb rate %dKbit ceil %dKbit burst 15k",
				ifname, upLinkRate, upLinkRate);

			for (j =1; j<=4; j++)
			{
				/*ql:20080821 START: when line rate is low than 1Mbps, rate should be smaller...*/
				//rate = 700 * (5-j)/10;
				if (upLinkRate > 950)
					rate = 70 * (5-j);
				else if (upLinkRate > 790)
					rate = 60 * (5-j);
				else if (upLinkRate > 650)
					rate = 50 * (5-j);
				else if (upLinkRate > 540)
					rate = 40 * (5-j);
				else if (upLinkRate > 300)
					rate = 30 * (5-j);
				else
					rate = 10 * (5-j);
				/*ql:20080821 END*/
				quantum = 1250 *(5-j);

				//if total bandwidth is too small, then reduce rate value
				if (rate > upLinkRate)
				{
					rate = upLinkRate * (5-j)/10;
				}
				//add subclass for one queue config
				//tc class add dev $DEV parent 10:1 classid 10:$SUBID htb rate $RATE ceil $RATE prio $PRIO
				DOCMDARGVS(TC, UNDOWAIT, "class change dev %s parent 1:1 classid 1:%d00 htb rate %dKbit ceil %dKbit prio 0 quantum %d",
					ifname, j, rate, upLinkRate, quantum);
			}
	    }
#else
		//tc class change dev $DEV parent 1: classid 1:1 htb rate $RATE ceil $CEIL
		DOCMDARGVS(TC, UNDOWAIT, "class change dev imq0 parent 1: classid 1:1 htb rate %dKbit ceil %dKbit burst 15k",
			upLinkRate, upLinkRate);

		for (j =1; j<=4; j++)
		{
				/*ql:20080821 START: when line rate is low than 1Mbps, rate should be smaller...*/
				//rate = 70 * (5-j);
				if (upLinkRate > 950)
					rate = 70 * (5-j);
				else if (upLinkRate > 790)
					rate = 60 * (5-j);
				else if (upLinkRate > 650)
					rate = 50 * (5-j);
				else if (upLinkRate > 540)
					rate = 40 * (5-j);
				else if (upLinkRate > 300)
					rate = 30 * (5-j);
				else
					rate = 10 * (5-j);
				/*ql:20080821 END*/
				quantum = 1250 * (5-j);
				/*ql:20080821 START: modify rate according to ceil*/
				//rate = (rate>=ceil)?(10*(5-j)):rate;
				if (rate > upLinkRate)
				{
					rate = upLinkRate * (5-j)/10;
				}
				/*ql:20080821 END*/

				//tc class add dev $DEV parent 10:1 classid 10:$SUBID htb rate $RATE ceil $RATE prio $PRIO
				DOCMDARGVS(TC, UNDOWAIT, "class change dev imq0 parent 1:1 classid 1:%d00 htb rate %dKbit ceil %dKbit prio 0 quantum %d",
					j, rate, upLinkRate, quantum);
		}
#endif
	}
	else if (qosmode == QOS_TC)
	{
	    vcnum = mib_chain_total(MIB_ATM_VC_TBL);
	    for(i=0; i<vcnum; i++)
	    {
			if((!mib_chain_get(MIB_ATM_VC_TBL, i, (void*)&entry)) || (!entry.enable))
			    continue;

			ifGetName(entry.ifIndex, ifname, sizeof(ifname));

			//tc class change dev $DEV parent 1: classid 1:1 htb rate $RATE ceil $CEIL
			DOCMDARGVS(TC,UNDOWAIT, "class change dev %s parent 1: classid 1:1 htb rate %dKbit ceil %dKbit",
				ifname, upLinkRate, upLinkRate);

			//tc class change dev $DEV parent 1:1 classid 1:2 htb rate $RATE ceil $CEIL
			DOCMDARGVS(TC,UNDOWAIT, "class change dev %s parent 1:1 classid 1:2 htb rate 10Kbit ceil %dKbit",
				ifname, upLinkRate);
	    }
	}

	mib_set(MIB_QOS_UPRATE, (void *)&upLinkRate);

	return 0;
}

int monitor_qos_setting(void)
{
    Modem_LinkSpeed vLs;
    unsigned char ret;
    unsigned char policy, mode, bandwidthlimit;
	unsigned int dsl_uprate;

	mib_get(MIB_QOS_POLICY, (void*)&policy);
	mib_get(MIB_QOS_UPRATE, (void *)&dsl_uprate);
	mib_get(MIB_QOS_MODE, (void *)&mode);
	mib_get(MIB_TOTAL_BANDWIDTH_LIMIT_EN, (void *)&bandwidthlimit);

	if (((mode==QOS_RULE) && (policy == PLY_WRR)) ||
		((mode==QOS_TC) && !bandwidthlimit))
	{//wrr or traffical control with no totalbandwidth restrict
	    ret = adsl_drv_get(RLCM_GET_LINK_SPEED, (void *)&vLs, RLCM_GET_LINK_SPEED_SIZE);
	    if (ret)
		{
			if(0 != vLs.upstreamRate)//setup
			{
			    if(dsl_uprate == vLs.upstreamRate)//need not setup
					return 0;
				else if((0 != dsl_uprate) && (dsl_uprate != vLs.upstreamRate))
				{
					change_queue(vLs.upstreamRate);
			    }
			}
		}
	}
    return 0;
}
#endif
/*ql: 20081114 END*/

int delIpQosTcRule(MIB_CE_ATM_VC_Tp pEntry)
{
	int total, i;
	MIB_CE_IP_TC_T entry;

	total = mib_chain_total(MIB_IP_QOS_TC_TBL);
	for (i=total-1; i>=0; i--)
	{
		mib_chain_get(MIB_IP_QOS_TC_TBL, i, &entry);
		if (entry.ifIndex != pEntry->ifIndex)
			continue;

		mib_chain_delete(MIB_IP_QOS_TC_TBL, i);
	}

	return(1);
}
#endif // of NEW_IP_QOS_SUPPORT

