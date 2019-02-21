/*
 *      System routines for IP QoS
 *
 */

#include "debug.h"
#include "utility.h"
#include <string.h>

#ifdef IP_QOS

int _setupIPQoSRule(int enable, unsigned int e_idx, MIB_CE_IP_QOS_Tp qEntry)
{
	MIB_CE_ATM_VC_T pvcEntry;
	char *argv[24], wanif[IFNAMSIZ], buf[128];
	char ipWanif[IFNAMSIZ];
	int k;
	unsigned char isValidRule= 0;
	char *tc_action=NULL, *fw_action=NULL, *table_action=NULL;
	char vChar;
	unsigned char prio_map[IPQOS_NUM_PKT_PRIO];
	MIB_CE_IP_QOS_QUEUE_T queue_entry;

	if (!isValidMedia(qEntry->outif))
		return 0;
	if(enable)
	{
		tc_action = (char *)ARG_ADD;
		fw_action = (char *)FW_ADD;
	}else
	{
		tc_action = (char *)ARG_DEL;
		fw_action = (char *)FW_DEL;
	}

	// Check qos queue
	if (getWanEntrybyindex(&pvcEntry, qEntry->outif) == 0) {
		if (pvcEntry.enable && pvcEntry.enableIpQos) { // active and valide interface
			queue_entry.outif = qEntry->outif;
			queue_entry.prior = qEntry->prior;
			if (findQosQueue(&queue_entry) && queue_entry.enable)
				isValidRule = 1;
		}
	}

	if(isValidRule ==0)
		return 0;
	/* TR069: Classification.1.ClassInterface */
	if(qEntry->flags & INGRESS_IS_WAN)
		return 0;

	// Kaohj
	// qos ip interface
	ifGetName(pvcEntry.ifIndex, ipWanif, sizeof(ipWanif));
	// qos media(vc, eth ...) interface
	//snprintf(wanif, 6, "vc%u", VC_INDEX(pvcEntry.ifIndex));
	ifGetName(PHY_INTF(pvcEntry.ifIndex), wanif, sizeof(wanif));

	if (pvcEntry.cmode != CHANNEL_MODE_BRIDGE) //for router mode
	{
		char saddr[20], daddr[20], sport[6], dport[6], mark[5], prio[4];
		char classId[]="0x00:0x00";
		char *psaddr, *pdaddr;
		int idx, tos, mark1p;

#ifdef _CWMP_MIB_
		if( enable )
			if( qEntry->enable==0 ) return 0;
#endif

		// source ip, mask
		snprintf(saddr, 20, "%s", inet_ntoa(*((struct in_addr *)qEntry->sip)));
		if (strcmp(saddr, ARG_0x4) == 0)
			psaddr = 0;
		else {
			if (qEntry->smaskbit!=0){
				snprintf(buf, sizeof(buf), "/%d", qEntry->smaskbi);
				strcat(saddr, buf);
				//snprintf(saddr, 20, "%s/%d", saddr, qEntry->smaskbit);
			}
			psaddr = saddr;
		}
		// destination ip, mask
		snprintf(daddr, 20, "%s", inet_ntoa(*((struct in_addr *)qEntry->dip)));
		if (strcmp(daddr, ARG_0x4) == 0)
			pdaddr = 0;
		else {
			if (qEntry->dmaskbit!=0){
				snprintf(buf, sizeof(buf), "/%d", qEntry->dmaskbit);
				strcat(daddr, buf);
				//snprintf(daddr, 20, "%s/%d", daddr, qEntry->dmaskbit);
			}
			pdaddr = daddr;
		}
		snprintf(sport, 6, "%d", qEntry->sPort);
		snprintf(dport, 6, "%d", qEntry->dPort);

		// mark the packet:  8-bits(high) |   8-bits(low)
		//                    class id    |  802.1p (if any)
		mark1p = _get_classification_mark(e_idx, qEntry);
		if (mark1p == 0) return 0;
		//ql: modify length of mark from 4 to 5
		snprintf(mark, 5, "%d", mark1p);

		// Rule
		argv[1] = (char *)ARG_T;
		argv[2] = "mangle";
		argv[3] = (char *)fw_action;
		argv[4] = (char *)FW_IPQ_MANGLE_USER;
		idx = 5;

		// lan port
		if (qEntry->phyPort != 0xff) {
			if (qEntry->phyPort < SW_LAN_PORT_NUM)
			{
				argv[idx++] = (char *)ARG_I;
				argv[idx++] = (char *)SW_LAN_PORT_IF[qEntry->phyPort];
			}
#ifdef CONFIG_USB_ETH
			else if (qEntry->phyPort == IFUSBETH_PHYNUM) {
				argv[idx++] = (char *)ARG_I;
				argv[idx++] = (char *)USBETHIF;
			}
#endif
#ifdef WLAN_SUPPORT
			else {
				argv[idx++] = (char *)ARG_I;
				argv[idx++] = (char *)WLANIF[0];
			}
#endif
		}
		else { // all lan ports
			argv[idx++] = (char *)ARG_I;
			argv[idx++] = (char *)LANIF;
		}

		argv[idx++]=(char *)ARG_O;
		// Kaohj --- for iptables
		//argv[idx++]=wanif;
		argv[idx++]=ipWanif;

		// protocol
		if (qEntry->protoType != PROTO_NONE) {
			argv[idx++] = "-p";
			if(qEntry->flags&EXC_PROTOCOL)
				argv[idx++] = (char *)ARG_NO;
			if (qEntry->protoType == PROTO_TCP)
				argv[idx++] = (char *)ARG_TCP;
			else if (qEntry->protoType == PROTO_UDP)
				argv[idx++] = (char *)ARG_UDP;
			else //if (qEntry->protoType == PROTO_ICMP)
				argv[idx++] = (char *)ARG_ICMP;
		}

		// src ip
		if (psaddr != 0)
		{
			argv[idx++] = "-s";
			if(qEntry->flags&EXC_SOURCEIP)
				argv[idx++] = (char *)ARG_NO;
			argv[idx++] = psaddr;

		}

		// src port
		if ((qEntry->protoType==PROTO_TCP ||
			qEntry->protoType==PROTO_UDP) &&
			(qEntry->flags&EXC_PROTOCOL)==0 &&
			qEntry->sPort != 0) {
			argv[idx++] = (char *)FW_SPORT;
			if(qEntry->flags&EXC_SOURCEPORT)
				argv[idx++] = (char *)ARG_NO;
			argv[idx++] = sport;
		}

		// dst ip
		if (pdaddr != 0)
		{
			argv[idx++] = "-d";
			if(qEntry->flags&EXC_DESTIP)
				argv[idx++] = (char *)ARG_NO;
			argv[idx++] = pdaddr;
		}
		// dst port
		if ((qEntry->protoType==PROTO_TCP ||
			qEntry->protoType==PROTO_UDP) &&
			(qEntry->flags&EXC_PROTOCOL)==0 &&
			qEntry->dPort != 0) {
			argv[idx++] = (char *)FW_DPORT;
			if(qEntry->flags&EXC_DESTPORT)
				argv[idx++] = (char *)ARG_NO;
			argv[idx++] = dport;
		}

		// target/jump
		argv[idx++] = "-j";

		// Mark 802.1p
		// iptables -t mangle -A m_ipq_user -i eth0_sw2
		//	-s 172.21.70.4/24
		//	-d 192.168.1.10/16 -p tcp --sport 25
		//	--dport 22 -j MARK --set-mark 22
		argv[idx] = "MARK";
		argv[idx+1] = "--set-mark";
		argv[idx+2] = mark;
		argv[idx+3] = NULL;
		TRACE(STA_SCRIPT, "%s %s %s %s %s %s %s ...--set-mark %s\n", IPTABLES, argv[1], argv[2], argv[3], argv[4], argv[5], argv[6], mark);
		do_cmd(IPTABLES, argv, 1);
		// Attribut to ClassQueue
		// Kaohj -- for skb->priority
		mib_get(MIB_QOS_DOMAIN, (void *)&vChar);
		if (vChar == (char)PRIO_IP)
			mib_get(MIB_PRED_PRIO, (void *)prio_map);
		else // PRIO_802_1p
			mib_get(MIB_8021P_PRIO, (void *)prio_map);
		for (k=0; k<8; k++) {
			if (prio_map[k] == (int)qEntry->prior) {
				classId[8]+=k;
				break;
			}
		}
		// Mark traffic class
		// iptables -t mangle -A m_ipq_user -i eth0_sw2
		//	-s 172.21.70.4/24
		//	-d 192.168.1.10/16 -p tcp --sport 25
		//	--dport 22 -j CLASSIFY --set-class 0x00:0x02
		argv[idx] = "CLASSIFY";
		argv[idx+1] = "--set-class";
		argv[idx+2] = classId;
		argv[idx+3] = NULL;
		TRACE(STA_SCRIPT, "%s %s %s %s %s %s %s ...--set-class %s\n", IPTABLES, argv[1], argv[2], argv[3], argv[4], argv[5], argv[6], classId);
		do_cmd(IPTABLES, argv, 1);

#if 0
		snprintf(prio, 4, "%d", (int)qEntry->prior);
		// tc filter add dev vc0 parent 1:0 prio 1 protocol ip handle 22 fw flowid 1:1
		va_cmd(TC, 15, 1, "filter", (char *)tc_action, "dev", wanif,
			"parent", "1:0", "prio", prio, "protocol", "ip", "handle", mark,
			"fw", "flowid", "1:1");
#endif

		// Mark ip tos
#ifdef QOS_DSCP
		if(qEntry->dscp==0) {
#endif
		// Kaohj -- use DSCP target to set IP-preced
		if (qEntry->m_ipprio) {
			tos = (qEntry->m_ipprio-1) << 3;
			snprintf(prio, 4, "%d", tos);
			argv[idx] = "DSCP";
			argv[idx+1] = "--set-dscp";
			argv[idx+2] = prio;
			argv[idx+3] = NULL;
			TRACE(STA_SCRIPT, "%s %s %s %s %s %s %s ...--set-dscp %s\n", IPTABLES, argv[1], argv[2], argv[3], argv[4], argv[5], argv[6], prio);
			do_cmd(IPTABLES, argv, 1);
		}
		if (qEntry->m_iptos != 0xff) {
			tos = qEntry->m_iptos;
			snprintf(prio, 4, "%d", tos);
			argv[idx] = "TOS";
			argv[idx+1] = "--set-tos";
			argv[idx+2] = prio;
			argv[idx+3] = NULL;
			TRACE(STA_SCRIPT, "%s %s %s %s %s %s %s ...--set-tos %s\n", IPTABLES, argv[1], argv[2], argv[3], argv[4], argv[5], argv[6], prio);
			do_cmd(IPTABLES, argv, 1);
		}
#ifdef QOS_DSCP
		}
		else if (qEntry->dscp == 1) {
			if (qEntry->m_ipprio != 0 || qEntry->m_iptos != 0) {
				tos = 0;
				tos = qEntry->m_ipprio << 3;
				tos |= qEntry->m_iptos << 1;
				snprintf(prio, 4, "%d", tos);
				argv[idx] = "DSCP";
				argv[idx+1] = "--set-dscp";
				argv[idx+2] = prio;
				argv[idx+3] = NULL;
				TRACE(STA_SCRIPT, "%s %s %s %s %s %s %s ...--set-dscp %s\n", IPTABLES, argv[1], argv[2], argv[3], argv[4], argv[5], argv[6], prio);
				do_cmd(IPTABLES, argv, 1);
			}
		}
#endif

		// hwnat qos
		hwnat_qos_translate_rule(qEntry);

		// Configure the filter to place the packets on class
		snprintf(prio, 4, "1:%d", (int)qEntry->prior+1);
		// tc filter add dev vc0 parent 1:0 prio 1 protocol ip handle 22 fw flowid 1:1
		// Create the root "prio" qdisc on wan interface
		// Kaohj -- not used, instead, use iptables to set skb->priority (CLASSIFY)
		#if 0
		va_cmd(TC, 15, 1, "filter", (char *)tc_action, "dev", wanif,
			"parent", "1:0", "prio", "1", "protocol", "ip", "handle", mark,
			"fw", "flowid", prio);
		#endif
#ifdef QOS_SPEED_LIMIT_SUPPORT
		if(qEntry->limitSpeedEnabled)
		{
			char lsParent[8]={0};
			char lsprio[8]={0};
			int flowidindex=mib_qos_speed_limit_existed(qEntry->limitSpeedRank,qEntry->prior);
			sprintf(lsParent,"1%d:",(int)qEntry->prior+1);
			sprintf(lsprio,"1%d:%d",(int)qEntry->prior+1,flowidindex+12);
			va_cmd(TC, 15, 1, "filter", (char *)tc_action, "dev", wanif,
				"parent",lsParent, "protocol","ip","prio", "1", "handle",mark,"fw","flowid", lsprio);
		}
#endif
	}
	else {
		char saddr[20], daddr[20], sport[6], dport[6], mark[5], prio[4];
		char *psaddr, *pdaddr;
		char *proto;
		int idx, tos, mark1p;

#ifdef _CWMP_MIB_
		if( enable )
			if( qEntry->enable==0 ) return 0;
#endif

		// source ip, mask
		snprintf(saddr, 20, "%s", inet_ntoa(*((struct in_addr *)qEntry->sip)));
		if (strcmp(saddr, ARG_0x4) == 0)
			psaddr = 0;
		else {
			if (qEntry->smaskbit!=0){
				snprintf(buf, sizeof(buf), "/%d", qEntry->smaskbit);
				strcat(saddr, buf);
				//snprintf(saddr, 20, "%s/%d", saddr, qEntry->smaskbit);
			}
			psaddr = saddr;
		}
		// destination ip, mask
		snprintf(daddr, 20, "%s", inet_ntoa(*((struct in_addr *)qEntry->dip)));
		if (strcmp(daddr, ARG_0x4) == 0)
			pdaddr = 0;
		else {
			if (qEntry->dmaskbit!=0){
				snprintf(buf, sizeof(buf), "/%d", qEntry->dmaskbit);
				strcat(daddr, buf);
				//snprintf(daddr, 20, "%s/%d", daddr, qEntry->dmaskbit);
			}
			pdaddr = daddr;
		}
		snprintf(sport, 6, "%d", qEntry->sPort);
		snprintf(dport, 6, "%d", qEntry->dPort);

		// mark the packet:  8-bits(high) |   8-bits(low)
		//                    class id    |  802.1p (if any)
		mark1p = _get_classification_mark(e_idx, qEntry);
		if (mark1p == 0) return 0;
		//ql: modify length of mark from 4 to 5
		snprintf(mark, 5, "%d", mark1p);

		// Rule
		argv[1] = (char *)ARG_T;
		argv[2] = "broute";
		argv[3] = (char *)fw_action;
		argv[4] = "BROUTING";
		idx = 5;

		// lan port
		if (qEntry->phyPort != 0xff) {
			if (qEntry->phyPort < SW_LAN_PORT_NUM)
			{
				argv[idx++] = (char *)ARG_I;
				argv[idx++] = (char *)SW_LAN_PORT_IF[qEntry->phyPort];
			}
#ifdef CONFIG_USB_ETH
			else if (qEntry->phyPort == IFUSBETH_PHYNUM) {
				argv[idx++] = (char *)ARG_I;
				argv[idx++] = (char *)USBETHIF;
			}
#endif
#ifdef WLAN_SUPPORT
			else {
				argv[idx++] = (char *)ARG_I;
				argv[idx++] = (char *)WLANIF[0];
			}
#endif
		}
	#if 0
		else { // all lan ports
			argv[idx++] = (char *)ARG_I;
			argv[idx++] = (char *)LANIF;
		}
	#endif

		if (qEntry->m_1p)
			argv[idx++] = "-p 0x8100";
		else
			argv[idx++] = "-p 0x0800";

		// protocol
		if (qEntry->protoType != PROTO_NONE) {
			argv[idx++] = "--ip-proto";
			if(qEntry->flags&EXC_PROTOCOL)
				argv[idx++] = (char *)ARG_NO;
			if (qEntry->protoType == PROTO_TCP)
				argv[idx++] = "6";
			else if (qEntry->protoType == PROTO_UDP)
				argv[idx++] = "17";
			else if (qEntry->protoType == PROTO_ICMP)
				argv[idx++] = "1";
		}

		// src ip
		if (psaddr != 0)
		{
			argv[idx++] = "--ip-source";
			if(qEntry->flags&EXC_SOURCEIP)
				argv[idx++] = (char *)ARG_NO;
			argv[idx++] = psaddr;

		}

		// src port
		if ((qEntry->protoType==PROTO_TCP ||
			qEntry->protoType==PROTO_UDP) &&
 			(qEntry->flags&EXC_PROTOCOL)==0 &&
			qEntry->sPort != 0) {
			argv[idx++] = "--ip-source-port";
			if(qEntry->flags&EXC_SOURCEPORT)
				argv[idx++] = (char *)ARG_NO;
			argv[idx++] = sport;
		}

		// dst ip
		if (pdaddr != 0)
		{
			argv[idx++] = "--ip-destination";
			if(qEntry->flags&EXC_DESTIP)
				argv[idx++] = (char *)ARG_NO;
			argv[idx++] = pdaddr;
		}
		// dst port
		if ((qEntry->protoType==PROTO_TCP ||
			qEntry->protoType==PROTO_UDP) &&
 			(qEntry->flags&EXC_PROTOCOL)==0 &&
			qEntry->dPort != 0) {
			argv[idx++] = "--ip-destination-port";
			if(qEntry->flags&EXC_DESTPORT)
				argv[idx++] = (char *)ARG_NO;
			argv[idx++] = dport;
		}

		// target/jump
		argv[idx++] = "-j";

		// Mark traffic class
		// iptables -t mangle -A PREROUTING -i eth0_sw2
		//	-s 172.21.70.4/24
		//	-d 192.168.1.10/16 -p tcp --sport 25
		//	--dport 22 -j MARK --set-mark 22
		argv[idx] = "mark";
		argv[idx+1] = "--set-mark";
		argv[idx+2] = mark;
		argv[idx+3] = NULL;
		TRACE(STA_SCRIPT, "%s %s %s %s %s %s %s ...--set-mark %s\n", EBTABLES, argv[1], argv[2], argv[3], argv[4], argv[5], argv[6], mark);
		do_cmd(EBTABLES, argv, 1);

#if 0
		snprintf(prio, 4, "%d", (int)qEntry->prior);
		// tc filter add dev vc0 parent 1:0 prio 1 protocol ip handle 22 fw flowid 1:1
		va_cmd(TC, 15, 1, "filter", (char *)tc_action, "dev", wanif,
			"parent", "1:0", "prio", prio, "protocol", "ip", "handle", mark,
			"fw", "flowid", "1:1");
#endif

		// Mark ip tos
		if (qEntry->m_ipprio != 0 || qEntry->m_iptos != 0xff) {
			tos = 0;
			if (qEntry->m_ipprio != 0)
				tos = (qEntry->m_ipprio-1) << 5;
			if (qEntry->m_iptos != 0xff)
				tos |= qEntry->m_iptos;
			snprintf(prio, 4, "%d", tos);
			argv[idx] = "ftos";
			argv[idx+1] = "--set-tos";
			argv[idx+2] = prio;
			argv[idx+3] = NULL;
			TRACE(STA_SCRIPT, "%s %s %s %s %s %s %s ...--set-tos %s\n", EBTABLES, argv[1], argv[2], argv[3], argv[4], argv[5], argv[6], prio);
			do_cmd(EBTABLES, argv, 1);
		}

		// Configure the filter to place the packets on class
		snprintf(prio, 4, "1:%d", (int)qEntry->prior+1);
		// tc filter add dev vc0 parent 1:0 prio 1 protocol ip handle 22 fw flowid 1:1
		// Create the root "prio" qdisc on wan interface
		va_cmd(TC, 15, 1, "filter", (char *)tc_action, "dev", wanif,
			"parent", "1:0", "prio", "1", "protocol", "ip", "handle", mark,
			"fw", "flowid", prio);
#ifdef QOS_SPEED_LIMIT_SUPPORT
		if(qEntry->limitSpeedEnabled)
		{
			char lsParent[8]={0};
			char lsprio[8]={0};
			int flowidindex=mib_qos_speed_limit_existed(qEntry->limitSpeedRank,qEntry->prior);
			sprintf(lsParent,"1%d:",(int)qEntry->prior+1);
			sprintf(lsprio,"1%d:%d",(int)qEntry->prior+1,flowidindex+12);
			va_cmd(TC, 15, 1, "filter", (char *)tc_action, "dev", wanif,
				"parent",lsParent, "protocol","ip","prio", "1", "handle",mark,"fw","flowid", lsprio);
		}
#endif
	}

	return 0;
}

int getQueueEntryByQinst(unsigned int qinst, MIB_CE_IP_QOS_QUEUE_T *p, unsigned int *id)
{
	int ret=-1;
	unsigned int i,num;

	if( (qinst==0) || (p==NULL) || (id==NULL) )
		return ret;

	num = mib_chain_total(MIB_IP_QOS_QUEUE_TBL);
	for(i=0; i<num; i++)
	{
		if( !mib_chain_get( MIB_IP_QOS_QUEUE_TBL, i, (void*)p ) )
			continue;

		if(p->QueueInstNum == qinst)
		{
			*id = i;
			ret = 0;
			break;
		}
	}
	return ret;
}

int setupDefaultQueue(int enable)
{
	unsigned int defaultQueue = 0;
	MIB_CE_ATM_VC_T pvcEntry;
	MIB_CE_IP_QOS_QUEUE_T queueEntry;
	char *argv[24], wanif[IFNAMSIZ],mark[5],prio[4];
	int k, vcnum,qosnum,chainid,mark1p,tos;
	unsigned int isValidRule = 0;
	char *tc_action=NULL, *fw_action=NULL;

	if(enable)
	{
		tc_action = (char *)ARG_ADD;
		fw_action = (char *)FW_ADD;
	}else
	{
		tc_action = (char *)ARG_DEL;
		fw_action = (char *)FW_DEL;
	}

	mib_get(MIB_QOS_DEFAULT_QUEUE,(void *)&defaultQueue);
	if(defaultQueue == 0)
		return 0;
	if(getQueueEntryByQinst(defaultQueue, &queueEntry,&chainid) < 0)
		return 0;

	vcnum = mib_chain_total(MIB_ATM_VC_TBL);
	for (k = 0; k < vcnum; k++) {
		/* get the specified chain record */
		if (!mib_chain_get(MIB_ATM_VC_TBL, k, (void *)&pvcEntry))
			continue;
		if (!pvcEntry.enable || !isValidMedia(pvcEntry.ifIndex))
			continue;
		if(pvcEntry.ifIndex==queueEntry.outif) {
			isValidRule = 1;
			break;
		}
	}

	if(isValidRule ==0)
		return 0;

	ifGetName(pvcEntry.ifIndex, wanif, sizeof(wanif));

	qosnum = mib_chain_total(MIB_IP_QOS_TBL);
	mark1p = ((qosnum+1) << 8);
	snprintf(mark, 5, "%d", mark1p);

	va_cmd(IPTABLES, 10, 1, "-t", "mangle", fw_action, "FORWARD", "-i", BRIF,"-j", "MARK", "--set-mark", mark);

	va_cmd(EBTABLES, 8, 1, "-t", "broute", fw_action, "BROUTING", "-j", "mark", "--set-mark", mark);

	snprintf(prio, 4, "1:%d", (int)queueEntry.prior+1);
	va_cmd(TC, 15, 1, "filter", (char *)tc_action, "dev", wanif,
		"parent", "1:0", "prio", "1", "protocol", "ip", "handle", mark,
		"fw", "flowid", prio);

	return 1;
}

int setupUserIPQoSRule(int enable)
{
	unsigned int num, i;
	MIB_CE_IP_QOS_T qEntry;

	num = mib_chain_total(MIB_IP_QOS_TBL);

	// set IP QoS rule
	for (i=0; i<num; i++)
	{
		if (!mib_chain_get(MIB_IP_QOS_TBL, i, (void *)&qEntry))
			continue;
#ifdef QOS_DIFFSERV
		if (qEntry.enDiffserv == 1) // Diffserv entry
			continue;
#endif

		_setupIPQoSRule( enable, i, &qEntry );
	}

	setupDefaultQueue(enable);
	return 0;
}

int stopIPQ(void)
{
	unsigned int num, i;
	MIB_CE_ATM_VC_T pvcEntry;
	char wanif[IFNAMSIZ], vChar;
	// Kaohj
	// Flush m_ipq_dft chain
	// iptables -t mangle -F m_ipq_dft
	va_cmd(IPTABLES, 4, 1, (char *)ARG_T, "mangle", "-F", (char *)FW_IPQ_MANGLE_DFT);
	// Kaohj -- delete chain for IPQoS mangle table in FORWARD
	//iptables -t mangle -D FORWARD -j m_ipq_dft
	va_cmd(IPTABLES, 6, 1, (char *)ARG_T, "mangle", (char *)FW_DEL, (char *)FW_FORWARD, "-j", (char *)FW_IPQ_MANGLE_DFT);
	// iptables -t mangle -X m_ipq_dft
	va_cmd(IPTABLES, 4, 1, (char *)ARG_T, "mangle", "-X", (char *)FW_IPQ_MANGLE_DFT);

	// Flush m_ipq_user chain
	// iptables -t mangle -F m_ipq_user
	va_cmd(IPTABLES, 4, 1, (char *)ARG_T, "mangle", "-F", (char *)FW_IPQ_MANGLE_USER);
	// Kaohj -- delete chain for IPQoS mangle table in FORWARD
	//iptables -t mangle -D FORWARD -j m_ipq_user
	va_cmd(IPTABLES, 6, 1, (char *)ARG_T, "mangle", (char *)FW_DEL, (char *)FW_FORWARD, "-j", (char *)FW_IPQ_MANGLE_USER);
	// iptables -t mangle -X m_ipq_user
	va_cmd(IPTABLES, 4, 1, (char *)ARG_T, "mangle", "-X", (char *)FW_IPQ_MANGLE_USER);
	//setupIPQoSRule( 0 );

	num = mib_chain_total(MIB_ATM_VC_TBL);
	// Create the root "prio" qdisc on wan interface
	for (i = 0; i < num; i++)
	{
		if (!mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&pvcEntry))
			continue;
		if (!pvcEntry.enable || !isValidMedia(pvcEntry.ifIndex))
			continue;
		if (!pvcEntry.enableIpQos)
			continue;

		// Kaohj -- place queueing in vc interface
		//snprintf(wanif, 6, "vc%u", VC_INDEX(pvcEntry.ifIndex));
		ifGetName( PHY_INTF(pvcEntry.ifIndex), wanif, sizeof(wanif));

		va_cmd(TC, 5, 1, "qdisc", (char *)ARG_DEL, "dev", wanif, "root");

	}

	// disable IPQoS

	__dev_setupIPQoS(0);	
	setWanIF1PMark();
	//printf("IP QoS: stopped\n");
}

// Kaohj
/* Match ip tos or 802.1p to skb->priority
 */
static void setupDefaultIPQRule()
{
	char vChar;
	int k;

	// hwnat qos
	//hwnat_qos_default_rule(); move outside
	mib_get(MIB_QOS_DOMAIN, (void *)&vChar);

	if (vChar == (char)PRIO_IP) {
		for (k=0; k<=(IPQOS_NUM_PKT_PRIO-1); k++) {
			// User CLASSIFY to attribute classification to flow
			char tosValue[]="0x00/0xe0";
			char classId[]="0x00:0x00";
			int prio;

			// MSB 3-bit
			prio = k<<1;
			if (prio<=9)
				tosValue[2] += prio;
			else
				tosValue[2] = 'a'+(prio-10);

			classId[8] += k;
			// Match 3-bit precedence value to skb->priority
			// iptables -t mangle -A m_ipq_dft -i br0 -m tos --tos 0xa0/0xe0 -j CLASSIFY --set-class 0x00:0x05
			va_cmd(IPTABLES, 14, 1, (char *)ARG_T, "mangle", (char *)FW_ADD, (char *)FW_IPQ_MANGLE_DFT, (char *)ARG_I,
				(char *)LANIF, "-m", "tos", "--tos", tosValue, "-j", "CLASSIFY", "--set-class", classId);
		}
	}
	else if(vChar == (char)PRIO_802_1p){ // PRIO_802_1p
		for (k=0; k<=(IPQOS_NUM_PKT_PRIO-1); k++) {
			char s_mark[]="0";
			char classId[]="0x00:0x00";

			s_mark[0] += (k+1);
			classId[8] += k;

			// iptables -t mangle -A m_ipq_dft -i br0 -m mark --mark 2 -j CLASSIFY --set-class 0x00:0x01
			va_cmd(IPTABLES, 14, 1, (char *)ARG_T, "mangle", (char *)FW_ADD, (char *)FW_IPQ_MANGLE_DFT, (char *)ARG_I,
				(char *)LANIF, "-m", "mark", "--mark", s_mark, "-j", "CLASSIFY", "--set-class", classId);
		}
	}
}

/*
 *	Setup Qdisc for each qos-enabled interface.
 *	Return:
 *	0: No qos-enabled interface
 *	1: there exists qos-enabled interface
 */
static int setupQdisc()
{
	unsigned int num, i;
	MIB_CE_ATM_VC_T pvcEntry;
	unsigned char prio_map[IPQOS_NUM_PKT_PRIO];
	char vChar;
	int enable_qos=0;
	char wanif[IFNAMSIZ];
	char myPriomap[100];
	char tc_cmd[100];

	// get the prio mapping
	mib_get(MIB_QOS_DOMAIN, (void *)&vChar);
	if (vChar == (char)PRIO_IP)
		mib_get(MIB_PRED_PRIO, (void *)prio_map);
	else // PRIO_802_1p
		mib_get(MIB_8021P_PRIO, (void *)prio_map);
	num = mib_chain_total(MIB_ATM_VC_TBL);
	// Create the root "prio" qdisc on wan interface
	for (i = 0; i < num; i++)
	{
		#ifdef QOS_SPEED_LIMIT_SUPPORT
		char s_level[]="0", s_classid[]="1:0", s_handle[]="11:";
		#else
		char s_level[]="0", s_classid[]="1:3", s_handle[]="3:";
		#endif
		/* get the specified chain record */
		if (!mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&pvcEntry))
			continue;
		if (!pvcEntry.enable || !isValidMedia(pvcEntry.ifIndex))
			continue;
		if ( pvcEntry.enableIpQos == 1 ) {
			enable_qos = 1;
		} else
			continue;

		// Kaohj -- IPQoS for vc interface
		// vc interface
		//snprintf(wanif, 6, "vc%u", VC_INDEX(pvcEntry.ifIndex));
		ifGetName( PHY_INTF(pvcEntry.ifIndex), wanif, sizeof(wanif));
		// tc qdisc add dev vc0 root handle 1: htb
		// tc qdisc add dev vc0 root handle 1: prio
		// By default, this command instantly create classes 1:1, 1:2
		// and 1:3 and each of them has its pfifo queue already installed.
		#if 0
		va_cmd(TC, 8, 1, "qdisc", (char *)ARG_ADD, "dev", wanif,
			"root", "handle", "1:", "prio");
		#endif
#if 1
		// Kaohj -- set default priomap for prio queue
		sprintf(myPriomap,"%d %d %d %d %d %d %d %d", prio_map[0], prio_map[1], prio_map[2],
			prio_map[3], prio_map[4], prio_map[5], prio_map[6], prio_map[7]);
		//va_cmd(TC, 27, 0, "qdisc", (char *)ARG_ADD, "dev", wanif, "root", "handle", "1:", "prio", "bands", "4", "priomap", myPriomap);
		snprintf(tc_cmd, 100, "tc qdisc add dev %s root handle 1: prio bands 4 priomap %s", wanif, myPriomap);
		system(tc_cmd);
		va_cmd(TC, 11, 1, "qdisc", (char *)ARG_ADD, "dev", wanif,
				"parent", "1:1", "handle", "2:", "pfifo", "limit", "10");
		va_cmd(TC, 11, 1, "qdisc", (char *)ARG_ADD, "dev", wanif,
				"parent", "1:2", "handle", "3:", "pfifo", "limit", "10");
		va_cmd(TC, 11, 1, "qdisc", (char *)ARG_ADD, "dev", wanif,
				"parent", "1:3", "handle", "4:", "pfifo", "limit", "10");
		va_cmd(TC, 11, 1, "qdisc", (char *)ARG_ADD, "dev", wanif,
				"parent", "1:4", "handle", "5:", "pfifo", "limit", "10");
#else
		s_level[0] += IPQOS_NUM_PRIOQ;
		va_cmd(TC, 10, 1, "qdisc", (char *)ARG_ADD, "dev", wanif,
			"root", "handle", "1:", "prio", "bands", s_level);
#endif

	}
	return enable_qos;
}

int setupIPQ(void)
{
	int enable_qos_flag=0;
#ifdef QOS_DIFFSERV
	unsigned char qosDomain;
	mib_get(MIB_QOS_DIFFSERV, (void *)&qosDomain);
	if (qosDomain == 1)
		return 1;
#endif
#ifdef QOS_SPEED_LIMIT_SUPPORT
	unsigned short pvcbandwidth;
	unsigned int totalpvcbandwidth=0;
	char pvcbandwidthS[16]={0};
	mib_get(MIB_PVC_TOTAL_BANDWIDTH,&pvcbandwidth);
	//totalpvcbandwidth=pvcbandwidth*1024;
	//sprintf(pvcbandwidthS,"%d",totalpvcbandwidth);
	//ql-- set parameter unit is KBps.
	sprintf(pvcbandwidthS, "%d", pvcbandwidth);
	va_cmd("/bin/sarctl",2,1,"tc",pvcbandwidthS);
#endif
	enable_qos_flag = setupQdisc();
	if ( enable_qos_flag != 1 ) {
		printf("NOT enable IP QoS on all interfaces\n");
		return;
	}

	// Kaohj -- add chain for IPQoS default rules in mangle table in FORWARD
	// iptables -t mangle -N m_ipq_dft
	va_cmd(IPTABLES, 4, 1, (char *)ARG_T, "mangle", "-N", (char *)FW_IPQ_MANGLE_DFT);
	//iptables -t mangle -A FORWARD -j m_ipq_dft
	va_cmd(IPTABLES, 6, 1, (char *)ARG_T, "mangle", (char *)FW_ADD, (char *)FW_FORWARD, "-j", (char *)FW_IPQ_MANGLE_DFT);

	setupDefaultIPQRule();

	// Kaohj -- add chain for IPQoS user-defined rules in mangle table in FORWARD
	// iptables -t mangle -N m_ipq_user
	va_cmd(IPTABLES, 4, 1, (char *)ARG_T, "mangle", "-N", (char *)FW_IPQ_MANGLE_USER);
	//iptables -t mangle -A FORWARD -j m_ipq_user
	va_cmd(IPTABLES, 6, 1, (char *)ARG_T, "mangle", (char *)FW_ADD, (char *)FW_FORWARD, "-j", (char *)FW_IPQ_MANGLE_USER);

	setupUserIPQoSRule(1);
	hwnat_qos_default_rule();
	// enable IPQoS

	__dev_setupIPQoS(1);
	//printf("IP QoS: started\n");
}
#endif //#ifdef IP_QOS

#if defined(IP_QOS) || defined(NEW_IP_QOS_SUPPORT)
/*
 * find entry from Queue Table.
 * Key: interface + precedence
 * Return: 0 : fail; 1: success
 * While successful, the Queue entry will be put in entry.
 */
int findQosQueue(MIB_CE_IP_QOS_QUEUE_T *entry)
{
	int entryNum, i;
	MIB_CE_IP_QOS_QUEUE_T qEntry;

	entryNum = mib_chain_total(MIB_IP_QOS_QUEUE_TBL);

	for (i=0; i<entryNum; i++) {
		mib_chain_get(MIB_IP_QOS_QUEUE_TBL, i, (void *)&qEntry);

		if (  entry->outif == qEntry.outif && entry->prior == qEntry.prior ) {
			memcpy((void *)entry, (void *)&qEntry, sizeof(MIB_CE_IP_QOS_QUEUE_T));
			return 1;
		}

	}
	return 0;
}

void update_qos_tbl()
{
	int i,j;
	unsigned int entryNum,vcEntryNum;
	MIB_CE_IP_QOS_T qos_entry;
	MIB_CE_IP_QOS_QUEUE_T queue_entry;
	MIB_CE_ATM_VC_T vc_entry;
	unsigned char qosIsChanged = 0;
	char qosQueueDesc[MAX_QUEUE_DESC_LEN];
	int isValid;
	MEDIA_TYPE_T mType;

	//update queue entry
	entryNum = mib_chain_total(MIB_IP_QOS_QUEUE_TBL);
	for(i=0; i<entryNum; i++)
	{
		if(!mib_chain_get(MIB_IP_QOS_QUEUE_TBL, i , (void *)&queue_entry))
			continue;
		isValid = 0;
		if (getWanEntrybyindex(&vc_entry, queue_entry.outif) == 0) {
			if (vc_entry.enableIpQos) // valide interface
				isValid = 1;
		}
		if (isValid) {
			mType = MEDIA_INDEX(queue_entry.outif);
			if (mType == MEDIA_ATM)
				sprintf(qosQueueDesc,"%d_%d_p%d",vc_entry.vpi,vc_entry.vci,queue_entry.prior);
			else if (mType == MEDIA_ETH)
				sprintf(qosQueueDesc,"nas%d_p%d",ETH_INDEX(queue_entry.outif),queue_entry.prior);
			else
				sprintf(qosQueueDesc,"unknown%d_p%d",ETH_INDEX(queue_entry.outif),queue_entry.prior);
			strncpy(queue_entry.desc,qosQueueDesc,MAX_QUEUE_DESC_LEN-1);
			queue_entry.desc[MAX_QUEUE_DESC_LEN-1] = 0;
			mib_chain_update(MIB_IP_QOS_QUEUE_TBL, (void *)&queue_entry, i);
		}
		else {
			qosIsChanged = 1;
			mib_chain_delete(MIB_IP_QOS_QUEUE_TBL, i);
			i--;
			entryNum = mib_chain_total(MIB_IP_QOS_QUEUE_TBL);
		}
	}

	//update classification entry
	entryNum = mib_chain_total(MIB_IP_QOS_TBL);
	for(i=0; i<entryNum; i++)
	{
		if(!mib_chain_get(MIB_IP_QOS_TBL, i , (void *)&qos_entry))
			continue;
		queue_entry.outif = qos_entry.outif;
		queue_entry.prior = qos_entry.prior;
		if (!findQosQueue(&queue_entry)) {
			qosIsChanged = 1;
			mib_chain_delete(MIB_IP_QOS_TBL, i);
			i--;
			entryNum = mib_chain_total(MIB_IP_QOS_TBL);
		}
	}

	#ifdef IP_QOS
	if(qosIsChanged == 1)
	{
		stopIPQ();
		setupIPQ();
	}
	#endif
}
#endif //#ifdef IP_QOS || NEW_IP_QOS_SUPPORT

