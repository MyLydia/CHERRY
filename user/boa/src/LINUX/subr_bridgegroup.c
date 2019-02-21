/*
 *      System routines for Port-mapping
 *
 */

#include <string.h>
#include "debug.h"
#include "utility.h"
#include <linux/wireless.h>

#if defined(CONFIG_USER_BRIDGE_GROUPING)
#ifdef CONFIG_RTK_L34_ENABLE // Rostelecom, Port Binding function
#include <rtk/rtusr_rg_api.h>
#define OMCI_WAN_INFO "/proc/omci/wanInfo"
#ifdef CONFIG_00R0
const char VLAN_BIND[] = "vlanbinding";
#include <signal.h>
#endif

void set_port_binding_rule(int enable)
{
	int i = 0, j = 0, num = 0;
#ifdef CONFIG_00R0
	int bind_bridge_WAN = 0;
#endif
	MIB_CE_ATM_VC_T pvcEntry;
	num = mib_chain_total(MIB_ATM_VC_TBL);

	if (enable)
	{
		// don't touch the DHCP server if mapping to bridge WAN
		for (i = 0; i < num; i++)
		{
			if (!mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&pvcEntry))
				continue;

			if (pvcEntry.enable == 0)
				continue;

			if (pvcEntry.cmode == CHANNEL_MODE_BRIDGE && pvcEntry.itfGroup != 0)
			{
				for (j = PMAP_ETH0_SW0; j <= PMAP_ETH0_SW3 && j < SW_LAN_PORT_NUM; ++j)
				{
					if (BIT_IS_SET(pvcEntry.itfGroup, j)) {
#ifdef CONFIG_00R0
						bind_bridge_WAN = 1;
#endif
						#ifdef _LINUX_3_18_
						va_cmd(IPTABLES, 12, 1, (char *)FW_ADD, (char *)FW_INACC, "-m", "physdev", "--physdev-in", SW_LAN_PORT_IF[j], "-p", (char *)ARG_UDP, (char *)FW_DPORT, (char *)PORT_DHCP, "-j", (char *)FW_DROP);
#ifdef CONFIG_00R0 //igmpProxy drop the IGMP report pkts from bridgeWan, IulianWu				
						va_cmd(IPTABLES, 10, 1, (char *)FW_ADD, (char *)FW_INACC, "-m", "physdev", "--physdev-in", SW_LAN_PORT_IF[j], "-d", "224.0.0.0/4", "-j", (char *)FW_DROP);
#endif						
						#else
						va_cmd(IPTABLES, 10, 1, (char *)FW_ADD, (char *)FW_INACC, (char *)ARG_I, SW_LAN_PORT_IF[j], "-p", (char *)ARG_UDP, (char *)FW_DPORT, (char *)PORT_DHCP, "-j", (char *)FW_DROP);
						#endif
					}
				}

#ifdef WLAN_SUPPORT
				for (j = PMAP_WLAN0; j <= PMAP_WLAN1_VAP3; ++j)
				{
					if (BIT_IS_SET(pvcEntry.itfGroup, j)) {
#ifdef CONFIG_00R0
						bind_bridge_WAN = 1;
#endif
						#ifdef _LINUX_3_18_
						va_cmd(IPTABLES, 12, 1, (char *)FW_ADD, (char *)FW_INACC, "-m", "physdev", "--physdev-in", wlan[j - PMAP_WLAN0], "-p", (char *)ARG_UDP, (char *)FW_DPORT, (char *)PORT_DHCP, "-j", (char *)FW_DROP);
#ifdef CONFIG_00R0 //igmpProxy drop the IGMP report pkts from bridgeWan, IulianWu	
						va_cmd(IPTABLES, 10, 1, (char *)FW_ADD, (char *)FW_INACC, "-m", "physdev", "--physdev-in", wlan[j - PMAP_WLAN0], "-d", "224.0.0.0/4", "-j", (char *)FW_DROP);
#endif
						#else
						va_cmd(IPTABLES, 10, 1, (char *)FW_ADD, (char *)FW_INACC, (char *)ARG_I, wlan[j - PMAP_WLAN0], "-p", (char *)ARG_UDP, (char *)FW_DPORT, (char *)PORT_DHCP, "-j", (char *)FW_DROP);
						#endif
					}
				}
#endif // WLAN_SUPPORT
			}
		}

#ifdef CONFIG_00R0
		if (bind_bridge_WAN == 1) {
			system("echo 999999 > /proc/rg/mcast_query_sec");
		}
#endif
	}
	else
	{
		// don't touch the DHCP server if mapping to bridge WAN
		for (i = 0; i < num; i++)
		{
			if (!mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&pvcEntry))
				continue;

			if (pvcEntry.enable == 0)
				continue;

			if (pvcEntry.cmode == CHANNEL_MODE_BRIDGE && pvcEntry.itfGroup != 0)
			{
				for (j = PMAP_ETH0_SW0; j <= PMAP_ETH0_SW3 && j < SW_LAN_PORT_NUM; ++j)
				{
					if (BIT_IS_SET(pvcEntry.itfGroup, j)) {
						#ifdef _LINUX_3_18_
						va_cmd(IPTABLES, 12, 1, (char *)FW_DEL, (char *)FW_INACC, "-m", "physdev", "--physdev-in", SW_LAN_PORT_IF[j], "-p", (char *)ARG_UDP, (char *)FW_DPORT, (char *)PORT_DHCP, "-j", (char *)FW_DROP);
#ifdef  CONFIG_00R0 //igmpProxy drop the IGMP report pkts from bridgeWan, IulianWu				
						va_cmd(IPTABLES, 10, 1, (char *)FW_DEL, (char *)FW_INACC, "-m", "physdev", "--physdev-in", SW_LAN_PORT_IF[j], "-d", "224.0.0.0/4", "-j", (char *)FW_DROP);
#endif	
						#else
						va_cmd(IPTABLES, 10, 1, (char *)FW_DEL, (char *)FW_INACC, (char *)ARG_I, SW_LAN_PORT_IF[j], "-p", (char *)ARG_UDP, (char *)FW_DPORT, (char *)PORT_DHCP, "-j", (char *)FW_DROP);
						#endif
					}
				}

#ifdef WLAN_SUPPORT
				for (j = PMAP_WLAN0; j <= PMAP_WLAN1_VAP3; ++j)
				{
					if (BIT_IS_SET(pvcEntry.itfGroup, j)) {
						#ifdef _LINUX_3_18_
						va_cmd(IPTABLES, 12, 1, (char *)FW_DEL, (char *)FW_INACC, "-m", "physdev", "--physdev-in", wlan[j - PMAP_WLAN0], "-p", (char *)ARG_UDP, (char *)FW_DPORT, (char *)PORT_DHCP, "-j", (char *)FW_DROP);
#ifdef CONFIG_00R0 //igmpProxy drop the IGMP report pkts from bridgeWan, IulianWu					
						va_cmd(IPTABLES, 10, 1, (char *)FW_DEL, (char *)FW_INACC, "-m", "physdev", "--physdev-in", wlan[j - PMAP_WLAN0], "-d", "224.0.0.0/4", "-j", (char *)FW_DROP);
#endif	
						#else
						va_cmd(IPTABLES, 10, 1, (char *)FW_DEL, (char *)FW_INACC, (char *)ARG_I, wlan[j - PMAP_WLAN0], "-p", (char *)ARG_UDP, (char *)FW_DPORT, (char *)PORT_DHCP, "-j", (char *)FW_DROP);
						#endif
					}
				}
#endif // WLAN_SUPPORT
			}
		}

#ifdef CONFIG_00R0
		system("echo 30 > /proc/rg/mcast_query_sec");
#endif
	}
}

int get_DefaultGWGroup()
{
	int i = 0, num = 0;
	MIB_CE_ATM_VC_T pvcEntry;
	num = mib_chain_total(MIB_ATM_VC_TBL);
	for (i = 0; i < num; i++)
	{
		if (!mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&pvcEntry))
			continue;

		if (isDefaultRouteWan(&pvcEntry)) // default gateway
		{
			return pvcEntry.itfGroupNum;
		}
	}

	return 0;
}

int rg_set_port_binding_mask(unsigned int set_wanlist)
{
	int i = 0, num = 0;
	MIB_CE_ATM_VC_T pvcEntry;
	char cmdStr[64] = {0};

	num = mib_chain_total(MIB_ATM_VC_TBL);
	for (i = 0; i < num; i++)
	{
		if ((set_wanlist & (1 << i)) != 0)
		{
			if (!mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&pvcEntry))
				continue;

			if (pvcEntry.enable == 0)
				continue;

			// reset omci wan info
			snprintf(cmdStr, sizeof(cmdStr), "echo %d %d %d %d %d %d %d > %s", pvcEntry.rg_wan_idx, 0, 0, 0, 0, 0, 0, OMCI_WAN_INFO);
			system(cmdStr);

			// only update wan_info.port_binding_mask.portmask and wan_info.wlan0_dev_binding_mask
			if (RG_add_wan(&pvcEntry, i) == -1)
			{
				fprintf(stderr, "[%s:%s@%d] RG_add_wan ERROR\n", __FILE__, __FUNCTION__, __LINE__);
				return -1;
			}
		}
	}

#ifdef CONFIG_00R0//iulian added cvlan for multicast 
			if(RG_WAN_CVLAN() < 0){
				printf("[%s:%s@%d] RG_WAN_CVLAN ERROR\n", __FILE__, __FUNCTION__, __LINE__);
				return -1;
			}
#endif
	return 0;
}

int set_port_binding_mask(unsigned int *wanlist)
{
	int i = 0, j = 0, num = 0, ifnum = 0, DefaultGWGroup = 0, change_num = 0, find_group_first_wan = 0, all_in_one_group = 0;
	unsigned int port_binding_mask = 0;
	struct itfInfo itfs[MAX_NUM_OF_ITFS];
	struct availableItfInfo itfList[MAX_NUM_OF_ITFS];
	MIB_CE_SW_PORT_T swportEntry;

	DefaultGWGroup = get_DefaultGWGroup();
#ifdef CONFIG_00R0
	int Available_num = 0;
	for (i = 0; i < IFGROUP_NUM; i++)
	{
		Available_num += get_group_ifinfo(itfs, MAX_NUM_OF_ITFS, i);
	}
#else
	int Available_num = get_AvailableInterface(itfList, MAX_NUM_OF_ITFS);
#endif
	*wanlist = 0;

	set_port_binding_rule(0);

	for (i = 0; i < IFGROUP_NUM; i++)
	{
		memset(itfs, 0, sizeof(itfs));
		ifnum = get_group_ifinfo(itfs, MAX_NUM_OF_ITFS, i);

		if (ifnum == 0)
			continue;

		if (ifnum == Available_num)
			all_in_one_group = 1;

		port_binding_mask = 0;
		find_group_first_wan = 0;

		// LAN Port
		for (j = PMAP_ETH0_SW0; j <= PMAP_ETH0_SW3 && j < SW_LAN_PORT_NUM; ++j)
		{
			if (!mib_chain_get(MIB_SW_PORT_TBL, j, &swportEntry))
				continue;

			if (swportEntry.itfGroup == i)
			{
				port_binding_mask |= (1 << j);
			}
		}

#ifdef WLAN_SUPPORT
		unsigned char vUChar = 0, wlgroup = 0;
		MIB_CE_MBSSIB_T mbssidEntry;
		int ori_wlan_idx;

		ori_wlan_idx = wlan_idx;
		wlan_idx = 0;

		for (j = PMAP_WLAN0; j <= PMAP_WLAN1_VAP3; j++)
		{
			if (wlan_en[j - PMAP_WLAN0] == 0)
				continue;

			if (j == PMAP_WLAN0)
			{
				mib_get(MIB_WLAN_DISABLED, &vUChar);
				if (vUChar == 0) {
					mib_get(MIB_WLAN_ITF_GROUP, &wlgroup);

					if (wlgroup == i)
					{
						port_binding_mask |= (1 << j);
					}
				}
			}

#ifdef WLAN_MBSSID
			if (j >= PMAP_WLAN0_VAP0 && j <= PMAP_WLAN0_VAP3)
			{
				if (!mib_chain_get(MIB_MBSSIB_TBL, (j - PMAP_WLAN0), &mbssidEntry) || mbssidEntry.wlanDisabled)
					continue;

				mib_get(MIB_WLAN_VAP0_ITF_GROUP + ((j - PMAP_WLAN0_VAP0) << 1), &wlgroup);
				if (wlgroup == i)
				{
					port_binding_mask |= (1 << j);
				}
			}
#endif

#if defined(CONFIG_RTL_92D_DMDP) || defined(WLAN_DUALBAND_CONCURRENT)
			if (j == PMAP_WLAN1)
			{
				mib_get(MIB_WLAN1_DISABLED, &vUChar);
				if (vUChar == 0) {
					mib_get(MIB_WLAN1_ITF_GROUP, &wlgroup);

					if (wlgroup == i)
					{
						port_binding_mask |= (1 << j);
					}
				}
			}

#ifdef WLAN_MBSSID
			if (j >= PMAP_WLAN1_VAP0 && j <= PMAP_WLAN1_VAP3)
			{
				if (!mib_chain_get(MIB_WLAN1_MBSSIB_TBL, (j - PMAP_WLAN1), &mbssidEntry) || mbssidEntry.wlanDisabled)
					continue;

				mib_get(MIB_WLAN1_VAP0_ITF_GROUP + ((j - PMAP_WLAN1_VAP0) << 1), &wlgroup);
				if (wlgroup == i)
				{
					port_binding_mask |= (1 << j);
				}
			}
#endif
#endif
		}
		wlan_idx = ori_wlan_idx;
#endif // WLAN_SUPPORT

		//fprintf(stderr, "\033[1;31m[%s:%s@%d]\033[0m  [Group%d] port_binding_mask=%d\n", __FILE__, __FUNCTION__, __LINE__, i, port_binding_mask);

		MIB_CE_ATM_VC_T pvcEntry;
		num = mib_chain_total(MIB_ATM_VC_TBL);
		for (j = 0; j < num; j++)
		{
			if (!mib_chain_get(MIB_ATM_VC_TBL, j, (void *)&pvcEntry))
				continue;

			if (pvcEntry.itfGroupNum == i && all_in_one_group == 1) // all interface in same group, set itfGroup to 0
			{
				if (pvcEntry.itfGroup != 0)
				{
					pvcEntry.itfGroup = 0;
					mib_chain_update(MIB_ATM_VC_TBL, (void *)&pvcEntry, j);
					change_num++;
					*wanlist |= (1 << j);
				}
				continue;
			}

			if (pvcEntry.itfGroupNum == DefaultGWGroup && !isDefaultRouteWan(&pvcEntry)) // default gateway group, only set default gateway itfGroup
			{
				if (pvcEntry.itfGroup != 0)
				{
					pvcEntry.itfGroup = 0;
					mib_chain_update(MIB_ATM_VC_TBL, (void *)&pvcEntry, j);
					change_num++;
					*wanlist |= (1 << j);
				}
				continue;
			}

			if (pvcEntry.itfGroupNum == i)
			{
				if (find_group_first_wan == 0)
				{
					find_group_first_wan = 1;
					if (pvcEntry.itfGroup != port_binding_mask)
					{
						pvcEntry.itfGroup = port_binding_mask;
						mib_chain_update(MIB_ATM_VC_TBL, (void *)&pvcEntry, j);
						change_num++;
						*wanlist |= (1 << j);
					}
				}
				else
				{
					if (pvcEntry.itfGroup != 0)
					{
						pvcEntry.itfGroup = 0;
						mib_chain_update(MIB_ATM_VC_TBL, (void *)&pvcEntry, j);
						change_num++;
						*wanlist |= (1 << j);
					}
				}
			}
		}
	}

	set_port_binding_rule(1);

	return change_num;
}

#ifdef CONFIG_00R0
void reset_VLANMapping()
{
	//ebtables -t broute -D BROUTING -j vlanbinding
	va_cmd(EBTABLES, 6, 1, "-t", "broute", (char *)FW_DEL, "BROUTING", "-j", (char *)VLAN_BIND);
	//ebtables -t broute -N vlanbinding
	va_cmd(EBTABLES, 4, 1, "-t", "broute", "-N", (char *)VLAN_BIND);
	//ebtables -t broute -P vlanbinding RETURN
	va_cmd(EBTABLES, 5, 1, "-t", "broute", "-P", (char *)VLAN_BIND, "RETURN");
	//ebtables -t broute -F vlanbinding
	va_cmd(EBTABLES, 4, 1, "-t", "broute", "-F", (char *)VLAN_BIND);
	//ebtables -t broute -A  BROUTING -j vlanbinding
	va_cmd(EBTABLES, 6, 1, "-t", "broute", "-A", "BROUTING", "-j", (char *)VLAN_BIND);
}

static int find_wanif_by_vlanid(unsigned short vid, MIB_CE_ATM_VC_T *vc_Entry)
{
	int j = 0, totalEntry = 0, ifIndex = 0;

	totalEntry = mib_chain_total(MIB_ATM_VC_TBL);
	for (j = 0; j < totalEntry; ++j)
	{
		mib_chain_get(MIB_ATM_VC_TBL, j, (void*)vc_Entry);
		if (vc_Entry->vlan && vc_Entry->vid == vid)
		{
			ifIndex	= (int)vc_Entry->ifIndex;

			return ifIndex;
		}
	}
	return -1;
}

void setup_VLANMapping(int ifidx, int enable)
{
	MIB_CE_PORT_BINDING_T pbEntry;
	struct vlan_pair *vid_pair;
	char str_vid_a[6] = {0};
	int j = 0;

	if (enable) {
		mib_chain_get(MIB_PORT_BINDING_TBL, ifidx, (void*)&pbEntry);
		vid_pair = (struct vlan_pair *)&pbEntry.pb_vlan0_a;
		for (j = 0; j < MAX_PAIR; j++) {
			if (vid_pair[j].vid_a) {
				int ifindex = 0;
				MIB_CE_ATM_VC_T vc_Entry;

				ifindex = find_wanif_by_vlanid(vid_pair[j].vid_b, &vc_Entry);

				if (ifindex < 0) {
					continue;
				}

				RG_add_vlanBinding(&vc_Entry, j, vid_pair[j].vid_a, ifidx);

				snprintf(str_vid_a, 6, "%d", vid_pair[j].vid_a);
				if (ifidx <= PMAP_ETH0_SW3 && ifidx < SW_LAN_PORT_NUM) {
					va_cmd(EBTABLES, 12, 1, "-t", "broute", "-A", VLAN_BIND, "-p", "8021q", "--vlan-id", str_vid_a, "-i", SW_LAN_PORT_IF[ifidx], "-j", "DROP");
				}
#ifdef WLAN_SUPPORT
				else {
					va_cmd(EBTABLES, 12, 1, "-t", "broute", "-A", VLAN_BIND, "-p", "8021q", "--vlan-id", str_vid_a, "-i", ELANIF, "-j", "DROP");
				}
#endif
			}
		}
	}
	else {
		mib_chain_get(MIB_PORT_BINDING_TBL, ifidx, (void*)&pbEntry);
		vid_pair = (struct vlan_pair *)&pbEntry.pb_vlan0_a;
		for (j = 0; j < MAX_PAIR; j++) {
			if (vid_pair[j].vid_a) {
				snprintf(str_vid_a, 6, "%d", vid_pair[j].vid_a);

				if (ifidx <= PMAP_ETH0_SW3 && ifidx < SW_LAN_PORT_NUM) {
					va_cmd(EBTABLES, 12, 1, "-t", "broute", "-D", VLAN_BIND, "-p", "8021q", "--vlan-id", str_vid_a, "-i", SW_LAN_PORT_IF[ifidx], "-j", "DROP");
				}
#ifdef WLAN_SUPPORT
				else {
					va_cmd(EBTABLES, 12, 1, "-t", "broute", "-D", VLAN_BIND, "-p", "8021q", "--vlan-id", str_vid_a, "-i", ELANIF, "-j", "DROP");
				}
#endif
			}
		}
		RG_flush_vlanBinding(ifidx);
	}
}

int setVLANByGroupnum(int groupnum, int enable, int vlan)
{
	struct itfInfo itfs[MAX_NUM_OF_ITFS];
	MIB_CE_PORT_BINDING_T pbEntry;
	unsigned int i = 0, ifnum = 0, ret = 0;

	ifnum = get_group_ifinfo(itfs, MAX_NUM_OF_ITFS, groupnum);

	if (ifnum > 0)
	{
		for (i = 0; i < ifnum; i++)
		{
			if (itfs[i].ifdomain == DOMAIN_ELAN)
			{
				if (itfs[i].ifid < ELANVIF_NUM) {
					mib_chain_get(MIB_PORT_BINDING_TBL, itfs[i].ifid, (void*)&pbEntry);

					setup_VLANMapping(itfs[i].ifid, 0);

					pbEntry.pb_vlan0_a = vlan;
					pbEntry.pb_vlan0_b = vlan;
					mib_chain_update(MIB_PORT_BINDING_TBL, (void *)&pbEntry, itfs[i].ifid);

					if (enable) {
						setup_VLANMapping(itfs[i].ifid, 1);
					}
				}
			}
			else if (itfs[i].ifdomain == DOMAIN_WAN)
			{
				continue;
			}
			else if (itfs[i].ifdomain == DOMAIN_WLAN)
			{
				mib_chain_get(MIB_PORT_BINDING_TBL, 4, (void*)&pbEntry);

				setup_VLANMapping(4, 0);

				pbEntry.pb_vlan0_a = vlan;
				pbEntry.pb_vlan0_b = vlan;
				mib_chain_update(MIB_PORT_BINDING_TBL, (void *)&pbEntry, 4);

				if (enable) {
					setup_VLANMapping(4, 1);
				}
			}
			else if (itfs[i].ifdomain == DOMAIN_ULAN)
			{
				continue;
			}
		}

		RTK_RG_Sync_OMCI_WAN_INFO();
	}

	return ret;
}

int getATMVCEntryandIDByIfindex(unsigned int ifindex, MIB_CE_ATM_VC_T *p, unsigned int *id)
{
	int ret = -1;
	unsigned int i = 0, num = 0;

	if ((ifindex == 0) || (p == NULL) || (id == NULL))
		return ret;

	num = mib_chain_total(MIB_ATM_VC_TBL);
	for (i = 0; i < num; i++)
	{
		if (!mib_chain_get(MIB_ATM_VC_TBL, i, (void*)p))
			continue;

		if (p->ifIndex == ifindex)
		{
			*id = i;
			ret = 0;
			break;
		}
	}
	return ret;
}

int getLayer2BrATMVCEntry(unsigned int ifdomain, unsigned int ifid, char *itfname, int groupnum, MIB_CE_ATM_VC_T *p, unsigned int *idx)
{
	int i = 0, num = 0, ret = 0;
	num = mib_chain_total(MIB_ATM_VC_TBL);

	//fprintf(stderr, "\033[1;31m[%s:%s@%d]\033[0m ifdomain = %d, ifid = %d, itfname = %s \n", __FILE__, __FUNCTION__, __LINE__, ifdomain, ifid, itfname);

	if (ifdomain == DOMAIN_WAN)
	{
		//fprintf(stderr, "\033[1;31m[%s:%s@%d]\033[0m DOMAIN_WAN\n", __FILE__, __FUNCTION__, __LINE__);
		// check how many L3 interface in this L2 interface
		int L3_Num = 0;
		char *pConDev = NULL;
		pConDev = itfname + strlen("WANConnectionDevice.");

		for (i = 0; i < num; i++)
		{
			if (!mib_chain_get(MIB_ATM_VC_TBL, i, (void*)p))
				continue;

			if (MEDIA_INDEX(p->ifIndex) == ifid && p->ConDevInstNum == atoi(pConDev) /*&& (p->ConPPPInstNum != 0 || p->ConIPInstNum != 0)*/) {
				L3_Num++;
			}
		}

		//fprintf(stderr, "\033[1;31m[%s:%s@%d]\033[0m L3_Num  = %d\n", __FILE__, __FUNCTION__, __LINE__, L3_Num);
		if (/*L3_Num == 1*/0)
		{
			for (i = 0; i < num; i++)
			{
				if (!mib_chain_get(MIB_ATM_VC_TBL, i, (void*)p))
					continue;

				if (MEDIA_INDEX(p->ifIndex) == ifid && p->ConDevInstNum == atoi(pConDev) && (p->ConPPPInstNum != 0 || p->ConIPInstNum != 0)) {
					//fprintf(stderr, "\033[1;31m[%s:%s@%d]\033[0m L3_Num  = %d, find MIB_ATM_VC_TBL.%d\n", __FILE__, __FUNCTION__, __LINE__, L3_Num, i);
					*idx = i;
					ret = 1;
					break;
				}
			}
		}
		else
		{
			// find automatic build bridge WAN
			for (i = 0; i < num; i++)
			{
				if (!mib_chain_get(MIB_ATM_VC_TBL, i, (void*)p))
					continue;

				if (MEDIA_INDEX(p->ifIndex) == ifid && p->ConDevInstNum == atoi(pConDev) && p->itfGroupNum == groupnum && (p->connDisable == 1 && p->ConPPPInstNum == 0 && p->ConIPInstNum == 0)) {
					//fprintf(stderr, "\033[1;31m[%s:%s@%d]\033[0m L3_Num  = %d, find automatic build MIB_ATM_VC_TBL.%d\n", __FILE__, __FUNCTION__, __LINE__, L3_Num, i);
					*idx = i;
					ret = 1;
					break;
				}
			}
		}
	}
	else if (ifdomain == DOMAIN_WANROUTERCONN)
	{
		//fprintf(stderr, "\033[1;31m[%s:%s@%d]\033[0m DOMAIN_WANROUTERCONN\n", __FILE__, __FUNCTION__, __LINE__);
		for (i = 0; i < num; i++)
		{
			if (!mib_chain_get(MIB_ATM_VC_TBL, i, (void*)p))
				continue;

			if (p->ifIndex == ifid)
			{
				*idx = i;
				ret = 1;
				break;
			}
		}
	}

	//fprintf(stderr, "\033[1;31m[%s:%s@%d]\033[0m ret  = %d\n", __FILE__, __FUNCTION__, __LINE__, ret);
	return ret;
}

unsigned int getNewIfIndex(int cmode, int my_condev_instnum, int media_type, int chainidx)
{
	int i;
	unsigned int if_index;
	MEDIA_TYPE_T mType;

	unsigned int totalEntry;
	MIB_CE_ATM_VC_T *pEntry, vc_entity;
	unsigned int map = 0;	// high half for PPP bitmap, low half for vc bitmap

	totalEntry = mib_chain_total(MIB_ATM_VC_TBL); /* get chain record size */

	for (i = 0; i < totalEntry; i++)
	{
		pEntry = &vc_entity;
		if (i == chainidx)
			continue;

		if (mib_chain_get(MIB_ATM_VC_TBL, i, (void*)pEntry)) /* get the specified chain record */
		{
			mType = MEDIA_INDEX(pEntry->ifIndex);

			if((mType != media_type) ||
				(pEntry->ConDevInstNum != my_condev_instnum) ||
				(pEntry->cmode != cmode) ||
				(pEntry->ConIPInstNum==0 && pEntry->ConPPPInstNum==0 && pEntry->connDisable == 1))//auto added bridge WAN
			{
				if (mType == MEDIA_ETH)
					map |= 1 << ETH_INDEX(pEntry->ifIndex);	// vc map
				else if (mType == MEDIA_ATM)
					map |= 1 << VC_INDEX(pEntry->ifIndex);	// vc map
#ifdef CONFIG_PTMWAN
				else if (mType == MEDIA_PTM)
					map |= 1 << PTM_INDEX(pEntry->ifIndex);	// vc map
#endif /*CONFIG_PTMWAN*/

				map |= (1 << 16) << PPP_INDEX(pEntry->ifIndex);	// PPP map
			}
		}
	}

	if_index = if_find_index(cmode, map);
	if ((if_index == NA_VC) || (if_index == NA_PPP))
		return if_index;

	if (media_type == MEDIA_ETH)
		if_index = TO_IFINDEX(MEDIA_ETH, PPP_INDEX(if_index), ETH_INDEX(if_index));
#ifdef CONFIG_PTMWAN
	if (media_type == MEDIA_PTM)
		if_index = TO_IFINDEX(MEDIA_PTM, PPP_INDEX(if_index), PTM_INDEX(if_index));
#endif /*CONFIG_PTMWAN*/

	return if_index;
}

int update_Layer2Br_bridge_WAN(char *type, unsigned int ifdomain, unsigned int ifid, char *itfname, int groupnum)
{
	//fprintf(stderr, "\033[1;31m[%s:%s@%d]\033[0m type = %s, ifdomain = %d, ifid = %d, itfname = %s groupnum = %d\n", __FILE__, __FUNCTION__, __LINE__, type, ifdomain, ifid, itfname, groupnum);

	int i = 0, total = 0;
	int F_L3WAN_num = 0, F_L2WAN_num = 0, M_L2WAN_num = 0;
	char *pConDev = NULL;
	pConDev = itfname + strlen("WANConnectionDevice.");
	MIB_CE_ATM_VC_T *pEntry, vc_entity;
	pEntry = &vc_entity;

	MIB_L2BRIDGE_FILTER_T *fp, fentry;
	fp = &fentry;

	MIB_L2BRIDGE_MARKING_T *mp, mentry;
	mp = &mentry;

	total = mib_chain_total(MIB_L2BRIDGING_FILTER_TBL);
	for (i = 0; i < total; i++)
	{
		if (!mib_chain_get(MIB_L2BRIDGING_FILTER_TBL, i, (void *)fp))
			continue;

		// check this group's L3 WAN Filter
		if (fp->groupnum == groupnum)
		{
			if (fp->enable == 1 && fp->ifdomain == DOMAIN_WANROUTERCONN)
			{
				F_L3WAN_num++;
			}
		}
	}

	if (strcmp(type, "Filter") == 0)
	{
		if (ifdomain == DOMAIN_WAN)
		{
			// automatic build bridge WAN if need
			int j = 0, total = 0;
			total = mib_chain_total(MIB_L2BRIDGING_MARKING_TBL);

			for (j = 0; j < total; j++)
			{
				if (!mib_chain_get(MIB_L2BRIDGING_MARKING_TBL, j, (void *)mp))
					continue;

				if (mp->ifdomain == DOMAIN_WAN)
				{
					if (mp->ifid == ifid && strcmp(mp->itfname, itfname) == 0 && mp->groupnum == groupnum) 
					{
						M_L2WAN_num++;
					}
				}
			}

			//fprintf(stderr, "\033[1;31m[%s:%s@%d]\033[0m M_L2WAN_num = %d, F_L3WAN_num = %d\n", __FILE__, __FUNCTION__, __LINE__, M_L2WAN_num, F_L3WAN_num);
			if (M_L2WAN_num > 0 && F_L3WAN_num == 0)
			{
				unsigned int new_ifindex;
				memset(&vc_entity, 0, sizeof(vc_entity));
				new_ifindex = getNewIfIndex(CHANNEL_MODE_BRIDGE, 1, MEDIA_ETH, -1);
				//fprintf(stderr, "\033[1;31m[%s:%s@%d]\033[0m new_ifindex = %d, MEDIA_INDEX(new_ifindex) = %d, ifid = %d\n", __FILE__, __FUNCTION__, __LINE__, new_ifindex, MEDIA_INDEX(new_ifindex), ifid);
				if ((new_ifindex == NA_VC)) {
					//fprintf(stderr, "\033[1;31m[%s:%s@%d]\033[0m new_ifindex = NA_VC\n", __FILE__, __FUNCTION__, __LINE__);
					return -1;
				}

				pEntry->enable = 1;
				pEntry->ifIndex = new_ifindex;
				pEntry->mtu = 1500;
				// connDisable == 1, ConIPInstNum == 0 and ConPPPInstNum == 0, it is automatic build bridge WAN
				pEntry->connDisable = 1; // do not show in TR-069
				pEntry->ConDevInstNum = atoi(pConDev);
				pEntry->ConIPInstNum = 0;
				pEntry->ConPPPInstNum = 0;
				pEntry->applicationtype = X_CT_SRV_OTHER;
				pEntry->cmode = CHANNEL_MODE_BRIDGE;
				pEntry->brmode = BRIDGE_DISABLE;

#ifdef CONFIG_IPV6
				pEntry->IpProtocol=IPVER_IPV4;//ipv4 as default
#endif /*CONFIG_IPV6*/
#if defined(CONFIG_LUNA) && defined(GEN_WAN_MAC)
				{
					char macaddr[MAC_ADDR_LEN] = {0};
					mib_get(MIB_ELAN_MAC_ADDR, (void *)macaddr);
					macaddr[MAC_ADDR_LEN-1] += 3 + ETH_INDEX(pEntry->ifIndex);
					memcpy(pEntry->MacAddr, macaddr, MAC_ADDR_LEN);
				}
#endif

				pEntry->itfGroupNum = groupnum;

				mib_chain_add(MIB_ATM_VC_TBL, pEntry);
			}
		}
		else if (ifdomain == DOMAIN_WANROUTERCONN)
		{
			// add L3 interface into this group, so remove the automatic build bridge WAN if it is existed
			total = mib_chain_total(MIB_ATM_VC_TBL);
			for (i = 0; i < total; i++)
			{
				if (!mib_chain_get(MIB_ATM_VC_TBL, i, (void*)pEntry))
					continue;

				if (pEntry->itfGroupNum == groupnum && (pEntry->connDisable == 1 && pEntry->ConPPPInstNum == 0 && pEntry->ConIPInstNum == 0))
				{
					//fprintf(stderr, "\033[1;31m[%s:%s@%d]\033[0m remove MIB_ATM_VC_TBL.%d\n", __FILE__, __FUNCTION__, __LINE__, i);
#ifdef _PRMT_X_TELEFONICA_ES_DHCPOPTION_
					if ((pEntry->cmode == CHANNEL_MODE_IPOE) && (pEntry->ipDhcp == DHCP_CLIENT))
						delDhcpcOption(pEntry->ifIndex);
#endif
#ifdef NEW_IP_QOS_SUPPORT
					delIpQosTcRule(pEntry);
#endif
					deleteConnection(CONFIGONE, pEntry);
					resolveServiceDependency(i);
					mib_chain_delete(MIB_ATM_VC_TBL, i);
					break;
				}
			}
		}
	}
	else if (strcmp(type, "Marking") == 0)
	{
		if (ifdomain == DOMAIN_WAN)
		{
			// automatic build bridge WAN if need
			int j = 0, total = 0;
			total = mib_chain_total(MIB_L2BRIDGING_FILTER_TBL);

			for (j = 0; j < total; j++)
			{
				if (!mib_chain_get(MIB_L2BRIDGING_FILTER_TBL, j, (void *)fp))
					continue;

				if (fp->ifdomain == DOMAIN_WAN)
				{
					if (fp->ifid == ifid && strcmp(fp->itfname, itfname) == 0 && fp->groupnum == groupnum) 
					{
						F_L2WAN_num++;
					}
				}
			}

			//fprintf(stderr, "\033[1;31m[%s:%s@%d]\033[0m F_L2WAN_num = %d, F_L3WAN_num = %d\n", __FILE__, __FUNCTION__, __LINE__, F_L2WAN_num, F_L3WAN_num);
			if (F_L2WAN_num > 0 && F_L3WAN_num == 0)
			{
				unsigned int new_ifindex;
				memset(&vc_entity, 0, sizeof(vc_entity));
				new_ifindex = getNewIfIndex(CHANNEL_MODE_BRIDGE, 1, MEDIA_ETH, -1);
				//fprintf(stderr, "\033[1;31m[%s:%s@%d]\033[0m new_ifindex = %d, MEDIA_INDEX(new_ifindex) = %d, ifid = %d\n", __FILE__, __FUNCTION__, __LINE__, new_ifindex, MEDIA_INDEX(new_ifindex), ifid);
				if ((new_ifindex == NA_VC)) {
					//fprintf(stderr, "\033[1;31m[%s:%s@%d]\033[0m new_ifindex = NA_VC\n", __FILE__, __FUNCTION__, __LINE__);
					return -1;
				}

				pEntry->enable = 1;
				pEntry->ifIndex = new_ifindex;
				pEntry->mtu = 1500;
				// connDisable == 1, ConIPInstNum == 0 and ConPPPInstNum == 0, it is automatic build bridge WAN
				pEntry->connDisable = 1; // do not show in TR-069
				pEntry->ConDevInstNum = atoi(pConDev);
				pEntry->ConIPInstNum = 0;
				pEntry->ConPPPInstNum = 0;
				pEntry->applicationtype = X_CT_SRV_OTHER;
				pEntry->cmode = CHANNEL_MODE_BRIDGE;
				pEntry->brmode = BRIDGE_DISABLE;

#ifdef CONFIG_IPV6
				pEntry->IpProtocol=IPVER_IPV4;//ipv4 as default
#endif /*CONFIG_IPV6*/
#if defined(CONFIG_LUNA) && defined(GEN_WAN_MAC)
				{
					char macaddr[MAC_ADDR_LEN] = {0};
					mib_get(MIB_ELAN_MAC_ADDR, (void *)macaddr);
					macaddr[MAC_ADDR_LEN-1] += 3 + ETH_INDEX(pEntry->ifIndex);
					memcpy(pEntry->MacAddr, macaddr, MAC_ADDR_LEN);
				}
#endif

				pEntry->itfGroupNum = groupnum;

				mib_chain_add(MIB_ATM_VC_TBL, pEntry);
			}
		}
	}
}

int setup_Layer2BrFilter(int idx)
{
	MIB_L2BRIDGE_FILTER_T *p, entry;
	p = &entry;

	if (mib_chain_get(MIB_L2BRIDGING_FILTER_TBL, idx, (void *)p))
	{
		//fprintf(stderr, "\033[1;31m[%s:%s@%d]\033[0m [L2BRIDGING_FILTER_TBL.%d]\n", __FILE__, __FUNCTION__, __LINE__, idx);
		if (p->ifdomain == DOMAIN_WAN || p->ifdomain == DOMAIN_WANROUTERCONN)
		{
			// check automatic build bridge WAN for this group
			update_Layer2Br_bridge_WAN("Filter", p->ifdomain, p->ifid, p->itfname, p->groupnum);

			MIB_CE_ATM_VC_T wanEntry;
			int vcchainid = 0;
			if (getLayer2BrATMVCEntry(p->ifdomain, p->ifid, p->itfname, p->groupnum, &wanEntry, &vcchainid) == 1)
			{
				setup_bridge_grouping(DEL_RULE);

				if (p->enable == 0) // disable this filter, set it to default group
				{
					wanEntry.itfGroupNum = 0;

					// sync default group's marking, todo
				}
				else
				{
					wanEntry.itfGroupNum = p->groupnum;

					// sync new group's marking
					int j = 0, total = 0, match = 0;
					MIB_L2BRIDGE_MARKING_T *mp, mentry;
					mp = &mentry;
					total = mib_chain_total(MIB_L2BRIDGING_MARKING_TBL);
					for (j = 0; j < total; j++)
					{
						if (!mib_chain_get(MIB_L2BRIDGING_MARKING_TBL, j, (void *)mp))
							continue;

						if (mp->ifdomain == DOMAIN_WAN)
						{
							char *pConDev = NULL;
							pConDev = mp->itfname + strlen("WANConnectionDevice.");

							if (mp->groupnum == p->groupnum && MEDIA_INDEX(wanEntry.ifIndex) == mp->ifid && wanEntry.ConDevInstNum == atoi(pConDev)) 
							{
								match = 1;
								break;
							}
						}
					}

					//fprintf(stderr, "\033[1;31m[%s:%s@%d]\033[0m match = %d, MIB_L2BRIDGING_MARKING_TBL.%d\n", __FILE__, __FUNCTION__, __LINE__, match, j);
					if (match)
					{
						wanEntry.vlan = mp->enable;
						if (mp->enable == 0)
						{
							wanEntry.vid = 0;
							wanEntry.vprio = 0;
						}
						else
						{
							if (mp->vid == -1)
							{
								wanEntry.vlan = 0;
								wanEntry.vid = 0;
							}
							else
							{
								wanEntry.vid = mp->vid;
							}

							wanEntry.vprio = mp->vprio + 1;
						}
					}
				}

				mib_chain_update(MIB_ATM_VC_TBL, (void *)&wanEntry, vcchainid);

				setup_bridge_grouping(ADD_RULE);
#ifdef CONFIG_RTK_L34_ENABLE // Rostelecom, Port Binding function
				unsigned int set_wanlist = 0;

				if (set_port_binding_mask(&set_wanlist) > 0)
				{
					rg_set_port_binding_mask(set_wanlist);
				}
				// update DNS info
				int sys_pid = -1;
				sys_pid = read_pid("/var/run/systemd.pid");
				if (sys_pid > 0) {
					kill(sys_pid, SIGUSR1);
					sleep(1);	//wait a second for DNS updating
				}
				RTK_RG_Sync_OMCI_WAN_INFO();
#endif
			}
		}
		else
		{
			int swNum = mib_chain_total(MIB_SW_PORT_TBL);
#ifdef CONFIG_00R0
			if (p->ifdomain == DOMAIN_ELAN && p->ifid == swNum*2)
				return 0;
#endif
			char list[512] = {0};
			setup_bridge_grouping(DEL_RULE);
#if 0//def CONFIG_RTK_L34_ENABLE // Rostelecom, Port Binding function
			MIB_CE_PORT_BINDING_T pbEntry;
			MIB_L2BRIDGE_GROUP_T *gp, gentry;
			gp = &gentry;
			int j = 0, total = 0;
			total = mib_chain_total(MIB_L2BRIDGING_BRIDGE_GROUP_TBL);
			for (j = 0; j < total; j++)
			{
				if (!mib_chain_get(MIB_L2BRIDGING_BRIDGE_GROUP_TBL, j, (void *)gp))
					continue;

				if (gp->groupnum == p->groupnum) 
				{
					break;
				}
			}

			if (p->ifdomain == DOMAIN_ELAN)
			{
				mib_chain_get(MIB_PORT_BINDING_TBL, p->ifid, (void*)&pbEntry);
				setup_VLANMapping(p->ifid, 0);
				if (p->enable == 1) {
					pbEntry.pb_vlan0_a = gp->vlanid;
					pbEntry.pb_vlan0_b = gp->vlanid;
					mib_chain_update(MIB_PORT_BINDING_TBL, (void *)&pbEntry, p->ifid);
					setup_VLANMapping(p->ifid, 1);
				}
			}
			else if (p->ifdomain == DOMAIN_WLAN)
			{
				mib_chain_get(MIB_PORT_BINDING_TBL, 4, (void*)&pbEntry);
				setup_VLANMapping(4, 0);
				if (p->enable == 1) {
					pbEntry.pb_vlan0_a = gp->vlanid;
					pbEntry.pb_vlan0_b = gp->vlanid;
					mib_chain_update(MIB_PORT_BINDING_TBL, (void *)&pbEntry, 4);
					setup_VLANMapping(4, 1);
				}
			}
#endif

			snprintf(list, 64, "%u,", IF_ID(p->ifdomain, p->ifid));
			if (p->enable == 0) // disable this filter, set it to default group
				setgroup(list, 0);
			else
				setgroup(list, p->groupnum);

			setup_bridge_grouping(ADD_RULE);
#ifdef CONFIG_RTK_L34_ENABLE // Rostelecom, Port Binding function
			unsigned int set_wanlist = 0;

			if (set_port_binding_mask(&set_wanlist) > 0)
			{
				rg_set_port_binding_mask(set_wanlist);
			}
			// update DNS info
			int sys_pid = -1;
			sys_pid = read_pid("/var/run/systemd.pid");
			if (sys_pid > 0) {
				kill(sys_pid, SIGUSR1);
				sleep(1);	//wait a second for DNS updating
			}
			RTK_RG_Sync_OMCI_WAN_INFO();
#endif
		}
	}

	return 0;
}

int setup_Layer2BrMarking(int idx)
{
	int i = 0, num = 0;
	MIB_L2BRIDGE_MARKING_T *p, entry;
	p = &entry;

	if (mib_chain_get(MIB_L2BRIDGING_MARKING_TBL, idx, (void *)p))
	{
		//fprintf(stderr, "\033[1;31m[%s:%s@%d]\033[0m [L2BRIDGING_MARKING_TBL.%d]\n", __FILE__, __FUNCTION__, __LINE__, idx);
		if (p->ifdomain == DOMAIN_WAN)
		{
			// check automatic build bridge WAN for this group
			update_Layer2Br_bridge_WAN("Marking", p->ifdomain, p->ifid, p->itfname, p->groupnum);

			MIB_CE_ATM_VC_T wanEntry;
			int vcchainid = 0;
			char *pConDev = NULL;
			pConDev = p->itfname + strlen("WANConnectionDevice.");
			num = mib_chain_total(MIB_ATM_VC_TBL);

			// sync marking info in this group
			for (i = 0; i < num; i++)
			{
				if (!mib_chain_get(MIB_ATM_VC_TBL, i, &wanEntry))
					continue;

				//fprintf(stderr, "\033[1;31m[%s:%s@%d]\033[0m [ATM_VC_TBL.%d]\n", __FILE__, __FUNCTION__, __LINE__, i);
				//fprintf(stderr, "\033[1;31m[%s:%s@%d]\033[0m wanEntry.itfGroupNum = %d, p->groupnum = %d\n", __FILE__, __FUNCTION__, __LINE__, wanEntry.itfGroupNum, p->groupnum);
				//fprintf(stderr, "\033[1;31m[%s:%s@%d]\033[0m MEDIA_INDEX(wanEntry.ifIndex) = %d, p->ifid = %d\n", __FILE__, __FUNCTION__, __LINE__, MEDIA_INDEX(wanEntry.ifIndex), p->ifid);
				//fprintf(stderr, "\033[1;31m[%s:%s@%d]\033[0m wanEntry.ConDevInstNum = %d, atoi(pConDev) = %d\n", __FILE__, __FUNCTION__, __LINE__, wanEntry.ConDevInstNum, atoi(pConDev));
				if (wanEntry.itfGroupNum == p->groupnum && MEDIA_INDEX(wanEntry.ifIndex) == p->ifid && wanEntry.ConDevInstNum == atoi(pConDev))
				{
					//fprintf(stderr, "\033[1;31m[%s:%s@%d]\033[0m Update [ATM_VC_TBL.%d] Marking info\n", __FILE__, __FUNCTION__, __LINE__, i);
					wanEntry.vlan = p->enable;
					if (p->enable == 0)
					{
						wanEntry.vid = 0;
						wanEntry.vprio = 0;
					}
					else
					{
						if (p->vid == -1)
						{
							wanEntry.vlan = 0;
							wanEntry.vid = 0;
						}
						else
						{
							wanEntry.vid = p->vid;
						}

						wanEntry.vprio = p->vprio + 1;
					}

					mib_chain_update(MIB_ATM_VC_TBL, (void *)&wanEntry, i);
				}
			}
		}
#ifdef CONFIG_00R0
		else if (p->ifdomain == DOMAIN_WANROUTERCONN)
		{
			MIB_CE_ATM_VC_T wanEntry;

			num = mib_chain_total(MIB_ATM_VC_TBL);
			for (i = 0; i < num; i++)
			{
				if (!mib_chain_get(MIB_ATM_VC_TBL, i, &wanEntry))
					continue;

				if (wanEntry.ifIndex == p->ifid)
				{
					setup_bridge_grouping(DEL_RULE);
					wanEntry.itfGroupNum = p->groupnum;

					wanEntry.vlan = p->enable;
					if (p->enable == 0)
					{
						wanEntry.vid = 0;
						wanEntry.vprio = 0;
					}
					else
					{
						if (p->vid == -1)
						{
							wanEntry.vlan = 0;
							wanEntry.vid = 0;
						}
						else
						{
							wanEntry.vid = p->vid;
						}

						wanEntry.vprio = p->vprio + 1;
					}
				}

				mib_chain_update(MIB_ATM_VC_TBL, (void *)&wanEntry, i);
				
				setup_bridge_grouping(ADD_RULE);
#ifdef CONFIG_RTK_L34_ENABLE // Rostelecom, Port Binding function
				unsigned int set_wanlist = 0;

				if (set_port_binding_mask(&set_wanlist) > 0)
				{
					rg_set_port_binding_mask(set_wanlist);
				}
				// update DNS info
				int sys_pid = -1;
				sys_pid = read_pid("/var/run/systemd.pid");
				if (sys_pid > 0) {
					kill(sys_pid, SIGUSR1);
					sleep(1);	//wait a second for DNS updating
				}
				RTK_RG_Sync_OMCI_WAN_INFO();
#endif

				break;
			}
		}
#endif
	}

	return 0;
}
#endif //end of CONFIG_00R0
#endif

int get_AvailableInterface(struct availableItfInfo *info, int len)
{
#if defined(ITF_GROUP_4P) || defined(CONFIG_RTL_8676HWNAT) || defined(CONFIG_APOLLO_ROMEDRIVER)
	unsigned int swNum;
	char strlan[] = "LAN0";
	MIB_CE_SW_PORT_T Entry;
#endif
	unsigned int vcNum;
	int i, num;
	unsigned char mygroup;
	MIB_CE_ATM_VC_T pvcEntry;
#if defined(WLAN_SUPPORT) || defined(WLAN_MBSSID)
	int ori_wlan_idx;
#endif
#if defined(WLAN_SUPPORT) && !defined(CONFIG_00R0)
	unsigned char vUChar;
#endif
#ifdef WLAN_MBSSID
	MIB_CE_MBSSIB_T mbssidEntry;
#endif

	num = 0;
#if defined(ITF_GROUP_4P) || defined(CONFIG_RTL_8676HWNAT) || defined(CONFIG_APOLLO_ROMEDRIVER)
	// LAN ports
	swNum = mib_chain_total(MIB_SW_PORT_TBL);
	for (i = 0; i < ELANVIF_NUM; i++) {
		if (!mib_chain_get(MIB_SW_PORT_TBL, i, &Entry))
			continue;

		strlan[3] = '0' + virt2user[i];	// LAN1, LAN2, LAN3, LAN4
		info[num].ifdomain = DOMAIN_ELAN;
		info[num].ifid = i;
		strncpy(info[num].name, strlan, sizeof(info[num].name));
		info[num].itfGroup = Entry.itfGroup;
		if (++num >= len)
			return num;

#ifdef CONFIG_USER_VLAN_ON_LAN		
		strlan[3] = '0' + virt2user[i];	// LAN1, LAN2, LAN3, LAN4
		info[num].ifdomain = DOMAIN_ELAN;
		info[num].ifid = i + swNum;
		snprintf(info[num].name, sizeof(info[num].name), "%s.%hu", strlan, Entry.vid);
		info[num].itfGroup = Entry.vlan_on_lan_itfGroup;
		if (++num >= len)
			return num;
#endif
	}

#ifdef CONFIG_00R0
	info[num].ifdomain = DOMAIN_ELAN;
	info[num].ifid = swNum*2;
	sprintf(info[num].name, "LANIPInterface");
	info[num].itfGroup = 0;
	if (++num >= len)
		return num;
#endif
#endif

#ifdef WLAN_SUPPORT
#ifdef CONFIG_00R0	
	ori_wlan_idx = wlan_idx;
	wlan_idx = 0;		// Magician: mib_get will add wlan_idx to mib id. Therefore wlan_idx must be set to 0.

#if defined(CONFIG_RTL_92D_DMDP) || defined(WLAN_DUALBAND_CONCURRENT)
	// wlan1
	mib_get(MIB_WLAN1_ITF_GROUP, &mygroup);
	info[num].ifdomain = DOMAIN_WLAN;
	info[num].ifid = 10;
	strncpy(info[num].name, (char *)WLANIF[1], sizeof(info[num].name));
	info[num].itfGroup = mygroup;
	if (++num >= len)
		return num;

#ifdef WLAN_MBSSID
	for (i = 0; i < WLAN_MBSSID_NUM; i++) {
		if (!mib_chain_get(MIB_WLAN1_MBSSIB_TBL, i + 1, &mbssidEntry))
			continue;

		// only 4 SSIDs in the 2.4G/5G band
		if (i > 2)
			break;

		mib_get(MIB_WLAN1_VAP0_ITF_GROUP + (i << 1), &mygroup);
		info[num].ifdomain = DOMAIN_WLAN;
		info[num].ifid = i + 11;
		sprintf(info[num].name, "wlan1-vap%d", i);
		info[num].itfGroup = mygroup;
		if (++num >= len)
			return num;
	}
#endif // WLAN_MBSSID
#endif

	// wlan0
	mib_get(MIB_WLAN_ITF_GROUP, &mygroup);
	info[num].ifdomain = DOMAIN_WLAN;
	info[num].ifid = 0;
	strncpy(info[num].name, (char *)WLANIF[0], sizeof(info[num].name));
	info[num].itfGroup = mygroup;
	if (++num >= len)
		return num;

#ifdef WLAN_MBSSID
	for (i = 0; i < WLAN_MBSSID_NUM; i++) {
		if (!mib_chain_get(MIB_MBSSIB_TBL, i + 1, &mbssidEntry))
			continue;

		// only 4 SSIDs in the 2.4G/5G band
		if (i > 2)
			break;

		mib_get(MIB_WLAN_VAP0_ITF_GROUP + (i << 1), &mygroup);
		info[num].ifdomain = DOMAIN_WLAN;
		info[num].ifid = i + 1;
		sprintf(info[num].name, "wlan0-vap%d", i);
		info[num].itfGroup = mygroup;
		if (++num >= len)
			return num;
	}
#endif // WLAN_MBSSID
#else
	// wlan0
	ori_wlan_idx = wlan_idx;
	wlan_idx = 0;		// Magician: mib_get will add wlan_idx to mib id. Therefore wlan_idx must be set to 0.

	mib_get(MIB_WLAN_DISABLED, &vUChar);
	if (vUChar == 0) {
		mib_get(MIB_WLAN_ITF_GROUP, &mygroup);
		info[num].ifdomain = DOMAIN_WLAN;
		info[num].ifid = 0;
		strncpy(info[num].name, (char *)WLANIF[0], sizeof(info[num].name));
		info[num].itfGroup = mygroup;
		if (++num >= len)
			return num;
	}

	// wlan1
#if defined(CONFIG_RTL_92D_DMDP) || defined(WLAN_DUALBAND_CONCURRENT)
	mib_get(MIB_WLAN1_DISABLED, &vUChar);
	if (vUChar == 0) {
		mib_get(MIB_WLAN1_ITF_GROUP, &mygroup);
		info[num].ifdomain = DOMAIN_WLAN;
		info[num].ifid = 10;
		strncpy(info[num].name, (char *)WLANIF[1], sizeof(info[num].name));
		info[num].itfGroup = mygroup;
		if (++num >= len)
			return num;
	}
#endif

#ifdef WLAN_MBSSID
	for (i = 0; i < IFGROUP_NUM - 1; i++) {
		if (!mib_chain_get(MIB_MBSSIB_TBL, i + 1, &mbssidEntry) ||
				mbssidEntry.wlanDisabled)
			continue;

		mib_get(MIB_WLAN_VAP0_ITF_GROUP + (i << 1), &mygroup);
		info[num].ifdomain = DOMAIN_WLAN;
		info[num].ifid = i + 1;
		sprintf(info[num].name, "wlan0-vap%d", i);
		info[num].itfGroup = mygroup;
		if (++num >= len)
			return num;
	}

#if defined(CONFIG_RTL_92D_DMDP) || defined(WLAN_DUALBAND_CONCURRENT)
	for (i = 0; i < IFGROUP_NUM - 1; i++) {
		if (!mib_chain_get(MIB_WLAN1_MBSSIB_TBL, i + 1, &mbssidEntry) ||
				mbssidEntry.wlanDisabled)
			continue;

		mib_get(MIB_WLAN1_VAP0_ITF_GROUP + (i << 1), &mygroup);
		info[num].ifdomain = DOMAIN_WLAN;
		info[num].ifid = i + 11;
		sprintf(info[num].name, "wlan1-vap%d", i);
		info[num].itfGroup = mygroup;
		if (++num >= len)
			return num;
	}
#endif
#endif // WLAN_MBSSID
#endif // CONFIG_00R0
	wlan_idx = ori_wlan_idx;
#endif // WLAN_SUPPORT

#ifdef CONFIG_USB_ETH
	// usb0
	mib_get(MIB_USBETH_ITF_GROUP, &mygroup);
	info[num].ifdomain = DOMAIN_ULAN;
	info[num].ifid = 0;
	strncpy(info[num].name, (char *)USBETHIF, sizeof(info[num].name));
	info[num].itfGroup = mygroup;
	if (++num >= len)
		return num;
#endif

	// vc
	vcNum = mib_chain_total(MIB_ATM_VC_TBL);

	for (i = 0; i < vcNum; i++) {
		if (!mib_chain_get(MIB_ATM_VC_TBL, i, &pvcEntry)) {
			printf("Get chain record error!\n");
			continue;
		}

		if (pvcEntry.enable == 0
		    || !isValidMedia(pvcEntry.ifIndex)
#ifdef CONFIG_00R0
		    || (pvcEntry.connDisable == 1 && pvcEntry.ConPPPInstNum == 0 && pvcEntry.ConIPInstNum == 0) // skip the automatic build bridge WAN
#endif
#ifdef CONFIG_RTK_L34_ENABLE // Rostelecom, Port Binding function
#else
		    || ( pvcEntry.cmode != CHANNEL_MODE_BRIDGE && pvcEntry.brmode == BRIDGE_DISABLE)
#endif
		    )
			continue;

		info[num].ifdomain = DOMAIN_WAN;
		info[num].ifid = pvcEntry.ifIndex;
		ifGetName(pvcEntry.ifIndex, info[num].name, sizeof(info[num].name));
		info[num].itfGroup = pvcEntry.itfGroupNum;
		if (++num >= len)
			return num;
	}

	return num;
}

int setup_bridge_grouping(int mode)
{
	unsigned char grpnum;
	int i, ifnum, ret, status = 0;
	struct itfInfo itfs[MAX_NUM_OF_ITFS];
	char brif[] = "br0";
	unsigned char vUChar;
	unsigned short vUShort;
	char str[16];
	MIB_CE_ATM_VC_T Entry;

#ifdef CONFIG_RTK_L34_ENABLE // Rostelecom, Port Binding function
	// do nothing
#else
	if (mode == ADD_RULE) {
		for (grpnum = 0; grpnum <= 4; grpnum++) {
			ifnum = get_group_ifinfo(itfs, MAX_NUM_OF_ITFS, grpnum);
			if (ifnum <= 0)
				continue;

			// default group (grpnum == 0) should not be "addbr" here
			if (grpnum == 0)
				goto step_3;

			brif[2] = '0' + grpnum;

			// (1) use brctl to create bridge interface
			// brctl addbr br[1-4]
			status |= va_cmd(BRCTL, 2, 1, "addbr", brif);

			// ifconfig br[1-4] hw ether "macaddr"
			if (getMIB2Str(MIB_ELAN_MAC_ADDR, str) == 0)
				status |= va_cmd(IFCONFIG, 4, 1, brif, "hw", "ether", str);

			if (mib_get(MIB_BRCTL_STP, &vUChar)) {
				if (vUChar) {
					// stp on
					// brctl stp br[1-4] on
					status |= va_cmd(BRCTL, 3, 1, "stp",
						   brif, "on");
				} else {
					// stp off
					// brctl stp br[1-4] off
					status |= va_cmd(BRCTL, 3, 1, "stp",
						   brif, "off");

					// brctl setfd br[1-4] 1
					// if forwarding_delay=0, fdb_get may fail in serveral seconds after booting
					status |= va_cmd(BRCTL, 3, 1, "setfd",
						   brif, "1");
				}
			}

			// brctl setageing br[1-4] ageingtime
			if (mib_get(MIB_BRCTL_AGEINGTIME, &vUShort)) {
				snprintf(str, sizeof(str), "%hu", vUShort);
				status |= va_cmd(BRCTL, 3, 1, "setageing",
					   brif, str);
			}

			// (2) use ifconfig to up interface
			// ifconfig br[1-4] up
			status |= va_cmd(IFCONFIG, 2, 1, brif, "up");
step_3:
			// (3) for all interfaces in grpnum, remove from br0, add to br[0-4]
			for (i = 0; i < ifnum; i++) {
				if (itfs[i].ifdomain == DOMAIN_WAN
					&& getATMVCEntryByIfIndex(itfs[i].ifid, &Entry)) {
				// skip when brpnum is 0 (br0) and itfs[i] is non-bridged-mode WAN
					//if (grpnum == 0 && Entry.cmode != ADSL_BR1483)
					if (grpnum == 0 && (Entry.cmode != CHANNEL_MODE_BRIDGE && Entry.brmode == BRIDGE_DISABLE))					
						continue;

					// convert ppp0 to vc0 (if ppp0 is over vc0)
					ifGetName(PHY_INTF(Entry.ifIndex), itfs[i].name, sizeof(itfs[i].name));
				}

				if (itfs[i].ifdomain == DOMAIN_ELAN) {
				// convert LAN1 to eth0.2
				ret = sscanf(itfs[i].name, "LAN%hhu.%hu", &vUChar, &vUShort);
				if (ret == 1)
					snprintf(itfs[i].name, sizeof(itfs[i].name), "%s", ELANVIF[vUChar - 1]);
				else if (ret == 2)
					snprintf(itfs[i].name, sizeof(itfs[i].name), "%s.%hu",
							ELANVIF[vUChar - 1], vUShort);
				}

				// brctl delif br0 eth0.2
				status |= va_cmd(BRCTL, 3, 1, "delif", (char *)BRIF, itfs[i].name);

				// brctl addif br[0-4] eth0.2
				status |= va_cmd(BRCTL, 3, 1, "addif", brif, itfs[i].name);

			}
		}
	} else if (mode == DEL_RULE) {
		for (grpnum = 1; grpnum <= 4; grpnum++) {
			// default group (grpnum == 0) should not be "delbr" here

			ifnum = get_group_ifinfo(itfs, MAX_NUM_OF_ITFS, grpnum);
			if (ifnum <= 0)
				continue;

			brif[2] = '0' + grpnum;

			// (1) down br[1-4]
			// ifconfig br[1-4] down
			status |= va_cmd(IFCONFIG, 2, 1, brif, "down");

			// (2) del all interfaces on br[1-4]
			// brctl delbr br[1-4]              
			status |= va_cmd(BRCTL, 2, 1, "delbr", brif);
		}
	}
#endif

	return status;
}

void setgroup(char *list, unsigned char grpnum)
{
	int ifdomain, ifid;
	int i, num;
	char *arg0, *token;
	MIB_CE_ATM_VC_T Entry;	
		
	arg0 = list;
	while ((token = strtok(arg0, ",")) != NULL) {
		ifid = atoi(token);
		ifdomain = IF_DOMAIN(ifid);
		ifid = IF_INDEX(ifid);	
		
#if defined(ITF_GROUP_4P) || defined(CONFIG_RTL_8676HWNAT) || defined(CONFIG_APOLLO_ROMEDRIVER)
		if (ifdomain == DOMAIN_ELAN) {
			MIB_CE_SW_PORT_T Entry;

			num = mib_chain_total(MIB_SW_PORT_TBL);
			if (ifid < num) {
				if (!mib_chain_get
				    (MIB_SW_PORT_TBL, ifid, &Entry))
					return;
				Entry.itfGroup = grpnum;				
				mib_chain_update(MIB_SW_PORT_TBL, &Entry, ifid);
			} else if (ifid >= num && ifid < num * 2) {
				if (!mib_chain_get
				    (MIB_SW_PORT_TBL, ifid - num, &Entry))
					return;
				Entry.vlan_on_lan_itfGroup = grpnum;				
				mib_chain_update(MIB_SW_PORT_TBL, &Entry, ifid - num);
			}
		}
#endif

#ifdef WLAN_SUPPORT
		else if (ifdomain == DOMAIN_WLAN) {
			int ori_wlan_idx = wlan_idx;

			wlan_idx = 0;

			if (ifid == 0) {
				mib_set(MIB_WLAN_ITF_GROUP, &grpnum);
				goto next_token;
			}

#if defined(CONFIG_RTL_92D_DMDP) || defined(WLAN_DUALBAND_CONCURRENT)
			if (ifid == 10) {
				mib_set(MIB_WLAN1_ITF_GROUP, &grpnum);
				goto next_token;
			}
#endif

			// Added by Mason Yu
#ifdef WLAN_MBSSID
			// wlan0_vap0
			if (ifid >= 1 && ifid < IFGROUP_NUM) {				
				mib_set(MIB_WLAN_VAP0_ITF_GROUP + ((ifid - 1) << 1), &grpnum);
				goto next_token;
			}
#if defined(CONFIG_RTL_92D_DMDP) || defined(WLAN_DUALBAND_CONCURRENT)
			// wlan1_vap0
			if (ifid >= 11 && ifid < IFGROUP_NUM + 10) {				
				mib_set(MIB_WLAN1_VAP0_ITF_GROUP + ((ifid - 11) << 1), &grpnum);
				goto next_token;
			}
#endif
#endif // WLAN_MBSSID
			wlan_idx = ori_wlan_idx;
		}
#endif // WLAN_SUPPORT

#ifdef CONFIG_USB_ETH
		else if (ifdomain == DOMAIN_ULAN) {
			if (ifid == 0)
				mib_set(MIB_USBETH_ITF_GROUP, &grpnum);
		}
#endif

		else if (ifdomain == DOMAIN_WAN) {

			num = mib_chain_total(MIB_ATM_VC_TBL);
			for (i = 0; i < num; i++) {
				if (!mib_chain_get
				    (MIB_ATM_VC_TBL, i, (void *)&Entry))
					return;
				if (Entry.enable && isValidMedia(Entry.ifIndex)
				    && Entry.ifIndex == ifid) {
					Entry.itfGroupNum = grpnum;
					mib_chain_update(MIB_ATM_VC_TBL,
							 (void *)&Entry, i);
				}
			}
		}
#ifdef CONFIG_NET_IPGRE	
		else if (ifdomain == DOMAIN_GRE) {
			MIB_GRE_T greEntry;
			num = mib_chain_total(MIB_GRE_TBL);
			if (ifid < num) {
				if (!mib_chain_get(MIB_GRE_TBL, ifid, (void *)&greEntry))
					return;
				greEntry.itfGroup = grpnum;				
				mib_chain_update(MIB_GRE_TBL, (void *)&greEntry, ifid);
			} else if (ifid >= num && ifid < num * 2) {
				if (!mib_chain_get(MIB_GRE_TBL, ifid - num, (void *)&greEntry))
					return;
				greEntry.itfGroupVlan = grpnum;				
				mib_chain_update(MIB_GRE_TBL, (void *)&greEntry, ifid - num);
			}
		}
#endif
		
next_token:
		arg0 = NULL;
	}
}

/*------------------------------------------------------------------
 * Get a list of interface info. (itfInfo) of group.
 * where,
 * info: a list of interface info entries
 * len: max length of the info list
 * grpnum: group id
 *-----------------------------------------------------------------*/
int get_group_ifinfo(struct itfInfo *info, int len, unsigned char grpnum)
{
#if defined(ITF_GROUP_4P) || defined(CONFIG_RTL_8676HWNAT) || defined(CONFIG_APOLLO_ROMEDRIVER)
	unsigned int swNum;
	char strlan[] = "LAN0";
	MIB_CE_SW_PORT_T Entry;
#endif
	unsigned int vcNum;
	int i, num;
	unsigned char mygroup;
	MIB_CE_ATM_VC_T pvcEntry;
#ifdef CONFIG_NET_IPGRE
	MIB_GRE_T greEntry;
	int greNum;
#endif
#if defined(WLAN_SUPPORT) || defined(WLAN_MBSSID)
	int ori_wlan_idx;
#endif
#ifdef WLAN_SUPPORT
	unsigned char vUChar;
#endif
#ifdef WLAN_MBSSID
	MIB_CE_MBSSIB_T mbssidEntry;
#endif

	num = 0;
#if defined(ITF_GROUP_4P) || defined(CONFIG_RTL_8676HWNAT) || defined(CONFIG_APOLLO_ROMEDRIVER)
	// LAN ports
	swNum = mib_chain_total(MIB_SW_PORT_TBL);
	for (i = 0; i < ELANVIF_NUM; i++) {
		if (!mib_chain_get(MIB_SW_PORT_TBL, i, &Entry))
			return -1;
		if (Entry.itfGroup == grpnum) {
			strlan[3] = '0' + virt2user[i];	// LAN1, LAN2, LAN3, LAN4
			info[num].ifdomain = DOMAIN_ELAN;
			info[num].ifid = i;
			strncpy(info[num].name, strlan, sizeof(info[num].name));
			if (++num >= len)
				return num;
		}

#ifdef CONFIG_USER_VLAN_ON_LAN		
		if (Entry.vlan_on_lan_enabled && Entry.vlan_on_lan_itfGroup == grpnum) {
			strlan[3] = '0' + virt2user[i];	// LAN1, LAN2, LAN3, LAN4
			info[num].ifdomain = DOMAIN_ELAN;
			info[num].ifid = i + swNum;
			snprintf(info[num].name, sizeof(info[num].name), "%s.%hu", strlan, Entry.vid);
			if (++num >= len)
				return num;
		}
#endif
	}
#endif

#ifdef WLAN_SUPPORT
	// wlan0
	ori_wlan_idx = wlan_idx;
	wlan_idx = 0;		// Magician: mib_get will add wlan_idx to mib id. Therefore wlan_idx must be set to 0.

	mib_get(MIB_WLAN_DISABLED, &vUChar);
	if (vUChar == 0) {
		mib_get(MIB_WLAN_ITF_GROUP, &mygroup);
		if (mygroup == grpnum) {
			info[num].ifdomain = DOMAIN_WLAN;
			info[num].ifid = 0;
			strncpy(info[num].name, (char *)WLANIF[0], sizeof(info[num].name));
			if (++num >= len)
				return num;
		}
	}
// wlan1
#if defined(CONFIG_RTL_92D_DMDP) || defined(WLAN_DUALBAND_CONCURRENT)
	mib_get(MIB_WLAN1_DISABLED, &vUChar);
	if (vUChar == 0) {
		mib_get(MIB_WLAN1_ITF_GROUP, &mygroup);
		if (mygroup == grpnum) {
			info[num].ifdomain = DOMAIN_WLAN;
			info[num].ifid = 10;
			strncpy(info[num].name, (char *)WLANIF[1], sizeof(info[num].name));
			if (++num >= len)
				return num;
		}
	}
#endif

#ifdef WLAN_MBSSID
#ifdef CONFIG_00R0
	for (i = 0; i < WLAN_MBSSID_NUM; i++) {
#else
	for (i = 0; i < IFGROUP_NUM - 1; i++) {
#endif
		if (!mib_chain_get(MIB_MBSSIB_TBL, i + 1, &mbssidEntry) ||
				mbssidEntry.wlanDisabled)
			continue;		
		
		mib_get(MIB_WLAN_VAP0_ITF_GROUP + (i << 1), &mygroup);
		if (mygroup == grpnum) {
			info[num].ifdomain = DOMAIN_WLAN;
			info[num].ifid = i + 1;
			sprintf(info[num].name, "wlan0-vap%d", i);
			if (++num >= len)
				return num;
		}
	}

#if defined(CONFIG_RTL_92D_DMDP) || defined(WLAN_DUALBAND_CONCURRENT)
#ifdef CONFIG_00R0
	for (i = 0; i < WLAN_MBSSID_NUM; i++) {
#else
	for (i = 0; i < IFGROUP_NUM - 1; i++) {
#endif
		if (!mib_chain_get(MIB_WLAN1_MBSSIB_TBL, i + 1, &mbssidEntry) ||
				mbssidEntry.wlanDisabled)
			continue;		
		
		mib_get(MIB_WLAN1_VAP0_ITF_GROUP + (i << 1), &mygroup);
		if (mygroup == grpnum) {
			info[num].ifdomain = DOMAIN_WLAN;
			info[num].ifid = i + 11;
			sprintf(info[num].name, "wlan1-vap%d", i);
			if (++num >= len)
				return num;
		}
	}
#endif
#endif // WLAN_MBSSID
	wlan_idx = ori_wlan_idx;
#endif // WLAN_SUPPORT

#ifdef CONFIG_USB_ETH
	// usb0
	mib_get(MIB_USBETH_ITF_GROUP, &mygroup);
	if (mygroup == grpnum) {
		info[num].ifdomain = DOMAIN_ULAN;
		info[num].ifid = 0;
		strncpy(info[num].name, (char *)USBETHIF, sizeof(info[num].name));
		if (++num >= len)
			return num;
	}
#endif

	// vc
	vcNum = mib_chain_total(MIB_ATM_VC_TBL);

	for (i = 0; i < vcNum; i++) {
		if (!mib_chain_get(MIB_ATM_VC_TBL, i, &pvcEntry)) {
			printf("Get chain record error!\n");
			return -1;
		}

		if (pvcEntry.enable == 0 || pvcEntry.itfGroupNum != grpnum
		    || !isValidMedia(pvcEntry.ifIndex)
#ifdef CONFIG_RTK_L34_ENABLE // Rostelecom, Port Binding function
#else
		    || ( pvcEntry.cmode != CHANNEL_MODE_BRIDGE && pvcEntry.brmode == BRIDGE_DISABLE)
#endif
		    )
			continue;

		info[num].ifdomain = DOMAIN_WAN;
		info[num].ifid = pvcEntry.ifIndex;
		ifGetName(pvcEntry.ifIndex, info[num].name,
			  sizeof(info[num].name));
		if (++num >= len)
			return num;
	}

#ifdef CONFIG_NET_IPGRE	
	// GRE Tunnel
	greNum = mib_chain_total(MIB_GRE_TBL);
	for (i = 0; i < greNum; i++) {
		extern const char* GREIF[];
		
		if (!mib_chain_get(MIB_GRE_TBL, i, &greEntry)) {
			printf("Get chain(MIB_GRE_TBL) record error!\n");
			return -1;
		}
		
		if (greEntry.enable == 1 && greEntry.itfGroup == grpnum) {
			info[num].ifdomain = DOMAIN_GRE;
			info[num].ifid = i;
			strncpy(info[num].name, (char *)GREIF[i], sizeof(info[num].name));			
			if (++num >= len)
				return num;
		}
		
		if (greEntry.enable == 1 && greEntry.itfGroupVlan == grpnum && greEntry.vlanid != 0) {			
			info[num].ifdomain = DOMAIN_GRE;
			info[num].ifid = i + greNum;
			snprintf(info[num].name, sizeof(info[num].name), "%s.%hu", GREIF[i], greEntry.vlanid);			
			if (++num >= len)
				return num;
		}
	}
#endif
	return num;
}

#endif
