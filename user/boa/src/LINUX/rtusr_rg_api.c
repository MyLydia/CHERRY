#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <memory.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <linux/config.h>
#include <rtk_rg_struct.h>
#include "rtusr_rg_api.h"
#include "mib.h"
#include "utility.h"

#ifdef CONFIG_TR142_MODULE
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <rtk/rtk_tr142.h>
#endif

#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
#define ACL_QOS_INTERNAL_PRIORITY_START 8
#else
#define ACL_QOS_INTERNAL_PRIORITY_START 4
#endif

#ifdef CONFIG_RTK_OMCI_V1
#include <omci_dm_sd.h>
#endif
#include "chip_deps.h"

const char DHCPC_ROUTERFILE_B[] = "/var/udhcpc/router";
const char RG_LAN_INF_IDX[] = "/var/rg_lan_inf_idx";
const char RG_MAC_RULES_FILE[] = "/var/rg_mac_rules_idx";
const char RG_ACL_RULES_FILE[] = "/var/rg_acl_rules_idx";
const char RG_ACL_DEFAULT_RULES_FILE[] = "/var/rg_acl_default_rules_idx";
const char RG_ACL_IPv6_RULES_FILE[] = "/var/rg_acl_ipv6_rules_idx";
const char RG_QOS_RULES_FILE[] = "/var/rg_acl_qos_idx";
#ifdef CONFIG_00R0
const char RG_QOS_TS_RULES_FILE[] = "/var/rg_qos_ts_idx";
#endif
const char RG_UPNP_CONNECTION_FILE[] = "/var/rg_upnp_idx";
const char RG_UPNP_TMP_FILE[] = "/var/rg_upnp_tmp";
const char RG_VERTUAL_SERVER_FILE[] = "/var/rg_vertual_servers_idx";
const char RG_URL_FILTER_FILE[] = "/var/rg_url_filter_idx";
const char MER_GWINFO_B[] = "/tmp/MERgw";
const char WAN_INTERFACE_TMP[] = "/var/wan_interface_tmp";
const char RG_GATEWAY_SERVICE_FILE[] = "/var/rg_gatewayService_idx";
const char RG_WIFI_INGRESS_RATE_LIMIT_FILE[] = "/proc/rg/wifi_ingress_rate_limit";
const char RG_ACL_MVLAN_RULES_FILE[] = "/var/rg_acl_mvlan_rules_idx";
const char RG_ROUTE_V6_RA_NS_FILTER_FILE[] = "/var/rg_acl_rule_for_v6_RA_NS_idx";
const char RG_ACL_FOR_VPN_POLICY_ROUTE[] = "/var/rg_acl_for_vpn_policy_route";
const char RG_ACL_WAN_PORT_MAPPING_POLICY_ROUTE[] = "/var/rg_acl_wan_portmapping_policy_route_idx";
#ifdef CONFIG_RTL9600_SERIES
const char RG_TRAP_ACL_RULES_FILE[] = "/var/rg_trap_pppoe_acl_rules_idx";
#endif
#if defined(CONFIG_E8B)
const char RG_DHCP_TRAP_ACL_RULES_FILE[] = "/var/rg_trap_dhcp_acl_rules_idx";
#endif
#ifdef DOS_SUPPORT
const char RG_DOS_FILTER_FILE[] = "/var/rg_dos_filter_idx";
#endif
#ifdef PARENTAL_CTRL
const char RG_PARENTAL_CTRL_MAC_FILE[] = "/var/rg_parental_ctrl_mac_idx";
const char RG_PARENTAL_CTRL_IP_FILE[] = "/var/rg_parental_ctrl_ip_idx";
#endif

#ifdef CONFIG_00R0
const char RG_VOIP_SIP_1P_FILE[] = "/var/rg_voip_sip_1p_idx";
const char RG_VOIP_RTP_1P_FILE[] = "/var/rg_voip_rtp_1p_idx";
const char RG_ACL_POLICY_ROUTE[] = "/var/rg_acl_policy_route_idx";
const char RG_IPQOS_WORKAROUND[] = "/var/rg_ipqos_traffic_idx";
const char RG_CWMP_1P_FILE[] = "/var/rg_cwmp_1p_idx";

const char smallbw_fpath[] = "/proc/rg/pppoe_gpon_small_bandwidth_control";
#endif

#if defined(CONFIG_WLAN_MBSSID_NUM) //CONFIG_WLAN_MBSSID_NUM define in kernel config
#define ITFGROUP_WLAN_NUM (CONFIG_WLAN_MBSSID_NUM+1)
#define ITFGROUP_WLAN0_DEV_BIT (PMAP_WLAN0)
#define ITFGROUP_WLAN1_DEV_BIT (ITFGROUP_WLAN_NUM+PMAP_WLAN0)
#define ITFGROUP_WLAN_MASK ((1<<(ITFGROUP_WLAN_NUM))-1) // ex. 0b100000 - 0b1 = 0b11111 =0x1f
#else
#define ITFGROUP_WLAN_NUM (5)
#define ITFGROUP_WLAN0_DEV_BIT (PMAP_WLAN0)
#define ITFGROUP_WLAN1_DEV_BIT (ITFGROUP_WLAN_NUM+PMAP_WLAN0)
#define ITFGROUP_WLAN_MASK 0x1f // ex. 0b100000 - 0b1 = 0b11111 =0x1f
#endif

#if defined(CONFIG_RTL9607C_SERIES) || defined(CONFIG_LUNA_G3_SERIES)
const char RG_INGRESS_CONTROL_PACKET_ACL_RULES_FILE[] = "/var/rg_control_ingress_packet_acl_rules_idx";
const char RG_EGRESS_CONTROL_PACKET_ACL_RULES_FILE[] = "/var/rg_control_egress_packet_acl_rules_idx";
const char RG_INGRESS_CONTROL_ITMS_PACKET_ACL_RULES_FILE[] = "/var/rg_control_ingress_itms_packet_acl_rules_idx";
const char RG_EGRESS_CONTROL_ITMS_PACKET_ACL_RULES_FILE[] = "/var/rg_control_egress_itms_packet_acl_rules_idx";
#endif
const char RG_IGMP_PROXY_ACL_RULE_FILE[] = "/var/rg_igmp_proxy_acl_idx";
const char RG_MLD_PROXY_ACL_RULE_FILE[] = "/var/rg_mld_proxy_acl_idx";
#ifdef SUPPORT_FON_GRE
const char RG_GRE_RULES_FILE[]="/var/rg_gre_rules_idx";
#endif
#if defined(CONFIG_SECONDARY_IP)
const char RG_IP_ALIAS_INTF_IDX_FILE[] = "/var/rg_ip_alias_intf_idx";
#endif
#ifdef CONFIG_RTL867X_VLAN_MAPPING
const char RG_ACL_VLAN_BINDING_DS_MC_RULES_FILE[] = "/var/rg_vlan_binding_ds_mc_acl_rules_idx";
#endif
#ifdef CONFIG_USER_DHCPCLIENT_MODE
const char RG_LAN_DHCP_CLIENT_ACL_RULE_FILE[] = "/var/rg_lan_dhcp_client_acl_idx";
#endif
#ifdef WLAN_UNIVERSAL_REPEATER
const char RG_VXD_WAN_IDX_FILE[] = "/var/rg_vxd_wan_idx";
#endif

#define ConfigACLLock "/var/run/configACLLock"
#define LOCK_ACL_CONFIG(f)	\
do {	\
	if ((lockfd = open(f, O_RDWR)) == -1) {	\
		perror("open pmap lockfile");	\
		return 0;	\
	}	\
	while (flock(lockfd, LOCK_EX)) { \
		if (errno != EINTR) \
			break; \
	}	\
} while (0)

#define UNLOCK_ACL_CONFIG()	\
do {	\
	flock(lockfd, LOCK_UN);	\
	close(lockfd);	\
} while (0)

#define UntagCPort 1
#define TagCPort 0
#ifdef CONFIG_GPON_FEATURE
#define OMCI_WAN_INFO "/proc/omci/wanInfo"
#if ! defined(_LINUX_2_6_) && defined(CONFIG_TR142_MODULE)
#define TR142_WAN_IDX_MAP "/proc/rtk_tr142/wan_idx_map"
#endif
/*
# cat /proc/omci/wanInfo
wanif[0]: vid=-1, pri=-1, type=-1, service=-1, netIfIdx=-1, isRuleCfg=0
--> omci add cf rule
type:(omci mode)
0 = PPPoE,
1 = IPoE,
2 = BRIDGE

service:
0 = other wan
1 = internet wan

isBinding:
0 = non binding
1 = binding

bAdd:
0 - delete
1 - add

what we write into proc:
netIfIdx=-1, vid=-1, pri=-1, type=-1, service=-1, isBinding=1,  is bAdd=0
*/
#endif
#define MAX_VALUE(val1, val2) (val1>val2?val1:val2)
#define MIN_VALUE(val1, val2) (val1<val2?val1:val2)
unsigned int RG_get_lan_phyPortMask(unsigned int portmask);
unsigned int RG_get_all_lan_phyPortMask(void);
unsigned int RG_get_wan_phyPortMask();
void RTK_Setup_Storm_Control(void);
int RG_add_WAN_Port_mapping_ACL(int wanindex, unsigned short itfGroup);
int FlushRTK_RG_WAN_Port_mapping_ACL(int wanindex);
int setup_vconfig(unsigned short LanVid, int LanPortIdx);
int flush_vconfig(unsigned short LanVid, int LanPortIdx);

int clearAllRGAclFile(void)
{
	//system("for i in `find /var/ -name \"*rg_*\"`; do cat /dev/null > $i; done");
	//system("for i in `find /var/ -name \"*rg_*\"`; do echo \"\" > $i; done");
	system("for i in `find /var/ -name \"*rg_*\"`; do rm $i; touch $i; done");
	return 0;
}

#if ! defined(_LINUX_2_6_) && defined(CONFIG_TR142_MODULE)
static int check_wan_omci_portbing(MIB_CE_ATM_VC_T *pentry)
{
	FILE *fp = NULL;
	char ifname[IFNAMSIZ] = {0}, ifname_tmp[IFNAMSIZ] = {0}, ifname_tmp2[IFNAMSIZ] = {0};
	int wan_idx = -1, port_bind = 0;
	char buf[64] = {0};
	
	
	if(pentry == NULL) return 0;

	fp = fopen(TR142_WAN_IDX_MAP, "r");
	if(fp){
		ifGetName(PHY_INTF(pentry->ifIndex), ifname, sizeof(ifname));
		while(!feof(fp)){
			fgets(buf, sizeof(buf)-1, fp);
			if(sscanf(buf, "%d %s %s %d", &wan_idx, ifname_tmp, ifname_tmp2, &port_bind) == 4){
				if(pentry->rg_wan_idx == wan_idx && !strcmp(ifname_tmp, ALIASNAME_NAS0)
					&& !strcmp(ifname_tmp2, ifname))
				{
					fclose(fp);
					return (port_bind == 1) ? 1 : 0;
				}	
			}
		}
		fclose(fp);
	}
	return 0;
}
#endif

int flush_rg_acl_rule_for_VPN_policy_route(void)
{
	FILE *fp;
	int filter_idx;

	if(!(fp = fopen(RG_ACL_FOR_VPN_POLICY_ROUTE, "r"))){
		//AUG_PRT("open=%s fail!!\n",RG_ACL_FOR_VPN_POLICY_ROUTE);
		return -2;
	}

	while(fscanf(fp, "%d\n", &filter_idx) != EOF)
	{
		if(rtk_rg_aclFilterAndQos_del(filter_idx))
			DBPRINT(1, "rtk_rg_naptFilterAndQos_del failed! idx = %d\n", filter_idx);
	}
//AUG_PRT("filter_idx=%d\n",filter_idx);
	fclose(fp);
	unlink(RG_ACL_FOR_VPN_POLICY_ROUTE);

	return 0;



}
int add_rg_acl_rule_for_VPN_policy_route(void)
{

	rtk_rg_aclFilterAndQos_t aclRule;
	MIB_CE_ATM_VC_T entry;
	int ret, totalVC_entry,i;
	int aclIdx=0;
	unsigned short itfGroup=0;
	FILE *fp = NULL;
	totalVC_entry = mib_chain_total(MIB_ATM_VC_TBL);
	//trap all binding port 
	for(i=0;i<totalVC_entry;i++){
		if(mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&entry) == 0)
			continue;
		if (entry.enable == 0)
			continue;	
		if (entry.itfGroup > 0)
			itfGroup |= entry.itfGroup;
	}
#ifdef CONFIG_RTL9602C_SERIES
	if((itfGroup & 0x3) == 0)
		return -1;
#else
	if((itfGroup & 0xf) == 0)
		return -1;
#endif
	AUG_PRT("----------->itfGroup=0x%x\n",itfGroup);	
	if(!(fp = fopen(RG_ACL_FOR_VPN_POLICY_ROUTE, "a+")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -2;
	}	
	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	aclRule.fwding_type_and_direction =  ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	aclRule.filter_fields |= INGRESS_PORT_BIT;
	#ifdef CONFIG_RTL9602C_SERIES
	aclRule.ingress_port_mask.portmask = RG_get_lan_phyPortMask(itfGroup & 0x3);
	#else
	aclRule.ingress_port_mask.portmask = RG_get_lan_phyPortMask(itfGroup & 0xf);
	#endif
	aclRule.acl_weight = RG_TRAP_ACL_WEIGHT;
	//trap to RG FWD engine
	aclRule.action_type = ACL_ACTION_TYPE_TRAP;
	if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0)
	{	
		fprintf(fp, "%d\n", aclIdx);
		printf("Add ACl Rule for VPN_policy_route %d\n",aclIdx);
	}else
		printf("Error! Add ACl VPN_policy_route Fail\n");

	//AUG_PRT("aclIdx=%d\n",aclIdx);

	if(fp)
		fclose(fp);
	return 0;

}

#ifdef CONFIG_RTL9600_SERIES
void trap_pppoe(int trap_action, int wan_ifIndex, char * ifname, unsigned char proto)
{
	FILE *fp = NULL;
	rtk_rg_aclFilterAndQos_t aclRule={0};
	int aclIdx = -1;
	char filename[100]={0};
	int ret = -1;

	sprintf(filename,"%s_%s",RG_TRAP_ACL_RULES_FILE,ifname);
	AUG_PRT("[%s: trap_action=%d,wan_ifIndex=%d, filename=%s\n",__func__,trap_action,wan_ifIndex,filename);


	if(trap_action==PON_PPPOE_TRAP_START){

		if(access(filename,0)==0){
			printf("File for trap rule existed. Do nothing!\n");
			return;
		}

		if(!(fp = fopen(filename, "w+"))){
			fprintf(stderr, "ERROR! %s\n", strerror(errno));
			return -1;
		}
		memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
		aclRule.fwding_type_and_direction =  ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
		aclRule.acl_weight = RG_TRAP_ACL_WEIGHT;
		aclRule.filter_fields |= INGRESS_DMAC_BIT;
		mib_get(MIB_ELAN_MAC_ADDR, (void *)&aclRule.ingress_dmac);
		aclRule.filter_fields |= INGRESS_PORT_BIT;
		aclRule.ingress_port_mask.portmask = RG_get_all_lan_phyPortMask() | (1<<RTK_RG_PORT_CPU);
		if(proto == IPVER_IPV4){//v4 only
			aclRule.filter_fields |= INGRESS_IPV4_TAGIF_BIT;
			aclRule.ingress_ipv4_tagif = 1;
		}else if(proto == IPVER_IPV6){ //v6 only
			aclRule.filter_fields |= INGRESS_IPV6_TAGIF_BIT;
			aclRule.ingress_ipv6_tagif = 1;
		}
		//v4 and v6 both, we don't care TAGIF bit
		//	proto & IPVER_IPV4_IPV6

		//aclRule.filter_fields |= EGRESS_INTF_BIT;
		//aclRule.egress_intf_idx = wan_ifIndex;  // Set egress interface.

		aclRule.action_type = ACL_ACTION_TYPE_TRAP;

		if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0)
			fprintf(fp, "%d\n", aclIdx);
		else
			printf("%s-%d rtk_rg_aclFilterAndQos_add fail =%d\n",__func__,__LINE__,ret);
		AUG_PRT("%s, added aclIdx=%d!\n",__func__,aclIdx);
		fclose(fp);
		return;
	}else if (trap_action == PON_PPPOE_TRAP_STOP){
		if(access(filename,0)!=0){
			printf("File for trap rule removed. Do nothing!\n");
			return;
		}
		if(!(fp = fopen(filename, "r"))){
			fprintf(stderr, "ERROR! %s\n", strerror(errno));
				return -1;
		}
		fscanf(fp, "%d\n", &aclIdx);
		AUG_PRT("%s, aclIdx=%d!\n",__func__,aclIdx);
		if(aclIdx!=-1){
			printf("%s, aclIdx=%d, now delete it!\n",__func__,aclIdx);
			if(rtk_rg_aclFilterAndQos_del(aclIdx))
				DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", aclIdx);
		}
		fclose(fp);
		unlink(filename);
		return;
	}

	AUG_PRT("%s, should not go here!\n");
	fclose(fp);
}
#endif

#ifdef CONFIG_00R0_NW
//This function is for if LAN port binding to other WAN, 
//avoid packet comes from CPU port to LAN be filtered by vlan filter.
void special_handle_for_vlan_filter()
{
	int ret;
	int aclIdx;

	rtk_rg_aclFilterAndQos_t aclRule;

	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));

	aclRule.fwding_type_and_direction =  ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	aclRule.action_type = ACL_ACTION_TYPE_QOS;
	aclRule.acl_weight = RG_QOS_ACL_WEIGHT;

	//filter CPU port and gateway's source mac
	aclRule.filter_fields |= INGRESS_PORT_BIT;
	aclRule.ingress_port_mask.portmask = (1<<RTK_RG_PORT_CPU);

	aclRule.filter_fields |= INGRESS_SMAC_BIT;
	mib_get(MIB_ELAN_MAC_ADDR, (void *)&aclRule.ingress_smac);
	
	//action make cvlan to 1
	aclRule.qos_actions |= ACL_ACTION_ACL_INGRESS_VID_BIT;
	aclRule.action_acl_ingress_vid = 1;


	if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0){
		printf("Add Acl for cvlan 1 success! aclIdx=%d\n",aclIdx);
	}
	else
		printf("Add Acl for cvlan 1 fail!");
}
#endif

#if defined(CONFIG_IPV6) || defined(CONFIG_00R0)
	unsigned char empty_ipv6[IPV6_ADDR_LEN] = {0};

void add_acl_rule_for_v6_RA()
{
	rtk_rg_aclFilterAndQos_t aclRule;
	int aclIdx=0;
	unsigned char ip6Addr[IP6_ADDR_LEN]={0};

	printf("enter %s\n",__func__);
	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));

	//ff02::1 , trap to protocol stack
	aclRule.filter_fields |= INGRESS_IPV6_DIP_RANGE_BIT;
	inet_pton(PF_INET6, "ff02::1",(void *)ip6Addr);
	memcpy(aclRule.ingress_dest_ipv6_addr_start, ip6Addr, IPV6_ADDR_LEN);
	memcpy(aclRule.ingress_dest_ipv6_addr_end, ip6Addr, IPV6_ADDR_LEN);

	aclRule.filter_fields |= INGRESS_L4_ICMPV6_BIT;

	aclRule.filter_fields |= INGRESS_PORT_BIT;
	aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();

	aclRule.action_type = ACL_ACTION_TYPE_TRAP_TO_PS;

	if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0)
{
		printf("Add ACl Rule for ff02::1 Successfully %d\n",aclIdx);
	}else
		printf("Error! Add ACl Rule for ff02::1 Faile\n");

	printf("exit %s\n",__func__);
}

/* ff02::1:ff00:0/104 Solicited-node multicast address */
void add_acl_rule_for_v6_NS()
{
	rtk_rg_aclFilterAndQos_t aclRule;
	int aclIdx=0;
	unsigned char ip6Addr[IP6_ADDR_LEN]={0};

	printf("enter %s\n",__func__);
	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));

	//ff02::1:ff00:0/104 , trap to protocol stack
	aclRule.filter_fields |= INGRESS_IPV6_DIP_RANGE_BIT;
	inet_pton(PF_INET6, "ff02::1:ff00:0",(void *)ip6Addr);
	memcpy(aclRule.ingress_dest_ipv6_addr_start, ip6Addr, IPV6_ADDR_LEN);
	inet_pton(PF_INET6, "ff02::1:ffff:ffff",(void *)ip6Addr);
	memcpy(aclRule.ingress_dest_ipv6_addr_end, ip6Addr, IPV6_ADDR_LEN);

	aclRule.filter_fields |= INGRESS_L4_ICMPV6_BIT;

	aclRule.filter_fields |= INGRESS_PORT_BIT;
	aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();

	aclRule.action_type = ACL_ACTION_TYPE_TRAP_TO_PS;

	if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0)
{
		printf("Add ACl Rule for ff02::1:ff00:0/104 (Neighbor Solictaion) Successfully %d\n",aclIdx);
	}else
		printf("Error! Add ACl Rule for ff02::1:ff00:0/104 (Neighbor Solictaion) Faile\n");

	printf("exit %s\n",__func__);
}

void  add_acl_rule_for_IGMP()
{
	rtk_rg_aclFilterAndQos_t aclRule;
	int aclIdx=0;

	printf("enter %s\n",__func__);
	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));

	aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	aclRule.filter_fields |= (INGRESS_L4_POROTCAL_VALUE_BIT | INGRESS_PORT_BIT);
	aclRule.ingress_port_mask.portmask = RTK_RG_ALL_MAC_PORTMASK;
	aclRule.ingress_l4_protocal = 0x2;
	
	aclRule.action_type = ACL_ACTION_TYPE_QOS;
	aclRule.qos_actions |= ACL_ACTION_ACL_PRIORITY_BIT;
	aclRule.action_acl_priority = 7;

	
	if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0)
	{
		printf("Add ACl Rule IGMP control packets Successfully %d\n",aclIdx);
	}else
		printf("Error! Add ACl Rule IGMP control packets Successfully Faile\n");

	printf("exit %s\n",__func__);

}


int RTK_RG_FLUSH_Route_V6_RA_NS_ACL_FILE(void)
{
	FILE *fp;
	int aclIdx=-1;
	if(!(fp = fopen(RG_ROUTE_V6_RA_NS_FILTER_FILE, "r"))){
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -2;
	}
	while(fscanf(fp, "%d\n", &aclIdx) != EOF)
	{
		if(rtk_rg_aclFilterAndQos_del(aclIdx))
			fprintf(stderr, "%s failed! idx = %d\n",__func__, aclIdx);
	}
	fclose(fp);
	unlink(RG_ROUTE_V6_RA_NS_FILTER_FILE);
	return 0;


}

int RTK_RG_Set_ACL_Route_V6_RA_NS_Filter(void)
{
	FILE *fp = NULL;
	int ret=-1;
	MIB_CE_ATM_VC_T entryVC;
	rtk_rg_aclFilterAndQos_t aclRule;
	int aclIdx=0;
	unsigned char ip6Addr[IP6_ADDR_LEN]={0}, mask[IP6_ADDR_LEN]={0};
	int created=0;

	int i, totalVC_entry = mib_chain_total(MIB_ATM_VC_TBL);
	for(i=0;i<totalVC_entry;i++){
		//routing mode
		if(mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&entryVC) == 0)
			continue;
		//printf("%s-%d entryVC.cmode=%d, created=%d\n",__func__,__LINE__,entryVC.cmode,created);
		if((entryVC.cmode > 0) && !created)
		{
			//printf("%s-%d\n",__func__,__LINE__);
			if(entryVC.IpProtocol & IPVER_IPV6){
				//printf("%s-%d\n",__func__,__LINE__);
				if(!(fp = fopen(RG_ROUTE_V6_RA_NS_FILTER_FILE, "a"))){
					fprintf(stderr, "open %s fail!", RG_ROUTE_V6_RA_NS_FILTER_FILE);
					return -2;
				}

				memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
				//RA ff02::1 , trap to protocol stack
				aclRule.acl_weight = RG_DEFAULT_ACL_WEIGHT;
				inet_pton(PF_INET6, "ff02::1",(void *)ip6Addr);
#if defined(CONFIG_RTL9602C_SERIES) || defined(CONFIG_RTL9607C_SERIES)
				aclRule.filter_fields |= INGRESS_IPV6_TAGIF_BIT | INGRESS_IPV6_DIP_BIT;
				memcpy(aclRule.ingress_dest_ipv6_addr, ip6Addr, IPV6_ADDR_LEN);
				aclRule.ingress_ipv6_tagif = 1;
#else
				aclRule.filter_fields |= INGRESS_IPV6_DIP_RANGE_BIT;
				memcpy(aclRule.ingress_dest_ipv6_addr_start, ip6Addr, IPV6_ADDR_LEN);
				memcpy(aclRule.ingress_dest_ipv6_addr_end, ip6Addr, IPV6_ADDR_LEN);
#endif

				aclRule.filter_fields |= INGRESS_L4_ICMPV6_BIT;
				aclRule.filter_fields |= INGRESS_PORT_BIT;
				aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();

				aclRule.action_type = ACL_ACTION_TYPE_TRAP_TO_PS;

				if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0)
				{
					fprintf(fp, "%d\n", aclIdx);
				}else
					printf("Error! Add ACl Rule for ff02::1 Faile\n");
				memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
				//NS ff02::1:ff00:0/104, trap to protocol stack
				aclRule.acl_weight = RG_DEFAULT_ACL_WEIGHT;
#ifdef defined(CONFIG_RTL9602C_SERIES) || defined(CONFIG_RTL9607C_SERIES)
				aclRule.filter_fields |= INGRESS_IPV6_TAGIF_BIT | INGRESS_IPV6_DIP_BIT;
				inet_pton(PF_INET6, "ff02::1:ff00:0",(void *)ip6Addr);
				memcpy(aclRule.ingress_dest_ipv6_addr, ip6Addr, IPV6_ADDR_LEN);
				inet_pton(PF_INET6, "ffff:ffff:ffff:ffff:ffff:ffff:ff00:0",(void *)mask);
				memcpy(aclRule.ingress_dest_ipv6_addr_mask, mask, IPV6_ADDR_LEN);
				aclRule.ingress_ipv6_tagif = 1;
#else
				aclRule.filter_fields |= INGRESS_IPV6_DIP_RANGE_BIT;
				inet_pton(PF_INET6, "ff02::1:ff00:0",(void *)ip6Addr);
				memcpy(aclRule.ingress_dest_ipv6_addr_start, ip6Addr, IPV6_ADDR_LEN);
				inet_pton(PF_INET6, "ff02::1:ffff:ffff",(void *)ip6Addr);
				memcpy(aclRule.ingress_dest_ipv6_addr_end, ip6Addr, IPV6_ADDR_LEN);
#endif
				aclRule.filter_fields |= INGRESS_L4_ICMPV6_BIT;
				aclRule.filter_fields |= INGRESS_PORT_BIT;
				aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();

				aclRule.action_type = ACL_ACTION_TYPE_TRAP_TO_PS;

				if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0)
				{
					fprintf(fp, "%d\n", aclIdx);
				}else
					printf("Add ACl Rule for ff02::1:ff00:0/104 (Neighbor Solictaion) Successfully error ret=%d\n",ret);
				created=1;
				//printf("%s-%d created=%d\n",__func__,__LINE__,created);
			}
		}
	}
	if(fp)
		fclose(fp);
	return ret;
}

#endif

void RG_add_vxd_wlanDevMask(int vlanID)
{
#ifdef WLAN_UNIVERSAL_REPEATER
	rtk_rg_cvlan_info_t cvlan_info;
	memset(&cvlan_info, 0, sizeof(rtk_rg_cvlan_info_t));
	cvlan_info.vlanId = vlanID;
	if(rtk_rg_cvlan_get(&cvlan_info) == RT_ERR_RG_OK){
		cvlan_info.wlan0DevMask |= (1<<RG_RET_MBSSID_MASTER_CLIENT_INTF); //vxd dev bit 13
		cvlan_info.wlan0UntagMask |= (1<<RG_RET_MBSSID_MASTER_CLIENT_INTF); //vxd dev bit 13
		if(rtk_rg_cvlan_add(&cvlan_info) != RT_ERR_RG_OK)
			printf("%s %d add failed\n", __func__, __LINE__);
	}
#endif
}

#ifdef WLAN_UNIVERSAL_REPEATER
int rtk_wlan_rg_vxd_setup_rules(int wlanIdx, int add)
{
#ifndef WLAN_WISP
	rtk_rg_wanIntfConf_t wan_info;
	struct sockaddr hwaddr;
	char intf_name[IFNAMSIZ];
	int vlan_id=0, wanIntfIdx=0;
	FILE *fp=NULL;
	char filename[64]={0};
	snprintf(filename, sizeof(filename), "%s_%d", RG_VXD_WAN_IDX_FILE, wlanIdx);

	if(add){
		memset(&wan_info,0,sizeof(wan_info));
		snprintf(intf_name, IFNAMSIZ, "%s-vxd", WLANIF[wlanIdx]);
		getInAddr(intf_name, HW_ADDR, (void *)&hwaddr);
		memcpy(wan_info.gmac.octet, hwaddr.sa_data, MAC_ADDR_LEN);

		if(wlanIdx == 0)
			wan_info.wan_port_idx=RTK_RG_EXT_PORT2;
		else
			wan_info.wan_port_idx=RTK_RG_EXT_PORT3;

		wan_info.wan_type=RTK_RG_BRIDGE;

		mib_get(MIB_LAN_VLAN_ID1, (void *)&vlan_id);
		wan_info.egress_vlan_id = vlan_id;

		if((rtk_rg_wanInterface_add(&wan_info, &wanIntfIdx))!=SUCCESS){
			DBPRINT(1, "%s failed! (idx = %d)\n", __func__, wanIntfIdx);
			return -1;
		}

		if(fp = fopen(filename, "w")){
			fprintf(fp, "%d\n", wanIntfIdx);
			fclose(fp);
		}
		else{
			DBPRINT(1, "%s failed!\n", __func__);
			return -1;
		}
	}
	else{ //delete
		if(fp = fopen(filename, "r")){
			if(fscanf(fp, "%d", &wanIntfIdx)!=1){
				DBPRINT(1, "%s failed!\n", __func__);
				fclose(fp);
				return -1;
			}
			fclose(fp);
			unlink(filename);

			if(rtk_rg_interface_del(wanIntfIdx)){
				DBPRINT(1, "%s failed! (idx = %d)\n", __func__, wanIntfIdx);
				return -1;
			}
		}
		else
			return -1;
	}
#endif
	return 0;
}
#endif

int Init_rg_api()
{
	int ret;
	unsigned char mbtd;
	rtk_rg_initParams_t init_param;
	char buf[200]={0};
	unsigned int vid;

	bzero(&init_param, sizeof(rtk_rg_initParams_t));
	printf("init mac based tag des\n");

	mib_get(MIB_MAC_BASED_TAG_DECISION, (void *)&mbtd);
	init_param.macBasedTagDecision = mbtd;
#if 1
	//add for storm control
	sprintf(buf,"echo 1 > /proc/rg/layer2LookupMissFlood2CPU\n");
	system(buf);
#endif

/*To configure user's define vlan id range*/
	mib_get(MIB_FWD_CPU_VLAN_ID, (void *)&vid);
	init_param.fwdVLAN_CPU = vid;
	//AUG_PRT("%s-%d fwdVLAN_CPU=%d\n",__func__,__LINE__,init_param.fwdVLAN_CPU);

	mib_get(MIB_FWD_CPU_SVLAN_ID, (void *)&vid);
	init_param.fwdVLAN_CPU_SVLAN = vid;

	mib_get(MIB_FWD_PROTO_BLOCK_VLAN_ID, (void *)&vid);
	init_param.fwdVLAN_Proto_Block = vid;
	//AUG_PRT("%s-%d fwdVLAN_Proto_Block=%d\n",__func__,__LINE__,init_param.fwdVLAN_Proto_Block);

	mib_get(MIB_FWD_BIND_INTERNET_VLAN_ID, (void *)&vid);
	init_param.fwdVLAN_BIND_INTERNET = vid;
	//AUG_PRT("%s-%d fwdVLAN_BIND_INTERNET=%d\n",__func__,__LINE__,init_param.fwdVLAN_BIND_INTERNET);

	mib_get(MIB_FWD_BIND_OTHER_VLAN_ID, (void *)&vid);
	init_param.fwdVLAN_BIND_OTHER = vid;
	//AUG_PRT("%s-%d fwdVLAN_BIND_OTHER=%d\n",__func__,__LINE__,init_param.fwdVLAN_BIND_OTHER);


#ifdef CONFIG_LUNA
#if defined(CONFIG_GPON_FEATURE) || defined(CONFIG_EPON_FEATURE) || defined(CONFIG_FIBER_FEATURE)
	unsigned int pon_mode;

	if (mib_get(MIB_PON_MODE, (void *)&pon_mode) != 0)
	{
		if ( pon_mode == GPON_MODE )
		{
			init_param.wanPortGponMode = 1;
			printf("Init RG with GPON mode.\n");
		}
		else {
			init_param.wanPortGponMode = 0;
			printf("Init RG with non-GPON mode.\n");
		}
	}
#endif
#endif

#ifdef MAC_FILTER
	// Get MAC filter white list callback function pointer from kernel space
	// & add MAC filter white list callback
	rtk_rg_callbackFunctionPtrGet_t callback_function_ptr_get_info;
	char macf_out_action;
	unsigned int mem;	

	mib_get(MIB_MACF_OUT_ACTION, (void *)&macf_out_action);
	if(macf_out_action == 0) {
		callback_function_ptr_get_info.callback_function_idx = MAC_ADD_BY_HW_CALLBACK_IDX;
		if(!rtk_rg_callback_function_ptr_get(&callback_function_ptr_get_info)) {
			mem = callback_function_ptr_get_info.callback_function_pointer;
			printf("------------>mem:%X , func:_rtk_rg_macAddByHwCallBack\n", mem);
			init_param.macAddByHwCallBack = mem;
		} else {
			printf("------------>rtk_rg_callback_function_ptr_get fail!\n");
		}
	} else {
		init_param.macAddByHwCallBack = NULL;
	}
#endif

#if defined(CONFIG_RTL_IGMP_SNOOPING)
	char igmp_mode;
	mib_get(MIB_MPMODE, (void *)&igmp_mode);
	if(igmp_mode & MP_IGMP_MASK)
		init_param.igmpSnoopingEnable = 1;
	else
		init_param.igmpSnoopingEnable = 0;

#ifdef CONFIG_00R0//iulian added cvlan for multicast
	init_param.ivlMulticastSupport =0;
#endif
	if((ret = rtk_rg_initParam_set(&init_param)) != SUCCESS)
	{
		DBPRINT(1, "rtk_rg_initParam_set failed! ret=%d\n", ret);
		return -1;
	}
#else
	if((ret = rtk_rg_initParam_set(&init_param)) != SUCCESS)
	{
		DBPRINT(1, "rtk_rg_initParam_set failed! ret=%d\n", ret);
		return -1;
	}
#endif
	printf("=============Init_rg_api SUCESS!!==================\n");
	unlink(RG_LAN_INF_IDX);

#ifdef CONFIG_00R0_NW
	special_handle_for_vlan_filter();
#endif

	// cvlan for multicast function, so RA from WAN will go to LAN
	// so trap to protocol stack
#if 0  //Change to use RTK_RG_Set_ACL_Route_V6_RA_NS_Filter instead since
       // it will impart bridge WAN, now only routing wan will trap
#ifdef CONFIG_IPV6
	add_acl_rule_for_v6_RA();
    add_acl_rule_for_v6_NS();
#endif
#endif
#ifdef CONFIG_00R0
	add_acl_rule_for_IGMP();
#endif
	

	sprintf(buf,"echo 1 > /proc/rg/proc_to_pipe\n");
	system(buf);
#ifdef CONFIG_00R0
	//Enable hardware patch : acl redirect port 5 to 4
	printf("Now enable the patch for small bandwidth!\n");
	sprintf(buf,"echo 1 > %s\n",smallbw_fpath);
	system(buf);
#endif
	RTK_Setup_Storm_Control();

	if(mbtd)
		RG_add_vxd_wlanDevMask(init_param.fwdVLAN_BIND_INTERNET);
		//avoid report from wan port to occupy multicast group
#ifdef CONFIG_RTL9602C_SERIES
	{
		//mask port 2
		system("echo 0xfffb > /proc/rg/igmp_report_ingress_filter_portmask");
	}
#elif defined(CONFIG_RTL9607C_SERIES)
	{
		//mask port 5
		system("echo 0xffdf > /proc/rg/igmp_report_ingress_filter_portmask");
	}
#else
	{		
		//apollo series mask port 4
		system("echo 0xffef > /proc/rg/igmp_report_ingress_filter_portmask");
	}
#endif

#if defined(CONFIG_RTL9607C_SERIES) || defined(CONFIG_LUNA_G3_SERIES)
	system("/bin/echo 1 > /proc/rg/protocolStackBypassRxQueue");
	RTK_RG_Control_Packet_Ingress_ACL_Rule_set();
	RTK_RG_Control_Packet_Egress_ACL_Rule_set();
	RTK_RG_add_TCP_syn_rate_limit();
	system("/bin/echo 1 > /proc/rg/flow_not_update_in_real_time");
	RTK_RG_add_ARP_broadcast_rate_limit();
#endif
	system("/bin/echo 1 > /proc/rg/inboundL4UnknownUdpConnDrop");
	//for avoid superfluous flood
	//system("/bin/echo 1 > /proc/rg/drop_superfluous_packet");
	//temply disable drop_superfluous_packet
	system("/bin/echo 0 > /proc/rg/drop_superfluous_packet");
	
	#ifdef WLAN_DUALBAND_CONCURRENT	
	system("echo 3 > /proc/rg/smp_wifi_11n_tx_cpu_from_cpu0");
    system("echo 3 > /proc/rg/smp_wifi_11n_tx_cpu_from_cpu1");
    system("echo 3 > /proc/rg/smp_wifi_11n_tx_cpu_from_cpu2");
    system("echo 3 > /proc/rg/smp_wifi_11n_tx_cpu_from_cpu3");
    system("echo 2 > /proc/irq/66/smp_affinity");
    system("echo 90 > /proc/rg/wlan0_flow_ctrl_on_threshold_mbps");
    system("echo 70 > /proc/rg/wlan0_flow_ctrl_off_threshold_mbps");
    system("echo 500 > /proc/rg/wlan1_flow_ctrl_on_threshold_mbps");
    system("echo 400 > /proc/rg/wlan1_flow_ctrl_off_threshold_mbps");
    system("echo 1 > /proc/rg/disableWifiRxDistributed");
	#endif

	return SUCCESS;
}
void dump_lan_info(rtk_rg_lanIntfConf_t *lan_info)
{
	printf("lan_info->ip_version=%d\n", lan_info->ip_version);
	printf("lan_info->gmac=%02X:%02X:%02X:%02X:%02X:%02X\n", lan_info->gmac.octet[0],lan_info->gmac.octet[1],lan_info->gmac.octet[2],lan_info->gmac.octet[3],lan_info->gmac.octet[4],lan_info->gmac.octet[5]);
	printf("lan_info->ip_addr=0x%08x\n", lan_info->ip_addr);
	printf("lan_info->ip_network_mask=%08x\n", lan_info->ip_network_mask);
	printf("lan_info->ipv6_network_mask_length=%08x\n", lan_info->ipv6_network_mask_length);
	printf("lan_info->port_mask.portmask=0x%08x\n", lan_info->port_mask.portmask);
	printf("lan_info->untag_mask.portmask=0x%08x\n", lan_info->untag_mask.portmask);
	printf("lan_info->intf_vlan_id=%d\n", lan_info->intf_vlan_id);
	printf("lan_info->vlan_based_pri=%d\n", lan_info->vlan_based_pri);
	printf("lan_info->vlan_based_pri_enable=%d\n", lan_info->vlan_based_pri_enable);
	printf("lan_info->mtu=%d\n", lan_info->mtu);
	printf("lan_info->isIVL=%d\n", lan_info->isIVL);
	printf("lan_info->replace_subnet=%d\n", lan_info->replace_subnet);
}
/*
    Due to RG maximum support 8 interface
    We must add error control handle to avoid
    unexpected error.
*/
#define MAX_INTF_NUM 7
int Check_RG_Intf_Count(void)
{
	int remained_intf_count=0;
	int cur_intf_count=0;
	rtk_rg_intfInfo_t *intf_info = NULL;
	int i=0,valid_idx=0;
	intf_info = (rtk_rg_intfInfo_t *)malloc(sizeof(rtk_rg_intfInfo_t));
	if(intf_info == NULL){
		printf("%s-%d Can't get enough memory space!\n",__func__,__LINE__);
		goto Error_remain;
	}
	for(i=0; i<MAX_INTF_NUM; i++){
		valid_idx = i;
		if(rtk_rg_intfInfo_find(intf_info,&i)!=SUCCESS){
			//printf("%s-%d INTF:[%d] free to use!\n",__func__,__LINE__,i);
			remained_intf_count++;
		}else{
			//printf("%s-%d INTF:[%d] has already occupied\n",__func__,__LINE__,i);
			if(valid_idx != i)
				remained_intf_count++;
			else
				cur_intf_count++;
		}
	}
	free(intf_info);
	Error_remain:
	fprintf(stderr, "%s-%d remained:%d, used:%d\n",__func__,__LINE__,remained_intf_count,cur_intf_count);
	return remained_intf_count;
}
#ifdef CONFIG_USER_DHCPCLIENT_MODE
int rtk_rg_trap_dhcp_for_lan_dhcp_client(int enable)
{
	int acl_idx = -1;
	FILE *fp = NULL;
	rtk_rg_aclFilterAndQos_t acl;

	if(!enable)
	{
		if (!(fp = fopen(RG_LAN_DHCP_CLIENT_ACL_RULE_FILE, "r")))
		{
			fprintf(stderr, "ERROR! %s\n", strerror(errno));
			return -1;
		}

		while (fscanf(fp, "%d\n", &acl_idx) != EOF)
		{
			if (rtk_rg_aclFilterAndQos_del(acl_idx))
				DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", acl_idx);
		}
		fclose(fp);
		unlink(RG_LAN_DHCP_CLIENT_ACL_RULE_FILE);
	}
	else
	{
		if (!(fp = fopen(RG_LAN_DHCP_CLIENT_ACL_RULE_FILE, "w")))
		{
			fprintf(stderr, "ERROR! %s\n", strerror(errno));
			return -1;
		}
		//add rule
		memset(&acl, 0, sizeof(rtk_rg_aclFilterAndQos_t));
		acl.fwding_type_and_direction =  ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
		acl.action_type = ACL_ACTION_TYPE_TRAP_TO_PS;
		acl.acl_weight = RG_TRAP_ACL_WEIGHT;
		acl.filter_fields |= INGRESS_L4_DPORT_RANGE_BIT | INGRESS_L4_SPORT_RANGE_BIT;
		acl.ingress_src_l4_port_start = acl.ingress_src_l4_port_end = 67;
		acl.ingress_dest_l4_port_start = acl.ingress_dest_l4_port_end = 68;
		acl.filter_fields |= INGRESS_PORT_BIT;
		acl.ingress_port_mask.portmask = RG_get_lan_phyPortMask(0xf);
#ifdef WLAN_SUPPORT //master and slave ext port
		acl.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN0));
		acl.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN1));
		//acl.filter_fields |= INGRESS_WLANDEV_BIT;
		//acl.ingress_wlanDevMask = ((1<<WLAN_SSID_NUM)-1)<<RG_RET_MBSSID_MASTER_ROOT_INTF | ((1<<WLAN_SSID_NUM)-1)<< RG_RET_MBSSID_SLAVE_ROOT_INTF | 1<<RG_RET_MBSSID_MASTER_WDS7_INTF;
#endif

		if(rtk_rg_aclFilterAndQos_add(&acl, &acl_idx) == 0)
			fprintf(fp, "%d\n", acl_idx);
		else
			fprintf(stderr, "<%s:%d> rtk_rg_aclFilterAndQos_add failed!\n", __func__, __LINE__);
		fclose(fp);		
	}

	return 0;
}
#endif
int RG_reset_LAN(void)
{
	FILE *fp=NULL;
	int lanIdx=-1;
	int lanIntfIdx = -1;
	int ret = 0;
	unsigned char value[6], ip_version=IPVER_V4V6, vchar, ipv6_addr[IPV6_ADDR_LEN], ipv6_prefix_len;
	struct ipv6_ifaddr ip6_addr[6];
	char ipv6addr_str[64], cur_ip6addr_str[64];
	rtk_rg_intfInfo_t *intf_info = NULL;
	rtk_rg_lanIntfConf_t *lan_info = NULL;
#ifdef CONFIG_USER_DHCPCLIENT_MODE
	struct in_addr inAddr;
	unsigned char dhcp_mode = 0;
#endif
	if(!(fp = fopen(RG_LAN_INF_IDX, "r"))){
		ret = -1;
		goto ErrorC;
	}
	intf_info = (rtk_rg_intfInfo_t *)malloc(sizeof(rtk_rg_intfInfo_t));
	if(intf_info == NULL){
		printf("%s-%d Can't get enough memory space!\n",__func__,__LINE__);
		ret = -1;
		goto ErrorC;
	}
	lan_info = (rtk_rg_lanIntfConf_t *)malloc(sizeof(rtk_rg_lanIntfConf_t));
	if(lan_info == NULL){
		printf("%s-%d Can't get enough memory space!\n",__func__,__LINE__);
		ret = -1;
		goto ErrorB;
	}

	memset(lan_info,0,sizeof(rtk_rg_lanIntfConf_t));
	memset(intf_info,0,sizeof(rtk_rg_intfInfo_t));

	while(fscanf(fp, "%d\n", &lanIdx) != EOF)
	{
		if(rtk_rg_intfInfo_find(intf_info,&lanIdx)!=SUCCESS){
			printf("%s-%d Can't find the lan interface idx:%d!",__func__,__LINE__,lanIdx);
			ret = -2;
			goto ErrorA;
		}
		memcpy(lan_info,&(intf_info->lan_intf),sizeof(rtk_rg_lanIntfConf_t));
		//clean lan ip info and force to zero, RG will flush lan routing info.
		//but keep lan intf index.
		lan_info->replace_subnet = 1;
		lan_info->ip_addr=0;
		if((rtk_rg_lanInterface_add(lan_info,&lanIntfIdx))!=SUCCESS)
		{
			DBPRINT(1, "Add LAN interface failed! lanIntfIdx=%d\n",lanIntfIdx);
			ret = -2;
			goto ErrorA;
		}
#ifdef CONFIG_USER_DHCPCLIENT_MODE
		rtk_rg_trap_dhcp_for_lan_dhcp_client(0);
		mib_get(MIB_DHCP_MODE, (void *)&dhcp_mode);
		if(dhcp_mode == DHCP_LAN_CLIENT)
		{
			rtk_rg_trap_dhcp_for_lan_dhcp_client(1);
			if(getInAddr(LANIF, SUBNET_MASK, &inAddr) == 1 /*&& ntohl(inAddr.s_addr)*/)
			{
				lan_info->ip_network_mask = ntohl(inAddr.s_addr);
				if(getInAddr(LANIF, IP_ADDR, &inAddr) == 1)
					lan_info->ip_addr = ntohl(inAddr.s_addr);
			}
		}
		else
#endif
		{
			if (mib_get(MIB_ADSL_LAN_IP, (void *)value) != 0)
			{
				lan_info->ip_addr=ntohl((((struct in_addr *)value)->s_addr)); //192.168.1.1
			}
			if (mib_get(MIB_ADSL_LAN_SUBNET, (void *)value) != 0)
			{
				lan_info->ip_network_mask=ntohl((((struct in_addr *)value)->s_addr)); //255.255.255.0
			}
		}
#ifdef CONFIG_IPV6
		mib_get(MIB_LAN_IP_VERSION1, (void *)&ip_version);
		lan_info->ip_version=ip_version;
		if(ip_version == IPVER_V4V6 || ip_version == IPVER_V6ONLY)
		{
			mib_get(MIB_LAN_IPV6_MODE1, (void *)&vchar);
			if(vchar == 0) // IPv6 address mode is auto
			{
				getifip6(LANIF, IPV6_ADDR_UNICAST, ip6_addr, 6);
				memcpy(lan_info->ipv6_addr.ipv6_addr, &ip6_addr[0].addr, IPV6_ADDR_LEN);
				lan_info->ipv6_network_mask_length = ip6_addr[0].prefix_len;
			}
			else
			{
				mib_get(MIB_LAN_IPV6_ADDR1, (void *)ipv6_addr);
				mib_get(MIB_LAN_IPV6_PREFIX_LEN1, (void *)&ipv6_prefix_len);
				memcpy(lan_info->ipv6_addr.ipv6_addr, ipv6_addr, IPV6_ADDR_LEN);
				lan_info->ipv6_network_mask_length = ipv6_prefix_len;
				inet_ntop(PF_INET6, ipv6_addr, ipv6addr_str, sizeof(ipv6addr_str));
				sprintf(ipv6addr_str, "%s/%d", ipv6addr_str, ipv6_prefix_len);
				getifip6(LANIF, IPV6_ADDR_UNICAST, ip6_addr, 6);
				inet_ntop(PF_INET6, &ip6_addr[0].addr, cur_ip6addr_str, sizeof(cur_ip6addr_str));
				sprintf(cur_ip6addr_str, "%s/%d", cur_ip6addr_str, ip6_addr[0].prefix_len);
				va_cmd(IFCONFIG, 3, 1, LANIF, "del", cur_ip6addr_str);
				va_cmd(IFCONFIG, 3, 1, LANIF, "add", ipv6addr_str);
			}
		}
#endif
		lan_info->replace_subnet = 1;
		//dump_lan_info(lan_info);
		if((rtk_rg_lanInterface_add(lan_info,&lanIntfIdx))!=SUCCESS)
		{
			DBPRINT(1, "Add LAN interface failed! lanIntfIdx=%d\n",lanIntfIdx);
			ret = -2;
			goto ErrorA;
		}
	}
ErrorA:

	if(lan_info)
		free(lan_info);
ErrorB:
	if(intf_info)
		free(intf_info);

ErrorC:
	if(fp)
	fclose(fp);

	return ret;
}
#ifdef CONFIG_IPV6
int set_LAN_IPv6_IP()
{
	unsigned char value[6], ip_version=IPVER_V4V6, vchar, ipv6_addr[IPV6_ADDR_LEN], ipv6_prefix_len;
	struct ipv6_ifaddr ip6_addr[6];
	char ipv6addr_str[64], cur_ip6addr_str[64];

	mib_get(MIB_LAN_IP_VERSION1, (void *)&ip_version);
	if(ip_version == IPVER_V4V6 || ip_version == IPVER_V6ONLY)
	{
		mib_get(MIB_LAN_IPV6_MODE1, (void *)&vchar);
		if(vchar != 0) // IPv6 address mode is manual
		{
			mib_get(MIB_LAN_IPV6_ADDR1, (void *)ipv6_addr);
			mib_get(MIB_LAN_IPV6_PREFIX_LEN1, (void *)&ipv6_prefix_len);

			inet_ntop(PF_INET6, ipv6_addr, ipv6addr_str, sizeof(ipv6addr_str));
			sprintf(ipv6addr_str, "%s/%d", ipv6addr_str, ipv6_prefix_len);

			getifip6(LANIF, IPV6_ADDR_UNICAST, ip6_addr, 6);
			inet_ntop(PF_INET6, &ip6_addr[0].addr, cur_ip6addr_str, sizeof(cur_ip6addr_str));
			sprintf(cur_ip6addr_str, "%s/%d", cur_ip6addr_str, ip6_addr[0].prefix_len);

			va_cmd(IFCONFIG, 3, 1, LANIF, "del", cur_ip6addr_str);
			va_cmd(IFCONFIG, 3, 1, LANIF, "add", ipv6addr_str);
		}
	}
	return 0;
}
#endif

int Init_RG_ELan(int isUnTagCPort, int isRoutingWan)
{
	rtk_rg_lanIntfConf_t lan_info;
	int lanIntfIdx = -1;
	unsigned char value[6], ip_version=IPVER_V4V6, vchar, ipv6_addr[IPV6_ADDR_LEN], ipv6_prefix_len;
	int i;
	int wanPhyPort=0, vlan_id;
	unsigned int portMask = 0;
	struct ipv6_ifaddr ip6_addr[6];
	char ipv6addr_str[64], cur_ip6addr_str[64];
	FILE *fp;
	MIB_CE_ATM_VC_T wan_entry;
	int untag_cpu_port = 0;
	int total_entry;
#ifdef CONFIG_USER_DHCPCLIENT_MODE
	struct in_addr inAddr;
	unsigned char dhcp_mode = 0;
#endif

#if 0
	Init_rg_api();
	DBPRINT(2, "Init_rg_api() on!\n");
#else
	DBPRINT(0, "Init_rg_api() off!!\n");
	RG_Del_All_LAN_Interfaces();
#endif
	memset(&lan_info,0,sizeof(lan_info));

	mib_get(MIB_LAN_IP_VERSION1, (void *)&ip_version);
	lan_info.ip_version=ip_version;

#ifdef CONFIG_IPV6
	if(ip_version == IPVER_V4V6 || ip_version == IPVER_V6ONLY)
	{
		setup_disable_ipv6(LANIF, 0);

		mib_get(MIB_LAN_IPV6_MODE1, (void *)&vchar);
		if(vchar == 0) // IPv6 address mode is auto
		{
			getifip6(LANIF, IPV6_ADDR_UNICAST, ip6_addr, 6);
			memcpy(lan_info.ipv6_addr.ipv6_addr, &ip6_addr[0].addr, IPV6_ADDR_LEN);
			lan_info.ipv6_network_mask_length = ip6_addr[0].prefix_len;
		}
		else
		{
			mib_get(MIB_LAN_IPV6_ADDR1, (void *)ipv6_addr);
			mib_get(MIB_LAN_IPV6_PREFIX_LEN1, (void *)&ipv6_prefix_len);
			memcpy(lan_info.ipv6_addr.ipv6_addr, ipv6_addr, IPV6_ADDR_LEN);
			lan_info.ipv6_network_mask_length = ipv6_prefix_len;

			inet_ntop(PF_INET6, ipv6_addr, ipv6addr_str, sizeof(ipv6addr_str));
			sprintf(ipv6addr_str, "%s/%d", ipv6addr_str, ipv6_prefix_len);

			getifip6(LANIF, IPV6_ADDR_UNICAST, ip6_addr, 6);
			inet_ntop(PF_INET6, &ip6_addr[0].addr, cur_ip6addr_str, sizeof(cur_ip6addr_str));
			sprintf(cur_ip6addr_str, "%s/%d", cur_ip6addr_str, ip6_addr[0].prefix_len);

			va_cmd(IFCONFIG, 3, 1, LANIF, "del", cur_ip6addr_str);
			va_cmd(IFCONFIG, 3, 1, LANIF, "add", ipv6addr_str);
		}
	}
	else
	{
		setup_disable_ipv6(LANIF, 1);
	}
#endif

	if(ip_version == IPVER_V4V6 || ip_version == IPVER_V4ONLY)
	{
#ifdef CONFIG_USER_DHCPCLIENT_MODE
		rtk_rg_trap_dhcp_for_lan_dhcp_client(0);
		mib_get(MIB_DHCP_MODE, (void *)&dhcp_mode);
		if(dhcp_mode == DHCP_LAN_CLIENT)
		{
			rtk_rg_trap_dhcp_for_lan_dhcp_client(1);
			if(getInAddr(LANIF, SUBNET_MASK, &inAddr) == 1 /*&& ntohl(inAddr.s_addr)*/)
			{
				lan_info.ip_network_mask = ntohl(inAddr.s_addr);
				if(getInAddr(LANIF, IP_ADDR, &inAddr) == 1)
					lan_info.ip_addr = ntohl(inAddr.s_addr);
			}
		}
		else
#endif
		{
			if (mib_get(MIB_ADSL_LAN_IP, (void *)value) != 0)
			{
				lan_info.ip_addr=ntohl((((struct in_addr *)value)->s_addr)); //192.168.1.1
			}
			if (mib_get(MIB_ADSL_LAN_SUBNET, (void *)value) != 0)
			{
				lan_info.ip_network_mask=ntohl((((struct in_addr *)value)->s_addr));
			}
		}
	}

	if (mib_get(MIB_ELAN_MAC_ADDR, (void *)value) != 0)
	{
		for(i =0;i<6;i++)
			lan_info.gmac.octet[i]=value[i];
	}

#if 0
	if(mib_get(MIB_WAN_PHY_PORT , (void *)&wanPhyPort) == 0){
		printf("get MIB_WAN_PHY_PORT failed!!!\n");
		wanPhyPort=RTK_RG_MAC_PORT3 ; //for 0371 default
	}
#endif
#if 0
/* We only support 1 bridge WAN currently,
   so we do not let user configure LAN VID.
   We need to decide LAN vid here.
   Fix me if you have better idea.
*/
	total_entry = mib_chain_total(MIB_ATM_VC_TBL);

	for(i = 0 ; i < total_entry ; i++)
	{
		if(mib_chain_get(MIB_ATM_VC_TBL, i, &wan_entry) == 0)
			continue;

		if(wan_entry.cmode == CHANNEL_MODE_BRIDGE)
		{
#ifndef CONFIG_00R0//Didn't need change VID when macDesc is up
			if(wan_entry.vlan)
			{
				untag_cpu_port = 0;
				vlan_id = wan_entry.vid;
			}
			else
			{
				untag_cpu_port = 1;
				vlan_id = 9;
			}
#else
			untag_cpu_port = 0;
			vlan_id = 9;
#endif
			break;
		}
	}
#endif
	if(mib_get(MIB_LAN_VLAN_ID1, (void *)&vlan_id) != 0)
		lan_info.intf_vlan_id = vlan_id;
	
	lan_info.vlan_based_pri=-1;

	lan_info.mtu=1500;

	portMask = RG_get_all_lan_phyPortMask();
	if(isRoutingWan){
		portMask &= (~(RG_get_wan_phyPortMask()));
	}
	#if 0
	lan_info.port_mask.portmask=((1<<RTK_RG_PORT0)|(1<<RTK_RG_PORT1)|(1<<RTK_RG_PORT2)|(1<<RTK_RG_PORT3));
	lan_info.untag_mask.portmask=((1<<RTK_RG_MAC_PORT0)|(1<<RTK_RG_MAC_PORT1)|(1<<RTK_RG_MAC_PORT2));
	#endif
	#ifdef CONFIG_RTL9602C_SERIES
	lan_info.port_mask.portmask=portMask|(1<<RTK_RG_EXT_PORT0)|(1<<RTK_RG_PORT_CPU);
	lan_info.untag_mask.portmask = portMask;
	#else
	lan_info.port_mask.portmask=portMask|(1<<RTK_RG_EXT_PORT0)|(1<<RTK_RG_EXT_PORT1)|(1<<RTK_RG_EXT_PORT2)|(1<<RTK_RG_EXT_PORT3)|(1<<RTK_RG_EXT_PORT4)|(1<<RTK_RG_PORT_CPU);
	lan_info.untag_mask.portmask = portMask;
	#endif
	if(isUnTagCPort)
		lan_info.untag_mask.portmask|=(1<<RTK_RG_MAC_PORT_CPU);

	if((rtk_rg_lanInterface_add(&lan_info,&lanIntfIdx))!=SUCCESS)
	{
		DBPRINT(1, "Add LAN interface 1 failed!\n");
		return -1;
	}
	if(fp = fopen(RG_LAN_INF_IDX, "w"))
	{
		fprintf(fp, "%d\n", lanIntfIdx);
		DBPRINT(0, "LAN interface index=%d\n", lanIntfIdx);
		fclose(fp);
	}
	else
		fprintf(stderr, "Open %s failed! %s\n", RG_LAN_INF_IDX, strerror(errno));

	RG_add_vxd_wlanDevMask(vlan_id);

	return SUCCESS;
}

/*Vlan and port binding will effect the OMCI CF rules
    so, we must check rules after setting vlan port mapping
*/
#if defined(CONFIG_RTK_L34_ENABLE) && defined(CONFIG_GPON_FEATURE)

int RTK_RG_Sync_OMCI_WAN_INFO(void)
{
	MIB_CE_ATM_VC_T entryVC;
	int totalVC_entry,i,wan_idx=-1,wanIntfIdx=-1;
	int omci_service=-1;
	int omci_mode=-1;
	int omci_bind=-1;
	int ret=0;
	char cmdStr[64];
	rtk_rg_intfInfo_t *intf_info = NULL;
	rtk_rg_wanIntfConf_t *wan_info_p = NULL;
	char vlan_based_pri=-1;
	int pon_mode;

	mib_get(MIB_PON_MODE, (void *)&pon_mode);
	if(pon_mode != GPON_MODE)
		return -2;

	intf_info = (rtk_rg_intfInfo_t *)malloc(sizeof(rtk_rg_intfInfo_t));
	if(intf_info == NULL){
		printf("%s-%d Can't get enough memory space!\n",__func__,__LINE__);
		return -1;
	}
	
#if ! defined(_LINUX_2_6_) && defined(CONFIG_TR142_MODULE)
	if( 1 /*SyncALL*/){
		snprintf(cmdStr, sizeof(cmdStr)-1,"echo clear > %s", TR142_WAN_IDX_MAP);
		system(cmdStr);
	}
#endif
	memset(intf_info,0,sizeof(rtk_rg_intfInfo_t));
	totalVC_entry = mib_chain_total(MIB_ATM_VC_TBL);
	for(i=0;i<totalVC_entry;i++){
		if(mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&entryVC) == 0)
			continue;
		if(rtk_rg_intfInfo_find(intf_info,&entryVC.rg_wan_idx)!=SUCCESS){
			printf("%s-%d Can't find the wan interface idx:%d!",__func__,__LINE__,entryVC.rg_wan_idx);
			free(intf_info);;
			return -1;
		}
		wan_info_p = &(intf_info->wan_intf.wan_intf_conf);
#ifdef CONFIG_RTL867X_VLAN_MAPPING /*for vlan binding, we don't need sync rg WAN info, but need to sync omci waninfo*/
		//for vlan binding, if we change binding relationship, we must sync rg WAN info.
		#ifdef CONFIG_RTL9602C_SERIES
		wan_info_p->port_binding_mask.portmask = RG_get_lan_phyPortMask(entryVC.itfGroup & 0x3);
		wan_info_p->wlan0_dev_binding_mask = ((entryVC.itfGroup & 0xf8) >> 3);
		#else
		wan_info_p->port_binding_mask.portmask = RG_get_lan_phyPortMask(entryVC.itfGroup & 0xf);
		wan_info_p->wlan0_dev_binding_mask = ((entryVC.itfGroup & 0x1f0) >> 4);
		#endif
#if defined(WLAN_DUALBAND_CONCURRENT)
#ifdef CONFIG_RTL_CLIENT_MODE_SUPPORT
		wan_info_p->wlan0_dev_binding_mask |= ((entryVC.itfGroup & 0x3e00) << 5);
#else
		wan_info_p->wlan0_dev_binding_mask |= ((entryVC.itfGroup & 0x3e00) << 4);
#endif
#endif				
		//wan_info_p->port_binding_mask.portmask = RG_get_lan_phyPortMask(entryVC.itfGroup & 0xf);
		//wan_info_p->wlan0_dev_binding_mask = ((entryVC.itfGroup & 0x1f0) >> 4);
		wan_info_p->forcedAddNewIntf = 0;
		if((ret = rtk_rg_wanInterface_add(wan_info_p, &entryVC.rg_wan_idx))!=SUCCESS){
			printf("%s-%d rtk_rg_wanInterface_add fail! ret=%d\n",__func__,__LINE__,ret);
			free(intf_info);
			return -1;
		}
#endif
		if((wan_info_p->port_binding_mask.portmask == 0) && (wan_info_p->vlan_binding_mask.portmask == 0) && (wan_info_p->wlan0_dev_binding_mask == 0))
		{
			if(entryVC.itfGroup > 0 || wan_info_p->vlan_binding_mask.portmask > 0){
				omci_bind=1;
			}else{
				omci_bind=0;
			}
#if ! defined(_LINUX_2_6_) && defined(CONFIG_TR142_MODULE)
			//Check port bing change
			if(omci_bind != check_wan_omci_portbing(&entryVC)) 
			{
#endif
			//none binding wan, reset omci wan info...
			//omci wan info can't write duplicate, must delete it before adding.
			snprintf(cmdStr, sizeof(cmdStr),"echo %d %d %d %d %d %d %d > %s",entryVC.rg_wan_idx,0,0,0,0,0,0,OMCI_WAN_INFO);
			system(cmdStr);
			if(wan_info_p->none_internet)
				omci_service = 0;
			else
				omci_service = 1;

			switch(entryVC.cmode){
				case CHANNEL_MODE_IPOE:
					if( (entryVC.IpProtocol == IPVER_IPV4_IPV6) && entryVC.napt ==1)
						omci_mode = OMCI_MODE_IPOE_V4NAPT_V6;
					else
						omci_mode = OMCI_MODE_IPOE;
					break;
				case CHANNEL_MODE_PPPOE:
					if( (entryVC.IpProtocol == IPVER_IPV4_IPV6) && entryVC.napt ==1)
						omci_mode = OMCI_MODE_PPPOE_V4NAPT_V6;
					else
						omci_mode = OMCI_MODE_PPPOE;
					break;
				case CHANNEL_MODE_BRIDGE:
					omci_mode = OMCI_MODE_BRIDGE;
					break;
				default:
					printf("unknow mode %d\n",omci_mode);
					break;
			}

			//sync omci cf rules.
			/*untag wan, omci egress vlan id = -1*/
			if(entryVC.vlan == 2)
				wan_info_p->egress_vlan_id = 4095;
			else{
				if(!wan_info_p->egress_vlan_tag_on)
					wan_info_p->egress_vlan_id = -1;
			}
			if(entryVC.vprio)
			{
				vlan_based_pri=(entryVC.vprio)-1;
			}
			else
			{
				vlan_based_pri=-1;
			}
#if ! defined(_LINUX_2_6_) && defined(CONFIG_TR142_MODULE)
			char ifname[IFNAMSIZ] = {0};
			ifGetName(PHY_INTF(entryVC.ifIndex), ifname, sizeof(ifname));
			snprintf(cmdStr, sizeof(cmdStr)-1,"echo %d %s %s %d > %s", entryVC.rg_wan_idx, ALIASNAME_NAS0, ifname, omci_bind, TR142_WAN_IDX_MAP);
			system(cmdStr);
#endif
			snprintf(cmdStr, sizeof(cmdStr),"echo %d %d %d %d %d %d %d > %s",entryVC.rg_wan_idx,wan_info_p->egress_vlan_id,vlan_based_pri,omci_mode,omci_service,omci_bind,1,OMCI_WAN_INFO);
			system(cmdStr);
#if ! defined(_LINUX_2_6_) && defined(CONFIG_TR142_MODULE)
			}
#endif
		}
	}
	free(intf_info);
	return 0;
}
#endif
static inline int RG_get_wan_type(MIB_CE_ATM_VC_Tp entry)
{
	if(entry == NULL)
		return -1;

	switch(entry->cmode)
	{
	case CHANNEL_MODE_BRIDGE:
		return RTK_RG_BRIDGE;
	case CHANNEL_MODE_IPOE:
		#ifdef CONFIG_IPV6
		if(entry->IpProtocol == IPVER_IPV6){
			//IPv6 only, then need to check v6's part to know it's static or dhcp
			if(entry->AddrMode == IPV6_WAN_STATIC)
				return RTK_RG_STATIC;
			else
				return RTK_RG_DHCP;
		}
		else
		#endif
		{
			if(entry->ipDhcp == DHCP_CLIENT)
				return RTK_RG_DHCP;
			else
				return RTK_RG_STATIC;
		}
	case CHANNEL_MODE_PPPOE:
		return RTK_RG_PPPoE;
	default:
		return -1;
	}
}
void dump_wan_info(rtk_rg_wanIntfConf_t *wan_info)
{
	printf("wan_info->wan_type=%d\n", wan_info->wan_type);
	printf("wan_info->gmac=%02X:%02X:%02X:%02X:%02X:%02X\n", wan_info->gmac.octet[0],wan_info->gmac.octet[1],wan_info->gmac.octet[2],wan_info->gmac.octet[3],wan_info->gmac.octet[4],wan_info->gmac.octet[5]);
	printf("wan_info->wan_port_idx=%d\n", wan_info->wan_port_idx);
	printf("wan_info->port_binding_mask=%08x\n", wan_info->port_binding_mask);
	printf("wan_info->vlan_binding_mask=%08x\n", wan_info->vlan_binding_mask);
	printf("wan_info->egress_vlan_tag_on=%d\n", wan_info->egress_vlan_tag_on);
	printf("wan_info->egress_vlan_id=%d\n", wan_info->egress_vlan_id);
	printf("wan_info->vlan_based_pri_enable=%d\n", wan_info->vlan_based_pri_enable);
	printf("wan_info->vlan_based_pri=%d\n", wan_info->vlan_based_pri);
	printf("wan_info->isIVL=%d\n", wan_info->isIVL);
	printf("wan_info->none_internet=%d\n", wan_info->none_internet);
	printf("wan_info->forcedAddNewIntf=%d\n", wan_info->forcedAddNewIntf);
	printf("wan_info->wlan0_dev_binding_mask=%08x\n", wan_info->wlan0_dev_binding_mask);
}
void dump_ipStaticInfo(rtk_rg_ipStaticInfo_t *staticInfo)
{
	printf("staticInfo->ipv4_default_gateway_on=%d\n", staticInfo->ipv4_default_gateway_on);
	printf("staticInfo->gw_mac_auto_learn_for_ipv4=%d\n", staticInfo->gw_mac_auto_learn_for_ipv4);
	printf("staticInfo->ip_addr=%08x\n", staticInfo->ip_addr);
	printf("staticInfo->ip_network_mask=%08x\n", staticInfo->ip_network_mask);
	printf("staticInfo->gateway_ipv4_addr=%08x\n", staticInfo->gateway_ipv4_addr);
	printf("staticInfo->mtu=%08x\n", staticInfo->mtu);
	printf("staticInfo->napt_enable=%d\n", staticInfo->napt_enable);
}
void dump_ipPppoeClientInfoA(rtk_rg_pppoeClientInfoAfterDial_t *pppoeInfoA)
{
	unsigned char gw_mac[6];
	printf("pppoeInfoA->hw_info.napt_enable=%d\n", pppoeInfoA->hw_info.napt_enable);
	printf("pppoeInfoA->hw_info.ip_addr=0x%08x\n", pppoeInfoA->hw_info.ip_addr);
	printf("pppoeInfoA->hw_info.ip_network_mask=0x%08x\n", pppoeInfoA->hw_info.ip_network_mask);
	printf("pppoeInfoA->hw_info.ipv4_default_gateway_on=0x%08x\n", pppoeInfoA->hw_info.ipv4_default_gateway_on);
	printf("pppoeInfoA->hw_info.gateway_ipv4_addr=0x%08x\n", pppoeInfoA->hw_info.gateway_ipv4_addr);
	printf("pppoeInfoA->hw_info.mtu=0x%08x\n", pppoeInfoA->hw_info.mtu);
	printf("pppoeInfoA->hw_info.gw_mac_auto_learn_for_ipv4=%d\n", pppoeInfoA->hw_info.gw_mac_auto_learn_for_ipv4);
	memcpy(gw_mac, pppoeInfoA->hw_info.gateway_mac_addr_for_ipv4.octet, 6);
	printf("pppoeInfoA->hw_info.gw_mac=>%02x:%02x:%02x:%02x:%02x:%02x\n", gw_mac[0],gw_mac[1],gw_mac[2],gw_mac[3],gw_mac[4],gw_mac[5]);
}
void dump_ipDhcpClientInfo(rtk_rg_ipDhcpClientInfo_t *dhcpClient_info)
{
	printf("dhcpClient_info->stauts=%d\n", dhcpClient_info->stauts);
	printf("dhcpClient_info->hw_info.ipv4_default_gateway_on=%d\n", dhcpClient_info->hw_info.ipv4_default_gateway_on);
	printf("dhcpClient_info->hw_info.gw_mac_auto_learn_for_ipv4=%d\n", dhcpClient_info->hw_info.gw_mac_auto_learn_for_ipv4);
	printf("dhcpClient_info->hw_info.ip_addr=0x%08x\n", dhcpClient_info->hw_info.ip_addr);
	printf("dhcpClient_info->hw_info.ip_network_mask=0x%08x\n",dhcpClient_info->hw_info.ip_network_mask);
	printf("dhcpClient_info->hw_info.mtu=0x%08x\n", dhcpClient_info->hw_info.mtu);
	printf("dhcpClient_info->hw_info.napt_enable=%d\n", dhcpClient_info->hw_info.napt_enable);
	printf("dhcpClient_info->hw_info.gateway_ipv4_addr=0x%08x\n", dhcpClient_info->hw_info.gateway_ipv4_addr);
}
int RG_reset_static_route(void)
{
	unsigned int entryNum, i;
	MIB_CE_IP_ROUTE_T Entry;

	entryNum = mib_chain_total(MIB_IP_ROUTE_TBL);
	for (i=0; i<entryNum; i++) {
		if (!mib_chain_get(MIB_IP_ROUTE_TBL, i, (void *)&Entry))
		{
			continue;
		}
		Entry.rg_wan_idx = -1;
		mib_chain_update(MIB_IP_ROUTE_TBL, (void *)&Entry, i);
	}
	printf("%s-%d DONE !\n",__func__,__LINE__);
#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif
	return 0;
}
int RG_del_static_route(MIB_CE_IP_ROUTE_T *entry)
{
	int ret=0;

	if(entry->rg_wan_idx > 0){
		ret = RG_WAN_Interface_Del(entry->rg_wan_idx);
		entry->rg_wan_idx = -1;
	}
	return ret;
}
#ifdef ROUTING
int RG_add_static_route_PPP(MIB_CE_IP_ROUTE_T *entry,MIB_CE_ATM_VC_T *vc_entry,int entryID)
{
	rtk_rg_wanIntfConf_t *wan_info = NULL;
	rtk_rg_intfInfo_t *intf_info = NULL;
	rtk_rg_pppoeClientInfoAfterDial_t *pppoeClientInfoA=NULL;
	int wan_idx=-1, wanIntfIdx=-1, ret=-1;
	int omci_service=-1;
	int omci_bind=-1;
	char cmdStr[64];
#if defined(CONFIG_RTK_L34_ENABLE) && defined(CONFIG_GPON_FEATURE)
	int pon_mode=0;
	mib_get(MIB_PON_MODE, (void *)&pon_mode);
#endif
	intf_info = (rtk_rg_intfInfo_t *)malloc(sizeof(rtk_rg_intfInfo_t));
	if(intf_info == NULL){
		printf("%s-%d Can't get enough memory space!\n",__func__,__LINE__);
		ret = -1;
		goto E_PPPOE_4;
	}
	memset(intf_info,0,sizeof(rtk_rg_intfInfo_t));
	wan_info = (rtk_rg_wanIntfConf_t *)malloc(sizeof(rtk_rg_wanIntfConf_t));
	if(wan_info == NULL){
		printf("%s-%d Can't get enough memory space!\n",__func__,__LINE__);
		ret = -1;
		goto E_PPPOE_3;
	}
	memset(wan_info,0,sizeof(rtk_rg_wanIntfConf_t));
	wan_idx = vc_entry->rg_wan_idx;
	if(rtk_rg_intfInfo_find(intf_info,&wan_idx)!=SUCCESS){
		printf("%s-%d Can't find the wan interface idx:%d!",__func__,__LINE__,wan_idx);
		ret = -1;
		goto E_PPPOE_2;
	}
	memcpy(wan_info,&(intf_info->wan_intf.wan_intf_conf),sizeof(rtk_rg_wanIntfConf_t));
	wan_info->forcedAddNewIntf = 1;
	if((ret = rtk_rg_wanInterface_add(wan_info, &wanIntfIdx))!=SUCCESS){
		printf("%s-%d rtk_rg_wanInterface_add fail! ret=%d\n",__func__,__LINE__,ret);
		ret = -1;
		goto E_PPPOE_2;
	}
#if defined(CONFIG_RTK_L34_ENABLE) && defined(CONFIG_GPON_FEATURE)
	if(pon_mode == GPON_MODE){
		char vlan_based_pri=-1;
		/*untag wan, omci egress vlan id = -1*/
		if(vc_entry->vlan == 2)
			wan_info->egress_vlan_id = 4095;
		else{
			if(!wan_info->egress_vlan_tag_on)
				wan_info->egress_vlan_id = -1;
		}
		if(wan_info->none_internet)
			omci_service = 0;
		else
			omci_service = 1;
		if((wan_info->port_binding_mask.portmask > 0) || (wan_info->wlan0_dev_binding_mask > 0))
			omci_bind = 1;
		else
			omci_bind = 0;
		if(vc_entry->vprio)
		{
			vlan_based_pri=(vc_entry->vprio)-1;
		}
		else
		{
			vlan_based_pri=-1;
		}
		snprintf(cmdStr, sizeof(cmdStr),"echo %d %d %d %d %d %d %d > %s",wanIntfIdx,wan_info->egress_vlan_id,vlan_based_pri,0,omci_service,omci_bind,1,OMCI_WAN_INFO);
		system(cmdStr);
	}
#endif
	entry->rg_wan_idx = wanIntfIdx;
	pppoeClientInfoA = (rtk_rg_pppoeClientInfoAfterDial_t *)malloc(sizeof(rtk_rg_pppoeClientInfoAfterDial_t));
	if(pppoeClientInfoA == NULL){
		printf("%s-%d Can't get enough memory space!\n",__func__,__LINE__);
		ret = -1;
		goto E_PPPOE_2;
	}
	memset(pppoeClientInfoA,0,sizeof(rtk_rg_pppoeClientInfoAfterDial_t));
	memcpy(pppoeClientInfoA,&(intf_info->wan_intf.pppoe_info.after_dial),sizeof(rtk_rg_pppoeClientInfoAfterDial_t));
	pppoeClientInfoA->hw_info.gateway_ipv4_addr = pppoeClientInfoA->hw_info.ip_addr;
	pppoeClientInfoA->hw_info.ip_addr = ntohl(((struct in_addr *)entry->destID)->s_addr);
	pppoeClientInfoA->hw_info.ip_network_mask = ntohl(((struct in_addr *)entry->netMask)->s_addr);
	pppoeClientInfoA->hw_info.ipv4_default_gateway_on =0;
	dump_ipPppoeClientInfoA(pppoeClientInfoA);
	if((ret = rtk_rg_pppoeClientInfoAfterDial_set(entry->rg_wan_idx, pppoeClientInfoA))!=SUCCESS){
		printf("%s-%d add rtk_rg_pppoeClientInfoAfterDial_set fail! ret=%d\n",__func__,__LINE__,ret);
		ret = -1;
	}
	mib_chain_update(MIB_IP_ROUTE_TBL, entry, entryID);
E_PPPOE_1:
	if(pppoeClientInfoA)
		free(pppoeClientInfoA);
E_PPPOE_2:
	if(wan_info)
		free(wan_info);
E_PPPOE_3:
	if(intf_info)
		free(intf_info);
E_PPPOE_4:
	return ret;
}

#ifdef CONFIG_00R0 //iulian added 
int RG_add_static_route_by_acl(in_addr_t  ip_addr, in_addr_t netmask, in_addr_t gateway, int rg_wan_idx)
{
	int i,aclIdx=0, ret, wan_index;
	char filename[32];
	rtk_rg_aclFilterAndQos_t aclRule;
	rtk_rg_ipDhcpClientInfo_t *dhcpClient_info=NULL;
	rtk_rg_pppoeClientInfoAfterDial_t *pppoeClientInfo=NULL;
	rtk_rg_intfInfo_t intf_info;
	FILE *fp;

	wan_index = rg_wan_idx;
	/* Setting the DHCP WAN, becuase the */
	ret = rtk_rg_intfInfo_find(&intf_info, &wan_index);
	if(ret!=0 ){
		printf("Find RG interface for wan index %d Fail! Return -1!\n",wan_index);
		return -1;
	}

	if(wan_index != rg_wan_idx){
		printf("Can't RG interface for wan index %d Fail! Return -1!\n",wan_index);
		return -1;
	}
	if ( intf_info.wan_intf.wan_intf_conf.wan_type == RTK_RG_DHCP )	{ /* Setting the DHCP WAN  */
		memset(&dhcpClient_info,0,sizeof(rtk_rg_ipDhcpClientInfo_t));
		dhcpClient_info = &(intf_info.wan_intf.dhcp_client_info);
		if ( (dhcpClient_info->hw_info.static_route_with_arp != 1) || 
			(dhcpClient_info->hw_info.gateway_ipv4_addr != ntohl(gateway)) ) {
			dhcpClient_info->hw_info.static_route_with_arp=1;
		 	dhcpClient_info->hw_info.gateway_ipv4_addr = ntohl(gateway); //only allow one gateway in acl policy route 

			if(rtk_rg_dhcpClientInfo_set(rg_wan_idx, dhcpClient_info)!=SUCCESS)
			{
				printf("rtk_rg_dhcpClientInfo_set error!!!\n");
				return -1;
			}
		}
	}else if ( intf_info.wan_intf.wan_intf_conf.wan_type == RTK_RG_PPPoE ) {  /* Setting the PPPoE WAN  */
		memset(&pppoeClientInfo,0,sizeof(rtk_rg_pppoeClientInfoAfterDial_t));
		pppoeClientInfo = &(intf_info.wan_intf.pppoe_info.after_dial);
		if (pppoeClientInfo->hw_info.static_route_with_arp != 1) {
			pppoeClientInfo->hw_info.static_route_with_arp = 1;
			if((rtk_rg_pppoeClientInfoAfterDial_set(rg_wan_idx, pppoeClientInfo)) != SUCCESS){
				printf("rtk_rg_pppoeClientInfoAfterDial_set error!!!\n");
				return -1;
			}				
		}
	}
	else { /* Others wan type TBD */
	}
	
	/* Setting the ACL rule */
	sprintf(filename, "%s_%d", RG_ACL_POLICY_ROUTE, rg_wan_idx);
	if(!(fp = fopen(filename, "a")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -2;
	}

	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	aclRule.filter_fields = INGRESS_IPV4_DIP_RANGE_BIT;

	aclRule.action_type = ACL_ACTION_TYPE_POLICY_ROUTE;	
	aclRule.ingress_dest_ipv4_addr_start = ntohl(ip_addr & netmask);
	aclRule.ingress_dest_ipv4_addr_end = ntohl(ip_addr |~ netmask);
	aclRule.action_policy_route_wan = rg_wan_idx;

	if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0) {
		fprintf(fp,"%d\n",aclIdx);
	}
	else {
		printf("RG_add_static_route_by_acl QoS rule failed! (ret = %d)\n", ret);
		fclose(fp);
		return -1;
	}
	fclose(fp);
	return 0;
}


int RG_del_static_route_by_acl(int rg_wan_idx)
{
	FILE *fp;
	int aclIdx=-1;
	char filename[32];

	sprintf(filename, "%s_%d", RG_ACL_POLICY_ROUTE, rg_wan_idx);
	if(!(fp = fopen(filename, "r"))){
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -2;
	}
	while(fscanf(fp, "%d\n", &aclIdx) != EOF)
	{
		if(rtk_rg_aclFilterAndQos_del(aclIdx))
			DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", aclIdx);
	}
	fclose(fp);
	unlink(filename);
	return 0;
}


int RG_add_IPQos_WorkAround()
{
	char filename[32], cmdBuf[100];
	int acl_filter_idx, ret=0;
	rtk_rg_aclFilterAndQos_t acl_filter;
	memset(&acl_filter,0,sizeof(acl_filter));	
	FILE *fp;
	
	/* 1. delete  PPPoE 8864 priority 7 */
	sprintf(filename, "%s", RG_IPQOS_WORKAROUND);
	if(!(fp = fopen(filename, "w")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -2;
	}
	
	acl_filter.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	acl_filter.filter_fields = (INGRESS_PORT_BIT|INGRESS_ETHERTYPE_BIT|INGRESS_IPV4_TAGIF_BIT|INGRESS_IPV6_TAGIF_BIT);
	acl_filter.ingress_port_mask.portmask = ((1<<RTK_RG_PORT_PON)|(1<<RTK_RG_PORT_CPU));
	acl_filter.ingress_ethertype = 0x8864;
	acl_filter.ingress_ipv4_tagif = 0;
	acl_filter.ingress_ipv6_tagif = 0;
	acl_filter.action_type = ACL_ACTION_TYPE_QOS;
	acl_filter.qos_actions = ACL_ACTION_ACL_PRIORITY_BIT;
	acl_filter.action_acl_priority = 7;

	if(ret = rtk_rg_aclFilterAndQos_add(&acl_filter, &acl_filter_idx) == 0) {
		fprintf(fp,"%d\n",acl_filter_idx);
	}
	else {
		printf("%s QoS traffic failed! (ret = %d)\n", __FUNCTION__, ret);
		fclose(fp);
		return -1;
	}

	//Trap all packets come from LAN to CPU
	memset(&acl_filter,0,sizeof(acl_filter));	
	acl_filter.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	acl_filter.filter_fields = (INGRESS_PORT_BIT);
	acl_filter.ingress_port_mask.portmask = ((1<<RTK_RG_PORT0) | (1<<RTK_RG_PORT1) |(1<<RTK_RG_PORT2)| (1<<RTK_RG_PORT3)) ;
	acl_filter.action_type = ACL_ACTION_TYPE_TRAP;

	if(ret = rtk_rg_aclFilterAndQos_add(&acl_filter, &acl_filter_idx) == 0) {
		fprintf(fp,"%d\n",acl_filter_idx);
	}
	else {
		printf("%s QoS traffic failed! (ret = %d)\n", __FUNCTION__, ret);
		fclose(fp);
		return -1;
	}

	fclose(fp);
	/* 2.  Disable flow control, default is disable, pass it */
	/*
	rtk_rg_phyPortAbilityInfo_t ability;
	memset(&ability,0,sizeof(ability));
	ability.force_disable_phy = 0;
	ability.valid = 1;
	ability.speed = 1;
	ability.duplex = 1;
	ability.flowCtrl = 0;
	rtk_rg_phyPortForceAbility_set(RTK_RG_MAC_PORT2,ability);
	
	memset(&ability,0,sizeof(ability));
	ability.force_disable_phy = 0;
	ability.valid = 1;
	ability.speed = 2;
	ability.duplex = 1;
	ability.flowCtrl = 0;
	rtk_rg_phyPortForceAbility_set(RTK_RG_MAC_PORT3,ability);
	*/

	return 0;
}


int RG_del_IPQos_WorkAround()
{
	FILE *fp;
	int aclIdx=-1;
	char filename[32], cmdBuf[100];

	/* 1. Delete  PPPoE 8864 priority 7 */

	sprintf(filename, "%s", RG_IPQOS_WORKAROUND);
	
	if(!(fp = fopen(filename, "r"))){
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -2;
	}
	while(fscanf(fp, "%d\n", &aclIdx) != EOF)
	{
		if(rtk_rg_aclFilterAndQos_del(aclIdx))
			DBPRINT(1, "RG_del_IPQos_WorkAround failed! idx = %d\n", aclIdx);
	}
	fclose(fp);
	unlink(filename);

	/* 2.  Enable flow control */
	/*
	rtk_rg_phyPortAbilityInfo_t ability;
	rtk_rg_phyPortForceAbility_get(RTK_RG_MAC_PORT2,&ability);
	ability.flowCtrl = 1;
	rtk_rg_phyPortForceAbility_set(RTK_RG_MAC_PORT2,ability);
	
	rtk_rg_phyPortForceAbility_get(RTK_RG_MAC_PORT3,&ability);
	ability.flowCtrl = 1;
	rtk_rg_phyPortForceAbility_set(RTK_RG_MAC_PORT3,ability);
	*/
	return 0;
}


#endif

int RG_add_static_route(MIB_CE_IP_ROUTE_T *entry, char *mac_str, int entryID)
{
	rtk_rg_wanIntfConf_t *wan_info = NULL;
	rtk_rg_intfInfo_t *intf_info = NULL;
	rtk_rg_ipStaticInfo_t *staticInfo = NULL;
	rtk_rg_ipDhcpClientInfo_t *dhcpClient_info=NULL;
	int ret=0;
	char cmdStr[64];
	MIB_CE_ATM_VC_T entryVC;
	int totalVC_entry,i,wan_idx=-1,wanIntfIdx=-1;
#if defined(CONFIG_RTK_L34_ENABLE) && defined(CONFIG_GPON_FEATURE)
	int omci_service=-1;
	int omci_bind=-1;
	int pon_mode=0;
	mib_get(MIB_PON_MODE, (void *)&pon_mode);
#endif
	totalVC_entry = mib_chain_total(MIB_ATM_VC_TBL);
	for(i=0;i<totalVC_entry;i++){
		if(mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&entryVC) == 0)
			continue;
		if(memcmp(entryVC.MacAddr, mac_str, MAC_ADDR_LEN)==0){
			wan_idx = entryVC.rg_wan_idx;
			break;
		}
	}
	if(wan_idx == -1){
		printf("can't find the respected RG WAN IDX!");
		ret = -1;
		goto Error4;
	}
	intf_info = (rtk_rg_intfInfo_t *)malloc(sizeof(rtk_rg_intfInfo_t));
	if(intf_info == NULL){
		printf("%s-%d Can't get enough memory space!\n",__func__,__LINE__);
		ret = -1;
		goto Error4;
	}
	memset(intf_info,0,sizeof(rtk_rg_intfInfo_t));
	wan_info = (rtk_rg_wanIntfConf_t *)malloc(sizeof(rtk_rg_wanIntfConf_t));
	if(wan_info == NULL){
		printf("%s-%d Can't get enough memory space!\n",__func__,__LINE__);
		ret = -1;
		goto Error3;
	}
	memset(wan_info,0,sizeof(rtk_rg_wanIntfConf_t));
	if(rtk_rg_intfInfo_find(intf_info,&wan_idx)!=SUCCESS){
		printf("%s-%d Can't find the wan interface idx:%d!",__func__,__LINE__,wan_idx);
		ret = -1;
		goto Error2;
	}
	memcpy(wan_info,&(intf_info->wan_intf.wan_intf_conf),sizeof(rtk_rg_wanIntfConf_t));
	/*force to add new WAN interface*/
	wan_info->forcedAddNewIntf = 1;

   	if((ret = rtk_rg_wanInterface_add(wan_info, &wanIntfIdx))!=SUCCESS){
		printf("%s-%d rtk_rg_wanInterface_add fail! ret=%d\n",__func__,__LINE__,ret);
		ret = -1;
		goto Error2;
	}
	//printf("%s-%d static wan wanIntfIdx:%d\n",__func__,__LINE__,wanIntfIdx);
	entry->rg_wan_idx = wanIntfIdx;
#if defined(CONFIG_RTK_L34_ENABLE) && defined(CONFIG_GPON_FEATURE)
	if(pon_mode == GPON_MODE){
		char vlan_based_pri=-1;
		/*untag wan, omci egress vlan id = -1*/
		if(entryVC.vlan == 2)
			wan_info->egress_vlan_id = 4095;
		else{
			if(!wan_info->egress_vlan_tag_on)
				wan_info->egress_vlan_id = -1;
		}
		if(wan_info->none_internet)
			omci_service = 0;
		else
			omci_service = 1;
		if((wan_info->port_binding_mask.portmask > 0) || (wan_info->wlan0_dev_binding_mask > 0))
			omci_bind = 1;
		else
			omci_bind = 0;
		if(entryVC.vprio)
		{
			vlan_based_pri=(entryVC.vprio)-1;
		}
		else
		{
			vlan_based_pri=-1;
		}
		snprintf(cmdStr, sizeof(cmdStr),"echo %d %d %d %d %d %d %d > %s",wanIntfIdx,wan_info->egress_vlan_id,vlan_based_pri,1,omci_service,omci_bind,1,OMCI_WAN_INFO);
		system(cmdStr);

	}
#endif
	switch(entryVC.cmode)
	{
		case CHANNEL_MODE_IPOE:
			if(entryVC.ipDhcp==DHCP_CLIENT){
				dhcpClient_info = (rtk_rg_ipDhcpClientInfo_t *)malloc(sizeof(rtk_rg_ipDhcpClientInfo_t));
				if(dhcpClient_info == NULL){
					printf("%s-%d Can't get enough memory space!\n",__func__,__LINE__);
					ret = -1;
					goto Error2;
				}
				memset(dhcpClient_info,0,sizeof(rtk_rg_ipDhcpClientInfo_t));
				memcpy(dhcpClient_info,&(intf_info->wan_intf.dhcp_client_info),sizeof(rtk_rg_ipDhcpClientInfo_t));
				dhcpClient_info->hw_info.ipv4_default_gateway_on=0;
				dhcpClient_info->hw_info.gw_mac_auto_learn_for_ipv4=1;
				dhcpClient_info->hw_info.ip_addr = ntohl(((struct in_addr *)entry->destID)->s_addr);
				dhcpClient_info->hw_info.ip_network_mask = ntohl(((struct in_addr *)entry->netMask)->s_addr);
				dhcpClient_info->hw_info.gateway_ipv4_addr = ntohl(((struct in_addr *)entry->nextHop)->s_addr);
				if(rtk_rg_dhcpClientInfo_set(entry->rg_wan_idx, dhcpClient_info)!=SUCCESS)
				{
					printf("rtk_rg_dhcpClientInfo_set error!!!\n");
					ret = -1;
					goto Error1;
				}
			}else{
				staticInfo = (rtk_rg_ipStaticInfo_t *)malloc(sizeof(rtk_rg_ipStaticInfo_t));
				if(staticInfo == NULL){
					printf("%s-%d Can't get enough memory space!\n",__func__,__LINE__);
					ret = -1;
					goto Error2;
				}
				memset(staticInfo,0,sizeof(rtk_rg_ipStaticInfo_t));
				staticInfo->ipv4_default_gateway_on=0;
				staticInfo->gw_mac_auto_learn_for_ipv4=1;
				staticInfo->ip_addr = ntohl(((struct in_addr *)entry->destID)->s_addr);
				staticInfo->ip_network_mask = ntohl(((struct in_addr *)entry->netMask)->s_addr);
				staticInfo->gateway_ipv4_addr = ntohl(((struct in_addr *)entry->nextHop)->s_addr);
				staticInfo->mtu=entryVC.mtu;
				if(entryVC.napt==1){
					staticInfo->napt_enable=1;
				}
				else{
					staticInfo->napt_enable=0;
				}
				if((ret = rtk_rg_staticInfo_set(entry->rg_wan_idx, staticInfo))!=SUCCESS){
					printf("%s-%d add rtk_rg_staticInfo_set fail! ret=%d\n",__func__,__LINE__,ret);
					ret = -1;
				}
			}
			break;
		default:
			printf("%s-%d entryVC.cmode=%d set static route error\n",__func__,__LINE__,entryVC.cmode);
			ret = -1;
			goto Error2;
	}
	mib_chain_update(MIB_IP_ROUTE_TBL, entry, entryID);
	if(staticInfo)
		free(staticInfo);
Error1:
	if(dhcpClient_info)
		free(dhcpClient_info);
Error2:
	if(wan_info)
		free(wan_info);
Error3:
	if(intf_info)
		free(intf_info);
Error4:
	return ret;
}
#endif

int RG_add_wan(MIB_CE_ATM_VC_Tp entry, int mib_vc_idx)
{
	int wanIntfIdx;
	int vcTotal, i, vlan_id;
	rtk_rg_wanIntfConf_t wan_info;
	unsigned char value[6];
	int ret=-1;
	int wanPhyPort=0;
	struct in_addr gw_addr;
    char cmdStr[64];
	int omci_mode=-1;
	//Init_RG_ELan(UntagCPort, RoutingWan);
	int rtk_rg_wan_type = RG_get_wan_type(entry);
	unsigned char mbtd;
#ifdef CONFIG_RTL_CLIENT_MODE_SUPPORT
	struct sockaddr hwaddr;
	char intf_name[IFNAMSIZ];
#endif
	int omci_service=-1;
	int omci_bind=-1;
	int pon_mode=0;
	if(rtk_rg_wan_type == -1)
		return -1;

	memset(&wan_info,0,sizeof(wan_info));
	memcpy(wan_info.gmac.octet, entry->MacAddr, MAC_ADDR_LEN);
#ifndef CONFIG_00R0//iulian added cvlan for multicast
	if(entry->vlan == 1)
#endif
		RG_WAN_CVLAN_DEL(entry->vid);

#if 0
	if(mib_get(MIB_WAN_PHY_PORT , (void *)&wanPhyPort) == 0){
		printf("get MIB_WAN_PHY_PORT failed!!!\n");
		wanPhyPort=RTK_RG_MAC_PORT3 ; //for 0371 default
	}
#endif
#ifdef CONFIG_RTL_CLIENT_MODE_SUPPORT
	if(MEDIA_INDEX(entry->ifIndex)==MEDIA_WLAN)
	{
		int tmp_wlan_idx;
		tmp_wlan_idx=ETH_INDEX(entry->ifIndex);
		if(tmp_wlan_idx)
			wanPhyPort=RTK_RG_EXT_PORT3;	//wlan1-vxd
		else
			wanPhyPort=RTK_RG_EXT_PORT2;	//wlan0-vxd

		snprintf(intf_name, IFNAMSIZ, "wlan%d-vxd", tmp_wlan_idx);
		getInAddr(intf_name, HW_ADDR, (void *)&hwaddr);
		memcpy(wan_info.gmac.octet, hwaddr.sa_data, MAC_ADDR_LEN);
	}
	else
#endif
		wanPhyPort=RG_get_wan_phyPortId();

	//wan_info.egress_vlan_id=8;
	//wan_info.vlan_based_pri=0;
	//wan_info.egress_vlan_tag_on=0;
	if (entry->vlan) {
		wan_info.egress_vlan_tag_on=1;
		wan_info.egress_vlan_id=entry->vid;
	}
	else{
		wan_info.egress_vlan_tag_on=0;
		mib_get(MIB_UNTAG_WAN_VLAN_ID, (void *)&vlan_id);
		wan_info.egress_vlan_id=vlan_id;


		if(rtk_rg_wan_type == RTK_RG_BRIDGE)
		{
			mib_get(MIB_LAN_VLAN_ID1, (void *)&vlan_id);
			wan_info.egress_vlan_id = vlan_id;
		}
	}

	//Only mac based decision supports port binding
	mib_get(MIB_MAC_BASED_TAG_DECISION, (void *)&mbtd);
	if(mbtd){
		#ifdef CONFIG_RTL9602C_SERIES
		wan_info.port_binding_mask.portmask = RG_get_lan_phyPortMask(entry->itfGroup & 0x3);
		#else
		wan_info.port_binding_mask.portmask = RG_get_lan_phyPortMask(entry->itfGroup & 0xf);
		#endif
		wan_info.wlan0_dev_binding_mask = ((entry->itfGroup & 0x1f0) >> 4);
#if defined(CONFIG_RG_WLAN_HWNAT_ACCELERATION) && !defined(CONFIG_ARCH_LUNA_SLAVE)
#ifdef CONFIG_RTL_CLIENT_MODE_SUPPORT
		wan_info.wlan0_dev_binding_mask |= ((entry->itfGroup & 0x3e00) << 5);
#else
		wan_info.wlan0_dev_binding_mask |= ((entry->itfGroup & 0x3e00) << 4);
#endif
#endif
	}
	if(entry->itfGroup > 0)
		omci_bind = 1;
	else
		omci_bind = 0;
/*
	wan_info.port_binding_mask.portmask = (entry->itfGroup & (1 << PMAP_ETH0_SW0)? 1 << RTK_RG_PORT0: 0) |
		(entry->itfGroup & (1 << PMAP_ETH0_SW1)? 1 << RTK_RG_PORT1: 0) |
		(entry->itfGroup & (1 << PMAP_ETH0_SW2)? 1 << RTK_RG_PORT2: 0) |
		(entry->itfGroup & (1 << PMAP_ETH0_SW3)? 1 << RTK_RG_PORT3: 0) |
		(entry->itfGroup & (1 << PMAP_WLAN0)? 1 << RTK_RG_EXT_PORT0: 0) |
		(entry->itfGroup & (1 << PMAP_WLAN0+1)? 1 << RTK_RG_EXT_PORT1: 0);
*/

	wan_info.wan_port_idx=wanPhyPort;
	wan_info.wan_type=rtk_rg_wan_type;

	/*RG: Internet = 0, other=1*/
	if(entry->applicationtype & X_CT_SRV_INTERNET){
		omci_service = 1;
		wan_info.none_internet = 0;
	}
	else{
		wan_info.none_internet = 1;
		omci_service = 0;
	}
	if((rtk_rg_wanInterface_add(&wan_info, &wanIntfIdx))!=SUCCESS)
		return -1;
	
	if((mbtd == 0) && (entry->itfGroup != 0)){//policy route
		printf("[%s] entry->cmode [%d]\n", __FUNCTION__, __LINE__, entry->cmode, CHANNEL_MODE_BRIDGE);
		if ( entry->cmode != CHANNEL_MODE_BRIDGE) {  // add condition if no wlan or lan interface assignment ?
			FlushRTK_RG_WAN_Port_mapping_ACL(wanIntfIdx);
			RG_add_WAN_Port_mapping_ACL(wanIntfIdx, entry->itfGroup);
		}  
	}
#if defined(CONFIG_RTK_L34_ENABLE) && defined(CONFIG_GPON_FEATURE)
//0 = PPPoE, 1 = IPoE, 2 = BRIDGE --> omci add cf rule

	switch(entry->cmode){
		case CHANNEL_MODE_IPOE:
			if( (entry->IpProtocol == IPVER_IPV4_IPV6) && entry->napt ==1)
				omci_mode = OMCI_MODE_IPOE_V4NAPT_V6;
			else
				omci_mode = OMCI_MODE_IPOE;
			break;
		case CHANNEL_MODE_PPPOE:
			if( (entry->IpProtocol == IPVER_IPV4_IPV6) && entry->napt ==1)
				omci_mode = OMCI_MODE_PPPOE_V4NAPT_V6;
			else
				omci_mode = OMCI_MODE_PPPOE;
			break;
		case CHANNEL_MODE_BRIDGE:
			omci_mode = OMCI_MODE_BRIDGE;
			break;
		default:
			printf("unknow mode %d\n",omci_mode);
			break;
	}

	//sync omci cf rules.
	mib_get(MIB_PON_MODE, (void *)&pon_mode);
	if(pon_mode == GPON_MODE){
		char vlan_based_pri;
		/*untag wan, omci egress vlan id = -1*/
		if(entry->vlan == 2)
			wan_info.egress_vlan_id = 4095;
		else{
			if(!wan_info.egress_vlan_tag_on)
				wan_info.egress_vlan_id = -1;
		}
		if(entry->vprio)
		{
			vlan_based_pri=(entry->vprio)-1;
		}
		else
		{
			vlan_based_pri=-1;
		}
#if ! defined(_LINUX_2_6_) && defined(CONFIG_TR142_MODULE)
		char ifname[IFNAMSIZ] = {0};
		ifGetName(PHY_INTF(entry->ifIndex), ifname, sizeof(ifname));
		snprintf(cmdStr, sizeof(cmdStr)-1,"echo %d %s %s %d > %s", wanIntfIdx, ALIASNAME_NAS0, ifname, omci_bind, TR142_WAN_IDX_MAP);
		system(cmdStr);
#endif
		snprintf(cmdStr, sizeof(cmdStr),"echo %d %d %d %d %d %d %d > %s",wanIntfIdx,wan_info.egress_vlan_id,vlan_based_pri,omci_mode,omci_service,omci_bind,1,OMCI_WAN_INFO);
		//AUG_PRT("%s\n",cmdStr);
		system(cmdStr);

	}
#endif
	entry->rg_wan_idx = wanIntfIdx;
	mib_chain_update(MIB_ATM_VC_TBL, entry, mib_vc_idx);
	return SUCCESS;
}
int RG_del_All_Acl_Rules(void)
{
	RG_del_All_default_Acl();
}
int RG_del_All_default_Acl(void)
{
	FILE *fp;
	int aclIdx=-1;
	if(!(fp = fopen(RG_ACL_DEFAULT_RULES_FILE, "r"))){
		return -2;
	}
	while(fscanf(fp, "%d\n", &aclIdx) != EOF)
	{
		if(rtk_rg_aclFilterAndQos_del(aclIdx))
			DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", aclIdx);
	}
	fclose(fp);
	unlink(RG_ACL_DEFAULT_RULES_FILE);
	return 0;
}
/*Due to SOC bug, ACL 1p priority is greater than OMCI CF 1p priority
    per Wan 1p priority would have problem.
    So, if configure GPON we disable per wan 1p ACL rules.
*/
int RG_add_default_Acl_Qos(void)
{
		MIB_CE_ATM_VC_T entry;
		int totalEntry = mib_chain_total(MIB_ATM_VC_TBL);
		int i,aclIdx=0, ret;
		rtk_rg_aclFilterAndQos_t aclRule;
		FILE *fp;
		if(!(fp = fopen(RG_ACL_DEFAULT_RULES_FILE, "a")))
		{
			fprintf(stderr, "ERROR! %s\n", strerror(errno));
			return -2;
		}
		//search all mib entry to add default ACL rules.
		for (i = 0; i < totalEntry; i++)
		{
			if (mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&entry) == 0)
				continue;
			if(entry.vprio){
				memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
				aclRule.acl_weight = RG_QOS_LOW_ACL_WEIGHT;
				aclRule.action_type = ACL_ACTION_TYPE_QOS;
				aclRule.qos_actions |= ACL_ACTION_1P_REMARKING_BIT;
				aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
/*
				aclRule.action_acl_cvlan.cvlanTagIfDecision = 1;
				aclRule.action_acl_cvlan.cvlanCvidDecision = 0;
				aclRule.action_acl_cvlan.cvlanCpriDecision = 0;
				aclRule.action_acl_cvlan.assignedCvid = entry.vid;
				aclRule.action_acl_cvlan.assignedCpri = (entry.vprio - 1);
*/
				aclRule.action_dot1p_remarking_pri = (entry.vprio - 1);

				if(entry.rg_wan_idx <= 0)
				{
					printf("Invalid rg_wan_idx value ! rg_wan_idx=%d\n", entry.rg_wan_idx);
					fclose(fp);
					return -1;
				}
				aclRule.egress_intf_idx = entry.rg_wan_idx;

				aclRule.filter_fields |= EGRESS_INTF_BIT;
//				aclRule.ingress_port_mask.portmask = 0xf;
				if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0)
					fprintf(fp,"%d\n",aclIdx);
				else
					printf("rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n", ret);
			}
		}
		fclose(fp);
		return 0;
}

int RG_set_static(MIB_CE_ATM_VC_Tp entry)
{
	rtk_rg_ipStaticInfo_t staticInfo;

	memset(&staticInfo, 0, sizeof(staticInfo));
	staticInfo.ipv4_default_gateway_on=entry->dgw;
	staticInfo.gw_mac_auto_learn_for_ipv4=1;
	if(entry->dgw)
		staticInfo.gateway_ipv4_addr = ntohl(((struct in_addr *)entry->remoteIpAddr)->s_addr);
	staticInfo.ip_addr = ntohl(((struct in_addr *)entry->ipAddr)->s_addr);
	staticInfo.ip_network_mask = ntohl(((struct in_addr *)entry->netMask)->s_addr);

	if(entry->dgw)
		staticInfo.ipv4_default_gateway_on = 1;

	staticInfo.ip_version = IPVER_V4ONLY;
	staticInfo.mtu=entry->mtu;
	if(entry->napt==1){
		staticInfo.napt_enable=1;
	}
	else{
		staticInfo.napt_enable=0;
	}

	if((rtk_rg_staticInfo_set(entry->rg_wan_idx, &staticInfo))!=SUCCESS)
		return -1;
	return SUCCESS;
}

int RG_release_static(int wanIntfIdx)
{
		rtk_rg_ipStaticInfo_t staticInfo;

		memset(&staticInfo, 0, sizeof(staticInfo));
		staticInfo.ipv4_default_gateway_on=0;
		staticInfo.gw_mac_auto_learn_for_ipv4=1;
		staticInfo.gateway_ipv4_addr=0;
		staticInfo.ip_addr=0;
		staticInfo.ip_network_mask=0;
		staticInfo.mtu=1500;
		staticInfo.napt_enable=0;

#ifdef CONFIG_IPV6
		staticInfo.ip_version = IPVER_V4V6;
		memcpy(staticInfo.ipv6_addr.ipv6_addr, empty_ipv6, IPV6_ADDR_LEN);
		staticInfo.ipv6_mask_length = 0;
		staticInfo.ipv6_default_gateway_on = 0;
		memcpy(staticInfo.gateway_ipv6_addr.ipv6_addr, empty_ipv6, IPV6_ADDR_LEN);
		staticInfo.gw_mac_auto_learn_for_ipv6 = 0;
#endif

		if((rtk_rg_staticInfo_set(wanIntfIdx, &staticInfo))!=SUCCESS)
			return -1;

		return SUCCESS;
}

const char RG_DHCP_WAN_TRAP_RULES_FILE[] = "/var/rg_dhcp_wan_trap_rules_idx.%s";
int RG_add_dhcp_wan_trap_rule(unsigned int ipaddr, char *ifname)
{
	rtk_rg_aclFilterAndQos_t aclRule;
	FILE *fp = NULL;
	int aclIdx;
	char fname[128] = {0};

	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	aclRule.action_type = ACL_ACTION_TYPE_TRAP_TO_PS;
	aclRule.acl_weight = RG_TRAP_ACL_WEIGHT;
	aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	aclRule.filter_fields = (INGRESS_IPV4_TAGIF_BIT | INGRESS_IPV4_DIP_RANGE_BIT | INGRESS_PORT_BIT);
	aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();
	aclRule.ingress_ipv4_tagif = 1;
	aclRule.ingress_dest_ipv4_addr_start = ntohl(ipaddr);
	aclRule.ingress_dest_ipv4_addr_end = ntohl(ipaddr);

	snprintf(fname, sizeof(fname), RG_DHCP_WAN_TRAP_RULES_FILE, ifname);
	if(!(fp = fopen(fname, "w")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -1;
	}

	if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0)
		fprintf(fp, "%d\n", aclIdx);
	else
		printf("[%s %d]rtk_rg_aclFilterAndQos_add failed!\n", __func__, __LINE__);

	fclose(fp);	
	return 0;
}

int RG_del_dhcp_wan_trap_rule(char *ifname)
{
	FILE *fp;
	int acl_idx;
	char fname[128] = {0};

	snprintf(fname, sizeof(fname), RG_DHCP_WAN_TRAP_RULES_FILE, ifname);

	fp = fopen(fname, "r");
	if(fp == NULL)
		return 0;

	while(fscanf(fp, "%d\n", &acl_idx) != EOF)
	{
		if(rtk_rg_aclFilterAndQos_del(acl_idx))
			DBPRINT(1, "RG_del_dhcp_wan_trap_rule delete ACL failed! idx = %d\n", acl_idx);
	}

	fclose(fp);
	unlink(fname);
	return 0;
}


#ifdef DBG_DHCP
#define DBG_DHCP_PRF(format, args...) printf(format, ##args)
#else
#define DBG_DHCP_PRF(format, args...)
#endif

int RG_set_dhcp(unsigned int ipaddr, unsigned int submsk, MIB_CE_ATM_VC_Tp entry)
{
	rtk_rg_ipDhcpClientInfo_t *dhcpClient_info=NULL;
	FILE *fp;
	struct in_addr gw_addr;
	char intf_name[10];
	int ret;
	rtk_rg_intfInfo_t intf_info;
	rtk_ipv6_addr_t zeroIPv6={{0}};

	ret = rtk_rg_intfInfo_find(&intf_info, &entry->rg_wan_idx);
	if(ret!=0){
		printf("Find RG interface for wan index %d Fail! Return -1!\n",entry->rg_wan_idx);
		return -1;
	}

#ifdef CONFIG_00R0 //Iulian Wu, Delete the all static route belong to this wan 
	RG_del_static_route_by_acl(entry->rg_wan_idx);
#endif	
	memset(&gw_addr,0,sizeof(struct in_addr));
	dhcpClient_info = &(intf_info.wan_intf.dhcp_client_info);
	ifGetName(entry->ifIndex, intf_name, sizeof(intf_name));
	DBG_DHCP_PRF("%s-%d : entry.ifIndex:%d intf_name:%s\n", __func__,__LINE__,entry->ifIndex, intf_name);
	DBG_DHCP_PRF("%s-%d : entry.ipDhcp:%d \n", __func__,__LINE__,entry->ipDhcp);
	DBG_DHCP_PRF("%s-%d : entry.ipAddr:%x.%x.%x.%x \n", __func__,__LINE__,entry->ipAddr[0],entry->ipAddr[1]
	,entry->ipAddr[2], entry->ipAddr[3]);
	DBG_DHCP_PRF("%s-%d : entry.netMask:%x.%x.%x.%x \n", __func__,__LINE__,entry->netMask[0],entry->netMask[1]
	,entry->netMask[2], entry->netMask[3]);
	if(entry->ipDhcp == 1)
	{
		char gwip[20];
		char buffer[50];
		sprintf(buffer, "%s.%s", MER_GWINFO_B, intf_name);
		if(!(fp = fopen(buffer, "r")))
			return -1;
			fscanf(fp, "%s", gwip);
			DBG_DHCP_PRF("%s-%d : gwip:%s \n", __func__,__LINE__,gwip);
			if(!inet_aton(gwip,&gw_addr)){
				printf("get gw_addr fail!\n");
			}
			DBG_DHCP_PRF("%s-%d: gw_addr:(%u.%u.%u.%u)\n",__func__,__LINE__,NIP_QUAD(gw_addr.s_addr));
			fclose(fp);
	}
	dhcpClient_info->hw_info.ipv4_default_gateway_on=entry->dgw;
	dhcpClient_info->hw_info.gw_mac_auto_learn_for_ipv4=1;
	dhcpClient_info->hw_info.ip_addr=ntohl(ipaddr);
	DBG_DHCP_PRF("%s-%d: ip_addr:(%u.%u.%u.%u)\n",__func__,__LINE__,NIP_QUAD(dhcpClient_info->hw_info.ip_addr));
	dhcpClient_info->hw_info.ip_network_mask=ntohl(submsk);
	dhcpClient_info->hw_info.mtu=1500;

	if(entry->napt==1){
		dhcpClient_info->hw_info.napt_enable=1;
	}else{
		dhcpClient_info->hw_info.napt_enable=0;
	}

	//if(entry->dgw || (entry->itfGroup > 0))
	dhcpClient_info->hw_info.gateway_ipv4_addr = ntohl(gw_addr.s_addr);

	DBG_DHCP_PRF("%s-%d: gateway_ip_addr:(%u.%u.%u.%u)\n",__func__,__LINE__,NIP_QUAD(dhcpClient_info->hw_info.gateway_ipv4_addr));
	DBG_DHCP_PRF("%s-%d: ip_network_mask:(%u.%u.%u.%u)\n",__func__,__LINE__,NIP_QUAD(dhcpClient_info->hw_info.ip_network_mask));
	dhcpClient_info->stauts=0;

#if defined(CONFIG_IPV6)
	if(entry->IpProtocol==IPVER_IPV4_IPV6){
		//If IPv6 is not ready, set IPv4 only
		dhcpClient_info->hw_info.ip_version = IPVER_V4V6;
	}
	else
#endif
	{
		dhcpClient_info->hw_info.ip_version = IPVER_V4ONLY;
	}

	if(rtk_rg_dhcpClientInfo_set(entry->rg_wan_idx, dhcpClient_info)!=SUCCESS)
	{
		printf("rtk_rg_dhcpClientInfo_set error!!!\n");
		return -1;
	}
	DBG_DHCP_PRF("%s-%d:\n",__func__,__LINE__);

	return SUCCESS;
}

int RG_release_dhcp(int wanIntfIdx)
{
	rtk_rg_ipDhcpClientInfo_t dhcpClient_info;
	FILE *fp;
	struct in_addr gw_addr;
	char intf_name[10];

	DBG_DHCP_PRF("%s-%d: Release IP got from DHCP\n",__func__,__LINE__);

#ifdef CONFIG_00R0 //Iulian Wu, Delete the all static route belong to this wan 
	RG_del_static_route_by_acl(wanIntfIdx);
#endif	
	memset(&dhcpClient_info,0,sizeof(dhcpClient_info));

	dhcpClient_info.stauts = 1;
	dhcpClient_info.hw_info.ipv4_default_gateway_on = 0;
	dhcpClient_info.hw_info.gw_mac_auto_learn_for_ipv4=1;
	dhcpClient_info.hw_info.ip_addr = 0;
	dhcpClient_info.hw_info.ip_network_mask = 0;
	dhcpClient_info.hw_info.mtu=1500;
	dhcpClient_info.hw_info.napt_enable=0;
	dhcpClient_info.hw_info.gateway_ipv4_addr = 0;

	if(rtk_rg_dhcpClientInfo_set(wanIntfIdx, &dhcpClient_info) != SUCCESS)
	{
		printf("rtk_rg_dhcpClientInfo_set error!!!\n");
		return -1;
	}
	DBG_DHCP_PRF("%s-%d:\n",__func__,__LINE__);

	return SUCCESS;
}
static unsigned int hextol(unsigned char *hex)
{
	return ( (hex[0] << 24) | (hex[1] << 16) | (hex[2] << 8) | (hex[3]));
}
#ifdef CONFIG_USER_L2TPD_L2TPD
int RG_add_l2tp_wan(MIB_L2TP_T *pentry, int mib_l2tp_idx)
{
	rtk_rg_wanIntfConf_t *wan_info = NULL;
	rtk_rg_intfInfo_t *intf_info = NULL;
	MIB_CE_ATM_VC_T entryVC;
	uint32_t ipAddr, netMask;
	uint32_t server_ip;
	int totalVC_entry, i, vc_wan_index=-1, ret=0, wanIntfIdx;
	server_ip = inet_addr(pentry->server);
	//printf("server_ip=0x%08X mib_l2tp_idx=%d\n",server_ip,mib_l2tp_idx);
	totalVC_entry = mib_chain_total(MIB_ATM_VC_TBL);
	for(i=0;i<totalVC_entry;i++){
		if(mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&entryVC) == 0)
			continue;
		ipAddr = hextol(entryVC.ipAddr);
		netMask = hextol(entryVC.netMask);
		//printf("ipAddr=0x%08X netMask=0x%08X\n",ipAddr, netMask);
		if(netMask == 0 || ipAddr == 0)
			continue;
		if((ipAddr & netMask) == (server_ip & netMask)){
			vc_wan_index = entryVC.rg_wan_idx;
			printf("[%s-%d]vc_wan_index = %d\n",__func__,__LINE__,vc_wan_index);
			break;
		}
	}
	if(vc_wan_index < 0){
		printf("[%s-%d]Can't find output WAN!\n",__func__,__LINE__);
		ret = -1;
		goto Error_l2tp3;
	}
	intf_info = (rtk_rg_intfInfo_t *)malloc(sizeof(rtk_rg_intfInfo_t));
	if(intf_info == NULL){
		fprintf(stderr, "ERROR! intf Can't get enough memory space %s\n", strerror(errno));
		ret = -1;
		goto Error_l2tp3;
	}
	memset(intf_info,0,sizeof(rtk_rg_intfInfo_t));

	wan_info = (rtk_rg_wanIntfConf_t *)malloc(sizeof(rtk_rg_wanIntfConf_t));
	if(wan_info == NULL){
		fprintf(stderr, "ERROR! wanIntf Can't get enough memory space %s\n", strerror(errno));
		ret = -1;
		goto Error_l2tp2;
	}
	memset(wan_info,0,sizeof(rtk_rg_wanIntfConf_t));

	ret = rtk_rg_intfInfo_find(intf_info, &vc_wan_index);
	if(ret!=0){
		fprintf(stderr, "ERROR! rtk_rg_intfInfo_find %s\n", strerror(errno));
		ret = -1;
		goto Error_l2tp1;
	}
	memcpy(wan_info,&(intf_info->wan_intf.wan_intf_conf),sizeof(rtk_rg_wanIntfConf_t));
	wan_info->wan_type = RTK_RG_L2TP;
	wan_info->forcedAddNewIntf = 1;
	//dump_wan_info(wan_info);
	if((rtk_rg_wanInterface_add(wan_info, &wanIntfIdx))!=SUCCESS){
		ret = -1;
		fprintf(stderr, "ERROR! rtk_rg_wanInterface_add %s\n", strerror(errno));
		goto Error_l2tp1;
	}
	//printf("[%s-%d] wanIntfIdx=%d\n",__func__,__LINE__,wanIntfIdx);
	pentry->rg_wan_idx = wanIntfIdx;
	mib_chain_update(MIB_L2TP_TBL, pentry, mib_l2tp_idx);
	Error_l2tp1:
		if(wan_info)
			free(wan_info);
	Error_l2tp2:
		if(intf_info)
			free(intf_info);
	Error_l2tp3:
	return ret;
}
int RG_add_l2tp(unsigned long gw_ip, unsigned long my_ip, MIB_L2TP_T *pentry)
{
	rtk_rg_l2tpClientInfoBeforeDial_t l2tpClientInfoB;
	rtk_rg_l2tpClientInfoAfterDial_t *l2tpClientInfoA = NULL;
	rtk_rg_intfInfo_t intf_info;
	rtk_rg_wanIntfConf_t *wan_info = NULL;
	int ret=-1, i, totalVC_entry, vc_wan_index;
	MIB_CE_ATM_VC_T entryVC;
	uint32_t ipAddr, netMask;
	uint32_t server_ip;
	totalVC_entry = mib_chain_total(MIB_ATM_VC_TBL);
	for(i=0;i<totalVC_entry;i++){
		if(mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&entryVC) == 0)
			continue;
		ipAddr = hextol(entryVC.ipAddr);
		netMask = hextol(entryVC.netMask);
		//printf("ipAddr=0x%08X netMask=0x%08X\n",ipAddr, netMask);
		if(netMask == 0 || ipAddr == 0)
			continue;
		if((ipAddr & netMask) == (server_ip & netMask)){
			vc_wan_index = entryVC.rg_wan_idx;
			//printf("[%s-%d]vc_wan_index = %d\n",__func__,__LINE__,vc_wan_index);
			break;
		}
	}
/*
	printf("\n[%s:%d] gw_ip=0x%x, my_ip=0x%x\n",__func__,__LINE__,gw_ip,my_ip);
	printf("\n[%s:%d] outer_port=%d, gateway_outer_port=%d\n",__func__,__LINE__,pentry->outer_port,pentry->gateway_outer_port);
	printf("\n[%s:%d] session_id=%d, gateway_session_id=%d\n",__func__,__LINE__,pentry->session_id,pentry->gateway_session_id);
	printf("\n[%s:%d] tunnel_id=%d, gateway_tunnel_id=%d\n",__func__,__LINE__,pentry->tunnel_id, pentry->gateway_tunnel_id);
*/
	memset(&l2tpClientInfoB, 0, sizeof(l2tpClientInfoB));
	memcpy(l2tpClientInfoB.username, pentry->username, MAX_NAME_LEN);
	memcpy(l2tpClientInfoB.password, pentry->password, MAX_NAME_LEN);
//	printf("\n[%s:%d] username=%s, password=%s\n",__func__,__LINE__,l2tpClientInfoB.username,l2tpClientInfoB.password);
	l2tpClientInfoB.l2tp_ipv4_addr=ntohl(inet_addr(pentry->server));
	if((rtk_rg_l2tpClientInfoBeforeDial_set(pentry->rg_wan_idx, &l2tpClientInfoB)) != SUCCESS){
		return -1;
	}
	ret = rtk_rg_intfInfo_find(&intf_info, &pentry->rg_wan_idx);
	if(ret!=0){
		printf("Find RG interface for wan index %d Fail! Return -1!\n",pentry->rg_wan_idx);
		return -1;
	}
	l2tpClientInfoA = &(intf_info.wan_intf.l2tp_info.after_dial);
	l2tpClientInfoA->outer_port=pentry->outer_port;
	l2tpClientInfoA->gateway_outer_port=pentry->gateway_outer_port;
	l2tpClientInfoA->tunnelId=pentry->tunnel_id;
	l2tpClientInfoA->sessionId=pentry->session_id;
	l2tpClientInfoA->gateway_tunnelId=pentry->gateway_tunnel_id;
	l2tpClientInfoA->gateway_sessionId=pentry->gateway_session_id;
	l2tpClientInfoA->hw_info.ip_version= IPVER_V4ONLY;
	l2tpClientInfoA->hw_info.napt_enable=entryVC.napt;
	l2tpClientInfoA->hw_info.ipv4_default_gateway_on=pentry->dgw;
	l2tpClientInfoA->hw_info.ip_addr=ntohl(my_ip); //wan ip:192.168.150.116
	l2tpClientInfoA->hw_info.ip_network_mask=0xffffff00; //255.255.255.0
	l2tpClientInfoA->hw_info.gateway_ipv4_addr =ntohl(gw_ip); //wan gateway ip:192.168.150.117
	l2tpClientInfoA->hw_info.mtu=1440;
	l2tpClientInfoA->hw_info.gw_mac_auto_learn_for_ipv4=1;
	if((rtk_rg_l2tpClientInfoAfterDial_set(pentry->rg_wan_idx, l2tpClientInfoA))!= SUCCESS)
	return -1;
	return ret;
}
#endif /*CONFIG_USER_L2TPD_L2TPD*/
#ifdef CONFIG_USER_PPTP_CLIENT_PPTP
int RG_add_pptp_wan(MIB_PPTP_T *pentry, int mib_pptp_idx)
{
	rtk_rg_wanIntfConf_t *wan_info = NULL;
	rtk_rg_intfInfo_t *intf_info = NULL;
	MIB_CE_ATM_VC_T entryVC;
	uint32_t ipAddr, netMask;
	uint32_t server_ip;
	int totalVC_entry, i, vc_wan_index=-1, ret=0, wanIntfIdx;
	server_ip = inet_addr(pentry->server);
//	printf("server_ip=0x%08X mib_pptp_idx=%d\n",server_ip,mib_pptp_idx);
	totalVC_entry = mib_chain_total(MIB_ATM_VC_TBL);
	for(i=0;i<totalVC_entry;i++){
		if(mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&entryVC) == 0)
			continue;
		ipAddr = hextol(entryVC.ipAddr);
		netMask = hextol(entryVC.netMask);
//		printf("ipAddr=0x%08X netMask=0x%08X\n",ipAddr, netMask);
		if(netMask == 0 || ipAddr == 0)
			continue;
		if((ipAddr & netMask) == (server_ip & netMask)){
			vc_wan_index = entryVC.rg_wan_idx;
			printf("[%s-%d] vc_wan_index = %d\n",__func__,__LINE__,vc_wan_index);
			break;
		}
	}
	if(vc_wan_index < 0){
		printf("[%s-%d]Can't find output WAN!\n",__func__,__LINE__);
		ret = -1;
		goto Error_Pptp3;
	}
	intf_info = (rtk_rg_intfInfo_t *)malloc(sizeof(rtk_rg_intfInfo_t));
	if(intf_info == NULL){
		fprintf(stderr, "ERROR! intf Can't get enough memory space %s\n", strerror(errno));
		ret = -1;
		goto Error_Pptp3;
	}
	memset(intf_info,0,sizeof(rtk_rg_intfInfo_t));
	wan_info = (rtk_rg_wanIntfConf_t *)malloc(sizeof(rtk_rg_wanIntfConf_t));
	if(wan_info == NULL){
		fprintf(stderr, "ERROR! wanIntf Can't get enough memory space %s\n", strerror(errno));
		ret = -1;
		goto Error_Pptp2;
	}
	memset(wan_info,0,sizeof(rtk_rg_wanIntfConf_t));
	ret = rtk_rg_intfInfo_find(intf_info, &vc_wan_index);
	if(ret!=0){
		fprintf(stderr, "ERROR! rtk_rg_intfInfo_find %s\n", strerror(errno));
		ret = -1;
		goto Error_Pptp1;
	}
	memcpy(wan_info,&(intf_info->wan_intf.wan_intf_conf),sizeof(rtk_rg_wanIntfConf_t));
	wan_info->wan_type = RTK_RG_PPTP;
	wan_info->forcedAddNewIntf = 1;
	//dump_wan_info(wan_info);
	if((rtk_rg_wanInterface_add(wan_info, &wanIntfIdx))!=SUCCESS){
		ret = -1;
		printf("%s-%d rtk_rg_wanInterface_add error\n",__func__,__LINE__);
		goto Error_Pptp1;
	}
	//printf("%s-%d wanIntfIdx=%d\n",__func__,__LINE__,wanIntfIdx);
	pentry->rg_wan_idx = wanIntfIdx;
	mib_chain_update(MIB_PPTP_TBL, pentry, mib_pptp_idx);
	Error_Pptp1:
		if(wan_info)
			free(wan_info);
	Error_Pptp2:
		if(intf_info)
			free(intf_info);
	Error_Pptp3:
	return ret;
}
int RG_add_pptp( unsigned long gw_ip, unsigned long my_ip, MIB_PPTP_T *pentry)
{
	rtk_rg_pptpClientInfoBeforeDial_t pptpClientInfoB;
	rtk_rg_pptpClientInfoAfterDial_t *pptpClientInfoA = NULL;
	rtk_rg_intfInfo_t intf_info;
	rtk_rg_wanIntfConf_t *wan_info = NULL;
	int ret=-1, i, totalVC_entry, vc_wan_index;
	MIB_CE_ATM_VC_T entryVC;
	uint32_t ipAddr, netMask;
	uint32_t server_ip;
	totalVC_entry = mib_chain_total(MIB_ATM_VC_TBL);
	for(i=0;i<totalVC_entry;i++){
		if(mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&entryVC) == 0)
			continue;
		ipAddr = hextol(entryVC.ipAddr);
		netMask = hextol(entryVC.netMask);
//		printf("ipAddr=0x%08X netMask=0x%08X\n",ipAddr, netMask);
		if(netMask == 0 || ipAddr == 0)
			continue;
		if((ipAddr & netMask) == (server_ip & netMask)){
			vc_wan_index = entryVC.rg_wan_idx;
			printf("vc_wan_index = %d\n",vc_wan_index);
			break;
		}
	}
//	printf("\n[%s:%d] callId=%d, gateway_callId=%d, gw_ip=0x%x, my_ip=0x%x\n",__func__,__LINE__,pentry->callid,pentry->peer_callid,gw_ip,my_ip);
	memset(&pptpClientInfoB, 0, sizeof(pptpClientInfoB));
	memcpy(pptpClientInfoB.username, pentry->username, MAX_NAME_LEN);
	memcpy(pptpClientInfoB.password, pentry->password, MAX_NAME_LEN);
//	printf("\n[%s:%d] username=%s, password=%s\n",__func__,__LINE__,pptpClientInfoB.username,pptpClientInfoB.password);
	pptpClientInfoB.pptp_ipv4_addr=ntohl(inet_addr(pentry->server));
	if((rtk_rg_pptpClientInfoBeforeDial_set(pentry->rg_wan_idx, &pptpClientInfoB)) != SUCCESS){
		return -1;
	}
	ret = rtk_rg_intfInfo_find(&intf_info, &pentry->rg_wan_idx);
	if(ret!=0){
		printf("Find RG interface for wan index %d Fail! Return -1!\n",pentry->rg_wan_idx);
		return -1;
	}
	pptpClientInfoA = &(intf_info.wan_intf.pptp_info.after_dial);
	pptpClientInfoA->callId=pentry->callid;
	pptpClientInfoA->gateway_callId=pentry->peer_callid;
	pptpClientInfoA->hw_info.ip_version= IPVER_V4ONLY;
	pptpClientInfoA->hw_info.napt_enable=entryVC.napt;
	pptpClientInfoA->hw_info.ipv4_default_gateway_on=pentry->dgw;;
	pptpClientInfoA->hw_info.ip_addr=ntohl(my_ip); //wan ip:192.168.150.116
	pptpClientInfoA->hw_info.ip_network_mask=0xffffff00; //255.255.255.0
	pptpClientInfoA->hw_info.gateway_ipv4_addr=ntohl(gw_ip); //wan gateway ip:192.168.150.117
	pptpClientInfoA->hw_info.mtu=1440;
	pptpClientInfoA->hw_info.gw_mac_auto_learn_for_ipv4=1;
	if((rtk_rg_pptpClientInfoAfterDial_set(pentry->rg_wan_idx, pptpClientInfoA))!= SUCCESS)
	return -1;
	return 0;
}
int RG_release_pptp(int wanIntfIdx)
{
	rtk_rg_pptpClientInfoBeforeDial_t pptpClientInfoB;
	rtk_rg_pptpClientInfoAfterDial_t pptpClientInfoA;
//	printf("\n[%s:%d] wanIntfIdx=%d, Release IP got from pptp\n",__func__,__LINE__,wanIntfIdx);
	memset(&pptpClientInfoB, 0, sizeof(pptpClientInfoB));
	memset(&pptpClientInfoA, 0, sizeof(pptpClientInfoA));
	if((rtk_rg_pptpClientInfoBeforeDial_set(wanIntfIdx, &pptpClientInfoB)) != SUCCESS){
		return -1;
	}
	pptpClientInfoA.hw_info.mtu=1492;
	pptpClientInfoA.hw_info.gw_mac_auto_learn_for_ipv4=1;
	if((rtk_rg_pptpClientInfoAfterDial_set(wanIntfIdx, &pptpClientInfoA))!= SUCCESS)
		return -1;
	return 0;
}
#endif /*CONFIG_USER_PPTP_CLIENT_PPTP*/
int RG_add_pppoe(unsigned short session_id, unsigned long gw_ip, unsigned long my_ip, unsigned char* gw_mac, MIB_CE_ATM_VC_T *vcEntry){
	rtk_rg_wanIntfConf_t wan_info;
	rtk_rg_pppoeClientInfoBeforeDial_t pppoeClientInfoB;
	rtk_rg_pppoeClientInfoAfterDial_t *pppoeClientInfoA=NULL;
	unsigned char value[6];
	int i,ret;
	int wanPhyPort=0;
	rtk_rg_intfInfo_t intf_info;
	rtk_ipv6_addr_t zeroIPv6={{0}};

	//This function is to set up PPPoE IPv4 IP/Gateway info into RG

#ifdef CONFIG_IPV6
	if(vcEntry->IpProtocol == IPVER_IPV6)
		return -1;
#endif

	printf("\n[%s:%d] session_id=%d, gw_ip=0x%x, my_ip=0x%x\n",__func__,__LINE__,session_id,gw_ip,my_ip);
	memset(&pppoeClientInfoB, 0, sizeof(pppoeClientInfoB));
	if((rtk_rg_pppoeClientInfoBeforeDial_set(vcEntry->rg_wan_idx, &pppoeClientInfoB)) != SUCCESS){
		return -1;
	}

	ret = rtk_rg_intfInfo_find(&intf_info, &vcEntry->rg_wan_idx);
	if(ret!=0){
		printf("Find RG interface for wan index %d Fail! Return -1!\n",vcEntry->rg_wan_idx);
		return -1;
	}
	pppoeClientInfoA = &(intf_info.wan_intf.pppoe_info.after_dial);
	pppoeClientInfoA->hw_info.napt_enable = vcEntry->napt;
	pppoeClientInfoA->hw_info.ip_addr = ntohl(my_ip);
	pppoeClientInfoA->hw_info.ip_network_mask = 0xffffffff;
	pppoeClientInfoA->hw_info.ipv4_default_gateway_on = vcEntry->dgw;
	pppoeClientInfoA->hw_info.gateway_ipv4_addr = ntohl(gw_ip);
	pppoeClientInfoA->hw_info.mtu = vcEntry->mtu;
	pppoeClientInfoA->sessionId = session_id;

	printf("!!!!!! session id :%d %d \n", pppoeClientInfoA->sessionId,session_id);

	pppoeClientInfoA->hw_info.gw_mac_auto_learn_for_ipv4 = 0;
	memcpy(pppoeClientInfoA->hw_info.gateway_mac_addr_for_ipv4.octet, gw_mac, 6);

#if defined(CONFIG_IPV6)
	if(vcEntry->IpProtocol==IPVER_IPV4_IPV6){
		//If IPv6 is not ready, set IPv4 only
		pppoeClientInfoA->hw_info.ip_version = IPVER_V4V6;
	}
	else if(vcEntry->IpProtocol==IPVER_IPV6){
		pppoeClientInfoA->hw_info.ip_version = IPVER_V6ONLY;
	}
	else
#endif
	{
		pppoeClientInfoA->hw_info.ip_version = IPVER_V4ONLY;
	}


	if((rtk_rg_pppoeClientInfoAfterDial_set(vcEntry->rg_wan_idx, pppoeClientInfoA)) != SUCCESS){
		return -1;
	}
}

//siyuan release pppoe setting in romedriver when pppoe connection is down
int RG_release_pppoe(MIB_CE_ATM_VC_Tp vcEntry)
{
	rtk_rg_wanIntfConf_t wan_info;
	rtk_rg_pppoeClientInfoAfterDial_t *pppoeClientInfoA=NULL;
	rtk_rg_pppoeClientInfoBeforeDial_t pppoeClientInfoB;
	rtk_rg_intfInfo_t intf_info;
	int ret;
	rtk_ipv6_addr_t zeroIPv6={{0}};

	printf("\n[%s:%d] wanIntfIdx=%d, Release IP got from PPPOE\n",__func__,__LINE__,vcEntry->rg_wan_idx);

	ret = rtk_rg_intfInfo_find(&intf_info, &vcEntry->rg_wan_idx);
	if(ret!=0){
		printf("Find RG interface for wan index %d Fail! Return -1!\n",vcEntry->rg_wan_idx);
		return -1;
	}

	pppoeClientInfoA = &(intf_info.wan_intf.pppoe_info.after_dial);
	pppoeClientInfoA->hw_info.napt_enable = 0;
	pppoeClientInfoA->hw_info.ip_addr = 0;
	pppoeClientInfoA->hw_info.ip_network_mask = 0;
	pppoeClientInfoA->hw_info.ipv4_default_gateway_on = 0;
	pppoeClientInfoA->hw_info.gateway_ipv4_addr = 0;
	pppoeClientInfoA->hw_info.gw_mac_auto_learn_for_ipv4 = 0;
	memset(&pppoeClientInfoA->hw_info.gateway_mac_addr_for_ipv4, 0, 6);
#if defined(CONFIG_IPV6)
	if(vcEntry->IpProtocol==IPVER_IPV4_IPV6){
		//If IPv4 is not ready, set IPv6 only
		pppoeClientInfoA->hw_info.ip_version = IPVER_V4V6;
	} 
	else if(vcEntry->IpProtocol==IPVER_IPV6){
		pppoeClientInfoA->hw_info.ip_version = IPVER_V6ONLY;
	}
	else
#endif
	{
		pppoeClientInfoA->hw_info.ip_version = IPVER_V4ONLY;
	}

	if(pppoeClientInfoA->sessionId != 0)
	{
		if((rtk_rg_pppoeClientInfoAfterDial_set(vcEntry->rg_wan_idx, pppoeClientInfoA)) != SUCCESS){
			return -1;
		}
	}
	else
	{
		printf("session id is empty!!!! skip\n");
		return -1;
	}

}

#ifdef CONFIG_IPV6
int RG_release_dslite_pppoev6(MIB_CE_ATM_VC_Tp vcEntry)
{
	rtk_rg_pppoeDsliteInfoAfterDial_t *pppoeClientiDslisteInfoA=NULL;
	rtk_rg_intfInfo_t intf_info;
	rtk_ipv6_addr_t zeroIPv6={{0}};
	
	int ret=0;

	printf("\n[%s:%d] wanIntfIdx=%d, Release IP got from PPPOE dslite\n",__func__,__LINE__,vcEntry->rg_wan_idx);

	ret = rtk_rg_intfInfo_find(&intf_info, &vcEntry->rg_wan_idx);
	if(ret!=0){
		printf("[%s-%d]Find RG interface for wan index %d Fail! Return -1!\n",__func__,__LINE__,vcEntry->rg_wan_idx);
		return -1;
	}
	pppoeClientiDslisteInfoA = &(intf_info.wan_intf.pppoe_dslite_info.after_dial);

	pppoeClientiDslisteInfoA->dslite_hw_info.static_info.mtu = vcEntry->mtu;
	pppoeClientiDslisteInfoA->dslite_hw_info.static_info.ip_addr = 0;
	pppoeClientiDslisteInfoA->dslite_hw_info.static_info.ip_network_mask = 0;
	pppoeClientiDslisteInfoA->dslite_hw_info.static_info.ipv6_mask_length = 128;
	pppoeClientiDslisteInfoA->dslite_hw_info.static_info.ipv4_default_gateway_on = 0;
	pppoeClientiDslisteInfoA->dslite_hw_info.static_info.ipv6_default_gateway_on = 0;
	pppoeClientiDslisteInfoA->dslite_hw_info.static_info.gw_mac_auto_learn_for_ipv4=0;
	pppoeClientiDslisteInfoA->dslite_hw_info.static_info.gw_mac_auto_learn_for_ipv6=0;
	memset((void *)pppoeClientiDslisteInfoA->dslite_hw_info.static_info.ipv6_addr.ipv6_addr, 0 ,sizeof(struct in6_addr));
	memset((void *)pppoeClientiDslisteInfoA->dslite_hw_info.static_info.gateway_ipv6_addr.ipv6_addr, 0,sizeof(struct in6_addr));
	memset((void *)pppoeClientiDslisteInfoA->dslite_hw_info.rtk_dslite.ipB4.ipv6_addr, 0 ,sizeof(struct in6_addr));
	memset((void *)pppoeClientiDslisteInfoA->dslite_hw_info.rtk_dslite.ipAftr.ipv6_addr, 0 ,sizeof(struct in6_addr));
	pppoeClientiDslisteInfoA->dslite_hw_info.static_info.ip_version = IPVER_V4V6;
	
	if(pppoeClientiDslisteInfoA->sessionId != 0)
	{
		if((rtk_rg_pppoeDsliteInfoAfterDial_set(vcEntry->rg_wan_idx, pppoeClientiDslisteInfoA)) != SUCCESS){
			printf("\n[%s:%d] wanIntfIdx=%d, Release IP got from PPPOE dslite fail!\n",__func__,__LINE__,vcEntry->rg_wan_idx);
			return -1;
		}
	}
	else
	{
		printf("session id is empty!!!! skip\n");
		return -1;
	}
	return 0;

}

int RG_release_pppoev6(MIB_CE_ATM_VC_Tp vcEntry)
{
	rtk_rg_wanIntfConf_t wan_info;
	rtk_rg_pppoeClientInfoAfterDial_t *pppoeClientInfoA=NULL;
	rtk_rg_pppoeClientInfoBeforeDial_t pppoeClientInfoB;
	rtk_rg_intfInfo_t intf_info;
	rtk_ipv6_addr_t zeroIPv6={{0}};
	int ret;

	printf("\n[%s:%d] wanIntfIdx=%d, Release IP got from PPPOE\n",__func__,__LINE__,vcEntry->rg_wan_idx);

	ret = rtk_rg_intfInfo_find(&intf_info, &vcEntry->rg_wan_idx);
	if(ret!=0){
		printf("Find RG interface for wan index %d Fail! Return -1!\n",vcEntry->rg_wan_idx);
		return -1;
	}
	
	pppoeClientInfoA = &(intf_info.wan_intf.pppoe_info.after_dial);
	memset(&pppoeClientInfoA->hw_info.ipv6_addr, 0, IP6_ADDR_LEN);
	pppoeClientInfoA->hw_info.ipv6_napt_enable = 0;
	pppoeClientInfoA->hw_info.ipv6_mask_length = 0;
	pppoeClientInfoA->hw_info.ipv6_default_gateway_on = 0;
	memset(&pppoeClientInfoA->hw_info.gateway_ipv6_addr, 0, IP6_ADDR_LEN);
	memset(&pppoeClientInfoA->hw_info.gateway_mac_addr_for_ipv6, 0, 6);
	pppoeClientInfoA->hw_info.gw_mac_auto_learn_for_ipv6 = 0;	

#if defined(CONFIG_IPV6)
	if(vcEntry->IpProtocol==IPVER_IPV4_IPV6){
		//If IPv6 is not ready, set IPv4 only
		pppoeClientInfoA->hw_info.ip_version = IPVER_V4V6;
	}
	else if(vcEntry->IpProtocol==IPVER_IPV6){
		pppoeClientInfoA->hw_info.ip_version = IPVER_V6ONLY;
	}
	else
#endif
	{
		pppoeClientInfoA->hw_info.ip_version = IPVER_V4ONLY;
	}
	
	if(pppoeClientInfoA->sessionId != 0)
	{
		if((rtk_rg_pppoeClientInfoAfterDial_set(vcEntry->rg_wan_idx, pppoeClientInfoA)) != SUCCESS){
			return -1;
		}
	}
	else
	{
		printf("session id is empty!!!! skip\n");
		return -1;
	}		
	return 0;

}
#endif

int RTK_RG_Del_CF_Rule_for_usflow(void)
{
#ifdef CONFIG_RTL9607C
	//cxy 2018-3-27:9607C RG not set classf to hw, so use rtk api to del cf rule
	rtk_classify_cfgEntry_del(64);
#else
	rtk_rg_classifyEntry_del(64);
#endif
	return 0;
}

int RTK_RG_Add_CF_Rule_for_usflow(MIB_CE_ATM_VC_T *pEntry, int flowid)
{
#ifdef CONFIG_RTL9607C
	//cxy 2018-3-27:9607C RG not set classf to hw, so use rtk api to add cf rule
	rtk_classify_field_t classifyField[3];
	rtk_classify_cfg_t cfRule;
	int ret;

	memset(&cfRule, 0, sizeof(cfRule));
	memset(&classifyField, 0, sizeof(classifyField));
	classifyField[0].fieldType = CLASSIFY_FIELD_UNI;
	classifyField[0].classify_pattern.uni.value = RTK_RG_PORT_CPU;
	classifyField[0].classify_pattern.uni.mask = 0xf;
	if(rtk_classify_field_add(&cfRule, &(classifyField[0])))
	{
		printf("<%s %d> Add CF Rule Filed 0 for speedtest failed\n",__func__,__LINE__);
		return -1;
	}
	if (pEntry->vid > 0)
    {
		classifyField[1].fieldType = CLASSIFY_FIELD_IS_CTAG;
		classifyField[1].classify_pattern.isCtag.value = 1;
		classifyField[1].classify_pattern.isCtag.mask= 1;
		if(rtk_classify_field_add(&cfRule, &(classifyField[1])))
		{
			printf("<%s %d> Add CF Rule Filed 1 for speedtest failed\n",__func__,__LINE__);
			return -1;
		}
		classifyField[2].fieldType = CLASSIFY_FIELD_TAG_VID;
		classifyField[2].classify_pattern.tagVid.value = pEntry->vid;
		classifyField[2].classify_pattern.tagVid.mask = 0xfff;
		if(rtk_classify_field_add(&cfRule, &(classifyField[2])))
		{
			printf("<%s %d> Add CF Rule Filed for speedtest failed\n",__func__,__LINE__);
			return -1;
		}
    }
	cfRule.index = 64;
	cfRule.direction = CLASSIFY_DIRECTION_US;
	cfRule.valid = 1;
	cfRule.act.usAct.sidQidAct = CLASSIFY_US_SQID_ACT_ASSIGN_SID;
	cfRule.act.usAct.sidQid = flowid;
	if(ret=rtk_classify_cfgEntry_add(&cfRule))
	{
		printf("<%s %d> Add CF Rule for speedtest failed ret=0x%x\n",__func__,__LINE__,ret);
		return -1;
	}
	printf("Add CF Rule for speedtest successfully\n");
	return 0;
#else
	rtk_rg_classifyEntry_t cfRule;
	int ret;

	memset(&cfRule, 0, sizeof(rtk_rg_classifyEntry_t));
	cfRule.index = 64;
	cfRule.direction = RTK_RG_CLASSIFY_DIRECTION_UPSTREAM;

	if (pEntry->vid > 0)
	{
		cfRule.action_cvlan.cvlanCvidDecision = ACL_CVLAN_CVID_ASSIGN;
		cfRule.action_cvlan.cvlanTagIfDecision = ACL_CVLAN_TAGIF_TAGGING;
		cfRule.action_cvlan.cvlanCpriDecision = ACL_CVLAN_CPRI_COPY_FROM_INTERNAL_PRI;
		cfRule.action_cvlan.assignedCvid = pEntry->vid;
		cfRule.us_action_field |= CF_US_ACTION_CTAG_BIT;
	}
	cfRule.action_sid_or_llid.assignedSid_or_llid = flowid;
	cfRule.us_action_field |= CF_US_ACTION_SID_BIT;

	/*assigned source uni port */
	cfRule.uni = RTK_RG_MAC_PORT_CPU;
	cfRule.uni_mask = 0x7;
	cfRule.filter_fields |= EGRESS_UNI_BIT;

    if (pEntry->vid > 0)
    {
        cfRule.outterTagVid = pEntry->vid;
        cfRule.filter_fields |= EGRESS_TAGVID_BIT;
        cfRule.ctagIf = 1;
        cfRule.filter_fields |= EGRESS_CTAGIF_BIT;
    }
	
	ret = rtk_rg_classifyEntry_add(&cfRule);
	if (ret != 0)
		printf("Add CF Rule for speedtest failed\n");
	else
		printf("Add CF Rule for speedtest successfully\n");

	return 0;
#endif
}

#ifdef CONFIG_XFRM
const char RG_IPSEC_TRAP_RULES_FILE[] = "/var/rg_ipsec_trap_rules_idx";

int RG_add_ipsec_trap_rule(MIB_IPSEC_T *pEntry)
{
	rtk_rg_aclFilterAndQos_t aclRule;
	FILE *fp = NULL;
	int aclIdx;
	ipaddr_t mask;

	/* trap all upstream packets matched with ipsec config to PS */
	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	aclRule.action_type = ACL_ACTION_TYPE_TRAP_TO_PS;
	aclRule.acl_weight = RG_TRAP_ACL_WEIGHT;
	aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	aclRule.filter_fields = INGRESS_IPV4_TAGIF_BIT | INGRESS_PORT_BIT;
	aclRule.ingress_port_mask.portmask = RG_get_all_lan_phyPortMask();
#ifdef WLAN_SUPPORT
	aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN0));
#ifdef WLAN_DUALBAND_CONCURRENT
	aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN1));
#endif
#endif
	aclRule.ingress_ipv4_tagif = 1;

	if (pEntry->filterProtocol != 0)
	{
		if (1 == pEntry->filterProtocol)
			aclRule.filter_fields |= INGRESS_L4_TCP_BIT;
		else if (2 == pEntry->filterProtocol)
			aclRule.filter_fields |= INGRESS_L4_UDP_BIT;
		else
			aclRule.filter_fields |= INGRESS_L4_ICMP_BIT;
	}

	if ((1 == pEntry->filterProtocol) || (2 == pEntry->filterProtocol)) {
		if(0 != pEntry->filterPort){
			aclRule.filter_fields |= INGRESS_L4_DPORT_RANGE_BIT;
			aclRule.ingress_dest_l4_port_start = aclRule.ingress_dest_l4_port_end = pEntry->filterPort;
		}
	}

	aclRule.filter_fields |= INGRESS_IPV4_SIP_RANGE_BIT;
	mask = ~0 << (sizeof(ipaddr_t)*8 - pEntry->localMask);
	mask = htonl(mask);
	aclRule.ingress_src_ipv4_addr_start = ntohl(*((ipaddr_t *)pEntry->localIP) & mask);
	aclRule.ingress_src_ipv4_addr_end = ntohl(*((ipaddr_t *)pEntry->localIP) | ~mask);

	aclRule.filter_fields |= INGRESS_IPV4_DIP_RANGE_BIT;
	mask = ~0 << (sizeof(ipaddr_t)*8 - pEntry->remoteMask);
	mask = htonl(mask);
	aclRule.ingress_dest_ipv4_addr_start = ntohl(*((ipaddr_t *)pEntry->remoteIP) & mask);
	aclRule.ingress_dest_ipv4_addr_end = ntohl(*((ipaddr_t *)pEntry->remoteIP) | ~mask);

	if(!(fp = fopen(RG_IPSEC_TRAP_RULES_FILE, "a")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -1;
	}

	if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0)
		fprintf(fp, "%d\n", aclIdx);
	else
		printf("[%s %d]rtk_rg_aclFilterAndQos_add failed!\n", __func__, __LINE__);

	/* trap all ESP/AH/ISAKMP packets to PS */
	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	aclRule.action_type = ACL_ACTION_TYPE_TRAP_TO_PS;
	aclRule.acl_weight = RG_TRAP_ACL_WEIGHT;
	aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	aclRule.filter_fields = INGRESS_IPV4_TAGIF_BIT | INGRESS_PORT_BIT;
	aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask() | RG_get_all_lan_phyPortMask();
	aclRule.ingress_ipv4_tagif = 1;

	aclRule.filter_fields |= INGRESS_L4_POROTCAL_VALUE_BIT;
	aclRule.ingress_l4_protocal = 50;	//ESP
	if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0)
		fprintf(fp, "%d\n", aclIdx);
	else
		printf("[%s %d]rtk_rg_aclFilterAndQos_add failed!\n", __func__, __LINE__);

	aclRule.ingress_l4_protocal = 51;	//AH
	if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0)
		fprintf(fp, "%d\n", aclIdx);
	else
		printf("[%s %d]rtk_rg_aclFilterAndQos_add failed!\n", __func__, __LINE__);

	aclRule.filter_fields &= ~INGRESS_L4_POROTCAL_VALUE_BIT;
	aclRule.filter_fields |= INGRESS_L4_UDP_BIT;
	aclRule.filter_fields |= INGRESS_L4_SPORT_RANGE_BIT;
	aclRule.ingress_src_l4_port_start = aclRule.ingress_src_l4_port_end = 500;
	aclRule.filter_fields |= INGRESS_L4_DPORT_RANGE_BIT;
	aclRule.ingress_dest_l4_port_start = aclRule.ingress_dest_l4_port_end = 500;
	if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0)
		fprintf(fp, "%d\n", aclIdx);
	else
		printf("[%s %d]rtk_rg_aclFilterAndQos_add failed!\n", __func__, __LINE__);

	fclose(fp);
	return 0;
}

int RG_flush_ipsec_trap_rule(void)
{
	FILE *fp;
	int acl_idx;

	fp = fopen(RG_IPSEC_TRAP_RULES_FILE, "r");
	if(fp == NULL)
		return 0;

	while(fscanf(fp, "%d\n", &acl_idx) != EOF)
	{
		if(rtk_rg_aclFilterAndQos_del(acl_idx))
			DBPRINT(1, "RG_flush_ipsec_trap_rule delete ACL failed! idx = %d\n", acl_idx);
	}

	fclose(fp);
	unlink(RG_IPSEC_TRAP_RULES_FILE);
	
	return 0;
}
#endif

int RG_Del_All_LAN_Interfaces()
{
	FILE *fp;
	int lanIdx;

	if(!(fp = fopen(RG_LAN_INF_IDX, "r")))
		return -2;
	//va_cmd("/bin/cat", 1, 1, RG_LAN_INF_IDX);

	while(fscanf(fp, "%d\n", &lanIdx) != EOF)
	{
//printf("%s-%d id=%d\n",__func__,__LINE__,lanIdx);
		if(rtk_rg_interface_del(lanIdx))
			DBPRINT(1, "RG_Del_All_LAN_Interfaces failed! (idx = %d)\n", lanIdx);
	}

	fclose(fp);
	unlink(RG_LAN_INF_IDX);
	return 0;
}

int RG_WAN_Interface_Del(unsigned int rg_wan_idx)
{
	int ret=0;
	char cmdStr[64];
	int pon_mode=0;
	rtk_rg_intfInfo_t intf_info;
	//printf("%s-%d del RG WAN[%d]\n",__func__,__LINE__,rg_wan_idx);
#if defined(CONFIG_RTK_L34_ENABLE) && defined(CONFIG_GPON_FEATURE)
	mib_get(MIB_PON_MODE, (void *)&pon_mode);
	if(pon_mode == GPON_MODE){
#if ! defined(_LINUX_2_6_) && defined(CONFIG_TR142_MODULE)
		snprintf(cmdStr, sizeof(cmdStr)-1,"echo clear %u > %s", rg_wan_idx, TR142_WAN_IDX_MAP);
		system(cmdStr);
#endif
		snprintf(cmdStr, sizeof(cmdStr),"echo %d %d %d %d %d %d %d > %s",rg_wan_idx,0,0,0,0,0,0,OMCI_WAN_INFO);
		system(cmdStr);
	}
#endif
	ret = rtk_rg_intfInfo_find(&intf_info, &rg_wan_idx);
	if(ret){
	    //printf("[%s:%d]Find RG interface for wan index %d Fail!\n",__func__,__LINE__,rg_wan_idx);
		return -1;
	}
	FlushRTK_RG_WAN_Port_mapping_ACL(rg_wan_idx);
	if(rtk_rg_interface_del(rg_wan_idx)){
		DBPRINT(1, "%s failed! (idx = %d)\n", __func__, rg_wan_idx);
		ret =-1;
	}
	return ret;
}

#ifdef CONFIG_00R0//iulian added cvlan for multicast

/* add policy route for dhcp option and ripv2 */
int RG_set_policy_route(char* ifname_wan) 
{
	char buff[256], ifname[IFNAMSIZ];
	int flgs, i=0, entrynum, isDhcp=0;
	struct in_addr dest, mask, gateway, dest_if, mask_if;
	MIB_CE_ATM_VC_T entry;
	FILE *file;

	entrynum = mib_chain_total(MIB_ATM_VC_TBL);
	for (i=0; i<entrynum; i++){
		if (!mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&entry) || !entry.enable)
			continue;
		ifGetName(entry.ifIndex,ifname,sizeof(ifname));
		if(!strcmp(ifname, ifname_wan))
			break;
	}
	
	if(i == entrynum){
		printf("[%s %d]can not find the interface %s", __func__, __LINE__, ifname_wan);
		return;
	}
	
	/* Delete the old setting */
	RG_del_static_route_by_acl(entry.rg_wan_idx);

	if (!(file = fopen("/proc/net/route", "r"))) {
		DBG_DHCP_PRF("%s-%d: Error: cannot open /proc/net/route\n",__func__,__LINE__);
		return -1;
	}
	getInAddr(ifname_wan,IP_ADDR,(void *)&dest_if);
	getInAddr(ifname_wan,SUBNET_MASK,(void *)&mask_if);

	fgets(buff, sizeof(buff), file);
	while (fgets(buff, sizeof(buff), file) != NULL) {
		if (sscanf(buff, "%s%x%x%x%*d%*d%*d%x", &ifname, &dest, &gateway, &flgs, &mask) != 5) {
			DBG_DHCP_PRF("%s-%d: Unsuported kernel route format\n",__func__,__LINE__);
			fclose(file);
			return 0;
		}
		if(strcmp(ifname,ifname_wan) != 0)
			continue;
		
		// filter the direct connect route
		if (dest.s_addr == 0)
			continue;
		if ((flgs & RTF_UP) && (mask.s_addr !=0 )) {
			if ((dest.s_addr & mask.s_addr) == (dest_if.s_addr & mask_if.s_addr)) {
				//printf("dest=0x%x, mask=0x%x\n", dest.s_addr, mask.s_addr); //Direct Connected interface
				continue;
			}
		}

		if (RG_add_static_route_by_acl(dest.s_addr, mask.s_addr, gateway.s_addr, entry.rg_wan_idx) < 0) {
			printf("rtk_rg_dhcpClientInfo_set static route error!!!\n");
			continue;
		}
		//printf("[%s:%d] : Found the static route ifname=%s dest=%x gateway=%x mask=%x\n", __FUNCTION__, __LINE__, ifname, dest, gateway, mask);
	}
	fclose(file);	
}
#endif

int RG_WAN_CVLAN_DEL(int vlanID)
{
	rtk_rg_cvlan_info_t cvlan_info;
	memset(&cvlan_info, 0, sizeof(rtk_rg_cvlan_info_t));
	cvlan_info.vlanId = vlanID;
	if(rtk_rg_cvlan_get(&cvlan_info) == RT_ERR_RG_OK)
		rtk_rg_cvlan_del(vlanID);
	return 0;
}

#ifdef CONFIG_00R0//iulian added cvlan for multicast
int RG_WAN_CVLAN()
{
	int i=0,j=0;
	unsigned int totalEntry;
	MIB_CE_ATM_VC_T cVlanEntry;
	rtk_rg_cvlan_info_t cVlan_info;
	rtk_rg_portmask_t unuse_portmask;

	memset(&unuse_portmask, 0, sizeof(rtk_rg_portmask_t));
	unuse_portmask.portmask |= ((1<<RTK_RG_PORT0) | (1<<RTK_RG_PORT1) |(1<<RTK_RG_PORT2)| (1<<RTK_RG_PORT3)) ;

	totalEntry = mib_chain_total(MIB_ATM_VC_TBL);
	if (totalEntry >= MAX_VC_NUM) {
		return -1;
	}

	for (i=0; i<totalEntry; i++) {
		if(mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&cVlanEntry) == 0)
			continue;
//iulian
		memset(&cVlan_info, 0, sizeof(rtk_rg_cvlan_info_t));
		if( cVlanEntry.itfGroupNum != 0  && cVlanEntry.cmode == CHANNEL_MODE_BRIDGE ) { //belong to the bridge group
			cVlan_info.vlanId = cVlanEntry.vid;
			for (j = PMAP_ETH0_SW0; j <= PMAP_ETH0_SW3 && j < SW_LAN_PORT_NUM; ++j)
			{
				if (BIT_IS_SET(cVlanEntry.itfGroup, j)) {
					cVlan_info.memberPortMask.portmask |= RG_get_lan_phyPortMask(1<<j);
					cVlan_info.untagPortMask.portmask |= RG_get_lan_phyPortMask(1<<j);
					unuse_portmask.portmask &= (~(1<<j));
				}
			}
#ifdef WLAN_SUPPORT //KNOW ISSUE : cvlan can't split the different AP on the same WLAN
			for (j = PMAP_WLAN0; j <= PMAP_WLAN0_VAP3; ++j)
			{
				if (BIT_IS_SET(cVlanEntry.itfGroup, j)) {
					cVlan_info.memberPortMask.portmask |= 1<<RTK_RG_EXT_PORT0;
					cVlan_info.untagPortMask.portmask |= 1<<RTK_RG_EXT_PORT0;
				}
			}

			for (j = PMAP_WLAN1; j <= PMAP_WLAN1_VAP3; ++j)
			{
				if (BIT_IS_SET(cVlanEntry.itfGroup, j)) {
					cVlan_info.memberPortMask.portmask |= 1<<RTK_RG_EXT_PORT1;
					cVlan_info.untagPortMask.portmask |= 1<<RTK_RG_EXT_PORT1;
				}
			}
#endif // WLAN_SUPPORT
			cVlan_info.memberPortMask.portmask |= ((1<<RTK_RG_PORT_CPU)|(1<<RTK_RG_PORT_PON) | (1<<RTK_RG_PORT_RGMII));
			if((rtk_rg_cvlan_add(&cVlan_info))!=SUCCESS) {
				return -1;
			}
		}
	}


	for (i=0; i<totalEntry; i++) { //Belong to the default group
		if(mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&cVlanEntry) == 0)
			continue;
		memset(&cVlan_info, 0, sizeof(rtk_rg_cvlan_info_t));
		if( cVlanEntry.itfGroupNum == 0 ){ //belong to default group
			cVlan_info.vlanId = cVlanEntry.vid;
			cVlan_info.memberPortMask.portmask |= (1<<RTK_RG_PORT_CPU) | (1<<RTK_RG_PORT_RGMII)| (1<<RTK_RG_PORT_PON)/* | RG_get_lan_phyPortMask(unuse_portmask.portmask)*/;
			cVlan_info.untagPortMask.portmask |= RG_get_lan_phyPortMask(unuse_portmask.portmask) ;

#ifdef WLAN_SUPPORT
			//cVlan_info.memberPortMask.portmask |= (1<<RTK_RG_EXT_PORT0) | (1<<RTK_RG_EXT_PORT1);
			cVlan_info.untagPortMask.portmask  |= (1<<RTK_RG_EXT_PORT0) | (1<<RTK_RG_EXT_PORT1);
#endif
		if((rtk_rg_cvlan_add(&cVlan_info))!=SUCCESS) {
				return -1;
			}
		}
	}
	return 0;
}
#endif


/*RG just only can set one default route, so we should block it in user space*/
/*The first Internet connection is set as default route, let others dgw=0*/
//check ATM_VC_TBL.x.dgw (default route is already exist!)
//check modify ATM_VC_TBL index if equal to default route
/*
check RG default route exist or not
3: means you modify the D route --> not D route; or del D route entry
2: D route existed already
1: the entry you choose is D route, must enable ATM_VC_TBL mib entry dgw = 1
0: D route is not exist, but don't need to be setted (bridge mode, or routing none_internet)
-1: something error!
*/
#ifndef CONFIG_00R0
int RG_check_Droute(int configAll, MIB_CE_ATM_VC_Tp pEntry, int *EntryID)
{
	int vcTotal=-1;
	int i,key,idx=-1;
	MIB_CE_ATM_VC_T Entry;
	vcTotal = mib_chain_total(MIB_ATM_VC_TBL);
	if(vcTotal<0)
		return -1;
//	if(configAll == CONFIGALL)
//		return 0;
	key=0;
	for (i = 0; i < vcTotal; i++)
	{
		if (!mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&Entry))
				return -1;
		if(Entry.dgw == 1){
	    /*If any entry match the condition, would return directly*/
	    /*Below conditons (case 0, 1, 3) are terminated*/
			return 2;
		}
		//VCentry existed an internet and routing WAN
		if((Entry.applicationtype & X_CT_SRV_INTERNET) && (Entry.cmode > 0) && (key==0)){
			key++;
			idx = i;
		}
	}
	if(key > 0){
		//get D route entry!
		if(!mib_chain_get(MIB_ATM_VC_TBL, idx, (void *)&Entry)){
			printf("%s-%d get chain MIB_ATM_VC_TBL fail\n",__func__,__LINE__);
			return -1;
		}
		Entry.dgw = 1;
		if( pEntry==NULL && EntryID == NULL){
			//it means we are at starting up process
			fprintf(stderr, "%s-%d key=%d, idx=%d\n",__func__,__LINE__,key,idx);
			mib_chain_update(MIB_ATM_VC_TBL, (void *)&Entry, idx);
			return 4;
		}

		fprintf(stderr, "%s-%d key=%d, Entry.dgw=%d\n",__func__,__LINE__,key,Entry.dgw);

		if(pEntry && pEntry->ifIndex == Entry.ifIndex){
		/*the entry which you modified is setted as D route!*/
			mib_chain_update(MIB_ATM_VC_TBL, (void *)&Entry, idx);
			return 1;
		}
		/*Two conditions will go here*/
		/*1. The original D route is deleted, choose another one as D route*/
		/*2. The original D route is modified, choose another one as D route*/
		/*the new one must restart again.*/
		*EntryID = idx;
		mib_chain_update(MIB_ATM_VC_TBL, (void *)&Entry, idx);
		return 3;
	}
	else
		return 0;
}
#else
/* Only 1 connection can have DGW, disable others */
int RG_check_Droute(int configAll, MIB_CE_ATM_VC_Tp pEntry, int *EntryID)
{
	int vcTotal=-1;
	int i,key,idx=-1;
	MIB_CE_ATM_VC_T Entry;

	if(pEntry == NULL || EntryID == NULL)
		return 0;

	if(!pEntry->enable || pEntry->dgw == 0)
		return 0;

	vcTotal = mib_chain_total(MIB_ATM_VC_TBL);
	if(vcTotal<0)
		return -1;

	key=0;
	for (i = 0; i < vcTotal; i++)
	{
		if (!mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&Entry))
			return -1;

		if(!Entry.enable || pEntry->ifIndex == Entry.ifIndex)
			continue;

		if(Entry.dgw)
		{
			fprintf(stderr, "%s-%d Disable default gateway on WAN idx=%d\n", __func__,__LINE__, idx);
			Entry.dgw = 0;
			mib_chain_update(MIB_ATM_VC_TBL, &Entry, i);
			*EntryID = i;
			return 3;
		}
	}

	return 0;
}
#endif

//#ifdef CONFIG_MCAST_VLAN
char MCAST_ADDR[MAC_ADDR_LEN]={0x01,0x00,0x5E,0x00,0x00,0x00};
char MCAST_MASK[MAC_ADDR_LEN]={0xff,0xff,0xff,0x00,0x00,0x00};
char MCAST_ADDR_V6[MAC_ADDR_LEN]={0x33,0x33,0x00,0x00,0x00,0x00};
char MCAST_MASK_V6[MAC_ADDR_LEN]={0xff,0xff,0x00,0x00,0x00,0x00};

/*one mVlan can only be setted to one WAN*/
int RTK_RG_ACL_Handle_IGMP(FILE *fp, MIB_CE_ATM_VC_T *pentry)
{
	unsigned char mode,igmp_snoop_flag=0;
	rtk_rg_aclFilterAndQos_t aclRule;
	int i,aclIdx=0, ret=0;
	rtk_rg_initParams_t init_param;
	int port_idx=0;
	unsigned short itfGroup;
	unsigned int fwdcpu_vid;
	int dev_idx=0; /*only support master WLAN*/

	bzero(&init_param, sizeof(rtk_rg_initParams_t));
	if((ret = rtk_rg_initParam_get(&init_param)) != SUCCESS)
	{
		fprintf(stderr, "rtk_rg_initParam_set failed! ret=%d\n", ret);
		return -1;
	}

	//check igmp snooping is on/off
	mib_get(MIB_MPMODE, (void *)&mode);
	igmp_snoop_flag = (((mode&MP_IGMP_MASK)==MP_IGMP_MASK)?1:0);
//AUG_PRT("igmp_snoop_flag:%d\n",igmp_snoop_flag);
	if(!igmp_snoop_flag){
//		AUG_PRT("%s-%d\n",__func__,__LINE__);

		memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
		//tranfser mVid to internal vid 1, to flood to all member!
		aclRule.filter_fields |= INGRESS_PORT_BIT;
		aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();//wan port
		aclRule.acl_weight = RG_DEFAULT_ACL_WEIGHT;
		aclRule.filter_fields |= INGRESS_CTAG_VID_BIT;

		if(pentry->mVid > 0)
			aclRule.ingress_ctag_vid = pentry->mVid;
		else
			aclRule.ingress_ctag_vid = pentry->vid;
		aclRule.filter_fields |= INGRESS_DMAC_BIT;
		memcpy(&aclRule.ingress_dmac,MCAST_ADDR,MAC_ADDR_LEN);
		memcpy(&aclRule.ingress_dmac_mask,MCAST_MASK,MAC_ADDR_LEN);
		aclRule.action_type = ACL_ACTION_TYPE_QOS;
		aclRule.qos_actions |= ACL_ACTION_ACL_INGRESS_VID_BIT;
		mib_get(MIB_FWD_CPU_VLAN_ID, (void *)&fwdcpu_vid);
		aclRule.action_acl_ingress_vid = fwdcpu_vid; //lan interface's vlan
		ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx);
		if(ret == 0){
			fprintf(fp,"%d\n",aclIdx);
//			AUG_PRT("%s-%d aclIdx=%d\n",__func__,__LINE__,aclIdx);

			//fprintf(stderr, "add mCast ACL Vlan:%d, index=%d success\n",pentry->mVid, aclIdx);
		}else{
			fprintf(stderr,"rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n", ret);
//			AUG_PRT("%s-%d ret=%d\n",__func__,__LINE__,ret);
			return -1;
		}
		goto CHECK_V4_SNOOPING;
	}

	if(pentry->mVid > 0){
		//transfer multicast vlan to wan's vlan to avoid ingress vlan filter.
		memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
		aclRule.filter_fields |= INGRESS_PORT_BIT;
		aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();//wan port
		aclRule.acl_weight = RG_DEFAULT_ACL_WEIGHT;
		aclRule.filter_fields |= INGRESS_CTAG_VID_BIT;
		aclRule.ingress_ctag_vid = pentry->mVid; //multicast vlan
		aclRule.filter_fields |= INGRESS_DMAC_BIT;
		memcpy(&aclRule.ingress_dmac,MCAST_ADDR,MAC_ADDR_LEN);
		memcpy(&aclRule.ingress_dmac_mask,MCAST_MASK,MAC_ADDR_LEN);
		aclRule.action_type = ACL_ACTION_TYPE_QOS;
		aclRule.qos_actions |= ACL_ACTION_ACL_INGRESS_VID_BIT;
		//fprintf(stderr, "port_idx:%d\n",port_idx);
		aclRule.action_acl_ingress_vid = pentry->vid; //wan's vlan
		//mib_get(MIB_FWD_CPU_VLAN_ID, (void *)&fwdcpu_vid);
		//aclRule.action_acl_ingress_vid = fwdcpu_vid;
		if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0){
			fprintf(fp,"%d\n",aclIdx);
			fprintf(stderr, "add mCast ACL Vlan:%d, index=%d success\n",pentry->mVid, aclIdx);
		}else{
			fprintf(stderr,"rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n", ret);
			return -1;
		}
	}

	#if 0
	port_idx=0;
	itfGroup = pentry->itfGroup;
	//printf("itfGroup:%x\n",itfGroup);
	//memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	if(itfGroup > 0){
		while(itfGroup > 0){
			if(itfGroup & 1){
				memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
				aclRule.filter_fields |= INGRESS_PORT_BIT;
				aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();//wan port
				aclRule.acl_weight = RG_DEFAULT_ACL_WEIGHT;
				aclRule.filter_fields |= INGRESS_CTAG_VID_BIT;
				if(pentry->mVid)
					aclRule.ingress_ctag_vid = pentry->mVid;
				else
					aclRule.ingress_ctag_vid = pentry->vid;
				aclRule.filter_fields |= INGRESS_DMAC_BIT;
				memcpy(&aclRule.ingress_dmac,MCAST_ADDR,MAC_ADDR_LEN);
				memcpy(&aclRule.ingress_dmac_mask,MCAST_MASK,MAC_ADDR_LEN);
				aclRule.action_type = ACL_ACTION_TYPE_QOS;
				aclRule.qos_actions |= ACL_ACTION_ACL_INGRESS_VID_BIT;
				//fprintf(stderr, "port_idx:%d\n",port_idx);
				RG_get_lan_phyPortId(port_idx);
				if(port_idx < 4){ //lan
					int phyID;
					phyID = RG_get_lan_phyPortId(port_idx);
					//fprintf(stderr, "%s-%d phyID:%d, logID=%d\n",__func__,__LINE__,phyID,port_idx);
					rtk_rg_portBasedCVlanId_get(phyID,&pPvid);
				}
				else{ //wlan
					int phyID;
					phyID = RG_get_wlan_phyPortId(port_idx);
					//fprintf(stderr, "%s-%d phyID:%d, logID=%d\n",__func__,__LINE__,phyID,port_idx);
					rtk_rg_wlanDevBasedCVlanId_get(phyID,dev_idx,&pPvid);
				}
				aclRule.action_acl_ingress_vid = pPvid; //lan interface's vlan
				if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0){
					fprintf(fp,"%d\n",aclIdx);
					fprintf(stderr, "add mCast ACL Vlan:%d, index=%d success\n",pentry->mVid, aclIdx);
				}else{
					fprintf(stderr,"rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n", ret);
					return -1;
				}
				break;
			}
			port_idx++;
			itfGroup=itfGroup>>1;
		}
	}else{
		memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
		//we have mVid, but not binding to any port.
		aclRule.filter_fields |= INGRESS_PORT_BIT;
		aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();//wan port
		aclRule.acl_weight = RG_DEFAULT_ACL_WEIGHT;
		aclRule.filter_fields |= INGRESS_CTAG_VID_BIT;
		if(pentry->mVid)
			aclRule.ingress_ctag_vid = pentry->mVid;
		else
			aclRule.ingress_ctag_vid = pentry->vid;
		aclRule.filter_fields |= INGRESS_DMAC_BIT;
		memcpy(&aclRule.ingress_dmac,MCAST_ADDR,MAC_ADDR_LEN);
		memcpy(&aclRule.ingress_dmac_mask,MCAST_MASK,MAC_ADDR_LEN);
		aclRule.action_type = ACL_ACTION_TYPE_QOS;
		aclRule.qos_actions |= ACL_ACTION_ACL_INGRESS_VID_BIT;
		//rtk_rg_portBasedCVlanId_get(port_idx,&pPvid);
		if(pentry->applicationtype & X_CT_SRV_INTERNET)
			aclRule.action_acl_ingress_vid = init_param.fwdVLAN_BIND_INTERNET; //lan interface's vlan
		else
			aclRule.action_acl_ingress_vid = pentry->vid;//init_param.fwdVLAN_BIND_OTHER; //lan interface's vlan
		if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0){
			fprintf(fp,"%d\n",aclIdx);
		//fprintf(stderr, "add mCast ACL Vlan:%d, index=%d success\n",entry.mVid, aclIdx);
		}else{
			fprintf(stderr,"rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n", ret);
			return -1;
		}
	}
	#endif
	CHECK_V4_SNOOPING:
//	AUG_PRT("%s-%d ret=%d\n",__func__,__LINE__,ret);
	return 0;

}

int RTK_RG_ACL_Handle_MLD(FILE *fp,MIB_CE_ATM_VC_T *pentry)
{
	unsigned char mode;
	unsigned char mld_snoop_flag=0;
	rtk_rg_aclFilterAndQos_t aclRule;
	int i,aclIdx=0, ret=0;
	rtk_rg_initParams_t init_param;
	int port_idx=0;
	unsigned short itfGroup;
	unsigned int fwdcpu_vid;
	int dev_idx=0; /*only support master WLAN*/
	bzero(&init_param, sizeof(rtk_rg_initParams_t));
	if((ret = rtk_rg_initParam_get(&init_param)) != SUCCESS)
	{
		fprintf(stderr, "rtk_rg_initParam_set failed! ret=%d\n", ret);
		return -1;
	}
	//check mld snooping is on/off
	mib_get(MIB_MPMODE, (void *)&mode);
	mld_snoop_flag = (((mode&MP_MLD_MASK)==MP_MLD_MASK)?1:0);
//fprintf(stderr, "%s-%d mld_snoop_flag=%d\n",__func__,__LINE__,mld_snoop_flag);
//	AUG_PRT("mld_snoop_flag:%d\n",mld_snoop_flag);

	//handle multicast v6
	if(!mld_snoop_flag){
		//multicast ipv6
		memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
		//tranfser mVid to internal vid 1, to flood to all member!
		aclRule.filter_fields |= INGRESS_PORT_BIT;
		aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();//wan port
		aclRule.acl_weight = RG_DEFAULT_ACL_WEIGHT;
		aclRule.filter_fields |= INGRESS_CTAG_VID_BIT;

		if(pentry->mVid > 0)
			aclRule.ingress_ctag_vid = pentry->mVid;
		else
			aclRule.ingress_ctag_vid = pentry->vid;
		aclRule.filter_fields |= INGRESS_DMAC_BIT;
		memcpy(&aclRule.ingress_dmac,MCAST_ADDR_V6,MAC_ADDR_LEN);
		memcpy(&aclRule.ingress_dmac_mask,MCAST_MASK_V6,MAC_ADDR_LEN);
		aclRule.action_type = ACL_ACTION_TYPE_QOS;
		aclRule.qos_actions |= ACL_ACTION_ACL_INGRESS_VID_BIT;
		mib_get(MIB_FWD_CPU_VLAN_ID, (void *)&fwdcpu_vid);
		aclRule.action_acl_ingress_vid = fwdcpu_vid; //lan interface's vlan
		if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0){
			fprintf(fp,"%d\n",aclIdx);
//			AUG_PRT("%s-%d aclIdx=%d\n",__func__,__LINE__,aclIdx);
			//fprintf(stderr, "%s-%d add mCast ACL Vlan:%d, index=%d success\n",__func__,__LINE__,pentry->mVid, aclIdx);
		}else{
			fprintf(stderr,"rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n", ret);
//			AUG_PRT("%s-%d ret=%d\n",__func__,__LINE__,ret);

			return -1;
		}
		goto CHECK_V6_SNOOPING;
	}

	if(pentry->mVid > 0)
	{
		//multicast ipv6, mld
		memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
		aclRule.filter_fields |= INGRESS_PORT_BIT;
		aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();//wan port
		aclRule.acl_weight = RG_DEFAULT_ACL_WEIGHT;
		aclRule.filter_fields |= INGRESS_CTAG_VID_BIT;
		aclRule.ingress_ctag_vid = pentry->mVid;
		aclRule.filter_fields |= INGRESS_DMAC_BIT;
		memcpy(&aclRule.ingress_dmac,MCAST_ADDR_V6,MAC_ADDR_LEN);
		memcpy(&aclRule.ingress_dmac_mask,MCAST_MASK_V6,MAC_ADDR_LEN);
		aclRule.action_type = ACL_ACTION_TYPE_QOS;
		aclRule.qos_actions |= ACL_ACTION_ACL_INGRESS_VID_BIT;
		aclRule.action_acl_ingress_vid = pentry->vid; //wan interface's vlan
		if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0){
			fprintf(fp,"%d\n",aclIdx);
			fprintf(stderr, "%s-%d add mCast ACL Vlan:%d, index=%d success\n",__func__,__LINE__,pentry->mVid, aclIdx);
		}else{
			fprintf(stderr,"rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n", ret);
			return -1;
		}
	}

	#if 0
	port_idx=0;
	itfGroup = pentry->itfGroup;
	//printf("itfGroup:%x\n",itfGroup);
	//memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	if(itfGroup > 0){
		while(itfGroup > 0){
			if(itfGroup & 1){
				//multicast ipv6, mld
				memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
				aclRule.filter_fields |= INGRESS_PORT_BIT;
				aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();//wan port
				aclRule.acl_weight = RG_DEFAULT_ACL_WEIGHT;
				aclRule.filter_fields |= INGRESS_CTAG_VID_BIT;
				aclRule.ingress_ctag_vid = pentry->mVid;
				aclRule.filter_fields |= INGRESS_DMAC_BIT;
				memcpy(&aclRule.ingress_dmac,MCAST_ADDR_V6,MAC_ADDR_LEN);
				memcpy(&aclRule.ingress_dmac_mask,MCAST_MASK_V6,MAC_ADDR_LEN);
				aclRule.action_type = ACL_ACTION_TYPE_QOS;
				aclRule.qos_actions |= ACL_ACTION_ACL_INGRESS_VID_BIT;
				//fprintf(stderr, "port_idx:%d\n",port_idx);
				if(port_idx < 4){ //lan
					int phyID;
					phyID = RG_get_lan_phyPortId(port_idx);
					//fprintf(stderr, "%s-%d phyID:%d, logID=%d\n",__func__,__LINE__,phyID,port_idx);
					rtk_rg_portBasedCVlanId_get(phyID,&pPvid);
				}
				else{ //wlan
					int phyID;
					phyID = RG_get_wlan_phyPortId(port_idx);
					//fprintf(stderr, "%s-%d phyID:%d, logID=%d\n",__func__,__LINE__,phyID,port_idx);
					rtk_rg_wlanDevBasedCVlanId_get(port_idx-4,dev_idx,&pPvid);
				}

				aclRule.action_acl_ingress_vid = pPvid; //lan interface's vlan
				if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0){
					fprintf(fp,"%d\n",aclIdx);
					fprintf(stderr, "%s-%d add mCast ACL Vlan:%d, index=%d success\n",__func__,__LINE__,pentry->mVid, aclIdx);
				}else{
					fprintf(stderr,"rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n", ret);
					return -1;
				}
				break;
			}
			port_idx++;
			itfGroup=itfGroup>>1;
		}
	}else{
			//multicast ipv6, mld
			memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
			//we have mVid, but not binding to any port.
			aclRule.filter_fields |= INGRESS_PORT_BIT;
			aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();//wan port
			aclRule.acl_weight = RG_DEFAULT_ACL_WEIGHT;
			aclRule.filter_fields |= INGRESS_CTAG_VID_BIT;
			aclRule.ingress_ctag_vid = pentry->mVid;
			aclRule.filter_fields |= INGRESS_DMAC_BIT;
			memcpy(&aclRule.ingress_dmac,MCAST_ADDR_V6,MAC_ADDR_LEN);
			memcpy(&aclRule.ingress_dmac_mask,MCAST_MASK_V6,MAC_ADDR_LEN);
			aclRule.action_type = ACL_ACTION_TYPE_QOS;
			aclRule.qos_actions |= ACL_ACTION_ACL_INGRESS_VID_BIT;
			//rtk_rg_portBasedCVlanId_get(port_idx,&pPvid);
			if(pentry->applicationtype & X_CT_SRV_INTERNET)
				aclRule.action_acl_ingress_vid = init_param.fwdVLAN_BIND_INTERNET; //lan interface's vlan
			else
				aclRule.action_acl_ingress_vid = init_param.fwdVLAN_BIND_OTHER; //lan interface's vlan
			if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0){
				fprintf(fp,"%d\n",aclIdx);
				fprintf(stderr, "%s-%d add mCast ACL Vlan:%d, index=%d success\n",__func__,__LINE__,pentry->mVid, aclIdx);
			}else{
				fprintf(stderr,"rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n", ret);
				return -1;
			}

	}
	#endif
	CHECK_V6_SNOOPING:
	//AUG_PRT("%s-%d ret=%d\n",__func__,__LINE__,ret);

	return 0;

}

int RTK_RG_ACL_Add_mVlan(void)
{
	MIB_CE_ATM_VC_T entry;
	unsigned char mode,igmp_snoop_flag=0;
	int port_idx=0;
	int pPvid;
	int totalEntry = mib_chain_total(MIB_ATM_VC_TBL);
	int i,aclIdx=0, ret;
	unsigned short itfGroup;
	rtk_rg_aclFilterAndQos_t aclRule;
	FILE *fp = NULL;
	int key=0;
    char cmdStr[64];
	rtk_rg_initParams_t init_param;
	int wlan_idx=0;
	int dev_idx=0; /*only support master WLAN*/
	unsigned char mldproxyEnable=0;
	unsigned int mldproxyItf=0;
	int setup_ds_bc_flag=0;
	if(!(fp = fopen(RG_ACL_MVLAN_RULES_FILE, "a")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -2;
	}
//	AUG_PRT("%s-%d totalEntry=%d\n",__func__,__LINE__,totalEntry);

	for (i = 0; i < totalEntry; i++)
	{
		if (mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&entry) == 0)
			continue;
		//if(entry.mVid > 0){
//AUG_PRT("%s-%d entry.IpProtocol=%d\n",__func__,__LINE__, entry.IpProtocol);
#ifdef CONFIG_IPV6
			if(entry.IpProtocol & IPVER_IPV4 || entry.cmode == 0){
#endif
//AUG_PRT("%s-%d entry.IpProtocol=%d\n",__func__,__LINE__, entry.IpProtocol);
				RTK_RG_ACL_Handle_IGMP(fp,&entry);
#if 0
				if(entry.enableIGMP){
					if(entry.mVid > 0){
					//for igmp query or mld query~
					memset(&filterRule, 0, sizeof(rtk_rg_gpon_ds_bc_vlanfilterAndRemarking_t));
					//rg set gponDsBcFilter pattern ingress_ctagIf 1
					filterRule.filter_fields |= GPON_DS_BC_FILTER_INGRESS_CTAGIf_BIT;
					filterRule.ingress_ctagIf = 1;
					//rg set gponDsBcFilter pattern ingress_ctag_cvid 600
					filterRule.filter_fields |= GPON_DS_BC_FILTER_INGRESS_CVID_BIT;
					filterRule.ingress_ctag_cvid = entry.mVid;
					//rg set gponDsBcFilter pattern egress_portmask 0x40
					//mvid 600 to cpu --> tag vid44
					filterRule.filter_fields |= GPON_DS_BC_FILTER_EGRESS_PORT_BIT;
					filterRule.egress_portmask.portmask |= RTK_RG_MAC_PORT_CPU;//cpu port
					//rg set gponDsBcFilter action tag_decision 1 tag_cvid 44 tag_cpri 0
					filterRule.ctag_action.ctag_decision = RTK_RG_GPON_BC_FORCE_TAGGIN_WITH_CVID;
					filterRule.ctag_action.assigned_ctag_cvid = entry.vid;
					filterRule.ctag_action.assigned_ctag_cpri = 0;
					rtk_rg_gponDsBcFilterAndRemarking_add(&filterRule, &ds_bc_index);
//fprintf(stderr, "%s-%d ds_bc_index=%d\n",__func__,__LINE__,ds_bc_index);
					setup_ds_bc_flag = 1;
					}
				}
#endif
#ifdef CONFIG_IPV6
			}
			if(entry.IpProtocol & IPVER_IPV6 || entry.cmode == 0){
//AUG_PRT("%s-%d entry.IpProtocol=%d\n",__func__,__LINE__, entry.IpProtocol);

				RTK_RG_ACL_Handle_MLD(fp,&entry);
#if 0
				mib_get(MIB_MLD_PROXY_DAEMON, (void *)&mldproxyEnable);
//fprintf(stderr, "%s-%d mldproxyEnable=%d\n",__func__,__LINE__, mldproxyEnable);
				if(mldproxyEnable){
					if(entry.mVid > 0){
					mib_get(MIB_MLD_PROXY_EXT_ITF, (void *)&mldproxyItf);
//fprintf(stderr, "%s-%d mldproxyItf=0x%x setup_ds_bc_flag=%d\n",__func__,__LINE__,mldproxyItf,setup_ds_bc_flag);
					//setup_ds_bc_flag --> if wan has protocol IPv4_IPv6
					//, don't set the same rules twice!
						if((entry.ifIndex == mldproxyItf) && !setup_ds_bc_flag)
						{
							//for igmp query or mld query~
							memset(&filterRule, 0, sizeof(rtk_rg_gpon_ds_bc_vlanfilterAndRemarking_t));
							//rg set gponDsBcFilter pattern ingress_ctagIf 1
							filterRule.filter_fields |= GPON_DS_BC_FILTER_INGRESS_CTAGIf_BIT;
							filterRule.ingress_ctagIf = 1;
							//rg set gponDsBcFilter pattern ingress_ctag_cvid 600
							filterRule.filter_fields |= GPON_DS_BC_FILTER_INGRESS_CVID_BIT;
							filterRule.ingress_ctag_cvid = entry.mVid;
							//rg set gponDsBcFilter pattern egress_portmask 0x40
							//mvid 600 to cpu --> tag vid44
							filterRule.filter_fields |= GPON_DS_BC_FILTER_EGRESS_PORT_BIT;
							filterRule.egress_portmask.portmask |= RTK_RG_MAC_PORT_CPU;//cpu port
							//rg set gponDsBcFilter action tag_decision 1 tag_cvid 44 tag_cpri 0
							filterRule.ctag_action.ctag_decision = RTK_RG_GPON_BC_FORCE_TAGGIN_WITH_CVID;
							filterRule.ctag_action.assigned_ctag_cvid = entry.vid;
							filterRule.ctag_action.assigned_ctag_cpri = 0;
							rtk_rg_gponDsBcFilterAndRemarking_add(&filterRule, &ds_bc_index);
							//fprintf(stderr, "%s-%d ds_bc_index=%d\n",__func__,__LINE__,ds_bc_index);
						}
					}
				}
#endif
			}
#endif
//			setup_ds_bc_flag = 0;
#if 0
			memset(&filterRule, 0, sizeof(rtk_rg_gpon_ds_bc_vlanfilterAndRemarking_t));
			//rg set gponDsBcFilter pattern ingress_ctagIf 1
			filterRule.filter_fields |= GPON_DS_BC_FILTER_INGRESS_CTAGIf_BIT;
			filterRule.ingress_ctagIf = 1;
			//rg set gponDsBcFilter pattern ingress_ctag_cvid 600
			filterRule.ingress_ctag_cvid = entry->mVid;
			//rg set gponDsBcFilter pattern egress_portmask 0x40
			//mvid 600 to internal  --> untag
			filterRule.egress_portmask.portmask = 0x40;
			//rg set gponDsBcFilter action tag_decision 1 tag_cvid 0 tag_cpri 0
			filterRule.ctag_action.ctag_decision = RTK_RG_GPON_BC_FORCE_UNATG;
			filterRule.ctag_action.assigned_ctag_cvid = 0;
			filterRule.ctag_action.assigned_ctag_cpri = 0;
			rtk_rg_apollo_gponDsBcFilterAndRemarking_add(&filterRule, &ds_bc_index);
#endif
//fprintf(stderr, "%s-%d setup_ds_bc_flag=%d\n",__func__,__LINE__, setup_ds_bc_flag);
		//}
	}
	if(fp)
		fclose(fp);
	return 0;
}

int RTK_RG_ACL_Flush_mVlan(void)
{

	FILE *fp;
	int aclIdx=-1;
//	AUG_PRT("%s-%d\n",__func__,__LINE__);

	if(!(fp = fopen(RG_ACL_MVLAN_RULES_FILE, "r"))){
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -2;
	}
	while(fscanf(fp, "%d\n", &aclIdx) != EOF)
	{
//		AUG_PRT("%s-%d del acl index-%d\n",__func__,__LINE__,aclIdx);

		//fprintf(stderr, "del mvlan index %d\n",aclIdx);
		if(rtk_rg_aclFilterAndQos_del(aclIdx)){
			fprintf(stderr, "%s failed! idx = %d\n",__func__, aclIdx);
//			AUG_PRT("%s-%d del acl index-%d\n",__func__,__LINE__,aclIdx);
		}
	}
	fclose(fp);
	unlink(RG_ACL_MVLAN_RULES_FILE);
//	AUG_PRT("%s-%d\n",__func__,__LINE__);

	return 0;
}
//#endif /*CONFIG_MCAST_VLAN*/

#ifdef MAC_FILTER
int AddRTK_RG_MAC_Filter(MIB_CE_MAC_FILTER_T *MacEntry, int mode)
{
	int ret;
	
	if(mode == 1){ // Add black list
		int macfilterIdx;
		rtk_rg_macFilterEntry_t macFilterEntry;
		FILE *fp;

		memset(&macFilterEntry, 0, sizeof(rtk_rg_macFilterEntry_t));
		memcpy(&macFilterEntry.mac, MacEntry->srcMac, MAC_ADDR_LEN);
		macFilterEntry.direct = MacEntry->dir;

		if(!(fp = fopen(RG_MAC_RULES_FILE, "a")))
		{
			fprintf(stderr, "ERROR! %s\n", strerror(errno));
			return -1;
		}

		if((ret = rtk_rg_macFilter_add(&macFilterEntry, &macfilterIdx)) == 0)
			fprintf(fp, "%d\n", macfilterIdx);
		else
			printf("Set rtk_rg_macFilter_add failed! dir = %s error = 0x%x\n", MacEntry->dir? MacEntry->dir == 1? "Source": "Destination": "Both", ret);

		fclose(fp);
	}
	else // Add white list
	{		
		rtk_rg_macFilterWhiteList_t mac_filter_whitelist_info;

		memcpy(&mac_filter_whitelist_info.mac, MacEntry->srcMac, MAC_ADDR_LEN);
		ret=rtk_rg_mac_filter_whitelist_add(&mac_filter_whitelist_info);

		if(ret)
			printf("rtk_rg_mac_filter_whitelist_add fail!\n");
	}

	return 0;
}

int FlushRTK_RG_MAC_Filters()
{
	rtk_rg_macFilterWhiteList_t mac_filter_whitelist_info;
	int mac_idx = 0, ret = 0;
	FILE *fp;

	// Flush blacklist if exist
	if((fp = fopen(RG_MAC_RULES_FILE, "r"))) {
		while(fscanf(fp, "%d\n", &mac_idx) != EOF)
		{
			ret=rtk_rg_macFilter_del(mac_idx);
			if(ret)
				printf("rtk_rg_macFilter_del failed! idx = %d\n", mac_idx);
		}

		fclose(fp);
		unlink(RG_MAC_RULES_FILE);
	}

	// Flush whitelist if exist
	mac_filter_whitelist_info.del_flag = MACF_DEL_ALL;
	ret=rtk_rg_mac_filter_whitelist_del(&mac_filter_whitelist_info);

	if(ret)		
		printf("rtk_rg_mac_filter_whitelist_del failed! idx = %d\n", mac_idx);
	
	return 0;
}
#endif // MAC_FILTER

int RTK_RG_Dynamic_MAC_Entry_flush(void)
{
	rtk_rg_macEntry_t macEntry;
	int valid_idx, ret, cnt=0;;

	for(valid_idx=0 ; valid_idx<MAX_LUT_HW_TABLE_SIZE ; valid_idx++) {
		ret=rtk_rg_macEntry_find(&macEntry, &valid_idx);

		if(!ret) {
			if(!macEntry.static_entry) {				
				printf("%s %d: %d MAC=0x%X !\n", __func__, __LINE__, macEntry.mac);
				ret = rtk_rg_macEntry_del(valid_idx);
				if(!ret)
					cnt++;
			}
		}
	}

	printf("%s %d: %d MAC entries deleted !\n", __func__, __LINE__, cnt);
	return 0;
}

#ifdef PARENTAL_CTRL
int FlushRTK_RG_Parental_Ctrl(void)
{
	int mac_idx = 0, aclIdx = 0, ret = 0;
	FILE *fp;

	// Flush mac based parental ctrl rule if exist
	if((fp = fopen(RG_PARENTAL_CTRL_MAC_FILE, "r"))) {
		while(fscanf(fp, "%d\n", &mac_idx) != EOF)
		{
			ret=rtk_rg_macFilter_del(mac_idx);
			if(ret)
				printf("rtk_rg_macFilter_del failed! idx = %d\n", mac_idx);
		}

		fclose(fp);
		unlink(RG_PARENTAL_CTRL_MAC_FILE);
	}

	// Flush ip based parental ctrl rule if exist
	if((fp = fopen(RG_PARENTAL_CTRL_IP_FILE, "r"))) {
		while(fscanf(fp, "%d\n", &aclIdx) != EOF)
		{
			if(rtk_rg_aclFilterAndQos_del(aclIdx))
				DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", aclIdx);
		}

		fclose(fp);
		unlink(RG_PARENTAL_CTRL_IP_FILE);
	}

	return 0;
}

int AddRTK_RG_MAC_Parental_Ctrl_Rule(MIB_PARENT_CTRL_T *entry)
{
	int macfilterIdx;
	rtk_rg_macFilterEntry_t macFilterEntry;
	FILE *fp;
	int ret;
	
	memset(&macFilterEntry, 0, sizeof(rtk_rg_macFilterEntry_t));
	memcpy(&macFilterEntry.mac, entry->mac, MAC_ADDR_LEN);
	macFilterEntry.direct = RTK_RG_MACFILTER_FILTER_SRC_MAC_ONLY;
	
	if(!(fp = fopen(RG_PARENTAL_CTRL_MAC_FILE, "a")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -1;
	}
	
	if((ret = rtk_rg_macFilter_add(&macFilterEntry, &macfilterIdx)) == 0)
		fprintf(fp, "%d\n", macfilterIdx);
	else
		printf("Set rtk_rg_macFilter_add failed!error = 0x%x\n", ret);

	entry->rg_acl_idx = macfilterIdx;
	
	fclose(fp);
	return 0;
}

int Del_RG_MAC_Parental_Ctrl_Rule(int aclIdx)
{
	int ret;
	
	ret=rtk_rg_macFilter_del(aclIdx);
	if(ret)
		printf("rtk_rg_macFilter_del failed! idx = %d\n", aclIdx);

	return ret;
}

int AddRTK_RG_IP_Parental_Ctrl_Rule(MIB_PARENT_CTRL_T *entry)
{
	rtk_rg_aclFilterAndQos_t aclRule;
	rtk_rg_intfInfo_t infinfo;
	int aclIdx, i;
	ipaddr_t mask;
	FILE *fp;

	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	aclRule.filter_fields |= INGRESS_PORT_BIT;
#ifdef CONFIG_RTL9602C_SERIES
	aclRule.ingress_port_mask.portmask = 0x7; // All physical ports.
#else
	aclRule.ingress_port_mask.portmask = 0x3f; // All physical ports.
#endif
#ifdef WLAN_SUPPORT
	aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN0));
#ifdef WLAN_DUALBAND_CONCURRENT
	aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN1));
#endif
	aclRule.ingress_port_mask.portmask |= (1 << RTK_RG_PORT_CPU);
#endif
	aclRule.acl_weight = RG_FIREWALL_ACL_WEIGHT;

	aclRule.action_type = ACL_ACTION_TYPE_DROP;

	// Source ip, mask
	aclRule.filter_fields |= INGRESS_IPV4_SIP_RANGE_BIT;

	aclRule.ingress_src_ipv4_addr_start = ntohl(*((ipaddr_t *)entry->sip));
	aclRule.ingress_src_ipv4_addr_end = ntohl(*((ipaddr_t *)entry->eip));

	if(!(fp = fopen(RG_PARENTAL_CTRL_IP_FILE, "a")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -2;
	}

	if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0)
		fprintf(fp, "%d\n", aclIdx);
	else
		printf("<%s:%d> rtk_rg_aclFilterAndQos_add failed!\n", __func__, __LINE__);

	entry->rg_acl_idx = aclIdx;

	fclose(fp);
	return 0;
}

int Del_RG_IP_Parental_Ctrl_Rule(int aclIdx)
{
	int ret;
	
	ret = rtk_rg_aclFilterAndQos_del(aclIdx);
	if (ret)
		printf("rtk_rg_aclFilterAndQos_del failed! idx = %d\n", aclIdx);

	return ret;
}
#endif

#ifdef IP_PORT_FILTER
int AddRTK_RG_ACL_IPPort_Filter(MIB_CE_IP_PORT_FILTER_T *ipEntry)
{
	rtk_rg_aclFilterAndQos_t aclRule;
	rtk_rg_intfInfo_t infinfo;
	int aclIdx, i;
	ipaddr_t mask;
	FILE *fp;

	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	aclRule.filter_fields |= INGRESS_PORT_BIT;
	#ifdef CONFIG_RTL9602C_SERIES
	aclRule.ingress_port_mask.portmask = 0x7; // All physical ports.
	#else
	aclRule.ingress_port_mask.portmask = 0x3f; // All physical ports.
	#endif
#ifdef WLAN_SUPPORT
	aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN0));
#ifdef WLAN_DUALBAND_CONCURRENT
	aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN1));
#endif
	aclRule.ingress_port_mask.portmask |= (1 << RTK_RG_PORT_CPU);
#endif
	aclRule.acl_weight = RG_FIREWALL_ACL_WEIGHT;

	if (ipEntry->action == 0)
		aclRule.action_type = ACL_ACTION_TYPE_DROP;
	else if (ipEntry->action == 1)
		aclRule.action_type = ACL_ACTION_TYPE_PERMIT;
	else
	{
		fprintf(stderr, "Wrong IP/Port filter action!\n");
		return -1;
	}

	// Source port
	if (ipEntry->srcPortFrom != 0)
	{
		aclRule.filter_fields |= INGRESS_L4_SPORT_RANGE_BIT;
		if (ipEntry->srcPortFrom == ipEntry->srcPortTo)
		{
			aclRule.ingress_src_l4_port_start = aclRule.ingress_src_l4_port_end = ipEntry->srcPortFrom;
		}
		else
		{
			aclRule.ingress_src_l4_port_start = ipEntry->srcPortFrom;
			aclRule.ingress_src_l4_port_end = ipEntry->srcPortTo;
		}
	}

	// Destination port
	if(ipEntry->dstPortFrom != 0)
	{
		aclRule.filter_fields |= INGRESS_L4_DPORT_RANGE_BIT;
		if(ipEntry->dstPortFrom == ipEntry->dstPortTo)
		{
			aclRule.ingress_dest_l4_port_start = aclRule.ingress_dest_l4_port_end = ipEntry->dstPortFrom;
		}
		else
		{
			aclRule.ingress_dest_l4_port_start = ipEntry->dstPortFrom;
			aclRule.ingress_dest_l4_port_end = ipEntry->dstPortTo;
		}
	}

	// Source ip, mask
	if(memcmp(ipEntry->srcIp, "\x00\x00\x00\x00", IP_ADDR_LEN) != 0)
	{
		aclRule.filter_fields |= INGRESS_IPV4_SIP_RANGE_BIT;

		if(ipEntry->smaskbit == 0)
			aclRule.ingress_src_ipv4_addr_start = aclRule.ingress_src_ipv4_addr_end = ntohl(*((ipaddr_t *)ipEntry->srcIp));
		else
		{
			mask = ~0 << (sizeof(ipaddr_t)*8 - ipEntry->smaskbit);
			mask = htonl(mask);
			aclRule.ingress_src_ipv4_addr_start = ntohl(*((in_addr_t *)ipEntry->srcIp) & mask);
			aclRule.ingress_src_ipv4_addr_end = ntohl(*((in_addr_t *)ipEntry->srcIp) | ~mask);
		}
	}

	// Destination ip, mask
	if(memcmp(ipEntry->dstIp, "\x00\x00\x00\x00", IP_ADDR_LEN) != 0)
	{
		aclRule.filter_fields |= INGRESS_IPV4_DIP_RANGE_BIT;
		aclRule.filter_fields |= INGRESS_IPV4_TAGIF_BIT;
		aclRule.ingress_ipv4_tagif = 1;

		if(ipEntry->dmaskbit == 0)
			aclRule.ingress_dest_ipv4_addr_start = aclRule.ingress_dest_ipv4_addr_end = ntohl(*((ipaddr_t *)ipEntry->dstIp));
		else
		{
			mask = ~0 << (sizeof(ipaddr_t)*8 - ipEntry->dmaskbit);
			mask = htonl(mask);
			aclRule.ingress_dest_ipv4_addr_start = ntohl(*((in_addr_t *)ipEntry->dstIp) & mask);
			aclRule.ingress_dest_ipv4_addr_end = ntohl(*((in_addr_t *)ipEntry->dstIp) | ~mask);
		}
	}

	// Protocol
	if( ipEntry->protoType != PROTO_NONE )
	{
		if( ipEntry->protoType == PROTO_TCP )
			aclRule.filter_fields |= INGRESS_L4_TCP_BIT;
		else if( ipEntry->protoType == PROTO_UDP )
			aclRule.filter_fields |= INGRESS_L4_UDP_BIT;
		else if( ipEntry->protoType == PROTO_ICMP)
			aclRule.filter_fields |= INGRESS_L4_ICMP_BIT;
		else
			return -1;
	}

	if(!(fp = fopen(RG_ACL_RULES_FILE, "a")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -2;
	}

	if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0)
		fprintf(fp, "%d\n", aclIdx);
	else
		printf("<%s:%d> rtk_rg_aclFilterAndQos_add failed!\n", __func__, __LINE__);

	fclose(fp);
	return 0;
}
#endif

int RTK_RG_ACL_IPPort_Filter_Default_Policy(int out_policy)
{
	rtk_rg_aclFilterAndQos_t aclRule;
	int aclIdx;
	FILE *fp;

	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));

	if(!(fp = fopen(RG_ACL_RULES_FILE, "a")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -2;
	}

	if( out_policy == 0 )
	{
		aclRule.action_type = ACL_ACTION_TYPE_DROP;
		aclRule.filter_fields = INGRESS_DMAC_BIT|INGRESS_PORT_BIT|INGRESS_IPV4_TAGIF_BIT;
		aclRule.ingress_ipv4_tagif = 1;
		#ifdef CONFIG_RTL9602C_SERIES
		aclRule.ingress_port_mask.portmask = 0x7; // All physical ports.
		#else
		aclRule.ingress_port_mask.portmask = 0x3f; // All physical ports.
		#endif
		aclRule.acl_weight = RG_FIREWALL_ACL_WEIGHT;

		mib_get(MIB_ELAN_MAC_ADDR, (void *)&aclRule.ingress_dmac);

		if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0)
			fprintf(fp, "%d\n", aclIdx);
		else
			printf("rtk_rg_aclFilterAndQos_add ip port filter default policy failed!\n");
	}

	fclose(fp);
	return 0;
}

int RTK_RG_ACL_IPPort_Filter_Allow_LAN_to_GW()
{
	rtk_rg_aclFilterAndQos_t aclRule;
	int aclIdx;
	FILE *fp;
	struct in_addr lan_ip;
	char ip2_enabled = 0;

	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));

	if(!(fp = fopen(RG_ACL_RULES_FILE, "a")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -1;
	}

	aclRule.action_type = ACL_ACTION_TYPE_PERMIT;
	aclRule.filter_fields = INGRESS_DMAC_BIT | INGRESS_IPV4_DIP_RANGE_BIT | INGRESS_IPV4_TAGIF_BIT| INGRESS_PORT_BIT;
	aclRule.ingress_ipv4_tagif = 1;

#ifdef CONFIG_RTL9602C_SERIES
	aclRule.ingress_port_mask.portmask = 0x7; // All physical ports.
#else
	aclRule.ingress_port_mask.portmask = 0x3f; // All physical ports.
#endif
	aclRule.acl_weight = RG_FIREWALL_ACL_WEIGHT;

	mib_get(MIB_ELAN_MAC_ADDR, (void *)&aclRule.ingress_dmac);
	mib_get(MIB_ADSL_LAN_IP, (void *)&lan_ip);
	aclRule.ingress_dest_ipv4_addr_start = aclRule.ingress_dest_ipv4_addr_end = ntohl(*((ipaddr_t *)&lan_ip.s_addr));

	if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0)
		fprintf(fp, "%d\n", aclIdx);
	else
		printf("rtk_rg_aclFilterAndQos_add allow gw ip failed!\n");

	mib_get(MIB_ADSL_LAN_ENABLE_IP2, (void *)&ip2_enabled);

	if(ip2_enabled)
	{
		mib_get(MIB_ADSL_LAN_IP2, (void *)&lan_ip);
		aclRule.ingress_dest_ipv4_addr_start = aclRule.ingress_dest_ipv4_addr_end = ntohl(*((ipaddr_t *)&lan_ip.s_addr));

		if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0)
			fprintf(fp, "%d\n", aclIdx);
		else
			printf("rtk_rg_aclFilterAndQos_add allow gw ip2 failed!\n");
	}

	aclRule.filter_fields = INGRESS_DMAC_BIT | INGRESS_ETHERTYPE_BIT | INGRESS_PORT_BIT;
	aclRule.ingress_port_mask.portmask = RG_get_all_lan_phyPortMask();
	aclRule.ingress_ethertype = 0x0806;

	if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0)
		fprintf(fp, "%d\n", aclIdx);
	else
		printf("rtk_rg_aclFilterAndQos_add allow gw arp failed!\n");

	fclose(fp);
	return 0;
}

int RG_add_WAN_Port_mapping_ACL(int wanindex, unsigned short itfGroup)
{
	int aclIdx = 0, ret = 0; 
	char filename[64] = {0};
	FILE *fp = NULL;

	rtk_rg_aclFilterAndQos_t aclRule;

	printf("[%s] wanindex %d, itfGroup 0x%x", __FUNCTION__, __LINE__, wanindex, itfGroup);
	sprintf(filename, "%s_%d", RG_ACL_WAN_PORT_MAPPING_POLICY_ROUTE, wanindex);
	if (!(fp = fopen(filename, "a"))) {
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -2;
	}
	// set up binding lan ports
	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	aclRule.action_type = ACL_ACTION_TYPE_POLICY_ROUTE;
	aclRule.filter_fields = INGRESS_PORT_BIT;
#ifdef CONFIG_RTL9602C_SERIES
	aclRule.ingress_port_mask.portmask = itfGroup & 0x3;
#else
	aclRule.ingress_port_mask.portmask = itfGroup & 0xf;
#endif
	aclRule.action_policy_route_wan = wanindex;
	aclRule.acl_weight = RG_DEFAULT_ACL_WEIGHT;
	//printf("[%s %d]src ip from %x to %x policy to wan(idx=%d)\n", __func__, __LINE__,aclRule.ingress_src_ipv4_addr_start,aclRule.ingress_src_ipv4_addr_end,rg_wan_idx);
	if ((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0) {
		fprintf(fp, "%d\n", aclIdx);
	}else {
		printf("[%s@%d] rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n", __FUNCTION__, __LINE__, ret);
		fclose(fp);
		return -1;
	}


#ifdef WLAN_SUPPORT
	if(itfGroup>>4){ // set up binding wlan ports
		memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
		aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
		aclRule.action_type = ACL_ACTION_TYPE_POLICY_ROUTE;
		aclRule.filter_fields = INGRESS_WLANDEV_BIT;
		aclRule.ingress_wlanDevMask = (((itfGroup>>ITFGROUP_WLAN0_DEV_BIT)&ITFGROUP_WLAN_MASK)<<RG_RET_MBSSID_MASTER_ROOT_INTF) | (((itfGroup>>ITFGROUP_WLAN1_DEV_BIT)&ITFGROUP_WLAN_MASK)<<RG_RET_MBSSID_SLAVE_ROOT_INTF) ;
		aclRule.action_policy_route_wan = wanindex;
		aclRule.acl_weight = RG_DEFAULT_ACL_WEIGHT;
		if ((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0) {
			fprintf(fp, "%d\n", aclIdx);
		}else {
			printf("[%s@%d] rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n", __FUNCTION__, __LINE__, ret);
			fclose(fp);
			return -1;
		}
	}
#endif

	// set up non-binding lan port can't browse wan
	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_OR_EGRESS_L34_UP_DROP;
	aclRule.action_type = ACL_ACTION_TYPE_DROP;
	aclRule.filter_fields = (INGRESS_PORT_BIT | EGRESS_INTF_BIT);
#ifdef CONFIG_RTL9602C_SERIES
	aclRule.ingress_port_mask.portmask = (itfGroup ^ 0x3) & 0x03;
#else
	aclRule.ingress_port_mask.portmask = (itfGroup ^ 0xf) & 0x0f;
#endif
	aclRule.egress_intf_idx = wanindex;
	aclRule.acl_weight = RG_DEFAULT_ACL_WEIGHT;
	if ( aclRule.ingress_port_mask.portmask != 0x0 ){
		if ((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0) {
			fprintf(fp, "%d\n", aclIdx);
		}else {
			printf("[%s@%d] rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n", __FUNCTION__, __LINE__, ret);
			fclose(fp);
			return -1;
		}
	}

#ifdef WLAN_SUPPORT
	// set up non-binding wlan port can't browse wan
	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_OR_EGRESS_L34_UP_DROP;
	aclRule.action_type = ACL_ACTION_TYPE_DROP;
	aclRule.filter_fields = (INGRESS_PORT_BIT | EGRESS_INTF_BIT | INGRESS_WLANDEV_BIT);

	aclRule.ingress_wlanDevMask = ~((((itfGroup>>ITFGROUP_WLAN0_DEV_BIT)&ITFGROUP_WLAN_MASK)<<RG_RET_MBSSID_MASTER_ROOT_INTF) | (((itfGroup>>ITFGROUP_WLAN1_DEV_BIT)&ITFGROUP_WLAN_MASK)<<RG_RET_MBSSID_SLAVE_ROOT_INTF) );
	aclRule.egress_intf_idx = wanindex;		
	aclRule.acl_weight = RG_DEFAULT_ACL_WEIGHT;

	if ( (aclRule.ingress_wlanDevMask ^ (~(((itfGroup>>ITFGROUP_WLAN0_DEV_BIT)&ITFGROUP_WLAN_MASK)<<RG_RET_MBSSID_MASTER_ROOT_INTF)) != 0x0) ||
        (aclRule.ingress_wlanDevMask ^ (~(((itfGroup>>ITFGROUP_WLAN1_DEV_BIT)&ITFGROUP_WLAN_MASK)<<RG_RET_MBSSID_SLAVE_ROOT_INTF)) != 0x0)
		) 
		aclRule.ingress_port_mask.portmask |= (1<<RTK_RG_EXT_PORT0); // assign wifi port

	if ( aclRule.ingress_wlanDevMask != 0x0 ){
		if ((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0) {
			fprintf(fp, "%d\n", aclIdx);
		}else {
			printf("[%s@%d] rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n", __FUNCTION__, __LINE__, ret);
			fclose(fp);
			return -1;
		}
	}
#endif

	fclose(fp);
	return 0;
}

int FlushRTK_RG_WAN_Port_mapping_ACL(int wanindex)
{
	FILE *fp;
	int filter_idx = 0;
	char filename[64] = {0};

	sprintf(filename, "%s_%d", RG_ACL_WAN_PORT_MAPPING_POLICY_ROUTE, wanindex);
	if(!(fp = fopen(filename, "r"))){
		return -2;
	}

	while(fscanf(fp, "%d\n", &filter_idx) != EOF)
	{
		if(rtk_rg_aclFilterAndQos_del(filter_idx))
			printf("rtk_rg_aclFilterAndQos_del failed! idx = %d\n", filter_idx);
	}
	//AUG_PRT("filter_idx=%d\n",filter_idx);
	fclose(fp);
	unlink(filename);

	return 0;
}

int FlushRTK_RG_ACL_Filters()
{
	FILE *fp;
	int aclIdx;

	if(!(fp = fopen(RG_ACL_RULES_FILE, "r")))
		return -2;

	while(fscanf(fp, "%d\n", &aclIdx) != EOF)
	{
		if(rtk_rg_aclFilterAndQos_del(aclIdx))
			DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", aclIdx);
	}

	fclose(fp);
	unlink(RG_ACL_RULES_FILE);
	return 0;
}

#ifdef SUPPORT_FON_GRE
int FlushRTK_RG_ACL_FON_GRE_RULE(void)
{
	FILE *fp;
	int aclIdx;

	if(!(fp = fopen(RG_GRE_RULES_FILE, "r")))
		return -2;

	while(fscanf(fp, "%d\n", &aclIdx) != EOF)
	{
		if(rtk_rg_aclFilterAndQos_del(aclIdx))
			DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", aclIdx);
	}

	fclose(fp);
	unlink(RG_GRE_RULES_FILE);
	return 0;
}

int AddRTK_RG_ACL_FON_GRE_RULE(void)
{
#ifdef WLAN_SUPPORT
	rtk_rg_aclFilterAndQos_t aclRule;
	int aclIdx;
	int ori_wlan_idx;
	unsigned char vChar;
	int wanPhyPort;
	FILE *fp;

	mib_get(MIB_FON_GRE_ENABLE, (void *)&vChar);
	if (!vChar)
		return 0;
	
	/****************** add upstream rule *****************/
	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));

	aclRule.filter_fields |= INGRESS_WLANDEV_BIT;
	ori_wlan_idx = wlan_idx;
	wlan_idx = 0;
	mib_get(MIB_WLAN_FREE_SSID_GRE_ENABLE, (void *)&vChar);
	if (vChar)
		aclRule.ingress_wlanDevMask |= 1<<1;//vap0 bit1
	mib_get(MIB_WLAN_CLOSED_SSID_GRE_ENABLE, (void *)&vChar);
	if (vChar)
		aclRule.ingress_wlanDevMask |= 1<<2;//vap1 bit1
	
	wlan_idx = 1;
	mib_get(MIB_WLAN_FREE_SSID_GRE_ENABLE, (void *)&vChar);
	if (vChar)
		aclRule.ingress_wlanDevMask |= 1<<15;//vap0 bit15
	mib_get(MIB_WLAN_CLOSED_SSID_GRE_ENABLE, (void *)&vChar);
	if (vChar)
		aclRule.ingress_wlanDevMask |= 1<<16;//vap1 bit16
	wlan_idx = ori_wlan_idx;

	if (0 == aclRule.ingress_wlanDevMask)
		return 0;

	aclRule.action_type = ACL_ACTION_TYPE_TRAP_TO_PS;
	
	if(!(fp = fopen(RG_GRE_RULES_FILE, "a")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -2;
	}

	if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0)
		fprintf(fp, "%d\n", aclIdx);
	else
		printf("rtk_rg_aclFilterAndQos_add gre upstream rule failed! %d\n", __LINE__);

	/****************** add downstream rule *****************/
	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	
	aclRule.filter_fields |= INGRESS_L4_POROTCAL_VALUE_BIT;
	aclRule.ingress_l4_protocal = 47;

	aclRule.filter_fields |= INGRESS_PORT_BIT;
	if(mib_get(MIB_WAN_PHY_PORT , (void *)&wanPhyPort) == 0)
	{
		printf("Get MIB_WAN_PHY_PORT failed!!!\n");
		wanPhyPort = RTK_RG_MAC_PORT_PON;
	}
	aclRule.ingress_port_mask.portmask = 1 << wanPhyPort;

	aclRule.action_type = ACL_ACTION_TYPE_TRAP_TO_PS;

	if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0)
		fprintf(fp, "%d\n", aclIdx);
	else
		printf("rtk_rg_aclFilterAndQos_add unnumbered upstream rule failed! %d\n", __LINE__);
	
	fclose(fp);
	return 0;
#endif
}
#endif//end of SUPPORT_FON_GRE

#ifdef CONFIG_IPV6
int IPv6PrefixToStartEnd(char ipv6_addr[IPV6_ADDR_LEN], int prefix, char ipv6_start[IPV6_ADDR_LEN], char ipv6_end[IPV6_ADDR_LEN])
{
	int num_byte = prefix / 8;
	int rem_bits = prefix % 8;

	memcpy(ipv6_start, ipv6_addr, IPV6_ADDR_LEN);
	memcpy(ipv6_end, ipv6_addr, IPV6_ADDR_LEN);

	if(num_byte < IPV6_ADDR_LEN)
	{
		ipv6_start[num_byte] &= ((char)0xFF) << (8-rem_bits);
		ipv6_end[num_byte] |= ~(((char)0xFF) << (8-rem_bits));

		if(num_byte+1 < IPV6_ADDR_LEN)
		{
			memset(ipv6_start+num_byte+1, 0, IPV6_ADDR_LEN-num_byte-1);
			memset(ipv6_end+num_byte+1, 0xff, IPV6_ADDR_LEN-num_byte-1);
		}
	}
}

int IPv6PrefixToIPaddressMask(char ipv6_addr[IPV6_ADDR_LEN], int prefix, char ipv6_addr_acl[IPV6_ADDR_LEN], char ipv6_mask[IPV6_ADDR_LEN])
{
	int num_byte = prefix / 8;
	int rem_bits = prefix % 8;
	int i;

	memcpy(ipv6_addr_acl, ipv6_addr, IPV6_ADDR_LEN);

	if(num_byte < IPV6_ADDR_LEN)
	{
		for(i=0 ; i<num_byte ; i++)
		{
			ipv6_mask[i] = 0xff;
		}
		ipv6_addr_acl[num_byte] &= ((char)0xFF) << (8-rem_bits);
		if(num_byte+1 < IPV6_ADDR_LEN)
		{
			memset(ipv6_addr_acl+num_byte+1, 0, IPV6_ADDR_LEN-num_byte-1);
			ipv6_mask[num_byte+1] = ((1<<rem_bits)-1)<<(8-rem_bits);
		}
	}
}

int AddRTK_RG_ACL_IPv6Port_Filter(MIB_CE_V6_IP_PORT_FILTER_T *ipv6_filter_entry, char *prefixIP)
{
	rtk_rg_aclFilterAndQos_t aclRule;
	rtk_rg_intfInfo_t infinfo;
	int aclIdx, i;
	FILE *fp;
	unsigned char empty_ipv6[IPV6_ADDR_LEN] = {0};

	//Set by PD+InterfaceID, Need Check PD not empty!
	if(memcmp(ipv6_filter_entry->sIfId6Start, empty_ipv6, IPV6_ADDR_LEN) != 0
		||memcmp(ipv6_filter_entry->dIfId6Start, empty_ipv6, IPV6_ADDR_LEN) != 0)
	{
		if(!prefixIP || memcmp(prefixIP,empty_ipv6,IPV6_ADDR_LEN) == 0)
			return -1;
	}
	
	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));

#ifndef CONFIG_IPV6_OLD_FILTER
	//Direction: Upstream, Downstream
	if(ipv6_filter_entry->dir == DIR_IN)
	{
		aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_OR_EGRESS_L34_DOWN_DROP;
		aclRule.filter_fields |= INGRESS_PORT_BIT;
		aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();
	}
	else if(ipv6_filter_entry->dir == DIR_OUT)
	{
		aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_OR_EGRESS_L34_UP_DROP;
		aclRule.filter_fields |= INGRESS_PORT_BIT;
		aclRule.ingress_port_mask.portmask = RG_get_all_lan_phyPortMask();
#ifdef WLAN_SUPPORT
		aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN0));
#ifdef WLAN_DUALBAND_CONCURRENT
		aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN1));
#endif
#endif
	}
#endif

	if (ipv6_filter_entry->action == 0)
		aclRule.action_type = ACL_ACTION_TYPE_DROP;
	else if (ipv6_filter_entry->action == 1) {
		// fwding_type_and_direction must be 0 when action_type=ACL_ACTION_TYPE_PERMIT
		aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
		aclRule.action_type = ACL_ACTION_TYPE_PERMIT;
	}
	else
	{
		fprintf(stderr, "Wrong IP/Port filter action!\n");
		return -1;
	}

	// Source port
	if (ipv6_filter_entry->srcPortFrom != 0)
	{
		aclRule.filter_fields |= INGRESS_L4_SPORT_RANGE_BIT;
		if (ipv6_filter_entry->srcPortFrom == ipv6_filter_entry->srcPortTo)
		{
			aclRule.ingress_src_l4_port_start = aclRule.ingress_src_l4_port_end = ipv6_filter_entry->srcPortFrom;
		}
		else
		{
			aclRule.ingress_src_l4_port_start = ipv6_filter_entry->srcPortFrom;
			aclRule.ingress_src_l4_port_end = ipv6_filter_entry->srcPortTo;
		}
	}

	// Destination port
	if(ipv6_filter_entry->dstPortFrom != 0)
	{
		aclRule.filter_fields |= INGRESS_L4_DPORT_RANGE_BIT;
		if(ipv6_filter_entry->dstPortFrom == ipv6_filter_entry->dstPortTo)
		{
			aclRule.ingress_dest_l4_port_start = aclRule.ingress_dest_l4_port_end = ipv6_filter_entry->dstPortFrom;
		}
		else
		{
			aclRule.ingress_dest_l4_port_start = ipv6_filter_entry->dstPortFrom;
			aclRule.ingress_dest_l4_port_end = ipv6_filter_entry->dstPortTo;
		}
	}

#ifdef CONFIG_IPV6_OLD_FILTER
	// Source ip, mask
	if(memcmp(ipv6_filter_entry->sip6Start, empty_ipv6, IPV6_ADDR_LEN) != 0)
	{
		aclRule.filter_fields |= INGRESS_IPV6_SIP_RANGE_BIT;

		if(ipv6_filter_entry->sip6End[0] == 0)
		{
			if(ipv6_filter_entry->sip6PrefixLen == 0)
			{
				memcpy(aclRule.ingress_src_ipv6_addr_start, ipv6_filter_entry->sip6Start, IPV6_ADDR_LEN);
				memcpy(aclRule.ingress_src_ipv6_addr_end, ipv6_filter_entry->sip6Start, IPV6_ADDR_LEN);
			}
			else
			{
#ifdef CONFIG_RTL9602C_SERIES
				aclRule.filter_fields &= ~INGRESS_IPV6_SIP_RANGE_BIT;
				aclRule.filter_fields |= INGRESS_IPV6_SIP_BIT;				
				IPv6PrefixToIPaddressMask(ipv6_filter_entry->sip6Start, ipv6_filter_entry->sip6PrefixLen, aclRule.ingress_src_ipv6_addr, aclRule.ingress_src_ipv6_addr_mask);
#else
				IPv6PrefixToStartEnd(ipv6_filter_entry->sip6Start, ipv6_filter_entry->sip6PrefixLen, aclRule.ingress_src_ipv6_addr_start, aclRule.ingress_src_ipv6_addr_end);
#endif
			}
		}
		else
		{
			memcpy(aclRule.ingress_src_ipv6_addr_start, ipv6_filter_entry->sip6Start, IPV6_ADDR_LEN);
			memcpy(aclRule.ingress_src_ipv6_addr_end, ipv6_filter_entry->sip6End, IPV6_ADDR_LEN);
		}
	}

	// Destination ip, mask
	if(memcmp(ipv6_filter_entry->dip6Start, empty_ipv6, IPV6_ADDR_LEN) != 0)
	{
		aclRule.filter_fields |= INGRESS_IPV6_DIP_RANGE_BIT;

		if(ipv6_filter_entry->dip6End[0] == 0)
		{
			if(ipv6_filter_entry->dip6PrefixLen == 0)
			{
				memcpy(aclRule.ingress_dest_ipv6_addr_start, ipv6_filter_entry->dip6Start, IPV6_ADDR_LEN);
				memcpy(aclRule.ingress_dest_ipv6_addr_end, ipv6_filter_entry->dip6Start, IPV6_ADDR_LEN);
			}
			else
			{
#ifdef CONFIG_RTL9602C_SERIES			
				aclRule.filter_fields &= ~INGRESS_IPV6_DIP_RANGE_BIT;
				aclRule.filter_fields |= INGRESS_IPV6_DIP_BIT;				
				IPv6PrefixToIPaddressMask(ipv6_filter_entry->dip6Start, ipv6_filter_entry->dip6PrefixLen, aclRule.ingress_dest_ipv6_addr, aclRule.ingress_dest_ipv6_addr_mask);
#else
				IPv6PrefixToStartEnd(ipv6_filter_entry->dip6Start, ipv6_filter_entry->dip6PrefixLen, aclRule.ingress_dest_ipv6_addr_start, aclRule.ingress_dest_ipv6_addr_end);
#endif
			}
		}
		else
		{
			memcpy(aclRule.ingress_dest_ipv6_addr_start, ipv6_filter_entry->dip6Start, IPV6_ADDR_LEN);
			memcpy(aclRule.ingress_dest_ipv6_addr_end, ipv6_filter_entry->dip6End, IPV6_ADDR_LEN);
		}
	}

#else
	// Source ip, mask
	if(memcmp(ipv6_filter_entry->sip6Start, empty_ipv6, IPV6_ADDR_LEN) != 0)
	{
		aclRule.filter_fields |= INGRESS_IPV6_SIP_RANGE_BIT;

		if(ipv6_filter_entry->sip6End[0] == 0)
		{
			if(ipv6_filter_entry->sip6PrefixLen == 0)
			{
				memcpy(aclRule.ingress_src_ipv6_addr_start, ipv6_filter_entry->sip6Start, IPV6_ADDR_LEN);
				memcpy(aclRule.ingress_src_ipv6_addr_end, ipv6_filter_entry->sip6Start, IPV6_ADDR_LEN);
			}
			else
			{
#ifdef CONFIG_RTL9602C_SERIES
				aclRule.filter_fields &= ~INGRESS_IPV6_SIP_RANGE_BIT;
				aclRule.filter_fields |= INGRESS_IPV6_SIP_BIT;				
				IPv6PrefixToIPaddressMask(ipv6_filter_entry->sip6Start, ipv6_filter_entry->sip6PrefixLen, aclRule.ingress_src_ipv6_addr, aclRule.ingress_src_ipv6_addr_mask);
#else
				IPv6PrefixToStartEnd(ipv6_filter_entry->sip6Start, ipv6_filter_entry->sip6PrefixLen, aclRule.ingress_src_ipv6_addr_start, aclRule.ingress_src_ipv6_addr_end);
#endif
			}
		}
		else
		{
			memcpy(aclRule.ingress_src_ipv6_addr_start, ipv6_filter_entry->sip6Start, IPV6_ADDR_LEN);
			memcpy(aclRule.ingress_src_ipv6_addr_end, ipv6_filter_entry->sip6End, IPV6_ADDR_LEN);
		}
	}

	// Destination ip, mask
	if(memcmp(ipv6_filter_entry->dip6Start, empty_ipv6, IPV6_ADDR_LEN) != 0)
	{
		aclRule.filter_fields |= INGRESS_IPV6_DIP_RANGE_BIT;

		if(ipv6_filter_entry->dip6End[0] == 0)
		{
			if(ipv6_filter_entry->dip6PrefixLen == 0)
			{
				memcpy(aclRule.ingress_dest_ipv6_addr_start, ipv6_filter_entry->dip6Start, IPV6_ADDR_LEN);
				memcpy(aclRule.ingress_dest_ipv6_addr_end, ipv6_filter_entry->dip6Start, IPV6_ADDR_LEN);
			}
			else
			{
#ifdef CONFIG_RTL9602C_SERIES
				aclRule.filter_fields &= ~INGRESS_IPV6_DIP_RANGE_BIT;
				aclRule.filter_fields |= INGRESS_IPV6_DIP_BIT;				
				IPv6PrefixToIPaddressMask(ipv6_filter_entry->dip6Start, ipv6_filter_entry->dip6PrefixLen, aclRule.ingress_dest_ipv6_addr, aclRule.ingress_dest_ipv6_addr_mask);
#else
				IPv6PrefixToStartEnd(ipv6_filter_entry->dip6Start, ipv6_filter_entry->dip6PrefixLen, aclRule.ingress_dest_ipv6_addr_start, aclRule.ingress_dest_ipv6_addr_end);
#endif
			}
		}
		else
		{
			memcpy(aclRule.ingress_dest_ipv6_addr_start, ipv6_filter_entry->dip6Start, IPV6_ADDR_LEN);
			memcpy(aclRule.ingress_dest_ipv6_addr_end, ipv6_filter_entry->dip6End, IPV6_ADDR_LEN);
		}
	}


	if(prefixIP && memcmp(prefixIP,empty_ipv6,IPV6_ADDR_LEN))
	{

		// Make Source ip from prefix+sIfId6Start
		if(memcmp(ipv6_filter_entry->sIfId6Start, empty_ipv6, IPV6_ADDR_LEN) != 0)
		{
			int index;

			aclRule.filter_fields |= INGRESS_IPV6_SIP_RANGE_BIT;

			memcpy(aclRule.ingress_src_ipv6_addr_start, (void *) prefixIP, IP6_ADDR_LEN);
			for (index=0; index<8; index++){
				aclRule.ingress_src_ipv6_addr_start[index+8] = ipv6_filter_entry->sIfId6Start[index+8];
			}

			memcpy(aclRule.ingress_src_ipv6_addr_end, aclRule.ingress_src_ipv6_addr_start, IPV6_ADDR_LEN);
		}

		// Make Destination  ip from prefix+dIfId6Start
		if(memcmp(ipv6_filter_entry->dIfId6Start, empty_ipv6, IPV6_ADDR_LEN) != 0)
		{
			int index;
			aclRule.filter_fields |= INGRESS_IPV6_DIP_RANGE_BIT;

			memcpy(aclRule.ingress_dest_ipv6_addr_start, (void *) prefixIP, IP6_ADDR_LEN);
			for (index=0; index<8; index++){
				aclRule.ingress_dest_ipv6_addr_start[index+8] = ipv6_filter_entry->dIfId6Start[index+8];
			}
			memcpy(aclRule.ingress_dest_ipv6_addr_end, aclRule.ingress_dest_ipv6_addr_start, IPV6_ADDR_LEN);
		}

	}
#endif

	// Protocol
	if( ipv6_filter_entry->protoType != PROTO_NONE )
	{
		if( ipv6_filter_entry->protoType == PROTO_TCP )
			aclRule.filter_fields |= INGRESS_L4_TCP_BIT;
		else if( ipv6_filter_entry->protoType == PROTO_UDP )
			aclRule.filter_fields |= INGRESS_L4_UDP_BIT;
		else if( ipv6_filter_entry->protoType == PROTO_ICMP)
			aclRule.filter_fields |= INGRESS_L4_ICMPV6_BIT;
		else
			return -1;
	}
	aclRule.acl_weight = RG_FIREWALL_ACL_WEIGHT;
	aclRule.filter_fields |= INGRESS_IPV6_TAGIF_BIT;
	aclRule.ingress_ipv6_tagif = 1;
	if(!(fp = fopen(RG_ACL_IPv6_RULES_FILE, "a")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -2;
	}

	if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0)
		fprintf(fp, "%d\n", aclIdx);
	else
		DBPRINT(1, "rtk_rg_aclFilterAndQos_add failed!\n");

	fclose(fp);
	return 0;
}

int RTK_RG_ACL_IPv6Port_Filter_Default_Policy(int out_policy)
{
	rtk_rg_aclFilterAndQos_t aclRule;
	int aclIdx;
	FILE *fp;
	struct sockaddr hwaddr;

	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));

	if(!(fp = fopen(RG_ACL_IPv6_RULES_FILE, "a")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -2;
	}

	if( out_policy == 0 )
	{
		aclRule.action_type = ACL_ACTION_TYPE_DROP;
		aclRule.filter_fields = INGRESS_DMAC_BIT|INGRESS_PORT_BIT|INGRESS_IPV6_TAGIF_BIT;
		aclRule.ingress_ipv6_tagif = 1;

#ifdef CONFIG_RTL9602C_SERIES
		aclRule.ingress_port_mask.portmask = 0x7; // All physical ports.
#else
		aclRule.ingress_port_mask.portmask = 0x3f; // All physical ports.
#endif
		aclRule.acl_weight = RG_FIREWALL_ACL_WEIGHT;

		//mib_get(MIB_ELAN_MAC_ADDR, (void *)&aclRule.ingress_dmac);
		getInAddr((char *)LANIF, HW_ADDR, &hwaddr);
		memcpy((void *)&aclRule.ingress_dmac, hwaddr.sa_data, 6);

		if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0)
			fprintf(fp, "%d\n", aclIdx);
		else
			printf("rtk_rg_aclFilterAndQos_add ipv6 port filter default policy failed!\n");
	}

	fclose(fp);
	return 0;
}

int FlushRTK_RG_ACL_IPv6Port_Filters()
{
	FILE *fp;
	int aclIdx;

	if(!(fp = fopen(RG_ACL_IPv6_RULES_FILE, "r")))
		return -2;

	while(fscanf(fp, "%d\n", &aclIdx) != EOF)
	{
		if(rtk_rg_aclFilterAndQos_del(aclIdx))
			DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", aclIdx);
	}

	fclose(fp);
	unlink(RG_ACL_IPv6_RULES_FILE);
	return 0;
}
#endif

int DelRTK_RG_DMZ_Napt_Connection(rtk_rg_dmzInfo_t *dmzConnection)
{
	int napt_idx, ret;
	rtk_rg_naptInfo_t naptInfo;
	
	for(napt_idx=0 ; napt_idx<1024 ; napt_idx++){
		ret = rtk_rg_naptConnection_find(&naptInfo,&napt_idx);		
		if(ret==RT_ERR_RG_OK){

			if(naptInfo.naptTuples.local_ip != dmzConnection->private_ip)
				continue;
	
			if((ret = rtk_rg_naptConnection_del(napt_idx)) != RT_ERR_RG_OK)
			{
				DBPRINT(1, "rtk_rg_naptConnection_del failed! idx=%d ret=%d\n", napt_idx, ret);
				return -1;
			}
			
			return 0;
		}
	}

	return 0;
}

int RTK_RG_DMZ_Set(int enabled, in_addr_t ip_addr)
{
	int i;
	rtk_rg_intfInfo_t infinfo;
	rtk_rg_dmzInfo_t dmz_info;
#ifdef CONFIG_00R0
	int rg_wan_idx=0;
	int totalEntry = mib_chain_total(MIB_ATM_VC_TBL);
	MIB_CE_ATM_VC_T entry;
	
	for (i = 0; i < totalEntry; i++)
	{
		if (mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&entry) == 0)
			continue;

		//Check this interface has INTERNET service type
		if(entry.applicationtype & X_CT_SRV_INTERNET){
			memset(&infinfo, 0, sizeof(rtk_rg_intfInfo_t));
			if (rtk_rg_intfInfo_find(&infinfo, &entry.rg_wan_idx) != SUCCESS) {
				printf("%s-%d Can't find the wan interface idx:%d!", __func__, __LINE__, entry.rg_wan_idx);
				break;
			}

			if(infinfo.is_wan && infinfo.wan_intf.wan_intf_conf.wan_type != RTK_RG_BRIDGE)
			{
				/* dmz setting */
				rg_wan_idx = entry.rg_wan_idx;
				memset(&dmz_info, 0, sizeof(rtk_rg_dmzInfo_t));
				dmz_info.enabled = enabled;
				dmz_info.mac_mapping_enabled = 0; //use ip
				dmz_info.private_ip = ntohl(ip_addr);
				rtk_rg_dmzHost_set(rg_wan_idx, &dmz_info);
				if(!enabled)
				{
					// We need to delete associative NAPT connection info from RG further
					DelRTK_RG_DMZ_Napt_Connection(&dmz_info);
				}
			}
		}
	}
#else
	for( i = 0; i < MAX_NETIF_SW_TABLE_SIZE; i++ )
	{
		memset(&infinfo, 0, sizeof(rtk_rg_intfInfo_t));
		if(rtk_rg_intfInfo_find(&infinfo, &i))
			break;

		if(infinfo.is_wan && infinfo.wan_intf.wan_intf_conf.wan_type != RTK_RG_BRIDGE)
		{
			/* dmz setting */
			memset(&dmz_info, 0, sizeof(rtk_rg_dmzInfo_t));
			dmz_info.enabled = enabled;
			dmz_info.mac_mapping_enabled = 0; //use ip
			dmz_info.private_ip = ntohl(ip_addr);
			rtk_rg_dmzHost_set(i, &dmz_info);
			if(!enabled)
			{
				// We need to delete associative NAPT connection info from RG further
				DelRTK_RG_DMZ_Napt_Connection(&dmz_info);
			}
		}
	}
#endif
}

#ifdef PORT_FORWARD_GENERAL
int RTK_RG_Vertual_Server_Set(MIB_CE_PORT_FW_T *pf)
{
	rtk_rg_virtualServer_t vs;
	rtk_rg_intfInfo_t inf_info;
	int vs_idx, i, ret;
	FILE *fp;

	memset(&vs, 0, sizeof(rtk_rg_virtualServer_t));

	vs.local_ip = ntohl(*((ipaddr_t *)pf->ipAddr));
	vs.valid = pf->enable;

	if(pf->fromPort)
	{
		vs.local_port_start = pf->fromPort;
		vs.gateway_port_start = pf->fromPort;
		vs.mappingPortRangeCnt = pf->toPort - pf->fromPort + 1;
	}

	if(pf->externalfromport)
	{
		if(!pf->fromPort)
			vs.local_port_start = pf->externalfromport;

		vs.gateway_port_start = pf->externalfromport;

		if(pf->externaltoport)
			vs.mappingPortRangeCnt = pf->externaltoport - pf->externalfromport + 1;
		else if(pf->fromPort && pf->toPort)
			vs.mappingPortRangeCnt = pf->toPort - pf->fromPort + 1;
		else
			vs.mappingPortRangeCnt = 1;
	}

	// Mapping all, if all fileds of ports are empty.
	if(!pf->fromPort && !pf->externalfromport)
	{
		vs.local_port_start = vs.gateway_port_start = 1;
		vs.mappingPortRangeCnt = 0xffff;
	}

	if(pf->remotehost[0])
	{
	}

	if(!(fp = fopen(RG_VERTUAL_SERVER_FILE, "a")))
		return -2;

	if(pf->ifIndex == DUMMY_IFINDEX) // Work on any interface.
	{
		for( i = 0; i < MAX_NETIF_SW_TABLE_SIZE; i++ )
		{
			memset(&inf_info, 0, sizeof(rtk_rg_intfInfo_t));
			if(rtk_rg_intfInfo_find(&inf_info, &i))
				break;

			if(inf_info.is_wan)
			{
				vs.wan_intf_idx = i;

				if(pf->protoType == PROTO_TCP || pf->protoType == PROTO_UDPTCP)
				{
					vs.is_tcp = 1;
#ifdef CONFIG_00R0
					switch(pf->fromPort)
					{
						case RTK_RG_ALG_FTP_TCP_PORT:
							vs.hookAlgType |= RTK_RG_ALG_FTP_TCP_SRV_IN_LAN_BIT;
							vs.disable_wan_check = 1;
							break;
						case RTK_RG_ALG_SIP_TCP_PORT:
							vs.hookAlgType |= RTK_RG_ALG_SIP_TCP_SRV_IN_LAN_BIT;
							vs.disable_wan_check = 1;
							break;
						case RTK_RG_ALG_H323_TCP_PORT:
							vs.hookAlgType |= RTK_RG_ALG_H323_TCP_SRV_IN_LAN_BIT;
							vs.disable_wan_check = 1;
							break;
						case RTK_RG_ALG_RTSP_TCP_PORT:
							vs.hookAlgType |= RTK_RG_ALG_RTSP_TCP_SRV_IN_LAN_BIT;
							vs.disable_wan_check = 1;
							break;
						default:
							printf("RG not support yet!\n");
							break;
					}
#endif
					ret = rtk_rg_virtualServer_add(&vs, &vs_idx);

					DBPRINT(0, "Add vertual server. RG WAN Index=%d, protocol=%s\n", vs.wan_intf_idx, vs.is_tcp? "TCP": "UDP");
					if(ret == 0)
						fprintf(fp, "%d\n", vs_idx);
					else
					{
						DBPRINT(1, "Error %d: rtk_rg_virtualServer_add failed! protoType=TCP\n", ret);
						continue;
					}
				}

				if(pf->protoType == PROTO_UDP || pf->protoType == PROTO_UDPTCP)
				{
					vs.is_tcp = 0;
					ret = rtk_rg_virtualServer_add(&vs, &vs_idx);

					DBPRINT(0, "Add vertual server. RG WAN Index=%d, protocol=%s\n", vs.wan_intf_idx, vs.is_tcp? "TCP": "UDP");

					if(ret == 0)
						fprintf(fp, "%d\n", vs_idx);
					else
					{
						DBPRINT(1, "Error %d: rtk_rg_virtualServer_add failed! protoType=UDP\n", ret);
						continue;
					}
				}
			}
		}
	}
	else
	{
		int totalEntry = mib_chain_total(MIB_ATM_VC_TBL);
		MIB_CE_ATM_VC_T entry;

		for (i = 0; i < totalEntry; i++)
		{
			if (mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&entry) == 0)
				continue;

			if( pf->ifIndex == entry.ifIndex )
			{
				vs.wan_intf_idx = entry.rg_wan_idx;

				if(pf->protoType == PROTO_TCP || pf->protoType == PROTO_UDPTCP)
				{
					vs.is_tcp = 1;
					ret = rtk_rg_virtualServer_add(&vs, &vs_idx);

					DBPRINT(2, "Add vertual server. Interface index=%X, RG WAN Index=%d, protocol=%s\n", entry.ifIndex, entry.rg_wan_idx, vs.is_tcp? "TCP": "UDP");
					if(ret == 0)
						fprintf(fp, "%d\n", vs_idx);
					else
					{
						DBPRINT(1, "Error %d: rtk_rg_virtualServer_add failed! protoType=TCP\n", ret);
						continue;
					}
				}

				if(pf->protoType == PROTO_UDP || pf->protoType == PROTO_UDPTCP)
				{
					vs.is_tcp = 0;
					ret = rtk_rg_virtualServer_add(&vs, &vs_idx);

					DBPRINT(2, "Add vertual server. Interface index=%X, RG WAN Index=%d, protocol=%s\n", entry.ifIndex, entry.rg_wan_idx, vs.is_tcp? "TCP": "UDP");
					if(ret == 0)
						fprintf(fp, "%d\n", vs_idx);
					else
					{
						DBPRINT(1, "Error %d: rtk_rg_virtualServer_add failed! protoType=UDP\n", ret);
						continue;
					}
				}
				break;
			}
		}
	}

	fclose(fp);
	return 0;
}

int FlushRTK_RG_Vertual_Server()
{
	FILE *fp = NULL;
	int vsIdx;

	if(!(fp = fopen(RG_VERTUAL_SERVER_FILE, "r")))
		return -1;

	while(fscanf(fp, "%d\n", &vsIdx) != EOF)
	{
		if(rtk_rg_virtualServer_del(vsIdx))
			printf("rtk_rg_virtualServer_del failed! idx = %d\n", vsIdx);
		else
			printf("Deleted Vertual Server %d.\n", vsIdx);
	}

	unlink(RG_VERTUAL_SERVER_FILE);
	fclose(fp);
	return 0;
}
#endif

#ifdef CONFIG_USER_IP_QOS_3

int RTK_RG_QoS_TotalBandwidth_Set(int TotalBandwidthKbps)
{
	int wanPhyPort=0;

	// Note: if TotalBandwidthKbps =0, means unlimit
#if 0
	if(!mib_get(MIB_WAN_PHY_PORT , (void *)&wanPhyPort)){
		printf("get MIB_WAN_PHY_PORT failed!!!\n");
		return -1;
	}
#endif
	if((wanPhyPort = RG_get_wan_phyPortId()) == -1){
		printf("get wan phy port id failed!!!\n");
		return -1;
	}

	if(rtk_rg_portEgrBandwidthCtrlRate_set(wanPhyPort,TotalBandwidthKbps)){
		printf("set EgrBandwidthCtrlRate on port %d failed!!!\n",wanPhyPort);
		return -1;
	}

	return 0;
}


#ifdef QOS_TRAFFIC_SHAPING_BY_SSID
void reset_ssid_traffic_shwping_rule()
{
	char cmdBuf[100]={0};
	int i,vwlan_idx, mapped_vwlan_idx;

	printf("reset_ssid_traffic_shwping_rule");
	for(i = 0; i<NUM_WLAN_INTERFACE; i++) {

#ifdef WLAN_MBSSID
		for (vwlan_idx=0; vwlan_idx<=NUM_VWLAN_INTERFACE; vwlan_idx++) {
			if(i==1){
#ifdef CONFIG_RTL_CLIENT_MODE_SUPPORT
				mapped_vwlan_idx = vwlan_idx+14;
#else
				mapped_vwlan_idx = vwlan_idx+13;
#endif
			}else
				mapped_vwlan_idx = vwlan_idx;

			sprintf(cmdBuf,"echo %d 0 > %s",mapped_vwlan_idx, RG_WIFI_INGRESS_RATE_LIMIT_FILE);
			printf("%s\n",cmdBuf);
			system(cmdBuf);
		}
#endif
	}
}

int set_ssid_traffic_shaping_rule(MIB_CE_IP_TC_Tp qos_entry)
{
	MIB_CE_MBSSIB_T Entry;
	int i,vwlan_idx;
	int found=0;
	int ori_wlan_idx;
	int found_wlan_idx=-1;

	ori_wlan_idx = wlan_idx;
	for(i = 0; i<NUM_WLAN_INTERFACE; i++) {

		wlan_idx = i;
		if (!getInFlags((char *)getWlanIfName(), 0)) {
			printf("Wireless Interface Not Found !\n");
			continue;
	    }

#ifdef WLAN_MBSSID
		for (vwlan_idx=0; vwlan_idx<=NUM_VWLAN_INTERFACE; vwlan_idx++) {
			wlan_getEntry(&Entry, vwlan_idx);
			if(Entry.wlanDisabled)
				continue;

			if(strcmp(Entry.ssid,qos_entry->ssid)==0){
				found=1;
				found_wlan_idx = wlan_idx;
				goto found;
			}
		}
#endif
	}

found:
	wlan_idx = ori_wlan_idx;
	if(found){
		char cmdBuf[100]={0};
		//echo Wlan_idx Rate > /proc/rg/wifi_ingress_rate_limit
		if(found_wlan_idx==0){  //wlan0
			sprintf(cmdBuf,"echo %d %d > /proc/rg/wifi_ingress_rate_limit",vwlan_idx,qos_entry->limitSpeed);
			printf("cmdBuf=%s\n",cmdBuf);
			system(cmdBuf);
			return 0;

		}else if(found_wlan_idx==1){ //wlan1
#ifdef CONFIG_RTL_CLIENT_MODE_SUPPORT
			vwlan_idx+=14;
#else
			vwlan_idx+=13;
#endif
			sprintf(cmdBuf,"echo %d %d > /proc/rg/wifi_ingress_rate_limit",vwlan_idx,qos_entry->limitSpeed);
			printf("cmdBuf=%s\n",cmdBuf);
			system(cmdBuf);
			return 0;

		}

	}
	else
		printf("Error! Not found this ssid in active SSID list\n");

	return -1;

}
#endif

#ifdef CONFIG_00R0
int RTK_RG_QoS_Car_Rule_Set(MIB_CE_IP_TC_Tp qos_entry)
{
	rtk_rg_naptFilterAndQos_t napt_filter;
	MIB_CE_ATM_VC_T vc_entry;
	int napt_filterIdx, ret, i, total_vc;
	FILE *fp;
	ipaddr_t mask;
	unsigned char empty_ipv6[IPV6_ADDR_LEN] = {0};

#ifdef QOS_TRAFFIC_SHAPING_BY_SSID
	if(qos_entry->ssid[0]){
		return set_ssid_traffic_shaping_rule(qos_entry);
	}
#endif

	memset(&napt_filter, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	napt_filter.direction=RTK_RG_NAPT_FILTER_OUTBOUND;
	napt_filter.action_fields = NAPT_SW_RATE_LIMIT_BIT;

	// Filter rule of Protocol: UDP, TCP, ICMP
	if(qos_entry->protoType != PROTO_NONE)
	{
		napt_filter.filter_fields |= L4_PROTOCAL;
		if(qos_entry->protoType == PROTO_TCP)
			napt_filter.ingress_l4_protocal = 0x6; 
		else if(qos_entry->protoType == PROTO_UDP)
			napt_filter.ingress_l4_protocal = 0x11; 
		else if(qos_entry->protoType == PROTO_ICMP)
			napt_filter.ingress_l4_protocal = 0x1; 
		else
		{
			DBPRINT(1, "Add acl rule failed! No support of this protocol type!\n");
			return -1;
		}
	}

	if(qos_entry->sport != 0)
	{
		napt_filter.filter_fields |= INGRESS_SPORT;
		napt_filter.ingress_src_l4_port = qos_entry->sport;
	}

	if(qos_entry->dport != 0)
	{
		napt_filter.filter_fields |= INGRESS_DPORT;
		napt_filter.ingress_dest_l4_port = qos_entry->dport;
	}

	if(qos_entry->IpProtocol == IPVER_IPV4) // IPv4
	{
		// Source ip, mask
		if(memcmp(qos_entry->srcip, "\x00\x00\x00\x00", IP_ADDR_LEN) != 0)
		{
			napt_filter.filter_fields |= INGRESS_SIP_RANGE;

			if(qos_entry->smaskbits == 0)
				napt_filter.ingress_src_ipv4_addr_range_start = napt_filter.ingress_src_ipv4_addr_range_end = ntohl(*((ipaddr_t *)qos_entry->srcip));
			else
			{
				mask = ~0 << (sizeof(ipaddr_t)*8 - qos_entry->smaskbits);
				mask = htonl(mask);
				napt_filter.ingress_src_ipv4_addr_range_start = ntohl(*((in_addr_t *)qos_entry->srcip) & mask);
				napt_filter.ingress_src_ipv4_addr_range_end = ntohl(*((in_addr_t *)qos_entry->srcip) | ~mask);
			}
			printf("napt_filter.ingress_src_ipv4_addr_range_start=%x\n",napt_filter.ingress_src_ipv4_addr_range_start);
			printf("napt_filter.ingress_src_ipv4_addr_range_end=%x\n",napt_filter.ingress_src_ipv4_addr_range_end);
		}

		// Destination ip, mask
		if(memcmp(qos_entry->dstip, "\x00\x00\x00\x00", IP_ADDR_LEN) != 0)
		{
			napt_filter.filter_fields |= INGRESS_DIP_RANGE;

			if(qos_entry->dmaskbits == 0)
				napt_filter.ingress_dest_ipv4_addr_range_start = napt_filter.ingress_dest_ipv4_addr_range_end = ntohl(*((ipaddr_t *)qos_entry->dstip));
			else
			{
				mask = ~0 << (sizeof(ipaddr_t)*8 - qos_entry->dmaskbits);
				mask = htonl(mask);
				napt_filter.ingress_dest_ipv4_addr_range_start = ntohl(*((in_addr_t *)qos_entry->dstip) & mask);
				napt_filter.ingress_dest_ipv4_addr_range_end = ntohl(*((in_addr_t *)qos_entry->dstip) | ~mask);
			}
		}
	}
	printf("napt_filter.filter_fields=%x\n",napt_filter.filter_fields);

	if(!(fp = fopen(RG_QOS_TS_RULES_FILE, "a")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -2;
	}

	napt_filter.assign_rate = qos_entry->limitSpeed;

	if((ret = rtk_rg_naptFilterAndQos_add(&napt_filterIdx, &napt_filter)) == 0)
		fprintf(fp, "%d\n", napt_filterIdx);
	else
		printf("rtk_rg_naptFilterAndQos_add QoSi TS rule failed! (ret = %d)\n", ret);

	fclose(fp);
	return 0;
}
#else
int RTK_RG_QoS_Car_Rule_Set(MIB_CE_IP_TC_Tp qos_entry)
{
	rtk_rg_aclFilterAndQos_t aclRule;
	MIB_CE_ATM_VC_T vc_entry;
	int aclIdx, ret, i, total_vc;
	FILE *fp=NULL;
	ipaddr_t mask;
	unsigned char empty_ipv6[IPV6_ADDR_LEN] = {0};

#ifdef QOS_TRAFFIC_SHAPING_BY_SSID
	if(qos_entry->ssid[0]){
		return set_ssid_traffic_shaping_rule(qos_entry);
	}
#endif

	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	aclRule.action_type = ACL_ACTION_TYPE_QOS;
	aclRule.acl_weight = RG_QOS_ACL_WEIGHT;

	//By default is filter packets from ALL LAN port.
	aclRule.filter_fields |= INGRESS_PORT_BIT;

	if(qos_entry->direction == QOS_DIRECTION_UPSTREAM)
		aclRule.ingress_port_mask.portmask = RG_get_all_lan_phyPortMask();
	else if(qos_entry->direction == QOS_DIRECTION_DOWNSTREAM)
		aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();

	// Filter rule of Protocol: UDP, TCP, ICMP, UDP and TCP
	if(qos_entry->protoType != PROTO_NONE)
	{
		if(qos_entry->protoType == PROTO_TCP)
			aclRule.filter_fields |= INGRESS_L4_TCP_BIT;
		else if(qos_entry->protoType == PROTO_UDP)
			aclRule.filter_fields |= INGRESS_L4_UDP_BIT;
		else if(qos_entry->protoType == PROTO_ICMP)
			aclRule.filter_fields |= INGRESS_L4_ICMP_BIT;
		else if(qos_entry->protoType == PROTO_UDPTCP)
			aclRule.filter_fields |= INGRESS_L4_TCP_BIT | INGRESS_L4_UDP_BIT;
		else
		{
			DBPRINT(1, "Add acl rule failed! No support of this protocol type!\n");
			return -1;
		}
	}

	if(qos_entry->vlanID != 0)
	{
		aclRule.filter_fields |= INGRESS_CTAG_VID_BIT;
		aclRule.ingress_ctag_vid = qos_entry->vlanID;
	}

	if(qos_entry->sport != 0)
	{
		aclRule.filter_fields |= INGRESS_L4_SPORT_RANGE_BIT;
		aclRule.ingress_src_l4_port_start = aclRule.ingress_src_l4_port_end = qos_entry->sport;
	}

	if(qos_entry->dport != 0)
	{
		aclRule.filter_fields |= INGRESS_L4_DPORT_RANGE_BIT;
		aclRule.ingress_dest_l4_port_start = aclRule.ingress_dest_l4_port_end = qos_entry->dport;
	}

#ifdef CONFIG_IPV6
	if(qos_entry->IpProtocol == IPVER_IPV6)  // IPv6
	{
		aclRule.filter_fields |= INGRESS_IPV4_TAGIF_BIT;
		//aclRule.ingress_ipv4_tagif = 1;
		// Source ip, prefix
		if(memcmp(qos_entry->sip6, empty_ipv6, IPV6_ADDR_LEN) != 0)
		{
			aclRule.filter_fields |= INGRESS_IPV6_SIP_RANGE_BIT;

			IPv6PrefixToStartEnd(qos_entry->sip6, qos_entry->sip6PrefixLen, aclRule.ingress_src_ipv6_addr_start, aclRule.ingress_src_ipv6_addr_end);
		}

		// Destination ip, prefix
		if(memcmp(qos_entry->dip6, empty_ipv6, IPV6_ADDR_LEN) != 0)
		{
			aclRule.filter_fields |= INGRESS_IPV6_DIP_RANGE_BIT;

			IPv6PrefixToStartEnd(qos_entry->dip6, qos_entry->dip6PrefixLen, aclRule.ingress_dest_ipv6_addr_start, aclRule.ingress_dest_ipv6_addr_end);
		}
	}
	else if(qos_entry->IpProtocol == IPVER_IPV4) // IPv4
	{
#endif
		aclRule.filter_fields |= INGRESS_IPV6_TAGIF_BIT;
		// Source ip, mask
		if(memcmp(qos_entry->srcip, "\x00\x00\x00\x00", IP_ADDR_LEN) != 0)
		{
			aclRule.filter_fields |= INGRESS_IPV4_SIP_RANGE_BIT;

			if(qos_entry->smaskbits == 0)
				aclRule.ingress_src_ipv4_addr_start = aclRule.ingress_src_ipv4_addr_end = ntohl(*((ipaddr_t *)qos_entry->srcip));
			else
			{
				mask = ~0 << (sizeof(ipaddr_t)*8 - qos_entry->smaskbits);
				mask = htonl(mask);
				aclRule.ingress_src_ipv4_addr_start = ntohl(*((in_addr_t *)qos_entry->srcip) & mask);
				aclRule.ingress_src_ipv4_addr_end = ntohl(*((in_addr_t *)qos_entry->srcip) | ~mask);
			}
		}

		// Destination ip, mask
		if(memcmp(qos_entry->dstip, "\x00\x00\x00\x00", IP_ADDR_LEN) != 0)
		{
			aclRule.filter_fields |= INGRESS_IPV4_DIP_RANGE_BIT;
			aclRule.filter_fields |= INGRESS_IPV4_TAGIF_BIT;
			aclRule.ingress_ipv4_tagif = 1;

			if(qos_entry->dmaskbits == 0)
				aclRule.ingress_dest_ipv4_addr_start = aclRule.ingress_dest_ipv4_addr_end = ntohl(*((ipaddr_t *)qos_entry->dstip));
			else
			{
				mask = ~0 << (sizeof(ipaddr_t)*8 - qos_entry->dmaskbits);
				mask = htonl(mask);
				aclRule.ingress_dest_ipv4_addr_start = ntohl(*((in_addr_t *)qos_entry->dstip) & mask);
				aclRule.ingress_dest_ipv4_addr_end = ntohl(*((in_addr_t *)qos_entry->dstip) | ~mask);
			}
		}
#ifdef CONFIG_IPV6
	}
#endif

/* ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET support ingress pattern only
 *
	// Filter rule of WAN interface
	if(qos_entry->ifIndex != DUMMY_IFINDEX)
	{
		total_vc = mib_chain_total(MIB_ATM_VC_TBL);

		for( i = 0; i < total_vc; i++ )
		{
			if(!mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&vc_entry))
				continue;

			if(vc_entry.ifIndex == qos_entry->ifIndex)
			{
				aclRule.filter_fields |= EGRESS_INTF_BIT;
				aclRule.egress_intf_idx = vc_entry.rg_wan_idx;  // Set egress interface.
			}
		}
	}
*/
	rtk_rg_shareMeter_set (qos_entry->entryid,qos_entry->limitSpeed,ENABLED);
	aclRule.qos_actions=ACL_ACTION_SHARE_METER_BIT;
	aclRule.action_share_meter=qos_entry->entryid;


	if(!(fp = fopen(RG_QOS_RULES_FILE, "a")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -2;
	}

	if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0)
		fprintf(fp, "%d\n", aclIdx);
	else
		printf("rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n", ret);

	fclose(fp);
	return 0;
}
#endif

#ifdef CONFIG_TR142_MODULE
#define TR142_DEV_FILE "/dev/rtk_tr142"
void set_wan_ponmac_qos_queue_num(void)
{
	int fd;
	unsigned char queue_num=4;
	
	fd = open(TR142_DEV_FILE, O_WRONLY);
	if(fd < 0)
	{
		DBPRINT(1, "ERROR: failed to open %s\n", TR142_DEV_FILE);
		return;
	}
#ifdef CONFIG_RTK_OMCI_V1
	mib_get(MIB_OMCI_WAN_QOS_QUEUE_NUM,&queue_num);
#endif
	if(ioctl(fd, RTK_TR142_IOCTL_SET_WAN_QUEUE_NUM, &queue_num) != 0)
	{
		DBPRINT(1, "ERROR: set PON QoS queues failed\n");
	}
	close(fd);
}

static void setup_pon_queues(unsigned char policy)
{
	MIB_CE_IP_QOS_QUEUE_T qEntry;
	int qEntryNum, i, fd;
	rtk_tr142_qos_queues_t queues = {0};
	unsigned char queue_num=4;
#ifdef CONFIG_RTK_OMCI_V1
	mib_get(MIB_OMCI_WAN_QOS_QUEUE_NUM,&queue_num);
#endif

	fd = open(TR142_DEV_FILE, O_WRONLY);
	if(fd < 0)
	{
		DBPRINT(1, "ERROR: failed to open %s\n", TR142_DEV_FILE);
		return;
	}

	if((qEntryNum = mib_chain_total(MIB_IP_QOS_QUEUE_TBL)) <=0)
	{
		DBPRINT(1, "ERROR: set PON QoS queues failed\n");
		close(fd);
		return;
	}

	for(i = 0; i < qEntryNum; i++)
	{
		if(!mib_chain_get(MIB_IP_QOS_QUEUE_TBL, i, (void*)&qEntry))
			continue;

		if(i >= queue_num)
			break;
#ifdef CONFIG_00R0 //queue 0 used for pppoe control packets 
		queues.queue[i+1].enable = qEntry.enable;
		queues.queue[i+1].type = (policy== 0) ? STRICT_PRIORITY : WFQ_WRR_PRIORITY;
		queues.queue[i+1].weight = (policy== 1) ? qEntry.weight : 0;
		//queues.queue[i+1].shaping_rate = qEntry.shaping_rate;
#else
		queues.queue[i].enable = qEntry.enable;
		queues.queue[i].type = (policy== 0) ? STRICT_PRIORITY : WFQ_WRR_PRIORITY;
		queues.queue[i].weight = (policy== 1) ? qEntry.weight : 0;
#endif
	}
	if(ioctl(fd, RTK_TR142_IOCTL_SET_QOS_QUEUES, &queues) != 0)
	{
		DBPRINT(1, "ERROR: set PON QoS queues failed\n");
	}
	close(fd);
}

static void clear_pon_queues(void)
{
	MIB_CE_IP_QOS_QUEUE_T qEntry;
	int qEntryNum, i, fd;
	rtk_tr142_qos_queues_t queues = {0};

	fd = open(TR142_DEV_FILE, O_WRONLY);
	if(fd < 0)
	{
		DBPRINT(1, "ERROR: failed to open %s\n", TR142_DEV_FILE);
		return;
	}

	if(ioctl(fd, RTK_TR142_IOCTL_SET_QOS_QUEUES, &queues) != 0)
	{
		DBPRINT(1, "ERROR: set PON QoS queues failed\n");
	}
	close(fd);
}

int set_dot1p_value_byCF(void)
{
	int fd;
	unsigned char dot1p_byCF;

	fd = open(TR142_DEV_FILE, O_WRONLY);
	if(fd < 0)
	{
		DBPRINT(1, "ERROR: failed to open %s\n", TR142_DEV_FILE);
		return 0;
	}
	
	if (mib_get(MIB_DOT1P_VALUE_BYCF, (void *)&dot1p_byCF) != 0)
	{	
		if(ioctl(fd, RTK_TR142_IOCTL_SET_DOT1P_VALUE_BYCF, &dot1p_byCF) != 0)
		{
			DBPRINT(1, "ERROR: set Dot1p value by CF failed\n");
		}
	}
	close(fd);
	return 0;
}

#endif


int RTK_RG_QoS_Queue_Set()
{
	unsigned char policy;
	int aclIdx, i, ret, lanPhyPort;
	rtk_rg_qos_queue_weights_t q_weight;
#if defined(CONFIG_GPON_FEATURE)
	unsigned int pon_mode;
	int wanPhyPort;
#endif
#if defined(CONFIG_USER_LAN_PORT_AS_ETH_WAN)
	int ethPhyPortId = -1;
	mib_get(MIB_ETH_WAN_PORT_PHY_INDEX, &ethPhyPortId);
#endif


	memset(&q_weight, 0, sizeof(q_weight));

	if(!mib_get(MIB_QOS_POLICY, (void *)&policy))
	{
		DBPRINT(1, "MIB get MIB_QOS_POLICY failed!\n");
		return -2;
	}

	if(policy == 0) // PRIO
	{
		q_weight.weights[6] = 0; // Queue4~7: Strict Priority
		q_weight.weights[5] = 0;
		q_weight.weights[4] = 0;
#if defined(CONFIG_EPON_FEATURE)
		q_weight.weights[3] = 0;
#else
		q_weight.weights[7] = 0;
#endif
	}
	else if(policy ==1) // WRR
	{
		MIB_CE_IP_QOS_QUEUE_T qEntry;
		int qEntryNum, i;

		if((qEntryNum = mib_chain_total(MIB_IP_QOS_QUEUE_TBL)) <=0)
			return -1;

		for(i = 0; i < qEntryNum; i++)
		{
			if(!mib_chain_get(MIB_IP_QOS_QUEUE_TBL, i, (void*)&qEntry))
				continue;
#if defined(CONFIG_EPON_FEATURE)
			if( i <= 4 )
				q_weight.weights[6-i] = qEntry.weight;
#else
			if( i <= 7 )
				q_weight.weights[7-i] = qEntry.weight;
#endif
		}
	}
	else
	{
		DBPRINT(1, "policy=%d: Unexpected policy value! (0=PRIO, 1=WRR)\n", policy);
		return -1;
	}

#if defined(CONFIG_RTK_L34_ENABLE) && defined(CONFIG_GPON_FEATURE)
	if (mib_get(MIB_PON_MODE, (void *)&pon_mode) == 0)
		printf("get MIB_PON_MODE failed!!!\n");

	if((wanPhyPort = RG_get_wan_phyPortId()) == -1)
		printf("get wan phy port id failed!!!\n");
#endif

	for( i = 0; i < 7; i++ )
	{
#if defined(CONFIG_GPON_FEATURE)
		//In GPON, queue in PON port should be set by OMCI, so ignore it.
		if ((pon_mode==GPON_MODE) && (i==wanPhyPort))
		{
#ifdef CONFIG_TR142_MODULE
			setup_pon_queues(policy);
#endif
			continue;
		}
#endif

        lanPhyPort= RG_get_lan_phyPortId(i);
        if (lanPhyPort < 0 ) continue; //Iulian , port mapping fail in 9602 series
#if defined(CONFIG_USER_LAN_PORT_AS_ETH_WAN)
		if (lanPhyPort == ethPhyPortId)
			continue;
#endif
        if((ret = rtk_rg_qosStrictPriorityOrWeightFairQueue_set(lanPhyPort, q_weight)) != 0)
			DBPRINT(1, "rtk_qos_schedulingQueue_set failed! (ret=%d, i=%d)\n", ret, i);
	}

	return 0;
}

int RTK_RG_QoS_Queue_Remove()
{
#if defined(CONFIG_RTK_L34_ENABLE) && defined(CONFIG_GPON_FEATURE)
	int wanPhyPort;
#endif
#if defined(CONFIG_EPON_FEATURE)
	int  i, ret, lanPhyPort;
	rtk_rg_qos_queue_weights_t q_weight;
#endif
	unsigned int pon_mode;
#if defined(CONFIG_USER_LAN_PORT_AS_ETH_WAN)
	int ethPhyPortId = -1;
	mib_get(MIB_ETH_WAN_PORT_PHY_INDEX, &ethPhyPortId);
#endif

#ifdef CONFIG_TR142_MODULE
	if (mib_get(MIB_PON_MODE, (void *)&pon_mode) == 0)
		printf("get MIB_PON_MODE failed!!!\n");

	if (pon_mode==GPON_MODE)
		clear_pon_queues();
#endif
#if defined(CONFIG_RTK_L34_ENABLE) && defined(CONFIG_GPON_FEATURE)
        if((wanPhyPort = RG_get_wan_phyPortId()) == -1)
                printf("get wan phy port id failed!!!\n");
#endif
#if defined(CONFIG_EPON_FEATURE)
	memset(&q_weight, 0, sizeof(q_weight));

	for( i = 0; i < 6; i++ )
	{
#if defined(CONFIG_GPON_FEATURE)
                //In GPON, queue in PON port should be set by OMCI, so ignore it.
                if ((pon_mode==GPON_MODE) && (i==wanPhyPort))
                        continue;
#endif
		/*reset to default*/
		lanPhyPort= RG_get_lan_phyPortId(i);
#if defined(CONFIG_USER_LAN_PORT_AS_ETH_WAN)
		if (lanPhyPort == ethPhyPortId)
			continue;
#endif
 	        if (lanPhyPort < 0 ) continue; //Iulian , port mapping fail in 9602 series
        	if((ret = rtk_rg_qosStrictPriorityOrWeightFairQueue_set(lanPhyPort, q_weight)) != 0)
			DBPRINT(1, "rtk_qos_schedulingQueue_set failed! (ret=%d, i=%d)\n", ret, i);
	}

#endif

	return 0;
}


int RTK_RG_QoS_Rule_Set(MIB_CE_IP_QOS_Tp qos_entry)
{
	rtk_rg_aclFilterAndQos_t aclRule;
	MIB_CE_ATM_VC_T vc_entry;
	int aclIdx, ret, i, total_vc, udp_tcp_rule=0;
	FILE *fp=NULL;
	ipaddr_t mask;
	unsigned char empty_ipv6[IPV6_ADDR_LEN] = {0};

	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));

	aclRule.fwding_type_and_direction =  ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	aclRule.action_type = ACL_ACTION_TYPE_QOS;
	aclRule.acl_weight = RG_QOS_ACL_WEIGHT;

	// Source MAC
	if(memcmp(qos_entry->smac, EMPTY_MAC, MAC_ADDR_LEN))
	{
		aclRule.filter_fields |= INGRESS_SMAC_BIT;
		memcpy(&aclRule.ingress_smac, qos_entry->smac, MAC_ADDR_LEN);
	}

	// Destination MAC
	if(memcmp(qos_entry->dmac, EMPTY_MAC, MAC_ADDR_LEN))
	{
		aclRule.filter_fields |= INGRESS_DMAC_BIT;
		memcpy(&aclRule.ingress_dmac, qos_entry->dmac, MAC_ADDR_LEN);
	}

	//By default is filter packets from ALL LAN port.
	aclRule.filter_fields |= INGRESS_PORT_BIT;
	aclRule.ingress_port_mask.portmask = RG_get_all_lan_phyPortMask();

	// Filter rule of physic ports.
	if(qos_entry->phyPort >= 1 && qos_entry->phyPort <= SW_LAN_PORT_NUM)
	{
		aclRule.filter_fields |= INGRESS_PORT_BIT;
		//aclRule.ingress_port_mask.portmask = (1 << RTK_RG_PORT0)  | (1 << RTK_RG_PORT1) | (1 << RTK_RG_PORT2) | (1 << RTK_RG_PORT3);
		aclRule.ingress_port_mask.portmask = RG_get_lan_phyPortMask(1 << (qos_entry->phyPort-1));
	}

	// Filter rule of DSCP
	if(qos_entry->qosDscp != 0)
	{
#ifdef CONFIG_IPV6
		if(qos_entry->IpProtocol == IPVER_IPV6)
		{
			aclRule.filter_fields |= INGRESS_IPV6_DSCP_BIT;
			aclRule.ingress_ipv6_dscp = qos_entry->qosDscp >> 2;
		}
		else
#endif
		{
			aclRule.filter_fields |= INGRESS_DSCP_BIT;
			aclRule.ingress_dscp = qos_entry->qosDscp >> 2;
		}
	}

	// Filter rule of Ether Type
	if(qos_entry->ethType != 0)
	{
		aclRule.filter_fields |= INGRESS_ETHERTYPE_BIT;
		aclRule.ingress_ethertype = qos_entry->ethType;
	}

	// Filter rule of 802.1p mark
	if(qos_entry->vlan1p != 0)
	{
		aclRule.filter_fields |= INGRESS_CTAG_PRI_BIT;
		aclRule.ingress_ctag_pri = qos_entry->vlan1p - 1;
	}

	// Filter rule of Protocol: UDP, TCP, ICMP, UDP and TCP
	if(qos_entry->protoType != PROTO_NONE)
	{
		if(qos_entry->protoType == PROTO_TCP)
			aclRule.filter_fields |= INGRESS_L4_TCP_BIT;
		else if(qos_entry->protoType == PROTO_UDP)
			aclRule.filter_fields |= INGRESS_L4_UDP_BIT;
		else if(qos_entry->protoType == PROTO_ICMP){
#ifdef CONFIG_IPV6
			if(qos_entry->IpProtocol == IPVER_IPV6)
				aclRule.filter_fields |= INGRESS_L4_ICMPV6_BIT;
			else
#endif
				aclRule.filter_fields |= INGRESS_L4_ICMP_BIT;
		}
		else if(qos_entry->protoType == PROTO_UDPTCP){
			aclRule.filter_fields |= INGRESS_L4_UDP_BIT;
			udp_tcp_rule = 1;
		}
		else
		{
			if(fp != NULL)
				fclose(fp);
			DBPRINT(1, "Add acl rule failed! No support of this protocol type!\n");
			return -1;
		}
	}

#ifdef CONFIG_00R0
	if(qos_entry->application != 0) //Add rule of Application
	{
			aclRule.filter_fields |= INGRESS_L4_UDP_BIT;
			udp_tcp_rule = 1;
	}
#endif

add_udp_tcp:
    if(udp_tcp_rule==2){
        aclRule.filter_fields &= ~(INGRESS_L4_UDP_BIT);
        aclRule.filter_fields |= INGRESS_L4_TCP_BIT; //add tcp for udp/tcp protocol
    }

	if(qos_entry->sPort != 0)
	{
		aclRule.filter_fields |= INGRESS_L4_SPORT_RANGE_BIT;
		if (qos_entry->sPort == qos_entry->sPortRangeMax)
		{
			aclRule.ingress_src_l4_port_start = aclRule.ingress_src_l4_port_end = qos_entry->sPort;
		}
		else
		{
			aclRule.ingress_src_l4_port_start = MIN_VALUE(qos_entry->sPort, qos_entry->sPortRangeMax);
			aclRule.ingress_src_l4_port_end = MAX_VALUE(qos_entry->sPort, qos_entry->sPortRangeMax);
		}
	}

	if(qos_entry->dPort != 0)
	{
		aclRule.filter_fields |= INGRESS_L4_DPORT_RANGE_BIT;
		if (qos_entry->dPort == qos_entry->dPortRangeMax)
		{
			aclRule.ingress_dest_l4_port_start = aclRule.ingress_dest_l4_port_end = qos_entry->dPort;
		}
		else
		{
			aclRule.ingress_dest_l4_port_start = MIN_VALUE(qos_entry->dPort, qos_entry->dPortRangeMax);
			aclRule.ingress_dest_l4_port_end = MAX_VALUE(qos_entry->dPort, qos_entry->dPortRangeMax);
		}
	}

#ifdef CONFIG_IPV6
	if(qos_entry->IpProtocol == IPVER_IPV6)  // IPv6
	{
		aclRule.filter_fields |= INGRESS_IPV6_TAGIF_BIT;
		aclRule.ingress_ipv6_tagif = 1;
		// Source ip, prefix
		if(memcmp(qos_entry->sip6, empty_ipv6, IPV6_ADDR_LEN) != 0)
		{
			aclRule.filter_fields |= INGRESS_IPV6_SIP_RANGE_BIT;

			IPv6PrefixToStartEnd(qos_entry->sip6, qos_entry->sip6PrefixLen, aclRule.ingress_src_ipv6_addr_start, aclRule.ingress_src_ipv6_addr_end);
		}

		// Destination ip, prefix
		if(memcmp(qos_entry->dip6, empty_ipv6, IPV6_ADDR_LEN) != 0)
		{
			aclRule.filter_fields |= INGRESS_IPV6_DIP_RANGE_BIT;

			IPv6PrefixToStartEnd(qos_entry->dip6, qos_entry->dip6PrefixLen, aclRule.ingress_dest_ipv6_addr_start, aclRule.ingress_dest_ipv6_addr_end);
		}
	}
	else if(qos_entry->IpProtocol == IPVER_IPV4) // IPv4
	{
#endif
		aclRule.filter_fields |= INGRESS_IPV4_TAGIF_BIT;
		aclRule.ingress_ipv4_tagif = 1;
		// Source ip, mask
		if(memcmp(qos_entry->sip, "\x00\x00\x00\x00", IP_ADDR_LEN) != 0)
		{
			aclRule.filter_fields |= INGRESS_IPV4_SIP_RANGE_BIT;

			if(qos_entry->smaskbit == 0)
				aclRule.ingress_src_ipv4_addr_start = aclRule.ingress_src_ipv4_addr_end = ntohl(*((ipaddr_t *)qos_entry->sip));
			else
			{
				mask = ~0 << (sizeof(ipaddr_t)*8 - qos_entry->smaskbit);
				mask = htonl(mask);
				aclRule.ingress_src_ipv4_addr_start = ntohl(*((in_addr_t *)qos_entry->sip) & mask);
				aclRule.ingress_src_ipv4_addr_end = ntohl(*((in_addr_t *)qos_entry->sip) | ~mask);
			}
		}

		// Destination ip, mask
		if(memcmp(qos_entry->dip, "\x00\x00\x00\x00", IP_ADDR_LEN) != 0)
		{
			aclRule.filter_fields |= INGRESS_IPV4_DIP_RANGE_BIT;
			aclRule.filter_fields |= INGRESS_IPV4_TAGIF_BIT;
			aclRule.ingress_ipv4_tagif = 1;

			if(qos_entry->dmaskbit == 0)
				aclRule.ingress_dest_ipv4_addr_start = aclRule.ingress_dest_ipv4_addr_end = ntohl(*((ipaddr_t *)qos_entry->dip));
			else
			{
				mask = ~0 << (sizeof(ipaddr_t)*8 - qos_entry->dmaskbit);
				mask = htonl(mask);
				aclRule.ingress_dest_ipv4_addr_start = ntohl(*((in_addr_t *)qos_entry->dip) & mask);
				aclRule.ingress_dest_ipv4_addr_end = ntohl(*((in_addr_t *)qos_entry->dip) | ~mask);
			}
		}
#ifdef CONFIG_IPV6
	}
#endif

// NOT support WANInterface now!
/*
	// Filter rule of WAN interface
	if(qos_entry->outif != DUMMY_IFINDEX)
	{
		total_vc = mib_chain_total(MIB_ATM_VC_TBL);

		for( i = 0; i < total_vc; i++ )
		{
			if(!mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&vc_entry))
				continue;

			if(vc_entry.ifIndex == qos_entry->outif)
			{
				aclRule.filter_fields |= EGRESS_INTF_BIT;
				aclRule.egress_intf_idx = vc_entry.rg_wan_idx;  // Set egress interface.
			}
		}
	}
*/

	// Action rule of DSCP
	if(qos_entry->m_dscp != 0)
	{
		aclRule.qos_actions |= ACL_ACTION_DSCP_REMARKING_BIT;
		aclRule.action_dscp_remarking_pri = qos_entry->m_dscp >> 2;
	}

	// Action rule of IP precedence.
	if(qos_entry->prior != 0)
	{
		MIB_CE_IP_QOS_QUEUE_T qEntry;
		int qEntryNum, i;

		if(!mib_chain_get(MIB_IP_QOS_QUEUE_TBL, qos_entry->prior-1, (void*)&qEntry)){
			if(fp != NULL)
				fclose(fp);			
			return -1;
		}

		if(qEntry.enable)
		{
			aclRule.qos_actions |= ACL_ACTION_ACL_PRIORITY_BIT;
#ifdef CONFIG_00R0
			aclRule.action_acl_priority = 8 - qos_entry->prior;  
			aclRule.action_acl_priority -= 1;  // Only use queue  6, 5, 4, 3, let priority 7 be used by PPPoE Keep-Alive to avoid disconnection
#else
			aclRule.action_acl_priority = ACL_QOS_INTERNAL_PRIORITY_START - qos_entry->prior;
			if(aclRule.action_acl_priority<0)
				aclRule.action_acl_priority=0;
#endif
		}
	}

	// Action rule of CVLAN priority change.
	if(qos_entry->m_1p != 0)
	{
		aclRule.qos_actions |= ACL_ACTION_1P_REMARKING_BIT;
		aclRule.action_dot1p_remarking_pri = qos_entry->m_1p - 1;
	}

#ifdef CONFIG_00R0
	if(qos_entry->applicationtype != 0) //Add rule of connection type
	{
		total_vc = mib_chain_total(MIB_ATM_VC_TBL);

		for( i = 0; i < total_vc; i++ )
		{
			if(!mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&vc_entry))
				continue;

			if(vc_entry.applicationtype == qos_entry->applicationtype)
			{
				aclRule.acl_weight = RG_QOS_WANINTERFACE_ACL_WEIGHT;
				// EGRESS_INTF_BIT conflict with INGRESS_CTAG_VID_BIT/INGRESS_PORT_BIT/INGRESS_IPV4_DIP_RANGE_BIT/INGRESS_DMAC_BIT
				aclRule.filter_fields = EGRESS_INTF_BIT;
				aclRule.egress_intf_idx = vc_entry.rg_wan_idx; // Set egress interface.
				break;
			}
		}

		if (i == total_vc) {
			DBPRINT(1, "Add acl rule failed! No connection type of WAN matched !\n");
			return -1;
		}

	}

	if(qos_entry->application != 0) //Add rule of Application
	{
		aclRule.filter_fields |= INGRESS_L4_DPORT_RANGE_BIT;
		aclRule.ingress_dest_l4_port_start = aclRule.ingress_dest_l4_port_end = qos_entry->application;
	}
#endif

	if(fp == NULL){
		if(!(fp = fopen(RG_QOS_RULES_FILE, "a")))
		{
			fprintf(stderr, "ERROR! %s\n", strerror(errno));
			return -2;
		}
	}

	if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0)
		fprintf(fp, "%d\n", aclIdx);
	else
		printf("rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n", ret);

    if(udp_tcp_rule==1){
        udp_tcp_rule = 2;
        goto add_udp_tcp;
    }

	fclose(fp);
	return 0;
}

#ifdef CONFIG_00R0
int FlushRTK_RG_QoS_TS_Rules()
{
	FILE *fp;
	int qos_idx;

	if(!(fp = fopen(RG_QOS_TS_RULES_FILE, "r")))
		return -2;

	while(fscanf(fp, "%d\n", &qos_idx) != EOF)
	{
		if(rtk_rg_naptFilterAndQos_del(qos_idx))
			DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", qos_idx);
	}

	fclose(fp);
	unlink(RG_QOS_TS_RULES_FILE);
	return 0;
}
#endif

int FlushRTK_RG_QoS_Rules()
{
	FILE *fp;
	int qos_idx;

	if(fp = fopen(RG_QOS_RULES_FILE, "r"))
	{
		while(fscanf(fp, "%d\n", &qos_idx) != EOF)
		{
			if(rtk_rg_aclFilterAndQos_del(qos_idx))
				DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", qos_idx);
		}

		fclose(fp);
		unlink(RG_QOS_RULES_FILE);
	}
	return 0;
}
#endif

#ifdef CONFIG_00R0
int RTK_RG_CWMP_1P_ADD(in_addr_t ip_addr, int priority)
{
	rtk_rg_aclFilterAndQos_t aclRule;
	int aclIdx = 0, ret = 0;
	FILE *fp = NULL;

	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));

	RTK_RG_CWMP_1P_DEL();

	aclRule.fwding_type_and_direction =  ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	aclRule.action_type = ACL_ACTION_TYPE_QOS;
	aclRule.acl_weight = RG_QOS_ACL_WEIGHT;
	aclRule.filter_fields = (INGRESS_PORT_BIT|INGRESS_IPV4_DIP_RANGE_BIT);
	aclRule.ingress_port_mask.portmask = ((1<<RTK_RG_PORT_PON) | (1<<RTK_RG_PORT_CPU));
	aclRule.ingress_dest_ipv4_addr_start = aclRule.ingress_dest_ipv4_addr_end = ntohl(ip_addr);
	aclRule.qos_actions = ACL_ACTION_1P_REMARKING_BIT;
	aclRule.action_dot1p_remarking_pri = priority;

	if (!(fp = fopen(RG_CWMP_1P_FILE, "a"))) {
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -2;
	}

	if ((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0) {
		fprintf(fp, "%d\n", aclIdx);
	}
	else {
		printf("rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n", ret);
		fclose(fp);
		return -1;
	}

	fclose(fp);
	return 0;
}

int RTK_RG_CWMP_1P_DEL()
{
	FILE *fp = NULL;
	int aclIdx= -1;
	if (!(fp = fopen(RG_CWMP_1P_FILE, "r"))) {
		return -2;
	}

	while (fscanf(fp, "%d\n", &aclIdx) != EOF) {
		if (rtk_rg_aclFilterAndQos_del(aclIdx))
			DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", aclIdx);
	}

	fclose(fp);
	unlink(RG_CWMP_1P_FILE);
	return 0;
}
#endif

#ifdef CONFIG_USER_MINIUPNPD
int AddRTK_RG_UPnP_Connection(unsigned short eport, const char *iaddr, unsigned short iport, int protocol)
{
	int upnpIdx, ret, total_vc, i;
	rtk_rg_upnpConnection_t upnp;
	MIB_CE_ATM_VC_T vc_entry;
	FILE *fp;
	unsigned int ext_if;
	char lan_ip[IP_ADDR_LEN];

	mib_get(MIB_UPNP_EXT_ITF, (void *)&ext_if);
	inet_pton(AF_INET, iaddr, (void *)lan_ip);
	memset(&upnp, 0, sizeof(rtk_rg_upnpConnection_t));

	upnp.valid = ENABLED;
	upnp.is_tcp = (protocol == IPPROTO_TCP? 1: 0);
	upnp.gateway_port = eport;
	upnp.local_ip = ntohl(*((ipaddr_t *)lan_ip));
	upnp.local_port = iport;
	upnp.limit_remote_ip = DISABLED;
	upnp.limit_remote_port = DISABLED;
	upnp.type = UPNP_TYPE_PERSIST;
	upnp.timeout = 0; // 0: disable auto-delete

	total_vc = mib_chain_total(MIB_ATM_VC_TBL);

	for( i = 0; i < total_vc; i++ )
	{
		if(!mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&vc_entry))
			continue;

		if(vc_entry.ifIndex == ext_if)
		{
			upnp.wan_intf_idx = vc_entry.rg_wan_idx;
			break;
		}
	}

	if(!(fp = fopen(RG_UPNP_CONNECTION_FILE, "a")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -2;
	}

	if((ret = rtk_rg_upnpConnection_add(&upnp, &upnpIdx)) == 0)
		fprintf(fp, "%d %u %d\n", upnpIdx, eport, protocol);
	else
		printf("rtk_rg_upnpConnection_add rule failed!\n");

	fclose(fp);
	return 0;
}

int DelRTK_RG_UPnP_Napt_Connection(rtk_rg_upnpConnection_t *upnpConnection)
{
	int napt_idx, ret;
	rtk_rg_naptInfo_t naptInfo;
	
	for(napt_idx=0 ; napt_idx<1024 ; napt_idx++){
		ret = rtk_rg_naptConnection_find(&naptInfo,&napt_idx);		
		if(ret==RT_ERR_RG_OK){

			if(naptInfo.naptTuples.external_port != upnpConnection->gateway_port)
				continue;

			if(naptInfo.naptTuples.local_port != upnpConnection->local_port)
				continue;

			if(naptInfo.naptTuples.local_ip != upnpConnection->local_ip)
				continue;

			if(naptInfo.naptTuples.wan_intf_idx != upnpConnection->wan_intf_idx)
				continue;
	
			if((ret = rtk_rg_naptConnection_del(napt_idx)) != RT_ERR_RG_OK)
			{
				DBPRINT(1, "rtk_rg_naptConnection_del failed! idx=%d ret=%d\n", napt_idx, ret);
				return -1;
			}
			
			return 0;
		}
	}

	return 0;
}

int DelRTK_RG_UPnP_Connection(unsigned short eport, int protocol)
{
	rtk_rg_upnpConnection_t upnpConnection = {0};
	FILE *fp, *fp_tmp;
	int upnp_idx, upnp_eport, upnp_proto;
	char line[24];

	if(!(fp = fopen(RG_UPNP_CONNECTION_FILE, "r")))
		return -2;

	if(!(fp_tmp = fopen(RG_UPNP_TMP_FILE, "w"))){
		fclose(fp);
		return -2;
	}

	while(fgets(line, 23, fp) != NULL)
	{
		sscanf(line, "%d %d %d\n", &upnp_idx, &upnp_eport, &upnp_proto);

		if( upnp_eport == eport && upnp_proto == protocol )
		{
			memset(&upnpConnection, 0, sizeof(rtk_rg_upnpConnection_t));
			if(rtk_rg_upnpConnection_find(&upnpConnection, &upnp_idx) == RT_ERR_RG_OK) {
				if(rtk_rg_upnpConnection_del(upnp_idx))
					DBPRINT(1, "rtk_rg_upnpConnection_del failed! idx = %d\n", upnp_idx);
				else
				{ 
					// We need to delete associative NAPT connection info from RG further
					DelRTK_RG_UPnP_Napt_Connection(&upnpConnection);
				}
			}
		}
		else
			fprintf(fp_tmp, "%d %d %d\n", upnp_idx, upnp_eport, upnp_proto);
	}

	fclose(fp);
	fclose(fp_tmp);
	unlink(RG_UPNP_CONNECTION_FILE);
	rename(RG_UPNP_TMP_FILE, RG_UPNP_CONNECTION_FILE);
	return 0;
}
#endif

#ifdef CONFIG_IP_NF_ALG_ONOFF
int RTK_RG_ALG_Set()
{
	rtk_rg_alg_type_t alg_app = 0;

	unsigned char value;
#ifdef CONFIG_NF_CONNTRACK_FTP
	if(mib_get(MIB_IP_ALG_FTP, &value) && value == 1)
		alg_app |= RTK_RG_ALG_FTP_TCP_BIT | RTK_RG_ALG_FTP_UDP_BIT;
#endif
#ifdef CONFIG_NF_CONNTRACK_TFTP
	if(mib_get(MIB_IP_ALG_TFTP, &value) && value == 1)
		alg_app |= RTK_RG_ALG_TFTP_UDP_BIT;
	else{
		alg_app &= ~(RTK_RG_ALG_TFTP_UDP_BIT);
	}
#endif
#ifdef CONFIG_NF_CONNTRACK_H323
	if(mib_get(MIB_IP_ALG_H323, &value) && value == 1)
		alg_app |= RTK_RG_ALG_H323_TCP_BIT | RTK_RG_ALG_H323_UDP_BIT;
#endif
#ifdef CONFIG_NF_CONNTRACK_RTSP
	if(mib_get(MIB_IP_ALG_RTSP, &value) && value == 1)
		alg_app |= RTK_RG_ALG_RTSP_TCP_BIT | RTK_RG_ALG_RTSP_UDP_BIT;
#endif
#ifdef CONFIG_NF_CONNTRACK_L2TP
	if(mib_get(MIB_IP_ALG_L2TP, &value) && value == 1)
		alg_app |= RTK_RG_ALG_L2TP_TCP_PASSTHROUGH_BIT | RTK_RG_ALG_L2TP_UDP_PASSTHROUGH_BIT;
#endif
#ifdef CONFIG_NF_CONNTRACK_IPSEC
	if(mib_get(MIB_IP_ALG_IPSEC, &value) && value == 1)
		alg_app |= RTK_RG_ALG_IPSEC_TCP_PASSTHROUGH_BIT | RTK_RG_ALG_IPSEC_UDP_PASSTHROUGH_BIT;
#endif
#ifdef CONFIG_NF_CONNTRACK_SIP
	if(mib_get(MIB_IP_ALG_SIP, &value) && value == 1)
		alg_app |= RTK_RG_ALG_SIP_TCP_BIT | RTK_RG_ALG_SIP_UDP_BIT;
#endif
#ifdef CONFIG_NF_CONNTRACK_PPTP
	if(mib_get(MIB_IP_ALG_PPTP, &value) && value == 1)
		alg_app |= RTK_RG_ALG_PPTP_TCP_PASSTHROUGH_BIT | RTK_RG_ALG_PPTP_UDP_PASSTHROUGH_BIT;
#endif

	if(rtk_rg_algApps_set(alg_app))
	{
		DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed! alg_app = %X\n", alg_app);
		return -1;
	}

	return 0;
}
#endif

#ifdef URL_BLOCKING_SUPPORT
int RTK_RG_URL_Filter_Set()
{
	int url_idx, ret, total_url, total_keyd, i;
	rtk_rg_urlFilterString_t url_f_s;
	MIB_CE_URL_FQDN_T fqdn;
	MIB_CE_KEYWD_FILTER_T keyword;
	FILE *fp;

	total_url = mib_chain_total(MIB_URL_FQDN_TBL);

	if(!(fp = fopen(RG_URL_FILTER_FILE, "a")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -2;
	}

	url_f_s.path_exactly_match = 0;

	for (i = 0; i < total_url; i++)
	{
		if (!mib_chain_get(MIB_URL_FQDN_TBL, i, (void *)&fqdn))
			continue;

		memset(&url_f_s,0,sizeof(rtk_rg_urlFilterString_t));
		strncpy(url_f_s.url_filter_string, fqdn.fqdn, MAX_URL_LENGTH);

		if((ret = rtk_rg_urlFilterString_add(&url_f_s, &url_idx)) == 0)
			fprintf(fp, "%d\n", url_idx);
		else
			DBPRINT(1, "rtk_rg_urlFilterString_add QoS rule failed!\n");
	}

	total_keyd = mib_chain_total(MIB_KEYWD_FILTER_TBL);

	for(i = 0; i < total_keyd; i++)
	{
		if(!mib_chain_get(MIB_KEYWD_FILTER_TBL, i, (void *)&keyword))
		 continue;

		memset(&url_f_s,0,sizeof(rtk_rg_urlFilterString_t));
		strncpy(url_f_s.url_filter_string, keyword.keyword, MAX_KEYWD_LENGTH);

		if((ret = rtk_rg_urlFilterString_add(&url_f_s, &url_idx)) == 0)
			fprintf(fp, "%d\n", url_idx);
		else
			DBPRINT(1, "rtk_rg_urlFilterString_add QoS rule failed!\n");
	}

	fclose(fp);
	return 0;
}

int Flush_RTK_RG_URL_Filter()
{
	FILE *fp;
	int url_filter_idx;

	if(!(fp = fopen(RG_URL_FILTER_FILE, "r")))
		return -2;

	while(fscanf(fp, "%d\n", &url_filter_idx) != EOF)
	{
		if(rtk_rg_urlFilterString_del(url_filter_idx))
			DBPRINT(1, "rtk_rg_urlFilterString_del failed! idx = %d\n", url_filter_idx);
	}

	fclose(fp);
	unlink(RG_URL_FILTER_FILE);
	return 0;
}
#endif

#if 0
#define CALLBACKREGIST  "/proc/rg/callbackRegist"
int callbackRegistCheck(void)
{
	FILE *fp;
	int proc_read;
	int enabled=0;
	char buffer[8];
	fp=fopen(CALLBACKREGIST, "r");
	if(fp==NULL)
	{
		printf("file %s open failed @%s line:%d\n", CALLBACKREGIST,__func__,__LINE__);
		return FALSE;
	}
	memset(buffer, 0, sizeof(buffer));
	proc_read=fread(buffer, 1, 8, fp);
	if(proc_read!=0){
		printf("read size=%d, buffer=%s\n", proc_read, buffer);
	}
	if(proc_read < 0){
		printf("proc_read failed @%s line:%d\n",__func__,__LINE__);
		goto err;
	}

	if(strncmp(buffer, "1",1) == 0){
		enabled = TRUE;
	}else if(strncmp(buffer, "0",1) == 0){
		enabled = FALSE;
	}
err:
	fclose(fp);

	return enabled;
}
#endif

int rg_eth2wire_block(int enable)
{
	rtk_rg_port_isolation_t isoset;
	int idx,phyPortId;

	// block from lan port
	for(idx = 0 ; idx < SW_LAN_PORT_NUM; idx++)
	{
		if(rtk_rg_switch_phyPortId_get(idx, &phyPortId) == 0)
			isoset.port = phyPortId;
		else
		{
			DBPRINT(1, "Get LAN port(%d) to phy port failed\n", idx);
			isoset.port = idx;
		}
		if(enable) 
			#ifdef CONFIG_RTL9607C
			isoset.portmask.portmask = 0xe7ff; // clear bit 11/12
			#else
			isoset.portmask.portmask = 0x5f; // clear bit 7/8
			#endif
		else isoset.portmask.portmask = RTK_RG_ALL_PORTMASK;
		if(rtk_rg_portIsolation_set(isoset) != 0)
			DBPRINT(1, "set LAN port(%d) to wireless blocking failed\n", idx);
	}
	// block from extport (port 7/8)
	#ifdef CONFIG_RTL9607C
	isoset.port = 11;
	#else
	isoset.port = 7;
	#endif
	if(enable) isoset.portmask.portmask = 0xff0;
	else isoset.portmask.portmask = RTK_RG_ALL_PORTMASK;
	if(rtk_rg_portIsolation_set(isoset) != 0)
		DBPRINT(1, "set EXT port(7) to LAN blocking failed\n");
	#if defined(WLAN_DUALBAND_CONCURRENT)
	#ifdef CONFIG_RTL9607C
	isoset.port = 12;
	#else
	isoset.port = 8;
	#endif
	if(enable) isoset.portmask.portmask = 0xff0;
	else isoset.portmask.portmask = 0xfff;
	if(rtk_rg_portIsolation_set(isoset) != 0)
		DBPRINT(1, "set EXT port(8) to LAN blocking failed\n");
	#endif

	return 0;
}

#ifdef DOS_SUPPORT
int RTK_RG_FLUSH_DOS_FILTER_RULE()
{
	FILE *fp;
	int filter_idx;

	if(!(fp = fopen(RG_DOS_FILTER_FILE, "r")))
		return -2;

	while(fscanf(fp, "%d\n", &filter_idx) != EOF)
	{
		if(rtk_rg_aclFilterAndQos_del(filter_idx))
			DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", filter_idx);
	}

	fclose(fp);
	unlink(RG_DOS_FILTER_FILE);
	return 0;
}

int RTK_RG_DoS_Set(int enable)
{
	rtk_rg_mac_portmask_t dos_port_mask;
	int wanPhyPort;
	int floodCount;
	int floodTh;

	if(!(enable & DOS_ENABLE)){
		printf("rg DoS: disable\n");
		dos_port_mask.portmask = 0x0;
		rtk_rg_dosPortMaskEnable_set(dos_port_mask);
	}
	else{
		printf("rg DoS: enable\n");
		#if 0
		if(mib_get(MIB_WAN_PHY_PORT , (void *)&wanPhyPort) == 0){
			printf("get MIB_WAN_PHY_PORT failed!!!\n");
			wanPhyPort=RTK_RG_MAC_PORT3 ; //for 0371 default
		}
		dos_port_mask.portmask = 1 << wanPhyPort;
		#endif
		dos_port_mask.portmask = RG_get_lan_phyPortMask(0xf) | RG_get_wan_phyPortMask();
		rtk_rg_dosPortMaskEnable_set(dos_port_mask);
	}

#if 0
	//for blocking udp flood
	if(enable & UDPBombEnabled) {
		int ret=0, acl_index=0;
		FILE *fp;
		rtk_rg_aclFilterAndQos_t aclRule;
		
		if(!(fp = fopen(RG_DOS_FILTER_FILE, "w")))
		{
			fprintf(stderr, "ERROR! %s\n", strerror(errno));
			return -2;
		}

		//rg add shareMeter index 1 rate 800 ifgInclude 1

		//rg set acl-filter fwding_type_and_direction 0
		//rg set acl-filter pattern ingress_port_mask 0x10
		//rg set acl-filter pattern ingress_l4_protocal 0
		//rg set acl-filter action action_type 3
		//rg set acl-filter action qos action_share_meter 1
		//rg add acl-filter entry
		ret = rtk_rg_shareMeter_set(28,800,RTK_RG_ENABLED);
#if 0 //2017-12-20 cxy:comment for not filter udp data flow
		memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
		aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
		aclRule.action_type = ACL_ACTION_TYPE_QOS;
		aclRule.acl_weight = RG_DEFAULT_ACL_WEIGHT;
		aclRule.filter_fields |= INGRESS_PORT_BIT;
		aclRule.ingress_port_mask.portmask =  RG_get_lan_phyPortMask(0xf) | RG_get_wan_phyPortMask();
		aclRule.filter_fields |= INGRESS_L4_UDP_BIT;
		aclRule.qos_actions = ACL_ACTION_SHARE_METER_BIT;
		aclRule.action_share_meter = 28;
		if((ret = rtk_rg_aclFilterAndQos_add(&aclRule,&acl_index)) == 0)
			fprintf(fp, "%d\n", acl_index);
		else
			printf("rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n", ret);
#endif
        /* filter 802.1x auth flood */
        memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
		aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
		aclRule.action_type = ACL_ACTION_TYPE_QOS;
		aclRule.acl_weight = RG_DEFAULT_ACL_WEIGHT;
		aclRule.filter_fields |= INGRESS_PORT_BIT;
		aclRule.ingress_port_mask.portmask =  RG_get_lan_phyPortMask(0xf) | RG_get_wan_phyPortMask();
		aclRule.filter_fields |= INGRESS_ETHERTYPE_BIT;
        aclRule.ingress_ethertype =  0x888e;
		aclRule.qos_actions = ACL_ACTION_SHARE_METER_BIT;
		aclRule.action_share_meter = 28;
		if((ret = rtk_rg_aclFilterAndQos_add(&aclRule,&acl_index)) == 0)
			fprintf(fp, "%d\n", acl_index);
		else
			printf("rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n", ret);

        /* arp attack flood */
        memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
		aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
		aclRule.action_type = ACL_ACTION_TYPE_QOS;
		aclRule.acl_weight = RG_DEFAULT_ACL_WEIGHT;
		aclRule.filter_fields |= INGRESS_PORT_BIT;
		aclRule.ingress_port_mask.portmask =  RG_get_lan_phyPortMask(0xf) | RG_get_wan_phyPortMask();
		aclRule.filter_fields |= INGRESS_ETHERTYPE_BIT;
        aclRule.ingress_ethertype =  0x0806;
		aclRule.qos_actions = ACL_ACTION_SHARE_METER_BIT;
		aclRule.action_share_meter = 28;
		if((ret = rtk_rg_aclFilterAndQos_add(&aclRule,&acl_index)) == 0)
			fprintf(fp, "%d\n", acl_index);
		else
			printf("rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n", ret);

        /* filter DHCP flood */
        memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
		aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
		aclRule.action_type = ACL_ACTION_TYPE_QOS;
		aclRule.acl_weight = RG_DEFAULT_ACL_WEIGHT;
		aclRule.filter_fields |= INGRESS_PORT_BIT;
		aclRule.ingress_port_mask.portmask =  RG_get_lan_phyPortMask(0xf) | RG_get_wan_phyPortMask();
        aclRule.filter_fields |= INGRESS_L4_UDP_BIT;
		aclRule.filter_fields |= INGRESS_L4_DPORT_RANGE_BIT;
        aclRule.ingress_dest_l4_port_start = 67;
        aclRule.ingress_dest_l4_port_end = 67;
		aclRule.qos_actions = ACL_ACTION_SHARE_METER_BIT;
		aclRule.action_share_meter = 28;
		if((ret = rtk_rg_aclFilterAndQos_add(&aclRule,&acl_index)) == 0)
			fprintf(fp, "%d\n", acl_index);
		else
			printf("rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n", ret);

        /* filter igmp flood */
        memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
		aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
		aclRule.action_type = ACL_ACTION_TYPE_QOS;
		aclRule.acl_weight = RG_DEFAULT_ACL_WEIGHT;
		aclRule.filter_fields |= INGRESS_PORT_BIT;
		aclRule.ingress_port_mask.portmask =  RG_get_lan_phyPortMask(0xf) | RG_get_wan_phyPortMask();
        aclRule.filter_fields |= INGRESS_ETHERTYPE_BIT;
        aclRule.ingress_ethertype =  0x0800;
		aclRule.filter_fields |= INGRESS_L4_POROTCAL_VALUE_BIT;
        aclRule.ingress_l4_protocal = 2;
		aclRule.qos_actions = ACL_ACTION_SHARE_METER_BIT;
		aclRule.action_share_meter = 28;
		if((ret = rtk_rg_aclFilterAndQos_add(&aclRule,&acl_index)) == 0)
			fprintf(fp, "%d\n", acl_index);
		else
			printf("rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n", ret);

        /* filter LACP flood */
        memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
		aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
		aclRule.action_type = ACL_ACTION_TYPE_QOS;
		aclRule.acl_weight = RG_DEFAULT_ACL_WEIGHT;
		aclRule.filter_fields |= INGRESS_PORT_BIT;
		aclRule.ingress_port_mask.portmask =  RG_get_lan_phyPortMask(0xf) | RG_get_wan_phyPortMask();
		aclRule.filter_fields |= INGRESS_ETHERTYPE_BIT;
        aclRule.ingress_ethertype =  0x8809;
		aclRule.qos_actions = ACL_ACTION_SHARE_METER_BIT;
		aclRule.action_share_meter = 28;
		if((ret = rtk_rg_aclFilterAndQos_add(&aclRule,&acl_index)) == 0)
			fprintf(fp, "%d\n", acl_index);
		else
			printf("rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n", ret);

        /* filter pppoe flood */
        memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
		aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
		aclRule.action_type = ACL_ACTION_TYPE_QOS;
		aclRule.acl_weight = RG_DEFAULT_ACL_WEIGHT;
		aclRule.filter_fields |= INGRESS_PORT_BIT;
		aclRule.ingress_port_mask.portmask =  RG_get_lan_phyPortMask(0xf) | RG_get_wan_phyPortMask();
		aclRule.filter_fields |= INGRESS_ETHERTYPE_BIT;
        aclRule.ingress_ethertype =  0x8863;
		aclRule.qos_actions = ACL_ACTION_SHARE_METER_BIT;
		aclRule.action_share_meter = 28;
		if((ret = rtk_rg_aclFilterAndQos_add(&aclRule,&acl_index)) == 0)
			fprintf(fp, "%d\n", acl_index);
		else
			printf("rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n", ret);

        /* filter stp flood */
        memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
		aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
		aclRule.action_type = ACL_ACTION_TYPE_QOS;
		aclRule.acl_weight = RG_DEFAULT_ACL_WEIGHT;
		aclRule.filter_fields |= INGRESS_PORT_BIT;
		aclRule.ingress_port_mask.portmask =  RG_get_lan_phyPortMask(0xf) | RG_get_wan_phyPortMask();
		aclRule.filter_fields |= INGRESS_ETHERTYPE_BIT;
        aclRule.ingress_ethertype =  0x0026;
		aclRule.qos_actions = ACL_ACTION_SHARE_METER_BIT;
		aclRule.action_share_meter = 28;
		if((ret = rtk_rg_aclFilterAndQos_add(&aclRule,&acl_index)) == 0)
			fprintf(fp, "%d\n", acl_index);
		else
			printf("rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n", ret);

        /* filter icmp flood */
        memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
		aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
		aclRule.action_type = ACL_ACTION_TYPE_QOS;
		aclRule.acl_weight = RG_DEFAULT_ACL_WEIGHT;
		aclRule.filter_fields |= INGRESS_PORT_BIT;
		aclRule.ingress_port_mask.portmask =  RG_get_lan_phyPortMask(0xf) | RG_get_wan_phyPortMask();
		aclRule.filter_fields |= INGRESS_L4_ICMP_BIT;
		aclRule.qos_actions = ACL_ACTION_SHARE_METER_BIT;
		aclRule.action_share_meter = 28;
		if((ret = rtk_rg_aclFilterAndQos_add(&aclRule,&acl_index)) == 0)
			fprintf(fp, "%d\n", acl_index);
		else
			printf("rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n", ret);

		fclose(fp);
	}
#endif

	if(enable & SYSFLOODSYN){
		if(mib_get(MIB_DOS_SYSSYN_FLOOD, (void *)&floodCount)!=0){
			floodTh = 1000/floodCount;
			if(rtk_rg_dosFloodType_set(RTK_RG_DOS_SYNFLOOD_DENY, 1,RTK_RG_DOS_ACTION_DROP,floodTh)) //time unit 1ms
				DBPRINT(1, "rtk_rg_dosFloodType_set failed! type = RTK_RG_DOS_SYNFLOOD_DENY\n");
		}
		else
			DBPRINT(1, "MIB_DOS_SYSSYN_FLOOD get failed! \n");
	}

	if(enable & SYSFLOODFIN){
		if(mib_get(MIB_DOS_SYSFIN_FLOOD, (void *)&floodCount)!=0){
			floodTh = 1000/floodCount;
			if(rtk_rg_dosFloodType_set(RTK_RG_DOS_FINFLOOD_DENY, 1,RTK_RG_DOS_ACTION_DROP,floodTh)) //time unit 1ms
				DBPRINT(1, "rtk_rg_dosFloodType_set failed! type = RTK_RG_DOS_FINFLOOD_DENY\n");
		}
		else
			DBPRINT(1, "MIB_DOS_SYSFIN_FLOOD get failed! \n");
	}

	if(enable & SYSFLOODICMP){
		if(mib_get(MIB_DOS_SYSICMP_FLOOD, (void *)&floodCount)!=0){
			floodTh = 1000/floodCount;
			if(rtk_rg_dosFloodType_set(RTK_RG_DOS_ICMPFLOOD_DENY,1,RTK_RG_DOS_ACTION_DROP,floodTh)) //time unit 1ms
				DBPRINT(1, "rtk_rg_dosFloodType_set failed! type = RTK_RG_DOS_ICMPFLOOD_DENY\n");
		}
		else
			DBPRINT(1, "MIB_DOS_SYSICMP_FLOOD get failed! \n");
	}

	if(rtk_rg_dosType_set(RTK_RG_DOS_LAND_DENY,(enable & IPLANDENABLED)? 1:0,RTK_RG_DOS_ACTION_DROP))
		DBPRINT(1, "rtk_rg_dosType_set failed! type = RTK_RG_DOS_LAND_DENY\n");

	if(rtk_rg_dosType_set(RTK_RG_DOS_POD_DENY,(enable & PINGOFDEATHENABLED)? 1:0,RTK_RG_DOS_ACTION_DROP))
		DBPRINT(1, "rtk_rg_dosType_set failed! type = RTK_RG_DOS_POD_DENY\n");


	if(enable & TCPSCANENABLED){
		if(rtk_rg_dosType_set(RTK_RG_DOS_SYNFIN_DENY,ENABLED,RTK_RG_DOS_ACTION_DROP))
			DBPRINT(1, "rtk_rg_dosType_set failed! type = RTK_RG_DOS_SYNFIN_DENY\n");

		if(rtk_rg_dosType_set(RTK_RG_DOS_XMA_DENY,ENABLED,RTK_RG_DOS_ACTION_DROP))
			DBPRINT(1, "rtk_rg_dosType_set failed! type = RTK_RG_DOS_XMA_DENY\n");

		if(rtk_rg_dosType_set(RTK_RG_DOS_NULLSCAN_DENY,ENABLED,RTK_RG_DOS_ACTION_DROP))
			DBPRINT(1, "rtk_rg_dosType_set failed! type = RTK_RG_DOS_NULLSCAN_DENY\n");
	}
	else{
		if(rtk_rg_dosType_set(RTK_RG_DOS_SYNFIN_DENY,DISABLED,RTK_RG_DOS_ACTION_DROP))
			DBPRINT(1, "rtk_rg_dosType_set failed! type = RTK_RG_DOS_SYNFIN_DENY\n");

		if(rtk_rg_dosType_set(RTK_RG_DOS_XMA_DENY,DISABLED,RTK_RG_DOS_ACTION_DROP))
			DBPRINT(1, "rtk_rg_dosType_set failed! type = RTK_RG_DOS_XMA_DENY\n");

		if(rtk_rg_dosType_set(RTK_RG_DOS_NULLSCAN_DENY,DISABLED,RTK_RG_DOS_ACTION_DROP))
			DBPRINT(1, "rtk_rg_dosType_set failed! type = RTK_RG_DOS_NULLSCAN_DENY\n");
	}

	if(rtk_rg_dosType_set(RTK_RG_DOS_SYNWITHDATA_DENY,(enable & TCPSynWithDataEnabled)? 1:0,RTK_RG_DOS_ACTION_DROP))
		DBPRINT(1, "rtk_rg_dosType_set failed! type = RTK_RG_DOS_SYNWITHDATA_DENY\n");

	return 0;
}
#endif

unsigned int RG_get_lan_phyPortMask(unsigned int portmask)
{
	unsigned char re_map_tbl[MAX_LAN_PORT_NUM];
	int i=0, phyPortId, ret;
	unsigned int phyportmask=0;
#if defined(CONFIG_USER_LAN_PORT_AS_ETH_WAN)
	int ethPhyPortId = -1;
	mib_get(MIB_ETH_WAN_PORT_PHY_INDEX, &ethPhyPortId);
#endif

	mib_get(MIB_PORT_REMAPPING, (void *)re_map_tbl);
	for(i=0;i<SW_LAN_PORT_NUM;i++)
	{
		if((portmask>>i) & 1){
			ret = rtk_rg_switch_phyPortId_get(re_map_tbl[i], &phyPortId);
			if(ret == 0)
			{
#if defined(CONFIG_USER_LAN_PORT_AS_ETH_WAN)
				if(phyPortId == ethPhyPortId)
					continue;
#endif
				phyportmask |= (1 << phyPortId);
			}
			else
				DBPRINT(1, "%s rtk_rg_switch_phyPortId_get id %d failed!\n", __FUNCTION__, i);
		}
	}

#ifdef CONFIG_RGMII_RESET_PROCESS
	phyportmask |= (1 << RTK_RG_MAC_PORT_RGMII);
#endif

	return phyportmask;
}

unsigned int RG_get_all_lan_phyPortMask(void)
{
#ifdef CONFIG_LAN_PORT_NUM
	unsigned int allLanPortMask = ((1<<CONFIG_LAN_PORT_NUM)-1);
	return RG_get_lan_phyPortMask(allLanPortMask);
#else
#ifdef CONFIG_RTL9602C_SERIES
	return RG_get_lan_phyPortMask(0x3);
#else
	return RG_get_lan_phyPortMask(0xf);
#endif
#endif
}

unsigned int RG_get_wan_phyPortMask()
{
	int phyPortId, ret, logPortId;
	unsigned int phyportmask=0;
#if defined(CONFIG_USER_LAN_PORT_AS_ETH_WAN)
	//cxy 2015-3-18: check if specify lan port as ether wan port. if so, return specify lan port
	int ethPhyPortId = -1;
	mib_get(MIB_ETH_WAN_PORT_PHY_INDEX, &ethPhyPortId);
	if (ethPhyPortId != -1)
		return (1 << ethPhyPortId);
#endif

#if defined(CONFIG_ETHWAN_USE_USB_SGMII)
	logPortId = RTK_PORT_HSG0;
#elif defined(CONFIG_ETHWAN_USE_PCIE1_SGMII)
	logPortId = RTK_PORT_HSG1;
#else
	logPortId = RTK_PORT_PON;
#endif
	ret = rtk_rg_switch_phyPortId_get(logPortId, &phyPortId);

	if(ret == 0)
		phyportmask |= (1 << phyPortId);
	else
		DBPRINT(1, "%s rtk_rg_switch_phyPortId_get failed!\n", __FUNCTION__);

	return phyportmask;
}

int RG_get_lan_phyPortId(int logPortId)
{
	unsigned char re_map_tbl[MAX_LAN_PORT_NUM];
	int phyPortId, ret;

	mib_get(MIB_PORT_REMAPPING, (void *)re_map_tbl);

	ret = rtk_rg_switch_phyPortId_get(re_map_tbl[logPortId], &phyPortId);

	if(ret == 0)
		return phyPortId;
	else{
		DBPRINT(1, "%s rtk_rg_switch_phyPortId_get failed!\n", __FUNCTION__);
		return -1;
	}
}

#ifdef WLAN_SUPPORT
int RG_get_wlan_phyPortId(int logPortId)
{
	int phyPortId, ret;
	if (logPortId >= PMAP_WLAN0 && logPortId <= PMAP_WLAN0_VAP3) {
		phyPortId = RTK_RG_EXT_PORT0;
	}
#ifdef WLAN_DUALBAND_CONCURRENT
	else if (logPortId >= PMAP_WLAN1 && logPortId <= PMAP_WLAN1_VAP3) {
		phyPortId = RTK_RG_EXT_PORT1;
	}
#endif
	else {
		phyPortId = RTK_RG_EXT_PORT0;
	}

	return phyPortId;
}
#endif


int RG_get_wan_phyPortId()
{
	int phyPortId, ret, logPortId;
#if defined(CONFIG_USER_LAN_PORT_AS_ETH_WAN)
	//cxy 2015-3-18: check if specify lan port as ether wan port. if so, return specify lan port
	int ethPhyPortId = -1;
	mib_get(MIB_ETH_WAN_PORT_PHY_INDEX, &ethPhyPortId);
	if (ethPhyPortId != -1)
		return ethPhyPortId;
#endif

#if defined(CONFIG_ETHWAN_USE_USB_SGMII)
	logPortId = RTK_PORT_HSG0;
#elif defined(CONFIG_ETHWAN_USE_PCIE1_SGMII)
	logPortId = RTK_PORT_HSG1;
#else
	logPortId = RTK_PORT_PON;
#endif
	ret = rtk_rg_switch_phyPortId_get(logPortId, &phyPortId);

	if(ret == 0) 
		return phyPortId;
	else{
		DBPRINT(1, "%s rtk_rg_switch_phyPortId_get failed!\n", __FUNCTION__);
		return -1;
	}
}

unsigned int RG_get_portCounter(unsigned int portIndex,unsigned long *tx_pkts,unsigned long *tx_drops,unsigned long *tx_errs,
										unsigned long *rx_pkts,unsigned long *rx_drops,unsigned long *rx_errs)
{
	rtk_rg_port_mib_info_t portmib;
	int ret;

	ret = rtk_rg_portMibInfo_get(RG_get_lan_phyPortId(portIndex),&portmib);
	if(ret != 0)
	{
		DBPRINT(1, "%s get port %d mib info failed!\n", __FUNCTION__, portIndex);
		return 0;
	}

	*rx_pkts = (portmib.ifInUcastPkts + portmib.ifInMulticastPkts + portmib.ifInBroadcastPkts);
	*rx_drops = portmib.dot1dTpPortInDiscards;
	*rx_errs = (portmib.dot3StatsSymbolErrors + portmib.dot3ControlInUnknownOpcodes);
	*tx_pkts = (portmib.ifOutUcastPkts + portmib.ifOutMulticastPkts + portmib.ifOutBrocastPkts);
	*tx_drops = portmib.ifOutDiscards ;
	*tx_errs = 0;
	return 1;
}

unsigned int RG_clear_portCounter(unsigned int portIndex)
{
	int ret;

	ret = rtk_rg_portMibInfo_clear(RG_get_lan_phyPortId(portIndex));
	if(ret != 0)
	{
		DBPRINT(1, "%s get port %d mib info failed!\n", __FUNCTION__, portIndex);
		return 0;
	}
	return 1;
}

int RG_wan_phy_force_power_down(int enabled)
{
	uint32 reg;
	rtk_rg_mac_port_idx_t port = 0;

	for(port = 0 ; port < RTK_RG_MAC_PORT_MAX ; port++)
	{
		rtk_rg_port_phyReg_get(port, 0xbc0, 19, &reg);
		if(enabled)
			reg = reg | 0x10;
		else
			reg = reg & 0xFFEF;
		rtk_rg_port_phyReg_set(port, 0xbc0, 19, reg);
	}
	return 0;
}


const char VCONFIG[] = "/bin/vconfig";
#define ALIASNAME_ELAN_RG_WLAN "eth0"

int setup_vconfig(unsigned short LanVid, int LanPortIdx)
{
	char v_eth_name[32] = {0};
	char sLanVid[16] = {0};
	unsigned char value[6] = {0};
	sprintf(sLanVid, "%d", LanVid);
	switch (LanPortIdx)
	{
		case 0:
			va_cmd(VCONFIG, 3, 1, "add", ALIASNAME_ELAN0, sLanVid);
			sprintf(v_eth_name, "%s.%d", ALIASNAME_ELAN0, LanVid);
			break;
		case 1:
			va_cmd(VCONFIG, 3, 1, "add", ALIASNAME_ELAN1, sLanVid);
			sprintf(v_eth_name, "%s.%d", ALIASNAME_ELAN1, LanVid);
			break;
		case 2:
			va_cmd(VCONFIG, 3, 1, "add", ALIASNAME_ELAN2, sLanVid);
			sprintf(v_eth_name, "%s.%d", ALIASNAME_ELAN2, LanVid);
			break;
		case 3:
			va_cmd(VCONFIG, 3, 1, "add", ALIASNAME_ELAN3, sLanVid);
			sprintf(v_eth_name, "%s.%d", ALIASNAME_ELAN3, LanVid);
			break;
#ifdef WLAN_SUPPORT
		case 4:
			//add this for normal path. (To protocol stack.)
			va_cmd(VCONFIG, 3, 1, "add", ALIASNAME_WLAN0, sLanVid);
			sprintf(v_eth_name, "%s.%d", ALIASNAME_WLAN0, LanVid);
			va_cmd(BRCTL, 3, 1, "addif", ALIASNAME_BR0, v_eth_name);
			va_cmd(IFCONFIG, 2, 1, v_eth_name, "up");

			//add this for forwarding engine
			va_cmd(VCONFIG, 3, 1, "add", ALIASNAME_ELAN_RG_WLAN, sLanVid);
			sprintf(v_eth_name, "%s.%d", ALIASNAME_ELAN_RG_WLAN, LanVid);
			break;
#endif
	}
	va_cmd(BRCTL, 3, 1, "addif", ALIASNAME_BR0, v_eth_name);
	va_cmd(IFCONFIG, 2, 1, v_eth_name, "up");
	return 0;
}

int flush_vconfig(unsigned short LanVid, int LanPortIdx)
{
	char v_eth_name[32] = {0};
	char sLanVid[16] = {0};
	unsigned char value[6] = {0};
	sprintf(sLanVid, "%d", LanVid);
	switch(LanPortIdx)
	{
		case 0:
			sprintf(v_eth_name, "%s.%d", ALIASNAME_ELAN0, LanVid);
			va_cmd(VCONFIG, 2, 1, "rem", v_eth_name);
			break;
		case 1:
			sprintf(v_eth_name, "%s.%d", ALIASNAME_ELAN1, LanVid);
			va_cmd(VCONFIG, 2, 1, "rem", v_eth_name);
			break;
		case 2:
			sprintf(v_eth_name, "%s.%d", ALIASNAME_ELAN2, LanVid);
			va_cmd(VCONFIG, 2, 1, "rem", v_eth_name);
			break;
		case 3:
			sprintf(v_eth_name, "%s.%d", ALIASNAME_ELAN3, LanVid);
			va_cmd(VCONFIG, 2, 1, "rem", v_eth_name);
#ifdef WLAN_SUPPORT
		case 4:
			//add this for normal path. (To protocol stack.)
			sprintf(v_eth_name, "%s.%d", ALIASNAME_WLAN0, LanVid);
			va_cmd(VCONFIG, 2, 1, "rem", v_eth_name);
			//add this for forwarding engine
			sprintf(v_eth_name, "%s.%d", ALIASNAME_ELAN_RG_WLAN, LanVid);
			va_cmd(VCONFIG, 2, 1, "rem", v_eth_name);
			break;
#endif
			break;
	}
	//va_cmd(BRCTL, 3, 1, "delif", ALIASNAME_BR0, v_eth_name);
	//va_cmd(IFCONFIG, 2, 1, v_eth_name, "down");
	return 0;
}
#ifdef CONFIG_RTL867X_VLAN_MAPPING
int RG_add_vlanBinding(MIB_CE_ATM_VC_Tp pEntry,int pairID, unsigned short LanVid, int LanPortIdx)
{
	rtk_rg_vlanBinding_t vlanBind;
	MIB_CE_PORT_BINDING_T pbEntry;
	int rg_bind_idx=-1;
	int omci_service=-1;
	int omci_bind=-1;
	int omci_mode=-1;
	int wanIntfIdx=-1;
	char cmdStr[64];
	char vlan_based_pri=-1;
	rtk_rg_intfInfo_t *intf_info = NULL;
	rtk_rg_wanIntfConf_t *wan_info_p = NULL;

	printf("%s-%d Entered!\n",__func__,__LINE__);

#if defined(CONFIG_USER_LAN_PORT_AS_ETH_WAN)
	int ethPhyPortId = -1;
	mib_get(MIB_ETH_WAN_PORT_PHY_INDEX, &ethPhyPortId);

	if (ethPhyPortId != -1 && RG_get_lan_phyPortId(LanPortIdx) == ethPhyPortId)
	{
		printf("%s-%d ethPhyPortId = %d\n",__func__,__LINE__, ethPhyPortId);
		return -1;
	}
#endif

	intf_info = (rtk_rg_intfInfo_t *)malloc(sizeof(rtk_rg_intfInfo_t));
	if(intf_info == NULL){
		printf("%s-%d Can't get enough memory space!\n",__func__,__LINE__);
		return -1;
	}
	memset(intf_info,0,sizeof(rtk_rg_intfInfo_t));
	wanIntfIdx = pEntry->rg_wan_idx;
	if(rtk_rg_intfInfo_find(intf_info,&wanIntfIdx)!=SUCCESS){
		printf("%s-%d Can't find the wan interface idx:%d!",__func__,__LINE__,pEntry->rg_wan_idx);
		free(intf_info);;
		return -1;
	}

	if (wanIntfIdx != pEntry->rg_wan_idx ){
		printf("%s-%d Can't find the wan interface idx:%d!",__func__,__LINE__,pEntry->rg_wan_idx);
		free(intf_info);;
		return -1;
	}
	
	wan_info_p = &(intf_info->wan_intf.wan_intf_conf);
	//wan_info_p->port_binding_mask.portmask = (entryVC.itfGroup & 0xf);
	//wan_info_p->wlan0_dev_binding_mask = ((entryVC.itfGroup & 0x1f0) >> 4);
	//wan_info_p->forcedAddNewIntf = 0;
	memset(&vlanBind,0,sizeof(rtk_rg_vlanBinding_t));
#ifdef WLAN_SUPPORT
	if(LanPortIdx <= PMAP_ETH0_SW3)
#endif
		vlanBind.port_idx = RG_get_lan_phyPortId(LanPortIdx);
#ifdef WLAN_SUPPORT
	else
		vlanBind.port_idx = RG_get_wlan_phyPortId(LanPortIdx);
#endif
	vlanBind.ingress_vid=LanVid;
	vlanBind.wan_intf_idx=pEntry->rg_wan_idx;
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	setup_vconfig(LanVid, LanPortIdx);
#endif
	mib_chain_get(MIB_PORT_BINDING_TBL, LanPortIdx, (void*)&pbEntry);
	//AUG_PRT("LanPortIdx=%d, LanVid=%d, rg_wan_idx=%d\n",LanPortIdx,LanVid,pEntry->rg_wan_idx);
	if(rtk_rg_vlanBinding_add(&vlanBind,&rg_bind_idx)!= SUCCESS){
		DBPRINT(1, "%s-%d rtk_rg_vlanBinding_add fail\n",__func__,__LINE__);
		free(intf_info);;
		return -1;
	}
#ifdef CONFIG_GPON_FEATURE
	//sync omci wan info......
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	if(pEntry->applicationtype & (X_CT_SRV_INTERNET|X_CT_SRV_SPECIAL_SERVICE_ALL)){
		omci_service = 1;
	}
	else{
		omci_service = 0;
	}
#else
	if(wan_info_p->none_internet)
		omci_service = 0;
	else
		omci_service = 1;
#endif
	//if((wan_info_p->port_binding_mask.portmask > 0) || (wan_info_p->wlan0_dev_binding_mask > 0))
		omci_bind = 1;
	//else
	//	omci_bind = 0;

	//omci wan info can't write duplicate, must delete it before adding.
	fprintf(stderr, "%s-%d sync waninfo with OMCI!\n",__func__,__LINE__);
	snprintf(cmdStr, sizeof(cmdStr),"echo %d %d %d %d %d %d %d > %s",pEntry->rg_wan_idx,0,0,0,0,0,0,OMCI_WAN_INFO);
	system(cmdStr);
	switch(pEntry->cmode){
			case CHANNEL_MODE_IPOE:
					if( (pEntry->IpProtocol == IPVER_IPV4_IPV6) && pEntry->napt ==1)
							omci_mode = OMCI_MODE_IPOE_V4NAPT_V6;
					else
							omci_mode = OMCI_MODE_IPOE;
					break;
			case CHANNEL_MODE_PPPOE:
					if( (pEntry->IpProtocol == IPVER_IPV4_IPV6) && pEntry->napt ==1)
							omci_mode = OMCI_MODE_PPPOE_V4NAPT_V6;
					else
							omci_mode = OMCI_MODE_PPPOE;
					break;
			case CHANNEL_MODE_BRIDGE:
					omci_mode = OMCI_MODE_BRIDGE;
					break;
			default:
					printf("unknow mode %d\n",omci_mode);
					break;
	}
	if(pEntry->vprio)
	{
		vlan_based_pri = pEntry->vprio-1;

	}
	else
	{
		vlan_based_pri = -1;
	}
#ifdef CONFIG_TR142_MODULE
	char ifname[IFNAMSIZ] = {0};
	ifGetName(PHY_INTF(pEntry->ifIndex), ifname, sizeof(ifname));
	snprintf(cmdStr, sizeof(cmdStr)-1,"echo %d %s %s %d > %s", pEntry->rg_wan_idx, ALIASNAME_NAS0, ifname, omci_bind, TR142_WAN_IDX_MAP);	
	system(cmdStr);
#endif	
	fprintf(stderr, "%s-%d sync waninfo with OMCI!\n",__func__,__LINE__);
	snprintf(cmdStr, sizeof(cmdStr),"echo %d %d %d %d %d %d %d > %s",pEntry->rg_wan_idx,wan_info_p->egress_vlan_id,wan_info_p->vlan_based_pri,omci_mode,omci_service,omci_bind,1,OMCI_WAN_INFO);
	system(cmdStr);
	//fprintf(stderr, "%s-%d %s\n",__func__,__LINE__,cmdStr);
#endif

	switch(pairID)
	{
		case 0:
			pbEntry.rg_vlan0_entryID = rg_bind_idx;
			break;
		case 1:
			pbEntry.rg_vlan1_entryID = rg_bind_idx;
			break;
		case 2:
			pbEntry.rg_vlan2_entryID = rg_bind_idx;
			break;
		case 3:
			pbEntry.rg_vlan3_entryID = rg_bind_idx;
			break;
		default:
			printf("%s-%d wrong pair id=%d\n",__func__,__LINE__,pairID);
	}
	mib_chain_update(MIB_PORT_BINDING_TBL,(void*)&pbEntry, LanPortIdx);
	free(intf_info);;
	return SUCCESS;
}
int RG_flush_vlanBinding(int LanPortIdx)
{
	rtk_rg_vlanBinding_t vlanBind;
	int totalPortbd,port;
	int valid_idx;
	MIB_CE_PORT_BINDING_T pbEntry;

#if defined(CONFIG_USER_LAN_PORT_AS_ETH_WAN)
	int ethPhyPortId = -1;
	mib_get(MIB_ETH_WAN_PORT_PHY_INDEX, &ethPhyPortId);

	if (ethPhyPortId != -1 && RG_get_lan_phyPortId(LanPortIdx) == ethPhyPortId)
	{
		printf("%s-%d ethPhyPortId = %d\n",__func__,__LINE__, ethPhyPortId);
		return -1;
	}
#endif

	memset(&vlanBind,0,sizeof(rtk_rg_vlanBinding_t));
		//get the number 'LanPortIdx' pbentry!
		mib_chain_get(MIB_PORT_BINDING_TBL, LanPortIdx, (void*)&pbEntry);
		//is it vlan-mapping lan-port?
		if((unsigned char)VLAN_BASED_MODE == pbEntry.pb_mode){
			struct v_pair *vid_pair;
			int k;
			vid_pair = (struct v_pair *)&pbEntry.pb_vlan0_a;
			// because there are only 4 pairs~
			for (k=0; k<4; k++)
			{
				//Be sure the content of vlan-mapping exsit!
				if (vid_pair[k].vid_a)
				{
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
					flush_vconfig(vid_pair[k].vid_a,LanPortIdx);
#endif
					if(rtk_rg_vlanBinding_del(vid_pair[k].rg_vbind_entryID)!= SUCCESS){
						DBPRINT(1, "%s-%d rtk_rg_vlanBinding_del fail\n",__func__,__LINE__);
						return -1;
					}
					vid_pair[k].rg_vbind_entryID = 0;
				}
			}
			mib_chain_update(MIB_PORT_BINDING_TBL,(void*)&pbEntry, LanPortIdx);
		}
	return 0;
}
#else
#if defined(CONFIG_00R0) && defined(CONFIG_USER_BRIDGE_GROUPING)

int RG_add_vlanBinding(MIB_CE_ATM_VC_Tp pEntry, int pairID, unsigned short LanVid, int LanPortIdx)
{
	rtk_rg_vlanBinding_t vlanBind;
	MIB_CE_PORT_BINDING_T pbEntry;
	int rg_bind_idx = -1;
	int omci_service = -1;
	int omci_bind = -1;
	int omci_mode = -1;
	char cmdStr[64] = {0};
	char vlan_based_pri = -1;
	rtk_rg_intfInfo_t *intf_info = NULL;
	rtk_rg_wanIntfConf_t *wan_info_p = NULL;

#if defined(CONFIG_USER_LAN_PORT_AS_ETH_WAN)
	int ethPhyPortId = -1;
	mib_get(MIB_ETH_WAN_PORT_PHY_INDEX, &ethPhyPortId);
	
	if (ethPhyPortId != -1 && RG_get_lan_phyPortId(LanPortIdx) == ethPhyPortId)
	{
		printf("%s-%d ethPhyPortId = %d\n",__func__,__LINE__, ethPhyPortId);
		return -1;
	}
#endif

	intf_info = (rtk_rg_intfInfo_t *)malloc(sizeof(rtk_rg_intfInfo_t));
	if (intf_info == NULL) {
		printf("%s-%d Can't get enough memory space!\n", __func__,__LINE__);
		return -1;
	}
	memset(intf_info, 0, sizeof(rtk_rg_intfInfo_t));
	if (rtk_rg_intfInfo_find(intf_info, &pEntry->rg_wan_idx) != SUCCESS) {
		printf("%s-%d Can't find the wan interface idx:%d!", __func__, __LINE__, pEntry->rg_wan_idx);
		free(intf_info);
		return -1;
	}

	wan_info_p = &(intf_info->wan_intf.wan_intf_conf);

	memset(&vlanBind, 0, sizeof(rtk_rg_vlanBinding_t));

	if (LanPortIdx <= PMAP_ETH0_SW3)
		vlanBind.port_idx = RG_get_lan_phyPortId(LanPortIdx);
	else
		vlanBind.port_idx = RG_get_wlan_phyPortId(LanPortIdx);

	vlanBind.ingress_vid = LanVid;
	vlanBind.wan_intf_idx = pEntry->rg_wan_idx;
	setup_vconfig(LanVid, LanPortIdx);
	mib_chain_get(MIB_PORT_BINDING_TBL, LanPortIdx, (void*)&pbEntry);

	if (rtk_rg_vlanBinding_add(&vlanBind, &rg_bind_idx) != SUCCESS) {
		DBPRINT(1, "%s-%d rtk_rg_vlanBinding_add fail\n", __func__, __LINE__);
		free(intf_info);
		return -1;
	}
#ifdef CONFIG_GPON_FEATURE
	if (wan_info_p->none_internet)
		omci_service = 0;
	else
		omci_service = 1;

	// this WAN with VLAN binding
	omci_bind = 1;

#if ! defined(_LINUX_2_6_) && defined(CONFIG_TR142_MODULE)
	if(omci_bind != check_wan_omci_portbing(pEntry)) 
	{
#endif
	//omci wan info can't write duplicate, must delete it before adding.
	snprintf(cmdStr, sizeof(cmdStr), "echo %d %d %d %d %d %d %d > %s", pEntry->rg_wan_idx, 0, 0, 0, 0, 0, 0, OMCI_WAN_INFO);
	system(cmdStr);
	switch (pEntry->cmode) {
		case CHANNEL_MODE_IPOE:
			omci_mode = 1;
			break;
		case CHANNEL_MODE_BRIDGE:
			omci_mode = 2;
			break;
		case CHANNEL_MODE_PPPOE:
			omci_mode = 0;
			break;
		default:
			printf("unknow mode %d\n", omci_mode);
			break;
	}

	if (pEntry->vprio)
		vlan_based_pri = pEntry->vprio - 1;
	else
		vlan_based_pri = -1;
#if ! defined(_LINUX_2_6_) && defined(CONFIG_TR142_MODULE)
	char ifname[IFNAMSIZ] = {0};
	ifGetName(PHY_INTF(pEntry->ifIndex), ifname, sizeof(ifname));
	snprintf(cmdStr, sizeof(cmdStr)-1,"echo %d %s %s %d > %s", pEntry->rg_wan_idx, ALIASNAME_NAS0, ifname, omci_bind, TR142_WAN_IDX_MAP);
	system(cmdStr);
#endif
	snprintf(cmdStr, sizeof(cmdStr), "echo %d %d %d %d %d %d %d > %s", pEntry->rg_wan_idx, wan_info_p->egress_vlan_id, wan_info_p->vlan_based_pri, omci_mode, omci_service, omci_bind, 1, OMCI_WAN_INFO);
	system(cmdStr);
#if ! defined(_LINUX_2_6_) && defined(CONFIG_TR142_MODULE)
	}
#endif
#endif
	switch (pairID)
	{
		case 0:
			pbEntry.rg_vlan0_entryID = rg_bind_idx;
			break;
		case 1:
			pbEntry.rg_vlan1_entryID = rg_bind_idx;
			break;
		case 2:
			pbEntry.rg_vlan2_entryID = rg_bind_idx;
			break;
		case 3:
			pbEntry.rg_vlan3_entryID = rg_bind_idx;
			break;
		default:
			printf("%s-%d wrong pair id=%d\n", __func__, __LINE__, pairID);
	}
	mib_chain_update(MIB_PORT_BINDING_TBL, (void*)&pbEntry, LanPortIdx);
	free(intf_info);
	return SUCCESS;
}

int RG_flush_vlanBinding(int LanPortIdx)
{
	rtk_rg_vlanBinding_t vlanBind;
	MIB_CE_PORT_BINDING_T pbEntry;
	struct v_pair *vid_pair;
	int k = 0;

#if defined(CONFIG_USER_LAN_PORT_AS_ETH_WAN)
	int ethPhyPortId = -1;
	mib_get(MIB_ETH_WAN_PORT_PHY_INDEX, &ethPhyPortId);
	
	if (ethPhyPortId != -1 && RG_get_lan_phyPortId(LanPortIdx) == ethPhyPortId)
	{
		printf("%s-%d ethPhyPortId = %d\n",__func__,__LINE__, ethPhyPortId);
		return -1;
	}
#endif

	memset(&vlanBind, 0, sizeof(rtk_rg_vlanBinding_t));

	mib_chain_get(MIB_PORT_BINDING_TBL, LanPortIdx, (void*)&pbEntry);

	vid_pair = (struct v_pair *)&pbEntry.pb_vlan0_a;

	for (k = 0; k < 4; k ++)
	{
		if (vid_pair[k].vid_a)
		{
			flush_vconfig(vid_pair[k].vid_a, LanPortIdx);
			if (rtk_rg_vlanBinding_del(vid_pair[k].rg_vbind_entryID) != SUCCESS) {
				DBPRINT(1, "%s-%d rtk_rg_vlanBinding_del fail\n", __func__, __LINE__);
				return -1;
			}
			vid_pair[k].rg_vbind_entryID = 0;
		}
	}
	mib_chain_update(MIB_PORT_BINDING_TBL, (void*)&pbEntry, LanPortIdx);

	return 0;
}
#endif
#endif

void RTK_RG_gatewayService_add()
{
	rtk_rg_gatewayServicePortEntry_t serviceEntry;
	unsigned int totalVoIPCfgEntry = 0;
#ifdef CONFIG_USER_RTK_VOIP
	voipCfgParam_t VoipEntry;
	voipCfgParam_t *pCfg = NULL;
	voipCfgPortParam_t *VoIPport;
#endif
	int ret, i=0, index;
	//int port_service_num[] = {53, 123, 5060, 67}; //DNS, SNTP, SIP, DHCP server port
	int port_service_num[] = {53, 123, 67, 1701}; //DNS, SNTP, DHCP, L2TP
	int port_service_num_server[] = {5060, 2944}; //SIP, H248
	FILE *fp;
	int port;


	if(!(fp = fopen(RG_GATEWAY_SERVICE_FILE, "a")))
	{
		fprintf(stderr, "Open %s failed! %s\n", RG_GATEWAY_SERVICE_FILE, strerror(errno));
	}

	for(i=0; i<(sizeof(port_service_num)/sizeof(port_service_num[0])); i++){
		serviceEntry.valid = 1;
		serviceEntry.port_num = port_service_num[i];
		serviceEntry.type = GATEWAY_CLIENT_SERVICE;

		if((ret = rtk_rg_gatewayServicePortRegister_add(&serviceEntry, &index)) == 0)
			fprintf(fp, "%d\n", index);
		else
			DBPRINT(1, "%s idx %d ret = %d rtk_rg_gatewayServicePortRegister_add failed!\n", __FUNCTION__, i, ret);
	}
	
	for(i=0; i<(sizeof(port_service_num_server)/sizeof(port_service_num_server[0])); i++){
		serviceEntry.valid = 1;
		serviceEntry.port_num = port_service_num_server[i];
		serviceEntry.type = GATEWAY_SERVER_SERVICE;

		if((ret = rtk_rg_gatewayServicePortRegister_add(&serviceEntry, &index)) == 0)
			fprintf(fp, "%d\n", index);
		else
			DBPRINT(1, "%s idx %d ret = %d rtk_rg_gatewayServicePortRegister_add failed!\n", __FUNCTION__, i, ret);
	}

#ifdef CONFIG_USER_CWMP_TR069
	//Add TR-069 http server
	mib_get(CWMP_CONREQ_PORT, &port);
	serviceEntry.valid = 1;
	serviceEntry.port_num = port;
	serviceEntry.type = GATEWAY_SERVER_SERVICE;
	if((ret = rtk_rg_gatewayServicePortRegister_add(&serviceEntry, &index)) == 0)
			fprintf(fp, "%d\n", index);
	else
		DBPRINT(1, "%s: add cwmp port via rtk_rg_gatewayServicePortRegister_add failed! ret = %d!\n", __FUNCTION__, ret);
#endif
#ifdef CONFIG_USER_RTK_VOIP
	//Add RTP, RTCP, T38 server
	totalVoIPCfgEntry = mib_chain_total(MIB_VOIP_CFG_TBL);
	if( totalVoIPCfgEntry > 0 ) {
		if(mib_chain_get(MIB_VOIP_CFG_TBL, 0, (void*)&VoipEntry)) {
			pCfg = &VoipEntry;
		}else {
			fprintf(stderr, "[%s %d]read voip config fail.\n",__FUNCTION__,__LINE__);
		}
	}else {
		fprintf(stderr, "[%s %d]flash do no have voip configuration.\n",__FUNCTION__,__LINE__);
	}

	if (pCfg)
	{
		VoIPport = &pCfg->ports[0];
		for(i=0; i<=4; i++) {
			serviceEntry.valid = 1;
			serviceEntry.port_num = VoIPport->media_port+i;
			serviceEntry.type = GATEWAY_SERVER_SERVICE;		
			if((ret = rtk_rg_gatewayServicePortRegister_add(&serviceEntry, &index)) == 0)
					fprintf(fp, "%d\n", index);
			else
				DBPRINT(1, "%s: add cwmp port via rtk_rg_gatewayServicePortRegister_add failed! ret = %d!\n", __FUNCTION__, ret);
		}
	}
#endif
	fclose(fp);
}

void Flush_RTK_RG_gatewayService()
{
	rtk_rg_gatewayServicePortEntry_t serviceEntry;
	int i=0;
	FILE *fp;

	if(!(fp = fopen(RG_GATEWAY_SERVICE_FILE, "r")))
	{
		fprintf(stderr, "Open %s failed! %s\n", RG_GATEWAY_SERVICE_FILE, strerror(errno));
	}


	while(fscanf(fp, "%d\n", &i) != EOF)
	{
		if(rtk_rg_gatewayServicePortRegister_find(&serviceEntry, &i) == RT_ERR_OK && serviceEntry.valid)
		{
			if(rtk_rg_gatewayServicePortRegister_del(i))
				DBPRINT(1, "rtk_rg_gatewayServicePortRegister_del failed! idx = %d\n", i);
		}
	}

	fclose(fp);
	unlink(RG_GATEWAY_SERVICE_FILE);

}
#if 1
void RTK_Setup_Storm_Control(void)
{
	int portId;
	int portNum;
	unsigned int meterId;
	rtk_switch_devInfo_t	tDevInfo;
	rtk_rate_storm_group_ctrl_t	stormCtrl;
	rtk_rg_switch_deviceInfo_get (&tDevInfo);
	meterId  = tDevInfo.capacityInfo.max_num_of_metering - 1;
        #ifdef CONFIG_RTL9600_SERIES
                rtk_rg_rate_shareMeterMode_set (meterId, METER_MODE_BIT_RATE);
                rtk_rg_rate_shareMeter_set (meterId, 7000, DISABLED);
        #else
                rtk_rg_rate_shareMeterMode_set (meterId, METER_MODE_PACKET_RATE);
                rtk_rg_rate_shareMeter_set (meterId, 7000, DISABLED);
        #endif
	rtk_rg_rate_stormControlEnable_get(&stormCtrl);
	stormCtrl.unknown_unicast_enable = ENABLED;
	stormCtrl.broadcast_enable = ENABLED;
	stormCtrl.unknown_multicast_enable  = ENABLED;
	rtk_rg_rate_stormControlEnable_set (&stormCtrl);
#if defined(CONFIG_PON_LED_PROFILE_DEMO_RTL9607) || defined(CONFIG_PON_LED_PROFILE_DEMO_RTL9607_IAD_V00) || defined(CONFIG_PON_LED_PROFILE_DEMO_RTL9607_IAD_V01)
	portNum = 4; //0,1,2,3  4(wan)
#elif defined(CONFIG_PON_LED_PROFILE_DEMO_RTL9602B) || defined(CONFIG_RTL9602C_SERIES)
	portNum = 2; //0,1  2(wan)
#else
	portNum = 4; // non-pon platform (8696)
#endif
	//AUG_PRT("%s-%d portNum=%d\n",__func__,__LINE__,portNum);

	/*portId for all LAN + WAN port*/
	for(portId = 0 ; portId <= portNum; portId ++)
	{
		rtk_rg_rate_stormControlMeterIdx_set(portId, STORM_GROUP_UNKNOWN_UNICAST, meterId);
		rtk_rg_rate_stormControlMeterIdx_set (portId, STORM_GROUP_BROADCAST, meterId);
		rtk_rg_rate_stormControlMeterIdx_set (portId, STORM_GROUP_UNKNOWN_MULTICAST, meterId);
		rtk_rg_rate_stormControlPortEnable_set (portId, STORM_GROUP_UNKNOWN_UNICAST, ENABLED);
		rtk_rg_rate_stormControlPortEnable_set (portId, STORM_GROUP_BROADCAST, ENABLED);
		rtk_rg_rate_stormControlPortEnable_set (portId, STORM_GROUP_UNKNOWN_MULTICAST, ENABLED);
	}



}
#endif

#if defined(CONFIG_E8B)
//if the second IPv6 WAN is DHCPv6 WAN and default gw is disable, 
//we need to add acl to trap packet that the IPv6 address belong to DHCPv6 WAN
#ifdef CONFIG_IPV6
int RTK_RG_ACL_Add_DHCP_WAN_IPV6(int wan_idx, unsigned char *ipaddr)
{
	int aclIdx = 0, ret = 0, wan_index = 0;
	char filename[64] = {0};
	FILE *fp = NULL;
	rtk_rg_intfInfo_t intf_info;
	rtk_rg_aclFilterAndQos_t aclRule;
	unsigned char zeroipaddr[16]={0};

	RTK_RG_ACL_Del_DHCP_WAN_IPV6(wan_idx);
	
	sprintf(filename, "%s_%d", RG_DHCP_TRAP_ACL_RULES_FILE, wan_idx);
	if (!(fp = fopen(filename, "w"))) {
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -2;
	}

	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));

	aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	aclRule.action_type = ACL_ACTION_TYPE_TRAP;
	aclRule.filter_fields = INGRESS_IPV6_DIP_BIT | INGRESS_PORT_BIT;
	aclRule.filter_fields |= INGRESS_IPV6_TAGIF_BIT;
	aclRule.ingress_ipv6_tagif = 1;

	if(memcmp(ipaddr, &zeroipaddr, 16)!=0){
		memcpy(aclRule.ingress_dest_ipv6_addr, ipaddr, IPV6_ADDR_LEN);
		memset(aclRule.ingress_dest_ipv6_addr_mask, 255, IPV6_ADDR_LEN);
		aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();

		if ((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0) {
			fprintf(fp, "%d\n", aclIdx);
		}
		else {
			printf("[%s@%d] RTK_RG_ACL_Add_DHCP_WAN_IPV6 QoS rule failed! (ret = %d)\n", __FUNCTION__, __LINE__, ret);
			fclose(fp);
			return -1;
		}
	}

	fclose(fp);
	return 0;
}

int RTK_RG_ACL_Del_DHCP_WAN_IPV6(int wan_idx)
{
	FILE *fp = NULL;
	int aclIdx = -1;
	char filename[64] = {0};

	sprintf(filename, "%s_%d", RG_DHCP_TRAP_ACL_RULES_FILE, wan_idx);
	if (!(fp = fopen(filename, "r"))) {
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -2;
	}

	while (fscanf(fp, "%d\n", &aclIdx) != EOF)
	{
		if (rtk_rg_aclFilterAndQos_del(aclIdx))
			DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", aclIdx);
	}
	fclose(fp);
	unlink(filename);
	return 0;
}
#endif
#endif

#if defined(CONFIG_00R0) && defined(CONFIG_USER_RTK_VOIP)
int RG_add_voip_sip_1p_Qos(int sip_port,int pri_num)
{

	FILE *fp;

	rtk_rg_aclFilterAndQos_t acl_filter;
	int acl_filter_idx;
	int cpu_port;
	memset(&acl_filter,0,sizeof(acl_filter));

	RG_del_voip_sip_1p_Acl();

	if(!(fp = fopen(RG_VOIP_SIP_1P_FILE, "a")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -2;
	}
	printf("RG_add_voip_sip_1p_Qos sip port %d, pri %d\n",sip_port,pri_num);

	acl_filter.filter_fields = (INGRESS_PORT_BIT|INGRESS_L4_SPORT_RANGE_BIT);
	cpu_port=(1<<RTK_RG_PORT_CPU);

//	printf("(1<<RTK_RG_PORT_CPU) is %d\n",(1<<RTK_RG_PORT_CPU));

	acl_filter.ingress_port_mask.portmask = cpu_port;


	acl_filter.ingress_src_l4_port_start=sip_port;
	acl_filter.ingress_src_l4_port_end=sip_port;

	acl_filter.action_type=ACL_ACTION_TYPE_QOS;

	acl_filter.qos_actions=ACL_ACTION_1P_REMARKING_BIT;
	acl_filter.action_dot1p_remarking_pri=pri_num;

	if(rtk_rg_aclFilterAndQos_add(&acl_filter, &acl_filter_idx)==0)
		fprintf(fp, "%d\n", acl_filter_idx);
	else
		printf("Set RG_add_voip_sip_1p_Qos failed!\n");

	fclose(fp);
	return 0;


}


int RG_add_voip_rtp_1p_Qos(int start_port,int end_port, int pri_num)
{

	FILE *fp;

	rtk_rg_aclFilterAndQos_t acl_filter;
	int acl_filter_idx;
	int cpu_port;
	memset(&acl_filter,0,sizeof(acl_filter));

	RG_del_voip_rtp_1p_Acl();

	if(!(fp = fopen(RG_VOIP_RTP_1P_FILE, "a")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -2;
	}
	printf("RG_add_voip_rtp_1p_Qos rtp port %d, pri %d\n",start_port,pri_num);

	acl_filter.filter_fields = (INGRESS_PORT_BIT|INGRESS_L4_SPORT_RANGE_BIT);
	cpu_port=(1<<RTK_RG_PORT_CPU);

	acl_filter.ingress_port_mask.portmask = cpu_port;


	acl_filter.ingress_src_l4_port_start=start_port;
	acl_filter.ingress_src_l4_port_end=end_port;

	acl_filter.action_type=ACL_ACTION_TYPE_QOS;

	acl_filter.qos_actions=ACL_ACTION_1P_REMARKING_BIT;
	acl_filter.action_dot1p_remarking_pri=pri_num;

	if(rtk_rg_aclFilterAndQos_add(&acl_filter, &acl_filter_idx)==0)
		fprintf(fp, "%d\n", acl_filter_idx);
	else
		printf("Set RG_add_voip_rtp_1p_Qos failed!\n");

	fclose(fp);
	return 0;


}


int RG_del_voip_sip_1p_Acl()
{
	FILE *fp;
	int aclIdx=-1;
	if(!(fp = fopen(RG_VOIP_SIP_1P_FILE, "r"))){
		return -2;
	}
	while(fscanf(fp, "%d\n", &aclIdx) != EOF)
	{
		if(rtk_rg_aclFilterAndQos_del(aclIdx))
			DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", aclIdx);
	}
	fclose(fp);
	unlink(RG_VOIP_SIP_1P_FILE);
	return 0;
}

int RG_del_voip_rtp_1p_Acl()
{
	FILE *fp;
	int aclIdx=-1;
	if(!(fp = fopen(RG_VOIP_RTP_1P_FILE, "r"))){
		return -2;
	}
	while(fscanf(fp, "%d\n", &aclIdx) != EOF)
	{
		if(rtk_rg_aclFilterAndQos_del(aclIdx))
			DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", aclIdx);
	}
	fclose(fp);
	unlink(RG_VOIP_RTP_1P_FILE);
	return 0;
}

void enlargeBW(int enable)
{
	if(enable == 1 ){
		rtk_rg_ponmac_bwThreshold_set(13, 14);	
	}
	else if(enable ==0){
		rtk_rg_ponmac_bwThreshold_set(9, 10);	
	}
}

int checkSolForSmallBW()
{
	//For solution of APOLLO+Small BW
	FILE *fp_smallbw = NULL;
	char cmd[100]={0};

	if(!(fp_smallbw = fopen(smallbw_fpath, "r"))) {
		fprintf(stderr, "ERROR! for open %s %s\n",smallbw_fpath, strerror(errno));
	}
	else{
		int small_bw_setting=-1;
		fscanf(fp_smallbw, "%d", &small_bw_setting);

		printf("small_bw_setting=%d\n",small_bw_setting);
		if(small_bw_setting==1){
			fclose(fp_smallbw);
			printf("Have hardware solution for small BW! Do Nothing!\n");
			return 1;
		}
		fclose(fp_smallbw);
	}		
	printf("Don't have hardware solution for small BW!\n");
	return 0;
}
#endif

#if defined(CONFIG_RTL9607C_SERIES) || defined(CONFIG_LUNA_G3_SERIES)
void RTK_RG_Control_Packet_Ingress_ACL_Rule_set(void)
{
	unsigned char ip6Addr[IP6_ADDR_LEN]={0}, mask[IP6_ADDR_LEN]={0};
	char MCAST_ADDR[MAC_ADDR_LEN]={0x01,0x00,0x5E,0x00,0x00,0x00};
	char MCAST_MASK[MAC_ADDR_LEN]={0xff,0xff,0xff,0x00,0x00,0x00};
	char UCAST_MASK[MAC_ADDR_LEN]={0xff,0xff,0xff,0xff,0xff,0xff};
	char acsurl[256] = {0}, ITMS_Server[256] = {0};
	unsigned char ipv4_ip[IP_ADDR_LEN] = {0};
	unsigned int lan_ip_address;
	struct in_addr ITMS_Server_Address;
	rtk_rg_aclFilterAndQos_t aclRule;
	MIB_CE_ATM_VC_T vcEntry;
	struct in_addr lan_ip;
	int i,aclIdx=0, ret;
	int vcTotal=-1;
	char cmdStr[64];
	FILE *fp;

	if(!(fp = fopen(RG_INGRESS_CONTROL_PACKET_ACL_RULES_FILE, "a")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return;
	}

	/* ARP */
	// LAN
	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	aclRule.acl_weight = RG_FIREWALL_ACL_WEIGHT;
	aclRule.filter_fields |= INGRESS_PORT_BIT;
	aclRule.ingress_port_mask.portmask = RG_get_all_lan_phyPortMask();
	aclRule.action_trap_with_priority = 7;
	// DMAC = ELAN_MAC_ADDR
	aclRule.filter_fields |= INGRESS_DMAC_BIT;
	mib_get(MIB_ELAN_MAC_ADDR, (void *)&aclRule.ingress_dmac);
	memcpy(&aclRule.ingress_dmac_mask,UCAST_MASK,MAC_ADDR_LEN);	
	aclRule.filter_fields |= INGRESS_ETHERTYPE_BIT;
	aclRule.ingress_ethertype = 0x0806;
	aclRule.ingress_ethertype_mask = 0xffff;
	aclRule.action_type = ACL_ACTION_TYPE_TRAP_WITH_PRIORITY;
	if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0) {
		fprintf(fp, "%d\n", aclIdx);
	} else {
		printf("[%s@%d] rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n",__func__,__LINE__, ret);
	}

	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	aclRule.acl_weight = RG_FIREWALL_ACL_WEIGHT;
	aclRule.filter_fields |= INGRESS_PORT_BIT;
	aclRule.ingress_port_mask.portmask = RG_get_all_lan_phyPortMask();
	aclRule.action_trap_with_priority = 7;
	// DMAC = ff:ff:ff:ff:ff:ff
	aclRule.filter_fields |= INGRESS_DMAC_BIT;
	memcpy(&aclRule.ingress_dmac,UCAST_MASK,MAC_ADDR_LEN);
	memcpy(&aclRule.ingress_dmac_mask,UCAST_MASK,MAC_ADDR_LEN);
	aclRule.filter_fields |= INGRESS_ETHERTYPE_BIT;
	aclRule.ingress_ethertype = 0x0806;
	aclRule.ingress_ethertype_mask = 0xffff;
	aclRule.action_type = ACL_ACTION_TYPE_TRAP_WITH_PRIORITY;
	if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0) {
		fprintf(fp, "%d\n", aclIdx);
	} else {
		printf("[%s@%d] rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n",__func__,__LINE__, ret);
	}
	
	// WAN
	vcTotal = mib_chain_total(MIB_ATM_VC_TBL);
	for(i=0 ; i<vcTotal ; i++) {		
		if (!mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&vcEntry))
			continue;
		
		if(vcEntry.cmode == CHANNEL_MODE_BRIDGE)
			continue;
		
		memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
		aclRule.acl_weight = RG_FIREWALL_ACL_WEIGHT;
		aclRule.filter_fields |= INGRESS_PORT_BIT;
		aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();
		aclRule.action_trap_with_priority = 7;
		aclRule.filter_fields |= INGRESS_DMAC_BIT;
		memcpy(&aclRule.ingress_dmac,vcEntry.MacAddr,MAC_ADDR_LEN);
		memcpy(&aclRule.ingress_dmac_mask,UCAST_MASK,MAC_ADDR_LEN);		
		aclRule.filter_fields |= INGRESS_ETHERTYPE_BIT;
		aclRule.ingress_ethertype = 0x0806;
		aclRule.ingress_ethertype_mask = 0xffff;
		aclRule.action_type = ACL_ACTION_TYPE_TRAP_WITH_PRIORITY;
		if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0) {
			fprintf(fp, "%d\n", aclIdx);
		} else {
			printf("[%s@%d] rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n",__func__,__LINE__, ret);
		}
	}

	/* DHCP */
	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	aclRule.acl_weight = RG_FIREWALL_ACL_WEIGHT;
	aclRule.filter_fields |= INGRESS_PORT_BIT;
	aclRule.ingress_port_mask.portmask = (RG_get_wan_phyPortMask() | RG_get_all_lan_phyPortMask());
	aclRule.action_trap_with_priority = 7;
	aclRule.filter_fields |= INGRESS_L4_UDP_BIT;
	aclRule.filter_fields |= INGRESS_L4_SPORT_RANGE_BIT;
	aclRule.ingress_src_l4_port_start = 67;
	aclRule.ingress_src_l4_port_end = 68;
	aclRule.filter_fields |= INGRESS_IPV4_TAGIF_BIT;
	aclRule.ingress_ipv4_tagif = 1;
	aclRule.action_type = ACL_ACTION_TYPE_TRAP_WITH_PRIORITY;
	if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0) {
		fprintf(fp, "%d\n", aclIdx);
	} else {
		printf("[%s@%d] rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n",__func__,__LINE__, ret);
	}

	/* DHCPv6 */
	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	aclRule.acl_weight = RG_FIREWALL_ACL_WEIGHT;
	aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	aclRule.filter_fields |= INGRESS_PORT_BIT;
	aclRule.ingress_port_mask.portmask = (RG_get_wan_phyPortMask() | RG_get_all_lan_phyPortMask());
	aclRule.action_trap_with_priority = 7;
	aclRule.filter_fields |= INGRESS_ETHERTYPE_BIT;
	aclRule.ingress_ethertype = 0x86dd;//ipv6
	aclRule.filter_fields |= INGRESS_IPV6_TAGIF_BIT;
	aclRule.ingress_ipv6_tagif = 1;
	aclRule.filter_fields |= INGRESS_L4_SPORT_RANGE_BIT;
	aclRule.ingress_src_l4_port_start = 547;
	aclRule.ingress_src_l4_port_end = 547;
	aclRule.filter_fields |= INGRESS_L4_DPORT_RANGE_BIT;
	aclRule.ingress_dest_l4_port_start = 546;
	aclRule.ingress_dest_l4_port_end = 546;
	aclRule.action_type = ACL_ACTION_TYPE_TRAP_WITH_PRIORITY;
	if((ret = rtk_rg_aclFilterAndQos_add(&aclRule,&aclIdx)) == 0)
		fprintf(fp, "%d\n", aclIdx);
	else
		printf("rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n", ret);

	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	aclRule.acl_weight = RG_FIREWALL_ACL_WEIGHT;
	aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	aclRule.filter_fields |= INGRESS_PORT_BIT;
	aclRule.ingress_port_mask.portmask = (RG_get_wan_phyPortMask() | RG_get_all_lan_phyPortMask());
	aclRule.action_trap_with_priority = 7;
	aclRule.filter_fields |= INGRESS_ETHERTYPE_BIT;
	aclRule.ingress_ethertype = 0x86dd;//ipv6
	aclRule.filter_fields |= INGRESS_IPV6_TAGIF_BIT;
	aclRule.ingress_ipv6_tagif = 1;
	aclRule.filter_fields |= INGRESS_L4_SPORT_RANGE_BIT;
	aclRule.ingress_src_l4_port_start = 546;
	aclRule.ingress_src_l4_port_end = 546;
	aclRule.filter_fields |= INGRESS_L4_DPORT_RANGE_BIT;
	aclRule.ingress_dest_l4_port_start = 547;
	aclRule.ingress_dest_l4_port_end = 547;
	aclRule.action_type = ACL_ACTION_TYPE_TRAP_WITH_PRIORITY;
	if((ret = rtk_rg_aclFilterAndQos_add(&aclRule,&aclIdx)) == 0)
		fprintf(fp, "%d\n", aclIdx);
	else
		printf("rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n", ret);

	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	aclRule.acl_weight = RG_FIREWALL_ACL_WEIGHT;
	//NS ff02::1:ff00:0/104, trap to protocol stack
	aclRule.filter_fields |= INGRESS_PORT_BIT;
	aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();
	aclRule.action_trap_with_priority = 7;
	aclRule.filter_fields |= INGRESS_IPV6_TAGIF_BIT | INGRESS_IPV6_DIP_BIT;
	inet_pton(PF_INET6, "ff02::1:ff00:0",(void *)ip6Addr);
	memcpy(aclRule.ingress_dest_ipv6_addr, ip6Addr, IPV6_ADDR_LEN);
	inet_pton(PF_INET6, "ffff:ffff:ffff:ffff:ffff:ffff:ff00:0",(void *)mask);
	memcpy(aclRule.ingress_dest_ipv6_addr_mask, mask, IPV6_ADDR_LEN);
	aclRule.ingress_ipv6_tagif = 1;
	aclRule.filter_fields |= INGRESS_L4_ICMPV6_BIT;
	aclRule.action_type = ACL_ACTION_TYPE_TRAP_WITH_PRIORITY;
	if((ret = rtk_rg_aclFilterAndQos_add(&aclRule,&aclIdx)) == 0)
	{
		fprintf(fp, "%d\n", aclIdx);
	}else
		printf("Add ACl Rule for ff02::1:ff00:0/104 (Neighbor Solictaion) Successfully error ret=%d\n",ret);

	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	aclRule.acl_weight = RG_FIREWALL_ACL_WEIGHT;
	//ff02::1 , trap to protocol stack
	aclRule.filter_fields |= INGRESS_PORT_BIT;	
	aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();
	aclRule.action_trap_with_priority = 7;
	aclRule.filter_fields |= INGRESS_IPV6_DIP_BIT;
	inet_pton(PF_INET6, "ff02::1",(void *)ip6Addr);
	memcpy(aclRule.ingress_dest_ipv6_addr, ip6Addr, IPV6_ADDR_LEN);
	inet_pton(PF_INET6, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",(void *)mask);
	memcpy(aclRule.ingress_dest_ipv6_addr_mask, mask, IPV6_ADDR_LEN);
	aclRule.filter_fields |= INGRESS_IPV6_TAGIF_BIT;
	aclRule.ingress_ipv6_tagif = 1;
	aclRule.filter_fields |= INGRESS_L4_ICMPV6_BIT;	
	aclRule.action_type = ACL_ACTION_TYPE_TRAP_WITH_PRIORITY;	
	if((ret = rtk_rg_aclFilterAndQos_add(&aclRule,&aclIdx)) == 0)
	{
		fprintf(fp, "%d\n", aclIdx);
	}else
		printf("Add ACl Rule for ff02::1 (Router Advertisement) Successfully error ret=%d\n",ret);
	
	/* PPPoE */
	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	aclRule.acl_weight = RG_FIREWALL_ACL_WEIGHT;
	aclRule.filter_fields |= INGRESS_PORT_BIT;
	aclRule.ingress_port_mask.portmask = (RG_get_wan_phyPortMask() | RG_get_all_lan_phyPortMask());
	aclRule.action_trap_with_priority = 7;
	aclRule.filter_fields |= INGRESS_ETHERTYPE_BIT;
	aclRule.ingress_ethertype = 0x8863;
	aclRule.ingress_ethertype_mask = 0xffff;
	aclRule.action_type = ACL_ACTION_TYPE_TRAP_WITH_PRIORITY;
	if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0) {
		fprintf(fp, "%d\n", aclIdx);
	} else {
		printf("[%s@%d] rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n",__func__,__LINE__, ret);
	}

	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	aclRule.acl_weight = RG_FIREWALL_ACL_WEIGHT;
	aclRule.filter_fields |= INGRESS_PORT_BIT;
	aclRule.ingress_port_mask.portmask = (RG_get_wan_phyPortMask() | RG_get_all_lan_phyPortMask());
	aclRule.action_trap_with_priority = 7;
	aclRule.filter_fields |= INGRESS_ETHERTYPE_BIT;
	aclRule.ingress_ethertype = 0x8864;
	aclRule.ingress_ethertype_mask = 0xffff;
	aclRule.filter_fields |= INGRESS_IPV4_TAGIF_BIT;
	aclRule.ingress_ipv4_tagif = 0;
	aclRule.filter_fields |= INGRESS_IPV6_TAGIF_BIT;
	aclRule.ingress_ipv6_tagif = 0;
	aclRule.action_type = ACL_ACTION_TYPE_TRAP_WITH_PRIORITY;
	if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0) {
		fprintf(fp, "%d\n", aclIdx);
	} else {
		printf("[%s@%d] rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n",__func__,__LINE__, ret);
	}

	/* HTTP */
	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	aclRule.acl_weight = RG_FIREWALL_ACL_WEIGHT;
	aclRule.filter_fields |= INGRESS_PORT_BIT;
	aclRule.ingress_port_mask.portmask = RG_get_all_lan_phyPortMask();
	aclRule.action_trap_with_priority = 7;
	aclRule.filter_fields |= INGRESS_L4_TCP_BIT;
	aclRule.filter_fields |= INGRESS_L4_DPORT_RANGE_BIT;
#if CONFIG_YUEME
	aclRule.ingress_dest_l4_port_start = 8080;
	aclRule.ingress_dest_l4_port_end = 8080;
#else
	aclRule.ingress_dest_l4_port_start = 80;
	aclRule.ingress_dest_l4_port_end = 80;
#endif
	aclRule.filter_fields |= INGRESS_IPV4_DIP_RANGE_BIT;
	mib_get(MIB_ADSL_LAN_IP, (void *)&lan_ip);
	aclRule.ingress_dest_ipv4_addr_start = aclRule.ingress_dest_ipv4_addr_end = *((ipaddr_t *)&lan_ip.s_addr);
	aclRule.filter_fields |= INGRESS_IPV4_TAGIF_BIT;
	aclRule.ingress_ipv4_tagif = 1;
	aclRule.action_type = ACL_ACTION_TYPE_TRAP_WITH_PRIORITY;
	if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0) {
		fprintf(fp, "%d\n", aclIdx);
	} else {
		printf("[%s@%d] rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n",__func__,__LINE__, ret);
	}

	/* IGMP */
#if 1
	system("/bin/echo 7 > /proc/rg/assign_igmp_priority");
#else
	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	aclRule.filter_fields |= INGRESS_PORT_BIT;
	aclRule.ingress_port_mask.portmask = RG_get_all_lan_phyPortMask();
	aclRule.action_trap_with_priority = 7;
	aclRule.filter_fields |= INGRESS_DMAC_BIT;
	memcpy(&aclRule.ingress_dmac,MCAST_ADDR,MAC_ADDR_LEN);
	memcpy(&aclRule.ingress_dmac_mask,MCAST_MASK,MAC_ADDR_LEN);
	/*aclRule.filter_fields |= INGRESS_L4_POROTCAL_VALUE_BIT;
	aclRule.ingress_l4_protocal = 0x2;*/
	aclRule.filter_fields |= INGRESS_IPV4_TAGIF_BIT;
	aclRule.ingress_ipv4_tagif = 1;
	aclRule.action_type = ACL_ACTION_TYPE_TRAP_WITH_PRIORITY;
	if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0) {
		fprintf(fp, "%d\n", aclIdx);
	} else {
		printf("[%s@%d] rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n",__func__,__LINE__, ret);
	}
#endif

	/* TR069 */
	if(!mib_get(CWMP_ACS_URL, (void*)acsurl))
	{
		fprintf(stderr, "<%s %d> Get mib value CWMP_ACS_URL failed!\n",__func__,__LINE__);
		return;
	}
	
	set_endpoint(ITMS_Server, acsurl);
	if(isIPAddr(ITMS_Server) && (inet_pton(AF_INET, ITMS_Server, &ITMS_Server_Address) == 1))
	{
		memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
		aclRule.acl_weight = RG_FIREWALL_ACL_WEIGHT;
		aclRule.filter_fields |= INGRESS_PORT_BIT;
		aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();
		aclRule.action_trap_with_priority = 7;
		aclRule.filter_fields |= INGRESS_IPV4_SIP_RANGE_BIT;
		memcpy(&aclRule.ingress_src_ipv4_addr_start, &ITMS_Server_Address, IP_ADDR_LEN);
		memcpy(&aclRule.ingress_src_ipv4_addr_end, &ITMS_Server_Address, IP_ADDR_LEN);
		aclRule.filter_fields |= INGRESS_IPV4_TAGIF_BIT;
		aclRule.ingress_ipv4_tagif = 1;
		aclRule.action_type = ACL_ACTION_TYPE_TRAP_WITH_PRIORITY;		
		if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0) {
			fprintf(fp, "%d\n", aclIdx);
		} else {
			printf("[%s@%d] rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n",__func__,__LINE__, ret);
		}
	}
	
	#ifdef CONFIG_USER_RTK_VOIP
	/* VoIP */
	unsigned int totalVoIPCfgEntry = 0;
	voipCfgParam_t VoipEntry;
	voipCfgParam_t *pCfg = NULL;
	voipCfgPortParam_t *VoIPport;
	totalVoIPCfgEntry = mib_chain_total(MIB_VOIP_CFG_TBL);
	if( totalVoIPCfgEntry > 0 ) {
		if(mib_chain_get(MIB_VOIP_CFG_TBL, 0, (void*)&VoipEntry)) {
			pCfg = &VoipEntry;
		}else {
			fprintf(stderr, "[%s %d]read voip config fail.\n",__FUNCTION__,__LINE__);
		}
	}else {
		fprintf(stderr, "[%s %d]flash do no have voip configuration.\n",__FUNCTION__,__LINE__);
	}
	if (pCfg)
	{
		VoIPport = &pCfg->ports[0];
		memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
		aclRule.acl_weight = RG_FIREWALL_ACL_WEIGHT;
		aclRule.filter_fields |= INGRESS_PORT_BIT;
		aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();
		aclRule.action_trap_with_priority = 7;
		aclRule.filter_fields |= INGRESS_L4_DPORT_RANGE_BIT;
		aclRule.ingress_dest_l4_port_start = VoIPport->sip_port;
		aclRule.ingress_dest_l4_port_end = VoIPport->sip_port;
		aclRule.filter_fields |= INGRESS_IPV4_TAGIF_BIT;
		aclRule.ingress_ipv4_tagif = 1;
		aclRule.action_type = ACL_ACTION_TYPE_TRAP_WITH_PRIORITY;		
		if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0) {
			fprintf(fp, "%d\n", aclIdx);
		} else {
			printf("[%s@%d] rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n",__func__,__LINE__, ret);
		}

		memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
		aclRule.acl_weight = RG_FIREWALL_ACL_WEIGHT;
		aclRule.filter_fields |= INGRESS_PORT_BIT;
		aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();
		aclRule.action_trap_with_priority = 7;
		aclRule.filter_fields |= INGRESS_L4_DPORT_RANGE_BIT;
		aclRule.ingress_dest_l4_port_start = VoIPport->media_port;
		aclRule.ingress_dest_l4_port_end = VoIPport->media_port+50;
		aclRule.filter_fields |= INGRESS_IPV4_TAGIF_BIT;
		aclRule.ingress_ipv4_tagif = 1;
		aclRule.action_type = ACL_ACTION_TYPE_TRAP_WITH_PRIORITY;		
		if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0) {
			fprintf(fp, "%d\n", aclIdx);
		} else {
			printf("[%s@%d] rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n",__func__,__LINE__, ret);
		}
	}
	#endif /* CONFIG_USER_RTK_VOIP */
	
	fclose(fp);
}

void RTK_RG_Control_Packet_Egress_ACL_Rule_set(void)
{
	char MCAST_ADDR[MAC_ADDR_LEN]={0x01,0x00,0x5E,0x00,0x00,0x00};
	char MCAST_MASK[MAC_ADDR_LEN]={0xff,0xff,0xff,0x00,0x00,0x00};
	char acsurl[256] = {0}, ITMS_Server[256] = {0};
	struct in_addr ITMS_Server_Address;
	rtk_rg_aclFilterAndQos_t aclRule;
	struct in_addr lan_ip;
	int i,aclIdx=0, ret;
	FILE *fp;
	
	if(!(fp = fopen(RG_EGRESS_CONTROL_PACKET_ACL_RULES_FILE, "a")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return;
	}

	/* ARP */
	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	aclRule.acl_weight = RG_FIREWALL_ACL_WEIGHT;
	aclRule.filter_fields |= INGRESS_PORT_BIT;
	aclRule.ingress_port_mask.portmask = RTK_RG_ALL_MAC_CPU_PORTMASK;
	aclRule.filter_fields |= INGRESS_ETHERTYPE_BIT;
	aclRule.ingress_ethertype = 0x0806;
	aclRule.ingress_ethertype_mask = 0xffff;	
	aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	aclRule.action_type = ACL_ACTION_TYPE_QOS;
	aclRule.qos_actions = ACL_ACTION_ACL_PRIORITY_BIT;
	aclRule.action_acl_priority = 7;
	if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0) {
		fprintf(fp, "%d\n", aclIdx);
	} else {
		printf("[%s@%d] rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n",__func__,__LINE__, ret);
	}

	/* DHCP */
	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	aclRule.acl_weight = RG_FIREWALL_ACL_WEIGHT;
	aclRule.filter_fields |= INGRESS_PORT_BIT;
	aclRule.ingress_port_mask.portmask = RTK_RG_ALL_MAC_CPU_PORTMASK;
	aclRule.filter_fields |= INGRESS_L4_UDP_BIT;
	aclRule.filter_fields |= INGRESS_L4_SPORT_RANGE_BIT;
	aclRule.ingress_src_l4_port_start = 67;
	aclRule.ingress_src_l4_port_end = 68;
	aclRule.filter_fields |= INGRESS_IPV4_TAGIF_BIT;
	aclRule.ingress_ipv4_tagif = 1;
	aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	aclRule.action_type = ACL_ACTION_TYPE_QOS;
	aclRule.qos_actions = ACL_ACTION_ACL_PRIORITY_BIT;
	aclRule.action_acl_priority = 7;
	if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0) {
		fprintf(fp, "%d\n", aclIdx);
	} else {
		printf("[%s@%d] rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n",__func__,__LINE__, ret);
	}

	/* DHCPv6 */
	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	aclRule.filter_fields |= INGRESS_PORT_BIT;
	aclRule.ingress_port_mask.portmask = RTK_RG_ALL_MAC_CPU_PORTMASK;
	aclRule.filter_fields |= INGRESS_ETHERTYPE_BIT;
	aclRule.ingress_ethertype = 0x86dd;//ipv6
	aclRule.filter_fields |= INGRESS_IPV6_TAGIF_BIT;
	aclRule.ingress_ipv6_tagif = 1;
	aclRule.filter_fields |= INGRESS_L4_SPORT_RANGE_BIT;
	aclRule.ingress_src_l4_port_start = 546;
	aclRule.ingress_src_l4_port_end = 546;
	aclRule.filter_fields |= INGRESS_L4_DPORT_RANGE_BIT;
	aclRule.ingress_dest_l4_port_start = 547;
	aclRule.ingress_dest_l4_port_end = 547;
	aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	aclRule.action_type = ACL_ACTION_TYPE_QOS;
	aclRule.qos_actions = ACL_ACTION_ACL_PRIORITY_BIT;
	aclRule.action_acl_priority = 7;
	if((ret = rtk_rg_aclFilterAndQos_add(&aclRule,&aclIdx)) == 0)
		fprintf(fp, "%d\n", aclIdx);
	else
		printf("rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n", ret);

	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	aclRule.filter_fields |= INGRESS_PORT_BIT;
	aclRule.ingress_port_mask.portmask = RTK_RG_ALL_MAC_CPU_PORTMASK;
	aclRule.filter_fields |= INGRESS_ETHERTYPE_BIT;
	aclRule.ingress_ethertype = 0x86dd;//ipv6
	aclRule.filter_fields |= INGRESS_IPV6_TAGIF_BIT;
	aclRule.ingress_ipv6_tagif = 1;
	aclRule.filter_fields |= INGRESS_L4_SPORT_RANGE_BIT;
	aclRule.ingress_src_l4_port_start = 547;
	aclRule.ingress_src_l4_port_end = 547;
	aclRule.filter_fields |= INGRESS_L4_DPORT_RANGE_BIT;
	aclRule.ingress_dest_l4_port_start = 546;
	aclRule.ingress_dest_l4_port_end = 546;
	aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	aclRule.action_type = ACL_ACTION_TYPE_QOS;
	aclRule.qos_actions = ACL_ACTION_ACL_PRIORITY_BIT;
	aclRule.action_acl_priority = 7;
	if((ret = rtk_rg_aclFilterAndQos_add(&aclRule,&aclIdx)) == 0)
		fprintf(fp, "%d\n", aclIdx);
	else
		printf("rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n", ret);

	/* PPPoE */
	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	aclRule.acl_weight = RG_FIREWALL_ACL_WEIGHT;
	aclRule.filter_fields |= INGRESS_PORT_BIT;
	aclRule.ingress_port_mask.portmask = RTK_RG_ALL_MAC_CPU_PORTMASK;
	aclRule.filter_fields |= INGRESS_ETHERTYPE_BIT;
	aclRule.ingress_ethertype = 0x8860;
	aclRule.ingress_ethertype_mask = 0xfff0;	
	aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	aclRule.action_type = ACL_ACTION_TYPE_QOS;
	aclRule.qos_actions = ACL_ACTION_ACL_PRIORITY_BIT;
	aclRule.action_acl_priority = 7;
	if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0) {
		fprintf(fp, "%d\n", aclIdx);
	} else {
		printf("[%s@%d] rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n",__func__,__LINE__, ret);
	}

	/* HTTP */
	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	aclRule.acl_weight = RG_FIREWALL_ACL_WEIGHT;
	aclRule.filter_fields |= INGRESS_PORT_BIT;
	aclRule.ingress_port_mask.portmask = RTK_RG_ALL_MAC_CPU_PORTMASK;
	aclRule.filter_fields |= INGRESS_L4_TCP_BIT;
	aclRule.filter_fields |= INGRESS_L4_SPORT_RANGE_BIT;
#if CONFIG_YUEME
	aclRule.ingress_src_l4_port_start = 8080;
	aclRule.ingress_src_l4_port_end = 8080;
#else
	aclRule.ingress_src_l4_port_start = 80;
	aclRule.ingress_src_l4_port_end = 80;
#endif
	aclRule.filter_fields |= INGRESS_IPV4_SIP_RANGE_BIT;
	mib_get(MIB_ADSL_LAN_IP, (void *)&lan_ip);
	aclRule.ingress_src_ipv4_addr_start = aclRule.ingress_src_ipv4_addr_end = *((ipaddr_t *)&lan_ip.s_addr);
	aclRule.filter_fields |= INGRESS_IPV4_TAGIF_BIT;
	aclRule.ingress_ipv4_tagif = 1;
	aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	aclRule.action_type = ACL_ACTION_TYPE_QOS;
	aclRule.qos_actions = ACL_ACTION_ACL_PRIORITY_BIT;
	aclRule.action_acl_priority = 7;
	if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0) {
		fprintf(fp, "%d\n", aclIdx);
	} else {
		printf("[%s@%d] rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n",__func__,__LINE__, ret);
	}

	/* IGMP */
	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	aclRule.acl_weight = RG_FIREWALL_ACL_WEIGHT;
	aclRule.filter_fields |= INGRESS_PORT_BIT;
	aclRule.ingress_port_mask.portmask = RTK_RG_ALL_MAC_CPU_PORTMASK;
	aclRule.filter_fields |= INGRESS_DMAC_BIT;
	memcpy(&aclRule.ingress_dmac,MCAST_ADDR,MAC_ADDR_LEN);
	memcpy(&aclRule.ingress_dmac_mask,MCAST_MASK,MAC_ADDR_LEN);
	aclRule.filter_fields |= INGRESS_L4_POROTCAL_VALUE_BIT;
	aclRule.ingress_l4_protocal = 0x2;
	aclRule.filter_fields |= INGRESS_IPV4_TAGIF_BIT;
	aclRule.ingress_ipv4_tagif = 1;
	aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	aclRule.action_type = ACL_ACTION_TYPE_QOS;
	aclRule.qos_actions = ACL_ACTION_ACL_PRIORITY_BIT;
	aclRule.action_acl_priority = 7;
	if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0) {
		fprintf(fp, "%d\n", aclIdx);
	} else {
		printf("[%s@%d] rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n",__func__,__LINE__, ret);
	}

	/* TR069 */
	if(!mib_get(CWMP_ACS_URL, (void*)acsurl))
	{
		fprintf(stderr, "<%s %d> Get mib value CWMP_ACS_URL failed!\n",__func__,__LINE__);
		return;
	}
	
	set_endpoint(ITMS_Server, acsurl);
	if(isIPAddr(ITMS_Server) && (inet_pton(AF_INET, ITMS_Server, &ITMS_Server_Address) == 1))
	{
		memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
		aclRule.acl_weight = RG_FIREWALL_ACL_WEIGHT;
		aclRule.filter_fields |= INGRESS_PORT_BIT;
		aclRule.ingress_port_mask.portmask = RTK_RG_ALL_MAC_CPU_PORTMASK;
		aclRule.filter_fields |= INGRESS_IPV4_DIP_RANGE_BIT;
		memcpy(&aclRule.ingress_dest_ipv4_addr_start, &ITMS_Server_Address, IP_ADDR_LEN);
		memcpy(&aclRule.ingress_dest_ipv4_addr_end, &ITMS_Server_Address, IP_ADDR_LEN);
		aclRule.filter_fields |= INGRESS_IPV4_TAGIF_BIT;
		aclRule.ingress_ipv4_tagif = 1;
		aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
		aclRule.action_type = ACL_ACTION_TYPE_QOS;
		aclRule.qos_actions = ACL_ACTION_ACL_PRIORITY_BIT;
		aclRule.action_acl_priority = 7;
		if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0) {
			fprintf(fp, "%d\n", aclIdx);
		} else {
			printf("[%s@%d] rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n",__func__,__LINE__, ret);
		}
	}

	#ifdef CONFIG_USER_RTK_VOIP
	/* VoIP */
	unsigned int totalVoIPCfgEntry = 0;
	voipCfgParam_t VoipEntry;
	voipCfgParam_t *pCfg = NULL;
	voipCfgPortParam_t *VoIPport;
	totalVoIPCfgEntry = mib_chain_total(MIB_VOIP_CFG_TBL);
	if( totalVoIPCfgEntry > 0 ) {
		if(mib_chain_get(MIB_VOIP_CFG_TBL, 0, (void*)&VoipEntry)) {
			pCfg = &VoipEntry;
		}else {
			fprintf(stderr, "[%s %d]read voip config fail.\n",__FUNCTION__,__LINE__);
		}
	}else {
		fprintf(stderr, "[%s %d]flash do no have voip configuration.\n",__FUNCTION__,__LINE__);
	}
	if (pCfg)
	{
		VoIPport = &pCfg->ports[0];
		memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
		aclRule.acl_weight = RG_FIREWALL_ACL_WEIGHT;
		aclRule.filter_fields |= INGRESS_PORT_BIT;
		aclRule.ingress_port_mask.portmask = RTK_RG_ALL_MAC_CPU_PORTMASK;
		aclRule.filter_fields |= INGRESS_L4_UDP_BIT;
		aclRule.filter_fields |= INGRESS_L4_SPORT_RANGE_BIT;
		aclRule.ingress_src_l4_port_start = VoIPport->sip_port;
		aclRule.ingress_src_l4_port_end = VoIPport->sip_port;
		aclRule.filter_fields |= INGRESS_IPV4_TAGIF_BIT;
		aclRule.ingress_ipv4_tagif = 1;
		aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
		aclRule.action_type = ACL_ACTION_TYPE_QOS;
		aclRule.qos_actions = ACL_ACTION_ACL_PRIORITY_BIT;
		aclRule.action_acl_priority = 7;
		if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0) {
			fprintf(fp, "%d\n", aclIdx);
		} else {
			printf("[%s@%d] rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n",__func__,__LINE__, ret);
		}

		memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
		aclRule.acl_weight = RG_FIREWALL_ACL_WEIGHT;
		aclRule.filter_fields |= INGRESS_PORT_BIT;
		aclRule.ingress_port_mask.portmask = RTK_RG_ALL_MAC_CPU_PORTMASK;
		aclRule.filter_fields |= INGRESS_L4_UDP_BIT;
		aclRule.filter_fields |= INGRESS_L4_SPORT_RANGE_BIT;
		aclRule.ingress_src_l4_port_start = VoIPport->media_port;
		aclRule.ingress_src_l4_port_end = VoIPport->media_port+50;
		aclRule.filter_fields |= INGRESS_IPV4_TAGIF_BIT;
		aclRule.ingress_ipv4_tagif = 1;
		aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
		aclRule.action_type = ACL_ACTION_TYPE_QOS;
		aclRule.qos_actions = ACL_ACTION_ACL_PRIORITY_BIT;
		aclRule.action_acl_priority = 7;
		if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0) {
			fprintf(fp, "%d\n", aclIdx);
		} else {
			printf("[%s@%d] rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n",__func__,__LINE__, ret);
		}
	}
	#endif /* CONFIG_USER_RTK_VOIP */

	fclose(fp);
}

void RTK_RG_Control_Packet_ITMS_Ingress_ACL_Rule_flush(void)
{
	FILE *fp;
	int aclIdx;

	if(!(fp = fopen(RG_INGRESS_CONTROL_ITMS_PACKET_ACL_RULES_FILE, "r")))
		return;

	while(fscanf(fp, "%d\n", &aclIdx) != EOF)
	{
		if(rtk_rg_aclFilterAndQos_del(aclIdx))
			DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", aclIdx);
	}
	
	fclose(fp);
	unlink(RG_INGRESS_CONTROL_ITMS_PACKET_ACL_RULES_FILE);
	return;
}

void RTK_RG_Control_Packet_ITMS_Ingress_ACL_Rule_set(void)
{
	char acsurl[256] = {0}, ITMS_Server[256] = {0};
	struct in_addr ITMS_Server_Address;
	rtk_rg_aclFilterAndQos_t aclRule;
	struct in_addr lan_ip;
	struct hostent *host;
	struct in_addr acsaddr;
	int i,aclIdx=0, ret;
	FILE *fp;
	
	if(!(fp = fopen(RG_INGRESS_CONTROL_ITMS_PACKET_ACL_RULES_FILE, "a")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return;
	}
	
	/* TR069 */
	if(!mib_get(CWMP_ACS_URL, (void*)acsurl))
	{
		fprintf(stderr, "<%s %d> Get mib value CWMP_ACS_URL failed!\n",__func__,__LINE__);
		fclose(fp);
		return;
	}
	
	set_endpoint(ITMS_Server, acsurl);

	if(!isIPAddr(ITMS_Server)) {
		if(!(host = gethostbyname(ITMS_Server)))
		{
			fprintf(stderr, "ACS URL gethostbyname failed!\n");
			fclose(fp);
			return;
		}

		memcpy((char *) &(acsaddr.s_addr), host->h_addr_list[0], host->h_length);
		strcpy(ITMS_Server, inet_ntoa(acsaddr));
	}
	
	if(isIPAddr(ITMS_Server) && (inet_pton(AF_INET, ITMS_Server, &ITMS_Server_Address) == 1))
	{
		memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
		aclRule.acl_weight = RG_FIREWALL_ACL_WEIGHT;
		aclRule.filter_fields |= INGRESS_PORT_BIT;
		aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();
		aclRule.action_trap_with_priority = 7;
		aclRule.filter_fields |= INGRESS_IPV4_SIP_RANGE_BIT;
		memcpy(&aclRule.ingress_src_ipv4_addr_start, &ITMS_Server_Address, IP_ADDR_LEN);
		memcpy(&aclRule.ingress_src_ipv4_addr_end, &ITMS_Server_Address, IP_ADDR_LEN);
		aclRule.filter_fields |= INGRESS_IPV4_TAGIF_BIT;
		aclRule.ingress_ipv4_tagif = 1;
		aclRule.action_type = ACL_ACTION_TYPE_TRAP_WITH_PRIORITY;		
		if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0) {
			fprintf(fp, "%d\n", aclIdx);
		} else {
			printf("[%s@%d] rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n",__func__,__LINE__, ret);
		}
	}

	fclose(fp);
}

void RTK_RG_Control_Packet_ITMS_Egress_ACL_Rule_flush(void)
{
	FILE *fp;
	int aclIdx;

	if(!(fp = fopen(RG_EGRESS_CONTROL_ITMS_PACKET_ACL_RULES_FILE, "r")))
		return;

	while(fscanf(fp, "%d\n", &aclIdx) != EOF)
	{
		if(rtk_rg_aclFilterAndQos_del(aclIdx))
			DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", aclIdx);
	}

	fclose(fp);
	unlink(RG_EGRESS_CONTROL_ITMS_PACKET_ACL_RULES_FILE);
	return;
}

void RTK_RG_Control_Packet_ITMS_Egress_ACL_Rule_set(void)
{
	char acsurl[256] = {0}, ITMS_Server[256] = {0};
	struct in_addr ITMS_Server_Address;
	rtk_rg_aclFilterAndQos_t aclRule;
	struct in_addr lan_ip;
	struct hostent *host;
	struct in_addr acsaddr;
	int i,aclIdx=0, ret;
	FILE *fp;
	
	if(!(fp = fopen(RG_EGRESS_CONTROL_ITMS_PACKET_ACL_RULES_FILE, "a")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return;
	}
	
	/* TR069 */
	if(!mib_get(CWMP_ACS_URL, (void*)acsurl))
	{
		fprintf(stderr, "<%s %d> Get mib value CWMP_ACS_URL failed!\n",__func__,__LINE__);
		fclose(fp);
		return;
	}
	
	set_endpoint(ITMS_Server, acsurl);

	if(!isIPAddr(ITMS_Server)) {
		if(!(host = gethostbyname(ITMS_Server)))
		{
			fprintf(stderr, "ACS URL gethostbyname failed!\n");
			fclose(fp);
			return;
		}

		memcpy((char *) &(acsaddr.s_addr), host->h_addr_list[0], host->h_length);
		strcpy(ITMS_Server, inet_ntoa(acsaddr));
	}
	
	if(isIPAddr(ITMS_Server) && (inet_pton(AF_INET, ITMS_Server, &ITMS_Server_Address) == 1))
	{
		memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
		aclRule.acl_weight = RG_FIREWALL_ACL_WEIGHT;
		aclRule.filter_fields |= INGRESS_PORT_BIT;
		aclRule.ingress_port_mask.portmask = RTK_RG_ALL_MAC_CPU_PORTMASK;
		aclRule.filter_fields |= INGRESS_IPV4_DIP_RANGE_BIT;
		memcpy(&aclRule.ingress_dest_ipv4_addr_start, &ITMS_Server_Address, IP_ADDR_LEN);
		memcpy(&aclRule.ingress_dest_ipv4_addr_end, &ITMS_Server_Address, IP_ADDR_LEN);
		aclRule.filter_fields |= INGRESS_IPV4_TAGIF_BIT;
		aclRule.ingress_ipv4_tagif = 1;
		aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
		aclRule.action_type = ACL_ACTION_TYPE_QOS;
		aclRule.qos_actions = ACL_ACTION_ACL_PRIORITY_BIT;
		aclRule.action_acl_priority = 7;
		if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0) {
			fprintf(fp, "%d\n", aclIdx);
		} else {
			printf("[%s@%d] rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n",__func__,__LINE__, ret);
		}
	}

	fclose(fp);
}

void RTK_RG_add_TCP_syn_rate_limit( void )
{
	system("/bin/echo 31 > /proc/rg/assign_syn_share_meter");
	if(rtk_rg_shareMeter_set(31, 3000, RTK_RG_ENABLED) != RT_ERR_RG_OK)
	{
		AUG_PRT(" rtk_rg_shareMeter_set fail !\n");
	}
}

void RTK_RG_add_ARP_broadcast_rate_limit( void )
{
	system("/bin/echo 0x20 > /proc/rg/ArpReq_rate_limit_portMask");
	system("/bin/echo 30 > /proc/rg/ArpReq_rate_limit");
	if(rtk_rg_shareMeter_set(30, 56, RTK_RG_ENABLED) != RT_ERR_RG_OK)
	{
		AUG_PRT(" rtk_rg_shareMeter_set fail !\n");
	}
}
#endif

void check_cvlan(void)
{
	MIB_CE_ATM_VC_T Entry;
	int vcTotal, i, ret;
	rtk_rg_cvlan_info_t cvlan_info;

	vcTotal = mib_chain_total(MIB_ATM_VC_TBL);
	for (i = 0; i < vcTotal; i++)
	{
		memset(&cvlan_info, 0x0, sizeof(rtk_rg_cvlan_info_t));
			if (!mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&Entry))
				return -1;

		if (Entry.enable == 0)
			continue;
		dump_cvlan(Entry.vid);
	}

}

void dump_cvlan(int vid)
{
	rtk_rg_cvlan_info_t cvlan_info;
	memset(&cvlan_info, 0x0, sizeof(rtk_rg_cvlan_info_t));
	
	cvlan_info.vlanId = vid;
	rtk_rg_cvlan_get(&cvlan_info);	
	AUG_PRT("cvlan_info.vlanId=%d\n",cvlan_info.vlanId);
	AUG_PRT("cvlan_info.memberPortMask.portmask=%x\n",cvlan_info.memberPortMask.portmask);
	AUG_PRT("cvlan_info.untagPortMask.portmask=%x\n",cvlan_info.untagPortMask.portmask);
#ifdef CONFIG_MASTER_WLAN0_ENABLE
	AUG_PRT("cvlan_info.wlan0DevMask=%x\n",cvlan_info.wlan0DevMask);
	AUG_PRT("cvlan_info.wlan0UntagMask=%x\n",cvlan_info.wlan0UntagMask);
#endif
	AUG_PRT("cvlan_info.vlan_based_pri_enable=%d\n",cvlan_info.vlan_based_pri_enable);
	AUG_PRT("cvlan_info.vlan_based_pri=%d\n",cvlan_info.vlan_based_pri);

}

//return value: wan's VID
//vcEntry: deleted atm vc entry.
int reset_unbinded_port_vlan(MIB_CE_ATM_VC_T *vcEntry)
{
	MIB_CE_ATM_VC_T Entry;
	int vcTotal, i, ret;
	unsigned int firstBrVid = -1;
	unsigned short itfGroup = 0;
	unsigned short unbinded_portMask = 0;
	unsigned short enable = 0, tmp = 0;
	int isFoundFirstBr = 0;
	unsigned char mbtd;
	unsigned char devicetype = 0;
	mib_get(MIB_DEVICE_TYPE, (void *)&devicetype);

	if ( devicetype == 2 ){
		printf("Hybrid mode, bypass %s\n", __FUNCTION__);
		return 0;
	}	
	
	if(vcEntry != NULL)
	{
		if(vcEntry->cmode != CHANNEL_MODE_BRIDGE)
			return 0;
	}
	vcTotal = mib_chain_total(MIB_ATM_VC_TBL);

	for (i = 0; i < vcTotal; i++)
	{
		if (!mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&Entry))
				return -1;

		if (Entry.enable == 0)
			continue;

		if(Entry.cmode == CHANNEL_MODE_BRIDGE && (Entry.applicationtype&X_CT_SRV_INTERNET) && isFoundFirstBr==0) {
			isFoundFirstBr = 1;
			firstBrVid = Entry.vid;
		}
		itfGroup |= Entry.itfGroup;		
	}
	//reset vconfig
//AUG_PRT("firstBrVid=%d,vcEntry.cmode=%d vcEntry.vid=%d\n",firstBrVid,vcEntry->cmode,vcEntry->vid);

	//get unbinded port mask
	if(isFoundFirstBr)
	{
		for(i=0;i<=PMAP_ETH0_SW3;i++)
		{
			tmp = (itfGroup >> i) & 1;
			if(tmp == 0){
	//AUG_PRT("flush_vconfig:%d,ubinded port:%d",firstBrVid,i);
				flush_vconfig(firstBrVid,i);
			}
		}
	}
	mib_get(MIB_MAC_BASED_TAG_DECISION, (void *)&mbtd);
	if(!mbtd && isFoundFirstBr)
	{
		//reset unbind lan member ship.
		rtk_rg_cvlan_info_t cvlan_info;
		memset(&cvlan_info, 0x0, sizeof(rtk_rg_cvlan_info_t));
		cvlan_info.vlanId=firstBrVid;
		rtk_rg_cvlan_get(&cvlan_info);
#ifdef CONFIG_RTL9602C_SERIES
		cvlan_info.memberPortMask.portmask &= ~(RG_get_lan_phyPortMask(0x3));
#else
		cvlan_info.memberPortMask.portmask &= ~(RG_get_lan_phyPortMask(0xf));
#endif
		cvlan_info.untagPortMask.portmask &= ~(RG_get_lan_phyPortMask(0xf));
		rtk_rg_cvlan_add(&cvlan_info);		
	}
#if 0//defined(CONFIG_CMCC) || defined(CONFIG_CU)
	for (i = 0; i < vcTotal; i++)
	{
		if (!mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&Entry))
				return -1;

		if (Entry.enable == 0)
			continue;

		if(Entry.cmode != CHANNEL_MODE_BRIDGE && isFoundFirstBr==1 && Entry.vid == firstBrVid) {
			RG_restore_cvlan_member(firstBrVid, Entry.itfGroup);
		}	
	}
#endif	
}


#ifndef CONFIG_RTL9600_SERIES
void check_port_based_vlan_of_bridge_inet_wan(void)
{
	int bridge_inet=0,i;
	int bvid=0, _itfGroup=0, untag_bridge=0;
	int vcTotal=-1;
	unsigned short unbinded_portMask = 0;
	unsigned short enable = 0, tmp = 0;	
	MIB_CE_ATM_VC_T Entry;
	int vlan_id=0,ret,lan_phy=0;
	unsigned char mbtd;
	int wlan_idx=0, pvid=0;
	unsigned int dev_idx=0;
#if defined(CONFIG_USER_LAN_PORT_AS_ETH_WAN)
	int ethPhyPortId = -1;
	mib_get(MIB_ETH_WAN_PORT_PHY_INDEX, &ethPhyPortId);
#endif

	unsigned char devicetype = 0;
	mib_get(MIB_DEVICE_TYPE, (void *)&devicetype);

	if ( devicetype == 2 ){
		printf("Hybrid mode, bypass %s\n", __FUNCTION__);
		return;
	}	
	mib_get(MIB_MAC_BASED_TAG_DECISION, (void *)&mbtd);
	
#if 0//def WLAN_SUPPORT
	RG_Flush_WIFI_UntagIn();
#endif
	vcTotal = mib_chain_total(MIB_ATM_VC_TBL);
	if(vcTotal<0)
		return;
	for (i = 0; i < vcTotal; i++)
	{
		if (!mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&Entry))
			continue;
		if (Entry.enable == 0)
			continue;		
		//VCentry existed an internet bridge WAN
		if(((Entry.applicationtype & X_CT_SRV_INTERNET)||(!mbtd)) && (Entry.cmode == CHANNEL_MODE_BRIDGE) && !bridge_inet){
			if (Entry.vlan == 1)
			{
				bvid=Entry.vid;
			}
			else
			{
				//config untag bridge wan's pvid as lan vid.
				mib_get(MIB_LAN_VLAN_ID1, (void *)&vlan_id);
				//mib_get(MIB_UNTAG_WAN_VLAN_ID, (void *)&vlan_id);
				bvid=vlan_id;
				untag_bridge=1;
			}
			bridge_inet=1;
		}
		_itfGroup |= Entry.itfGroup;
	}
	//get unbinded port mask
#if defined(WLAN_DUALBAND_CONCURRENT)
	for(i=0; i <=PMAP_WLAN1_VAP_END; i++)
#else
	for(i=0; i <=PMAP_WLAN0_VAP_END; i++)
#endif
	{
		tmp = (_itfGroup >> i) & 1;

		if(tmp == 0){
			unbinded_portMask |= (1 << i);
		}
	}

	if(bridge_inet)
	{
		//RG_get_lan_phyPortId
//		for(i=0;i<SW_LAN_PORT_NUM;i++)
#if defined(WLAN_DUALBAND_CONCURRENT)
		for(i=0; i <=PMAP_WLAN1_VAP_END; i++)
#else
		for(i=0; i <=PMAP_WLAN0_VAP_END; i++)
#endif
		{
			if(!((_itfGroup >> i) & 1)){
#ifdef CONFIG_RTL9602C_SERIES
				if(i < PMAP_ETH0_SW2)
#else
				if(i <= PMAP_ETH0_SW3)
#endif
				{
					lan_phy = RG_get_lan_phyPortId(i);
#if defined(CONFIG_USER_LAN_PORT_AS_ETH_WAN)
					if (ethPhyPortId != -1 &&  lan_phy == ethPhyPortId)
					{
						printf("%s-%d lan_phy=%d ignore\n",__func__,__LINE__, lan_phy,vlan_id);
						continue;
					}
#endif
//AUG_PRT("lan_phy=%d bvid=%d\n",lan_phy,bvid);
					if(ret = rtk_rg_portBasedCVlanId_set(lan_phy,bvid)){
						printf("%s-%d rtk_rg_portBasedCVlanId_set error lan ret=%d port:%d, vid:%d\n",__func__,__LINE__,ret,lan_phy,bvid);
					}
					//setup vconfig to detag pvid, which would tag to CPU.
					if(!untag_bridge)
						setup_vconfig(bvid,i);
				}
				else if(i >= PMAP_WLAN0)
				{
					wlan_idx=0;
#ifdef WLAN_DUALBAND_CONCURRENT
					dev_idx = (i > PMAP_WLAN0_VAP_END) ? ((i-PMAP_WLAN1)+RG_RET_MBSSID_SLAVE_ROOT_INTF) : ((i-PMAP_WLAN0)+RG_RET_MBSSID_MASTER_ROOT_INTF);
#else
					dev_idx = i-PMAP_WLAN0;
#endif
					rtk_rg_wlanDevBasedCVlanId_get(wlan_idx,dev_idx, &pvid);
					printf("\033[1;33;40m @@@@@@@@@@@@@@@@@########### %s:%d pvid %d dev_idx %d i %d \033[m\n", __FUNCTION__, __LINE__, pvid, dev_idx, i);
					//prevent to overwrite Wlan Port isolation setting, if vlan id is 4005. the device is default, we can set
#if 0
					if(pvid < WLAN_DEV_BASED_CVLAN_START){
						rtk_rg_wlanDevBasedCVlanId_set(wlan_idx,dev_idx, bvid);
					}
#endif					
					rtk_rg_wlanDevBasedCVlanId_set(wlan_idx,dev_idx, bvid);

				}
			}
		}
#if 0//def WLAN_SUPPORT
		RG_set_WIFI_UntagIn(bvid);
#endif
	}
	else
	{
		if(!mbtd)
		{
			//bridge internet is not existed, reset port base vlan to internal vid
			if(mib_get(MIB_LAN_VLAN_ID1, (void *)&vlan_id) != 0)
			{
#if defined(WLAN_DUALBAND_CONCURRENT)
				for(i=0; i <=PMAP_WLAN1_VAP_END; i++)
#else
				for(i=0; i <=PMAP_WLAN0_VAP_END; i++)
#endif
				{
#ifdef CONFIG_RTL9602C_SERIES
					if(i < PMAP_ETH0_SW2)
#else
					if(i <= PMAP_ETH0_SW3)
#endif
					{
						lan_phy = RG_get_lan_phyPortId(i);
#if defined(CONFIG_USER_LAN_PORT_AS_ETH_WAN)
						if (ethPhyPortId != -1 &&  lan_phy == ethPhyPortId)
						{
							printf("%s-%d lan_phy=%d ignore\n",__func__,__LINE__, lan_phy,vlan_id);
							continue;
						}
#endif
//AUG_PRT("lan_phy=%d vlan_id=%d\n",lan_phy,vlan_id);
						if(ret = rtk_rg_portBasedCVlanId_set(lan_phy,vlan_id)){
							printf("%s-%d rtk_rg_portBasedCVlanId_set error lan ret=%d port:%d, vid:%d\n",__func__,__LINE__,ret,lan_phy,bvid);
						}
					}
					else if(i >= PMAP_WLAN0)
					{
						wlan_idx=0;
#ifdef WLAN_DUALBAND_CONCURRENT
						dev_idx = (i > PMAP_WLAN0_VAP_END) ? ((i-PMAP_WLAN1)+RG_RET_MBSSID_SLAVE_ROOT_INTF) : ((i-PMAP_WLAN0)+RG_RET_MBSSID_MASTER_ROOT_INTF);
#else
						dev_idx = i-PMAP_WLAN0;
#endif
						rtk_rg_wlanDevBasedCVlanId_get(wlan_idx,dev_idx, &pvid);
						//printf("\033[1;33;40m @@@@@@@@@@@@@@@@@########### %s:%d pvid %d dev_idx %d i %d \033[m\n", __FUNCTION__, __LINE__, pvid, dev_idx, i);
						//prevent to overwrite Wlan Port isolation setting, if vlan id is 4005. the device is default, we can set
#if 0
						if(pvid < WLAN_DEV_BASED_CVLAN_START){
							rtk_rg_wlanDevBasedCVlanId_set(wlan_idx,dev_idx, bvid);
						}
#endif					
						rtk_rg_wlanDevBasedCVlanId_set(wlan_idx,dev_idx, vlan_id);

					}					
				}
			}
		}
	}
	if(!mbtd && bridge_inet)
	{
		//disable mac based tag decision, we must handle 
		//vlan member ship by ourself otherwise RG would
		//take care it.
		rtk_rg_cvlan_info_t cvlan_info;
		memset(&cvlan_info, 0x0, sizeof(rtk_rg_cvlan_info_t));
		cvlan_info.vlanId=bvid;
		rtk_rg_cvlan_get(&cvlan_info);
#ifdef CONFIG_RTL9602C_SERIES
		cvlan_info.memberPortMask.portmask |=RG_get_lan_phyPortMask(unbinded_portMask&0x3);
#else
		cvlan_info.memberPortMask.portmask |=RG_get_lan_phyPortMask(unbinded_portMask&0xf);
#endif
		//to LAN untag.
		cvlan_info.untagPortMask.portmask |=RG_get_lan_phyPortMask(unbinded_portMask&0xf);
#ifdef WLAN_SUPPORT
#ifdef CONFIG_MASTER_WLAN0_ENABLE
		//add extensions port for broadcast wifi packet
		if((unbinded_portMask & (ITFGROUP_WLAN_MASK << ITFGROUP_WLAN0_DEV_BIT)) > 0){
			//printf("\033[1;33;40m @@@@@@@@@@@@@@@@@########### extensions port 1 pvid %d %x\033[m\n", pvid, (1 << RG_get_wlan_phyPortId(PMAP_WLAN0)));
			cvlan_info.memberPortMask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN0));
		}
		cvlan_info.wlan0DevMask |= (((unbinded_portMask >> ITFGROUP_WLAN0_DEV_BIT) & ITFGROUP_WLAN_MASK) << RG_RET_MBSSID_MASTER_ROOT_INTF);
#if defined(WLAN_DUALBAND_CONCURRENT)
#ifdef WLAN_SUPPORT
	//add extensions port for broadcast wifi packet
	if((unbinded_portMask & (ITFGROUP_WLAN_MASK << ITFGROUP_WLAN1_DEV_BIT)) > 0){
		//printf("\033[1;33;40m @@@@@@@@@@@@@@@@@########### extensions port 2 pvid %d\033[m\n", pvid);
		cvlan_info.memberPortMask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN1));
	}
#endif
	cvlan_info.wlan0DevMask |= (((unbinded_portMask >> ITFGROUP_WLAN1_DEV_BIT) & ITFGROUP_WLAN_MASK) << RG_RET_MBSSID_SLAVE_ROOT_INTF);
	cvlan_info.wlan0UntagMask |= cvlan_info.wlan0DevMask;
#endif
#endif /*CONFIG_MASTER_WLAN0_ENABLE*/
#endif /*WLAN_SUPPORT*/
		ret = rtk_rg_cvlan_add(&cvlan_info);
		//dump_cvlan(bvid);
	}

}
#endif

#ifdef CONFIG_RTL867X_VLAN_MAPPING
int RTK_RG_VLAN_Binding_MC_DS_Rule_check(int port_idx, int binding_idx, unsigned short vlan_a, unsigned short vlan_b)
{
	MIB_CE_PORT_BINDING_T pbEntry;
	int p_idx;

	for (p_idx = 0; p_idx < port_idx; p_idx++)
	{
		mib_chain_get(MIB_PORT_BINDING_TBL, p_idx, (void*)&pbEntry);
		if((unsigned char)VLAN_BASED_MODE == pbEntry.pb_mode)
		{
			struct v_pair *vid_pair;
			int b_idx;
			vid_pair = (struct v_pair *)&pbEntry.pb_vlan0_a;
			for (b_idx=0; b_idx<4; b_idx++)
			{				
				if(!vid_pair[p_idx].vid_a || !vid_pair[p_idx].vid_b)
					continue;

				if(vid_pair[p_idx].vid_a == vlan_a && vid_pair[p_idx].vid_b == vlan_b)
					return 1;
			}
		}
	}

	return 0;
}

int RTK_RG_VLAN_Binding_MC_DS_Rule_flush(void)
{
	FILE *fp;
	int aclIdx;

	if(!(fp = fopen(RG_ACL_VLAN_BINDING_DS_MC_RULES_FILE, "r")))
		return -2;

	while(fscanf(fp, "%d\n", &aclIdx) != EOF)
	{
		if(rtk_rg_aclFilterAndQos_del(aclIdx))
			DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", aclIdx);
	}

	fclose(fp);
	unlink(RG_ACL_VLAN_BINDING_DS_MC_RULES_FILE);
	return 0;
}

#if 1
int RTK_RG_VLAN_Binding_MC_DS_Rule_set(int mode)
{
	char MCAST_ADDR[MAC_ADDR_LEN]={0x01,0x00,0x5E,0x00,0x00,0x00};
	char MCAST_MASK[MAC_ADDR_LEN]={0xff,0xff,0xff,0x00,0x00,0x00};
#ifdef CONFIG_IPV6
	char MCAST_ADDR_V6[MAC_ADDR_LEN]={0x33,0x33,0x00,0x00,0x00,0x00};
	char MCAST_MASK_V6[MAC_ADDR_LEN]={0xff,0xff,0x00,0x00,0x00,0x00};
#endif
	rtk_rg_aclFilterAndQos_t aclRule = {0};
	MIB_CE_PORT_BINDING_T pbEntry;
	MIB_CE_ATM_VC_T atmVcEntry;
	int aclIdx, port_idx, totalPortbd;
	int isHitSomeMvid = 0, hitMvid = -1;
	int atmVcNum, i;
	FILE *fp;

	if(!(fp = fopen(RG_ACL_VLAN_BINDING_DS_MC_RULES_FILE, "a")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -1;
	}

	totalPortbd = mib_chain_total(MIB_PORT_BINDING_TBL);
	//polling every lanport vlan-mapping entry
	for (port_idx = 0; port_idx < totalPortbd; port_idx++)
	{
		mib_chain_get(MIB_PORT_BINDING_TBL, port_idx, (void*)&pbEntry);
		if((unsigned char)VLAN_BASED_MODE == pbEntry.pb_mode)
		{
			struct v_pair *vid_pair;
			int k;
			
			vid_pair = (struct v_pair *)&pbEntry.pb_vlan0_a;

			for (k=0; k<4; k++)
			{
				//Be sure the content of vlan-mapping exsit!
				if (vid_pair[k].vid_a && vid_pair[k].vid_b)
				{
					int atmVcEntryBridgeWanIndx;
					int atmVcEntryWanIndx;
					rtk_rg_cvlan_info_t cvlan_info;
					memset(&cvlan_info,0,sizeof(rtk_rg_cvlan_info_t));					
					atmVcEntryBridgeWanIndx = -1;
					atmVcEntryWanIndx = -1;
					atmVcNum = mib_chain_total(MIB_ATM_VC_TBL); 
					isHitSomeMvid = 0;
					hitMvid = -1;
					for (i=0; i < atmVcNum; i++) {
						if (!mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&atmVcEntry))
						{
							printf("Get chain record error!\n");
							return -1;
						}

						if(atmVcEntry.vlan==1 && atmVcEntry.vid == vid_pair[k].vid_b && atmVcEntry.cmode == CHANNEL_MODE_BRIDGE)
						{
							atmVcEntryBridgeWanIndx = i;
						} 
						else if(atmVcEntry.vlan==1 && atmVcEntry.vid == vid_pair[k].vid_b)
						{
							atmVcEntryWanIndx = i;
						}

						if(atmVcEntry.vlan==1 && atmVcEntry.mVid && atmVcEntry.vid == vid_pair[k].vid_b)
						{
							isHitSomeMvid = 1;
							hitMvid = atmVcEntry.mVid;
							break;
						}
					}

					/* 9603C/9607C dose not need to transform ingress VLAN by ACL 
					   & modifying LAN CVLAN way
					   RG will learn ingress report automatically 
					   after proc: proc/rg/igmp_auto_learn_ctagif is enabled */
#if !defined(CONFIG_RTL9607C_SERIES)

					/*
					diag
					rg clear acl-filter
					rg set acl-filter acl_weight 200
					rg set acl-filter fwding_type_and_direction 0
					rg set acl-filter action action_type 0
					rg set acl-filter action qos action_ingress_vid 43
					rg set acl-filter pattern ingress_ctag_vid 40
					rg set acl-filter pattern ingress_dmac 1:0:5e:0:0:0
					rg set acl-filter pattern ingress_dmac_mask ff:ff:ff:0:0:0
					rg set acl-filter pattern ingress_port_mask 0x10
					rg add acl-filter entry
					rg clear acl-filter
					*/
					
					memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
					aclRule.acl_weight = RG_FIREWALL_ACL_WEIGHT;
					aclRule.fwding_type_and_direction =  ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
					aclRule.action_type = ACL_ACTION_TYPE_QOS;
					aclRule.qos_actions |= ACL_ACTION_ACL_INGRESS_VID_BIT;
					aclRule.action_acl_ingress_vid = vid_pair[k].vid_a;
					aclRule.filter_fields |= INGRESS_CTAG_VID_BIT;
					if(isHitSomeMvid)
						aclRule.ingress_ctag_vid = hitMvid;
					else
						aclRule.ingress_ctag_vid = vid_pair[k].vid_b;
					aclRule.filter_fields |= INGRESS_DMAC_BIT;
					memcpy(&aclRule.ingress_dmac,MCAST_ADDR,MAC_ADDR_LEN);
					memcpy(&aclRule.ingress_dmac_mask,MCAST_MASK,MAC_ADDR_LEN);					
					aclRule.filter_fields |= INGRESS_PORT_BIT;
					aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();				

					if(!RTK_RG_VLAN_Binding_MC_DS_Rule_check(port_idx, k, vid_pair[k].vid_a, vid_pair[k].vid_b)){
						if(atmVcEntryWanIndx != -1 || atmVcEntryBridgeWanIndx != -1){
							if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0){
								fprintf(fp, "%d\n", aclIdx);
							}
							else
								printf("Set rtk_rg_aclFilterAndQos_add failed!\n");
#ifdef CONFIG_IPV6
							memcpy(&aclRule.ingress_dmac,MCAST_ADDR_V6,MAC_ADDR_LEN);
							memcpy(&aclRule.ingress_dmac_mask,MCAST_MASK_V6,MAC_ADDR_LEN);
							if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0){
								fprintf(fp, "%d\n", aclIdx);
							}
							else
								printf("Set rtk_rg_aclFilterAndQos_add failed!\n");
#endif
						}
					}
#endif

					if(mode) {
						memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
						aclRule.fwding_type_and_direction =  ACL_FWD_TYPE_DIR_INGRESS_OR_EGRESS_L34_DOWN_CVLAN_SVLAN;
						aclRule.filter_fields |= INGRESS_PORT_BIT;
						aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();
						aclRule.filter_fields |= INGRESS_EGRESS_PORTIDX_BIT;
						aclRule.ingress_port_idx = 0;
						aclRule.ingress_port_idx_mask = 0x0;
						aclRule.egress_port_idx = RG_get_lan_phyPortId(port_idx);
						aclRule.egress_port_idx_mask = 0xf;
						aclRule.filter_fields |= INGRESS_CTAGIF_BIT;
						aclRule.ingress_ctagIf = 1;
						aclRule.filter_fields |= INGRESS_CTAG_VID_BIT;
						aclRule.ingress_ctag_vid = vid_pair[k].vid_b;
						aclRule.action_type = ACL_ACTION_TYPE_QOS;
						aclRule.qos_actions |= ACL_ACTION_ACL_CVLANTAG_BIT;
						aclRule.action_acl_cvlan.cvlanTagIfDecision=ACL_CVLAN_TAGIF_TAGGING;
						aclRule.action_acl_cvlan.cvlanCvidDecision = 0;
						aclRule.action_acl_cvlan.cvlanCpriDecision = ACL_CVLAN_CPRI_COPY_FROM_INTERNAL_PRI;
						aclRule.action_acl_cvlan.assignedCvid = vid_pair[k].vid_a;
						aclRule.action_acl_cvlan.assignedCpri = 0;
						if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0){
							fprintf(fp, "%d\n", aclIdx);
						}
						else
							printf("Set rtk_rg_aclFilterAndQos_add failed!\n");
					}
					cvlan_info.vlanId = vid_pair[k].vid_a;
					if(rtk_rg_cvlan_get(&cvlan_info) == RT_ERR_RG_OK) {
						cvlan_info.memberPortMask.portmask |= (RG_get_wan_phyPortMask());
						cvlan_info.memberPortMask.portmask |= (1<<RG_get_lan_phyPortId(port_idx));
						cvlan_info.untagPortMask.portmask &= ~(RG_get_wan_phyPortMask());
						cvlan_info.untagPortMask.portmask &= ~(1<<RG_get_lan_phyPortId(port_idx));
						if(rtk_rg_cvlan_add(&cvlan_info)!= RT_ERR_RG_OK)
							printf("RG_add_lan_binding_vlan_member failed\n");
					}
				}
			}
		}
	}

	fclose(fp);
	return 0;
}
#else
int RTK_RG_VLAN_Binding_MC_DS_Rule_set(imt mode)
{
	char MCAST_ADDR[MAC_ADDR_LEN]={0x01,0x00,0x5E,0x00,0x00,0x00};
	char MCAST_MASK[MAC_ADDR_LEN]={0xff,0xff,0xff,0x00,0x00,0x00};
	char MCAST_ADDR_V6[MAC_ADDR_LEN]={0x33,0x33,0x00,0x00,0x00,0x00};
	char MCAST_MASK_V6[MAC_ADDR_LEN]={0xff,0xff,0x00,0x00,0x00,0x00};
	rtk_rg_aclFilterAndQos_t aclRule = {0};
	MIB_CE_PORT_BINDING_T pbEntry;
	MIB_CE_ATM_VC_T atmVcEntry;
	int aclIdx, port_idx, totalPortbd;
	int isHitSomeMvid = 0, hitMvid = -1;
	int atmVcNum, i;
	FILE *fp;

	if(!(fp = fopen(RG_ACL_VLAN_BINDING_DS_MC_RULES_FILE, "a")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -1;
	}

	totalPortbd = mib_chain_total(MIB_PORT_BINDING_TBL);
	//polling every lanport vlan-mapping entry
	for (port_idx = 0; port_idx < totalPortbd; port_idx++)
	{
		mib_chain_get(MIB_PORT_BINDING_TBL, port_idx, (void*)&pbEntry);
		if((unsigned char)VLAN_BASED_MODE == pbEntry.pb_mode)
		{
			struct v_pair *vid_pair;
			int k;
			
			vid_pair = (struct v_pair *)&pbEntry.pb_vlan0_a;

			for (k=0; k<4; k++)
			{
				//Be sure the content of vlan-mapping exsit!
				if (vid_pair[k].vid_a && vid_pair[k].vid_b)
				{
					int atmVcEntryBridgeWanIndx;
					int atmVcEntryWanIndx;
					atmVcEntryBridgeWanIndx = -1;
					atmVcEntryWanIndx = -1;
					atmVcNum = mib_chain_total(MIB_ATM_VC_TBL); 
					isHitSomeMvid = 0;
					hitMvid = -1;
					for (i=0; i < atmVcNum; i++) {
						if (!mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&atmVcEntry))
						{
							printf("Get chain record error!\n");
							return -1;
						}

						if(atmVcEntry.vlan==1 && atmVcEntry.vid == vid_pair[k].vid_b && atmVcEntry.cmode == CHANNEL_MODE_BRIDGE)
						{
							atmVcEntryBridgeWanIndx = i;
						} 
						else if(atmVcEntry.vlan==1 && atmVcEntry.vid == vid_pair[k].vid_b)
						{
							atmVcEntryWanIndx = i;
						}

						if(atmVcEntry.vlan==1 && atmVcEntry.mVid && atmVcEntry.vid == vid_pair[k].vid_b)
						{
							isHitSomeMvid = 1;
							hitMvid = atmVcEntry.mVid;
							break;
						}
					}				
					memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
					aclRule.fwding_type_and_direction =  ACL_FWD_TYPE_DIR_INGRESS_OR_EGRESS_L34_DOWN_CVLAN_SVLAN;
					aclRule.filter_fields |= INGRESS_PORT_BIT;
					aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();
					aclRule.filter_fields |= INGRESS_EGRESS_PORTIDX_BIT;
					aclRule.ingress_port_idx = 0;
					aclRule.ingress_port_idx_mask = 0x0;
					aclRule.egress_port_idx = RG_get_lan_phyPortId(port_idx);
					aclRule.egress_port_idx_mask = aclRule.egress_port_idx;
					aclRule.filter_fields |= INGRESS_DMAC_BIT;
					memcpy(&aclRule.ingress_dmac,MCAST_ADDR,MAC_ADDR_LEN);
					memcpy(&aclRule.ingress_dmac_mask,MCAST_MASK,MAC_ADDR_LEN);
					aclRule.filter_fields |= INGRESS_CTAGIF_BIT;
					aclRule.ingress_ctagIf = 1;
					aclRule.filter_fields |= INGRESS_CTAG_VID_BIT;
					if(isHitSomeMvid)
						aclRule.ingress_ctag_vid = hitMvid;
					else
						aclRule.ingress_ctag_vid = vid_pair[k].vid_b;
					aclRule.action_type = ACL_ACTION_TYPE_QOS;
					aclRule.qos_actions |= ACL_ACTION_ACL_CVLANTAG_BIT;
					aclRule.action_acl_cvlan.cvlanTagIfDecision=ACL_CVLAN_TAGIF_TAGGING;
					aclRule.action_acl_cvlan.cvlanCvidDecision = 0;
					aclRule.action_acl_cvlan.cvlanCpriDecision = 0;
					aclRule.action_acl_cvlan.assignedCvid = vid_pair[k].vid_a;
					aclRule.action_acl_cvlan.assignedCpri = 0;

					if(atmVcEntryWanIndx != -1 || atmVcEntryBridgeWanIndx != -1){
						if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0){
							fprintf(fp, "%d\n", aclIdx);
						}
						else
							printf("Set rtk_rg_aclFilterAndQos_add failed!\n");

						memcpy(&aclRule.ingress_dmac,MCAST_ADDR_V6,MAC_ADDR_LEN);
						memcpy(&aclRule.ingress_dmac_mask,MCAST_MASK_V6,MAC_ADDR_LEN);
						if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0){
							fprintf(fp, "%d\n", aclIdx);
						}
						else
							printf("Set rtk_rg_aclFilterAndQos_add failed!\n");
					}

					if(atmVcEntryBridgeWanIndx != -1) {
						aclRule.filter_fields &= ~INGRESS_DMAC_BIT;
						aclRule.ingress_ctag_vid = vid_pair[k].vid_b;
						if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0){
							fprintf(fp, "%d\n", aclIdx);
						}
						else
							printf("Set rtk_rg_aclFilterAndQos_add failed!\n");
					}
				}
			}
		}
	}

	fclose(fp);
	return 0;
}
#endif
int RTK_RG_VLAN_Binding_MC_DS_Rule_Config(int mode)
{
	int lockfd;
	LOCK_ACL_CONFIG(ConfigACLLock);
	RTK_RG_VLAN_Binding_MC_DS_Rule_flush();
	RTK_RG_VLAN_Binding_MC_DS_Rule_set(mode);
	UNLOCK_ACL_CONFIG();
	return 0;
}
#endif

int RTK_RG_multicastFlow_add(unsigned int group, int *index)
{
	rtk_rg_multicastFlow_t mcFlow = {0};
	char ipStr[INET6_ADDRSTRLEN] = {0};	
	int ret;

	if(index==NULL)
		return -1;

	if(!isIgmproxyEnabled())
		return -1;

	if(isIGMPSnoopingEnabled())
		return -1;

	mcFlow.isIPv6 = 0;
	mcFlow.multicast_ipv4_addr = group;	
#ifdef CONFIG_RTL9602C_SERIES
	mcFlow.port_mask.portmask = RG_get_lan_phyPortMask(0x3);
#else
	mcFlow.port_mask.portmask = RG_get_lan_phyPortMask(0xf);
#endif
	mcFlow.routingMode = RTK_RG_IPV4MC_EN_ROUTING;

	inet_ntop(AF_INET, (struct in_addr *)&(mcFlow.multicast_ipv4_addr), ipStr, sizeof(ipStr));	
	ret=rtk_rg_multicastFlow_add(&mcFlow, index);
	AUG_PRT("ret=%d multicast_ipv4_addr=%s, index=%d\n", ret, ipStr, *index);
	return ret;
}

int RTK_RG_multicastFlow_delete(int index)
{
#if 1
	if(index == -1)
		return -1;

	if(!isIgmproxyEnabled())
		return -1;

	if(isIGMPSnoopingEnabled())
		return -1;
		
	AUG_PRT("index=%d\n", index);
	return rtk_rg_multicastFlow_del(index);
#else
	rtk_rg_multicastFlow_t mcFlow = {0};
	char ipStr[INET6_ADDRSTRLEN] = {0};
	
	if(!isIgmproxyEnabled())
		return -1;

	if(isIGMPSnoopingEnabled())
		return -1;

	if(rtk_rg_multicastFlow_find(&mcFlow, &index) == RT_ERR_RG_OK)
	{
		if(mcFlow.isIPv6)
			return -1;
		
		AUG_PRT("ret=%d multicast_ipv4_addr=%s, index=%d\n", ret, ipStr, *index);
		return rtk_rg_multicastFlow_del(index);
	}
#endif
}

int RTK_RG_multicastFlow_reset(void)
{
	return RTK_RG_multicastFlow_flush();
}

int RTK_RG_multicastFlow_flush(void)
{
#if 1
	AUG_PRT("/bin/echo 2 > /proc/rg/mcast_protocol\n");
	system("/bin/echo 2 > /proc/rg/mcast_protocol");
	AUG_PRT("/bin/echo 0 > /proc/rg/mcast_protocol\n");
	system("/bin/echo 0 > /proc/rg/mcast_protocol");
#else
	rtk_rg_multicastFlow_t mcFlow = {0};
	char ipStr[INET6_ADDRSTRLEN] = {0};
	int index;
	
	for(index=0 ; index<DEFAULT_MAX_FLOW_COUNT ; index++)
	{
		if(rtk_rg_multicastFlow_find(&mcFlow, &index) == RT_ERR_RG_OK)
		{
			if(mcFlow.isIPv6)
				continue;
 			
			AUG_PRT("ret=%d multicast_ipv4_addr=%s, index=%d\n", ret, ipStr, *index);
			rtk_rg_multicastFlow_del(index);
		}
	}
#endif
	return 0;
}

int RTK_RG_Ipv6_multicastFlow_add(unsigned int *group, int *index)
{
	rtk_rg_multicastFlow_t mcFlow = {0};
	char ipv6addr_str[64];
	int ret;

	if(group==NULL)
		return -1;

	if(index==NULL)
		return -1;
		
	if(!isMLDProxyEnabled())
		return -1;

	if(isMLDSnoopingEnabled())
		return -1;
	
	mcFlow.isIPv6 = 1;	
	memcpy(mcFlow.multicast_ipv6_addr, group, sizeof(mcFlow.multicast_ipv6_addr));
#ifdef CONFIG_RTL9602C_SERIES
	mcFlow.port_mask.portmask = RG_get_lan_phyPortMask(0x3);
#else
	mcFlow.port_mask.portmask = RG_get_lan_phyPortMask(0xf);
#endif

	mcFlow.routingMode = RTK_RG_IPV4MC_EN_ROUTING;

	inet_ntop(PF_INET6, mcFlow.multicast_ipv6_addr, ipv6addr_str, sizeof(ipv6addr_str));
	ret=rtk_rg_multicastFlow_add(&mcFlow, index);
	AUG_PRT("ret=%d multicast_ipv6_addr=%s, index=%d\n", ret, ipv6addr_str, *index);
	return ret;
}

int RTK_RG_Ipv6_multicastFlow_delete(int index)
{
#if 1
	if(index == -1)
		return -1;

	if(!isMLDProxyEnabled())
		return -1;

	if(isMLDSnoopingEnabled())
		return -1;

	AUG_PRT("index=%d\n", index);
	return rtk_rg_multicastFlow_del(index);
#else
	rtk_rg_multicastFlow_t mcFlow = {0};
	char ipv6addr_str[64];
	
	if(!isMLDProxyEnabled())
		return -1;

	if(isMLDSnoopingEnabled())
		return -1;

	if(rtk_rg_multicastFlow_find(&mcFlow, &index) == RT_ERR_RG_OK)
	{
		if(!mcFlow.isIPv6)
			return -1;
		
		AUG_PRT("ret=%d multicast_ipv6_addr=%s, index=%d\n", ret, ipv6addr_str, *index);
		return rtk_rg_multicastFlow_del(index);
	}
#endif
}

int RTK_RG_Ipv6_multicastFlow_reset(void)
{
	return RTK_RG_Ipv6_multicastFlow_flush();
}

int RTK_RG_Ipv6_multicastFlow_flush(void)
{
#if 1
	AUG_PRT("/bin/echo 1 > /proc/rg/mcast_protocol\n");
	system("/bin/echo 1 > /proc/rg/mcast_protocol");
	AUG_PRT("/bin/echo 0 > /proc/rg/mcast_protocol\n");
	system("/bin/echo 0 > /proc/rg/mcast_protocol");
#else
	rtk_rg_multicastFlow_t mcFlow = {0};
	char ipv6addr_str[64];
	int index;
	
	for(index=0 ; index<DEFAULT_MAX_FLOW_COUNT ; index++)
	{
		if(rtk_rg_multicastFlow_find(&mcFlow, &index) == RT_ERR_RG_OK)
		{
			if(!mcFlow.isIPv6)
				continue;
			
			AUG_PRT("ret=%d multicast_ipv6_addr=%s, index=%d\n", ret, ipv6addr_str, *index);
			rtk_rg_multicastFlow_del(index);
		}
	}
#endif
	return 0;
}

int isVidBridgeWanExist(int vid)
{
	MIB_CE_ATM_VC_T Entry;
	unsigned int entryNum;
	int i;
	
	entryNum = mib_chain_total(MIB_ATM_VC_TBL);
	for (i=0; i<entryNum; i++)
	{
		 if (!mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&Entry))
		 {
  			printf("error get atm vc entry\n");
			return 0;
		 }

		 if(vid==Entry.vid && (Entry.cmode==CHANNEL_MODE_BRIDGE))
			return 1;
	}

	return 0;
}

void RTK_RG_Flush_IGMP_proxy_ACL_rule(void)
{
	FILE *fp;
	int aclIdx;

	if(!(fp = fopen(RG_IGMP_PROXY_ACL_RULE_FILE, "r")))
		return -2;

	while(fscanf(fp, "%d\n", &aclIdx) != EOF)
	{
		if(rtk_rg_aclFilterAndQos_del(aclIdx))
			DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", aclIdx);
	}

	fclose(fp);
	unlink(RG_IGMP_PROXY_ACL_RULE_FILE);
	return 0;
}

void RTK_RG_set_IGMP_proxy_ACL_rule(void)
{
	char MCAST_ADDR[MAC_ADDR_LEN]={0x01,0x00,0x5E,0x00,0x00,0x00};
	char MCAST_MASK[MAC_ADDR_LEN]={0xff,0xff,0xff,0x00,0x00,0x00};
	struct in_addr IP_Address;
	rtk_rg_aclFilterAndQos_t aclRule;
	int i,aclIdx=0, ret;
	unsigned char igmpProxyEnable;
	MIB_CE_ATM_VC_T Entry;
	unsigned int entryNum;
	FILE *fp;
	
	if(!(fp = fopen(RG_IGMP_PROXY_ACL_RULE_FILE, "a")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -2;
	}
	
	mib_get(MIB_IGMP_PROXY, (void *)&igmpProxyEnable);
	entryNum = mib_chain_total(MIB_ATM_VC_TBL);
	for (i=0; i<entryNum; i++)
	{
		 if (!mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&Entry))
		 {
  			printf("error get atm vc entry\n");
			return -1;
		 }

		// check if IGMP proxy enabled ?
		if(!Entry.enable || !Entry.enableIGMP || !igmpProxyEnable)
		{
			if(isVidBridgeWanExist(Entry.vid))
				continue;

			if(!Entry.mVid) {
				/* Permit */
				memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
				aclRule.acl_weight = RG_FIREWALL_ACL_WEIGHT;
				aclRule.filter_fields |= INGRESS_PORT_BIT;
				aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();
				aclRule.filter_fields |= INGRESS_CTAG_VID_BIT;
				aclRule.ingress_ctag_vid = Entry.vid;
				aclRule.filter_fields |= INGRESS_L4_UDP_BIT;			
				aclRule.filter_fields |= INGRESS_DMAC_BIT;
				memcpy(&aclRule.ingress_dmac,MCAST_ADDR,MAC_ADDR_LEN);
				memcpy(&aclRule.ingress_dmac_mask,MCAST_MASK,MAC_ADDR_LEN);
				aclRule.filter_fields |= INGRESS_IPV4_DIP_RANGE_BIT;
				inet_pton(AF_INET, "239.255.255.250", &IP_Address);
				memcpy(&aclRule.ingress_dest_ipv4_addr_start, &IP_Address, IP_ADDR_LEN);
				memcpy(&aclRule.ingress_dest_ipv4_addr_end, &IP_Address, IP_ADDR_LEN);
				aclRule.filter_fields |= INGRESS_IPV4_TAGIF_BIT;
				aclRule.ingress_ipv4_tagif = 1;
				aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
				aclRule.action_type = ACL_ACTION_TYPE_PERMIT;
				if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0) {
					fprintf(fp, "%d\n", aclIdx);
				} else {
					printf("[%s@%d] rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n",__func__,__LINE__, ret);
				}
				
				memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
				aclRule.acl_weight = RG_FIREWALL_ACL_WEIGHT;
				aclRule.filter_fields |= INGRESS_PORT_BIT;
				aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();
				aclRule.filter_fields |= INGRESS_CTAG_VID_BIT;
				aclRule.ingress_ctag_vid = Entry.vid;
				aclRule.filter_fields |= INGRESS_L4_UDP_BIT;
				aclRule.filter_fields |= INGRESS_DMAC_BIT;
				memcpy(&aclRule.ingress_dmac,MCAST_ADDR,MAC_ADDR_LEN);
				memcpy(&aclRule.ingress_dmac_mask,MCAST_MASK,MAC_ADDR_LEN);
				aclRule.filter_fields |= INGRESS_IPV4_DIP_RANGE_BIT;
				inet_pton(AF_INET, "224.0.0.0", &IP_Address);
				memcpy(&aclRule.ingress_dest_ipv4_addr_start, &IP_Address, IP_ADDR_LEN);
				inet_pton(AF_INET, "224.0.0.255", &IP_Address);
				memcpy(&aclRule.ingress_dest_ipv4_addr_end, &IP_Address, IP_ADDR_LEN);
				aclRule.filter_fields |= INGRESS_IPV4_TAGIF_BIT;
				aclRule.ingress_ipv4_tagif = 1;
				aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
				aclRule.action_type = ACL_ACTION_TYPE_PERMIT;
				if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0) {
					fprintf(fp, "%d\n", aclIdx);
				} else {
					printf("[%s@%d] rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n",__func__,__LINE__, ret);
				}

				/* Drop */
				memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
				aclRule.acl_weight = RG_FIREWALL_ACL_WEIGHT;
				aclRule.filter_fields |= INGRESS_PORT_BIT;
				aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();
				aclRule.filter_fields |= INGRESS_CTAG_VID_BIT;
				aclRule.ingress_ctag_vid = Entry.vid;
				aclRule.filter_fields |= INGRESS_L4_UDP_BIT;
				aclRule.filter_fields |= INGRESS_DMAC_BIT;
				memcpy(&aclRule.ingress_dmac,MCAST_ADDR,MAC_ADDR_LEN);
				memcpy(&aclRule.ingress_dmac_mask,MCAST_MASK,MAC_ADDR_LEN);
				inet_pton(AF_INET, "224.0.0.x", &IP_Address);
				memcpy(&aclRule.ingress_dest_ipv4_addr_start, &IP_Address, IP_ADDR_LEN);
				inet_pton(AF_INET, "239.255.255.255", &IP_Address);
				memcpy(&aclRule.ingress_dest_ipv4_addr_end, &IP_Address, IP_ADDR_LEN);
				aclRule.filter_fields |= INGRESS_IPV4_TAGIF_BIT;
				aclRule.ingress_ipv4_tagif = 1;
				aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
				aclRule.action_type = ACL_ACTION_TYPE_DROP;
				if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0) {
					fprintf(fp, "%d\n", aclIdx);
				} else {
					printf("[%s@%d] rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n",__func__,__LINE__, ret);
				}
			} else {
				memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
				aclRule.acl_weight = RG_FIREWALL_ACL_WEIGHT;
				aclRule.filter_fields |= INGRESS_PORT_BIT;
				aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();
				aclRule.filter_fields |= INGRESS_CTAG_VID_BIT;
				aclRule.ingress_ctag_vid = Entry.mVid;
				aclRule.filter_fields |= INGRESS_L4_UDP_BIT;
				aclRule.filter_fields |= INGRESS_DMAC_BIT;
				memcpy(&aclRule.ingress_dmac,MCAST_ADDR,MAC_ADDR_LEN);
				memcpy(&aclRule.ingress_dmac_mask,MCAST_MASK,MAC_ADDR_LEN);
				inet_pton(AF_INET, "224.0.0.x", &IP_Address);
				memcpy(&aclRule.ingress_dest_ipv4_addr_start, &IP_Address, IP_ADDR_LEN);
				inet_pton(AF_INET, "239.255.255.255", &IP_Address);
				memcpy(&aclRule.ingress_dest_ipv4_addr_end, &IP_Address, IP_ADDR_LEN);
				aclRule.filter_fields |= INGRESS_IPV4_TAGIF_BIT;
				aclRule.ingress_ipv4_tagif = 1;
				aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
				aclRule.action_type = ACL_ACTION_TYPE_DROP;
				if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0) {
					fprintf(fp, "%d\n", aclIdx);
				} else {
					printf("[%s@%d] rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n",__func__,__LINE__, ret);
				}
			}
		}
	}

	fclose(fp);
}

void RTK_RG_Flush_MLD_proxy_ACL_rule(void)
{
	FILE *fp;
	int aclIdx;

	if(!(fp = fopen(RG_MLD_PROXY_ACL_RULE_FILE, "r")))
		return -2;

	while(fscanf(fp, "%d\n", &aclIdx) != EOF)
	{
		if(rtk_rg_aclFilterAndQos_del(aclIdx))
			DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", aclIdx);
	}

	fclose(fp);
	unlink(RG_MLD_PROXY_ACL_RULE_FILE);
	return 0;
}

void RTK_RG_set_MLD_proxy_ACL_rule(void)
{
	unsigned char ip6Addr[IP6_ADDR_LEN]={0}, mask[IP6_ADDR_LEN]={0};
	char MCAST_ADDR[MAC_ADDR_LEN]={0x33,0x33,0x00,0x00,0x00,0x00};
	char MCAST_MASK[MAC_ADDR_LEN]={0xff,0xff,0x00,0x00,0x00,0x00};
	rtk_rg_aclFilterAndQos_t aclRule;
	unsigned int mldproxyItf;
	unsigned int entryNum;
	char ifname[IFNAMSIZ];
	MIB_CE_ATM_VC_T Entry;
	int i,aclIdx=0, ret;
	unsigned char is_enabled;
	FILE *fp;
	
	if(!(fp = fopen(RG_MLD_PROXY_ACL_RULE_FILE, "a")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return;
	}

#ifdef CONFIG_MLDPROXY_MULTIWAN
	entryNum = mib_chain_total(MIB_ATM_VC_TBL);
	for (i=entryNum; i>0; i--)
	{
		if (!mib_chain_get(MIB_ATM_VC_TBL, i-1, (void *)&Entry))
		{
			printf("error get atm vc entry\n");
			return;
		}

		if(Entry.enableMLD)
		{
			continue;
		}
		
		if (!(Entry.IpProtocol & IPVER_IPV6) || (Entry.cmode == CHANNEL_MODE_BRIDGE))
			continue;

		if(isVidBridgeWanExist(Entry.vid))
			continue;
		
		if(!Entry.mVid) {
			memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
			aclRule.acl_weight = RG_FIREWALL_ACL_WEIGHT;
			aclRule.filter_fields |= INGRESS_PORT_BIT;
			aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();
			aclRule.filter_fields |= INGRESS_CTAG_VID_BIT;
			aclRule.ingress_ctag_vid = Entry.vid;
			aclRule.filter_fields |= INGRESS_DMAC_BIT;
			memcpy(&aclRule.ingress_dmac,MCAST_ADDR,MAC_ADDR_LEN);
			memcpy(&aclRule.ingress_dmac_mask,MCAST_MASK,MAC_ADDR_LEN);
			aclRule.filter_fields |= INGRESS_IPV6_DIP_BIT;
			inet_pton(PF_INET6, "ff0e::0",(void *)ip6Addr);
			memcpy(aclRule.ingress_dest_ipv6_addr, ip6Addr, IPV6_ADDR_LEN);
			inet_pton(PF_INET6, "ff0f:0:0:0:0:0:0:0",(void *)mask);
			memcpy(aclRule.ingress_dest_ipv6_addr_mask, mask, IPV6_ADDR_LEN);
			aclRule.filter_fields |= INGRESS_IPV6_TAGIF_BIT;
			aclRule.ingress_ipv6_tagif = 1;
			aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
			aclRule.action_type = ACL_ACTION_TYPE_DROP;
			if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0) {
				fprintf(fp, "%d\n", aclIdx);
			} else {
				printf("[%s@%d] rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n",__func__,__LINE__, ret);
			}
		} else {
			memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
			aclRule.acl_weight = RG_FIREWALL_ACL_WEIGHT;
			aclRule.filter_fields |= INGRESS_PORT_BIT;
			aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();
			aclRule.filter_fields |= INGRESS_CTAG_VID_BIT;
			aclRule.ingress_ctag_vid = Entry.mVid;
			aclRule.filter_fields |= INGRESS_DMAC_BIT;
			memcpy(&aclRule.ingress_dmac,MCAST_ADDR,MAC_ADDR_LEN);
			memcpy(&aclRule.ingress_dmac_mask,MCAST_MASK,MAC_ADDR_LEN);
			aclRule.filter_fields |= INGRESS_IPV6_DIP_BIT;
			inet_pton(PF_INET6, "ff0e::0",(void *)ip6Addr);
			memcpy(aclRule.ingress_dest_ipv6_addr, ip6Addr, IPV6_ADDR_LEN);
			inet_pton(PF_INET6, "ff0f:0:0:0:0:0:0:0",(void *)mask);
			memcpy(aclRule.ingress_dest_ipv6_addr_mask, mask, IPV6_ADDR_LEN);
			aclRule.filter_fields |= INGRESS_IPV6_TAGIF_BIT;
			aclRule.ingress_ipv6_tagif = 1;
			aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
			aclRule.action_type = ACL_ACTION_TYPE_DROP;
			if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0) {
				fprintf(fp, "%d\n", aclIdx);
			} else {
				printf("[%s@%d] rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n",__func__,__LINE__, ret);
			}
		}
	}
#else
	if(!mib_get(MIB_MLD_PROXY_DAEMON, (void *)&is_enabled))
	{
		return;
	}
	
	if (mib_get(MIB_MLD_PROXY_EXT_ITF, (void *)&mldproxyItf) != 0)
	{
		entryNum = mib_chain_total(MIB_ATM_VC_TBL);
		for (i=entryNum; i>0; i--)
		{
			if (!mib_chain_get(MIB_ATM_VC_TBL, i-1, (void *)&Entry))
			{
				printf("error get atm vc entry\n");
				return;
			}

			if(ifGetName(mldproxyItf, ifname, sizeof(ifname)))
			{
				if(Entry.ifIndex != mldproxyItf && is_enabled)
					continue;
			}
			
			if (!(Entry.IpProtocol & IPVER_IPV6) || (Entry.cmode == CHANNEL_MODE_BRIDGE))
				continue;

			if(isVidBridgeWanExist(Entry.vid))
				continue;
			
			if(!Entry.mVid) {
				memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
				aclRule.acl_weight = RG_FIREWALL_ACL_WEIGHT;
				aclRule.filter_fields |= INGRESS_PORT_BIT;
				aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();
				aclRule.filter_fields |= INGRESS_CTAG_VID_BIT;
				aclRule.ingress_ctag_vid = Entry.vid;
				aclRule.filter_fields |= INGRESS_DMAC_BIT;
				memcpy(&aclRule.ingress_dmac,MCAST_ADDR,MAC_ADDR_LEN);
				memcpy(&aclRule.ingress_dmac_mask,MCAST_MASK,MAC_ADDR_LEN);
				aclRule.filter_fields |= INGRESS_IPV6_DIP_BIT;
				inet_pton(PF_INET6, "ff0e::0",(void *)ip6Addr);
				memcpy(aclRule.ingress_dest_ipv6_addr, ip6Addr, IPV6_ADDR_LEN);
				inet_pton(PF_INET6, "ff0f:0:0:0:0:0:0:0",(void *)mask);
				memcpy(aclRule.ingress_dest_ipv6_addr_mask, mask, IPV6_ADDR_LEN);
				aclRule.filter_fields |= INGRESS_IPV6_TAGIF_BIT;
				aclRule.ingress_ipv6_tagif = 1;
				aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
				aclRule.action_type = ACL_ACTION_TYPE_DROP;
				if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0) {
					fprintf(fp, "%d\n", aclIdx);
				} else {
					printf("[%s@%d] rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n",__func__,__LINE__, ret);
				}
			} else {
				memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
				aclRule.acl_weight = RG_FIREWALL_ACL_WEIGHT;
				aclRule.filter_fields |= INGRESS_PORT_BIT;
				aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();
				aclRule.filter_fields |= INGRESS_CTAG_VID_BIT;
				aclRule.ingress_ctag_vid = Entry.mVid;
				aclRule.filter_fields |= INGRESS_DMAC_BIT;
				memcpy(&aclRule.ingress_dmac,MCAST_ADDR,MAC_ADDR_LEN);
				memcpy(&aclRule.ingress_dmac_mask,MCAST_MASK,MAC_ADDR_LEN);
				aclRule.filter_fields |= INGRESS_IPV6_DIP_BIT;
				inet_pton(PF_INET6, "ff0e::0",(void *)ip6Addr);
				memcpy(aclRule.ingress_dest_ipv6_addr, ip6Addr, IPV6_ADDR_LEN);
				inet_pton(PF_INET6, "ff0f:0:0:0:0:0:0:0",(void *)mask);
				memcpy(aclRule.ingress_dest_ipv6_addr_mask, mask, IPV6_ADDR_LEN);
				aclRule.filter_fields |= INGRESS_IPV6_TAGIF_BIT;
				aclRule.ingress_ipv6_tagif = 1;
				aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
				aclRule.action_type = ACL_ACTION_TYPE_DROP;
				if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0) {
					fprintf(fp, "%d\n", aclIdx);
				} else {
					printf("[%s@%d] rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n",__func__,__LINE__, ret);
				}
			}
		}
	}
#endif
	
	fclose(fp);
}

#if defined(CONFIG_SECONDARY_IP)
#define ALIAS_IP_IDX_NUM 5
int RG_set_ip_alias(char *ifname, int ipver, int set)
{
	char file_path[64] = {0}, *tmp;
	struct in_addr inAddr;
	struct ipv6_ifaddr ip6_addr[6];
	unsigned char ip_version = IPVER_V4V6;
	unsigned char macAddr[6];
	unsigned int portMask = 0;
	unsigned int phy_portmask;
	int lanIdx = -1, ret = 0, aliasIdx = -1, vlan_id = 0, i;
	FILE *fp = NULL;
	rtk_rg_intfInfo_t intf_info;
	rtk_rg_lanIntfConf_t lan_info;
	
	if(ifname == NULL) return -1;

	if((tmp = strchr(ifname, ':'))){
		aliasIdx = atoi(tmp+1);
	}
	
	if(strncmp(ifname, "br0", 3) || aliasIdx < 0 || aliasIdx > ALIAS_IP_IDX_NUM)
	{
		DBPRINT(1, "Cannnot support config IP alias for %s\n",ifname);
		return -1;
	}
	
	memset(&lan_info,0,sizeof(rtk_rg_lanIntfConf_t));
	memset(&intf_info,0,sizeof(rtk_rg_intfInfo_t));
	
	sprintf(file_path, "%s_%s", RG_IP_ALIAS_INTF_IDX_FILE, ifname);
	fp = fopen(file_path, "r");
	if(fp)
	{
		if(fscanf(fp, "%d", &lanIdx)) {
			if(rtk_rg_intfInfo_find(&intf_info,&lanIdx)==SUCCESS){
				memcpy(&lan_info,&(intf_info.lan_intf),sizeof(rtk_rg_lanIntfConf_t));
			} else {
				DBPRINT(1, "Get LAN interface failed! lanIntfIdx=%d\n",lanIdx);
			}
		} else {
			DBPRINT(1, "Get LAN interface idx failed! ifname=%s\n",ifname);
		}
		fclose(fp);
		fp = NULL;
	}
	
	if(set)
	{
		//for ip alias need force ip verion to v4+v6, 
		//because bridge traffic will check RG lan intf ip version
		ip_version = IPVER_V4V6;
		if(ipver == IPVER_IPV4)
		{
			if(getInAddr(ifname, SUBNET_MASK, &inAddr) == 1 && ntohl(inAddr.s_addr))
			{
				lan_info.ip_network_mask = ntohl(inAddr.s_addr);
				if(getInAddr(ifname, IP_ADDR, &inAddr) == 1)
					lan_info.ip_addr = ntohl(inAddr.s_addr);
			}
		}
		else if(ipver == IPVER_IPV6)
		{
			if(getifip6(ifname, IPV6_ADDR_UNICAST, ip6_addr, 1) > 0)
			{
				memcpy(lan_info.ipv6_addr.ipv6_addr, &ip6_addr[0].addr, IPV6_ADDR_LEN);
				lan_info.ipv6_network_mask_length = ip6_addr[0].prefix_len;
			}
		}
		lan_info.ip_version = ip_version;
		
		if(lanIdx >= 0)
		{
			lan_info.replace_subnet = 1;
			if((rtk_rg_lanInterface_add(&lan_info,&lanIdx))!=SUCCESS)
			{
				DBPRINT(1, "Edit LAN interface failed! lanIntfIdx=%d\n",lanIdx);
				ret = -2;
			}
		}
		else
		{
			if (mib_get(MIB_ELAN_MAC_ADDR, (void *)macAddr) != 0)
				for(i =0;i<6;i++)
					lan_info.gmac.octet[i]=macAddr[i];
			
			if(mib_get(MIB_LAN_ALIAS_VLAN_ID, (void *)&vlan_id) != 0)
				lan_info.intf_vlan_id = vlan_id + aliasIdx;
			
			lan_info.vlan_based_pri=-1;
			lan_info.mtu=1500;
			
			mib_get(MIB_LAN_PORT_MASK1, (void *)&portMask);
			//portMask = ((1<<RTK_RG_MAC_PORT0)|(1<<RTK_RG_MAC_PORT1)|(1<<RTK_RG_MAC_PORT2)|(1<<RTK_RG_MAC_PORT3));
#if CONFIG_LAN_PORT_NUM > 4 // for RGMII port
			portMask |= (1<<(CONFIG_LAN_PORT_NUM-1));
#endif
			phy_portmask = RG_get_lan_phyPortMask(portMask);
			portMask = phy_portmask;
			portMask &= (~(RG_get_wan_phyPortMask())); //RoutingWan
#ifndef WLAN_DUALBAND_CONCURRENT
			lan_info.port_mask.portmask = portMask|(1 << RTK_RG_EXT_PORT0)|RTK_RG_ALL_CPU_PORTMASK;
#else
			lan_info.port_mask.portmask = portMask|(1 << RG_get_wlan_phyPortId(PMAP_WLAN0))|(1 << RG_get_wlan_phyPortId(PMAP_WLAN1))|RTK_RG_ALL_CPU_PORTMASK;
#endif
			lan_info.untag_mask.portmask = portMask;
			lan_info.untag_mask.portmask |= RTK_RG_ALL_MAC_CPU_PORTMASK; //UntagCPort
			
			lan_info.replace_subnet = 0;
			if((rtk_rg_lanInterface_add(&lan_info,&lanIdx))!=SUCCESS)
			{
				DBPRINT(1, "Add LAN interface failed! lanIntfIdx=%d\n",lanIdx);
				ret = -2;
			}
			else
			{
				if((fp = fopen(file_path, "w")))
				{
					fprintf(fp, "%d", lanIdx);
					fclose(fp);
					fp = NULL;
				}
				else
				{
					DBPRINT(1, "Add LAN interface failed! lanIntfIdx=%d, file_path=%s\n",lanIdx, file_path);
					ret = -3;
				}
			}
		}
	}
	else
	{
		if(lanIdx >= 0)
		{
			//for ip alias need force ip verion to v4+v6, 
			//because bridge traffic will check RG lan intf ip version
			ip_version = IPVER_V4V6;
			if(ipver == IPVER_IPV4)
			{
				lan_info.ip_addr = 0;
				lan_info.ip_network_mask = 0;
			}
			else if(ipver == IPVER_IPV6)
			{
				memset(lan_info.ipv6_addr.ipv6_addr, 0, IPV6_ADDR_LEN);
				lan_info.ipv6_network_mask_length = 0;
			}
			lan_info.ip_version = ip_version;
			
			if(lan_info.ip_network_mask == 0 && lan_info.ipv6_network_mask_length == 0)
			{
				if((rtk_rg_interface_del(lanIdx))==SUCCESS)
				{
					unlink(file_path);
				}
				else {
					DBPRINT(1, "Delete LAN interface failed! lanIntfIdx=%d\n",lanIdx);
					ret = -2;
				}
			}
			else{
				lan_info.replace_subnet = 1;
				if((rtk_rg_lanInterface_add(&lan_info, &lanIdx))!=SUCCESS)
				{
					DBPRINT(1, "Edit LAN interface failed! lanIntfIdx=%d\n",lanIdx);
					ret = -2;
				}
			}
		}
		else {
			DBPRINT(1, "Get LAN interface failed! ifname=%s\n",ifname);
			ret = -1;
		}
	}
	
	return ret;
}
#endif

