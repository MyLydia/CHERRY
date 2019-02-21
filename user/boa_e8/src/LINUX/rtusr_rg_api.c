#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <memory.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/config.h>
#include <rtk_rg_struct.h>
#include "rtusr_rg_api.h"
#include "mib.h"
#include "utility.h"
#include <ctype.h>
#include <unistd.h>
#include "ipv6_info.h"
#include <rtk_rg_liteRomeDriver.h>
#include <inttypes.h>

#ifdef CONFIG_TR142_MODULE
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <rtk/rtk_tr142.h>

#define TR142_DEV_FILE "/dev/rtk_tr142"
#endif

#if defined(CONFIG_USER_L2TPD_L2TPD) || defined(CONFIG_USER_PPTP_CLIENT_PPTP)
#include <sys/types.h>
#include <regex.h>
#endif
#ifdef CONFIG_RTK_OMCI_V1
#include <omci_dm_sd.h>
#endif

#ifdef CONFIG_USER_L2TPD_L2TPD
#include <sys/types.h>
#include <regex.h>
#endif
#include <sys/file.h>

#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
#define ACL_QOS_INTERNAL_PRIORITY_START 8
#else
#define ACL_QOS_INTERNAL_PRIORITY_START 4
#endif

const char DHCPC_ROUTERFILE_B[] = "/var/udhcpc/router";
const char RG_LAN_INF_IDX[] = "/var/rg_lan_inf_idx";
#ifdef CONFIG_CU
const char RG_ACL_RULES_LOOPBACK_FILE[] = "/var/rg_acl_rules_loopback_idx";
#endif
const char RG_MAC_RULES_FILE[] = "/var/rg_mac_rules_idx";
const char RG_MAC_ACL_RULES_FILE[] = "/var/rg_mac_acl_rules_idx";
const char RG_MAC_NAPT_RULES_FILE[] = "/var/rg_mac_napt_rules_idx";
const char RG_ACL_RULES_FILE[] = "/var/rg_acl_rules_idx";
const char RG_ACL_DEFAULT_RULES_FILE[] = "/var/rg_acl_default_rules_idx";
const char RG_ACL_PPPoE_PASS_RULES_FILE[] = "/var/rg_acl_PPPoE_pass_rules_idx";
const char RG_ACL_IPv6_RULES_FILE[] = "/var/rg_acl_ipv6_rules_idx";
const char RG_ACL_BRIDGE_IPv4IPv6_FILTER_RULES_FILE[] = "/var/rg_acl_bridge_ipv4ipv6_filter_rules_idx";
const char RG_QOS_RULES_FILE[] = "/var/rg_acl_qos_idx";
const char RG_QOS_RTP_RULES_FILE[] = "/var/rg_acl_qos_rtp_idx";
const char RG_PPPOEPROXY_RULES_FILE[] = "/var/rg_acl_pppoeproxy_idx";
const char RG_ACL_MVLAN_RULES_FILE[] = "/var/rg_acl_mvlan_rules_idx";
#ifdef SUPPORT_WEB_REDIRECT
const char RG_ACL_HTTP_RULES_FILE[] = "/var/rg_acl_webredirect_rules_idx";
#endif
#if defined (CONFIG_EPON_FEATURE) || defined(CONFIG_GPON_FEATURE)
const char RG_ROUTE_PPPOE_MULTICAST_ACL_FILE[] = "/var/rg_route_pppoe_mul_idx";
#endif
const char RG_ACL_USER_APP_RULES_FILE[] = "/var/rg_acl_user_app_rules_idx";
const char RG_UPNP_CONNECTION_FILE[] = "/var/rg_upnp_idx";
const char RG_UPNP_TMP_FILE[] = "/var/rg_upnp_tmp";
const char RG_VERTUAL_SERVER_FILE[] = "/var/rg_vertual_servers_idx";
const char RG_VIRTUAL_SERVER_FILE[] = "/var/rg_virtual_servers_idx";
const char RG_VIRTUAL_SERVER_IP_FILE[] = "/var/rg_virtual_servers_ip";
const char RG_DMZ_FILE[] = "/var/rg_dmz_info";
const char RG_URL_FILTER_FILE[] = "/var/rg_url_filter_idx";
const char MER_GWINFO_B[] = "/tmp/MERgw";
const char WAN_INTERFACE_TMP[] = "/var/wan_interface_tmp";
const char RG_GATEWAY_SERVICE_FILE[] = "/var/rg_gatewayService_idx";
const char RG_WIFI_INGRESS_RATE_LIMIT_FILE[] = "/proc/rg/wifi_ingress_rate_limit";
const char RG_WIFI_EGRESS_RATE_LIMIT_FILE[] = "/proc/rg/wifi_egress_rate_limit";
const char RG_IPV6_Bridge_From_Wan_ACL_RILES[] = "/var/rg_ipv6_bridge_from_wan";
const char RG_IPV4V6_Bridge_From_Wan_ACL_RILES[] = "/var/rg_ipv4v6_bridge_from_wan";

const char RG_IPV4_Bridge_From_Wan_ACL_RILES[] = "/var/rg_ipv4_bridge_from_wan";
const char RG_IPV6_PPPoE_From_Wan_KeepOVID_ACL_RILES[] = "/var/rg_ipv6_pppoe_from_wan";
const char RG_IPV4_PPPoE_From_Wan_KeepOVID_ACL_RILES[] = "/var/rg_ipv4_pppoe_from_wan";

#ifdef CONFIG_EPON_FEATURE
const char RG_Bridge_From_Lan_ACL_RILES[] = "/var/rg_bridge_from_lan";
#endif
const char RG_ACL_FOR_VPN_POLICY_ROUTE[] = "/var/rg_acl_for_vpn_policy_route";
const char RG_PATCH_FOR_AVALANCHE[] = "/var/rg_patch_for_avalanche";
const char RG_ALG_FILTER_FILE[] = "/var/rg_alg_filter_idx";
const char RG_DOS_FILTER_FILE[] = "/var/rg_dos_filter_idx";

const char RG_BRIDGE_INET_DHCP_RA_FILTER_FILE[] = "/var/rg_bridge_inet_dhcp_ra_filter_idx";
const char RG_ROUTE_V6_RA_NS_FILTER_FILE[] = "/var/rg_acl_rule_for_v6_RA_NS_idx";
const char RG_INTERNET_ACCESS_DENY_RULES_FILE[] = "/var/rg_internet_access_deny_rules_idx";
const char RG_INTERNET_ACCESS_NO_INTERNET_RULES_FILE[] = "/var/rg_internet_access_no_internet_rules_idx";
const char RG_MAX_US_BANDWIDTH_FILE[] = "/var/rg_max_us_bandwidth_idx";
const char RG_MAX_DS_BANDWIDTH_FILE[] = "/var/rg_max_ds_bandwidth_idx";
#ifdef CONFIG_RTL9600_SERIES
const char RG_TRAP_ACL_RULES_FILE[] = "/var/rg_trap_pppoe_acl_rules_idx";
#endif
#if defined(CONFIG_USER_PPPOE_PROXY)
const char RG_PPPOE_PROXY_RULES_FILE[] = "/var/rg_pppoe_proxy_rules_idx";
const char RG_PPPOE_PROXY_RULES_TEMP_FILE[] = "/var/rg_pppoe_proxy_rules_idx_temp";
#endif
const char RG_DHCP_TRAP_ACL_RULES_FILE[] = "/var/rg_trap_dhcp_acl_rules_idx";
const char RG_ICMPV6_TRAP_ACL_RULES_FILE[] = "/var/rg_trap_icmpv6_acl_rules_idx";

#ifdef _PRMT_X_CT_COM_LANBINDING_CONFIG_
const char RG_ACL_LAN_BINDING_RULES_FILE[] = "/var/rg_lan_binding_acl_rules_idx";
#endif
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
const char RG_HANDLE_PRI_TAG0_ACL_FILTER_FILE[] = "/var/rg_handle_pri_tag0_acl_filter_idx";
const char RG_ACL_CMCC_MAC_FILTER_FILE[] =  "/proc/osgi/mac_filter/mac_filter_add";
const char RG_BRIDGETYPE_RULES_FILE[] = "/var/rg_acl_bridgeType_idx";
#endif
#ifdef CONFIG_CMCC_FORWARD_RULE_SUPPORT
const char RG_ACL_CMCC_FORWARD_RULE_FILE[] = "/var/rg_acl_cmcc_forward_rules_idx";
const char RG_ACL_CMCC_FORWARD_RULE_TMP_FILE[] = "/var/rg_acl_cmcc_forward_rules_tmp_idx";
#endif
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
const char RG_MIRROR_ACL_RULES_FILE[] = "/var/rg_mirror_acl_rules_idx";
#endif
#ifdef CONFIG_CMCC_IPV6_SECURITY_SUPPORT
const char RG_IPV6_SEC_RULES_FILE[] = "/var/rg_acl_ipv6_sec_idx";
#endif
const char RG_WIFI_UNTAG_RULES_FILE[] = "/var/rg_acl_wifi_untag_idx";
#if defined(CONFIG_YUEME)
const char RG_INGRESS_CONTROL_PACKET_ACL_RULES_FILE[] = "/var/rg_control_ingress_packet_acl_rules_idx";
const char RG_EGRESS_CONTROL_PACKET_ACL_RULES_FILE[] = "/var/rg_control_egress_packet_acl_rules_idx";
const char RG_INGRESS_CONTROL_ITMS_PACKET_ACL_RULES_FILE[] = "/var/rg_control_ingress_itms_packet_acl_rules_idx";
const char RG_EGRESS_CONTROL_ITMS_PACKET_ACL_RULES_FILE[] = "/var/rg_control_egress_itms_packet_acl_rules_idx";
#endif
#if (defined(CONFIG_CMCC) || defined(CONFIG_CU)) && defined(CONFIG_IPV6)
const char RG_ACL_IPV6_BINDING_RULES_FILE[] = "/var/rg_acl_ipv6_binding_rules_idx";
const char RG_IPV4V6_DUAL_POLICYROUTE_RULES_FILE[] = "/var/rg_acl_ipv4v6_dual_policyroute_idx";
const char RG_ACL_VLAN_INGRESS_RULES_FILE[] =  "/var/rg_acl_vlan_ingress_rules_idx";
#endif

#ifdef CONFIG_USER_CUMANAGEDEAMON
const char RG_ACL_FILTER_DSCP_REMAKR_FILE[] = "/var/rg_dscp_remark_rules_idx";
const char RG_ACL_FILTER_DSCP_REMAKR_TEMP_FILE[] = "/var/rg_dscp_remark_rules_idx_temp";
#endif
const char RG_IGMP_PROXY_ACL_RULE_FILE[] = "/var/rg_igmp_proxy_acl_idx";
const char RG_MLD_PROXY_ACL_RULE_FILE[] = "/var/rg_mld_proxy_acl_idx";

const char RG_IGMP_SNOOP_ACL_RULES_FILE[] = "/var/rg_igmp_snoop_rules_idx";
const char RG_MLD_SNOOP_ACL_RULES_FILE[] = "/var/rg_mld_snoop_rules_idx";

const char RG_ACL_VLAN_BINDING_DS_MC_RULES_FILE[] = "/var/rg_vlan_binding_ds_mc_acl_rules_idx";

#ifdef CONFIG_YUEME
const char RG_WIFI_ACCESS_RULE_FILE[] = "/var/rg_acl_wifi_accessrule_idx";
#endif

#define UntagCPort 1
#define TagCPort 0
#define OMCI_WAN_INFO "/proc/omci/wanInfo"
#define WLAN0_PHY_PORT_ID 7
#if ! defined(_LINUX_2_6_) && defined(CONFIG_TR142_MODULE)
#define TR142_WAN_IDX_MAP "/proc/rtk_tr142/wan_idx_map"
#endif
#ifdef CONFIG_MCAST_VLAN
char MCAST_ADDR[MAC_ADDR_LEN]={0x01,0x00,0x5E,0x00,0x00,0x00};
char MCAST_MASK[MAC_ADDR_LEN]={0xff,0xff,0xff,0x00,0x00,0x00};
char MCAST_ADDR_V6[MAC_ADDR_LEN]={0x33,0x33,0x00,0x00,0x00,0x00};
char MCAST_MASK_V6[MAC_ADDR_LEN]={0xff,0xff,0x00,0x00,0x00,0x00};
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
#define MAX_VALUE(val1, val2) (val1>val2?val1:val2)
#define MIN_VALUE(val1, val2) (val1<val2?val1:val2)
int RG_WAN_Interface_Del(unsigned int rg_wan_idx);
unsigned int RG_get_lan_phyPortMask(unsigned int portmask);
unsigned int RG_get_all_lan_phyPortMask(void);
unsigned int RG_get_wan_phyPortMask();
void RTK_Setup_Storm_Control(void);
#if defined(CONFIG_USER_PPTP_CLIENT_PPTP) && defined(CONFIG_USER_L2TPD_L2TPD)
unsigned int load_vpn_packet_count_by_ip(VPN_TYPE_T vpn_type, unsigned long ip);
unsigned int load_vpn_packet_count_by_route_idx(VPN_TYPE_T vpn_type, unsigned int route_idx);
#endif
void ddos_smurf_attack_protect(void);
void assign_loopback_detect_to_high_queue(void);

//int patch_for_avalanche=0;
#ifdef CONFIG_RTL9600_SERIES
void trap_pppoe(int trap_action, int wan_ifIndex, char * ifname, unsigned char proto);
#endif

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

#ifdef CONFIG_RTK_HOST_SPEEDUP
int flush_rg_cf_rule_for_speedtest(void)
{
#ifdef CONFIG_RTL9607C
	//cxy 2018-3-27:9607C RG not set classf to hw, so use rtk api to del cf rule
	rtk_classify_cfgEntry_del(64);
#else
	rtk_rg_classifyEntry_del(64);
#endif
	return 0;
}

int add_rg_cf_rule_for_speedtest(MIB_CE_ATM_VC_T *pEntry, int flowid)
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
#endif

#ifdef CONFIG_IPV6
void add_acl_rule_for_v6_RA(int vid)
{
	rtk_rg_aclFilterAndQos_t aclRule;
	int aclIdx=0;
	unsigned char ip6Addr[IP6_ADDR_LEN]={0};
	char cmd[256] = {0};

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
	
	if(vid > 0){
   		aclRule.filter_fields |= INGRESS_CTAGIF_BIT;
		aclRule.ingress_ctagIf = 1;
		//rg set acl-filter pattern ingress_ctag_vid 45
		aclRule.filter_fields |= INGRESS_CTAG_VID_BIT;
		aclRule.ingress_ctag_vid = vid;
	}
	
	aclRule.acl_weight = RG_TRAP_ACL_WEIGHT;

	aclRule.action_type = ACL_ACTION_TYPE_TRAP_TO_PS;

	if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0)
	{	
		//fprintf(fp, "%d\n", aclIdx);
		sprintf(cmd, "echo %d >> %s", aclIdx, RG_ICMPV6_TRAP_ACL_RULES_FILE);
		system(cmd);
		printf("Add ACl Rule for ff02::1 Successfully %d\n",aclIdx);
	}else
		printf("Error! Add ACl Rule for ff02::1 Faile\n");

	printf("exit %s\n",__func__);
}

/* ff02::1:ff00:0/104 Solicited-node multicast address */
void add_acl_rule_for_v6_NS(int vid)
{
	rtk_rg_aclFilterAndQos_t aclRule;
	int aclIdx=0;
	unsigned char ip6Addr[IP6_ADDR_LEN]={0};
	char cmd[256] = {0};

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

	if(vid > 0){
   		aclRule.filter_fields |= INGRESS_CTAGIF_BIT;
		aclRule.ingress_ctagIf = 1;
		//rg set acl-filter pattern ingress_ctag_vid 45
		aclRule.filter_fields |= INGRESS_CTAG_VID_BIT;
		aclRule.ingress_ctag_vid = vid;
	}

	aclRule.acl_weight = RG_TRAP_ACL_WEIGHT;

	aclRule.action_type = ACL_ACTION_TYPE_TRAP_TO_PS;

	if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0)
	{
		//fprintf(fp, "%d\n", aclIdx);
		sprintf(cmd, "echo %d >> %s", aclIdx, RG_ICMPV6_TRAP_ACL_RULES_FILE);
		system(cmd);
		printf("Add ACl Rule for ff02::1:ff00:0/104 (Neighbor Solictaion) Successfully %d\n",aclIdx);
	}else
		printf("Error! Add ACl Rule for ff02::1:ff00:0/104 (Neighbor Solictaion) Faile\n");

	printf("exit %s\n",__func__);
}

void RTK_RG_add_acl_rule_for_v6_icmp()
{
	int ret, totalVC_entry,i;
	MIB_CE_ATM_VC_T entryVC;
	totalVC_entry = mib_chain_total(MIB_ATM_VC_TBL);
	char mode;
	mib_get(MIB_MPMODE, (void *)&mode);

	RTK_RG_del_acl_rule_for_v6_icmp();
	
	for(i=0;i<totalVC_entry;i++){
		if(mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&entryVC) == 0)
			continue;
		if (entryVC.enable == 0)
			continue;
		if(entryVC.cmode == CHANNEL_MODE_BRIDGE)
			continue;
		if(entryVC.IpProtocol == IPVER_IPV4)
			continue;

		if((mode&MP_MLD_MASK)!=MP_MLD_MASK){
			add_acl_rule_for_v6_RA(entryVC.vid);
			add_acl_rule_for_v6_NS(entryVC.vid);
		}
	}
}

void RTK_RG_del_acl_rule_for_v6_icmp()
{
	FILE *fp = NULL;
	int aclIdx = -1;
	char filename[64] = {0};

	sprintf(filename, "%s", RG_ICMPV6_TRAP_ACL_RULES_FILE);
	if (!(fp = fopen(filename, "r"))) {
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return;
	}

	while (fscanf(fp, "%d\n", &aclIdx) != EOF)
	{
		if (rtk_rg_aclFilterAndQos_del(aclIdx))
			DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", aclIdx);
	}
	fclose(fp);
	unlink(filename);
	
	return;
}
#endif

int Init_rg_api()
{
	int ret;
	unsigned char mbtd;
	rtk_rg_initParams_t init_param;
	unsigned int vid;
	unsigned char avalanche_en=0,value;
	FILE *fp = NULL;
	FILE *fp_proc = NULL;
	unsigned short portmaskA, portmaskB;
	char buf[200]={0};
	rtk_rg_aclFilterAndQos_t aclRule;
	int aclIdx;
	bzero(&init_param, sizeof(rtk_rg_initParams_t));
	printf("init mac based tag des\n");

	mib_get(MIB_MAC_BASED_TAG_DECISION, (void *)&mbtd);
	init_param.macBasedTagDecision = mbtd;

#if 1
	//add for storm control
	sprintf(buf,"echo 1 > /proc/rg/layer2LookupMissFlood2CPU\n");
	system(buf);
#endif


#ifdef CONFIG_LUNA
#if defined(CONFIG_GPON_FEATURE) || defined(CONFIG_EPON_FEATURE)
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
	mib_get(MIB_AVALANCHE_ENABLE, (void *)&avalanche_en);
	/*
		system("echo 0 > /proc/rg/tcp_hw_learning_at_syn");
		system("echo 0 > /proc/rg/tcp_in_shortcut_learning_at_syn");
		system("echo 0 > /proc/rg/trap_syn_and_disable_svlan");
	*/

	fp = fopen("/proc/rg/tcp_hw_learning_at_syn", "w");
	if(fp)
	{
		fprintf(fp, "0\n");
		fclose(fp);
	}else
		fprintf(stderr, "open /proc/rg/tcp_hw_learning_at_syn fail!\n");

		usleep(300000);
		fp = fopen("/proc/rg/tcp_in_shortcut_learning_at_syn", "w");
		if(fp)
		{
			fprintf(fp, "0\n");
			fclose(fp);
		}else
			fprintf(stderr, "open /proc/rg/tcp_in_shortcut_learning_at_syn fail!\n");

		usleep(300000);
		fp = fopen("/proc/rg/trap_syn_and_disable_svlan", "w");
		if(fp)
		{
			fprintf(fp, "0\n");
			fclose(fp);
		}else
			fprintf(stderr, "open /proc/rg/trap_syn_and_disable_svlan fail!\n");

	// default disable, for wan/lan giga/100 use
	if(avalanche_en == 1)
	{
		//#turn_off_congestion_ctrl
		//#turn it on after rg init~
		// write proc interface(/proc/rg/bridgeWan_drop_by_protocal)
		usleep(300000);
		fp = fopen("/proc/rg/congestion_ctrl_port_mask", "w");
		if(fp)
		{
			fprintf(fp, "0x0\n");
			fclose(fp);
		}else
			fprintf(stderr, "open /proc/rg/congestion_ctrl_port_mask fail!\n");

		usleep(300000);
		fp = fopen("/proc/rg/congestion_ctrl_send_remainder_in_next_gap", "w");
		if(fp)
		{
			fprintf(fp, "0\n");
			fclose(fp);
		}else
			fprintf(stderr, "open /proc/rg/congestion_ctrl_send_remainder_in_next_gap fail!\n");

		usleep(300000);
		fp = fopen("/proc/rg/congestion_ctrl_inbound_ack_to_high_queue", "w");
		if(fp)
		{
			fprintf(fp, "0\n");
			fclose(fp);
		}else
			fprintf(stderr, "open /proc/rg/congestion_ctrl_inbound_ack_to_high_queue fail!\n");

/*
		system("echo 0 > /proc/rg/tcp_hw_learning_at_syn");
		system("echo 0 > /proc/rg/tcp_in_shortcut_learning_at_syn");
		system("echo 0 > /proc/rg/trap_syn_and_disable_svlan");
		system("echo 0x0 > /proc/rg/congestion_ctrl_port_mask");
		system("echo 0 > /proc/rg/congestion_ctrl_send_remainder_in_next_gap");
		system("echo 0 > /proc/rg/congestion_ctrl_inbound_ack_to_high_queue");
*/
	}
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

#ifdef CONFIG_RG_BRIDGE_PPP_STATUS
	//init_param.initByHwCallBack = 0xfffffffe;
	{
		char cmd[100], buff[256], addrstr[16];
		FILE *fp;
		unsigned int addr=0;
		sprintf(cmd, "echo 1 > /proc/rg/proc_to_pipe");
		va_cmd("/bin/sh", 2, 1, "-c", cmd);
		sprintf(cmd, "cat /proc/rg/callback | grep _rtk_rg_pppoeLCPStateCallBack > /tmp/lcp.callback");
		va_cmd("/bin/sh", 2, 1, "-c", cmd);
		sprintf(cmd, "echo 0 > /proc/rg/proc_to_pipe");
		va_cmd("/bin/sh", 2, 1, "-c", cmd);
		if ((fp = fopen("/tmp/lcp.callback", "r")) != 0)
		{
			if(fgets(buff, 256, fp)!=NULL)
			{
				//printf("[%s %d]buff=%s\n", __func__, __LINE__, buff);
				if(sscanf(buff, "%*s%s\n", addrstr)!= -1)
				{
					//printf("[%s %d]addrstr=%s\n", __func__, __LINE__, addrstr);
					addr = strtoul(addrstr, NULL, 16);
					init_param.pppoeLCPStateCallBack = (p_pppoeLCPStateCallBack)addr;
					printf("[%s %d]init_param.pppoeLCPStateCallBack=0x%x\n", __func__, __LINE__, addr);
				}
			}
			fclose(fp);
			unlink("/tmp/lcp.callback");
		}
		else
		{
			printf("[%s %d]can not open /tmp/lcp.callback\n", __func__, __LINE__);
		}
	}
#endif

/*To configure user's define vlan id range*/
	mib_get(MIB_FWD_CPU_VLAN_ID, (void *)&vid);
	init_param.fwdVLAN_CPU = vid;
	//AUG_PRT("%s-%d fwdVLAN_CPU=%d\n",__func__,__LINE__,init_param.fwdVLAN_CPU);

	mib_get(MIB_FWD_PROTO_BLOCK_VLAN_ID, (void *)&vid);
	init_param.fwdVLAN_Proto_Block = vid;
	//AUG_PRT("%s-%d fwdVLAN_Proto_Block=%d\n",__func__,__LINE__,init_param.fwdVLAN_Proto_Block);

	mib_get(MIB_FWD_BIND_INTERNET_VLAN_ID, (void *)&vid);
	init_param.fwdVLAN_BIND_INTERNET = vid;
	//AUG_PRT("%s-%d fwdVLAN_BIND_INTERNET=%d\n",__func__,__LINE__,init_param.fwdVLAN_BIND_INTERNET);

	mib_get(MIB_FWD_BIND_OTHER_VLAN_ID, (void *)&vid);
	init_param.fwdVLAN_BIND_OTHER = vid;
	//AUG_PRT("%s-%d fwdVLAN_BIND_OTHER=%d\n",__func__,__LINE__,init_param.fwdVLAN_BIND_OTHER);


#ifdef CONFIG_YUEME_DPI
	// Get DPI callback function pointer from kernel space & add DPI callback
	rtk_rg_callbackFunctionPtrGet_t callback_function_ptr_get_info;
	uintptr_t mem;

	callback_function_ptr_get_info.callback_function_idx = DPI_NAPT_INFO_ADD_CALLBACK_IDX;
	if(!rtk_rg_callback_function_ptr_get(&callback_function_ptr_get_info)) {
		mem = callback_function_ptr_get_info.callback_function_pointer;
		printf("mem:%" PRIXPTR " , func:DPI_naptInfoAddCallBack\n", mem);
		init_param.softwareNaptInfoAddCallBack = (p_naptAddByHwCallBack)mem;
	} else {
		AUG_PRT("rtk_rg_callback_function_ptr_get fail!\n");
	}

	callback_function_ptr_get_info.callback_function_idx = DPI_NAPT_INFO_DEL_CALLBACK_IDX;
	if(!rtk_rg_callback_function_ptr_get(&callback_function_ptr_get_info)) {
		mem = callback_function_ptr_get_info.callback_function_pointer;
		printf("mem:%" PRIXPTR" , func:DPI_naptInfoDeleteCallBack\n", mem);
		init_param.softwareNaptInfoDeleteCallBack =(p_naptDelByHwCallBack)mem;
	} else {
		AUG_PRT("rtk_rg_callback_function_ptr_get fail!\n");
	}

	callback_function_ptr_get_info.callback_function_idx = DPI_NAPT_PREROUTING_CALLBACK_IDX;
	if(!rtk_rg_callback_function_ptr_get(&callback_function_ptr_get_info)) {
		mem = callback_function_ptr_get_info.callback_function_pointer;
		printf("mem:%" PRIXPTR " , func:DPI_naptPreRouteCallBack\n", mem);
		init_param.naptPreRouteDPICallBack =(p_naptPreRouteDPICallBack) mem;
	} else {
		AUG_PRT("rtk_rg_callback_function_ptr_get fail!\n");
	}

	callback_function_ptr_get_info.callback_function_idx = DPI_NAPT_FORWARDING_CALLBACK_IDX;
	if(!rtk_rg_callback_function_ptr_get(&callback_function_ptr_get_info)) {
		mem = callback_function_ptr_get_info.callback_function_pointer;
		printf("mem:%" PRIXPTR " , func:DPI_naptForwardCallBack\n", mem);
		init_param.naptForwardDPICallBack = (p_naptForwardDPICallBack)mem;
	} else {
		AUG_PRT("rtk_rg_callback_function_ptr_get fail!\n");
	}
#endif

#if (defined(CONFIG_CMCC) || defined(CONFIG_CU)) && defined(MAC_FILTER)
	{
		rtk_rg_callbackFunctionPtrGet_t callback_function_ptr_get_info;
		unsigned int mem; 	
		callback_function_ptr_get_info.callback_function_idx = MAC_ADD_BY_HW_CALLBACK_IDX;
		if(!rtk_rg_callback_function_ptr_get(&callback_function_ptr_get_info)){
			mem = callback_function_ptr_get_info.callback_function_pointer;
			AUG_PRT("mem:%X , func:_rtk_rg_macAddByHwCallBack\n", mem);
			init_param.macAddByHwCallBack = (p_macAddByHwCallBack)mem;
		}else{
			AUG_PRT("rtk_rg_callback_function_ptr_get fail!\n");
		}
	}
#endif

#if defined(CONFIG_RTL_IGMP_SNOOPING)
	char igmp_mode;
	mib_get(MIB_MPMODE, (void *)&igmp_mode);
	if(igmp_mode & MP_IGMP_MASK)
		init_param.igmpSnoopingEnable = 1;
	else
		init_param.igmpSnoopingEnable = 0;
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

#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	FILE* fp_rg;
	if (fp_rg=fopen("/tmp/RG_init_finish", "w"))
	{    
		fprintf(stderr, "Create check point of RG_init...\n"); 
		fclose(fp_rg);
	}    
	else  
		fprintf(stderr, "Create check point of RG_init failed...\n"); 
#endif

#ifdef CONFIG_NF_CONNTRACK_FTP
	//we didn't know web's default value, but avalanche test may
	//need to turn on alg for FTP.
	if(mib_get(MIB_IP_ALG_FTP, &value) && value == 1){
		rtk_rg_alg_type_t alg_app = 0;
		rtk_rg_algApps_get(&alg_app);
		alg_app |= RTK_RG_ALG_FTP_TCP_BIT | RTK_RG_ALG_FTP_UDP_BIT;
		rtk_rg_algApps_set(alg_app);
	}
#endif

	if(avalanche_en == 1)
	{
		//(1) FTP algmask (0xc0)
		//add to trap unicast packet
/*
		rg clear acl-filter
		rg set acl-filter fwding_type_and_direction 0
		rg set acl-filter action action_type 2
		rg set acl-filter pattern ingress_dmac 0:0:0:0:0:0
		rg set acl-filter pattern ingress_dmac_mask 1:0:0:0:0:0
		rg set acl-filter pattern ingress_port_mask 0x10
		rg add acl-filter entry

*/
		if(!(fp = fopen(RG_PATCH_FOR_AVALANCHE, "a")))
		{
			fprintf(stderr, "ERROR! %s\n", strerror(errno));
			return -2;
		}

		memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
		aclRule.fwding_type_and_direction =  ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
		aclRule.action_type = ACL_ACTION_TYPE_TRAP;
		aclRule.filter_fields |= INGRESS_DMAC_BIT;
		aclRule.ingress_dmac.octet[0] = 0;
		aclRule.ingress_dmac.octet[1] = 0;
		aclRule.ingress_dmac.octet[2] = 0;
		aclRule.ingress_dmac.octet[3] = 0;
		aclRule.ingress_dmac.octet[4] = 0;
		aclRule.ingress_dmac.octet[5] = 0;
		aclRule.ingress_dmac_mask.octet[0] = 0x1;
		aclRule.ingress_dmac_mask.octet[1] = 0;
		aclRule.ingress_dmac_mask.octet[2] = 0;
		aclRule.ingress_dmac_mask.octet[3] = 0;
		aclRule.ingress_dmac_mask.octet[4] = 0;
		aclRule.ingress_dmac_mask.octet[5] = 0;
		aclRule.filter_fields |= INGRESS_PORT_BIT;
		aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();//wan port
		//rg add acl-filter entry
		if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0){
			fprintf(fp,"%d\n",aclIdx);
			//fprintf(stderr, "add %s-%d Vlan:%d, index=%d success\n",__func__,__LINE__,entry->vid, aclIdx);
		}else{
			fprintf(stderr,"%s-%d add rule failed! (ret = %d)\n",__func__,__LINE__, ret);
			fclose(fp);
			return -1;
		}
		/*
		rg clear acl-filter
		rg set acl-filter fwding_type_and_direction 0
		rg set acl-filter action action_type 2
		rg set acl-filter pattern ingress_port_mask 0xf
		rg set acl-filter pattern ingress_dest_l4_port_start 80 ingress_dest_l4_port_end 80
		rg set acl-filter pattern ingress_src_ipv4_addr_start 0.0.0.0 ingress_src_ipv4_addr_end 255.255.255.255
		rg add acl-filter entry
		*/
		memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
		aclRule.fwding_type_and_direction =  ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
		aclRule.action_type = ACL_ACTION_TYPE_TRAP;
		aclRule.filter_fields |= INGRESS_PORT_BIT;
		aclRule.ingress_port_mask.portmask = RG_get_all_lan_phyPortMask();
		aclRule.filter_fields |= INGRESS_L4_DPORT_RANGE_BIT;
		aclRule.ingress_dest_l4_port_start = 80;
		aclRule.ingress_dest_l4_port_end = 80;
		aclRule.filter_fields |= INGRESS_IPV4_SIP_RANGE_BIT;
		aclRule.filter_fields |= INGRESS_IPV4_TAGIF_BIT;
		aclRule.ingress_ipv4_tagif = 1;
		aclRule.ingress_src_ipv4_addr_start = 0x0;
		aclRule.ingress_src_ipv4_addr_end = 0xffffffff;
		//rg add acl-filter entry
		if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0){
			fprintf(fp,"%d\n",aclIdx);
			//fprintf(stderr, "add %s-%d Vlan:%d, index=%d success\n",__func__,__LINE__,entry->vid, aclIdx);
		}else{
			fprintf(stderr,"%s-%d add rule failed! (ret = %d)\n",__func__,__LINE__, ret);
			fclose(fp);
			return -1;
		}
		fclose(fp);

#if defined(CONFIG_PON_LED_PROFILE_DEMO_RTL9607) || defined(CONFIG_PON_LED_PROFILE_DEMO_RTL9607_IAD_V00) || defined(CONFIG_PON_LED_PROFILE_DEMO_RTL9607_IAD_V01)
//		system("echo 0xd > /proc/rg/congestion_ctrl_port_mask");
		usleep(300000);
		fp_proc = fopen("/proc/rg/congestion_ctrl_port_mask", "w");
		if(fp_proc)
		{
			//we use 9607 to simulate 9603 case filled at 0x5!!
			//In the future, if we use 9607 model to
			//do e8c avalanche test, we must disable congestion ctrl.
			// giga port and multicast port not join into congestion port mask
			// 4 lan port:config lan port 2 as iptv
			// 2 lan port:config lan port 2 as iptv
			// phy port 3 is giga port
			if(CONFIG_LAN_PORT_NUM == 2){
				//two port case
				fprintf(fp_proc, "0x4\n");//to exclude phy port 3
			}
			else{
				//four port case
				portmaskA = 0x7;//to exclude phy port 3
				portmaskB = RG_get_lan_phyPortMask(0x2);
				portmaskA &= ~(portmaskB);//clear iptv port
				//AUG_PRT("portmask=0x%x\n",portmaskA);
				fprintf(fp_proc, "0x%x\n",portmaskA);
			}

			fclose(fp_proc);
		}else
			fprintf(stderr, "open /proc/rg/congestion_ctrl_port_mask fail!\n");

#elif defined(CONFIG_PON_LED_PROFILE_DEMO_RTL9602B) || defined(CONFIG_RTL9602C_SERIES)
//		system("echo 0x4 > /proc/rg/congestion_ctrl_port_mask");
		usleep(300000);
		fp_proc = fopen("/proc/rg/congestion_ctrl_port_mask", "w");
		if(fp_proc)
		{
#if defined(CONFIG_RTL9602C_SERIES)
			fprintf(fp_proc, "0x1\n");//to exclude phy port 1 (giga port)
#else
			fprintf(fp_proc, "0x4\n");
#endif
			fclose(fp_proc);
		}else
			fprintf(stderr, "open /proc/rg/congestion_ctrl_port_mask fail!\n");

#endif
//		system("echo 1000 > /proc/rg/congestion_ctrl_interval_usec");
		usleep(300000);
		fp_proc = fopen("/proc/rg/congestion_ctrl_interval_usec", "w");
		if(fp_proc)
		{
			fprintf(fp_proc, "1000\n");
			fclose(fp_proc);
		}else
			fprintf(stderr, "open /proc/rg/congestion_ctrl_interval_usec fail!\n");

//		system("echo 12600000 > /proc/rg/congestion_ctrl_send_byte_per_sec");
		usleep(300000);
		fp_proc = fopen("/proc/rg/congestion_ctrl_send_byte_per_sec", "w");
		if(fp_proc)
		{
			fprintf(fp_proc, "12600000\n");
			fclose(fp_proc);
		}else
			fprintf(stderr, "open /proc/rg/congestion_ctrl_send_byte_per_sec fail!\n");

//		system("echo 1 > /proc/rg/congestion_ctrl_send_remainder_in_next_gap");
		usleep(300000);
		fp_proc = fopen("/proc/rg/congestion_ctrl_send_remainder_in_next_gap", "w");
		if(fp_proc)
		{
			fprintf(fp_proc, "1\n");
			fclose(fp_proc);
		}else
			fprintf(stderr, "open /proc/rg/congestion_ctrl_send_remainder_in_next_gap fail!\n");

//		system("echo 1 > /proc/rg/congestion_ctrl_inbound_ack_to_high_queue");
		usleep(300000);
		fp_proc = fopen("/proc/rg/congestion_ctrl_inbound_ack_to_high_queue", "w");
		if(fp_proc)
		{
			fprintf(fp_proc, "1\n");
			fclose(fp_proc);
		}else
			fprintf(stderr, "open /proc/rg/congestion_ctrl_inbound_ack_to_high_queue fail!\n");

		usleep(300000);
		//system("echo 1 > /proc/rg/trap_syn_and_disable_svlan");
		fp_proc = fopen("/proc/rg/trap_syn_and_disable_svlan", "w");
		if(fp_proc)
		{
			fprintf(fp_proc, "1\n");
			fclose(fp_proc);
		}else
			fprintf(stderr, "open /proc/rg/trap_syn_and_disable_svlan fail!\n");

		usleep(300000);
		//system("echo 1 > /proc/rg/tcp_hw_learning_at_syn");
		fp_proc = fopen("/proc/rg/tcp_hw_learning_at_syn", "w");
		if(fp_proc)
		{
			fprintf(fp_proc, "1\n");
			fclose(fp_proc);
		}else
			fprintf(stderr, "open /proc/rg/tcp_hw_learning_at_syn fail!\n");

		usleep(300000);
		//system("echo 1 > /proc/rg/tcp_in_shortcut_learning_at_syn");
		fp_proc = fopen("/proc/rg/tcp_in_shortcut_learning_at_syn", "w");
		if(fp_proc)
		{
			fprintf(fp_proc, "1\n");
			fclose(fp_proc);
		}else
			fprintf(stderr, "open /proc/rg/tcp_in_shortcut_learning_at_syn fail!\n");

	}
	printf("=============Init_rg_api SUCESS!!==================\n");
	unlink(RG_LAN_INF_IDX);

	// RA from WAN will go to LAN
	// so trap to protocol stack
	//add_acl_rule_for_v6_RA();
	//add_acl_rule_for_v6_NS();

	//char buf[200]={0};
	sprintf(buf,"echo 1 > /proc/rg/proc_to_pipe\n");
	system(buf);
	// set 1p prioity to intpri
	if(rtk_rg_qosDot1pPriRemapToInternalPri_set(7,5) == 0)
		printf("Set 1p priority 7 to internal priority 5\n");

	RTK_Setup_Storm_Control();
#if defined(CONFIG_GPON_FEATURE) || defined(CONFIG_EPON_FEATURE)
	#ifdef CONFIG_YUEME
        if (pon_mode == EPON_MODE )
        {
		printf("EPON change flowcontrol value\n");
		system("diag flowctrl set ingress system drop-threshold high-on threshold 5800");
		system("diag flowctrl set ingress system drop-threshold high-off threshold 5600");
		system("diag flowctrl set ingress system drop-threshold low-on threshold 5600");
		system("diag flowctrl set ingress system drop-threshold low-off threshold 5400");
        }
	#endif
#endif
	//sync kernel port range into rg
	fp_proc = fopen("/proc/sys/net/ipv4/ip_local_port_range", "r");		
	if(fp_proc!=NULL)	
	{
		FILE *fp_rg = NULL;
		int portA=0, portB=0;
		fseek(fp_proc, 0, SEEK_SET);	
		fgets(buf, sizeof(buf), fp_proc);
		sscanf(buf,"%d %d",&portA,&portB);
		//AUG_PRT("portA=%d, portB=%d\n",portA,portB);		
		fp_rg = fopen("proc/rg/port_range_used_by_ps","w+");
		if(fp_rg){
			//fprintf(fp_rg, "%d %d\n",portA,portB);
			//fprintf(fp_rg, "%d %d\n",10000,20000);
			fprintf(fp_rg, "%d %d\n",2000,12000);			
			fclose(fp_rg);
		}
		fclose(fp_proc);
		system(" echo 300 > /proc/rg/tcp_short_timeout");		
	}else{
		printf("file /proc/sys/net/ipv4/ip_local_port_range open failed\n");		
	}
	/*
	trap link-local 
	rg clear acl-filter
	rg set acl-filter fwding_type_and_direction 0
	rg set acl-filter action action_type 2
	rg set acl-filter pattern ingress_dest_ipv6_addr fe80:0000:0000:0000:0000:0000:0000:0000
	rg set acl-filter pattern ingress_dest_ipv6_addr_mask ffff:0000:0000:0000:0000:0000:0000:0000
	rg set acl-filter pattern ingress_port_mask 0x10
	rg add acl-filter entry
	*/
	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	aclRule.fwding_type_and_direction =  ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	aclRule.filter_fields |= INGRESS_PORT_BIT;
	aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();//wan port
	aclRule.acl_weight = RG_QOS_ACL_WEIGHT;
	aclRule.filter_fields |= INGRESS_IPV6_TAGIF_BIT;
	aclRule.ingress_ipv6_tagif = 1;
	aclRule.filter_fields |= INGRESS_IPV6_DIP_BIT;
	aclRule.ingress_dest_ipv6_addr[0]=0xfe;
	aclRule.ingress_dest_ipv6_addr[1]=0x80;
	aclRule.ingress_dest_ipv6_addr_mask[0]=0xff;
	aclRule.ingress_dest_ipv6_addr_mask[1]=0xff;
	aclRule.action_type = ACL_ACTION_TYPE_TRAP;
	if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0){
		printf("add trap link-local ok!\n");
	}else{
		fprintf(stderr,"%s-%d add rule failed! (ret = %d)\n",__func__,__LINE__, ret);
	}
	// handle dmac to cvid enable
	{
		unsigned char dmac2cvid;
		mib_get(MIB_MAC_DMAC2CVID_DISABLE, (void *)&dmac2cvid);
		if(dmac2cvid == 1)
		{
			printf("Disable DMAC to CVID !!\n");
			system("echo 1 > /proc/rg/wan_dmac2cvid_force_disabled");
		}
		else
		{
			printf("Enable DMAC to CVID !!\n");
			system("echo 0 > /proc/rg/wan_dmac2cvid_force_disabled");
		}
    }
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
#elif defined(CONFIG_LUNA_G3_SERIES)
	{
		//mask port 7
		system("echo 0xffffff7f > /proc/rg/igmp_report_ingress_filter_portmask");
	}
#else
	{		
		//apollo series mask port 4
		system("echo 0xffef > /proc/rg/igmp_report_ingress_filter_portmask");
	}
#endif	

#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	system("/bin/echo 1 > /proc/rg/keepWifiUntagToPS");
	RG_tcp_stateful_tracking(0);
#endif
#ifdef CONFIG_YUEME
	// auto detect PBO configuration
	system("echo 1 >/proc/rg/disableSWPBOAutoConf");
	// for L3 stateful 
	system("echo 2 > /proc/rg/L3TcpUdpStatefulTracking");
#endif 

#ifdef CONFIG_RTL9607C_SERIES
	system("echo 1 > /proc/rg/igmp_auto_learn_ctagif");
#endif

#ifdef CONFIG_RTL9600_SERIES
		mib_get(PROVINCE_IGMP_PPPOE_PASSTHROUGH_LEARN, (void *)&value);
		if(value == 1)
			system("echo 1 > /proc/rg/igmp_pppoe_passthrough_learning");
		else
			system("echo 0 > /proc/rg/igmp_pppoe_passthrough_learning");		
	
		mib_get(PROVINCE_WAN_RING_CHECK_ETH_TYPE, (void *)&value);
		if(value == 1)
		{//want to drop olt ring check packet
			system("echo 0x8300  > /proc/rg/wan_ring_check_eth_type");
			system("diag flowctrl set egress system drop-threshold low-off threshold 6900");
			system("diag flowctrl set egress system drop-threshold low-on threshold 7000");
			system("diag flowctrl set egress system drop-threshold high-off threshold 7000");
			system("diag flowctrl set egress system drop-threshold high-on threshold 7100");
			system("diag flowctrl set egress system flowctrl-threshold low-off threshold 6900");
			system("diag flowctrl set egress system flowctrl-threshold low-on threshold 7000");
			system("diag flowctrl set egress system flowctrl-threshold high-off threshold 7000");
			system("diag flowctrl set egress system flowctrl-threshold high-on threshold 7100");
			system("diag flowctrl set ingress egress-drop port 3 threshold 7117");
			system("diag flowctrl set ingress egress-drop port 6 threshold 3500");
			system("diag flowctrl set pause-all threshold 7117");				
		}
		else
			system("echo 0 > /proc/rg/wan_ring_check_eth_type");		
#endif	

#if defined(CONFIG_YUEME)
	system("/bin/echo 1 > /proc/rg/inboundL4UnknownUdpConnDrop");
	system("/bin/echo 1 > /proc/rg/protocolStackBypassRxQueue");
	RTK_RG_Control_Packet_Ingress_ACL_Rule_set();
	RTK_RG_Control_Packet_Egress_ACL_Rule_set();
	//for avoid superfluous flood
	//system("/bin/echo 1 > /proc/rg/drop_superfluous_packet");
	//temply disable drop_superfluous_packet
	system("/bin/echo 0 > /proc/rg/drop_superfluous_packet");	
	RTK_RG_add_TCP_syn_rate_limit();
	RTK_RG_add_ARP_broadcast_rate_limit();
	system("/bin/echo 1 > /proc/rg/flow_not_update_in_real_time");
#endif
#ifdef CONFIG_MCAST_VLAN
	//disable ingress mcast vlan filter.
	mib_get(PROVINCE_DISABLE_MCAST_INGRESS_VLAN_FILTER, (void *)&value);
	if(value == 1)
	{
		FILE *fpmvlan=NULL;
		unsigned int fwdcpu_vid = 0;
		char filename[64] = {0};
		sprintf(filename, "%s_default", RG_ACL_MVLAN_RULES_FILE);
		if (!(fpmvlan = fopen(filename, "a"))) {
			fprintf(stderr, "ERROR! %s\n", strerror(errno));
			goto SKIP_MVLAN;
		}
		//AUG_PRT("%s\n",filename); 	
		memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
		//tranfser v4 mcast packets to internal vid 1, let snooping decide forward to which one!
		aclRule.filter_fields |= INGRESS_PORT_BIT;
		aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();//wan port
		aclRule.acl_weight = RG_DEFAULT_ACL_WEIGHT;
		aclRule.filter_fields |= INGRESS_DMAC_BIT;
		memcpy(&aclRule.ingress_dmac,MCAST_ADDR,MAC_ADDR_LEN);
		memcpy(&aclRule.ingress_dmac_mask,MCAST_MASK,MAC_ADDR_LEN);
		aclRule.action_type = ACL_ACTION_TYPE_QOS;
		aclRule.qos_actions |= ACL_ACTION_ACL_INGRESS_VID_BIT;
		mib_get(MIB_FWD_CPU_VLAN_ID, (void *)&fwdcpu_vid);
		aclRule.action_acl_ingress_vid = fwdcpu_vid; //lan interface's vlan
		if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0){
			fprintf(fpmvlan,"%d\n",aclIdx);
			fprintf(stderr, "add mCast acl index=%d success\n", aclIdx);
			//AUG_PRT("add mCast acl index=%d success\n", aclIdx);
		}else{
			fprintf(stderr,"rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n", ret);
			fclose(fpmvlan);
			goto SKIP_MVLAN;
		}
		memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
		aclRule.filter_fields |= INGRESS_PORT_BIT;
		aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();//wan port
		aclRule.acl_weight = RG_DEFAULT_ACL_WEIGHT;
		aclRule.filter_fields |= INGRESS_DMAC_BIT;
		memcpy(&aclRule.ingress_dmac,MCAST_ADDR_V6,MAC_ADDR_LEN);
		memcpy(&aclRule.ingress_dmac_mask,MCAST_MASK_V6,MAC_ADDR_LEN);
		aclRule.action_type = ACL_ACTION_TYPE_QOS;
		aclRule.qos_actions |= ACL_ACTION_ACL_INGRESS_VID_BIT;
		mib_get(MIB_FWD_CPU_VLAN_ID, (void *)&fwdcpu_vid);
		aclRule.action_acl_ingress_vid = fwdcpu_vid; //lan interface's vlan
		if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0){
			fprintf(fpmvlan,"%d\n",aclIdx);
			fprintf(stderr, "%s-%d add mCast ACL index=%d success\n",__func__,__LINE__, aclIdx);
			//AUG_PRT("add mCast acl index=%d success\n", aclIdx);		
		}else{
			fprintf(stderr,"rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n", ret);
			fclose(fpmvlan);	
			goto SKIP_MVLAN;
		}		
		fclose(fpmvlan);	
	}
	SKIP_MVLAN:
#endif
	//transparent 4K vlan, exclude reserved vlan.
	mib_get(MIB_VLAN_4K_TRANSPARENT_EN, (void *)&value);
	if(value == 1)
	{
		AUG_PRT("enable 4K vlan transparent!\n");
		do_vlan_transparent();
	}
	assign_loopback_detect_to_high_queue();
	ddos_smurf_attack_protect();

	// IGMP setting
	unsigned int igmpSnoopGrpTimeout = 0;
	if(mib_get(MIB_IGMP_SNOOPING_GROUP_TIMEOUT, (void *)&igmpSnoopGrpTimeout))
	{
		sprintf(buf, "echo %u > /proc/rg/igmp_groupMemberAgingTime", igmpSnoopGrpTimeout);
		system(buf);
	}

#if defined(CONFIG_RG_G3_SERIES) && defined(CONFIG_RTL8192CD_MODULE)
#if CONFIG_NR_CPUS  == 4
        system("echo 1 > /proc/rg/disableWifiTxDistributed");
#endif
#endif

	return SUCCESS;
}

//avoid too much broadcast/multicast packets to block loopback detect pkts
//and run out of nic priv skb buffer make system crash, we raise loopback
//detect pkts to high queue to have higher priority
void assign_loopback_detect_to_high_queue(void)
{
	rtk_rg_aclFilterAndQos_t aclRule;
	int aclIdx=0, ret;

	/* loopback eth type = 0xfffa */
	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	aclRule.acl_weight = RG_FIREWALL_ACL_WEIGHT;
	aclRule.filter_fields |= INGRESS_PORT_BIT;
	aclRule.ingress_port_mask.portmask = RTK_RG_ALL_MAC_CPU_PORTMASK;
	//include all lan port
	aclRule.ingress_port_mask.portmask |= RG_get_all_lan_phyPortMask();
	aclRule.filter_fields |= INGRESS_ETHERTYPE_BIT;
	aclRule.ingress_ethertype = 0xfffa;
	aclRule.ingress_ethertype_mask = 0xffff;	
	aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	aclRule.action_type = ACL_ACTION_TYPE_QOS;
	aclRule.qos_actions = ACL_ACTION_ACL_PRIORITY_BIT;
	aclRule.action_acl_priority = 7;
	if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0) {
		printf("%d\n", aclIdx);
	} else {
		printf("[%s@%d] rtk_rg_aclFilterAndQos_add loopback QoS rule failed! (ret = %d)\n",__func__,__LINE__, ret);
	}


}

void ddos_smurf_attack_protect(void)
{
	int ret=0, acl_index=0;
	rtk_rg_aclFilterAndQos_t aclRule;
	struct in_addr lan_ip;
		//Yueme test plan 9.1.4.1 Ddos attack, smurf attack
		//smurf ddos attack! target ip 192.168.1.255, target dmac br0's mac
		/*
		rg clear acl-filter
		rg set acl-filter acl_weight 400
		rg set acl-filter fwding_type_and_direction 0
		rg set acl-filter action action_type 0
		rg set acl-filter pattern ingress_dest_ipv4_addr_start 192.168.1.255 ingress_dest_ipv4_addr_end 192.168.1.255
		rg set acl-filter pattern ingress_dmac 00:00:00:00:00:00
		rg set acl-filter pattern ingress_dmac_mask 01:00:00:00:00:00
		rg set acl-filter pattern ingress_port_mask 0x1e
		rg add acl-filter entry
		*/
		memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
		aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
		aclRule.action_type = ACL_ACTION_TYPE_DROP;
		aclRule.acl_weight = RG_ACL_HIGHEST_PRI_WEIGHT;
		aclRule.filter_fields |= INGRESS_PORT_BIT;
		//for all lan port.
		//aclRule.ingress_port_mask.portmask =  dos_port_mask.portmask;
		aclRule.ingress_port_mask.portmask |= RG_get_all_lan_phyPortMask();
#ifdef WLAN_SUPPORT
		aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN0));
#ifdef WLAN_DUALBAND_CONCURRENT
		aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN1));
#endif
#endif		
		aclRule.ingress_port_mask.portmask |= RG_get_wan_phyPortMask();

		aclRule.filter_fields |= INGRESS_IPV4_DIP_RANGE_BIT;
		mib_get(MIB_ADSL_LAN_IP, (void *)&lan_ip);
		aclRule.ingress_dest_ipv4_addr_start = aclRule.ingress_dest_ipv4_addr_end = (ntohl(*((ipaddr_t *)&lan_ip.s_addr)) | 0xff);
		aclRule.filter_fields |= INGRESS_DMAC_BIT;
		aclRule.ingress_dmac.octet[0] = 0;
		aclRule.ingress_dmac.octet[1] = 0;
		aclRule.ingress_dmac.octet[2] = 0;
		aclRule.ingress_dmac.octet[3] = 0;
		aclRule.ingress_dmac.octet[4] = 0;
		aclRule.ingress_dmac.octet[5] = 0;
		aclRule.ingress_dmac_mask.octet[0] = 0x1;
		aclRule.ingress_dmac_mask.octet[1] = 0;
		aclRule.ingress_dmac_mask.octet[2] = 0;
		aclRule.ingress_dmac_mask.octet[3] = 0;
		aclRule.ingress_dmac_mask.octet[4] = 0;
		aclRule.ingress_dmac_mask.octet[5] = 0;
		if((ret = rtk_rg_aclFilterAndQos_add(&aclRule,&acl_index)) == 0)
			printf("%d\n", acl_index);
		else
			printf("[%s@%d] rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n",__func__,__LINE__, ret);

}

void dump_cvlan_info(rtk_rg_cvlan_info_t *cvlan_info)
{
	printf("-------------%s-------------\n",__func__);
	printf("cvlan_info->vlanId=%d\n",cvlan_info->vlanId);
	printf("cvlan_info->isIVL=%d\n",cvlan_info->isIVL); 	//0: SVL, 1:IVL
	printf("cvlan_info->memberPortMask=%x\n",cvlan_info->memberPortMask);
	printf("cvlan_info->untagPortMask=%x\n",cvlan_info->untagPortMask);
#ifdef CONFIG_MASTER_WLAN0_ENABLE
	printf("cvlan_info->wlan0DevMask=%x\n",cvlan_info->wlan0DevMask);
	printf("cvlan_info->wlan0UntagMask=%x\n",cvlan_info->wlan0UntagMask);
#endif
	printf("cvlan_info->vlan_based_pri_enable=%d\n",cvlan_info->vlan_based_pri_enable);
	printf("cvlan_info->vlan_based_pri=%d\n",cvlan_info->vlan_based_pri);
	printf("cvlan_info->addedAsCustomerVLAN=%d\n",cvlan_info->addedAsCustomerVLAN);
	printf("----------------------------\n");
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


#define MAX_INTF_NUM 14
int Check_RG_Intf_Count(void)
{
	int remained_intf_count=0;
	int cur_intf_count=0;
	rtk_rg_intfInfo_t *intf_info = NULL;
	int i=0, valid_idx=0;
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
	Error_remain:
	printf("%s-%d remained:%d, used:%d\n",__func__,__LINE__,remained_intf_count,cur_intf_count);
	return remained_intf_count;
}
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
		if (mib_get(MIB_ADSL_LAN_IP, (void *)value) != 0)
		{
			lan_info->ip_addr=ntohl((((struct in_addr *)value)->s_addr)); //192.168.1.1
		}
		if (mib_get(MIB_ADSL_LAN_SUBNET, (void *)value) != 0)
		{
			lan_info->ip_network_mask=ntohl((((struct in_addr *)value)->s_addr)); //255.255.255.0
		}
#ifdef CONFIG_IPV6
		mib_get(MIB_LAN_IP_VERSION1, (void *)&ip_version);
		lan_info->ip_version=ip_version;
		if(ip_version == IPVER_V4V6 || ip_version == IPVER_V6ONLY)
		{
			mib_get(MIB_LAN_IPV6_MODE1, (void *)&vchar);
			if(vchar == 0) // IPv6 address mode is auto
			{
				getifip6((char*)LANIF, IPV6_ADDR_UNICAST, ip6_addr, 6);
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
				getifip6((char*)LANIF, IPV6_ADDR_UNICAST, ip6_addr, 6);
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
#ifdef CONFIG_SECONDARY_IP
		mib_get(MIB_ADSL_LAN_ENABLE_IP2, (void *)value);
		if (value[0] == 1)
		{
			if (mib_get(MIB_ADSL_LAN_IP2, (void *)value) != 0)
			{
				lan_info->ip_addr=ntohl((((struct in_addr *)value)->s_addr)); //192.168.1.1
			}
			if (mib_get(MIB_ADSL_LAN_SUBNET2, (void *)value) != 0)
			{
				lan_info->ip_network_mask=ntohl((((struct in_addr *)value)->s_addr)); //255.255.255.0
			}
			lan_info->replace_subnet = 0;
			if((rtk_rg_lanInterface_add(lan_info,&lanIntfIdx))!=SUCCESS)
			{
				DBPRINT(1, "Add LAN interface 2 failed! lanIntfIdx=%d\n",lanIntfIdx);
				ret = -2;
				goto ErrorA;
			}
		}
#endif
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
int Init_RG_ELan(int isUnTagCPort, int isRoutingWan)
{
	rtk_rg_lanIntfConf_t lan_info;
	int lanIntfIdx = -1;
#ifdef CONFIG_SECONDARY_IP
	int lanIntfIdx2 = -1;
#endif
	unsigned char value[6], ip_version=IPVER_V4V6, vchar, ipv6_addr[IPV6_ADDR_LEN], ipv6_prefix_len;
	int i;
	int wanPhyPort=0, vlan_id;
	unsigned int portMask = 0;
	unsigned int phy_portmask;
	struct ipv6_ifaddr ip6_addr[6];
	char ipv6addr_str[64], cur_ip6addr_str[64];
	FILE *fp;
	rtk_rg_cvlan_info_t cvlan_info;
	memset(&cvlan_info,0,sizeof(rtk_rg_cvlan_info_t));

#if 0
	Init_rg_api();
	DBPRINT(2, "Init_rg_api() on!\n");
#else
	//AUG_PRT("%s-%d",__func__,__LINE__);
	RG_Del_All_LAN_Interfaces();
	//AUG_PRT("%s-%d",__func__,__LINE__);
#endif
	memset(&lan_info,0,sizeof(lan_info));

	mib_get(MIB_LAN_IP_VERSION1, (void *)&ip_version);
	lan_info.ip_version=ip_version;


#ifdef CONFIG_IPV6
	if(ip_version == IPVER_V4V6 || ip_version == IPVER_V6ONLY)
	{
		setup_disable_ipv6((char*)LANIF, 0);

		mib_get(MIB_LAN_IPV6_MODE1, (void *)&vchar);
		if(vchar == 0) // IPv6 address mode is auto
		{
			getifip6((char*)LANIF, IPV6_ADDR_UNICAST, ip6_addr, 6);
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

			getifip6((char*)LANIF, IPV6_ADDR_UNICAST, ip6_addr, 6);
			inet_ntop(PF_INET6, &ip6_addr[0].addr, cur_ip6addr_str, sizeof(cur_ip6addr_str));
			sprintf(cur_ip6addr_str, "%s/%d", cur_ip6addr_str, ip6_addr[0].prefix_len);

			va_cmd(IFCONFIG, 3, 1, LANIF, "del", cur_ip6addr_str);
			va_cmd(IFCONFIG, 3, 1, LANIF, "add", ipv6addr_str);
		}
	}
	else
	{
		setup_disable_ipv6((char*)LANIF, 1);
	}
#endif

	if(ip_version == IPVER_V4V6 || ip_version == IPVER_V4ONLY)
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

	if(mib_get(MIB_LAN_VLAN_ID1, (void *)&vlan_id) != 0)
		lan_info.intf_vlan_id = vlan_id;
	lan_info.vlan_based_pri=-1;

	lan_info.mtu=1500;
	cvlan_info.vlanId = vlan_id;
	printf("%s vlan:%d\n",__func__,vlan_id);
	if(rtk_rg_cvlan_get(&cvlan_info) == RT_ERR_RG_OK)
	{
		AUG_PRT("check vlan:%d existed!\n",vlan_id);
		//dump_cvlan_info(&cvlan_info);
		if(cvlan_info.addedAsCustomerVLAN == 1)
		{
			if(rtk_rg_cvlan_del(vlan_id)!= RT_ERR_RG_OK)
				printf("%s-%d rtk_rg_cvlan_del failed\n",__func__,__LINE__);
		}
	}


	mib_get(MIB_LAN_PORT_MASK1, (void *)&portMask);
	//portMask = ((1<<RTK_RG_MAC_PORT0)|(1<<RTK_RG_MAC_PORT1)|(1<<RTK_RG_MAC_PORT2)|(1<<RTK_RG_MAC_PORT3));
	phy_portmask = RG_get_lan_phyPortMask(portMask);
	portMask = phy_portmask;
	if(isRoutingWan){
		portMask &= (~(RG_get_wan_phyPortMask()));
	}
	#if 0
	lan_info.port_mask.portmask=((1<<RTK_RG_PORT0)|(1<<RTK_RG_PORT1)|(1<<RTK_RG_PORT2)|(1<<RTK_RG_PORT3));
	lan_info.untag_mask.portmask=((1<<RTK_RG_MAC_PORT0)|(1<<RTK_RG_MAC_PORT1)|(1<<RTK_RG_MAC_PORT2));
	#endif
	#ifndef WLAN_DUALBAND_CONCURRENT
	#ifdef CONFIG_RG_G3_SERIES
	lan_info.port_mask.portmask=portMask|(1 << RTK_RG_EXT_PORT0)|RTK_RG_ALL_MASTER_CPU_PORTMASK;
	#else
	lan_info.port_mask.portmask=portMask|(1 << RTK_RG_EXT_PORT0)|RTK_RG_ALL_CPU_PORTMASK;
	#endif
	#else
#ifdef WLAN_SUPPORT
	lan_info.port_mask.portmask=portMask|(1 << RG_get_wlan_phyPortId(PMAP_WLAN0))|(1 << RG_get_wlan_phyPortId(PMAP_WLAN1))|RTK_RG_ALL_CPU_PORTMASK;
#endif
	//lan_info.port_mask.portmask=portMask|RTK_RG_ALL_MASTER_EXT_PORTMASK|RTK_RG_ALL_SLAVE_EXT_PORTMASK|RTK_RG_ALL_CPU_PORTMASK;
	#endif
	lan_info.untag_mask.portmask = portMask;

	if(isUnTagCPort)
	#ifdef CONFIG_RG_G3_SERIES
		lan_info.untag_mask.portmask|=RTK_RG_ALL_MAC_MASTER_CPU_PORTMASK;
	#else
		lan_info.untag_mask.portmask|=RTK_RG_ALL_MAC_CPU_PORTMASK;
	#endif

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

#ifdef CONFIG_SECONDARY_IP
	mib_get(MIB_ADSL_LAN_ENABLE_IP2, (void *)value);

	if (value[0] == 1)
	{
		ip_version = IPVER_V4V6;
		mib_get(MIB_LAN_IP_VERSION2, (void *)&ip_version);
		lan_info.ip_version = ip_version;

		if(ip_version == IPVER_V4V6 || ip_version == IPVER_V4ONLY)
		{
			if (mib_get(MIB_ADSL_LAN_IP2, (void *)value) != 0)
				lan_info.ip_addr=ntohl((((struct in_addr *)value)->s_addr));

			if (mib_get(MIB_ADSL_LAN_SUBNET2, (void *)value) != 0)
				lan_info.ip_network_mask=ntohl((((struct in_addr *)value)->s_addr));
		}
/*

		if(mib_get(MIB_LAN_VLAN_ID2, (void *)&vlan_id) != 0)
			lan_info.intf_vlan_id = vlan_id;

		if(mib_get(MIB_LAN_PORT_MASK2, (void *)&portMask)!=0)
		{
			phy_portmask = RG_get_lan_phyPortMask(portMask);
			portMask = phy_portmask;
			if(isRoutingWan)
				portMask &= (~(RG_get_wan_phyPortMask()));

			lan_info.port_mask.portmask=portMask|(1<<RTK_RG_EXT_PORT0)|(1<<RTK_RG_EXT_PORT1)|(1<<RTK_RG_EXT_PORT2)|(1<<RTK_RG_EXT_PORT3)|(1<<RTK_RG_EXT_PORT4);
			lan_info.untag_mask.portmask = portMask;

			if(isUnTagCPort)
				lan_info.untag_mask.portmask|=(1<<RTK_RG_MAC_PORT_CPU);
		}
*/
		lan_info.vlan_based_pri=-1;
		lan_info.mtu=1500;
/*
#ifdef CONFIG_IPV6
		if(ip_version == IPVER_V4V6 || ip_version == IPVER_V6ONLY)
		{
			mib_get(MIB_LAN_IPV6_MODE2, (void *)&vchar);
			if(vchar == 0) // IPv6 address mode is auto
			{
				getifip6(LAN_ALIAS, IPV6_ADDR_UNICAST, ip6_addr, 6);
				memcpy(lan_info.ipv6_addr.ipv6_addr, &ip6_addr[0].addr, IPV6_ADDR_LEN);
				lan_info.ipv6_network_mask_length = ip6_addr[0].prefix_len;
			}
			else
			{
				mib_get(MIB_LAN_IPV6_ADDR2, (void *)ipv6_addr);
				mib_get(MIB_LAN_IPV6_PREFIX_LEN2, (void *)&ipv6_prefix_len);
				memcpy(lan_info.ipv6_addr.ipv6_addr, ipv6_addr, IPV6_ADDR_LEN);
				lan_info.ipv6_network_mask_length = ipv6_prefix_len;

				inet_ntop(PF_INET6, ipv6_addr, ipv6addr_str, sizeof(ipv6addr_str));
				sprintf(ipv6addr_str, "%s/%d", ipv6addr_str, ipv6_prefix_len);

				getifip6(LAN_ALIAS, IPV6_ADDR_UNICAST, ip6_addr, 6);
				inet_ntop(PF_INET6, &ip6_addr[0].addr, cur_ip6addr_str, sizeof(cur_ip6addr_str));
				sprintf(cur_ip6addr_str, "%s/%d", cur_ip6addr_str, ip6_addr[0].prefix_len);

				va_cmd(IFCONFIG, 3, 1, LAN_ALIAS, "del", cur_ip6addr_str);
				va_cmd(IFCONFIG, 3, 1, LAN_ALIAS, "add", ipv6addr_str);
			}
		}
#endif
*/

		if((rtk_rg_lanInterface_add(&lan_info,&lanIntfIdx2))!=SUCCESS)
		{
			DBPRINT(1, "Add LAN interface 2 failed!\n");
			return -1;
		}
	}
#endif
#if 0
	if(fp = fopen(RG_LAN_INF_IDX, "w"))
	{
		fprintf(fp, "%d\n", lanIntfIdx);
		DBPRINT(0, "LAN interface index=%d\n", lanIntfIdx);
#ifdef CONFIG_SECONDARY_IP
		if(lanIntfIdx2 != -1)
		{
			fprintf(fp, "%d\n", lanIntfIdx2);
			DBPRINT(0, "LAN interface2 index=%d\n", lanIntfIdx2);
		}
#endif
		fclose(fp);
	}
	else
		fprintf(stderr, "Open %s failed! %s\n", RG_LAN_INF_IDX, strerror(errno));
#endif
	return SUCCESS;
}
/*find wan or lan interface index*/
int RG_intfInfo_find(MIB_CE_ATM_VC_Tp entry)
{
	rtk_rg_intfInfo_t *intf_info;
	int ret=0;
	int IntfIdx=-1;
	if(rtk_rg_intfInfo_find(intf_info,(int *)(intptr_t)IntfIdx)!=0){
		printf("%s-%d Can't find the interface!",__func__,__LINE__);
		return -1;
	}
	return IntfIdx;
}

extern struct pmap_s pmap_list[MAX_VC_NUM];
extern int get_pmap_fgroup(struct pmap_s *pmap_p, int num);
unsigned short RG_get_port_binding(MIB_CE_ATM_VC_Tp entry)
{
        int i;
        unsigned int Index = entry->ifIndex;
		unsigned int wanPhyPort=0;
        get_pmap_fgroup(pmap_list,MAX_VC_NUM);
        for(i=0; i<MAX_VC_NUM; i++)
        {
                if(pmap_list[i].ifIndex == Index){
			return pmap_list[i].fgroup;
                }
        }
        printf("%s-%d Can't find the respected index\n");
        return -1;
}

const char VCONFIG[] = "/bin/vconfig";
#define ALIASNAME_ELAN_RG_WLAN "eth0"
/*setup vconfig of LAN for vlan binding*/
int setup_vconfig(unsigned short LanVid, int LanPortIdx)
{
	char v_eth_name[32];
	char sLanVid[16];
	unsigned char value[6];
	sprintf(sLanVid,"%d",LanVid);
	switch(LanPortIdx)
	{
		case 0:
			va_cmd_no_error(VCONFIG, 3, 1, "add", ALIASNAME_ELAN0, sLanVid);
			sprintf(v_eth_name,"%s.%d",ALIASNAME_ELAN0,LanVid);
			break;
		case 1:
			va_cmd_no_error(VCONFIG, 3, 1, "add", ALIASNAME_ELAN1, sLanVid);
			sprintf(v_eth_name,"%s.%d",ALIASNAME_ELAN1,LanVid);
			break;
		case 2:
			va_cmd_no_error(VCONFIG, 3, 1, "add", ALIASNAME_ELAN2, sLanVid);
			sprintf(v_eth_name,"%s.%d",ALIASNAME_ELAN2,LanVid);
			break;
		case 3:
			va_cmd_no_error(VCONFIG, 3, 1, "add", ALIASNAME_ELAN3, sLanVid);
			sprintf(v_eth_name,"%s.%d",ALIASNAME_ELAN3,LanVid);
			break;
#ifdef WLAN_SUPPORT
		case 4:
			//add this for normal path. (To protocol stack.)
			va_cmd_no_error(VCONFIG, 3, 1, "add", ALIASNAME_WLAN0, sLanVid);
			sprintf(v_eth_name,"%s.%d",ALIASNAME_WLAN0,LanVid);
			va_cmd_no_error(BRCTL, 3, 1, "addif", ALIASNAME_BR0, v_eth_name);
			va_cmd_no_error(IFCONFIG, 2, 1, v_eth_name, "up");

			//add this for forwarding engine
			va_cmd_no_error(VCONFIG, 3, 1, "add", ALIASNAME_ELAN_RG_WLAN, sLanVid);
			sprintf(v_eth_name,"%s.%d",ALIASNAME_ELAN_RG_WLAN,LanVid);
			break;
#endif
	}
	va_cmd_no_error(BRCTL, 3, 1, "addif", ALIASNAME_BR0, v_eth_name);
	va_cmd_no_error(IFCONFIG, 2, 1, v_eth_name, "up");
	return 0;
}
int flush_vconfig(unsigned short LanVid, int LanPortIdx)
{
	char v_eth_name[32];
	char sLanVid[16];
	unsigned char value[6];
	sprintf(sLanVid,"%d",LanVid);
	switch(LanPortIdx)
	{
		case 0:
			sprintf(v_eth_name,"%s.%d",ALIASNAME_ELAN0,LanVid);
			va_cmd(VCONFIG, 2, 1, "rem", v_eth_name);
			break;
		case 1:
			sprintf(v_eth_name,"%s.%d",ALIASNAME_ELAN1,LanVid);
			va_cmd(VCONFIG, 2, 1, "rem", v_eth_name);
			break;
		case 2:
			sprintf(v_eth_name,"%s.%d",ALIASNAME_ELAN2,LanVid);
			va_cmd(VCONFIG, 2, 1, "rem", v_eth_name);
			break;
		case 3:
			sprintf(v_eth_name,"%s.%d",ALIASNAME_ELAN3,LanVid);
			va_cmd(VCONFIG, 2, 1, "rem", v_eth_name);
#ifdef WLAN_SUPPORT
		case 4:
			//add this for normal path. (To protocol stack.)
			sprintf(v_eth_name,"%s.%d",ALIASNAME_WLAN0,LanVid);
			va_cmd(VCONFIG, 2, 1, "rem", v_eth_name);
			//add this for forwarding engine
			sprintf(v_eth_name,"%s.%d",ALIASNAME_ELAN_RG_WLAN,LanVid);
			va_cmd(VCONFIG, 2, 1, "rem", v_eth_name);
			break;
#endif
			break;
	}
	//va_cmd(BRCTL, 3, 1, "delif", ALIASNAME_BR0, v_eth_name);
	//va_cmd(IFCONFIG, 2, 1, v_eth_name, "down");
	return 0;

}

/*Vlan and port binding will effect the OMCI CF rules
    so, we must check rules after setting vlan port mapping
*/
#if defined(CONFIG_RTK_L34_ENABLE) && defined(CONFIG_GPON_FEATURE)

/*
input value:
SyncALL = 1; ---> sync all [forward]+ [local in/out] omci wan info. del each and add each
SyncALL = 0; ---> sync all [forward] omci wan info. del each and add each
*/
int RTK_RG_Sync_OMCI_WAN_INFO(int SyncALL)
{
	unsigned int temp_port_binding_mask, temp_wlan0_dev_binding_mask;
	int totalVC_entry,i,wan_idx=-1,wanIntfIdx=-1, wan_idx_dual=-1;
	rtk_rg_wanIntfConf_t *wan_info_p = NULL;
	rtk_rg_intfInfo_t *intf_info = NULL;
	MIB_CE_ATM_VC_T entryVC;
	char vlan_based_pri=-1;
	int omci_service=-1;
	int omci_mode=-1;
	int omci_bind=-1;
	int ret=0;
	char cmdStr[64];
	int pon_mode;
	unsigned short portMask_dual=0;

	mib_get(MIB_PON_MODE, (void *)&pon_mode);

	intf_info = (rtk_rg_intfInfo_t *)malloc(sizeof(rtk_rg_intfInfo_t));
	if(intf_info == NULL){
		printf("%s-%d Can't get enough memory space!\n",__func__,__LINE__);
		return -1;
	}
	//AUG_PRT("SyncALL=%d\n",SyncALL);		
#if ! defined(_LINUX_2_6_) && defined(CONFIG_TR142_MODULE)
	if(SyncALL){
		snprintf(cmdStr, sizeof(cmdStr)-1,"echo clear > %s", TR142_WAN_IDX_MAP);
		system(cmdStr);
	}
#endif
	memset(intf_info,0,sizeof(rtk_rg_intfInfo_t));
	totalVC_entry = mib_chain_total(MIB_ATM_VC_TBL);
	for(i=0;i<totalVC_entry;i++){
		if(mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&entryVC) == 0)
			continue;
		if(entryVC.enable == 0 || (entryVC.rg_wan_idx <= 0))
			continue;
		//just for forwarding wan, we need to re-sync lan-wan relationship
		if(!(entryVC.applicationtype & (X_CT_SRV_INTERNET|X_CT_SRV_OTHER)) && (SyncALL == 0))
			continue;
		if(rtk_rg_intfInfo_find(intf_info,&entryVC.rg_wan_idx)!=SUCCESS){
			printf("%s-%d Can't find the wan interface idx:%d!",__func__,__LINE__,entryVC.rg_wan_idx);
			free(intf_info);
			return -1;
		}
		//for vlan binding, if we change binding relationship, we must sync rg WAN info.
		wan_info_p = &(intf_info->wan_intf.wan_intf_conf);
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		if(checkIPv4_IPv6_Dual_PolicyRoute(&wan_idx_dual, &portMask_dual)==1){
			if(entryVC.rg_wan_idx==wan_idx_dual){
				//printf("\033[1;33;40m @@@@@@@@@@@@@@@@@########### %s:%d IPv4_IPv6_Dual policy route clean IPv4 binding port\033[m\n", __FUNCTION__, __LINE__);
				entryVC.itfGroup = 0;
			}
		}
#endif

#if 1 /*for vlan binding, we don't need sync rg WAN info, but need to sync omci waninfo*/
		//for vlan binding, if we change binding relationship, we must sync rg WAN info.
		#ifdef CONFIG_RTL9602C_SERIES
		temp_port_binding_mask = RG_get_lan_phyPortMask(entryVC.itfGroup & 0x3);
		#else
		temp_port_binding_mask = RG_get_lan_phyPortMask(entryVC.itfGroup & 0xf);
		#endif
#if defined(WLAN_SUPPORT)
		temp_wlan0_dev_binding_mask = (((entryVC.itfGroup >> ITFGROUP_WLAN0_DEV_BIT) & ITFGROUP_WLAN_MASK ) << RG_RET_MBSSID_MASTER_ROOT_INTF);
#if defined(WLAN_DUALBAND_CONCURRENT)
		temp_wlan0_dev_binding_mask |= (((entryVC.itfGroup >> ITFGROUP_WLAN1_DEV_BIT) & ITFGROUP_WLAN_MASK ) << RG_RET_MBSSID_SLAVE_ROOT_INTF);
#endif
#endif	
		if(temp_port_binding_mask != wan_info_p->port_binding_mask.portmask
			|| temp_wlan0_dev_binding_mask != wan_info_p->wlan0_dev_binding_mask)
		{
			wan_info_p->forcedAddNewIntf = 0;
			wan_info_p->port_binding_mask.portmask = temp_port_binding_mask;
			wan_info_p->wlan0_dev_binding_mask = temp_wlan0_dev_binding_mask;
			if((ret = rtk_rg_wanInterface_add(wan_info_p, &entryVC.rg_wan_idx))!=SUCCESS){
				printf("%s-%d rtk_rg_wanInterface_add fail! ret=%d\n",__func__,__LINE__,ret);
				free(intf_info);
				return -1;
			}
		}
#endif

		if (pon_mode == EPON_MODE) //EPON do not need sync. OMCI_WAN_INFO
			continue;

#ifdef CONFIG_GPON_FEATURE
		//AUG_PRT("entryVC.vid=%d entryVC.itfGroup=%x\n",entryVC.vid,entryVC.itfGroup);
		if((temp_port_binding_mask == 0) && (wan_info_p->vlan_binding_mask.portmask == 0) && (temp_wlan0_dev_binding_mask == 0) || SyncALL)
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
//AUG_PRT("entryVC.vid=%d entryVC.itfGroup=%x\n",entryVC.vid,entryVC.itfGroup, omci_bind);	
			//none binding wan, reset omci wan info...
			//omci wan info can't write duplicate, must delete it before adding.
			fprintf(stderr, "%s-%d sync waninfo with OMCI!\n",__func__,__LINE__);
			snprintf(cmdStr, sizeof(cmdStr),"echo %d %d %d %d %d %d %d > %s",entryVC.rg_wan_idx,0,0,0,0,0,0,OMCI_WAN_INFO);
			system(cmdStr);
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
			if(entryVC.applicationtype & (X_CT_SRV_INTERNET|X_CT_SRV_SPECIAL_SERVICE_ALL)){
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
			//omci_bind = 0;
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
			fprintf(stderr, "%s-%d sync waninfo with OMCI!\n",__func__,__LINE__);
			snprintf(cmdStr, sizeof(cmdStr),"echo %d %d %d %d %d %d %d > %s",entryVC.rg_wan_idx,wan_info_p->egress_vlan_id,vlan_based_pri,omci_mode,omci_service,omci_bind,1,OMCI_WAN_INFO);
			system(cmdStr);
#if ! defined(_LINUX_2_6_) && defined(CONFIG_TR142_MODULE)
			}
#endif
		}
#endif	
	}
	free(intf_info);
#if defined(CONFIG_YUEME)
	ssidisolation_portmap();
#elif defined(CONFIG_CMCC) || defined(CONFIG_CU)
	RG_Flush_Handle_Priority_Tag0_ACL_FILE();
	RG_Handle_Priority_Tag0_By_Port();
	ssidisolation_portmap();
	//set unbinded port to vlan 9, to make unbinded port can access other binded port,
	//RG_set_unbinded_port_vlan should behide ssidisolation_portmap()
	RG_set_unbinded_port_vlan();
	RGSyncIPv4_IPv6_Dual_WAN();
#endif	
	return 0;
}
#endif
int RG_add_vlanBinding(MIB_CE_ATM_VC_Tp pEntry,int pairID, unsigned short LanVid, int LanPortIdx)
{
	rtk_rg_vlanBinding_t vlanBind;
	MIB_CE_PORT_BINDING_T pbEntry;
	int rg_bind_idx=-1;
	int omci_service=-1;
	int omci_bind=-1;
	int omci_mode=-1;
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
	if(rtk_rg_intfInfo_find(intf_info,&pEntry->rg_wan_idx)!=SUCCESS){
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
	//DBPRINT(2, "%s-%d \n",__func__,__LINE__,LanPortIdx,LanVid,RG_WAN_idx);
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
#if ! defined(_LINUX_2_6_) && defined(CONFIG_TR142_MODULE)
	if(omci_bind != check_wan_omci_portbing(pEntry)) 
	{
#endif
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
#if ! defined(_LINUX_2_6_) && defined(CONFIG_TR142_MODULE)
	char ifname[IFNAMSIZ] = {0};
	ifGetName(PHY_INTF(pEntry->ifIndex), ifname, sizeof(ifname));
	snprintf(cmdStr, sizeof(cmdStr)-1,"echo %d %s %s %d > %s", pEntry->rg_wan_idx, ALIASNAME_NAS0, ifname, omci_bind, TR142_WAN_IDX_MAP);
	system(cmdStr);
#endif
	fprintf(stderr, "%s-%d sync waninfo with OMCI!\n",__func__,__LINE__);
	snprintf(cmdStr, sizeof(cmdStr),"echo %d %d %d %d %d %d %d > %s",pEntry->rg_wan_idx,wan_info_p->egress_vlan_id,wan_info_p->vlan_based_pri,omci_mode,omci_service,omci_bind,1,OMCI_WAN_INFO);
	system(cmdStr);
#if ! defined(_LINUX_2_6_) && defined(CONFIG_TR142_MODULE)
	}
#endif
#endif
	//fprintf(stderr, "%s-%d %s\n",__func__,__LINE__,cmdStr);
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

/*input value, wan's vid,  del rg vlan binding info 
  before add wan or del wan.
  add bind info after add wan or del wan.
*/
int RG_flush_vlanBinding_by_WanVID(int vid)
{
	rtk_rg_vlanBinding_t vlanBind;
	int valid_idx;
	MIB_CE_PORT_BINDING_T pbEntry;
	int totalnum=0,i;
	if(vid < 0)
		return -1;
	memset(&vlanBind,0,sizeof(rtk_rg_vlanBinding_t));
	//search all lan port id 0~total_num-1
	totalnum = mib_chain_total(MIB_PORT_BINDING_TBL);
	for(i=0;i<totalnum;i++)
	{
		mib_chain_get(MIB_PORT_BINDING_TBL, i, (void*)&pbEntry);
		//is it vlan-mapping lan-port?
		if((unsigned char)VLAN_BASED_MODE == pbEntry.pb_mode)
		{
			struct v_pair *vid_pair;
			int k;
			vid_pair = (struct v_pair *)&pbEntry.pb_vlan0_a;
			//Be sure the content of vlan-mapping exsit!
			for (k=0; k<4; k++)
			{
				if ((vid_pair[k].vid_b == vid || vid_pair[k].vid_a == vid) && vid_pair[k].vid_a !=0)
				{
					//flush_vconfig(vid_pair[k].vid_a,LanPortIdx);
					if(rtk_rg_vlanBinding_del(vid_pair[k].rg_vbind_entryID)!= SUCCESS){
						DBPRINT(1, "%s-%d rtk_rg_vlanBinding_del fail\n",__func__,__LINE__);
						return -1;
					}
					AUG_PRT("del rg vlan binding info index=%d, vid=%d\n",vid_pair[k].rg_vbind_entryID,vid);
				}
			}
		}
	}
	return 0;
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

#ifdef CONFIG_CMCC_MULTICAST_CROSS_VLAN_SUPPORT
const char RG_multicast_cross_vlan_filter_rules[] = "/tmp/rg_multicast_cross_vlan_filter_rules";
const char RG_multicast_cross_vlan_vid_rules[] = "/tmp/rg_multicast_cross_vlan_vid_rules";
int RG_flush_multicastCrossVlan()
{
	int filter_idx = -1;
	FILE *fp = NULL;
	rtk_rg_cvlan_info_t cvlan_info;
	unsigned short vid;
	int lanPortIdx;
	int ret;
	
	fp = fopen(RG_multicast_cross_vlan_vid_rules, "r");
	if(fp)
	{
		while (fscanf(fp, "%hu %d\n", &vid, &lanPortIdx) != EOF)
		{
			memset(&cvlan_info, 0x0, sizeof(rtk_rg_cvlan_info_t));
			cvlan_info.vlanId = vid;
			rtk_rg_cvlan_get(&cvlan_info);
			cvlan_info.memberPortMask.portmask &= ~ RG_get_lan_phyPortMask(lanPortIdx);
			//printf("%s vlan[%d] port[0x%x] portmask[0x%x]\n", __func__,vid,lanPortIdx,cvlan_info.memberPortMask.portmask);
			if(cvlan_info.memberPortMask.portmask == ((1<<RTK_RG_PORT_CPU) | (1<<RTK_RG_PORT_MAINCPU)))
			{
				ret = rtk_rg_cvlan_del(vid);
				if(ret!=RT_ERR_RG_OK)
					fprintf(stderr, "rtk_rg_cvlan_del failed. ret=0x%x \n",ret);
			}
			else
			{
				ret = rtk_rg_cvlan_add(&cvlan_info);
				if(ret!=RT_ERR_RG_OK)
					fprintf(stderr, "rtk_rg_cvlan_add failed. ret=0x%x \n",ret);
			}
		}
		fclose(fp);
		unlink(RG_multicast_cross_vlan_vid_rules);
	}
	
	if (!(fp = fopen(RG_multicast_cross_vlan_filter_rules, "r")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -1;
	}
	
	while (fscanf(fp, "%d\n", &filter_idx) != EOF)
	{
		if (rtk_rg_gponDsBcFilterAndRemarking_del(filter_idx))
			fprintf(stderr, "rtk_rg_gponDsBcFilterAndRemarking_del failed! idx = %d\n", filter_idx);
	}
	fclose(fp);
	unlink(RG_multicast_cross_vlan_filter_rules);
	//rtk_rg_gponDsBcFilterAndRemarking_Enable(RTK_RG_DISABLED);
	return 0;
}

int RG_add_multicastCrossVlan(unsigned short LanVid, int LanPortIdx)
{
	int ret;
	int filter_idx = -1;
	FILE *fp = NULL;
	rtk_rg_gpon_ds_bc_vlanfilterAndRemarking_t vlanfilter;
	rtk_rg_cvlan_info_t cvlan_info;
	
	if (!(fp = fopen(RG_multicast_cross_vlan_filter_rules, "a")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -1;
	}

	//rtk_rg_gponDsBcFilterAndRemarking_Enable(RTK_RG_ENABLED);

	memset(&vlanfilter, 0, sizeof(rtk_rg_gpon_ds_bc_vlanfilterAndRemarking_t));	
	vlanfilter.filter_fields |= GPON_DS_BC_FILTER_EGRESS_PORT_BIT;
	vlanfilter.egress_portmask.portmask= RG_get_lan_phyPortMask(LanPortIdx);
	
	vlanfilter.ctag_action.ctag_decision = RTK_RG_GPON_BC_FORCE_TAGGIN_WITH_CVID;
	vlanfilter.ctag_action.assigned_ctag_cvid = LanVid;
	vlanfilter.ctag_action.assigned_ctag_cpri = 0;

	ret = rtk_rg_gponDsBcFilterAndRemarking_add(&vlanfilter,&filter_idx);
	if(ret!=RT_ERR_RG_OK)
		fprintf(stderr, "rtk_rg_gponDsBcFilterAndRemarking_add failed. ret=0x%x \n",ret);
	else
		fprintf(fp, "%d\n", filter_idx);

	fclose(fp);

	/* add vlan table to allow ingress igmp report with vlan tag from lan ports */
	if (!(fp = fopen(RG_multicast_cross_vlan_vid_rules, "a")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -1;
	}
	memset(&cvlan_info, 0x0, sizeof(rtk_rg_cvlan_info_t));
	cvlan_info.vlanId = LanVid;
	rtk_rg_cvlan_get(&cvlan_info);
	cvlan_info.memberPortMask.portmask |= RG_get_lan_phyPortMask(LanPortIdx);
	cvlan_info.memberPortMask.portmask |= ((1<<RTK_RG_PORT_CPU) | (1<<RTK_RG_PORT_MAINCPU));
	cvlan_info.untagPortMask.portmask |= ((1<<RTK_RG_PORT_CPU) | (1<<RTK_RG_PORT_MAINCPU));

	ret = rtk_rg_cvlan_add(&cvlan_info);
	if(ret!=RT_ERR_RG_OK)
		fprintf(stderr, "rtk_rg_cvlan_add failed. ret=0x%x \n",ret);
	else
		fprintf(fp, "%d %d\n", LanVid, LanPortIdx);
	fclose(fp);
	
	return ret;
}
#endif

static inline int RG_get_wan_type(MIB_CE_ATM_VC_Tp entry)
{
	if(entry == NULL)
		return -1;

#if defined(CONFIG_IPV6) && defined(DUAL_STACK_LITE)
	//if ds-lite enable, special care first
	if(entry->dslite_enable){
		if(entry->cmode == CHANNEL_MODE_IPOE)
			return RTK_RG_DSLITE;

		else if(entry->cmode == CHANNEL_MODE_PPPOE)
			return RTK_RG_PPPoE_DSLITE;
	}
#endif

	switch(entry->cmode)
	{
	case CHANNEL_MODE_BRIDGE:
		return RTK_RG_BRIDGE;
	case CHANNEL_MODE_IPOE:
#if defined(CONFIG_IPV6)
		if ( entry->IpProtocol == IPVER_IPV6) {
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
int RG_del_static_route(MIB_CE_IP_ROUTE_T *entry, int entry_idx)
	{
	int ret=0;	
	if (entry->rg_staticRoute_idx >=0) {
		if(rtk_rg_staticRoute_del(entry->rg_staticRoute_idx) != SUCCESS){
			DBPRINT(1, "%s failed! (idx = %d)\n", __func__, entry->rg_staticRoute_idx);
			return -1;
		}
		else {
			entry->rg_staticRoute_idx = -1;
		}
	}	
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	if(entry->rg_acl_idx > 0) {
		RG_del_policy_route_by_acl(entry->rg_acl_idx);
		entry->rg_acl_idx = -1;
	}
#endif
	return 0;
}

#ifdef CONFIG_IPV6
int RG_del_static_route_v6(MIB_CE_IPV6_ROUTE_T *entry, int entryID)
{
	int ret=0;
	if (entry->rg_staticRoute_idx >=0) {
		if(rtk_rg_staticRoute_del(entry->rg_staticRoute_idx) != SUCCESS){
			DBPRINT(1, "%s failed! (idx = %d)\n", __func__, entry->rg_staticRoute_idx);
			return -1;
		}
		else {
			entry->rg_staticRoute_idx = -1;
		}
	}
	else
		mib_chain_update(MIB_IPV6_ROUTE_TBL,(void *)entry,entryID);
	return 0;
}
#endif

int RG_add_static_route(MIB_CE_IP_ROUTE_T *entry, int entryID)
				{
	int ret, index;
	rtk_rg_staticRoute_t staticRoute;
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	struct in_addr gateway;
#endif

	memset(&staticRoute,0,sizeof(rtk_rg_staticRoute_t));
	staticRoute.ipv4.addr = ntohl(((struct in_addr *)entry->destID)->s_addr);	
	staticRoute.ipv4.mask= ntohl(((struct in_addr *)entry->netMask)->s_addr);
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	if(entry->nextHopEnable==1){
		//printf("%s-%d\n",__func__,__LINE__);
		staticRoute.ipv4.nexthop = ntohl(((struct in_addr *)entry->nextHop)->s_addr);
	}
	else{
		//find intf's default gateway for RG API
		//printf("%s-%d\n",__func__,__LINE__);
		if(get_wan_gateway(entry->ifIndex, (struct in_addr *)&gateway)!=SUCCESS){
			printf("%s-%d get_wan_gateway fail! ret=%d\n",__func__,__LINE__,ret);
			return ret;
		}
		staticRoute.ipv4.nexthop = ntohl(gateway.s_addr);
	}
#else
	staticRoute.ipv4.nexthop = ntohl(((struct in_addr *)entry->nextHop)->s_addr);
#endif
	staticRoute.ip_version = 0;//0: ipv4, 1: ipv6
	staticRoute.nexthop_mac_auto_learn = 1;

	if((ret = rtk_rg_staticRoute_add(&staticRoute, &index))!=SUCCESS){
		printf("%s-%d add rtk_rg_staticRoute_add fail! ret=%d\n",__func__,__LINE__,ret);
		return ret;
	}
	else {
		printf("rtk_rg_staticRoute_add success!!\n");
		entry->rg_staticRoute_idx = index;
		mib_chain_update(MIB_IP_ROUTE_TBL, entry, entryID);
		return ret;
	}
}

#ifdef CONFIG_IPV6
int RG_add_static_route_v6(MIB_CE_IPV6_ROUTE_T *entry, int entryID)
{
	int ret, index;
	char dest[48]={};
	char prefix[4]={};
	char *split;
	rtk_rg_staticRoute_t staticRoute;
	memset(&staticRoute,0,sizeof(rtk_rg_staticRoute_t));

	strcpy(dest, entry->Dstination);
	split=strchr(dest, '/');
	*split='\0';
	strcpy(prefix, split+1);

	inet_pton(PF_INET6, dest, staticRoute.ipv6.addr.ipv6_addr);
	staticRoute.ipv6.mask_length=atoi(prefix);
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	if(entry->nextHopEnable==1){
		//printf("%s-%d\n",__func__,__LINE__);
		inet_pton(PF_INET6,entry->NextHop, staticRoute.ipv6.nexthop.ipv6_addr);
	}
	else{
		if(get_wan6_gateway(entry->DstIfIndex, staticRoute.ipv6.nexthop.ipv6_addr)!=SUCCESS){
			printf("%s-%d get_wan6_gateway fail! ret=%d\n",__func__,__LINE__,ret);
			return ret;
		}
	}
#else
	inet_pton(PF_INET6,entry->NextHop, staticRoute.ipv6.nexthop.ipv6_addr);
#endif
	staticRoute.ip_version=1;
	staticRoute.nexthop_mac_auto_learn=1;
	/*
printf("---[%s %d] dest= %02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X\n",\
	__func__, __LINE__, staticRoute.ipv6.addr.ipv6_addr[0], staticRoute.ipv6.addr.ipv6_addr[1], \
	staticRoute.ipv6.addr.ipv6_addr[2], staticRoute.ipv6.addr.ipv6_addr[3], \
	staticRoute.ipv6.addr.ipv6_addr[4], staticRoute.ipv6.addr.ipv6_addr[5], \
	staticRoute.ipv6.addr.ipv6_addr[6], staticRoute.ipv6.addr.ipv6_addr[7], \
	staticRoute.ipv6.addr.ipv6_addr[8], staticRoute.ipv6.addr.ipv6_addr[9], \
	staticRoute.ipv6.addr.ipv6_addr[10], staticRoute.ipv6.addr.ipv6_addr[11], \
	staticRoute.ipv6.addr.ipv6_addr[12], staticRoute.ipv6.addr.ipv6_addr[13], \
	staticRoute.ipv6.addr.ipv6_addr[14], staticRoute.ipv6.addr.ipv6_addr[15]);
printf("---[%s %d] prefix=%d\n", __func__, __LINE__, staticRoute.ipv6.mask_length);
printf("---[%s %d] dest= %02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X\n",\
	__func__, __LINE__, staticRoute.ipv6.nexthop.ipv6_addr[0], staticRoute.ipv6.nexthop.ipv6_addr[1], \
	staticRoute.ipv6.nexthop.ipv6_addr[2], staticRoute.ipv6.nexthop.ipv6_addr[3], \
	staticRoute.ipv6.nexthop.ipv6_addr[4], staticRoute.ipv6.nexthop.ipv6_addr[5], \
	staticRoute.ipv6.nexthop.ipv6_addr[6], staticRoute.ipv6.nexthop.ipv6_addr[7], \
	staticRoute.ipv6.nexthop.ipv6_addr[8], staticRoute.ipv6.nexthop.ipv6_addr[9], \
	staticRoute.ipv6.nexthop.ipv6_addr[10], staticRoute.ipv6.nexthop.ipv6_addr[11], \
	staticRoute.ipv6.nexthop.ipv6_addr[12], staticRoute.ipv6.nexthop.ipv6_addr[13], \
	staticRoute.ipv6.nexthop.ipv6_addr[14], staticRoute.ipv6.nexthop.ipv6_addr[15]);
	*/
	if((ret = rtk_rg_staticRoute_add(&staticRoute, &index))!=SUCCESS){
		printf("%s-%d add rtk_rg_staticRoute_add fail! ret=%d\n",__func__,__LINE__,ret);
		return ret;
	}
	else {
		printf("rtk_rg_staticRoute_add success!!\n");
		entry->rg_staticRoute_idx = index;
		mib_chain_update(MIB_IPV6_ROUTE_TBL, entry, entryID);
		return ret;
	}
}
#endif

#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
int RG_add_policy_route_by_acl(int rg_wan_idx, int ip_ver, char *ip_start, char *ip_end, char *gateway)
{
	int aclIdx = 0, ret = 0, wan_index = 0;
	rtk_rg_intfInfo_t intf_info;
	rtk_rg_ipDhcpClientInfo_t *dhcpClient_info = NULL;
	rtk_rg_pppoeClientInfoAfterDial_t *pppoeClientInfo = NULL;
	rtk_rg_aclFilterAndQos_t aclRule;
	wan_index = rg_wan_idx;

	ret = rtk_rg_intfInfo_find(&intf_info, &wan_index);
	if (ret != 0) {
		printf("[%s@%d] Find RG interface for wan index %d Fail!\n", __FUNCTION__, __LINE__, wan_index);
		return -1;
	}

	if (wan_index != rg_wan_idx) {
		printf("[%s@%d] Find RG interface for wan index %d Fail!\n", __FUNCTION__, __LINE__, wan_index);
		return -1;
	}

	if (ip_ver == IPVER_IPV4) {
		if (intf_info.wan_intf.wan_intf_conf.wan_type == RTK_RG_DHCP) { // DHCP WAN
			struct in_addr ina_gw;
			dhcpClient_info = &(intf_info.wan_intf.dhcp_client_info);
			if (gateway[0] != '\0') {
				inet_pton(AF_INET, gateway, &ina_gw);
			}
			if ((dhcpClient_info->hw_info.ipv4_default_gateway_on == 0) &&
				((dhcpClient_info->hw_info.static_route_with_arp != 1) ||
				(dhcpClient_info->hw_info.napt_enable != 1)))
			{
				dhcpClient_info->hw_info.static_route_with_arp = 1;
				dhcpClient_info->hw_info.napt_enable = 1;
				if (rtk_rg_dhcpClientInfo_set(rg_wan_idx, dhcpClient_info) != SUCCESS) {
					printf("[%s@%d] rtk_rg_dhcpClientInfo_set error!\n", __FUNCTION__, __LINE__);
					return -1;
				}
			}
		}
		else if (intf_info.wan_intf.wan_intf_conf.wan_type == RTK_RG_PPPoE) {  // PPPoE WAN didn't need  static route with arp
		}
	}

	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	aclRule.action_type = ACL_ACTION_TYPE_POLICY_ROUTE;

	aclRule.filter_fields |= INGRESS_PORT_BIT;
	aclRule.ingress_port_mask.portmask = RG_get_all_lan_phyPortMask();
#ifdef WLAN_SUPPORT
	aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN0));
#ifdef WLAN_DUALBAND_CONCURRENT
	aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN1));
#endif
#endif
	aclRule.ingress_port_mask.portmask |= (1 << RTK_RG_PORT_CPU);

	if (ip_ver == IPVER_IPV4) {
		struct in_addr ina_start, ina_end;
		aclRule.filter_fields |= INGRESS_IPV4_DIP_RANGE_BIT;

		inet_pton(AF_INET, ip_start, &ina_start);
		inet_pton(AF_INET, ip_end, &ina_end);
		aclRule.ingress_dest_ipv4_addr_start = ntohl(ina_start.s_addr);
		aclRule.ingress_dest_ipv4_addr_end = ntohl(ina_end.s_addr);
		aclRule.action_policy_route_wan = rg_wan_idx;
	}
	else if (ip_ver == IPVER_IPV6) {
		unsigned char addr_start[IP6_ADDR_LEN] = {0}, addr_end[IP6_ADDR_LEN] = {0};
		aclRule.filter_fields |= INGRESS_IPV6_DIP_RANGE_BIT;

		inet_pton(PF_INET6, ip_start,(void *)addr_start);
		inet_pton(PF_INET6, ip_end,(void *)addr_end);
		memcpy(aclRule.ingress_dest_ipv6_addr_start, addr_start, IPV6_ADDR_LEN);
		memcpy(aclRule.ingress_dest_ipv6_addr_end, addr_end, IPV6_ADDR_LEN);
		aclRule.action_policy_route_wan = rg_wan_idx;
	}
	if ((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) != 0) {
		printf("[%s@%d] RG_add_static_route_by_acl QoS rule failed! (ret = %d)\n", __FUNCTION__, __LINE__, ret);
		return -1;
	}
	return aclIdx;
}

int RG_del_policy_route_by_acl(int acl_idx)
{
	if (rtk_rg_aclFilterAndQos_del(acl_idx)) {
		DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", acl_idx);
		return -1;
	}
	return 0;
}
#endif


#ifdef _PRMT_X_CT_COM_WANEXT_
const char RG_ACL_POLICY_ROUTE[] = "/var/rg_acl_policy_route_idx";

int RG_add_static_route_by_acl(int rg_wan_idx, int ip_ver, char *ip_start, char *ip_end, char *gateway)
{
	int aclIdx = 0, ret = 0, wan_index = 0;
	char filename[64] = {0};
	FILE *fp = NULL;
	rtk_rg_intfInfo_t intf_info;
	rtk_rg_ipDhcpClientInfo_t *dhcpClient_info = NULL;
	rtk_rg_pppoeClientInfoAfterDial_t *pppoeClientInfo = NULL;
	rtk_rg_aclFilterAndQos_t aclRule;

	wan_index = rg_wan_idx;
	ret = rtk_rg_intfInfo_find(&intf_info, &wan_index);
	if (ret != 0) {
		printf("[%s@%d] Find RG interface for wan index %d Fail!\n", __FUNCTION__, __LINE__, wan_index);
		return -1;
	}

	if (wan_index != rg_wan_idx) {
		printf("[%s@%d] Find RG interface for wan index %d Fail!\n", __FUNCTION__, __LINE__, wan_index);
		return -1;
	}

	if (ip_ver == IPVER_IPV4) {
		if (intf_info.wan_intf.wan_intf_conf.wan_type == RTK_RG_DHCP) { // DHCP WAN
			struct in_addr ina_gw;
			memset(&ina_gw,0,sizeof(struct in_addr));
			memset(&dhcpClient_info, 0, sizeof(rtk_rg_ipDhcpClientInfo_t));
			dhcpClient_info = &(intf_info.wan_intf.dhcp_client_info);
			if (gateway[0] != '\0') {
				inet_pton(AF_INET, gateway, &ina_gw);
			}
			if ((dhcpClient_info->hw_info.static_route_with_arp != 1) || 
				(dhcpClient_info->hw_info.gateway_ipv4_addr != ntohl(ina_gw.s_addr)) ||
				(dhcpClient_info->hw_info.napt_enable != 1)) {
				dhcpClient_info->hw_info.static_route_with_arp = 1;
				dhcpClient_info->hw_info.gateway_ipv4_addr = ntohl(ina_gw.s_addr);
				dhcpClient_info->hw_info.napt_enable = 1;
				if (rtk_rg_dhcpClientInfo_set(rg_wan_idx, dhcpClient_info) != SUCCESS) {
					printf("[%s@%d] rtk_rg_dhcpClientInfo_set error!\n", __FUNCTION__, __LINE__);
					return -1;
				}
			}
		}
		else if (intf_info.wan_intf.wan_intf_conf.wan_type == RTK_RG_PPPoE) { // PPPoE WAN
			memset(&pppoeClientInfo, 0, sizeof(rtk_rg_pppoeClientInfoAfterDial_t));
			pppoeClientInfo = &(intf_info.wan_intf.pppoe_info.after_dial);
			if (pppoeClientInfo->hw_info.ipv4_default_gateway_on == 0 && pppoeClientInfo->hw_info.static_route_with_arp != 1) {
				pppoeClientInfo->hw_info.static_route_with_arp = 1;
				if ((rtk_rg_pppoeClientInfoAfterDial_set(rg_wan_idx, pppoeClientInfo)) != SUCCESS) {
					printf("[%s@%d] rtk_rg_pppoeClientInfoAfterDial_set error!\n", __FUNCTION__, __LINE__);
					return -1;
				}				
			}
		}
	}

	sprintf(filename, "%s_%d", RG_ACL_POLICY_ROUTE, rg_wan_idx);
	if (!(fp = fopen(filename, "a"))) {
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -2;
	}

	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));

	aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	aclRule.action_type = ACL_ACTION_TYPE_POLICY_ROUTE;
	if (ip_ver == IPVER_IPV4) {
		struct in_addr ina_start, ina_end;
		aclRule.filter_fields = INGRESS_IPV4_DIP_RANGE_BIT;

		inet_pton(AF_INET, ip_start, &ina_start);
		inet_pton(AF_INET, ip_end, &ina_end);
		aclRule.ingress_dest_ipv4_addr_start = ntohl(ina_start.s_addr);
		aclRule.ingress_dest_ipv4_addr_end = ntohl(ina_end.s_addr);
		aclRule.action_policy_route_wan = rg_wan_idx;
	}
	else if (ip_ver == IPVER_IPV6) {
		unsigned char addr_start[IP6_ADDR_LEN] = {0}, addr_end[IP6_ADDR_LEN] = {0};
		aclRule.filter_fields = INGRESS_IPV6_DIP_RANGE_BIT;

		inet_pton(PF_INET6, ip_start,(void *)addr_start);
		inet_pton(PF_INET6, ip_end,(void *)addr_end);
		memcpy(aclRule.ingress_dest_ipv6_addr_start, addr_start, IPV6_ADDR_LEN);
		memcpy(aclRule.ingress_dest_ipv6_addr_end, addr_end, IPV6_ADDR_LEN);
		aclRule.action_policy_route_wan = rg_wan_idx;
	}

	if ((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0) {
		fprintf(fp, "%d\n", aclIdx);
	}
	else {
		printf("[%s@%d] RG_add_static_route_by_acl QoS rule failed! (ret = %d)\n", __FUNCTION__, __LINE__, ret);
		fclose(fp);
		return -1;
	}

	fclose(fp);
	return 0;
}

int RG_del_static_route_by_acl(int rg_wan_idx)
{
	FILE *fp = NULL;
	int aclIdx = -1;
	char filename[64] = {0};

	sprintf(filename, "%s_%d", RG_ACL_POLICY_ROUTE, rg_wan_idx);
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

/*For E8C 2014 Test Plan 2.2.4/2.2.3*/
/*Two wan with the same VID + PortBinding MASK*/
/*
case 1: (2.2.3)
1)Routing Wan ipv4
2)Bridge Wan ipv6
case 2: (2.2.4)
1)Bridge Wan ipv4
2)Routing Wan ipv6
*/
int RTK_RG_Check_VID_PortBind(void)
{

	int totalVC_entry,i,j,k,wan_idx=-1,wanIntfIdx=-1;
	MIB_CE_ATM_VC_T entryVC, entryA;
	int ret;
	totalVC_entry = mib_chain_total(MIB_ATM_VC_TBL);
	for(i=totalVC_entry-1;i>=0;i--){
		if(mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&entryVC) == 0)
			continue;
		//if(entryVC.IpProtocol == IPVER_IPV4_IPV6)
		//	continue;
		if(entryVC.applicationtype != X_CT_SRV_INTERNET)
			continue;				
		k=i-1;
		for(j=k;j>=0;j--){
			if(mib_chain_get(MIB_ATM_VC_TBL, j, (void *)&entryA) == 0)
				continue;
			//if(entryA.IpProtocol == IPVER_IPV4_IPV6)
			//	continue;
			if(entryA.applicationtype != X_CT_SRV_INTERNET)
				continue;			
			//if(entryA.IpProtocol == IPVER_IPV4_IPV6)
			//	continue;
			if((entryVC.vid == entryA.vid)){
				rtk_rg_intfInfo_t *intf_info = NULL;
				rtk_rg_wanIntfConf_t *wan_info_p;
				intf_info = (rtk_rg_intfInfo_t *)malloc(sizeof(rtk_rg_intfInfo_t));
				if(intf_info == NULL){
					printf("%s-%d Can't get enough memory space!\n",__func__,__LINE__);
					ret = -1;
					goto ERR_VP;
				}
				memset(intf_info,0,sizeof(rtk_rg_intfInfo_t));
				if(entryVC.cmode == CHANNEL_MODE_BRIDGE && (entryA.cmode != CHANNEL_MODE_BRIDGE)){
					if((entryVC.itfGroup == entryA.itfGroup) && (entryVC.itfGroup > 0))
					{
						if(rtk_rg_intfInfo_find(intf_info,&entryVC.rg_wan_idx)!=SUCCESS){
							printf("%s-%d Can't find the wan interface idx:%d!",__func__,__LINE__,entryVC.rg_wan_idx);
							ret = -1;
							goto ERR_VP;
						}
						wan_info_p = &(intf_info->wan_intf.wan_intf_conf);
						wan_info_p->port_binding_mask.portmask = 0;
						wan_info_p->wlan0_dev_binding_mask = 0;
						wan_info_p->forcedAddNewIntf = 0;
						if((ret = rtk_rg_wanInterface_add(wan_info_p, &entryVC.rg_wan_idx))!=SUCCESS){
							printf("%s-%d rtk_rg_wanInterface_add fail! ret=%d\n",__func__,__LINE__,ret);
							ret = -1;
							goto ERR_VP;
						}
						memset(intf_info,0,sizeof(rtk_rg_intfInfo_t));
						//first routing wan's itfGroup will be replaced by second bridge~
						if(rtk_rg_intfInfo_find(intf_info,&entryA.rg_wan_idx)!=SUCCESS){
							printf("%s-%d Can't find the wan interface idx:%d!",__func__,__LINE__,entryA.rg_wan_idx);
							ret = -1;
							goto ERR_VP;
						}
						wan_info_p = &(intf_info->wan_intf.wan_intf_conf);
	#ifdef CONFIG_RTL9602C_SERIES
						wan_info_p->port_binding_mask.portmask = RG_get_lan_phyPortMask(entryA.itfGroup & 0x3);
						wan_info_p->wlan0_dev_binding_mask = ((entryA.itfGroup & 0xf8) >> 3);
	#else
						wan_info_p->port_binding_mask.portmask = RG_get_lan_phyPortMask(entryA.itfGroup & 0xf);
						wan_info_p->wlan0_dev_binding_mask = ((entryA.itfGroup & 0x1f0) >> 4);
	#endif
	#if defined(WLAN_DUALBAND_CONCURRENT)
	#ifdef CONFIG_RTL_CLIENT_MODE_SUPPORT
						wan_info_p->wlan0_dev_binding_mask |= ((entryA.itfGroup & 0x3e00) << 5);
	#else
						wan_info_p->wlan0_dev_binding_mask |= ((entryA.itfGroup & 0x3e00) << 4);
	#endif
	#endif
						wan_info_p->forcedAddNewIntf = 0;
						if((ret = rtk_rg_wanInterface_add(wan_info_p, &entryA.rg_wan_idx))!=SUCCESS){
							printf("%s-%d rtk_rg_wanInterface_add fail! ret=%d\n",__func__,__LINE__,ret);
							ret = -1;
							goto ERR_VP;
						}
					}


					/*case1: first wan is routed, second wan is bridged*/
					switch(entryVC.IpProtocol)
					{
					case IPVER_IPV4: // 2.IPv4 Bridge, 1.IPv6 Routing
						RTK_RG_Set_ACL_IPV6_PPPoE_from_Wan_KeepOVID(&entryA);
						RTK_RG_Set_ACL_IPV4_Bridge_from_Wan(&entryVC);
						system("echo 2 > /proc/rg/portBindingByProtocal");
						break;
					case IPVER_IPV6: // 2.IPv6 Bridge, 1.IPv4 Routing
						RTK_RG_Set_ACL_IPV4_PPPoE_from_Wan_KeepOVID(&entryA);
						RTK_RG_Set_ACL_IPV6_Bridge_from_Wan(&entryVC);
						system("echo 1 > /proc/rg/portBindingByProtocal");
						break;
					case IPVER_IPV4_IPV6:
						switch(entryA.IpProtocol)//routing protocol
						{
							case IPVER_IPV4:/*routing v4 only*/
								RTK_RG_Set_ACL_IPV4_PPPoE_from_Wan_KeepOVID(&entryA);
								RTK_RG_Set_ACL_IPV4V6_Bridge_from_Wan(&entryVC);
								break;
							case IPVER_IPV6:/*routing v6 only*/
								RTK_RG_Set_ACL_IPV6_PPPoE_from_Wan_KeepOVID(&entryA);
								RTK_RG_Set_ACL_IPV4V6_Bridge_from_Wan(&entryVC);
								break;
						}
						default:
						/*not implement*/
						break;
					}
#if 0//def CONFIG_EPON_FEATURE
					if(entryVC.vid > 0)
					{
						unsigned int pon_mode=0;
						mib_get(MIB_PON_MODE, (void *)&pon_mode);
						if(pon_mode == EPON_MODE)
						{
							RTK_RG_Set_ACL_Bridge_from_Lan(&entryVC);
						}
					}
#endif
					if((entryVC.itfGroup == entryA.itfGroup) && (entryVC.itfGroup > 0))
					{
						entryVC.check_br_pm = 1;
						mib_chain_update(MIB_ATM_VC_TBL, (void*)&entryVC, i);
					}
				}
				else if(entryVC.cmode != CHANNEL_MODE_BRIDGE && entryA.cmode == CHANNEL_MODE_BRIDGE){
					/*routing*/
					/*case2: first wan is bridged, second wan is routed*/
					/*we must remove first bridge wan's port binding mask.*/
/*
					if(rtk_rg_intfInfo_find(intf_info,&entryA.rg_wan_idx)!=SUCCESS){
						printf("%s-%d Can't find the wan interface idx:%d!",__func__,__LINE__,entryA.rg_wan_idx);
						ret = -1;
						goto ERR_VP;
					}
					wan_info_p = &(intf_info->wan_intf.wan_intf_conf);
					wan_info_p->port_binding_mask.portmask = 0;
					wan_info_p->wlan0_dev_binding_mask = 0;
					wan_info_p->forcedAddNewIntf = 0;

					//dump_wan_info(wan_info);
					if((ret = rtk_rg_wanInterface_add(wan_info_p, &entryA.rg_wan_idx))!=SUCCESS){
						printf("%s-%d rtk_rg_wanInterface_add fail! ret=%d\n",__func__,__LINE__,ret);
						ret = -1;
						goto ERR_VP;
					}
*/
					/*first bridge, second routing wan*/
					switch(entryA.IpProtocol)//bridge protocol
					{
						case IPVER_IPV6:  //2.IPv4 Routing, 1.IPv6 Bridge
						RTK_RG_Set_ACL_IPV4_PPPoE_from_Wan_KeepOVID(&entryVC);
						RTK_RG_Set_ACL_IPV6_Bridge_from_Wan(&entryA);
						system("echo 1 > /proc/rg/portBindingByProtocal");
							break;
						case IPVER_IPV4: //2.IPv6 Routing, 1.IPv4 Bridge
						RTK_RG_Set_ACL_IPV6_PPPoE_from_Wan_KeepOVID(&entryVC);
						RTK_RG_Set_ACL_IPV4_Bridge_from_Wan(&entryA);
						system("echo 2 > /proc/rg/portBindingByProtocal");
							break;
						case IPVER_IPV4_IPV6:
						switch(entryVC.IpProtocol)//routing protocol
						{
							case IPVER_IPV4:/*routing v4 only*/
								RTK_RG_Set_ACL_IPV4_PPPoE_from_Wan_KeepOVID(&entryVC);
								RTK_RG_Set_ACL_IPV4V6_Bridge_from_Wan(&entryA);
								break;
							case IPVER_IPV6:/*routing v6 only*/
								RTK_RG_Set_ACL_IPV6_PPPoE_from_Wan_KeepOVID(&entryVC);
								RTK_RG_Set_ACL_IPV4V6_Bridge_from_Wan(&entryA);
								break;
						}
						default:
						/*not implement*/
							break;
					}
#if 0//def CONFIG_EPON_FEATURE
					if(entryA.vid > 0)
					{
						unsigned int pon_mode=0;
						mib_get(MIB_PON_MODE, (void *)&pon_mode);
						if(pon_mode == EPON_MODE)
						{
							RTK_RG_Set_ACL_Bridge_from_Lan(&entryA);
						}
					}
#endif
					if((entryVC.itfGroup == entryA.itfGroup) && (entryVC.itfGroup > 0))
					{
						entryA.check_br_pm = 1;
						mib_chain_update(MIB_ATM_VC_TBL, (void*)&entryA, j);
					}
				}
				ERR_VP:
					if(intf_info)
						free(intf_info);
				return 1;
			}
		}

	}
	system("echo 0 > /proc/rg/portBindingByProtocal");

	return 0;

}

int RTK_RG_Set_IPv4_IPv6_Vid_Binding_ACL(void)
{
	int ret, totalVC_entry,i;
	MIB_CE_ATM_VC_T entryVC;
	totalVC_entry = mib_chain_total(MIB_ATM_VC_TBL);
	ret = RTK_RG_Check_VID_PortBind();
//fprintf(stderr, "%s-%d ret=%d\n",__func__,__LINE__,ret);
	if(ret == 0)
	{
		for(i=0;i<totalVC_entry;i++){
			if(mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&entryVC) == 0)
				continue;
			//fprintf(stderr, "%s-%d i=%d, entryVC.check_br_pm=%d\n",__func__,__LINE__,i,entryVC.check_br_pm);

			if(entryVC.check_br_pm)
			{
				//fprintf(stderr, "%s-%d entryVC.cmode=%d\n",__func__,__LINE__,entryVC.cmode);

				//reset BridgeWan's port mask
				if(entryVC.cmode == CHANNEL_MODE_BRIDGE)
				{
					rtk_rg_intfInfo_t *intf_info = NULL;
					rtk_rg_wanIntfConf_t *wan_info_p = NULL;
					intf_info = (rtk_rg_intfInfo_t *)malloc(sizeof(rtk_rg_intfInfo_t));
					if(intf_info == NULL){
						printf("%s-%d Can't get enough memory space!\n",__func__,__LINE__);
						ret = -1;
						goto ERR_CHECK_BR;
					}
					memset(intf_info,0,sizeof(rtk_rg_intfInfo_t));

					if(rtk_rg_intfInfo_find(intf_info,&entryVC.rg_wan_idx)!=SUCCESS){
						printf("%s-%d Can't find the wan interface idx:%d!",__func__,__LINE__,entryVC.rg_wan_idx);
						ret = -1;
						free(intf_info);;
						goto ERR_CHECK_BR;
					}
					wan_info_p = &(intf_info->wan_intf.wan_intf_conf);
					#ifdef CONFIG_RTL9602C_SERIES
					wan_info_p->port_binding_mask.portmask =  RG_get_lan_phyPortMask(entryVC.itfGroup & 0x3);
					#else
					wan_info_p->port_binding_mask.portmask = RG_get_lan_phyPortMask(entryVC.itfGroup & 0xf);
					#endif
					#ifdef WLAN_SUPPORT
					wan_info_p->wlan0_dev_binding_mask = (((entryVC.itfGroup >> ITFGROUP_WLAN0_DEV_BIT) & ITFGROUP_WLAN_MASK) << RG_RET_MBSSID_MASTER_ROOT_INTF);
					#endif

					wan_info_p->forcedAddNewIntf = 0;
					if((ret = rtk_rg_wanInterface_add(wan_info_p, &entryVC.rg_wan_idx))!=SUCCESS){
						printf("%s-%d rtk_rg_wanInterface_add fail! ret=%d\n",__func__,__LINE__,ret);
						ret = -1;
						free(intf_info);;
						goto ERR_CHECK_BR;
					}
					entryVC.check_br_pm = 0;
					//fprintf(stderr, "%s-%d entryVC.check_br_pm=%d\n",__func__,__LINE__,entryVC.check_br_pm);
					mib_chain_update(MIB_ATM_VC_TBL, (void*)&entryVC, i);
					free(intf_info);;
				}
			}
		}
	}
	ERR_CHECK_BR:
	return ret;
}
int Flush_RTK_RG_IPv4_Bridge_From_Wan_ACL(void)
{
	FILE *fp;
	int acl_idx;

	if(!(fp = fopen(RG_IPV4_Bridge_From_Wan_ACL_RILES, "r")))
		return -2;

	while(fscanf(fp, "%d\n", &acl_idx) != EOF)
	{
		if(rtk_rg_aclFilterAndQos_del(acl_idx))
			DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", acl_idx);
	}

	fclose(fp);
	unlink(RG_IPV4_Bridge_From_Wan_ACL_RILES);
	return 0;
}

int Flush_RTK_RG_IPv4_PPPoE_From_Wan_ACL(void)
{
	FILE *fp;
	int acl_idx;

	if(!(fp = fopen(RG_IPV4_PPPoE_From_Wan_KeepOVID_ACL_RILES, "r")))
		return -2;

	while(fscanf(fp, "%d\n", &acl_idx) != EOF)
	{
		if(rtk_rg_aclFilterAndQos_del(acl_idx))
			DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", acl_idx);
	}

	fclose(fp);
	unlink(RG_IPV4_PPPoE_From_Wan_KeepOVID_ACL_RILES);
	return 0;
}


int Flush_RTK_RG_IPv6_Bridge_From_Wan_ACL(void)
{
	FILE *fp;
	int acl_idx;

	if(!(fp = fopen(RG_IPV6_Bridge_From_Wan_ACL_RILES, "r")))
		return -2;

	while(fscanf(fp, "%d\n", &acl_idx) != EOF)
	{
		if(rtk_rg_aclFilterAndQos_del(acl_idx))
			DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", acl_idx);
	}

	fclose(fp);
	unlink(RG_IPV6_Bridge_From_Wan_ACL_RILES);
	return 0;
}

int Flush_RTK_RG_IPv6_PPPoE_From_Wan_ACL(void)
{
	FILE *fp;
	int acl_idx;

	if(!(fp = fopen(RG_IPV6_PPPoE_From_Wan_KeepOVID_ACL_RILES, "r")))
		return -2;

	while(fscanf(fp, "%d\n", &acl_idx) != EOF)
	{
		if(rtk_rg_aclFilterAndQos_del(acl_idx))
			DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", acl_idx);
	}

	fclose(fp);
	unlink(RG_IPV6_PPPoE_From_Wan_KeepOVID_ACL_RILES);


	return 0;
}

int Flush_RTK_RG_IPV4V6_Bridge_from_Wan_ACL(void)
{
	FILE *fp;
	int acl_idx;

	if(!(fp = fopen(RG_IPV4V6_Bridge_From_Wan_ACL_RILES, "r")))
		return -2;

	while(fscanf(fp, "%d\n", &acl_idx) != EOF)
	{
		if(rtk_rg_aclFilterAndQos_del(acl_idx))
			DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", acl_idx);
	}

	fclose(fp);
	unlink(RG_IPV4V6_Bridge_From_Wan_ACL_RILES);
	return 0;
}

#ifdef CONFIG_EPON_FEATURE
int Flush_RTK_RG_Bridge_from_Lan_ACL(void)
{
	FILE *fp = NULL;
	int acl_idx=-1,i;
	MIB_CE_ATM_VC_T entry;

	int totalEntry = mib_chain_total(MIB_ATM_VC_TBL);
	for(i;i<totalEntry;i++)
	{
		char filename[64] = {0};
	
		if(mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&entry) == 0)
			continue;
		if(entry.enable == 0 || entry.rg_wan_idx <=0)
			continue;
		sprintf(filename, "%s_%d", RG_Bridge_From_Lan_ACL_RILES, entry.rg_wan_idx);
		if (!(fp = fopen(filename, "a"))) {
			fprintf(stderr, "ERROR! %s\n", strerror(errno));
			return -2;
		}		
		while(fscanf(fp, "%d\n", &acl_idx) != EOF)
		{
			//AUG_PRT("del acl index %d\n",acl_idx);
			if(rtk_rg_aclFilterAndQos_del(acl_idx))
				DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", acl_idx);
		}

		fclose(fp);
		unlink(filename);
	}
	return 0;
}
int Flush_RTK_RG_Bridge_from_Lan_ACL_perWan(int wan_idx)
{
	FILE *fp = NULL;
	int acl_idx = -1;
	char filename[64] = {0};

	sprintf(filename, "%s_%d", RG_Bridge_From_Lan_ACL_RILES, wan_idx);
	if (!(fp = fopen(filename, "a"))) {
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -2;
	}

	while(fscanf(fp, "%d\n", &acl_idx) != EOF)
	{
		//AUG_PRT("del acl index %d\n",acl_idx);
		if(rtk_rg_aclFilterAndQos_del(acl_idx))
			DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", acl_idx);
	}

	fclose(fp);
	unlink(filename);
	return 0;
}

#endif
int Flush_RTK_RG_IPv4_IPv6_Vid_Binding_ACL(void)
{
	Flush_RTK_RG_IPv4_Bridge_From_Wan_ACL();
	Flush_RTK_RG_IPv4_PPPoE_From_Wan_ACL();
	Flush_RTK_RG_IPv6_Bridge_From_Wan_ACL();
	Flush_RTK_RG_IPv6_PPPoE_From_Wan_ACL();
	Flush_RTK_RG_IPV4V6_Bridge_from_Wan_ACL();
	return 0;
}

int RTK_RG_Set_ACL_IPV4V6_Bridge_from_Wan(MIB_CE_ATM_VC_Tp entry)
{
	FILE *fp;
	rtk_rg_aclFilterAndQos_t aclRule;
	int aclIdx, ret;
	rtk_rg_initParams_t init_param;
    char cmdStr[64];
	bzero(&init_param, sizeof(rtk_rg_initParams_t));
	if((ret = rtk_rg_initParam_get(&init_param)) != SUCCESS)
	{
		fprintf(stderr, "rtk_rg_initParam_set failed! ret=%d\n", ret);
		return -1;
	}
	if(!(fp = fopen(RG_IPV4V6_Bridge_From_Wan_ACL_RILES, "a")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -2;
	}
#if 0
	//For IPv4v6 IPoE Bridge packet from Wan
	//rg clear acl-filter
	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	//rg set acl-filter fwding_type_and_direction 0
	aclRule.fwding_type_and_direction =  ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	//rg set acl-filter pattern ingress_port_mask 0x10
	aclRule.filter_fields |= INGRESS_PORT_BIT;
	aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();//wan port
	aclRule.acl_weight = RG_DEFAULT_ACL_WEIGHT;
	if(entry->vid > 0){
		//rg set acl-filter pattern ingress_ctagIf 1
   		aclRule.filter_fields |= INGRESS_CTAGIF_BIT;
		aclRule.ingress_ctagIf = 1;
		//rg set acl-filter pattern ingress_ctag_vid 45
		aclRule.filter_fields |= INGRESS_CTAG_VID_BIT;
		aclRule.ingress_ctag_vid = entry->vid;
	}
	//rg set acl-filter action action_type 3
	aclRule.action_type = ACL_ACTION_TYPE_QOS;
	//rg set acl-filter action qos action_ingress_vid 4005
	aclRule.qos_actions |= ACL_ACTION_ACL_INGRESS_VID_BIT;
	aclRule.action_acl_ingress_vid = init_param.fwdVLAN_BIND_INTERNET; //lan interface's vlan
	//rg add acl-filter entry
	if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0){
		fprintf(fp,"%d\n",aclIdx);
		//fprintf(stderr, "add %s-%d Vlan:%d, index=%d success\n",__func__,__LINE__,entry->vid, aclIdx);
	}else{
		fprintf(stderr,"%s-%d add rule failed! (ret = %d)\n",__func__,__LINE__, ret);
		fclose(fp);
		return -1;
	}
#endif
	//trap upstream ipv6 pppoe bridge
	//rg clear acl-filter
	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	//rg set acl-filter pattern ingress_port_mask 0xf
	aclRule.filter_fields |= INGRESS_PORT_BIT;
	aclRule.ingress_port_mask.portmask = RG_get_all_lan_phyPortMask();
#ifdef WLAN_SUPPORT //master and slave ext port
	aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN0));
	aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN1));
	aclRule.ingress_port_mask.portmask |= (1 << RTK_RG_PORT_CPU);
#endif	
	//rg set acl-filter pattern ingress_ethertype 0x8864
	aclRule.filter_fields |= INGRESS_ETHERTYPE_BIT;
	aclRule.ingress_ethertype = 0x8864;
	aclRule.action_type = ACL_ACTION_TYPE_TRAP;
	//rg add acl-filter entry
	if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0){
		fprintf(fp,"%d\n",aclIdx);
		//fprintf(stderr, "add %s-%d Vlan:%d, index=%d success\n",__func__,__LINE__,entry->vid, aclIdx);
	}else{
		fprintf(stderr,"%s-%d add rule failed! (ret = %d)\n",__func__,__LINE__, ret);
		fclose(fp);
		return -1;
	}
	snprintf(cmdStr, sizeof(cmdStr),"echo 1 > /proc/rg/pppoe_bc_passthrought_to_bindingWan");
	system(cmdStr);
	fclose(fp);

}
int RTK_RG_Set_ACL_IPV6_Bridge_from_Wan(MIB_CE_ATM_VC_Tp entry)
{
	FILE *fp;
	rtk_rg_aclFilterAndQos_t aclRule;
	int aclIdx, ret;
	rtk_rg_initParams_t init_param;
	bzero(&init_param, sizeof(rtk_rg_initParams_t));
	if((ret = rtk_rg_initParam_get(&init_param)) != SUCCESS)
	{
		fprintf(stderr, "rtk_rg_initParam_set failed! ret=%d\n", ret);
		return -1;
	}
	if(!(fp = fopen(RG_IPV6_Bridge_From_Wan_ACL_RILES, "a")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -2;
	}
#if 0
	//For IPv6 IPoE Bridge packet from Wan
	//rg clear acl-filter
	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	//rg set acl-filter fwding_type_and_direction 0
	aclRule.fwding_type_and_direction =  ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	//rg set acl-filter pattern ingress_port_mask 0x10
	aclRule.filter_fields |= INGRESS_PORT_BIT;
	aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();//wan port
	aclRule.acl_weight = RG_DEFAULT_ACL_WEIGHT;
	if(entry->vid > 0){
		//rg set acl-filter pattern ingress_ctagIf 1
   		aclRule.filter_fields |= INGRESS_CTAGIF_BIT;
		aclRule.ingress_ctagIf = 1;
		//rg set acl-filter pattern ingress_ctag_vid 45
		aclRule.filter_fields |= INGRESS_CTAG_VID_BIT;
		aclRule.ingress_ctag_vid = entry->vid;
	}
	//rg set acl-filter pattern ingress_ethertype 0x86dd (ipv6)
	aclRule.filter_fields |= INGRESS_ETHERTYPE_BIT;
	aclRule.ingress_ethertype = 0x86dd;
	//rg set acl-filter action action_type 3
	aclRule.action_type = ACL_ACTION_TYPE_QOS;
	//rg set acl-filter action qos action_ingress_vid 4005
	aclRule.qos_actions |= ACL_ACTION_ACL_INGRESS_VID_BIT;
	aclRule.action_acl_ingress_vid = init_param.fwdVLAN_BIND_INTERNET; //lan interface's vlan
	//rg add acl-filter entry
	if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0){
		fprintf(fp,"%d\n",aclIdx);
		//fprintf(stderr, "add %s-%d Vlan:%d, index=%d success\n",__func__,__LINE__,entry->vid, aclIdx);
	}else{
		fprintf(stderr,"%s-%d add rule failed! (ret = %d)\n",__func__,__LINE__, ret);
		fclose(fp);
		return -1;
	}
	//For IPv6 PPPoE(0x8863/8864) Bridge packet from Wan
	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	//rg set acl-filter fwding_type_and_direction 0
	aclRule.fwding_type_and_direction =  ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	//rg set acl-filter pattern ingress_port_mask 0x10
	aclRule.filter_fields |= INGRESS_PORT_BIT;
	aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();//wan port
	aclRule.acl_weight = RG_DEFAULT_ACL_WEIGHT;
	if(entry->vid > 0){
		//rg set acl-filter pattern ingress_ctagIf 1
   		aclRule.filter_fields |= INGRESS_CTAGIF_BIT;
		aclRule.ingress_ctagIf = 1;
		//rg set acl-filter pattern ingress_ctag_vid 45
		aclRule.filter_fields |= INGRESS_CTAG_VID_BIT;
		aclRule.ingress_ctag_vid = entry->vid;
	}
	//rg set acl-filter pattern ingress_ethertype 0x8863
	aclRule.filter_fields |= INGRESS_ETHERTYPE_BIT;
	aclRule.ingress_ethertype = 0x8860;
	aclRule.ingress_ethertype_mask = 0xFFF0;	
	//rg set acl-filter action action_type 3
	aclRule.action_type = ACL_ACTION_TYPE_QOS;
	//rg set acl-filter action qos action_ingress_vid 4005
	aclRule.qos_actions |= ACL_ACTION_ACL_INGRESS_VID_BIT;
	aclRule.action_acl_ingress_vid = init_param.fwdVLAN_BIND_INTERNET; //lan interface's vlan
	//rg add acl-filter entry
	if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0){
		fprintf(fp,"%d\n",aclIdx);
		//fprintf(stderr, "add %s-%d Vlan:%d, index=%d success\n",__func__,__LINE__,entry->vid, aclIdx);
	}else{
		fprintf(stderr,"%s-%d add rule failed! (ret = %d)\n",__func__,__LINE__, ret);
		fclose(fp);
		return -1;
	}
#endif
#if 0		
	//For IPv6 PPPoE(0x8864) Bridge packet from Wan
	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	//rg set acl-filter fwding_type_and_direction 0
	aclRule.fwding_type_and_direction =  ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	//rg set acl-filter pattern ingress_port_mask 0x10
	aclRule.filter_fields |= INGRESS_PORT_BIT;
	aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();//wan port
	aclRule.acl_weight = RG_DEFAULT_ACL_WEIGHT;
	if(entry->vid > 0){
		//rg set acl-filter pattern ingress_ctagIf 1
   		aclRule.filter_fields |= INGRESS_CTAGIF_BIT;
		aclRule.ingress_ctagIf = 1;
		//rg set acl-filter pattern ingress_ctag_vid 45
		aclRule.filter_fields |= INGRESS_CTAG_VID_BIT;
		aclRule.ingress_ctag_vid = entry->vid;
	}
	//rg set acl-filter pattern ingress_ethertype 0x8864
	aclRule.filter_fields |= INGRESS_ETHERTYPE_BIT;
	aclRule.ingress_ethertype = 0x8864;
	//rg set acl-filter action action_type 3
	aclRule.action_type = ACL_ACTION_TYPE_QOS;
	//rg set acl-filter action qos action_ingress_vid 4005
	aclRule.qos_actions |= ACL_ACTION_ACL_INGRESS_VID_BIT;
	aclRule.action_acl_ingress_vid = init_param.fwdVLAN_BIND_INTERNET; //lan interface's vlan
	//rg add acl-filter entry
	if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0){
		fprintf(fp,"%d\n",aclIdx);
		//fprintf(stderr, "add %s-%d Vlan:%d, index=%d success\n",__func__,__LINE__,entry->vid, aclIdx);
	}else{
		fprintf(stderr,"%s-%d add rule failed! (ret = %d)\n",__func__,__LINE__, ret);
		fclose(fp);
		return -1;
	}
#endif		
	//trap upstream ipv6 pppoe bridge
	//rg clear acl-filter
	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	//rg set acl-filter pattern ingress_port_mask 0xf
	aclRule.filter_fields |= INGRESS_PORT_BIT;
	aclRule.ingress_port_mask.portmask = RG_get_all_lan_phyPortMask();
#ifdef WLAN_SUPPORT //master and slave ext port
	aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN0));
	aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN1));
	aclRule.ingress_port_mask.portmask |= (1 << RTK_RG_PORT_CPU);
#endif	
	//rg set acl-filter pattern ingress_ethertype 0x8864
	aclRule.filter_fields |= INGRESS_ETHERTYPE_BIT;
	aclRule.ingress_ethertype = 0x8864;
	//rg set acl-filter pattern ingress_ipv6_tagif 1
	//aclRule.filter_fields |= INGRESS_IPV6_TAGIF_BIT;
	//aclRule.ingress_ipv6_tagif = 1;
	//rg set acl-filter action action_type 2
	aclRule.action_type = ACL_ACTION_TYPE_TRAP;
	//rg add acl-filter entry
	if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0){
		fprintf(fp,"%d\n",aclIdx);
		//fprintf(stderr, "add %s-%d Vlan:%d, index=%d success\n",__func__,__LINE__,entry->vid, aclIdx);
	}else{
		fprintf(stderr,"%s-%d add rule failed! (ret = %d)\n",__func__,__LINE__, ret);
		fclose(fp);
		return -1;
	}

#if 0//def WLAN_SUPPORT //master and slave ext port
	//trap upstream ipv6 pppoe bridge from wifi
	//Can't bind the LAN with EXT port
	//[WARNING] Macport and extPort should be seperate as two ACL rule!
	//rg clear acl-filter
	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	//rg set acl-filter pattern ingress_port_mask 0x180
	aclRule.filter_fields |= INGRESS_PORT_BIT;
	aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN0));
	aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN1));
	//rg set acl-filter pattern ingress_ethertype 0x8864
	aclRule.filter_fields |= INGRESS_ETHERTYPE_BIT;
	aclRule.ingress_ethertype = 0x8864;
	aclRule.ingress_ipv6_tagif = 1;
	//rg set acl-filter action action_type 2
	aclRule.action_type = ACL_ACTION_TYPE_TRAP;
	//rg add acl-filter entry
	if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0){
		fprintf(fp,"%d\n",aclIdx);
		//fprintf(stderr, "add %s-%d Vlan:%d, index=%d success\n",__func__,__LINE__,entry->vid, aclIdx);
	}else{
		fprintf(stderr,"%s-%d add rule failed! (ret = %d)\n",__func__,__LINE__, ret);
		fclose(fp);
		return -1;
	}
#endif

	fclose(fp);
	return 0;
}
int RTK_RG_Set_ACL_IPV4_Bridge_from_Wan(MIB_CE_ATM_VC_Tp entry)
{
	FILE *fp;
	rtk_rg_aclFilterAndQos_t aclRule;
	int aclIdx, ret;
	int pon_mode;
	if(!(fp = fopen(RG_IPV4_Bridge_From_Wan_ACL_RILES, "a")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -2;
	}
#if 0
	//For IPv4 IPoE Bridge packet from Wan
	//rg clear acl-filter
	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	//rg set acl-filter fwding_type_and_direction 0
	aclRule.fwding_type_and_direction =  ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	//rg set acl-filter pattern ingress_port_mask 0x10
	aclRule.filter_fields |= INGRESS_PORT_BIT;
	aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();//wan port
	aclRule.acl_weight = RG_DEFAULT_ACL_WEIGHT;
	if(entry->vid > 0){
		//rg set acl-filter pattern ingress_ctagIf 1
   		aclRule.filter_fields |= INGRESS_CTAGIF_BIT;
		aclRule.ingress_ctagIf = 1;
		//rg set acl-filter pattern ingress_ctag_vid 45
		aclRule.filter_fields |= INGRESS_CTAG_VID_BIT;
		aclRule.ingress_ctag_vid = entry->vid;
	}
//	fprintf(stderr, "%s-%d entry->vid=%d\n",__func__,__LINE__,entry->vid);

	//rg set acl-filter pattern ingress_ethertype 0x0800 (ipv4)
	aclRule.filter_fields |= INGRESS_ETHERTYPE_BIT;
	aclRule.ingress_ethertype = 0x0800;
	//rg set acl-filter action action_type 3
	aclRule.action_type = ACL_ACTION_TYPE_QOS;
	//rg set acl-filter action qos action_ingress_vid 4005
	aclRule.qos_actions |= ACL_ACTION_ACL_INGRESS_VID_BIT;
	aclRule.action_acl_ingress_vid = init_param.fwdVLAN_BIND_INTERNET; //lan interface's vlan
	//rg add acl-filter entry
	if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0){
		fprintf(fp,"%d\n",aclIdx);
		//fprintf(stderr, "add %s-%d Vlan:%d, index=%d success\n",__func__,__LINE__,entry->vid, aclIdx);
	}else{
		fprintf(stderr,"%s-%d add rule failed! (ret = %d)\n",__func__,__LINE__, ret);
		fclose(fp);
		return -1;
	}
	//For IPv4 IPoE Bridge packet from Wan
	//rg clear acl-filter
	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	//rg set acl-filter fwding_type_and_direction 0
	aclRule.fwding_type_and_direction =  ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	//rg set acl-filter pattern ingress_port_mask 0x10
	aclRule.filter_fields |= INGRESS_PORT_BIT;
	aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();//wan port
	aclRule.acl_weight = RG_DEFAULT_ACL_WEIGHT;
	if(entry->vid > 0){
		//rg set acl-filter pattern ingress_ctagIf 1
   		aclRule.filter_fields |= INGRESS_CTAGIF_BIT;
		aclRule.ingress_ctagIf = 1;
		//rg set acl-filter pattern ingress_ctag_vid 45
		aclRule.filter_fields |= INGRESS_CTAG_VID_BIT;
		aclRule.ingress_ctag_vid = entry->vid;
	}
	//rg set acl-filter pattern ingress_ethertype 0x0806 (ipv4)
	aclRule.filter_fields |= INGRESS_ETHERTYPE_BIT;
	aclRule.ingress_ethertype = 0x0806;
	//rg set acl-filter action action_type 3
	aclRule.action_type = ACL_ACTION_TYPE_QOS;
	//rg set acl-filter action qos action_ingress_vid 4005
	aclRule.qos_actions |= ACL_ACTION_ACL_INGRESS_VID_BIT;
	aclRule.action_acl_ingress_vid = init_param.fwdVLAN_BIND_INTERNET; //lan interface's vlan
	//rg add acl-filter entry
	if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0){
		fprintf(fp,"%d\n",aclIdx);
		//fprintf(stderr, "add %s-%d Vlan:%d, index=%d success\n",__func__,__LINE__,entry->vid, aclIdx);
	}else{
		fprintf(stderr,"%s-%d add rule failed! (ret = %d)\n",__func__,__LINE__, ret);
		fclose(fp);
		return -1;
	}

	//For IPv4 PPPoE(0x8863/8864) Bridge packet from Wan
	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	//rg set acl-filter fwding_type_and_direction 0
	aclRule.fwding_type_and_direction =  ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	//rg set acl-filter pattern ingress_port_mask 0x10
	aclRule.filter_fields |= INGRESS_PORT_BIT;
	aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();//wan port
	aclRule.acl_weight = RG_DEFAULT_ACL_WEIGHT;
	if(entry->vid > 0){
		//rg set acl-filter pattern ingress_ctagIf 1
   		aclRule.filter_fields |= INGRESS_CTAGIF_BIT;
		aclRule.ingress_ctagIf = 1;
		//rg set acl-filter pattern ingress_ctag_vid 45
		aclRule.filter_fields |= INGRESS_CTAG_VID_BIT;
		aclRule.ingress_ctag_vid = entry->vid;
	}
	//rg set acl-filter pattern ingress_ethertype 0x8863
	aclRule.filter_fields |= INGRESS_ETHERTYPE_BIT;
	aclRule.ingress_ethertype = 0x8860;
	aclRule.ingress_ethertype_mask = 0xFFF0;

	//rg set acl-filter action action_type 3
	aclRule.action_type = ACL_ACTION_TYPE_QOS;
	//rg set acl-filter action qos action_ingress_vid 4005
	aclRule.qos_actions |= ACL_ACTION_ACL_INGRESS_VID_BIT;
	aclRule.action_acl_ingress_vid = init_param.fwdVLAN_BIND_INTERNET; //lan interface's vlan
	//rg add acl-filter entry
	if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0){
		fprintf(fp,"%d\n",aclIdx);
		//fprintf(stderr, "add %s-%d Vlan:%d, index=%d success\n",__func__,__LINE__,entry->vid, aclIdx);
	}else{
		fprintf(stderr,"%s-%d add rule failed! (ret = %d)\n",__func__,__LINE__, ret);
		fclose(fp);
		return -1;
	}
#endif
#if 0		
	//For IPv4 PPPoE(0x8864) Bridge packet from Wan
	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	//rg set acl-filter fwding_type_and_direction 0
	aclRule.fwding_type_and_direction =  ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	//rg set acl-filter pattern ingress_port_mask 0x10
	aclRule.filter_fields |= INGRESS_PORT_BIT;
	aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();//wan port
	aclRule.acl_weight = RG_DEFAULT_ACL_WEIGHT;
	if(entry->vid > 0){
		//rg set acl-filter pattern ingress_ctagIf 1
   		aclRule.filter_fields |= INGRESS_CTAGIF_BIT;
		aclRule.ingress_ctagIf = 1;
		//rg set acl-filter pattern ingress_ctag_vid 45
		aclRule.filter_fields |= INGRESS_CTAG_VID_BIT;
		aclRule.ingress_ctag_vid = entry->vid;
	}
	//rg set acl-filter pattern ingress_ethertype 0x8864
	aclRule.filter_fields |= INGRESS_ETHERTYPE_BIT;
	aclRule.ingress_ethertype = 0x8864;
	//rg set acl-filter action action_type 3
	aclRule.action_type = ACL_ACTION_TYPE_QOS;
	//rg set acl-filter action qos action_ingress_vid 4005
	aclRule.qos_actions |= ACL_ACTION_ACL_INGRESS_VID_BIT;
	aclRule.action_acl_ingress_vid = init_param.fwdVLAN_BIND_INTERNET; //lan interface's vlan
	//rg add acl-filter entry
	if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0){
		fprintf(fp,"%d\n",aclIdx);
		//fprintf(stderr, "add %s-%d Vlan:%d, index=%d success\n",__func__,__LINE__,entry->vid, aclIdx);
	}else{
		fprintf(stderr,"%s-%d add rule failed! (ret = %d)\n",__func__,__LINE__, ret);
		fclose(fp);
		return -1;
	}
#endif		
	//trap upstream ipv4 pppoe bridge
	//rg clear acl-filter
	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	//rg set acl-filter pattern ingress_port_mask 0xf
	aclRule.filter_fields |= INGRESS_PORT_BIT;
	aclRule.ingress_port_mask.portmask = RG_get_all_lan_phyPortMask();
#ifdef WLAN_SUPPORT //master and slave ext port
	aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN0));
	aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN1));
	aclRule.ingress_port_mask.portmask |= (1 << RTK_RG_PORT_CPU);
#endif
	//rg set acl-filter pattern ingress_ethertype 0x8864
	aclRule.filter_fields |= INGRESS_ETHERTYPE_BIT;
	aclRule.ingress_ethertype = 0x8864;
	//rg set acl-filter pattern ingress_ipv4_tagif 1
	//aclRule.filter_fields |= INGRESS_IPV4_TAGIF_BIT;
	//aclRule.ingress_ipv4_tagif = 1;
	//rg set acl-filter action action_type 2
	aclRule.action_type = ACL_ACTION_TYPE_TRAP;
	//rg add acl-filter entry
	if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0){
		fprintf(fp,"%d\n",aclIdx);
		//fprintf(stderr, "add %s-%d Vlan:%d, index=%d success\n",__func__,__LINE__,entry->vid, aclIdx);
	}else{
		fprintf(stderr,"%s-%d add rule failed! (ret = %d)\n",__func__,__LINE__, ret);
		fclose(fp);
		return -1;
	}

#if 0//def WLAN_SUPPORT //master and slave ext port
	//trap upstream ipv4 pppoe bridge from wifi
	//Can't bind the LAN with EXT port
	//[WARNING] Macport and extPort should be seperate as two ACL rule!	
	//rg clear acl-filter
	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	//rg set acl-filter pattern ingress_port_mask 0x180
	aclRule.filter_fields |= INGRESS_PORT_BIT;
	aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN0));
	aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN1));
	//rg set acl-filter pattern ingress_ethertype 0x8864
	aclRule.filter_fields |= INGRESS_ETHERTYPE_BIT;
	aclRule.ingress_ethertype = 0x8864;
	//rg set acl-filter action action_type 2
	aclRule.action_type = ACL_ACTION_TYPE_TRAP;
	//rg add acl-filter entry
	if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0){
		fprintf(fp,"%d\n",aclIdx);
		//fprintf(stderr, "add %s-%d Vlan:%d, index=%d success\n",__func__,__LINE__,entry->vid, aclIdx);
	}else{
		fprintf(stderr,"%s-%d add rule failed! (ret = %d)\n",__func__,__LINE__, ret);
		fclose(fp);
		return -1;
	}
#endif

#if defined(CONFIG_GPON_FEATURE) || defined(CONFIG_EPON_FEATURE)
	//pppoe padr can passthrough to lan
	//gpon olt will add acl rule automatically, epon should add acl rule itself
	mib_get(MIB_PON_MODE, (void *)&pon_mode);
	if(pon_mode == EPON_MODE){
		memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
		//rg set acl-filter fwding_type_and_direction 0
		aclRule.filter_fields |= EGRESS_INTF_BIT;
		aclRule.filter_fields |= INGRESS_CTAGIF_BIT;
		aclRule.fwding_type_and_direction =  ACL_FWD_TYPE_DIR_INGRESS_OR_EGRESS_L34_UP_STREAMID_CVLAN_SVLAN;
		aclRule.action_type = ACL_ACTION_TYPE_QOS;
		//rg set acl-filter action qos action_ingress_vid 
		aclRule.qos_actions |= ACL_ACTION_ACL_CVLANTAG_BIT;
		if(entry->vid > 0){
			aclRule.action_acl_cvlan.cvlanTagIfDecision = ACL_CVLAN_TAGIF_TAGGING;
			aclRule.action_acl_cvlan.cvlanCvidDecision = ACL_CVLAN_CVID_ASSIGN;
			aclRule.action_acl_cvlan.cvlanCpriDecision = ACL_CVLAN_CPRI_COPY_FROM_INTERNAL_PRI;
			aclRule.action_acl_cvlan.assignedCvid = entry->vid; 
		}
		//rg add acl-filter entry
		if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0){
			fprintf(fp,"%d\n",aclIdx);
			//fprintf(stderr, "add %s-%d Vlan:%d, index=%d success\n",__func__,__LINE__,entry->vid, aclIdx);
		}else{
			fprintf(stderr,"%s-%d add rule failed! (ret = %d)\n",__func__,__LINE__, ret);
			fclose(fp);
			return -1;
		}
	}
#endif
	fclose(fp);
	return 0;

}

#ifdef CONFIG_EPON_FEATURE
/* EPON mode:for untag packets from lan port, add bridge vlan tag when egress to pon port */
int RTK_RG_Set_ACL_Bridge_from_Lan(void)
{
	FILE *fp;
	rtk_rg_aclFilterAndQos_t aclRule;
	int aclIdx, ret, vcTotal=0,i;
	MIB_CE_ATM_VC_T entryVC;

	vcTotal = mib_chain_total(MIB_ATM_VC_TBL);
	/*
		rtk_rg_initParams_t init_param;

		bzero(&init_param, sizeof(rtk_rg_initParams_t));
		if((ret = rtk_rg_initParam_get(&init_param)) != SUCCESS)
		{
			fprintf(stderr, "rtk_rg_initParam_set failed! ret=%d\n", ret);
			return -1;
		}
		
	if(!(fp = fopen(RG_Bridge_From_Lan_ACL_RILES, "a")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -2;
	}
	*/

	for (i = 0; i < vcTotal; i++)
	{
		char filename[64] = {0};		
		if(mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&entryVC) == 0)
			continue;
		if(entryVC.rg_wan_idx <= 0)
			continue;		
		if(entryVC.cmode == CHANNEL_MODE_BRIDGE && entryVC.applicationtype == X_CT_SRV_INTERNET){
			sprintf(filename, "%s_%d", RG_Bridge_From_Lan_ACL_RILES, entryVC.rg_wan_idx);
			if (!(fp = fopen(filename, "a"))) {
				fprintf(stderr, "ERROR! %s\n", strerror(errno));
				return -2;
			}
			//rg clear acl-filter
			memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
			//rg set acl-filter fwding_type_and_direction 3
			aclRule.fwding_type_and_direction =  ACL_FWD_TYPE_DIR_INGRESS_OR_EGRESS_L34_UP_STREAMID_CVLAN_SVLAN;

			//rg set acl-filter action action_type 3
			aclRule.action_type = ACL_ACTION_TYPE_QOS;
			//rg set acl-filter action qos action_ctag tagging cvidDecision 0 cpriDecision 0 cvid 81 cpri 0
			aclRule.qos_actions |= ACL_ACTION_ACL_CVLANTAG_BIT;
			if(entryVC.vid > 0){
				aclRule.action_acl_cvlan.cvlanTagIfDecision=ACL_CVLAN_TAGIF_TAGGING;
				aclRule.action_acl_cvlan.cvlanCvidDecision = 0;
				aclRule.action_acl_cvlan.cvlanCpriDecision = 0;
				aclRule.action_acl_cvlan.assignedCvid = entryVC.vid;
				if(entryVC.vprio > 0)
					aclRule.action_acl_cvlan.assignedCpri = (entryVC.vprio - 1);
			}else{
				aclRule.action_acl_cvlan.cvlanTagIfDecision=ACL_CVLAN_TAGIF_UNTAG;
			}
			//rg set acl-filter pattern egress_intf_idx 0
			aclRule.filter_fields |= EGRESS_INTF_BIT;
			aclRule.egress_intf_idx = 0;

			//rg set acl-filter pattern ingress_ctagIf 0
			aclRule.filter_fields |= INGRESS_CTAGIF_BIT;
			aclRule.ingress_ctagIf = 0;

			//rg set acl-filter action qos action_stream_id 0
			aclRule.qos_actions |= ACL_ACTION_STREAM_ID_OR_LLID_BIT;
			aclRule.action_stream_id_or_llid = 0;

			if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0){
				fprintf(fp,"%d\n",aclIdx);
			}else{
				fprintf(stderr,"%s-%d add rule failed! (ret = %d)\n",__func__,__LINE__, ret);
				fclose(fp);
				return -1;
			}
			//AUG_PRT("add aclIdx %d\n",aclIdx);
			fclose(fp);
			break;
		}
	}
	return 0;
}
#endif

int RTK_RG_Set_ACL_IPV6_PPPoE_from_Wan_KeepOVID(MIB_CE_ATM_VC_Tp entry)
{
	FILE *fp;
	rtk_rg_aclFilterAndQos_t aclRule;
	int aclIdx, ret;
	if(!(fp = fopen(RG_IPV6_PPPoE_From_Wan_KeepOVID_ACL_RILES, "a")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -2;
	}
#if 0	
	if(entry->cmode == CHANNEL_MODE_PPPOE){	
		//For IPv6 PPPoE(0x8863) Routing packet from Wan, keep original VID
		memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
		//rg set acl-filter fwding_type_and_direction 0
		aclRule.fwding_type_and_direction =  ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
		//rg set acl-filter pattern ingress_port_mask 0x10
		aclRule.filter_fields |= INGRESS_PORT_BIT;
		aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();//wan port
		aclRule.acl_weight = RG_DEFAULT_ACL_WEIGHT;
		if(entry->vid > 0){
			//rg set acl-filter pattern ingress_ctagIf 1
	   		aclRule.filter_fields |= INGRESS_CTAGIF_BIT;
			aclRule.ingress_ctagIf = 1;
			//rg set acl-filter pattern ingress_ctag_vid 45
			aclRule.filter_fields |= INGRESS_CTAG_VID_BIT;
			aclRule.ingress_ctag_vid = entry->vid;
		}
		//rg set acl-filter pattern ingress_ethertype 0x8863
		aclRule.filter_fields |= INGRESS_ETHERTYPE_BIT;
		aclRule.ingress_ethertype = 0x8860;
		aclRule.ingress_ethertype_mask = 0xFFF0;
		//rg set acl-filter pattern ingress_dmac 00:00:39:00:74:00
	   	aclRule.filter_fields |= INGRESS_DMAC_BIT;
		memcpy(&aclRule.ingress_dmac, entry->MacAddr, MAC_ADDR_LEN);
		//rg set acl-filter action action_type 3
		aclRule.action_type = ACL_ACTION_TYPE_QOS;
		//rg set acl-filter action qos action_ingress_vid 45
		aclRule.qos_actions |= ACL_ACTION_ACL_INGRESS_VID_BIT;
		aclRule.action_acl_ingress_vid = entry->vid;
		//rg add acl-filter entry
		if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0){
			fprintf(fp,"%d\n",aclIdx);
			//fprintf(stderr, "add %s-%d Vlan:%d, index=%d success\n",__func__,__LINE__,entry->vid, aclIdx);
		}else{
			fprintf(stderr,"%s-%d add rule failed! (ret = %d)\n",__func__,__LINE__, ret);
			fclose(fp);
			return -1;
		}
	}else if(entry->cmode == CHANNEL_MODE_IPOE)
	{
			//For IPv6 Routing packet from Wan, keep original VID
			memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
			//rg set acl-filter fwding_type_and_direction 0
			aclRule.fwding_type_and_direction =  ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
			//rg set acl-filter pattern ingress_port_mask 0x10
			aclRule.filter_fields |= INGRESS_PORT_BIT;
			aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();//wan port
			aclRule.acl_weight = RG_DEFAULT_ACL_WEIGHT;
			if(entry->vid > 0){
				//rg set acl-filter pattern ingress_ctagIf 1
				aclRule.filter_fields |= INGRESS_CTAGIF_BIT;
				aclRule.ingress_ctagIf = 1;
				//rg set acl-filter pattern ingress_ctag_vid 45
				aclRule.filter_fields |= INGRESS_CTAG_VID_BIT;
				aclRule.ingress_ctag_vid = entry->vid;
			}
			//rg set acl-filter pattern ingress_dmac 00:00:39:00:74:00
			aclRule.filter_fields |= INGRESS_DMAC_BIT;
			memcpy(&aclRule.ingress_dmac, entry->MacAddr, MAC_ADDR_LEN);
			//rg set acl-filter action action_type 3
			aclRule.action_type = ACL_ACTION_TYPE_QOS;
			//rg set acl-filter action qos action_ingress_vid 45
			aclRule.qos_actions |= ACL_ACTION_ACL_INGRESS_VID_BIT;
			aclRule.action_acl_ingress_vid = entry->vid;
			//rg add acl-filter entry
			if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0){
				fprintf(fp,"%d\n",aclIdx);
				//fprintf(stderr, "add %s-%d Vlan:%d, index=%d success\n",__func__,__LINE__,entry->vid, aclIdx);
			}else{
				fprintf(stderr,"%s-%d add rule failed! (ret = %d)\n",__func__,__LINE__, ret);
				fclose(fp);
				return -1;
			}

	}
#endif	
#if 0		
	//For IPv4 PPPoE(0x8864) Routing packet from Wan,  keep original VID
	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	//rg set acl-filter fwding_type_and_direction 0
	aclRule.fwding_type_and_direction =  ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	//rg set acl-filter pattern ingress_port_mask 0x10
	aclRule.filter_fields |= INGRESS_PORT_BIT;
	aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();//wan port
	aclRule.acl_weight = RG_DEFAULT_ACL_WEIGHT;
	if(entry->vid > 0){
		//rg set acl-filter pattern ingress_ctagIf 1
   		aclRule.filter_fields |= INGRESS_CTAGIF_BIT;
		aclRule.ingress_ctagIf = 1;
		//rg set acl-filter pattern ingress_ctag_vid 45
		aclRule.filter_fields |= INGRESS_CTAG_VID_BIT;
		aclRule.ingress_ctag_vid = entry->vid;
	}
	//rg set acl-filter pattern ingress_ethertype 0x8864
	aclRule.filter_fields |= INGRESS_ETHERTYPE_BIT;
	aclRule.ingress_ethertype = 0x8864;
	//rg set acl-filter pattern ingress_dmac 00:00:39:00:74:00
   	aclRule.filter_fields |= INGRESS_DMAC_BIT;
	memcpy(&aclRule.ingress_dmac, entry->MacAddr, MAC_ADDR_LEN);
	//rg set acl-filter action action_type 3
	aclRule.action_type = ACL_ACTION_TYPE_QOS;
	//rg set acl-filter action qos action_ingress_vid 45
	aclRule.qos_actions |= ACL_ACTION_ACL_INGRESS_VID_BIT;
	aclRule.action_acl_ingress_vid = entry->vid;
	//rg add acl-filter entry
	if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0){
		fprintf(fp,"%d\n",aclIdx);
		//fprintf(stderr, "add %s-%d Vlan:%d, index=%d success\n",__func__,__LINE__,entry->vid, aclIdx);
	}else{
		fprintf(stderr,"%s-%d add rule failed! (ret = %d)\n",__func__,__LINE__, ret);
		fclose(fp);
		return -1;
	}
#endif		
	//below permit rules will make ipv6 dest addr fe80::0 trap to cpu acl rules failure.
	//we add acls before below rules. (i don't know it have another side effect or not?)
/*
	rg clear acl-filter
	rg set acl-filter acl_weight 2
	rg set acl-filter fwding_type_and_direction 0
	rg set acl-filter action action_type 2
	rg set acl-filter pattern ingress_src_ipv6_addr fe80:0000:0000:0000:0000:0000:0000:0000
	rg set acl-filter pattern ingress_src_ipv6_addr_mask ffff:0000:0000:0000:0000:0000:0000:0000
	rg set acl-filter pattern ingress_port_mask 0x10
	rg add acl-filter entry
*/
//RG use one reserved acl to trap link-local fe80:: , so we don't need below acl rules.
#if 0
	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	aclRule.fwding_type_and_direction =  ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	aclRule.filter_fields |= INGRESS_PORT_BIT;
	aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();//wan port
	aclRule.acl_weight = RG_FIREWALL_ACL_WEIGHT;
	if(entry->vid > 0){
   		aclRule.filter_fields |= INGRESS_CTAGIF_BIT;
		aclRule.ingress_ctagIf = 1;
		//rg set acl-filter pattern ingress_ctag_vid 45
		aclRule.filter_fields |= INGRESS_CTAG_VID_BIT;
		aclRule.ingress_ctag_vid = entry->vid;
	}
	aclRule.filter_fields |= INGRESS_IPV6_TAGIF_BIT;
	aclRule.ingress_ipv6_tagif = 1;
	//aclRule.filter_fields |= INGRESS_IPV6_SIP_BIT;
 //
	//EPON didn't support IPv6 SIP
	aclRule.filter_fields |= INGRESS_IPV6_DIP_BIT;
	aclRule.ingress_dest_ipv6_addr[0]=0xfe;
	aclRule.ingress_dest_ipv6_addr[1]=0x80;
	aclRule.ingress_dest_ipv6_addr_mask[0]=0xff;
	aclRule.ingress_dest_ipv6_addr_mask[1]=0xff;
	aclRule.action_type = ACL_ACTION_TYPE_TRAP;
	//rg add acl-filter entry
	if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0){
		fprintf(fp,"%d\n",aclIdx);
		//fprintf(stderr, "add %s-%d Vlan:%d, index=%d success\n",__func__,__LINE__,entry->vid, aclIdx);
	}else{
		fprintf(stderr,"%s-%d add rule failed! (ret = %d)\n",__func__,__LINE__, ret);
		fclose(fp);
		return -1;
	}
#endif
	//memcpy((void *)aclRule.ingress_dest_ipv6_addr, (void *)ip6addr ,sizeof(struct in6_addr));
	//memset((void *)aclRule.ingress_dest_ipv6_addr_mask, 0xff ,sizeof(struct in6_addr));

	//ipv4 only bridge will add acl to block ipv6 routing packet if vlan is the same
	//we add acl rules to permit ipv6 routing packet by dmac!
	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	//rg set acl-filter fwding_type_and_direction 0
	aclRule.fwding_type_and_direction =  ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	//rg set acl-filter pattern ingress_port_mask 0x10
	aclRule.filter_fields |= INGRESS_PORT_BIT;
	aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();//wan port
	aclRule.acl_weight = RG_QOS_ACL_WEIGHT;
	if(entry->vid > 0){
		//rg set acl-filter pattern ingress_ctagIf 1
   		aclRule.filter_fields |= INGRESS_CTAGIF_BIT;
		aclRule.ingress_ctagIf = 1;
		//rg set acl-filter pattern ingress_ctag_vid 45
		aclRule.filter_fields |= INGRESS_CTAG_VID_BIT;
		aclRule.ingress_ctag_vid = entry->vid;
	}
	aclRule.filter_fields |= INGRESS_IPV6_TAGIF_BIT;
	aclRule.ingress_ipv6_tagif = 1;
	//rg set acl-filter pattern ingress_dmac 00:00:39:00:74:00
	#ifdef CONFIG_RTL9600_SERIES
	aclRule.action_type = ACL_ACTION_TYPE_TRAP;
	#else
	aclRule.action_type = ACL_ACTION_TYPE_PERMIT;
	#endif
   	aclRule.filter_fields |= INGRESS_DMAC_BIT;
	memcpy(&aclRule.ingress_dmac, entry->MacAddr, MAC_ADDR_LEN);
	//rg add acl-filter entry
	if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0){
		fprintf(fp,"%d\n",aclIdx);
		//fprintf(stderr, "add %s-%d Vlan:%d, index=%d success\n",__func__,__LINE__,entry->vid, aclIdx);
	}else{
		fprintf(stderr,"%s-%d add rule failed! (ret = %d)\n",__func__,__LINE__, ret);
		fclose(fp);
		return -1;
	}
	#ifdef CONFIG_RTL9600_SERIES
	aclRule.action_type = ACL_ACTION_TYPE_SW_PERMIT;
	if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0){
		fprintf(fp,"%d\n",aclIdx);
		//fprintf(stderr, "add %s-%d Vlan:%d, index=%d success\n",__func__,__LINE__,entry->vid, aclIdx);
	}else{
		fprintf(stderr,"%s-%d add rule failed! (ret = %d)\n",__func__,__LINE__, ret);
		fclose(fp);
		return -1;
	}	
	#endif
	fclose(fp);

	return 0;

}

int RTK_RG_Set_ACL_IPV4_PPPoE_from_Wan_KeepOVID(MIB_CE_ATM_VC_Tp entry)
{

	FILE *fp;
	rtk_rg_aclFilterAndQos_t aclRule;
	int aclIdx, ret;
	if(!(fp = fopen(RG_IPV4_PPPoE_From_Wan_KeepOVID_ACL_RILES, "a")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -2;
	}
#if 0	
	if(entry->cmode == CHANNEL_MODE_PPPOE){	
		//For IPv4 PPPoE(0x8863) Routing packet from Wan, keep original VID
		memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
		//rg set acl-filter fwding_type_and_direction 0
		aclRule.fwding_type_and_direction =  ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
		//rg set acl-filter pattern ingress_port_mask 0x10
		aclRule.filter_fields |= INGRESS_PORT_BIT;
		aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();//wan port
		aclRule.acl_weight = RG_DEFAULT_ACL_WEIGHT;
		if(entry->vid > 0){
			//rg set acl-filter pattern ingress_ctagIf 1
	   		aclRule.filter_fields |= INGRESS_CTAGIF_BIT;
			aclRule.ingress_ctagIf = 1;
			//rg set acl-filter pattern ingress_ctag_vid 45
			aclRule.filter_fields |= INGRESS_CTAG_VID_BIT;
			aclRule.ingress_ctag_vid = entry->vid;
		}
		//rg set acl-filter pattern ingress_ethertype 0x8863
		aclRule.filter_fields |= INGRESS_ETHERTYPE_BIT;
		aclRule.ingress_ethertype = 0x8863;
		aclRule.ingress_ethertype_mask = 0xFFF0;
		//rg set acl-filter pattern ingress_dmac 00:00:39:00:74:00
	   	aclRule.filter_fields |= INGRESS_DMAC_BIT;
		memcpy(&aclRule.ingress_dmac, entry->MacAddr, MAC_ADDR_LEN);
		//rg set acl-filter action action_type 3
		aclRule.action_type = ACL_ACTION_TYPE_QOS;
		//rg set acl-filter action qos action_ingress_vid 45
		aclRule.qos_actions |= ACL_ACTION_ACL_INGRESS_VID_BIT;
		aclRule.action_acl_ingress_vid = entry->vid;
		//rg add acl-filter entry
		if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0){
			fprintf(fp,"%d\n",aclIdx);
			//fprintf(stderr, "add %s-%d Vlan:%d, index=%d success\n",__func__,__LINE__,entry->vid, aclIdx);
		}else{
			fprintf(stderr,"%s-%d add rule failed! (ret = %d)\n",__func__,__LINE__, ret);
			fclose(fp);
			return -1;
		}
	}else if(entry->cmode == CHANNEL_MODE_IPOE)
	{
		//if route wan is dhcp wan or static wan.
		//For IPv4 ipoe Routing packet from Wan, keep original VID
		memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
		//rg set acl-filter fwding_type_and_direction 0
		aclRule.fwding_type_and_direction =  ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
		//rg set acl-filter pattern ingress_port_mask 0x10
		aclRule.filter_fields |= INGRESS_PORT_BIT;
		aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();//wan port
		aclRule.acl_weight = RG_DEFAULT_ACL_WEIGHT;
		if(entry->vid > 0){
			//rg set acl-filter pattern ingress_ctagIf 1
			aclRule.filter_fields |= INGRESS_CTAGIF_BIT;
			aclRule.ingress_ctagIf = 1;
			//rg set acl-filter pattern ingress_ctag_vid 45
			aclRule.filter_fields |= INGRESS_CTAG_VID_BIT;
			aclRule.ingress_ctag_vid = entry->vid;
		}
		//rg set acl-filter pattern ingress_dmac 00:00:39:00:74:00
		aclRule.filter_fields |= INGRESS_DMAC_BIT;
		memcpy(&aclRule.ingress_dmac, entry->MacAddr, MAC_ADDR_LEN);
		//rg set acl-filter action action_type 3
		aclRule.action_type = ACL_ACTION_TYPE_QOS;
		//rg set acl-filter action qos action_ingress_vid 45
		aclRule.qos_actions |= ACL_ACTION_ACL_INGRESS_VID_BIT;
		aclRule.action_acl_ingress_vid = entry->vid;
		//rg add acl-filter entry
		if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0){
			fprintf(fp,"%d\n",aclIdx);
			//fprintf(stderr, "add %s-%d Vlan:%d, index=%d success\n",__func__,__LINE__,entry->vid, aclIdx);
		}else{
			fprintf(stderr,"%s-%d add rule failed! (ret = %d)\n",__func__,__LINE__, ret);
			fclose(fp);
			return -1;
		}
	}
#endif	
#if 0		
	//For IPv4 PPPoE(0x8864) Routing packet from Wan,  keep original VID
	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	//rg set acl-filter fwding_type_and_direction 0
	aclRule.fwding_type_and_direction =  ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	//rg set acl-filter pattern ingress_port_mask 0x10
	aclRule.filter_fields |= INGRESS_PORT_BIT;
	aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();//wan port
	aclRule.acl_weight = RG_DEFAULT_ACL_WEIGHT;
	if(entry->vid > 0){
		//rg set acl-filter pattern ingress_ctagIf 1
   		aclRule.filter_fields |= INGRESS_CTAGIF_BIT;
		aclRule.ingress_ctagIf = 1;
		//rg set acl-filter pattern ingress_ctag_vid 45
		aclRule.filter_fields |= INGRESS_CTAG_VID_BIT;
		aclRule.ingress_ctag_vid = entry->vid;
	}
	//rg set acl-filter pattern ingress_ethertype 0x8864
	aclRule.filter_fields |= INGRESS_ETHERTYPE_BIT;
	aclRule.ingress_ethertype = 0x8864;
	//rg set acl-filter pattern ingress_dmac 00:00:39:00:74:00
   	aclRule.filter_fields |= INGRESS_DMAC_BIT;
	memcpy(&aclRule.ingress_dmac, entry->MacAddr, MAC_ADDR_LEN);
	//rg set acl-filter action action_type 3
	aclRule.action_type = ACL_ACTION_TYPE_QOS;
	//rg set acl-filter action qos action_ingress_vid 45
	aclRule.qos_actions |= ACL_ACTION_ACL_INGRESS_VID_BIT;
	aclRule.action_acl_ingress_vid = entry->vid;
	//rg add acl-filter entry
	if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0){
		fprintf(fp,"%d\n",aclIdx);
		//fprintf(stderr, "add %s-%d Vlan:%d, index=%d success\n",__func__,__LINE__,entry->vid, aclIdx);
	}else{
		fprintf(stderr,"%s-%d add rule failed! (ret = %d)\n",__func__,__LINE__, ret);
		fclose(fp);
		return -1;
	}
#endif
	//ipv6 only bridge will add acl to block ipv4 routing packet if vlan is the same
	//we add acl rules to permit ipv4 routing packet by dmac!
	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	//rg set acl-filter fwding_type_and_direction 0
	aclRule.fwding_type_and_direction =  ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	//rg set acl-filter pattern ingress_port_mask 0x10
	aclRule.filter_fields |= INGRESS_PORT_BIT;
	aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();//wan port
	aclRule.acl_weight = RG_QOS_ACL_WEIGHT;
	if(entry->vid > 0){
		//rg set acl-filter pattern ingress_ctagIf 1
   		aclRule.filter_fields |= INGRESS_CTAGIF_BIT;
		aclRule.ingress_ctagIf = 1;
		//rg set acl-filter pattern ingress_ctag_vid 45
		aclRule.filter_fields |= INGRESS_CTAG_VID_BIT;
		aclRule.ingress_ctag_vid = entry->vid;
	}
	aclRule.filter_fields |= INGRESS_IPV4_TAGIF_BIT;
	aclRule.ingress_ipv4_tagif = 1;
	//rg set acl-filter pattern ingress_dmac 00:00:39:00:74:00
	#ifdef CONFIG_RTL9600_SERIES
	aclRule.action_type = ACL_ACTION_TYPE_TRAP;
	#else
	aclRule.action_type = ACL_ACTION_TYPE_PERMIT;
	#endif
   	aclRule.filter_fields |= INGRESS_DMAC_BIT;
	memcpy(&aclRule.ingress_dmac, entry->MacAddr, MAC_ADDR_LEN);
	//rg add acl-filter entry
	if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0){
		fprintf(fp,"%d\n",aclIdx);
		//fprintf(stderr, "add %s-%d Vlan:%d, index=%d success\n",__func__,__LINE__,entry->vid, aclIdx);
	}else{
		fprintf(stderr,"%s-%d add rule failed! (ret = %d)\n",__func__,__LINE__, ret);
		fclose(fp);
		return -1;
	}
	#ifdef CONFIG_RTL9600_SERIES
	aclRule.action_type = ACL_ACTION_TYPE_SW_PERMIT;
	if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0){
		fprintf(fp,"%d\n",aclIdx);
		//fprintf(stderr, "add %s-%d Vlan:%d, index=%d success\n",__func__,__LINE__,entry->vid, aclIdx);
	}else{
		fprintf(stderr,"%s-%d add rule failed! (ret = %d)\n",__func__,__LINE__, ret);
		fclose(fp);
		return -1;
	}	
	#endif		
	fclose(fp);
	return 0;
}

int RTK_RG_FLUSH_Bridge_DHCP_ACL_FILE(void)
{
	FILE *fp;
	int aclIdx=-1;
	if(!(fp = fopen(RG_BRIDGE_INET_DHCP_RA_FILTER_FILE, "r"))){
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -2;
	}
	while(fscanf(fp, "%d\n", &aclIdx) != EOF)
	{
		//fprintf(stderr, "del mvlan index %d\n",aclIdx);
		if(rtk_rg_aclFilterAndQos_del(aclIdx))
			fprintf(stderr, "%s failed! idx = %d\n",__func__, aclIdx);
	}
	fclose(fp);
	unlink(RG_BRIDGE_INET_DHCP_RA_FILTER_FILE);
	return 0;


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
		AUG_PRT("%s-%d entryVC.cmode=%d, created=%d\n",__func__,__LINE__,entryVC.cmode,created);
		if((entryVC.cmode > 0) && !created)
		{
			AUG_PRT("%s-%d\n",__func__,__LINE__);
			if(entryVC.IpProtocol & IPVER_IPV6){
				AUG_PRT("%s-%d\n",__func__,__LINE__);
				if(!(fp = fopen(RG_ROUTE_V6_RA_NS_FILTER_FILE, "a"))){
					fprintf(stderr, "open %s fail!", RG_ROUTE_V6_RA_NS_FILTER_FILE);
					return -2;
				}

				memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
				//RA ff02::1 , trap to protocol stack
				aclRule.acl_weight = RG_TRAP_ACL_WEIGHT;
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
				AUG_PRT("%s-%d\n",__func__,__LINE__);
				memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
				//NS ff02::1:ff00:0/104, trap to protocol stack
				aclRule.acl_weight = RG_TRAP_ACL_WEIGHT;
#if defined(CONFIG_RTL9602C_SERIES) || defined(CONFIG_RTL9607C_SERIES)				
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
				AUG_PRT("%s-%d created=%d\n",__func__,__LINE__,created);
			}
		}
	}
	if(fp)
		fclose(fp);
	AUG_PRT("%s-%d\n",__func__,__LINE__);
	return ret;
}


int RTK_RG_Set_ACL_Bridge_DHCP_Filter(void)
{
	FILE *fp;
	int acl_index=0, ret=-1;
	MIB_CE_ATM_VC_T entryVC;
	rtk_rg_aclFilterAndQos_t aclRule;
	int i, totalVC_entry = mib_chain_total(MIB_ATM_VC_TBL);
	for(i=0;i<totalVC_entry;i++){
		if(mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&entryVC) == 0)
			continue;

		if(entryVC.cmode == CHANNEL_MODE_BRIDGE && (entryVC.applicationtype & (X_CT_SRV_INTERNET|X_CT_SRV_SPECIAL_SERVICE_ALL)) && (entryVC.disableLanDhcp == 0))
		{
			if(!(fp = fopen(RG_BRIDGE_INET_DHCP_RA_FILTER_FILE, "a"))){
				fprintf(stderr, "open %s fail!", RG_BRIDGE_INET_DHCP_RA_FILTER_FILE);
				return -2;
			}
#if 0
			if(entryVC.IpProtocol & IPVER_IPV6){
				/*bridge internet wan, we don't wan to receive dhcp/RA offer from outside.*/
				/*we want to let lan get IP from gateway, so we set acl to filter*/
		 		//#drop from wan 3001 ipv6 ra
				//rg clear acl-filter
				//rg set acl-filter fwding_type_and_direction 0
				//rg set acl-filter action action_type 0
				//rg set acl-filter pattern ingress_ctag_vid 3001
				//rg set acl-filter pattern ingress_l4_protocal_value 0x3a
				//rg set acl-filter pattern ingress_port_mask 0x10
				//rg add acl-filter entry
				memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
				aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
				aclRule.acl_weight = RG_DEFAULT_ACL_WEIGHT;

				aclRule.action_type = ACL_ACTION_TYPE_TRAP_TO_PS;
				aclRule.filter_fields |= INGRESS_PORT_BIT;
		       	aclRule.filter_fields |= INGRESS_CTAGIF_BIT;
				aclRule.ingress_ctagIf = 1;
		       	aclRule.filter_fields |= INGRESS_CTAG_VID_BIT;
				aclRule.ingress_ctag_vid = entryVC.vid;
				aclRule.filter_fields |= INGRESS_L4_POROTCAL_VALUE_BIT;
				aclRule.ingress_l4_protocal = 0x3a;
				aclRule.filter_fields |= INGRESS_PORT_BIT;
				aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();
				aclRule.filter_fields |= INGRESS_IPV6_TAGIF_BIT;
				aclRule.ingress_ipv6_tagif = 1;
				aclRule.filter_fields |= INGRESS_IPV6_DIP_BIT;
				aclRule.ingress_dest_ipv6_addr[0]=0xff;
				aclRule.ingress_dest_ipv6_addr[1]=0x02;
				aclRule.ingress_dest_ipv6_addr[15]=0x1;
				memset((void *)aclRule.ingress_dest_ipv6_addr_mask, 0xff ,sizeof(struct in6_addr));
				//aclRule.ingress_dest_ipv6_addr_mask[0]=0xff;
				//aclRule.ingress_dest_ipv6_addr_mask[1]=0xff;
				if((ret = rtk_rg_aclFilterAndQos_add(&aclRule,&acl_index)) == 0)
					fprintf(fp, "%d\n", acl_index);
				else
					printf("rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n", ret);
				//downstream DHCPv6
				memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
				aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
				aclRule.action_type = ACL_ACTION_TYPE_DROP;
				aclRule.filter_fields |= INGRESS_PORT_BIT;
		       	aclRule.filter_fields |= INGRESS_CTAGIF_BIT;
				aclRule.ingress_ctagIf = 1;
		       	aclRule.filter_fields |= INGRESS_CTAG_VID_BIT;
				aclRule.ingress_ctag_vid = entryVC.vid;
				aclRule.filter_fields |= INGRESS_PORT_BIT;
				aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();
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
				if((ret = rtk_rg_aclFilterAndQos_add(&aclRule,&acl_index)) == 0)
					fprintf(fp, "%d\n", acl_index);
				else
					printf("rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n", ret);
			}
#endif
			if(entryVC.IpProtocol & IPVER_IPV4){
				//rg clear acl-filter
				//rg set acl-filter fwding_type_and_direction 0
				//rg set acl-filter action action_type 0
				//rg set acl-filter pattern ingress_l4_protocal 0
				//rg set acl-filter pattern ingress_port_mask 0x10
				//rg set acl-filter pattern ingress_ctag_vid 3001
				//rg set acl-filter pattern ingress_src_l4_port_start 67 ingress_src_l4_port_end 67
				//rg set acl-filter pattern ingress_dest_l4_port_start 68 ingress_dest_l4_port_end 68
				//rg add acl-filter entry
				memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
				aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
				aclRule.action_type = ACL_ACTION_TYPE_DROP;
				aclRule.filter_fields |= INGRESS_PORT_BIT;
				aclRule.filter_fields |= INGRESS_CTAGIF_BIT;
				aclRule.ingress_ctagIf = 1;
		       	aclRule.filter_fields |= INGRESS_CTAG_VID_BIT;
				aclRule.ingress_ctag_vid = entryVC.vid;
				aclRule.filter_fields |= INGRESS_L4_UDP_BIT;
				aclRule.filter_fields |= INGRESS_PORT_BIT;
				aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();
				aclRule.filter_fields |= INGRESS_L4_SPORT_RANGE_BIT;
				aclRule.ingress_src_l4_port_start = 67;
				aclRule.ingress_src_l4_port_end = 67;
				aclRule.filter_fields |= INGRESS_L4_DPORT_RANGE_BIT;
				aclRule.ingress_dest_l4_port_start = 68;
				aclRule.ingress_dest_l4_port_end = 68;
				if((ret = rtk_rg_aclFilterAndQos_add(&aclRule,&acl_index)) == 0)
					fprintf(fp, "%d\n", acl_index);
				else
					printf("rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n", ret);
			}
			fclose(fp);
		}
	}
	return ret;
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
			return;
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
				return;
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

#if defined (CONFIG_EPON_FEATURE) || defined(CONFIG_GPON_FEATURE)
int RG_del_route_pppoe_multicast_permit(MIB_CE_ATM_VC_T *pentry)
{
	FILE*fp;
	int ret;
	int aclIdx = -1;
	char ifname[32];
	char aclfile[64];

	if(pentry->cmode == CHANNEL_MODE_BRIDGE || !(pentry->enableIGMP)||
		(!(pentry->applicationtype&X_CT_SRV_INTERNET) && !(pentry->applicationtype&X_CT_SRV_OTHER)))
		return 0;
	ifGetName(pentry->ifIndex, ifname, sizeof(ifname));
	snprintf(aclfile,sizeof(aclfile),"%s.%s",RG_ROUTE_PPPOE_MULTICAST_ACL_FILE,ifname);
	if((fp = fopen(aclfile, "r")) == NULL)
		return 0;
	while(fscanf(fp, "%d\n", &aclIdx) != EOF)
	{
		if(rtk_rg_aclFilterAndQos_del(aclIdx)) {
			printf( "RG_del_bridge_pppoe_multicast_trap delete acl rule failed! idx = %d\n", aclIdx);
			fclose(fp);
			return -1;
		}
	}
	fclose(fp);
	unlink(aclfile);
	return 1;
}
//cxy 2016-6-16:patch for "diag l34 set ip-mcast-trans 15 pppoe-act remove"
// for 9602 bridge pppoe multicast pkt, l34 rule wiil remove pppoe tag to lan port.
int RG_set_route_pppoe_multicast_permit(MIB_CE_ATM_VC_T *pentry)
{
	FILE*fp;
	int ret;
	rtk_rg_aclFilterAndQos_t aclRule={0};
	int aclIdx = -1;
	char ifname[32];
	char aclfile[64];

	if(pentry->cmode == CHANNEL_MODE_BRIDGE || !(pentry->enableIGMP)||
		(!(pentry->applicationtype&X_CT_SRV_INTERNET) && !(pentry->applicationtype&X_CT_SRV_OTHER)))
		return 0;
	ifGetName(pentry->ifIndex, ifname, sizeof(ifname));
	snprintf(aclfile,sizeof(aclfile),"%s.%s",RG_ROUTE_PPPOE_MULTICAST_ACL_FILE,ifname);
	if((fp = fopen(aclfile, "w")) == NULL)
		return 0;
	aclRule.fwding_type_and_direction =  ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	aclRule.acl_weight = RG_DEFAULT_ACL_WEIGHT;
	aclRule.filter_fields |= INGRESS_PORT_BIT;
	aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();
	aclRule.filter_fields |= INGRESS_DMAC_BIT;
	memcpy(&(aclRule.ingress_dmac), pentry->MacAddr, MAC_ADDR_LEN);
	memset(&(aclRule.ingress_dmac_mask), 0xff, MAC_ADDR_LEN);
	aclRule.filter_fields |= INGRESS_ETHERTYPE_BIT;
	aclRule.ingress_ethertype = 0x8864;
	aclRule.filter_fields |= INGRESS_IPV4_DIP_RANGE_BIT;
	aclRule.ingress_dest_ipv4_addr_start=0xe0000000;
	aclRule.ingress_dest_ipv4_addr_end=0xffffffff;
	aclRule.action_type = ACL_ACTION_TYPE_PERMIT;
	if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0)
		fprintf(fp, "%d\n", aclIdx);
	else
		printf("%s-%d rtk_rg_aclFilterAndQos_add fail =%d\n",__func__,__LINE__,ret);
	fclose(fp);
	return 1;
}

int RG_set_default_pppoe_multicast_trap(void)
{
	int ret;
	rtk_rg_aclFilterAndQos_t aclRule={0};
	int aclIdx = -1;

	aclRule.fwding_type_and_direction =  ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	aclRule.acl_weight = RG_RESERVED_ACL_WEIGHT;
	aclRule.filter_fields |= INGRESS_PORT_BIT;
	aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();
	aclRule.filter_fields |= INGRESS_DMAC_BIT;
	memset(&(aclRule.ingress_dmac), 0x0, MAC_ADDR_LEN);
	memset(&(aclRule.ingress_dmac_mask), 0x0, MAC_ADDR_LEN);
	aclRule.ingress_dmac_mask.octet[0]=0x1;
	aclRule.filter_fields |= INGRESS_ETHERTYPE_BIT;
	aclRule.ingress_ethertype = 0x8864;
	aclRule.filter_fields |= INGRESS_IPV4_DIP_RANGE_BIT;
	aclRule.ingress_dest_ipv4_addr_start=0xe0000000;
	aclRule.ingress_dest_ipv4_addr_end=0xffffffff;
	aclRule.action_type = ACL_ACTION_TYPE_TRAP;
	if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0)
		printf("in <%s>add default pppoe multicast trap acl=%d\n",__func__,aclIdx);
	else
		printf("%s-%d rtk_rg_aclFilterAndQos_add fail =%d\n",__func__,__LINE__,ret);
	return ret;
}
#endif

#if defined(CONFIG_CMCC) || defined(CONFIG_CU)

int RG_Flush_Handle_Priority_Tag0_ACL_FILE(void)
{
	FILE *fp;
	int aclIdx=-1;
	if(!(fp = fopen(RG_HANDLE_PRI_TAG0_ACL_FILTER_FILE, "r"))){
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -2;
	}
	while(fscanf(fp, "%d\n", &aclIdx) != EOF)
	{
		//fprintf(stderr, "del mvlan index %d\n",aclIdx);
		if(rtk_rg_aclFilterAndQos_del(aclIdx))
			fprintf(stderr, "%s failed! idx = %d\n",__func__, aclIdx);
	}
	fclose(fp);
	unlink(RG_HANDLE_PRI_TAG0_ACL_FILTER_FILE);
	return 0;


}

/*
CMCC project
Set acl to transfer ingress vlan id 0 to port base vlan. 
To avoid ingress vlan filter.
ex:
rg clear acl-filter
rg set acl-filter fwding_type_and_direction 0
rg set acl-filter pattern ingress_ctag_vid 0
rg set acl-filter pattern ingress_port_mask 0xf
rg set acl-filter pattern ingress_ctagIf 1
rg set acl-filter action action_type 3
rg set acl-filter action qos action_ingress_vid 4005
rg add acl-filter entry
*/
int RG_Handle_Priority_Tag0_By_Port(void)
{
	rtk_rg_aclFilterAndQos_t aclRule;
	int i,aclIdx=0, ret=0, portID=0;
	int pPvid=-1;
	int phyID=-1;
	int wlan_idx=0; /*only support master WLAN right now*/
	int dev_idx=0; /*only support master WLAN right now*/
	unsigned short itfGroupCount=0;
	MIB_CE_ATM_VC_T entryVC;
	int totalVC_entry;
	FILE *fp=NULL;
	if(!(fp = fopen(RG_HANDLE_PRI_TAG0_ACL_FILTER_FILE, "a"))){
		fprintf(stderr, "open %s fail!", RG_HANDLE_PRI_TAG0_ACL_FILTER_FILE);
		return -2;
	}
	totalVC_entry = mib_chain_total(MIB_ATM_VC_TBL);
	for(i=0;i<totalVC_entry;i++){
		if(mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&entryVC) == 0)
			continue;
		//for vlan mark test 7.1.2, vlan taged the same as wan's vlan [ex:100], drop!
		//bridge mode,vlan group would have lan member port, lan taged 100 would forward
		//so we need to add acl to drop it.
		if(entryVC.cmode == 0)
		{
		
AUG_PRT("entryVC.itfGroup=%x\n",entryVC.itfGroup);
			if(entryVC.itfGroup > 0){
				//taged 0 + port binding mask ---> permit
				memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
				aclRule.fwding_type_and_direction =  ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
				aclRule.filter_fields |= INGRESS_PORT_BIT;
				aclRule.acl_weight = RG_DEFAULT_ACL_WEIGHT + 1;
#ifdef CONFIG_RTL9602C_SERIES
				aclRule.ingress_port_mask.portmask = RG_get_lan_phyPortMask(entryVC.itfGroup & 0x3);
#else
				aclRule.ingress_port_mask.portmask = RG_get_lan_phyPortMask(entryVC.itfGroup & 0xf);
#endif
#ifdef WLAN_SUPPORT
				if(entryVC.itfGroup & (ITFGROUP_WLAN_MASK << ITFGROUP_WLAN0_DEV_BIT))
					aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN0));
#ifdef WLAN_DUALBAND_CONCURRENT
				if(entryVC.itfGroup & (ITFGROUP_WLAN_MASK << ITFGROUP_WLAN1_DEV_BIT))
					aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN1));
#endif
#endif
				aclRule.filter_fields |= INGRESS_CTAGIF_BIT;
				aclRule.ingress_ctagIf = 1;
				aclRule.filter_fields |= INGRESS_CTAG_VID_BIT;
				aclRule.ingress_ctag_vid = 0;
				aclRule.action_type = ACL_ACTION_TYPE_PERMIT;			
				if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0){
						fprintf(fp,"%d\n",aclIdx);
						fprintf(stderr, "add pri tag0 ACL rules index=%d success\n", aclIdx);
				}else{
						fprintf(stderr,"rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n", ret);
						fclose(fp);
						return -1;
				}
				
				//taged + port binding mask ---> drop
				memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
				aclRule.fwding_type_and_direction =  ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
				aclRule.filter_fields |= INGRESS_PORT_BIT;
				aclRule.acl_weight = RG_DEFAULT_ACL_WEIGHT;
#ifdef CONFIG_RTL9602C_SERIES
				aclRule.ingress_port_mask.portmask = RG_get_lan_phyPortMask(entryVC.itfGroup & 0x3);
#else
				aclRule.ingress_port_mask.portmask = RG_get_lan_phyPortMask(entryVC.itfGroup & 0xf);
#endif
#ifdef WLAN_SUPPORT
				if(entryVC.itfGroup & (ITFGROUP_WLAN_MASK << ITFGROUP_WLAN0_DEV_BIT))
					aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN0));
#ifdef WLAN_DUALBAND_CONCURRENT
				if(entryVC.itfGroup & (ITFGROUP_WLAN_MASK << ITFGROUP_WLAN1_DEV_BIT))
					aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN1));
#endif
#endif
				aclRule.filter_fields |= INGRESS_CTAGIF_BIT;
				aclRule.ingress_ctagIf = 1;
				aclRule.action_type = ACL_ACTION_TYPE_DROP;			
				if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0){
						fprintf(fp,"%d\n",aclIdx);
						fprintf(stderr, "add pri tag0 ACL rules index=%d success\n", aclIdx);
				}else{
						fprintf(stderr,"rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n", ret);
						fclose(fp);
						return -1;
				}
			}
		}		
		itfGroupCount = entryVC.itfGroup;
		AUG_PRT("itfGroupCount=%x\n",itfGroupCount);
		memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
		if(itfGroupCount > 0){
			aclRule.fwding_type_and_direction =  ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
			aclRule.filter_fields |= INGRESS_PORT_BIT;
#ifdef CONFIG_RTL9602C_SERIES
			aclRule.ingress_port_mask.portmask = RG_get_lan_phyPortMask(itfGroupCount & 0x3);
#else
			aclRule.ingress_port_mask.portmask = RG_get_lan_phyPortMask(itfGroupCount & 0xf);
#endif
#ifdef WLAN_SUPPORT
			if(itfGroupCount & (ITFGROUP_WLAN_MASK << ITFGROUP_WLAN0_DEV_BIT))
			aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN0));
#ifdef WLAN_DUALBAND_CONCURRENT
			if(itfGroupCount & (ITFGROUP_WLAN_MASK << ITFGROUP_WLAN1_DEV_BIT))
			aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN1));
#endif
#endif
#if defined(CONFIG_USER_LAN_PORT_AS_ETH_WAN)
			int ethPhyPortId = -1;
			mib_get(MIB_ETH_WAN_PORT_PHY_INDEX, &ethPhyPortId);
#endif

			portID=0;
			while(itfGroupCount > 0){
				if(itfGroupCount & 1){
					aclRule.acl_weight = RG_DEFAULT_ACL_WEIGHT;
					aclRule.filter_fields |= INGRESS_CTAG_VID_BIT;
					aclRule.ingress_ctag_vid = 0;//pri tag.
					aclRule.filter_fields |= INGRESS_CTAGIF_BIT;
	                aclRule.ingress_ctagIf = 1;
					aclRule.action_type = ACL_ACTION_TYPE_QOS;
					aclRule.qos_actions |= ACL_ACTION_ACL_INGRESS_VID_BIT;					
					if(portID < 4){ //lan
						phyID = RG_get_lan_phyPortId(portID);
#if defined(CONFIG_USER_LAN_PORT_AS_ETH_WAN)
						if (phyID == ethPhyPortId)
							continue;
#endif
						//fprintf(stderr, "%s-%d phyID:%d, logID=%d\n",__func__,__LINE__,phyID,port_idx);
						rtk_rg_portBasedCVlanId_get(phyID,&pPvid);
						AUG_PRT("get pPvid=%d\n",pPvid);
					}else if(portID >= 4 || portID <=8){//wlan
						wlan_idx=0;
						dev_idx = portID-4;
						phyID = RG_get_wlan_phyPortId(portID);
						AUG_PRT("get phyID=%d dev_idx=%d\n",phyID, dev_idx);
						rtk_rg_wlanDevBasedCVlanId_get(wlan_idx,dev_idx,&pPvid);
						AUG_PRT("get pPvid=%d\n",pPvid);
					}
#if 0 /*RG only support wlan0 right now!*/					
					else{
						wlan_idx=1;
						dev_idx = portID-8;
						phyID = RG_get_wlan_phyPortId(portID);
						AUG_PRT("get phyID=%d dev_idx=%d\n",phyID, dev_idx);
						rtk_rg_wlanDevBasedCVlanId_get(wlan_idx,dev_idx,&pPvid);
						AUG_PRT("get pPvid=%d\n",pPvid);
					}
#endif					
					if(pPvid != 0){
						aclRule.action_acl_ingress_vid = pPvid;
						if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0){
							fprintf(fp,"%d\n",aclIdx);
							fprintf(stderr, "add pri tag0 ACL rules index=%d success\n", aclIdx);
						}else{
							fprintf(stderr,"rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n", ret);
							fclose(fp);
							return -1;
						}
					}
					break;
				}
				portID++;
				AUG_PRT("portID=%d\n",portID);
				itfGroupCount=itfGroupCount>>1;
			}
		}
	}
	fclose(fp);
	return 0;
}
#endif



int RG_add_wan(MIB_CE_ATM_VC_Tp entry, int mib_vc_idx)
{
	int wanIntfIdx;
	int vcTotal, i, vlan_id;
	char intf_name[10], mbtd;
	rtk_rg_wanIntfConf_t wan_info;
	unsigned char value[6];
	int ret=-1;
	int wanPhyPort=0;
	struct in_addr gw_addr;
    char cmdStr[64];
	int omci_mode=-1;
	int omci_service=-1;
	int omci_bind=-1;

	int pb_group=-1;
	unsigned int pon_mode=0;
	//Init_RG_ELan(UntagCPort, RoutingWan);
	int rtk_rg_wan_type = RG_get_wan_type(entry);

	if(rtk_rg_wan_type == -1)
		return -1;

	memset(&wan_info,0,sizeof(wan_info));
	memcpy(wan_info.gmac.octet, entry->MacAddr, MAC_ADDR_LEN);
	if(entry->vlan == 1)
		RG_WAN_CVLAN_DEL(entry->vid);

#if 0
	if(mib_get(MIB_WAN_PHY_PORT , (void *)&wanPhyPort) == 0){
		printf("get MIB_WAN_PHY_PORT failed!!!\n");
		wanPhyPort=RTK_RG_MAC_PORT3 ; //for 0371 default
	}
#else

	wanPhyPort=RG_get_wan_phyPortId();
#endif
	//wan_info.egress_vlan_id=8;
	//wan_info.vlan_based_pri=0;
	//wan_info.egress_vlan_tag_on=0;
	if (entry->vlan == 1) {
		wan_info.egress_vlan_tag_on=1;
		wan_info.egress_vlan_id=entry->vid;
		//ramen-2080420-to fix the loss of 802.1p setting for wan info
		if(entry->vprio){
			wan_info.vlan_based_pri_enable=RTK_RG_ENABLED;
			wan_info.vlan_based_pri=(entry->vprio)-1;
		}
	}
	else{
		wan_info.egress_vlan_tag_on=0;
		mib_get(MIB_UNTAG_WAN_VLAN_ID, (void *)&vlan_id);
		wan_info.egress_vlan_id=vlan_id;


		if(rtk_rg_wan_type == RTK_RG_BRIDGE)
		{
			mib_get(MIB_MAC_BASED_TAG_DECISION, (void *)&mbtd);

			if(mbtd == RTK_RG_DISABLED)
			{
				mib_get(MIB_LAN_VLAN_ID1, (void *)&vlan_id);
				wan_info.egress_vlan_id = vlan_id;
			}
		}
	}
#ifdef CONFIG_RTL9602C_SERIES
	wan_info.port_binding_mask.portmask = RG_get_lan_phyPortMask(entry->itfGroup & 0x3);
#else
	wan_info.port_binding_mask.portmask = RG_get_lan_phyPortMask(entry->itfGroup & 0xf);
#endif
	wan_info.wlan0_dev_binding_mask = (((entry->itfGroup >> ITFGROUP_WLAN0_DEV_BIT) & ITFGROUP_WLAN_MASK ) << RG_RET_MBSSID_MASTER_ROOT_INTF);
#if defined(WLAN_DUALBAND_CONCURRENT)
	wan_info.wlan0_dev_binding_mask |= (((entry->itfGroup >> ITFGROUP_WLAN1_DEV_BIT) & ITFGROUP_WLAN_MASK ) << RG_RET_MBSSID_SLAVE_ROOT_INTF);
#endif
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

#if 0//defined(CONFIG_GPON_FEATURE)
	unsigned int pon_mode;

	if (mib_get(MIB_PON_MODE, (void *)&pon_mode) != 0)
	{
		if ( pon_mode == GPON_MODE )
		{
			wan_info.gponStreamID = entry->sid;
			printf("GPON StreamID : %d.\n",wan_info.gponStreamID);
		}
	}
#endif
	/*RG: Internet = 0, other=1*/
	if(entry->applicationtype & (X_CT_SRV_INTERNET|X_CT_SRV_SPECIAL_SERVICE_ALL)){
		omci_service = 1;
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		wan_info.none_internet = 1; //for support lan port binding to difficent vlans and traffic can not pass through
#else
		wan_info.none_internet = 0;
#endif
	}
	else{
		wan_info.none_internet = 1;
		omci_service = 0;
	}

	if((rtk_rg_wanInterface_add(&wan_info, &wanIntfIdx))!=SUCCESS)
		return -1;
	//disable per Wan interface trap link-local reserved acl rules, only for routing wan
	if(entry->cmode > 0)
	{
		snprintf(cmdStr, sizeof(cmdStr),"echo %d %d > %s",wanIntfIdx,1,"/proc/rg/wanIntf_disable_ipv6_linkLocal_rsvACL");
		printf("%s-%d cmd:%s\n",__func__,__LINE__,cmdStr);
		system(cmdStr);
	}
#ifdef CONFIG_GPON_FEATURE
	//0 = PPPoE, 1 = IPoE, 2 = BRIDGE --> omci add cf rule
	switch(entry->cmode){
		case CHANNEL_MODE_IPOE:
			if( (entry->IpProtocol == IPVER_IPV4_IPV6) && entry->napt ==1)
				omci_mode = OMCI_MODE_IPOE_V4NAPT_V6;
			else
				omci_mode = OMCI_MODE_IPOE;
			break;
		case CHANNEL_MODE_PPPOE:
			{
#ifdef CONFIG_RTL9600_SERIES
			mib_get(MIB_PON_MODE, (void *)&pon_mode);
			if(pon_mode == GPON_MODE)
			{
				//unsigned char province_trap_pppoe_traffic=0;
				//mib_get(PROVINCE_TRAP_PPPOE_TRAFFIC, (void *)&province_trap_pppoe_traffic);
				//if(!province_trap_pppoe_traffic)
				{
					system("echo 1 > /proc/rg/gpon_pppoe_status");
				}
			}
#endif
			//system("cat /proc/dump/acl_rg");
			if( (entry->IpProtocol == IPVER_IPV4_IPV6) && entry->napt ==1)
				omci_mode = OMCI_MODE_PPPOE_V4NAPT_V6;
			else
				omci_mode = OMCI_MODE_PPPOE;
			}
			break;
		case CHANNEL_MODE_BRIDGE:
			omci_mode = OMCI_MODE_BRIDGE;
			break;
		default:
			printf("unknow mode %d\n",omci_mode);
			break;
	}

	mib_get(MIB_PON_MODE, (void *)&pon_mode);
	if(pon_mode == GPON_MODE){
		char vlan_based_pri;
		if(entry->vprio)
		{
			vlan_based_pri=(entry->vprio)-1;
		}
		else
		{
			vlan_based_pri=-1;
		}
		//sync omci cf rules.
		/*untag wan, omci egress vlan id = -1*/
		if(entry->vlan == 2)
			wan_info.egress_vlan_id = 4095;
		else{
			if(!wan_info.egress_vlan_tag_on)
				wan_info.egress_vlan_id = -1;
		}
#if ! defined(_LINUX_2_6_) && defined(CONFIG_TR142_MODULE)
		char ifname[IFNAMSIZ] = {0};
		ifGetName(PHY_INTF(entry->ifIndex), ifname, sizeof(ifname));
		snprintf(cmdStr, sizeof(cmdStr)-1,"echo %d %s %s %d > %s", wanIntfIdx, ALIASNAME_NAS0, ifname, omci_bind, TR142_WAN_IDX_MAP);
		system(cmdStr);
#endif
		fprintf(stderr, "%s-%d sync waninfo with OMCI!\n",__func__,__LINE__);
		snprintf(cmdStr, sizeof(cmdStr),"echo %d %d %d %d %d %d %d > %s",wanIntfIdx,wan_info.egress_vlan_id,vlan_based_pri,omci_mode,omci_service,omci_bind,1,OMCI_WAN_INFO);
		//fprintf(stderr, "%s\n",cmdStr);
		system(cmdStr);
	}

#endif
	entry->rg_wan_idx = wanIntfIdx;
	mib_chain_update(MIB_ATM_VC_TBL, entry, mib_vc_idx);
        // handle dmac to cvid enable
        {
                unsigned char dmac2cvid;
                mib_get(MIB_MAC_DMAC2CVID_DISABLE, (void *)&dmac2cvid);
                if(dmac2cvid == 1)
                {
                        printf("Disable DMAC to CVID !!\n");
                        system("echo 1 > /proc/rg/wan_dmac2cvid_force_disabled");
                }
                else
                {
                        printf("Enable DMAC to CVID !!\n");
                        system("echo 0 > /proc/rg/wan_dmac2cvid_force_disabled");
                }
        }
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
/*When user enable pppoe routing/bridge mixed mode
    must add the acl rules for downstream path. or LAN
    pppoe passthrough will be dropped.
*/
int RG_flush_pppoe_pass_acl_per_wan(int wan_idx)
{
	char filename[64] = {0};
	FILE *fp = NULL;
	int aclIdx=-1;
	sprintf(filename, "%s_%d", RG_ACL_PPPoE_PASS_RULES_FILE, wan_idx);
	//AUG_PRT("%s\n",filename);
	if (!(fp = fopen(filename, "r"))) 
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -2;
	}	
	while(fscanf(fp, "%d\n", &aclIdx) != EOF)
	{
		fprintf(stderr, "del pppoe pass idx = %d\n", aclIdx);
		if(rtk_rg_aclFilterAndQos_del(aclIdx))
			fprintf(stderr, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", aclIdx);
	}
	fclose(fp);
	unlink(filename);
	//AUG_PRT("exit\n");
	return 0;
}
//flush all
int RG_del_PPPoE_Acl(void)
{
	FILE *fp = NULL;
	int aclIdx=-1,i;
	char cmdStr[64] = {0};
	MIB_CE_ATM_VC_T entry;

	int totalEntry = mib_chain_total(MIB_ATM_VC_TBL);
	for(i; i < totalEntry; i++)
	{
		char filename[64] = {0};
		if (mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&entry) == 0)
			continue;
		if(entry.rg_wan_idx > 0)
		{
			sprintf(filename, "%s_%d", RG_ACL_PPPoE_PASS_RULES_FILE, entry.rg_wan_idx);
			//AUG_PRT("%s\n",filename);
			if (!(fp = fopen(filename, "r"))) 
			{
				fprintf(stderr, "ERROR! %s\n", strerror(errno));
				return -2;
			}		
	
			while(fscanf(fp, "%d\n", &aclIdx) != EOF)
			{
				fprintf(stderr, "del pppoe pass idx = %d\n", aclIdx);
				if(rtk_rg_aclFilterAndQos_del(aclIdx))
					fprintf(stderr, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", aclIdx);
			}
			fclose(fp);
			unlink(filename);
		}
	}
	snprintf(cmdStr, sizeof(cmdStr),"echo 0 > /proc/rg/pppoe_bc_passthrought_to_bindingWan");
	system(cmdStr);
	return 0;

}


int RG_add_PPPoE_RB_passthrough_Acl(void)
{
	MIB_CE_ATM_VC_T entry;
	MIB_CE_ATM_VC_T tempEntry;
	int totalEntry = mib_chain_total(MIB_ATM_VC_TBL);
	int i, j,aclIdx=0, ret, vlan_id=0;
	rtk_rg_aclFilterAndQos_t aclRule;
	rtk_rg_aclFilterAndQos_t tempAclRule;
	FILE *fp;
	int key=0;
    char cmdStr[64];
	int internet_vid = 0;
	char filename[64] = {0};	

	for (i = 0; i < totalEntry; i++)
	{
		if (mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&entry) == 0)
			continue;
		if(entry.enable == 0 || entry.rg_wan_idx <= 0)
			continue;		
		if(entry.cmode == CHANNEL_MODE_PPPOE && entry.brmode == BRIDGE_PPPOE){
			sprintf(filename, "%s_%d", RG_ACL_PPPoE_PASS_RULES_FILE, entry.rg_wan_idx);
			if (!(fp = fopen(filename, "a"))) 
			{
				fprintf(stderr, "ERROR! %s\n", strerror(errno));
				return -2;
			}

			//ACL for pppoe passthrought support us by SW (session ID keep original)
			#ifdef CONFIG_RTL9600_SERIES
			if(key == 0){
				//for pppoe passthrough, lan must trap for RG handle, we set once only.
				memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
				aclRule.fwding_type_and_direction =  ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	       		aclRule.acl_weight = RG_DEFAULT_ACL_WEIGHT;
	        	aclRule.filter_fields |= INGRESS_PORT_BIT;
				#ifdef CONFIG_RTL9602C_SERIES
				aclRule.ingress_port_mask.portmask = RG_get_lan_phyPortMask(entry.itfGroup & 0x3);
				#else
				aclRule.ingress_port_mask.portmask = RG_get_lan_phyPortMask(entry.itfGroup & 0xf);
				#endif
				if(entry.itfGroup > 0){
		        	aclRule.filter_fields |= INGRESS_ETHERTYPE_BIT;
					aclRule.ingress_ethertype = 0x8860;
					aclRule.ingress_ethertype_mask =0xFFF0;
					aclRule.action_type = ACL_ACTION_TYPE_TRAP;
					if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0)
						fprintf(fp,"%d\n",aclIdx);
					else
						fprintf(stderr,"rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n", ret);
				}
			}
			#endif
#if 0			
			memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
       		aclRule.acl_weight = RG_DEFAULT_ACL_WEIGHT;
        	aclRule.filter_fields |= INGRESS_PORT_BIT;
			aclRule.ingress_port_mask.portmask = RG_get_all_lan_phyPortMask();
			if(entry.itfGroup > 0){
	        	aclRule.filter_fields |= INGRESS_ETHERTYPE_BIT;
				aclRule.ingress_ethertype = 0x8864;
				aclRule.action_type = ACL_ACTION_TYPE_TRAP;
				if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0)
					fprintf(fp,"%d\n",aclIdx);
				else
					fprintf(stderr,"rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n", ret);
			}
#endif			
			//ACL for pppoe routing ds vlan keep original (avoid vlan translate for routing wan)
			memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
       		aclRule.acl_weight = RG_TRAP_ACL_WEIGHT;
        	aclRule.filter_fields |= INGRESS_PORT_BIT;
			aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();
        	aclRule.filter_fields |= INGRESS_ETHERTYPE_BIT;
			aclRule.ingress_ethertype = 0x8860;
			aclRule.ingress_ethertype_mask =0xFFF0;
        	aclRule.filter_fields |= INGRESS_DMAC_BIT;
			memcpy(&aclRule.ingress_dmac, entry.MacAddr, MAC_ADDR_LEN);
			if(entry.vlan){
        		aclRule.filter_fields |= INGRESS_CTAGIF_BIT;
				aclRule.ingress_ctagIf = 1;
				aclRule.filter_fields |= INGRESS_CTAG_VID_BIT;
				aclRule.ingress_ctag_vid = entry.vid;
			}
			aclRule.action_type = ACL_ACTION_TYPE_QOS;
			aclRule.qos_actions |= ACL_ACTION_ACL_INGRESS_VID_BIT;
			if(entry.vlan){
				aclRule.action_acl_ingress_vid = entry.vid;
			}else{
				mib_get(MIB_UNTAG_WAN_VLAN_ID, (void *)&vlan_id);
				aclRule.action_acl_ingress_vid = vlan_id;
			}
			if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0)
				fprintf(fp,"%d\n",aclIdx);
			else
				fprintf(stderr,"rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n", ret);
#if 0
			memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
       		aclRule.acl_weight = RG_DEFAULT_ACL_WEIGHT;
        	aclRule.filter_fields |= INGRESS_PORT_BIT;
			aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();
        	aclRule.filter_fields |= INGRESS_ETHERTYPE_BIT;
			aclRule.ingress_ethertype = 0x8864;
        	aclRule.filter_fields |= INGRESS_DMAC_BIT;
			memcpy(&aclRule.ingress_dmac, entry.MacAddr, MAC_ADDR_LEN);
			if(entry.vlan){
        		aclRule.filter_fields |= INGRESS_CTAGIF_BIT;
				aclRule.ingress_ctagIf = 1;
				aclRule.filter_fields |= INGRESS_CTAG_VID_BIT;			
				aclRule.ingress_ctag_vid = entry.vid;
			}
			aclRule.action_type = ACL_ACTION_TYPE_QOS;
			aclRule.qos_actions |= ACL_ACTION_ACL_INGRESS_VID_BIT;
			if(entry.vlan){
				aclRule.action_acl_ingress_vid = entry.vid;
			}else{
				mib_get(MIB_UNTAG_WAN_VLAN_ID, (void *)&vlan_id);
				aclRule.action_acl_ingress_vid = vlan_id;
			}
			if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0)
				fprintf(fp,"%d\n",aclIdx);
			else
				fprintf(stderr,"rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n", ret);
#endif
			//ACL for pppoe ds passthrough (vlan translate to lan vid to avoid vlan filter)
			memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
       		aclRule.acl_weight = RG_DEFAULT_ACL_WEIGHT;
        	aclRule.filter_fields |= INGRESS_PORT_BIT;
			aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();
        	aclRule.filter_fields |= INGRESS_ETHERTYPE_BIT;
			aclRule.ingress_ethertype = 0x8860;
			aclRule.ingress_ethertype_mask =0xFFF0;			
        	aclRule.filter_fields |= INGRESS_CTAGIF_BIT;
			aclRule.ingress_ctagIf = 1;
			aclRule.filter_fields |= INGRESS_CTAG_VID_BIT;
			if(entry.vlan){
				aclRule.ingress_ctag_vid = entry.vid;
			}else{
				mib_get(MIB_UNTAG_WAN_VLAN_ID, (void *)&vlan_id);
				aclRule.ingress_ctag_vid = vlan_id;
			}
			aclRule.action_type = ACL_ACTION_TYPE_QOS;
			aclRule.qos_actions |= ACL_ACTION_ACL_INGRESS_VID_BIT;
			mib_get(MIB_FWD_BIND_INTERNET_VLAN_ID,(void *)&internet_vid);
			fprintf(stderr,"---------fwdVLAN_BIND_INTERNET vid = %d\n",internet_vid);

			aclRule.action_acl_ingress_vid = internet_vid; 			
			if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0)
				fprintf(fp,"%d\n",aclIdx);
			else
				fprintf(stderr,"rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n", ret);
			
			/*
			 *	We need add following ACL to ensure keep VLAN to PS
			 *	, otherwise when exist PPPoE WAN disable hybrid bridge mode
			 *   && VID is equal to some PPPoE WAN which enable hybrid bridge mode
			 *  , packet will untagged to PS and diag PPPoE FAIL !!!
			 *  (because some PPPoE WAN which enable hybrid will add ACL to remove tag for pass through to LAN)
			 */
			for(j = 0; j < totalEntry; j++) {
				if (mib_chain_get(MIB_ATM_VC_TBL, j, (void *)&tempEntry) == 0)
					continue;

				if((i == j) || (entry.vid != tempEntry.vid))
					continue;

				if(tempEntry.cmode == CHANNEL_MODE_PPPOE && tempEntry.brmode != BRIDGE_PPPOE) {
					//ACL for pppoe routing ds vlan keep original (avoid vlan translate for routing wan)
					memset(&tempAclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
					tempAclRule.acl_weight = RG_TRAP_ACL_WEIGHT;
					tempAclRule.filter_fields |= INGRESS_PORT_BIT;
					tempAclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();
					tempAclRule.filter_fields |= INGRESS_ETHERTYPE_BIT;
					tempAclRule.ingress_ethertype = 0x8860;
					tempAclRule.ingress_ethertype_mask =0xFFF0;
					tempAclRule.filter_fields |= INGRESS_DMAC_BIT;
					memcpy(&tempAclRule.ingress_dmac, tempEntry.MacAddr, MAC_ADDR_LEN);
					if(tempEntry.vlan){
		        		tempAclRule.filter_fields |= INGRESS_CTAGIF_BIT;
						tempAclRule.ingress_ctagIf = 1;
						tempAclRule.filter_fields |= INGRESS_CTAG_VID_BIT;
						tempAclRule.ingress_ctag_vid = tempEntry.vid;
					}
					tempAclRule.action_type = ACL_ACTION_TYPE_QOS;
					tempAclRule.qos_actions |= ACL_ACTION_ACL_INGRESS_VID_BIT;
					if(tempEntry.vlan){
						tempAclRule.action_acl_ingress_vid = tempEntry.vid;
					}else{
						mib_get(MIB_UNTAG_WAN_VLAN_ID, (void *)&vlan_id);
						tempAclRule.action_acl_ingress_vid = vlan_id;
					}
					if((ret = rtk_rg_aclFilterAndQos_add(&tempAclRule, &aclIdx)) == 0)
						fprintf(fp,"%d\n",aclIdx);
					else
						fprintf(stderr,"rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n", ret);
				}
			}
#if 0
			memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
       		aclRule.acl_weight = RG_DEFAULT_ACL_WEIGHT;
        	aclRule.filter_fields |= INGRESS_PORT_BIT;
			aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();
        	aclRule.filter_fields |= INGRESS_ETHERTYPE_BIT;
			aclRule.ingress_ethertype = 0x8864;
			if(entry.vlan){
        		aclRule.filter_fields |= INGRESS_CTAGIF_BIT;
				aclRule.ingress_ctagIf = 1;
				aclRule.filter_fields |= INGRESS_CTAG_VID_BIT;			
				aclRule.ingress_ctag_vid = entry.vid;
			}
			aclRule.action_type = ACL_ACTION_TYPE_QOS;
			aclRule.qos_actions |= ACL_ACTION_ACL_INGRESS_VID_BIT;
			aclRule.action_acl_ingress_vid = init_param.fwdVLAN_BIND_INTERNET; //lan interface's vlan
			if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0)
				fprintf(fp,"%d\n",aclIdx);
			else
				fprintf(stderr,"rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n", ret);
#endif
			key = 1;
			fclose(fp);
		}
	}
	if(key){
		snprintf(cmdStr, sizeof(cmdStr),"echo 1 > /proc/rg/pppoe_bc_passthrought_to_bindingWan");
		system(cmdStr);
	}

	return 0;

}

int RG_add_default_Acl_Qos(void)
{
		MIB_CE_ATM_VC_T entry;
		int totalEntry = mib_chain_total(MIB_ATM_VC_TBL);
		int i,aclIdx=0, ret;
		rtk_rg_aclFilterAndQos_t aclRule;
		FILE *fp;
		unsigned int pon_mode=0;
		mib_get(MIB_PON_MODE, (void *)&pon_mode);
		//AUG_PRT("pon_mode=%d\n",pon_mode);
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
			if(entry.enable == 0)
				continue;
			if(entry.vprio && (entry.vlan == 1)){
				memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
				//aclRule.acl_weight = RG_QOS_LOW_ACL_WEIGHT;
				aclRule.action_type = ACL_ACTION_TYPE_QOS;
#ifdef CONFIG_RTL9600_SERIES				
				if(pon_mode == EPON_MODE){
					//due acl limitation, we use CF rules to replace ori acl rules to do 1p remarking
					aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_OR_EGRESS_L34_UP_STREAMID_CVLAN_SVLAN;
					aclRule.qos_actions |= ACL_ACTION_STREAM_ID_OR_LLID_BIT;
					aclRule.action_stream_id_or_llid = 0;
					aclRule.qos_actions |= ACL_ACTION_ACL_CVLANTAG_BIT;
					AUG_PRT("pon_mode=%d\n",pon_mode);
					aclRule.action_acl_cvlan.cvlanTagIfDecision=ACL_CVLAN_TAGIF_TAGGING;
					aclRule.action_acl_cvlan.cvlanCvidDecision = 0;
					aclRule.action_acl_cvlan.cvlanCpriDecision = 0;
					aclRule.action_acl_cvlan.assignedCvid = entry.vid;
					aclRule.action_acl_cvlan.assignedCpri = (entry.vprio - 1);		
					if(entry.rg_wan_idx <= 0)
					{
						printf("Invalid rg_wan_idx value ! rg_wan_idx=%d\n", entry.rg_wan_idx);
						//fclose(fp);
						continue;
					}
					aclRule.egress_intf_idx = entry.rg_wan_idx;
					aclRule.filter_fields |= EGRESS_INTF_BIT;
				}else
#endif
				{
					aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;				
					AUG_PRT("pon_mode=%d\n",pon_mode);
					aclRule.qos_actions |= ACL_ACTION_1P_REMARKING_BIT;
					aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
					aclRule.action_dot1p_remarking_pri = (entry.vprio - 1);
					if(entry.rg_wan_idx <= 0)
					{
						printf("Invalid rg_wan_idx value ! rg_wan_idx=%d\n", entry.rg_wan_idx);
						//fclose(fp);
						//return -1;
						continue;
					}
					//for local-in/out wan, we don't user egress wan as pattern,
					//it will waste more acl rules to compose change p-bit value behaviors
					//AUG_PRT("cmode=%d applicationtype=%d vid=%d\n",entry.cmode,entry.applicationtype,entry.vid);
					if(entry.cmode > 0 && !(entry.applicationtype & (X_CT_SRV_INTERNET|X_CT_SRV_OTHER))){
						//[WARNING] Mix egress WAN pattern rule with non-egress-WAN pattern rule at same weight!
						aclRule.acl_weight = RG_QOS_LOW_ACL_WEIGHT+1;
						aclRule.filter_fields |= INGRESS_SMAC_BIT;
						aclRule.filter_fields |= INGRESS_PORT_BIT;
						aclRule.ingress_port_mask.portmask = (1<<RTK_RG_PORT_CPU);
						memcpy(&aclRule.ingress_smac, entry.MacAddr, MAC_ADDR_LEN);
						//AUG_PRT("%d\n");
					}
					else{
						aclRule.acl_weight = RG_QOS_LOW_ACL_WEIGHT;
						aclRule.egress_intf_idx = entry.rg_wan_idx;
						aclRule.filter_fields |= EGRESS_INTF_BIT;
						//AUG_PRT("%d\n");
					}

				}
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

	memset(&staticInfo,0,sizeof(staticInfo));
	staticInfo.ipv4_default_gateway_on=entry->dgw;
	staticInfo.gw_mac_auto_learn_for_ipv4=1;
	if(entry->itfGroup && !(entry->dgw))
		staticInfo.static_route_with_arp = 1;
	else
		staticInfo.static_route_with_arp = 0;
	
	if(entry->dgw || entry->itfGroup)
		staticInfo.gateway_ipv4_addr=ntohl(((struct in_addr *)entry->remoteIpAddr)->s_addr);
	staticInfo.ip_addr=ntohl(((struct in_addr *)entry->ipAddr)->s_addr);
	staticInfo.ip_network_mask=ntohl(((struct in_addr *)entry->netMask)->s_addr);

	if(entry->dgw)
		staticInfo.ipv4_default_gateway_on = 1;

	staticInfo.ip_version = IPVER_V4ONLY;
	staticInfo.mtu=entry->mtu;
	if(entry->napt==1){

		staticInfo.napt_enable=1;
	}
	else{
#ifdef CONFIG_RTL9600_SERIES
		if (entry->applicationtype == X_CT_SRV_TR069 | entry->applicationtype == X_CT_SRV_VOICE | entry->applicationtype == (X_CT_SRV_VOICE|X_CT_SRV_TR069))
			staticInfo.napt_enable=1;
		else
#endif			
		staticInfo.napt_enable=0;
	}

#if defined(CONFIG_YUEME)
	char ifName[IFNAMSIZ];
	ifGetName(entry->ifIndex, ifName, sizeof(ifName));
	RTK_RG_add_UDP_rate_limit(ifName, (struct in_addr *) entry->ipAddr);
#endif
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
	staticInfo.static_route_with_arp = 0;

	if((rtk_rg_staticInfo_set(wanIntfIdx, &staticInfo))!=SUCCESS)
		return -1;

	return SUCCESS;
}

#ifdef SUPPORT_ACCESS_RIGHT
int FlushRTK_RG_RT_INTERNET_ACCESS_RIGHT()
{
	FILE *fp;
	int mac_idx;
	int acl_idx;

	fp = fopen(RG_INTERNET_ACCESS_DENY_RULES_FILE, "r");

	if(fp)
	{
		while(fscanf(fp, "%d\n", &mac_idx) != EOF)
		{
			if(rtk_rg_macFilter_del(mac_idx))
				DBPRINT(1, "rtk_rg_macFilter_del failed! idx = %d\n", mac_idx);
		}

		fclose(fp);
		unlink(RG_INTERNET_ACCESS_DENY_RULES_FILE);
	}

	if(!(fp = fopen(RG_INTERNET_ACCESS_NO_INTERNET_RULES_FILE, "r")))
		return -2;

	while(fscanf(fp, "%d\n", &acl_idx) != EOF)
	{
		if(rtk_rg_aclFilterAndQos_del(acl_idx))
			DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", acl_idx);
	}

	fclose(fp);
	unlink(RG_INTERNET_ACCESS_NO_INTERNET_RULES_FILE);
	return 0;
}


int AddRTK_RG_RT_INTERNET_ACCESS_RIGHT(unsigned char  internetAccessRight, unsigned char *smac)
{
	FILE *fp;
	int ret;

	if(internetAccessRight ==  INTERNET_ACCESS_DENY)
	{
		int macfilterIdx;
		rtk_rg_macFilterEntry_t macFilterEntry;

		memset(&macFilterEntry, 0, sizeof(rtk_rg_macFilterEntry_t));
		memcpy(&macFilterEntry.mac, smac, MAC_ADDR_LEN);
		macFilterEntry.direct = RTK_RG_MACFILTER_FILTER_SRC_MAC_ONLY;

		if(!(fp = fopen(RG_INTERNET_ACCESS_DENY_RULES_FILE, "a")))
		{
			fprintf(stderr, "ERROR! %s\n", strerror(errno));
			return -1;
		}

		if(rtk_rg_macFilter_add(&macFilterEntry, &macfilterIdx) == 0)
			fprintf(fp, "%d\n", macfilterIdx);
		else
			printf("Set rtk_rg_macFilter_add failed! dir = Source\n");

		fclose(fp);
		return 0;
	}
	else if(internetAccessRight == INTERNET_ACCESS_NO_INTERNET)
	{
		int aclIdx;
		rtk_rg_aclFilterAndQos_t aclRule;
		unsigned char gateway_ip[IP_ADDR_LEN] = {0};
		char gateway_mac[MAC_ADDR_LEN];

		if(!(fp = fopen(RG_INTERNET_ACCESS_NO_INTERNET_RULES_FILE, "a")))
		{
			fprintf(stderr, "ERROR! %s\n", strerror(errno));
			return -2;
		}

		mib_get(MIB_ELAN_MAC_ADDR, (void *)gateway_mac);
		mib_get(MIB_ADSL_LAN_IP, gateway_ip);

		/*acl rule 1: permit if match smac, dmac is gateway mac and dip is gateway ip */
		memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
#ifdef CONFIG_RTL9600_SERIES
		aclRule.action_type = ACL_ACTION_TYPE_TRAP;
#else
		aclRule.action_type = ACL_ACTION_TYPE_PERMIT;
#endif
		aclRule.filter_fields |= INGRESS_PORT_BIT;
		aclRule.ingress_port_mask.portmask = RG_get_all_lan_phyPortMask();

#ifdef WLAN_SUPPORT
		aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN0));
#ifdef WLAN_DUALBAND_CONCURRENT
		aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN1));
#endif
#endif
		aclRule.filter_fields |= INGRESS_SMAC_BIT;
		memcpy(&aclRule.ingress_smac, smac, MAC_ADDR_LEN);

		aclRule.filter_fields |= INGRESS_DMAC_BIT;
		memcpy(&aclRule.ingress_dmac, gateway_mac, MAC_ADDR_LEN);

		aclRule.filter_fields |= INGRESS_IPV4_DIP_RANGE_BIT;
		aclRule.ingress_dest_ipv4_addr_start = aclRule.ingress_dest_ipv4_addr_end = ntohl(*((in_addr_t *)gateway_ip));

		if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0)
			fprintf(fp, "%d\n", aclIdx);
		else
			printf("rtk_rg_aclFilterAndQos_add permit rule failed!\n");

#ifdef CONFIG_RTL9600_SERIES
		aclRule.action_type = ACL_ACTION_TYPE_SW_PERMIT;
		if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0)
			fprintf(fp, "%d\n", aclIdx);
		else
			printf("rtk_rg_aclFilterAndQos_add permit rule failed!\n");
#endif

		/* acl rule 2: permit if match smac and ethertype is arp */
		memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
#ifdef CONFIG_RTL9600_SERIES
		aclRule.action_type = ACL_ACTION_TYPE_TRAP;
#else
		aclRule.action_type = ACL_ACTION_TYPE_PERMIT;
#endif
		aclRule.filter_fields |= INGRESS_PORT_BIT;
		aclRule.ingress_port_mask.portmask = RG_get_all_lan_phyPortMask();	
#ifdef WLAN_SUPPORT
		aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN0));
#ifdef WLAN_DUALBAND_CONCURRENT
		aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN1));
#endif
#endif
		aclRule.filter_fields |= INGRESS_ETHERTYPE_BIT;
		aclRule.ingress_ethertype = 0x0806;

		aclRule.filter_fields |= INGRESS_SMAC_BIT;
		memcpy(&aclRule.ingress_smac, smac, MAC_ADDR_LEN);

		if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0)
			fprintf(fp, "%d\n", aclIdx);
		else
			printf("rtk_rg_aclFilterAndQos_add permit arp rule failed!\n");

#ifdef CONFIG_RTL9600_SERIES
		aclRule.action_type = ACL_ACTION_TYPE_SW_PERMIT;
		if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0)
			fprintf(fp, "%d\n", aclIdx);
		else
			printf("rtk_rg_aclFilterAndQos_add permit arp rule failed!\n");
#endif	

		/*acl rule 3: drop if match smac and dmac is gateway mac*/
		memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
		aclRule.action_type = ACL_ACTION_TYPE_DROP;
		aclRule.filter_fields |= INGRESS_PORT_BIT;
		aclRule.ingress_port_mask.portmask = RG_get_all_lan_phyPortMask();	
#ifdef WLAN_SUPPORT
		aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN0));
#ifdef WLAN_DUALBAND_CONCURRENT
		aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN1));
#endif
#endif
		aclRule.filter_fields |= INGRESS_SMAC_BIT;
		memcpy(&aclRule.ingress_smac, smac, MAC_ADDR_LEN);

		aclRule.filter_fields |= INGRESS_DMAC_BIT;
		memcpy(&aclRule.ingress_dmac, gateway_mac, MAC_ADDR_LEN);

		if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0)
			fprintf(fp, "%d\n", aclIdx);
		else
			printf("rtk_rg_aclFilterAndQos_add drop rule failed!\n");

		fclose(fp);
		return 0;
	}
}
#endif

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
	dhcpClient_info->hw_info.mtu=entry->mtu;

	if(entry->napt==1){
		dhcpClient_info->hw_info.napt_enable=1;
	}else{
#ifdef CONFIG_RTL9600_SERIES
		if (entry->applicationtype == X_CT_SRV_TR069 | entry->applicationtype == X_CT_SRV_VOICE | entry->applicationtype == (X_CT_SRV_VOICE|X_CT_SRV_TR069))
			dhcpClient_info->hw_info.napt_enable=1;
		else
#endif
		dhcpClient_info->hw_info.napt_enable=0;
	}
	
	if(entry->itfGroup && !(entry->dgw))
		dhcpClient_info->hw_info.static_route_with_arp = 1;
	else
		dhcpClient_info->hw_info.static_route_with_arp = 0;

	if(entry->dgw || (entry->itfGroup > 0))
	{
		dhcpClient_info->hw_info.gateway_ipv4_addr = ntohl(gw_addr.s_addr);
	}

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
#if defined(CONFIG_YUEME)
	char ifName[IFNAMSIZ];
	ifGetName(entry->ifIndex, ifName, sizeof(ifName));
	RTK_RG_add_UDP_rate_limit(ifName, (struct in_addr *) &ipaddr);
#endif
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

	memset(&dhcpClient_info,0,sizeof(dhcpClient_info));

	dhcpClient_info.stauts = 1;
	dhcpClient_info.hw_info.ipv4_default_gateway_on = 0;
	dhcpClient_info.hw_info.gw_mac_auto_learn_for_ipv4=1;
	dhcpClient_info.hw_info.ip_addr = 0;
	dhcpClient_info.hw_info.ip_network_mask = 0;
	dhcpClient_info.hw_info.mtu=1500;
	dhcpClient_info.hw_info.napt_enable=0;
	dhcpClient_info.hw_info.gateway_ipv4_addr = 0;
	dhcpClient_info.hw_info.static_route_with_arp = 0;

	if(rtk_rg_dhcpClientInfo_set(wanIntfIdx, &dhcpClient_info) != SUCCESS)
	{
		printf("rtk_rg_dhcpClientInfo_set error!!!\n");
		return -1;
	}
	DBG_DHCP_PRF("%s-%d:\n",__func__,__LINE__);

	return SUCCESS;
}

#ifdef CONFIG_USER_L2TPD_L2TPD
int RG_add_l2tp_wan(MIB_L2TP_T *pentry, int mib_l2tp_idx)
{
	rtk_rg_wanIntfConf_t *wan_info = NULL;
	rtk_rg_intfInfo_t *intf_info = NULL;
	MIB_CE_ATM_VC_T entryVC;
	uint32_t ipAddr, netMask;
	uint32_t server_ip;
	int totalVC_entry, i, rg_vc_wan_index=-1, mib_vc_wan_index=-1, ret=0, wanIntfIdx;
	int dgw_idx = -1;
	unsigned int pon_mode=0;
	char cmdStr[64];
	int omci_mode=-1;
	int omci_service=-1;
	int omci_bind=-1;

	server_ip = inet_addr(pentry->server);
	//printf("server_ip=0x%08X mib_l2tp_idx=%d\n",server_ip,mib_l2tp_idx);
	totalVC_entry = mib_chain_total(MIB_ATM_VC_TBL);
	for(i=0;i<totalVC_entry;i++){
		if(mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&entryVC) == 0)
			continue;

		if(entryVC.dgw==1 && dgw_idx==-1){
			dgw_idx = entryVC.rg_wan_idx;
			mib_vc_wan_index = i;
		}
		ipAddr = hextol(entryVC.ipAddr);
		netMask = hextol(entryVC.netMask);
		//printf("ipAddr=0x%08X netMask=0x%08X\n",ipAddr, netMask);
		if(netMask == 0 || ipAddr == 0)
			continue;
		if((ipAddr & netMask) == (server_ip & netMask)){
			rg_vc_wan_index = entryVC.rg_wan_idx;
			printf("[%s-%d]rg_vc_wan_index = %d\n",__func__,__LINE__,rg_vc_wan_index);
			break;
		}
	}

	if(mib_vc_wan_index < 0)
		mib_vc_wan_index = i;

	if(rg_vc_wan_index < 0){
		if(dgw_idx!=-1){
			rg_vc_wan_index = dgw_idx;
		}
		else{
			printf("[%s-%d]Can't find output WAN!\n",__func__,__LINE__);
			ret = -1;
			goto Error_l2tp3;
		}
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

	ret = rtk_rg_intfInfo_find(intf_info, &rg_vc_wan_index);
	if(ret!=0){
		fprintf(stderr, "ERROR! rtk_rg_intfInfo_find %s\n", strerror(errno));
		ret = -1;
		goto Error_l2tp1;
	}
	memcpy(wan_info,&(intf_info->wan_intf.wan_intf_conf),sizeof(rtk_rg_wanIntfConf_t));
	wan_info->wan_type = RTK_RG_L2TP;
	//if we set port binding mask, before dial-on-demand request ---> use napt_filterrule to check
	//packet count to dial l2tp. will be ingress vlan filtered by wan's vlan. because we don't have IP.
	//RG will trap 2 PS. 
	//[TRACE] Unmatch for L34 binding to L3 WAN... @ _rtk_rg_routingDecisionTablesLookup(3549)
	//[TRACE] Unmatch Binding Action: do L3 bind and skip L4 @ _rtk_rg_unmatchBindingAct(3367)
	//Apollo HW don't support VPN speedup, so trap2RG handle (SW forward), it is OK.	
	wan_info->port_binding_mask.portmask = 0;	
	wan_info->forcedAddNewIntf = 1;
	//AUG_PRT("wan_type=%x, portmask=0x%x\n",wan_info->wan_type,wan_info->port_binding_mask.portmask);
	//dump_wan_info(wan_info);
	if((rtk_rg_wanInterface_add(wan_info, &wanIntfIdx))!=SUCCESS){
		ret = -1;
		fprintf(stderr, "ERROR! rtk_rg_wanInterface_add %s\n", strerror(errno));
		goto Error_l2tp1;
	}
	//AUG_PRT("wanIntfIdx=%d\n",wanIntfIdx);

	mib_chain_get(MIB_ATM_VC_TBL, mib_vc_wan_index, (void *)&entryVC);
	if(entryVC.itfGroup > 0)
		omci_bind = 1;
	else
		omci_bind = 0;
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
#ifdef CONFIG_GPON_FEATURE
	mib_get(MIB_PON_MODE, (void *)&pon_mode);
	if(pon_mode == GPON_MODE){
		char vlan_based_pri;
		if(entryVC.vprio)
		{
			vlan_based_pri=(entryVC.vprio)-1;
		}
		else
		{
			vlan_based_pri=-1;
		}
		//sync omci cf rules.
		/*untag wan, omci egress vlan id = -1*/
		if(entryVC.vlan == 2)
			wan_info->egress_vlan_id = 4095;
		else{
			if(!wan_info->egress_vlan_tag_on)
				wan_info->egress_vlan_id = -1;
		}
#if ! defined(_LINUX_2_6_) && defined(CONFIG_TR142_MODULE)
		char ifname[IFNAMSIZ] = {0};
		ifGetName(PHY_INTF(pentry->ifIndex), ifname, sizeof(ifname));
		snprintf(cmdStr, sizeof(cmdStr)-1,"echo %d %s %s %d > %s", wanIntfIdx, ALIASNAME_NAS0, ifname, omci_bind, TR142_WAN_IDX_MAP);
		system(cmdStr);
#endif
		snprintf(cmdStr, sizeof(cmdStr),"echo %d %d %d %d %d %d %d > %s",wanIntfIdx,wan_info->egress_vlan_id,vlan_based_pri,omci_mode,omci_service,omci_bind,1,OMCI_WAN_INFO);
		system(cmdStr);
	}
#endif

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
	int ret=-1;
	

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
	l2tpClientInfoA->hw_info.napt_enable=1;
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


int RG_release_l2tp(int wanIntfIdx)
{
	rtk_rg_l2tpClientInfoBeforeDial_t l2tpClientInfoB;
	rtk_rg_l2tpClientInfoAfterDial_t l2tpClientInfoA;
//	printf("\n[%s:%d] wanIntfIdx=%d, Release IP got from pptp\n",__func__,__LINE__,wanIntfIdx);
	memset(&l2tpClientInfoB, 0, sizeof(l2tpClientInfoB));
	memset(&l2tpClientInfoA, 0, sizeof(l2tpClientInfoA));
	if((rtk_rg_l2tpClientInfoBeforeDial_set(wanIntfIdx, &l2tpClientInfoB)) != SUCCESS){
		return -1;
	}
	l2tpClientInfoA.hw_info.mtu=1492;
	l2tpClientInfoA.hw_info.gw_mac_auto_learn_for_ipv4=1;
	if((rtk_rg_l2tpClientInfoAfterDial_set(wanIntfIdx, &l2tpClientInfoA))!= SUCCESS)
		return -1;
	return 0;
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
	int totalVC_entry, i, rg_vc_wan_index=-1, mib_vc_wan_index=-1, ret=0, wanIntfIdx;
	int dgw_idx = -1;
	unsigned int pon_mode=0;
	char cmdStr[64];
	int omci_mode=-1;
	int omci_service=-1;
	int omci_bind=-1;


	server_ip = inet_addr(pentry->server);
	//printf("server_ip=0x%08X mib_pptp_idx=%d\n",server_ip,mib_pptp_idx);
	totalVC_entry = mib_chain_total(MIB_ATM_VC_TBL);
	for(i=0;i<totalVC_entry;i++){
		if(mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&entryVC) == 0)
			continue;

		if(entryVC.dgw==1 && dgw_idx==-1){
			dgw_idx = entryVC.rg_wan_idx;
			mib_vc_wan_index = i;
		}
		ipAddr = hextol(entryVC.ipAddr);
		netMask = hextol(entryVC.netMask);
		printf("ipAddr=0x%08X netMask=0x%08X\n",ipAddr, netMask);
		if(netMask == 0 || ipAddr == 0)
			continue;
		if((ipAddr & netMask) == (server_ip & netMask)){
			rg_vc_wan_index = entryVC.rg_wan_idx;
			printf("[%s-%d] rg_vc_wan_index = %d\n",__func__,__LINE__,rg_vc_wan_index);
			break;
		}
	}

	if(mib_vc_wan_index < 0)
		mib_vc_wan_index = i;

	if(rg_vc_wan_index < 0){
		if(dgw_idx!=-1){
			rg_vc_wan_index = dgw_idx;
		}
		else{
			printf("[%s-%d]Can't find output WAN!\n",__func__,__LINE__);
			ret = -1;
			goto Error_Pptp3;
		}
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
	ret = rtk_rg_intfInfo_find(intf_info, &rg_vc_wan_index);
	if(ret!=0){
		fprintf(stderr, "ERROR! rtk_rg_intfInfo_find %s\n", strerror(errno));
		ret = -1;
		goto Error_Pptp1;
	}
	memcpy(wan_info,&(intf_info->wan_intf.wan_intf_conf),sizeof(rtk_rg_wanIntfConf_t));
	wan_info->wan_type = RTK_RG_PPTP;
	//if we set port binding mask, before dial-on-demand request ---> use napt_filterrule to check
	//packet count to dial pptp. will be ingress vlan filtered by wan's vlan. because we don't have IP.
	//RG will trap 2 PS. 
	//[TRACE] Unmatch for L34 binding to L3 WAN... @ _rtk_rg_routingDecisionTablesLookup(3549)
	//[TRACE] Unmatch Binding Action: do L3 bind and skip L4 @ _rtk_rg_unmatchBindingAct(3367)
	//Apollo HW don't support VPN speedup, so trap2RG handle (SW forward), it is OK.
	wan_info->port_binding_mask.portmask = 0;	
	wan_info->forcedAddNewIntf = 1;
	//dump_wan_info(wan_info);
	if((rtk_rg_wanInterface_add(wan_info, &wanIntfIdx))!=SUCCESS){
		ret = -1;
		printf("%s-%d rtk_rg_wanInterface_add error\n",__func__,__LINE__);
		goto Error_Pptp1;
	}
	//AUG_PRT("wanIntfIdx=%d\n",wanIntfIdx);


	mib_chain_get(MIB_ATM_VC_TBL, mib_vc_wan_index, (void *)&entryVC);
	if(entryVC.itfGroup > 0)
		omci_bind = 1;
	else
		omci_bind = 0;
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
#ifdef CONFIG_GPON_FEATURE
	mib_get(MIB_PON_MODE, (void *)&pon_mode);
	if(pon_mode == GPON_MODE){
		char vlan_based_pri;
		if(entryVC.vprio)
		{
			vlan_based_pri=(entryVC.vprio)-1;
		}
		else
		{
			vlan_based_pri=-1;
		}
		//sync omci cf rules.
		/*untag wan, omci egress vlan id = -1*/
		if(entryVC.vlan == 2)
			wan_info->egress_vlan_id = 4095;
		else{
			if(!wan_info->egress_vlan_tag_on)
				wan_info->egress_vlan_id = -1;
		}
#if ! defined(_LINUX_2_6_) && defined(CONFIG_TR142_MODULE)
		char ifname[IFNAMSIZ] = {0};
		ifGetName(PHY_INTF(pentry->ifIndex), ifname, sizeof(ifname));
		snprintf(cmdStr, sizeof(cmdStr)-1,"echo %d %s %s %d > %s", wanIntfIdx, ALIASNAME_NAS0, ifname, omci_bind, TR142_WAN_IDX_MAP);
		system(cmdStr);
#endif
		snprintf(cmdStr, sizeof(cmdStr),"echo %d %d %d %d %d %d %d > %s",wanIntfIdx,wan_info->egress_vlan_id,vlan_based_pri,omci_mode,omci_service,omci_bind,1,OMCI_WAN_INFO);
		system(cmdStr);
	}
#endif

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
	int ret=-1;

	
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
	pptpClientInfoA->hw_info.napt_enable=1;
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
int RG_add_pppoe(unsigned short session_id, unsigned int gw_ip, unsigned int my_ip, unsigned char* gw_mac, MIB_CE_ATM_VC_T *vcEntry){
	rtk_rg_wanIntfConf_t wan_info;
	rtk_rg_pppoeClientInfoBeforeDial_t pppoeClientInfoB;
	rtk_rg_pppoeClientInfoAfterDial_t *pppoeClientInfoA=NULL;
	unsigned char value[6];
	int i,ret;
	int wanPhyPort=0;
	rtk_rg_intfInfo_t intf_info;
	rtk_ipv6_addr_t zeroIPv6={{0}};

	//This function is to set up PPPoE IPv4 IP/Gateway info into RG

	if(vcEntry->IpProtocol == IPVER_IPV6)
		return -1;

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
#if defined(CONFIG_YUEME)
	char ifName[IFNAMSIZ];
	ifGetName(vcEntry->ifIndex, ifName, sizeof(ifName));
	RTK_RG_add_UDP_rate_limit(ifName, (struct in_addr *) &my_ip);
#endif
	if((rtk_rg_pppoeClientInfoAfterDial_set(vcEntry->rg_wan_idx, pppoeClientInfoA)) != SUCCESS){
		return -1;
	}

#ifdef CONFIG_USER_PPPOE_PROXY
	if(vcEntry->PPPoEProxyEnable)
	{
		struct in_addr lan_ip;
		struct in_addr lan_ipmask;
		int acl_idx;
		int ret;
		char filename[128];
		FILE* fp;
		rtk_rg_aclFilterAndQos_t aclRule;

		mib_get(MIB_ADSL_LAN_IP, (void *)&lan_ip);
		mib_get(MIB_ADSL_LAN_SUBNET, (void *)&lan_ipmask);
		memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
		aclRule.action_type = ACL_ACTION_TYPE_DROP;
		aclRule.acl_weight = RG_DEFAULT_ACL_WEIGHT;
		aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
		aclRule.filter_fields |= (INGRESS_IPV4_SIP_RANGE_BIT|INGRESS_PORT_BIT|INGRESS_IPV4_TAGIF_BIT);
		aclRule.ingress_src_ipv4_addr_start = ntohl(lan_ip.s_addr&lan_ipmask.s_addr);
		aclRule.ingress_src_ipv4_addr_end = ntohl(lan_ip.s_addr|(~lan_ipmask.s_addr));
		aclRule.ingress_port_mask.portmask = RG_get_lan_phyPortMask(vcEntry->itfGroup);
		aclRule.ingress_ipv4_tagif = 1;

		snprintf(filename, 128, "/var/rg_acl_PPPOEPROXY_drop_rules_idx.%x", vcEntry->ifIndex);
		if(!(fp = fopen(filename, "a")))
		{
			fprintf(stderr, "ERROR! %s\n", strerror(errno));
			return -2;
		}
		else
		{

			if((ret=rtk_rg_aclFilterAndQos_add(&aclRule, &acl_idx)) == 0)
			{
				printf("[%s %d]Drop packets with SIP[0x%08x -> 0x%08x] portmask 0x%x, acl_idx=%u\n", __func__, __LINE__,
					aclRule.ingress_src_ipv4_addr_start, aclRule.ingress_src_ipv4_addr_end, aclRule.ingress_port_mask.portmask, acl_idx);
				fprintf(fp,"%d\n",acl_idx);
				fclose(fp);
				return 0;
			}
			else
			{
				printf("[%s %d]rtk_rg_aclFilterAndQos_add failed, ret=%d\n", __func__, __LINE__, ret);
			}
			fclose(fp);
			return -1;
		}
	}
#endif
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


int RG_Del_All_LAN_Interfaces()
{
	FILE *fp;
	int lanIdx;

	if(!(fp = fopen(RG_LAN_INF_IDX, "r")))
		return -2;

	while(fscanf(fp, "%d\n", &lanIdx) != EOF)
	{
		if(rtk_rg_interface_del(lanIdx))
			DBPRINT(1, "RG_Del_All_LAN_Interfaces failed! (idx = %d)\n", lanIdx);
	}

	fclose(fp);
	unlink(RG_LAN_INF_IDX);
	return 0;
}

#ifdef CONFIG_USER_PPTP_CLIENT_PPTP
const char PPTP_ACL_ROUTE_TBL[] = "/var/rg_pptp_acl_route_idx";
const char PPTP_ACL_ROUTE_TBL_TMP[] = "/var/rg_pptp_acl_route_idx_tmp";
const char PPTP_ACL_ROUTE_TBL_LOCK[] = "/var/rg_pptp_acl_route_idx_lock";

const char PPTP_ACL_URL_ROUTE_TBL[] = "/var/rg_pptp_acl_url_route_idx";
const char PPTP_ACL_URL_ROUTE_TBL_TMP[] = "/var/rg_pptp_acl_url_route_idx_tmp";
const char PPTP_ACL_URL_ROUTE_TBL_LOCK[] = "/var/rg_pptp_acl_url_route_idx_lock";

int RG_Flush_PPTP_Route_All(void)
{
	FILE *fp,*fp_tmp,*fp_lock;
	int acl_idx, napt_idx, pptp_route_idx;
	unsigned int napt_last_pkt_cnt;
	char line[64];
	char name[32];


	fp_lock = fopen(PPTP_ACL_ROUTE_TBL_LOCK, "r");
	while(fp_lock) {
		fp_lock = fopen(PPTP_ACL_ROUTE_TBL_LOCK, "r");
	}
	fp_lock = fopen(PPTP_ACL_ROUTE_TBL_LOCK, "a");
	
	if(!(fp = fopen(PPTP_ACL_ROUTE_TBL, "r"))) {
		fclose(fp_lock);
		unlink(PPTP_ACL_ROUTE_TBL_LOCK);
		return -2;
	}

	while(fgets(line, 64, fp) != NULL)
	{
		sscanf(line, "%s %d %d %d %d\n",name, &acl_idx, &pptp_route_idx, &napt_idx, &napt_last_pkt_cnt);
		if(acl_idx != -1) {
			if(rtk_rg_aclFilterAndQos_del(acl_idx))
				DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", acl_idx);
		}

		if(napt_idx != -1) {
			if(rtk_rg_naptFilterAndQos_del(napt_idx))
				DBPRINT(1, "rtk_rg_naptFilterAndQos_del failed! idx = %d\n", napt_idx);
		}
	}

	fclose(fp);
	fclose(fp_lock);
	unlink(PPTP_ACL_ROUTE_TBL);
	unlink(PPTP_ACL_ROUTE_TBL_LOCK);

	return 0;
}

int RG_Flush_PPTP_Route(unsigned char *tunnelName)
{
	FILE *fp,*fp_tmp,*fp_lock;
	int acl_idx, napt_idx, pptp_route_idx;
	unsigned int napt_last_pkt_cnt;
	char line[64];
	char name[32];


	fp_lock = fopen(PPTP_ACL_ROUTE_TBL_LOCK, "r");
	while(fp_lock) {
		fp_lock = fopen(PPTP_ACL_ROUTE_TBL_LOCK, "r");
	}
	fp_lock = fopen(PPTP_ACL_ROUTE_TBL_LOCK, "a");

	if(!(fp = fopen(PPTP_ACL_ROUTE_TBL, "r"))) {
		fclose(fp_lock);
		unlink(PPTP_ACL_ROUTE_TBL_LOCK);
		return -2;
	}

	if(!(fp_tmp = fopen(PPTP_ACL_ROUTE_TBL_TMP, "w"))) {
		fclose(fp);
		fclose(fp_lock);
		unlink(PPTP_ACL_ROUTE_TBL_LOCK);
		return -2;
	}

	while(fgets(line, 64, fp) != NULL)
	{
		sscanf(line, "%s %d %d %d %d\n",name, &acl_idx, &pptp_route_idx, &napt_idx, &napt_last_pkt_cnt);

		if(!strcmp(tunnelName,name)){
			if(acl_idx != -1) {
				if(rtk_rg_aclFilterAndQos_del(acl_idx))
					DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", acl_idx);
			}

			if(napt_idx != -1) {
				if(rtk_rg_naptFilterAndQos_del(napt_idx))
					DBPRINT(1, "rtk_rg_naptFilterAndQos_del failed! idx = %d\n", napt_idx);
			}
		}
		else
			fprintf(fp_tmp, "%s %d %d %d %d\n", name, acl_idx, pptp_route_idx, napt_idx, napt_last_pkt_cnt);


	}


	fclose(fp);
	fclose(fp_tmp);
	fclose(fp_lock);
	unlink(PPTP_ACL_ROUTE_TBL);
	rename(PPTP_ACL_ROUTE_TBL_TMP, PPTP_ACL_ROUTE_TBL);
	unlink(PPTP_ACL_ROUTE_TBL_LOCK);

	return 0;
}


int RG_Flush_PPTP_Dynamic_URL_Route(unsigned char *tunnelName)
{
	FILE *fp,*fp_tmp;
	int acl_idx, napt_idx, pptp_route_idx;
	unsigned int napt_last_pkt_cnt;
	char line[64];
	char name[32];


	if(!(fp = fopen(PPTP_ACL_URL_ROUTE_TBL, "r")))
		return -2;

	if(!(fp_tmp = fopen(PPTP_ACL_URL_ROUTE_TBL_TMP, "w")))
		return -2;

	while(fgets(line, 64, fp) != NULL)
	{
		sscanf(line, "%s %d %d %d %d\n",name, &acl_idx, &pptp_route_idx, &napt_idx, &napt_last_pkt_cnt);

		if(!strcmp(tunnelName,name)){
			if(acl_idx != -1) {
				if(rtk_rg_aclFilterAndQos_del(acl_idx))
					DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", acl_idx);
			}

			if(napt_idx != -1) {
				if(rtk_rg_naptFilterAndQos_del(napt_idx))
					DBPRINT(1, "rtk_rg_naptFilterAndQos_del failed! idx = %d\n", napt_idx);
			}
		}
		else
			fprintf(fp_tmp, "%s %d %d %d %d\n", name, acl_idx, pptp_route_idx, napt_idx, napt_last_pkt_cnt);
	}

	fclose(fp);
	fclose(fp_tmp);
	unlink(PPTP_ACL_URL_ROUTE_TBL);
	rename(PPTP_ACL_URL_ROUTE_TBL_TMP, PPTP_ACL_URL_ROUTE_TBL);


	return 0;
}


int RG_Set_PPTP_Dynamic_URL_Route(char *name, struct in_addr addr)
{
	FILE *fp=NULL;
	MIB_CE_PPTP_ROUTE_T entry;
	int total_entry,i,enable,status;
	int cflags = REG_EXTENDED;
	regmatch_t pmatch[1];
	const size_t nmatch=1;
	rtk_rg_aclFilterAndQos_t aclRule;
	rtk_rg_naptFilterAndQos_t naptRule;
	int aclIdx, naptIdx, ret;
	int flags, flags_found, isPPTPup=0;
	char ifname[IFNAMSIZ];
	struct in_addr if_address;
	regex_t reg;
	

	if ( !mib_get(MIB_PPTP_ENABLE, (void *)&enable) ){
		printf("MIB_PPTP_ENABLE is not exist!");
		return -1;
	}

	if(!enable){
		printf("MIB_PPTP_ENABLE is not enable!");
		return 0;
	}

	total_entry = mib_chain_total(MIB_PPTP_ROUTE_TBL);
	for(i=0;i<total_entry;i++)
	{
		if(mib_chain_get(MIB_PPTP_ROUTE_TBL, i, (void *)&entry) == 0)
			continue;
		if((entry.url[0] != '\0') && (entry.ipv4_src_start==0) && (entry.ipv4_src_end==0))
		{
			AUG_PRT("%s-%d URL=%s name=%s\n",__func__,__LINE__,entry.url, name);
			if(regcomp(&reg, entry.url, cflags))
			{
				printf("failed to compile!\n");
				continue;
			}
			status = regexec(&reg, name, nmatch, pmatch, 0);
			if(status == REG_NOMATCH){
				printf("No match!\n");
			}
			else if(status==0)
			{
				printf("match:%s\n",name);
				//for(i=pmatch[0].rm_so;i<pmatch[0].rm_eo;++i)
				//	printf("%s",name);
					//putchar(buf[i]);
				//printf("\n");
				printf("addr=0x%x\n",addr.s_addr);
				
				ifGetName(entry.ifIndex, ifname, sizeof(ifname));
				getInAddr(ifname, IP_ADDR, &if_address);
				
				//check interface up or not, if up we set acl rules.
				if(!is_vpn_tunnel_encypted(VPN_TYPE_PPTP, entry.tunnelName)
					&& if_address.s_addr!=0x40404040)
				{					
					if(!Check_ACL_With_IP(VPN_TYPE_PPTP,addr,entry.tunnelName)){
						memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
						aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
						aclRule.action_type = ACL_ACTION_TYPE_POLICY_ROUTE;
						aclRule.filter_fields |= INGRESS_IPV4_DIP_RANGE_BIT;
						aclRule.ingress_dest_ipv4_addr_start = ntohl(addr.s_addr);
						aclRule.ingress_dest_ipv4_addr_end = ntohl(addr.s_addr);
						aclRule.action_policy_route_wan = entry.rg_wan_idx;  // Set egress interface to WAN.
						if(entry.priority >= 0){
							aclRule.acl_weight = VPN_PRIO_7-entry.priority;
							naptRule.weight = VPN_PRIO_7-entry.priority;
						}
						
						if(!(fp = fopen(PPTP_ACL_URL_ROUTE_TBL, "a")))	{
							fprintf(stderr, "ERROR! %s\n", strerror(errno));
							regfree(&reg);
							return -2;
						}						
						
						if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0)
							fprintf(fp, "%s %d -1 -1 -1\n",entry.tunnelName, aclIdx);
						else {							
							regfree(&reg);
							DBPRINT(1, "rtk_rg_aclFilterAndQos_add failed!\n");
							fclose(fp);
							return -1;
						}

						fclose(fp);
					}
				}
				
				if(!Check_NAPT_With_IP(VPN_TYPE_PPTP,addr,entry.tunnelName)) {
					unsigned int saved_packet_count;
					memset(&naptRule, 0, sizeof(rtk_rg_naptFilterAndQos_t));
					naptRule.filter_fields |= INGRESS_DIP_RANGE;
					naptRule.ingress_dest_ipv4_addr_range_start = ntohl(addr.s_addr);
					naptRule.ingress_dest_ipv4_addr_range_end = ntohl(addr.s_addr);
					naptRule.direction=RTK_RG_NAPT_FILTER_OUTBOUND;
					if(is_vpn_tunnel_encypted(VPN_TYPE_PPTP, entry.tunnelName)
						&& if_address.s_addr!=0x40404040)
						naptRule.action_fields = NAPT_SW_PACKET_COUNT | NAPT_SW_TRAP_TO_PS;
					else
						naptRule.action_fields = NAPT_SW_PACKET_COUNT;	
					saved_packet_count = load_vpn_packet_count_by_ip(VPN_TYPE_PPTP, naptRule.ingress_dest_ipv4_addr_range_start);
					if(saved_packet_count) {
						naptRule.packet_count = saved_packet_count;						
						save_vpn_packet_count(VPN_TYPE_PPTP, i, naptRule.ingress_dest_ipv4_addr_range_start, 0);
					}

					if(!(fp = fopen(PPTP_ACL_URL_ROUTE_TBL, "a")))	{							
						fprintf(stderr, "ERROR! %s\n", strerror(errno));
						regfree(&reg);
						return -2;
					}
					
					if(rtk_rg_naptFilterAndQos_add(&naptIdx, &naptRule) == 0) {
						fprintf(fp, "%s -1 %d %d 0\n",entry.tunnelName, i, naptIdx);
					}
					else {						
						regfree(&reg);
						DBPRINT(1, "rtk_rg_naptFilterAndQos_add failed!\n");
						fclose(fp);
						return -1;
					}

					fclose(fp);
				}
			}
			regfree(&reg);
		}
	}
}

int RG_Set_PPTP_Acl_Policy_Route(unsigned char *tunnelName, ATTACH_MODE_T attach_mode)
{

	MIB_CE_PPTP_ROUTE_T entry;
	int total_entry,i,enable;
	FILE *fp;
	rtk_rg_aclFilterAndQos_t aclRule;
	rtk_rg_naptFilterAndQos_t naptRule;
	int aclIdx, naptIdx, ret;
	int flags, flags_found, isPPTPup=0;
	char ifname[IFNAMSIZ];
	unsigned char sMAC_mask[MAC_ADDR_LEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};


	if ( !mib_get(MIB_PPTP_ENABLE, (void *)&enable) ){
		printf("MIB_PPTP_ENABLE is not exist!");
		return -1;
	}

	if(!enable){
		printf("MIB_PPTP_ENABLE is not enable!");
		return 0;
	}

	if(!(fp = fopen(PPTP_ACL_ROUTE_TBL, "a")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -2;
	}

	total_entry = mib_chain_total(MIB_PPTP_ROUTE_TBL);
	for(i=0;i<total_entry;i++)
	{
		if(mib_chain_get(MIB_PPTP_ROUTE_TBL, i, (void *)&entry) == 0)
			continue;

		if(!strcmp(entry.tunnelName,tunnelName))
		{
			if(entry.ipv4_src_start == 0 && entry.ipv4_src_end == 0 && !(entry.sMAC[0]|entry.sMAC[1]|entry.sMAC[2]|entry.sMAC[3]|entry.sMAC[4]|entry.sMAC[5]))/*route by URL*/
				continue;
			//check interface is up or not!
			ifGetName(entry.ifIndex, ifname, sizeof(ifname));

			flags_found = getInFlags(ifname, &flags);

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
			//check interface up or not, if up we set acl rules.
			if(isPPTPup)
			{
				memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
				memset(&naptRule, 0, sizeof(rtk_rg_naptFilterAndQos_t));
				aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
				aclRule.action_type = ACL_ACTION_TYPE_POLICY_ROUTE;
				if(entry.priority >= 0){
					aclRule.acl_weight = VPN_PRIO_7-entry.priority;
					naptRule.weight = VPN_PRIO_7-entry.priority; 					
				}				
				if(entry.ipv4_src_start || entry.ipv4_src_end)
				{
					if(ATTACH_MODE_DIP!=attach_mode)
						continue;

					aclRule.filter_fields |= INGRESS_IPV4_DIP_RANGE_BIT;
					aclRule.ingress_dest_ipv4_addr_start = ntohl(entry.ipv4_src_start);
					aclRule.ingress_dest_ipv4_addr_end = ntohl(entry.ipv4_src_end);

					naptRule.filter_fields |= INGRESS_DIP_RANGE;
					naptRule.ingress_dest_ipv4_addr_range_start = ntohl(entry.ipv4_src_start);
					naptRule.ingress_dest_ipv4_addr_range_end = ntohl(entry.ipv4_src_end);
				}
				else
				{
					if(ATTACH_MODE_SMAC!=attach_mode)
						continue;

					aclRule.filter_fields |= INGRESS_SMAC_BIT;
					memcpy(&aclRule.ingress_smac, entry.sMAC, MAC_ADDR_LEN);
					memcpy(&aclRule.ingress_smac_mask, sMAC_mask, MAC_ADDR_LEN);

					naptRule.filter_fields |= INGRESS_SMAC;
					memcpy(&naptRule.ingress_smac, entry.sMAC, MAC_ADDR_LEN);
				}

				naptRule.direction=RTK_RG_NAPT_FILTER_OUTBOUND;
				aclRule.action_policy_route_wan = entry.rg_wan_idx;  // Set egress interface to WAN.

				if(is_vpn_tunnel_encypted(VPN_TYPE_PPTP, entry.tunnelName)) {					
					naptRule.action_fields = NAPT_SW_PACKET_COUNT | NAPT_SW_TRAP_TO_PS;	
					if(rtk_rg_naptFilterAndQos_add(&naptIdx, &naptRule) == 0){
						fprintf(fp, "%s -1 %d %d 0\n",entry.tunnelName, i, naptIdx);
					}
					else {
						fclose(fp);
						DBPRINT(1, "rtk_rg_naptFilterAndQos_add failed!\n");
						return -1;
					}
				} else {
					naptRule.action_fields = NAPT_SW_PACKET_COUNT;
					if(rtk_rg_naptFilterAndQos_add(&naptIdx, &naptRule))
						DBPRINT(1, "rtk_rg_naptFilterAndQos_add failed!\n");

					if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0){
						fprintf(fp, "%s %d %d %d 0\n",entry.tunnelName, aclIdx, i, naptIdx);
					}
					else {
						fclose(fp);
						DBPRINT(1, "rtk_rg_aclFilterAndQos_add failed!\n");
						return -1;
					}
				}
			}
		}
	}
	fclose(fp);

	return 0;
}

int RG_Preset_PPTP_Napt_Rule( void )
{
	unsigned char sMAC_mask[MAC_ADDR_LEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	int total_route_entry,total_pptp_entry,i,j,enable;
	MIB_CE_PPTP_ROUTE_T route_entry;
	MIB_PPTP_T pptp_entry;
	rtk_rg_naptFilterAndQos_t naptRule;
	int naptIdx, ret;
	FILE *fp, *fp_lock;	

	
	if ( !mib_get(MIB_PPTP_ENABLE, (void *)&enable) ){
		printf("MIB_PPTP_ENABLE is not exist!");
		return -1;
	}
	
	if(!enable){
		printf("MIB_PPTP_ENABLE is not enable!");
		return 0;
	}

	fp_lock = fopen(PPTP_ACL_ROUTE_TBL_LOCK, "r");
	while(fp_lock) {
		fp_lock = fopen(PPTP_ACL_ROUTE_TBL_LOCK, "r");
	}
	fp_lock = fopen(PPTP_ACL_ROUTE_TBL_LOCK, "a");
	
	if(!(fp = fopen(PPTP_ACL_ROUTE_TBL, "a")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		fclose(fp_lock);
		unlink(PPTP_ACL_ROUTE_TBL_LOCK);
		return -2;
	}

	total_pptp_entry = mib_chain_total(MIB_PPTP_TBL);	
	total_route_entry = mib_chain_total(MIB_PPTP_ROUTE_TBL);
	for(i=0;i<total_pptp_entry;i++)
	{
		if(mib_chain_get(MIB_PPTP_TBL, i, (void *)&pptp_entry) == 0)
			continue;		
		
		for(j=0;j<total_route_entry;j++)
		{
			if(mib_chain_get(MIB_PPTP_ROUTE_TBL, j, (void *)&route_entry) == 0)
				continue;
			
			if(!strcmp(route_entry.tunnelName,pptp_entry.tunnelName))
			{
				if(route_entry.ipv4_src_start == 0 && route_entry.ipv4_src_end == 0 && !(route_entry.sMAC[0]|route_entry.sMAC[1]|route_entry.sMAC[2]|route_entry.sMAC[3]|route_entry.sMAC[4]|route_entry.sMAC[5]))/*route by URL*/
					continue;
				
				//check interface is up or not!
				memset(&naptRule, 0, sizeof(rtk_rg_naptFilterAndQos_t));
				if(route_entry.ipv4_src_start || route_entry.ipv4_src_end)
				{
					if(ATTACH_MODE_DIP!=pptp_entry.attach_mode)
						continue;

					naptRule.filter_fields |= INGRESS_DIP_RANGE;
					naptRule.ingress_dest_ipv4_addr_range_start = ntohl(route_entry.ipv4_src_start);
					naptRule.ingress_dest_ipv4_addr_range_end = ntohl(route_entry.ipv4_src_end);
					naptRule.direction=RTK_RG_NAPT_FILTER_OUTBOUND;
				}
				else
				{
					if(ATTACH_MODE_SMAC!=pptp_entry.attach_mode)
						continue;

					naptRule.filter_fields |= INGRESS_SMAC;
					memcpy(&naptRule.ingress_smac, route_entry.sMAC, MAC_ADDR_LEN);
					naptRule.direction=RTK_RG_NAPT_FILTER_OUTBOUND;
				}
				naptRule.action_fields = NAPT_SW_PACKET_COUNT;

				if(route_entry.priority >= 0){
					naptRule.weight = VPN_PRIO_7-route_entry.priority;
				}

				if(rtk_rg_naptFilterAndQos_add(&naptIdx, &naptRule) == 0)
					fprintf(fp, "%s -1 %d %d 0\n",route_entry.tunnelName, j, naptIdx);
				else {
					fclose(fp);
					fclose(fp_lock);
					unlink(PPTP_ACL_ROUTE_TBL_LOCK);
					DBPRINT(1, "rtk_rg_naptFilterAndQos_add failed!\n");
					return -1;
				}
			}
		}
	}
	
	fclose(fp);
	fclose(fp_lock);
	unlink(PPTP_ACL_ROUTE_TBL_LOCK);

	return 0;
}
#endif /*CONFIG_USER_PPTP_CLIENT_PPTP*/

#ifdef CONFIG_USER_L2TPD_L2TPD
const char L2TP_ACL_ROUTE_TBL[] = "/var/rg_l2tp_acl_route_idx";
const char L2TP_ACL_ROUTE_TBL_TMP[] = "/var/rg_l2tp_acl_route_idx_tmp";
const char L2TP_ACL_ROUTE_TBL_LOCK[] = "/var/rg_l2tp_acl_route_idx_lock";

const char L2TP_ACL_URL_ROUTE_TBL[] = "/var/rg_l2tp_acl_url_route_idx";
const char L2TP_ACL_URL_ROUTE_TBL_TMP[] = "/var/rg_l2tp_acl_url_route_idx_tmp";
const char L2TP_ACL_URL_ROUTE_TBL_LOCK[] = "/var/rg_l2tp_acl_url_route_idx_lock";

int RG_Flush_L2TP_Route_All(void)
{
	FILE *fp,*fp_tmp,*fp_lock;
	int acl_idx, napt_idx, pptp_route_idx;
	unsigned int napt_last_pkt_cnt;
	char line[64];
	char name[32];


	fp_lock = fopen(L2TP_ACL_ROUTE_TBL_LOCK, "r");
	while(fp_lock) {
		fp_lock = fopen(L2TP_ACL_ROUTE_TBL_LOCK, "r");
	}
	fp_lock = fopen(L2TP_ACL_ROUTE_TBL_LOCK, "a");
	
	if(!(fp = fopen(L2TP_ACL_ROUTE_TBL, "r"))) {
		fclose(fp_lock);
		unlink(L2TP_ACL_ROUTE_TBL_LOCK);
		return -2;
	}

	while(fgets(line, 64, fp) != NULL)
	{
		sscanf(line, "%s %d %d %d %d\n",name, &acl_idx, &pptp_route_idx, &napt_idx, &napt_last_pkt_cnt);
		if(acl_idx != -1) {
			if(rtk_rg_aclFilterAndQos_del(acl_idx))
				DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", acl_idx);
		}

		if(napt_idx != -1) {
			if(rtk_rg_naptFilterAndQos_del(napt_idx))
				DBPRINT(1, "rtk_rg_naptFilterAndQos_del failed! idx = %d\n", napt_idx);
		}
	}

	fclose(fp);
	fclose(fp_lock);
	unlink(L2TP_ACL_ROUTE_TBL);
	unlink(L2TP_ACL_ROUTE_TBL_LOCK);

	return 0;
}

/*
* rule_type: 0 both, 1 acl only
*/
int RG_Flush_L2TP_Route(unsigned char *tunnelName, unsigned char rule_type)
{
	FILE *fp,*fp_tmp,*fp_lock=NULL;
	int acl_idx, napt_idx, route_idx;
	unsigned int napt_last_pkt_cnt;
	char line[64];
	char name[32];

	
	fp_lock = fopen(L2TP_ACL_ROUTE_TBL_LOCK, "r");
	while(fp_lock) {
		fp_lock = fopen(L2TP_ACL_ROUTE_TBL_LOCK, "r");
	}
	fp_lock = fopen(L2TP_ACL_ROUTE_TBL_LOCK, "a");

	if(!(fp = fopen(L2TP_ACL_ROUTE_TBL, "r"))) {
		fclose(fp_lock);
		unlink(L2TP_ACL_ROUTE_TBL_LOCK);
		return -2;
	}

	if(!(fp_tmp = fopen(L2TP_ACL_ROUTE_TBL_TMP, "w"))) {
		fclose(fp);
		fclose(fp_lock);
		unlink(L2TP_ACL_ROUTE_TBL_LOCK);
		return -2;
	}

	while(fgets(line, 64, fp) != NULL)
	{
		sscanf(line, "%s %d %d %d %d\n",name, &acl_idx, &route_idx, &napt_idx, &napt_last_pkt_cnt);
		if(!strcmp(tunnelName,name)){
			if(acl_idx != -1) {
				if(rtk_rg_aclFilterAndQos_del(acl_idx))
					DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", acl_idx);
			}

			if(napt_idx != -1) {
				if(rule_type == 1) {
					// flush ACL only && this entry is not ACL(is for NAPT), then we reserve it
					fprintf(fp_tmp, "%s %d %d %d %d\n", name, acl_idx, route_idx, napt_idx, napt_last_pkt_cnt);
				} else {
					if(rtk_rg_naptFilterAndQos_del(napt_idx))
						DBPRINT(1, "rtk_rg_naptFilterAndQos_del failed! idx = %d\n", napt_idx);
				}
			}
		}
		else
			fprintf(fp_tmp, "%s %d %d %d %d\n", name, acl_idx, route_idx, napt_idx, napt_last_pkt_cnt);

	}

	fclose(fp);
	fclose(fp_tmp);
	fclose(fp_lock);
	unlink(L2TP_ACL_ROUTE_TBL);
	rename(L2TP_ACL_ROUTE_TBL_TMP, L2TP_ACL_ROUTE_TBL);
	unlink(L2TP_ACL_ROUTE_TBL_LOCK);

	return 0;
}

int Static_L2TP_ACL_Policy_Route_Remove(unsigned char *if_name)
{
	unsigned char mib_ifname[20], if_tunnelname[MAX_NAME_LEN];
	MIB_CE_ATM_VC_T vc_entry;
	MIB_L2TP_T l2tp_entry;
	int total_num;	
	int ret;
	int i;
	

	if_tunnelname[0] = '\0';
	total_num = mib_chain_total(MIB_L2TP_TBL); /* get chain record size */
	for(i=0 ; i<total_num ; i++) {
		if ( !mib_chain_get(MIB_L2TP_TBL, i, (void *)&l2tp_entry) )
			continue;

		ifGetName(l2tp_entry.ifIndex, mib_ifname, sizeof(mib_ifname));
		if(!strcmp(mib_ifname, if_name)) {
			sprintf(if_tunnelname, "%s", l2tp_entry.tunnelName);
		}
	}

	if(if_tunnelname[0] != '\0')
		RG_Flush_L2TP_Route(if_tunnelname, 1);// Flush ACL only while L2TP wan is UP/DOWN(do not flush NAPT)

	return 0;
}

int RG_Flush_L2TP_Dynamic_URL_Route(unsigned char *tunnelName)
{
	FILE *fp,*fp_tmp;
	int acl_idx, napt_idx, pptp_route_idx;
	unsigned int napt_last_pkt_cnt;
	char line[64];
	char name[32];
	

	if(!(fp = fopen(L2TP_ACL_URL_ROUTE_TBL, "r"))) 
		return -2;

	if(!(fp_tmp = fopen(L2TP_ACL_URL_ROUTE_TBL_TMP, "w"))) {
		fclose(fp);
		return -2;
	}

	while(fgets(line, 64, fp) != NULL)
	{
		sscanf(line, "%s %d %d %d %d\n",name, &acl_idx, &pptp_route_idx, &napt_idx, &napt_last_pkt_cnt);

		if(!strcmp(tunnelName,name)){
			if(acl_idx != -1) {
				if(rtk_rg_aclFilterAndQos_del(acl_idx))
					DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", acl_idx);
			}

			if(napt_idx != -1){
				if(rtk_rg_naptFilterAndQos_del(napt_idx))
					DBPRINT(1, "rtk_rg_naptFilterAndQos_del failed! idx = %d\n", napt_idx);
			}
		}
		else
			fprintf(fp_tmp, "%s %d %d %d %d\n", name, acl_idx, pptp_route_idx, napt_idx, napt_last_pkt_cnt);
	}


	fclose(fp);
	fclose(fp_tmp);
	unlink(L2TP_ACL_URL_ROUTE_TBL);
	rename(L2TP_ACL_URL_ROUTE_TBL_TMP, L2TP_ACL_URL_ROUTE_TBL);

	return 0;
}


int RG_Set_L2TP_Dynamic_URL_Route(char *name, struct in_addr addr)
{
	MIB_CE_L2TP_ROUTE_T entry;
	int total_entry,i,enable,status;
	int cflags = REG_EXTENDED;	
	rtk_rg_aclFilterAndQos_t aclRule;
	rtk_rg_naptFilterAndQos_t naptRule;
	int aclIdx, naptIdx, ret;
	int flags, flags_found, isL2TPup=0;
	char ifname[IFNAMSIZ];		
	int total_num, def_RGWANIdx;	
	MIB_CE_ATM_VC_T vc_entry;
	struct in_addr if_address;
	regmatch_t pmatch[1];
	const size_t nmatch=1;
	regex_t reg;	
	FILE *fp=NULL;

	
	def_RGWANIdx = -1;
	total_num = mib_chain_total(MIB_ATM_VC_TBL); /* get chain record size */
	for(i=0 ; i<total_num ; i++) {
		if ( !mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&vc_entry) )
			continue;

		if(vc_entry.dgw == 1) {
			def_RGWANIdx = vc_entry.rg_wan_idx;
			break;
		}
	}

	if ( !mib_get(MIB_L2TP_ENABLE, (void *)&enable) ){
		printf("MIB_L2TP_ENABLE is not exist!");
		return -1;
	}
	if(!enable){
		printf("MIB_L2TP_ENABLE is not enable!");
		return 0;
	}
	
	total_entry = mib_chain_total(MIB_L2TP_ROUTE_TBL);
	for(i=0;i<total_entry;i++)
	{
		if(mib_chain_get(MIB_L2TP_ROUTE_TBL, i, (void *)&entry) == 0)
			continue;
		
		if((entry.url[0] != '\0') && (entry.ipv4_src_start==0) && (entry.ipv4_src_end==0))
		{
			AUG_PRT("%s-%d URL=%s name=%s\n",__func__,__LINE__,entry.url, name);
			
			if(regcomp(&reg, entry.url, cflags))
			{
				printf("failed to compile!\n");
				continue;
			}
			status = regexec(&reg, name, nmatch, pmatch, 0);
			if(status == REG_NOMATCH){
				printf("No match!\n");
			}
			else if(status==0)
			{
				printf("match:%s\n",name);
				printf("addr=0x%x\n",addr.s_addr);				
				if(!Check_ACL_With_IP(VPN_TYPE_L2TP,addr,entry.tunnelName)){
					memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
					aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
					aclRule.action_type = ACL_ACTION_TYPE_POLICY_ROUTE;
					aclRule.filter_fields |= INGRESS_IPV4_DIP_RANGE_BIT;
					aclRule.ingress_dest_ipv4_addr_start = ntohl(addr.s_addr);
					aclRule.ingress_dest_ipv4_addr_end = ntohl(addr.s_addr);
					if(entry.priority >= 0){
						aclRule.acl_weight = VPN_PRIO_7-entry.priority;
						naptRule.weight = VPN_PRIO_7-entry.priority;							
					}

					ifGetName(entry.ifIndex, ifname, sizeof(ifname));
					getInAddr(ifname, IP_ADDR, &if_address);
					if(if_address.s_addr!=0x40404040)
						aclRule.action_policy_route_wan = entry.rg_wan_idx;  // Set egress interface to WAN.
					else
						aclRule.action_policy_route_wan = def_RGWANIdx;

					if(!(fp = fopen(L2TP_ACL_URL_ROUTE_TBL, "a")))	{
						fprintf(stderr, "ERROR! %s\n", strerror(errno));
						regfree(&reg);
						return -2;
					}

					if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0)
						fprintf(fp, "%s %d -1 -1 -1\n",entry.tunnelName, aclIdx);
					else {							
						regfree(&reg);
						fclose(fp);
						DBPRINT(1, "rtk_rg_aclFilterAndQos_add failed!\n");
						return -1;
					}
					fclose(fp);
				}
				
				if(!Check_NAPT_With_IP(VPN_TYPE_L2TP,addr,entry.tunnelName)){
					unsigned int saved_packet_count;					
					memset(&naptRule, 0, sizeof(rtk_rg_naptFilterAndQos_t));
					naptRule.filter_fields |= INGRESS_DIP_RANGE;
					naptRule.ingress_dest_ipv4_addr_range_start = ntohl(addr.s_addr);
					naptRule.ingress_dest_ipv4_addr_range_end = ntohl(addr.s_addr);
					naptRule.direction=RTK_RG_NAPT_FILTER_OUTBOUND;					
					naptRule.action_fields = NAPT_SW_PACKET_COUNT;
					saved_packet_count = load_vpn_packet_count_by_ip(VPN_TYPE_L2TP, naptRule.ingress_dest_ipv4_addr_range_start);
					if(saved_packet_count) {
						naptRule.packet_count = saved_packet_count;						
						save_vpn_packet_count(VPN_TYPE_L2TP, i, naptRule.ingress_dest_ipv4_addr_range_start, 0);
					}

					if(!(fp = fopen(L2TP_ACL_URL_ROUTE_TBL, "a")))	{
						fprintf(stderr, "ERROR! %s\n", strerror(errno));
						regfree(&reg);
						return -2;
					}
					
					if(rtk_rg_naptFilterAndQos_add(&naptIdx, &naptRule) == 0)
						fprintf(fp, "%s -1 %d %d 0\n",entry.tunnelName, i, naptIdx);
					else {						
						regfree(&reg);
						fclose(fp);
						DBPRINT(1, "rtk_rg_naptFilterAndQos_add failed!\n");
						return -1;
					}
					fclose(fp);
				}
			}
			regfree(&reg);
		}
	}
}

int RG_Set_L2TP_Acl_Policy_Route(unsigned char *tunnelName, ATTACH_MODE_T attach_mode)
{

	MIB_CE_L2TP_ROUTE_T entry;
	int total_entry,i,enable;
	FILE *fp;
	rtk_rg_aclFilterAndQos_t aclRule;
	int aclIdx, ret;
	int flags, flags_found, isL2TPup=0;
	char ifname[IFNAMSIZ];
	unsigned char sMAC_mask[MAC_ADDR_LEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

	if ( !mib_get(MIB_L2TP_ENABLE, (void *)&enable) ){
		printf("MIB_L2TP_ENABLE is not exist!");
		return -1;
	}
	
	if(!enable){
		printf("MIB_L2TP_ENABLE is not enable!");
		return 0;
	}
	
	if(!(fp = fopen(L2TP_ACL_ROUTE_TBL, "a")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -2;
	}

	total_entry = mib_chain_total(MIB_L2TP_ROUTE_TBL);
	for(i=0;i<total_entry;i++)
	{
		if(mib_chain_get(MIB_L2TP_ROUTE_TBL, i, (void *)&entry) == 0)
			continue;
		if(!strcmp(entry.tunnelName,tunnelName))
		{
			if(entry.ipv4_src_start == 0 && entry.ipv4_src_end == 0 && !(entry.sMAC[0]|entry.sMAC[1]|entry.sMAC[2]|entry.sMAC[3]|entry.sMAC[4]|entry.sMAC[5]))/*route by URL*/
				continue;
			
			//check interface is up or not!
			ifGetName(entry.ifIndex, ifname, sizeof(ifname));
			flags_found = getInFlags(ifname, &flags);
			if (flags_found)
			{
				if (flags & IFF_UP)
				{
					isL2TPup = 1;
				}
			}
			//check interface up or not, if up we set acl rules.
			
			if(isL2TPup)
			{
				memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
				aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
				aclRule.action_type = ACL_ACTION_TYPE_POLICY_ROUTE;
				
				if(entry.priority >= 0){
					aclRule.acl_weight = VPN_PRIO_7-entry.priority;
				}
				
				if(entry.ipv4_src_start || entry.ipv4_src_end)
				{
					if(ATTACH_MODE_DIP!=attach_mode)
						continue;

					aclRule.filter_fields |= INGRESS_IPV4_DIP_RANGE_BIT;
					aclRule.ingress_dest_ipv4_addr_start = ntohl(entry.ipv4_src_start);
					aclRule.ingress_dest_ipv4_addr_end = ntohl(entry.ipv4_src_end);
				}
				else
				{
					if(ATTACH_MODE_SMAC!=attach_mode)
						continue;

					aclRule.filter_fields |= INGRESS_SMAC_BIT;
					memcpy(&aclRule.ingress_smac, entry.sMAC, MAC_ADDR_LEN);
					memcpy(&aclRule.ingress_smac_mask, sMAC_mask, MAC_ADDR_LEN);
				}
				aclRule.action_policy_route_wan = entry.rg_wan_idx;  // Set egress interface to WAN.

				if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0)
					fprintf(fp, "%s %d -1 -1 -1\n",entry.tunnelName, aclIdx);
				else {
					fclose(fp);
					DBPRINT(1, "rtk_rg_aclFilterAndQos_add failed!\n");
					return -1;
				}
			}
		}
	}
	fclose(fp);

	return 0;
}

int RG_Preset_L2TP_Napt_Rule( void )
{
	unsigned char sMAC_mask[MAC_ADDR_LEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	int total_route_entry,total_l2tp_entry,i,j,enable;
	MIB_CE_L2TP_ROUTE_T route_entry;
	MIB_L2TP_T l2tp_entry;
	rtk_rg_naptFilterAndQos_t naptRule;
	int naptIdx, ret;
	FILE *fp,*fp_lock=NULL;
	
	
	if ( !mib_get(MIB_L2TP_ENABLE, (void *)&enable) ){
		printf("MIB_L2TP_ENABLE is not exist!");
		return -1;
	}
	
	if(!enable){
		printf("MIB_L2TP_ENABLE is not enable!");
		return 0;
	}
	
	fp_lock = fopen(L2TP_ACL_ROUTE_TBL_LOCK, "r");
	while(fp_lock) {
		fp_lock = fopen(L2TP_ACL_ROUTE_TBL_LOCK, "r");
	}
	fp_lock = fopen(L2TP_ACL_ROUTE_TBL_LOCK, "a");

	if(!(fp = fopen(L2TP_ACL_ROUTE_TBL, "a")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		fclose(fp_lock);
		unlink(L2TP_ACL_ROUTE_TBL_LOCK);
		return -2;
	}
	
	total_l2tp_entry = mib_chain_total(MIB_L2TP_TBL);	
	total_route_entry = mib_chain_total(MIB_L2TP_ROUTE_TBL);
	for(i=0;i<total_l2tp_entry;i++)
	{
		if(mib_chain_get(MIB_L2TP_TBL, i, (void *)&l2tp_entry) == 0)
			continue;		
		
		for(j=0;j<total_route_entry;j++)
		{
			if(mib_chain_get(MIB_L2TP_ROUTE_TBL, j, (void *)&route_entry) == 0)
				continue;
			
			if(!strcmp(route_entry.tunnelName,l2tp_entry.tunnelName))
			{
				if(route_entry.ipv4_src_start == 0 && route_entry.ipv4_src_end == 0 && !(route_entry.sMAC[0]|route_entry.sMAC[1]|route_entry.sMAC[2]|route_entry.sMAC[3]|route_entry.sMAC[4]|route_entry.sMAC[5]))/*route by URL*/
					continue;
				
				//check interface is up or not!
				memset(&naptRule, 0, sizeof(rtk_rg_naptFilterAndQos_t));
				if(route_entry.ipv4_src_start || route_entry.ipv4_src_end)
				{
					if(ATTACH_MODE_DIP!=l2tp_entry.attach_mode)
						continue;

					naptRule.filter_fields |= INGRESS_DIP_RANGE;
					naptRule.ingress_dest_ipv4_addr_range_start = ntohl(route_entry.ipv4_src_start);
					naptRule.ingress_dest_ipv4_addr_range_end = ntohl(route_entry.ipv4_src_end);
					naptRule.direction=RTK_RG_NAPT_FILTER_OUTBOUND;
				}
				else
				{
					if(ATTACH_MODE_SMAC!=l2tp_entry.attach_mode)
						continue;

					naptRule.filter_fields |= INGRESS_SMAC;
					memcpy(&naptRule.ingress_smac, route_entry.sMAC, MAC_ADDR_LEN);
					naptRule.direction=RTK_RG_NAPT_FILTER_OUTBOUND;
				}
				naptRule.action_fields = NAPT_SW_PACKET_COUNT;
				
				if(route_entry.priority >= 0){
					naptRule.weight = VPN_PRIO_7-route_entry.priority;
				}

				if(rtk_rg_naptFilterAndQos_add(&naptIdx, &naptRule) == 0) {
					fprintf(fp, "%s -1 %d %d 0\n",route_entry.tunnelName, j, naptIdx);
				} else {
					DBPRINT(1, "rtk_rg_naptFilterAndQos_add failed!\n");
					continue;
				}
			}
		}
	}
	
	fclose(fp);
	fclose(fp_lock);
	unlink(L2TP_ACL_ROUTE_TBL_LOCK);

	return 0;
}
#endif /*CONFIG_USER_L2TPD_L2TPD*/

int RG_Interface_Del(int rg_intf_idx)
{
	rtk_rg_interface_del(rg_intf_idx);
}
int RG_WAN_Interface_Del(unsigned int rg_wan_idx)
{
	int ret=0;
	char cmdStr[64];
	unsigned int pon_mode;
	mib_get(MIB_PON_MODE, (void *)&pon_mode);
	
	if(rg_wan_idx > 0){
#if ! defined(_LINUX_2_6_) && defined(CONFIG_TR142_MODULE)
		snprintf(cmdStr, sizeof(cmdStr)-1,"echo clear %u > %s", rg_wan_idx, TR142_WAN_IDX_MAP);
		system(cmdStr);
#endif
		printf("%s-%d del RG WAN[%d]\n",__func__,__LINE__,rg_wan_idx);
		RTK_RG_FLUSH_MVLAN_ACL(rg_wan_idx);
		FlushRTK_RG_QoS_Rules_perWan(rg_wan_idx);
		RG_flush_pppoe_pass_acl_per_wan(rg_wan_idx);
#if defined(CONFIG_EPON_FEATURE) && defined(CONFIG_RTL9600_SERIES)
		//for EPON none binding lan port 
		if(pon_mode == EPON_MODE)
		{	
			Flush_RTK_RG_Bridge_from_Lan_ACL_perWan(rg_wan_idx);
		}
#endif	
#if defined(CONFIG_GPON_FEATURE)
		if(pon_mode == GPON_MODE)
		{
			fprintf(stderr, "%s-%d sync waninfo with OMCI!\n",__func__,__LINE__);
			snprintf(cmdStr, sizeof(cmdStr),"echo %d %d %d %d %d %d %d > %s",rg_wan_idx,0,0,0,0,0,0,OMCI_WAN_INFO);
			system(cmdStr);
		}
#endif
		if(rtk_rg_interface_del(rg_wan_idx)){
			DBPRINT(1, "%s failed! (idx = %d)\n", __func__, rg_wan_idx);
			ret =-1;
		}

#if defined(CONFIG_SUPPORT_AUTO_DIAG) && defined(CONFIG_TR142_MODULE)
		void delete_pppoe_emu_helper(int wan_index);
		delete_pppoe_emu_helper(rg_wan_idx);
#endif
	}

	return ret;
}
int RG_WAN_CVLAN_DEL(int vlanID)
{
	rtk_rg_cvlan_info_t cvlan_info;
	memset(&cvlan_info, 0, sizeof(rtk_rg_cvlan_info_t));
	cvlan_info.vlanId = vlanID;
	if(rtk_rg_cvlan_get(&cvlan_info) == RT_ERR_RG_OK)
	{
		//dump_cvlan_info(&cvlan_info);
		if(cvlan_info.addedAsCustomerVLAN == 1)
			rtk_rg_cvlan_del(vlanID);
	}
	return 0;
}


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
int RG_check_Droute(int configAll, MIB_CE_ATM_VC_Tp pEntry, int *EntryID)
{
	int vcTotal=-1;
	int i,key,idx=-1, rm_idx=-1, dgw_updated=0;
	MIB_CE_ATM_VC_T Entry, rm_Entry;

#if 1
		return 0;
#else
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
		if(Entry.enable == 0)
			continue;

		if(Entry.dgw == 1){
	    /*If any entry match the condition, would return directly*/
	    /*Below conditons (case 0, 1, 3) are terminated*/
			if(Entry.applicationtype & X_CT_SRV_INTERNET){
				return 2;
			}
			else{ // it might be SPECIAL_SERVICE WAN
				rm_idx = i;
			}
		}
		//VCentry existed an internet and routing WAN
		if((Entry.applicationtype & X_CT_SRV_INTERNET) && (Entry.cmode > 0) && (key==0)){
			key++;
			idx = i;
			
			if(rm_idx >= 0){
				if (!mib_chain_get(MIB_ATM_VC_TBL, rm_idx, (void *)&rm_Entry))
					return -1;
				rm_Entry.dgw=0;
				mib_chain_update(MIB_ATM_VC_TBL, (void *)&rm_Entry, rm_idx);
				dgw_updated=1;
			}
		}	
	}
			
			// if No X_CT_SRV_INTERNET type gateway, set a X_CT_SRV_SPECIAL_SERVICE_ALL as dgw if exist
	if(!key){
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
			if((Entry.applicationtype & X_CT_SRV_SPECIAL_SERVICE_ALL) && (Entry.cmode > 0) && (key==0)){
				key++;
				idx = i;
			}

		}
	}
	
	if(key > 0){
		//get D route entry!
		mib_chain_get(MIB_ATM_VC_TBL, idx, (void *)&Entry);
		Entry.dgw = 1;
		if( pEntry==NULL && EntryID == NULL){
			//it means we are at starting up process
			//fprintf(stderr, "%s-%d key=%d, idx=%d\n",__func__,__LINE__,key,idx);
			mib_chain_update(MIB_ATM_VC_TBL, (void *)&Entry, idx);
			return 4;
		}

		//fprintf(stderr, "%s-%d key=%d, Entry.dgw=%d\n",__func__,__LINE__,key,Entry.dgw);

		if(!dgw_updated){
			if(pEntry && pEntry->ifIndex == Entry.ifIndex){
			/*the entry which you modified is setted as D route!*/
				mib_chain_update(MIB_ATM_VC_TBL, (void *)&Entry, idx);
				return 1;
			}
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
#endif
}

#ifdef CONFIG_MCAST_VLAN
/*one mVlan can only be setted to one WAN*/
int RTK_RG_ACL_Handle_IGMP(MIB_CE_ATM_VC_T *pentry)
{
	unsigned char mode,igmp_snoop_flag=0;
	rtk_rg_aclFilterAndQos_t aclRule;
	int i,aclIdx=0, ret;
	int port_idx=0;
	unsigned short itfGroup;
	unsigned int fwdcpu_vid;
	int dev_idx=0; /*only support master WLAN*/
	FILE *fp = NULL;
	char filename[64] = {0};
	char dis_vlan_filter=0;
	
	sprintf(filename, "%s_%d", RG_ACL_MVLAN_RULES_FILE, pentry->rg_wan_idx);
	if (!(fp = fopen(filename, "a"))) {
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -2;
	}
	AUG_PRT("%s\n",filename);
	mib_get(PROVINCE_DISABLE_MCAST_INGRESS_VLAN_FILTER, (void *)&dis_vlan_filter);	
	AUG_PRT("%s dis_vlan_filter=%d\n",filename,dis_vlan_filter);

	//check igmp snooping is on/off
#if 0
	mib_get(MIB_MPMODE, (void *)&mode);
	igmp_snoop_flag = (((mode&MP_IGMP_MASK)==MP_IGMP_MASK)?1:0);
//fprintf(stderr, "igmp_snoop_flag:%d\n",igmp_snoop_flag);
	if(!igmp_snoop_flag){
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
		if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0){
			fprintf(fp,"%d\n",aclIdx);
			fprintf(stderr, "add mCast ACL Vlan:%d, index=%d success\n",pentry->mVid, aclIdx);
		}else{
			fprintf(stderr,"rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n", ret);
			return -1;
		}
		goto CHECK_V4_SNOOPING;
	}
#endif
	if(pentry->mVid > 0){
		FILE *fpmVid=NULL;
		int pon_mode=0, avalanche_en=0;
		if(dis_vlan_filter == 0)
		{	
			//transfer multicast vlan to wan's vlan to avoid ingress vlan filter.
			if(pentry->mVid != pentry->vid)
			{			
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
				if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0){
					fprintf(fp,"%d\n",aclIdx);
					fprintf(stderr, "add mCast ACL Vlan:%d, index=%d success\n",pentry->mVid, aclIdx);
				}else{
					fprintf(stderr,"[%s@%d] rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n",__func__,__LINE__, ret);
					fclose(fp);
					return -1;
				}
			}
		}

		//for avalanche test under epon mode.
		mib_get(MIB_AVALANCHE_ENABLE, (void *)&avalanche_en);
		if(avalanche_en)
		{
			//enable avalanche.
#if defined(CONFIG_GPON_FEATURE) || defined(CONFIG_EPON_FEATURE)
			mib_get(MIB_PON_MODE, (void *)&pon_mode);
			if(pon_mode == EPON_MODE)
			{
				AUG_PRT("%s-%d\n",__func__,__LINE__);
#if defined(CONFIG_RTL9602C_SERIES)
				//APOLLOFE:
				//rg clear acl-filter
				//rg set acl-filter fwding_type_and_direction 3
				//rg set acl-filter action action_type 3
				//rg set acl-filter action qos action_ctag tagging cvidDecision 0 cpriDecision 0 cvid 901 cpri 0
				//rg set acl-filter action qos action_stream_id 0
				//rg set acl-filter pattern ingress_dmac 1:0:5e:0:0:0
				//rg set acl-filter pattern ingress_dmac_mask ff:ff:ff:0:0:0
				//rg set acl-filter pattern ingress_port_mask 0x3
				//rg add acl-filter entry
				memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
				aclRule.fwding_type_and_direction =  ACL_FWD_TYPE_DIR_INGRESS_OR_EGRESS_L34_UP_STREAMID_CVLAN_SVLAN;
				aclRule.action_type = ACL_ACTION_TYPE_QOS;
				aclRule.qos_actions |= ACL_ACTION_ACL_CVLANTAG_BIT;
				aclRule.action_acl_cvlan.cvlanTagIfDecision=ACL_CVLAN_TAGIF_TAGGING;
				aclRule.action_acl_cvlan.cvlanCvidDecision = 0;
				aclRule.action_acl_cvlan.cvlanCpriDecision = 0;
				aclRule.action_acl_cvlan.assignedCvid = pentry->mVid;
				aclRule.action_acl_cvlan.assignedCpri = 0;
				//rg set acl-filter action qos action_stream_id 0
				aclRule.qos_actions |= ACL_ACTION_STREAM_ID_OR_LLID_BIT;
				aclRule.action_stream_id_or_llid = 0;
				aclRule.filter_fields |= EGRESS_INTF_BIT;
				aclRule.egress_intf_idx = pentry->rg_wan_idx;
				aclRule.filter_fields |= INGRESS_DMAC_BIT;
				memcpy(&aclRule.ingress_dmac,MCAST_ADDR,MAC_ADDR_LEN);
				memcpy(&aclRule.ingress_dmac_mask,MCAST_MASK,MAC_ADDR_LEN);
				aclRule.filter_fields |= INGRESS_PORT_BIT;
				aclRule.ingress_port_mask.portmask = RG_get_all_lan_phyPortMask();
				//rg add acl-filter entry
				if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0){
					fprintf(fp,"%d\n",aclIdx);
					//AUG_PRT("add Vlan:%d, index=%d success\n",pentry->mVid, aclIdx);
					//fprintf(stderr, "add %s-%d Vlan:%d, index=%d success\n",__func__,__LINE__,entry->vid, aclIdx);
				}else{
					fprintf(stderr,"%s-%d add rule failed! (ret = %d)\n",__func__,__LINE__, ret);
					fclose(fp);
					return -1;
				}
#else
				//APOLLO:
				//rg clear acl-filter
				//rg set acl-filter fwding_type_and_direction 3
				//rg set acl-filter action action_type 3
				//rg set acl-filter action qos action_ctag tagging cvidDecision 0 cpriDecision 0 cvid 901 cpri 0
				//rg set acl-filter action qos action_stream_id 0
				//rg set acl-filter pattern egress_intf_idx 3
				//rg set acl-filter pattern ingress_dmac 1:0:5e:0:0:0
				//rg set acl-filter pattern ingress_dmac_mask ff:ff:ff:0:0:0
				//rg set acl-filter pattern ingress_port_mask 0xf
				//rg add acl-filter entry
				memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
				aclRule.fwding_type_and_direction =  ACL_FWD_TYPE_DIR_INGRESS_OR_EGRESS_L34_UP_STREAMID_CVLAN_SVLAN;
				aclRule.action_type = ACL_ACTION_TYPE_QOS;
				aclRule.qos_actions |= ACL_ACTION_ACL_CVLANTAG_BIT;
				aclRule.action_acl_cvlan.cvlanTagIfDecision=ACL_CVLAN_TAGIF_TAGGING;
				aclRule.action_acl_cvlan.cvlanCvidDecision = 0;
				aclRule.action_acl_cvlan.cvlanCpriDecision = 0;
				aclRule.action_acl_cvlan.assignedCvid = pentry->mVid;
				aclRule.action_acl_cvlan.assignedCpri = 0;
				aclRule.filter_fields |= EGRESS_INTF_BIT;
				aclRule.egress_intf_idx = pentry->rg_wan_idx;
				//rg set acl-filter action qos action_stream_id 0
				aclRule.qos_actions |= ACL_ACTION_STREAM_ID_OR_LLID_BIT;
				aclRule.action_stream_id_or_llid = 0;
				aclRule.filter_fields |= INGRESS_DMAC_BIT;
				memcpy(&aclRule.ingress_dmac,MCAST_ADDR,MAC_ADDR_LEN);
				memcpy(&aclRule.ingress_dmac_mask,MCAST_MASK,MAC_ADDR_LEN);
				aclRule.filter_fields |= INGRESS_PORT_BIT;
				aclRule.ingress_port_mask.portmask = RG_get_all_lan_phyPortMask();
				//rg add acl-filter entry
				if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0){
					fprintf(fp,"%d\n",aclIdx);
					//AUG_PRT("add Vlan:%d, index=%d success\n",pentry->mVid, aclIdx);
					//fprintf(stderr, "add %s-%d Vlan:%d, index=%d success\n",__func__,__LINE__,entry->vid, aclIdx);
				}else{
					fprintf(stderr,"%s-%d add rule failed! (ret = %d)\n",__func__,__LINE__, ret);
					fclose(fp);
					return -1;
				}
#endif
			}
#endif
		}
	}
#ifdef CONFIG_RTL9600_SERIES
	if(pentry->cmode == CHANNEL_MODE_BRIDGE && pentry->applicationtype == X_CT_SRV_OTHER)
	{
			FILE *fpmVid=NULL;
			if(dis_vlan_filter != 0)
			{
				//due setup acl rule to do transfer dwonstream mcast data
				//from xxx vid to internal 1. it would affect smart tv, so 
				//we add a higher priority acl let smart tv mcast to transfert	
				//to bridge wan's vlan group.
				//transfer multicast vlan to wan's vlan to avoid ingress vlan filter.
				memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
				aclRule.filter_fields |= INGRESS_PORT_BIT;
				aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();//wan port
				aclRule.acl_weight = RG_DEFAULT_ACL_WEIGHT+1;
				aclRule.filter_fields |= INGRESS_CTAG_VID_BIT;
				if(pentry->mVid > 0)
					aclRule.ingress_ctag_vid = pentry->mVid; //multicast vlan
				else
					aclRule.ingress_ctag_vid = pentry->vid; //multicast vlan
				aclRule.filter_fields |= INGRESS_DMAC_BIT;
				memcpy(&aclRule.ingress_dmac,MCAST_ADDR,MAC_ADDR_LEN);
				memcpy(&aclRule.ingress_dmac_mask,MCAST_MASK,MAC_ADDR_LEN);
				aclRule.action_type = ACL_ACTION_TYPE_QOS;
				aclRule.qos_actions |= ACL_ACTION_ACL_INGRESS_VID_BIT;
				//keep original vlan
				aclRule.action_acl_ingress_vid = pentry->vid; //wan's vlan
				if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0){
					fprintf(fp,"%d\n",aclIdx);
					fprintf(stderr, "add mCast ACL Vlan:%d, index=%d success\n",pentry->mVid, aclIdx);
				}else{
					fprintf(stderr,"rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n", ret);
					fclose(fp);
					return -1;
				}				
			}			
			fpmVid = fopen("/proc/rg/acl_force_mc_cvid_when_rearrange", "w");
			if(fpmVid)
			{
				fprintf(fpmVid, "%d\n",pentry->vid);
				fclose(fpmVid);
			}else
				fprintf(stderr, "open /proc/rg/acl_force_mc_cvid_when_rearrange!\n");
	}
#endif		

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
#ifdef WLAN_SUPPORT
				else{ //wlan
					int phyID;
					phyID = RG_get_wlan_phyPortId(port_idx);
					//fprintf(stderr, "%s-%d phyID:%d, logID=%d\n",__func__,__LINE__,phyID,port_idx);
					rtk_rg_wlanDevBasedCVlanId_get(phyID,dev_idx,&pPvid);
				}
#endif
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
	fclose(fp);	
	return 0;

}

int RTK_RG_ACL_Handle_MLD(MIB_CE_ATM_VC_T *pentry)
{
	unsigned char mode;
	unsigned char mld_snoop_flag=0;
	rtk_rg_aclFilterAndQos_t aclRule;
	int i,aclIdx=0, ret;
	int port_idx=0;
	unsigned short itfGroup;
	unsigned int fwdcpu_vid;
	int dev_idx=0; /*only support master WLAN*/
	FILE *fp = NULL;
	char filename[64] = {0};//check mld snooping is on/off
	char dis_vlan_filter=0;
	mib_get(PROVINCE_DISABLE_MCAST_INGRESS_VLAN_FILTER, (void *)&dis_vlan_filter);
	//AUG_PRT("dis_vlan_filter=%d\n",dis_vlan_filter);	
	sprintf(filename, "%s_%d", RG_ACL_MVLAN_RULES_FILE, pentry->rg_wan_idx);
	if (!(fp = fopen(filename, "a"))) {
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -2;
	}
#if 0	
	mib_get(MIB_MPMODE, (void *)&mode);
	mld_snoop_flag = (((mode&MP_MLD_MASK)==MP_MLD_MASK)?1:0);
//fprintf(stderr, "%s-%d mld_snoop_flag=%d\n",__func__,__LINE__,mld_snoop_flag);

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
			fprintf(stderr, "%s-%d add mCast ACL Vlan:%d, index=%d success\n",__func__,__LINE__,pentry->mVid, aclIdx);
		}else{
			fprintf(stderr,"rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n", ret);
			return -1;
		}
		goto CHECK_V6_SNOOPING;
	}
#endif	
	if(pentry->mVid > 0)
	{
		//multicast ipv6, mld
		if(dis_vlan_filter == 0)
		{
			if(pentry->mVid != pentry->vid)
			{		
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
#ifdef CONFIG_RTL9600_SERIES
				if(pentry->cmode != CHANNEL_MODE_BRIDGE){
					//apollo v6 multicast don't support multicast route
					//we need to transfer it from mcast vid into lan's vid 1
					mib_get(MIB_FWD_CPU_VLAN_ID, (void *)&fwdcpu_vid);
					aclRule.action_acl_ingress_vid = fwdcpu_vid; //lan interface's vlan
				}
				else
#endif			
					aclRule.action_acl_ingress_vid = pentry->vid; //wan interface's vlan
				if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0){
					fprintf(fp,"%d\n",aclIdx);
					fprintf(stderr, "%s-%d add mCast ACL Vlan:%d, index=%d success\n",__func__,__LINE__,pentry->mVid, aclIdx);
				}else{
					fprintf(stderr,"[%s@%d] rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n",__func__,__LINE__, ret);
					fclose(fp);
					return -1;
				}
			}
		}
	}
#ifdef CONFIG_RTL9600_SERIES		
	if(pentry->cmode == CHANNEL_MODE_BRIDGE && pentry->applicationtype == X_CT_SRV_OTHER)
	{
		FILE *fpmVid=NULL;
		fpmVid = fopen("/proc/rg/acl_force_mc_cvid_when_rearrange", "w");
		if(fpmVid)
		{
			fprintf(fpmVid, "%d\n",pentry->vid);
			fclose(fpmVid);
		}else
			fprintf(stderr, "open /proc/rg/acl_force_mc_cvid_when_rearrange!\n");
	}
#endif

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
#ifdef WLAN_SUPPORT
				else{ //wlan
					int phyID;
					phyID = RG_get_wlan_phyPortId(port_idx);
					//fprintf(stderr, "%s-%d phyID:%d, logID=%d\n",__func__,__LINE__,phyID,port_idx);
					rtk_rg_wlanDevBasedCVlanId_get(port_idx-4,dev_idx,&pPvid);
				}
#endif

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
	fclose(fp);		
	return 0;

}

int RTK_RG_Add_MVLAN_ACL(MIB_CE_ATM_VC_T *pEntry)
{
#ifdef CONFIG_IPV6
				if(pEntry->IpProtocol & IPVER_IPV4)
#endif
					RTK_RG_ACL_Handle_IGMP(pEntry);
#ifdef CONFIG_IPV6
				if(pEntry->IpProtocol & IPVER_IPV6)
					RTK_RG_ACL_Handle_MLD(pEntry);
#endif
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
	int wlan_idx=0;
	int dev_idx=0; /*only support master WLAN*/
	unsigned char mldproxyEnable=0;
	unsigned int mldproxyItf=0;
	int setup_ds_bc_flag=0;

	for (i = 0; i < totalEntry; i++)
	{
		if (mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&entry) == 0)
			continue;
#ifdef CONFIG_IPV6
			if(entry.IpProtocol & IPVER_IPV4)
#endif
				RTK_RG_ACL_Handle_IGMP(&entry);
#ifdef CONFIG_IPV6
			if(entry.IpProtocol & IPVER_IPV6)
				RTK_RG_ACL_Handle_MLD(&entry);
#endif
	}
	return 0;
}

int RTK_RG_FlushDsBcFilter_Rules(void)
{
	int i;
	for(i=0;i<128;i++)
		rtk_rg_gponDsBcFilterAndRemarking_del(i);
	return 0;
}
//delete indicated wan index mvlan acl rules
int RTK_RG_FLUSH_MVLAN_ACL(int wan_idx)
{
	char filename[64] = {0};
	FILE *fp = NULL;
	int aclIdx=-1;
	
	sprintf(filename, "%s_%d", RG_ACL_MVLAN_RULES_FILE, wan_idx);
	//AUG_PRT("%s\n",filename);
	if (!(fp = fopen(filename, "r"))) {
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -2;
	}
	while(fscanf(fp, "%d\n", &aclIdx) != EOF)
	{
		fprintf(stderr, "del mvlan index %d\n",aclIdx);
		if(rtk_rg_aclFilterAndQos_del(aclIdx))
			fprintf(stderr, "%s failed! idx = %d\n",__func__, aclIdx);
	}
	fclose(fp);
	unlink(filename);
	return 0;
}
//flush all wan
int RTK_RG_ACL_Flush_mVlan(void)
{

	FILE *fp;
	int aclIdx=-1,i;
	MIB_CE_ATM_VC_T entry;
	int totalEntry = mib_chain_total(MIB_ATM_VC_TBL);
	for (i = 0; i < totalEntry; i++)
	{
		char filename[64] = {0};
		if (mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&entry) == 0)
			continue;
		if(entry.rg_wan_idx > 0)
		{
			sprintf(filename, "%s_%d", RG_ACL_MVLAN_RULES_FILE, entry.rg_wan_idx);
			AUG_PRT("%s\n",filename);
			if (!(fp = fopen(filename, "r"))) {
				fprintf(stderr, "ERROR! %s\n", strerror(errno));
				return -2;
			}
			
			while(fscanf(fp, "%d\n", &aclIdx) != EOF)
			{
				fprintf(stderr, "del mvlan index %d\n",aclIdx);
				if(rtk_rg_aclFilterAndQos_del(aclIdx))
					fprintf(stderr, "%s failed! idx = %d\n",__func__, aclIdx);
			}
			fclose(fp);
			unlink(filename);
		}
	}
	return 0;
}

#endif /*CONFIG_MCAST_VLAN*/

#ifdef CONFIG_SUPPORT_AUTO_DIAG
#ifdef CONFIG_TR142_MODULE
void setup_pppoe_emu_helper(int wan_index, int vid)
{
	rtk_tr142_pppoe_emu_info_t info;
	int fd;

	info.rg_wan_index = wan_index;
	info.vid = vid;

	fd = open(TR142_DEV_FILE, O_WRONLY);
	if(fd >= 0)
	{
		if(ioctl(fd, RTK_TR142_IOCTL_SET_PPPOE_EMU_HELPER, &info) != 0)
		{
			DBPRINT(1, "ERROR: set PPPoE emulator helper failed\n");
		}

		close(fd);
	}
}

void delete_pppoe_emu_helper(int wan_index)
{
	int fd;

	fd = open(TR142_DEV_FILE, O_WRONLY);
	if(fd >= 0)
	{
		if(ioctl(fd, RTK_TR142_IOCTL_DEL_PPPOE_EMU_HELPER, &wan_index) != 0)
		{
			DBPRINT(1, "ERROR: set PPPoE emulator helper failed\n");
		}

		close(fd);
	}
}
#endif

int RG_Add_Simu_Trap_ACL(unsigned char* mac, int* aclIdx)
{
	rtk_rg_aclFilterAndQos_t aclRule;

	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	aclRule.action_type = ACL_ACTION_TYPE_TRAP_TO_PS;
	aclRule.acl_weight = RG_TRAP_ACL_WEIGHT;
	aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	aclRule.filter_fields |= (INGRESS_DMAC_BIT|INGRESS_PORT_BIT);
	aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();
	memcpy(aclRule.ingress_dmac.octet, mac, ETHER_ADDR_LEN);
	aclRule.ingress_dmac_mask.octet[0] = 0xFF;
	aclRule.ingress_dmac_mask.octet[1] = 0xFF;
	aclRule.ingress_dmac_mask.octet[2] = 0xFF;
	aclRule.ingress_dmac_mask.octet[3] = 0xFF;
	aclRule.ingress_dmac_mask.octet[4] = 0xFF;
	aclRule.ingress_dmac_mask.octet[5] = 0xFF;

	if(rtk_rg_aclFilterAndQos_add(&aclRule, aclIdx) == 0)
	{
		//printf("Trap packets with DMAC[0x%02x%02x%02x%02x%02x%02x] to PS.\n", aclRule.ingress_dmac.octet[0], aclRule.ingress_dmac.octet[1],
			//aclRule.ingress_dmac.octet[2], aclRule.ingress_dmac.octet[3], aclRule.ingress_dmac.octet[4], aclRule.ingress_dmac.octet[5]);
	}
	else
	{
		printf("[%s %d]rtk_rg_aclFilterAndQos_add failed!\n", __func__, __LINE__);
		return -1;
	}
	return 0;
}

int RG_Del_Simu_Trap_ACL(int aclIdx)
{
	if(rtk_rg_aclFilterAndQos_del(aclIdx))
	{
		printf("rtk_rg_aclFilterAndQos_del failed! idx = %d\n", aclIdx);
	}
	return 0;
}

int RG_add_simu_wan(MIB_CE_ATM_VC_Tp entry, int mib_vc_idx)
{
	int wanIntfIdx;
	int vcTotal, i, vlan_id;
	char intf_name[10], mbtd;
	rtk_rg_wanIntfConf_t wan_info;
	unsigned char value[6];
	int ret=-1;
	int wanPhyPort=0;
	struct in_addr gw_addr;
	char cmdStr[64];
	int omci_mode=-1;
	int omci_service=-1;
	int omci_bind=-1;

	int pb_group=-1;
	unsigned int pon_mode=0;

	memset(&wan_info,0,sizeof(wan_info));
	memcpy(wan_info.gmac.octet, entry->MacAddr, MAC_ADDR_LEN);
	RG_WAN_CVLAN_DEL(entry->vid);

	wanPhyPort=RG_get_wan_phyPortId();

	if (entry->vlan == 1)
	{
		wan_info.egress_vlan_tag_on=1;
		wan_info.egress_vlan_id=entry->vid;
	}
	else
	{
		wan_info.egress_vlan_tag_on=0;
		mib_get(MIB_UNTAG_WAN_VLAN_ID, (void *)&vlan_id);
		wan_info.egress_vlan_id=vlan_id;
	}

#ifdef CONFIG_RTL9602C_SERIES
	wan_info.port_binding_mask.portmask = RG_get_lan_phyPortMask(entry->itfGroup & 0x3);
#else
	wan_info.port_binding_mask.portmask = RG_get_lan_phyPortMask(entry->itfGroup & 0xf);
#endif
	wan_info.wlan0_dev_binding_mask = (((entry->itfGroup >> ITFGROUP_WLAN0_DEV_BIT) & ITFGROUP_WLAN_MASK) << RG_RET_MBSSID_MASTER_ROOT_INTF);
	if(entry->itfGroup > 0)
		omci_bind = 1;
	else
		omci_bind = 0;

	wan_info.wan_port_idx=wanPhyPort;
	if(entry->ipDhcp == DHCP_CLIENT)
		wan_info.wan_type = RTK_RG_DHCP;
	else
		wan_info.wan_type = RTK_RG_STATIC;

	/*RG: Internet = 0, other=1*/
	if(entry->applicationtype & X_CT_SRV_INTERNET)
	{
		omci_service = 1;
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		wan_info.none_internet = 1;
#else
		wan_info.none_internet = 0;
#endif
	}
	else{
		wan_info.none_internet = 1;
		omci_service = 0;
	}

	if((rtk_rg_wanInterface_add(&wan_info, &wanIntfIdx))!=SUCCESS)
		return -1;
	//0 = PPPoE, 1 = IPoE, 2 = BRIDGE --> omci add cf rule
	switch(entry->cmode)
	{
		case CHANNEL_MODE_IPOE:
			if( (entry->IpProtocol == IPVER_IPV4_IPV6) && entry->napt ==1)
				omci_mode = OMCI_MODE_IPOE_V4NAPT_V6;
			else
				omci_mode = OMCI_MODE_IPOE;
			break;
		case CHANNEL_MODE_PPPOE:
		{
#ifdef CONFIG_RTL9600_SERIES
			//For simulation, ifname should be nas0_0_0/nas0_0_1...
			//But we donot use Mode_PPPOE, so donot care.
			//printf("[%s %d]PPPOE???????????????\n", __func__, __LINE__);
			mib_get(MIB_PON_MODE, (void *)&pon_mode);
			if(pon_mode == GPON_MODE)
			{
				//unsigned char province_trap_pppoe_traffic=0;
				//mib_get(PROVINCE_TRAP_PPPOE_TRAFFIC, (void *)&province_trap_pppoe_traffic);
				//if(!province_trap_pppoe_traffic)
				{
					system("echo 1 > /proc/rg/gpon_pppoe_status");
				}
			}	
#endif
			//system("cat /proc/dump/acl_rg");
			if( (entry->IpProtocol == IPVER_IPV4_IPV6) && entry->napt ==1)
				omci_mode = OMCI_MODE_PPPOE_V4NAPT_V6;
			else
				omci_mode = OMCI_MODE_PPPOE;
		}
			break;
		case CHANNEL_MODE_BRIDGE:
			omci_mode = OMCI_MODE_BRIDGE;
			break;
		default:
			printf("unknow mode %d\n",omci_mode);
			break;
	}
#ifdef CONFIG_GPON_FEATURE
	mib_get(MIB_PON_MODE, (void *)&pon_mode);
	if(pon_mode == GPON_MODE)
	{
		char vlan_based_pri;
		if(entry->vprio)
		{
			vlan_based_pri=(entry->vprio)-1;
		}
		else
		{
			vlan_based_pri=-1;
		}
		//sync omci cf rules.
		/*untag wan, omci egress vlan id = -1*/
		if(entry->vlan == 2)
		{
			wan_info.egress_vlan_id = 4095;
		}
		else
		{
			if(!wan_info.egress_vlan_tag_on)
			{
				wan_info.egress_vlan_id = -1;
			}
		}
#if ! defined(_LINUX_2_6_) && defined(CONFIG_TR142_MODULE)
		char ifname[IFNAMSIZ] = {0};
		ifGetName(PHY_INTF(entry->ifIndex), ifname, sizeof(ifname));
		snprintf(cmdStr, sizeof(cmdStr)-1,"echo %d %s %s %d > %s", wanIntfIdx, ALIASNAME_NAS0, ifname, omci_bind, TR142_WAN_IDX_MAP);
		system(cmdStr);
#endif
		fprintf(stderr, "%s-%d sync waninfo with OMCI!\n",__func__,__LINE__);
		snprintf(cmdStr, sizeof(cmdStr),"echo %d %d %d %d %d %d %d > %s",wanIntfIdx,wan_info.egress_vlan_id,vlan_based_pri,omci_mode,omci_service,omci_bind,1,OMCI_WAN_INFO);
		//fprintf(stderr, "%s\n",cmdStr);
		system(cmdStr);

#ifdef CONFIG_TR142_MODULE
		setup_pppoe_emu_helper(wanIntfIdx, wan_info.egress_vlan_id);
#endif
	}
#endif
	entry->rg_wan_idx = wanIntfIdx;
	mib_chain_update(MIB_SIMU_ATM_VC_TBL, entry, mib_vc_idx);
	// handle dmac to cvid enable
	{
		unsigned char dmac2cvid;
		mib_get(MIB_MAC_DMAC2CVID_DISABLE, (void *)&dmac2cvid);
		if(dmac2cvid == 1)
		{
			//printf("Disable DMAC to CVID !!\n");
			system("echo 1 > /proc/rg/wan_dmac2cvid_force_disabled");
		}
		else
		{
			//printf("Enable DMAC to CVID !!\n");
			system("echo 0 > /proc/rg/wan_dmac2cvid_force_disabled");
		}
	}

	return SUCCESS;
}
#endif

#ifdef CONFIG_RG_BRIDGE_PPP_STATUS
int AddRTK_RG_Bridge_PPPSession_Filter()
{
	int aclIdx;
	rtk_rg_aclFilterAndQos_t aclRule;

	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	aclRule.action_type = ACL_ACTION_TYPE_TRAP;
	aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	aclRule.filter_fields |= (INGRESS_PORT_BIT|INGRESS_ETHERTYPE_BIT|INGRESS_IPV4_TAGIF_BIT|INGRESS_IPV6_TAGIF_BIT);
    aclRule.ingress_port_mask.portmask = RG_get_all_lan_phyPortMask() | RG_get_wan_phyPortMask();
	aclRule.ingress_ethertype = 0x8864;
	aclRule.ingress_ethertype_mask = 0xFFF0;
	aclRule.ingress_ipv4_tagif = 0;
	aclRule.ingress_ipv6_tagif = 0;

	if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0)
	{
		printf("Trap bridge ppp session packets to CPU.\n");
	}
	else
	{
		printf("[%s %d]rtk_rg_aclFilterAndQos_add failed!\n", __func__, __LINE__);
		return -1;
	}
	return 0;
}
#endif

#ifdef MAC_FILTER
int AddRTK_RG_MAC_Filter(MIB_CE_MAC_FILTER_T *MacEntry)
{
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

	if(rtk_rg_macFilter_add(&macFilterEntry, &macfilterIdx) == 0)
		fprintf(fp, "%d\n", macfilterIdx);
	else
		printf("Set rtk_rg_macFilter_add failed! dir = %d\n", MacEntry->dir? MacEntry->dir == 1? "Source": "Destination": "Both");

	fclose(fp);
	return 0;
#if 0
	rtk_rg_aclFilterAndQos_t aclRule;
	rtk_rg_intfInfo_t infinfo;
	int aclIdx, i;
	FILE *fp;

	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));

	if (MacEntry->action == 0)
		aclRule.action_type = ACL_ACTION_TYPE_DROP;
	else if (MacEntry->action == 1)
		aclRule.action_type = ACL_ACTION_TYPE_PERMIT;
	else
	{
		fprintf(stderr, "Wrong mac filter action!\n");
		return -1;
	}

	if (memcmp(MacEntry->srcMac, "\x00\x00\x00\x00\x00\x00", MAC_ADDR_LEN))  // src mac is not empty.
	{
		aclRule.filter_fields |= INGRESS_SMAC_BIT;
		memcpy(&aclRule.ingress_smac, MacEntry->srcMac, MAC_ADDR_LEN);
	}

	if(memcmp(MacEntry->dstMac, "\x00\x00\x00\x00\x00\x00", MAC_ADDR_LEN))  // dst mac is not empty.
	{
		aclRule.filter_fields |= INGRESS_DMAC_BIT;
		memcpy(&aclRule.ingress_dmac, MacEntry->dstMac, MAC_ADDR_LEN);
	}

	if(!(fp = fopen(ACL_MAC_RULES_FILE, "a")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -1;
	}

	for( i = 0; i < MAX_NETIF_SW_TABLE_SIZE; i++ )
	{
		if(rtk_rg_intfInfo_find(&infinfo, &i))
			break;

		if(infinfo.is_wan && infinfo.wan_intf.wan_intf_conf.wan_type == RTK_RG_BRIDGE)
		{
			if(MacEntry->dir == DIR_OUT)
			{
				aclRule.filter_fields |= EGRESS_INTF_BIT;
				aclRule.egress_intf_idx = i;  // Set egress interface to WAN.
			}
			else if(MacEntry->dir == DIR_IN)
			{
				aclRule.filter_fields |= INGRESS_INTF_BIT;
				aclRule.ingress_intf_idx = i;  // Set ingress interface to WAN.
			}
			else
			{
				DBPRINT(1, "Invalid MAC filtering direction!\n");
				return -1;
			}

			if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0)
				fprintf(fp, "%d\n", aclIdx);
			else
				printf("Set rtk_rg_aclFilterAndQos_add failed! dir = %s\n", MacEntry->dir? "Incoming": "Outgoing");
		}
	}

	fclose(fp);
#endif
}

int AddRTK_RG_BG_MAC_Filter(MIB_CE_BRGMAC_T *MacEntry, unsigned char *smac, unsigned char *dmac, unsigned char macFilterMode, int ethertype)
{
#if 0
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

	if(rtk_rg_macFilter_add(&macFilterEntry, &macfilterIdx) == 0)
		fprintf(fp, "%d\n", macfilterIdx);
	else
		printf("Set rtk_rg_macFilter_add failed! dir = %d\n", MacEntry->dir? MacEntry->dir == 1? "Source": "Destination": "Both");

	fclose(fp);
	return 0;
#endif
#if 1
	rtk_rg_aclFilterAndQos_t aclRule;
	rtk_rg_intfInfo_t infinfo;
	int aclIdx, i;
	FILE *fp;
	unsigned int wanPhyPort;
	MIB_CE_ATM_VC_T vc_entry;

	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));

	if (macFilterMode == 0)
		aclRule.action_type = ACL_ACTION_TYPE_DROP;
	else if (macFilterMode == 1)
		aclRule.action_type = ACL_ACTION_TYPE_PERMIT;
	else
	{
		fprintf(stderr, "Wrong mac filter action!\n");
		return -1;
	}

	//if (memcmp(MacEntry->smac, "\x00\x00\x00\x00\x00\x00", MAC_ADDR_LEN))  // src mac is not empty.
	if(strlen(MacEntry->smac))
	{
		aclRule.filter_fields |= INGRESS_SMAC_BIT;
		memcpy(&aclRule.ingress_smac, smac, MAC_ADDR_LEN);
	}

	//if(memcmp(MacEntry->dmac, "\x00\x00\x00\x00\x00\x00", MAC_ADDR_LEN))  // dst mac is not empty.
	if(strlen(MacEntry->dmac))
	{
		aclRule.filter_fields |= INGRESS_DMAC_BIT;
		memcpy(&aclRule.ingress_dmac, dmac, MAC_ADDR_LEN);
	}

	if(ethertype!=0)
	{
		aclRule.filter_fields |= INGRESS_ETHERTYPE_BIT;
		aclRule.ingress_ethertype = ethertype;
	}

	if(!(fp = fopen(RG_MAC_ACL_RULES_FILE, "a")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -1;
	}

	int itfindex=0;
	for(itfindex=0;itfindex<MacEntry->portNum;itfindex++)
	{

		if(getATMVCEntryByIfIndex(MacEntry->ifIndex[itfindex], &vc_entry) == NULL){
			fclose(fp);
			return -1;
		}
		i = vc_entry.rg_wan_idx;

		if(rtk_rg_intfInfo_find(&infinfo, &i))
			break;

		if(infinfo.is_wan && infinfo.wan_intf.wan_intf_conf.wan_type == RTK_RG_BRIDGE)
		{
			if(MacEntry->direction == DIR_OUT || MacEntry->direction == 2)
			{
				if(macFilterMode == 0){
					aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_OR_EGRESS_L34_UP_DROP;
					aclRule.filter_fields |= (EGRESS_INTF_BIT|INGRESS_PORT_BIT);
					aclRule.egress_intf_idx = i;  // Set egress interface to WAN.
					aclRule.ingress_port_mask.portmask = RG_get_all_lan_phyPortMask();
#ifdef WLAN_SUPPORT
					aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN0));
#ifdef WLAN_DUALBAND_CONCURRENT
					aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN1));
#endif
					aclRule.ingress_port_mask.portmask |= (1 << RTK_RG_PORT_CPU);
#endif

					if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0)
						fprintf(fp, "%d\n", aclIdx);
					else
						printf("Set rtk_rg_aclFilterAndQos_add failed! dir = Outgoing\n");
				}
				else
					printf("%s not support permit rule in RG for dir = Outgoing\n", __FUNCTION__);
			}

			if(MacEntry->direction == DIR_IN || MacEntry->direction == 2)
			{
				aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
				aclRule.filter_fields &= ~(EGRESS_INTF_BIT);
				aclRule.filter_fields |= (INGRESS_INTF_BIT|INGRESS_PORT_BIT);
				aclRule.ingress_intf_idx = i;  // Set ingress interface to WAN.

				#if 0
				if(mib_get(MIB_WAN_PHY_PORT , (void *)&wanPhyPort) == 0){
					printf("get MIB_WAN_PHY_PORT failed!!!\n");
					wanPhyPort = RTK_RG_MAC_PORT_PON;
				}
				aclRule.ingress_port_mask.portmask = 1 << wanPhyPort; //wan port
				#endif

				aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();

				if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0)
					fprintf(fp, "%d\n", aclIdx);
				else
					printf("Set rtk_rg_aclFilterAndQos_add failed! dir = Incoming\n");
			}

			if(MacEntry->direction > 2)
			{
				DBPRINT(1, "Invalid MAC filtering direction!\n");
				fclose(fp);
				return -1;
			}

		}
	}

	fclose(fp);
	return 0;
#endif
}

#ifdef MAC_FILTER_BLOCKTIMES_SUPPORT
#include <netinet/ether.h>
unsigned int get_MAC_Filter_BlockTimes(int instnum, const char *macStr)
{
	rtk_rg_naptFilterAndQos_t napt_filter;
	FILE *fp = NULL;
	char line[64];
	struct ether_addr mac;
	int index, naptIdx;
	int ret;
	unsigned int packet_count = 0;
	
	if(ether_aton_r(macStr, &mac) == NULL){
		return 0;
	}
	
	if((fp = fopen(RG_MAC_NAPT_RULES_FILE, "r")))
	{
		while(fgets(line, 64, fp) != NULL)
		{
			sscanf(line, "%d %d\n", &index, &naptIdx);

			if (instnum == index)
			{
				memset(&napt_filter,0,sizeof(napt_filter));
				ret = rtk_rg_naptFilterAndQos_find(&naptIdx, &napt_filter);
				if(ret!=RT_ERR_RG_OK) {
					printf("%s %d rtk_rg_apollo_naptFilterAndQos_find FAIL!", __func__, __LINE__);
					break;
				}
				packet_count += napt_filter.packet_count;
				
				break;
			}
		}
		
		fclose(fp);
	}
#if defined(WLAN_SUPPORT) && defined(CONFIG_YUEME)
	packet_count += get_wlan_MAC_ACL_BlockTimes(mac.ether_addr_octet);
#endif

	return packet_count;
}
#endif

#ifdef MAC_FILTER_BLOCKTIMES_SUPPORT
int AddRTK_RG_RT_MAC_Filter(unsigned char *smac, int mode, int instnum)
#else
int AddRTK_RG_RT_MAC_Filter(unsigned char *smac, int mode)
#endif
{
#if defined(CONFIG_CMCC) || defined(CONFIG_CU) //Need send "LAN_DEV_REFUSED" to OSGI bundle , so need trap mac filter to PS.
	int ret=0;
	MAC_FILTER_WHITELIST_WAY_T whitelist_way = WHITELIST_WAY;
	if(mode == 0){//add black list

		rtk_rg_aclFilterAndQos_t aclRule;
		int aclIdx;
		char syscmd[64];
		FILE *fp;
		if(!(fp = fopen(RG_MAC_RULES_FILE, "a")))
		{
			fprintf(stderr, "ERROR! %s\n", strerror(errno));
			return -1;
		}

		memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
		aclRule.action_type = ACL_ACTION_TYPE_TRAP_TO_PS;
		aclRule.acl_weight = RG_DEFAULT_ACL_WEIGHT;
		aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
		aclRule.filter_fields |= (INGRESS_SMAC_BIT|INGRESS_PORT_BIT);
		aclRule.ingress_port_mask.portmask = RG_get_all_lan_phyPortMask();
#ifdef WLAN_SUPPORT
		aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN0));
#ifdef WLAN_DUALBAND_CONCURRENT
		aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN1));
#endif
#endif		
		memcpy(&aclRule.ingress_smac, smac, MAC_ADDR_LEN);
		if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0)
		{
		/*
			printf("[%s:%d] Trap packets with SMAC[0x%02x%02x%02x%02x%02x%02x] to PS. aclIdx=%d \n", 
						__FUNCTION__, __LINE__, aclRule.ingress_smac.octet[0], aclRule.ingress_smac.octet[1],
						aclRule.ingress_smac.octet[2], aclRule.ingress_smac.octet[3], aclRule.ingress_smac.octet[4], 
						aclRule.ingress_smac.octet[5], aclIdx);*/
			fprintf(fp, "%d\n", aclIdx);
			/* add  the entry to netfilter hook */
			sprintf(syscmd, "echo 0 %d %02x:%02x:%02x:%02x:%02x:%02x > %s", 
				aclIdx, smac[0], smac[1], smac[2], smac[3], smac[4], smac[5], RG_ACL_CMCC_MAC_FILTER_FILE);
			system(syscmd);
		}
		else
		{
			printf("[%s %d]rtk_rg_aclFilterAndQos_add failed!\n", __func__, __LINE__);
			return -1;
		}
		fclose(fp);
	}else{ //mode  ==1, add white list
		if(whitelist_way==WHITELIST_USING_LUT_TBL)
			Add_RTK_RG_MACTbl_MAC_Filters_Whitelist(smac);
		else
			Add_RTK_RG_ACL_MAC_Filters_Whitelist(smac);
	}
	return 0;
#else

#ifdef MAC_FILTER_BLOCKTIMES_SUPPORT
	int filterIdx;
	rtk_rg_naptFilterAndQos_t naptFilter;
#else
	int macfilterIdx;
	rtk_rg_macFilterEntry_t macFilterEntry;
#endif
	FILE *fp;
	MAC_FILTER_WHITELIST_WAY_T whitelist_way = WHITELIST_WAY;

	if(mode == 0){//add black list
#ifdef MAC_FILTER_BLOCKTIMES_SUPPORT
		memset(&naptFilter, 0, sizeof(naptFilter));
		naptFilter.direction = RTK_RG_NAPT_FILTER_OUTBOUND;
		naptFilter.filter_fields = INGRESS_SMAC;
		memcpy(&naptFilter.ingress_smac, smac, MAC_ADDR_LEN);
		naptFilter.action_fields = NAPT_DROP_BIT | NAPT_SW_PACKET_COUNT;
		naptFilter.ruleType = RTK_RG_NAPT_FILTER_PERSIST;

		if(!(fp = fopen(RG_MAC_NAPT_RULES_FILE, "a")))
		{
			fprintf(stderr, "ERROR! %s\n", strerror(errno));
			return -1;
		}
		
		if(rtk_rg_naptFilterAndQos_add( &filterIdx, &naptFilter) == 0)
			fprintf(fp, "%d %d\n", instnum, filterIdx);
		else
			printf("[%s@%d] rtk_rg_naptFilterAndQos_add QoS rule failed!\n",__func__,__LINE__);

		fclose(fp);
#else
		memset(&macFilterEntry, 0, sizeof(rtk_rg_macFilterEntry_t));
		memcpy(&macFilterEntry.mac, smac, MAC_ADDR_LEN);
		macFilterEntry.direct = RTK_RG_MACFILTER_FILTER_SRC_MAC_ONLY;
		//printf("add black list:%x %x %x %x %x %x\n", macFilterEntry.mac.octet[0], macFilterEntry.mac.octet[1], macFilterEntry.mac.octet[2]
		//	, macFilterEntry.mac.octet[3], macFilterEntry.mac.octet[4], macFilterEntry.mac.octet[5]);

		if(!(fp = fopen(RG_MAC_RULES_FILE, "a")))
		{
			fprintf(stderr, "ERROR! %s\n", strerror(errno));
			return -1;
		}

		if(rtk_rg_macFilter_add(&macFilterEntry, &macfilterIdx) == 0)
			fprintf(fp, "%d\n", macfilterIdx);
		else
			printf("Set rtk_rg_macFilter_add failed! dir = Source\n");

		fclose(fp);
#endif
	}
	else{ //mode  ==1, add white list
		//printf("add white list %02x-%02x-%02x-%02x-%02x-%02x\n"
		//	,smac[0],smac[1],smac[2],smac[3],smac[4],smac[5]);
		if(whitelist_way==WHITELIST_USING_LUT_TBL)
			Add_RTK_RG_MACTbl_MAC_Filters_Whitelist(smac);
		else
			Add_RTK_RG_ACL_MAC_Filters_Whitelist(smac);
	}
	return 0;
#endif
}

int RTK_RG_Dynamic_MAC_Entry_flush(void)
{
	rtk_rg_macEntry_t macEntry;
	int valid_idx, ret, cnt=0;;

	for(valid_idx=0 ; valid_idx<MAX_LUT_HW_TABLE_SIZE ; valid_idx++) {
		ret=rtk_rg_macEntry_find(&macEntry, &valid_idx);
		if(!ret) {
			if(!macEntry.static_entry) {				
				printf("%s %d: %d MAC=%02X:%02X:%02X:%02X:%02X:%02X !\n", __func__, __LINE__,valid_idx, macEntry.mac.octet[0],macEntry.mac.octet[1],macEntry.mac.octet[2],macEntry.mac.octet[3],macEntry.mac.octet[4],macEntry.mac.octet[5]);
				rtk_rg_macEntry_del(valid_idx);
				cnt++;
			}
		}
	}
	AUG_PRT("%s %d: %d MAC entries deleted !\n", __func__, __LINE__, cnt);
	return 0;
}

int RTK_RG_ACL_MAC_Filter_Default_Policy(int out_policy)
{
	unsigned char ipv4_ip[IP_ADDR_LEN] = {0}, ipv6_addr[64] = {0};
	unsigned char ipv6_addr_n[IP6_ADDR_LEN]={0};
	rtk_rg_aclFilterAndQos_t aclRule;
	int aclIdx, i;
	FILE *fp;
	unsigned char macFilterwhitelistLocalAllow = 1; 

	
	mib_get(PROVINCE_MACFILTER_WHITELIST_LOCAL_ALLOW, &macFilterwhitelistLocalAllow);
	if(!(fp = fopen(RG_MAC_ACL_RULES_FILE, "a")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -2;
	}
	
	if( out_policy == 0 )
	{
		if(macFilterwhitelistLocalAllow)
		{
			// Permit all LAN side ingress packets which DA is our router's LAN MAC & DIP=192.168.1.1
			memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
			aclRule.action_type = ACL_ACTION_TYPE_PERMIT;
			aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
			aclRule.filter_fields = INGRESS_IPV4_DIP_RANGE_BIT|INGRESS_DMAC_BIT|INGRESS_PORT_BIT;
			aclRule.ingress_port_mask.portmask = RG_get_all_lan_phyPortMask();
#ifdef WLAN_SUPPORT
			aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN0));
#ifdef WLAN_DUALBAND_CONCURRENT
			aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN1));
#endif
			//aclRule.ingress_port_mask.portmask |= (1 << RTK_RG_PORT_CPU);
#endif
			mib_get(MIB_ADSL_LAN_IP, ipv4_ip);
			aclRule.ingress_dest_ipv4_addr_start = aclRule.ingress_dest_ipv4_addr_end = ntohl(*((in_addr_t *)ipv4_ip));
			aclRule.acl_weight = RG_FIREWALL_ACL_WEIGHT;
			mib_get(MIB_ELAN_MAC_ADDR, (void *)&aclRule.ingress_dmac);
			if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0)
				fprintf(fp, "%d\n", aclIdx);
			else
				printf("rtk_rg_aclFilterAndQos_add mac default policy permit1 failed!\n");

			// Permit all LAN side ingress packets which DA is our router's LAN MAC & DIP=fe80::1
			memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
			aclRule.action_type = ACL_ACTION_TYPE_PERMIT;
			aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
			aclRule.filter_fields = INGRESS_IPV6_DIP_RANGE_BIT|INGRESS_DMAC_BIT|INGRESS_PORT_BIT;
			aclRule.ingress_port_mask.portmask = RG_get_all_lan_phyPortMask();
#ifdef WLAN_SUPPORT
			aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN0));
#ifdef WLAN_DUALBAND_CONCURRENT
			aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN1));
#endif
			//aclRule.ingress_port_mask.portmask |= (1 << RTK_RG_PORT_CPU);
#endif
			mib_get(MIB_IPV6_LAN_IP_ADDR, (void *)ipv6_addr);
			inet_pton(PF_INET6, ipv6_addr, &ipv6_addr_n);
			memcpy(aclRule.ingress_dest_ipv6_addr_start, ipv6_addr_n, IPV6_ADDR_LEN);
			memcpy(aclRule.ingress_dest_ipv6_addr_end, ipv6_addr_n, IPV6_ADDR_LEN);
			aclRule.acl_weight = RG_FIREWALL_ACL_WEIGHT;
			mib_get(MIB_ELAN_MAC_ADDR, (void *)&aclRule.ingress_dmac);
			if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0)
				fprintf(fp, "%d\n", aclIdx);
			else
				printf("rtk_rg_aclFilterAndQos_add mac default policy permit1 failed!\n");

			// Permit all LAN side ingress packets which DA is broadcast
			memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
			aclRule.action_type = ACL_ACTION_TYPE_PERMIT;
			aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
			aclRule.filter_fields = INGRESS_DMAC_BIT|INGRESS_PORT_BIT;
			aclRule.ingress_port_mask.portmask = RG_get_all_lan_phyPortMask();
#ifdef WLAN_SUPPORT
			aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN0));
#ifdef WLAN_DUALBAND_CONCURRENT
			aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN1));
#endif
			//aclRule.ingress_port_mask.portmask |= (1 << RTK_RG_PORT_CPU);
#endif
			aclRule.acl_weight = RG_FIREWALL_ACL_WEIGHT;
			for(i=0 ; i<MAC_ADDR_LEN ; i++)
			{
				aclRule.ingress_dmac.octet[i]=0xff;
			}
			if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0)
				fprintf(fp, "%d\n", aclIdx);
			else
				printf("rtk_rg_aclFilterAndQos_add mac default policy permit2 failed!\n");
		}

		// Drop all LAN side ingress packets which if not match above ACL rule
		memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
		aclRule.action_type = ACL_ACTION_TYPE_DROP;
		aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
		aclRule.filter_fields = INGRESS_PORT_BIT;
		aclRule.ingress_port_mask.portmask = RG_get_all_lan_phyPortMask();
#ifdef WLAN_SUPPORT
		aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN0));
#ifdef WLAN_DUALBAND_CONCURRENT
		aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN1));
#endif
		//aclRule.ingress_port_mask.portmask |= (1 << RTK_RG_PORT_CPU);
#endif

		aclRule.acl_weight = RG_FIREWALL_ACL_WEIGHT;
		if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0)
			fprintf(fp, "%d\n", aclIdx);
		else
			printf("rtk_rg_aclFilterAndQos_add mac default policy drop failed!\n");
	}

	fclose(fp);
	return 0;
}

int RTK_RG_MAC_Filter_Default_Policy(int out_policy, int in_policy)
{
	rtk_rg_aclFilterAndQos_t aclRule;
	rtk_rg_intfInfo_t infinfo;
	int aclIdx, i;
	FILE *fp;
	unsigned int wanPhyPort;
	int ret;

	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));

	if(!(fp = fopen(RG_MAC_ACL_RULES_FILE, "a")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -1;
	}

	if( out_policy == 0 || in_policy == 0 )
	{
		aclRule.action_type = ACL_ACTION_TYPE_DROP;

		for( i = 0; i < MAX_NETIF_SW_TABLE_SIZE; i++ )
		{
			memset(&infinfo, 0, sizeof(rtk_rg_intfInfo_t));
			if(rtk_rg_intfInfo_find(&infinfo, &i))
				break;

			DBPRINT(0, "i=%d; is_wan=%d; intf_name=%s\n", i, infinfo.is_wan, infinfo.intf_name);
			if(infinfo.is_wan && infinfo.wan_intf.wan_intf_conf.wan_type == RTK_RG_BRIDGE)
			{

				if(out_policy == 0)
				{
					aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_OR_EGRESS_L34_UP_DROP;
					aclRule.filter_fields = (EGRESS_INTF_BIT|INGRESS_PORT_BIT);
					aclRule.egress_intf_idx = i;  // Set egress interface to WAN.
					aclRule.ingress_port_mask.portmask = RG_get_all_lan_phyPortMask();
#ifdef WLAN_SUPPORT
					aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN0));
#ifdef WLAN_DUALBAND_CONCURRENT
					aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN1));
#endif
					aclRule.ingress_port_mask.portmask |= (1 << RTK_RG_PORT_CPU);
#endif

					ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx);

					if(ret == 0)
						fprintf(fp, "%d\n", aclIdx);
					else
						printf("<%s>: Set rtk_rg_aclFilterAndQos_add failed! fault code = %d (out policy=%d)\n", __func__, ret, out_policy);
				}

				if(in_policy == 0)
				{
					aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
					aclRule.filter_fields = (INGRESS_INTF_BIT|INGRESS_PORT_BIT);
					aclRule.ingress_intf_idx = i;  // Set ingress interface to WAN.

					#if 0
					if(mib_get(MIB_WAN_PHY_PORT , (void *)&wanPhyPort) == 0){
						printf("get MIB_WAN_PHY_PORT failed!!!\n");
						wanPhyPort = RTK_RG_MAC_PORT_PON;
					}
					aclRule.ingress_port_mask.portmask = 1 << wanPhyPort; //wan port
					#endif

					aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();

					ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx);

					if(ret == 0)
						fprintf(fp, "%d\n", aclIdx);
					else
						printf("<%s>: Set rtk_rg_aclFilterAndQos_add failed! fault code = %d (in policy=%d)\n", __func__, ret, in_policy);
				}
			}
		}
	}

	fclose(fp);
	return 0;
}

int Flush_RTK_RG_ACL_MAC_Filters(void)
{
	FILE *fp;
	int aclIdx;

	if(!(fp = fopen(RG_MAC_ACL_RULES_FILE, "r")))
		return -2;

	while(fscanf(fp, "%d\n", &aclIdx) != EOF)
	{
		if(rtk_rg_aclFilterAndQos_del(aclIdx))
			DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", aclIdx);
	}

	fclose(fp);
	unlink(RG_MAC_ACL_RULES_FILE);
	return 0;
}

int Flush_RTK_RG_MACTbl_MAC_Filters(void)
{
	rtk_rg_macFilterWhiteList_t mac_filter_whitelist_info;
	int ret;
	
	// Flush whitelist if exist
	mac_filter_whitelist_info.del_flag = MACF_DEL_ALL;
	ret=rtk_rg_mac_filter_whitelist_del(&mac_filter_whitelist_info);

	if(ret)		
		printf("rtk_rg_mac_filter_whitelist_del MACF_DEL_ALL failed!\n");

	return ret;
}

int FlushRTK_RG_MAC_Filters(void)
{
	FILE *fp;
	int mac_idx;
	MAC_FILTER_WHITELIST_WAY_T whitelist_way = WHITELIST_WAY;
	char syscmd[64];

#ifdef MAC_FILTER_SRC_WHITELIST
	if(whitelist_way==WHITELIST_USING_LUT_TBL)
		Flush_RTK_RG_MACTbl_MAC_Filters();
	else
		Flush_RTK_RG_ACL_MAC_Filters();
#endif

#ifdef MAC_FILTER_BLOCKTIMES_SUPPORT
	if(!(fp = fopen(RG_MAC_NAPT_RULES_FILE, "r")))
		return -2;

	while(fscanf(fp, "%*d %d\n", &mac_idx) != EOF)
	{
		if(rtk_rg_naptFilterAndQos_del(mac_idx))
			DBPRINT(1, "rtk_rg_naptFilterAndQos_del failed! idx = %d\n", mac_idx);
	}

	fclose(fp);
	unlink(RG_MAC_NAPT_RULES_FILE);
#else
	if(!(fp = fopen(RG_MAC_RULES_FILE, "r")))
		return -2;

	while(fscanf(fp, "%d\n", &mac_idx) != EOF)
	{
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		if(rtk_rg_aclFilterAndQos_del(mac_idx))
			DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", mac_idx);
		/* delete the entry in netfilter hook */
		sprintf(syscmd, "echo 2 %d > %s", mac_idx, RG_ACL_CMCC_MAC_FILTER_FILE);
		system(syscmd);			
#else
		if(rtk_rg_macFilter_del(mac_idx))
			DBPRINT(1, "rtk_rg_macFilter_del failed! idx = %d\n", mac_idx);
#endif
	}

	fclose(fp);
	unlink(RG_MAC_RULES_FILE);
#endif
	return 0;
}

int Add_RTK_RG_ACL_MAC_Filters_Whitelist(unsigned char *smac)
{
	rtk_rg_aclFilterAndQos_t aclRule;
	rtk_rg_intfInfo_t infinfo;
	int aclIdx, i;
	FILE *fp;

	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	aclRule.acl_weight = RG_FIREWALL_ACL_WEIGHT;
	aclRule.filter_fields |= INGRESS_PORT_BIT;
	aclRule.ingress_port_mask.portmask = RG_get_all_lan_phyPortMask();
#ifdef WLAN_SUPPORT
	aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN0));
#ifdef WLAN_DUALBAND_CONCURRENT
	aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN1));
#endif
	//aclRule.ingress_port_mask.portmask |= (1 << RTK_RG_PORT_CPU);
#endif

	aclRule.action_type = ACL_ACTION_TYPE_PERMIT;
	if (memcmp(smac, "\x00\x00\x00\x00\x00\x00", MAC_ADDR_LEN))  // src mac is not empty.
	{
		aclRule.filter_fields |= INGRESS_SMAC_BIT;
		memcpy(&aclRule.ingress_smac, smac, MAC_ADDR_LEN);
	}	
	if(!(fp = fopen(RG_MAC_ACL_RULES_FILE, "a")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -1;
	}
	if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0){
		fprintf(fp, "%d\n", aclIdx);
	}
	else
		printf("Set rtk_rg_aclFilterAndQos_add failed!\n");
	
	fclose(fp);
	return 0;
}

int Add_RTK_RG_MACTbl_MAC_Filters_Whitelist(unsigned char *smac)
{
	rtk_rg_macFilterWhiteList_t mac_filter_whitelist_info;
	int ret;

	memcpy(&mac_filter_whitelist_info.mac, smac, MAC_ADDR_LEN);
	ret=rtk_rg_mac_filter_whitelist_add(&mac_filter_whitelist_info);

	if(ret)
		printf("rtk_rg_mac_filter_whitelist_add fail!\n");

	return ret;
}
#endif // MAC_FILTER

#ifdef _PRMT_X_CMCC_LANINTERFACES_
const char RG_L2FILTER_RULES_FILE[] = "/var/rg_l2filter_rules_idx";

int AddRTK_RG_l2filter_rule(int idx, MIB_CE_L2FILTER_T *pEntry)
{
	rtk_rg_aclFilterAndQos_t acl;
	rtk_rg_intfInfo_t infinfo;
	int aclIdx, type;
	FILE *fp;
	int is_mac_set = 0;

	memset(&acl, 0, sizeof(rtk_rg_aclFilterAndQos_t));

	acl.action_type = ACL_ACTION_TYPE_DROP;
	acl.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	if(idx < CONFIG_LAN_PORT_NUM)
	{
		//Ethernet LAN port
		acl.filter_fields |= INGRESS_PORT_BIT;
		acl.ingress_port_mask.portmask = RG_get_lan_phyPortMask(1 << idx);
		
		if (memcmp(pEntry->src_mac, "\x00\x00\x00\x00\x00\x00", MAC_ADDR_LEN))  // src mac is not empty.
		{
			acl.filter_fields |= INGRESS_SMAC_BIT;
			memcpy(&acl.ingress_smac, pEntry->src_mac, MAC_ADDR_LEN);
			is_mac_set = 1;
		}
		
		if(memcmp(pEntry->dst_mac, "\x00\x00\x00\x00\x00\x00", MAC_ADDR_LEN))	// dst mac is not empty.
		{
			acl.filter_fields |= INGRESS_DMAC_BIT;
			memcpy(&acl.ingress_dmac, pEntry->dst_mac, MAC_ADDR_LEN);
			is_mac_set = 1;
		}
	}
	else if(idx >= CONFIG_LAN_PORT_NUM && idx < CONFIG_LAN_PORT_NUM + WLAN_MBSSID_NUM + 1)
	{
		//wlan0
		int wlan_port = idx - CONFIG_LAN_PORT_NUM;
		acl.filter_fields |= INGRESS_WLANDEV_BIT;
		acl.ingress_wlanDevMask = (1 << wlan_port);
	}
	else if(idx >= CONFIG_LAN_PORT_NUM && idx < CONFIG_LAN_PORT_NUM + 2*(WLAN_MBSSID_NUM + 1))
	{
		//wlan1
		int wlan_port = idx - CONFIG_LAN_PORT_NUM - WLAN_MBSSID_NUM - 1;
		acl.filter_fields |= INGRESS_WLANDEV_BIT;
		acl.ingress_wlanDevMask = (1 << wlan_port) << 13;
	}
	else
	{
		fprintf(stderr, "<%:%d> idx out of range. idx=%d\n", idx);
		return -1;	//error
	}

	if(!(fp = fopen(RG_L2FILTER_RULES_FILE, "a")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -1;
	}

	for( type = 1 ; type < L2FILTER_ETH_END ; type <<= 1 )
	{
		if((pEntry->eth_type & type) == 0)
			continue;

		acl.filter_fields |= INGRESS_ETHERTYPE_BIT;
		switch(type)
		{
		case L2FILTER_ETH_IPV4OE:
			acl.ingress_ethertype = 0x0800;
			break;
		case L2FILTER_ETH_PPPOE:
			acl.ingress_ethertype = 0x8863;	//Do we need to add 0x8864?
			break;
		case L2FILTER_ETH_ARP:
			acl.ingress_ethertype = 0x0806;
			break;
		case L2FILTER_ETH_IPV6OE:
			acl.ingress_ethertype = 0x86dd;
			break;
		default:
			fprintf(stderr, "<%s:%d> Unknow eth_type: %x", __func__, __LINE__, type);
			break;
		}

		if(rtk_rg_aclFilterAndQos_add(&acl, &aclIdx) == 0)
			fprintf(fp, "%d\n", aclIdx);
		else
			printf("Set rtk_rg_aclFilterAndQos_add failed! idx= %d, type = %d\n", idx, type);
	}

	if(is_mac_set && pEntry->eth_type == L2FILTER_ETH_NONE)
	{
		// Only mac is set
		if(rtk_rg_aclFilterAndQos_add(&acl, &aclIdx) == 0)
			fprintf(fp, "%d\n", aclIdx);
		else
			printf("Set rtk_rg_aclFilterAndQos_add failed! type = %d\n", type);
	}

	fclose(fp);
	return 0;
}

int FlushRTK_RG_l2filter_rules()
{
	FILE *fp;
	int aclIdx;

	if(!(fp = fopen(RG_L2FILTER_RULES_FILE, "r")))
		return -2;

	while(fscanf(fp, "%d\n", &aclIdx) != EOF)
	{
		if(rtk_rg_aclFilterAndQos_del(aclIdx))
			DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", aclIdx);
	}

	fclose(fp);
	unlink(RG_L2FILTER_RULES_FILE);
	return 0;
}

int RG_setup_mac_limit(void)
{
	MIB_CE_ELAN_CONF_T entry;
	int i, total = mib_chain_total(MIB_ELAN_CONF_TBL);
	rtk_rg_port_idx_t port;
	rtk_rg_saLearningLimitInfo_t info;
#if defined(CONFIG_USER_LAN_PORT_AS_ETH_WAN)
	int ethPhyPortId = -1;
	mib_get(MIB_ETH_WAN_PORT_PHY_INDEX, &ethPhyPortId);
#endif

	for(i = 0 ; i < CONFIG_LAN_PORT_NUM ; i++)
	{
		if(mib_chain_get(MIB_ELAN_CONF_TBL, i, &entry) == 0)
			continue;

		port = RG_get_lan_phyPortId(i);
		if(port == -1)
		{
			fprintf(stderr, "<%s:%d> RG_get_lan_phyPortId failed when i=%d\n", __func__, __LINE__, i);
			continue;
		}

#if defined(CONFIG_USER_LAN_PORT_AS_ETH_WAN)
		if (port == ethPhyPortId)
			continue;
#endif

		if(entry.mac_limit == 0)
		{
			info.learningLimitNumber = -1;
			info.action = SA_LEARN_EXCEED_ACTION_DROP;
		}
		else
		{
			info.learningLimitNumber = entry.mac_limit;
			info.action = SA_LEARN_EXCEED_ACTION_DROP;
		}

		if(rtk_rg_softwareSourceAddrLearningLimit_set(info, port) != RT_ERR_RG_OK)
			fprintf(stderr, "<%s:%d> rtk_rg_softwareSourceAddrLearningLimit_set failed when i=%d\n", __func__, __LINE__, i);
	}

	return 0;
}
#endif	//_PRMT_X_CMCC_LANINTERFACES_


#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
int AddRTK_RG_ACL_IPPort_Filter(MIB_CE_IP_PORT_FILTER_T *ipEntry, unsigned char in_action, unsigned char out_action)
#else
int AddRTK_RG_ACL_IPPort_Filter(MIB_CE_IP_PORT_FILTER_T *ipEntry)
#endif
{
	rtk_rg_aclFilterAndQos_t aclRule;
	rtk_rg_intfInfo_t infinfo;
	int aclIdx, i, udp_tcp_rule=0;
	ipaddr_t mask;
	FILE *fp;

	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	aclRule.acl_weight = RG_FIREWALL_ACL_WEIGHT;

#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	if ((in_action == 1 && ipEntry->dir == DIR_IN) || (out_action == 1 && ipEntry->dir == DIR_OUT))
		aclRule.action_type = ACL_ACTION_TYPE_DROP;
	else
		aclRule.action_type = ACL_ACTION_TYPE_PERMIT;
#else
	if (ipEntry->action == 0)
		aclRule.action_type = ACL_ACTION_TYPE_DROP;
	else if (ipEntry->action == 1)
		aclRule.action_type = ACL_ACTION_TYPE_PERMIT;
	else
	{
		fprintf(stderr, "Wrong IP/Port filter action!\n");
		return -1;
	}
#endif

	// Source port
	if (ipEntry->srcPortFrom != 0)
	{
		aclRule.filter_fields |= INGRESS_L4_SPORT_RANGE_BIT;
		if (ipEntry->srcPortTo == 0)
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
		if(ipEntry->dstPortTo == 0)
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
		aclRule.filter_fields |= INGRESS_IPV4_TAGIF_BIT;
		aclRule.ingress_ipv4_tagif = 1;

		if(ipEntry->smaskbit == 0)
		{
			aclRule.ingress_src_ipv4_addr_start = ntohl(*((in_addr_t *)ipEntry->srcIp));
			if(memcmp(ipEntry->srcIp2, "\x00\x00\x00\x00", IP_ADDR_LEN) != 0)
				aclRule.ingress_src_ipv4_addr_end = ntohl(*((in_addr_t *)ipEntry->srcIp2));
			else
				aclRule.ingress_src_ipv4_addr_end = ntohl(*((in_addr_t *)ipEntry->srcIp));
		}
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
		{
			aclRule.ingress_dest_ipv4_addr_start = ntohl(*((in_addr_t *)ipEntry->dstIp));
			if(memcmp(ipEntry->dstIp2, "\x00\x00\x00\x00", IP_ADDR_LEN) != 0)
				aclRule.ingress_dest_ipv4_addr_end = ntohl(*((in_addr_t *)ipEntry->dstIp2));
			else
				aclRule.ingress_dest_ipv4_addr_end = ntohl(*((in_addr_t *)ipEntry->dstIp));
		}
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
		else if(ipEntry->protoType == PROTO_UDPTCP){
			aclRule.filter_fields |= INGRESS_L4_UDP_BIT; //add udp for udp/tcp protocol
			udp_tcp_rule = 1;
		}
		else
			return -1;
	}

	if(!(fp = fopen(RG_ACL_RULES_FILE, "a")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -2;
	}

add_udp_tcp:
	if(udp_tcp_rule==2){
		aclRule.filter_fields &= ~(INGRESS_L4_UDP_BIT);
		aclRule.filter_fields |= INGRESS_L4_TCP_BIT; //add tcp for udp/tcp protocol
	}
	if(ipEntry->dir == DIR_OUT)
	{
		aclRule.filter_fields |= INGRESS_PORT_BIT;
		aclRule.ingress_port_mask.portmask = RG_get_all_lan_phyPortMask();
#ifdef WLAN_SUPPORT
		aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN0));
#ifdef WLAN_DUALBAND_CONCURRENT
		aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN1));
#endif
		aclRule.ingress_port_mask.portmask |= (1 << RTK_RG_PORT_CPU);
#endif

		if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0)
			fprintf(fp, "%d\n", aclIdx);
		else
			printf("rtk_rg_aclFilterAndQos_add ingress dmac failed!\n");
	}
	else if(ipEntry->dir == DIR_IN)
	{
		int wanPhyPort;
		aclRule.filter_fields |= INGRESS_PORT_BIT;

		aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();

		if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0)
			fprintf(fp, "%d\n", aclIdx);
		else
			printf("rtk_rg_aclFilterAndQos_add physic port failed!\n");
	}
	else
	{
		DBPRINT(1, "Invalid filtering direction!\n");
		fclose(fp);
		return -1;
	}
	if(udp_tcp_rule==1){
		udp_tcp_rule = 2;
		goto add_udp_tcp;
	}

	fclose(fp);
	return 0;
}

int RTK_RG_ACL_IPPort_Filter_Default_Policy(int out_policy, int in_policy)
{
	rtk_rg_aclFilterAndQos_t aclRule;
	int aclIdx, ret;
	FILE *fp;
	int wanPhyPort;
	int lanIdx;

	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));

	if(!(fp = fopen(RG_ACL_RULES_FILE, "a")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -2;
	}

	if( out_policy == 0 )
	{
		aclRule.action_type = ACL_ACTION_TYPE_DROP;
		aclRule.filter_fields = INGRESS_DMAC_BIT|INGRESS_PORT_BIT;
		aclRule.ingress_port_mask.portmask = RG_get_all_lan_phyPortMask();
#ifdef WLAN_SUPPORT
		aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN0));
#ifdef WLAN_DUALBAND_CONCURRENT
		aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN1));
#endif
		aclRule.ingress_port_mask.portmask |= (1 << RTK_RG_PORT_CPU);
#endif
		//aclRule.acl_weight = RG_FIREWALL_ACL_WEIGHT;
		aclRule.acl_weight = RG_TRAP_ACL_WEIGHT;
		aclRule.filter_fields |= INGRESS_IPV4_TAGIF_BIT;
		aclRule.ingress_ipv4_tagif = 1;

		mib_get(MIB_ELAN_MAC_ADDR, (void *)&aclRule.ingress_dmac);

		if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0)
			fprintf(fp, "%d\n", aclIdx);
		else
			printf("rtk_rg_aclFilterAndQos_add physic port failed!\n");
	}

	if( in_policy == 0 ) //WAN -> LAN
	{
		rtk_rg_intfInfo_t infinfo;
		int i;

		memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));

		aclRule.action_type = ACL_ACTION_TYPE_DROP;
		aclRule.filter_fields = (INGRESS_INTF_BIT | INGRESS_PORT_BIT);

#if 0
		if(mib_get(MIB_WAN_PHY_PORT , (void *)&wanPhyPort) == 0)
		{
			printf("Get MIB_WAN_PHY_PORT failed!!!\n");
			wanPhyPort = RTK_RG_MAC_PORT3; //for 0371 default
		}
#endif
		wanPhyPort=RG_get_wan_phyPortId();

		aclRule.ingress_port_mask.portmask = 1 << wanPhyPort;
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		MIB_CE_ATM_VC_T entryVC;
		int totalVC_entry;
		totalVC_entry = mib_chain_total(MIB_ATM_VC_TBL);
		for(i=0; i<totalVC_entry; i++){
			if(mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&entryVC) == 0)
				continue;
			if(entryVC.enable == 0)
				continue;
		
			if((entryVC.applicationtype & (X_CT_SRV_INTERNET|X_CT_SRV_SPECIAL_SERVICE_ALL)) && entryVC.cmode != CHANNEL_MODE_BRIDGE)
			{
				//Only add internet routing WAN
				aclRule.ingress_intf_idx = entryVC.rg_wan_idx;
				if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0)
					fprintf(fp, "%d\n", aclIdx);
				else
					printf("rtk_rg_aclFilterAndQos_add physic port failed!\n");
			}
		}
#else
		for( i = 0; i < MAX_NETIF_SW_TABLE_SIZE; i++ )
		{
			memset(&infinfo, 0, sizeof(rtk_rg_intfInfo_t));
			if(rtk_rg_intfInfo_find(&infinfo, &i))
				break;

			DBPRINT(0, "i=%d; is_wan=%d; intf_name=%s\n", i, infinfo.is_wan, infinfo.intf_name);
			if(infinfo.is_wan && infinfo.wan_intf.wan_intf_conf.none_internet == 0 && infinfo.wan_intf.wan_intf_conf.wan_type != RTK_RG_BRIDGE)
			{
				//Only add internet routing WAN
				aclRule.ingress_intf_idx = i;
				if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0)
					fprintf(fp, "%d\n", aclIdx);
				else
					printf("rtk_rg_aclFilterAndQos_add physic port failed!\n");
			}
		}
#endif
	}

	fclose(fp);
	return 0;
}


#ifdef CONFIG_CU
int RTK_RG_ACL_IPPort_Filter_Loopback_Policy(int out_policy)
{
	rtk_rg_aclFilterAndQos_t aclRule;
	int aclIdx;
	FILE *fp;

	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));

	if( out_policy == 0 )
	{
		if(!(fp = fopen(RG_ACL_RULES_LOOPBACK_FILE, "w")))
		{
			fprintf(stderr, "ERROR! %s\n", strerror(errno));
			return -2;
		}
		aclRule.action_type = ACL_ACTION_TYPE_DROP;
		aclRule.filter_fields = INGRESS_DMAC_BIT|INGRESS_PORT_BIT;
		#ifdef CONFIG_RTL9602C_SERIES
		aclRule.ingress_port_mask.portmask = RG_get_lan_phyPortMask(0x3);
		#else
		aclRule.ingress_port_mask.portmask = RG_get_lan_phyPortMask(0xf);
		#endif
#ifdef WLAN_SUPPORT
		aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN0));
#ifdef WLAN_DUALBAND_CONCURRENT
		aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN1));
#endif
		aclRule.ingress_port_mask.portmask |= (1 << RTK_RG_PORT_CPU);
#endif
		//aclRule.acl_weight = RG_FIREWALL_ACL_WEIGHT;
		aclRule.acl_weight = RG_TRAP_ACL_WEIGHT;
		aclRule.filter_fields |= INGRESS_IPV4_TAGIF_BIT;
		aclRule.ingress_ipv4_tagif = 1;

		mib_get(MIB_ELAN_MAC_ADDR, (void *)&aclRule.ingress_dmac);

		if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0)
			fprintf(fp, "%d\n", aclIdx);
		else
			printf("rtk_rg_aclFilterAndQos_add physic port failed!\n");

		fclose(fp);
		return 0;
	}else {
		if(!(fp = fopen(RG_ACL_RULES_LOOPBACK_FILE, "r")))
		return -2;

		while(fscanf(fp, "%d\n", &aclIdx) != EOF)
		{
			if(rtk_rg_aclFilterAndQos_del(aclIdx))
				DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", aclIdx);
		}

		fclose(fp);
		unlink(RG_ACL_RULES_LOOPBACK_FILE);
		return 0;
	}

	
}

#endif

int RTK_RG_ACL_IPPort_Filter_Allow_LAN_to_GW()
{
	rtk_rg_aclFilterAndQos_t aclRule;
	int aclIdx, ret;
	FILE *fp;
	struct in_addr lan_ip;
	char ip2_enabled = 0;

	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));

	if(!(fp = fopen(RG_ACL_RULES_FILE, "a")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -1;
	}
#ifdef CONFIG_RTL9600_SERIES
	//to avoid acl permit rules, and trap 2 cpu. HW can't keep original vlan problem
	aclRule.action_type = ACL_ACTION_TYPE_TRAP;
#else
	aclRule.action_type = ACL_ACTION_TYPE_PERMIT;
#endif
	aclRule.filter_fields = INGRESS_DMAC_BIT | INGRESS_IPV4_DIP_RANGE_BIT | INGRESS_PORT_BIT;
	aclRule.filter_fields |= INGRESS_IPV4_TAGIF_BIT;
	aclRule.ingress_ipv4_tagif = 1;
	aclRule.ingress_port_mask.portmask = RG_get_all_lan_phyPortMask();
	aclRule.ingress_port_mask.portmask |= (1<<RTK_RG_PORT_CPU);
#ifdef WLAN_SUPPORT
	aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN0));
#ifdef WLAN_DUALBAND_CONCURRENT
	aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN1));
#endif
#endif
	aclRule.acl_weight = RG_TRAP_ACL_WEIGHT;

	mib_get(MIB_ELAN_MAC_ADDR, (void *)&aclRule.ingress_dmac);
	mib_get(MIB_ADSL_LAN_IP, (void *)&lan_ip);
	aclRule.ingress_dest_ipv4_addr_start = aclRule.ingress_dest_ipv4_addr_end = ntohl(*((ipaddr_t *)&lan_ip.s_addr));

	if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0)
		fprintf(fp, "%d\n", aclIdx);
	else
		printf("rtk_rg_aclFilterAndQos_add allow gw ip failed!\n");

	//add ACL_ACTION_TYPE_SW_PERMIT in apollo series.
	//to avoid acl permit rules, and trap 2 cpu. HW can't keep original vlan problem
#ifdef CONFIG_RTL9600_SERIES
	aclRule.action_type = ACL_ACTION_TYPE_SW_PERMIT;
	if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0)
		fprintf(fp, "%d\n", aclIdx);
	else
		printf("rtk_rg_aclFilterAndQos_add allow gw ip failed!\n");
#endif


	mib_get(MIB_ADSL_LAN_ENABLE_IP2, (void *)&ip2_enabled);

	if(ip2_enabled)
	{
#ifdef CONFIG_RTL9600_SERIES
		//to avoid acl permit rules, and trap 2 cpu. HW can't keep original vlan problem
		aclRule.action_type = ACL_ACTION_TYPE_TRAP;
#else
		aclRule.action_type = ACL_ACTION_TYPE_PERMIT;
#endif	
		mib_get(MIB_ADSL_LAN_IP2, (void *)&lan_ip);
		aclRule.ingress_dest_ipv4_addr_start = aclRule.ingress_dest_ipv4_addr_end = ntohl(*((ipaddr_t *)&lan_ip.s_addr));

		if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0)
			fprintf(fp, "%d\n", aclIdx);
		else
			printf("rtk_rg_aclFilterAndQos_add allow gw ip2 failed!\n");
	}
	fclose(fp);
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

#if 0
int AddRTK_RG_ACL_IPv6Port_Filter(MIB_CE_V6_IP_PORT_FILTER_T *ipv6_filter_entry)
{
	rtk_rg_aclFilterAndQos_t aclRule;
	rtk_rg_intfInfo_t infinfo;
	int aclIdx, i;
	FILE *fp;
	unsigned char empty_ipv6[IPV6_ADDR_LEN] = {0};

	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));

	if (ipv6_filter_entry->action == 0)
		aclRule.action_type = ACL_ACTION_TYPE_DROP;
	else if (ipv6_filter_entry->action == 1)
		aclRule.action_type = ACL_ACTION_TYPE_PERMIT;
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
				IPv6PrefixToStartEnd(ipv6_filter_entry->sip6Start, ipv6_filter_entry->sip6PrefixLen, aclRule.ingress_src_ipv6_addr_start, aclRule.ingress_src_ipv6_addr_end);
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
				IPv6PrefixToStartEnd(ipv6_filter_entry->dip6Start, ipv6_filter_entry->dip6PrefixLen, aclRule.ingress_dest_ipv6_addr_start, aclRule.ingress_dest_ipv6_addr_end);
		}
		else
		{
			memcpy(aclRule.ingress_dest_ipv6_addr_start, ipv6_filter_entry->dip6Start, IPV6_ADDR_LEN);
			memcpy(aclRule.ingress_dest_ipv6_addr_end, ipv6_filter_entry->dip6End, IPV6_ADDR_LEN);
		}
	}

	// Protocol
	if( ipv6_filter_entry->protoType != PROTO_NONE )
	{
		if( ipv6_filter_entry->protoType == PROTO_TCP )
			aclRule.filter_fields |= INGRESS_L4_TCP_BIT;
		else if( ipv6_filter_entry->protoType == PROTO_UDP )
			aclRule.filter_fields |= INGRESS_L4_UDP_BIT;
		else if( ipv6_filter_entry->protoType == PROTO_ICMP)
			aclRule.filter_fields |= INGRESS_L4_ICMP_BIT;
		else
			return -1;
	}

	if(!(fp = fopen(RG_ACL_IPv6_RULES_FILE, "a")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -2;
	}

	if(ipv6_filter_entry->dir == DIR_OUT)
	{
		for( i = 0; i < MAX_NETIF_SW_TABLE_SIZE; i++ )
		{
			memset(&infinfo, 0, sizeof(rtk_rg_intfInfo_t));
			if(rtk_rg_intfInfo_find(&infinfo, &i))
				break;

			if(infinfo.is_wan)
			{
				aclRule.filter_fields |= EGRESS_INTF_BIT;
				aclRule.egress_intf_idx = i;

				if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0)
					fprintf(fp, "%d\n", aclIdx);
				else
					DBPRINT(1, "rtk_rg_aclFilterAndQos_add failed!\n");
			}
		}
	}
	else if(ipv6_filter_entry->dir == DIR_IN)
	{
		int wanPhyPort;
		aclRule.filter_fields |= INGRESS_PORT_BIT;

		if(mib_get(MIB_WAN_PHY_PORT , (void *)&wanPhyPort) == 0)
		{
			printf("Get MIB_WAN_PHY_PORT failed!!!\n");
			wanPhyPort = RTK_RG_MAC_PORT3; //for 0371 default
		}

		aclRule.ingress_port_mask.portmask = 1 << wanPhyPort;

		if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0)
			fprintf(fp, "%d\n", aclIdx);
		else
			DBPRINT(1, "rtk_rg_aclFilterAndQos_add failed!\n");
	}
	else
	{
		DBPRINT(1, "Invalid filtering direction!\n");
		fclose(fp);
		return -1;
	}

	fclose(fp);
	return 0;
}
#endif

#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
int AddRTK_RG_ACL_IPPort_Filter_IPv6(MIB_CE_IP_PORT_FILTER_T *ipEntry, unsigned char in_action, unsigned char out_action)
#else
int AddRTK_RG_ACL_IPPort_Filter_IPv6(MIB_CE_IP_PORT_FILTER_T *ipEntry)
#endif
{
	rtk_rg_aclFilterAndQos_t aclRule;
	rtk_rg_intfInfo_t infinfo;
	int aclIdx, i, udp_tcp_rule=0;
	FILE *fp;
	unsigned char empty_ipv6[IPV6_ADDR_LEN] = {0};

	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	aclRule.acl_weight = RG_FIREWALL_ACL_WEIGHT;

#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	if ((in_action == 1 && ipEntry->dir == DIR_IN) || (out_action == 1 && ipEntry->dir == DIR_OUT))
		aclRule.action_type = ACL_ACTION_TYPE_DROP;
	else
		aclRule.action_type = ACL_ACTION_TYPE_PERMIT;
#else
	if (ipEntry->action == 0)
		aclRule.action_type = ACL_ACTION_TYPE_DROP;
	else if (ipEntry->action == 1)
		aclRule.action_type = ACL_ACTION_TYPE_PERMIT;
	else
	{
		fprintf(stderr, "Wrong IP/Port filter action!\n");
		return -1;
	}
#endif

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
	if(memcmp(ipEntry->sip6Start, empty_ipv6, IPV6_ADDR_LEN) != 0)
	{
		aclRule.filter_fields |= INGRESS_IPV6_SIP_RANGE_BIT;

		if(ipEntry->sip6End[0] == 0)
		{
			if(ipEntry->sip6PrefixLen == 0)
			{
				memcpy(aclRule.ingress_src_ipv6_addr_start, ipEntry->sip6Start, IPV6_ADDR_LEN);
				memcpy(aclRule.ingress_src_ipv6_addr_end, ipEntry->sip6Start, IPV6_ADDR_LEN);
			}
			else
			{
#ifdef CONFIG_RTL9602C_SERIES
				aclRule.filter_fields &= ~INGRESS_IPV6_SIP_RANGE_BIT;
				aclRule.filter_fields |= INGRESS_IPV6_SIP_BIT;				
				IPv6PrefixToIPaddressMask(ipEntry->sip6Start, ipEntry->sip6PrefixLen, aclRule.ingress_src_ipv6_addr, aclRule.ingress_src_ipv6_addr_mask);
#else
				IPv6PrefixToStartEnd(ipEntry->sip6Start, ipEntry->sip6PrefixLen, aclRule.ingress_src_ipv6_addr_start, aclRule.ingress_src_ipv6_addr_end);
#endif
			}
		}
		else
		{
			memcpy(aclRule.ingress_src_ipv6_addr_start, ipEntry->sip6Start, IPV6_ADDR_LEN);
			memcpy(aclRule.ingress_src_ipv6_addr_end, ipEntry->sip6End, IPV6_ADDR_LEN);
		}
	}

	// Destination ip, mask
	if(memcmp(ipEntry->dip6Start, empty_ipv6, IPV6_ADDR_LEN) != 0)
	{
		aclRule.filter_fields |= INGRESS_IPV6_DIP_RANGE_BIT;

		if(ipEntry->dip6End[0] == 0)
		{
			if(ipEntry->dip6PrefixLen == 0)
			{
				memcpy(aclRule.ingress_dest_ipv6_addr_start, ipEntry->dip6Start, IPV6_ADDR_LEN);
				memcpy(aclRule.ingress_dest_ipv6_addr_end, ipEntry->dip6Start, IPV6_ADDR_LEN);
			}
			else
			{
#ifdef CONFIG_RTL9602C_SERIES			
				aclRule.filter_fields &= ~INGRESS_IPV6_DIP_RANGE_BIT;
				aclRule.filter_fields |= INGRESS_IPV6_DIP_BIT;				
				IPv6PrefixToIPaddressMask(ipEntry->dip6Start, ipEntry->dip6PrefixLen, aclRule.ingress_dest_ipv6_addr, aclRule.ingress_dest_ipv6_addr_mask);
#else
				IPv6PrefixToStartEnd(ipEntry->dip6Start, ipEntry->dip6PrefixLen, aclRule.ingress_dest_ipv6_addr_start, aclRule.ingress_dest_ipv6_addr_end);
#endif
			}
		}
		else
		{
			memcpy(aclRule.ingress_dest_ipv6_addr_start, ipEntry->dip6Start, IPV6_ADDR_LEN);
			memcpy(aclRule.ingress_dest_ipv6_addr_end, ipEntry->dip6End, IPV6_ADDR_LEN);
		}
	}

	// Protocol
	if( ipEntry->protoType != PROTO_NONE )
	{
		if( ipEntry->protoType == PROTO_TCP )
			aclRule.filter_fields |= INGRESS_L4_TCP_BIT;
		else if( ipEntry->protoType == PROTO_UDP )
			aclRule.filter_fields |= INGRESS_L4_UDP_BIT;
		else if( ipEntry->protoType == PROTO_ICMP){
			if( ipEntry->IpProtocol == IPVER_IPV6)
				aclRule.filter_fields |= INGRESS_L4_ICMPV6_BIT;
			else
				aclRule.filter_fields |= INGRESS_L4_ICMP_BIT;
		}
		else if( ipEntry->protoType == PROTO_UDPTCP){
			aclRule.filter_fields |= INGRESS_L4_UDP_BIT; //add udp for udp/tcp protocol
			udp_tcp_rule = 1;
		}
		else
			return -1;
	}

	if(!(fp = fopen(RG_ACL_IPv6_RULES_FILE, "a")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -2;
	}

add_udp_tcp:
	if(udp_tcp_rule==2){
		aclRule.filter_fields &= ~(INGRESS_L4_UDP_BIT);
		aclRule.filter_fields |= INGRESS_L4_TCP_BIT; //add tcp for udp/tcp protocol
	}

	if(ipEntry->dir == DIR_OUT)
	{
		int wanPhyPort;
		aclRule.filter_fields |= INGRESS_PORT_BIT;

		#if 0
		if(mib_get(MIB_WAN_PHY_PORT , (void *)&wanPhyPort) == 0)
		{
			printf("Get MIB_WAN_PHY_PORT failed!!!\n");
			wanPhyPort = RTK_RG_MAC_PORT3; //for 0371 default
		}

		aclRule.ingress_port_mask.portmask = (0xf)&~(1 << wanPhyPort);
		#endif
		aclRule.ingress_port_mask.portmask = RG_get_all_lan_phyPortMask() & ~(RG_get_wan_phyPortMask());
#ifdef WLAN_SUPPORT
		aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN0));
#ifdef WLAN_DUALBAND_CONCURRENT
		aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN1));
#endif
		aclRule.ingress_port_mask.portmask |= (1 << RTK_RG_PORT_CPU);
#endif
	}
	else if(ipEntry->dir == DIR_IN)
	{
		int wanPhyPort;
		aclRule.filter_fields |= INGRESS_PORT_BIT;

		#if 0
		if(mib_get(MIB_WAN_PHY_PORT , (void *)&wanPhyPort) == 0)
		{
			printf("Get MIB_WAN_PHY_PORT failed!!!\n");
			wanPhyPort = RTK_RG_MAC_PORT3; //for 0371 default
		}

		aclRule.ingress_port_mask.portmask = 1 << wanPhyPort;
		#endif

		aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();

	}
	else
	{
		DBPRINT(1, "Invalid filtering direction!\n");
		fclose(fp);
		return -1;
	}

	if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0)
		fprintf(fp, "%d\n", aclIdx);
	else
		DBPRINT(1, "rtk_rg_aclFilterAndQos_add failed!\n");

	if(udp_tcp_rule==1){
		udp_tcp_rule = 2;
		goto add_udp_tcp;
	}

	fclose(fp);
	return 0;
}

// Magician: No support default policy yet.
int RTK_RG_ACL_IPv6Port_Filter_Default_Policy(int out_policy, int in_policy)
{
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

/************************************************************************************
 * Martin zhu add for Bridge IPv4/IPv6 filter support 2015.6.29
 * Target: IPv4 only: Drop IPv6 tagif packet and IPv6 PPPoE dial packet
 *		   IPv6 only: Drop IPv4 tagif packet and IPv4 PPPoE dial packet
 *		   IPv4&IPv6: Do nothing.
 * Implement method:
 * 		   Rule1: Drop IPv4 or IPv6 tag packet by pEntry->protocol
 *		   Rule2: Trap all PPPoE(0x8864) packets which have no IPv4&IPv6 tagif to CPU
 * 	       Exp:	  Because Rule1 match before Rule2, so all PPPoE(0x8864) LCP/IPCP/IPCPv6 will
 * 				  be traped to CPU and Proc interface(/proc/rg/bridgeWan_drop_by_protocal)
 *                will drop or permit those packets.
**************************************************************************************/
int AddRTK_RG_ACL_Bridge_IPv4IPv6_Filters( MIB_CE_ATM_VC_Tp pEntry )
{
	rtk_rg_aclFilterAndQos_t aclRule;
	rtk_rg_intfInfo_t infinfo;
	int aclIdx, i;
	FILE *fp;
	char fileName[256] = {0};

	if (NULL == pEntry)
		return -1;

	if ( (pEntry->IpProtocol != 0x01) && (pEntry->IpProtocol != 0x02) )//IPv4 & IPv6,do nothing
		return 0;

	sprintf(fileName,"%s_for_%d",RG_ACL_BRIDGE_IPv4IPv6_FILTER_RULES_FILE,pEntry->ifIndex);
	if(!(fp = fopen(fileName, "a")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -2;
	}

	// Rule1: Drop IPv4 or IPv6 tag packet by pEntry->IpProtocol
	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	aclRule.action_type = ACL_ACTION_TYPE_DROP;
	aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	aclRule.filter_fields |= INGRESS_INTF_BIT;
	aclRule.ingress_intf_idx = pEntry->rg_wan_idx;
	if ( 0x01 == pEntry->IpProtocol ){//only IPv4 Pass, drop IPv6 tagif
		aclRule.filter_fields |= INGRESS_IPV6_TAGIF_BIT;
		aclRule.ingress_ipv6_tagif = 1;
	} else if ( 0x02 == pEntry->IpProtocol ){//only IPv6 Pass, drop IPv4 tagif
		aclRule.filter_fields |= INGRESS_IPV4_TAGIF_BIT;
		aclRule.ingress_ipv4_tagif = 1;
	}

	aclRule.filter_fields |= INGRESS_PORT_BIT;
	aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();
	if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0)
		fprintf(fp, "%d\n", aclIdx);
	else {
		fclose(fp);
		DBPRINT(1, "rtk_rg_aclFilterAndQos_add failed!\n");
		return -1;
	}

	// Rule2: Trap all PPPoE(0x8864) packets which have no IPv4&IPv6 tagif to CPU.
	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	aclRule.action_type = ACL_ACTION_TYPE_TRAP;
	aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	aclRule.filter_fields |= INGRESS_INTF_BIT;
	aclRule.ingress_intf_idx = pEntry->rg_wan_idx;
	aclRule.filter_fields |= INGRESS_ETHERTYPE_BIT;
	aclRule.ingress_ethertype = 0x8864;
	//Trap all PPPoE 0x8864 packet without IPv4&IPv6 tagif to CPU
	aclRule.filter_fields |= INGRESS_IPV6_TAGIF_BIT;
	aclRule.ingress_ipv6_tagif = 0;
	aclRule.filter_fields |= INGRESS_IPV4_TAGIF_BIT;
	aclRule.ingress_ipv4_tagif = 0;

	aclRule.filter_fields |= INGRESS_PORT_BIT;
	aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();
	if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0)
		fprintf(fp, "%d\n", aclIdx);
	else {
		fclose(fp);
		DBPRINT(1, "rtk_rg_aclFilterAndQos_add failed!\n");
		return -1;
	}
	fclose(fp);

	// write proc interface(/proc/rg/bridgeWan_drop_by_protocal)
	fp = fopen("/proc/rg/bridgeWan_drop_by_protocal", "w");
	if(fp)
	{
		fprintf(fp, "%d %d\n",pEntry->rg_wan_idx, pEntry->IpProtocol);
		fclose(fp);
	}

#if 0
	//upstream:LAN->WAN
	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	aclRule.action_type = ACL_ACTION_TYPE_DROP;
	aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_OR_EGRESS_L34_UP_DROP;
#if 0
	aclRule.filter_fields |= EGRESS_INTF_BIT;
	aclRule.egress_intf_idx = pEntry->rg_wan_idx;
#endif
	aclRule.filter_fields |= INGRESS_ETHERTYPE_BIT;
	if ( 0x01 == pEntry->IpProtocol ){//only IPv4
		aclRule.ingress_ethertype = 0x86dd;
	} else if ( 0x02 == pEntry->IpProtocol ){//only IPv6
		aclRule.ingress_ethertype = 0x0800;
	}
#if 1
	aclRule.filter_fields |= INGRESS_PORT_BIT;
	if (pEntry->itfGroup != 0){
		aclRule.ingress_port_mask.portmask = RG_get_lan_phyPortMask(pEntry->itfGroup);
	}else {
		aclRule.ingress_port_mask.portmask = RG_get_all_lan_phyPortMask();
	}
#endif
	printf("%s %d:egress_intf_idx =%d\n", __func__, __LINE__,pEntry->rg_wan_idx);
	sleep(5);
	if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0)
		fprintf(fp, "%d\n", aclIdx);
	else {
		fclose(fp);
		DBPRINT(1, "rtk_rg_aclFilterAndQos_add failed!\n");
		return -1;
	}

	if ( 0x02 == pEntry->IpProtocol ){//upstream:ARP
		memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
		aclRule.action_type = ACL_ACTION_TYPE_DROP;
		aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_OR_EGRESS_L34_UP_DROP;
#if 0
		aclRule.filter_fields |= EGRESS_INTF_BIT;
		aclRule.egress_intf_idx = pEntry->rg_wan_idx;
#endif
		aclRule.filter_fields |= INGRESS_ETHERTYPE_BIT;
		aclRule.ingress_ethertype = 0x0806;
#if 1
		aclRule.filter_fields |= INGRESS_PORT_BIT;
		if (pEntry->itfGroup != 0){
			aclRule.ingress_port_mask.portmask = RG_get_lan_phyPortMask(pEntry->itfGroup);
		}else {
			aclRule.ingress_port_mask.portmask = RG_get_all_lan_phyPortMask();
		}
#endif
		printf("%s %d:egress_intf_idx = %d\n", __func__, __LINE__,pEntry->rg_wan_idx);
		sleep(5);
		if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0)
			fprintf(fp, "%d\n", aclIdx);
		else {
			fclose(fp);
			DBPRINT(1, "rtk_rg_aclFilterAndQos_add failed!\n");
			return -1;
		}
	}
#endif
	return 0;
}

int FlushRTK_RG_ACL_Bridge_IPv4IPv6_Filters( MIB_CE_ATM_VC_Tp pEntry )
{
	FILE *fp;
	int aclIdx;
	char fileName[256];

	if (NULL == pEntry)
		return -1;

	sprintf(fileName,"%s_for_%d",RG_ACL_BRIDGE_IPv4IPv6_FILTER_RULES_FILE, pEntry->ifIndex);
	if(!(fp = fopen(fileName, "r")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -2;
	}

	while(fscanf(fp, "%d\n", &aclIdx) != EOF)
	{
		if(rtk_rg_aclFilterAndQos_del(aclIdx)) {
			fclose(fp);
			DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", aclIdx);
			return -1;
		}
	}

	fclose(fp);
	unlink(fileName);

	fp = fopen("/proc/rg/bridgeWan_drop_by_protocal", "w");
	if(fp)
	{
		fprintf(fp, "%d %d\n",pEntry->rg_wan_idx, 0);// IPv4 && IPv6 pass
		fclose(fp);
	}

	return 0;
}
#endif

typedef struct napt_entry_t{
	rtk_rg_naptEntry_t entry;
	unsigned char tail;
	struct napt_entry_t *next;
}napt_entry_s;

static void freeNaptEntryList(napt_entry_s *list)
{
	napt_entry_s *t = list, *tmp;
	while(t && t->tail == 0){
		tmp = t;
		free(tmp);
		t = t->next;
	}
}

int DelRTK_RG_ALG_SRV_in_Lan_Napt_Connection(napt_entry_s *list)
{
	int napt_idx, ret;
	rtk_rg_naptInfo_t naptInfo;
	napt_entry_s *tmp_list;
	
	for(napt_idx=0 ; napt_idx<1024 ; napt_idx++){
		ret = rtk_rg_naptConnection_find(&naptInfo,&napt_idx);
		
		if(ret==RT_ERR_RG_OK){
			
			tmp_list = list;
			
			while(tmp_list && tmp_list->tail == 0){

				if(naptInfo.naptTuples.is_tcp != tmp_list->entry.is_tcp)
					goto next;
				if(naptInfo.naptTuples.local_ip != tmp_list->entry.local_ip)
					goto next;
				if(naptInfo.naptTuples.local_port != tmp_list->entry.local_port)
					goto next;
		
				if((ret = rtk_rg_naptConnection_del(napt_idx)) != RT_ERR_RG_OK)
				{
					DBPRINT(1, "rtk_rg_naptConnection_del failed! idx=%d ret=%d\n", napt_idx, ret);
				}

next:
				tmp_list = tmp_list->next;
			}
		}
		else
			break;
	}

	return 0;
}

int Flush_RTK_RG_ALG_SRV_in_Lan(int flush_napt)
{
	int i, j, ret;
	rtk_rg_alg_type_t alg_app, alg_app_dis;
	rtk_rg_alg_type_t server_in_lan_bit[]={RTK_RG_ALG_FTP_UDP_SRV_IN_LAN_BIT, RTK_RG_ALG_FTP_TCP_SRV_IN_LAN_BIT};
	FILE *fp = NULL;
	int enabled=0;
	in_addr_t ip_addr=0;
	rtk_rg_intfInfo_t infinfo;
	int totalEntry = mib_chain_total(MIB_ATM_VC_TBL);
	MIB_CE_ATM_VC_T entry;
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	unsigned int dmzWan = 0;
#endif
	napt_entry_s napt_pattern_list, *p_napt_pattern_list, *tmp_list;

	p_napt_pattern_list = &napt_pattern_list;
	napt_pattern_list.tail = 1;

	if(flush_napt){
		fp = fopen(RG_DMZ_FILE, "r");
		if(fp){
			fscanf(fp, "%d %lx\n", &enabled, &ip_addr);
			fclose(fp);
		}
		else{
			enabled = 0;
			ip_addr = 0;
		}
	}

	for(i=0; i<(sizeof(server_in_lan_bit)/sizeof(server_in_lan_bit[0])); i++)
	{
		if((ret = rtk_rg_algApps_get(&alg_app))){
			DBPRINT(1, "Error %d: rtk_rg_algApps_get failed!\n", ret);
			continue;
		}
		alg_app_dis  = (alg_app & ~server_in_lan_bit[i]);
		if((ret = rtk_rg_algApps_set(alg_app_dis))){
			DBPRINT(1, "Error %d: rtk_rg_algApps_set failed!\n", ret);
			continue;
		}
		if(alg_app & server_in_lan_bit[i]){
			if((ret=rtk_rg_algServerInLanAppsIpAddr_del(server_in_lan_bit[i]))){
				DBPRINT(1, "Error %d: rtk_rg_algServerInLanAppsIpAddr_del failed!\n", ret);
				continue;
			}
			else{
				if(flush_napt == 0 || enabled == 0)
					continue;
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
				if (!mib_get(MIB_DMZ_WAN, (void *)&dmzWan)){
					continue;
				}
				totalEntry = mib_chain_total(MIB_ATM_VC_TBL);
				for( j = 0; j < totalEntry; j++ )
				{
					if (mib_chain_get(MIB_ATM_VC_TBL, j, (void *)&entry) == 0)
						continue;
					//Check this interface has INTERNET service type
					if(entry.ifIndex == dmzWan){
						memset(&infinfo, 0, sizeof(rtk_rg_intfInfo_t));
						if (rtk_rg_intfInfo_find(&infinfo, &entry.rg_wan_idx) != SUCCESS) {
							printf("%s-%d Can't find the wan interface idx:%d!", __func__, __LINE__, entry.rg_wan_idx);
							break;
						}
			
						if(infinfo.is_wan && infinfo.wan_intf.wan_intf_conf.wan_type != RTK_RG_BRIDGE)
						{
							// We need to delete associative NAPT connection info from RG further
							tmp_list = calloc(1, sizeof(napt_entry_s));
							tmp_list->entry.local_ip = ip_addr;
							tmp_list->entry.local_port = 21;
							tmp_list->entry.is_tcp = i;
							tmp_list->next = p_napt_pattern_list;
							p_napt_pattern_list = tmp_list;
						}
						break;
					}
				}
#else
				tmp_list = calloc(1, sizeof(napt_entry_s));
				tmp_list->entry.local_ip = ip_addr;
				tmp_list->entry.local_port = 21;
				tmp_list->entry.is_tcp = i;
				tmp_list->next = p_napt_pattern_list;
				p_napt_pattern_list = tmp_list;
				
				
#endif
			}
		}
	}

	if(p_napt_pattern_list->tail == 0)
		DelRTK_RG_ALG_SRV_in_Lan_Napt_Connection(p_napt_pattern_list);
	freeNaptEntryList(p_napt_pattern_list);
	
	return 0;
}

int RTK_RG_ALG_SRV_in_Lan_Set(void)
{
	int i, ret, vsr_num=0;
	rtk_rg_alg_type_t alg_app, alg_app_dis;
	rtk_rg_alg_serverIpMapping_t srvIpMapping;
	rtk_rg_alg_type_t server_in_lan_bit[]={RTK_RG_ALG_FTP_UDP_SRV_IN_LAN_BIT, RTK_RG_ALG_FTP_TCP_SRV_IN_LAN_BIT};
	FILE *fp;
	int enabled=0;
	in_addr_t ip_addr=0;
	int is_tcp=0;

	for(i=0; i<(sizeof(server_in_lan_bit)/sizeof(server_in_lan_bit[0])); i++)
	{
#if 0
		if((ret = rtk_rg_algApps_get(&alg_app))){
			DBPRINT(1, "Error %d: rtk_rg_algApps_get failed!\n", ret);
			continue;
		}
		alg_app_dis  = (alg_app & ~server_in_lan_bit[i]);
		if((ret = rtk_rg_algApps_set(alg_app_dis))){
			DBPRINT(1, "Error %d: rtk_rg_algApps_set failed!\n", ret);
			continue;
		}
		if(alg_app & server_in_lan_bit[i]){
			if((ret=rtk_rg_algServerInLanAppsIpAddr_del(server_in_lan_bit[i]))){
				DBPRINT(1, "Error %d: rtk_rg_algServerInLanAppsIpAddr_del failed!\n", ret);
				continue;
			}
		}
		alg_app = alg_app_dis;
#endif

		memset(&srvIpMapping, 0, sizeof(rtk_rg_alg_serverIpMapping_t));
		srvIpMapping.algType = server_in_lan_bit[i];

#ifdef VIRTUAL_SERVER_SUPPORT
		//virtual server
		vsr_num = 0;
		fp = fopen(RG_VIRTUAL_SERVER_IP_FILE, "r");
		if(fp){
			while(fscanf(fp, "%lx %d\n", &ip_addr, &is_tcp)!=EOF){
				if(is_tcp == i && ip_addr){
					//srvIpMapping.serverAddress=ip_addr;
					vsr_num++;
					break;
				}
				ip_addr = 0;
				is_tcp = 0;
			}
			fclose(fp);
			if(vsr_num)
				continue;
		}
#endif
		//dmz
		if(!vsr_num){
			fp = fopen(RG_DMZ_FILE, "r");
			if(fp){
				fscanf(fp, "%d %lx\n", &enabled, &ip_addr);
				if(enabled)
					srvIpMapping.serverAddress=ip_addr;
				fclose(fp);
			}
			else{
				enabled = 0;
				ip_addr = 0;
			}
		}

		if(enabled /*|| vsr_num > 0*/){
			if((ret=rtk_rg_algServerInLanAppsIpAddr_add(&srvIpMapping))){
				DBPRINT(1, "Error %d: rtk_rg_algServerInLanAppsIpAddr_add failed!\n", ret);
			}
			else{
				if((ret = rtk_rg_algApps_get(&alg_app))){
					DBPRINT(1, "Error %d: rtk_rg_algApps_get failed!\n", ret);
				}
				else{
					alg_app |= server_in_lan_bit[i];
					if((ret = rtk_rg_algApps_set(alg_app))){
						DBPRINT(1, "Error %d: rtk_rg_algApps_set failed!\n", ret);
					}
				}
			}
		}
	}
}

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
			}
		}
		else
			break;
	}

	return 0;
}

int RTK_RG_DMZ_Set(int enabled, in_addr_t ip_addr, int isBoot)
{
	int i,rg_wan_idx=0;
	rtk_rg_intfInfo_t infinfo;
	rtk_rg_dmzInfo_t dmz_info;
	FILE *fp;
	int totalEntry = mib_chain_total(MIB_ATM_VC_TBL);
	MIB_CE_ATM_VC_T entry;
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	unsigned int dmzWan = 0;
#endif


	fp = fopen(RG_DMZ_FILE, "w");
	if(fp){
		fprintf(fp, "%d %lx\n", enabled, ntohl(ip_addr));
		fclose(fp);
	}
	else
		return -2;

#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	if (!mib_get(MIB_DMZ_WAN, (void *)&dmzWan)){
		return -2;
	}
	for( i = 0; i < totalEntry; i++ )
	{
		if (mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&entry) == 0)
			continue;
		//Check this interface has INTERNET service type
		if(entry.ifIndex == dmzWan){
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
				if(!enabled && !isBoot)
				{
					// We need to delete associative NAPT connection info from RG further
					DelRTK_RG_DMZ_Napt_Connection(&dmz_info);
				}
			}
		}
	}
#else
	for( i = 0; i < totalEntry; i++ )
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
				if(!enabled && !isBoot)
				{
					// We need to delete associative NAPT connection info from RG further
					DelRTK_RG_DMZ_Napt_Connection(&dmz_info);
				}
			}
		}
	}
#endif

	Flush_RTK_RG_ALG_SRV_in_Lan(0);

	if(enabled)
		RTK_RG_ALG_SRV_in_Lan_Set();
}

#ifdef VIRTUAL_SERVER_SUPPORT
int RTK_RG_Virtual_Server_Set(MIB_VIRTUAL_SVR_T *pf)
{
	rtk_rg_virtualServer_t vs;
	rtk_rg_intfInfo_t inf_info;
	int vs_idx, i, ret, j;
	FILE *fp, *fp2;
	int totalEntry = mib_chain_total(MIB_ATM_VC_TBL);
	MIB_CE_ATM_VC_T entry;
	int is_internet_wan = 0;

	memset(&vs, 0, sizeof(rtk_rg_virtualServer_t));

	vs.local_ip = ntohl(*((ipaddr_t *)pf->serverIp));
	vs.remote_ip = ntohl(*((ipaddr_t *)pf->remotehost));
	vs.valid = ENABLED;

	if(pf->lanPort)
	{
		vs.local_port_start = pf->lanPort;
		vs.gateway_port_start = pf->lanPort;
		vs.mappingPortRangeCnt = 1;
	}

	if(pf->wanStartPort)
	{
		if(!pf->lanPort)
			vs.local_port_start = pf->wanStartPort;

		vs.gateway_port_start = pf->wanStartPort;

		if(pf->wanEndPort)
			vs.mappingPortRangeCnt = pf->wanEndPort - pf->wanStartPort + 1;
		else
			vs.mappingPortRangeCnt = 1;
	}

	// Mapping all, if all fileds of ports are empty.
	if(!pf->lanPort && !pf->wanStartPort)
	{
		vs.local_port_start = vs.gateway_port_start = 1;
		vs.mappingPortRangeCnt = 0xffff;
	}

	if(!(fp = fopen(RG_VIRTUAL_SERVER_FILE, "a")))
		return -2;

	if(!(fp2 = fopen(RG_VIRTUAL_SERVER_IP_FILE, "a"))){
		fclose(fp);
		return -2;
	}

#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	{
		for( i = 0; i < totalEntry; i++ )
		{
			if (mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&entry) == 0)
				continue;
			//Check this interface has INTERNET service type
			//printf("entry.ifIndex %u, pf->ifIndex %u\n", entry.ifIndex, pf->ifIndex);
			if(entry.ifIndex ==  pf->ifIndex){
				vs.wan_intf_idx = entry.rg_wan_idx;
				//vs.mappingType=VS_MAPPING_N_TO_1;

				if(pf->protoType == PROTO_TCP || pf->protoType == 0)
				{
					vs.is_tcp = 1;
					if(pf->lanPort == 21){
						vs.hookAlgType = RTK_RG_ALG_FTP_TCP_SRV_IN_LAN_BIT;
						vs.disable_wan_check = 1;
					}
					ret = rtk_rg_virtualServer_add(&vs, &vs_idx);

					DBPRINT(0, "Add virtual server. RG WAN Index=%d, protocol=%s\n", vs.wan_intf_idx, vs.is_tcp? "TCP": "UDP");
					if(ret == 0){
						if(pf->lanPort == 21)
							fprintf(fp2, "%lx %d\n", vs.local_ip, vs.is_tcp);
						fprintf(fp, "%d\n", vs_idx);
					}
					else
					{
						DBPRINT(1, "Error %d: rtk_rg_virtualServer_add failed! protoType=TCP\n", ret);
					}
				}

				if(pf->protoType == PROTO_UDP || pf->protoType == 0)
				{
					vs.is_tcp = 0;
					if(pf->lanPort == 21){
						vs.hookAlgType = RTK_RG_ALG_FTP_UDP_SRV_IN_LAN_BIT;
						vs.disable_wan_check = 1;
					}
					ret = rtk_rg_virtualServer_add(&vs, &vs_idx);

					DBPRINT(0, "Add virtual server. RG WAN Index=%d, protocol=%s\n", vs.wan_intf_idx, vs.is_tcp? "TCP": "UDP");

					if(ret == 0){
						if(pf->lanPort == 21)
							fprintf(fp2, "%lx %d\n", vs.local_ip, vs.is_tcp);
						fprintf(fp, "%d\n", vs_idx);
					}
					else
					{
						DBPRINT(1, "Error %d: rtk_rg_virtualServer_add failed! protoType=UDP\n", ret);
					}
				}
			}
		}
	}
#else
	for( i = 0; i < MAX_NETIF_SW_TABLE_SIZE; i++ )
	{
		memset(&inf_info, 0, sizeof(rtk_rg_intfInfo_t));
		if(rtk_rg_intfInfo_find(&inf_info, &i))
			break;

		
		if(inf_info.is_wan && (inf_info.wan_intf.wan_intf_conf.wan_type != RTK_RG_BRIDGE))
		{
			is_internet_wan = 0;
			for( j = 0; j < totalEntry; j++ )
			{
				if (mib_chain_get(MIB_ATM_VC_TBL, j, (void *)&entry) == 0)
					continue;
				if(i == entry.rg_wan_idx)
				{
					if(entry.applicationtype & X_CT_SRV_INTERNET)
						is_internet_wan = 1;
					break;
				}
			}

			vs.wan_intf_idx = i;
			//vs.mappingType=VS_MAPPING_N_TO_1;

			if(pf->protoType == PROTO_TCP || pf->protoType == 0)
			{
				vs.is_tcp = 1;
				if(is_internet_wan == 1 && pf->lanPort == 21){
					vs.hookAlgType = RTK_RG_ALG_FTP_TCP_SRV_IN_LAN_BIT;
					vs.disable_wan_check = 1;
				}
				ret = rtk_rg_virtualServer_add(&vs, &vs_idx);

				DBPRINT(0, "Add virtual server. RG WAN Index=%d, protocol=%s\n", vs.wan_intf_idx, vs.is_tcp? "TCP": "UDP");
				if(ret == 0){
					if(is_internet_wan == 1 && pf->lanPort == 21)
						fprintf(fp2, "%lx %d\n", vs.local_ip, vs.is_tcp);
					fprintf(fp, "%d\n", vs_idx);
				}
				else
				{
					DBPRINT(1, "Error %d: rtk_rg_virtualServer_add failed! protoType=TCP\n", ret);
					continue;
				}
			}

			if(pf->protoType == PROTO_UDP || pf->protoType == 0)
			{
				vs.is_tcp = 0;
				if(is_internet_wan == 1 && pf->lanPort == 21){
					vs.hookAlgType = RTK_RG_ALG_FTP_UDP_SRV_IN_LAN_BIT;
					vs.disable_wan_check = 1;
				}
				ret = rtk_rg_virtualServer_add(&vs, &vs_idx);

				DBPRINT(0, "Add virtual server. RG WAN Index=%d, protocol=%s\n", vs.wan_intf_idx, vs.is_tcp? "TCP": "UDP");

				if(ret == 0){
					if(is_internet_wan == 1 && pf->lanPort == 21)
						fprintf(fp2, "%lx %d\n", vs.local_ip, vs.is_tcp);
					fprintf(fp, "%d\n", vs_idx);
				}
				else
				{
					DBPRINT(1, "Error %d: rtk_rg_virtualServer_add failed! protoType=UDP\n", ret);
					continue;
				}
			}
		}
	}
#endif

	fclose(fp2);
	fclose(fp);
	return 0;
}

int DelRTK_RG_Virtual_Server_Napt_Connection(rtk_rg_virtualServer_t *vsConnection)
{
	int napt_idx, ret;
	rtk_rg_naptInfo_t naptInfo;
	
	for(napt_idx=0 ; napt_idx<1024 ; napt_idx++){
		ret = rtk_rg_naptConnection_find(&naptInfo,&napt_idx);		
		if(ret==RT_ERR_RG_OK){

			/*if(naptInfo.naptTuples.wan_intf_idx != vsConnection->wan_intf_idx)
				continue;*/

			if(naptInfo.naptTuples.local_ip != vsConnection->local_ip)
				continue;

			/*if(naptInfo.naptTuples.remote_ip != vsConnection->remote_ip)
				continue;*/

			if(naptInfo.naptTuples.external_port < vsConnection->gateway_port_start
			&& naptInfo.naptTuples.external_port >= vsConnection->gateway_port_start+vsConnection->mappingPortRangeCnt)
				continue;

			if(vsConnection->mappingType == VS_MAPPING_N_TO_N) {
				if(naptInfo.naptTuples.local_port < vsConnection->local_port_start
				&& naptInfo.naptTuples.local_port >= vsConnection->local_port_start+vsConnection->mappingPortRangeCnt)
					continue;
			} else if (vsConnection->mappingType == VS_MAPPING_N_TO_1) {
				if(naptInfo.naptTuples.local_port != vsConnection->local_port_start)
					continue;				
			}
			
			if((ret = rtk_rg_naptConnection_del(napt_idx)) != RT_ERR_RG_OK)
			{
				DBPRINT(1, "rtk_rg_naptConnection_del failed! idx=%d ret=%d\n", napt_idx, ret);
			}
		}
		else
			break;
	}

	return 0;
}

int FlushRTK_RG_Virtual_Server()
{
	rtk_rg_virtualServer_t vs;
	FILE *fp;
	int vsIdx;

	Flush_RTK_RG_ALG_SRV_in_Lan(1);

	if(!(fp = fopen(RG_VIRTUAL_SERVER_FILE, "r")))
		return -1;

	while(fscanf(fp, "%d\n", &vsIdx) != EOF)
	{
		if(rtk_rg_virtualServer_find(&vs, &vsIdx) == RT_ERR_RG_OK) {
			if(rtk_rg_virtualServer_del(vsIdx))
				printf("rtk_rg_virtualServer_del failed! idx = %d\n", vsIdx);
			else {
				DelRTK_RG_Virtual_Server_Napt_Connection(&vs);
				printf("Deleted Virtual Server %d.\n", vsIdx);
			}
		}
	}
	unlink(RG_VIRTUAL_SERVER_IP_FILE);
	unlink(RG_VIRTUAL_SERVER_FILE);

	fclose(fp);
	return 0;
}
#endif


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
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	//Test Center send traffic is IFG include
	system("diag bandwidth set egress ifg include");
#endif

	return 0;
}

#ifdef _PRMT_X_CT_COM_DATA_SPEED_LIMIT_
/**
 * dir: 0:up, 1: down
 * share_meter_offset: Use dir and share_meter_offset to locate the share meter entry.
*/
int RTK_RG_data_speed_limit_if_set(int dir, int sm_offset, MIB_CE_DATA_SPEED_LIMIT_IF_Tp entry)
{
	rtk_rg_aclFilterAndQos_t aclRule;
	int aclIdx, ret;
	FILE *fp;
	int share_meter_id = DATA_SPEED_LIMIT_SM_ID_START + dir * MAX_DATA_SPEED_LIMIT_ENTRY + sm_offset;

	if(entry == NULL)
		return -1;

	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));

	aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	aclRule.action_type = ACL_ACTION_TYPE_QOS;

	if(dir == QOS_DIRECTION_UPSTREAM)
	{
		if(entry->if_id >=1 && entry->if_id <= 4)
		{
			aclRule.filter_fields |= INGRESS_PORT_BIT;
			aclRule.ingress_port_mask.portmask = RG_get_lan_phyPortMask( 1 << (entry->if_id - 1));
		}
#ifdef WLAN_SUPPORT
		else if(entry->if_id >= 5 && entry->if_id <= 8)
		{
			aclRule.filter_fields |= INGRESS_WLANDEV_BIT;
			aclRule.ingress_wlanDevMask = 1 << (entry->if_id - 5);
		}
		else
		{
			aclRule.filter_fields |= INGRESS_WLANDEV_BIT;
			aclRule.ingress_wlanDevMask = 1 << (entry->if_id - 9 + 13);
		}
#endif
	}
	else if(dir == QOS_DIRECTION_DOWNSTREAM)
	{
		// We don't support egress LAN port filter
		return 0;
	}

	rtk_rg_shareMeter_set(share_meter_id, entry->speed_unit * 512, RTK_RG_ENABLED);
	aclRule.qos_actions=ACL_ACTION_SHARE_METER_BIT;
	aclRule.action_share_meter = share_meter_id;

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

/**
 * dir: 0:up, 1: down
 * share_meter_offset: Use dir and share_meter_offset to locate the share meter entry.
*/
int RTK_RG_data_speed_limit_vlan_set(int dir, int sm_offset, MIB_CE_DATA_SPEED_LIMIT_VLAN_Tp entry)
{
	rtk_rg_aclFilterAndQos_t aclRule;
	int aclIdx, ret;
	FILE *fp;
	int share_meter_id = DATA_SPEED_LIMIT_SM_ID_START + dir * MAX_DATA_SPEED_LIMIT_ENTRY + sm_offset;

	if(entry == NULL)
		return -1;

	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));

	aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	aclRule.action_type = ACL_ACTION_TYPE_QOS;

	aclRule.filter_fields |= INGRESS_PORT_BIT;
	if(dir == QOS_DIRECTION_UPSTREAM)
	{
		//By default is filter packets from ALL LAN port.
		aclRule.ingress_port_mask.portmask = RG_get_all_lan_phyPortMask();
	}
	else if(dir == QOS_DIRECTION_DOWNSTREAM)
		aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();

	aclRule.filter_fields |= INGRESS_CTAGIF_BIT;
	if(entry->vlan >= 0)
	{
		aclRule.ingress_ctagIf = 1;
		aclRule.filter_fields |= INGRESS_CTAG_VID_BIT;
		aclRule.ingress_ctag_vid = entry->vlan;
	}
	else
		aclRule.ingress_ctagIf = 0;
	
	rtk_rg_shareMeter_set(share_meter_id, entry->speed_unit * 512, RTK_RG_ENABLED);
	aclRule.qos_actions=ACL_ACTION_SHARE_METER_BIT;
	aclRule.action_share_meter = share_meter_id;

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

/**
 * dir: 0:up, 1: down
 * share_meter_offset: Use dir and share_meter_offset to locate the share meter entry.
*/
int RTK_RG_data_speed_limit_ip_set(int dir, int sm_offset, MIB_CE_DATA_SPEED_LIMIT_IP_Tp entry)
{
	rtk_rg_aclFilterAndQos_t aclRule;
	int aclIdx, ret;
	FILE *fp;
	int share_meter_id = DATA_SPEED_LIMIT_SM_ID_START + dir * MAX_DATA_SPEED_LIMIT_ENTRY + sm_offset;
	struct in_addr ipv4_addr;
	unsigned char empty_ipv6[IPV6_ADDR_LEN] = {0};

	if(entry == NULL)
		return -1;

	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));

	aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	aclRule.action_type = ACL_ACTION_TYPE_QOS;

	aclRule.filter_fields |= INGRESS_PORT_BIT;
	if(dir == QOS_DIRECTION_UPSTREAM)
	{
		//By default is filter packets from ALL LAN port.
		aclRule.ingress_port_mask.portmask = RG_get_all_lan_phyPortMask();
		if(entry->ip_ver == IPVER_IPV6)
		{
			aclRule.filter_fields |= INGRESS_IPV6_TAGIF_BIT;
			aclRule.ingress_ipv6_tagif = 1;

			aclRule.filter_fields |= INGRESS_IPV6_SIP_RANGE_BIT;
			if(inet_pton(AF_INET6, entry->ip_start, (void *)aclRule.ingress_src_ipv6_addr_start) != 1)
			{
				fprintf(stderr, "<%s:%d> invalid IP address: %s\n", __func__, __LINE__, entry->ip_start);
				return -1;
			}

			if(inet_pton(AF_INET6, entry->ip_end, (void *)aclRule.ingress_src_ipv6_addr_end) != 1)
			{
				fprintf(stderr, "<%s:%d> invalid IP address: %s\n", __func__, __LINE__, entry->ip_end);
				return -1;
			}
		}
		else
		{
			aclRule.filter_fields |= INGRESS_IPV4_TAGIF_BIT;
			aclRule.ingress_ipv4_tagif = 1;

			aclRule.filter_fields |= INGRESS_IPV4_SIP_RANGE_BIT;
			if(inet_pton(AF_INET, entry->ip_start, (void *)&ipv4_addr) != 1)
			{
				fprintf(stderr, "<%s:%d> invalid IP address: %s\n", __func__, __LINE__, entry->ip_start);
				return -1;
			}
			aclRule.ingress_src_ipv4_addr_start = ntohl(ipv4_addr.s_addr);

			if(inet_pton(AF_INET, entry->ip_end, (void *)&ipv4_addr) != 1)
			{
				fprintf(stderr, "<%s:%d> invalid IP address: %s\n", __func__, __LINE__, entry->ip_end);
				return -1;
			}
			aclRule.ingress_src_ipv4_addr_end = ntohl(ipv4_addr.s_addr);
		}
	}
	else if(dir == QOS_DIRECTION_DOWNSTREAM)
	{
		aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();

		if(entry->ip_ver == IPVER_IPV6)
		{
			aclRule.filter_fields |= INGRESS_IPV6_TAGIF_BIT;
			aclRule.ingress_ipv6_tagif = 1;

			aclRule.filter_fields |= INGRESS_IPV6_DIP_RANGE_BIT;
			if(inet_pton(AF_INET6, entry->ip_start, (void *)aclRule.ingress_dest_ipv6_addr_start) != 1)
			{
				fprintf(stderr, "<%s:%d> invalid IP address: %s\n", __func__, __LINE__, entry->ip_start);
				return -1;
			}

			if(inet_pton(AF_INET6, entry->ip_end, (void *)aclRule.ingress_dest_ipv6_addr_end) != 1)
			{
				fprintf(stderr, "<%s:%d> invalid IP address: %s\n", __func__, __LINE__, entry->ip_end);
				return -1;
			}
		}
		else
		{
			aclRule.filter_fields |= INGRESS_IPV4_TAGIF_BIT;
			aclRule.ingress_ipv4_tagif = 1;

			aclRule.filter_fields |= EGRESS_IPV4_DIP_RANGE_BIT;
			if(inet_pton(AF_INET, entry->ip_start, (void *)&ipv4_addr) != 1)
			{
				fprintf(stderr, "<%s:%d> invalid IP address: %s\n", __func__, __LINE__, entry->ip_start);
				return -1;
			}
			aclRule.egress_dest_ipv4_addr_start = ntohl(ipv4_addr.s_addr);

			if(inet_pton(AF_INET, entry->ip_end, (void *)&ipv4_addr) != 1)
			{
				fprintf(stderr, "<%s:%d> invalid IP address: %s\n", __func__, __LINE__, entry->ip_end);
				return -1;
			}
			aclRule.egress_dest_ipv4_addr_end  = ntohl(ipv4_addr.s_addr);
		}
	}

	rtk_rg_shareMeter_set(share_meter_id, entry->speed_unit * 512, RTK_RG_ENABLED);
	aclRule.qos_actions=ACL_ACTION_SHARE_METER_BIT;
	aclRule.action_share_meter = share_meter_id;

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

#else
int RTK_RG_QoS_Car_Rule_Set(MIB_CE_IP_TC_Tp qos_entry)
{
	rtk_rg_aclFilterAndQos_t aclRule;
	MIB_CE_ATM_VC_T vc_entry;
	int aclIdx, ret, i, total_vc;
	FILE *fp;
	ipaddr_t mask;
	unsigned char empty_ipv6[IPV6_ADDR_LEN] = {0};

	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));

	aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	aclRule.action_type = ACL_ACTION_TYPE_QOS;

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
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		unsigned char qosEnable=0;
#endif
	
	fd = open(TR142_DEV_FILE, O_WRONLY);
	if(fd < 0)
	{
		DBPRINT(1, "ERROR: failed to open %s\n", TR142_DEV_FILE);
		return;
	}
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		mib_get(MIB_QOS_ENABLE_QOS, (void*)&qosEnable);
#endif

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

		queues.queue[i].enable = qEntry.enable;
		queues.queue[i].type = (policy== 0) ? STRICT_PRIORITY : WFQ_WRR_PRIORITY;
		queues.queue[i].weight = (policy== 1) ? qEntry.weight : 0;
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		printf("upmaxrate = %d qEntry.dscp=%d logEnable=%d\n",qEntry.upmaxrate,qEntry.dscp,qEntry.logEnable);
		if ((qEntry.upmaxrate) & 0x7)
			queues.queue[i].pir = ((qEntry.upmaxrate)>>3) + 1;
		else
			queues.queue[i].pir = (qEntry.upmaxrate)>>3;
		queues.queue[i].dscpval = qEntry.dscp;
		queues.queue[i].logEnable= qEntry.logEnable;
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
#endif

int RTK_RG_QoS_Queue_Set()
{
	unsigned char policy;
	int aclIdx, i, ret;
	rtk_rg_qos_queue_weights_t q_weight;
	int lanPhyPort;
#if defined(CONFIG_GPON_FEATURE) || defined(CONFIG_EPON_FEATURE)
	unsigned int pon_mode;
	int wanPhyPort;
#endif
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	MIB_CE_IP_QOS_QUEUE_T qEntry;
	unsigned char qosEnable=0;
	int qnum;
	unsigned int upRate, downRate;//kbps
	int qid, meteridx;
		
	rtk_ponmac_queue_t queue;
	rtk_ponmac_queueCfg_t  queueCfg;
	int downmaxrate_flag = 0;
#endif
#if defined(CONFIG_USER_LAN_PORT_AS_ETH_WAN)
	int ethPhyPortId = -1;
	mib_get(MIB_ETH_WAN_PORT_PHY_INDEX, &ethPhyPortId);
#endif

	memset(&q_weight, 0, sizeof(q_weight));
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	mib_get(MIB_QOS_ENABLE_QOS, (void*)&qosEnable);
	if(qosEnable)
#endif
	{
		if(!mib_get(MIB_QOS_POLICY, (void *)&policy))
		{
			DBPRINT(1, "MIB get MIB_QOS_POLICY failed!\n");
			return -2;
		}
	}

	if(policy == 0) // PRIO
	{
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		int i = 0;
		for(i=0;i<RTK_RG_MAX_NUM_OF_QUEUE;i++){
			q_weight.weights[i]=0;
		}
#else

		q_weight.weights[6] = 0; // Queue4~7: Strict Priority
		q_weight.weights[5] = 0;
		q_weight.weights[4] = 0;
#if defined(CONFIG_EPON_FEATURE)
		q_weight.weights[3] = 0;
#else
		q_weight.weights[7] = 0;
#endif
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
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
			if( i <= 7 )
				q_weight.weights[7-i] = qEntry.weight;
#else
			if( i <= 4 )
				q_weight.weights[6-i] = qEntry.weight;
#endif			
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


#if defined(CONFIG_GPON_FEATURE)
	if (mib_get(MIB_PON_MODE, (void *)&pon_mode) == 0)
		printf("get MIB_PON_MODE failed!!!\n");
#if 0
	if(mib_get(MIB_WAN_PHY_PORT , (void *)&wanPhyPort) == 0)
		printf("get MIB_WAN_PHY_PORT failed!!!\n");
#endif
	if((wanPhyPort = RG_get_wan_phyPortId()) == -1)
		printf("get wan phy port id failed!!!\n");
#endif

#ifdef CONFIG_TR142_MODULE
	if(pon_mode==GPON_MODE)
		setup_pon_queues(policy);
#endif
	for( i = 0; i < 6; i++ )
	{
#if defined(CONFIG_GPON_FEATURE)
		//In GPON, queue in PON port should be set by OMCI, so ignore it.
		if ((pon_mode==GPON_MODE) && (i==wanPhyPort))
			continue;
#endif
#if defined(CONFIG_EPON_FEATURE)
		if((wanPhyPort = RG_get_wan_phyPortId()) == -1)
			printf("get wan phy port id failed!!!\n");
		if ((pon_mode==EPON_MODE) && (i==wanPhyPort))
		{
			if((ret = rtk_rg_qosStrictPriorityOrWeightFairQueue_set(wanPhyPort, q_weight)) != 0)
			DBPRINT(1, "rtk_qos_schedulingQueue_set failed! (ret=%d, i=%d)\n", ret, i);
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
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
#if 1
	//disable switch port share meter because of no enough hw resources
	downmaxrate_flag = 0;
#else
	qnum = mib_chain_total(MIB_IP_QOS_QUEUE_TBL);
	/**************** per-queue rate configuration *****************/
	for (qid=0; (qid<qnum)&&(qid<RTK_RG_MAX_NUM_OF_QUEUE); qid++)
	{
			if(!mib_chain_get(MIB_IP_QOS_QUEUE_TBL, qid, (void*)&qEntry))
					continue;
			if(qEntry.downmaxrate>0){
				downmaxrate_flag = 1;
				break;
			}
	}
#endif	
				
	if (qosEnable)
	{
		//1. config maximum rate on shared meters
		qnum = mib_chain_total(MIB_IP_QOS_QUEUE_TBL);
		
		
		/* here i means port num
		 * wan port is PON, queue type/weight/pir/cir is set separately.
		 */
		if(downmaxrate_flag){
			for ( i = 0; i < SW_LAN_PORT_NUM; i++ )
			{
				for (qid=0; (qid<qnum)&&(qid<RTK_RG_MAX_NUM_OF_QUEUE); qid++)
				{
					if(!mib_chain_get(MIB_IP_QOS_QUEUE_TBL, qid, (void*)&qEntry))
						continue;
					meteridx =8*i+qid;
					printf("set meter %d downmaxrate %d\n",meteridx,qEntry.downmaxrate?qEntry.downmaxrate:RG_SHAREMETER_UNLIMITED_SPEED);
					rtk_rg_shareMeter_set(meteridx, qEntry.downmaxrate?qEntry.downmaxrate:RG_SHAREMETER_UNLIMITED_SPEED, 1);
				}
			}
		
			//enable per-port/per-queue rate limit
			for ( i = 0; i < SW_LAN_PORT_NUM; i++ )
				for (qid=0; (qid<qnum)&&(qid<RTK_RG_MAX_NUM_OF_QUEUE); qid++)
				{
#ifdef CONFIG_EPON_FEATURE
					rtk_rg_rate_egrQueueBwCtrlEnable_set(i, ACL_QOS_INTERNAL_PRIORITY_START-1-qid, 1);
#else
					rtk_rg_rate_egrQueueBwCtrlEnable_set(i, 7-qid, 1);
#endif
			}
		}
		//set per-prt / per queue share meter index
		for( i = 0; i < SW_PORT_NUM; i++ )
		{
			if (4 == i)//wan port
			{
#if defined(CONFIG_GPON_FEATURE)
				if(pon_mode==GPON_MODE)//set by setup_pon_queues
					continue;
#endif
				for (qid=0; (qid<qnum)&&(qid<RTK_RG_MAX_NUM_OF_QUEUE); qid++)
				{
					if(!mib_chain_get(MIB_IP_QOS_QUEUE_TBL, qid, (void*)&qEntry))
						continue;
						
					queue.schedulerId = 0;
#ifdef CONFIG_EPON_FEATURE
#ifdef CONFIG_RG_RTL9607C_SERIES
					//ramen 20180129 9607C/9603C has supported 7 queues and extra one queue for OAM
					queue.queueId = 7-qid;
#else
					queue.queueId = 6-qid;
#endif
#else
					queue.queueId = 7-qid;
#endif
						
					rtk_ponmac_queue_get(&queue,&queueCfg);
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
					unsigned int bandwidth = getUpLinkRate();
					fprintf(stderr,"bandwidth=%d policy=%d qEntry.weight=%d\n",bandwidth,policy,qEntry.weight);
					if(bandwidth&&policy==1){
						qEntry.upmaxrate =(bandwidth*qEntry.weight)/100;
						fprintf(stderr,"bandwidth=%d policy=%d upmaxrate=%d\n",bandwidth,policy,qEntry.upmaxrate);
					}
#endif
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)

					if(qEntry.upmaxrate){
#endif						
						if ((qEntry.upmaxrate) & 0x7)
							queueCfg.pir = ((qEntry.upmaxrate)>>3) + 1;
						else
							queueCfg.pir = (qEntry.upmaxrate)>>3;
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)						
					}else{
							queueCfg.pir = 131071;
					}
#endif	

					queueCfg.type = STRICT_PRIORITY;
					queueCfg.type =(policy==0)? STRICT_PRIORITY:WFQ_WRR_PRIORITY;
					if(queueCfg.type==WFQ_WRR_PRIORITY)
						queueCfg.weight=qEntry.weight;

					rtk_ponmac_queue_add(&queue, &queueCfg);
				}
			}
			else
			{
				if(downmaxrate_flag){
					for (qid=0; (qid<qnum)&&(qid<RTK_RG_MAX_NUM_OF_QUEUE); qid++)
					{
#ifdef CONFIG_EPON_FEATURE
							rtk_rg_rate_egrQueueBwCtrlMeterIdx_set(i, ACL_QOS_INTERNAL_PRIORITY_START-1-qid, 8*i+qid);
#else
							rtk_rg_rate_egrQueueBwCtrlMeterIdx_set(i, 7-qid, 8*i+qid);
#endif
					}
				}
			}
		}
	
		//set port based priority to lowest(3)
		for ( i = 0; i <= 6; i++ ) {
#ifdef CONFIG_EPON_FEATURE
			rtk_qos_portPri_set(i, ACL_QOS_INTERNAL_PRIORITY_START-qnum);
#else
			rtk_qos_portPri_set(i, 3);
#endif
		}
	
		//set dscp based priority to lowest(3)
		for (i=0; i<64; i++)
		{
			uint32 intPri, DP;
				
			rtk_qos_dscpPriRemapGroup_get(0, i, &intPri, &DP);
#ifdef CONFIG_EPON_FEATURE
			rtk_qos_dscpPriRemapGroup_set(0, i,  ACL_QOS_INTERNAL_PRIORITY_START-qnum, DP);
#else
			rtk_qos_dscpPriRemapGroup_set(0, i, 3, DP);
#endif
		}
	
		//set Dot1Q based priority to lowest(3)
		for (i=0; i<8; i++)
		{
			uint32 intPri, DP;
	
			rtk_qos_1pPriRemapGroup_get(0, i, &intPri, &DP);
#ifdef CONFIG_EPON_FEATURE
			rtk_qos_1pPriRemapGroup_set(0, i,  ACL_QOS_INTERNAL_PRIORITY_START-qnum, DP);
#else
			rtk_qos_1pPriRemapGroup_set(0, i, 3, DP);
#endif
		}
			
		//priority weight remapping
		for ( i = 0; i <= 6; i++ )
		{
			uint32 grpIdx;
			rtk_qos_priSelWeight_t weight;
			
			rtk_qos_portPriSelGroup_get(i, &grpIdx);

			weight.weight_of_acl = 15;
			weight.weight_of_l4Based = 14;
			weight.weight_of_portBased = 13;
			weight.weight_of_saBaed = 12;
			weight.weight_of_lutFwd = 11;
			weight.weight_of_svlanBased = 9;
			weight.weight_of_vlanBased = 10;
			weight.weight_of_dot1q = 2;
			weight.weight_of_dscp = 0;
			rtk_qos_priSelGroup_set(grpIdx, &weight);
		}
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
#if 1
#else
		printf("echo 1 > /proc/rg/turn_on_acl_counter\n");
		system("echo 1 > /proc/rg/turn_on_acl_counter");
		printf("set switch each port mib log to bytes\n");
		for(i=0;i<qnum;i++){
			rtk_rg_aclLogCounterControl_set(30-i*2,STAT_LOG_TYPE_BYTECNT,STAT_LOG_MODE_64BITS);
		}
		printf("echo 0 > /proc/rg/turn_on_acl_counter\n");
		system("echo 0 > /proc/rg/turn_on_acl_counter");
#endif		
#endif
	}
	else
	{
		qnum = mib_chain_total(MIB_IP_QOS_QUEUE_TBL);
			
		//disable per-port/per-queue rate limit
		for ( i = 0; i < SW_LAN_PORT_NUM; i++ )
			for (qid=0; (qid<qnum)&&(qid<RTK_RG_MAX_NUM_OF_QUEUE); qid++)
#ifdef CONFIG_EPON_FEATURE
				rtk_rg_rate_egrQueueBwCtrlEnable_set(i, ACL_QOS_INTERNAL_PRIORITY_START-1-qid, 0);
#else
				rtk_rg_rate_egrQueueBwCtrlEnable_set(i, 7-qid, 0);
#endif
		if(downmaxrate_flag){
			//delete shared meter entry
			for ( i = 0; i < SW_LAN_PORT_NUM; i++ )
			{
				for (qid=0; (qid<qnum)&&(qid<RTK_RG_MAX_NUM_OF_QUEUE); qid++)
				{
					if(!mib_chain_get(MIB_IP_QOS_QUEUE_TBL, qid, (void*)&qEntry))
						continue;
		
					//set shared meters rate
					meteridx = 8*i+qid;
					rtk_rg_shareMeter_set(meteridx, 0, 0);
				}
			}
		}	
			//reset PON MAC
#if defined(CONFIG_GPON_FEATURE)
		if(pon_mode!=GPON_MODE)//set by setup_pon_queues
#endif
			for (qid=0; (qid<qnum)&&(qid<RTK_RG_MAX_NUM_OF_QUEUE); qid++)
			{
				queue.schedulerId = 0;
#ifdef CONFIG_EPON_FEATURE
#ifdef CONFIG_RG_RTL9607C_SERIES
				queue.queueId = 7-qid;
#else
				queue.queueId = 6-qid;
#endif
#else
				queue.queueId = 7-qid;
#endif
				rtk_ponmac_queue_get(&queue,&queueCfg); 	
				queueCfg.pir = 131071;
				rtk_ponmac_queue_add(&queue, &queueCfg);
			}
	
			//reset port based priority to 0
		for ( i = 0; i <= 6; i++ ) {
			rtk_qos_portPri_set(i, 0);
		}
			
			//reset dscp based priority
		for (i=0; i<64; i++)
		{
			uint32 intPri, DP;
				
			rtk_qos_dscpPriRemapGroup_get(0, i, &intPri, &DP);
			rtk_qos_dscpPriRemapGroup_set(0, i, 0, DP);
		}
	
		//reset Dot1Q based priority
		for (i=0; i<8; i++)
		{
			uint32 intPri, DP;
	
			rtk_qos_1pPriRemapGroup_get(0, i, &intPri, &DP);
			rtk_qos_1pPriRemapGroup_set(0, i, i, DP);
		}
			
		//priority weight remapping
		for ( i = 0; i <= 6; i++ )
		{
			uint32 grpIdx;
			rtk_qos_priSelWeight_t weight;
				
			rtk_qos_portPriSelGroup_get(i, &grpIdx);
	
			weight.weight_of_acl = 15;
			weight.weight_of_l4Based = 11;
			weight.weight_of_portBased = 1;
			weight.weight_of_saBaed = 13;
			weight.weight_of_lutFwd = 14;
			weight.weight_of_svlanBased = 9;
			weight.weight_of_vlanBased = 10;
			weight.weight_of_dot1q = 2;
			weight.weight_of_dscp = 0;
			rtk_qos_priSelGroup_set(grpIdx, &weight);
		}
	}
#endif
	return 0;
}

int RTK_RG_QoS_Queue_Remove()
{
	int wanPhyPort;
#if defined(CONFIG_EPON_FEATURE)
	int  i, ret, lanPhyPort;
	rtk_rg_qos_queue_weights_t q_weight;
#endif
#if  defined(CONFIG_TR142_MODULE) || defined(CONFIG_EPON_FEATURE) || defined(CONFIG_GPON_FEATURE)
	unsigned int pon_mode;

	if (mib_get(MIB_PON_MODE, (void *)&pon_mode) == 0)
		printf("get MIB_PON_MODE failed!!!\n");

#if  defined(CONFIG_TR142_MODULE)
	if (pon_mode==GPON_MODE)
		clear_pon_queues();
#endif
#endif
#if defined(CONFIG_USER_LAN_PORT_AS_ETH_WAN)
	int ethPhyPortId = -1;
	mib_get(MIB_ETH_WAN_PORT_PHY_INDEX, &ethPhyPortId);
#endif

	if((wanPhyPort = RG_get_wan_phyPortId()) == -1)
                printf("get wan phy port id failed!!!\n");

#if defined(CONFIG_EPON_FEATURE)
	memset(&q_weight, 0, sizeof(q_weight));

	for( i = 0; i < 6; i++ )
	{
		if ((pon_mode==GPON_MODE) && (i==wanPhyPort))
			continue;
		
		lanPhyPort= RG_get_lan_phyPortId(i);
		if (lanPhyPort < 0 ) continue; //Iulian , port mapping fail in 9602 series
#if defined(CONFIG_USER_LAN_PORT_AS_ETH_WAN)
		if (lanPhyPort == ethPhyPortId)
			continue;
#endif
		if((ret = rtk_rg_qosStrictPriorityOrWeightFairQueue_set(lanPhyPort, q_weight)) != 0)
			DBPRINT(1, "rtk_qos_schedulingQueue_set failed! (ret=%d, i=%d)\n", ret, i);
	}

#endif

	return 0;
}

int do_special_handle_RTP(int prior)
{
	FILE *fp=NULL;
	int aclIdx,ret;
	rtk_rg_alg_type_t alg_app;


	rtk_rg_naptFilterAndQos_t naptFilter;

	//enable SIP alg
	rtk_rg_algApps_get(&alg_app);
	alg_app|= (RTK_RG_ALG_SIP_TCP_BIT|RTK_RG_ALG_SIP_UDP_BIT);
	printf("ALG APP is 0x%x\n",alg_app);
	rtk_rg_algApps_set(alg_app);

	memset(&naptFilter, 0, sizeof(rtk_rg_naptFilterAndQos_t));

	naptFilter.ingress_dest_l4_port = 5060;
	naptFilter.assign_priority = 8-prior;
	naptFilter.action_fields |= ASSIGN_NAPT_PRIORITY_BIT;
	naptFilter.filter_fields |= INGRESS_DPORT;

	if(!(fp = fopen(RG_QOS_RTP_RULES_FILE, "a")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -2;
	}

	if((ret = rtk_rg_naptFilterAndQos_add(&aclIdx, &naptFilter)) == 0)
		fprintf(fp, "%d\n", aclIdx);
	else
		printf("rtk_rg_apollo_naptFilterAndQos_add  QoS rule failed! (ret = %d)\n", ret);

	fclose(fp);
	return 0;
}


int clean_special_handle_RTP()
{
	FILE *fp=NULL;
	int qos_idx;

	if(!(fp = fopen(RG_QOS_RTP_RULES_FILE, "r")))
		return -2;

	while(fscanf(fp, "%d\n", &qos_idx) != EOF)
	{
		if(rtk_rg_naptFilterAndQos_del(qos_idx))
			DBPRINT(1, "rtk_rg_apollo_naptFilterAndQos_del failed! idx = %d\n", qos_idx);
	}

	fclose(fp);
	unlink(RG_QOS_RTP_RULES_FILE);
	return 0;
}

#if defined(CONFIG_USER_PPPOE_PROXY)
int RTK_RG_PPPoEProxy_ACL_Rule_Set(MIB_CE_ATM_VC_Tp pentry)
{
	FILE *fp;
	rtk_rg_aclFilterAndQos_t aclRule;
	int aclIdx, ret;

	if(!pentry->PPPoEProxyEnable || pentry->itfGroup == 0)
		return -1;
	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));

	aclRule.fwding_type_and_direction =  ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	aclRule.action_type = ACL_ACTION_TYPE_TRAP_TO_PS;
	aclRule.acl_weight = RG_DEFAULT_ACL_WEIGHT;
	aclRule.filter_fields |= INGRESS_PORT_BIT;
#ifdef CONFIG_RTL9602C_SERIES
	aclRule.ingress_port_mask.portmask = RG_get_lan_phyPortMask((pentry->itfGroup)&0x3);
#else
	aclRule.ingress_port_mask.portmask = RG_get_lan_phyPortMask((pentry->itfGroup)&0xf);
#endif
#ifdef WLAN_SUPPORT
	if(pentry->itfGroup>>4)//bind wlan
	{
		aclRule.filter_fields |= INGRESS_WLANDEV_BIT;
		aclRule.ingress_wlanDevMask = (((pentry->itfGroup>>ITFGROUP_WLAN0_DEV_BIT)&ITFGROUP_WLAN_MASK)<<RG_RET_MBSSID_MASTER_ROOT_INTF) | (((pentry->itfGroup>>ITFGROUP_WLAN1_DEV_BIT)&ITFGROUP_WLAN_MASK)<<RG_RET_MBSSID_SLAVE_ROOT_INTF) ;
	}
#endif

	aclRule.filter_fields |= INGRESS_ETHERTYPE_BIT;
	aclRule.ingress_ethertype =  0x8864;

	if(!(fp = fopen(RG_PPPOEPROXY_RULES_FILE, "w")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -2;
	}

	if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0)
		fprintf(fp, "%d\n", aclIdx);
	else
		printf("rtk_rg_aclFilterAndQos_add PPPoEProxy rule failed! (ret = %d)\n", ret);

	fclose(fp);
	return 0;
}

int RTK_RG_PPPoEProxy_ACL_Rule_Flush()
{
	FILE *fp;
	int acl_idx;

	if(!(fp = fopen(RG_PPPOEPROXY_RULES_FILE, "r")))
		return -2;

	while(fscanf(fp, "%d\n", &acl_idx) != EOF)
	{
		if(rtk_rg_aclFilterAndQos_del(acl_idx))
			DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", acl_idx);
	}

	fclose(fp);
	unlink(RG_PPPOEPROXY_RULES_FILE);
	return 0;
}
#endif
int RTK_RG_USER_APP_ACL_Rule_Flush(void)
{
	FILE *fp;
	int acl_idx;

	if(!(fp = fopen(RG_ACL_USER_APP_RULES_FILE, "r")))
		return -2;

	while(fscanf(fp, "%d\n", &acl_idx) != EOF)
	{
		if(rtk_rg_aclFilterAndQos_del(acl_idx))
			DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", acl_idx);
	}

	fclose(fp);
	unlink(RG_ACL_USER_APP_RULES_FILE);
	return 0;

	return 0;
}

int RTK_RG_USER_APP_ACL_Rule_Set(void)
{
	FILE *fp;
	int acl_idx=-1, ret;
	rtk_rg_aclFilterAndQos_t aclRule;

	if(!(fp = fopen(RG_ACL_USER_APP_RULES_FILE, "w")))
		return -2;
	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	aclRule.fwding_type_and_direction =  ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	aclRule.acl_weight = RG_QOS_USER_APP_WEIGHT;
	aclRule.filter_fields |= INGRESS_PORT_BIT;
	aclRule.action_type = ACL_ACTION_TYPE_QOS;
	aclRule.ingress_port_mask.portmask = RG_get_all_lan_phyPortMask() | (1<<RTK_RG_PORT_CPU);
	aclRule.filter_fields |= INGRESS_L4_DPORT_RANGE_BIT;
	//acl to speedup well known port, http,ftp,ssh,dns...
	aclRule.ingress_dest_l4_port_start = 20;
	aclRule.ingress_dest_l4_port_end = 500;
	aclRule.qos_actions |= ACL_ACTION_ACL_PRIORITY_BIT;
	aclRule.action_acl_priority = ACL_QOS_INTERNAL_PRIORITY_START - 3;
	if(aclRule.action_acl_priority>7){
		AUG_PRT("%s-%d action_acl_priority can't > 7!!\n",__func__,__LINE__);
		return -1;
	}
	if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &acl_idx)) == 0)
		fprintf(fp, "%d\n", acl_idx);
	else
		printf("rtk_rg_aclFilterAndQos_add user app rule failed! (ret = %d)\n", ret);

	fclose(fp);

	return 0;
}

static int rg_apply_acl(rtk_rg_aclFilterAndQos_t *paclRule, FILE *fp)
{
	int ret = 0;
    int aclIdx;
	if((ret = rtk_rg_aclFilterAndQos_add(paclRule, &aclIdx)) == 0)
		fprintf(fp, "%d\n", aclIdx);
	else
		printf("rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n", ret);   

	if(ret == 0)
    	return aclIdx;
	else
		return -1;
}
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
int RTK_RG_QoS_Rule_Set_defaultDSRule(){
#if 1
#else
	rtk_rg_aclFilterAndQos_t aclRule;
	FILE* fp=NULL;
	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	int queue_Num = mib_chain_total(MIB_IP_QOS_QUEUE_TBL);
	aclRule.fwding_type_and_direction =  ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	aclRule.action_type = ACL_ACTION_TYPE_QOS;
	aclRule.qos_actions |= ACL_ACTION_ACL_PRIORITY_BIT;
	aclRule.action_acl_priority = ACL_QOS_INTERNAL_PRIORITY_START -queue_Num;
	aclRule.filter_fields |= INGRESS_PORT_BIT;
	aclRule.ingress_port_mask.portmask = (1<<RTK_RG_PORT_PON);
	aclRule.qos_actions |= ACL_ACTION_LOG_COUNTER_BIT;
	aclRule.action_log_counter=30-((queue_Num-1)*2);
	aclRule.acl_weight = RG_DEFAULT_ACL_WEIGHT;
	if(!(fp = fopen(RG_QOS_RULES_FILE, "a")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -2;
	}
	system("echo 1 > /proc/rg/turn_on_acl_counter");
         rg_apply_acl(&aclRule, fp);
	system("echo 0 > /proc/rg/turn_on_acl_counter");	 
	fclose(fp);
#endif
}

/*
	put the all of the no specified priority to default priority
*/

int RTK_RG_QoS_Rule_Set_defaultUSRule(){
	rtk_rg_aclFilterAndQos_t aclRule;
	FILE* fp=NULL;
	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	aclRule.fwding_type_and_direction =  ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	aclRule.filter_fields |= INGRESS_PORT_BIT;
	aclRule.ingress_port_mask.portmask = RG_get_all_lan_phyPortMask();
#ifdef WLAN_SUPPORT //master and slave ext port
	aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN0));
	aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN1));
	aclRule.ingress_port_mask.portmask |= (1 << RTK_RG_PORT_CPU);
#endif
	aclRule.action_type = ACL_ACTION_TYPE_FLOW_MIB;		
	aclRule.action_flowmib_counter_idx = 0;
	aclRule.acl_weight = RG_DEFAULT_ACL_WEIGHT;
	if(!(fp = fopen(RG_QOS_RULES_FILE, "a")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -2;
	}
    rg_apply_acl(&aclRule, fp); 
	fclose(fp);
	return 0;
}

#endif
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
int RTK_RG_QoS_Rule_Set_DownstreamACLRule(MIB_CE_IP_QOS_Tp qos_entry,rtk_rg_aclFilterAndQos_t* aclRule,FILE *fp){
#if 1
	return 1;
#else	
			//fix the stream direction
			//uint32 lanip=0;
			//uint32 lanmask=0;
			//if ((mib_get(MIB_ADSL_LAN_IP, (void *)&lanip) != 0)&&(mib_get(MIB_ADSL_LAN_SUBNET, (void *)&lanmask) != 0))
			//if(((aclRule.ingress_dest_ipv4_addr_start&lanmask)==(lanip&lanmask))&&((aclRule.ingress_dest_ipv4_addr_end&lanmask)==(lanip&lanmask)))
			//if(qos_entry->phyPort==0)
			//	return 0;
			if((qos_entry->IpProtocol==IPVER_IPV4)&&(strlen(qos_entry->dip)>0)
				&&(qos_entry->dmaskbit!=0)&&(qos_entry->smaskbit==0)
				&&(qos_entry->sPort==0)&&(qos_entry->sPortRangeMax==0))
			{
				rtk_rg_aclFilterAndQos_t ds_aclRule;
				memcpy(&ds_aclRule,aclRule,sizeof(ds_aclRule));
				ds_aclRule.ingress_src_ipv4_addr_start = ds_aclRule.ingress_dest_ipv4_addr_start;
				ds_aclRule.ingress_src_ipv4_addr_end = ds_aclRule.ingress_dest_ipv4_addr_end;
				ds_aclRule.filter_fields |= INGRESS_IPV4_SIP_RANGE_BIT;
				ds_aclRule.filter_fields &= ~INGRESS_IPV4_DIP_RANGE_BIT;
				ds_aclRule.ingress_dest_ipv4_addr_start = 0;
				ds_aclRule.ingress_dest_ipv4_addr_end = 0;
				if(ds_aclRule.filter_fields &INGRESS_L4_DPORT_RANGE_BIT){
						ds_aclRule.filter_fields |= INGRESS_L4_SPORT_RANGE_BIT;
						ds_aclRule.ingress_src_l4_port_start=ds_aclRule.ingress_dest_l4_port_start;
						ds_aclRule.ingress_src_l4_port_end=ds_aclRule.ingress_dest_l4_port_end;
						ds_aclRule.ingress_dest_l4_port_start=ds_aclRule.ingress_dest_l4_port_end=0;
						ds_aclRule.filter_fields &= ~INGRESS_L4_DPORT_RANGE_BIT;						
				}
				ds_aclRule.filter_fields |= INGRESS_PORT_BIT;
				ds_aclRule.ingress_port_mask.portmask = (1<<RTK_RG_PORT_PON);
				ds_aclRule.qos_actions |= ACL_ACTION_LOG_COUNTER_BIT;
				ds_aclRule.action_log_counter=30-((qos_entry->prior-1)*2);
				//printf("echo 1 > /proc/rg/turn_on_acl_counter\n");
				system("echo 1 > /proc/rg/turn_on_acl_counter");
				rg_apply_acl(&ds_aclRule, fp);
				//printf("echo 0 > /proc/rg/turn_on_acl_counter\n");
				system("echo 0 > /proc/rg/turn_on_acl_counter");
				return 1;
		}		
#endif				
}

#endif
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
unsigned char getStreamIDFromWanQosQueue(int wanidx,int priority){
	   FILE* proc_rtk_tr142_waninfo_fp=NULL;
	   char *line=NULL;
	   int len = 0;
	   //char wanIdx[32];
	   int wanIdx=0;
	   int read = 0;
	   int usFlowId[ACL_QOS_INTERNAL_PRIORITY_START];
	   int findFlag = 0;
	   //printf("wanidx=%d priority=%d\n",wanidx,priority);
	   if ((proc_rtk_tr142_waninfo_fp = fopen("/proc/rtk_tr142/wan_info", "r")) == NULL){
		   return 0xff;
	   }
#if	 ACL_QOS_INTERNAL_PRIORITY_START==4		
	   while ((read = getline(&line, &len, proc_rtk_tr142_waninfo_fp)) != -1) {
				  if(strstr(line,"	wanIdx = ")&&sscanf(line, "	wanIdx = %d", &wanIdx)){
					  printf("wanIdx=%d\n",wanIdx);
				  }
				    if(wanIdx==wanidx){
					  if(sscanf(line, "	usFlowId = %d %d %d %d", &usFlowId[0],&usFlowId[1],&usFlowId[2],&usFlowId[3])){
						  printf("usFlowId=%d %d %d %d\n",usFlowId[0],usFlowId[1],usFlowId[2],usFlowId[3]);
						  findFlag = 1;
					  	  break;
					  }
				    }
				  
		 }		
#elif  ACL_QOS_INTERNAL_PRIORITY_START==8
		
		 while ((read = getline(&line, &len, proc_rtk_tr142_waninfo_fp)) != -1) {
				  if(strstr(line,"	wanIdx = ")&&sscanf(line, "	wanIdx = %d", &wanIdx)){
					  printf("wanIdx=%d\n",wanIdx);
				  }
				    if(wanIdx==wanidx){
					  if(sscanf(line, "	usFlowId = %d %d %d %d %d %d %d %d", &usFlowId[0],&usFlowId[1],&usFlowId[2],&usFlowId[3],&usFlowId[4],&usFlowId[5],&usFlowId[6],&usFlowId[7])){
						  printf("usFlowId=%d %d %d %d %d %d %d %d\n",usFlowId[0],usFlowId[1],usFlowId[2],usFlowId[3],usFlowId[4],usFlowId[5],usFlowId[6],usFlowId[7]);
						  findFlag = 1;
					  	  break;
					  }
				    }
				  
		 }		
#else
	#error  "please define ACL_QOS_INTERNAL_PRIORITY_START as 4 or 8"
#endif
	   free(line);	   	
	   fclose(proc_rtk_tr142_waninfo_fp);
	   if(findFlag)
		   	return usFlowId[priority];
	   else
			return 0xff;
}
#endif


int RTK_RG_QoS_Rule_Set(MIB_CE_IP_QOS_Tp qos_entry)
{
	rtk_rg_aclFilterAndQos_t aclRule;
	MIB_CE_ATM_VC_T vc_entry;
	int aclIdx, ret, i, total_vc, udp_tcp_rule=0;
	FILE *fp = NULL;
	ipaddr_t mask;
	unsigned char empty_ipv6[IPV6_ADDR_LEN] = {0};
	unsigned char enableDscpMark=1;
	unsigned char enableQos1p=2;  // enableQos1p=0: not use, enableQos1p=1: use old value, enableQos1p=2: mark new value
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	int pon_mode = 0;
	if (mib_get(MIB_PON_MODE, (void *)&pon_mode) == 0)
			printf("get MIB_PON_MODE failed!!!\n");

	int dscp_i = 0;
	int ctag_pri_i = 0;
	int ctag_pri_action_i=0;
	int ctag_pri_action_total = 0;
	int is_hidden_qos_rule = 0;
	for(dscp_i = 0; dscp_i<=(qos_entry->qosDscp_end-qos_entry->qosDscp);dscp_i++){
		for(ctag_pri_i = 0; ctag_pri_i<=(qos_entry->vlan1p_end-qos_entry->vlan1p);ctag_pri_i++){
			printf("%s %d dscp_i=%d ctag_pri_i=%d\n",__FUNCTION__,__LINE__,dscp_i,ctag_pri_i);
						
	is_hidden_qos_rule = 0;		
	if(!strncmp(qos_entry->RuleName,"rule_",strlen("rule_"))){
		is_hidden_qos_rule = 1;
	}
#endif

	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));

	aclRule.fwding_type_and_direction =  ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	aclRule.action_type = ACL_ACTION_TYPE_QOS;

	if(strcmp(qos_entry->RuleName,"rule_INTERNET") == 0){
		//check subr_qos_3.c
		//sprintf(p->RuleName, "%s", "rule_INTERNET");
		aclRule.acl_weight = RG_QOS_LOW_ACL_WEIGHT;
	}else
		aclRule.acl_weight = RG_QOS_ACL_WEIGHT;

#if defined(CONFIG_USER_IP_QOS) && defined(_PRMT_X_CT_COM_QOS_)
	mib_get(MIB_QOS_ENABLE_DSCP_MARK, (void *)&enableDscpMark);
	mib_get(MIB_QOS_ENABLE_1P, (void *)&enableQos1p);
#endif
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	//ramen 20180109 to fix dip is zero when the domain can't resolved
	if(strlen(qos_entry->domainName)){
		if(!memcmp(qos_entry->dip,"\x0\x0\x0\x0",4))
			return -1;
	}
#endif

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

#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	if(qos_entry->phyPort==0)
#endif
	{
	//By default is filter packets from ALL LAN port.
	aclRule.filter_fields |= INGRESS_PORT_BIT;
	aclRule.ingress_port_mask.portmask = RG_get_all_lan_phyPortMask() | (1<<RTK_RG_PORT_CPU);

#ifdef WLAN_SUPPORT
		aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN0));
#ifdef WLAN_DUALBAND_CONCURRENT
		aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN1));
#endif
		aclRule.ingress_port_mask.portmask |= (1 << RTK_RG_PORT_CPU);
#endif
	}
	// Filter rule of physic ports.
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	else {
		//support lan pyhport range
		int lanport = 0;
		for(lanport=qos_entry->phyPort;lanport<=qos_entry->phyPort_end;lanport++){
			if(lanport >= 1 && lanport <= SW_LAN_PORT_NUM)
			{
				aclRule.filter_fields |= INGRESS_PORT_BIT;
				aclRule.ingress_port_mask.portmask |= RG_get_lan_phyPortMask(1 << (lanport-1));
			}
#ifdef WLAN_SUPPORT
			else if(lanport>SW_LAN_PORT_NUM && lanport<=(SW_LAN_PORT_NUM + WLAN_SSID_NUM))
			{
				aclRule.filter_fields |= INGRESS_WLANDEV_BIT;
				aclRule.ingress_wlanDevMask |= (1 << (lanport - SW_LAN_PORT_NUM - 1));
			}
#ifdef WLAN_DUALBAND_CONCURRENT
			else if(lanport>(SW_LAN_PORT_NUM + WLAN_SSID_NUM) && lanport<=(SW_LAN_PORT_NUM + 2*WLAN_SSID_NUM))
			{
				aclRule.filter_fields |= INGRESS_WLANDEV_BIT;
				aclRule.ingress_wlanDevMask |= (1 << ((lanport - SW_LAN_PORT_NUM - WLAN_SSID_NUM - 1) + 13));
			}
#endif
#endif
		}
	}
#else	//CONFIG_CMCC	
	if(qos_entry->phyPort >= 1 && qos_entry->phyPort <= SW_LAN_PORT_NUM)
	{
		aclRule.filter_fields |= INGRESS_PORT_BIT;
		//aclRule.ingress_port_mask.portmask = (1 << RTK_RG_PORT0)  | (1 << RTK_RG_PORT1) | (1 << RTK_RG_PORT2) | (1 << RTK_RG_PORT3);
		aclRule.ingress_port_mask.portmask = RG_get_lan_phyPortMask(1 << (qos_entry->phyPort-1));
	}
#ifdef WLAN_SUPPORT
	else if(qos_entry->phyPort>SW_LAN_PORT_NUM && qos_entry->phyPort<=(SW_LAN_PORT_NUM + WLAN_SSID_NUM))
	{
		aclRule.filter_fields |= INGRESS_WLANDEV_BIT;
		aclRule.ingress_wlanDevMask = (1 << (qos_entry->phyPort - SW_LAN_PORT_NUM - 1));
	}
#ifdef WLAN_DUALBAND_CONCURRENT
	else if(qos_entry->phyPort>(SW_LAN_PORT_NUM + WLAN_SSID_NUM) && qos_entry->phyPort<=(SW_LAN_PORT_NUM + 2*WLAN_SSID_NUM))
	{
		aclRule.filter_fields |= INGRESS_WLANDEV_BIT;
		aclRule.ingress_wlanDevMask = (1 << ((qos_entry->phyPort - SW_LAN_PORT_NUM - WLAN_SSID_NUM - 1) + 13));
	}
#endif
#endif
#endif

	// Filter rule of DSCP
#ifdef QOS_DIFFSERV
	if(qos_entry->qosDscp != 0)
	{
#ifdef CONFIG_IPV6
		if(qos_entry->IpProtocol == IPVER_IPV6)
		{
			aclRule.filter_fields |= INGRESS_IPV6_DSCP_BIT;
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
			aclRule.ingress_ipv6_dscp = (qos_entry->qosDscp+dscp_i);
#else
			aclRule.ingress_ipv6_dscp = qos_entry->qosDscp >> 2;
#endif
		}
		else
#endif
		{
			aclRule.filter_fields |= INGRESS_DSCP_BIT;
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
			aclRule.ingress_dscp = (qos_entry->qosDscp+dscp_i);
#else			
			aclRule.ingress_dscp = qos_entry->qosDscp >> 2;
#endif

		}
	}
#endif
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	// Filter rule for tos
	if(qos_entry->tos != 0)
	{
		aclRule.filter_fields |= INGRESS_TOS_BIT;
		aclRule.ingress_tos = qos_entry->tos;
	}

	// Filter rule of Ether Type
	if(qos_entry->ethType != 0)
	{
		aclRule.filter_fields |= INGRESS_ETHERTYPE_BIT;
		aclRule.ingress_ethertype = qos_entry->ethType;
	}
#endif

	// Filter rule of 802.1p mark
	if(qos_entry->vlan1p != 0)
	{
		aclRule.filter_fields |= INGRESS_CTAG_PRI_BIT;
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		aclRule.ingress_ctag_pri = (qos_entry->vlan1p+ctag_pri_i-1);
#else		
		aclRule.ingress_ctag_pri = qos_entry->vlan1p - 1;
#endif
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
		else if(qos_entry->protoType == PROTO_RTP){
			do_special_handle_RTP(qos_entry->prior);
			if(fp != NULL)
				fclose(fp);				
			return 0;
		}
		else
		{
			if(fp != NULL)
				fclose(fp); 
			DBPRINT(1, "Add acl rule failed! No support of this protocol type!\n");
			return -1;
		}
	}

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
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
			aclRule.ingress_src_ipv4_addr_start = ntohl(*((ipaddr_t *)qos_entry->sip));
			aclRule.ingress_src_ipv4_addr_end = ntohl(*((ipaddr_t *)qos_entry->sip_end));
#else
			if(qos_entry->smaskbit == 0)
				aclRule.ingress_src_ipv4_addr_start = aclRule.ingress_src_ipv4_addr_end = ntohl(*((ipaddr_t *)qos_entry->sip));
			else
			{
				mask = ~0 << (sizeof(ipaddr_t)*8 - qos_entry->smaskbit);
				mask = htonl(mask);
				aclRule.ingress_src_ipv4_addr_start = ntohl(*((in_addr_t *)qos_entry->sip) & mask);
				aclRule.ingress_src_ipv4_addr_end = ntohl(*((in_addr_t *)qos_entry->sip) | ~mask);
			}
#endif			
		}

		// Destination ip, mask
		if(memcmp(qos_entry->dip, "\x00\x00\x00\x00", IP_ADDR_LEN) != 0)
		{
			aclRule.filter_fields |= INGRESS_IPV4_DIP_RANGE_BIT;
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
			aclRule.ingress_dest_ipv4_addr_start = ntohl(*((ipaddr_t *)qos_entry->dip));
			aclRule.ingress_dest_ipv4_addr_end = ntohl(*((ipaddr_t *)qos_entry->dip_end));
#else

			if(qos_entry->dmaskbit == 0)
				aclRule.ingress_dest_ipv4_addr_start = aclRule.ingress_dest_ipv4_addr_end = ntohl(*((ipaddr_t *)qos_entry->dip));
			else
			{
				mask = ~0 << (sizeof(ipaddr_t)*8 - qos_entry->dmaskbit);
				mask = htonl(mask);
				aclRule.ingress_dest_ipv4_addr_start = ntohl(*((in_addr_t *)qos_entry->dip) & mask);
				aclRule.ingress_dest_ipv4_addr_end = ntohl(*((in_addr_t *)qos_entry->dip) | ~mask);
			}
#endif			
		}
#ifdef CONFIG_IPV6
	}
#endif

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
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
				//if(qos_entry->prior != 0)
				//20180202 ramen to fix out interface qos pattern unvalid in epon mode.Epon don't need the acl to assign sid or llid,it just set the right priority is enough
				if(pon_mode==GPON_MODE)
				{
					aclRule.qos_actions |= ACL_ACTION_STREAM_ID_OR_LLID_BIT;
					aclRule.action_stream_id_or_llid= getStreamIDFromWanQosQueue(vc_entry.rg_wan_idx,ACL_QOS_INTERNAL_PRIORITY_START - qos_entry->prior);					
				}

#else
				aclRule.filter_fields &= ~(INGRESS_PORT_BIT|INGRESS_IPV4_DIP_RANGE_BIT|INGRESS_CTAG_VID_BIT|INGRESS_IPV4_DIP_RANGE_BIT|INGRESS_DMAC_BIT);		// Current RG design, using egress pattern, should not have ingress pattern
#endif				

				//IF QoS has egress pattern, let QoS be lower then normal QoS.
				//or it will be sorted to higher prioirty then other QoS rules.
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
				if(strcmp(qos_entry->RuleName,"rule_INTERNET"))
					aclRule.acl_weight = RG_QOS_WANINTERFACE_ACL_WEIGHT;
#else				
				aclRule.acl_weight = RG_QOS_LOW_ACL_WEIGHT;
#endif
			}
		}
	}


	// Action rule of DSCP
	if( enableDscpMark && (qos_entry->m_dscp != 0))
	{
		aclRule.qos_actions |= ACL_ACTION_DSCP_REMARKING_BIT;
		aclRule.action_dscp_remarking_pri = qos_entry->m_dscp >> 2;
	}

	// Action rule of IP precedence.
	if(qos_entry->prior != 0)
	{
		MIB_CE_IP_QOS_QUEUE_T qEntry;
		int qEntryNum, i;

		if(!qos_entry->classtype){
			if(!mib_chain_get(MIB_IP_QOS_QUEUE_TBL, qos_entry->prior-1, (void*)&qEntry)){
				if(fp != NULL)
					fclose(fp);						
				return -1;
			}

			if(qEntry.enable)
			{
#ifdef CONFIG_RTL9607C
				if(aclRule.filter_fields & EGRESS_INTF_BIT){
					aclRule.qos_actions |= ACL_ACTION_ACL_EGRESS_INTERNAL_PRIORITY_BIT; 				
					aclRule.egress_internal_priority = ACL_QOS_INTERNAL_PRIORITY_START - qos_entry->prior;
					if(aclRule.egress_internal_priority>7){
						AUG_PRT("%s-%d action_acl_priority can't > 7!!\n",__func__,__LINE__);
						return -1;
					}
				}else{												
#endif
					aclRule.qos_actions |= ACL_ACTION_ACL_PRIORITY_BIT;
					aclRule.action_acl_priority = ACL_QOS_INTERNAL_PRIORITY_START - qos_entry->prior;
					if(aclRule.action_acl_priority>7){
						AUG_PRT("%s-%d action_acl_priority can't > 7!!\n",__func__,__LINE__);
						return -1;
					}
#ifdef CONFIG_RTL9607C				
				}
#endif

			}
		}		
		else{	
#ifdef CONFIG_RTL9607C
			if(aclRule.filter_fields & EGRESS_INTF_BIT){
					aclRule.qos_actions |= ACL_ACTION_ACL_EGRESS_INTERNAL_PRIORITY_BIT; 				
					aclRule.egress_internal_priority = ACL_QOS_INTERNAL_PRIORITY_START - qos_entry->prior;
					if(aclRule.egress_internal_priority>7){
						AUG_PRT("%s-%d action_acl_priority can't > 7!!\n",__func__,__LINE__);
						return -1;
					}
			}else{							
#endif			
				aclRule.qos_actions |= ACL_ACTION_ACL_PRIORITY_BIT;
				aclRule.action_acl_priority = ACL_QOS_INTERNAL_PRIORITY_START - qos_entry->prior;
				if(aclRule.action_acl_priority>7){
					AUG_PRT("%s-%d action_acl_priority can't > 7!!\n",__func__,__LINE__);
					return -1;
				}	
#ifdef CONFIG_RTL9607C				
			}
#endif
		}
	}

#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		if(!is_hidden_qos_rule){
#endif		
		// 1p remarking.
			if( (enableQos1p==2) && (qos_entry->m_1p != 0))
			{
				aclRule.qos_actions |= ACL_ACTION_1P_REMARKING_BIT;
				aclRule.action_dot1p_remarking_pri = qos_entry->m_1p - 1;
			}
			else{
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
			if(enableQos1p==0){
					aclRule.qos_actions |= ACL_ACTION_1P_REMARKING_BIT;
					aclRule.action_dot1p_remarking_pri = 0;
			}else if(enableQos1p==1){
					//Do nothing for 1p remarking
					//aclRule.action_acl_cvlan.cvlanCpriDecision =ACL_CVLAN_CPRI_NOP;
					//aclRule.qos_actions |= ACL_ACTION_1P_REMARKING_BIT;
					//aclRule.action_dot1p_remarking_pri = 0;
			}
#endif		
			}
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)				
		}
#endif


	if(qos_entry->applicationtype != 0) //Add rule of connection type 
	{
		total_vc = mib_chain_total(MIB_ATM_VC_TBL);
		

		for( i = 0; i < total_vc; i++ )
		{
			if(!mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&vc_entry))
				continue;
			
			if(vc_entry.applicationtype == qos_entry->applicationtype)
			{
				if(vc_entry.cmode > 0 && !(vc_entry.applicationtype & (X_CT_SRV_INTERNET|X_CT_SRV_OTHER))){
					//[WARNING] Mix egress WAN pattern rule with non-egress-WAN pattern rule at same weight!
					aclRule.acl_weight = RG_QOS_WANINTERFACE_ACL_WEIGHT+1;
					aclRule.filter_fields |= INGRESS_SMAC_BIT;
					aclRule.filter_fields |= INGRESS_PORT_BIT;
					aclRule.ingress_port_mask.portmask = (1<<RTK_RG_PORT_CPU);
					memcpy(&aclRule.ingress_smac, vc_entry.MacAddr, MAC_ADDR_LEN);
					//AUG_PRT("\n");
				}else{
					aclRule.acl_weight = RG_QOS_WANINTERFACE_ACL_WEIGHT;
					// EGRESS_INTF_BIT conflict with INGRESS_CTAG_VID_BIT/INGRESS_PORT_BIT/INGRESS_IPV4_DIP_RANGE_BIT/INGRESS_DMAC_BIT
					aclRule.filter_fields = EGRESS_INTF_BIT; 
					if(aclRule.qos_actions & ACL_ACTION_ACL_PRIORITY_BIT)
					{	
						aclRule.qos_actions &= ~ (ACL_ACTION_ACL_PRIORITY_BIT);	
						aclRule.qos_actions |= ACL_ACTION_ACL_EGRESS_INTERNAL_PRIORITY_BIT;
					}	
					aclRule.egress_intf_idx = vc_entry.rg_wan_idx; // Set egress interface.
					//AUG_PRT("\n");
				}
				break;
			}
		}

		
		if (i == total_vc) {
			if(fp != NULL)
				fclose(fp);		
			DBPRINT(1, "Add acl rule failed! No connection type of WAN matched !\n");
			return -1;
		}
			
	}
	if(fp == NULL){
		//acl depended on wan
		if(aclRule.egress_intf_idx > 0 && (aclRule.filter_fields & EGRESS_INTF_BIT))
		{
			char filename[64] = {0};
			sprintf(filename, "%s_%d", RG_QOS_RULES_FILE, aclRule.egress_intf_idx);
			AUG_PRT("%s\n",filename);
			if (!(fp = fopen(filename, "a"))) {
				fprintf(stderr, "ERROR! %s\n", strerror(errno));
				return -2;
			}
		}
		else
		{
			//pattern not depended on wan
			if(!(fp = fopen(RG_QOS_RULES_FILE, "a")))
			{
				fprintf(stderr, "ERROR! %s\n", strerror(errno));
				return -2;
			}
		}

	}

#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	/* if dport use !x, parse it two rg_acls, sample: !80, parse it to 1~79 and 81~65535 */
	if(aclRule.qos_actions & ACL_ACTION_STREAM_ID_OR_LLID_BIT){
			if(aclRule.action_stream_id_or_llid==0xff)
				continue;
	}

	ctag_pri_action_total = 1;
	if(!is_hidden_qos_rule&&enableQos1p==1){
		ctag_pri_action_total = 8;
	}
	ctag_pri_action_i = 0;
	//20180427 ramen--if acl rule includes PRI condition,no need to add all of pris(0~7) as condition
	if(aclRule.filter_fields & INGRESS_CTAG_PRI_BIT){
		ctag_pri_action_i = aclRule.ingress_ctag_pri;
		ctag_pri_action_total=ctag_pri_action_i+1;
	}

	for(;ctag_pri_action_i<ctag_pri_action_total;ctag_pri_action_i++){
		if(!is_hidden_qos_rule&&enableQos1p==1){
			//Do nothing for 1p remarking
			//aclRule.action_acl_cvlan.cvlanCpriDecision =ACL_CVLAN_CPRI_NOP;
			//aclRule.filter_fields_inverse|= INGRESS_CTAGIF_BIT;
			aclRule.filter_fields |= INGRESS_CTAGIF_BIT;
			aclRule.ingress_ctagIf= 1;
			aclRule.filter_fields |= INGRESS_CTAG_PRI_BIT;
			aclRule.ingress_ctag_pri = ctag_pri_action_i;
			aclRule.qos_actions |= ACL_ACTION_1P_REMARKING_BIT;
			aclRule.action_dot1p_remarking_pri = ctag_pri_action_i;
		}
	    if(1 == qos_entry->dportNot) 
	    {
			aclRule.ingress_dest_l4_port_start = 1;
	        aclRule.ingress_dest_l4_port_end = qos_entry->dPort - 1;
	        rg_apply_acl(&aclRule, fp);

	        aclRule.ingress_dest_l4_port_start = qos_entry->dPort + 1;
	        aclRule.ingress_dest_l4_port_end = 65535;
	        rg_apply_acl(&aclRule, fp);
	    }
		else
	    {
	       rg_apply_acl(&aclRule, fp);
	    }
	}

#else
	if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0)
		fprintf(fp, "%d\n", aclIdx);
	else
		printf("rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n", ret);
#endif

    if(udp_tcp_rule==1){
        udp_tcp_rule = 2;
        goto add_udp_tcp;
    }
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		/*
			20170930 ramen for mib counter 
			priority i---counter id i
		*/
		do{
			aclRule.action_type = ACL_ACTION_TYPE_FLOW_MIB; 	
			aclRule.qos_actions = 0;
			aclRule.action_flowmib_counter_idx = ACL_QOS_INTERNAL_PRIORITY_START - qos_entry->prior;
			rg_apply_acl(&aclRule, fp);
		}while(0);
#endif

#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		}
	}
#endif
	fclose(fp);
	return 0;
}
int FlushRTK_RG_QoS_Rules_perWan(int wan_idx)
{
	char filename[64] = {0};
	FILE *fp = NULL;
	int qos_idx = -1;

	sprintf(filename, "%s_%d", RG_QOS_RULES_FILE, wan_idx);
	//AUG_PRT("%s\n",filename);
	if (!(fp = fopen(filename, "r"))) {
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -2;
	}
	while(fscanf(fp, "%d\n", &qos_idx) != EOF)
	{
		if(rtk_rg_aclFilterAndQos_del(qos_idx))
			DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", qos_idx);
		fprintf(stderr, "del qos ACL index=%d success\n", qos_idx);
	}

	fclose(fp);
	unlink(filename);
	return 0;
}

int FlushRTK_RG_QoS_Rules()
{
	FILE *fp;
	int qos_idx;
	int total_vc = mib_chain_total(MIB_ATM_VC_TBL);
	MIB_CE_ATM_VC_T vc_entry;
	int i;

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
	//flush per wan.
	for( i = 0; i < total_vc; i++ )
	{
		char filename[64] = {0};
		if(!mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&vc_entry))
			continue;
		if(vc_entry.rg_wan_idx > 0)
		{
			sprintf(filename, "%s_%d", RG_QOS_RULES_FILE, vc_entry.rg_wan_idx);
			AUG_PRT("%s\n",filename);
			if (!(fp = fopen(filename, "r"))) 
			{
				fprintf(stderr, "ERROR! %s\n", strerror(errno));
				return -2;
			}
			while(fscanf(fp, "%d\n", &qos_idx) != EOF)
			{
				if(rtk_rg_aclFilterAndQos_del(qos_idx))
					DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", qos_idx);
				fprintf(stderr, "del qos ACL index=%d success\n", qos_idx);
			}
			fclose(fp);
			unlink(filename);
		}

	}	
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

int FLUSH_RTK_RG_UPnP_Entry(void)
{
	FILE *fp, *fp_tmp;
	int upnp_idx;
	char line[64];
	if(!(fp = fopen(RG_UPNP_CONNECTION_FILE, "r")))
		return -2;

	while(fgets(line, 64, fp) != NULL)
	{
		sscanf(line, "%d\n", &upnp_idx);
			if(rtk_rg_upnpConnection_del(upnp_idx))
				DBPRINT(1, "rtk_rg_upnpConnection_del failed! idx = %d\n", upnp_idx);
	}
	unlink(RG_UPNP_CONNECTION_FILE);
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
			}
		}
		else
			break;
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

	if(!(fp_tmp = fopen(RG_UPNP_TMP_FILE, "w")))
		return -2;

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
int RTK_RG_FLUSH_ALG_FILTER_RULE()
{

	FILE *fp;
	int filter_idx;

	if(!(fp = fopen(RG_ALG_FILTER_FILE, "r")))
		return -2;

	while(fscanf(fp, "%d\n", &filter_idx) != EOF)
	{
		if(rtk_rg_naptFilterAndQos_del(filter_idx))
			DBPRINT(1, "rtk_rg_naptFilterAndQos_del failed! idx = %d\n", filter_idx);
	}

	fclose(fp);
	unlink(RG_ALG_FILTER_FILE);

	return 0;


}
int RTK_RG_ALG_Set()
{
	rtk_rg_alg_type_t alg_app = 0;
	rtk_rg_naptFilterAndQos_t napt_filter;
	int ret=0;
	int filterIdx=0;
	FILE *fp;
	unsigned char value = 0;

	if((ret = rtk_rg_algApps_get(&alg_app))){
		DBPRINT(1, "Error %d: rtk_rg_algApps_get failed!\n", ret);
		return -1;
	}

	if(!(fp = fopen(RG_ALG_FILTER_FILE, "w")))
		return -2;


#ifdef CONFIG_NF_CONNTRACK_FTP
	if(mib_get(MIB_IP_ALG_FTP, &value) && value == 1)
		alg_app |= RTK_RG_ALG_FTP_TCP_BIT | RTK_RG_ALG_FTP_UDP_BIT;
	else{
		alg_app &= ~(RTK_RG_ALG_FTP_TCP_BIT | RTK_RG_ALG_FTP_UDP_BIT);

		//disable alg for ftp
			memset(&napt_filter, 0, sizeof(rtk_rg_naptFilterAndQos_t));
			napt_filter.direction = RTK_RG_NAPT_FILTER_OUTBOUND;
			napt_filter.filter_fields = (L4_PROTOCAL | INGRESS_DPORT);
			napt_filter.ingress_dest_l4_port = 21; //pptp wellknown port
			napt_filter.ingress_l4_protocal = 0x6; //tcp protocol
			napt_filter.action_fields = NAPT_DROP_BIT;
			napt_filter.ruleType = RTK_RG_NAPT_FILTER_PERSIST;
			if((ret = rtk_rg_naptFilterAndQos_add( &filterIdx, &napt_filter)) == 0)
				fprintf(fp, "%d\n", filterIdx);
			else
				printf("rtk_rg_naptFilterAndQos_add QoS rule failed! (ret = %d)\n", ret);

	}
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
	else{
		alg_app &= ~(RTK_RG_ALG_H323_TCP_BIT | RTK_RG_ALG_H323_UDP_BIT);
	}
#endif
#ifdef CONFIG_NF_CONNTRACK_RTSP
	if(mib_get(MIB_IP_ALG_RTSP, &value) && value == 1)
		alg_app |= RTK_RG_ALG_RTSP_TCP_BIT | RTK_RG_ALG_RTSP_UDP_BIT;
	else{
		alg_app &= ~(RTK_RG_ALG_RTSP_TCP_BIT | RTK_RG_ALG_RTSP_UDP_BIT);
		//disable alg for rtsp
//		AUG_PRT("disable alg for tcp rtsp\n");
		memset(&napt_filter, 0, sizeof(rtk_rg_naptFilterAndQos_t));
		napt_filter.direction = RTK_RG_NAPT_FILTER_OUTBOUND;
		napt_filter.filter_fields = (L4_PROTOCAL | INGRESS_DPORT);
		napt_filter.ingress_dest_l4_port = 554; //rtsp wellknown port
		napt_filter.ingress_l4_protocal = 0x6; //tcp protocol
		napt_filter.action_fields = NAPT_DROP_BIT;
		napt_filter.ruleType = RTK_RG_NAPT_FILTER_PERSIST;
		if((ret = rtk_rg_naptFilterAndQos_add( &filterIdx, &napt_filter)) == 0)
			fprintf(fp, "%d\n", filterIdx);
		else
			printf("[%s@%d] rtk_rg_naptFilterAndQos_add QoS rule failed! (ret = %d)\n",__func__,__LINE__, ret);

//		AUG_PRT("disable alg for udp rtsp\n");
		memset(&napt_filter, 0, sizeof(rtk_rg_naptFilterAndQos_t));
		napt_filter.direction = RTK_RG_NAPT_FILTER_OUTBOUND;
		napt_filter.filter_fields = (L4_PROTOCAL | INGRESS_DPORT);
		napt_filter.ingress_dest_l4_port = 554; //rtsp wellknown port
		napt_filter.ingress_l4_protocal = 0x11; //tcp protocol
		napt_filter.action_fields = NAPT_DROP_BIT;
		napt_filter.ruleType = RTK_RG_NAPT_FILTER_PERSIST;
		if((ret = rtk_rg_naptFilterAndQos_add( &filterIdx, &napt_filter)) == 0)
			fprintf(fp, "%d\n", filterIdx);
		else
			printf("[%s@%d] rtk_rg_naptFilterAndQos_add QoS rule failed! (ret = %d)\n",__func__,__LINE__, ret);
			
	}
#endif
#ifdef CONFIG_NF_CONNTRACK_L2TP
	if(mib_get(MIB_IP_ALG_L2TP, &value) && value == 1)
		alg_app |= RTK_RG_ALG_L2TP_TCP_PASSTHROUGH_BIT | RTK_RG_ALG_L2TP_UDP_PASSTHROUGH_BIT;
	else{
		alg_app &= ~(RTK_RG_ALG_L2TP_TCP_PASSTHROUGH_BIT | RTK_RG_ALG_L2TP_UDP_PASSTHROUGH_BIT);

		//disable alg for l2tp
		memset(&napt_filter, 0, sizeof(rtk_rg_naptFilterAndQos_t));
		napt_filter.direction = RTK_RG_NAPT_FILTER_OUTBOUND;
		napt_filter.filter_fields = (L4_PROTOCAL | INGRESS_DPORT);
		napt_filter.ingress_dest_l4_port = 1701; //l2tp wellknown port
		napt_filter.ingress_l4_protocal = 0x11; //udp protocol
		napt_filter.action_fields = NAPT_DROP_BIT;
		napt_filter.ruleType = RTK_RG_NAPT_FILTER_PERSIST;
		if((ret = rtk_rg_naptFilterAndQos_add( &filterIdx, &napt_filter)) == 0)
			fprintf(fp, "%d\n", filterIdx);
		else
			printf("rtk_rg_naptFilterAndQos_add QoS rule failed! (ret = %d)\n", ret);

	}
#endif
#ifdef CONFIG_NF_CONNTRACK_IPSEC
	if(mib_get(MIB_IP_ALG_IPSEC, &value) && value == 1)
		alg_app |= RTK_RG_ALG_IPSEC_TCP_PASSTHROUGH_BIT | RTK_RG_ALG_IPSEC_UDP_PASSTHROUGH_BIT;
	else{
		alg_app &= ~(RTK_RG_ALG_IPSEC_TCP_PASSTHROUGH_BIT | RTK_RG_ALG_IPSEC_UDP_PASSTHROUGH_BIT);

		//disable alg for ipsec
		memset(&napt_filter, 0, sizeof(rtk_rg_naptFilterAndQos_t));
		napt_filter.direction = RTK_RG_NAPT_FILTER_OUTBOUND;
		napt_filter.filter_fields = (L4_PROTOCAL | INGRESS_DPORT);
		napt_filter.ingress_dest_l4_port = 500; //ipsec wellknown port
		napt_filter.ingress_l4_protocal = 0x11; //udp protocol
		napt_filter.action_fields = NAPT_DROP_BIT;
		napt_filter.ruleType = RTK_RG_NAPT_FILTER_PERSIST;
		if((ret = rtk_rg_naptFilterAndQos_add( &filterIdx, &napt_filter)) == 0)
			fprintf(fp, "%d\n", filterIdx);
		else
			printf("rtk_rg_naptFilterAndQos_add QoS rule failed! (ret = %d)\n", ret);

		//disable alg for ipsec
		memset(&napt_filter, 0, sizeof(rtk_rg_naptFilterAndQos_t));
		napt_filter.direction = RTK_RG_NAPT_FILTER_OUTBOUND;
		napt_filter.filter_fields = (L4_PROTOCAL | INGRESS_DPORT);
		napt_filter.ingress_dest_l4_port = 4500; //ipsec wellknown port
		napt_filter.ingress_l4_protocal = 0x11; //udp protocol
		napt_filter.action_fields = NAPT_DROP_BIT;
		napt_filter.ruleType = RTK_RG_NAPT_FILTER_PERSIST;
		if((ret = rtk_rg_naptFilterAndQos_add( &filterIdx, &napt_filter)) == 0)
			fprintf(fp, "%d\n", filterIdx);
		else
			printf("rtk_rg_naptFilterAndQos_add QoS rule failed! (ret = %d)\n", ret);

	}
#endif
#ifdef CONFIG_NF_CONNTRACK_SIP
	if(mib_get(MIB_IP_ALG_SIP, &value) && value == 1){
		alg_app |= RTK_RG_ALG_SIP_TCP_BIT | RTK_RG_ALG_SIP_UDP_BIT;
		/*Due to napt entry will be added into HW, so traffic won't handle by Romedriver
		    Alg passthrough will fail., so we trap sip packet to forwarding engine, let RG have
		    chance to handle.
		    Acl Trap will have another problem, would hit RG l3 short cut.
		    so......just use napt find entry. which dport == 5060 to delete it.!!
		*/
		//loop MAX_NAPT_OUT_HW_TABLE_SIZE
		int i, ret;
		rtk_rg_naptInfo_t naptInfo;
		for(i=0;i<MAX_NAPT_OUT_HW_TABLE_SIZE;i++){
			ret = rtk_rg_naptConnection_find(&naptInfo,&i);
			if(ret==RT_ERR_RG_OK){
				/*
				Acl Trap will have another problem, would hit RG l3 shortcut.
				so......just use napt find entry. which dport == 5060 to delete it.!!
				*/
				if(naptInfo.naptTuples.remote_port == 5060){
					ret = rtk_rg_naptConnection_del(i);
					if(ret != 0)
						fprintf(stderr,"%s-%d error ret=%d del entry:%d fail!",__func__,__LINE__,ret,i);
				}
			}
		}
	}
	else{
		alg_app &= ~(RTK_RG_ALG_SIP_TCP_BIT | RTK_RG_ALG_SIP_UDP_BIT);

	}
#endif
#ifdef CONFIG_NF_CONNTRACK_PPTP
	if(mib_get(MIB_IP_ALG_PPTP, &value) && value == 1)
		alg_app |= RTK_RG_ALG_PPTP_TCP_PASSTHROUGH_BIT | RTK_RG_ALG_PPTP_UDP_PASSTHROUGH_BIT;
	else{
		alg_app &= ~(RTK_RG_ALG_PPTP_TCP_PASSTHROUGH_BIT | RTK_RG_ALG_PPTP_UDP_PASSTHROUGH_BIT);

		//disable alg for pptp
			memset(&napt_filter, 0, sizeof(rtk_rg_naptFilterAndQos_t));
			napt_filter.direction = RTK_RG_NAPT_FILTER_OUTBOUND;
			napt_filter.filter_fields = (L4_PROTOCAL | INGRESS_DPORT);
			napt_filter.ingress_dest_l4_port = 1723; //pptp wellknown port
			napt_filter.ingress_l4_protocal = 0x6; //tcp protocol
			napt_filter.action_fields = NAPT_DROP_BIT;
			napt_filter.ruleType = RTK_RG_NAPT_FILTER_PERSIST;
			if((ret = rtk_rg_naptFilterAndQos_add( &filterIdx, &napt_filter)) == 0)
				fprintf(fp, "%d\n", filterIdx);
			else
				printf("rtk_rg_naptFilterAndQos_add QoS rule failed! (ret = %d)\n", ret);

	}
#endif
	if(rtk_rg_algApps_set(alg_app))
	{
		fclose(fp);
		DBPRINT(1, "rtk_rg_algApps_set failed! alg_app = %X\n", alg_app);
		return -1;
	}

	fclose(fp);
	return 0;
}
#endif

#ifdef CONFIG_CTC_E8_CLIENT_LIMIT
enum DevType
{
	//RG set category 0 as default category, all traffic will learn mac at category 0.
	//then compare with other category. So, we shift all category by 1.
	CTC_RG_Default=0,
	CTC_Computer_,
	CTC_Camera_,
	CTC_HGW_,
	CTC_STB_,
	CTC_PHONE_,
	CTC_UNKNOWN_=100
};
int RTK_RG_AccessWanLimitCategory_Set(unsigned char *mac, int category)
{
#ifdef _PRMT_X_CT_COM_MWBAND_
	/*
		typedef struct rtk_rg_accessWanLimitCategory_s
		{
			unsigned char category;
			rtk_mac_t mac;
		}rtk_rg_accessWanLimitCategory_t;
	*/
	rtk_rg_accessWanLimitCategory_t macCategory_info;
	int ret=0;
	unsigned int vInt;
	mib_get( CWMP_CT_MWBAND_MODE, (void *)&vInt);
	if(vInt != 2) //mode 2 is equal to RG struct.h's RG_ACCESSWAN_TYPE_CATEGORY
		return 0;
	macCategory_info.category = category;
	memcpy(&macCategory_info.mac,mac,MAC_ADDR_LEN);
	ret = rtk_rg_accessWanLimitCategory_set(macCategory_info);
	if(ret){
			fprintf(stderr, "%s-%d error ret=%d\n",__func__,__LINE__,ret);
			return -1;
	}
	return ret;
#else
		return 0;
#endif
}

int RTK_RG_disable_AccessWanLimit(void)
{
	rtk_rg_accessWanLimitData_t access_wan_info;
	int ret=0;
	unsigned int vInt;
	unsigned char Value;
	memset(&access_wan_info,0,sizeof(rtk_rg_accessWanLimitData_t));
	access_wan_info.type = RG_ACCESSWAN_TYPE_UNLIMIT;
	access_wan_info.action = SA_LEARN_EXCEED_ACTION_PERMIT;
	ret = rtk_rg_accessWanLimit_set(access_wan_info);
	if(ret){
		fprintf(stderr, "%s-%d error ret=%d\n",__func__,__LINE__,ret);
	}

	return ret;
}

int RTK_RG_AccessWanLimit_Set(void)
{
#ifdef _PRMT_X_CT_COM_MWBAND_
	/*
		rtk_rg_accessWanLimitType_t type;
		union
		{
			unsigned char category;
			rtk_rg_portmask_t port_mask;
		}data;
		int learningLimitNumber;
		int learningCount;
		rtk_rg_sa_learning_exceed_action_t action;
#ifdef CONFIG_MASTER_WLAN0_ENABLE
		unsigned int wlan0_dev_mask;	//used for WLAN0 device access limit
#endif
	*/

	rtk_rg_accessWanLimitData_t access_wan_info;
	int ret=0;
	unsigned int vInt;
	unsigned char Value;
	unsigned char type = RG_ACCESSWAN_LIMIT_BY_SMAC;
	memset(&access_wan_info,0,sizeof(rtk_rg_accessWanLimitData_t));
	mib_get( CWMP_CT_MWBAND_MODE, (void *)&vInt);
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	mib_get( CWMP_CT_MWBAND_TERMINAL_TYPE, (void *)&type);
	type = (type == 0) ? RG_ACCESSWAN_LIMIT_BY_SIP : RG_ACCESSWAN_LIMIT_BY_SMAC;
#endif
	switch(vInt)
	{
		case 0:
			access_wan_info.type = RG_ACCESSWAN_TYPE_UNLIMIT;
			access_wan_info.action = SA_LEARN_EXCEED_ACTION_PERMIT;
			ret = rtk_rg_accessWanLimit_set(access_wan_info);
			if(ret){
				fprintf(stderr, "%s-%d error ret=%d\n",__func__,__LINE__,ret);
				return -1;
			}
			break;
		case 1://all port
			access_wan_info.type = RG_ACCESSWAN_TYPE_PORTMASK;
			// all lan port
			unsigned int portMask = 0;
		        unsigned int phy_portmask;
			mib_get(MIB_LAN_PORT_MASK1, (void *)&portMask);
			phy_portmask = RG_get_lan_phyPortMask(portMask);
			portMask = phy_portmask;
			access_wan_info.data.port_mask.portmask = portMask;
			//master and slave ext port
			access_wan_info.data.port_mask.portmask |= (1 << RTK_RG_EXT_PORT0);
			#if defined(WLAN_DUALBAND_CONCURRENT) && defined(WLAN_SUPPORT)
			access_wan_info.data.port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN1));
			#endif
#ifdef CONFIG_MASTER_WLAN0_ENABLE
			//access_wan_info.wlan0_dev_mask = 0x1f;//all mast wifi port
			access_wan_info.wlan0_dev_mask = 0x0;
#endif
			mib_get( CWMP_CT_MWBAND_NUMBER, (void *)&vInt);
			access_wan_info.learningLimitNumber = vInt;
			access_wan_info.action = SA_LEARN_EXCEED_ACTION_PERMIT_L2;
			access_wan_info.field = type;
			ret = rtk_rg_accessWanLimit_set(access_wan_info);
			if(ret){
				fprintf(stderr, "%s-%d error ret=%d\n",__func__,__LINE__,ret);
				return -1;
			}
			break;
		case 2:
			access_wan_info.type = RG_ACCESSWAN_TYPE_CATEGORY;
			access_wan_info.action = SA_LEARN_EXCEED_ACTION_PERMIT_L2;
			break;
	}

	if(access_wan_info.type == RG_ACCESSWAN_TYPE_CATEGORY)
	{
		mib_get( CWMP_CT_MWBAND_PC_ENABLE, (void *)&Value);
		if(Value){
			access_wan_info.data.category = CTC_Computer_;
			mib_get( CWMP_CT_MWBAND_PC_NUM, (void *)&vInt);
			access_wan_info.learningLimitNumber = vInt;
			ret = rtk_rg_accessWanLimit_set(access_wan_info);
			if(ret){
				fprintf(stderr, "%s-%d error ret=%d\n",__func__,__LINE__,ret);
				return -1;
			}
		}

		mib_get( CWMP_CT_MWBAND_CMR_ENABLE, (void *)&Value);
		if(Value){
			access_wan_info.data.category = CTC_Camera_;
			mib_get( CWMP_CT_MWBAND_CMR_NUM, (void *)&vInt);
			access_wan_info.learningLimitNumber = vInt;
			ret = rtk_rg_accessWanLimit_set(access_wan_info);
			if(ret){
				fprintf(stderr, "%s-%d error ret=%d\n",__func__,__LINE__,ret);
				return -1;
			}
		}

		mib_get( CWMP_CT_MWBAND_STB_ENABLE, (void *)&Value);
		if(Value){
			access_wan_info.data.category = CTC_STB_;
			mib_get( CWMP_CT_MWBAND_STB_NUM, (void *)&vInt);
			access_wan_info.learningLimitNumber = vInt;
			ret = rtk_rg_accessWanLimit_set(access_wan_info);
			if(ret){
				fprintf(stderr, "%s-%d error ret=%d\n",__func__,__LINE__,ret);
				return -1;
			}
		}
		mib_get( CWMP_CT_MWBAND_PHN_ENABLE, (void *)&Value);

		if(Value){
			access_wan_info.data.category = CTC_PHONE_;
			mib_get( CWMP_CT_MWBAND_PHN_NUM, (void *)&vInt);
			access_wan_info.learningLimitNumber = vInt;
			ret = rtk_rg_accessWanLimit_set(access_wan_info);
			if(ret){
				fprintf(stderr, "%s-%d error ret=%d\n",__func__,__LINE__,ret);
				return -1;
			}
		}

	}
#endif
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

	for (i = 0; i < total_url; i++)
	{
		if (!mib_chain_get(MIB_URL_FQDN_TBL, i, (void *)&fqdn))
			continue;

		memset(&url_f_s,0,sizeof(rtk_rg_urlFilterString_t));

		url_f_s.path_exactly_match = 0;

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

		url_f_s.path_exactly_match = 0;

		strncpy(url_f_s.url_filter_string, keyword.keyword, MAX_KEYWD_LENGTH);

		if((ret = rtk_rg_urlFilterString_add(&url_f_s, &url_idx)) == 0)
			fprintf(fp, "%d\n", url_idx);
		else
			DBPRINT(1, "rtk_rg_urlFilterString_add QoS rule failed!\n");
	}

	fclose(fp);
	return 0;
}

int RTK_RG_URL_Filter_Set_By_Key(int mode)
{
	int url_idx, ret, total_url, i;
	rtk_rg_urlFilterString_t url_f_s;
	MIB_CE_URL_FQDN_T fqdn;
	FILE *fp;

	if(mode==1) //blacklist
		system("echo 0 > /proc/rg/urlFilter_mode");
	else if(mode==2) //whitelist
		system("echo 1 > /proc/rg/urlFilter_mode");
	else { //disable
		system("echo 0 > /proc/rg/urlFilter_mode");
		return 0;
	}

	total_url = mib_chain_total(MIB_URL_FQDN_TBL);

	if(!(fp = fopen(RG_URL_FILTER_FILE, "a")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -2;
	}

	for (i = 0; i < total_url; i++)
	{
		if (!mib_chain_get(MIB_URL_FQDN_TBL, i, (void *)&fqdn))
			continue;

		memset(&url_f_s,0,sizeof(rtk_rg_urlFilterString_t));

		url_f_s.path_exactly_match = 0;

		strncpy(url_f_s.url_filter_string, fqdn.key, MAX_URL_LENGTH);

		if((ret = rtk_rg_urlFilterString_add(&url_f_s, &url_idx)) == 0)
			fprintf(fp, "%d\n", url_idx);
		else
			DBPRINT(1, "rtk_rg_urlFilterString_add QoS rule failed!\n");
	}
#ifdef _PRMT_C_CU_USERACCOUNT_
	if(mode == 1)//black list
	{
		printf("user account urlblock set by rg.\n");
		USER_ACCOUNT_URL_T uentry;	

		total_url = mib_chain_total(CONFIG_USER_ACCOUNT_URL_BLACK);
		for (i=0; i<total_url; i++) {
			if (!mib_chain_get(CONFIG_USER_ACCOUNT_URL_BLACK, i, (void *)&uentry))
				continue;
			if(!strcmp(uentry.filter,""))
				continue;
			
			memset(&url_f_s,0,sizeof(rtk_rg_urlFilterString_t));
			url_f_s.path_exactly_match = 0;
			strncpy(url_f_s.url_filter_string,uentry.filter, MAX_URL_LENGTH);
			if((ret = rtk_rg_urlFilterString_add(&url_f_s, &url_idx)) == 0)
				fprintf(fp, "%d\n", url_idx);
			else
				DBPRINT(1, "rtk_rg_urlFilterString_add QoS rule failed!\n");
		}
	}
	else if(mode == 2)//white list
	{
		printf("user account urlallow set by rg.\n");
		USER_ACCOUNT_URL_T uentry;	

		total_url = mib_chain_total(CONFIG_USER_ACCOUNT_URL_WHITE);
		for (i=0; i<total_url; i++) {
			if (!mib_chain_get(CONFIG_USER_ACCOUNT_URL_WHITE, i, (void *)&uentry))
				continue;
			if(!strcmp(uentry.filter,""))
				continue;
			
			memset(&url_f_s,0,sizeof(rtk_rg_urlFilterString_t));
			url_f_s.path_exactly_match = 0;
			strncpy(url_f_s.url_filter_string,uentry.filter, MAX_URL_LENGTH);
			if((ret = rtk_rg_urlFilterString_add(&url_f_s, &url_idx)) == 0)
				fprintf(fp, "%d\n", url_idx);
			else
				DBPRINT(1, "rtk_rg_urlFilterString_add QoS rule failed!\n");
		}
	}
#endif
	fclose(fp);
	return 0;
}

int Flush_RTK_RG_URL_Filter_new()
{
	FILE *fp;
	int url_filter_idx, ret;
	char url_id[64]={0};
	char url[256]={0};
	char *pch = NULL;

	if(!(fp = fopen(RG_URL_FILTER_FILE, "r")))
		return -2;

	while(fscanf(fp, "%s %s\n",url, url_id) != EOF)
	{
		if(strstr(url_id, ","))
		{
			pch = strtok(url_id, ",");
			while (pch != NULL)
			{
				url_filter_idx = atoi(pch);
				if(rtk_rg_urlFilterString_del(url_filter_idx))
					DBPRINT(1, "rtk_rg_urlFilterString_del failed! idx = %d\n", url_filter_idx);
			
				pch = strtok(NULL, ",");
			}
		}
		else
		{
			url_filter_idx = atoi(url_id);
			if(rtk_rg_urlFilterString_del(url_filter_idx))
				DBPRINT(1, "rtk_rg_urlFilterString_del failed! idx = %d\n", url_filter_idx);
		}
			
	}

	fclose(fp);
	unlink(RG_URL_FILTER_FILE);
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

#ifdef SUPPORT_URL_FILTER
int getURLFilterBlocktime(char *key)
{
	FILE *fp;
	int url_filter_idx, ret=0, count=0;
	char url_id[64]={0};
	char url[256]={0};
	char *pch = NULL;
	rtk_rg_urlFilterString_t url_f_s;

	if(!(fp = fopen(RG_URL_FILTER_FILE, "r")))
		return -2;

	while(fscanf(fp, "%s %s\n",url, url_id) != EOF)
	{
		if(strcmp(key, url) == 0)
		{
			if(strstr(url_id, ","))
			{
				pch = strtok(url_id, ",");
				while (pch != NULL)
				{
					url_filter_idx = atoi(pch);
					ret = rtk_rg_urlFilterString_find(&url_f_s, &url_filter_idx);
					if(ret!=RT_ERR_RG_OK)
					{
						printf("rtk_rg_urlFilterString_find failed,  url_filter_idx=%d\n", url_filter_idx);
					}
					else
					{
						count+=url_f_s.urlBlockAllowTimes;
					}
					
					pch = strtok(NULL, ",");
				}
			}
			else
			{
				url_filter_idx = atoi(url_id);
				ret = rtk_rg_urlFilterString_find(&url_f_s, &url_filter_idx);
				if(ret!=RT_ERR_RG_OK)
				{
					printf("rtk_rg_urlFilterString_find failed,  url_filter_idx=%d\n", url_filter_idx);
				}
				else
				{
					count=url_f_s.urlBlockAllowTimes;
				}
			}
		}
	}

	fclose(fp);
	return count;
}

int RTK_RG_URL_Filter_Set_By_Key_new()
{
	int url_idx, ret, total_url, i;
	rtk_rg_urlFilterString_t url_f_s;
	MIB_CE_URL_FILTER_T urlfilter;
	FILE *fp;
	int port=0;
	char key[256]={0};
	char *pch = NULL;
	char url_filter_idx[64]={0};
	char url_idx_str[64]={0};
	char tmp[64]={0};

	system("echo 0 > /proc/rg/urlFilter_mode");
	
	total_url = mib_chain_total(MIB_URL_FILTER_TBL);

	if(!(fp = fopen(RG_URL_FILTER_FILE, "a")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -2;
	}

	for (i = 0; i < total_url; i++)
	{
		if (!mib_chain_get(MIB_URL_FILTER_TBL, i, (void *)&urlfilter))
			continue;

		if(urlfilter.Enable == 0)
			continue;

		memset(&url_f_s,0,sizeof(rtk_rg_urlFilterString_t));
		parse_ur_filter(urlfilter.url, key, &port);
		if(strstr(urlfilter.mac, ","))
		{
			pch = strtok(urlfilter.mac, ",");
			while (pch != NULL)
			{
				url_f_s.path_exactly_match = 0;
				strncpy(url_f_s.url_filter_string, key, MAX_URL_LENGTH);
				url_f_s.urlfilterSmacMode=RG_FILTER_BLACK;
				if(strlen(urlfilter.mac))
				{		
					url_f_s.urlfilterSmacCheck=1;
					changeMacFormat(pch,':','-');
					changeStringToMac(url_f_s.urlfilterSamc, pch);
				}
				if((ret = rtk_rg_urlFilterString_add(&url_f_s, &url_idx)) == 0)
				{
					sprintf(url_idx_str, "%d,", url_idx);
					strcat(url_filter_idx, url_idx_str);
				}
				else
					DBPRINT(1, "[%s@%d] rtk_rg_urlFilterString_add QoS rule failed!\n",__func__,__LINE__);				
		  		pch = strtok(NULL, ",");
			} 

			strncpy(tmp, url_filter_idx, strlen(url_filter_idx)-1);
			fprintf(fp, "%s %s\n", key, tmp);
	
		}
		else
		{
			url_f_s.path_exactly_match = 0;
			strncpy(url_f_s.url_filter_string, key, MAX_URL_LENGTH);
			url_f_s.urlfilterSmacMode=RG_FILTER_BLACK;
			if(strlen(urlfilter.mac))
			{
				url_f_s.urlfilterSmacCheck=1;
				changeMacFormat(urlfilter.mac,':','-');
				changeStringToMac(url_f_s.urlfilterSamc, urlfilter.mac);
			}
				
			if((ret = rtk_rg_urlFilterString_add(&url_f_s, &url_idx)) == 0)
				fprintf(fp, "%s %d\n", key, url_idx);
			else
				DBPRINT(1, "[%s@%d] rtk_rg_urlFilterString_add QoS rule failed!\n",__func__,__LINE__);
		}

	}

	fclose(fp);
	return 0;
}
#endif

#ifdef _PRMT_X_CMCC_SECURITY_
int RTK_RG_ParentalCtrl_MAC_Policy_Set(unsigned char *mac, int mode, char *url)
{
	int ret = 0, url_idx = 0;
	rtk_rg_urlFilterString_t url_f_s;
	memset(&url_f_s, 0, sizeof(rtk_rg_urlFilterString_t));

	// flush invalid rules
	while (RT_ERR_RG_OK == rtk_rg_urlFilterString_find(&url_f_s, &url_idx))
	{
		if (url_f_s.urlfilterSmacCheck == 1 && memcmp(url_f_s.urlfilterSamc, mac, MAC_ADDR_LEN) == 0)
		{
			if (mode == RG_FILTER_NONE || url_f_s.urlfilterSmacMode != mode)
			{
				ret = rtk_rg_urlFilterString_del(url_idx);
				if (ret)
				{
					printf("rtk_rg_urlFilterString_del failed! [%02x:%02x:%02x:%02x:%02x:%02x] mode = %d (ret = %d)\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], mode, ret);
				}
			}
		}
		url_idx++;
		memset(&url_f_s, 0, sizeof(rtk_rg_urlFilterString_t));
	}

	if (mode != RG_FILTER_NONE)
	{
		url_f_s.urlfilterSmacCheck = 1;
		url_f_s.urlfilterSmacMode = mode;
		memcpy(url_f_s.urlfilterSamc, mac, MAC_ADDR_LEN);

		if (url != NULL)
		{
			strncpy(url_f_s.url_filter_string, url, MAX_URL_LENGTH);
		}
		url_f_s.path_exactly_match = 0;
		ret = rtk_rg_urlFilterString_add(&url_f_s, &url_idx);
		if (ret)
		{
			printf("rtk_rg_urlFilterString_add failed! [%02x:%02x:%02x:%02x:%02x:%02x] [%s] (ret = %d)\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], (url)?url:"NULL", ret);
		}
	}

	return ret;
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

	rtk_portmask_t portmask,extportmask;
	if(enable == 1)
		portmask.bits[0] = (RTK_RG_ALL_MAC_PORTMASK&(~RTK_RG_ALL_LAN_PORTMASK));
	else
		portmask.bits[0] = RTK_RG_ALL_MAC_PORTMASK; // disalbe

	extportmask.bits[0] = ((0x1<<(RTK_RG_MAC_EXT_PORT_MAX-RTK_RG_MAC_EXT_PORT0))-1);

	//for master
	rtk_rg_port_isolationEntryExt_set(RTK_PORT_ISO_CFG_0,1,&portmask,&extportmask);
	rtk_rg_port_isolationEntryExt_set(RTK_PORT_ISO_CFG_1,1,&portmask,&extportmask);

	//for slave
	rtk_rg_port_isolationEntryExt_set(RTK_PORT_ISO_CFG_0,2,&portmask,&extportmask);
	rtk_rg_port_isolationEntryExt_set(RTK_PORT_ISO_CFG_1,2,&portmask,&extportmask);

	return 0;
}

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

int RTK_RG_DoS_Set(int enable_flag)
{
	rtk_rg_mac_portmask_t dos_port_mask;
	int wanPhyPort;
	unsigned int enable;

	if(!(enable_flag & DOS_ENABLE)){
		printf("rg DoS: disable! only enable the DOS setting on firwarepage\n");
		enable = enable_flag;
	}
	else {
		printf("rg DoS: enable\n");
		enable = DOS_ENABLE_ALL;
	}
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		dos_port_mask.portmask = RG_get_wan_phyPortMask();
#ifdef WLAN_SUPPORT
		dos_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN0));
#ifdef WLAN_DUALBAND_CONCURRENT
		dos_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN1));
#endif
		dos_port_mask.portmask |= (1 << RTK_RG_PORT_CPU);
#endif
		rtk_rg_dosPortMaskEnable_set(dos_port_mask);
#else
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
		dos_port_mask.portmask = RG_get_wan_phyPortMask();
		dos_port_mask.portmask |= RG_get_all_lan_phyPortMask();
#ifdef WLAN_SUPPORT
		dos_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN0));
#ifdef WLAN_DUALBAND_CONCURRENT
		dos_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN1));
#endif
#endif
		//printf("dos port mask %x\n", dos_port_mask.portmask);
		rtk_rg_dosPortMaskEnable_set(dos_port_mask);
	}
#endif

	if(rtk_rg_dosFloodType_set(RTK_RG_DOS_SYNFLOOD_DENY, (enable & SYSFLOODSYN)? 1:0,RTK_RG_DOS_ACTION_DROP,3)) //threshold 5K/sec
		DBPRINT(1, "rtk_rg_dosFloodType_set failed! type = RTK_RG_DOS_SYNFLOOD_DENY\n");

	if(rtk_rg_dosFloodType_set(RTK_RG_DOS_FINFLOOD_DENY, (enable & SYSFLOODFIN)? 1:0,RTK_RG_DOS_ACTION_DROP,3)) //threshold 5K/sec
		DBPRINT(1, "rtk_rg_dosFloodType_set failed! type = RTK_RG_DOS_FINFLOOD_DENY\n");

	if(rtk_rg_dosFloodType_set(RTK_RG_DOS_ICMPFLOOD_DENY,(enable & SYSFLOODICMP)? 1:0,RTK_RG_DOS_ACTION_DROP,5)) //threshold 5K/sec
		DBPRINT(1, "rtk_rg_dosFloodType_set failed! type = RTK_RG_DOS_ICMPFLOOD_DENY\n");

	if(rtk_rg_dosType_set(RTK_RG_DOS_LAND_DENY,(enable & IPLANDENABLED)? 1:0,RTK_RG_DOS_ACTION_DROP))
		DBPRINT(1, "rtk_rg_dosType_set failed! type = RTK_RG_DOS_LAND_DENY\n");

	if(rtk_rg_dosType_set(RTK_RG_DOS_POD_DENY,(enable & PINGOFDEATHENABLED)? 1:0,RTK_RG_DOS_ACTION_DROP))
		DBPRINT(1, "rtk_rg_dosType_set failed! type = RTK_RG_DOS_POD_DENY\n");

	if(rtk_rg_dosType_set(RTK_RG_DOS_UDPBOMB_DENY,(enable & UDPBombEnabled)? 1:0,RTK_RG_DOS_ACTION_DROP))
		DBPRINT(1, "rtk_rg_dosType_set failed! type = RTK_RG_DOS_UDPBOMB_DENY\n");

	if(rtk_rg_dosType_set(RTK_RG_DOS_ICMP_FRAG_PKTS_DENY,(enable & ICMPFRAGMENT)? 1:0,RTK_RG_DOS_ACTION_DROP))
		DBPRINT(1, "rtk_rg_dosType_set failed! type = RTK_RG_DOS_ICMP_FRAG_PKTS_DENY\n");

	if(rtk_rg_dosType_set(RTK_RG_DOS_TCP_FRAG_OFF_MIN_CHECK,(enable & TCPFRAGOFFMIN)? 1:0,RTK_RG_DOS_ACTION_DROP))
		DBPRINT(1, "rtk_rg_dosType_set failed! type = RTK_RG_DOS_TCP_FRAG_OFF_MIN_CHECK\n");

	if(rtk_rg_dosType_set(RTK_RG_DOS_TCPHDR_MIN_CHECK,(enable & TCPHDRMIN)? 1:0,RTK_RG_DOS_ACTION_DROP))
		DBPRINT(1, "rtk_rg_dosType_set failed! type = RTK_RG_DOS_TCPHDR_MIN_CHECK\n");


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

unsigned int RG_get_lan_phyPortMask(unsigned int portmask)
{
	int i=0, phyPortId, ret;
	unsigned int phyportmask=0;
    unsigned char re_map_tbl[4];

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
	int phyPortId, ret;
    unsigned char re_map_tbl[4];

    mib_get(MIB_PORT_REMAPPING, (void *)re_map_tbl);

	ret = rtk_rg_switch_phyPortId_get(re_map_tbl[logPortId], &phyPortId);

	if(ret == 0)
		return phyPortId;
	else{
		DBPRINT(1, "%s rtk_rg_switch_phyPortId_get failed!\n", __FUNCTION__);
		return -1;
	}
}

int RG_get_lan_logPortId(int phyPortId)
{
	int ret;
    unsigned char re_map_tbl[4];
	int i = 0;

    mib_get(MIB_PORT_REMAPPING, (void *)re_map_tbl);
	for(i=0; i < 4; i++){
		if(re_map_tbl[i] == phyPortId){
			return i+1; //1-based
		}
	}
	return -1;
}

int RG_get_lan_phyPortId_mapping(int phyPortId_arr[], int size)
{
	int ret=0, i, ret2=0;
	unsigned char re_map_tbl[4];

    if(mib_get(MIB_PORT_REMAPPING, (void *)re_map_tbl)==0)
    {
    	//if get port remapping failed, use default
    	for(i=0; i<size; i++){
			ret |= (ret2 = rtk_rg_switch_phyPortId_get(i, &phyPortId_arr[i]));
			if(ret2)
				DBPRINT(1, "%s rtk_rg_switch_phyPortId_get port id %d failed!\n", __func__, i);
		}
    }
    else
	{
		for(i=0; i<size; i++){
			ret |= (ret2 = rtk_rg_switch_phyPortId_get(re_map_tbl[i], &phyPortId_arr[i]));
			if(ret2)
				DBPRINT(1, "%s rtk_rg_switch_phyPortId_get port id %d failed!\n", __func__, re_map_tbl[i]);
		}
    }
	return ret;
}

#ifdef WLAN_SUPPORT
int RG_get_wlan_phyPortId(int logPortId)
{
	int phyPortId, ret;
	if (logPortId >= PMAP_WLAN0 && logPortId <= PMAP_WLAN0_VAP_END) {
		phyPortId = RTK_RG_EXT_PORT0;
	}
#ifdef WLAN_DUALBAND_CONCURRENT
#ifdef CONFIG_RTL9607C_SERIES
	else if (logPortId >= PMAP_WLAN1 && logPortId <= PMAP_WLAN1_VAP_END) {
		phyPortId = RTK_RG_MAC10_EXT_PORT0;
	}
#else
	else if (logPortId >= PMAP_WLAN1 && logPortId <= PMAP_WLAN1_VAP_END) {
		phyPortId = RTK_RG_EXT_PORT1;
	}
#endif
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

unsigned int RG_get_portCounter(unsigned int portIndex, unsigned long long *tx_bytes,unsigned long *tx_pkts,unsigned long *tx_drops,unsigned long *tx_errs,
										unsigned long long *rx_bytes, unsigned long *rx_pkts,unsigned long *rx_drops,unsigned long *rx_errs)
{
	rtk_rg_port_mib_info_t portmib;
	int ret;

	ret = rtk_rg_portMibInfo_get(RG_get_lan_phyPortId(portIndex),&portmib);
	if(ret != 0)
	{
		DBPRINT(1, "%s get port %d mib info failed!\n", __FUNCTION__, portIndex);
		return 0;
	}

	*rx_bytes = portmib.ifInOctets;
	*rx_pkts = (portmib.ifInUcastPkts + portmib.ifInMulticastPkts + portmib.ifInBroadcastPkts);
	*rx_drops = portmib.dot1dTpPortInDiscards;
	*rx_errs = (portmib.dot3StatsSymbolErrors + portmib.dot3ControlInUnknownOpcodes);
	*tx_bytes = portmib.ifOutOctets;
	*tx_pkts = (portmib.ifOutUcastPkts + portmib.ifOutMulticastPkts + portmib.ifOutBrocastPkts);
	*tx_drops = portmib.ifOutDiscards ;
	*tx_errs = 0;
	return 1;
}

int RG_get_phyPort_status(unsigned int portIndex, rtk_rg_portStatusInfo_t *portInfo)
{
	int ret = rtk_rg_portStatus_get(RG_get_lan_phyPortId(portIndex), portInfo);
	if(ret!=RT_ERR_RG_OK)
	{
		DBPRINT(1, "%s get port %d status failed!\n", __FUNCTION__, portIndex);
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

void RTK_RG_gatewayService_add()
{
	rtk_rg_gatewayServicePortEntry_t serviceEntry;
	#ifdef CONFIG_RTK_VOIP
	unsigned int totalVoIPCfgEntry = 0;	
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

	//Add TR-069 http server
	mib_get(CWMP_CONREQ_PORT, &port);
	serviceEntry.valid = 1;
	serviceEntry.port_num = port;
	serviceEntry.type = GATEWAY_SERVER_SERVICE;
	if((ret = rtk_rg_gatewayServicePortRegister_add(&serviceEntry, &index)) == 0)
			fprintf(fp, "%d\n", index);
	else
		DBPRINT(1, "%s: add cwmp port via rtk_rg_gatewayServicePortRegister_add failed! ret = %d!\n", __FUNCTION__, ret);

	#ifdef CONFIG_RTK_VOIP
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
		for(i=0; i<=12; i++) {
			serviceEntry.valid = 1;
			serviceEntry.port_num = VoIPport->media_port+i;
			serviceEntry.type = GATEWAY_SERVER_SERVICE;		
			if((ret = rtk_rg_gatewayServicePortRegister_add(&serviceEntry, &index)) == 0)
					fprintf(fp, "%d\n", index);
			else
				DBPRINT(1, "%s: add cwmp port via rtk_rg_gatewayServicePortRegister_add failed! ret = %d!\n", __FUNCTION__, ret);
		}
	}
	#endif // CONFIG_RTK_VOIP 

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

void RG_tcp_stateful_tracking(int enable)
{
	if(enable)
		system("echo 0 > /proc/rg/tcp_disable_stateful_tracking");
	else
		system("echo 1 > /proc/rg/tcp_disable_stateful_tracking");
}

int RG_get_MAC_list_by_interface(unsigned int portIndex, char *mac_list)
{
	int macidx = 0, mac_num = 0, list_len = 0;
	rtk_rg_macEntry_t macEntry;
	memset(&macEntry, 0, sizeof(rtk_rg_macEntry_t));

	while (RT_ERR_RG_OK == rtk_rg_macEntry_find(&macEntry, &macidx))
	{
		//fprintf(stderr, "macidx = %d\n", macidx);
		//fprintf(stderr, "macEntry.port_idx = %d\n", macEntry.port_idx);
		char mac_str[20] = {0};
		sprintf(mac_str, "%02X:%02X:%02X:%02X:%02X:%02X",
			(unsigned char)macEntry.mac.octet[0], (unsigned char)macEntry.mac.octet[1], (unsigned char)macEntry.mac.octet[2],
			(unsigned char)macEntry.mac.octet[3], (unsigned char)macEntry.mac.octet[4], (unsigned char)macEntry.mac.octet[5]);
		//fprintf(stderr, "mac_str = %s\n\n", mac_str);

		if (macEntry.port_idx == RG_get_lan_phyPortId(portIndex)) {
			sprintf(mac_list, "%s%s;", mac_list, mac_str);
			mac_num++;
		}

		macidx++;
		memset(&macEntry, 0, sizeof(rtk_rg_macEntry_t));
	}

	list_len = strlen(mac_list);
	if (list_len > 0) {
		mac_list[list_len - 1] = 0;
	}
	fprintf(stderr, "[%s] mac_list = %s\n", __FUNCTION__, mac_list);

	return mac_num;
}

int RG_del_LUT_MAC(char *del_mac)
{
	int macidx = 0;
	rtk_rg_macEntry_t macEntry;
	memset(&macEntry, 0, sizeof(rtk_rg_macEntry_t));

	while (RT_ERR_RG_OK == rtk_rg_macEntry_find(&macEntry, &macidx))
	{
		//fprintf(stderr, "macidx = %d\n", macidx);
		//fprintf(stderr, "macEntry.port_idx = %d\n", macEntry.port_idx);
		char mac_str[20] = {0};
		sprintf(mac_str, "%02X:%02X:%02X:%02X:%02X:%02X",
			(unsigned char)macEntry.mac.octet[0], (unsigned char)macEntry.mac.octet[1], (unsigned char)macEntry.mac.octet[2],
			(unsigned char)macEntry.mac.octet[3], (unsigned char)macEntry.mac.octet[4], (unsigned char)macEntry.mac.octet[5]);
		//fprintf(stderr, "mac_str = %s\n\n", mac_str);

		if (strcasecmp(del_mac, mac_str) == 0) {
			fprintf(stderr, "del %s (%d)\n", mac_str, macidx);
			rtk_rg_macEntry_del(macidx);
			return 1;
		}

		macidx++;
		memset(&macEntry, 0, sizeof(rtk_rg_macEntry_t));
	}

	return 0;
}

#ifdef SUPPORT_WAN_BANDWIDTH_INFO
int RG_get_interface_counter(int rg_wan_idx, unsigned long long * uploadcnt, unsigned long long * downloadcnt)
{
	int ret;
	unsigned int chipId;
	unsigned int rev;
	unsigned int subType;

	rtk_rg_switch_version_get(&chipId, &rev, &subType);

	if(chipId == RTL9602C_CHIP_ID)
	{
		rtk_rg_netifMib_entry_t netifMib;

		netifMib.netifIdx = rg_wan_idx;
	    ret = rtk_rg_interfaceMibCounter_get(&netifMib);
		if(ret != RT_ERR_OK)
		{
			DBPRINT(1, "%s rtk_rg_interfaceMibCounter_get idx[%d] failed!\n", __FUNCTION__, rg_wan_idx);
			return -1;
		}
		*uploadcnt = netifMib.out_intf_uc_byte_cnt;
		*downloadcnt = netifMib.in_intf_uc_byte_cnt;
	}
	else
	{
		ret = rtk_rg_stat_port_get(RTK_RG_PORT_PON, IF_OUT_OCTETS_INDEX, uploadcnt);
		if(ret != RT_ERR_OK)
		{
			DBPRINT(1, "%s rtk_rg_stat_port_get failed!\n", __FUNCTION__);
			return -1;
		}

		ret = rtk_rg_stat_port_get(RTK_RG_PORT_PON, IF_IN_OCTETS_INDEX, downloadcnt);
		if(ret != RT_ERR_OK)
		{
			DBPRINT(1, "%s rtk_rg_stat_port_get failed!\n", __FUNCTION__);
			return -1;
		}
	}

	return 0;
}
#endif

#ifdef SUPPORT_WEB_REDIRECT
int RG_set_http_trap_for_bridge(int enable)
{
#ifdef CONFIG_RTL9600_SERIES
	system("echo 0 > /proc/rg/http_trap_bridg_only");
#else
	rtk_rg_aclFilterAndQos_t aclRule;
	FILE *fp;
	int aclIdx;
		
	if((fp = fopen(RG_ACL_HTTP_RULES_FILE, "r"))!=NULL)
	{
		while(fscanf(fp, "%d\n", &aclIdx) != EOF)
		{
			if(rtk_rg_aclFilterAndQos_del(aclIdx))
				DBPRINT(1, "[%s %d]rtk_rg_aclFilterAndQos_del failed! idx = %d\n", __func__,__LINE__,aclIdx);
		}
		
		fclose(fp);
		unlink(RG_ACL_HTTP_RULES_FILE);
	}
#endif
	system("echo 0 > /proc/rg/turn_off_ipv4_shortcut");
		
	if(!enable)
	{
		return 0;
	}
		
#ifdef CONFIG_RTL9600_SERIES
	system("echo 1 > /proc/rg/http_trap_bridg_only");
#else
	if(!(fp = fopen(RG_ACL_HTTP_RULES_FILE, "a")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -1;
	}
		
	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	aclRule.action_type = ACL_ACTION_TYPE_PERMIT;
	aclRule.filter_fields = INGRESS_DMAC_BIT |	INGRESS_PORT_BIT;
	aclRule.ingress_port_mask.portmask = RG_get_all_lan_phyPortMask();
#ifdef WLAN_SUPPORT
	aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN0));
#endif
	aclRule.acl_weight = RG_DEFAULT_ACL_WEIGHT;
		
	mib_get(MIB_ELAN_MAC_ADDR, (void *)&aclRule.ingress_dmac);
	memset(&(aclRule.ingress_dmac_mask), 0xff, MAC_ADDR_LEN);
	if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0)
		fprintf(fp, "%d\n", aclIdx);
	else
		printf("rtk_rg_aclFilterAndQos_add trap http for bridge failed!\n");
		
	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	aclRule.action_type = ACL_ACTION_TYPE_TRAP;
	aclRule.filter_fields = INGRESS_L4_DPORT_RANGE_BIT|  INGRESS_PORT_BIT;
	aclRule.ingress_port_mask.portmask = RG_get_all_lan_phyPortMask();
#ifdef WLAN_SUPPORT
	aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN0));
#ifdef WLAN_DUALBAND_CONCURRENT
		aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN1));
#endif
	aclRule.ingress_port_mask.portmask |= (1 << RTK_RG_PORT_CPU);
#endif
	aclRule.acl_weight = RG_DEFAULT_ACL_WEIGHT;
		
	aclRule.ingress_dest_l4_port_start=80;
	aclRule.ingress_dest_l4_port_end=80;
	if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0)
		fprintf(fp, "%d\n", aclIdx);
	else
		printf("rtk_rg_aclFilterAndQos_add trap http for bridge failed 2!\n");
	fclose(fp);
#endif//end of CONFIG_RTL9600_SERIES
		
	system("echo 1 > /proc/rg/turn_off_ipv4_shortcut");
		
	return 0;
}

int RG_set_redirect_http_Count(int enable, char * httpContent, int size, int count)
{
	int ret;
	rtk_rg_redirectHttpCount_t redInfo;

	if(enable)
		strncpy(redInfo.pushweb, httpContent, MAX_REDIRECT_PUSH_WEB_SIZE);
	else
		redInfo.pushweb[0] = '\0';

	redInfo.enable= enable;
    redInfo.count = count;
	ret = rtk_rg_redirectHttpCount_set(&redInfo);
	if(ret != RT_ERR_OK){
		DBPRINT(1, "%s rtk_rg_redirectHttpAll_set failed ret[%x]\n", __func__, ret);
		return -1;
	}

	return 0;
}

int RG_set_redirect_http_all(int enable, char * httpContent, int size, int count)
{
	int ret;
	rtk_rg_redirectHttpAll_t redInfo;

	printf("%s http size[%d]\n",__func__,size);
	if(enable)
		strncpy(redInfo.pushweb, httpContent, MAX_REDIRECT_PUSH_WEB_SIZE);
	else
		redInfo.pushweb[0] = '\0';

	redInfo.enable= enable;
    redInfo.count = count;
	ret = rtk_rg_redirectHttpAll_set(&redInfo);
	if(ret != RT_ERR_OK){
		DBPRINT(1, "%s rtk_rg_redirectHttpAll_set failed ret[%x]\n", __func__, ret);
		return -1;
	}

	return 0;
}

static const char RG_REDIRECT_HTTP[] = "/proc/rg/redirect_first_http_req_set_url";
int RG_set_welcome_redirect(int enable, char * url)
{
	FILE *fp;

	if (enable)
	{
		fp = fopen(RG_REDIRECT_HTTP, "w");
		fprintf(fp, "a -1 %s", url);
		fclose(fp);
	}else
	{
		fp = fopen(RG_REDIRECT_HTTP, "w");
		fprintf(fp, "d -1");
		fclose(fp);
	}
	return 0;
}

int RG_add_redirectHttpURL(MIB_REDIRECT_URL_LIST_T * redirectUrl)
{
	int ret;
	rtk_rg_redirectHttpURL_t redInfo;

	strncpy(redInfo.url_str, redirectUrl->srcUrl, MAX_URL_FILTER_STR_LENGTH);
	strncpy(redInfo.dst_url_str, redirectUrl->dstUrl, MAX_URL_FILTER_STR_LENGTH);

	redInfo.count= redirectUrl->number;
	ret = rtk_rg_redirectHttpURL_add(&redInfo);
	if(ret != RT_ERR_OK){
		DBPRINT(1, "%s rtk_rg_redirectHttpURL_add ret[%x]\n", __func__, ret);
		return -1;
	}
	return 0;
}

int RG_del_redirectHttpURL(MIB_REDIRECT_URL_LIST_T * redirectUrl)
{
	int ret;
	rtk_rg_redirectHttpURL_t redInfo;

	strncpy(redInfo.url_str, redirectUrl->srcUrl, MAX_URL_FILTER_STR_LENGTH);

	ret = rtk_rg_redirectHttpURL_del(&redInfo);
	if(ret != RT_ERR_OK){
		DBPRINT(1, "%s rtk_rg_redirectHttpURL_del ret[%x]\n", __func__, ret);
		return -1;
	}
	return 0;
}

int RG_add_redirectWhiteUrl(MIB_REDIRECT_WHITE_LIST_T * whiteUrl)
{
	int ret;
	rtk_rg_redirectHttpWhiteList_t redInfo;

	strncpy(redInfo.url_str, whiteUrl->url, MAX_URL_FILTER_STR_LENGTH);
	strncpy(redInfo.keyword_str, whiteUrl->keyword, MAX_URL_FILTER_STR_LENGTH);
	ret = rtk_rg_redirectHttpWhiteList_add(&redInfo);
	if(ret != RT_ERR_OK){
		DBPRINT(1, "%s rtk_rg_redirectHttpWhiteList_add ret[%x]\n", __func__, ret);
		return -1;
	}
	return 0;
}

int RG_del_redirectWhiteUrl(MIB_REDIRECT_WHITE_LIST_T * whiteUrl)
{
	int ret;
	rtk_rg_redirectHttpWhiteList_t redInfo;

	strncpy(redInfo.url_str, whiteUrl->url, MAX_URL_FILTER_STR_LENGTH);
	strncpy(redInfo.keyword_str, whiteUrl->keyword, MAX_URL_FILTER_STR_LENGTH);
	ret = rtk_rg_redirectHttpWhiteList_del(&redInfo);
	if(ret != RT_ERR_OK){
		DBPRINT(1, "%s rtk_rg_redirectHttpWhiteList_del ret[%x]\n", __func__, ret);
		return -1;
	}
	return 0;
}

#endif

#if defined(SUPPORT_MCAST_TEST) || defined(CONFIG_USER_QUICKINSTALL)
int RG_get_pon_port_stat(unsigned long long * downloadcnt)
{
	int ret;
	ret = rtk_rg_stat_port_get(RTK_RG_PORT_PON, IF_IN_OCTETS_INDEX, downloadcnt);
	if(ret != RT_ERR_OK)
	{
		DBPRINT(1, "%s rtk_rg_stat_port_get failed!\n", __FUNCTION__);
		return -1;
	}

	return 0;
}

int RG_get_WanPortBindingMask(int rg_wan_idx, int *portbindingmask)
{
	rtk_rg_intfInfo_t intf_info;
	int ret;
	memset(&intf_info, 0, sizeof(rtk_rg_intfInfo_t));
	ret = rtk_rg_intfInfo_find(&intf_info, &rg_wan_idx);
	if(ret != RT_ERR_OK){
		printf("Find RG interface for wan index %d Fail! Return -1!\n", rg_wan_idx);
		return -1;
	}
	*portbindingmask = intf_info.wan_intf.wan_intf_conf.port_binding_mask.portmask;
	return 0;
}

int RG_get_MulticastFlow(int *valid_idx, int *portmask)
{

	rtk_rg_multicastFlow_t mcFlow;
	memset(&mcFlow, 0, sizeof(rtk_rg_multicastFlow_t));
	rtk_rg_multicastFlow_find(&mcFlow, valid_idx);

	if(mcFlow.multicast_ipv4_addr==0) //null entry, find with new valid_idx
		return -1;

	*portmask = mcFlow.port_mask.portmask;

	//printf("%d %x %x\n", *valid_idx, *portmask, mcFlow.multicast_ipv4_addr);

	if(mcFlow.multicast_ipv4_addr == 0xEFFFFFFA) //239.255.255.250
		return -1;

	if((mcFlow.multicast_ipv4_addr & 0xFFFFFF00) == 0xE0000000) //224.0.0.x
		return -1;

	*valid_idx++;
	return 0;
}
#endif



void RTK_Setup_Storm_Control(void)
{
	int portId;
	int portNum;
	unsigned int meterId;
	unsigned int bcmeterId;	
	rtk_switch_devInfo_t	tDevInfo;
	rtk_rate_storm_group_ctrl_t	stormCtrl;
	rtk_rate_storm_group_ctrl_t bcstormCtrl;	
	
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	unsigned int storm_control_bit_rate = 0;
	mib_get(MIB_STORM_CONTROL_BIT_RATE, (void *)&storm_control_bit_rate);

	meterId = STORM_CONTROL_SM_ID_NUM;
	bcmeterId = STORM_CONTROL_BCAST_SM_ID_NUM; //STORM_CONTROL_SM_ID_NUM-1
	rtk_rg_shareMeter_set(meterId, (storm_control_bit_rate > 0) ? storm_control_bit_rate:800, RTK_RG_ENABLED);
	rtk_rg_shareMeter_set(bcmeterId, (storm_control_bit_rate > 0) ? storm_control_bit_rate:800, RTK_RG_ENABLED);

	unsigned int lan_portmask = 0;
	char cmdStr[64] = {0};
	lan_portmask = RG_get_all_lan_phyPortMask();
	sprintf(cmdStr, "echo %d > /proc/rg/IPv4_MC_rate_limit", meterId);
	system(cmdStr);
	sprintf(cmdStr, "echo 0x%x > /proc/rg/IPv4_MC_rate_limit_portMask", lan_portmask);
	system(cmdStr);
#ifdef CONFIG_IPV6
	sprintf(cmdStr, "echo %d > /proc/rg/IPv6_MC_rate_limit", meterId);
	system(cmdStr);
	sprintf(cmdStr, "echo 0x%x > /proc/rg/IPv6_MC_rate_limit_portMask", lan_portmask);
	system(cmdStr);
#endif
#else
	rtk_rg_switch_deviceInfo_get (&tDevInfo);
	meterId  = tDevInfo.capacityInfo.max_num_of_metering - 1;
	bcmeterId = meterId -1;	
#ifdef CONFIG_RTL9600_SERIES
	rtk_rg_rate_shareMeterMode_set (meterId, METER_MODE_BIT_RATE);
	rtk_rg_rate_shareMeter_set (meterId, 7000, DISABLED);
	rtk_rg_rate_shareMeterMode_set (bcmeterId, METER_MODE_BIT_RATE);
    rtk_rg_rate_shareMeter_set (bcmeterId, 7000, DISABLED);	
#else
	rtk_rg_rate_shareMeterMode_set (meterId, METER_MODE_PACKET_RATE);
	rtk_rg_rate_shareMeter_set (meterId, 7000, DISABLED);
    rtk_rg_rate_shareMeterMode_set (bcmeterId, METER_MODE_PACKET_RATE);
    rtk_rg_rate_shareMeter_set (bcmeterId, 7000, DISABLED);	
#endif
#endif
	rtk_rg_rate_stormControlEnable_get(&stormCtrl);
	stormCtrl.unknown_unicast_enable = ENABLED;
	//stormCtrl.unknown_multicast_enable  = ENABLED;
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	//stormCtrl.dhcp_enable = ENABLED;
	stormCtrl.arp_enable = ENABLED;
	stormCtrl.igmp_mld_enable = ENABLED;
#endif
	rtk_rg_rate_stormControlEnable_set (&stormCtrl);
	rtk_rg_rate_stormControlEnable_get(&bcstormCtrl);
	bcstormCtrl.broadcast_enable = ENABLED;
	rtk_rg_rate_stormControlEnable_set (&bcstormCtrl);

#if defined(CONFIG_PON_LED_PROFILE_DEMO_RTL9607) || defined(CONFIG_PON_LED_PROFILE_DEMO_RTL9607_IAD_V00) || defined(CONFIG_PON_LED_PROFILE_DEMO_RTL9607_IAD_V01)
	portNum = 4; //0,1,2,3  4(wan)
#elif defined(CONFIG_PON_LED_PROFILE_DEMO_RTL9602B) || defined(CONFIG_RTL9602C_SERIES)
	portNum = 2; //0,1  2(wan)
#elif defined(CONFIG_RTL9607C_SERIES)
	portNum = 5;
#else
	portNum = 4; //other case such as 8696
#endif
//AUG_PRT("%s-%d portNum=%d\n",__func__,__LINE__,portNum);

	/*portId for all LAN + WAN port*/
	for(portId = 0 ; portId <= portNum; portId ++)
	{
		rtk_rg_rate_stormControlMeterIdx_set(portId, STORM_GROUP_UNKNOWN_UNICAST, meterId);
		rtk_rg_rate_stormControlMeterIdx_set (portId, STORM_GROUP_BROADCAST, bcmeterId);
		//rtk_rg_rate_stormControlMeterIdx_set (portId, STORM_GROUP_UNKNOWN_MULTICAST, meterId);
		rtk_rg_rate_stormControlPortEnable_set (portId, STORM_GROUP_UNKNOWN_UNICAST, ENABLED);
		rtk_rg_rate_stormControlPortEnable_set (portId, STORM_GROUP_BROADCAST, ENABLED);
		//rtk_rg_rate_stormControlPortEnable_set (portId, STORM_GROUP_UNKNOWN_MULTICAST, ENABLED);
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		//rtk_rg_rate_stormControlMeterIdx_set (portId, STORM_GROUP_DHCP, meterId);
		rtk_rg_rate_stormControlMeterIdx_set (portId, STORM_GROUP_ARP, meterId);
		rtk_rg_rate_stormControlMeterIdx_set (portId, STORM_GROUP_IGMP_MLD, meterId);
		//rtk_rg_rate_stormControlPortEnable_set (portId, STORM_GROUP_DHCP, ENABLED);
		rtk_rg_rate_stormControlPortEnable_set (portId, STORM_GROUP_ARP, ENABLED);
		rtk_rg_rate_stormControlPortEnable_set (portId, STORM_GROUP_IGMP_MLD, ENABLED);
#endif
	}



}

#if defined(CONFIG_USER_PPTP_CLIENT_PPTP) && defined(CONFIG_USER_L2TPD_L2TPD)
int RG_Set_WanVPN_QoS(int vpn_type)
{
	int i, ret, faild=0;
	unsigned int vpn_entry_num=0;
	rtk_rg_aclFilterAndQos_t aclRule;
	MIB_L2TP_T l2tp_entry;
	MIB_PPTP_T pptp_entry;
	int aclIdx;

	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));

	if(VPN_TYPE_L2TP==vpn_type){
		vpn_entry_num = mib_chain_total(MIB_L2TP_TBL);
		for( i = 0; i < vpn_entry_num; i++ )
		{
			if(!mib_chain_get(MIB_L2TP_TBL, i, (void *)&l2tp_entry))
				continue;

			if(l2tp_entry.acl_idx)
			{
				if(rtk_rg_aclFilterAndQos_del(l2tp_entry.acl_idx))
					DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed!\n");
			}

			if(l2tp_entry.rg_wan_idx) {
				if( 0<=l2tp_entry.priority && l2tp_entry.priority<=7 )
				{
					aclRule.acl_weight = RG_QOS_WANVPNINTERFACE_ACL_WEIGHT;
					aclRule.filter_fields = EGRESS_INTF_BIT;
					aclRule.egress_intf_idx = l2tp_entry.rg_wan_idx; // Set egress interface.
					aclRule.action_type = ACL_ACTION_TYPE_QOS;
					aclRule.qos_actions |= ACL_ACTION_ACL_PRIORITY_BIT;
					aclRule.action_acl_priority = ACL_QOS_INTERNAL_PRIORITY_START - 4;
					if(aclRule.action_acl_priority>7){
						AUG_PRT("%s-%d action_acl_priority can't > 7!!\n",__func__,__LINE__);
						return -1;
					}					
					if(ret=rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)){
						printf("rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n", ret);
						faild=1;
					}
					l2tp_entry.acl_idx = aclIdx;
					mib_chain_update(MIB_L2TP_TBL, &l2tp_entry, i);
				}
			}
		}
	}
	else if(VPN_TYPE_PPTP==vpn_type) {
		vpn_entry_num = mib_chain_total(MIB_PPTP_TBL);
		for( i = 0; i < vpn_entry_num; i++ )
		{
			if(!mib_chain_get(MIB_PPTP_TBL, i, (void *)&pptp_entry))
				continue;

			if(pptp_entry.acl_idx)
			{
				if(rtk_rg_aclFilterAndQos_del(pptp_entry.acl_idx))
					DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed!\n");
			}

			if(pptp_entry.rg_wan_idx) {
				if( 0<=pptp_entry.priority && pptp_entry.priority<=7 )
				{
					aclRule.acl_weight = RG_QOS_WANVPNINTERFACE_ACL_WEIGHT;
					aclRule.filter_fields = EGRESS_INTF_BIT;
					aclRule.egress_intf_idx = pptp_entry.rg_wan_idx; // Set egress interface.
					aclRule.action_type = ACL_ACTION_TYPE_QOS;
					aclRule.qos_actions |= ACL_ACTION_ACL_PRIORITY_BIT;
					aclRule.action_acl_priority = ACL_QOS_INTERNAL_PRIORITY_START - 4;
					if(aclRule.action_acl_priority>7){
						AUG_PRT("%s-%d action_acl_priority can't > 7!!\n",__func__,__LINE__);
						return -1;
					}					
					if(ret=rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)){
						printf("rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n", ret);
						faild=1;
					}
					pptp_entry.acl_idx = aclIdx;
					mib_chain_update(MIB_PPTP_TBL, &pptp_entry, i);
				}
			}
		}
	}
	else{
		printf("%s %d Invalid vpn_type!\n", __func__, __LINE__);
		return -1;
	}

	if(faild){
		printf("%s %d Some ACL rule create FAIL!\n", __func__, __LINE__);
		return -1;
	}
	else{
		return 0;
	}
}

int RG_Del_WanVPN_QoS(unsigned int acl_idx)
{
	if(acl_idx){
		if(rtk_rg_aclFilterAndQos_del(acl_idx)){
			DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed!\n");
			return -1;
		}

		return 0;
	}
	else{
		printf("%s %d Invalid acl_idx=%d!\n", __func__, __LINE__, acl_idx);
		return -1;
	}
}

int RG_Get_WanVPN_Status(unsigned int index)
{
	int ret, packet_count=-1;
	rtk_rg_naptFilterAndQos_t napt_filter;

	if(index == -1)
		return 0;

	memset(&napt_filter,0,sizeof(napt_filter));
	ret = rtk_rg_naptFilterAndQos_find(&index,&napt_filter);
	if(ret!=RT_ERR_RG_OK) {
		printf("%s %d rtk_rg_apollo_naptFilterAndQos_find FAIL!", __func__, __LINE__);
		return -1;
	}
	packet_count=napt_filter.packet_count;
	return packet_count;
}

int Get_Packet_Count_By_Route_Index(VPN_TYPE_T vpn_type, unsigned int index)
{
	FILE *fp,*fp_tmp;
	int acl_idx, napt_idx, route_idx;
	unsigned int napt_last_pkt_cnt;
	char line[64];
	char name[32];
	int total_packet_count=0;
	int pad_packet_count;


	switch(vpn_type)
	{
		case VPN_TYPE_PPTP:

			if((fp = fopen(PPTP_ACL_ROUTE_TBL, "r"))) {
				while(fgets(line, 64, fp) != NULL)
				{
					sscanf(line, "%s %d %d %d %d\n",name, &acl_idx, &route_idx, &napt_idx, &napt_last_pkt_cnt);
					if(index==route_idx){
						total_packet_count += RG_Get_WanVPN_Status(napt_idx);
					}
				}
				fclose(fp);
			}

			if((fp = fopen(PPTP_ACL_URL_ROUTE_TBL, "r"))) {		
				while(fgets(line, 64, fp) != NULL)
				{
					sscanf(line, "%s %d %d %d %d\n",name, &acl_idx, &route_idx, &napt_idx, &napt_last_pkt_cnt);
					if(index==route_idx){
						total_packet_count += RG_Get_WanVPN_Status(napt_idx);
					}
				}
				fclose(fp);
			}

			break;

		case VPN_TYPE_L2TP:

			if((fp = fopen(L2TP_ACL_ROUTE_TBL, "r"))) {
				while(fgets(line, 64, fp) != NULL)
				{
					sscanf(line, "%s %d %d %d %d\n",name, &acl_idx, &route_idx, &napt_idx, &napt_last_pkt_cnt);
					if(index==route_idx){
						total_packet_count += RG_Get_WanVPN_Status(napt_idx);
					}
				}
				fclose(fp);
			}

			if((fp = fopen(L2TP_ACL_URL_ROUTE_TBL, "r"))) {
				while(fgets(line, 64, fp) != NULL)
				{
					sscanf(line, "%s %d %d %d %d\n",name, &acl_idx, &route_idx, &napt_idx, &napt_last_pkt_cnt);
					if(index==route_idx){
						total_packet_count += RG_Get_WanVPN_Status(napt_idx);
					}
				}
				fclose(fp);
			}

			break;

		default:
			printf("%s %d Invalid VPN Type!", __func__, __LINE__);
			return 0;
	}

	total_packet_count += load_vpn_packet_count_by_route_idx(vpn_type, index);
	if(total_packet_count) {
		//pad minus total packet count to refreash the statistic for next time query
		pad_packet_count = load_vpn_packet_count_by_ip(vpn_type, 0xffffff00+index);
		save_vpn_packet_count(vpn_type, index, 0xffffff00+index, pad_packet_count-total_packet_count);
	}

	if(total_packet_count>0)
		return total_packet_count;
	else 
		return 0;
}

int RG_Get_Packet_Count_By_Ifname(VPN_TYPE_T vpn_type, unsigned char *if_name)
{
	MIB_L2TP_T l2tp_entry;
	MIB_PPTP_T pptp_entry;
	int total_l2tp_num, total_pptp_num;
	unsigned char mib_ifname[20], if_tunnelname[MAX_NAME_LEN];
	unsigned int total_pkt_cnt=0;
	FILE *fp,*fp_tmp;
	int acl_idx, napt_idx, route_idx, i;
	unsigned int napt_last_pkt_cnt;
	char line[64];
	char name[32];


	switch(vpn_type)
	{
		case VPN_TYPE_PPTP:

			if_tunnelname[0] = '\0';
			total_pptp_num = mib_chain_total(MIB_PPTP_TBL); /* get chain record size */
			for(i=0 ; i<total_pptp_num ; i++) {
				if ( !mib_chain_get(MIB_PPTP_TBL, i, (void *)&pptp_entry) )
					continue;

				ifGetName(pptp_entry.ifIndex, mib_ifname, sizeof(mib_ifname));
				if(!strcmp(mib_ifname, if_name)) {
					sprintf(if_tunnelname, "%s", pptp_entry.tunnelName);
				}
			}	

			if(if_tunnelname[0] != '\0') {
				if((fp = fopen(PPTP_ACL_ROUTE_TBL, "r"))) {
					while(fgets(line, 64, fp) != NULL)
					{
						sscanf(line, "%s %d %d %d %d\n",name, &acl_idx, &route_idx, &napt_idx, &napt_last_pkt_cnt);
						if(!strcmp(if_tunnelname, name)){
							total_pkt_cnt += RG_Get_WanVPN_Status(napt_idx);
						}
					}
					fclose(fp);
				}

				if((fp = fopen(PPTP_ACL_URL_ROUTE_TBL, "r"))) {
					while(fgets(line, 64, fp) != NULL)
					{
						sscanf(line, "%s %d %d %d %d\n",name, &acl_idx, &route_idx, &napt_idx, &napt_last_pkt_cnt);
						if(!strcmp(if_tunnelname, name) && (napt_idx != -1)){
							total_pkt_cnt += RG_Get_WanVPN_Status(napt_idx);
						}
					}
					fclose(fp);
				}
			}

			break;

		case VPN_TYPE_L2TP:
			
			if_tunnelname[0] = '\0';
			total_l2tp_num = mib_chain_total(MIB_L2TP_TBL); /* get chain record size */
			for(i=0 ; i<total_l2tp_num ; i++) {
				if ( !mib_chain_get(MIB_L2TP_TBL, i, (void *)&l2tp_entry) )
					continue;

				ifGetName(l2tp_entry.ifIndex, mib_ifname, sizeof(mib_ifname));
				if(!strcmp(mib_ifname, if_name)) {
					sprintf(if_tunnelname, "%s", l2tp_entry.tunnelName);
				}
			}	

			if(if_tunnelname[0] != '\0') {
				if((fp = fopen(L2TP_ACL_ROUTE_TBL, "r"))) {
					while(fgets(line, 64, fp) != NULL)
					{
						sscanf(line, "%s %d %d %d %d\n",name, &acl_idx, &route_idx, &napt_idx, &napt_last_pkt_cnt);
						if(!strcmp(if_tunnelname, name)){
							total_pkt_cnt += RG_Get_WanVPN_Status(napt_idx);
						}
					}
					fclose(fp);
				}				

				if((fp = fopen(L2TP_ACL_URL_ROUTE_TBL, "r"))) {
					while(fgets(line, 64, fp) != NULL)
					{
						sscanf(line, "%s %d %d %d %d\n",name, &acl_idx, &route_idx, &napt_idx, &napt_last_pkt_cnt);
						if(!strcmp(if_tunnelname, name) && (napt_idx != -1)){
							total_pkt_cnt += RG_Get_WanVPN_Status(napt_idx);
						}
					}
					fclose(fp);
				}
			}
			
			break;

		default:
			printf("%s %d Invalid VPN Type!", __func__, __LINE__);
			return 0;
	}

	return total_pkt_cnt;
}

int Dynamic_VPN_ACL_Policy_Route_Update(VPN_TYPE_T vpn_type, unsigned char *if_name, unsigned char to_default) {
	unsigned char mib_ifname[20], if_tunnelname[MAX_NAME_LEN];
	int acl_idx, napt_idx, route_idx, tmp_idx, i;
	unsigned int napt_last_pkt_cnt;
	rtk_rg_aclFilterAndQos_t aclRule;
	MIB_CE_ATM_VC_T vc_entry;
	MIB_L2TP_T l2tp_entry;
	MIB_PPTP_T pptp_entry;
	int total_num, def_RGWANIdx;	
	FILE *fp,*fp_tmp;	
	char line[64];
	char name[32];
	int ret;

	def_RGWANIdx = -1;
	total_num = mib_chain_total(MIB_ATM_VC_TBL); /* get chain record size */
	for(i=0 ; i<total_num ; i++) {
		if ( !mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&vc_entry) )
			continue;

		if(vc_entry.dgw == 1) {
			def_RGWANIdx = vc_entry.rg_wan_idx;
			break;
		}
	}

	switch(vpn_type)
	{
		case VPN_TYPE_PPTP:

			if_tunnelname[0] = '\0';
			total_num = mib_chain_total(MIB_PPTP_TBL); /* get chain record size */
			for(i=0 ; i<total_num ; i++) {
				if ( !mib_chain_get(MIB_PPTP_TBL, i, (void *)&pptp_entry) )
					continue;

				ifGetName(pptp_entry.ifIndex, mib_ifname, sizeof(mib_ifname));
				if(!strcmp(mib_ifname, if_name)) {
					sprintf(if_tunnelname, "%s", pptp_entry.tunnelName);
				}
			}
			
			if(if_tunnelname[0] != '\0') {				
				if((fp = fopen(PPTP_ACL_URL_ROUTE_TBL, "r"))) {
					
					if(!(fp_tmp = fopen(PPTP_ACL_URL_ROUTE_TBL_TMP, "w"))) {
						fclose(fp);
						return -2;
					}
					
					while(fgets(line, 64, fp) != NULL)
					{
						sscanf(line, "%s %d %d %d %d\n",name, &acl_idx, &route_idx, &napt_idx, &napt_last_pkt_cnt);

						if(!strcmp(if_tunnelname, name)){
							if(acl_idx != -1) {							
								tmp_idx = acl_idx;
								memset(&aclRule, 0x0, sizeof(rtk_rg_aclFilterAndQos_t));
								if(!rtk_rg_aclFilterAndQos_find(&aclRule, &acl_idx)) {
									if(tmp_idx == acl_idx) {
										if(!rtk_rg_aclFilterAndQos_del(acl_idx)) {
											if(to_default && def_RGWANIdx != -1)
												aclRule.action_policy_route_wan = def_RGWANIdx;
											else
												aclRule.action_policy_route_wan = pptp_entry.rg_wan_idx;
											if(rtk_rg_aclFilterAndQos_add(&aclRule, &acl_idx)) {											
												DBPRINT(1, "rtk_rg_aclFilterAndQos_add failed! idx = %d\n", acl_idx);												
											} else {
												fprintf(fp_tmp, "%s %d -1 -1 -1\n", name, acl_idx);
											}
										}
									} else {									
										DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", acl_idx);
										fprintf(fp_tmp, "%s %d %d %d %d\n", name, acl_idx, route_idx, napt_idx, napt_last_pkt_cnt);
									}								
								} else {							
									DBPRINT(1, "rtk_rg_aclFilterAndQos_find failed! idx = %d\n", acl_idx);
								}
							} else {
								fprintf(fp_tmp, "%s %d %d %d %d\n", name, acl_idx, route_idx, napt_idx, napt_last_pkt_cnt);
							}
						} else {
							fprintf(fp_tmp, "%s %d %d %d %d\n", name, acl_idx, route_idx, napt_idx, napt_last_pkt_cnt);
						}
					}

					fclose(fp);
					fclose(fp_tmp);					
					unlink(PPTP_ACL_URL_ROUTE_TBL);
					rename(PPTP_ACL_URL_ROUTE_TBL_TMP, PPTP_ACL_URL_ROUTE_TBL);
				}
			}
			
			break;
		
		case VPN_TYPE_L2TP:
			
			if_tunnelname[0] = '\0';
			total_num = mib_chain_total(MIB_L2TP_TBL); /* get chain record size */
			for(i=0 ; i<total_num ; i++) {
				if ( !mib_chain_get(MIB_L2TP_TBL, i, (void *)&l2tp_entry) )
					continue;

				ifGetName(l2tp_entry.ifIndex, mib_ifname, sizeof(mib_ifname));
				if(!strcmp(mib_ifname, if_name)) {
					sprintf(if_tunnelname, "%s", l2tp_entry.tunnelName);
					break;
				}
			}	

			if(if_tunnelname[0] != '\0') {				
				if((fp = fopen(L2TP_ACL_URL_ROUTE_TBL, "r"))) {
					
					if(!(fp_tmp = fopen(L2TP_ACL_URL_ROUTE_TBL_TMP, "w"))) {
						fclose(fp);
						return -2;
					}
					
					while(fgets(line, 64, fp) != NULL)
					{
						sscanf(line, "%s %d %d %d %d\n",name, &acl_idx, &route_idx, &napt_idx, &napt_last_pkt_cnt);

						if(!strcmp(if_tunnelname, name)){
							if(acl_idx != -1) {							
								tmp_idx = acl_idx;
								memset(&aclRule, 0x0, sizeof(rtk_rg_aclFilterAndQos_t));
								if(!rtk_rg_aclFilterAndQos_find(&aclRule, &acl_idx)) {
									if(tmp_idx == acl_idx) {
										if(!rtk_rg_aclFilterAndQos_del(acl_idx)) {
											if(to_default && def_RGWANIdx != -1)
												aclRule.action_policy_route_wan = def_RGWANIdx;
											else
												aclRule.action_policy_route_wan = l2tp_entry.rg_wan_idx;
											if(rtk_rg_aclFilterAndQos_add(&aclRule, &acl_idx)) {											
												DBPRINT(1, "rtk_rg_aclFilterAndQos_add failed! idx = %d\n", acl_idx);												
											} else {
												fprintf(fp_tmp, "%s %d -1 -1 -1\n", name, acl_idx);
											}
										}
									} else {									
										DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", acl_idx);
										fprintf(fp_tmp, "%s %d %d %d %d\n", name, acl_idx, route_idx, napt_idx, napt_last_pkt_cnt);
									}								
								} else {							
									DBPRINT(1, "rtk_rg_aclFilterAndQos_find failed! idx = %d\n", acl_idx);
								}
							} else {
								fprintf(fp_tmp, "%s %d %d %d %d\n", name, acl_idx, route_idx, napt_idx, napt_last_pkt_cnt);
							}
						} else {
							fprintf(fp_tmp, "%s %d %d %d %d\n", name, acl_idx, route_idx, napt_idx, napt_last_pkt_cnt);
						}
					}

					fclose(fp);
					fclose(fp_tmp);					
					unlink(L2TP_ACL_URL_ROUTE_TBL);
					rename(L2TP_ACL_URL_ROUTE_TBL_TMP, L2TP_ACL_URL_ROUTE_TBL);
				}
			}
			
			break;
	}
}

/*
* type: 0 static, 1 dynamic
* to_default: 0: only packet count 1: packet count + trap to protocol stack
*/
int VPN_NAPT_Rule_Update(VPN_TYPE_T vpn_type, unsigned char *if_name, unsigned char to_default, unsigned char type) {
	unsigned char mib_ifname[20], if_tunnelname[MAX_NAME_LEN];
	int acl_idx, napt_idx, route_idx, tmp_idx, i;
	unsigned int napt_last_pkt_cnt;
	rtk_rg_naptFilterAndQos_t naptRule;
	MIB_CE_ATM_VC_T vc_entry;
	MIB_L2TP_T l2tp_entry;
	MIB_PPTP_T pptp_entry;
	int total_num;	
	FILE *fp,*fp_tmp,*fp_lock;	
	char line[64];
	char name[32];
	int ret;
	
		
	switch(vpn_type)
	{
		case VPN_TYPE_PPTP:

			if_tunnelname[0] = '\0';
			total_num = mib_chain_total(MIB_PPTP_TBL); /* get chain record size */
			for(i=0 ; i<total_num ; i++) {
				if ( !mib_chain_get(MIB_PPTP_TBL, i, (void *)&pptp_entry) )
					continue;

				ifGetName(pptp_entry.ifIndex, mib_ifname, sizeof(mib_ifname));
				if(!strcmp(mib_ifname, if_name)) {
					sprintf(if_tunnelname, "%s", pptp_entry.tunnelName);
					break;
				}
			}
			
			if(if_tunnelname[0] != '\0') {
				
				fp_lock = fopen(type?PPTP_ACL_URL_ROUTE_TBL_LOCK:PPTP_ACL_ROUTE_TBL_LOCK, "r");
				while(fp_lock) {
					fp_lock = fopen(type?PPTP_ACL_URL_ROUTE_TBL_LOCK:PPTP_ACL_ROUTE_TBL_LOCK, "r");
				}
				fp_lock = fopen(type?PPTP_ACL_URL_ROUTE_TBL_LOCK:PPTP_ACL_ROUTE_TBL_LOCK, "a");
				
				if((fp = fopen(type?PPTP_ACL_URL_ROUTE_TBL:PPTP_ACL_ROUTE_TBL, "r"))) {
					
					if(!(fp_tmp = fopen(type?PPTP_ACL_URL_ROUTE_TBL_TMP:PPTP_ACL_ROUTE_TBL_TMP, "w"))) {
						fclose(fp);
						fclose(fp_lock);
						unlink(type?PPTP_ACL_URL_ROUTE_TBL_LOCK:PPTP_ACL_ROUTE_TBL_LOCK);
						return -2;
					}
					
					while(fgets(line, 64, fp) != NULL)
					{
						sscanf(line, "%s %d %d %d %d\n",name, &acl_idx, &route_idx, &napt_idx, &napt_last_pkt_cnt);						
						if(!strcmp(if_tunnelname, name)){
							if(napt_idx != -1) {							
								tmp_idx = napt_idx;
								memset(&naptRule, 0x0, sizeof(rtk_rg_naptFilterAndQos_t));
								if(!rtk_rg_naptFilterAndQos_find(&napt_idx, &naptRule)) {									
									if(tmp_idx == napt_idx) {
										if(!rtk_rg_naptFilterAndQos_del(napt_idx)) {
											if(!to_default && pptp_entry.enctype != VPN_ENCTYPE_NONE) {
												naptRule.action_fields = NAPT_SW_PACKET_COUNT | NAPT_SW_TRAP_TO_PS;
											} else {
												naptRule.action_fields = NAPT_SW_PACKET_COUNT;
											}
											if(rtk_rg_naptFilterAndQos_add(&napt_idx, &naptRule)) {											
												DBPRINT(1, "rtk_rg_aclFilterAndQos_add failed! idx = %d\n", napt_idx);												
											} else {
												fprintf(fp_tmp, "%s -1 %d %d %d\n", name, route_idx, napt_idx, napt_last_pkt_cnt);
											}
										}
									} else {
										DBPRINT(1, "rtk_rg_naptFilterAndQos_del failed! idx = %d\n", napt_idx);										
										fprintf(fp_tmp, "%s %d %d %d %d\n", name, acl_idx, route_idx, napt_idx, napt_last_pkt_cnt);
									}								
								} else {							
									DBPRINT(1, "rtk_rg_naptFilterAndQos_find failed! idx = %d\n", napt_idx);
								}
							} else {
								fprintf(fp_tmp, "%s %d %d %d %d\n", name, acl_idx, route_idx, napt_idx, napt_last_pkt_cnt);
							}
						} else {
							fprintf(fp_tmp, "%s %d %d %d %d\n", name, acl_idx, route_idx, napt_idx, napt_last_pkt_cnt);
						}
					}

					fclose(fp);
					fclose(fp_tmp);					
					unlink(type?PPTP_ACL_URL_ROUTE_TBL:PPTP_ACL_ROUTE_TBL);
					rename(type?PPTP_ACL_URL_ROUTE_TBL_TMP:PPTP_ACL_ROUTE_TBL_TMP, type?PPTP_ACL_URL_ROUTE_TBL:PPTP_ACL_ROUTE_TBL);
					
				}
				
				fclose(fp_lock);
				unlink(type?PPTP_ACL_URL_ROUTE_TBL_LOCK:PPTP_ACL_ROUTE_TBL_LOCK);
			}
			
			break;
		
		case VPN_TYPE_L2TP:
			
			if_tunnelname[0] = '\0';
			total_num = mib_chain_total(MIB_L2TP_TBL); /* get chain record size */
			for(i=0 ; i<total_num ; i++) {
				if ( !mib_chain_get(MIB_L2TP_TBL, i, (void *)&l2tp_entry) )
					continue;

				ifGetName(l2tp_entry.ifIndex, mib_ifname, sizeof(mib_ifname));
				if(!strcmp(mib_ifname, if_name)) {
					sprintf(if_tunnelname, "%s", l2tp_entry.tunnelName);
					break;
				}
			}	

			if(if_tunnelname[0] != '\0') {	

				fp_lock = fopen(type?L2TP_ACL_URL_ROUTE_TBL_LOCK:L2TP_ACL_ROUTE_TBL_LOCK, "r");
				while(fp_lock) {
					fp_lock = fopen(type?L2TP_ACL_URL_ROUTE_TBL_LOCK:L2TP_ACL_ROUTE_TBL_LOCK, "r");
				}
				fp_lock = fopen(type?L2TP_ACL_URL_ROUTE_TBL_LOCK:L2TP_ACL_ROUTE_TBL_LOCK, "a");
				
				if((fp = fopen(type?L2TP_ACL_URL_ROUTE_TBL:L2TP_ACL_ROUTE_TBL, "r"))) {
					
					if(!(fp_tmp = fopen(type?L2TP_ACL_URL_ROUTE_TBL_TMP:L2TP_ACL_ROUTE_TBL_TMP, "w"))) {
						fclose(fp);
						fclose(fp_lock);
						unlink(type?L2TP_ACL_URL_ROUTE_TBL_LOCK:L2TP_ACL_ROUTE_TBL_LOCK);
						return -2;
					}
					
					while(fgets(line, 64, fp) != NULL)
					{
						sscanf(line, "%s %d %d %d %d\n",name, &acl_idx, &route_idx, &napt_idx, &napt_last_pkt_cnt);

						if(!strcmp(if_tunnelname, name)){
							if(napt_idx != -1) {							
								tmp_idx = napt_idx;
								memset(&naptRule, 0x0, sizeof(rtk_rg_naptFilterAndQos_t));
								if(!rtk_rg_naptFilterAndQos_find(&napt_idx, &naptRule)) {
									if(tmp_idx == napt_idx) {
										if(!rtk_rg_naptFilterAndQos_del(napt_idx)) {
											if(to_default && l2tp_entry.enctype == VPN_ENCTYPE_NONE)
												naptRule.action_fields = NAPT_SW_PACKET_COUNT;
											else
												naptRule.action_fields = NAPT_SW_PACKET_COUNT | NAPT_SW_TRAP_TO_PS;
											if(rtk_rg_naptFilterAndQos_add(&napt_idx, &naptRule)) {											
												DBPRINT(1, "rtk_rg_aclFilterAndQos_add failed! idx = %d\n", napt_idx);
											} else {												
												fprintf(fp_tmp, "%s -1 %d %d %d\n", name, route_idx, napt_idx, napt_last_pkt_cnt);
											}
										}
									} else {									
										DBPRINT(1, "rtk_rg_naptFilterAndQos_del failed! idx = %d\n", napt_idx);										
										fprintf(fp_tmp, "%s %d %d %d %d\n", name, acl_idx, route_idx, napt_idx, napt_last_pkt_cnt);
									}								
								} else {							
									DBPRINT(1, "rtk_rg_naptFilterAndQos_find failed! idx = %d\n", napt_idx);
								}
							} else {
								fprintf(fp_tmp, "%s %d %d %d %d\n", name, acl_idx, route_idx, napt_idx, napt_last_pkt_cnt);
							}
						} else {
							fprintf(fp_tmp, "%s %d %d %d %d\n", name, acl_idx, route_idx, napt_idx, napt_last_pkt_cnt);
						}
					}

					fclose(fp);
					fclose(fp_tmp);					
					unlink(type?L2TP_ACL_URL_ROUTE_TBL:L2TP_ACL_ROUTE_TBL);
					rename(type?L2TP_ACL_URL_ROUTE_TBL_TMP:L2TP_ACL_URL_ROUTE_TBL, type?L2TP_ACL_URL_ROUTE_TBL:L2TP_ACL_ROUTE_TBL);
					
				}
				
				fclose(fp_lock);
				unlink(type?L2TP_ACL_URL_ROUTE_TBL_LOCK:L2TP_ACL_ROUTE_TBL_LOCK);
			}
			
			break;
	}
} 

unsigned int RG_Sync_Dynamic_ACL_Table( VPN_TYPE_T vpn_type )
{
	int acl_idx, napt_idx, route_idx, tmp_idx, i;
	unsigned int napt_last_pkt_cnt;
	rtk_rg_aclFilterAndQos_t aclRule;
	unsigned int acl_removed_num=0;
	char line[64], name[32];
	FILE *fp,*fp_tmp;

	
	if((fp = fopen((vpn_type==VPN_TYPE_PPTP) ? PPTP_ACL_URL_ROUTE_TBL : L2TP_ACL_URL_ROUTE_TBL, "r"))) {
	
		if(!(fp_tmp = fopen((vpn_type==VPN_TYPE_PPTP) ? PPTP_ACL_URL_ROUTE_TBL_TMP : L2TP_ACL_URL_ROUTE_TBL_TMP, "w"))) {
			fclose(fp);
			return 0;
		}

		while(fgets(line, 64, fp) != NULL)
		{
			sscanf(line, "%s %d %d %d %d\n",name, &acl_idx, &route_idx, &napt_idx, &napt_last_pkt_cnt);

			if(acl_idx != -1) {
				tmp_idx = acl_idx;
				memset(&aclRule, 0x0, sizeof(rtk_rg_aclFilterAndQos_t));
				if(!rtk_rg_aclFilterAndQos_find(&aclRule, &acl_idx) && (tmp_idx == acl_idx)) {
					// Double check what ACL rule I found is what I set.
					if(aclRule.fwding_type_and_direction == ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET
						&& aclRule.action_type == ACL_ACTION_TYPE_POLICY_ROUTE) {
						fprintf(fp_tmp, "%s %d %d %d %d\n", name, acl_idx, route_idx, napt_idx, napt_last_pkt_cnt);	
					} else {
						acl_removed_num++;
					}
				} else {					
					acl_removed_num++;
				}
			} else {				
				fprintf(fp_tmp, "%s %d %d %d %d\n", name, acl_idx, route_idx, napt_idx, napt_last_pkt_cnt);
			}
		}

		fclose(fp);
		fclose(fp_tmp);
		unlink((vpn_type==VPN_TYPE_PPTP) ? PPTP_ACL_URL_ROUTE_TBL : L2TP_ACL_URL_ROUTE_TBL);
		rename((vpn_type==VPN_TYPE_PPTP) ? PPTP_ACL_URL_ROUTE_TBL_TMP : L2TP_ACL_URL_ROUTE_TBL_TMP, (vpn_type==VPN_TYPE_PPTP) ? PPTP_ACL_URL_ROUTE_TBL : L2TP_ACL_URL_ROUTE_TBL);
	}
	
	return acl_removed_num;
}

#define TEMP_L2TP_VPN_CONN_STAT_TBL	"/var/wan_l2tp_vpn_connec_statistic"
#define TEMP_L2TP_VPN_CONN_STAT_TBL_TMP	"/var/wan_l2tp_vpn_connec_statistic_tmp"
#define TEMP_PPTP_VPN_CONN_STAT_TBL	"/var/wan_pptp_vpn_connec_statistic"
#define TEMP_PPTP_VPN_CONN_STAT_TBL_TMP	"/var/wan_pptp_vpn_connec_statistic_tmp"
void save_vpn_packet_count(VPN_TYPE_T vpn_type, unsigned int route_idx, unsigned long ip, unsigned int packet_count)
{
	FILE *statis_fp=NULL, *statis_fp_tmp;
	unsigned int saved_pkt_cnt, saved_route_idx;
	char saved_ip[32], ip_str[32];
	unsigned char bytes[4];
	char line[64];
	char exist=0;


	if(ip == 0x0)
		return;

	bytes[0] = ip & 0xFF;
	bytes[1] = (ip >> 8) & 0xFF;
	bytes[2] = (ip >> 16) & 0xFF;
	bytes[3] = (ip >> 24) & 0xFF;
	snprintf(ip_str, 32, "%d.%d.%d.%d", bytes[3], bytes[2], bytes[1], bytes[0]);

	
	if(!(statis_fp = fopen((vpn_type==VPN_TYPE_L2TP)?TEMP_L2TP_VPN_CONN_STAT_TBL:TEMP_PPTP_VPN_CONN_STAT_TBL, "r"))) {
		statis_fp = fopen((vpn_type==VPN_TYPE_L2TP)?TEMP_L2TP_VPN_CONN_STAT_TBL:TEMP_PPTP_VPN_CONN_STAT_TBL, "a");
	}
	
 	if(statis_fp != NULL) {
		if(!(statis_fp_tmp = fopen((vpn_type==VPN_TYPE_L2TP)?TEMP_L2TP_VPN_CONN_STAT_TBL_TMP:TEMP_PPTP_VPN_CONN_STAT_TBL_TMP, "w"))) {
			fclose(statis_fp);
			return;
		}

		while(fgets(line, 64, statis_fp) != NULL)
		{
			sscanf(line, "%d %s %d\n", &saved_route_idx, saved_ip, &saved_pkt_cnt);			 
			if(!strcmp(ip_str, saved_ip)) {
				fprintf(statis_fp_tmp, "%d %s %d\n", saved_route_idx, saved_ip, packet_count);
				exist = 1;
			} else {
				fprintf(statis_fp_tmp, "%d %s %d\n", saved_route_idx, saved_ip, saved_pkt_cnt);
			}
		}

		if(!exist) {
			fprintf(statis_fp_tmp, "%d %s %d\n", route_idx, ip_str, packet_count);
		}

		fclose(statis_fp);
		fclose(statis_fp_tmp);
		unlink((vpn_type==VPN_TYPE_L2TP)?TEMP_L2TP_VPN_CONN_STAT_TBL:TEMP_PPTP_VPN_CONN_STAT_TBL);
		rename((vpn_type==VPN_TYPE_L2TP)?TEMP_L2TP_VPN_CONN_STAT_TBL_TMP:TEMP_PPTP_VPN_CONN_STAT_TBL_TMP, (vpn_type==VPN_TYPE_L2TP)?TEMP_L2TP_VPN_CONN_STAT_TBL:TEMP_PPTP_VPN_CONN_STAT_TBL);
	}

	return;
}

unsigned int load_vpn_packet_count_by_ip(VPN_TYPE_T vpn_type, unsigned long ip)
{
	FILE *statis_fp;
	unsigned int saved_pkt_cnt, saved_route_idx;	
	char saved_ip[32], ip_str[32];
	unsigned char bytes[4];
	char line[64];
	char exist=0;

	
	if(ip==0x0)
		return 0;

	bytes[0] = ip & 0xFF;
	bytes[1] = (ip >> 8) & 0xFF;
	bytes[2] = (ip >> 16) & 0xFF;
	bytes[3] = (ip >> 24) & 0xFF;	
	snprintf(ip_str, 32, "%d.%d.%d.%d", bytes[3], bytes[2], bytes[1], bytes[0]);

	if(statis_fp = fopen((vpn_type==VPN_TYPE_L2TP)?TEMP_L2TP_VPN_CONN_STAT_TBL:TEMP_PPTP_VPN_CONN_STAT_TBL, "r")) {
		while(fgets(line, 64, statis_fp) != NULL)
		{
			sscanf(line, "%d %s %d\n", &saved_route_idx, saved_ip, &saved_pkt_cnt);
			if(!strcmp(ip_str, saved_ip)) {
				fclose(statis_fp);
				return saved_pkt_cnt;
			}
		}
		fclose(statis_fp);
	}
	
	return 0;
}

unsigned int load_vpn_packet_count_by_route_idx(VPN_TYPE_T vpn_type, unsigned int route_idx)
{
	FILE *statis_fp;
	unsigned int saved_pkt_cnt, saved_route_idx;
	unsigned int total_packet_count=0;
	char saved_ip[32];
	char line[64];
	char exist=0;


	if(statis_fp = fopen((vpn_type==VPN_TYPE_L2TP)?TEMP_L2TP_VPN_CONN_STAT_TBL:TEMP_PPTP_VPN_CONN_STAT_TBL, "r")) {
		while(fgets(line, 64, statis_fp) != NULL)
		{
			sscanf(line, "%d %s %d\n", &saved_route_idx, saved_ip, &saved_pkt_cnt);
			if(route_idx == saved_route_idx) {
				total_packet_count += saved_pkt_cnt;
			}
		}
		fclose(statis_fp);
	}
	
	return total_packet_count;
}


unsigned int RG_VPN_Classification_Rule_Recycle( VPN_TYPE_T vpn_type )
{
	int acl_idx, napt_idx, route_idx, tmp_idx, i;
	unsigned int napt_last_pkt_cnt;
	int search_acl_idx;
	rtk_rg_naptFilterAndQos_t naptRule;
	rtk_rg_aclFilterAndQos_t aclRule;
	unsigned int recycle_num=0, acl_removed_num=0;
	char line[64], name[32];
	FILE *fp,*fp_tmp;

	
	if((fp = fopen((vpn_type==VPN_TYPE_PPTP) ? PPTP_ACL_URL_ROUTE_TBL : L2TP_ACL_URL_ROUTE_TBL, "r"))) {
	
		if(!(fp_tmp = fopen((vpn_type==VPN_TYPE_PPTP) ? PPTP_ACL_URL_ROUTE_TBL_TMP : L2TP_ACL_URL_ROUTE_TBL_TMP, "w"))) {
			fclose(fp);
			return 0;
		}

		while(fgets(line, 64, fp) != NULL)
		{
			sscanf(line, "%s %d %d %d %d\n",name, &acl_idx, &route_idx, &napt_idx, &napt_last_pkt_cnt);

			if(napt_idx != -1) {							
				tmp_idx = napt_idx;
				memset(&naptRule, 0x0, sizeof(rtk_rg_naptFilterAndQos_t));
				if(!rtk_rg_naptFilterAndQos_find(&napt_idx, &naptRule)) {
					if(tmp_idx == napt_idx) {						
						if(!naptRule.packet_count || naptRule.packet_count==napt_last_pkt_cnt) {
							for(search_acl_idx=0 ; search_acl_idx < 128 ; search_acl_idx++) {				
								memset(&aclRule, 0x0, sizeof(rtk_rg_aclFilterAndQos_t));
								if(!rtk_rg_aclFilterAndQos_find(&aclRule, &search_acl_idx)) {
									if(aclRule.fwding_type_and_direction != ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET)
										continue;
									
									if(aclRule.action_type != ACL_ACTION_TYPE_POLICY_ROUTE)
										continue;

									if(aclRule.ingress_dest_ipv4_addr_start != naptRule.ingress_dest_ipv4_addr_range_start)
										continue;

									if(aclRule.ingress_dest_ipv4_addr_end != naptRule.ingress_dest_ipv4_addr_range_end)
										continue;										
									
									if(rtk_rg_aclFilterAndQos_del(search_acl_idx))
										DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", aclRule);
									
								}
							}

							if(naptRule.packet_count != 0) {
								save_vpn_packet_count(vpn_type, route_idx, naptRule.ingress_dest_ipv4_addr_range_start, naptRule.packet_count);
							}
							
							if(rtk_rg_naptFilterAndQos_del(napt_idx))
								DBPRINT(1, "rtk_rg_naptFilterAndQos_del failed! idx = %d\n", napt_idx);
							
							recycle_num++;
						} else {							
							fprintf(fp_tmp, "%s %d %d %d %d\n", name, acl_idx, route_idx, napt_idx, naptRule.packet_count);
						}
					} else {						
						fprintf(fp_tmp, "%s %d %d %d %d\n", name, acl_idx, route_idx, napt_idx, napt_last_pkt_cnt);
					}
				} else {	
					fprintf(fp_tmp, "%s %d %d %d %d\n", name, acl_idx, route_idx, napt_idx, napt_last_pkt_cnt);
				}
			} else {	
				fprintf(fp_tmp, "%s %d %d %d %d\n", name, acl_idx, route_idx, napt_idx, napt_last_pkt_cnt);
			}
		}
		
		fclose(fp);
		fclose(fp_tmp);		
		unlink((vpn_type==VPN_TYPE_PPTP) ? PPTP_ACL_URL_ROUTE_TBL : L2TP_ACL_URL_ROUTE_TBL);
		rename((vpn_type==VPN_TYPE_PPTP) ? PPTP_ACL_URL_ROUTE_TBL_TMP : L2TP_ACL_URL_ROUTE_TBL_TMP, (vpn_type==VPN_TYPE_PPTP) ? PPTP_ACL_URL_ROUTE_TBL : L2TP_ACL_URL_ROUTE_TBL);
	}

	acl_removed_num = RG_Sync_Dynamic_ACL_Table(vpn_type);
	if(acl_removed_num)		
		printf("%d %s ACL rules removed !\n", recycle_num, (vpn_type==VPN_TYPE_PPTP)?"PPTP":"L2TP");

	return recycle_num;
}

/*
return value:
1 --> already exist!
0 --> not exist, insert it!
*/
int Check_ACL_With_IP(VPN_TYPE_T vpn_type, struct in_addr addr, char *tunnelName)
{
	int acl_idx, tmp_idx, napt_idx, route_idx;
	unsigned int napt_last_pkt_cnt;
	char line[64];
	char name[32];
	rtk_rg_aclFilterAndQos_t aclRule;
	FILE *fp=NULL;

	if(vpn_type == VPN_TYPE_L2TP) {		
		if(!(fp = fopen(L2TP_ACL_URL_ROUTE_TBL, "r")))	{
			if(!(fp = fopen(L2TP_ACL_URL_ROUTE_TBL, "a")))	{
				fprintf(stderr, "ERROR! %s\n", strerror(errno));
				return 0;
			}
		}
	} else if(vpn_type == VPN_TYPE_PPTP) {		
		if(!(fp = fopen(PPTP_ACL_URL_ROUTE_TBL, "r")))	{
			if(!(fp = fopen(PPTP_ACL_URL_ROUTE_TBL, "a")))	{
				fprintf(stderr, "ERROR! %s\n", strerror(errno));
				return 0;
			}
		}
	} else {
		return 0;
	}

	while(fgets(line, 64, fp) != NULL)
	{
		sscanf(line, "%s %d %d %d %d\n",name, &acl_idx, &route_idx, &napt_idx, &napt_last_pkt_cnt);
//AUG_PRT("%s-%d name=%s, acl_idx=%d\n",__func__,__LINE__,name,acl_idx);

		if(!strcmp(tunnelName,name)){
			if(acl_idx != -1) {
				tmp_idx = acl_idx;
				memset(&aclRule, 0x0, sizeof(rtk_rg_aclFilterAndQos_t));
				if(rtk_rg_aclFilterAndQos_find(&aclRule, &acl_idx)) {
					DBPRINT(1, "rtk_rg_aclFilterAndQos_find failed! idx = %d\n", acl_idx);
				}

				/*check valid_idx*/
				if(tmp_idx == acl_idx)
				{
	//AUG_PRT("%s-%d acl ip=0x%x, addr.s_addr=0x%x\n",__func__,__LINE__,aclRule.ingress_dest_ipv4_addr_start,addr.s_addr);
					if(aclRule.ingress_dest_ipv4_addr_start == ntohl(addr.s_addr)){
						fclose(fp);
						return 1;
					}
				}
			}				
		}
	}

	fclose(fp);
	return 0;
}

/*
return value:
1 --> already exist!
0 --> not exist, insert it!
*/
int Check_NAPT_With_IP(VPN_TYPE_T vpn_type, struct in_addr addr, char *tunnelName)
{
	int acl_idx, tmp_idx, napt_idx, route_idx;
	unsigned int napt_last_pkt_cnt;
	char line[64];
	char name[32];
	rtk_rg_naptFilterAndQos_t naptRule;
	FILE *fp=NULL;
	

	if(vpn_type == VPN_TYPE_L2TP) {		
		if(!(fp = fopen(L2TP_ACL_URL_ROUTE_TBL, "r")))	{
			if(!(fp = fopen(L2TP_ACL_URL_ROUTE_TBL, "a")))	{
				fprintf(stderr, "ERROR! %s\n", strerror(errno));
				return 0;
			}
		}
	} else if(vpn_type == VPN_TYPE_PPTP){		
		if(!(fp = fopen(PPTP_ACL_URL_ROUTE_TBL, "r")))	{
			if(!(fp = fopen(PPTP_ACL_URL_ROUTE_TBL, "a")))	{
				fprintf(stderr, "ERROR! %s\n", strerror(errno));
				return 0;
			}
		}
	} else {
		return 0;
	}

	while(fgets(line, 64, fp) != NULL)
	{
		sscanf(line, "%s %d %d %d %d\n",name, &acl_idx, &route_idx, &napt_idx, &napt_last_pkt_cnt);
		//AUG_PRT("%s-%d name=%s, acl_idx=%d\n",__func__,__LINE__,name,acl_idx);

		if(!strcmp(tunnelName,name)){
			if(napt_idx != -1) {			
				tmp_idx = napt_idx;
				memset(&naptRule, 0x0, sizeof(rtk_rg_naptFilterAndQos_t));
				if(rtk_rg_naptFilterAndQos_find(&napt_idx, &naptRule)) {
					DBPRINT(1, "rtk_rg_naptFilterAndQos_find failed! idx = %d\n", napt_idx);
				}

				/*check valid_idx*/
				if(tmp_idx == napt_idx)
				{
					//AUG_PRT("%s-%d acl ip=0x%x, addr.s_addr=0x%x\n",__func__,__LINE__,aclRule.ingress_dest_ipv4_addr_start,addr.s_addr);
					if(naptRule.ingress_dest_ipv4_addr_range_start == ntohl(addr.s_addr)){
						fclose(fp);
						return 1;
					}
				}
			}				
		}
	}

	fclose(fp);
	return 0;
}

int is_vpn_tunnel_encypted(VPN_TYPE_T vpn_type, char *tunnel_name) {
	unsigned int vpn_entry_num=0;
	MIB_L2TP_T l2tp_entry;
	MIB_PPTP_T pptp_entry;
	int i;
	
	if(vpn_type == VPN_TYPE_L2TP) {
		vpn_entry_num = mib_chain_total(MIB_L2TP_TBL);
		for( i = 0; i < vpn_entry_num; i++ )
		{
			if(!mib_chain_get(MIB_L2TP_TBL, i, (void *)&l2tp_entry))
				continue;

			if(!strcmp(l2tp_entry.tunnelName, tunnel_name)) {
				if(l2tp_entry.enctype != VPN_ENCTYPE_NONE) {
					return 1;
				}
			}
		}		
	} else if(vpn_type == VPN_TYPE_PPTP){
		vpn_entry_num = mib_chain_total(MIB_PPTP_TBL);
		for( i = 0; i < vpn_entry_num; i++ )
		{
			if(!mib_chain_get(MIB_PPTP_TBL, i, (void *)&pptp_entry))
				continue;

			if(!strcmp(pptp_entry.tunnelName, tunnel_name)) {
				if(pptp_entry.enctype != VPN_ENCTYPE_NONE) {
					return 1;
				}
			}
		}
	}

	return 0;
}
#endif

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

//if the router recive dhcp discover with option60(SCITV | @ITV)  ,  
//we need to forward this packet to VOIP wan,and add an acl rule to forward that mac address to voip wan  
#ifdef _PRMT_X_CT_COM_LANBINDING_CONFIG_
int getOtherVid(void)
{
	int vcNum,i;
	MIB_CE_ATM_VC_T pvcEntry;	
	vcNum = mib_chain_total(MIB_ATM_VC_TBL); 
	for (i=0; i < vcNum; i++) {
		if (!mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&pvcEntry))
		{
			printf("Get chain record error!\n");
			return -1;
		}
		if((pvcEntry.applicationtype & X_CT_SRV_OTHER) != 0)
			return pvcEntry.vid;
	}
	return -1;
}

unsigned int getL2phyportFormMac(char *MacAddr)
{
	int macidx = -1;
	rtk_rg_macEntry_t macEntry;
	memset(&macEntry, 0, sizeof(rtk_rg_macEntry_t));	
	memcpy(macEntry.mac.octet, MacAddr, sizeof(macEntry.mac.octet));

	if(RT_ERR_RG_OK == rtk_rg_macEntry_find(&macEntry, &macidx))
	{
		printf("phyport %d\n",macEntry.port_idx);
		return macEntry.port_idx;
	}
	return -1;
}

static int string_to_hex(char *string, unsigned char *key, int len)
{
	char tmpBuf[4];
	int i, j = 0;

	for (i = 0; i < len; i += 2)
	{
		tmpBuf[0] = string[i];
		tmpBuf[1] = string[i+1];
		tmpBuf[2] = 0;

		if (!isxdigit(tmpBuf[0]) || !isxdigit(tmpBuf[1]))
			return 0;

		key[j++] = (unsigned char)strtol(tmpBuf, (char**)NULL, 16);
	}
	return 1;
}

static int mac17ToMac6(char *mac17,char *mac6)
{
	int i;

	for (i=0; i<17; i++){
		if ((i+1)%3 != 0)
			mac17[i-(i+1)/3] = mac17[i];
	}
	mac17[12] = '\0';
	if (strlen(mac17) != 12  || !string_to_hex(mac17, mac6, 12) || !isValidMacAddr(mac6)) {
		printf("strInvdMACAddr\n");
		return -1;
	}
	return 0;
}

void initLanBindingAclRule(rtk_rg_aclFilterAndQos_t*aclRule, int otherVid,char *mac6)
{
	aclRule->fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	aclRule->action_type = ACL_ACTION_TYPE_QOS;
	aclRule->filter_fields = INGRESS_PORT_BIT | INGRESS_SMAC_BIT;
	aclRule->qos_actions |= ACL_ACTION_ACL_INGRESS_VID_BIT;
	aclRule->ingress_port_mask.portmask = RG_get_all_lan_phyPortMask() | (1<<RTK_RG_PORT_CPU);
	aclRule->action_acl_ingress_vid = otherVid;
	
	memcpy(&aclRule->ingress_smac, mac6, MAC_ADDR_LEN);
	return;
}

int RG_add_lan_binding_vlan_member(unsigned int phyport)
{
	int otherVid;
	rtk_rg_cvlan_info_t cvlan_info;
	memset(&cvlan_info,0,sizeof(rtk_rg_cvlan_info_t));
	otherVid = getOtherVid();
	if( otherVid == -1){
		printf("ERROR! can't get other vid\n");
		return -1;
	}
	cvlan_info.vlanId = otherVid;
	if(rtk_rg_cvlan_get(&cvlan_info) == RT_ERR_RG_OK)
	{

#ifdef WLAN_SUPPORT
	if(phyport <= 4)
#endif
		cvlan_info.memberPortMask.portmask |= (1<< RG_get_lan_phyPortId(phyport));
#ifdef WLAN_SUPPORT
	else
		cvlan_info.memberPortMask.portmask |= (1<< RG_get_wlan_phyPortId(phyport));
#endif
	//	printf("cvlan_info.memberPortMask.portmask = 0x%x\n",cvlan_info.memberPortMask.portmask);

		if(rtk_rg_cvlan_add(&cvlan_info)!= RT_ERR_RG_OK)
			printf("RG_add_lan_binding_vlan_member failed\n");
	}
	return 0;
}

int RG_del_lan_binding_vlan_member(int otherVid,int phyport)
{
	rtk_rg_cvlan_info_t cvlan_info;
	memset(&cvlan_info,0,sizeof(rtk_rg_cvlan_info_t));
	
	cvlan_info.vlanId = otherVid;
	if(rtk_rg_cvlan_get(&cvlan_info) == RT_ERR_RG_OK)
	{
	
#ifdef WLAN_SUPPORT
		if(phyport <= 4)
#endif
			cvlan_info.memberPortMask.portmask &= ~(1<< RG_get_lan_phyPortId(phyport));
#ifdef WLAN_SUPPORT
		else
			cvlan_info.memberPortMask.portmask &= ~(1<< RG_get_wlan_phyPortId(phyport));
#endif
		//printf("cvlan_info.memberPortMask.portmask = 0x%x\n",cvlan_info.memberPortMask.portmask);

		if(rtk_rg_cvlan_add(&cvlan_info)!= RT_ERR_RG_OK)
			printf("RG_add_lan_binding_vlan_member failed\n");
	}
	return 0;
}

int RTK_RG_acl_Add_Lan_Binding(char *MacAddr)
{
	printf("RTK_RG_acl_Add_Lan_Binding\n");
	int aclIdx = 0, ret = 0;
	int otherVid;
	unsigned int phyport;
	FILE *fp = NULL;
	rtk_rg_aclFilterAndQos_t aclRule;
	
	otherVid = getOtherVid();
	if( otherVid == -1){
		printf("ERROR! can't get other bridge vlan id\n");
		return -1;
	}
	printf("otherVid %d\n",otherVid);

	if (!(fp = fopen(RG_ACL_LAN_BINDING_RULES_FILE, "a"))) {
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -2;
	}
	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	initLanBindingAclRule(&aclRule,otherVid,MacAddr);

	if ((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0) {
		
		if((phyport =getL2phyportFormMac(MacAddr)) == -1){
			printf("ERROR! can't get phyport \n");
			fclose(fp);
			return -1;
		}
		RG_add_lan_binding_vlan_member(phyport);

		fprintf(fp, "%02x:%02x:%02x:%02x:%02x:%02x#%d#%d#%d\n", 
			(unsigned char)MacAddr[0],(unsigned char)MacAddr[1],(unsigned char)MacAddr[2],
			(unsigned char)MacAddr[3],(unsigned char)MacAddr[4],(unsigned char)MacAddr[5],
			aclIdx,otherVid,phyport
			);
	}
	else {
		printf("RTK_RG_acl_Add_Lan_Binding failed! \n");
		fclose(fp);
		return -1;
	}

	fclose(fp);
	return 0;
}

int RTK_RG_del_Lan_Binding_Acl(void)
{
	FILE *fp = NULL;
	int aclIdx = -1;
	int phyport = -1;
	int old_otherVid = 0;
    char tmp[64];
	char *p;
	if(fp = fopen(RG_ACL_LAN_BINDING_RULES_FILE, "r"))
	{
		while(fgets(tmp, sizeof(tmp), fp) != NULL)
		{
			p = strstr(tmp,"#");
			sscanf(p, "#%d#%d#%d",&aclIdx,&old_otherVid,&phyport);
			if(rtk_rg_aclFilterAndQos_del(aclIdx))
				printf("rtk_rg_aclFilterAndQos_del failed! idx = %d\n", aclIdx);
			if(RG_del_lan_binding_vlan_member(old_otherVid,phyport))
				printf("RG_del_lan_binding_vlan_member failed! phyport = %d\n", phyport);
		}
		fclose(fp);
	}else{ 
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		printf("fail to open file %s\n",RG_ACL_LAN_BINDING_RULES_FILE);
	}
	return 0;
}

int add_lan_binding_acl(void)
{
	FILE *fp = NULL,*fp1;
	int aclIdx = -1;
	unsigned int phyport;
	char tmp[64],buff[64];
	char *p;
	char mac6[6];
	int ret = 0;
	int old_otherVid;
	rtk_rg_aclFilterAndQos_t aclRule;
	char rule[1024] = {0};// 

	int otherVid = getOtherVid();
	if( otherVid == -1){
		printf("ERROR! can't get other vid\n");
		return -1;
	}

	if(fp = fopen(RG_ACL_LAN_BINDING_RULES_FILE, "r"))
	{
		while(fgets(tmp, sizeof(tmp), fp) != NULL)
		{
			printf("tmp = %s\n",tmp);
			p = strstr(tmp,"#");
			sscanf(p, "#%d#%d#%d",&aclIdx,&old_otherVid,&phyport);
			*p = 0;
			sprintf(buff, "%s#%d#%d#%d\n",tmp,aclIdx,otherVid,phyport);
			if(mac17ToMac6(tmp,mac6) == -1){
				printf("ERROR! mac addr \n");
				continue;
			}
			
			memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
			initLanBindingAclRule(&aclRule,otherVid,mac6);
		
			if ((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0) {	
				RG_add_lan_binding_vlan_member(phyport);
				strcat(rule,buff);
			}
			else
				printf(" add_lan_binding_acl for  %s failed! ret= %d\n",tmp,ret );

		}
		fclose(fp);

	}else{ 
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		printf("fail to open file %s\n",RG_ACL_LAN_BINDING_RULES_FILE);
	}
	if(rule[0]!=0){
		if(fp1 = fopen(RG_ACL_LAN_BINDING_RULES_FILE, "w"))
		{
			fprintf(fp1, "%s", rule);
			fclose(fp1);
		}else{
			printf("open RG_ACL_LAN_BINDING_RULES_FILE failed!\n");
			fprintf(stderr, "ERROR! %s\n", strerror(errno));
		}
	}
	return 0;
}

#endif


#define R01_MAX_TRAP_PS_DOMAIN_NUM	2
char *r01_trap_ps_domain_list[R01_MAX_TRAP_PS_DOMAIN_NUM]= 
{
	"www.lvmama.com",
	"m.lvmama.com"
};
const char R01_TRAP_PS_NAPT_INDEX_TBL[] = "/var/r01_trap_to_ps_url_napt_idx";

int Is_R01_Trap_Ps_NAPT_Rule_Exist(struct in_addr addr)
{
	rtk_rg_naptFilterAndQos_t naptRule;
	char saved_ip[32], ip_str[32];
	unsigned int ip, napt_idx;
	unsigned char bytes[4];
	char domain_name[32];
	char line[64];
	FILE *fp=NULL;
	

	//bytes[0] = addr.s_addr & 0xFF;
	//bytes[1] = (addr.s_addr >> 8) & 0xFF;
	//bytes[2] = (addr.s_addr >> 16) & 0xFF;
	//bytes[3] = (addr.s_addr >> 24) & 0xFF;
	//snprintf(ip_str, 32, "%d.%d.%d.%d", bytes[3], bytes[2], bytes[1], bytes[0]);
	inet_ntop(AF_INET, (struct in_addr *)&addr, ip_str, INET_ADDRSTRLEN);
	
	if(!(fp = fopen(R01_TRAP_PS_NAPT_INDEX_TBL, "r")))	{
		if(!(fp = fopen(R01_TRAP_PS_NAPT_INDEX_TBL, "a")))	{
			fprintf(stderr, "ERROR! %s\n", strerror(errno));
			return 0;
		}
	}

	while(fgets(line, 64, fp) != NULL)
	{
		sscanf(line, "%s %s %d\n", domain_name, saved_ip, &napt_idx);
		if(strcmp(ip_str, saved_ip)) {
			continue;
		}

		memset(&naptRule, 0x0, sizeof(rtk_rg_naptFilterAndQos_t));
		if(rtk_rg_naptFilterAndQos_find(&napt_idx, &naptRule)) {
			DBPRINT(1, "rtk_rg_naptFilterAndQos_find failed! idx = %d\n", napt_idx);
			continue;
		}

		if(naptRule.ingress_dest_ipv4_addr_range_start != ntohl(addr.s_addr)) {
			continue;
		}

		fclose(fp);
		return 1;
	}

	fclose(fp);
	return 0;
}

int RG_Set_R01_URL_Trap_To_Ps(char *name, struct in_addr addr)
{
	rtk_rg_naptFilterAndQos_t naptRule;
	char saved_ip[32], ip_str[32];
	unsigned char bytes[4];
	int napt_idx, i;
	FILE *fp=NULL;

	
	//bytes[0] = addr.s_addr & 0xFF;
	//bytes[1] = (addr.s_addr >> 8) & 0xFF;
	//bytes[2] = (addr.s_addr >> 16) & 0xFF;
	//bytes[3] = (addr.s_addr >> 24) & 0xFF;
	//snprintf(ip_str, 32, "%d.%d.%d.%d", bytes[3], bytes[2], bytes[1], bytes[0]);
	inet_ntop(AF_INET, (struct in_addr *)&addr, ip_str, INET_ADDRSTRLEN);

	if(Is_R01_Trap_Ps_NAPT_Rule_Exist(addr)) {
		return 0;
	}

	for(i=0 ; i<R01_MAX_TRAP_PS_DOMAIN_NUM ; i++) {
		if(!strcmp(name, r01_trap_ps_domain_list[i])) {
			memset(&naptRule, 0, sizeof(rtk_rg_naptFilterAndQos_t));
			naptRule.filter_fields |= INGRESS_DIP_RANGE;
			naptRule.ingress_dest_ipv4_addr_range_start = ntohl(addr.s_addr);
			naptRule.ingress_dest_ipv4_addr_range_end = ntohl(addr.s_addr);
			naptRule.direction = RTK_RG_NAPT_FILTER_OUTBOUND;
			naptRule.action_fields = NAPT_SW_TRAP_TO_PS;

			if(!(fp = fopen(R01_TRAP_PS_NAPT_INDEX_TBL, "a")))	{
				fprintf(stderr, "ERROR! %s\n", strerror(errno));
				return -2;
			}	

			if(rtk_rg_naptFilterAndQos_add(&napt_idx, &naptRule)) {											
				DBPRINT(1, "rtk_rg_aclFilterAndQos_add failed! idx = %d\n", napt_idx);
				fclose(fp);
				return -1;
			} else {
				fprintf(fp, "%s %s %d\n", name, ip_str, napt_idx);
			}

			fclose(fp);
			break;
		}
	}
	
	return 0;
}

void dump_cvlan(rtk_rg_cvlan_info_t *cvlan_info)
{
	AUG_PRT("cvlan_info.vlanId=%d\n",cvlan_info->vlanId);
	AUG_PRT("cvlan_info.memberPortMask.portmask=%x\n",cvlan_info->memberPortMask.portmask);
	AUG_PRT("cvlan_info.memberPortMask.portmask=%x\n",cvlan_info->memberPortMask.portmask);
	AUG_PRT("cvlan_info.untagPortMask.portmask=%x\n",cvlan_info->untagPortMask.portmask);
#ifdef CONFIG_MASTER_WLAN0_ENABLE
	AUG_PRT("cvlan_info.wlan0DevMask=%x\n",cvlan_info->wlan0DevMask);
	AUG_PRT("cvlan_info.wlan0UntagMask=%x\n",cvlan_info->wlan0UntagMask);
#endif
	AUG_PRT("cvlan_info.vlan_based_pri_enable=%d\n",cvlan_info->vlan_based_pri_enable);
	AUG_PRT("cvlan_info.vlan_based_pri=%d\n",cvlan_info->vlan_based_pri);

}

#if defined(CONFIG_CMCC) || defined(CONFIG_YUEME) || defined(CONFIG_CU)
#if defined(CONFIG_RTL9607C_SERIES)
#define WLAN_DEV_BASED_CVLAN_START	4300
#else
#define WLAN_DEV_BASED_CVLAN_START	4070
#endif
int RG_Wlan_Portisolation_Set(unsigned char enable, int ssid_index)
{
	rtk_rg_cvlan_info_t cvlan_info, tmpcvlan_info;
	int vlanID = WLAN_DEV_BASED_CVLAN_START+ssid_index-1;
	unsigned int rg_wlan_idx;
	unsigned int rg_dev_idx;
	unsigned int rg_vlanId;
	unsigned int wlportmask = PMAP_WLAN0+ssid_index-1;
	int ret = 0;

	if(enable)
	{
		// Set CVLAN
		memset(&cvlan_info, 0, sizeof(rtk_rg_cvlan_info_t));
		memset(&tmpcvlan_info, 0, sizeof(rtk_rg_cvlan_info_t));
		cvlan_info.vlanId = vlanID;
		if(rtk_rg_cvlan_get(&cvlan_info) != RT_ERR_RG_OK)
		{
			cvlan_info.isIVL = 0;
#ifdef WLAN_DUALBAND_CONCURRENT
#ifdef CONFIG_RTL9607C_SERIES
			cvlan_info.memberPortMask.portmask = (1<<RTK_RG_PORT_MAINCPU)|(1<<RTK_RG_EXT_PORT0)|(1<<RTK_RG_EXT_PORT1)|(1<<RTK_RG_PORT_CPU)|(1<<RTK_RG_MAC10_EXT_PORT0)|(1<<RTK_RG_MAC10_EXT_PORT1)|(1<<RTK_RG_PORT_PON);
			cvlan_info.untagPortMask.portmask = (1<<RTK_RG_PORT_MAINCPU)|(1<<RTK_RG_PORT_CPU)|(1<<RTK_RG_PORT_PON);
#else
			cvlan_info.memberPortMask.portmask = (1<<RTK_RG_PORT_CPU)|(1<<RTK_RG_EXT_PORT0)|(1<<RTK_RG_EXT_PORT1)|(1<<RTK_RG_PORT_PON);
			cvlan_info.untagPortMask.portmask = (1<<RTK_RG_PORT_CPU)|(1<<RTK_RG_PORT_PON);	
#endif
			cvlan_info.wlan0DevMask |= (((wlportmask >> ITFGROUP_WLAN0_DEV_BIT) & ITFGROUP_WLAN_MASK) << RG_RET_MBSSID_MASTER_ROOT_INTF);
#ifdef WLAN_SUPPORT
			//add extensions port for broadcast wifi packet
			if((wlportmask & (ITFGROUP_WLAN_MASK << ITFGROUP_WLAN1_DEV_BIT)) > 0){
				//printf("\033[1;33;40m @@@@@@@@@@@@@@@@@########### extensions port 2 pvid %d\033[m\n", pvid);
				cvlan_info.memberPortMask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN1));
			}
#endif
			cvlan_info.wlan0DevMask |= (((wlportmask >> ITFGROUP_WLAN1_DEV_BIT) & ITFGROUP_WLAN_MASK) << RG_RET_MBSSID_SLAVE_ROOT_INTF);
#else
#ifdef CONFIG_RTL9607C_SERIES
			cvlan_info.memberPortMask.portmask = (1<<RTK_RG_PORT_MAINCPU)|(1<<RTK_RG_EXT_PORT0)|(1<<RTK_RG_PORT_CPU)|(1<<RTK_RG_MAC10_EXT_PORT0)|(1<<RTK_RG_PORT_PON);
			cvlan_info.untagPortMask.portmask = (1<<RTK_RG_PORT_MAINCPU)|(1<<RTK_RG_PORT_CPU)|(1<<RTK_RG_PORT_PON);
#else
			cvlan_info.memberPortMask.portmask = (1<<RTK_RG_PORT_CPU)|(1<<RTK_RG_EXT_PORT0)|(1<<RTK_RG_PORT_PON);
			cvlan_info.untagPortMask.portmask = (1<<RTK_RG_PORT_CPU)|(1<<RTK_RG_PORT_PON);
#endif
			cvlan_info.wlan0DevMask |= (((wlportmask >> ITFGROUP_WLAN0_DEV_BIT) & ITFGROUP_WLAN_MASK) << RG_RET_MBSSID_MASTER_ROOT_INTF);
#endif
			cvlan_info.wlan0UntagMask = cvlan_info.wlan0DevMask;
			cvlan_info.vlan_based_pri_enable = 0;
			cvlan_info.vlan_based_pri = 0;
			rtk_rg_cvlan_add(&cvlan_info);
		}
		/*else
		{
			AUG_PRT(" CVLAN CVID=%d has been exist !\n", vlanID);
		}*/

		// Set device-based CVLAN
		rg_wlan_idx = 0;

#ifdef WLAN_DUALBAND_CONCURRENT
		rg_dev_idx = (wlportmask > PMAP_WLAN0_VAP_END) ? ((wlportmask-PMAP_WLAN1)+RG_RET_MBSSID_SLAVE_ROOT_INTF) : ((wlportmask-PMAP_WLAN0)+RG_RET_MBSSID_MASTER_ROOT_INTF);
#else
		rg_dev_idx = wlportmask-PMAP_WLAN0;
#endif
		rg_vlanId = vlanID;
		tmpcvlan_info.vlanId = rg_vlanId;
		ret = rtk_rg_cvlan_get(&tmpcvlan_info);
		if(ret == RT_ERR_RG_OK){
			rtk_rg_wlanDevBasedCVlanId_set(rg_wlan_idx, rg_dev_idx, rg_vlanId);
		}
		else{
			AUG_PRT("%s:%d rg_vlanId %d is not created!\n", __FUNCTION__, __LINE__, rg_vlanId);
		}
	}
	else
	{
		// Set CVLAN
		memset(&cvlan_info, 0, sizeof(rtk_rg_cvlan_info_t));
		cvlan_info.vlanId = vlanID;
		if(rtk_rg_cvlan_get(&cvlan_info) == RT_ERR_RG_OK)
		{
			rtk_rg_cvlan_del(vlanID);
		}
		/*else
		{
			AUG_PRT(" CVLAN CVID=%d not exist !\n", vlanID);
		}*/
	}	
	return 0;
}
#endif

#ifdef CONFIG_CMCC_FORWARD_RULE_SUPPORT
int AddRTK_RG_ACL_CmccForwardRule(MIB_CMCC_FORWARD_RULE_T *entry, int type)
{
	rtk_rg_aclFilterAndQos_t aclRule;
	rtk_rg_intfInfo_t infinfo;
	int aclIdx, i;
	FILE *fp;
	struct in6_addr remoteAddress6_1;
	struct in6_addr remoteAddress6_2;
	struct in_addr remoteAddress1;
	struct in_addr remoteAddress2;
	int remoteporttype = -1, startPort, endPort;
	int iprangetype=0;
	char ipaddr1[64]={0}, ipaddr2[64] ={0};

	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	
	aclRule.acl_weight = RG_FIREWALL_ACL_WEIGHT;
	aclRule.action_type = ACL_ACTION_TYPE_TRAP_TO_PS;

	// remoteAddress support IPV4 and IPv6
	if(!strcmp(entry->remoteAddress, "") || !strcmp(entry->remoteAddress, "0")){
		//should not have this condition
	}
	else{
		iprangetype = getIpRange(entry->realremoteAddress, ipaddr1, ipaddr2);
		if(inet_pton(AF_INET, ipaddr1, &remoteAddress1) == 1 && 
			inet_pton(AF_INET, ipaddr2, &remoteAddress2))
		{
			aclRule.filter_fields |= INGRESS_IPV4_DIP_RANGE_BIT;
			aclRule.filter_fields |= INGRESS_IPV4_TAGIF_BIT;
			aclRule.ingress_ipv4_tagif = 1;

			aclRule.ingress_dest_ipv4_addr_start = ntohl(remoteAddress1.s_addr);
			aclRule.ingress_dest_ipv4_addr_end = ntohl(remoteAddress2.s_addr);
			//memcpy(&aclRule.ingress_dest_ipv4_addr_start, &remoteAddress1, IP_ADDR_LEN);
			//memcpy(&aclRule.ingress_dest_ipv4_addr_end, &remoteAddress2, IP_ADDR_LEN);
		}
		else if(inet_pton(AF_INET6, ipaddr1, &remoteAddress6_1) == 1 &&
			inet_pton(AF_INET6, ipaddr2, &remoteAddress6_2) == 1)
		{
			aclRule.filter_fields |= INGRESS_IPV6_DIP_RANGE_BIT;
			aclRule.filter_fields |= INGRESS_IPV6_TAGIF_BIT;
			aclRule.ingress_ipv6_tagif = 1;

			memcpy(aclRule.ingress_dest_ipv6_addr_start, &remoteAddress6_1, IPV6_ADDR_LEN);
			memcpy(aclRule.ingress_dest_ipv6_addr_end, &remoteAddress6_2, IPV6_ADDR_LEN);
		}
		else{
			printf("%s:%d\n", __FUNCTION__, __LINE__);
			return -1;
		}
	}
	
	// In CMCC spec, remotePort format could be x-y/!x/x , 0 means no limit
	// RG does not support !x  format(reverse), we will trap to PS let CPU handle
	// only x-y/x will fulfill this condition
	remoteporttype = parseRemotePort(entry->remotePort, &startPort, &endPort);
	if(remoteporttype == 0 || remoteporttype == 2)
	{
		aclRule.filter_fields |= INGRESS_L4_DPORT_RANGE_BIT;
		aclRule.ingress_dest_l4_port_start = startPort;
		aclRule.ingress_dest_l4_port_end = endPort;
		if(aclRule.ingress_dest_l4_port_start > aclRule.ingress_dest_l4_port_end){
			printf("%s:%d\n", __FUNCTION__, __LINE__);
			return -1;
		}
	}

	// Protocol
	if( entry->protocol != PROTO_NONE )
	{
		if( entry->protocol == PROTO_TCP )
			aclRule.filter_fields |= INGRESS_L4_TCP_BIT;
		else if( entry->protocol == PROTO_UDP )
			aclRule.filter_fields |= INGRESS_L4_UDP_BIT;
		else if( entry->protocol == PROTO_ICMP)
			aclRule.filter_fields |= INGRESS_L4_ICMP_BIT;
		else if( entry->protocol == PROTO_UDPTCP){
			aclRule.filter_fields |= INGRESS_L4_UDP_BIT; //add udp for udp/tcp protocol
		}
		else{
			printf("%s:%d\n", __FUNCTION__, __LINE__);
			return -1;
		}
	}

	//hostMAC
	if( !strcmp(entry->hostMAC, "") || !strcmp(entry->hostMAC, "0") ){
		//all mac
		//do nothing
	}
	else{
		convertMacFormat(entry->hostMAC, (unsigned char *)&aclRule.ingress_smac);
	}

	aclRule.filter_fields |= INGRESS_PORT_BIT;
	aclRule.ingress_port_mask.portmask = RG_get_all_lan_phyPortMask();
#ifdef WLAN_SUPPORT
	aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN0));
#ifdef WLAN_DUALBAND_CONCURRENT
	aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN1));
#endif
	aclRule.ingress_port_mask.portmask |= (1 << RTK_RG_PORT_CPU);
#endif
	aclRule.ingress_port_mask.portmask |= RG_get_wan_phyPortMask();

	if(!(fp = fopen(RG_ACL_CMCC_FORWARD_RULE_FILE, "a")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -2;
	}
	
	/* if dport use !x, parse it two rg_acls, sample: !80, parse it to 1~79 and 81~65535 */
    if(remoteporttype == 1) 
    {
		aclRule.ingress_dest_l4_port_start = 1;
        aclRule.ingress_dest_l4_port_end = startPort - 1;
        entry->aclIdx = rg_apply_acl(&aclRule, fp);
		printf("%s:%d start %d end %d\n", __FUNCTION__, __LINE__, aclRule.ingress_dest_l4_port_start, aclRule.ingress_dest_l4_port_end);

        aclRule.ingress_dest_l4_port_start = startPort + 1;
        aclRule.ingress_dest_l4_port_end = 65535;
        entry->aclIdx1 = rg_apply_acl(&aclRule, fp);
		printf("%s:%d start %d end %d\n", __FUNCTION__, __LINE__, aclRule.ingress_dest_l4_port_start, aclRule.ingress_dest_l4_port_end);
    }
	else{
		entry->aclIdx = rg_apply_acl(&aclRule, fp);
		entry->aclIdx1 = -1;
	}

	fclose(fp);
	return entry->aclIdx;
}

int delRTK_RG_ACL_CmccForwardRule(int index)
{
	FILE *fp, *fp1;
	int aclIdx;
	char cmd[512] = {0};

	if(!(fp = fopen(RG_ACL_CMCC_FORWARD_RULE_FILE, "r")))
		return -2;
	if(!(fp1 = fopen(RG_ACL_CMCC_FORWARD_RULE_TMP_FILE, "w")))
		return -2;

	if(rtk_rg_aclFilterAndQos_del(index))
		DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", index);
	
	while(fscanf(fp, "%d\n", &aclIdx) != EOF)
	{
		if(aclIdx != index){
			fprintf(fp1, "%d\n", aclIdx);
		}
	}

	fclose(fp);
	fclose(fp1);
	unlink(RG_ACL_CMCC_FORWARD_RULE_FILE);
	sprintf(cmd, "mv %s %s", RG_ACL_CMCC_FORWARD_RULE_TMP_FILE, RG_ACL_CMCC_FORWARD_RULE_FILE);
	system(cmd);
	
	return 0;
}

int FlushRTK_RG_CmccForwardRule()
{
	FILE *fp;
	int aclIdx;

	if(!(fp = fopen(RG_ACL_CMCC_FORWARD_RULE_FILE, "r")))
		return -2;

	while(fscanf(fp, "%d\n", &aclIdx) != EOF)
	{
		if(rtk_rg_aclFilterAndQos_del(aclIdx))
			DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", aclIdx);
	}

	fclose(fp);
	unlink(RG_ACL_CMCC_FORWARD_RULE_FILE);
	return 0;
}

int AddRTK_RG_ACL_CmccForwardRule_URL(char*domainName, char* addr)
{
	int EntryNum = 0;
	int i = 0;
	MIB_CMCC_FORWARD_RULE_T entry;
	int iptype = 0;;
	int ret = 0;
	

	EntryNum = mib_chain_total(MIB_CMCC_FORDWARD_RULE_TBL);
	for(i=0; i < EntryNum; i++){
		if(!mib_chain_get(MIB_CMCC_FORDWARD_RULE_TBL, i, &entry))
			continue;
		if(!strcmp(domainName, entry.remoteAddress)){
			iptype = checkIPv4OrIPv6(addr, entry.forwardToIP);
			if(!(iptype == 5 || iptype ==7)){//error situation we skip, ipv4+ipv6 or ipv6+ipv4
				printf("%s:%d: domainName %s, addr %s", __FUNCTION__, __LINE__, domainName, addr);
				DelCmccForwardRule(&entry);
				sprintf(entry.realremoteAddress, "%s", addr);
				ret = AddCmccForwardRule(&entry, CMCC_FORWARDRULE_ADD);
				if(ret >= 0){//if set success, update mib
					mib_chain_update(MIB_CMCC_FORDWARD_RULE_TBL, &entry, i);
				}
			}
		}
	}
	return ret;
}
#endif


#ifdef CONFIG_CMCC_TRAFFIC_PROCESS_RULE_SUPPORT
const char RG_ACL_CMCC_TRAFFIC_PROCESS_RULE_FILE[] = "/var/rg_acl_cmcc_traffic_process_rules_idx";
const char RG_ACL_CMCC_TRAFFIC_PROCESS_RULE_TMP_FILE[] = "/var/rg_acl_cmcc_traffic_process_rules_tmp_idx";
#define TRAFFIC_PROCESS_NETFILTER_HOOK_ADD	"/proc/osgi_traffic_process/traffice_process_rule"
enum {
    DIR_UP = 0,
    DIR_DOWN,
    DIR_UP_AND_DOWN
};

void _add_tf_rule_into_nfhook(MIB_CMCC_TRAFFIC_PROCESS_RULE_Tp rule)
{
    char cmd[512];
    int dir = 0;
    int ret = 0;
    if (strcmp(rule->direction, "UP") == 0) {
        dir = DIR_UP;
    } else if (strcmp(rule->direction, "DOWN") == 0) {
        dir = DIR_DOWN;
    } else {
        dir = DIR_UP_AND_DOWN;
    }

    sprintf(cmd,
            "/bin/echo  \"RemoteAddress:%s RemotePort:%s Direction:%d HostMAC:%s MethodList:%s statuscodeList:%s HeaderList:%s BundleName:%s Index:%d\" > %s",
            rule->realremoteAddress, rule->remotePort, dir, rule->hostMAC,
            rule->methodList, rule->statuscodeList, rule->headerList,
            rule->bundlename, rule->ruleIdx, TRAFFIC_PROCESS_NETFILTER_HOOK_ADD);

    ret = system(cmd);
    return;
}

void _del_tf_rule_from_nfhook(int index)
{
    char cmd[128];
    int ret = 0;
    sprintf(cmd, "/bin/echo  %d > %s", index,
            TRAFFIC_PROCESS_NETFILTER_HOOK_ADD);
	
    ret = system(cmd);
}

#define CMCC_TF_P_USE_ACLFILTER 0
int RTK_RG_ACL_Add_Cmcc_Traffic_Process_Rule(MIB_CMCC_TRAFFIC_PROCESS_RULE_T *entry)
{
#if CMCC_TF_P_USE_ACLFILTER
	rtk_rg_aclFilterAndQos_t aclRule0;
	rtk_rg_aclFilterAndQos_t aclRule1;
#else
	rtk_rg_naptFilterAndQos_t naptRule0;  /* WAN -> LAN */
	rtk_rg_naptFilterAndQos_t naptRule1;  /* LAN -> WAN */
#endif
	rtk_rg_intfInfo_t infinfo;
	int aclIdx, i;
	int aclIdx1;
	FILE *fp;
	struct in6_addr remoteAddress6;
	struct in_addr remoteAddress;
	int remoteporttype = -1, startPort, endPort;
#if CMCC_TF_P_USE_ACLFILTER
	memset(&aclRule0, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	memset(&aclRule1, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	
	aclRule0.acl_weight = 1000;
	aclRule0.action_type = ACL_ACTION_TYPE_TRAP_TO_PS;
	aclRule0.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;

	aclRule1.acl_weight = 1000;
	aclRule1.action_type = ACL_ACTION_TYPE_TRAP_TO_PS;
	aclRule1.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;	
#else
    /* Wan -> LAN */
    memset(&naptRule0, 0, sizeof(rtk_rg_naptFilterAndQos_t));
    naptRule0.direction = RTK_RG_NAPT_FILTER_INBOUND;
	naptRule0.action_fields = NAPT_SW_TRAP_TO_PS;	
    /* LAN -> WAN */
    memset(&naptRule1, 0, sizeof(rtk_rg_naptFilterAndQos_t));
    naptRule1.direction = RTK_RG_NAPT_FILTER_OUTBOUND;
    naptRule1.action_fields = NAPT_SW_TRAP_TO_PS;	
#endif
	// remoteAddress support IPV4 and IPv6
	if(!strcmp(entry->remoteAddress, "") || !strcmp(entry->remoteAddress, "0")){
		//TODO
	}
	else{		
		if(inet_pton(AF_INET, entry->realremoteAddress, &remoteAddress) == 1)
		{
#if  CMCC_TF_P_USE_ACLFILTER			
			aclRule0.filter_fields |= INGRESS_IPV4_SIP_RANGE_BIT;
			aclRule0.filter_fields |= INGRESS_IPV4_TAGIF_BIT;
			aclRule0.ingress_ipv4_tagif = 1;

			aclRule0.ingress_src_ipv4_addr_start = aclRule0.ingress_src_ipv4_addr_end = ntohl(remoteAddress.s_addr);

			//memcpy(&aclRule0.ingress_src_ipv4_addr_start, &remoteAddress, IP_ADDR_LEN);
			//memcpy(&aclRule0.ingress_src_ipv4_addr_end, &remoteAddress, IP_ADDR_LEN);
			//acl 1, LAN -> wan
			aclRule1.filter_fields |= INGRESS_IPV4_DIP_RANGE_BIT;
			aclRule1.filter_fields |= INGRESS_IPV4_TAGIF_BIT;
			aclRule1.ingress_ipv4_tagif = 1;

			aclRule1.ingress_dest_ipv4_addr_start = aclRule1.ingress_dest_ipv4_addr_end = ntohl(remoteAddress.s_addr);

			//memcpy(&aclRule1.ingress_dest_ipv4_addr_start, &remoteAddress, IP_ADDR_LEN);
			//memcpy(&aclRule1.ingress_dest_ipv4_addr_end, &remoteAddress, IP_ADDR_LEN);
#else
			/* WAN -> LAN */
			naptRule0.filter_fields |= INGRESS_SIP;
			naptRule0.ingress_src_ipv4_addr = ntohl(remoteAddress.s_addr);
			/* LAN -> WAN */
			naptRule1.filter_fields |= INGRESS_DIP;
			naptRule1.ingress_dest_ipv4_addr = ntohl(remoteAddress.s_addr);
#endif
		}
		else{
			printf("%s:%d\n", __FUNCTION__, __LINE__);
			return -1;
		}
	}
	
	// In CMCC spec, remotePort format could be x-y/!x/x , 0 means no limit
	// RG does not support !x  format(reverse), we will trap to PS let CPU handle
	// only x-y/x will fulfill this condition
	remoteporttype = parseRemotePort(entry->remotePort, &startPort, &endPort);
	if(remoteporttype == 0 || remoteporttype == 2)
	{
#if CMCC_TF_P_USE_ACLFILTER
		aclRule0.filter_fields |= INGRESS_L4_SPORT_RANGE_BIT;
		aclRule0.ingress_src_l4_port_start = startPort;
		aclRule0.ingress_src_l4_port_end = endPort;
		if(aclRule0.ingress_src_l4_port_start > aclRule0.ingress_src_l4_port_end){
			printf("%s:%d\n", __FUNCTION__, __LINE__);
			return -1;
		}
		
		aclRule1.filter_fields |= INGRESS_L4_DPORT_RANGE_BIT;
		aclRule1.ingress_dest_l4_port_start = startPort;
		aclRule1.ingress_dest_l4_port_end = endPort;
		if(aclRule1.ingress_dest_l4_port_start > aclRule1.ingress_dest_l4_port_end){
			printf("%s:%d\n", __FUNCTION__, __LINE__);
			return -1;
		}
#else
	 /* WAN -> LAN */
		naptRule0.filter_fields |= INGRESS_SPORT_RANGE;
		naptRule0.ingress_src_l4_port_range_start = startPort;
		naptRule0.ingress_src_l4_port_range_end   = endPort;
		
		if(naptRule0.ingress_src_l4_port_range_start > naptRule0.ingress_src_l4_port_range_end){
			printf("%s:%d\n", __FUNCTION__, __LINE__);
			return -1;
		}
	 /* LAN -> WAN */	
		naptRule1.filter_fields |= INGRESS_DPORT_RANGE;
		naptRule1.ingress_dest_l4_port_range_start = startPort;
		naptRule1.ingress_dest_l4_port_range_end   = endPort;
		if(naptRule1.ingress_dest_l4_port_range_start > naptRule1.ingress_dest_l4_port_range_end){
			printf("%s:%d\n", __FUNCTION__, __LINE__);
			return -1;
		}
#endif
		
	}

	// Protocol, HTTP only TCP
	//hostMAC
	if( !strcmp(entry->hostMAC, "") || !strcmp(entry->hostMAC, "0") ){
		//all mac
		//do nothing
	}
	else{
#if CMCC_TF_P_USE_ACLFILTER
		aclRule1.filter_fields |= INGRESS_SMAC_BIT;
		convertMacFormat(entry->hostMAC, (unsigned char *)&aclRule1.ingress_smac);
#else
		naptRule1.filter_fields |= INGRESS_SMAC;
		convertMacFormat(entry->hostMAC, (unsigned char *)&naptRule1.ingress_smac);
#endif
	}

#if CMCC_TF_P_USE_ACLFILTER
	aclRule0.filter_fields |= INGRESS_PORT_BIT;
	aclRule0.ingress_port_mask.portmask = RG_get_wan_phyPortMask();

	
	//acl1 from lan to wan
	aclRule1.filter_fields |= INGRESS_PORT_BIT;
	aclRule1.ingress_port_mask.portmask = RG_get_all_lan_phyPortMask();
#ifdef WLAN_SUPPORT
	aclRule1.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN0));
#ifdef WLAN_DUALBAND_CONCURRENT
	aclRule1.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN1));
#ifdef CONFIG_RTL9607C_SERIES
	//aclRule1.ingress_port_mask.portmask |=  (1<<RTK_RG_PORT_MAINCPU);
#endif
#endif
	aclRule1.ingress_port_mask.portmask |= (1 << RTK_RG_PORT_CPU);
#endif
#endif //CMCC_TF_P_USE_ACLFILTER
	
	if(!(fp = fopen(RG_ACL_CMCC_TRAFFIC_PROCESS_RULE_FILE, "a")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -2;
	}
#if CMCC_TF_P_USE_ACLFILTER
	if(rtk_rg_aclFilterAndQos_add(&aclRule0, &aclIdx) == 0){
#else
	if(rtk_rg_naptFilterAndQos_add( &aclIdx, &naptRule0) == 0){
#endif
		//fprintf(fp, "%d\n", aclIdx);
	}else{
		DBPRINT(1, "%s:%d failed!\n", __FUNCTION__, __LINE__);
		aclIdx = -1;
	}
#if CMCC_TF_P_USE_ACLFILTER
	if(rtk_rg_aclFilterAndQos_add(&aclRule1, &aclIdx1) == 0){
#else
	if(rtk_rg_naptFilterAndQos_add( &aclIdx1, &naptRule1) == 0){
#endif
		fprintf(fp, "%d\n", aclIdx);
		fprintf(fp, "%d\n", aclIdx1);
		entry->aclIdx_0 = aclIdx;
		entry->aclIdx_1 = aclIdx1;
		// printf("acl0=%d, acl1=%d\n", entry->aclIdx_0 , entry->aclIdx_1);
		
	}else{
		DBPRINT(1, "%s:%d failed!\n", __FUNCTION__, __LINE__);
#if CMCC_TF_P_USE_ACLFILTER
		 if(rtk_rg_aclFilterAndQos_del(aclIdx)){
#else
	     if(rtk_rg_naptFilterAndQos_del(aclIdx)){
#endif
		   DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", index);
	     }
		aclIdx = -1;
	}

	fclose(fp);
	return aclIdx;
}
int RTK_RG_ACL_Del_Cmcc_Traffic_Process_Rule(int index0, int index1){
  	FILE *fp, *fp1;
	int aclIdx;
	char cmd[512] = {0};

	if(!(fp = fopen(RG_ACL_CMCC_TRAFFIC_PROCESS_RULE_FILE, "r")))
		return -2;
	if(!(fp1 = fopen(RG_ACL_CMCC_TRAFFIC_PROCESS_RULE_TMP_FILE, "w")))
		return -2;

	if(index0>=0){
#if CMCC_TF_P_USE_ACLFILTER
		if(rtk_rg_aclFilterAndQos_del(index0))
#else
		if(rtk_rg_naptFilterAndQos_del(index0))
#endif
			DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", index0);
	}

	if(index1>=0){
#if CMCC_TF_P_USE_ACLFILTER
		if(rtk_rg_aclFilterAndQos_del(index1))
#else
		if(rtk_rg_naptFilterAndQos_del(index1))
#endif
			DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", index1);
	}

	
	while(fscanf(fp, "%d\n", &aclIdx) != EOF)
	{
		if((aclIdx != index0) || (aclIdx != index1)){
			fprintf(fp1, "%d\n", aclIdx);
		}
	}

	fclose(fp);
	fclose(fp1);
	unlink(RG_ACL_CMCC_TRAFFIC_PROCESS_RULE_FILE);
	sprintf(cmd, "mv %s %s", RG_ACL_CMCC_TRAFFIC_PROCESS_RULE_TMP_FILE, RG_ACL_CMCC_TRAFFIC_PROCESS_RULE_FILE);
	system(cmd);
	
	return 0;
}
int RTK_RG_Flush_Cmcc_Traffic_Process_Rule(void)
{
	FILE *fp;
	int aclIdx;
	int EntryNum = 0, i;
	MIB_CMCC_TRAFFIC_PROCESS_RULE_T entry;
	
	EntryNum = mib_chain_total(MIB_CMCC_TRAFFIC_PROCESS_RULE_TBL);

    for (i = 0; i < EntryNum; i++) {
        if(!mib_chain_get(MIB_CMCC_TRAFFIC_PROCESS_RULE_TBL, i, &entry))
			continue;
		if(entry.aclIdx_0>=0){
#if CMCC_TF_P_USE_ACLFILTER
			if(rtk_rg_aclFilterAndQos_del(entry.aclIdx_0))
#else
			if(rtk_rg_naptFilterAndQos_del(entry.aclIdx_0))
#endif
				DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", entry.aclIdx_0);
		}
		if(entry.aclIdx_1>=0){
#if CMCC_TF_P_USE_ACLFILTER
			if(rtk_rg_aclFilterAndQos_del(entry.aclIdx_1))
#else
			if(rtk_rg_naptFilterAndQos_del(entry.aclIdx_1))
#endif
				DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", entry.aclIdx_1);
		}
    }

	unlink(RG_ACL_CMCC_TRAFFIC_PROCESS_RULE_FILE);
	return 0;
}

int RTK_RG_ACL_Add_Cmcc_Traffic_Process_Rule_URL(char*domainName, char* addr)
{
	int EntryNum = 0;
	int i = 0;
	MIB_CMCC_TRAFFIC_PROCESS_RULE_T entry;
	int iptype = 0;
	int ret = 0;
	char cmd[512]={0};

	EntryNum = mib_chain_total(MIB_CMCC_TRAFFIC_PROCESS_RULE_TBL);
	for(i=0; i < EntryNum; i++){
		if(!mib_chain_get(MIB_CMCC_TRAFFIC_PROCESS_RULE_TBL, i, &entry))
			continue;
		if(!strcmp(domainName, entry.remoteAddress)){
			printf("%s:%d: domainName %s, addr %s", __FUNCTION__, __LINE__, domainName, addr);
			_del_tf_rule_from_nfhook(entry.ruleIdx);
			RTK_RG_ACL_Del_Cmcc_Traffic_Process_Rule(entry.aclIdx_0, entry.aclIdx_1);
			sprintf(entry.realremoteAddress, "%s", addr);
			_add_tf_rule_into_nfhook(&entry);
			RTK_RG_ACL_Add_Cmcc_Traffic_Process_Rule(&entry);
			mib_chain_update(MIB_CMCC_TRAFFIC_PROCESS_RULE_TBL, &entry, i);
		}
	}

	return ret;
}
#endif

int RG_set_CPU_port_egress_bandwidth_control(unsigned int rate)
{
	int ret, port;

#ifdef CONFIG_RTL9607C_SERIES
	port = RTK_RG_PORT_MAINCPU;
	if (rtk_rg_portEgrBandwidthCtrlRate_set(port, rate) != RT_ERR_RG_OK ) 
	{
		printf("[%s@%d] RG set CPU egress bandwidth failed! (port = %d, ret = %d)\n", __FUNCTION__, __LINE__, port, ret);
		return -1;
	}
#endif
	port = RTK_RG_PORT_CPU;
	if (rtk_rg_portEgrBandwidthCtrlRate_set(port, rate) != RT_ERR_RG_OK ) 
	{
		printf("[%s@%d] RG set CPU egress bandwidth failed! (port = %d, ret = %d)\n", __FUNCTION__, __LINE__, port, ret);
		return -1;
	}
	
	return 0;
}


#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
int RTK_RG_ACL_ADD_TRAFFIC_MONITOR(MIB_CMCC_TRAFFICMONITOR_RULE_Tp entry, int *naptIdx)
{
	int ret = 0;
	rtk_rg_naptFilterAndQos_t naptRule;
	struct in_addr ina_start;
	ipaddr_t mask;
	
	if (!strcmp(entry->real_monitor_ip, "") || entry->real_monitor_ip == NULL ){ //query url address , update later
		return 0;
	}

	memset(&naptRule, 0, sizeof(rtk_rg_naptFilterAndQos_t));
	naptRule.filter_fields |= INGRESS_DIP_RANGE;
	naptRule.direction = RTK_RG_NAPT_FILTER_OUTBOUND;
	naptRule.action_fields = NAPT_SW_TRAP_TO_PS;	

	inet_pton(AF_INET, entry->real_monitor_ip, &ina_start);
	if (entry->netmask == 0) {
		naptRule.ingress_dest_ipv4_addr_range_start = naptRule.ingress_dest_ipv4_addr_range_end = ntohl(ina_start.s_addr);
	}	
	else {
		mask = ~0 << (sizeof(ipaddr_t)*8 - entry->netmask);
		mask = htonl(mask);
		naptRule.ingress_dest_ipv4_addr_range_start = ntohl(ina_start.s_addr & mask);
		naptRule.ingress_dest_ipv4_addr_range_end = ntohl(ina_start.s_addr | ~mask);			
	}

	if ((ret = rtk_rg_naptFilterAndQos_add(naptIdx, &naptRule)) == 0) { 
	}
	else {
		printf("[%s@%d] RTK_RG_ACL_ADD_TRAFFIC_MONITOR add NAPT rule failed! (ret = %d)\n", __FUNCTION__, __LINE__, ret);
		return -1;
	}
	return 0;

}

int RTK_RG_ACL_DEL_TRAFFIC_MONITOR(int naptIdx)
{
	if(rtk_rg_naptFilterAndQos_del(naptIdx)) {
		DBPRINT(1, "rtk_rg_naptFilterAndQos_del failed! idx = %d\n", naptIdx);
		return -1;
	}
	return 0;
}

int RTK_RG_ACL_MOD_TRAFFIC_MONITOR(char *url,  struct in_addr addr)
{
	int i=0, naptIdx=-1;
	int EntryNum = 0, ret=0;
	unsigned char bytes[4];
	char ip_start[128];
	MIB_CMCC_TRAFFICMONITOR_RULE_T entry;
	rtk_rg_naptFilterAndQos_t naptRule;

	EntryNum = mib_chain_total(MIB_CMCC_TRAFFICMONITOR_RULE_TBL);
	for(i=0; i < EntryNum; i++){
		memset(&entry, 0, sizeof(MIB_CMCC_TRAFFICMONITOR_RULE_T));
		if(!mib_chain_get(MIB_CMCC_TRAFFICMONITOR_RULE_TBL, i, &entry))
			continue;
		if (!strcmp(url, entry.monitor_ip_url)) {
			if(rtk_rg_naptFilterAndQos_del(entry.naptIdx))
				DBPRINT(1, "rtk_rg_naptFilterAndQos_del failed! idx = %d\n", entry.naptIdx);

	//bytes[0] = addr.s_addr & 0xFF;
	//bytes[1] = (addr.s_addr >> 8) & 0xFF;
	//bytes[2] = (addr.s_addr >> 16) & 0xFF;
	//bytes[3] = (addr.s_addr >> 24) & 0xFF;
	//snprintf(ip_start, 32, "%d.%d.%d.%d", bytes[3], bytes[2], bytes[1], bytes[0]);
	inet_ntop(AF_INET, (struct in_addr *)&addr, ip_start, INET_ADDRSTRLEN);

			memset(&naptRule, 0, sizeof(rtk_rg_naptFilterAndQos_t));
			naptRule.filter_fields |= INGRESS_DIP_RANGE;
			naptRule.direction = RTK_RG_NAPT_FILTER_OUTBOUND;
			naptRule.action_fields = NAPT_SW_TRAP_TO_PS;	
			naptRule.ingress_dest_ipv4_addr_range_start = naptRule.ingress_dest_ipv4_addr_range_end = ntohl(addr.s_addr);
			
			if ((ret = rtk_rg_naptFilterAndQos_add(&naptIdx, &naptRule)) == 0) {
				memcpy(entry.real_monitor_ip, ip_start, sizeof(ip_start));
				entry.naptIdx = naptIdx;
				mib_chain_update(MIB_CMCC_TRAFFICMONITOR_RULE_TBL, &entry, i);				
				printf("[%s@%d] RTK_RG_ACL_MOD_TRAFFIC_MONITOR update domain=%s ip=%s\n", __FUNCTION__, __LINE__, url, ip_start);

			}
			else {
				printf("[%s@%d] RTK_RG_ACL_MOD_TRAFFIC_MONITOR add NAPT rule failed! (ret = %d)\n", __FUNCTION__, __LINE__, ret);
				return -1;
			}

			//Change the url address in kernel space
			char cmd[512];
			sprintf(cmd, "/bin/echo \"%d %s 32 %s\" > /proc/osgi/traffic_monitor_mod", entry.bundleID, ip_start, url );
			system(cmd);				
		}
	}
	return 0;

}




#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
#define RG_UNBIND_PORT_VLAN_ID 9

/*
*  Support 8.1.1
*  1. same binded ports can access each other
*  2. different binded ports(binded to different routing wan and vlan is different) cannot access each other
*  3. unbinded ports has no limit and can access unbinded and binded ports
*  limitation: RG_set_unbinded_port_vlan() must behide startWlan(), ssidisolation_portmap() or rg_addWanIf()
*/
static int RG_set_cvlan_member(int vlan, unsigned short unbinded_portMask)
{
	rtk_rg_cvlan_info_t cvlan_info;
	memset(&cvlan_info, 0x0, sizeof(rtk_rg_cvlan_info_t));
	cvlan_info.vlanId=vlan;
	rtk_rg_cvlan_get(&cvlan_info);
#ifdef CONFIG_RTL9602C_SERIES
	cvlan_info.memberPortMask.portmask |=RG_get_lan_phyPortMask(unbinded_portMask&0x3);
#else
	cvlan_info.memberPortMask.portmask |=RG_get_lan_phyPortMask(unbinded_portMask&0xf);
#endif
#ifdef WLAN_SUPPORT
	//add extensions port for broadcast wifi packet
	if((unbinded_portMask & (ITFGROUP_WLAN_MASK << ITFGROUP_WLAN0_DEV_BIT)) > 0){
		//printf("\033[1;33;40m @@@@@@@@@@@@@@@@@########### extensions port 1 pvid %d\033[m\n", pvid);
		cvlan_info.memberPortMask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN0));
	}
#endif
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
#endif
	cvlan_info.wlan0UntagMask |= cvlan_info.wlan0DevMask;
	rtk_rg_cvlan_add(&cvlan_info);

	return 0;
}



int filter_internetBr_vlanBinding_port(int vlan, unsigned int *currentPortMask)
{
	if(currentPortMask == NULL){
		return -1;
	}
	MIB_CE_PORT_BINDING_T pbEntry;
	int totalPortbd;
	int port;
	int lan_vlan;

	mib_get(MIB_LAN_VLAN_ID1, &lan_vlan);
	totalPortbd = mib_chain_total(MIB_PORT_BINDING_TBL);
	for (port = 0; port < totalPortbd; ++port)
	{
		mib_chain_get(MIB_PORT_BINDING_TBL, port, (void*)&pbEntry);
		if((unsigned char)VLAN_BASED_MODE == pbEntry.pb_mode)
		{
			struct v_pair *vid_pair;
			int k;
			MIB_CE_ATM_VC_T vc_Entry;
			vid_pair = (struct v_pair *)&pbEntry.pb_vlan0_a;
			for (k=0; k<4; k++)
			{
				if (vid_pair[k].vid_a && vid_pair[k].vid_b != vlan && find_wanif_by_vlanid(vid_pair[k].vid_b, &vc_Entry) > 0)
				{
					if(port <= PMAP_ETH0_SW3){
						*currentPortMask |= (1 << RG_get_lan_phyPortId(port));
						rtk_rg_portBasedCVlanId_set(RG_get_lan_phyPortId(port), lan_vlan);
					}
#ifdef WLAN_SUPPORT
					else if((port > PMAP_ETH0_SW3) && (port < PMAP_ITF_END)){
						*currentPortMask |= (1 << RG_get_wlan_phyPortId(port));
						rtk_rg_wlanDevBasedCVlanId_set(0,RG_get_wlan_phyPortId(port), lan_vlan);
					}
#endif
					//printf("\033[1;33;40m @@@@@@@@@@@@@@@@@########### port %d vid_pair[%d].vid_a=%d, vid_pair[%d].vid_b=%d, *currentPortMask %x\033[m\n", port, k, vid_pair[k].vid_a, k, vid_pair[k].vid_b, *currentPortMask);
				}
			}
		}
	}

	return 0;
}

int RG_set_unbinded_port_vlan(void)
{
#if 1
	int vcTotal, i, ret;
	MIB_CE_ATM_VC_T Entry;
	unsigned short itfGroup = 0;
	unsigned int phyID = 0, dev_idx = 0, pvid;
	int wlan_idx=0; /*only support master WLAN right now*/
	unsigned short unbinded_portMask = 0;
	unsigned short enable = 0, tmp = 0;
	rtk_rg_cvlan_info_t cvlan_info, firstBrcvlan_info, tmpcvlan_info;
	int isFoundFirstBr = 0;
	int isFoundFirstR = 0;
	unsigned int firstBrVid = RG_UNBIND_PORT_VLAN_ID;
	int fwdvlan_cpu, fwdvlan_proto_block, fwdvlan_bind_internet, lan_vlan;

#if (defined(CONFIG_CMCC) || defined(CONFIG_CU)) && defined(CONFIG_IPV6)
	char ipv6_vlan_enable;
	int v4ID=0, v6ID=0;

	mib_get(MIB_IPV6_VLAN_ENABLE,(void *)&ipv6_vlan_enable);
	/* when IPv6 VLAN is enabled, all lan/wlan port should be add the IPv6_VLAN member*/
	if (ipv6_vlan_enable)
	{
		mib_get(MIB_IPV4_VLAN_ID, (void *)&v4ID);
		mib_get(MIB_IPV6_VLAN_ID, (void *)&v6ID);
	}
#endif
#if defined(CONFIG_USER_LAN_PORT_AS_ETH_WAN)
	int ethPhyPortId = -1;
	mib_get(MIB_ETH_WAN_PORT_PHY_INDEX, &ethPhyPortId);
#endif

	ret = 1;
	RG_Flush_WIFI_UntagIn();
	
	vcTotal = mib_chain_total(MIB_ATM_VC_TBL);
	mib_get(MIB_FWD_CPU_VLAN_ID, &fwdvlan_cpu);
	mib_get(MIB_FWD_PROTO_BLOCK_VLAN_ID, &fwdvlan_proto_block);
	mib_get(MIB_FWD_BIND_INTERNET_VLAN_ID, &fwdvlan_bind_internet);
	mib_get(MIB_LAN_VLAN_ID1, &lan_vlan);
	firstBrVid = lan_vlan;
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
		if(Entry.cmode != CHANNEL_MODE_BRIDGE && (Entry.applicationtype&X_CT_SRV_INTERNET)) {
			isFoundFirstR = 1;
			firstBrVid = lan_vlan;
		}
		itfGroup |= Entry.itfGroup;		
	}

	//when internet routing exist, we disable internet bridge setting
	if(isFoundFirstR==1){
		//printf("\033[1;33;40m @@@@@@@@@@@@@@@@@########### isFoundFirstR=1\033[m\n");
		isFoundFirstBr=0;
	}
	
	//check firstBrVid exist or not
	if(isFoundFirstBr==1){
		cvlan_info.vlanId=firstBrVid;
		if(rtk_rg_cvlan_get(&cvlan_info)!=RT_ERR_RG_OK){
			return -1;
		}
	}
	
	//get unbinded port mask
#if defined(WLAN_DUALBAND_CONCURRENT)
	for(i=0; i <=PMAP_WLAN1_VAP_END; i++)
#else
	for(i=0; i <=PMAP_WLAN0_VAP_END; i++)
#endif
	{
#if defined(CONFIG_USER_LAN_PORT_AS_ETH_WAN)
		if (i <= PMAP_ETH0_SW3) {
			phyID = RG_get_lan_phyPortId(i);
			if (phyID == ethPhyPortId)
				continue;
		}
#endif
		tmp = (itfGroup >> i) & 1;

		if(tmp == 0){
			unbinded_portMask |= (1 << i);
		}
	}
	
	//printf("\033[1;33;40m @@@@@@@@@@@@@@@@@########### itfGroup %d unsigned short %d, unbinded_portMask 0x%x\033[m\n", itfGroup, sizeof(itfGroup), unbinded_portMask);

	//unbinded port join binded-port vlan
#if defined(WLAN_DUALBAND_CONCURRENT)
	for(i=0; i <=PMAP_WLAN1_VAP_END; i++)
#else
	for(i=0; i <=PMAP_WLAN0_VAP_END; i++)
#endif
	{
		tmp = (itfGroup >> i) & 1;
		if(tmp==1){
			if(i <= PMAP_ETH0_SW3){
				phyID = RG_get_lan_phyPortId(i);
#if defined(CONFIG_USER_LAN_PORT_AS_ETH_WAN)
				if (phyID == ethPhyPortId)
					continue;
#endif
				rtk_rg_portBasedCVlanId_get(phyID, &pvid);
			}
			else if (i >= PMAP_WLAN0){
				wlan_idx=0;
#ifdef WLAN_DUALBAND_CONCURRENT
				dev_idx = (i > PMAP_WLAN0_VAP_END) ? ((i-PMAP_WLAN1)+RG_RET_MBSSID_SLAVE_ROOT_INTF) : ((i-PMAP_WLAN0)+RG_RET_MBSSID_MASTER_ROOT_INTF);
#else
				dev_idx = i-PMAP_WLAN0;
#endif
				rtk_rg_wlanDevBasedCVlanId_get(wlan_idx,dev_idx, &pvid);
			}
			//cannot set default vlan setting
			if(pvid !=fwdvlan_cpu && pvid !=fwdvlan_proto_block && pvid !=fwdvlan_bind_internet){
#if (defined(CONFIG_CMCC) || defined(CONFIG_CU)) && defined(CONFIG_IPV6)
				if ((pvid != v4ID) && (pvid != v6ID))
#endif
					RG_set_cvlan_member(pvid, unbinded_portMask);
			}
		}
	}

	//set unbinded port pvid as vid 9 or firstBrVid
#if defined(WLAN_DUALBAND_CONCURRENT)
	for(i=0; i <=PMAP_WLAN1_VAP_END; i++)
#else
	for(i=0; i <=PMAP_WLAN0_VAP_END; i++)
#endif
	{
		enable = (unbinded_portMask >> i) & 1;
		if(enable == 1 && i <= PMAP_ETH0_SW3){ //lan
			phyID = RG_get_lan_phyPortId(i);
#if defined(CONFIG_USER_LAN_PORT_AS_ETH_WAN)
			if (phyID == ethPhyPortId)
				continue;
#endif
			//rtk_rg_wlanDevBasedCVlanId_get(0,0, &pvid);
			//printf("\033[1;33;40m @@@@@@@@@@@@@@@@@########### %s:%d pvid %d \033[m\n", __FUNCTION__, __LINE__, pvid);
			tmpcvlan_info.vlanId=firstBrVid;
			if(rtk_rg_cvlan_get(&tmpcvlan_info)==RT_ERR_RG_OK){
				rtk_rg_portBasedCVlanId_set(phyID, firstBrVid);
			}
			//rtk_rg_wlanDevBasedCVlanId_get(0,0, &pvid);
			//printf("\033[1;33;40m @@@@@@@@@@@@@@@@@########### %s:%d pvid %d \033[m\n", __FUNCTION__, __LINE__, pvid);
		}
		else if(enable == 1 && (i >= PMAP_WLAN0 )){//wlan 0
			wlan_idx=0;
#ifdef WLAN_DUALBAND_CONCURRENT
			dev_idx = (i > PMAP_WLAN0_VAP_END) ? ((i-PMAP_WLAN1)+RG_RET_MBSSID_SLAVE_ROOT_INTF) : ((i-PMAP_WLAN0)+RG_RET_MBSSID_MASTER_ROOT_INTF);
#else
			dev_idx = i-PMAP_WLAN0;
#endif
			rtk_rg_wlanDevBasedCVlanId_get(wlan_idx,dev_idx, &pvid);
			//printf("\033[1;33;40m @@@@@@@@@@@@@@@@@########### %s:%d pvid %d dev_idx %d i %d \033[m\n", __FUNCTION__, __LINE__, pvid, dev_idx, i);
			//prevent to overwrite Wlan Port isolation setting, if vlan id is 4005. the device is default, we can set
			tmpcvlan_info.vlanId=firstBrVid;
			ret = rtk_rg_cvlan_get(&tmpcvlan_info);
			if(pvid < WLAN_DEV_BASED_CVLAN_START && (ret == RT_ERR_RG_OK)){
				rtk_rg_wlanDevBasedCVlanId_set(wlan_idx,dev_idx, firstBrVid);
			}
			else{
				printf("%s:%d firstBrVid %d is not created!\n", __FUNCTION__, __LINE__, firstBrVid);
				return -1;
			}
		}
	}

	if(isFoundFirstBr == 1){
		memset(&cvlan_info, 0x0, sizeof(rtk_rg_cvlan_info_t));
		cvlan_info.vlanId=lan_vlan;
		rtk_rg_cvlan_get(&cvlan_info);
		//dump_cvlan(&cvlan_info);
		//first internet bridge needs to include vlan 9 setting
		memset(&firstBrcvlan_info, 0x0, sizeof(rtk_rg_cvlan_info_t));
		firstBrcvlan_info.vlanId = firstBrVid;
		rtk_rg_cvlan_get(&firstBrcvlan_info);
		//dump_cvlan(&firstBrcvlan_info);
		cvlan_info.vlanId=firstBrVid;
		cvlan_info.memberPortMask.portmask |= firstBrcvlan_info.memberPortMask.portmask;
		cvlan_info.wlan0DevMask |= firstBrcvlan_info.wlan0DevMask;
		cvlan_info.wlan0UntagMask = cvlan_info.wlan0DevMask;
		cvlan_info.untagPortMask = firstBrcvlan_info.untagPortMask;
		//setup vconfig to detag pvid, which would tag to CPU.
		for(i=0;i<=PMAP_ETH0_SW3;i++){
			enable = (unbinded_portMask >> i) & 1;
			if(enable == 1 && i <= PMAP_ETH0_SW3){ //lan
				setup_vconfig(firstBrVid,i);
			}
		}
		//dump_cvlan(&cvlan_info);
#if (defined(CONFIG_CMCC) || defined(CONFIG_CU)) && defined(CONFIG_IPV6)
		if ((lan_vlan != v4ID) && (lan_vlan != v6ID))
#endif
			rtk_rg_cvlan_add(&cvlan_info);

		//rtk_rg_cvlan_get(&cvlan_info);
		//printf("\033[1;33;40m @@@@@@@@@@@@@@@@@########### before cvlan_info.untagPortMask %x\033[m\n", cvlan_info.untagPortMask);
		//RG_set_WIFI_UntagIn(firstBrVid);
	}
#endif

	return 0;
}


#endif //CONFIG_CMCC

int RTK_RG_FLUSH_MIRROR_ACL_RULE(void)
{
	FILE *fp;
	int aclIdx=-1;
	if(!(fp = fopen(RG_MIRROR_ACL_RULES_FILE, "r"))){
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -2;
	}
	while(fscanf(fp, "%d\n", &aclIdx) != EOF)
	{
		//fprintf(stderr, "del mirror rule index %d\n",aclIdx);
		if(rtk_rg_aclFilterAndQos_del(aclIdx))
			fprintf(stderr, "%s failed! idx = %d\n",__func__, aclIdx);
	}
	fclose(fp);
	unlink(RG_MIRROR_ACL_RULES_FILE);
	return 0;
}

void initMirrorAclRule(rtk_rg_aclFilterAndQos_t * p_aclRule, MIB_CE_MIRROR_RULE_Tp p_entry)
{
	int iprangetype = 0;
	char ip_addr[20];
	ipaddr_t mask;
	struct in_addr remoteAddress_start;
	struct in_addr remoteAddress_end;
	char ipaddr_start[64]={0}, ipaddr_end[64] ={0};

	memset(p_aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	//remoteAddress
	if(strcmp(p_entry->remote_ip, "") == 0){
		//do nothing
	}
	else{
		iprangetype = getIpRange(p_entry->real_remote_ip, ipaddr_start, ipaddr_end);
		if( (inet_pton(AF_INET, ipaddr_start, &remoteAddress_start) == 1) &&
			(inet_pton(AF_INET, ipaddr_end, &remoteAddress_end ))) { //IPV4
			
			p_aclRule->filter_fields |= INGRESS_IPV4_TAGIF_BIT;
			p_aclRule->ingress_ipv4_tagif = 1;
			p_aclRule->filter_fields |= INGRESS_IPV4_DIP_RANGE_BIT;
			p_aclRule->ingress_dest_ipv4_addr_start = ntohl(remoteAddress_start.s_addr);
			p_aclRule->ingress_dest_ipv4_addr_end = ntohl(remoteAddress_end.s_addr);
			//memcpy(&p_aclRule->ingress_dest_ipv4_addr_start, &remoteAddress_start, IP_ADDR_LEN);
			//memcpy(&p_aclRule->ingress_dest_ipv4_addr_end, &remoteAddress_end, IP_ADDR_LEN);
		}
		else { //IPv6 
			printf("%s: not support IPv6 address yet \n", __FUNCTION__);
		}
	}
	
	//remotePort
	if(p_entry->remote_port_start != 0){
		p_aclRule->filter_fields |= INGRESS_L4_DPORT_RANGE_BIT;
		p_aclRule->ingress_dest_l4_port_start = p_entry->remote_port_start;			
		p_aclRule->ingress_dest_l4_port_end = p_entry->remote_port_end;				
	}

	//protocol
	if(p_entry->protocol == PROTO_TCP){
		p_aclRule->filter_fields |= INGRESS_L4_TCP_BIT;
	} else if(p_entry->protocol == PROTO_UDP){
		p_aclRule->filter_fields |= INGRESS_L4_UDP_BIT;
	}

	//hostMAC
	if(memcmp(p_entry->hostmac, EMPTY_MAC, MAC_ADDR_LEN)){
		p_aclRule->filter_fields |= INGRESS_DMAC_BIT;
		memcpy(&p_aclRule->ingress_dmac, p_entry->hostmac, MAC_ADDR_LEN);
	}
}

void RGSyncMirrorRule()
{
	rtk_rg_aclFilterAndQos_t aclRule={0};
	MIB_CE_MIRROR_RULE_T entry={0};
	int aclIdx=0, ret=0, i=0;
	int totalNUM=0;
	FILE *fp = NULL;
	unsigned char source_Addr[MAC_ADDR_LEN];

	//Flush all, and re-add according to MIRROR_RULE_TBL
	RTK_RG_FLUSH_MIRROR_ACL_RULE();

	totalNUM = mib_chain_total(MIB_MIRROR_RULE_TBL);
	if(totalNUM<=0){
		fprintf(stderr, "ERROR! Mirror Rule number =0\n");
		return;
	}
	
	if(!(fp = fopen(RG_MIRROR_ACL_RULES_FILE, "a")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return;
	}

	for(i=0;i<totalNUM;i++){
		memset(&entry, 0, sizeof(MIB_CE_MIRROR_RULE_T));
		if(!mib_chain_get(MIB_MIRROR_RULE_TBL, i, (void *)&entry)){
			printf("[%s %d]Get mib[%d] failed\n", __func__, __LINE__, i);
			fclose(fp);
			return;
		}
#if defined(CONFIG_RTL9600_SERIES)
		//If IC is 9607, need to add acl to trap packets to forwarding engine
		memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
		
		initMirrorAclRule(&aclRule,&entry);
		aclRule.fwding_type_and_direction =  ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
		aclRule.action_type = ACL_ACTION_TYPE_TRAP;

		if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0)
			fprintf(fp, "%d\n", aclIdx);
		else
			printf("rtk_rg_aclFilterAndQos_add for mirror function, trap acl rule failed !\n");
#endif

		//for mirror ACL Rule, need to wait RG function ready for integrating test	
		memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
		initMirrorAclRule(&aclRule,&entry);
		aclRule.fwding_type_and_direction =  ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
		aclRule.filter_fields |= INGRESS_PORT_BIT;
		aclRule.ingress_port_mask.portmask = RG_get_all_lan_phyPortMask();
		aclRule.ingress_port_mask.portmask |= RG_get_wan_phyPortMask();
#ifdef WLAN_SUPPORT
		aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN0));
#ifdef WLAN_DUALBAND_CONCURRENT
		aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN1));
#endif
#endif
#if defined(CONFIG_RTL9607C_SERIES)
		aclRule.ingress_port_mask.portmask |= (1 << RTK_RG_PORT_MAINCPU) |(1<<RTK_RG_PORT_CPU);
#endif

		aclRule.action_type = ACL_ACTION_TYPE_SW_MIRROR_WITH_UDP_ENCAP;

		//mirrorToIP
		if(memcmp(&entry.mirror_to_ip, "\x00\x00\x00\x00", IP_ADDR_LEN) != 0){
			aclRule.action_encap_udp.encap_Dip = *((ipaddr_t *)entry.mirror_to_ip);
		}

		//mirrorToPort
		aclRule.action_encap_udp.encap_Dport= entry.mirror_to_port;

		//mirror To DMAC for lan host
		if(memcmp(&entry.assign_dmac, EMPTY_MAC, MAC_ADDR_LEN)){
			memcpy(&(aclRule.action_encap_udp.encap_dmac), &(entry.assign_dmac), MAC_ADDR_LEN);
		}

		//mirror To SMAC for lan host, given an random MAC for napt forwarding
		getMacAddr("br0", source_Addr);
		source_Addr[5]+=1;
		memcpy(&(aclRule.action_encap_udp.encap_smac), source_Addr, MAC_ADDR_LEN);

		//Mirror to Assign SIP
		if(memcmp(&entry.assign_sip, "\x00\x00\x00\x00", IP_ADDR_LEN) != 0){
			aclRule.action_encap_udp.encap_Sip = *((ipaddr_t *)entry.assign_sip);
		}

		if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0)
			fprintf(fp, "%d\n", aclIdx);
		else
			printf("rtk_rg_aclFilterAndQos_add for mirror acl rule failed !\n");		
	}

	fclose(fp);
}

int AddRTK_RG_ACL_CmccMirrorRule_URL(char*domainName, char* addr)
{
	int EntryNum = 0;
	int i = 0;
	MIB_CE_MIRROR_RULE_T entry;
	int isFound = 0, iptype = 0;;
	int ret = 0;
	

	EntryNum = mib_chain_total(MIB_MIRROR_RULE_TBL);
	for(i=0; i < EntryNum; i++){
		if(!mib_chain_get(MIB_MIRROR_RULE_TBL, i, &entry))
			continue;
		if(!strcmp(domainName, entry.remote_ip)){
			iptype = checkIPv4OrIPv6(addr, entry.mirror_to_ip);
			if((iptype ==3 || iptype ==4)){//only support ipv4
				isFound = 1;
			}
			break;
		}
	}

	if(isFound==1){
		printf("%s:%d: domainName %s, addr %s", __FUNCTION__, __LINE__, domainName, addr);
		sprintf(entry.real_remote_ip, "%s", addr);
		mib_chain_update(MIB_MIRROR_RULE_TBL, &entry, i);
		RGSyncMirrorRule();
	}
	return ret;
}


int RTK_RG_BridgeType_ACL_Rule_Set(MIB_CE_ATM_VC_Tp pentry)
{
	FILE *fp;
	rtk_rg_aclFilterAndQos_t aclRule;
	int aclIdx, ret;
	char buff[64];

	if( (pentry->cmode != CHANNEL_MODE_BRIDGE ) ||(pentry->itfGroup == 0))
		return -1;
	sprintf(buff, "%s_%d", RG_BRIDGETYPE_RULES_FILE, pentry->rg_wan_idx);

	if(!(fp = fopen(buff, "w")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -2;
	}
	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));

	aclRule.fwding_type_and_direction =  ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	aclRule.action_type = ACL_ACTION_TYPE_DROP;
	aclRule.acl_weight = RG_DEFAULT_ACL_WEIGHT;
	aclRule.filter_fields |= INGRESS_PORT_BIT;
#ifdef CONFIG_RTL9602C_SERIES
	aclRule.ingress_port_mask.portmask = RG_get_lan_phyPortMask((pentry->itfGroup)&0x3);
#else
	aclRule.ingress_port_mask.portmask = RG_get_lan_phyPortMask((pentry->itfGroup)&0xf);
#endif
#ifdef WLAN_SUPPORT
	if(pentry->itfGroup>>4)//bind wlan
	{
		aclRule.filter_fields |= INGRESS_WLANDEV_BIT;
		aclRule.ingress_wlanDevMask = (((pentry->itfGroup>>ITFGROUP_WLAN0_DEV_BIT)&ITFGROUP_WLAN_MASK) << RG_RET_MBSSID_MASTER_ROOT_INTF) | (((pentry->itfGroup>>ITFGROUP_WLAN1_DEV_BIT)&ITFGROUP_WLAN_MASK)<<RG_RET_MBSSID_SLAVE_ROOT_INTF) ;
	}
#endif
	if(pentry->brmode == 1) //PPPoE_BRIDGE drop DHCP packets
	{
		aclRule.filter_fields |= INGRESS_L4_DPORT_RANGE_BIT | INGRESS_L4_SPORT_RANGE_BIT;
		aclRule.ingress_src_l4_port_start = aclRule.ingress_src_l4_port_end = 68;
		aclRule.ingress_dest_l4_port_start = aclRule.ingress_dest_l4_port_end = 67;
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)		
		if (pentry->disableLanDhcp == 0) // allow the user to access the DHCP server in ONU
			aclRule.action_type = ACL_ACTION_TYPE_PERMIT;
#endif		
	} 
	else { //IP Bridge drop PPPoE Packets
		aclRule.filter_fields |= INGRESS_ETHERTYPE_BIT;
		aclRule.ingress_ethertype =  0x8864;
		aclRule.ingress_ethertype_mask = 0xFFF0;
	}

	if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0)
		fprintf(fp, "%d\n", aclIdx);
	else
		printf("rtk_rg_aclFilterAndQos_add bridgeType rule failed! (ret = %d)\n", ret);

	fclose(fp);
	return 0;
}


int RTK_RG_BridgeType_ACL_Rule_Flush(int rg_wan_idx)
{
	FILE *fp;
	int acl_idx;
	char buff[64];

	sprintf(buff, "%s_%d", RG_BRIDGETYPE_RULES_FILE, rg_wan_idx);
	if(!(fp = fopen(buff, "r")))
		return -2;
	while(fscanf(fp, "%d\n", &acl_idx) != EOF)
	{
		if(rtk_rg_aclFilterAndQos_del(acl_idx))
			DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", acl_idx);
	}

	fclose(fp);
	unlink(buff);
	return 0;
}


#endif //CONFIG_CMCC
#define RG_WIFI_UNTAG_VID 2020

int RG_set_WIFI_UntagIn(int vid)
{
	rtk_rg_cvlan_info_t cvlan_info;
	rtk_rg_aclFilterAndQos_t aclRule;
	FILE *fp;
	int aclIdx, ret;
	int untagWifiVid = RG_WIFI_UNTAG_VID;

	mib_get(MIB_PORT_UNBIND_WIFI_UNTAG_VID, &untagWifiVid);
	//add vlan 2020 to make wifi to CPU untag
	memset(&cvlan_info, 0x0, sizeof(rtk_rg_cvlan_info_t));
	cvlan_info.vlanId=vid;
	rtk_rg_cvlan_get(&cvlan_info);
	cvlan_info.vlanId = untagWifiVid;

#ifdef CONFIG_RTL9607C_SERIES
	cvlan_info.memberPortMask.portmask |= (1<<RTK_RG_PORT_MAINCPU)|(1<<RTK_RG_PORT_CPU);
#else
	cvlan_info.memberPortMask.portmask |= (1<<RTK_RG_PORT_CPU);
#endif
	cvlan_info.untagPortMask.portmask = RTK_RG_ALL_PORTMASK;
	cvlan_info.untagPortMask.portmask &= ~RTK_RG_ALL_EXT_PORTMASK;
	rtk_rg_cvlan_add(&cvlan_info);
	//add acl to redirct tag wifi packet to vlan 2020
	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	aclRule.action_type = ACL_ACTION_TYPE_QOS;
	aclRule.qos_actions |= ACL_ACTION_ACL_INGRESS_VID_BIT;
	aclRule.action_acl_ingress_vid = untagWifiVid;
	aclRule.filter_fields |= INGRESS_PORT_BIT;
#ifdef WLAN_SUPPORT
	aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN0));
#if defined(WLAN_DUALBAND_CONCURRENT)
	aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN1));
#endif
#endif
	if(!(fp = fopen(RG_WIFI_UNTAG_RULES_FILE, "a")))
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

int RG_Flush_WIFI_UntagIn()
{
	FILE *fp;
	int aclIdx;
	int ret = 0;

	if(!(fp = fopen(RG_WIFI_UNTAG_RULES_FILE, "r")))
		return -2;

	while(fscanf(fp, "%d\n", &aclIdx) != EOF)
	{
		if(rtk_rg_aclFilterAndQos_del(aclIdx))
			DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", aclIdx);
	}

	fclose(fp);
	unlink(RG_WIFI_UNTAG_RULES_FILE);
}


#ifdef SUPPORT_DHCPV6_RELAY
const char RG_dhcpv6_relay_acl_rules[] = "/tmp/rg_dhcpv6_relay_acl_rules";
int RG_trap_dhcpv6_for_relay(int enable)
{
	int acl_idx = -1;
	FILE *fp = NULL;
	rtk_rg_aclFilterAndQos_t acl;

	if(!enable)
	{
		if (!(fp = fopen(RG_dhcpv6_relay_acl_rules, "r")))
		{
			fprintf(stderr, "ERROR! %s\n", strerror(errno));
			return -1;
		}

		while (fscanf(fp, "%d\n", &acl_idx) != EOF)
		{
			if (rtk_rg_aclFilterAndQos_del(acl_idx))
				fprintf(stderr, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", acl_idx);
		}
		fclose(fp);
		unlink(RG_dhcpv6_relay_acl_rules);
	}
	else
	{
		if (!(fp = fopen(RG_dhcpv6_relay_acl_rules, "w")))
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
		acl.ingress_src_l4_port_start = acl.ingress_src_l4_port_end = 546;
		acl.ingress_dest_l4_port_start = acl.ingress_dest_l4_port_end = 547;
		acl.filter_fields |= INGRESS_PORT_BIT;
		acl.ingress_port_mask.portmask = RG_get_all_lan_phyPortMask();
		acl.filter_fields |= INGRESS_IPV6_TAGIF_BIT;
		acl.ingress_ipv6_tagif= 1;
		acl.filter_fields |= INGRESS_L4_UDP_BIT;
		
		if(rtk_rg_aclFilterAndQos_add(&acl, &acl_idx) == 0)
			fprintf(fp, "%d\n", acl_idx);
		else
			fprintf(stderr, "<%s:%d> rtk_rg_aclFilterAndQos_add failed!\n", __func__, __LINE__);
		fclose(fp);		
	}

	return 0;
}
#endif

#ifdef _PRMT_X_CMCC_WLANSHARE_
const char RG__wlan_share_acl_rules[] = "/tmp/rg_wlan_share_acl_rules";
int RG_trap_dhcp_for_wlan_share(int enable, unsigned int ssid_idx)
{
	int acl_idx = -1;
	FILE *fp = NULL;
	rtk_rg_aclFilterAndQos_t acl;

	if(!enable)
	{
		if (!(fp = fopen(RG__wlan_share_acl_rules, "r")))
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
		unlink(RG__wlan_share_acl_rules);
	}
	else
	{
		if (!(fp = fopen(RG__wlan_share_acl_rules, "w")))
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
		acl.ingress_src_l4_port_start = acl.ingress_src_l4_port_end = 68;
		acl.ingress_dest_l4_port_start = acl.ingress_dest_l4_port_end = 67;
		acl.filter_fields |= INGRESS_WLANDEV_BIT;
		if(ssid_idx >= 1 && ssid_idx <= 4)
			acl.ingress_wlanDevMask = 1 << (ssid_idx-1);
		else if (ssid_idx >= 5 && ssid_idx <= 8)
			acl.ingress_wlanDevMask = 1 << (ssid_idx-5 + 13);
		else
		{
			fprintf(stderr, "<%s:%d> Invalid ssid_idx: %d\n", __func__, __LINE__, ssid_idx);
			return -1;
		}

		if(rtk_rg_aclFilterAndQos_add(&acl, &acl_idx) == 0)
			fprintf(fp, "%d\n", acl_idx);
		else
			fprintf(stderr, "<%s:%d> rtk_rg_aclFilterAndQos_add failed!\n", __func__, __LINE__);
		fclose(fp);		
	}

	return 0;
}
#endif
#define RG_HOST_POLICE_CONTROL_DEBUG_ENABLE		0
#define MIN_HPC_HOSTIDX	0
#define MAX_HPC_HOSTIDX	31
#define LAN_BANDWIDTH_CONTROL_DS_HOSTIDX_START	MIN_HPC_HOSTIDX
#define LAN_BANDWIDTH_CONTROL_DS_HOSTIDX_END	(LAN_BANDWIDTH_CONTROL_DS_HOSTIDX_START+LAN_BANDWIDTH_CONTROL_DS_SM_ID_END-LAN_BANDWIDTH_CONTROL_DS_SM_ID_START)
#define LAN_BANDWIDTH_CONTROL_US_HOSTIDX_START	(LAN_BANDWIDTH_CONTROL_DS_HOSTIDX_END+1)
#define LAN_BANDWIDTH_CONTROL_US_HOSTIDX_END	(LAN_BANDWIDTH_CONTROL_US_HOSTIDX_START+LAN_BANDWIDTH_CONTROL_US_SM_ID_END-LAN_BANDWIDTH_CONTROL_US_SM_ID_START)
#define LAN_HPC_MIB_COUNTER_HOSTIDX_START		MIN_HPC_HOSTIDX
#define LAN_HPC_MIB_COUNTER_HOSTIDX_END			MAX_HPC_HOSTIDX
#define LanHostPoliceCtrlSetupLock	"/var/lanHostPoliceCtrlSetupLock"
#define LOCK_HOST_POLICE_CONTROL(f)	\
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

#define UNLOCK_HOST_POLICE_CONTROL()	\
do {	\
	flock(lockfd, LOCK_UN);	\
	close(lockfd);	\
} while (0)

#if defined(CONFIG_USER_LAN_BANDWIDTH_CONTROL) && (defined(CONFIG_RTL9607C_SERIES) || defined(CONFIG_LUNA_G3_SERIES))
const char LAN_DS_BABDWIDTH_CTRL_DEBUG_FILE[] = "/var/debugLanHostPoliceCtrlDownstreamBandwidthControl";
const char LAN_US_BABDWIDTH_CTRL_DEBUG_FILE[] = "/var/debugLanHostPoliceCtrlUpstreamBandwidthControl";
void RG_update_lan_bandwidth_control_debug_info(int dir)
{
	int hostIndex, hostIndexStart, hostIndexEnd;
	rtk_rg_hostPoliceControl_t nullHostPoliceControl = {0};
	rtk_rg_hostPoliceControl_t hostPoliceControl;
	int shareMeterRate;
	rtk_rg_enable_t shareMeterEnabled;	
	FILE *fp = NULL;
	
	if(dir == 0) // downstream
	{
		hostIndexStart = LAN_BANDWIDTH_CONTROL_DS_HOSTIDX_START;
		hostIndexEnd = LAN_BANDWIDTH_CONTROL_DS_HOSTIDX_END;
		if (!(fp = fopen(LAN_DS_BABDWIDTH_CTRL_DEBUG_FILE, "w")))
		{
			fprintf(stderr, "ERROR! %s\n", strerror(errno));
			return;
		}
		fprintf(fp, "HostPoliceControlDownStreamSpeedLimit debug info:\n");
	}
	else // upstream
	{
		hostIndexStart = LAN_BANDWIDTH_CONTROL_US_HOSTIDX_START;
		hostIndexEnd = LAN_BANDWIDTH_CONTROL_US_HOSTIDX_END;
		if (!(fp = fopen(LAN_US_BABDWIDTH_CTRL_DEBUG_FILE, "w")))
		{
			fprintf(stderr, "ERROR! %s\n", strerror(errno));
			return;
		}
		fprintf(fp, "HostPoliceControlUpStreamSpeedLimit debug info:\n");
	}

	fprintf(fp, "===========================================================================================================\n");
	fprintf(fp, "Maxmum bandwidth control shareMeterID num = %d\n", MAX_BANDWIDTH_CONTROL_SM_ID_NUM);
	fprintf(fp, "Range of downstream shareMeterID = %d ~ %d\n", LAN_BANDWIDTH_CONTROL_DS_SM_ID_START, LAN_BANDWIDTH_CONTROL_DS_SM_ID_END);
	fprintf(fp, "Range of upstream shareMeterID = %d ~ %d\n", LAN_BANDWIDTH_CONTROL_US_SM_ID_START, LAN_BANDWIDTH_CONTROL_US_SM_ID_END);
	fprintf(fp, "Range of downstream hostIndex = %d ~ %d\n", LAN_BANDWIDTH_CONTROL_DS_HOSTIDX_START, LAN_BANDWIDTH_CONTROL_DS_HOSTIDX_END);
	fprintf(fp, "Range of upstream hostIndex = %d ~ %d\n", LAN_BANDWIDTH_CONTROL_US_HOSTIDX_START, LAN_BANDWIDTH_CONTROL_US_HOSTIDX_END);
	fprintf(fp, "Range of hostMibCtrl hostIndex = %d ~ %d\n", LAN_HPC_MIB_COUNTER_HOSTIDX_START, LAN_HPC_MIB_COUNTER_HOSTIDX_END);
	for(hostIndex=hostIndexStart ; hostIndex<=hostIndexEnd ; hostIndex++)
	{
		memset(&hostPoliceControl, 0, sizeof(rtk_rg_hostPoliceControl_t));
		if(rtk_rg_hostPoliceControl_get(&hostPoliceControl, hostIndex) == RT_ERR_RG_OK)
		{
			// not an empty rtk_rg_hostPoliceControl_t structure
			if(memcmp(&hostPoliceControl, &nullHostPoliceControl, sizeof(rtk_rg_hostPoliceControl_t)))
			{
				fprintf(fp, "hostIndex=%d, MAC=%02X:%02X:%02X:%02X:%02X:%02X, ingressLimitCtrl=%d, egressLimitCtrl=%d, mibCountCtrl=%d, limitMeterIdx=%d\n", hostIndex, hostPoliceControl.macAddr.octet[0], hostPoliceControl.macAddr.octet[1]
					, hostPoliceControl.macAddr.octet[2], hostPoliceControl.macAddr.octet[3], hostPoliceControl.macAddr.octet[4], hostPoliceControl.macAddr.octet[5],
					hostPoliceControl.ingressLimitCtrl, hostPoliceControl.egressLimitCtrl, hostPoliceControl.mibCountCtrl, hostPoliceControl.limitMeterIdx);
				if(hostPoliceControl.ingressLimitCtrl || hostPoliceControl.egressLimitCtrl) {
					if(rtk_rg_shareMeter_get(hostPoliceControl.limitMeterIdx, &shareMeterRate, &shareMeterEnabled) == RT_ERR_RG_OK)
					{
						fprintf(fp, "              , shareMeterRate=%d, shareMeterEnabled=%d\n", shareMeterRate, shareMeterEnabled);
					}
				}
			}
		}
	}
	fprintf(fp, "===========================================================================================================\n");
	fclose(fp);	
	return;
}

int RG_set_port_ingress_bandwidth_control(unsigned char *mac, unsigned int rate)
{
	int hostIndex, foundHostIndex=-1, nullHostIndex=-1, limitMeterIndex;
	rtk_rg_hostPoliceControl_t nullHostPoliceControl = {0};
	rtk_rg_hostPoliceControl_t hostPoliceControl;
	int hostIndexStart, hostIndexEnd;
	int hostIndexIsInMibCtrlRange = 0;
	int hostIndexToBeRemoved;
	int lockfd;

	if(mac == NULL)
		return -1;

	if(mac[0]==0x0 && mac[1]==0x0 && mac[2]==0x0 && mac[3]==0x0 && mac[4]==0x0 && mac[5]==0x0)
		return -1;

	LOCK_HOST_POLICE_CONTROL(LanHostPoliceCtrlSetupLock);
	/* if there exist a hostindex which keep same MAC in MIB control range & out of downstream rate control range
	   it means the sequence is setting MIB control of this MAC is before downstream rate control
	   we need to remove this hostindex from MIB control range to downstream rate control range */
#if defined(CONFIG_USER_LANNETINFO)
	for(hostIndex=(LAN_BANDWIDTH_CONTROL_US_HOSTIDX_END+1) ; hostIndex<=LAN_HPC_MIB_COUNTER_HOSTIDX_END ; hostIndex++)
	{
		memset(&hostPoliceControl, 0, sizeof(rtk_rg_hostPoliceControl_t));
		if(rtk_rg_hostPoliceControl_get(&hostPoliceControl, hostIndex) == RT_ERR_RG_OK)
		{
			// search same MAC address in the range of mib control if any & move it to DS rate limit range
			if(!memcmp(&hostPoliceControl.macAddr, mac, MAC_ADDR_LEN))
			{
				hostIndexIsInMibCtrlRange = 1;
				hostIndexToBeRemoved = hostIndex;
				break;
			}
		}
	}
#endif
	// search my hostindex or an first empty hostindex in downstream rate control range
	hostIndexStart = LAN_BANDWIDTH_CONTROL_DS_HOSTIDX_START;
	hostIndexEnd = LAN_BANDWIDTH_CONTROL_DS_HOSTIDX_END;
	for(hostIndex=hostIndexStart ; hostIndex<=hostIndexEnd ; hostIndex++)
	{
		memset(&hostPoliceControl, 0, sizeof(rtk_rg_hostPoliceControl_t));
		if(rtk_rg_hostPoliceControl_get(&hostPoliceControl, hostIndex) == RT_ERR_RG_OK)
		{
			// search for my hostindex
			if(!memcmp(&hostPoliceControl.macAddr, mac, MAC_ADDR_LEN))
			{
				foundHostIndex = hostIndex;
				break;
			}
			// search a empty hostindex
			if(!memcmp(&hostPoliceControl, &nullHostPoliceControl, sizeof(rtk_rg_hostPoliceControl_t)))
			{
				if(nullHostIndex == -1)
					nullHostIndex = hostIndex;
			}
		}
	}

	hostIndex = -1;
	if(foundHostIndex != -1)
	{
		hostIndex = foundHostIndex;
	}
	else if(nullHostIndex != -1)
	{
		hostIndex = nullHostIndex;
	}

	if(hostIndex != -1)
	{
		limitMeterIndex = (LAN_BANDWIDTH_CONTROL_DS_SM_ID_START+hostIndexEnd-hostIndex);
		if(rtk_rg_shareMeter_set(limitMeterIndex, rate, rate?RTK_RG_ENABLED:RTK_RG_DISABLED) != RT_ERR_RG_OK)
		{
			AUG_PRT(" rtk_rg_shareMeter_set fail !\n");
			UNLOCK_HOST_POLICE_CONTROL();
			return -1;
		}
		memcpy(&hostPoliceControl.macAddr, mac, MAC_ADDR_LEN);
		if(rate == 0)
			hostPoliceControl.ingressLimitCtrl = RTK_RG_DISABLED;
		else
			hostPoliceControl.ingressLimitCtrl = ENABLED;
		hostPoliceControl.limitMeterIdx = limitMeterIndex;
		if(hostIndexIsInMibCtrlRange)
		{
			if(rtk_rg_hostPoliceControl_set(&nullHostPoliceControl, hostIndexToBeRemoved) != RT_ERR_RG_OK)
			{
				AUG_PRT(" rtk_rg_hostPoliceControl_set fail !\n");
				UNLOCK_HOST_POLICE_CONTROL();
				return -1;
			}
			if(rtk_rg_hostPoliceLogging_del(hostIndexToBeRemoved) != RT_ERR_RG_OK)
			{
				AUG_PRT(" rtk_rg_hostPoliceLogging_del fail !\n");
				UNLOCK_HOST_POLICE_CONTROL();
				return -1;
			}
			hostPoliceControl.mibCountCtrl = ENABLED;
		}

#if RG_HOST_POLICE_CONTROL_DEBUG_ENABLE
		if(rate)
		{
			printf(" %s %d> macAddr=%02X:%02X:%02X:%02X:%02X:%02X eingressLimitCtrl=%d egressLimitCtrl=%d mibCountCtrl=%d limitMeterIdx=%d hostIndex=%d\n"
				, __func__, __LINE__, hostPoliceControl.macAddr.octet[0], hostPoliceControl.macAddr.octet[1]
				, hostPoliceControl.macAddr.octet[2], hostPoliceControl.macAddr.octet[3], hostPoliceControl.macAddr.octet[4]
				, hostPoliceControl.macAddr.octet[5], hostPoliceControl.ingressLimitCtrl, hostPoliceControl.egressLimitCtrl
				, hostPoliceControl.mibCountCtrl, hostPoliceControl.limitMeterIdx, hostIndex);
		}
		else
		{
			printf(" %s %d> macAddr=%02X:%02X:%02X:%02X:%02X:%02X eingressLimitCtrl=%d egressLimitCtrl=%d mibCountCtrl=%d limitMeterIdx=%d hostIndex=%d\n"
				, __func__, __LINE__, nullHostPoliceControl.macAddr.octet[0], nullHostPoliceControl.macAddr.octet[1]
				, nullHostPoliceControl.macAddr.octet[2], nullHostPoliceControl.macAddr.octet[3], nullHostPoliceControl.macAddr.octet[4]
				, nullHostPoliceControl.macAddr.octet[5], nullHostPoliceControl.ingressLimitCtrl, nullHostPoliceControl.egressLimitCtrl
				, nullHostPoliceControl.mibCountCtrl, nullHostPoliceControl.limitMeterIdx, hostIndex);
		}
#endif
		if(rtk_rg_hostPoliceControl_set((rate||hostPoliceControl.mibCountCtrl)?&hostPoliceControl:&nullHostPoliceControl, hostIndex) != RT_ERR_RG_OK)
		{
			AUG_PRT(" rtk_rg_hostPoliceControl_set fail !\n");
			UNLOCK_HOST_POLICE_CONTROL();
			return -1;
		}
	}
	else
	{
		//AUG_PRT(" RG host police control table full !\n");
		UNLOCK_HOST_POLICE_CONTROL();
		return -1;
	}

	// update debug information
	RG_update_lan_hpc_for_mib_debug_info();
	RG_update_lan_bandwidth_control_debug_info(0);

	UNLOCK_HOST_POLICE_CONTROL();
	return 0;
}

int RG_set_port_egress_bandwidth_control(unsigned char *mac, unsigned int rate)
{
	int hostIndex, foundHostIndex=-1, nullHostIndex=-1, limitMeterIndex;
	rtk_rg_hostPoliceControl_t nullHostPoliceControl = {0};
	rtk_rg_hostPoliceControl_t hostPoliceControl;
	int hostIndexStart, hostIndexEnd;
	int lockfd;

	if(mac == NULL)
		return -1;

	if(isZeroMac(mac))
		return -1;

	LOCK_HOST_POLICE_CONTROL(LanHostPoliceCtrlSetupLock);
	// search my hostindex or an first empty hostindex in upstream rate control range
	hostIndexStart = LAN_BANDWIDTH_CONTROL_US_HOSTIDX_START;
	hostIndexEnd = LAN_BANDWIDTH_CONTROL_US_HOSTIDX_END;
	for(hostIndex=hostIndexStart ; hostIndex<=hostIndexEnd ; hostIndex++)
	{
		memset(&hostPoliceControl, 0, sizeof(rtk_rg_hostPoliceControl_t));
		if(rtk_rg_hostPoliceControl_get(&hostPoliceControl, hostIndex) == RT_ERR_RG_OK)
		{
			// search for my hostindex
			if(!memcmp(&hostPoliceControl.macAddr, mac, MAC_ADDR_LEN))
			{
				foundHostIndex = hostIndex;
				break;
			}
			// search a empty hostindex
			if(!memcmp(&hostPoliceControl, &nullHostPoliceControl, sizeof(rtk_rg_hostPoliceControl_t)))
			{
				if(nullHostIndex == -1)
					nullHostIndex = hostIndex;
			}
		}
	}

	hostIndex = -1;
	if(foundHostIndex != -1)
	{
		hostIndex = foundHostIndex;
	}
	else if(nullHostIndex != -1)
	{
		hostIndex = nullHostIndex;
	}

	if(hostIndex != -1)
	{
		limitMeterIndex = (LAN_BANDWIDTH_CONTROL_US_SM_ID_START+hostIndexEnd-hostIndex);
		if(rtk_rg_shareMeter_set(limitMeterIndex, rate, rate?RTK_RG_ENABLED:RTK_RG_DISABLED) != RT_ERR_RG_OK)
		{
			AUG_PRT(" rtk_rg_shareMeter_set fail !\n");
			UNLOCK_HOST_POLICE_CONTROL();
			return -1;
		}
		memcpy(&hostPoliceControl.macAddr, mac, MAC_ADDR_LEN);
		if(rate == 0)
			hostPoliceControl.egressLimitCtrl = RTK_RG_DISABLED;
		else
			hostPoliceControl.egressLimitCtrl = ENABLED;		
		hostPoliceControl.limitMeterIdx = limitMeterIndex;
		
#if RG_HOST_POLICE_CONTROL_DEBUG_ENABLE
		if(rate)
		{
			printf(" %s %d> macAddr=%02X:%02X:%02X:%02X:%02X:%02X eingressLimitCtrl=%d egressLimitCtrl=%d mibCountCtrl=%d limitMeterIdx=%d hostIndex=%d\n"
				, __func__, __LINE__, hostPoliceControl.macAddr.octet[0], hostPoliceControl.macAddr.octet[1]
				, hostPoliceControl.macAddr.octet[2], hostPoliceControl.macAddr.octet[3], hostPoliceControl.macAddr.octet[4]
				, hostPoliceControl.macAddr.octet[5], hostPoliceControl.ingressLimitCtrl, hostPoliceControl.egressLimitCtrl
				, hostPoliceControl.mibCountCtrl, hostPoliceControl.limitMeterIdx, hostIndex);
		}
		else
		{
			printf(" %s %d> macAddr=%02X:%02X:%02X:%02X:%02X:%02X eingressLimitCtrl=%d egressLimitCtrl=%d mibCountCtrl=%d limitMeterIdx=%d hostIndex=%d\n"
				, __func__, __LINE__, nullHostPoliceControl.macAddr.octet[0], nullHostPoliceControl.macAddr.octet[1]
				, nullHostPoliceControl.macAddr.octet[2], nullHostPoliceControl.macAddr.octet[3], nullHostPoliceControl.macAddr.octet[4]
				, nullHostPoliceControl.macAddr.octet[5], nullHostPoliceControl.ingressLimitCtrl, nullHostPoliceControl.egressLimitCtrl
				, nullHostPoliceControl.mibCountCtrl, nullHostPoliceControl.limitMeterIdx, hostIndex);
		}
#endif
		if(rtk_rg_hostPoliceControl_set((rate||hostPoliceControl.mibCountCtrl)?&hostPoliceControl:&nullHostPoliceControl, hostIndex) != RT_ERR_RG_OK)
		{
			AUG_PRT(" rtk_rg_hostPoliceControl_set fail !\n");
			UNLOCK_HOST_POLICE_CONTROL();
			return -1;
		}
	}
	else
	{
		//AUG_PRT(" RG host police control table full !\n");
		UNLOCK_HOST_POLICE_CONTROL();
		return -1;
	}

	// update debug information
	RG_update_lan_hpc_for_mib_debug_info();
	RG_update_lan_bandwidth_control_debug_info(1);

	UNLOCK_HOST_POLICE_CONTROL();
	return 0;
}
#else
int RG_set_port_ingress_bandwidth_control(int port, unsigned int rate)
{
	int ret;
	ret=rtk_rg_portIgrBandwidthCtrlRate_set(port, rate);
	return ret;
}
int RG_set_port_egress_bandwidth_control(int port, unsigned int rate)
{
	int ret;
	ret=rtk_rg_portEgrBandwidthCtrlRate_set(port, rate);
	return ret;
}
#endif

#if defined(CONFIG_USER_LANNETINFO) && (defined(CONFIG_RTL9607C_SERIES) || defined(CONFIG_LUNA_G3_SERIES)) 
const char LAN_HOST_POLICE_CTRL_MIB_DEBUG_FILE[] = "/var/debugLanHostPoliceCtrlForMib";
void RG_update_lan_hpc_for_mib_debug_info(void)
{
	int hostIndex, hostIndexStart, hostIndexEnd;
	rtk_rg_hostPoliceControl_t nullHostPoliceControl = {0};
	rtk_rg_hostPoliceControl_t hostPoliceControl;
	rtk_rg_hostPoliceLogging_t hostPoliceLogging;
	FILE *fp = NULL;
	int lockfd;
	
	if (!(fp = fopen(LAN_HOST_POLICE_CTRL_MIB_DEBUG_FILE, "w")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return;
	}

	fprintf(fp, "HostPoliceControlMib debug info:\n");
	fprintf(fp, "===========================================================================================================\n");
	fprintf(fp, "Maxmum bandwidth control shareMeterID num = %d\n", MAX_BANDWIDTH_CONTROL_SM_ID_NUM);
	fprintf(fp, "Range of downstream shareMeterID = %d ~ %d\n", LAN_BANDWIDTH_CONTROL_DS_SM_ID_START, LAN_BANDWIDTH_CONTROL_DS_SM_ID_END);
	fprintf(fp, "Range of upstream shareMeterID = %d ~ %d\n", LAN_BANDWIDTH_CONTROL_US_SM_ID_START, LAN_BANDWIDTH_CONTROL_US_SM_ID_END);
	fprintf(fp, "Range of downstream hostIndex = %d ~ %d\n", LAN_BANDWIDTH_CONTROL_DS_HOSTIDX_START, LAN_BANDWIDTH_CONTROL_DS_HOSTIDX_END);
	fprintf(fp, "Range of upstream hostIndex = %d ~ %d\n", LAN_BANDWIDTH_CONTROL_US_HOSTIDX_START, LAN_BANDWIDTH_CONTROL_US_HOSTIDX_END);
	fprintf(fp, "Range of hostMibCtrl hostIndex = %d ~ %d\n", LAN_HPC_MIB_COUNTER_HOSTIDX_START, LAN_HPC_MIB_COUNTER_HOSTIDX_END);
	hostIndexStart = LAN_HPC_MIB_COUNTER_HOSTIDX_START;
	hostIndexEnd = LAN_HPC_MIB_COUNTER_HOSTIDX_END;
	for(hostIndex=hostIndexStart ; hostIndex<=hostIndexEnd ; hostIndex++)
	{
		memset(&hostPoliceControl, 0, sizeof(rtk_rg_hostPoliceControl_t));
		if(rtk_rg_hostPoliceControl_get(&hostPoliceControl, hostIndex) == RT_ERR_RG_OK)
		{
			// not an empty rtk_rg_hostPoliceControl_t structure
			if(memcmp(&hostPoliceControl, &nullHostPoliceControl, sizeof(rtk_rg_hostPoliceControl_t)))
			{
				fprintf(fp, "hostIndex=%d, MAC=%02X:%02X:%02X:%02X:%02X:%02X, ingressLimitCtrl=%d, egressLimitCtrl=%d, mibCountCtrl=%d, limitMeterIdx=%d\n", hostIndex, hostPoliceControl.macAddr.octet[0], hostPoliceControl.macAddr.octet[1]
					, hostPoliceControl.macAddr.octet[2], hostPoliceControl.macAddr.octet[3], hostPoliceControl.macAddr.octet[4], hostPoliceControl.macAddr.octet[5],
					hostPoliceControl.ingressLimitCtrl, hostPoliceControl.egressLimitCtrl, hostPoliceControl.mibCountCtrl, hostPoliceControl.limitMeterIdx);
				memset(&hostPoliceLogging, 0, sizeof(rtk_rg_hostPoliceLogging_t));
				if(rtk_rg_hostPoliceLogging_get(&hostPoliceLogging, hostIndex) == RT_ERR_RG_OK)
				{
					fprintf(fp, "              , rx_count=%10lld, tx_count=%10lld\n", hostPoliceLogging.rx_count, hostPoliceLogging.tx_count);
				}
			}
		}
	}
	fprintf(fp, "===========================================================================================================\n");
	fclose(fp);	
	return;
}

int RG_update_lan_hpc_for_mib(unsigned char *mac)
{
	int hostIndex, foundHostIndex=-1, nullHostIndex=-1, limitMeterIndex;
	rtk_rg_hostPoliceControl_t nullHostPoliceControl = {0};
	rtk_rg_hostPoliceControl_t hostPoliceControl;
	int hostIndexStart, hostIndexEnd;
	int lockfd;

	if(mac == NULL)
		return -1;

	if(isZeroMac(mac))
		return -1;

	LOCK_HOST_POLICE_CONTROL(LanHostPoliceCtrlSetupLock);
	// search my hostindex or an first empty hostindex in MIB control range
	hostIndexStart = LAN_HPC_MIB_COUNTER_HOSTIDX_START;
	hostIndexEnd = LAN_HPC_MIB_COUNTER_HOSTIDX_END;
	for(hostIndex=hostIndexStart ; hostIndex<=hostIndexEnd ; hostIndex++)
	{
		if(hostIndex >= LAN_BANDWIDTH_CONTROL_US_HOSTIDX_START && hostIndex <= LAN_BANDWIDTH_CONTROL_US_HOSTIDX_END)
		{
			continue;
		}
		memset(&hostPoliceControl, 0, sizeof(rtk_rg_hostPoliceControl_t));
		if(rtk_rg_hostPoliceControl_get(&hostPoliceControl, hostIndex) == RT_ERR_RG_OK)
		{
			// search for my hostindex
			if(!memcmp(&hostPoliceControl.macAddr, mac, MAC_ADDR_LEN))
			{
				foundHostIndex = hostIndex;
				if(hostPoliceControl.mibCountCtrl == ENABLED) 
				{
					RG_update_lan_hpc_for_mib_debug_info();
					UNLOCK_HOST_POLICE_CONTROL();
					return 0;
				}
				break;
			}
			// not in DS/US rate limit scope
			if(hostIndex>LAN_BANDWIDTH_CONTROL_US_HOSTIDX_END)
			{
				// search a empty hostindex
				if(!memcmp(&hostPoliceControl, &nullHostPoliceControl, sizeof(rtk_rg_hostPoliceControl_t)))
				{
					if(nullHostIndex == -1)
						nullHostIndex = hostIndex;
				}
			}
		}
	}
	
	hostIndex = -1;
	if(foundHostIndex != -1)
	{
		hostIndex = foundHostIndex;
	}
	else if(nullHostIndex != -1)
	{
		hostIndex = nullHostIndex;
	}

	if(hostIndex != -1)
	{
		memcpy(&hostPoliceControl.macAddr, mac, MAC_ADDR_LEN);
		hostPoliceControl.mibCountCtrl = ENABLED;

#if RG_HOST_POLICE_CONTROL_DEBUG_ENABLE
		printf(" %s %d> macAddr=%02X:%02X:%02X:%02X:%02X:%02X eingressLimitCtrl=%d egressLimitCtrl=%d mibCountCtrl=%d limitMeterIdx=%d hostIndex=%d\n"
			, __func__, __LINE__, hostPoliceControl.macAddr.octet[0], hostPoliceControl.macAddr.octet[1]
			, hostPoliceControl.macAddr.octet[2], hostPoliceControl.macAddr.octet[3], hostPoliceControl.macAddr.octet[4]
			, hostPoliceControl.macAddr.octet[5], hostPoliceControl.ingressLimitCtrl, hostPoliceControl.egressLimitCtrl
			, hostPoliceControl.mibCountCtrl, hostPoliceControl.limitMeterIdx, hostIndex);
#endif
		if(rtk_rg_hostPoliceControl_set(&hostPoliceControl, hostIndex) != RT_ERR_RG_OK)
		{
			AUG_PRT(" rtk_rg_hostPoliceControl_set fail !\n");
			UNLOCK_HOST_POLICE_CONTROL();
			return -1;
		}
	}
	else
	{
		//AUG_PRT(" RG host police control table full !\n");
		UNLOCK_HOST_POLICE_CONTROL();
		return -1;
	}
	
	RG_update_lan_hpc_for_mib_debug_info();
	if(hostIndex>=LAN_BANDWIDTH_CONTROL_DS_HOSTIDX_START && hostIndex<=LAN_BANDWIDTH_CONTROL_DS_HOSTIDX_END)
		RG_update_lan_bandwidth_control_debug_info(0);
	if(hostIndex>=LAN_BANDWIDTH_CONTROL_US_HOSTIDX_START && hostIndex<=LAN_BANDWIDTH_CONTROL_US_HOSTIDX_END)
		RG_update_lan_bandwidth_control_debug_info(1);

	UNLOCK_HOST_POLICE_CONTROL();
	return 0;
}

int RG_delete_lan_hpc_for_mib(unsigned char *mac)
{
	int hostIndex, foundHostIndex=-1, limitMeterIndex;
	rtk_rg_hostPoliceControl_t nullHostPoliceControl = {0};
	rtk_rg_hostPoliceControl_t hostPoliceControl;
	int hostIndexStart, hostIndexEnd;
	int lockfd;

	if(mac == NULL)
		return -1;

	if(isZeroMac(mac))
		return -1;

	LOCK_HOST_POLICE_CONTROL(LanHostPoliceCtrlSetupLock);
	hostIndexStart = LAN_HPC_MIB_COUNTER_HOSTIDX_START;
	hostIndexEnd = LAN_HPC_MIB_COUNTER_HOSTIDX_END;
	for(hostIndex=hostIndexStart ; hostIndex<=hostIndexEnd ; hostIndex++)
	{
		if(hostIndex >= LAN_BANDWIDTH_CONTROL_US_HOSTIDX_START 
			&& hostIndex <= LAN_BANDWIDTH_CONTROL_US_HOSTIDX_END)
		{
			continue;
		}
		memset(&hostPoliceControl, 0, sizeof(rtk_rg_hostPoliceControl_t));
		if(rtk_rg_hostPoliceControl_get(&hostPoliceControl, hostIndex) == RT_ERR_RG_OK)
		{
			// search for my hostindex
			if(!memcmp(&hostPoliceControl.macAddr, mac, MAC_ADDR_LEN))
			{
				foundHostIndex = hostIndex;
				break;
			}
		}
	}

	if(foundHostIndex != -1)
	{
		memcpy(&hostPoliceControl.macAddr, mac, MAC_ADDR_LEN);
		hostPoliceControl.mibCountCtrl = DISABLED;
		if(!hostPoliceControl.ingressLimitCtrl && !hostPoliceControl.egressLimitCtrl)
		{
			memcpy(&hostPoliceControl, &nullHostPoliceControl, sizeof(rtk_rg_hostPoliceControl_t));
		}

#if RG_HOST_POLICE_CONTROL_DEBUG_ENABLE
		printf(" %s %d> macAddr=%02X:%02X:%02X:%02X:%02X:%02X eingressLimitCtrl=%d egressLimitCtrl=%d mibCountCtrl=%d limitMeterIdx=%d hostIndex=%d\n"
			, __func__, __LINE__, hostPoliceControl.macAddr.octet[0], hostPoliceControl.macAddr.octet[1]
			, hostPoliceControl.macAddr.octet[2], hostPoliceControl.macAddr.octet[3], hostPoliceControl.macAddr.octet[4]
			, hostPoliceControl.macAddr.octet[5], hostPoliceControl.ingressLimitCtrl, hostPoliceControl.egressLimitCtrl
			, hostPoliceControl.mibCountCtrl, hostPoliceControl.limitMeterIdx, foundHostIndex);
#endif
		if(rtk_rg_hostPoliceControl_set(&hostPoliceControl, foundHostIndex) != RT_ERR_RG_OK)
		{
			AUG_PRT(" rtk_rg_hostPoliceControl_set fail !\n");
			UNLOCK_HOST_POLICE_CONTROL();
			return -1;
		}
		if(rtk_rg_hostPoliceLogging_del(foundHostIndex) != RT_ERR_RG_OK)
		{
			AUG_PRT(" rtk_rg_hostPoliceLogging_del fail !\n");
			UNLOCK_HOST_POLICE_CONTROL();
			return -1;
		}
	}
	else
	{
		//AUG_PRT(" RG host police control table entry not found ! (macAddr=%02X:%02X:%02X:%02X:%02X:%02X)\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
		UNLOCK_HOST_POLICE_CONTROL();
		return -1;
	}
	
	RG_update_lan_hpc_for_mib_debug_info();
	if(foundHostIndex>=LAN_BANDWIDTH_CONTROL_DS_HOSTIDX_START 
		&& foundHostIndex<=LAN_BANDWIDTH_CONTROL_DS_HOSTIDX_END) 
	{
		RG_update_lan_bandwidth_control_debug_info(0);
	}
	if(foundHostIndex>=LAN_BANDWIDTH_CONTROL_US_HOSTIDX_START 
		&& foundHostIndex<=LAN_BANDWIDTH_CONTROL_US_HOSTIDX_END) 
	{
		RG_update_lan_bandwidth_control_debug_info(1);
	}

	UNLOCK_HOST_POLICE_CONTROL();
	return 0;
}

int RG_get_host_police_control_mib_counter(unsigned char *mac, LAN_HOST_POLICE_CTRL_MIB_TYPE_T type, unsigned long long *result)
{
	int hostIndex, foundHostIndex=-1;
	rtk_rg_hostPoliceControl_t nullHostPoliceControl = {0};
	rtk_rg_hostPoliceControl_t hostPoliceControl;
	rtk_rg_hostPoliceLogging_t hostPoliceLogging;
	int hostIndexStart, hostIndexEnd;
	int lockfd;
	
	if(mac == NULL || result == NULL)
		return -1;

	if(isZeroMac(mac))
		return -1;

	LOCK_HOST_POLICE_CONTROL(LanHostPoliceCtrlSetupLock);
	hostIndexStart = LAN_HPC_MIB_COUNTER_HOSTIDX_START;
	hostIndexEnd = LAN_HPC_MIB_COUNTER_HOSTIDX_END;
	for(hostIndex=hostIndexStart ; hostIndex<=hostIndexEnd ; hostIndex++)
	{
		if(hostIndex >= LAN_BANDWIDTH_CONTROL_US_HOSTIDX_START 
			&& hostIndex <= LAN_BANDWIDTH_CONTROL_US_HOSTIDX_END)
		{
			continue;
		}
		memset(&hostPoliceControl, 0, sizeof(rtk_rg_hostPoliceControl_t));
		if(rtk_rg_hostPoliceControl_get(&hostPoliceControl, hostIndex) == RT_ERR_RG_OK)
		{
			// search for my hostindex
			if(!memcmp(&hostPoliceControl.macAddr, mac, MAC_ADDR_LEN) 
				&& hostPoliceControl.mibCountCtrl == ENABLED)
			{
				foundHostIndex = hostIndex;
				break;
			}
		}
	}

	if(foundHostIndex != -1)
	{
		memset(&hostPoliceLogging, 0, sizeof(rtk_rg_hostPoliceLogging_t));
		if(rtk_rg_hostPoliceLogging_get(&hostPoliceLogging, hostIndex) == RT_ERR_RG_OK)
		{
			switch(type)
			{
				case MIB_TYPE_RX_BYTES:
					*result = hostPoliceLogging.rx_count;
					break;
				case MIB_TYPE_TX_BYTES:
					*result = hostPoliceLogging.tx_count;
					break;
				default:
					AUG_PRT(" Invalid MIB type = %d\n", type);
					UNLOCK_HOST_POLICE_CONTROL();
					return -1;
			}
		}
		else
		{
			AUG_PRT(" rtk_rg_hostPoliceLogging_get fail ! \n");
			UNLOCK_HOST_POLICE_CONTROL();
			return -1;
		}
	}
	else
	{
		/*AUG_PRT(" RG host police control table entry not found ! (macAddr=%02X:%02X:%02X:%02X:%02X:%02X)\n"
			, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);*/
		UNLOCK_HOST_POLICE_CONTROL();
		return -1;
	}

	UNLOCK_HOST_POLICE_CONTROL();
	return 0;
}
#endif

#if defined(CONFIG_PPP) && defined(CONFIG_USER_PPPOE_PROXY)
int RTK_RG_PPPoE_Proxy_Rule_Set( MIB_CE_ATM_VC_Tp atmVcEntryPtr )
{
	rtk_rg_aclFilterAndQos_t aclRule;
	int aclIdx, ret;
	FILE *fp;

	if(atmVcEntryPtr->cmode == CHANNEL_MODE_PPPOE && atmVcEntryPtr->PPPoEProxyEnable)
	{
		memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
		aclRule.acl_weight = RG_DEFAULT_ACL_WEIGHT;
		aclRule.filter_fields |= INGRESS_PORT_BIT;
		if(atmVcEntryPtr->itfGroup) {
#ifdef CONFIG_RTL9602C_SERIES
			aclRule.ingress_port_mask.portmask = RG_get_lan_phyPortMask(atmVcEntryPtr->itfGroup & 0x3);
#else
			aclRule.ingress_port_mask.portmask = RG_get_lan_phyPortMask(atmVcEntryPtr->itfGroup & 0xf);
#endif
		} else {
			aclRule.ingress_port_mask.portmask = RG_get_all_lan_phyPortMask();
		}
		aclRule.filter_fields |= INGRESS_ETHERTYPE_BIT;
		aclRule.ingress_ethertype = 0x8864;
		aclRule.ingress_ethertype_mask = 0xffff;
		aclRule.action_type = ACL_ACTION_TYPE_TRAP_TO_PS;

		if(!(fp = fopen(RG_PPPOE_PROXY_RULES_FILE, "a")))
		{
			fprintf(stderr, "ERROR! %s\n", strerror(errno));
			return -2;
		}

		if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0) {
			fprintf(fp, "%d %d\n", atmVcEntryPtr->ifIndex, aclIdx);
		} else {
			printf("rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n", ret);
		}

		fclose(fp);
		return 0;
	}
}

int RTK_RG_PPPoE_Proxy_Rule_Delete( MIB_CE_ATM_VC_Tp atmVcEntryPtr )
{
	unsigned int ifIndex;
	FILE *fp, *fp_tmp;
	char line[24];
	int rule_idx;

	if(!(fp = fopen(RG_PPPOE_PROXY_RULES_FILE, "r")))
		return -2;

	if(!(fp_tmp = fopen(RG_PPPOE_PROXY_RULES_TEMP_FILE, "w")))
		return -2;

	while(fgets(line, 23, fp) != NULL)
	{
		sscanf(line, "%d %d\n", &ifIndex, &rule_idx);
		if(atmVcEntryPtr->ifIndex == ifIndex) {
			if(rtk_rg_aclFilterAndQos_del(rule_idx))
				DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", rule_idx);
		} else {
			fprintf(fp_tmp, "%d %d\n", ifIndex, rule_idx);
		}
	}

	fclose(fp);
	fclose(fp_tmp);
	unlink(RG_PPPOE_PROXY_RULES_FILE);
	rename(RG_PPPOE_PROXY_RULES_TEMP_FILE, RG_PPPOE_PROXY_RULES_FILE);
	return 0;
}
#endif

int RTK_RG_Reset_SSID_shaping_rule()
{
	char cmdBuf[100]={0};
	printf("Reset SSID shaping rate rule");
	
	sprintf(cmdBuf,"echo -1 -1 > %s", RG_WIFI_INGRESS_RATE_LIMIT_FILE);
	system(cmdBuf);
	
	sprintf(cmdBuf,"echo -1 -1 > %s", RG_WIFI_EGRESS_RATE_LIMIT_FILE);
	system(cmdBuf);
	
	return 0;
}

int RTK_RG_Config_SSID_shaping_rule()
{
#ifdef WLAN_MBSSID
	MIB_CE_MBSSIB_T Entry;
	int i,vwlan_idx, ori_wlan_idx, idx;
	char cmdBuf[100]={0};

	ori_wlan_idx = wlan_idx;
	for(i = 0; i<NUM_WLAN_INTERFACE; i++) 
	{
		wlan_idx = i;
		if (!getInFlags((char *)getWlanIfName(), 0)) {
			printf("Wireless Interface Not Found !\n");
			continue;
	    }

		for (vwlan_idx=0; vwlan_idx<=NUM_VWLAN_INTERFACE; vwlan_idx++) {
			if(!wlan_getEntry(&Entry, vwlan_idx) || Entry.wlanDisabled)
				continue;

			idx = vwlan_idx + WLAN_DEVICE_NUM*i;
			sprintf(cmdBuf,"echo %d %d > /proc/rg/wifi_ingress_rate_limit",idx,Entry.ingressLimitSpeed);
			system(cmdBuf);
			sprintf(cmdBuf,"echo %d %d > /proc/rg/wifi_egress_rate_limit",idx,Entry.egressLimitSpeed);
			system(cmdBuf);
		}
	}
	
	wlan_idx = ori_wlan_idx;
#endif
	return 0;
}

#ifdef CONFIG_CMCC_IPV6_SECURITY_SUPPORT
int RG_del_ipv6_sec_rule(int ruleidx)
{
	if(rtk_rg_aclFilterAndQos_del(ruleidx))
		DBPRINT(1, "del acl rule failed! idx = %d\n", ruleidx);
	return 0;
}

int RG_add_ipv6_sec_rule(struct in6_addr* p_ip6_addr, unsigned int portmask,unsigned short vid)
{
	rtk_rg_aclFilterAndQos_t aclRule;
	int aclIdx=-1;
	int ret=0;

	if(p_ip6_addr==NULL || portmask==0)
		return -1;

	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	aclRule.acl_weight = RG_RESERVED_ACL_WEIGHT+1;
	aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	aclRule.filter_fields = INGRESS_PORT_BIT|INGRESS_IPV6_TAGIF_BIT|INGRESS_IPV6_SIP_BIT;
	if(vid)
	{
		aclRule.filter_fields |= INGRESS_CTAG_VID_BIT;
		aclRule.ingress_ctag_vid = vid;
	}
	aclRule.ingress_ipv6_tagif = 1;
	aclRule.ingress_port_mask.portmask = portmask;
	memcpy(aclRule.ingress_src_ipv6_addr, p_ip6_addr, sizeof(struct in6_addr));
	memset(aclRule.ingress_src_ipv6_addr_mask, 0xff, sizeof(struct in6_addr));
	aclRule.action_type = ACL_ACTION_TYPE_PERMIT;
	if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0)
		;
	else
		printf("<%s %d> add acl rule failed! (ret = %d)\n",__func__,__LINE__, ret);
	return aclIdx;
}

int RG_add_default_ipv6_sec_rule(void)
{
	rtk_rg_aclFilterAndQos_t aclRule;
	int ret=0;
	FILE*fp;
	int aclIdx;

	if(!(fp = fopen(RG_IPV6_SEC_RULES_FILE, "w")))
	{
		return -1;
	}
	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	aclRule.acl_weight = RG_RESERVED_ACL_WEIGHT;
	aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	//aclRule.filter_fields = INGRESS_PORT_BIT|INGRESS_IPV6_TAGIF_BIT|INGRESS_IPV6_SIP_BIT;

	aclRule.ingress_port_mask.portmask = RG_get_all_lan_phyPortMask() & ~(RG_get_wan_phyPortMask());
#ifdef WLAN_SUPPORT
	aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN0));
#ifdef WLAN_DUALBAND_CONCURRENT
	aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN1));
#endif
	aclRule.ingress_port_mask.portmask |= (1 << RTK_RG_PORT_CPU);
#endif
	aclRule.ingress_ipv6_tagif = 1;
#if 0
	aclRule.ingress_src_ipv6_addr[0] = 0xfe;
	aclRule.ingress_src_ipv6_addr[1] = 0x80;
	memset(aclRule.ingress_src_ipv6_addr_mask, 0xff, 8);
	aclRule.action_type = ACL_ACTION_TYPE_PERMIT;
	if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0)
		fprintf(fp, "%d\n", aclIdx);
	else
		printf("<%s %d> add acl rule failed! (ret = %d)\n",__func__,__LINE__, ret);
#endif	
	aclRule.filter_fields = INGRESS_PORT_BIT|INGRESS_IPV6_TAGIF_BIT|INGRESS_L4_ICMPV6_BIT;
	aclRule.action_type = ACL_ACTION_TYPE_PERMIT;
	if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0)
		fprintf(fp, "%d\n", aclIdx);
	else
		printf("<%s %d> add acl rule failed! (ret = %d)\n",__func__,__LINE__, ret);

	aclRule.filter_fields = INGRESS_PORT_BIT|INGRESS_IPV6_TAGIF_BIT;
	aclRule.action_type = ACL_ACTION_TYPE_DROP;
	if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0)
		fprintf(fp, "%d\n", aclIdx);
	else
		printf("<%s %d> add acl rule failed! (ret = %d)\n",__func__,__LINE__, ret);
	fclose(fp);
	return aclIdx;
}

int RG_flush_default_ipv6_sec_rule(void)
{
	FILE *fp;
	int aclIdx;
	int ret = 0;

	if(!(fp = fopen(RG_IPV6_SEC_RULES_FILE, "r")))
		return -2;

	while(fscanf(fp, "%d\n", &aclIdx) != EOF)
	{
		if(rtk_rg_aclFilterAndQos_del(aclIdx))
			DBPRINT(1, "<%s %d>del acl rule failed! idx = %d\n", __func__,__LINE__,aclIdx);
	}

	fclose(fp);
	unlink(RG_IPV6_SEC_RULES_FILE);
	return  0;
}
#endif

#if (defined(CONFIG_CMCC) || defined(CONFIG_CU)) && defined(CONFIG_IPV6)
int RG_flush_ipv6_binding_rules()
{
	FILE *fp;
	int aclIdx;	

	//delete acl rules
	if(!(fp = fopen(RG_ACL_IPV6_BINDING_RULES_FILE, "r")))
		return -2;
	while(fscanf(fp, "%d\n", &aclIdx) != EOF)
	{
		if(rtk_rg_aclFilterAndQos_del(aclIdx))
			DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", aclIdx);
	}
	fclose(fp);
	unlink(RG_ACL_IPV6_BINDING_RULES_FILE);	
	return 0;	
}

int RG_add_ipv6_binding_rules(MIB_IPV6_BINDING_T *entry, int rg_wan_idx)
{
	rtk_rg_aclFilterAndQos_t aclRule;
	FILE *fp;
	int aclIdx, ret = 1;
	int len=0;
	char addr[MAX_V6_IP_LEN] ={0};
	char addr_num[IPV6_ADDR_LEN] = {0};
	unsigned int portMask = 0;
	sscanf(entry->ipv6_addr, "%[^/]/%d", addr, &len);
	inet_pton(AF_INET6, addr, (void *)addr_num);
	if(!(fp = fopen(RG_ACL_IPV6_BINDING_RULES_FILE, "a")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -1;
	}
	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	aclRule.action_type = ACL_ACTION_TYPE_POLICY_ROUTE;
	aclRule.action_policy_route_wan = rg_wan_idx;
	aclRule.filter_fields |= INGRESS_ETHERTYPE_BIT;
	aclRule.ingress_ethertype =  0x86DD;
	aclRule.ingress_ethertype_mask = 0xFFFF;
	aclRule.filter_fields |= INGRESS_IPV6_SIP_RANGE_BIT;
	IPv6PrefixToStartEnd(addr_num, len, aclRule.ingress_src_ipv6_addr_start, aclRule.ingress_src_ipv6_addr_end);
	if(entry->binding_mode == 0)
	{
		
		portMask = 1<<entry->binding_port;
		aclRule.filter_fields |= INGRESS_PORT_BIT;
#ifdef CONFIG_RTL9602C_SERIES
		aclRule.ingress_port_mask.portmask = RG_get_lan_phyPortMask((portMask)&0x3);
#else
		aclRule.ingress_port_mask.portmask = RG_get_lan_phyPortMask((portMask)&0xf);
#endif
#ifdef WLAN_SUPPORT
		if(portMask >>4)//bind wlan
		{
			aclRule.filter_fields |= INGRESS_WLANDEV_BIT;
			aclRule.ingress_wlanDevMask = ((portMask>>4)&0x1f) | (((portMask>>9)&0x1f)<<13) ;
		}
#endif
	}
	else
	{
		if(entry->binding_vlan>0 && entry->binding_vlan<4095)
		{
			aclRule.filter_fields |= INGRESS_CTAGIF_BIT;
			aclRule.ingress_ctagIf = 1;
			aclRule.filter_fields |= INGRESS_CTAG_VID_BIT;			
			aclRule.ingress_ctag_vid = entry->binding_vlan;
			aclRule.filter_fields |= INGRESS_PORT_BIT;
			aclRule.ingress_port_mask.portmask = RG_get_all_lan_phyPortMask();
#ifdef WLAN_SUPPORT
			aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN0));
#ifdef WLAN_DUALBAND_CONCURRENT
			aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN1));
#endif
#endif
		}	
	}
	if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0)
		fprintf(fp, "%d\n", aclIdx);
	else
	{
		printf("rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n", ret);
		return 0;
	}

	//add permit rules
	aclRule.action_type = ACL_ACTION_TYPE_PERMIT;
	if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0)
		fprintf(fp, "%d\n", aclIdx);
	else
	{
		printf("rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n", ret);
		return 0;
	}
	fclose(fp);
	return ret;
}

int RG_add_drop_all_rules()
{
	rtk_rg_aclFilterAndQos_t aclRule;
	FILE *fp;
	int i,j,entryTotal, ifidx, aclIdx, ret = 1;
	int record_port[32],record_vlan[32], idx_port = 0, idx_vlan = 0;
	MIB_IPV6_BINDING_T entry;
	int new_flag = 1;
	unsigned int portMask = 0;

	if(!(fp = fopen(RG_ACL_IPV6_BINDING_RULES_FILE, "a")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -1;
	}
	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	aclRule.action_type = ACL_ACTION_TYPE_DROP;
	aclRule.filter_fields |= INGRESS_ETHERTYPE_BIT;
	aclRule.ingress_ethertype =  0x86DD;
	aclRule.ingress_ethertype_mask = 0xFFFF;
	entryTotal = mib_chain_total(MIB_IPV6_BINDING);	
	for(j=0 ; j<entryTotal ; j++)
	{
		if (!mib_chain_get(MIB_IPV6_BINDING, j, (void *)&entry)) {
			printf("get mib chain error!\n");
			return 0;
		}
		if(entry.binding_mode == 0)
		{
			ifidx = entry.binding_port;
			new_flag = 1;
			for(i = 0; i < idx_port; i++)
			{
				if(ifidx == record_port[i])
				{
					new_flag = 0;
					break;
				}			
			}
			if(new_flag)
			{
				record_port[idx_port++] = ifidx;				
				//add drop rules
				aclRule.filter_fields |= INGRESS_PORT_BIT;
				portMask = 1<<entry.binding_port;
#ifdef CONFIG_RTL9602C_SERIES
				aclRule.ingress_port_mask.portmask = RG_get_lan_phyPortMask((portMask)&0x3);
#else
				aclRule.ingress_port_mask.portmask = RG_get_lan_phyPortMask((portMask)&0xf);
#endif
#ifdef WLAN_SUPPORT
				if(portMask >>4)//bind wlan
				{
					aclRule.filter_fields |= INGRESS_WLANDEV_BIT;
					aclRule.ingress_wlanDevMask = ((portMask>>4)&0x1f) | (((portMask>>9)&0x1f)<<13) ;
				}
#endif
			}						
		}
		else
		{			
			new_flag = 1;
			for(i = 0; i < idx_vlan; i++)
			{
				if(entry.binding_vlan == record_vlan[i])
				{
					new_flag = 0;
					break;
				}					
			}
			if(new_flag)
			{
				aclRule.filter_fields |= INGRESS_CTAG_VID_BIT;			
				aclRule.ingress_ctag_vid = entry.binding_vlan;
				aclRule.filter_fields |= INGRESS_PORT_BIT;
				aclRule.ingress_port_mask.portmask = RG_get_all_lan_phyPortMask();
#ifdef WLAN_SUPPORT
				aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN0));
#ifdef WLAN_DUALBAND_CONCURRENT
				aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN1));
#endif
#endif
			}
		}
		if(new_flag)
		{
			if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0)
			fprintf(fp, "%d\n", aclIdx);
			else
			{
				printf("rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n", ret);
				return 0;
			}
		}
	}	
	fclose(fp);
	return ret;
}

#ifdef CONFIG_USER_CUMANAGEDEAMON
void add_acl_rule_for_dscp_mark(unsigned char *smac)
{
	rtk_rg_aclFilterAndQos_t aclRule;
	int aclIdx=0;
	char cmd[256] = {0};
	char macString[32]={0};
	unsigned char sMAC_mask[MAC_ADDR_LEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

	printf("enter %s\n",__func__);
	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));

	aclRule.filter_fields |= INGRESS_PORT_BIT;
#ifdef CONFIG_RTL9602C_SERIES
	aclRule.ingress_port_mask.portmask = RG_get_lan_phyPortMask(0x3);
#else
	aclRule.ingress_port_mask.portmask = RG_get_lan_phyPortMask(0xf);
#endif

#ifdef WLAN_SUPPORT
	aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN0));
#ifdef WLAN_DUALBAND_CONCURRENT
	aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN1));
#endif
#endif

	aclRule.filter_fields |= INGRESS_SMAC_BIT;
	memcpy(&aclRule.ingress_smac, smac, MAC_ADDR_LEN);
	memcpy(&aclRule.ingress_smac_mask, sMAC_mask, MAC_ADDR_LEN);

	aclRule.action_type = ACL_ACTION_TYPE_QOS;

	aclRule.qos_actions |= ACL_ACTION_DSCP_REMARKING_BIT;
	aclRule.action_dscp_remarking_pri = 63;

	if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0)
	{	
		sprintf(macString, "%02x:%02x:%02x:%02x:%02x:%02x", smac[0], smac[1], smac[2], smac[3], smac[4], smac[5]);
		sprintf(cmd, "echo %s %d >> %s", macString, aclIdx, RG_ACL_FILTER_DSCP_REMAKR_FILE);
		system(cmd);
		printf("add dscp remark rule Successfully %d\n",aclIdx);
	}else
		printf("Error! Add dscp remark rule Failed\n");

	printf("exit %s\n",__func__);
}

int del_acl_rule_for_dscp_mark(unsigned char *smac)
{
	FILE *fp, *fp_tmp;
	char line[64];
	char macString[32]={0};
	char tmpString[32]={0};
	int rule_idx;

	if(!(fp = fopen(RG_ACL_FILTER_DSCP_REMAKR_FILE, "r")))
		return -2;

	if(!(fp_tmp = fopen(RG_ACL_FILTER_DSCP_REMAKR_TEMP_FILE, "w")))
		return -2;

	sprintf(tmpString, "%02x:%02x:%02x:%02x:%02x:%02x", smac[0], smac[1], smac[2], smac[3], smac[4], smac[5]);
	while(fgets(line, 64, fp) != NULL)
	{
		sscanf(line, "%s %d\n", macString, &rule_idx);
		if(strcmp(tmpString, macString)==0) {
			if(rtk_rg_aclFilterAndQos_del(rule_idx))
				DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", rule_idx);
		} else {
			fprintf(fp_tmp, "%s %d\n", macString, rule_idx);
		}
	}

	fclose(fp);
	fclose(fp_tmp);
	unlink(RG_ACL_FILTER_DSCP_REMAKR_FILE);
	rename(RG_ACL_FILTER_DSCP_REMAKR_TEMP_FILE, RG_ACL_FILTER_DSCP_REMAKR_FILE);
	return 0;
}

int get_acl_rule_for_dscp_mark(unsigned char *smac)
{
	FILE *fp=NULL;
	char line[64];
	char macString[32]={0};
	char tmpString[32]={0};
	int rule_idx, ret=0;

	if(!(fp = fopen(RG_ACL_FILTER_DSCP_REMAKR_FILE, "r")))
		return 0;

	sprintf(tmpString, "%02x:%02x:%02x:%02x:%02x:%02x", smac[0], smac[1], smac[2], smac[3], smac[4], smac[5]);
	while(fgets(line, 64, fp) != NULL)
	{
		sscanf(line, "%s %d\n", macString, &rule_idx);
		if(strcmp(tmpString, macString)==0) {
			ret = 1;
			break;
		} 
	}

	fclose(fp);
	return ret;
}
#endif

int checkIPv4_IPv6_Dual_PolicyRoute(int *wanIndex, unsigned short *portMask)
{
	int vcTotal, i, ret;
	MIB_CE_ATM_VC_T Entry;
	MIB_CE_ATM_VC_T EntryV4, EntryV6;
	int isFoundv4 = 0, isFoundv6 = 0;
	
	vcTotal = mib_chain_total(MIB_ATM_VC_TBL);
	for (i = 0; i < vcTotal; i++)
	{
		if (!mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&Entry))
				return -1;

		if (Entry.enable == 0)
			continue;

		if(Entry.cmode != CHANNEL_MODE_BRIDGE && (Entry.applicationtype&X_CT_SRV_INTERNET) && Entry.IpProtocol == IPVER_IPV4) {
			memcpy(&EntryV4, &Entry, sizeof(Entry));
			isFoundv4 = 1;
		}
		if(Entry.cmode != CHANNEL_MODE_BRIDGE && (Entry.applicationtype&X_CT_SRV_INTERNET) && Entry.IpProtocol == IPVER_IPV6) {
			memcpy(&EntryV6, &Entry, sizeof(Entry));
			isFoundv6 = 1;
		}
		if(isFoundv4==1 && isFoundv6==1){
			break;
		}
	}

	if(isFoundv4==1 && isFoundv6==1 && EntryV4.itfGroup!=0 && EntryV4.itfGroup==EntryV6.itfGroup){
		*wanIndex = EntryV4.rg_wan_idx;
		*portMask = EntryV4.itfGroup;
		return 1;
	}
	else{
		return 0;
	}
}

int checkIPv4_IPv6_Dual_PolicyRoute_ex(MIB_CE_ATM_VC_Tp pEntry, int *wanIndex, unsigned short *portMask)
{
	int vcTotal, i, ret;
	MIB_CE_ATM_VC_T Entry;
	MIB_CE_ATM_VC_T EntryV4, EntryV6;
	int isFoundv4 = 0, isFoundv6 = 0;

	if(pEntry->cmode != CHANNEL_MODE_BRIDGE && (pEntry->applicationtype&X_CT_SRV_INTERNET) && pEntry->IpProtocol == IPVER_IPV4){
		memcpy(&EntryV4, pEntry, sizeof(Entry));
		isFoundv4 = 1;
		vcTotal = mib_chain_total(MIB_ATM_VC_TBL);
		for (i = 0; i < vcTotal; i++)
		{
			if (!mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&Entry))
					return -1;

			if (Entry.enable == 0)
				continue;

			if(Entry.cmode != CHANNEL_MODE_BRIDGE && (Entry.applicationtype&X_CT_SRV_INTERNET) && Entry.IpProtocol == IPVER_IPV6) {
				memcpy(&EntryV6, &Entry, sizeof(Entry));
				isFoundv6 = 1;
			}
			if(isFoundv4==1 && isFoundv6==1){
				break;
			}
		}
	}
	else if(pEntry->cmode != CHANNEL_MODE_BRIDGE && (pEntry->applicationtype&X_CT_SRV_INTERNET) && pEntry->IpProtocol == IPVER_IPV6) {
		memcpy(&EntryV6, pEntry, sizeof(Entry));
		isFoundv6 = 1;
		vcTotal = mib_chain_total(MIB_ATM_VC_TBL);
		for (i = 0; i < vcTotal; i++)
		{
			if (!mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&Entry))
					return -1;

			if (Entry.enable == 0)
				continue;

			if(Entry.cmode != CHANNEL_MODE_BRIDGE && (Entry.applicationtype&X_CT_SRV_INTERNET) && Entry.IpProtocol == IPVER_IPV4) {
				memcpy(&EntryV4, &Entry, sizeof(Entry));
				isFoundv4 = 1;
			}

			if(isFoundv4==1 && isFoundv6==1){
				break;
			}
		}
	}
	

	if(isFoundv4==1 && isFoundv6==1 && EntryV4.itfGroup!=0 && EntryV4.itfGroup==EntryV6.itfGroup){
		*wanIndex = EntryV4.rg_wan_idx;
		*portMask = EntryV4.itfGroup;
		return 1;
	}
	else{
		return 0;
	}
}

void RTK_RG_FLUSH_IPv4_IPv6_Dual_PolicyRoute()
{
	FILE *fp;
	int aclIdx;
	int ret = 0;

	if(!(fp = fopen(RG_IPV4V6_DUAL_POLICYROUTE_RULES_FILE, "r")))
		return;

	while(fscanf(fp, "%d\n", &aclIdx) != EOF)
	{
		if(rtk_rg_aclFilterAndQos_del(aclIdx))
			DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", aclIdx);
	}

	fclose(fp);
	unlink(RG_IPV4V6_DUAL_POLICYROUTE_RULES_FILE);
}

int RGSyncIPv4_IPv6_Dual_WAN()
{
	int wanIndex = 0;
	unsigned short portMask = 0;
	int aclIdx = 0, ret = 0;
	rtk_rg_aclFilterAndQos_t aclRule;
	FILE *fp = NULL;
	
	RTK_RG_FLUSH_IPv4_IPv6_Dual_PolicyRoute();
	if(checkIPv4_IPv6_Dual_PolicyRoute(&wanIndex, &portMask)==0){
		//printf("\033[1;33;40m @@@@@@@@@@@@@@@@@########### %s:%d DO NOT need add IPv4_IPv6_Dual policy route\033[m\n", __FUNCTION__, __LINE__);
		return;
	}

	if(!(fp = fopen(RG_IPV4V6_DUAL_POLICYROUTE_RULES_FILE, "a")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -1;
	}
	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	aclRule.acl_weight = RG_FIREWALL_ACL_WEIGHT;
	aclRule.action_type = ACL_ACTION_TYPE_POLICY_ROUTE;

	aclRule.filter_fields |= INGRESS_PORT_BIT;
	#ifdef CONFIG_RTL9602C_SERIES
	aclRule.ingress_port_mask.portmask = RG_get_lan_phyPortMask(portMask &0x3);
	#else
	aclRule.ingress_port_mask.portmask = RG_get_lan_phyPortMask(portMask &0xf);
	#endif
	aclRule.filter_fields |= INGRESS_IPV4_TAGIF_BIT;
	aclRule.ingress_ipv4_tagif = 1;
	aclRule.action_policy_route_wan = wanIndex;
#ifdef WLAN_SUPPORT
	if(portMask & 0x1f0)
		aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN0));
#ifdef WLAN_DUALBAND_CONCURRENT
	if(portMask & 0x3e00)
		aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN1));
#endif
#endif

	if ((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) != 0) {
		printf("[%s@%d] QoS rule failed! (ret = %d)\n", __FUNCTION__, __LINE__, ret);
		//printf("\033[1;33;40m @@@@@@@@@@@@@@@@@########### %s:%d add IPv4_IPv6_Dual policy route fail!\033[m\n", __FUNCTION__, __LINE__);
		return -1;
	}
	else{
		fprintf(fp, "%d\n", aclIdx);
		//printf("\033[1;33;40m @@@@@@@@@@@@@@@@@########### %s:%d add IPv4_IPv6_Dual policy route successful! [%d]\033[m\n", __FUNCTION__, __LINE__, aclIdx);
	}
	fclose(fp);

	return 0;
}

int Clear_Vlan_Cfg()
{
	FILE *fp;
	int aclIdx;	

	//delete acl rules
	if(!(fp = fopen(RG_ACL_VLAN_INGRESS_RULES_FILE, "r")))
		return -2;
	while(fscanf(fp, "%d\n", &aclIdx) != EOF)
	{
		if(rtk_rg_aclFilterAndQos_del(aclIdx))
			DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", aclIdx);
	}
	fclose(fp);
	unlink(RG_ACL_VLAN_INGRESS_RULES_FILE);	
	return 0;	
}

int Add_Cvlan_IPv4_IPv6(int ipv4_vlanID,int ipv6_vlanID)
{
	rtk_rg_cvlan_info_t cvlan_info;
	int ret = 1;
	
	if(ipv4_vlanID > 0)
	{
		memset(&cvlan_info, 0x0, sizeof(rtk_rg_cvlan_info_t));
		cvlan_info.vlanId = ipv4_vlanID;
		rtk_rg_cvlan_get(&cvlan_info);
#ifdef CONFIG_RTL9607C_SERIES
		//cvlan_info.memberPortMask.portmask = (1<<RTK_RG_PORT_MAINCPU)|(1<<RTK_RG_PORT_CPU)|(1<<RTK_RG_PORT_PON)|(1<<RTK_RG_PORT0)
		//	|(1<<RTK_RG_PORT1)|(1<<RTK_RG_PORT2)|(1<<RTK_RG_PORT3)|(1<<RTK_RG_EXT_PORT0)|(1<<RTK_RG_EXT_PORT1);
		cvlan_info.memberPortMask.portmask = RG_get_all_lan_phyPortMask();
		cvlan_info.memberPortMask.portmask |= (1<<RTK_RG_PORT_MAINCPU)|(1<<RTK_RG_PORT_CPU)|(1<<RTK_RG_PORT_PON);
		cvlan_info.memberPortMask.portmask |= (1<<RTK_RG_EXT_PORT0)|(1<<RTK_RG_EXT_PORT1);
		
		//cvlan_info.untagPortMask.portmask = (1<<RTK_RG_PORT_MAINCPU)|(1<<RTK_RG_PORT_CPU)|(1<<RTK_RG_PORT0)
		//	|(1<<RTK_RG_PORT1)|(1<<RTK_RG_PORT2)|(1<<RTK_RG_PORT3)|(1<<RTK_RG_EXT_PORT0)|(1<<RTK_RG_EXT_PORT1);
		cvlan_info.untagPortMask.portmask = RG_get_all_lan_phyPortMask();
		cvlan_info.untagPortMask.portmask |= (1<<RTK_RG_PORT_MAINCPU)|(1<<RTK_RG_PORT_CPU);
		cvlan_info.untagPortMask.portmask |= (1<<RTK_RG_EXT_PORT0)|(1<<RTK_RG_EXT_PORT1);
#else
		//cvlan_info.memberPortMask.portmask = (1<<RTK_RG_PORT_CPU)|(1<<RTK_RG_PORT_PON)|(1<<RTK_RG_PORT0)
		//	|(1<<RTK_RG_PORT1)|(1<<RTK_RG_PORT2)|(1<<RTK_RG_PORT3)|(1<<RTK_RG_EXT_PORT0)|(1<<RTK_RG_EXT_PORT1);
		cvlan_info.memberPortMask.portmask = RG_get_all_lan_phyPortMask();
		cvlan_info.memberPortMask.portmask |= (1<<RTK_RG_PORT_CPU)|(1<<RTK_RG_PORT_PON);
		cvlan_info.memberPortMask.portmask |= (1<<RTK_RG_EXT_PORT0)|(1<<RTK_RG_EXT_PORT1);
		
		//cvlan_info.untagPortMask.portmask = (1<<RTK_RG_PORT_CPU)|(1<<RTK_RG_PORT0)
		//	|(1<<RTK_RG_PORT1)|(1<<RTK_RG_PORT2)|(1<<RTK_RG_PORT3)|(1<<RTK_RG_EXT_PORT0)|(1<<RTK_RG_EXT_PORT1);
		cvlan_info.untagPortMask.portmask = RG_get_all_lan_phyPortMask();
		cvlan_info.untagPortMask.portmask |= (1<<RTK_RG_PORT_CPU);
		cvlan_info.untagPortMask.portmask |= (1<<RTK_RG_EXT_PORT0)|(1<<RTK_RG_EXT_PORT1);
#endif
		cvlan_info.wlan0DevMask = 0;
		cvlan_info.wlan0UntagMask = 0;

		ret = rtk_rg_cvlan_add(&cvlan_info);
	}
	
	if(ipv6_vlanID > 0)
	{
		memset(&cvlan_info, 0x0, sizeof(rtk_rg_cvlan_info_t));
		cvlan_info.vlanId = ipv6_vlanID;
		rtk_rg_cvlan_get(&cvlan_info);
#ifdef CONFIG_RTL9607C_SERIES
		//cvlan_info.memberPortMask.portmask = (1<<RTK_RG_PORT_MAINCPU)|(1<<RTK_RG_PORT_CPU)|(1<<RTK_RG_PORT_PON)|(1<<RTK_RG_PORT0)
		//	|(1<<RTK_RG_PORT1)|(1<<RTK_RG_PORT2)|(1<<RTK_RG_PORT3)|(1<<RTK_RG_EXT_PORT0)|(1<<RTK_RG_EXT_PORT1);
		cvlan_info.memberPortMask.portmask = RG_get_all_lan_phyPortMask();
		cvlan_info.memberPortMask.portmask |= (1<<RTK_RG_PORT_MAINCPU)|(1<<RTK_RG_PORT_CPU)|(1<<RTK_RG_PORT_PON);
		cvlan_info.memberPortMask.portmask |= (1<<RTK_RG_EXT_PORT0)|(1<<RTK_RG_EXT_PORT1);
		
		//cvlan_info.untagPortMask.portmask = (1<<RTK_RG_PORT_MAINCPU)|(1<<RTK_RG_PORT_CPU)|(1<<RTK_RG_PORT0)
		//	|(1<<RTK_RG_PORT1)|(1<<RTK_RG_PORT2)|(1<<RTK_RG_PORT3)|(1<<RTK_RG_EXT_PORT0)|(1<<RTK_RG_EXT_PORT1);
		cvlan_info.untagPortMask.portmask = RG_get_all_lan_phyPortMask();
		cvlan_info.untagPortMask.portmask |= (1<<RTK_RG_PORT_MAINCPU)|(1<<RTK_RG_PORT_CPU);
		cvlan_info.untagPortMask.portmask |= (1<<RTK_RG_EXT_PORT0)|(1<<RTK_RG_EXT_PORT1);
#else
		//cvlan_info.memberPortMask.portmask = (1<<RTK_RG_PORT_CPU)|(1<<RTK_RG_PORT_PON)|(1<<RTK_RG_PORT0)
		//	|(1<<RTK_RG_PORT1)|(1<<RTK_RG_PORT2)|(1<<RTK_RG_PORT3)|(1<<RTK_RG_EXT_PORT0)|(1<<RTK_RG_EXT_PORT1);
		cvlan_info.memberPortMask.portmask = RG_get_all_lan_phyPortMask();
		cvlan_info.memberPortMask.portmask |= (1<<RTK_RG_PORT_CPU)|(1<<RTK_RG_PORT_PON);
		cvlan_info.memberPortMask.portmask |= (1<<RTK_RG_EXT_PORT0)|(1<<RTK_RG_EXT_PORT1);
		
		//cvlan_info.untagPortMask.portmask = (1<<RTK_RG_PORT_CPU)|(1<<RTK_RG_PORT0)
		//	|(1<<RTK_RG_PORT1)|(1<<RTK_RG_PORT2)|(1<<RTK_RG_PORT3)|(1<<RTK_RG_EXT_PORT0)|(1<<RTK_RG_EXT_PORT1);
		cvlan_info.untagPortMask.portmask = RG_get_all_lan_phyPortMask();
		cvlan_info.untagPortMask.portmask |= (1<<RTK_RG_PORT_CPU);
		cvlan_info.untagPortMask.portmask |= (1<<RTK_RG_EXT_PORT0)|(1<<RTK_RG_EXT_PORT1);
#endif
		cvlan_info.wlan0DevMask = 0;
		cvlan_info.wlan0UntagMask = 0;
		
		ret = rtk_rg_cvlan_add(&cvlan_info);
	}
	
	return ret;
}


int Add_ACL_Vlan_Cfg(int ipv4_vlanID,int ipv6_vlanID)
{
	rtk_rg_aclFilterAndQos_t aclRule;
	FILE *fp;
	int aclIdx, ret = 1;
	unsigned short portMask = 0;

	if(!(fp = fopen(RG_ACL_VLAN_INGRESS_RULES_FILE, "a")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -1;
	}
	//set common acl feature
	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;
	aclRule.action_type = ACL_ACTION_TYPE_QOS;
	aclRule.qos_actions |= ACL_ACTION_ACL_INGRESS_VID_BIT;	
	aclRule.filter_fields |= INGRESS_ETHERTYPE_BIT;
	aclRule.ingress_ethertype_mask = 0xFFFF;
	aclRule.filter_fields |= INGRESS_PORT_BIT;
	aclRule.ingress_port_mask.portmask = RG_get_all_lan_phyPortMask();
	aclRule.ingress_port_mask.portmask |= RG_get_wan_phyPortMask();
#ifdef WLAN_SUPPORT
	aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN0));
#ifdef WLAN_DUALBAND_CONCURRENT
	aclRule.ingress_port_mask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN1));
#endif
#endif
	//add acl rule for ipv4
	if(ipv4_vlanID > 0)
	{		
		aclRule.action_acl_ingress_vid = ipv4_vlanID;		
		aclRule.ingress_ethertype =  0x0800;
		if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0)
			fprintf(fp, "%d\n", aclIdx);
		else
		{
			printf("rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n", ret);
			return 0;
		}	
	}
	//add acl rule for ipv6
	if(ipv6_vlanID > 0)
	{
		aclRule.action_acl_ingress_vid = ipv6_vlanID;
		aclRule.ingress_ethertype =  0x86DD;
		if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0)
			fprintf(fp, "%d\n", aclIdx);
		else
		{
			printf("rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n", ret);
			return 0;
		}
	}
	fclose(fp);	
	return ret;
}

#endif

#if defined(CONFIG_YUEME)
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
	aclRule.acl_weight = RG_ACL_HIGHEST_PRI_WEIGHT;
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
	aclRule.acl_weight = RG_ACL_HIGHEST_PRI_WEIGHT;
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
		aclRule.acl_weight = RG_ACL_HIGHEST_PRI_WEIGHT;
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
	aclRule.acl_weight = RG_ACL_HIGHEST_PRI_WEIGHT;
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
	aclRule.acl_weight = RG_ACL_HIGHEST_PRI_WEIGHT;
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
	aclRule.acl_weight = RG_ACL_HIGHEST_PRI_WEIGHT;
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
	aclRule.acl_weight = RG_ACL_HIGHEST_PRI_WEIGHT;
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
	aclRule.acl_weight = RG_ACL_HIGHEST_PRI_WEIGHT;
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
	aclRule.acl_weight = RG_ACL_HIGHEST_PRI_WEIGHT;
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
	aclRule.acl_weight = RG_ACL_HIGHEST_PRI_WEIGHT;
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
	aclRule.acl_weight = RG_ACL_HIGHEST_PRI_WEIGHT;
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
	aclRule.ingress_dest_ipv4_addr_start = aclRule.ingress_dest_ipv4_addr_end = ntohl(*((ipaddr_t *)&lan_ip.s_addr));
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
	aclRule.acl_weight = RG_FIREWALL_ACL_WEIGHT;
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
		aclRule.acl_weight = RG_ACL_HIGHEST_PRI_WEIGHT;
		aclRule.filter_fields |= INGRESS_PORT_BIT;
		aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();
		aclRule.action_trap_with_priority = 7;
		aclRule.filter_fields |= INGRESS_IPV4_SIP_RANGE_BIT;
		aclRule.ingress_src_ipv4_addr_start = aclRule.ingress_src_ipv4_addr_end = ntohl(ITMS_Server_Address.s_addr);
		//memcpy(&aclRule.ingress_src_ipv4_addr_start, &ITMS_Server_Address, IP_ADDR_LEN);
		//memcpy(&aclRule.ingress_src_ipv4_addr_end, &ITMS_Server_Address, IP_ADDR_LEN);
		aclRule.filter_fields |= INGRESS_IPV4_TAGIF_BIT;
		aclRule.ingress_ipv4_tagif = 1;
		aclRule.action_type = ACL_ACTION_TYPE_TRAP_WITH_PRIORITY;		
		if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0) {
			fprintf(fp, "%d\n", aclIdx);
		} else {
			printf("[%s@%d] rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n",__func__,__LINE__, ret);
		}
	}

	/* VoIP */
	#ifdef CONFIG_RTK_VOIP
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
		aclRule.acl_weight = RG_ACL_HIGHEST_PRI_WEIGHT;
		aclRule.filter_fields |= INGRESS_PORT_BIT;
		aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();
		aclRule.action_trap_with_priority = 7;
		aclRule.filter_fields |= INGRESS_L4_DPORT_RANGE_BIT;
		aclRule.filter_fields |= INGRESS_L4_UDP_BIT;		
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
		aclRule.acl_weight = RG_ACL_HIGHEST_PRI_WEIGHT;
		aclRule.filter_fields |= INGRESS_PORT_BIT;
		aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();
		aclRule.action_trap_with_priority = 7;
		aclRule.filter_fields |= INGRESS_L4_DPORT_RANGE_BIT;
		aclRule.filter_fields |= INGRESS_L4_UDP_BIT;		
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
	#endif // CONFIG_RTK_VOIP
	
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
	aclRule.ingress_src_ipv4_addr_start = aclRule.ingress_src_ipv4_addr_end = ntohl(*((ipaddr_t *)&lan_ip.s_addr));
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
#if 0
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
#endif
	#ifdef CONFIG_RTK_VOIP
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
	#endif //CONFIG_RTK_VOIP

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

void RTK_RG_Control_Packet_ITMS_Ingress_ACL_Rule_set(struct in_addr *addr)
{
	rtk_rg_aclFilterAndQos_t aclRule;
	int aclIdx=0, ret;
	FILE *fp;
	
	if(!(fp = fopen(RG_INGRESS_CONTROL_ITMS_PACKET_ACL_RULES_FILE, "a")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return;
	}
	
	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	aclRule.acl_weight = RG_ACL_HIGHEST_PRI_WEIGHT;
	aclRule.filter_fields |= INGRESS_PORT_BIT;
	aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();
	aclRule.action_trap_with_priority = 7;
	aclRule.filter_fields |= INGRESS_IPV4_SIP_RANGE_BIT;
	aclRule.ingress_src_ipv4_addr_start = aclRule.ingress_src_ipv4_addr_end = ntohl(addr->s_addr);
	//memcpy(&aclRule.ingress_src_ipv4_addr_start, addr, IP_ADDR_LEN);
	//memcpy(&aclRule.ingress_src_ipv4_addr_end, addr, IP_ADDR_LEN);
	aclRule.filter_fields |= INGRESS_IPV4_TAGIF_BIT;
	aclRule.ingress_ipv4_tagif = 1;
	aclRule.action_type = ACL_ACTION_TYPE_TRAP_WITH_PRIORITY;		
	if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0) {
		fprintf(fp, "%d\n", aclIdx);
	} else {
		printf("[%s@%d] rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n",__func__,__LINE__, ret);
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

void RTK_RG_Control_Packet_ITMS_Egress_ACL_Rule_set(struct in_addr *addr)
{
	rtk_rg_aclFilterAndQos_t aclRule;
	int aclIdx=0, ret;
	FILE *fp;
	
	if(!(fp = fopen(RG_EGRESS_CONTROL_ITMS_PACKET_ACL_RULES_FILE, "a")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return;
	}

	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	aclRule.acl_weight = RG_FIREWALL_ACL_WEIGHT;
	aclRule.filter_fields |= INGRESS_PORT_BIT;
	aclRule.ingress_port_mask.portmask = RTK_RG_ALL_MAC_CPU_PORTMASK;
	aclRule.filter_fields |= INGRESS_IPV4_DIP_RANGE_BIT;
	aclRule.ingress_dest_ipv4_addr_start = aclRule.ingress_dest_ipv4_addr_end = ntohl(addr->s_addr);
	//memcpy(&aclRule.ingress_dest_ipv4_addr_start, addr, IP_ADDR_LEN);
	//memcpy(&aclRule.ingress_dest_ipv4_addr_end, addr, IP_ADDR_LEN);
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
	char cmd[256] = {0};
	sprintf(cmd, "/bin/echo 0x%x > /proc/rg/ArpReq_rate_limit_portMask", RG_get_wan_phyPortMask());
	system(cmd);
	system("/bin/echo 30 > /proc/rg/ArpReq_rate_limit");
	if(rtk_rg_shareMeter_set(30, 56, RTK_RG_ENABLED) != RT_ERR_RG_OK)
	{
		AUG_PRT(" rtk_rg_shareMeter_set fail !\n");
	}
}

void RTK_RG_add_UDP_rate_limit( char *ifname, struct in_addr *ipAddr)
{
	unsigned char mibIfname[IFNAMSIZ];
	char cmdStr[512] = {0};
	MIB_CE_ATM_VC_T atmVcEntry;
	unsigned int atmVcEntryNum;
	int i, j, intWanFound = -1;
	int wanIfIndex;
	char ip_str[INET_ADDRSTRLEN];
	
	wanIfIndex = getIfIndexByName(ifname);
	atmVcEntryNum = mib_chain_total(MIB_ATM_VC_TBL);
	for (i=0; i<atmVcEntryNum; i++)
	{
		if (!mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&atmVcEntry))
		{
			printf("error get atm vc entry\n");
			return;
		}

		if(atmVcEntry.applicationtype&X_CT_SRV_INTERNET) {
			if (atmVcEntry.cmode == CHANNEL_MODE_IPOE) {
				ifGetName(atmVcEntry.ifIndex, mibIfname, sizeof(mibIfname));
				if(!strcmp(mibIfname, ifname))
				{
					intWanFound = i;
					break;
				}
			} else if (atmVcEntry.cmode == CHANNEL_MODE_PPPOE && (!strcmp(ifname, "ppp0") || !strcmp(ifname, "ppp1"))) {
				int totalSession = mib_chain_total(MIB_PPPOE_SESSION_TBL);
				MIB_CE_PPPOE_SESSION_T session = {0};
				for(j = 0 ; j < totalSession ; j++)
				{
					mib_chain_get(MIB_PPPOE_SESSION_TBL, j, &session);
					if(session.uifno == atmVcEntry.ifIndex)
					{
						intWanFound = i;
						break;
					}
				}
			}
		}
	}

	if(intWanFound!=-1) {

		if (!mib_chain_get(MIB_ATM_VC_TBL, intWanFound, (void *)&atmVcEntry))
		{
			printf("error get atm vc entry\n");
			return;
		}
		
		inet_ntop(AF_INET, &(ipAddr->s_addr), ip_str, INET_ADDRSTRLEN);
		//echo "Portmask 0x20 Ctagif 1 CtagVid 81 DA 00:00:00:0a:0b:0c DIP 10.10.10.1 Tcp 0 Length_start 128 Length_end 132" > /proc/rg/dos_rate_limit_pattern
		sprintf(cmdStr, "/bin/echo \"Portmask 0x%x Ctagif 1 CtagVid %d DA %02x:%02x:%02x:%02x:%02x:%02x DIP %s Tcp 0 Length_start %d Length_end %d\" > /proc/rg/dos_rate_limit_pattern", RG_get_wan_phyPortMask(), atmVcEntry.vid, atmVcEntry.MacAddr[0], atmVcEntry.MacAddr[1], atmVcEntry.MacAddr[2], atmVcEntry.MacAddr[3], atmVcEntry.MacAddr[4], atmVcEntry.MacAddr[5], ip_str, 124, 128);
		AUG_PRT("cmdStr=%s\n", &cmdStr[0]);
		system(cmdStr);
		system("/bin/echo 28 > /proc/rg/dos_rate_limit");
		if(rtk_rg_shareMeter_set(28, 300, RTK_RG_ENABLED) != RT_ERR_RG_OK)
		{
			AUG_PRT(" rtk_rg_shareMeter_set fail !\n");
		}
	}
}
#endif

static int RG_restore_cvlan_member(int vlan, unsigned short unbinded_portMask)
{
	rtk_rg_cvlan_info_t cvlan_info;
	memset(&cvlan_info, 0x0, sizeof(rtk_rg_cvlan_info_t));
	cvlan_info.vlanId=vlan;
#ifdef CONFIG_RTL9602C_SERIES
	cvlan_info.memberPortMask.portmask |=RG_get_lan_phyPortMask(unbinded_portMask&0x3);
#else
	cvlan_info.memberPortMask.portmask |=RG_get_lan_phyPortMask(unbinded_portMask&0xf);
#endif
#ifdef WLAN_SUPPORT
	//add extensions port for broadcast wifi packet
	if((unbinded_portMask & (ITFGROUP_WLAN_MASK << ITFGROUP_WLAN0_DEV_BIT)) > 0){
		//printf("\033[1;33;40m @@@@@@@@@@@@@@@@@########### extensions port 1 pvid %d\033[m\n", pvid);
		cvlan_info.memberPortMask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN0));
	}
#endif
#if defined(WLAN_SUPPORT)	
	cvlan_info.wlan0DevMask |= (((unbinded_portMask >> ITFGROUP_WLAN0_DEV_BIT) & ITFGROUP_WLAN_MASK ) << RG_RET_MBSSID_MASTER_ROOT_INTF);
#if defined(WLAN_DUALBAND_CONCURRENT)
	//add extensions port for broadcast wifi packet
	if((unbinded_portMask & (ITFGROUP_WLAN_MASK << ITFGROUP_WLAN1_DEV_BIT)) > 0){
		//printf("\033[1;33;40m @@@@@@@@@@@@@@@@@########### extensions port 2 pvid %d\033[m\n", pvid);
		cvlan_info.memberPortMask.portmask |= (1 << RG_get_wlan_phyPortId(PMAP_WLAN1));
	}
	cvlan_info.wlan0DevMask |= (((unbinded_portMask >> ITFGROUP_WLAN1_DEV_BIT) & ITFGROUP_WLAN_MASK ) << RG_RET_MBSSID_SLAVE_ROOT_INTF);
#endif
	cvlan_info.wlan0UntagMask |= cvlan_info.wlan0DevMask;
#endif
	rtk_rg_cvlan_add(&cvlan_info);

	return 0;
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

	if(vcEntry->cmode != CHANNEL_MODE_BRIDGE)
		return 0;
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
//AUG_PRT("firstBrVid=%d,vcEntry.cmode=%d vcEntry.vid=%d",firstBrVid,vcEntry->cmode,vcEntry->vid);

	//get unbinded port mask
	for(i=0;i<=PMAP_ETH0_SW3;i++)
	{
		tmp = (itfGroup >> i) & 1;
		if(tmp == 0){
//AUG_PRT("flush_vconfig:%d,ubinded port:%d",firstBrVid,i);
			flush_vconfig(firstBrVid,i);
		}
	}
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
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

//for yueme factory vlan transparent request 
//open 4K vlan transparen, skip reserved vlan.
int do_vlan_transparent(void)
{
	int i,cpuVid,blockVid,internetVid,otherVid,lanVid;
	/*To configure user's define vlan id range*/
	mib_get(MIB_FWD_CPU_VLAN_ID, (void *)&cpuVid);
	AUG_PRT("cpuVid=%d\n",cpuVid);

	mib_get(MIB_FWD_PROTO_BLOCK_VLAN_ID, (void *)&blockVid);
	AUG_PRT("blockVid=%d\n",blockVid);

	mib_get(MIB_FWD_BIND_INTERNET_VLAN_ID, (void *)&internetVid);
	AUG_PRT("internetVid=%d\n",internetVid);

	mib_get(MIB_FWD_BIND_OTHER_VLAN_ID, (void *)&otherVid);
	AUG_PRT("otherVid=%d\n",otherVid);
	
	for(i=1;i<4095;i++)
	{
		//skip system reserved vlan.
		//printf("vlan:%d\n",i);
		if((i >= otherVid) && ( i<= (otherVid + DEFAULT_BIND_LAN_OFFSET)))
		{
			printf("skip reserved vlan:%d\n",i);
			continue;
		}
		if((i==cpuVid)||(i==blockVid)||(i==internetVid))
		{
			printf("skip reserved vlan:%d\n",i);
			continue;
		}
		
		add_vlan_transparent(i);

	}

	return 0;
}
//this func would let input vid group tag transparent, tag to egress port.
int add_vlan_transparent(int vid)
{
	rtk_rg_cvlan_info_t cvlan_info;
	memset(&cvlan_info,0,sizeof(rtk_rg_cvlan_info_t));
	//printf("%s vlan:%d\n",__func__,vid);
	cvlan_info.vlanId = vid;
	//if(rtk_rg_cvlan_get(&cvlan_info) == RT_ERR_RG_OK)
	{
		cvlan_info.memberPortMask.portmask = RTK_RG_ALL_PORTMASK;
		cvlan_info.untagPortMask.portmask = 0x0;
#ifdef CONFIG_MASTER_WLAN0_ENABLE
		cvlan_info.wlan0DevMask = 0xffffffff;
		cvlan_info.wlan0UntagMask = 0x0;
#endif
		if(rtk_rg_cvlan_add(&cvlan_info)!= RT_ERR_RG_OK)
			printf("%s-%d rtk_rg_cvlan_add failed\n",__func__,__LINE__);
	}
	return 0;
}

//vlan binding would conflict with add cvlan
//for 4K vlan transparent, we need to check vlan binding before
//calling rg API....
int check_cvlan_group_before_add_vlan_binding(void)
{
	int totalPortbd,port;
	char value=0;
	MIB_CE_PORT_BINDING_T pbEntry;
	rtk_rg_cvlan_info_t cvlan_info;
	memset(&cvlan_info,0,sizeof(rtk_rg_cvlan_info_t));	
	mib_get(MIB_VLAN_4K_TRANSPARENT_EN, (void *)&value);
	if(value == 0)
		return 0;
	
	totalPortbd = mib_chain_total(MIB_PORT_BINDING_TBL);
	//polling every lanport vlan-mapping entry
	for (port = 0; port < totalPortbd; ++port)
	{
		//get the number 'port' pbentry!
		mib_chain_get(MIB_PORT_BINDING_TBL, port, (void*)&pbEntry);	
		//is it vlan-mapping lan-port?
		if((unsigned char)VLAN_BASED_MODE == pbEntry.pb_mode)
		{
			struct v_pair *vid_pair;
			int k;

			vid_pair = (struct v_pair *)&pbEntry.pb_vlan0_a;

			// because there are only 4 pairs~
			for (k=0; k<4; k++)
			{
				//Be sure the content of vlan-mapping exsit!
				if (vid_pair[k].vid_a)
				{
					cvlan_info.vlanId = vid_pair[k].vid_a;
					//AUG_PRT("vlan:%d\n",cvlan_info.vlanId);
					if(rtk_rg_cvlan_get(&cvlan_info) == RT_ERR_RG_OK)
					{
						printf("check vlan:%d existed! del it\n",cvlan_info.vlanId);
						if(cvlan_info.addedAsCustomerVLAN == 1)
						{
							if(rtk_rg_cvlan_del(cvlan_info.vlanId)!= RT_ERR_RG_OK)
								printf("%s-%d rtk_rg_cvlan_del failed\n",__func__,__LINE__);
						}					}
				}
			}
		}

	}

}


int flush_igmp_snoop_acl_rule(void)
{
	FILE *fp;
	int filter_idx;

	if(!(fp = fopen(RG_IGMP_SNOOP_ACL_RULES_FILE, "r"))){
		printf("open=%s fail!!\n",RG_IGMP_SNOOP_ACL_RULES_FILE);
		return -2;
	}

	while(fscanf(fp, "%d\n", &filter_idx) != EOF)
	{
		if(rtk_rg_aclFilterAndQos_del(filter_idx))
			DBPRINT(1, "rtk_rg_naptFilterAndQos_del failed! idx = %d\n", filter_idx);
	}
	AUG_PRT("filter_idx=%d\n",filter_idx);
	fclose(fp);
	unlink(RG_IGMP_SNOOP_ACL_RULES_FILE);
	return 0;

}
int flush_mld_snoop_acl_rule(void)
{
	FILE *fp;
	int filter_idx;

	if(!(fp = fopen(RG_MLD_SNOOP_ACL_RULES_FILE, "r"))){
		printf("open=%s fail!!\n",RG_MLD_SNOOP_ACL_RULES_FILE);
		return -2;
	}

	while(fscanf(fp, "%d\n", &filter_idx) != EOF)
	{
		if(rtk_rg_aclFilterAndQos_del(filter_idx))
			DBPRINT(1, "rtk_rg_naptFilterAndQos_del failed! idx = %d\n", filter_idx);
	}
	AUG_PRT("filter_idx=%d\n",filter_idx);
	fclose(fp);
	unlink(RG_MLD_SNOOP_ACL_RULES_FILE);
	return 0;

}


int check_v4_igmp_snooping(void)
{
#if 1
		return 0;
#else
	int igmp_snoop_flag=0,aclIdx=0,ret=0;
	rtk_rg_aclFilterAndQos_t aclRule;
	unsigned int fwdcpu_vid;
	FILE *fp = NULL;
	unsigned char mode;
	char filename[64] = {0};
	if (!(fp = fopen(RG_IGMP_SNOOP_ACL_RULES_FILE, "a"))) {
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -2;
	}
	
	mib_get(MIB_MPMODE, (void *)&mode);
	AUG_PRT("mode:%d\n",mode);	
	igmp_snoop_flag = (((mode&MP_IGMP_MASK)==MP_IGMP_MASK)?1:0);
	//fprintf(stderr, "igmp_snoop_flag:%d\n",igmp_snoop_flag);
	AUG_PRT("igmp_snoop_flag:%d\n",igmp_snoop_flag);		
	if(!igmp_snoop_flag){
			unsigned int pmask=0;
			pmask = RG_get_all_lan_phyPortMask();		
			AUG_PRT("pmask:%d\n",pmask);
			if(pmask == 0x1e)//9603C
			{
				system("/bin/diag l2-table set lookup-miss multicast flood-ports 1-4");
			}
			else
			{
				system("/bin/diag l2-table set lookup-miss multicast flood-ports 0-3");
			}
			system("/bin/diag l2-table set lookup-miss port all ip-mcast action flood-in-vlan");
			system("echo 1 > /proc/rg/igmpProxyOnly2Wifi");

			memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
			//tranfser mVid to internal vid 1, to flood to all member!
			aclRule.filter_fields |= INGRESS_PORT_BIT;
			aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();//wan port
			aclRule.acl_weight = RG_DEFAULT_ACL_WEIGHT;
			aclRule.filter_fields |= INGRESS_IPV4_DIP_RANGE_BIT;
			aclRule.filter_fields |= INGRESS_IPV4_TAGIF_BIT;
			aclRule.ingress_ipv4_tagif = 1;
			aclRule.ingress_dest_ipv4_addr_start=0xe0000000;
			aclRule.ingress_dest_ipv4_addr_end=0xefffffff;
			aclRule.filter_fields |= INGRESS_L4_UDP_BIT;			
			aclRule.action_type = ACL_ACTION_TYPE_QOS;
			aclRule.qos_actions |= ACL_ACTION_ACL_INGRESS_VID_BIT;
			mib_get(MIB_FWD_CPU_VLAN_ID, (void *)&fwdcpu_vid);
			aclRule.action_acl_ingress_vid = fwdcpu_vid; //lan interface's vlan
			if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0){
				fprintf(fp,"%d\n",aclIdx);
				fprintf(stderr, "%s-%d, index=%d success\n",__func__,__LINE__, aclIdx);
				AUG_PRT("index=%d success\n",aclIdx);			
			}else{
				fprintf(stderr, "%s-%d, fail!\n",__func__,__LINE__);
			}
	}
	fclose(fp);
#endif
}

int check_v6_mld_snooping(void)
{
#if 1
		return 0;
#else
	int mld_snoop_flag=0,aclIdx=0,ret=0;
	rtk_rg_aclFilterAndQos_t aclRule;
	unsigned int fwdcpu_vid;
	FILE *fp = NULL;
	char filename[64] = {0};
	unsigned char mode;
	unsigned char ip6Addr[IP6_ADDR_LEN]={0}, mask[IP6_ADDR_LEN]={0};
	
	if (!(fp = fopen(RG_MLD_SNOOP_ACL_RULES_FILE, "a"))) {
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -2;
	}
	
	mib_get(MIB_MPMODE, (void *)&mode);
	AUG_PRT("mode:%d\n",mode);	
	mld_snoop_flag = (((mode&MP_MLD_MASK)==MP_MLD_MASK)?1:0);
	//fprintf(stderr, "igmp_snoop_flag:%d\n",igmp_snoop_flag);
	AUG_PRT("mld_snoop_flag:%d\n",mld_snoop_flag);	
	if(!mld_snoop_flag){
		unsigned int pmask=0;
		pmask = RG_get_all_lan_phyPortMask();		
		AUG_PRT("pmask:%d\n",pmask);
		if(pmask == 0x1e)//9603C
		{
			system("/bin/diag l2-table set lookup-miss multicast flood-ports 1-4");
		}
		else
		{
			system("/bin/diag l2-table set lookup-miss multicast flood-ports 0-3");
		}
		system("/bin/diag l2-table set lookup-miss port all ip6-mcast action flood-in-vlan");
		system("echo 1 > /proc/rg/igmpProxyOnly2Wifi");
		
			memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
			//tranfser mVid to internal vid 1, to flood to all member!
			aclRule.filter_fields |= INGRESS_PORT_BIT;
			aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();//wan port
			aclRule.acl_weight = RG_DEFAULT_ACL_WEIGHT;
			aclRule.filter_fields |= INGRESS_IPV6_DIP_BIT;
			aclRule.filter_fields |= INGRESS_L4_UDP_BIT;
			aclRule.ingress_ipv6_tagif = 1;
			inet_pton(PF_INET6, "ff0e::0",(void *)ip6Addr);
			memcpy(aclRule.ingress_dest_ipv6_addr, ip6Addr, IPV6_ADDR_LEN);
			inet_pton(PF_INET6, "ff0f:0:0:0:0:0:0:0",(void *)mask);
			memcpy(aclRule.ingress_dest_ipv6_addr_mask, mask, IPV6_ADDR_LEN);
			aclRule.filter_fields |= INGRESS_IPV6_TAGIF_BIT;
			aclRule.ingress_ipv6_tagif = 1;	
			//aclRule.filter_fields |= INGRESS_DMAC_BIT;
			//memcpy(&aclRule.ingress_dmac,MCAST_ADDR,MAC_ADDR_LEN);
			//memcpy(&aclRule.ingress_dmac_mask,MCAST_MASK,MAC_ADDR_LEN);
			aclRule.action_type = ACL_ACTION_TYPE_QOS;
			aclRule.qos_actions |= ACL_ACTION_ACL_INGRESS_VID_BIT;
			mib_get(MIB_FWD_CPU_VLAN_ID, (void *)&fwdcpu_vid);
			aclRule.action_acl_ingress_vid = fwdcpu_vid; //lan interface's vlan
			if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0){
				fprintf(fp,"%d\n",aclIdx);
				fprintf(stderr, "%s-%d, index=%d success\n",__func__,__LINE__, aclIdx);
				AUG_PRT("index=%d success\n",aclIdx);

			}else{
				fprintf(stderr, "%s-%d, fail!\n",__func__,__LINE__);
			}
	}

	fclose(fp);
#endif
}

#ifdef _PRMT_X_CT_COM_MULTICAST_DIAGNOSIS_
/* retrun -1: error
     return >0 : aclidx
*/
int aclTrapMulticastGrpToPS(unsigned int grp)
{
	rtk_rg_aclFilterAndQos_t aclRule;
	int i,aclIdx=0, ret;
	
	char MCAST_ADDR[MAC_ADDR_LEN]={0x01,0x00,0x5E,0x00,0x00,0x00};
	char MCAST_MASK[MAC_ADDR_LEN]={0xff,0xff,0xff,0x00,0x00,0x00};
	
	memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
	aclRule.fwding_type_and_direction = ACL_FWD_TYPE_DIR_INGRESS_ALL_PACKET;

	aclRule.filter_fields |= INGRESS_PORT_BIT;
	aclRule.ingress_port_mask.portmask = RG_get_wan_phyPortMask();//wan port
	aclRule.acl_weight = RG_DEFAULT_ACL_WEIGHT;

	aclRule.filter_fields |= INGRESS_IPV4_DIP_RANGE_BIT;
	aclRule.ingress_dest_ipv4_addr_start = ntohl(grp);
	aclRule.ingress_dest_ipv4_addr_end = ntohl(grp);

	
	aclRule.filter_fields |= INGRESS_DMAC_BIT;
	memcpy(&aclRule.ingress_dmac,MCAST_ADDR,MAC_ADDR_LEN);
	memcpy(&aclRule.ingress_dmac_mask,MCAST_MASK,MAC_ADDR_LEN);

	aclRule.action_type = ACL_ACTION_TYPE_TRAP_TO_PS;
	if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0){
		fprintf(stderr, "Add acl trap, index=%d success\n", aclIdx);
		return aclIdx;
	}else{
		fprintf(stderr,"rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n", ret);
		return -1;
	}
}

/* retrun -1: error
     return >0 : aclidx
*/
int addVritualGroupToRG(unsigned int grp)
{
	rtk_rg_multicastFlow_t macFlow;
	int flowIdx;
	int ret;
	int logPortId, phyPortId;

	/*
	rg set multicastFlow multicast_ipv4_addr 224.1.2.6 multicast_ipv6_addr 0::0  isIPv6 0 port_mask 0x200 isIVL 0 vlanId 0
	rg add multicastFlow entry
	*/
	memset(&macFlow, 0, sizeof(rtk_rg_multicastFlow_t));
	macFlow.multicast_ipv4_addr = ntohl(grp);
	
	logPortId = RTK_PORT_CPU;
	ret = rtk_rg_switch_phyPortId_get(logPortId, &phyPortId);
	
	if(ret == 0)
		macFlow.port_mask.portmask |= (1 << phyPortId);
	else
		DBPRINT(1, "%s rtk_rg_switch_phyPortId_get failed!\n", __FUNCTION__);

	fprintf(stderr, "CPU phyportid = %d\n", phyPortId);
	ret = rtk_rg_multicastFlow_add(&macFlow, &flowIdx);
	
	if(ret == 0){
		fprintf(stderr, "Add group entry, index=%d success\n", flowIdx);
		return flowIdx;
	}else{
		fprintf(stderr,"rtk_rg_multicastFlow_add() failed! (ret = %d)\n", ret);
		return -1;
	}
}
#endif

#ifdef CONFIG_YUEME
int RTK_RG_Wifi_AccessRule_ACL_Rule_set(wl_ipport_rule *rule)
{
	int aclIdx, i, j, shiftMask, ret;
	unsigned int mask = 0;
	FILE *fp;
	rtk_rg_aclFilterAndQos_t aclRule;
	wl_ipport_rule *prule = rule;
	
	if(prule == NULL) {
		fprintf(stderr, "[%s@%d] ERROR! Input argument\n", __FUNCTION__, __LINE__);
		return -1;
	}
	
	if((fp = fopen(RG_WIFI_ACCESS_RULE_FILE, "r")))
	{
		while(fscanf(fp, "%d\n", &aclIdx) != EOF)
		{
			if(rtk_rg_aclFilterAndQos_del(aclIdx))
				DBPRINT(1, "rtk_rg_aclFilterAndQos_del failed! idx = %d\n", aclIdx);
		}
		fclose(fp);
	}
	
	if(!(fp = fopen(RG_WIFI_ACCESS_RULE_FILE, "w")))
	{
		fprintf(stderr, "ERROR! %s\n", strerror(errno));
		return -2;
	}
	
	while(prule)
	{
		if(prule->wlan_idx_mask > 0)
		{
			memset(&aclRule, 0, sizeof(rtk_rg_aclFilterAndQos_t));
			if(prule->action){
				aclRule.action_type = ACL_ACTION_TYPE_PERMIT;
				aclRule.acl_weight = RG_QOS_ACL_WEIGHT;
			}
			else{
				aclRule.action_type = ACL_ACTION_TYPE_DROP;
				aclRule.acl_weight = RG_QOS_USER_APP_WEIGHT;
			}	
			
			aclRule.filter_fields |= INGRESS_WLANDEV_BIT;
			for(i=0; i<NUM_WLAN_INTERFACE; i++)
			{
				if((i*WLAN_MBSSID_NUM) < WLAN_MBSSID_NUM)
					shiftMask = RG_RET_MBSSID_MASTER_ROOT_INTF;
				else 
					shiftMask = RG_RET_MBSSID_SLAVE_ROOT_INTF;
				
				for(j=0;j<WLAN_MBSSID_NUM; j++)
				{
					mask = 1<<(i*WLAN_MBSSID_NUM+j);
					if(prule->wlan_idx_mask & mask){
						aclRule.ingress_wlanDevMask |= 1<<(shiftMask+j);
					}
				}
			}
			
			if(prule->ipport.sin_family == AF_INET)
			{
				struct in_addr *addr_v4 = (struct in_addr *)&(prule->ipport.start_addr);
				if(addr_v4->s_addr > 0)
				{
					aclRule.filter_fields |= INGRESS_IPV4_DIP_RANGE_BIT;
					aclRule.ingress_dest_ipv4_addr_start = ntohl(addr_v4->s_addr);

					addr_v4 = (struct in_addr *)&(prule->ipport.end_addr);
					aclRule.ingress_dest_ipv4_addr_end = ntohl(addr_v4->s_addr);
				}
				
				if(prule->ipport.start_port > 0)
				{
					aclRule.filter_fields |= INGRESS_L4_DPORT_RANGE_BIT;
					aclRule.ingress_dest_l4_port_start = prule->ipport.start_port;
					aclRule.ingress_dest_l4_port_end = prule->ipport.end_port;
				}
				
				if(prule->ipport.eth_protocol > 0)
				{
					aclRule.filter_fields |= INGRESS_ETHERTYPE_BIT;
					aclRule.ingress_ethertype = prule->ipport.eth_protocol;
					aclRule.ingress_ethertype_mask = 0xFFFF;
				}
			}

			if((ret = rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx)) == 0) {
				fprintf(fp, "%d\n", aclIdx);
			}
			else {
				printf("[%s@%d] rtk_rg_aclFilterAndQos_add QoS rule failed! (ret = %d)\n",__func__,__LINE__, ret);
			}
		}

		prule = prule->next;
	}
	
	fclose(fp);
	
	return 0;
}
#endif

#ifdef CONFIG_CT_AWIFI_JITUAN_SMARTWIFI

int RTK_RG_Wifidog_Rule_set()

{

	char wifidogenable=0,ret=0;

	MIB_CE_MBSSIB_T Entry;

	

	ret=wlan_getEntry(&Entry, 1);

	wifidogenable=!Entry.wlanDisabled;

	

	if(wifidogenable)

	{

		unsigned char sourceinterface;

		unsigned char lan1port,lan2port,lan3port,lan4port,ssid1port;

		char cmdStr[64];

		

		mib_get(AWIFI_LAN1_AUTH_ENABLE,&lan1port);

		mib_get(AWIFI_LAN2_AUTH_ENABLE,&lan2port);

		mib_get(AWIFI_LAN3_AUTH_ENABLE,&lan3port);

		mib_get(AWIFI_LAN4_AUTH_ENABLE,&lan4port);

		mib_get(AWIFI_WLAN1_AUTH_ENABLE,&ssid1port);

		

		sourceinterface=0x20;

		if(lan1port)

			sourceinterface|=0x01;

		if(lan2port)

			sourceinterface|=0x02;

		if(lan3port)

			sourceinterface|=0x04;

		if(lan4port)

			sourceinterface|=0x08;

		if(ssid1port)

			sourceinterface|=0x10;

				

		snprintf(cmdStr, sizeof(cmdStr),"/bin/echo %d > /proc/rg/wifidog_interface",sourceinterface);

		system(cmdStr);

		

		system("/bin/echo 1 > /proc/rg/wifidog_flag");

	}else{

		system("/bin/echo 0 > /proc/rg/wifidog_flag");

	}

}

#endif




#ifndef CONFIG_RTL9600_SERIES
void check_port_based_vlan_of_binding_bridge_inet_wan(void)
{
	int bridge_inet=0,i;
	int bvid=0, _itfGroup=0;
	int vcTotal=-1;
	unsigned short unbinded_portMask = 0;
	unsigned short enable = 0, tmp = 0;	
	MIB_CE_ATM_VC_T Entry;
	int vlan_id;

	RG_Flush_WIFI_UntagIn();

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
		if((Entry.applicationtype & X_CT_SRV_INTERNET) && (Entry.cmode == CHANNEL_MODE_BRIDGE) && !bridge_inet){
			if (Entry.vlan == 1) {
				bvid=Entry.vid;
			}else{
				mib_get(MIB_UNTAG_WAN_VLAN_ID, (void *)&vlan_id);
				bvid=vlan_id;
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

	if(bridge_inet){
		//RG_get_lan_phyPortId
		int i, lan_phy=0, ret, wlan_idx=0, pvid=0;
		unsigned int dev_idx=0;
//		for(i=0;i<SW_LAN_PORT_NUM;i++)
#if defined(WLAN_DUALBAND_CONCURRENT)
		for(i=0; i <=PMAP_WLAN1_VAP_END; i++)
#else
		for(i=0; i <=PMAP_WLAN0_VAP_END; i++)
#endif
		{
			if(!((_itfGroup >> i) & 1)){
				if(i <= PMAP_ETH0_SW3)
				{
					lan_phy = RG_get_lan_phyPortId(i);
	AUG_PRT("%s-%d lan_phy=%d bvid=%d\n",__func__,__LINE__,lan_phy,bvid);
					if(ret = rtk_rg_portBasedCVlanId_set(lan_phy,bvid)){
						printf("%s-%d rtk_rg_portBasedCVlanId_set error lan ret=%d port:%d, vid:%d\n",__func__,__LINE__,ret,lan_phy,bvid);
					}
					//setup vconfig to detag pvid, which would tag to CPU.
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
					//printf("\033[1;33;40m @@@@@@@@@@@@@@@@@########### %s:%d pvid %d dev_idx %d i %d \033[m\n", __FUNCTION__, __LINE__, pvid, dev_idx, i);
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
		RG_set_WIFI_UntagIn(bvid);
	}

}
#endif

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

int RTK_RG_VLAN_Binding_MC_DS_Rule_set(void)
#if 1
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

							memcpy(&aclRule.ingress_dmac,MCAST_ADDR_V6,MAC_ADDR_LEN);
							memcpy(&aclRule.ingress_dmac_mask,MCAST_MASK_V6,MAC_ADDR_LEN);
							if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0){
								fprintf(fp, "%d\n", aclIdx);
							}
							else
								printf("Set rtk_rg_aclFilterAndQos_add failed!\n");
						}
					}
#endif

					if(atmVcEntryBridgeWanIndx != -1) {
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
						aclRule.action_acl_cvlan.cvlanCpriDecision = 0;
						aclRule.action_acl_cvlan.assignedCvid = vid_pair[k].vid_a;
						aclRule.action_acl_cvlan.assignedCpri = 0;
						if(rtk_rg_aclFilterAndQos_add(&aclRule, &aclIdx) == 0){
							fprintf(fp, "%d\n", aclIdx);
						}
						else
							printf("Set rtk_rg_aclFilterAndQos_add failed!\n");
					}

					/* 9603C/9607C dose not need to transform ingress VLAN by ACL 
					   & modifying LAN CVLAN way
					   RG will learn ingress report automatically 
					   after proc: proc/rg/igmp_auto_learn_ctagif is enabled */
#if !defined(CONFIG_RTL9607C_SERIES)
					cvlan_info.vlanId = vid_pair[k].vid_a;
					if(rtk_rg_cvlan_get(&cvlan_info) == RT_ERR_RG_OK) {
						cvlan_info.memberPortMask.portmask |= (RG_get_wan_phyPortMask());
						cvlan_info.memberPortMask.portmask |= (1<<RG_get_lan_phyPortId(port_idx));
						cvlan_info.untagPortMask.portmask &= ~(RG_get_wan_phyPortMask());
						cvlan_info.untagPortMask.portmask &= ~(1<<RG_get_lan_phyPortId(port_idx));
						if(rtk_rg_cvlan_add(&cvlan_info)!= RT_ERR_RG_OK)
							printf("RG_add_lan_binding_vlan_member failed\n");
					}
#endif
				}
			}
		}
	}

	fclose(fp);
	return 0;
}
#else
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

int RG_update_default_route(void)
{
	rtk_rg_pppoeClientInfoAfterDial_t *pppoeClientInfoA=NULL;
	rtk_rg_ipDhcpClientInfo_t *dhcpClient_info=NULL;
	MIB_CE_ATM_VC_T vc_entry = {0};
	rtk_rg_intfInfo_t intf_info;
	unsigned int i,num;
	int ret, set;

	num = mib_chain_total(MIB_ATM_VC_TBL);
	for( i=0 ; i<num ; i++ )
	{
		if( !mib_chain_get(MIB_ATM_VC_TBL, i, (void*)&vc_entry))
			continue;

		if(!(vc_entry.IpProtocol & IPVER_IPV4))
			continue;

		if(!vc_entry.dgw || !vc_entry.cmode)
			set = 0;
		else
			set = 1;

		switch(vc_entry.cmode)
		{
			case CHANNEL_MODE_IPOE:
				if(vc_entry.ipDhcp==DHCP_CLIENT)
				{
					ret = rtk_rg_intfInfo_find(&intf_info, &vc_entry.rg_wan_idx);
					if(ret!=0){
						printf("Find RG interface for wan index %d Fail! Return -1!\n",vc_entry.rg_wan_idx);
						continue;
					}
					dhcpClient_info = &(intf_info.wan_intf.dhcp_client_info);
					dhcpClient_info->hw_info.ipv4_default_gateway_on = set;
					if(vc_entry.itfGroup && !(set))
						dhcpClient_info->hw_info.static_route_with_arp = 1;
					else
						dhcpClient_info->hw_info.static_route_with_arp = 0;					
					if(rtk_rg_dhcpClientInfo_set(vc_entry.rg_wan_idx, dhcpClient_info)==SUCCESS)
					{
						continue;
					}
				}
				else
				{
					if(RG_set_static(&vc_entry)==SUCCESS)
						continue;					
				}
				continue;
			case CHANNEL_MODE_PPPOE:
				ret = rtk_rg_intfInfo_find(&intf_info, &vc_entry.rg_wan_idx);
				if(ret!=0){
					printf("Find RG interface for wan index %d Fail! Return -1!\n",vc_entry.rg_wan_idx);
					continue;
				}
				pppoeClientInfoA = &(intf_info.wan_intf.pppoe_info.after_dial);
				pppoeClientInfoA->hw_info.ipv4_default_gateway_on = set;
				if((rtk_rg_pppoeClientInfoAfterDial_set(vc_entry.rg_wan_idx, pppoeClientInfoA))==SUCCESS){
					continue;
				}
		}
	}
	return 0;
}

int RG_update_default_route_v6(void)
{
	rtk_rg_ipStaticInfo_t *staticInfo=NULL;
	rtk_rg_ipDhcpClientInfo_t *dhcpClientInfo = NULL;
	rtk_rg_pppoeClientInfoAfterDial_t *pppoeClientInfoA=NULL;
	rtk_rg_ipDslitStaticInfo_t *dslite_info=NULL;
	rtk_rg_pppoeDsliteInfoAfterDial_t *pppoeClientiDslisteInfoA=NULL;
	MIB_CE_ATM_VC_T vc_entry = {0};
	rtk_rg_intfInfo_t intf_info;
	unsigned int i,num;
	int ret, set;

	num = mib_chain_total(MIB_ATM_VC_TBL);
	for( i=0 ; i<num ; i++ )
	{
		if( !mib_chain_get(MIB_ATM_VC_TBL, i, (void*)&vc_entry))
			continue;

		if(!(vc_entry.IpProtocol & IPVER_IPV6))
			continue;

		if(!vc_entry.dgw || !vc_entry.cmode)
			set = 0;
		else
			set = 1;

		ret = rtk_rg_intfInfo_find(&intf_info, &vc_entry.rg_wan_idx);
		if((ret==0) && intf_info.is_wan){
			switch(intf_info.wan_intf.wan_intf_conf.wan_type)
			{
				case RTK_RG_STATIC:
					printf("[%s] Update IPv6 WAN dgw part to wan type RTK_RG_STATIC\n",__func__);
					staticInfo = &(intf_info.wan_intf.static_info);
					staticInfo->ipv6_default_gateway_on = set;
					ret = rtk_rg_staticInfo_set(vc_entry.rg_wan_idx, staticInfo);
					printf("[%s] update ret=%d\n",__func__,ret);
					break;
				case RTK_RG_DHCP:
					printf("[%s] Update IPv6 WAN dgw part to wan type RTK_RG_DHCP\n",__func__);
					dhcpClientInfo = &(intf_info.wan_intf.dhcp_client_info);
					dhcpClientInfo->hw_info.ipv6_default_gateway_on = set;
					ret = rtk_rg_dhcpClientInfo_set(vc_entry.rg_wan_idx, dhcpClientInfo);
					printf("[%s] update ret=%d\n",__func__,ret);
					break;
				case RTK_RG_PPPoE:
					printf("[%s] Update IPv6 WAN dgw part to wan type RTK_RG_PPPoE\n",__func__);
					pppoeClientInfoA = &(intf_info.wan_intf.pppoe_info.after_dial);
					pppoeClientInfoA->hw_info.ipv6_default_gateway_on = set;
					ret = rtk_rg_pppoeClientInfoAfterDial_set(vc_entry.rg_wan_idx, pppoeClientInfoA);
					printf("[%s] update ret=%d\n",__func__,ret);
					break;
#if defined(CONFIG_IPV6) && defined(DUAL_STACK_LITE)
				case RTK_RG_DSLITE:
					printf("[%s] Update IPv6 WAN dgw part to wan type RTK_RG_DSLITE\n",__func__);
					dslite_info = &(intf_info.wan_intf.dslite_info);
					dslite_info->static_info.ipv4_default_gateway_on = set;
					dslite_info->static_info.ipv6_default_gateway_on = set;
					ret = rtk_rg_dsliteInfo_set(vc_entry.rg_wan_idx, dslite_info);
					printf("[%s] update ret=%d\n",__func__,ret);
					break;
				case RTK_RG_PPPoE_DSLITE:
					printf("[%s] Update IPv6 WAN dgw part to wan type RTK_RG_PPPoE_DSLITE\n",__func__);
					pppoeClientiDslisteInfoA = &(intf_info.wan_intf.pppoe_dslite_info.after_dial);
					pppoeClientiDslisteInfoA->dslite_hw_info.static_info.ipv4_default_gateway_on = set;
					pppoeClientiDslisteInfoA->dslite_hw_info.static_info.ipv6_default_gateway_on = set;
					ret = rtk_rg_pppoeDsliteInfoAfterDial_set(vc_entry.rg_wan_idx, pppoeClientiDslisteInfoA);
					printf("[%s] update ret=%d\n",__func__,ret);
					break;
#endif
				default:
					break;
			}
		}
	}
	return 0;
}

int RG_get_wan_interface_packet_status(int rg_wan_idx, 
								unsigned int *rxPkts, unsigned long long int *rxBytes, 
								unsigned int *txPkts, unsigned long long int *txBytes,
								unsigned int *rxMcPkts, unsigned long long int *rxMcBytes, 
								unsigned int *txMcPkts, unsigned long long int *txMcBytes,
								unsigned int *rxBcPkts, unsigned long long int *rxBcBytes, 
								unsigned int *txBcPkts, unsigned long long int *txBcBytes)
{
#if defined(CONFIG_RTL9600_SERIES)
	rtk_rg_port_mib_info_t portmib;
	int wanPhyPort = RG_get_wan_phyPortId();
	if((wanPhyPort <= -1) || (rtk_rg_portMibInfo_get(wanPhyPort,&portmib) != RT_ERR_OK))
	{
		DBPRINT(1, "%s rtk_rg_portMibInfo_get idx[%d] failed!\n", __FUNCTION__, rg_wan_idx);
		return -1;
	}
	
	if(rxPkts) 		*rxPkts 	= portmib.ifInUcastPkts;
	if(rxBytes) 	*rxBytes 	= portmib.ifInOctets;
	if(txPkts) 		*txPkts 	= portmib.ifOutUcastPkts;
	if(txBytes) 	*txBytes 	= portmib.ifOutOctets;

	if(rxMcPkts) 	*rxMcPkts 	= portmib.ifInMulticastPkts;
	if(rxMcBytes) 	*rxMcBytes 	= 0;
	if(txMcPkts) 	*txMcPkts 	= portmib.ifOutMulticastPkts;
	if(txMcBytes) 	*txMcBytes 	= 0;

	if(rxBcPkts) 	*rxBcPkts 	= portmib.ifInBroadcastPkts;
	if(rxBcBytes) 	*rxBcBytes 	= 0;
	if(txBcPkts) 	*txBcPkts 	= portmib.ifInBroadcastPkts;
	if(txBcBytes) 	*txBcBytes 	= 0; 
	
#else
	rtk_rg_netifMib_entry_t netifMib;
	netifMib.netifIdx = rg_wan_idx;
	if(rtk_rg_interfaceMibCounter_get(&netifMib) != RT_ERR_OK)
	{
		DBPRINT(1, "%s rtk_rg_interfaceMibCounter_get idx[%d] failed!\n", __FUNCTION__, rg_wan_idx);
		return -1;
	}
	if(rxPkts) 		*rxPkts 	= netifMib.in_intf_uc_packet_cnt;
	if(rxBytes) 	*rxBytes 	= netifMib.in_intf_uc_byte_cnt;
	if(txPkts) 		*txPkts 	= netifMib.out_intf_uc_packet_cnt;
	if(txBytes) 	*txBytes 	= netifMib.out_intf_uc_byte_cnt;
	
	if(rxMcPkts) 	*rxMcPkts 	= netifMib.in_intf_mc_packet_cnt;
	if(rxMcBytes) 	*rxMcBytes 	= netifMib.in_intf_mc_byte_cnt;
	if(txMcPkts) 	*txMcPkts 	= netifMib.out_intf_mc_packet_cnt;
	if(txMcBytes) 	*txMcBytes 	= netifMib.out_intf_mc_byte_cnt;
	
	if(rxBcPkts) 	*rxBcPkts 	= netifMib.in_intf_bc_packet_cnt;
	if(rxBcBytes) 	*rxBcBytes 	= netifMib.in_intf_bc_byte_cnt;
	if(txBcPkts) 	*txBcPkts 	= netifMib.out_intf_bc_packet_cnt;
	if(txBcBytes) 	*txBcBytes 	= netifMib.out_intf_bc_byte_cnt; 
	
#endif

	return 0;
}

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
	return 0;
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
		
	if(!isIgmproxyEnabled())
		return -1;

	if(isIGMPSnoopingEnabled())
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
	return 0;
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

int RTK_RG_Flush_IGMP_proxy_ACL_rule(void)
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

int RTK_RG_set_IGMP_proxy_ACL_rule(void)
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

int RTK_RG_Flush_MLD_proxy_ACL_rule(void)
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
	
	fclose(fp);
}


