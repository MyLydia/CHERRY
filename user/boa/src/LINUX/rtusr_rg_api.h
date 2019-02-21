#include "options.h"
#include "mib.h"

#define UntagCPort 1
#define TagCPort 0

#define BridgeWan 0
#define RoutingWan 1

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#ifndef SUCCESS
#define SUCCESS 0
#endif

#ifndef FAIL
#define FAIL -1
#endif

//ccwei: for debug
#define NIP_QUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]

int flush_rg_acl_rule_for_VPN_policy_route(void);
int add_rg_acl_rule_for_VPN_policy_route(void);


#if defined(CONFIG_RTK_L34_ENABLE) || defined(CONFIG_GPON_FEATURE)
int RTK_RG_Sync_OMCI_WAN_INFO(void);
#endif
int RG_add_wan(MIB_CE_ATM_VC_Tp entry, int mib_vc_idx);
int Init_RG_API(int isUnTagCPort);

int RG_set_static(MIB_CE_ATM_VC_Tp entry);
int RG_release_static(int wanIntfIdx);
int RG_set_dhcp(unsigned int ipaddr, unsigned int submsk, MIB_CE_ATM_VC_Tp entry);
int RG_release_dhcp(int wanIntfIdx);

int RG_release_pppoe(MIB_CE_ATM_VC_Tp vcEntry);
#ifdef CONFIG_IPV6
int RG_release_dslite_pppoev6(MIB_CE_ATM_VC_Tp vcEntry);
int RG_release_pppoev6(MIB_CE_ATM_VC_Tp vcEntry);
#endif

int RG_Del_All_LAN_Interfaces();
int RG_WAN_Interface_Del(unsigned int);
//#ifdef CONFIG_MCAST_VLAN
int RTK_RG_ACL_Add_mVlan(void);
int RTK_RG_ACL_Flush_mVlan(void);
//#endif
#ifdef CONFIG_00R0//iulian added cvlan for multicast 
int RG_WAN_CVLAN_DEL(int vlanID);
int RG_WAN_cvlan();
int RG_set_policy_route(char* ifname_wan);
#endif

#ifdef MAC_FILTER
int AddRTK_RG_MAC_Filter(MIB_CE_MAC_FILTER_T *, int);
int RTK_RG_MAC_Filter_Default_Policy(int out_policy);
int FlushRTK_RG_MAC_Filters_in_ACL();
int FlushRTK_RG_MAC_Filters();
#endif
#ifdef IP_PORT_FILTER
int AddRTK_RG_ACL_IPPort_Filter(MIB_CE_IP_PORT_FILTER_T *);
#endif
int RTK_RG_ACL_IPPort_Filter_Default_Policy(int out_policy);
int RTK_RG_ACL_IPPort_Filter_Allow_LAN_to_GW();
int FlushRTK_RG_ACL_Filters();
#ifdef CONFIG_IPV6
int AddRTK_RG_ACL_IPv6Port_Filter(MIB_CE_V6_IP_PORT_FILTER_T *, char * prefixIP);
int RTK_RG_ACL_IPv6Port_Filter_Default_Policy(int out_policy);
int FlushRTK_RG_ACL_IPv6Port_Filters();
#endif
int RTK_RG_DMZ_Set(int enabled, in_addr_t ip_addr);
#ifdef PORT_FORWARD_GENERAL
int RTK_RG_Vertual_Server_Set(MIB_CE_PORT_FW_T *pf);
#endif
#ifdef CONFIG_USER_IP_QOS_3
int RTK_RG_QoS_Queue_Set();
int RTK_RG_QoS_Queue_Remove();
int RTK_RG_QoS_Rule_Set(MIB_CE_IP_QOS_Tp);
#endif
#ifdef CONFIG_USER_MINIUPNPD
int AddRTK_RG_UPnP_Connection(unsigned short, const char *, unsigned short, int);
int DelRTK_RG_UPnP_Connection(unsigned short, int);
#endif
#ifdef URL_BLOCKING_SUPPORT
int RTK_RG_URL_Filter_Set();
int Flush_RTK_RG_URL_Filter();
#endif
#if 0
int callbackRegistCheck(void);
#endif
int Init_rg_api(void);
int RG_del_All_Acl_Rules(void);
int RG_add_default_Acl_Qos(void);
#ifdef ROUTING
#ifdef CONFIG_00R0 //iulian added 
int RG_add_static_route_by_acl(in_addr_t  ip_addr, in_addr_t netmask, in_addr_t gateway, int rg_wan_idx);
int RG_del_static_route_by_acl(int rg_wan_idx);
int	RG_add_IPQos_WorkAround();
int	RG_del_IPQos_WorkAround();
#endif
#ifdef CONFIG_00R0
int RTK_RG_CWMP_1P_ADD(in_addr_t ip_addr, int priority);
int RTK_RG_CWMP_1P_DEL();
#endif
int RG_add_static_route(MIB_CE_IP_ROUTE_T *entry, char *mac_str, int entryID);
int RG_add_static_route_PPP(MIB_CE_IP_ROUTE_T *entry,MIB_CE_ATM_VC_T *vc_entry,int entryID);
#endif
int RG_reset_LAN(void);
int RG_check_Droute(int configAll, MIB_CE_ATM_VC_Tp pEntry, int *EntryID);
#ifdef DOS_SUPPORT
int RTK_RG_DoS_Set(int enable);
#endif
int Check_RG_Intf_Count(void);
int RG_get_lan_phyPortId(int logPortId);
int RG_get_wan_phyPortId();
#ifdef CONFIG_USER_PPTP_CLIENT_PPTP
int RG_add_pptp_wan(MIB_PPTP_T *pentry, int mib_pptp_idx);
int RG_add_pptp( unsigned long gw_ip, unsigned long my_ip, MIB_PPTP_T *pentry);
#endif
#ifdef CONFIG_USER_L2TPD_L2TPD
int RG_add_l2tp_wan(MIB_L2TP_T *pentry, int mib_l2tp_idx);
int RG_add_l2tp(unsigned long gw_ip, unsigned long my_ip, MIB_L2TP_T *pentry);
#endif
#if (defined(CONFIG_00R0) && defined(CONFIG_USER_BRIDGE_GROUPING)) || defined(CONFIG_RTL867X_VLAN_MAPPING)
int RG_add_vlanBinding(MIB_CE_ATM_VC_Tp pEntry, int pairID, unsigned short LanVid, int LanPortIdx);
int RG_flush_vlanBinding(int LanPortIdx);
#endif
unsigned int RG_get_portCounter(unsigned int portIndex,unsigned long *tx_pkts,unsigned long *tx_drops,unsigned long *tx_errs,
										unsigned long *rx_pkts,unsigned long *rx_drops,unsigned long *rx_errs);
void RTK_RG_gatewayService_add();
void Flush_RTK_RG_gatewayService();
#ifdef CONFIG_RTL9600_SERIES
void trap_pppoe(int trap_action, int wan_ifIndex, char * ifname, unsigned char proto);
#endif

#if defined(CONFIG_E8B)
#ifdef CONFIG_IPV6
int RTK_RG_ACL_Add_DHCP_WAN_IPV6(int wan_idx, unsigned char *ipaddr);
int RTK_RG_ACL_Del_DHCP_WAN_IPV6(int wan_idx);
#endif
#endif

#if defined(CONFIG_00R0) && defined (CONFIG_USER_RTK_VOIP)
int RG_add_voip_sip_1p_Qos(int sip_port,int pri_num);
int RG_add_voip_rtp_1p_Qos(int start_port,int end_port,int pri_num);

int RG_del_voip_sip_1p_Acl();
int RG_del_voip_rtp_1p_Acl();
#endif

#if defined(CONFIG_RTL9607C_SERIES) || defined(CONFIG_LUNA_G3_SERIES)
void RTK_RG_Control_Packet_Ingress_ACL_Rule_set(void);
void RTK_RG_Control_Packet_Egress_ACL_Rule_set(void);
void RTK_RG_Control_Packet_ITMS_Ingress_ACL_Rule_flush(void);
void RTK_RG_Control_Packet_ITMS_Ingress_ACL_Rule_set(void);
void RTK_RG_Control_Packet_ITMS_Egress_ACL_Rule_flush(void);
void RTK_RG_Control_Packet_ITMS_Egress_ACL_Rule_set(void);
void RTK_RG_add_TCP_syn_rate_limit( void );
void RTK_RG_add_ARP_broadcast_rate_limit( void );
#endif

int RTK_RG_multicastFlow_add(unsigned int group, int *index);
int RTK_RG_multicastFlow_delete(int index);
int RTK_RG_multicastFlow_reset(void);
int RTK_RG_multicastFlow_flush(void);

int RTK_RG_Ipv6_multicastFlow_add(unsigned int *group, int *index);
int RTK_RG_Ipv6_multicastFlow_delete(int index);
int RTK_RG_Ipv6_multicastFlow_reset(void);
int RTK_RG_Ipv6_multicastFlow_flush(void);

#if defined(CONFIG_SECONDARY_IP)
int RG_set_ip_alias(char *ifname, int ipver, int set);
#endif
#ifdef CONFIG_RTL867X_VLAN_MAPPING
int RTK_RG_VLAN_Binding_MC_DS_Rule_flush(void);
int RTK_RG_VLAN_Binding_MC_DS_Rule_set(int mode);
int RTK_RG_VLAN_Binding_MC_DS_Rule_Config(int mode);
#endif
#ifdef WLAN_UNIVERSAL_REPEATER
int rtk_wlan_rg_vxd_setup_rules(int wlanIdx, int add);
#endif

