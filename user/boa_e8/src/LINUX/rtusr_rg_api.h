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

extern int rtk_rg_aclFilterAndQos_del(int acl_filter_idx);

//extern int patch_for_avalanche;
//ccwei: for debug
#define NIP_QUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]
int add_rg_acl_rule_for_VPN_policy_route(void);
int flush_rg_acl_rule_for_VPN_policy_route(void);
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
int RG_Flush_Handle_Priority_Tag0_ACL_FILE(void);
int RG_Handle_Priority_Tag0_By_Port(void);
#endif

#ifdef CONFIG_CTC_E8_CLIENT_LIMIT
int RTK_RG_AccessWanLimit_Set(void);
int RTK_RG_disable_AccessWanLimit(void);
int RTK_RG_AccessWanLimitCategory_Set(unsigned char *mac, int category);
#endif
#ifdef CONFIG_EPON_FEATURE
/* EPON mode:for untag packets from lan port, add bridge vlan tag when egress to pon port */
int RTK_RG_Set_ACL_Bridge_from_Lan(void);
int Flush_RTK_RG_Bridge_from_Lan_ACL(void);
#endif

int reset_unbinded_port_vlan(MIB_CE_ATM_VC_T *vcEntry);

int RTK_RG_Sync_OMCI_WAN_INFO(int SyncALL);
int RTK_RG_USER_APP_ACL_Rule_Flush(void);
int RTK_RG_USER_APP_ACL_Rule_Set(void);

int Flush_RTK_RG_IPv4_IPv6_Vid_Binding_ACL(void);
int RTK_RG_Set_IPv4_IPv6_Vid_Binding_ACL(void);

int RTK_RG_FLUSH_Bridge_DHCP_ACL_FILE(void);
int RTK_RG_Set_ACL_Bridge_DHCP_Filter(void);

int RG_add_wan(MIB_CE_ATM_VC_Tp entry, int mib_vc_idx);
int Init_RG_API(int isUnTagCPort);

int RG_set_static(MIB_CE_ATM_VC_Tp entry);
int RG_release_static(int wanIntfIdx);

int RG_add_dhcp_wan_trap_rule(unsigned int ipaddr, char *ifname);
int RG_del_dhcp_wan_trap_rule(char *ifname);
int RG_set_dhcp(unsigned int ipaddr, unsigned int submsk, MIB_CE_ATM_VC_Tp entry);
int RG_release_dhcp(int wanIntfIdx);

int RG_release_pppoe(MIB_CE_ATM_VC_Tp vcEntry);
#ifdef CONFIG_IPV6
int RG_release_dslite_pppoev6(MIB_CE_ATM_VC_Tp vcEntry);
int RG_release_pppoev6(MIB_CE_ATM_VC_Tp vcEntry);
#endif

int RG_Del_All_LAN_Interfaces();
int RG_WAN_Interface_Del(unsigned int);
#ifdef CONFIG_MCAST_VLAN
int RTK_RG_ACL_Add_mVlan(void);
int RTK_RG_ACL_Flush_mVlan(void);
#endif
int RTK_RG_Add_MVLAN_ACL(MIB_CE_ATM_VC_T *pEntry);
int RTK_RG_FLUSH_MVLAN_ACL(int wan_idx);

#ifdef CONFIG_USER_MINIUPNPD
int FLUSH_RTK_RG_UPnP_Entry(void);
#endif
#ifdef CONFIG_USER_L2TPD_L2TPD
int RG_Flush_L2TP_Route_All(void);
int RG_Flush_L2TP_Route(unsigned char *tunnelName, unsigned char rule_type);
int RG_Set_L2TP_Dynamic_URL_Route(char *name, struct in_addr addr);
int RG_Flush_L2TP_Dynamic_URL_Route(unsigned char *tunnelName);
int Static_L2TP_ACL_Policy_Route_Remove(unsigned char *if_name);
#endif
#ifdef CONFIG_RG_BRIDGE_PPP_STATUS
int AddRTK_RG_Bridge_PPPSession_Filter();
#endif
#ifdef MAC_FILTER
int AddRTK_RG_MAC_Filter(MIB_CE_MAC_FILTER_T *);
int RTK_RG_MAC_Filter_Default_Policy(int out_policy, int in_policy);
int FlushRTK_RG_MAC_Filters();
#endif
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
int AddRTK_RG_ACL_IPPort_Filter(MIB_CE_IP_PORT_FILTER_T *ipEntry, unsigned char in_action, unsigned char out_action);
#else
int AddRTK_RG_ACL_IPPort_Filter(MIB_CE_IP_PORT_FILTER_T *ipEntry);
#endif
int RTK_RG_ACL_IPPort_Filter_Default_Policy(int out_policy, int in_policy);
int RTK_RG_ACL_IPPort_Filter_Allow_LAN_to_GW();
int FlushRTK_RG_ACL_Filters();
#ifdef CONFIG_IPV6
//int AddRTK_RG_ACL_IPv6Port_Filter(MIB_CE_V6_IP_PORT_FILTER_T *, char * prefixIP);
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
int AddRTK_RG_ACL_IPPort_Filter_IPv6(MIB_CE_IP_PORT_FILTER_T *ipEntry, unsigned char in_action, unsigned char out_action);
#else
int AddRTK_RG_ACL_IPPort_Filter_IPv6(MIB_CE_IP_PORT_FILTER_T *ipEntry);
#endif
int RTK_RG_ACL_IPv6Port_Filter_Default_Policy(int out_policy, int in_policy);
int FlushRTK_RG_ACL_IPv6Port_Filters();
#endif
int RTK_RG_ALG_SRV_in_Lan_Set(void);
int RTK_RG_DMZ_Set(int enabled, in_addr_t ip_addr, int isBoot);
#ifdef PORT_FORWARD_GENERAL
int RTK_RG_Vertual_Server_Set(MIB_CE_PORT_FW_T *pf);
#endif
#ifdef VIRTUAL_SERVER_SUPPORT
int RTK_RG_Virtual_Server_Set(MIB_VIRTUAL_SVR_T *pf);
int FlushRTK_RG_Virtual_Server();
#endif
#ifdef CONFIG_TR142_MODULE
void set_wan_ponmac_qos_queue_num(void);
#endif
#ifdef CONFIG_USER_IP_QOS_3
int RTK_RG_QoS_Queue_Set();
int RTK_RG_QoS_Queue_Remove();
int RTK_RG_QoS_Rule_Set(MIB_CE_IP_QOS_Tp qos_entry);
int FlushRTK_RG_QoS_Rules_perWan(int wan_idx);
#endif
#if defined(CONFIG_USER_PPPOE_PROXY)
int RTK_RG_PPPoEProxy_ACL_Rule_Set(MIB_CE_ATM_VC_Tp pentry);
int RTK_RG_PPPoEProxy_ACL_Rule_Flush();
#endif
#ifdef CONFIG_USER_MINIUPNPD
int AddRTK_RG_UPnP_Connection(unsigned short, const char *, unsigned short, int);
int DelRTK_RG_UPnP_Connection(unsigned short, int);
#endif
#ifdef URL_BLOCKING_SUPPORT
int RTK_RG_URL_Filter_Set();
int RTK_RG_URL_Filter_Set_By_Key(int);
int Flush_RTK_RG_URL_Filter();
#endif

#ifdef _PRMT_X_CMCC_SECURITY_
int RTK_RG_ParentalCtrl_MAC_Policy_Set(unsigned char *mac, int mode, char *url);
#endif

#if 0
int callbackRegistCheck(void);
#endif
int Init_rg_api(void);
int RTK_RG_DoS_Set(int enable);
int RG_del_All_Acl_Rules(void);
int RG_add_default_Acl_Qos(void);
int RG_add_PPPoE_RB_passthrough_Acl(void);
int RG_del_PPPoE_Acl(void);
int RG_add_pppoe(unsigned short session_id, unsigned int gw_ip, unsigned int my_ip, unsigned char* gw_mac, MIB_CE_ATM_VC_T *vcEntry);

int RG_add_static_route(MIB_CE_IP_ROUTE_T *entry, int entryID);
#ifdef CONFIG_IPV6
int RG_add_static_route_v6(MIB_CE_IPV6_ROUTE_T *entry, int entryID);
#endif
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
int RG_add_policy_route_by_acl(int rg_wan_idx, int ip_ver, char *ip_start, char *ip_end, char *gateway);
int RG_del_policy_route_by_acl(int acl_idx);
#endif
#ifdef _PRMT_X_CT_COM_WANEXT_
int RG_add_static_route_by_acl(int rg_wan_idx, int ip_ver, char *ip_start, char *ip_end, char *gateway);
int RG_del_static_route_by_acl(int rg_wan_idx);
#endif
int RG_reset_LAN(void);
int RG_check_Droute(int configAll, MIB_CE_ATM_VC_Tp pEntry, int *EntryID);
int Check_RG_Intf_Count(void);
int RG_flush_vlanBinding(int LanPortIdx);
int RG_flush_vlanBinding_by_WanVID(int vid);
int RG_add_vlanBinding(MIB_CE_ATM_VC_Tp pEntry,int pairID, unsigned short LanVid, int LanPortIdx);
int check_cvlan_group_before_add_vlan_binding(void);
int RG_get_lan_phyPortId(int logPortId);
int RG_get_lan_logPortId(int phyPortId);
int RG_get_lan_phyPortId_mapping(int phyPortId_arr[], int size);
int RG_get_wan_phyPortId();
#ifdef CONFIG_USER_PPTP_CLIENT_PPTP
int RG_add_pptp_wan(MIB_PPTP_T *pentry, int mib_pptp_idx);
int RG_add_pptp( unsigned long gw_ip, unsigned long my_ip, MIB_PPTP_T *pentry);
#endif
#ifdef CONFIG_USER_L2TPD_L2TPD
int RG_add_l2tp_wan(MIB_L2TP_T *pentry, int mib_l2tp_idx);
int RG_add_l2tp(unsigned long gw_ip, unsigned long my_ip, MIB_L2TP_T *pentry);
#endif
unsigned int RG_get_portCounter(unsigned int portIndex, unsigned long long *tx_bytes,unsigned long *tx_pkts,unsigned long *tx_drops,unsigned long *tx_errs,
										unsigned long long *rx_bytes, unsigned long *rx_pkts,unsigned long *rx_drops,unsigned long *rx_errs);
void RTK_RG_gatewayService_add();
void Flush_RTK_RG_gatewayService();
void RG_tcp_stateful_tracking(int enable);

int RG_get_MAC_list_by_interface(unsigned int portIndex, char *mac_list);
int RG_del_LUT_MAC(char *del_mac);

#ifdef SUPPORT_WAN_BANDWIDTH_INFO
int RG_get_interface_counter(int rg_wan_idx, unsigned long long * uploadcnt, unsigned long long * downloadcnt);
#endif

#ifdef SUPPORT_WEB_REDIRECT
int RG_set_redirect_http_Count(int enable, char * httpContent, int size, int count);
int RG_set_redirect_http_all(int enable, char * httpContent, int size, int count);
int RG_set_welcome_redirect(int enable, char * url);
int RG_add_redirectHttpURL(MIB_REDIRECT_URL_LIST_T * redirectUrl);
int RG_del_redirectHttpURL(MIB_REDIRECT_URL_LIST_T * redirectUrl);
int RG_add_redirectWhiteUrl(MIB_REDIRECT_WHITE_LIST_T * whiteUrl);
int RG_del_redirectWhiteUrl(MIB_REDIRECT_WHITE_LIST_T * whiteUrl);
#endif

#ifdef SUPPORT_MCAST_TEST
int RG_get_WanPortBindingMask(int rg_wan_idx, int *portbindingmask);
int RG_get_MulticastFlow(int *valid_idx, int *portmask);

#ifdef CONFIG_RTL9600_SERIES
void trap_pppoe(int trap_action, int wan_ifIndex, char * ifname, unsigned char proto);
#endif
#endif

#ifdef CONFIG_IPV6
int RTK_RG_ACL_Add_DHCP_WAN_IPV6(int wan_idx, unsigned char *ipaddr);
int RTK_RG_ACL_Del_DHCP_WAN_IPV6(int wan_idx);
#endif

#ifdef _PRMT_X_CT_COM_LANBINDING_CONFIG_
int RTK_RG_acl_Add_Lan_Binding(char *MacAddr);
int RTK_RG_del_Lan_Binding_Acl(void);
int add_lan_binding_acl(void);
#endif
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
int RTK_RG_ACL_ADD_TRAFFIC_MONITOR(MIB_CMCC_TRAFFICMONITOR_RULE_Tp entry, int *naptIdx);
int RTK_RG_ACL_DEL_TRAFFIC_MONITOR(int naptIdx);
int RTK_RG_ACL_MOD_TRAFFIC_MONITOR(char *url,  struct in_addr addr);
#endif
int RG_set_CPU_port_egress_bandwidth_control(unsigned int rate);
#ifdef  CONFIG_CMCC_TRAFFIC_PROCESS_RULE_SUPPORT
int RTK_RG_ACL_Add_Cmcc_Traffic_Process_Rule(MIB_CMCC_TRAFFIC_PROCESS_RULE_T *entry);
int RTK_RG_ACL_Del_Cmcc_Traffic_Process_Rule(int index0, int index1);
int RTK_RG_Flush_Cmcc_Traffic_Process_Rule(void);
int RTK_RG_BridgeType_ACL_Rule_Set(MIB_CE_ATM_VC_Tp pentry);
int RTK_RG_BridgeType_ACL_Rule_Flush(int rg_wan_idx);

#endif
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
#define RG_SHAREMETER_UNLIMITED_SPEED (0x1ffff*8)
#endif

#ifdef CONFIG_CMCC_FORWARD_RULE_SUPPORT
void _add_tf_rule_into_nfhook(MIB_CMCC_TRAFFIC_PROCESS_RULE_Tp rule);
void _del_tf_rule_from_nfhook(int index);
int AddRTK_RG_ACL_CmccForwardRule(MIB_CMCC_FORWARD_RULE_T *entry, int type);
int delRTK_RG_ACL_CmccForwardRule(int index);
int FlushRTK_RG_CmccForwardRule();
int AddRTK_RG_ACL_CmccForwardRule_URL(char*domainName, char* addr);
#endif

int AddRTK_RG_ACL_CmccMirrorRule_URL(char*domainName, char* addr);
int AddRTK_RG_ACL_Bridge_IPv4IPv6_Filters( MIB_CE_ATM_VC_Tp pEntry );
int AddRTK_RG_BG_MAC_Filter(MIB_CE_BRGMAC_T *MacEntry, unsigned char *smac, unsigned char *dmac, unsigned char macFilterMode, int ethertype);
int AddRTK_RG_RT_INTERNET_ACCESS_RIGHT(unsigned char  internetAccessRight, unsigned char *smac);
#if defined(CONFIG_USER_L2TPD_L2TPD) &&  defined(CONFIG_USER_PPTP_CLIENT_PPTP)
int Check_ACL_With_IP(VPN_TYPE_T vpn_type, struct in_addr addr, char *tunnelName);
int Check_NAPT_With_IP(VPN_TYPE_T vpn_type, struct in_addr addr, char *tunnelName);
int Get_Packet_Count_By_Route_Index(VPN_TYPE_T vpn_type, unsigned int index);
int is_vpn_tunnel_encypted(VPN_TYPE_T vpn_type, char *tunnel_name);
int RG_Set_L2TP_Acl_Policy_Route(unsigned char *tunnelName, ATTACH_MODE_T attach_mode);
int RG_Set_PPTP_Acl_Policy_Route(unsigned char *tunnelName, ATTACH_MODE_T attach_mode);
void save_vpn_packet_count(VPN_TYPE_T vpn_type, unsigned int route_idx, unsigned long ip, unsigned int packet_count);
int Dynamic_VPN_ACL_Policy_Route_Update(VPN_TYPE_T vpn_type, unsigned char *if_name, unsigned char to_default);
int VPN_NAPT_Rule_Update(VPN_TYPE_T vpn_type, unsigned char *if_name, unsigned char to_default, unsigned char type);
#endif
int clean_special_handle_RTP(void);
int FlushRTK_RG_ACL_Bridge_IPv4IPv6_Filters( MIB_CE_ATM_VC_Tp pEntry );
int Flush_RTK_RG_ACL_MAC_Filters(void);
int FlushRTK_RG_QoS_Rules(void);
int FlushRTK_RG_RT_INTERNET_ACCESS_RIGHT(void);
int FlushRTK_RG_Vertual_Server(void);
int Init_RG_ELan(int isUnTagCPort, int isRoutingWan);
int RG_del_All_default_Acl(void);
int RG_del_static_route(MIB_CE_IP_ROUTE_T *entry, int entry_idx);
int RG_del_static_route_v6(MIB_CE_IPV6_ROUTE_T *entry, int entryID);
int RG_Del_WanVPN_QoS(unsigned int acl_idx);
int rg_eth2wire_block(int enable);
int RG_Flush_PPTP_Dynamic_URL_Route(unsigned char *tunnelName);
int RG_Flush_PPTP_Route_All(void);
int RG_Flush_PPTP_Route(unsigned char *tunnelName);
#ifdef WLAN_SUPPORT
int RG_get_wlan_phyPortId(int logPortId);
#endif
int RG_Preset_L2TP_Napt_Rule( void );
int RG_Preset_PPTP_Napt_Rule( void );
int RG_release_l2tp(int wanIntfIdx);
int RG_set_http_trap_for_bridge(int enable);
int RG_Set_WanVPN_QoS(int vpn_type);
int RG_WAN_CVLAN_DEL(int vlanID);
int RTK_RG_ALG_Set(void);
#ifdef _PRMT_X_CT_COM_DATA_SPEED_LIMIT_
int RTK_RG_data_speed_limit_if_set(int dir, int sm_offset, MIB_CE_DATA_SPEED_LIMIT_IF_Tp entry);
int RTK_RG_data_speed_limit_ip_set(int dir, int sm_offset, MIB_CE_DATA_SPEED_LIMIT_IP_Tp entry);
int RTK_RG_data_speed_limit_vlan_set(int dir, int sm_offset, MIB_CE_DATA_SPEED_LIMIT_VLAN_Tp entry);
#else
int RTK_RG_QoS_Car_Rule_Set(MIB_CE_IP_TC_Tp qos_entry);
#endif
int RTK_RG_FLUSH_ALG_FILTER_RULE(void);
int RTK_RG_FLUSH_DOS_FILTER_RULE(void);
int RTK_RG_QoS_TotalBandwidth_Set(int TotalBandwidthKbps);
int RTK_RG_Set_ACL_IPV4_Bridge_from_Wan(MIB_CE_ATM_VC_Tp entry);
int RTK_RG_Set_ACL_IPV4_PPPoE_from_Wan_KeepOVID(MIB_CE_ATM_VC_Tp entry);
int RTK_RG_Set_ACL_IPV4V6_Bridge_from_Wan(MIB_CE_ATM_VC_Tp entry);
int RTK_RG_Set_ACL_IPV6_Bridge_from_Wan(MIB_CE_ATM_VC_Tp entry);
int RTK_RG_Set_ACL_IPV6_PPPoE_from_Wan_KeepOVID(MIB_CE_ATM_VC_Tp entry);
void RTK_RG_add_acl_rule_for_v6_icmp(void);
void RTK_RG_del_acl_rule_for_v6_icmp(void);
int RTK_RG_VLAN_Binding_MC_DS_Rule_flush(void);
int RTK_RG_VLAN_Binding_MC_DS_Rule_set(void);
int RG_update_default_route(void);
int RG_update_default_route_v6(void);

#if defined(CONFIG_USER_LAN_BANDWIDTH_CONTROL) && (defined(CONFIG_RTL9607C_SERIES) || defined(CONFIG_LUNA_G3_SERIES))
void RG_update_lan_bandwidth_control_debug_info(int dir);
int RG_set_port_ingress_bandwidth_control(unsigned char *mac, unsigned int rate);
int RG_set_port_egress_bandwidth_control(unsigned char *mac, unsigned int rate);
#else
int RG_set_port_ingress_bandwidth_control(int port, unsigned int rate);
int RG_set_port_egress_bandwidth_control(int port, unsigned int rate);
#endif

#if defined(CONFIG_USER_LANNETINFO) && (defined(CONFIG_RTL9607C_SERIES) || defined(CONFIG_LUNA_G3_SERIES)) 
void RG_update_lan_hpc_for_mib_debug_info(void);
#endif
#if defined(CONFIG_PPP) && defined(CONFIG_USER_PPPOE_PROXY)
int RTK_RG_PPPoE_Proxy_Rule_Set( MIB_CE_ATM_VC_Tp atmVcEntryPtr );
int RTK_RG_PPPoE_Proxy_Rule_Delete( MIB_CE_ATM_VC_Tp atmVcEntryPtr );
#endif
#ifdef MAC_FILTER_BLOCKTIMES_SUPPORT
int AddRTK_RG_RT_MAC_Filter(unsigned char *smac, int mode, int blockTimes);
#else
int AddRTK_RG_RT_MAC_Filter(unsigned char *smac, int mode);
#endif
int RTK_RG_ACL_MAC_Filter_Default_Policy(int out_policy);
int RTK_RG_Dynamic_MAC_Entry_flush(void);
int Add_RTK_RG_MACTbl_MAC_Filters_Whitelist(unsigned char *smac);
int Add_RTK_RG_ACL_MAC_Filters_Whitelist(unsigned char *smac);
int RTK_RG_Reset_SSID_shaping_rule(void);
#ifdef CONFIG_CMCC_IPV6_SECURITY_SUPPORT
int RG_del_ipv6_sec_rule(int ruleidx);
int RG_add_ipv6_sec_rule(struct in6_addr* p_ip6_addr, unsigned int portmask, unsigned short vid);
int RG_add_default_ipv6_sec_rule(void);
int RG_flush_default_ipv6_sec_rule(void);
#endif
int RTK_RG_Config_SSID_shaping_rule(void);

#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
int RG_set_unbinded_port_vlan(void);	
int RG_set_WIFI_UntagIn(int vid);
int RG_Flush_WIFI_UntagIn();
#endif

#if (defined(CONFIG_CMCC) || defined(CONFIG_CU)) && defined(CONFIG_IPV6)
int RG_flush_ipv6_binding_rules();
int RG_add_ipv6_binding_rules(MIB_IPV6_BINDING_T *entry, int rg_wan_idx);
int RG_add_drop_all_rules();

int checkIPv4_IPv6_Dual_PolicyRoute(int *wanIndex, unsigned short *portMask);
int checkIPv4_IPv6_Dual_PolicyRoute_ex(MIB_CE_ATM_VC_Tp pEntry, int *wanIndex, unsigned short *portMask);
void RTK_RG_FLUSH_IPv4_IPv6_Dual_PolicyRoute();
int RGSyncIPv4_IPv6_Dual_WAN();

int Clear_Vlan_Cfg();
int Add_Cvlan_IPv4_IPv6(int ipv4_vlanID,int ipv6_vlanID);
int Add_ACL_Vlan_Cfg(int ipv4_vlanID,int ipv6_vlanID);
#endif
#ifdef CONFIG_RTK_L34_ENABLE
int Flush_RTK_RG_URL_Filter_new();
#endif
#ifdef SUPPORT_URL_FILTER
int RTK_RG_URL_Filter_Set_By_Key_new();
#endif

#if defined(CONFIG_CMCC) || defined(CONFIG_YUEME) || defined(CONFIG_CU)
int RG_Wlan_Portisolation_Set(unsigned char enable, int ssid_index);
#endif

#if defined(CONFIG_YUEME)
void RTK_RG_Control_Packet_Ingress_ACL_Rule_set(void);
void RTK_RG_Control_Packet_Egress_ACL_Rule_set(void);
void RTK_RG_Control_Packet_ITMS_Ingress_ACL_Rule_flush(void);
void RTK_RG_Control_Packet_ITMS_Ingress_ACL_Rule_set(struct in_addr *addr);
void RTK_RG_Control_Packet_ITMS_Egress_ACL_Rule_flush(void);
void RTK_RG_Control_Packet_ITMS_Egress_ACL_Rule_set(struct in_addr *addr);
void RTK_RG_add_TCP_syn_rate_limit( void );
void RTK_RG_add_ARP_broadcast_rate_limit( void );
void RTK_RG_add_UDP_rate_limit( char *ifname, struct in_addr *ipAddr);
#endif
int RTK_RG_Flush_IGMP_proxy_ACL_rule(void);
int RTK_RG_set_IGMP_proxy_ACL_rule(void);
int RTK_RG_Flush_MLD_proxy_ACL_rule(void);
void RTK_RG_set_MLD_proxy_ACL_rule(void);

int do_vlan_transparent(void);
int add_vlan_transparent(int vid);
#if defined(CONFIG_MCAST_VLAN) && defined(CONFIG_RTK_L34_ENABLE)
int check_v4_igmp_snooping(void);
int flush_igmp_snoop_acl_rule(void);
int flush_mld_snoop_acl_rule(void);
int check_v6_mld_snooping(void);
#endif
#ifdef CONFIG_RTK_HOST_SPEEDUP
int flush_rg_cf_rule_for_speedtest(void);
int add_rg_cf_rule_for_speedtest(MIB_CE_ATM_VC_T *pEntry, int flowid);
#endif
#ifdef CONFIG_CT_AWIFI_JITUAN_SMARTWIFI
int RTK_RG_Wifidog_Rule_set(void);
#endif
#ifndef CONFIG_RTL9600_SERIES
void check_port_based_vlan_of_binding_bridge_inet_wan(void);
#endif
unsigned int RG_get_lan_phyPortMask(unsigned int portmask);

int RG_get_wan_interface_packet_status(int rg_wan_idx, 
								unsigned int *rxPkts, unsigned long long int *rxBytes, 
								unsigned int *txPkts, unsigned long long int *txBytes,
								unsigned int *rxMcPkts, unsigned long long int *rxMcBytes, 
								unsigned int *txMcPkts, unsigned long long int *txMcBytes,
								unsigned int *rxBcPkts, unsigned long long int *rxBcBytes, 
								unsigned int *txBcPkts, unsigned long long int *txBcBytes);

int RTK_RG_multicastFlow_add(unsigned int group, int *index);
int RTK_RG_multicastFlow_delete(int index);
int RTK_RG_multicastFlow_reset(void);
int RTK_RG_multicastFlow_flush(void);

int RTK_RG_Ipv6_multicastFlow_add(unsigned int *group, int *index);
int RTK_RG_Ipv6_multicastFlow_delete(int index);
int RTK_RG_Ipv6_multicastFlow_reset(void);
int RTK_RG_Ipv6_multicastFlow_flush(void);

