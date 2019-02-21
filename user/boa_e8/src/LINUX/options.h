/*
 *	option.h
 */


#ifndef INCLUDE_OPTIONS_H
#define INCLUDE_OPTIONS_H

#if defined(EMBED) || defined(__KERNEL__)
#include <linux/config.h>
#else
#include "../../../../include/linux/autoconf.h"
#endif

#ifdef EMBED
#include <config/autoconf.h>
#else
#include "../../../../config/autoconf.h"
#endif

//jiunming, redirect the web page to specific page only once per pc for wired router
#undef WEB_REDIRECT_BY_MAC

//alex
#undef CONFIG_USBCLIENT
//jim for power_led behavior according to TR068..
#undef WLAN_BUTTON_LED
// try to restore the user setting when config checking error
#define KEEP_CRITICAL_HW_SETTING
#undef KEEP_CRITICAL_CURRENT_SETTING

#ifndef CONFIG_LUNA_FIRMWARE_UPGRADE_SUPPORT
//ql--if image header error, dont reboot the system.
#define ENABLE_SIGNATURE_ADV
#undef ENABLE_SIGNATURE
#ifdef ENABLE_SIGNATURE
#define SIGNATURE	""
#endif
#endif

//ql-- limit upstream traffic
#undef UPSTREAM_TRAFFIC_CTL

#define BR_ROUTE_ONEPVC   //allow set one br and one route on the same pvc
//august: NEW_PORTMAPPING is used in user space
//#ifdef CONFIG_NEW_PORTMAPPING
#define NEW_PORTMAPPING
//#endif

#define INCLUDE_DEFAULT_VALUE		1

#ifdef CONFIG_USER_UDHCP099PRE2
#define COMBINE_DHCPD_DHCRELAY
#endif

#ifdef CONFIG_YUEME
// Define the specail DHCPD option 125 for CTC yumme test
#define CTC_YUNMESTB_DHCPD_DHCPOPTION	1
#ifdef CONFIG_USER_DBUS_PROXY_VERSION_3_0
#define YUEME_3_0_SPEC					1
#define YUEME_3_0_SPEC_SSID_ALIAS		1
#endif
#endif

#define APPLY_CHANGE

//#define SECONDARY_IP
//star: for set acl ip range
#undef ACL_IP_RANGE
//star: for layer7 filter
#undef LAYER7_FILTER_SUPPORT

#ifdef CONFIG_USER_WIRELESS_TOOLS

#define WLAN_SUPPORT			1
#define WLAN_WPA			1
#ifdef CONFIG_USER_WIRELESS_WDS
#define WLAN_WDS			1
#endif
#define WLAN_1x				1
#define WLAN_ACL			1
#undef WIFI_TEST
#ifdef CONFIG_USER_WLAN_QOS
#define WLAN_QoS
#endif
#ifdef CONFIG_USER_WIRELESS_MBSSID
#define WLAN_MBSSID			1
#if !defined(CONFIG_CMCC) && !defined(CONFIG_CU)
#define CTCOM_WLAN_REQ		1   //CTCOM request tr069 wireless mssid entity can be add and del
#endif
#endif

#ifdef CONFIG_RTL_CLIENT_MODE_SUPPORT
#define WLAN_CLIENT
#endif
#ifdef CONFIG_RTL_REPEATER_MODE_SUPPORT
#define WLAN_UNIVERSAL_REPEATER
#endif

#if (defined(CONFIG_MASTER_WLAN0_ENABLE) && defined(CONFIG_SLAVE_WLAN1_ENABLE)) || \
	(defined(CONFIG_USE_PCIE_SLOT_0) && defined(CONFIG_USE_PCIE_SLOT_1))
#define WLAN_DUALBAND_CONCURRENT 1
#endif

#if defined(WLAN_DUALBAND_CONCURRENT)
#if defined(CONFIG_YUEME) && defined(CONFIG_LUNA_DUAL_LINUX)
#define WLAN0_2G_WLAN1_5G	1
#else
#if defined(CONFIG_WLAN0_5G_WLAN1_2G)
#define WLAN0_5G_WLAN1_2G       1
#elif defined(CONFIG_WLAN0_2G_WLAN1_5G)
#define WLAN0_2G_WLAN1_5G       1
#else //check by driver config
#if defined(CONFIG_BAND_5G_ON_WLAN0)
#define WLAN0_5G_WLAN1_2G       1
#else
#define WLAN0_2G_WLAN1_5G       1
#endif
#endif
#endif
#endif

#if defined(WLAN_DUALBAND_CONCURRENT)
#if (defined(CONFIG_YUEME) || defined(CONFIG_CMCC) || defined(CONFIG_CU)) && !defined(CONFIG_LUNA_DUAL_LINUX) && defined(WLAN0_2G_WLAN1_5G)
#define SWAP_HW_WLAN_MIB_INDEX	1
#endif
#endif

#if (!defined(WLAN_DUALBAND_CONCURRENT) && (defined(CONFIG_RTL_8812_SUPPORT)||defined(CONFIG_WLAN_HAL_8814AE)||defined(CONFIG_WLAN_HAL_8822BE))) || \
	(defined(WLAN0_5G_WLAN1_2G)) || \
	(defined(CONFIG_NO_WLAN_DRIVER) && (defined(CONFIG_RTL_8812_SUPPORT)))
	//single band 5G,  dual band 5G, dual linux slave wlan only 5G
#define WLAN0_5G_SUPPORT  1
#endif

#if (!defined(WLAN_DUALBAND_CONCURRENT) && ((defined(CONFIG_RTL_8812_SUPPORT)||defined(CONFIG_WLAN_HAL_8814AE)||defined(CONFIG_WLAN_HAL_8822BE))&& !defined(CONFIG_RTL_8812AR_VN_SUPPORT))) || \
	(defined(WLAN0_5G_WLAN1_2G) && ((defined(CONFIG_RTL_8812_SUPPORT)||defined(CONFIG_WLAN_HAL_8814AE)||defined(CONFIG_WLAN_HAL_8822BE)) && !defined(CONFIG_RTL_8812AR_VN_SUPPORT))) || \
	(defined(CONFIG_NO_WLAN_DRIVER) && (defined(CONFIG_RTL_8812_SUPPORT) && !defined(CONFIG_RTL_8812AR_VN_SUPPORT)))
	// single band 5G 11ac, dual band 5G 11ac, dual linux slave wlan only 5G 11ac
#define WLAN0_5G_11AC_SUPPORT 1
#endif

#if defined(WLAN0_2G_WLAN1_5G)
	//dualband
#define WLAN1_5G_SUPPORT 1
#endif

#if defined (CONFIG_WLAN1_5G_11AC_SUPPORT)  || \
	(defined(WLAN0_2G_WLAN1_5G)  && ((defined(CONFIG_RTL_8812_SUPPORT)||defined(CONFIG_WLAN_HAL_8814AE)||defined(CONFIG_WLAN_HAL_8822BE))&& !defined(CONFIG_RTL_8812AR_VN_SUPPORT)))
	//dual linux slave wlan 5G 11ac, dual band single linux wlan1 5G 11ac
#define WLAN1_5G_11AC_SUPPORT 1
#endif

#if defined(CONFIG_RTL_92D_SUPPORT) || defined(WLAN_DUALBAND_CONCURRENT)
#define NUM_WLAN_INTERFACE		2	// number of wlan interface supported
#else
#define NUM_WLAN_INTERFACE		1	// number of wlan interface supported
#endif

#if (CONFIG_WLAN_MBSSID_NUM == 7)
#define WLAN_8_SSID_SUPPORT		1
#endif

#ifdef WLAN_MBSSID
#ifdef WLAN_8_SSID_SUPPORT //support 8 ssid
#define WLAN_MBSSID_NUM		7
#define MAX_WLAN_VAP		7
#else
#define WLAN_MBSSID_NUM		3
#define MAX_WLAN_VAP		4
#endif
#else
#define WLAN_MBSSID_NUM		0
#define MAX_WLAN_VAP		0
#endif
#define WLAN_VAP_ITF_INDEX		1 // root
#define WLAN_REPEATER_ITF_INDEX		(1+WLAN_MBSSID_NUM) // root+VAP
#ifdef WLAN_UNIVERSAL_REPEATER
#define NUM_VWLAN_INTERFACE	WLAN_MBSSID_NUM+1 // VAP+Repeater
#else
#define NUM_VWLAN_INTERFACE	WLAN_MBSSID_NUM // VAP
#endif

#define WLAN_SSID_NUM	(1+WLAN_MBSSID_NUM)

#define WLAN_MAX_ITF_INDEX	(MAX_WLAN_VAP+1)

#undef E8A_CHINA

#undef WLAN_ONOFF_BUTTON_SUPPORT

//xl_yue: support zte531b--light:wps function is ok; die:wps function failed; blink: wps connecting
//#undef	 REVERSE_WPS_LED

#define ENABLE_WPAAES_WPA2TKIP

#ifdef CONFIG_RTL_11W_SUPPORT
#define WLAN_11W
#endif

#ifdef CONFIG_RTL_11R_SUPPORT
#define WLAN_11R
#endif

#ifdef CONFIG_RTL_DOT11K_SUPPORT
#define WLAN_11K
#endif

#ifdef CONFIG_RTL_11V_SUPPORT
#define WLAN_11V
#endif

#ifdef CONFIG_WIFI_TIMER_SCHEDULE
#define WIFI_TIMER_SCHEDULE
#endif

#if defined(CONFIG_WIFI_SIMPLE_CONFIG)
#ifdef CONFIG_USER_WLAN_WPS_QUERY
#define WPS_QUERY
#endif
#ifdef CONFIG_USER_WLAN_WPS_VAP
#define WLAN_WPS_VAP
#define WLAN_WPS_MULTI_DAEMON
#endif
#endif
#ifdef CONFIG_YUEME
#define WLAN_LIFETIME
#define WLAN_RATE_PRIOR
#define WLAN_TXPOWER_HIGH
#ifdef YUEME_3_0_SPEC
#define WLAN_SMARTAPP_ENABLE
#define WLAN_ROAMING
#define YUEME_WLAN_USE_MAPPING_IDX
#define WLAN_VSIE_SERVICE
#endif
#endif
#ifdef CONFIG_USER_WIRELESS_LIMITED_STA_NUM
#define WLAN_LIMITED_STA_NUM
#endif

#if (defined(CONFIG_SLOT_0_ANT_SWITCH) && defined(CONFIG_SLOT_0_8192EE)) || (defined(CONFIG_SLOT_1_ANT_SWITCH) && defined(CONFIG_SLOT_1_8192EE))
#if defined (WLAN_DUALBAND_CONCURRENT) && defined(WLAN0_5G_WLAN1_2G)
#define WLAN_INTF_TXBF_DISABLE 1
#else
#define WLAN_INTF_TXBF_DISABLE 0
#endif
#endif

#endif

#ifndef CONFIG_SFU
#define IP_PORT_FILTER
#define MAC_FILTER
#define MAC_FILTER_SRC_ONLY 1
#define MAC_FILTER_SRC_WHITELIST 1
//#ifdef CONFIG_RTL9607C_SERIES
/* mac filter times support */
#define MAC_FILTER_BLOCKTIMES_SUPPORT	1
//#endif
#define PORT_FORWARD_GENERAL
#define URL_BLOCKING_SUPPORT
#define URL_ALLOWING_SUPPORT
#define DOMAIN_BLOCKING_SUPPORT
#ifdef CONFIG_USER_PARENTAL_CONTROL
#define PARENTAL_CTRL
#endif
//uncomment for TCP/UDP connection limit
//#define TCP_UDP_CONN_LIMIT	1
#undef TCP_UDP_CONN_LIMIT
#undef NAT_CONN_LIMIT
#undef NATIP_FORWARDING
#undef PORT_TRIGGERING
#define DMZ
#undef ADDRESS_MAPPING
#define ROUTING
#define REMOTE_ACCESS_CTL
#define IP_PASSTHROUGH
#define IP_ACL
#endif

// Mason Yu
#undef PORT_FORWARD_ADVANCE
#define VIRTUAL_SERVER_SUPPORT			// Mason Yu. 2630-e8b
#ifdef CONFIG_USER_RTK_PPPOE_PASSTHROUGH
#define PPPOE_PASSTHROUGH
#endif
#undef  MULTI_ADDRESS_MAPPING
#undef CONFIG_IGMP_FORBID
#define FORCE_IGMP_V2			1


#undef SUPPORT_AUTH_DIGEST

#ifdef CONFIG_USB_SUPPORT
#define USB_SUPPORT					1
#define _PRMT_USBRESTORE            1
#endif

#define WEB_UPGRADE			1
//#undef WEB_UPGRADE			// jimluo e8-A spec, unsupport web upgrade.

#ifdef CONFIG_USER_VSNTP
#define TIME_ZONE			1
#endif

#ifdef CONFIG_USER_IPROUTE2_TC_TC

/*#ifdef CONFIG_NET_SCH_DSMARK*/
#define QOS_DIFFSERV
/*#endif*/
#define	IP_QOS_VPORT		1
#undef   CONFIG_8021P_PRIO
#ifdef CONFIG_IP_NF_TARGET_DSCP
#define QOS_DSCP		1
#endif
//#ifdef NEW_IP_QOS_SUPPORT
#if defined(NEW_IP_QOS_SUPPORT) || defined(QOS_DIFFSERV)
#ifdef CONFIG_IP_NF_MATCH_DSCP
#define QOS_DSCP_MATCH		1
#endif
#endif
#endif
#ifdef CONFIG_USER_IPROUTE2_IP_IP
#ifdef IP_QOS
#define IP_POLICY_ROUTING		1
#endif
#endif

#ifndef NEW_PORTMAPPING
#define ITF_GROUP			1
#endif

#define ENABLE_802_1Q		// enable_802_1p_090722
// Mason Yu. combine_1p_4p_PortMapping
#ifdef ITF_GROUP
	#define ITF_GROUP_1P
#endif

#undef VLAN_GROUP
#undef ELAN_LINK_MODE
#undef ELAN_LINK_MODE_INTRENAL_PHY
#define DIAGNOSTIC_TEST			1

//xl_yue
#undef	DOS_SUPPORT

#define NEW_DGW_POLICY   // E8B: the dgw is useless in MIB_ATM_VC_TBL, the INTERNET type connection who first get ip will be default gateway
#define DEFAULT_GATEWAY_V1	//set dgw per pvc
#undef DEFAULT_GATEWAY_V2	// set dgw interface in routing page
#ifndef DEFAULT_GATEWAY_V2
#ifndef DEFAULT_GATEWAY_V1
#define DEFAULT_GATEWAY_V1	1
#endif
#endif
#ifdef DEFAULT_GATEWAY_V2
#define AUTO_PPPOE_ROUTE	1
//#undef AUTO_PPPOE_ROUTE
#endif

//alex_huang
#undef  CONFIG_SPPPD_STATICIP
#undef XOR_ENCRYPT
#undef XML_TR069
#define TELNET_IDLE_TIME	600 //10*60 sec. Please compile boa and telnetd

/* wpeng defined for support dhcp option 33/121/249*/
#define _CONFIG_DHCPC_OPTION33_         1
/* wpeng 20120412 END*/

#ifdef CONFIG_USER_CWMP_TR069
// Mason Yu
#ifndef XML_TR069
#define XML_TR069
#endif  //XML_TR069
#define _CWMP_MIB_				1
#ifdef CONFIG_USER_CWMP_WITH_SSL
#define _CWMP_WITH_SSL_				1
#endif //CONFIG_USER_CWMP_WITH_SSL
#define _PRMT_SERVICES_				1
#define _PRMT_CAPABILITIES_			1
#define _PRMT_DEVICECONFIG_			1
//#define _PRMT_USERINTERFACE_			1
/*disable connection request authentication*/
//#define _TR069_CONREQ_AUTH_SELECT_		1
#ifdef CONFIG_USER_TR143
#define _PRMT_TR143_				1
#endif //CONFIG_USER_TR143
#ifdef CONFIG_USB_ETH
#define _PRMT_USB_ETH_				1
#endif //CONFIG_USB_ETH


/*ping_zhang:20081217 START:patch from telefonica branch to support WT-107*/
#define _PRMT_WT107_					1
#ifdef _PRMT_WT107_
#define _SUPPORT_TRACEROUTE_PROFILE_		1
#define _SUPPORT_ADSL2DSLDIAG_PROFILE_		1
#define _SUPPORT_ADSL2WAN_PROFILE_		1
#endif //_PRMT_WT107_
/*ping_zhang:20081217 END*/

#define _PRMT_X_TELEFONICA_ES_DHCPOPTION_	1

/*ping_zhang:20081223 START:define for support multi server by default*/
#define SNTP_MULTI_SERVER			1
/*ping_zhang:20081223 END*/

// Mason Yu. for e8b_2630, client limit
#if defined(CONFIG_LUNA) || defined(CONFIG_CTC_E8_CLIENT_LIMIT)
#define IP_BASED_CLIENT_TYPE
#endif

/* copy from e8-user*/
#define CTC_TELECOM_ACCOUNT
#if !defined(CONFIG_YUEME)
#define FTP_ACCOUNT_INDEPENDENT
#endif
#ifdef CONFIG_YUEME
#define FTP_SERVER_INTERGRATION
#define FTP_SERVER_API_INTERGRATION
#endif
#if !defined(CONFIG_CMCC) && !defined(CONFIG_CU)
#define TELNET_ACCOUNT_INDEPENDENT
#endif

#define SSH_ACCOUNT_INDEPENDENT
#define TFTP_ACCOUNT_INDEPENDENT
#define SNMP_ACCOUNT_INDEPENDENT

#ifdef CONFIG_YUEME
#define DHCPC_RIGOROUSNESS_SUPPORT
#define STB_L2_FRAME_LOSS_RATE
#endif

//#define ENABLE_WPAAES_WPA2TKIP
#define E8B_NEW_DIAGNOSE
#define _PRMT_X_CT_EXT_ENABLE_
#ifdef CONFIG_CU
#define CTCOM_NAME_PREFIX "CU"
#elif defined(CONFIG_CMCC)
#define CTCOM_NAME_PREFIX "CMCC"
#else
#define CTCOM_NAME_PREFIX "CT-COM"
#endif

#ifdef _PRMT_X_CT_EXT_ENABLE_
	/*TW's ACS has some problem with this extension field*/
	#define _INFORM_EXT_FOR_X_CT_		1
    #ifdef _PRMT_SERVICES_
#if defined(CONFIG_RTL_IGMP_SNOOPING)
	#define _PRMT_X_CT_COM_IPTV_		1
#endif
	#define _PRMT_X_CT_COM_MWBAND_		1
    #endif //_PRMT_SERVICES_
	#define	_PRMT_X_CT_COM_DDNS_		1
	#define _PRMT_X_CT_COM_ALG_		1
	#define _PRMT_X_CT_COM_ACCOUNT_		1
	#define _PRMT_X_CT_COM_RECON_		1
	#define _PRMT_X_CT_COM_PORTALMNT_	1
	#define _PRMT_X_CT_COM_SRVMNG_		1	/*ServiceManage*/
	#define _PRMT_X_CT_COM_PPPOE_PROXY_	1
    #ifdef WLAN_SUPPORT
	#define _PRMT_X_CT_COM_WLAN_		1
    #endif //WLAN_SUPPORT
	#define _PRMT_X_CT_COM_DHCP_		1
	#define _PRMT_X_CT_COM_WANEXT_		1
	#define _PRMT_X_CT_COM_DLNA_		1
	#define _PRMT_X_CT_COM_UPNP_		1
	#define _PRMT_X_CT_COM_DEVINFO_		1
	#define _PRMT_X_CT_COM_ALARM_MONITOR_	1
	#define _PRMT_X_CT_COM_IPv6_		1
	#define _PRMT_X_CT_COM_ETHLINK_		1
	#define _PRMT_X_CT_COM_PING_		1
	#define _PRMT_X_CT_COM_TIME_		1
	#define _PRMT_X_CT_COM_QOS_		1
	//#define _PRMT_X_STD_QOS_			1
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	#define _PRMT_X_CT_COM_DATA_SPEED_LIMIT_ 1
#endif
	#define _PRMT_X_CT_COM_USERINFO_	1
	#define _PRMT_X_CT_COM_SYSLOG_	1
	#define _PRMT_X_CT_COM_VLAN_BOUND_	1
	#ifdef CONFIG_USER_RTK_LBD
	#define _PRMT_X_CT_COM_LBD_ 		1
	#endif
	#ifdef CONFIG_USER_CWMP_UPNP_DM
	#define _PRMT_X_CT_COM_PROXY_DEV_ 		1
	#endif
	#if 1 // CONFIG_USER_QOE
	#define _PRMT_X_CT_COM_QOE_ 1
	#endif
	#ifdef CONFIG_USER_CTMANAGEDEAMON
	#define _PRMT_X_CT_LOCATION_ 1
	#endif
	#define _PRMT_X_CT_COM_LANMAC_ 1
	#ifdef CONFIG_YUEME
	#define _PRMT_X_CT_COM_MGT_		1
	#define _PRMT_X_CT_COM_TRACEROUTE_	1
#ifdef CONFIG_RTK_L34_ENABLE
	#define _PRMT_X_CT_COM_PERFORMANCE_REPORT_		1
#endif 
	#define _PRMT_X_CT_COM_MACFILTER_		1
	#define _PRMT_X_CT_COM_IPoEDiagnostics_ 		1
	#define _PRMT_X_WLANFORISP_ 1
	#define _PRMT_X_CT_COM_WirelessTestDiagnostics_ 		1
	#define _PRMT_SC_CT_COM_			1
#ifdef _PRMT_SC_CT_COM_
	#define _PRMT_SC_CT_COM_NAME "SC_CT-COM"
	#define _PRMT_SC_CT_COM_Device_
	#define _PRMT_SC_CT_COM_InternetService_
	#define _PRMT_SC_CT_COM_GroupCompanyService_
#ifdef _PRMT_SC_CT_COM_InternetService_
	#define _PRMT_SC_CT_COM_InternetService_MAXSession_		1
	#define _PRMT_SC_CT_COM_InternetService_UserQoS_		1
#endif
#ifdef _PRMT_SC_CT_COM_GroupCompanyService_
	#define _PRMT_SC_CT_COM_GroupCompanyService_Plugin_	1
#endif
#ifdef _PRMT_SC_CT_COM_Device_
	#define _PRMT_SC_CT_COM_Device_LightSwitch_			1
#endif

	#define _PRMT_X_CT_CONTROL_PORT_SC	1
	#define _PRMT_X_CT_IPTRACEROUTE_SC	1
	#define TERMINAL_INSPECTION_SC	1
#endif
#ifdef CONFIG_RTK_L34_ENABLE
	#define _PRMT_X_CT_COM_MULTICAST_DIAGNOSIS_     1
	#define _PRMT_X_CT_COM_LANBINDING_CONFIG_ 		1
#endif
	#define EXTERNAL_ACCESS_SC 1
	#define _PRMT_X_CT_ACCESS_EQUIPMENTMAC 1
	#define _PRMT_X_CT_SUPPER_DHCP_LEASE_SC 1
#endif
#endif //_PRMT_X_CT_EXT_ENABLE_

#ifdef CONFIG_CU
#define _PRMT_X_CU_EXTEND_ 1
#define CONFIG_SUPPORT_IPTV_APPLICATIONTYPE
#define _SUPPORT_CAPTIVEPORTAL_PROFILE_		1
#ifdef _SUPPORT_CAPTIVEPORTAL_PROFILE_
#define CONFIG_SUPPORT_CAPTIVE_PORTAL
#endif
#define CONFIG_SUPPORT_PON_LINK_DOWN_PROMPT

#define _PRMT_C_CU_IGMP_ 1
#define  _PRMT_C_CU_FIREWALL_ 1
#define  _PRMT_C_CU_WEB_ 1
#define _PRMT_C_CU_LOGALARM_ 1
#define _PRMT_C_CU_TELNET_ 1
#define _PRMT_C_CU_DDNS_ 1
#define _PRMT_C_CU_DMZ_ 1
//#define _PRMT_C_CU_USERACCOUNT_ 1
//#define _PRMT_C_CU_FTPSERVICE_ 1
#ifdef CONFIG_USER_CUSPEEDTEST
#define _PRMT_C_CU_SPEEDTEST_ 1
#endif

#ifdef _PRMT_SERVICES_
#define _PRMT_C_CU_FTPSERVICE_ 1
#define _PRMT_C_CU_USERACCOUNT_ 1
#endif
#define _PRMT_C_CU_FACTORYRESET_ 1
#ifdef CONFIG_USER_CUMANAGEDEAMON
#define _PRMT_C_CU_SERVICEMGT_ 1
#endif
#define _PRMT_X_CU_DEVICEINFO_ 1
#define _PRMT_X_CU_MANAGEMENTSERVER_ 1
#define _PRMT_X_CU_COM_TIME_ 1 
#define _PRMT_X_CU_XPON_INTERFACE_CONFIG_ 1

//open for parent control
#define _PRMT_X_CMCC_SECURITY_ 1

#ifdef CONFIG_USER_CUMANAGEDEAMON
#define CU_APP_SCHEDULE_LOG 1
#define CU_CUMANAGEDEAMON_NEW_SPEC	1
#endif

#elif defined(CONFIG_CMCC)
#ifdef CONFIG_USER_OPENJDK8 
#define _PRMT_X_CMCC_JSON_ 1
#endif
#define _PRMT_X_CMCC_LEDCONTROL_ 1
#define _PRMT_X_CMCC_DEVICEINFO_ 1
#define _PRMT_X_CMCC_IPOEDIAGNOSTICS_ 1
#define _PRMT_X_CMCC_LAYER3FORWARDING_ 1
#define _PRMT_X_CMCC_LANDEVICE_ 1
#define _PRMT_X_CMCC_SECURITY_ 1
#define _PRMT_X_CMCC_LANINTERFACES_ 1
#ifdef CONFIG_USER_OPENJDK8
#define _PRMT_X_CMCC_OSGI_ 1
#endif
#define _PRMT_X_CMCC_WLANSHARE_ 1
#define _PRMT_X_CMCC_WLANFORGUEST_ 1
#ifdef WIFI_TIMER_SCHEDULE
#define _PRMT_X_CMCC_WLANSWITCHTC_ 1
#endif
#endif

#endif //CONFIG_USER_CWMP_TR069
#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_

//Ramen 20171212 pls add subitem for performance report
#define  _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_WholeFuncEnable_
#define  _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_ReportSerialNumberEnable_
#define  _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_CPURateEnable_
#define  _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_MemRateEnable_
#define  _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_SEREnable_
#define  _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_ErrorCodeEnable_
#define  _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_PLREnable_
#define  _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_PacketLostEnable_
#define  _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_TEMPEnable_
#define  _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_UpDataEnable_
#define  _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_DownDataEnable_
#define  _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_AllDeviceNumberEnable_
#define  _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_LANDeviceMACEnable_
#define  _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_WLANDeviceMACEnable_
#define  _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_OpticalInPowerEnable_
#define  _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_OpticalOutPowerEnable_
#define  _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_RoutingModeEnable_
#define  _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_DialingNumberEnable_
#define  _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_DialingErrorEnable_
#define  _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_RegisterNumberEnable_
#define  _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_RegisterSuccessNumberEnable_
#define  _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_AllWirelessChannelEnable_
#define  _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_BestWirelessChannelEnable_
#define  _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_WirelessChannelNumberEnable_
#define  _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_WirelessBandwidthEnable_
#define  _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_WirelessPowerEnable_
#define  _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_QosTypeEnable_
#define  _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_WirelessTypeEnable_
#define  _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_WorkingTimeEnable_
#define  _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_PluginUpNumberEnable_
#define  _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_PluginAllNumberEnable_
#define  _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_LANxStateEnable_
#define  _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_LANxWorkBandwidthEnable_
#define  _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_DevicePacketLossEnable_
#define  _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_TransceiverTypeEnable_
#define  _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_TransceiverSerialEnable_
#define  _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_VoiceInfoEnable_
#define  _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_VoiceStateEnable_
#define  _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_MulticastNumberEnable_




enum PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM{
	//Ramen 20171212 pls add subitem for performance report
	_PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_WholeFuncEnable_BIT,
	_PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_ReportFuncEnable_BIT,
   _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_ReportSerialNumberEnable_BIT,
   _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_CPURateEnable_BIT,
   _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_MemRateEnable_BIT,
   _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_SEREnable_BIT,
   _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_ErrorCodeEnable_BIT,
   _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_PLREnable_BIT,
   _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_PacketLostEnable_BIT,
   _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_TEMPEnable_BIT,
   _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_UpDataEnable_BIT,
   _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_DownDataEnable_BIT,
   _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_AllDeviceNumberEnable_BIT,
   _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_WLANDeviceMACDataEnable_BIT,
   _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_LANDeviceMACEnable_BIT,
   _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_WLANDeviceMACEnable_BIT,
   _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_OpticalInPowerEnable_BIT,
   _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_OpticalOutPowerEnable_BIT,
   _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_RoutingModeEnable_BIT,
   _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_DialingNumberEnable_BIT,
   _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_DialingErrorEnable_BIT,
   _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_RegisterNumberEnable_BIT,
   _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_RegisterSuccessNumberEnable_BIT,
   _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_AllWirelessChannelEnable_BIT,
   _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_BestWirelessChannelEnable_BIT,
   _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_WirelessChannelNumberEnable_BIT,
   _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_WirelessBandwidthEnable_BIT,
   _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_WirelessPowerEnable_BIT,
   _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_QosTypeEnable_BIT,
   _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_WirelessTypeEnable_BIT,
   _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_WorkingTimeEnable_BIT,
   _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_PluginUpNumberEnable_BIT,
   _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_PluginAllNumberEnable_BIT,
   _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_LANxStateEnable_BIT,
   _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_LANxWorkBandwidthEnable_BIT,
   _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_DevicePacketLossEnable_BIT,
   _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_TransceiverTypeEnable_BIT,
   _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_TransceiverSerialEnable_BIT,
   _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_VoiceInfoEnable_BIT,
   _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_VoiceStateEnable_BIT,
   _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_MulticastNumberEnable_BIT,
   _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_END	
};
#endif

#define E8B_GET_OUI

#ifdef WEB_UPGRADE
#define	UPGRADE_V1			1
#endif // if WEB_UPGRADE

//ql add
#ifdef CONFIG_RESERVE_KEY_SETTING
#define	RESERVE_KEY_SETTING
#endif

#undef WEB_ENABLE_PPP_DEBUG
// Mason Yu
#undef SEND_LOG
#define BB_FEATURE_SAVE_LOG
#define USE_BUSYBOX_KLOGD

//xl_yue add,web logining is maintenanced by web server
#define	USE_LOGINWEB_OF_SERVER

#ifdef USE_LOGINWEB_OF_SERVER
//xl_yue add,if have logined error for three times continuely,please relogin after 1 minute
#define LOGIN_ERR_TIMES_LIMITED 1
//xl_yue add,only one user can login with the same account at the same time
#define ONE_USER_LIMITED	1
//#define ONE_USER_BY_SESSIONID 1
#undef USE_BASE64_MD5_PASSWD
#endif

/*######################*/
//jim 2007-05-22
//4 jim_luo Bridge Mode only access on web
//#define BRIDGE_ONLY_ON_WEB
#undef  BRIDGE_ONLY_ON_WEB

//4 E8-A unsupport save and restore configuration file, then should remark belwo macro CONFIG_SAVE_RESTORE
#define CONFIG_SAVE_RESTORE

//E8-A unsupport web upgrade image, we should enable #undef WEB_UPGRADE at line 52
/*########################*/

//add by ramen
//#define  DNS_BIND_PVC_SUPPORT
//#define	 DNSV6_BIND_PVC_SUPPORT
//#define  POLICY_ROUTING_DNSV4RELAY
#undef QOS_SPEED_LIMIT_SUPPORT

#define  DHCPS_POOL_COMPLETE_IP
#define  DHCPS_DNS_OPTIONS
#undef ACCOUNT_CONFIG
#undef MULTI_USER_PRIV
#ifdef MULTI_USER_PRIV
#define ACCOUNT_CONFIG
#endif

/*xl_yue:20090210 add cli cmdedit*/
#ifdef CONFIG_USER_CMD_CLI
#define CONFIG_CLI_CMD_EDIT
#define CONFIG_CLI_TAB_FEATURE
#endif

//added by ql to support imagenio service
//#define IMAGENIO_IPTV_SUPPORT		// base on option60 with option240~241


#endif  // INCLUDE_OPTIONS_H

#undef AUTO_DETECT_DMZ
// add by yq_zhou
#undef CONFIG_11N_SAGEM_WEB

// Magician
#define COMMIT_IMMEDIATELY

//cathy
#define USE_11N_UDP_SERVER

//support reserved IP addresses for DHCP, jiunming
#define SUPPORT_DHCP_RESERVED_IPADDR	1

#undef URL_BLOCKING_ON_BRIDGE_MODE
#define CONFIG_IGMPPROXY_MULTIWAN

//for FIELD_TRY_SAFE_MODE web control, need ADSL driver support
#undef FIELD_TRY_SAFE_MODE

#define DEBUG_MEMORY_CHANGE 0  // Magician: for something about memory debugging.
#ifdef CONFIG_IPV6
#define DUAL_STACK_LITE
#endif

#undef ENABLE_ADSL_MODE_GINP

#if defined(CONFIG_RTK_L34_ENABLE) && (defined(CONFIG_YUEME) || defined(CONFIG_CMCC) || defined(CONFIG_CU))
//define for yueme DNS port binding request.
#define DNSQUERY_PORT_BINDING
#endif
// Mason Yu.
// Define all functions on boa for LUNA
#ifdef CONFIG_LUNA
#define GEN_WAN_MAC
#endif

//#define DEBUGPRINT  fprintf(stderr,"%s %d %s.............\n",__FILE__,__LINE__,__FUNCTION__);
#define DEBUGPRINT
#define CTC_WAN_NAME

// for e8 project, do not redial when connection lost.
#define CONFIG_NO_REDIAL

#define IP_RANGE_FILTER_SUPPORT

#define WEB_AUTH_PRIVILEGE

#ifdef CONFIG_YUEME
#define CTC_DNS_SPEED_LIMIT
#define CTC_DNS_TUNNEL

#if defined(CONFIG_MCAST_VLAN) && defined(CONFIG_RTK_L34_ENABLE)
#define SUPPORT_MCAST_TEST
#endif
#if defined(CONFIG_USER_JAMVM) && defined(CONFIG_APACHE_FELIX_FRAMEWORK)
#define OSGI_SUPPORT
#undef ENABLE_SIGNATURE_ADV // undefine and boa can upload over 1M file
#endif

#define SUPPORT_WAN_BANDWIDTH_INFO
#define SUPPORT_ACCESS_RIGHT
#define SUPPORT_INCOMING_FILTER
#ifdef URL_BLOCKING_SUPPORT
#define SUPPORT_URL_FILTER
#endif
#ifdef DOMAIN_BLOCKING_SUPPORT
#define SUPPORT_DNS_FILTER
#endif

#define CTC_TELNET_LOGIN_WITH_NORMAL_USER_PRIVILEGE

#define CTC_TELNET_LOGIN_TRY_LIMIT
#define CTC_TELNET_LOGIN_TRY_MAX 1
#define CTC_TELNET_LOGIN_TRY_LOCK_TIME 60
#define CTC_TELNET_LOGIN_FAIL_MAX 3

#define CTC_TELNET_LOGOUT_IDLE
#define CTC_TELNET_LOGOUT_IDLE_TIME 300 //5*60 sec.

#define CTC_TELNET_SCHEDULED_CLOSE
#define CTC_TELNET_SCHEDULED_CLOSE_TIME (24*60*60) // 24 hours

#if defined(CONFIG_USER_MENU_CLI)
#define CTC_YUEME_MENU_CLI
#endif

#define CTC_TELNET_CLI_CTRL

#define CTC_TELNET_CMD_CTRL 1
#define CTC_TELNET_ONE_USER_LIMIT
#endif

#if defined(CONFIG_YUEME) || defined(CONFIG_CMCC) || defined(CONFIG_CU)
#define SUPPORT_ACCESS_RIGHT
#endif

//20180103:these functions can be control by PROVINCE_SICHUAN_FUNCTION_MASK.
#define PROVINCE_SICHUAN_TRACEROUTE_TEST 0x1
#define PROVINCE_SICHUAN_RESETFACTORY_TEST 0x2
#define PROVINCE_SICHUAN_PORTCONTROL_TEST 0x4
#define PROVINCE_SICHUAN_TERMINAL_INSPECTION 0x8


#ifdef CONFIG_E8B
#ifdef CONFIG_RTK_L34_ENABLE //FIXME!! we need implement this feature based on FC drive
#define SUPPORT_WEB_REDIRECT
#define SUPPORT_WEB_PUSHUP
#define SUPPORT_PUSHWEB_FOR_FIRMWARE_UPGRADE
#endif
#define CONFIG_USER_LOG_ERRCODE
#define SUPPORT_LOID_BURNING
#ifndef CONFIG_YUEME
#define BOOT_SELF_CHECK
#endif
#endif

#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
#define CONFIG_CMCC_MULTICAST_CROSS_VLAN_SUPPORT
#if defined(CONFIG_USER_DHCPV6_ISC_DHCP411)
#define SUPPORT_DHCPV6_RELAY
#endif
#endif

#if defined(CONFIG_CU)
#define CONFIG_USER_LAN_BANDWIDTH_EX_CONTROL
#endif
