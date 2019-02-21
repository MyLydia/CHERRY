/*
*  fmmenucreate.c is used to create menu
*  added by xl_yue
*/
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "../webs.h"
#include "boa.h"
#include "mib.h"
#include "webform.h"
#include "utility.h"
//add by ramen to include the autoconf.h created by kernel
#ifdef EMBED
#include <linux/config.h>
#else
#include "../../../../include/linux/autoconf.h"
#endif
#include <rtk/options.h>

#define BEGIN_CATALOG(name)  	boaWrite (wp, "mncata = new menu(\"%s\");", name)
#define FLUSH_CATALOG()  		boaWrite (wp, "mnroot.add(mncata);")

#define BEGIN_MENU(name)  		boaWrite (wp, "mnpage = new menu(\"%s\");", name)
#define ADD_MENU(link, page)  		boaWrite (wp, "mnpage.add(\"%s\",\"%s\");", link, page)
#define END_MENU()  				boaWrite (wp, "mncata.add(mnpage);")

#ifdef E8B_NEW_DIAGNOSE
//Added by robin, for diagnosis pages
int createMenuDiag(int eid, request * wp, int argc, char **argv)
{
	boaWrite(wp, "var mncata = null;\n");
	boaWrite(wp, "var mnpage = null;\n");

	//状态
	//modify by liuxiao 2008-01-23
	BEGIN_CATALOG("状态");

	BEGIN_MENU("设备信息");
	ADD_MENU("diag_dev_basic_info.asp", "设备基本信息");
	END_MENU();

	BEGIN_MENU("网络侧信息");
	ADD_MENU("diag_net_connect_info.asp", "连接信息");
	ADD_MENU("diag_net_dsl_info.asp", "DSL信息");
	END_MENU();

	BEGIN_MENU("用户侧信息");
#ifdef WLAN_SUPPORT
	ADD_MENU("diag_wlan_info.asp", "WLan接口信息");
#endif
	ADD_MENU("diag_ethernet_info.asp", "以太网口信息");
	ADD_MENU("diag_usb_info.asp", "USB接口信息");
	END_MENU();

	BEGIN_MENU("远程管理状态");
	ADD_MENU("status_tr069_info.asp", "远程连接建立状态");
	ADD_MENU("status_tr069_config.asp", "业务配置下发状态");
	END_MENU();

	FLUSH_CATALOG();

	BEGIN_CATALOG("诊断");

	BEGIN_MENU("诊断测试");
	ADD_MENU("diag_ping.asp", "PING测试");
	ADD_MENU("diag_tracert.asp", "Tracert测试");
	ADD_MENU("diagnose_tr069.asp", "手动上报 Inform");
	END_MENU();

	FLUSH_CATALOG();

}
#endif
int createMenuEx(int eid, request * wp, int argc, char **argv)
{
#if defined(CONFIG_EPON_FEATURE) || defined(CONFIG_GPON_FEATURE)
	unsigned int pon_mode;

	mib_get(MIB_PON_MODE, &pon_mode);
#endif
	struct user_info *pUser_info;
	unsigned char miscfunc_type; //MIB_PROVINCE_MISCFUNC_TYPE

	pUser_info = search_login_list(wp);

	if (!pUser_info)
		return -1;

	mib_get(PROVINCE_MISCFUNC_TYPE, &miscfunc_type);
	
	boaWrite(wp, "var mncata = null;\n");
	boaWrite(wp, "var mnpage = null;\n");

	//状态
	//modify by liuxiao 2008-01-23
	BEGIN_CATALOG("状态");	//user

	BEGIN_MENU("设备信息");	//user
	ADD_MENU("status_device_basic_info.asp", "设备基本信息");
	END_MENU();

	BEGIN_MENU("网络侧信息");	//user
	if (pUser_info->priv) {	//admin
		ADD_MENU("status_net_connet_info.asp", "IPv4连接信息");
		ADD_MENU("status_net_connet_info_ipv6.asp", "IPv6连接信息");
#ifdef SUPPORT_WAN_BANDWIDTH_INFO
		ADD_MENU("status_wan_bandwidth.asp", "WAN带宽信息");
#endif
	} else {
		ADD_MENU("status_user_net_connet_info.asp", "IPv4连接信息");
		ADD_MENU("status_user_net_connet_info_ipv6.asp",
			 "IPv6连接信息");
	}


#ifdef CONFIG_EPON_FEATURE
	if (pon_mode == EPON_MODE)
		ADD_MENU("status_epon.asp", "EPON 信息");
#endif

#ifdef CONFIG_GPON_FEATURE
	if (pon_mode == GPON_MODE)
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		ADD_MENU("status_gpon.asp", "PON链路连接信息");
		#else
		ADD_MENU("status_gpon.asp", "GPON 信息");
		#endif
#endif

	END_MENU();

	BEGIN_MENU("用户侧信息");	//user
#ifdef WLAN_SUPPORT
#if defined(CONFIG_USB_RTL8192SU_SOFTAP) || defined(CONFIG_RTL8192CD) || defined(CONFIG_RTL8192CD_MODULE)
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	ADD_MENU("status_wlan_info_11n_24g_cmcc.asp", "WLAN2.4G接口信息");
#if defined(WLAN_DUALBAND_CONCURRENT)
	ADD_MENU("status_wlan_info_11n_5g_cmcc.asp", "WLAN5G接口信息");
#endif
#else
	ADD_MENU("status_wlan_info_11n.asp", "WLAN接口信息");
#endif
#else
	ADD_MENU("status_wlan_info.asp", "WLAN接口信息");
#endif
#endif
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	ADD_MENU("status_ethernet_info_cmcc.asp", "LAN接口信息");
#else
	ADD_MENU("status_ethernet_info.asp", "以太网接口信息");

#ifdef CONFIG_USER_LANNETINFO
		ADD_MENU("status_lan_net_info.asp", "下挂设备信息");
#endif
#endif

#ifdef CONFIG_USER_LAN_BANDWIDTH_MONITOR
{
	unsigned char vChar=0;
	mib_get(MIB_LANHOST_BANDWIDTH_MONITOR_ENABLE, (void*)&vChar);
#if !defined(CONFIG_CMCC) && !defined(CONFIG_CU)
	if(vChar)
		ADD_MENU("status_lan_bandwidth_monitor.asp", "下挂设备带宽监测信息");
#endif
}
#endif

#ifdef USB_SUPPORT
	ADD_MENU("status_usb_info.asp", "USB接口信息");
#endif
#ifdef CONFIG_YUEME
	ADD_MENU("status_plug_in_module.asp", "智能插件信息");
#endif
	END_MENU();

#ifdef VOIP_SUPPORT
	//SD6-bohungwu, e8c voip
	BEGIN_MENU("宽带语音信息");
	ADD_MENU("status_voip_info.asp", "宽带语音信息");
	END_MENU();
#endif //#ifdef VOIP_SUPPORT

#ifdef E8B_NEW_DIAGNOSE
	if (pUser_info->priv)	//admin
	{
		BEGIN_MENU("远程管理状态");
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		ADD_MENU("status_tr069_info_admin_cmcc.asp", "交互建立");
		ADD_MENU("status_tr069_config_admin_cmcc.asp", "业务配置下发状态");
#else
		ADD_MENU("status_tr069_info_admin.asp", "远程连接建立状态");
		ADD_MENU("status_tr069_config_admin.asp", "业务配置下发状态");
#endif
#ifdef CONFIG_USER_CTMANAGEDEAMON
		ADD_MENU("status_bucpe_location_admin.asp", "地理位置信息状态");
#endif
		END_MENU();

#ifdef CONFIG_USER_CUMANAGEDEAMON
		BEGIN_MENU("智能管理平台状态");
		ADD_MENU("status_cumanage_info_admin_cu.asp", "智能平台状态");
		END_MENU();
#endif
	}
#endif

#ifdef CONFIG_YUEME	
	BEGIN_MENU("智能应用管理");
#ifdef YUEME_3_0_SPEC
	ADD_MENU("status_intellappl_connect_info_new.asp", "智能网关连接状态");
#else
	ADD_MENU("status_intellappl_connect_info.asp", "智能网关连接状态");
#endif
	ADD_MENU("status_plug_in_config.asp", "插件配置下发状态");
	END_MENU();
#endif

	FLUSH_CATALOG();
	//modify end by liuxiao 2008-01-23
#ifdef CONFIG_CT_AWIFI_JITUAN_FEATURE
    unsigned char functype=0; 
    mib_get(AWIFI_PROVINCE_CODE, &functype);
    if(functype == AWIFI_ZJ){


	//aWiFi start
		BEGIN_CATALOG("aWiFi配置");	//user
	
		BEGIN_MENU("个性化站点"); //user
		ADD_MENU("awifi_unique_station.asp", "个性化站点");
		END_MENU();

	if (pUser_info->priv)	//admin
	{
		BEGIN_MENU("aWiFi无线网络");	//user
		ADD_MENU("awifi_wireless_network.asp", "aWiFi无线网络");
		END_MENU();

	
		BEGIN_MENU("LAN 口认证配置");	//user
		ADD_MENU("awifi_lan_auth_config.asp", "LAN 口配置");
		END_MENU();


		BEGIN_MENU("个性化站点服务器");	//user
		ADD_MENU("awifi_site_server.asp", "个性化站点服务器配置");
		END_MENU();


		BEGIN_MENU("默认服务器");	//user
		ADD_MENU("awifi_default_server.asp", "默认服务器配置");
		END_MENU();


		BEGIN_MENU("自动升级配置");	//user
		ADD_MENU("awifi_update_config.asp", "自动升级配置");
		END_MENU();
	}

	
		FLUSH_CATALOG();
    }
	//aWiFi end
#endif

	//网  络
	BEGIN_CATALOG("网  络");	//user

	if (pUser_info->priv)	//admin
	{
		BEGIN_MENU("宽带设置");
#if defined(CONFIG_ETHWAN)
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		ADD_MENU
		    ("boaform/formWanRedirect?redirect-url=/net_eth_links_cmcc.asp&if=eth",
		     "宽带设置");
#else
		ADD_MENU
		    ("boaform/formWanRedirect?redirect-url=/net_eth_links.asp&if=eth",
		     "Internet 连接");
#endif
#endif
		END_MENU();
#if defined(CONFIG_RTL867X_VLAN_MAPPING) || defined(CONFIG_APOLLO_ROMEDRIVER)
		BEGIN_MENU("绑定设置");
		ADD_MENU("net_vlan_mapping.asp", "绑定模式");
		END_MENU();
#endif
	}
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	if (pUser_info->priv)	//admin
#endif
	{
	BEGIN_MENU("LAN侧地址配置");
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	ADD_MENU("net_dhcpd_cmcc.asp", "IPv4配置");
#else
	ADD_MENU("net_dhcpd.asp", "IPv4配置");
#endif
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		ADD_MENU("net_ipv6_cmcc.asp", "IPv6 配置");
#else
		ADD_MENU("ipv6.asp", "IPv6 配置");
#endif
#if !defined(CONFIG_CMCC) && !defined(CONFIG_CU)
	ADD_MENU("dhcpdv6.asp", "IPv6 DHCP Server配置");
	if (pUser_info->priv)	//admin
	{
		ADD_MENU("radvdconf.asp", "RA 配置");
	}
#endif
	END_MENU();
	}
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	else   //User
	{
		unsigned char InformType = 0;

		mib_get(PROVINCE_CWMP_INFORM_TYPE, &InformType);
		if (InformType == CWMP_INFORM_TYPE_CMCC_SHD)
		{
			BEGIN_MENU("LAN侧地址配置");
			ADD_MENU("net_dhcpd_cmcc.asp", "IPv4配置");
			ADD_MENU("net_ipv6_cmcc.asp", "IPv6 配置");
			END_MENU();
		}
	}
#endif
#if defined(CONFIG_USER_PPTP_CLIENT_PPTP) || defined(CONFIG_USER_L2TPD_L2TPD)
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	//hide pptp, l2tp web page
#else
	if (pUser_info->priv){

		BEGIN_MENU("VPN WAN"); //user
		ADD_MENU("pptp.asp", "PPTP");	
		ADD_MENU("l2tp.asp", "L2TP");	
		END_MENU();
	}
#endif
#endif

#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	if (pUser_info->priv){
			BEGIN_MENU("QoS");	
			ADD_MENU("net_qos_imq_policy.asp", "上行QoS配置");
			ADD_MENU("net_qos_data_speed_limit.asp", "限速配置");
			END_MENU();
	}
#endif

#ifdef WLAN_SUPPORT
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	BEGIN_MENU("WLAN2.4G网络配置");	//user
#else
	BEGIN_MENU("WLAN配置");	//user
#endif
#if defined(CONFIG_USB_RTL8192SU_SOFTAP) || defined(CONFIG_RTL8192CD) || defined(CONFIG_RTL8192CD_MODULE)
#if defined(CONFIG_YUEME)
	ADD_MENU("boaform/admin/formWlanRedirect?redirect-url=/net_wlan_basic_11n_yueme.asp&wlan_idx=0", "WLAN2.4G配置");
#elif defined(CONFIG_CMCC) || defined(CONFIG_CU)
	if (pUser_info->priv)	//admin
		ADD_MENU("boaform/admin/formWlanRedirect?redirect-url=/net_wlan_basic_11n_24g_cmcc.asp&wlan_idx=0", "WLAN2.4G参数配置");
	else
		ADD_MENU("boaform/admin/formWlanRedirect?redirect-url=/net_wlan_basic_11n_24g_user_cmcc.asp&wlan_idx=0", "WLAN2.4G参数配置");
#else
	if (pUser_info->priv)	//admin
		ADD_MENU("net_wlan_basic_11n.asp", "WLAN配置");
	else
		ADD_MENU("net_wlan_basic_user_11n.asp", "WLAN配置");
#endif
#else
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	if (pUser_info->priv)	//admin
		ADD_MENU("net_wlan_basic_cmcc.asp", "WLAN配置");
	else
		ADD_MENU("net_wlan_basic_user_cmcc.asp", "WLAN配置");
#else
	if (pUser_info->priv)	//admin
		ADD_MENU("net_wlan_basic.asp", "WLAN配置");
	else
		ADD_MENU("net_wlan_basic_user.asp", "WLAN配置");
#endif
#endif
#if defined(CONFIG_YUEME) && defined(WLAN_DUALBAND_CONCURRENT)
	ADD_MENU("boaform/admin/formWlanRedirect?redirect-url=/net_wlan_basic_11n_yueme.asp&wlan_idx=1", "WLAN5G配置");
#endif
#if !defined(CONFIG_CMCC) && !defined(CONFIG_CU)
#ifdef WIFI_TIMER_SCHEDULE
	if (pUser_info->priv)	//admin
	{
		ADD_MENU("net_wlan_sched.asp", "开关定时");
		ADD_MENU("net_wlan_timer.asp", "开关定时(周期)");
	}
#endif
#endif
#ifdef _PRMT_X_CMCC_WLANSHARE_
	if (pUser_info->priv)	//admin
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		ADD_MENU("net_wlan_share.asp", "WLAN2.4G共享配置");
#else
		ADD_MENU("net_wlan_share.asp", "WLAN共享配置");
#endif
#endif
	END_MENU();
#endif
/********************************************************************************/	
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
#ifdef WLAN_SUPPORT
#ifdef WLAN_DUALBAND_CONCURRENT
	BEGIN_MENU("WLAN5G网络配置");	//user

#if defined(CONFIG_USB_RTL8192SU_SOFTAP) || defined(CONFIG_RTL8192CD) || defined(CONFIG_RTL8192CD_MODULE)
	if (pUser_info->priv)	//admin
		ADD_MENU("boaform/admin/formWlanRedirect?redirect-url=/net_wlan_basic_11n_5g_cmcc.asp&wlan_idx=1", "WLAN5G参数配置");
	else
		ADD_MENU("boaform/admin/formWlanRedirect?redirect-url=/net_wlan_basic_11n_5g_cmcc.asp&wlan_idx=1", "WLAN5G参数配置");
#endif
	END_MENU();
#endif
#endif
#endif
//////////////////////////////////////////////////////////////////////////////////	
	
#ifdef CONFIG_CU
	BEGIN_MENU("远程管理");
	if (pUser_info->priv)	//admin
	{
		ADD_MENU("net_tr069_cmcc.asp", "RMS服务器");
	}
	ADD_MENU("usereg_inside_loid_cmcc.asp", "LOID配置");
	END_MENU();
#elif defined(CONFIG_CMCC)
	BEGIN_MENU("远程管理");
	if (pUser_info->priv)	//admin
	{
		ADD_MENU("net_tr069_cmcc.asp", "省级数字家庭管理平台服务器");
	}
	if(getWebLoidPageEnable()==1)
	{
		ADD_MENU("usereg_inside_loid_cmcc.asp", "LOID认证");
	}
	if(getWebPasswordPageEnable()==1){
		ADD_MENU("usereg_inside_menu_cmcc.asp", "认证");
	}
	END_MENU();
#else
	if (pUser_info->priv)	//admin
	{
		BEGIN_MENU("远程管理");
		ADD_MENU("net_tr069.asp", "ITMS服务器");
		ADD_MENU("net_certca.asp", "上传CA证书");
#ifdef CONFIG_MIDDLEWARE
		ADD_MENU("net_midware.asp", "中间件配置");
#endif
		ADD_MENU("usereg_inside_menu.asp", "逻辑ID注册");
		END_MENU();
	}
#endif

	if (pUser_info->priv)	//admin
	{
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
#else
		BEGIN_MENU("QoS");
		//ADD_MENU("net_qos_queue.asp", "队列配置");
	/*
#ifndef QOS_SETUP_IMQ
		ADD_MENU("net_qos_policy.asp", "策略配置");
#else
		ADD_MENU("net_qos_imq_policy.asp", "策略配置");
#endif
*/
		
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		ADD_MENU("net_qos_imq_policy.asp", "上行QoS配置");
#else
		ADD_MENU("net_qos_imq_policy.asp", "策略配置");
		ADD_MENU("net_qos_cls.asp", "QoS分类");
#endif
//		ADD_MENU("net_qos_app.asp", "QoS业务");
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		ADD_MENU("net_qos_data_speed_limit.asp", "限速配置");
#else
		ADD_MENU("net_qos_traffictl.asp", "流量控制");
#endif
		END_MENU();
#endif
		BEGIN_MENU("时间管理");
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		ADD_MENU("net_sntp_cmcc.asp", "时间管理");
#else
		ADD_MENU("net_sntp.asp", "时间服务器");
#endif
		END_MENU();

		BEGIN_MENU("路由配置");
		// Mason Yu. 2630-e8b
#if !defined(CONFIG_CMCC) && !defined(CONFIG_CU)
		ADD_MENU("rip.asp", "动态路由");
#endif
		// Mason Yu. 2630-e8b
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		ADD_MENU("routing_cmcc.asp", "静态路由");
#else
		ADD_MENU("routing.asp", "静态路由");
#endif
		END_MENU();

#if defined(CONFIG_CMCC) && defined(CONFIG_CMCC_MULTICAST_CROSS_VLAN_SUPPORT)
		BEGIN_MENU("跨VLAN组播");
		ADD_MENU("net_cross_vlan_cmcc.asp","跨VLAN组播");
		END_MENU();
#endif

#if defined(CONFIG_CMCC) && defined(CONFIG_IPV6)
		BEGIN_MENU("IPv6绑定");
		ADD_MENU("net_ipv6_binding.asp","IPv6绑定");
		END_MENU();

		BEGIN_MENU("VLAN配置");
		ADD_MENU("net_vlan_cfg.asp","VLAN配置");
		END_MENU();
#endif
	}

	FLUSH_CATALOG();

	//安  全
	BEGIN_CATALOG("安  全");	//user

	BEGIN_MENU("广域网访问设置");	//user
#ifdef SUPPORT_URL_FILTER
	ADD_MENU("secu_urlfilter_cfg_dbus.asp", "URL访问设置");
#else
	ADD_MENU("secu_urlfilter_cfg.asp", "广域网访问设置");
#endif
#ifdef SUPPORT_DNS_FILTER
	ADD_MENU("secu_dnsfilter_cfg.asp", "DNS访问设置");
#endif
	END_MENU();

	BEGIN_MENU("防火墙");
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	ADD_MENU("secu_firewall_level_cmcc.asp", "安全级");	//user
#else
	ADD_MENU("secu_firewall_level.asp", "安全级");	//user
#endif
#if !defined(CONFIG_CMCC) && !defined(CONFIG_CU)
	if (pUser_info->priv)	//admin
#endif
	{
		ADD_MENU("secu_firewall_dosprev.asp", "攻击保护设置");
	}
	END_MENU();

	BEGIN_MENU("MAC过滤");	//user
#ifdef	MAC_FILTER_SRC_ONLY
	ADD_MENU("secu_macfilter_src.asp", "MAC过滤");
#else
	ADD_MENU("secu_macfilter_bridge.asp", "桥接MAC过滤");
	ADD_MENU("secu_macfilter_router.asp", "路由MAC过滤");
#endif
	END_MENU();

	if (pUser_info->priv)	//admin
	{
		BEGIN_MENU("端口过滤");
		ADD_MENU("secu_portfilter_cfg.asp", "端口过滤");
		END_MENU();
	}

	FLUSH_CATALOG();

	//应  用
	
	BEGIN_CATALOG("应  用");	

	if (pUser_info->priv)	//admin
	{
#ifdef CONFIG_RG_SLEEPMODE_TIMER
		BEGIN_MENU("网关休眠配置");
		ADD_MENU("app_sleepmode_rule.asp", "网关休眠配置");
		END_MENU();
#endif
#if !defined(CONFIG_CMCC) && !defined(CONFIG_CU)
#ifdef CONFIG_LED_INDICATOR_TIMER
		BEGIN_MENU("网关LED配置");
		ADD_MENU("app_led_sched.asp", "网关LED配置");
		END_MENU();
#endif
#endif
		BEGIN_MENU("DDNS配置");
#if defined(CONFIG_CMCC) && !defined(CONFIG_CU)
		ADD_MENU("app_ddns.asp", "DDNS配置");
#else
		ADD_MENU("app_ddns_show.asp", "DDNS配置");
#endif
		END_MENU();

		BEGIN_MENU("高级NAT配置");
		// Mason Yu. 2630-e8b
		ADD_MENU("algonoff.asp", "ALG配置");
		ADD_MENU("fw-dmz.asp", "DMZ配置");
		ADD_MENU("app_nat_vrtsvr_cfg.asp", "虚拟主机配置");
#if 0
		ADD_MENU("app_nat_porttrig_show.asp", "端口触发");
#endif
		END_MENU();

		BEGIN_MENU("UPNP配置");
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		ADD_MENU("app_upnp_cmcc.asp", "UPNP配置");
#else
		ADD_MENU("app_upnp.asp", "UPNP配置");
#endif
#ifdef CONFIG_USER_MINIDLNA
#if !defined(CONFIG_CMCC) && !defined(CONFIG_CU)
		ADD_MENU("dms.asp", "DLNA配置");
#endif
#endif
		END_MENU();

		//SD6-bohungwu, e8c voip
#ifdef VOIP_SUPPORT
		BEGIN_MENU("宽带电话设置");
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		ADD_MENU("cmcc_app_voip.asp", "宽带电话设置");
#else
		ADD_MENU("app_voip.asp", "宽带电话设置");
		ADD_MENU("app_voip2.asp", "宽带电话高级设置");
#endif	
		END_MENU();
#endif //#ifdef VOIP_SUPPORT

#if !defined(CONFIG_CMCC) && !defined(CONFIG_CU)
		BEGIN_MENU("IGMP设置");
		ADD_MENU("app_igmp_snooping.asp", "IGMP SNOOPING");
		ADD_MENU("app_igmp_proxy.asp", "IGMP Proxy ");
		END_MENU();

		// Mason Yu. MLD Proxy
		BEGIN_MENU("MLD配置");
		ADD_MENU("app_mld_snooping.asp", "MLD SNOOPING配置");	// Mason Yu. MLD snooping for e8b
		ADD_MENU("app_mldProxy.asp", "MLD Proxy配置");
		END_MENU();
#else
		BEGIN_MENU("IGMP设置");
		ADD_MENU("snooping_proxy_cmcc.asp", "IGMP设置");	
		END_MENU();
#endif
		if(1==miscfunc_type)
		{
			BEGIN_MENU("端口限速");
			ADD_MENU("app_port_bwcontrol.asp", "端口限速");
			END_MENU();
		}
		
#if defined (CONFIG_USER_LAN_BANDWIDTH_MONITOR) || defined (CONFIG_USER_LAN_BANDWIDTH_CONTROL)
#if !defined(CONFIG_CMCC) && !defined(CONFIG_CU)
		BEGIN_MENU("下挂终端配置");
#ifdef CONFIG_USER_LAN_BANDWIDTH_MONITOR
		ADD_MENU("app_bandwidth_monitor.asp", "上下行带宽监测");
#endif
#ifdef CONFIG_USER_LAN_BANDWIDTH_CONTROL
		ADD_MENU("app_bandwidth_control.asp", "上下行带宽限制");
#endif
		END_MENU();
#endif
#endif	// end of (CONFIG_USER_LAN_BANDWIDTH_MONITOR) || defined (CONFIG_USER_LAN_BANDWIDTH_CONTROL)		

#ifdef CONFIG_SUPPORT_CAPTIVE_PORTAL
		BEGIN_MENU("强制门户设置");
		ADD_MENU("url_redirect.asp", "强制门户设置");
		END_MENU();
#endif
	}
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
else{
		unsigned char InformType = 0;

		mib_get(PROVINCE_CWMP_INFORM_TYPE, &InformType);
		if (InformType == CWMP_INFORM_TYPE_CMCC_SHD)
		{
			BEGIN_MENU("高级NAT配置");
			ADD_MENU("algonoff.asp", "ALG配置");
			ADD_MENU("fw-dmz.asp", "DMZ配置");
			ADD_MENU("app_nat_vrtsvr_cfg.asp", "虚拟主机配置");
			END_MENU();
			FLUSH_CATALOG();
		}
	}
#endif	

#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	if(pUser_info->priv)
#endif
	{
#if !defined(CONFIG_CMCC) && !defined(CONFIG_CU)
	BEGIN_MENU("日常应用");	//user
#ifdef USB_SUPPORT
	ADD_MENU("app_storage.asp", "家庭存储");
#endif
#ifdef CONFIG_MCAST_VLAN
	if (pUser_info->priv)
		ADD_MENU("app_iptv.asp", "IPTV");
#endif
	END_MENU();
#endif
	}

#if !defined(USB_SUPPORT) || defined(CONFIG_CMCC) || defined(CONFIG_CU)
if(pUser_info->priv)
#endif
	FLUSH_CATALOG();

	//管  理
	BEGIN_CATALOG("管  理");	//user

	BEGIN_MENU("用户管理");	//user
	ADD_MENU("mgm_usr_user.asp", "用户管理");
	END_MENU();

	BEGIN_MENU("设备管理");
	ADD_MENU("mgm_dev_reboot.asp", "设备重启");	//user
	if (pUser_info->priv)	//admin
	{
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		ADD_MENU("mgm_dev_reset_cmcc.asp", "恢复配置");
#else
		ADD_MENU("mgm_dev_reset.asp", "恢复出厂设置");
#endif
	}
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	else
	{
		unsigned char InformType = 0;

		mib_get(PROVINCE_CWMP_INFORM_TYPE, &InformType);
		if (InformType != CWMP_INFORM_TYPE_CMCC_SHD)
		ADD_MENU("mgm_dev_reset_user_cmcc.asp", "恢复配置");
	}
#endif
#ifdef USB_SUPPORT
#if !defined(CONFIG_CMCC) && !defined(CONFIG_CU)
	ADD_MENU("mgm_dev_usbbak.asp", "USB备份配置");
	ADD_MENU("mgm_dev_usb_umount.asp", "USB卸载");
#else
#ifdef CONFIG_CU
	ADD_MENU("mgm_dev_usb_umount.asp", "USB卸载");
#endif
#endif
#endif
	END_MENU();

	if (pUser_info->priv)	//admin
	{
		BEGIN_MENU("日志文件管理");
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		ADD_MENU("mgm_log_cfg_cmcc.asp", "设置");
		ADD_MENU("mgm_log_view_cmcc.asp", "日志查看");
#else
		ADD_MENU("mgm_log_cfg.asp", "写入等级设置");
		ADD_MENU("mgm_log_view.asp", "设备日志");
#endif
		END_MENU();
		
#if !defined(CONFIG_CMCC) && !defined(CONFIG_CU)
		BEGIN_MENU("维护");
		ADD_MENU("mgm_mnt_mnt.asp", "维护");
		END_MENU();
#else
#ifdef CONFIG_CU
		BEGIN_MENU("维护");
		ADD_MENU("mgm_mnt_mnt.asp", "维护");
		END_MENU();
#endif
#endif
	}

	FLUSH_CATALOG();

#ifdef E8B_NEW_DIAGNOSE
	if (pUser_info->priv)	//admin
	{
		//诊断
		BEGIN_CATALOG("诊断");

		BEGIN_MENU("网络诊断");
		ADD_MENU("diag_ping_admin.asp", "PING测试");
		ADD_MENU("diag_tracert_admin.asp", "Tracert测试");
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		ADD_MENU("diagnose_tr069_admin_cmcc.asp", "Inform手动上报");
#else
		ADD_MENU("diagnose_tr069_admin.asp", "手动上报 Inform");
#endif
#ifdef CONFIG_SUPPORT_AUTO_DIAG
#if !defined(CONFIG_CMCC) && !defined(CONFIG_CU)
		ADD_MENU("diag_autosystem_admin.asp", "智能诊断系统");
#endif
#endif
		END_MENU();

#ifdef CONFIG_USER_RTK_LBD
#if !defined(CONFIG_CMCC) //&& !defined(CONFIG_CU)
		BEGIN_MENU("环路检测");
		ADD_MENU("diag_loopback_detect.asp", "环路检测");
		END_MENU();
#endif
#endif

#ifdef VOIP_SUPPORT
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		BEGIN_MENU("VoIP诊断");
		ADD_MENU("auto_call_voip.asp", "VoIP诊断");
#else
		BEGIN_MENU("业务诊断");
		ADD_MENU("diag_voip.asp", "语音诊断");
#endif	
		END_MENU();
#endif //#ifdef VOIP_SUPPORT

		FLUSH_CATALOG();
	}
#endif

	//帮  助
	//modify by liuxiao 2008-01-23
	BEGIN_CATALOG("帮  助");	//user
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	BEGIN_MENU("状态帮助");
	ADD_MENU("/help_cmcc/help_status_device.html", "设备信息帮助");
	ADD_MENU("/help_cmcc/help_status_net.asp", "网络侧信息帮助");
	ADD_MENU("/help_cmcc/help_status_user.html", "用户侧信息帮助");
#ifdef VOIP_SUPPORT
	ADD_MENU("/help/help_status_voip.html", "宽带语音信息帮助");
#endif
	if (pUser_info->priv)	//admin
		ADD_MENU("/help_cmcc/help_status_tr069.html", "远程管理状态帮助");
	END_MENU();

	BEGIN_MENU("网络帮助");
	if (pUser_info->priv)	//admin
	{
#if defined(CONFIG_GPON_FEATURE) || defined(CONFIG_EPON_FEATURE)
		ADD_MENU("/help_cmcc/help_net_pon.html", "宽带设置帮助");
#endif
		ADD_MENU("/help_cmcc/help_net_vlan_binding.html", "绑定设置帮助");
		ADD_MENU("/help_cmcc/help_net_lan.html", "LAN侧地址配置帮助");
	}
#ifdef WLAN_SUPPORT
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	ADD_MENU("/help_cmcc/help_net_wlan.asp", "WLAN2.4G网络配置");
#ifdef WLAN_DUALBAND_CONCURRENT
	ADD_MENU("/help_cmcc/help_net_wlan5G.asp", "WLAN5G网络配置");
#endif
#else
	ADD_MENU("/help_cmcc/help_net_wlan.asp", "WLAN配置帮助");
#endif
#endif
	ADD_MENU("/help_cmcc/help_net_remote.asp", "远程管理帮助");
	if (pUser_info->priv)	//admin
	{	
		ADD_MENU("/help_cmcc/help_net_qos.html", "QoS帮助");
		ADD_MENU("/help_cmcc/help_net_time.html", "时间管理帮助");
		ADD_MENU("/help_cmcc/help_net_route.html", "路由配置帮助");
	}
	END_MENU();

	BEGIN_MENU("安全帮助");
	ADD_MENU("/help_cmcc/help_security_wanaccess.html", "广域网访问设置帮助");
	ADD_MENU("/help_cmcc/help_security_firewall.html", "防火墙帮助");
	ADD_MENU("/help_cmcc/help_security_macfilter.html", "MAC过滤帮助");
	if (pUser_info->priv)	//admin
	{
		ADD_MENU("/help_cmcc/help_security_portfilter.html", "端口过滤帮助");
	}
	END_MENU();

	if (pUser_info->priv)	//admin
	{
		BEGIN_MENU("应用帮助");
	
		ADD_MENU("/help_cmcc/help_apply_ddns.html", "DDNS配置帮助");
		ADD_MENU("/help_cmcc/help_apply_nat.html", "高级NAT配置帮助");
		ADD_MENU("/help_cmcc/help_apply_upnp.html", "UPNP配置帮助");
#ifdef VOIP_SUPPORT
		ADD_MENU("/help/help_apply_voip.html", "宽带电话设置帮助");
#endif
		ADD_MENU("/help_cmcc/help_apply_igmp.html", "IGMP设置帮助");
		ADD_MENU("/help_cmcc/help_apply_mld.html", "MLD配置帮助");
#ifdef USB_SUPPORT
		ADD_MENU("/help_cmcc/help_apply_familymemory.html", "日常应用帮助");
#endif
		END_MENU();
	}

	BEGIN_MENU("管理帮助");
	ADD_MENU("/help_cmcc/help_manage_user.html", "用户管理帮助");
	ADD_MENU("/help_cmcc/help_manage_device.asp", "设备管理帮助");
	if (pUser_info->priv)	//admin
	{
		ADD_MENU("/help_cmcc/help_manage_logfile.html", "日志文件管理帮助");
		ADD_MENU("/help_cmcc/help_manage_keep.html", "维护帮助");
	}
	END_MENU();
	
	if (pUser_info->priv)	//admin
	{
		BEGIN_MENU("诊断帮助");
		ADD_MENU("/help_cmcc/help_diag_net.html", "网络诊断");
#ifndef CONFIG_CMCC
		ADD_MENU("/", "环路检测");
#endif
		ADD_MENU("/", "业务诊断");
		END_MENU();
	}
#else
	BEGIN_MENU("状态帮助");
	ADD_MENU("/help/help_status_device.html", "设备信息帮助");
	ADD_MENU("/help/help_status_net.asp", "网络侧信息帮助");
	ADD_MENU("/help/help_status_user.html", "用户侧信息帮助");
#ifdef VOIP_SUPPORT
	ADD_MENU("/help/help_status_voip.html", "宽带语音信息帮助");
#endif
	END_MENU();

	BEGIN_MENU("网络帮助");
	//if (pUser_info->priv)	//admin
	{
#if defined(CONFIG_GPON_FEATURE) || defined(CONFIG_EPON_FEATURE)
		ADD_MENU("/help/help_net_pon.html", "宽带设置帮助");
#endif
		ADD_MENU("/help/help_net_dhcp.html", "DHCP设置帮助");
	}
#ifdef WLAN_SUPPORT
	ADD_MENU("/help/help_net_wlan.html", "WLAN配置帮助");
#endif
	//if (pUser_info->priv)	//admin
	{
		ADD_MENU("/help/help_net_remote.html", "远程管理帮助");
		ADD_MENU("/help/help_net_qos.html", "QoS帮助");
		ADD_MENU("/help/help_net_time.html", "时间管理帮助");
		ADD_MENU("/help/help_net_route.html", "路由配置帮助");
	}
	END_MENU();

	BEGIN_MENU("安全帮助");
	ADD_MENU("/help/help_security_wanaccess.html", "广域网访问设置帮助");
	ADD_MENU("/help/help_security_firewall.html", "防火墙帮助");
	ADD_MENU("/help/help_security_macfilter.html", "MAC过滤帮助");
	if (pUser_info->priv)	//admin
	{
		ADD_MENU("/help/help_security_portfilter.html", "端口过滤帮助");
	}
	END_MENU();

	BEGIN_MENU("应用帮助");
	//if (pUser_info->priv)	//admin
	{
		ADD_MENU("/help/help_apply_ddns.html", "DDNS配置帮助");
		ADD_MENU("/help/help_apply_nat.html", "高级NAT配置帮助");
		ADD_MENU("/help/help_apply_upnp.html", "UPNP配置帮助");
#ifdef VOIP_SUPPORT
		ADD_MENU("/help/help_apply_voip.html", "宽带电话设置帮助");
#endif
		ADD_MENU("/help/help_apply_igmp.html", "IGMP设置帮助");
	}
#ifdef USB_SUPPORT
	ADD_MENU("/help/help_apply_familymemory.html", "家庭存储帮助");
#endif
	END_MENU();

	BEGIN_MENU("管理帮助");
	ADD_MENU("/help/help_manage_user.html", "用户管理帮助");
	ADD_MENU("/help/help_manage_device.html", "设备管理帮助");
	if (pUser_info->priv)	//admin
	{
		ADD_MENU("/help/help_manage_logfile.html", "日志文件管理帮助");
		ADD_MENU("/help/help_manage_keep.html", "维护帮助");
	}
	END_MENU();
#endif

	FLUSH_CATALOG();
	//modify end by liuxiao 2008-01-23

	return 0;
}
