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

	//״̬
	//modify by liuxiao 2008-01-23
	BEGIN_CATALOG("״̬");

	BEGIN_MENU("�豸��Ϣ");
	ADD_MENU("diag_dev_basic_info.asp", "�豸������Ϣ");
	END_MENU();

	BEGIN_MENU("�������Ϣ");
	ADD_MENU("diag_net_connect_info.asp", "������Ϣ");
	ADD_MENU("diag_net_dsl_info.asp", "DSL��Ϣ");
	END_MENU();

	BEGIN_MENU("�û�����Ϣ");
#ifdef WLAN_SUPPORT
	ADD_MENU("diag_wlan_info.asp", "WLan�ӿ���Ϣ");
#endif
	ADD_MENU("diag_ethernet_info.asp", "��̫������Ϣ");
	ADD_MENU("diag_usb_info.asp", "USB�ӿ���Ϣ");
	END_MENU();

	BEGIN_MENU("Զ�̹���״̬");
	ADD_MENU("status_tr069_info.asp", "Զ�����ӽ���״̬");
	ADD_MENU("status_tr069_config.asp", "ҵ�������·�״̬");
	END_MENU();

	FLUSH_CATALOG();

	BEGIN_CATALOG("���");

	BEGIN_MENU("��ϲ���");
	ADD_MENU("diag_ping.asp", "PING����");
	ADD_MENU("diag_tracert.asp", "Tracert����");
	ADD_MENU("diagnose_tr069.asp", "�ֶ��ϱ� Inform");
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

	//״̬
	//modify by liuxiao 2008-01-23
	BEGIN_CATALOG("״̬");	//user

	BEGIN_MENU("�豸��Ϣ");	//user
	ADD_MENU("status_device_basic_info.asp", "�豸������Ϣ");
	END_MENU();

	BEGIN_MENU("�������Ϣ");	//user
	if (pUser_info->priv) {	//admin
		ADD_MENU("status_net_connet_info.asp", "IPv4������Ϣ");
		ADD_MENU("status_net_connet_info_ipv6.asp", "IPv6������Ϣ");
#ifdef SUPPORT_WAN_BANDWIDTH_INFO
		ADD_MENU("status_wan_bandwidth.asp", "WAN������Ϣ");
#endif
	} else {
		ADD_MENU("status_user_net_connet_info.asp", "IPv4������Ϣ");
		ADD_MENU("status_user_net_connet_info_ipv6.asp",
			 "IPv6������Ϣ");
	}


#ifdef CONFIG_EPON_FEATURE
	if (pon_mode == EPON_MODE)
		ADD_MENU("status_epon.asp", "EPON ��Ϣ");
#endif

#ifdef CONFIG_GPON_FEATURE
	if (pon_mode == GPON_MODE)
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		ADD_MENU("status_gpon.asp", "PON��·������Ϣ");
		#else
		ADD_MENU("status_gpon.asp", "GPON ��Ϣ");
		#endif
#endif

	END_MENU();

	BEGIN_MENU("�û�����Ϣ");	//user
#ifdef WLAN_SUPPORT
#if defined(CONFIG_USB_RTL8192SU_SOFTAP) || defined(CONFIG_RTL8192CD) || defined(CONFIG_RTL8192CD_MODULE)
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	ADD_MENU("status_wlan_info_11n_24g_cmcc.asp", "WLAN2.4G�ӿ���Ϣ");
#if defined(WLAN_DUALBAND_CONCURRENT)
	ADD_MENU("status_wlan_info_11n_5g_cmcc.asp", "WLAN5G�ӿ���Ϣ");
#endif
#else
	ADD_MENU("status_wlan_info_11n.asp", "WLAN�ӿ���Ϣ");
#endif
#else
	ADD_MENU("status_wlan_info.asp", "WLAN�ӿ���Ϣ");
#endif
#endif
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	ADD_MENU("status_ethernet_info_cmcc.asp", "LAN�ӿ���Ϣ");
#else
	ADD_MENU("status_ethernet_info.asp", "��̫���ӿ���Ϣ");

#ifdef CONFIG_USER_LANNETINFO
		ADD_MENU("status_lan_net_info.asp", "�¹��豸��Ϣ");
#endif
#endif

#ifdef CONFIG_USER_LAN_BANDWIDTH_MONITOR
{
	unsigned char vChar=0;
	mib_get(MIB_LANHOST_BANDWIDTH_MONITOR_ENABLE, (void*)&vChar);
#if !defined(CONFIG_CMCC) && !defined(CONFIG_CU)
	if(vChar)
		ADD_MENU("status_lan_bandwidth_monitor.asp", "�¹��豸��������Ϣ");
#endif
}
#endif

#ifdef USB_SUPPORT
	ADD_MENU("status_usb_info.asp", "USB�ӿ���Ϣ");
#endif
#ifdef CONFIG_YUEME
	ADD_MENU("status_plug_in_module.asp", "���ܲ����Ϣ");
#endif
	END_MENU();

#ifdef VOIP_SUPPORT
	//SD6-bohungwu, e8c voip
	BEGIN_MENU("���������Ϣ");
	ADD_MENU("status_voip_info.asp", "���������Ϣ");
	END_MENU();
#endif //#ifdef VOIP_SUPPORT

#ifdef E8B_NEW_DIAGNOSE
	if (pUser_info->priv)	//admin
	{
		BEGIN_MENU("Զ�̹���״̬");
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		ADD_MENU("status_tr069_info_admin_cmcc.asp", "��������");
		ADD_MENU("status_tr069_config_admin_cmcc.asp", "ҵ�������·�״̬");
#else
		ADD_MENU("status_tr069_info_admin.asp", "Զ�����ӽ���״̬");
		ADD_MENU("status_tr069_config_admin.asp", "ҵ�������·�״̬");
#endif
#ifdef CONFIG_USER_CTMANAGEDEAMON
		ADD_MENU("status_bucpe_location_admin.asp", "����λ����Ϣ״̬");
#endif
		END_MENU();

#ifdef CONFIG_USER_CUMANAGEDEAMON
		BEGIN_MENU("���ܹ���ƽ̨״̬");
		ADD_MENU("status_cumanage_info_admin_cu.asp", "����ƽ̨״̬");
		END_MENU();
#endif
	}
#endif

#ifdef CONFIG_YUEME	
	BEGIN_MENU("����Ӧ�ù���");
#ifdef YUEME_3_0_SPEC
	ADD_MENU("status_intellappl_connect_info_new.asp", "������������״̬");
#else
	ADD_MENU("status_intellappl_connect_info.asp", "������������״̬");
#endif
	ADD_MENU("status_plug_in_config.asp", "��������·�״̬");
	END_MENU();
#endif

	FLUSH_CATALOG();
	//modify end by liuxiao 2008-01-23
#ifdef CONFIG_CT_AWIFI_JITUAN_FEATURE
    unsigned char functype=0; 
    mib_get(AWIFI_PROVINCE_CODE, &functype);
    if(functype == AWIFI_ZJ){


	//aWiFi start
		BEGIN_CATALOG("aWiFi����");	//user
	
		BEGIN_MENU("���Ի�վ��"); //user
		ADD_MENU("awifi_unique_station.asp", "���Ի�վ��");
		END_MENU();

	if (pUser_info->priv)	//admin
	{
		BEGIN_MENU("aWiFi��������");	//user
		ADD_MENU("awifi_wireless_network.asp", "aWiFi��������");
		END_MENU();

	
		BEGIN_MENU("LAN ����֤����");	//user
		ADD_MENU("awifi_lan_auth_config.asp", "LAN ������");
		END_MENU();


		BEGIN_MENU("���Ի�վ�������");	//user
		ADD_MENU("awifi_site_server.asp", "���Ի�վ�����������");
		END_MENU();


		BEGIN_MENU("Ĭ�Ϸ�����");	//user
		ADD_MENU("awifi_default_server.asp", "Ĭ�Ϸ���������");
		END_MENU();


		BEGIN_MENU("�Զ���������");	//user
		ADD_MENU("awifi_update_config.asp", "�Զ���������");
		END_MENU();
	}

	
		FLUSH_CATALOG();
    }
	//aWiFi end
#endif

	//��  ��
	BEGIN_CATALOG("��  ��");	//user

	if (pUser_info->priv)	//admin
	{
		BEGIN_MENU("�������");
#if defined(CONFIG_ETHWAN)
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		ADD_MENU
		    ("boaform/formWanRedirect?redirect-url=/net_eth_links_cmcc.asp&if=eth",
		     "�������");
#else
		ADD_MENU
		    ("boaform/formWanRedirect?redirect-url=/net_eth_links.asp&if=eth",
		     "Internet ����");
#endif
#endif
		END_MENU();
#if defined(CONFIG_RTL867X_VLAN_MAPPING) || defined(CONFIG_APOLLO_ROMEDRIVER)
		BEGIN_MENU("������");
		ADD_MENU("net_vlan_mapping.asp", "��ģʽ");
		END_MENU();
#endif
	}
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	if (pUser_info->priv)	//admin
#endif
	{
	BEGIN_MENU("LAN���ַ����");
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	ADD_MENU("net_dhcpd_cmcc.asp", "IPv4����");
#else
	ADD_MENU("net_dhcpd.asp", "IPv4����");
#endif
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		ADD_MENU("net_ipv6_cmcc.asp", "IPv6 ����");
#else
		ADD_MENU("ipv6.asp", "IPv6 ����");
#endif
#if !defined(CONFIG_CMCC) && !defined(CONFIG_CU)
	ADD_MENU("dhcpdv6.asp", "IPv6 DHCP Server����");
	if (pUser_info->priv)	//admin
	{
		ADD_MENU("radvdconf.asp", "RA ����");
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
			BEGIN_MENU("LAN���ַ����");
			ADD_MENU("net_dhcpd_cmcc.asp", "IPv4����");
			ADD_MENU("net_ipv6_cmcc.asp", "IPv6 ����");
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
			ADD_MENU("net_qos_imq_policy.asp", "����QoS����");
			ADD_MENU("net_qos_data_speed_limit.asp", "��������");
			END_MENU();
	}
#endif

#ifdef WLAN_SUPPORT
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	BEGIN_MENU("WLAN2.4G��������");	//user
#else
	BEGIN_MENU("WLAN����");	//user
#endif
#if defined(CONFIG_USB_RTL8192SU_SOFTAP) || defined(CONFIG_RTL8192CD) || defined(CONFIG_RTL8192CD_MODULE)
#if defined(CONFIG_YUEME)
	ADD_MENU("boaform/admin/formWlanRedirect?redirect-url=/net_wlan_basic_11n_yueme.asp&wlan_idx=0", "WLAN2.4G����");
#elif defined(CONFIG_CMCC) || defined(CONFIG_CU)
	if (pUser_info->priv)	//admin
		ADD_MENU("boaform/admin/formWlanRedirect?redirect-url=/net_wlan_basic_11n_24g_cmcc.asp&wlan_idx=0", "WLAN2.4G��������");
	else
		ADD_MENU("boaform/admin/formWlanRedirect?redirect-url=/net_wlan_basic_11n_24g_user_cmcc.asp&wlan_idx=0", "WLAN2.4G��������");
#else
	if (pUser_info->priv)	//admin
		ADD_MENU("net_wlan_basic_11n.asp", "WLAN����");
	else
		ADD_MENU("net_wlan_basic_user_11n.asp", "WLAN����");
#endif
#else
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	if (pUser_info->priv)	//admin
		ADD_MENU("net_wlan_basic_cmcc.asp", "WLAN����");
	else
		ADD_MENU("net_wlan_basic_user_cmcc.asp", "WLAN����");
#else
	if (pUser_info->priv)	//admin
		ADD_MENU("net_wlan_basic.asp", "WLAN����");
	else
		ADD_MENU("net_wlan_basic_user.asp", "WLAN����");
#endif
#endif
#if defined(CONFIG_YUEME) && defined(WLAN_DUALBAND_CONCURRENT)
	ADD_MENU("boaform/admin/formWlanRedirect?redirect-url=/net_wlan_basic_11n_yueme.asp&wlan_idx=1", "WLAN5G����");
#endif
#if !defined(CONFIG_CMCC) && !defined(CONFIG_CU)
#ifdef WIFI_TIMER_SCHEDULE
	if (pUser_info->priv)	//admin
	{
		ADD_MENU("net_wlan_sched.asp", "���ض�ʱ");
		ADD_MENU("net_wlan_timer.asp", "���ض�ʱ(����)");
	}
#endif
#endif
#ifdef _PRMT_X_CMCC_WLANSHARE_
	if (pUser_info->priv)	//admin
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		ADD_MENU("net_wlan_share.asp", "WLAN2.4G��������");
#else
		ADD_MENU("net_wlan_share.asp", "WLAN��������");
#endif
#endif
	END_MENU();
#endif
/********************************************************************************/	
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
#ifdef WLAN_SUPPORT
#ifdef WLAN_DUALBAND_CONCURRENT
	BEGIN_MENU("WLAN5G��������");	//user

#if defined(CONFIG_USB_RTL8192SU_SOFTAP) || defined(CONFIG_RTL8192CD) || defined(CONFIG_RTL8192CD_MODULE)
	if (pUser_info->priv)	//admin
		ADD_MENU("boaform/admin/formWlanRedirect?redirect-url=/net_wlan_basic_11n_5g_cmcc.asp&wlan_idx=1", "WLAN5G��������");
	else
		ADD_MENU("boaform/admin/formWlanRedirect?redirect-url=/net_wlan_basic_11n_5g_cmcc.asp&wlan_idx=1", "WLAN5G��������");
#endif
	END_MENU();
#endif
#endif
#endif
//////////////////////////////////////////////////////////////////////////////////	
	
#ifdef CONFIG_CU
	BEGIN_MENU("Զ�̹���");
	if (pUser_info->priv)	//admin
	{
		ADD_MENU("net_tr069_cmcc.asp", "RMS������");
	}
	ADD_MENU("usereg_inside_loid_cmcc.asp", "LOID����");
	END_MENU();
#elif defined(CONFIG_CMCC)
	BEGIN_MENU("Զ�̹���");
	if (pUser_info->priv)	//admin
	{
		ADD_MENU("net_tr069_cmcc.asp", "ʡ�����ּ�ͥ����ƽ̨������");
	}
	if(getWebLoidPageEnable()==1)
	{
		ADD_MENU("usereg_inside_loid_cmcc.asp", "LOID��֤");
	}
	if(getWebPasswordPageEnable()==1){
		ADD_MENU("usereg_inside_menu_cmcc.asp", "��֤");
	}
	END_MENU();
#else
	if (pUser_info->priv)	//admin
	{
		BEGIN_MENU("Զ�̹���");
		ADD_MENU("net_tr069.asp", "ITMS������");
		ADD_MENU("net_certca.asp", "�ϴ�CA֤��");
#ifdef CONFIG_MIDDLEWARE
		ADD_MENU("net_midware.asp", "�м������");
#endif
		ADD_MENU("usereg_inside_menu.asp", "�߼�IDע��");
		END_MENU();
	}
#endif

	if (pUser_info->priv)	//admin
	{
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
#else
		BEGIN_MENU("QoS");
		//ADD_MENU("net_qos_queue.asp", "��������");
	/*
#ifndef QOS_SETUP_IMQ
		ADD_MENU("net_qos_policy.asp", "��������");
#else
		ADD_MENU("net_qos_imq_policy.asp", "��������");
#endif
*/
		
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		ADD_MENU("net_qos_imq_policy.asp", "����QoS����");
#else
		ADD_MENU("net_qos_imq_policy.asp", "��������");
		ADD_MENU("net_qos_cls.asp", "QoS����");
#endif
//		ADD_MENU("net_qos_app.asp", "QoSҵ��");
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		ADD_MENU("net_qos_data_speed_limit.asp", "��������");
#else
		ADD_MENU("net_qos_traffictl.asp", "��������");
#endif
		END_MENU();
#endif
		BEGIN_MENU("ʱ�����");
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		ADD_MENU("net_sntp_cmcc.asp", "ʱ�����");
#else
		ADD_MENU("net_sntp.asp", "ʱ�������");
#endif
		END_MENU();

		BEGIN_MENU("·������");
		// Mason Yu. 2630-e8b
#if !defined(CONFIG_CMCC) && !defined(CONFIG_CU)
		ADD_MENU("rip.asp", "��̬·��");
#endif
		// Mason Yu. 2630-e8b
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		ADD_MENU("routing_cmcc.asp", "��̬·��");
#else
		ADD_MENU("routing.asp", "��̬·��");
#endif
		END_MENU();

#if defined(CONFIG_CMCC) && defined(CONFIG_CMCC_MULTICAST_CROSS_VLAN_SUPPORT)
		BEGIN_MENU("��VLAN�鲥");
		ADD_MENU("net_cross_vlan_cmcc.asp","��VLAN�鲥");
		END_MENU();
#endif

#if defined(CONFIG_CMCC) && defined(CONFIG_IPV6)
		BEGIN_MENU("IPv6��");
		ADD_MENU("net_ipv6_binding.asp","IPv6��");
		END_MENU();

		BEGIN_MENU("VLAN����");
		ADD_MENU("net_vlan_cfg.asp","VLAN����");
		END_MENU();
#endif
	}

	FLUSH_CATALOG();

	//��  ȫ
	BEGIN_CATALOG("��  ȫ");	//user

	BEGIN_MENU("��������������");	//user
#ifdef SUPPORT_URL_FILTER
	ADD_MENU("secu_urlfilter_cfg_dbus.asp", "URL��������");
#else
	ADD_MENU("secu_urlfilter_cfg.asp", "��������������");
#endif
#ifdef SUPPORT_DNS_FILTER
	ADD_MENU("secu_dnsfilter_cfg.asp", "DNS��������");
#endif
	END_MENU();

	BEGIN_MENU("����ǽ");
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	ADD_MENU("secu_firewall_level_cmcc.asp", "��ȫ��");	//user
#else
	ADD_MENU("secu_firewall_level.asp", "��ȫ��");	//user
#endif
#if !defined(CONFIG_CMCC) && !defined(CONFIG_CU)
	if (pUser_info->priv)	//admin
#endif
	{
		ADD_MENU("secu_firewall_dosprev.asp", "������������");
	}
	END_MENU();

	BEGIN_MENU("MAC����");	//user
#ifdef	MAC_FILTER_SRC_ONLY
	ADD_MENU("secu_macfilter_src.asp", "MAC����");
#else
	ADD_MENU("secu_macfilter_bridge.asp", "�Ž�MAC����");
	ADD_MENU("secu_macfilter_router.asp", "·��MAC����");
#endif
	END_MENU();

	if (pUser_info->priv)	//admin
	{
		BEGIN_MENU("�˿ڹ���");
		ADD_MENU("secu_portfilter_cfg.asp", "�˿ڹ���");
		END_MENU();
	}

	FLUSH_CATALOG();

	//Ӧ  ��
	
	BEGIN_CATALOG("Ӧ  ��");	

	if (pUser_info->priv)	//admin
	{
#ifdef CONFIG_RG_SLEEPMODE_TIMER
		BEGIN_MENU("������������");
		ADD_MENU("app_sleepmode_rule.asp", "������������");
		END_MENU();
#endif
#if !defined(CONFIG_CMCC) && !defined(CONFIG_CU)
#ifdef CONFIG_LED_INDICATOR_TIMER
		BEGIN_MENU("����LED����");
		ADD_MENU("app_led_sched.asp", "����LED����");
		END_MENU();
#endif
#endif
		BEGIN_MENU("DDNS����");
#if defined(CONFIG_CMCC) && !defined(CONFIG_CU)
		ADD_MENU("app_ddns.asp", "DDNS����");
#else
		ADD_MENU("app_ddns_show.asp", "DDNS����");
#endif
		END_MENU();

		BEGIN_MENU("�߼�NAT����");
		// Mason Yu. 2630-e8b
		ADD_MENU("algonoff.asp", "ALG����");
		ADD_MENU("fw-dmz.asp", "DMZ����");
		ADD_MENU("app_nat_vrtsvr_cfg.asp", "������������");
#if 0
		ADD_MENU("app_nat_porttrig_show.asp", "�˿ڴ���");
#endif
		END_MENU();

		BEGIN_MENU("UPNP����");
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		ADD_MENU("app_upnp_cmcc.asp", "UPNP����");
#else
		ADD_MENU("app_upnp.asp", "UPNP����");
#endif
#ifdef CONFIG_USER_MINIDLNA
#if !defined(CONFIG_CMCC) && !defined(CONFIG_CU)
		ADD_MENU("dms.asp", "DLNA����");
#endif
#endif
		END_MENU();

		//SD6-bohungwu, e8c voip
#ifdef VOIP_SUPPORT
		BEGIN_MENU("����绰����");
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		ADD_MENU("cmcc_app_voip.asp", "����绰����");
#else
		ADD_MENU("app_voip.asp", "����绰����");
		ADD_MENU("app_voip2.asp", "����绰�߼�����");
#endif	
		END_MENU();
#endif //#ifdef VOIP_SUPPORT

#if !defined(CONFIG_CMCC) && !defined(CONFIG_CU)
		BEGIN_MENU("IGMP����");
		ADD_MENU("app_igmp_snooping.asp", "IGMP SNOOPING");
		ADD_MENU("app_igmp_proxy.asp", "IGMP Proxy ");
		END_MENU();

		// Mason Yu. MLD Proxy
		BEGIN_MENU("MLD����");
		ADD_MENU("app_mld_snooping.asp", "MLD SNOOPING����");	// Mason Yu. MLD snooping for e8b
		ADD_MENU("app_mldProxy.asp", "MLD Proxy����");
		END_MENU();
#else
		BEGIN_MENU("IGMP����");
		ADD_MENU("snooping_proxy_cmcc.asp", "IGMP����");	
		END_MENU();
#endif
		if(1==miscfunc_type)
		{
			BEGIN_MENU("�˿�����");
			ADD_MENU("app_port_bwcontrol.asp", "�˿�����");
			END_MENU();
		}
		
#if defined (CONFIG_USER_LAN_BANDWIDTH_MONITOR) || defined (CONFIG_USER_LAN_BANDWIDTH_CONTROL)
#if !defined(CONFIG_CMCC) && !defined(CONFIG_CU)
		BEGIN_MENU("�¹��ն�����");
#ifdef CONFIG_USER_LAN_BANDWIDTH_MONITOR
		ADD_MENU("app_bandwidth_monitor.asp", "�����д�����");
#endif
#ifdef CONFIG_USER_LAN_BANDWIDTH_CONTROL
		ADD_MENU("app_bandwidth_control.asp", "�����д�������");
#endif
		END_MENU();
#endif
#endif	// end of (CONFIG_USER_LAN_BANDWIDTH_MONITOR) || defined (CONFIG_USER_LAN_BANDWIDTH_CONTROL)		

#ifdef CONFIG_SUPPORT_CAPTIVE_PORTAL
		BEGIN_MENU("ǿ���Ż�����");
		ADD_MENU("url_redirect.asp", "ǿ���Ż�����");
		END_MENU();
#endif
	}
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
else{
		unsigned char InformType = 0;

		mib_get(PROVINCE_CWMP_INFORM_TYPE, &InformType);
		if (InformType == CWMP_INFORM_TYPE_CMCC_SHD)
		{
			BEGIN_MENU("�߼�NAT����");
			ADD_MENU("algonoff.asp", "ALG����");
			ADD_MENU("fw-dmz.asp", "DMZ����");
			ADD_MENU("app_nat_vrtsvr_cfg.asp", "������������");
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
	BEGIN_MENU("�ճ�Ӧ��");	//user
#ifdef USB_SUPPORT
	ADD_MENU("app_storage.asp", "��ͥ�洢");
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

	//��  ��
	BEGIN_CATALOG("��  ��");	//user

	BEGIN_MENU("�û�����");	//user
	ADD_MENU("mgm_usr_user.asp", "�û�����");
	END_MENU();

	BEGIN_MENU("�豸����");
	ADD_MENU("mgm_dev_reboot.asp", "�豸����");	//user
	if (pUser_info->priv)	//admin
	{
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		ADD_MENU("mgm_dev_reset_cmcc.asp", "�ָ�����");
#else
		ADD_MENU("mgm_dev_reset.asp", "�ָ���������");
#endif
	}
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	else
	{
		unsigned char InformType = 0;

		mib_get(PROVINCE_CWMP_INFORM_TYPE, &InformType);
		if (InformType != CWMP_INFORM_TYPE_CMCC_SHD)
		ADD_MENU("mgm_dev_reset_user_cmcc.asp", "�ָ�����");
	}
#endif
#ifdef USB_SUPPORT
#if !defined(CONFIG_CMCC) && !defined(CONFIG_CU)
	ADD_MENU("mgm_dev_usbbak.asp", "USB��������");
	ADD_MENU("mgm_dev_usb_umount.asp", "USBж��");
#else
#ifdef CONFIG_CU
	ADD_MENU("mgm_dev_usb_umount.asp", "USBж��");
#endif
#endif
#endif
	END_MENU();

	if (pUser_info->priv)	//admin
	{
		BEGIN_MENU("��־�ļ�����");
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		ADD_MENU("mgm_log_cfg_cmcc.asp", "����");
		ADD_MENU("mgm_log_view_cmcc.asp", "��־�鿴");
#else
		ADD_MENU("mgm_log_cfg.asp", "д��ȼ�����");
		ADD_MENU("mgm_log_view.asp", "�豸��־");
#endif
		END_MENU();
		
#if !defined(CONFIG_CMCC) && !defined(CONFIG_CU)
		BEGIN_MENU("ά��");
		ADD_MENU("mgm_mnt_mnt.asp", "ά��");
		END_MENU();
#else
#ifdef CONFIG_CU
		BEGIN_MENU("ά��");
		ADD_MENU("mgm_mnt_mnt.asp", "ά��");
		END_MENU();
#endif
#endif
	}

	FLUSH_CATALOG();

#ifdef E8B_NEW_DIAGNOSE
	if (pUser_info->priv)	//admin
	{
		//���
		BEGIN_CATALOG("���");

		BEGIN_MENU("�������");
		ADD_MENU("diag_ping_admin.asp", "PING����");
		ADD_MENU("diag_tracert_admin.asp", "Tracert����");
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		ADD_MENU("diagnose_tr069_admin_cmcc.asp", "Inform�ֶ��ϱ�");
#else
		ADD_MENU("diagnose_tr069_admin.asp", "�ֶ��ϱ� Inform");
#endif
#ifdef CONFIG_SUPPORT_AUTO_DIAG
#if !defined(CONFIG_CMCC) && !defined(CONFIG_CU)
		ADD_MENU("diag_autosystem_admin.asp", "�������ϵͳ");
#endif
#endif
		END_MENU();

#ifdef CONFIG_USER_RTK_LBD
#if !defined(CONFIG_CMCC) //&& !defined(CONFIG_CU)
		BEGIN_MENU("��·���");
		ADD_MENU("diag_loopback_detect.asp", "��·���");
		END_MENU();
#endif
#endif

#ifdef VOIP_SUPPORT
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		BEGIN_MENU("VoIP���");
		ADD_MENU("auto_call_voip.asp", "VoIP���");
#else
		BEGIN_MENU("ҵ�����");
		ADD_MENU("diag_voip.asp", "�������");
#endif	
		END_MENU();
#endif //#ifdef VOIP_SUPPORT

		FLUSH_CATALOG();
	}
#endif

	//��  ��
	//modify by liuxiao 2008-01-23
	BEGIN_CATALOG("��  ��");	//user
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	BEGIN_MENU("״̬����");
	ADD_MENU("/help_cmcc/help_status_device.html", "�豸��Ϣ����");
	ADD_MENU("/help_cmcc/help_status_net.asp", "�������Ϣ����");
	ADD_MENU("/help_cmcc/help_status_user.html", "�û�����Ϣ����");
#ifdef VOIP_SUPPORT
	ADD_MENU("/help/help_status_voip.html", "���������Ϣ����");
#endif
	if (pUser_info->priv)	//admin
		ADD_MENU("/help_cmcc/help_status_tr069.html", "Զ�̹���״̬����");
	END_MENU();

	BEGIN_MENU("�������");
	if (pUser_info->priv)	//admin
	{
#if defined(CONFIG_GPON_FEATURE) || defined(CONFIG_EPON_FEATURE)
		ADD_MENU("/help_cmcc/help_net_pon.html", "������ð���");
#endif
		ADD_MENU("/help_cmcc/help_net_vlan_binding.html", "�����ð���");
		ADD_MENU("/help_cmcc/help_net_lan.html", "LAN���ַ���ð���");
	}
#ifdef WLAN_SUPPORT
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	ADD_MENU("/help_cmcc/help_net_wlan.asp", "WLAN2.4G��������");
#ifdef WLAN_DUALBAND_CONCURRENT
	ADD_MENU("/help_cmcc/help_net_wlan5G.asp", "WLAN5G��������");
#endif
#else
	ADD_MENU("/help_cmcc/help_net_wlan.asp", "WLAN���ð���");
#endif
#endif
	ADD_MENU("/help_cmcc/help_net_remote.asp", "Զ�̹������");
	if (pUser_info->priv)	//admin
	{	
		ADD_MENU("/help_cmcc/help_net_qos.html", "QoS����");
		ADD_MENU("/help_cmcc/help_net_time.html", "ʱ��������");
		ADD_MENU("/help_cmcc/help_net_route.html", "·�����ð���");
	}
	END_MENU();

	BEGIN_MENU("��ȫ����");
	ADD_MENU("/help_cmcc/help_security_wanaccess.html", "�������������ð���");
	ADD_MENU("/help_cmcc/help_security_firewall.html", "����ǽ����");
	ADD_MENU("/help_cmcc/help_security_macfilter.html", "MAC���˰���");
	if (pUser_info->priv)	//admin
	{
		ADD_MENU("/help_cmcc/help_security_portfilter.html", "�˿ڹ��˰���");
	}
	END_MENU();

	if (pUser_info->priv)	//admin
	{
		BEGIN_MENU("Ӧ�ð���");
	
		ADD_MENU("/help_cmcc/help_apply_ddns.html", "DDNS���ð���");
		ADD_MENU("/help_cmcc/help_apply_nat.html", "�߼�NAT���ð���");
		ADD_MENU("/help_cmcc/help_apply_upnp.html", "UPNP���ð���");
#ifdef VOIP_SUPPORT
		ADD_MENU("/help/help_apply_voip.html", "����绰���ð���");
#endif
		ADD_MENU("/help_cmcc/help_apply_igmp.html", "IGMP���ð���");
		ADD_MENU("/help_cmcc/help_apply_mld.html", "MLD���ð���");
#ifdef USB_SUPPORT
		ADD_MENU("/help_cmcc/help_apply_familymemory.html", "�ճ�Ӧ�ð���");
#endif
		END_MENU();
	}

	BEGIN_MENU("�������");
	ADD_MENU("/help_cmcc/help_manage_user.html", "�û��������");
	ADD_MENU("/help_cmcc/help_manage_device.asp", "�豸�������");
	if (pUser_info->priv)	//admin
	{
		ADD_MENU("/help_cmcc/help_manage_logfile.html", "��־�ļ��������");
		ADD_MENU("/help_cmcc/help_manage_keep.html", "ά������");
	}
	END_MENU();
	
	if (pUser_info->priv)	//admin
	{
		BEGIN_MENU("��ϰ���");
		ADD_MENU("/help_cmcc/help_diag_net.html", "�������");
#ifndef CONFIG_CMCC
		ADD_MENU("/", "��·���");
#endif
		ADD_MENU("/", "ҵ�����");
		END_MENU();
	}
#else
	BEGIN_MENU("״̬����");
	ADD_MENU("/help/help_status_device.html", "�豸��Ϣ����");
	ADD_MENU("/help/help_status_net.asp", "�������Ϣ����");
	ADD_MENU("/help/help_status_user.html", "�û�����Ϣ����");
#ifdef VOIP_SUPPORT
	ADD_MENU("/help/help_status_voip.html", "���������Ϣ����");
#endif
	END_MENU();

	BEGIN_MENU("�������");
	//if (pUser_info->priv)	//admin
	{
#if defined(CONFIG_GPON_FEATURE) || defined(CONFIG_EPON_FEATURE)
		ADD_MENU("/help/help_net_pon.html", "������ð���");
#endif
		ADD_MENU("/help/help_net_dhcp.html", "DHCP���ð���");
	}
#ifdef WLAN_SUPPORT
	ADD_MENU("/help/help_net_wlan.html", "WLAN���ð���");
#endif
	//if (pUser_info->priv)	//admin
	{
		ADD_MENU("/help/help_net_remote.html", "Զ�̹������");
		ADD_MENU("/help/help_net_qos.html", "QoS����");
		ADD_MENU("/help/help_net_time.html", "ʱ��������");
		ADD_MENU("/help/help_net_route.html", "·�����ð���");
	}
	END_MENU();

	BEGIN_MENU("��ȫ����");
	ADD_MENU("/help/help_security_wanaccess.html", "�������������ð���");
	ADD_MENU("/help/help_security_firewall.html", "����ǽ����");
	ADD_MENU("/help/help_security_macfilter.html", "MAC���˰���");
	if (pUser_info->priv)	//admin
	{
		ADD_MENU("/help/help_security_portfilter.html", "�˿ڹ��˰���");
	}
	END_MENU();

	BEGIN_MENU("Ӧ�ð���");
	//if (pUser_info->priv)	//admin
	{
		ADD_MENU("/help/help_apply_ddns.html", "DDNS���ð���");
		ADD_MENU("/help/help_apply_nat.html", "�߼�NAT���ð���");
		ADD_MENU("/help/help_apply_upnp.html", "UPNP���ð���");
#ifdef VOIP_SUPPORT
		ADD_MENU("/help/help_apply_voip.html", "����绰���ð���");
#endif
		ADD_MENU("/help/help_apply_igmp.html", "IGMP���ð���");
	}
#ifdef USB_SUPPORT
	ADD_MENU("/help/help_apply_familymemory.html", "��ͥ�洢����");
#endif
	END_MENU();

	BEGIN_MENU("�������");
	ADD_MENU("/help/help_manage_user.html", "�û��������");
	ADD_MENU("/help/help_manage_device.html", "�豸�������");
	if (pUser_info->priv)	//admin
	{
		ADD_MENU("/help/help_manage_logfile.html", "��־�ļ��������");
		ADD_MENU("/help/help_manage_keep.html", "ά������");
	}
	END_MENU();
#endif

	FLUSH_CATALOG();
	//modify end by liuxiao 2008-01-23

	return 0;
}
