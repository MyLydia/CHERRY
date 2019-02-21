/*

*  fmmenucreate_user.c is used to create menu

*  added by xl_yue

*/





#include <string.h>

#include <stdlib.h>

#include <unistd.h>

#include <sys/types.h>

#include <sys/wait.h>



#include "../webs.h"

#include "mib.h"

#include "webform.h"

#include "utility.h"

#include "multilang.h"



#ifdef CONFIG_DEFAULT_WEB	// default pages

/*

 *	Second Layer Menu

 */

#if defined(CONFIG_00R0) && (defined(CONFIG_GPON_FEATURE) || defined(CONFIG_EPON_FEATURE))
#define GPON_SETTINGS_STR "GPON Settings"
#define EPON_SETTINGS_STR "EPON Settings"
#define PON_STR "PON"
#endif

#if defined(CONFIG_RTL_92D_SUPPORT) || defined(WLAN_DUALBAND_CONCURRENT)
struct RootMenu childmenu_wlan0_user[] = {

	{"Basic Settings", MENU_URL, "../boaform/admin/formWlanRedirect?redirect-url=/admin/wlbasic.asp&wlan_idx=0",	"Setup wireless basic configuration", 0, 0, MENU_DISPLAY, LANG_BASIC_SETTINGS},

	{"Advanced Settings", MENU_URL, "../boaform/admin/formWlanRedirect?redirect-url=/admin/wladvanced.asp&wlan_idx=0",   "Setup wireless advanced configuration", 0, 0, MENU_DISPLAY, LANG_ADVANCED_SETTINGS},

	{"Security", MENU_URL, "../boaform/admin/formWlanRedirect?redirect-url=/admin/wlwpa.asp&wlan_idx=0", "Setup wireless security", 0, 0, MENU_DISPLAY, LANG_SECURITY},

#ifdef WLAN_11R
	{"Fast Roaming", MENU_URL, "../boaform/admin/formWlanRedirect?redirect-url=/admin/wlft.asp&wlan_idx=0", "Fast BSS Transition", 0, 0, MENU_DISPLAY, LANG_FAST_ROAMING},
#endif

#ifdef WLAN_ACL

	{"Access Control", MENU_URL, "../boaform/admin/formWlanRedirect?redirect-url=/admin/wlactrl.asp&wlan_idx=0",	"Setup access control list for wireless clients", 0, 0, MENU_DISPLAY, LANG_ACCESS_CONTROL},

#endif

#ifdef WLAN_WDS

	{"WDS", MENU_URL, "../boaform/admin/formWlanRedirect?redirect-url=/admin/wlwds.asp&wlan_idx=0", "WDS Settings", 0, 0, MENU_DISPLAY, LANG_WDS},

#endif

#if defined(WLAN_CLIENT) || defined(WLAN_SITESURVEY)
#ifdef CONFIG_00R0
	{"Wi-Fi Radar", MENU_URL, "../boaform/admin/formWlanRedirect?redirect-url=/admin/wlsurvey.asp&wlan_idx=0", "Wi-Fi Radar", 0, 0, MENU_DISPLAY, LANG_SITE_SURVEY},	
#else
	{"Site Survey", MENU_URL, "../boaform/admin/formWlanRedirect?redirect-url=/admin/wlsurvey.asp&wlan_idx=0", "Wireless Site Survey", 0, 0, MENU_DISPLAY, LANG_SITE_SURVEY},
#endif
#endif

#ifdef CONFIG_WIFI_SIMPLE_CONFIG	// WPS

	{"WPS", MENU_URL, "../boaform/admin/formWlanRedirect?redirect-url=/admin/wlwps.asp&wlan_idx=0", "Wireless Protected Setup", 0, 0, MENU_DISPLAY, LANG_WPS},

#endif

	{"Status", MENU_URL, "../boaform/admin/formWlanRedirect?redirect-url=/admin/wlstatus.asp&wlan_idx=0", "Wireless Current Status", 0, 0, MENU_DISPLAY, LANG_STATUS},

	{0, 0, 0, 0, 0, 0, 0, 0}

};

struct RootMenu childmenu_wlan1_user[] = {

	{"Basic Settings", MENU_URL, "../boaform/admin/formWlanRedirect?redirect-url=/admin/wlbasic.asp&wlan_idx=1",	"Setup wireless basic configuration", 0, 0, MENU_DISPLAY, LANG_BASIC_SETTINGS},

	{"Advanced Settings", MENU_URL, "../boaform/admin/formWlanRedirect?redirect-url=/admin/wladvanced.asp&wlan_idx=1",   "Setup wireless advanced configuration", 0, 0, MENU_DISPLAY, LANG_ADVANCED_SETTINGS},

	{"Security", MENU_URL, "../boaform/admin/formWlanRedirect?redirect-url=/admin/wlwpa.asp&wlan_idx=1", "Setup wireless security", 0, 0, MENU_DISPLAY, LANG_SECURITY},

#ifdef WLAN_11R
	{"Fast Roaming", MENU_URL, "../boaform/admin/formWlanRedirect?redirect-url=/admin/wlft.asp&wlan_idx=1", "Fast BSS Transition (user)", 0, 0, MENU_DISPLAY, LANG_FAST_ROAMING},
#endif

#ifdef WLAN_ACL

	{"Access Control", MENU_URL, "../boaform/admin/formWlanRedirect?redirect-url=/admin/wlactrl.asp&wlan_idx=1",	"Setup access control list for wireless clients", 0, 0, MENU_DISPLAY, LANG_ACCESS_CONTROL},

#endif

#ifdef WLAN_WDS

	{"WDS", MENU_URL, "../boaform/admin/formWlanRedirect?redirect-url=/admin/wlwds.asp&wlan_idx=1", "WDS Settings", 0, 0, MENU_DISPLAY, LANG_WDS},

#endif

#if defined(WLAN_CLIENT) || defined(WLAN_SITESURVEY)
#ifdef CONFIG_00R0
	{"Wi-Fi Radar", MENU_URL, "../boaform/admin/formWlanRedirect?redirect-url=/admin/wlsurvey.asp&wlan_idx=1", "Wi-Fi Radar", 0, 0, MENU_DISPLAY, LANG_SITE_SURVEY},
#else
	{"Site Survey", MENU_URL, "../boaform/admin/formWlanRedirect?redirect-url=/admin/wlsurvey.asp&wlan_idx=1", "Wireless Site Survey", 0, 0, MENU_DISPLAY, LANG_SITE_SURVEY},
#endif
#endif

#ifdef CONFIG_WIFI_SIMPLE_CONFIG	// WPS

	{"WPS", MENU_URL, "../boaform/admin/formWlanRedirect?redirect-url=/admin/wlwps.asp&wlan_idx=1", "Wireless Protected Setup", 0, 0, MENU_DISPLAY, LANG_WPS},

#endif

	{"Status", MENU_URL, "../boaform/admin/formWlanRedirect?redirect-url=/admin/wlstatus.asp&wlan_idx=1", "Wireless Current Status", 0, 0, MENU_DISPLAY, LANG_STATUS},

	{0, 0, 0, 0, 0, 0, 0, 0}

};

#if defined(TRIBAND_SUPPORT)
struct RootMenu childmenu_wlan2_user[] = {

	{"Basic Settings", MENU_URL, "../boaform/admin/formWlanRedirect?redirect-url=/admin/wlbasic.asp&wlan_idx=2",	"Setup wireless basic configuration", 0, 0, MENU_DISPLAY, LANG_BASIC_SETTINGS},

	{"Advanced Settings", MENU_URL, "../boaform/admin/formWlanRedirect?redirect-url=/admin/wladvanced.asp&wlan_idx=2",   "Setup wireless advanced configuration", 0, 0, MENU_DISPLAY, LANG_ADVANCED_SETTINGS},

	{"Security", MENU_URL, "../boaform/admin/formWlanRedirect?redirect-url=/admin/wlwpa.asp&wlan_idx=2", "Setup wireless security", 0, 0, MENU_DISPLAY, LANG_SECURITY},

#ifdef WLAN_11R
	{"Fast Roaming", MENU_URL, "../boaform/admin/formWlanRedirect?redirect-url=/admin/wlft.asp&wlan_idx=2", "Fast BSS Transition (user)", 0, 0, MENU_DISPLAY, LANG_FAST_ROAMING},
#endif

#ifdef WLAN_ACL

	{"Access Control", MENU_URL, "../boaform/admin/formWlanRedirect?redirect-url=/admin/wlactrl.asp&wlan_idx=2",	"Setup access control list for wireless clients", 0, 0, MENU_DISPLAY, LANG_ACCESS_CONTROL},

#endif

#ifdef WLAN_WDS

	{"WDS", MENU_URL, "../boaform/admin/formWlanRedirect?redirect-url=/admin/wlwds.asp&wlan_idx=2", "WDS Settings", 0, 0, MENU_DISPLAY, LANG_WDS},

#endif

#if defined(WLAN_CLIENT) || defined(WLAN_SITESURVEY)
#ifdef CONFIG_00R0
	{"Wi-Fi Radar", MENU_URL, "../boaform/admin/formWlanRedirect?redirect-url=/admin/wlsurvey.asp&wlan_idx=2", "Wi-Fi Radar", 0, 0, MENU_DISPLAY, LANG_SITE_SURVEY},
#else
	{"Site Survey", MENU_URL, "../boaform/admin/formWlanRedirect?redirect-url=/admin/wlsurvey.asp&wlan_idx=2", "Wireless Site Survey", 0, 0, MENU_DISPLAY, LANG_SITE_SURVEY},
#endif
#endif

#ifdef CONFIG_WIFI_SIMPLE_CONFIG	// WPS

	{"WPS", MENU_URL, "../boaform/admin/formWlanRedirect?redirect-url=/admin/wlwps.asp&wlan_idx=2", "Wireless Protected Setup", 0, 0, MENU_DISPLAY, LANG_WPS},

#endif

	{"Status", MENU_URL, "../boaform/admin/formWlanRedirect?redirect-url=/admin/wlstatus.asp&wlan_idx=2", "Wireless Current Status", 0, 0, MENU_DISPLAY, LANG_STATUS},

	{0, 0, 0, 0, 0, 0, 0, 0}

};
#endif /* defined(TRIBAND_SUPPORT) */

#endif //CONFIG_RTL_92D_SUPPORT

/*

 *	First Layer Menu

 */

struct RootMenu childmenu_status_user[] = {
	{"Device", MENU_URL, "status.asp", "Device status", 0, 0, MENU_DISPLAY, LANG_DEVICE},
#ifdef CONFIG_IPV6
	{"IPv6", MENU_URL, "status_ipv6.asp", "IPv6 status", 0, 0, MENU_DISPLAY, LANG_IPV6},
#endif
#if defined(CONFIG_00R0) && (defined(CONFIG_GPON_FEATURE) || defined(CONFIG_EPON_FEATURE))
	{"PON", MENU_URL, "status_pon.asp",   "PON Status", 0, 0, MENU_DISPLAY, LANG_PON},
#endif
  {0, 0, 0, 0, 0, 0, 0, 0}
};

struct RootMenu childmenu_wlan_user[] = {

#if defined(CONFIG_RTL_92D_SUPPORT)
  {"Wireless Band Mode", MENU_URL, "wlbandmode.asp",   "Setup wireless band mode", 0, 0, MENU_DISPLAY, LANG_WIRELESS_BAND_MODE},
  {"wlan0 (5GHz)", MENU_FOLDER, &childmenu_wlan0_user, "", sizeof (childmenu_wlan0_user) / sizeof (struct RootMenu) - 1, 0, MENU_DISPLAY, LANG_WLAN0_5GHZ},
  {"wlan1 (2.4GHz)", MENU_FOLDER, &childmenu_wlan1_user, "", sizeof (childmenu_wlan1_user) / sizeof (struct RootMenu) - 1, 0, MENU_DISPLAY, LANG_WLAN1_2_4GHZ},
#elif defined(TRIBAND_SUPPORT)
  {"wlan0 (5GHz)", MENU_FOLDER, &childmenu_wlan0_user, "", sizeof (childmenu_wlan0_user) / sizeof (struct RootMenu) - 1, 0, MENU_DISPLAY, LANG_WLAN0_5GHZ},
  {"wlan1 (5GHz)", MENU_FOLDER, &childmenu_wlan1_user, "", sizeof (childmenu_wlan1_user) / sizeof (struct RootMenu) - 1, 0, MENU_DISPLAY, LANG_WLAN1_5GHZ},
  {"wlan2 (2.4GHz)", MENU_FOLDER, &childmenu_wlan2_user, "", sizeof (childmenu_wlan2_user) / sizeof (struct RootMenu) - 1, 0, MENU_DISPLAY, LANG_WLAN2_2_4GHZ},
#elif defined (WLAN_DUALBAND_CONCURRENT)
#if defined (CONFIG_WLAN0_2G_WLAN1_5G) || defined(WLAN1_QTN)
  {"wlan0 (2.4GHz)", MENU_FOLDER, &childmenu_wlan0_user, "", sizeof (childmenu_wlan0_user) / sizeof (struct RootMenu) - 1, 0, MENU_DISPLAY, LANG_WLAN0_2_4GHZ},
  {"wlan1 (5GHz)", MENU_FOLDER, &childmenu_wlan1_user, "", sizeof (childmenu_wlan1_user) / sizeof (struct RootMenu) - 1, 0, MENU_DISPLAY, LANG_WLAN1_5GHZ},
#else
  {"wlan0 (5GHz)", MENU_FOLDER, &childmenu_wlan0_user, "", sizeof (childmenu_wlan0_user) / sizeof (struct RootMenu) - 1, 0, MENU_DISPLAY, LANG_WLAN0_5GHZ},
  {"wlan1 (2.4GHz)", MENU_FOLDER, &childmenu_wlan1_user, "", sizeof (childmenu_wlan1_user) / sizeof (struct RootMenu) - 1, 0, MENU_DISPLAY, LANG_WLAN1_2_4GHZ},
#endif
#else //CONFIG_RTL_92D_SUPPORT || WLAN_DUALBAND_CONCURRENT || CONFIG_MASTER_WLAN0_ENABLE || CONFIG_SLAVE_WLAN1_ENABLE

	{"Basic Settings", MENU_URL, "wlbasic.asp", "Setup wireless basic configuration", 0, 0, MENU_DISPLAY, LANG_BASIC_SETTINGS},

	{"Advanced Settings", MENU_URL, "wladvanced.asp", "Setup wireless advanced configuration", 0, 0, MENU_DISPLAY, LANG_ADVANCED_SETTINGS},

	{"Security", MENU_URL, "wlwpa.asp", "Setup wireless security", 0, 0, MENU_DISPLAY, LANG_SECURITY},

#ifdef WLAN_11R
	{"Fast Roaming", MENU_URL, "wlft.asp", "Fast BSS Transition", 0, 0, MENU_DISPLAY, LANG_FAST_ROAMING},
#endif

#ifdef WLAN_ACL

	{"Access Control", MENU_URL, "wlactrl.asp", "Setup access control list for wireless clients", 0, 0, MENU_DISPLAY, LANG_ACCESS_CONTROL},

#endif

#ifdef WLAN_WDS

	{"WDS", MENU_URL, "wlwds.asp", "WDS Settings", 0, 0, MENU_DISPLAY, LANG_WDS},

#endif

#if defined(WLAN_CLIENT) || defined(WLAN_SITESURVEY)
#ifdef CONFIG_00R0
	{"Wi-Fi Radar", MENU_URL, "wlsurvey.asp", "Wi-Fi Radar", 0, 0, MENU_DISPLAY, LANG_SITE_SURVEY},
#else
	{"Site Survey", MENU_URL, "wlsurvey.asp", "Wireless Site Survey", 0, 0, MENU_DISPLAY, LANG_SITE_SURVEY},
#endif
#endif

#ifdef CONFIG_WIFI_SIMPLE_CONFIG	// WPS

	{"WPS", MENU_URL, "wlwps.asp", "Wireless Protected Setup", 0, 0, MENU_DISPLAY, LANG_WPS},

#endif

	{"Status", MENU_URL, "wlstatus.asp", "Wireless Current Status", 0, 0, MENU_DISPLAY, LANG_STATUS},

#endif //CONFIG_RTL_92D_SUPPORT

	{0, 0, 0, 0, 0, 0, 0, 0}

};



struct RootMenu childmenu_wan_user[] = {

#ifdef CONFIG_ETHWAN
#if defined(CONFIG_GPON_FEATURE) || defined(CONFIG_EPON_FEATURE)
#ifdef CONFIG_00R0
	{PON_CONF_STR, MENU_URL, "/admin/multi_wan_generic_admin.asp", "PON WAN Configuration", 0, 0, MENU_DISPLAY, LANG_PON_WAN},
#else
	{PON_CONF_STR, MENU_URL, "../boaform/admin/formWanRedirect?redirect-url=/admin/multi_wan_generic.asp&if=pon", "PON WAN Configuration", 0, 0, MENU_DISPLAY, LANG_PON_WAN},
#endif	
#else
#ifdef CONFIG_RTL_MULTI_ETH_WAN
	{ETHWAN_CONF_STR, MENU_URL, "../boaform/admin/formWanRedirect?redirect-url=/admin/multi_wan_generic.asp&if=eth", "ETH WAN Configuration", 0, 0, MENU_DISPLAY, LANG_ETHERNET_WAN},
#else
	{ETHWAN_CONF_STR, MENU_URL, "waneth.asp", "Ethernet WAN Configuration", 0, 0, MENU_DISPLAY, LANG_ETHERNET_WAN},
#endif
#endif
#endif
#ifdef CONFIG_PTMWAN
	{PTMWAN_CONF_STR, MENU_URL, "../boaform/admin/formWanRedirect?redirect-url=/admin/multi_wan_generic.asp&if=ptm", "PTM WAN Configuration", 0, 0, MENU_DISPLAY, LANG_PTM_WAN},
#endif /*CONFIG_PTMWAN*/
#ifdef CONFIG_DEV_xDSL
  {DSLWAN_CONF_STR, MENU_URL, "wanadsl.asp", "ADSL Channel Configuration", 0, 0, MENU_DISPLAY, LANG_ATM_WAN},
  {ATM_SETTINGS_STR, MENU_URL, "wanatm.asp", "Setup ATM", 0, 0, MENU_DISPLAY, LANG_ATM_SETTINGS},
  {ADSL_SETTINGS_STR, MENU_URL, "/admin/adsl-set.asp", "Setup ADSL", 0, 0, MENU_DISPLAY, LANG_DSL_SETTINGS},
  #ifdef CONFIG_DSL_VTUO
  {VTUO_SETTINGS_STR, MENU_URL, "/admin/vtuo-set.asp", "Setup VTU-O DSL", 0, 0, MENU_DISPLAY, LANG_VTUO_SETTINGS},
  #endif /*CONFIG_DSL_VTUO*/
#endif
#ifdef CONFIG_USER_PPPOMODEM
#ifndef CONFIG_00R0
	{"3G Settings", MENU_URL, "wan3gconf.asp", "Setup 3G WAN", 0, 0, MENU_DISPLAY, LANG_3G_SETTINGS},
#endif
#endif //CONFIG_USER_PPPOMODEM

	{0, 0, 0, 0, 0, 0, 0, 0}

};


#ifndef CONFIG_00R0
struct RootMenu childmenu_fw_user[] = {

#ifdef MAC_FILTER
#ifdef CONFIG_RTK_L34_ENABLE
	{"MAC Filtering", MENU_URL, "fw-macfilter_rg.asp", "Setup MAC filering", 0, 0, MENU_DISPLAY, LANG_MAC_FILTERING},
#else
	{"MAC Filtering", MENU_URL, "fw-macfilter.asp", "Setup MAC filering", 0, 0, MENU_DISPLAY, LANG_MAC_FILTERING},
#endif
#endif

	{0, 0, 0, 0, 0, 0, 0, 0}

};
#endif


struct RootMenu childmenu_admin_user[] = {

	{"Commit/Reboot", MENU_URL, "reboot.asp", "Commit/reboot the system", 0, 0, MENU_DISPLAY, LANG_COMMIT_REBOOT},
#ifdef CONFIG_USER_BOA_WITH_MULTILANG
	{"Multi-lingual Settings", MENU_URL, "multi_lang.asp", "Multi-language setting", 0, 0, MENU_DISPLAY, LANG_MULTI_LINGUAL_SETTINGS},
#endif
#ifdef CONFIG_00R0
#ifdef CONFIG_SAVE_RESTORE
	{"Backup/Restore", MENU_URL, "saveconf.asp", "Backup/restore current settings", 0, 0, MENU_DISPLAY, LANG_BACKUP_RESTORE},
#endif
#ifdef CONFIG_USER_RTK_SYSLOG
#ifndef SEND_LOG
  {"System Log", MENU_URL, "syslog.asp", "Show system log", 0, 0, MENU_DISPLAY, LANG_SYSTEM_LOG},
#endif
#endif
#endif //CONFIG_00R0
#ifdef ACCOUNT_LOGIN_CONTROL

	{"Logout", MENU_URL, "/admin/adminlogout.asp", "Logout", 0, 0, MENU_DISPLAY, LANG_LOGOUT},

#endif

	{"Password", MENU_URL, "/admin/user-password.asp", "Setup access password", 0, 0, MENU_DISPLAY, LANG_PASSWORD},
#ifdef CONFIG_00R0
#ifdef WEB_UPGRADE
#ifdef UPGRADE_V1
  {"Firmware Upgrade", MENU_URL, "upgrade.asp", "Firmware Upgrade", 0, 0, MENU_DISPLAY, LANG_FIRMWARE_UPGRADE},
#endif // of UPGRADE_V1
#endif // of WEB_UPGRADE
#endif //CONFIG_00R0
#ifdef IP_ACL

	{"ACL Config", MENU_URL, "acl.asp", "ACL Setting", 0, 0, MENU_DISPLAY, LANG_ACL_CONFIG},

#endif
#ifdef CONFIG_00R0
#ifdef TIME_ZONE
  {"Time Zone", MENU_URL, "tz.asp", "Time Zone Configuration", 0, 0, MENU_DISPLAY, LANG_TIME_ZONE},
#endif
#endif //CONFIG_00R0

//added by xl_yue

#ifndef CONFIG_00R0
#ifdef USE_LOGINWEB_OF_SERVER

	{"Logout", MENU_URL, "/admin/logout.asp", "Logout", 0, 0, MENU_DISPLAY, LANG_LOGOUT},

#endif
#endif

	{0, 0, 0, 0, 0, 0, 0, 0}

};

#ifdef CONFIG_00R0
struct RootMenu childmenu_dns_user[] = {
  //{"DNS Server", MENU_URL, "dns.asp", "DNS Server Configuration", 0, 0, MENU_DISPLAY, LANG_DNS_SERVER},
#ifdef CONFIG_USER_DDNS
  {"Dynamic DNS", MENU_URL, "ddns.asp", "DDNS Configuration", 0, 0, MENU_DISPLAY, LANG_DYNAMIC_DNS},
#endif
  {0, 0, 0, 0, 0, 0, 0, 0}
};

struct RootMenu childmenu_fw_user[] = {
#ifdef CONFIG_IP_NF_ALG_ONOFF
  {"ALG", MENU_URL, "algonoff.asp", "ALG on-off", 0, 0, MENU_DISPLAY, LANG_ALG},
#endif
#ifdef IP_PORT_FILTER
#ifdef CONFIG_RTK_L34_ENABLE
 {"IP/Port Filtering", MENU_URL, "fw-ipportfilter_rg.asp",
  "Setup IP/Port filering", 0, 0, MENU_DISPLAY, LANG_IP_PORT_FILTERING},
#else
  {"IP/Port Filtering", MENU_URL, "fw-ipportfilter.asp",
   "Setup IP/Port filering", 0, 0, MENU_DISPLAY, LANG_IP_PORT_FILTERING},
#endif
#endif
#ifdef MAC_FILTER
#ifdef CONFIG_RTK_L34_ENABLE
	{"MAC Filtering", MENU_URL, "fw-macfilter_rg.asp", "Setup MAC filering", 0, 0, MENU_DISPLAY, LANG_MAC_FILTERING},
#else
  {"MAC Filtering", MENU_URL, "fw-macfilter.asp", "Setup MAC filering", 0, 0, MENU_DISPLAY, LANG_MAC_FILTERING},
#endif
#endif
#ifdef PORT_FORWARD_GENERAL
  {"Port Forwarding", MENU_URL, "fw-portfw.asp", "Setup port-forwarding", 0,
   0, MENU_DISPLAY, LANG_PORT_FORWARDING},
#endif
#ifdef URL_BLOCKING_SUPPORT
  {"URL Blocking", MENU_URL, "url_blocking.asp", "URL Blocking Setting", 0,
   0, MENU_DISPLAY, LANG_URL_BLOCKING},
#endif
#ifdef DOMAIN_BLOCKING_SUPPORT
  {"Domain Blocking", MENU_URL, "domainblk.asp", "Domain Blocking Setting", 0,
   0, MENU_DISPLAY, LANG_DOMAIN_BLOCKING},
#endif
#ifdef PARENTAL_CTRL
  {"Parental Control", MENU_URL, "parental-ctrl.asp", "Parental Control Setting", 0,
   0, MENU_DISPLAY, LANG_PARENTAL_CONTROL},
#endif
#ifdef TCP_UDP_CONN_LIMIT
  {"Connection Limit", MENU_URL, "connlimit.asp", "Connection Limit Setting", 0,
   0, MENU_DISPLAY, LANG_CONNECTION_LIMIT},
#endif // TCP_UDP_CONN_LIMIT
#ifdef NATIP_FORWARDING
  {"NAT IP Forwarding", MENU_URL, "fw-ipfw.asp", "Setup NAT IP Mapping", 0,
   0, MENU_DISPLAY, LANG_NAT_IP_FORWARDING},
#endif
#ifdef PORT_TRIGGERING
  {"Port Triggering", MENU_URL, "gaming.asp", "Setup Port Triggering", 0, 0, MENU_DISPLAY, LANG_PORT_TRIGGERING},
#endif
#ifdef DMZ
  {"DMZ", MENU_URL, "fw-dmz.asp", "Setup DMZ",0, 0, MENU_DISPLAY, LANG_DMZ},
#endif
#ifdef ADDRESS_MAPPING
#ifdef MULTI_ADDRESS_MAPPING
 // Eric Chen add for True
  {"NAT Rule Configuration", MENU_URL, "multi_addr_mapping.asp", "Setup NAT Rule",0, 0, MENU_DISPLAY, LANG_NAT_RULE_CONFIGURATION},
#else //!MULTI_ADDRESS_MAPPING
 // Mason Yu on True
  {"NAT Rule Configuration", MENU_URL, "addr_mapping.asp", "Setup NAT Rule",0, 0, MENU_DISPLAY, LANG_NAT_RULE_CONFIGURATION},
  #endif// end of !MULTI_ADDRESS_MAPPING
#endif
  {0, 0, 0, 0, 0, 0, 0, 0}

};


struct RootMenu childmenu_service_user[] = {
#ifdef CONFIG_USER_DHCP_SERVER
  //{"DHCP Mode", MENU_URL, "dhcpmode.asp", "DHCP Mode Configuration", 0, 0, MENU_DISPLAY},
#ifdef IMAGENIO_IPTV_SUPPORT
  {"DHCP", MENU_URL, "dhcpd_sc.asp", "DHCP Configuration", 0, 0, MENU_DISPLAY, LANG_DHCP},
#else
  {"DHCP", MENU_URL, "dhcpd.asp", "DHCP Configuration", 0, 0, MENU_DISPLAY, LANG_DHCP},
#endif
#endif
#ifdef CONFIG_USER_VLAN_ON_LAN
  {"VLAN on LAN", MENU_URL, "vlan_on_lan.asp", "VLAN on LAN Configuration", 0, 0, MENU_DISPLAY, LANG_VLAN_ON_LAN},
#endif
#ifndef CONFIG_SFU
  {"DNS", MENU_FOLDER, &childmenu_dns_user, "",
   sizeof (childmenu_dns_user) / sizeof (struct RootMenu) - 1, 0, MENU_DISPLAY, LANG_DNS},
  {"Firewall", MENU_FOLDER, &childmenu_fw_user, "",
   sizeof (childmenu_fw_user) / sizeof (struct RootMenu) - 1, 0, MENU_DISPLAY, LANG_FIREWALL},
#endif
#if defined(CONFIG_USER_IGMPPROXY)&&!defined(CONFIG_IGMPPROXY_MULTIWAN)
  {"IGMP Proxy", MENU_URL, "igmproxy.asp", "IGMP Proxy Configuration", 0, 0, MENU_DISPLAY, LANG_IGMP_PROXY},
#endif
#if defined(CONFIG_USER_UPNPD)||defined(CONFIG_USER_MINIUPNPD)
  {"UPnP", MENU_URL, "upnp.asp", "UPnP Configuration", 0, 0, MENU_DISPLAY, LANG_UPNP},
#endif
#ifdef CONFIG_USER_ROUTED_ROUTED
  {"RIP", MENU_URL, "rip.asp", "RIP Configuration", 0, 0, MENU_DISPLAY, LANG_RIP},
#endif
#ifdef WEB_REDIRECT_BY_MAC
  {"Landing Page", MENU_URL, "landing.asp", "Landing Page Configuration", 0, 0, MENU_DISPLAY, LANG_LANDING_PAGE},
#endif
#if defined(CONFIG_USER_MINIDLNA)
	{"DMS", MENU_URL, "dms.asp", "DMS Configuration", 0, 0, MENU_DISPLAY, LANG_DMS},
#endif
#ifdef CONFIG_USER_SAMBA
  {"Samba", MENU_URL, "samba.asp", "Samba Configuration", 0, 0, MENU_DISPLAY, LANG_SAMBA},
#endif
  {0, 0, 0, 0, 0, 0, 0, 0}
};


#ifdef CONFIG_IPV6
struct RootMenu childmenu_ipv6_user[] = {
  {"IPv6", MENU_URL, "ipv6_enabledisable.asp", "IPv6 Enable/Disable Configuration", 0, 0, MENU_DISPLAY, LANG_IPV6},
#if defined(CONFIG_IPV6) && defined(CONFIG_USER_RADVD)
  {"RADVD", MENU_URL, "radvdconf.asp", "RADVD configuration", 0, 0, MENU_DISPLAY, LANG_RADVD},
#endif
#ifdef CONFIG_USER_DHCPV6_ISC_DHCP411
  {"DHCPv6", MENU_URL, "dhcpdv6.asp", "DHCPv6 Configuration", 0, 0, MENU_DISPLAY, LANG_DHCPV6},
#endif
#ifdef CONFIG_USER_ECMH
  {"MLD Proxy", MENU_URL, "app_mldProxy.asp", "MLD Proxy Configuration", 0, 0, MENU_DISPLAY, LANG_MLD_PROXY},
  {"MLD Snooping", MENU_URL, "app_mld_snooping.asp", "MLD Snooping Configuration", 0, 0, MENU_DISPLAY, LANG_MLD_SNOOPING},
#endif
  {"IPv6 Routing", MENU_URL, "routing_ipv6.asp", "IPv6 Routing Configuration", 0, 0, MENU_DISPLAY, LANG_IPV6_ROUTING},
#ifdef IP_PORT_FILTER
#ifdef CONFIG_IPV6_OLD_FILTER
#ifdef CONFIG_RTK_L34_ENABLE
  {"IP/Port Filtering", MENU_URL, "fw-ipportfilter-v6_rg.asp", "Setup IPv6/Port filering", 0, 0, MENU_DISPLAY, LANG_IP_PORT_FILTERING},
#else
  {"IP/Port Filtering", MENU_URL, "fw-ipportfilter-v6.asp", "Setup IPv6/Port filering", 0, 0, MENU_DISPLAY, LANG_IP_PORT_FILTERING},
#endif
#else
#ifdef CONFIG_RTK_L34_ENABLE
  {"IP/Port Filtering", MENU_URL, "fw-ipportfilter-v6_IfId_rg.asp", "Setup IPv6/Port filering", 0, 0, MENU_DISPLAY, LANG_IP_PORT_FILTERING},
#else
  {"IP/Port Filtering", MENU_URL, "fw-ipportfilter-v6_IfId.asp", "Setup IPv6/Port filering", 0, 0, MENU_DISPLAY, LANG_IP_PORT_FILTERING},
#endif
#endif  
#endif
  {0, 0, 0, 0, 0, 0, 0, 0}
};
#endif



struct RootMenu childmenu_adv_user[] = {
#ifdef CONFIG_RTL9601B_SERIES
  {"VLAN Settings", MENU_URL, "vlan.asp", "VLAN Settings", 0, 0, MENU_DISPLAY, LANG_VLAN_SETTINGS},
#endif
  {"ARP Table", MENU_URL, "arptable.asp", "ARP Table", 0, 0, MENU_DISPLAY, LANG_ARP_TABLE},
#ifndef CONFIG_SFU
  {"Bridging", MENU_URL, "bridging.asp", "Bridge Configuration", 0, 0, MENU_DISPLAY, LANG_BRIDGING},
#endif
#ifdef ROUTING
  {"Routing", MENU_URL, "routing.asp", "Routing Configuration", 0, 0, MENU_DISPLAY, LANG_ROUTING},
#endif
#ifdef CONFIG_USER_SNMPD_SNMPD_V2CTRAP
  {"SNMP", MENU_URL, "snmp.asp", "SNMP Protocol Configuration", 0, 0, MENU_DISPLAY, LANG_SNMP},
#endif
#ifdef CONFIG_USER_BRIDGE_GROUPING
  {"Bridge Grouping", MENU_URL, "bridge_grouping.asp", "Bridge Grouping Configuration", 0, 0, MENU_DISPLAY, LANG_BRIDGE_GROUPING},
#if 0//def CONFIG_RTK_L34_ENABLE // Rostelecom, Port Binding function
  {"VLAN Mapping", MENU_URL, "vlan_mapping.asp", "VLAN Mapping Configuration", 0, 0, MENU_DISPLAY, LANG_VLAN_MAPPING},
#endif
#endif
#ifdef VLAN_GROUP
  {"Port Mapping", MENU_URL, "eth2pvc_vlan.asp", "Port-vlan mapping", 0, 0, MENU_DISPLAY, LANG_PORT_MAPPING},
#endif
#ifdef QOS_DIFFSERV
  {"DiffServ", MENU_URL, "diffserv.asp", "Differentiated Services Setting", 0, 0, MENU_DISPLAY, LANG_DIFFSERV},
#endif
#if defined(CONFIG_RTL_MULTI_LAN_DEV)
#ifdef ELAN_LINK_MODE
  {"Link Mode", MENU_URL, "linkmode.asp", "Ethernet Link Mode Setting", 0, 0, MENU_DISPLAY, LANG_LINK_MODE},
#endif
#else
#ifdef ELAN_LINK_MODE_INTRENAL_PHY
	{"Link Mode", MENU_URL, "linkmode_eth.asp", "Ethernet Link Mode Setting", 0, 0, MENU_DISPLAY, LANG_LINK_MODE},
#endif
#endif
#ifdef REMOTE_ACCESS_CTL
  {"Remote Access", MENU_URL, "rmtacc.asp", "Services Access Control", 0, 0, MENU_DISPLAY, LANG_REMOTE_ACCESS},
#endif
#ifdef IP_PASSTHROUGH
  {"Others", MENU_URL, "others.asp", "Other advanced Configuration", 0, 0, MENU_DISPLAY, LANG_OTHERS},
#endif
#ifdef CONFIG_IPV6
  {"IPv6", MENU_FOLDER, &childmenu_ipv6_user, "",
  sizeof (childmenu_ipv6_user) / sizeof (struct RootMenu) - 1, 0, MENU_DISPLAY, LANG_IPV6},
#endif
  {0, 0, 0, 0, 0, 0, 0, 0}
};

struct RootMenu childmenu_diag_user[] = {
  {"Ping", MENU_URL, "ping.asp", "Ping Diagnostics", 0, 0, MENU_DISPLAY, LANG_PING},
#ifdef CONFIG_USER_TCPDUMP_WEB
  {"Packet Dump", MENU_URL, "pdump.asp", "Packet Dump Diagnostics", 0, 0, MENU_DISPLAY, LANG_PACKET_DUMP},
#endif
  {ATM_LOOPBACK_STR, MENU_URL, "oamloopback.asp", "ATM Loopback Diagnostics", 0, 0, MENU_HIDDEN, LANG_ATM_LOOPBACK},
  {ADSL_TONE_STR, MENU_URL, "/admin/adsl-diag.asp", "ADSL Tone Diagnostics", 0, 0, MENU_HIDDEN, LANG_DSL_TONE},
#ifdef CONFIG_USER_XDSL_SLAVE
  {ADSL_SLV_TONE_STR, MENU_URL, "/admin/adsl-slv-diag.asp", "ADSL Slave Tone Diagnostics", 0, 0, MENU_HIDDEN, LANG_DSL_SLAVE_TONE},
#endif /*CONFIG_USER_XDSL_SLAVE*/
#ifdef DIAGNOSTIC_TEST
  {ADSL_CONNECTION_STR, MENU_URL, "diag-test.asp", "ADSL Connection Diagnostics", 0, 0, MENU_HIDDEN, LANG_ADSL_CONNECTION},
#endif
#ifdef CONFIG_USER_DOT1AG_UTILS
  {"802.1ag", MENU_FOLDER, &childmenu_dot1ag, "", sizeof (childmenu_dot1ag) / sizeof (struct RootMenu) - 1, 0, MENU_DISPLAY, LANG_802_1AG},
#endif
  {0, 0, 0, 0, 0, 0, 0, 0}
};

struct RootMenu childmenu_statis_user[] = {
#ifdef CONFIG_SFU
{"Statistics", MENU_URL, "stats.asp", "Display packet statistics", 0, 0, MENU_DISPLAY, LANG_STATISTICS},
#else
  {"Interface", MENU_URL, "stats.asp", "Display packet statistics", 0, 0, MENU_DISPLAY, LANG_INTERFACE},
#endif
  {ADSL_STR, MENU_URL, "/admin/adsl-stats.asp",
#ifdef CONFIG_VDSL
  	"Display DSL statistics",
#else
  	"Display ADSL statistics",
#endif /*CONFIG_VDSL*/
  	0, 0, MENU_HIDDEN, LANG_DSL},

#ifdef CONFIG_DSL_VTUO
  {VTUO_STATUS_STR, MENU_URL, "/admin/vtuo-stats.asp", "Display VTU-O DSL statistics", 0, 0, MENU_HIDDEN, LANG_VTUO_DSL},
#endif /*CONFIG_DSL_VTUO*/

#ifdef CONFIG_USER_XDSL_SLAVE
  {ADSL_SLV_STR, MENU_URL, "/admin/adsl-slv-stats.asp",
#ifdef CONFIG_VDSL
  	"Display DSL Slave statistics",
#else
  	"Display ADSL Slave statistics",
#endif /*CONFIG_VDSL*/
  	0, 0, MENU_HIDDEN, LANG_DSL_SLAVE},
#endif /*CONFIG_USER_XDSL_SLAVE*/

#if defined(CONFIG_GPON_FEATURE) || defined(CONFIG_EPON_FEATURE)
  {PON_STR, MENU_URL, "/admin/pon-stats.asp", "Display PON Statistics", 0, 0, MENU_DISPLAY, LANG_PON},
#endif /*CONFIG_DSL_VTUO*/

  {0, 0, 0, 0, 0, 0, 0, 0}
};
#endif //CONFIG_00R0

/*

 *	Root Menu

 */

struct RootMenu rootmenu_user[] = {

	{"Status", MENU_FOLDER, &childmenu_status_user, "", sizeof(childmenu_status_user) / sizeof(struct RootMenu) - 1, 0, MENU_DISPLAY, LANG_STATUS},
#ifdef CONFIG_00R0
	{"Wizard", MENU_URL, "wizard_screen_menu.asp", "Setup Wizard", 0, 0, MENU_DISPLAY, LANG_WIZARD},
	{"LAN", MENU_URL, "tcpiplan.asp", "Setup LAN Interface", 0, 0, MENU_DISPLAY, LANG_LAN},
#endif

#ifdef WLAN_SUPPORT

	{"Wireless", MENU_FOLDER, &childmenu_wlan_user, "", sizeof(childmenu_wlan_user) / sizeof(struct RootMenu) - 1, 0, MENU_DISPLAY, LANG_WIRELESS},

#endif

#ifdef CONFIG_00R0 //Display PPPOE WAN user & password only.
	{"WAN", MENU_FOLDER, &childmenu_wan_user, "", sizeof(childmenu_wan_user) / sizeof(struct RootMenu) - 1, 0, MENU_DISPLAY, LANG_WAN},
#ifdef CONFIG_USER_DHCP_SERVER
/*if configure SFU but want have dhcp server*/
	{"Services", MENU_FOLDER, &childmenu_service_user, "", sizeof (childmenu_service_user) / sizeof (struct RootMenu) - 1, 0, MENU_DISPLAY, LANG_SERVICES},
#endif
	{"Advance", MENU_FOLDER, &childmenu_adv_user, "", sizeof (childmenu_adv_user) / sizeof (struct RootMenu) - 1, 0, MENU_DISPLAY, LANG_ADVANCE},
	{"Diagnostics", MENU_FOLDER, &childmenu_diag_user, "", sizeof (childmenu_diag_user) / sizeof (struct RootMenu) - 1, 0, MENU_DISPLAY, LANG_DIAGNOSTICS},
#else
	{"WAN", MENU_FOLDER, &childmenu_wan_user, "", sizeof(childmenu_wan_user) / sizeof(struct RootMenu) - 1, 0, MENU_DISPLAY, LANG_WAN},
	{"Firewall", MENU_FOLDER, &childmenu_fw_user, "", sizeof(childmenu_fw_user) / sizeof(struct RootMenu) - 1, 0, MENU_DISPLAY, LANG_FIREWALL},
#endif //CONFIG_00R0
	{"Admin", MENU_FOLDER, &childmenu_admin_user, "", sizeof(childmenu_admin_user) / sizeof(struct RootMenu) - 1, 0, MENU_DISPLAY, LANG_ADMIN},
#ifdef CONFIG_00R0
	{"Statistics", MENU_FOLDER, &childmenu_statis_user, "", sizeof (childmenu_statis_user) / sizeof (struct RootMenu) - 1, 0, MENU_DISPLAY, LANG_STATISTICS},
#if defined(USE_LOGINWEB_OF_SERVER)&&defined(CONFIG_00R0)
	{"Logout", MENU_URL, "/admin/logout.asp", "Logout", 0, 0, MENU_DISPLAY, LANG_LOGOUT},
#endif
#endif //CONFIG_00R0
	{0, 0, 0, 0, 0, 0, 0, 0}

};

#endif				// of CONFIG_DEFAULT_WEB


int createMenu_user(int eid, request * wp, int argc, char ** argv)
{
	int i = 0, totalIdNums = 0, maxchildrensize = 0;

	int IdIndex = 0;

	unsigned char isRootMenuEnd = 0;

#ifdef CONFIG_RTL_92D_SUPPORT

	wlanMenuUpdate(rootmenu);

	wlanMenuUpdate(rootmenu_user);

#endif //CONFIG_RTL_92D_SUPPORT


	//calc the id nums and the max children size

	totalIdNums = calcFolderNum(rootmenu_user, &maxchildrensize);

	//product the js code

	addMenuJavaScript(wp, totalIdNums, maxchildrensize);

	//create the header
/* add by yq_zhou 09.2.02 add sagem logo for 11n*/
#ifdef CONFIG_11N_SAGEM_WEB
  boaWrite (wp, "<body  onload=\"initIt()\" bgcolor=\"#FFFFFF\" >\n");
#else
  boaWrite (wp, "<body  onload=\"initIt()\" bgcolor=\"#000000\" >\n");
#endif
	boaWrite(wp, "<table width=100%% border=0 cellpadding=0 cellspacing=0>\n<tr><td  width=100%% align=left>\n");

	boaWrite(wp, "<table border=0 cellpadding=0 cellspacing=0>\n" "<tr><td width=18 height=18><img src=menu-images/menu_root.gif width=18 height=18></td>\n" "<td  height=18 colspan=4 class=link><font size=3>%s:</font></td></tr>\n</table>\n", multilang(LANG_SITE_CONTENTS));



	if (rootmenu_user[1].u.addr)

		addMenu(wp, &rootmenu_user[0], 0, &IdIndex, 0);

	else

		addMenu(wp, &rootmenu_user[0], 0, &IdIndex, 1);



	boaWrite(wp, "</td></tr>\n</table>\n");


	return 0;
}
