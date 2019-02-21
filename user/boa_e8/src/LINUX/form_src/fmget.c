/*
 *      Web server handler routines for get info and index (getinfo(), getindex())
 *      Authors: David Hsu	<davidhsu@realtek.com.tw>
 *      Authors: Dick Tam	<dicktam@realtek.com.tw>
 *
 */

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <sys/sysinfo.h>
#ifdef EMBED
#include <linux/config.h>
#include <config/autoconf.h>
#else
#include "../../../../include/linux/autoconf.h"
#include "../../../../config/autoconf.h"
#endif

#include "../webs.h"
#include "mib.h"
#include "utility.h"
#include "../../port.h"
#include "devtree.h"
#include "multilang.h"
#include <sys/ioctl.h>
//added by xl_yue
#include "../defs.h"
#ifdef WLAN_SUPPORT
#include <linux/wireless.h>
#endif
// Mason Yu. t123
#include "webform.h"
#if defined(CONFIG_RTK_L34_ENABLE) && defined(CONFIG_USER_LAN_PORT_AS_ETH_WAN)
#include <rtk_rg_define.h>
#endif

#if defined(CONFIG_USER_DDNS) && (defined(CONFIG_CMCC) || defined(CONFIG_CU))
typedef enum {DDNS_RESYLT_INIT=0, DDNS_RESYLT_SUCCESS, DDNS_RESYLT_FAIL, DDNS_RESYLT_DISABLE} DDNS_RESULT_CODE_T;
unsigned char *ddnsResultChineseString[4] = {
	"初始化中",
	"注册成功",
	"连接失败",
	"去使能"
};
#endif

#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
#define CA_STATUS_FILE  "/tmp/ca_status"
#endif
// remote config status flag: 0: disabled, 1: enabled
int g_remoteConfig=0;
int g_remoteAccessPort=51003;

// Added by Mason Yu
extern char suName[MAX_NAME_LEN];
extern char usName[MAX_NAME_LEN];
// Mason Yu on True
extern unsigned char g_login_username[MAX_NAME_LEN];

#if defined(CONFIG_USER_DDNS) && (defined(CONFIG_CMCC) || defined(CONFIG_CU))
int get_ddns_result_code()
{
	unsigned char	ddnsEnable = 1;
	int num;
	MIB_CE_DDNS_T Entry;
	FILE *fp;
	int status;
	int fh;
	char filename[256]={0};
		
	mib_get(MIB_DDNS_ENABLE,(void*)&ddnsEnable);
	num = mib_chain_total(MIB_DDNS_TBL);
	if(mib_chain_get(MIB_DDNS_TBL,0,(void*)&Entry)!=1){
		return DDNS_RESYLT_INIT;
	}

	if(ddnsEnable == 0 || strcmp(Entry.username, "")==0 || strcmp(Entry.password, "")==0){
		return DDNS_RESYLT_DISABLE;
	}

	sprintf(filename, "/var/%s.%s.%s.txt", Entry.provider, Entry.username, Entry.password);
	fh = open(filename, O_RDWR);
	if ( fh == -1 ) return DDNS_RESYLT_INIT;
	if ((fp = fdopen(fh, "r")) == NULL) return DDNS_RESYLT_INIT;
	fscanf(fp, "%d", &status);
	fclose(fp);
	close(fh);

	if(status==0){
		return DDNS_RESYLT_SUCCESS;
	}
	else{
		return DDNS_RESYLT_FAIL;
	}

	return DDNS_RESYLT_INIT;
}
#endif

#ifdef WLAN_SUPPORT
void translate_control_code(char *buffer)
{
	char tmpBuf[200], *p1 = buffer, *p2 = tmpBuf;


	while (*p1) {
		if (*p1 == '"') {
			memcpy(p2, "&quot;", 6);
			p2 += 6;
		}
		else if (*p1 == '\x27') {
			memcpy(p2, "&#39;", 5);
			p2 += 5;
		}
		else if (*p1 == '\x5c') {
			memcpy(p2, "&#92;", 5);
			p2 += 5;
		}
		else if (*p1 =='<'){
			memcpy(p2, "&lt;", 4);
			p2 += 4;
		}
		else if (*p1 =='>'){
			memcpy(p2, "&gt;", 4);
			p2 += 4;
		}
		else
			*p2++ = *p1;
		p1++;
	}
	*p2 = '\0';

	strcpy(buffer, tmpBuf);
}
#endif

// Kaohj
typedef enum {
	INFO_MIB,
	INFO_SYS
} INFO_T;

typedef struct {
	char *cmd;
	INFO_T type;
	int id;
} web_get_cmd;

typedef struct {
	char *cmd;
	int (*handler)(int , request* , int , char **, char *);
} web_custome_cmd;

web_get_cmd get_info_list[] = {
	{"lan-ip", INFO_MIB, MIB_ADSL_LAN_IP},
	{"lan-subnet", INFO_MIB, MIB_ADSL_LAN_SUBNET},
	{"lan-ip2", INFO_MIB, MIB_ADSL_LAN_IP2},
	{"lan-subnet2", INFO_MIB, MIB_ADSL_LAN_SUBNET2},
	// Kaohj
	#ifndef DHCPS_POOL_COMPLETE_IP
	{"lan-dhcpRangeStart", INFO_MIB, MIB_ADSL_LAN_CLIENT_START},
	{"lan-dhcpRangeEnd", INFO_MIB, MIB_ADSL_LAN_CLIENT_END},
	#else
	{"lan-dhcpRangeStart", INFO_MIB, MIB_DHCP_POOL_START},
	{"lan-dhcpRangeEnd", INFO_MIB, MIB_DHCP_POOL_END},
	#endif
	{"lan-dhcpSubnetMask", INFO_MIB, MIB_DHCP_SUBNET_MASK},
	{"dhcps-dns1", INFO_MIB, MIB_DHCPS_DNS1},
	{"dhcps-dns2", INFO_MIB, MIB_DHCPS_DNS2},
	{"dhcps-dns3", INFO_MIB, MIB_DHCPS_DNS3},
	{"lan-dhcpLTime", INFO_MIB, MIB_ADSL_LAN_DHCP_LEASE},
	{"lan-dhcpDName", INFO_MIB, MIB_ADSL_LAN_DHCP_DOMAIN},
	{"elan-Mac", INFO_MIB, MIB_ELAN_MAC_ADDR},
	{"wlan-Mac", INFO_MIB, MIB_WLAN_MAC_ADDR},
	{"wan-dns1", INFO_MIB, MIB_ADSL_WAN_DNS1},
	{"wan-dns2", INFO_MIB, MIB_ADSL_WAN_DNS2},
	{"wan-dns3", INFO_MIB, MIB_ADSL_WAN_DNS3},
	{"wan-dhcps", INFO_MIB, MIB_ADSL_WAN_DHCPS},
	{"dmzHost", INFO_MIB, MIB_DMZ_IP},
#ifdef CONFIG_USER_SNMPD_SNMPD_V2CTRAP
	{"snmpSysDescr", INFO_MIB, MIB_SNMP_SYS_DESCR},
	{"snmpSysContact", INFO_MIB, MIB_SNMP_SYS_CONTACT},
	{"snmpSysLocation", INFO_MIB, MIB_SNMP_SYS_LOCATION},
	{"snmpSysObjectID", INFO_MIB, MIB_SNMP_SYS_OID},
	{"snmpTrapIpAddr", INFO_MIB, MIB_SNMP_TRAP_IP},
	{"snmpCommunityRO", INFO_MIB, MIB_SNMP_COMM_RO},
	{"snmpCommunityRW", INFO_MIB, MIB_SNMP_COMM_RW},
	{"name", INFO_MIB, MIB_SNMP_SYS_NAME},
#endif
	{"snmpSysName", INFO_MIB, MIB_SNMP_SYS_NAME},
	{"name", INFO_MIB, MIB_SNMP_SYS_NAME},
#ifdef TIME_ZONE
	{"ntpTimeZoneDBIndex", INFO_MIB, MIB_NTP_TIMEZONE_DB_INDEX},
	{"ntpServerHost1", INFO_MIB, MIB_NTP_SERVER_HOST1},
	{"ntpServerHost2", INFO_MIB, MIB_NTP_SERVER_HOST2},
#endif
	{"uptime", INFO_SYS, SYS_UPTIME},
	{"date", INFO_SYS, SYS_DATE},
	{"year", INFO_SYS, SYS_YEAR},
	{"month", INFO_SYS, SYS_MONTH},
	{"day", INFO_SYS, SYS_DAY},
	{"hour", INFO_SYS, SYS_HOUR},
	{"minute", INFO_SYS, SYS_MINUTE},
	{"second", INFO_SYS, SYS_SECOND},
	{"fwVersion", INFO_SYS, SYS_FWVERSION},
	{"stVer", INFO_SYS, SYS_FWVERSION},
	{"buildtime", INFO_SYS, SYS_BUILDTIME},
	{"dhcplan-ip", INFO_SYS, SYS_DHCP_LAN_IP},
	{"dhcplan-subnet", INFO_SYS, SYS_DHCP_LAN_SUBNET},
	{"dslstate", INFO_SYS, SYS_DSL_OPSTATE},
	{"bridge-ageingTime", INFO_MIB, MIB_BRCTL_AGEINGTIME},
#ifdef CONFIG_USER_IGMPPROXY
	{"igmp-proxy-itf", INFO_MIB, MIB_IGMP_PROXY_ITF},
#endif
//#ifdef CONFIG_USER_UPNPD
#if defined(CONFIG_USER_UPNPD)||defined(CONFIG_USER_MINIUPNPD)
	{"upnp-ext-itf", INFO_MIB, MIB_UPNP_EXT_ITF},
#endif

#ifdef CONFIG_IPV6
#ifdef CONFIG_USER_ECMH
	{"mldproxy-ext-itf", INFO_MIB, MIB_MLD_PROXY_EXT_ITF}, 		// Mason Yu. MLD Proxy
#endif
#endif

#ifdef AUTO_PROVISIONING
	{"http-ip", INFO_MIB, MIB_HTTP_SERVER_IP},
#endif
#ifdef IP_PASSTHROUGH
	{"ippt-itf", INFO_MIB, MIB_IPPT_ITF},
	{"ippt-lease", INFO_MIB, MIB_IPPT_LEASE},
	{"ippt-lanacc", INFO_MIB, MIB_IPPT_LANACC},
#endif
#ifdef WLAN_SUPPORT
	{"ssid", INFO_SYS, SYS_WLAN_SSID},
	{"channel", INFO_MIB, MIB_WLAN_CHAN_NUM},
	{"fragThreshold", INFO_MIB, MIB_WLAN_FRAG_THRESHOLD},
	{"rtsThreshold", INFO_MIB, MIB_WLAN_RTS_THRESHOLD},
	{"beaconInterval", INFO_MIB, MIB_WLAN_BEACON_INTERVAL},
	{"wlanDisabled",INFO_SYS,SYS_WLAN_DISABLED},
	{"hidden_ssid",INFO_SYS,SYS_WLAN_HIDDEN_SSID},
	{"pskValue", INFO_SYS, SYS_WLAN_PSKVAL},
	{"WiFiTest", INFO_MIB, MIB_WIFI_TEST},
#ifdef WLAN_1x
	{"rsPort",INFO_SYS,SYS_WLAN_RS_PORT},
	{"rsIp",INFO_SYS,SYS_WLAN_RS_IP},
	{"rsPassword",INFO_SYS,SYS_WLAN_RS_PASSWORD},
	{"enable1X", INFO_SYS,SYS_WLAN_ENABLE_1X},
#endif
	{"wlanMode",INFO_SYS,SYS_WLAN_MODE_VAL},
	{"encrypt",INFO_SYS,SYS_WLAN_ENCRYPT_VAL},
	{"wpa_cipher",INFO_SYS,SYS_WLAN_WPA_CIPHER_SUITE},
	{"wpa2_cipher",INFO_SYS,SYS_WLAN_WPA2_CIPHER_SUITE},
	{"wpaAuth",INFO_SYS,SYS_WLAN_WPA_AUTH},
	{"networkType",INFO_MIB,MIB_WLAN_NETWORK_TYPE},

#ifdef CONFIG_WIFI_SIMPLE_CONFIG // WPS
	{"wscDisable",INFO_SYS,SYS_WSC_DISABLE},
	//{"wscConfig",INFO_MIB,MIB_WSC_CONFIGURED},
	{"wps_auth",INFO_SYS,SYS_WSC_AUTH},
	{"wps_enc",INFO_SYS,SYS_WSC_ENC},
	{"wscLoocalPin", INFO_MIB, MIB_WSC_PIN},

#endif

#ifdef WLAN_WDS
	{"wlanWdsEnabled",INFO_MIB,MIB_WLAN_WDS_ENABLED},
#endif
#ifdef WLAN_UNIVERSAL_REPEATER
	{"repeaterSSID", INFO_MIB, MIB_REPEATER_SSID1},
#endif
#endif // of WLAN_SUPPORT
	//{ "dnsServer", INFO_SYS, SYS_DNS_SERVER},
	{"maxmsglen",INFO_MIB,MIB_MAXLOGLEN},
#ifdef _CWMP_MIB_
#ifdef CONFIG_TR142_MODULE
	//{"acs-url", INFO_MIB, RS_CWMP_USED_ACS_URL},
#else
	{"acs-url", INFO_MIB, CWMP_ACS_URL},
#endif
	{"acs-username", INFO_MIB, CWMP_ACS_USERNAME},
	{"acs-password", INFO_MIB, CWMP_ACS_PASSWORD},
	{"inform-interval", INFO_MIB, CWMP_INFORM_INTERVAL},
	{"conreq-name", INFO_MIB, CWMP_CONREQ_USERNAME},
	{"conreq-pw", INFO_MIB, CWMP_CONREQ_PASSWORD},
	{"cert-pw", INFO_MIB, CWMP_CERT_PASSWORD},
	{"conreq-path", INFO_MIB, CWMP_CONREQ_PATH},
	{"conreq-port", INFO_MIB, CWMP_CONREQ_PORT},
#endif
#ifdef CONFIG_MIDDLEWARE
	{"midwareServerAddr", INFO_MIB, CWMP_MIDWARE_SERVER_ADDR},
	{"midwareServerPort", INFO_MIB, CWMP_MIDWARE_SERVER_PORT},
#endif
#ifdef DOS_SUPPORT
	{"syssynFlood", INFO_MIB, MIB_DOS_SYSSYN_FLOOD},
	{"sysfinFlood", INFO_MIB, MIB_DOS_SYSFIN_FLOOD},
	{"sysudpFlood", INFO_MIB, MIB_DOS_SYSUDP_FLOOD},
	{"sysicmpFlood", INFO_MIB, MIB_DOS_SYSICMP_FLOOD},
	{"pipsynFlood", INFO_MIB, MIB_DOS_PIPSYN_FLOOD},
	{"pipfinFlood", INFO_MIB, MIB_DOS_PIPFIN_FLOOD},
	{"pipudpFlood", INFO_MIB, MIB_DOS_PIPUDP_FLOOD},
	{"pipicmpFlood", INFO_MIB, MIB_DOS_PIPICMP_FLOOD},
	{"blockTime", INFO_MIB, MIB_DOS_BLOCK_TIME},
#endif
	{"lan-dhcp-gateway", INFO_MIB, MIB_ADSL_LAN_DHCP_GATEWAY},
#ifdef ADDRESS_MAPPING
#ifndef MULTI_ADDRESS_MAPPING
	{"local-s-ip", INFO_MIB, MIB_LOCAL_START_IP},
	{"local-e-ip", INFO_MIB, MIB_LOCAL_END_IP},
	{"global-s-ip", INFO_MIB, MIB_GLOBAL_START_IP},
	{"global-e-ip", INFO_MIB, MIB_GLOBAL_END_IP},
#endif //!MULTI_ADDRESS_MAPPING
#endif
#ifdef CONFIG_USER_RTK_SYSLOG
	{"log-level", INFO_MIB, MIB_SYSLOG_LOG_LEVEL},
	{"display-level", INFO_MIB, MIB_SYSLOG_DISPLAY_LEVEL},
#ifdef CONFIG_USER_RTK_SYSLOG_REMOTE
	{"syslog-mode", INFO_MIB, MIB_SYSLOG_MODE},
	{"syslog-server-ip", INFO_MIB, MIB_SYSLOG_SERVER_IP},
	{"syslog-server-port", INFO_MIB, MIB_SYSLOG_SERVER_PORT},
#endif
#ifdef SEND_LOG
	{"log-server-ip", INFO_MIB, MIB_LOG_SERVER_IP},
	{"log-server-username", INFO_MIB, MIB_LOG_SERVER_NAME},
#endif
#endif
#ifdef TCP_UDP_CONN_LIMIT
	{"connLimit-tcp", INFO_MIB, MIB_CONNLIMIT_TCP},
	{"connLimit-udp", INFO_MIB, MIB_CONNLIMIT_UDP},
#endif
#ifdef WEB_REDIRECT_BY_MAC
	{"landing-page-time", INFO_MIB, MIB_WEB_REDIR_BY_MAC_INTERVAL},
#endif
	{"super-user", INFO_MIB, MIB_SUSER_NAME},
	{"normal-user", INFO_MIB, MIB_USER_NAME},
#ifdef DEFAULT_GATEWAY_V2
	{"wan-default-gateway", INFO_MIB, MIB_ADSL_WAN_DGW_IP},
	{"itf-default-gateway", INFO_MIB, MIB_ADSL_WAN_DGW_ITF},
#endif
//ql 20090119
#ifdef IMAGENIO_IPTV_SUPPORT
	{"stb-dns1", INFO_MIB, MIB_IMAGENIO_DNS1},
	{"stb-dns2", INFO_MIB, MIB_IMAGENIO_DNS2},
	{"opch-addr", INFO_MIB, MIB_OPCH_ADDRESS},
	{"opch-port", INFO_MIB, MIB_OPCH_PORT},
#endif

#ifdef CONFIG_IPV6
#ifdef CONFIG_USER_RADVD
	{"V6MaxRtrAdvInterval", INFO_MIB, MIB_V6_MAXRTRADVINTERVAL},
	{"V6MinRtrAdvInterval", INFO_MIB, MIB_V6_MINRTRADVINTERVAL},
	{"V6AdvCurHopLimit", INFO_MIB, MIB_V6_ADVCURHOPLIMIT},
	{"V6AdvDefaultLifetime", INFO_MIB, MIB_V6_ADVDEFAULTLIFETIME},
	{"V6AdvReachableTime", INFO_MIB, MIB_V6_ADVREACHABLETIME},
	{"V6AdvRetransTimer", INFO_MIB, MIB_V6_ADVRETRANSTIMER},
	{"V6AdvLinkMTU", INFO_MIB, MIB_V6_ADVLINKMTU},
	{"V6prefix_ip", INFO_MIB, MIB_V6_PREFIX_IP},
	{"V6prefix_len", INFO_MIB, MIB_V6_PREFIX_LEN},
	{"V6ValidLifetime", INFO_MIB, MIB_V6_VALIDLIFETIME},
	{"V6PreferredLifetime", INFO_MIB, MIB_V6_PREFERREDLIFETIME},
#endif

#ifdef CONFIG_USER_DHCPV6_ISC_DHCP411
	{"dhcpv6s_prefix_length", INFO_MIB, MIB_DHCPV6S_PREFIX_LENGTH},
	{"dhcpv6s_range_start", INFO_MIB, MIB_DHCPV6S_RANGE_START},
	{"dhcpv6s_range_end", INFO_MIB, MIB_DHCPV6S_RANGE_END},
	{"dhcpv6s_default_LTime", INFO_MIB, MIB_DHCPV6S_DEFAULT_LEASE},
	{"dhcpv6s_preferred_LTime", INFO_MIB, MIB_DHCPV6S_PREFERRED_LIFETIME},
	{"dhcpv6_mode", INFO_SYS, SYS_DHCPV6_MODE},
	{"dhcpv6_relay_itf", INFO_SYS, SYS_DHCPV6_RELAY_UPPER_ITF},
	{"dhcpv6s_renew_time", INFO_MIB, MIB_DHCPV6S_RENEW_TIME},
	{"dhcpv6s_rebind_time", INFO_MIB, MIB_DHCPV6S_REBIND_TIME},
	{"dhcpv6s_clientID", INFO_MIB, MIB_DHCPV6S_CLIENT_DUID},
	{"dhcpv6s_min_address", INFO_MIB, MIB_DHCPV6S_MIN_ADDRESS},
	{"dhcpv6s_max_address", INFO_MIB, MIB_DHCPV6S_MAX_ADDRESS},
	{"dhcpv6s_prefix", INFO_MIB, MIB_IPV6_LAN_PREFIX}, //from IPV6_LAN_PREFIX
	{"dhcpv6s_dnsassignmode", INFO_MIB, MIB_DHCPV6S_DNS_ASSIGN_MODE},
	{"dhcpv6s_pooladdrformat", INFO_MIB, MIB_DHCPV6S_POOL_ADDR_FORMAT},
#endif
	{"ip6_ll", INFO_SYS, SYS_LAN_IP6_LL},
	{"ip6_ll_no_prefix", INFO_SYS, SYS_LAN_IP6_LL_NO_PREFIX},
	{"ip6_global", INFO_SYS, SYS_LAN_IP6_GLOBAL},
#endif // of CONFIG_IPV6

#ifdef CONFIG_RTL_WAPI_SUPPORT
	{ "wapiUcastReKeyType", INFO_MIB, MIB_WLAN_WAPI_UCAST_REKETTYPE},
	{ "wapiUcastTime", INFO_MIB, MIB_WLAN_WAPI_UCAST_TIME},
	{ "wapiUcastPackets", INFO_MIB, MIB_WLAN_WAPI_UCAST_PACKETS},
	{ "wapiMcastReKeyType", INFO_MIB, MIB_WLAN_WAPI_MCAST_REKEYTYPE},
	{ "wapiMcastTime", INFO_MIB, MIB_WLAN_WAPI_MCAST_TIME},
	{ "wapiMcastPackets", INFO_MIB, MIB_WLAN_WAPI_MCAST_PACKETS},
#endif
#ifdef CONFIG_IPV6
	{"wan-dnsv61", INFO_MIB, MIB_ADSL_WAN_DNSV61},
	{"wan-dnsv62", INFO_MIB, MIB_ADSL_WAN_DNSV62},
	{"wan-dnsv63", INFO_MIB, MIB_ADSL_WAN_DNSV63},
#endif
	{"wan_mode", INFO_MIB, MIB_WAN_MODE},
#ifdef CONFIG_RTK_L34_ENABLE
	{"mac_based_tag_decision", INFO_MIB, MIB_MAC_BASED_TAG_DECISION},
	{"lan_vlan_id1", INFO_MIB, MIB_LAN_VLAN_ID1},
	{"lan_vlan_id2", INFO_MIB, MIB_LAN_VLAN_ID2},
#endif
	{"loid", INFO_MIB, MIB_LOID},
#ifdef _PRMT_X_CT_COM_USERINFO_
	{"cwmp_UserInfo_Status", INFO_MIB, CWMP_USERINFO_STATUS},
#endif
	{"rtk_manufacturer", INFO_MIB, RTK_DEVID_MANUFACTURER},
	{"rtk_oui", INFO_MIB, RTK_DEVID_OUI},
	{"rtk_productclass", INFO_MIB, RTK_DEVID_PRODUCTCLASS},
	{"rtk_serialno", INFO_MIB, MIB_HW_SERIAL_NUMBER},
	{"cwmp_provisioningcode", INFO_MIB, CWMP_PROVISIONINGCODE},
	{"rtk_specver", INFO_MIB, RTK_DEVINFO_SPECVER},
	{"rtk_swver", INFO_MIB, RTK_DEVINFO_SWVER},
	{"rtk_hwver", INFO_MIB, RTK_DEVINFO_HWVER},
#if defined(CONFIG_GPON_FEATURE)
	{"gpon_sn",INFO_MIB,MIB_GPON_SN},
#endif
	{"elan_mac_addr", INFO_MIB, MIB_ELAN_MAC_ADDR},
#ifdef CONFIG_IPV6
	{"prefix-mode", INFO_MIB, MIB_PREFIXINFO_PREFIX_MODE},
	{"prefix-delegation-wan-conn", INFO_MIB, MIB_PREFIXINFO_DELEGATED_WANCONN},
	{"dns-mode", INFO_MIB, MIB_LAN_DNSV6_MODE},
	{"dns-wan-conn", INFO_MIB, MIB_DNSINFO_WANCONN},
#endif
#ifdef _PRMT_X_CT_COM_USERINFO_
	{"loid_reg_status", INFO_MIB, CWMP_USERINFO_STATUS},
	{"loid_reg_result", INFO_MIB, CWMP_USERINFO_RESULT},
#endif
	{"cwmp_conf", INFO_MIB, CWMP_CONFIGURABLE},
	{"manufacture", INFO_MIB, MIB_HW_CWMP_MANUFACTURER},
	{"devModel", INFO_MIB, MIB_HW_CWMP_PRODUCTCLASS},
	{"hdVer", INFO_MIB, MIB_HW_HWVER},
#ifdef CONFIG_USER_CTMANAGEDEAMON
	{"BUCPEInformURL", INFO_MIB, MIB_BUCPE_MANAGEMENT_PLATFORM},
	{"BUCPEInformURLbak", INFO_MIB, MIB_BUCPE_BACKUP_MANAGEMENT_PLATFORM},
	{"BUCPETraceURL", INFO_MIB, MIB_BUCPE_TRACE_URL},
#endif
#ifdef CONFIG_CT_AWIFI_JITUAN_SMARTWIFI	
	{"providerName", INFO_MIB, MIB_DEVICE_NAME},
	{"upgradeURL", INFO_MIB, AWIFI_IMAGE_URL},
	{"reportURL", INFO_MIB, AWIFI_REPORT_URL},
	{"applyID", INFO_MIB, AWIFI_APPLYID},
	{"city", INFO_MIB, AWIFI_CITY},
#endif	
#if defined(CONFIG_USER_SAMBA) && (defined(CONFIG_CMCC) || defined(CONFIG_CU))
#ifdef CONFIG_USER_NMBD
	{"samba-netbios-name", INFO_MIB, MIB_SAMBA_NETBIOS_NAME},
#endif
	{"samba-server-string", INFO_MIB, MIB_SAMBA_SERVER_STRING},
#endif
	{"dmzWan", INFO_MIB, MIB_DMZ_WAN},
#ifdef CONFIG_SUPPORT_CAPTIVE_PORTAL
	{"redirect_url", INFO_MIB, MIB_CAPTIVEPORTAL_URL},
#endif
	{NULL, 0, 0}
};

#ifdef WLAN_SUPPORT
#ifdef CONFIG_WIFI_SIMPLE_CONFIG//WPS
static void convert_bin_to_str(unsigned char *bin, int len, char *out)
{
	int i;
	char tmpbuf[10];

	out[0] = '\0';

	for (i=0; i<len; i++) {
		sprintf(tmpbuf, "%02x", bin[i]);
		strcat(out, tmpbuf);
	}
}


static int fnget_wpsKey(int eid, request* wp, int argc, char **argv, char *buffer) {
	unsigned char key, vChar, type;
	int mib_id;
	MIB_CE_MBSSIB_T Entry;

	wlan_getEntry(&Entry, 0);

	vChar = Entry.wsc_enc;
	buffer[0]='\0';
	if (vChar == WSC_ENCRYPT_WEP) {
		unsigned char tmp[100];
		vChar = Entry.wep;
		type = Entry.wepKeyType;
		key = Entry.wepDefaultKey; //default key
		if (vChar == 1) {
			if (key == 0)
				mib_id = MIB_WLAN_WEP64_KEY1;
			else if (key == 1)
				mib_id = MIB_WLAN_WEP64_KEY2;
			else if (key == 2)
				mib_id = MIB_WLAN_WEP64_KEY3;
			else
				mib_id = MIB_WLAN_WEP64_KEY4;
			strcpy(tmp, Entry.wep64Key1);
			if(type == KEY_ASCII){
				memcpy(buffer, tmp, 5);
				buffer[5] = '\0';
			}else{
				convert_bin_to_str(tmp, 5, buffer);
				buffer[10] = '\0';
			}
		}
		else {
			if (key == 0)
				mib_id = MIB_WLAN_WEP128_KEY1;
			else if (key == 1)
				mib_id = MIB_WLAN_WEP128_KEY2;
			else if (key == 2)
				mib_id = MIB_WLAN_WEP128_KEY3;
			else
				mib_id = MIB_WLAN_WEP128_KEY4;
			strcpy(tmp, Entry.wep128Key1);
			if(type == KEY_ASCII){
				memcpy(buffer, tmp, 13);
				buffer[13] = '\0';
			}else{
				convert_bin_to_str(tmp, 13, buffer);
				buffer[26] = '\0';
			}
		}
	}
	else {
		if (vChar ==0 || vChar == WSC_ENCRYPT_NONE)
			strcpy(buffer, "N/A");
		else
			strcpy(buffer, Entry.wscPsk);
	}
   	return boaWrite(wp, buffer);
}
#endif
#endif

web_custome_cmd get_info_custom_list[] = {
	#ifdef WLAN_SUPPORT
	#ifdef CONFIG_WIFI_SIMPLE_CONFIG//WPS
	{ "wps_key", fnget_wpsKey },
	#endif
	#endif
	{ NULL, 0 }
};
#ifdef CONFIG_CT_AWIFI_JITUAN_SMARTWIFI
#define DEFAULT_GATEWAYPORT 2060
#endif

#ifdef CONFIG_USER_CTMANAGEDEAMON
static void IntToAscii(int n, char s[]){
        char c[32];
        int i, sign, j;
        if((sign=n)<0)
                n=-n;
        i=0;
        do{
                s[i++]=n%10+'0';
        }while((n/=10)>0);
        if(sign<0)
                s[i++]='-';
        s[i]='\0';
        //assert(i<31);
        for(j=0,i--;i>=0;j++,i--)
                c[j]=s[i];
        c[j]='\0';
        memcpy(s, c, (size_t)(j+1));
}

static void IntToBucpeFloat(int location ,char *xString)
{
	char tmp[16],*ptmp;
	ptmp = tmp;
	int i = 0,j = 0,len, d_point;
#define LOCATION_ACCURACY 5

	IntToAscii(location,tmp);
	if(location == 0)
	{
		strcpy(xString,tmp);
		return;
	}
	
	if(tmp[0] == '-'){
		xString[0] = tmp[0];
		ptmp++ ;
		i++;
		j++;
	}

	len = strlen(ptmp);

	if(len <= LOCATION_ACCURACY){
		strcat(xString,"0.");
		j += 2;
		int k = 0;

		for(k;k< LOCATION_ACCURACY - len ;k++){
			xString[j++] = '0';
		}	
		len = len + i;
		for(i;i<len;i++)
			xString[j++] = tmp[i];
	}else
	{
		len = len +i;
		d_point = len - LOCATION_ACCURACY;
		for(i;i< len;i++){
			if( i == d_point){
				xString[j++] = '.';
				xString[j] = tmp[i];
			}
			else
				xString[j] = tmp[i];
			j++;
		}
	}
		
//	printf("result_str = %s\n",xString);
}
#endif

static void hex_to_string(unsigned char* hex_str, int length, char * acsii_str)
{
	int i = 0, j = 0;

	for (i = 0; i < length/2; i++, j+=2) 
		sprintf(acsii_str+j, "%x", hex_str[i]);
}

int IsFolderExist(const char* path)
{
    DIR *dp;
    if ((dp = opendir(path)) == NULL)
    {
        return 0;
    }

    closedir(dp);
    return 1;
}

int gettopstyle(int eid, request* wp, int argc, char **argv)
{
#ifdef CONFIG_CT_AWIFI_JITUAN_FEATURE
	unsigned char functype=0;
	mib_get(AWIFI_PROVINCE_CODE, &functype);
	if(functype == AWIFI_ZJ){
		boaWrite(wp,"top_style=1;\n");
	}
	else
#endif
	{
		boaWrite(wp,"top_style=0;\n");
	}
	return 0;
}

#ifdef E8B_NEW_DIAGNOSE
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
void update_acs_status(void)
{
	char tmpbuf[256 + 1];
	FILE *fp;
	int cwmp_found = 0;
	int wan_found = 0;
	int acs_setting = 1;
	int num, i;
	MIB_CE_ATM_VC_T entry;
	int flags;
	struct in_addr inAddr;
	unsigned int events;
	pid_t  tr069_pid;
	char cause[64];                                                                                                                         
	int status;

	num = mib_chain_total(MIB_ATM_VC_TBL);
	for (i = 0; i < num; i ++) {
		if (!mib_chain_get(MIB_ATM_VC_TBL, i, &entry))
			continue;

		if (!(entry.applicationtype & X_CT_SRV_TR069))
			continue;

		cwmp_found = 1;

		if (!entry.enable)
			continue;

		ifGetName(entry.ifIndex, tmpbuf, sizeof(tmpbuf));

		if (getInFlags(tmpbuf, &flags)) {
			if ((flags & IFF_UP) && getInAddr(tmpbuf, IP_ADDR, &inAddr)) {
				wan_found = 1;
				break;
			}
		}
	}

#ifdef CONFIG_TR142_MODULE
	if ( mib_get(RS_CWMP_USED_ACS_URL, tmpbuf) == 0 || strlen(tmpbuf) == 0 )
#else
	if ( mib_get(CWMP_ACS_URL, tmpbuf) == 0 || strlen(tmpbuf) == 0 )
#endif
		acs_setting = 0;

	if (acs_setting == 0) {
		sprintf(tmpbuf, "%d:%s", NO_INFORM, CWMP_NO_ACSSETTING);
	} else if (cwmp_found == 0) {
		sprintf(tmpbuf, "%d:%s", NO_INFORM, NO_CWMP_CONNECTION);
	} else if (wan_found == 0) {
		sprintf(tmpbuf, "%d:%s", NO_INFORM, CWMP_CONNECTION_DISABLE);
	} else {
		tmpbuf[0] = '\0';
	}

	if (strlen(tmpbuf) != 0 && tmpbuf[0] != '\0') {
		fp = fopen(INFORM_STATUS_FILE, "w");
		if (fp) {
			fprintf(fp, "%s", tmpbuf);
			fclose(fp);
		}
	}

	if(tmpbuf[0] == '\0')
	{
		tr069_pid = read_pid("/var/run/cwmp.pid");
		if ( tr069_pid > 0) 
		{
			fp = fopen(INFORM_STATUS_FILE, "r");
			if (fp) 
			{
				fscanf(fp, "%d:%64[^\n]", &status, cause);
				fclose(fp);
			}
			if(status==NO_INFORM && cause[0]=='3')
			{
				mib_get(CWMP_INFORM_EVENTCODE, &events);
				#define EC_PERIODIC 0x000004	
				events |= EC_PERIODIC;
				mib_set(CWMP_INFORM_EVENTCODE, &events);
			}
		}
	}
}
#endif
#endif

int getInfo(int eid, request* wp, int argc, char **argv)
{
	char	*name;
	unsigned char buffer[256 + 1];
	int idx, ret;
	FILE *fp;

	if (boaArgs(argc, argv, "%s", &name) < 1) {
		boaError(wp, 400, "Insufficient args\n");
		return -1;
	}

	memset(buffer,0x00,64);
#ifdef CONFIG_CU	
	if(!strncmp(name,"pcRangeStart",12)) {
		DHCPS_SERVING_POOL_T dhcppoolentry;
		int i;
		int entryNum = mib_chain_total(MIB_DHCPS_SERVING_POOL_TBL);
		for(i = 0; i < entryNum; i++){
			if(!mib_chain_get(MIB_DHCPS_SERVING_POOL_TBL, i, (void *)&dhcppoolentry))
				continue;
			
			if(dhcppoolentry.poolname){
				if(!strcmp(dhcppoolentry.poolname, "Computer"))
				break;
			}
		}
		if(i >= entryNum) 
			return boaWrite(wp, "%s", "");
		else
			return boaWrite(wp, "%s", inet_ntoa(*((struct in_addr *)dhcppoolentry.startaddr)));
	}

	if(!strncmp(name,"pcRangeEnd",12)) {
		DHCPS_SERVING_POOL_T dhcppoolentry;
		int i;
		int entryNum = mib_chain_total(MIB_DHCPS_SERVING_POOL_TBL);
		for(i = 0; i < entryNum; i++){
			if(!mib_chain_get(MIB_DHCPS_SERVING_POOL_TBL, i, (void *)&dhcppoolentry))
				continue;
			
			if(dhcppoolentry.poolname){
				if(!strcmp(dhcppoolentry.poolname, "Computer"))
				break;
			}
		}
		if(i >= entryNum) 
			return boaWrite(wp, "%s", "");
		else 
			return boaWrite(wp, "%s", inet_ntoa(*((struct in_addr *)dhcppoolentry.endaddr)));
	}

	if(!strncmp(name,"cmrRangeStart",12)) {
		DHCPS_SERVING_POOL_T dhcppoolentry;
		int i;
		int entryNum = mib_chain_total(MIB_DHCPS_SERVING_POOL_TBL);
		for(i = 0; i < entryNum; i++){
			if(!mib_chain_get(MIB_DHCPS_SERVING_POOL_TBL, i, (void *)&dhcppoolentry))
				continue;
			
			if(dhcppoolentry.poolname){
				if(!strcmp(dhcppoolentry.poolname, "Camera"))
				break;
			}
		}
		if(i >= entryNum) 
			return boaWrite(wp, "%s", "");
		else 
			return boaWrite(wp, "%s", inet_ntoa(*((struct in_addr *)dhcppoolentry.startaddr)));
	}

	if(!strncmp(name,"cmrRangeEnd",12)) {
		DHCPS_SERVING_POOL_T dhcppoolentry;
		int i;
		int entryNum = mib_chain_total(MIB_DHCPS_SERVING_POOL_TBL);
		for(i = 0; i < entryNum; i++){
			if(!mib_chain_get(MIB_DHCPS_SERVING_POOL_TBL, i, (void *)&dhcppoolentry))
				continue;
			
			if(dhcppoolentry.poolname){
				if(!strcmp(dhcppoolentry.poolname, "Camera"))
				break;
			}
		}
		if(i >= entryNum) 
			return boaWrite(wp, "%s", "");
		else 
			return boaWrite(wp, "%s", inet_ntoa(*((struct in_addr *)dhcppoolentry.endaddr)));
	}

	if(!strncmp(name,"stbRangeStart",12)) {
		DHCPS_SERVING_POOL_T dhcppoolentry;
		int i;
		int entryNum = mib_chain_total(MIB_DHCPS_SERVING_POOL_TBL);
		for(i = 0; i < entryNum; i++){
			if(!mib_chain_get(MIB_DHCPS_SERVING_POOL_TBL, i, (void *)&dhcppoolentry))
				continue;
			
			if(dhcppoolentry.poolname){
				if(!strcmp(dhcppoolentry.poolname, "STB"))
				break;
			}
		}
		if(i >= entryNum) 
			return boaWrite(wp, "%s", "");
		else 
			return boaWrite(wp, "%s", inet_ntoa(*((struct in_addr *)dhcppoolentry.startaddr)));
	}

	if(!strncmp(name,"stbRangeEnd",12)) {
		DHCPS_SERVING_POOL_T dhcppoolentry;
		int i;
		int entryNum = mib_chain_total(MIB_DHCPS_SERVING_POOL_TBL);
		for(i = 0; i < entryNum; i++){
			if(!mib_chain_get(MIB_DHCPS_SERVING_POOL_TBL, i, (void *)&dhcppoolentry))
				continue;
			
			if(dhcppoolentry.poolname){
				if(!strcmp(dhcppoolentry.poolname, "STB"))
				break;
			}
		}
		if(i >= entryNum) 
			return boaWrite(wp, "%s", "");
		else 
			return boaWrite(wp, "%s", inet_ntoa(*((struct in_addr *)dhcppoolentry.endaddr)));
	}

	if(!strncmp(name,"phoneRangeStart",12)) {
		DHCPS_SERVING_POOL_T dhcppoolentry;
		int i;
		int entryNum = mib_chain_total(MIB_DHCPS_SERVING_POOL_TBL);
		for(i = 0; i < entryNum; i++){
			if(!mib_chain_get(MIB_DHCPS_SERVING_POOL_TBL, i, (void *)&dhcppoolentry))
				continue;
			
			if(dhcppoolentry.poolname){
				if(!strcmp(dhcppoolentry.poolname, "Phone"))
				break;
			}
		}
		if(i >= entryNum) 
			return boaWrite(wp, "%s", "");
		else 
			return boaWrite(wp, "%s", inet_ntoa(*((struct in_addr *)dhcppoolentry.startaddr)));
	}

	if(!strncmp(name,"phoneRangeEnd",12)) {
		DHCPS_SERVING_POOL_T dhcppoolentry;
		int i;
		int entryNum = mib_chain_total(MIB_DHCPS_SERVING_POOL_TBL);
		for(i = 0; i < entryNum; i++){
			if(!mib_chain_get(MIB_DHCPS_SERVING_POOL_TBL, i, (void *)&dhcppoolentry))
				continue;
			
			if(dhcppoolentry.poolname){
				if(!strcmp(dhcppoolentry.poolname, "Phone"))
				break;
			}
		}
		if(i >= entryNum) 
			return boaWrite(wp, "%s", "");
		else 
			return boaWrite(wp, "%s", inet_ntoa(*((struct in_addr *)dhcppoolentry.endaddr)));
	}
#endif

#ifdef VOIP_SUPPORT
	if(!strncmp(name, "voip_", 5)){
		extern int asp_voip_getInfo(int eid, request * wp, int argc, char **argv);
		return asp_voip_getInfo(eid, wp, argc, argv);
	}
#endif /*VOIP_SUPPORT*/
	if(!strcmp(name, "login-user")){
#ifdef USE_LOGINWEB_OF_SERVER
		ret = boaWrite(wp, "%s", g_login_username);
#else
		ret = boaWrite(wp, "%s", wp->user);
#endif
		goto NEXTSTEP;
	}

#ifdef E8B_NEW_DIAGNOSE
	/* willin.hou 2009-03-28 */
	if (!strncmp(name, "tr069Inform", 11)) {
		char cause[64];
		int status, ret;
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		update_acs_status();
#endif
		
		fp = fopen(INFORM_STATUS_FILE, "r");
		if (fp == NULL) {
			return boaWrite(wp, "无");
		}
		cause[0] = '\0';
		
		ret = fscanf(fp, "%d:%64[^\n]", &status, cause);
		fclose(fp);
		if (ret == EOF) {
			return boaWrite(wp, "无");
		}
		switch (status) {
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		case NO_INFORM:
			if( cause[0]=='1')
				return boaWrite(wp, "Inform手动上报测试结果:未上报（智能网关正在启动）");
			else if( cause[0]=='2')
				return boaWrite(wp, "Inform手动上报测试结果:未上报（无远程管理WAN连接）");
			else if( cause[0]=='3')
				return boaWrite(wp, "Inform手动上报测试结果:未上报（远程管理WAN连接未生效）");
			else if( cause[0]=='4')
				return boaWrite(wp, "Inform手动上报测试结果:未上报（无管理通道DNS信息）");
			else if( cause[0]=='5')
				return boaWrite(wp, "Inform手动上报测试结果:未上报（无省级数字家庭管理平台配置参数）");
			else if( cause[0]=='6')
				return boaWrite(wp, "Inform手动上报测试结果:未上报（省级数字家庭管理平台域名解析失败）");
		case NO_RESPONSE:
			return boaWrite(wp, "Inform手动上报测试结果:上报无回应");
		case INFORM_BREAK:
			return boaWrite(wp, "Inform手动上报测试结果:上报过程中断");
		case INFORM_SUCCESS:
			return boaWrite(wp, "Inform手动上报测试结果:上报成功");
		case INFORM_AUTH_FAIL:
			return boaWrite(wp, "Inform手动上报测试结果:上报验证失败");
		case INFORMING:
			return boaWrite(wp, "<B><font color=\"#FF0000\" size=\"-1\">正在手动上报,请稍等...</font></B>");		
		default:
			return boaWrite(wp, "Inform手动上报测试结果:无结果");
#else
		case NO_INFORM:
			return boaWrite(wp, "未上报（%s）", cause);
		case NO_RESPONSE:
			return boaWrite(wp, "上报无回应");
		case INFORM_BREAK:
			return boaWrite(wp, "上报过程中断");
		case INFORM_SUCCESS:
			return boaWrite(wp, "上报成功");
		case INFORM_AUTH_FAIL:
			return boaWrite(wp, "上报验证失败");
		case INFORMING:
			return boaWrite(wp, "上报中...");
		default:
			return boaWrite(wp, "无");
#endif
		}
	}

#ifdef TERMINAL_INSPECTION_SC
	if (!strncmp(name, "SCtr069Register", 15))
	{
		int status, ret;

		fp = fopen(CONNREQ_STATUS_FILE, "r");
		if (fp == NULL) {
			return boaWrite(wp, "无");
		}
		ret = fscanf(fp, "%d", &status);
		fclose(fp);
		if (ret == EOF) {
			return boaWrite(wp, "无");
		}
		switch (status) {
		case NO_REQUEST:
			return boaWrite(wp, "未注册");
		case REQUEST_BREAK:
			return boaWrite(wp, "注册失败");
		case REQUEST_SUCCESS:
			return boaWrite(wp, "注册成功");
		default:
			return boaWrite(wp, "未注册");
		}
	}
			
	if (!strncmp(name, "SCtr069Download", 15)) {
		unsigned int regResult;

		mib_get(CWMP_USERINFO_RESULT, &regResult);

		switch (regResult) {
		case NO_SET:
			return boaWrite(wp, "未下发");
		case NOW_SETTING:
			return boaWrite(wp, "下发中");
		case SET_SUCCESS:
			return boaWrite(wp, "已下发");
		case SET_FAULT:
			return boaWrite(wp, "下发失败");
		default:
			return boaWrite(wp, "未下发");
		}
	}
#endif

#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	if (!strncmp(name, "tr069-Inform", 12)) {
		char cause[64];
		int status, ret;

		update_acs_status();

		fp = fopen(INFORM_STATUS_FILE, "r");
		if (fp == NULL) {
			return boaWrite(wp, "N/A");
		}
		cause[0] = '\0';
		
		ret = fscanf(fp, "%d:%64[^\n]", &status, cause);
		fclose(fp);
		if (ret == EOF) {
			return boaWrite(wp, "N/A");
		}
		switch (status) {

		case NO_INFORM:
			if( cause[0]=='1')
				return boaWrite(wp, "未上报（智能网关正在启动）");
			else if( cause[0]=='2')
				return boaWrite(wp, "未上报（无远程管理WAN连接）");
			else if( cause[0]=='3')
				return boaWrite(wp, "未上报（远程管理WAN连接未生效）");
			else if( cause[0]=='4')
				return boaWrite(wp, "未上报（无管理通道DNS信息）");
			else if( cause[0]=='5')
				return boaWrite(wp, "未上报（无省级数字家庭管理平台配置参数）");
			else if( cause[0]=='6')
				return boaWrite(wp, "未上报（省级数字家庭管理平台域名解析失败）");
		case NO_RESPONSE:
			return boaWrite(wp, "上报无回应");
		case INFORM_BREAK:
			return boaWrite(wp, "上报过程中断");
		case INFORM_SUCCESS:
			return boaWrite(wp, "上报成功");
		case INFORM_AUTH_FAIL:
			return boaWrite(wp, "上报验证失败");
		case INFORMING:
			return boaWrite(wp, "正在上报,请稍等...");		
		default:
			return boaWrite(wp, "N/A");
		}
	}
#endif

	if (!strncmp(name, "tr069Connect", 12)) {
		int status, ret;

		fp = fopen(CONNREQ_STATUS_FILE, "r");
		if (fp == NULL) {
			return boaWrite(wp, "无");
		}
		ret = fscanf(fp, "%d", &status);
		fclose(fp);
		if (ret == EOF) {
			return boaWrite(wp, "无");
		}
		switch (status) {
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		case NO_REQUEST:
			return boaWrite(wp, "未收到远程连接请求");
		case REQUEST_BREAK:
			return boaWrite(wp, "省级数字家庭管理平台发起的远程连接过程中断");
		case REQUEST_SUCCESS:
			return boaWrite(wp, "省级数字家庭管理平台发起的远程连接过程成功");
		default:
			return boaWrite(wp, "未收到远程连接请求");
#else
		case NO_REQUEST:
			return boaWrite(wp, "未收到远程连接请求");
		case REQUEST_BREAK:
			return boaWrite(wp, "ITMS+发起的远程连接过程中断");
		case REQUEST_SUCCESS:
			return boaWrite(wp, "ITMS+发起的远程连接过程成功");
		default:
			return boaWrite(wp, "无");
#endif
		}
	}

	if (!strncmp(name, "tr069Config", 12)) {
		unsigned int regResult;

		mib_get(CWMP_USERINFO_RESULT, &regResult);

		switch (regResult) {
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		case NO_SET:
			return boaWrite(wp, "省级数字家庭管理平台未下发远程业务配置状态");
		case NOW_SETTING:
			return boaWrite(wp, "正在接受省级数字家庭管理平台的远程业务配置");
		case SET_SUCCESS:
			return boaWrite(wp, "业务配置成功");
		case SET_FAULT:
			return boaWrite(wp, "业务配置失败");
		default:
			return boaWrite(wp, "省级数字家庭管理平台未下发远程业务配置状态");
#else
		case NO_SET:
			return boaWrite(wp, "ITMS未下发远程业务配置状态");
		case NOW_SETTING:
			return boaWrite(wp, "正在接受ITMS的远程业务配置");
		case SET_SUCCESS:
			return boaWrite(wp, "业务配置成功");
		case SET_FAULT:
			return boaWrite(wp, "业务配置失败");
		default:
			return boaWrite(wp, "无");
#endif
		}
	}
#endif
#ifdef CONFIG_USER_CTMANAGEDEAMON 
	if(!strncmp(name, "BUCPEWANMAC", 12)){
		unsigned char macAddr[MAC_ADDR_LEN] = {0};
		mib_get( MIB_ELAN_MAC_ADDR, (void *)macAddr);
		sprintf (macAddr, "%02x%02x%02x%02x%02x%02x", macAddr[0],macAddr[1],macAddr[2],macAddr[3],macAddr[4],macAddr[5]+2);
		if(strlen(macAddr))
			return boaWrite(wp, "%s", macAddr);
		else
			return -1;
	}
	if(!strncmp(name, "BUCPEUplink", 12)){
		char uplink[16] = {0};
		if(strlen(uplink))
			return boaWrite(wp, "%s", uplink);
		else
			return -1;
	}
	if(!strncmp(name, "BUCPEB1InterfaceVersion", 24)){
		return boaWrite(wp, "1.0");
	}
	if(!strncmp(name, "BUCPEInformCycle", 16)){
		int informCycle;
	
		mib_get(MIB_BUCPE_REPORT_PERIOD, &informCycle);
		if(informCycle)
			return boaWrite(wp, "%d", informCycle/60);
		else
			return -1;
	}
	if(!strncmp(name, "BUCPETaskCycle", 14)){
		int taskCycle;
	
		mib_get(MIB_BUCPE_DIAG_CYCLE, &taskCycle);
		if(taskCycle)
			return boaWrite(wp, "%d", taskCycle/3600);
		else
			return -1;
	}
	if(!strncmp(name, "locationRegID", 13)){
		char regID[65];

		mib_get(MIB_BUCPE_REGID, regID);
		if(strlen(regID))
			return boaWrite(wp, "%s", regID);
		else
			return boaWrite(wp, "-");
	}
		if(!strncmp(name, "locationUUID", 12)){
			char uuid[64];
		
			mib_get(MIB_BUCPE_UUID, uuid);
			if(strlen(uuid))
				return boaWrite(wp, "%s", uuid);
			else
				return boaWrite(wp, "-");
		}
	if(!strncmp(name, "BUCPEspeedURL", 13)){
		return boaWrite(wp, "%s", "http://www.bbums.cn/speedtest/");
	}
	if(!strncmp(name, "BUCPEspeedbakURL", 16)){
		return boaWrite(wp, "%s", "http://www.bbums.org.cn/speedtest/");
	}
	if (!strncmp(name, "locationLocationInform0", 23)) {
		char regID[64];
	
		mib_get(MIB_BUCPE_REGID, &regID);
		if(strlen(regID))
			return boaWrite(wp, "上报成功");
		else
			return boaWrite(wp, "未上报");
	}
	if(!strncmp(name, "locationA", 9))
	{
		int locationstatus;
		mib_get(MIB_BUCPE_A_LOCATION_OK, &locationstatus);
		if(!locationstatus)
			return boaWrite(wp, "-");
		if (!strncmp(name, "locationALongitude", 18)) 
		{
			char longitudestr[16] = {0};

			if(mib_get(MIB_BUCPE_A_LOCATION_LONGITUDE, longitudestr))
				return boaWrite(wp, "%s",longitudestr);
			else
				return boaWrite(wp, "-");
		}
		if (!strncmp(name, "locationALatitude", 17)) 
		{
			char latitudestr[16] = {0};

			if(mib_get(MIB_BUCPE_A_LOCATION_LATITUDE, latitudestr))
				return boaWrite(wp, "%s",latitudestr);
			else
				return boaWrite(wp, "-");
		}
		if (!strncmp(name, "locationAElevation", 18)) {
			short elevation;

			mib_get(MIB_BUCPE_A_LOCATION_ALTITUDE, &elevation);
			if(elevation<0x8fff)
				return boaWrite(wp, "%d",elevation);
			else
				return boaWrite(wp, "-");
		}
		if (!strncmp(name, "locationAHorizontalerror", 24)) {
			unsigned short horizontalerror;

			mib_get(MIB_BUCPE_A_LOCATION_HORIZONTALERROR, &horizontalerror);
			if(horizontalerror<0xffff)
				return boaWrite(wp, "%d",horizontalerror);
			else
				return boaWrite(wp, "-");
		}
		if (!strncmp(name, "locationAAltitudeerror", 22)) {
			unsigned short Altitudeerror;

			mib_get(MIB_BUCPE_A_LOCATION_ALTITUDEERROR, &Altitudeerror);
			if(Altitudeerror<0xffff)
				return boaWrite(wp, "%d",Altitudeerror);
			else
				return boaWrite(wp, "-");
		}
		if (!strncmp(name, "locationAAreacode", 17)) {
			char areacode[30];

			mib_get(MIB_BUCPE_A_AREACODE, &areacode);
			if(strlen(areacode))
				return boaWrite(wp, "%s",areacode);
			else
				return boaWrite(wp, "-");
		}
		if (!strncmp(name, "locationATimeStamp", 18)) {
			const time_t timeStamp;
			struct tm *tm_time;
			char strbuf[256];
			mib_get(MIB_BUCPE_A_GISLOCKTIME, (void *)&timeStamp);

			if(timeStamp == 0)
				return boaWrite(wp, "-");
			
			tm_time = gmtime(&timeStamp);
			//strftime(strbuf, 200, "%a %b %e %H:%M:%S %Z %Y", tm_time);
			snprintf(strbuf, 15, "%04d%02d%02d%02d%02d%02d", (tm_time->tm_year+ 1900),(tm_time->tm_mon+ 1),(tm_time->tm_mday)
						,(tm_time->tm_hour),(tm_time->tm_min),(tm_time->tm_sec));

			if(timeStamp<0xffffffff)
				return boaWrite(wp, "%s",strbuf);
			else
				return boaWrite(wp, "-");
		}
		if (!strncmp(name, "locationAGISDigest", 18)) {
			char GISDigest[30];

			mib_get(MIB_BUCPE_A_GISDIGEST, &GISDigest);
			if(strlen(GISDigest))
				return boaWrite(wp, "%s",GISDigest);
			else
				return boaWrite(wp, "-");
		}
	}
	if(!strncmp(name, "locationB", 9))
	{
		int locationstatus;
		mib_get(MIB_BUCPE_B_LOCATION_OK, &locationstatus);
		if(!locationstatus)
			return boaWrite(wp, "-");
		if (!strncmp(name, "locationBLongitude", 18)) 
		{
			char longitudestr[16] = {0};

			if(mib_get(MIB_BUCPE_B_LOCATION_LONGITUDE, longitudestr))
				return boaWrite(wp, "%s",longitudestr);
			else
				return boaWrite(wp, "-");
		}
		if (!strncmp(name, "locationBLatitude", 17)) {
			char latitudestr[16] = {0};

			if(mib_get(MIB_BUCPE_B_LOCATION_LATITUDE, latitudestr))
				return boaWrite(wp, "%s",latitudestr);
			else
				return boaWrite(wp, "-");
		}
		if (!strncmp(name, "locationBElevation", 18)) {
			short elevation;

			mib_get(MIB_BUCPE_B_LOCATION_ALTITUDE, &elevation);
			if(elevation<0x8fff)
				return boaWrite(wp, "%d",elevation);
			else
				return boaWrite(wp, "-");
		}
		if (!strncmp(name, "locationBHorizontalerror", 24)) {
			unsigned short horizontalerror;

			mib_get(MIB_BUCPE_B_LOCATION_HORIZONTALERROR, &horizontalerror);
			if(horizontalerror<0xffff)
				return boaWrite(wp, "%d",horizontalerror);
			else
				return boaWrite(wp, "-");
		}
		if (!strncmp(name, "locationBAltitudeerror", 22)) {
			unsigned short Altitudeerror;

			mib_get(MIB_BUCPE_B_LOCATION_ALTITUDEERROR, &Altitudeerror);
			if(Altitudeerror<0xffff)
				return boaWrite(wp, "%d",Altitudeerror);
			else
				return boaWrite(wp, "-");
		}
		if (!strncmp(name, "locationBAreacode", 17)) {
			char areacode[30];

			mib_get(MIB_BUCPE_B_AREACODE, &areacode);
			if(strlen(areacode))
				return boaWrite(wp, "%s",areacode);
			else
				return boaWrite(wp, "-");
		}
		if (!strncmp(name, "locationBTimeStamp", 18)) {
			const time_t timeStamp;
			struct tm *tm_time;
			char strbuf[256];
			mib_get(MIB_BUCPE_B_GISLOCKTIME, (void *)&timeStamp);

			if(timeStamp == 0)
				return boaWrite(wp, "-");
			
			tm_time = gmtime(&timeStamp);
			snprintf(strbuf, 15, "%04d%02d%02d%02d%02d%02d", (tm_time->tm_year+ 1900),(tm_time->tm_mon+ 1),(tm_time->tm_mday)
						,(tm_time->tm_hour),(tm_time->tm_min),(tm_time->tm_sec));

			if(timeStamp<0xffffffff)
				return boaWrite(wp, "%s",strbuf);
			else
				return boaWrite(wp, "-");
		}
		if (!strncmp(name, "locationBGISDigest", 18)) {
			char GISDigest[30];

			mib_get(MIB_BUCPE_B_GISDIGEST, &GISDigest);
			if(strlen(GISDigest))
				return boaWrite(wp, "%s",GISDigest);
			else
				return boaWrite(wp, "-");
		}
	}
#endif

#ifdef _PRMT_X_CT_COM_MWBAND_
	if (!strncmp(name, "wan_limit", 9))
	{
		int enable = 0, limit = 0;

		mib_get(CWMP_CT_MWBAND_MODE, &enable);
		mib_get(CWMP_CT_MWBAND_NUMBER, &limit);
		if(enable)
			return boaWrite(wp, "%d", limit);
		else
			return boaWrite(wp, "0");
	}
#endif

#ifdef CONFIG_TR142_MODULE
	if (!strcmp(name, "acs-url")) {

		mib_get(RS_CWMP_USED_ACS_URL, buffer);

		// If there's no ACS URL is decided, show ACS URL in MIB.
		if(strlen(buffer) == 0)
			mib_get(CWMP_ACS_URL, buffer);

		return boaWrite(wp, "%s", buffer);
	}
#endif
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	if (!strncmp(name, "ca-status", 11)) 
	{
		FILE *fp;
		unsigned char ca_status;

		fp = fopen(CA_STATUS_FILE, "r");
		if(fp)
		{
			if( (ca_status = fgetc(fp)) != 0 )
			{
				boaWrite(wp, "%c", ca_status);
			}
			else
				boaWrite(wp, "8");   //read CA_STATUS_FILE failed
			fclose(fp);
		}
		else{          //NO CA_STATUS_FILE
			boaWrite(wp, "4");
		}
	}
#endif

 	for (idx=0; get_info_custom_list[idx].cmd != NULL; idx++) {
 		if (!strcmp(name, get_info_custom_list[idx].cmd)) {
 			return get_info_custom_list[idx].handler(eid, wp, argc, argv, buffer);
 		}
 	}

	for (idx=0; get_info_list[idx].cmd != NULL; idx++) {
		if (!strcmp(name, get_info_list[idx].cmd)) {
			if (get_info_list[idx].type == INFO_MIB) {
				if (getMIB2Str(get_info_list[idx].id, buffer)) {
					fprintf(stderr, "failed to get %s\n", name);
					return -1;
				}
			}
			else {
				if (getSYS2Str(get_info_list[idx].id, buffer))
					return -1;
			}
			// Kaohj
			if ((!strncmp(name, "wan-dns", 7))&& !strcmp(buffer, "0.0.0.0"))
				ret = boaWrite(wp, "");
			else
			ret = boaWrite(wp, "%s", buffer);
			//fprintf(stderr, "%s = %s\n", name, buffer);
			//printf("%s = %s\n", name, buffer);
			break;
		}
	}

	if (!strncmp(name, "devId", 5)) {
#ifdef _CWMP_MIB_
		unsigned char *bufptr;
		/*Jim 20081007 START */
#ifdef E8B_GET_OUI
		getOUIfromMAC(buffer);
#else
		strcpy(buffer, DEF_MANUFACTUREROUI_STR);
#endif
		bufptr = buffer + strlen(buffer);
		/*Jim 20081007 END */
#if !defined(CONFIG_CMCC) && !defined(CONFIG_CU)
		*bufptr = '-';
		bufptr++;
#endif
		mib_get(MIB_HW_SERIAL_NUMBER, (void *)bufptr);
		return boaWrite(wp, "%s", buffer);
#else
		return boaWrite(wp, "%s", "devId");
#endif
	}

#ifdef WLAN_SUPPORT
#ifdef TERMINAL_INSPECTION_SC
	if ( !strncmp(name, "SCwlanState", 11) )
	{
		MIB_CE_MBSSIB_T Entry;
		wlan_getEntry(&Entry, 0);

		if (!Entry.wlanDisabled)
		{
			return boaWrite (wp, "正常");
		}
		else
		{
			return boaWrite (wp, "异常");
		}
	}
			
#endif

	if ( !strncmp(name, "wlanState", 9) )
	{
		MIB_CE_MBSSIB_T Entry;
		wlan_getEntry(&Entry, 0);

		if (!Entry.wlanDisabled)
			return boaWrite (wp, INFO_ENABLED);
		else
			return boaWrite (wp, INFO_DISABLED);
	}

	//cathy, for e8b wlan status
	if( !strncmp(name, "wlDefChannel", 12) ) {
		struct iwreq wrq;
		int ret;
		#define RTL8185_IOCTL_GET_MIB	0x89f2
		idx= socket(AF_INET, SOCK_DGRAM, 0);
		strcpy(wrq.ifr_name, "wlan0");
		strcpy(buffer,"channel");
		wrq.u.data.pointer = (caddr_t)&buffer;
		wrq.u.data.length = 10;
		ret = ioctl(idx, RTL8185_IOCTL_GET_MIB, &wrq);
		close( idx );
		if ( ret != -1) {
			return boaWrite (wp, "%d", buffer[wrq.u.data.length-1]);
		}
		else
			return boaWrite (wp, "N/A");
	}
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	if( !strncmp(name, "wlanWEPKey1", 11)||!strncmp(name, "wlanS2WEPKey1", 13) ) {
		char print_str[32] = {'\0'};
		MIB_CE_MBSSIB_T Entry;

		if(!strncmp(name, "wlanWEPKey1", 11))
			wlan_getEntry(&Entry, 0);
		else
			wlan_getEntry(&Entry, 1);

		if(Entry.wep == WEP64)
		{
			if(Entry.wepKeyType == 0) 
				strncpy(print_str, Entry.wep64Key1, 5);
			else
				hex_to_string(Entry.wep64Key1, 10, print_str);
		}
		else if (Entry.wep == WEP128)
		{
			if(Entry.wepKeyType == 0) 
				strncpy(print_str, Entry.wep128Key1, 13);
			else
				hex_to_string(Entry.wep128Key1, 26, print_str);
		}
		return boaWrite(wp, "%s", print_str);
	}
	if( !strncmp(name, "wlanWEPKey2", 11)||!strncmp(name, "wlanS2WEPKey2", 13) ) {
		char print_str[32] = {'\0'};;
		MIB_CE_MBSSIB_T Entry;

		if(!strncmp(name, "wlanWEPKey2", 11))
			wlan_getEntry(&Entry, 0);
		else
			wlan_getEntry(&Entry, 1);

		if(Entry.wep == WEP64)
		{
			if(Entry.wepKeyType == 0) 
				strncpy(print_str, Entry.wep64Key2, 5);
			else
				hex_to_string(Entry.wep64Key2, 10, print_str);
		}
		else if (Entry.wep == WEP128)
		{
			if(Entry.wepKeyType == 0) 
				strncpy(print_str, Entry.wep128Key2, 13);
			else
				hex_to_string(Entry.wep128Key2, 26, print_str);
		}
		return boaWrite(wp, "%s", print_str);
	}
	if( !strncmp(name, "wlanWEPKey3", 11)||!strncmp(name, "wlanS2WEPKey3", 13) ) {
		char print_str[32] = {'\0'};;
		MIB_CE_MBSSIB_T Entry;

		if(!strncmp(name, "wlanWEPKey3", 11))
			wlan_getEntry(&Entry, 0);
		else
			wlan_getEntry(&Entry, 1);

		if(Entry.wep == WEP64)
		{
			if(Entry.wepKeyType == 0) 
				strncpy(print_str, Entry.wep64Key3, 5);
			else
				hex_to_string(Entry.wep64Key3, 10, print_str);
		}
		else if (Entry.wep == WEP128)
		{
			if(Entry.wepKeyType == 0) 
				strncpy(print_str, Entry.wep128Key3, 13);
			else
				hex_to_string(Entry.wep128Key3, 26, print_str);
		}
		return boaWrite(wp, "%s", print_str);
	}
	if( !strncmp(name, "wlanWEPKey4", 11)||!strncmp(name, "wlanS2WEPKey4", 13) ) {
		char print_str[32] = {'\0'};;
		MIB_CE_MBSSIB_T Entry;

		if(!strncmp(name, "wlanWEPKey4", 11))
			wlan_getEntry(&Entry, 0);
		else
			wlan_getEntry(&Entry, 1);

		if(Entry.wep == WEP64)
		{
			if(Entry.wepKeyType == 0) 
				strncpy(print_str, Entry.wep64Key4, 5);
			else
				hex_to_string(Entry.wep64Key4, 10, print_str);
		}
		else if (Entry.wep == WEP128)
		{
			if(Entry.wepKeyType == 0) 
				strncpy(print_str, Entry.wep128Key4, 13);
			else
				hex_to_string(Entry.wep128Key4, 26, print_str);
		}
		return boaWrite(wp, "%s", print_str);
	}
#endif
	if( !strncmp(name, "wlanMode", 8) ) {
		unsigned char vChar;
		const char *wlan_band[] ={0,"802.11b","802.11g","802.11 b+g" ,0
//#ifdef CONFIG_USB_RTL8192SU_SOFTAP
#if defined(CONFIG_USB_RTL8192SU_SOFTAP) || defined(CONFIG_RTL8192CD) || defined(CONFIG_RTL8192CD_MODULE)
	     , 0, 0, 0,	"802.11 n", 0,	"802.11 g+n",	"802.11 b+g+n",0
#endif
			};
		MIB_CE_MBSSIB_T Entry;
		wlan_getEntry(&Entry, 0);
		return boaWrite (wp, "%s", wlan_band[Entry.wlanBand]);
	}
	if( !strncmp(name, "wlTxPower", 9) ) {
		unsigned char vChar;
		mib_get( MIB_TX_POWER, (void *)&vChar);
		if(vChar == 0)
			return boaWrite (wp, "100%%");
		else if(vChar == 1)
			return boaWrite (wp, "80%%");
		else if(vChar == 2)
			return boaWrite (wp, "60%%");
		else if(vChar == 3)
			return boaWrite (wp, "25%%");
		else
			return boaWrite (wp, "10%%");
	}
	if( !strncmp(name, "wlanBssid", 9) ) {
		unsigned char strbf[20];
		mib_get(MIB_ELAN_MAC_ADDR, (void *)buffer);
		snprintf(strbf, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
				buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5]);
		return boaWrite(wp, "%s", (void *)strbf);
	}
	if( !strncmp(name, "wlanSsidAttr", 12) ) {
		MIB_CE_MBSSIB_T Entry;
		wlan_getEntry(&Entry, 0);
		return boaWrite (wp, (Entry.hidessid==0)?"Visual":"Hidden");
	}
	if( !strncmp(name, "ssidName", 8) ) {
		MIB_CE_MBSSIB_T Entry;
		wlan_getEntry(&Entry, 0);
		return boaWrite(wp, "%s", (void *)Entry.ssid);
	}
	if( !strncmp(name, "encryptState", 12) ) {
		MIB_CE_MBSSIB_T Entry;
		wlan_getEntry(&Entry, 0);
		return boaWrite (wp, (Entry.encrypt==0)?INFO_DISABLED:INFO_ENABLED);
	}
#endif
	//add end by liuxiao 2008-01-28 for wlan status
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	if( !strncmp(name, "lan-mac", 7) ) {
		unsigned char strbf[20];
		mib_get(MIB_ELAN_MAC_ADDR, (void *)buffer);
		snprintf(strbf, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
				buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5]);
		return boaWrite(wp, "%s", (void *)strbf);
	}
	if (!strcmp(name, "usbstate")){
		FILE *fp = fopen("/proc/led_usb", "r");
		char buf[100]={0};
		boaWrite(wp, "<tr><td width=168 class=\"hdb\">USB设备</td><td width=320 class=\"hdt\">");
		if(fp){
			if(fgets(buf, 100, fp)!=NULL){
				if(strstr(buf, "off")){
					//because of HW layout, usb port 1 plug detect by folder created
					if(IsFolderExist("/sys/bus/usb/devices/3-1.2")){
						boaWrite(wp, "已连接");
					}
					else if(IsFolderExist("/mnt/usb1_1")){
						boaWrite(wp, "已连接");
					}
					else{
						boaWrite(wp, "未连接");
					}
				}
				else
					boaWrite(wp, "已连接");
			}
			else
				boaWrite(wp, "不支援");
			fclose(fp);
		}
		else{
			boaWrite(wp, "不支援");
		}
		boaWrite(wp, "</td></tr>");
	}
#else
	if (!strcmp(name, "usbstate")) {
		int fd;
		#ifdef CONFIG_USB_DEVICEFS
		char *buf = "/proc/bus/usb/devices";
		#else
		char *buf = "/sys/kernel/debug/usb/devices";
		#endif

		if (access(buf, R_OK) < 0) {
			#ifdef CONFIG_USB_DEVICEFS
			va_cmd("/bin/mount", 4, 1, "-t", "usbfs", "none", "/proc/bus/usb");
			#else
			va_cmd("/bin/mount", 4, 1, "-t", "debugfs", "none", "/sys/kernel/debug/");
			#endif
		}
		if ((fd = open(buf, O_RDONLY)) == -1) {
			fprintf(stderr, "cannot open %s, %s (%d)\n", buf, strerror(errno), errno);
			return -1;
		}
		devtree_parsedevfile(fd);
		close(fd);
		devtree_processchanges();
		devtree_dump_for_web(wp);

		return 0;
	}
#endif
	/* End Magician: Copy from Realsil E8B */

	// Magician: Get primary DNS of default gateway.
	if( !strncmp(name, "wan-dns-1", 10) )
	{
		FILE *fp;
		char dns[64];
		int ret = -1;

		if (!(fp=fopen(RESOLV_BACKUP, "r"))) {
			fclose(fp);
			printf("Error: cannot open %s !!\n", RESOLV_BACKUP);
			return ret;
		}

		while( fgets(dns, sizeof(dns), fp) != NULL )
		{
			if ( (strchr(dns, '.') != NULL))
			{
				boaWrite(wp, "%s", dns);
				ret = 0;
				break;
			}
		}
		fclose(fp);
		return ret;
	}

	// Magician: Get 2nd DNS of default gateway.
	if( !strncmp(name, "wan-dns-2", 10) )
	{
		FILE *fp;
		char dns[64];
		int order=0;
		int ret = -1;

		if (!(fp=fopen(RESOLV_BACKUP, "r"))) {
			fclose(fp);
			printf("Error: cannot open %s !!\n", RESOLV_BACKUP);
			return ret;
		}

		while( fgets(dns, sizeof(dns), fp) != NULL )
		{
			if ( (strchr(dns, '.') != NULL))
			{
				order++;
				if(order == 2)
				{
					boaWrite(wp, "%s", dns);
					ret = 0;
					break;
				}
			}
		}
		fclose(fp);
		return ret;
	}

	// Mason Yu: Get 1st DNSv6 server
	if( !strncmp(name, "wan-dns6-1", 10) )
	{
		FILE *fp;
		char dns[64];
		int ret = -1;

		if (!(fp=fopen(RESOLV_BACKUP, "r"))) {
			fclose(fp);
			printf("Error: cannot open %s !!\n", RESOLV_BACKUP);
			return ret;
		}

		while( fgets(dns, sizeof(dns), fp) != NULL )
		{
			if ( (strchr(dns, ':') != NULL))
			{
				boaWrite(wp, "%s", dns);
				ret = 0;
				break;
			}
		}
		fclose(fp);
		return ret;
	}

	// Mason Yu: Get 2nd DNSv6 server
	if( !strncmp(name, "wan-dns6-2", 10) )
	{
		FILE *fp;
		char dns[64];
		int order=0;
		int ret = -1;

		if (!(fp=fopen(RESOLV_BACKUP, "r"))) {
			fclose(fp);
			printf("Error: cannot open %s !!\n", RESOLV_BACKUP);
			return ret;
		}

		while( fgets(dns, sizeof(dns), fp) != NULL )
		{
			if ( (strchr(dns, ':') != NULL))
			{
				order++;
				if(order == 2)
				{
					boaWrite(wp, "%s", dns);
					ret = 0;
					break;
				}
			}
		}
		fclose(fp);
		return ret;
	}

	if( !strncmp(name, "dnsv6-mode", 10) )
	{
		unsigned char dnsv6Mode=0;
		unsigned int ext_if = 0;
		mib_get(MIB_LAN_DNSV6_MODE,(void*)&dnsv6Mode);
		//printf("dnsv6Mode %d \n", dnsv6Mode);
		if(dnsv6Mode == IPV6_DNS_WANCONN){
			mib_get(MIB_DNSINFO_WANCONN,(void*)&ext_if);
			//printf("MIB_DNSINFO_WANCONN %d \n", ext_if);
			return boaWrite(wp, "%d", ext_if);
		}
		else {
			return boaWrite(wp, "%d", dnsv6Mode);
		}
	}

	if( !strncmp(name, "voiceName", 9) ) {
		return boaWrite(wp, WAN_VOIP_VOICE_NAME);
	}
	
	if( !strcmp(name, "ponmode") )
	{
		int ponmode=0;
#if defined(CONFIG_LUNA) && (defined(CONFIG_GPON_FEATURE)||defined(CONFIG_EPON_FEATURE))
		mib_get(MIB_PON_MODE,(void*)&ponmode);

#endif
		return boaWrite(wp, "%d", ponmode);
	}
#ifdef CONFIG_CT_AWIFI_JITUAN_FEATURE
	if( !strcmp(name,"awifi-portal-url") )
	{
		char tmpurl[MAX_SERVERURL_LEN+1];
		unsigned char lan_ip[IP_ADDR_LEN] = {0};
		char lan_ip_str[INET_ADDRSTRLEN] = {0};
		unsigned char macadd[MAC_ADDR_LEN];
		char auth_mac[20];
		int gwport, i;
		char devicename[64] =  {0};
		char tmpbuf[MAX_SERVERURL_LEN+1];
		geAwifiVersion(tmpbuf, MAX_SERVERURL_LEN);
		mib_get(MIB_DEVICE_NAME, (void *) devicename);
#ifdef CONFIG_CT_AWIFI_JITUAN_SMARTWIFI
		mib_get(AWIFI_LAN_REG_SERVER,tmpurl);
#endif

#ifdef CONFIG_CT_AWIFI_JITUAN_SMARTWIFI	
		if(getgwaddrFromaWiFiConf(lan_ip_str) == 0)
#endif			
		{
			mib_get(MIB_ADSL_LAN_IP2, lan_ip);
			inet_ntop(AF_INET, lan_ip, lan_ip_str, INET_ADDRSTRLEN);
		}

#ifdef CONFIG_CT_AWIFI_JITUAN_SMARTWIFI	
		if(getgwportFromaWiFiConf(&gwport) == 0)
#endif			
		{
			gwport = DEFAULT_GATEWAYPORT;
		}

		mib_get(MIB_ELAN_MAC_ADDR, macadd);
		
		sprintf(auth_mac, "%02x%02x%02x%02x%02x%02x", macadd[0], macadd[1],
			macadd[2], macadd[3], macadd[4], macadd[5]);
	
		for (i = 0; i < strlen(auth_mac); i++) 
		{
			auth_mac[i] = toupper(auth_mac[i]);
		}
		auth_mac[i] = '\0';
		return boaWrite(wp, "\"window.open('http://%s/api10/register.htm?gw_address=%s&gw_port=%d&gw_id=%s&gw_mac=%s&soft_ver=%s');\"",
			tmpurl,lan_ip_str, gwport,devicename,auth_mac,tmpbuf);
	}

	if( !strcmp(name,"awifi-version") )
	{
#ifdef CONFIG_CT_AWIFI_JITUAN_SMARTWIFI	
		FILE *fp;
		unsigned char tmp[64];
		char tmpbuf[MAX_SERVERURL_LEN+1];
		tmp[0]=0;
		fp = fopen("/var/config/awifi/binversion", "r");
		if (fp!=NULL) {
			fgets(tmp, sizeof(tmp), fp);  //main version
			fclose(fp);
		}
		if(!strlen(tmp))
			snprintf(tmpbuf,MAX_SERVERURL_LEN, "V4.0.0");
		else
			snprintf(tmpbuf,MAX_SERVERURL_LEN,"%s", tmp);
#else
		char tmpbuf[MAX_SERVERURL_LEN+1];
		mib_get(AWIFI_SOFTVER,(void*)tmpbuf);
#endif
		return boaWrite(wp, "%s", tmpbuf);
	}
#endif

#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	if( !strcmp(name, "province_sw_ver") )
	{
		mib_get(MIB_PROVINCE_SW_VERSION, (void *)buffer);

		return boaWrite(wp, "%s", buffer);
	}
	if( !strcmp(name, "web_loid_enable") )
	{
		char web_loid_enable;
		mib_get(MIB_WEB_LOID_PAGE_ENABLE, (void *)&web_loid_enable);

		return boaWrite(wp, "%d", web_loid_enable);
	}
#endif
#ifdef CONFIG_USER_CUMANAGEDEAMON
	if(!strcmp(name, "cumanage_url")){
		mib_get(CU_SRVMGT_MGTURL,(void*)buffer);
		return boaWrite(wp, "%s", buffer);
	}
	if(!strcmp(name, "cumanage_port")){
		int port;
		mib_get(CU_SRVMGT_MGTPORT,(void*)&port);
		return boaWrite(wp, "%d", port);
	}
	if(!strcmp(name, "cumanage_regstatus")){
		FILE *fp;
		fp=fopen("/var/cumanag_status","r");
		if(fp){
			buffer[0]=0;
			fgets(buffer, sizeof(buffer), fp);
			fclose(fp);
		}
		return boaWrite(wp, "%s", buffer);
	}
	if(!strcmp(name, "cumanage_connstatus")){
		FILE *fp;
		fp=fopen("/var/cumanag_connstatus","r");
		if(fp){
			buffer[0]=0;
			fgets(buffer, sizeof(buffer), fp);
			fclose(fp);
		}
		return boaWrite(wp, "%s", buffer);
	}
#endif

NEXTSTEP:
	return ret;
}

int addMenuJavaScript( request* wp,int nums,int maxchildrensize)
{
#ifdef WEB_MENU_USE_NEW
	boaWrite(wp,"<script >\n");
	int i=0;
	boaWrite(wp,"scores = new Array(%d);\n",nums);
	for(i=0;i<nums;i++ )
		boaWrite(wp,"scores[%d]='Submenu%d';\n",i,i);
	boaWrite(wp,"btns = new Array(%d);\n",nums);
	for(i=0;i<nums;i++ )
		boaWrite(wp,"btns[%d]='Btn%d';\n",i,i);
	boaWrite(wp,"\nfunction initIt()\n"
		"{\n\tdivColl = document.all.tags(\"div\");\n"
		"\tfor (i=0; i<divColl.length; i++)\n "
		"\t{\n\t\twhichEl = divColl[i];\n"
		"\t\tif (whichEl.className == \"Child\")\n"
		"\t\t\twhichEl.style.display = \"none\";\n\t}\n}\n\n");
	boaWrite(wp,"function closeMenu(el)\n"
		"{\n"
		"\tfor(i=0;i<%d;i++)\n"
		"\t{\n\t\tfor(j=0;j<%d;j++)"
		"{\n\t\t\tif(scores[i]!=el)\n"
		"\t\t\t{\n\t\t\t\tid=scores[i]+\"Child\"+j.toString();\n"
		"\t\t\t\tif(document.getElementById(id))\n"
		"\t\t\t\t{\n\t\t\t\t\tdocument.getElementById(id).style.display = \"none\";\n"
		"\t\t\t\t\twhichEl = eval(scores[i] + \"Child\");\n"
		"\t\t\t\t\twhichEl.style.display = \"none\";\n"
		"\t\t\t\t\tdocument.getElementById(btns[i]).src =\"menu-images/menu_folder_closed.gif\";\n"
		"\t\t\t\t}\n\t\t\t}\n\t\t}\n\t}\n}\n\n",nums, maxchildrensize);

	boaWrite(wp,"function expandMenu(el,imgs, num)\n"
		"{\n\tcloseMenu(el);\n");
	boaWrite(wp,"\tif (num == 0) {\n\t\twhichEl1 = eval(el + \"Child\";\n"
		"\t\tfor(i=0;i<%d;i++)\n"),nums);
	boaWrite(wp,"\t\t{\n\t\t\twhichEl = eval(scores[i] + \"Child\";\n"
		"\t\t\tif(whichEl!=whichEl1)\n "
		"\t\t\t{\n\t\t\t\twhichEl.style.display = \"none\";\n"
		"\t\t\t\tdocument.getElementById(btns[i]).src =\"menu-images/menu_folder_closed.gif\";\n"
		"\t\t\t}\n\t\t}\n"));
	boaWrite(wp,"\t\twhichEl1 = eval(el + \"Child\";\n"
		"\t\tif (whichEl1.style.display == \"none\")\n "
		"\t\t{\n"
		"\t\t\twhichEl1.style.display = \"\";\n"
		"\t\t\tdocument.getElementById(imgs).src =\"menu-images/menu_folder_open.gif\";\n"
		"\t\t}\n\t\telse {\n\t\t\twhichEl1.style.display =\"none\";\n"
		"\t\t\tdocument.getElementById(imgs).src =\"menu-images/menu_folder_closed.gif\";\n"
		"\t\t}\n\t}\n\telse {\n"));
	boaWrite(wp,"\t\tfor(i=0;i<num;i++) {\n"
		"\t\t\tid = el + \"Child\"+i.toString();\n"
		"\t\t\twhichEl1 = document.getElementById(id);\n"
		"\t\t\tif (whichEl1) {\n"
		"\t\t\t\tif (whichEl1.style.display == \"none\")\n"
		"\t\t\t\t{\n"
		"\t\t\t\t\twhichEl1.style.display = \"\";\n"
		"\t\t\t\t\tdocument.getElementById(imgs).src =\"menu-images/menu_folder_open.gif\";\n"
		"\t\t\t\t}\n\t\t\t\telse {\n\t\t\t\t\twhichEl1.style.display =\"none\";\n"
		"\t\t\t\t\tdocument.getElementById(imgs).src =\"menu-images/menu_folder_closed.gif\";\n"
		"\t\t\t\t}\n\t\t\t}\n\t\t}\n\t}\n}\n</script>\n");

	boaWrite(wp,"<style type=\"text/css\">\n"
		"\n.link {\n"
/* add by yq_zhou 09.2.02 add sagem logo for 11n*/
#ifdef CONFIG_11N_SAGEM_WEB
		"\tfont-family: arial, Helvetica, sans-serif, bold;\n\tfont-size:10pt;\n\twhite-space:nowrap;\n\tcolor: #000000;\n\ttext-decoration: none;\n}\n"
#else
		"\tfont-family: arial, Helvetica, sans-serif, bold;\n\tfont-size:10pt;\n\twhite-space:nowrap;\n\tcolor: #FFFFFF;\n\ttext-decoration: none;\n}\n"
#endif
		"</style>");
#else
	boaWrite(wp,"<script type=\"text/javascript\" src=\"/admin/mtmcode.js\">\n"
	"</script>\n"
	"\n"
	"<script type=\"text/javascript\">\n"
	"    // Morten's JavaScript Tree Menu\n"
	"    // version 2.3.2-macfriendly, dated 2002-06-10\n"
	"    // http://www.treemenu.com/\n"
	"\n"
	"    // Copyright (c) 2001-2002, Morten Wang & contributors\n"
	"    // All rights reserved.\n"
	"\n"
	"    // This software is released under the BSD License which should accompany\n");
	boaWrite(wp,"    // it in the file \"COPYING\".  If you do not have this file you can access\n"
	"    // the license through the WWW at http://www.treemenu.com/license.txt\n"
	"\n"
	"    // Nearly all user-configurable options are set to their default values.\n"
	"    // Have a look at the section \"Setting options\" in the installation guide\n"
	"    // for description of each option and their possible values.\n");
	boaWrite(wp,"\n"
	"MTMDefaultTarget = \"view\";\n"
	"\n"
	"/******************************************************************************\n"
	" * User-configurable list of icons.                                            *\n"
	" ******************************************************************************/\n");
	boaWrite(wp,"\n"
	"var MTMIconList = null;\n"
	"MTMIconList = new IconList();\n"
	"MTMIconList.addIcon(new MTMIcon(\"menu_link_external.gif\", \"http://\", \"pre\"));\n"
	"MTMIconList.addIcon(new MTMIcon(\"menu_link_pdf.gif\", \".pdf\", \"post\"));\n");
	boaWrite(wp,"\n"
	"/******************************************************************************\n"
	" * User-configurable menu.                                                     *\n"
	" ******************************************************************************/\n");
	boaWrite(wp,"\n"
	"var menu = null;\n"
	"\n"
	"menu = new MTMenu();\n");
#endif
}

// Kaohj
int checkWrite(int eid, request* wp, int argc, char **argv)
{
	char *name;
	unsigned char vChar;
	unsigned short vUShort;
	unsigned int vUInt;

   	if (boaArgs(argc, argv, "%s", &name) < 1) {
   		boaError(wp, 400, "Insufficient args\n");
   		return -1;
   	}
	if ( !strcmp(name, "devType") ) {
		if ( !mib_get( MIB_DEVICE_TYPE, (void *)&vChar) )
			return -1;
#ifdef EMBED
		if (0 == vChar)
			boaWrite(wp, "disableTextField(document.adsl.adslConnectionMode);");
#endif
		return 0;
	}
#ifdef CONFIG_USER_ROUTED_ROUTED
	else if ( !strcmp(name, "rip-on-0") ) {
		if ( !mib_get( MIB_RIP_ENABLE, (void *)&vChar) )
			return -1;
		if (0 == vChar)
			boaWrite(wp, "checked");
		return 0;
	}
	else if ( !strcmp(name, "rip-on-1") ) {
		if ( !mib_get( MIB_RIP_ENABLE, (void *)&vChar) )
			return -1;
		if (1 == vChar)
			boaWrite(wp, "checked");
		return 0;
	}
	if ( !strcmp(name, "rip-ver") ) {
		if ( !mib_get( MIB_RIP_VERSION, (void *)&vChar) )
			return -1;
		if (0==vChar) {
			boaWrite(wp, "<option selected value=0>v1</option>\n");
			boaWrite(wp, "\t<option value=1>v2</option>");
		} else {
			boaWrite(wp, "<option value=0>v1</option>\n");
			boaWrite(wp, "\t<option selected value=1>v2</option>\n");
		}
		return 0;
	}
#endif
#ifdef CONFIG_USER_ZEBRA_OSPFD_OSPFD
	if (!strcmp(name, "ripEn"))
	{
#ifdef CONFIG_USER_ROUTED_ROUTED
		if (!mib_get(MIB_RIP_ENABLE, (void *)&vChar))
			return -1;
#else
		vChar = 0;
#endif
		if (1 == vChar)
			boaWrite(wp, "1");
		else
			boaWrite(wp, "0");

		return 0;
	}
	if (!strcmp(name, "ospfEn"))
	{
		if (!mib_get(MIB_OSPF_ENABLE, (void *)&vChar))
			return -1;
		if (1 == vChar)
			boaWrite(wp, "1");
		else
			boaWrite(wp, "0");

		return 0;
	}
#endif
if (!strcmp (name, "SoftwareVersion"))
    {


      return 0;
    }


  if (!strcmp (name, "DnsServer"))
    {
   boaWrite (wp,
                 "<tr bgcolor=\"#EEEEEE\">\n<td width=20%%><font size=2><b>DNS Servers</b></td>");
  boaWrite (wp, " <td width=80%%><font size=2>");
      getNameServer (0, wp, 1, 0);
      boaWrite (wp, "</td>\n</tr>");
      return 0;
    }

  if (!strcmp (name, "DefaultGw"))
    {
    boaWrite (wp,
                 "<tr bgcolor=\"#DDDDDD\">\n <td width=20%% ><font size=2><b>Default Gateway</b></td>");
	  boaWrite (wp, "<td width=80%% colspan=\"6\"><font size=2>");
      getDefaultGW (0, wp, 1, 0);
      boaWrite (wp, "</td> </tr>");

      return 0;
    }

	if (!strcmp (name, "wlaninfo"))
	{
#ifdef WLAN_SUPPORT
      		const char *bgColor[]={"#EEEEEE","#DDDDDD"};
      		int col_nums=0;
      		const char *wlan_band[] ={0,"802.11b","802.11g","802.11 b+g",0};
      		unsigned char vChar;
		MIB_CE_MBSSIB_T Entry;
		wlan_getEntry(&Entry, 0);
	 	boaWrite(wp,"<tr>\n <td width=100%% colspan=\"2\" bgcolor=\"#008000\"><font color=\"#FFFFFF\" size=2><b>Wireless Configuration</b></font></td>");
	  	boaWrite(wp,"<tr bgcolor=%s> <td width=40%%><font size=2><b>Wireless</b></td>",bgColor[col_nums++%2]);

      		//ramen--wireless enable??
      		boaWrite (wp, "<td width=60%%><font size=2>");

     		vChar = Entry.wlanDisabled;
      		if (!vChar)
        		boaWrite (wp, INFO_ENABLED);
      		else{
          		boaWrite (wp, INFO_DISABLED);
          		boaWrite (wp, "\n</td>\n</tr>\n");
          		goto wlend;
        	}

      		boaWrite (wp, "\n</td>\n</tr>\n");

      		//ramen--get the wireless band
	   	boaWrite (wp,"<tr bgcolor=%s> <td width=40%%><font size=2><b>band</b></td>",bgColor[col_nums++%2]);
      		boaWrite (wp, "<td width=60%%><font size=2>");
		vChar = Entry.wlanBand;
     	 	boaWrite (wp, "%s", wlan_band[(BAND_TYPE_T) vChar]);
      		boaWrite (wp, "\n</td>\n</tr>\n");

	  //ramen--get wireless mode
	  	{
			vChar = Entry.wlanMode;
			boaWrite (wp,  "<tr bgcolor=%s> <td width=40%%><font size=2><b>Mode</b></td>",bgColor[col_nums++%2]);
          		boaWrite (wp, "<td width=60%%><font size=2>");

          		if (vChar == AP_MODE)
            			boaWrite (wp, "AP");
          		else if (vChar == CLIENT_MODE)
            			boaWrite (wp, "Client");
          		else if (vChar == AP_WDS_MODE)// jim support wds info shown.
            			boaWrite (wp, "AP+WDS");
          		else if (vChar == WDS_MODE)
            			boaWrite (wp, "WDS");
          		boaWrite (wp, "\n</td>\n</tr>\n");
        	}

      	//ramen---broadcast SSID
	    	boaWrite (wp,  "<tr bgcolor=%s> <td width=40%%><font size=2><b>Broadcast  SSID</b></td>",bgColor[col_nums++%2]);
     		boaWrite (wp, "<td width=60%%><font size=2>");
		vChar = Entry.hidessid;
          	boaWrite (wp, (vChar!=0)?INFO_DISABLED:INFO_ENABLED);
          	boaWrite (wp, "\n</td>\n</tr>\n");

wlend:
      		boaWrite (wp, "</tr>");
#endif
      		return 0;

	}

 	if(!strcmp(name,"wlanencryptioninfo"))
  	{
  		return 0;
  	}

  	if (!strcmp(name,"wlanClient"))
    	{
#ifdef WLAN_SUPPORT
 		boaWrite(wp,"<P><table border=0 width=\"550\">"
                     "<tr> <td width=100%% colspan=\"6\" bgcolor=\"#008000\"><font color=\"#FFFFFF\" size=2><b>Wireless Client List</b></font></td> </tr>"
                     "<tr bgcolor=#7f7f7f><td width=\"25%%\"><font size=2><b>MAC Address</b></td>"
                     "<td width=\"15%%\"><font size=2><b>Tx Packet</b></td>"
                     "<td width=\"15%%\"><font size=2><b>Rx Packet</b></td>"
                     "<td width=\"15%%\"><font size=2><b>Tx Rate (Mbps)</b></td>"
                     "<td width=\"15%%\"><font size=2><b>Power Saving</b></td>"
                     "<td width=\"15%%\"><font size=2><b>Expired Time (s)</b></td></tr>");
			// Mason Yu. t123
      		//wirelessClientList(0,wp,1,0);
      		boaWrite(wp,"</table>");
#endif
      		return 0;
    	}

  	if (!strcmp(name,"wlanAccessControl"))
    	{
#ifdef WLAN_SUPPORT
#ifdef WLAN_ACL
      		unsigned char vChar;
      		char *acType[]={"Disable","Allow Listed","Deny Listed"};

      		mib_get( MIB_WLAN_AC_ENABLED, (void *)&vChar);
   		boaWrite(wp,"<P><table border=0 width=550>"
                     "<tr> <td width=100%%  bgcolor=\"#008000\" colspan=\"2\"><font color=\"#FFFFFF\" size=2><b>Current Access Control List:</b></font></td> </tr>");
      		boaWrite(wp,"<tr bgcolor=\"#EEEEEE\"><td><font size=2><b>Mode</b></font></td><td align=left><font size=2>%s</font></td></tr>",acType[vChar]);

      		if (vChar){
				// Mason Yu. t123
          		//wlShowAcList(0,wp,1,0);
        	}

      		boaWrite(wp," </table>");
#endif
#endif
      		return 0;
    	}
	
	if ( !strcmp(name, "procfg") ) 
		{
		unsigned char procfg = 0;
		mib_get(PROVINCE_SICHUAN_PROCFG, &procfg);
		if(procfg){
			boaWrite(wp, "1");
		}
		else{
			boaWrite(wp, "0");
		}
		return 0;
		}

  	if (!strcmp (name, "showpvctable0"))
    	{
   		boaWrite (wp,"<table border=\"0\" width=700><tr><font size=2><b>Current ATM VC Table:</b></font></tr>");
      		atmVcList2 (0, wp, 1, 0);
      		boaWrite (wp, "</table>");
      		return 0;
    	}

  if (!strcmp (name, "showpvctable1"))
    {
      boaWrite (wp,
                 "<table border=\"0\" width=700><tr><font size=2><b>Current ATM VC Table:</b></font></tr>");
      atmVcList2 (0, wp, 1, 0);
      boaWrite (wp, "</table>");
      return 0;
    }
	if ( !strcmp(name, "dhcpMode") ) {
 		if ( !mib_get( MIB_DHCP_MODE, (void *)&vChar) )
			return -1;
/*		if (vChar == 0) {
			boaWrite(wp, "<option selected value=\"0\">None</option>\n" );
			boaWrite(wp, "<option value=\"1\">DHCP Relay</option>\n" );
			boaWrite(wp, "<option value=\"2\">DHCP Server</option>\n" );
		}
		if (vChar == 1) {
			boaWrite(wp, "<option selected value=\"1\">DHCP Relay</option>\n" );
			boaWrite(wp, "<option value=\"0\">None</option>\n" );
			boaWrite(wp, "<option value=\"2\">DHCP Server</option>\n" );
		}
		if (vChar == 2) {
			boaWrite(wp, "<option selected value=\"2\">DHCP Server</option>\n" );
			boaWrite(wp, "<option value=\"0\">None</option>\n" );
			boaWrite(wp, "<option value=\"1\">DHCP Relay</option>\n" );
		}*/
		boaWrite(wp, "<input type=\"radio\" name=dhcpdenable value=0 onClick=\"disabledhcpd()\">None&nbsp;&nbsp;\n" );
		boaWrite(wp, "<input type=\"radio\"name=dhcpdenable value=1 onClick=\"enabledhcprelay()\">DHCP Relay&nbsp;&nbsp;\n" );
		boaWrite(wp, "<input type=\"radio\"name=dhcpdenable value=2 onClick=\"enabledhcpd()\">DHCP Server&nbsp;&nbsp;\n" );
		return 0;
	}

	if (!strcmp(name, "wan-interface-name")) {
		int mibTotal, i;
		MIB_CE_ATM_VC_T vcEntry;
		char interface_name[MAX_WAN_NAME_LEN];

		mibTotal = mib_chain_total(MIB_ATM_VC_TBL);
		for (i=0; i<mibTotal; i++) {
			if (!mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&vcEntry)) {
				printf("get mib_atm_vc_tbl error!\n");
			}

			if (vcEntry.cmode == CHANNEL_MODE_BRIDGE)
				continue;

			//get name
			getWanName(&vcEntry, interface_name);
			boaWrite(wp, "<option value=\"%s\">%s</option>\n",interface_name,interface_name);
		}
	}

#ifdef CONFIG_SUPPORT_AUTO_DIAG
		if (!strcmp(name, "autoDiagURL")) {
			unsigned char url[128];
			if (!mib_get(MIB_AUTO_DIAG_URL, (void *)url))
				return -1;

			boaWrite(wp, "value=\"%s\"", url);
		}
		if (!strcmp(name, "autoDiagEnable")) {
			if (!mib_get(MIB_AUTO_DIAG_ENABLE, (void *)&vChar))
				return -1;

			if(0 == vChar)
				boaWrite(wp, "关闭");
			else
				boaWrite(wp, "开启");
		}

		if (!strcmp(name, "QOEEnable"))
		{
			if (!mib_get(CWMP_CT_QOE_ENABLE, (void *)&vChar))
				return -1;

			if(0 == vChar)
				boaWrite(wp, "关闭");
			else
				boaWrite(wp, "开启");
		}
		if (!strcmp(name, "QOE_URL")) {
			unsigned char url[128];
			if (!mib_get(CWMP_CT_QOE_TESTDOWNLOADURL, (void *)url))
				return -1;

			boaWrite(wp, "value=\"%s\"", url);
		}
#endif

	if ( !strcmp(name, "dhcpV6Mode") ) {
 		if ( !mib_get( MIB_DHCP_MODE, (void *)&vChar) )
			return -1;
/*		if (vChar == 0) {
			boaWrite(wp, "<option selected value=\"0\">None</option>\n" );
			boaWrite(wp, "<option value=\"1\">DHCP Relay</option>\n" );
			boaWrite(wp, "<option value=\"2\">DHCP Server</option>\n" );
		}
		if (vChar == 1) {
			boaWrite(wp, "<option selected value=\"1\">DHCP Relay</option>\n" );
			boaWrite(wp, "<option value=\"0\">None</option>\n" );
			boaWrite(wp, "<option value=\"2\">DHCP Server</option>\n" );
		}
		if (vChar == 2) {
			boaWrite(wp, "<option selected value=\"2\">DHCP Server</option>\n" );
			boaWrite(wp, "<option value=\"0\">None</option>\n" );
			boaWrite(wp, "<option value=\"1\">DHCP Relay</option>\n" );
		}*/
		boaWrite(wp, "<input type=\"radio\" name=dhcpdenable value=0 onClick=\"disabledhcpd()\">Disable&nbsp;\n" );
		//hide unneed UI for real world IPv6 usage
		boaWrite(wp, "<div id=advancedDHCPv6setting style=\"display:none\">" );
			boaWrite(wp, "<input type=\"radio\"name=dhcpdenable value=1 onClick=\"enabledhcprelay()\">Relay&nbsp;\n" );
			boaWrite(wp, "<input type=\"radio\"name=dhcpdenable value=2 onClick=\"enabledhcpd()\">Server(Manual)&nbsp;\n" );
		boaWrite(wp, "</div>" );
			boaWrite(wp, "<input type=\"radio\"name=dhcpdenable value=3 onClick=\"autodhcpd()\">Enable;\n" );
		return 0;
	}

#ifdef ADDRESS_MAPPING
#ifndef MULTI_ADDRESS_MAPPING
	if ( !strcmp(name, "addressMapType") ) {
 		if ( !mib_get( MIB_ADDRESS_MAP_TYPE, (void *)&vChar) )
			return -1;

		boaWrite(wp, "<option value=0>None</option>\n" );
		boaWrite(wp, "<option value=1>One-to-One</option>\n" );
		boaWrite(wp, "<option value=2>Many-to-One</option>\n" );
		boaWrite(wp, "<option value=3>Many-to-Many Overload</option>\n" );
		// Mason Yu on True
		boaWrite(wp, "<option value=4>One-to-Many</option>\n" );
		return 0;
	}
#endif	// end of !MULTI_ADDRESS_MAPPING
#endif

#ifdef WLAN_SUPPORT
#ifdef WLAN_ACL
	if (!strcmp(name, "wlanAcNum")) {
		MIB_CE_WLAN_AC_T entry;
		int i;
		vUInt = mib_chain_total(MIB_WLAN_AC_TBL);
		for (i=0; i<vUInt; i++) {
			if (!mib_chain_get(MIB_WLAN_AC_TBL, i, (void *)&entry)) {
				i = vUInt;
				break;
			}
			if(entry.wlanIdx == wlan_idx)
				break;
		}
		if (i == vUInt)
			boaWrite(wp, "disableDelButton();");
		return 0;
	}
#endif
#ifdef WLAN_WDS
		if (!strcmp(name, "wlanWDSNum")) {
			vUInt = mib_chain_total(MIB_WDS_TBL);
			if (0 == vUInt)
				boaWrite(wp, "disableDelButton();");
			return 0;
		}
#endif
	if ( !strcmp(name, "wlmode") ) {
		MIB_CE_MBSSIB_T Entry;
		if(!wlan_getEntry(&Entry, 0))
			return -1;
		vChar = Entry.wlanMode;
		if (vChar == AP_MODE) {
			boaWrite(wp, "<option selected value=\"0\">AP</option>\n" );
#ifdef WLAN_CLIENT
			boaWrite(wp, "<option value=\"1\">Client</option>\n" );
#endif
#ifdef WLAN_WDS
			boaWrite(wp, "<option value=\"3\">AP+WDS</option>\n" );
#endif
		}
#ifdef WLAN_CLIENT
		if (vChar == CLIENT_MODE) {
			boaWrite(wp, "<option value=\"0\">AP</option>\n" );
			boaWrite(wp, "<option selected value=\"1\">Client</option>\n" );
#ifdef WLAN_WDS

			boaWrite(wp, "<option value=\"3\">AP+WDS</option>\n" );
#endif
		}
#endif
#ifdef WLAN_WDS
		if (vChar == AP_WDS_MODE) {
			boaWrite(wp, "<option value=\"0\">AP</option>\n" );
#ifdef WLAN_CLIENT
			boaWrite(wp, "<option value=\"1\">Client</option>\n" );
#endif
			boaWrite(wp, "<option selected value=\"3\">AP+WDS</option>\n" );
		}
#endif
		return 0;
	}
#ifdef WLAN_WDS
	if ( !strcmp(name, "wlanWdsEnabled") ) {
		if ( !mib_get( MIB_WLAN_WDS_ENABLED, (void *)&vChar) )
			return -1;
		if (1 == vChar)
			boaWrite(wp, "checked");
		return 0;
	}

#endif
	if ( !strcmp(name, "wlbandchoose") ) {
#if defined(WLAN0_5G_WLAN1_2G) || defined(CONFIG_RTL_92D_SUPPORT)
		boaWrite(wp, "<input type=\"radio\" name=\"select_2g5g\" onClick=\"BandSelected(0)\"> 5GHz");
		boaWrite(wp, "<input type=\"radio\" name=\"select_2g5g\" onClick=\"BandSelected(1)\"> 2.4GHz");
#elif defined (WLAN0_2G_WLAN1_5G)
		boaWrite(wp, "<input type=\"radio\" name=\"select_2g5g\" onClick=\"BandSelected(0)\"> 2.4GHz");
		boaWrite(wp, "<input type=\"radio\" name=\"select_2g5g\" onClick=\"BandSelected(1)\"> 5GHz");
#else
		boaWrite(wp, "<input style=\"display:none\" type=\"radio\" name=\"select_2g5g\" onClick=\"BandSelected(0)\">");
#endif
		return 0;
	}
	if ( !strcmp(name, "band") ) {
		MIB_CE_MBSSIB_T Entry;
		if(!wlan_getEntry(&Entry, 0))
			return -1;
		boaWrite(wp, "%d", Entry.wlanBand-1);
		return 0;
	}
	
	if ( !strcmp(name, "ssidLimit") ) 
	{
		unsigned char scSsidLimit = 0;
		mib_get(PROVINCE_SICHUAN_WLAN_SSID_CHINANET, &scSsidLimit);
		if(scSsidLimit)
		{
			boaWrite(wp, "1");
		}
		else
		{
			boaWrite(wp, "0");
		}
		return 0;
	}
	
	if ( !strcmp(name, "wlband") ) {
#ifdef WIFI_TEST
		boaWrite(wp, "<option value=3>WiFi-G</option>\n" );
		boaWrite(wp, "<option value=4>WiFi-BG</option>\n" );
#endif

#if defined(CONFIG_RTL_92D_SUPPORT) || defined(WLAN_DUALBAND_CONCURRENT)
		if ( !mib_get(MIB_WLAN_PHY_BAND_SELECT, (void *)&vChar) )
			return -1;

#if defined (CONFIG_RTL_92D_SUPPORT)
		unsigned char wlanBand2G5GSelect;
		if ( !mib_get(MIB_WLAN_BAND2G5G_SELECT, (void *)&wlanBand2G5GSelect) )
				return -1;
		if((vChar == PHYBAND_5G) || (wlanBand2G5GSelect == BANDMODESINGLE))
#else
		if(vChar == PHYBAND_5G)
#endif
		{
			boaWrite(wp, "<option value=3>5 GHz (A)</option>\n" );
			boaWrite(wp, "<option value=7>5 GHz (N)</option>\n" );
			boaWrite(wp, "<option value=11>5 GHz (A+N)</option>\n" );
#if defined (WLAN0_5G_11AC_SUPPORT) || defined(WLAN1_5G_11AC_SUPPORT)
			boaWrite(wp, "<option value=63>5 GHz (AC)</option>\n" );
			boaWrite(wp, "<option value=71>5 GHz (N+AC)</option>\n" );
			boaWrite(wp, "<option value=75>5 GHz (A+N+AC)</option>\n" );
#endif
		}
#endif

#if (defined (WLAN0_5G_SUPPORT) || defined(WLAN1_5G_SUPPORT)) && !defined(WLAN_DUALBAND_CONCURRENT)
		boaWrite(wp, "<option value=3>5 GHz (A)</option>\n" );
		boaWrite(wp, "<option value=7>5 GHz (N)</option>\n" );
		boaWrite(wp, "<option value=11>5 GHz (A+N)</option>\n" );
#if defined (WLAN0_5G_11AC_SUPPORT) || defined(WLAN1_5G_11AC_SUPPORT)
		boaWrite(wp, "<option value=63>5 GHz (AC)</option>\n" );
		boaWrite(wp, "<option value=71>5 GHz (N+AC)</option>\n" );
		boaWrite(wp, "<option value=75>5 GHz (A+N+AC)</option>\n" );
#endif
#endif

#if defined (CONFIG_RTL_92D_SUPPORT)
		if((vChar == PHYBAND_2G) || (wlanBand2G5GSelect == BANDMODESINGLE))
#elif defined(WLAN_DUALBAND_CONCURRENT)
		if(vChar == PHYBAND_2G)
#endif
		{
			boaWrite(wp, "<option value=0>2.4 GHz (B)</option>\n");
			boaWrite(wp, "<option value=1>2.4 GHz (G)</option>\n");
			boaWrite(wp, "<option value=2>2.4 GHz (B+G)</option>\n");
			boaWrite(wp, "<option value=7>2.4 GHz (N)</option>\n" );
			boaWrite(wp, "<option value=9>2.4 GHz (G+N)</option>\n" );
			boaWrite(wp, "<option value=10>2.4 GHz (B+G+N)</option>\n" );
		}
		return 0;
	}
	if ( !strcmp(name, "wlchanwid") ) {
		boaWrite(wp, "<option value=\"0\">20MHZ</option>\n" );
		boaWrite(wp, "<option value=\"1\">40MHZ</option>\n" );
#if defined (WLAN0_5G_11AC_SUPPORT) || defined(WLAN1_5G_11AC_SUPPORT)
		mib_get( MIB_WLAN_PHY_BAND_SELECT, (void *)&vChar);
		if(vChar == PHYBAND_5G) {
			boaWrite(wp, "<option value=\"2\">80MHZ</option>\n" );
		}
#endif
		return 0;
	}
	if ( !strcmp(name, "wlctlband") ) {
#if defined(CONFIG_USB_RTL8192SU_SOFTAP) || defined(CONFIG_RTL8192CD) || defined(CONFIG_RTL8192CD_MODULE)
		boaWrite(wp, "<option value=\"0\">Upper</option>\n" );
		boaWrite(wp, "<option value=\"1\">Lower</option>\n" );
#endif
		return 0;
	}
#if defined(CONFIG_CMCC) || defined(CONFIG_YUEME) || defined(CONFIG_CU)
	if ( !strcmp(name, "wlshortGI0") ) {
		boaWrite(wp, "<option value=\"0\">Long</option>\n" );
		boaWrite(wp, "<option value=\"1\">Short</option>\n" );
		return 0;
	}
	if ( !strcmp(name, "wlauth_type") ) {
		boaWrite(wp, "<option value=\"open\">open</option>\n" );
		boaWrite(wp, "<option value=\"shared\">shared</option>\n" );
		boaWrite(wp, "<option value=\"both\">open+share</option>\n" );
		return 0;
	}
#endif
#ifdef CONFIG_YUEME	
	if ( !strcmp(name, "wlshowSSIDidx")){
		int i=0;
		MIB_CE_MBSSIB_T wlan_Entry;
#ifdef YUEME_3_0_SPEC_SSID_ALIAS
		char phyband_name[8]={0};
#ifdef WLAN_DUALBAND_CONCURRENT
		unsigned char phyband = PHYBAND_2G;
		mib_get(MIB_WLAN_PHY_BAND_SELECT, &phyband);
		if(phyband==PHYBAND_5G)
			strcpy(phyband_name, "5G");
		else
#endif
			strcpy(phyband_name, "2.4G");
#endif
		for(i=0; i<=NUM_VWLAN_INTERFACE;i++){
			wlan_getEntry(&wlan_Entry, i);

			if(i==0)
#ifdef YUEME_3_0_SPEC_SSID_ALIAS
				boaWrite(wp, "<option value=\"%d\">%s-%d</option>\n", i, phyband_name, i+1);
#else
				boaWrite(wp, "<option value=\"%d\">SSID%d</option>\n", i, i+1+wlan_idx*(WLAN_SSID_NUM) );
#endif
			else{
#ifdef _PRMT_X_WLANFORISP_
				if(wlan_Entry.instnum != 0 && isWLANForISP(i) == 0)
#else
				if(wlan_Entry.instnum != 0)
#endif
#ifdef YUEME_3_0_SPEC_SSID_ALIAS
					boaWrite(wp, "<option value=\"%d\">%s-%d</option>\n", i, phyband_name, i+1);
#else
					boaWrite(wp, "<option value=\"%d\">SSID%d</option>\n", i, i+1+wlan_idx*(WLAN_SSID_NUM));
#endif
			}
			
		}
		return 0;
	}
#endif
	// Added by Mason Yu for TxPower
	if ( !strcmp(name, "txpower") ) {
//modified by xl_yue
#if 1 //def WLAN_TX_POWER_DISPLAY
			boaWrite(wp, "<option value=\"0\">100%%</option>\n" );
			boaWrite(wp, "<option value=\"1\">80%%</option>\n" );
			boaWrite(wp, "<option value=\"2\">60%%</option>\n" );
			boaWrite(wp, "<option value=\"3\">35%%</option>\n" );
			boaWrite(wp, "<option value=\"4\">15%%</option>\n" );
#else
 		if ( !mib_get( MIB_TX_POWER, (void *)&vChar) )
			return -1;

		if (vChar == 0) {
			boaWrite(wp, "<option selected value=\"0\">15 mW</option>\n" );
			boaWrite(wp, "<option value=\"1\">30 mW</option>\n" );
			boaWrite(wp, "<option value=\"2\">60 mW</option>\n" );
		}
		if (vChar == 1) {
			boaWrite(wp, "<option selected value=\"1\">30 mW</option>\n" );
			boaWrite(wp, "<option value=\"0\">15 mW</option>\n" );
			boaWrite(wp, "<option value=\"2\">60 mW</option>\n" );
		}
		if (vChar == 2) {
			boaWrite(wp, "<option selected value=\"2\">60 mW</option>\n" );
			boaWrite(wp, "<option value=\"0\">15 mW</option>\n" );
			boaWrite(wp, "<option value=\"1\">30 mW</option>\n" );
		}
#endif // of WLAN_TX_POWER_DISPLAY
		return 0;
	}
	if (!strcmp(name, "wifiSecurity")) {
		unsigned char mode = 0;
		MIB_CE_MBSSIB_T Entry;
		if(!wlan_getEntry(&Entry, 0))
			return -1;
		mode = Entry.wlanMode;
		boaWrite(wp, "<option value=%d>None</option>\n", WIFI_SEC_NONE);
#if defined(CONFIG_CMCC) || defined(CONFIG_YUEME) || defined(CONFIG_CU)
		boaWrite(wp, "<option value=%d>WEP</option>\n", WIFI_SEC_WEP);
		boaWrite(wp, "<option value=%d>WPA-PSK</option>\n", WIFI_SEC_WPA);
		boaWrite(wp, "<option value=%d>WPA2-PSK</option>\n", WIFI_SEC_WPA2);
#else
		boaWrite(wp, "<option value=%d>WEP</option>\n", WIFI_SEC_WEP);
		boaWrite(wp, "<option value=%d>WPA</option>\n", WIFI_SEC_WPA);
		boaWrite(wp, "<option value=%d>WPA2</option>\n", WIFI_SEC_WPA2);
#endif
		if (mode != CLIENT_MODE)
		{
#if defined(CONFIG_CMCC) || defined(CONFIG_YUEME) || defined(CONFIG_CU)
			boaWrite(wp, "<option value=%d>WPA-PSK/WPA2-PSK</option>\n", WIFI_SEC_WPA2_MIXED);
#else
		boaWrite(wp, "<option value=%d>WPA2 Mixed</option>\n", WIFI_SEC_WPA2_MIXED);
#endif
		}
#ifdef CONFIG_RTL_WAPI_SUPPORT
		boaWrite(wp, "<option value=%d>WAPI</option>\n", WIFI_SEC_WAPI);
#endif
		return 0;
	}
	if (!strcmp(name, "wpaEncrypt")) {
		unsigned char band = 0;
		MIB_CE_MBSSIB_T Entry;
		if(!wlan_getEntry(&Entry, 0))
			return -1;

		band = Entry.wlanBand;

		boaWrite(wp, "<option value=%d>None</option>\n", ENCRYPT_DISABLED);
		boaWrite(wp, "<option value=%d>WEP</option>\n", ENCRYPT_WEP);
		if (!wl_isNband(band))
			boaWrite(wp, "<option value=%d>WPA(TKIP)</option>\n", ENCRYPT_WPA_TKIP);
#ifdef ENABLE_WPAAES_WPA2TKIP
		boaWrite(wp, "<option value=%d>WPA(AES)</option>\n", ENCRYPT_WPA_AES);
#endif
		boaWrite(wp, "<option value=%d>WPA2(AES)</option>\n", ENCRYPT_WPA2_AES);
#ifdef ENABLE_WPAAES_WPA2TKIP
		if (!wl_isNband(band))
			boaWrite(wp, "<option value=%d>WPA2(TKIP)</option>\n", ENCRYPT_WPA2_TKIP);
#endif
		boaWrite(wp, "<option value=%d>WPA2 Mixed</option>\n", ENCRYPT_WPA2_MIXED);
#ifdef CONFIG_RTL_WAPI_SUPPORT
		boaWrite(wp, "<option value=%d>WAPI</option>\n", ENCRYPT_WAPI);
#endif
	}
	#ifdef WLAN_UNIVERSAL_REPEATER
	if ( !strcmp(name, "repeaterEnabled") ) {
		mib_get( MIB_REPEATER_ENABLED1, (void *)&vChar);
		if (vChar)
			boaWrite(wp, "checked");
	}
	#endif
	if( !strcmp(name, "wlan_idx") ) {
		boaWrite(wp, "%d", wlan_idx);
		return 0;
	}
	if( !strcmp(name, "2G_ssid") ) {
		char ssid[33];
		int i, orig_wlan_idx = wlan_idx;
		MIB_CE_MBSSIB_T Entry;
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		char ssid_tmp[33];
		char *ssidptr;
		unsigned char ssidprefix_enable = 0;
		mib_get(MIB_WEB_WLAN_SSIDPREFIX_ENABLE, &ssidprefix_enable);
#endif
#if defined(CONFIG_RTL_92D_SUPPORT) || defined(WLAN_DUALBAND_CONCURRENT)
		for(i=0; i<NUM_WLAN_INTERFACE; i++) {
			wlan_idx = i;
			mib_get( MIB_WLAN_PHY_BAND_SELECT, (void *)&vChar);
			if(vChar == PHYBAND_2G) {
				if(!wlan_getEntry(&Entry, 0))
					return -1;
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
				if (ssidprefix_enable==1)
				{	
					strcpy(ssid_tmp, Entry.ssid);
					if(!strcmp(ssid_tmp,"0"))
						ssidptr = ssid_tmp;
					else
#ifdef CONFIG_CU
						ssidptr = ssid_tmp+strlen("CU_");
#else
						ssidptr = ssid_tmp+strlen("CMCC-");
#endif
					strcpy(ssid, ssidptr);
				}
				else
					strcpy(ssid, Entry.ssid);
#else
				strcpy(ssid, Entry.ssid);
#endif
				boaWrite(wp, "%s", ssid);
				break;
			}
		}
#else //CONFIG_RTL_92D_SUPPORT
		if(!wlan_getEntry(&Entry, 0))
			return -1;
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		if (ssidprefix_enable==1)
		{	
			strcpy(ssid_tmp, Entry.ssid);
			strcpy(ssid, ssid_tmp+5);
		}
		else
			strcpy(ssid, Entry.ssid);
#else
		strcpy(ssid, Entry.ssid);
#endif
		boaWrite(wp, "%s", ssid);
#endif //CONFIG_RTL_92D_SUPPORT
		wlan_idx = orig_wlan_idx;
		return 0;
	}
	if( !strcmp(name, "5G_ssid") ) {
		char ssid[33];
		int i, orig_wlan_idx = wlan_idx;
		MIB_CE_MBSSIB_T Entry;
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		char ssid_tmp[33];
		char *ssidptr;
		unsigned char ssidprefix_enable = 0;
		mib_get(MIB_WEB_WLAN_SSIDPREFIX_ENABLE, &ssidprefix_enable);
#endif
#if defined(CONFIG_RTL_92D_SUPPORT) || defined(WLAN_DUALBAND_CONCURRENT)
		for(i=0; i<NUM_WLAN_INTERFACE; i++) {
			wlan_idx = i;
			mib_get( MIB_WLAN_PHY_BAND_SELECT, (void *)&vChar);
			if(vChar == PHYBAND_5G) {
				if(!wlan_getEntry(&Entry, 0))
					return -1;
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
				if (ssidprefix_enable==1)
				{	
					strcpy(ssid_tmp, Entry.ssid);
					if(!strcmp(ssid_tmp,"0"))
						ssidptr = ssid_tmp;
					else
#ifdef CONFIG_CU
						ssidptr = ssid_tmp+strlen("CU_");
#else
						ssidptr = ssid_tmp+strlen("CMCC-");
#endif
					strcpy(ssid, ssidptr);
				}
				else
					strcpy(ssid, Entry.ssid);
#else
				strcpy(ssid, Entry.ssid);
#endif
				boaWrite(wp, "%s", ssid);
				break;
			}
		}
#else //CONFIG_RTL_92D_SUPPORT
		if(!wlan_getEntry(&Entry, 0))
			return -1;
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		if (ssidprefix_enable==1)
		{	
			strcpy(ssid_tmp, Entry.ssid);
			strcpy(ssid, ssid_tmp+5);
		}
		else
			strcpy(ssid, Entry.ssid);
#else
		strcpy(ssid, Entry.ssid);
#endif
		boaWrite(wp, "%s", ssid);
#endif //CONFIG_RTL_92D_SUPPORT
		wlan_idx = orig_wlan_idx;
		return 0;
	}
	if (!strcmp(name, "dfs_enable")) {
#if defined(CONFIG_RTL_DFS_SUPPORT)
		boaWrite(wp, "1");
#else
		boaWrite(wp, "0");
#endif
		return 0;
	}
	if( !strcmp(name, "Band2G5GSupport") ) {
#if defined(CONFIG_RTL_92D_SUPPORT)  || defined(WLAN0_5G_SUPPORT) || defined(WLAN1_5G_SUPPORT)
		mib_get( MIB_WLAN_PHY_BAND_SELECT, (void *)&vChar);
		boaWrite(wp, "%d", vChar);
#else //CONFIG_RTL_92D_SUPPORT
		vChar = PHYBAND_2G;
		boaWrite(wp, "%d", vChar);
#endif //CONFIG_RTL_92D_SUPPORT
		return 0;
	}
#ifdef CONFIG_RTL_92D_SUPPORT
	if( !strcmp(name, "wlanBand2G5GSelect") ) {
		mib_get( MIB_WLAN_BAND2G5G_SELECT, (void *)&vChar);
		boaWrite(wp, "%d", vChar);
		return 0;
	}
	if( !strcmp(name, "onoff_dmdphy_comment_start") ) {
#ifdef CONFIG_RTL_92D_DMDP
		boaWrite(wp, "");
#else //CONFIG_RTL_92D_DMDP
		boaWrite(wp, "<!--");
#endif //CONFIG_RTL_92D_DMDP
		return 0;
	}

	if( !strcmp(name, "onoff_dmdphy_comment_end") ) {
#ifdef CONFIG_RTL_92D_DMDP
		boaWrite(wp, "");
#else //CONFIG_RTL_92D_DMDP
		boaWrite(wp, "-->");
#endif //CONFIG_RTL_92D_DMDP
		return 0;
	}
#endif //CONFIG_RTL_92D_SUPPORT
	if(!strcmp(name, "wlan_num")){
		boaWrite(wp, "%d", NUM_WLAN_INTERFACE);
		return 0;
	}
	if(!strcmp(name, "wlan_ssid_num")){
		boaWrite(wp, "%d", WLAN_SSID_NUM);
		return 0;
	}
	if(!strcmp(name, "wlan_ssid_num")){
		boaWrite(wp, "%d", WLAN_SSID_NUM*NUM_WLAN_INTERFACE);
		return 0;
	}
#ifdef WIFI_TIMER_SCHEDULE
	if(!strcmp(name, "wifi_timer_ssid_name")){
#ifdef YUEME_3_0_SPEC_SSID_ALIAS
		boaWrite(wp, "[\"2.4G-1\",\"2.4G-2\", \"2.4G-3\", \"2.4G-4\", \"2.4G-5\", \"2.4G-6\", \"2.4G-7\", \"2.4G-8\","
						"\"5G-1\",\"5G-2\", \"5G-3\", \"5G-4\", \"5G-5\", \"5G-6\", \"5G-7\", \"5G-8\"]");
#else
		boaWrite(wp, "[\"1\",\"2\", \"3\", \"4\", \"5\", \"6\", \"7\", \"8\", \"9\", \"10\", \"11\", \"12\", \"13\", \"14\", \"15\", \"16\"]");
#endif
		return 0;
	}
#endif
	if(!strcmp(name,"wlan_support_8812e")) //8812
	{
#if (defined(CONFIG_RTL_8812_SUPPORT) && !defined(CONFIG_RTL_8812AR_VN_SUPPORT)) || defined(WLAN0_5G_11AC_SUPPORT) || defined(WLAN1_5G_11AC_SUPPORT)
		boaWrite(wp, "1");
#else
		boaWrite(wp, "0");
#endif
		return 0;
	}
	if(!strcmp(name, "wlan_module_enable"))
	{
#ifdef YUEME_3_0_SPEC
		if(argc==2){
			if(!strcmp(argv[1], "0"))
				mib_local_mapping_get(MIB_WLAN_DISABLED, 0, (void *)&vChar);
			else
#ifdef WLAN_DUALBAND_CONCURRENT
				mib_local_mapping_get(MIB_WLAN_DISABLED, 1, (void *)&vChar);
#else
				vChar = 1;
#endif
		}
		else{
			mib_get(MIB_WLAN_DISABLED, (void *)&vChar);	
		}
		if(vChar == 0)
			boaWrite(wp, "1");
		else
			boaWrite(wp, "0");
#else
		mib_get(MIB_WIFI_MODULE_DISABLED, (void *)&vChar);
		if(vChar == 0)
			boaWrite(wp, "1");
		else
			boaWrite(wp, "0");
#endif

		return 0;
	}
	if(!strcmp(name,"wlan_sta_control")){
#if defined(CONFIG_RTL_STA_CONTROL_SUPPORT) && defined(WLAN_DUALBAND_CONCURRENT)
		if(!get_root_wlan_status())
			return 0;

		boaWrite(wp, "<table border=\"0\" cellpadding=\"4\" cellspacing=\"0\">\n"
		"\t<tr><td valign=\"middle\" align=\"center\" width=\"30\" height=\"30\">\n"
		"\t\t<input type='checkbox' name='wlanStaControl' onClick='' value=\"ON\"></td>\n"
		"\t\t<td>启用双频设定为相同的SSID (此功能启用时双频使用相同SSID及加密模式)</td></tr>\n"
		"\t</table>\n");
#endif
		return 0;
	}
	if(!strcmp(name,"wlan_rate_prior_enable")){
#ifdef WLAN_RATE_PRIOR
		boaWrite(wp, "1");
#else
		boaWrite(wp, "0");
#endif
		return 0;
	}
#ifdef WLAN_11R
	if(!strcmp(name, "11r_ftkh_num")){
		boaWrite(wp, "%d", MAX_VWLAN_FTKH_NUM);
		return 0;
	}
#endif
	if(!strcmp(name,"wlan_txpower_high_enable")){
#ifdef WLAN_TXPOWER_HIGH
		boaWrite(wp, "1");
#else
		boaWrite(wp, "0");
#endif
		return 0;
	}
#endif // of WLAN_SUPPORT
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	if ( !strcmp(name, "user_mode") ) {
		struct user_info *pUser_info;
		pUser_info = search_login_list(wp);
		if (!pUser_info)
			return -1;

		boaWrite(wp, "%d", pUser_info->priv);
		return 0;
	}
	if ( !strcmp(name, "province_set") ) {
		unsigned char InformType = 0;

		mib_get(PROVINCE_CWMP_INFORM_TYPE, &InformType);
		if (InformType == CWMP_INFORM_TYPE_CMCC_SHD)
			boaWrite(wp, "%d", 1);
		else
			boaWrite(wp, "%d", 0);
		return 0;
	}
	if ( !strcmp(name, "ssid2_enable") ) {
		unsigned char ssid2_enable = 0;

		mib_get(MIB_WEB_WLAN_SSID2_ENABLE, &ssid2_enable);
		if (ssid2_enable==1)
			boaWrite(wp, "%d", 1);
		else
			boaWrite(wp, "%d", 0);
		return 0;
	}
	if ( !strcmp(name, "ssid2_only_enable") ) {
		unsigned char ssid2_only_enable = 0;

		mib_get(MIB_WEB_WLAN_SSID2_ONLY_ENABLE, &ssid2_only_enable);
		if (ssid2_only_enable==1)
			boaWrite(wp, "%d", 1);
		else
			boaWrite(wp, "%d", 0);
		return 0;
	}
	if ( !strcmp(name, "ssidprefix_enable") ) {
		unsigned char ssidprefix_enable = 0;

		mib_get(MIB_WEB_WLAN_SSIDPREFIX_ENABLE, &ssidprefix_enable);
		if (ssidprefix_enable==1)
			boaWrite(wp, "%d", 1);
		else
			boaWrite(wp, "%d", 0);
		return 0;
	}
#endif	
	if(!strcmp(name, "wlan_interface_change")){
#if defined (WLAN_SUPPORT) && defined(CONFIG_YUEME) && defined(CONFIG_LUNA_DUAL_LINUX)
		boaWrite(wp, "1");
#else
		boaWrite(wp, "0");
#endif
		return 0;
	}
	if(!strcmp(name, "lan_interface_num")){
#if defined (WLAN_SUPPORT)
		boaWrite(wp, "%d", (4+WLAN_MAX_ITF_INDEX*2));
#else
		boaWrite(wp, "14");
#endif
		return 0;
	}
	if(!strcmp(name, "wlan_interface_num")){
#if defined (WLAN_SUPPORT)
		boaWrite(wp, "%d", (WLAN_MAX_ITF_INDEX));
#else
		boaWrite(wp, "0");
#endif
		return 0;
	}

	if ( !strcmp(name, "wapiScript0") ) {
		#ifdef CONFIG_RTL_WAPI_SUPPORT
		boaWrite(wp, "if ( (form.method.selectedIndex == 2 && wpaAuth[0].checked) ) {"\
			"\tdisableTextField(form.radiusPort);"\
			"\tenableTextField(form.radiusIP);"\
			"\tdisableTextField(form.radiusPass);"\
			"\tdisableTextField(document.formEncrypt.pskFormat);"\
			"\tdisableTextField(document.formEncrypt.pskValue);"\
			"} else");
		#endif
	}

	// Added by Mason Yu for 2 level web page
	if ( !strcmp(name, "userMode") ) {
		#ifdef ACCOUNT_CONFIG
		MIB_CE_ACCOUNT_CONFIG_T Entry;
		int totalEntry, i;
		#else
		char suStr[100], usStr[100];
		#endif
#ifdef ACCOUNT_CONFIG
		#ifdef USE_LOGINWEB_OF_SERVER
		if (!strcmp(g_login_username, suName))
		#else
		if (!strcmp(wp->user, suName))
		#endif
		{
			boaWrite(wp, "<option selected value=\"0\">%s</option>\n", suName);
			boaWrite(wp, "<option value=\"1\">%s</option>\n", usName);
		}
		#ifdef USE_LOGINWEB_OF_SERVER
		else if (!strcmp(g_login_username, usName))
		#else
		else if (!strcmp(wp->user, usName))
		#endif
		{
			boaWrite(wp, "<option value=\"0\">%s</option>\n", suName);
			boaWrite(wp, "<option selected value=\"1\">%s</option>\n", usName);
		}
		totalEntry = mib_chain_total(MIB_ACCOUNT_CONFIG_TBL);
		for (i=0; i<totalEntry; i++) {
			if (!mib_chain_get(MIB_ACCOUNT_CONFIG_TBL, i, (void *)&Entry))
				continue;
			#ifdef USE_LOGINWEB_OF_SERVER
			if (!strcmp(g_login_username, Entry.userName))
			#else
			if (strcmp(wp->user, Entry.userName) == 0)
			#endif
				boaWrite(wp, "<option selected value=\"%d\">%s</option>\n", i+2, Entry.userName);
			else
				boaWrite(wp, "<option value=\"%d\">%s</option>\n", i+2, Entry.userName);
		}
#else
		#ifdef USE_LOGINWEB_OF_SERVER
		if (!strcmp(g_login_username, suName))
		#else
		if(!strcmp(wp->user,suName))
		#endif
			{
			sprintf(suStr, "<option selected value=\"0\">%s</option>\n", suName);
			sprintf(usStr, "<option value=\"1\">%s</option>\n", usName);
			}
		else
			sprintf(usStr, "<option selected value=\"1\">%s</option>\n", usName);

		boaWrite(wp, suStr );
		boaWrite(wp, usStr );
#endif
		return 0;
	}
	if ( !strcmp(name, "lan-dhcp-st") ) {
		if ( !mib_get( MIB_DHCP_MODE, (void *)&vChar) )
			return -1;
		if (DHCP_LAN_SERVER == vChar)
			boaWrite(wp, "Enabled");
		else
			boaWrite(wp, "Disabled");
		return 0;
	}
	else if ( !strcmp(name, "br-stp-0") ) {
		if ( !mib_get( MIB_BRCTL_STP, (void *)&vChar) )
			return -1;
		if (0 == vChar)
			boaWrite(wp, "checked");
		return 0;
	}
	else if ( !strcmp(name, "br-stp-1") ) {
		if ( !mib_get( MIB_BRCTL_STP, (void *)&vChar) )
			return -1;
		if (1 == vChar)
			boaWrite(wp, "checked");
		return 0;
	}
#ifdef CONFIG_USER_IGMPPROXY
	else if ( !strcmp(name, "igmpProxy0") ) {
		if ( !mib_get( MIB_IGMP_PROXY, (void *)&vChar) )
			return -1;
		if (0 == vChar)
			boaWrite(wp, "checked");
		if (ifWanNum("rt") ==0)
			boaWrite(wp, " disabled");
		return 0;
	}
	else if ( !strcmp(name, "igmpProxy1") ) {
		if ( !mib_get( MIB_IGMP_PROXY, (void *)&vChar) )
			return -1;
		if (1 == vChar)
			boaWrite(wp, "checked");
		if (ifWanNum("rt") ==0)
			boaWrite(wp, " disabled");
		return 0;
	}
	else if ( !strcmp(name, "igmpProxy0d") ) {
		if ( !mib_get( MIB_IGMP_PROXY, (void *)&vChar) )
			return -1;
		if (0 == vChar)
			boaWrite(wp, "disabled");
		return 0;
	}
#endif
#if defined(CONFIG_USER_PPTP_CLIENT_PPTP) || defined(CONFIG_USER_PPTPD_PPTPD)
	else if (!strcmp(name, "pptpenable0")) {
		if ( !mib_get( MIB_PPTP_ENABLE, (void *)&vUInt) )
			return -1;
		//printf("pptp %s\n", vUInt?"enable":"disable");
		if (0 == vUInt)
			boaWrite(wp, "checked");
		return 0;
	}
	else if (!strcmp(name, "pptpenable1")) {
		if ( !mib_get( MIB_PPTP_ENABLE, (void *)&vUInt) )
			return -1;
		//printf("pptp %s\n", vUInt?"enable":"disable");
		if (1 == vUInt)
			boaWrite(wp, "checked");
		return 0;
	}
#endif //end of CONFIG_USER_PPTP_CLIENT_PPTP
#if defined(CONFIG_USER_L2TPD_L2TPD) || defined(CONFIG_USER_L2TPD_LNS)
	else if (!strcmp(name, "l2tpenable0")) {
		if (!mib_get( MIB_L2TP_ENABLE, (void *)&vUInt))
			return -1;
		if (0 == vUInt)
			boaWrite(wp, "checked");
		return 0;
	}
	else if (!strcmp(name, "l2tpenable1")) {
		if ( !mib_get( MIB_L2TP_ENABLE, (void *)&vUInt) )
			return -1;
		if (1 == vUInt)
			boaWrite(wp, "checked");
		return 0;
	}
#endif //endof CONFIG_USER_L2TPD_L2TPD
//#ifdef CONFIG_USER_UPNPD
#ifdef CONFIG_USER_MINIUPNPD
	else if ( !strcmp(name, "upnp0") ) {
		if ( !mib_get( MIB_UPNP_DAEMON, (void *)&vChar) )
			return -1;
		if (0 == vChar)
			boaWrite(wp, "checked");
		if (ifWanNum("rt") ==0)
			boaWrite(wp, " disabled");
		return 0;
	}
	else if ( !strcmp(name, "upnp1") ) {
		if ( !mib_get( MIB_UPNP_DAEMON, (void *)&vChar) )
			return -1;
		if (1 == vChar)
			boaWrite(wp, "checked");
		if (ifWanNum("rt") ==0)
			boaWrite(wp, " disabled");
		return 0;
	}
	else if ( !strcmp(name, "upnp0d") ) {
		//if ( !mib_get( MIB_UPNP_DAEMON, (void *)&vChar) )
		//	return -1;
		if (ifWanNum("rt") ==0)
			boaWrite(wp, "disabled");
		return 0;
	}
#endif

// Mason Yu. MLD Proxy
#ifdef CONFIG_IPV6
#ifdef CONFIG_USER_ECMH
	else if ( !strcmp(name, "mldproxy0") ) {
		if ( !mib_get( MIB_MLD_PROXY_DAEMON, (void *)&vChar) )
			return -1;
		if (0 == vChar)
			boaWrite(wp, "checked");
		if (ifWanNum("rtv6") ==0)
			boaWrite(wp, " disabled");
		return 0;
	}
	else if ( !strcmp(name, "mldproxy1") ) {
		if ( !mib_get( MIB_MLD_PROXY_DAEMON, (void *)&vChar) )
			return -1;
		if (1 == vChar)
			boaWrite(wp, "checked");
		if (ifWanNum("rtv6") ==0)
			boaWrite(wp, " disabled");
		return 0;
	}
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	else if ( !strcmp(name, "mldproxy0dcmcc") ) {
		if (ifWanNum("rtInternetOther") ==0)
			boaWrite(wp, "disabled");
		return 0;
	}
#endif
	else if ( !strcmp(name, "mldproxy0d") ) {
		//if ( !mib_get( MIB_MLD_PROXY_DAEMON, (void *)&vChar) )
		//	return -1;
		if (ifWanNum("rtv6") ==0)
			boaWrite(wp, "disabled");
		return 0;
	}
#endif

#if defined(CONFIG_USER_DHCPV6_ISC_DHCP411)
	else if ( !strcmp(name, "prefix_delegation_info") ) {
		struct in6_addr ip6Prefix;
		unsigned char value[48], len;

		len = cmd_get_PD_prefix_len();
		if (0 == len) {
			boaWrite(wp, "");
		}
		else {
			cmd_get_PD_prefix_ip((void *)&ip6Prefix);
			inet_ntop(PF_INET6, &ip6Prefix, value, sizeof(value));
			boaWrite(wp, "%s/%d", value, len);
		}
		return 0;
	}
#endif

#endif

#ifdef NAT_CONN_LIMIT
	else if (!strcmp(name, "connlimit")) {
		if (!mib_get(MIB_NAT_CONN_LIMIT, (void *)&vChar))
			return -1;
		if (1 == vChar)
			boaWrite(wp, "checked");
	}
#endif
	else if (!strcmp(name, "telnetenable0")) {
#ifdef REMOTE_ACCESS_CTL
		MIB_CE_ACC_T Entry;
		if (!mib_chain_get(MIB_ACC_TBL, 0, (void *)&Entry))
		{
			printf("[%s %d]mib_chain_get failed\n", __func__, __LINE__);
			return -1;
		}
		else
		{
			if((Entry.telnet&0x3)==0)
			{
				boaWrite(wp, "checked");
			}
		}
#endif
		return 0;
	}
	else if (!strcmp(name, "telnetenable1")) {
#ifdef REMOTE_ACCESS_CTL
		MIB_CE_ACC_T Entry;
		if (!mib_chain_get(MIB_ACC_TBL, 0, (void *)&Entry))
		{
			printf("[%s %d]mib_chain_get failed\n", __func__, __LINE__);
			return -1;
		}
		else
		{
			if(Entry.telnet==2)
			{
				boaWrite(wp, "checked");
			}
		}
#endif
		return 0;
	}
        else if (!strcmp(name, "telnetenable2")) {
#ifdef REMOTE_ACCESS_CTL
                MIB_CE_ACC_T Entry;
                if (!mib_chain_get(MIB_ACC_TBL, 0, (void *)&Entry))
                {
                        printf("[%s %d]mib_chain_get failed\n", __func__, __LINE__);
                        return -1;
                }
                else
                {
                        if(Entry.telnet==3)
                        {
                                boaWrite(wp, "checked");
                        }
                }
#endif
                return 0;
        }
	else if (!strcmp(name, "enable_ping_wan")) {
#ifdef REMOTE_ACCESS_CTL
		MIB_CE_ACC_T Entry;
		if (!mib_chain_get(MIB_ACC_TBL, 0, (void *)&Entry))
		{
			printf("[%s %d]mib_chain_get failed\n", __func__, __LINE__);
			return -1;
		}
		else if(Entry.icmp & 0x1)
			boaWrite(wp, "checked");
#endif
		return 0;
	}

#ifdef TCP_UDP_CONN_LIMIT
	else if ( !strcmp(name, "connLimit-cap0") ) {
   		if ( !mib_get( MIB_CONNLIMIT_ENABLE, (void *)&vChar) )
			return -1;
		if (0 == vChar)
			boaWrite(wp, "checked");
		return 0;
	}
	else if ( !strcmp(name, "connLimit-cap1") ) {
   		if ( !mib_get( MIB_CONNLIMIT_ENABLE, (void *)&vChar) )
			return -1;
		if (1 == vChar)
			boaWrite(wp, "checked");
		return 0;
	}

#endif

	else if ( !strcmp(name, "acl-cap0") ) {
   		if ( !mib_get( MIB_ACL_CAPABILITY, (void *)&vChar) )
			return -1;
		if (0 == vChar)
			boaWrite(wp, "checked");
		return 0;
	}
	else if ( !strcmp(name, "acl-cap1") ) {
   		if ( !mib_get( MIB_ACL_CAPABILITY, (void *)&vChar) )
			return -1;
		if (1 == vChar)
			boaWrite(wp, "checked");
		return 0;
	}
#ifdef CONFIG_USER_SNMPD_SNMPD_V2CTRAP
	else if ( !strcmp(name, "snmpd-on") ) {
   		if ( !mib_get( MIB_SNMPD_ENABLE, (void *)&vChar) )
			return -1;
		if (0 == vChar)
			boaWrite(wp, "checked");
		return 0;
	}
	else if ( !strcmp(name, "snmpd-off") ) {
   		if ( !mib_get( MIB_SNMPD_ENABLE, (void *)&vChar) )
			return -1;
		if (1 == vChar)
			boaWrite(wp, "checked");
		return 0;
	}
#endif
#ifdef URL_BLOCKING_SUPPORT
	else if ( !strcmp(name, "url-cap0") ) {
   		if ( !mib_get( MIB_URL_CAPABILITY, (void *)&vChar) )
			return -1;
		if (0 == vChar)
			boaWrite(wp, "checked");
		return 0;
	}
	else if ( !strcmp(name, "url-cap1") ) {
   		if ( !mib_get( MIB_URL_CAPABILITY, (void *)&vChar) )
			return -1;
		if (1 == vChar)
			boaWrite(wp, "checked");
		return 0;
	}
#endif
//alex_huang
#ifdef URL_ALLOWING_SUPPORT
       else if( !strcmp(name ,"url-cap2") ) {
	   	if( !mib_get (MIB_URL_CAPABILITY,(void*)&vChar) )
			return -1;
		if(2 == vChar)
			{
			    boaWrite(wp, "checked");
			}
		return 0;

       	}
#endif


#ifdef DOMAIN_BLOCKING_SUPPORT
	else if ( !strcmp(name, "domainblk-cap0") ) {
   		if ( !mib_get( MIB_DOMAINBLK_CAPABILITY, (void *)&vChar) )
			return -1;
		if (0 == vChar)
			boaWrite(wp, "checked");
		return 0;
	}
	else if ( !strcmp(name, "domainblk-cap1") ) {
   		if ( !mib_get( MIB_DOMAINBLK_CAPABILITY, (void *)&vChar) )
			return -1;
		if (1 == vChar)
			boaWrite(wp, "checked");
		return 0;
	}
#endif
	else if ( !strcmp(name, "dns0") ) {
		if ( !mib_get( MIB_ADSL_WAN_DNS_MODE, (void *)&vChar) )
			return -1;
		if (0 == vChar)
			boaWrite(wp, "checked");
		return 0;
	}
	else if ( !strcmp(name, "dns1") ) {
		if ( !mib_get( MIB_ADSL_WAN_DNS_MODE, (void *)&vChar) )
			return -1;
		if (1 == vChar)
			boaWrite(wp, "checked");
		return 0;
	}
/*	else if ( !strcmp(name, "portFwEn")) {
		if ( !mib_get( MIB_PORT_FW_ENABLE, (void *)&vChar) )
			return -1;
		if (1 == vChar)
			boaWrite(wp, "checked");
		return 0;
	}*/
	else if ( !strcmp(name, "portFw-cap0") ) {
   		if ( !mib_get( MIB_PORT_FW_ENABLE, (void *)&vChar) )
			return -1;
		if (0 == vChar)
			boaWrite(wp, "checked");
		return 0;
	}
	else if ( !strcmp(name, "portFw-cap1") ) {
   		if ( !mib_get( MIB_PORT_FW_ENABLE, (void *)&vChar) )
			return -1;
		if (1 == vChar)
			boaWrite(wp, "checked");
		return 0;
	}
	if ( !strcmp(name, "portFwNum")) {
		vUInt = mib_chain_total(MIB_PORT_FW_TBL);
		if (0 == vUInt)
			boaWrite(wp, "disableDelButton();");
		return 0;
	}
#ifdef NATIP_FORWARDING
	else if ( !strcmp(name, "ipFwEn")) {
		if ( !mib_get( MIB_IP_FW_ENABLE, (void *)&vChar) )
			return -1;
		if (1 == vChar)
			boaWrite(wp, "checked");
		return 0;
	}
	if ( !strcmp(name, "ipFwNum")) {
		vUInt = mib_chain_total(MIB_IP_FW_TBL);
		if (0 == vUInt)
			boaWrite(wp, "disableDelButton();");
		return 0;
	}
#endif
#ifdef CONFIG_IPV6
#ifdef CONFIG_USER_RADVD
	else if ( !strcmp(name, "radvd_SendAdvert0")) {
		if ( !mib_get( MIB_V6_SENDADVERT, (void *)&vChar) )
			return -1;
		if (0 == vChar)
			boaWrite(wp, "checked");
		return 0;
	}
	else if ( !strcmp(name, "radvd_SendAdvert1")) {
		if ( !mib_get( MIB_V6_SENDADVERT, (void *)&vChar) )
			return -1;
		if (1 == vChar)
			boaWrite(wp, "checked");
		return 0;
	}
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	else if ( !strcmp(name, "radvd_enable")) {
		if ( !mib_get( MIB_V6_RADVD_ENABLE, (void *)&vChar) )
			return -1;
		if(vChar==1)
			boaWrite(wp, "'1' checked");
		else
			boaWrite(wp, "'0'");
		return 0;
	}
#endif
	else if ( !strcmp(name, "radvd_enable0")) {
		if ( !mib_get( MIB_V6_RADVD_ENABLE, (void *)&vChar) )
			return -1;
		if (0 == vChar)
			boaWrite(wp, "checked");
		return 0;
	}
	else if ( !strcmp(name, "radvd_enable1")) {
		if ( !mib_get( MIB_V6_RADVD_ENABLE, (void *)&vChar) )
			return -1;
		if (1 == vChar)
			boaWrite(wp, "checked");
		return 0;
	}
	else if ( !strcmp(name, "radvd_ManagedFlag0")) {
		if ( !mib_get( MIB_V6_MANAGEDFLAG, (void *)&vChar) )
			return -1;
		if (0 == vChar)
			boaWrite(wp, "checked");
		return 0;
	}
	else if ( !strcmp(name, "radvd_ManagedFlag1")) {
		if ( !mib_get( MIB_V6_MANAGEDFLAG, (void *)&vChar) )
			return -1;
		if (1 == vChar)
			boaWrite(wp, "checked");
		return 0;
	}
	else if ( !strcmp(name, "radvd_OtherConfigFlag0")) {
		if ( !mib_get( MIB_V6_OTHERCONFIGFLAG, (void *)&vChar) )
			return -1;
		if (0 == vChar)
			boaWrite(wp, "checked");
		return 0;
	}
	else if ( !strcmp(name, "radvd_OtherConfigFlag1")) {
		if ( !mib_get( MIB_V6_OTHERCONFIGFLAG, (void *)&vChar) )
			return -1;
		if (1 == vChar)
			boaWrite(wp, "checked");
		return 0;
	}
	else if ( !strcmp(name, "radvd_OnLink0")) {
		if ( !mib_get( MIB_V6_ONLINK, (void *)&vChar) )
			return -1;
		if (0 == vChar)
			boaWrite(wp, "checked");
		return 0;
	}
	else if ( !strcmp(name, "radvd_OnLink1")) {
		if ( !mib_get( MIB_V6_ONLINK, (void *)&vChar) )
			return -1;
		if (1 == vChar)
			boaWrite(wp, "checked");
		return 0;
	}
	else if ( !strcmp(name, "radvd_Autonomous0")) {
		if ( !mib_get( MIB_V6_AUTONOMOUS, (void *)&vChar) )
			return -1;
		if (0 == vChar)
			boaWrite(wp, "checked");
		return 0;
	}
	else if ( !strcmp(name, "radvd_Autonomous1")) {
		if ( !mib_get( MIB_V6_AUTONOMOUS, (void *)&vChar) )
			return -1;
		if (1 == vChar)
			boaWrite(wp, "checked");
		return 0;
	}
#endif // of CONFIG_USER_RADVD
#endif
	else if ( !strcmp(name, "ipf_out_act0")) {
		if ( !mib_get( MIB_IPF_OUT_ACTION, (void *)&vChar) )
			return -1;
		if (0 == vChar)
			boaWrite(wp, "checked");
		return 0;
	}
	else if ( !strcmp(name, "ipf_out_act1")) {
		if ( !mib_get( MIB_IPF_OUT_ACTION, (void *)&vChar) )
			return -1;
		if (1 == vChar)
			boaWrite(wp, "checked");
		return 0;
	}
	else if ( !strcmp(name, "ipf_in_act0")) {
		if ( !mib_get( MIB_IPF_IN_ACTION, (void *)&vChar) )
			return -1;
		if (0 == vChar)
			boaWrite(wp, "checked");
		return 0;
	}
	else if ( !strcmp(name, "ipf_in_act1")) {
		if ( !mib_get( MIB_IPF_IN_ACTION, (void *)&vChar) )
			return -1;
		if (1 == vChar)
			boaWrite(wp, "checked");
		return 0;
	}
	else if ( !strcmp(name, "macf_out_act0")) {
		if ( !mib_get( MIB_MACF_OUT_ACTION, (void *)&vChar) )
			return -1;
		if (0 == vChar)
			boaWrite(wp, "checked");
		return 0;
	}
	else if ( !strcmp(name, "macf_out_act1")) {
		if ( !mib_get( MIB_MACF_OUT_ACTION, (void *)&vChar) )
			return -1;
		if (1 == vChar)
			boaWrite(wp, "checked");
		return 0;
	}
	else if ( !strcmp(name, "macf_in_act0")) {
		if ( !mib_get( MIB_MACF_IN_ACTION, (void *)&vChar) )
			return -1;
		if (0 == vChar)
			boaWrite(wp, "checked");
		return 0;
	}
	else if ( !strcmp(name, "macf_in_act1")) {
		if ( !mib_get( MIB_MACF_IN_ACTION, (void *)&vChar) )
			return -1;
		if (1 == vChar)
			boaWrite(wp, "checked");
		return 0;
	}
/*	else if ( !strcmp(name, "dmzEn")) {
		if ( !mib_get( MIB_DMZ_ENABLE, (void *)&vChar) )
			return -1;
		if (vChar)
			boaWrite(wp, "checked");
		return 0;
	}*/
	else if ( !strcmp(name, "dmz-cap0") ) {
   		if ( !mib_get( MIB_DMZ_ENABLE, (void *)&vChar) )
			return -1;
		if (0 == vChar)
			boaWrite(wp, "checked");
		return 0;
	}
	else if ( !strcmp(name, "dmz-cap1") ) {
   		if ( !mib_get( MIB_DMZ_ENABLE, (void *)&vChar) )
			return -1;
		if (1 == vChar)
			boaWrite(wp, "checked");
		return 0;
	}
	else if ( !strcmp(name, "ipFilterNum")) {
		vUInt = mib_chain_total(MIB_IP_PORT_FILTER_TBL);
		if (0 == vUInt)
			boaWrite(wp, "disableDelButton();");
		return 0;
	}
#ifdef TCP_UDP_CONN_LIMIT
	else if ( !strcmp(name, "connLimitNum")) {
		vUInt = mib_chain_total(MIB_TCP_UDP_CONN_LIMIT_TBL);
		if (0 == vUInt)
			boaWrite(wp, "disableDelButton();");
		return 0;
	}
#endif
#ifdef MULTI_ADDRESS_MAPPING
	else if ( !strcmp(name, "AddresMapNum")) {
		vUInt = mib_chain_total(MULTI_ADDRESS_MAPPING_LIMIT_TBL);
		if (0 == vUInt)
			boaWrite(wp, "disableDelButton();");
		return 0;
	}
#endif  // end of MULTI_ADDRESS_MAPPING
#ifdef URL_BLOCKING_SUPPORT
	else if ( !strcmp(name, "keywdNum")) {
		vUInt = mib_chain_total(MIB_KEYWD_FILTER_TBL);
		if (0 == vUInt)
			boaWrite(wp, "disableDelKeywdButton();");
		return 0;
	}
	else if ( !strcmp(name, "FQDNNum")) {
		vUInt = mib_chain_total(MIB_URL_FQDN_TBL);
		if (0 == vUInt)
			boaWrite(wp, "disableDelFQDNButton();");
		return 0;
	}
#endif
#ifdef DOMAIN_BLOCKING_SUPPORT
	else if ( !strcmp(name, "domainNum")) {
		vUInt = mib_chain_total(MIB_DOMAIN_BLOCKING_TBL);
		if (0 == vUInt)
			boaWrite(wp, "disableDelButton();");
		return 0;
	}
#endif
	else if ( !strcmp(name, "ripNum")) {
		vUInt = mib_chain_total(MIB_RIP_TBL);
		if (0 == vUInt)
			boaWrite(wp, "disableDelButton();");
		return 0;
	}
	else if ( !strcmp(name, "aclNum")) {
		vUInt = mib_chain_total(MIB_ACL_IP_TBL);
		if (0 == vUInt)
			boaWrite(wp, "disableDelButton();");
		return 0;
	}
	else if ( !strcmp(name, "macFilterNum")) {
		vUInt = mib_chain_total(MIB_MAC_FILTER_TBL);
		if (0 == vUInt)
			boaWrite(wp, "disableDelButton();");
		return 0;
	}
#ifdef PARENTAL_CTRL
	else if( !strcmp(name, "parentCtrlNum")) {
			return 1;  //temp
		}
/*
	else if ( !strcmp(name, "parentCtrlNum")) {
		vUInt = mib_chain_total(MIB_MAC_FILTER_TBL);
		if (0 == vUInt)
			boaWrite(wp, "disableDelButton();");
		return 0;
	}
*/
#endif
	else if ( !strcmp(name, "vcMax")) {
		vUInt = mib_chain_total(MIB_ATM_VC_TBL);
		if (vUInt >= 16) {
			boaWrite(wp, "alert(\"Max number of ATM VC Settings is 16!\");");
			boaWrite(wp, "return false;");
		}
		return 0;
	}
	else if ( !strcmp(name, "vcCount")) {
		vUInt = mib_chain_total(MIB_ATM_VC_TBL);
		if (vUInt == 0) {
			boaWrite(wp, "disableButton(document.adsl.delvc);");
			// Commented by Mason Yu. The "refresh" button is be disabled on wanadsl.asp
			//boaWrite(wp, "disableButton(document.adsl.refresh);");
		}
		return 0;
	}
	else if ( !strcmp(name, "pppoeStatus") ) {
		if (0) {
			boaWrite(wp, "\n<script> setPPPConnected(); </script>\n");
		}
		return 0;
	}
#ifdef CONFIG_USER_PPPOE_PROXY
  else if(!strcmp(name,"pppoeProxy"))
  	{
  	boaWrite(wp,"<tr><td><font size=2><b>PPPoE Proxy:</b></td>"
         "<td><b><input type=\"radio\" value=1 name=\"pppEnable\" >Enable&nbsp;&nbsp;"
	"<input type=\"radio\" value=0 name=\"pppEnable\" checked>Disable</b></td></tr>");
  	}
  else if(!strcmp(name,"pppSettingsDisable"))
  	{
  	  boaWrite(wp,"{document.adsl.pppEnable[0].disabled=true;\n"
	  	"document.adsl.pppEnable[1].disabled=true;}");
  	}
    else if(!strcmp(name,"pppSettingsEnable"))
  	{
  	  boaWrite(wp,"{document.adsl.pppEnable[0].disabled=false;\n"
	  	"document.adsl.pppEnable[1].disabled=false;}else{document.adsl.pppEnable[0].disabled=true;\n"
	  	"document.adsl.pppEnable[1].disabled=true;}"
	  	"document.adsl.pppEnable[0].checked=false;"
	  	"document.adsl.pppEnable[1].checked=true;");
  	}

 #endif
  #ifdef CONFIG_USER_PPPOE_PROXY
     else if(!strcmp(name,"PostVC"))
     	{
     	   boaWrite(wp,"function postVC(vpi,vci,encap,napt,mode,username,passwd,pppType,idletime,pppoeProxyEnable,ipunnum,ipmode,ipaddr,remoteip,netmask,droute,status,enable)");
     	}
     else if(!strcmp(name,"pppoeProxyEnable"))
     	{
	boaWrite(wp,"  if(mode==\"PPPoE\""
		"{if(pppoeProxyEnable)"
		"{ document.adsl.pppEnable[0].checked=true;\n"
                  "document.adsl.pppEnable[1].checked=false;}\n"
		"else {document.adsl.pppEnable[0].checked=false;"
		 " document.adsl.pppEnable[1].checked=true;}  "
		" document.adsl.pppEnable[0].disabled=false;"
			  " document.adsl.pppEnable[1].disabled=false;");
	boaWrite(wp," }else"
		"{"
		"	  document.adsl.pppEnable[0].checked=false;"
		"	   document.adsl.pppEnable[1].checked=true;"
		"	   document.adsl.pppEnable[0].disabled=true;"
		"	   document.adsl.pppEnable[1].disabled=true;}"
		);
     	}
  #else
   else if(!strcmp(name,"PostVC"))
     	{
     	   boaWrite(wp,"function postVC(vpi,vci,encap,napt,mode,username,passwd,pppType,idletime,ipunnum,ipmode,ipaddr,remoteip,netmask,droute,status,enable)");
     	}
     else if(!strcmp(name,"pppoeProxyEnable"))
     	{

     	}
  #endif

	else if ( !strcmp(name, "adsl-line-mode") ) {
		if ( !mib_get( MIB_ADSL_MODE, (void *)&vChar) )
			return -1;
		if (1 == vChar) {
			boaWrite(wp,"<option selected value=\"1\">T1.413</option>");
			boaWrite(wp,"<option value=\"2\">G.dmt</option>");
			boaWrite(wp,"<option value=\"3\">MultiMode</option>");
		} else if (2 == vChar) {
			boaWrite(wp,"<option value=\"1\">T1.413</option>");
			boaWrite(wp,"<option selected value=\"2\">G.dmt</option>");
			boaWrite(wp,"<option value=\"3\">MultiMode</option>");
		} else if (3 == vChar) {
			boaWrite(wp,"<option value=\"1\">T1.413</option>");
			boaWrite(wp,"<option value=\"2\">G.dmt</option>");
			boaWrite(wp,"<option selected value=\"3\">MultiMode</option>");
		}
		return 0;
	}
#ifdef WLAN_SUPPORT
	else if ( !strcmp(name, "wl_txRate")) {
		struct _misc_data_ misc_data;
		MIB_CE_MBSSIB_T Entry;
		if(!wlan_getEntry(&Entry, 0))
			return -1;
		boaWrite(wp, "band=%d\n", Entry.wlanBand);
		boaWrite(wp, "txrate=%u\n",Entry.fixedTxRate);
		boaWrite(wp, "auto=%d\n",Entry.rateAdaptiveEnabled);
		mib_get( MIB_WLAN_CHANNEL_WIDTH, (void *)&vChar);
		boaWrite(wp, "chanwid=%d\n",vChar);

		//cathy, get rf number
		memset(&misc_data, 0, sizeof(struct _misc_data_));
		getMiscData(getWlanIfName(), &misc_data);
		boaWrite(wp, "rf_num=%u\n", misc_data.mimo_tr_used);

#ifdef CONFIG_BOA_WEB_E8B_CH	//cathy
#ifdef CONFIG_USB_RTL8187SU_SOFTAP
		vUShort = Entry.mlcstRate;
		boaWrite(wp, "mulrate=%d\n",vUShort);
#else
		boaWrite(wp, "mulrate=0\n");
#endif
#endif
	}

	else if ( !strcmp(name, "wl_chno")) {
		mib_get( MIB_HW_REG_DOMAIN, (void *)&vChar);
		boaWrite(wp, "regDomain=%d\n",vChar);
		mib_get( MIB_WLAN_CHAN_NUM ,(void *)&vChar);
		boaWrite(wp, "defaultChan=%d\n",vChar);
	}
#endif

	//for web log
	else if ( !strcmp(name, "log-cap0") ) {
		if ( !mib_get( MIB_SYSLOG, (void *)&vChar) )
			return -1;
		if (0 == vChar)
			boaWrite(wp, "checked");
		return 0;
	}
	else if ( !strcmp(name, "log-cap1") ) {
		if ( !mib_get( MIB_SYSLOG, (void *)&vChar) )
			return -1;
		if (0 != vChar)
			boaWrite(wp, "checked");
		return 0;
	}
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	else if ( !strcmp(name, "log-cap") ) {
		if ( !mib_get( MIB_SYSLOG, (void *)&vChar) )
			return -1;
		boaWrite(wp, "syslog = %d;\n",vChar);
		return 0;
	}
#ifdef CONFIG_USER_SAMBA
	else if (!strcmp(name, "samba-cap0")) {
		if (!mib_get(MIB_SAMBA_ENABLE, &vChar))
			return -1;
		if (0 == vChar)
			boaWrite(wp, "checked");
		return 0;
	} else if (!strcmp(name, "samba-cap1")) {
		if (!mib_get(MIB_SAMBA_ENABLE, &vChar))
			return -1;
		if (1 == vChar)
			boaWrite(wp, "checked");
		return 0;
	}
	else if (!strcmp(name, "nmbd-cap")) {
#ifndef CONFIG_USER_NMBD
		boaWrite(wp, "style=\"display: none\"");
#endif
		return 0;
	}
#endif
#endif
	if (!strcmp(name, "syslog-log") || !strcmp(name, "syslog-display")) {
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		char *SYSLOGLEVEL[] = {"紧急", "警报", "重要", "错误", "警告", "注意", "通知", "调试"};
#else
		char *SYSLOGLEVEL[] = {"Emergency", "Alert", "Critical", "Error", "Warning", "Notice", "Infomational", "Debugging"};
#endif
		int i;
		if (!strcmp(name, "syslog-log")) {
			if (!mib_get(MIB_SYSLOG_LOG_LEVEL, (void *)&vChar))
				return -1;
		}
		else if (!strcmp(name, "syslog-display")) {
			if (!mib_get(MIB_SYSLOG_DISPLAY_LEVEL, (void *)&vChar))
				return -1;
		}
		for (i=0; i<8; i++) {
			if (i == vChar)
				boaWrite(wp,"<option selected value=\"%d\">%s</option>", i, SYSLOGLEVEL[i]);
			else
				boaWrite(wp,"<option value=\"%d\">%s</option>", i, SYSLOGLEVEL[i]);
		}
		return 0;
	}
#ifdef CONFIG_USER_RTK_SYSLOG_REMOTE
	if (!strcmp(name, "syslog-mode")) {
		char *SYSLOGMODE[] = { "", "Local", "Remote", "Both" };
		int i;
		if (!mib_get(MIB_SYSLOG_MODE, &vChar))
			return -1;
		for (i = 1; i <= 3; i++) {
			if (i == vChar)
				boaWrite(wp, "<option selected value=\"%d\">%s</option>", i, SYSLOGMODE[i]);
			else
				boaWrite(wp, "<option value=\"%d\">%s</option>", i, SYSLOGMODE[i]);
		}
	}
#endif

	//for adsl debug
	else if ( !strcmp(name, "adsldbg-cap0") ) {
   		if ( !mib_get( MIB_ADSL_DEBUG, (void *)&vChar) )
			return -1;
		if (0 == vChar)
			boaWrite(wp, "checked");
		return 0;
	}
	else if ( !strcmp(name, "adsldbg-cap1") ) {
   		if ( !mib_get( MIB_ADSL_DEBUG, (void *)&vChar) )
			return -1;
		if (1 == vChar)
			boaWrite(wp, "checked");
		return 0;
	}
#ifdef _CWMP_MIB_
	else if ( !strcmp(name, "tr069-interval") ) {
   		if ( !mib_get( CWMP_INFORM_ENABLE, (void *)&vChar) )
			return -1;
		if (0 == vChar)
			boaWrite(wp, "disabled");
		return 0;
	}
	else if ( !strcmp(name, "tr069-inform-0") ) {
   		if ( !mib_get( CWMP_INFORM_ENABLE, (void *)&vChar) )
			return -1;
		if (0 == vChar)
			boaWrite(wp, "checked");
		return 0;
	}
	else if ( !strcmp(name, "tr069-inform-1") ) {
   		if ( !mib_get( CWMP_INFORM_ENABLE, (void *)&vChar) )
			return -1;
		if (1 == vChar)
			boaWrite(wp, "checked");
		return 0;
	}
	else if ( !strcmp(name, "tr069-inform-2") ) {
   		if ( !mib_get( CWMP_INFORM_ENABLE, (void *)&vChar) )
			return -1;
		if (2 == vChar)
			boaWrite(wp, "checked");
		return 0;
	}
	else if ( !strcmp(name, "tr069-dbgmsg-0") ) {
   		if ( !mib_get( CWMP_FLAG, (void *)&vChar) )
			return -1;
		if ( (vChar & CWMP_FLAG_DEBUG_MSG)==0 )
			boaWrite(wp, "checked");
		return 0;
	}
	else if ( !strcmp(name, "tr069-dbgmsg-1") ) {
   		if ( !mib_get( CWMP_FLAG, (void *)&vChar) )
			return -1;
		if ( (vChar & CWMP_FLAG_DEBUG_MSG)!=0 )
			boaWrite(wp, "checked");
		return 0;
	}
	else if ( !strcmp(name, "tr069-certauth-0") ) {
		if ( !mib_get( CWMP_FLAG, (void *)&vChar) )
			return -1;
		if ( (vChar & CWMP_FLAG_CERT_AUTH)==0 )
			boaWrite(wp, "checked");
		return 0;
	}
	else if ( !strcmp(name, "tr069-certauth-1") ) {
   		if ( !mib_get( CWMP_FLAG, (void *)&vChar) )
			return -1;
		if ( (vChar & CWMP_FLAG_CERT_AUTH)!=0 )
			boaWrite(wp, "checked");
		return 0;
	}
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	else if ( !strcmp(name, "tr069-passauth-1") ) {
		if ( !mib_get( CWMP_GUI_PASSWORD_ENABLE, (void *)&vChar) )
			return -1;
		if (1 == vChar)
			boaWrite(wp, "checked");
		return 0;
	}
	else if ( !strcmp(name, "tr069-passauth-0") ) {
		if ( !mib_get( CWMP_GUI_PASSWORD_ENABLE, (void *)&vChar) )
			return -1;
		if (0 == vChar)
			boaWrite(wp, "checked");
		return 0;
	}
#endif
	else if ( !strcmp(name, "tr069-sendgetrpc-0") ) {
   		if ( !mib_get( CWMP_FLAG, (void *)&vChar) )
			return -1;
		if ( (vChar & CWMP_FLAG_SENDGETRPC)==0 )
			boaWrite(wp, "checked");
		return 0;
	}
	else if ( !strcmp(name, "tr069-sendgetrpc-1") ) {
   		if ( !mib_get( CWMP_FLAG, (void *)&vChar) )
			return -1;
		if ( (vChar & CWMP_FLAG_SENDGETRPC)!=0 )
			boaWrite(wp, "checked");
		return 0;
	}
	else if ( !strcmp(name, "tr069-skipmreboot-0") ) {
   		if ( !mib_get( CWMP_FLAG, (void *)&vChar) )
			return -1;
		if ( (vChar & CWMP_FLAG_SKIPMREBOOT)==0 )
			boaWrite(wp, "checked");
		return 0;
	}
	else if ( !strcmp(name, "tr069-skipmreboot-1") ) {
   		if ( !mib_get( CWMP_FLAG, (void *)&vChar) )
			return -1;
		if ( (vChar & CWMP_FLAG_SKIPMREBOOT)!=0 )
			boaWrite(wp, "checked");
		return 0;
	}
	else if ( !strcmp(name, "tr069-delay-0") ) {
   		if ( !mib_get( CWMP_FLAG, (void *)&vChar) )
			return -1;
		if ( (vChar & CWMP_FLAG_DELAY)==0 )
			boaWrite(wp, "checked");
		return 0;
	}
	else if ( !strcmp(name, "tr069-delay-1") ) {
   		if ( !mib_get( CWMP_FLAG, (void *)&vChar) )
			return -1;
		if ( (vChar & CWMP_FLAG_DELAY)!=0 )
			boaWrite(wp, "checked");
		return 0;
	}
	else if ( !strcmp(name, "tr069-autoexec-0") ) {
   		if ( !mib_get( CWMP_FLAG, (void *)&vChar) )
			return -1;
		if ( (vChar & CWMP_FLAG_AUTORUN)==0 )
			boaWrite(wp, "checked");
		return 0;
	}
	else if ( !strcmp(name, "check-certca") ) {
		if(access("/var/config/cacert.pem", F_OK ) == -1)
			boaWrite(wp, "disabled");
		return 0;
	}

//czhu add for middleware 2015-5-4
#ifdef CONFIG_MIDDLEWARE
	else if ( !strcmp(name, "midware-disable") ) {
		if ( !mib_get(CWMP_TR069_ENABLE, (void *)&vChar) )
			return -1;
		if ( vChar == 1 )
			boaWrite(wp, "checked");
		return 0;
	}
	else if ( !strcmp(name, "midware-enable1") ) {
		if ( !mib_get(CWMP_TR069_ENABLE, (void *)&vChar) )
			return -1;
		if ( vChar == 0 )
			boaWrite(wp, "checked");
		return 0;
	}
	else if ( !strcmp(name, "midware-enable2") ) {
		if ( !mib_get(CWMP_TR069_ENABLE, (void *)&vChar) )
			return -1;
		if ( vChar == 2 )
			boaWrite(wp, "checked");
		return 0;
	}
#endif //end of CONFIG_MIDDLEWARE
// Mason Yu. t123
#if 0
	else if( !strcmp(name, "tr069-connReqEnable")){ // star: for e8b feature
		if ( !mib_get( CWMP_CONREQ_ENABLE, (void *)&vChar) )
			return -1;
		if (vChar == 1 )
			boaWrite(wp, "checked");
		return 0;
	}
#endif
#endif
#ifdef WLAN_SUPPORT
#ifdef CONFIG_WIFI_SIMPLE_CONFIG // WPS
	else if (!strcmp(name, "wpsVer")) {
	#ifdef WPS20
		boaWrite(wp, "wps20 = 1;\n");
	#else
		boaWrite(wp, "wps20 = 0;\n");
	#endif
		return 0;
	}
	else if (!strcmp(name, "wscConfig-0") ) {
		MIB_CE_MBSSIB_T Entry;
		if(!wlan_getEntry(&Entry, 0))
			return -1;
		if (!Entry.wsc_configured)
			boaWrite(wp, "checked");
		return 0;
	}
	else if (!strcmp(name, "wscConfig-1")) {
		MIB_CE_MBSSIB_T Entry;
		if(!wlan_getEntry(&Entry, 0))
			return -1;
		if (Entry.wsc_configured)
			boaWrite(wp, "checked");
		return 0;
	}
	else if (!strcmp(name, "wscConfig-A")) {
		MIB_CE_MBSSIB_T Entry;
		if(!wlan_getEntry(&Entry, 0))
			return -1;
		if (Entry.wsc_configured)
			boaWrite(wp, "isConfig=1;");
		else
			boaWrite(wp, "isConfig=0;");
		return 0;
	}
#if defined(CONFIG_USB_RTL8192SU_SOFTAP) || defined(CONFIG_RTL8192CD)  || defined(CONFIG_RTL8192CD_MODULE)		// add by yq_zhou 1.20
	else if (!strcmp(name,"wscConfig")){
		MIB_CE_MBSSIB_T Entry;
		if(!wlan_getEntry(&Entry, 0))
			return -1;
		if (Entry.wsc_configured)
			boaWrite(wp, "enableButton(form.elements['resetUnConfiguredBtn']);");
		else
			boaWrite(wp, "disableButton(form.elements['resetUnConfiguredBtn']);");
		return 0;
	}
	else if (!strcmp(name,"protectionDisabled-0")){
		if (!mib_get(MIB_WLAN_PROTECTION_DISABLED,(void *)&vChar))
			return -1;
		if (!vChar)
			boaWrite(wp,"checked");
	}
	else if (!strcmp(name,"protectionDisabled-1")){
		if (!mib_get(MIB_WLAN_PROTECTION_DISABLED,(void *)&vChar))
			return -1;
		if (vChar)
			boaWrite(wp,"checked");
	}
	else if (!strcmp(name,"aggregation-0")){
		if (!mib_get(MIB_WLAN_AGGREGATION,(void *)&vChar))
			return -1;
		if (vChar)
			boaWrite(wp,"checked");
	}
	else if (!strcmp(name,"aggregation-1")){
		if (!mib_get(MIB_WLAN_AGGREGATION,(void *)&vChar))
			return -1;
		if (vChar)
			boaWrite(wp,"checked");
	}
	else if (!strcmp(name,"shortGIEnabled-0")){
		if (!mib_get(MIB_WLAN_SHORTGI_ENABLED,(void *)&vChar))
			return -1;
		if (vChar)
			boaWrite(wp,"checked");
	}
	else if (!strcmp(name,"shortGIEnabled-1")){
		if (!mib_get(MIB_WLAN_SHORTGI_ENABLED,(void *)&vChar))
			return -1;
		if (vChar)
			boaWrite(wp,"checked");
	}
#endif
	else if (!strcmp(name, "wlanMode"))  {
		MIB_CE_MBSSIB_T Entry;
		if(!wlan_getEntry(&Entry, 0))
			return -1;
		if (Entry.wlanMode == CLIENT_MODE)
			boaWrite(wp, "isClient=1;");
		else
			boaWrite(wp, "isClient=0;");
		return 0;

	}
	else if (!strcmp(name, "wscDisable"))  {

		MIB_CE_MBSSIB_T Entry;
		if(!wlan_getEntry(&Entry, 0))
			return -1;
		if (Entry.wsc_disabled)
			boaWrite(wp, "checked");
		return 0;
	}
	else if (!strcmp(name, "wps_auth"))  {

		MIB_CE_MBSSIB_T Entry;
		if(!wlan_getEntry(&Entry, 0))
			return -1;
		switch(Entry.wsc_auth) {
			case WSC_AUTH_OPEN: boaWrite(wp, "Open"); break;
			case WSC_AUTH_WPAPSK: boaWrite(wp, "WPA PSK"); break;
			case WSC_AUTH_SHARED: boaWrite(wp, "WEP Shared"); break;
			case WSC_AUTH_WPA: boaWrite(wp, "WPA Enterprise"); break;

			case WSC_AUTH_WPA2: boaWrite(wp, "WPA2 Enterprise"); break;
			case WSC_AUTH_WPA2PSK: boaWrite(wp, "WPA2 PSK"); break;
			case WSC_AUTH_WPA2PSKMIXED: boaWrite(wp, "WPA2-Mixed PSK"); break;
			default:
				break;
		}
		return 0;
	}
	else if (!strcmp(name, "wps_enc"))  {
		MIB_CE_MBSSIB_T Entry;
		if(!wlan_getEntry(&Entry, 0))
			return -1;
		vChar = Entry.wsc_enc;
		switch(vChar) {
			case 0:
			case WSC_ENCRYPT_NONE: boaWrite(wp, "None"); break;
			case WSC_ENCRYPT_WEP: boaWrite(wp, "WEP"); break;
			case WSC_ENCRYPT_TKIP: boaWrite(wp, "TKIP"); break;
			case WSC_ENCRYPT_AES: boaWrite(wp, "AES"); break;
			case WSC_ENCRYPT_TKIPAES: boaWrite(wp, "TKIP+AES"); break;
			default:
				break;
		}
		return 0;
	}
#endif
#endif

#ifndef CONFIG_GUI_WEB
#else
	else if(!strcmp(name,"naptEnable"))
	{
		boaWrite(wp,"\tif ((document.adsl.adslConnectionMode.selectedIndex == 1) ||\n"
			"\t\t(document.adsl.adslConnectionMode.selectedIndex == 2) || (document.adsl.adslConnectionMode.selectedIndex == 3))\n"
			"\t\tdocument.adsl.naptEnabled.checked = true;\n"
			"\telse\n"
			"\t\tdocument.adsl.naptEnabled.checked = false;\n");
		return 0;
	}
#endif
	else if(!strcmp(name,"qos_mode"))
	{
#if defined(CONFIG_USER_IP_QOS) && defined(_PRMT_X_CT_COM_QOS_)
		char tmpBuf[40];
   		if ( mib_get(CTQOS_MODE, (void *)&tmpBuf) ){
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
			boaWrite(wp, "%s", tmpBuf);
#else
			boaWrite(wp,"\t%s\n",tmpBuf);
#endif
		}
#endif
		return 0;
	}

#ifdef CONFIG_IPV6
	else if(!strcmp(name,"IPv6vcCheck1"))
	{
		if (boaArgs(argc, argv, "%*s %s", &name) < 2) {
			boaError(wp, 400, "Insufficient args\n");
			return -1;
		}

		boaWrite(wp,"if(%s.IpProtocolType.value == 3 || %s.IpProtocolType.value == 1){\n", name, name);
		return 0;
	}
	else if(!strcmp(name,"IPv6vcCheck2"))
	{
		boaWrite(wp,"}\n");
		return 0;
	}
	else if(!strcmp(name,"IPv6vcCheck3"))
	{
		if (boaArgs(argc, argv, "%*s %s", &name) < 2) {
			boaError(wp, 400, "Insufficient args\n");
			return -1;
		}
	boaWrite(wp,"if(%s.IpProtocolType.value == 3 || %s.IpProtocolType.value == 2)\n"
			"\t{\n"
			"\t	if(%s.staticIpv6.checked) {\n"
			"\t		if(%s.itfenable.checked == false ){\n"
			"\t			if(%s.Ipv6Addr.value == \"\" ){\n"
			"\t				alert(\"Please input ipv6 address or open DHCPv6 client!\");\n"
			"\t				%s.Ipv6Addr.focus();\n"
			"\t				return false;\n"
			"\t			}\n"
			"\t		}\n", name, name, name, name, name, name);
	boaWrite(wp,"\t		if(%s.Ipv6Addr.value != \"\"{\n"
			"\t			if (! isGlobalIpv6Address( %s.Ipv6Addr.value) ){\n"
			"\t				alert(\"Invalid ipv6 address!\");\n"
			"\t				%s.Ipv6Addr.focus();\n"
			"\t				return false;\n"
			"\t			}\n", name, name, name);
	boaWrite(wp,"\t			var prefixlen= getDigit(%s.Ipv6PrefixLen.value, 1);\n"
			"\t			if (prefixlen > 128 || prefixlen <= 0) {\n"
			"\t				alert(\"Invalid ipv6 prefix length!\");\n"
			"\t				%s.Ipv6PrefixLen.focus();\n"
			"\t				return false;\n"
			"\t			}\n"
			"\t		}\n", name, name);
	boaWrite(wp,"\t		if(%s.Ipv6Gateway.value != \"\" ){\n"
			"\t			if (! isUnicastIpv6Address( %s.Ipv6Gateway.value) ){\n"
			"\t				alert(\"Invalid ipv6 gateway address!\");\n"
			"\t				%s.Ipv6Gateway.focus();\n"
			"\t				return false;\n"
			"\t			}\n"
			"\t		}\n", name, name, name);
	boaWrite(wp,"\t	}else{\n"
			"\t		%s.Ipv6Addr.value = \"\";\n"
			"\t		%s.Ipv6PrefixLen.value = \"\";\n"
			"\t		%s.Ipv6Gateway.value = \"\";\n"
			"\t	}\n"
			"\t}\n", name, name, name);

		return 0;
	}
	else if(!strcmp(name,"IPv6vcCheck9"))
	{
		boaWrite(wp,"<tr nowrap><td width=\"150px\"><input type=\"radio\" id=\"IPMode\" name=\"ipmode\" value=\"3\" onClick=\"on_ctrlupdate(this)\">Static</td><td>经ISP处配置一个静态地址</td></tr>\n");
		return 0;
	}
	else if(!strcmp(name,"IPv6ChannelMode1"))
	{
		boaWrite(wp,"ipv6SettingsEnable();\n"
			       "	document.getElementById('tbprotocol').style.display=\"block\";\n");
		return 0;
	}
	else if(!strcmp(name,"IPv6ChannelMode2"))
	{
		boaWrite(wp,"ipv6SettingsDisable();\n"
			       "		document.getElementById('tbprotocol').style.display=\"none\";\n");
		return 0;
	}
#endif
	else if(!strcmp(name,"IPv6Show"))
	{
#ifdef CONFIG_IPV6
		boaWrite(wp,"1");
#else
		boaWrite(wp,"0");
#endif
		return 0;
	}
	else if(!strcmp(name,"DSLiteShow"))
	{
#ifdef DUAL_STACK_LITE
		boaWrite(wp,"1");
#else
		boaWrite(wp,"0");
#endif
		return 0;
	}
	//add by ramen for zte acl default ip
	else if(!strcmp(name,"remoteClientIp"))
	{
		boaWrite(wp,"%s",wp->remote_ip_addr);
		return 0;
	}
#ifdef DEFAULT_GATEWAY_V2
	// Jenny, for PPPoE auto route
	else if ( !strcmp(name, "autort") ) {
#ifdef AUTO_PPPOE_ROUTE
		boaWrite(wp, "<option value=239>Auto</option>" );
#endif
		return 0;
	}
#endif
	else if ( !strcmp(name, "pppExist") ) {
		MIB_CE_ATM_VC_T Entry;
		unsigned int totalEntry;
		int i, isPPP=0;
		totalEntry = mib_chain_total(MIB_ATM_VC_TBL); /* get chain record size */
		for (i=0; i<totalEntry; i++)
			if (mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&Entry))
				if (Entry.enable == 1 && (Entry.cmode == CHANNEL_MODE_PPPOE || Entry.cmode == CHANNEL_MODE_PPPOA)) {
					isPPP = 1;
					break;
				}
		if (isPPP == 0)
			boaWrite(wp,"document.pppauth.username.disabled = true;\n"
							"document.pppauth.password.disabled = true;\n"
							"document.all.Submit.disabled = true;\n");
		return 0;
	}
#ifdef CONFIG_IP_NF_ALG_ONOFF
	else if(!strcmp(name,"GetAlgType"))
		{
		GetAlgTypes(wp);
		return 0;
		}
	else if(!strcmp(name,"AlgTypeStatus"))
		{
		CreatejsAlgTypeStatus( wp);
	 	return 0;
		}
#endif
#ifdef DNS_BIND_PVC_SUPPORT
	else if(!strcmp(name,"DnsBindPvc"))
		{
		unsigned char dnsBindPvcEnable=0;
		mib_get(MIB_DNS_BIND_PVC_ENABLE,(void*)&dnsBindPvcEnable);
		//printf("dns bind pvc = %d\n",dnsBindPvcEnable);
		boaWrite(wp,"<font size=2>开启DNS绑定:<input type=\"checkbox\" name=\"enableDnsBind\" value=\"on\" %s onClick=\"DnsBindPvcClicked();\"></font>",
			(dnsBindPvcEnable)?"checked":"");
		return 0;
		}
#endif

#ifdef CONFIG_IPV6
#ifdef DNSV6_BIND_PVC_SUPPORT
	else if(!strcmp(name,"Dnsv6BindPvc"))
		{
		unsigned char dnsv6BindPvcEnable=0;
		mib_get(MIB_DNSV6_BIND_PVC_ENABLE,(void*)&dnsv6BindPvcEnable);
		//printf("dnsv6 bind pvc = %d\n",dnsv6BindPvcEnable);
		boaWrite(wp,"<font size=2>开启DNSv6绑定:<input type=\"checkbox\" name=\"enableDnsv6Bind\" value=\"on\" %s onClick=\"Dnsv6BindPvcClicked();\"></font>",
			(dnsv6BindPvcEnable)?"checked":"");
		return 0;
		}
#endif
#endif

	else  if(!strcmp(name,"WanPvcRouter"))
		{
#ifdef DNS_BIND_PVC_SUPPORT
				MIB_CE_ATM_VC_T Entry;
				int entryNum;
				int mibcnt;
				char interfacename[MAX_NAME_LEN];
				entryNum = mib_chain_total(MIB_ATM_VC_TBL);
				unsigned char forSelect=0;
		            for(mibcnt=0;mibcnt<entryNum;mibcnt++)
		            {
		            if (!mib_chain_get(MIB_ATM_VC_TBL, mibcnt, (void *)&Entry))
						{
		  					boaError(wp, 400, "Get chain record error!\n");
							return -1;
						}
			      if(Entry.cmode!=CHANNEL_MODE_BRIDGE)// CHANNEL_MODE_BRIDGE CHANNEL_MODE_IPOE CHANNEL_MODE_PPPOE CHANNEL_MODE_PPPOA	CHANNEL_MODE_RT1483	CHANNEL_MODE_RT1577
			      	{
			      	boaWrite(wp,"0");
				return 0;
		                  }

		            }
		           boaWrite(wp,"1");
#else
	 		 boaWrite(wp,"0");
#endif
			return 0;

		}

#ifdef DNS_BIND_PVC_SUPPORT
	else if(!strcmp(name,"dnsBindPvcInit"))
			{
				unsigned int dnspvc1,dnspvc2,dnspvc3;
				if(!mib_get(MIB_DNS_BIND_PVC1,(void*)&dnspvc1))
					{
					boaError(wp, 400, "Get MIB_DNS_BIND_PVC1 record error!\n");
							return -1;
					}
				if(!mib_get(MIB_DNS_BIND_PVC2,(void*)&dnspvc2))
					{
					boaError(wp, 400, "Get MIB_DNS_BIND_PVC2 record error!\n");
							return -1;
					}
				if(!mib_get(MIB_DNS_BIND_PVC3,(void*)&dnspvc3))
					{
					boaError(wp, 400, "Get MIB_DNS_BIND_PVC3 record error!\n");
							return -1;
					}

				    boaWrite(wp,"DnsBindSelectdInit('wanlist1',%d);\n",dnspvc1);
				    boaWrite(wp,"DnsBindSelectdInit('wanlist2',%d);\n",dnspvc2);
				    boaWrite(wp,"DnsBindSelectdInit('wanlist3',%d);\n",dnspvc3);
				boaWrite(wp,"DnsBindPvcClicked();");
				return 0;
			}
#endif

#ifdef CONFIG_IPV6
#ifdef DNSV6_BIND_PVC_SUPPORT
	else if(!strcmp(name,"dnsv6BindPvcInit"))
			{
				unsigned int dnspvc1,dnspvc2,dnspvc3;
				if(!mib_get(MIB_DNSV6_BIND_PVC1,(void*)&dnspvc1))
					{
					boaError(wp, 400, "Get MIB_DNSV6_BIND_PVC1 record error!\n");
							return -1;
					}
				if(!mib_get(MIB_DNSV6_BIND_PVC2,(void*)&dnspvc2))
					{
					boaError(wp, 400, "Get MIB_DNSV6_BIND_PVC2 record error!\n");
							return -1;
					}
				if(!mib_get(MIB_DNSV6_BIND_PVC3,(void*)&dnspvc3))
					{
					boaError(wp, 400, "Get MIB_DNSV6_BIND_PVC3 record error!\n");
							return -1;
					}

				    boaWrite(wp,"DnsBindSelectdInit('v6wanlist1',%d);\n",dnspvc1);
				    boaWrite(wp,"DnsBindSelectdInit('v6wanlist2',%d);\n",dnspvc2);
				    boaWrite(wp,"DnsBindSelectdInit('v6wanlist3',%d);\n",dnspvc3);
				boaWrite(wp,"Dnsv6BindPvcClicked();");
				return 0;
			}
#endif
#endif

	else if(!strcmp(name,"QosSpeedLimitWeb"))
		{
#ifdef QOS_SPEED_LIMIT_SUPPORT
	         boaWrite(wp,"<td>\n"
		"<input type=\"checkbox\" name= qosspeedenable onClick=\"qosSpeedClick(this)\"; > <font size=2>限速</font>\n"
		"</td>\n "
	         "<td>\n"
	         "<div id='speedlimit' style=\"display:none\">\n"
		"<table>\n"
		"<tr>\n<td>\n"
		"<input type=text name=speedLimitRank  size=6 maxlength=5 >\n"
		"</td>\n<td><font size=2>\nkBps< bytes/sec * 1024></td>\n</tr>\n</table>\n"
		"</div>\n"
		"</td>\n");
#endif
		return 0;
		}
#if defined(CONFIG_USER_ZEBRA_OSPFD_OSPFD) || defined(CONFIG_USER_ROUTED_ROUTED)
	else if (!strcmp(name, "ospf")) {
#ifdef CONFIG_USER_ROUTED_ROUTED
		boaWrite(wp, "	<option value=\"0\">RIP</option>\n");
#endif
#ifdef CONFIG_USER_ZEBRA_OSPFD_OSPFD
		boaWrite(wp, "	<option value=\"1\">OSPF</option>");
#endif
	}
#endif

	else if(!strcmp(name, "dgw")){
#ifdef DEFAULT_GATEWAY_V1
		boaWrite(wp, "\tif (droute == 1)\n");
		boaWrite(wp, "\t\tdocument.adsl.droute[1].checked = true;\n");
		boaWrite(wp, "\telse\n");
		boaWrite(wp, "\t\tdocument.adsl.droute[0].checked = true;\n");
#else
		GetDefaultGateway(eid, wp, argc, argv);
		boaWrite(wp, "\tautoDGWclicked();\n");
#endif
	}
/* add by yq_zhou 09.2.02 add sagem logo for 11n*/
	else if(!strncmp(name, "title", 5))	{
#ifndef CONFIG_11N_SAGEM_WEB
//		boaWrite(wp, "<img src=\"graphics/topbar.gif\" width=900 height=90 border=0>");
		boaWrite(wp,	"<img src=\"graphics/topbar.gif\" width=900 height=60 border=0>");
#else
//		boaWrite(wp,"<img src=\"graphics/sagemlogo1.gif\" width=1350 height=90 border=0>");
		boaWrite(wp,	"<img src=\"graphics/sagemlogo1.gif\" width=1350 height=60 border=0>");
#endif
	}
	else if(!strncmp(name, "logobelow", 9))	{
#ifdef CONFIG_11N_SAGEM_WEB
//		boaWrite(wp,"<img src=\"graphics/sagemlogo2.gif\" width=180 height=90 border=0>");
		boaWrite(wp,"<img src=\"graphics/sagemlogo2.gif\" width=180 height=60 border=0>");
#endif
	}
#ifdef CONFIG_ETHWAN
	else if(!strncmp(name, "ethwanSelection", 15)){
		MIB_CE_ATM_VC_T Entry;

		memset((void *)&Entry, 0, sizeof(Entry));
		if (getWanEntrybyMedia(&Entry, MEDIA_ETH)>=0)
			boaWrite(wp, "document.ethwan.adslConnectionMode.value = \"%d\";\n", Entry.cmode);
	}
#endif
	else if ( !strcmp(name, "usb-res0") ) {
#ifdef _PRMT_USBRESTORE
   		if (!mib_get(MIB_USBRESTORE, (void *)&vChar))
			return -1;
		if (0 == vChar)
			boaWrite(wp, "checked");
#else
		boaWrite(wp, "checked");
#endif
		return 0;
	}
	else if ( !strcmp(name, "usb-res1") ) {
#ifdef _PRMT_USBRESTORE
   		if ( !mib_get( MIB_USBRESTORE, (void *)&vChar) )
			return -1;
		if (1 == vChar)
			boaWrite(wp, "checked");
#endif
		return 0;
	}
	else if ( !strcmp(name, "sntp_if_type_voip") ) {
#ifdef VOIP_SUPPORT
		boaWrite(wp, "<option value = \"1\">VOICE</option>\n");
#endif
		return 0;
	}
#ifdef CONFIG_IPV6
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	else if ( !strcmp(name, "lanIpv6ramanage") ) {
		if ( !mib_get( MIB_V6_MANAGEDFLAG, (void *)&vChar) )
			return -1;
		if(vChar==1)
			boaWrite(wp, "'1' checked");
		else
			boaWrite(wp, "'0'");
		return 0;
	}
	else if ( !strcmp(name, "lanIpv6raother") ) {
		if ( !mib_get( MIB_V6_OTHERCONFIGFLAG, (void *)&vChar) )
			return -1;
		if(vChar==1)
			boaWrite(wp, "'1' checked");
		else
			boaWrite(wp, "'0'");
		return 0;
	}
	if ( !strcmp(name, "enableDhcpServer") ) {
		if ( !mib_get( MIB_DHCP_MODE, (void *)&vChar) )
			return -1;
		if(vChar==0){
			boaWrite(wp, "'0'");
		}
		else{
			boaWrite(wp, "'1' checked");
		}
		return 0;
	}
	if ( !strcmp(name, "enableDhcpv6Server") ) {
		if ( !mib_get( MIB_DHCPV6_MODE, (void *)&vChar) )
			return -1;
#ifdef SUPPORT_DHCPV6_RELAY
		if(vChar == DHCP_LAN_SERVER_AUTO)
			vChar = DHCP_LAN_SERVER;
		boaWrite(wp, "%d", vChar);
#else
		if(vChar==0){
			boaWrite(wp, "'0'");
		}
		else{
			boaWrite(wp, "'1' checked");
		}
#endif
		return 0;
	}
#endif //CONFIG_CMCC
	else if ( !strcmp(name, "lanipv6addr") ) {
		char tmpBuf[40];
   		if ( !mib_get( MIB_IPV6_LAN_IP_ADDR, (void *)&tmpBuf) )
			return -1;
		boaWrite(wp, "%s", tmpBuf);
		return 0;
	}
	else if ( !strcmp(name, "lanipv6prefix") ) {
		char tmpBuf[40], len;
   		if ( !mib_get( MIB_IPV6_LAN_PREFIX, (void *)&tmpBuf) )
		{
			return -1;
		}
   		if ( !mib_get( MIB_IPV6_LAN_PREFIX_LEN, (void *)&len) )
		{
			return -1;
		}
		if(tmpBuf[0] && (len!=0))
			boaWrite(wp, "%s/%d", tmpBuf,len);
		return 0;
	}
#endif
#if defined(CONFIG_USER_IP_QOS) && defined(_PRMT_X_CT_COM_QOS_)
	else if ( !strcmp(name, "enable_force_weight0")) {
		if ( !mib_get( MIB_QOS_ENABLE_FORCE_WEIGHT, (void *)&vChar) )
			return -1;
		if (0 == vChar)
			boaWrite(wp, "checked");
		return 0;
	}
	else if ( !strcmp(name, "enable_force_weight1")) {
		if ( !mib_get( MIB_QOS_ENABLE_FORCE_WEIGHT, (void *)&vChar) )
			return -1;
		if (1 == vChar)
			boaWrite(wp, "checked");
		return 0;
	}
	else if ( !strcmp(name, "enable_bandwidth0")) {
		if ( !mib_get( MIB_TOTAL_BANDWIDTH_LIMIT_EN, (void *)&vChar) )
			return -1;
		if (0 == vChar)
			boaWrite(wp, "checked");
		return 0;
	}
	else if ( !strcmp(name, "enable_bandwidth1")) {
		if ( !mib_get( MIB_TOTAL_BANDWIDTH_LIMIT_EN, (void *)&vChar) )
			return -1;
		if (1 == vChar)
			boaWrite(wp, "checked");
		return 0;
	}
	else if ( !strcmp(name, "enable_dscp_remark0")) {
		if ( !mib_get( MIB_QOS_ENABLE_DSCP_MARK , (void *)&vChar) )
			return -1;
		if (0 == vChar)
			boaWrite(wp, "checked");
		return 0;
	}
	else if ( !strcmp(name, "enable_dscp_remark1")) {
		if ( !mib_get( MIB_QOS_ENABLE_DSCP_MARK , (void *)&vChar) )
			return -1;
		if (1 == vChar)
			boaWrite(wp, "checked");
		return 0;
	}
	else if ( !strcmp(name, "enable_1p_remark0")) {
		if ( !mib_get( MIB_QOS_ENABLE_1P , (void *)&vChar) )
			return -1;
		if (0 == vChar)
			boaWrite(wp, "checked");
		return 0;
	}
	else if ( !strcmp(name, "enable_1p_remark1")) {
		if ( !mib_get( MIB_QOS_ENABLE_1P , (void *)&vChar) )
			return -1;
		if (1 == vChar)
			boaWrite(wp, "checked");
		return 0;
	}
	else if ( !strcmp(name, "enable_1p_remark2")) {
		if ( !mib_get( MIB_QOS_ENABLE_1P , (void *)&vChar) )
			return -1;
		if (2 == vChar)
			boaWrite(wp, "checked");
		return 0;
	}
#endif
	else if ( !strcmp(name, "priv") ) {
		struct user_info *pUser_info;

		pUser_info = search_login_list(wp);
		if (!pUser_info)
			return -1;

		if (!pUser_info->priv)
			boaWrite(wp, "style=\"display: none\"");

		return 0;
	}
	else if(!strcmp(name, "vlan_mapping_interface")){
		int i,first=1;
		boaWrite(wp, "[");
		for(i=0; i<SW_LAN_PORT_NUM;i++)
		{
#if defined(CONFIG_RTK_L34_ENABLE) && defined(CONFIG_USER_LAN_PORT_AS_ETH_WAN)
			int phyPortId;
			int ethPhyPortId = -1;
			mib_get(MIB_ETH_WAN_PORT_PHY_INDEX, &ethPhyPortId);

			phyPortId = RG_get_lan_phyPortId(i);
			if (phyPortId != -1 && phyPortId == ethPhyPortId)
				continue;
#endif
			if(first)
			{
				boaWrite(wp, "\"LAN%d\"",i+1);
				first=0;
			}
			else
				boaWrite(wp, ",\"LAN%d\"",i+1);
		}
#ifdef WLAN_SUPPORT
		int orig_wlan_idx = wlan_idx;
		int j;
#ifdef YUEME_3_0_SPEC_SSID_ALIAS
		unsigned char phyband = PHYBAND_2G;
#endif
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		unsigned char ssid2_enable = 0;

		mib_get(MIB_WEB_WLAN_SSID2_ENABLE, &ssid2_enable);
#endif			
		for(j=0; j<NUM_WLAN_INTERFACE; j++)
		{
			wlan_idx = j;
#ifdef YUEME_3_0_SPEC_SSID_ALIAS
#ifdef WLAN_DUALBAND_CONCURRENT
			mib_get(MIB_WLAN_PHY_BAND_SELECT, &phyband);
#endif
			boaWrite(wp, ",\"%s-%d\"", phyband==PHYBAND_2G? "2.4G":"5G", 1);
#else
			boaWrite(wp, ",\"SSID%d\"", j*(WLAN_MBSSID_NUM+1) + 1);
#endif
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
			if (ssid2_enable==0)
			{
#ifdef WLAN_DUALBAND_CONCURRENT
				boaWrite(wp, ",\"SSID5\"");
#endif
				break;
			}
#endif
#ifdef WLAN_MBSSID
			MIB_CE_MBSSIB_T entry;
			for (i = 0; i < WLAN_MBSSID_NUM; i++)
			{
				mib_chain_get(MIB_MBSSIB_TBL, i + 1, &entry);
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
				boaWrite(wp, ",\"SSID%d\"", j*(WLAN_MBSSID_NUM+1) + (i + 2));
#else
				if (entry.wlanDisabled) {
					boaWrite(wp, ",\"SSID_DISABLE\"");
				}
				else {
#ifdef YUEME_3_0_SPEC_SSID_ALIAS
					boaWrite(wp, ",\"%s-%d\"", phyband==PHYBAND_2G? "2.4G":"5G", (i + 2));
#else
					boaWrite(wp, ",\"SSID%d\"", j*(WLAN_MBSSID_NUM+1) + (i + 2));
#endif
				}
#endif
			}
#endif
			for (i = 0; i < (MAX_WLAN_VAP - WLAN_MBSSID_NUM); i++) {
				boaWrite(wp, ",\"SSID_DISABLE\"");
			}
		}
		boaWrite(wp,"]");
		wlan_idx = orig_wlan_idx;
#else
		boaWrite(wp,"]");
#endif

		return 0;
	}
#if 0
	else if (!strcmp(name, "ctmdw_off"))
	{
		unsigned char vChar;

		mib_get(CWMP_TR069_ENABLE,(void *)&vChar);
		if (1 == vChar)//off
			boaWrite(wp,"checked");
	}
	else if (!strcmp(name, "ctmdw_on"))
	{
		unsigned char vChar;

		mib_get(CWMP_TR069_ENABLE,(void *)&vChar);
		if (1 != vChar)//on
			boaWrite(wp,"checked");
	}
#endif//end of CONFIG_MIDDLEWARE
	else if(!strcmp(name, "qos_interface")){
		int i;
#if defined(CONFIG_RTK_L34_ENABLE) && defined(CONFIG_USER_LAN_PORT_AS_ETH_WAN)
		int phyPortId;
		int ethPhyPortId = -1;
		mib_get(MIB_ETH_WAN_PORT_PHY_INDEX, &ethPhyPortId);
#endif
		for(i=1; i<=SW_LAN_PORT_NUM;i++)
		{
#if defined(CONFIG_RTK_L34_ENABLE) && defined(CONFIG_USER_LAN_PORT_AS_ETH_WAN)
			phyPortId = RG_get_lan_phyPortId(i - 1);
			if (phyPortId != -1 && phyPortId == ethPhyPortId)
				continue;
#endif
			boaWrite(wp, ", \"LAN%d\"",i);
		}
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
#ifdef WLAN_SUPPORT
		for(i=1; i<=WLAN_SSID_NUM; i++)
				boaWrite(wp, ", \"SSID%d\"", i);

#ifdef WLAN_DUALBAND_CONCURRENT
		for(i=1; i<=WLAN_SSID_NUM; i++)
			boaWrite(wp, ", \"SSID%d\"", i+WLAN_SSID_NUM);
#endif
#endif
#endif
		return 0;
	}
	else if(!strcmp(name, "wan_interface_name"))
	{
#if defined(CONFIG_GPON_FEATURE) || defined(CONFIG_EPON_FEATURE)
		boaWrite(wp, "PON");
#endif
		return 0;
	}
#ifdef SUPPORT_WEB_PUSHUP
        else if (!strcmp(name, "embedURL"))
        {
                extern char firmware_upgrade_pushup_base_url[1024];

                if (firmware_upgrade_pushup_base_url[0])
                {
                        boaWrite(wp, "http://");
                        boaWrite(wp, firmware_upgrade_pushup_base_url);
                }
                return 0;
        }
#endif
#ifdef _PRMT_X_CT_COM_USERINFO_
	else if(!strcmp(name, "dev_reg_btn"))
	{
		unsigned char reg_type;
		unsigned int reg_status;
		mib_get(PROVINCE_DEV_REG_TYPE, &reg_type);
		mib_get(CWMP_USERINFO_STATUS, &reg_status);
		if(reg_type == DEV_REG_TYPE_JSU && (reg_status==0 || reg_status==5))
			boaWrite(wp, "disabled");
	}
#endif
	else if(!strcmp(name, "ah_login"))
	{
		unsigned char reg_type;
		mib_get(PROVINCE_DEV_REG_TYPE, &reg_type);
		if(reg_type == DEV_REG_TYPE_AH)
		{
			//boaWrite(wp, "style=\"display:block\"");
		}
		else
		{
			boaWrite(wp, "style=\"display:none\"");
		}
	}
	else if(!strcmp(name, "login"))
	{
		unsigned char reg_type;
		mib_get(PROVINCE_DEV_REG_TYPE, &reg_type);
		if(reg_type == DEV_REG_TYPE_AH)
		{
			boaWrite(wp, "style=\"display: none\"");
		}
		else
		{
			//boaWrite(wp, "style=\"display: block\"");
		}
	}
#ifdef _PRMT_X_CT_COM_USERINFO_
	else if(!strcmp(name, "dev_reg_btn1"))
	{
		unsigned char reg_type;
		unsigned int reg_status;
		mib_get(PROVINCE_DEV_REG_TYPE, &reg_type);
		mib_get(CWMP_USERINFO_STATUS, &reg_status);
		if(reg_type == DEV_REG_TYPE_AH)
		{
			if(reg_status==0 || reg_status==5)
			{
				boaWrite(wp, "style=\"display:none\"");	
			}
			else
			{
				boaWrite(wp, "style=\"display:block\"");	
			}
		}
	}
	else if(!strcmp(name, "dev_reg_btn2"))
	{
		unsigned char reg_type;
		unsigned int reg_status;
		mib_get(PROVINCE_DEV_REG_TYPE, &reg_type);
		mib_get(CWMP_USERINFO_STATUS, &reg_status);
		if(reg_type == DEV_REG_TYPE_AH)
		{
			if(reg_status==0 || reg_status==5)
			{
				boaWrite(wp, "style=\"display:block\"");	
			}
			else
			{
				boaWrite(wp, "style=\"display:none\"");	
			}
		}
	}
#endif
#ifdef CONFIG_YUEME
	else if (!strcmp(name, "platform_dist_status"))
	{
		if (!mib_get( MIB_PLATFORM_DISTSTATUS_TBL, (void *)&vChar))
			return 0;
		if(vChar==1)
			boaWrite(wp, "未连接");
		else if(vChar==2)
			boaWrite(wp, "正在尝试连接分发平台");
		else if(vChar==3)
			boaWrite(wp, "与分发平台保持连接中");
		else if(vChar==4)
			boaWrite(wp, "与分发平台连接结束");
		else if(vChar==5)
			boaWrite(wp, "尝试连接分发平台失败");
		return 0;
	}
	else if (!strcmp(name, "platform_oper_status"))
	{
		if (!mib_get( MIB_PLATFORM_OPERSTATUS_TBL, (void *)&vChar))
			return 0;
		if(vChar==1)
			boaWrite(wp, "未连接");
		else if(vChar==2)
			boaWrite(wp, "正在尝试连接");
		else if(vChar==3)
			boaWrite(wp, "向运营平台注册中");
		else if(vChar==4)
			boaWrite(wp, "向运营平台心跳保活中");
		else if(vChar==5)
			boaWrite(wp, "与运营平台等待下一次心跳中");
		else if(vChar==6)
			boaWrite(wp, "尝试连接运营平台失败");
		return 0;
	}
	else if (!strcmp(name, "platform_plugin_status"))
	{
		if (!mib_get( MIB_PLATFORM_PLUGINSTATUS_TBL, (void *)&vChar))
			return 0;
		if(vChar==1)
			boaWrite(wp, "未连接");
		else if(vChar==2)
			boaWrite(wp, "正在尝试连接");
		else if(vChar==3)
			boaWrite(wp, "向插件中心注册中");
		else if(vChar==4)
			boaWrite(wp, "向插件中心心跳保活中");
		else if(vChar==5)
			boaWrite(wp, "与插件中心等待下一次心跳");
		else if(vChar==6)
			boaWrite(wp, "尝试连接插件中心失败");
		return 0;
	}
#endif
	else if(!strcmp(name, "loid_allow_empty"))
	{
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		boaWrite(wp, "1");
#else
		boaWrite(wp, "0");
#endif
		return 0;
	}
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	else if(!strcmp(name, "is_dosEnble"))
	{
		unsigned int dosEnble;	// 1- 使能;  0- 禁用
		if (!mib_get(MIB_DOS_ENABLED, (void *)&dosEnble)) 
			return 0;
		if( dosEnble & DOS_ENABLE)
			boaWrite(wp, "checked");
	}
#endif
#if defined(CONFIG_USER_DDNS) && (defined(CONFIG_CMCC) || defined(CONFIG_CU))
	else if(!strcmp(name, "ddns_ext_if"))
	{
		int num;
		num = mib_chain_total(MIB_DDNS_TBL);
		if(num==0){
			boaWrite(wp, "");
		}
		else{
			MIB_CE_DDNS_T Entry;
			if(mib_chain_get(MIB_DDNS_TBL,0,(void*)&Entry)!=1){
				return 0;
			}
			boaWrite(wp, "%u", getIfIndexByName(Entry.interface));
		}
		return 0;
	}
	else if(!strcmp(name, "ddns_hostname"))
	{
		int num;
		num = mib_chain_total(MIB_DDNS_TBL);
		if(num==0){
			boaWrite(wp, "");
		}
		else{
			MIB_CE_DDNS_T Entry;
			if(mib_chain_get(MIB_DDNS_TBL,0,(void*)&Entry)!=1){
				return 0;
			}
			boaWrite(wp, "%s", Entry.hostname);
		}
		return 0;
	}
	else if(!strcmp(name, "ddns_orayusername"))
	{
		int num;
		num = mib_chain_total(MIB_DDNS_TBL);
		if(num==0){
			boaWrite(wp, "");
		}
		else{
			MIB_CE_DDNS_T Entry;
			if(mib_chain_get(MIB_DDNS_TBL,0,(void*)&Entry)!=1){
				return 0;
			}
			boaWrite(wp, "%s", Entry.username);
		}
		return 0;
	}
	else if(!strcmp(name, "ddns_oraypassword"))
	{
		int num;
		num = mib_chain_total(MIB_DDNS_TBL);
		if(num==0){
			boaWrite(wp, "");
		}
		else{
			MIB_CE_DDNS_T Entry;
			if(mib_chain_get(MIB_DDNS_TBL,0,(void*)&Entry)!=1){
				return 0;
			}
			boaWrite(wp, "%s", Entry.password);
		}
		return 0;
	}
	else if(!strcmp(name, "ddns_enable"))
	{
		unsigned char	ddnsEnable = 1;
		mib_get(MIB_DDNS_ENABLE,(void*)&ddnsEnable);
		if(ddnsEnable == 1){
			boaWrite(wp, "value='%d' checked", ddnsEnable);
		}
		else{
			boaWrite(wp, "value='%d'", ddnsEnable);
		}
		return 0;
	}
	else if(!strcmp(name, "ddns_status"))
	{
		//printf("%s:%d\n", __FUNCTION__, __LINE__);
		boaWrite(wp, "%s", ddnsResultChineseString[get_ddns_result_code()]);
		return 0;
	}
	else if(!strcmp(name, "ddns_domain"))
	{
		//printf("%s:%d\n", __FUNCTION__, __LINE__);
		int status = get_ddns_result_code();
		if(status==DDNS_RESYLT_SUCCESS){
			int num;
			MIB_CE_DDNS_T Entry;
					
			num = mib_chain_total(MIB_DDNS_TBL);
			if(mib_chain_get(MIB_DDNS_TBL,0,(void*)&Entry)!=1){
				boaWrite(wp, "");
				return 0;
			}
			boaWrite(wp, "%s", Entry.hostname);
		}
		else{
			boaWrite(wp, "");
		}
		return 0;
	}
#endif
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	else if(!strcmp(name, "dmz_enable"))
	{
		unsigned char	dmzEnable = 1;
		mib_get(MIB_DMZ_ENABLE,(void*)&dmzEnable);
		if(dmzEnable == 1){
			boaWrite(wp, "value='%d' checked", dmzEnable);
		}
		else{
			boaWrite(wp, "value='%d'", dmzEnable);
		}
		return 0;
	}
	else if(!strcmp(name, "web_loid_page_enable"))
	{
		if(getWebLoidPageEnable()==1){
			boaWrite(wp, "<li class=\"tablinks active\" onclick=\"openTab(event, 'passwordTab')\" id=\"passwdbtn\">PASSWORD认证</li>");
			boaWrite(wp, "<li class=\"tablinks\" onclick=\"openTab(event, 'loidTab')\" id=\"loidbtn\">LOID认证</li>");
			boaWrite(wp, "<li class=\"tablinks back\" onClick=\"location.href='/admin/login.asp';\">返回登录页面</li>");
		}
		else{
			boaWrite(wp, "<li class=\"tablinks active\" onclick=\"openTab(event, 'passwordTab')\" id=\"passwdbtn\">PASSWORD认证</li>");
			boaWrite(wp, "<li style=\"display:none;\" class=\"tablinks\" onclick=\"openTab(event, 'loidTab')\" id=\"loidbtn\">LOID认证</li>");
			boaWrite(wp, "<li class=\"tablinks back\" onClick=\"location.href='/admin/login.asp';\">返回登录页面</li>");
		}
		return 0;
	}
#endif
#ifdef CONFIG_USER_MINIUPNPD
	else if(!strcmp(name, "upnp_enable"))
	{
		unsigned char	upnpEnable = 1;
		mib_get(MIB_UPNP_DAEMON,(void*)&upnpEnable);
		if(upnpEnable == 1){
			boaWrite(wp, "value='%d' checked", upnpEnable);
		}
		else{
			boaWrite(wp, "value='%d'", upnpEnable);
		}
		return 0;
	}
#endif
	else if(!strcmp(name, "dhcpv6s_prefix_length"))
	{
		unsigned char	len = 0;
   		if ( !mib_get( MIB_IPV6_LAN_PREFIX_LEN, (void *)&len) )
			return -1;

		if(len == 0){
			boaWrite(wp, "");
		}
		else{
			boaWrite(wp, "%u", len);
		}
	}
#ifdef CONFIG_SUPPORT_CAPTIVE_PORTAL
	else if(!strcmp(name, "urlredirect_enable"))
	{
		unsigned char	urlRedirectEnable = 1;
		mib_get(MIB_CAPTIVEPORTAL_ENABLE,(void*)&urlRedirectEnable);
		if(urlRedirectEnable == 1){
			boaWrite(wp, "value='%d' checked", urlRedirectEnable);
		}
		else{
			boaWrite(wp, "value='%d'", urlRedirectEnable);
		}
		return 0;
	}
#endif
	else
		return -1;

	return 0;
}

void write_wladvanced(int eid, request* wp, int argc, char **argv)        //add by yq_zhou 1.20
{
#if 0
	boaWrite(wp,
     "<tr><td width=\"30%%\"><font size=2><b>Preamble Type:</b></td>"\
     "<td width=\"70%%\"><font size=2>"\
     "<input type=\"radio\" value=\"long\" name=\"preamble\">Long Preamble&nbsp;&nbsp;"\
     "<input type=\"radio\" name=\"preamble\" value=\"short\">Short Preamble</td></tr>"\
     "<tr><td width=\"30%%\"><font size=2><b>Broadcast SSID:</b></td>"\
     "<td width=\"70%%\"><font size=2>"\
     "<input type=\"radio\" name=\"hiddenSSID\" value=\"no\">Enabled&nbsp;&nbsp;"\
     "<input type=\"radio\" name=\"hiddenSSID\" value=\"yes\">Disabled</td></tr>");
	boaWrite(wp,
     "<tr><td width=\"30%%\"><font size=2><b>Relay Blocking:</b></td>"\
     "<td width=\"70%%\"><font size=2>"\
     "<input type=\"radio\" name=block value=1>Enabled&nbsp;&nbsp;"\
     "<input type=\"radio\" name=block value=0>Disabled</td></tr>");
#ifdef CONFIG_USB_RTL8192SU_SOFTAP
	boaWrite(wp,
     "<tr><td width=\"30%%\"><font size=2><b>Protection:</b></td>"\
     "<td width=\"70%%\"><font size=2>"\
     "<input type=\"radio\" name=\"11g_protection\" value=\"yes\">Enabled&nbsp;&nbsp;"\
     "<input type=\"radio\" name=\"11g_protection\" value=\"no\">Disabled</td></tr>");
     	boaWrite(wp,
     "<tr><td width=\"30%%\"><font size=2><b>Aggregation:</b></td>"\
     "<td width=\"70%%\"><font size=2>"\
     "<input type=\"radio\" name=\"aggregation\" value=\"enable\">Enabled&nbsp;&nbsp;"\
     "<input type=\"radio\" name=\"aggregation\" value=\"disable\">Disabled</td></tr>");
       boaWrite(wp,
     "<tr id=\"ShortGi\" style=\"display:\">"\
     "<td width=\"30%%\"><font size=2><b>Short GI:</b></td>"\
     "<td width=\"70%%\"><font size=2>"\
     "<input type=\"radio\" name=\"shortGI0\" value=\"on\">Enabled&nbsp;&nbsp;"\
     "<input type=\"radio\" name=\"shortGI0\" value=\"off\">Disabled</td></tr>");
       boaWrite(wp,
     "<tr><td width=\"30%%\"><font size=2><b>RF Output Power:</b></td>"\
     "<td width=\"70%%\"><font size=2>"\
     "<input type=\"radio\" name=\"RFPower\" value=0>100%%&nbsp;&nbsp;"\
     "<input type=\"radio\" name=\"RFPower\" value=1>70%%&nbsp;&nbsp;"\
     "<input type=\"radio\" name=\"RFPower\" value=2>50%%&nbsp;&nbsp;"\
     "<input type=\"radio\" name=\"RFPower\" value=3>35%%&nbsp;&nbsp;"\
     "<input type=\"radio\" name=\"RFPower\" value=4>15%%</td></tr>");
#endif
#endif
	boaWrite(wp,
     "<tr><td width=\"30%%\"><font size=2><b>Preamble Type:</b></td>\n"
     "<td width=\"70%%\"><font size=2>\n"
     "<input type=\"radio\" value=\"long\" name=\"preamble\">Long Preamble&nbsp;&nbsp;\n"
     "<input type=\"radio\" name=\"preamble\" value=\"short\">Short Preamble</td></tr>\n");
	boaWrite(wp,
     "<tr><td width=\"30%%\"><font size=2><b>Broadcast SSID:</b></td>\n"
     "<td width=\"70%%\"><font size=2>\n"
     "<input type=\"radio\" name=\"hiddenSSID\" value=\"no\">Enabled&nbsp;&nbsp;\n"
     "<input type=\"radio\" name=\"hiddenSSID\" value=\"yes\">Disabled</td></tr>\n");
	boaWrite(wp,
     "<tr><td width=\"30%%\"><font size=2><b>Relay Blocking:</b></td>\n"
     "<td width=\"70%%\"><font size=2>\n"
     "<input type=\"radio\" name=block value=1>Enabled&nbsp;&nbsp;\n"
     "<input type=\"radio\" name=block value=0>Disabled</td></tr>\n");
	boaWrite(wp,
     "<tr><td width=\"30%%\"><font size=2><b>Protection:</b></td>\n"
     "<td width=\"70%%\"><font size=2>\n"
     "<input type=\"radio\" name=\"protection\" value=\"yes\">Enabled&nbsp;&nbsp;\n"
     "<input type=\"radio\" name=\"protection\" value=\"no\">Disabled</td></tr>\n");
   #if defined(CONFIG_USB_RTL8192SU_SOFTAP) || defined(CONFIG_RTL8192CD)  || defined(CONFIG_RTL8192CD_MODULE)
  	boaWrite(wp,
     "<tr><td width=\"30%%\"><font size=2><b>Aggregation:</b></td>\n"
     "<td width=\"70%%\"><font size=2>\n"
     "<input type=\"radio\" name=\"aggregation\" value=\"enable\">Enabled&nbsp;&nbsp;\n"
     "<input type=\"radio\" name=\"aggregation\" value=\"disable\">Disabled</td></tr>\n");
       boaWrite(wp,
     "<tr id=\"ShortGi\" style=\"display:\">\n"
     "<td width=\"30%%\"><font size=2><b>Short GI:</b></td>\n"
     "<td width=\"70%%\"><font size=2>\n"
     "<input type=\"radio\" name=\"shortGI0\" value=\"on\">Enabled&nbsp;&nbsp;\n"
     "<input type=\"radio\" name=\"shortGI0\" value=\"off\">Disabled</td></tr>\n");
#endif
}

/* add by yq_zhou 09.2.02 add sagem logo for 11n*/
#if 0
void write_title(int eid, request* wp, int argc, char **argv)
{
	printf("%s ...............1\n",__FUNCTION__);
#ifndef CONFIG_11N_SAGEM_WEB
	boaWrite(wp,	"<img src=\"graphics/topbar.gif\" width=900 height=60 border=0>");
#else
	boaWrite(wp,	"<img src=\"graphics/sagemlogo1.gif\" width=1350 height=60 border=0>");
#endif
}

void write_logo_below(int eid, request* wp, int argc, char **argv)
{
#ifdef CONFIG_11N_SAGEM_WEB
	printf("%s ...............1\n",__FUNCTION__);
	boaWrite(wp,
	"<img src=\"graphics/sagemlogo2.gif\" width=160 height=80 border=0>");
#endif
}
#endif

// Kaohj
#if 0
int getIndex(int eid, request* wp, int argc, char **argv)
{
	char *name;
	char  buffer[100];

	unsigned char vChar;
	unsigned short vUShort;
	unsigned int vUInt;

   	if (boaArgs(argc, argv, "%s", &name) < 1) {
   		boaError(wp, 400, "Insufficient args\n");
   		return -1;
   	}

	memset(buffer,0x00,100);
   	if ( !strcmp(name, "device-type") ) {
 		if ( !mib_get( MIB_DEVICE_TYPE, (void *)&vChar) )
			return -1;
#ifdef __uClinux__
		sprintf(buffer, "%u", vChar);
#else
		sprintf(buffer,"%u", 1);
#endif
		ejSetResult(eid, buffer);
		return 0;
	}
	if ( !strcmp(name, "dhcp-mode") ) {
 		if ( !mib_get( MIB_DHCP_MODE, (void *)&vChar) )
			return -1;
		sprintf(buffer, "%u", vChar);
		ejSetResult(eid, buffer);
		return 0;
	}
   	if ( !strcmp(name, "adsl-line-mode") ) {
 		if ( !mib_get( MIB_ADSL_MODE, (void *)&vChar) )
			return -1;
		sprintf(buffer, "%u", vChar);
		ejSetResult(eid, buffer);
		return 0;
	}
#ifdef CONFIG_USER_ROUTED_ROUTED
   	if ( !strcmp(name, "rip-on") ) {
 		if ( !mib_get( MIB_RIP_ENABLE, (void *)&vChar) )
			return -1;
		sprintf(buffer, "%u", vChar);
		ejSetResult(eid, buffer);
		return 0;
	}
   	if ( !strcmp(name, "rip-ver") ) {
 		if ( !mib_get( MIB_RIP_VERSION, (void *)&vChar) )
			return -1;
		sprintf(buffer, "%u", vChar);
		ejSetResult(eid, buffer);
		return 0;
	}
#endif
// Commented by Mason Yu for dhcpmode
#if 0
   	if ( !strcmp(name, "lan-dhcp") ) {
 		if ( !mib_get( MIB_ADSL_LAN_DHCP, (void *)&vChar) )
			return -1;
		sprintf(buffer, "%u", vChar);
		ejSetResult(eid, buffer);
		return 0;
	}
#endif
 	else if ( !strcmp(name, "br-stp") ) {
   		if ( !mib_get( MIB_BRCTL_STP, (void *)&vChar) )
			return -1;
		sprintf(buffer, "%u", vChar);
		ejSetResult(eid, buffer);
		return 0;
	}
#ifdef CONFIG_EXT_SWITCH
 	else if ( !strcmp(name, "mp-mode") ) {
   		if ( !mib_get( MIB_MPMODE, (void *)&vChar) )
			return -1;
		sprintf(buffer, "%u", vChar);
		ejSetResult(eid, buffer);
		return 0;
	}
#endif
#ifdef CONFIG_USER_IGMPPROXY
 	else if ( !strcmp(name, "igmp-proxy") ) {
   		if ( !mib_get( MIB_IGMP_PROXY, (void *)&vChar) )
			return -1;
		sprintf(buffer, "%u", vChar);
		ejSetResult(eid, buffer);
		return 0;
	}
#endif

	else if ( !strcmp(name, "acl-cap") ) {
   		if ( !mib_get( MIB_ACL_CAPABILITY, (void *)&vChar) )
			return -1;
		sprintf(buffer, "%u", vChar);
		ejSetResult(eid, buffer);
		return 0;
	}

   	else if ( !strcmp(name, "wan-dns") ) {
 		if ( !mib_get( MIB_ADSL_WAN_DNS_MODE, (void *)&vChar) )
			return -1;
		sprintf(buffer, "%u", vChar);
		ejSetResult(eid, buffer);
		return 0;
	}
	else if ( !strcmp(name, "portFwEnabled")) {
		if ( !mib_get( MIB_PORT_FW_ENABLE, (void *)&vChar) )
			return -1;
		sprintf(buffer, "%u", vChar);
		ejSetResult(eid, buffer);
		return 0;
	}
	else if ( !strcmp(name, "defaultFilterAction")) {
		if ( !mib_get( MIB_IPF_OUT_ACTION, (void *)&vChar) )
			return -1;
		sprintf(buffer, "%u", vChar);
		ejSetResult(eid, buffer);
		return 0;
	}
	else if ( !strcmp(name, "dmzEnabled")) {
		if ( !mib_get( MIB_DMZ_ENABLE, (void *)&vChar) )
			return -1;
		sprintf(buffer, "%u", vChar);
		ejSetResult(eid, buffer);
		return 0;
	}
	else if ( !strcmp(name, "vc-auto")) {
		if ( !mib_get( MIB_ATM_VC_AUTOSEARCH, (void *)&vChar) )
			return -1;
		sprintf(buffer, "%u", vChar);
		ejSetResult(eid, buffer);
		return 0;
	}
   	else if ( !strcmp(name, "ippt-itf")) {
		if( !mib_get( MIB_IPPT_ITF,  (void *)&vChar))
			return -1;
		sprintf(buffer, "%u", vChar);
		ejSetResult(eid, buffer);
		return 0;
	}
   	else if ( !strcmp(name, "ippt-lanacc")) {
		if( !mib_get( MIB_IPPT_LANACC,  (void *)&vChar))
			return -1;
		sprintf(buffer, "%u", vChar);
		ejSetResult(eid, buffer);
		return 0;
	}
	else if ( !strcmp(name, "rconf-status")) {
		sprintf(buffer, "%d", g_remoteConfig);
		ejSetResult(eid, buffer);
		return 0;
	}
	else if ( !strcmp(name, "rconf-port")) {
		sprintf(buffer, "%d", g_remoteAccessPort);
		ejSetResult(eid, buffer);
		return 0;
	}
   	else if ( !strcmp(name, "spc-enable")) {
		if( !mib_get( MIB_SPC_ENABLE,  (void *)&vChar))
			return -1;
		sprintf(buffer, "%u", vChar);
		ejSetResult(eid, buffer);
		return 0;
	}
   	else if ( !strcmp(name, "spc-iptype")) {
		if( !mib_get( MIB_SPC_IPTYPE,  (void *)&vChar))
			return -1;
		sprintf(buffer, "%u", vChar);
		ejSetResult(eid, buffer);
		return 0;
	}
	else if ( !strcmp(name, "ipPortFilterNum")) {
		vUInt = mib_chain_total(MIB_IP_PORT_FILTER_TBL);
		sprintf(buffer, "%u", vUInt);
		ejSetResult(eid, buffer);
		return 0;
	}
	else if ( !strcmp(name, "macFilterNum")) {
		vUInt = mib_chain_total(MIB_MAC_FILTER_TBL);
		sprintf(buffer, "%u", vUInt);
		ejSetResult(eid, buffer);
		return 0;
	}
	else if ( !strcmp(name, "portFwNum")) {
		vUInt = mib_chain_total(MIB_PORT_FW_TBL);
		sprintf(buffer, "%u", vUInt);
		ejSetResult(eid, buffer);
		return 0;
	}
	else if ( !strcmp(name, "atmVcNum")) {
		vUInt = mib_chain_total(MIB_ATM_VC_TBL);
		sprintf(buffer, "%u", vUInt);
		ejSetResult(eid, buffer);
		return 0;
	}
   	else if ( !strcmp(name, "wan-pppoeConnectStatus") ) {
////	check the pppoe status
		sprintf(buffer, "%d", 0);
		ejSetResult(eid, buffer);
		return 0;
	}
#ifdef WLAN_SUPPORT
	else if ( !strcmp(name, "channel") ) {
		if ( !mib_get( MIB_WLAN_CHAN_NUM, (void *)&vChar) )
			return -1;
		sprintf(buffer, "%d", vChar);
		ejSetResult(eid, buffer);
		return 0;
	}
	else if ( !strcmp(name, "regDomain") ) {
		if ( !mib_get( MIB_HW_REG_DOMAIN, (void *)&vChar) )
			return -1;
		sprintf(buffer, "%u", vChar);
		ejSetResult(eid, buffer);
		return 0;
	}
	else if ( !strcmp(name, "wep") ) {
		if ( !mib_get( MIB_WLAN_WEP, (void *)&vChar) )
			return -1;
		sprintf(buffer, "%u", vChar);
		ejSetResult(eid, buffer);
   	    	return 0;
	}
	else if ( !strcmp(name, "defaultKeyId") ) {
		if ( !mib_get( MIB_WLAN_WEP_DEFAULT_KEY, (void *)&vChar) )
			return -1;
		vChar++;
		sprintf(buffer, "%u", vChar) ;
		ejSetResult(eid, buffer);
		return 0;
	}
	else if ( !strcmp(name, "keyType") ) {
		if ( !mib_get( MIB_WLAN_WEP_KEY_TYPE, (void *)&vChar) )
			return -1;
		sprintf(buffer, "%u", vChar) ;
		ejSetResult(eid, buffer);
		return 0;
	}
  	else if ( !strcmp(name, "authType")) {
		if ( !mib_get( MIB_WLAN_AUTH_TYPE, (void *)&vChar) )
			return -1;
		sprintf(buffer, "%u", vChar) ;
		ejSetResult(eid, buffer);
		return 0;
	}
	else if ( !strcmp(name, "operRate")) {
		if ( !mib_get( MIB_WLAN_SUPPORTED_RATE, (void *)&vUShort) )
			return -1;
		sprintf(buffer, "%u", vUShort);
		ejSetResult(eid, buffer);
		return 0;
	}
	else if ( !strcmp(name, "basicRate")) {
		if ( !mib_get( MIB_WLAN_BASIC_RATE, (void *)&vUShort) )
			return -1;
		sprintf(buffer, "%u", vUShort);
		ejSetResult(eid, buffer);
		return 0;
	}
	else if ( !strcmp(name, "preamble")) {
		if ( !mib_get( MIB_WLAN_PREAMBLE_TYPE, (void *)&vChar) )
			return -1;
		sprintf(buffer, "%u", vChar);
		ejSetResult(eid, buffer);
		return 0;
	}
	else if ( !strcmp(name, "hiddenSSID")) {
		if ( !mib_get( MIB_WLAN_HIDDEN_SSID, (void *)&vChar) )
			return -1;
		sprintf(buffer, "%u", vChar);
		ejSetResult(eid, buffer);
		return 0;
	}
	else if ( !strcmp(name, "wmFilterNum")) {
		if ( !mib_get( MIB_WLAN_AC_NUM, (void *)&vChar) )
			return -1;
		sprintf(buffer, "%u", vChar);
		ejSetResult(eid, buffer);
		return 0;
	}
	else if ( !strcmp(name, "wlanDisabled")) {
		if ( !mib_get( MIB_WLAN_DISABLED, (void *)&vChar) )
			return -1;
		sprintf(buffer, "%u", vChar);
		ejSetResult(eid, buffer);
		return 0;
	}
	else if ( !strcmp(name, "wlanAcNum") ) {
		if ( !mib_get( MIB_WLAN_AC_NUM, (void *)&vChar) )
			return -1;
		sprintf(buffer, "%u", vChar);
		ejSetResult(eid, buffer);
		return 0;
	}
	else if ( !strcmp(name, "wlanAcEnabled")) {
		if ( !mib_get( MIB_WLAN_AC_ENABLED, (void *)&vChar) )
			return -1;
		sprintf(buffer, "%u", vChar);
		ejSetResult(eid, buffer);
		return 0;
	}
	else if ( !strcmp(name, "rateAdaptiveEnabled")) {
		if ( !mib_get( MIB_WLAN_RATE_ADAPTIVE_ENABLED, (void *)&vChar) )
			return -1;
		sprintf(buffer, "%u", vChar);
		ejSetResult(eid, buffer);
		return 0;
	}
	else if ( !strcmp(name, "wlanMode")) {
		if ( !mib_get( MIB_WLAN_MODE, (void *)&vChar) )
			return -1;
		sprintf(buffer, "%u", vChar);
		ejSetResult(eid, buffer);
		return 0;
	}
	else if ( !strcmp(name, "networkType")) {
		if ( !mib_get( MIB_WLAN_NETWORK_TYPE, (void *)&vChar) )
			return -1;
		sprintf(buffer, "%u", vChar);
		ejSetResult(eid, buffer);
		return 0;
	}
	else if ( !strcmp(name, "iappDisabled")) {
		if ( !mib_get( MIB_WLAN_IAPP_DISABLED, (void *)&vChar) )
			return -1;
		sprintf(buffer, "%u", vChar);
		ejSetResult(eid, buffer);
		return 0;
	}
#ifdef WLAN_WPA
	else if ( !strcmp(name, "encrypt")) {
		if ( !mib_get( MIB_WLAN_ENCRYPT, (void *)&vChar) )
			return -1;
		sprintf(buffer, "%u", vChar);
		ejSetResult(eid, buffer);
		return 0;
	}
	else if ( !strcmp(name, "enable1X")) {
		if ( !mib_get( MIB_WLAN_ENABLE_1X, (void *)&vChar) )
			return -1;
		sprintf(buffer, "%u", vChar);
		ejSetResult(eid, buffer);
		return 0;
	}
	else if ( !strcmp(name, "enableSuppNonWpa")) {
		if ( !mib_get( MIB_WLAN_ENABLE_SUPP_NONWPA, (void *)&vChar) )
			return -1;
		sprintf(buffer, "%u", vChar);
		ejSetResult(eid, buffer);
		return 0;
	}
	else if ( !strcmp(name, "suppNonWpa")) {
		if ( !mib_get( MIB_WLAN_SUPP_NONWPA, (void *)&vChar) )
			return -1;
		sprintf(buffer, "%u", vChar);
		ejSetResult(eid, buffer);
		return 0;
	}
	else if ( !strcmp(name, "wpaAuth")) {
		if ( !mib_get( MIB_WLAN_WPA_AUTH, (void *)&vChar) )
			return -1;
		sprintf(buffer, "%u", vChar);
		ejSetResult(eid, buffer);
		return 0;
	}
	else if ( !strcmp(name, "wpaCipher")) {
		if ( !mib_get( MIB_WLAN_WPA_CIPHER_SUITE, (void *)&vChar) )
			return -1;
		sprintf(buffer, "%u", vChar);
		ejSetResult(eid, buffer);
		return 0;
	}
	else if ( !strcmp(name, "pskFormat")) {
		if ( !mib_get( MIB_WLAN_WPA_PSK_FORMAT, (void *)&vChar) )
			return -1;
		sprintf(buffer, "%u", vChar);
		ejSetResult(eid, buffer);
		return 0;
	}
	else if ( !strcmp(name, "enableMacAuth")) {
		if ( !mib_get( MIB_WLAN_ENABLE_MAC_AUTH, (void *)&vChar) )
			return -1;
		sprintf(buffer, "%u", vChar);
		ejSetResult(eid, buffer);
		return 0;
	}
	else if ( !strcmp(name, "rsRetry") ) {
		if ( !mib_get( MIB_WLAN_RS_RETRY, (void *)&vChar) )
			return -1;
		sprintf(buffer, "%u", vChar);
		ejSetResult(eid, buffer);
		return 0;
	}
#endif

#ifdef WLAN_WDS
	else if ( !strcmp(name, "wlanWdsEnabled")) {
		if ( !mib_get( MIB_WLAN_WDS_ENABLED, (void *)&vChar) )
			return -1;
		sprintf(buffer, "%u", vChar);
		ejSetResult(eid, buffer);
		return 0;
	}
	else if ( !strcmp(name, "wlanWdsNum")) {
		if ( !mib_get( MIB_WLAN_WDS_NUM, (void *)&vChar) )
			return -1;
		sprintf(buffer, "%u", vChar);
		ejSetResult(eid, buffer);
		return 0;
	}
	else if ( !strcmp(name, "wdsWep")) {
		if ( !mib_get( MIB_WLAN_WDS_WEP, (void *)&vChar) )
			return -1;
		sprintf(buffer, "%u", vChar);
		ejSetResult(eid, buffer);
		return 0;
	}
	else if ( !strcmp(name, "wdsDefaultKeyId")) {
		if ( !mib_get( MIB_WLAN_WDS_WEP_DEFAULT_KEY, (void *)&vChar) )
			return -1;
		sprintf(buffer, "%u", ++vChar);
		ejSetResult(eid, buffer);
		return 0;
	}
	else if ( !strcmp(name, "wdsKeyType") ) {
		if ( !mib_get( MIB_WLAN_WDS_WEP_KEY_TYPE, (void *)&vChar) )
			return -1;
		sprintf(buffer, "%u", vChar) ;
		 ejSetResult(eid, buffer);
		return 0;
	}
#endif

#ifdef WLAN_8185AG
	else if ( !strcmp(name, "RFType") ) {
		if ( !mib_get( MIB_HW_RF_TYPE, (void *)&vChar) )
			return -1;
		sprintf(buffer, "%u", vChar) ;
		 ejSetResult(eid, buffer);
		return 0;
	}
	else if ( !strcmp(name, "band") ) {
		if ( !mib_get( MIB_WLAN_BAND, (void *)&vChar) )
			return -1;
		sprintf(buffer, "%u", (int)vChar) ;
		 ejSetResult(eid, buffer);
		return 0;
	}
	else if ( !strcmp(name, "fixTxRate") ) {
		if ( !mib_get( MIB_WLAN_FIX_RATE, (void *)&vUShort) )
			return -1;
		sprintf(buffer, "%u", vUShort) ;
		 ejSetResult(eid, buffer);
		return 0;
	}
#endif

#endif // of WLAN_SUPPORT

	sprintf(buffer, "%d", -1);
	ejSetResult(eid, buffer);
	return 0;

//   	return -1;
}
#endif

int isConnectPPP(void)
{
	return 0;
}

int getNameServer(int eid, request* wp, int argc, char **argv) {

	FILE *fp;
	char buffer[128], tmpbuf[64];
	int count = 0;
	//fprintf(stderr, "getNameServer %x\n", gResolvFile);
	//boaWrite(wp, "[]", tmpbuf);
	//if ((gResolvFile == NULL) ||
	if ( (fp = fopen("/var/resolv.conf", "r")) == NULL ) {
		//printf("Unable to open resolver file\n");
		return -1;
	}

	while (fgets(buffer, sizeof(buffer), fp) != NULL) {
		if (sscanf(buffer, "nameserver %s", tmpbuf) != 1) {
			continue;
		}

		if (count == 0)
			boaWrite(wp, "%s", tmpbuf);
		else
			boaWrite(wp, ", %s", tmpbuf);
		count ++;
	}

	fclose(fp);
	return 0;
}

#ifndef RTF_UP
/* Keep this in sync with /usr/src/linux/include/linux/route.h */
#define RTF_UP          0x0001	/* route usable                 */
#define RTF_GATEWAY     0x0002	/* destination is a gateway     */
#define RTF_HOST        0x0004	/* host entry (net otherwise)   */
#define RTF_REINSTATE   0x0008	/* reinstate route after tmout  */
#define RTF_DYNAMIC     0x0010	/* created dyn. (by redirect)   */
#define RTF_MODIFIED    0x0020	/* modified dyn. (by redirect)  */
#define RTF_MTU         0x0040	/* specific MTU for this route  */
#ifndef RTF_MSS
#define RTF_MSS         RTF_MTU	/* Compatibility :-(            */
#endif
#define RTF_WINDOW      0x0080	/* per route window clamping    */
#define RTF_IRTT        0x0100	/* Initial round trip time      */
#define RTF_REJECT      0x0200	/* Reject route                 */
#endif

int getDefaultGWMask(int eid, request* wp, int argc, char **argv)
{
	char buff[256];
	int flags, ret = -1;
	struct in_addr gw, dest, mask, inAddr;
	char ifname[16], dgw[16];
	FILE *fp;

	if (!(fp = fopen("/proc/net/route", "r"))) {
		printf("Error: cannot open /proc/net/route - continuing...\n");
		return ret;
	}

	fgets(buff, sizeof(buff), fp);
	while (fgets(buff, sizeof(buff), fp) != NULL) {
		if (sscanf
		    (buff, "%s%x%x%x%*d%*d%*d%x", ifname, &dest, &gw, &flags,
		     &mask) != 5) {
			printf("Unsuported kernel route format\n");
			ret = -1;
			break;
		}
		//printf("ifname=%s, dest=%x, gw=%x, flags=%x, mask=%x\n", ifname, dest.s_addr, gw.s_addr, flags, mask.s_addr);
		if (flags & RTF_UP) {
			// default gateway
			if (getInAddr(ifname, IP_ADDR, &inAddr) == 1) {
				if (inAddr.s_addr == 0x40404040) {
					boaWrite(wp, "");
					ret = 0;
					break;
				}
			}

			if (getInAddr(ifname, SUBNET_MASK, &inAddr)) {
				boaWrite(wp, "%s", inet_ntoa(inAddr));
				ret = 0;
				break;
			}
		}
	}

	fclose(fp);
	return ret;
}

// Jenny, get default gateway information
int getDefaultGW(int eid, request* wp, int argc, char **argv)
{
	char buff[256];
	int flags, ret = -1;
	struct in_addr gw, dest, mask, inAddr;
	char ifname[MAX_WAN_NAME_LEN], dgw[16], vc_ifname[16], total_entry, i;
	FILE *fp;
	MIB_CE_ATM_VC_T entry;

	if (!(fp=fopen("/proc/net/route", "r"))) {
		printf("Error: cannot open /proc/net/route - continuing...\n");
		return ret;
	}

	fgets(buff, sizeof(buff), fp);
	while (fgets(buff, sizeof(buff), fp) != NULL) {
		if (sscanf(buff, "%s%x%x%x%*d%*d%*d%x", ifname, &dest, &gw, &flags, &mask) != 5) {
			printf("Unsuported kernel route format\n");
			ret = -1;
			break;
		}

		//printf("ifname=%s, dest=%x, gw=%x, flags=%x, mask=%x\n", ifname, dest.s_addr, gw.s_addr, flags, mask.s_addr);
		if(flags & RTF_UP) {
			// default gateway
			if (getInAddr(ifname, IP_ADDR, (void *)&inAddr) == 1) {
				if (inAddr.s_addr == 0x40404040) {
					boaWrite(wp, "");
					ret = 0;
					break;
				}
			}
			if (dest.s_addr == 0 && mask.s_addr == 0) {
				if (gw.s_addr != 0) {
					strncpy(dgw,  inet_ntoa(gw), 16);
					boaWrite(wp, "%s", dgw);
					ret = 0;
					break;
				}
				else
				{
					total_entry = mib_chain_total(MIB_ATM_VC_TBL);

					for( i = 0; i < total_entry; i++ )
					{
						if(!mib_chain_get(MIB_ATM_VC_TBL, i, &entry))
							continue;

						if (entry.cmode == CHANNEL_MODE_PPPOE || entry.cmode == CHANNEL_MODE_PPPOA)
							snprintf(vc_ifname, 6, "ppp%u", PPP_INDEX(entry.ifIndex));
						else
							strcpy(vc_ifname, "aabbcc");
						if(entry.dgw != 1)
							continue;
						if(!strcmp(vc_ifname, ifname))
						{
							//getWanName(&entry, ifname);
							break;
						}
					}
					if (getInAddr(ifname, DST_IP_ADDR, &inAddr)) {
						boaWrite(wp, "%s", inet_ntoa(inAddr));
						ret = 0;
						break;
					}

					//boaWrite(wp, "%s", ifname);
					//ret = 0;
					//break;
				}
			}
		}
	}

	fclose(fp);
	return ret;
}

#ifdef CONFIG_IPV6
int getDefaultGW_ipv6(int eid, request* wp, int argc, char **argv)
{
	char buff[256];
	struct in6_addr addr, zero_ip = {0};
	unsigned char len;
	unsigned char devname[10];
	unsigned char value[48];
	FILE *fp;
	int i;

	if (!(fp=fopen("/proc/net/ipv6_route", "r"))) {
		printf("Error: cannot open /proc/net/ipv6_route - continuing...\n");
		return -1;
	}

	fgets(buff, sizeof(buff), fp);
	while (fgets(buff, sizeof(buff), fp) != NULL) {
		if(sscanf( buff,
			"%*32s%02hhx%*32s%*02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%*x%*x%*x%*x%s",
			&len,
			&addr.s6_addr[ 0], &addr.s6_addr[ 1], &addr.s6_addr[ 2], &addr.s6_addr[ 3],
			&addr.s6_addr[ 4], &addr.s6_addr[ 5], &addr.s6_addr[ 6], &addr.s6_addr[ 7],
			&addr.s6_addr[ 8], &addr.s6_addr[ 9], &addr.s6_addr[10], &addr.s6_addr[11],
			&addr.s6_addr[12], &addr.s6_addr[13], &addr.s6_addr[14], &addr.s6_addr[15], devname)) {

			//printf("len=%d, devname=%s\n", len, devname);
			//for ( i=0; i<16; i++)
			//	printf("%x ", addr.s6_addr[i]);
			//printf("\n");

			if( len == 0 && (strcmp(devname, "lo") !=0) && (memcmp(&zero_ip, &addr, sizeof(struct in6_addr)) != 0)) {

				inet_ntop(PF_INET6, &addr, value, sizeof(value));
				boaWrite(wp, "%s", value);
				fclose(fp);
				return 0;
			}
		}
	}
	boaWrite(wp, "");
	fclose(fp);
	return 0;
}
#endif

int multilang_asp(int eid, request * wp, int argc, char **argv)
{
	int key;

	if (boaArgs(argc, argv, "%d", &key) < 1) {
		boaError(wp, 400, "Insufficient args\n");
		return -1;
	}

	return boaWrite(wp, "%s", multilang(key));
}

#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_SEREnable_
int showSER(int eid, request * wp, int argc, char **argv)
{
	int SER = getSER(0);
	return boaWrite(wp, "%d", SER);
}
#endif

#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_ErrorCodeEnable_
int showErrorCode(int eid, request * wp, int argc, char **argv)
{
	int ErrorCode = getErrorCode(0);
	return boaWrite(wp, "%d", ErrorCode);
}
#endif

#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_PLREnable_
int showPLR(int eid, request * wp, int argc, char **argv)
{
	int PLR = getPLR(0);
	return boaWrite(wp, "%d", PLR);
}
#endif

#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_PacketLostEnable_
int showPacketLost(int eid, request * wp, int argc, char **argv)
{
	int PacketLost = getPacketLost(0);
	return boaWrite(wp, "%d", PacketLost);
}
#endif

#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_RegisterNumberEnable_
int showRegisterNumberITMS(int eid, request * wp, int argc, char **argv)
{
	int RegisterNumberITMS = getRegisterNumberITMS();
	return boaWrite(wp, "%d", RegisterNumberITMS);
}
#endif

#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_RegisterSuccessNumberEnable_
int showRegisterSuccNumITMS(int eid, request * wp, int argc, char **argv)
{
	int RegisterSuccNumITMS = getRegisterSuccNumITMS();
	return boaWrite(wp, "%d", RegisterSuccNumITMS);
}
#endif
#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_RegisterNumberEnable_
int showDHCPRegisterNumber(int eid, request * wp, int argc, char **argv)
{
	int number = 0;
	number = getDHCPRegisterNumber();
	return boaWrite(wp, "%d", number);
}
#endif
#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_RegisterSuccessNumberEnable_
int showDHCPSuccessNumber(int eid, request * wp, int argc, char **argv)
{
	int number = 0;
	number = getDHCPSuccessNumber();
	return boaWrite(wp, "%d", number);
}
#endif

#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_LANxStateEnable_
int showLANxState(int eid, request * wp, int argc, char **argv)
{
	char state[256] = {0};
	
	getLANxState(state, sizeof(state));
	return boaWrite(wp, state);
}
#endif

#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_UpDataEnable_
int showUpData(int eid, request * wp, int argc, char **argv)
{
	char data[256] = {0};
	
	getUpData(data, sizeof(data), 0);
	return boaWrite(wp, data);
}
#endif

#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_DownDataEnable_
int showDownData(int eid, request * wp, int argc, char **argv)
{
	char data[256] = {0};
	
	getDownData(data, sizeof(data), 0);
	return boaWrite(wp, data);
}
#endif

#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_LANxWorkBandwidthEnable_
int showLANxWorkBandwidth(int eid, request * wp, int argc, char **argv)
{
	char bandwith[256] = {0};
	
	getLANxWorkBandwidth(bandwith, sizeof(bandwith));
	return boaWrite(wp, bandwith);
}
#endif

#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_AllDeviceNumberEnable_
int showAllDeviceNumber(int eid, request * wp, int argc, char **argv)
{
	int number = 0;
	number = getAllDeviceNumber();
	return boaWrite(wp, "%d", number);
}

#endif

#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_WLANDeviceMACEnable_
int showWLANDeviceMAC(int eid, request * wp, int argc, char **argv)
{
	char deviceInfo[1024] = {0};
	getWLANDeviceMAC(deviceInfo, sizeof(deviceInfo));
	return boaWrite(wp, "%s", deviceInfo);
}
#endif

#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_LANDeviceMACEnable_
int showLANDeviceMAC(int eid, request * wp, int argc, char **argv)
{
	char deviceInfo[1024] = {0};
	getLANDeviceMAC(deviceInfo, sizeof(deviceInfo));
	return boaWrite(wp, "%s", deviceInfo);
}
#endif

#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_DevicePacketLossEnable_
int showDevicePacketLoss(int eid, request * wp, int argc, char **argv)
{
	char pktLoss[1024] = {0};
	getDevicePacketLoss(pktLoss, sizeof(pktLoss));
	return boaWrite(wp, "%s", pktLoss);
}
#endif

#ifdef  _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_CPURateEnable_
int showCPURate(int eid, request * wp, int argc, char **argv)
{
	unsigned int CPURate;
	getCPURate(&CPURate);
	return boaWrite(wp, "%u", CPURate);
}
#endif

#ifdef  _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_MemRateEnable_
int showMemRate(int eid, request * wp, int argc, char **argv)
{
	unsigned int MemRate;
	getMemRate(&MemRate);
	return boaWrite(wp, "%u", MemRate);	
}
#endif

#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_DialingNumberEnable_
int showDialingNumber(int eid, request * wp, int argc, char **argv)
{
	int DialingNumber = getPppoeDialingNumber();
	return boaWrite(wp, "%d", DialingNumber);
}
#endif

#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_DialingErrorEnable_
int showDialingError(int eid, request * wp, int argc, char **argv)
{
	char DialingError[64];
	getPppoeDialingError(DialingError);
	return boaWrite(wp, "%s", DialingError);
}
#endif
#ifdef  _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_TEMPEnable_
int showTEMP(int eid, request * wp, int argc, char **argv)
{
	double temp;
	getTEMP(&temp);
	return boaWrite(wp, "%.2lf°C", temp);	
}
#endif
#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_OpticalInPowerEnable_
int showOpticalInPower(int eid, request * wp, int argc, char **argv)
{
	char buf[30];
	double power;
	getOpticalInPower(buf);
	sscanf(buf, "%lf  dBm", &power);
	return boaWrite(wp, "%.1lf", power);
}
#endif
#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_OpticalOutPowerEnable_
int showOpticalOutPower(int eid, request * wp, int argc, char **argv)
{
	char buf[30];
	double power;
	getOpticalOutPower(buf);
	sscanf(buf, "%lf  dBm", &power);
	return boaWrite(wp, "%.1lf", power);
}
#endif
#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_RoutingModeEnable_
int showRoutingMode(int eid, request * wp, int argc, char **argv)
{
	int bridgeMode;
	bridgeMode = getRoutingMode();
	
	return boaWrite(wp, "%d(%s)", bridgeMode, bridgeMode?"Bridge":"Routing");
}
#endif
#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_RegisterNumberEnable_
int showRegisterOLTNumber(int eid, request * wp, int argc, char **argv)
{
	int number = 0;
	number = getRegisterOLTNumber();
	return boaWrite(wp, "%d", number);
}
#endif
#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_RegisterSuccessNumberEnable_
int showRegisterOLTSuccNumber(int eid, request * wp, int argc, char **argv)
{
	int number = 0;
	number = getRegisterOLTSuccNumber();
	return boaWrite(wp, "%d", number);
}
#endif
#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_MulticastNumberEnable_
int showMulticastNumber(int eid, request * wp, int argc, char **argv)
{
	int number;
	number = getMulticastNumber();
	
	return boaWrite(wp, "%d", number);
}
#endif

