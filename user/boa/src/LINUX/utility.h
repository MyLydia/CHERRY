/*
 *      Include file of utility.c
 *
 *      Authors: David Hsu	<davidhsu@realtek.com.tw>
 *      Authors: Dick Tam	<dicktam@realtek.com.tw>
 *
 *
 */

#ifndef INCLUDE_UTILITY_H
#define INCLUDE_UTILITY_H

#ifndef CONFIG_RTL_ALIASNAME
#define ALIASNAME_VC   "vc"
#define ALIASNAME_BR   "br"
#define ALIASNAME_NAS  "nas"
#define ALIASNAME_DSL  "dsl"
#define ALIASNAME_ETH  "eth"
#define ALIASNAME_WLAN "wlan"
#define ALIASNAME_PPP  "ppp"
#define ALIASNAME_MWNAS  "nas0_"
#define ALIASNAME_ELAN_PREFIX  "eth0."
#ifdef CONFIG_USER_CMD_CLIENT_SIDE
#define ALIASNAME_PTM  "nas"
#else
#define ALIASNAME_PTM  "ptm"
#endif
#define ALIASNAME_MWPTM  "ptm0_"
#define ORIGINATE_NUM 2

#else
#define ALIASNAME_VC   CONFIG_ALIASNAME_VC//"vc"
#define ALIASNAME_BR   CONFIG_ALIASNAME_BR//"br"
#define ALIASNAME_NAS  CONFIG_ALIASNAME_NAS//"nas"
#define ALIASNAME_DSL  CONFIG_ALIASNAME_DSL//"dsl"
#define ALIASNAME_ETH  CONFIG_ALIASNAME_ETH//"eth"
#define ALIASNAME_WLAN  CONFIG_ALIASNAME_WLAN//"wlan"
#define ALIASNAME_PPP  CONFIG_ALIASNAME_PPP//"ppp"
#define ALIASNAME_MWNAS  CONFIG_ALIASNAME_MWNAS//"nas0_"
#define ALIASNAME_ELAN_PREFIX  CONFIG_ALIASNAME_ELAN_PREFIX//"eth0."
#define ALIASNAME_PTM  CONFIG_ALIASNAME_PTM//"ptm"
#define ALIASNAME_MWPTM  CONFIG_ALIASNAME_MWPTM//"ptm0_"
#define ORIGINATE_NUM CONFIG_ORIGINATE_NUM

#endif

#define RTL_DEV_NAME_NUM(name,num)	name#num

#define ALIASNAME_NAS0  RTL_DEV_NAME_NUM(ALIASNAME_NAS,0)//"nas0"
#define ALIASNAME_PTM0  RTL_DEV_NAME_NUM(ALIASNAME_PTM,0)//"ptm0"

#define ALIASNAME_DSL0  RTL_DEV_NAME_NUM(ALIASNAME_DSL,0)//dsl0
#define ALIASNAME_ELAN0  RTL_DEV_NAME_NUM(ALIASNAME_ELAN_PREFIX,2)
#define ALIASNAME_ELAN1  RTL_DEV_NAME_NUM(ALIASNAME_ELAN_PREFIX,3)
#define ALIASNAME_ELAN2  RTL_DEV_NAME_NUM(ALIASNAME_ELAN_PREFIX,4)
#define ALIASNAME_ELAN3  RTL_DEV_NAME_NUM(ALIASNAME_ELAN_PREFIX,5)
#define ALIASNAME_ELAN4  RTL_DEV_NAME_NUM(ALIASNAME_ELAN_PREFIX,6)
#define ALIASNAME_ELAN5  RTL_DEV_NAME_NUM(ALIASNAME_ELAN_PREFIX,7)

#define ALIASNAME_BR0   RTL_DEV_NAME_NUM(ALIASNAME_BR,0)//"br0"
#define ALIASNAME_WLAN0  RTL_DEV_NAME_NUM(ALIASNAME_WLAN,0)//"wlan0"

#define ALIASNAME_VAP   "-vap" //must include '-' at fast
#define ALIASNAME_WLAN0_VAP  RTL_DEV_NAME_NUM(ALIASNAME_WLAN0,-vap)//"wlan0-vap"

#define ALIASNAME_WLAN0_VAP0  RTL_DEV_NAME_NUM(ALIASNAME_WLAN0_VAP,0)//"wlan0-vap0"
#define ALIASNAME_WLAN0_VAP1  RTL_DEV_NAME_NUM(ALIASNAME_WLAN0_VAP,1)//"wlan0-vap1"
#define ALIASNAME_WLAN0_VAP2  RTL_DEV_NAME_NUM(ALIASNAME_WLAN0_VAP,2)//"wlan0-vap2"
#define ALIASNAME_WLAN0_VAP3  RTL_DEV_NAME_NUM(ALIASNAME_WLAN0_VAP,3)//"wlan0-vap3"

#define WANMODE_CONF_STR "WAN Mode"
#define PON_CONF_STR "PON WAN"
#define ETHWAN_CONF_STR "Ethernet WAN"
#define PTMWAN_CONF_STR "PTM WAN"
#ifdef WLAN_WISP
#define WLWAN_CONF_STR "Wireless WAN"
#endif
#ifdef CONFIG_VDSL
#define DSLWAN_CONF_STR "ATM WAN"
#define ADSL_SETTINGS_STR "DSL Settings"
#define ADSL_STR "DSL"
#define ADSL_TONE_STR "DSL Tone"
#define ADSL_SLV_STR "DSL Slave"
#define ADSL_SLV_TONE_STR "DSL Slave Tone"
#else
#define DSLWAN_CONF_STR "DSL WAN"
#define ADSL_SETTINGS_STR "ADSL Settings"
#define ADSL_STR "ADSL"
#define ADSL_TONE_STR "ADSL Tone"
#define ADSL_SLV_STR "ADSL Slave"
#define ADSL_SLV_TONE_STR "ADSL Slave Tone"
#endif /*CONFIG_VDSL*/
#define ATM_SETTINGS_STR "ATM Settings"
#define ATM_LOOPBACK_STR "ATM Loopback"
#define ADSL_CONNECTION_STR "ADSL Connection"
#ifdef CONFIG_DSL_VTUO
#define VTUO_SETTINGS_STR "VTU-O DSL Settings"
#define VTUO_STATUS_STR "VTU-O DSL"
#endif /*CONFIG_DSL_VTUO*/

#include <sys/socket.h>
#include <linux/if.h>
#include <stdarg.h>
#include <stdio.h>
#include <net/route.h>
#include <netdb.h>
#include <netpacket/packet.h>

#include "adslif.h"
#include "mib.h"
#include "sysconfig.h"
#include "subr_dhcpv6.h"
#include "options.h"
//#ifdef CONFIG_USER_XDSL_SLAVE
//#include "subr_nfbi_api.h"
//#endif /*CONFIG_USER_XDSL_SLAVE*/
#ifdef WLAN_SUPPORT
#include "subr_wlan.h"
#endif
#ifdef TIME_ZONE
#include "tz.h"
#endif

#ifdef NAT_LOOPBACK
#define DEL_ALL_NATLB_DYNAMIC			1
#define DEL_PORTFW_NATLB_DYNAMIC		2
#define DEL_DMZ_NATLB_DYNAMIC			3
#endif

#if defined(SUPPORT_BYPASS_RG_FWDENGINE)
/* FON GRE should bypass fwdEngine, so I add a new macro */
#define BYPASS_FWDENGINE_MARK_OFFSET	3
#define BYPASS_FWDENGINE_MARK_MASK		(0x1<<BYPASS_FWDENGINE_MARK_OFFSET)
#endif

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
// todo --- temporary used, should be removed after new toolchain(for IPv6) is ready.
#define IPV6_ADDR_ANY		0x0000U
#define IPV6_ADDR_UNICAST	0x0001U
#define IPV6_ADDR_MULTICAST	0x0002U
#define IPV6_ADDR_LOOPBACK	0x0010U
#define IPV6_ADDR_LINKLOCAL	0x0020U
#define IPV6_ADDR_SITELOCAL	0x0040U
#define IPV6_ADDR_COMPATv4	0x0080U
#define IPV6_ADDR_SCOPE_MASK	0x00f0U
#define IPV6_ADDR_MAPPED	0x1000U
#define IPV6_ADDR_RESERVED	0x2000U	/* reserved address space */
// todo -- end of temporary used

// defined to use pppd, otherwise, use spppd if not defined
//#define USE_PPPD

/* Magician: Debug macro */
/* Example: CWMPDBP(2, "File not fould, file name=%s", filename);*/
/* Output: <DEBUG: abc.c, 1122>File not fould, file name=test.txt */
#define LINE_(line) #line
#define LINE(line) LINE_(line)
#define DBPRINT0(...) while(0){}
#define DBPRINT1(...) fprintf(stderr, "<"__FILE__","LINE(__LINE__)">"__VA_ARGS__)
#define DBPRINT2(...) fprintf(stderr, "<DEBUG:"__FILE__","LINE(__LINE__)">"__VA_ARGS__)
#define DBPRINT(level, ...) DBPRINT##level(__VA_ARGS__)

#define BUF_SIZE		256
#define MAX_POE_PER_VC		5
struct data_to_pass_st {
	int	id;
	char data[BUF_SIZE];
};

void setup_mac_addr(unsigned char *macAddr, int index);

//Alan Chang 20160727-netcore
#if defined(CONFIG_IPV6)
/************************************************
* Propose: ipv6_linklocal_eui64()
*    Produce Link local IPv6 address
*      e.q: MAC Address 00:E0:4C:86:53:38  ==>
			Linklocal IPv6 Address fe80::2e0:4cff:fe86:5338
* Parameter:
*	unsigned char *d      LinkLocal IPV6 Address   (output)
*     unsigned char *p      MAC Address                 (input)
* Return:
*     None
* Author:
*     Alan
*************************************************/
#define ipv6_linklocal_eui64(d, p) \
  *(d)++ = 0xFE; *(d)++ = 0x80; *(d)++ = 0; *(d)++ = 0; \
  *(d)++ = 0; *(d)++ = 0; *(d)++ = 0; *(d)++ = 0; \
  *(d)++ = ((p)[0]|0x2); *(d)++ = (p)[1]; *(d)++ = (p)[2] ;*(d)++ = 0xff; \
  *(d)++ = 0xfe; *(d)++ = (p)[3]; *(d)++ = (p)[4] ;*(d)++ = (p)[5];
#endif

// Mason Yu. For Set IPQOS
#ifdef CONFIG_USER_IP_QOS
#define		SETIPQOS		0x01

/*
 * Structure used in SIOCSIPQOS request.
 */

struct ifIpQos
{
	int	cmd;
	char	enable;
};
#endif
#if defined(NEW_IP_QOS_SUPPORT) || defined(CONFIG_USER_IP_QOS_3)
enum qos_policy_t
{
	PLY_PRIO=0,
	PLY_WRR,
	PLY_NONE
};
#endif
#ifdef NEW_IP_QOS_SUPPORT
int setup_qos_setting(void);
void take_qos_effect(void);
void stop_IPQoS(void);
#ifdef CONFIG_DEV_xDSL
int monitor_qos_setting(void);
#endif
int delIpQosTcRule(MIB_CE_ATM_VC_Tp pEntry);
#endif

// Mason Yu
#ifdef IP_PASSTHROUGH
struct ippt_para
{
	unsigned int old_ippt_itf;
	unsigned int new_ippt_itf;
	unsigned char old_ippt_lanacc;
	unsigned char new_ippt_lanacc;
	unsigned int old_ippt_lease;
	unsigned int new_ippt_lease;
};
#endif

// Mason Yu. combine_1p_4p_PortMapping
#if defined(NEW_PORTMAPPING)
#define		VLAN_ENABLE		0x01
#define		VLAN_SETINFO		0x02
#define		VLAN_SETPVIDX		0x03
#define		VLAN_SETTXTAG		0x04
#define		VLAN_DISABLE1PPRIORITY	0x05
#define		VLAN_SETIGMPSNOOP	0x06
#define		VLAN_SETPORTMAPPING	0x07
#define		VLAN_SETIPQOS		0x08
#define		VLAN_VIRTUAL_PORT	0x09
#define		VLAN_SETVLANGROUPING	0x0a
#ifdef CONFIG_PPPOE_PROXY
#define    SET_PPPOE_PROXY_PORTMAP  0x0b
#endif

#ifdef CONFIG_IGMP_FORBID
#define           IGMP_FORBID              0x0a
#endif
#define		TAG_DCARE	0x03
#define		TAG_ADD		0x02
#define		TAG_REMOVE	0x01
#define		TAG_REPLACE	0x00

struct brmap {
	int	brid;
	unsigned char pvcIdx;
};

extern int virtual_port_enabled;
#endif

/*
 * Structure used in SIOCSIFVLAN request.
 */

struct ifvlan
{
	int	cmd;
	char	enable;
	short	vlanIdx;
	short	vid;
	char		disable_priority;
	int	member;
	int	port;
	char	txtag;
};

extern const int virt2user[];

#ifdef CONFIG_USER_DHCPCLIENT_MODE
int setupDHCPClient(void);
#endif

#ifdef CONFIG_USER_DDNS		// Mason Yu. Support ddns status file.
void remove_ddns_status(void);
#endif
#if defined(CONFIG_LUNA) && defined(CONFIG_RTK_L34_ENABLE)
void write_to_dhcpc_info(unsigned long requested_ip,unsigned long subnet_mask,unsigned long gw_addr);
#endif
#define MSG_BOA_PID		2222
// mtype for configd: Used as mtype to send message to configd; should be
//	well-configured to avoid conflict with the pid of any other processes
//	since the processes use	their pid as mtype to receive reply message
//	from configd.
#define MSG_CONFIGD_PID		8

// Mason Yu. Support ddns status file.
enum ddns_status{
	SUCCESSFULLY_UPDATED=0,
	CONNECTION_ERROR=1,
	AUTH_FAILURE=2,
	WRONG_OPTION=3,
	HANDLING=4,
	LINK_DOWN=5
};

// Mason Yu
enum PortMappingGrp
{
	PM_DEFAULTGRP=0,
	PM_GROUP1=1,
	PM_GROUP2=2,
	PM_GROUP3=3,
	PM_GROUP4=4
};

enum PortMappingAction
{
	PM_PRINT=0,
	PM_ADD=1,
	PM_REMOVE=2
};


extern const char*  wlan[];
extern const char*  wlan_itf[];
extern const int  wlan_en[];

//#ifdef NEW_PORTMAPPING
typedef enum MARK
{
	PMAP_ETH0_SW0 = 0,
	PMAP_ETH0_SW1,
	PMAP_ETH0_SW2,
	PMAP_ETH0_SW3,
	PMAP_WLAN0 = 4,
	PMAP_WLAN0_VAP0,
	PMAP_WLAN0_VAP1,
	PMAP_WLAN0_VAP2,
	PMAP_WLAN0_VAP3 = 8,
	PMAP_WLAN1 = 9,
	PMAP_WLAN1_VAP0,
	PMAP_WLAN1_VAP1,
	PMAP_WLAN1_VAP2,
	PMAP_WLAN1_VAP3 = 13,
	PMAP_ITF_END
} PMAP_LAN_T;
//#endif

#define PMAP_WLAN0_VAP_END PMAP_WLAN0_VAP3
#define PMAP_WLAN1_VAP_END PMAP_WLAN1_VAP3

struct itfInfo
{
	#define	DOMAIN_ELAN	0x1
	#define	DOMAIN_WAN	0x2
	#define	DOMAIN_GRE	0x3
	#define	DOMAIN_WLAN	0x4
	#define	DOMAIN_ULAN	0x8	//usbeth
	#define	DOMAIN_WANROUTERCONN 0x10
	int	ifdomain;
	int	ifid;
	char	name[40];// changed by jim
};

// IF_ID(domain, ifIndex)
#define IF_ID(x, y)		((x<<24)|y)
#define IF_DOMAIN(x)		(x>>24)
#define IF_INDEX(x)		(x&0x00ffffff)
#ifndef CONFIG_00R0
#define IFGROUP_NUM		5
#endif

#if defined(CONFIG_USBCLIENT) || !defined(CONFIG_RTL8672NIC)
#define DEVICE_SHIFT		5
#else
#define DEVICE_SHIFT		4
#endif
#define IFWLAN_SHIFT		6
#define IFWLAN1_SHIFT 12

#define MAX_NUM_OF_ITFS 32


#ifdef CONFIG_USB_ETH
#ifdef WLAN_SUPPORT
#define IFUSBETH_SHIFT		(IFWLAN_SHIFT+WLAN_MBSSID_NUM+1)
#else
#define IFUSBETH_SHIFT          (IFWLAN_SHIFT+1)
#endif
#define IFUSBETH_PHYNUM		(SW_LAN_PORT_NUM+5+1)  //for ipqos.phyPort (5: wlanphy max, 1:usb0)
#endif //CONFIG_USB_ETH


#define	IPQOS_NUM_PKT_PRIO	8
#define	IPQOS_NUM_PRIOQ		MAX_QOS_QUEUE_NUM

struct mymsgbuf;

typedef enum { IP_ADDR, DST_IP_ADDR, SUBNET_MASK, DEFAULT_GATEWAY, HW_ADDR } ADDR_T;
typedef enum {
	SYS_UPTIME,
	SYS_DATE,
	SYS_YEAR,
	SYS_MONTH,
	SYS_DAY,
	SYS_HOUR,
	SYS_MINUTE,
	SYS_SECOND,
	SYS_FWVERSION,
	SYS_HWVERSION,
#ifdef CONFIG_00R0
	SYS_BOOTLOADER_FWVERSION,
	SYS_BOOTLOADER_CRC,
	SYS_FWVERSION_SUM_1,
	SYS_FWVERSION_SUM_2,
#endif
#ifdef CPU_UTILITY
	SYS_CPU_UTIL,
#endif
#ifdef MEM_UTILITY
	SYS_MEM_UTIL,
#endif
	SYS_LAN_DHCP,
	SYS_DHCP_LAN_IP,
	SYS_DHCP_LAN_SUBNET,
	SYS_DHCPS_IPPOOL_PREFIX,
	SYS_DNS_MODE,
#ifdef CONFIG_USER_DHCPCLIENT_MODE
	SYS_LAN_IP,
	SYS_LAN_MASK,
#endif
	SYS_WLAN,
	SYS_WLAN_SSID,
	SYS_WLAN_DISABLED,
	SYS_WLAN_HIDDEN_SSID,
	SYS_WLAN_BAND,
	SYS_WLAN_AUTH,
	SYS_WLAN_PREAMBLE,
	SYS_WLAN_BCASTSSID,
	SYS_WLAN_ENCRYPT,
	SYS_WLAN_MODE_VAL,
	SYS_WLAN_ENCRYPT_VAL,
	SYS_WLAN_WPA_CIPHER_SUITE,
	SYS_WLAN_WPA2_CIPHER_SUITE,
	SYS_WLAN_WPA_AUTH,
	SYS_WLAN_PSKFMT,
	SYS_WLAN_PSKVAL,
#ifdef USER_WEB_WIZARD
	SYS_WLAN_PSKVAL_WIZARD,
#endif
	SYS_WLAN_WEP_KEYLEN,
	SYS_WLAN_WEP_KEYFMT,
	SYS_WLAN_WPA_MODE,
	SYS_WLAN_RSPASSWD,
	SYS_WLAN_RS_PORT,
	SYS_WLAN_RS_IP,
	SYS_WLAN_RS_PASSWORD,
	SYS_WLAN_ENABLE_1X,
	SYS_TX_POWER,
	SYS_WLAN_MODE,
	SYS_WLAN_TXRATE,
	SYS_WLAN_BLOCKRELAY,
	SYS_WLAN_AC_ENABLED,
	SYS_WLAN_WDS_ENABLED,
	SYS_WLAN_QoS,
	SYS_WLAN_WPS_ENABLED,
	SYS_WLAN_WPS_STATUS,
	SYS_WLAN_WPS_LOCKDOWN,
	SYS_WSC_DISABLE,
	SYS_WSC_AUTH,
	SYS_WSC_ENC,
	SYS_DHCP_MODE,
	SYS_IPF_OUT_ACTION,
	SYS_DEFAULT_PORT_FW_ACTION,
	SYS_MP_MODE,
	SYS_IGMP_SNOOPING,
	SYS_PORT_MAPPING,
	SYS_IP_QOS,
	SYS_IPF_IN_ACTION,
	SYS_WLAN_BLOCK_ETH2WIR,
	SYS_DNS_SERVER,
	SYS_LAN_IP2,
	SYS_LAN_DHCP_POOLUSE,
	SYS_DEFAULT_URL_BLK_ACTION,
	SYS_DEFAULT_DOMAIN_BLK_ACTION,
	SYS_DSL_OPSTATE,
	SYS_LAN1_VID,
	SYS_LAN2_VID,
	SYS_LAN3_VID,
	SYS_LAN4_VID,
	SYS_LAN1_STATUS,
	SYS_LAN2_STATUS,
	SYS_LAN3_STATUS,
	SYS_LAN4_STATUS,
//#ifdef CONFIG_USER_XDSL_SLAVE
	SYS_DSL_SLV_OPSTATE,
//#endif /*CONFIG_USER_XDSL_SLAVE*/
	SYS_DHCPV6_MODE,
	SYS_DHCPV6_RELAY_UPPER_ITF,
	SYS_LAN_IP6_LL,
	SYS_LAN_IP6_GLOBAL,
	SYS_WLAN_WPA_CIPHER,
	SYS_WLAN_WPA2_CIPHER
} SYSID_T;

// enumeration of user process bit-shift for process bit-mapping
typedef enum {
	PID_DNSMASQ=0,
	PID_SNMPD,
	PID_WEB,
	PID_CLI,
	PID_DHCPD,
	PID_DHCPRELAY,
	PID_TELNETD,
	PID_FTPD,
	PID_TFTPD,
	PID_SSHD,
	PID_SYSLOGD,
	PID_KLOGD,
	PID_IGMPPROXY,
	PID_RIPD,
	PID_WATCHDOGD,
	PID_SNTPD,
	PID_MPOAD,
	PID_SPPPD,
	PID_UPNPD,
	PID_UPDATEDD,
	PID_CWMP, /*tr069/cwmpClient pid,jiunming*/
	PID_WSCD,
	PID_MINIUPNPD,
	PID_SMBD,
	PID_NMBD,
#ifdef VOIP_SUPPORT
	PID_VOIPGWDT,
	PID_SOLAR,
#endif
} PID_SHIFT_T;

enum PortMappingPriority
{
	HighestPrio=0,
	HighPrio=1,
	MediumPrio=2,
	lowPrio=3
};


#define		PID_SHIFT(x)		(1<<x)
#define		NET_PID			PID_SHIFT(PID_MPOAD)|PID_SHIFT(PID_SPPPD)
#define		ALL_PID			0xffffffff & ~(NET_PID)


#ifdef _USE_RSDK_WRAPPER_
#include <sys/syslog.h>
#endif //_USE_RSDK_WRAPPER_

int startSSDP(void);
int IfName2ItfId(char *s);
int do_ioctl(unsigned int cmd, struct ifreq *ifr);
int isDirectConnect(struct in_addr *haddr, MIB_CE_ATM_VC_Tp pEntry);
int getInAddr(char *interface, ADDR_T type, void *pAddr);
int getInFlags(char *interface, int *flags );
int setInFlags(char *interface, int flags );
int INET_resolve(char *name, struct sockaddr *sa);
int read_pid(const char *filename);
int getLinkStatus(struct ifreq *ifr);
char *trim_white_space(char *str);

extern const char AUTO_RESOLV[];
extern const char DNS_RESOLV[];
extern const char DNS6_RESOLV[];
extern const char PPP_RESOLV[];
extern const char RESOLV[];
extern const char DNSMASQ_CONF[];
extern const char RESOLV_BACKUP[];
extern const char HOSTS[];
extern const char MINIDLNAPID[];

#define MAX_CONFIG_FILESIZE 300000
//extern int wlan_idx;	// interface index
// Added by Kaohj
extern const char LANIF[];
extern const char LAN_ALIAS[];	// alias for secondary IP
#ifdef CONFIG_NET_IPGRE
extern const char* GREIF[];
extern struct callout_s gre_ch;
void poll_GRE(void *dummy);
#define GRE_BACKUP_INTERVAL 120
#endif
#ifdef IP_PASSTHROUGH
extern const char LAN_IPPT[];	// alias for IP passthrough
#endif
extern const char ELANIF[];
#ifdef CONFIG_RTL_MULTI_LAN_DEV
#ifdef CONFIG_RTL9601B_SERIES
#define ELANVIF_NUM 1//eth lan virtual interface number
#else
#define ELANVIF_NUM CONFIG_LAN_PORT_NUM//eth lan virtual interface number
#endif
#else
#define ELANVIF_NUM 1
#endif
//#if defined(CONFIG_ETHWAN) || defined(CONFIG_RTL_MULTI_LAN_DEV)
extern const char* ELANVIF[];
extern const char* SW_LAN_PORT_IF[];
//#endif

extern const char BRIF[];
extern const char VC_BR[];
extern const char LLC_BR[];
extern const char VC_RT[];
extern const char BLANK[];
extern const char LLC_RT[];
extern const char PORT_DHCP[];
extern const char ARG_ADD[];
extern const char ARG_CHANGE[];
extern const char ARG_DEL[];
extern const char ARG_ENCAPS[];
extern const char ARG_QOS[];
extern const char ARG_255x4[];
extern const char ARG_0x4[];
extern const char ARG_BKG[];
extern const char ARG_I[];
extern const char ARG_O[];
extern const char ARG_T[];
extern const char ARG_TCP[];
extern const char ARG_UDP[];
extern const char ARG_NO[];
#ifdef NEW_IP_QOS_SUPPORT
extern const char ARG_TCPUDP[];
#endif
extern const char ARG_ICMP[];
extern const char FW_BLOCK[];
extern const char FW_INACC[];
extern const char PORTMAP_IPTBL[];
extern const char PORTMAP_IGMP[];
#ifdef REMOTE_ACCESS_CTL
extern const char RMACC_MARK[];
#endif
#ifdef IP_PORT_FILTER
extern const char FW_IPFILTER[];
#endif
#ifdef PORT_FORWARD_GENERAL
extern const char PORT_FW[];
#endif
#if defined(PORT_FORWARD_GENERAL) || defined(DMZ)
#ifdef NAT_LOOPBACK
extern const char PORT_FW_PRE_NAT_LB[];
extern const char PORT_FW_POST_NAT_LB[];
#endif
#endif
#ifdef DMZ
#ifdef NAT_LOOPBACK
extern const char IPTABLE_DMZ_PRE_NAT_LB[];
extern const char IPTABLE_DMZ_POST_NAT_LB[];
#endif
extern const char IPTABLE_DMZ[];
#endif
#ifdef NATIP_FORWARDING
extern const char IPTABLE_IPFW[];
extern const char IPTABLE_IPFW2[];
#endif
extern const char FW_DHCPS_DIS[];
#ifdef PORT_TRIGGERING
extern const char IPTABLES_PORTTRIGGER[];
#endif
extern const char FW_MACFILTER[];
extern const char FW_IPQ_MANGLE_DFT[];
extern const char FW_IPQ_MANGLE_USER[];
extern const char IPTABLE_TR069[];
extern const char FW_DROP[];
extern const char FW_ACCEPT[];
extern const char FW_RETURN[];
extern const char FW_FORWARD[];
extern const char FW_INPUT[];
extern const char FW_PREROUTING[];
extern const char FW_DPORT[];
extern const char FW_SPORT[];
extern const char FW_ADD[];
extern const char FW_DEL[];
extern const char FW_INSERT[];
#ifdef PORT_FORWARD_ADVANCE
extern const char FW_PPTP[];
extern const char FW_L2TP[];
extern const char *PFW_Gategory[];
extern const char *PFW_Rule[];
int config_PFWAdvance( int action_type );
#endif
extern const char *strItf[];
extern const char CONFIG_HEADER[];
extern const char CONFIG_TRAILER[];
extern const char CONFIG_HEADER_HS[];
extern const char CONFIG_TRAILER_HS[];
extern const char CONFIG_XMLFILE[];
extern const char CONFIG_RAWFILE[];
extern const char CONFIG_XMLFILE_HS[];
extern const char CONFIG_RAWFILE_HS[];
extern const char PPP_SYSLOG[];
extern const char PPP_DEBUG_LOG[];
#ifdef CONFIG_PPP
extern const char PPP_CONF[];
extern const char PPPD_FIFO[];
extern const char PPPOA_CONF[];
extern const char PPPOE_CONF[];
extern const char PPP_PID[];
extern const char SPPPD[];
#endif

#ifdef CONFIG_USER_CMD_CLIENT_SIDE
#define SWITCH_WAN_PORT 3
#define SWITCH_WAN_PORT_MASK	 (1<<SWITCH_WAN_PORT)
#define CMD_CLIENT_MONITOR_INTF ALIASNAME_PTM0
extern const char CMDSERV_CTRLERD[];
#endif
#ifdef CONFIG_USER_CMD_SERVER_SIDE
#define CMD_SERVER_MONITOR_INTF "eth0"	//for 0882
extern const char CMDSERV_ENDPTD[];
#endif
extern const char ADSLCTRL[];
extern const char IFCONFIG[];
//extern const char IWPRIV[];
extern const char BRCTL[];
extern const char MPOAD[];
extern const char MPOACTL[];
extern const char DHCPD[];
extern const char DHCPC[];
#if defined(CONFIG_USER_DNSMASQ_DNSMASQ) || defined(CONFIG_USER_DNSMASQ_DNSMASQ245)
extern const char DNSRELAY[];
extern const char DNSRELAYPID[];
#endif
extern const char WEBSERVER[];
extern const char SNMPD[];
extern const char ROUTE[];
extern const char IPTABLES[];
#ifdef CONFIG_IPV6
extern const char IP6TABLES[];
extern const char FW_IPV6FILTER[];
extern const char ARG_ICMPV6[];
#endif
extern const char EMPTY_MAC[MAC_ADDR_LEN];

/*ql 20081114 START need ebtables support*/
extern const char EBTABLES[];
extern const char ZEBRA[];
#ifdef CONFIG_USER_ZEBRA_OSPFD_OSPFD
extern const char OSPFD[];
#endif
extern const char RIPD[];
extern const char ROUTED[];
extern const char IGMPROXY[];
extern const char TC[];
extern const char NETLOGGER[];
#ifdef TIME_ZONE
extern const char SNTPC[];
extern const char SNTPC_PID[];
#endif
#ifdef CONFIG_USER_DDNS	 
extern const char DDNSC_PID[];
#endif

extern const char PROC_DYNADDR[];
extern const char PROC_IPFORWARD[];
extern const char PROC_FORCE_IGMP_VERSION[];
extern const char MPOAD_FIFO[];
extern const char STR_DISABLE[];
extern const char STR_ENABLE[];
extern const char STR_UNNUMBERED[];
extern const char rebootWord0[];
extern const char rebootWord1[];
extern const char rebootWord2[];
extern const char errGetEntry[];
extern const char MER_GWINFO[];

extern const char *n0to7[];
extern const char *prioLevel[];
extern const int priomap[];
extern const char *ipTos[];
//alex
#ifdef CONFIG_8021P_PRIO
extern const char *set1ptable[];
#endif

#if defined(CONFIG_RTL8681_PTM)
extern const char PTMIF[];
#endif

#ifdef CONFIG_USB_ETH
extern const char USBETHIF[];
#endif //CONFIG_USB_ETH

//Alan 20160728
extern const char hideErrMsg1[];
extern const char hideErrMsg2[];


#ifdef CONFIG_USER_CUPS
int getPrinterList(char *str, size_t size);
#endif // CONFIG_USER_CUPS

extern const char STR_NULL[];
extern const char DHCPC_PID[];
extern const char DHCPC_ROUTERFILE[];
extern const char DHCPC_SCRIPT[];
extern const char DHCPC_SCRIPT_NAME[];
extern const char DHCPD_CONF[];
extern const char DHCPD_LEASE[];
extern const char DHCPSERVERPID[];
extern const char DHCPRELAYPID[];

#ifdef XOR_ENCRYPT
//Jenny, Configuration file encryption
extern const char XOR_KEY[];
void xor_encrypt(char *inputfile, char *outputfile);
#endif

extern const char PW_HOME_DIR[];
extern const char PW_CMD_SHELL[];
extern const char PW_NULL_SHELL[];

#if defined CONFIG_IPV6 || defined CONFIG_RTK_L34_ENABLE
#ifdef CONFIG_USER_DHCPV6_ISC_DHCP411
extern const char DHCPDV6_CONF_AUTO[];
extern const char DHCPDV6_CONF[];
extern const char DHCPDV6_LEASES[];
extern const char DHCPDV6[];
extern const char DHCREALYV6[];
extern const char DHCPSERVER6PID[];
extern const char DHCPRELAY6PID[];
extern const char DHCPCV6SCRIPT[];
extern const char DHCPCV6[];
extern const char DHCPCV6STR[];
#endif
struct ipv6_ifaddr
{
	int			valid;
	struct in6_addr		addr;
	unsigned int		prefix_len;
	unsigned int		flags;
	unsigned int		scope;
};
#endif // of CONFIG_IPV6

extern const char *ppp_auth[];
#if defined(CONFIG_USER_BRIDGE_GROUPING)
void setgroup(char *list, unsigned char grpnum);
int get_group_ifinfo(struct itfInfo *info, int len, unsigned char grpnum);

struct availableItfInfo {
	#define DOMAIN_ELAN	0x1
	#define DOMAIN_WAN	0x2
	#define DOMAIN_WLAN	0x4
	#define DOMAIN_ULAN	0x8
	unsigned int ifdomain;
	unsigned int ifid;
	char name[40];
	unsigned char itfGroup;
};

#ifdef CONFIG_00R0
int getATMVCEntryandIDByIfindex(unsigned int ifindex, MIB_CE_ATM_VC_T *p, unsigned int *id);
int setup_Layer2BrFilter(int idx);
int setup_Layer2BrMarking(int idx);
#endif
int get_AvailableInterface(struct availableItfInfo *info, int len);
#endif 
#if defined(CONFIG_RTL_IGMP_SNOOPING)
void __dev_setupIGMPSnoop(int flag);	// enable/disable IGMP snooping
#endif

#if defined(CONFIG_RTL_MLD_SNOOPING)
void __dev_setupMLDSnoop(int flag);
#endif

void __dev_setupDirectBridge(int flag);
#ifdef CONFIG_USER_IP_QOS
int hwnat_wanif_rule(void);
int setWanIF1PMark(void);
#endif
void __dev_setupIPQoS(int flag);
#ifdef QOS_DIFFSERV
void cleanupDiffservRule(int idx);
int setupDiffServ(void);
#endif
int get_domain_ifinfo(struct itfInfo *info, int len, int ifdomain);

int do_cmd(const char *filename, char *argv [], int dowait);
int va_cmd(const char *cmd, int num, int dowait, ...);  //return 0:OK, other:fail
int va_cmd_no_echo(const char *cmd, int num, int dowait, ...);  //return 0:OK, other:fail
int call_cmd(const char *filename, int num, int dowait, ...);	//return 0:OK, other:fail
int write_to_mpoad(struct data_to_pass_st *);
int startDhcpc(char *inf, MIB_CE_ATM_VC_Tp pEntry);
void config_AddressMap(int action);
int startIP(char *inf, MIB_CE_ATM_VC_Tp pEntry, CHANNEL_MODE_T ipEncap);
#ifdef CONFIG_PPP
void stopPPP(void);
int startPPP(char *inf, MIB_CE_ATM_VC_Tp pEntry, char *qos, CHANNEL_MODE_T pppEncap);
int find_ppp_from_conf(char *pppif);
void write_to_pppd(struct data_to_pass_st *);
#endif
int _get_classification_mark(int entryNo, MIB_CE_IP_QOS_T *p);
int get_classification_mark(int entryNo);
int startConnection(MIB_CE_ATM_VC_Tp pEntry, int);
void stopConnection(MIB_CE_ATM_VC_Tp pEntry);
int stopLog(void);
int startLog(void);
#ifdef DEFAULT_GATEWAY_V2
int ifExistedDGW(void);
#endif
int msgProcess(struct mymsgbuf *qbuf);
#if !defined(CONFIG_MTD_NAND) && defined(CONFIG_BLK_DEV_INITRD)
static inline int flashdrv_filewrite(FILE * fp, int size, void *dstP)
{
	return 0;
}
#else
int flashdrv_filewrite(FILE * fp, int size, void *dstP);
#endif


#ifdef CONFIG_USER_IGMPPROXY
int startIgmproxy(void);
#ifdef CONFIG_IGMPPROXY_MULTIWAN
int setting_Igmproxy(void);
#endif
#endif
#ifdef CONFIG_IPV6
#ifdef CONFIG_USER_ECMH
int startMLDproxy(void);		// Mason Yu. MLD Proxy
#endif
#ifdef CONFIG_USER_RADVD
int setup_radvd_conf(void);
void init_radvd_conf_mib(void);   // Added by Mason Yu for p2r_test
#endif
#if defined(CONFIG_USER_DHCPV6_ISC_DHCP411) || defined(CONFIG_USER_RADVD)
extern const char RADVD_CONF[];
extern const char RADVD_PID[];
#endif
#ifdef CONFIG_USER_DOT1AG_UTILS
void arrange_dot1ag_table();
void startDot1ag();
#endif

int route_v6_cfg_modify(MIB_CE_IPV6_ROUTE_T *pRoute, int del);
#endif
int setupMacFilter(void);
#ifdef LAYER7_FILTER_SUPPORT
int setupAppFilter(void);
#endif
#ifdef PARENTAL_CTRL
int parent_ctrl_table_init(void);
int parent_ctrl_table_add(MIB_PARENT_CTRL_T *addedEntry);
int parent_ctrl_table_del(MIB_PARENT_CTRL_T *addedEntry);
int parent_ctrl_table_rule_update(void);
#endif
#ifdef DMZ
int setupDMZ(void);
#endif

#ifdef CONFIG_DEV_xDSL
char adsl_drv_get(unsigned int id, void *rValue, unsigned int len);
#ifdef CONFIG_VDSL
char dsl_msg_set_array(int msg, int *pval);
char dsl_msg_set(int msg, int val);
char dsl_msg_get_array(int msg, int *pval);
char dsl_msg_get(int msg, int *pval);
#endif /*CONFIG_VDSL*/

#define DEV_NAME_MAX_LEN 128

struct id_info
{
	int id;
	char dev_name[DEV_NAME_MAX_LEN];
	FILE *file_ptr;
};

struct id_info* id_info_search(char *dev_name);

typedef struct _xdsl_op_
{
	int id;
	char (*xdsl_drv_get)(unsigned int id, void *rValue, unsigned int len);
#ifdef CONFIG_VDSL
	char (*xdsl_msg_set_array)(int msg, int *pval);
	char (*xdsl_msg_get_array)(int msg, int *pval);
	char (*xdsl_msg_set)(int msg, int val);
	char (*xdsl_msg_get)(int msg, int *pval);
#endif /*CONFIG_VDSL*/
	int  (*xdsl_get_info)(int id, char *buf, int len);
} XDSL_OP;
XDSL_OP *xdsl_get_op(int id);
int setupDsl(void);

#if defined(CONFIG_USER_XDSL_SLAVE)
int setupSlvDsl(void);
#endif
#endif

int getLeasesInfo(const char *fname, DLG_INFO_Tp pInfo);
int getMIB2Str(unsigned int id, char *str);
int getSYS2Str(SYSID_T id, char *str);
int ifWanNum(const char *type); /* type="all", "rt", "br" */
#ifdef REMOTE_ACCESS_CTL
void remote_access_modify(MIB_CE_ACC_T accEntry, int enable);
void filter_set_remote_access(int enable);
#endif
#ifdef IP_ACL
void filter_set_acl(int enable);
#ifdef CONFIG_IPV6
void filter_set_v6_acl(int enable);
#endif
#endif
#ifdef NAT_CONN_LIMIT
int restart_connlimit(void);
void set_conn_limit(void);
#endif
#ifdef TCP_UDP_CONN_LIMIT
int restart_connlimit(void);
void set_conn_limit(void);
#endif
#ifdef DOS_SUPPORT
void DoS_syslog(int signum);
#endif
#ifdef URL_BLOCKING_SUPPORT
void filter_set_url(int enable);
int restart_urlblocking(void);
#ifdef URL_ALLOWING_SUPPORT
void set_url(int enable);
int restart_url(void);
#endif
#endif
void itfcfg(char *if_name, int up_flag);
#ifdef DOMAIN_BLOCKING_SUPPORT
void filter_set_domain(int enable);
int restart_domainBLK(void);
void patch_for_office365(void);
#endif
#if defined(CONFIG_USER_ROUTED_ROUTED) || defined(CONFIG_USER_ZEBRA_OSPFD_OSPFD)
int startRip(void);
#endif
#ifdef CONFIG_USER_ZEBRA_OSPFD_OSPFD
int startOspf(void);
#endif
#ifdef CONFIG_USER_DHCP_SERVER
#ifdef SUPPORT_DHCP_RESERVED_IPADDR
int clearDHCPReservedIPAddrByInstNum(unsigned int instnum);
#endif
int setupDhcpd(void);
int startDhcpRelay(void);
#endif

typedef struct {
	unsigned int	key;		/* magic key */

#define BOOT_IMAGE             0xB0010001
#define CONFIG_IMAGE           0xCF010002
#define APPLICATION_IMAGE      0xA0000003
#ifdef CONFIG_RTL8686
#define APPLICATION_UBOOT      	0xA0000103	/*uboot only*/
#define APPLICATION_UIMAGE      0xA0000203	/*uimage only*/
#define APPLICATION_ROOTFS      0xA0000403	/*rootfs only*/
#endif
#define BOOTPTABLE             0xB0AB0004


	unsigned int	address;	/* image loading DRAM address */
	unsigned int	length;		/* image length */
	unsigned int	entry;		/* starting point of program */
	unsigned short	chksum;		/* chksum of */

	unsigned char	type;
#define KEEPHEADER    0x01   /* set save header to flash */
#define FLASHIMAGE    0x02   /* flash image */
#define COMPRESSHEADER    0x04       /* compress header */
#define MULTIHEADER       0x08       /* multiple image header */
#define IMAGEMATCH        0x10       /* match image name before upgrade */


	unsigned char	   date[25];  /* sting format include 24 + null */
	unsigned char	   version[16];
	unsigned int  *flashp;  /* pointer to flash address */

} IMGHDR;

//ql_xu ---signature header
#define SIG_LEN			20
typedef struct {
	unsigned int sigLen;	//signature len
	unsigned char sigStr[SIG_LEN];	//signature content
	unsigned short chksum;	//chksum of imghdr and img
}SIGHDR;

struct wstatus_info {
	unsigned int ifIndex;
	char ifname[IFNAMSIZ];
	char devname[IFNAMSIZ];
	char ifDisplayName[IFNAMSIZ];
	unsigned int tvpi;
	unsigned int tvci;
	int cmode;
	char encaps[8];
	char protocol[10];
	char ipver;	// IPv4 or IPv6
	char ipAddr[20];
	char remoteIp[20];
	char *strStatus;
	char *strStatus_IPv6;
	char uptime[20];
	char totaluptime[20];
	char vpivci[12];
	int pppDoD;
	int itf_state;
	int link_state;
	unsigned int recordNum;
#if defined(CONFIG_LUNA)
	unsigned short vid;
#ifdef CONFIG_00R0
	unsigned char MacAddr[MAC_ADDR_LEN];
#endif
	char serviceType[30];
#endif
	
};

unsigned short ipchksum(unsigned char *ptr, int count, unsigned short resid);

#ifdef PORT_FORWARD_GENERAL
void clear_dynamic_port_fw(int (*upnp_delete_redirection)(unsigned short eport, const char * protocol));
int setupPortFW(void);
void portfw_modify( MIB_CE_PORT_FW_T *p, int del);
#endif
#ifdef TIME_ZONE
int startNTP(void);
int stopNTP(void);
#endif

#ifdef CONFIG_USER_MINIDLNA
void startMiniDLNA(void);
void stopMiniDLNA(void);
#endif

#ifdef IP_QOS
int setupUserIPQoSRule(int enable);
#endif
#if defined(IP_QOS) | defined(CONFIG_USER_IP_QOS_3)
int stopIPQ(void);
int setupIPQ(void);
#endif
#ifdef CONFIG_USER_IP_QOS_3
void take_qos_effect_v3(void);
#endif
/*ql:20081114 START: support GRED*/
#define UNDOWAIT 0
#define DOWAIT 1
#define MAX_SPACE_LEGNTH 1024

#define DOCMDINIT \
		char cmdargvs[MAX_SPACE_LEGNTH]={0};\
		int argvs_index=1;\
		char *_argvs[32];

#define DOCMDARGVS(cmd,dowait,format,args...) \
		argvs_index=1;\
		memset(cmdargvs,0,sizeof(cmdargvs));\
		memset(_argvs,0,sizeof(_argvs));\
		snprintf(cmdargvs,sizeof(cmdargvs),format , ##args);\
		fprintf(stderr,"%s %s\n",cmd,cmdargvs);\
		_argvs[argvs_index]=strtok(cmdargvs," ");\
		while(_argvs[argvs_index]){\
			_argvs[++argvs_index]=strtok(NULL," ");\
		}\
		do_cmd(cmd,_argvs,dowait);
/*ql:20081114 END*/

#ifdef CONFIG_XFRM
#define SETKEY_CONF "/tmp/setkey.conf"
#define RACOON_CONF "/tmp/racoon.conf"
#define RACOON_PID "/var/run/racoon.pid"
#define RACOON_LOG "/tmp/racoon.log"
#define PSK_FILE "/tmp/psk.txt"
#define CERT_FLOD "/var/config"
#define DHGROUP_INDEX(x)	((x >> 24) & 0xff)
#define ENCRYPT_INDEX(x)	((x >> 16) & 0xff)
#define AHAUTH_INDEX(x)	((x >> 8) & 0xff)
#define AUTH_INDEX(x)	(x & 0xff)
struct IPSEC_PROP_ST
{
    char valid;
	char name[MAX_NAME_LEN];
	unsigned int algorithm; //dhGroup|espEncryption|ahAuth|espAuth
};

void ipsec_take_effect(void);
extern struct IPSEC_PROP_ST ikeProps[];
extern char *curr_dhArray[];
extern char *curr_encryptAlgm[];
extern char *curr_authAlgm[];
#endif

#ifdef CONFIG_USER_L2TPD_LNS
int applyL2TP(MIB_L2TP_T *pentry, int enable, int l2tp_index);
void l2tp_take_effect(void);
#endif

#ifdef CONFIG_USER_PPTP_CLIENT_PPTP
#ifdef CONFIG_USER_PPTPD_PPTPD
void applyPptpAccount(MIB_VPN_ACCOUNT_T *pentry, int enable);
void pptpd_take_effect(void);
#endif
void applyPPtP(MIB_PPTP_T *pentry, int enable, int pptp_index);
void pptp_take_effect(void);
#endif
#ifdef CONFIG_USER_L2TPD_LNS
void applyL2tpAccount(MIB_VPN_ACCOUNT_T *pentry, int enable);
#endif
#if defined(CONFIG_USER_SNMPD_SNMPD_V2CTRAP) || defined(CONFIG_USER_SNMPD_SNMPD_V3)
int startSnmp(void);
int restart_snmp(int flag);
#endif
#if defined(CONFIG_USER_CWMP_TR069) || defined(APPLY_CHANGE)
void off_tr069(void);
#endif
#if defined(IP_ACL)
int checkACL(char *pMsg, int idx, unsigned char aclcap);
int restart_acl(void);
#endif
#if defined(CONFIG_USER_DNSMASQ_DNSMASQ) || defined(CONFIG_USER_DNSMASQ_DNSMASQ245)
int restart_dnsrelay(void); //Jenny
int delete_hosts(unsigned char *yiaddr);
#endif
int restart_dhcp(void);
int restart_lanip(void);
#ifdef CONFIG_USER_ROUTED_ROUTED
int delRipTable(unsigned int ifindex);
#endif
int delPPPoESession(unsigned int ifindex);
MIB_CE_ATM_VC_T *getATMVCEntryByIfIndex(unsigned int ifIndex, MIB_CE_ATM_VC_T *p);
int find_wanif_by_vlanid(unsigned short latvid, MIB_CE_ATM_VC_T* vc_Entry);
#ifdef _CWMP_MIB_ /*jiunming, for cwmp-tr069*/
#ifdef PORT_FORWARD_GENERAL
int delPortForwarding( unsigned int ifindex );
int updatePortForwarding( unsigned int old_id, unsigned int new_id );
#endif
unsigned int findMaxConDevInstNum(MEDIA_TYPE_T mType);
unsigned int findConDevInstNumByPVC(unsigned char vpi, unsigned short vci);
unsigned int findMaxPPPConInstNum(MEDIA_TYPE_T mType, unsigned int condev_inst);
unsigned int findMaxIPConInstNum(MEDIA_TYPE_T mType, unsigned int condev_inst);
/*start use_fun_call_for_wan_instnum*/
int resetWanInstNum(MIB_CE_ATM_VC_Tp entry);
int updateWanInstNum(MIB_CE_ATM_VC_Tp entry);
#define dumpWanInstNum(p, s) do{}while(0)
/*end use_fun_call_for_wan_instnum*/
#ifdef _PRMT_X_TELEFONICA_ES_DHCPOPTION_
int delDhcpcOption( unsigned int ifindex );
unsigned int findMaxDHCPOptionInstNum( unsigned int usedFor, unsigned int dhcpConSPInstNum);
int getDHCPOptionByOptInstNum( unsigned int dhcpOptNum, unsigned int dhcpSPNum, unsigned int usedFor, MIB_CE_DHCP_OPTION_T *p, unsigned int *id );
int getDHCPClientOptionByOptInstNum( unsigned int dhcpOptNum, unsigned int ifIndex, unsigned int usedFor, MIB_CE_DHCP_OPTION_T *p, unsigned int *id );
unsigned int findMaxDHCPClientOptionInstNum(int usedFor, unsigned int ifIndex);
unsigned int findDHCPOptionNum(int usedFor, unsigned int ifIndex);
unsigned int findMaxDHCPReqOptionOrder(unsigned int ifIndex);
unsigned int findMaxDHCPConSPInsNum(void );
unsigned int findMaxDHCPConSPOrder(void );
int getDHCPConSPByInstNum( unsigned int dhcpspNum,  DHCPS_SERVING_POOL_T *p, unsigned int *id );
void clearOptTbl(unsigned int instnum);
unsigned int getSPDHCPOptEntryNum(unsigned int usedFor, unsigned int instnum);
int getSPDHCPRsvOptEntryByCode(unsigned int instnum, unsigned char optCode, MIB_CE_DHCP_OPTION_T *optEntry ,int *id);
void initSPDHCPOptEntry(DHCPS_SERVING_POOL_T *p);
#endif
#if defined(IP_QOS) || defined(NEW_IP_QOS_SUPPORT) || defined(CONFIG_USER_IP_QOS_3)
unsigned int findUnusedQueueInstNum(void);
unsigned int getQoSQueueNum(void);
#endif
MIB_CE_ATM_VC_T *getATMVCByInstNum( unsigned int devnum, unsigned int ipnum, unsigned int pppnum, MIB_CE_ATM_VC_T *p, unsigned int *chainid );
int startCWMP(void);
int getOUIfromMAC(char* oui);
int set_endpoint(char *newurl, char *acsurl); //star: remove "http://" from acs url string
#if defined(IP_QOS) || defined(NEW_IP_QOS_SUPPORT)
/*star:20100305 START add qos rule to set tr069 packets to the first priority queue*/
void setQosfortr069(int mode, char *urlvalue);
void setTr069QosFlag(int var);
int getTr069QosFlag(void);
#endif
void storeOldACS(void);
int getOldACS(char *acsurl);
#endif //_CWMP_MIB_

int restart_ddns(void);
int getDisplayWanName(MIB_CE_ATM_VC_T *pEntry, char* name);
int getWanEntrybyindex(MIB_CE_ATM_VC_T *pEntry, unsigned int ifIndex);
int getWanEntrybyMedia(MIB_CE_ATM_VC_T *pEntry, MEDIA_TYPE_T mType);
unsigned int getWanIfMapbyMedia(MEDIA_TYPE_T mType);
int isValidMedia(unsigned int ifIndex);
unsigned int if_find_index(int cmode, unsigned int map);

int setWanName(char *str, int applicationtype);
int generateWanName(MIB_CE_ATM_VC_T * entry, char *wanname);
int getWanName(MIB_CE_ATM_VC_T * pEntry, char *name);

int create_icmp_socket(void);
int in_cksum(unsigned short *buf, int sz);
int utilping(char *str);
int defaultGWAddr(char *gwaddr);
int pdnsAddr(char *dnsaddr);
int getATMEntrybyVPIVCIUsrPswd(MIB_CE_ATM_VC_T* Entry, int vpi, int vci, char* username, char* password, char* ifname);

int getNameServers(char *buf);
int setNameServers(char *buf);
#ifdef ACCOUNT_CONFIG
int getAccPriv(char *user);
#endif
int isValidIpAddr(char *ipAddr);
int isValidHostID(char *ip, char *mask);
int isValidNetmask(char *mask, int checkbyte);
int isSameSubnet(char *ipAddr1, char *ipAddr2, char *mask);
int isValidMacString(char *MacStr);
int isValidMacAddr(unsigned char *macAddr);
#if defined(CONFIG_PON_LINKCHANGE_EVENT) || defined(CONFIG_00R0)
int doReleaseWanConneciton(void);
#endif

typedef struct pppoe_s_info {
	unsigned int	uifno;			/* index of device */
	unsigned short session;				/* Identifier for our session */
	struct sockaddr_ll remote;
} PPPOE_SESSION_INFO;

struct ppp_policy_route_info {
	u_char	if_name[IFNAMSIZ];
	u_long	hisip;
	u_long	myip;
	u_long	primary_dns;
	u_long	second_dns;
};
extern int set_ppp_source_route(struct ppp_policy_route_info *ppp_info);
extern int set_pppv6_source_route(MIB_CE_ATM_VC_T *pEntry, char *ifname, struct in6_addr * ip6addr);
extern int set_ipv6_static_source_route(MIB_CE_ATM_VC_T *pEntry, char *ifname, struct in6_addr * ip6addr);

#ifdef QOS_SPEED_LIMIT_SUPPORT
int mib_qos_speed_limit_existed(int speed,int prior);
#endif
int restart_ethernet(int instnum);
#ifdef ELAN_LINK_MODE
int setupLinkMode(void);
#endif

#ifdef _PRMT_TR143_
struct TR143_UDPEchoConfig
{
	unsigned char	Enable;
	unsigned char	EchoPlusEnabled;
	unsigned short	UDPPort;
	unsigned char	Interface[IFNAMSIZ];
	unsigned char	SourceIPAddress[4];
};
void UDPEchoConfigSave(struct TR143_UDPEchoConfig *p);
int UDPEchoConfigStart( struct TR143_UDPEchoConfig *p );
int UDPEchoConfigStop( struct TR143_UDPEchoConfig *p );
#endif //_PRMT_TR143_

/*ping_zhang:20081217 START:patch from telefonica branch to support WT-107*/
#ifdef _PRMT_WT107_
enum eTStatus
{
	eTStatusDisabled,
	eTStatusUnsynchronized,
	eTStatusSynchronized,
	eTStatusErrorFailed,/*Error_FailedToSynchronize*/
	eTStatusError
};
#endif
/*ping_zhang:20081217 END*/

//void pppoe_session_update(void *p);
//void save_pppoe_sessionid(void *p);
// Added by Magician for external use
int deleteConnection(int configAll, MIB_CE_ATM_VC_Tp pEntry);
#ifdef CONFIG_DEV_xDSL
int RegisterPVCnumber(void);
#endif
int startWan(int configAll, MIB_CE_ATM_VC_Tp pEntry);
#define CONFIGONE	0
#define CONFIGALL 	1
#define CONFIGCWMP 2

struct	callout_s {
    struct timeval	c_time;		/* time at which to call routine */
    void		*c_arg;		/* argument to routine */
    void		(*c_func) __P((void *)); /* routine */
    struct		callout_s *c_next;
};

void timeout_utility(void (*func) __P((void *)), void *arg, int time, struct callout_s *handle);
void untimeout_utility(struct callout_s *handle);
// Mason Yu
#define WEB_REDIRECT_BY_MAC_INTERVAL	12*60*60	/* Polling DHCP release table every 12 hours */
#define TIMEOUT_F(fun, arg1, arg2, handle) 	timeout_utility(fun,arg1,arg2, &handle)
#define UNTIMEOUT_F(fun, arg, handle)		untimeout_utility(&handle)
#ifdef WEB_REDIRECT_BY_MAC
extern struct callout_s landingPage_ch;
void clearLandingPageRule(void *dummy);
#endif
#ifdef AUTO_DETECT_DMZ
extern struct callout_s autoDMZ_ch;
#endif

// Mason Yu. Timer for auto search PVC
#ifdef CONFIG_DEV_xDSL
#if defined(AUTO_PVC_SEARCH_TR068_OAMPING) || defined(AUTO_PVC_SEARCH_PURE_OAMPING) || defined(AUTO_PVC_SEARCH_AUTOHUNT)
extern struct callout_s autoSearchPVC_ch;
int startAutoSearchPVC(void);
#define INTERVAL_AUTOPVC 10//45
#define COUNT_AUTOPVC	0//4 If COUNT_AUTOPVC is 0, the AutoPvcSearch will repeat until it find the PVC.
#endif
#endif
int pppdbg_get(int unit);
#ifdef CONFIG_ATM_CLIP
void sendAtmInARPRep(unsigned char update);
#endif

void poll_autoDMZ(void *dummy);
void startSNAT(void);
void restartWAN(int configAll, MIB_CE_ATM_VC_Tp pEntry);
void resolveServiceDependency(unsigned int idx);
#ifdef IP_PASSTHROUGH
void restartIPPT(struct ippt_para para);
#endif
#ifdef DOS_SUPPORT
void setup_dos_protection(void);
#endif

#if defined(CONFIG_00R0) && defined(CONFIG_RTK_L34_ENABLE)
void voip_set_rg_1p_tag(void);
#endif

#ifdef COMMIT_IMMEDIATELY
void Commit(void);
#endif

void setup_ipforwarding(int enable);
#ifdef ROUTING
int route_cfg_modify(MIB_CE_IP_ROUTE_T *, int, int entryID);

int checkRoute(MIB_CE_IP_ROUTE_T, int);
void route_ppp_ifup(unsigned long pppGW, char *ifname);
int delRoutingTable( unsigned int ifindex );
int updateRoutingTable( unsigned int old_id, unsigned int new_id );
void addStaticRoute(void);
void deleteStaticRoute(void);
#endif
char *ifGetName(int, char *, unsigned int);
int getIfIndexByName(char *pIfname);
int getNameByIP(char *ip, char *buffer, unsigned int len);

/* WAPI */
#define WAPI_TMP_CERT "/var/tmp/tmp.cert"
#define WAPI_AP_CERT "/var/myca/ap.cert"
#define WAPI_CA_CERT "/var/myca/CA.cert"
#define WAPI_CA4AP_CERT "/var/myca/ca4ap.cert"
#define WAPI_AP_CERT_SAVE "/var/config/ap.cert"
#define WAPI_CA_CERT_SAVE "/var/config/CA.cert"
#define WAPI_CA4AP_CERT_SAVE "/var/config/ca4ap.cert"
void wapi_cert_link_one(const char *name, const char *lnname);

#if defined(CONFIG_ETHWAN) || defined(CONFIG_PTMWAN)
#ifndef CONFIG_RTL8672NIC
#define ETHWAN_PORT 0//in virtual view
#define PTMWAN_PORT 5//in virtual view
#else
#define ETHWAN_PORT 3
#endif
int init_ethwan_config(MIB_CE_ATM_VC_T *pEntry);
#endif

#ifdef CONFIG_USER_WT_146
int wt146_dbglog_get(unsigned char *ifname);
void wt146_create_wan(MIB_CE_ATM_VC_Tp pEntry, int reset_bfd_only );
void wt146_del_wan(MIB_CE_ATM_VC_Tp pEntry);
void wt146_set_default_config(MIB_CE_ATM_VC_Tp pEntry);
void wt146_copy_config(MIB_CE_ATM_VC_Tp pto, MIB_CE_ATM_VC_Tp pfrom);
#endif //CONFIG_USER_WT_146

// Magician: This function is for checking the validation of whole config file.
int checkConfigFile(const char *config_file);

// Magician: This function can show memory usage change on the fly.
#if DEBUG_MEMORY_CHANGE
extern char last_memsize[128], last_file[32], last_func[32]; // Use to indicate last position where you put ShowMemChange().
extern int last_line;  // Use to indicate last position where you put ShowMemChange().
int ShowMemChange(char *file, char *func, int line);
#endif

#ifndef CONFIG_RTL8672NIC
void setupIPQoSflag(int flag);
#endif

#if defined(IP_PORT_FILTER) || defined(MAC_FILTER)
int restart_IPFilter_DMZ_MACFilter(void);
#endif
void cleanAllFirewallRule(void);
int setupFirewall(void);
#ifdef CONFIG_IP_NF_ALG_ONOFF
int setupAlgOnOff(void);
#endif
#ifdef _SUPPORT_CAPTIVEPORTAL_PROFILE_
int start_captiveportal(void);
int stop_captiveportal(void);
#endif

//Kevin:Check whether to enable/disable upstream ip fastpath
void UpdateIpFastpathStatus(void);

#define BIT_IS_SET(a, no)  (a & (0x1 << no))
#define AUG_DBG
#ifdef AUG_DBG
#define AUG_PRT(fmt,args...)  printf("\033[1;33;46m<%s %d %s> \033[m"fmt, __FILE__, __LINE__, __func__ , ##args)
#else
#define AUG_PRT(fmt,args...)  do{}while(0)
#endif
#ifdef NEW_PORTMAPPING
//define it when debug newportmapping
#define NEWPORTMAPPING_DBG
#ifdef NEWPORTMAPPING_DBG
#define AUG_PRT(fmt,args...)  printf("\033[1;33;46m<%s %d %s> \033[m"fmt, __FILE__, __LINE__, __func__ , ##args)
#else
#define AUG_PRT(fmt,args...)  do{}while(0)
#endif

#define PMAP_DEFAULT_TBLID	252
struct pmap_s {
	int valid;
	unsigned int ifIndex;	// resv | media | ppp | vc
	unsigned int applicationtype;
	unsigned short itfGroup;
	unsigned short fgroup;
};

extern struct pmap_s pmap_list[MAX_VC_NUM];
int get_pmap_fgroup(struct pmap_s *pmap_p, int num);
int check_itfGroup(MIB_CE_ATM_VC_Tp pEntry, MIB_CE_ATM_VC_Tp pOldEntry);
int pmap_reset_ip_route(MIB_CE_ATM_VC_Tp pEntry);
int exec_portmp(void);
void setupnewEth2pvc(void);

int caculate_tblid(uint32_t ifid);

void setup_wan_pmap_lanmember(MEDIA_TYPE_T mType, unsigned int Index);


#if defined(CONFIG_USER_PPTP_CLIENT_PPTP) || defined(CONFIG_USER_L2TPD_L2TPD)
void modPolicyRouteTable(const char *pptp_ifname, struct in_addr *real_addr);
#ifdef CONFIG_IPV6_VPN
void modIPv6PolicyRouteTable(const char *pptp_ifname, struct in6_addr *real_addr);
#endif
#endif
#endif

#ifdef CONFIG_HWNAT
void setup_hwnat_eth_member(int port, int mbr, char enable);
#ifdef CONFIG_PTMWAN
void setup_hwnat_ptm_member(int port, int mbr, char enable);
#endif
#endif
#if defined(CONFIG_LUNA) && defined(CONFIG_RTK_L34_ENABLE)
int Init_RTK_RG_Device(void);
int check_RG_static_route(void);
int check_RG_static_route_PPP(MIB_CE_ATM_VC_T *vc_entry);
#ifdef CONFIG_00R0
int isRouteExist(struct in_addr ipddr, struct in_addr netmask, struct in_addr gwaddr);
#endif
int rg_add_route(MIB_CE_IP_ROUTE_T *entry, int entryID);
#endif

struct net_device_stats
{
	unsigned long	rx_packets;		/* total packets received	*/
	unsigned long	tx_packets;		/* total packets transmitted	*/
	unsigned long	rx_bytes;		/* total bytes received 	*/
	unsigned long	tx_bytes;		/* total bytes transmitted	*/
	unsigned long	rx_errors;		/* bad packets received		*/
	unsigned long	tx_errors;		/* packet transmit problems	*/
	unsigned long	rx_dropped;		/* no space in linux buffers	*/
	unsigned long	tx_dropped;		/* no space available in linux	*/
	unsigned long	multicast;		/* multicast packets received	*/
	unsigned long	collisions;

	/* detailed rx_errors: */
	unsigned long	rx_length_errors;
	unsigned long	rx_over_errors;		/* receiver ring buff overflow	*/
	unsigned long	rx_crc_errors;		/* recved pkt with crc error	*/
	unsigned long	rx_frame_errors;	/* recv'd frame alignment error */
	unsigned long	rx_fifo_errors;		/* recv'r fifo overrun		*/
	unsigned long	rx_missed_errors;	/* receiver missed packet	*/

	/* detailed tx_errors */
	unsigned long	tx_aborted_errors;
	unsigned long	tx_carrier_errors;
	unsigned long	tx_fifo_errors;
	unsigned long	tx_heartbeat_errors;
	unsigned long	tx_window_errors;

	/* for cslip etc */
	unsigned long	rx_compressed;
	unsigned long	tx_compressed;
};

/*
 *	Refer to linux/ethtool.h
 */
struct net_link_info
{
	unsigned long	supported;	/* Features this interface supports: ports, link modes, auto-negotiation */
	unsigned long	advertising;	/* Features this interface advertises: link modes, pause frame use, auto-negotiation */
	unsigned short	speed;		/* The forced speed, 10Mb, 100Mb, gigabit */
	unsigned char	duplex;		/* Duplex, half or full */
	unsigned char	phy_address;
	unsigned char	transceiver;	/* Which transceiver to use */
	unsigned char	autoneg;	/* Enable or disable autonegotiation */
};

#define _PATH_PROCNET_DEV "/proc/net/dev"
int list_net_device_with_flags(short flags, int nr_names,
				char (* const names)[IFNAMSIZ]);
int get_net_device_stats(const char *ifname, struct net_device_stats *nds);
enum {
	RX_OCTETS,
	RX_DISCARDS,
	RX_UCAST_PACKETS,
	RX_MCAST_PACKETS,
	RX_BCAST_PACKETS,
	TX_OCTETS,
	TX_DISCARDS,
	TX_UCAST_PACKETS,
	TX_MCAST_PACKETS,
	TX_BCAST_PACKETS,
};
struct ethtool_stats * ethtool_gstats(const char *ifname);
int get_net_link_status(const char *ifname);
int get_net_link_info(const char *ifname, struct net_link_info *info);
int get_dev_ShapingRate(const char *ifname);
int set_dev_ShapingRate(const char *ifname, int rate);
int get_dev_ShapingBurstSize(const char *ifname);
int set_dev_ShapingBurstSize(const char *ifname, unsigned int bsize);

#define WAN_MODE GetWanMode()
enum e_wan_mode {MODE_ATM = 1, MODE_Ethernet = 2, MODE_PTM = 4, MODE_BOND = 8, MODE_Wlan = 0x10};
int GetWanMode(void);
int isInterfaceMatch(unsigned int);
int isDefaultRouteWan(MIB_CE_ATM_VC_Tp pEntry);
#if defined(CONFIG_USER_XDSL_SLAVE)
#define WAN_MODE_MASK (GET_MODE_ATM|GET_MODE_ETHWAN|GET_MODE_PTM|GET_MODE_BOND|GET_MODE_WLAN)
#else
#define WAN_MODE_MASK (GET_MODE_ATM|GET_MODE_ETHWAN|GET_MODE_PTM|GET_MODE_WLAN)
#endif

#ifdef CONFIG_DEV_xDSL
#define GET_MODE_ATM 0x1
#else
#define GET_MODE_ATM 0x0
#endif

#ifdef CONFIG_ETHWAN
#define GET_MODE_ETHWAN 0x2
#else
#define GET_MODE_ETHWAN 0x0
#endif

#ifdef CONFIG_PTMWAN
#define GET_MODE_PTM 0x4
#else
#define GET_MODE_PTM 0
#endif

#ifdef CONFIG_USER_XDSL_SLAVE
#define GET_MODE_BOND 0x8
#else
#define GET_MODE_BOND 0
#endif

#ifdef WLAN_WISP
#define GET_MODE_WLAN 0x10
#else
#define GET_MODE_WLAN 0
#endif

int reset_cs_to_default(int flag);

#ifdef CONFIG_USER_SAMBA
#ifdef CONFIG_MULTI_SMBD_ACCOUNT
#define SMB_CONF_FILE "/var/smb.conf"
#define SMB_PWD_FILE "/var/samba/smbpasswd"
int addSmbPwd(char *username, char *passwd);
void initSmbPwd(void);
int updateSambaCfg(unsigned char sec_enable);
int initSamba(void);
#endif
int startSamba(void);
int stopSamba(void);
#endif // CONFIG_USER_SAMBA

#ifdef CONFIG_TR_064
#define TR064_STATUS GetTR064Status()
int GetTR064Status(void);
#endif

// Mason Yu. Specify IP Address
struct ddns_info {    				/* Used as argument to ddnsC() */
	int		ipversion;        		/* IPVersion . 1:IPv4, 2:IPv6, 3:IPv4 and IPv6 */
	char 	ifname[IFNAMSIZ];        /* Interface name */
};

#ifdef CONFIG_USER_VLAN_ON_LAN
int setup_VLANonLAN(int mode);
#endif
#ifdef CONFIG_USER_BRIDGE_GROUPING
int setup_bridge_grouping(int mode);
#ifdef CONFIG_RTK_L34_ENABLE // Rostelecom, Port Binding function
#ifdef CONFIG_00R0
void reset_VLANMapping(void);
void setup_VLANMapping(int ifidx, int enable);
int setVLANByGroupnum(int groupnum, int enable, int vlan);
#endif
void set_port_binding_rule(int enable);
int set_port_binding_mask(unsigned int *wanlist);
int rg_set_port_binding_mask(unsigned int set_wanlist);
#define MAX_PAIR 1 // max mapping pair per LAN interface(1~4)

struct vlan_pair {
	unsigned short vid_a;
	unsigned short vid_b;
	unsigned short rg_vbind_entryID;
};
#endif
#endif
int update_hosts(char *, struct addrinfo *);
struct addrinfo *hostname_to_ip(char *, IP_PROTOCOL);

#define PMAP_VC_START	1
#define PMAP_PPP_START	0x10
#define PMAP_NAS_START 0x20
#define PMAP_NAS_PPP_START 0x30
#ifdef CONFIG_PTMWAN
#define PMAP_PTM_START 0x40
#define PMAP_PTM_PPP_START 0x50
#endif
#define ITF_SOURCE_ROUTE_VC_START	0x60
#define ITF_SOURCE_ROUTE_NAS_START	0x70
#define ITF_SOURCE_ROUTE_PTM_START	0x80
#define ITF_SOURCE_ROUTE_PPP_START	0x90

#ifdef CONFIG_REMOTE_CONFIGD
#ifdef CONFIG_SPC
#include <unistd.h>

#define PF_SPC          AF_SPC
#define AF_SPC          28      /* Slow Protocol Channel        */
#endif
#endif

#ifdef DOS_SUPPORT
#define DOS_ENABLE		0x01
#define SYSFLOODSYN		0x02
#define SYSFLOODFIN		0x04
#define SYSFLOODUDP		0x08
#define SYSFLOODICMP	0x10
#define IPFLOODSYN		0x20
#define IPFLOODFIN		0x40
#define IPFLOODUDP		0x80
#define IPFLOODICMP		0x100
#define TCPUDPPORTSCAN	0x200
#define ICMPSMURFENABLED	0x400
#define IPLANDENABLED		0x800
#define IPSPOOFENABLED		0x1000
#define IPTEARDROPENABLED	0x2000
#define PINGOFDEATHENABLED	0x4000
#define TCPSCANENABLED		0x8000
#define TCPSynWithDataEnabled	0x10000
#define UDPBombEnabled			0x20000
#define UDPEchoChargenEnabled	0x40000
#define sourceIPblock		0x400000
#endif

#ifdef CONFIG_USB_SUPPORT
struct usb_info{
                char disk_type[64];
                char disk_status[64];
                char disk_fs[64];
                unsigned long disk_used;
                unsigned long disk_available;
                char disk_mounton[256];
};
void getUSBDeviceInfo(int *disk_sum,struct usb_info* disk1,struct usb_info *disk2);
#endif// end of CONFIG_USB_SUPPORT

int check_user_is_registered(void);

#if defined(CONFIG_IPV6)
/************************************************
* Propose: delOrgLanLinklocalIPv6Address
*
*    delete the original Link local IPv6 address
*      e.q: ifconfig br0 del fe80::2e0:4cff:fe86:5338/64 >/dev/null 2>&1
*
*    When modify the function, please also modify _delOrgLanLinklocalIPv6Address()
*    in src/linux/msgparser.c
* Parameter:
*	None
* Return:
*     None
* Author:
*     Alan
*************************************************/
void delOrgLanLinklocalIPv6Address(void);

/************************************************
* Propose: setLanLinkLocalIPv6Address()
*    set the Link local IPv6 address
*      e.q: ifconfig br0 add fe80::1/64 >/dev/null 2>&1
*
*    When modify the function, please also modify _setLanLinkLocalIPv6Address()
*    in src/linux/msgparser.c
* Parameter:
*	None
* Return:
*     None
* Author:
*     Alan
*************************************************/
void setLanLinkLocalIPv6Address(void);


/************************************************
* Propose: radvdRunningMode()
*    Get radvd running mode
* Parameter:
*	None
* Return:
*      0  :  RADVD_RUNNING_MODE_DISABLE
*      1  :  RADVD_RUNNING_MODE_STATIC
*      2  :  RADVD_RUNNING_MODE_DELEGATION
* Author:
*     Alan
*************************************************/
int radvdRunningMode(void);

/************************************************
* Propose: setLinklocalIPv6Address
*
*    set thel Link local IPv6 address
*      e.q: ifconfig br0 add fe80::2e0:4cff:fe86:5338/64 >/dev/null 2>&1
*
* Parameter:
*	char* ifname              interface name
* Return:
*     None
* Author:
*     Alan
*************************************************/
void setLinklocalIPv6Address(char* ifname);

#endif/*CONFIG_IPV6*/

/************************************************
* Propose: checkProcess()
*    Check process exist or not
* Parameter:
*	char* pidfile      pid file path
* Return:
*      1  :  exist
*      0  :  not exist
*      -1: parameter error
* Author:
*     Alan
*************************************************/
int checkProcess(char* pname);

#define WAIT_INFINITE 0 
/************************************************
* Propose: waitProcessTerminate()
*    wait process until process does not exist
* Parameter:
*	char* pidfile                    pid file path
*     unsigned int timeout        0: wait infinite, otherise wait timeout miliseconds(mutiple of 10)
* Return:
*      0  : success
*      -1: parameter error
* Author:
*     Alan
*************************************************/
int waitProcessTerminate(char* pidfile, unsigned int timeout);

/************************************************
* Propose: getMacAddr
*
*    get MAC address
*
* Parameter:
*	char* ifname                     interface name
*     unsigned char* macaddr      mac addr
* Return:
*     -1 : fail
*       0 : success
* Author:
*     Alan
*************************************************/
int getMacAddr(char* ifname, unsigned char* macaddr);

#ifdef CONFIG_00R0
/* bootloader parameters, Iulian Wu*/
#define BOOTLOADER_UBOOT_HEADER "version"
#define BOOTLOADER_UBOOT_CRC "bootloader_crc"
#define BOOTLOADER_SW_ACTIVE 	"sw_active"
#define BOOTLOADER_SW_VERSION 	"sw_version"
#define BOOTLOADER_SW_CRC 		"sw_crc"

#ifdef CONFIG_RTK_HOST_SPEEDUP
int add_host_speedup(struct in_addr srcip, unsigned short sport, struct in_addr dstip, unsigned short dport);
int del_host_speedup(struct in_addr srcip, unsigned short sport, struct in_addr dstip, unsigned short dport);
#endif /*CONFIG_RTK_HOST_SPEEDUP*/
void reSync_reStartVoIP(void);
int checkAndModifyWanServiceType(int applicationtype, int change_type, int index);
#endif

int check_vlan_conflict(MIB_CE_ATM_VC_T *pEntry, int idx, char *err_msg);
void compact_reqoption_order(unsigned int ifIndex);

/* shell type for config_xmlconfig.sh
 * Added by Davian
 */
#ifdef CONFIG_USER_XMLCONFIG
//const char *shell_name;
#endif

int mib_to_string(char *string, const void *mib, TYPE_T type, int size);
int string_to_mib(void *mib, const char *string, TYPE_T type, int size);
int _load_xml_file(const char *loadfile, CONFIG_DATA_T cnf_type, unsigned char flag);
int _save_xml_file(const char *savefile, CONFIG_DATA_T cnf_type, unsigned char flag);
void print_chain_member(FILE *fp, char *format_str, mib_chain_member_entry_T * desc, void *addr, int depth);

int before_upload(const char *fname);
int after_download(const char *fname);

#define CWMP_START_WAN_LIST "/var/cwmp_start_wan_list"

#if defined(CONFIG_RTL8686) || defined(CONFIG_RTL9607C)
#define PROC_UNI_CAPABILITY "/proc/realtek/uni_capability"
void setupUniPortCapability(void);
#endif

int lock_file_by_flock(const char *filename, int wait);
int unlock_file_by_flock(int lockfd);

struct v_pair {
	unsigned short vid_a;
	unsigned short vid_b;
#ifdef CONFIG_RTK_L34_ENABLE
	unsigned short rg_vbind_entryID;
#endif
};

#if defined(CONFIG_RTL9600_SERIES) && defined(CONFIG_RTK_L34_ENABLE)
int checkVlanConfictWithMib(int internalVid, int mibId);
int checkVlanConfictWithInternal(int internalVid, int mibId);
void checkVlanConfict(void);
#endif

int isIGMPSnoopingEnabled(void);
int isMLDSnoopingEnabled(void);
int isIgmproxyEnabled(void);
int isMLDroxyEnabled(void);

#endif // INCLUDE_UTILITY_H
