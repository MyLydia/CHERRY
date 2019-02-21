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
#define ALIASNAME_PTM  "ptm"
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

#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
#define INTERFACE_UPTIME_FILE "/var/interface/uptime/"
#endif
#define RTL_DEV_NAME_NUM(name,num)	name#num

#define ALIASNAME_NAS0  RTL_DEV_NAME_NUM(ALIASNAME_NAS,0)//"nas0"
#define ALIASNAME_PTM0  RTL_DEV_NAME_NUM(ALIASNAME_PTM,0)//"ptm0"

#define ALIASNAME_DSL0  RTL_DEV_NAME_NUM(ALIASNAME_DSL,0)//dsl0
#define ALIASNAME_ELAN0  RTL_DEV_NAME_NUM(ALIASNAME_ELAN_PREFIX,2)
#define ALIASNAME_ELAN1  RTL_DEV_NAME_NUM(ALIASNAME_ELAN_PREFIX,3)
#define ALIASNAME_ELAN2  RTL_DEV_NAME_NUM(ALIASNAME_ELAN_PREFIX,4)
#define ALIASNAME_ELAN3  RTL_DEV_NAME_NUM(ALIASNAME_ELAN_PREFIX,5)

#define ALIASNAME_BR0   RTL_DEV_NAME_NUM(ALIASNAME_BR,0)//"br0"
#define ALIASNAME_WLAN0  RTL_DEV_NAME_NUM(ALIASNAME_WLAN,0)//"wlan0"

#define ALIASNAME_VAP   "-vap" //must include '-' at fast
#define ALIASNAME_WLAN0_VAP  RTL_DEV_NAME_NUM(ALIASNAME_WLAN0,-vap)//"wlan0-vap"

#define ALIASNAME_WLAN0_VAP0  RTL_DEV_NAME_NUM(ALIASNAME_WLAN0_VAP,0)//"wlan0-vap0"
#define ALIASNAME_WLAN0_VAP1  RTL_DEV_NAME_NUM(ALIASNAME_WLAN0_VAP,1)//"wlan0-vap1"
#define ALIASNAME_WLAN0_VAP2  RTL_DEV_NAME_NUM(ALIASNAME_WLAN0_VAP,2)//"wlan0-vap2"
#define ALIASNAME_WLAN0_VAP3  RTL_DEV_NAME_NUM(ALIASNAME_WLAN0_VAP,3)//"wlan0-vap3"

#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
#define WAN_VOIP_VOICE_NAME "VOIP"
#define WAN_VOIP_VOICE_NAME_CONN "VOIP_"
#define WAN_TR069_VOIP_VOICE_NAME "TR069_VOIP"
#define WAN_VOIP_VOICE_INTERNET_NAME "VOIP_INTERNET"
#define WAN_TR069_VOIP_VOICE_INTERNET_NAME "TR069_VOIP_INTERNET"
#ifdef CONFIG_SUPPORT_IPTV_APPLICATIONTYPE
#define WAN_IPTV_NAME "IPTV"
#endif
#else
#define WAN_VOIP_VOICE_NAME "VOICE"
#define WAN_VOIP_VOICE_NAME_CONN "VOICE_"
#define WAN_TR069_VOIP_VOICE_NAME "TR069_VOICE"
#define WAN_VOIP_VOICE_INTERNET_NAME "VOICE_INTERNET"
#define WAN_TR069_VOIP_VOICE_INTERNET_NAME "TR069_VOICE_INTERNET"
#endif

#include <sys/socket.h>
#include <linux/if.h>
#include <stdarg.h>
#include <stdio.h>
#include <net/route.h>
#include <netdb.h>
#include <dirent.h>
#include <netpacket/packet.h>

#include "mib.h"
#include "sysconfig.h"
#include "subr_dhcpv6.h"
#include "options.h"
#ifdef TIME_ZONE
#include "tz.h"
#endif

#define SYNC_OMCI_WAN_INFO_ALL 1
#define SYNC_OMCI_WAN_INFO_FORWARD 0

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
// kaotest --- temporary used, should be removed after new toolchain(for IPv6) is ready.
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
// kaotest -- end of temporary used

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

#define BUF_SIZE		512
#define MAX_POE_PER_VC		5
struct data_to_pass_st {
	int	id;
	char data[BUF_SIZE];
};
#ifdef CONFIG_CT_AWIFI_JITUAN_SMARTWIFI
struct default_server_setting {
	int	linenum;
	char data[BUF_SIZE];
	struct default_server_setting *next;
};

extern struct default_server_setting *gServerSetting;

#define CHAIN_MARK_MASK "0xfff"
#define AWIFI_LAN_START_NUM		2
#define AWIFI_LAN_END_NUM		6

typedef enum _t_fw_marks {
    FW_MARK_NONE = 0, /**< @brief No mark set. */
    FW_MARK_PROBATION = 1, /**< @brief The client is in probation period and must be authenticated 
			    @todo: VERIFY THAT THIS IS ACCURATE*/
    FW_MARK_KNOWN = 2,  /**< @brief The client is known to the firewall */
    FW_MARK_AUTH_IS_DOWN = 253, /**< @brief The auth servers are down */
    FW_MARK_LOCKED = 254 /**< @brief The client has been locked out */
} t_fw_marks;

#endif

// Mason Yu. 2630-e8b
#ifdef TIME_ZONE
#define SNTP_DISABLED 0
#define SNTP_ENABLED 1
#endif

#ifdef CONFIG_CMCC_OSGIMANAGE
#define OSGIMANAGE_DISABLED 0
#define OSGIMANAGE_ENABLED 1
#endif

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

#ifdef VIRTUAL_SERVER_SUPPORT
#define VIRTUAL_SERVER_DELETE 0
#define VIRTUAL_SERVER_ADD  1
#define VIRTUAL_SERVER_ACTION_APPEND(type) (type==VIRTUAL_SERVER_ADD)?"-A":"-D"
#define VIRTUAL_SERVER_ACTION_INSERT(type)   (type==VIRTUAL_SERVER_ADD)?"-I":"-D"
#define VIRTUAL_SERVER_ACTION_PARAM_INT(type,d) (type==VIRTUAL_SERVER_ADD)?int2str(d):""

int setupVtlsvr(int type);
#endif

void setup_mac_addr(unsigned char *macAddr, int index);
void convertMacFormat(char *str, unsigned char *mac);
#ifdef CONFIG_CMCC_FORWARD_RULE_SUPPORT
#define CMCC_FORWARDRULE_DELETE 0
#define CMCC_FORWARDRULE_ADD  1
#define CMCC_FORWARDRULE_MOD  2
#define CMCC_FORWARDRULE_ACTION_APPEND(type) (type==CMCC_FORWARDRULE_ADD)?"-A":"-D"
#define CMCC_FORWARDRULE_ACTION_INSERT(type)   (type==CMCC_FORWARDRULE_ADD)?"-I":"-D"
#define CMCC_FORWARDRULE_ACTION_PARAM_INT(type,d) (type==CMCC_FORWARDRULE_ADD)?int2str(d):""

int setupCmccForwardRule(int type);
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
#if (defined( ITF_GROUP_1P) && defined(ITF_GROUP)) || defined(NEW_PORTMAPPING)
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

struct brmap {
	int	brid;
	unsigned char pvcIdx;
};

extern int virtual_port_enabled;
extern const int virt2user[];
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
#endif

extern const char*  wlan[];
extern const int  wlan_en[];

#ifdef WLAN_8_SSID_SUPPORT
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
	PMAP_WLAN0_VAP3,
	PMAP_WLAN0_VAP4,
	PMAP_WLAN0_VAP5,
	PMAP_WLAN0_VAP6 = 11,
	PMAP_WLAN1 = 12,
	PMAP_WLAN1_VAP0,
	PMAP_WLAN1_VAP1,
	PMAP_WLAN1_VAP2,
	PMAP_WLAN1_VAP3,
	PMAP_WLAN1_VAP4,
	PMAP_WLAN1_VAP5,
	PMAP_WLAN1_VAP6 = 19,
	PMAP_ITF_END
} PMAP_LAN_T;
#else
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
#endif

#ifdef WLAN_8_SSID_SUPPORT
#define PMAP_WLAN0_VAP_END PMAP_WLAN0_VAP6
#define PMAP_WLAN1_VAP_END PMAP_WLAN1_VAP6
#else
#define PMAP_WLAN0_VAP_END PMAP_WLAN0_VAP3
#define PMAP_WLAN1_VAP_END PMAP_WLAN1_VAP3
#endif

struct itfInfo
{
	#define	DOMAIN_ELAN	0x1
	#define	DOMAIN_WAN	0x2
	#define	DOMAIN_WLAN	0x4
	#define	DOMAIN_ULAN	0x8	//usbeth
	int	ifdomain;
	int	ifid;
	char	name[40];// changed by jim
};

// IF_ID(domain, ifIndex)
#define IF_ID(x, y)		((x<<24)|y)
#define IF_DOMAIN(x)		(x>>24)
#define IF_INDEX(x)		(x&0x00ffffff)
#define IFGROUP_NUM		5

#if defined(CONFIG_USBCLIENT)
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
#define	IPQOS_NUM_PRIOQ		4

#ifdef _PRMT_X_CT_COM_QOS_
#define MODEINTERNET	0
#define MODETR069	1
#define MODEIPTV	2
#define MODEVOIP	3
#define MODEOTHER	4
#endif

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
	SYS_BUILDTIME,
	SYS_LAN_DHCP,
	SYS_DHCP_LAN_IP,
	SYS_DHCP_LAN_SUBNET,
	SYS_DHCPS_IPPOOL_PREFIX,
	SYS_DNS_MODE,
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
	SYS_DHCPV6_MODE,
	SYS_DHCPV6_RELAY_UPPER_ITF,
	SYS_LAN_IP6_LL,
	SYS_LAN_IP6_GLOBAL,
	SYS_WLAN_WPA_CIPHER,
	SYS_WLAN_WPA2_CIPHER,
	SYS_LAN_IP6_LL_NO_PREFIX
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
#ifdef CONFIG_USER_MONITORD
	PID_MONITORD,
#endif
#if defined(CONFIG_USER_OPENJDK8) && (defined(CONFIG_CMCC) || defined(CONFIG_CU))
	PID_JAVA,
#endif
} PID_SHIFT_T;

enum PortMappingPriority
{
	HighestPrio=0,
	HighPrio=1,
	MediumPrio=2,
	lowPrio=3
};

#ifdef STB_L2_FRAME_LOSS_RATE
#define MAX_STB	5

#define L2LOSSTESTMSGSTART	1
#define L2LOSSTESTMSGEND	2
#define L2LOSSTESTMSGSTARTFROMWEB	3

typedef struct l2LossRateResult
{
	unsigned char stbMac[6];
	unsigned char port;
	float lossRate;
	unsigned int timeDelay;
	unsigned int timeTremble;
	unsigned int recvPktNum;
	unsigned int lastTimeDelay;
}l2LossRateResult_t, *l2LossRateResult_p;
typedef struct stbL2Msg
{
	long int msgType;
	l2LossRateResult_t res[MAX_STB];
}stbL2Msg_t, *stbL2Msg_p;

#define L2LOSSRATEFILE ("/bin/stbL2Com")

#define STB_L2_DIAG_RESULT  "/tmp/stbL2Diag.tmp"
#endif


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
char *convertIPAddrToString(unsigned int ipAddr, unsigned char *pAddrStr);
char * fixSpecialChar(char *str,char *srcstr,int length);
int isDhcpProcessExist(unsigned int ifIndex);

extern const char AUTO_RESOLV[];
extern const char DNS_RESOLV[];
extern const char DNS6_RESOLV[];
extern const char PPP_RESOLV[];
extern const char RESOLV[];
extern const char DNSMASQ_CONF[];
extern const char RESOLV_BACKUP[];
extern const char HOSTS[];
extern const char MINIDLNAPID[];
extern const char DBUS_DNS_FILE[];

#define MAX_CONFIG_FILESIZE 300000
// Added by Kaohj
extern const char LANIF[];
extern const char LAN_ALIAS[];	// alias for secondary IP
extern const char LAN_IPPT[];	// alias for IP passthrough
extern const char ELANIF[];
#ifdef CONFIG_RTL_MULTI_LAN_DEV
#define ELANVIF_NUM CONFIG_LAN_PORT_NUM //eth lan virtual interface number
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
extern const char PORTMAP_IGMP[];
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
extern const char FW_IPFILTER_IN[];
extern const char FW_IPFILTER_OUT[];
#else
extern const char FW_IPFILTER[];
#endif
extern const char PORT_FW[];
extern const char IPTABLE_DMZ[];
extern const char IPTABLE_IPFW[];
extern const char IPTABLE_IPFW2[];
#ifdef NEW_PORTMAPPING
extern const char FW_DHCPS_DIS[];
extern const char FW_DNS_DIS[];
#endif
extern const char FW_MACFILTER[];
extern const char FW_IPQ_MANGLE_DFT[];
extern const char FW_IPQ_MANGLE_USER[];
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
extern const char RMACC_MARK[];
extern const char CONFIG_HEADER[];
extern const char CONFIG_TRAILER[];
extern const char CONFIG_HEADER_HS[];
extern const char CONFIG_TRAILER_HS[];
extern const char CONFIG_XMLFILE[];
extern const char CONFIG_RAWFILE[];
extern const char CONFIG_XMLFILE_HS[];
extern const char CONFIG_RAWFILE_HS[];
extern const char CONFIG_XMLENC[];
extern const char PPP_SYSLOG[];
extern const char PPP_DEBUG_LOG[];
extern const char PPP_CONF[];
extern const char PPP_PID[];
extern const char PPPOE_CONF[];
extern const char PPPOA_CONF[];
extern const char BACKUP_DIRNAME[];

extern const char ADSLCTRL[];
extern const char IFCONFIG[];
extern const char BRCTL[];
extern const char MPOAD[];
extern const char MPOACTL[];
extern const char DHCPD[];
extern const char DHCPC[];
extern const char DNSRELAY[];
extern const char DNSRELAYPID[];
extern const char SPPPD[];
extern const char SPPPCTL[];
extern const char WEBSERVER[];
extern const char SNMPD[];
extern const char ROUTE[];
extern const char IPTABLES[];

#ifdef CONFIG_IPV6
extern const char IP6TABLES[];
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
extern const char FW_IPV6FILTER_IN[];
extern const char FW_IPV6FILTER_OUT[];
#else
extern const char FW_IPV6FILTER[];
#endif
#ifdef CONFIG_CMCC_IPV6_SECURITY_SUPPORT
extern const char IP6SEC[];
extern const char IP6SECCTRL[];
#endif
extern const char FW_IPV6REMOTEACC[];
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
#ifdef CONFIG_CMCC_OSGIMANAGE
extern const char OSGIMANAGE_PID[];
#endif
#ifdef CONFIG_USER_CUMANAGEDEAMON
extern const char CUMANAGE_PID[];
#endif
#ifdef CONFIG_USER_DDNS
extern const char DDNSC_PID[];
#endif

#ifdef CONFIG_USER_MONITORD
#define MONITORD_PID "/var/run/monitord.pid"
#define MONITOR_LIST "/var/monitor_list"
int update_monitor_list_file(char *process_name, int action);
#endif

extern const char PROC_DYNADDR[];
extern const char PROC_IPFORWARD[];
extern const char PROC_FORCE_IGMP_VERSION[];
extern const char PPPD_FIFO[];
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
extern const int priomap[];;
extern const char *ipTos[];
//alex
#ifdef CONFIG_8021P_PRIO
extern const char *set1ptable[];
#ifdef NEW_IP_QOS_SUPPORT
extern const char *setpredtable[];
#endif
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

#if defined(CONFIG_RTL_IGMP_SNOOPING)
void __dev_setupIGMPSnoop(int flag);	// enable/disable IGMP snooping
#endif

#if defined(CONFIG_RTL_MLD_SNOOPING)
void __dev_setupMLDSnoop(int flag);
#endif
#ifndef CONFIG_KERNEL_4_4_x
void __dev_setupDirectBridge(int flag);
#endif
#ifdef CONFIG_USER_IP_QOS
int setWanIF1PMark(void);
#endif
void __dev_setupIPQoS(int flag);
#ifdef QOS_DIFFSERV
void cleanupDiffservRule(int idx);
int setupDiffServ(void);
#endif
int get_domain_ifinfo(struct itfInfo *info, int len, int ifdomain);
int _do_cmd(const char *filename, char *argv [], int dowait, int donice);
#define do_cmd(a,b,c) _do_cmd(a,b,c,0)
#define do_nice_cmd(a,b,c) _do_cmd(a,b,c,1)
int do_cmd_ex(const char *filename, char *argv [], int dowait, int noError);
int va_cmd(const char *cmd, int num, int dowait, ...);  //return 0:OK, other:fail
int va_niced_cmd(const char *cmd, int num, int dowait, ...);  //return 0:OK, other:fail
int va_cmd_no_error(const char *cmd, int num, int dowait, ...);  //return 0:OK, other:fail
int va_cmd_no_echo(const char *cmd, int num, int dowait, ...);  //return 0:OK, other:fail
int call_cmd(const char *filename, int num, int dowait, ...);	//return 0:OK, other:fail
void write_to_pppd(struct data_to_pass_st *);
int write_to_mpoad(struct data_to_pass_st *);
int startDhcpc(char *inf, MIB_CE_ATM_VC_Tp pEntry, int is_diag);
void config_AddressMap(int action);
int startIP_v4(char *inf, MIB_CE_ATM_VC_Tp pEntry, CHANNEL_MODE_T ipEncap);
int startIP(char *inf, MIB_CE_ATM_VC_Tp pEntry, CHANNEL_MODE_T ipEncap);
#ifdef _PRMT_X_CMCC_IPOEDIAGNOSTICS_
#define IPOE_DIAG_RESULT_DHCPC_FILE  "/tmp/ipoe_diag_dhcp"
#define IPOE_DIAG_RESULT_PING_FILE  "/tmp/ipoe_diag_ping"

int ipoeSimulationStart(int ifIndex, unsigned char *mac, char* ping_host, unsigned int repitation, unsigned int timeout);
#endif
void stopPPP(void);
int startPPP(char *inf, MIB_CE_ATM_VC_Tp pEntry, char *qos, CHANNEL_MODE_T pppEncap);
int find_ppp_from_conf(char *pppif);
#if defined(CONFIG_SUPPORT_AUTO_DIAG)||defined(_PRMT_X_CT_COM_IPoEDiagnostics_)
struct DIAG_RESULT_T
{
	unsigned char 	result[128];
	unsigned int 	errCode;
	unsigned int 	ipType;
	unsigned int 	sessionId;
	unsigned char 	aftr[256];
	unsigned char 	ipAddr[16];
	unsigned char 	gateWay[16];
	unsigned char 	dns[16];
	unsigned char 	ipv6Addr[256];
	unsigned char 	ipv6GW[256];
	unsigned char 	ipv6DNS[256];
	unsigned char 	ipv6Prefix[256];
	unsigned char 	ipv6LANPrefix[256];
	unsigned char 	authMSG[256];
#ifdef _PRMT_X_CT_COM_IPoEDiagnostics_
	unsigned char 	netmask[16];
#endif
};
void addSimuEthWANdev(MIB_CE_ATM_VC_Tp pEntry, int autosimu);
int pppoeSimulationStart(char* devname, char* username, char* password, int ipv6AddrMode);
int getSimulationResult(char* devname, struct DIAG_RESULT_T* state);
unsigned int getOptionFromleases(char* filename, char* iaprfix, char* dns, char* aftr);
int initAutoBridgeFIFO(void);
int setOmciState(int state);
int setSimuDebug(int debug);
int poll_msg(int fd);
int query_aftr(char *aftr,  char *aftr_dst, char *aftr_addr_str);
#endif
int _get_classification_mark(int entryNo, MIB_CE_IP_QOS_T *p);
int get_classification_mark(int entryNo);
int startConnection(MIB_CE_ATM_VC_Tp pEntry, int);
void stopConnection(MIB_CE_ATM_VC_Tp pEntry);
#ifdef CONFIG_NO_REDIAL
void startReconnect(void);
#endif
#ifdef CONFIG_USER_RTK_SYSLOG
extern char *log_severity[8];
int stopLog(void);
int startLog(void);
#endif
#if defined(BB_FEATURE_SAVE_LOG) || defined(CONFIG_USER_RTK_SYSLOG)
void writeLogFileHeader(FILE * fp);
#endif
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
int isMLDProxyEnabled(void);
#endif
#ifdef CONFIG_USER_RADVD
int setup_radvd_conf(void);
void init_radvd_conf_mib(void);   // Added by Mason Yu for p2r_test
#endif
#if defined(CONFIG_USER_DHCPV6_ISC_DHCP411) || defined(CONFIG_USER_RADVD)
extern const char RADVD_CONF[];
extern const char RADVD_PID[];
#endif
int checkIPv6Route(MIB_CE_IPV6_ROUTE_Tp new_entry);
void route_v6_cfg_modify(MIB_CE_IPV6_ROUTE_T *pRoute, int del, int entryID);
#endif
void addStaticRoute(void);
void deleteStaticRoute(void);
void addStaticRoute_per_wan(unsigned int ifIndex);
void deleteStaticRoute_per_wan(unsigned int ifIndex);
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
int setupDMZ(int isBoot);


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
#endif
#ifdef NAT_CONN_LIMIT
int restart_connlimit(void);
void set_conn_limit(void);
#endif
#ifdef TCP_UDP_CONN_LIMIT
int restart_connlimit(void);
void set_conn_limit(void);
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
#endif
#if defined(CONFIG_USER_ROUTED_ROUTED) || defined(CONFIG_USER_ZEBRA_OSPFD_OSPFD)
int startRip(void);
#endif
#ifdef CONFIG_USER_ZEBRA_OSPFD_OSPFD
int startOspf(void);
#endif
#ifdef SUPPORT_DHCP_RESERVED_IPADDR
int clearDHCPReservedIPAddrByInstNum(unsigned int instnum);
#endif
int setupDhcpd(void);
int startDhcpRelay(void);
unsigned char isZeroMac(unsigned char *pMac);

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
	char uptime[20];
	char totaluptime[20];
	char vpivci[12];
	int pppDoD;
	int itf_state;
	int link_state;
};

unsigned short ipchksum(unsigned char *ptr, int count, unsigned short resid);

struct file_pipe {
	unsigned char *buffer;
	size_t bufsize;
	void (*func)(unsigned char *buffer, size_t *bufsize);
};
#ifdef _PRMT_USBRESTORE
int usbRestore(void);
#endif
void encode(unsigned char *buf, size_t * buflen);
void decode(unsigned char *buf, size_t *buflen);
int file_copy_pipe(const char *inputfile, const char *outputfile, struct file_pipe *pipe);
int usb_filter(const struct dirent *dirent);
int isUSBMounted(void);

#ifdef PORT_FORWARD_GENERAL
void clear_dynamic_port_fw(int (*upnp_delete_redirection)(unsigned short eport, const char * protocol));
int setupPortFW(void);
void portfw_modify( MIB_CE_PORT_FW_T *p, int del );
#endif
#ifdef TIME_ZONE
int startNTP(void);
int stopNTP(void);
#endif
#ifdef CONFIG_CMCC_OSGIMANAGE
int startOsgiManage(void);
int stopOsgiManage(void);
#endif

#ifdef CONFIG_USER_MINIDLNA
void startMiniDLNA(void);
void stopMiniDLNA(void);
#endif

// Mason Yu. combine_1p_4p_PortMapping
#if (defined( ITF_GROUP_1P) && defined(ITF_GROUP)) || (defined( ITF_GROUP_4P) && defined(ITF_GROUP))
void setupEth2pvc(void);
#endif
#ifdef IP_QOS
int setupUserIPQoSRule(int enable);
#endif
#if defined(IP_QOS) | defined(CONFIG_USER_IP_QOS_3)
int stopIPQ(void);
int setupIPQ(void);
int restore_hw_queue(void);
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

#define DONICEDCMDARGVS(cmd,dowait,format,args...) \
		argvs_index=1;\
		memset(cmdargvs,0,sizeof(cmdargvs));\
		memset(_argvs,0,sizeof(_argvs));\
		snprintf(cmdargvs,sizeof(cmdargvs),format , ##args);\
		fprintf(stderr,"%s %s\n",cmd,cmdargvs);\
		_argvs[argvs_index]=strtok(cmdargvs," ");\
		while(_argvs[argvs_index]){\
			_argvs[++argvs_index]=strtok(NULL," ");\
		}\
		do_nice_cmd(cmd,_argvs,dowait);
		
/*ql:20081114 END*/

#ifdef CONFIG_XFRM
#define SETKEY_CONF "/tmp/setkey.conf"
#define RACOON_CONF "/tmp/racoon.conf"
#define RACOON_PID "/var/run/racoon.pid"
#define PSK_FILE "/tmp/psk.txt"
#define DHGROUP_INDEX(x)	((x >> 24) & 0xff)
#define ENCRYPT_INDEX(x)	((x >> 16) & 0xff)
#define AHAUTH_INDEX(x)	((x >> 8) & 0xff)
#define AUTH_INDEX(x)	(x & 0xff)
struct IPSEC_PROP_ST
{
	char name[MAX_NAME_LEN];
	unsigned int algorithm; //dhGroup|espEncryption|ahAuth|espAuth
};

void ipsec_take_effect(void);
extern struct IPSEC_PROP_ST ikeProps[];
extern struct IPSEC_PROP_ST saProps[];
#endif

#if defined(CONFIG_USER_L2TPD_LNS) || defined(CONFIG_USER_L2TPD_L2TPD)
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
void l2tpd_take_effect(void);
#endif
#ifdef CONFIG_USER_SNMPD_SNMPD_V2CTRAP
int startSnmp(void);
int restart_snmp(int flag);
#endif
#if defined(CONFIG_USER_CWMP_TR069) || defined(APPLY_CHANGE)
void off_tr069(void);
#endif
#if defined(CONFIG_USER_CWMP_TR069) || defined(IP_ACL)
int restart_acl(void);
#endif
#ifdef CONFIG_USER_CUMANAGEDEAMON
void restart_cumanage(void);
#endif
int restart_dnsrelay(void); //Jenny
int restart_dhcp(void);
int restart_lanip(void);
#ifdef CONFIG_USER_ROUTED_ROUTED
int delRipTable(unsigned int ifindex);
#endif
int delPPPoESession(unsigned int ifindex);
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
extern char* ip_qos_classficationtype_str[IP_QOS_CLASSFICATIONTYPE_MAX];
extern char* ip_qos_protocol_str[IP_QOS_PROTOCOL_MAX];

void QosClassficationToQosRule(int action,int cls_id);
int delQosClassficationTypeRule(int ifIndex);
#endif
MIB_CE_ATM_VC_T *getATMVCEntryByIfIndex(unsigned int ifIndex, MIB_CE_ATM_VC_T *p);

#ifdef _CWMP_MIB_ /*jiunming, for cwmp-tr069*/
int delPortForwarding( unsigned int ifindex );
int updatePortForwarding( unsigned int old_id, unsigned int new_id );
int delRoutingTable( unsigned int ifindex );
int updateRoutingTable( unsigned int old_id, unsigned int new_id );
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
#if defined(IP_QOS) || defined(CONFIG_USER_IP_QOS_3)
unsigned int getQoSQueueNum(void);
#endif
MIB_CE_ATM_VC_T *getATMVCByInstNum( unsigned int devnum, unsigned int ipnum, unsigned int pppnum, MIB_CE_ATM_VC_T *p, unsigned int *chainid );
int startCWMP(void);
#ifdef E8B_GET_OUI
void getOUIfromMAC(char *ouiname);
#endif
#ifdef CONFIG_CTC_E8_CLIENT_LIMIT
int proc_write_for_mwband(void);
#endif
void set_endpoint(char *newurl, char *acsurl); //star: remove "http://" from acs url string
#if defined(IP_QOS) || defined(NEW_IP_QOS_SUPPORT)
/*star:20100305 START add qos rule to set tr069 packets to the first priority queue*/
void setQosfortr069(int mode, char *urlvalue);
void setTr069QosFlag(int var);
int getTr069QosFlag(void);
#endif

#ifdef CONFIG_MIDDLEWARE
int sendSetDefaultRetMsg2MidIntf(void);
int sendSetDefaultFlagMsg2MidProcess(void);
int apply_Midware( int action_type, int id, void *olddata );	/*note: cann't restart cwmp process for apply immediately*/
void setapplicationtype_mw(MIB_CE_ATM_VC_T *pEntry, int mode, char *mwaddr);
void setMidwareRouteFW(int clearold);
#endif

void storeOldACS(void);
int getOldACS(char *acsurl);
#ifdef _PRMT_X_CT_COM_PORTALMNT_
#define TR069_FILE_PORTALMNT  "/proc/fp_tr069"
void setPortalMNT(void);
#endif
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
int getifIndexByWanName(const char *name);

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
#ifdef CONFIG_GPON_FEATURE
#ifdef CONFIG_RTK_HOST_SPEEDUP
int set_speedup_usflow(MIB_CE_ATM_VC_T *pEntry);
int clear_speedup_usflow(void);
#endif
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
extern void update_wan_routing(char *ifname);

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
int startWan(int configAll, MIB_CE_ATM_VC_Tp pEntry, int isBoot);
#define CONFIGONE	0
#define CONFIGALL 	1
#define CONFIGCWMP 2

// Mason Yu
#define WEB_REDIRECT_BY_MAC_INTERVAL	12*60*60	/* Polling DHCP release table every 12 hours */
struct webserver_callout;
void timeout_utility(void (*func) __P((void *)), void *arg, int time, struct webserver_callout *handle);
void untimeout_utility(struct webserver_callout *handle);
#ifndef TIMEOUT
#define TIMEOUT(fun, arg1, arg2, handle) 	timeout_utility(fun,arg1,arg2, &handle)
#endif

#ifndef UNTIMEOUT
#define UNTIMEOUT(fun, arg, handle)		untimeout_utility(&handle)
#endif

#ifdef WEB_REDIRECT_BY_MAC
extern struct webserver_callout landingPage_ch;
void clearLandingPageRule(void *dummy);
#endif
#ifdef AUTO_DETECT_DMZ
extern struct webserver_callout autoDMZ_ch;
#endif

// Mason Yu. Timer for auto search PVC
int pppdbg_get(int unit);
struct sysinfo * updateLinkTime(unsigned char update);

void poll_autoDMZ(void *dummy);
void restartWAN(int configAll, MIB_CE_ATM_VC_Tp pEntry);
void resolveServiceDependency(unsigned int idx);
#ifdef IP_PASSTHROUGH
void restartIPPT(struct ippt_para para);
#endif
#ifdef DOS_SUPPORT
void setup_dos_protection(void);
#endif

#ifdef CONFIG_LED_INDICATOR_TIMER
//extern struct webserver_callout ledsched_ch;
//void led_schedule(void);
int setLedIndicator(unsigned char enable, unsigned char ctlCycle, unsigned char startHour, unsigned char startMin, unsigned char endHour, unsigned char endMin);
int get_ledctrl_state(void);
#endif

#ifdef CONFIG_RG_SLEEPMODE_TIMER
extern struct webserver_callout sleepmode_ch;
void sleepmode_schedule(void);
int get_sleepmode_state(void);
#endif

#ifdef COMMIT_IMMEDIATELY
void Commit(void);
#endif

int checkRoute(MIB_CE_IP_ROUTE_T, int);
void setup_ipforwarding(int enable);
void check_staticRoute_change(char *ifname);
void route_cfg_modify(MIB_CE_IP_ROUTE_T *, int, int entryID);
void route_ppp_ifup(unsigned long pppGW, char *ifname);
void ppp_if6up(char *ifname);
char *ifGetName(int, char *, unsigned int);
int getIfIndexByName(char *pIfname);
int getNameByIP(char *ip, char *buffer, unsigned int len);
#if defined(ITF_GROUP_1P) && defined(ITF_GROUP)
int setVlan(struct ifreq *ifr);
#endif


/* WAPI */
#define WAPI_TMP_CERT "/var/tmp/tmp.cert"
#define WAPI_AP_CERT "/var/myca/ap.cert"
#define WAPI_CA_CERT "/var/myca/CA.cert"
#define WAPI_CA4AP_CERT "/var/myca/ca4ap.cert"
#define WAPI_AP_CERT_SAVE "/var/config/ap.cert"
#define WAPI_CA_CERT_SAVE "/var/config/CA.cert"
#define WAPI_CA4AP_CERT_SAVE "/var/config/ca4ap.cert"
void wapi_cert_link_one(const char *name, const char *lnname);

#if defined(CONFIG_ETHWAN)
#define ETHWAN_PORT 3
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

int setupMacFilterTables(void);
int restart_IPFilter_DMZ_MACFilter(void);
void cleanAllFirewallRule(void);
int setupFirewall(int isBoot);
#ifdef CONFIG_IP_NF_ALG_ONOFF
int setupAlgOnOff(void);
#endif
#ifdef _SUPPORT_CAPTIVEPORTAL_PROFILE_
int start_captiveportal(void);
int stop_captiveportal(void);
void enable_http_redirect2CaptivePortalURL(int);
#endif

//Kevin:Check whether to enable/disable upstream ip fastpath
void UpdateIpFastpathStatus(void);

#define BIT_IS_SET(a, no)  (a & (0x1 << no))

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

#ifdef _PRMT_X_CT_COM_WANEXT_
void handle_IPForwardMode(int wan_idx);
#endif

#if defined(CONFIG_USER_PPTP_CLIENT_PPTP) && defined(CONFIG_USER_L2TPD_L2TPD)
#define MAGIC_TUNNEL_NAME	"Magic_tunnelName"
typedef struct gdbus_vpn_tunnel_info {    				/* Used as argument to CreateWanL2TPTunnel() */
	VPN_MODE_T vpn_mode;
	VPN_PRIO_T vpn_priority;
	VPN_TYPE_T vpn_type;
	VPN_ENABLE_T vpn_enable;
	VPN_AUTH_TYPE_T authtype;
	VPN_ENCTYPE_T enctype;
	unsigned char account_proxy[MAX_DOMAIN_LENGTH];
	unsigned char account_proxy_msg[MAX_DOMAIN_LENGTH];
	unsigned char account_proxy_mac[MAC_ADDR_LEN];
	int account_proxy_result;
	int account_proxy_param_status;
	unsigned int vpn_port;
	unsigned int vpn_idletime;
	unsigned char serverIP[MAX_DOMAIN_LENGTH];
	unsigned char userName[MAX_VPN_ACC_PW_LEN+1];
	unsigned char passwd[MAX_VPN_ACC_PW_LEN+1];
	unsigned char tunnelName[MAX_NAME_LEN];
	unsigned char userID[MAX_NAME_LEN];
} gdbus_vpn_tunnel_info_t;

typedef struct gdbus_vpn_connection_info {
	ATTACH_MODE_T attach_mode;
	unsigned char *domains[20];
	unsigned char *ips[20];
	unsigned char *terminal_mac[20];
	gdbus_vpn_tunnel_info_t vpn_tunnel_info;
} gdbus_vpn_connection_info_t;

int CreateWanPPTPTunnel(gdbus_vpn_tunnel_info_t *vpn_tunnel_info, ATTACH_MODE_T attach_mode, unsigned char *reason);
int RemoveWanPPTPTunnel(gdbus_vpn_tunnel_info_t *vpn_tunnel_info, unsigned char *reason);
int AttachWanPPTPTunnel(gdbus_vpn_tunnel_info_t *vpn_tunnel_info, unsigned char *ipDomainNameAddr[], unsigned char *reason);
typedef struct pptp_tunnel_status
{
	char tunnelName[32];
	char tunnelStatus[8];
}PPTP_Status_T, *PPTP_Status_Tp;
int DetachWanPPTPTunnel(gdbus_vpn_tunnel_info_t *vpn_tunnel_info, ATTACH_MODE_T attach_mode, unsigned char *ipDomainNameAddr[], unsigned char *reason);

int GetWanPPTPTunnelStatus(gdbus_vpn_tunnel_info_t *vpn_tunnel_info, unsigned char *reason, PPTP_Status_Tp pptp_list, int *num);

int CreateWanL2TPTunnel(gdbus_vpn_tunnel_info_t *vpn_tunnel_info, ATTACH_MODE_T attach_mode, unsigned char *reason);
int RemoveWanL2TPTunnel(gdbus_vpn_tunnel_info_t *vpn_tunnel_info, unsigned char *reason);
int AttachWanL2TPTunnel(gdbus_vpn_tunnel_info_t *vpn_tunnel_info, unsigned char *ipDomainNameAddr[], unsigned char *reason);
typedef struct l2tp_tunnel_status
{
	char tunnelName[32];
	char tunnelStatus[8];
}L2TP_Status_T, *L2TP_Status_Tp;
int DetachWanL2TPTunnel(gdbus_vpn_tunnel_info_t *vpn_tunnel_info, ATTACH_MODE_T attach_mode, unsigned char *ipDomainNameAddr[], unsigned char *reason);

int GetWanL2TPTunnelStatus(gdbus_vpn_tunnel_info_t *vpn_tunnel_info, unsigned char *reason, L2TP_Status_Tp l2tp_list, int *num);


void modPolicyRouteTable(const char *pptp_ifname, struct in_addr *real_addr);
#ifdef CONFIG_IPV6_VPN
void modIPv6PolicyRouteTable(const char *pptp_ifname, struct in6_addr *real_addr);
#endif
#endif
#endif

#if defined(CONFIG_LUNA) && defined(CONFIG_RTK_L34_ENABLE)
int Init_RTK_RG_Device(void);
void clearRG_Wan_Index(void);
int Flush_RG_static_route(void);
int Flush_RG_static_route_per_WAN(unsigned int ifIndex);
int check_RG_static_route(void);
int check_RG_static_route_per_WAN(unsigned int ifIndex);
#if defined(CONFIG_CMCC) || defined(CONFIG_CU) 
int check_RG_policy_route_on_static(int entryID);
int Flush_RG_policy_route_on_static(void);
int Set_RG_policy_route_on_static(void);
#endif
void rg_add_route(MIB_CE_IP_ROUTE_T *entry, int entryID);
int get_wan_gateway(unsigned int ifIndex, struct in_addr *gateway);
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

#define WAN_MODE GetWanMode()
enum e_wan_mode {MODE_ATM = 1, MODE_Ethernet = 2, MODE_PTM = 4, MODE_BOND = 8, MODE_Wlan = 0x10};
int GetWanMode(void);
int isInterfaceMatch(unsigned int);
#define WAN_MODE_MASK (GET_MODE_ETHWAN|GET_MODE_WLAN)

#ifdef CONFIG_ETHWAN
#define GET_MODE_ETHWAN 0x2
#else
#define GET_MODE_ETHWAN 0x0
#endif

#ifdef WLAN_WISP
#define GET_MODE_WLAN 0x10
#else
#define GET_MODE_WLAN 0
#endif

int reset_cs_to_default(int flag); // 0: short reset; 1: long reset

#ifdef CONFIG_USER_SAMBA
int startSamba(void);
int stopSamba(void);
#endif // CONFIG_USER_SAMBA

#ifdef CONFIG_TR_064
#define TR064_STATUS GetTR064Status()
int GetTR064Status(void);
#endif

#ifdef CONFIG_USER_CWMP_TR069
#define PRE_CWMP_WAN_INTF "/var/pre_cwmp_wan_intf"
enum {Old_ACS_URL = 1, Cur_ACS_URL};
int SetTR069WANInterface(void); // Magician: Bind WAN interface to TR-069
int SetTR069WANInterfacePPP(void);
int SetTR069WANInterfaceDHCP(void);
int DelTR069WANInterface(char);
#endif

// Mason Yu. Specify IP Address
struct ddns_info {    				/* Used as argument to ddnsC() */
	int		ipversion;        		/* IPVersion . 1:IPv4, 2:IPv6, 3:IPv4 and IPv6 */
	char 	ifname[IFNAMSIZ];        /* Interface name */
};

int update_hosts(char *, struct addrinfo *);
struct addrinfo *hostname_to_ip(char *, IP_PROTOCOL);

#define PMAP_VC_START	1
#define PMAP_PPP_START	0x10
#define PMAP_NAS_START 0x20
#define PMAP_NAS_PPP_START 0x30
#define ITF_SOURCE_ROUTE_VC_START	0x60
#define ITF_SOURCE_ROUTE_NAS_START	0x70
#define ITF_SOURCE_ROUTE_PTM_START	0x80
#define ITF_SOURCE_ROUTE_PPP_START	0x90
#define ITF_SOURCE_ROUTE_SIMU_START	0xa0

/***********************************************************************/
/* parameter structure & utility functions. */
/***********************************************************************/
/*error code*/
#define ERR_9000	-9000	/*Method not supported*/
#define ERR_9001	-9001	/*Request denied*/
#define ERR_9002	-9002	/*Internal error*/
#define ERR_9003	-9003	/*Invalid arguments*/
#define ERR_9004	-9004	/*Resources exceeded*/
#define ERR_9005	-9005	/*Invalid parameter name*/
#define ERR_9006	-9006	/*Invalid parameter type*/
#define ERR_9007	-9007	/*Invalid parameter value*/
#define ERR_9008	-9008	/*Attempt to set a non-writable parameter*/
#define ERR_9009	-9009	/*Notification request rejected*/
#define ERR_9010	-9010	/*Download failure*/
#define ERR_9011	-9011	/*Upload failure*/
#define ERR_9012	-9012	/*File transfer server authentication failure*/
#define ERR_9013	-9013	/*Unsupported protocol for file transfer*/

#if defined(NEW_IP_QOS_SUPPORT)
int setMIBforQosMode(unsigned char modeflag);
//int cr2reg(int pcr);
#endif //IP_QOS

/* mac to string function */
int hex(unsigned char);
void convert_mac(char *);

/*star:20080807 START add for ct qos model*/
#define NONEMODE  0
#define INTERNETMODE 1
#define TR069MODE     2
#define IPTVMODE       4
#define  VOIPMODE      8
#define  OTHERMODE    16
/*star:20080807 END*/

// Magician: E8B Security
typedef struct _WAN_STATE_ST_ {
	char xDSLMode;	//xDSL mode: route, route&bridge
	char wanItf;	//0-MER only; 1- PPPoE only;  2- MER&PPPoE
	char ifNum;		//num of route interface
	char null;
} WAN_STATE_T;

typedef struct _VC_STATE_ST_ {
	char ifName[IFNAMSIZ];	//interface name
	char chMode;	//channel mode of current PVC: CHANNEL_MODE_IPOE ...
	char fstPvc;	//show if is the first configured wan interface
	char dfGW;		//show if interface with default GW
	char null;
} VC_STATE_T, *VC_STATE_Pt;

//use fw_state_t to reserve the set state of firewall grade
typedef struct _FW_GRADE_INIT_ST_{
	char linkDownInit;	//set firewall grade while link down
	char linkUpInit;	//set firewall grade while link up.
	char preFwGrade;	//previous firewall grade
	char null;
} FW_GRADE_INIT_St;

#define EBTABLES_ENABLED 1
#define EBTABLES_DISABLED 0
#define MAC_FILTER_BRIDGE_RULES 16
#define MAC_FILTER_ROUTER_RULES 16

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
#define ICMPFRAGMENT		0x80000
#define TCPFRAGOFFMIN		0x100000
#define TCPHDRMIN			0x200000
#define sourceIPblock		0x400000

#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
#define CMCC_FIREWARE_LEVEL_HIGH	IPTEARDROPENABLED|IPFLOODSYN|IPFLOODFIN|IPFLOODUDP|IPFLOODICMP|PINGOFDEATHENABLED|sourceIPblock
#define CMCC_FIREWARE_LEVEL_MIDDLE	TCPSCANENABLED|TCPSynWithDataEnabled|TCPUDPPORTSCAN|SYSFLOODSYN|SYSFLOODFIN|SYSFLOODUDP|SYSFLOODICMP|ICMPSMURFENABLED
#define CMCC_FIREWARE_LEVEL_LOW		IPLANDENABLED|IPSPOOFENABLED|UDPBombEnabled|UDPEchoChargenEnabled
#endif
#define DOS_ENABLE_ALL	(DOS_ENABLE|SYSFLOODSYN|SYSFLOODFIN|SYSFLOODUDP|SYSFLOODICMP|IPFLOODSYN|\
						IPFLOODFIN|IPFLOODUDP|IPFLOODICMP|TCPUDPPORTSCAN|ICMPSMURFENABLED|\
						IPLANDENABLED|IPSPOOFENABLED|IPTEARDROPENABLED|PINGOFDEATHENABLED|\
						TCPSCANENABLED|TCPSynWithDataEnabled|UDPBombEnabled|UDPEchoChargenEnabled|\
						sourceIPblock|ICMPFRAGMENT|TCPFRAGOFFMIN|TCPHDRMIN)

int startFirewall(void);
int changeFwGrade(unsigned char enable, int currGrade);
int setup_psd(void);	//port scan
int setupDos(void);
// End Magician: E8B Security
#ifdef _PRMT_X_CT_COM_ALARM_MONITOR_
int set_ctcom_alarm(unsigned int alarm_num);
int clear_ctcom_alarm(unsigned int alarm_num);
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
#endif
#ifdef CONFIG_HTTP_DOWNLOAD_TEST
extern struct webserver_callout httptest_ch;
#endif

#ifdef CONFIG_SUPPORT_AUTO_DIAG
//extern struct webserver_callout autoSimulation_ch;
int startAutoBridgePppoeSimulation(char* wanname);
int stopAutoBridgePppoeSimulation(char* wanname);
#endif


#ifdef SUPPORT_WAN_BANDWIDTH_INFO
extern struct webserver_callout bandwidth_ch;
void poll_bandwidth(void *dummy);
int wan_bandwidth_set(unsigned char enable, unsigned int interval);
int wan_bandwidth_get(int rg_wan_idx, int * uploadrate, int * downloadrate);
#endif
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
extern struct webserver_callout ponFlowTxBytes_ch;
void poll_ponFlowTxBytes(void *arg);

#endif

#ifdef CONFIG_USER_QUICKINSTALL
extern struct webserver_callout downspeed_ch;
void poll_wan_downspeed(void *dummy);
#endif

#ifdef CONFIG_USER_LAN_BANDWIDTH_CONTROL
extern struct webserver_callout macinfo_ch;
void poll_macinfo(void);
#endif

#ifdef SUPPORT_WEB_REDIRECT
void welcomeRedirectCheck(void *arg);
int webRedirectSetRGRule(int add);
void web404RedirectCheck(void);
#endif

void compact_reqoption_order(unsigned int ifIndex);

int check_user_is_registered(void);
int sync_itfGroup(int ifidx);	//for vlan binding
#if defined(CONFIG_CT_AWIFI_JITUAN_SMARTWIFI)
int killWiFiDog(void);
void startWiFiDog(void *null);
void restartWiFiDog(int restart);
extern struct webserver_callout wifiAuth_ch;
extern int g_wan_modify;
extern void wifiAuthCheck(void* null);
#define WA_MAX_WAN_NAME 33
#define WIFIDOGPATH "/var/config/awifi/smartwifi"
#define WIFIDOGCONFPATH "/var/config/awifi/awifi.conf"
#define WIFIDOGTMPCONFPATH "/var/config/awifi/temp.conf"
#define WIFIDOGBAKCONFPATH "/var/config/awifi/awifi_bak.conf"
#define KILLWIFIDOGSTR "killall smartwifi"
#define AWIFI_DEFAULT_BIN_VERSION		"V4.0.0"
#endif

/***************************************************************************/
#ifdef SUPPORT_ACCESS_RIGHT
#define INTERNET_ACCESS_DENY				0
#define INTERNET_ACCESS_NO_INTERNET			1 /* can access lan side but can't access internet */
#define INTERNET_ACCESS_ALLOW				2
#define STORAGE_ACCESS_DENY		0
#define STORAGE_ACCESS_ALLOW	1
#endif
#ifdef CONFIG_USER_LAN_BANDWIDTH_CONTROL
#define DEFAULT_MAX_US_BANDWIDTH		1024*1024
#define DEFAULT_MAX_DS_BANDWIDTH		1024*1024
#endif

#define DEFAULT_STATE_FILE "/var/run/udhcpc.state"

#ifdef CONFIG_USER_LANNETINFO
#define MAX_LANNET_DEV_NAME_LENGTH			32
#define MAX_LANNET_BRAND_NAME_LENGTH		16
#define MAX_LANNET_MODEL_NAME_LENGTH		16
#define MAX_LANNET_OS_NAME_LENGTH			16

#define MAX_LAN_HOST_NUM		256
#define MAX_DEV_TIME_LEN		64

typedef struct lanHostInfo_s
{
	unsigned char		mac[MAC_ADDR_LEN];
	char				devName[MAX_LANNET_DEV_NAME_LENGTH];
	unsigned char		devType;	/* 0-phone 1-pad 2-PC 3-STB 4-other  0xff-unknown */
	unsigned int		ip; /* network order */
	unsigned char		connectionType;	/* 0- wired 1-wireless */
	unsigned char		port;	/* 0-wifi, 1- lan1, 2-lan2, 3-lan3, 4-lan4 */
	char				brand[MAX_LANNET_BRAND_NAME_LENGTH];
	char				model[MAX_LANNET_MODEL_NAME_LENGTH];
	char				os[MAX_LANNET_OS_NAME_LENGTH];
	unsigned int		onLineTime;
	unsigned int 		upRate;   /* in unit of kbps */
	unsigned int 		downRate; /* in unit of kbps */
	unsigned long long	rxBytes;
	unsigned long long	txBytes;
	unsigned char		firstConnect;
	unsigned char		disConnect;
	char 				latestActiveTime[MAX_DEV_TIME_LEN];
	char				latestInactiveTime[MAX_DEV_TIME_LEN];
	unsigned char 		controlStatus;
	unsigned char  		internetAccess; /* default is 2 */
	unsigned char  		storageAccess; /* default is 1 */
} lanHostInfo_t;

typedef struct hgDevInfo_s
{
	unsigned char	mac[MAC_ADDR_LEN];
	char			devName[MAX_LANNET_DEV_NAME_LENGTH];
} hgDevInfo_t;


#define MAX_DEVICE_INFO_SIZE  2048
typedef struct lannetmsgInfo {
	int		cmd;
	int		arg1;
	int		arg2;
	char	mtext[MAX_DEVICE_INFO_SIZE];
} LANNETINFO_MSG_T;

struct lanNetInfoMsg {
    long mtype;			// Message type
    long request;		// Request ID/Status code
    long tgid;			// thread group tgid
	LANNETINFO_MSG_T msg;
};

#define LANNETINFO_MSG_SUCC		0
#define LANNETINFO_MSG_FAIL		1

#define CMD_NEW_DEVICE_INFO_GET				0x1
#define CMD_LEAVE_DEVICE_INFO_GET			0x2
#define CMD_LAN_HOST_MAX_NUMBER_SET			0x4
#define CMD_LAN_HOST_MAX_NUMBER_GET			0x8
#define CMD_LAN_HOST_NUMBER_GET				0x10
#define CMD_CONTROL_LIST_MAX_NUMBER_SET		0x20
#define CMD_CONTROL_LIST_MAX_NUMBER_GET		0x40
#define CMD_CONTROL_LIST_NUMBER_GET			0x80
#define CMD_LAN_HOST_CONTROL_STATUS_SET		0x100
#define CMD_LAN_HOST_CONTROL_STATUS_GET		0x200
#define CMD_LAN_HOST_ACCESS_RIGHT_SET		0x400
#define CMD_LAN_HOST_ACCESS_RIGHT_GET		0x800
#define CMD_LAN_HOST_DEVICE_TYPE_SET		0x1000
#define CMD_LAN_HOST_DEVICE_TYPE_GET		0x2000
#define CMD_LAN_HOST_BRAND_SET				0x4000
#define CMD_LAN_HOST_BRAND_GET				0x8000
#define CMD_LAN_HOST_MODEL_SET				0x10000
#define CMD_LAN_HOST_MODEL_GET				0x20000
#define CMD_LAN_HOST_OS_SET					0x40000
#define CMD_LAN_HOST_OS_GET					0x80000
#define CMD_LAN_HOST_INFORMATION_CHANGE_GET	0x100000
#define CMD_LAN_HOST_LINKCHANGE_PORT_SET	0x200000

int set_lanhost_max_number(unsigned int number);
int get_lanhost_max_number(unsigned int * number);
int get_lanhost_number(unsigned int * number);
int set_controllist_max_number(unsigned int number);
int get_controllist_max_number(unsigned int * number);
int get_controllist_number(unsigned int * number);
int set_lanhost_control_status(unsigned char *pMacAddr, unsigned char controlStatus);
int get_lanhost_control_status(unsigned char *pMacAddr, unsigned char * controlStatus);
int set_lanhost_access_right(unsigned char *pMacAddr, unsigned char internetAccessRight, unsigned char storageAccessRight);
int get_lanhost_access_right(unsigned char *pMacAddr, unsigned char * internetAccessRight, unsigned char * storageAccessRight);
int set_lanhost_device_type(unsigned char *pMacAddr, unsigned char devType);
int get_lanhost_device_type(unsigned char *pMacAddr, unsigned char *devType);
int set_lanhost_brand(unsigned char *pMacAddr, unsigned char *brand);
int get_lanhost_brand(unsigned char *pMacAddr, unsigned char *brand);
int set_lanhost_model(unsigned char *pMacAddr, unsigned char *model);
int get_lanhost_model(unsigned char *pMacAddr, unsigned char *model);
int set_lanhost_OS(unsigned char *pMacAddr, unsigned char *os);
int get_lanhost_OS(unsigned char *pMacAddr, unsigned char *os);
int get_lanhost_information_change(lanHostInfo_t *pLanDeviceInfo, int num);
int set_lanhost_linkchange_port_status(int portIdx);
int sendMessageToLanNetInfo(LANNETINFO_MSG_T *msg);
int readMessageFromLanNetInfo(struct lanNetInfoMsg *qbuf);
#endif	//CONFIG_USER_LANNETINFO

int setDnsIPForLanPC(unsigned char enable, struct in_addr ip);

#define BOOTLOADER_SW_ACTIVE   "sw_active"
#define BOOTLOADER_SW_VERSION  "sw_version"

#ifdef CONFIG_RTK_HOST_SPEEDUP
int add_host_speedup(struct in_addr rip, unsigned short rport, struct in_addr lip, unsigned short lport);
int del_host_speedup(struct in_addr rip, unsigned short rport, struct in_addr lip, unsigned short lport);
#if defined(CONFIG_SMP) && (CONFIG_NR_CPUS > 1)
#if !defined __USE_GNU
# define CPU_ZERO_S(setsize, cpusetp) \
  do {									      \
    size_t __i;								      \
    size_t __imax = (setsize) / sizeof (__cpu_mask);			      \
    __cpu_mask *__bits = (cpusetp)->__bits;				      \
    for (__i = 0; __i < __imax; ++__i)					      \
      __bits[__i] = 0;							      \
  } while (0)

# define CPU_SET_S(cpu, setsize, cpusetp) \
   ({ size_t __cpu = (cpu);						      \
      __cpu < 8 * (setsize)						      \
      ? (((__cpu_mask *) ((cpusetp)->__bits))[__CPUELT (__cpu)]		      \
	 |= __CPUMASK (__cpu))						      \
      : 0; })

# define CPU_ISSET_S(cpu, setsize, cpusetp) \
   ({ size_t __cpu = (cpu);						      \
      __cpu < 8 * (setsize)						      \
      ? ((((__cpu_mask *) ((cpusetp)->__bits))[__CPUELT (__cpu)]	      \
	  & __CPUMASK (__cpu))) != 0					      \
      : 0; })
#endif
int get_gmac_intrrupt_mapping_processor(void);
#endif
#endif /*CONFIG_RTK_HOST_SPEEDUP*/

#ifdef CTC_DNS_TUNNEL
/* For DBUS API */
typedef struct ctc_dns_tunnel_node_s
{
	char *server_ip;
	char *domain;
	struct ctc_dns_tunnel_node_s *next;
}dns_tunnel_node_t;

int attach_wan_dns_tunnel(dns_tunnel_node_t *node);
int detach_wan_dns_tunnel(dns_tunnel_node_t *node);
int get_wan_dns_tunnel(dns_tunnel_node_t **tunnels);
#endif

#ifdef CONFIG_USER_DBUS_CTC_IGD
struct ctc_igd_msgbuf
{
    long mtype;
    int type;
        int mib_id;
    int index;
};

struct ctc_igd_sys_msgbuf
{
    long mtype;
    int arg1;
        int arg2;
    char mtext[4096];
};

enum {CTC_IGD_SYSTEM_LAN_INFO=0, CTC_IGD_SYSTEM_WAN_INFO, CTC_IGD_SYSTEM_WIFI_INFO, CTC_IGD_SYSTEM_VOIP_INFO};
#define CTC_IGD_MSG_FROM_MIB 333
#define CTC_IGD_MSG_FROM_SYSTEMD 222
#define CTC_IGD_MSG_RECV 245
#define CTC_IGD_SHM_KEY 4321

int send_msg_ctc_igd_server(struct ctc_igd_sys_msgbuf *pMsg);
#endif

#ifdef SUPPORT_INCOMING_FILTER
#define IN_COMING_API_ADD (1)
#define IN_COMING_API_DEL (2)
#define IN_COMING_RET_SUCCESSFUL (0)
#define IN_COMING_RET_FAIL (-1)
#define IN_COMING_IP_MAX_LEN (64)
#define IN_COMING_CMD_BUF_MAX_LEN (1024)
#define IN_COMING_IS_IPV4 (1)
#define IN_COMING_IS_IPV6 (2)

typedef enum
{
	IN_COMING_PROTO_TCP_E = 0,
	IN_COMING_PROTO_UDP_E ,
	IN_COMING_PROTO_TCP_AND_UDP_E ,
} in_coming_proto_e;

typedef enum
{
	IN_COMING_INTERFACE_WAN_E = 0,
	IN_COMING_INTERFACE_LAN_E,
} in_coming_interface_e;

typedef struct
{
	char remoteIP[IN_COMING_IP_MAX_LEN];
	in_coming_proto_e protocol;
	unsigned int port;
	in_coming_interface_e interface;
} smart_func_in_coming_val;

int smart_func_add_in_coming_api(int cmd, smart_func_in_coming_val *in_coming_val, char *errdesc);
#endif

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

#ifdef CONFIG_USER_BEHAVIOR_ANALYSIS
void setup_behavior_analysis(void);
#endif

typedef enum { DBUS_DNS=0 } DBUS_CALLBACK_ID_T;

struct	dbusCallout {
	int id;
    int type;
	int pid;
    struct		dbusCallout *c_next;
};

#ifdef SUPPORT_WEB_PUSHUP
typedef enum
{
	FW_UPGRADE_STATUS_NONE=0,
	FW_UPGRADE_STATUS_VER_INCORRECT,
	FW_UPGRADE_STATUS_FAIL,
	FW_UPGRADE_STATUS_SPACE_INVALID,
	FW_UPGRADE_STATUS_VER_EXIST,
	FW_UPGRADE_STATUS_OTHERS,
	FW_UPGRADE_STATUS_PROGGRESSING,
	FW_UPGRADE_STATUS_SUCCESS
} FW_UPGRADE_STATUS_T;
#endif

#ifdef CONFIG_USER_DBUS_PROXY
#define M_dbus_proxy_pid "/tmp/dbusproxy_pid"
#define DBUS_STRING_LEN 64

#ifdef CONFIG_MIDDLEWARE
#define MANUFACTURER_STR	"REALTEK"
#else
#define MANUFACTURER_STR	"REALTEK SEMICONDUCTOR CORP."
#endif
#define MANUFACTUREROUI_STR	"00E04C"
#define SPECVERSION_STR		"1.0"
#ifdef CONFIG_RTL8686
#define HWVERSION_STR           "V101"
#else
#define HWVERSION_STR		"8671x"
#endif

//#ifdef SUPPORT_MCAST_TEST
#define MCDIAG_RESULT_NO_IPTV_CONNECTION ("NO_IPTV_CONNECTION")
#define MCDIAG_RESULT_IPTV_CONNECTION_EXIST ("IPTV_CONNECTION_EXIST")
#define MCDIAG_RESULT_IPTV_DISCONNECT ("IPTV_DISCONNECT")
#define MCDIAG_RESULT_IPTV_CONNECT ("IPTV_CONNECT")
#define MCDIAG_RESULT_INVALID_MULTIVLAN ("INVALID_MULTIVLAN")
#define MCDIAG_RESULT_VALID_MULTIVLAN ("VALID_MULTIVLAN")
#define MCDIAG_RESULT_IPTV_BUSSINESS_NOK ("IPTV_BUSSINESS_NOK")
#define MCDIAG_RESULT_IPTV_BUSSINESS_OK ("IPTV_BUSSINESS_OK")
#define ROMEDRIVER_IGMP_PROC "/proc/rg/igmpSnooping"
#define ROMEDRIVER_IGMP_INFO "address"

#define MCDIAG_RESULT_IPTV_INFO_GET_ERRS ("iptv info get failed")

#define NETCORE_SMT_HGU_MCDIAG_RESULT_LEN 32
#define NETCORE_SMT_HGU_MCDIAG_FAIL_REASON_LEN 32
#define NETCORE_SMT_HGU_MCDIAG_START  0x0001

#define NETCORE_SMT_HGU_OK 0x0000
#define NETCORE_SMT_HGU_FAIL 0x0001

#define M_dbus_proxy_pid "/tmp/dbusproxy_pid"
typedef struct
{
    int  mcdiagstatus;
    char mcdiagresult[NETCORE_SMT_HGU_MCDIAG_RESULT_LEN];
	char failreason[NETCORE_SMT_HGU_MCDIAG_FAIL_REASON_LEN];
}netcore_smt_hgu_mcdiag_t;
//#endif
/*gaozm add for mcdiag*/

/*james : mib 2 dbusproxy notify */
#ifndef DATA_LEN
    #define DATA_LEN 1024
#endif

typedef struct{
    int   table_id;
    int   Signal_id;
    int   iPid;       /**process id **/
    char  content[DATA_LEN];
}mib2dbus_notify_app_t;

extern int mib_2_dbus_notify_dbus_api(mib2dbus_notify_app_t *notify_app);

typedef enum{
    e_dbus_proxy_signal_mib_list = 0x9000,
    e_dbus_signal_mib_set,
    e_dbus_signal_mib_chain_add,
    e_dbus_signal_mib_chain_delete,
    e_dbus_signal_mib_chain_update,

    e_dbus_proxy_signal_mib_list_end
}e_notify_mib_signal_id;

typedef enum{
    e_table_list_action_init = 0x6000,
    e_table_list_action_retrieve,

    e_table_list_action_end
}e_table_list_action_T;
#endif

int getIPaddrInfo(MIB_CE_ATM_VC_Tp entryp, char *ipaddr, char *netmask, char *gateway);
#ifdef CONFIG_IPV6
int getIPv6addrInfo(MIB_CE_ATM_VC_Tp entryp, char *ipaddr, char *netmask, char *gateway);
#endif

#ifdef CONFIG_E8B
enum PWR_LED_CTRL_OP_t
{
	PWR_LED_OFF=0,
	PWR_LED_ON,
	PWR_LED_BLINKING,
	PWR_LED_STOP_BLINKING
};
#endif

#if defined(CONFIG_PON_LINKCHANGE_EVENT) || defined(CONFIG_PON_CONFIGURATION_COMPLETE_EVENT)
#define OMCI_CONFIG_COMPELETE_STR	"OMCI_Config_is_Compelete"
#endif

#if defined(CONFIG_CMCC) || defined(CONFIG_CU)//iulian send socket Message to OSGI management server
int sendMessageOSGIManagement(char*, char*);
#endif

#ifdef CONFIG_USER_RTK_OMD
#define UNKNOWN_REBOOT			0x00
#define ITMS_REBOOT				0x01
#define TELECOM_WEB_REBOOT		0x02
#define DBUS_REBOOT				0x04
#define TERMINAL_REBOOT			0x08
#define POWER_REBOOT			0x10
#define EXCEP_REBOOT			0x20
#define REBOOT_FLAG				0x80
#endif

#ifdef _PRMT_X_CMCC_SECURITY_
int get_Templates_entry_by_inst_num(unsigned int num, MIB_PARENTALCTRL_TEMPLATES_Tp pEntry, int *idx);
#endif

/***************************************************************************/
#ifdef CONFIG_USER_XMLCONFIG
extern const char shell_name[];
#endif

int mib_to_string(char *string, const void *mib, TYPE_T type, int size);
int string_to_mib(void *mib, const char *string, TYPE_T type, int size);
int _load_xml_file(const char *loadfile, CONFIG_DATA_T cnf_type, unsigned char flag);
int _save_xml_file(const char *savefile, CONFIG_DATA_T cnf_type, unsigned char flag);
void print_chain_member(FILE *fp, char *format_str, mib_chain_member_entry_T * desc, void *addr, int depth);

int before_upload(const char *fname);
int after_download(const char *fname);

int getIpRange(char *src, char* start, char*end);

#define CWMP_START_WAN_LIST "/var/cwmp_start_wan_list"

#ifdef CONFIG_E8B
#define PROC_UNI_CAPABILITY "/proc/realtek/uni_capability"
void setupUniPortCapability(void);
int getUniPortCapability(int logPortId);
#endif

#ifdef MAC_FILTER_SRC_WHITELIST
#if defined(CONFIG_RTL9607C_SERIES) || defined(CONFIG_RG_G3_SERIES)
#define WHITELIST_WAY WHITELIST_USING_ACL_RULE
#else
#define WHITELIST_WAY WHITELIST_USING_LUT_TBL
#endif
#endif

#ifdef WLAN_SUPPORT
#include "subr_wlan.h"
#endif

unsigned int getInternetIPv4WANIfindex(void);
char *trim_white_space(char *str);
int add_dsldevice_on_hosts(void);
int reloadDnsRelay(void);
int applyPortBandWidthControl(void);
int base64_decode(void *dst,char *src,int maxlen);
int bootSelfCheck(void);
#ifdef CONFIG_USER_L2TPD_L2TPD
int Check_L2TP_Route_DIP(unsigned char *tunnelName,unsigned int ipv4_addr1,unsigned int ipv4_addr2);
int Check_L2TP_Route_SMAC(unsigned char *tunnelName, unsigned char* sMAC_addr);
int Check_L2TP_Route_URL(unsigned char *tunnelName,char *url);
int NF_Set_L2TP_Dynamic_URL_Route(char *name, struct in_addr addr);
int NF_Set_L2TP_Policy_Route(unsigned char *tunnelName, ATTACH_MODE_T attach_mode);
MIB_L2TP_T *getL2TPEntryByIfIndex(unsigned int ifIndex, MIB_L2TP_T *p);
int getIfIndexByL2TPName(char *pIfname);
int NF_l2tp_ip_chagne(char *ifname, struct in_addr *new_ip, struct in_addr *ifa_local);
#endif
int Check_PPTP_Route_DIP(unsigned char *tunnelName,unsigned int ipv4_addr1,unsigned int ipv4_addr2);
int Check_PPTP_Route_SMAC(unsigned char *tunnelName, unsigned char* sMAC_addr);
int Check_PPTP_Route_URL(unsigned char *tunnelName,char *url);
int delcttypevalue(MIB_CE_IP_QOS_T *p, int typeinst);
int delete_dsldevice_on_hosts(void);
int Del_L2TP_Route_DIP(unsigned char *tunnelName,unsigned int ipv4_addr1,unsigned int ipv4_addr2);
int Del_L2TP_Route_SMAC(unsigned char *tunnelName, unsigned char* sMAC_addr);
int Del_LT2P_Route_URL(unsigned char *tunnelName,char *url);
int Del_PPTP_Route_DIP(unsigned char *tunnelName,unsigned int ipv4_addr1,unsigned int ipv4_addr2);
int Del_PPTP_Route_SMAC(unsigned char *tunnelName, unsigned char* sMAC_addr);
int Del_PPTP_Route_URL(unsigned char *tunnelName,char *url);
int epon_getAuthState(int llid);
int find_wanif_by_vlanid(unsigned short latvid, MIB_CE_ATM_VC_T* vc_Entry);
int gen_ctcom_dhcp_opt(unsigned char type, char *output, int out_len);
int getEponONUState(unsigned int llidx);
int getLedStatus(unsigned char* status);
int getOneDhcpClient(char **ppStart, unsigned long *size, char *ip, char *mac, char *liveTime);
int getQosEnable(void);
int getQosRuleNum(void);
int getWanStatus(struct wstatus_info *sEntry, int max);
int ifIPv6LanPrefixConfigured(void);
int ifPrefixUsingPD(void);
int init_alarm_numbers(void);
int isIPAddr(char * IPStr);
int is_terminal_reboot(void);
int NF_Flush_L2TP_Dynamic_URL_Route(unsigned char *tunnelName);
int NF_Flush_L2TP_Route(unsigned char *tunnelName);
int NF_Flush_PPTP_Dynamic_URL_Route(unsigned char *tunnelName);
int NF_Flush_PPTP_Route(unsigned char *tunnelName);
int NF_Init_VPN_Policy_Route(unsigned char *tunnelName);
int registerDbusGetInfoCallbackFunc(int type, int pid, void *arg);
int set_dhcp_source_route(int fh, MIB_CE_ATM_VC_Tp pEntry, int is_diag);
int setLedStatus(unsigned char status);
int setupNtp(int type);
int smartHGU_Samba_Initialize(void);
int startHomeNas(void);
int startNetlink(void);
int update_appbased_qos_tbl(void);
int updatecttypevalue(MIB_CE_IP_QOS_T *p);
int updateMIBforQosMode(unsigned char *qosMode);
int upgradeWebSet(int enable);
int write_omd_reboot_log(unsigned int flag);
unsigned int get_omci_complete_event_shm( void );
unsigned int hextol(unsigned char *hex);
void apply_accessRight(unsigned char enable);
void apply_maxBandwidth(void);
void base64_encode(unsigned char *from, char *to, int len);
void callDbusGetInfoCallbackFunc(int type);
void calltimeout(void);
void changeMacFormat(char *str, char s, char d);
void changeMacToString(unsigned char *mac, unsigned char *macString);
void changeStringToMac(unsigned char *mac, unsigned char *macString);
void check_inform_status(int firstflag);
void clear_maxBandwidth(void);
void fillcharZeroToMacString(unsigned char *macString);
void formatPloamPasswordToHex(char *src, char* dest);
void ftpd_account_change(void);
void fwupgrade_pushweb_set(int enable, int width, int height, int top, int left, char * url, int second, int count);
void get_dns_by_wan(MIB_CE_ATM_VC_T *pEntry, char *dns1, char *dns2);
void get_poninfo(int s,double *buffer);
#ifdef CONFIG_E8B
void power_led_control_operation(enum PWR_LED_CTRL_OP_t operation);
#endif
int check_default_route_exist(void);
int is_default_route(char *ifname);
int set_default_route(char *ifname, int set);
int update_default_route(char *ifname);
int remove_and_update_default_route(char *ifname);
void rtl8670_AspInit(void);
void SaveLOIDReg(void);
void setupBridgeIPv4IPv6Filter( MIB_CE_ATM_VC_Tp pEntry, unsigned char isadd );
void setupLBD(void);
#ifdef CONFIG_YUEME
void smartHGU_ftpserver_init_api(void);
void smartHGU_ftpserver_account_update(void);
#endif
void smbd_account_change(void);
void startDdnsc(struct ddns_info tinfo);
void startPushwebTimer(unsigned int time);
void startSNAT(void);
void startUpgradeFirmware(int needreboot);
void translate_control_code(char *buffer);
void unregisterDbusGetInfoCallbackFunc(int id);
void updateScheduleCrondFile(char *pathname, int startup);
extern int rtk_env_get(const char *name, char *buf, unsigned int buflen);
extern int rtk_env_set(const char *name, const char *value);
#ifdef CONFIG_USER_LANNETINFO
int get_lan_net_info(lanHostInfo_t **ppLANNetInfoData, unsigned int *pCount);
#endif
#if defined(CONFIG_USER_PPTP_CLIENT_PPTP) && defined(CONFIG_USER_L2TPD_L2TPD)
int request_vpn_accpxy_server( gdbus_vpn_tunnel_info_t *vpn_tunnel_info, char *reason );
int NF_Set_PPTP_Policy_Route(unsigned char *tunnelName, ATTACH_MODE_T attach_mode);
int get_attach_pattern_by_mode(gdbus_vpn_connection_info_t *vpn_connection_info,unsigned char *attach_pattern[],unsigned char *reason);
int NF_Update_PPTP_Ip_Route_Table(unsigned char *tunnelName, unsigned int ifIndex);
MIB_PPTP_T *getPPTPEntryByIfIndex(unsigned int ifIndex, MIB_PPTP_T *p);
int getIfIndexByPPTPName(char *pIfname);
int NF_pptp_ip_chagne(char *ifname, struct in_addr *new_ip, struct in_addr *ifa_local);
#endif
#ifdef SUPPORT_WEB_PUSHUP
FW_UPGRADE_STATUS_T firmwareUpgradeConfigStatus( void );
void firmwareUpgradeConfigStatusSet( FW_UPGRADE_STATUS_T status );
#endif
#ifdef CONFIG_USER_DBUS_PROXY
int mib_notify_table_list_handle_func(int table_id, e_table_list_action_T action);
void send_notify_msg_dbusproxy(int id, e_notify_mib_signal_id signal_id, int recordNum);
#endif
#ifdef CONFIG_GPON_FEATURE
int getGponONUState(void);
void checkOMCI_startup(void);
extern int32_t rtk_gpon_usFecSts_get(int32_t* en);
extern int32_t rtk_gpon_dsFecSts_get(int32_t* pEn);
#endif
#if defined CONFIG_IPV6 || defined CONFIG_RTK_L34_ENABLE
int getifip6(char *ifname, unsigned int addr_scope, struct ipv6_ifaddr *addr_lst, int num);
#endif

#ifdef CONFIG_USER_OPENJDK8
int setupOsgiAutoStart(void);
#endif

#if (defined(CONFIG_CMCC) || defined(CONFIG_CU)) && defined(CONFIG_IPV6)
int ipv6_binding_update(void);
int set_vlan_cfg_action(int v4OldID, int v6OldID);
#endif

#ifdef SUPPORT_DNS_FILTER
#define DNSFILTERFILENAME "/var/dnsfilter_record"
#define TMPDNSFILTERFILENAME "/var/tmp_dnsfilter_record"
int UpdateDNSFilterBlocktime(char *name, char *url, int blocktime);
int getDNSFilterBlockedTimes(char *name, char *url);
#endif

#ifdef SUPPORT_URL_FILTER
int parse_ur_filter(char *url, char *key, int *port);
void set_url_filter(void);
int restart_urlfilter(void);
#endif

#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
int getWebLoidPageEnable(void);
int getWebPasswordPageEnable(void);
#else
void data_base64decode(unsigned char *input, unsigned char *output);
#endif
#ifdef CONFIG_USER_OPENJDK8
void setupOsgiPrebundlePath(void);
#endif

#ifdef CONFIG_YUEME
int checkValidRedirect(char*redirecturl, char** checklist);
int doPreRestoreFunc(void );
#endif
#ifdef _PRMT_X_CT_COM_IPoEDiagnostics_
	/***** IPoE Emulators *****/
typedef struct ipoe_diag_s
{
	int DiagnosticsState;		
	char		*WANInterface;
	int 	wanIfIndex;
	unsigned char usermac[6];
	unsigned char VendorClassID[64+1];
	unsigned char PingDestIPAddress[16+1];
	unsigned int PingNumberOfRepetitions;
	unsigned int Timeout;
	unsigned int SuccessCount;
	unsigned int FailureCount;
	unsigned int AverageResponseTime;
	unsigned int MinimumResponseTime;
	unsigned int MaximumResponseTime;
	struct DIAG_RESULT_T result;	
	pthread_t tid;	
}ipoe_diag_t;

#define IPOE_EMU_PING_DIAG_OUTPUT_FILENAME "/tmp/ipoe_emu_ping_diag_output"

extern int isSimuInterface ;
#ifdef _PRMT_X_CT_COM_IPoEDiagnostics_
#define SIMU_INTERFACE_OFFSET 8
#endif

#endif

#ifdef CONFIG_YUEME
#ifdef RESERVE_KEY_SETTING
#define RESET_CS_FLAG_FILE "/var/config/reset_cs_flag"
void reset_check(int flag);
#endif
#endif

struct process_nice_table_entry {
	unsigned char	processName[64];
	unsigned int	nice; //-20~19
};
#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_
int IS_PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_ON(int item_bit);
int SET_PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM(int item_bit, int enable);
#endif
#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_SEREnable_
unsigned int getSER(int flag);
void start_record_ser_errorCode(int flag);
#endif
#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_ErrorCodeEnable_
unsigned int getErrorCode(int flag);
#endif
#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_PLREnable_
unsigned int getPLR(int flag);
#endif
#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_PacketLostEnable_
unsigned int getPacketLost(int flag);
#endif
#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_
int getAllWirelessChannelOnce(void);
#endif

#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_AllWirelessChannelEnable_
int getWlan0AllChannel(char *allChannelBuf, int size);
#endif

#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_BestWirelessChannelEnable_
int getWlan0BestChannel(char *bestChannelBuf,int size);
#endif

#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_WirelessBandwidthEnable_
int getWlan0BandWidth(void);
#endif

#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_WirelessChannelNumberEnable_
int getWlan0CurChannel(char *curChannel);
#endif

#ifdef  _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_WirelessPowerEnable_
int getWlan0Power(void);
#endif

#ifdef  _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_QosTypeEnable_
int getWlan0QosType(void);
#endif

#ifdef  _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_WirelessTypeEnable_
int getWlan0WirelessType(char* curWirlessType, int size);
#endif

#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_WorkingTimeEnable_
int getSysWorkingTime(void);
#endif

#ifdef _PRMT_SC_CT_COM_GroupCompanyService_Plugin_
int getPluginNameAndState(int instnum, char *pluginName, unsigned int *pluginState);
#endif

#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_PluginUpNumberEnable_
unsigned int getPluginUpNumber(void);
#endif

#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_PluginAllNumberEnable_
unsigned int getPluginAllNumber(void);
#endif

#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_RegisterNumberEnable_
int getRegisterNumberITMS(void);
int addRegisterNumberITMS(void);
int defRegisterNumberITMS(void);
int getDHCPRegisterNumber(void);
void clearDHCPRegisterNumber(void);
#endif
#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_RegisterSuccessNumberEnable_
int getRegisterSuccNumITMS(void);
int addRegisterSuccNumITMS(void);
int defRegisterSuccNumITMS(void);
int clearDHCPSuccessNumber(void);
int getDHCPSuccessNumber(void);
int addDHCPSuccessNumber(void);
#endif
#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_RegisterNumberEnable_
#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_RegisterSuccessNumberEnable_
int getRegisterOLTNumber(void);
int getRegisterOLTSuccNumber(void);
#endif
#endif
#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_MulticastNumberEnable_
int getMulticastNumber(void);
#endif
#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_WLANDeviceMACEnable_
int getWLANDeviceMAC(char *deviceInfo, int size);
#endif
#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_LANDeviceMACEnable_
int getLANDeviceMAC(char *deviceInfo, int size);
#endif
#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_LANxStateEnable_
int getLANxState(char *state, int size);
#endif
#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_TEMPEnable_
int getTEMP(double *buf);
#endif
#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_OpticalInPowerEnable_
int getOpticalInPower(char *buf);
#endif
#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_OpticalOutPowerEnable_
int getOpticalOutPower(char *buf);
#endif
#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_RoutingModeEnable_
int getRoutingMode(void);
#endif
#ifdef TERMINAL_INSPECTION_SC
int getLANxStateTerminal(char *state, int size);
#endif

#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_UpDataEnable_
int getUpData(char *data, int size, int clear);
#endif

#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_DownDataEnable_
int getDownData(char *data, int size, int clear);
#endif

#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_DevicePacketLossEnable_
int getDevicePacketLoss(char *pktLoss, int size);

struct stLanDevicePktLoss
{
	unsigned int ip;  //network order;
	int pktLoss;  //can set -1;
	int averagDelay; //can set -1;
	unsigned char clinetMac[6];
	unsigned short reserved;
};
#endif

#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_LANxWorkBandwidthEnable_
int getLANxWorkBandwidth(char *bandwith, int size);
#endif
#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_AllDeviceNumberEnable_
int getAllDeviceNumber(void);
#endif

#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_CPURateEnable_
int getCPURate(unsigned int *CPURate);
#endif

#ifdef  _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_MemRateEnable_
int getMemRate(unsigned int *MemRate);
#endif

#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_DialingNumberEnable_
int getPppoeDialingNumber(void);
#endif

#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_DialingErrorEnable_
int getPppoeDialingError(char *DialingError);
#endif

#if 1
#define LAN_DEVICE_PKT_LOSS_FILENAME "/tmp/lan_device_pkt_loss"

typedef struct cwmp_msg2ClientData_s {
 long mtype;
 char msgqData[32]; 
} cwmp_msg2ClientData_t;
#endif
int lock_file_by_flock(const char *filename, int wait);
int unlock_file_by_flock(int lockfd);

#if defined(CONFIG_YUEME)
typedef struct _ipPortRange {
	short int sin_family;
	unsigned char start_addr[16];
	unsigned char end_addr[16];
	unsigned short int start_port;
	unsigned short int end_port;
	unsigned short eth_protocol;
} ipPortRange;

typedef struct _wl_ipport_rule {
	ipPortRange ipport;
	unsigned int wlan_idx_mask;
	unsigned char action;
	struct _wl_ipport_rule *next;
} wl_ipport_rule;
int RTK_RG_Wifi_AccessRule_ACL_Rule_set(wl_ipport_rule *rule);
int setup_wlan_accessRule_netfilter_init(void);
int setup_wlan_accessRule_netfilter(char *ifname, MIB_CE_MBSSIB_Tp pEntry);
int setup_wlan_accessRule(void);
#endif

#ifdef DHCPS_DNS_OPTIONS 
int get_network_dns(char *dns1, char *dns2);
#endif

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

#ifdef CTC_TELNET_SCHEDULED_CLOSE
extern struct webserver_callout sch_telnet_ch;
void schTelnetCheck(void);
#endif

#ifdef CONFIG_CT_AWIFI_JITUAN_SMARTWIFI
char *geAwifiVersion(char *buf, int len);
int getgwaddrFromaWiFiConf(char *gwaddr);
int getgwportFromaWiFiConf(int *gwport);
int parse_ServerHostname(const char *filename, char *ServerStr, char *hostname);
int parse_ServerHttpPort(const char *filename, char *ServerStr, int *port);
void free_server_setting(void);
int getLineNumber(char *ServerStr, char *TypeStr);
void addServerSetting(int linenum, char *newconf);
int UpdateAwifiConfSetting(void);
int awifiAddFwRuleChain(void);
#endif

#ifdef CONFIG_YUEME
int get_ftpUserAccount(char *username, char *password);
int set_ftpUserAccount(char *username, char *password);
int get_ftp_enable(void);
int set_ftp_enable(int data);
#endif

#ifdef CONFIG_USER_CUMANAGEDEAMON
#define CUMANAGE_LOID_FILE		"/tmp/cumanage_loid"
#define CUMANAGE_GUESTSSID_FILE		"/tmp/wlanguestssidrestart"     //set guest ssid restart
#define CUMANAGE_PPPOEACCOUNT_FILE		"/tmp/wanpppoerestart"          // set pppoe for wan restart
#define CUMANAGE_LANPARM_FILE		"/tmp/lanparmrestart"            // set lan parm for dhcp restart
#define CUMANAGE_GUESTSSIDREMAIN_FILE		"/tmp/wlanguestremain"            // set lan parm for dhcp restart
extern struct webserver_callout cuManage_ch;
void cuManageSechedule(void *dummy);

enum
{
	eUserReg_REGISTER_DEFAULT=0,
	eUserReg_REGISTER_REGISTED,
	eUserReg_REGISTER_TIMEOUT,
	eUserReg_REGISTER_NOMATCH_NOLIMITED,
	eUserReg_REGISTER_NOMATCH_LIMITED,
	eUserReg_REGISTER_NOACCOUNT_NOLIMITED,
	eUserReg_REGISTER_NOACCOUNT_LIMITED,
	eUserReg_REGISTER_NOUSER_NOLIMITED,
	eUserReg_REGISTER_NOUSER_LIMITED,
	eUserReg_REGISTER_OLT,
	eUserReg_REGISTER_OLT_FAIL,
	eUserReg_REGISTER_OK_DOWN_BUSINESS,
	eUserReg_REGISTER_OK,
	eUserReg_REGISTER_OK_NOW_REBOOT,
	eUserReg_REGISTER_POK,

	eeUserReg_REGISTER_FAIL,

	eUserReg_End /*last one*/
};

#define PON_HISTORY_TRAFFIC_MONITOR
#if defined(PON_HISTORY_TRAFFIC_MONITOR)
#define PON_HISTORY_TRAFFIC_MONITOR_INTERVAL 300 //5minutes
#define PON_HISTORY_TRAFFIC_MONITOR_DURATION (72*60*60) // 72 hours
#define PON_HISTORY_TRAFFIC_MONITOR_ITEM_MAX (PON_HISTORY_TRAFFIC_MONITOR_DURATION/PON_HISTORY_TRAFFIC_MONITOR_INTERVAL)

extern struct webserver_callout pon_traffic_monitor_ch;
void pon_traffic_monitor(void *dummy);
#endif
#endif

#ifdef CONFIG_RTL_WAPI_SUPPORT
extern struct webserver_callout ntp_ch;
void ntpSechedule_wapi(void *null);
#endif


#ifdef _PRMT_C_CU_LOGALARM_
#define ALARM_SERIOUS	1
#define ALARM_MAJOR	2
#define ALARM_MINOR	3

#define ALARM_RECOVER		1
#define ALARM_UNRECOVER	2
#define ALARM_RECOVERED	3

#define ALARM_REBOOT				104001
#define ALARM_PORT_UNAVAILABLE	104006
#define ALARM_WLAN_ERROR			104012
#define ALARM_CPU_OVERLOAD		104030
#define ALARM_ADMINLOGIN_ERROR	104032
#define ALARM_BIT_ERROR			104033
#define ALARM_ENCRYPT_FAIL			104034
#define ALARM_BANDWITH			104035
#define ALARM_FILESERVER_WRONG			104050
#define ALARM_FILESERVER_AUTHERROR		104051
#define ALARM_DOWNLOAD_TIMEOUT			104052
#define ALARM_FILESERVER_NOFILE			104053
#define ALARM_UPGRADECONFIG_FAIL			104054
#define ALARM_BACKUPCONFIG_FAIL			104055
#define ALARM_RESTOREUPCONFIG_FAIL		104056
#define ALARM_NOTAVIL_CONFIG				104057
#define ALARM_UPGRADE_FW_FAIL			104058
#define ALARM_FLASH_NOTENOUGH			104059
#define ALARM_USER_UPGRADE_FW_FAIL		104060
#define ALARM_LOG_UPLOAD_FAIL				104061
#define ALARM_EPG_SERVER_ERROR			104122
#define ALARM_DDNS_SERVER_ERROR			104142
#define ALARM_DDNS_AUTH_FAIL				104143
#define ALARM_VIDEO_DEVICE_NOTSUPPORT			104160

#define LOG_ALARM_PATH "/var/config/log_alarm.txt"
#define TEMP_LOG_ALARM_PATH "/var/config/temp_log_alarm.txt"

typedef struct alarm_record
{
  int	alarmid;
  int	alarmcode;
  int alarmRaisedTime;
  int	cleartime;
  int	alarmstatus;
  int	perceivedseverity;
  char   logStr[64];
}ALARMRECORD_T, *ALARMRECORD_TP;
#endif

int isIGMPSnoopingEnabled(void);
int isMLDSnoopingEnabled(void);
int isIgmproxyEnabled(void);
int isMLDroxyEnabled(void);
void checkIGMPMLDProxySnooping(int isIGMPenable, int isMLDenable, int isIGMPProxyEnable, int isMLDProxyEnable);

#endif // INCLUDE_UTILITY_H
