/*
 *      Web server handler routines for NET
 *      Authors:
 *
 */

/*-- System inlcude files --*/
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <semaphore.h>
#ifdef VOIP_SUPPORT
#include "web_voip.h"
#endif
#ifdef EMBED
#include <linux/config.h>
#else
#include "../../../uClibc/include/linux/autoconf.h"
#endif
#include <config/autoconf.h>
#if defined(CONFIG_EPON_FEATURE) && defined(CONFIG_RTK_L34_ENABLE)
#include <rtk_rg_define.h>
#endif
#ifdef CONFIG_RTK_OMCI_V1
#include <omci_api.h>
#include <gos_type.h>
#endif

#ifdef CONFIG_EPON_FEATURE
#include <rtk/epon.h>
#endif

#ifdef CONFIG_MIDDLEWARE
#include <rtk/midwaredefs.h>
#endif

#include "cJSON.h"
#include "../webs.h"
#include "fmdefs.h"
#include "mib.h"
#include "utility.h"
#include "../../port.h"
#include "../rtusr_rg_api.h"
// Mason Yu. t123
#include "webform.h"
#define UBR_WITHOUT_PCR		0
#define UBR_WITH_PCR		1
#define CBR			2
#define NO_RT_VBR		3
#define RT_VBR			4

#ifdef CONFIG_YUEME
#define MAX_SRV_NUM		12
#else
#define MAX_SRV_NUM		8
#endif
int web2mib_srv[MAX_SRV_NUM] = {
	X_CT_SRV_TR069|X_CT_SRV_INTERNET,
	X_CT_SRV_INTERNET,
	X_CT_SRV_TR069,
	X_CT_SRV_OTHER,
	X_CT_SRV_VOICE,
	X_CT_SRV_TR069|X_CT_SRV_VOICE,
	X_CT_SRV_VOICE|X_CT_SRV_INTERNET,
	X_CT_SRV_TR069|X_CT_SRV_VOICE|X_CT_SRV_INTERNET,
#ifdef CONFIG_YUEME
	X_CT_SRV_SPECIAL_SERVICE_1,
	X_CT_SRV_SPECIAL_SERVICE_2,
	X_CT_SRV_SPECIAL_SERVICE_3,
	X_CT_SRV_SPECIAL_SERVICE_4,
#endif
};

typedef enum {
	CONN_DISABLED=0,
	CONN_NOT_EXIST,
	CONN_DOWN,
	CONN_UP
} CONN_T;

#ifdef DEFAULT_GATEWAY_V1
static int dr=0, pdgw=0;
#endif

static char wanif[10];
static const char IF_UP[] = "up";
static const char IF_DOWN[] = "down";
static const char IF_NA[] = "n/a";
static const char IF_DISABLED[] = "Disabled";
static const char IF_ENABLE[]="Enable";
static const char IF_ON[] = "On";
static const char IF_OFF[] = "Off";

static unsigned char base64chars[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                              "abcdefghijklmnopqrstuvwxyz0123456789+/=";

static int base64charsIndex(unsigned char c){
	int i=0;
	while(i<65){
		if(base64chars[i]==c)
			return i;
		i++;
	}
}

static void  data_base64encode(unsigned char *input, unsigned char *output)
{
	unsigned char chr1, chr2, chr3;
	unsigned char enc1, enc2, enc3, enc4;
	int i=0, j=0, len=strlen(input);


	for (i = 0; i <= len - 3; i += 3)
	{
		output[j++] = base64chars[(input[i] >> 2)];
		output[j++] = base64chars[((input[i] & 3) << 4) | (input[i+1] >> 4)];
		output[j++] = base64chars[((input[i+1] & 15) << 2) | (input[i+2] >> 6)];
		output[j++] = base64chars[input[i+2] & 63];
	}

	if (len % 3 == 2)
	{
		output[j++] = base64chars[(input[i] >> 2)];
		output[j++] = base64chars[((input[i] & 3) << 4) | (input[i+1] >> 4)];
		output[j++] = base64chars[((input[i+1] & 15) << 2)];
		output[j++] = base64chars[64];
	}
	else if (len % 3 == 1)
	{
		output[j++] = base64chars[(input[i] >> 2)];
		output[j++] = base64chars[((input[i] & 3) << 4)];
		output[j++] = base64chars[64];
		output[j++] = base64chars[64];
	}
}

static void convert_to_star_string(char *star_string, int length)
{
	int i=0;
	for(i=0;i<length;i++)
		strcat(star_string, "*");
}

#ifdef CONFIG_IPV6
int retrieveIPv6Record(request * wp, MIB_CE_ATM_VC_Tp pEntry)
{
	char *strValue;
	struct in6_addr ip6Addr;

	// IpProtocolType(ipv4/ipv6, ipv4, ipv6)
	strValue = boaGetVar(wp, "IpProtocolType", "");
	if (strValue[0]) {
		pEntry->IpProtocol = strValue[0] - '0';
	}

	strValue = boaGetVar(wp, "AddrMode", "");
	if (strValue[0]) {
		pEntry->AddrMode = (char)atoi(strValue);
	}

	pEntry->Ipv6Dhcp = 0;
	if(pEntry->AddrMode == IPV6_WAN_STATIC)
	{
		// Local IPv6 IP
		strValue = boaGetVar(wp, "Ipv6Addr", "");
		if(strValue[0]) {
			inet_pton(PF_INET6, strValue, &ip6Addr);
			memcpy(pEntry->Ipv6Addr, &ip6Addr, sizeof(pEntry->Ipv6Addr));
		}

		// Local Prefix length of IPv6's IP
		strValue = boaGetVar(wp, "Ipv6PrefixLen", "");
		if(strValue[0]) {
			pEntry->Ipv6AddrPrefixLen = (char)atoi(strValue);
		}

		// Remote IPv6 IP
		strValue = boaGetVar(wp, "Ipv6Gateway", "");
		if(strValue[0]) {
			inet_pton(PF_INET6, strValue, &ip6Addr);
			memcpy(pEntry->RemoteIpv6Addr, &ip6Addr, sizeof(pEntry->RemoteIpv6Addr));
		}

		// IPv6 DNS 1
		strValue = boaGetVar(wp, "Ipv6Dns1", "");
		if(strValue[0]) {
			inet_pton(PF_INET6, strValue, &ip6Addr);
			memcpy(pEntry->Ipv6Dns1, &ip6Addr, sizeof(pEntry->Ipv6Dns1));
		}

		// IPv6 DNS 2
		strValue = boaGetVar(wp, "Ipv6Dns2", "");
		if(strValue[0]) {
			inet_pton(PF_INET6, strValue, &ip6Addr);
			memcpy(pEntry->Ipv6Dns2, &ip6Addr, sizeof(pEntry->Ipv6Dns2));
		}
	}
	else if(pEntry->AddrMode == IPV6_WAN_DHCP) // Enable DHCPv6 client
	{
		pEntry->Ipv6Dhcp = 1;
		// Request Address
		strValue = boaGetVar(wp, "iana", "");
		if ( !gstrcmp(strValue, "ON"))
			pEntry->Ipv6DhcpRequest |= 1;

	}

	strValue = boaGetVar(wp, "iapd", "");
#if defined(CONFIG_CMCC) || defined(CONFIG_CU) || defined(CONFIG_CU)
	if ( !gstrcmp(strValue, "ON")){
		pEntry->Ipv6DhcpRequest |= 2;
		pEntry->IPv6PrefixOrigin = IPV6_PREFIX_DELEGATION; 
	}else{
		//ToDo: so far don't have manual for prefix setting. 
		pEntry->IPv6PrefixOrigin = IPV6_PREFIX_STATIC; 
	}
#else
	if ( !gstrcmp(strValue, "ON"))
		pEntry->Ipv6DhcpRequest |= 2;
#endif

#if defined(CONFIG_IPV6) && defined(DUAL_STACK_LITE)
	// ds-lite enable
	if(pEntry->IpProtocol==IPVER_IPV6){
	strValue = boaGetVar(wp, "dslite_enable", "");
	if ( !gstrcmp(strValue, "ON")){
		pEntry->dslite_enable = 1;

			strValue = boaGetVar(wp, "dslite_aftr_mode", "");
			if(strValue[0])
				pEntry->dslite_aftr_mode = strValue[0] - '0';

			printf("dslite_aftr_mode=%d\n",pEntry->dslite_aftr_mode);

			if(pEntry->dslite_aftr_mode == IPV6_DSLITE_MODE_STATIC){
				strValue = boaGetVar(wp, "dslite_aftr_hostname", "");
				if(strValue[0])
					strncpy(pEntry->dslite_aftr_hostname,strValue,sizeof(pEntry->dslite_aftr_hostname));
				printf("dslite_aftr_hostname=%s\n",pEntry->dslite_aftr_hostname);
			}

		}
	}
#endif

/*
#ifdef DUAL_STACK_LITE
	// Get parameter for DS-Lite
	else if ((pEntry->AddrMode & IPV6_WAN_DSLITE) == IPV6_WAN_DSLITE)
	{
		// DSLiteLocalIP
		strValue = boaGetVar(wp, "DSLiteLocalIP", "");
		if(strValue[0]) {
			inet_pton(PF_INET6, strValue, &ip6Addr);
			memcpy(pEntry->Ipv6Addr, &ip6Addr, sizeof(pEntry->Ipv6Addr));
		}

		// DSLiteGateway
		strValue = boaGetVar(wp, "DSLiteGateway", "");
		if(strValue[0]) {
			inet_pton(PF_INET6, strValue, &ip6Addr);
			memcpy(pEntry->RemoteIpv6Addr, &ip6Addr, sizeof(pEntry->RemoteIpv6Addr));
		}

		// DSLiteRemoteIP
		strValue = boaGetVar(wp, "DSLiteRemoteIP", "");
		if(strValue[0]) {
			inet_pton(PF_INET6, strValue, &ip6Addr);
			memcpy(pEntry->RemoteIpv6EndPointAddr, &ip6Addr, sizeof(pEntry->RemoteIpv6EndPointAddr));
		}
	}
#endif
*/
	return 0;
}
#endif

int atmVcList2(int eid, request * wp, int argc, char **argv)
{
	int nBytesSent=0;

	unsigned int entryNum, i;
	MIB_CE_ATM_VC_T Entry;
	char ifname[IFNAMSIZ];
#ifdef CTC_WAN_NAME
	char ctcWanName[MAX_WAN_NAME_LEN];
#endif
	char if_display_name[16];
	char	*mode, vpi[6], vci[6], *aal5Encap;
	char	*strNapt, ipAddr[20], remoteIp[20], netmask[20], *strUnnum, *strDroute;
	char IpMask[20];
	char *strIgmp;
	char *strQos;
#ifdef CONFIG_GUI_WEB
	char	userName[P_MAX_NAME_LEN], passwd[P_MAX_NAME_LEN];
#else
	char	userName[MAX_PPP_NAME_LEN+1], passwd[MAX_NAME_LEN];
#endif
#ifdef CONFIG_USER_PPPOE_PROXY
     char pppoeProxy[10]={0};
#endif
	const char	*pppType, *strStatus;
	char	*temp;
	CONN_T	conn_status;

	entryNum = mib_chain_total(MIB_ATM_VC_TBL);
#ifdef DEFAULT_GATEWAY_V1
	dr = 0;
#endif

	nBytesSent += boaWrite(wp, "<tr><font size=2>"
	"<td align=center width=\"5%%\" bgcolor=\"#808080\"><font size=2>Select</td>\n"
	"<td align=center width=\"4%%\" bgcolor=\"#808080\"><font size=2>Inf</td>\n"
	"<td align=center width=\"7%%\" bgcolor=\"#808080\"><font size=2>Mode</td>\n"
	"<td align=center width=\"4%%\" bgcolor=\"#808080\"><font size=2>VPI</td>\n"
	"<td align=center width=\"5%%\" bgcolor=\"#808080\"><font size=2>VCI</td>\n"
	"<td align=center width=\"5%%\" bgcolor=\"#808080\"><font size=2>Encap</td>\n"
	"<td align=center width=\"3%%\" bgcolor=\"#808080\"><font size=2>NAPT</td>\n"
#ifdef CONFIG_IGMPPROXY_MULTIWAN
	"<td align=center width=\"3%%\" bgcolor=\"#808080\"><font size=2>IGMP</td>\n"
#endif
#ifdef IP_QOS
	"<td align=center width=\"3%%\" bgcolor=\"#808080\"><font size=2>IP QoS</td>\n"
#endif
	"<td align=center width=\"13%%\" bgcolor=\"#808080\"><font size=2>IP Addr</td>\n"
#ifdef DEFAULT_GATEWAY_V1
	"<td align=center width=\"13%%\" bgcolor=\"#808080\"><font size=2>Remote IP</td>\n"
#endif
	"<td align=center width=\"13%%\" bgcolor=\"#808080\"><font size=2>Subnet Mask</td>\n"
	"<td align=center width=\"15%%\" bgcolor=\"#808080\"><font size=2>User Name</td>\n");

#ifdef DEFAULT_GATEWAY_V1
	nBytesSent += boaWrite(wp, "<td align=center width=\"3%%\" bgcolor=\"#808080\"><font size=2>DRoute</td>\n");
#endif
	nBytesSent += boaWrite(wp, "<td align=center width=\"5%%\" bgcolor=\"#808080\"><font size=2>Status</td>\n"
	"<td align=center width=\"5%%\" bgcolor=\"#808080\"><font size=2>Actions</td></font></tr>\n");

	for (i=0; i<entryNum; i++) {
		struct in_addr inAddr;
		int flags;

		if (!mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&Entry))
		{
  			boaError(wp, 400, "Get chain record error!\n");
			return -1;
		}

		if (MEDIA_INDEX(Entry.ifIndex) != MEDIA_ATM)
			continue;

		mode = 0;

		if (Entry.cmode == CHANNEL_MODE_PPPOE)
			mode = "PPPoE";
		else if (Entry.cmode == CHANNEL_MODE_PPPOA)
			mode = "PPPoA";
		else if (Entry.cmode == CHANNEL_MODE_BRIDGE)
			mode = "br1483";
		else if (Entry.cmode == CHANNEL_MODE_IPOE)
			mode = "mer1483";
		else if (Entry.cmode == CHANNEL_MODE_RT1483)
			mode = "rt1483";

		snprintf(vpi, 6, "%u", Entry.vpi);
		snprintf(vci, 6, "%u", Entry.vci);

		aal5Encap = 0;
		if (Entry.encap == 0)
			aal5Encap = "VCMUX";
		else
			aal5Encap = "LLC";

		if (Entry.napt == 0)
			strNapt = (char*)IF_OFF;
		else
			strNapt = (char*)IF_ON;

#ifdef CONFIG_IGMPPROXY_MULTIWAN
		if (Entry.enableIGMP == 0)
			strIgmp = (char*)IF_OFF;
		else
			strIgmp = (char*)IF_ON;
#else
		strIgmp = (char *)IF_OFF;
#endif
#ifdef IP_QOS
		if (Entry.enableIpQos == 0)
			strQos = (char*)IF_OFF;
		else
			strQos = (char*)IF_ON;
#else
		strQos = (char *)IF_OFF;
#endif

#ifdef DEFAULT_GATEWAY_V1
		if (Entry.dgw == 0)	// Jenny, default route
			strDroute = (char*)IF_OFF;
		else
			strDroute = (char*)IF_ON;
		if (Entry.dgw && Entry.cmode != CHANNEL_MODE_BRIDGE)
			dr = 1;
#endif

		ifGetName(Entry.ifIndex, ifname, sizeof(ifname));
		if (Entry.cmode == CHANNEL_MODE_PPPOE || Entry.cmode == CHANNEL_MODE_PPPOA)
		{
			PPP_CONNECT_TYPE_T type;
#ifdef CONFIG_GUI_WEB
			strncpy(userName, Entry.pppUsername, P_MAX_NAME_LEN-1);
			userName[P_MAX_NAME_LEN-1] = '\0';
			//userName[P_MAX_NAME_LEN] = '\0';
			strncpy(passwd, Entry.pppPassword, P_MAX_NAME_LEN-1);
			passwd[P_MAX_NAME_LEN-1] = '\0';
			//passwd[P_MAX_NAME_LEN] = '\0';
#else
			strncpy(userName, Entry.pppUsername, MAX_PPP_NAME_LEN);
			userName[MAX_PPP_NAME_LEN] = '\0';
			//userName[MAX_NAME_LEN] = '\0';
			strncpy(passwd, Entry.pppPassword, MAX_NAME_LEN-1);
			passwd[MAX_NAME_LEN-1] = '\0';
			//passwd[MAX_NAME_LEN] = '\0';
#endif
			type = Entry.pppCtype;

			if (type == CONTINUOUS)
				pppType = "conti";
			else if (type == CONNECT_ON_DEMAND)
				pppType = "demand";
			else
				pppType = "manual";

#ifdef CONFIG_SPPPD_STATICIP
			if (Entry.cmode == CHANNEL_MODE_PPPOE && Entry.pppIp) {
				temp = inet_ntoa(*((struct in_addr *)Entry.ipAddr));
				strcpy(ipAddr, temp);
				strcpy(IpMask, temp);
			}
			else {
				strcpy(ipAddr, "");
				strcpy(IpMask, "");
			}
#else
			strcpy(ipAddr, "");
			strcpy(IpMask, "");
#endif
				strcpy(remoteIp, "");
				strcpy(netmask, "");

			// set status flag
			if (Entry.enable == 0)
			{
				strStatus = IF_DISABLED;
				conn_status = CONN_DISABLED;
			}
			else
			if (getInFlags( ifname, &flags) == 1)
			{
				if (flags & IFF_UP)
				{
//					strStatus = (char *)IF_UP;
					strStatus = IF_ENABLE;
					conn_status = CONN_UP;
				}
				else
				{
					if (find_ppp_from_conf(ifname))
					{
//						strStatus = (char *)IF_DOWN;
						strStatus = IF_ENABLE;
						conn_status = CONN_DOWN;
					}
					else
					{
//						strStatus = (char *)IF_NA;
						strStatus = IF_ENABLE;
						conn_status = CONN_NOT_EXIST;
					}
				}
			}
			else
			{
//				strStatus = (char *)IF_NA;
				strStatus = IF_ENABLE;
				conn_status = CONN_NOT_EXIST;
			}
			#ifdef CONFIG_USER_PPPOE_PROXY
			if(Entry.cmode==CHANNEL_MODE_PPPOE)
			{
				if(Entry.PPPoEProxyEnable)
					strcpy(pppoeProxy,"Enable");
				else
					strcpy(pppoeProxy,"Disabled");
			}
			#endif
		}
		else
		{
			if (Entry.ipDhcp == (char)DHCP_DISABLED)
			{
				// static IP address
				temp = inet_ntoa(*((struct in_addr *)Entry.ipAddr));
				strcpy(ipAddr, temp);

				temp = inet_ntoa(*((struct in_addr *)Entry.remoteIpAddr));
				strcpy(remoteIp, temp);

				temp = inet_ntoa(*((struct in_addr *)Entry.netMask));	// Jenny, subnet mask
				strcpy(netmask, temp);
			}
			else
			{
				// DHCP enabled
					strcpy(ipAddr, "");
					strcpy(IpMask, "");
					strcpy(remoteIp, "");
					strcpy(netmask, "");
			}

			if (Entry.ipunnumbered)
			{
				strcpy(ipAddr, "");
				strcpy(IpMask, "");
				strcpy(netmask, "");
				strcpy(remoteIp, "");
			}

			if (Entry.cmode == CHANNEL_MODE_BRIDGE)
			{
				strcpy(ipAddr, "");
				strcpy(IpMask, "");
				strcpy(netmask, "");
				strcpy(remoteIp, "");
				strNapt = "";
				strIgmp = "";
				strDroute = "";
			}
			else if (Entry.cmode == CHANNEL_MODE_RT1483)
				strcpy(netmask, "");

			// set status flag
			if (Entry.enable == 0)
			{
				strStatus = IF_DISABLED;
				conn_status = CONN_DISABLED;
			}
			else
			if (getInFlags( ifname, &flags) == 1)
			{
				if (flags & IFF_UP)
				{
//					strStatus = (char *)IF_UP;
					strStatus = IF_ENABLE;
					conn_status = CONN_UP;
				}
				else
				{
//					strStatus = (char *)IF_DOWN;
					strStatus = IF_ENABLE;
					conn_status = CONN_DOWN;
				}
			}
			else
			{
//				strStatus = (char *)IF_NA;
				strStatus = IF_ENABLE;
				conn_status = CONN_NOT_EXIST;
			}

			strcpy(userName, "");
			passwd[0]='\0';
			pppType = BLANK;
		}
		getDisplayWanName(&Entry, if_display_name);
		#ifdef CONFIG_USER_PPPOE_PROXY
		if(Entry.cmode != CHANNEL_MODE_PPPOE)
		{
			strcpy(pppoeProxy,"----");
		}
		#endif

#ifdef CTC_WAN_NAME
		{
			memset(ctcWanName, 0, sizeof(ctcWanName));
			getWanName(&Entry, ctcWanName);
		}

#endif

#ifdef CONFIG_IPV6
		unsigned char 	Ipv6AddrStr[48], RemoteIpv6AddrStr[48];

		if ((Entry.AddrMode & IPV6_WAN_STATIC) == IPV6_WAN_STATIC)
		{
			inet_ntop(PF_INET6, (struct in6_addr *)Entry.Ipv6Addr, Ipv6AddrStr, sizeof(Ipv6AddrStr));
			inet_ntop(PF_INET6, (struct in6_addr *)Entry.RemoteIpv6Addr, RemoteIpv6AddrStr, sizeof(RemoteIpv6AddrStr));
		} else {
			strcpy(Ipv6AddrStr, "");
			strcpy(RemoteIpv6AddrStr, "");
		}
#endif

         #ifdef CONFIG_USER_PPPOE_PROXY
 		nBytesSent += boaWrite (wp, "<tr>"
			"<td align=center width=\"3%%\" bgcolor=\"#C0C0C0\" style=\"word-break:break-all\"><font size=\"2\"><input type=\"radio\" name=\"select\""
#ifdef CONFIG_IPV6
			" value=\"s%d\" onClick=\"postVC2(%s,%s,'%s','%s','%s','%s','%s','%s',%d,%d,%d,%d,'%s','%s', '%s', %d, %d, %d"
			"%d, %d,'%s','%s', %d, %d, %d)\"></td>\n",
#else
			" value=\"s%d\" onClick=\"postVC(%s,%s,'%s','%s','%s','%s','%s','%s',%d,%d,%d,%d,'%s','%s', '%s', %d, %d, %d)\"></td>\n"),
#endif
			i, vpi, vci, aal5Encap, strNapt, mode,
			userName, passwd, pppType,
			Entry.pppIdleTime,
			Entry.PPPoEProxyEnable,
			Entry.ipunnumbered,
			Entry.ipDhcp, ipAddr,
			remoteIp,
			netmask, Entry.dgw, conn_status,
#ifdef CONFIG_IPV6
			Entry.enable,
			Entry.IpProtocol, Entry.AddrMode, Ipv6AddrStr, RemoteIpv6AddrStr, Entry.Ipv6AddrPrefixLen,  Entry.Ipv6Dhcp, Entry.Ipv6DhcpRequest);
#else
			Entry.enable);
#endif
	#else
		nBytesSent += boaWrite(wp, "<tr>"
		"<td align=center width=\"2%%\" bgcolor=\"#C0C0C0\" style=\"word-break:break-all\"><font size=\"2\"><input type=\"radio\" name=\"select\""
#ifdef CONFIG_IPV6
		" value=\"s%d\" onClick=\"postVC2(%s,%s,'%s','%s',"
#else
		" value=\"s%d\" onClick=\"postVC(%s,%s,'%s','%s',"
#endif
		"'%s',"
		"'%s',"
#ifdef CONFIG_IPV6
		"'%s','%s','%s','%s',%d,%d,%d,'%s','%s', '%s', %d, %d, %d,"
		"%d, %d,'%s','%s', %d, %d, %d)\"></td>\n",
#else
		"'%s','%s','%s','%s',%d,%d,%d,'%s','%s', '%s', %d, %d, %d)\"></td>\n"),
#endif
		i,vpi,vci,aal5Encap,strNapt,
		strIgmp,
		strQos,
		mode,userName,passwd,pppType,
		Entry.pppIdleTime,Entry.ipunnumbered,Entry.ipDhcp,ipAddr,
#ifdef CONFIG_IPV6
		remoteIp, netmask, Entry.dgw, conn_status, Entry.enable,
		Entry.IpProtocol, Entry.AddrMode, Ipv6AddrStr, RemoteIpv6AddrStr, Entry.Ipv6AddrPrefixLen,  Entry.Ipv6Dhcp, Entry.Ipv6DhcpRequest);
#else
		remoteIp, netmask, Entry.dgw, conn_status, Entry.enable);
#endif

	#endif

#ifdef CTC_WAN_NAME
		nBytesSent += boaWrite(wp,
		"<td align=center width=\"14%%\" bgcolor=\"#C0C0C0\" style=\"word-break:break-all\"><font size=\"2\"><b>%s</b></font></td>\n"
		"<td align=center width=\"9%%\" bgcolor=\"#C0C0C0\" style=\"word-break:break-all\"><font size=\"2\"><b>%s</b></font></td>\n"
		"<td align=center width=\"4%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"><b>%s</b></font></td>\n"
		"<td align=center width=\"5%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"><b>%s</b></font></td>\n"
		"<td align=center width=\"7%%\" bgcolor=\"#C0C0C0\" style=\"word-break:break-all\"><font size=\"2\"><b>%s</b></font></td>\n"
		"<td align=center width=\"6%%\" bgcolor=\"#C0C0C0\" style=\"word-break:break-all\"><font size=\"2\"><b>%s</b></font></td>\n"
		"<td align=center width=\"19%%\" bgcolor=\"#C0C0C0\" style=\"word-break:break-all\"><font size=\"2\"><b>%s</b></font></td>\n",
		ctcWanName, mode,
		vpi, vci,
		aal5Encap, strNapt,
		ipAddr
		);
#else
		nBytesSent += boaWrite(wp,
		"<td align=center width=\"4%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"><b>%s</b></font></td>\n"
		"<td align=center width=\"7%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"><b>%s</b></font></td>\n"
		"<td align=center width=\"4%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"><b>%s</b></font></td>\n"
		"<td align=center width=\"5%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"><b>%s</b></font></td>\n"
		"<td align=center width=\"5%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"><b>%s</b></font></td>\n"
		"<td align=center width=\"3%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"><b>%s</b></font></td>\n"
#ifdef CONFIG_IGMPPROXY_MULTIWAN
		"<td align=center width=\"3%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"><b>%s</b></font></td>\n"
#endif
#ifdef IP_QOS
		"<td align=center width=\"3%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"><b>%s</b></font></td>\n"
#endif
		"<td align=center width=\"13%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"><b>%s</b></font></td>\n",
		if_display_name, mode, vpi, vci, aal5Encap, strNapt,
#ifdef CONFIG_IGMPPROXY_MULTIWAN
		strIgmp,
#endif
#ifdef IP_QOS
		strQos,
#endif
		ipAddr);
#endif
#ifdef DEFAULT_GATEWAY_V1
		nBytesSent += boaWrite(wp,
		"<td align=center width=\"15%%\" bgcolor=\"#C0C0C0\" style=\"word-break:break-all\"><font size=\"2\"><b>%s</b></font></td>\n"
#else
		nBytesSent += boaWrite(wp,
#endif
		"<td align=center width=\"13%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"><b>%s</b></font></td>\n"
		"<td align=center width=\"9%%\" bgcolor=\"#C0C0C0\" style=\"word-break:break-all\"><font size=\"2\"><b>%s</b></font></td>\n"

#ifdef DEFAULT_GATEWAY_V1
		"<td align=center width=\"6%%\" bgcolor=\"#C0C0C0\" style=\"word-break:break-all\"><font size=\"2\"><b>%s</b></font></td>\n"
#endif
		"<td align=center width=\"3%%\" bgcolor=\"#C0C0C0\" style=\"word-break:break-all\"><font size=\"2\"><b>%s</b></font></td>\n"
		"<td align=center width=\"3%%\" bgcolor=\"#C0C0C0\" style=\"word-break:break-all\">",
#ifdef DEFAULT_GATEWAY_V1
		remoteIp,
#endif
		netmask,
		userName,

#ifdef DEFAULT_GATEWAY_V1
		strDroute,
#endif
		strStatus);
		nBytesSent += boaWrite(wp,
		"<a href=\"#?edit\" onClick=\"editClick(%d)\">"
		"<image border=0 src=\"graphics/edit.gif\" alt=\"Edit\" /></a>", i);

		nBytesSent += boaWrite(wp,
		"<a href=\"#?delete\" onClick=\"delClick(%d)\">"
		"<image border=0 src=\"graphics/del.gif\" alt=Delete /></td></tr>\n", i);
	}

	return nBytesSent;
}

#ifdef BR_ROUTE_ONEPVC
/*
 *	Set device interface of mibentry to be the same as the one of Entry's.
 *	Entry and mibentry share the same pvc. One for bridged mode and the
 *	other for routed mode.
 */
void modifyifIndex(MIB_CE_ATM_VC_Tp Entry,MIB_CE_ATM_VC_Tp mibentry)
{
	if(Entry->cmode != CHANNEL_MODE_BRIDGE && mibentry->cmode == CHANNEL_MODE_BRIDGE)
		mibentry->ifIndex = TO_IFINDEX(MEDIA_INDEX(mibentry->ifIndex), DUMMY_PPP_INDEX, VC_INDEX(Entry->ifIndex));
	if(Entry->cmode == CHANNEL_MODE_BRIDGE && (mibentry->cmode == CHANNEL_MODE_PPPOE || mibentry->cmode == CHANNEL_MODE_PPPOA))
		mibentry->ifIndex = TO_IFINDEX(MEDIA_INDEX(mibentry->ifIndex), PPP_INDEX(mibentry->ifIndex), VC_INDEX(Entry->ifIndex));
	else
		mibentry->ifIndex = TO_IFINDEX(MEDIA_INDEX(mibentry->ifIndex), DUMMY_PPP_INDEX, VC_INDEX(Entry->ifIndex));
}

/*
 *	Disable br_route_flag of pvc-Entry which share the same pvc of pEntry.
 */
void modify_Br_Rt_entry(MIB_CE_ATM_VC_Tp pEntry)
{
	int num,i;
	MIB_CE_ATM_VC_T entry;

	num=mib_chain_total(MIB_ATM_VC_TBL);
	for(i=0;i<num;i++){
		if(mib_chain_get(MIB_ATM_VC_TBL,i,&entry)!=1)
			continue;
		if(entry.br_route_flag==1 && entry.vpi==pEntry->vpi&&entry.vci==pEntry->vci){
			entry.br_route_flag=0;
			mib_chain_update(MIB_ATM_VC_TBL,&entry,i);
		}
	}
}
#endif

static int mib2web(MIB_CE_ATM_VC_Tp mibentry,struct atmvc_entryx* webentry)
{
	int i;

	webentry->svtype = mibentry->svtype;
	webentry->vpi = mibentry->vpi;
	webentry->vci = mibentry->vci;
	webentry->pcr = mibentry->pcr;
	webentry->scr = mibentry->scr;
	webentry->mbs = mibentry->mbs;
	webentry->encap = (mibentry->encap==1?0:1);
	webentry->napt = mibentry->napt;
	webentry->mtu =	mibentry->mtu;
	if(mibentry->cmode==CHANNEL_MODE_PPPOE){
		if(mibentry->mtu > 1492)
			webentry->mtu = 1492;
		//Include IPV6 header to avoid IPv6 fragmentation, IulianWu
		if ((mibentry->dslite_enable) && (mibentry->mtu > 1452)) {
			webentry->mtu = 1452;
		}
	}
	if(mibentry->cmode==CHANNEL_MODE_PPPOA||mibentry->cmode==CHANNEL_MODE_RT1483)
		return -1;
	webentry->cmode = mibentry->cmode;
 	//webentry->brmode = mibentry->brmode;
	webentry->AddrMode = mibentry->AddrMode;
	strcpy(webentry->pppUsername,mibentry->pppUsername);
	strcpy(webentry->pppPassword, mibentry->pppPassword);
	webentry->pppAuth = mibentry->pppAuth;
#ifdef _CWMP_MIB_ /*jiunming, for cwmp-tr069*/
	strcpy(webentry->pppServiceName, mibentry->pppServiceName);
#endif
/*star:20080718 START add for set acname by net_adsl_links_acname.asp*/
	strcpy(webentry->pppACName, mibentry->pppACName);
/*star:20080718 END*/
	webentry->pppCtype = mibentry->pppCtype;
	webentry->ipDhcp = mibentry->ipDhcp;
	*(unsigned int*)&(webentry->ipAddr) = (*(unsigned int*)&(mibentry->ipAddr));
	*(unsigned int*)&(webentry->remoteIpAddr) = (*(unsigned int*)&(mibentry->remoteIpAddr));
	*(unsigned int*)&(webentry->netMask) = (*(unsigned int*)&(mibentry->netMask));
	webentry->dnsMode = mibentry->dnsMode;
	*(unsigned int*)&(webentry->v4dns1) = (*(unsigned int*)&(mibentry->v4dns1));
	*(unsigned int*)&(webentry->v4dns2) = (*(unsigned int*)&(mibentry->v4dns2));
#if 1
	webentry->vlan = mibentry->vlan;
	webentry->vid = mibentry->vid;
	webentry->vprio = mibentry->vprio;
	webentry->vpass = mibentry->vpass;
#endif
#if defined(IP_QOS) || defined(NEW_IP_QOS_SUPPORT)
	webentry->qos = mibentry->enableIpQos;
#endif
#ifdef CONFIG_USER_PPPOE_PROXY
	webentry->PPPoEProxyEnable = mibentry->PPPoEProxyEnable;
	webentry->PPPoEProxyMaxUser = mibentry->PPPoEProxyMaxUser;
#endif
#ifdef CTC_WAN_NAME
	for (i=0; i<MAX_SRV_NUM; i++) {
		if (web2mib_srv[i] == (mibentry->applicationtype&CT_SRV_MASK))
		{
#ifdef CONFIG_SUPPORT_IPTV_APPLICATIONTYPE
			if(mibentry->applicationtype == X_CT_SRV_OTHER)
			{
				if(mibentry->othertype==OTHER_IPTV_TYPE)
					webentry->applicationtype=MAX_SRV_NUM;
				else
					webentry->applicationtype=i;
			}
			else
#endif
			webentry->applicationtype = i;
		}
	}
#endif
	webentry->disableLanDhcp = mibentry->disableLanDhcp;
	webentry->dgw = mibentry->dgw;
	webentry->ifIndex = mibentry->ifIndex;
#ifdef PPPOE_PASSTHROUGH
	if(mibentry->cmode==CHANNEL_MODE_PPPOE || mibentry->cmode==CHANNEL_MODE_BRIDGE){
		if(mibentry->brmode==BRIDGE_DISABLE)
			webentry->brmode=0;
		else if(mibentry->brmode==BRIDGE_PPPOE)
			webentry->brmode=1;
		else
			webentry->brmode=0;
	}else
		webentry->brmode=0;
#endif
	if(mibentry->itfGroup==0)
		webentry->itfGroup=0;
	else{
		unsigned char vChar,vcgroup;
		int i;
		unsigned short group=0;

//now we just update the group in the web
#ifdef NEW_PORTMAPPING
		group = mibentry->itfGroup;
#else

#ifdef CONFIG_EXT_SWITCH
		MIB_CE_SW_PORT_T Port;

		vcgroup = mibentry->itfGroup;

	printf("\nitfgroup=%d\n",vcgroup);
		for(i=0;i<4;i++){
			if( mib_chain_get(MIB_SW_PORT_TBL, i, (void *)&Port) ){
				if(vcgroup == Port.itfGroup)
					group|=(1<<i);
			}
		}
#endif

#ifdef WLAN_SUPPORT
		mib_get(MIB_WLAN_ITF_GROUP, (void *)&vChar);
		if(vcgroup == vChar)
			group|=0x10;
#ifdef WLAN_MBSSID
		mib_get(MIB_WLAN_VAP0_ITF_GROUP, (void *)&vChar);
		if(vcgroup == vChar)
			group|=0x20;
		mib_get(MIB_WLAN_VAP1_ITF_GROUP, (void *)&vChar);
		if(vcgroup == vChar)
			group|=0x40;
		mib_get(MIB_WLAN_VAP2_ITF_GROUP, (void *)&vChar);
		if(vcgroup == vChar)
			group|=0x80;
		mib_get(MIB_WLAN_VAP3_ITF_GROUP, (void *)&vChar);
		if(vcgroup == vChar)
			group|=0x100;
#endif //WLAN_MBSSID
#endif //WLAN_SUPPORT

#endif// NEW_PORTMAPPING
		//the group record the finale states
		webentry->itfGroup = group;
	}
	return 0;

}

#ifdef CONFIG_SUPPORT_IPTV_APPLICATIONTYPE
int getOtherServiceTypeIndex()
{
	int i;
	for (i=0; i<MAX_SRV_NUM; i++) 
	{
		if (web2mib_srv[i] == X_CT_SRV_OTHER)
		{
			return i;
		}
	}

	return -1;
}
#endif

static int web2mib(struct atmvc_entryx* webentry,MIB_CE_ATM_VC_Tp mibentry)
{
	switch(webentry->svtype){
		case UBR_WITHOUT_PCR:
		case UBR_WITH_PCR:
			mibentry->qos=ATMQOS_UBR;
			break;
		case CBR:
			mibentry->qos=ATMQOS_CBR;
			break;
		case NO_RT_VBR:
			mibentry->qos=ATMQOS_VBR_NRT;
			break;
		case RT_VBR:
			mibentry->qos=ATMQOS_VBR_RT;
			break;
		default:
			mibentry->qos=ATMQOS_UBR;
	}
	mibentry->svtype = webentry->svtype;
	mibentry->vpi = webentry->vpi;
	mibentry->vci = webentry->vci;
	mibentry->pcr = webentry->pcr;
	mibentry->scr = webentry->scr;
	mibentry->mbs = webentry->mbs;
	mibentry->encap = (webentry->encap==1?0:1);
	mibentry->napt = webentry->napt;
	mibentry->cmode = webentry->cmode;
	mibentry->mtu = webentry->mtu;
	//mibentry->brmode = webentry->brmode;
	mibentry->AddrMode = webentry->AddrMode;
	strcpy(mibentry->pppUsername,webentry->pppUsername);
	strcpy(mibentry->pppPassword, webentry->pppPassword);
	mibentry->pppAuth = webentry->pppAuth;
#ifdef _CWMP_MIB_ /*jiunming, for cwmp-tr069*/
	strcpy(mibentry->pppServiceName, webentry->pppServiceName);
#endif
/*star:20080718 START add for set acname by net_adsl_links_acname.asp*/
	strcpy(mibentry->pppACName, webentry->pppACName);
/*star:20080718 END*/
	mibentry->pppCtype = webentry->pppCtype;
    //patch for idletime
    if (1 == webentry->pppCtype)
        mibentry->pppIdleTime = 30;//default idle 30s
	mibentry->ipDhcp = webentry->ipDhcp;
	*(unsigned int*)&(mibentry->ipAddr) = *(unsigned int*)&(webentry->ipAddr);
	*(unsigned int*)&(mibentry->remoteIpAddr) = *(unsigned int*)&(webentry->remoteIpAddr);
	*(unsigned int*)&(mibentry->netMask) = *(unsigned int*)&(webentry->netMask);
#if 1//defined(CONFIG_EXT_SWITCH) || defined(CONFIG_RTL_8676HWNAT)
	mibentry->vlan = webentry->vlan;
	mibentry->vid = webentry->vid;
	mibentry->vprio = webentry->vprio;
	mibentry->vpass = webentry->vpass;
#endif
#if defined(IP_QOS) || defined(NEW_IP_QOS_SUPPORT)
	// Kaohj -- E8 don't care, so always enabled.
	//mibentry->enableIpQos = webentry->qos;
	mibentry->enableIpQos = 1;
#endif
#ifdef CONFIG_USER_PPPOE_PROXY
	mibentry->PPPoEProxyEnable = webentry->PPPoEProxyEnable;
	mibentry->PPPoEProxyMaxUser = webentry->PPPoEProxyMaxUser;
#endif
#ifdef CTC_WAN_NAME
#ifdef CONFIG_SUPPORT_IPTV_APPLICATIONTYPE
	if (webentry->applicationtype>=0 && webentry->applicationtype<=MAX_SRV_NUM)
#else
	if (webentry->applicationtype>=0 && webentry->applicationtype<MAX_SRV_NUM)
#endif		
	{
#ifdef CONFIG_SUPPORT_IPTV_APPLICATIONTYPE
		if(webentry->applicationtype == MAX_SRV_NUM)
		{
			mibentry->othertype = OTHER_IPTV_TYPE;
			mibentry->applicationtype = X_CT_SRV_OTHER;
		}
		else if(webentry->applicationtype == getOtherServiceTypeIndex())
		{
			mibentry->othertype = OTHER_NORMAL_TYPE;
			mibentry->applicationtype = X_CT_SRV_OTHER;
		}
		else
			mibentry->applicationtype = web2mib_srv[webentry->applicationtype];
#else
		mibentry->applicationtype = web2mib_srv[webentry->applicationtype];
#endif
	}
	else
	{
		mibentry->applicationtype = 0;
	}

#ifdef _PRMT_X_CT_COM_WANEXT_
	mibentry->ServiceList = mibentry->applicationtype;
#endif
	mibentry->disableLanDhcp = webentry->disableLanDhcp;
#if 0	/* Now we configure it on GUI */
    if (mibentry->applicationtype&X_CT_SRV_OTHER)
    {
        /* wan that is other type need disable dhcp on lan interface binding with it */
        mibentry->disableLanDhcp = 1;
    }
#endif
#endif
	mibentry->dgw = webentry->dgw;
#ifdef PPPOE_PASSTHROUGH
	if (mibentry->cmode == CHANNEL_MODE_BRIDGE)
/*star:20090403 START to make the br connection is displayed in WANPPPConnection of tr069*/
		mibentry->brmode = webentry->brmode;
//		mibentry->brmode = BRIDGE_ETHERNET; //BRIDGE_PPPOE;
/*star:20090403 END*/
	else if(mibentry->cmode == CHANNEL_MODE_IPOE)
		mibentry->brmode = BRIDGE_DISABLE;
	else{
		if(webentry->brmode==0)
			mibentry->brmode=BRIDGE_DISABLE;
		else
			mibentry->brmode=BRIDGE_PPPOE;
	}
#endif
	//printf("\nbrmode:%d %d\n",mibentry->brmode,webentry->brmode);

#ifdef NEW_PORTMAPPING
	mibentry->itfGroup = webentry->itfGroup;
#endif

#ifdef CTC_WAN_NAME
	// no napt, dgw for TR069 and/or VOICE.
	if (!(mibentry->applicationtype&(X_CT_SRV_INTERNET|X_CT_SRV_SPECIAL_SERVICE_ALL|X_CT_SRV_OTHER)))
	{
		mibentry->napt=0;
		mibentry->dgw=0;
	}
#endif

	mibentry->dslite_enable = webentry->dslite_enable;
	mibentry->dslite_aftr_mode = webentry->dslite_aftr_mode;
	strcpy(mibentry->dslite_aftr_hostname,webentry->dslite_aftr_hostname);
	return 0;

}

int initdgwoption(int eid, request * wp, int argc, char ** argv)
{
#ifdef NEW_DGW_POLICY
	boaWrite(wp, "tbdgw.style.display =\"none\";\n");
#endif
	return 0;
}

static void do_wan_restart()
{
//add by ramen to take effect rip
#ifdef CONFIG_USER_ROUTED_ROUTED
	startRip();
#endif
	DEBUGPRINT;
	va_cmd(IFCONFIG, 2, 1, "imq0", "down");
	restartWAN(CONFIGALL, NULL);
}

/*****************************
** Internet连接
*/

#if defined(CONFIG_ETHWAN)
#define CHECK_CONNECTION_MODE(cmode1, cmode2) (((cmode1 == CHANNEL_MODE_BRIDGE) && (cmode2 == CHANNEL_MODE_BRIDGE))\
						|| ((cmode1 > CHANNEL_MODE_BRIDGE) && (cmode2 > CHANNEL_MODE_BRIDGE)\
							&& cmode1 != CHANNEL_MODE_PPPOE && cmode2 != CHANNEL_MODE_PPPOE\
							&& cmode2 != CHANNEL_MODE_PPPOA && cmode2 != CHANNEL_MODE_PPPOA))
/*****************************
** Internet连接
*/
int initPageEth(int eid, request * wp, int argc, char ** argv)
{
	struct atmvc_entryx	entry;
	int				pppnumleft = 5;
	int				cnt = 0;
	int				index = 0;
	unsigned char	ipAddr[16];		//IP地址
	unsigned char	remoteIpAddr[16];	//缺省网关
	unsigned char	netMask[16];	//子网掩码
	unsigned char	v4dns1[16];
	unsigned char	v4dns2[16];
	unsigned int	fstdns = 0;	//缺省DNS
	unsigned int	secdns = 0;	//可选DNS
	int				lineno = __LINE__;
#if defined(CONFIG_RTL867X_VLAN_MAPPING) || defined(CONFIG_APOLLO_ROMEDRIVER)
	MIB_CE_PORT_BINDING_T pbEntry;
	int vlan_map;
#endif
	int poe_proxy;
	unsigned char encPppUsername[ENC_NAME_LEN+1];
	unsigned char pppPassword[MAX_NAME_LEN];

	_TRACE_CALL;

	/************Place your code here, do what you want to do! ************/
	/*test code*
	cnt = 1;
	pppnumleft = 7;

	memset(&entry, 0, sizeof(entry));
	entry.svtype = 0;
	entry.vpi = 0;
	entry.vci = 32;
	entry.pcr = 0;
	entry.scr = 0;
	entry.mbs = 0;
	entry.encap = 0;
	entry.napt = 0;
	entry.cmode = 2;
	entry.brmode = 1;
	strcpy(entry.pppUsername, "test");
	strcpy(entry.pppPassword, "test");
	entry.pppAuth = 0;
	strcpy(entry.pppServiceName, "test");
	entry.pppCtype = 0;
	entry.ipDhcp = 0;
	*(unsigned int*)&(entry.ipAddr) = 0x77777777;
	*(unsigned int*)&(entry.remoteIpAddr) = 0x77777777;
	*(unsigned int*)&(entry.netMask) = htonl(0xFFFFFF00);
	entry.vlan = 1;
	entry.vid = 0;
	entry.vprio = 0;
	entry.vpass = 0;
	entry.itfGroup = 0x48;
	entry.qos = 1;
	entry.PPPoEProxyEnable = 1;
	entry.PPPoEProxyMaxUser = 0;
	entry.applicationtype = 2;
	************Place your code here, do what you want to do! ************/
	MIB_CE_ATM_VC_T mibentry;
	int mibtotal,i;
	char wanname[MAX_WAN_NAME_LEN];
	unsigned int upmodes = 0;

#if defined(CONFIG_GPON_FEATURE) || defined(CONFIG_EPON_FEATURE)
	mib_get(MIB_PON_MODE, (void *)&upmodes);
#else // ETHWAN or PTMWAN
	upmodes = 0;
#endif


#if defined(CONFIG_RTL867X_VLAN_MAPPING) || defined(CONFIG_APOLLO_ROMEDRIVER)
	vlan_map = 0;
	cnt = mib_chain_total(MIB_PORT_BINDING_TBL);
	for (index=0; index<cnt; index++) {
		mib_chain_get(MIB_PORT_BINDING_TBL, index, (void*)&pbEntry);
		if (pbEntry.pb_mode)
			vlan_map |= (1<<index);
	}
	// put vlan-based port mapping
	_PUT_INT(vlan_map);
#endif
#ifdef CONFIG_USER_PPPOE_PROXY
	poe_proxy = 1;
#else
	poe_proxy = 0;
#endif
	_PUT_INT(poe_proxy);
	memset(&entry,0,sizeof(entry));

	_PUT_INT(pppnumleft);
	mibtotal = mib_chain_total(MIB_ATM_VC_TBL);
	for(i=0;i<mibtotal;i++){
		if(mib_chain_get(MIB_ATM_VC_TBL,i,&mibentry)!=1)
			continue;
		{
			if( MEDIA_INDEX(mibentry.ifIndex) != MEDIA_ETH )
				continue;
		}

#if defined(CONFIG_CMCC) || defined(CONFIG_CU) || defined(CONFIG_CU)
		if(mibentry.omci_configured && mibentry.applicationtype == X_CT_SRV_VOICE)
			continue;
#endif

//		_PUT_INT(pppnumleft);
	//	_PUT_IP(fstdns);
	//	_PUT_IP(secdns);

//	for(index = 0; index < cnt; index++)
		{
			/************Place your code here, do what you want to do! ************/
			/************Place your code here, do what you want to do! ************/

			getWanName(&mibentry, wanname);
			int tmp=mib2web(&mibentry,&entry);
			if(tmp==-1)
				continue;

			
#if defined(CONFIG_CMCC) || defined(CONFIG_CU) || defined(CONFIG_CU)
			strcpy(ipAddr, inet_ntoa(*((struct in_addr *)entry.ipAddr)));
			if (strcmp(ipAddr, "0.0.0.0")==0)
				strcpy(ipAddr, "");

			strcpy(remoteIpAddr, inet_ntoa(*((struct in_addr *)entry.remoteIpAddr)));
			if (strcmp(remoteIpAddr, "0.0.0.0")==0)
				strcpy(remoteIpAddr, "");

			strcpy(netMask, inet_ntoa(*((struct in_addr *)entry.netMask)));
			if (strcmp(netMask, "0.0.0.0")==0)
				strcpy(netMask, "");
#endif

			strcpy(v4dns1, inet_ntoa(*((struct in_addr *)mibentry.v4dns1)));
			if (strcmp(v4dns1, "0.0.0.0")==0)
				strcpy(v4dns1, "");

			strcpy(v4dns2, inet_ntoa(*((struct in_addr *)mibentry.v4dns2)));
			if (strcmp(v4dns2, "0.0.0.0")==0)
				strcpy(v4dns2, "");

#ifdef CONFIG_IPV6
			unsigned char 	Ipv6AddrStr[48]={0}, RemoteIpv6AddrStr[48]={0}, RemoteIpv6EndPointAddrStr[48]={0};
			char Ipv6Dns1Str[48]={0}, Ipv6Dns2Str[48]={0};
			unsigned char zeroIpv6Dns[IP6_ADDR_LEN]={0};
			unsigned char	IPv6Str1[40], IPv6Str2[40];
			unsigned char prefixLenStr[5]={0};

			strcpy(Ipv6AddrStr, "");
			strcpy(RemoteIpv6AddrStr, "");
			strcpy(RemoteIpv6EndPointAddrStr, "");
			strcpy(IPv6Str1, "Ipv6Addr");
			strcpy(IPv6Str2, "Ipv6Gateway");
			if(mibentry.Ipv6AddrPrefixLen!=0)
				sprintf(prefixLenStr,"%d",mibentry.Ipv6AddrPrefixLen);

			if ((mibentry.AddrMode & IPV6_WAN_STATIC) == IPV6_WAN_STATIC)
			{
				inet_ntop(PF_INET6, (struct in6_addr *)mibentry.Ipv6Addr, Ipv6AddrStr, sizeof(Ipv6AddrStr));
				inet_ntop(PF_INET6, (struct in6_addr *)mibentry.RemoteIpv6Addr, RemoteIpv6AddrStr, sizeof(RemoteIpv6AddrStr));
				if(memcmp(zeroIpv6Dns, mibentry.Ipv6Dns1, sizeof(zeroIpv6Dns)))
				inet_ntop(PF_INET6, (struct in6_addr *)mibentry.Ipv6Dns1, Ipv6Dns1Str, sizeof(Ipv6Dns1Str));
				if(memcmp(zeroIpv6Dns, mibentry.Ipv6Dns2, sizeof(zeroIpv6Dns)))
				inet_ntop(PF_INET6, (struct in6_addr *)mibentry.Ipv6Dns2, Ipv6Dns2Str, sizeof(Ipv6Dns2Str));

			}
#ifdef DUAL_STACK_LITE
			else if ((mibentry.AddrMode & IPV6_WAN_DSLITE) == IPV6_WAN_DSLITE)
			{
				inet_ntop(PF_INET6, (struct in6_addr *)mibentry.Ipv6Addr, Ipv6AddrStr, sizeof(Ipv6AddrStr));
				inet_ntop(PF_INET6, (struct in6_addr *)mibentry.RemoteIpv6Addr, RemoteIpv6AddrStr, sizeof(RemoteIpv6AddrStr));
				inet_ntop(PF_INET6, (struct in6_addr *)mibentry.RemoteIpv6EndPointAddr, RemoteIpv6EndPointAddrStr, sizeof(RemoteIpv6EndPointAddrStr));
				strcpy(IPv6Str1, "DSLiteLocalIP");
				strcpy(IPv6Str2, "DSLiteGateway");
			}
#endif
#endif
    		memset(encPppUsername, 0, sizeof(encPppUsername));
    		data_base64encode(entry.pppUsername, encPppUsername);
    		encPppUsername[ENC_NAME_LEN]='\0';
    		memset(pppPassword, 0, sizeof(pppPassword));
    		convert_to_star_string(pppPassword,strlen(entry.pppPassword));
    		pppPassword[MAX_NAME_LEN-1]='\0';

#ifndef CONFIG_IPV6
			boaWrite(wp, "push(new it_nr(\"%s\"" _PTI \
				_PTI _PTI _PTI \
				_PTS _PTS _PTI _PTS _PTS \
				_PTI _PTI \
				_PTS _PTS _PTS _PTI\
				_PTS _PTS _PTI\
				_PTI _PTI _PTI _PTI _PTI _PTI \
				_PTI _PTI _PTI _PTI _PTI"));\n",
				wanname, "upmode", upmodes,
				_PME(napt), _PME(cmode), _PME(brmode),
				"encodePppUserName", encPppUsername, "pppPassword", pppPassword, _PME(pppAuth),  _PME(pppServiceName),  _PME(pppACName),
				_PME(pppCtype), _PME(ipDhcp),
				_PMEIP(ipAddr), _PMEIP(remoteIpAddr), _PMEIP(netMask), _PME(dgw),
				"v4dns1", v4dns1, "v4dns2", v4dns2, "dnsMode", (mibentry.dnsMode != REQUEST_DNS) ? 0 : 1,
				_PME(vlan), _PME(vid), _PME(mtu), _PME(vprio), _PME(vpass), _PME(itfGroup),
				_PME(qos), _PME(PPPoEProxyEnable), _PME(PPPoEProxyMaxUser), _PME(applicationtype),
				_PME(disableLanDhcp)
				);
#else
#if defined(CONFIG_CMCC) || defined(CONFIG_CU) || defined(CONFIG_CU)
			boaWrite(wp, "push(new it_nr(\"%s\"" _PTI  \
				_PTI _PTI _PTI _PTI \
				_PTS _PTS _PTI _PTS _PTS \
				_PTI _PTI \
				_PTS _PTS _PTS _PTI\
				_PTS _PTS _PTI\
				_PTI _PTI _PTI _PTI _PTI _PTI \
				_PTI _PTI _PTI _PTI _PTI \
				_PTI _PTI _PTI \
				_PTS _PTS \
				_PTS _PTS \
				_PTS \
				_PTI \
				_PTS _PTI \
				_PTI _PTI \
				_PTI _PTS \
				_PTI _PTI _PTI _PTI"));\n",
				wanname, "upmode", upmodes,
				_PME(napt), _PME(cmode), _PME(brmode), _PME(AddrMode),
				"encodePppUserName", encPppUsername, "pppPassword", pppPassword, _PME(pppAuth),  _PME(pppServiceName),	_PME(pppACName),
				_PME(pppCtype), _PME(ipDhcp),
				"ipAddr", ipAddr, "remoteIpAddr", remoteIpAddr, "netMask", netMask, _PME(dgw),
				"v4dns1", v4dns1, "v4dns2", v4dns2, "dnsMode", (mibentry.dnsMode != REQUEST_DNS) ? 0 : 1,
				_PME(vlan), _PME(vid), _PME(mtu), _PME(vprio), _PME(vpass), _PME(itfGroup),
				_PME(qos), _PME(PPPoEProxyEnable), _PME(PPPoEProxyMaxUser), _PME(applicationtype), _PME(disableLanDhcp),
				"IpProtocolType", mibentry.IpProtocol , "slacc", (mibentry.AddrMode & IPV6_WAN_AUTO) == IPV6_WAN_AUTO ? 1:0, "staticIpv6", (mibentry.AddrMode & IPV6_WAN_STATIC) == IPV6_WAN_STATIC ? 1:0,
				IPv6Str1, Ipv6AddrStr, IPv6Str2, RemoteIpv6AddrStr,
				"Ipv6Dns1", Ipv6Dns1Str, "Ipv6Dns2", Ipv6Dns2Str,
				"DSLiteRemoteIP", RemoteIpv6EndPointAddrStr,
				"dslite_enable", mibentry.dslite_enable,
				"Ipv6PrefixLen", prefixLenStr, "itfenable", mibentry.Ipv6Dhcp,
				"iana", (mibentry.Ipv6DhcpRequest & 0x1) == 0x1 ? 1:0, "iapd", (mibentry.Ipv6DhcpRequest & 0x2) == 0x2 ? 1:0,
				"dslite_aftr_mode", mibentry.dslite_aftr_mode,
				"dslite_aftr_hostname", mibentry.dslite_aftr_hostname,
				"dnsv6Mode", (mibentry.dnsv6Mode != REQUEST_DNS) ? 0 : 1,
				"enable", mibentry.enable, "mcastVid", mibentry.mVid,
#ifdef WLAN_DUALBAND_CONCURRENT
				"wlanMode", 2
#else
				"wlanMode", 1
#endif				
				);
#else
			boaWrite(wp, "push(new it_nr(\"%s\"" _PTI  \
				_PTI _PTI _PTI _PTI \
				_PTS _PTS _PTI _PTS _PTS \
				_PTI _PTI \
				_PTS _PTS _PTS _PTI\
				_PTS _PTS _PTI\
				_PTI _PTI _PTI _PTI _PTI _PTI \
				_PTI _PTI _PTI _PTI _PTI \
				_PTI _PTI _PTI \
				_PTS _PTS \
				_PTS _PTS \
				_PTS \
				_PTI \
				_PTS _PTI \
				_PTI _PTI \
				_PTI _PTS \
				_PTI"));\n",
				wanname, "upmode", upmodes,
				_PME(napt), _PME(cmode), _PME(brmode), _PME(AddrMode),
				"encodePppUserName", encPppUsername, "pppPassword", pppPassword, _PME(pppAuth),  _PME(pppServiceName),  _PME(pppACName),
				_PME(pppCtype), _PME(ipDhcp),
				_PMEIP(ipAddr), _PMEIP(remoteIpAddr), _PMEIP(netMask), _PME(dgw),
				"v4dns1", v4dns1, "v4dns2", v4dns2, "dnsMode", (mibentry.dnsMode != REQUEST_DNS) ? 0 : 1,
				_PME(vlan), _PME(vid), _PME(mtu), _PME(vprio), _PME(vpass), _PME(itfGroup),
				_PME(qos), _PME(PPPoEProxyEnable), _PME(PPPoEProxyMaxUser), _PME(applicationtype), _PME(disableLanDhcp),
				"IpProtocolType", mibentry.IpProtocol , "slacc", (mibentry.AddrMode & IPV6_WAN_AUTO) == IPV6_WAN_AUTO ? 1:0, "staticIpv6", (mibentry.AddrMode & IPV6_WAN_STATIC) == IPV6_WAN_STATIC ? 1:0,
				IPv6Str1, Ipv6AddrStr, IPv6Str2, RemoteIpv6AddrStr,
				"Ipv6Dns1", Ipv6Dns1Str, "Ipv6Dns2", Ipv6Dns2Str,
				"DSLiteRemoteIP", RemoteIpv6EndPointAddrStr,
				"dslite_enable", mibentry.dslite_enable,
				"Ipv6PrefixLen", prefixLenStr, "itfenable", mibentry.Ipv6Dhcp,
				"iana", (mibentry.Ipv6DhcpRequest & 0x1) == 0x1 ? 1:0, "iapd", (mibentry.Ipv6DhcpRequest & 0x2) == 0x2 ? 1:0,
				"dslite_aftr_mode", mibentry.dslite_aftr_mode,
				"dslite_aftr_hostname", mibentry.dslite_aftr_hostname,
				"dnsv6Mode", (mibentry.dnsv6Mode != REQUEST_DNS) ? 0 : 1
				);
#endif
#endif
		}
	}

check_err:
	_TRACE_LEAVEL;
	return 0;
}

int initPageEth2(int eid, request * wp, int argc, char ** argv)
{
	unsigned char cwmp_configurable = 0;
	unsigned int is_backdoor_login = is_backdoor_userlogin(wp);
	unsigned char pcustom_en;
	unsigned char pcustom_prio[32];
	unsigned char prio[PROVINCE_8021PCUSTOM_NUM]={0};
	char *delim=",";
	char *p;
	int i=0;
#if defined(CONFIG_GPON_FEATURE) || defined(CONFIG_EPON_FEATURE)
	unsigned int upmodes;
	static char *str_upmodes[] = {"LAN", "GPON", "EPON"};

	mib_get(MIB_PON_MODE, (void *)&upmodes);
	boaWrite(wp, "var upmodes = new Array(\"%s\");\n", str_upmodes[upmodes]);
#else
	boaWrite(wp, "var upmodes = new Array(\"LAN\");\n");
#endif

	mib_get(CWMP_CONFIGURABLE, &cwmp_configurable);

	boaWrite(wp, "var apmodes = new Array("
		"\"TR069_INTERNET\", \"INTERNET\", \"TR069\", \"Other\""
#ifdef CONFIG_YUEME
#ifdef VOIP_SUPPORT
	", \"WAN_VOIP_VOICE_NAME\", \"WAN_TR069_VOIP_VOICE_NAME\", \"WAN_VOIP_VOICE_INTERNET_NAME\", \"WAN_TR069_VOIP_VOICE_INTERNET_NAME\", \"SPECIAL_SERVICE_1\", \"SPECIAL_SERVICE_2\", \"SPECIAL_SERVICE_3\", \"SPECIAL_SERVICE_4\");\n");
#else
	", \"SPECIAL_SERVICE_1\", \"SPECIAL_SERVICE_2\", \"SPECIAL_SERVICE_3\", \"SPECIAL_SERVICE_4\");\n");
#endif
#else
#ifdef VOIP_SUPPORT
	", \"WAN_VOIP_VOICE_NAME\", \"WAN_TR069_VOIP_VOICE_NAME\", \"WAN_VOIP_VOICE_INTERNET_NAME\", \"WAN_TR069_VOIP_VOICE_INTERNET_NAME\");\n");
#else
		");\n");
#endif
#endif

	boaWrite(wp, "var cwmp_configurable = %d;\n", (cwmp_configurable || is_backdoor_login) ? 1 : 0);

	mib_get(PROVINCE_8021PCUSTOM_ENABLE, (void *)&pcustom_en);
#if 1

	mib_get(PROVINCE_8021PCUSTOM_PRIORITY, (void *)&pcustom_prio);

	p = strtok(pcustom_prio,delim);
	prio[i]= *p + 1;//web prio mapping from 0-->none, 1-->prio 0, 8--> prio 7
	i++;
	while((p=strtok(NULL,delim))){
		prio[i]= *p + 1;
		i++;
	}
/*
	for(i=0;i<PROVINCE_8021PCUSTOM_NUM;i++)
		printf("%c \t",prio[i]);

	printf("\n");
*/
#endif
	boaWrite(wp, "var province_8021pcustom_enable = %d;\n", pcustom_en);
	boaWrite(wp, "var prio = new Array(""\"%c\", \"%c\", \"%c\", \"%c\""");\n", prio[0],prio[1],prio[2],prio[3]);
	return 0;
}

int initVlanRange(int eid, request * wp, int argc, char ** argv)
{
	unsigned int untag_wan_vid, fwdvlan_cpu, fwdvlan_proto_block, fwdvlan_bind_internet, fwdvlan_bind_other;
	unsigned int lan_vlan_id1, lan_vlan_id2;
#ifdef CONFIG_RTK_L34_ENABLE
	mib_get(MIB_FWD_CPU_VLAN_ID, (void *)&fwdvlan_cpu);
	mib_get(MIB_FWD_PROTO_BLOCK_VLAN_ID, (void *)&fwdvlan_proto_block);
	mib_get(MIB_FWD_BIND_INTERNET_VLAN_ID, (void *)&fwdvlan_bind_internet);
	mib_get(MIB_FWD_BIND_OTHER_VLAN_ID, (void *)&fwdvlan_bind_other);
	mib_get(MIB_UNTAG_WAN_VLAN_ID, (void *)&untag_wan_vid);
	mib_get(MIB_LAN_VLAN_ID1, (void *)&lan_vlan_id1);
	mib_get(MIB_LAN_VLAN_ID2, (void *)&lan_vlan_id2);

	boaWrite(wp, "var reservedVlanA = [%d, %d, %d, %d, %d, %d, %d, %d];\n", 0, fwdvlan_cpu,lan_vlan_id1, untag_wan_vid ,lan_vlan_id2 , fwdvlan_proto_block,  fwdvlan_bind_internet,4095);
	boaWrite(wp, "var otherVlanStart = %d;\n",fwdvlan_bind_other);
	boaWrite(wp, "var otherVlanEnd = %d;\n",fwdvlan_bind_other+DEFAULT_BIND_LAN_OFFSET);
	boaWrite(wp, "var alertVlanStr = \"%d, %d, %d, %d, %d, %d, %d, %d ~ %d, %d\";\n",0, fwdvlan_cpu,lan_vlan_id1, untag_wan_vid ,lan_vlan_id2 , fwdvlan_proto_block,  fwdvlan_bind_internet,fwdvlan_bind_other,fwdvlan_bind_other+DEFAULT_BIND_LAN_OFFSET,4095);
#else
	/*For no RG project, you must set the reserved vlan here,
	or the web page would have problem*/
	unsigned int bind_other_offset=10;
	fwdvlan_bind_other = 4000;
	boaWrite(wp, "var reservedVlanA = [%d, %d, %d];\n", 0, lan_vlan_id1 ,4095);
	boaWrite(wp, "var otherVlanStart = %d;\n",fwdvlan_bind_other);
	boaWrite(wp, "var otherVlanEnd = %d;\n",fwdvlan_bind_other+bind_other_offset);
	boaWrite(wp, "var alertVlanStr = \"%d, %d, %d ~ %d, %d\";\n",0, lan_vlan_id1, fwdvlan_bind_other,fwdvlan_bind_other+bind_other_offset,4095);
#endif
	//printf("initVlanRange:done\n");

	return 0;
}


int initPageQoSAPP(int eid, request * wp, int argc, char ** argv)
{
#ifdef VOIP_SUPPORT
	boaWrite(wp, "var appNames = new Array(\"\", \"VOIP\", \"TR069\");\n");
#else
	boaWrite(wp, "var appNames = new Array(\"\",  \"TR069\");\n");
#endif
	return 0;
}

#ifdef CONFIG_IPV6
void clear_delegated_default_wanconn(MIB_CE_ATM_VC_Tp mibentry_p)
{
	//If use this WAN as default conn in prefix delegated, clear this value.

	unsigned char lanIPv6PrefixMode;
	unsigned int old_wan_conn=0;

	if(((mibentry_p->cmode!=CHANNEL_MODE_BRIDGE) && (mibentry_p->IpProtocol&IPVER_IPV6)) && (mibentry_p->applicationtype & X_CT_SRV_INTERNET)){
		if (!mib_get(MIB_PREFIXINFO_PREFIX_MODE, (void *)&lanIPv6PrefixMode))
			printf("Error! Fail to et MIB_PREFIXINFO_PREFIX_MODE!\n");
		if(lanIPv6PrefixMode == IPV6_PREFIX_DELEGATION){
			if (!mib_get(MIB_PREFIXINFO_DELEGATED_WANCONN, (void *)&old_wan_conn))
				printf("Error! Fail to get MIB_PREFIXINFO_DELEGATED_WANCONN!\n");
			if(old_wan_conn && (old_wan_conn==mibentry_p->ifIndex)){
				printf("Prefix Mode is WANDelegated and using this  WAN Connection %x, now clear this!, %x\n",mibentry_p->ifIndex);
				old_wan_conn = 0;
				if (!mib_set(MIB_PREFIXINFO_DELEGATED_WANCONN, (void *)&old_wan_conn))
					printf("Error! Fail to set MIB_PREFIXINFO_DELEGATED_WANCONN!\n");
			}
		}
	}

}

void setup_delegated_default_wanconn(MIB_CE_ATM_VC_Tp mibentry_p)
{
	//In Spec , if prefix mode WANDelegated, and the default WANN conn
	//			is the one have INTERNET connection type

	unsigned char lanIPv6PrefixMode;
	unsigned int old_wan_conn=0;

	if(((mibentry_p->cmode!=CHANNEL_MODE_BRIDGE) && (mibentry_p->IpProtocol&IPVER_IPV6)) && (mibentry_p->applicationtype & X_CT_SRV_INTERNET)){
		if (!mib_get(MIB_PREFIXINFO_PREFIX_MODE, (void *)&lanIPv6PrefixMode))
			printf("Error! Fail to et MIB_PREFIXINFO_PREFIX_MODE!\n");
		if(lanIPv6PrefixMode == IPV6_PREFIX_DELEGATION){
			if (!mib_get(MIB_PREFIXINFO_DELEGATED_WANCONN, (void *)&old_wan_conn))
				printf("Error! Fail to get MIB_PREFIXINFO_DELEGATED_WANCONN!\n");

			if(old_wan_conn==0){
				printf("Prefix Mode is WANDelegated but not set WAN Connection yet, now use this WAN, %x\n",mibentry_p->ifIndex);
				if (!mib_set(MIB_PREFIXINFO_DELEGATED_WANCONN, (void *)&mibentry_p->ifIndex))
					printf("Error! Fail to set MIB_PREFIXINFO_DELEGATED_WANCONN!\n");
			}
		}
	}
}
#endif

static inline int isAllStar(char *data)
{
	int i;
	for (i=0; i<strlen(data); i++) {
		if (data[i] != '*')
			return 0;
	}
	return 1;
}

#if defined(CONFIG_CMCC) || defined(CONFIG_CU) || defined(CONFIG_CU)
#define _ENTRY_IP_CMCC(name, mib_name, opt){FETCH_INVALID_OPT(stemp, #name, opt); *(unsigned int*)&(entry.mib_name) = (*stemp?inet_addr(stemp):0);}
#define _ENTRY_STR_CMCC(name, mib_name, opt){FETCH_INVALID_OPT(stemp, #name, opt); strncpy(entry.mib_name, stemp, sizeof(entry.name));}
#define _ENTRY_INT_CMCC(name, mib_name, opt){FETCH_INVALID_OPT(stemp, #name, opt); entry.mib_name = atoi(stemp);}
#define _ENTRY_BOOL_CMCC(name, mib_name, opt){FETCH_INVALID_OPT(stemp, #name, _OPT); entry.mib_name = (strcmp(stemp, "on") == 0 )? 1 : 0;}

int retrieveIPv6Record_cmcc(request * wp, MIB_CE_ATM_VC_Tp pEntry)
{
	char *strValue;
	struct in6_addr ip6Addr;

	strValue = boaGetVar(wp, "IpVersion", "");
	if (strcmp(strValue, "IPv4") == 0) 
		pEntry->IpProtocol = IPVER_IPV4;
	else if (strcmp(strValue, "IPv6") == 0)
		pEntry->IpProtocol = IPVER_IPV6;
	else
		pEntry->IpProtocol = IPVER_IPV4_IPV6;	

	//strValue = boaGetVar(wp, "AddrMode", "");
	strValue = boaGetVar(wp, "IdIpv6AddrType", "");
	if (strcmp(strValue, "SLAAC") == 0) 
		pEntry->AddrMode = IPV6_WAN_AUTO;
	else if (strcmp(strValue, "DHCP") == 0)
		pEntry->AddrMode = IPV6_WAN_DHCP;
	else 
		pEntry->AddrMode = IPV6_WAN_STATIC;
	

	pEntry->Ipv6Dhcp = 0;
	if(pEntry->AddrMode == IPV6_WAN_STATIC)
	{
		// Local IPv6 IP
		strValue = boaGetVar(wp, "IdIpv6Addr", "");
		if(strValue[0]) {
			inet_pton(PF_INET6, strValue, &ip6Addr);
			memcpy(pEntry->Ipv6Addr, &ip6Addr, sizeof(pEntry->Ipv6Addr));
		}

		// Local Prefix length of IPv6's IP
		strValue = boaGetVar(wp, "IdIpv6PrefixLen", "");
		if(strValue[0]) {
			pEntry->Ipv6AddrPrefixLen = (char)atoi(strValue);
		}

		// Remote IPv6 IP
		strValue = boaGetVar(wp, "IdIpv6Gateway", "");
		if(strValue[0]) {
			inet_pton(PF_INET6, strValue, &ip6Addr);
			memcpy(pEntry->RemoteIpv6Addr, &ip6Addr, sizeof(pEntry->RemoteIpv6Addr));
		}

		// IPv6 DNS 1
		strValue = boaGetVar(wp, "IdIpv6Dns1", "");
		if(strValue[0]) {
			inet_pton(PF_INET6, strValue, &ip6Addr);
			memcpy(pEntry->Ipv6Dns1, &ip6Addr, sizeof(pEntry->Ipv6Dns1));
		}

		// IPv6 DNS 2
		strValue = boaGetVar(wp, "IdIpv6Dns2", "");
		if(strValue[0]) {
			inet_pton(PF_INET6, strValue, &ip6Addr);
			memcpy(pEntry->Ipv6Dns2, &ip6Addr, sizeof(pEntry->Ipv6Dns2));
		}
	}
	else if(pEntry->AddrMode == IPV6_WAN_DHCP) // Enable DHCPv6 client
	{
		pEntry->Ipv6Dhcp = 1;
		pEntry->Ipv6DhcpRequest |= 1;
	}
	strValue = boaGetVar(wp, "cb_enabledpd", "");

	if ( !gstrcmp(strValue, "on")){
		pEntry->Ipv6DhcpRequest |= 2;
		pEntry->IPv6PrefixOrigin = IPV6_PREFIX_DELEGATION; 
	}else{
		//ToDo: so far don't have manual for prefix setting. 
		pEntry->IPv6PrefixOrigin = IPV6_PREFIX_STATIC; 
	}
#if defined(CONFIG_IPV6) && defined(DUAL_STACK_LITE)
	// ds-lite enable
	if(pEntry->IpProtocol==IPVER_IPV6){
		strValue = boaGetVar(wp, "cb_enabledslite", "");
		if ( !gstrcmp(strValue, "on")){
			pEntry->dslite_enable = 1;
			strValue = boaGetVar(wp, "dslitemode", "");
			pEntry->dslite_aftr_mode = atoi(strValue);
			printf("dslite_aftr_mode\n",pEntry->dslite_aftr_mode);

			if(pEntry->dslite_aftr_mode == IPV6_DSLITE_MODE_STATIC){
				strValue = boaGetVar(wp, "dsliteaddress", "");
				if(strValue[0])
					strncpy(pEntry->dslite_aftr_hostname,strValue,sizeof(pEntry->dslite_aftr_hostname));
				printf("dslite_aftr_hostname=%s\n",pEntry->dslite_aftr_hostname);
			}
		}
	}
#endif
	return 0;
}


void formEthernet_cmcc(request * wp, char *path, char *query)
{
	char *submitUrl;
	char *strValue;
	char* stemp = "";
	char tmpBuf[100];
	char act[10];
	int	lineno = __LINE__;
	int totalEntry=0, i=0;
	struct atmvc_entryx	entry;
	MIB_CE_ATM_VC_T mibentry,Entry;
	MEDIA_TYPE_T mType;
	char *dns1Ip, *dns2Ip;
	char *dns1Ipv6, *dns2Ipv6;
	unsigned int ifMap;


	//FETCH_INVALID_OPT(stemp, "wanName", _NEED);
	FETCH_INVALID_OPT(stemp, "OperatorStyle", _NEED);
	strncpy(act,stemp,10);
	if(strcmp(act, "Del") == 0)
	{
		int idx=-1;
		char webwanname[MAX_WAN_NAME_LEN];
		char mibwanname[MAX_WAN_NAME_LEN];

		/************Place your code here, do what you want to do! ************/
		/*use 'stemp' as 'link name' to match 'atmvc_entry' entry and remove relevant entry from MIB */
		/************Place your code here, do what you want to do! ************/

		FETCH_INVALID_OPT(stemp, "wanName", _NEED);
		strncpy(webwanname,stemp,MAX_WAN_NAME_LEN-1);

		totalEntry = mib_chain_total(MIB_ATM_VC_TBL);
		for(i=0;i<totalEntry;i++){
			if(mib_chain_get(MIB_ATM_VC_TBL,i,&Entry)!=1)
				continue;
			getWanName(&Entry,mibwanname);
			if((!strcmp(mibwanname,webwanname))){
				idx=i;
				break;
			}
		}
		/* YueMe uses app based rules. */
#ifndef CONFIG_YUEME
#if defined(CONFIG_USER_IP_QOS) && defined(_PRMT_X_CT_COM_QOS_)
		//Delete QoS rule if CTQOS_MODE has string INTERNET and this WAN is with type INTERNET
		if((Entry.applicationtype & X_CT_SRV_INTERNET)){
			char qos_mode[MAX_NAME_LEN]={0};

			if(mib_get(CTQOS_MODE, qos_mode)){
				if(strcasestr(qos_mode,"INTERNET")){
					printf("delete MIB for QoS Mode INTERNET\n");
					delQoSRuleByMode("INTERNET");
				}
			}
		}
#endif
#endif

		if(idx!=-1){
			resolveServiceDependency(idx);
#ifdef CONFIG_CMCC_IPV6_SECURITY_SUPPORT
			del_bridge_ip6sec_prefix_info(&Entry, NULL);
#endif

#ifdef DNS_BIND_PVC_SUPPORT
			MIB_CE_ATM_VC_T dnsPvcEntry;
			if(mib_chain_get(MIB_ATM_VC_TBL,idx,&dnsPvcEntry)&&(dnsPvcEntry.cmode!=CHANNEL_MODE_BRIDGE))
			{
				int tempi=0;
				unsigned int pvcifIdx=0;
				for(tempi=0;tempi<3;tempi++)
				{
					mib_get(MIB_DNS_BIND_PVC1+tempi,(void*)&pvcifIdx);
					if(pvcifIdx==dnsPvcEntry.ifIndex)//I get it
					{
						pvcifIdx=DUMMY_IFINDEX;
						mib_set(MIB_DNS_BIND_PVC1+tempi,(void*)&pvcifIdx);
					}
				}
			}
#endif

#ifdef CONFIG_IPV6
#ifdef DNSV6_BIND_PVC_SUPPORT
			MIB_CE_ATM_VC_T dnsv6PvcEntry;
			if(mib_chain_get(MIB_ATM_VC_TBL,idx,&dnsv6PvcEntry)&&(dnsv6PvcEntry.cmode!=CHANNEL_MODE_BRIDGE))
			{
				int tempi=0;
				unsigned int pvcifIdx=0;
				for(tempi=0;tempi<3;tempi++)
				{
					mib_get(MIB_DNSV6_BIND_PVC1+tempi,(void*)&pvcifIdx);
					if(pvcifIdx==dnsv6PvcEntry.ifIndex)//I get it
					{
						pvcifIdx = DUMMY_IFINDEX;
						mib_set(MIB_DNSV6_BIND_PVC1+tempi,(void*)&pvcifIdx);
					}
				}
			}
#endif
#endif
			// Mason Yu. ITMS4
			{
				MIB_CE_ATM_VC_T vcEntry;
				if (mib_chain_get(MIB_ATM_VC_TBL, idx, (void *)&vcEntry))
				{
#ifdef CONFIG_IPV6
					clear_delegated_default_wanconn(&vcEntry);
#endif

#ifdef NEW_IP_QOS_SUPPORT//ql 20081125
					delIpQosTcRule(&vcEntry);
#endif
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
					//before delete wan, we must reset unbinded_port_vlan
					reset_unbinded_port_vlan(&vcEntry);
#endif
					deleteConnection(CONFIGONE, &vcEntry);
				}
			}

			if(mib_chain_delete(MIB_ATM_VC_TBL, idx) != 1) {
					strcpy(tmpBuf, strDelChainerror);
					goto setErr_restart;
			}


//ql add: check if it is necessary to delete a group of interface
#ifdef ITF_GROUP
			{
				int wanPortNum;
				unsigned int swNum, vcNum;
				MIB_CE_SW_PORT_T Entry;
				MIB_CE_ATM_VC_T pvcEntry;
				int j, grpnum;
				char mygroup;
				int enable_portmap =0;

				vcNum = mib_chain_total(MIB_ATM_VC_TBL);
				for (grpnum=1; grpnum<=4; grpnum++) {
					wanPortNum = 0;

					for (j=0; j<vcNum; j++) {
						if (!mib_chain_get(MIB_ATM_VC_TBL, j, (void *)&pvcEntry))
						{
							//boaError(wp, 400, "Get chain record error!\n");
							printf("Get chain record error!\n");
							return;
						}
						if(pvcEntry.itfGroup!=0)
							enable_portmap++;
						if (pvcEntry.enable == 0 || pvcEntry.itfGroup!=grpnum)
							continue;

						if (pvcEntry.applicationtype & (X_CT_SRV_INTERNET|X_CT_SRV_OTHER))
							wanPortNum++;

					}
					//printf("\nwanPortNum=%d\n",wanPortNum);
					if (0 == wanPortNum) {
						//printf("delete port mapping group %d\n", grpnum);
						//release LAN ports
						swNum = mib_chain_total(MIB_SW_PORT_TBL);
						for (j=swNum; j>0; j--) {
							if (!mib_chain_get(MIB_SW_PORT_TBL, j-1, (void *)&Entry))
								return;
							if (Entry.itfGroup == grpnum) {
								Entry.itfGroup = 0;
								mib_chain_update(MIB_SW_PORT_TBL, (void *)&Entry, j-1);
							}
						}
#ifdef WLAN_SUPPORT
						//release wlan0
						mib_get(MIB_WLAN_ITF_GROUP, (void *)&mygroup);
						if (mygroup == grpnum) {
							mygroup = 0;
							mib_set(MIB_WLAN_ITF_GROUP, (void *)&mygroup);
						}
#endif
#ifdef WLAN_MBSSID
						//release MBSSID
						for (j=1; j<5; j++) {
							mib_get(MIB_WLAN_VAP0_ITF_GROUP+j-1, (void *)&mygroup);
							if (mygroup == grpnum) {
								mygroup = 0;
								mib_set(MIB_WLAN_VAP0_ITF_GROUP+j-1, (void *)&mygroup);
							}
						}
#endif
						for (j=0; j<vcNum; j++) {
							if (!mib_chain_get(MIB_ATM_VC_TBL, j, (void *)&pvcEntry))
							{
								//boaError(wp, 400, "Get chain record error!\n");
								printf("Get chain record error!\n");
								return;
							}
							if(pvcEntry.itfGroup==grpnum){
								printf("\nmodify tr069 portmapping!\n");
								pvcEntry.itfGroup=0;
								mib_chain_update(MIB_ATM_VC_TBL,(void *)&pvcEntry,j);
							}
						}
						//setgroup("", grpnum, lowPrio);
						setgroup("", grpnum);

					}
				}

				if(!enable_portmap)
				{
					printf("\nstop portmapping!\n");

						mib_get(MIB_MPMODE, (void *)&mode);
						 mode &= 0xfe;
						mib_set(MIB_MPMODE, (void *)&mode);
				}
			}//end
#endif
		}
		else
		{
			strcpy(tmpBuf, strSelectvc);
			goto setErr_nochange;
		}

		// Mason Yu. ITMS4
		restartWAN(CONFIGONE, NULL);
#ifdef CONFIG_CU
		syslog(LOG_INFO, "WEB: Delete Wan Configuration\n");
#endif
		goto setOk_filter;

		
	}
	
	memset(&entry, 0, sizeof(entry));
	memset(&mibentry, 0, sizeof(mibentry));	

	FETCH_INVALID_OPT(stemp, "IpVersion", _OPT);
	if (strcmp(stemp, "IPv4") == 0) 
		mibentry.IpProtocol = IPVER_IPV4;
	else if (strcmp(stemp, "IPv6") == 0)
		mibentry.IpProtocol = IPVER_IPV6;
	else
		mibentry.IpProtocol = IPVER_IPV4_IPV6;

	_ENTRY_BOOL_CMCC(cb_nat, napt, _OPT);

	FETCH_INVALID_OPT(stemp, "wanMode", _OPT);
	if (strcmp(stemp, "Bridge") == 0)
	{
		entry.cmode = CHANNEL_MODE_BRIDGE;
		FETCH_INVALID_OPT(stemp, "bridgeMode", _OPT);
		if (strcmp(stemp, "PPPoE_Bridged") == 0) //PPPoE_Bridged
			entry.brmode = BRIDGE_PPPOE;
		else //IP_Bridged
			entry.brmode= BRIDGE_ETHERNET;	
	}
	else 
	{	//wanMode : Route
		FETCH_INVALID_OPT(stemp, "linkMode", _OPT);
		if (strcmp(stemp, "linkPPP") == 0)
		{
			entry.cmode = CHANNEL_MODE_PPPOE;

			FETCH_INVALID_OPT(stemp, "encodePppUserName", _NEED);
			data_base64decode(stemp, entry.pppUsername);
			if ( strlen(entry.pppUsername) >= MAX_NAME_LEN ) {
				lineno = __LINE__;
				goto check_err;
			}

			FETCH_INVALID_OPT(stemp, "encodePppPassword", _NEED);
			data_base64decode(stemp, entry.pppPassword);
			if ( strlen(entry.pppPassword) >= MAX_NAME_LEN ) {
				lineno = __LINE__;
				goto check_err;
			}
			entry.pppPassword[MAX_NAME_LEN-1]='\0';

#ifdef CONFIG_CU
			FETCH_INVALID_OPT(stemp, "pppServiceName", _OPT);
			if ( strlen(stemp) >= MAX_NAME_LEN ) {
				lineno = __LINE__;
				goto check_err;
			}
			strcpy(entry.pppServiceName,stemp);
			entry.pppServiceName[MAX_NAME_LEN-1]='\0';
			//printf("entry.pppServiceName=%s\n",entry.pppServiceName);
#endif		

			//entry.brmode = BRIDGE_PPPOE;		
			_ENTRY_BOOL_CMCC(cb_enable_pppbi, brmode, _NEED);			
		}
		else if (strcmp(stemp, "linkIP") == 0)
		{
			entry.cmode = CHANNEL_MODE_IPOE;
			if (mibentry.IpProtocol & IPVER_IPV4) {
				FETCH_INVALID_OPT(stemp, "IpMode", _OPT);
				if (strcmp(stemp, "DHCP") == 0)
					entry.ipDhcp = DHCP_CLIENT;
				else if (strcmp(stemp, "Static") == 0)
				{
					entry.ipDhcp = DHCP_DISABLED;
					_ENTRY_IP_CMCC(wanIpAddress, ipAddr, _NEED);
					_ENTRY_IP_CMCC(defaultGateway, remoteIpAddr, _NEED);
					_ENTRY_IP_CMCC(wanSubnetMask, netMask, _NEED);
				}
				if(entry.ipDhcp > DHCP_CLIENT){lineno = __LINE__; goto check_err;}
			}	
		}
	}

	FETCH_INVALID_OPT(stemp, "VLANMode", _OPT);
	if (strcmp(stemp, "UNTAG") == 0)
		entry.vlan = 0;
	else if (strcmp(stemp, "TAG") == 0) {
		entry.vlan = 1;
		_ENTRY_INT_CMCC(vlan, vid, _NEED);
		if(entry.vid > 4095){lineno = __LINE__; goto check_err;}

		_ENTRY_BOOL_CMCC(cb_8021P, vprio, _OPT);
		if (entry.vprio > 0) {
			_ENTRY_INT_CMCC(v8021P, vprio, _NEED);
			entry.vprio += 1;
		}
		if(entry.vprio > 8){lineno = __LINE__; goto check_err;}
	}
	else //TRANSPARENT
		entry.vlan = 2;


	_ENTRY_INT_CMCC(MTU, mtu, _NEED);
	if(entry.mtu > 1500 || entry.mtu < 576){lineno = __LINE__; goto check_err;}


	FETCH_INVALID_OPT(stemp, "cb_bindlan1", _OPT);
	if(strcmp(stemp, "on") == 0 )
		entry.itfGroup += (0x1 << 0);
	FETCH_INVALID_OPT(stemp, "cb_bindlan2", _OPT);
	if(strcmp(stemp, "on") == 0 )
		entry.itfGroup += (0x1 << 1);
	FETCH_INVALID_OPT(stemp, "cb_bindlan3", _OPT);
	if(strcmp(stemp, "on") == 0)
		entry.itfGroup += (0x1 << 2);
	FETCH_INVALID_OPT(stemp, "cb_bindlan4", _OPT);
	if(strcmp(stemp, "on") == 0)
		entry.itfGroup += (0x1 << 3);
	FETCH_INVALID_OPT(stemp, "cb_bindwireless1", _OPT);
	if(strcmp(stemp, "on") == 0 )
		entry.itfGroup += (0x1 << 4);
	FETCH_INVALID_OPT(stemp, "cb_bindwireless2", _OPT);
	if(strcmp(stemp, "on") == 0 )
		entry.itfGroup += (0x1 << 5);	
	FETCH_INVALID_OPT(stemp, "cb_bindwirelessac1", _OPT);
	if(strcmp(stemp, "on") == 0 )
		entry.itfGroup += (0x1 << 9);

	//CMCC:("TR069_INTERNET", "INTERNET", "TR069", "Other", "VOICE", "TR069_VOICE", "VOICE_INTERNET", "TR069_VOICE_INTERNET");
	FETCH_INVALID_OPT(stemp, "serviceList", _NEED);
	if(strcmp(stemp, "TR069_INTERNET") == 0 )
		entry.applicationtype = 0;
	else if (strcmp(stemp, "INTERNET") == 0 )
		entry.applicationtype = 1;
	else if (strcmp(stemp, "TR069") == 0 )
		entry.applicationtype = 2;
	else if ( (strcmp(stemp, "Other") == 0) || (strcmp(stemp, "OTHER") == 0))
		entry.applicationtype = 3;
	else if (strcmp(stemp, WAN_VOIP_VOICE_NAME) == 0 )
		entry.applicationtype = 4;
	else if (strcmp(stemp, WAN_TR069_VOIP_VOICE_NAME) == 0 )
		entry.applicationtype = 5;
	else if (strcmp(stemp, WAN_VOIP_VOICE_INTERNET_NAME) == 0 )
		entry.applicationtype = 6;
	else if (strcmp(stemp, WAN_TR069_VOIP_VOICE_INTERNET_NAME) == 0 )
		entry.applicationtype = 7;
#ifdef CONFIG_SUPPORT_IPTV_APPLICATIONTYPE
	else if (strcmp(stemp, WAN_IPTV_NAME) == 0 )
		entry.applicationtype = 8;
#endif

	//_ENTRY_BOOL_CMCC(cb_enabledhcp, disableLanDhcp, _NEED);
	FETCH_INVALID_OPT(stemp, "cb_enabledhcp", _OPT);
	entry.disableLanDhcp = (strcmp(stemp, "on") == 0 )? 0 : 1;
	web2mib(&entry,&mibentry);

#ifdef CONFIG_USER_PPPOE_PROXY
	if(entry.PPPoEProxyEnable){
		if(mibentry.itfGroup > 0){
			system("echo 1 > /proc/rg/pppoe_proxy_only_for_binding_packet");
			printf("echo 1 > /proc/rg/pppoe_proxy_only_for_binding_packet\n");
		}else{
			system("echo 0 > /proc/rg/pppoe_proxy_only_for_binding_packet");
			printf("echo 0 > /proc/rg/pppoe_proxy_only_for_binding_packet\n");
		}
	}
#endif

	FETCH_INVALID_OPT(stemp, "IpMode", _OPT);
	if (strcmp(stemp, "Static") == 0)
	{
		if (mibentry.cmode == CHANNEL_MODE_IPOE)
		{
			FETCH_INVALID_OPT(dns1Ip, "dnsPrimary", _OPT);
			FETCH_INVALID_OPT(dns2Ip, "dnsSecondary", _OPT);
			
			if ( (!dns1Ip[0]) && (!dns2Ip[0]))
				mibentry.dnsMode = 1;
			else {
				mibentry.dnsMode = 0;
		
				if (dns1Ip[0]) {
					if (!inet_aton(dns1Ip, (struct in_addr *)&mibentry.v4dns1)) {
						strcpy(tmpBuf, "Invalid dnsPrimary IP-address value!"); //Invalid dnsv4 1 IP-address value!
						goto setErr_nochange;
					}
				}

				if (dns2Ip[0]) {
					if (!inet_aton(dns2Ip, (struct in_addr *)&mibentry.v4dns2)) {
						strcpy(tmpBuf, "Invalid dnsSecondary IP-address value!"); //Invalid dnsv4 2 IP-address value!
						goto setErr_nochange;
					}
				}
			}
		}
		else
			mibentry.dnsMode = 1; // default is enable dnsMode
		
		if(mibentry.cmode == CHANNEL_MODE_IPOE){
			FETCH_INVALID_OPT(dns1Ipv6, "IdIpv6Dns1", _OPT);
			FETCH_INVALID_OPT(dns2Ipv6, "IdIpv6Dns2", _OPT);
			if ( (!dns1Ip[0]) && (!dns2Ip[0]))
				mibentry.dnsv6Mode = 1;
			else {
				mibentry.dnsv6Mode = 0;
				if (dns1Ipv6[0]) {
					printf("dnsv6 Address1 %s \n", dns1Ipv6);
					if (!inet_pton(PF_INET6, dns1Ipv6, (struct in6_addr *)mibentry.Ipv6Dns1)) {
						strcpy(tmpBuf, "nvalid IdIpv6Dns1 IP-address value!"); //Invalid dnsv6 1 IP-address value!
						goto setErr_nochange;
					}
				}

				if (dns2Ipv6[0]) {
					printf("dnsv6 Address2 %s \n", dns2Ipv6);
					if (!inet_pton(PF_INET6, dns2Ipv6, (struct in6_addr *)mibentry.Ipv6Dns2)) {
						strcpy(tmpBuf, "Invalid IdIpv6Dns2 IP-address value!"); //Invalid dnsv6 2 IP-address value!
						goto setErr_nochange;
					}
				}
			}
		}
		else{
			mibentry.dnsv6Mode = 1; // default is enable dnsMode
			printf("dnsv6Mode %d \n", mibentry.dnsv6Mode);
		}

	}
	else {
		mibentry.dnsMode = 1; // default is enable dnsMode
		strcpy(mibentry.v4dns1, "");
		strcpy(mibentry.v4dns2, "");
		mibentry.dnsv6Mode = 1;
		strcpy(mibentry.Ipv6Dns1,"");
		strcpy(mibentry.Ipv6Dns2,"");
	}

	if(mibentry.applicationtype & ~CT_SRV_MASK)
		{lineno = __LINE__; goto check_err;}
	// E8B: if 'INTERNET', set as default route.
#if 0//ndef CONFIG_RTK_L34_ENABLE
	if((mibentry.applicationtype & (X_CT_SRV_INTERNET|X_CT_SRV_SPECIAL_SERVICE_ALL)) && entry.cmode != CHANNEL_MODE_BRIDGE)
		mibentry.dgw = 1;
	else
		mibentry.dgw = 0;
#endif

	//Disable or Enable Service
	FETCH_INVALID_OPT(stemp, "cb_enblService", _OPT);
	mibentry.enable = (strcmp(stemp, "on") == 0 )? 1 : 0;

	totalEntry = mib_chain_total(MIB_ATM_VC_TBL);
	if (mibentry.cmode != CHANNEL_MODE_BRIDGE) {
		if (mibentry.IpProtocol & IPVER_IPV6)
			retrieveIPv6Record_cmcc(wp, &mibentry);
	}

	//mcastVlan
	FETCH_INVALID_OPT(stemp, "MulticastVID", _OPT);
	mibentry.mVid = atoi(stemp);

	if (strcmp(act, "Add") == 0)
	{
		int cnt = 0, pIdx;
		unsigned char vcIdx;
		int intVal, remained=0;
		int ifMap = 0;

		if (totalEntry >= MAX_VC_NUM)
		{
			strcpy(tmpBuf, strMaxVc);
			goto setErr_nochange;
		}

#ifdef CONFIG_RTK_L34_ENABLE
		remained = Check_RG_Intf_Count();
		if(remained == 0){
			/*Table FULL*/
			strcpy(tmpBuf, strTableFull);
			goto setErr_nochange;
		}
#endif
		if(entry.vlan==1)
		{
			for (i=0; i<totalEntry; i++) 
			{
				if (!mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&Entry))
				{
					boaError(wp, 400, strGetChainerror);
					return;
				}
				mType = MEDIA_INDEX(Entry.ifIndex);

#ifdef CONFIG_RTK_L34_ENABLE
				char yjyx_savevlan;
				mib_get(PROVINCE_YJYX_SAMEVLAN, &yjyx_savevlan);
				if(yjyx_savevlan)
				//skip
				;
				else{
					if (mType == MEDIA_ETH && Entry.vlan==1 && Entry.vid == entry.vid && CHECK_CONNECTION_MODE(Entry.cmode, entry.cmode)) {
						strcpy(tmpBuf, strConnectExist);
						goto setErr_nochange;
					}
				}
#else
				if (mType == MEDIA_ETH && Entry.vlan==1 && Entry.vid == entry.vid && CHECK_CONNECTION_MODE(Entry.cmode, entry.cmode)) {
					strcpy(tmpBuf, strConnectExist);
					goto setErr_nochange;
				}
#endif


				if (mType == MEDIA_ETH)
					ifMap |= 1 << ETH_INDEX(Entry.ifIndex);	// vc map
				ifMap |= (1 << 16) << PPP_INDEX(Entry.ifIndex); // PPP map
			}
			mibentry.vlan = entry.vlan;
			mibentry.vid = entry.vid;
			mibentry.vprio = entry.vprio;		
		}
		else
		{
			for (i=0; i<totalEntry; i++) {
				if (!mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&Entry))
				{
					boaError(wp, 400, strGetChainerror);
					return;
				}
				mType = MEDIA_INDEX(Entry.ifIndex);
#ifdef CONFIG_RTK_L34_ENABLE
				char yjyx_savevlan;
				mib_get(PROVINCE_YJYX_SAMEVLAN, &yjyx_savevlan);
				if(yjyx_savevlan)
					//skip
					;
				else{
					if (mType == MEDIA_ETH && Entry.vlan==0 && CHECK_CONNECTION_MODE(Entry.cmode, entry.cmode)) {
						strcpy(tmpBuf, strConnectExist);
						goto setErr_nochange;
					}
				}
				#else
				if (mType == MEDIA_ETH && Entry.vlan==0 && CHECK_CONNECTION_MODE(Entry.cmode, entry.cmode)) {
					strcpy(tmpBuf, strConnectExist);
					goto setErr_nochange;
				}
#endif
				if (mType == MEDIA_ETH)
					ifMap |= 1 << ETH_INDEX(Entry.ifIndex);	// vc map
				ifMap |= (1 << 16) << PPP_INDEX(Entry.ifIndex); // PPP map
			}
				mibentry.vlan = 0;
				mibentry.vid = 0;
				mibentry.vprio = 0;		
		}


		mibentry.ifIndex = if_find_index(mibentry.cmode, ifMap);
		mibentry.ifIndex = TO_IFINDEX(MEDIA_ETH, PPP_INDEX(mibentry.ifIndex), ETH_INDEX(mibentry.ifIndex));		
		AUG_PRT("The mibentry.ifIndex is 0x%x\n", mibentry.ifIndex);
		if (mibentry.ifIndex == NA_VC) {
			strcpy(tmpBuf, strMaxVc);
			goto setErr_nochange;
		}
		else if (mibentry.ifIndex == NA_PPP) {
			strcpy(tmpBuf, strMaxNumPPPoE);
			goto setErr_nochange;
		}
#ifdef _CWMP_MIB_ /*jiunming, for cwmp-tr069*/
		resetWanInstNum(&mibentry);
		updateWanInstNum(&mibentry);
#endif

		if (mibentry.cmode == CHANNEL_MODE_PPPOE)
		{
			if(mibentry.mtu > 1492)
				mibentry.mtu = 1492;
			//Include IPV6 header to avoid IPv6 fragmentation, IulianWu
			if ((mibentry.dslite_enable) && (mibentry.mtu > 1452))
				mibentry.mtu = 1452;
		}

#ifdef NEW_PORTMAPPING
		check_itfGroup(&mibentry, 0);
#endif

/*star:20090302 START wen INTERNET pvc start, igmp proxy open auto*/
		mibentry.enableIGMP=0;
		if(mibentry.cmode!=CHANNEL_MODE_BRIDGE)
			if (mibentry.applicationtype&(X_CT_SRV_INTERNET|X_CT_SRV_OTHER|X_CT_SRV_SPECIAL_SERVICE_ALL))
				mibentry.enableIGMP=1;
/*star:20090302 END*/
		// Mason Yu. ITMS4
#if defined(CONFIG_LUNA) && defined(GEN_WAN_MAC)
		{
//AUG_PRT("================>>>>>>>%s-%d mibentry.ifIndex=0x%x\n",__func__,__LINE__,mibentry.ifIndex);
		unsigned char macaddr[MAC_ADDR_LEN]={0};
		mib_get(MIB_ELAN_MAC_ADDR, (void *)macaddr);
		setup_mac_addr(macaddr,WAN_HW_ETHER_START_BASE + ETH_INDEX(mibentry.ifIndex));
		//macaddr[MAC_ADDR_LEN-1] += WAN_HW_ETHER_START_BASE + ETH_INDEX(mibentry.ifIndex);
		memcpy(mibentry.MacAddr, macaddr, MAC_ADDR_LEN);
//AUG_PRT("================>>>>>>>%s-%d %02X:%02X:%02X:%02X:%02X:%02X\n",__func__,__LINE__,macaddr[0],macaddr[1],macaddr[2],macaddr[3],macaddr[4],macaddr[5]);
		}
#endif

#ifdef CONFIG_IPV6
		setup_delegated_default_wanconn(&mibentry);
#endif

#ifdef _PRMT_X_CT_COM_DHCP_
		unsigned char opt60_type;

		mib_get(PROVINCE_DHCP_OPT60_TYPE, &opt60_type);
		for(i= 0 ; i < 4 ; i++)
		{
			if(opt60_type == DHCP_OPT60_TYPE_JSU)
				mibentry.dhcp_opt60_value_mode[i] = 2;

			mibentry.dhcp_opt60_type[i] = 34;
			mibentry.dhcp_opt125_type[i] = 2;
			mibentry.dhcpv6_opt16_type[i] = 34;
			mibentry.dhcpv6_opt17_type[i] = 2;
		}
#endif
		intVal = mib_chain_add(MIB_ATM_VC_TBL, (unsigned char*)&mibentry);
		if (intVal == 0) {
			strcpy(tmpBuf, strAddChainerror);
			goto setErr_restart;
		}
		else if (intVal == -1) {
			strcpy(tmpBuf, strTableFull);
			goto setErr_restart;
		}

/* YueMe uses app based rules. */
#ifndef CONFIG_YUEME
#if defined(CONFIG_USER_IP_QOS) && defined(_PRMT_X_CT_COM_QOS_)
		//Update QoS rule if mib CTQOS_MODE has string INTERNET and this new added WAN is with type INTERNET
		if((mibentry.applicationtype & X_CT_SRV_INTERNET)){
			char qos_mode[MAX_NAME_LEN]={0};
			if(mib_get(CTQOS_MODE, qos_mode)){
				if(strcasestr(qos_mode,"INTERNET")){
					printf("update MIB for QoS Mode %s\n",qos_mode);
					mib_get(CTQOS_MODE, (void *)qos_mode);
					updateMIBforQosMode(qos_mode);
				}
			}
		}
#endif
#endif
		// Mason Yu. ITMS4
		restartWAN(CONFIGONE, &mibentry);	 // Add
#ifdef CONFIG_CU
		syslog(LOG_INFO, "WEB: Add New Wan Configuration\n");
#endif
		goto setOk_filter;
	
	}
	else if (strcmp(act, "Modify") == 0)
	{
		int cnt=0, pIdx;
		int selected=-1;
		int itsMe;
		MIB_CE_ATM_VC_T myEntry;
		char webwanname[MAX_WAN_NAME_LEN];
		char mibwanname[MAX_WAN_NAME_LEN];
		
		ifMap=0;
		FETCH_INVALID_OPT(stemp, "wanName", _NEED);
		strncpy(webwanname,stemp,MAX_WAN_NAME_LEN-1);

		for (i=0; i<totalEntry; i++) 
		{
			if (!mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&Entry))
			{
				boaError(wp, 400, strGetChainerror);
				return;
			}
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
			//before delete wan, we must reset unbinded_port_vlan
			reset_unbinded_port_vlan(&Entry);
#endif
			getWanName(&Entry,mibwanname);
			//printf("\nmibname=%s\n",mibwanname);
			DEBUGPRINT;
			mType = MEDIA_INDEX(Entry.ifIndex);
			itsMe = 0;
			if (!strcmp(webwanname,mibwanname)) {
				itsMe = 1;
				if (selected == -1)
					selected = i;
				else{
					strcpy(tmpBuf, strConnectExist);
					goto setErr_nochange;
				}
			}
#ifdef CONFIG_RTK_L34_ENABLE
			char yjyx_savevlan;
			mib_get(PROVINCE_YJYX_SAMEVLAN, &yjyx_savevlan);
			if(yjyx_savevlan)
				//skip
				;
			else{
				if ((mType == MEDIA_ETH) &&
					(Entry.vlan == mibentry.vlan) && (Entry.vid == mibentry.vid) && CHECK_CONNECTION_MODE(Entry.cmode, mibentry.cmode) &&
					!itsMe){
					strcpy(tmpBuf, strConnectExist);
					goto setErr_nochange;
				}
			}
#else
			if ((mType == MEDIA_ETH) &&
				(Entry.vlan == mibentry.vlan) && (Entry.vid == mibentry.vid) && CHECK_CONNECTION_MODE(Entry.cmode, mibentry.cmode) &&
				!itsMe){
				strcpy(tmpBuf, strConnectExist);
				goto setErr_nochange;
			}
#endif

			if (!itsMe) {
DEBUGPRINT;
				if (mType == MEDIA_ETH)
					ifMap |= 1 << ETH_INDEX(Entry.ifIndex); // vc map
				ifMap |= (1 << 16) << PPP_INDEX(Entry.ifIndex); // PPP map
			}
		}


DEBUGPRINT;
		if (!mib_chain_get(MIB_ATM_VC_TBL, selected, (void *)&Entry)) {
			strcpy(tmpBuf, errGetEntry);
			goto setErr_nochange;
		}
		// restore stuff not posted in this form
		if (mibentry.enable
			&& ((CHANNEL_MODE_IPOE == mibentry.cmode)
			|| (CHANNEL_MODE_PPPOA == mibentry.cmode)
			|| (CHANNEL_MODE_PPPOE == mibentry.cmode)
			|| (CHANNEL_MODE_RT1483 == mibentry.cmode)))
		{
			/* restore igmp-proxy setting */
			mibentry.enableIGMP = Entry.enableIGMP;
		}
		if (mibentry.cmode == CHANNEL_MODE_PPPOE)
		{
			if (cnt > 0) {		// Jenny, for multisession PPPoE, ifIndex(VC device) must refer to existed PPPoE connection
				{
					ifMap &= 0xffff0000; // don't care the vc part
					mibentry.ifIndex = if_find_index(mibentry.cmode, ifMap);
					mibentry.ifIndex = TO_IFINDEX(MEDIA_ETH, PPP_INDEX(mibentry.ifIndex), ETH_INDEX(myEntry.ifIndex));
				}
			}
			else 
			{
DEBUGPRINT;
				mibentry.ifIndex = if_find_index(mibentry.cmode, ifMap);
				mibentry.ifIndex = TO_IFINDEX(MEDIA_ETH, PPP_INDEX(mibentry.ifIndex), ETH_INDEX(mibentry.ifIndex));
		
			}
		}
		else
		{
			mibentry.ifIndex = Entry.ifIndex;
			mibentry.ifIndex = TO_IFINDEX(MEDIA_ETH, PPP_INDEX(mibentry.ifIndex), ETH_INDEX(mibentry.ifIndex));
		}
DEBUGPRINT;

		mibentry.pppAuth = Entry.pppAuth;
		mibentry.rip = Entry.rip;
		
		if (mibentry.cmode == CHANNEL_MODE_PPPOE){
			if(mibentry.mtu > 1492)
				mibentry.mtu = 1492;
			//Include IPV6 header to avoid IPv6 fragmentation, IulianWu
			if ((mibentry.dslite_enable) && (mibentry.mtu > 1452))
				mibentry.mtu = 1452;
		}

DEBUGPRINT;
#ifdef CONFIG_SPPPD_STATICIP
		if(mibentry.cmode == CHANNEL_MODE_PPPOE)
		{
			mibentry.pppIp = Entry.pppIp;
			strcpy( mibentry.ipAddr, Entry.ipAddr);
		}
#endif
DEBUGPRINT;
#if 0//def PPPOE_PASSTHROUGH
		if (mibentry.cmode != CHANNEL_MODE_PPPOE) 
			if (mibentry.cmode == Entry.cmode)
				mibentry.brmode = Entry.brmode;		
#endif

#ifdef _CWMP_MIB_ /*jiunming, for cwmp-tr069*/
		mibentry.connDisable = 0;
		resetWanInstNum(&mibentry);
		mibentry.ConDevInstNum = Entry.ConDevInstNum;
		mibentry.ConIPInstNum = Entry.ConIPInstNum;
		mibentry.ConPPPInstNum = Entry.ConPPPInstNum;
		updateWanInstNum(&mibentry);
		//fprintf( stderr, "<%s:%d>NewInstNum=>ConDev:%u, PPPCon:%u, IPCon:%u\n", __FILE__, __LINE__, mibentry.ConDevInstNum, mibentry.ConPPPInstNum, mibentry.ConIPInstNum );

		mibentry.autoDisTime = Entry.autoDisTime;
		mibentry.warnDisDelay = Entry.warnDisDelay;
		//strcpy( entry.pppServiceName, Entry.pppServiceName );
		strcpy( mibentry.WanName, Entry.WanName );

#ifdef _PRMT_X_CT_COM_WANEXT_
		strcpy(mibentry.IPForwardList, Entry.IPForwardList);
#endif //_PRMT_X_CT_COM_WANEXT_
#ifdef _PRMT_X_CT_COM_DHCP_
		memcpy(mibentry.dhcpv6_opt16_enable, Entry.dhcpv6_opt16_enable, sizeof(Entry.dhcpv6_opt16_enable));
		memcpy(mibentry.dhcpv6_opt16_type, Entry.dhcpv6_opt16_type, sizeof(Entry.dhcpv6_opt16_type));
		memcpy(mibentry.dhcpv6_opt16_value_mode, Entry.dhcpv6_opt16_value_mode, sizeof(Entry.dhcpv6_opt16_value_mode));
		memcpy(mibentry.dhcpv6_opt16_value, Entry.dhcpv6_opt16_value, 4 * 80);
		memcpy(mibentry.dhcpv6_opt17_enable, Entry.dhcpv6_opt17_enable, sizeof(Entry.dhcpv6_opt17_enable));
		memcpy(mibentry.dhcpv6_opt17_type, Entry.dhcpv6_opt17_type, sizeof(Entry.dhcpv6_opt17_type));
		memcpy(mibentry.dhcpv6_opt17_sub_code, Entry.dhcpv6_opt17_sub_code, sizeof(Entry.dhcpv6_opt17_sub_code));
		memcpy(mibentry.dhcpv6_opt17_sub_data, Entry.dhcpv6_opt17_sub_data, 4 * 36);
		memcpy(mibentry.dhcpv6_opt17_value, Entry.dhcpv6_opt17_value, 4 * 36);

		memcpy(mibentry.dhcp_opt60_enable, Entry.dhcp_opt60_enable, sizeof(Entry.dhcp_opt60_enable));
		memcpy(mibentry.dhcp_opt60_type, Entry.dhcp_opt60_type, sizeof(Entry.dhcp_opt60_type));
		memcpy(mibentry.dhcp_opt60_value_mode, Entry.dhcp_opt60_value_mode, sizeof(Entry.dhcp_opt60_value_mode));
		memcpy(mibentry.dhcp_opt60_value, Entry.dhcp_opt60_value, 4 * 80);
		memcpy(mibentry.dhcp_opt125_enable, Entry.dhcp_opt125_enable, sizeof(Entry.dhcp_opt125_enable));
		memcpy(mibentry.dhcp_opt125_type, Entry.dhcp_opt125_type, sizeof(Entry.dhcp_opt125_type));
		memcpy(mibentry.dhcp_opt125_sub_code, Entry.dhcp_opt125_sub_code, sizeof(Entry.dhcp_opt125_sub_code));
		memcpy(mibentry.dhcp_opt125_sub_data, Entry.dhcp_opt125_sub_data, 4 * 36);
		memcpy(mibentry.dhcp_opt125_value, Entry.dhcp_opt125_value, 4 * 36);
#endif
#endif //_CWMP_MIB_

#ifdef CONFIG_RTK_L34_ENABLE
		mibentry.rg_wan_idx = Entry.rg_wan_idx;
#endif
#ifdef CONFIG_MCAST_VLAN
		//mibentry.mVid = Entry.mVid;
		//AUG_PRT("%s-%d mVlan=%d %d\n",__func__,__LINE__,mibentry.mVid, Entry.mVid);
#endif
			// find the ifIndex
		if (mibentry.cmode != Entry.cmode)
		{
			if (!(mibentry.cmode == CHANNEL_MODE_PPPOE && cnt>0)){	// Jenny, entries except multisession PPPoE
				mibentry.ifIndex = if_find_index(mibentry.cmode, ifMap);
				mibentry.ifIndex = TO_IFINDEX(MEDIA_ETH, PPP_INDEX(mibentry.ifIndex), ETH_INDEX(mibentry.ifIndex));
			}
			if (mibentry.ifIndex == NA_VC) {
				strcpy(tmpBuf, strMaxVc);
				goto setErr_nochange;
			}
			else if (mibentry.ifIndex == NA_PPP) {
				strcpy(tmpBuf, strMaxNumPPPoE);
				goto setErr_nochange;
			}
			// mode changed, restore to default
			if (mibentry.cmode == CHANNEL_MODE_PPPOE) {
				if(mibentry.mtu < 1492) //set by web
					mibentry.mtu = 1492;
				//Include IPV6 header to avoid IPv6 fragmentation, IulianWu
				if ((mibentry.dslite_enable) && (mibentry.mtu > 1452))
					mibentry.mtu = 1452;

			}
		}
#ifdef CONFIG_CMCC_IPV6_SECURITY_SUPPORT
		del_bridge_ip6sec_prefix_info(&Entry, &mibentry)
#endif
			

DEBUGPRINT;
		if( mibentry.ifIndex!=Entry.ifIndex ||
#if defined(IP_QOS) || defined(NEW_IP_QOS_SUPPORT)
			mibentry.enableIpQos != Entry.enableIpQos ||
#endif
			mibentry.cmode != Entry.cmode)
			resolveServiceDependency(selected);

		mibentry.vlan = entry.vlan;
		mibentry.vid = entry.vid;
		mibentry.vprio = entry.vprio;
#ifdef NEW_PORTMAPPING
		AUG_PRT("^O^ %s:%d. The mibentry.itfgroup is 0x%x, The Entry's itfgroup is 0x%x, the apptype is %d\n", __FILE__,
			__LINE__, mibentry.itfGroup, Entry.itfGroup, Entry.applicationtype);
		check_itfGroup(&mibentry, &Entry);
#endif
DEBUGPRINT;
		mibentry.enableIGMP=0;
		if(mibentry.cmode!=CHANNEL_MODE_BRIDGE)
#if defined(CONFIG_CMCC) || defined(CONFIG_CU) || defined(CONFIG_CU)			
			if (mibentry.applicationtype&(X_CT_SRV_INTERNET|X_CT_SRV_OTHER|X_CT_SRV_SPECIAL_SERVICE_ALL))
#else				
			if (mibentry.applicationtype&X_CT_SRV_INTERNET)
#endif				
				mibentry.enableIGMP=1;

		if(mibentry.cmode == CHANNEL_MODE_PPPOE || mibentry.cmode == CHANNEL_MODE_PPPOA){	
			if(isAllStar(mibentry.pppPassword))
				strncpy( mibentry.pppPassword, Entry.pppPassword , MAX_NAME_LEN);
		}

//add by ramen for DNS bind pvc
#ifdef DNS_BIND_PVC_SUPPORT
		MIB_CE_ATM_VC_T dnsPvcEntry;
		if(mib_chain_get(MIB_ATM_VC_TBL,selected,&dnsPvcEntry)&&(dnsPvcEntry.cmode!=CHANNEL_MODE_BRIDGE))
		{
			int tempi=0;
			unsigned int pvcifIdx=0;
			for(tempi=0;tempi<3;tempi++)
			{
				mib_get(MIB_DNS_BIND_PVC1+tempi,(void*)&pvcifIdx);
				if(pvcifIdx==dnsPvcEntry.ifIndex)//I get it
				{
					if(mibentry.cmode==CHANNEL_MODE_BRIDGE)
						pvcifIdx = DUMMY_IFINDEX;
					else
						pvcifIdx=mibentry.ifIndex;
					mib_set(MIB_DNS_BIND_PVC1+tempi,(void*)&pvcifIdx);
				}
			}
		}
#endif
#ifdef CONFIG_IPV6
#ifdef DNSV6_BIND_PVC_SUPPORT
		MIB_CE_ATM_VC_T dnsv6PvcEntry;
		if(mib_chain_get(MIB_ATM_VC_TBL,selected,&dnsv6PvcEntry)&&(dnsv6PvcEntry.cmode!=CHANNEL_MODE_BRIDGE))
		{
			int tempi=0;
			unsigned int pvcifIdx=0;
			for(tempi=0;tempi<3;tempi++)
			{
				mib_get(MIB_DNSV6_BIND_PVC1+tempi,(void*)&pvcifIdx);
				if(pvcifIdx==dnsv6PvcEntry.ifIndex)//I get it
				{
					if(mibentry.cmode==CHANNEL_MODE_BRIDGE)
						pvcifIdx = DUMMY_IFINDEX;
					else
						pvcifIdx=mibentry.ifIndex;
					mib_set(MIB_DNSV6_BIND_PVC1+tempi,(void*)&pvcifIdx);
				}
			}
		}
#endif
#endif

#if defined(CONFIG_LUNA) && defined(GEN_WAN_MAC)
		unsigned char macaddr[MAC_ADDR_LEN]={0};
		/* Magician: Auto generate MAC address for every WAN interface. */
		mib_get(MIB_ELAN_MAC_ADDR, (void *)macaddr);
		setup_mac_addr(macaddr,WAN_HW_ETHER_START_BASE + ETH_INDEX(mibentry.ifIndex));	
		//macaddr[MAC_ADDR_LEN-1] += WAN_HW_ETHER_START_BASE + ETH_INDEX(mibentry.ifIndex);
		memcpy(mibentry.MacAddr, macaddr, MAC_ADDR_LEN);
		/* End Majgician */
#endif

#ifdef CONFIG_IPV6
		setup_delegated_default_wanconn(&mibentry);
#endif

		deleteConnection(CONFIGONE, &Entry);		// Modify
		mib_chain_update(MIB_ATM_VC_TBL, (void *)&mibentry, selected);
		restartWAN(CONFIGONE, &mibentry);			// Modify

#ifdef CONFIG_CU
		syslog(LOG_INFO, "WEB: Modify Wan Configuration\n");
#endif

DEBUGPRINT;
		goto setOk_filter;
		
	}
	else {lineno = __LINE__; goto check_err;}
		

_COND_REDIRECT;

check_err:
		_TRACE_LEAVEL;		
		strcpy(tmpBuf, "参数错误");
		goto setErr_nochange;
		return;

setOk_filter:
#ifdef COMMIT_IMMEDIATELY
		Commit();
#endif

	DEBUGPRINT;//ql_xu
#ifdef VOIP_SUPPORT
		web_restart_solar();
#endif
	submitUrl = boaGetVar(wp, "submit-url", "");   // hidden page

	if (submitUrl[0])
		boaRedirect(wp, submitUrl);
	else
		boaDone(wp, 200);

	return;
setErr_restart:
setErr_nochange:
		ERR_MSG(tmpBuf);


}
#endif

void formEthernet(request * wp, char *path, char *query)
{
	struct atmvc_entryx	entry;
	char*			pifname = NULL;
	char*			stemp = "";
	char 			*submitUrl;
	unsigned int	fstdns = 0;	//缺省DNS
	unsigned int	secdns = 0;	//可选DNS
	int				ival = 0;
#ifdef CONFIG_USER_PPPOE_PROXY
	int				pppnummax = 5;//default value
#endif
	int				lineno = __LINE__;

	MIB_CE_ATM_VC_T mibentry,Entry;
	int totalEntry,i;
	char tmpBuf[100];
	int remained=0;
	unsigned int ifMap;
	char* strValue;
	char *dns1Ip, *dns2Ip;
#ifdef CONFIG_IPV6
	char *dns1Ipv6, *dns2Ipv6;
#endif
	unsigned char mode;
	unsigned char voip_wan_changed = 0;


	char act[10];
	MEDIA_TYPE_T mType;
/*star:20080718 START add for set acname by net_adsl_links_acname.asp*/
	int acflag=0;
	FETCH_INVALID_OPT(stemp, "acnameflag", _NEED);
	if(strcmp(stemp,"have")==0)
		acflag=1;
/*star:20080718 END*/
	_TRACE_CALL;
	FETCH_INVALID_OPT(stemp, "action", _NEED);
	strncpy(act,stemp,10);


	if(strcmp(stemp, "rm") == 0)	//remove
	{
		int idx=-1;
		char webwanname[MAX_WAN_NAME_LEN];
		char mibwanname[MAX_WAN_NAME_LEN];

		/************Place your code here, do what you want to do! ************/
		/*use 'stemp' as 'link name' to match 'atmvc_entry' entry and remove relevant entry from MIB */
		/************Place your code here, do what you want to do! ************/

		FETCH_INVALID_OPT(stemp, "lst", _NEED);
		strncpy(webwanname,stemp,MAX_WAN_NAME_LEN-1);

		totalEntry = mib_chain_total(MIB_ATM_VC_TBL);
		for(i=0;i<totalEntry;i++){
			if(mib_chain_get(MIB_ATM_VC_TBL,i,&Entry)!=1)
				continue;
			getWanName(&Entry,mibwanname);
			if((!strcmp(mibwanname,webwanname))){
				idx=i;
				break;
			}
		}

/* YueMe uses app based rules. */
#ifndef CONFIG_YUEME
#if defined(CONFIG_USER_IP_QOS) && defined(_PRMT_X_CT_COM_QOS_)
		//Delete QoS rule if CTQOS_MODE has string INTERNET and this WAN is with type INTERNET
		if((Entry.applicationtype & X_CT_SRV_INTERNET)){
			char qos_mode[MAX_NAME_LEN]={0};

			if(mib_get(CTQOS_MODE, qos_mode)){
				if(strcasestr(qos_mode,"INTERNET")){
					printf("delete MIB for QoS Mode INTERNET\n");
					delQoSRuleByMode("INTERNET");
				}
			}
		}
#endif
#endif

		if(idx!=-1){
			resolveServiceDependency(idx);

#ifdef DNS_BIND_PVC_SUPPORT
			MIB_CE_ATM_VC_T dnsPvcEntry;
			if(mib_chain_get(MIB_ATM_VC_TBL,idx,&dnsPvcEntry)&&(dnsPvcEntry.cmode!=CHANNEL_MODE_BRIDGE))
			{
				int tempi=0;
				unsigned int pvcifIdx=0;
				for(tempi=0;tempi<3;tempi++)
				{
					mib_get(MIB_DNS_BIND_PVC1+tempi,(void*)&pvcifIdx);
					if(pvcifIdx==dnsPvcEntry.ifIndex)//I get it
					{
						pvcifIdx=DUMMY_IFINDEX;
						mib_set(MIB_DNS_BIND_PVC1+tempi,(void*)&pvcifIdx);
					}
				}
			}
#endif

#ifdef CONFIG_IPV6
#ifdef DNSV6_BIND_PVC_SUPPORT
			MIB_CE_ATM_VC_T dnsv6PvcEntry;
			if(mib_chain_get(MIB_ATM_VC_TBL,idx,&dnsv6PvcEntry)&&(dnsv6PvcEntry.cmode!=CHANNEL_MODE_BRIDGE))
			{
				int tempi=0;
				unsigned int pvcifIdx=0;
				for(tempi=0;tempi<3;tempi++)
				{
					mib_get(MIB_DNSV6_BIND_PVC1+tempi,(void*)&pvcifIdx);
					if(pvcifIdx==dnsv6PvcEntry.ifIndex)//I get it
					{
						pvcifIdx = DUMMY_IFINDEX;
						mib_set(MIB_DNSV6_BIND_PVC1+tempi,(void*)&pvcifIdx);
					}
				}
			}
#endif
#endif

			// Mason Yu. ITMS4
			{
				MIB_CE_ATM_VC_T vcEntry;
				if (mib_chain_get(MIB_ATM_VC_TBL, idx, (void *)&vcEntry))
				{
#ifdef CONFIG_IPV6
					clear_delegated_default_wanconn(&vcEntry);
#endif

#ifdef NEW_IP_QOS_SUPPORT//ql 20081125
					delIpQosTcRule(&vcEntry);
#endif
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
					reset_unbinded_port_vlan(&vcEntry);
#endif

					deleteConnection(CONFIGONE, &vcEntry);
					if(vcEntry.applicationtype & X_CT_SRV_VOICE)
						voip_wan_changed = 1;
				}
			}

			if(mib_chain_delete(MIB_ATM_VC_TBL, idx) != 1) {
					strcpy(tmpBuf, strDelChainerror);
					goto setErr_restart;
			}


//ql add: check if it is necessary to delete a group of interface
#ifdef ITF_GROUP
			{
				int wanPortNum;
				unsigned int swNum, vcNum;
				MIB_CE_SW_PORT_T Entry;
				MIB_CE_ATM_VC_T pvcEntry;
				int j, grpnum;
				char mygroup;
				int enable_portmap =0;

				vcNum = mib_chain_total(MIB_ATM_VC_TBL);
				for (grpnum=1; grpnum<=4; grpnum++) {
					wanPortNum = 0;

					for (j=0; j<vcNum; j++) {
						if (!mib_chain_get(MIB_ATM_VC_TBL, j, (void *)&pvcEntry))
						{
							//boaError(wp, 400, "Get chain record error!\n");
							printf("Get chain record error!\n");
							return;
						}
						if(pvcEntry.itfGroup!=0)
							enable_portmap++;
						if (pvcEntry.enable == 0 || pvcEntry.itfGroup!=grpnum)
							continue;

						if (pvcEntry.applicationtype & (X_CT_SRV_INTERNET|X_CT_SRV_OTHER))
							wanPortNum++;

					}
					//printf("\nwanPortNum=%d\n",wanPortNum);
					if (0 == wanPortNum) {
						//printf("delete port mapping group %d\n", grpnum);
						//release LAN ports
						swNum = mib_chain_total(MIB_SW_PORT_TBL);
						for (j=swNum; j>0; j--) {
							if (!mib_chain_get(MIB_SW_PORT_TBL, j-1, (void *)&Entry))
								return;
							if (Entry.itfGroup == grpnum) {
								Entry.itfGroup = 0;
								mib_chain_update(MIB_SW_PORT_TBL, (void *)&Entry, j-1);
							}
						}
#ifdef WLAN_SUPPORT
						//release wlan0
						mib_get(MIB_WLAN_ITF_GROUP, (void *)&mygroup);
						if (mygroup == grpnum) {
							mygroup = 0;
							mib_set(MIB_WLAN_ITF_GROUP, (void *)&mygroup);
						}
#endif
#ifdef WLAN_MBSSID
						//release MBSSID
						for (j=1; j<5; j++) {
							mib_get(MIB_WLAN_VAP0_ITF_GROUP+j-1, (void *)&mygroup);
							if (mygroup == grpnum) {
								mygroup = 0;
								mib_set(MIB_WLAN_VAP0_ITF_GROUP+j-1, (void *)&mygroup);
							}
						}
#endif
						for (j=0; j<vcNum; j++) {
							if (!mib_chain_get(MIB_ATM_VC_TBL, j, (void *)&pvcEntry))
							{
								//boaError(wp, 400, "Get chain record error!\n");
								printf("Get chain record error!\n");
								return;
							}
							if(pvcEntry.itfGroup==grpnum){
								printf("\nmodify tr069 portmapping!\n");
								pvcEntry.itfGroup=0;
								mib_chain_update(MIB_ATM_VC_TBL,(void *)&pvcEntry,j);
							}
						}
						//setgroup("", grpnum, lowPrio);
						setgroup("", grpnum);

					}
				}

				if(!enable_portmap)
				{
				    printf("\nstop portmapping!\n");

			            mib_get(MIB_MPMODE, (void *)&mode);
			             mode &= 0xfe;
			            mib_set(MIB_MPMODE, (void *)&mode);
				}
			}//end
#endif
		}else
		{
			strcpy(tmpBuf, strSelectvc);
			goto setErr_nochange;
		}

		// Mason Yu. ITMS4
		restartWAN(CONFIGONE, NULL);
		goto setOk_filter;

	}
	else if(strcmp(stemp, "sv") == 0)	//add or modify
		{
		memset(&entry, 0, sizeof(entry));
		memset(&mibentry, 0, sizeof(mibentry));

		//_GET_PSTR(ifname, _OPT);
		//(fstdns, _OPT);
		//_GET_IP(secdns, _OPT);
		// Mason Yu. for IPV6
#ifdef CONFIG_IPV6
		strValue = boaGetVar(wp, "IpProtocolType", "");
		if (strValue[0]) {
			mibentry.IpProtocol = strValue[0] - '0';
		}

#endif

		_ENTRY_BOOL(napt, _NEED);

		_ENTRY_INT(cmode, _NEED);
		if(entry.cmode > 2){lineno = __LINE__; goto check_err;}

		switch(entry.cmode)
		{
		case CHANNEL_MODE_BRIDGE://bridge
			{
				_ENTRY_BOOL(brmode, _NEED);
			}break;
		case CHANNEL_MODE_IPOE://route
			{
#ifdef CONFIG_IPV6
				if (mibentry.IpProtocol & IPVER_IPV4) {
#endif
				_ENTRY_INT(ipDhcp, _NEED);
				if(entry.ipDhcp > 1){lineno = __LINE__; goto check_err;}
				if(entry.cmode == 1)//static ip
				{
					//_ENTRY_IP(ipAddr, _NEED);
					FETCH_INVALID_OPT(stemp, "ipAddr", _NEED);
					//printf("\nweb ip %s\n",stemp);
					*(unsigned int*)&(entry.ipAddr) = inet_addr(stemp);
					//printf("\nentry ip:%x\n",*(unsigned int*)&(entry.ipAddr));
					_ENTRY_IP(remoteIpAddr, _NEED);
					_ENTRY_IP(netMask, _NEED);
				}
#ifdef CONFIG_IPV6
				}
#endif
			}break;
		case CHANNEL_MODE_PPPOE://pppoe
			{
/*star:20090302 START ppp username and password can be empty*/
				//_ENTRY_STR(pppUsername, _NEED);
				//_ENTRY_STR(pppPassword, _NEED);
				//_ENTRY_STR(pppUsername, _OPT);
				//_ENTRY_STR(pppPassword, _OPT);
                FETCH_INVALID_OPT(stemp, "encodePppUserName", _NEED);
    			data_base64decode(stemp, entry.pppUsername);
    			if ( strlen(entry.pppUsername) >= MAX_NAME_LEN ) {
                    lineno = __LINE__;
    				goto check_err;
    			}
    			entry.pppUsername[MAX_NAME_LEN-1]='\0';

                FETCH_INVALID_OPT(stemp, "encodePppPassword", _NEED);
    			data_base64decode(stemp, entry.pppPassword);
    			if ( strlen(entry.pppPassword) >= MAX_NAME_LEN ) {
    				lineno = __LINE__;
    				goto check_err;
    			}
    			entry.pppPassword[MAX_NAME_LEN-1]='\0';
/*star:20090302 END*/

				_ENTRY_INT(pppCtype, _NEED);
				if(entry.pppCtype > 1){lineno = __LINE__; goto check_err;}
				_ENTRY_STR(pppServiceName, _OPT);
/*star:20080718 START add for set acname by net_adsl_links_acname.asp*/
				if(acflag==1)
					_ENTRY_STR(pppACName, _OPT);
/*star:20080718 END*/
#ifdef CONFIG_USER_PPPOE_PROXY
				_ENTRY_BOOL(PPPoEProxyEnable, _NEED);
				if(entry.PPPoEProxyEnable)
				{
					_ENTRY_INT(PPPoEProxyMaxUser, _NEED);
					if(entry.PPPoEProxyMaxUser < 0 || entry.PPPoEProxyMaxUser > (unsigned)pppnummax){lineno = __LINE__; goto check_err;}
				}
				_ENTRY_BOOL(brmode, _NEED);
#endif
			}break;
		}

		_ENTRY_BOOL(vlan, _NEED);
		if(entry.vlan)
		{
			_ENTRY_INT(vid, _NEED);
			if(entry.vid > 4095){lineno = __LINE__; goto check_err;}

			_ENTRY_INT(vprio, _NEED);// entry.vprio == (无)
			if(entry.vprio > 8){lineno = __LINE__; goto check_err;}
		}
		_ENTRY_INT(mtu, _NEED);
		if(entry.mtu > 1500 || entry.mtu < 576){lineno = __LINE__; goto check_err;}
		_ENTRY_INT(vpass, _OPT);

		_ENTRY_INT(itfGroup, _NEED);


		_ENTRY_BOOL(qos, _NEED);

		_ENTRY_INT(applicationtype, _NEED);
		_ENTRY_BOOL(disableLanDhcp, _NEED);
		web2mib(&entry,&mibentry);
#ifdef CONFIG_USER_PPPOE_PROXY
		if(entry.PPPoEProxyEnable){
			if(mibentry.itfGroup > 0){
				system("echo 1 > /proc/rg/pppoe_proxy_only_for_binding_packet");
				printf("echo 1 > /proc/rg/pppoe_proxy_only_for_binding_packet\n");
			}else{
				system("echo 0 > /proc/rg/pppoe_proxy_only_for_binding_packet");
				printf("echo 0 > /proc/rg/pppoe_proxy_only_for_binding_packet\n");
			}
		}
#endif
		if (mibentry.cmode == CHANNEL_MODE_IPOE)
		{
			strValue = boaGetVar(wp, "dnsMode", "");
			if (strValue[0]) {
				mibentry.dnsMode = strValue[0] - '0';
			}

			dns1Ip = boaGetVar(wp, "v4dns1", "");
			if (dns1Ip[0]) {
				if (!inet_aton(dns1Ip, (struct in_addr *)&mibentry.v4dns1)) {
					strcpy(tmpBuf, "不合法的dnsv4 1 IP地址!"); //Invalid dnsv4 1 IP-address value!
					goto setErr_nochange;
				}
			}

			dns2Ip = boaGetVar(wp, "v4dns2", "");
			if (dns2Ip[0]) {
				if (!inet_aton(dns2Ip, (struct in_addr *)&mibentry.v4dns2)) {
					strcpy(tmpBuf, "不合法的dnsv4 2 IP地址!"); //Invalid dnsv4 2 IP-address value!
					goto setErr_nochange;
				}
			}
		}
		else
			mibentry.dnsMode = 1; // default is enable dnsMode

#ifdef CONFIG_IPV6
		if(mibentry.cmode == CHANNEL_MODE_IPOE){
			strValue = boaGetVar(wp, "dnsv6Mode", "");
			if (strValue[0]) {
				printf("dnsv6Mode %s \n", strValue);
				mibentry.dnsv6Mode = atoi(strValue);
			}

			dns1Ipv6 = boaGetVar(wp, "Ipv6Dns1", "");
			if (dns1Ipv6[0]) {
				printf("dnsv6 Address1 %s \n", dns1Ipv6);
				if (!inet_pton(PF_INET6, dns1Ipv6, (struct in6_addr *)mibentry.Ipv6Dns1)) {
					strcpy(tmpBuf, "不合法的dnsv6 1 IP地址!"); //Invalid dnsv6 1 IP-address value!
					goto setErr_nochange;
				}
			}

			dns2Ipv6 = boaGetVar(wp, "Ipv6Dns2", "");
			if (dns2Ipv6[0]) {
				printf("dnsv6 Address2 %s \n", dns2Ipv6);
				if (!inet_pton(PF_INET6, dns2Ipv6, (struct in6_addr *)mibentry.Ipv6Dns2)) {
					strcpy(tmpBuf, "不合法的dnsv6 2 IP地址!"); //Invalid dnsv6 2 IP-address value!
					goto setErr_nochange;
				}
			}
		}
		else{
			mibentry.dnsv6Mode = 1; // default is enable dnsMode
			printf("dnsv6Mode %d \n", mibentry.dnsv6Mode);
		}
#endif

		if(mibentry.applicationtype & ~CT_SRV_MASK)
			{lineno = __LINE__; goto check_err;}

		// E8B: if 'INTERNET', set as default route.
#if 0//ndef CONFIG_RTK_L34_ENABLE
		if((mibentry.applicationtype & (X_CT_SRV_INTERNET|X_CT_SRV_SPECIAL_SERVICE_ALL)) && entry.cmode != CHANNEL_MODE_BRIDGE)
			mibentry.dgw = 1;
		else
			mibentry.dgw = 0;
#endif
		//_ENTRY_BOOL(dgw,_NEED);

		/************Place your code here, do what you want to do! ************/
		/************Place your code here, do what you want to do! ************/

		totalEntry = mib_chain_total(MIB_ATM_VC_TBL);
		mibentry.enable=1;//always enable

#ifdef CONFIG_IPV6
		if (mibentry.cmode != CHANNEL_MODE_BRIDGE) {
			if (mibentry.IpProtocol & IPVER_IPV6)
				retrieveIPv6Record(wp, &mibentry);
		}
#endif

		FETCH_INVALID_OPT(stemp, "lkname", _NEED);
		if(strcmp(stemp,"new")==0){   //add
			int cnt, pIdx;
			unsigned char vcIdx;
			int intVal;

			if (totalEntry >= MAX_VC_NUM)
			{
				strcpy(tmpBuf, strMaxVc);
				goto setErr_nochange;
			}
			// check if connection exists
			ifMap = 0;
			cnt=0;
#ifdef CONFIG_RTK_L34_ENABLE
			remained = Check_RG_Intf_Count();
			if(remained == 0){
				/*Table FULL*/
				strcpy(tmpBuf, strTableFull);
				goto setErr_nochange;
			}
#endif
			if(entry.vlan==1){
				for (i=0; i<totalEntry; i++) {
					if (!mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&Entry))
					{
						boaError(wp, 400, strGetChainerror);
						return;
					}
					mType = MEDIA_INDEX(Entry.ifIndex);

					{
						#ifdef CONFIG_RTK_L34_ENABLE
						char yjyx_savevlan;
						mib_get(PROVINCE_YJYX_SAMEVLAN, &yjyx_savevlan);
						if(yjyx_savevlan)
							//skip
							;
						else{
							if (mType == MEDIA_ETH && Entry.vlan==1 && Entry.vid == entry.vid && CHECK_CONNECTION_MODE(Entry.cmode, entry.cmode)) {
								strcpy(tmpBuf, strConnectExist);
								goto setErr_nochange;
							}
						}
						#else
						if (mType == MEDIA_ETH && Entry.vlan==1 && Entry.vid == entry.vid && CHECK_CONNECTION_MODE(Entry.cmode, entry.cmode)) {
							strcpy(tmpBuf, strConnectExist);
							goto setErr_nochange;
						}
						#endif
					}

					{
						if (mType == MEDIA_ETH)
							ifMap |= 1 << ETH_INDEX(Entry.ifIndex);	// vc map
					}
					ifMap |= (1 << 16) << PPP_INDEX(Entry.ifIndex); // PPP map
				}
				mibentry.vlan = entry.vlan;
				mibentry.vid = entry.vid;
				mibentry.vprio = entry.vprio;
			}
			else{
				for (i=0; i<totalEntry; i++) {
					if (!mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&Entry))
					{
						boaError(wp, 400, strGetChainerror);
						return;
					}
					mType = MEDIA_INDEX(Entry.ifIndex);

					{
						#ifdef CONFIG_RTK_L34_ENABLE
						char yjyx_savevlan;
						mib_get(PROVINCE_YJYX_SAMEVLAN, &yjyx_savevlan);
						if(yjyx_savevlan)
							//skip
							;
						else{
							if (mType == MEDIA_ETH && Entry.vlan==0 && CHECK_CONNECTION_MODE(Entry.cmode, entry.cmode)) {
								strcpy(tmpBuf, strConnectExist);
								goto setErr_nochange;
							}
						}
						#else
						if (mType == MEDIA_ETH && Entry.vlan==0 && CHECK_CONNECTION_MODE(Entry.cmode, entry.cmode)) {
							strcpy(tmpBuf, strConnectExist);
							goto setErr_nochange;
						}
						#endif

					}

					{
						if (mType == MEDIA_ETH)
							ifMap |= 1 << ETH_INDEX(Entry.ifIndex);	// vc map
					}
					ifMap |= (1 << 16) << PPP_INDEX(Entry.ifIndex); // PPP map
				}
				mibentry.vlan = 0;
				mibentry.vid = 0;
				mibentry.vprio = 0;
			}

			if (cnt == 0)	// pvc not exists
			{
				mibentry.ifIndex = if_find_index(mibentry.cmode, ifMap);
				mibentry.ifIndex = TO_IFINDEX(MEDIA_ETH, PPP_INDEX(mibentry.ifIndex), ETH_INDEX(mibentry.ifIndex));
				AUG_PRT("The mibentry.ifIndex is 0x%x\n", mibentry.ifIndex);
				if (mibentry.ifIndex == NA_VC) {
					strcpy(tmpBuf, strMaxVc);
					goto setErr_nochange;
				}
				else if (mibentry.ifIndex == NA_PPP) {
					strcpy(tmpBuf, strMaxNumPPPoE);
					goto setErr_nochange;
				}

#ifdef _CWMP_MIB_ /*jiunming, for cwmp-tr069*/
				resetWanInstNum(&mibentry);
				updateWanInstNum(&mibentry);
#endif
			}

			// set default
			if (mibentry.cmode == CHANNEL_MODE_PPPOE)
			{
				if(mibentry.mtu > 1492)
					mibentry.mtu = 1492;
				//Include IPV6 header to avoid IPv6 fragmentation, IulianWu
				if ((mibentry.dslite_enable) && (mibentry.mtu > 1452))
					mibentry.mtu = 1452;
			}
#if 0
			if (mibentry.cmode == CHANNEL_MODE_PPPOE)
			{
				mibentry.mtu = 1492;
/*
#ifdef CONFIG_USER_PPPOE_PROXY
				mibentry.PPPoEProxyMaxUser=4;
				mibentry.PPPoEProxyEnable=0;
#endif
*///set by web
			}
			else
				mibentry.mtu = 1500;
#endif
/*
#ifdef CONFIG_EXT_SWITCH
			// VLAN
			mibentry.vlan = 0;	// disable
			mibentry.vid = 0; // VLAN tag
			mibentry.vprio = 0; // priority bits (0 ~ 7)
			mibentry.vpass = 0; // no pass-through
#endif
*///set by web
// todo: check e8b

#ifdef NEW_PORTMAPPING
			check_itfGroup(&mibentry, 0);
#endif

/*			if(mib_chain_add(MIB_ATM_VC_TBL, (unsigned char*)&mibentry) != 1){
				strcpy(tmpBuf, strAddChainerror);
				goto setErr_filter;
			}
*/
/*star:20090302 START wen INTERNET pvc start, igmp proxy open auto*/
			mibentry.enableIGMP=0;
			if(mibentry.cmode!=CHANNEL_MODE_BRIDGE)
				if (mibentry.applicationtype&(X_CT_SRV_INTERNET|X_CT_SRV_OTHER|X_CT_SRV_SPECIAL_SERVICE_ALL))
					mibentry.enableIGMP=1;
/*star:20090302 END*/
			// Mason Yu. ITMS4
#if defined(CONFIG_LUNA) && defined(GEN_WAN_MAC)
			{
//AUG_PRT("================>>>>>>>%s-%d mibentry.ifIndex=0x%x\n",__func__,__LINE__,mibentry.ifIndex);
			unsigned char macaddr[MAC_ADDR_LEN]={0};
			mib_get(MIB_ELAN_MAC_ADDR, (void *)macaddr);
			setup_mac_addr(macaddr,WAN_HW_ETHER_START_BASE + ETH_INDEX(mibentry.ifIndex));	
			//macaddr[MAC_ADDR_LEN-1] += WAN_HW_ETHER_START_BASE + ETH_INDEX(mibentry.ifIndex);
			memcpy(mibentry.MacAddr, macaddr, MAC_ADDR_LEN);
//AUG_PRT("================>>>>>>>%s-%d %02X:%02X:%02X:%02X:%02X:%02X\n",__func__,__LINE__,macaddr[0],macaddr[1],macaddr[2],macaddr[3],macaddr[4],macaddr[5]);
			}
#endif

#ifdef CONFIG_IPV6
			setup_delegated_default_wanconn(&mibentry);
#endif

#ifdef _PRMT_X_CT_COM_DHCP_
			unsigned char opt60_type;

			mib_get(PROVINCE_DHCP_OPT60_TYPE, &opt60_type);
			for(i= 0 ; i < 4 ; i++)
			{
				if(opt60_type == DHCP_OPT60_TYPE_JSU)
					mibentry.dhcp_opt60_value_mode[i] = 2;

				mibentry.dhcp_opt60_type[i] = 34;
				mibentry.dhcp_opt125_type[i] = 2;
				mibentry.dhcpv6_opt16_type[i] = 34;
				mibentry.dhcpv6_opt17_type[i] = 2;
			}
#endif
			intVal = mib_chain_add(MIB_ATM_VC_TBL, (unsigned char*)&mibentry);
			if (intVal == 0) {
				strcpy(tmpBuf, strAddChainerror);
				goto setErr_restart;
			}
			else if (intVal == -1) {
				strcpy(tmpBuf, strTableFull);
				goto setErr_restart;
			}
			// Kaohj -- Queue LEN table not supportted.
			#if 0
#ifndef QOS_SETUP_IMQ
			//ql_xu: add qos queue
			if (mibentry.enableIpQos)
				addIpQosQueue(mibentry.ifIndex);
#endif
			#endif

/* YueMe uses app based rules. */
#ifndef CONFIG_YUEME
#if defined(CONFIG_USER_IP_QOS) && defined(_PRMT_X_CT_COM_QOS_)
			//Update QoS rule if mib CTQOS_MODE has string INTERNET and this new added WAN is with type INTERNET
			if((mibentry.applicationtype & X_CT_SRV_INTERNET)){
				char qos_mode[MAX_NAME_LEN]={0};

				if(mib_get(CTQOS_MODE, qos_mode)){
					if(strcasestr(qos_mode,"INTERNET")){
						printf("update MIB for QoS Mode %s\n",qos_mode);
						mib_get(CTQOS_MODE, (void *)qos_mode);
						updateMIBforQosMode(qos_mode);
					}
				}
			}
#endif
#endif

			// Mason Yu. ITMS4
			restartWAN(CONFIGONE, &mibentry);    // Add
			if(mibentry.applicationtype & X_CT_SRV_VOICE)
				voip_wan_changed = 1;
			goto setOk_filter;

		}else{   //modify
			int cnt=0, pIdx;
			int selected=-1;
			int itsMe;
			MIB_CE_ATM_VC_T myEntry;
			char webwanname[MAX_WAN_NAME_LEN];
			char mibwanname[MAX_WAN_NAME_LEN];

			ifMap=0;
			FETCH_INVALID_OPT(stemp, "lst", _NEED);
			strncpy(webwanname,stemp,MAX_WAN_NAME_LEN-1);

			for (i=0; i<totalEntry; i++) {
				if (!mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&Entry))
				{
					boaError(wp, 400, strGetChainerror);
					return;
				}
				getWanName(&Entry,mibwanname);
				//printf("\nmibname=%s\n",mibwanname);
		DEBUGPRINT;
				mType = MEDIA_INDEX(Entry.ifIndex);
				itsMe = 0;
				if (!strcmp(webwanname,mibwanname)) {
					itsMe = 1;
					if (selected == -1)
						selected = i;
					else{
						strcpy(tmpBuf, strConnectExist);
						goto setErr_nochange;
					}
				}
				{
					#ifdef CONFIG_RTK_L34_ENABLE
					char yjyx_savevlan;
					mib_get(PROVINCE_YJYX_SAMEVLAN, &yjyx_savevlan);
					if(yjyx_savevlan)
						//skip
						;
					else{
						if ((mType == MEDIA_ETH) &&
							(Entry.vlan == mibentry.vlan) && (Entry.vid == mibentry.vid) && CHECK_CONNECTION_MODE(Entry.cmode, mibentry.cmode) &&
							!itsMe){
							strcpy(tmpBuf, strConnectExist);
							goto setErr_nochange;
						}
					}
					#else
						if ((mType == MEDIA_ETH) &&
							(Entry.vlan == mibentry.vlan) && (Entry.vid == mibentry.vid) && CHECK_CONNECTION_MODE(Entry.cmode, mibentry.cmode) &&
							!itsMe){
							strcpy(tmpBuf, strConnectExist);
							goto setErr_nochange;
						}
					#endif
				}

				if (!itsMe) {
		DEBUGPRINT;
					{
						if (mType == MEDIA_ETH)
							ifMap |= 1 << ETH_INDEX(Entry.ifIndex);	// vc map
					}
					ifMap |= (1 << 16) << PPP_INDEX(Entry.ifIndex); // PPP map
				}
			}

		DEBUGPRINT;
			if (!mib_chain_get(MIB_ATM_VC_TBL, selected, (void *)&Entry)) {
				strcpy(tmpBuf, errGetEntry);
				goto setErr_nochange;
			}
			// restore stuff not posted in this form
			if (mibentry.enable
				&& ((CHANNEL_MODE_IPOE == mibentry.cmode)
				|| (CHANNEL_MODE_PPPOA == mibentry.cmode)
				|| (CHANNEL_MODE_PPPOE == mibentry.cmode)
				|| (CHANNEL_MODE_RT1483 == mibentry.cmode)))
			{
				/* restore igmp-proxy setting */
				mibentry.enableIGMP = Entry.enableIGMP;
			}

#if 0
			if (mibentry.applicationtype == Entry.applicationtype)
			{
				/* application type not changed, reserve the dhcp setting on lan interface */
				mibentry.disableLanDhcp = Entry.disableLanDhcp;
			}
#endif
			if (mibentry.cmode == CHANNEL_MODE_PPPOE)
				if (cnt > 0) {		// Jenny, for multisession PPPoE, ifIndex(VC device) must refer to existed PPPoE connection
					{
						ifMap &= 0xffff0000; // don't care the vc part
						mibentry.ifIndex = if_find_index(mibentry.cmode, ifMap);
						mibentry.ifIndex = TO_IFINDEX(MEDIA_ETH, PPP_INDEX(mibentry.ifIndex), ETH_INDEX(myEntry.ifIndex));
					}
				}
				else {
		DEBUGPRINT;
					mibentry.ifIndex = if_find_index(mibentry.cmode, ifMap);
					mibentry.ifIndex = TO_IFINDEX(MEDIA_ETH, PPP_INDEX(mibentry.ifIndex), ETH_INDEX(mibentry.ifIndex));
				}
			else{
				mibentry.ifIndex = Entry.ifIndex;
				mibentry.ifIndex = TO_IFINDEX(MEDIA_ETH, PPP_INDEX(mibentry.ifIndex), ETH_INDEX(mibentry.ifIndex));
			}
	DEBUGPRINT;
/*
			entry.qos = Entry.qos;
			entry.pcr = Entry.pcr;
			entry.scr = Entry.scr;
			entry.mbs = Entry.mbs;
			entry.cdvt = Entry.cdvt;
*///set by web
			mibentry.pppAuth = Entry.pppAuth;
			mibentry.rip = Entry.rip;
			//entry.dgw = Entry.dgw;
			//mibentry.mtu = Entry.mtu;
			if (mibentry.cmode == CHANNEL_MODE_PPPOE){
				if(mibentry.mtu > 1492)
					mibentry.mtu = 1492;
				//Include IPV6 header to avoid IPv6 fragmentation, IulianWu
				if ((mibentry.dslite_enable) && (mibentry.mtu > 1452))
					mibentry.mtu = 1452;
			}

#ifdef CONFIG_EXT_SWITCH
			//ql: when pvc is modified, interface group don't changed???
			//mibentry.itfGroup = Entry.itfGroup;
#endif

	DEBUGPRINT;
#ifdef CONFIG_SPPPD_STATICIP
			if(mibentry.cmode == CHANNEL_MODE_PPPOE)
			{
				mibentry.pppIp = Entry.pppIp;
				strcpy( mibentry.ipAddr, Entry.ipAddr);
			}
#endif
	DEBUGPRINT;

#ifdef PPPOE_PASSTHROUGH
			//printf("\nentry.cmode=%d,Entry.cmode=%d,Entry.brmode=%d\n",mibentry.cmode,Entry.cmode,Entry.brmode);
			//if (mibentry.cmode != CHANNEL_MODE_PPPOE && mibentry.cmode != CHANNEL_MODE_BRIDGE)
			if (mibentry.cmode != CHANNEL_MODE_PPPOE)
				if (mibentry.cmode == Entry.cmode)
					mibentry.brmode = Entry.brmode;
#endif
DEBUGPRINT;
#ifdef CONFIG_EXT_SWITCH
/*
			// VLAN
			entry.vlan = Entry.vlan;
			entry.vid = Entry.vid;
			entry.vprio = Entry.vprio;
			entry.vpass = Entry.vpass;
*///set by web
#ifdef _PRMT_X_CT_COM_ETHLINK_
			//mibentry.pmark = Entry.pmark;
#endif
#endif
	DEBUGPRINT;
#ifdef _CWMP_MIB_ /*jiunming, for cwmp-tr069*/
			mibentry.connDisable = 0;
			resetWanInstNum(&mibentry);
			mibentry.ConDevInstNum = Entry.ConDevInstNum;
			mibentry.ConIPInstNum = Entry.ConIPInstNum;
			mibentry.ConPPPInstNum = Entry.ConPPPInstNum;
			updateWanInstNum(&mibentry);
			//fprintf( stderr, "<%s:%d>NewInstNum=>ConDev:%u, PPPCon:%u, IPCon:%u\n", __FILE__, __LINE__, mibentry.ConDevInstNum, mibentry.ConPPPInstNum, mibentry.ConIPInstNum );

			mibentry.autoDisTime = Entry.autoDisTime;
			mibentry.warnDisDelay = Entry.warnDisDelay;
			//strcpy( entry.pppServiceName, Entry.pppServiceName );
			strcpy( mibentry.WanName, Entry.WanName );
/*
#ifdef _PRMT_X_CT_COM_PPPOEv2_
			entry.PPPoEProxyEnable = Entry.PPPoEProxyEnable;
			entry.PPPoEProxyMaxUser = Entry.PPPoEProxyMaxUser;
#endif //_PRMT_X_CT_COM_PPPOEv2_
*///set by web
#ifdef _PRMT_X_CT_COM_WANEXT_
//			mibentry.ServiceList = Entry.ServiceList;
			strcpy(mibentry.IPForwardList, Entry.IPForwardList);
#endif //_PRMT_X_CT_COM_WANEXT_
#ifdef _PRMT_X_CT_COM_DHCP_
			memcpy(mibentry.dhcpv6_opt16_enable, Entry.dhcpv6_opt16_enable, sizeof(Entry.dhcpv6_opt16_enable));
			memcpy(mibentry.dhcpv6_opt16_type, Entry.dhcpv6_opt16_type, sizeof(Entry.dhcpv6_opt16_type));
			memcpy(mibentry.dhcpv6_opt16_value_mode, Entry.dhcpv6_opt16_value_mode, sizeof(Entry.dhcpv6_opt16_value_mode));
			memcpy(mibentry.dhcpv6_opt16_value, Entry.dhcpv6_opt16_value, 4 * 80);
			memcpy(mibentry.dhcpv6_opt17_enable, Entry.dhcpv6_opt17_enable, sizeof(Entry.dhcpv6_opt17_enable));
			memcpy(mibentry.dhcpv6_opt17_type, Entry.dhcpv6_opt17_type, sizeof(Entry.dhcpv6_opt17_type));
			memcpy(mibentry.dhcpv6_opt17_sub_code, Entry.dhcpv6_opt17_sub_code, sizeof(Entry.dhcpv6_opt17_sub_code));
			memcpy(mibentry.dhcpv6_opt17_sub_data, Entry.dhcpv6_opt17_sub_data, 4 * 36);
			memcpy(mibentry.dhcpv6_opt17_value, Entry.dhcpv6_opt17_value, 4 * 36);

			memcpy(mibentry.dhcp_opt60_enable, Entry.dhcp_opt60_enable, sizeof(Entry.dhcp_opt60_enable));
			memcpy(mibentry.dhcp_opt60_type, Entry.dhcp_opt60_type, sizeof(Entry.dhcp_opt60_type));
			memcpy(mibentry.dhcp_opt60_value_mode, Entry.dhcp_opt60_value_mode, sizeof(Entry.dhcp_opt60_value_mode));
			memcpy(mibentry.dhcp_opt60_value, Entry.dhcp_opt60_value, 4 * 80);
			memcpy(mibentry.dhcp_opt125_enable, Entry.dhcp_opt125_enable, sizeof(Entry.dhcp_opt125_enable));
			memcpy(mibentry.dhcp_opt125_type, Entry.dhcp_opt125_type, sizeof(Entry.dhcp_opt125_type));
			memcpy(mibentry.dhcp_opt125_sub_code, Entry.dhcp_opt125_sub_code, sizeof(Entry.dhcp_opt125_sub_code));
			memcpy(mibentry.dhcp_opt125_sub_data, Entry.dhcp_opt125_sub_data, 4 * 36);
			memcpy(mibentry.dhcp_opt125_value, Entry.dhcp_opt125_value, 4 * 36);
#endif
#endif //_CWMP_MIB_

#ifdef CONFIG_RTK_L34_ENABLE
			mibentry.rg_wan_idx = Entry.rg_wan_idx;
#endif
#ifdef CONFIG_MCAST_VLAN
			mibentry.mVid = Entry.mVid;
			//AUG_PRT("%s-%d mVlan=%d %d\n",__func__,__LINE__,mibentry.mVid, Entry.mVid);
#endif

/*star:20080718 START add for set acname by net_adsl_links_acname.asp*/
			if(acflag==0)
/*star:20080718 END*/
				strcpy(mibentry.pppACName, Entry.pppACName);

			// find the ifIndex
			if (mibentry.cmode != Entry.cmode)
			{
				if (!(mibentry.cmode == CHANNEL_MODE_PPPOE && cnt>0)){	// Jenny, entries except multisession PPPoE
					mibentry.ifIndex = if_find_index(mibentry.cmode, ifMap);
					mibentry.ifIndex = TO_IFINDEX(MEDIA_ETH, PPP_INDEX(mibentry.ifIndex), ETH_INDEX(mibentry.ifIndex));
				}
				if (mibentry.ifIndex == NA_VC) {
					strcpy(tmpBuf, strMaxVc);
					goto setErr_nochange;
				}
				else if (mibentry.ifIndex == NA_PPP) {
					strcpy(tmpBuf, strMaxNumPPPoE);
					goto setErr_nochange;
				}
	DEBUGPRINT;
				// mode changed, restore to default
				if (mibentry.cmode == CHANNEL_MODE_PPPOE) {
					if(mibentry.mtu < 1492) //set by web
						mibentry.mtu = 1492;
					//Include IPV6 header to avoid IPv6 fragmentation, IulianWu
					if ((mibentry.dslite_enable) && (mibentry.mtu > 1452))
						mibentry.mtu = 1452;
/*
#ifdef CONFIG_USER_PPPOE_PROXY
					entry.PPPoEProxyMaxUser=4;
#endif
					entry.pppAuth = 0;
*///set by web
				}
//				else {
/*
#ifdef CONFIG_USER_PPPOE_PROXY
					entry.PPPoEProxyMaxUser=0;
#endif
*/
	//				entry.dgw = 1;
//					mibentry.mtu = 1500;
//				}
	DEBUGPRINT;
	//			entry.dgw = 1;
/*
#ifdef CONFIG_EXT_SWITCH
				// VLAN
				entry.vlan = 0;	// disable
				entry.vid = 0; // VLAN tag
				entry.vprio = 0; // priority bits (0 ~ 7)
				entry.vpass = 0; // no pass-through
#endif
*///set by web
			}

DEBUGPRINT;
			if( mibentry.ifIndex!=Entry.ifIndex ||
#if defined(IP_QOS) || defined(NEW_IP_QOS_SUPPORT)
				mibentry.enableIpQos != Entry.enableIpQos ||
#endif
				mibentry.cmode != Entry.cmode)
				resolveServiceDependency(selected);

			if( mibentry.ifIndex!=Entry.ifIndex)
			{
				// todo: check e8b
				#if 0
		#ifdef CONFIG_USER_DDNS
				delDDNSinter(Entry.ifIndex);
		#endif
				delBrgMacFilterRule(Entry.ifIndex);
				delIpRouteTbl(Entry.ifIndex);
				#endif
			}
			// todo: check e8b
			#if 0
			if (mibentry.cmode != CHANNEL_MODE_BRIDGE)
			{
				delBrgMacFilterRule(mibentry.ifIndex);
			}
			#endif
DEBUGPRINT;
			mibentry.vlan = entry.vlan;
			mibentry.vid = entry.vid;
			mibentry.vprio = entry.vprio;
// todo: check e8b
#ifdef NEW_PORTMAPPING
			//mibentry record current web record;
			//Entry record old record;
			AUG_PRT("^O^ %s:%d. The mibentry.itfgroup is 0x%x, The Entry's itfgroup is 0x%x, the apptype is %d\n", __FILE__,
				__LINE__, mibentry.itfGroup, Entry.itfGroup, Entry.applicationtype);
			//do not need more check work!
			check_itfGroup(&mibentry, &Entry);
#endif

/*star:20090302 START wen INTERNET pvc start, igmp proxy open auto*/
			mibentry.enableIGMP=0;
			if(mibentry.cmode!=CHANNEL_MODE_BRIDGE)
				if (mibentry.applicationtype&(X_CT_SRV_INTERNET|X_CT_SRV_OTHER|X_CT_SRV_SPECIAL_SERVICE_ALL))
					mibentry.enableIGMP=1;
/*star:20090302 END*/

        	if(mibentry.cmode == CHANNEL_MODE_PPPOE || mibentry.cmode == CHANNEL_MODE_PPPOA){
        		if(isAllStar(mibentry.pppPassword))
        			strncpy( mibentry.pppPassword, Entry.pppPassword , MAX_NAME_LEN);
        	}

	//add by ramen for DNS bind pvc
#ifdef DNS_BIND_PVC_SUPPORT
			MIB_CE_ATM_VC_T dnsPvcEntry;
			if(mib_chain_get(MIB_ATM_VC_TBL,selected,&dnsPvcEntry)&&(dnsPvcEntry.cmode!=CHANNEL_MODE_BRIDGE))
			{
				int tempi=0;
				unsigned int pvcifIdx=0;
				for(tempi=0;tempi<3;tempi++)
				{
					mib_get(MIB_DNS_BIND_PVC1+tempi,(void*)&pvcifIdx);
					if(pvcifIdx==dnsPvcEntry.ifIndex)//I get it
					{
						if(mibentry.cmode==CHANNEL_MODE_BRIDGE)
							pvcifIdx = DUMMY_IFINDEX;
						else
							pvcifIdx=mibentry.ifIndex;
						mib_set(MIB_DNS_BIND_PVC1+tempi,(void*)&pvcifIdx);
					}
				}
			}
#endif

#ifdef CONFIG_IPV6
#ifdef DNSV6_BIND_PVC_SUPPORT
			MIB_CE_ATM_VC_T dnsv6PvcEntry;
			if(mib_chain_get(MIB_ATM_VC_TBL,selected,&dnsv6PvcEntry)&&(dnsv6PvcEntry.cmode!=CHANNEL_MODE_BRIDGE))
			{
				int tempi=0;
				unsigned int pvcifIdx=0;
				for(tempi=0;tempi<3;tempi++)
				{
					mib_get(MIB_DNSV6_BIND_PVC1+tempi,(void*)&pvcifIdx);
					if(pvcifIdx==dnsv6PvcEntry.ifIndex)//I get it
					{
						if(mibentry.cmode==CHANNEL_MODE_BRIDGE)
							pvcifIdx = DUMMY_IFINDEX;
						else
							pvcifIdx=mibentry.ifIndex;
						mib_set(MIB_DNSV6_BIND_PVC1+tempi,(void*)&pvcifIdx);
					}
				}
			}
#endif
#endif
#if defined(CONFIG_LUNA) && defined(GEN_WAN_MAC)
			{
			unsigned char macaddr[MAC_ADDR_LEN]={0};
			/* Magician: Auto generate MAC address for every WAN interface. */
			mib_get(MIB_ELAN_MAC_ADDR, (void *)macaddr);
			setup_mac_addr(macaddr,WAN_HW_ETHER_START_BASE + ETH_INDEX(mibentry.ifIndex));			
			//macaddr[MAC_ADDR_LEN-1] += WAN_HW_ETHER_START_BASE + ETH_INDEX(mibentry.ifIndex);
			memcpy(mibentry.MacAddr, macaddr, MAC_ADDR_LEN);
			/* End Majgician */
			}
#endif
	        //jim garbage action...
			//memcpy(&Entry, &entry, sizeof(entry));
			// log message
			// Mason Yu

#ifdef CONFIG_IPV6
			setup_delegated_default_wanconn(&mibentry);
#endif
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
			reset_unbinded_port_vlan(&Entry);
#endif

			// Mason Yu. ITMS4
			deleteConnection(CONFIGONE, &Entry);		// Modify
			mib_chain_update(MIB_ATM_VC_TBL, (void *)&mibentry, selected);
			restartWAN(CONFIGONE, &mibentry);			// Modify

			if(Entry.applicationtype & X_CT_SRV_VOICE || mibentry.applicationtype & X_CT_SRV_VOICE)
				voip_wan_changed = 1;
	// todo: check e8b
	#if 0
#ifndef QOS_SETUP_IMQ
			//ql_xu: add IP QoS queue
			if (mibentry.enableIpQos)
				addIpQosQueue(mibentry.ifIndex);
#endif
	#endif
//			restart_dnsrelay(); //star
			DEBUGPRINT;

			goto setOk_filter;
		}
	}
	else {lineno = __LINE__; goto check_err;}

	_COND_REDIRECT;
check_err:
	_TRACE_LEAVEL;
	strcpy(tmpBuf, "参数错误");
	goto setErr_nochange;
	return;

setOk_filter:

#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif

	// Mason Yu. ITMS4
	//do_wan_restart();
/*star:20081205 START when change wan by web, tr069 associated notify entry should be updated*/
	// todo: check e8b
	//writeWanChangeFile();
/*star:20081205 END*/
#ifdef VOIP_SUPPORT
	extern int web_restart_solar();
	if(voip_wan_changed)
		web_restart_solar();
#endif

	DEBUGPRINT;//ql_xu
	submitUrl = boaGetVar(wp, "submit-url", "");   // hidden page

	if (submitUrl[0])
		boaRedirect(wp, submitUrl);
	else
		boaDone(wp, 200);
	return;

setErr_restart:
	// Mason Yu. ITMS4
	//do_wan_restart();
setErr_nochange:
	ERR_MSG(tmpBuf);
	//startWan(BOOT_LAST);
}

#endif

/*****************************
** wan if list
*/
int listWanif(int eid, request * wp, int argc, char ** argv)
{
#define _LK_FLAG_RT		0x01
#define _LK_FLAG_BR		0x02
	struct atmvc_entryx	entry;
	char* type = NULL;
	int cnt = 1;
	int index = 0;
	int flag = 0;
	int lineno = __LINE__;
	unsigned char	ipAddr[16];		//IP地址
	unsigned char	remoteIpAddr[16];	//缺省网关
	unsigned char	netMask[16];	//子网掩码

	MIB_CE_ATM_VC_T mibentry;
	int mibtotal,i;

	char wanname[MAX_WAN_NAME_LEN];

	_TRACE_CALL;

	if (boaArgs(argc, argv, "%s", &type) < 1) {
		flag = _LK_FLAG_RT | _LK_FLAG_BR;
	}
	else if (strcmp(type, "rt") == 0) {
		flag = _LK_FLAG_RT;
	}
	else if (strcmp(type, "br") == 0) {
		flag = _LK_FLAG_BR;
	}
	else if (strcmp(type, "all") == 0) {
		flag = _LK_FLAG_BR;
	}
	else return -1;

	/************Place your code here, do what you want to do! ************/
	/************Place your code here, do what you want to do! ************/

	memset(&entry,0,sizeof(entry));

	mibtotal = mib_chain_total(MIB_ATM_VC_TBL);
	for (i = 0; i < mibtotal; i ++) {
		if (mib_chain_get(MIB_ATM_VC_TBL,i,&mibentry)!=1)
			continue;
		/************Place your code here, do what you want to do! ************/
		/************Place your code here, do what you want to do! ************/
		getWanName(&mibentry, wanname);
		int tmp = mib2web(&mibentry, &entry);
		if (tmp ==-1)
			continue;

		if (entry.cmode == 0 && !(flag & _LK_FLAG_BR))
			continue;
		else if (entry.cmode != 0 && !(flag & _LK_FLAG_RT))
			continue;

		_TRACE_POINT;
		boaWrite(wp, "push(new it_nr(\"%s\"" _PTI _PTI _PTI _PTI _PTI _PTI \
			_PTI _PTI _PTI _PTI  _PTI \
			_PTS _PTI _PTS _PTS\
			_PTI _PTI _PTS _PTS _PTS _PTI _PTI _PTI _PTI _PTI _PTI _PTI _PTI _PTI "));\n",
			wanname, _PME(vpi), _PME(qos), _PME(vci), _PME(pcr), _PME(scr), _PME(mbs),
			_PME(encap), _PME(napt), _PME(cmode), _PME(brmode), _PME(AddrMode),
			_PME(pppUsername)/*, _PME(pppPassword)*/, _PME(pppAuth), _PME(pppServiceName), _PME(pppACName),
			_PME(pppCtype), _PME(ipDhcp),
			_PMEIP(ipAddr), _PMEIP(remoteIpAddr), _PMEIP(netMask),
			_PME(vlan), _PME(vid), _PME(vprio), _PME(vpass), _PME(itfGroup),
			_PME(PPPoEProxyEnable), _PME(PPPoEProxyMaxUser), _PME(applicationtype), _PME(ifIndex)
			);
	}

check_err:
	_TRACE_LEAVEL;
	return 0;
}

#if defined(CONFIG_CMCC) || defined(CONFIG_CU) || defined(CONFIG_CU)
/*****************************
*var nEntryNum = 4;
*var vArrayStr = "1_TR069_R_VID_4015,2_INTERNET_R_VID_200,3_OTHER_R_VID_2030,4_VOICE_R_VID_3951,";
*var vEntryName = vArrayStr.split(',');
*vArrayStr = "nas0_0,nas1_0,ppp16,nas3_0,";
*var vEntryValue = vArrayStr.split(',');
*vArrayStr = "0,8,16,24,";
*vArrayStr = "Yes,Yes,No,No,";
*vArrayStr = "Disabled,Enable,Enable,Disabled,";
*var WANEnNAT = vArrayStr.split(',');
*/
int listWanPath(int eid, request * wp, int argc, char ** argv)
{
	printf("listWanPath\n");
	struct atmvc_entryx	entry;
	char* type = NULL;
	int cnt = 1;
	int index = 0;
	int flag = 0;
	int lineno = __LINE__;
	unsigned char	ipAddr[16];		//IP地址
	unsigned char	remoteIpAddr[16];	//缺省网关
	unsigned char	netMask[16];	//子网掩码

	unsigned char vEntryName[256] = {0};
	unsigned char vEntryValue[256] = {0};
	unsigned char WANEnNAT[256] = {0};

	MIB_CE_ATM_VC_T mibentry;
	int mibtotal,i;

	char wanname[MAX_WAN_NAME_LEN];
	char ifname[MAX_WAN_NAME_LEN];

	_TRACE_CALL;

	memset(&entry,0,sizeof(entry));

	mibtotal = mib_chain_total(MIB_ATM_VC_TBL);
	boaWrite(wp, "var nEntryNum = %d;\n",mibtotal);
	for (i = 0; i < mibtotal; i ++) {
		if (mib_chain_get(MIB_ATM_VC_TBL,i,&mibentry)!=1)
			continue;
		
		memset(wanname, 0, MAX_WAN_NAME_LEN);
		
		getWanName(&mibentry, wanname);
		int tmp = mib2web(&mibentry, &entry);
		if (tmp ==-1)
			continue;

		_TRACE_POINT;

		strcat(vEntryName, wanname);
		strcat(vEntryName, ",");

		memset(ifname, 0, MAX_WAN_NAME_LEN);
		ifGetName(PHY_INTF(mibentry.ifIndex), ifname, sizeof(ifname));
		strcat(vEntryValue, ifname);
		strcat(vEntryValue, ",");

		if(mibentry.napt == 0){
			strcat(WANEnNAT, "Disabled,");
		}else
			strcat(WANEnNAT, "Enable,");
	}
	
	_TRACE_POINT;
	boaWrite(wp, "var vArrayStr = \"%s\";\n",vEntryName);
	boaWrite(wp, "var vEntryName = vArrayStr.split(',');\n");
	boaWrite(wp, "var vArrayStr = \"%s\";\n",vEntryValue);
	boaWrite(wp, "var vEntryValue = vArrayStr.split(',');\n");
	boaWrite(wp, "var vArrayStr = \"%s\";\n",WANEnNAT);
	boaWrite(wp, "var WANEnNAT = vArrayStr.split(',');\n");

check_err:
	_TRACE_LEAVEL;
	return 0;
}

#endif
#ifdef _PRMT_X_CT_COM_USERINFO_
#if defined(CONFIG_GPON_FEATURE) || defined(CONFIG_EPON_FEATURE)
#define USERINFO_LINE				"光纤"
#define USERINFO_LINE_LED			"光信号灯已处于熄灭"
#else
#define USERINFO_LINE				"网络"
#define USERINFO_LINE_PORT			"L"
#define USERINFO_LINE_LED			"“"USERINFO_LINE USERINFO_LINE_PORT"”灯处于常亮或闪烁"
#endif

#ifdef CONFIG_CU
#define OLT_ACCOUNT_REG_FAIL			"在OLT上注册失败，请检查逻辑ID和密码是否正确"
#define OLT_ACCOUNT_REG_ING			"正在注册OLT"
#define OLT_ACCOUNT_REG_SUCC			"正在获取管理IP"
#define E8CLIENT_ACCOUNT_REG			"正在注册，请稍候……"
#define E8CLIENT_TR069_READY			"已获得管理IP，正在连接RMS"
#define E8CLIENT_ITMS_NOT_REACHABLE		"注册失败，很抱歉，暂时无法注册，如有疑问，请致电10010，协助解决"
#define E8CLIENT_ACCOUNT_REG_FAIL		"注册失败！请重试"

#define E8CLIENT_ACCOUNT_REG_SUCC		"注册成功，等待RMS平台下发业务数据"
#define E8CLIENT_ACCOUNT_REMOTE_SETTING0	"RMS平台正在下发业务数据，请勿断电或拨线"
#define E8CLIENT_ACCOUNT_REMOTE_SETTING1	"RMS平台正在下发 %s 业务数据，请勿断电或拨线"
#elif defined(CONFIG_CMCC)
#define OLT_ACCOUNT_REG_FAIL			"在OLT上注册失败，请检查光信号灯是否处于熄灭状态、Password是否正确"
#define OLT_ACCOUNT_REG_ING			"正在注册OLT"
#define OLT_ACCOUNT_REG_SUCC			"正在获取管理IP"
#define E8CLIENT_ACCOUNT_REG			"正在注册，请稍候……"
#define E8CLIENT_TR069_READY			"已获得管理IP，正在连接省级数字家庭管理平台"
#define E8CLIENT_ITMS_NOT_REACHABLE		"到省级数字家庭管理平台的通道不通，请联系客户经理或拨打10086"
#define E8CLIENT_ACCOUNT_REG_FAIL		"注册失败！请重试"

#define E8CLIENT_ACCOUNT_REG_SUCC		"等待省级数字家庭管理平台下发业务数据"
#define E8CLIENT_ACCOUNT_REMOTE_SETTING0	"省级数字家庭管理平台正在下发业务数据，请勿断电或拨光纤"
#define E8CLIENT_ACCOUNT_REMOTE_SETTING1	"省级数字家庭管理平台正在下发 %s 业务数据，请勿断电或拨光纤"
#else
#define OLT_ACCOUNT_REG_FAIL			"在 OLT 上注册失败，请检查光信号灯是否处于熄灭状态、 逻辑 ID 和密码是否正确或拨打10000"
#define OLT_ACCOUNT_REG_ING			"正在注册OLT"
#define OLT_ACCOUNT_REG_SUCC			"注册OLT成功，正在获取管理IP"
#define E8CLIENT_ACCOUNT_REG			"正在注册，请稍候……"
#define E8CLIENT_TR069_READY			"已获得管理IP，正在连接ITMS"
#define E8CLIENT_ITMS_NOT_REACHABLE		"到ITMS的通道不通，请联系客户经理或拨打10000"
#define E8CLIENT_ACCOUNT_REG_FAIL		"注册失败！请重试"

#define E8CLIENT_ACCOUNT_REG_SUCC		"注册ITMS成功，等待ITMS平台下发业务数据"
#define E8CLIENT_ACCOUNT_REMOTE_SETTING0	"注册ITMS成功，正在下发业务，请勿断电或拨"USERINFO_LINE
#define E8CLIENT_ACCOUNT_REMOTE_SETTING1	"ITMS平台正在下发 %s 业务数据，请勿断电或拨"USERINFO_LINE
#endif
#ifdef CONFIG_YUEME
#define E8CLIENT_ACCOUNT_REMOTE_SETTING_SUCCESS	"ITMS平台业务数据下发成功，共下发了 %s%d 个业务，欢迎使用天翼网关"
#define E8CLIENT_ACCOUNT_REMOTE_SETTING_REBOOT	"ITMS平台业务数据下发成功，共下发了 %s%d 个业务，天翼网关网关需要重启，请等待…"
#define E8CLIENT_ACCOUNT_REMOTE_SETTING_SUCCESS_NO_SERV	"ITMS平台业务数据下发成功，欢迎使用天翼网关"
#define E8CLIENT_ACCOUNT_REMOTE_SETTING_REBOOT_NO_SERV	"ITMS平台业务数据下发成功，天翼网关需要重启，请等待…"
#elif defined(CONFIG_CU)
#define E8CLIENT_ACCOUNT_REMOTE_SETTING_SUCCESS	"RMS平台业务数据下发成功，共下发了 %s%d 个业务，欢迎使用业务"
#define E8CLIENT_ACCOUNT_REMOTE_SETTING_REBOOT	"RMS平台业务数据下发成功，共下发了 %s%d 个业务，家庭网关需要重启，请等待…"
#define E8CLIENT_ACCOUNT_REMOTE_SETTING_SUCCESS_NO_SERV	"注册成功，下发业务成功"
#define E8CLIENT_ACCOUNT_REMOTE_SETTING_REBOOT_NO_SERV	"注册成功，下发业务成功，家庭网关需要重启，请等待…"
#elif defined(CONFIG_CMCC)
#define E8CLIENT_ACCOUNT_REMOTE_SETTING_SUCCESS	"省级数字家庭管理平台 平台业务数据下发成功，共下发了 %s%d 个业务，欢迎使用业务"
#define E8CLIENT_ACCOUNT_REMOTE_SETTING_REBOOT	"省级数字家庭管理平台 平台业务数据下发成功，共下发了 %s%d 个业务，家庭网关需要重启，请等待…"
#define E8CLIENT_ACCOUNT_REMOTE_SETTING_SUCCESS_NO_SERV	"省级数字家庭管理平台 平台业务数据下发成功，欢迎使用业务"
#define E8CLIENT_ACCOUNT_REMOTE_SETTING_REBOOT_NO_SERV	"省级数字家庭管理平台 平台业务数据下发成功，家庭网关需要重启，请等待…"
#else
#define E8CLIENT_ACCOUNT_REMOTE_SETTING_SUCCESS	"ITMS平台业务数据下发成功，共下发了 %s%d 个业务，欢迎使用业务"
#define E8CLIENT_ACCOUNT_REMOTE_SETTING_REBOOT	"ITMS平台业务数据下发成功，共下发了 %s%d 个业务，家庭网关需要重启，请等待…"
#define E8CLIENT_ACCOUNT_REMOTE_SETTING_SUCCESS_NO_SERV	"ITMS平台业务数据下发成功，欢迎使用业务"
#define E8CLIENT_ACCOUNT_REMOTE_SETTING_REBOOT_NO_SERV	"ITMS平台业务数据下发成功，家庭网关需要重启，请等待…"
#endif
#ifdef CONFIG_CU
#define E8CLIENT_ACCOUNT_REMOTE_SETTING_FAIL	"注册成功，下发业务失败，请联系10010"
#define E8CLIENT_ACCOUNT_REG_FAIL1_2_3		"在RMS上注册失败！请检查逻辑ID和密码是否正确或联系客户经理或拨打10010"
#define E8CLIENT_ACCOUNT_REG_FAIL1_2_3_OVER	"在RMS上注册失败！请3分钟后重试或联系客户经理或拨打10010"
#define E8CLIENT_ACCOUNT_REG_FAIL1			"逻辑ID不对，注册失败，请重试（剩余尝试次数：%d）"
#define E8CLIENT_ACCOUNT_REG_FAIL1_OVER		"逻辑ID不对，注册失败，请联系10010"
#define E8CLIENT_ACCOUNT_REG_FAIL2			"密码不对，注册失败，请重试（剩余尝试次数：%d）"
#define E8CLIENT_ACCOUNT_REG_FAIL2_OVER		"密码不对，注册失败，请联系10010"
#define E8CLIENT_ACCOUNT_REG_FAIL3			"逻辑ID与密码不匹配！请重试（剩余尝试次数：%d）"
#define E8CLIENT_ACCOUNT_REG_FAIL3_OVER		"逻辑ID与密码不匹配！注册失败，请联系10010"
#define E8CLIENT_ACCOUNT_REG_FAIL4		"注册超时！请检查线路后重试"
#define E8CLIENT_ACCOUNT_REG_FAIL5		"已经在RMS注册成功，无需再注册"
#elif defined(CONFIG_CMCC)
#define E8CLIENT_ACCOUNT_REMOTE_SETTING_FAIL	"在省级数字家庭管理平台上注册失败，请联系客户经理或拨打10086"
#define E8CLIENT_ACCOUNT_REG_FAIL1_2_3		"在省级数字家庭管理平台上注册失败，正在重试"
#define E8CLIENT_ACCOUNT_REG_FAIL1_2_3_OVER	"在省级数字家庭管理平台上注册失败，请联系客户经理或拨打10086"
#define E8CLIENT_ACCOUNT_REG_FAIL4		"在省级数字家庭管理平台上注册失败，请联系客户经理或拨打10086"
#define E8CLIENT_ACCOUNT_REG_FAIL5		"已经在ITMS注册成功，无需再注册"
#else
#define E8CLIENT_ACCOUNT_REMOTE_SETTING_FAIL	"ITMS下发业务异常！请联系客户经理或拨打10000"
#define E8CLIENT_ACCOUNT_REG_FAIL1_2_3		"在ITMS上注册失败！请检查宽带识别码和密码是否正确，如无法解决请联系客户经理或拨打10000"
#define E8CLIENT_ACCOUNT_REG_FAIL1_2_3_OVER	"在ITMS上注册失败！请3分钟后重试，如无法解决请联系客户经理或拨打10000"
#define E8CLIENT_ACCOUNT_REG_FAIL4		"在ITMS上注册超时！请检查线路后重试，如无法解决请联系客户经理或拨打10000"
#define E8CLIENT_ACCOUNT_REG_FAIL5		"已经在ITMS注册成功，无需再注册"
#endif

#ifdef CONFIG_CU
#define E8CLIENT_ACCOUNT_REMOTE_SETTING_SUCCESS2		"终端注册OLT 成功，获取管理地址成功，注册RMS 成功"
#else
#define E8CLIENT_ACCOUNT_REMOTE_SETTING_SUCCESS2		"终端注册OLT 成功，获取管理地址成功，注册ITMS 成功"
#endif



/*star:20090302 START when "正在注册中...", there is no OK button*/
#define E8CLIENT_REG_HAVE_OK(s) {\
	boaWrite(wp, "<form style=\"border:0; padding:0; \">\n");\
	boaWrite(wp, "<table cellspacing=\"0\" cellpadding=\"0\" width=\"300\" align=\"center\" border=\"0\">\n");\
	boaWrite(wp, "<tr><td><font size=4>%s</td></tr></table>\n", s);\
	boaWrite(wp, "</form>\n");\
	boaWrite(wp, "<br><input id=\"return\" type=\"button\" value=\"确定\" onClick=\"window.location.href='/ehomeclient/e8clientusereg.asp';\" style=\"width:80px; border-style:groove; font-weight:bold \">");\
}

#define E8CLIENT_REG_NO_OK(s) {\
	boaWrite(wp, "<form style=\"border:0; padding:0; \">\n");\
	boaWrite(wp, "<table cellspacing=\"0\" cellpadding=\"0\" width=\"300\" align=\"center\" border=\"0\">\n");\
	boaWrite(wp, "<tr><td><font size=4>%s</td></tr></table>\n", s);\
	boaWrite(wp, "</form>\n");\
}

#define E8CLIENT_REG_HAVE_OK_AUTORUN(s) {\
	boaWrite(wp, "<form style=\"border:0; padding:0; \">\n");\
	boaWrite(wp, "<table cellspacing=\"0\" cellpadding=\"0\" width=\"300\" align=\"center\" border=\"0\">\n");\
	boaWrite(wp, "<tr><td><font size=4>%s</td></tr></table>\n", s);\
	boaWrite(wp, "</form>\n");\
	boaWrite(wp, "<br><input id=\"return\" type=\"button\" value=\"确定\" onClick=\"window.location.href='/autorun/accreg.asp';\" style=\"width:80px; border-style:groove; font-weight:bold \">");\
}
/*star:20090302 END*/

/*star:20080827 START add for reg timeout*/
static int ctregcount = 0;
static int regOLTCount = 0;
static int getIPCount = 0;
static int regITMSCount = 0;
static int issueBussinessCount = 0;

static float inProcess=0.0;
static char* inStrProcess = NULL;
/*star:20080827 END*/

/******************************************************************/
/* Martin ZHU: 2016-3-22 start */
/******************************************************************/
/* 1%~22% */
#define OLT_ACCOUNT_REG_ING_4STAGEDIAG_1			"终端正在向OLT 注册，请等待... ..."
/* 23% */
#define OLT_ACCOUNT_REG_FAIL_NOLOID_4STAGEDIAG_1	"终端注册OLT 失败，LOID 不存在，请重试"
/* 24% */
#define OLT_ACCOUNT_REG_TIMEOUT_4STAGEDIAG_1		"终端注册OLT 超时，请确认PON 接入方式和LOID 是否与施工单一致。如果都正常，请拨打支撑电话检查OLT 的PON 板卡是否正常，PON 口预部署数据配置是否正常"
/* 25% */
#define OLT_ACCOUNT_REG_SUCC_4STAGEDIAG_1			"终端注册OLT 成功"

/* 26%~48% */
#define E8CLIENT_ACCOUNT_GET_ING_IP_4STAGEDIAG_2	"终端注册OLT 成功，正在获取管理地址，请等待... ..."
/* 49% */
#define E8CLIENT_ACCOUNT_GET_IP_FAIL_4STAGEDIAG_2	"终端注册OLT 成功，获取管理地址失败"
#define E8CLIENT_ACCOUNT_CALL_FOR_BRAS_OK			"请拨打支撑电话检查终端到BRAS通道及BRAS地址池配置是否正常"
/* 50% */
#define E8CLIENT_ACCOUNT_GET_IP_SUCC_4STAGEDIAG_2	"终端注册OLT 成功，获取管理地址成功"

/* 51%~70% */
#define E8CLIENT_ITMS_CONNECT_4STAGEDIAG_3			"终端注册OLT 成功，获取管理地址成功，正在向ITMS 发送注册请求，请等待... ..."
/* 71%~72% */
#define E8CLIENT_ITMS_PING_4STAGEDIAG_3				"终端向ITMS 注册失败，正在Ping 上层链路是否正常，请等待... ..."
/* 73% */
#define E8CLIENT_ITMS_PING_FAIL_4STAGEDIAG_3		"终端注册OLT 成功，获取管理地址成功，注册ITMS 失败，上层链路不通"
#define E8CLIENT_ITMS_CALL_FOR_OK					"请拨打支撑电话检查终端到ITMS路由是否正常，ITMS平台是否正常"
/* 74% */
#define E8CLIENT_ITMS_PING_SUCC_4STAGEDIAG_3		"终端注册OLT 成功，获取管理地址成功，注册ITMS 失败，上层链路正常"
#define E8CLIENT_ITMS_CALL_FOR_OK_AND_TRY_AGAIN		"请拨打支撑电话查询ITMS平台终端是否在线，并重新注册，跟踪终端注册报文"
/* 75% */
#define E8CLIENT_ITMS_SUCC_4STAGEDIAG_3				"终端注册OLT 成功，获取管理地址成功，注册ITMS 成功"

/* 76%~97% */
#define E8CLIENT_ITMS_CONFIG_ING_4STAGEDIAG_4		"终端注册OLT 成功，获取管理地址成功，注册ITMS 成功，正在下发业务，请等待... ..."
/* 98% */
#define E8CLIENT_ITMS_CONFIG_FAIL_4STAGEDIAG_4		"终端注册OLT 成功，获取管理地址成功，注册ITMS 成功，下发业务失败，请重试"
/* 99% */
#define E8CLIENT_ITMS_CONFIG_TIMEOUT_4STAGEDIAG_4	"ITMS 下发业务超时，请重试"
/* 100% */
#define E8CLIENT_ITMS_CONFIG_SUCC_4STAGEDIAG_4		"终端注册OLT 成功，获取管理地址成功，注册ITMS 成功，下发业务成功"
/* 100% */
#define E8CLIENT_INTERENT_IPTV_VOICE_SUCC_4STAGEDIAG_4	"终端注册OLT 成功，获取管理地址成功，注册ITMS 成功，下发业务成功，完成%s业务下发"

#define	E8CLIENT_REPEAT_REG_4STAGEDIAG_4			"已注册成功，无需再注册"
#define	E8CLIENT_ITMS_INVALID_LOID_4STAGEDIAG		"ITMS平台无此LOID工单存在！请重试。"
#define	E8CLIENT_ITMS_INVALID_LOID_MSG_4STAGEDIAG	"请拨打支撑电话检查ITMS平台是否收到该注册的LOID业务工单，检查ITMS平台录入注册终端的型号、版本、OUI是否正确。"

#define OLT_ACCOUNT_REG_FAIL_MSG	"  终端注册光信号丢失，请检查光线路的光功率是否正常，终端光模块是否正常。"
#define OLT_ACCOUNT_REG_AGAIN		"请点击返回，重新注册"

#define E8CLIENT_4STAGEDIAG_REG_FAIL_TO_RETURN(s1, s2) {\
	boaWrite(wp, "<tr><td><font color='0xaa26a7' size='3'>%s</font></td>", s1);\
	boaWrite(wp, "<td><br><font color='red' size='3'>%s</font></td></tr>\n", s2);\
	boaWrite(wp, "<br><br>\n");\
	boaWrite(wp, "<input id=\"return\" type=\"button\" value=\"返回\" onclick=\"location.href='/usereg.asp';\" style=\"width:80px; border-style:groove; font-weight:bold\">");\
}

#define E8CLIENT_4STAGEDIAG_REG_SUCC(s1) {\
	boaWrite(wp, "%s\n", s1);\
	boaWrite(wp, "<br><br>\n");\
	boaWrite(wp, "<input id=\"return\" type=\"button\" value=\"确定\" onclick=\"location.href='/admin/login.asp';\" style=\"width:80px; border-style:groove; font-weight:bold\">");\
}

#define TIMEOUT_SET(N) {\
	boaWrite(wp, "<script language=\"javascript\">setTimeout('myrefresh()',N*1000); ;</script>", N);\
}

static int pingAgain=0, pingCount=0;
/********************Martin ZHU: 2016-03-22  end********************/

#if defined(_PRMT_X_CT_COM_USERINFO_) && defined(E8B_NEW_DIAGNOSE)
int initE8clientUserRegPage(int eid, request * wp, int argc, char ** argv)
{
	MIB_CE_ATM_VC_T entry;
	unsigned int i, num;
	unsigned char over = 0;
	unsigned char loid[MAX_NAME_LEN];
	unsigned char password[MAX_NAME_LEN];
	unsigned int regLimit;
	unsigned int regTimes;
	unsigned int regResult;
	unsigned int regStatus;
	unsigned char reg_type = DEV_REG_TYPE_DEFAULT;
	unsigned char registered = 0;
	unsigned int value;

	mib_get(CWMP_USERINFO_LIMIT, &regLimit);
	mib_get(CWMP_USERINFO_TIMES, &regTimes);
	mib_get(CWMP_USERINFO_RESULT, &regResult);
	over = regTimes >= regLimit;
	mib_get(CWMP_USERINFO_STATUS, &regStatus);
	mib_get(MIB_LOID, loid);
	mib_get(MIB_LOID_PASSWD, password);

	boaWrite(wp, "over = %hhu;\n", over);
	if((regStatus == 0 && regResult == 1) || regStatus ==5)
		registered = 1;
	boaWrite(wp, "registered = %d;\n", registered);
	boaWrite(wp, "loid = \"%s\";\n", loid);
	boaWrite(wp, "password = \"%s\";\n", password);

	mib_get(PROVINCE_DEV_REG_TYPE, &reg_type);
	if(reg_type == DEV_REG_TYPE_JSU && registered)
		boaWrite(wp, "btn_disabled = 1;\n");

	boaWrite(wp, "provinceType = %d;\n", reg_type);
	//20180103: to control the function that add reset button on the webpage of register
	mib_get(PROVINCE_SICHUAN_FUNCTION_MASK,&value);
	if((value & PROVINCE_SICHUAN_RESETFACTORY_TEST) != 0)
	{		
		boaWrite(wp, "showreset = 1;\n"); //For SICHUANG, to control the function that add reset button on the webpage of register
	}
	if((value & PROVINCE_SICHUAN_TERMINAL_INSPECTION) != 0)
	{		
		boaWrite(wp, "showterminal = 1;\n"); //For SICHUANG, to control the function that add terminal_inspection button on the webpage of register
	}

	return 0;
}
#endif

int getProvinceInfo(int eid, request * wp, int argc, char ** argv)
{
	unsigned char reg_type = DEV_REG_TYPE_DEFAULT;

	if(!mib_get(PROVINCE_DEV_REG_TYPE, &reg_type))
	{
		printf("mib_get failed(PROVINCE_DEV_REG_TYPE)\n");
	}
	boaWrite(wp, "provinceType = %d;\n", reg_type);

	return 0;
}

int regresultBodyStyle(int eid, request * wp, int argc, char ** argv)
{
	unsigned char reg_type = DEV_REG_TYPE_DEFAULT;

	if(!mib_get(PROVINCE_DEV_REG_TYPE, &reg_type))
	{
		printf("mib_get failed(PROVINCE_DEV_REG_TYPE)\n");
	}

	if(DEV_REG_TYPE_AH == reg_type)
	{
		boaWrite(wp, "background-image: url('/image/loidreg_ah_01.gif');\n\tbackground-repeat: repeat-x;");
	}
	else
	{
		boaWrite(wp, "background-image: url('/image/loid_register.gif');\n\tbackground-repeat: no-repeat;");
	}

	return 0;
}

int regresultMainDivStyle(int eid, request * wp, int argc, char ** argv)
{
	unsigned char reg_type = DEV_REG_TYPE_DEFAULT;

	if(!mib_get(PROVINCE_DEV_REG_TYPE, &reg_type))
	{
		printf("mib_get failed(PROVINCE_DEV_REG_TYPE)\n");
	}

	if(DEV_REG_TYPE_AH == reg_type)
	{
		boaWrite(wp, "background-image: url('/image/useregresult_ah.gif');\n\twidth: 830px;\n\theight: 536px;");
	}
	else
	{
		//do nothing;
	}

	return 0;
}

int regresultBlankDivStyle(int eid, request * wp, int argc, char ** argv)
{
	unsigned char reg_type = DEV_REG_TYPE_DEFAULT;

	if(!mib_get(PROVINCE_DEV_REG_TYPE, &reg_type))
	{
		printf("mib_get failed(PROVINCE_DEV_REG_TYPE)\n");
	}

	if(DEV_REG_TYPE_AH == reg_type)
	{
		boaWrite(wp, "style=\"width:830px; height:130px; float:center\"");
	}
	else
	{
		boaWrite(wp, "style=\"width:830px; height:0px; float:center display:none\"");
	}

	return 0;
}

int regresultLoginStyle(int eid, request * wp, int argc, char ** argv)
{
	unsigned char reg_type = DEV_REG_TYPE_DEFAULT;

	if(!mib_get(PROVINCE_DEV_REG_TYPE, &reg_type))
	{
		printf("mib_get failed(PROVINCE_DEV_REG_TYPE)\n");
	}

	if(DEV_REG_TYPE_AH == reg_type)
	{
		boaWrite(wp, "left: 230px;");
	}
	else
	{
		boaWrite(wp, "left: 260px;");
	}

	return 0;
}

int regresultLoginFontStyle(int eid, request * wp, int argc, char ** argv)
{
	unsigned char reg_type = DEV_REG_TYPE_DEFAULT;

	if(!mib_get(PROVINCE_DEV_REG_TYPE, &reg_type))
	{
		printf("mib_get failed(PROVINCE_DEV_REG_TYPE)\n");
	}

	if(DEV_REG_TYPE_AH == reg_type)
	{
		boaWrite(wp, "style=\"font-size:14px; font-family:SimSun\"");
	}
	else
	{
		boaWrite(wp, "style=\"font-size:18px;\"");
	}

	return 0;
}

int e8clientAccountRegResult(int eid, request * wp, int argc, char **argv)
{
	unsigned int regStatus;
	unsigned int regLimit;
	unsigned int regTimes;
	unsigned char regInformStatus;

	mib_get(CWMP_USERINFO_STATUS, &regStatus);
	mib_get(CWMP_USERINFO_LIMIT, &regLimit);
	mib_get(CWMP_USERINFO_TIMES, &regTimes);
	mib_get(CWMP_REG_INFORM_STATUS, &regInformStatus);

	if (regTimes >= regLimit) {
		E8CLIENT_REG_HAVE_OK(E8CLIENT_ACCOUNT_REG_FAIL1_2_3_OVER);
		return 0;
	}

	if (regInformStatus != CWMP_REG_RESPONSED) {	//ACS not returned result
/*star:20080827 START add for reg timeout*/
		if (ctregcount >= 4) {
			E8CLIENT_REG_HAVE_OK(E8CLIENT_ACCOUNT_REG_FAIL4);
		} else {
			ctregcount++;
			E8CLIENT_REG_NO_OK(E8CLIENT_ACCOUNT_REG);
		}
/*star:20080827 END*/
	} else {
		if (regStatus == 0) {
			E8CLIENT_REG_HAVE_OK(E8CLIENT_ACCOUNT_REG_SUCC);
		} else {
			E8CLIENT_REG_HAVE_OK(E8CLIENT_ACCOUNT_REG_FAIL);
		}
	}

	return 0;
}

/*star: 20090302 START add for autorun*/
int e8clientAutorunAccountRegResult(int eid, request * wp, int argc, char **argv)
{
	unsigned int regStatus;
	unsigned int regLimit;
	unsigned int regTimes;
	unsigned char regInformStatus;

	mib_get(CWMP_USERINFO_STATUS, &regStatus);
	mib_get(CWMP_USERINFO_LIMIT, &regLimit);
	mib_get(CWMP_USERINFO_TIMES, &regTimes);
	mib_get(CWMP_REG_INFORM_STATUS, &regInformStatus);

	if (regTimes >= regLimit) {
		E8CLIENT_REG_HAVE_OK_AUTORUN(E8CLIENT_ACCOUNT_REG_FAIL1_2_3_OVER);
		return 0;
	}

	if (regInformStatus != CWMP_REG_RESPONSED) {	//ACS not returned result
/*star:20080827 START add for reg timeout*/
		if (ctregcount >= 4) {
			E8CLIENT_REG_HAVE_OK_AUTORUN(E8CLIENT_ACCOUNT_REG_FAIL4);
		} else {
			ctregcount++;
			E8CLIENT_REG_NO_OK(E8CLIENT_ACCOUNT_REG);
		}
/*star:20080827 END*/
	} else {
		if (regStatus == 0) {
			E8CLIENT_REG_HAVE_OK_AUTORUN(E8CLIENT_ACCOUNT_REG_SUCC);
		} else {
			E8CLIENT_REG_HAVE_OK_AUTORUN(E8CLIENT_ACCOUNT_REG_FAIL);
		}
	}

	return 0;
}
/*star: 20090302 END*/

void formAccountReg(request * wp, char *path, char *query)
{
	char *stemp;
	unsigned char vChar;
	unsigned int regLimit;
	unsigned int regTimes;
	unsigned lineno;

	_TRACE_CALL;

	mib_get(CWMP_USERINFO_LIMIT, &regLimit);
	mib_get(CWMP_USERINFO_TIMES, &regTimes);
	if (regTimes >= regLimit) {
		vChar = CWMP_REG_IDLE;
		mib_set(CWMP_REG_INFORM_STATUS, &vChar);
		goto FINISH;
	}

	//_ENTRY_STR(auth, _NEED);
	//_ENTRY_STR(user, _NEED);
	stemp = boaGetVar(wp, "broadbandusername", "");
	if (stemp[0])
		mib_set(MIB_LOID, stemp);
	else {
		fprintf(stderr, "get broadband username error!\n");
		goto check_err;
	}

	stemp = boaGetVar(wp, "customer+ID", "");
	if (stemp[0])
		mib_set(MIB_LOID_PASSWD, stemp);
	else {
		fprintf(stderr, "get customer ID error!\n");
		goto check_err;
	}

/*xl_yue:20081225 record the inform status to avoid acs responses twice for only once informing*/
	vChar = CWMP_REG_REQUESTED;
	mib_set(CWMP_REG_INFORM_STATUS, &vChar);
/*xl_yue:20081225 END*/

#ifdef CONFIG_MIDDLEWARE
	mib_get(CWMP_TR069_ENABLE, &vChar);
	if (!vChar) {
		//Martin_ZHU: send CTEVENT_BIND to MidProcess
		vChar = CTEVENT_BIND;
		sendInformEventMsg2MidProcess( vChar );
	} else
#endif
	{
		pid_t cwmp_pid;

		// send signal to tr069
		cwmp_pid = read_pid("/var/run/cwmp.pid");
		if (cwmp_pid > 0) {
#ifdef CONFIG_MIDDLEWARE
			vChar = CTEVENT_BIND;
			mib_set(MIB_MIDWARE_INFORM_EVENT, &vChar);
			kill(cwmp_pid, SIGUSR1);	//SIGUSR2 is used by midware
#else
			kill(cwmp_pid, SIGUSR2);
#endif
		}
	}

/*star:20080827 START add for reg timeout*/
	ctregcount = 0;
/*star:20080827 END*/

FINISH:
	//web redirect
	_COND_REDIRECT;

check_err:
	_TRACE_LEAVEL;
	return;
}

#ifdef CONFIG_CU
#define CREATE_NPROGRESS() {\
	boaWrite(wp, "<form name=\"form1\">\n");\
 	boaWrite(wp, "	<div id=\"progress_id\" class=\"progress\">\n");\
	boaWrite(wp, "		<div id=\"table1\"></div>\n");\
	boaWrite(wp, "		<input type=\"text\" name=\"percent\" style=\"font-family:Arial;color:#fff; text-align:center;border-width:medium; border-style:none;background:none;position: absolute;top:10px;left:75%;font-size: 16px;color:#c0c0c0\">\n");\
	boaWrite(wp, "		<script>\n");\
	boaWrite(wp, "			createTable();\n");\
	boaWrite(wp, "		</script>\n");\
	boaWrite(wp, "	</div>\n");\
	boaWrite(wp, "</form>\n");\
}
#else
#define CREATE_NPROGRESS() {\
	boaWrite(wp, "<form name=\"form1\">\n");\
	boaWrite(wp, "	<div id=\"progress_id\" class=\"progress\">\n");\
	boaWrite(wp, "		<div id=\"table1\" style=\"border:2px solid #ccc;\"></div>\n");\
	boaWrite(wp, "		<input type=\"text\" name=\"percent\" style=\"font-family:Arial;color:#000; text-align:center;border-width:medium; border-style:none;background:none;position: absolute;top:7px;left:34%%;font-size: 14px;\">\n");\
	boaWrite(wp, "		<script>\n");\
	boaWrite(wp, "			createTable();\n");\
	boaWrite(wp, "		</script>\n");\
	boaWrite(wp, "	</div>\n");\
	boaWrite(wp, "</form>\n");\
}
#endif

#ifdef CONFIG_CU 
#define USER_REG_HAVE_FAIL(s) {\
	CREATE_NPROGRESS();\
	boaWrite(wp, "<div class=\"error_ifo\" align=\"left\"><font color=\"#c0c0c0\">%s</font></div><br>", s);\
	boaWrite(wp, "<div class=\"back_ifo\" align=\"center\"><a style=\"text-decoration:none;\"  href=\"/usereg.asp\" ><font style=\"color:#c0c0c0;\" size=\"3\" >返回</font></a></div>");\
	boaWrite(wp, "<div id=\"ok\"></div>");\
}
#define USER_REG_HAVE_OK(s) {\
	CREATE_NPROGRESS();\
	boaWrite(wp, "<div class=\"reg_secs\">%s</div><br>", s);\
	boaWrite(wp, "<div align=\"center\"><a style=\"text-decoration:none;\" href=\"/usereg.asp\" ><font style=\"color:#c0c0c0;\" size=\"3\" >返回</font></a></div>");\
	boaWrite(wp, "<div id=\"ok\"></div>");\
}

#elif defined(CONFIG_CMCC)
#define USER_REG_HAVE_FAIL(s) {\
	CREATE_NPROGRESS();\
	boaWrite(wp, "<div align=\"left\"><font color=\"red\">%s</font></div><br>", s);\
	boaWrite(wp, "<div align=\"center\"><a href=\"/usereg.asp\" ><font style=\"color:#ffffff;\" size=\"3\" >返回</font></a></div>");\
	boaWrite(wp, "<div id=\"ok\"></div>");\
}
#define USER_REG_HAVE_OK(s) {\
	CREATE_NPROGRESS();\
	boaWrite(wp, "<div align=\"left\">%s</div><br>", s);\
	boaWrite(wp, "<div align=\"center\"><a href=\"/usereg.asp\" ><font style=\"color:#ffffff;\" size=\"3\" >返回</font></a></div>");\
	boaWrite(wp, "<div id=\"ok\"></div>");\
}

#else
#define USER_REG_HAVE_OK(s) {\
	boaWrite(wp, "%s\n", s);\
	CREATE_NPROGRESS();\
	boaWrite(wp, "<input id=\"ok\" type=\"button\" value=\"确定\" align=\"center\" onclick=\"location.href='/usereg.asp';\" >");\
}
#endif

#ifdef CONFIG_CU 
#define USER_REG_NO_OK(s) {\
	CREATE_NPROGRESS();\
	boaWrite(wp, "<br><p class=\"reg_no\">%s</p>\n", s);\
	boaWrite(wp, "<div id=\"progress-boader\"></div>");\
}
#elif defined(CONFIG_CMCC)
#define USER_REG_NO_OK(s) {\
	CREATE_NPROGRESS();\
	boaWrite(wp, "<br>%s\n", s);\
	boaWrite(wp, "<div id=\"progress-boader\"></div>");\
}
#else
#define USER_REG_NO_OK(s) {\
	boaWrite(wp, "%s\n", s);\
	CREATE_NPROGRESS();\
	boaWrite(wp, "<div id=\"progress-boader\"></div>");\
}
#endif

#define USER_REG_REBOOT() {\
	boaWrite(wp, "<script>\n");\
	boaWrite(wp, "window.opener=null \n");\
	boaWrite(wp, "window.close();\n");\
	boaWrite(wp, "</script> \n");\
}

#ifdef CONFIG_CU
#define NPROGRESS_SET(N) {\
	if(N==1.0)\
		boaWrite(wp, "<script language=\"javascript\">hideProgress();</script>");\
	else\
		boaWrite(wp, "<script language=\"javascript\">setProgressVal(%d);</script>", (unsigned int)((N)*100));\
}
#else
#define NPROGRESS_SET(N) {\
	boaWrite(wp, "<script language=\"javascript\">setProgressVal(%d);</script>", (unsigned int)((N)*100));\
}
#endif

#define NPROGRESS_DONE() {\
	boaWrite(wp, "<script language=\"javascript\">setProgressDone();</script>");\
}

#define NPROGRESS_HIDE() {\
	boaWrite(wp, "<script language=\"javascript\">hideProgress();</script>");\
}

#if defined(CONFIG_GPON_FEATURE) || defined(CONFIG_EPON_FEATURE)
#if defined(_PRMT_X_CT_COM_USERINFO_) && defined(E8B_NEW_DIAGNOSE)
#define USER_REG_SIMPLE_HAVE_OK(s) {\
	boaWrite(wp, "%s\n", s);\
	boaWrite(wp, "<input id=\"ok\" type=\"button\" value=\"确定\"  onclick=\"location.href='/usereg.asp';\" >");\
}

#define USER_REG_SIMPLE_NO_OK(s) {\
	boaWrite(wp, "%s\n", s);\
}


int UserAccountRegResultSimple(int eid, request * wp, int argc, char **argv)
{
	static int rebootTime = 0;
	int i, total, ret;
	MIB_CE_ATM_VC_T entry;
	struct in_addr inAddr;
	FILE *fp=NULL;
	char buf[256], serviceName[32];
	unsigned int regStatus;
	unsigned int regResult;
	int inform_status = NO_INFORM;

#ifdef CONFIG_RTK_OMCI_V1
	PON_OMCI_CMD_T msg;
#endif
#if defined(CONFIG_GPON_FEATURE) || defined(CONFIG_EPON_FEATURE)
	unsigned int pon_mode, pon_state;
	mib_get(MIB_PON_MODE, &pon_mode);
#endif
	unsigned char loid[MAX_NAME_LEN];
        unsigned char password[MAX_NAME_LEN];
        unsigned char old_loid[MAX_NAME_LEN];
        unsigned char old_password[MAX_NAME_LEN];


	fp = fopen(INFORM_STATUS_FILE, "r");
	if (fp)
	{
		if (fscanf(fp, "%d:%*s", &inform_status) == EOF)
			inform_status = NO_INFORM;
	}
	else
		inform_status = NO_INFORM;


        mib_get(MIB_LOID, loid);
        mib_get(MIB_LOID_OLD, old_loid);
        if(strcmp(loid, old_loid) != 0)
        {
                mib_set(MIB_LOID_OLD, loid);
                #ifdef COMMIT_IMMEDIATELY
                Commit();
                #endif
        }
        mib_get(MIB_LOID_PASSWD, password);
        mib_get(MIB_LOID_PASSWD_OLD, old_password);
        if(strcmp(password, old_password) != 0)
        {
                mib_set(MIB_LOID_PASSWD_OLD, password);
                #ifdef COMMIT_IMMEDIATELY
                Commit();
                #endif
        }

	if (inform_status != INFORM_SUCCESS)	//ACS not responsed
	{

		total = mib_chain_total(MIB_ATM_VC_TBL);

		for (i = 0; i < total; i++)
		{
			if (mib_chain_get(MIB_ATM_VC_TBL, i, &entry) == 0)
				continue;

			if ((entry.applicationtype & X_CT_SRV_TR069) &&
					ifGetName(entry.ifIndex, buf, sizeof(buf)) &&
					getInFlags(buf, &ret) &&
					(ret & IFF_UP) &&
					getInAddr(buf, IP_ADDR, &inAddr))
				break;
		}

#if defined(CONFIG_GPON_FEATURE) || defined(CONFIG_EPON_FEATURE)
		if(pon_mode == 1)
		{
#if defined(CONFIG_GPON_FEATURE) && defined(CONFIG_RTK_OMCI_V1)
			/* During deactivate, the IP may not be cleared in a small period of time.*/
			/* So check gpon state first. */
			memset(&msg, 0, sizeof(msg));
			msg.cmd = PON_OMCI_CMD_LOIDAUTH_GET_RSP;
			ret = omci_SendCmdAndGet(&msg);

			if (ret != GOS_OK || (msg.state != 0 && msg.state != 1)) {
				USER_REG_SIMPLE_NO_OK(OLT_ACCOUNT_REG_FAIL);
				return 0;
			}
			pon_state = msg.state;
#endif
		}
		else if(pon_mode == 2)
		{
#ifdef CONFIG_EPON_FEATURE
			rtk_epon_llid_entry_t  llidEntry;

			memset(&llidEntry, 0, sizeof(rtk_epon_llid_entry_t));
			llidEntry.llidIdx = 0;
#ifdef CONFIG_RTK_L34_ENABLE
			rtk_rg_epon_llid_entry_get(&llidEntry);
#else
			rtk_epon_llid_entry_get(&llidEntry);
#endif
			if(llidEntry.valid)
			{
				int ret = epon_getAuthState(llidEntry.llidIdx);

				switch(ret)
				{
				case 2:	// not complete
					pon_state = 0;
					break;
				case 1:	// OK
					pon_state = 1;
					break;
				default:	// fail
					USER_REG_HAVE_OK(OLT_ACCOUNT_REG_FAIL);
					NPROGRESS_DONE();
					if(fp!=NULL)
						fclose(fp);
					return 0;
		}
			}
			else
				pon_state = 0;	// not complete
#endif
		}
#endif
		if (ctregcount >= 24)
		{
			/* 120 seconds, timeout */
			if (i == total) {
				/* The interface for TR069 is not ready */
				USER_REG_SIMPLE_HAVE_OK(E8CLIENT_ACCOUNT_REG_FAIL4);
			} else {
				USER_REG_SIMPLE_HAVE_OK(E8CLIENT_ITMS_NOT_REACHABLE);
			}
		} else {
			ctregcount++;
#if defined(CONFIG_GPON_FEATURE) || defined(CONFIG_EPON_FEATURE)
			if (pon_state == 0) {
				USER_REG_SIMPLE_NO_OK(OLT_ACCOUNT_REG_ING);
				if(fp!=NULL)
					fclose(fp);
				return 0;
			}
#endif
			if (i == total) {
				/* The interface for TR069 is not ready */
#if defined(CONFIG_GPON_FEATURE) || defined(CONFIG_EPON_FEATURE)
				if(pon_state == 1)
				{
					USER_REG_SIMPLE_NO_OK(OLT_ACCOUNT_REG_SUCC);
					SaveLOIDReg();
				}
#else
				USER_REG_SIMPLE_NO_OK(E8CLIENT_ACCOUNT_REG);
#endif
			} else {
				USER_REG_SIMPLE_NO_OK(E8CLIENT_TR069_READY);
				SaveLOIDReg();
			}
		}
	}
	else
	{
		SaveLOIDReg();
		USER_REG_SIMPLE_HAVE_OK(E8CLIENT_ACCOUNT_REMOTE_SETTING_SUCCESS2);

		regStatus = 0;
		mib_set(CWMP_USERINFO_STATUS, &regStatus);
		regResult = SET_SUCCESS;
		mib_set(CWMP_USERINFO_RESULT, &regResult);
		Commit();
	}
	if(fp!=NULL)	
		fclose(fp);
	return 0;
}

int UserAccountRegResultFor4StageDiag(int eid, request * wp, int argc, char **argv)
{
	int i, total, ret, pingpid=0, ping_succ=0;
	MIB_CE_ATM_VC_T entry;
	struct in_addr inAddr;
	struct stat st;
	FILE *fp;
	char buf[512], serviceName[32], doneServiceName[64];
	unsigned int regStatus;
	unsigned int regLimit;
	unsigned int regTimes;
	unsigned char regInformStatus;
	unsigned int regResult;
	unsigned char needReboot;
	int serviceNum;
#if defined(CONFIG_GPON_FEATURE) || defined(CONFIG_EPON_FEATURE)
#ifdef CONFIG_RTK_OMCI_V1
	PON_OMCI_CMD_T msg;
#endif
	int loid_exist=0;
	unsigned int pon_mode, pon_state;
	rtk_enable_t pon_lost;
#elif defined(CONFIG_ETHWAN)
	unsigned int eth_state;
#endif

#if defined(CONFIG_GPON_FEATURE) || defined(CONFIG_EPON_FEATURE)
	mib_get(MIB_PON_MODE, &pon_mode);
#ifdef CONFIG_RTK_L34_ENABLE
	rtk_rg_ponmac_losState_get(&pon_lost);
#else
	rtk_ponmac_losState_get(&pon_lost);
#endif

	if (pon_mode == GPON_MODE) {
#ifdef 	CONFIG_GPON_FEATURE
		pon_state = getGponONUState();
#endif
		boaWrite(wp, "<tr><td><font size='5' color='red'>GPON 上行 E8-C 终端</font></td></tr>");
	} else if (pon_mode == EPON_MODE) {
#ifdef CONFIG_EPON_FEATURE
		pon_state = getEponONUState(0);
        if (pon_state == 5)
        {
           // int ret;
            loid_exist = epon_getAuthState(0);//0--fail,1--successful, 2-- not complete
           // if (1 == ret)//auth successful
            //    loid_exist = 1;
        }
#endif
		boaWrite(wp, "<tr><td><font size='5' color='red'>EPON 上行 E8-C 终端</font></td></tr>");
	}
#elif defined(CONFIG_ETHWAN)
	eth_state = get_net_link_status(ALIASNAME_NAS0);
	boaWrite(wp, "<tr><td><font size='5' color='red'>ETH 上行 E8-C 终端</font></td></tr>");
#endif

	mib_get(CWMP_USERINFO_STATUS, &regStatus);
	mib_get(CWMP_USERINFO_LIMIT, &regLimit);
	mib_get(CWMP_USERINFO_TIMES, &regTimes);
	mib_get(CWMP_REG_INFORM_STATUS, &regInformStatus);
	mib_get(CWMP_USERINFO_RESULT, &regResult);
	mib_get(CWMP_USERINFO_NEED_REBOOT, &needReboot);
	mib_get(CWMP_USERINFO_SERV_NUM, &serviceNum);

	CREATE_NPROGRESS();
	boaWrite(wp, "<br><br>");

#if defined(CONFIG_GPON_FEATURE) || defined(CONFIG_EPON_FEATURE)
	if(pon_lost)//error
#elif defined(CONFIG_ETHWAN)
	if(eth_state != 1)
#endif
	{
		E8CLIENT_4STAGEDIAG_REG_FAIL_TO_RETURN(OLT_ACCOUNT_REG_FAIL_MSG, OLT_ACCOUNT_REG_AGAIN);
		NPROGRESS_HIDE();
		return 0;
	}

	if (regInformStatus != CWMP_REG_RESPONSED) {	//ACS not returned result

		total = mib_chain_total(MIB_ATM_VC_TBL);

		for (i = 0; i < total; i++) {
			if (mib_chain_get(MIB_ATM_VC_TBL, i, &entry) == 0)
				continue;

			if ((entry.applicationtype & X_CT_SRV_TR069) &&
					ifGetName(entry.ifIndex, buf, sizeof(buf)) &&
					getInFlags(buf, &ret) &&
					(ret & IFF_UP) &&
					getInAddr(buf, IP_ADDR, &inAddr))
				break;
		}

#if defined (CONFIG_RTK_OMCI_V1) && defined(CONFIG_GPON_FEATURE)
		if(pon_mode == 1)//gpon mode
		{
			/* During deactivate, the IP may not be cleared in a small period of time.*/
			/* So check gpon state first. */
			memset(&msg, 0, sizeof(msg));
			msg.cmd = PON_OMCI_CMD_LOIDAUTH_GET_RSP;
			ret = omci_SendCmdAndGet(&msg);

			if (ret != GOS_OK) {
				NPROGRESS_SET(0.23);
				E8CLIENT_4STAGEDIAG_REG_FAIL_TO_RETURN(OLT_ACCOUNT_REG_FAIL_NOLOID_4STAGEDIAG_1, OLT_ACCOUNT_REG_AGAIN);
				return 0;
			}
			loid_exist = msg.state;
		}
#endif

		if (regOLTCount >= 36)
		{/* 180 seconds, timeout */
#if defined(CONFIG_GPON_FEATURE) || defined(CONFIG_EPON_FEATURE)
			if(pon_state != 5)
#elif CONFIG_ETHWAN
			if(eth_state != 1)
#endif
			{
#ifdef CONFIG_GPON_FEATURE
				/* for GPON only:2-LOID error, 3-password error, 4-duplicate LOID */
				if ((pon_mode == 1)&&(pon_state > 0)&&(loid_exist>=2) ) {
					E8CLIENT_4STAGEDIAG_REG_FAIL_TO_RETURN(OLT_ACCOUNT_REG_FAIL_NOLOID_4STAGEDIAG_1, OLT_ACCOUNT_REG_AGAIN);
					NPROGRESS_SET(0.23);
					return 0;
				}
#endif
				NPROGRESS_SET(0.24);
				E8CLIENT_4STAGEDIAG_REG_FAIL_TO_RETURN(OLT_ACCOUNT_REG_TIMEOUT_4STAGEDIAG_1, OLT_ACCOUNT_REG_AGAIN);
				return 0;
			}

#ifdef CONFIG_EPON_FEATURE
            else if ((pon_mode==2)&&(pon_state == 5) && (loid_exist == 0))
            {
            	//printf("[%s %d]\n", __func__, __LINE__);
				NPROGRESS_SET(0.23);
				inProcess = 0.23;
				E8CLIENT_4STAGEDIAG_REG_FAIL_TO_RETURN(OLT_ACCOUNT_REG_FAIL_NOLOID_4STAGEDIAG_1, OLT_ACCOUNT_REG_AGAIN);
				return 0;
            }
#endif
		} else {//regOLTCount<=36
#if defined(CONFIG_GPON_FEATURE) || defined(CONFIG_EPON_FEATURE)
			/* for GPON only:2-LOID error, 3-password error, 4-duplicate LOID */
			if ((pon_mode == 1)&&(pon_state > 0)&&(loid_exist>=2) ) {
				E8CLIENT_4STAGEDIAG_REG_FAIL_TO_RETURN(OLT_ACCOUNT_REG_FAIL_NOLOID_4STAGEDIAG_1, OLT_ACCOUNT_REG_AGAIN);
				NPROGRESS_SET(0.23);
				inProcess = 0.23;
				//printf("[%s %d]\n", __func__, __LINE__);
				return 0;
			}

			if( (pon_mode == 1)&& ((pon_state < 5) || (loid_exist == 0)))
			{//registering in OLT
				regOLTCount++;
				boaWrite(wp, OLT_ACCOUNT_REG_ING_4STAGEDIAG_1);
				if(0.04*pon_state >= inProcess)
				{
					NPROGRESS_SET(0.04*pon_state);
					inProcess = 0.04*pon_state;
				}
				else
				{
					NPROGRESS_SET(inProcess);
				}
				return 0;
			}
			else if( (pon_mode == 2)&&(pon_state == 5)&&(loid_exist == 0) )//LOID error
			{
				regOLTCount++;
				//printf("[%s %d]\n", __func__, __LINE__);
				NPROGRESS_SET(0.23);
				inProcess = 0.23;
				E8CLIENT_4STAGEDIAG_REG_FAIL_TO_RETURN(OLT_ACCOUNT_REG_FAIL_NOLOID_4STAGEDIAG_1, OLT_ACCOUNT_REG_AGAIN);
				return 0;
			}
			else if( (pon_mode == 2)&&(pon_state < 5) )
			{//registering in OLT
				regOLTCount++;
				boaWrite(wp, OLT_ACCOUNT_REG_ING_4STAGEDIAG_1);
				if(0.04*pon_state >= inProcess)
				{
					//printf("[%s %d]\n", __func__, __LINE__);
					NPROGRESS_SET(0.04*pon_state);
					inProcess = 0.04*pon_state;
				}
				else
				{
					NPROGRESS_SET(inProcess);
				}
				return 0;
			}
			else if( (pon_state == 5)&&(pon_mode == 2)&&(loid_exist == 2) )
			{
				regOLTCount++;
				//printf("[%s %d]:loid_exist=%d\n", __func__, __LINE__, loid_exist);
				if(inProcess <= 0.22)
				{
					boaWrite(wp, OLT_ACCOUNT_REG_ING_4STAGEDIAG_1);
					NPROGRESS_SET(0.22);
					inProcess = 0.22;
				}else if( inProcess>=26 )
				{
					boaWrite(wp, E8CLIENT_ACCOUNT_GET_ING_IP_4STAGEDIAG_2);
					NPROGRESS_SET(inProcess);
				}
				return 0;
			}
#endif
#if defined(CONFIG_GPON_FEATURE) || defined(CONFIG_EPON_FEATURE)
			if( (pon_state == 5) && ( ((pon_mode==1)&&(loid_exist == 1))||( (pon_mode==2)&&(loid_exist == 1) ) ) )
#elif defined(CONFIG_ETHWAN)
			if(eth_state == 1)
#endif
			{//olt register successfully
/*****************************************************************/
				//printf("[%s %d]:loid_exist=%d\n", __func__, __LINE__, loid_exist);
				getIPCount++;
				SaveLOIDReg();
#ifdef CONFIG_EPON_FEATURE
				if( (i != total)&&(pon_mode == 2)&&(getIPCount == 1) )
				{
					//printf("[%s %d]\n", __func__, __LINE__);
					regOLTCount++;
					boaWrite(wp, OLT_ACCOUNT_REG_ING_4STAGEDIAG_1);
					NPROGRESS_SET(0.22);
					inProcess = 0.22;
					return 0;
				}
				else if( (i != total)&&(pon_mode == 2)&&(getIPCount==2) )
				{
					//printf("[%s %d]\n", __func__, __LINE__);
					boaWrite(wp, OLT_ACCOUNT_REG_SUCC_4STAGEDIAG_1);
					NPROGRESS_SET(0.25);
					inProcess = 0.25;
					return 0;
				}
				else if( (i != total)&&(pon_mode == 2)&&(getIPCount==3) )
				{
					//printf("[%s %d]\n", __func__, __LINE__);
					boaWrite(wp, E8CLIENT_ACCOUNT_GET_ING_IP_4STAGEDIAG_2);
					NPROGRESS_SET(0.26);
					inProcess = 0.26;
					return 0;
				}
#endif
				if( (i == total)&&(getIPCount < 2) )
				{
					regOLTCount++;
					//printf("[%s %d]\n", __func__, __LINE__);
					boaWrite(wp, OLT_ACCOUNT_REG_ING_4STAGEDIAG_1);
					NPROGRESS_SET(0.22);
					inProcess = 0.22;
					return 0;
				}else if( (i == total)&&(getIPCount==2) )
				{
					//printf("[%s %d]\n", __func__, __LINE__);
					boaWrite(wp, OLT_ACCOUNT_REG_SUCC_4STAGEDIAG_1);
					NPROGRESS_SET(0.25);
					inProcess = 0.25;
					return 0;
				}
/****************************************************************/
				if( (i == total)&&(getIPCount<=16) )
				{//getting ip
					float getIPProcess = 0.0;
					boaWrite(wp, E8CLIENT_ACCOUNT_GET_ING_IP_4STAGEDIAG_2);
					SaveLOIDReg();
					getIPProcess = 0.26 + 0.02*(getIPCount-3);
					if(getIPProcess < 0.48)
					{
						inProcess = getIPProcess;
						NPROGRESS_SET(getIPProcess);
					}else{
						inProcess = 0.48;
						NPROGRESS_SET(0.48);
					}
					return 0;
				}
				else if( (i == total)&&(getIPCount>16) )
				{//get ip timeout
					NPROGRESS_SET(0.49);
					E8CLIENT_4STAGEDIAG_REG_FAIL_TO_RETURN(E8CLIENT_ACCOUNT_GET_IP_FAIL_4STAGEDIAG_2, E8CLIENT_ACCOUNT_CALL_FOR_BRAS_OK);
					return 0;
				}
				else//have get ip
				{
					SaveLOIDReg();
					if(regInformStatus == CWMP_REG_IDLE)//get ip but not send request to ITMS
					{
						boaWrite(wp, E8CLIENT_ACCOUNT_GET_IP_SUCC_4STAGEDIAG_2);
						SaveLOIDReg();
						NPROGRESS_SET(0.5);
						regITMSCount++;
						inProcess = 0.5;
						return 0;
					}
#if defined(CONFIG_GPON_FEATURE) || defined(CONFIG_EPON_FEATURE)
					if(regITMSCount == 0)
					{
						regITMSCount++;
						boaWrite(wp, E8CLIENT_ACCOUNT_GET_IP_SUCC_4STAGEDIAG_2);
						NPROGRESS_SET(0.5);
						inProcess = 0.5;
						return 0;
					}
					else if(regITMSCount == 1)
					{
						regITMSCount++;
						boaWrite(wp, E8CLIENT_ITMS_CONNECT_4STAGEDIAG_3);
						NPROGRESS_SET(0.51);
						inProcess = 0.51;
						return 0;
					}
#endif
					if( (regITMSCount < 12)&&(regInformStatus == CWMP_REG_REQUESTED) )
					{//send cwmp register request to ITMS
						boaWrite(wp, E8CLIENT_ITMS_CONNECT_4STAGEDIAG_3);
						SaveLOIDReg();
						NPROGRESS_SET(0.6);
						inProcess = 0.6;
						regITMSCount++;
						return 0;
					}
					else if(regITMSCount >= 12)
					{
						//printf("[%s %d]:ping start\n", __func__, __LINE__);
						if( pingAgain==0 )
						{
							char ITMS_Server[256];
							char acsurl[256];

							va_cmd("/bin/killall", 1, 1, "ping");
							unlink("/tmp/pon_diag_ping.tmp");

							memset(ITMS_Server, 0, 256);
							memset(acsurl, 0, 256);
							if(!mib_get(CWMP_ACS_URL, (void*)acsurl))
							{
								fprintf(stderr, "Get mib value CWMP_ACS_URL failed!\n");
							}
							else
							{
								set_endpoint(ITMS_Server, acsurl);
								memset(buf, 0, sizeof(buf));
								sprintf(buf, "/bin/ping -c 3 -w 6 %s -I nas0_0 > /tmp/pon_diag_ping.tmp\n", ITMS_Server);
								va_cmd("/bin/sh", 2, 0, "-c", buf);
								printf("buf is : %s \n" , buf);
							}
							pingAgain++;
						}

						unlink("/tmp/pingpid.tmp");
						system("/bin/pidof ping > /tmp/pingpid.tmp\n");

						fp = fopen("/tmp/pingpid.tmp", "r");
						if(fp)
						{
							fscanf(fp, "%d", &pingpid);
							if(pingpid)
							{//ping is still running
								boaWrite(wp, E8CLIENT_ITMS_PING_4STAGEDIAG_3);
								//E8CLIENT_4STAGEDIAG_REG_FAIL_TO_RETURN(OLT_ACCOUNT_REG_FAIL_MSG, OLT_ACCOUNT_REG_AGAIN);
								NPROGRESS_SET(0.72);//have send ping
								fclose(fp);
								return 0;
							}
							fclose(fp);
						}

						fp = fopen("/tmp/pon_diag_ping.tmp", "r");
						if (fp)
						{
							while (fgets(buf, sizeof(buf), fp))
							{
								if ( strstr(buf, "ttl=") )
								{
									ping_succ = 1;
									break;
								}
							}
							if(ping_succ)
							{
								NPROGRESS_SET(0.74);
								E8CLIENT_4STAGEDIAG_REG_FAIL_TO_RETURN(E8CLIENT_ITMS_PING_SUCC_4STAGEDIAG_3, E8CLIENT_ITMS_CALL_FOR_OK_AND_TRY_AGAIN);
							}
							else
							{
								printf("[%s %d]\n", __func__, __LINE__);
								NPROGRESS_SET(0.73);
								E8CLIENT_4STAGEDIAG_REG_FAIL_TO_RETURN(E8CLIENT_ITMS_PING_FAIL_4STAGEDIAG_3, E8CLIENT_ITMS_CALL_FOR_OK);
							}
							fclose(fp);
						}// end fp=fopen
					}//end of else if(regITMSCount >= 12)
				}//end of //have get ip
			}//end of if(pon_state == 5)
		}//end of if (regOLTCount < 36)
	} else {//ITMS responsed
		SaveLOIDReg();
		if (regStatus == 0) {
			if(regResult == SET_FAULT)
			{
				E8CLIENT_4STAGEDIAG_REG_FAIL_TO_RETURN(E8CLIENT_ITMS_CONFIG_FAIL_4STAGEDIAG_4, OLT_ACCOUNT_REG_AGAIN);
				NPROGRESS_SET(0.98);
				return 0;
			}

			if( (regResult != SET_SUCCESS) && (issueBussinessCount >= 48) )
			{
				E8CLIENT_4STAGEDIAG_REG_FAIL_TO_RETURN(E8CLIENT_ITMS_CONFIG_TIMEOUT_4STAGEDIAG_4, OLT_ACCOUNT_REG_AGAIN);
				NPROGRESS_SET(0.99);
				return 0;
			}
			else
			{
#ifdef CONFIG_EPON_FEATURE
				if( (pon_mode == 2)&&(getIPCount == 0) )
				{
					regOLTCount++;
					boaWrite(wp, OLT_ACCOUNT_REG_ING_4STAGEDIAG_1);
					NPROGRESS_SET(0.22);
					inProcess = 0.22;
					//printf("[%s %d]\n", __func__, __LINE__);
					getIPCount++;
					return 0;
				}
				else if( (pon_mode == 2)&&(getIPCount==1) )
				{
					boaWrite(wp, OLT_ACCOUNT_REG_SUCC_4STAGEDIAG_1);
					NPROGRESS_SET(0.25);
					getIPCount++;
					inProcess=0.25;
					return 0;
				}
				else if( (pon_mode == 2)&&(getIPCount==2) )
				{
					boaWrite(wp, E8CLIENT_ACCOUNT_GET_ING_IP_4STAGEDIAG_2);
					NPROGRESS_SET(0.26);
					getIPCount++;
					inProcess=0.26;
					return 0;
				}

				if( (pon_mode == 2)&&(regITMSCount == 0) )
				{
					regITMSCount++;
					boaWrite(wp, E8CLIENT_ACCOUNT_GET_IP_SUCC_4STAGEDIAG_2);
					NPROGRESS_SET(0.5);
					inProcess=0.5;
					return 0;
				}
				else if( (pon_mode == 2)&&(regITMSCount == 1) )
				{
					regITMSCount++;
					boaWrite(wp, E8CLIENT_ITMS_CONNECT_4STAGEDIAG_3);
					NPROGRESS_SET(0.51);
					inProcess=0.51;
					return 0;
				}
#endif
#if defined (CONFIG_GPON_FEATURE) || defined (CONFIG_EPON_FEATURE)
				if(issueBussinessCount == 0)
				{
					boaWrite(wp, E8CLIENT_ITMS_SUCC_4STAGEDIAG_3);
					NPROGRESS_SET(0.75);
					issueBussinessCount++;
					return 0;
				}
#endif

				switch (regResult) {
				case NO_SET:
					//printf("[%s %d]\n", __func__, __LINE__);
					boaWrite(wp, E8CLIENT_ITMS_SUCC_4STAGEDIAG_3);
					NPROGRESS_SET(0.75);
					unlink(REBOOT_DELAY_FILE);
					issueBussinessCount++;
					break;
				case NOW_SETTING:
					//printf("[%s %d]\n", __func__, __LINE__);
					boaWrite(wp, E8CLIENT_ITMS_CONFIG_ING_4STAGEDIAG_4);
					mib_get(CWMP_USERINFO_SERV_NUM_DONE, &i);

					if(serviceNum > 0)
					{
					//	printf("[%s %d]\n", __func__, __LINE__);
						NPROGRESS_SET(0.76 + 0.21 * i / serviceNum);
					}
					else
					{
					//	printf("[%s %d]\n", __func__, __LINE__);
						NPROGRESS_SET(0.76);// ITMS not set this mib now
					}

					issueBussinessCount++;
					break;
				case SET_SUCCESS:
#ifdef CONFIG_EPON_FEATURE
					if( (pon_mode == 2)&&(issueBussinessCount == 0) )
					{
						boaWrite(wp, E8CLIENT_ITMS_SUCC_4STAGEDIAG_3);
						NPROGRESS_SET(0.75);
						issueBussinessCount++;
						return 0;
					}
					else if( (pon_mode == 2)&&(issueBussinessCount == 1) )
					{
						boaWrite(wp, E8CLIENT_ITMS_CONFIG_ING_4STAGEDIAG_4);
						NPROGRESS_SET(0.76);
						issueBussinessCount++;
						return 0;
					}
					else if( (pon_mode == 2)&&(issueBussinessCount < 2+serviceNum) )
					{
						if(serviceNum > 0)
						{
							NPROGRESS_SET(0.76 + 0.21 * (issueBussinessCount-1) / serviceNum);
							boaWrite(wp, E8CLIENT_ITMS_CONFIG_ING_4STAGEDIAG_4);

							issueBussinessCount++;
							return 0;
						}
					}
#endif
					mib_get(CWMP_USERINFO_SERV_NAME_DONE, serviceName);

					memset(doneServiceName, 0, sizeof(doneServiceName));
					if( strstr(serviceName, "INTERNET") )
					{
						sprintf(doneServiceName, "宽带");
					}
					if( strstr(serviceName, WAN_VOIP_VOICE_NAME) )
					{
						strcat(doneServiceName, "、语音");
					}
					if( strstr(serviceName, "ITV") )
					{
						strcat(doneServiceName, "、ITV");
					}

					if(doneServiceName[0] != 0)
					{
						memset(buf, 0, sizeof(buf));
						sprintf(buf, E8CLIENT_INTERENT_IPTV_VOICE_SUCC_4STAGEDIAG_4, doneServiceName);
						E8CLIENT_4STAGEDIAG_REG_SUCC(buf);
					}
					else
					{
						E8CLIENT_4STAGEDIAG_REG_SUCC(E8CLIENT_ITMS_CONFIG_SUCC_4STAGEDIAG_4);
					}
						//printf("[%s %d]\n", __func__, __LINE__);
						NPROGRESS_SET(1.0);
						unlink(REBOOT_DELAY_FILE);
						break;
					}//end of switch
			}// end of else
		}// if (regStatus == 0)
		else if (regStatus == 2 && regResult == 99)
		{//invalid LOID
			unsigned int int_process = (unsigned int)(inProcess*100);
#ifdef CONFIG_EPON_FEATURE
			if( (pon_mode == 2)&&(int_process < 51) )
			{
				//printf("[%s %d]:int_process=%d\n", __func__, __LINE__, int_process);
				if(int_process < 22)
				{
					boaWrite(wp, OLT_ACCOUNT_REG_ING_4STAGEDIAG_1);
					NPROGRESS_SET(0.22);
					inProcess = 0.22;
					return 0;
				}else if(int_process<25)
				{
					boaWrite(wp, OLT_ACCOUNT_REG_SUCC_4STAGEDIAG_1);
					NPROGRESS_SET(0.25);
					inProcess = 0.25;
					return 0;
				}else if(int_process <26)
				{
					boaWrite(wp, E8CLIENT_ACCOUNT_GET_ING_IP_4STAGEDIAG_2);
					NPROGRESS_SET(0.26);
					inProcess = 0.26;
					return 0;
				}
				else if(int_process <50)
				{
					boaWrite(wp, E8CLIENT_ACCOUNT_GET_IP_SUCC_4STAGEDIAG_2);
					NPROGRESS_SET(0.5);
					inProcess = 0.50;
					return 0;
				}
				else if(int_process < 51)
				{
					boaWrite(wp, E8CLIENT_ITMS_CONNECT_4STAGEDIAG_3);
					NPROGRESS_SET(0.51);
					inProcess = 0.51;
					return 0;
				}
			}
#endif
			E8CLIENT_4STAGEDIAG_REG_FAIL_TO_RETURN(E8CLIENT_ITMS_INVALID_LOID_4STAGEDIAG, E8CLIENT_ITMS_INVALID_LOID_MSG_4STAGEDIAG);
			NPROGRESS_HIDE();
			return 0;
		}
		else if (regStatus == 5)
		{//no need register to ITMS
			//printf("[%s %d]\n", __func__, __LINE__);
			E8CLIENT_4STAGEDIAG_REG_SUCC(E8CLIENT_REPEAT_REG_4STAGEDIAG_4);
			NPROGRESS_SET(1.0);
			return 0;
		}
		else if(regStatus <= 4)
		{//send ping to tr069 server
			if(regITMSCount<12)
			{
				boaWrite(wp, E8CLIENT_ITMS_CONNECT_4STAGEDIAG_3);
				SaveLOIDReg();
				NPROGRESS_SET(0.6);
				regITMSCount++;
				return 0;
			}
			else
			{
				printf("[%s %d]:ping start\n", __func__, __LINE__);

				if( pingAgain==0 )
				{
					char ITMS_Server[256];
					char acsurl[256];

					va_cmd("/bin/killall", 1, 1, "ping");
					unlink("/tmp/pon_diag_ping.tmp");

					memset(ITMS_Server, 0, 256);
					memset(acsurl, 0, 256);
					if(!mib_get(CWMP_ACS_URL, (void*)acsurl))
					{
						fprintf(stderr, "Get mib value CWMP_ACS_URL failed!\n");
					}
					else
					{
						set_endpoint(ITMS_Server, acsurl);
						memset(buf, 0, sizeof(buf));
						sprintf(buf, "/bin/ping -c 3 -w 6 %s -I nas0_0 > /tmp/pon_diag_ping.tmp\n", ITMS_Server);
						va_cmd("/bin/sh", 2, 0, "-c", buf);
						printf("buf is : %s \n" , buf);
					}
					pingAgain++;
				}

				unlink("/tmp/pingpid.tmp");
				system("/bin/pidof ping > /tmp/pingpid.tmp\n");

				fp = fopen("/tmp/pingpid.tmp", "r");
				if(fp)
				{
					fscanf(fp, "%d", &pingpid);
					if(pingpid)
					{//ping is still running
						boaWrite(wp, E8CLIENT_ITMS_PING_4STAGEDIAG_3);
						//E8CLIENT_4STAGEDIAG_REG_FAIL_TO_RETURN(OLT_ACCOUNT_REG_FAIL_MSG, OLT_ACCOUNT_REG_AGAIN);
						NPROGRESS_SET(0.72);//have send ping
						fclose(fp);
						return 0;
					}
					fclose(fp);
				}

				fp = fopen("/tmp/pon_diag_ping.tmp", "r");
				if (fp)
				{
					while (fgets(buf, sizeof(buf), fp))
					{
						if ( strstr(buf, "ttl=") )
						{
							ping_succ = 1;
							break;
						}
					}

					if(ping_succ)
					{
						NPROGRESS_SET(0.74);
						E8CLIENT_4STAGEDIAG_REG_FAIL_TO_RETURN(E8CLIENT_ITMS_PING_SUCC_4STAGEDIAG_3, E8CLIENT_ITMS_CALL_FOR_OK_AND_TRY_AGAIN);
					}
					else
					{
						//printf("[%s %d]\n", __func__, __LINE__);
						NPROGRESS_SET(0.73);
						E8CLIENT_4STAGEDIAG_REG_FAIL_TO_RETURN(E8CLIENT_ITMS_PING_FAIL_4STAGEDIAG_3, E8CLIENT_ITMS_CALL_FOR_OK);
					}
					fclose(fp);
				}
				else // no such file , dns query itms domain name fail
				{
					//printf("[%s %d]\n", __func__, __LINE__);
					NPROGRESS_SET(0.73);
                    E8CLIENT_4STAGEDIAG_REG_FAIL_TO_RETURN(E8CLIENT_ITMS_PING_FAIL_4STAGEDIAG_3, E8CLIENT_ITMS_CALL_FOR_OK);
				}
			}// end of else
		}// end of else if(regStatus <= 4)
	} // end of //ITMS responsed
	return 0;
}
#endif

#endif

#ifdef CONFIG_USER_RTK_ONUCOMM
#include "../../onucomm/onucomm.h"
#include <sys/socket.h>
#include <sys/un.h>
static int g_check_eth_link;
#define ONUCOMM_SOCK_FILE "/tmp/onucomm_sock"
static int onucomm_sock = 0;
static int init_onucomm_sock(void)
{
    int ret;
    struct sockaddr_un srv_addr;
    //creat unix socket
    onucomm_sock =socket(PF_UNIX,SOCK_STREAM,0);
    if(onucomm_sock < 0)
    {
        printf("cannot create communication socket\n");
        return -1;
    }
    srv_addr.sun_family = AF_UNIX;
    strcpy(srv_addr.sun_path, ONUCOMM_SOCK_FILE);
    //connect server

retry:
    ret =  connect(onucomm_sock,(struct sockaddr*)&srv_addr,sizeof(srv_addr));
    if(ret == -1)
    {
		perror("Error ");
		if(errno == EINTR)
			goto retry;
        printf("cannot connect to the server\n");
        close(onucomm_sock);
        return -1;
    }
	printf("connect success\n");
    return 0;
}
static int close_onucomm_sock(void)
{
	if(onucomm_sock)
	{
		close(onucomm_sock);
		printf("close ok\n");
	}
}
static int onucomm_pon_los(void)
{
    char buf[1500] = {0};
    char recv_buf[256] = {0};
    int recv_len = 0;
	int los = 0;
    ONU_TLV_T *tlv = (ONU_TLV_T *)buf;
	init_onucomm_sock();
    tlv->type = ONU_DATA_TYPE_PON_LOS;
    write(onucomm_sock, buf, sizeof(ONU_TLV_T));
    recv_len = read(onucomm_sock, recv_buf, sizeof(recv_buf));
    tlv = (ONU_TLV_T *)recv_buf;
    memcpy(&los, tlv->data, sizeof(int));
    printf("get gpon los %d\n", los);
	close_onucomm_sock();
    return los;
}
static int onucomm_pon_process2324(void)
{
    char buf[1500] = {0};
    char recv_buf[256] = {0};
    int recv_len = 0;
    int process = 0;
    ONU_TLV_T *tlv = (ONU_TLV_T *)buf;
	init_onucomm_sock();
    tlv->type = ONU_DATA_TYPE_PON_PROCESS;
    write(onucomm_sock, buf, sizeof(ONU_TLV_T));
    recv_len = read(onucomm_sock, recv_buf, sizeof(recv_buf));
    tlv = (ONU_TLV_T *)recv_buf;
    memcpy(&process, tlv->data, sizeof(int));
    printf("get gpon process %d\n", process);
	close_onucomm_sock();
    return process;
}
static void onucomm_pon_loid(char* loid)
{
    char buf[1500] = {0};
    char recv_buf[256] = {0};
    int recv_len = 0;

    ONU_TLV_T *tlv = (ONU_TLV_T *)buf;
	init_onucomm_sock();
    tlv->type = ONU_DATA_TYPE_INFORM_LOID;
    strcpy(tlv->data, loid);
    tlv->len = strlen(loid);
	printf("loid : %s , %d \n" , tlv->data , tlv->len);
    write(onucomm_sock, buf, sizeof(ONU_TLV_T)+tlv->len);
	close_onucomm_sock();
    return;
}

static int onucomm_pon_onustate(void)
{
    char buf[1500] = {0};
    char recv_buf[256] = {0};
    int recv_len = 0;
	int state = 0;
    ONU_TLV_T *tlv = (ONU_TLV_T *)buf;
	init_onucomm_sock();
    tlv->type = ONU_DATA_TYPE_REGISTER_STATE;
    tlv->len = 0;
    write(onucomm_sock, buf, sizeof(ONU_TLV_T));
    recv_len = read(onucomm_sock, recv_buf, sizeof(recv_buf));
    tlv = (ONU_TLV_T *)recv_buf;
    memcpy(&state, tlv->data, sizeof(int));
	close_onucomm_sock();
    printf("sample get gpon register state is %d\n", state);
	return state;
}


int UserAccountRegResultFor4StageDiagONUComm(int eid, request * wp, int argc, char **argv)
{
	int i, total, ret, pingpid=0, ping_succ=0;
	MIB_CE_ATM_VC_T entry;
	struct in_addr inAddr;
	struct stat st;
	FILE *fp;
	char buf[512], serviceName[32], doneServiceName[64];
	unsigned int regStatus;
	unsigned int regLimit;
	unsigned int regTimes;
	unsigned char regInformStatus;
	unsigned int regResult;
	unsigned char needReboot;
	int serviceNum;
	unsigned int eth_state;
	unsigned int pon_mode;
	unsigned int pon_state = 0;
	static int prev_pon_state = 0;


	mib_get(MIB_PON_MODE, &pon_mode);

	if (pon_mode == GPON_MODE) {
		boaWrite(wp, "<tr><td><font size='5' color='red'>GPON 上行 E8-C 终端</font></td></tr>");
	} else if (pon_mode == EPON_MODE) {
		boaWrite(wp, "<tr><td><font size='5' color='red'>EPON 上行 E8-C 终端</font></td></tr>");
	}
	eth_state = get_net_link_status(ALIASNAME_NAS0);

	mib_get(CWMP_USERINFO_STATUS, &regStatus);
	mib_get(CWMP_USERINFO_LIMIT, &regLimit);
	mib_get(CWMP_USERINFO_TIMES, &regTimes);
	mib_get(CWMP_REG_INFORM_STATUS, &regInformStatus);
	mib_get(CWMP_USERINFO_RESULT, &regResult);
	mib_get(CWMP_USERINFO_NEED_REBOOT, &needReboot);
	mib_get(CWMP_USERINFO_SERV_NUM, &serviceNum);

	CREATE_NPROGRESS();
	boaWrite(wp, "<br><br>");

	if(eth_state != 1 && g_check_eth_link ==0)
	{
		E8CLIENT_4STAGEDIAG_REG_FAIL_TO_RETURN(OLT_ACCOUNT_REG_FAIL_MSG, OLT_ACCOUNT_REG_AGAIN);
		NPROGRESS_HIDE();
		g_check_eth_link = 0;
		return 0;
	}else g_check_eth_link = 1;

	if(eth_state != 1) g_check_eth_link = 0;

	if(onucomm_pon_los() == 1)
	{
		printf("Check LOS again \n");
		if(onucomm_pon_los() == 1)
		{
			E8CLIENT_4STAGEDIAG_REG_FAIL_TO_RETURN(OLT_ACCOUNT_REG_FAIL_MSG, OLT_ACCOUNT_REG_AGAIN);
			NPROGRESS_HIDE();
			g_check_eth_link = 0;
			return 0;
		}
	}

	if(onucomm_pon_process2324() == ONUCOMM_PON_PROCESS_23)
	{
		E8CLIENT_4STAGEDIAG_REG_FAIL_TO_RETURN(OLT_ACCOUNT_REG_FAIL_NOLOID_4STAGEDIAG_1, OLT_ACCOUNT_REG_AGAIN);
		NPROGRESS_SET(0.23);
		inProcess = 0.23;
		return 0;
	}
	printf("regOLT : %d , getIPCount:%d \n" , regOLTCount, getIPCount);
	if(regOLTCount >= 36)
	{
		if(onucomm_pon_process2324() == ONUCOMM_PON_PROCESS_23)
		{
			E8CLIENT_4STAGEDIAG_REG_FAIL_TO_RETURN(OLT_ACCOUNT_REG_FAIL_NOLOID_4STAGEDIAG_1, OLT_ACCOUNT_REG_AGAIN);
			NPROGRESS_SET(0.23);
			inProcess = 0.23;
			return 0;
		}
		NPROGRESS_SET(0.24);
		E8CLIENT_4STAGEDIAG_REG_FAIL_TO_RETURN(OLT_ACCOUNT_REG_TIMEOUT_4STAGEDIAG_1, OLT_ACCOUNT_REG_AGAIN);
		inProcess = 0.24;
		return 0;
	}



	if (regInformStatus != CWMP_REG_RESPONSED)
	{	//ACS not returned result

		total = mib_chain_total(MIB_ATM_VC_TBL);

		for (i = 0; i < total; i++)
		{
			if (mib_chain_get(MIB_ATM_VC_TBL, i, &entry) == 0)
				continue;

			if ((entry.applicationtype & X_CT_SRV_TR069) &&
					ifGetName(entry.ifIndex, buf, sizeof(buf)) &&
					getInFlags(buf, &ret) &&
					(ret & IFF_UP) &&
					getInAddr(buf, IP_ADDR, &inAddr))
				break;
		}

		pon_state = onucomm_pon_onustate();

		if(pon_state == 0) pon_state = prev_pon_state;
		else prev_pon_state = pon_state;

		printf("i:%d , total:%d \n" , i, total);
		if(eth_state == 1 && pon_state == 5)
		{//olt register successfully
/*****************************************************************/
			//printf("[%s %d]:loid_exist=%d\n", __func__, __LINE__, loid_exist);
			getIPCount++;
			SaveLOIDReg();
			if((i != total)&&(getIPCount == 1))
			{
				boaWrite(wp, OLT_ACCOUNT_REG_ING_4STAGEDIAG_1);
				NPROGRESS_SET(0.22);
				inProcess = 0.22;
				return 0;
			}
			else if((i != total)&&(getIPCount == 2))
			{
				//printf("[%s %d]\n", __func__, __LINE__);
				boaWrite(wp, OLT_ACCOUNT_REG_SUCC_4STAGEDIAG_1);
				NPROGRESS_SET(0.25);
				inProcess = 0.25;
				close_onucomm_sock();
				return 0;
			}
			else if((i != total)&&(getIPCount==3) )
			{
				//printf("[%s %d]\n", __func__, __LINE__);
				boaWrite(wp, E8CLIENT_ACCOUNT_GET_ING_IP_4STAGEDIAG_2);
				NPROGRESS_SET(0.26);
				inProcess = 0.26;
				return 0;
			}

			if( (i == total)&&(getIPCount < 2) )
			{
				regOLTCount++;
				//printf("[%s %d]\n", __func__, __LINE__);
				boaWrite(wp, OLT_ACCOUNT_REG_ING_4STAGEDIAG_1);
				NPROGRESS_SET(0.22);
				inProcess = 0.22;
				return 0;
			}
			else if( (i == total)&&(getIPCount==2) )
            {
				//printf("[%s %d]\n", __func__, __LINE__);
				boaWrite(wp, OLT_ACCOUNT_REG_SUCC_4STAGEDIAG_1);
				NPROGRESS_SET(0.25);
				inProcess = 0.25;
				return 0;
			}

			if( (i == total)&&(getIPCount<=16) )
			{//getting ip
				float getIPProcess = 0.0;
				boaWrite(wp, E8CLIENT_ACCOUNT_GET_ING_IP_4STAGEDIAG_2);
				SaveLOIDReg();
				getIPProcess = 0.26 + 0.02*(getIPCount-3);
				if(getIPProcess < 0.48)
				{
					inProcess = getIPProcess;
					NPROGRESS_SET(getIPProcess);
				}else{
					inProcess = 0.48;
					NPROGRESS_SET(0.48);
				}
				return 0;
            }
/****************************************************************/
			if( (i == total)&&(getIPCount>16) )
			{//get ip timeout
				NPROGRESS_SET(0.49);
				E8CLIENT_4STAGEDIAG_REG_FAIL_TO_RETURN(E8CLIENT_ACCOUNT_GET_IP_FAIL_4STAGEDIAG_2, E8CLIENT_ACCOUNT_CALL_FOR_BRAS_OK);
				return 0;
			}
			else//have get ip
			{
				printf("[%s %d] olt:%d , getip:%d\n" , __func__,__LINE__,regOLTCount,getIPCount);
				SaveLOIDReg();
				if(regInformStatus == CWMP_REG_IDLE)//get ip but not send request to ITMS
				{
					boaWrite(wp, E8CLIENT_ACCOUNT_GET_IP_SUCC_4STAGEDIAG_2);
					SaveLOIDReg();
					NPROGRESS_SET(0.5);
					regITMSCount++;
					inProcess = 0.5;
					printf("[%s %d]\n" , __func__,__LINE__);
					return 0;
				}
				if(regITMSCount == 0)
				{
					regITMSCount++;
					boaWrite(wp, E8CLIENT_ACCOUNT_GET_IP_SUCC_4STAGEDIAG_2);
					NPROGRESS_SET(0.5);
					inProcess = 0.5;
					printf("[%s %d]\n" , __func__,__LINE__);
					return 0;
				}
				else if(regITMSCount == 1)
				{
					regITMSCount++;
					boaWrite(wp, E8CLIENT_ITMS_CONNECT_4STAGEDIAG_3);
					NPROGRESS_SET(0.51);
					inProcess = 0.51;
					printf("[%s %d]\n" , __func__,__LINE__);
					return 0;
				}
				if( (regITMSCount < 12)&&(regInformStatus == CWMP_REG_REQUESTED) )
				{//send cwmp register request to ITMS
					boaWrite(wp, E8CLIENT_ITMS_CONNECT_4STAGEDIAG_3);
					SaveLOIDReg();
					NPROGRESS_SET(0.6);
					inProcess = 0.6;
					regITMSCount++;
					printf("[%s %d]\n" , __func__,__LINE__);
					return 0;
				}
				else if(regITMSCount >= 12)
				{
					//printf("[%s %d]:ping start\n", __func__, __LINE__);
					if( pingAgain==0 )
					{
						char ITMS_Server[256];
						char acsurl[256];

						va_cmd("/bin/killall", 1, 1, "ping");
						unlink("/tmp/pon_diag_ping.tmp");

						memset(ITMS_Server, 0, 256);
						memset(acsurl, 0, 256);
						if(!mib_get(CWMP_ACS_URL, (void*)acsurl))
						{
							fprintf(stderr, "Get mib value CWMP_ACS_URL failed!\n");
						}
						else
						{
							set_endpoint(ITMS_Server, acsurl);
							memset(buf, 0, sizeof(buf));
							sprintf(buf, "/bin/ping -c 3 -w 6 %s -I nas0_0 > /tmp/pon_diag_ping.tmp\n", ITMS_Server);
							va_cmd("/bin/sh", 2, 0, "-c", buf);
							printf("buf is : %s \n" , buf);
						}
						pingAgain++;
					}

					unlink("/tmp/pingpid.tmp");
					system("/bin/pidof ping > /tmp/pingpid.tmp\n");

					fp = fopen("/tmp/pingpid.tmp", "r");
					if(fp)
					{
						fscanf(fp, "%d", &pingpid);
						if(pingpid)
						{//ping is still running
							boaWrite(wp, E8CLIENT_ITMS_PING_4STAGEDIAG_3);
							//E8CLIENT_4STAGEDIAG_REG_FAIL_TO_RETURN(OLT_ACCOUNT_REG_FAIL_MSG, OLT_ACCOUNT_REG_AGAIN);
							NPROGRESS_SET(0.72);//have send ping
							fclose(fp);
							return;
						}
						fclose(fp);
					}

					fp = fopen("/tmp/pon_diag_ping.tmp", "r");
					if (fp)
					{
						while (fgets(buf, sizeof(buf), fp))
						{
							if ( strstr(buf, "ttl=") )
							{
								ping_succ = 1;
								break;
							}
						}
						if(ping_succ)
						{
							NPROGRESS_SET(0.74);
							E8CLIENT_4STAGEDIAG_REG_FAIL_TO_RETURN(E8CLIENT_ITMS_PING_SUCC_4STAGEDIAG_3, E8CLIENT_ITMS_CALL_FOR_OK_AND_TRY_AGAIN);
						}
						else
						{
							printf("[%s %d]\n", __func__, __LINE__);
							NPROGRESS_SET(0.73);
							E8CLIENT_4STAGEDIAG_REG_FAIL_TO_RETURN(E8CLIENT_ITMS_PING_FAIL_4STAGEDIAG_3, E8CLIENT_ITMS_CALL_FOR_OK);
						}
						fclose(fp);
					}// end fp=fopen
				}//end of else if(regITMSCount >= 12)
			}//end of //have get ip
		}//end of if(pon_state == 5)
		else // eth_state != 1
		{
			boaWrite(wp, OLT_ACCOUNT_REG_ING_4STAGEDIAG_1);
			regOLTCount++;
			NPROGRESS_SET(0.22);
			inProcess = 0.22;
			getIPCount = 0;
			return 0;
		}

	} else {//ITMS responsed
		SaveLOIDReg();
		if (regStatus == 0) {
			if(regResult == SET_FAULT)
			{
				E8CLIENT_4STAGEDIAG_REG_FAIL_TO_RETURN(E8CLIENT_ITMS_CONFIG_FAIL_4STAGEDIAG_4, OLT_ACCOUNT_REG_AGAIN);
				NPROGRESS_SET(0.98);
				return 0;
			}

			if( (regResult != SET_SUCCESS) && (issueBussinessCount >= 48) )
			{
				E8CLIENT_4STAGEDIAG_REG_FAIL_TO_RETURN(E8CLIENT_ITMS_CONFIG_TIMEOUT_4STAGEDIAG_4, OLT_ACCOUNT_REG_AGAIN);
				NPROGRESS_SET(0.99);
				return 0;
			}
			else
			{
				if( regITMSCount == 0 )
				{
					regITMSCount++;
					boaWrite(wp, E8CLIENT_ACCOUNT_GET_IP_SUCC_4STAGEDIAG_2);
					NPROGRESS_SET(0.5);
					inProcess=0.5;
					return 0;
				}
				else if(regITMSCount == 1 )
				{
					regITMSCount++;
					boaWrite(wp, E8CLIENT_ITMS_CONNECT_4STAGEDIAG_3);
					NPROGRESS_SET(0.51);
					inProcess=0.51;
					return 0;
				}
				if(issueBussinessCount == 0)
				{
					boaWrite(wp, E8CLIENT_ITMS_SUCC_4STAGEDIAG_3);
					NPROGRESS_SET(0.75);
					issueBussinessCount++;
					return 0;
                }


				switch (regResult) {
				case NO_SET:
					//printf("[%s %d]\n", __func__, __LINE__);
					boaWrite(wp, E8CLIENT_ITMS_SUCC_4STAGEDIAG_3);
					NPROGRESS_SET(0.75);
					unlink(REBOOT_DELAY_FILE);
					issueBussinessCount++;
					break;
				case NOW_SETTING:
					//printf("[%s %d]\n", __func__, __LINE__);
					boaWrite(wp, E8CLIENT_ITMS_CONFIG_ING_4STAGEDIAG_4);
					mib_get(CWMP_USERINFO_SERV_NUM_DONE, &i);

					if(serviceNum > 0)
					{
					//	printf("[%s %d]\n", __func__, __LINE__);
						NPROGRESS_SET(0.76 + 0.21 * i / serviceNum);
					}
					else
					{
					//	printf("[%s %d]\n", __func__, __LINE__);
						NPROGRESS_SET(0.76);// ITMS not set this mib now
					}

					issueBussinessCount++;
					break;
				case SET_SUCCESS:
					mib_get(CWMP_USERINFO_SERV_NAME_DONE, serviceName);

					memset(doneServiceName, 0, sizeof(doneServiceName));
					if( strstr(serviceName, "INTERNET") )
					{
						sprintf(doneServiceName, "宽带");
					}
					if( strstr(serviceName, WAN_VOIP_VOICE_NAME) )
					{
						strcat(doneServiceName, "、语音");
					}
					if( strstr(serviceName, "ITV") )
					{
						strcat(doneServiceName, "、ITV");
					}

					if(doneServiceName[0] != 0)
					{
						memset(buf, 0, sizeof(buf));
						sprintf(buf, E8CLIENT_INTERENT_IPTV_VOICE_SUCC_4STAGEDIAG_4, doneServiceName);
						E8CLIENT_4STAGEDIAG_REG_SUCC(buf);
					}
					else
					{
						E8CLIENT_4STAGEDIAG_REG_SUCC(E8CLIENT_ITMS_CONFIG_SUCC_4STAGEDIAG_4);
					}
						//printf("[%s %d]\n", __func__, __LINE__);
						NPROGRESS_SET(1.0);
						unlink(REBOOT_DELAY_FILE);
						break;
					}//end of switch
			}// end of else
		}// if (regStatus == 0)
		else if (regStatus == 2 && regResult == 99)
		{//invalid LOID
			unsigned int int_process = (unsigned int)(inProcess*100);
			E8CLIENT_4STAGEDIAG_REG_FAIL_TO_RETURN(E8CLIENT_ITMS_INVALID_LOID_4STAGEDIAG, E8CLIENT_ITMS_INVALID_LOID_MSG_4STAGEDIAG);
			NPROGRESS_HIDE();
			return 0;
		}
		else if (regStatus == 5)
		{//no need register to ITMS
			//printf("[%s %d]\n", __func__, __LINE__);
			E8CLIENT_4STAGEDIAG_REG_SUCC(E8CLIENT_REPEAT_REG_4STAGEDIAG_4);
			NPROGRESS_SET(1.0);
			return 0;
		}
		else if(regStatus <= 4)
		{//send ping to tr069 server
			if(regITMSCount<12)
			{
				boaWrite(wp, E8CLIENT_ITMS_CONNECT_4STAGEDIAG_3);
				SaveLOIDReg();
				NPROGRESS_SET(0.6);
				regITMSCount++;
				return 0;
			}
			else
			{
				printf("[%s %d]:ping start\n", __func__, __LINE__);

				if( pingAgain==0 )
				{
					char ITMS_Server[256];
					char acsurl[256];

					va_cmd("/bin/killall", 1, 1, "ping");
					unlink("/tmp/pon_diag_ping.tmp");

					memset(ITMS_Server, 0, 256);
					memset(acsurl, 0, 256);
					if(!mib_get(CWMP_ACS_URL, (void*)acsurl))
					{
						fprintf(stderr, "Get mib value CWMP_ACS_URL failed!\n");
					}
					else
					{
						set_endpoint(ITMS_Server, acsurl);
						memset(buf, 0, sizeof(buf));
						sprintf(buf, "/bin/ping -c 3 -w 6 %s -I nas0_0 > /tmp/pon_diag_ping.tmp\n", ITMS_Server);
						va_cmd("/bin/sh", 2, 0, "-c", buf);
						printf("buf is : %s \n" , buf);
					}
					pingAgain++;
				}

				unlink("/tmp/pingpid.tmp");
				system("/bin/pidof ping > /tmp/pingpid.tmp\n");

				fp = fopen("/tmp/pingpid.tmp", "r");
				if(fp)
				{
					fscanf(fp, "%d", &pingpid);
					if(pingpid)
					{//ping is still running
						boaWrite(wp, E8CLIENT_ITMS_PING_4STAGEDIAG_3);
						//E8CLIENT_4STAGEDIAG_REG_FAIL_TO_RETURN(OLT_ACCOUNT_REG_FAIL_MSG, OLT_ACCOUNT_REG_AGAIN);
						NPROGRESS_SET(0.72);//have send ping
						fclose(fp);
						return 0;
					}
					fclose(fp);
				}

				fp = fopen("/tmp/pon_diag_ping.tmp", "r");
				if (fp)
				{
					while (fgets(buf, sizeof(buf), fp))
					{
						if ( strstr(buf, "ttl=") )
						{
							ping_succ = 1;
							break;
						}
					}

					if(ping_succ)
					{
						NPROGRESS_SET(0.74);
						E8CLIENT_4STAGEDIAG_REG_FAIL_TO_RETURN(E8CLIENT_ITMS_PING_SUCC_4STAGEDIAG_3, E8CLIENT_ITMS_CALL_FOR_OK_AND_TRY_AGAIN);
					}
					else
					{
						//printf("[%s %d]\n", __func__, __LINE__);
						NPROGRESS_SET(0.73);
						E8CLIENT_4STAGEDIAG_REG_FAIL_TO_RETURN(E8CLIENT_ITMS_PING_FAIL_4STAGEDIAG_3, E8CLIENT_ITMS_CALL_FOR_OK);
					}
					fclose(fp);
				}
				else // no such file , dns query itms domain name fail
				{
					//printf("[%s %d]\n", __func__, __LINE__);
					NPROGRESS_SET(0.73);
                    E8CLIENT_4STAGEDIAG_REG_FAIL_TO_RETURN(E8CLIENT_ITMS_PING_FAIL_4STAGEDIAG_3, E8CLIENT_ITMS_CALL_FOR_OK);
				}
			}// end of else
		}// end of else if(regStatus <= 4)
	} // end of //ITMS responsed
	return 0;
}
#endif //#ifdef CONFIG_USER_RTK_ONUCOMM

int UserAccountRegResult(int eid, request * wp, int argc, char **argv)
{
	static int rebootTime = 0;
#if defined(CONFIG_CMCC) || defined(CONFIG_CU) || defined(CONFIG_CU)
	static int passRegFailTimes = 0;  //for pass reg
	static long last_time = 0;  
#endif
	int i, total, ret;
	MIB_CE_ATM_VC_T entry;
	struct in_addr inAddr;
	FILE *fp;
	char buf[256], serviceName[32];
	unsigned int regStatus;
	unsigned int regLimit;
	unsigned int regTimes;
	unsigned char regInformStatus;
	unsigned int regResult;
	unsigned char needReboot;
	unsigned char enable4StageDiag;
	int serviceNum;
	unsigned char cwmp_status = CWMP_STATUS_NOT_CONNECTED;
	/* Set defautl to JSU becuase mib_get may fail before reboot. */
	/* To prevent show progress bar with FW for JSU. */
	unsigned char reg_type = DEV_REG_TYPE_JSU;
#ifdef CONFIG_RTK_OMCI_V1
	PON_OMCI_CMD_T msg;
#endif
#if defined(CONFIG_GPON_FEATURE) || defined(CONFIG_EPON_FEATURE)
	unsigned int pon_mode=0, pon_state=0;
	mib_get(MIB_PON_MODE, &pon_mode);
#endif

#if defined(CONFIG_GPON_FEATURE) || defined(CONFIG_EPON_FEATURE)
	/* if enable 4 stage diag, call UserAccountRegResultFor4StageDiag */
	mib_get(PROVINCE_PONREG_4STAGEDIAG, &enable4StageDiag);
	if(enable4StageDiag)
	{
		#ifdef CONFIG_USER_RTK_ONUCOMM
		ret = UserAccountRegResultFor4StageDiagONUComm(eid, wp, argc, argv);
		#else
		ret = UserAccountRegResultFor4StageDiag(eid, wp, argc, argv);
		#endif
		return ret;
	}
#endif
	mib_get(PROVINCE_DEV_REG_TYPE, &reg_type);
#if defined(CONFIG_GPON_FEATURE) || defined(CONFIG_EPON_FEATURE)
	if(reg_type == DEV_REG_TYPE_JSU)
		return UserAccountRegResultSimple(eid, wp, argc, argv);
#endif

	mib_get(CWMP_USERINFO_STATUS, &regStatus);
	mib_get(CWMP_USERINFO_LIMIT, &regLimit);
	mib_get(CWMP_USERINFO_TIMES, &regTimes);
	mib_get(CWMP_REG_INFORM_STATUS, &regInformStatus);
	mib_get(CWMP_USERINFO_RESULT, &regResult);
	mib_get(CWMP_USERINFO_NEED_REBOOT, &needReboot);
	mib_get(CWMP_USERINFO_SERV_NUM, &serviceNum);
	mib_get(RS_CWMP_STATUS, &cwmp_status);

#if defined(CONFIG_CMCC) || defined(CONFIG_CU) || defined(CONFIG_CU)
	if(passRegFailTimes>2 && getSYSInfoTimer()-last_time<=180)
	{
			USER_REG_HAVE_FAIL(E8CLIENT_ACCOUNT_REG_FAIL1_2_3_OVER);
			NPROGRESS_HIDE();
			return 0;
	}
	
	if(getSYSInfoTimer()-last_time>180)
		passRegFailTimes = 0;
#endif
	if (regInformStatus != CWMP_REG_RESPONSED) {	//ACS not returned result

		total = mib_chain_total(MIB_ATM_VC_TBL);

		for (i = 0; i < total; i++) {
			if (mib_chain_get(MIB_ATM_VC_TBL, i, &entry) == 0)
				continue;

			if ((entry.applicationtype & X_CT_SRV_TR069) &&
					ifGetName(entry.ifIndex, buf, sizeof(buf)) &&
					getInFlags(buf, &ret) &&
					(ret & IFF_UP) &&
					getInAddr(buf, IP_ADDR, &inAddr))
				break;
		}

#if defined(CONFIG_GPON_FEATURE) || defined(CONFIG_EPON_FEATURE)
		if(pon_mode == 1)
		{
#ifdef CONFIG_RTK_OMCI_V1
			/* During deactivate, the IP may not be cleared in a small period of time.*/
			/* So check gpon state first. */
			memset(&msg, 0, sizeof(msg));
			msg.cmd = PON_OMCI_CMD_LOIDAUTH_GET_RSP;
			ret = omci_SendCmdAndGet(&msg);

			if (ret != GOS_OK || (msg.state != 0 && msg.state != 1)) {
				USER_REG_HAVE_OK(OLT_ACCOUNT_REG_FAIL);
				NPROGRESS_DONE();
				return 0;
			}
			pon_state = msg.state;
#endif
#if defined(CONFIG_CMCC) || defined(CONFIG_CU) && defined(CONFIG_E8B) && defined(CONFIG_GPON_FEATURE)
			if(getGponONUState()==GPON_STATE_O5){
				pon_state = 1;
				printf("%s:%d pon_state is O5\n", __FUNCTION__, __LINE__);
			}
			else{
				pon_state = 0;
				printf("%s:%d pon_state is %d\n", __FUNCTION__, __LINE__, getGponONUState());
			}
#endif
		}
		else if(pon_mode == 2)
		{
#ifdef CONFIG_EPON_FEATURE
			rtk_epon_llid_entry_t  llidEntry;

			memset(&llidEntry, 0, sizeof(rtk_epon_llid_entry_t));
			llidEntry.llidIdx = 0;
#ifdef CONFIG_RTK_L34_ENABLE
			rtk_rg_epon_llid_entry_get(&llidEntry);
#else
			rtk_epon_llid_entry_get(&llidEntry);
#endif
			
			if(llidEntry.valid)
			{
				ret = epon_getAuthState(llidEntry.llidIdx);

				switch(ret)
				{
				case 2:	// not complete
					pon_state = 0;
					break;
				case 1:	// OK
					pon_state = 1;
					break;
				default:	// fail
					pon_state = 0;
					break;
				}
			}
			else
				pon_state = 0;	// not complete
#endif
		}
#endif

		if (ctregcount >= 48)
		{
			/* 240 seconds, timeout */
			if (i == total) {
				/* The interface for TR069 is not ready */
#if defined(CONFIG_GPON_FEATURE) || defined(CONFIG_EPON_FEATURE)
				if(pon_state == 1) // already register olt
				{
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
					USER_REG_HAVE_FAIL(E8CLIENT_ITMS_NOT_REACHABLE);
#else
					USER_REG_HAVE_OK(E8CLIENT_ITMS_NOT_REACHABLE);
#endif
					NPROGRESS_HIDE();
				}
				else
				{
#endif
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
					USER_REG_HAVE_FAIL(OLT_ACCOUNT_REG_FAIL);
#else
					USER_REG_HAVE_OK(OLT_ACCOUNT_REG_FAIL);
#endif
					NPROGRESS_HIDE();
#if defined(CONFIG_GPON_FEATURE) || defined(CONFIG_EPON_FEATURE)
				}
#endif
			} else {
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
				passRegFailTimes++;
				last_time = getSYSInfoTimer(); 
				USER_REG_HAVE_FAIL(E8CLIENT_ITMS_NOT_REACHABLE);
#else
				USER_REG_HAVE_OK(E8CLIENT_ITMS_NOT_REACHABLE);
#endif
				NPROGRESS_HIDE();
#if defined(CONFIG_CMCC) || defined(CONFIG_CU) || defined(CONFIG_CU)
				return 0;	
#endif
			}
			NPROGRESS_DONE();
		} else {
			ctregcount++;
#if defined(CONFIG_GPON_FEATURE) || defined(CONFIG_EPON_FEATURE)
			if (pon_state == 0) {
				USER_REG_NO_OK(OLT_ACCOUNT_REG_ING);
				NPROGRESS_SET(0.2);
				return 0;
			}

#endif

			if (i == total) {
				/* The interface for TR069 is not ready */
#if defined(CONFIG_GPON_FEATURE) || defined(CONFIG_EPON_FEATURE)
				if(pon_state == 1)
				{
					USER_REG_NO_OK(OLT_ACCOUNT_REG_SUCC);
					SaveLOIDReg();
					NPROGRESS_SET(0.3);
				}
#else
				USER_REG_NO_OK(E8CLIENT_ACCOUNT_REG);
				NPROGRESS_SET(0.3);
#endif
			} else {
				USER_REG_NO_OK(E8CLIENT_TR069_READY);
				SaveLOIDReg();
				NPROGRESS_SET(0.4);
			}
		}
/*star:20080827 END*/
	} else {
		if(reg_type == DEV_REG_TYPE_AH)
		{
			ctregcount++;
			if(ctregcount > 120)
			{
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
				USER_REG_HAVE_FAIL(E8CLIENT_ACCOUNT_REMOTE_SETTING_FAIL);
#else
				USER_REG_HAVE_OK(E8CLIENT_ACCOUNT_REMOTE_SETTING_FAIL);
#endif
				NPROGRESS_HIDE();
				return 0;
			}
		}
		if (regStatus == 0) {
REG_RESULT_RECHECK:
			switch (regResult) {
			case NO_SET:
				USER_REG_NO_OK(E8CLIENT_ACCOUNT_REG_SUCC);
				NPROGRESS_SET(0.5);
				unlink(REBOOT_DELAY_FILE);
				break;
			case NOW_SETTING:
				mib_get(CWMP_USERINFO_SERV_NAME, serviceName);
				if (!strstr(serviceName, "IPTV") &&
					!strstr(serviceName, "INTERNET") &&
					!strstr(serviceName, "VOIP")
				   ) {
					USER_REG_NO_OK(E8CLIENT_ACCOUNT_REMOTE_SETTING0);
				} else {
					sprintf(buf, E8CLIENT_ACCOUNT_REMOTE_SETTING1, serviceName);
					USER_REG_NO_OK(buf);
				}
				mib_get(CWMP_USERINFO_SERV_NUM_DONE, &i);

				if(serviceNum > 0)
				{
					if(i>0)
					{
						NPROGRESS_SET(0.6 + 0.4 * (i-1) / serviceNum);
					}
					else
					{
						NPROGRESS_SET(0.6);
					}
				}
				else
				{
					NPROGRESS_SET(0.6);
				}
				break;
			case SET_SUCCESS:
#if defined(CONFIG_CMCC) || defined(CONFIG_CU) || defined(CONFIG_CU)
				passRegFailTimes=0;
#endif
				if(cwmp_status == CWMP_STATUS_CONNETED)
				{
					regResult = NOW_SETTING;
					goto REG_RESULT_RECHECK;
				}
				if (needReboot) {
					if(serviceNum)
					{
						sprintf(buf, E8CLIENT_ACCOUNT_REMOTE_SETTING_REBOOT, serviceName, serviceNum);
						USER_REG_HAVE_OK(buf);
					}
					else
						USER_REG_HAVE_OK(E8CLIENT_ACCOUNT_REMOTE_SETTING_REBOOT_NO_SERV);
					unlink(REBOOT_DELAY_FILE);
				} else {
					if(serviceNum)
					{
						sprintf(buf, E8CLIENT_ACCOUNT_REMOTE_SETTING_SUCCESS, serviceName, serviceNum);
						USER_REG_HAVE_OK(buf);
					}
					else
						USER_REG_HAVE_OK(E8CLIENT_ACCOUNT_REMOTE_SETTING_SUCCESS_NO_SERV);
					unlink(REBOOT_DELAY_FILE);
				}
				NPROGRESS_SET(1.0);
				break;
			case SET_FAULT:
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
				USER_REG_HAVE_FAIL(E8CLIENT_ACCOUNT_REMOTE_SETTING_FAIL);
#else
				USER_REG_HAVE_OK(E8CLIENT_ACCOUNT_REMOTE_SETTING_FAIL);
#endif
				NPROGRESS_DONE();
				break;
			}
		} 
#ifdef CONFIG_CU
		else if (regStatus == 1) {
			if (regTimes < regLimit) {
				sprintf(buf, E8CLIENT_ACCOUNT_REG_FAIL1, regLimit-regTimes);
				USER_REG_HAVE_FAIL(buf);
				NPROGRESS_DONE();
			} else {
				USER_REG_HAVE_FAIL(E8CLIENT_ACCOUNT_REG_FAIL1_OVER);
				NPROGRESS_DONE();
			}
		}else if (regStatus == 2) {
			if (regTimes < regLimit) {
				sprintf(buf, E8CLIENT_ACCOUNT_REG_FAIL2, regLimit-regTimes);
				USER_REG_HAVE_FAIL(buf);
				NPROGRESS_DONE();
			} else {
				USER_REG_HAVE_FAIL(E8CLIENT_ACCOUNT_REG_FAIL2_OVER);
				NPROGRESS_DONE();
			}
		}else if (regStatus == 3) {
			if (regTimes < regLimit) {
				sprintf(buf, E8CLIENT_ACCOUNT_REG_FAIL3, regLimit-regTimes);
				USER_REG_HAVE_FAIL(buf);
				NPROGRESS_DONE();
			} else {
				USER_REG_HAVE_FAIL(E8CLIENT_ACCOUNT_REG_FAIL3_OVER);
				NPROGRESS_DONE();
			}
		}
#else
		else if (regStatus >= 1 && regStatus <= 3) {
			if (regTimes < regLimit) {
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
				USER_REG_HAVE_FAIL(E8CLIENT_ACCOUNT_REG_FAIL1_2_3);
#else
				USER_REG_HAVE_OK(E8CLIENT_ACCOUNT_REG_FAIL1_2_3);
#endif
				NPROGRESS_DONE();
			} else {
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
				USER_REG_HAVE_FAIL(E8CLIENT_ACCOUNT_REG_FAIL1_2_3_OVER);
#else
				USER_REG_HAVE_OK(E8CLIENT_ACCOUNT_REG_FAIL1_2_3_OVER);
#endif
				NPROGRESS_DONE();
			}
		} 
#endif
		else if (regStatus == 4) {
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
			USER_REG_HAVE_FAIL(E8CLIENT_ACCOUNT_REG_FAIL4);
#else
			USER_REG_HAVE_OK(E8CLIENT_ACCOUNT_REG_FAIL4);
#endif
			NPROGRESS_DONE();
		} else if (regStatus == 5) {
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
			USER_REG_HAVE_FAIL(E8CLIENT_ACCOUNT_REG_FAIL5);
#else
			USER_REG_HAVE_OK(E8CLIENT_ACCOUNT_REG_FAIL5);
#endif
			NPROGRESS_DONE();
		} else {
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
			USER_REG_HAVE_FAIL(E8CLIENT_ACCOUNT_REG_FAIL1_2_3_OVER);
#else
			USER_REG_HAVE_OK(E8CLIENT_ACCOUNT_REG_FAIL1_2_3_OVER);
#endif
			NPROGRESS_DONE();
		}
	}

	return 0;
}

void formUserReg(request * wp, char *path, char *query)
{
	char *loid, *s;
	unsigned char vChar;
	unsigned char enable4StageDiag;
	unsigned int regLimit;
	unsigned int regTimes;
	unsigned int lineno;
	pid_t cwmp_pid;
	int num_done;
	unsigned int value;
	char *strReset;
#if defined(CONFIG_CMCC) || defined(CONFIG_CU) || defined(CONFIG_CU)
	char *webpassword;
#else
	char webpassword[256]={0}, *reset;
#endif
	char mibpassword[MAX_NAME_LEN];
#if defined(CONFIG_GPON_FEATURE)
	int i=0;
#endif
#if defined(CONFIG_EPON_FEATURE)
	int index, entryNum;
	char cmdBuf[64] = {0};
#endif
	int sleep_time = 3;
#if defined(CONFIG_GPON_FEATURE) || defined(CONFIG_EPON_FEATURE)
	unsigned int pon_mode;
	mib_get(MIB_PON_MODE, &pon_mode);
#endif
	unsigned char reg_type;
	unsigned char password_hex[MAX_NAME_LEN]={0};
#if defined(CONFIG_CMCC) || defined(CONFIG_CU) || defined(CONFIG_CU)
	unsigned char gui_passauth_enable = 1;
	char *password;
#else
	char password[256]={0}, *usereg_encode;
#endif

	_TRACE_CALL;
	mib_get(PROVINCE_DEV_REG_TYPE, &reg_type);
	mib_get(CWMP_USERINFO_LIMIT, &regLimit);
	mib_get(CWMP_USERINFO_TIMES, &regTimes);
	if (regTimes >= regLimit) {
		vChar = CWMP_REG_IDLE;
		mib_set(CWMP_REG_INFORM_STATUS, &vChar);
		goto FINISH;
	}

	//20180103: add buttorn on the webpage of register page
		int temp = mib_get(PROVINCE_SICHUAN_FUNCTION_MASK,&value);
		if((value & PROVINCE_SICHUAN_RESETFACTORY_TEST) != 0)
		{
			//add reset buttorn in the web of register
			strReset = boaGetVar(wp, "factoryreset", "");
#if defined(CONFIG_CMCC) || defined(CONFIG_CU) || defined(CONFIG_CU)
			webpassword = boaGetVar(wp, "resetpassword", ""); //password from web
#else
			reset = boaGetVar(wp, "reset_encode", ""); //password from web
			data_base64decode(reset, webpassword);
#endif
			mib_get(PROVINCE_SICHUAN_RESET_PASSWORD, mibpassword); 
#ifdef EMBED
			if(strReset[0] && webpassword[0] && (strcmp(webpassword, mibpassword) == 0)) {
				boaHeader(wp);
			//--- Add timer countdown
				boaWrite(wp, "<head><META http-equiv=content-type content=\"text/html; charset=gbk\"><style>\n" \
				"#cntdwn{ border-color: white; border-width: 0px; font-size: 12pt; color: red; text-align:left; font-weight:bold; font-family: Courier;}\n" \
				"</style><script language=javascript>\n" \
				"var h = 70;\n" \
				"function stop() { clearTimeout(id); }\n"\
				"function start() { h--; if (h >= 0) { frm.time.value = h; frm.textname.value='设备重启中, 请稍候 ...'; id = setTimeout(\"start()\", 1000); }\n" \
				"if (h == 0) { top.location.href= \"/usereg.asp\" }}\n" \
				"</script></head>");
				boaWrite(wp,
				"<body bgcolor=white onLoad=\"start();\" onUnload=\"stop();\"><blockquote>" \
				"<form name=frm><b><font color=red><input type=text name=textname size=40 id=\"cntdwn\">\n" \
				"<input type=text name=time size=5 id=\"cntdwn\"></font></form></blockquote></body>" );
				//--- End of timer countdown
				boaFooter(wp);
				boaDone(wp, 200);
#ifdef CONFIG_MIDDLEWARE
			unsigned char vChar;
			mib_get(CWMP_TR069_ENABLE, (void*)&vChar);
			if ( (vChar == 0)||(vChar == 2) ) {
				if( (sendSetDefaultFlagMsg2MidProcess() == 0)&&(sendSetDefaultRetMsg2MidIntf() == 0) )
				{
					sleep(10);	//wait reboot command from middleware
				}
			}
#endif	//end of CONFIG_MIDDLEWARE
				reset_cs_to_default(2); //FactoryReset
#ifdef CONFIG_USER_RTK_OMD
				write_omd_reboot_log(TELECOM_WEB_REBOOT);
#endif
				cmd_reboot();	
				return; 
			}
			else if(strReset[0] && webpassword[0] && (strcmp(webpassword, mibpassword) != 0))
			{
				printf("Enter the wrong password!\n");
				ERR_MSG1("错误: 密码错误!", "/usereg.asp"); //ERROR:wrong password! redirect to usereg.asp
				return;
			}
#endif
		}
		
#ifdef STB_L2_FRAME_LOSS_RATE
		if((value & PROVINCE_SICHUAN_TERMINAL_INSPECTION) != 0) //For sichuan terminal inspection
		{
			char *start;
			key_t key = ftok("/bin/stbL2Com", 100);
			int msgid = msgget(key, 0);
			stbL2Msg_t l2Msg;
			
			start = boaGetVar(wp, "stbTestStart", "");
			if(!strncmp(start, "1", 1))
			{
				unlink("/tmp/stbL2Diag.tmp");
				memset(&l2Msg, 0, sizeof(stbL2Msg_t));
				l2Msg.msgType = L2LOSSTESTMSGSTARTFROMWEB;
				if(msgsnd(msgid, &l2Msg, sizeof(stbL2Msg_t)-sizeof(long int), 0)==-1)
					perror("msgsnd:");
				printf("%s %d: msg send success!\n", __FUNCTION__,__LINE__);
				boaRedirect(wp, "/terminal_inspec.asp");
				return;
			}
		}
#endif

	loid = boaGetVar(wp, "loid", "");
	printf("loid is %s\n", loid);
	if (loid[0]) {
		mib_set(MIB_LOID, loid);
		if(reg_type != DEV_REG_TYPE_DEFAULT)
			mib_set(MIB_LOID_OLD,loid);
		#ifdef CONFIG_USER_RTK_ONUCOMM
		//init_onucomm_sock();
		onucomm_pon_loid(loid);
		//close_onucomm_sock();
		#endif
	}
#if defined(CONFIG_CMCC) || defined(CONFIG_CU) || defined(CONFIG_CU)
	else{
		mib_set(MIB_LOID, loid);
		if(reg_type != DEV_REG_TYPE_DEFAULT)
			mib_set(MIB_LOID_OLD,loid);
	}
#else
	else {
		fprintf(stderr, "get LOID error!\n");
		goto check_err;
	}
#endif

#if defined(CONFIG_CMCC) || defined(CONFIG_CU) || defined(CONFIG_CU)
	password = boaGetVar(wp, "password", "");
#else
	usereg_encode = boaGetVar(wp, "usereg_encode", "");
	data_base64decode(usereg_encode, password);
#endif
	printf("password is %s\n", password);
		mib_set(MIB_LOID_PASSWD, password);
		if(reg_type != DEV_REG_TYPE_DEFAULT)
			mib_set(MIB_LOID_PASSWD_OLD,password);

#if defined(CONFIG_CMCC) || defined(CONFIG_CU) || defined(CONFIG_CU)		
		mib_set(CWMP_GUI_PASSWORD_ENABLE, &gui_passauth_enable);
#endif

/*xl_yue:20081225 record the inform status to avoid acs responses twice for only once informing*/
	vChar = CWMP_REG_REQUESTED;
	mib_set(CWMP_REG_INFORM_STATUS, &vChar);
	/* reset to zero */
	num_done = 0;
	mib_set(CWMP_USERINFO_SERV_NUM_DONE, &num_done);
	mib_set(CWMP_USERINFO_SERV_NAME_DONE, "");
/*xl_yue:20081225 END*/

#if defined(CONFIG_GPON_FEATURE)
	if(pon_mode == 1)
	{
	// Deactive GPON
	// do not use rtk_rg_gpon_deActivate() becuase it does not send link down event.

		system("diag gpon reg-set page 1 offset 0x10 value 0x1");

		system("omcicli mib reset");

#if defined(CONFIG_CMCC) || defined(CONFIG_CU) || defined(CONFIG_CU)
		if(loid[0])
#endif
		{
			if (password[0]) {
				va_cmd("/bin/omcicli", 4, 1, "set", "loid", loid, password);
			} else {
				va_cmd("/bin/omcicli", 3, 1, "set", "loid", loid);
			}
		}

#if defined(CONFIG_CMCC) || defined(CONFIG_CU) && defined(CONFIG_PON_LINKCHANGE_EVENT)
		//because we deactivate the gpon
		//we need CONFIG_CMCC_OSGIMANAGE=y
		system("/bin/diag gpon deactivate");
		if (password[0]) {
			//diag gpon set password xxxx
			formatPloamPasswordToHex(password, password_hex);
			va_cmd("/sbin/diag", 4, 1, "gpon", "set", "password-hex", password_hex);
		}
		else {
			va_cmd("/sbin/diag", 4, 1, "gpon", "set", "password", "0000000000");
		}
		system("/bin/diag gpon activate init-state o1");
#endif

		while(i++ < 10)
			system("diag gpon reg-set page 1 offset 0x10 value 0x3");
	}
#endif
#if defined(CONFIG_EPON_FEATURE)
	if(pon_mode == 2)
	{
		/* Martin ZHU add: release all wan connection IP */
		va_cmd("/bin/ethctl", 2, 1, "enable_nas0_wan", "0");

		va_cmd("/bin/ethctl", 2, 1, "enable_nas0_wan", "1");

#if defined(CONFIG_RTK_L34_ENABLE) && !defined(CONFIG_RG_G3_SERIES)
		rtk_rg_epon_llidEntryNum_get(&entryNum);
#else
		rtk_epon_llidEntryNum_get(&entryNum);
#endif

		/* Martin ZHU: 2016-3-24  */
		mib_get(PROVINCE_PONREG_4STAGEDIAG, (void *) &enable4StageDiag);
		for (index = 0; index < entryNum; index++) {
			if(enable4StageDiag)
			{
				system("diag epon reset mib-counter");
			}

			memset(cmdBuf, 0, sizeof(cmdBuf));

			if (password[0]) {
				sprintf(cmdBuf, "/bin/oamcli set ctc loid %d %s %s\n",index, loid, password);
			} else {
				sprintf(cmdBuf, "/bin/oamcli set ctc loid %d %s\n",index, loid);
			}
			system(cmdBuf);

			/* 2016-04-29 siyuan: oam needs to register again using new loid and password */
			sprintf(cmdBuf,"/bin/oamcli trigger register %d", index);
			system(cmdBuf);
		}
	}
#endif

	if(reg_type == DEV_REG_TYPE_JSU)
	{
		int result = NOW_SETTING;
		int status = 99;
		mib_set(CWMP_USERINFO_RESULT, &result);
		mib_set(CWMP_USERINFO_STATUS, &status);
		unlink("/var/inform_status");
	}

#ifdef CONFIG_MIDDLEWARE
	mib_get(CWMP_TR069_ENABLE,(void *)&vChar);
	if(!vChar)
	{	// Martin_ZHU:send CTEVENT_BIND to MidProcess
		vChar = CTEVENT_BIND;
		sendInformEventMsg2MidProcess( vChar );
	}else
#endif
	{
		{
			pid_t tr069_pid;

			// send signal to tr069
			tr069_pid = read_pid("/var/run/cwmp.pid");
			if ( tr069_pid > 0){
#ifdef CONFIG_MIDDLEWARE
				vChar = CTEVENT_BIND;
				mib_set(MIB_MIDWARE_INFORM_EVENT,(void*)&vChar);
				kill(tr069_pid, SIGUSR1);	//SIGUSR2 is used by midware
#else
				kill(tr069_pid, SIGUSR2);
#endif
			}
		}
	}

	// Purposes:
	// 1. Wait for PON driver ready.
	// 2. Wait for old IP release.
	while(sleep_time)
		sleep_time = sleep(sleep_time);

/*star:20080827 START add for reg timeout*/
	ctregcount = 0;
/*star:20080827 END*/

/*Martin ZHU 2016-03-22 add for ping diag timeout*/
	pingCount = 0;
/*Martin ZHU 2016-03-22  END*/
#ifdef CONFIG_USER_RTK_ONUCOMM
	g_check_eth_link = 1;
#endif // CONFIG_USER_RTK_ONUCOMM

FINISH:
#ifdef COMMIT_IMMEDIATELY
#if defined(CONFIG_CMCC) || defined(CONFIG_CU) || defined(CONFIG_CU)
	SaveLOIDReg(); //save LOID and PASSWORD directly, SaveLOIDReg() already has Commit() function
#else
	Commit();
#endif
#endif

	//web redirect
	s = boaGetVar(wp, "submit-url", "");
	if(s && *s)
		boaRedirectTemp(wp, s);

check_err:
	_TRACE_LEAVEL;
}

int UserRegMsg(int eid, request * wp, int argc, char **argv)
{
	int nBytesSent = 0;
	char line[128]={0};
	char title[64]={0};
#if defined(CONFIG_GPON_FEATURE) || defined(CONFIG_EPON_FEATURE)
	unsigned int pon_mode;
#endif

	strcpy(line, USERINFO_LINE);

#if defined(CONFIG_GPON_FEATURE) || defined(CONFIG_EPON_FEATURE)
	mib_get(MIB_PON_MODE, &pon_mode);
	if (pon_mode == GPON_MODE) {
		strcat(line, "G");
		strcat(title,"<font color='red'><h1>GPON 上行 E8-C 终端</h1></font><br>");
	} else if (pon_mode == EPON_MODE) {
		strcat(line, "E");
		strcat(title,"<font color='red'><h1>EPON 上行 E8-C 终端</h1></font><br>");
	}
#else
	strcat(line, USERINFO_LINE_PORT);
	strcat(title, "<br><br><br><br>"); // we remove usereg.asp 4 <br> and copy to here
#endif

	nBytesSent += boaWrite(wp, "%s%s%s%s", title,"请插紧“", line,
					"”接口的" USERINFO_LINE "，检查并确认"
					USERINFO_LINE_LED "状态<br>"
					"准确输入“逻辑ID”和“密码”，点击“确定”进行注册<br>"
					"在注册及业务下发过程中（10分钟内）不要断电、不要拨"USERINFO_LINE"<br>"
					"本注册功能仅用于新设备的认证及业务下发，已正常在用设备请勿重新注册<br>");

	return nBytesSent;
}

int UserRegMsgPassword(int eid, request * wp, int argc, char **argv)
{
	int nBytesSent = 0;
	unsigned char reg_type = DEV_REG_TYPE_DEFAULT;
	if(!mib_get(PROVINCE_DEV_REG_TYPE, &reg_type))
    {
		printf("mib_get failed(PROVINCE_DEV_REG_TYPE)\n");
	}
	if(reg_type == DEV_REG_TYPE_GUD)
		nBytesSent += boaWrite(wp, "<tr nowrap><td>E8-C终端密码为空，不能填写</td></tr>");
	return nBytesSent;
}

void formUserReg_inside_menu(request * wp, char *path, char *query)
{
	return formUserReg(wp,path,query);
}

#if defined(CONFIG_CMCC) || defined(CONFIG_CU) || defined(CONFIG_CU)
int UserInsideRegLoidPage(int eid, request * wp, int argc, char **argv)
{
	int registed=1;
	int nBytesSent = 0;
	unsigned char functype = 0;
	unsigned int regStatus = 99;
	unsigned int regResult = 99;
	unsigned char gui_passauth_enable = 0;

	mib_get(PROVINCE_MISCFUNC_TYPE,&functype);
	mib_get(CWMP_USERINFO_STATUS, &regStatus);
	mib_get(CWMP_GUI_PASSWORD_ENABLE, &gui_passauth_enable);
	mib_get(CWMP_USERINFO_RESULT, &regResult);

	if(regResult != 0 && regResult != 1)
		registed = 0;
	if(regStatus != 0 && regStatus != 5)
		registed = 0;

	printf("regsited : %d \n" , registed);
	if(functype != 1) // anhui should grayout the field if registed
		registed = 0;

	printf("regsited : %d , func:%d \n" , registed, functype);

	nBytesSent += boaWrite(wp, "<table cellspacing=\"0\" cellpadding=\"0\"  border=\"0\">"
				"<tr nowrap><td width=10>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</td>"
				"<td width=\"55%\">LOID：</td>"
				"<td colspan=\"2\"><input size=\"10\" style=\"WIDTH: 150px\" type=\"text\" name=\"loid\" id=\"loid\" maxlength=\"27\"></td>"
				"<tr nowrap><td width=10>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</td>"
				"<td width=\"55%\">Password:</td>"
				"<td colspan=\"2\"><input size=\"10\" style=\"WIDTH: 150px\" type=\"password\" name=\"password\" id=\"password\" maxlength=\"27\"></td>"
				"</table>"
				,registed?"readonly":"", registed?"readonly":"");

	nBytesSent += boaWrite(wp,"<br><table border=\"0\" cellpadding=\"1\" cellspacing=\"0\"></table>"
				"<br><br><br><br><div class=\"child\"><tr><center>"
				"<td align=\"center\"><input class=\"btnsaveup\" type=\"submit\" id=\"regbutton\" name=\"regbutton\" value=\"认证\"  %s>&nbsp;&nbsp;</td>"	
				"<td id=\"reset\" align=\"center\"><input class=\"btnsaveup2\" type=\"button\" value=\"取消\" onClick=\"reset_loid();\"  %s></td> &nbsp;&nbsp;&nbsp;"
				"</tr></center></div>",registed?"disabled":"",registed?"disabled":"");

	return nBytesSent;
}
#endif

int UserInsideRegPage(int eid, request * wp, int argc, char **argv)
{
#if defined(CONFIG_CMCC) || defined(CONFIG_CU) || defined(CONFIG_CU)
	int registed=1;
	int nBytesSent = 0;
	unsigned char functype = 0;
	unsigned int regStatus = 99;
	unsigned int regResult = 99;
	unsigned char gui_passauth_enable = 0;

	mib_get(PROVINCE_MISCFUNC_TYPE,&functype);
	mib_get(CWMP_USERINFO_STATUS, &regStatus);
	mib_get(CWMP_GUI_PASSWORD_ENABLE, &gui_passauth_enable);
	mib_get(CWMP_USERINFO_RESULT, &regResult);

	if(regResult != 0 && regResult != 1)
		registed = 0;
	if(regStatus != 0 && regStatus != 5)
		registed = 0;

	printf("regsited : %d \n" , registed);
	if(functype != 1) // anhui should grayout the field if registed
		registed = 0;

	printf("regsited : %d , func:%d \n" , registed,functype);
/*	if (1==gui_passauth_enable)
	{*/
		nBytesSent += boaWrite(wp, "<table cellspacing=\"0\" cellpadding=\"0\"  border=\"0\">"
				"<tr nowrap style=\"display:none\"><td>逻辑 ID：</td><td ><input type=\"text\" id=\"loid\" name=\"loid\" maxlength=\"24\" size=\"24\" style=\"width:150px \" %s></td></tr><br>"
				"<tr nowrap><br><td>Password:</td><td align\"center\">"
				"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"
				"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"
				"<input type=\"password\" id=\"password\" name=\"password\" maxlength=\"24\" size=\"24\" style=\"width:150px \" %s></td></tr>"
				"</table",registed?"readonly":"", registed?"readonly":"");
/*	}
	else
	{
		nBytesSent += boaWrite(wp, "<table cellspacing=\"0\" cellpadding=\"0\"  border=\"0\">"
				"<tr nowrap style=\"display:none\"><td>逻辑 ID：</td><td ><input type=\"text\" id=\"loid\" name=\"loid\" maxlength=\"24\" size=\"24\" style=\"width:150px \" %s></td></tr><br>"
				"<tr nowrap><td>Password</td><td><input type=\"password\" id=\"password\" name=\"password\" disabled=\"true\" maxlength=\"24\" size=\"24\" style=\"width:150px \" %s></td></tr>"
				"</table",registed?"readonly":"", registed?"readonly":"");

	}*/	
	nBytesSent += boaWrite(wp,"<br><table border=\"0\" cellpadding=\"1\" cellspacing=\"0\"></table>"
			"<br><br><br><br><div class=\"child\"><tr><center>"
			"<td align=\"center\"><input class=\"btnsaveup\" type=\"submit\" id=\"regbutton\" name=\"regbutton\" value=\"认证\"  %s>&nbsp;&nbsp;</td>"	
			"<td id=\"reset\" align=\"center\"><input class=\"btnsaveup2\"  type=\"button\" value=\"取消\" onClick=\"reset_loid();\"  %s></td> &nbsp;&nbsp;&nbsp;"
			"</tr></center></div>",registed?"disabled":"",registed?"disabled":"");

	return nBytesSent;
#else
	int registed=1;
	int nBytesSent = 0;
	unsigned char functype = 0;
	unsigned int regStatus = 99;
	unsigned int regResult = 99;

	mib_get(PROVINCE_MISCFUNC_TYPE,&functype);
	mib_get(CWMP_USERINFO_STATUS, &regStatus);
	mib_get(CWMP_USERINFO_RESULT, &regResult);

	if(regResult != 0 && regResult != 1)
		registed = 0;
	if(regStatus != 0 && regStatus != 5)
		registed = 0;

	printf("regsited : %d \n" , registed);
	if(functype != 1) // anhui should grayout the field if registed
		registed = 0;

	printf("regsited : %d , func:%d \n" , registed,functype);
	nBytesSent += boaWrite(wp, "<table cellspacing=\"0\" cellpadding=\"0\"  border=\"0\">"
			"<tr nowrap><td>逻辑 ID：</td><td ><input type=\"text\" id=\"loid\" name=\"loid\" maxlength=\"24\" size=\"24\" style=\"width:150px \" %s></td></tr><br>"
			"<tr nowrap><td>密码：</td><td><input type=\"password\" id=\"password\" name=\"password\" autocomplete=\"off\" maxlength=\"24\" size=\"24\" style=\"width:150px \" %s></td></tr>"
			"</table",registed?"readonly":"", registed?"readonly":"");
	nBytesSent += boaWrite(wp,"<table border=\"0\" cellpadding=\"1\" cellspacing=\"0\">"
			"<tr>"
			"<td><input type=\"submit\" id=\"regbutton\" name=\"regbutton\" value=\"确定\" style=\"width:80px; border-style:groove; font-weight:bold \" %s></td>"
			"<td id=\"reset\"><input type=\"button\" value=\"重置\" onClick=\"reset_loid();\" style=\"width:80px; border-style:groove; font-weight:bold \" %s></td>"
			"<td id=\"back\"><input type=\"button\" value=\"返回登录页面\" onClick=\"location.href='/admin/login.asp';\" style=\"border-style:groove; font-weight:bold \"></td>"
			"</tr>"
			"</table>",registed?"disabled":"",registed?"disabled":"");

	return nBytesSent;
#endif
}

int checkPopupRegPage(int eid, request * wp, int argc, char **argv)
{
	if(check_user_is_registered())
		return 0;

	return boaWrite(wp, "\tvar win = window.open('/usereg.asp');\n"
			"\twin.focus();\n");
}
#endif

#ifdef SUPPORT_LOID_BURNING
static void start_dev_register()
{
	char loid[30] = {0}, password[32] = {0};
	unsigned char vChar;
	unsigned char enable4StageDiag;
	pid_t cwmp_pid;
#if defined(CONFIG_GPON_FEATURE)
	int i=0;
#endif
#if defined(CONFIG_EPON_FEATURE)
	int index, entryNum;
	char cmdBuf[64] = {0};
#endif
	int sleep_time = 3;
#if defined(CONFIG_GPON_FEATURE) || defined(CONFIG_EPON_FEATURE)
	unsigned int pon_mode;
	mib_get(MIB_PON_MODE, &pon_mode);
#endif
	unsigned char password_hex[MAX_NAME_LEN]={0};
	
	if(loid == NULL)
	{
		fprintf(stderr, "LOID is NULL\n");
		return;
	}

	mib_get(MIB_LOID, loid);
	mib_get(MIB_LOID_PASSWD, password);

#if defined(CONFIG_GPON_FEATURE)
	if(pon_mode == 1)
	{
	// Deactive GPON
	// do not use rtk_rg_gpon_deActivate() becuase it does not send link down event.

		system("diag gpon reg-set page 1 offset 0x10 value 0x1");

		system("omcicli mib reset");

#if defined(CONFIG_CMCC) || defined(CONFIG_CU) || defined(CONFIG_CU)
		if(loid[0])
#endif
		{
			if (password[0]) {
				va_cmd("/bin/omcicli", 4, 1, "set", "loid", loid, password);
			} else {
				va_cmd("/bin/omcicli", 3, 1, "set", "loid", loid);
			}
		}

#if defined(CONFIG_CMCC) || defined(CONFIG_CU) && defined(CONFIG_PON_LINKCHANGE_EVENT)
		//because we deactivate the gpon
		//we need CONFIG_CMCC_OSGIMANAGE=y
		system("/bin/diag gpon deactivate");
		if (password[0]) {
			//diag gpon set password xxxx
			formatPloamPasswordToHex(password, password_hex);
			va_cmd("/sbin/diag", 4, 1, "gpon", "set", "password-hex", password_hex);
		}
		else {
			va_cmd("/sbin/diag", 4, 1, "gpon", "set", "password", "0000000000");
		}
		system("/bin/diag gpon activate init-state o1");
#endif

		while(i++ < 10)
			system("diag gpon reg-set page 1 offset 0x10 value 0x3");
	}
#endif
#if defined(CONFIG_EPON_FEATURE)
	if(pon_mode == 2)
	{
		/* Martin ZHU add: release all wan connection IP */
		va_cmd("/bin/etctl", 2, 1, "enable_nas0_wan", "0");

		va_cmd("/bin/etctl", 2, 1, "enable_nas0_wan", "1");

#if defined(CONFIG_RTK_L34_ENABLE) && !defined(CONFIG_RG_G3_SERIES)
		rtk_rg_epon_llidEntryNum_get(&entryNum);
#else
		rtk_epon_llidEntryNum_get(&entryNum);
#endif

		/* Martin ZHU: 2016-3-24  */
		mib_get(PROVINCE_PONREG_4STAGEDIAG, (void *) &enable4StageDiag);
		for (index = 0; index < entryNum; index++) {
			if(enable4StageDiag)
			{
				system("diag epon reset mib-counter");
			}

			memset(cmdBuf, 0, sizeof(cmdBuf));

			if (password[0]) {
				sprintf(cmdBuf, "/bin/oamcli set ctc loid %d %s %s\n",index, loid, password);
			} else {
				sprintf(cmdBuf, "/bin/oamcli set ctc loid %d %s\n",index, loid);
			}
			system(cmdBuf);

			/* 2016-04-29 siyuan: oam needs to register again using new loid and password */
			sprintf(cmdBuf,"/bin/oamcli trigger register %d", index);
			system(cmdBuf);
		}
	}
#endif

#if defined(_PRMT_X_CT_COM_USERINFO_) && defined(E8B_NEW_DIAGNOSE)
	int result = SET_SUCCESS;
	int status = 0;
	mib_set(CWMP_USERINFO_RESULT, &result);
	mib_set(CWMP_USERINFO_STATUS, &status);
#endif

#ifdef CONFIG_MIDDLEWARE
	mib_get(CWMP_TR069_ENABLE,(void *)&vChar);
	if(!vChar)
	{	// Martin_ZHU:send CTEVENT_BIND to MidProcess
		vChar = CTEVENT_BIND;
		sendInformEventMsg2MidProcess( vChar );
	}else
#endif
	{
		{
			pid_t tr069_pid;

			// send signal to tr069
			tr069_pid = read_pid("/var/run/cwmp.pid");
			if ( tr069_pid > 0){
#ifdef CONFIG_MIDDLEWARE
				vChar = CTEVENT_BIND;
				mib_set(MIB_MIDWARE_INFORM_EVENT,(void*)&vChar);
				kill(tr069_pid, SIGUSR1);	//SIGUSR2 is used by midware
#else
				kill(tr069_pid, SIGUSR2);
#endif
			}
		}
	}

	// Purposes:
	// 1. Wait for PON driver ready.
	// 2. Wait for old IP release.
	while(sleep_time)
		sleep_time = sleep(sleep_time);

FINISH:
	Commit();
}


void form_loid_burning(request * wp, char *path, char *query)
{
	int bytes_sent = 0;
	char *loid = NULL;
	char *username = NULL;
	char *passwd = NULL;
	char mib_user[MAX_NAME_LEN];
	char mib_pass[MAX_NAME_LEN];
	char result[32];
	
	mib_get(MIB_SUSER_NAME, mib_user);
	mib_get(MIB_SUSER_PASSWORD, mib_pass);

	loid = boaGetVar(wp, "loid", "");
	username = boaGetVar(wp, "user", "");
	passwd = boaGetVar(wp, "pass", "");

	boaHeader(wp);
	boaWrite(wp, "<head><META http-equiv=content-type content=\"text/html; charset=gbk\">\n"
		"<script>");

	if(strcmp(username, mib_user) || strcmp(passwd, mib_pass))
		//boaWrite(wp, "alert(\"账号或密码错误\");\n");
		strcpy(result,"烧制LOID失败");
	else
	{
		unsigned int event;

		fprintf(stderr, "Burnning LOID: %s\n", loid);
		mib_set(MIB_LOID, loid);
		mib_set(MIB_LOID_OLD, loid);

		start_dev_register();
		//boaWrite(wp, "alert(\"烧制SN成功\");\n");
		strcpy(result,"烧制LOID成功");

#if 0	/* Send BIND2 for Jiang-Su if we have to send BIND */
		mib_get(CWMP_INFORM_USER_EVENTCODE, &event);
		event |= EC_X_CT_COM_BIND_2;
		mib_set(CWMP_INFORM_USER_EVENTCODE, &event);
#endif
	}

	boaWrite(wp, "document.getElementsByTagName('HTML')[0].innerHTML = \"%s\";\n",result);
	//boaWrite(wp, "window.location = \"/\";");
	boaWrite(wp, "</script></head>\n");
	boaWrite(wp, "<input type=\"button\" value =\"返回\" onclick=\"location.href=\'/\'\"/>\n");
	
	boaFooter(wp);
	boaDone(wp, 200);

	return;
}
#endif

#ifdef SUPPORT_PUSHWEB_FOR_FIRMWARE_UPGRADE
int initFirmwareUpgradeWarnPage(int eid, request * wp, int argc, char **argv)
{
    int nBytesSent = 0;
    unsigned int dlPhase;

    mib_get(MIB_CWMP_DL_PHASE, (void *)&dlPhase);
    nBytesSent += boaWrite(wp, "phase = %d;\n", dlPhase);

    return nBytesSent;
}

void formFirmwareUpgradeWarn(request * wp, char *path, char *query)
{
	char *submitUrl;

	submitUrl = boaGetVar(wp, "submit-url", "");
	if (submitUrl[0])
		boaRedirect(wp, submitUrl);
}
#endif

#ifdef E8B_NEW_DIAGNOSE
int dumpPingInfo(int eid, request *wp, int argc, char **argv)
{
	int nBytesSent = 0;
	struct stat st;
	FILE *pf;
	char line[512];

	if (system("/bin/pidof ping > /dev/null") == 0) {
#if defined(CONFIG_CMCC) || defined(CONFIG_CU) || defined(CONFIG_CU)
	nBytesSent += boaWrite(wp, "%s", "<div align=\"left\"><b><font color=\'#FF0000\' size=\'-1\'>正在进行Ping测试,请稍等...</font></b></div>\n");
		return nBytesSent;
#else
		nBytesSent += boaWrite(wp, "%s", "\t<div align=\"left\"><b>请稍候</b>\n\t<br><br>\n\t</div>\n");
#endif
	} else if (stat("/tmp/ping.tmp", &st) || st.st_size == 0) {
#if defined(CONFIG_CMCC) || defined(CONFIG_CU) || defined(CONFIG_CU)
			nBytesSent += boaWrite(wp, "%s", "<div align=\"left\"><b><font color=\'#FF0000\' size=\'-1\'>PING测试失败</font></b></div>\n");
#else
		nBytesSent += boaWrite(wp, "%s", "\t<div align=\"left\"><b>PING测试失败</b>\n\t<br><br>\n\t</div>\n");
#endif
		return nBytesSent;
	} else {
#if defined(CONFIG_CMCC) || defined(CONFIG_CU) || defined(CONFIG_CU)
	nBytesSent += boaWrite(wp, "%s", "<div align=\"left\"><b>Ping Result</b></div>\n");
#else
		nBytesSent += boaWrite(wp, "%s", "\t<div align=\"left\"><b>完成</b>\n\t<br><br>\n\t</div>\n");
#endif
	}

	pf = fopen("/tmp/ping.tmp", "r");
	if (!pf) {
		return nBytesSent;
	}

	nBytesSent += boaWrite(wp, "%s", "\t<pre>\n");
	while (fgets(line, sizeof(line), pf)) {
		nBytesSent += boaWrite(wp, "%s", line);
	}
	nBytesSent += boaWrite(wp, "%s", "\t</pre>\n");

	fclose(pf);

	return nBytesSent;
}

void formPing(request * wp, char *path, char *query)
{
	char *target_addr, *waninf;
	char cmd[256], outInf[IFNAMSIZ], wanname[MAX_WAN_NAME_LEN];
	int entries_num, i;
	MIB_CE_ATM_VC_T entry;
	char *proto ="";

	va_cmd("/bin/killall", 1, 1, "ping");
	unlink("/tmp/ping.tmp");

	target_addr = boaGetVar(wp, "target_addr", "");
#if defined(CONFIG_CMCC) || defined(CONFIG_CU) || defined(CONFIG_CU)
    int target_num = atoi(boaGetVar(wp, "target_num", "5"));
#endif
	waninf = boaGetVar(wp, "waninf", "");

	if (!target_addr[0] || !waninf[0]) {
#if defined(CONFIG_CMCC) || defined(CONFIG_CU) || defined(CONFIG_CU)
        boaWrite(wp, "<script>alert(\"目标地址非法！请重新输入！\")</script>");
#else
		ERR_MSG("目标地址或者WAN接口不正确!");
#endif
		return;
	}
#if defined(CONFIG_CMCC) || defined(CONFIG_CU) || defined(CONFIG_CU)
    if (target_num>10 || target_num<1) {
		//ERR_MSG("目标地址或者WAN接口不正确!");
		return;
	}
#endif
#if defined(CONFIG_CMCC) || defined(CONFIG_CU) || defined(CONFIG_CU)
		printf("starting ping(target: %s, interface: %s, num: %d)...\n", target_addr, waninf,target_num);
#else
	printf("starting ping(target: %s, interface: %s)...\n", target_addr, waninf);
#endif
	memset(&entry, 0, sizeof(MIB_CE_ATM_VC_T));

	entries_num = mib_chain_total(MIB_ATM_VC_TBL);
	for (i = 0; i < entries_num; i++) {
		if (!mib_chain_get(MIB_ATM_VC_TBL, i, &entry)) {
			ERR_MSG("没有找到相应的WAN接口!");
			return;
		}

		getWanName(&entry, wanname);
		if (strcmp(waninf, wanname) == 0)
			break;
	}
	ifGetName(entry.ifIndex, outInf, sizeof(outInf));
	if(entry.IpProtocol == IPVER_IPV4)
		proto = "-4";
	else if(entry.IpProtocol == IPVER_IPV6)
		proto = "-6";

	if(!isIPAddr(target_addr)) {
		unsigned int ping_intf = entry.ifIndex;
		static char Host[256+1];
		int sys_pid = -1;
		mib_set(MIB_RS_PING_INTF, (void *)&ping_intf);
		sprintf(Host, "%s", target_addr);
		mib_set(MIB_RS_PING_HOST, Host);
		sys_pid = read_pid("/var/run/systemd.pid");
		if (sys_pid > 0) {
			kill(sys_pid, SIGUSR1); //update DNS info
			sleep(1);	//wait a second for DNS updating
		}
	}
#if defined(CONFIG_CMCC) || defined(CONFIG_CU) || defined(CONFIG_CU)
	snprintf(cmd, sizeof(cmd), "ping %s -c %d -I %s -w 10 %s > /tmp/ping.tmp", proto, target_num, outInf, target_addr);
#else
	snprintf(cmd, sizeof(cmd), "ping %s -c 4 -I %s -w 5 %s > /tmp/ping.tmp", proto, outInf, target_addr);
#endif
	va_cmd("/bin/sh", 2, 0, "-c", cmd);

	boaRedirect(wp, "/diag_ping_admin_result.asp");

	return;
}

int dumpTraceInfo(int eid, request * wp, int argc, char **argv)
{
	int nBytesSent = 0;
	struct stat st;
	FILE *pf;
	char line[512];

	if (system("/bin/pidof traceroute > /dev/null") == 0) {
#if defined(CONFIG_CMCC) || defined(CONFIG_CU) || defined(CONFIG_CU)
		nBytesSent += boaWrite(wp, "%s", "<div align=\"left\"><b><font color=\'#FF0000\' size=\'-1\'>正在进行Tracert测试,请稍等...</font></b></div>\n");
		return nBytesSent;
#else
		nBytesSent += boaWrite(wp, "%s", "\t<div align=\"left\"><b>请稍候</b>\n\t<br><br>\n\t</div>\n");
#endif
	} else if (stat("/tmp/tracert.tmp", &st) || st.st_size == 0) {
#if defined(CONFIG_CMCC) || defined(CONFIG_CU) || defined(CONFIG_CU)
	nBytesSent += boaWrite(wp, "%s", "<div align=\"left\"><b><font color=\'#FF0000\' size=\'-1\'>Tracert测试失败</font></b></div>\n");
#else
		nBytesSent += boaWrite(wp, "%s", "\t<div align=\"left\"><b>Tracert测试失败</b>\n\t<br><br>\n\t</div>\n");
#endif
		return nBytesSent;
	} else {
#if defined(CONFIG_CMCC) || defined(CONFIG_CU) || defined(CONFIG_CU)
	nBytesSent += boaWrite(wp, "%s", "<div align=\"left\"><b>Tracert Result</b></div>\n");
#else
		nBytesSent += boaWrite(wp, "%s", "\t<div align=\"left\"><b>完成</b>\n\t<br><br>\n\t</div>\n");
#endif
	}

	pf = fopen("/tmp/tracert.tmp", "r");
	if (!pf) {
		return nBytesSent;
	}

	nBytesSent += boaWrite(wp, "%s", "\t<pre>\n");
	while (fgets(line, sizeof(line), pf)) {
		nBytesSent += boaWrite(wp, "%s", line);
	}
	nBytesSent += boaWrite(wp, "%s", "\t</pre>\n");

	fclose(pf);

	return nBytesSent;
}

void formTracert(request * wp, char *path, char *query)
{
	char *target_addr, *wanInf, *proto = "";
	char line[512] = {0}, cmd[512] = {0}, outInf[20] = {0};
	FILE *pf = NULL;
	int entries_num = 0, i = 0;
	MIB_CE_ATM_VC_T entry;
	int flags = 0;
	struct in_addr inAddr;
	FILE *fp;
	char buff[64];
	int pppif;
	int found = 0;
	struct data_to_pass_st msg;
	int state = 0;
	unsigned int value;
#ifdef CONFIG_USER_LOG_ERRCODE
		unsigned char errCode[256];
#endif	

	va_cmd("/bin/killall", 1, 1, "traceroute");

	unlink("/tmp/tracert.tmp");

	target_addr = boaGetVar(wp, "target_addr", "");
	wanInf = boaGetVar(wp, "waninf", "");

	printf("target: %s, wanInf: %s\n", target_addr, wanInf);

	if (!target_addr[0]) {
#if defined(CONFIG_CMCC) || defined(CONFIG_CU) || defined(CONFIG_CU)
        boaWrite(wp, "<script>alert(\"目标地址非法！请重新输入！\")</script>");
#else
		ERR_MSG("地址不正确!");
#endif
		return;
	}

	entries_num = mib_chain_total(MIB_ATM_VC_TBL);
	for (i = 0; i < entries_num; i ++) {
		char wanname[MAX_WAN_NAME_LEN] = {0};
		if (!mib_chain_get(MIB_ATM_VC_TBL, i, &entry)) {
			ERR_MSG("没有找到相应的WAN接口!");
			return;
		}

		getWanName(&entry, wanname);
		if(strcmp(wanInf, wanname) == 0)
			break;
	}

	ifGetName(entry.ifIndex, outInf,sizeof(outInf));

	//20180103: Traceroute test, if there is no IP then try dial again
	mib_get(PROVINCE_SICHUAN_FUNCTION_MASK,&value);
	if((value & PROVINCE_SICHUAN_TRACEROUTE_TEST) != 0)
	{	
		if (getInFlags( outInf, &flags) == 1 && flags & IFF_UP)//UP
		{
			//intf("%s is UP!\n" , outInf);
			if (getInAddr(outInf, IP_ADDR, (void *)&inAddr) == 1)//with IP 
			{
				//intf("%s has got IP!\n" , outInf);
			}
			else 
			{
				if(entry.cmode == CHANNEL_MODE_IPOE && entry.ipDhcp== DHCP_CLIENT )//DHCP
				{
					if(isDhcpProcessExist(entry.ifIndex) == 1) {
						//PID exist, but without IP, so do nothing
						printf("%s PID exist, but it have no IP!\n" , outInf);
					}
					else 
					{
						//PID don't exist, then get IP,and wait for a while
						startIP(outInf, &entry, CHANNEL_MODE_IPOE); 
						sleep(5);
					}
				}
			}
		}
		else //not UP
		{
			if(entry.cmode == CHANNEL_MODE_PPPOE)//PPPOE
			{
				fp=fopen("/tmp/ppp_error_log", "r");
				if (fp) 
				{
					while (fgets(buff, sizeof(buff), fp) != NULL) 
					{
#ifdef CONFIG_USER_LOG_ERRCODE
						sprintf(buff, "%d:%d:%s\n", &pppif, &state, errCode);
#else
						sprintf(buff, "%d:%d\n", &pppif, &state);
#endif
						if (pppif == PPP_INDEX(entry.ifIndex)){ //has dialled
							found = 1;
							if (state == 5){  //state is 5: user disconect it, then dail again
								snprintf(msg.data, BUF_SIZE, "spppctl up %u", PPP_INDEX(entry.ifIndex)); //dail
								write_to_pppd(&msg);
								sleep(5);
								break;
							}
							else
							{
								break;
							}
						}
						else
						{
							continue;
						}
					}
					if(!found)
					{
						startPPP(outInf,&entry,0,CHANNEL_MODE_PPPOE); //start dailing and wait for a while
						sleep(5);
					}
				}
				fclose(fp);
			}
		}
	}

	
	if(entry.IpProtocol == IPVER_IPV4)
		proto = "-4";
	else if(entry.IpProtocol == IPVER_IPV6)
		proto = "-6";

	//snprintf(cmd, sizeof(cmd), "traceroute -q 1 -w 2 %s > /tmp/tracert.tmp 2>&1", ip);
	//cxy 2015-1-14: traceroute use icmp  and specify out interface
#if defined(CONFIG_CMCC) || defined(CONFIG_CU) || defined(CONFIG_CU)
	snprintf(cmd, sizeof(cmd), "traceroute %s -I -i %s %s -m 10 > /tmp/tracert.tmp", proto, outInf, target_addr);
#else
	snprintf(cmd, sizeof(cmd), "traceroute %s -I -i %s %s > /tmp/tracert.tmp", proto, outInf, target_addr);
#endif
#if 1
	va_cmd("/bin/sh", 2, 0, "-c", cmd);

	boaRedirect(wp, "/diag_tracert_admin_result.asp");
#else
	if (outInf[0] != 0)
		temp_route_modify(ip, outInf, 1);
	va_cmd("/bin/sh", 2, 1, "-c", cmd);
	if (outInf[0] != 0)
		temp_route_modify(ip, outInf, 0);

	pf = fopen("/tmp/tracert.tmp", "r");
	if (pf) {
		boaHeader(wp);
   		boaWrite(wp, "<body><blockquote><pre>\n");
		while (fgets(line, sizeof(line), pf)) {
			printf("%s", line);
			boaWrite(wp, "%s", line);
		}
		boaWrite(wp, "</pre><form><input type=button value=\"  %s  \" OnClick=window.location.replace(\"/diag_tracert_admin.asp\")></form></blockquote></body>", IDS_RESULT_OK);
		boaFooter(wp);
		boaDone(wp, 200);
		fclose(pf);
	}
	//system("rm -rf /tmp/tracert.tmp");
	unlink("/tmp/tracert.tmp");
#endif
	return;
}

#ifdef CONFIG_SUPPORT_AUTO_DIAG
void formAutoDiag(request * wp, char *path, char *query)
{
	char status = 0;

	mib_set(MIB_AUTO_DIAG_ENABLE, (void *)&status);
	Commit();

	boaRedirect(wp, "/diag_autosystem_admin.asp");
	return;
}

void formQOE(request * wp, char *path, char *query)
{
	unsigned char enable = 0;

	mib_set(CWMP_CT_QOE_ENABLE, (void *)&enable);
	Commit();

	boaRedirect(wp, "/diag_autosystem_admin.asp");
	return;
}
#endif
#endif

#ifdef CONFIG_YUEME
char* WanRedirectAllowList[] = {"net_eth_links.asp", NULL};
#endif
void formWanRedirect(request * wp, char *path, char *query)
{
	char *redirectUrl;
	char *strWanIf;

	redirectUrl= boaGetVar(wp, "redirect-url", "");
	strWanIf= boaGetVar(wp, "if", "");
	if(strWanIf[0]){
		strcpy(wanif,strWanIf);
	}

	if(redirectUrl[0])
	{
#ifdef CONFIG_YUEME
		if(!checkValidRedirect(redirectUrl, WanRedirectAllowList))
		{
			wp->buffer_end=0; // clear header
			send_r_bad_request(wp);
		}
		else
#endif
			boaRedirectTemp(wp,redirectUrl);
	}
}

int ShowDefaultGateway(int eid, request * wp, int argc, char **argv)
{
#ifdef DEFAULT_GATEWAY_V2
	boaWrite(wp, "	<td colspan=4><input type=\"radio\" name=\"droute\" value=\"1\" onClick='autoDGWclicked()'>"
	"<font size=2><b>&nbsp;&nbsp;Obtain default gateway automatically</b></td>\n</tr>\n"
	"<tr><th></th>\n	<td colspan=4><input type=\"radio\" name=\"droute\" value=\"0\" onClick='autoDGWclicked()'>"
	"<font size=2><b>&nbsp;&nbsp;Use the following default gateway:</b></td>\n</tr>\n");
	boaWrite(wp, "<div id='gwInfo'>\n"
	"<tr><th></th>\n	<td>&nbsp;</td>\n"
	"	<td colspan=2><font size=2><input type=\"radio\" name='gwStr' value=\"0\" onClick='gwStrClick()'><b>&nbsp;Use Remote WAN IP Address:&nbsp;&nbsp;</b></td>\n"
	"	<td><div id='id_dfltgwy'><font size=2><input type='text' name='dstGtwy' maxlength=\"15\" size=\"10\"></div></td>\n</tr>\n"
	"<tr><th></th>\n	<td>&nbsp;</td>\n"
	"	<td colspan=2><font size=2><input type=\"radio\" name='gwStr' value=\"1\" onClick='gwStrClick()'><b>&nbsp;Use WAN Interface:&nbsp;&nbsp;</b></td>\n"
	"	<td><div id='id_wanIf'><font size=2><select name='wanIf'>");
	ifwanList(eid, wp, argc, argv);
	boaWrite(wp, "</select></div></td>\n</tr>\n</div>\n</table>\n");
	boaWrite(wp, "<input type=\"hidden\"  name=\"remoteIp\">\n");
#else
	boaWrite(wp, "<div id='gwInfo'>\n");
	boaWrite(wp, "<input type=\"hidden\"  name=\"gwStr\">\n");
	boaWrite(wp, "<div id='id_dfltgwy'>\n");
	boaWrite(wp, "<input type=\"hidden\"  name=\"dstGtwy\"></div>\n");
	boaWrite(wp, "<input type=\"hidden\"  name=\"gwStr\">\n");
	boaWrite(wp, "<div id='id_wanIf'>\n");
	boaWrite(wp, "<input type=\"hidden\"  name=\"wanIf\"></div>\n</div>\n");
#endif
}

int ShowPortMapping(int eid, request * wp, int argc, char **argv)
{
	int i;
#if defined(CONFIG_RTK_L34_ENABLE) && defined(CONFIG_USER_LAN_PORT_AS_ETH_WAN)
	int phyPortId = -1;
	int ethPhyPortId = -1;
	mib_get(MIB_ETH_WAN_PORT_PHY_INDEX, &ethPhyPortId);
#endif

	boaWrite(wp, "<table id=\"tbbind\" cellpadding=\"0px\" cellspacing=\"2px\">\n"
			"<tr class=\"sep\"><td colspan=\"2\"><hr align=\"left\" class=\"sep\" size=\"1\" width=\"100%%\"></td></tr>\n"
			"<tr nowrap><td width=\"150px\">绑定端口：</td><td>&nbsp;</td></tr>\n");
	for (i=PMAP_ETH0_SW0; i<=PMAP_ETH0_SW3; i++) {
		if (i < SW_LAN_PORT_NUM) {
			if (!(i&0x1))
				boaWrite(wp, "<tr nowrap>");
#if defined(CONFIG_RTK_L34_ENABLE) && defined(CONFIG_USER_LAN_PORT_AS_ETH_WAN)
			phyPortId = RG_get_lan_phyPortId(i);
			if (phyPortId != -1 && phyPortId == ethPhyPortId)
				boaWrite(wp, "<td style=\"display:none\"><input type=checkbox name=chkpt>端口_%d</font></td>", i+1);
			else
#endif
			boaWrite(wp, "<td><input type=checkbox name=chkpt>端口_%d</font></td>", i+1);
			if ((i&0x1) || (i+1) == SW_LAN_PORT_NUM)
				boaWrite(wp, "</tr>\n");
		}
		else
			boaWrite(wp, "<input type=hidden name=chkpt>\n");
	}

#ifdef WLAN_SUPPORT
	int orig_wlan_idx = wlan_idx;
	int j;
#ifdef YUEME_3_0_SPEC_SSID_ALIAS
	unsigned char phyband = PHYBAND_2G;
#endif
	for(j=0; j<NUM_WLAN_INTERFACE;j++){
		wlan_idx = j;
#ifdef YUEME_3_0_SPEC_SSID_ALIAS
		mib_get(MIB_WLAN_PHY_BAND_SELECT, &phyband);
		boaWrite(wp, "<tr nowrap><td><input type=\"checkbox\" name=\"chkpt\">无线(%s-%d)</td>", phyband==PHYBAND_2G? "2.4G":"5G", 1);
#else
		boaWrite(wp, "<tr nowrap><td><input type=\"checkbox\" name=\"chkpt\">无线(SSID%d)</td>", (j*(WLAN_MBSSID_NUM+1)) + 1);
#endif
#ifdef WLAN_MBSSID
		int showNum = 0;
		MIB_CE_MBSSIB_T entry;
		for (i = 0; i < WLAN_MBSSID_NUM; i++)
		{
			mib_chain_get(MIB_MBSSIB_TBL, i + 1, &entry);
			if (entry.wlanDisabled) {
				boaWrite(wp, "<input type=hidden name=chkpt>\n");
				continue;
			}

			showNum++;

			if (!(showNum & 0x1))
				boaWrite(wp, "<tr nowrap>");

#ifdef YUEME_3_0_SPEC_SSID_ALIAS
			boaWrite(wp, "<td><input type=\"checkbox\" name=\"chkpt\">无线(%s-%d)</td>", phyband==PHYBAND_2G? "2.4G":"5G", (i+2));
#else
			boaWrite(wp, "<td><input type=\"checkbox\" name=\"chkpt\">无线(SSID%d)</td>", (j*(WLAN_MBSSID_NUM+1)) + (i+2));
#endif

			if ((showNum & 0x1))
				boaWrite(wp,  "</tr>\n");
		}

		if (!(showNum & 0x1))
			boaWrite(wp,  "</tr>\n");
#else
		boaWrite(wp, "</tr>\n");
		for (i = 0; i <WLAN_MBSSID_NUM; i++)
			boaWrite(wp, "<input type=hidden name=chkpt>\n");
#endif
		for(i=0; i<(MAX_WLAN_VAP-WLAN_MBSSID_NUM); i++)
			boaWrite(wp, "<input type=hidden name=chkpt>\n");
	}
	wlan_idx = orig_wlan_idx;
#ifndef WLAN_DUALBAND_CONCURRENT
	for(i=0; i<(1+MAX_WLAN_VAP); i++)
		boaWrite(wp, "<input type=hidden name=chkpt>\n");
#endif
#else
	boaWrite(wp, "<input type=hidden name=chkpt>\n");
	boaWrite(wp, "<input type=hidden name=chkpt>\n");
	boaWrite(wp, "<input type=hidden name=chkpt>\n");
	boaWrite(wp, "<input type=hidden name=chkpt>\n");
	boaWrite(wp, "<input type=hidden name=chkpt>\n");
	boaWrite(wp, "<input type=hidden name=chkpt>\n");
	boaWrite(wp, "<input type=hidden name=chkpt>\n");
	boaWrite(wp, "<input type=hidden name=chkpt>\n");
	boaWrite(wp, "<input type=hidden name=chkpt>\n");
	boaWrite(wp, "<input type=hidden name=chkpt>\n");
#endif

	boaWrite(wp, "</table>\n");
}

#if defined(CONFIG_CMCC) || defined(CONFIG_CU) && defined(CONFIG_IPV6)
void formVlanCfg(request * wp, char *path, char *query)
{
	char *str_vlan, *submitUrl;
	int vlan_id, vlan_id4v4_old,vlan_id4v6_old;
	char vlan_enable=0;

	str_vlan = boaGetVar(wp, "vlan", "");
	vlan_enable = str_vlan[0]-'0';
	mib_set(MIB_IPV6_VLAN_ENABLE, (void *)&vlan_enable);
	mib_get(MIB_IPV4_VLAN_ID, (void *)&vlan_id4v4_old);
	mib_get(MIB_IPV6_VLAN_ID, (void *)&vlan_id4v6_old);
	if(vlan_enable)		//enable ipv6 vlan
	{
		vlan_id = atoi(boaGetVar(wp, "vlanid4v4", ""));	
		mib_set(MIB_IPV4_VLAN_ID, (void *)&vlan_id);
		vlan_id = atoi(boaGetVar(wp, "vlanid4v6", ""));	
		mib_set(MIB_IPV6_VLAN_ID, (void *)&vlan_id);
	}
	mib_update(CURRENT_SETTING, CONFIG_MIB_ALL);
	set_vlan_cfg_action(vlan_id4v4_old,vlan_id4v6_old);
	submitUrl = boaGetVar(wp, "submit-url", "");
	if (submitUrl[0])
		boaRedirect(wp, submitUrl);
	else
		boaDone(wp, 200);
	return;
}
#endif

#ifdef CONFIG_YUEME
#define CLOUD_CLIENT_STATUS_FILE "/tmp/cloud_client_status_file"
#define CLOUD_CLIENT_STATUS_FILE_BK "/tmp/cloud_client_status_file_bk"

int listPlatformService(int eid, request * wp, int argc, char ** argv)
{
	FILE *f=NULL;
	long len;
	char *data;
	cJSON *root=NULL;
	cJSON *item=NULL;
	cJSON *item_sub=NULL;
	cJSON *item_status=NULL, *item_server=NULL;
	int update=0;
	char cmd[512]={0};

	_TRACE_CALL;

	va_cmd("/bin/get_platform_servers", 0, 1);

	f=fopen(CLOUD_CLIENT_STATUS_FILE,"rb");
	if(!f){
		f=fopen(CLOUD_CLIENT_STATUS_FILE_BK,"rb");
		if(!f)
			goto check_err;
	}
	else{
		update = 1;
	}
	
	fseek(f,0,SEEK_END);
	len=ftell(f);
	fseek(f,0,SEEK_SET);
	
	data=(char*)malloc(len+1);
	if(!data)
		goto check_err;
	
	fread(data,1,len,f);
	
	root = cJSON_Parse(data);
	if (!root) 
	{
		printf("Error before: [%s]\n",cJSON_GetErrorPtr());
		goto check_err;
	}
	if(cJSON_GetArraySize(root)==0)
		goto check_err;

	item = cJSON_GetArrayItem(root, 0);
	do
	{
		//printf("%s\n" , item->string);
		if(item->child)
		{
			item_status = NULL;
			item_status = cJSON_GetObjectItem(item,"Status");
			//if(item_status)
			//	printf("%s %s\n" , item_status->string, item_status->valuestring);
			item_server = NULL;		
			item_server = cJSON_GetObjectItem(item,"Server");
			//if(item_server)
			//	printf("%s %s\n" , item_server->string, item_server->valuestring);

			boaWrite(wp, "push(new it_nr(\"%s\"" _PTS _PTS  "));\n",
				item->string, 
				item_server->string, item_server->valuestring,
				item_status->string, item_status->valuestring);
			
		}
		item = item->next;
	}while(item);

check_err:
	_TRACE_LEAVEL;
	if(root)
		cJSON_Delete(root);	
	if(f)
		fclose(f);

	if(update){
		unlink(CLOUD_CLIENT_STATUS_FILE_BK);
		snprintf(cmd, 512, "mv %s %s", CLOUD_CLIENT_STATUS_FILE, CLOUD_CLIENT_STATUS_FILE_BK);
		system(cmd);
	}
	return 0;
}
#endif
