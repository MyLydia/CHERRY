/*
 *      Web server handler routines for System IPv6 status
 *
 */

#include "../webs.h"
#include "webform.h"
#include "mib.h"
#include "utility.h"
#include "debug.h"
#include "multilang.h"

#ifdef CONFIG_IPV6
void formStatus_ipv6(request * wp, char *path, char *query)
{
	char *submitUrl;

	submitUrl = boaGetVar(wp, "submit-url", "");
	if (submitUrl[0])
		boaRedirect(wp, submitUrl);
	else
		boaDone(wp, 200);
  	return;
}

int wanip6ConfList(int eid, request * wp, int argc, char **argv)
{
	int nBytesSent=0;
	int in_turn=0, ifcount=0;
	int i, j, k;
	struct ipv6_ifaddr ip6_addr[6];
	char buf[256], str_ip6[INET6_ADDRSTRLEN];
	struct wstatus_info sEntry[MAX_VC_NUM+MAX_PPP_NUM];

	ifcount = getWanStatus(sEntry, MAX_VC_NUM+MAX_PPP_NUM);
#ifndef CONFIG_GENERAL_WEB
	nBytesSent += boaWrite(wp, "<tr bgcolor=\"#808080\">"
	"<td width=\"8%%\" align=center><font size=2><b>%s</b></font></td>\n"
	"<td width=\"12%%\" align=center><font size=2><b>%s</b></font></td>\n"
	"<td width=\"12%%\" align=center><font size=2><b>%s</b></font></td>\n"
	"<td width=\"12%%\" align=center><font size=2><b>%s</b></font></td>\n"
	"<td width=\"22%%\" align=center><font size=2><b>%s</b></font></td>\n"
	"<td width=\"12%%\" align=center><font size=2><b>%s</b></font></td></tr>\n",
#else
	nBytesSent += boaWrite(wp, "<tr>"
	"<th width=\"8%%\">%s</th>\n"
	"<th width=\"12%%\">%s</th>\n"
	"<th width=\"12%%\">%s</th>\n"
	"<th width=\"12%%\">%s</th>\n"
	"<th width=\"22%%\">%s</th>\n"
	"<th width=\"12%%\">%s</th></tr>\n",
#endif
	multilang(LANG_INTERFACE), 
#if defined(CONFIG_LUNA)
	multilang(LANG_VLAN_ID), multilang(LANG_CONNECTION_TYPE),
#else
	multilang(LANG_VPI_VCI), multilang(LANG_ENCAPSULATION),
#endif
	multilang(LANG_PROTOCOL), multilang(LANG_IP_ADDRESS), multilang(LANG_STATUS));
	in_turn = 0;
	for (i=0; i<ifcount; i++) {
		if (sEntry[i].cmode == CHANNEL_MODE_BRIDGE || (sEntry[i].ipver == IPVER_IPV4))
			continue; // not IPv6 capable
#ifndef CONFIG_GENERAL_WEB
		if (in_turn == 0)
			nBytesSent += boaWrite(wp, "<tr bgcolor=\"#EEEEEE\">\n");
		else
			nBytesSent += boaWrite(wp, "<tr bgcolor=\"#DDDDDD\">\n");
#else
		if (in_turn == 0)
			nBytesSent += boaWrite(wp, "<tr>\n");
#endif

		in_turn ^= 0x01;
		k=getifip6(sEntry[i].ifname, IPV6_ADDR_UNICAST, ip6_addr, 6);
		buf[0]=0;
		if (k) {
			for (j=0; j<k; j++) {
				inet_ntop(PF_INET6, &ip6_addr[j].addr, str_ip6, INET6_ADDRSTRLEN);
				if (j == 0)
					sprintf(buf, "%s/%d", str_ip6, ip6_addr[j].prefix_len);
				else
					sprintf(buf, "%s, %s/%d", buf, str_ip6, ip6_addr[j].prefix_len);
			}
		}
		nBytesSent += boaWrite(wp,
#ifndef CONFIG_GENERAL_WEB
		"<td align=center width=\"5%%\"><font size=2>%s</td>\n"
#if defined(CONFIG_LUNA)
		"<td align=center width=\"1%%\"><font size=2>%d</td>\n"
		"<td align=center width=\"9%%\"><font size=2>%s</td>\n"
#else
		"<td align=center width=\"5%%\"><font size=2>%s</td>\n"
		"<td align=center width=\"5%%\"><font size=2>%s</td>\n"
#endif
		"<td align=center width=\"5%%\"><font size=2>%s</td>\n"
		"<td align=center width=\"10%%\"><font size=2>%s</td>\n"
		"<td align=center width=\"23%%\"><font size=2>%s\n",
#else	//CONFIG_GENERAL_WEB
		"<td width=\"5%%\">%s</th>\n"
#if defined(CONFIG_LUNA)
		"<td width=\"1%%\">%d</th>\n"
		"<td width=\"9%%\">%s</th>\n"
#else
		"<td width=\"5%%\">%s</th>\n"
		"<td width=\"5%%\">%s</th>\n"
#endif
		"<td width=\"5%%\">%s</th>\n"
		"<td width=\"10%%\">%s</th>\n"
		"<td width=\"23%%\">%s\n",
#endif	//CONFIG_GENERAL_WEB
		sEntry[i].ifDisplayName, 
#if defined(CONFIG_LUNA)
		sEntry[i].vid, sEntry[i].serviceType,
#else
		sEntry[i].vpivci, sEntry[i].encaps,
#endif
		sEntry[i].protocol, buf, sEntry[i].strStatus_IPv6);
		nBytesSent += boaWrite(wp, "</td></tr>\n");
	}
	return nBytesSent;
}
#endif //#ifdef CONFIG_IPV6
