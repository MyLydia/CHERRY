/*
 *      Web server handler routines for Ethernet-to-PVC mapping stuffs
 *
 */


/*-- System inlcude files --*/
//#include <net/if.h>
#include <signal.h>
#ifdef EMBED
#include <linux/config.h>
#else
#include "../../../../include/linux/autoconf.h"
#endif

/*-- Local inlcude files --*/
#include "../webs.h"
#include "webform.h"
#include "mib.h"
#include "utility.h"
#include "options.h"

#ifdef __i386__
#define _LITTLE_ENDIAN_
#endif

#ifdef CONFIG_00R0
#ifdef CONFIG_RTK_L34_ENABLE // Rostelecom, Port Binding function
#define LANIF_NUM	5 // LAN1 ~ LAN4, WLAN

void formVLANMapping(request * wp, char *path, char *query)
{
	int total = 0, i = 0, ifidx = 0, nVal= 0;
	char *strData = NULL, *submitUrl = NULL;
	char tmpBuf[100] = {0};
	MIB_CE_PORT_BINDING_T pbEntry;
	struct vlan_pair *vid_pair;

	total = mib_chain_total(MIB_PORT_BINDING_TBL);
	if (total == 0) {
		memset(&pbEntry, 0, sizeof(MIB_CE_PORT_BINDING_T));
		for (i = 0; i < LANIF_NUM; i++) {
			mib_chain_add(MIB_PORT_BINDING_TBL, (void *)&pbEntry);
		}
	}

	strData = boaGetVar(wp, "intf_sel", "");
	ifidx = atoi(strData);
	if (ifidx < 0 || ifidx >= LANIF_NUM) {
		strcpy(tmpBuf, strModChainerror);
		goto setErr_VLANMapping;
	}

	mib_chain_get(MIB_PORT_BINDING_TBL, ifidx, (void*)&pbEntry);

	setup_VLANMapping(ifidx, 0);

	strData = boaGetVar(wp, "Frm_VLAN0a", "");
	if (strlen(strData)) {
		nVal = atoi(strData);
		pbEntry.pb_vlan0_a = nVal;
	}
	strData = boaGetVar(wp, "Frm_VLAN0b", "");
	if (strlen(strData)) {
		nVal = atoi(strData);
		pbEntry.pb_vlan0_b = nVal;
	}

	strData = boaGetVar(wp, "Frm_VLAN1a", "");
	if (strlen(strData)) {
		nVal = atoi(strData);
		pbEntry.pb_vlan1_a = nVal;
	}
	strData = boaGetVar(wp, "Frm_VLAN1b", "");
	if (strlen(strData)) {
		nVal = atoi(strData);
		pbEntry.pb_vlan1_b = nVal;
	}

	strData = boaGetVar(wp, "Frm_VLAN2a", "");
	if (strlen(strData)) {
		nVal = atoi(strData);
		pbEntry.pb_vlan2_a = nVal;
	}
	strData = boaGetVar(wp, "Frm_VLAN2b", "");
	if (strlen(strData)) {
		nVal = atoi(strData);
		pbEntry.pb_vlan2_b = nVal;
	}

	strData = boaGetVar(wp, "Frm_VLAN3a", "");
	if (strlen(strData)) {
		nVal = atoi(strData);
		pbEntry.pb_vlan3_a = nVal;
	}
	strData = boaGetVar(wp, "Frm_VLAN3b", "");
	if (strlen(strData)) {
		nVal = atoi(strData);
		pbEntry.pb_vlan3_b = nVal;
	}

	mib_chain_update(MIB_PORT_BINDING_TBL, (void *)&pbEntry, ifidx);

	setup_VLANMapping(ifidx, 1);
	RTK_RG_Sync_OMCI_WAN_INFO();

#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif

	submitUrl = boaGetVar(wp, "submit-url", "");
	OK_MSG(submitUrl);

	return;

setErr_VLANMapping:
	ERR_MSG(tmpBuf);

}

int itfSelList(int eid, request * wp, int argc, char **argv)
{
	int nBytesSent = 0, i = 0;

	for (i = 0; i < ELANVIF_NUM; i++) {
			nBytesSent += boaWrite(wp, "<option value=\"%d\">LAN%d</option>\n", i, (i + 1));
	}

	nBytesSent += boaWrite(wp, "<option value=\"%d\">WLAN</option>\n", 4);

	return nBytesSent;
}

int mappingInputList(int eid, request * wp, int argc, char **argv)
{
	int nBytesSent = 0, i = 0;

	for (i = 0; i < MAX_PAIR; i++) {
		nBytesSent += boaWrite(wp,  "<tr>\n");
		nBytesSent += boaWrite(wp,  "\t<td><input id=\"Frm_VLAN%da\" name=\"Frm_VLAN%da\" size=\"10\" maxlength=\"4\" type=\"text\" value=\"\"></td>\n", i, i);
		nBytesSent += boaWrite(wp,  "\t<td><input id=\"Frm_VLAN%db\" name=\"Frm_VLAN%db\" size=\"10\" maxlength=\"4\" type=\"text\" value=\"\"></td>\n", i, i);
		nBytesSent += boaWrite(wp,  "</tr>\n");
	}

	return nBytesSent;
}
#endif //CONFIG_RTK_L34_ENABLE
#endif //CONFIG_00R0

void formBridgeGrouping(request * wp, char *path, char *query)
{
	char *str, *submitUrl;
	int grpnum;

	str = boaGetVar(wp, "select", "");
	if (str[0]) {
		setup_bridge_grouping(DEL_RULE);

		/* s1 ~ s4 */
		grpnum = str[1] - '0';
		str = boaGetVar(wp, "itfsGroup", "");
		if (str[0]) {
			setgroup(str, grpnum);
		}

		str = boaGetVar(wp, "itfsAvail", "");
		if (str[0]) {
			setgroup(str, 0);
		}

		setup_bridge_grouping(ADD_RULE);
#ifdef CONFIG_RTK_L34_ENABLE // Rostelecom, Port Binding function
		unsigned int set_wanlist = 0;

		if (set_port_binding_mask(&set_wanlist) > 0)
		{
			rg_set_port_binding_mask(set_wanlist);
		}
#ifdef CONFIG_00R0
		// update DNS info
		int sys_pid = -1;
		sys_pid = read_pid("/var/run/systemd.pid");
		if (sys_pid > 0) {
			kill(sys_pid, SIGUSR1);
			sleep(1);	//wait a second for DNS updating
		}
#endif
#endif
		
#ifdef CONFIG_NET_IPGRE
		update_gre_ssid();
		stopGreQoS();
		setupGreQoS();
#endif
// Magician: Commit immediately
#ifdef COMMIT_IMMEDIATELY
		Commit();
#endif
	}

	submitUrl = boaGetVar(wp, "submit-url", "");
	OK_MSG(submitUrl);
}

int ifGroupList(int eid, request * wp, int argc, char **argv)
{
	int nBytesSent = 0;
	int i, ifnum, num;
	struct itfInfo itfs[MAX_NUM_OF_ITFS];
	char groupitf[512], groupval[512], availitf[512], availval[512];
	char *ptr;

#ifndef CONFIG_GENERAL_WEB
	nBytesSent += boaWrite(wp, "<tr><font size=2>"
			       "<td align=center bgcolor=\"#808080\">%s</td>\n"
			       "<td align=center bgcolor=\"#808080\">%s</td></font></tr>\n",multilang(LANG_SELECT),multilang(LANG_INTERFACES));
#else
	nBytesSent += boaWrite(wp, "<div class=\"data_common data_vertical\">\n<table>\n");
	nBytesSent += boaWrite(wp, "<tr>"
			       "<th align=center>%s</th>\n"
			       "<th align=center>%s</th></tr>\n",multilang(LANG_SELECT),multilang(LANG_INTERFACES));
#endif
	// Show default group
	ifnum = get_group_ifinfo(itfs, MAX_NUM_OF_ITFS, 0);
	availitf[0] = availval[0] = '\0';
	if (ifnum > 0) {
		strncat(availitf, itfs[0].name, 64);
		ptr = availval + snprintf(availval, 64, "%u",
			 IF_ID(itfs[0].ifdomain, itfs[0].ifid));
		ifnum--;
		for (i = 1; i <= ifnum; i++) {
			strncat(availitf, ", ", 64);
			strncat(availitf, itfs[i].name, 64);
			ptr += snprintf(ptr, 64, ", %u",
				 IF_ID(itfs[i].ifdomain, itfs[i].ifid));
		}
	}
#ifndef CONFIG_GENERAL_WEB
	nBytesSent += boaWrite(wp, "<tr><font size=2>"
			       "<td align=center bgcolor=\"#C0C0C0\">Default</td>\n"
			       "<td align=center bgcolor=\"#C0C0C0\">%s</td></font></tr>\n",
			       availitf);
#else
	nBytesSent += boaWrite(wp, "<tr>"
			       "<td align=center>Default</td>\n"
			       "<td align=center>%s</td></tr>\n",
			       availitf);
#endif
	// Show the specified groups
#ifdef CONFIG_00R0
	for (num = 1; num <IFGROUP_NUM; num++) {
#else
	for (num = 1; num <= 4; num++) {
#endif
		ifnum = get_group_ifinfo(itfs, MAX_NUM_OF_ITFS, num);
		groupitf[0] = groupval[0] = '\0';
		if (ifnum > 0) {
			strncat(groupitf, itfs[0].name, 64);
			ptr = groupval + snprintf(groupval, 64, "%u",
				 IF_ID(itfs[0].ifdomain, itfs[0].ifid));
			ifnum--;
			for (i = 1; i <= ifnum; i++) {
				strncat(groupitf, ", ", 64);
				strncat(groupitf, itfs[i].name, 64);
				ptr += snprintf(ptr, 64, ", %u",
					 IF_ID(itfs[i].ifdomain, itfs[i].ifid));
			}
		}
#ifndef CONFIG_GENERAL_WEB
		nBytesSent += boaWrite(wp, "<tr><font size=\"2\">"
				       "<td align=center bgcolor=\"#C0C0C0\"><input type=\"radio\" name=\"select\""
				       " value=\"s%d\" onClick=\"postit('%s','%s','%s','%s')\"</td>\n",
				       num, groupitf, groupval, availitf, availval);
		nBytesSent +=
		    boaWrite(wp,
			     "<td align=center bgcolor=\"#C0C0C0\">%s</td></font></tr>\n",
			     groupitf);
#else
		nBytesSent += boaWrite(wp, "<tr>"
				       "<td align=center><input type=\"radio\" name=\"select\""
				       " value=\"s%d\" onClick=\"postit('%s','%s','%s','%s')\"</td>\n",
				       num, groupitf, groupval, availitf, availval);
		nBytesSent +=
		    boaWrite(wp,
			     "<td align=center>%s</td></tr>\n",
			     groupitf);
#endif
	}
#ifdef CONFIG_GENERAL_WEB
	nBytesSent += boaWrite(wp, "</table>\n</div>");
#endif
	return nBytesSent;
}

