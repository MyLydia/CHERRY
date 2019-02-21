/*
 *      Web server handler routines for NET
 *
 */

/*-- System inlcude files --*/
#include <config/autoconf.h>
#include "../webs.h"
#include "webform.h"
#include "mib.h"
#include "utility.h"
#ifdef CONFIG_RTK_L34_ENABLE
#include "../rtusr_rg_api.h"
#endif
#include <stdlib.h>

#define LANIF_NUM	PMAP_ITF_END
struct vlan_pair {
	unsigned short vid_a;
	unsigned short vid_b;
#ifdef CONFIG_RTK_L34_ENABLE
	unsigned short rg_vbind_entryID;
#endif
};

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

int initPagePBind(int eid, request * wp, int argc, char ** argv)
{
	int total, i, k, chainid;
	char vlan_str[40]={0};
	char vlan_str_tmp[40]={0};	
	struct vlan_pair *vid_pair;
	MIB_CE_PORT_BINDING_T pbEntry;
	
	total = mib_chain_total(MIB_PORT_BINDING_TBL);
	
	for (i=0; i<total; i++) {
		chainid = i;
#ifdef WLAN_SUPPORT
#if defined(CONFIG_YUEME) && defined(CONFIG_LUNA_DUAL_LINUX)
		if (i >= PMAP_WLAN0 && i <= PMAP_WLAN0_VAP_END) {
			chainid += (WLAN_MAX_ITF_INDEX);
		}
		else if(i >= PMAP_WLAN1 && i <= PMAP_WLAN1_VAP_END) {
			chainid -= (WLAN_MAX_ITF_INDEX);
		}
#endif
#endif
		mib_chain_get(MIB_PORT_BINDING_TBL, chainid, (void*)&pbEntry);
		vid_pair = (struct vlan_pair *)&pbEntry.pb_vlan0_a;
		boaWrite(wp, "setValue('Mode%d', %d);\n\t", i, pbEntry.pb_mode);
		if (pbEntry.pb_mode == 0) {
			boaWrite(wp, "setValue('VLAN%d', '');\n\t", i);
			continue;
		}
		vlan_str[0]='\0';
		for (k=0; k<4; k++) {
			if (vid_pair[k].vid_a) {
				if (k==0)
					sprintf(vlan_str, "%d/%d", vid_pair[k].vid_a, vid_pair[k].vid_b);
				else
				{
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
					sprintf(vlan_str, "%s,%d/%d", vlan_str_tmp, vid_pair[k].vid_a, vid_pair[k].vid_b);
#else
					sprintf(vlan_str, "%s;%d/%d", vlan_str_tmp, vid_pair[k].vid_a, vid_pair[k].vid_b);
#endif
				}
				strncpy(vlan_str_tmp,vlan_str,sizeof(vlan_str));				
			}
		}
		boaWrite(wp, "setValue('VLAN%d', '%s');\n\t", i, vlan_str);
	}
}

void formVlanMapping(request * wp, char *path, char *query)
{
	char *strData;
	char 			*submitUrl;
	int total, i, ifidx, nVal, org_mode;
	char tmpBuf[100];
	MIB_CE_PORT_BINDING_T pbEntry;
	
	total = mib_chain_total(MIB_PORT_BINDING_TBL);
	if (total == 0) {
		memset(&pbEntry, 0, sizeof(MIB_CE_PORT_BINDING_T));
		for (i=0; i<LANIF_NUM; i++) {
			mib_chain_add(MIB_PORT_BINDING_TBL, (void *)&pbEntry);
		}
	}
	strData = boaGetVar(wp, "if_index", "");
	ifidx = atoi(strData);
	if (ifidx < 0 || ifidx >= LANIF_NUM) {
		strcpy(tmpBuf, "error");
		goto setErr_vmap;
	}
#ifdef WLAN_SUPPORT
#if defined(CONFIG_YUEME) && defined(CONFIG_LUNA_DUAL_LINUX)
	if (ifidx >= PMAP_WLAN0 && ifidx <= PMAP_WLAN0_VAP_END) {
		ifidx += WLAN_MAX_ITF_INDEX;
	}
	else if (ifidx >= PMAP_WLAN1 && ifidx <= PMAP_WLAN1_VAP_END) {
		ifidx -= WLAN_MAX_ITF_INDEX;
	}
#endif
#endif

	mib_chain_get(MIB_PORT_BINDING_TBL, ifidx, (void*)&pbEntry);
#ifdef CONFIG_RTK_L34_ENABLE
	RG_flush_vlanBinding(ifidx);
#endif
	
	org_mode = pbEntry.pb_mode;
	strData = boaGetVar(wp, "Frm_Mode", "");
	nVal = atoi(strData);
	pbEntry.pb_mode = nVal;

	strData = boaGetVar(wp, "Frm_VLAN0a", "");
	nVal = atoi(strData);
	pbEntry.pb_vlan0_a = nVal;
	strData = boaGetVar(wp, "Frm_VLAN0b", "");
	nVal = atoi(strData);
	pbEntry.pb_vlan0_b = nVal;

	strData = boaGetVar(wp, "Frm_VLAN1a", "");
	nVal = atoi(strData);
	pbEntry.pb_vlan1_a = nVal;
	strData = boaGetVar(wp, "Frm_VLAN1b", "");
	nVal = atoi(strData);
	pbEntry.pb_vlan1_b = nVal;

	strData = boaGetVar(wp, "Frm_VLAN2a", "");
	nVal = atoi(strData);
	pbEntry.pb_vlan2_a = nVal;
	strData = boaGetVar(wp, "Frm_VLAN2b", "");
	nVal = atoi(strData);
	pbEntry.pb_vlan2_b = nVal;

	strData = boaGetVar(wp, "Frm_VLAN3a", "");
	nVal = atoi(strData);
	pbEntry.pb_vlan3_a = nVal;
	strData = boaGetVar(wp, "Frm_VLAN3b", "");
	nVal = atoi(strData);
	pbEntry.pb_vlan3_b = nVal;

	if((unsigned char)VLAN_BASED_MODE == pbEntry.pb_mode)
	{
		struct vlan_pair *vid_pair;
		int k;
		int ifindex;
		MIB_CE_ATM_VC_T vc_Entry;
		
		vid_pair = (struct vlan_pair *)&pbEntry.pb_vlan0_a;

		// because there are only 4 pairs~
		for (k=0; k<4; k++)
		{
			//Be sure the content of vlan-mapping exsit!
			if (vid_pair[k].vid_a)
			{				
				ifindex = find_wanif_by_vlanid(vid_pair[k].vid_b, &vc_Entry);					

				//this vid_pair does not match any wan interface!
				if(ifindex < 0)
				{
					sprintf(tmpBuf, "index[%d] vlan %d does not match any wan interface!", k, vid_pair[k].vid_b);
					goto setErr_vmap;
				}
/*
				if((vid_pair[k].vid_a == vid_pair[k].vid_b) && (CHANNEL_MODE_BRIDGE != vc_Entry.cmode))
				{
					sprintf(tmpBuf, "index[%d] vlan %d/%d must not be same for route wan interface!", 
							k, vid_pair[k].vid_a, vid_pair[k].vid_b);
					goto setErr_vmap;
				}
*/
			}
		}
	}
	
	mib_chain_update(MIB_PORT_BINDING_TBL, (void *)&pbEntry, ifidx);
	// sync with port-based mapping
	//if (pbEntry.pb_mode!=0 && org_mode != pbEntry.pb_mode)
	//	sync_itfGroup(ifidx);
#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif

	setupnewEth2pvc();
	
	submitUrl = boaGetVar(wp, "submit-url", "");   // hidden page

	if (submitUrl[0])
		boaRedirect(wp, submitUrl);
	else
		boaDone(wp, 200);
	return;
setErr_vmap:
	ERR_MSG(tmpBuf);
}

#ifdef CONFIG_CMCC_MULTICAST_CROSS_VLAN_SUPPORT
int initCrossVlan(int eid, request * wp, int argc, char ** argv)
{
	MIB_MULTICAST_CROSS_VLAN_T entry;
	
	if(!mib_chain_get(MIB_MULTICAST_CROSS_VLAN_TBL, 0, (void*)&entry))
	{
		boaWrite(wp, "vlanArray[0] = 0;\n");
		boaWrite(wp, "vlanArray[1] = 0;\n");
		boaWrite(wp, "vlanArray[2] = 0;\n");
		boaWrite(wp, "vlanArray[3] = 0;\n");
	}
	else
	{
		boaWrite(wp, "vlanArray[0] = %d;\n", entry.cross_vlan0);
		boaWrite(wp, "vlanArray[1] = %d;\n", entry.cross_vlan1);
		boaWrite(wp, "vlanArray[2] = %d;\n", entry.cross_vlan2);
		boaWrite(wp, "vlanArray[3] = %d;\n", entry.cross_vlan3);
	}
}

void formCrossVlan(request * wp, char *path, char *query)
{
	char *strData;
	char *submitUrl;
	char tmpBuf[100];
	unsigned short vlan;
	int total;
	MIB_MULTICAST_CROSS_VLAN_T entry;

	total = mib_chain_total(MIB_MULTICAST_CROSS_VLAN_TBL);
	if (total == 0) {
		memset(&entry, 0, sizeof(MIB_MULTICAST_CROSS_VLAN_T));		
		mib_chain_add(MIB_MULTICAST_CROSS_VLAN_TBL, (void *)&entry);
	}
	
	mib_chain_get(MIB_MULTICAST_CROSS_VLAN_TBL, 0, (void*)&entry);
	
	strData = boaGetVar(wp, "crossLan0", "");
	if(strData[0])
	{
		vlan = atoi(strData);
		entry.cross_vlan0 = vlan;
	}

	strData = boaGetVar(wp, "crossLan1", "");
	if(strData[0])
	{
		vlan = atoi(strData);
		entry.cross_vlan1 = vlan;
	}

	strData = boaGetVar(wp, "crossLan2", "");
	if(strData[0])
	{
		vlan = atoi(strData);
		entry.cross_vlan2 = vlan;
	}

	strData = boaGetVar(wp, "crossLan3", "");
	if(strData[0])
	{
		vlan = atoi(strData);
		entry.cross_vlan3 = vlan;
	}
	
	mib_chain_update(MIB_MULTICAST_CROSS_VLAN_TBL, (void *)&entry, 0);

#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif

#ifdef CONFIG_RTK_L34_ENABLE
	set_multicast_cross_vlan();
#endif

	submitUrl = boaGetVar(wp, "submit-url", "");   // hidden page	
	if (submitUrl[0])
		boaRedirect(wp, submitUrl);
	else
		boaDone(wp, 200);
	return;
	
setErr_vmap:
	ERR_MSG(tmpBuf);
}
#endif

#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
void formIPv6Binding(request * wp, char *path, char *query)
{
	char	*str, *submitUrl;
	char tmpBuf[100];
	MIB_IPV6_BINDING_T entry, Entry;
	int delNum = 0;
	unsigned int i,totalEntry;

	memset( &entry, 0, sizeof(MIB_IPV6_BINDING_T));
	memset( &Entry, 0, sizeof(MIB_IPV6_BINDING_T));

	totalEntry = mib_chain_total(MIB_IPV6_BINDING); /* get chain record size */
	// Delete
	str = boaGetVar(wp, "delV6Binding", "");
	if (str[0]) {
		unsigned int idx;	
		
		for (i=0; i<totalEntry; i++) {
			sprintf(tmpBuf, "del%d", i);
			str = boaGetVar(wp, tmpBuf, "");
			if(!strncmp(str, "on", 2))
			{
				if (!mib_chain_get(MIB_IPV6_BINDING, i-delNum, (void *)&Entry)) {
					strcpy(tmpBuf, errGetEntry);
					goto setErr;
				}

				// delete from chain record
				if(mib_chain_delete(MIB_IPV6_BINDING, i-delNum) != 1) {
					strcpy(tmpBuf, "删除失败!");
					goto setErr;
				}
				delNum++;
			}
		}
		if(delNum == 0)
		{
			strcpy(tmpBuf, "没有选择删除的项目!");
			goto setErr;
		}
		else
		{
			ipv6_binding_update();
			goto setOk;
		}	
	}

	// Add
	str = boaGetVar(wp, "addV6Route", "");
	if (str && str[0]) {
		if(totalEntry >= CONFIG_IPV6_BINDING_NUM)
		{
			strcpy(tmpBuf, "已达最大绑定数!");
			goto setErr;
		}
		str = boaGetVar(wp, "addr", "");
		if (str[0])
		    strcpy(entry.ipv6_addr,str);
		str = boaGetVar(wp, "prefixLen", "");
		if ( str && str[0] ) {
			strcat(entry.ipv6_addr, "/");
			strcat(entry.ipv6_addr, str);
		}
		str = boaGetVar(wp, "bindmode", "");
		if (str[0] == '0')
		{
			entry.binding_mode = 0;
			entry.binding_port =atoi(boaGetVar(wp, "portList", ""));	 
			memset( &Entry, 0, sizeof(MIB_IPV6_BINDING_T));
			for (i=0; i<totalEntry; i++) {
				if (!mib_chain_get(MIB_IPV6_BINDING, i, (void *)&Entry)) {
					strcpy(tmpBuf, errGetEntry);
					goto setErr;
				}
				if((entry.binding_mode == Entry.binding_mode) && (entry.binding_port == Entry.binding_port) && 
					!strcmp(entry.ipv6_addr,Entry.ipv6_addr))
				{
					strcpy(tmpBuf, "该绑定已存在，请先删除对应绑定");
					goto setErr;
					break;
				}
			}
		}
		else if(str[0] == '1')
		{
			entry.binding_mode = 1;
			entry.binding_vlan = atoi(boaGetVar(wp, "vlan_id", ""));
			memset( &Entry, 0, sizeof(MIB_IPV6_BINDING_T));
			for (i=0; i<totalEntry; i++) {
				if (!mib_chain_get(MIB_IPV6_BINDING, i, (void *)&Entry)) {
					strcpy(tmpBuf, errGetEntry);
					goto setErr;
				}
				if((entry.binding_mode == Entry.binding_mode) && (entry.binding_vlan == Entry.binding_vlan) &&
					!strcmp(entry.ipv6_addr,Entry.ipv6_addr))
				{
					strcpy(tmpBuf, "该绑定已存在，请先删除对应绑定");
					goto setErr;
					break;
				}
			}
		}
		mib_chain_add(MIB_IPV6_BINDING, (unsigned char*)&entry);
		ipv6_binding_update();
		mib_update(CURRENT_SETTING, CONFIG_MIB_ALL);
	}
setOk:
// Magician: Commit immediately
#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif
	submitUrl = boaGetVar(wp, "submit-url", "");
	if (submitUrl[0])
		boaRedirect(wp, submitUrl);
	else
		boaDone(wp, 200);
  	return;
setErr:
	ERR_MSG(tmpBuf);
}


int showIPv6Binding (int eid, request * wp, int argc, char **argv)
{
	int nBytesSent=0;
	unsigned int entryNum, i;
	MIB_IPV6_BINDING_T Entry;
	char *portName[6] = {"LAN1","LAN2","LAN3","LAN4","SSID1","SSID2"};

	entryNum = mib_chain_total(MIB_IPV6_BINDING);
	nBytesSent += boaWrite(wp, "<tr>"
	"<td align=center>IP地址/前缀</td>\n"
	"<td align=center>绑定模式</td>\n"
	"<td align=center>绑定配置</td>\n"
	"<td align=center>删除</td>\n"
	"</tr>\n");

	for (i=0; i<entryNum; i++) {
		char str_vlan[4];
		if (!mib_chain_get(MIB_IPV6_BINDING, i, (void *)&Entry))
		{
  			boaError(wp, 400, "Get chain record error!\n");
			return -1;
		}
		sprintf(str_vlan,"%d", Entry.binding_vlan);
		nBytesSent += boaWrite(wp, "<tr>"
		"<td align=center width=\"8%%\">%s</td>\n"
		"<td align=center width=\"8%%\">%s</td>\n"
		"<td align=center width=\"8%%\">%s</td>\n"
		"<td align=center width=\"5%%\"><input type=\"checkbox\" name=\"del%d\""
		"></td>\n"		
		"</tr>\n",
		Entry.ipv6_addr, Entry.binding_mode ? "VLAN绑定" : "端口绑定", Entry.binding_mode ? str_vlan : portName[Entry.binding_port],  
		i);
	}
	return 0;
}
#endif

