/*
 *      Web server handler routines for Routing stuffs
 *
 */


/*-- System inlcude files --*/
#include <string.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <net/route.h>

/*-- Local inlcude files --*/
#include "../webs.h"
#include "webform.h"
#include "mib.h"
#include "utility.h"
#include "../../port.h"
#include "../rtusr_rg_api.h"
#if !defined(CONFIG_CMCC) && !defined(CONFIG_CU)
#include "utf8_string.h"
#endif

///////////////////////////////////////////////////////////////////
void formRoute(request * wp, char *path, char *query)
{
	char	*str, *submitUrl;
	char tmpBuf[100];
	//struct rtentry rt;
	struct in_addr *addr;
	MIB_CE_IP_ROUTE_T entry;
	int xflag, isnet;
	int skfd;
	int intVal;
	//char ifname[16];
#ifndef NO_ACTION
	int pid;
#endif

	memset( &entry, 0, sizeof(MIB_CE_IP_ROUTE_T));

#ifdef DEFAULT_GATEWAY_V2
	// Jenny, Default Gateway setting
	str = boaGetVar(wp, "dgwSet", "");
	if (str[0]) {
		unsigned int dgw;

		str = boaGetVar(wp, "droute", "");
		dgw = (unsigned int)atoi(str);
		if (!mib_set(MIB_ADSL_WAN_DGW_ITF, (void *)&dgw)) {
			strcpy(tmpBuf, "Set Default Gateway error!");
			goto setErr_route;
		}
		goto setOk_route;
	}
#endif

	// Delete
	str = boaGetVar(wp, "delRoute", "");
	if (str[0]) {
		unsigned int i;
		unsigned int idx;
		MIB_CE_IP_ROUTE_T Entry;
		unsigned int totalEntry = mib_chain_total(MIB_IP_ROUTE_TBL); /* get chain record size */
		str = boaGetVar(wp, "select", "");

		if (str[0]) {
			for (i=0; i<totalEntry; i++) {
				idx = totalEntry-i-1;
				snprintf(tmpBuf, 4, "s%d", idx);

				if ( !gstrcmp(str, tmpBuf) ) {
					//struct sockaddr_in *s_in;
					/* get the specified chain record */
					if (!mib_chain_get(MIB_IP_ROUTE_TBL, idx, (void *)&Entry)) {
						strcpy(tmpBuf, errGetEntry);
						goto setErr_route;
					}
					
					route_cfg_modify(&Entry, 1, idx);//This API will update mib entry, so it has to be called before delete mib entry.
					
					// delete from chain record
					if(mib_chain_delete(MIB_IP_ROUTE_TBL, idx) != 1) {
						strcpy(tmpBuf, "ɾ��ʧ��!"); //Delete chain record error!
						goto setErr_route;
					}

					goto setOk_route;
				}
			} // end of for
		}
		else {
			strcpy(tmpBuf, "û��ѡ��ɾ������Ŀ!"); //There is no item selected to delete!
			goto setErr_route;
		}

		goto setOk_route;
	}

	// parse input
	str = boaGetVar(wp, "destNet", "");
	if (!inet_aton(str, (struct in_addr *)&entry.destID)) {
		snprintf(tmpBuf, 100, "����: �޷�����Ŀ�� %s", str); //Error: can't resolve dest
		goto setErr_route;
	}

	str = boaGetVar(wp, "subMask", "");
	if (str[0]) {
		if (!isValidNetmask(str, 1)) {
			snprintf(tmpBuf, 100, "����: ���Ϸ����������� %s", str); //Error: Invalid subnet mask
			goto setErr_route;
		}
		if (!inet_aton(str, (struct in_addr *)&entry.netMask)) {
			snprintf(tmpBuf, 100, "����: �޷��������� %s", str); //Error: can't resolve mask 
			goto setErr_route;
		}
	}

#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	entry.FWMetric = 0;

	entry.ifIndex = DUMMY_IFINDEX;
	str = boaGetVar(wp, "intfEnable", "0");
	entry.intfEnable = 0;
	if(atoi(str)==1){
		entry.intfEnable = 1;
		str = boaGetVar(wp, "interface", "");
		if ( str ) {
			if (!string_to_dec(str, &intVal)) {
				snprintf(tmpBuf, 100, "����: ifname ���� %s", str); //Error: ifname error
				goto setErr_route;
			}
			entry.ifIndex = intVal;
		}
	}

#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	str = boaGetVar(wp, "nextHopEnable", "0");
	entry.nextHopEnable = 0;
	if(atoi(str)==1){
		entry.nextHopEnable = 1;
#endif
		str = boaGetVar(wp, "nextHop", "");
		if (!str && (entry.ifIndex == DUMMY_IFINDEX)) {
			snprintf(tmpBuf, 100, "����: �޷�������һ���� %s", str); //Error: can't resolve next tHop
			goto setErr_route;
		} else if (str[0]) {
			if (!inet_aton(str, (struct in_addr *)&entry.nextHop)) {
				snprintf(tmpBuf, 100, "����: �޷�������һ���� %s", str); //Error: can't resolve next tHop
				goto setErr_route;
			}
		}
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	}
#endif
	
	entry.Enable = 1;
#else
	str = boaGetVar(wp, "metric", "");
	if ( str[0] ) {
		if (!string_to_dec(str, &intVal)) {
			snprintf(tmpBuf, 100, "����: Metric"); //Error: Metric
			goto setErr_route;
		}

		if ((intVal < 0) || (intVal > 16)) {
			snprintf(tmpBuf, 100, "����: Metric ���� 0 to 16"); //Error: Metric must be 0 to 16
			goto setErr_route;
		}
		entry.FWMetric = intVal;
	}
	
	entry.ifIndex = DUMMY_IFINDEX;
	str = boaGetVar(wp, "interface", "");
	if ( str ) {
		if (!string_to_dec(str, &intVal)) {
			snprintf(tmpBuf, 100, "����: ifname ���� %s", str); //Error: ifname error
			goto setErr_route;
		}
		entry.ifIndex = intVal;
	}

	str = boaGetVar(wp, "nextHop", "");
	if (!str && (entry.ifIndex == DUMMY_IFINDEX)) {
		snprintf(tmpBuf, 100, "����: �޷�������һ���� %s", str); //Error: can't resolve next tHop
		goto setErr_route;
	} else if (str[0]) {
		if (!inet_aton(str, (struct in_addr *)&entry.nextHop)) {
			snprintf(tmpBuf, 100, "����: �޷�������һ���� %s", str); //Error: can't resolve next tHop
			goto setErr_route;
		}
	}

	str = boaGetVar(wp, "enable", "");
	if ( str && str[0] ) {
		entry.Enable = 1;
	}
#endif

	// Update
	str = boaGetVar(wp, "updateRoute", "");
	if (str && str[0]) {
		char *select, strBuf[8];
		int i, idx;
		MIB_CE_IP_ROUTE_T tmp;
		unsigned int totalEntry = mib_chain_total(MIB_IP_ROUTE_TBL); /* get chain record size */

		select = boaGetVar(wp, "select", "");
		if (!select )
			goto setOk_route;

		for (i=0; i<totalEntry; i++) {
			idx = totalEntry-i-1;
			snprintf(strBuf, 4, "s%d", idx);

			if (!gstrcmp(select, strBuf)) {
				if (mib_chain_get(MIB_IP_ROUTE_TBL, idx, (void *)&tmp)) {
					route_cfg_modify(&tmp, 1, idx); // delete original route
					entry.InstanceNum = tmp.InstanceNum; /*keep old instancenum, jiunming*/
				}

				if (!checkRoute(entry, idx)) {	// Jenny
					route_cfg_modify(&tmp, 0, idx);
					strcpy(tmpBuf, Tinvalid_rule);
					goto setErr_route;
				}
				route_cfg_modify(&entry, 0, idx); // add new route
				mib_chain_update(MIB_IP_ROUTE_TBL, &entry, idx);

				goto setOk_route;
			}
		} // end of for

		goto setOk_route;
	}

	// Add
	str = boaGetVar(wp, "addRoute", "");
	if (str && str[0]) {
		int totalEntry = 0;
		if (!checkRoute(entry, -1)) {	// Jenny
			strcpy(tmpBuf, Tinvalid_rule);
			goto setErr_route;
		}
#ifdef CONFIG_RTK_L34_ENABLE
		{
			int remained=0;
			remained = Check_RG_Intf_Count();
			if(remained == 0){
				printf("%s-%d remained=%d\n",__func__,__LINE__,remained);
				strcpy(tmpBuf, strTableFull);
				goto setErr_route;
			}
		}
#endif
		printf("add route\n");
#ifdef CONFIG_RTK_L34_ENABLE
		entry.rg_staticRoute_idx = -1;//initail value 
#endif
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)		
		entry.rg_acl_idx=-1;
#endif
		/* Clean out the RTREQ sgructure. */
		intVal = mib_chain_add(MIB_IP_ROUTE_TBL, (unsigned char*)&entry);
		if (intVal == 0) {
			strcpy(tmpBuf, Tadd_chain_error);
			goto setErr_route;
		}
		else if (intVal == -1) {
			strcpy(tmpBuf, strTableFull);
			goto setErr_route;
		}
		/* get chain record size */
		totalEntry = mib_chain_total(MIB_IP_ROUTE_TBL); 

		route_cfg_modify(&entry, 0, totalEntry-1);
	}

setOk_route:
// Magician: Commit immediately
#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif

#ifndef NO_ACTION
	pid = fork();
	if (pid)
		waitpid(pid, NULL, 0);
	else if (pid == 0) {
		snprintf(tmpBuf, 100, "%s/%s", _CONFIG_SCRIPT_PATH, _CONFIG_SCRIPT_PROG);
#ifdef HOME_GATEWAY
		execl( tmpBuf, _CONFIG_SCRIPT_PROG, "gw", "bridge", NULL);
#else
		execl( tmpBuf, _CONFIG_SCRIPT_PROG, "ap", "bridge", NULL);
#endif
		exit(1);
	}
#endif

	submitUrl = boaGetVar(wp, "submit-url", "");
	if (submitUrl[0])
		boaRedirect(wp, submitUrl);
	else
		boaDone(wp, 200);
  	return;

setErr_route:
	ERR_MSG(tmpBuf);
}
int GetDefaultGateway(int eid, request * wp, int argc, char **argv)
{
#ifdef DEFAULT_GATEWAY_V2
	unsigned int dgw;
	mib_get(MIB_ADSL_WAN_DGW_ITF, (void *)&dgw);
	//boaWrite(wp, "<script>\n"
	//				"	document.route.droute.value = %u;\n"
	//				"</script>", dgw);
#ifdef AUTO_PPPOE_ROUTE
	if (dgw == DGW_AUTO)
		boaWrite(wp, "	document.forms[0].droute[0].checked = true;\n");
	else
#endif
		boaWrite(wp, "	document.forms[0].droute[1].checked = true;\n");
#endif
}

#ifdef CONFIG_IPV6
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
void formIPv6Route(request * wp, char *path, char *query)
{
	char	*str, *submitUrl;
	char tmpBuf[100];
	//struct rtentry rt;
	struct in_addr *addr;
	MIB_CE_IPV6_ROUTE_T entry;
	int xflag, isnet, ret;
	int skfd;
	int intVal;
	unsigned int totalEntry;
	//char ifname[16];
#ifndef NO_ACTION
	int pid;
#endif

	memset( &entry, 0, sizeof(MIB_CE_IPV6_ROUTE_T));

	// Delete
	str = boaGetVar(wp, "delV6Route", "");
	if (str[0]) {
		unsigned int i;
		unsigned int idx;
		MIB_CE_IPV6_ROUTE_T Entry;
		unsigned int totalEntry = mib_chain_total(MIB_IPV6_ROUTE_TBL); /* get chain record size */
		str = boaGetVar(wp, "select", "");

		if (str[0]) {
			for (i=0; i<totalEntry; i++) {
				idx = totalEntry-i-1;
				snprintf(tmpBuf, 4, "s%d", idx);

				if ( !gstrcmp(str, tmpBuf) ) {
					//struct sockaddr_in *s_in;
					/* get the specified chain record */
					if (!mib_chain_get(MIB_IPV6_ROUTE_TBL, idx, (void *)&Entry)) {
						strcpy(tmpBuf, errGetEntry);
						goto setErr_route;
					}

					route_v6_cfg_modify(&Entry, 1, idx);

					// delete from chain record
					if(mib_chain_delete(MIB_IPV6_ROUTE_TBL, idx) != 1) {
						strcpy(tmpBuf, "ɾ��ʧ��!");
						goto setErr_route;
					}

					goto setOk_route;
				}
			} // end of for
		}
		else {
			strcpy(tmpBuf, "û��ѡ��ɾ������Ŀ!");
			goto setErr_route;
		}

		goto setOk_route;
	}

	// parse input
	str = boaGetVar(wp, "destNet", "");
	if (str[0])
	    strcpy(entry.Dstination,str);

	entry.DstIfIndex = DUMMY_IFINDEX;
	str = boaGetVar(wp, "interface", "");
	if ( str ) {
		if (!string_to_dec(str, &intVal)) {
			snprintf(tmpBuf, 100, "����: ifname ���� %s", str);
			goto setErr_route;
		}
		entry.DstIfIndex = intVal;
	}

#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	str = boaGetVar(wp, "nextHopEnable", "0");
	printf("nextHopEnable is %s\n", str);
	entry.nextHopEnable = 0;
	if(atoi(str)==1){
		entry.nextHopEnable = 1;
#endif
		str = boaGetVar(wp, "nextHop", "");
		//nextHop = ntohl(inet_addr(str));	// Jenny, for checking duplicated destination address
		if (!str && (entry.DstIfIndex == DUMMY_IFINDEX)) {
			snprintf(tmpBuf, 100, "����: �޷�������һ���� %s", str);
			goto setErr_route;
		} else if (str[0]) {
			struct in6_addr tmp;
			strcpy(entry.NextHop, str);
			if (!inet_pton(AF_INET6, str, (struct in6_addr *)&tmp)) {
				snprintf(tmpBuf, 100, "����: �޷�������һ���� %s", str);
				goto setErr_route;
			}
		}
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	}
#endif

	str = boaGetVar(wp, "enable", "");
	if ( str && str[0] ) {
		entry.Enable = 1;
	}

	str = boaGetVar(wp, "prefixLen", "");
	if ( str && str[0] ) {
		strcat(entry.Dstination, "/");
		strcat(entry.Dstination, str);
	}

	// Update
	str = boaGetVar(wp, "updateV6Route", "");
	if (str && str[0]) {
		//char *select, tmpBuf[8];
		char *select, strBuf[8];
		int i, idx;
		MIB_CE_IPV6_ROUTE_T tmp;
		totalEntry = mib_chain_total(MIB_IPV6_ROUTE_TBL); /* get chain record size */

		select = boaGetVar(wp, "select", "");
		if (!select )
			goto setOk_route;

		for (i=0; i<totalEntry; i++) {
			idx = totalEntry-i-1;
			snprintf(strBuf, 4, "s%d", idx);
			//snprintf(tmpBuf, 4, "s%d", idx);

			//if ( !gstrcmp(select, tmpBuf) ) {
			if (!gstrcmp(select, strBuf)) {
				if (mib_chain_get(MIB_IPV6_ROUTE_TBL, idx, (void *)&tmp)) {
					route_v6_cfg_modify(&tmp, 1, idx);
					entry.InstanceNum = tmp.InstanceNum; /*keep old instancenum, jiunming*/
					entry.FWMetric = tmp.FWMetric;
				}
#if 0
				if (!checkIPv6Route(&entry)) {	// Jenny
					route_v6_cfg_modify(&tmp, 0);
					strcpy(tmpBuf, Tinvalid_rule);
					goto setErr_route;
				}
#endif

				route_v6_cfg_modify(&entry, 0, idx);
				mib_chain_update(MIB_IPV6_ROUTE_TBL, &entry, idx);

				goto setOk_route;
			}
		} // end of for

		goto setOk_route;
	}
#ifdef CONFIG_RTK_L34_ENABLE
	entry.rg_staticRoute_idx = -1;
#endif
	// Add
	str = boaGetVar(wp, "addV6Route", "");
	if (str && str[0]) {
		intVal = checkIPv6Route(&entry);
		if (intVal == 0) {
			strcpy(tmpBuf, "���·���Ѵ�����MIB!");
			goto setErr_route;
		}
		entry.FWMetric = 1;

		intVal = mib_chain_add(MIB_IPV6_ROUTE_TBL, (unsigned char*)&entry);
		if (intVal == 0) {
			strcpy(tmpBuf, Tadd_chain_error);
			goto setErr_route;
		}
		else if (intVal == -1) {
			strcpy(tmpBuf, strTableFull);
			goto setErr_route;
		}
		
		totalEntry = mib_chain_total(MIB_IPV6_ROUTE_TBL); 
		route_v6_cfg_modify(&entry, 0, totalEntry-1);
	}

setOk_route:
// Magician: Commit immediately
#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif

#ifndef NO_ACTION
	pid = fork();
	if (pid)
		waitpid(pid, NULL, 0);
	else if (pid == 0) {
		snprintf(tmpBuf, 100, "%s/%s", _CONFIG_SCRIPT_PATH, _CONFIG_SCRIPT_PROG);
#ifdef HOME_GATEWAY
		execl( tmpBuf, _CONFIG_SCRIPT_PROG, "gw", "bridge", NULL);
#else
		execl( tmpBuf, _CONFIG_SCRIPT_PROG, "ap", "bridge", NULL);
#endif
		exit(1);
	}
#endif

	submitUrl = boaGetVar(wp, "submit-url", "");
	if (submitUrl[0])
		boaRedirect(wp, submitUrl);
	else
		boaDone(wp, 200);
  	return;

setErr_route:
	ERR_MSG(tmpBuf);
}
#endif
#endif

#if defined(CONFIG_USER_ROUTED_ROUTED) && !defined(CONFIG_USER_ZEBRA_OSPFD_OSPFD)
void formRip(request * wp, char *path, char *query)
{
	char	*str, *submitUrl, *strVal;
	char tmpBuf[100];
	unsigned int rip_if;
	unsigned int entryNum, i;
	MIB_CE_RIP_T Entry;
#ifndef NO_ACTION
	int pid;
#endif

	// RIP Add
	str = boaGetVar(wp, "ripAdd", "");
	if (str[0]) {
		int intVal;
		str = boaGetVar(wp, "rip_if", "");
		rip_if = (unsigned int)atoi(str);

		// Check RIP table
		entryNum = mib_chain_total(MIB_RIP_TBL);
		for (i=0; i<entryNum; i++) {
			mib_chain_get(MIB_RIP_TBL, i, (void *)&Entry);
			if (Entry.ifIndex == rip_if) {
				strcpy(tmpBuf, "Entry already exists!");
				goto setErr_rip;
			}
		}

		memset(&Entry, '\0', sizeof(MIB_CE_RIP_T));
		Entry.ifIndex = rip_if;
		str = boaGetVar(wp, "receive_mode", "");
		if ( str[0]=='0' ) {
			Entry.receiveMode = RIP_NONE;    // None
		} else if ( str[0]=='1') {
			Entry.receiveMode = RIP_V1;      // RIPV1
		} else if ( str[0]=='2') {
			Entry.receiveMode = RIP_V2;      // RIPV2
		} else if ( str[0]=='3') {
			Entry.receiveMode = RIP_V1_V2;   // RIPV1 and RIPV2
		} else {
			strcpy(tmpBuf, "�趨RIP����ģʽʧ��!"); //Set RIP receive mode error!
			goto setErr_rip;
		}

		str = boaGetVar(wp, "send_mode", "");
		if ( str[0]=='0' ) {
			Entry.sendMode = RIP_NONE;    		// None
		} else if ( str[0]=='1') {
			Entry.sendMode = RIP_V1;      		// RIPV1
		} else if ( str[0]=='2') {
			Entry.sendMode = RIP_V2;      		// RIPV2
		} else if ( str[0]=='4') {
			Entry.sendMode = RIP_V1_COMPAT;      	// RIPV1COMPAT
		} else {
			strcpy(tmpBuf, "�趨RIP����ģʽʧ��!"); //Set RIP send mode error!
			goto setErr_rip;
		}

		intVal = mib_chain_add(MIB_RIP_TBL, (unsigned char*)&Entry);
		if (intVal == 0) {
			//boaWrite(wp, "%s", "Error: Add MIB_RIP_TBL chain record.");
			//return;
			strcpy(tmpBuf, "����: ����MIB_RIP_TBL chain recordʧ��"); //Error: Add MIB_RIP_TBL chain record.
			goto setErr_rip;
		}
		else if (intVal == -1) {
			strcpy(tmpBuf, strTableFull);
			goto setErr_rip;
		}
		goto setRefresh_rip;
	}

	// Delete all
	str = boaGetVar(wp, "ripDelAll", "");
	if (str[0]) {
		mib_chain_clear(MIB_RIP_TBL); /* clear chain record */
		goto setRefresh_rip;
	}

	/* Delete selected */
	str = boaGetVar(wp, "ripDel", "");
	if (str[0]) {
		unsigned int i;
		unsigned int idx;
		unsigned int deleted = 0;
		unsigned int totalEntry = mib_chain_total(MIB_RIP_TBL); /* get chain record size */

		for (i=0; i<totalEntry; i++) {

			idx = totalEntry-i-1;
			snprintf(tmpBuf, 20, "select%d", idx);
			strVal = boaGetVar(wp, tmpBuf, "");

			if ( !gstrcmp(strVal, "ON") ) {
				deleted ++;
				if(mib_chain_delete(MIB_RIP_TBL, idx) != 1) {
					strcpy(tmpBuf, "����: ɾ��MIB_RIP_TBL chain recordʧ��!"); //Delete MIB_RIP_TBL chain record error!
					goto setErr_rip;
				}
			}
		}
		if (deleted <= 0) {
			strcpy(tmpBuf, "û��ѡ��ɾ������Ŀ!"); //There is no item selected to delete!
			goto setErr_rip;
		}

		goto setRefresh_rip;
	}
	// RIP setting
	str = boaGetVar(wp, "ripSet", "");
	if (str[0]) {
		unsigned char ripVal;

		str = boaGetVar(wp, "rip_on", "");
		if (str[0] == '1')
			ripVal = 1;
		else
			ripVal = 0;	// default "off"
		if (!mib_set(MIB_RIP_ENABLE, (void *)&ripVal)) {
			strcpy(tmpBuf, "Set RIP error!");
			goto setErr_rip;
		}

		// Commented by Mason Yu
		/*
		str = boaGetVar(wp, "rip_ver", "");
		if (str[0] == '0')
			ripVal = 0;
		else
			ripVal = 1;	// default "v2"
		if (!mib_set(MIB_RIP_VERSION, (void *)&ripVal)) {
			strcpy(tmpBuf, "Set RIP error!");
			goto setErr_rip;
		}
		*/
	}

setOk_rip:
	startRip();

// Magician: Commit immediately
#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif

#ifndef NO_ACTION
	pid = fork();
	if (pid)
		waitpid(pid, NULL, 0);
	else if (pid == 0) {
		snprintf(tmpBuf, 100, "%s/%s", _CONFIG_SCRIPT_PATH, _CONFIG_SCRIPT_PROG);
#ifdef HOME_GATEWAY
		execl( tmpBuf, _CONFIG_SCRIPT_PROG, "gw", "bridge", NULL);
#else
		execl( tmpBuf, _CONFIG_SCRIPT_PROG, "ap", "bridge", NULL);
#endif
		exit(1);
	}
#endif

	submitUrl = boaGetVar(wp, "submit-url", "");
	//OK_MSG(submitUrl);
	if (submitUrl[0])
		boaRedirect(wp, submitUrl);
	else
		boaDone(wp, 200);
	return;

setRefresh_rip:
	startRip();

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

setErr_rip:
	ERR_MSG(tmpBuf);
}
#else
#ifdef CONFIG_USER_ZEBRA_OSPFD_OSPFD
void formRip(request * wp, char *path, char *query)
{
	char	*str, *submitUrl;
	char *strVal;
	char tmpBuf[100];
	unsigned char igpEnable;
#ifndef NO_ACTION
	int pid;
#endif

	//check if it is RIP
	strVal = boaGetVar(wp, "igp", "");
	if (strVal[0] == '0') {//RIP
		// RIP Add
		str = boaGetVar(wp, "ripAdd", "");
		if (str[0]) {
			unsigned int rip_if;
			unsigned int i;
			MIB_CE_RIP_T Entry;
			int intVal;

			memset(&Entry, '\0', sizeof(MIB_CE_RIP_T));

			str = boaGetVar(wp, "rip_if", "");
			rip_if = (unsigned char)atoi(str);
			Entry.ifIndex = rip_if;

			str = boaGetVar(wp, "receive_mode", "");
			if ( str[0]=='0' ) {
				Entry.receiveMode = RIP_NONE;    // None
			} else if ( str[0]=='1') {
				Entry.receiveMode = RIP_V1;      // RIPV1
			} else if ( str[0]=='2') {
				Entry.receiveMode = RIP_V2;      // RIPV2
			} else if ( str[0]=='3') {
				Entry.receiveMode = RIP_V1_V2;   // RIPV1 and RIPV2
			} else {
				strcpy(tmpBuf, "�趨RIP����ģʽʧ��!"); //Set RIP receive mode error!
				goto setErr_rip;
			}

			str = boaGetVar(wp, "send_mode", "");
			if ( str[0]=='0' ) {
				Entry.sendMode = RIP_NONE;    		// None
			} else if ( str[0]=='1') {
				Entry.sendMode = RIP_V1;      		// RIPV1
			} else if ( str[0]=='2') {
				Entry.sendMode = RIP_V2;      		// RIPV2
			} else if ( str[0]=='4') {
				Entry.sendMode = RIP_V1_COMPAT;      	// RIPV1COMPAT
			} else {
				strcpy(tmpBuf, "�趨RIP����ģʽʧ��!"); //Set RIP send mode error!
				goto setErr_rip;
			}

			intVal = mib_chain_add(MIB_RIP_TBL, (unsigned char*)&Entry);
			if (intVal == 0) {
				//boaWrite(wp, "%s", "Error: Add MIB_RIP_TBL chain record.");
				//return;
				strcpy(tmpBuf, "����: ����MIB_RIP_TBL chain recordʧ��"); //Error: Add MIB_RIP_TBL chain record.
				goto setErr_rip;
			}
			else if (intVal == -1) {
				strcpy(tmpBuf, strTableFull);
				goto setErr_rip;
			}
			goto setRefresh_rip;
		}

		// Delete all
		str = boaGetVar(wp, "ripDelAll", "");
		if (str[0]) {
			mib_chain_clear(MIB_RIP_TBL); /* clear chain record */
			goto setRefresh_rip;
		}

		/* Delete selected */
		str = boaGetVar(wp, "ripDel", "");
		if (str[0]) {
			unsigned int i;
			unsigned int idx;
			unsigned int deleted = 0;
			unsigned int totalEntry = mib_chain_total(MIB_RIP_TBL); /* get chain record size */

			for (i=0; i<totalEntry; i++) {

				idx = totalEntry-i-1;
				snprintf(tmpBuf, 20, "select%d", idx);
				strVal = boaGetVar(wp, tmpBuf, "");

				if ( !gstrcmp(strVal, "ON") ) {
					deleted ++;
					if(mib_chain_delete(MIB_RIP_TBL, idx) != 1) {
						strcpy(tmpBuf, "����: ɾ��MIB_RIP_TBL chain recordʧ��!"); //Delete MIB_RIP_TBL chain record error!
						goto setErr_rip;
					}
				}
			}
			if (deleted <= 0) {
				strcpy(tmpBuf, "û��ѡ��ɾ������Ŀ!"); //There is no item selected to delete!
				goto setErr_rip;
			}

			goto setRefresh_rip;
		}
#if 0
		// Delete
		str = boaGetVar(wp, "ripDel", "");
		if (str[0]) {
			unsigned int i;
			unsigned int idx;
			MIB_CE_RIP_T Entry;
			unsigned int totalEntry = mib_chain_total(MIB_RIP_TBL); /* get chain record size */

			str = boaGetVar(wp, "select", "");

			if (str[0]) {
				for (i=0; i<totalEntry; i++) {
					idx = totalEntry-i-1;
					snprintf(tmpBuf, 4, "s%d", idx);

					if ( !gstrcmp(str, tmpBuf) ) {

						// delete from chain record
						if(mib_chain_delete(MIB_RIP_TBL, idx) != 1) {
							strcpy(tmpBuf, "Delete MIB_RIP_TBL chain record error!");
							goto setErr_rip;
						}
					}
				} // end of for
			}
			goto setRefresh_rip;
		}
#endif

		// RIP setting
		str = boaGetVar(wp, "ripSet", "");
		if (str[0]) {
			unsigned char ripVal;

			str = boaGetVar(wp, "rip_on", "");
			if (str[0] == '1')
				ripVal = 1;
			else
				ripVal = 0;	// default "off"
			if (!mib_set(MIB_RIP_ENABLE, (void *)&ripVal)) {
				strcpy(tmpBuf, "Set RIP error!");
				goto setErr_rip;
			}

			// Commented by Mason Yu
			/*
			str = boaGetVar(wp, "rip_ver", "");
			if (str[0] == '0')
				ripVal = 0;
			else
				ripVal = 1;	// default "v2"
			if (!mib_set(MIB_RIP_VERSION, (void *)&ripVal)) {
				strcpy(tmpBuf, "Set RIP error!");
				goto setErr_rip;
			}
			*/
		}

		mib_get(MIB_RIP_ENABLE, (void *)&igpEnable);
		if (igpEnable == 1) {//if rip enabled, close ospf; else dont change any state.
			igpEnable = 0;
			mib_set(MIB_OSPF_ENABLE, (void *)&igpEnable);
		}
	}
	else if (strVal[0] == '1') {
		//ospf add
		str = boaGetVar(wp, "ripAdd", "");
		if (str[0]) {
			MIB_CE_OSPF_T Entry;
			int intVal;

			str = boaGetVar(wp, "ip", "");
			if (str[0]) {
				if ( !inet_aton(str, (struct in_addr *)&Entry.ipAddr) ) {
					strcpy(tmpBuf, Tinvalid_if_ip);
					goto setErr_rip;
				}
			}
			str = boaGetVar(wp, "mask", "");
			if (str[0]) {
				if (!isValidNetmask(str, 1)) {
					strcpy(tmpBuf, Tinvalid_if_mask);
					goto setErr_rip;
				}
				if ( !inet_aton(str, (struct in_addr *)&Entry.netMask) ) {
					strcpy(tmpBuf, Tinvalid_if_mask);
					goto setErr_rip;
				}
			}
			intVal = mib_chain_add(MIB_OSPF_TBL, (unsigned char*)&Entry);
			if (intVal == 0) {
				//boaWrite(wp, "%s", "Error: Add MIB_OSPF_TBL chain record.");
				//return;
				strcpy(tmpBuf, "����: ���� MIB_OSPF_TBL chain recordʧ��"); //Error: Add MIB_OSPF_TBL chain record.
				goto setErr_rip;
			}
			else if (intVal == -1) {
				strcpy(tmpBuf, strTableFull);
				goto setErr_rip;
			}
			goto setRefresh_rip;
		}

		// Delete
		str = boaGetVar(wp, "ripDel", "");
		if (str[0]) {
			unsigned int i;
			unsigned int idx;
			MIB_CE_OSPF_T Entry;
			unsigned int totalEntry = mib_chain_total(MIB_OSPF_TBL); /* get chain record size */

			str = boaGetVar(wp, "select", "");

			if (str[0]) {
				for (i=0; i<totalEntry; i++) {
					idx = totalEntry-i-1;
					snprintf(tmpBuf, 4, "s%d", idx);

					if ( !gstrcmp(str, tmpBuf) ) {

						// delete from chain record
						if(mib_chain_delete(MIB_OSPF_TBL, idx) != 1) {
							strcpy(tmpBuf, "����: ɾ�� MIB_OSPF_TBL chain recordʧ��!"); //Delete MIB_OSPF_TBL chain record error!
							goto setErr_rip;
						}
					}
				} // end of for
			}
			goto setRefresh_rip;
		}

		// OSPF setting
		str = boaGetVar(wp, "ripSet", "");
		if (str[0]) {
			unsigned char ripVal;

			str = boaGetVar(wp, "rip_on", "");
			if (str[0] == '1')
				ripVal = 1;
			else
				ripVal = 0;	// default "off"
			if (!mib_set(MIB_OSPF_ENABLE, (void *)&ripVal)) {
				strcpy(tmpBuf, "Set OSPF error!");
				goto setErr_rip;
			}
		}

		mib_get(MIB_OSPF_ENABLE, (void *)&igpEnable);
#ifdef CONFIG_USER_ROUTED_ROUTED
		if (igpEnable == 1) {//if ospf enabled, close rip; else dont change any state.
			igpEnable = 0;
			mib_set(MIB_RIP_ENABLE, (void *)&igpEnable);
		}
#endif
	}

setRefresh_rip:
#ifdef CONFIG_USER_ROUTED_ROUTED
	startRip();
#endif
	startOspf();

	submitUrl = boaGetVar(wp, "submit-url", "");
	if (submitUrl[0])
		boaRedirect(wp, submitUrl);
	else
		boaDone(wp, 200);
	return;

setErr_rip:
	ERR_MSG(tmpBuf);
}
#endif // of CONFIG_USER_ZEBRA_OSPFD_OSPFD
#endif

#ifdef CONFIG_USER_ROUTED_ROUTED
// List all the rip interface at web page.
// return: number of rip interface listed.
int showRipIf(int eid, request * wp, int argc, char **argv)
{
	int nBytesSent=0;
	unsigned int entryNum, i;
	MIB_CE_RIP_T Entry;
	char ifname[IFNAMSIZ], receive_mode[5], send_mode[16];

	entryNum = mib_chain_total(MIB_RIP_TBL);
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	nBytesSent += boaWrite(wp, "<tr><font size=1>"
	"<td align=center width=\"5%%\" bgcolor=\"#808080\">ɾ��</td>\n"
	"<td align=center width=\"20%%\" bgcolor=\"#808080\">�ӿ�</td>"
	"<td align=center width=\"20%%\" bgcolor=\"#808080\">���հ汾</td>"
	"<td align=center width=\"20%%\" bgcolor=\"#808080\">���Ͱ汾</td></font></tr>\n");
#else
	nBytesSent += boaWrite(wp, "<tr><font size=1>"
		"<td align=center width=\"5%%\" bgcolor=\"#808080\">%s</td>\n"
		"<td align=center width=\"20%%\" bgcolor=\"#808080\">%s</td>"
		"<td align=center width=\"20%%\" bgcolor=\"#808080\">%s%s</td>"
		"<td align=center width=\"20%%\" bgcolor=\"#808080\">%s%s</td></font></tr>\n", 
		UTF8_STR_DELETE, UTF8_STR_INTERFACE, UTF8_STR_RECEIVE, UTF8_STR_VERSION, UTF8_STR_TRANSMIT, UTF8_STR_VERSION);
#endif

	for (i=0; i<entryNum; i++) {

		if (!mib_chain_get(MIB_RIP_TBL, i, (void *)&Entry))
		{
  			boaError(wp, 400, "Get MIB_RIP_TBL chain record ����!\n");
			return -1;
		}

		if( Entry.ifIndex == DUMMY_IFINDEX) {
			strncpy(ifname, "br0", strlen("br0"));
			ifname[strlen("br0")] = '\0';
		} else {
			ifGetName(Entry.ifIndex, ifname, sizeof(ifname));
		}

		if ( Entry.receiveMode == RIP_NONE ) {
			strncpy(receive_mode, "None", strlen("None"));
			receive_mode[strlen("None")] = '\0';
		} else if ( Entry.receiveMode == RIP_V1 ) {
			strncpy(receive_mode, "RIP1", strlen("RIP1"));
			receive_mode[strlen("RIP1")] = '\0';
		} else if ( Entry.receiveMode == RIP_V2 ) {
			strncpy(receive_mode, "RIP2", strlen("RIP2"));
			receive_mode[strlen("RIP2")] = '\0';
		} else if ( Entry.receiveMode == RIP_V1_V2 ) {
			strncpy(receive_mode, "Both", strlen("Both"));
			receive_mode[strlen("Both")] = '\0';
		} else {
			boaError(wp, 400, "Get RIP Receive Mode ����!\n");
			return -1;
		}

		if ( Entry.sendMode == RIP_NONE ) {
			strncpy(send_mode, "None", strlen("None"));
			send_mode[strlen("None")] = '\0';
		} else if ( Entry.sendMode == RIP_V1 ) {
			strncpy(send_mode, "RIP1", strlen("RIP1"));
			send_mode[strlen("RIP1")] = '\0';
		} else if ( Entry.sendMode == RIP_V2 ) {
			strncpy(send_mode, "RIP2", strlen("RIP2"));
			send_mode[strlen("RIP2")] = '\0';
		} else if ( Entry.sendMode == RIP_V1_COMPAT ) {
			strncpy(send_mode, "RIP1COMPAT", strlen("RIP1COMPAT"));
			send_mode[strlen("RIP1COMPAT")] = '\0';
		} else {
			boaError(wp, 400, "Get RIP Send Mode ����!\n");
			return -1;
		}

		nBytesSent += boaWrite(wp, "<tr>"
//		"<td align=center width=\"5%%\" bgcolor=\"#C0C0C0\"><input type=\"radio\" name=\"select\""
//		" value=\"s%d\""
//		"></td>\n"
		"<td align=center width=\"5%%\" bgcolor=\"#C0C0C0\"><input type=\"checkbox\" name=\"select%d\" value=\"ON\"></td>\n"
		"<td align=center width=\"20%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"><b>%s</b></font></td>"
		"<td align=center width=\"20%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"><b>%s</b></font></td>"
		"<td align=center width=\"20%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"><b>%s</b></font></td>"
		"</tr>\n",
		i,
		ifname, receive_mode, send_mode);
	}
	return 0;
}

int ifRipNum()
{
	int ifnum=0;

	unsigned int entryNum, i;
	MIB_CE_ATM_VC_T Entry;
	char  buffer[3];


	// check LAN
	if (mib_get(MIB_ADSL_LAN_RIP, (void *)buffer) != 0) {
		if (buffer[0] == 1) {
			ifnum++;
		}
	}

	// check WAN
	entryNum = mib_chain_total(MIB_ATM_VC_TBL);
	for (i=0; i<entryNum; i++) {

		if (!mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&Entry))
		{
			return -1;
		}

		if (Entry.enable == 0)
			continue;

		if (Entry.cmode != CHANNEL_MODE_BRIDGE && Entry.rip)
		{
			ifnum++;
		}
	}

	return ifnum;
}
#endif	// of CONFIG_USER_ROUTED_ROUTED

int showStaticRoute(int eid, request * wp, int argc, char **argv)
{
	int nBytesSent=0;

	unsigned int entryNum, i;
	MIB_CE_IP_ROUTE_T Entry;
	unsigned long int d,g,m;
	struct in_addr dest;
	struct in_addr gw;
	struct in_addr mask;
	char sdest[16], sgw[16];
	char interface_name[IFNAMSIZ];
	MIB_CE_ATM_VC_T vcEntry;
	int j;
	int mibTotal = mib_chain_total(MIB_ATM_VC_TBL);


	entryNum = mib_chain_total(MIB_IP_ROUTE_TBL);
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	nBytesSent += boaWrite(wp, "<tr>"
	"<td align=center width=\"8%%\">Ŀ�ĵ�ַ</td>\n"
	"<td align=center width=\"8%%\">����</td>\n"
	"<td align=center width=\"8%%\">��������</td>\n"
	"<td align=center width=\"8%%\">�ӿ�</td>\n"
	"<td align=center width=\"5%%\">ɾ��</td>\n"
	"</tr>\n");
#else
	nBytesSent += boaWrite(wp, "<tr><font size=1>"
	"<td align=center width=\"5%%\" bgcolor=\"#808080\">ѡ��</td>\n"
	"<td align=center width=\"5%%\" bgcolor=\"#808080\">״̬</td>\n"
	"<td align=center width=\"8%%\" bgcolor=\"#808080\">Ŀ��</td>\n"
	"<td align=center width=\"8%%\" bgcolor=\"#808080\">��������</td>\n"
	"<td align=center width=\"8%%\" bgcolor=\"#808080\">����</td>\n"
	"<td align=center width=\"8%%\" bgcolor=\"#808080\">Metric</td>\n"
	"<td align=center width=\"8%%\" bgcolor=\"#808080\">�ӿ�</td>\n"
	"</font></tr>\n");
#endif

	for (i=0; i<entryNum; i++) {

		char destNet[16], subMask[16], nextHop[16];

		if (!mib_chain_get(MIB_IP_ROUTE_TBL, i, (void *)&Entry))
		{
  			boaError(wp, 400, "Get chain record error!\n");
			return -1;
		}

		dest.s_addr = *(unsigned long *)Entry.destID;
		gw.s_addr   = *(unsigned long *)Entry.nextHop;
		mask.s_addr = *(unsigned long *)Entry.netMask;
		// inet_ntoa is not reentrant, we have to
		// copy the static memory before reuse it
		strcpy(sdest, inet_ntoa(dest));

#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		if(Entry.nextHopEnable==1){
			strcpy(sgw, inet_ntoa(gw));
		}
		else{
			strcpy(sgw, "N/A");
		}
#else
		strcpy(sgw, inet_ntoa(gw));
#endif
		if (!ifGetName(Entry.ifIndex, interface_name, sizeof(interface_name)))
			strcpy( interface_name, "---" );
		strcpy(destNet, inet_ntoa(*((struct in_addr *)Entry.destID)) );
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		if(Entry.nextHopEnable==1){
			strcpy(nextHop, inet_ntoa(*((struct in_addr *)Entry.nextHop)) );
		}
		else{
			strcpy(nextHop, "N/A");
		}
#else
		strcpy(nextHop, inet_ntoa(*((struct in_addr *)Entry.nextHop)) );
#endif
		strcpy(subMask, inet_ntoa(*((struct in_addr *)Entry.netMask)) );


		nBytesSent += boaWrite(wp, "<tr>"
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		"<td align=center width=\"8%%\"> %s</td>\n"
		"<td align=center width=\"8%%\"> %s</td>\n"
		"<td align=center width=\"8%%\"> %s</td>"
		"<td align=center width=\"8%%\"> %s</td>"	
		"<td align=center width=\"5%%\"><input type=\"radio\" name=\"select\""
		" value=\"s%d\" "
		"onClick=\"postGW(%d,  '%s','%s','%s',%d,%d,'select%d' )\""

		"></td>\n"
		"</tr>\n",
		sdest, sgw, inet_ntoa(mask), interface_name,
		i, Entry.Enable, destNet, subMask, nextHop, Entry.FWMetric, Entry.ifIndex, i);
#else
		"<td align=center width=\"5%%\" bgcolor=\"#C0C0C0\"><input type=\"radio\" name=\"select\""
		" value=\"s%d\" "
		"onClick=\"postGW(%d,  '%s','%s','%s',%d,%d,'select%d' )\""

		"></td>\n"
		"<td align=center width=\"8%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"><b>%s</b></font></td>\n"
		"<td align=center width=\"8%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"><b>%s</b></font></td>\n"
		"<td align=center width=\"8%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"><b>%s</b></font></td>\n"
		"<td align=center width=\"8%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"><b>%s</b></font></td>"
		"<td align=center width=\"8%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"><b>%d</b></font></td>"
		"<td align=center width=\"8%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"><b>%s</b></font></td>"
		"</tr>\n",
		i,
		Entry.Enable, destNet, subMask, nextHop, Entry.FWMetric, Entry.ifIndex, i,
		Entry.Enable ? "����" : "����", sdest, inet_ntoa(mask), sgw, Entry.FWMetric, interface_name);
#endif
	}

	return 0;
}

#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
#ifdef CONFIG_IPV6
int showIPv6StaticRoute(int eid, request * wp, int argc, char **argv)
{
	int nBytesSent=0;

	unsigned int entryNum, i;
	MIB_CE_IPV6_ROUTE_T Entry;
	unsigned long int d,g,m;
	char sdest[40], sgw[40];
	char interface_name[IFNAMSIZ];
	MIB_CE_ATM_VC_T vcEntry;
	int j;
	int mibTotal = mib_chain_total(MIB_ATM_VC_TBL);
	int len=0;
	char addr[MAX_V6_IP_LEN] ={0};

	entryNum = mib_chain_total(MIB_IPV6_ROUTE_TBL);
	
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	nBytesSent += boaWrite(wp, "<tr>"
	"<td align=center>Ŀ�ĵ�ַ</td>\n"
	"<td align=center>����</td>\n"
	"<td align=center>�ӿ�</td>\n"
	"<td align=center>ʹ��</td>\n"
	"<td align=center>ɾ��</td>\n"
	"</tr>\n");
#else
	nBytesSent += boaWrite(wp, "<tr><font size=1>"
	"<td align=center bgcolor=\"#c8c8c8\">ѡ��</td>\n"
	"<td align=center bgcolor=\"#c8c8c8\">״̬</td>\n"
	"<td align=center bgcolor=\"#c8c8c8\">Ŀ��</td>\n"
	"<td align=center bgcolor=\"#c8c8c8\">ǰ׺����</td>\n"
	"<td align=center bgcolor=\"#c8c8c8\">����</td>\n"
	"<td align=center bgcolor=\"#c8c8c8\">�ӿ�</td>\n"
	"</font></tr>\n");
#endif

	for (i=0; i<entryNum; i++) {
		char destNet[48], nextHop[48];

		if (!mib_chain_get(MIB_IPV6_ROUTE_TBL, i, (void *)&Entry))
		{
  			boaError(wp, 400, "Get chain record error!\n");
			return -1;
		}

		if (!ifGetName(Entry.DstIfIndex, interface_name, sizeof(interface_name)))
			strcpy( interface_name, "---" );

		sscanf(Entry.Dstination, "%[^/]/%d", addr, &len);
        strcpy(destNet, addr);
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		if(Entry.nextHopEnable==1){
			strcpy(nextHop, Entry.NextHop);
		}
		else{
			strcpy(nextHop, "");
		}
#else
		strcpy(nextHop, Entry.NextHop);
#endif

		nBytesSent += boaWrite(wp, "<tr>"
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		"<td align=center width=\"8%%\">%s</td>\n"
		"<td align=center width=\"8%%\">%s</td>\n"
		"<td align=center width=\"8%%\">%s</td>"
		"<td align=center width=\"8%%\">%s</td>"
		"<td align=center width=\"5%%\"><input type=\"radio\" name=\"select\""
		" value=\"s%d\" "
		"onClick=\"postGWv6(%d,  '%s',%d,'%s',%d,'select%d' )\""
		"></td>\n"		
		"</tr>\n",
		destNet, nextHop, interface_name, Entry.Enable ? "ʹ��" : "����", 
		i, Entry.Enable, destNet, len, nextHop, Entry.DstIfIndex, i);
#else
		"<td align=center width=\"5%%\" bgcolor=\"#c8c8c8\"><input type=\"radio\" name=\"select\""
		" value=\"s%d\" "
		"onClick=\"postGW(%d,  '%s',%d,'%s',%d,'select%d' )\""
		
		"></td>\n"
		"<td align=center width=\"8%%\" bgcolor=\"#f4f4f4\"><font size=\"2\"><b>%s</b></font></td>\n"
		"<td align=center width=\"8%%\" bgcolor=\"#f4f4f4\"><font size=\"2\"><b>%s</b></font></td>\n"
		"<td align=center width=\"8%%\" bgcolor=\"#f4f4f4\"><font size=\"2\"><b>%d</b></font></td>"
		"<td align=center width=\"8%%\" bgcolor=\"#f4f4f4\"><font size=\"2\"><b>%s</b></font></td>"
		"<td align=center width=\"8%%\" bgcolor=\"#f4f4f4\"><font size=\"2\"><b>%s</b></font></td>"
		"</tr>\n",
		i,
		Entry.Enable, destNet, len, nextHop, Entry.DstIfIndex, i,
		Entry.Enable ? "����" : "����", destNet, len,  nextHop, interface_name);
#endif
	}
	return 0;
}
#endif
#endif


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

int routeList(int eid, request * wp, int argc, char **argv)
{
	int nBytesSent=0;
	char buff[256];
	int flgs, metric;
	unsigned long int d,g,m;
	struct in_addr dest;
	struct in_addr gw;
	struct in_addr mask;
	char sdest[16], sgw[16], iface[30];
	FILE *fp;

	if (!(fp=fopen("/proc/net/route", "r"))) {
		fclose(fp);
		printf("Error: cannot open /proc/net/route - continuing...\n");
		boaWrite(wp, "%s", "Error: cannot open /proc/net/route !!");
		return -1;
	}
	nBytesSent += boaWrite(wp, "<tr><font size=1>"
	"<td align=center width=\"8%%\" bgcolor=\"#808080\">Ŀ��</td>\n"
	"<td align=center width=\"8%%\" bgcolor=\"#808080\">��������</td>\n"
	"<td align=center width=\"8%%\" bgcolor=\"#808080\">����</td>\n"
	"<td align=center width=\"8%%\" bgcolor=\"#808080\">Metric</td>\n"
	"<td align=center width=\"8%%\" bgcolor=\"#808080\">�ӿ�</td></font></tr>\n");
	fgets(buff, sizeof(buff), fp);

	while( fgets(buff, sizeof(buff), fp) != NULL ) {
		if(sscanf(buff, "%s%lx%lx%X%*d%*d%d%lx",
		   iface, &d, &g, &flgs, &metric, &m)!=6) {
			printf("Unsuported kernel route format\n");
			boaWrite(wp, "%s", "Error: Unsuported kernel route format !!");
			fclose(fp);
			return -1;
		}

		if(flgs & RTF_UP) {
			dest.s_addr = d;
			gw.s_addr   = g;
			mask.s_addr = m;
			// inet_ntoa is not reentrant, we have to
			// copy the static memory before reuse it
			strcpy(sdest, inet_ntoa(dest));
			strcpy(sgw,  (gw.s_addr==0   ? "*" : inet_ntoa(gw)));

			nBytesSent += boaWrite(wp, "<tr>"
			"<td align=center width=\"8%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"><b>%s</b></font></td>\n"
			"<td align=center width=\"8%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"><b>%s</b></font></td>\n"
			"<td align=center width=\"8%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"><b>%s</b></font></td>\n"
			"<td align=center width=\"8%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"><b>%d</b></font></td>\n"
			"<td align=center width=\"8%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"><b>%s</b></font></td></tr>\n",
			sdest, inet_ntoa(mask), sgw, metric, iface);
		}
	}

	fclose(fp);
	return 0;
}

/////////////////////////////////////////////////////////////////////////////
void formRefleshRouteTbl(request * wp, char *path, char *query)
{
	char *submitUrl;

	submitUrl = boaGetVar(wp, "submit-url", "");
	if (submitUrl[0])
		boaRedirect(wp, submitUrl);
}

//ql_xu
#ifdef CONFIG_USER_ZEBRA_OSPFD_OSPFD
int showOspfIf(int eid, request * wp, int argc, char **argv)
{
	int nBytesSent=0;
	unsigned int entryNum, i, j;
	MIB_CE_OSPF_T Entry;
	char net[20]={0};
	char net_tmp[20]={0};

	unsigned int uMask;
	unsigned int uIp;

	entryNum = mib_chain_total(MIB_OSPF_TBL);
	nBytesSent = boaWrite(wp, "<tr><font size=1>"
		"<td align=center width=\"5%%\" bgcolor=\"#808080\">ѡ��</td>\n"
		"<td align=center width=\"20%%\" bgcolor=\"#808080\">OSPF�㲥����</td></font></tr>\n");

	for (i=0; i<entryNum; i++) {

		if (!mib_chain_get(MIB_OSPF_TBL, i, (void *)&Entry))
		{
  			boaError(wp, 400, "Get MIB_OSPF_TBL chain record error!\n");
			return;
		}

		uIp = *(unsigned int *)Entry.ipAddr;
		uMask = *(unsigned int *)Entry.netMask;
		uIp = uIp & uMask;
		sprintf(net, "%s", inet_ntoa(*((struct in_addr *)&uIp)));
		for (j=0; j<32; j++)
			if ((uMask>>j) & 0x01)
				break;
		uMask = 32 - j;
		snprintf(net_tmp, 20, "%s/%d", net, uMask);

		nBytesSent += boaWrite(wp, "<tr>\n"
			"<td align=center width=\"5%%\" bgcolor=\"#C0C0C0\"><input type=\"radio\" name=\"select\""
			" value=\"s%d\"></td>\n"
			"<td align=center width=\"20%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"><b>%s</b></font></td>\n"
			"</tr>\n",
			i, net_tmp);
	}
	return 0;
}
#endif
