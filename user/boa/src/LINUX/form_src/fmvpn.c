/*
 *      Web server handler routines for IP QoS
 *
 */

/*-- System inlcude files --*/
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/wait.h>
#include <memory.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/route.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <errno.h>
#include <sys/wait.h>
#include <time.h>
#include <sys/sysinfo.h>


#include "../webs.h"
#include "webform.h"
#include "mib.h"
#include "utility.h"
#include "multilang.h"

#ifdef EMBED
#include <linux/config.h>
#else
#include "../../../../include/linux/autoconf.h"
#endif


#ifdef CONFIG_USER_PPTP_CLIENT_PPTP
#if 0
void startPPtP(MIB_PPTP_T *pentry)
{
	char *argv[20];
	int i=0;

	argv[i++] = "/bin/pptp";
	argv[i++] = pentry->server;
	argv[i++] = "-detach";
	switch (pentry->authtype)
	{
	case 1://pap
		argv[i++] = "+pap";
		break;
	case 2://chap
		argv[i++] = "+chap";
		break;
	case 3://chapmsv2
		argv[i++] = "+chapms-v2";
		break;
	default:
		break;
	}
	argv[i++] = "noaccomp";
	argv[i++] = "novj";
	argv[i++] = "novjccomp";
	argv[i++] = "default-asyncmap";
	argv[i++] = "noauth";
	argv[i++] = "user";
	argv[i++] = pentry->username;
	argv[i++] = "password";
	argv[i++] = pentry->password;
	if (pentry->dgw)
		argv[i++] = "defaultroute";
	argv[i++] = NULL;

	do_cmd("/bin/pptp", argv, 0);
}
#endif

void formPPtP(request * wp, char *path, char *query)
{
#ifdef CONFIG_USER_PPTPD_PPTPD
	char *submitUrl, *strAddPptpClient, *strDelPptpClient, *strVal;
	char *strAddPptpAccount, *strDelPptpAccount, *strSavePptpAccount;
	char *strSetPptpServer;
#else
	char *submitUrl, *strAddPPtP, *strDelPPtP, *strVal;
#endif
	char tmpBuf[100];
	int intVal;
	int pptpEntryNum, i;
#ifdef CONFIG_USER_L2TPD_L2TPD
	int l2tpEntryNum;
	MIB_L2TP_T l2tpEntry;
#endif
	MIB_CE_ATM_VC_T vcEntry;
	int wanNum;
	MIB_PPTP_T entry, tmpEntry;
#ifdef CONFIG_USER_PPTPD_PPTPD
	MIB_VPN_ACCOUNT_T account, tmpAccount;
	int accountNum;
#endif
	int deleted = 0;
	int enable;
	int pid;
	unsigned int map=0;//maximum rule num is MAX_PPTP_NUM

	strVal = boaGetVar(wp, "lst", "");

	// enable/disable PPtP
	if (strVal[0]) {
		strVal = boaGetVar(wp, "pptpen", "");

		if ( strVal[0] == '1' ) {//enable
			enable = 1;
		}
		else//disable
			enable = 0;

		mib_set(MIB_PPTP_ENABLE, (void *)&enable);

		pptp_take_effect();
#ifdef CONFIG_USER_PPTPD_PPTPD
		pptpd_take_effect();
#endif

		goto setOK_pptp;
	}

#ifdef CONFIG_USER_PPTPD_PPTPD
	strAddPptpClient = boaGetVar(wp, "addClient", "");
	strDelPptpClient = boaGetVar(wp, "delSelClient", "");
	strAddPptpAccount = boaGetVar(wp, "addAccount", "");
	strDelPptpAccount = boaGetVar(wp, "delSelAccount", "");
	strSavePptpAccount = boaGetVar(wp, "saveAccount", "");
	strSetPptpServer = boaGetVar(wp, "addServer", "");
#else
	strAddPPtP = boaGetVar(wp, "addPPtP", "");
	strDelPPtP = boaGetVar(wp, "delSel", "");
#endif

	memset(&entry, 0, sizeof(entry));
	pptpEntryNum = mib_chain_total(MIB_PPTP_TBL); /* get chain record size */
#ifdef CONFIG_USER_L2TPD_L2TPD
	l2tpEntryNum = mib_chain_total(MIB_L2TP_TBL);
#endif
	wanNum = mib_chain_total(MIB_ATM_VC_TBL);
#ifdef CONFIG_USER_PPTPD_PPTPD
	accountNum = mib_chain_total(MIB_VPN_ACCOUNT_TBL);
#endif

#ifdef CONFIG_USER_PPTPD_PPTPD
	/* Add new pptp client entry */
	if (strAddPptpClient[0]) {
		printf("add pptp client entry.\n");

		strVal = boaGetVar(wp, "c_name", "");
		strcpy(entry.name, strVal);

		strVal = boaGetVar(wp, "c_addr", "");
		strcpy(entry.server, strVal);

		for (i=0; i<pptpEntryNum; i++)
		{
			if ( !mib_chain_get(MIB_PPTP_TBL, i, (void *)&tmpEntry) )
				continue;

			if ( !strcmp(tmpEntry.server, entry.server) || !strcmp(tmpEntry.name, entry.name))
			{
				strcpy(tmpBuf, multilang(LANG_PPTP_VPN_INTERFACE_HAS_ALREADY_EXIST));
				goto setErr_pptp;
			}

			map |= (1<< tmpEntry.idx);
		}
// Mason Yu. Add VPN ifIndex
#if 0
#ifdef CONFIG_USER_L2TPD_L2TPD
		for (i=0; i<l2tpEntryNum; i++)
		{
			if ( !mib_chain_get(MIB_L2TP_TBL, i, (void *)&l2tpEntry) )
				continue;
			map |= (1<<l2tpEntry.idx);
		}
#endif//endof CONFIG_USER_L2TPD_L2TPD
#endif
		strVal = boaGetVar(wp, "c_username", "");
		strcpy(entry.username, strVal);

		strVal = boaGetVar(wp, "c_password", "");
		strcpy(entry.password, strVal);

		strVal = boaGetVar(wp, "c_auth", "");
		entry.authtype = strVal[0] - '0';

		if (entry.authtype == 3) {
	        strVal = boaGetVar(wp, "c_enctype", "");
			entry.enctype = strVal[0] - '0';
		}

		strVal = boaGetVar(wp, "defaultgw", "");
		if (strVal[0]) {
			entry.dgw = 1;
			for (i=0; i<pptpEntryNum; i++)
			{
				if ( !mib_chain_get(MIB_PPTP_TBL, i, (void *)&tmpEntry) )
					continue;

				if (tmpEntry.dgw)
				{
					strcpy(tmpBuf, multilang(LANG_DEFAULT_GW_HAS_ALREADY_EXIST_FOR_PPTP_VPN));
					goto setErr_pptp;
				}
			}
			//check if conflicts with wan interface setting
			for (i=0; i<wanNum; i++)
			{
				if (!mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&vcEntry))
					continue;
				if (vcEntry.dgw)
				{
					strcpy(tmpBuf, multilang(LANG_DEFAULT_GW_HAS_ALREADY_EXIST));
					goto setErr_pptp;
				}
			}
#ifdef CONFIG_USER_L2TPD_L2TPD
			for (i=0; i<l2tpEntryNum; i++)
			{
				if ( !mib_chain_get(MIB_L2TP_TBL, i, (void *)&l2tpEntry) )
					continue;
				if (l2tpEntry.dgw)
				{
					strcpy(tmpBuf, multilang(LANG_DEFAULT_GW_HAS_ALREADY_EXIST_FOR_L2TP_VPN));
					goto setErr_pptp;
				}
			}
#endif//end of CONFIG_USER_L2TPD_L2TPD
#ifdef CONFIG_NET_IPIP
			{
				MIB_IPIP_T ipEntry;
				int ipEntryNum;
				ipEntryNum = mib_chain_total(MIB_IPIP_TBL);
				for (i=0; i<ipEntryNum; i++) {
					if (!mib_chain_get(MIB_IPIP_TBL, i, (void *)&ipEntry))
						continue;
					if (ipEntry.dgw)
					{
						strcpy(tmpBuf, multilang(LANG_DEFAULT_GW_HAS_ALREADY_EXIST_FOR_IPIP_VPN));
						goto setErr_pptp;
					}
				}
			}
#endif//end of CONFIG_NET_IPIP
		}
#ifdef CONFIG_IPV6_VPN
		strVal = boaGetVar(wp, "IpProtocolType", "");
		if (strVal[0]) {
			entry.IpProtocol = strVal[0] - '0';
		}
#endif
#ifdef CONFIG_RTK_L34_ENABLE
{
		int remained;
		remained = Check_RG_Intf_Count();
		if(remained == 0){
			/*RG HW Table FULL*/
			strcpy(tmpBuf, strTableFull);
			goto setErr_pptp; 	
		}
}
#endif
		for (i=0; i<MAX_PPTP_NUM; i++) {
			if (!(map & (1<<i))) {
				entry.idx = i;
				break;
			}
		}
		// Mason Yu. Add VPN ifIndex
		// unit declarations for ppp  on if_sppp.h
		// (1) 0 ~ 7: pppoe/pppoa, (2) 8: 3G, (3) 9 ~ 10: PPTP, (4) 11 ~12: L2TP
		entry.ifIndex = TO_IFINDEX(MEDIA_PPTP, (entry.idx+9), PPTP_INDEX(entry.idx));
		//printf("***** PPTP: entry.ifIndex=0x%x\n", entry.ifIndex);

		intVal = mib_chain_add(MIB_PPTP_TBL, (void *)&entry);
		if (intVal == 0) {
			strcpy(tmpBuf, Tadd_chain_error);
			goto setErr_pptp;
		}
		else if (intVal == -1) {
			strcpy(tmpBuf, strTableFull);
			goto setErr_pptp;
		}
		pptpEntryNum = mib_chain_total(MIB_PPTP_TBL);
		//startPPtP(&entry);
		applyPPtP(&entry, 1, pptpEntryNum-1);

		goto setOK_pptp;
	}
#else
	/* Add new pptp entry */
	if (strAddPPtP[0]) {
		printf("add pptp entry.\n");

		strVal = boaGetVar(wp, "server", "");
		strcpy(entry.server, strVal);

		for (i=0; i<pptpEntryNum; i++)
		{
			if ( !mib_chain_get(MIB_PPTP_TBL, i, (void *)&tmpEntry) )
				continue;

			if ( !strcmp(tmpEntry.server, entry.server))
			{
				strcpy(tmpBuf, multilang(LANG_PPTP_VPN_INTERFACE_HAS_ALREADY_EXIST));
				goto setErr_pptp;
			}

			map |= (1<< tmpEntry.idx);
		}
// Mason Yu. Add VPN ifIndex
#if 0
#ifdef CONFIG_USER_L2TPD_L2TPD
		for (i=0; i<l2tpEntryNum; i++)
		{
			if ( !mib_chain_get(MIB_L2TP_TBL, i, (void *)&l2tpEntry) )
				continue;
			map |= (1<<l2tpEntry.idx);
		}
#endif//endof CONFIG_USER_L2TPD_L2TPD
#endif
		strVal = boaGetVar(wp, "username", "");
		strcpy(entry.username, strVal);

		strVal = boaGetVar(wp, "password", "");
		strcpy(entry.password, strVal);

		strVal = boaGetVar(wp, "auth", "");
		entry.authtype = strVal[0] - '0';

		if (entry.authtype == 3) {
	        strVal = boaGetVar(wp, "enctype", "");
			entry.enctype = strVal[0] - '0';
		}

		strVal = boaGetVar(wp, "defaultgw", "");
		if (strVal[0]) {
			entry.dgw = 1;
			for (i=0; i<pptpEntryNum; i++)
			{
				if ( !mib_chain_get(MIB_PPTP_TBL, i, (void *)&tmpEntry) )
					continue;

				if (tmpEntry.dgw)
				{
					strcpy(tmpBuf, multilang(LANG_DEFAULT_GW_HAS_ALREADY_EXIST));
					goto setErr_pptp;
				}
			}
			//check if conflicts with wan interface setting
			for (i=0; i<wanNum; i++)
			{
				if (!mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&vcEntry))
					continue;
				if (vcEntry.dgw)
				{
					strcpy(tmpBuf, multilang(LANG_DEFAULT_GW_HAS_ALREADY_EXIST));
					goto setErr_pptp;
				}
			}
#ifdef CONFIG_USER_L2TPD_L2TPD
			for (i=0; i<l2tpEntryNum; i++)
			{
				if ( !mib_chain_get(MIB_L2TP_TBL, i, (void *)&l2tpEntry) )
					continue;
				if (l2tpEntry.dgw)
				{
					strcpy(tmpBuf, multilang(LANG_DEFAULT_GW_HAS_ALREADY_EXIST_FOR_L2TP_VPN));
					goto setErr_pptp;
				}
			}
#endif//end of CONFIG_USER_L2TPD_L2TPD
#ifdef CONFIG_NET_IPIP
			{
				MIB_IPIP_T ipEntry;
				int ipEntryNum;
				ipEntryNum = mib_chain_total(MIB_IPIP_TBL);
				for (i=0; i<ipEntryNum; i++) {
					if (!mib_chain_get(MIB_IPIP_TBL, i, (void *)&ipEntry))
						continue;
					if (ipEntry.dgw)
					{
						strcpy(tmpBuf, multilang(LANG_DEFAULT_GW_HAS_ALREADY_EXIST_FOR_IPIP_VPN));
						goto setErr_pptp;
					}
				}
			}
#endif//end of CONFIG_NET_IPIP
		}
#ifdef CONFIG_IPV6_VPN
		strVal = boaGetVar(wp, "IpProtocolType", "");
		if (strVal[0]) {
			entry.IpProtocol = strVal[0] - '0';
		}
#endif
#ifdef CONFIG_RTK_L34_ENABLE
		{
				int remained;
				remained = Check_RG_Intf_Count();
				if(remained == 0){
					/*RG HW Table FULL*/
					strcpy(tmpBuf, strTableFull);
					goto setErr_pptp;	
				}
		}
#endif
		for (i=0; i<MAX_PPTP_NUM; i++) {
			if (!(map & (1<<i))) {
				entry.idx = i;
				break;
			}
		}
		// Mason Yu. Add VPN ifIndex
		// unit declarations for ppp  on if_sppp.h
		// (1) 0 ~ 7: pppoe/pppoa, (2) 8: 3G, (3) 9 ~ 10: PPTP, (4) 11 ~12: L2TP
		entry.ifIndex = TO_IFINDEX(MEDIA_PPTP, (entry.idx+9), PPTP_INDEX(entry.idx));
		//printf("***** PPTP: entry.ifIndex=0x%x\n", entry.ifIndex);

		intVal = mib_chain_add(MIB_PPTP_TBL, (void *)&entry);
		if (intVal == 0) {
			strcpy(tmpBuf, Tadd_chain_error);
			goto setErr_pptp;
		}
		else if (intVal == -1) {
			strcpy(tmpBuf, strTableFull);
			goto setErr_pptp;
		}
		pptpEntryNum = mib_chain_total(MIB_PPTP_TBL);
		//startPPtP(&entry);
		applyPPtP(&entry, 1, pptpEntryNum-1);

		goto setOK_pptp;
	}
#endif

	/* Delete client */
#ifdef CONFIG_USER_PPTPD_PPTPD
	if (strDelPptpClient[0])
#else
	if (strDelPPtP[0])
#endif
	{
		printf("delete pptp client entry(total %d).\n", pptpEntryNum);
		for (i=pptpEntryNum-1; i>=0; i--) {
			mib_chain_get(MIB_PPTP_TBL, i, (void *)&tmpEntry);
			snprintf(tmpBuf, 20, "s%d", tmpEntry.idx);
			strVal = boaGetVar(wp, tmpBuf, "");

			if (strVal[0] == '1') {
				deleted ++;
				#if 0
				sprintf(tmpBuf, "/var/run/pptp.pid.%s", tmpEntry.server);
				pid = read_pid(tmpBuf);
				if (pid>0)
					kill(pid, SIGTERM);
				#else
				applyPPtP(&tmpEntry, 0, i);
				#endif
				if(mib_chain_delete(MIB_PPTP_TBL, i) != 1) {
					strcpy(tmpBuf, Tdelete_chain_error);
					goto setErr_pptp;
				}
			}
		}

		if (deleted <= 0) {
			strcpy(tmpBuf, multilang(LANG_THERE_IS_NO_ITEM_SELECTED_TO_DELETE));
			goto setErr_pptp;
		}

		goto setOK_pptp;
	}

#ifdef CONFIG_USER_PPTPD_PPTPD
	/* configure pptp server */
	if (strSetPptpServer[0]) {
		MIB_VPND_T server, pre_server;
		int servernum;
		struct in_addr addr;

		memset(&server, 0, sizeof(MIB_VPND_T));

		server.type = VPN_PPTP;

		strVal = boaGetVar(wp, "s_auth", "");
		server.authtype = strVal[0] - '0';

		if (server.authtype == 3) {
	        strVal = boaGetVar(wp, "s_enctype", "");
			server.enctype = strVal[0] - '0';
		}

		strVal = boaGetVar(wp, "peeraddr", "");
		inet_aton(strVal, &addr);
		server.peeraddr = addr.s_addr;
		printf("%s peeraddr=%x\n", __func__, server.peeraddr);

		strVal = boaGetVar(wp, "localaddr", "");
		inet_aton(strVal, &addr);
		server.localaddr = addr.s_addr;
		printf("%s localaddr=%x\n", __func__, server.localaddr);

		/* check if pptp server is modified */
		servernum = mib_chain_total(MIB_VPN_SERVER_TBL);
		for (i=0; i<servernum; i++) {
			if (!mib_chain_get(MIB_VPN_SERVER_TBL, i, &pre_server))
				continue;
			if (VPN_PPTP == pre_server.type)
				break;
		}
		if (i < servernum) {//we are to modify pptp server
			if ((pre_server.authtype != server.authtype) ||
				(pre_server.enctype != server.enctype) ||
				(pre_server.localaddr != server.localaddr) ||
				(pre_server.peeraddr != server.peeraddr))
			{
				printf("pptp server modified, all pptpd account should be reenabled.\n");
				mib_chain_update(MIB_VPN_SERVER_TBL, &server, i);
				pptpd_take_effect();
			}
		}
		else {//add pptp server
			mib_chain_add(MIB_VPN_SERVER_TBL, &server);
		}

		goto setOK_pptp;
	}

	/* Add new pptp account entry */
	if (strAddPptpAccount[0]) {
		printf("add pptp account.\n");

		memset(&account, 0, sizeof(MIB_VPN_ACCOUNT_T));
		map = 0;

		strVal = boaGetVar(wp, "s_name", "");
		strcpy(account.name, "0");
		strcat(account.name, strVal);

		strVal = boaGetVar(wp, "tunnelen", "");
		account.enable = strVal[0] - '0';

		for (i=0; i<accountNum; i++)
		{
			if ( !mib_chain_get(MIB_VPN_ACCOUNT_TBL, i, (void *)&tmpAccount) )
				continue;

			if (VPN_L2TP == tmpAccount.type)//
				continue;

			if (!strcmp(tmpAccount.name, account.name))
			{
				strcpy(tmpBuf, multilang(LANG_PPTP_VPN_ACCOUNT_HAS_ALREADY_EXIST));
				goto setErr_pptp;
			}

			map |= (1<< tmpAccount.idx);
		}

		strVal = boaGetVar(wp, "s_username", "");
		strcpy(account.username, strVal);

		strVal = boaGetVar(wp, "s_password", "");
		strcpy(account.password, strVal);

		for (i=0; i<MAX_PPTP_NUM; i++) {
			if (!(map & (1<<i))) {
				account.idx = i;
				break;
			}
		}

		intVal = mib_chain_add(MIB_VPN_ACCOUNT_TBL, (void *)&account);
		if (intVal == 0) {
			strcpy(tmpBuf, Tadd_chain_error);
			goto setErr_pptp;
		}
		else if (intVal == -1) {
			strcpy(tmpBuf, strTableFull);
			goto setErr_pptp;
		}

		applyPptpAccount(&account, 1);

		goto setOK_pptp;
	}

	if (strDelPptpAccount[0]) {
		unsigned int deleted = 0;

		printf("delete pptp account(total %d).\n", accountNum);
		for (i=accountNum-1; i>=0; i--) {
			mib_chain_get(MIB_VPN_ACCOUNT_TBL, i, (void *)&tmpAccount);
			if (VPN_L2TP == tmpAccount.type)
				continue;
			snprintf(tmpBuf, 100, "sel%d", tmpAccount.idx);
			strVal = boaGetVar(wp, tmpBuf, "");
			if ( strVal[0] ) {
				deleted++;

				applyPptpAccount(&tmpAccount, 0);

				if(mib_chain_delete(MIB_VPN_ACCOUNT_TBL, i) != 1) {
					strcpy(tmpBuf, Tdelete_chain_error);
					goto setErr_pptp;
				}
			}
		}

		if (deleted <= 0) {
			strcpy(tmpBuf, multilang(LANG_THERE_IS_NO_ITEM_SELECTED_TO_DELETE));
			goto setErr_pptp;
		}

		goto setOK_pptp;
	}

	if (strSavePptpAccount[0]) {
		int enaAccount;
		for (i=0; i<accountNum; i++) {
			mib_chain_get(MIB_VPN_ACCOUNT_TBL, i, (void *)&tmpAccount);
			if (VPN_L2TP == tmpAccount.type)
				continue;
			snprintf(tmpBuf, 100, "en%d", tmpAccount.idx);
			enaAccount = 0;
			strVal = boaGetVar(wp, tmpBuf, "");
			if ( strVal[0] ) {
				enaAccount = 1;
			}

			if (enaAccount == tmpAccount.enable)
				continue;
			else {
				tmpAccount.enable = enaAccount;
				mib_chain_update(MIB_VPN_ACCOUNT_TBL, (void *)&tmpAccount, i);
				if (enaAccount)
					applyPptpAccount(&tmpAccount, 1);
				else
					applyPptpAccount(&tmpAccount, 0);
			}
		}

		goto setOK_pptp;
	}
#endif

	/* pptp client */
	for (i=0; i<pptpEntryNum; i++) {
		mib_chain_get(MIB_PPTP_TBL, i, (void *)&tmpEntry);
		snprintf(tmpBuf, 100, "submitpptp%d", tmpEntry.idx);
		strVal = boaGetVar(wp, tmpBuf, "");
		if ( strVal[0] ) {
			#if 0
			sprintf(tmpBuf, "/var/run/pptp.pid.%s", tmpEntry.server);
			pid = read_pid(tmpBuf);
			if (pid>0)
				kill(pid, SIGTERM);

			if ( !strcmp(strVal, "Connect") ) {
				startPPtP(&tmpEntry);
			}
			#else
			applyPPtP(&tmpEntry, 0, i);
			if ( !strcmp(strVal, "Connect") )
				applyPPtP(&tmpEntry, 1, i);
			#endif
		}
	}

setOK_pptp:

// Magician: Commit immediately
#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif

#ifndef NO_ACTION
	pid = fork();
	if (pid) {
		waitpid(pid, NULL, 0);
	}
	else if (pid == 0) {
		snprintf(tmpBuf, 100, "%s/%s", _CONFIG_SCRIPT_PATH, _FIREWALL_SCRIPT_PROG);
		execl( tmpBuf, _FIREWALL_SCRIPT_PROG, NULL);
		exit(1);
	}
#endif

	submitUrl = boaGetVar(wp, "submit-url", "");   // hidden page
	if (submitUrl[0])
		boaRedirect(wp, submitUrl);
	else
		boaDone(wp, 200);
	return;

setErr_pptp:
	ERR_MSG(tmpBuf);
}

#define PPTP_CONF	"/var/ppp/pptp.conf"
#define FILE_LOCK
/*
 * FILE FORMAT
 * state(established/closed)
 */
int pptpList(int eid, request * wp, int argc, char **argv)
{
	int nBytesSent=0;

	MIB_PPTP_T Entry;
	unsigned int entryNum, i;
	unsigned int pptpEnable, opened=0;
	FILE *fp;
	#ifdef FILE_LOCK
	struct flock flptp;
	int fdptp;
	#endif
	char buff[256];
	char devname[10];
	char status[20];
	//char filename[150];
	char ifname[10];
	char state[20]="Dead";
	char dev_ifname[IFNAMSIZ], web_ifname[15];
	char *web_state[3]={"Disconnected", "Connecting", "Connected"};

	mib_get(MIB_PPTP_ENABLE, (void *)&pptpEnable);
	//if (0 == pptpEnable)//pptp vpn is disable, so no activited pptp itf exists.
	//	return 0;

	entryNum = mib_chain_total(MIB_PPTP_TBL);
	for (i=0; i<entryNum; i++)
	{
		if (!mib_chain_get(MIB_PPTP_TBL, i, (void *)&Entry))
		{
			boaError(wp, 400, "Get chain record error!\n");
			return -1;
		}

		snprintf(ifname, 10, "pptp%d", Entry.idx);

		//init state[]
		snprintf(state, 20, "Dead");

#if 0
		snprintf(filename, 150, PPTP_STATUS, Entry.server);

		fp = fopen(filename, "r");
		if (NULL == fp) {
			strcpy(state, "closed");
		}
		else {
			if (fscanf(fp, "%s", state) != 1)
				strcpy(state, "closed");
			fclose(fp);
		}
#else
	#ifdef FILE_LOCK
		// file locking
		fdptp = open(PPTP_CONF, O_RDWR);
		if (fdptp != -1) {
			flptp.l_type = F_RDLCK;
			flptp.l_whence = SEEK_SET;
			flptp.l_start = 0;
			flptp.l_len = 0;
			flptp.l_pid = getpid();
			if (fcntl(fdptp, F_SETLKW, &flptp) == -1) {
				printf("pptp read lock failed\n");
				close(fdptp);
				fdptp = -1;
			}
		}

		if (-1 != fdptp) {
	#endif
			if (!(fp=fopen(PPTP_CONF, "r")))
				printf("%s not exists.\n", PPTP_CONF);
			else {
				fgets(buff, sizeof(buff), fp);
				while ( fgets(buff, sizeof(buff), fp) != NULL ) {
					//"if", "dev", "uptime", "totaluptime", "status");
					if(sscanf(buff, "%*s%s%*s%*s%s\n", devname, status) != 2) {
						printf("Unsuported pptp configuration format\n");
						break;
					}
					else {
						if (!strcmp(ifname, devname)) {
							strcpy(state, status);
							break;
						}
					}
				}
				fclose(fp);
			}
	#ifdef FILE_LOCK
		}

		// file unlocking
		if (fdptp != -1) {
			flptp.l_type = F_UNLCK;
			if (fcntl(fdptp, F_SETLK, &flptp) == -1)
				printf("pptp read unlock failed\n");
			close(fdptp);
		}
	#endif
#endif

		if (!strncmp(state, "Call_Establish", strlen("Call_Establish"))) {
			// <input type="submit" id="ppp0" value="Disconnect" name="submitppp0" onClick="disButton('ppp0')">
			opened = 2;
		}
		else if (!strncmp(state, "Dead", strlen("Dead")))
			opened = 0;
		else
			opened = 1;

		// Mason Yu. Add VPN ifIndex
		ifGetName(Entry.ifIndex, dev_ifname, sizeof(dev_ifname));
		//snprintf(web_ifname, 15, "pptp%d(%s)", Entry.idx, dev_ifname);
		snprintf(web_ifname, 15, "%s_pptp%d", dev_ifname, Entry.idx);

		if ((1 == opened) || (0 == pptpEnable)) {
			nBytesSent += boaWrite(wp, "<tr>"
#ifndef CONFIG_GENERAL_WEB
				"<td align=center width=\"3%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"><input type=\"checkbox\" name=\"s%d\" value=1></td>\n"
				"<td align=center width=\"5%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
				"<td align=center width=\"5%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
				"<td align=center width=\"8%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s "
#else
				"<td align=center width=\"3%%\"><input type=\"checkbox\" name=\"s%d\" value=1></td>\n"
				"<td align=center width=\"5%%\">%s</td>\n"
				"<td align=center width=\"5%%\">%s</td>\n"
				"<td align=center width=\"8%%\">%s</td>\n"
#endif
				"</tr>",
				Entry.idx, web_ifname, Entry.server, web_state[opened]);
		}
		else {
			nBytesSent += boaWrite(wp, "<tr>"
#ifndef CONFIG_GENERAL_WEB
				"<td align=center width=\"3%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"><input type=\"checkbox\" name=\"s%d\" value=1></td>\n"
				"<td align=center width=\"5%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
				"<td align=center width=\"5%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
				//"<td align=center width=\"8%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s ")
				"<td align=center width=\"8%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"> "
				"<input type=\"submit\" id=\"%s\" value=\"%s\" name=\"submit%s\" onClick=on_submit(this)></td>\n"
#else
				"<td align=center width=\"3%%\"><input type=\"checkbox\" name=\"s%d\" value=1></td>\n"
				"<td align=center width=\"5%%\">%s</td>\n"
				"<td align=center width=\"5%%\">%s</td>\n"
				//"<th align=center width=\"8%%\">%s ")
				"<td align=center width=\"8%%\"> "
				"<input class=\"inner_btn\" type=\"submit\" id=\"%s\" value=\"%s\" name=\"submit%s\" onClick=on_submit(this)></td>\n"
#endif
				"</tr>",
				Entry.idx,
				web_ifname, Entry.server,
				//web_state[opened],
				ifname, (2 == opened) ? "Disconnect" : "Connect", ifname);
		}
	}
	return nBytesSent;
}

#ifdef CONFIG_USER_PPTPD_PPTPD
int pptpServerList(int eid, request * wp, int argc, char **argv)
{
	int nBytesSent=0;
	MIB_VPN_ACCOUNT_T Entry;
	unsigned int entryNum, i;

	entryNum = mib_chain_total(MIB_VPN_ACCOUNT_TBL);
	for (i=0; i<entryNum; i++)
	{
		if (!mib_chain_get(MIB_VPN_ACCOUNT_TBL, i, (void *)&Entry))
		{
			boaError(wp, 400, "Get chain record error!\n");
			return -1;
		}

		if (VPN_L2TP == Entry.type)
			continue;

		nBytesSent += boaWrite(wp, "<tr>"
#ifndef CONFIG_GENERAL_WEB
			"<td align=center width=\"3%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"><input type=\"checkbox\" name=\"sel%d\" value=1></td>\n"
			"<td align=center width=\"5%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
			"<td align=center width=\"5%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"><input type=\"checkbox\" name=\"en%d\" %s value=1></td>\n"
			"<td align=center width=\"5%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
			"<td align=center width=\"5%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
#else
			"<td align=center><input type=\"checkbox\" name=\"sel%d\" value=1></td>\n"
			"<td align=center>%s</td>\n"
			"<td align=center><input type=\"checkbox\" name=\"en%d\" %s value=1></td>\n"
			"<td align=center>%s</td>\n"
			"<td align=center>%s</td>\n"
#endif
			"</tr>",
			Entry.idx,
			Entry.name+1, Entry.idx, Entry.enable?"checked":"",
			Entry.username, Entry.password);
	}
}
#endif
#endif

#ifdef CONFIG_USER_L2TPD_L2TPD
//#define L2TP_PID_FILENAME	"/var/run/openl2tpd.pid"
//#define L2TP_CONF			"/var/openl2tpd.conf"
#define L2TP_CONF				"/var/ppp/l2tp.conf"

void formL2TP(request * wp, char *path, char *query)
{
#ifdef CONFIG_USER_L2TPD_LNS
		char *submitUrl, *strAddL2tpClient, *strDelL2tpClient, *strVal;
		char *strAddL2tpAccount, *strDelL2tpAccount, *strSaveL2tpAccount;
		char *strSetL2tpServer;
#else
	char *submitUrl, *strAdd, *strDel, *strVal;
#endif
	char tmpBuf[100];
	int intVal, i;
	unsigned int entryNum, l2tpEntryNum;
#ifdef CONFIG_USER_PPTP_CLIENT_PPTP
	unsigned int pptpEntryNum;
	MIB_PPTP_T ptpEntry;
#endif
	MIB_CE_ATM_VC_T vcEntry;
	unsigned int wanNum;
	MIB_L2TP_T entry, tmpEntry;
#ifdef CONFIG_USER_L2TPD_LNS
	MIB_VPN_ACCOUNT_T account, tmpAccount;
	int accountNum;
#endif
	int enable;
	int pid;
	unsigned int map=0;//maximum rule num is MAX_L2TP_NUM

	strVal = boaGetVar(wp, "lst", "");

	// enable/disable L2TP
	if (strVal[0]) {
		strVal = boaGetVar(wp, "l2tpen", "");

		if ( strVal[0] == '1' ) {//enable
			enable = 1;
		}
		else//disable
			enable = 0;

		mib_set(MIB_L2TP_ENABLE, (void *)&enable);

		l2tp_take_effect();
#ifdef CONFIG_USER_L2TPD_LNS
		l2tpd_take_effect();
#endif
		goto setOK_l2tp;
	}

#ifdef CONFIG_USER_L2TPD_LNS
	strAddL2tpClient = boaGetVar(wp, "addClient", "");
	strDelL2tpClient = boaGetVar(wp, "delSelClient", "");
	strAddL2tpAccount = boaGetVar(wp, "addAccount", "");
	strDelL2tpAccount = boaGetVar(wp, "delSelAccount", "");
	strSaveL2tpAccount = boaGetVar(wp, "saveAccount", "");
	strSetL2tpServer = boaGetVar(wp, "addServer", "");
#else
	strAdd = boaGetVar(wp, "addL2TP", "");
	strDel = boaGetVar(wp, "delSel", "");
#endif

	memset(&entry, 0, sizeof(entry));
	l2tpEntryNum = mib_chain_total(MIB_L2TP_TBL); /* get chain record size */
#ifdef CONFIG_USER_PPTP_CLIENT_PPTP
	pptpEntryNum = mib_chain_total(MIB_PPTP_TBL);
#endif
	wanNum = mib_chain_total(MIB_ATM_VC_TBL);
#ifdef CONFIG_USER_L2TPD_LNS
		accountNum = mib_chain_total(MIB_VPN_ACCOUNT_TBL);
#endif

	/* Add new l2tp entry */
#ifdef CONFIG_USER_L2TPD_LNS
	if (strAddL2tpClient[0])
#else
	if (strAdd[0])
#endif
	{
#ifdef CONFIG_USER_L2TPD_LNS
		strVal = boaGetVar(wp, "c_name", "");
		strcpy(entry.name, strVal);
#endif
		strVal = boaGetVar(wp, "server", "");
		strcpy(entry.server, strVal);

		for (i=0; i<l2tpEntryNum; i++)
		{
			if ( !mib_chain_get(MIB_L2TP_TBL, i, (void *)&tmpEntry) )
				continue;

			if ( !strcmp(tmpEntry.server, entry.server)
#ifdef CONFIG_USER_L2TPD_LNS
				|| !strcmp(tmpEntry.name, entry.name)
#endif
				)
			{
				strcpy(tmpBuf, multilang(LANG_L2TP_VPN_INTERFACE_HAS_ALREADY_EXIST));
				goto setErr_l2tp;
			}

			map |= (1<< tmpEntry.idx);
		}
// Mason Yu. Add VPN ifIndex
#if 0
#ifdef CONFIG_USER_PPTP_CLIENT_PPTP
		for (i=0; i<pptpEntryNum; i++)
		{
			if ( !mib_chain_get(MIB_PPTP_TBL, i, (void *)&ptpEntry) )
				continue;
			map |= (1<<ptpEntry.idx);
		}
#endif
#endif
		strVal = boaGetVar(wp, "tunnel_auth", "");
		if (strVal[0])
			entry.tunnel_auth = 1;

		if (entry.tunnel_auth) {
			strVal = boaGetVar(wp, "tunnel_secret", "");
			strcpy(entry.secret, strVal);
		}

		strVal = boaGetVar(wp, "auth", "");
		entry.authtype = strVal[0] - '0';

		if (entry.authtype == 3) {
	        strVal = boaGetVar(wp, "enctype", "");
			entry.enctype = strVal[0] - '0';
		}

		strVal = boaGetVar(wp, "username", "");
		strcpy(entry.username, strVal);

		strVal = boaGetVar(wp, "password", "");
		strcpy(entry.password, strVal);

		strVal = boaGetVar(wp, "pppconntype", "");
		entry.conntype = strVal[0] - '0';

		if (entry.conntype == 1)
		{
			unsigned int idletime;
			// Mason Yu. If the connection is dial-on-demand, set dgw=1.
			entry.dgw = 1;
			strVal = boaGetVar(wp, "idletime", "");
			if (strVal[0]) {
				sscanf(strVal, "%u", &entry.idletime);
				//sscanf(strVal, "%u", &idletime);
				//printf("idletime is %d\n", idletime);
				//entry.idletime = idletime;
			}
		}

		strVal = boaGetVar(wp, "mtu", "");
		if (strVal[0]) {
			unsigned int mtu;
			sscanf(strVal, "%u", &entry.mtu);
			//sscanf(strVal, "%u", &mtu);
			//printf("mtu is %d\n", mtu);
			//entry.mtu = mtu;
		}

		strVal = boaGetVar(wp, "defaultgw", "");
		if (strVal[0]) {
			entry.dgw = 1;
		}

		if (entry.dgw == 1) {
			for (i=0; i<l2tpEntryNum; i++)
			{
				if ( !mib_chain_get(MIB_L2TP_TBL, i, (void *)&tmpEntry) )
					continue;

				if (tmpEntry.dgw)
				{
					strcpy(tmpBuf, multilang(LANG_DEFAULT_GW_HAS_ALREADY_EXIST));
					goto setErr_l2tp;
				}
			}
#ifdef CONFIG_USER_PPTP_CLIENT_PPTP
			for (i=0; i<pptpEntryNum; i++)
			{
				if (!mib_chain_get(MIB_PPTP_TBL, i, (void *)&ptpEntry))
					continue;
				if (ptpEntry.dgw)
				{
					strcpy(tmpBuf, multilang(LANG_DEFAULT_GW_HAS_ALREADY_EXIST_FOR_PPTP_VPN));
					goto setErr_l2tp;
				}
			}
#endif//endof CONFIG_USER_PPTP_CLIENT_PPTP
#ifdef CONFIG_NET_IPIP
			{
				MIB_IPIP_T ipEntry;
				int ipEntryNum;
				ipEntryNum = mib_chain_total(MIB_IPIP_TBL);
				for (i=0; i<ipEntryNum; i++) {
					if (!mib_chain_get(MIB_IPIP_TBL, i, (void *)&ipEntry))
						continue;
					if (ipEntry.dgw)
					{
						strcpy(tmpBuf, multilang(LANG_DEFAULT_GW_HAS_ALREADY_EXIST_FOR_IPIP_VPN));
						goto setErr_l2tp;
					}
				}
			}
#endif//end of CONFIG_NET_IPIP
			//check if conflicts with wan interface setting
			for (i=0; i<wanNum; i++)
			{
				if (!mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&vcEntry))
					continue;
				if (vcEntry.dgw)
				{
					strcpy(tmpBuf, multilang(LANG_DEFAULT_GW_HAS_ALREADY_EXIST));
					goto setErr_l2tp;
				}
			}
		}

#ifdef CONFIG_IPV6_VPN
		strVal = boaGetVar(wp, "IpProtocolType", "");
		if (strVal[0]) {
			entry.IpProtocol = strVal[0] - '0';
		}
#endif
#ifdef CONFIG_RTK_L34_ENABLE
{
		int remained;
		remained = Check_RG_Intf_Count();
		if(remained == 0){
			/*RG HW Table FULL*/
			strcpy(tmpBuf, strTableFull);
			goto setErr_l2tp;	
		}
}
#endif

		for (i=0; i<MAX_L2TP_NUM; i++) {
			if (!(map & (1<<i))) {
				entry.idx = i;
				break;
			}
		}
		// Mason Yu. Add VPN ifIndex
		// unit declarations for ppp  on if_sppp.h
		// (1) 0 ~ 7: pppoe/pppoa, (2) 8: 3G, (3) 9 ~ 10: PPTP, (4) 11 ~12: L2TP
		entry.ifIndex = TO_IFINDEX(MEDIA_L2TP, (entry.idx+11), L2TP_INDEX(entry.idx));
		//printf("***** L2TP: entry.ifIndex=0x%x\n", entry.ifIndex);

		intVal = mib_chain_add(MIB_L2TP_TBL, (void *)&entry);
		if (intVal == 0) {
			strcpy(tmpBuf, Tadd_chain_error);
			goto setErr_l2tp;
		}
		else if (intVal == -1) {
			strcpy(tmpBuf, strTableFull);
			goto setErr_l2tp;
		}
		l2tpEntryNum = mib_chain_total(MIB_L2TP_TBL); /* get chain record size */

		applyL2TP(&entry, 1, l2tpEntryNum-1);

		goto setOK_l2tp;
	}

	/* Delete entry */
#ifdef CONFIG_USER_L2TPD_LNS
	if (strDelL2tpClient[0])
#else
	if (strDel[0])
#endif
	{
		int i;
		unsigned int deleted = 0;

		for (i=l2tpEntryNum-1; i>=0; i--) {
			mib_chain_get(MIB_L2TP_TBL, i, (void *)&tmpEntry);
			snprintf(tmpBuf, 20, "s%d", tmpEntry.idx);
			strVal = boaGetVar(wp, tmpBuf, "");

			if (strVal[0] == '1') {
				deleted ++;
				applyL2TP(&tmpEntry, 0, i);
				if(mib_chain_delete(MIB_L2TP_TBL, i) != 1) {
					strcpy(tmpBuf, Tdelete_chain_error);
					goto setErr_l2tp;
				}
			}
		}

		if (deleted <= 0) {
			strcpy(tmpBuf, multilang(LANG_THERE_IS_NO_ITEM_SELECTED_TO_DELETE));
			goto setErr_l2tp;
		}

		goto setOK_l2tp;
	}

#ifdef CONFIG_USER_L2TPD_LNS
	/* configure l2tp server */
	if (strSetL2tpServer[0]) {
		MIB_VPND_T server, pre_server;
		int servernum;
		struct in_addr addr;

		memset(&server, 0, sizeof(MIB_VPND_T));

		server.type = VPN_L2TP;

		strVal = boaGetVar(wp, "s_auth", "");
		server.authtype = strVal[0] - '0';

		if (server.authtype == 3) {
			strVal = boaGetVar(wp, "s_enctype", "");
			server.enctype = strVal[0] - '0';
		}

		strVal = boaGetVar(wp, "s_tunnelAuth", "");
		if ( strVal[0] )
			server.tunnel_auth = 1;

		if(server.tunnel_auth == 1){
			strVal = boaGetVar(wp, "s_authKey", "");
			strcpy(server.tunnel_key, strVal);
		}

		strVal = boaGetVar(wp, "peeraddr", "");
		inet_aton(strVal, &addr);
		server.peeraddr = addr.s_addr;

		strVal = boaGetVar(wp, "localaddr", "");
		inet_aton(strVal, &addr);
		server.localaddr = addr.s_addr;

		/* check if l2tp server is modified */
		servernum = mib_chain_total(MIB_VPN_SERVER_TBL);
		for (i=0; i<servernum; i++) {
			if (!mib_chain_get(MIB_VPN_SERVER_TBL, i, &pre_server))
				continue;
			if (VPN_L2TP == pre_server.type)
				break;
		}
		if (i < servernum) {//we are to modify l2tp server
			if ((pre_server.authtype != server.authtype) ||
				(pre_server.enctype != server.enctype) ||
				(pre_server.tunnel_auth != server.tunnel_auth) ||
				(pre_server.tunnel_key != server.tunnel_key) ||
				(pre_server.localaddr != server.localaddr) ||
				(pre_server.peeraddr != server.peeraddr))
			{
				printf("l2tp server modified, all l2tpd account should be reenabled.\n");
				mib_chain_update(MIB_VPN_SERVER_TBL, &server, i);
				l2tpd_take_effect();
			}
		}
		else {//add l2tp server
			mib_chain_add(MIB_VPN_SERVER_TBL, &server);
		}

		goto setOK_l2tp;
	}
	/* Add new l2tp account entry */
	if (strAddL2tpAccount[0]) {
		memset(&account, 0, sizeof(MIB_VPN_ACCOUNT_T));
		map = 0;

		account.type = VPN_L2TP;

		strVal = boaGetVar(wp, "s_name", "");
		strcpy(account.name, "1");
		strcat(account.name, strVal);

		strVal = boaGetVar(wp, "tunnelen", "");
		account.enable = strVal[0] - '0';

		for (i=0; i<accountNum; i++)
		{
			if ( !mib_chain_get(MIB_VPN_ACCOUNT_TBL, i, (void *)&tmpAccount) )
				continue;

			if (VPN_PPTP == tmpAccount.type)//
				continue;

			if (!strcmp(tmpAccount.name, account.name))
			{
				strcpy(tmpBuf, multilang(LANG_L2TP_VPN_ACCOUNT_HAS_ALREADY_EXIST));
				goto setErr_l2tp;
			}

			map |= (1<< tmpAccount.idx);
		}

		strVal = boaGetVar(wp, "s_username", "");
		strcpy(account.username, strVal);

		strVal = boaGetVar(wp, "s_password", "");
		strcpy(account.password, strVal);

		for (i=0; i<MAX_L2TP_NUM; i++) {
			if (!(map & (1<<i))) {
				account.idx = i;
				break;
			}
		}

		intVal = mib_chain_add(MIB_VPN_ACCOUNT_TBL, (void *)&account);
		if (intVal == 0) {
			strcpy(tmpBuf, Tadd_chain_error);
			goto setErr_l2tp;
		}
		else if (intVal == -1) {
			strcpy(tmpBuf, strTableFull);
			goto setErr_l2tp;
		}

		if(account.enable == 1)
			applyL2tpAccount(&account, 1);

		goto setOK_l2tp;
	}

	if (strDelL2tpAccount[0]) {
		unsigned int deleted = 0;

		for (i=accountNum-1; i>=0; i--) {
			mib_chain_get(MIB_VPN_ACCOUNT_TBL, i, (void *)&tmpAccount);
			if (VPN_PPTP == tmpAccount.type)
				continue;
			snprintf(tmpBuf, 100, "sel%d", tmpAccount.idx);
			strVal = boaGetVar(wp, tmpBuf, "");
			if ( strVal[0] ) {
				deleted++;

				if(tmpAccount.enable == 1)
					applyL2tpAccount(&tmpAccount, 0);
				if(mib_chain_delete(MIB_VPN_ACCOUNT_TBL, i) != 1) {
					strcpy(tmpBuf, Tdelete_chain_error);
					goto setErr_l2tp;
				}
			}
		}

		if (deleted <= 0) {
			strcpy(tmpBuf, multilang(LANG_THERE_IS_NO_ITEM_SELECTED_TO_DELETE));
			goto setErr_l2tp;
		}

		goto setOK_l2tp;
	}

	if (strSaveL2tpAccount[0]) {
		int enaAccount;
		for (i=0; i<accountNum; i++) {
			mib_chain_get(MIB_VPN_ACCOUNT_TBL, i, (void *)&tmpAccount);
			if (VPN_PPTP == tmpAccount.type)
				continue;
			snprintf(tmpBuf, 100, "en%d", tmpAccount.idx);
			enaAccount = 0;
			strVal = boaGetVar(wp, tmpBuf, "");
			if ( strVal[0] ) {
				enaAccount = 1;
			}

			if (enaAccount == tmpAccount.enable)
				continue;
			else {
				tmpAccount.enable = enaAccount;
				mib_chain_update(MIB_VPN_ACCOUNT_TBL, (void *)&tmpAccount, i);
				if (enaAccount)
					applyL2tpAccount(&tmpAccount, 1);
				else
					applyL2tpAccount(&tmpAccount, 0);
			}
		}

		goto setOK_l2tp;
	}
#endif

	for (i=0; i<l2tpEntryNum; i++) {
		mib_chain_get(MIB_L2TP_TBL, i, (void *)&tmpEntry);
		snprintf(tmpBuf, 100, "submitl2tp%d", tmpEntry.idx);
		strVal = boaGetVar(wp, tmpBuf, "");
		if ( strVal[0] ) {
			if (tmpEntry.conntype != MANUAL) {
				applyL2TP(&tmpEntry, 0, i);		// delete ppp interface
				if ( !strcmp(strVal, "Connect") )
					applyL2TP(&tmpEntry, 1, i);	// add	a ppp interface
			}
			else if (tmpEntry.conntype == MANUAL) {
				if ( !strcmp(strVal, "Disconnect") )
					applyL2TP(&tmpEntry, 3, i);	// disconnect(down) for dial on demand
				if ( !strcmp(strVal, "Connect") ) {
					applyL2TP(&tmpEntry, 0, i);    // delete
					applyL2TP(&tmpEntry, 1, i);   	// new
					applyL2TP(&tmpEntry, 2, i);   	// connect(up) for dial on demand
				}
			}
		}
	}

setOK_l2tp:

// Magician: Commit immediately
#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif

#ifndef NO_ACTION
	pid = fork();
	if (pid) {
		waitpid(pid, NULL, 0);
	}
	else if (pid == 0) {
		snprintf(tmpBuf, 100, "%s/%s", _CONFIG_SCRIPT_PATH, _FIREWALL_SCRIPT_PROG);
		execl( tmpBuf, _FIREWALL_SCRIPT_PROG, NULL);
		exit(1);
	}
#endif

	submitUrl = boaGetVar(wp, "submit-url", "");   // hidden page
	if (submitUrl[0])
		boaRedirect(wp, submitUrl);
	else
		boaDone(wp, 200);
	return;

setErr_l2tp:
	ERR_MSG(tmpBuf);
}


int l2tpList(int eid, request * wp, int argc, char **argv)
{
	MIB_L2TP_T Entry;
	unsigned int entryNum, i;
	int l2tpEnable, l2tp_phase=0;
	char ifname[10], l2tp_status[20], devname[10], buff[256];
	char *state[3]={"Disconnected", "Connecting", "Connected"};
	FILE *fp;
	struct flock fl;
	int fd;
	int nBytesSent=0;
	char dev_ifname[IFNAMSIZ], web_ifname[15], action_str[15];
	int action_int;

	mib_get(MIB_L2TP_ENABLE, (void *)&l2tpEnable);

	entryNum = mib_chain_total(MIB_L2TP_TBL);
	for (i=0; i<entryNum; i++)
	{
		if (!mib_chain_get(MIB_L2TP_TBL, i, (void *)&Entry))
		{
			boaError(wp, 400, "Get chain record error!\n");
			return -1;
		}

		snprintf(ifname, 10, "l2tp%d", Entry.idx);

		l2tp_phase = 0;

		// file locking
		fd = open(L2TP_CONF, O_RDWR);
		if (fd != -1) {
			fl.l_type = F_RDLCK;
			fl.l_whence = SEEK_SET;
			fl.l_start = 0;
			fl.l_len = 0;
			fl.l_pid = getpid();
			if (fcntl(fd, F_SETLKW, &fl) == -1) {
				printf("l2tp read lock failed\n");
				close(fd);
				fd = -1;
			}
		}

		if (-1 != fd) {
			if (!(fp=fopen(L2TP_CONF, "r")))
				printf("%s not exists.\n", L2TP_CONF);
			else {
				fgets(buff, sizeof(buff), fp);
				while ( fgets(buff, sizeof(buff), fp) != NULL ) {
					//"if", "dev", "uptime", "totaluptime", "status");
					if(sscanf(buff, "%*s%s%*s%*s%s\n", devname, l2tp_status) != 2) {
						printf("Unsuported l2tp configuration format\n");
						break;
					}
					else {
						// Mason Yu
						//printf("ifname=%s, devname=%s, l2tp_status=%s\n", ifname, devname, l2tp_status);
						if (!strcmp(ifname, devname)) {
							if (!strncmp(l2tp_status, "session_establish", strlen("session_establish")))
								l2tp_phase = 2;
							else if (!strncmp(l2tp_status, "dead", strlen("dead")))
								l2tp_phase = 0;
							else
								l2tp_phase = 1;
							break;
						}
					}
				}
				fclose(fp);
			}
		}

		// file unlocking
		if (fd != -1) {
			fl.l_type = F_UNLCK;
			if (fcntl(fd, F_SETLK, &fl) == -1)
				printf("l2tp read unlock failed\n");
			close(fd);
		}

		// Mason Yu. Add VPN ifIndex
		ifGetName(Entry.ifIndex, dev_ifname, sizeof(dev_ifname));
		//snprintf(web_ifname, 15, "l2tp%d(%s)", Entry.idx, dev_ifname);
		snprintf(web_ifname, 15, "%s_l2tp%d", dev_ifname, Entry.idx);

		//if (Entry.conntype == MANUAL) {
			if( 2 == l2tp_phase)
				//snprintf(action_str, 15, "Disconnect");
				action_int =LANG_DISCONNECT;
			else
				//snprintf(action_str, 15, "Connect");
				action_int =LANG_CONNECT;
		//}
		//else {
		//	if( 2 == l2tp_phase)
		//		snprintf(action_str, 15, "Disable");
		//	else
		//		snprintf(action_str, 15, "Enable");
		//}

		if ((1 == l2tp_phase) || (0 == l2tpEnable)) {
			nBytesSent += boaWrite(wp, "<tr>"
#ifndef CONFIG_GENERAL_WEB
				"<td align=center width=\"3%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"><input type=\"checkbox\" name=\"s%d\" value=1></td>\n"
				"<td align=center width=\"5%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
				  "<td align=center width=\"5%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
				  "<td align=center width=\"5%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
				  "<td align=center width=\"5%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
				  "<td align=center width=\"5%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%d</td>\n"
				  "<td align=center width=\"5%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
				  "<td align=center width=\"8%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
#else
				"<td align=center width=\"3%%\"><input type=\"checkbox\" name=\"s%d\" value=1></td>\n"
				"<td align=center width=\"5%%\">%s</td>\n"
				  "<td align=center width=\"5%%\">%s</td>\n"
				  "<td align=center width=\"5%%\">%s</td>\n"
				  "<td align=center width=\"5%%\">%s</td>\n"
				  "<td align=center width=\"5%%\">%d</td>\n"
				  "<td align=center width=\"5%%\">%s</td>\n"
				  "<td align=center width=\"8%%\">%s</td>\n"
#endif
				"</tr>",
				Entry.idx,
#ifdef CONFIG_USER_L2TPD_LNS
				Entry.name,
#else
				web_ifname,
#endif
				Entry.server,
				multilang(Entry.tunnel_auth ? LANG_CHALLENGE : LANG_NONE),
				ppp_auth[Entry.authtype], Entry.mtu,
				multilang(Entry.dgw ? LANG_ON : LANG_OFF), state[l2tp_phase]);
		}
		else {
			nBytesSent += boaWrite(wp, "<tr>"
#ifndef CONFIG_GENERAL_WEB
				"<td align=center width=\"3%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"><input type=\"checkbox\" name=\"s%d\" value=1></td>\n"
				"<td align=center width=\"5%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
				  "<td align=center width=\"5%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
				  "<td align=center width=\"5%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
				  "<td align=center width=\"5%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
				  "<td align=center width=\"5%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%d</td>\n"
				  "<td align=center width=\"5%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
				  //"<td align=center width=\"8%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s ")
				  "<td align=center width=\"8%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"> "
				"<input type=\"submit\" id=\"%s\" value=\"%s\" name=\"submit%s\"></td>\n"
#else
				"<td align=center width=\"3%%\"><input type=\"checkbox\" name=\"s%d\" value=1></td>\n"
				"<td align=center width=\"5%%\">%s</td>\n"
				  "<td align=center width=\"5%%\">%s</td>\n"
				  "<td align=center width=\"5%%\">%s</td>\n"
				  "<td align=center width=\"5%%\">%s</td>\n"
				  "<td align=center width=\"5%%\">%d</td>\n"
				  "<td align=center width=\"5%%\">%s</td>\n"
				  //"<td align=center width=\"8%%\">%s ")
				  "<td align=center width=\"8%%\"> "
				"<input type=\"submit\" id=\"%s\" value=\"%s\" name=\"submit%s\" onClick=\"return on_submit(this)\"></td>\n"
#endif
				"</tr>",
				Entry.idx,
#ifdef CONFIG_USER_L2TPD_LNS
				Entry.name,
#else
				web_ifname,
#endif
				Entry.server,
				multilang(Entry.tunnel_auth ? LANG_CHALLENGE : LANG_NONE),
				ppp_auth[Entry.authtype], Entry.mtu,
				multilang(Entry.dgw ? LANG_ON : LANG_OFF),
				//state[l2tp_phase],
				ifname,
				//multilang((2 == l2tp_phase) ? "Disconnect" : "Connect"), ifname);
				multilang(action_int), ifname);
		}
	}
	return nBytesSent;
}
#ifdef CONFIG_USER_L2TPD_LNS
int l2tpServerList(int eid, request * wp, int argc, char **argv)
{
	int nBytesSent=0;
	MIB_VPN_ACCOUNT_T Entry;
	unsigned int entryNum, i;

	entryNum = mib_chain_total(MIB_VPN_ACCOUNT_TBL);
	for (i=0; i<entryNum; i++)
	{
		if (!mib_chain_get(MIB_VPN_ACCOUNT_TBL, i, (void *)&Entry))
		{
			boaError(wp, 400, "Get chain record error!\n");
			return -1;
		}

		if (VPN_PPTP == Entry.type)
			continue;

		nBytesSent += boaWrite(wp, "<tr>"
			"<td align=center width=\"3%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"><input type=\"checkbox\" name=\"sel%d\" value=1></td>\n"
			"<td align=center width=\"5%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
			"<td align=center width=\"5%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"><input type=\"checkbox\" name=\"en%d\" %s value=1></td>\n"
			"<td align=center width=\"5%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
			"<td align=center width=\"8%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
			"</tr>",
			Entry.idx,
			Entry.name+1, Entry.idx, Entry.enable?"checked":"",
			Entry.username, Entry.password);
	}
	return nBytesSent;
}
#endif
#endif //end of CONFIG_USER_L2TPD_L2TPD

#ifdef CONFIG_XFRM
#define	CONFIG_DIR	"/var/config"
#define IPSECCERT_FNAME	CONFIG_DIR"/cert.pem"
#define IPSECKEY_FNAME	CONFIG_DIR"/privKey.pem"

#define UPLOAD_MSG(url) { \
	boaHeader(wp); \
	boaWrite(wp, "<body><blockquote><h4>Upload a file successfully!" \
                "<form><input type=button value=\"  OK  \" OnClick=window.location.replace(\"%s\")></form></blockquote></body>", url);\
	boaFooter(wp); \
	boaDone(wp, 200); \
}

//copy from fmmgmt.c
//find the start and end of the upload file.
FILE *uploadGetCertFile(request *wp, unsigned int *startPos, unsigned *endPos)
{
	FILE *fp=NULL;
	struct stat statbuf;
	unsigned char *buf;
	int c;
	char boundary[80];


	if (wp->method == M_POST)
	{
		int i;

		fstat(wp->post_data_fd, &statbuf);
		lseek(wp->post_data_fd, SEEK_SET, 0);

		printf("file size=%d\n",statbuf.st_size);
		fp=fopen(wp->post_file_name, "rb");
		if(fp==NULL) goto error;

		memset(boundary, 0, sizeof(boundary));
		if( fgets(boundary, 80, fp)==NULL ) goto error;
		if( boundary[0]!='-' || boundary[1]!='-') goto error;

		i= strlen( boundary ) - 1;
		while( boundary[i]=='\r' || boundary[i]=='\n' )
		{
			boundary[i]='\0';
			i--;
		}
		printf( "boundary=%s\n", boundary );
	}
	else goto error;

   	//printf("_uploadGet\n");
	do
	{
		if(feof(fp))
		{
			printf("Cannot find start of file\n");
			goto error;
		}
		c= fgetc(fp);
		if (c!=0xd)
			continue;
		c= fgetc(fp);
		if (c!=0xa)
			continue;
		c= fgetc(fp);
		if (c!=0xd)
			continue;
		c= fgetc(fp);
		if (c!=0xa)
			continue;
		break;
	}while(1);
	(*startPos)=ftell(fp);

	if(fseek(fp,statbuf.st_size-0x200,SEEK_SET)<0)
		goto error;

	do
	{
		if(feof(fp))
		{
			printf("Cannot find end of file\n");
			goto error;
		}
		c= fgetc(fp);
		if (c!=0xd)
			continue;
		c= fgetc(fp);
		if (c!=0xa)
			continue;

		{
			int i, blen;

			blen= strlen( boundary );
			for( i=0; i<blen; i++)
			{
				c= fgetc(fp);
				//printf("%c(%u)", c, c);
				if (c!=boundary[i])
				{
					ungetc( c, fp );
					break;
				}
			}
			//printf("\r\n");
			if( i!=blen ) continue;
		}

		break;
	}while(1);
	(*endPos)=ftell(fp)-strlen(boundary)-2;

	return fp;
error:
   	return NULL;
}

void formIPsec(request * wp, char *path, char *query)
{
	char *strVal;
	char *addConf, *deleteConf, *enable, *disable, *refresh;
	char *submitUrl;
	int negoType = 0, intVal;
	long netmask;
	char tmpBuf[100];
	struct in_addr ipAddr;
	int i, entryNum;
	MIB_IPSEC_T Entry;
    int found = 0;
	
	addConf = boaGetVar(wp, "saveConf", "");
	deleteConf = boaGetVar(wp, "delConf", "");
	enable = boaGetVar(wp, "enableConf", "");
	disable = boaGetVar(wp, "disableConf", "");
	memset(&Entry, 0, sizeof(MIB_IPSEC_T));
	if(addConf[0]){
		strVal = boaGetVar(wp, "negoType", "");
		if(strVal[0] == '1')
			Entry.negotiationType= 1;  //0:IKE; 1:Manual

		strVal = boaGetVar(wp, "transMode", ""); //0-tunnel; 1-transport;
		Entry.transportMode= strVal[0] - '0';

		strVal = boaGetVar(wp, "rtunnelAddr", "");
		if(strVal[0]) {
			if (!inet_aton(strVal, (struct in_addr *)&Entry.remoteTunnel)) {
				strcpy(tmpBuf, strInvalIP);
				goto setErr_IPsec;
			}
		}

		strVal = boaGetVar(wp, "remoteip", "");
		if (strVal[0]) {
			if (!inet_aton(strVal, (struct in_addr *)&Entry.remoteIP)) {
				strcpy(tmpBuf, strInvalIP);
				goto setErr_IPsec;
			}
		}
		
		strVal = boaGetVar(wp, "remotemask", "");
		if (strVal[0]) {
			if(!inet_aton(strVal, &ipAddr)) {
				strcpy(tmpBuf, strInvalIP);
				goto setErr_IPsec;
			}
			netmask = ntohl(ipAddr.s_addr);
			intVal = 0;
			for(intVal = 0; intVal < 32 && !((netmask >> intVal) & 1); intVal++);
			Entry.remoteMask = 32 - intVal;
		}
		
		strVal = boaGetVar(wp, "ltunnelAddr", "");
		if (strVal[0]) {
			if (!inet_aton(strVal, (struct in_addr *)&Entry.localTunnel)) {
				strcpy(tmpBuf, strInvalIP);
				goto setErr_IPsec;
			}
		}

		strVal = boaGetVar(wp, "localip", "");
		if (strVal[0]) {
			if (!inet_aton(strVal, (struct in_addr *)&Entry.localIP)) {
				strcpy(tmpBuf, strInvalIP);
				goto setErr_IPsec;
			}
		}

		strVal = boaGetVar(wp, "localmask", "");
		if (strVal[0]) {
			if(!inet_aton(strVal, &ipAddr)) {
				strcpy(tmpBuf, strInvalIP);
				goto setErr_IPsec;
			}
			netmask = ntohl(ipAddr.s_addr);
			intVal = 0;
			for(intVal = 0; intVal < 32 && !((netmask >> intVal) & 1); intVal++);
			Entry.localMask = 32 - intVal;
		}

		strVal = boaGetVar(wp, "encapsType", "");
			Entry.encapMode = strVal[0] - '0';

		strVal = boaGetVar(wp, "filterProtocol", "");
			Entry.filterProtocol= strVal[0] - '0';

		if(Entry.filterProtocol==1 || Entry.filterProtocol==2){
			strVal = boaGetVar(wp, "filterPort", "");
			if (strVal[0]) {		
				sscanf(strVal, "%d", &Entry.filterPort);
			}
		}

		if(Entry.negotiationType ==0){
			//IKE mode
			strVal = boaGetVar(wp, "ikeAuthMethod", "");
			Entry.auth_method = strVal[0] - '0';

			if(0 == Entry.auth_method)
			{
				strVal = boaGetVar(wp, "psk", "");
				if(strlen(strVal)>128){
					strcpy(tmpBuf, multilang(LANG_PSK_LENGTH_ERROR_TOO_LONG)); //length error, too long!
					goto setErr_IPsec;
				}
				strncpy(Entry.psk, strVal, 130);
			}

			strVal = boaGetVar(wp, "negoMode", "");
			Entry.ikeMode = strVal[0] - '0';

			strVal = boaGetVar(wp, "ikeAliveTime", "");
			if (strVal[0]) {		
				sscanf(strVal, "%d", &Entry.ikeAliveTime);
			}

			strVal = boaGetVar(wp, "ikeProposal0", "");
			Entry.ikeProposal[0]= strVal[0] - '0';

			strVal = boaGetVar(wp, "ikeProposal1", "");
			Entry.ikeProposal[1]= strVal[0] - '0';
			
			strVal = boaGetVar(wp, "ikeProposal2", "");
			Entry.ikeProposal[2]= strVal[0] - '0';
			
			strVal = boaGetVar(wp, "ikeProposal3", "");
			Entry.ikeProposal[3]= strVal[0] - '0';

			strVal = boaGetVar(wp, "dhArray_p2", "");			
			Entry.pfs_group = 1<<(strVal[0] - '0');
			
			if(Entry.encapMode != 2)        //ESP or ESP+AH
			{
				strVal = boaGetVar(wp, "encrypt_p2", "");
				if (strVal[0]) {		
					sscanf(strVal, "%d", &Entry.encrypt_group);
				}
			}
			else
			{
				Entry.encrypt_group = 1;    //none_enc for AH only
			}
			
			strVal = boaGetVar(wp, "auth_p2", "");
			if (strVal[0]) {		
				sscanf(strVal, "%d", &Entry.auth_group);
			}

			strVal = boaGetVar(wp, "saAliveTime", "");
			if (strVal[0]) {		
				sscanf(strVal, "%d", &Entry.saAliveTime);
			}

			strVal = boaGetVar(wp, "saAliveByte", "");
			if (strVal[0]) {		
				sscanf(strVal, "%d", &Entry.saAliveByte);
			}
		}else{
			//manual mode	
			if(Entry.encapMode%2 == 1){
				strVal = boaGetVar(wp, "esp_e_algo", "");
				Entry.espEncrypt = strVal[0] - '0';
				
				strVal = boaGetVar(wp, "esp_ekey", "");
				strcpy(Entry.espEncryptKey, strVal);

				strVal = boaGetVar(wp, "esp_a_algo", "");
				Entry.espAuth= strVal[0] - '0';

				strVal = boaGetVar(wp, "esp_akey", "");
				strcpy(Entry.espAuthKey, strVal);

				strVal = boaGetVar(wp, "spi_out_esp", "");
				if (strVal[0]) {		
					sscanf(strVal, "%d", &Entry.espOUTSPI);
				}

				strVal = boaGetVar(wp, "spi_in_esp", "");
				if (strVal[0]) {		
					sscanf(strVal, "%d", &Entry.espINSPI);
				}
			}
			
			if(Entry.encapMode/2 == 1){
				strVal = boaGetVar(wp, "ah_algo", "");
				Entry.ahAuth= strVal[0] - '0';

				strVal = boaGetVar(wp, "ah_key", "");
				strcpy(Entry.ahAuthKey, strVal);

				strVal = boaGetVar(wp, "spi_out_ah", "");
				if (strVal[0]) {		
					sscanf(strVal, "%d", &Entry.ahOUTSPI);
				}

				strVal = boaGetVar(wp, "spi_in_ah", "");
				if (strVal[0]) {		
					sscanf(strVal, "%d", &Entry.ahINSPI);
				}
			}
		}

		Entry.enable = Entry.state = 1;
		intVal = mib_chain_add(MIB_IPSEC_TBL, (void *)&Entry);
		if (intVal == 0) {
			strcpy(tmpBuf, Tadd_chain_error);
			goto setErr_IPsec;
		}
		else if (intVal == -1) {
			strcpy(tmpBuf, strTableFull);
			goto setErr_IPsec;
		}

		ipsec_take_effect();
		goto setOK_IPsec;
	}
	if(deleteConf[0]){
		//delete a configuration
		entryNum = mib_chain_total(MIB_IPSEC_TBL);	
		for (i=entryNum-1; i>=0; i--) {
			mib_chain_get(MIB_IPSEC_TBL, i, (void *)&Entry);
			snprintf(tmpBuf, 100, "row_%d", i);
			strVal = boaGetVar(wp, tmpBuf, "");

			if (strVal[0] == '1') {
                found = 1;
                if(Entry.state)
                {
                    Entry.state = 0;
                    apply_nat_rule(&Entry);
                }
				if(mib_chain_delete(MIB_IPSEC_TBL, i) != 1) {
					strcpy(tmpBuf, Tdelete_chain_error);
					goto setErr_IPsec;
				}
			}
		}
        if(found)
		ipsec_take_effect();
		goto setOK_IPsec;
	}
	if(enable[0]){
		//enable a configuration
		entryNum = mib_chain_total(MIB_IPSEC_TBL);	
		for (i=0; i<entryNum; i++) {
			mib_chain_get(MIB_IPSEC_TBL, i, (void *)&Entry);
			snprintf(tmpBuf, 100, "row_%d", i);
			strVal = boaGetVar(wp, tmpBuf, "");

			if (strVal[0] == '1') {
				if(Entry.enable == 0){
                    found = 1;
					Entry.enable = 1;
					mib_chain_update(MIB_IPSEC_TBL, &Entry, i);
				}
			}
		}
        if(found)
		ipsec_take_effect();
		goto setOK_IPsec;
	}
	if(disable[0]){
		//disable a configuration
		entryNum = mib_chain_total(MIB_IPSEC_TBL);	
		for (i=entryNum-1; i>=0; i--) {
			mib_chain_get(MIB_IPSEC_TBL, i, (void *)&Entry);
			snprintf(tmpBuf, 100, "row_%d", i);
			strVal = boaGetVar(wp, tmpBuf, "");

			if (strVal[0] == '1') {
				if(Entry.enable == 1){
                    found = 1;
					Entry.state = Entry.enable = 0;
					mib_chain_update(MIB_IPSEC_TBL, &Entry, i);
				}
			}
		}
        if(found)
		ipsec_take_effect();
		goto setOK_IPsec;
	}

	if(refresh[0]){
		//refresh
		
	}

setOK_IPsec:

// Magician: Commit immediately
#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif

	submitUrl = boaGetVar(wp, "submit-url", "");   // hidden page
	if (submitUrl[0])
		boaRedirect(wp, submitUrl);
	else
		boaDone(wp, 200);
	return;

setErr_IPsec:
	ERR_MSG(tmpBuf);
}

void formIPSecCert(request * wp, char *path, char *query)
{
    char *strData;
    char tmpBuf[100];
    FILE *fp=NULL,*fp_input;
    unsigned char *buf;
    unsigned int startPos,endPos,nLen,nRead;
    if ((fp = uploadGetCertFile(wp, &startPos, &endPos)) == NULL)
    {
        strcpy(tmpBuf, "Upload error!");
        goto setErr_ipseccert;
    }

    nLen = endPos - startPos;
    //printf("filesize is %d\n", nLen);
    buf = malloc(nLen+1);
    if (!buf)
    {
        strcpy(tmpBuf, "Malloc failed!");
        goto setErr_ipseccert;
    }

    fseek(fp, startPos, SEEK_SET);
    nRead = fread((void *)buf, 1, nLen, fp);
    buf[nRead]=0;
    if (nRead != nLen)
        printf("Read %d bytes, expect %d bytes\n", nRead, nLen);

    //printf("write to %d bytes from %08x\n", nLen, buf);

    fp_input=fopen(IPSECCERT_FNAME,"w");
    if (!fp_input)
    {
        strcpy(tmpBuf, "create cert file fail!");
        goto setErr_ipseccert;
    }

    fprintf(fp_input,buf);
    printf("create file %s\n", IPSECCERT_FNAME);
    free(buf);
    fclose(fp_input);

#ifdef CONFIG_USER_FLATFSD_XXX
    if( va_cmd( "/bin/flatfsd",1,1,"-s" ) )
        printf( "[%d %d]:exec 'flatfsd -s' error!",__FILE__, __LINE__);
#endif

    strData = boaGetVar(wp, "submit-url", "/ipsec.asp");
    UPLOAD_MSG(strData);// display reconnect msg to remote
    return;

setErr_ipseccert:
    ERR_MSG(tmpBuf);
}


void formIPSecKey(request * wp, char *path, char *query)
{
    char *strData;
    char tmpBuf[100];
    FILE *fp=NULL,*fp_input;
    unsigned char *buf;
    unsigned int startPos,endPos,nLen,nRead;
    if ((fp = uploadGetCertFile(wp, &startPos, &endPos)) == NULL)
    {
        strcpy(tmpBuf, "Upload error!");
        goto setErr_ipseckey;
    }

    nLen = endPos - startPos;
    //printf("filesize is %d\n", nLen);
    buf = malloc(nLen+1);
    if (!buf)
    {
        strcpy(tmpBuf, "Malloc failed!");
        goto setErr_ipseckey;
    }

    fseek(fp, startPos, SEEK_SET);
    nRead = fread((void *)buf, 1, nLen, fp);
    buf[nRead]=0;
    if (nRead != nLen)
        printf("Read %d bytes, expect %d bytes\n", nRead, nLen);

    //printf("write to %d bytes from %08x\n", nLen, buf);

    fp_input=fopen(IPSECKEY_FNAME,"w");
    if (!fp_input)
    {
        strcpy(tmpBuf, "create key file fail!");
        goto setErr_ipseckey;
    }
    fprintf(fp_input,buf);
    printf("create file %s\n", IPSECKEY_FNAME);
    free(buf);
    fclose(fp_input);

#ifdef CONFIG_USER_FLATFSD_XXX
    if( va_cmd( "/bin/flatfsd",1,1,"-s" ) )
        printf( "[%d]:exec 'flatfsd -s' error!",__FILE__ );
#endif

    strData = boaGetVar(wp, "submit-url", "/ipsec.asp");
    UPLOAD_MSG(strData);// display reconnect msg to remote
    return;

setErr_ipseckey:
    ERR_MSG(tmpBuf);
}


int ipsec_wanList(int eid, request * wp, int argc, char **argv){
	int nBytesSent=0;
	int wanMode;
	unsigned int entryNum, i;
	MIB_CE_ATM_VC_T Entry;
	char ifName[16];
	entryNum = mib_chain_total(MIB_ATM_VC_TBL);
	wanMode = GetWanMode();
	
	for(i=0; i<entryNum; i++){
		if (!mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&Entry)){
			boaError(wp, 400, "Get chain record error!\n");
			return -1;
		}
		if(((!(wanMode&1))&&MEDIA_INDEX(Entry.ifIndex)==MEDIA_ATM)
		  #ifdef CONFIG_PTMWAN
			||((!(wanMode&1))&&MEDIA_INDEX(Entry.ifIndex)==MEDIA_PTM)
		  #endif /*CONFIG_PTMWAN*/
			||((!(wanMode&2))&&MEDIA_INDEX(Entry.ifIndex)==MEDIA_ETH))
			continue;
		getDisplayWanName((void *)&Entry, ifName);
		nBytesSent += boaWrite(wp,
			"<option value=\"%s\">%s</option>",
			Entry.WanName, ifName);
	}
	return nBytesSent;
}

int ipsec_ikePropList(int eid, request * wp, int argc, char **argv){
	int nBytesSent=0;
	int i;

	for(i=0; ikeProps[i].valid!=0; i++){
		nBytesSent += boaWrite(wp,	
			"<option value=\"%d\">%s</option>",
			i, ikeProps[i].name);
	}
}

int ipsec_encrypt_p2List(int eid, request * wp, int argc, char **argv){
	int nBytesSent=0;
	int i;

	for(i=0; curr_encryptAlgm[i]!=NULL; i++){
		nBytesSent += boaWrite(wp,			
			"<input type=\"checkbox\" name=\"%s\" id=\"%s\" value=\"1\" %s onClick=\"encrypt_p2_change('%s', %d)\"/>%s&nbsp;",			
			curr_encryptAlgm[i], curr_encryptAlgm[i], i!=0?"checked":"", curr_encryptAlgm[i], i, curr_encryptAlgm[i]);	
	}
}

int ipsec_auth_p2List(int eid, request * wp, int argc, char **argv){
	int nBytesSent=0;
	int i;

	for(i=0; curr_authAlgm[i]!=NULL; i++){
		nBytesSent += boaWrite(wp,			
			"<input type=\"checkbox\" name=\"%s\" id=\"%s\" value=\"1\" %s onClick=\"auth_p2_change('%s', %d)\"/>%s&nbsp;",			
			curr_authAlgm[i], curr_authAlgm[i], i!=0?"checked":"", curr_authAlgm[i], i, curr_authAlgm[i]);	
	}
}

int ipsecAlgoScripts(int eid, request * wp, int argc, char **argv){
	int nBytesSent=0;
	int i;

    int dh_all=0, encrypt_all=0, auth_all=0;

    for(i=1; curr_dhArray[i]!=NULL; i++){
		dh_all |= (1<<i);	
	}

    for(i=1; curr_encryptAlgm[i]!=NULL; i++){
		encrypt_all |= (1<<i);	
	}
    
	for(i=1; curr_authAlgm[i]!=NULL; i++){
		auth_all |= (1<<i);
	}

    nBytesSent += boaWrite(wp, "dh_algo_p2 = %d;\n", dh_all);
    nBytesSent += boaWrite(wp, "encrypt_algo_p2 = %d;\n", encrypt_all);
    nBytesSent += boaWrite(wp, "auth_algo_p2 = %d;\n", auth_all);
}


int ipsec_infoList(int eid, request * wp, int argc, char **argv){
	int nBytesSent=0;
	char *strVal;
	MIB_IPSEC_T Entry;
	int i, intVal, entryNum, encap = 0;
	char local[20], remote[20], remoteTunnel[20], localTunnel[20];
	char *enableStr[2]={"Disable", "Enable"};
	char *stateStr[2]={"Not Apply", "Applyed"};
	char *negoType[2]={"AUTO", "Manual"};
	char *encapStr[3]={"ESP", "AH", "ESP+AH"};
	char *transportMode[2]={"tunnel", "transport"};
	char *filterProtocol[4]={"any", "tcp", "udp", "icmp"};
	char filterPort[10];

	entryNum = mib_chain_total(MIB_IPSEC_TBL);
	for (i=0; i<entryNum; i++){
		if (!mib_chain_get(MIB_IPSEC_TBL, i, (void *)&Entry)){
			boaError(wp, 400, "Get chain record error!\n");	
			return -1;
		}

		strVal = inet_ntoa(*(struct in_addr*)Entry.remoteIP);
		strncpy(remote, strVal, 20);

		strVal = inet_ntoa(*(struct in_addr*)Entry.localIP);
		strncpy(local, strVal, 20);

		strVal = inet_ntoa(*(struct in_addr*)Entry.remoteTunnel);
		strncpy(remoteTunnel, strVal, 20);

		strVal = inet_ntoa(*(struct in_addr*)Entry.localTunnel);
		strncpy(localTunnel, strVal, 20);
		
		if(Entry.filterPort != 0)
			snprintf(filterPort, 10, "%d", Entry.filterPort);
		else
			snprintf(filterPort, 10, "%s", "any");

		nBytesSent = boaWrite(wp, "<tr>"
#ifndef CONFIG_GENERAL_WEB
			"<td class=\"infoContent\"><input type=\"checkbox\" name=\"row_%d\" value=1></td>\n"
			"<td class=\"infoContent\">%s</td>\n"
			"<td class=\"infoContent\">%s</td>\n"
			"<td class=\"infoContent\">%s</td>\n"
			"<td class=\"infoContent\">%s</td>\n"
			"<td class=\"infoContent\">%s</td>\n"
			"<td class=\"infoContent\">%s</td>\n"
			"<td class=\"infoContent\">%s</td>\n"
			"<td class=\"infoContent\">%s</td>\n"
			"<td class=\"infoContent\">%s</td>\n"
			"<td class=\"infoContent\">%s</td>\n"
			"</tr>",
#else
			"<td><input type=\"checkbox\" name=\"row_%d\" value=1></td>\n"
			"<td>%s</td>\n"
			"<td>%s</td>\n"
			"<td>%s</td>\n"
			"<td>%s</td>\n"
			"<td>%s</td>\n"
			"<td>%s</td>\n"
			"<td>%s</td>\n"
			"<td>%s</td>\n"
			"<td>%s</td>\n"
			"<td>%s</td>\n"
			"</tr>",
#endif
			i, enableStr[Entry.enable], stateStr[Entry.state], negoType[Entry.negotiationType], remoteTunnel, remote, localTunnel, local,
			encapStr[Entry.encapMode-1], filterProtocol[Entry.filterProtocol], filterPort);
	}
}

#endif

#ifdef CONFIG_NET_IPIP
//max MAX_IPIP_NUM IPIP tunnels.
static unsigned char IPIP_STATUS[MAX_IPIP_NUM]={0};
int applyIPIP(MIB_IPIP_T *pentry, int enable);

void ipip_take_effect()
{
	MIB_IPIP_T entry;
	unsigned int entrynum, i;//, j;
	int enable;

	if ( !mib_get(MIB_IPIP_ENABLE, (void *)&enable) )
		return;

	entrynum = mib_chain_total(MIB_IPIP_TBL);

	//delete all firstly
	for (i=0; i<entrynum; i++)
	{
		if ( !mib_chain_get(MIB_IPIP_TBL, i, (void *)&entry) )
			return;

		applyIPIP(&entry, 0);
	}

	if (enable) {
		for (i=0; i<entrynum; i++)
		{
			if ( !mib_chain_get(MIB_IPIP_TBL, i, (void *)&entry) )
				return;

			applyIPIP(&entry, 1);
		}
	}
}

int applyIPIP(MIB_IPIP_T *pentry, int enable)
{
	char *action;
	char local[20];
	char remote[20];
	char ifname[IFNAMSIZ];
	char nat_cmd[100];

	if (enable) {
		IPIP_STATUS[pentry->idx] = 1;
		action = "add";
	}
	else {
		IPIP_STATUS[pentry->idx] = 0;
		action = "del";
	}

	snprintf(local, 20, "%s", inet_ntoa(*((struct in_addr *)&pentry->saddr)));
	snprintf(remote, 20, "%s", inet_ntoa(*((struct in_addr *)&pentry->daddr)));
	ifGetName(pentry->ifIndex, ifname, sizeof(ifname));	// Mason Yu. Add VPN ifIndex

	if (!enable) {
		printf("%s:ifconfig %s down\n", __func__, ifname);
		va_cmd("/bin/ifconfig", 2, 1, ifname, "down");
	}

	printf("%s:ip tunnel %s %s mode ipip remote %s local %s\n", __func__, action, ifname, remote, local);
	va_cmd("/bin/ip", 9, 1, "tunnel", action, ifname, "mode", "ipip", "remote", remote, "local", local);

	if (enable) {
		printf("%s:ifconfig %s up\n", __func__, ifname);
		va_cmd("/bin/ifconfig", 2, 1, ifname, "up");

		/*if def gw enabled, then add new default route now. don't do SNAT for original packet.*/
		if (pentry->dgw) {
			printf("%s:route del default.\n", __func__);
			va_cmd("/bin/route", 2, 1, "del", "default");

			printf("%s:route add default %s\n", __func__, ifname);
			va_cmd("/bin/route", 3, 1, "add", "default", ifname);

#ifdef NEW_PORTMAPPING
			extern void modPolicyRouteTable(const char *pptp_ifname, struct in_addr *real_addr);
			modPolicyRouteTable(ifname, (struct in_addr *)&pentry->saddr);
#endif//endof NEW_PORTMAPPING

			sprintf(nat_cmd, "iptables -D FORWARD -o %s -p tcp --syn -j TCPMSS --set-mss 1480", ifname);
			printf("%s:%s\n", __func__, nat_cmd);
			system(nat_cmd);

			sprintf(nat_cmd, "iptables -I FORWARD 1 -o %sd -p tcp --syn -j TCPMSS --set-mss 1480", ifname);
			printf("%s:%s\n", __func__, nat_cmd);
			system(nat_cmd);
		}
	}

	return 1;
}

void formIPIP(request * wp, char *path, char *query)
{
	char *submitUrl, *strAddIPIP, *strDelIPIP, *strVal;
	char tmpBuf[100];
	int intVal;
	unsigned int ipEntryNum, i;
	MIB_IPIP_T entry, tmpEntry;
#ifdef CONFIG_USER_L2TPD_L2TPD
	unsigned int l2tpEntryNum;
	MIB_L2TP_T l2tpEntry;
#endif//end of CONFIG_USER_L2TPD_L2TPD
#ifdef CONFIG_USER_PPTP_CLIENT_PPTP
	unsigned int pptpEntryNum;
	MIB_PPTP_T pptpEntry;
#endif//end of CONFIG_USER_PPTP_CLIENT_PPTP
	MIB_CE_ATM_VC_T vcEntry;
	unsigned int wanNum;
	int enable;
	int pid;
	unsigned int map=0;//maximum rule num is MAX_IPIP_NUM
	char ifname[IFNAMSIZ];

	strVal = boaGetVar(wp, "lst", "");

	// enable/disable IPIP
	if (strVal[0]) {
		strVal = boaGetVar(wp, "ipipen", "");

		if ( strVal[0] == '1' ) {//enable
			enable = 1;
		}
		else//disable
			enable = 0;

		mib_set(MIB_IPIP_ENABLE, (void *)&enable);

		ipip_take_effect();

		goto setOK_ipip;
	}

	strAddIPIP = boaGetVar(wp, "addIPIP", "");
	strDelIPIP = boaGetVar(wp, "delSel", "");

	memset(&entry, 0, sizeof(entry));
	ipEntryNum = mib_chain_total(MIB_IPIP_TBL); /* get chain record size */
#ifdef CONFIG_USER_L2TPD_L2TPD
	l2tpEntryNum = mib_chain_total(MIB_L2TP_TBL); /* get chain record size */
#endif//end of CONFIG_USER_L2TPD_L2TPD
#ifdef CONFIG_USER_PPTP_CLIENT_PPTP
	pptpEntryNum = mib_chain_total(MIB_PPTP_TBL); /* get chain record size */
#endif//end of CONFIG_USER_PPTP_CLIENT_PPTP
	wanNum = mib_chain_total(MIB_ATM_VC_TBL);

	/* Add new ipip entry */
	if (strAddIPIP[0]) {
		printf("add ipip entry.\n");

		for (i=0; i<ipEntryNum; i++)
		{
			if ( !mib_chain_get(MIB_IPIP_TBL, i, (void *)&tmpEntry) )
				continue;

			/*
			if ( !strcmp(tmpEntry.tunnel_name, entry.tunnel_name))
			{
				strcpy(tmpBuf, "ipip vpn interface has already exist!");
				goto setErr_ipip;
			}
			*/

			map |= (1<< tmpEntry.idx);
		}

		// Mason Yu. Add VPN ifIndex
		for (i=0; i<MAX_IPIP_NUM; i++) {
			if (!(map & (1<<i))) {
				entry.idx = i;
				break;
			}
		}
		entry.ifIndex = TO_IFINDEX(MEDIA_IPIP, 0xff, IPIP_INDEX(entry.idx));
		//printf("***** IPIP: entry.ifIndex=0x%x\n", entry.ifIndex);

		strVal = boaGetVar(wp, "remote", "");
		inet_aton(strVal, &entry.daddr);

		strVal = boaGetVar(wp, "local", "");
		inet_aton(strVal, &entry.saddr);

		strVal = boaGetVar(wp, "defaultgw", "");
		if (strVal[0]) {
			entry.dgw = 1;
			for (i=0; i<ipEntryNum; i++)
			{
				if ( !mib_chain_get(MIB_IPIP_TBL, i, (void *)&tmpEntry) )
					continue;

				if (tmpEntry.dgw)
				{
					strcpy(tmpBuf, multilang(LANG_DEFAULT_GW_HAS_ALREADY_EXIST));
					goto setErr_ipip;
				}
			}

			//check if conflicts with wan interface setting
			for (i=0; i<wanNum; i++)
			{
				if (!mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&vcEntry))
					continue;
				if (vcEntry.dgw)
				{
					strcpy(tmpBuf, multilang(LANG_DEFAULT_GW_HAS_ALREADY_EXIST));
					goto setErr_ipip;
				}
			}

#ifdef CONFIG_USER_L2TPD_L2TPD
			for (i=0; i<l2tpEntryNum; i++)
			{
				if (!mib_chain_get(MIB_L2TP_TBL, i, (void *)&l2tpEntry))
					continue;
				if (l2tpEntry.dgw)
				{
					strcpy(tmpBuf, multilang(LANG_DEFAULT_GW_HAS_ALREADY_EXIST_FOR_L2TP_VPN));
					goto setErr_ipip;
				}
			}
#endif//end of CONFIG_USER_L2TPD_L2TPD
#ifdef CONFIG_USER_PPTP_CLIENT_PPTP
			for (i=0; i<pptpEntryNum; i++)
			{
				if (!mib_chain_get(MIB_PPTP_TBL, i, (void *)&pptpEntry))
					continue;
				if (pptpEntry.dgw)
				{
					strcpy(tmpBuf, multilang(LANG_DEFAULT_GW_HAS_ALREADY_EXIST_FOR_PPTP_VPN));
					goto setErr_ipip;
				}
			}
#endif//end of CONFIG_USER_PPTP_CLIENT_PPTP
		}

		intVal = mib_chain_add(MIB_IPIP_TBL, (void *)&entry);
		if (intVal == 0) {
			strcpy(tmpBuf, Tadd_chain_error);
			goto setErr_ipip;
		}
		else if (intVal == -1) {
			strcpy(tmpBuf, strTableFull);
			goto setErr_ipip;
		}

		applyIPIP(&entry, 1);

		goto setOK_ipip;
	}

	/* Delete entry */
	if (strDelIPIP[0])
	{
		int i;
		unsigned int deleted = 0;

		printf("delete ipip entry(total %d).\n", ipEntryNum);
		for (i=ipEntryNum-1; i>=0; i--) {
			mib_chain_get(MIB_IPIP_TBL, i, (void *)&tmpEntry);
			snprintf(tmpBuf, 20, "s%d", tmpEntry.idx);
			strVal = boaGetVar(wp, tmpBuf, "");

			if (strVal[0] == '1') {
				deleted ++;
				applyIPIP(&tmpEntry, 0);
				if(mib_chain_delete(MIB_IPIP_TBL, i) != 1) {
					strcpy(tmpBuf, Tdelete_chain_error);
					goto setErr_ipip;
				}
			}
		}

		if (deleted <= 0) {
			strcpy(tmpBuf, multilang(LANG_THERE_IS_NO_ITEM_SELECTED_TO_DELETE));
			goto setErr_ipip;
		}

		goto setOK_ipip;
	}

	for (i=0; i<ipEntryNum; i++) {
		mib_chain_get(MIB_IPIP_TBL, i, (void *)&tmpEntry);
		ifGetName(tmpEntry.ifIndex, ifname, sizeof(ifname));	// Mason Yu. Add VPN ifIndex
		snprintf(tmpBuf, 100, "submit%s", ifname);
		strVal = boaGetVar(wp, tmpBuf, "");
		if ( strVal[0] ) {
			applyIPIP(&tmpEntry, 0);
			if ( !strcmp(strVal, "Connect") )
				applyIPIP(&tmpEntry, 1);
		}
	}

setOK_ipip:

// Magician: Commit immediately
#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif

#ifndef NO_ACTION
	pid = fork();
	if (pid) {
		waitpid(pid, NULL, 0);
	}
	else if (pid == 0) {
		snprintf(tmpBuf, 100, "%s/%s", _CONFIG_SCRIPT_PATH, _FIREWALL_SCRIPT_PROG);
		execl( tmpBuf, _FIREWALL_SCRIPT_PROG, NULL);
		exit(1);
	}
#endif

	submitUrl = boaGetVar(wp, "submit-url", "");   // hidden page
	if (submitUrl[0])
		boaRedirect(wp, submitUrl);
	else
		boaDone(wp, 200);
	return;

setErr_ipip:
	ERR_MSG(tmpBuf);
}


int ipipList(int eid, request * wp, int argc, char **argv)
{
	MIB_IPIP_T Entry;
	unsigned int entryNum, i;
	char remote[20], local[20];
	int enable;
	int nBytesSent=0;
	char ifname[IFNAMSIZ];
	unsigned int ipipEnable;

	mib_get(MIB_IPIP_ENABLE, (void *)&ipipEnable);
	entryNum = mib_chain_total(MIB_IPIP_TBL);
	for (i=0; i<entryNum; i++)
	{
		if (!mib_chain_get(MIB_IPIP_TBL, i, (void *)&Entry))
		{
			boaError(wp, 400, "Get chain record error!\n");
			return -1;
		}

		snprintf(local, 20, "%s", inet_ntoa(*((struct in_addr *)&Entry.saddr)));
		snprintf(remote, 20, "%s", inet_ntoa(*((struct in_addr *)&Entry.daddr)));
		ifGetName(Entry.ifIndex, ifname, sizeof(ifname));   // Mason Yu. Add VPN ifIndex

		if (ipipEnable) {
			nBytesSent += boaWrite(wp, "<tr>"
#ifndef CONFIG_GENERAL_WEB
				"<td bgcolor=\"#C0C0C0\"><input type=\"checkbox\" name=\"s%d\" value=1></td>\n"
				"<td bgcolor=\"#C0C0C0\">%s</td>\n"
				"<td bgcolor=\"#C0C0C0\">%s</td>\n"
				"<td bgcolor=\"#C0C0C0\">%s</td>\n"
				"<td bgcolor=\"#C0C0C0\">%s</td>\n"
				//"<td align=center width=\"5%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s ")
				"<td bgcolor=\"#C0C0C0\"> "
				"<input type=\"submit\" id=\"%s\" value=\"%s\" name=\"submit%s\"></td>\n"
				"</tr>",
#else
				"<td><input type=\"checkbox\" name=\"s%d\" value=1></td>\n"
				"<td>%s</td>\n"
				"<td>%s</td>\n"
				"<td>%s</td>\n"
				"<td>%s</td>\n"
				//"<td align=center width=\"5%%\"><font size=\"2\">%s ")
				"<td> "
				"<input class=\"inner_btn\" type=\"submit\" id=\"%s\" value=\"%s\" name=\"submit%s\"></td>\n"
				"</tr>",
#endif
				Entry.idx, ifname, local, remote,
				multilang(Entry.dgw ? LANG_ON : LANG_OFF), ifname,
				//IPIP_STATUS[Entry.idx]?"ON":"OFF",
				multilang(IPIP_STATUS[Entry.idx] ? LANG_DISCONNECT : LANG_CONNECT),
				ifname);
		}
		else {
			nBytesSent += boaWrite(wp, "<tr>"
#ifndef CONFIG_GENERAL_WEB
				"<td bgcolor=\"#C0C0C0\"><input type=\"checkbox\" name=\"s%d\" value=1></td>\n"
				"<td bgcolor=\"#C0C0C0\">%s</td>\n"
				"<td bgcolor=\"#C0C0C0\">%s</td>\n"
				"<td bgcolor=\"#C0C0C0\">%s</td>\n"
				"<td bgcolor=\"#C0C0C0\">%s</td>\n"
				"<td bgcolor=\"#C0C0C0\">%s "
#else
				"<td><input type=\"checkbox\" name=\"s%d\" value=1></td>\n"
				"<td>%s</td>\n"
				"<td>%s</td>\n"
				"<td>%s</td>\n"
				"<td>%s</td>\n"
				"<td>%s "
#endif
				"</tr>",
				Entry.idx, ifname, local, remote,
				multilang(Entry.dgw ? LANG_ON : LANG_OFF), multilang(LANG_OFF));
		}

	}

	return nBytesSent;
}
#endif //end of CONFIG_NET_IPIP

#ifdef CONFIG_NET_IPGRE
int showGRETable(int eid, request * wp, int argc, char **argv)
{
	int nBytesSent=0;
	unsigned int entryNum, i;
	MIB_GRE_T Entry;
	unsigned long int d,g,m;
	struct in_addr dest;
	struct in_addr gw;
	struct in_addr mask;
	char sdest[16], sgw[16];
	int status;
	char *statusStr=NULL;
	char VidStr[8]="";
	char upRateStr[8]="";
	char downRateStr[8]="";
	char keyStr[16]="";
	char dscpStr[5]="";
	
	entryNum = mib_chain_total(MIB_GRE_TBL);

#ifndef CONFIG_GENERAL_WEB
	nBytesSent += boaWrite(wp, "<tr><font size=1>"
	"<td align=center width=\"5%%\" bgcolor=\"#808080\">%s</td>\n"
	"<td align=center width=\"5%%\" bgcolor=\"#808080\">%s</td>"
	"<td align=center width=\"10%%\" bgcolor=\"#808080\">%s</td>"
	"<td align=center width=\"20%%\" bgcolor=\"#808080\">%s</td>"
	"<td align=center width=\"20%%\" bgcolor=\"#808080\">%s</td>"
	"<td align=center width=\"5%%\" bgcolor=\"#808080\">%s</td>"
	"<td align=center width=\"5%%\" bgcolor=\"#808080\">%s</td>"
	"<td align=center width=\"5%%\" bgcolor=\"#808080\">%s</td>"
	"<td align=center width=\"5%%\" bgcolor=\"#808080\">%s</td>"
	"<td align=center width=\"5%%\" bgcolor=\"#808080\">%s</td>"
	"<td align=center width=\"5%%\" bgcolor=\"#808080\">%s</td>"
	"<td align=center width=\"5%%\" bgcolor=\"#808080\">%s</td>"
	"<td align=center width=\"5%%\" bgcolor=\"#808080\">%s</td>"
	"</font></tr>\n", multilang(LANG_SELECT), multilang(LANG_STATE), multilang(LANG_NAME), "EndPoint", "Back EndPoint",
	"Checksum", "Sequence", "DSCP", "Key", "Key value",
	"VLAN ID", "UP Rate", "Down Rate");
#else
	nBytesSent += boaWrite(wp, "<tr>"
	"<th align=center width=\"5%%\">%s</th>\n"
	"<th align=center width=\"5%%\">%s</th>"
	"<th align=center width=\"10%%\">%s</th>"
	"<th align=center width=\"20%%\">%s</th>"
	"<th align=center width=\"20%%\">%s</th>"
	"<th align=center width=\"5%%\">%s</th>"
	"<th align=center width=\"5%%\">%s</th>"
	"<th align=center width=\"5%%\">%s</th>"
	"<th align=center width=\"5%%\">%s</th>"
	"<th align=center width=\"5%%\">%s</th>"
	"<th align=center width=\"5%%\">%s</th>"
	"<th align=center width=\"5%%\">%s</th>"
	"<th align=center width=\"5%%\">%s</th>"
	"</tr>\n", multilang(LANG_SELECT), multilang(LANG_STATE), multilang(LANG_NAME), "EndPoint", "Back EndPoint",
	"Checksum", "Sequence", "DSCP", "Key", "Key value",
	"VLAN ID", "UP Rate", "Down Rate");
#endif

	for (i=0; i<entryNum; i++) {

		if (!mib_chain_get(MIB_GRE_TBL, i, (void *)&Entry))
		{
  			boaError(wp, 400, "Get chain record error!\n");
			return -1;
		}
		strncpy(VidStr, "", sizeof(VidStr));
		strncpy(upRateStr, "", sizeof(upRateStr));
		strncpy(downRateStr, "", sizeof(downRateStr));
		
		nBytesSent += boaWrite(wp, "<tr>"
#ifndef CONFIG_GENERAL_WEB
		"<td align=center width=\"5%%\" bgcolor=\"#C0C0C0\"><input type=\"radio\" name=\"select\""
		" value=\"s%d\" onClick=postEntry(%d,'%s','%s','%s',%d,%d,%d,%d,%d,%d,%d,%d)></td>\n",
#else
		
		"<td align=center width=\"5%%\"><input type=\"radio\" name=\"select\""
		" value=\"s%d\" onClick=postEntry(%d,'%s','%s','%s',%d,%d,%d,%d,%d,%d,%d,%d)></td>\n",
#endif
		i, Entry.enable, Entry.name, Entry.greIpAddr1, Entry.greIpAddr2,
		Entry.csum_enable, Entry.seq_enable, Entry.key_enable, Entry.key_value, Entry.m_dscp,
		Entry.vlanid, Entry.upBandWidth, Entry.downBandWidth );
		
		if (Entry.vlanid)
			snprintf(VidStr, sizeof(VidStr), "%u", Entry.vlanid);
		
		if (Entry.upBandWidth)
			snprintf(upRateStr, sizeof(upRateStr), "%u", Entry.upBandWidth);
		
		if (Entry.downBandWidth)
			snprintf(downRateStr, sizeof(downRateStr), "%u", Entry.downBandWidth);
		
		if (Entry.key_value)
			snprintf(keyStr, sizeof(keyStr), "%u", Entry.key_value);
		
		if (Entry.m_dscp)
			snprintf(dscpStr, sizeof(dscpStr), "0x%x", Entry.m_dscp-1);
		
		nBytesSent += boaWrite(wp,
#ifndef CONFIG_GENERAL_WEB
		"<td align=center width=\"5%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"><b>%s</b></font></td>"
		"<td align=center width=\"10%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"><b>%s</b></font></td>"
		"<td align=center width=\"20%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"><b>%s</b></font></td>"
		"<td align=center width=\"20%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"><b>%s</b></font></td>"
		"<td align=center width=\"5%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"><b>%s</b></font></td>"
		"<td align=center width=\"5%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"><b>%s</b></font></td>"
		"<td align=center width=\"5%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"><b>%s</b></font></td>"
		"<td align=center width=\"5%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"><b>%s</b></font></td>"
		"<td align=center width=\"5%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"><b>%s</b></font></td>"
		"<td align=center width=\"5%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"><b>%s</b></font></td>"
		"<td align=center width=\"5%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"><b>%s</b></font></td>"
		"<td align=center width=\"5%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"><b>%s</b></font></td>"
#else	
		"<td align=center width=\"5%%\">%s</td>"
		"<td align=center width=\"10%%\">%s</td>"
		"<td align=center width=\"20%%\">%s</td>"
		"<td align=center width=\"20%%\">%s</td>"
		"<td align=center width=\"5%%\">%s</td>"
		"<td align=center width=\"5%%\">%s</td>"
		"<td align=center width=\"5%%\">%s</td>"
		"<td align=center width=\"5%%\">%s</td>"
		"<td align=center width=\"5%%\">%s</td>"
		"<td align=center width=\"5%%\">%s</td>"
		"<td align=center width=\"5%%\">%s</td>"
		"<td align=center width=\"5%%\">%s</td>"
#endif
		"</tr>\n",		
		multilang(Entry.enable ? LANG_ENABLE : LANG_DISABLE), Entry.name, Entry.greIpAddr1, Entry.greIpAddr2, 
		multilang(Entry.csum_enable ? LANG_ENABLE : LANG_DISABLE), multilang(Entry.seq_enable ? LANG_ENABLE : LANG_DISABLE),
		dscpStr, multilang(Entry.key_enable ? LANG_ENABLE : LANG_DISABLE), keyStr,
		VidStr, upRateStr, downRateStr );		
	}
	
	return 0;
}

static void getGreEntry(request * wp, MIB_GRE_Tp pEntry)
{
	char *strVal, *saveConf, *tmp=NULL;	
	
	memset(pEntry, 0, sizeof(MIB_GRE_T));

	strVal = boaGetVar(wp, "grename", "");
	strncpy(pEntry->name, strVal, IFNAMSIZ);
	
	strVal = boaGetVar(wp, "tunnelEn", "");
	pEntry->enable = strVal[0] - '0';		
	
	strVal = boaGetVar(wp, "csumEn", "");
	pEntry->csum_enable = strVal[0] - '0';	
	
	strVal = boaGetVar(wp, "seqEn", "");
	pEntry->seq_enable = strVal[0] - '0';		
	
	strVal = boaGetVar(wp, "keyEn", "");
	pEntry->key_enable = strVal[0] - '0';	
	
	strVal = boaGetVar(wp, "keyValue", "");
	if (strVal[0]) {		
		sscanf(strVal, "%d", &pEntry->key_value);
	}
	
	strVal = boaGetVar(wp, "mdscp", "");
	if(strVal[0]) 
		pEntry->m_dscp = strtol(strVal, &tmp, 0);
	else
		pEntry->m_dscp = 0;
		
	strVal = boaGetVar(wp, "greIP1", "");
	if(strVal[0])
		strcpy(pEntry->greIpAddr1, strVal);

	strVal = boaGetVar(wp, "greIP2", "");
	if (strVal[0])
		strcpy(pEntry->greIpAddr2, strVal);
	
	strVal = boaGetVar(wp, "grevid", "");
	if (strVal[0]) {		
		sscanf(strVal, "%d", &pEntry->vlanid);
		pEntry->itfGroup = IFGROUP_NUM;		// If this is a VLAN GRE, not use untag_gre interface on br.
	}
	
	strVal = boaGetVar(wp, "uprate", "");
	if (strVal[0]) {		
		sscanf(strVal, "%d", &pEntry->upBandWidth);
	}
	
	strVal = boaGetVar(wp, "downrate", "");
	if (strVal[0]) {		
		sscanf(strVal, "%d", &pEntry->downBandWidth);
	}

}

void formGRE(request * wp, char *path, char *query)
{
	char *str, *submitUrl;
	char tmpBuf[100];		
	MIB_GRE_T Entry, orgEntry;	
	int intVal;	
	unsigned int totalEntry, i, idx;
	int selected=0;
	unsigned char totalbandwidthEn=0;	
	
	stopGreQoS();
	
	//totalbandwidthEn = 1;
	//if (!mib_set(MIB_TOTAL_BANDWIDTH_LIMIT_EN, (void *)&totalbandwidthEn))
	//	goto setErr_gre;	
				
	totalEntry = mib_chain_total(MIB_GRE_TBL); /* get chain record size */
	// Remove
	str = boaGetVar(wp, "delgre", "");
	if (str[0]) {
		str = boaGetVar(wp, "select", "");
		if (str[0]) {
			for (i=0; i<totalEntry; i++) {
				idx = totalEntry-i-1;
				snprintf(tmpBuf, 4, "s%d", idx);
				//printf("tmpBuf(select) = %s idx=%d\n", tmpBuf, idx);

				if ( !gstrcmp(str, tmpBuf) ) {
					// delete old GRE Tunnel
					if (!mib_chain_get(MIB_GRE_TBL, idx, (void *)&orgEntry)) {
						strcpy(tmpBuf, "Get GRE TBL error(Remove)");
						goto setErr_gre;
					}			
					applyGRE(0, idx, 0);
					
					// delete from chain record
					if(mib_chain_delete(MIB_GRE_TBL, idx) != 1) {
						strcpy(tmpBuf, Tdelete_chain_error);
						goto setErr_gre;
					}
				}
			} // end of for
		}		
		goto setOK_gre;
	}
	
	// Add
	str = boaGetVar(wp, "add", "");
	if (str[0]) {
		
		getGreEntry(wp, &Entry);		
		
		intVal = mib_chain_add(MIB_GRE_TBL, (unsigned char*)&Entry);
		if (intVal == 0) {			
			sprintf(tmpBuf, "%s (MIB_GRE_TBL)",Tadd_chain_error);
			goto setErr_gre;
		}
		else if (intVal == -1) {
			strcpy(tmpBuf, strTableFull);
			goto setErr_gre;
		}
		applyGRE(1, totalEntry, 0);		
	}
	
	// Modify
	str = boaGetVar(wp, "modify", "");
	if (str[0]) {
		selected = -1;
		str = boaGetVar(wp, "select", "");
		if (str[0]) {
			for (i=0; i<totalEntry; i++) {
				idx = totalEntry-i-1;
				snprintf(tmpBuf, 4, "s%d", idx);

				if ( !gstrcmp(str, tmpBuf) ) {
					selected = idx;
					break;
				}
			}
			// delete old GRE Tunnel
			if (!mib_chain_get(MIB_GRE_TBL, selected, (void *)&orgEntry)) {
				strcpy(tmpBuf, "Get GRE TBL error");
				goto setErr_gre;
			}
			
			applyGRE(0, selected, 0);
			
			if (selected >= 0) {
				getGreEntry(wp, &Entry);
				if (Entry.vlanid != 0)
					Entry.itfGroup = IFGROUP_NUM;		// If this is a VLAN GRE, not use untag_gre interface on br.
				else if (Entry.vlanid == 0 && orgEntry.vlanid == 0)
					Entry.itfGroup = orgEntry.itfGroup;
				else if (Entry.vlanid == 0 && orgEntry.vlanid != 0)
					Entry.itfGroup = orgEntry.itfGroupVlan;
				
				Entry.itfGroupVlan = orgEntry.itfGroupVlan;
				strncpy(Entry.ssid, orgEntry.ssid, strlen(orgEntry.ssid));
				mib_chain_update(MIB_GRE_TBL, (void *)&Entry, selected);
				// Create modofied GRE Tunnel
				applyGRE(1, selected, 0);
			}
		}
	}
	
	// GRE setting
	str = boaGetVar(wp, "greSet", "");
	if (str[0]) {
		unsigned char greVal;

		str = boaGetVar(wp, "greEn", "");
		if (str[0] == '1')
			greVal = 1;
		else
			greVal = 0;	// default "off"
		if (!mib_set(MIB_GRE_ENABLE, (void *)&greVal)) {
			strcpy(tmpBuf, "SET_RIP_ERROR");
			goto setErr_gre;
		}
		gre_take_effect(0);
	}

setOK_gre:	
	
// Magician: Commit immediately
#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif

#ifndef NO_ACTION
	pid = fork();
	if (pid) {
		waitpid(pid, NULL, 0);
	}
	else if (pid == 0) {
		snprintf(tmpBuf, 100, "%s/%s", _CONFIG_SCRIPT_PATH, _FIREWALL_SCRIPT_PROG);
		execl( tmpBuf, _FIREWALL_SCRIPT_PROG, NULL);
		exit(1);
	}
#endif

	submitUrl = boaGetVar(wp, "submit-url", "");   // hidden page
	if (submitUrl[0])
		boaRedirect(wp, submitUrl);
	else
		boaDone(wp, 200);
	return;

setErr_gre:
	ERR_MSG(tmpBuf);

}

#endif


