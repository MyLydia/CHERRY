/*
 *      Web server handler routines for URL stuffs
 */
#include "options.h"
#ifdef SUPPORT_DNS_FILTER

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
#include "fmdefs.h"

#define  URL_MAX_ENTRY  500
#define  KEY_MAX_ENTRY  500

void formDNSFilter(request * wp, char *path, char *query)
{
	MIB_CE_DNS_FILTER_T entry, tmp_entry;
	int act_idx = -1;
	char*			stemp = "";
	int				lineno = __LINE__;
	_BC_USE;
	int idx;
	int total;
	int ret = 0;

	_TRACE_CALL;

	FETCH_INVALID_OPT(stemp, "action", _NEED);

	if(strcmp(stemp, "rm") == 0)	//remove
	{
		FETCH_INVALID_OPT(stemp, "idx", _NEED);
		act_idx = atoi(stemp);

		total = mib_chain_total(MIB_DNS_FILTER_TBL);
		if(total > act_idx)
			ret = mib_chain_delete(MIB_DNS_FILTER_TBL, act_idx);
	}
	else if(strcmp(stemp, "ad") == 0)	//add
	{
		memset(&entry, 0, sizeof(MIB_CE_DNS_FILTER_T));

		_ENTRY_STR(name, _NEED);
		
		_ENTRY_STR(hostname, _NEED);
		printf("hostname is %s\n", entry.hostname);
		
		_ENTRY_STR(mac, _OPT);
		changeMacFormat(entry.mac,'-',':');

		FETCH_INVALID_OPT(stemp, "Enable", _NEED);
		entry.Enable = atoi(stemp);

		printf("%s %d entry.Enable=%d\n", __FUNCTION__, __LINE__, entry.Enable);

		FETCH_INVALID_OPT(stemp, "dnsaction", _NEED);
		entry.action = atoi(stemp);		

		total = mib_chain_total(MIB_DNS_FILTER_TBL);
		for (idx=0; idx<total; idx++)
		{
			if (!mib_chain_get(MIB_DNS_FILTER_TBL, idx, (void *)&tmp_entry)) {
				printf("get DNS chain error!\n");
				goto check_err;
			}
			if (!gstrcmp(tmp_entry.hostname, entry.hostname) && !gstrcmp(tmp_entry.name, entry.name))
			{
				ERR_MSG("规则已存在!");
				goto check_ok;
			}
		}
		
		ret = mib_chain_add(MIB_DNS_FILTER_TBL, (void *)&entry);
		
		if( ret == -1 ){
			printf("Max number of rules reached!");
			goto Max_Size_Reached;
		}
		else if( ret == 0 ){
			printf("add DNS chain error!\n");
			goto check_err;
		}
	}
	else if(strcmp(stemp, "modify") == 0)	//modify
	{
		/*ql:20080715 START: if url start with http, try to search key after www.*/
		char *pTmp;//point to the string after "http://"
		char urlTmp[MAX_URL_LENGTH];
		int blockTimes = 0;
		/*ql:20080715 END*/

		FETCH_INVALID_OPT(stemp, "idx", _NEED);
		act_idx = atoi(stemp);
		
		if(mib_chain_get(MIB_DNS_FILTER_TBL, act_idx, (void*)&entry) != 1)
		{
			printf("modify DNS chain error!\n");
			goto check_err;
		}
		
		if(entry.Enable) blockTimes = getDNSFilterBlockedTimes(entry.name, entry.hostname);

		FETCH_INVALID_OPT(stemp, "Enable", _NEED);
		entry.Enable = atoi(stemp);
		
		_ENTRY_STR(name, _NEED);
		
		_ENTRY_STR(hostname, _NEED);
		printf("hostname is %s\n", entry.hostname);
		
		_ENTRY_STR(mac, _OPT);
		changeMacFormat(entry.mac,'-',':');

		FETCH_INVALID_OPT(stemp, "dnsaction", _NEED);
		if(atoi(stemp) != entry.action && entry.Enable)
		{
			blockTimes = 0;
		}
		entry.action = atoi(stemp);
		
		total = mib_chain_total(MIB_DNS_FILTER_TBL);
		for (idx=0; idx<total; idx++)
		{
			if(idx == act_idx) continue; 
			if (!mib_chain_get(MIB_DNS_FILTER_TBL, idx, (void *)&tmp_entry)) {
				printf("get DNS chain error!\n");
				goto check_err;
			}
			if (!gstrcmp(tmp_entry.hostname, entry.hostname) && !gstrcmp(tmp_entry.name, entry.name))
			{
				ERR_MSG("规则已存在!");
				goto check_ok;
			}
		}
		
		if(entry.Enable) UpdateDNSFilterBlocktime(entry.name, entry.hostname, blockTimes);

		total = mib_chain_total(MIB_DNS_FILTER_TBL);
		if(total > act_idx)
			ret = mib_chain_update(MIB_DNS_FILTER_TBL, (void*)&entry, act_idx);

	}
	else {lineno = __LINE__; goto check_err;}
	
	if(ret >= 1) reloadDnsRelay();

	//write to flash
	mib_update(CURRENT_SETTING, CONFIG_MIB_ALL);

check_ok:
	_COND_REDIRECT;
	_BC_FREE();
	return;

Max_Size_Reached:
	_BC_FREE();
	_TRACE_LEAVEL;
	ERR_MSG("已达最大规则数上限!"); //Max number of rules reached!
	return;

check_err:
	_BC_FREE();
	_TRACE_LEAVEL;
	return;
}

int initPageDNS(int eid, request * wp, int argc, char ** argv)
{
	unsigned char dnscap; 	//0-disable, 1-black list, 2-white list
	MIB_CE_DNS_FILTER_T entry;
	char fixhost[100*2]={0};
	int total = 0;
	int idx = 0;
	int lineno = __LINE__;

	_TRACE_CALL;
	
	unsigned char macString[32]={0};
	total = mib_chain_total(MIB_DNS_FILTER_TBL);
	for(idx = 0; idx < total; idx++)
	{
		if (!mib_chain_get(MIB_DNS_FILTER_TBL, idx, (void *)&entry)) {
			printf("get URL chain error!\n");
			goto check_err;
		}

		memset(macString, 0, 32);
		changeMacToString(entry.mac, macString);
		
		boaWrite (wp, "push(new it_nr(\"%d\""_PTS _PTS _PTS _PTI _PTI"));\n", idx, "name", entry.name,
			"hostname", entry.hostname,
			 _PME(mac),
			"Enable", entry.Enable,
			"dnsaction", entry.action);
	}

check_err:
	_TRACE_LEAVEL;
	return 0;
}
#endif

