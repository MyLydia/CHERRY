/*
 *      Web server handler routines for URL stuffs
 */
#include "options.h"
#ifdef URL_BLOCKING_SUPPORT

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

void formURL(request * wp, char *path, char *query)
{
#ifndef SUPPORT_URL_FILTER
	unsigned char urlfilterEnble = 0;	// 0-off, 1-on
	unsigned char urlFilterMode = 0;	// 0-black list, 1-white list
#endif	
	unsigned char urlcap; // 0-off, 1-black list, 2-white list
#ifdef SUPPORT_URL_FILTER
	MIB_CE_URL_FILTER_T entry;
	int act_idx = -1;
#else
	MIB_CE_URL_FQDN_T entry;
#endif
	char*			stemp = "";
	int				lineno = __LINE__;
	_BC_USE;
	int idx;
	int total;
	int ret;

	_TRACE_CALL;

	FETCH_INVALID_OPT(stemp, "action", _NEED);

#ifndef SUPPORT_URL_FILTER
	if(strcmp(stemp, "sw") == 0)	// switch
	{
		_GET_BOOL(urlfilterEnble, _NEED);
		_GET_BOOL(urlFilterMode, _NEED);

		if(urlfilterEnble)
			urlfilterEnble += urlFilterMode;

		if(!mib_set(MIB_URL_CAPABILITY, (void *)&urlfilterEnble))
		{
			printf("Set URL Enable error!");
			goto check_err;
		}
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		syslog(LOG_CRIT, "URL Filter, %s url filter.", urlfilterEnble? "open": "close");
		if(urlfilterEnble)
			syslog(LOG_CRIT, "URL Filter, mode (%s)", urlfilterEnble==2? "whitelist":"blacklist");
#endif
	}
	else if(strcmp(stemp, "md") == 0)	//mode
	{
		_GET_BOOL(urlfilterEnble, _NEED);
		_GET_BOOL(urlFilterMode, _NEED);

		if(urlfilterEnble)
			urlFilterMode += urlfilterEnble;

		if(urlfilterEnble && !mib_set(MIB_URL_CAPABILITY, (void *)&urlFilterMode))
		{
			printf("Set URL Mode error!");
			goto check_err;
		}
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		syslog(LOG_CRIT, "URL Filter, mode (%s)", urlFilterMode==2? "whitelist":"blacklist");
#endif
	}
#endif	
#ifdef SUPPORT_URL_FILTER
	if(strcmp(stemp, "rm") == 0)	//remove
	{
		MIB_CE_URL_FILTER_T rm_entry;
		FETCH_INVALID_OPT(stemp, "idx", _NEED);
		act_idx = atoi(stemp);

		total = mib_chain_total(MIB_URL_FILTER_TBL);
		if(total > act_idx)
			mib_chain_delete(MIB_URL_FILTER_TBL, act_idx);
	}
	else if(strcmp(stemp, "ad") == 0)	//add
	{
		MIB_CE_URL_FILTER_T	add_entry;
		/*ql:20080715 START: if url start with http, try to search key after www.*/
		char *pTmp;//point to the string after "http://"
		char urlTmp[MAX_URL_LENGTH];
		/*ql:20080715 END*/

		memset(&entry, 0, sizeof(MIB_CE_URL_FILTER_T));

		_ENTRY_STR(name, _NEED);

		printf("<%s, %d, name=%s>\n", __FUNCTION__, __LINE__, entry.name);
		
		_ENTRY_STR(url, _NEED);
		if (!strncmp(entry.url, "http://", 7))
			strcpy(urlTmp, entry.url+7);
		else
			strcpy(urlTmp, entry.url);

		pTmp = strtok(urlTmp, ":");

		if (!strncmp(pTmp, "www.", 4)) {
			if (!pTmp[4]) {
				ERR_MSG("请输入正确的URL!");
				goto check_err;
			}
		} else {
			if (!pTmp[0]) {
				ERR_MSG("请输入正确的URL!");
				goto check_err;
			}
		}
		/*ql:20080715 END*/

		_ENTRY_STR(mac, _OPT);
		changeMacFormat(entry.mac,'-',':');

		FETCH_INVALID_OPT(stemp, "Enable", _NEED);
		entry.Enable = atoi(stemp);
		
		printf("%s %d entry.Enable=%d\n", __FUNCTION__, __LINE__, entry.Enable);

		total = mib_chain_total(MIB_URL_FILTER_TBL);
		for (idx=0; idx<total; idx++)
		{
			if (!mib_chain_get(MIB_URL_FILTER_TBL, idx, (void *)&add_entry)) {
				printf("get URL chain error!\n");
				goto check_err;
			}
			if (!gstrcmp(add_entry.url, entry.url))
			{
				ERR_MSG("规则已存在!");
				goto check_ok;
			}
		}
		
		ret = mib_chain_add(MIB_URL_FILTER_TBL, (void *)&entry);
		
		if( ret == -1 ){
			printf("Max number of rules reached!");
			goto Max_Size_Reached;
		}
		else if( ret == 0 ){
			printf("add URL chain error!\n");
			goto check_err;
		}
	}
	else if(strcmp(stemp, "modify") == 0)	//modify
	{
		/*ql:20080715 START: if url start with http, try to search key after www.*/
		char *pTmp;//point to the string after "http://"
		char urlTmp[MAX_URL_LENGTH];
		/*ql:20080715 END*/

		FETCH_INVALID_OPT(stemp, "idx", _NEED);
		act_idx = atoi(stemp);
		
		memset(&entry, 0, sizeof(MIB_CE_URL_FILTER_T));

		_ENTRY_STR(name, _NEED);

		printf("<%s, %d, name=%s>\n", __FUNCTION__, __LINE__, entry.name);
		_ENTRY_STR(url, _NEED);
		if (!strncmp(entry.url, "http://", 7))
			strcpy(urlTmp, entry.url+7);
		else
			strcpy(urlTmp, entry.url);

		pTmp = strtok(urlTmp, ":");

		if (!strncmp(pTmp, "www.", 4)) {
			if (!pTmp[4]) {
				ERR_MSG("请输入正确的URL!");
				goto check_err;
			}
		} else {
			if (!pTmp[0]) {
				ERR_MSG("请输入正确的URL!");
				goto check_err;
			}
		}
		/*ql:20080715 END*/

		_ENTRY_STR(mac, _OPT);
		changeMacFormat(entry.mac,'-',':');

		FETCH_INVALID_OPT(stemp, "Enable", _NEED);
		entry.Enable = atoi(stemp);

		total = mib_chain_total(MIB_URL_FILTER_TBL);
		if(total > act_idx)
			mib_chain_update(MIB_URL_FILTER_TBL, (void*)&entry, act_idx);

	}
#else
	else if(strcmp(stemp, "rm") == 0)	//remove
	{
		MIB_CE_URL_FQDN_T	rm_entry;
		int del_rule_num = 0;

		_BC_INIT("bcdata");
		while(_BC_NEXT())
		{
			//_BC_ENTRY_STR(url, _NEED);
			//_BC_ENTRY_INT(port, _OPT);
			_BC_ENTRY_INTX(idx, _NEED);
			/************Place your code here, do what you want to do! ************/
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
			if(mib_chain_get(MIB_URL_FQDN_TBL, idx - del_rule_num, (void *)&rm_entry)==1)
				syslog(LOG_CRIT, "URL Filter, delete url %s", rm_entry.url);		
#endif
			//delete from chain record
			if (mib_chain_delete(MIB_URL_FQDN_TBL, idx - del_rule_num) != 1)
			{
				printf("Delete URL chain record error!");
				goto check_err;
			}
			del_rule_num++;
			/*
			total = mib_chain_total(MIB_URL_FQDN_TBL);
			for(idx = 0; idx < total; idx++)
			{
				if (!mib_chain_get(MIB_URL_FQDN_TBL, idx, (void *)&rm_entry)) {
					printf("get URL chain error!\n");
					goto check_err;
				}

				if (!gstrcmp(entry.url, rm_entry.url))
				{
					//delete from chain record
					if (mib_chain_delete(MIB_URL_FQDN_TBL, idx) != 1)
					{
						printf("Delete URL chain record error!");
						goto check_err;
					}
					printf("delete %s\n", entry.url);
					break;
				}
			}
			*/
		}
	}
	else if(strcmp(stemp, "ad") == 0)	//add
	{
		MIB_CE_URL_FQDN_T	add_entry;
		/*ql:20080715 START: if url start with http, try to search key after www.*/
		char *pTmp;//point to the string after "http://"
		char urlTmp[MAX_URL_LENGTH];
		/*ql:20080715 END*/

		memset(&entry, 0, sizeof(MIB_CE_URL_FQDN_T));

		_ENTRY_STR(url, _NEED);
		//_ENTRY_INT(port, _NEED);
		//if(entry.port == 0){lineno = __LINE__; goto check_err;}

		/*ql:20080715 START: if url start with http, try to search key after www.*/
		/*below is original code*/
		//ql_xu: get keyword from url
		/*if (!strncmp(entry.url, "www.", 4)) {
			if (!entry.url[4])
				goto check_err;

			strcpy(entry.key, entry.url + 3);
		} else
			strcpy(entry.key, entry.url);*/
		/*new code*/
		if (!strncmp(entry.url, "http://", 7))
			strcpy(urlTmp, entry.url+7);
		else
			strcpy(urlTmp, entry.url);

		pTmp = strtok(urlTmp, ":");

		if (!strncmp(pTmp, "www.", 4)) {
			if (!pTmp[4]) {
				ERR_MSG("请输入正确的URL!");
				goto check_err;
			}

			strcpy(entry.key, pTmp + 3);
		} else {
			if (!pTmp[0]) {
				ERR_MSG("请输入正确的URL!");
				goto check_err;
			}
			strcpy(entry.key, pTmp);
		}

		/*ql:20080715 END*/

		printf("url key:%s\n", entry.key);

		pTmp = strtok(NULL, ":");
		if(pTmp == NULL)
			entry.port = 80;
		else
			entry.port = atoi(pTmp);

		printf("url port:%d\n", entry.port);

		total = mib_chain_total(MIB_URL_FQDN_TBL);
		for (idx=0; idx<total; idx++)
		{
			if (!mib_chain_get(MIB_URL_FQDN_TBL, idx, (void *)&add_entry)) {
				printf("get URL chain error!\n");
				goto check_err;
			}
			if (!gstrcmp(add_entry.url, entry.url) && add_entry.port==entry.port)
			{
				ERR_MSG("规则已存在!");
				goto check_ok;
			}
		}
		
		ret = mib_chain_add(MIB_URL_FQDN_TBL, (void *)&entry);
		
		if( ret == -1 ){
			printf("Max number of rules reached!");
			goto Max_Size_Reached;
		}
		else if( ret == 0 ){
			printf("add URL chain error!\n");
			goto check_err;
		}
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		syslog(LOG_CRIT, "URL Filter, add url %s", entry.url);
#endif
	}
#endif
	else {lineno = __LINE__; goto check_err;}

	//write to flash
	mib_update(CURRENT_SETTING, CONFIG_MIB_ALL);

	//take effect
	if(!mib_get(MIB_URL_CAPABILITY, (void *)&urlcap))
		goto check_err;

#ifdef SUPPORT_URL_FILTER
	set_url_filter();
#else	
	filter_set_url(urlcap);
#endif

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

int initPageURL(int eid, request * wp, int argc, char ** argv)
{
	unsigned char urlcap; 	//0-disable, 1-black list, 2-white list
#ifndef SUPPORT_URL_FILTER	
	unsigned char urlfilterEnble = 0, urlFilterMode = 0; // urlFilterMode = 0 for black list, urlFilterMode = 1 for white list.
#endif	
#ifdef SUPPORT_URL_FILTER
	MIB_CE_URL_FILTER_T entry;
#else
	MIB_CE_URL_FQDN_T entry;
#endif
	char fixurl[100*2]={0};
	int total = 0;
	int idx = 0;
	int lineno = __LINE__;

	_TRACE_CALL;

	if (!mib_get(MIB_URL_CAPABILITY, (void *)&urlcap))
		return -1;

#ifndef SUPPORT_URL_FILTER
	switch(urlcap)
	{
		case 2:
			urlFilterMode = 1;
		case 1:
			urlfilterEnble = 1;
			break;
	}

	_PUT_BOOL(urlfilterEnble);
	_PUT_BOOL(urlFilterMode);
#endif

#ifdef SUPPORT_URL_FILTER
	unsigned char macString[32]={0};
	total = mib_chain_total(MIB_URL_FILTER_TBL);
	for(idx = 0; idx < total; idx++)
	{
		if (!mib_chain_get(MIB_URL_FILTER_TBL, idx, (void *)&entry)) {
			printf("get URL chain error!\n");
			goto check_err;
		}

		memset(macString, 0, 32);
		changeMacToString(entry.mac, macString);
		
		boaWrite (wp, "push(new it_nr(\"%d\""_PTS _PTS _PTS _PTI"));\n", idx, "name", entry.name,
			"url", fixSpecialChar(fixurl, entry.url,sizeof(fixurl)),
			 _PME(mac),
			"Enable", entry.Enable);
	}
#else
	total = mib_chain_total(MIB_URL_FQDN_TBL);
	for(idx = 0; idx < total; idx++)
	{
		if (!mib_chain_get(MIB_URL_FQDN_TBL, idx, (void *)&entry)) {
			printf("get URL chain error!\n");
			goto check_err;
		}

		//boaWrite (wp, "push(new it_nr(\"%d\""_PTS _PTI "));\n", index,  _PME(url), _PME(port));
		//boaWrite (wp, "push(new it_nr(\"%d\""_PTS _PTI "));\n", idx, "url", fixSpecialChar(fixurl, entry.url,sizeof(fixurl)), _PME(port));		
		boaWrite (wp, "push(new it_nr(\"%d\""_PTS "));\n", idx, "url", fixSpecialChar(fixurl, entry.url,sizeof(fixurl)));
	}
#endif	

check_err:
	_TRACE_LEAVEL;
	return 0;
}
#endif

