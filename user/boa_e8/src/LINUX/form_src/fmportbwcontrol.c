/*
 *      Web server handler routines for URL stuffs
 */
#include "options.h"

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

void formPortBandWidth(request * wp, char *path, char *query)
{
	char *submitUrl;
	char *stemp = "";
	unsigned char bandcontrolEnable;
	unsigned int act_idx;
	unsigned int us_band;
	unsigned int ds_band;
	int	lineno = __LINE__;
	int chainNum=-1;
	MIB_CE_PORT_BANDWIDTH_ENTRY_T entry;

	FETCH_INVALID_OPT(stemp, "action", _NEED);
	if(strcmp(stemp, "sw") == 0)	// switch
	{
		_GET_BOOL(bandcontrolEnable, _NEED);
			
		if(!mib_set(MIB_PORT_BANDWIDTH_CONTROL_ENABLE, (void *)&bandcontrolEnable))
		{
			printf("Set Bandwidth Control Enable error!");
			goto check_err;
		}
	}
	else if(strcmp(stemp, "modify") == 0)//modify
	{
		FETCH_INVALID_OPT(stemp, "idx", _NEED);
		act_idx = atoi(stemp);
			
		FETCH_INVALID_OPT(stemp, "usBandwidth", _NEED);
		us_band = atoi(stemp);
		FETCH_INVALID_OPT(stemp, "dsBandwidth", _NEED);
		ds_band = atoi(stemp);

		chainNum = mib_chain_total(MIB_PORT_BANDWIDTH_TBL);
		if(act_idx<chainNum)
		{
			if (!mib_chain_get(MIB_PORT_BANDWIDTH_TBL, act_idx, (void *)&entry)) {
				printf("get bandwidth control chain error!\n");
				goto check_err;
			}
		
			entry.upRate = us_band;
			entry.downRate = ds_band;
			mib_chain_update(MIB_PORT_BANDWIDTH_TBL, (void*)&entry, act_idx);
		}
	}
	else if(strcmp(stemp, "rm") == 0)
	{
		FETCH_INVALID_OPT(stemp, "idx", _NEED);
		act_idx = atoi(stemp);

		chainNum = mib_chain_total(MIB_PORT_BANDWIDTH_TBL);
		if(act_idx<chainNum)
		{
			mib_chain_delete(MIB_PORT_BANDWIDTH_TBL, act_idx);
		}
	}
	else if(strcmp(stemp, "add") == 0)//add
	{
		FETCH_INVALID_OPT(stemp, "port", _NEED);
		entry.port= atoi(stemp);

		FETCH_INVALID_OPT(stemp, "us_cfg", _NEED);
		entry.upRate = atoi(stemp);

		FETCH_INVALID_OPT(stemp, "ds_cfg", _NEED);
		entry.downRate = atoi(stemp);

		mib_chain_add(MIB_PORT_BANDWIDTH_TBL, &entry);
	}else
	{
		printf("[%s %d]action [%s] is not supported.\n", __func__, __LINE__, stemp);
		goto check_err;
	}
	
#ifdef COMMIT_IMMEDIATELY
		Commit();
#endif

	applyPortBandWidthControl();
check_err:
	submitUrl = boaGetVar(wp, "submit-url", "");   // hidden page
	if (submitUrl[0])
		boaRedirect(wp, submitUrl);
	else
		boaDone(wp, 200);
	return;
}

int bandwidthSelect(int eid, request * wp, int argc, char ** argv)
{
	int idx = 0;

	for (idx=PMAP_ETH0_SW0; idx<SW_LAN_PORT_NUM;idx++)
	{
		boaWrite(wp, "<option value=\"%d\">¶Ë¿Ú_%d</option>", idx, idx);
	}

	return 0;
}

int initPagePortBWControl(int eid, request * wp, int argc, char ** argv)
{
	unsigned char bandcontrolEnable;
	MIB_CE_PORT_BANDWIDTH_ENTRY_T entry;
	
	int total = 0;
	int idx = 0;

	_TRACE_CALL;

	if (!mib_get(MIB_PORT_BANDWIDTH_CONTROL_ENABLE, (void *)&bandcontrolEnable))
		return -1;

	_PUT_BOOL(bandcontrolEnable);

	if(bandcontrolEnable)
	{
		total = mib_chain_total(MIB_PORT_BANDWIDTH_TBL);
		for(idx = 0; idx < total; idx++)
		{
			if(idx<SW_LAN_PORT_NUM)
			{
				if (!mib_chain_get(MIB_PORT_BANDWIDTH_TBL, idx, (void *)&entry)) 
				{
					printf("get ACCESS RIGHT chain error!\n");
					goto check_err;
				}
				boaWrite (wp, "push(new it_nr(\"%d\""_PTI _PTI _PTI"));\n", idx, "port", entry.port, "usBandwidth", entry.upRate, "dsBandwidth", entry.downRate);
			}
		}
	}

check_err:
	_TRACE_LEAVEL;
	return 0;
}