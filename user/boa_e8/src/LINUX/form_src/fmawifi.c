#include <config/autoconf.h>
#include "../webs.h"
#include "fmdefs.h"
#include "mib.h"
#include "utility.h"
#include "fmdefs.h"
#ifdef CONFIG_RTK_L34_ENABLE
#include "../rtusr_rg_api.h"
#endif

#ifdef CONFIG_CT_AWIFI_JITUAN_FEATURE
void formAwifiStation(request * wp,char * path,char * query)
{
	//char tmpBuf[100];
	int ret=1;
	if (ret == 0){
		boaHeader(wp);
		boaWrite(wp, "<head><title>中国电信</title><META http-equiv=content-type content=\'text/html; charset=gbk\'>\n" \
					"<style>font-size: 12pt; color: red; text-align:left; font-weight:bold;</style></head>\n");
		 boaWrite(wp,"<body><blockquote>" \
					"<div style=\"padding-left:20px;\"><br><p>个性化站点启动成功！</p><p>个性化站点管理：pub.51awifi.com, 您可以登录该网址，管理您的个性化站点。</p><br>\n" \
					"</div></blockquote></body>" );
		 boaFooter(wp);

	} else{
		boaHeader(wp);
		boaWrite(wp, "<head><title>中国电信</title><style type=text/css>@import url(../../style/default.css);</style>\n" \
					"<style>"
					"p{padding:0;margin: 0;}"
					".error_img{background:url('../../image/awifierror.jpg') no-repeat 48%% 50%%;width:450px;height:95px;}"
					".help_img{background:url('../../image/awifihelp.jpg') no-repeat 48%% 97%%;height: 70px;width: 53px;float: left;}"
					".help_text{display: inline-block;padding-left: 10px;padding-top: 13px;width: 400px;}"
					"</style>\n"
					"<script>function goback(){window.location.href='../../awifi_unique_station.asp';}</script>\n");

		 boaWrite(wp,"<body style='font-size: 14px;'><blockquote>\n" \
					"<form action=\'/boaform/admin/formAwifiStation\' method=\'post\' name=\'AwifiStation\'>\n" \
					"<div style=\'background:#e7e9ed;width:450px;height:180px;text-align:center;border:1px solid #ccc;\'><div class=\'error_img\'></div><p>个性化站点启动异常，请重新尝试！</p><input type=\'button\' value=\'关闭\' OnClick=\'goback();\' style=\'margin-top:10px;padding:0 10px;\'></div>\n" \
					" <div><span class=\'help_img\' ></span><span class=\'help_text\'><p>个性化站点启动异常？</p><p>1） 网络是否正常，请确保你的网络处于畅通状态</p> <p>2） 设备注册信息是否填写完整</p></span></div>\n" \
					"</form></blockquote></body>");
		 boaFooter(wp);	
	}

}

int initAwifiNetwork(int eid, request * wp, int argc, char ** argv)
{
	unsigned char awifiEnabled=0;
	MIB_CE_MBSSIB_T Entry;
	unsigned char security_method;
	char *awifi_name;
	int ret;

	_TRACE_CALL;

	ret=wlan_getEntry(&Entry, 1);

	if(ret){
		awifiEnabled = !Entry.wlanDisabled;
		_PUT_BOOL(awifiEnabled);
		
		awifi_name=Entry.ssid;
		_PUT_STR(awifi_name);
	}
	
	_TRACE_LEAVEL;
	return 0;
}

void formAwifiNetwork(request * wp, char *path, char *query)
{
	char *submitUrl, *strVal;
	unsigned char awifiEnabled;
	MIB_CE_MBSSIB_T Entry, rootEntry;
	int intVal;
	
	_TRACE_CALL;

	strVal = boaGetVar(wp, "awifiEnabled", "");
	printf("%s:%d:awifiEnabled=%s\n",__FUNCTION__,__LINE__,strVal);
	awifiEnabled = strcmp(strVal,"on")?0:1;

	wlan_getEntry(&Entry, 1);

	if(awifiEnabled){
		strVal = boaGetVar(wp, "awifi_name", "");
		printf("%s:%d:awifi_name=%s\n",__FUNCTION__,__LINE__,strVal);
		if ( strVal[0] ) {
			snprintf(Entry.ssid,MAX_SSID_LEN-1,"%s",strVal);
		}
		Entry.encrypt=0;
		Entry.wlanDisabled=0;
	}else{
		Entry.wlanDisabled=1;
	}

	wlan_setEntry(&Entry, 1);

#ifdef CONFIG_WIFI_SIMPLE_CONFIG //WPS
	//fprintf(stderr, "WPA WPS Configure\n");
	strVal = boaGetVar(wp, "wps_clear_configure_by_reg0", "");
	intVal = 0;
	if (strVal && strVal[0])
		intVal = atoi(strVal);
	update_wps_configured(intVal);
#endif

// Magician: Commit immediately
#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif // of #if COMMIT_IMMEDIATELY
	config_WLAN(ACT_RESTART, CONFIG_SSID_ALL);

	submitUrl = boaGetVar(wp, "submit-url", "");   // hidden page
	//OK_MSG(submitUrl);
	if (submitUrl[0])
		boaRedirect(wp, submitUrl);
	else
		boaDone(wp, 200);
	return;	
	
}

int initAwifiLanAuth(int eid, request * wp, int argc, char ** argv)
{
	unsigned char awifiLanEnabled=0;
	unsigned char lan1port=0,lan2port=0,lan3port=0,lan4port=0,ssid1port=0;
	char dhcpRangeStart[16],dhcpRangeEnd[16];
	int ulTime;

	_TRACE_CALL;
#ifdef CONFIG_CT_AWIFI_JITUAN_SMARTWIFI
	mib_get(AWIFI_LAN_AUTH_ENABLE,&awifiLanEnabled);
	_PUT_BOOL(awifiLanEnabled);

	mib_get(AWIFI_LAN1_AUTH_ENABLE,&lan1port);
	_PUT_BOOL(lan1port);

	mib_get(AWIFI_LAN2_AUTH_ENABLE,&lan2port);
	_PUT_BOOL(lan2port);

	mib_get(AWIFI_LAN3_AUTH_ENABLE,&lan3port);
	_PUT_BOOL(lan3port);

	mib_get(AWIFI_LAN4_AUTH_ENABLE,&lan4port);
	_PUT_BOOL(lan4port);

	mib_get(AWIFI_WLAN1_AUTH_ENABLE,&ssid1port);
	_PUT_BOOL(ssid1port);
#endif

#ifdef _PRMT_X_TELEFONICA_ES_DHCPOPTION_
	{
		unsigned int i,numpool;
		numpool = mib_chain_total( MIB_DHCPS_SERVING_POOL_AWIFI_TBL );
		for( i=0; i<numpool;i++ )
		{
			unsigned int j,num;
			DHCPS_SERVING_POOL_T entrypool;

			if( !mib_chain_get( MIB_DHCPS_SERVING_POOL_AWIFI_TBL, i, (void*)&entrypool ) )
				continue;

			//skip disable or relay pools
			if( entrypool.enable==0)
				continue;

			if(strcmp(entrypool.poolname,"awifi"))
				continue;

			strncpy(dhcpRangeStart, inet_ntoa(*((struct in_addr *)(entrypool.startaddr))), 16);
			strncpy(dhcpRangeEnd, inet_ntoa(*((struct in_addr *)(entrypool.endaddr))), 16);
			ulTime=entrypool.leasetime;

			_PUT_STR(dhcpRangeStart);
			_PUT_STR(dhcpRangeEnd);
			_PUT_INT(ulTime);
			break;
		}
	}
#endif //_PRMT_X_TELEFONICA_ES_DHCPOPTION_
	
	
	_TRACE_LEAVEL;
	return 0;
}

#define goto_dhcp_check_err(errorStr) \
    do {lineno = __LINE__; strcpy(tmpBuf, errorStr); goto check_err;} while(0)
extern int awifi_lan_enable();

void formAwifiLanAuth(request *wp, char *path, char *query)
{
	char *submitUrl, *strVal;
	unsigned char awifiLanEnabled;
	unsigned char lan1port=0,lan2port=0,lan3port=0,lan4port=0,ssid1port=0;
	int intVal;
	unsigned int uIp = 0, olduIp;            //	modem ip
	unsigned int uMask = 0, olduMask;          //	modem netmask
	unsigned int ulTime,oldulTime;
	unsigned int dhcpRangeStart;
	unsigned int dhcpRangeEnd;
	char tmpBuf[128];
	unsigned char vChar;
	int lineno = __LINE__;
	char *stemp = "";
	int changeflag=0;
	int ipchangeflag=0;
	
	strVal = boaGetVar(wp, "awifiLanEnabled", "");
	printf("%s:%d:awifiLanEnabled=%s\n",__FUNCTION__,__LINE__,strVal);
	awifiLanEnabled = strcmp(strVal,"on")?0:1;
#ifdef CONFIG_CT_AWIFI_JITUAN_SMARTWIFI
	mib_set(AWIFI_LAN_AUTH_ENABLE,&awifiLanEnabled);

	if(!awifiLanEnabled){
		strVal = boaGetVar(wp, "lan1port", "");
		printf("%s:%d:lan1port=%s\n",__FUNCTION__,__LINE__,strVal);
		lan1port = strcmp(strVal,"on")?0:1;
		mib_set(AWIFI_LAN1_AUTH_ENABLE,&lan1port);

		strVal = boaGetVar(wp, "lan2port", "");
		printf("%s:%d:lan2port=%s\n",__FUNCTION__,__LINE__,strVal);
		lan2port = strcmp(strVal,"on")?0:1;
		mib_set(AWIFI_LAN2_AUTH_ENABLE,&lan2port);
		
        strVal = boaGetVar(wp, "lan3port", "");
		printf("%s:%d:lan3port=%s\n",__FUNCTION__,__LINE__,strVal);
		lan3port = strcmp(strVal,"on")?0:1;
		mib_set(AWIFI_LAN3_AUTH_ENABLE,&lan3port);
		
        strVal = boaGetVar(wp, "lan4port", "");
		printf("%s:%d:lan4port=%s\n",__FUNCTION__,__LINE__,strVal);
		lan4port = strcmp(strVal,"on")?0:1;
		mib_set(AWIFI_LAN4_AUTH_ENABLE,&lan4port);
	}else{
		lan1port = 1;
		lan2port = 1;
		lan3port = 1;
		lan4port = 1;
		mib_set(AWIFI_LAN1_AUTH_ENABLE,&lan1port);
		mib_set(AWIFI_LAN2_AUTH_ENABLE,&lan2port);
		mib_set(AWIFI_LAN3_AUTH_ENABLE,&lan3port);
		mib_set(AWIFI_LAN4_AUTH_ENABLE,&lan4port);
	}

	strVal = boaGetVar(wp, "ssid1port", "");
	printf("%s:%d:ssid1port=%s\n",__FUNCTION__,__LINE__,strVal);
	ssid1port = strcmp(strVal,"on")?0:1;
	mib_set(AWIFI_WLAN1_AUTH_ENABLE,&ssid1port);

	awifi_lan_enable();
#endif

	//modem ip
	_GET_IP(uIp, _NEED);
	if(uIp == 0)
	{
		goto_dhcp_check_err(strWrongIP);
	}

	//netmask
	_GET_IP(uMask, _NEED);
	if(uMask == 0)
	{
		goto_dhcp_check_err(strWrongMask);
	}

	_GET_IP(dhcpRangeStart, _NEED);
	if(dhcpRangeStart == 0)
	{
		goto_dhcp_check_err(strInvalidRange);
	}

	_GET_IP(dhcpRangeEnd, _NEED);
	if(dhcpRangeEnd == 0)
	{
		goto_dhcp_check_err(strInvalidRange);
	}

	_GET_INT(ulTime, _NEED);
	if(ulTime == 0)
	{
		goto_dhcp_check_err(strSetLeaseTimeerror);
	}

	vChar=1;
	mib_set(MIB_ADSL_LAN_ENABLE_IP2, (void *)&vChar);

	mib_get(MIB_ADSL_LAN_IP2, (void *)&olduIp);
	if(olduIp != uIp)
	{
		ipchangeflag=1;
		changeflag=1;
	}
	mib_set(MIB_ADSL_LAN_IP2, (void *)&uIp);

	mib_get(MIB_ADSL_LAN_SUBNET2, (void *)&olduMask);
	if(olduMask != uMask)
		changeflag=1;
	mib_set(MIB_ADSL_LAN_SUBNET2, (void *)&uMask);

	if(changeflag)
		restart_lanip();

	changeflag=0;

#ifdef _PRMT_X_TELEFONICA_ES_DHCPOPTION_
	{
		unsigned int i,numpool;
		unsigned char sourceinterface;
		sourceinterface=0x20;
		if(lan1port)
			sourceinterface|=0x01;
		if(lan2port)
			sourceinterface|=0x02;
		if(lan3port)
			sourceinterface|=0x04;
		if(lan4port)
			sourceinterface|=0x08;
		if(ssid1port)
			sourceinterface|=0x10;
		numpool = mib_chain_total( MIB_DHCPS_SERVING_POOL_AWIFI_TBL );
		for( i=0; i<numpool;i++ )
		{
			unsigned int j,num;
			DHCPS_SERVING_POOL_T entrypool;

			if( !mib_chain_get( MIB_DHCPS_SERVING_POOL_AWIFI_TBL, i, (void*)&entrypool ) )
				continue;

			//skip disable or relay pools
			if( entrypool.enable==0)
				continue;

			if(strcmp(entrypool.poolname,"awifi"))
				continue;

			printf("find pool!\n");

			if(memcmp(entrypool.iprouter,&uIp,IP_ADDR_LEN))
				changeflag=1;
			if(memcmp(entrypool.dnsserver1,&uIp,IP_ADDR_LEN))
				changeflag=1;
			if(memcmp(entrypool.startaddr,&dhcpRangeStart,IP_ADDR_LEN))
				changeflag=1;
			if(memcmp(entrypool.endaddr,&dhcpRangeEnd,IP_ADDR_LEN))
				changeflag=1;
			if(entrypool.leasetime != ulTime)
				changeflag=1;
			if(entrypool.sourceinterface != sourceinterface)
				changeflag = 1;

			memcpy(entrypool.iprouter,&uIp,IP_ADDR_LEN);
			memcpy(entrypool.dnsserver1,&uIp,IP_ADDR_LEN);
			memcpy(entrypool.startaddr,&dhcpRangeStart,IP_ADDR_LEN);
			memcpy(entrypool.endaddr,&dhcpRangeEnd,IP_ADDR_LEN);
			entrypool.leasetime=ulTime;
			entrypool.sourceinterface = sourceinterface;

			printf("change awifi pool interface to 0x%x\n",entrypool.sourceinterface);

			mib_chain_update(MIB_DHCPS_SERVING_POOL_AWIFI_TBL,(void*)&entrypool,i);
			break;
		}
		if(changeflag){
			restart_dhcp();
            RTK_RG_Wifidog_Rule_set();
		}
	}
#endif //_PRMT_X_TELEFONICA_ES_DHCPOPTION_	

// Magician: Commit immediately
#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif // of #if COMMIT_IMMEDIATELY

#ifdef CONFIG_CT_AWIFI_JITUAN_SMARTWIFI
	if(ipchangeflag)
	{
        void *null;
		system(KILLWIFIDOGSTR);
		//startWiFiDog(null);	
	}
#endif	
	
	_TRACE_LEAVEL;
	submitUrl = boaGetVar(wp, "submit-url", "");   // hidden page
	//OK_MSG(submitUrl);
	if (submitUrl[0])
		boaRedirect(wp, submitUrl);
	else
		boaDone(wp, 200);
	return;	

check_err:
	_TRACE_LEAVEL;
	ERR_MSG(tmpBuf);
	return;
}

int initAwifiSiteServer(int eid, request * wp, int argc, char ** argv)
{
	char serverurl[MAX_SERVERURL_LEN];
	int portvalue;
	char *reg_server,*reg_url,*auth_server,*auth_url;
	int reg_port,auth_port;

	_TRACE_CALL;

#ifdef CONFIG_CT_AWIFI_JITUAN_SMARTWIFI
	mib_get(AWIFI_LAN_REG_SERVER,(void*)serverurl);
	reg_server=serverurl;
	_PUT_STR(reg_server);

	mib_get(AWIFI_LAN_REG_PORT,(void*)&portvalue);
	reg_port=portvalue;
	_PUT_INT(reg_port);

	mib_get(AWIFI_LAN_REG_URL,(void*)serverurl);
	reg_url=serverurl;
	_PUT_STR(reg_url);

	
	mib_get(AWIFI_LAN_AUTH_SERVER,(void*)serverurl);
	auth_server=serverurl;
	_PUT_STR(auth_server);

	mib_get(AWIFI_LAN_AUTH_PORT,(void*)&portvalue);
	auth_port=portvalue;
	_PUT_INT(auth_port);

	mib_get(AWIFI_LAN_AUTH_URL,(void*)serverurl);
	auth_url=serverurl;
	_PUT_STR(auth_url);
#endif
	
	_TRACE_LEAVEL;
	return 0;
}

void formAwifiSiteServer(request * wp, char * path, char * query)
{
	char *submitUrl, *strVal;
	int intVal;
	
	_TRACE_CALL;

#ifdef CONFIG_CT_AWIFI_JITUAN_SMARTWIFI
	strVal = boaGetVar(wp, "reg_server", "");
	mib_set(AWIFI_LAN_REG_SERVER,(void*)strVal);

	strVal = boaGetVar(wp, "reg_port", "");
	intVal = atoi(strVal);
	mib_set(AWIFI_LAN_REG_PORT,(void*)&intVal);


	strVal = boaGetVar(wp, "auth_server", "");
	mib_set(AWIFI_LAN_AUTH_SERVER,(void*)strVal);

	strVal = boaGetVar(wp, "auth_port", "");
	intVal = atoi(strVal);
	mib_set(AWIFI_LAN_AUTH_PORT,(void*)&intVal);
#endif

// Magician: Commit immediately
#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif // of #if COMMIT_IMMEDIATELY

	submitUrl = boaGetVar(wp, "submit-url", "");   // hidden page

	if (submitUrl[0])
		boaRedirect(wp, submitUrl);
	else
		boaDone(wp, 200);

	return;

}

int initAwifiDefaultServer(int eid, request * wp, int argc, char ** argv)
{
	char serverurl[MAX_SERVERURL_LEN];
	int portvalue;
	char *reg_server,*auth_server,*portal_server;
	int reg_port,auth_port,portal_port;

	_TRACE_CALL;

#ifdef CONFIG_CT_AWIFI_JITUAN_SMARTWIFI
	parse_ServerHostname(WIFIDOGCONFPATH, "PlatformServer", serverurl);
	reg_server=serverurl;
	_PUT_STR(reg_server);

	parse_ServerHttpPort(WIFIDOGCONFPATH, "PlatformServer", &portvalue);
	reg_port=portvalue;
	_PUT_INT(reg_port);
	
	parse_ServerHostname(WIFIDOGCONFPATH, "AuthServer", serverurl);
	auth_server=serverurl;
	_PUT_STR(auth_server);

	parse_ServerHttpPort(WIFIDOGCONFPATH, "AuthServer", &portvalue);
	auth_port=portvalue;
	_PUT_INT(auth_port);

	parse_ServerHostname(WIFIDOGCONFPATH, "PortalServer", serverurl);
	portal_server=serverurl;
	_PUT_STR(portal_server);

	parse_ServerHttpPort(WIFIDOGCONFPATH, "PortalServer", &portvalue);
	portal_port=portvalue;
	_PUT_INT(portal_port);
#endif
	
	_TRACE_LEAVEL;
	return 0;
}

void formAwifiDefaultServer(request * wp, char * path, char * query)
{
	char *submitUrl, *strVal;
	int intVal, linenum=0, change=0;
	int portvalue;
	char portstr[64], serverstr[128];
	char serverurl[MAX_SERVERURL_LEN];
	
	_TRACE_CALL;

#ifdef CONFIG_CT_AWIFI_JITUAN_SMARTWIFI
	free_server_setting();
	strVal = boaGetVar(wp, "reg_server", "");
	parse_ServerHostname(WIFIDOGCONFPATH, "PlatformServer", serverurl);
	if(strcmp(strVal, serverurl))
	{
		change=1;
		snprintf(serverstr,MAX_SERVERURL_LEN,"Hostname %s\n", strVal);
		linenum = getLineNumber("PlatformServer", "Hostname");
		addServerSetting(linenum, serverstr);
	}

	strVal = boaGetVar(wp, "reg_port", "");
	intVal = atoi(strVal);
	parse_ServerHttpPort(WIFIDOGCONFPATH, "PlatformServer", &portvalue);
	if(intVal != portvalue)
	{
		change=1;
		snprintf(portstr,64,"HttpPort %d\n", intVal);
		linenum = getLineNumber("PlatformServer", "HttpPort");
		addServerSetting(linenum, portstr);
	}

	strVal = boaGetVar(wp, "auth_server", "");
	parse_ServerHostname(WIFIDOGCONFPATH, "AuthServer", serverurl);
	if(strcmp(strVal, serverurl))
	{
		change=1;
		snprintf(serverstr,MAX_SERVERURL_LEN,"Hostname %s\n", strVal);
		linenum = getLineNumber("AuthServer", "Hostname");
		addServerSetting(linenum, serverstr);
	}

	strVal = boaGetVar(wp, "auth_port", "");
	intVal = atoi(strVal);
	parse_ServerHttpPort(WIFIDOGCONFPATH, "AuthServer", &portvalue);
	if(intVal != portvalue)
	{
		change=1;
		snprintf(portstr,64,"HttpPort %d\n", intVal);
		linenum = getLineNumber("AuthServer", "HttpPort");
		addServerSetting(linenum, portstr);
	}

	strVal = boaGetVar(wp, "portal_server", "");
	parse_ServerHostname(WIFIDOGCONFPATH, "PortalServer", serverurl);
	if(strcmp(strVal, serverurl))
	{
		change=1;
		snprintf(serverstr,MAX_SERVERURL_LEN,"Hostname %s\n", strVal);
		linenum = getLineNumber("PortalServer", "Hostname");
		addServerSetting(linenum, serverstr);
	}

	strVal = boaGetVar(wp, "portal_port", "");
	intVal = atoi(strVal);
	parse_ServerHttpPort(WIFIDOGCONFPATH, "PortalServer", &portvalue);
	if(intVal != portvalue)
	{
		change=1;
		snprintf(portstr,64,"HttpPort %d\n", intVal);
		linenum = getLineNumber("PortalServer", "HttpPort");
		addServerSetting(linenum, portstr);
	}
#endif

// Magician: Commit immediately
#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif // of #if COMMIT_IMMEDIATELY

#ifdef CONFIG_CT_AWIFI_JITUAN_SMARTWIFI
	if(change==1)
	{
		UpdateAwifiConfSetting();
		system(KILLWIFIDOGSTR);
	//	startWiFiDog();
	}
#endif	

	submitUrl = boaGetVar(wp, "submit-url", "");   // hidden page

	if (submitUrl[0])
		boaRedirect(wp, submitUrl);
	else
		boaDone(wp, 200);
	return;

}

int initAwifiUpdateCfg(int eid, request * wp, int argc, char ** argv)
{

	return 0;
}

void formAwifiUpdateCfg(request * wp, char * path, char * query)
{
	char *submitUrl, *strVal;
		
	_TRACE_CALL;
	
#ifdef CONFIG_CT_AWIFI_JITUAN_SMARTWIFI
	strVal = boaGetVar(wp, "update_url", "");
	mib_set(AWIFI_IMAGE_URL,(void*)strVal);

	strVal = boaGetVar(wp, "key", "");
	mib_set(AWIFI_APPLYID,(void*)strVal);

	strVal = boaGetVar(wp, "ver_server", "");
	mib_set(AWIFI_REPORT_URL,(void*)strVal);

	strVal = boaGetVar(wp, "encode", "");
	mib_set(AWIFI_CITY,(void*)strVal);
#endif

// Magician: Commit immediately
#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif // of #if COMMIT_IMMEDIATELY

	submitUrl = boaGetVar(wp, "submit-url", "");   // hidden page

	if (submitUrl[0])
		boaRedirect(wp, submitUrl);
	else
		boaDone(wp, 200);
	return;

}


#endif

