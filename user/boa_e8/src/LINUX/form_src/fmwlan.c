/*
 *      Web server handler routines for wlan stuffs
 *
 *      Authors: David Hsu	<davidhsu@realtek.com.tw>
 *
 *      $Id: fmwlan.c,v 1.97 2012/11/21 13:00:11 kaohj Exp $
 *
 */

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "../webs.h"
#include "mib.h"
#include "webform.h"
#include "utility.h"
//xl_yue add
#include "../defs.h"
#include "multilang.h"
#include "fmdefs.h"

WLAN_RATE_T rate_11n_table_20M_LONG[]={
	{MCS0, 	"6.5"},
	{MCS1, 	"13"},
	{MCS2, 	"19.5"},
	{MCS3, 	"26"},
	{MCS4, 	"39"},
	{MCS5, 	"52"},
	{MCS6, 	"58.5"},
	{MCS7, 	"65"},
	{MCS8, 	"13"},
	{MCS9, 	"26"},
	{MCS10, 	"39"},
	{MCS11, 	"52"},
	{MCS12, 	"78"},
	{MCS13, 	"104"},
	{MCS14, 	"117"},
	{MCS15, 	"130"},
	{0}
};
WLAN_RATE_T rate_11n_table_20M_SHORT[]={
	{MCS0, 	"7.2"},
	{MCS1, 	"14.4"},
	{MCS2, 	"21.7"},
	{MCS3, 	"28.9"},
	{MCS4, 	"43.3"},
	{MCS5, 	"57.8"},
	{MCS6, 	"65"},
	{MCS7, 	"72.2"},
	{MCS8, 	"14.444"},
	{MCS9, 	"28.889"},
	{MCS10, 	"43.333"},
	{MCS11, 	"57.778"},
	{MCS12, 	"86.667"},
	{MCS13, 	"115.556"},
	{MCS14, 	"130"},
	{MCS15, 	"144.444"},
	{0}
};
WLAN_RATE_T rate_11n_table_40M_LONG[]={
	{MCS0, 	"13.5"},
	{MCS1, 	"27"},
	{MCS2, 	"40.5"},
	{MCS3, 	"54"},
	{MCS4, 	"81"},
	{MCS5, 	"108"},
	{MCS6, 	"121.5"},
	{MCS7, 	"135"},
	{MCS8, 	"27"},
	{MCS9, 	"54"},
	{MCS10, 	"81"},
	{MCS11, 	"108"},
	{MCS12, 	"162"},
	{MCS13, 	"216"},
	{MCS14, 	"243"},
	{MCS15, 	"270"},
	{0}
};
WLAN_RATE_T rate_11n_table_40M_SHORT[]={
	{MCS0, 	"15"},
	{MCS1, 	"30"},
	{MCS2, 	"45"},
	{MCS3, 	"60"},
	{MCS4, 	"90"},
	{MCS5, 	"120"},
	{MCS6, 	"135"},
	{MCS7, 	"150"},
	{MCS8, 	"30"},
	{MCS9, 	"60"},
	{MCS10, 	"90"},
	{MCS11, 	"120"},
	{MCS12, 	"180"},
	{MCS13, 	"240"},
	{MCS14, 	"270"},
	{MCS15, 	"300"},
	{0}
};
WLAN_RATE_T tx_fixed_rate[]={
	{1, "1"},
	{(1<<1), 	"2"},
	{(1<<2), 	"5.5"},
	{(1<<3), 	"11"},
	{(1<<4), 	"6"},
	{(1<<5), 	"9"},
	{(1<<6), 	"12"},
	{(1<<7), 	"18"},
	{(1<<8), 	"24"},
	{(1<<9), 	"36"},
	{(1<<10), 	"48"},
	{(1<<11), 	"54"},
	{(1<<12), 	"MCS0"},
	{(1<<13), 	"MCS1"},
	{(1<<14), 	"MCS2"},
	{(1<<15), 	"MCS3"},
	{(1<<16), 	"MCS4"},
	{(1<<17), 	"MCS5"},
	{(1<<18), 	"MCS6"},
	{(1<<19), 	"MCS7"},
	{(1<<20), 	"MCS8"},
	{(1<<21), 	"MCS9"},
	{(1<<22), 	"MCS10"},
	{(1<<23), 	"MCS11"},
	{(1<<24), 	"MCS12"},
	{(1<<25), 	"MCS13"},
	{(1<<26), 	"MCS14"},
	{(1<<27), 	"MCS15"},
	{0}
};

//changes in following table should be synced to VHT_MCS_DATA_RATE[] in 8812_vht_gen.c
const unsigned short VHT_MCS_DATA_RATE[3][2][20] =
        {       {       {13, 26, 39, 52, 78, 104, 117, 130, 156, 156,
                         26, 52, 78, 104, 156, 208, 234, 260, 312, 312},                        // Long GI, 20MHz
                        {14, 29, 43, 58, 87, 116, 130, 144, 173, 173,
                        29, 58, 87, 116, 173, 231, 260, 289, 347, 347}  },              // Short GI, 20MHz
                {       {27, 54, 81, 108, 162, 216, 243, 270, 324, 360,
                        54, 108, 162, 216, 324, 432, 486, 540, 648, 720},               // Long GI, 40MHz
                        {30, 60, 90, 120, 180, 240, 270, 300,360, 400,
                        60, 120, 180, 240, 360, 480, 540, 600, 720, 800}},              // Short GI, 40MHz
                {       {59, 117,  176, 234, 351, 468, 527, 585, 702, 780,
                        117, 234, 351, 468, 702, 936, 1053, 1170, 1404, 1560},  // Long GI, 80MHz
                        {65, 130, 195, 260, 390, 520, 585, 650, 780, 867,
                        130, 260, 390, 520, 780, 1040, 1170, 1300, 1560,1733}   }       // Short GI, 80MHz
        };


/////////////////////////////////////////////////////////////////////////////
#ifndef NO_ACTION
static void run_script(int mode)
{
	int pid;
	char tmpBuf[100];
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

#ifdef CONFIG_YUEME
char *wlanRedirecAllowList[]={"net_wlan_basic_11n_yueme.asp", "net_wlan_adv.asp", "net_wlan_ft.asp", NULL};
#endif
void formWlanRedirect(request * wp, char *path, char *query)
{
	char *redirectUrl;
	char *strWlanId;
	char tmpBuf[32];

	redirectUrl= boaGetVar(wp, "redirect-url", "");   // hidden page
	strWlanId= boaGetVar(wp, "wlan_idx", "");   // hidden page
	if(strWlanId[0]){
		wlan_idx = atoi(strWlanId);
		if (!isValid_wlan_idx(wlan_idx)) {
			snprintf(tmpBuf, 32, "Invalid wlan_idx: %d", wlan_idx);
			ERR_MSG(tmpBuf);
			return;
		}
	}

	if(redirectUrl[0])
	{
#ifdef CONFIG_YUEME
		if(!checkValidRedirect(redirectUrl, wlanRedirecAllowList))
		{
			wp->buffer_end=0; // clear header
			send_r_bad_request(wp);
		}
		else
#endif
			boaRedirectTemp(wp,redirectUrl); //avoid caching
	}
}
#if defined(CONFIG_RTL_92D_SUPPORT)
static int swapWlanMibSetting(unsigned char wlanifNumA, unsigned char wlanifNumB, char *tmpBuf)
{
	int i = 0;
#ifdef WLAN_MBSSID
	MIB_CE_MBSSIB_T entryA, entryB;
	unsigned char idx;
#endif	//WLAN_MBSSID
#ifdef WLAN_ACL
	MIB_CE_WLAN_AC_T entryACL;
	int entryNumACL;
#endif

	if((wlanifNumA >= NUM_WLAN_INTERFACE) || (wlanifNumB >= NUM_WLAN_INTERFACE)) {
		printf("%s: wrong wlan interface number!\n", __func__);
		goto setErr_wlan;
	}

	for(i = DUAL_WLAN_START_ID + 1; i < DUAL_WLAN_END_ID; i += NUM_WLAN_INTERFACE){
		if(mib_swap( i, i + 1) == 0){
			strcpy(tmpBuf, "Swap WLAN MIB failed!");
			goto setErr_wlan;
		}
	}

#ifdef WLAN_MBSSID
	for(i=0; i<=WLAN_REPEATER_ITF_INDEX; i++)
		mib_chain_swap(MIB_MBSSIB_TBL, wlanifNumA * (WLAN_REPEATER_ITF_INDEX + 1) + i, wlanifNumB * (WLAN_REPEATER_ITF_INDEX + 1) + i);
#endif	//WLAN_MBSSID

#ifdef WLAN_ACL
	entryNumACL = mib_chain_total(MIB_WLAN_AC_TBL);
	for(i=0; i<entryNumACL; i++) {
		if(!mib_chain_get(MIB_WLAN_AC_TBL, i, (void *)&entryACL)) {
			strcpy(tmpBuf, "Get chain record error!\n");
			goto setErr_wlan;
		}
		if(entryACL.wlanIdx == wlanifNumA)
			entryACL.wlanIdx = wlanifNumB;
		else if(entryACL.wlanIdx == wlanifNumB)
			entryACL.wlanIdx = wlanifNumA;
		else
			continue;

		mib_chain_update(MIB_WLAN_AC_TBL, (void *)&entryACL, i);
	}
#endif

	return 0;

setErr_wlan:
	return -1;
}

void formWlanBand2G5G(request * wp, char *path, char *query)
{
	char *submitUrl;
	char tmpBuf[100];
	char *tmpStr;
	char vChar, wlanBand2G5GSelect, origBand2G5GSelect, phyBand[NUM_WLAN_INTERFACE];
	char lan_ip[30];
	int i;

	mib_get(MIB_WLAN_BAND2G5G_SELECT, (void *)&origBand2G5GSelect);

	submitUrl = boaGetVar(wp, "submit-url", "");   // hidden page
	tmpStr = boaGetVar(wp, "wlBandMode", "");

	if(tmpStr[0]) {
		wlanBand2G5GSelect = tmpStr[0]-'0';
	}

	if(wlanBand2G5GSelect<BANDMODEBOTH || wlanBand2G5GSelect>BANDMODESINGLE) {
		strcpy(tmpBuf, "Get wrong band mode value!");
		goto setErr_wlan;
	}
	else if(origBand2G5GSelect == wlanBand2G5GSelect) {
		goto sameBand;
	}
	else if(mib_set(MIB_WLAN_BAND2G5G_SELECT, (void *)&wlanBand2G5GSelect) == 0) {
		strcpy(tmpBuf, "Set wlan band 2G/5G select failed!");
		goto setErr_wlan;
	}

	for(i=0; i<NUM_WLAN_INTERFACE; i++) {
		wlan_idx = i;
		mib_get(MIB_WLAN_PHY_BAND_SELECT, (void *)&phyBand[i]);

		/* init all wireless interface is set radio off and DMACDPHY */
		vChar = 1;
		if(mib_set(MIB_WLAN_DISABLED, (void *)&vChar) == 0) {
			strcpy(tmpBuf, strDisbWlanErr);
			goto setErr_wlan;
		}
		vChar = DMACDPHY;
		if(mib_set(MIB_WLAN_MAC_PHY_MODE, (void *)&vChar) == 0) {
			strcpy(tmpBuf, "Set wlan mca phy mode failed!");
			goto setErr_wlan;
		}
	}
	if(wlanBand2G5GSelect == BANDMODEBOTH) {
		for(i=0; i<NUM_WLAN_INTERFACE; i++) {
			wlan_idx = i;
			vChar = 0;
			if(mib_set(MIB_WLAN_DISABLED, (void *)&vChar) == 0) {
				strcpy(tmpBuf, strDisbWlanErr);
				goto setErr_wlan;
			}
			vChar = DMACDPHY;
			if(mib_set(MIB_WLAN_MAC_PHY_MODE, (void *)&vChar) == 0) {
				strcpy(tmpBuf, "Set wlan mca phy mode failed!");
				goto setErr_wlan;
			}
		}

		/* 92d rule, 5g must up in wlan0 */
		/*
		for(i=0; i<NUM_WLAN_INTERFACE; i++) {
			if(phyBand[i] == PHYBAND_5G) {
				if((i != 0) && (swapWlanMibSetting(0, i, tmpBuf) < 0))
					goto setErr_wlan;
				break;
			}
		}
		*/
	}
	else if(wlanBand2G5GSelect == BANDMODESINGLE) {
		for(i=0; i<NUM_WLAN_INTERFACE; i++) {
			wlan_idx = i;
			if(i == 0) {	//enable wlan0
				vChar = 0;
				if(mib_set(MIB_WLAN_DISABLED, (void *)&vChar) == 0) {
					strcpy(tmpBuf, strDisbWlanErr);
					goto setErr_wlan;
				}
			}

			vChar = SMACSPHY;
			if(mib_set(MIB_WLAN_MAC_PHY_MODE, (void *)&vChar) == 0) {
				strcpy(tmpBuf, "Set wlan mca phy mode failed!");
				goto setErr_wlan;
			}
		}
		vChar = 0;
		if(mib_set(MIB_WLAN_BAND2G5G_SINGLE_SELECT, (void *)&vChar) == 0) {
			strcpy(tmpBuf, strDisbWlanErr);
			goto setErr_wlan;
		}
	}
	else {
		strcpy(tmpBuf, "Only support both or single mode switch!\n");
		goto setErr_wlan;
	}

	getMIB2Str(MIB_ADSL_LAN_IP, lan_ip);
	sprintf(tmpBuf,"%s","<h4>Change setting successfully!<BR><BR>Do not turn off or reboot the Device during this time.</h4>");
	OK_MSG_FW(tmpBuf, submitUrl,APPLY_COUNTDOWN_TIME,lan_ip);

#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif
	config_WLAN(ACT_RESTART, CONFIG_SSID_ALL);
	//OK_MSG(submitUrl);
	return;

sameBand:
	if(submitUrl[0])
		boaRedirect(wp,submitUrl);
setErr_wlan:
	ERR_MSG(tmpBuf);
}
#endif //CONFIG_RTL_92D_SUPPORT

/*
 *	Whenever band changed, it must be called to check some dependency items.
 */
static void update_on_band_changed(MIB_CE_MBSSIB_T *pEntry, int idx, int cur_band)
{
	if(wl_isNband(cur_band)) {	//n mode is enabled
		/*
		 * andrew: new test plan require N mode to
		 * avoid using TKIP.
		 */
		if (pEntry->encrypt != WIFI_SEC_WPA2_MIXED) {
			pEntry->unicastCipher = WPA_CIPHER_AES;
			pEntry->wpa2UnicastCipher= WPA_CIPHER_AES;
		}
	}
}

static void update_vap_band(unsigned char root_band)
{
	MIB_CE_MBSSIB_T Entry;
	int i;
	
	for(i=1; i<=NUM_VWLAN_INTERFACE; i++) {
		wlan_getEntry(&Entry, i);
#ifndef CONFIG_YUEME
		if (!Entry.wlanDisabled) 
#endif
		{
			Entry.wlanBand &= root_band;
			if (Entry.wlanBand == 0) {
				Entry.wlanBand = root_band;
				update_on_band_changed(&Entry, i, Entry.wlanBand);
			}
			mib_chain_update(MIB_MBSSIB_TBL, (void *)&Entry, i);
		}
	}
}

/////////////////////////////////////////////////////////////////////////////
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
#ifdef CONFIG_WIFI_SIMPLE_CONFIG // WPS
#define _WSC_DAEMON_PROG	"/bin/wscd"
#define WSC_PBC_WAITTIME	120
#define WSCD_PBC_CANCEL		"echo 1 > /tmp/wscd_cancel"

static void start_PBC(char* ptr)
{
	system(ptr);
	sleep(WSC_PBC_WAITTIME);
	unlink(ptr+8);
	system(WSCD_PBC_CANCEL);
}

static void stop_PBC(char* ptr)
{
	system(WSCD_PBC_CANCEL);
	unlink(ptr+8);
}
#endif
#endif

void formWlanSetup(request * wp, char *path, char *query)
{
	char *submitUrl, *strSSID, *strChan, *strDisabled, *strVal;
	char vChar, chan, disabled, mode=-1;
	NETWORK_TYPE_T net;
	char tmpBuf[100];
	int flags;
	MIB_CE_MBSSIB_T Entry;
	MIB_CE_MBSSIB_T RootEntry;
	int warn = 0;
#if defined(CONFIG_CMCC) || defined(CONFIG_YUEME) || defined(CONFIG_CU)
	unsigned short uShort=0;
	int vInt=0, ssidIdx, wlmib_idx=0;
#if defined(CONFIG_YUEME)
	unsigned char update_all_ssid=0;
#endif
#ifndef WLAN_DUALBAND_CONCURRENT
	int all_ssid_modify=0;
#endif
#endif
#ifdef WLAN_UNIVERSAL_REPEATER
	MIB_CE_MBSSIB_T repeaterEntry;
#endif
#if defined(CONFIG_RTL_92D_SUPPORT) || defined(WLAN_DUALBAND_CONCURRENT)
	char phyBandSelect, wlanBand2G5GSelect, phyBandOrig, wlanBand2G5GSelect_single;
	int phyBandSelectChange = 0;
	char lan_ip[30];
	int orig_idx;
#if defined(CONFIG_YUEME) || defined(CONFIG_CMCC) || defined(CONFIG_CU)
	int both_band_modify=0;
#ifdef CONFIG_RTL_STA_CONTROL_SUPPORT
	unsigned char sta_control=0, sta_control_change=0;
#endif
#endif
#endif //CONFIG_RTL_92D_SUPPORT || WLAN_DUALBAND_CONCURRENT

#if !defined(WLAN_WPS_VAP)
#ifdef CONFIG_WIFI_SIMPLE_CONFIG
#ifdef WPS20
	unsigned char wpsUseVersion;
#ifdef WPS_VERSION_CONFIGURABLE
	if (mib_get(MIB_WSC_VERSION, (void *)&wpsUseVersion) == 0)
#endif
		wpsUseVersion = WPS_VERSION_V2;
#endif
#endif
#endif


#if 0 //def CONFIG_RTL_92D_SUPPORT
	mib_get(MIB_WLAN_BAND2G5G_SELECT, (void *)&wlanBand2G5GSelect);

	if(wlanBand2G5GSelect == BANDMODESINGLE) {
		strVal = boaGetVar(wp, "Band2G5GSupport", "");
		if ( strVal[0] ) {
			printf("Band2G5GSupport=%d\n", strVal[0]-'0');
			phyBandSelect = strVal[0]-'0';

			for(i=0; i<NUM_WLAN_INTERFACE; i++) {
				wlan_idx = i;
				mib_get(MIB_WLAN_PHY_BAND_SELECT, (void *)&phyBandOrig);
				if(phyBandOrig == phyBandSelect) {
					if(i != 0) {
						wlan_idx = 0;
						vChar = 1;
						if(mib_set(MIB_WLAN_DISABLED, (void *)&vChar) == 0) {	//close original interface
							strcpy(tmpBuf, strDisbWlanErr);
							goto setErr_wlan;
						}
						if(swapWlanMibSetting(0, i, tmpBuf) < 0)
							goto setErr_wlan;

						vChar = 0;
						if(mib_set(MIB_WLAN_DISABLED, (void *)&vChar) == 0) {	//enable new interface
							strcpy(tmpBuf, strDisbWlanErr);
							goto setErr_wlan;
						}
					}
					break;
				}
			}
		}
	}

	strVal = boaGetVar(wp, "wlan_idx", "");
	if ( strVal[0] ) {
		printf("wlan_idx=%d\n", strVal[0]-'0');
		wlan_idx = strVal[0]-'0';
	}
#endif //CONFIG_RTL_92D_SUPPORT

#if defined(CONFIG_RTL_92D_SUPPORT) || defined(WLAN_DUALBAND_CONCURRENT)
	strVal = boaGetVar(wp, "wlan_idx", "");
	if ( strVal[0] ) {
		printf("wlan_idx=%d\n", strVal[0]-'0');
		wlan_idx = strVal[0]-'0';
	}
#if defined(CONFIG_RTL_92D_SUPPORT)
	mib_get(MIB_WLAN_BAND2G5G_SELECT, (void *)&wlanBand2G5GSelect);

	if(wlanBand2G5GSelect == BANDMODESINGLE) {
		strVal = boaGetVar(wp, "Band2G5GSupport", "");
		printf("Band2G5GSupport=%d\n", strVal[0]-'0');
		phyBandSelect = strVal[0]-'0';
		mib_get(MIB_WLAN_BAND2G5G_SINGLE_SELECT, (void *)&wlanBand2G5GSelect_single);
		phyBandOrig = (wlanBand2G5GSelect_single == BANDMODE5G) ? PHYBAND_5G : PHYBAND_2G;
		if(phyBandSelect != phyBandOrig){
			phyBandSelectChange = 1;
			
			//close original interface
			if(!mib_chain_get(MIB_MBSSIB_TBL, 0, (void *)&Entry)){
				strcpy(tmpBuf, strDisbWlanErr);
				goto setErr_wlan;
			}
			Entry.wlanDisabled = 1;
			if(!mib_chain_update(MIB_MBSSIB_TBL, (void *)&Entry, 0)){
				strcpy(tmpBuf, strDisbWlanErr);
				goto setErr_wlan;
			}
			if(wlan_idx == 1) wlan_idx = 0;
			else wlan_idx = 1;
			
			//enable new interface
			if(!mib_chain_get(MIB_MBSSIB_TBL, 0, (void *)&Entry)){
				strcpy(tmpBuf, strDisbWlanErr);
				goto setErr_wlan;
			}
			Entry.wlanDisabled = 0;
			if(!mib_chain_update(MIB_MBSSIB_TBL, (void *)&Entry, 0)){
				strcpy(tmpBuf, strDisbWlanErr);
				goto setErr_wlan;
			}
			vChar = wlan_idx;
			mib_set(MIB_WLAN_BAND2G5G_SINGLE_SELECT, (void *)&vChar);
		}
		
	}
#endif
#endif

#ifdef CONFIG_YUEME
	strVal = boaGetVar(wp, "ssid_idx", "");
	ssidIdx = strVal[0] - '0'; 

	mib_chain_get(MIB_MBSSIB_TBL, ssidIdx, (void *)&Entry);
#elif defined(CONFIG_CMCC) || defined(CONFIG_CU)
	strVal = boaGetVar(wp, "ssid_idx", "");
	ssidIdx = strVal[0] - '0'; 

	if(ssidIdx == 2)    //SSID2
	{
		memset( &Entry, 0, sizeof( MIB_CE_MBSSIB_T ));
		wlmib_idx = 1;
		memset( &RootEntry, 0, sizeof( MIB_CE_MBSSIB_T ));
		mib_chain_get(MIB_MBSSIB_TBL, 0, (void *)&RootEntry);
	}
	else if(ssidIdx == 0)
		wlmib_idx = 0;

	mib_chain_get(MIB_MBSSIB_TBL, wlmib_idx, (void *)&Entry);
#else
	mib_chain_get(MIB_MBSSIB_TBL, 0, (void *)&Entry);
#endif

	strDisabled = boaGetVar(wp, "wlanDisabled", "");

	if ( !gstrcmp(strDisabled, "ON") )
		disabled = 1;
	else
		disabled = 0;

	strDisabled = boaGetVar(wp, "wlanEnabled", "");

	if ( !gstrcmp(strDisabled, "ON") )
		disabled = 0;
	else
		disabled = 1;

#if 0	
	if (getInFlags(getWlanIfName(), &flags) == 1) {
		if (disabled)
			flags &= ~IFF_UP;
		else
			flags |= IFF_UP;

		setInFlags(getWlanIfName(), flags);
	}
#endif
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
#ifdef WLAN_DUALBAND_CONCURRENT
	mib_get(MIB_WIFI_MODULE_DISABLED, (void *)&vChar);
	if(disabled!=vChar)
		both_band_modify = 1;
#endif
#endif
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
#ifndef WLAN_DUALBAND_CONCURRENT
	mib_get(MIB_WIFI_MODULE_DISABLED, (void *)&vChar);
	if(disabled!=vChar)
		all_ssid_modify=1;
#endif
#endif
#ifdef CONFIG_YUEME
#ifdef YUEME_3_0_SPEC
	mib_get(MIB_WLAN_DISABLED, (void *)&vChar);
	if(vChar!=disabled)
		update_all_ssid = 1;
	mib_set(MIB_WLAN_DISABLED, (void *)&disabled);
#else
	mib_get(MIB_WIFI_MODULE_DISABLED, (void *)&vChar);
	if(vChar!=disabled){
		update_all_ssid = 1;
#ifdef WLAN_DUALBAND_CONCURRENT
		both_band_modify = 1;
#endif
	}
	mib_set(MIB_WIFI_MODULE_DISABLED, (void *)&disabled);
#endif
#else	
	mib_set(MIB_WIFI_MODULE_DISABLED, (void *)&disabled);
#endif

	if ( disabled ){
#ifdef YUEME_3_0_SPEC
#ifdef WLAN_DUALBAND_CONCURRENT
#ifdef CONFIG_RTL_STA_CONTROL_SUPPORT
		mib_get(MIB_WIFI_STA_CONTROL, (void *)&sta_control);
		if(sta_control==1)
		{
			sta_control = 0;
			if ( mib_set( MIB_WIFI_STA_CONTROL, (void *)&sta_control) == 0)
			{
				goto setErr_wlan;
			}
			both_band_modify = 1;
			SetOrCancelSameSSID(sta_control);
		}
#endif
#endif
#endif
		goto setwlan_module_disable;
	}

#if defined(CONFIG_CMCC) || defined(CONFIG_YUEME) || defined(CONFIG_CU)
	strVal = boaGetVar(wp, "enableSSID", "");

	if ( !gstrcmp(strVal, "ON") )
		Entry.wlanDisabled = 0;
	else
	{
		Entry.wlanDisabled = 1;
#ifdef WLAN_DUALBAND_CONCURRENT
#ifdef CONFIG_RTL_STA_CONTROL_SUPPORT
		mib_get(MIB_WIFI_STA_CONTROL, (void *)&sta_control);
		if(sta_control==1)
		{
			sta_control = 0;
			if ( mib_set( MIB_WIFI_STA_CONTROL, (void *)&sta_control) == 0)
			{
				goto setErr_wlan;
			}
			both_band_modify = 1;
			sta_control_change = 1;
		}
#endif
#endif
	}
#else
	if(Entry.wlanDisabled)
		goto setwlan_module_disable;
#endif

#ifdef CONFIG_YUEME
	if(ssidIdx==0)
#endif
	{
		
#ifdef WLAN_DUALBAND_CONCURRENT
#ifdef CONFIG_RTL_STA_CONTROL_SUPPORT
		if(Entry.wlanDisabled == 0)
		{
			strDisabled = boaGetVar(wp, "wlanStaControl", "");

			if ( !gstrcmp(strDisabled, "ON") )
				vChar = 1;
			else
				vChar = 0;
#ifdef CONFIG_YUEME
			mib_get(MIB_WIFI_STA_CONTROL, (void *)&sta_control);
			
			if(sta_control!=vChar || vChar&&wlan_idx==0)
			{
				both_band_modify = 1;
				sta_control_change = 1;
			}
			sta_control = vChar;
#endif

			if ( mib_set( MIB_WIFI_STA_CONTROL, (void *)&vChar) == 0) {
				goto setErr_wlan;
			}
		}
#endif
#endif

#ifdef WLAN_RATE_PRIOR
		strVal = boaGetVar(wp, "wlanRatePrior", "");

		if ( !gstrcmp(strVal, "ON") )
			vChar = 1;
		else
			vChar = 0;
		if ( mib_set( MIB_WLAN_RATE_PRIOR, (void *)&vChar) == 0) {
			goto setErr_wlan;
		}
#endif

		// Added by Mason Yu for TxPower
		strVal = boaGetVar(wp, "txpower", "");
		if ( strVal[0] ) {

			if (strVal[0] < '0' || strVal[0] > '5') {
				strcpy(tmpBuf, strInvdTxPower);
				goto setErr_wlan;
			}

			if(strVal[0]=='5')
				mode = 0;
			else
				mode = strVal[0] - '0';

			if ( mib_set( MIB_TX_POWER, (void *)&mode) == 0) {
	   			strcpy(tmpBuf, strSetMIBTXPOWErr);
				goto setErr_wlan;
			}

			if(strVal[0]=='5')
				mode = 1;
			else
				mode = 0;

			if ( mib_set( MIB_WLAN_TX_POWER_HIGH, (void *)&mode) == 0) {
	   			strcpy(tmpBuf, strSetMIBTXPOWErr);
				goto setErr_wlan;
			}
			

		}
	}

	strVal = boaGetVar(wp, "mode", "");
	if ( strVal[0] ) {
		if (strVal[0]!= '0' && strVal[0]!= '1' && strVal[0]!= '2' && strVal[0]!= '3') {
			strcpy(tmpBuf, strInvdMode);
			goto setErr_wlan;
		}
		mode = strVal[0] - '0';

#ifdef WLAN_CLIENT
		if (mode == CLIENT_MODE) {
			WIFI_SECURITY_T encrypt;

			vChar = Entry.encrypt;
			encrypt = (WIFI_SECURITY_T)vChar;
			if (encrypt == WIFI_SEC_WPA || encrypt == WIFI_SEC_WPA2) {
				vChar = Entry.wpaAuth;
				if (vChar & 1) { // radius
					strcpy(tmpBuf, strSetWPAWarn);
					goto setErr_wlan;
				}
			}
			else if (encrypt == WIFI_SEC_WEP) {
				vChar = Entry.enable1X;
				if (vChar & 1) {
					strcpy(tmpBuf, strSetWEPWarn);
					goto setErr_wlan;
				}
			}
			else if (encrypt == WIFI_SEC_WPA2_MIXED) {
				vChar = WIFI_SEC_WPA2;
				Entry.encrypt = vChar;
				strcpy(tmpBuf, "警告! WPA2混合模式不支援client mode <BR> 请改为WPA2加密!"); //Warning! WPA2 Mixed encryption is not supported in client Mode. <BR> Change to WPA2 Encryption.
				warn = 1;
			}
		}
#endif
		Entry.wlanMode = mode;
	}

	strSSID = boaGetVar(wp, "ssid", "");
	
	if ( strSSID[0] ) {
		char real_ssid[64] = "";
#if defined(CONFIG_YUEME)
		sprintf(real_ssid, "%s", strSSID);
#elif defined(CONFIG_CU)
		unsigned char ssidprefix_enable = 0;

		mib_get(MIB_WEB_WLAN_SSIDPREFIX_ENABLE, &ssidprefix_enable);
		if (ssidprefix_enable==1)
			sprintf(real_ssid, "CU_%s", strSSID);
		else
			sprintf(real_ssid, "%s", strSSID);
#elif defined(CONFIG_CMCC)
		unsigned char ssidprefix_enable = 0;

		mib_get(MIB_WEB_WLAN_SSIDPREFIX_ENABLE, &ssidprefix_enable);
		if (ssidprefix_enable==1)
			sprintf(real_ssid, "CMCC-%s", strSSID);
		else
			sprintf(real_ssid, "%s", strSSID);
#else
		sprintf(real_ssid, "ChinaNet-%s", strSSID);
#endif
		strcpy(Entry.ssid, real_ssid);
	}
	//else if ( mode == 1 && !strSSID[0] ) { // client and NULL SSID
	//	if ( mib_set(MIB_WLAN_SSID, (void *)strSSID) == 0) {
   	// 			strcpy(tmpBuf, strSetSSIDErr);
	//			goto setErr_wlan;
	//	}
	//}

#ifdef CONFIG_YUEME
	if(ssidIdx==0)
#endif
	{
		strChan = boaGetVar(wp, "chan", "");
		if ( strChan[0] ) {
			errno=0;
			chan = strtol( strChan, (char **)NULL, 10);
			if (errno) {
	   			strcpy(tmpBuf, strInvdChanNum);
				goto setErr_wlan;
			}
			if(chan != 0)
			{
				vChar = 0;	//disable auto channel
				if ( mib_set( MIB_WLAN_CHAN_NUM, (void *)&chan) == 0) {
					strcpy(tmpBuf, strSetChanErr);
					goto setErr_wlan;
				}
			}
			else
				vChar = 1;	//enable auto channel

			if ( mib_set( MIB_WLAN_AUTO_CHAN_ENABLED, (void *)&vChar) == 0) {
				strcpy(tmpBuf, strSetChanErr);
				goto setErr_wlan;
			}
		}
	}
#if 0// defined(WLAN0_5G_SUPPORT) || defined(WLAN1_5G_SUPPORT)
	{
		char band2G5GSelect = 0;
		char band_no, band_val;
		strVal = boaGetVar(wp, "Band2G5GSupport", "");
		if(strVal[0])
		{
			band2G5GSelect = atoi(strVal);
			printf("band2G5GSelect = %d\n", band2G5GSelect);
		}
		strVal = boaGetVar(wp, "band", "");
		if(strVal[0])
		{
			band_no = atoi(strVal);
			//printf("band_no = %d\n", band_no);
		}
		if(band_no==3 || band_no==11 || band_no==63 || band_no==71 || band_no==75)
			band_val = 2;
		else if(band_no==7)
		{
			band_val = band2G5GSelect;
		}
		else
			band_val = 1;

		if ( mib_set( MIB_WLAN_PHY_BAND_SELECT, (void *)&band_val) == 0) {
			strcpy(tmpBuf, ("Set band error!"));
			goto setErr_wlan;
		}
	}
#endif

	char *strRate;
	unsigned short val;

	strVal = boaGetVar(wp, "band", "");
	if ( strVal[0] ) {
		mode = atoi(strVal);
		mode++;

#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		if(ssidIdx == 2)
			RootEntry.wlanBand = mode;
#endif

		update_on_band_changed(&Entry, 0, mode);
#ifdef CONFIG_YUEME
	if(ssidIdx==0)
#endif
		update_vap_band(mode); // Update vap band based on root band
		
		Entry.wlanBand = mode;
	}
/*
	strRate = boaGetVar(wp, "basicrates", "");
	if ( strRate[0] ) {
		val = atoi(strRate);
		if ( mib_set(MIB_WLAN_BASIC_RATE, (void *)&val) == 0) {
			strcpy(tmpBuf, strSetBaseRateErr);
			goto setErr_wlan;
		}
	}

	strRate = boaGetVar(wp, "operrates", "");
	if ( strRate[0] ) {
		val = atoi(strRate);
		if ( mib_set(MIB_WLAN_SUPPORTED_RATE, (void *)&val) == 0) {
			strcpy(tmpBuf, strSetOperRateErr);
			goto setErr_wlan;
		}
	}
*/
#ifdef CONFIG_YUEME
	if(ssidIdx==0)
#endif
	{
		strVal = boaGetVar(wp, "chanwid", "");            //add by yq_zhou 2.10
		if ( strVal[0] ) {
			int band = mode;
			mode = strVal[0] - '0';
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
			if(mode == 2 && band != 64) //20/40MHz
#else
			if(mode == 2 && band < 64) //20/40MHz
#endif
			{
				mode--;
				vChar = 1;
			}
			else
				vChar = 0;
			if ( mib_set( MIB_WLAN_CHANNEL_WIDTH, (void *)&mode) == 0) {
				strcpy(tmpBuf, strSetChanWidthErr);
				goto setErr_wlan;
			}
			if ( mib_set( MIB_WLAN_11N_COEXIST, (void *)&vChar) == 0) {
				strcpy(tmpBuf, strSet11NCoexistErr);
				goto setErr_wlan;
			}
		}

		strVal = boaGetVar(wp, "ctlband", "");            //add by yq_zhou 2.10
		if ( strVal[0] ) {
			mode = strVal[0] - '0';
			if ( mib_set( MIB_WLAN_CONTROL_BAND, (void *)&mode) == 0) {
				strcpy(tmpBuf, strSetCtlBandErr);
				goto setErr_wlan;
			}
		}
	}

	// set tx rate
	strRate = boaGetVar(wp, "txRate", "");
	if ( strRate[0] ) {
		if ( strRate[0] == '0' ) { // auto
			Entry.rateAdaptiveEnabled = 1;
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
			if(ssidIdx == 2)
				RootEntry.rateAdaptiveEnabled = 1;
#endif
		}
		else  {
			Entry.rateAdaptiveEnabled = 0;
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
			if(ssidIdx == 2)
				RootEntry.rateAdaptiveEnabled = 0;
#endif
			{
				unsigned int uInt;
				uInt = atoi(strRate);
				if(uInt<30)
					uInt = 1 << (uInt-1);
				else
					uInt = ((1 << 31) + (uInt-30));
				
				Entry.fixedTxRate = uInt;
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
				if(ssidIdx == 2)
					RootEntry.fixedTxRate = uInt;
#endif
			}
			strRate = boaGetVar(wp, "basicrates", "");
			if ( strRate[0] ) {
				val = atoi(strRate);
				if ( mib_set(MIB_WLAN_BASIC_RATE, (void *)&val) == 0) {
					strcpy(tmpBuf, strSetBaseRateErr);
					goto setErr_wlan;
				}
			}

			strRate = boaGetVar(wp, "operrates", "");
			if ( strRate[0] ) {
				val = atoi(strRate);
				if ( mib_set(MIB_WLAN_SUPPORTED_RATE, (void *)&val) == 0) {
					strcpy(tmpBuf, strSetOperRateErr);
					goto setErr_wlan;
				}
			}
		}
	}
	else { // set rate in operate, basic sperately
#ifdef WIFI_TEST
		// disable rate adaptive
		Entry.rateAdaptiveEnabled = 0;
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		if(ssidIdx == 2)
			RootEntry.rateAdaptiveEnabled = 0;
#endif

#endif // of WIFI_TEST
	}

#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	strVal = boaGetVar(wp, "beaconInterval", "");
	if (strVal[0]) {
		if ( !string_to_dec(strVal, &vInt) || vInt<20 || vInt>1024) {
			strcpy(tmpBuf, strInvdBeaconIntv);
			goto setErr_wlan;
		}
		uShort = (unsigned short)vInt;
		if ( mib_set(MIB_WLAN_BEACON_INTERVAL, (void *)&uShort) == 0) {
			strcpy(tmpBuf, strSetBeaconIntvErr);
			goto setErr_wlan;
		}
	}

	strVal = boaGetVar(wp, "dtimPeriod", "");
	if (strVal[0]) {
		if ( !string_to_dec(strVal, &vInt) || vInt<1 || vInt>255) {
			strcpy(tmpBuf, strInvdDTIMPerd);
			goto setErr_wlan;
		}
		vChar = (char)vInt;
		if ( mib_set(MIB_WLAN_DTIM_PERIOD, (void *)&vChar) == 0) {
			strcpy(tmpBuf, strSetDTIMErr);
			goto setErr_wlan;
		}
	}
#endif

	// set hidden SSID
	strVal = boaGetVar(wp, "hiddenSSID", "");
	if (!gstrcmp(strVal, "ON"))
		vChar = 1;
	else
		vChar = 0;
	
	Entry.hidessid = vChar;
#if !defined(WLAN_WPS_VAP)
#ifdef CONFIG_WIFI_SIMPLE_CONFIG	
	#ifdef WPS20
	if(vChar && wpsUseVersion != 0){//if hidden, wsc should disable
		Entry.wsc_disabled = vChar;
	}
	#endif
#endif
#endif

#ifdef CONFIG_YUEME
	if(ssidIdx==0)
#endif
	{
		strVal = boaGetVar(wp, "shortGI0", "");
		if (strVal[0]) {
#if defined(CONFIG_CMCC) || defined(CONFIG_YUEME) || defined(CONFIG_CU)
		
			if (strVal[0] == '0')
			{
				vChar = 0;
			}
			else 
			{
				vChar = 1;
			}
#else
			if (!gstrcmp(strVal,"on"))
				vChar = 1;
			else if (!gstrcmp(strVal,"off"))
				vChar = 0;
			else{
				strcpy(tmpBuf, strInvdShortGI0);
				goto setErr_wlan;
			}
#endif
			if (mib_set(MIB_WLAN_SHORTGI_ENABLED,(void *)&vChar) ==0){
				strcpy(tmpBuf, strSetShortGI0Err);
				goto setErr_wlan;
			}
		}
	}
#ifdef WLAN_11K
	strVal = boaGetVar(wp, "dot11kEnabled", "");
	if (strVal[0]) {
		if (strVal[0] == '0')
			Entry.rm_activated = 0;
		else // '1'
			Entry.rm_activated = 1;
	}
#endif
#ifdef WLAN_11V
	strVal = boaGetVar(wp, "dot11vEnabled", "");
	if (strVal[0]) {
		if (strVal[0] == '0')
			Entry.BssTransEnable = 0;
		else // '1'
			Entry.BssTransEnable = 1;
	}
#endif

#if defined(CONFIG_YUEME)
	mib_chain_update(MIB_MBSSIB_TBL, (void *)&Entry, ssidIdx);
#elif defined(CONFIG_CMCC) || defined(CONFIG_CU)
	mib_chain_update(MIB_MBSSIB_TBL, (void *)&Entry, wlmib_idx);
	if(ssidIdx == 2)
		mib_chain_update(MIB_MBSSIB_TBL, (void *)&RootEntry, 0);
#else
	mib_chain_update(MIB_MBSSIB_TBL, (void *)&Entry, 0);
#endif

#ifdef WLAN_UNIVERSAL_REPEATER
	strVal = boaGetVar(wp, "repeaterEnabled", "");
	mib_chain_get(MIB_MBSSIB_TBL, WLAN_REPEATER_ITF_INDEX, (void *)&repeaterEntry);
	if ( strVal[0] ) {
		vChar=1;
		repeaterEntry.wlanDisabled = 0;
	}
	else {
		vChar=0;
		repeaterEntry.wlanDisabled = 1;
	}
	mib_set( MIB_REPEATER_ENABLED1, (void *)&vChar);

	strVal = boaGetVar(wp, "repeaterSSID", "");
	if ( strVal[0] ) {
		mib_set( MIB_REPEATER_SSID1, (void *)strVal);
		strncpy(repeaterEntry.ssid, strVal, MAX_SSID_LEN);
	}
	mib_chain_update(MIB_MBSSIB_TBL, (void *)&repeaterEntry, WLAN_REPEATER_ITF_INDEX);
#endif

#if defined(CONFIG_CMCC) || defined(CONFIG_YUEME) || defined(CONFIG_CU)
//--------------------------------
// Encrypt
	char *strEncrypt;
	char *strKeyLen, *strFormat, *wepKey, *strAuth;
	int key_index=0, key_i;
	char *strKeySelcted;
	char strbuf_idx[16], strbuf_errmsg1[16], strbuf_errmsg2[16];
	WIFI_SECURITY_T encrypt;
	int enableRS=0, intVal, getPSK=0, len, keyLen;
	SUPP_NONWAP_T suppNonWPA;
	struct in_addr inIp;
	WEP_T wep;
	char key[30];
	AUTH_TYPE_T authType;
	int i;

#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	strVal = boaGetVar(wp, "wpaSSID", "");

	if (strVal[0]) {
		i = strVal[0]-'0';
		if (i<0 || i > NUM_VWLAN_INTERFACE) {
			strcpy(tmpBuf, strNotSuptSSIDType);
			goto setErr_encrypt;
		}

	} else {
		strcpy(tmpBuf, strNoSSIDTypeErr);
		goto setErr_encrypt;
	}

	if (!wlan_getEntry(&Entry, wlmib_idx)){
		strcpy(tmpBuf, strGetMBSSIBTBLErr);
		goto setErr_encrypt;
	}
#endif
#if defined(CONFIG_YUEME)
	i = ssidIdx;
#endif
	strEncrypt = boaGetVar(wp, "security_method", "");
	if (!strEncrypt[0]) {
 		strcpy(tmpBuf, strNoEncryptionErr);
		goto setErr_encrypt;
	}

	encrypt = (WIFI_SECURITY_T) strEncrypt[0] - '0';
	vChar = (char)encrypt;
	Entry.encrypt = vChar;

	if (encrypt == WIFI_SEC_NONE || encrypt == WIFI_SEC_WEP) {

#ifdef WLAN_1x
		strVal = boaGetVar(wp, "use1x", "");
		if ( !gstrcmp(strVal, "ON")) {
			vChar = Entry.wlanMode;
			if (vChar) { // not AP mode
				strcpy(tmpBuf, strSet8021xWarning);
				goto setErr_encrypt;
			}
			vChar = 1;
			enableRS = 1;
		}
		else
			vChar = 0;
		Entry.enable1X = vChar;
#endif

		if (encrypt == WIFI_SEC_WEP) {
	 		WEP_T wep;
			// Mason Yu. 201009_new_security. If wireless do not use 802.1x for wep mode. We should set wep key and Authentication type.
			if ( enableRS != 1 ) {
				// (1) Authentication Type
				strAuth = boaGetVar(wp, "auth_type", "");
				if (strAuth[0]) {
					if ( !gstrcmp(strAuth, "open"))
						authType = AUTH_OPEN;
					else if ( !gstrcmp(strAuth, "shared"))
						authType = AUTH_SHARED;
					else if ( !gstrcmp(strAuth, "both"))
						authType = AUTH_BOTH;
					else {
						strcpy(tmpBuf, strInvdAuthType);
						goto setErr_encrypt;
					}
					vChar = (char)authType;
					Entry.authType = vChar;
				}

				// (2) Key Length
				strKeyLen = boaGetVar(wp, "length0", "");
				if (!strKeyLen[0]) {
 					strcpy(tmpBuf, strKeyLenMustExist);
					goto setErr_encrypt;
				}
				if (strKeyLen[0]!='1' && strKeyLen[0]!='2') {
 					strcpy(tmpBuf, strInvdKeyLen);
					goto setErr_encrypt;
				}
				if (strKeyLen[0] == '1')
					wep = WEP64;
				else
					wep = WEP128;

				vChar = (char)wep;
				Entry.wep = vChar;

				// (3) Key Format
				strFormat = boaGetVar(wp, "format0", "");
				if (!strFormat[0]) {
 					strcpy(tmpBuf, strKeyTypeMustExist);
					goto setErr_encrypt;
				}

				if (strFormat[0]!='1' && strFormat[0]!='2') {
					strcpy(tmpBuf, strInvdKeyType);
					goto setErr_encrypt;
				}

				vChar = (char)(strFormat[0] - '0' - 1);
				Entry.wepKeyType = vChar;

				if (wep == WEP64) {
					if (strFormat[0]=='1')
						keyLen = WEP64_KEY_LEN;
					else
						keyLen = WEP64_KEY_LEN*2;
				}
				else {
					if (strFormat[0]=='1')
						keyLen = WEP128_KEY_LEN;
					else
						keyLen = WEP128_KEY_LEN*2;
				}
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
				// Key selected
				strKeySelcted = boaGetVar(wp, "defaultKeyidx", "");
				if (!strKeySelcted[0]) {
					strcpy(tmpBuf, strKeySelectedMustExist);
					goto setErr_encrypt;
				}
				if (strKeySelcted[0]!='1' && strKeySelcted[0]!='2' && strKeySelcted[0]!='3' && strKeySelcted[0]!='4') {
					strcpy(tmpBuf, strInvdKeySel);
					goto setErr_encrypt;
				}
				if (strKeySelcted[0] == '1')
					key_index = 0;
				else if (strKeySelcted[0] == '2')
					key_index = 1;
				else if (strKeySelcted[0] == '3')
					key_index = 2;
				else
					key_index = 3;
#else
				key_index = 0;
#endif
				Entry.wepDefaultKey = key_index;

				// (4) Encryption Key
				//
				for (key_i=0; key_i<4; key_i++)
				{
					sprintf(strbuf_idx, "key%d", key_i);
					sprintf(strbuf_errmsg1, "strInvdKey%dLen", key_i+1);
					sprintf(strbuf_errmsg2, "strInvdWEPKey%d", key_i+1);

					wepKey = boaGetVar(wp, strbuf_idx, "");
				
					if  (wepKey[0]) {
						if (strlen(wepKey) != keyLen) {
							strcpy(tmpBuf, strbuf_errmsg1);
							goto setErr_encrypt;
						}
						if ( !isAllStar(wepKey) ) {
							if (strFormat[0] == '1') // ascii
								strcpy(key, wepKey);
							else { // hex
								if ( !string_to_hex(wepKey, key, keyLen)) {
									strcpy(tmpBuf, strbuf_errmsg2);
									goto setErr_encrypt;
								}
							}
							if (wep == WEP64)
							{
								switch(key_i)
								{
									case 0:
										memcpy(Entry.wep64Key1, key, WEP64_KEY_LEN);
										break;
									case 1:
										memcpy(Entry.wep64Key2, key, WEP64_KEY_LEN);
										break;
									case 2:
										memcpy(Entry.wep64Key3, key, WEP64_KEY_LEN);
										break;
									case 3:
										memcpy(Entry.wep64Key4, key, WEP64_KEY_LEN);
										break;
								}
							}
							else
							{
								switch(key_i)
								{
									case 0:
										memcpy(Entry.wep128Key1, key, WEP128_KEY_LEN);
										break;
									case 1:
										memcpy(Entry.wep128Key2, key, WEP128_KEY_LEN);
										break;
									case 2:
										memcpy(Entry.wep128Key3, key, WEP128_KEY_LEN);
										break;
									case 3:
										memcpy(Entry.wep128Key4, key, WEP128_KEY_LEN);
										break;
								}
							}
						}
					}
				}// (4) Encryption Key
			}
#if !defined(WLAN_WPS_VAP)
#ifdef CONFIG_WIFI_SIMPLE_CONFIG
			#ifdef WPS20
			if (0 == i && wpsUseVersion != 0) {
				Entry.wsc_disabled = 1;
			}
			#endif
#endif
#endif
		}
	}
#ifdef CONFIG_RTL_WAPI_SUPPORT
	/* assume MBSSID for now. */
	else if (encrypt == WIFI_SEC_WAPI) {
		char *wapiAuth=0, *pskFormat=0, *pskValue=0;
		unsigned char asIP[IP_ADDR_LEN]={0}, wapiType=0;
		int len;
		//fprintf(stderr, "%s(%d):\n", __FUNCTION__,__LINE__);
		wapiAuth = boaGetVar(wp, "wapiAuth", "");

		if (wapiAuth[0] == '1') {
			wapiType = 1;
			//asIP = boaGetVar(wp, "radiusIP", "");
			//fprintf(stderr, "%s(%d): %p\n", __FUNCTION__,__LINE__, asIP);
		}
		else if (wapiAuth[0] == '2') {
			wapiType = 2;
			pskFormat = boaGetVar(wp, "wapipskFormat", "");
			pskValue = boaGetVar(wp, "wapipskValue", "");
			len = strlen(pskValue);
		}
		else {
			strcpy(tmpBuf, strInvdWPAAuthValue);
			goto setErr_encrypt;
		}


		//fprintf(stderr, "%s(%d):\n", __FUNCTION__,__LINE__);
		if (0 == i) {

			Entry.wapiAuth = wapiType;
			if (wapiType == 2) { // PSK
				vChar = pskFormat[0] - '0';
				if (vChar != 0 && vChar != 1) {
					strcpy(tmpBuf, strInvdPSKFormat);
					goto setErr_encrypt;
				}
				Entry.wapiPskFormat = vChar;//mib_set(MIB_WLAN_WAPI_PSK_FORMAT, (void *)&vChar);
				if (vChar == 1) {// hex
					printf("(%s,%d) pskstring:%s\n",__func__,__LINE__,pskValue);
					memset(tmpBuf, 0, sizeof(tmpBuf));
					if (!string_to_hex(pskValue, tmpBuf, len)) {
						strcpy(tmpBuf, strInvdPSKValue);
						printf("(%s,%d) invalid pskvalue\n",__func__,__LINE__);
						goto setErr_encrypt;
					}


					if ((len & 1) || (len/2 >= MAX_PSK_LEN)) {
						strcpy(tmpBuf, strInvdPSKValue);
						goto setErr_encrypt;
					}
					len = len / 2;
					vChar = len;
					Entry.wapiPskLen = vChar;//mib_set(MIB_WLAN_WAPI_PSKLEN, &vChar);
					strcpy(Entry.wapiPsk, tmpBuf);//mib_set(MIB_WLAN_WAPI_PSK, (void *)tmpBuf);

				} else { // passphrase

					if (len==0 || len > (MAX_PSK_LEN - 1)) {
						strcpy(tmpBuf, strInvdPSKValue);
						goto setErr_encrypt;
					}
					vChar = len;
					Entry.wapiPskLen = vChar;//mib_set(MIB_WLAN_WAPI_PSKLEN, &vChar);
					strcpy(Entry.wapiPsk, pskValue);//mib_set(MIB_WLAN_WAPI_PSK, (void *)pskValue);

				}

			} else { // AS
				if ( !mib_get(MIB_ADSL_LAN_IP, (void *)&inIp) ) {
					strcpy(tmpBuf, strInvdRSIPValue);
					goto setErr_encrypt;
				}
				*((unsigned long *)Entry.wapiAsIpAddr) = inIp.s_addr;
			}

		} else {
			//fprintf(stderr, "%s(%d):\n", __FUNCTION__,__LINE__);
			mib_set(MIB_WLAN_WAPI_AUTH, (void *)&wapiType);
			if (wapiType == 2) { // PSK
				vChar = pskFormat[0] - '0';
				if (vChar != 0 && vChar != 1) {
					strcpy(tmpBuf, strInvdPSKFormat);
					goto setErr_encrypt;
				}
				mib_set(MIB_WLAN_WAPI_PSK_FORMAT, (void *)&vChar);
				if (vChar == 1) {// hex
					if (!string_to_hex(pskValue, tmpBuf, MAX_PSK_LEN)) {
						strcpy(tmpBuf, strInvdPSKValue);
						goto setErr_encrypt;
					}
					//fprintf(stderr, "%s(%d): %08x%08x%08x%08x\n",
					//	__FUNCTION__,__LINE__, (long *)&pskValue[0],
					//	(long *)&pskValue[4],(long *)&pskValue[8],(long *)&pskValue[12]);
					if ((len & 1) || (len/2 >= MAX_PSK_LEN)) {
						strcpy(tmpBuf, strInvdPSKValue);
						goto setErr_encrypt;
					}
					len = len / 2;
					vChar = len;
					mib_set(MIB_WLAN_WAPI_PSKLEN, &vChar);
					mib_set(MIB_WLAN_WAPI_PSK, (void *)pskValue);

				} else { // passphrase

					if (len==0 || len > (MAX_PSK_LEN - 1)) {
						strcpy(tmpBuf, strInvdPSKValue);
						goto setErr_encrypt;
					}
					vChar = len;
					mib_set(MIB_WLAN_WAPI_PSKLEN, &vChar);
					mib_set(MIB_WLAN_WAPI_PSK, (void *)pskValue);

				}

			} else { // AS
				//fprintf(stderr, "%s(%d):\n", __FUNCTION__,__LINE__);
				if ( !inet_aton(asIP, &inIp) ) {
					strcpy(tmpBuf, strInvdRSIPValue);
					goto setErr_encrypt;
				}
				//fprintf(stderr, "%s(%d):\n", __FUNCTION__,__LINE__);
				mib_set(MIB_WLAN_WAPI_ASIPADDR, (void *)&inIp);
			}


		}
	}
#endif 	// CONFIG_RTL_WAPI_SUPPORT
	else {	// WPA
#ifdef WPS20
		unsigned char disableWps = 0;
#endif //WPS20
#ifdef WLAN_1x
		// WPA authentication
		vChar = 0;
		Entry.enable1X = vChar;

		strVal = boaGetVar(wp, "wpaAuth", "");
		if (strVal[0]) {
			if ( !gstrcmp(strVal, "eap")) {
				vChar = Entry.wlanMode;
				if (vChar) { // not AP mode
					strcpy(tmpBuf, strSetWPARADIUSWarn);
					goto setErr_encrypt;
				}
				vChar = WPA_AUTH_AUTO;
				enableRS = 1;
			}
			else if ( !gstrcmp(strVal, "psk")) {
				vChar = WPA_AUTH_PSK;
				getPSK = 1;
			}
			else {
				strcpy(tmpBuf, strInvdWPAAuthValue);
				goto setErr_encrypt;
			}
			Entry.wpaAuth = vChar;
		}
#endif

		// Mason Yu. 201009_new_security. Set ciphersuite(wpa_cipher) for wpa/wpa mixed
		if ((encrypt == WIFI_SEC_WPA) || (encrypt == WIFI_SEC_WPA2_MIXED)) {
			unsigned char intVal = 0;
			unsigned char val2;

			strVal = boaGetVar(wp, "ciphersuite", ""); 
			if (strVal[0]) {
				if (strVal[0] == '1') 
				{    
					intVal |= WPA_CIPHER_TKIP;
				}    
				else if (strVal[0] == '2') 
				{    
					intVal |= WPA_CIPHER_AES;
				}    
				else if (strVal[0] == '3') 
				{    
					intVal |= WPA_CIPHER_MIXED;
				}    
			}

			if ( intVal == 0 )
				intVal = WPA_CIPHER_TKIP;

				Entry.unicastCipher = intVal;

			if(i==0){
				#ifdef WPS20
				if ((encrypt == WIFI_SEC_WPA) ||
					(encrypt == WIFI_SEC_WPA2_MIXED && intVal == WPA_CIPHER_TKIP)) {	//disable wps if wpa only or tkip only
					disableWps = 1;
				}
				#endif
			}
		}

		// Mason Yu. 201009_new_security. Set wpa2ciphersuite(wpa2_cipher) for wpa2/wpa mixed
		if ((encrypt == WIFI_SEC_WPA2) || (encrypt == WIFI_SEC_WPA2_MIXED)) {
			unsigned char intVal = 0;

			strVal = boaGetVar(wp, "wpa2ciphersuite", ""); 
			if (strVal[0]) 
			{
				if (strVal[0] == '1') 
				{    
					intVal |= WPA_CIPHER_TKIP;
				}    
				else if (strVal[0] == '2') 
				{    
					intVal |= WPA_CIPHER_AES;
				}    
				else if (strVal[0] == '3') 
				{    
					intVal |= WPA_CIPHER_MIXED;
				}    
			}

			if ( intVal == 0 )
				intVal = WPA_CIPHER_AES;

			Entry.wpa2UnicastCipher = intVal;

			if(i == 0){
				#ifdef WPS20
				if (encrypt == WIFI_SEC_WPA2) {
					if (intVal == WPA_CIPHER_TKIP)
						disableWps = 1;
				}
				else { // mixed
					if (intVal == WPA_CIPHER_TKIP && disableWps)	//disable wps if wpa2 mixed + tkip only
						disableWps = 1;
					else
						disableWps = 0;
				}
				#endif //WPS20
			}
		}
#if !defined(WLAN_WPS_VAP)
#ifdef CONFIG_WIFI_SIMPLE_CONFIG
		#ifdef WPS20
		if (disableWps && wpsUseVersion != 0) {
			Entry.wsc_disabled = 1;
		}
		#endif //WPS20
#endif
#endif
		// pre-shared key
		if ( getPSK ) {
			
			strVal = boaGetVar(wp, "pskFormat", "");
			if (!strVal[0]) {
	 			strcpy(tmpBuf, strNoPSKFormat);
				goto setErr_encrypt;
			}
			vChar = strVal[0] - '0';
			
			//vChar = 0;
			if (vChar != 0 && vChar != 1) {
	 			strcpy(tmpBuf, strInvdPSKFormat);
				goto setErr_encrypt;
			}

			strVal = boaGetVar(wp, "pskValue", "");
			len = strlen(strVal);
			Entry.wpaPSKFormat = vChar;

			if (vChar==1) { // hex
				if (len!=MAX_PSK_LEN || !string_to_hex(strVal, tmpBuf, MAX_PSK_LEN)) {
	 				strcpy(tmpBuf, strInvdPSKValue);
					goto setErr_encrypt;
				}
			}
			else { // passphras
				if (len==0 || len > (MAX_PSK_LEN - 1) ) {
	 				strcpy(tmpBuf, strInvdPSKValue);
					goto setErr_encrypt;
				}
			}
			strcpy(Entry.wpaPSK, strVal);
			
		}
	}
#ifdef WLAN_1x
	if (enableRS == 1) { // if 1x enabled, get RADIUS server info
		unsigned short uShort;

		strVal = boaGetVar(wp, "radiusPort", "");
		if (!strVal[0]) {
			strcpy(tmpBuf, "没有RS端口数值!"); //No RS port number!
			goto setErr_encrypt;
		}
		if (!string_to_dec(strVal, &intVal) || intVal<=0 || intVal>65535) {
			strcpy(tmpBuf, strInvdRSPortNum);
			goto setErr_encrypt;
		}
		uShort = (unsigned short)intVal;
		Entry.rsPort = uShort;

		strVal = boaGetVar(wp, "radiusIP", "");
		if (!strVal[0]) {
			strcpy(tmpBuf, strNoIPAddr);
			goto setErr_encrypt;
		}
		if ( !inet_aton(strVal, &inIp) ) {
			strcpy(tmpBuf, strInvdRSIPValue);
			goto setErr_encrypt;
		}
		*((unsigned long *)Entry.rsIpAddr) = inIp.s_addr;

		strVal = boaGetVar(wp, "radiusPass", "");
		if (strlen(strVal) > (MAX_PSK_LEN) ) {
			strcpy(tmpBuf, strRSPwdTooLong);
			goto setErr_encrypt;
		}
		strcpy(Entry.rsPassword, strVal);

		strVal = boaGetVar(wp, "radiusRetry", "");
		if (strVal[0]) {
			if ( !string_to_dec(strVal, &intVal) ) {
				strcpy(tmpBuf, strInvdRSRetry);
				goto setErr_encrypt;
			}
			vChar = (char)intVal;
			if ( !mib_set(MIB_WLAN_RS_RETRY, (void *)&vChar)) {
				strcpy(tmpBuf, strSetRSRETRYErr);
				goto setErr_encrypt;
			}
		}
		strVal = boaGetVar(wp, "radiusTime", "");
		if (strVal[0]) {
			if ( !string_to_dec(strVal, &intVal) ) {
				strcpy(tmpBuf, strInvdRSTime);
				goto setErr_encrypt;
			}
			uShort = (unsigned short)intVal;
			if ( !mib_set(MIB_WLAN_RS_INTERVAL_TIME, (void *)&uShort)) {
				strcpy(tmpBuf, strSetRSINTVLTIMEErr);
				goto setErr_encrypt;
			}
		}

get_wepkey:
		// get 802.1x WEP key length
		strVal = boaGetVar(wp, "wepKeyLen", "");
		if (strVal[0]) {
			if ( !gstrcmp(strVal, "wep64"))
				vChar = WEP64;
			else if ( !gstrcmp(strVal, "wep128"))
				vChar = WEP128;
			else {
				strcpy(tmpBuf, strInvdWepKeyLen);
				goto setErr_encrypt;
			}
			Entry.wep = vChar;
		}
	}
#endif

#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	wlan_setEntry(&Entry, wlmib_idx);
#else
	wlan_setEntry(&Entry,i);
#endif

#ifdef CONFIG_YUEME
#if defined(WLAN_DUALBAND_CONCURRENT) && defined(CONFIG_RTL_STA_CONTROL_SUPPORT)
	if(sta_control_change)
		SetOrCancelSameSSID(sta_control);
#endif
#endif

	sleep(5);

#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif // of #if COMMIT_IMMEDIATELY

//---------------------------------
//WPS
#if (defined(CONFIG_CMCC) || defined(CONFIG_CU)) && defined(CONFIG_WIFI_SIMPLE_CONFIG)
	char tmpbuf_wps[200];
	int action, ssididx;
	pid_t pid;
	char *msg = "echo 1> /var/cmcc_wsc_running";

	wlan_getEntry((void *)&Entry, wlmib_idx);

	strVal  = boaGetVar(wp, "action", "");
	action = strVal[0] - '0';
	if(strVal[0] && action!=0)
	{
#ifndef WLAN_WPS_MULTI_DAEMON
		if(wlan_idx==0) 
			ssididx = 1;
		else
			ssididx = 5;
		set_wps_ssid(ssididx);
#endif

		if (Entry.wsc_disabled) {
			Entry.wsc_disabled = 0;
			wlan_setEntry((void *)&Entry, wlmib_idx);
			mib_update(CURRENT_SETTING, CONFIG_MIB_ALL);	// update to flash
			system("echo 1 > /var/wps_start_pbc");
#ifndef NO_ACTION
			run_init_script("bridge");
#endif
		}
		else {
#ifndef WLAN_WPS_MULTI_DAEMON
			if(wlan_idx == 0 )
			{
				system("echo 1 > /var/wps_start_interface0");
			}
			else
			{
				system("echo 1 > /var/wps_start_interface1");

			}
#endif
			va_niced_cmd(_WSC_DAEMON_PROG, 2 , 1 , "-sig_pbc" , getWlanIfName());
		}

		if (action == 1)
		{
			pid = fork();
			if (pid==0)
			{
				start_PBC(msg);
				exit(0);
			}
		}
		else if(action == 2)
		{
			stop_PBC(msg);
		}

		submitUrl = boaGetVar(wp, "submit-url", "");
		boaRedirect(wp, submitUrl);
		return;
	}

	if(wlmib_idx == 0){ //update for root ssid only
		strVal = boaGetVar(wp, "disableWPS", "");
		if ( !strcmp(strVal, "ON") )
		{
			intVal = 0;
		}
		else
		{
			intVal = 1;
		}

		Entry.wsc_disabled = intVal;
		wlan_setEntry((void *)&Entry, wlmib_idx);
		update_wps_mib();

		if(Entry.wsc_disabled == 0){
			strVal = boaGetVar(wp, "localPin", "");
			if (strVal[0]){
				int local_pin_changed = 0;
				char wpin[PIN_LEN+1]={0};
				mib_get(MIB_WSC_PIN, (void *)wpin);
				if (strcmp(wpin, strVal)) {
					mib_set(MIB_WSC_PIN, (void *)strVal);
					local_pin_changed = 1;
#ifdef WLAN_DUALBAND_CONCURRENT
					both_band_modify = 1;
#endif
				}
				#if 0
				if(local_pin_changed){
					if(wlan_idx==0) 
						ssididx = 1;
					else
						ssididx = 5;
					mib_get(MIB_WPS_SSID, &vChar);
					if(vChar != ssididx){
						vChar = ssididx;
						mib_set(MIB_WPS_SSID, &vChar);
					}
				}
				#endif
			}
		}
	}

#endif

#endif

setwlan_ret:
#ifdef CONFIG_WIFI_SIMPLE_CONFIG//WPS def WIFI_SIMPLE_CONFIG
	{
		int ret;
		char *wepKey;
		wepKey = boaGetVar(wp, "wps_clear_configure_by_reg0", "");
		ret = 0;
		if (wepKey && wepKey[0])
			ret = atoi(wepKey);
		update_wps_configured(ret);
	}
#endif
setwlan_module_disable:

submitUrl = boaGetVar(wp, "submit-url", "");   // hidden page

#if defined(CONFIG_RTL_92D_SUPPORT)
if(phyBandSelectChange){
	getMIB2Str(MIB_ADSL_LAN_IP, lan_ip);
	sprintf(tmpBuf,"%s","<h4>Change setting successfully!<BR><BR>Do not turn off or reboot the Device during this time.</h4>");
	OK_MSG_FW(tmpBuf, submitUrl,APPLY_COUNTDOWN_TIME,lan_ip);
}
#endif

// Magician: Commit immediately
#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif // of #if COMMIT_IMMEDIATELY

#ifndef NO_ACTION
	run_script(mode);
#endif

#ifdef CONFIG_YUEME
	if(ssidIdx != 0 && update_all_ssid == 0){
#ifdef WLAN_DUALBAND_CONCURRENT
		config_WLAN(get_wlan_phyband()==PHYBAND_2G? ACT_RESTART_2G: ACT_RESTART_5G, ssidIdx);
#else
		config_WLAN(ACT_RESTART_2G, ssidIdx);
#endif
	}
	else{
#ifdef WLAN_DUALBAND_CONCURRENT
		if(both_band_modify == 0)
			config_WLAN(get_wlan_phyband()==PHYBAND_2G? ACT_RESTART_2G: ACT_RESTART_5G, CONFIG_SSID_ALL);
		else
#endif
		config_WLAN(ACT_RESTART, CONFIG_SSID_ALL);
	}
#endif

#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	if(wlan_idx == 0)
	{
#ifdef WLAN_DUALBAND_CONCURRENT
		if(both_band_modify==1)
			config_WLAN(ACT_RESTART, CONFIG_SSID_ALL);
		else
#endif
#ifndef WLAN_DUALBAND_CONCURRENT
		if(all_ssid_modify==1)
			config_WLAN(ACT_RESTART_2G, CONFIG_SSID_ALL);
		else
#endif
		{
			if(ssidIdx == 2)
			{
				mib_chain_update(MIB_MBSSIB_TBL, (void *)&RootEntry, 0);
				config_WLAN(ACT_RESTART_2G, 0);
			}
			config_WLAN(ACT_RESTART_2G, wlmib_idx);
		}
	}
	else
	{
#ifdef WLAN_DUALBAND_CONCURRENT
		if(both_band_modify==1)
			config_WLAN(ACT_RESTART, CONFIG_SSID_ALL);
		else
#endif	
			config_WLAN(ACT_RESTART_5G, CONFIG_SSID_ALL);
	}
#endif

#if !defined(CONFIG_CMCC) && !defined(CONFIG_YUEME) && !defined(CONFIG_CU)
	config_WLAN(ACT_RESTART, CONFIG_SSID_ALL);
#endif

//	submitUrl = boaGetVar(wp, "submit-url", "");   // hidden page
#if defined(CONFIG_RTL_92D_SUPPORT)
if(!phyBandSelectChange){
#endif
	if (warn) {
		OK_MSG1(tmpBuf, submitUrl);
	}
	else {
		//OK_MSG(submitUrl);
		if (submitUrl[0])
			boaRedirect(wp, submitUrl);
		else
			boaDone(wp, 200);
	}
#if defined(CONFIG_RTL_92D_SUPPORT)
}
#endif
	return;

setErr_wlan:
	ERR_MSG(tmpBuf);

#if defined(CONFIG_CMCC) || defined(CONFIG_YUEME) || defined(CONFIG_CU)
setErr_encrypt:
	ERR_MSG(tmpBuf);
#endif
}

#ifdef CONFIG_RTL_WAPI_SUPPORT

#define CERT_START "-----BEGIN CERTIFICATE-----"
#define CERT_END "-----END CERTIFICATE-----"
extern FILE * _uploadGet(request *wp, unsigned int *startPos, unsigned *endPos);
static void formUploadWapiCert(request * wp, char * path, char * query,
	const char *name, const char *submitUrl)
{
	/*save asu and user cert*/
	char *strVal;
	char tmpBuf[128];
	char cmd[128];
	FILE *fp, *fp_input;
	int startPos,endPos,nLen,nRead,nToRead;

	if ((fp_input = _uploadGet(wp, &startPos, &endPos)) == NULL) {
		strcpy(tmpBuf,"Upload failed");
		goto upload_ERR;
	}

	//fprintf(stderr, "%s(%d): %s,%s (%d,%d)\n", __FUNCTION__,__LINE__,
	//	 submitUrl, strVal, startPos, endPos);

	nLen = endPos - startPos;
	fseek(fp_input, startPos, SEEK_SET); // seek to the data star

	fp=fopen(WAPI_TMP_CERT,"w");
	if(NULL == fp)
	{
		strcpy(tmpBuf,"Can not open tmp cert!");
		goto upload_ERR;
	}

	/* copy startPos - endPost to another file */
	nToRead = nLen;
	do {
		nRead = nToRead > sizeof(tmpBuf) ? sizeof(tmpBuf) : nToRead;

		nRead = fread(tmpBuf, 1, nRead, fp_input);
		fwrite(tmpBuf, 1, nRead, fp);
		nToRead -= nRead;
	} while (nRead > 0);

	fclose(fp);
	fclose(fp_input);

	strcpy(cmd,"mv ");
	strcat(cmd,WAPI_TMP_CERT);
	strcat(cmd," ");
	strcat(cmd,name);
	system(cmd);
//ccwei_flatfsd
#ifdef CONFIG_USER_FLATFSD_XXX
	strcpy(cmd, "flatfsd -s");
	system(cmd);
#endif
	/*strcpy(cmd, "ln -s ");
	strcat(cmd, name);
	strcat(cmd," ");
	strcat(cmd, lnname);
	system(cmd); */


	config_WLAN(ACT_RESTART, CONFIG_SSID_ALL);

	//fprintf(stderr, "%s(%d):cmd \"%s\"\n", __FUNCTION__,__LINE__,cmd);
	/*check if user or asu cerification*/
	strcpy(tmpBuf,"Cerification Install Success!");
	//OK_MSG1(tmpBuf, submitUrl);
	OK_MSG(submitUrl);
	return;
upload_ERR:
	ERR_MSG(tmpBuf);
}



void formUploadWapiCert1(request * wp, char * path, char * query)
{
	formUploadWapiCert(wp, path, query, WAPI_CA4AP_CERT_SAVE, "/wlwapiinstallcert.asp");
	wapi_cert_link_one(WAPI_CA4AP_CERT_SAVE, WAPI_CA4AP_CERT);
}

void formUploadWapiCert2(request * wp, char * path, char * query)
{
	formUploadWapiCert(wp, path, query, WAPI_AP_CERT_SAVE, "/wlwapiinstallcert.asp");
	wapi_cert_link_one(WAPI_AP_CERT_SAVE, WAPI_AP_CERT);
}

void formWapiReKey(request * wp, char * path, char * query)
{
	char *submitUrl, *strVal;
	char vChar;
	int vLong, ret;
	char tmpBuf[128];

	submitUrl = boaGetVar(wp, "submit-url", "");

	strVal = boaGetVar(wp, "REKEY_POLICY", "");
	//fprintf(stderr, "%s(%d): %s\n",__FUNCTION__,__LINE__, strVal);
	if (strVal[0]) {
		vChar=strVal[0]-'0';
		ret = mib_set(MIB_WLAN_WAPI_UCAST_REKETTYPE,(void *)&vChar);
		//fprintf(stderr, "%s(%d): %d, %d\n",__FUNCTION__,__LINE__, vChar, ret);
		if (vChar!=1) {
			strVal = boaGetVar(wp, "REKEY_TIME", "");
			if (strVal[0]) {
				vLong = atoi(strVal);
				ret = mib_set(MIB_WLAN_WAPI_UCAST_TIME,(void *)&vLong);
				//fprintf(stderr, "%s(%d): %s,%d\n",__FUNCTION__,__LINE__, strVal,ret);
			}
			strVal = boaGetVar(wp, "REKEY_PACKET", "");
			if (strVal[0]) {
				vLong = atoi(strVal);
				ret = mib_set(MIB_WLAN_WAPI_UCAST_PACKETS,(void *)&vLong);
				//fprintf(stderr, "%s(%d): %s,%d\n",__FUNCTION__,__LINE__, strVal,ret);
			}
		}
	}

	strVal = boaGetVar(wp, "REKEY_M_POLICY", "");
	if (strVal[0]) {
		vChar=strVal[0]-'0';
		mib_set(MIB_WLAN_WAPI_MCAST_REKEYTYPE,(void *)&vChar);

		if (vChar!=1) {
			strVal = boaGetVar(wp, "REKEY_M_TIME", "");
			if (strVal[0]) {
				vLong = atoi(strVal);
				mib_set(MIB_WLAN_WAPI_MCAST_TIME,(void *)&vLong);
			}

			strVal = boaGetVar(wp, "REKEY_M_PACKET", "");
			if (strVal[0]) {
				vLong = atoi(strVal);
				mib_set(MIB_WLAN_WAPI_MCAST_PACKETS,(void *)&vLong);
			}
		}
	}
#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif

	config_WLAN(ACT_RESTART, CONFIG_SSID_ALL);

	OK_MSG(submitUrl);
	return;

upload_ERR:
	ERR_MSG(tmpBuf);
}



#endif //CONFIG_RTL_WAPI_SUPPORT

//#define testWEP 1
#ifdef WLAN_WPA
/////////////////////////////////////////////////////////////////////////////
void formWlEncrypt(request * wp, char *path, char *query)
{
	char *submitUrl, *strEncrypt, *strVal;
	char vChar, *strKeyLen, *strFormat, *wepKey, *strAuth;
	char tmpBuf[100];
	WIFI_SECURITY_T encrypt;
	int enableRS=0, intVal, getPSK=0, len, keyLen;
	SUPP_NONWAP_T suppNonWPA;
	struct in_addr inIp;
	WEP_T wep;
	char key[30];
	AUTH_TYPE_T authType;
	MIB_CE_MBSSIB_T Entry;
	int i;
#ifdef CONFIG_YUEME
#if defined(WLAN_DUALBAND_CONCURRENT) && defined(CONFIG_RTL_STA_CONTROL_SUPPORT)
	unsigned char sta_control;
#endif
#endif
#if defined(CONFIG_RTL_92D_SUPPORT) || defined(WLAN_DUALBAND_CONCURRENT)
	strVal = boaGetVar(wp, "wlan_idx", "");
	if ( strVal[0] ) {
		printf("wlan_idx=%d\n", strVal[0]-'0');
		wlan_idx = strVal[0]-'0';
	}
#endif //CONFIG_RTL_92D_SUPPORT || WLAN_DUALBAND_CONCURRENT

	strVal = boaGetVar(wp, "wpaSSID", "");

	if (strVal[0]) {
		i = strVal[0]-'0';
		if (i<0 || i > NUM_VWLAN_INTERFACE) {
			strcpy(tmpBuf, strNotSuptSSIDType);
			goto setErr_encrypt;
		}

	} else {
		strcpy(tmpBuf, strNoSSIDTypeErr);
		goto setErr_encrypt;
	}

	if (!wlan_getEntry(&Entry, i)){
		strcpy(tmpBuf, strGetMBSSIBTBLErr);
		goto setErr_encrypt;
	}
	// Added by Mason Yu. End
	/*
	printf("Entry.idx=%d\n", Entry.idx);
	printf("Entry.encrypt=%d\n", Entry.encrypt);
	printf("Entry.enable1X=%d\n", Entry.enable1X);
	printf("Entry.wep=%d\n", Entry.wep);
	printf("Entry.wpaAuth=%d\n", Entry.wpaAuth);
	printf("Entry.wpaPSKFormat=%d\n", Entry.wpaPSKFormat);
	printf("Entry.wpaPSK=%s\n", Entry.wpaPSK);
	printf("Entry.rsPort=%d\n", Entry.rsPort);
	printf("Entry.rsIpAddr=0x%x\n", *((unsigned long *)Entry.rsIpAddr));
	printf("Entry.rsPassword=%s\n", Entry.rsPassword);
	*/

	strEncrypt = boaGetVar(wp, "security_method", "");
	if (!strEncrypt[0]) {
 		strcpy(tmpBuf, strNoEncryptionErr);
		goto setErr_encrypt;
	}

	encrypt = (WIFI_SECURITY_T) strEncrypt[0] - '0';
	vChar = (char)encrypt;
	Entry.encrypt = vChar;

	if (encrypt == WIFI_SEC_NONE || encrypt == WIFI_SEC_WEP) {

#ifdef WLAN_1x
		strVal = boaGetVar(wp, "use1x", "");
		if ( !gstrcmp(strVal, "ON")) {
			vChar = Entry.wlanMode;
			if (vChar) { // not AP mode
				strcpy(tmpBuf, strSet8021xWarning);
				goto setErr_encrypt;
			}
			vChar = 1;
			enableRS = 1;
		}
		else
			vChar = 0;
		Entry.enable1X = vChar;
#endif

		if (encrypt == WIFI_SEC_WEP) {
	 		WEP_T wep;
			// Mason Yu. 201009_new_security. If wireless do not use 802.1x for wep mode. We should set wep key and Authentication type.
			if ( enableRS != 1 ) {
				// (1) Authentication Type
				strAuth = boaGetVar(wp, "auth_type", "");
				if (strAuth[0]) {
					if ( !gstrcmp(strAuth, "open"))
						authType = AUTH_OPEN;
					else if ( !gstrcmp(strAuth, "shared"))
						authType = AUTH_SHARED;
					else if ( !gstrcmp(strAuth, "both"))
						authType = AUTH_BOTH;
					else {
						strcpy(tmpBuf, strInvdAuthType);
						goto setErr_encrypt;
					}
					vChar = (char)authType;
					Entry.authType = vChar;
				}

				// (2) Key Length
				strKeyLen = boaGetVar(wp, "length0", "");
				if (!strKeyLen[0]) {
 					strcpy(tmpBuf, strKeyLenMustExist);
					goto setErr_encrypt;
				}
				if (strKeyLen[0]!='1' && strKeyLen[0]!='2') {
 					strcpy(tmpBuf, strInvdKeyLen);
					goto setErr_encrypt;
				}
				if (strKeyLen[0] == '1')
					wep = WEP64;
				else
					wep = WEP128;

				vChar = (char)wep;
				Entry.wep = vChar;

				// (3) Key Format
				strFormat = boaGetVar(wp, "format0", "");
				if (!strFormat[0]) {
 					strcpy(tmpBuf, strKeyTypeMustExist);
					goto setErr_encrypt;
				}

				if (strFormat[0]!='1' && strFormat[0]!='2') {
					strcpy(tmpBuf, strInvdKeyType);
					goto setErr_encrypt;
				}

				vChar = (char)(strFormat[0] - '0' - 1);
				Entry.wepKeyType = vChar;

				if (wep == WEP64) {
					if (strFormat[0]=='1')
						keyLen = WEP64_KEY_LEN;
					else
						keyLen = WEP64_KEY_LEN*2;
				}
				else {
					if (strFormat[0]=='1')
						keyLen = WEP128_KEY_LEN;
					else
						keyLen = WEP128_KEY_LEN*2;
				}

				// (4) Encryption Key
				wepKey = boaGetVar(wp, "key0", "");
				if  (wepKey[0]) {
					if (strlen(wepKey) != keyLen) {
						strcpy(tmpBuf, strInvdKey1Len);
						goto setErr_encrypt;
					}
					if ( !isAllStar(wepKey) ) {
						if (strFormat[0] == '1') // ascii
							strcpy(key, wepKey);
						else { // hex
							if ( !string_to_hex(wepKey, key, keyLen)) {
				   				strcpy(tmpBuf, strInvdWEPKey1);
								goto setErr_encrypt;
							}
						}
						if (wep == WEP64)
							memcpy(Entry.wep64Key1,key,WEP64_KEY_LEN);
						else
							memcpy(Entry.wep128Key1,key,WEP128_KEY_LEN);
					}
				}// (4) Encryption Key


			}
#ifdef CONFIG_WIFI_SIMPLE_CONFIG
			#ifdef WPS20
			if (0 == i) {
				Entry.wsc_disabled = 1;
			}
			#endif
#endif
		}
	}
#ifdef CONFIG_RTL_WAPI_SUPPORT
	/* assume MBSSID for now. */
	else if (encrypt == WIFI_SEC_WAPI) {
		char *wpaAuth=0, *pskFormat=0, *pskValue=0;
		char *asIP=0, wapiType=0;
		int len;
		//fprintf(stderr, "%s(%d):\n", __FUNCTION__,__LINE__);
		wpaAuth = boaGetVar(wp, "wpaAuth", "");

		if (wpaAuth && !gstrcmp(wpaAuth, "eap")) {
			wapiType = 1;
			asIP = boaGetVar(wp, "radiusIP", "");
			//fprintf(stderr, "%s(%d): %p\n", __FUNCTION__,__LINE__, asIP);
		}
		else if (wpaAuth && !gstrcmp(wpaAuth, "psk")) {
			wapiType = 2;
			pskFormat = boaGetVar(wp, "pskFormat", "");
			pskValue = boaGetVar(wp, "pskValue", "");
			len = strlen(pskValue);
		}
		else {
			strcpy(tmpBuf, strInvdWPAAuthValue);
			goto setErr_encrypt;
		}


		//fprintf(stderr, "%s(%d):\n", __FUNCTION__,__LINE__);
		if (0 != i) {

			Entry.wapiAuth = wapiType;
			if (wapiType == 2) { // PSK
				vChar = pskFormat[0] - '0';
				if (vChar != 0 && vChar != 1) {
					strcpy(tmpBuf, strInvdPSKFormat);
					goto setErr_encrypt;
				}
				Entry.wapiPskFormat = vChar;//mib_set(MIB_WLAN_WAPI_PSK_FORMAT, (void *)&vChar);
				if (vChar == 1) {// hex
					if (!string_to_hex(pskValue, tmpBuf, MAX_PSK_LEN)) {
						strcpy(tmpBuf, strInvdPSKValue);
						goto setErr_encrypt;
					}


					if ((len & 1) || (len/2 >= MAX_PSK_LEN)) {
						strcpy(tmpBuf, strInvdPSKValue);
						goto setErr_encrypt;
					}
					len = len / 2;
					vChar = len;
					Entry.wapiPskLen = vChar;//mib_set(MIB_WLAN_WAPI_PSKLEN, &vChar);
					strcpy(Entry.wapiPsk, tmpBuf);//mib_set(MIB_WLAN_WAPI_PSK, (void *)tmpBuf);

				} else { // passphrase

					if (len==0 || len > (MAX_PSK_LEN - 1)) {
						strcpy(tmpBuf, strInvdPSKValue);
						goto setErr_encrypt;
					}
					vChar = len;
					Entry.wapiPskLen = vChar;//mib_set(MIB_WLAN_WAPI_PSKLEN, &vChar);
					strcpy(Entry.wapiPsk, pskValue);//mib_set(MIB_WLAN_WAPI_PSK, (void *)pskValue);

				}

			} else { // AS

				if ( !inet_aton(asIP, &inIp) ) {
					strcpy(tmpBuf, strInvdRSIPValue);
					goto setErr_encrypt;
				}
				*((unsigned long *)Entry.wapiAsIpAddr) = inIp.s_addr;
			}

		} else {
			//fprintf(stderr, "%s(%d):\n", __FUNCTION__,__LINE__);
			mib_set(MIB_WLAN_WAPI_AUTH, (void *)&wapiType);
			if (wapiType == 2) { // PSK
				vChar = pskFormat[0] - '0';
				if (vChar != 0 && vChar != 1) {
					strcpy(tmpBuf, strInvdPSKFormat);
					goto setErr_encrypt;
				}
				mib_set(MIB_WLAN_WAPI_PSK_FORMAT, (void *)&vChar);
				if (vChar == 1) {// hex
					if (!string_to_hex(pskValue, tmpBuf, MAX_PSK_LEN)) {
						strcpy(tmpBuf, strInvdPSKValue);
						goto setErr_encrypt;
					}
					//fprintf(stderr, "%s(%d): %08x%08x%08x%08x\n",
					//	__FUNCTION__,__LINE__, (long *)&pskValue[0],
					//	(long *)&pskValue[4],(long *)&pskValue[8],(long *)&pskValue[12]);
					if ((len & 1) || (len/2 >= MAX_PSK_LEN)) {
						strcpy(tmpBuf, strInvdPSKValue);
						goto setErr_encrypt;
					}
					len = len / 2;
					vChar = len;
					mib_set(MIB_WLAN_WAPI_PSKLEN, &vChar);
					mib_set(MIB_WLAN_WAPI_PSK, (void *)pskValue);

				} else { // passphrase

					if (len==0 || len > (MAX_PSK_LEN - 1)) {
						strcpy(tmpBuf, strInvdPSKValue);
						goto setErr_encrypt;
					}
					vChar = len;
					mib_set(MIB_WLAN_WAPI_PSKLEN, &vChar);
					mib_set(MIB_WLAN_WAPI_PSK, (void *)pskValue);

				}

			} else { // AS
				//fprintf(stderr, "%s(%d):\n", __FUNCTION__,__LINE__);
				if ( !inet_aton(asIP, &inIp) ) {
					strcpy(tmpBuf, strInvdRSIPValue);
					goto setErr_encrypt;
				}
				//fprintf(stderr, "%s(%d):\n", __FUNCTION__,__LINE__);
				mib_set(MIB_WLAN_WAPI_ASIPADDR, (void *)&inIp);
			}


		}
	}
#endif 	// CONFIG_RTL_WAPI_SUPPORT
	else {	// WPA
#ifdef WPS20
		unsigned char disableWps = 0;
#endif //WPS20
#ifdef WLAN_1x
		// WPA authentication
		vChar = 0;
		Entry.enable1X = vChar;

		strVal = boaGetVar(wp, "wpaAuth", "");
		if (strVal[0]) {
			if ( !gstrcmp(strVal, "eap")) {
				vChar = Entry.wlanMode;
				if (vChar) { // not AP mode
					strcpy(tmpBuf, strSetWPARADIUSWarn);
					goto setErr_encrypt;
				}
				vChar = WPA_AUTH_AUTO;
				enableRS = 1;
			}
			else if ( !gstrcmp(strVal, "psk")) {
				vChar = WPA_AUTH_PSK;
				getPSK = 1;
			}
			else {
				strcpy(tmpBuf, strInvdWPAAuthValue);
				goto setErr_encrypt;
			}
			Entry.wpaAuth = vChar;
		}
#endif

		// Mason Yu. 201009_new_security. Set ciphersuite(wpa_cipher) for wpa/wpa mixed
		if ((encrypt == WIFI_SEC_WPA) || (encrypt == WIFI_SEC_WPA2_MIXED)) {
			unsigned char intVal = 0;
			unsigned char val2;
			strVal = boaGetVar(wp, "ciphersuite_t", "");
			if (strVal[0]=='1')
				intVal |= WPA_CIPHER_TKIP;
			strVal = boaGetVar(wp, "ciphersuite_a", "");
			if (strVal[0]=='1')
				intVal |= WPA_CIPHER_AES;

			if ( intVal == 0 )
				intVal = WPA_CIPHER_TKIP;

				Entry.unicastCipher = intVal;

			if(i==0){
				#ifdef WPS20
				if ((encrypt == WIFI_SEC_WPA) ||
					(encrypt == WIFI_SEC_WPA2_MIXED && intVal == WPA_CIPHER_TKIP)) {	//disable wps if wpa only or tkip only
					disableWps = 1;
				}
				#endif
			}
		}

		// Mason Yu. 201009_new_security. Set wpa2ciphersuite(wpa2_cipher) for wpa2/wpa mixed
		if ((encrypt == WIFI_SEC_WPA2) || (encrypt == WIFI_SEC_WPA2_MIXED)) {
			unsigned char intVal = 0;
			strVal = boaGetVar(wp, "wpa2ciphersuite_t", "");
			if (strVal[0]=='1')
				intVal |= WPA_CIPHER_TKIP;
			strVal = boaGetVar(wp, "wpa2ciphersuite_a", "");
			if (strVal[0]=='1')
				intVal |= WPA_CIPHER_AES;

			if ( intVal == 0 )
				intVal = WPA_CIPHER_AES;

			Entry.wpa2UnicastCipher = intVal;

			if(i == 0){
				#ifdef WPS20
				if (encrypt == WIFI_SEC_WPA2) {
					if (intVal == WPA_CIPHER_TKIP)
						disableWps = 1;
				}
				else { // mixed
					if (intVal == WPA_CIPHER_TKIP && disableWps)	//disable wps if wpa2 mixed + tkip only
						disableWps = 1;
					else
						disableWps = 0;
				}
				#endif //WPS20
			}
		}
#ifdef CONFIG_WIFI_SIMPLE_CONFIG
		#ifdef WPS20
		if (disableWps) {
			Entry.wsc_disabled = 1;
		}
		#endif //WPS20
#endif
		// pre-shared key
		if ( getPSK ) {
			
			strVal = boaGetVar(wp, "pskFormat", "");
			if (!strVal[0]) {
	 			strcpy(tmpBuf, strNoPSKFormat);
				goto setErr_encrypt;
			}
			vChar = strVal[0] - '0';
			
			//vChar = 0;
			if (vChar != 0 && vChar != 1) {
	 			strcpy(tmpBuf, strInvdPSKFormat);
				goto setErr_encrypt;
			}

			strVal = boaGetVar(wp, "pskValue", "");
			len = strlen(strVal);
			Entry.wpaPSKFormat = vChar;

			if (vChar==1) { // hex
				if (len!=MAX_PSK_LEN || !string_to_hex(strVal, tmpBuf, MAX_PSK_LEN)) {
	 				strcpy(tmpBuf, strInvdPSKValue);
					goto setErr_encrypt;
				}
			}
			else { // passphras
				if (len==0 || len > (MAX_PSK_LEN - 1) ) {
	 				strcpy(tmpBuf, strInvdPSKValue);
					goto setErr_encrypt;
				}
			}
			strcpy(Entry.wpaPSK, strVal);
			
		}
	}
#ifdef WLAN_1x
	if (enableRS == 1) { // if 1x enabled, get RADIUS server info
		unsigned short uShort;

		strVal = boaGetVar(wp, "radiusPort", "");
		if (!strVal[0]) {
			strcpy(tmpBuf, "没有RS端口数值!"); //No RS port number!
			goto setErr_encrypt;
		}
		if (!string_to_dec(strVal, &intVal) || intVal<=0 || intVal>65535) {
			strcpy(tmpBuf, strInvdRSPortNum);
			goto setErr_encrypt;
		}
		uShort = (unsigned short)intVal;
		Entry.rsPort = uShort;

		strVal = boaGetVar(wp, "radiusIP", "");
		if (!strVal[0]) {
			strcpy(tmpBuf, strNoIPAddr);
			goto setErr_encrypt;
		}
		if ( !inet_aton(strVal, &inIp) ) {
			strcpy(tmpBuf, strInvdRSIPValue);
			goto setErr_encrypt;
		}
		*((unsigned long *)Entry.rsIpAddr) = inIp.s_addr;

		strVal = boaGetVar(wp, "radiusPass", "");
		if (strlen(strVal) > (MAX_PSK_LEN) ) {
			strcpy(tmpBuf, strRSPwdTooLong);
			goto setErr_encrypt;
		}
		strcpy(Entry.rsPassword, strVal);

		strVal = boaGetVar(wp, "radiusRetry", "");
		if (strVal[0]) {
			if ( !string_to_dec(strVal, &intVal) ) {
				strcpy(tmpBuf, strInvdRSRetry);
				goto setErr_encrypt;
			}
			vChar = (char)intVal;
			if ( !mib_set(MIB_WLAN_RS_RETRY, (void *)&vChar)) {
				strcpy(tmpBuf, strSetRSRETRYErr);
				goto setErr_encrypt;
			}
		}
		strVal = boaGetVar(wp, "radiusTime", "");
		if (strVal[0]) {
			if ( !string_to_dec(strVal, &intVal) ) {
				strcpy(tmpBuf, strInvdRSTime);
				goto setErr_encrypt;
			}
			uShort = (unsigned short)intVal;
			if ( !mib_set(MIB_WLAN_RS_INTERVAL_TIME, (void *)&uShort)) {
				strcpy(tmpBuf, strSetRSINTVLTIMEErr);
				goto setErr_encrypt;
			}
		}

get_wepkey:
		// get 802.1x WEP key length
		strVal = boaGetVar(wp, "wepKeyLen", "");
		if (strVal[0]) {
			if ( !gstrcmp(strVal, "wep64"))
				vChar = WEP64;
			else if ( !gstrcmp(strVal, "wep128"))
				vChar = WEP128;
			else {
				strcpy(tmpBuf, strInvdWepKeyLen);
				goto setErr_encrypt;
			}
			Entry.wep = vChar;
		}
	}
#endif

	wlan_setEntry(&Entry,i);

	sleep(5);
	/*
	if (!wlan_getEntry(&Entry,i)) {
 		strcpy(tmpBuf, strGetMBSSIBTBLUpdtErr);
		goto setErr_encrypt;
	}
	
	printf("MIB_MBSSIB_TBL updated\n");
	printf("Entry.idx=%d\n", Entry.idx);
	printf("Entry.encrypt=%d\n", Entry.encrypt);
	printf("Entry.enable1X=%d\n", Entry.enable1X);
	printf("Entry.wep=%d\n", Entry.wep);
	printf("Entry.wpaAuth=%d\n", Entry.wpaAuth);
	printf("Entry.wpaPSKFormat=%d\n", Entry.wpaPSKFormat);
	printf("Entry.wpaPSK=%s\n", Entry.wpaPSK);
	printf("Entry.rsPort=%d\n", Entry.rsPort);
	printf("Entry.rsIpAddr=0x%x\n", *((unsigned long *)Entry.rsIpAddr));
	printf("Entry.rsPassword=%s\n", Entry.rsPassword);
	*/

set_OK:
#ifndef NO_ACTION
	run_script(-1);
#endif
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
#if defined(WLAN_DUALBAND_CONCURRENT) && defined(CONFIG_YUEME)
#if defined(CONFIG_RTL_STA_CONTROL_SUPPORT)
	mib_get(MIB_WIFI_STA_CONTROL, (void *)&sta_control);
	if(sta_control==1 && wlan_idx==0)
		config_WLAN(ACT_RESTART, CONFIG_SSID_ALL);
	else
#endif
		config_WLAN(get_wlan_phyband()==PHYBAND_2G? ACT_RESTART_2G: ACT_RESTART_5G, CONFIG_SSID_ALL);
#else
	config_WLAN(ACT_RESTART, CONFIG_SSID_ALL);
#endif

	submitUrl = boaGetVar(wp, "submit-url", "");   // hidden page
	//OK_MSG(submitUrl);
	if (submitUrl[0])
		boaRedirect(wp, submitUrl);
	else
		boaDone(wp, 200);

	return;

setErr_encrypt:
	ERR_MSG(tmpBuf);
}
#endif // WLAN_WPA

#ifdef WLAN_ACL
/////////////////////////////////////////////////////////////////////////////
int wlAcList(int eid, request * wp, int argc, char **argv)
{
	int nBytesSent=0, entryNum, i;
	MIB_CE_WLAN_AC_T Entry;
	char tmpBuf[100];
#if defined(CONFIG_RTL_92D_SUPPORT) || defined(WLAN_DUALBAND_CONCURRENT)
	char *strVal;
	strVal = boaGetVar(wp, "wlan_idx", "");
	if ( strVal[0] ) {
		printf("wlan_idx=%d\n", strVal[0]-'0');
		wlan_idx = strVal[0]-'0';
	}
#endif //CONFIG_RTL_92D_SUPPORT || WLAN_DUALBAND_CONCURRENT

	entryNum = mib_chain_total(MIB_WLAN_AC_TBL);

	nBytesSent += boaWrite(wp, "<tr>"
      	"<td align=center width=\"45%%\" bgcolor=\"#808080\"><font size=\"2\"><b>%s</b></font></td>\n"
      	"<td align=center width=\"20%%\" bgcolor=\"#808080\"><font size=\"2\"><b>%s</b></font></td></tr>\n", multilang_bpas(strMACAddr), multilang_bpas(strSelect));
	for (i=0; i<entryNum; i++) {
		if (!mib_chain_get(MIB_WLAN_AC_TBL, i, (void *)&Entry))
		{
  			boaError(wp, 400, "Get chain record error!\n");
			return -1;
		}
		if(Entry.wlanIdx != wlan_idx)
			continue;
		snprintf(tmpBuf, 100, "%02x:%02x:%02x:%02x:%02x:%02x",
			Entry.macAddr[0], Entry.macAddr[1], Entry.macAddr[2],
			Entry.macAddr[3], Entry.macAddr[4], Entry.macAddr[5]);

		nBytesSent += boaWrite(wp, "<tr>"
			"<td align=center width=\"45%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
       			"<td align=center width=\"20%%\" bgcolor=\"#C0C0C0\"><input type=\"checkbox\" name=\"select%d\" value=\"ON\"></td></tr>\n",
				tmpBuf, i);
	}
	return nBytesSent;
}

/////////////////////////////////////////////////////////////////////////////
void formWlAc(request * wp, char *path, char *query)
{
	char *strAddMac, *strDelMac, *strDelAllMac, *strVal, *submitUrl, *strEnabled;
	char tmpBuf[100];
	char vChar;
	int entryNum, i, enabled;
	MIB_CE_WLAN_AC_T macEntry;
	MIB_CE_WLAN_AC_T Entry;
//xl_yue
	char * strSetMode;
	strSetMode = boaGetVar(wp, "setFilterMode", "");
	strAddMac = boaGetVar(wp, "addFilterMac", "");
	strDelMac = boaGetVar(wp, "deleteSelFilterMac", "");
	strDelAllMac = boaGetVar(wp, "deleteAllFilterMac", "");
	strEnabled = boaGetVar(wp, "wlanAcEnabled", "");
#if defined(CONFIG_RTL_92D_SUPPORT) || defined(WLAN_DUALBAND_CONCURRENT)
	strVal = boaGetVar(wp, "wlan_idx", "");
	if ( strVal[0] ) {
		printf("wlan_idx=%d\n", strVal[0]-'0');
		wlan_idx = strVal[0]-'0';
	}
#endif //CONFIG_RTL_92D_SUPPORT || WLAN_DUALBAND_CONCURRENT


//xl_yue: access control mode is set independently from adding MAC for 531b
	if (strSetMode[0]) {
		vChar = strEnabled[0] - '0';

		if ( mib_set( MIB_WLAN_AC_ENABLED, (void *)&vChar) == 0) {
  			strcpy(tmpBuf, strEnabAccCtlErr);
			goto setErr_ac;
		}
		goto setac_ret;
	}

	if (strAddMac[0]) {
		int intVal;
		/*
		if ( !gstrcmp(strEnabled, "ON"))
			vChar = 1;
		else
			vChar = 0;
		*/
		strVal = boaGetVar(wp, "mac", "");
		if ( !strVal[0] ) {
//			strcpy(tmpBuf, "Error! No mac address to set.");
			goto setac_ret;
		}

		if (strlen(strVal)!=12 || !string_to_hex(strVal, macEntry.macAddr, 12)) {
			strcpy(tmpBuf, strInvdMACAddr);
			goto setErr_ac;
		}
		if (!isValidMacAddr(macEntry.macAddr)) {
			strcpy(tmpBuf, strInvdMACAddr);
			goto setErr_ac;
		}
		macEntry.wlanIdx = wlan_idx;
/*
		strVal = boaGetVar(wp, "comment", "");
		if ( strVal[0] ) {
			if (strlen(strVal) > COMMENT_LEN-1) {
				strcpy(tmpBuf, "Error! Comment length too long.");
				goto setErr_ac;
			}
			strcpy(macEntry.comment, strVal);
		}
		else
			macEntry.comment[0] = '\0';
*/

		entryNum = mib_chain_total(MIB_WLAN_AC_TBL);
		if ( entryNum >= MAX_WLAN_AC_NUM ) {
			strcpy(tmpBuf, strAddAcErrForFull);
			goto setErr_ac;
		}

		// set to MIB. Check if entry exists
		for (i=0; i<entryNum; i++) {
			if (!mib_chain_get(MIB_WLAN_AC_TBL, i, (void *)&Entry))
			{
	  			strcpy(tmpBuf, "Get chain record error!\n");
				goto setErr_ac;
			}
			if(Entry.wlanIdx != macEntry.wlanIdx)
				continue;
			if (!memcmp(macEntry.macAddr, Entry.macAddr, 6))
			{
				strcpy(tmpBuf, strMACInList);
				goto setErr_ac;
			}
		}

		intVal = mib_chain_add(MIB_WLAN_AC_TBL, (unsigned char*)&macEntry);
		if (intVal == 0) {
			strcpy(tmpBuf, strAddListErr);
			goto setErr_ac;
		}
		else if (intVal == -1) {
			strcpy(tmpBuf, strTableFull);
			goto setErr_ac;
		}
	}

	/* Delete entry */
	if (strDelMac[0]) {
		unsigned int deleted = 0;
		entryNum = mib_chain_total(MIB_WLAN_AC_TBL);
		for (i=entryNum; i>0; i--) {
			if (!mib_chain_get(MIB_WLAN_AC_TBL, i-1, (void *)&Entry))
				break;
			if(Entry.wlanIdx != wlan_idx)
				continue;
			snprintf(tmpBuf, 20, "select%d", i-1);
			strVal = boaGetVar(wp, tmpBuf, "");

			if ( !gstrcmp(strVal, "ON") ) {

				deleted ++;
				if(mib_chain_delete(MIB_WLAN_AC_TBL, i-1) != 1) {
					strcpy(tmpBuf, strDelListErr);
					goto setErr_ac;
				}
			}
		}
		if (deleted <= 0) {
			strcpy(tmpBuf, "没有选择删除的项目!"); //There is no item selected to delete!
			goto setErr_ac;
		}
	}

	/* Delete all entry */
	if ( strDelAllMac[0]) {
		//mib_chain_clear(MIB_WLAN_AC_TBL); /* clear chain record */
		entryNum = mib_chain_total(MIB_WLAN_AC_TBL);
		for (i=entryNum; i>0; i--) {
			if (!mib_chain_get(MIB_WLAN_AC_TBL, i-1, (void *)&Entry)) {
	  			strcpy(tmpBuf, "chain record读取错误!");//Get chain record error!
				goto setErr_ac;
			}
			if(Entry.wlanIdx == wlan_idx) {
				if(mib_chain_delete(MIB_WLAN_AC_TBL, i-1) != 1) {
					strcpy(tmpBuf, strDelListErr);
					goto setErr_ac;
				}
			}
		}
	}

setac_ret:
	config_WLAN(ACT_RESTART, CONFIG_SSID_ALL);
// Magician: Commit immediately
#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif // of #if COMMIT_IMMEDIATELY

#ifndef NO_ACTION
	run_script(-1);
#endif

	submitUrl = boaGetVar(wp, "submit-url", "");   // hidden page
	//OK_MSG( submitUrl );
	if (submitUrl[0])
		boaRedirect(wp, submitUrl);
	else
		boaDone(wp, 200);
  	return;

setErr_ac:
	ERR_MSG(tmpBuf);
}
#endif

// Added by Mason Yu
#ifdef WLAN_MBSSID
int wlmbssid_asp(int eid, request * wp, int argc, char **argv)
{
	char	*string_0[] = {	"Vap0", "Vap1", "Vap2", "Vap3" };
    	char	*string_1[] = { "En_vap0", "En_vap1", "En_vap2", "En_vap3"}; //En_vap(WlanCardIdx)(VAPIdx)
    	char	*string_2[] = { "ssid_v0", "ssid_v1", "ssid_v2", "ssid_v3"};     //ssid_v(WlanCardIdx)(VAPIdx)
    	volatile int	cntLoop, cntwlancard;
    	//uint8	totalWlanCards;

    	//totalWlanCards = pRomeCfgParam->wlaninterCfgParam.totalWlanCards;

	boaWrite(wp,
			"<form method=\"get\" action=\"/boaform/asp_setWlanMBS\" name=userform>\n"\
			"<BR>\n"
	);

	//for (cntwlancard=0; cntwlancard<totalWlanCards; cntwlancard++)
	{

			boaWrite(wp,
				"<table cellSpacing=1 cellPadding=2 border=1>\n"\
				"<tr><td bgColor=bbccff>Wireless Card </td></tr></table>\n"\
				"<table cellSpacing=1 cellPadding=2 border=0>\n"\
				"<tr>\n"
				);


			for(cntLoop=0; cntLoop<MAX_WLAN_VAP; cntLoop++)
			{
				boaWrite(wp,
					"<tr>\n"\
					"<td bgColor=#ddeeff>%s</td>\n",
					string_0[cntLoop]
				);
				/*
				if (pRomeCfgParam->wlanCfgParam[cntwlancard].enable)
				{
					boaWrite(wp,
						"<td bgColor=#ddeeff><input type=checkbox name=%s value=1 %s onClick=\"onload_func();\">Enable</td>\n",
						string_1[cntwlancard*4+cntLoop], pRomeCfgParam->wlanCfgParam[cntwlancard].enable_vap[cntLoop]?"checked":""
					);
				}
				else
				{
					boaWrite(wp,
						"<td bgColor=#ddeeff><input type=checkbox name=%s disabled value=1 %s onClick=\"onload_func();\">Enable</td>\n",
						string_1[cntwlancard*4+cntLoop], pRomeCfgParam->wlanCfgParam[cntwlancard].enable_vap[cntLoop]?"checked":""
					);
				}
				*/
				boaWrite(wp,
						"<td bgColor=#ddeeff><input type=checkbox name=%s value=1 %s onClick=\"onload_func();\">Enable</td>\n",
						string_1[cntLoop], "checked"
					);

				boaWrite(wp,
					"<td bgColor=#aaddff>SSID</td>\n"\
					"<td bgColor=#ddeeff><input type=text name=%s size=16 maxlength=16 value=%s></td>\n"\
					"</tr>\n",
					string_2[cntLoop], "CTC-1q2w"
		            );
			}
	}

	boaWrite(wp,
			"<tr>\n"\
			"<td colspan=2 align=center>\n"\
			"<input type=submit value=Apply>\n"\
	        	"<input type=reset value=Reset>\n"\
			"</td>\n"\
			"</tr>\n"\
			"</table> </form>\n"
	);
}

void formWlanMBSSID(request * wp, char *path, char *query)
{
	char	*str, *submitUrl;
	MIB_CE_MBSSIB_T Entry;
	char tmpBuf[100], en_vap[256];
	int i;
	AUTH_TYPE_T authType;
#ifndef NO_ACTION
	int pid;
#endif
	unsigned char vChar;

#if defined(CONFIG_RTL_92D_SUPPORT) || defined(WLAN_DUALBAND_CONCURRENT)
	str = boaGetVar(wp, "wlan_idx", "");
	if ( str[0] ) {
		printf("wlan_idx=%d\n", str[0]-'0');
		wlan_idx = str[0]-'0';
	}
#endif //CONFIG_RTL_92D_SUPPORT || WLAN_DUALBAND_CONCURRENT

	//for blocking between MBSSID
	sprintf(en_vap, "mbssid_block");
	str = boaGetVar(wp, en_vap, "");
	if (str[0]) {
		if ( !gstrcmp(str, "disable"))
			vChar = 0;
		else
			vChar = 1;

		if ( mib_set(MIB_WLAN_BLOCK_MBSSID, (void *)&vChar) == 0) {
			strcpy(tmpBuf, "set MBSSID error!");
			goto setErr_mbssid;
		}
	}

	for (i=0; i<4; i++) {
		sprintf(en_vap, "En_vap%d", i);
		str = boaGetVar(wp, en_vap, "");
		if ( str && str[0] ) {	// enable
			if (!mib_chain_get(MIB_MBSSIB_TBL, i+1, (void *)&Entry)) {
  				strcpy(tmpBuf, strGetMBSSIBTBLErr);
				goto setErr_mbssid;
			}

			Entry.wlanDisabled = 0;
			mib_chain_update(MIB_MBSSIB_TBL, (void *)&Entry, i+1);
		} else {		// disable
			if (!mib_chain_get(MIB_MBSSIB_TBL, i+1, (void *)&Entry)) {
  				strcpy(tmpBuf, strGetMBSSIBTBLErr);
				goto setErr_mbssid;
			}

			Entry.wlanDisabled = 1;
			mib_chain_update(MIB_MBSSIB_TBL, (void *)&Entry, i+1);
		}
	}

	for (i=0; i<4; i++) {
		sprintf(en_vap, "ssid_v%d", i);
		str = boaGetVar(wp, en_vap, "");
		if ( str ) {
			if (!mib_chain_get(MIB_MBSSIB_TBL, i+1, (void *)&Entry)) {
  				strcpy(tmpBuf, strGetVAPMBSSIBTBLErr);
				goto setErr_mbssid;
			}

			strcpy(Entry.ssid, str);
			mib_chain_update(MIB_MBSSIB_TBL, (void *)&Entry, i+1);
		}
	}

	for (i=0; i<4; i++) {
		sprintf(en_vap, "wlAPIsolation_wl%d", i);
		str = boaGetVar(wp, en_vap, "");
		if ( str ) {
			if (!mib_chain_get(MIB_MBSSIB_TBL, i+1, (void *)&Entry)) {
  				strcpy(tmpBuf, "strGetVAPMBSSIBTBLErr");
				goto setErr_mbssid;
			}
			if (str[0] == '0')
				vChar = 0;
			else // '1'
				vChar = 1;

			Entry.userisolation = vChar;
			mib_chain_update(MIB_MBSSIB_TBL, (void *)&Entry, i+1);
		}
	}

	config_WLAN(ACT_RESTART, CONFIG_SSID_ALL);

#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif // of #if COMMIT_IMMEDIATELY

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
	OK_MSG(submitUrl);
  	return;

setErr_mbssid:
	ERR_MSG(tmpBuf);
}


#ifdef CONFIG_RTL_WAPI_SUPPORT
void wapi_mod_entry(MIB_CE_MBSSIB_T *Entry, char *strbuf, char *strbuf2) {
	int len;

	Entry->wpaPSKFormat = Entry->wapiPskFormat;
	Entry->wep = 0;
	Entry->enable1X = 0;
	Entry->rsPort = 0;
	Entry->rsPassword[0] = 0;

	if (Entry->wapiAuth==1) {// AS
		Entry->wpaAuth = 1;

		if ( ((struct in_addr *)Entry->wapiAsIpAddr)->s_addr == INADDR_NONE ) {
			sprintf(strbuf2, "%s", "");
		} else {
			sprintf(strbuf2, "%s", inet_ntoa(*((struct in_addr *)Entry->wapiAsIpAddr)));
		}


	} else { //PSK
		Entry->wpaAuth = 2;

		for (len=0; len<Entry->wapiPskLen; len++)
			strbuf[len]='*';
		strbuf[len]='\0';
	}
}
#endif

void formWlanMultipleAP(request * wp, char *path, char *query)
{
	char *str, *submitUrl;
	MIB_CE_MBSSIB_T Entry;
	char tmpBuf[100], en_vap[256];
	int i, val;
#ifndef NO_ACTION
	int pid;
#endif
	unsigned char vChar;

#if defined(CONFIG_RTL_92D_SUPPORT) || defined(WLAN_DUALBAND_CONCURRENT)
	str = boaGetVar(wp, "wlan_idx", "");
	if ( str[0] ) {
		printf("wlan_idx=%d\n", str[0]-'0');
		wlan_idx = str[0]-'0';
	}
#endif //CONFIG_RTL_92D_SUPPORT || WLAN_DUALBAND_CONCURRENT

	//for blocking between MBSSID
	sprintf(en_vap, "mbssid_block");
	str = boaGetVar(wp, en_vap, "");
	if (str[0]) {
		if ( !gstrcmp(str, "disable"))
			vChar = 0;
		else
			vChar = 1;

		if ( mib_set(MIB_WLAN_BLOCK_MBSSID, (void *)&vChar) == 0) {
			strcpy(tmpBuf, "set MBSSID error!");
			goto setErr_mbssid;
		}
	}

	for (i = 1; i <= NUM_VWLAN_INTERFACE; i ++) {
		if (!mib_chain_get(MIB_MBSSIB_TBL, i, (void *)&Entry)) {
			strcpy(tmpBuf, strGetMULTIAPTBLErr);
			goto setErr_mbssid;
		}

		sprintf(en_vap, "wl_disable%d", i);
		str = boaGetVar(wp, en_vap, "");
		if (str && !strcmp(str, "ON")) {	// enable
			Entry.wlanDisabled = 0;
		}
		else {	// disable
			Entry.wlanDisabled = 1;
			mib_chain_update(MIB_MBSSIB_TBL, (void *)&Entry, i);
			continue;
		}

		sprintf(en_vap, "wl_band%d", i);
		str = boaGetVar(wp, en_vap, "");
		if (str) {
			vChar = atoi(str);
			vChar ++;

			Entry.wlanBand= vChar;
			update_on_band_changed(&Entry, i, Entry.wlanBand);
		}

		sprintf(en_vap, "wl_ssid%d", i);
		str = boaGetVar(wp, en_vap, "");
		if (str) {
			strcpy(Entry.ssid, str);
		}

		sprintf(en_vap, "TxRate%d", i);
		str = boaGetVar(wp, en_vap, "");
		if (str) {
			if (str[0] == '0') { // auto
				vChar = 1;
				Entry.rateAdaptiveEnabled = vChar;
			}
			else {
				vChar = 0;
				Entry.rateAdaptiveEnabled = vChar;
				val = atoi(str);
				if (val < 30)
					val = 1 << (val - 1);
				else
					val = ((1 << 31) + (val - 30));
				Entry.fixedTxRate = val;
			}
		}

		sprintf(en_vap, "wl_hide_ssid%d", i);
		str = boaGetVar(wp, en_vap, "");
		if (str) {
			if (str[0] == '0')
				vChar = 0;
			else		// '1'
				vChar = 1;
			Entry.hidessid = vChar;
		}

		sprintf(en_vap, "wl_wmm_capable%d", i);
		str = boaGetVar(wp, en_vap, "");
		if (str) {
			if (str[0] == '0')
				vChar = 0;
			else		// '1'
				vChar = 1;
			Entry.wmmEnabled = vChar;
		}

		sprintf(en_vap, "wl_access%d", i);
		str = boaGetVar(wp, en_vap, "");
		if (str) {
			if (str[0] == '0')
				vChar = 0;
			else		// '1'
				vChar = 1;
			Entry.userisolation = vChar;
		}
		mib_chain_update(MIB_MBSSIB_TBL, (void *)&Entry, i);
	}

	config_WLAN(ACT_RESTART, CONFIG_SSID_ALL);

#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif // of #if COMMIT_IMMEDIATELY

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
	OK_MSG(submitUrl);
  	return;

setErr_mbssid:
	ERR_MSG(tmpBuf);
}

int checkSSID(int eid, request * wp, int argc, char **argv)
{
	char *name;
	MIB_CE_MBSSIB_T Entry;
	//char strbuf[20], strbuf2[20];
	//int len;
	int i;

	if (boaArgs(argc, argv, "%s", &name) < 1) {
		boaError(wp, 400, "Insufficient args\n");
		return -1;
	}

	if ( !strcmp(name, "vap0") ){
		i = 1;

	}
	else if ( !strcmp(name, "vap1") ) {
		i = 2;
	}
	else if ( !strcmp(name, "vap2") ) {
		i = 3;
	}
	else if ( !strcmp(name, "vap3") ) {
		i = 4;
	}
	else {
		printf("Not support this VAP!\n");
		return 1;
	}

	if (!mib_chain_get(MIB_MBSSIB_TBL, i, (void *)&Entry)) {
  		printf("Error! Get MIB_MBSSIB_TBL(Root) error.\n");
			return 1;
	}

	if ( Entry.wlanDisabled == 0 ) {
		boaWrite(wp, "checked");
	} else {
		boaWrite(wp, "");
	}
}


int SSIDStr(int eid, request * wp, int argc, char **argv)
{
	char *name;
	MIB_CE_MBSSIB_T Entry;
	//char strbuf[20], strbuf2[20];
	//int len;
	int i;
	char ssid[200];

	if (boaArgs(argc, argv, "%s", &name) < 1) {
		boaError(wp, 400, "Insufficient args\n");
		return -1;
	}

	if ( !strcmp(name, "vap0") ){
		i = 1;

	}
	else if ( !strcmp(name, "vap1") ) {
		i = 2;

	}
	else if ( !strcmp(name, "vap2") ) {
		i = 3;
	}
	else if ( !strcmp(name, "vap3") ) {
		i = 4;
	}
	else {
		printf("SSIDStr: Not support this VAP!\n");
		return 1;
	}
	{
		if (!mib_chain_get(MIB_MBSSIB_TBL, i, (void *)&Entry)) {
	  		printf("Error! Get MIB_MBSSIB_TBL(SSIDStr) error.\n");
  			return 1;
		}
	}
	{
		strncpy(ssid, Entry.ssid, MAX_SSID_LEN);
		translate_control_code(ssid);
		boaWrite(wp, "%s", ssid);
	}

	return 0;
}
#endif

/////////////////////////////////////////////////////////////////////////////
//check wlan status and set checkbox
int wlanStatus(int eid, request * wp, int argc, char **argv)
{
#ifdef WLAN_SUPPORT
	if (wlan_is_up())
	    //boaWrite(wp, "\"OFF\" enabled");
	    boaWrite(wp, "\"OFF\"");
	else
	    //boaWrite(wp, "\"ON\" checked disabled");
	    boaWrite(wp, "\"ON\" checked");
	return 0;
#endif
}

#ifdef WLAN_SUPPORT
int wlan_interface_status(int eid, request * wp, int argc, char **argv)
{
	int status;
	MIB_CE_MBSSIB_T Entry;
#if defined(CONFIG_RTL_92D_SUPPORT) || defined(WLAN_DUALBAND_CONCURRENT)
	int orig_idx = wlan_idx;
#endif
	int i, j;
	for(i=0; i<NUM_WLAN_INTERFACE; i++){
		wlan_idx = i;
		status = 0;
		
		mib_chain_get(MIB_MBSSIB_TBL, 0, (void *)&Entry);
		if(Entry.wlanDisabled==0){
			status=1;
		}

		if(status==0){
			for(j=0; j<WLAN_MBSSID_NUM; j++){
				mib_chain_get(MIB_MBSSIB_TBL, j+1, (void *)&Entry);
				if(Entry.wlanDisabled==0){
					status=1;
					break;
				}
			}
		}
		
		boaWrite(wp, "wlan_root_interface_up[%d]=%d;\n", i, status);
	}
#if defined(CONFIG_RTL_92D_SUPPORT) || defined(WLAN_DUALBAND_CONCURRENT)
	wlan_idx = orig_idx;
#endif
	return 0;
}
#endif

#ifdef WLAN_SUPPORT
int wlan_ssid_select(int eid, request * wp, int argc, char **argv)
{
	MIB_CE_MBSSIB_T Entry;
	WLAN_MODE_T root_mode;
	int len, i, k;
	char repeater_AP[]="Repeater AP";
	char repeater_Client[]="Repeater Client";
	char *pstr;
	char ssid[200];

	wlan_getEntry(&Entry, 0);
	strncpy(ssid, Entry.ssid, MAX_SSID_LEN);
	translate_control_code(ssid);
	root_mode = (WLAN_MODE_T)Entry.wlanMode;
	k=0;
	if (root_mode!=CLIENT_MODE) {
		/*--------------------- Root AP ----------------------------*/
		boaWrite(wp, "<option value=0>Root AP - %s</option>\n", ssid);
		#ifdef WLAN_MBSSID
		/*----------------------- VAP ------------------------------*/
		for (i=0; i<WLAN_MBSSID_NUM; i++) {
#if defined(CONFIG_CT_AWIFI_JITUAN_FEATURE)
            unsigned char functype=0;
            mib_get(AWIFI_PROVINCE_CODE, &functype);
            if(functype == AWIFI_ZJ){
                if(i == 0)	continue;
            }
#endif
			wlan_getEntry(&Entry, WLAN_VAP_ITF_INDEX+i);
			strncpy(ssid, Entry.ssid, MAX_SSID_LEN);
			translate_control_code(ssid);
			if (!Entry.wlanDisabled) {
				boaWrite(wp, "\t\t<option value=%d>AP%d - %s\n", WLAN_VAP_ITF_INDEX + i, i + 1, ssid);
			}
		}
		#endif
	}
	else { // client mode
		/*--------------------- Root Client ----------------------------*/
		boaWrite(wp, "<option value=0>Root Client - %s</option>\n", Entry.ssid);
	}
	#ifdef WLAN_UNIVERSAL_REPEATER
	wlan_getEntry(&Entry, WLAN_REPEATER_ITF_INDEX);
	strncpy(ssid, Entry.ssid, MAX_SSID_LEN);
	translate_control_code(ssid);
	if (!Entry.wlanDisabled && (root_mode != WDS_MODE)) {
		if (root_mode == CLIENT_MODE)
			pstr = repeater_AP;
		else
			pstr = repeater_Client;

		boaWrite(wp, "\t\t<option value=%d>%s - %s</option>\n", WLAN_REPEATER_ITF_INDEX, pstr, ssid);
	}
	#endif
	return 0;
}
#endif

/////////////////////////////////////////////////////////////////////////////
void formAdvanceSetup(request * wp, char *path, char *query)
{
	char *submitUrl, *strAuth, *strFragTh, *strRtsTh, *strBeacon, *strPreamble;
	char *strRate, *strHiddenSSID, *strDtim, *strIapp, *strBlock;
	char *strProtection, *strAggregation, *strShortGIO, *strVal;
	char vChar;
	unsigned short uShort;
	AUTH_TYPE_T authType;
	PREAMBLE_T preamble;
	int val;
	char tmpBuf[100];
	MIB_CE_MBSSIB_T Entry;

#if defined(CONFIG_RTL_92D_SUPPORT) || defined(WLAN_DUALBAND_CONCURRENT)
	strVal = boaGetVar(wp, "wlan_idx", "");
	if ( strVal[0] ) {
		printf("wlan_idx=%d\n", strVal[0]-'0');
		wlan_idx = strVal[0]-'0';
	}
#endif //CONFIG_RTL_92D_SUPPORT || WLAN_DUALBAND_CONCURRENT
//xl_yue: translocate to basic_setting   for ZTE531B BRIDGE
	mib_chain_get(MIB_MBSSIB_TBL, 0, (void *)&Entry);

	strFragTh = boaGetVar(wp, "fragThreshold", "");
	if (strFragTh[0]) {
		if ( !string_to_dec(strFragTh, &val) || val<256 || val>2346) {
			strcpy(tmpBuf, strFragThreshold);
			goto setErr_advance;
		}
		uShort = (unsigned short)val;
		if ( mib_set(MIB_WLAN_FRAG_THRESHOLD, (void *)&uShort) == 0) {
			strcpy(tmpBuf, strSetFragThreErr);
			goto setErr_advance;
		}
	}
	strRtsTh = boaGetVar(wp, "rtsThreshold", "");
	if (strRtsTh[0]) {
		if ( !string_to_dec(strRtsTh, &val) || val<0 || val>2347) {
			strcpy(tmpBuf, strRTSThreshold);
			goto setErr_advance;
		}
		uShort = (unsigned short)val;
		if ( mib_set(MIB_WLAN_RTS_THRESHOLD, (void *)&uShort) == 0) {
			strcpy(tmpBuf, strSetRTSThreErr);
			goto setErr_advance;
		}
	}

	strBeacon = boaGetVar(wp, "beaconInterval", "");
	if (strBeacon[0]) {
		if ( !string_to_dec(strBeacon, &val) || val<20 || val>1024) {
			strcpy(tmpBuf, strInvdBeaconIntv);
			goto setErr_advance;
		}
		uShort = (unsigned short)val;
		if ( mib_set(MIB_WLAN_BEACON_INTERVAL, (void *)&uShort) == 0) {
			strcpy(tmpBuf, strSetBeaconIntvErr);
			goto setErr_advance;
		}
	}

//xl_yue: translocate to basic_setting  for ZTE531B BRIDGE
	// set tx rate
	strRate = boaGetVar(wp, "txRate", "");
	if ( strRate[0] ) {
		if ( strRate[0] == '0' )  // auto
			Entry.rateAdaptiveEnabled = 1;
		else  {
			Entry.rateAdaptiveEnabled = 0;
			{
				unsigned int uInt;
				uInt = atoi(strRate);
				if(uInt<30)
					uInt = 1 << (uInt-1);
				else
					uInt = ((1 << 31) + (uInt-30));
				Entry.fixedTxRate = uInt;
			}
			strRate = boaGetVar(wp, "basicrates", "");
			if ( strRate[0] ) {
				uShort = atoi(strRate);
				if ( mib_set(MIB_WLAN_BASIC_RATE, (void *)&uShort) == 0) {
					strcpy(tmpBuf, strSetBaseRateErr);
					goto setErr_advance;
				}
			}

			strRate = boaGetVar(wp, "operrates", "");
			if ( strRate[0] ) {
				uShort = atoi(strRate);
				if ( mib_set(MIB_WLAN_SUPPORTED_RATE, (void *)&uShort) == 0) {
					strcpy(tmpBuf, strSetOperRateErr);
					goto setErr_advance;
				}
			}
		}
	}
	else { // set rate in operate, basic sperately
#ifdef WIFI_TEST
		// disable rate adaptive
		Entry.rateAdaptiveEnabled = 0;
#endif // of WIFI_TEST
	}

	// set preamble
	strPreamble = boaGetVar(wp, "preamble", "");
	if (strPreamble[0]) {
		if (!gstrcmp(strPreamble, "long"))
			preamble = LONG_PREAMBLE;
		else if (!gstrcmp(strPreamble, "short"))
			preamble = SHORT_PREAMBLE;
		else {
			strcpy(tmpBuf, strInvdPreamble);
			goto setErr_advance;
		}
		vChar = (char)preamble;
		if ( mib_set(MIB_WLAN_PREAMBLE_TYPE, (void *)&vChar) == 0) {
			strcpy(tmpBuf, strSetPreambleErr);
			goto setErr_advance;
		}
	}

	// set hidden SSID
	strHiddenSSID = boaGetVar(wp, "hiddenSSID", "");
	if (strHiddenSSID[0]) {
		if (!gstrcmp(strHiddenSSID, "no"))
			vChar = 0;
		else if (!gstrcmp(strHiddenSSID, "yes"))
			vChar = 1;
		else {
			strcpy(tmpBuf, strInvdBrodSSID);
			goto setErr_advance;
		}
		Entry.hidessid = vChar;
#ifdef CONFIG_WIFI_SIMPLE_CONFIG
		#ifdef WPS20
		if(vChar){//if hidden, wsc should disable
			Entry.wsc_disabled = vChar;
		}
		#endif
#endif
	}

	strProtection = boaGetVar(wp, "protection", "");
	if (strProtection[0]){
		if (!gstrcmp(strProtection,"yes"))
			vChar = 0;
		else if (!gstrcmp(strProtection,"no"))
			vChar = 1;
		else{
			strcpy(tmpBuf, strInvdProtection);
			goto setErr_advance;
		}
		if (mib_set(MIB_WLAN_PROTECTION_DISABLED,(void *)&vChar) ==0){
			strcpy(tmpBuf, strSetProtectionErr);
			goto setErr_advance;
		}
	}

	strAggregation = boaGetVar(wp, "aggregation", "");
	if (strAggregation[0]){
		if (!gstrcmp(strAggregation,"enable"))
			vChar = 1;
		else if (!gstrcmp(strAggregation,"disable"))
			vChar = 0;
		else{
			strcpy(tmpBuf, strInvdAggregation);
			goto setErr_advance;
		}
		if (mib_set(MIB_WLAN_AGGREGATION,(void *)&vChar) ==0){
			strcpy(tmpBuf, strSetAggregationErr);
			goto setErr_advance;
		}
	}

	strShortGIO = boaGetVar(wp, "shortGI0", "");
	if (strShortGIO[0]){
		if (!gstrcmp(strShortGIO,"on"))
			vChar = 1;
		else if (!gstrcmp(strShortGIO,"off"))
			vChar = 0;
		else{
			strcpy(tmpBuf, strInvdShortGI0);
			goto setErr_advance;
		}
		if (mib_set(MIB_WLAN_SHORTGI_ENABLED,(void *)&vChar) ==0){
			strcpy(tmpBuf, strSetShortGI0Err);
			goto setErr_advance;
		}
	}

	strDtim = boaGetVar(wp, "dtimPeriod", "");
	if (strDtim[0]) {
		if ( !string_to_dec(strDtim, &val) || val<1 || val>255) {
			strcpy(tmpBuf, strInvdDTIMPerd);
			goto setErr_advance;
		}
		vChar = (char)val;
		if ( mib_set(MIB_WLAN_DTIM_PERIOD, (void *)&vChar) == 0) {
			strcpy(tmpBuf, strSetDTIMErr);
			goto setErr_advance;
		}
	}

	// set block-relay
	strBlock = boaGetVar(wp, "block", "");
	if (strBlock[0]) {
		if (strBlock[0] == '0')
			vChar = 0;
		else // '1'
			vChar = 1;
		Entry.userisolation = vChar;
	}

#ifdef WLAN_QoS
	strBlock = boaGetVar(wp, "WmmEnabled", "");
	if (strBlock[0]) {
		if (strBlock[0] == '0')
			vChar = 0;
		else // '1'
			vChar = 1;
		Entry.wmmEnabled = vChar;
	}
#endif
	mib_chain_update(MIB_MBSSIB_TBL, (void *)&Entry, 0);
	config_WLAN(ACT_RESTART, CONFIG_SSID_ALL);

// Magician: Commit immediately
#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif // of #if COMMIT_IMMEDIATELY

#ifndef NO_ACTION
	run_script(-1);
#endif

	submitUrl = boaGetVar(wp, "submit-url", "");   // hidden page

//	boaRedirect(wp, submitUrl);
	//OK_MSG(submitUrl);
	if (submitUrl[0])
		boaRedirect(wp, submitUrl);
	else
		boaDone(wp, 200);
  	return;

setErr_advance:
	ERR_MSG(tmpBuf);
}

void set_11ac_txrate(WLAN_STA_INFO_Tp pInfo,char* txrate)
{
	char channelWidth=0;//20M 0,40M 1,80M 2
	char shortGi=0;
	char rate_idx=pInfo->txOperaRates-0x90;
	if(!txrate)return;
/*
	TX_USE_40M_MODE         = BIT(0),
	TX_USE_SHORT_GI         = BIT(1),
	TX_USE_80M_MODE         = BIT(2)
*/
	if(pInfo->ht_info & 0x4)
		channelWidth=2;
	else if(pInfo->ht_info & 0x1)
		channelWidth=1;
	else
		channelWidth=0;
	if(pInfo->ht_info & 0x2)
		shortGi=1;
	
	sprintf(txrate, "%d", VHT_MCS_DATA_RATE[channelWidth][shortGi][rate_idx]>>1);

}

/////////////////////////////////////////////////////////////////////////////
int wirelessVAPClientList(int eid, request *wp, int argc, char **argv)
{
	int nBytesSent=0, i, found=0;
	WLAN_STA_INFO_Tp pInfo;
	char *buff;
	char s_ifname[16];
	char mode_buf[20];
	char txrate[20];
	int rateid=0;

	buff = calloc(1, sizeof(WLAN_STA_INFO_T) * (MAX_STA_NUM+1));
	if ( buff == 0 ) {
		printf("Allocate buffer failed!\n");
		return 0;
	}

#ifdef WLAN_MBSSID
	char Root_WLAN_IF[20];

	snprintf(s_ifname, 16, "%s", (char *)getWlanIfName());
	strcpy(Root_WLAN_IF, s_ifname);
	if (argc == 2) {
		int virtual_index;
		char virtual_name[20];
		virtual_index = atoi(argv[argc-1]) - 1;

		snprintf(s_ifname, 16, "%s-vap%d", (char *)getWlanIfName(), virtual_index);
	}
#endif

	if (getWlStaInfo(s_ifname,  (WLAN_STA_INFO_Tp)buff) < 0) {
		printf("Read wlan sta info failed!\n");

#ifdef WLAN_MBSSID
		if (argc == 2)
			strcpy(s_ifname, Root_WLAN_IF);
#endif
		return 0;
	}

#ifdef WLAN_MBSSID
	if (argc == 2)
		strcpy(s_ifname, Root_WLAN_IF);
#endif

	for (i=1; i<=MAX_STA_NUM; i++) {
		pInfo = (WLAN_STA_INFO_Tp)&buff[i*sizeof(WLAN_STA_INFO_T)];
		if (pInfo->aid && (pInfo->flag & STA_INFO_FLAG_ASOC)) {
			if (pInfo->network & BAND_11N)
				sprintf(mode_buf, "%s", (" 11n"));
			else if (pInfo->network & BAND_11G)
				sprintf(mode_buf,"%s",  (" 11g"));
			else if (pInfo->network & BAND_11B)
				sprintf(mode_buf, "%s", (" 11b"));
			else if (pInfo->network& BAND_11A)
				sprintf(mode_buf, "%s", (" 11a"));
			else
				sprintf(mode_buf, "%s", (" ---"));

			//printf("\n\nthe sta txrate=%d\n\n\n", pInfo->txOperaRates);

			if ((pInfo->txOperaRates & 0x80) != 0x80) {
				if (pInfo->txOperaRates%2) {
					sprintf(txrate, "%d%s",pInfo->txOperaRates/2, ".5");
				} else {
					sprintf(txrate, "%d",pInfo->txOperaRates/2);
				}
			} else {
				if ((pInfo->ht_info & 0x1)==0) { //20M
					if ((pInfo->ht_info & 0x2)==0){//long
						for (rateid=0; rateid<16;rateid++) {
							if (rate_11n_table_20M_LONG[rateid].id == pInfo->txOperaRates) {
								sprintf(txrate, "%s", rate_11n_table_20M_LONG[rateid].rate);
								break;
							}
						}
					} else if ((pInfo->ht_info & 0x2)==0x2) {//short
						for (rateid=0; rateid<16;rateid++) {
							if (rate_11n_table_20M_SHORT[rateid].id == pInfo->txOperaRates) {
								sprintf(txrate, "%s", rate_11n_table_20M_SHORT[rateid].rate);
								break;
							}
						}
					}
				} else if ((pInfo->ht_info & 0x1)==0x1) {//40M
					if ((pInfo->ht_info & 0x2)==0) {//long
						for (rateid=0; rateid<16;rateid++) {
							if (rate_11n_table_40M_LONG[rateid].id == pInfo->txOperaRates) {
								sprintf(txrate, "%s", rate_11n_table_40M_LONG[rateid].rate);
								break;
							}
						}
					} else if ((pInfo->ht_info & 0x2)==0x2) {//short
						for (rateid=0; rateid<16;rateid++) {
							if (rate_11n_table_40M_SHORT[rateid].id == pInfo->txOperaRates) {
								sprintf(txrate, "%s", rate_11n_table_40M_SHORT[rateid].rate);
								break;
							}
						}
					}
				}
			}
			nBytesSent += boaWrite(wp,
		   		"<tr bgcolor=#b7b7b7><td><font size=2>%02x:%02x:%02x:%02x:%02x:%02x</td>"
				"<td><font size=2>%s</td>"
				"<td><font size=2>%d</td>"
	     			"<td><font size=2>%d</td>"
				"<td><font size=2>%s</td>"
				"<td><font size=2>%s</td>"
				"<td><font size=2>%d</td>"
				"</tr>",
				pInfo->addr[0],pInfo->addr[1],pInfo->addr[2],pInfo->addr[3],pInfo->addr[4],pInfo->addr[5],
				mode_buf,
				pInfo->tx_packets, pInfo->rx_packets,
				txrate,
				((pInfo->flag & STA_INFO_FLAG_ASLEEP) ? "yes" : "no"),
				pInfo->expired_time / 100
			);
			found ++;
		}
	}
	if (found == 0) {
		nBytesSent += boaWrite(wp,
	   		"<tr bgcolor=#b7b7b7><td><font size=2>None</td>"
			"<td><font size=2>---</td>"
	     		"<td><font size=2>---</td>"
			"<td><font size=2>---</td>"
			"<td><font size=2>---</td>"
			"<td><font size=2>---</td>"
			"<td><font size=2>---</td>"
			"</tr>");
	}

	free(buff);

	return nBytesSent;
}

/////////////////////////////////////////////////////////////////////////////
void formWirelessVAPTbl(request * wp, char *path, char *query)
{
	char *submitUrl;

	submitUrl = boaGetVar(wp, "submit-url", "");
	if (submitUrl[0])
		boaRedirect(wp, submitUrl);
}

/////////////////////////////////////////////////////////////////////////////
int wirelessClientList(int eid, request * wp, int argc, char **argv)
{
	int nBytesSent = 0, i, found = 0;
	int x,y;
	WLAN_STA_INFO_Tp pInfo;
	char *buff;
	char ifname[16];

	buff = calloc(1, sizeof(WLAN_STA_INFO_T) * (MAX_STA_NUM + 1));
	if (buff == 0) {
		printf("Allocate buffer failed!\n");
		return 0;
	}

	for (x=0; x<NUM_WLAN_INTERFACE; x++)
	{
	for(y=0; y<=WLAN_MBSSID_NUM; y++)
	{
		memset(buff, 0, sizeof(WLAN_STA_INFO_T) * (MAX_STA_NUM + 1));
		if(y==0)
			snprintf(ifname, 16, "%s", WLANIF[x]);
		else
			snprintf(ifname, 16, "%s-vap%d", WLANIF[x], y-1);

	if (getInFlags(ifname, 0)==0){
		continue;
	}
	if (getWlStaInfo(ifname, (WLAN_STA_INFO_Tp) buff) < 0) {
		printf("Read wlan sta info failed!\n");
		//free(buff);
		//return 0;
		continue;
	}

	for (i = 1; i <= MAX_STA_NUM; i++) {
		pInfo = (WLAN_STA_INFO_Tp) & buff[i * sizeof(WLAN_STA_INFO_T)];
		if (pInfo->aid && (pInfo->flag & STA_INFO_FLAG_ASOC)) {
			char txrate[20];
			int rateid = 0;

			if(pInfo->txOperaRates >= 0x90) {
				//sprintf(txrate, "%d", pInfo->acTxOperaRate);
				set_11ac_txrate(pInfo, txrate);
			}else if ((pInfo->txOperaRates & 0x80) != 0x80) {
				if (pInfo->txOperaRates % 2) {
					sprintf(txrate, "%d%s",
						pInfo->txOperaRates / 2, ".5");
				} else {
					sprintf(txrate, "%d",
						pInfo->txOperaRates / 2);
				}
			} else {
				if ((pInfo->ht_info & 0x1) == 0) {	//20M
					if ((pInfo->ht_info & 0x2) == 0) {	//long
						for (rateid = 0;
						     rateid < 16; rateid++) {
							if (rate_11n_table_20M_LONG[rateid].id == pInfo->txOperaRates) {
								sprintf
								    (txrate,
								     "%s",
								     rate_11n_table_20M_LONG
								     [rateid].rate);
								break;
							}
						}
					} else if ((pInfo->ht_info & 0x2) == 0x2) {	//short
						for (rateid = 0;
						     rateid < 16; rateid++) {
							if (rate_11n_table_20M_SHORT[rateid].id == pInfo->txOperaRates) {
								sprintf
								    (txrate,
								     "%s",
								     rate_11n_table_20M_SHORT
								     [rateid].rate);
								break;
							}
						}
					}
				} else if ((pInfo->ht_info & 0x1) == 0x1) {	//40M
					if ((pInfo->ht_info & 0x2) == 0) {	//long

						for (rateid = 0;
						     rateid < 16; rateid++) {
							if (rate_11n_table_40M_LONG[rateid].id == pInfo->txOperaRates) {
								sprintf
								    (txrate,
								     "%s",
								     rate_11n_table_40M_LONG
								     [rateid].rate);
								break;
							}
						}
					} else if ((pInfo->ht_info & 0x2) == 0x2) {	//short
						for (rateid = 0;
						     rateid < 16; rateid++) {
							if (rate_11n_table_40M_SHORT[rateid].id == pInfo->txOperaRates) {
								sprintf
								    (txrate,
								     "%s",
								     rate_11n_table_40M_SHORT
								     [rateid].rate);
								break;
							}
						}
					}
				}

			}

			nBytesSent += boaWrite(wp,
					       "<tr align=\"center\" nowrap><font size=2>"
					       "<td>%02x:%02x:%02x:%02x:%02x:%02x</td>"
					       "<td>%d</td>"
					       "<td>%d</td>"
					       "<td>%s</td>"
					       "<td>%s</td>"
					       "<td>%d</td>"
					       "</font></tr>",
					       pInfo->addr[0], pInfo->addr[1],
					       pInfo->addr[2], pInfo->addr[3],
					       pInfo->addr[4], pInfo->addr[5],
					       pInfo->tx_packets, pInfo->rx_packets,
					       txrate, ((pInfo->flag &
						 STA_INFO_FLAG_ASLEEP) ?
						"yes" : "no"), pInfo->expired_time / 100);
			found++;
		}
	}
	}
	}

	if (found == 0) {
		nBytesSent += boaWrite(wp,
				       "<tr align=\"center\" nowrap><font size=2>"
				       "<td>None</td>"
				       "<td>---</td>"
				       "<td>---</td>"
				       "<td>---</td>"
				       "<td>---</td>"
				       "<td>---</td>"
				       "</font></tr>");
	}
	free(buff);

	return nBytesSent;
}

/////////////////////////////////////////////////////////////////////////////
void formWirelessTbl(request * wp, char *path, char *query)
{
	char *submitUrl;
	char *strWlanId;

	strWlanId= boaGetVar(wp, "wlan_idx", "");
	if(strWlanId[0]){
		wlan_idx = atoi(strWlanId);
		//printf("%s: wlan_idx=%d\n", __func__, wlan_idx);
	}
	submitUrl = boaGetVar(wp, "submit-url", "");
	if (submitUrl[0])
		boaRedirect(wp, submitUrl);
}

#ifdef WLAN_CLIENT
static SS_STATUS_Tp pStatus=NULL;
/////////////////////////////////////////////////////////////////////////////
void formWlSiteSurvey(request * wp, char *path, char *query)
{
 	char *submitUrl, *refresh, *connect, *strSel;
	int status, idx;
	unsigned char res, *pMsg=NULL;
	int wait_time;
	char tmpBuf[100];

#if defined(CONFIG_RTL_92D_SUPPORT) || defined(WLAN_DUALBAND_CONCURRENT)
	char *strVal;
	strVal = boaGetVar(wp, "wlan_idx", "");
	if ( strVal[0] ) {
		printf("wlan_idx=%d\n", strVal[0]-'0');
		wlan_idx = strVal[0]-'0';
	}
#endif //CONFIG_RTL_92D_SUPPORT || WLAN_DUALBAND_CONCURRENT

	submitUrl = boaGetVar(wp, "submit-url", "");

	refresh = boaGetVar(wp, "refresh", "");
	if ( refresh[0] ) {
		// issue scan request
		wait_time = 0;
		while (1) {
			if ( getWlSiteSurveyRequest(getWlanIfName(),  &status) < 0 ) {
				strcpy(tmpBuf, "Site-survey request failed!");
				goto ss_err;
			}
			if (status != 0) {	// not ready
				if (wait_time++ > 5) {
					strcpy(tmpBuf, "scan request timeout!");
					goto ss_err;
				}
				sleep(1);
			}
			else
				break;
		}

		// wait until scan completely
		wait_time = 0;
		while (1) {
			res = 1;	// only request request status
			if ( getWlSiteSurveyResult(getWlanIfName(), (SS_STATUS_Tp)&res) < 0 ) {
				strcpy(tmpBuf, "Read site-survey status failed!");
				free(pStatus);
				pStatus = NULL;
				goto ss_err;
			}
			if (res == 0xff) {   // in progress
				if (wait_time++ > 10) {
					strcpy(tmpBuf, "scan timeout!");
					free(pStatus);
					pStatus = NULL;
					goto ss_err;
				}
				sleep(1);
			}
			else
				break;
		}

		if (submitUrl[0])
			boaRedirect(wp, submitUrl);

		return;
	}

	connect = boaGetVar(wp, "connect", "");
	if ( connect[0] ) {
		strSel = boaGetVar(wp, "select", "");
		if (strSel[0]) {
			unsigned char res;
			NETWORK_TYPE_T net;
			int chan;
			unsigned char encrypt;
			MIB_CE_MBSSIB_T pEntry;

			if (pStatus == NULL) {
				strcpy(tmpBuf, "Please refresh again!");
				goto ss_err;

			}
			sscanf(strSel, "sel%d", &idx);
			if ( idx >= pStatus->number ) { // invalid index
				strcpy(tmpBuf, "Connect failed 1!");
				goto ss_err;
			}
			wlan_getEntry(&pEntry, 0);
			// check encryption type match or not
			encrypt = pEntry.encrypt;
			// no encryption
			if (encrypt == WIFI_SEC_NONE)
			{
				if (pStatus->bssdb[idx].capability & 0x00000010) {
					strcpy(tmpBuf, "Encryption type mismatch!");
					goto ss_err;
				}
				else
					; // success
			}
			// legacy encryption
			else if (encrypt == WIFI_SEC_WEP)
			{
				if ((pStatus->bssdb[idx].capability & 0x00000010) == 0) {
					strcpy(tmpBuf, "Encryption type mismatch!");
					goto ss_err;
				}
				else if (pStatus->bssdb[idx].t_stamp[0] != 0) {
					strcpy(tmpBuf, "Encryption type mismatch!");
					goto ss_err;
				}
				else
					; // success
			}
			// WPA/WPA2
			else
			{
				int isPSK;
				unsigned char auth;
				auth = pEntry.wpaAuth;
				if (auth == WPA_AUTH_PSK)
					isPSK = 1;
				else
					isPSK = 0;

				if ((pStatus->bssdb[idx].capability & 0x00000010) == 0) {
					strcpy(tmpBuf, "Encryption type mismatch!");
					goto ss_err;
				}
				else if (pStatus->bssdb[idx].t_stamp[0] == 0) {
					strcpy(tmpBuf, "Encryption type mismatch!");
					goto ss_err;
				}
				else if (encrypt == WIFI_SEC_WPA) {
					if (((pStatus->bssdb[idx].t_stamp[0] & 0x0000ffff) == 0) ||
							(isPSK && !(pStatus->bssdb[idx].t_stamp[0] & 0x4000)) ||
							(!isPSK && (pStatus->bssdb[idx].t_stamp[0] & 0x4000)) ) {
						strcpy(tmpBuf, "Encryption type mismatch!");
						goto ss_err;
					}
				}
				else if (encrypt == WIFI_SEC_WPA2) {
					if (((pStatus->bssdb[idx].t_stamp[0] & 0xffff0000) == 0) ||
							(isPSK && !(pStatus->bssdb[idx].t_stamp[0] & 0x40000000)) ||
							(!isPSK && (pStatus->bssdb[idx].t_stamp[0] & 0x40000000)) ) {
						strcpy(tmpBuf, "Encryption type mismatch!");
						goto ss_err;
					}
				}
				else
					; // success
			}

			// Set SSID, network type to MIB
			memcpy(tmpBuf, pStatus->bssdb[idx].ssid, pStatus->bssdb[idx].ssidlen);
			tmpBuf[pStatus->bssdb[idx].ssidlen] = '\0';
			strcpy(pEntry.ssid,tmpBuf);

			if ( pStatus->bssdb[idx].capability & cESS )
				net = INFRASTRUCTURE;
			else
				net = ADHOC;

			if ( mib_set(MIB_WLAN_NETWORK_TYPE, (void *)&net) == 0) {
				strcpy(tmpBuf, "Set MIB_WLAN_NETWORK_TYPE failed!");
				goto ss_err;
			}

			if (net == ADHOC) {
				chan = pStatus->bssdb[idx].channel;
				if ( mib_set( MIB_WLAN_CHAN_NUM, (void *)&chan) == 0) {
   					strcpy(tmpBuf, "Set channel number error!");
					goto ss_err;
				}
			}
			
			wlan_setEntry(&pEntry, 0);
			mib_update(CURRENT_SETTING, CONFIG_MIB_ALL);	// update to flash

			res = idx;
			wait_time = 0;
			while (1) {
				if ( getWlJoinRequest(getWlanIfName(), &pStatus->bssdb[idx], &res) < 0 ) {
					strcpy(tmpBuf, "Join request failed!");
					goto ss_err;
				}
				if ( res == 1 ) { // wait
					if (wait_time++ > 5) {
						strcpy(tmpBuf, "connect-request timeout!");
						goto ss_err;
					}
					sleep(1);
					continue;
				}
				break;
			}

			if ( res == 2 ) // invalid index
				pMsg = "Connect failed 2!";
			else {
				wait_time = 0;
				while (1) {
					if ( getWlJoinResult(getWlanIfName(), &res) < 0 ) {
						strcpy(tmpBuf, "Get Join result failed!");
						goto ss_err;
					}
					if ( res != 0xff ) { // completed
						break;
					}
					if (wait_time++ > 10) {
						strcpy(tmpBuf, "connect timeout!");
						goto ss_err;
					}
					sleep(1);
				}

				if ( res!=STATE_Bss && res!=STATE_Ibss_Idle && res!=STATE_Ibss_Active )
					pMsg = "Connect failed 3!";
				else {
					status = 0;
					if (encrypt == WIFI_SEC_WPA
						|| encrypt == WIFI_SEC_WPA2) {
						bss_info bss;
						wait_time = 0;
						while (wait_time++ < 5) {
							getWlBssInfo(getWlanIfName(), &bss);
							if (bss.state == STATE_CONNECTED)
								break;
							sleep(1);
						}
						if (wait_time >= 5)
							status = 1;
					}
					if (status)
						pMsg = "Connect failed 4!";
					else
						pMsg = "Connect successfully!";
				}
			}
			OK_MSG1(pMsg, submitUrl);
		}
	}
	return;

ss_err:
	ERR_MSG(tmpBuf);
}

/////////////////////////////////////////////////////////////////////////////
int wlSiteSurveyTbl(int eid, request * wp, int argc, char **argv)
{
	int nBytesSent=0, i;
	BssDscr *pBss;
	char tmpBuf[100], ssidbuf[40];
	WLAN_MODE_T mode;
	unsigned char mib_mode;
	bss_info bss;
	MIB_CE_MBSSIB_T Entry;
	if (pStatus==NULL) {
		pStatus = calloc(1, sizeof(SS_STATUS_T));
		if ( pStatus == NULL ) {
			printf("Allocate buffer failed!\n");
			return 0;
		}
	}

	pStatus->number = 0; // request BSS DB

	if ( getWlSiteSurveyResult(getWlanIfName(), pStatus) < 0 ) {
		ERR_MSG("Read site-survey status failed!");
		free(pStatus);
		pStatus = NULL;
		return 0;
	}
	wlan_getEntry((void *)&Entry, 0);
	mode=Entry.wlanMode;
	if ( getWlBssInfo(getWlanIfName(), &bss) < 0) {
		printf("Get bssinfo failed!");
		return 0;
	}

	nBytesSent += boaWrite(wp, "<tr>"
	"<td align=center width=\"30%%\" bgcolor=\"#808080\"><font size=\"2\"><b>SSID</b></font></td>\n"
	"<td align=center width=\"20%%\" bgcolor=\"#808080\"><font size=\"2\"><b>BSSID</b></font></td>\n"
	"<td align=center width=\"10%%\" bgcolor=\"#808080\"><font size=\"2\"><b>%s</b></font></td>\n"
      	"<td align=center width=\"10%%\" bgcolor=\"#808080\"><font size=\"2\"><b>%s</b></font></td>\n"
      	"<td align=center width=\"10%%\" bgcolor=\"#808080\"><font size=\"2\"><b>%s</b></font></td>\n"
	"<td align=center width=\"10%%\" bgcolor=\"#808080\"><font size=\"2\"><b>%s</b></font></td>\n",
	multilang_bpas("Channel"), multilang_bpas("Type"), multilang_bpas("Encryption"), multilang_bpas("Signal"));
	if ( mode == CLIENT_MODE )
		nBytesSent += boaWrite(wp, "<td align=center width=\"10%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Select</b></font></td></tr>\n");
	else
		nBytesSent += boaWrite(wp, "</tr>\n");

	for (i=0; i<pStatus->number && pStatus->number!=0xff; i++) {
		pBss = &pStatus->bssdb[i];
		snprintf(tmpBuf, 200, "%02x:%02x:%02x:%02x:%02x:%02x",
			pBss->bssid[0], pBss->bssid[1], pBss->bssid[2],
			pBss->bssid[3], pBss->bssid[4], pBss->bssid[5]);

		//memcpy(ssidbuf, pBss->bdSsIdBuf, pBss->bdSsId.Length);
		//ssidbuf[pBss->bdSsId.Length] = '\0';
		memcpy(ssidbuf, pBss->ssid, pBss->ssidlen>=SSID_LEN?SSID_LEN-1:pBss->ssidlen);
		ssidbuf[pBss->ssidlen>=SSID_LEN?SSID_LEN-1:pBss->ssidlen] = '\0';

		nBytesSent += boaWrite(wp, "<tr>"
			"<td align=left width=\"20%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
			"<td align=center width=\"20%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
      			"<td align=center width=\"10%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%d</td>\n"
      			"<td align=center width=\"10%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
			"<td align=center width=\"10%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
			"<td align=center width=\"10%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%d</td>\n",
			ssidbuf, tmpBuf, pBss->channel,
			((pBss->capability & cIBSS) ? "Ad hoc" : "AP"),
			multilang_bpas((pBss->capability & cPrivacy) ? "Yes" : "No"), pBss->rssi);

		if ( mode == CLIENT_MODE )
			nBytesSent += boaWrite(wp,
			"<td align=center width=\"10%%\" bgcolor=\"#C0C0C0\"><input type=\"radio\" name="
			"\"select\" value=\"sel%d\" onClick=\"enableConnect()\"></td></tr>\n", i);
		else
			nBytesSent += boaWrite(wp, "</tr>\n");
	}

	return nBytesSent;
}
#endif	// of WLAN_CLIENT


#ifdef WLAN_WDS
/////////////////////////////////////////////////////////////////////////////
void formWlWds(request * wp, char *path, char *query)
{
	char *strAddMac, *strDelMac, *strDelAllMac, *strVal, *submitUrl, *strEnabled, *strSet, *strRate;
	char tmpBuf[100];
	int  i,idx;
	WDS_T macEntry;
	WDS_T Entry;
	unsigned char entryNum,enabled,delNum=0;

	strSet = boaGetVar(wp, "wdsSet", "");
	strAddMac = boaGetVar(wp, "addWdsMac", "");
	strDelMac = boaGetVar(wp, "deleteSelWdsMac", "");
	strDelAllMac = boaGetVar(wp, "deleteAllWdsMac", "");
	strEnabled = boaGetVar(wp, "wlanWdsEnabled", "");

#if defined(CONFIG_RTL_92D_SUPPORT) || defined(WLAN_DUALBAND_CONCURRENT)
	strVal = boaGetVar(wp, "wlan_idx", "");
	if ( strVal[0] ) {
		printf("wlan_idx=%d\n", strVal[0]-'0');
		wlan_idx = strVal[0]-'0';
	}
#endif //CONFIG_RTL_92D_SUPPORT || WLAN_DUALBAND_CONCURRENT

	if (strSet[0]) {
		if (!gstrcmp(strEnabled, "ON")){
			enabled = 1;
		}
		else
			enabled = 0;
		if (mib_set( MIB_WLAN_WDS_ENABLED, (void *)&enabled) == 0) {
  			strcpy(tmpBuf, strSetEnableErr);
			goto setErr_wds;
		}
	}

	if (strAddMac[0]) {
		int intVal;
		/*if ( !gstrcmp(strEnabled, "ON")){
			enabled = 1;
		}
		else
			enabled = 0;
		if ( mib_set( MIB_WLAN_WDS_ENABLED, (void *)&enabled) == 0) {
  			strcpy(tmpBuf, strSetEnableErr);
			goto setErr_wds;
		}*/
		strVal = boaGetVar(wp, "mac", "");
		if ( !strVal[0] )
			goto setWds_ret;

		if (strlen(strVal)!=12 || !string_to_hex(strVal, macEntry.macAddr, 12)) {
			strcpy(tmpBuf, strInvdMACAddr);
			goto setErr_wds;
		}
		if (!isValidMacAddr(macEntry.macAddr)) {
			strcpy(tmpBuf, strInvdMACAddr);
			goto setErr_wds;
		}

		strVal = boaGetVar(wp, "comment", "");
		if ( strVal[0] ) {
			if (strlen(strVal) > COMMENT_LEN-1) {
				strcpy(tmpBuf, strCommentTooLong);
				goto setErr_wds;
			}
			strcpy(macEntry.comment, strVal);
		}
		else
			macEntry.comment[0] = '\0';
		strRate = boaGetVar(wp, "txRate", "");
		if ( strRate[0] ) {
			if ( strRate[0] == '0' ) { // auto
				macEntry.fixedTxRate =0;
			}else  {
				intVal = atoi(strRate);
				intVal = 1 << (intVal-1);
				macEntry.fixedTxRate = intVal;
			}
		}

		if ( !mib_get(MIB_WLAN_WDS_NUM, (void *)&entryNum)) {
			strcpy(tmpBuf, strGetEntryNumErr);
			goto setErr_wds;
		}
		if ( (entryNum + 1) > MAX_WDS_NUM) {
			strcpy(tmpBuf, strErrForTablFull);
			goto setErr_wds;
		}

		// Jenny added, set to MIB. Check if entry exists
		for (i=0; i<entryNum; i++) {
			if (!mib_chain_get(MIB_WDS_TBL, i, (void *)&Entry)) {
	  			boaError(wp, 400, "Get chain record error!\n");
				return;
			}
			if (!memcmp(macEntry.macAddr, Entry.macAddr, 6)) {
				strcpy(tmpBuf, strMACInList);
				goto setErr_wds;
			}
		}

		// set to MIB. try to delete it first to avoid duplicate case
		//mib_set(MIB_WLAN_WDS_DEL, (void *)&macEntry);
		intVal = mib_chain_add(MIB_WDS_TBL, (void *)&macEntry);
		if (intVal == 0) {
			strcpy(tmpBuf, strAddEntryErr);
			goto setErr_wds;
		}
		else if (intVal == -1) {
			strcpy(tmpBuf, strTableFull);
			goto setErr_wds;
		}
		entryNum++;
		if ( !mib_set(MIB_WLAN_WDS_NUM, (void *)&entryNum)) {
			strcpy(tmpBuf, strGetEntryNumErr);
			goto setErr_wds;
		}
	}

	/* Delete entry */
	delNum=0;
	if (strDelMac[0]) {
		if ( !mib_get(MIB_WLAN_WDS_NUM, (void *)&entryNum)) {
			strcpy(tmpBuf, strGetEntryNumErr);
			goto setErr_wds;
		}
		for (i=0; i<entryNum; i++) {

			idx = entryNum-i-1;
			snprintf(tmpBuf, 20, "select%d", idx);
			strVal = boaGetVar(wp, tmpBuf, "");

			if ( !gstrcmp(strVal, "ON") ) {
				if(mib_chain_delete(MIB_WDS_TBL, idx) != 1) {
					strcpy(tmpBuf, strDelRecordErr);
				}
				delNum++;
			}
		}
		entryNum-=delNum;
		if ( !mib_set(MIB_WLAN_WDS_NUM, (void *)&entryNum)) {
			strcpy(tmpBuf, strGetEntryNumErr);
			goto setErr_wds;
		}
		if (delNum <= 0) {
			strcpy(tmpBuf, "There is no item selected to delete!");
			goto setErr_wds;
		}
	}

	/* Delete all entry */
	if ( strDelAllMac[0]) {
		mib_chain_clear(MIB_WDS_TBL); /* clear chain record */

		entryNum=0;
		if ( !mib_set(MIB_WLAN_WDS_NUM, (void *)&entryNum)) {
			strcpy(tmpBuf, strGetEntryNumErr);
			goto setErr_wds;
		}

	}

setWds_ret:
	config_WLAN(ACT_RESTART, CONFIG_SSID_ALL);
// Magician: Commit immediately
#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif // of #if COMMIT_IMMEDIATELY

#ifndef NO_ACTION
	run_script(-1);
#endif

	submitUrl = boaGetVar(wp, "submit-url", "");   // hidden page
	OK_MSG( submitUrl );
	return;

setErr_wds:
	ERR_MSG(tmpBuf);
}

void formWdsEncrypt(request * wp, char *path, char *query)
{
	char *strVal, *submitUrl;
	unsigned char tmpBuf[100];
	unsigned char encrypt;
	unsigned char intVal, keyLen=0, oldFormat, oldPskLen, len, i;
	char charArray[16]={'0' ,'1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
	char key[100];
	char varName[20];
	sprintf(varName, "encrypt%d", wlan_idx);
	strVal = boaGetVar(wp, varName, "");
	if (strVal[0]) {
		encrypt = strVal[0] - '0';
		if (encrypt != WDS_ENCRYPT_DISABLED && encrypt != WDS_ENCRYPT_WEP64 &&
			encrypt != WDS_ENCRYPT_WEP128 && encrypt != WDS_ENCRYPT_TKIP &&
				encrypt != WDS_ENCRYPT_AES) {
			strcpy(tmpBuf, "encrypt value not validt!");
			goto setErr_wdsEncrypt;
		}
		if ( !mib_set(MIB_WLAN_WDS_ENCRYPT, (void *)&encrypt)) {
			strcpy(tmpBuf, strGetEntryNumErr);
			goto setErr_wdsEncrypt;
		}
	}
	else{
		if ( !mib_get(MIB_WLAN_WDS_ENCRYPT, (void *)&encrypt)) {
			strcpy(tmpBuf, strGetEntryNumErr);
			goto setErr_wdsEncrypt;
		}
	}
	if (encrypt == WDS_ENCRYPT_WEP64 || encrypt == WDS_ENCRYPT_WEP128) {
		sprintf(varName, "format%d", wlan_idx);
		strVal = boaGetVar(wp, varName, "");
		if (strVal[0]) {
			if (strVal[0]!='0' && strVal[0]!='1') {
				strcpy(tmpBuf, "Invalid wep key format value!");
				goto setErr_wdsEncrypt;
			}
			intVal = strVal[0] - '0';
			if ( !mib_set(MIB_WLAN_WDS_WEP_FORMAT, (void *)&intVal)) {
				strcpy(tmpBuf, strGetEntryNumErr);
				goto setErr_wdsEncrypt;
			}
		}
		else{
			if ( !mib_get(MIB_WLAN_WDS_WEP_FORMAT, (void *)&intVal)) {
				strcpy(tmpBuf, strGetEntryNumErr);
				goto setErr_wdsEncrypt;
			}
		}
		if (encrypt == WDS_ENCRYPT_WEP64)
			keyLen = WEP64_KEY_LEN;
		else if (encrypt == WDS_ENCRYPT_WEP128)
			keyLen = WEP128_KEY_LEN;
		if (intVal == 1) // hex
			keyLen <<= 1;
		sprintf(varName, "wepKey%d", wlan_idx);
		strVal = boaGetVar(wp, varName, "");
		if(strVal[0]) {
			if (strlen(strVal) != keyLen) {
				strcpy(tmpBuf, "Invalid wep key length!");
				goto setErr_wdsEncrypt;
			}
			if ( !isAllStar(strVal) ) {
				if (intVal == 0) { // ascii
					for (i=0; i<keyLen; i++) {
						key[i*2] = charArray[(strVal[i]>>4)&0xf];
						key[i*2+1] = charArray[strVal[i]&0xf];
					}
					key[i*2] = '\0';
				}
				else  // hex
					strcpy(key, strVal);
				if ( !mib_set(MIB_WLAN_WDS_WEP_KEY, (void *)key)) {
					strcpy(tmpBuf, strGetEntryNumErr);
					goto setErr_wdsEncrypt;
				}
			}
		}
	}
	if (encrypt == WDS_ENCRYPT_TKIP || encrypt == WDS_ENCRYPT_AES) {
		sprintf(varName, "pskFormat%d", wlan_idx);
		strVal = boaGetVar(wp, varName, "");
		if (strVal[0]) {
			if (strVal[0]!='0' && strVal[0]!='1') {
				strcpy(tmpBuf, "Invalid wep key format value!");
				goto setErr_wdsEncrypt;
			}
			intVal = strVal[0] - '0';
		}
		else{
			if ( !mib_get(MIB_WLAN_WDS_PSK_FORMAT, (void *)&intVal)) {
				strcpy(tmpBuf, strGetEntryNumErr);
				goto setErr_wdsEncrypt;
			}
		}
		if ( !mib_get(MIB_WLAN_WDS_PSK_FORMAT, (void *)&oldFormat)) {
			strcpy(tmpBuf, strGetEntryNumErr);
			goto setErr_wdsEncrypt;
		}
		if ( !mib_get(MIB_WLAN_WDS_PSK, (void *)tmpBuf)) {
			strcpy(tmpBuf, strGetEntryNumErr);
			goto setErr_wdsEncrypt;
		}
		oldPskLen = strlen(tmpBuf);
		sprintf(varName, "pskValue%d", wlan_idx);
		strVal = boaGetVar(wp, varName, "");
		len = strlen(strVal);
		if (len > 0 && oldFormat == intVal && len == oldPskLen ) {
			for (i=0; i<len; i++) {
				if ( strVal[i] != '*' )
				break;
			}
			if (i == len)
				goto save_wdsEcrypt;
		}
		if (intVal==1) { // hex
			if (len!=MAX_PSK_LEN || !string_to_hex(strVal, tmpBuf, MAX_PSK_LEN)) {
				strcpy(tmpBuf, "Error! invalid psk value.");
				goto setErr_wdsEncrypt;
			}
		}
		else { // passphras
			if (len==0 || len > (MAX_PSK_LEN-1) ) {
				strcpy(tmpBuf, "Error! invalid psk value.");
				goto setErr_wdsEncrypt;
			}
		}
		if ( !mib_set(MIB_WLAN_WDS_PSK_FORMAT, (void *)&intVal)) {
			strcpy(tmpBuf, strGetEntryNumErr);
			goto setErr_wdsEncrypt;
		}
		if ( !mib_set(MIB_WLAN_WDS_PSK, (void *)strVal)) {
			strcpy(tmpBuf, strGetEntryNumErr);
			goto setErr_wdsEncrypt;
		}
	}
save_wdsEcrypt:
	{
		unsigned char enable = 1;
		if ( !mib_set(MIB_WLAN_WDS_ENABLED, (void *)&enable)) {
			strcpy(tmpBuf, strGetEntryNumErr);
			goto setErr_wdsEncrypt;
		}
	}
	config_WLAN(ACT_RESTART, CONFIG_SSID_ALL);
#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif // of #if COMMIT_IMMEDIATELY
	submitUrl = boaGetVar(wp, "submit-url", "");   // hidden page
	OK_MSG(submitUrl);
	return;
setErr_wdsEncrypt:
	ERR_MSG(tmpBuf);
}

/////////////////////////////////////////////////////////////////////////////
int wlWdsList(int eid, request * wp, int argc, char **argv)
{
	int nBytesSent=0, i;
	WDS_T entry;
	char tmpBuf[100];
	char txrate[20];
	unsigned char entryNum;
	WDS_T Entry;
	int rateid = 0;

	if ( !mib_get(MIB_WLAN_WDS_NUM, (void *)&entryNum)) {
  		boaError(wp, 400, "Get table entry error!\n");
		return -1;
	}
//modified by xl_yue
	nBytesSent += boaWrite(wp, "<tr>"
      	"<td align=center width=\"20%%\" bgcolor=\"#808080\"><font size=\"2\"><b>%s</b></font></td>\n"
      	"<td align=center width=\"45%%\" bgcolor=\"#808080\"><font size=\"2\"><b>%s</b></font></td>\n"
      	"<td align=center width=\"25%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Tx Rate (Mbps)</b></font></td>\n"
      	"<td align=center width=\"35%%\" bgcolor=\"#808080\"><font size=\"2\"><b>%s</b></font></td></tr>\n",
	multilang_bpas(strSelect), multilang_bpas(strMACAddr), multilang_bpas(strWdsComment));

	for (i=0; i<entryNum; i++) {
		*((char *)&entry) = (char)i;
		if (!mib_chain_get(MIB_WDS_TBL, i, (void *)&Entry)) {
  			boaError(wp, 400, errGetEntry);
			return -1;
		}
		snprintf(tmpBuf, 100, "%02x:%02x:%02x:%02x:%02x:%02x",
			Entry.macAddr[0], Entry.macAddr[1], Entry.macAddr[2],
			Entry.macAddr[3], Entry.macAddr[4], Entry.macAddr[5]);

		//strcpy(txrate, "N/A");
		if(Entry.fixedTxRate == 0){
			sprintf(txrate, "%s","Auto");
		}
		else{
			for(rateid=0; rateid<28;rateid++){
				if(tx_fixed_rate[rateid].id == Entry.fixedTxRate){
					sprintf(txrate, "%s", tx_fixed_rate[rateid].rate);
					break;
				}
			}
		}

		nBytesSent += boaWrite(wp, "<tr>"
			"<td align=center width=\"20%%\" bgcolor=\"#C0C0C0\"><input type=\"checkbox\" name=\"select%d\" value=\"ON\"></td>\n"
			"<td align=center width=\"45%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
			"<td align=center width=\"25%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
			"<td align=center width=\"35%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td></tr>\n",
			i, tmpBuf, txrate, Entry.comment);
	}
	return nBytesSent;
}

int wdsList(int eid, request * wp, int argc, char **argv)
{
	int nBytesSent=0, i;
	WDS_INFO_Tp pInfo;
	char *buff;

	buff = calloc(1, sizeof(WDS_INFO_T)*MAX_WDS_NUM);
	if ( buff == 0 ) {
		printf("Allocate buffer failed!\n");
		return 0;
	}

	if ( getWdsInfo(getWlanIfName(), buff) < 0 ) {
		printf("Read wlan sta info failed!\n");
		return 0;
	}

	for (i=0; i<MAX_WDS_NUM; i++) {
		pInfo = (WDS_INFO_Tp)&buff[i*sizeof(WDS_INFO_T)];

		if (pInfo->state == STATE_WDS_EMPTY)
			break;

		nBytesSent += boaWrite(wp,
	   		"<tr bgcolor=#b7b7b7><td><font size=2>%02x:%02x:%02x:%02x:%02x:%02x</td>"
			"<td><font size=2>%d</td>"
	     		"<td><font size=2>%d</td>"
			"<td><font size=2>%d</td>"
			"<td><font size=2>%d%s</td></tr>",
			pInfo->addr[0],pInfo->addr[1],pInfo->addr[2],pInfo->addr[3],pInfo->addr[4],pInfo->addr[5],
			pInfo->tx_packets, pInfo->tx_errors, pInfo->rx_packets,
			pInfo->txOperaRate/2, ((pInfo->txOperaRate%2) ? ".5" : "" ));
	}

	free(buff);

	return nBytesSent;
}
#endif // WLAN_WDS

#ifdef CONFIG_WIFI_SIMPLE_CONFIG // WPS
#define _WSC_DAEMON_PROG       "/bin/wscd"
#define WLAN_IF  "wlan0"

#define OK_MSG2(msg, msg1, url) { \
        char tmp[200]; \
        sprintf(tmp, msg, msg1); \
        OK_MSG1(tmp, url); \
}
#define START_PBC_MSG \
        "Start PBC successfully!<br><br>" \
        "You have to run Wi-Fi Protected Setup in %s within 2 minutes."
#define START_PIN_MSG \
        "Start PIN successfully!<br><br>" \
        "You have to run Wi-Fi Protected Setup in %s within 2 minutes."
#define SET_PIN_MSG \
        "Applied client's PIN successfully!<br><br>" \
        "You have to run Wi-Fi Protected Setup in client within 2 minutes."
/*for WPS2DOTX brute force attack , unlock*/
#define UNLOCK_MSG \
	"Applied WPS unlock successfully!<br>"

void formWsc(request * wp, char *path, char *query)
{
	char *strVal, *submitUrl;
	char intVal;
	char tmpbuf[200];
//	int mode;
	unsigned char mode;
	MIB_CE_MBSSIB_T Entry;


#if defined(CONFIG_RTL_92D_SUPPORT) || defined(WLAN_DUALBAND_CONCURRENT)
	strVal = boaGetVar(wp, "wlan_idx", "");
	if ( strVal[0] ) {
		printf("wlan_idx=%d\n", strVal[0]-'0');
		wlan_idx = strVal[0]-'0';
	}
#endif //CONFIG_RTL_92D_SUPPORT || WLAN_DUALBAND_CONCURRENT
	wlan_getEntry((void *)&Entry, 0);
	mode = Entry.wlanMode;
	submitUrl = boaGetVar(wp, "submit-url", "");
#ifdef CONFIG_WIFI_SIMPLE_CONFIG
	// for PIN brute force attack
	strVal = boaGetVar(wp, "unlockautolockdown", "");
	if (strVal[0]) {
		va_niced_cmd(_WSC_DAEMON_PROG, 1, 1, "-sig_unlock");
		OK_MSG2(UNLOCK_MSG, ((mode==AP_MODE) ? "client" : "AP"), submitUrl);
		return;
	}

	strVal = boaGetVar(wp, "triggerPBC", "");
	if (strVal[0]) {
		if (Entry.wsc_disabled) {
			Entry.wsc_disabled = 0;
			wlan_setEntry((void *)&Entry, 0);
			mib_update(CURRENT_SETTING, CONFIG_MIB_ALL);	// update to flash
			system("echo 1 > /var/wps_start_pbc");
#ifndef NO_ACTION
			run_init_script("bridge");
#endif
		}
		else {
			//sprintf(tmpbuf, "%s -sig_pbc", _WSC_DAEMON_PROG);
			//system(tmpbuf);
			//va_niced_cmd(_WSC_DAEMON_PROG, 1, 1, "-sig_pbc");
			if(wlan_idx == 0 )
			{
				system("echo 1 > /var/wps_start_interface0");
			}
			else
			{
				system("echo 1 > /var/wps_start_interface1");

			}
			va_niced_cmd(_WSC_DAEMON_PROG, 2 , 1 , "-sig_pbc" , getWlanIfName());
		}
		OK_MSG2(START_PBC_MSG, ((mode==AP_MODE) ? "client" : "AP"), submitUrl);
		return;
	}

	strVal = boaGetVar(wp, "triggerPIN", "");
	if (strVal[0]) {
		int local_pin_changed = 0;
		strVal = boaGetVar(wp, "localPin", "");
		if (strVal[0]) {
			mib_get(MIB_WSC_PIN, (void *)tmpbuf);
			if (strcmp(tmpbuf, strVal)) {
				mib_set(MIB_WSC_PIN, (void *)strVal);
				local_pin_changed = 1;
			}
		}
		if (Entry.wsc_disabled) {
			char localpin[100];
			Entry.wsc_disabled = 0;
			wlan_setEntry((void *)&Entry, 0);
			mib_update(CURRENT_SETTING, CONFIG_MIB_ALL);	// update to flash
			system("echo 1 > /var/wps_start_pin");

#ifndef NO_ACTION
			if (local_pin_changed) {
				mib_get(MIB_WSC_PIN, (void *)localpin);
				sprintf(tmpbuf, "echo %s > /var/wps_local_pin", localpin);
				system(tmpbuf);
			}
			run_init_script("bridge");
#endif
		}
		else {
			if (local_pin_changed) {
				system("echo 1 > /var/wps_start_pin");

				mib_update(CURRENT_SETTING,CONFIG_MIB_ALL);
				//run_init_script("bridge");
			}
			else {
				va_niced_cmd(_WSC_DAEMON_PROG, 1, 0, "-sig_start");
			}
		}
		OK_MSG2(START_PIN_MSG, ((mode==AP_MODE) ? "client" : "AP"), submitUrl);
		return;
	}

	strVal = boaGetVar(wp, "setPIN", "");
	if (strVal[0]) {
		strVal = boaGetVar(wp, "peerPin", "");
		if (strVal[0]) {
			if (Entry.wsc_disabled) {
				Entry.wsc_disabled = 0;
				wlan_setEntry((void *)&Entry, 0);
				mib_update(CURRENT_SETTING, CONFIG_MIB_ALL);

				sprintf(tmpbuf, "echo %s > /var/wps_peer_pin", strVal);
				system(tmpbuf);

#ifndef NO_ACTION
				run_init_script("bridge");
#endif
			}
			else {
				//sprintf(tmpbuf, "iwpriv %s set_mib pin=%s", WLAN_IF, strVal);
				//system(tmpbuf);
				if(wlan_idx == 0 )
				{
					system("echo 1 > /var/wps_start_interface0");
				}
				else
				{
					system("echo 1 > /var/wps_start_interface1");
				}
				sprintf(tmpbuf, "pin=%s", strVal);
				va_cmd("/bin/iwpriv", 3, 1, getWlanIfName(), "set_mib", tmpbuf);
			}
			OK_MSG1(SET_PIN_MSG, submitUrl);
			return;
		}
	}

	strVal = boaGetVar(wp, "disableWPS", "");
	if ( !gstrcmp(strVal, "ON"))
		intVal = 1;
	else
		intVal = 0;
	Entry.wsc_disabled = intVal;
	wlan_setEntry((void *)&Entry, 0);
	update_wps_mib();

	strVal = boaGetVar(wp, "localPin", "");
	if (strVal[0])
		mib_set(MIB_WSC_PIN, (void *)strVal);
#endif
//	update_wps_configured(0);
	config_WLAN(ACT_RESTART, CONFIG_SSID_ALL);

#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif // of #if COMMIT_IMMEDIATELY

#ifndef NO_ACTION
	run_init_script("bridge");
#endif

	OK_MSG(submitUrl);
}
#endif

int wlStatsList(int eid, request * wp, int argc, char **argv)
{
	int i, intf_num = 0, orig_wlan_idx;
	char ssid[MAX_SSID_LEN];
	struct net_device_stats nds;
	MIB_CE_MBSSIB_T entry;
#ifdef WLAN_MBSSID
	int j;
	char vapname[15];
#endif
	unsigned char wlan_module_disabled;
	//_TRACE_CALL;

//	if (!wlan_is_up()) {
//		return -1;
//	}
#ifndef YUEME_3_0_SPEC
	mib_get(MIB_WIFI_MODULE_DISABLED, (void *)&wlan_module_disabled);
	if(wlan_module_disabled==1)
		return -1;
#endif

	orig_wlan_idx = wlan_idx;

	//process each wlan interface
	for (i = 0; i < NUM_WLAN_INTERFACE; i++) {
		wlan_idx = i;
#ifdef YUEME_3_0_SPEC
		mib_get(MIB_WLAN_DISABLED, (void *)&wlan_module_disabled);
		if(wlan_module_disabled==1)
			continue;
#endif
		
#if defined(CONFIG_RTL_STA_CONTROL_SUPPORT) && defined(WLAN_DUALBAND_CONCURRENT)
		unsigned char wlan_sta_control=0;
		if(wlan_idx == 1){
			mib_get(MIB_WIFI_STA_CONTROL, (void *)&wlan_sta_control);
			if(wlan_sta_control==1)
				wlan_idx = 0;
		}
#endif
		wlan_getEntry(&entry, 0);

#if defined(CONFIG_RTL_STA_CONTROL_SUPPORT) && defined(WLAN_DUALBAND_CONCURRENT)
		wlan_idx = i;
#endif
		if (!entry.wlanDisabled && getInFlags(getWlanIfName(), 0)) {
		get_wlan_net_device_stats(getWlanIfName(), &nds);
		boaWrite(wp, "rcs.push(new it_nr(\"%d\""
			 _PTS _PTUL _PTUL
			 _PTUL _PTUL _PTUL
			 _PTUL _PTUL _PTUL "));\n",
			 intf_num, "ifname", entry.ssid,
			 "rx_packets", nds.rx_packets,
			 "rx_bytes", nds.rx_bytes,
			 "rx_errors", nds.rx_errors,
			 "rx_dropped", nds.rx_dropped,
			 "tx_packets", nds.tx_packets,
			 "tx_bytes", nds.tx_bytes,
			 "tx_errors", nds.tx_errors,
			 "tx_dropped", nds.tx_dropped);
		intf_num++;
		}

#ifdef WLAN_MBSSID
		/* append wlan0-vapX to names if not disabled */
		for (j = 0; j < WLAN_MBSSID_NUM; j++) {
			mib_chain_get(MIB_MBSSIB_TBL, j + 1, &entry);
			if (entry.wlanDisabled) {
				continue;
			}
			sprintf(vapname, "%s-vap%d", getWlanIfName(), j);
			if(getInFlags(vapname, 0)==0)
				continue;
			get_wlan_net_device_stats(vapname, &nds);
			boaWrite(wp, "rcs.push(new it_nr(\"%d\""
				 _PTS _PTUL _PTUL
				 _PTUL _PTUL _PTUL
				 _PTUL _PTUL _PTUL "));\n",
				 intf_num, "ifname", entry.ssid,
				 "rx_packets", nds.rx_packets,
				 "rx_bytes", nds.rx_bytes,
				 "rx_errors", nds.rx_errors,
				 "rx_dropped", nds.rx_dropped,
				 "tx_packets", nds.tx_packets,
				 "tx_bytes", nds.tx_bytes,
				 "tx_errors", nds.tx_errors,
				 "tx_dropped", nds.tx_dropped);
			intf_num++;
		}
#endif
	}
	wlan_idx = orig_wlan_idx;
check_err:
	//_TRACE_LEAVEL;
	return 0;
}
#ifdef WIFI_TIMER_SCHEDULE
/////////////////////////////////////////////////////////////////////////////
void formWifiTimerEx(request * wp, char *path, char *query)
{
	char *strVal, *strVal2, *submitUrl;
	char tmpBuf[100];
	unsigned char vChar;
	int i, val, action;
	MIB_CE_WIFI_TIMER_EX_T Entry;

	strVal  = boaGetVar(wp, "action", "");
	if(strVal[0]){
		action = strVal[0] - '0';
	}
	else
		goto setErr_wlsched;

	if(!action){
		strVal  = boaGetVar(wp, "if_index", "");
		if (!strVal[0]) 
			goto setErr_wlsched;
		vChar = strVal[0] - '0';
		if(mib_chain_delete(MIB_WIFI_TIMER_EX_TBL, vChar) == 0){
			goto setErr_wlsched;
		}
		goto setwlsched_ret;
	}
	else{
		if(action == 2){
			
			strVal  = boaGetVar(wp, "if_index", "");
			if (!strVal[0]) {
				goto setErr_wlsched;
			}
			i = strVal[0] - '0';
		}

		strVal = boaGetVar(wp, "Fnt_Active", "");

		if ( !gstrcmp(strVal, "ON") )
			Entry.enable = 1;
		else
			Entry.enable = 0;

		strVal = boaGetVar(wp, "Fnt_Enable", "");
		if (!strVal[0]) {
			goto setErr_wlsched;
		}

		Entry.onoff = strVal[0] - '0';

		strVal = boaGetVar(wp, "Frm_Start1", "");
		if (!strVal[0]) {
			goto setErr_wlsched;
		}

		strVal2 = boaGetVar(wp, "Frm_Start2", "");
		if (!strVal2[0]) {
			goto setErr_wlsched;
		}

		snprintf(Entry.Time, 6,"%s:%s", strVal, strVal2);

		vChar = 0;
		strVal  = boaGetVar(wp, "Frm_Monday_S", "");
		if ( !gstrcmp(strVal, "ON") )
			vChar |=(1<<1);
		strVal  = boaGetVar(wp, "Frm_Tuesday_S", "");
		if ( !gstrcmp(strVal, "ON") )
			vChar |=(1<<2);
		strVal  = boaGetVar(wp, "Frm_Wednesday_S", "");
		if ( !gstrcmp(strVal, "ON") )
			vChar |=(1<<3);
		strVal  = boaGetVar(wp, "Frm_Thursday_S", "");
		if ( !gstrcmp(strVal, "ON") )
			vChar |=(1<<4);
		strVal  = boaGetVar(wp, "Frm_Friday_S", "");
		if ( !gstrcmp(strVal, "ON") )
			vChar |=(1<<5);
		strVal  = boaGetVar(wp, "Frm_Saturday_S", "");
		if ( !gstrcmp(strVal, "ON") )
			vChar |=(1<<6);
		strVal  = boaGetVar(wp, "Frm_Sunday_S", "");
		if ( !gstrcmp(strVal, "ON") )
			vChar |=(1<<7);

		Entry.day = vChar;

		strVal = boaGetVar(wp, "ssid_mask", "");
		if (!strVal[0]) {
			goto setwlsched_ret;
		}
		Entry.SSIDMask = atoi(strVal);

		if(action == 2){
			if(mib_chain_update(MIB_WIFI_TIMER_EX_TBL, &Entry, i) == 0){
				goto setErr_wlsched;
			}
		}
		else{
			if(mib_chain_add(MIB_WIFI_TIMER_EX_TBL, &Entry) == 0){
				goto setErr_wlsched;
			}
		}
		goto setwlsched_ret;
	}

setwlsched_ret:
	
// Magician: Commit immediately
#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif // of #if COMMIT_IMMEDIATELY

#ifndef NO_ACTION
	run_script(-1);
#endif

	updateScheduleCrondFile("/var/spool/cron/crontabs", 0);

	submitUrl = boaGetVar(wp, "submit-url", "");   // hidden page
	//OK_MSG( submitUrl );
	if (submitUrl[0])
		boaRedirect(wp, submitUrl);
	else
		boaDone(wp, 200);
  	return;

setErr_wlsched:
	ERR_MSG(tmpBuf);
}

/////////////////////////////////////////////////////////////////////////////
void formWifiTimer(request * wp, char *path, char *query)
{
	char *strVal, *strVal2, *submitUrl;
	char tmpBuf[100];
	char vChar;
	int i, val, action;
	MIB_CE_WIFI_TIMER_T Entry;

	strVal  = boaGetVar(wp, "action", "");
	if(strVal[0]){
		action = strVal[0] - '0';
	}
	else
		goto setErr_wltimer;

	if(!action){
		strVal  = boaGetVar(wp, "if_index", "");
		if (!strVal[0]) 
			goto setErr_wltimer;
		vChar = strVal[0] - '0';
		if(mib_chain_delete(MIB_WIFI_TIMER_TBL, vChar) == 0){
			goto setErr_wltimer;
		}
		goto setwlsched_ret;
	}
	else{
		if(action == 2){
			
			strVal  = boaGetVar(wp, "if_index", "");
			if (!strVal[0]) {
				goto setErr_wltimer;
			}
			i = strVal[0] - '0';
		}

		strVal = boaGetVar(wp, "Fnt_Active", "");

		if ( !gstrcmp(strVal, "ON") )
			Entry.enable = 1;
		else
			Entry.enable = 0;

		strVal = boaGetVar(wp, "Frm_Start1", "");
		if (!strVal[0]) {
			goto setErr_wltimer;
		}
		
		strVal2 = boaGetVar(wp, "Frm_Start2", "");
		if (!strVal2[0]) {
			goto setErr_wltimer;
		}

		snprintf(Entry.startTime, 6,"%02d:%02d", atoi(strVal), atoi(strVal2));

		strVal = boaGetVar(wp, "Frm_End1", "");
		if (!strVal[0]) {
			goto setErr_wltimer;
		}
		
		strVal2 = boaGetVar(wp, "Frm_End2", "");
		if (!strVal2[0]) {
			goto setErr_wltimer;
		}

		snprintf(Entry.endTime, 6,"%02d:%02d", atoi(strVal), atoi(strVal2));
#if 0
		strVal = boaGetVar(wp, "Frm_Day", "");
		if (!strVal[0]) {
			goto setErr_wltimer;
		}

		string_to_dec(strVal, &val);
		Entry.controlCycle = (unsigned char) val;	
#endif
		Entry.controlCycle = 1;

		strVal = boaGetVar(wp, "ssid_mask", "");
		if (!strVal[0]) {
			goto setErr_wltimer;
		}
		Entry.SSIDMask = atoi(strVal);

		if(action == 2){
			if(mib_chain_update(MIB_WIFI_TIMER_TBL, &Entry, i) == 0){
				goto setErr_wltimer;
			}
		}
		else{
			if(mib_chain_add(MIB_WIFI_TIMER_TBL, &Entry) == 0){
				goto setErr_wltimer;
			}
		}
		goto setwlsched_ret;
	}

setwlsched_ret:
	
// Magician: Commit immediately
#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif // of #if COMMIT_IMMEDIATELY

#ifndef NO_ACTION
	run_script(-1);
#endif

	updateScheduleCrondFile("/var/spool/cron/crontabs", 0);

	submitUrl = boaGetVar(wp, "submit-url", "");   // hidden page
	//OK_MSG( submitUrl );
	if (submitUrl[0])
		boaRedirect(wp, submitUrl);
	else
		boaDone(wp, 200);
  	return;

setErr_wltimer:
	ERR_MSG(tmpBuf);
}

int ShowWifiTimerMask(int eid, request * wp, int argc, char **argv)
{
#ifdef WLAN_SUPPORT
	int i;

	int orig_wlan_idx = wlan_idx;
	int j;
#ifdef YUEME_3_0_SPEC_SSID_ALIAS
	unsigned char phyband = PHYBAND_2G;
#endif
	for(j=0; j<NUM_WLAN_INTERFACE;j++){
		wlan_idx = j;
#ifdef YUEME_3_0_SPEC_SSID_ALIAS
#ifdef WLAN_DUALBAND_CONCURRENT
		mib_get(MIB_WLAN_PHY_BAND_SELECT, &phyband);
#endif
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

#ifdef CTCOM_WLAN_REQ
			if(entry.instnum==0){
				boaWrite(wp, "<input type=hidden name=chkpt>\n");
				continue;
			}
#endif
			showNum++;

			if (!(showNum & 0x1))
				boaWrite(wp, "<tr nowrap>");

#ifdef YUEME_3_0_SPEC_SSID_ALIAS
			boaWrite(wp, "<td><input type=\"checkbox\" name=\"chkpt\">无线(%s-%d)</td>",  phyband==PHYBAND_2G? "2.4G":"5G", (i+2));
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
	}
	wlan_idx = orig_wlan_idx;
#ifndef WLAN_DUALBAND_CONCURRENT
	for(i=0; i<(1+WLAN_MBSSID_NUM); i++)
		boaWrite(wp, "<input type=hidden name=chkpt>\n");
#endif
#endif
}

#endif

#ifdef WLAN_11R
extern char FT_DAEMON_PROG[];
void formFt(request * wp, char *path, char *query)
{
	char *strVal, *submitUrl;
	char tmpbuf[200];
	MIB_CE_MBSSIB_T Entry;
	MIB_CE_WLAN_FTKH_T khEntry, getEntry;
	int idx, i, entryNum, intVal, deleted=0;

	submitUrl = boaGetVar(wp, "submit-url", "");
#if defined(CONFIG_RTL_92D_SUPPORT) || defined(WLAN_DUALBAND_CONCURRENT)
	strVal = boaGetVar(wp, "wlan_idx", "");
	if ( strVal[0] ) {
		printf("wlan_idx=%d\n", strVal[0]-'0');
		wlan_idx = strVal[0]-'0';
	}
#endif //CONFIG_RTL_92D_SUPPORT || WLAN_DUALBAND_CONCURRENT

	// check which interface is selected
	strVal = boaGetVar(wp, "ftSSID", "");
	if (strVal[0]) {
		idx = strVal[0]-'0';
		if (idx<0 || idx > NUM_VWLAN_INTERFACE) {
			strcpy(tmpbuf, strNotSuptSSIDType);
			goto setErr_ft;
		}
	} else {
		strcpy(tmpbuf, strNoSSIDTypeErr);
		goto setErr_ft;
	}

	if (!wlan_getEntry((void *)&Entry, idx)) {
		strcpy(tmpbuf, strGetMBSSIBTBLErr);
		goto setErr_ft;
	}

	// for driver configurateion
	strVal = boaGetVar(wp, "ftSaveConfig", "");
	if (strVal[0]) {
		// 802.11r related settings
		strVal = boaGetVar(wp, "ft_enable", "");
		if (strVal[0])
			Entry.ft_enable = atoi(strVal);

		strVal = boaGetVar(wp, "ft_mdid", "");
		if (strVal[0])
			strncpy(Entry.ft_mdid, strVal, 4);

		strVal = boaGetVar(wp, "ft_over_ds", "");
		if (strVal[0])
			Entry.ft_over_ds = atoi(strVal);

		strVal = boaGetVar(wp, "ft_res_request", "");
		if (strVal[0])
			Entry.ft_res_request = atoi(strVal);

		strVal = boaGetVar(wp, "ft_r0key_timeout", "");
		if (strVal[0])
			Entry.ft_r0key_timeout = atoi(strVal);

		strVal = boaGetVar(wp, "ft_reasoc_timeout", "");
		if (strVal[0])
			Entry.ft_reasoc_timeout = atoi(strVal);

		strVal = boaGetVar(wp, "ft_r0kh_id", "");
		if (strVal[0])
			strncpy(Entry.ft_r0kh_id, strVal, 48);

		strVal = boaGetVar(wp, "ft_push", "");
		if (strVal[0])
			Entry.ft_push = atoi(strVal);

		// save changes
		wlan_setEntry(&Entry, idx);
		mib_chain_update(MIB_MBSSIB_TBL, (void *)&Entry, idx);
		config_WLAN(ACT_RESTART, CONFIG_SSID_ALL);
		goto setOk_ft;
	}

	// for R0KH/R1KH configuration
	/* Add entry */
	strVal = boaGetVar(wp, "ftAddKH", "");
	if (strVal[0]) {
		if ( Entry.ft_kh_num >= MAX_VWLAN_FTKH_NUM ) {
			strcpy(tmpbuf, strAddAcErrForFull);
			goto setErr_ft;
		}

		memset(&khEntry, 0, sizeof(khEntry));
		strVal = boaGetVar(wp, "kh_mac", "");
		if (!strVal[0]) {
			strcpy(tmpbuf, "错误 ! 设置没有 mac 地址。");
			goto setErr_ft;
		}
		if (strlen(strVal)!=12 || !string_to_hex(strVal, khEntry.addr, 12)) {
			strcpy(tmpbuf, strInvdMACAddr);
			goto setErr_ft;
		}
		if (!isValidMacAddr(khEntry.addr)) {
			strcpy(tmpbuf, strInvdMACAddr);
			goto setErr_ft;
		}
		khEntry.wlanIdx = wlan_idx;
		khEntry.intfIdx = idx;

		strVal = boaGetVar(wp, "kh_nas_id", "");
		if (!strVal[0]) {
			strcpy(tmpbuf, "无效的 NAS 标识符 (1 ~ 48 个字符)");
			goto setErr_ft;
		}
		strncpy(khEntry.r0kh_id, strVal, 48);

		strVal = boaGetVar(wp, "kh_kek", "");
		if (!strVal[0]) {
			strcpy(tmpbuf, "错误! 没有设定 R0KH/R1KH 的值");
			goto setErr_ft;
		}
		strncpy(khEntry.key, strVal, 32);

		entryNum = mib_chain_total(MIB_WLAN_FTKH_TBL);

		// set to MIB. Check if entry exists
		for (i=0; i<entryNum; i++) {
			if (!mib_chain_get(MIB_WLAN_FTKH_TBL, i, (void *)&getEntry))
			{
	  			strcpy(tmpbuf, strGetChainerror);
				goto setErr_ft;
			}
			if (!memcmp(khEntry.addr, getEntry.addr, 6) && khEntry.intfIdx==getEntry.intfIdx)
			{
				strcpy(tmpbuf, strMACInList);
				goto setErr_ft;
			}
		}

		// add new KH entry
		intVal = mib_chain_add(MIB_WLAN_FTKH_TBL, (unsigned char *)&khEntry);
		if (intVal == 0) {
			strcpy(tmpbuf, strAddListErr);
			goto setErr_ft;
		}
		else if (intVal == -1) {
			strcpy(tmpbuf, strTableFull);
			goto setErr_ft;
		}

		// save entry count
		Entry.ft_kh_num++;
		wlan_setEntry(&Entry, idx);
		mib_chain_update(MIB_MBSSIB_TBL, (void *)&Entry, idx);

		// generate new ft.conf and update to FT daemon
		genFtKhConfig();
		va_niced_cmd(FT_DAEMON_PROG, 1 , 1 , "-update");
		goto setOk_ft;
	}

	/* Delete selected entry */
	strVal = boaGetVar(wp, "ftDelSelKh", "");
	if (strVal[0]) {
		entryNum = mib_chain_total(MIB_WLAN_FTKH_TBL);
		for (i=entryNum-1; i>=0; i--) {
			if (!mib_chain_get(MIB_WLAN_FTKH_TBL, i, (void *)&khEntry))
				break;
			if(khEntry.wlanIdx != wlan_idx)
				continue;

			snprintf(tmpbuf, 20, "kh_entry_%d", i);
			strVal = boaGetVar(wp, tmpbuf, "");

			if (!strcmp(strVal, "ON")) {
				deleted++;
				if(mib_chain_delete(MIB_WLAN_FTKH_TBL, i) != 1) {
					strcpy(tmpbuf, strDelListErr);
					goto setErr_ft;
				}
			}
		}
		if (deleted <= 0) {
			strcpy(tmpbuf, "没有选择要删除的项目！");
			goto setErr_ft;
		}

		// save entry count
		Entry.ft_kh_num--;
		wlan_setEntry(&Entry, idx);
		mib_chain_update(MIB_MBSSIB_TBL, (void *)&Entry, idx);

		// generate new ft.conf and update to FT daemon
		genFtKhConfig();
		va_niced_cmd(FT_DAEMON_PROG, 1 , 1 , "-clear");
		va_niced_cmd(FT_DAEMON_PROG, 1 , 1 , "-update");
		goto setOk_ft;
	}

	/* Delete all entry */
	strVal = boaGetVar(wp, "ftDelAllKh", "");
	if (strVal[0]) {
		entryNum = mib_chain_total(MIB_WLAN_FTKH_TBL);
		for (i=entryNum-1; i>=0; i--) {
			if (!mib_chain_get(MIB_WLAN_FTKH_TBL, i, (void *)&khEntry)) {
	  			strcpy(tmpbuf, strGetChainerror);
				goto setErr_ft;
			}
			if(khEntry.wlanIdx == wlan_idx) {
				if(mib_chain_delete(MIB_WLAN_FTKH_TBL, i) != 1) {
					strcpy(tmpbuf, strDelListErr);
					goto setErr_ft;
				}
			}
		}

		// reset entry count
		for (i=0; i<=NUM_VWLAN_INTERFACE; i++) {
			if (!wlan_getEntry((void *)&Entry, i)) {
				strcpy(tmpbuf, strGetMBSSIBTBLErr);
				goto setErr_ft;
			}
			Entry.ft_kh_num = 0;
			wlan_setEntry(&Entry, i);
			mib_chain_update(MIB_MBSSIB_TBL, (void *)&Entry, i);
		}

		// generate new ft.conf and update to FT daemon
		genFtKhConfig();
		va_niced_cmd(FT_DAEMON_PROG, 1 , 1 , "-clear");
		goto setOk_ft;
	}

setOk_ft:
#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif // of #if COMMIT_IMMEDIATELY
	if (submitUrl[0])
		boaRedirect(wp, submitUrl);
	else
		boaDone(wp, 200);
	return;

setErr_ft:
	ERR_MSG(tmpbuf);
	return;
}

int wlFtKhList(int eid, request * wp, int argc, char **argv)
{
	int nBytesSent=0, entryNum, i, j, intfIndex=-1;
	MIB_CE_MBSSIB_T Entry;
	MIB_CE_WLAN_FTKH_T khEntry;
	char strAddr[18], strId[49], strKey[33];

	// show title
	nBytesSent += boaWrite(wp, "<tr class=\"hd\">"
      	"<td align=center width=\"14%%\">%s</td>\n"
      	"<td align=center width=\"44%%\">%s</td>\n"
      	"<td align=center width=\"30%%\">%s</td>\n"
      	"<td align=center width=\"7%%\">%s</td></tr>\n",
      	"MAC地址", "NAS identifier", "128-bit key / passphrase", "选择");

	// get total count of KH entry
	entryNum = mib_chain_total(MIB_WLAN_FTKH_TBL);

	// list KH entries, in order of interface index
	//for (j=0; j<=NUM_VWLAN_INTERFACE; j++) 
	j=0;
	{
		for (i=0; i<entryNum; i++) {
			// get KH entries
			if (!mib_chain_get(MIB_WLAN_FTKH_TBL, i, (void *)&khEntry)) {
	  			boaError(wp, 400, "Get chain record error!\n");
				return -1;
			}
			if (khEntry.intfIdx != j)
				continue;

			// show SSID if
			if (intfIndex != j) {
				if (!wlan_getEntry((void *)&Entry, j)) {
					boaError(wp, 400, "Get chain record error!\n");
					return -1;
				}
				nBytesSent += boaWrite(wp, "<tr>"
					"<td align=left width=\"100%%\" colspan=\"4\" bgcolor=\"#A0A0A0\">%s</td></tr>\n",
					Entry.ssid);
				intfIndex = j;
			}

			// show content of KH entry
			snprintf(strAddr, sizeof(strAddr), "%02x:%02x:%02x:%02x:%02x:%02x",
				khEntry.addr[0], khEntry.addr[1], khEntry.addr[2],
				khEntry.addr[3], khEntry.addr[4], khEntry.addr[5]);
			snprintf(strId, sizeof(strId), "%s", khEntry.r0kh_id);
			snprintf(strKey, sizeof(strKey), "%s", khEntry.key);

			nBytesSent += boaWrite(wp, "<tr>"
				"<td align=center width=\"14%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
				"<td align=center width=\"44%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
				"<td align=center width=\"30%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
				"<td align=center width=\"7%%\" bgcolor=\"#C0C0C0\"><input type=\"checkbox\" name=\"kh_entry_%d\" value=\"ON\"></td></tr>\n",
					strAddr, strId, strKey, i);
		}
	}

	return nBytesSent;
}
#endif

#if defined(WLAN_SUPPORT) && (defined(CONFIG_CMCC) || defined(CONFIG_CU))
int wlan_interface_status_get(int eid, request * wp, int argc, char **argv, int band)
{
	int status;
	MIB_CE_MBSSIB_T Entry;
#if defined(CONFIG_RTL_92D_SUPPORT) || defined(WLAN_DUALBAND_CONCURRENT)
	int orig_idx = wlan_idx;
#endif
	int i, j;

	//process wlan interface
		wlan_idx = band;
		status = 0;
		
		mib_chain_get(MIB_MBSSIB_TBL, 0, (void *)&Entry);
		if(Entry.wlanDisabled==0){
			status=1;
		}

		if(status==0){
			for(j=0; j<WLAN_MBSSID_NUM; j++){
				mib_chain_get(MIB_MBSSIB_TBL, j+1, (void *)&Entry);
				if(Entry.wlanDisabled==0){
					status=1;
					break;
				}
			}
		}
		
		boaWrite(wp, "wlan_root_interface_up[%d]=%d;\n", i, status);
#if defined(CONFIG_RTL_92D_SUPPORT) || defined(WLAN_DUALBAND_CONCURRENT)
	wlan_idx = orig_idx;
#endif
	return 0;
}

int wlan_interface_status_24G(int eid, request * wp, int argc, char **argv)
{
	return wlan_interface_status_get(eid, wp, argc, argv, 0);
}

int wlStatsList_get(int eid, request * wp, int argc, char **argv, int band)
{
	int i, intf_num = 0, orig_wlan_idx;
	char ssid[MAX_SSID_LEN];
	struct net_device_stats nds;
	MIB_CE_MBSSIB_T entry;
#ifdef WLAN_MBSSID
	int j;
	char vapname[15];
#endif
	unsigned char wlan_module_disabled;
	//_TRACE_CALL;

//	if (!wlan_is_up()) {
//		return -1;
//	}
	mib_get(MIB_WIFI_MODULE_DISABLED, (void *)&wlan_module_disabled);
	if(wlan_module_disabled==1)
		return -1;

	orig_wlan_idx = wlan_idx;

	//process wlan interface
		wlan_idx = band;
		
#if defined(CONFIG_RTL_STA_CONTROL_SUPPORT) && defined(WLAN_DUALBAND_CONCURRENT)
		unsigned char wlan_sta_control=0;
		if(wlan_idx == 1){
			mib_get(MIB_WIFI_STA_CONTROL, (void *)&wlan_sta_control);
			if(wlan_sta_control==1)
				wlan_idx = 0;
		}
#endif
		wlan_getEntry(&entry, 0);

#if defined(CONFIG_RTL_STA_CONTROL_SUPPORT) && defined(WLAN_DUALBAND_CONCURRENT)
		wlan_idx = i;
#endif
		if (!entry.wlanDisabled && getInFlags(getWlanIfName(), 0)) {
		get_wlan_net_device_stats(getWlanIfName(), &nds);
		boaWrite(wp, "rcs.push(new it_nr(\"%d\""
			 _PTS _PTUL _PTUL
			 _PTUL _PTUL _PTUL
			 _PTUL _PTUL _PTUL "));\n",
			 intf_num, "ifname", "无线",
			 "rx_packets", nds.rx_packets,
			 "rx_bytes", nds.rx_bytes,
			 "rx_errors", nds.rx_errors,
			 "rx_dropped", nds.rx_dropped,
			 "tx_packets", nds.tx_packets,
			 "tx_bytes", nds.tx_bytes,
			 "tx_errors", nds.tx_errors,
			 "tx_dropped", nds.tx_dropped);
		intf_num++;
		}
		
#if 0
//#ifdef WLAN_MBSSID
		/* append wlan0-vapX to names if not disabled */
		for (j = 0; j < WLAN_MBSSID_NUM; j++) {
			mib_chain_get(MIB_MBSSIB_TBL, j + 1, &entry);
			if (entry.wlanDisabled) {
				continue;
			}
			sprintf(vapname, "%s-vap%d", getWlanIfName(), j);
			if(getInFlags(vapname, 0)==0)
				continue;
			get_wlan_net_device_stats(vapname, &nds);
			boaWrite(wp, "rcs.push(new it_nr(\"%d\""
				 _PTS _PTUL _PTUL
				 _PTUL _PTUL _PTUL
				 _PTUL _PTUL _PTUL "));\n",
				 intf_num, "ifname", entry.ssid,
				 "rx_packets", nds.rx_packets,
				 "rx_bytes", nds.rx_bytes,
				 "rx_errors", nds.rx_errors,
				 "rx_dropped", nds.rx_dropped,
				 "tx_packets", nds.tx_packets,
				 "tx_bytes", nds.tx_bytes,
				 "tx_errors", nds.tx_errors,
				 "tx_dropped", nds.tx_dropped);
			intf_num++;
		}
#endif
	wlan_idx = orig_wlan_idx;
check_err:
	//_TRACE_LEAVEL;
	return 0;
}

int wlStatsList_24G(int eid, request * wp, int argc, char **argv)
{
	return wlStatsList_get(eid, wp, argc, argv, 0);
}

#if defined(WLAN_DUALBAND_CONCURRENT)
int wlan_interface_status_5G(int eid, request * wp, int argc, char **argv)
{
	return wlan_interface_status_get(eid, wp, argc, argv, 1);
}

int wlStatsList_5G(int eid, request * wp, int argc, char **argv)
{
	return wlStatsList_get(eid, wp, argc, argv, 1);
}
#endif //#if defined(WLAN_DUALBAND_CONCURRENT)

#endif //defined(WLAN_SUPPORT) && (defined(CONFIG_CMCC) || defined(CONFIG_CU))

#ifdef _PRMT_X_CMCC_WLANSHARE_
void formWlanShare(request * wp, char *path, char *query)
{
	char *strVal, *submitUrl;
	char tmpBuf[100];
	unsigned char enable=0, wlan_restart=0;
	MIB_CE_WLAN_SHARE_T Entry;
	MIB_CE_MBSSIB_T wlanEntry;
	int total = mib_chain_total(MIB_WLAN_SHARE_TBL);

	strVal  = boaGetVar(wp, "EnableUserId", "");
	if(strVal[0]){
		enable = strVal[0] - '0';
	}
	else{
		strcpy(tmpBuf, "错误! 没有EnableUserId");
		goto setErr_wlshare;
	}
	
	if(enable==0 && total==0)
		goto setNo_wlshare;
	
	if(total == 0){
		memset(&Entry, 0, sizeof(MIB_CE_WLAN_SHARE_T));
	}
	else{
		if( !mib_chain_get(MIB_WLAN_SHARE_TBL, 0, &Entry)){
			strcpy(tmpBuf, "错误! MIB_WLAN_SHARE_TBL读取错误");
			goto setErr_wlshare;
		}
	}
	
	Entry.userid_enable = enable;

	strVal  = boaGetVar(wp, "ShareIndex", "");	
	if (!strVal[0]) {
		strcpy(tmpBuf, "错误! 没有ShareIndex");
		goto setErr_wlshare;
	}
	Entry.ssid_idx = strVal[0] - '0';

	if(enable){
		strVal  = boaGetVar(wp, "UserId", "");
		if (strVal[0]) {
			strcpy( Entry.userid, strVal);
		}
	}
	else{
		memset(Entry.userid, 0, sizeof(Entry.userid));
	}

	if(total==0){
		if(!mib_chain_add(MIB_WLAN_SHARE_TBL, &Entry)){
			strcpy(tmpBuf, strAddEntryErr);
			goto setErr_wlshare;
		}
	}
	else{
		mib_chain_update(MIB_WLAN_SHARE_TBL, &Entry, 0);
	}

// Magician: Commit immediately
#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif // of #if COMMIT_IMMEDIATELY

#ifndef NO_ACTION
	run_script(-1);
#endif

	setup_wlan_share();

setNo_wlshare:
	submitUrl = boaGetVar(wp, "submit-url", "");   // hidden page
	//OK_MSG( submitUrl );
	if (submitUrl[0])
		boaRedirect(wp, submitUrl);
	else
		boaDone(wp, 200);
  	return;

setErr_wlshare:
	ERR_MSG(tmpBuf);
}
#endif
