#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <errno.h>

#include <sys/ioctl.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "ipv6_info.h"
#include "rtusr_rg_api.h"

#include "debug.h"
#include "utility.h"
#include <linux/wireless.h>
//#include "subr_wlan.h"
#ifdef WLAN_FAST_INIT
#include "../../../linux-2.6.x/drivers/net/wireless/rtl8192cd/ieee802_mib.h"
#endif

#if defined(CONFIG_SLAVE_WLAN1_ENABLE) && !defined(CONFIG_MASTER_WLAN0_ENABLE)
const char* WLANIF[] = {"wlan1"};
#elif defined(CONFIG_YUEME) && defined(CONFIG_LUNA_DUAL_LINUX)
const char* WLANIF[] = {"wlan1", "wlan0"};
#else
const char* WLANIF[] = {"wlan0", "wlan1"};
#endif

const char IWPRIV[] = "/bin/iwpriv";
const char AUTH_DAEMON[] = "/bin/auth";
const char IWCONTROL[] = "/bin/iwcontrol";
const char AUTH_PID[] = "/var/run/auth-wlan0.pid";

#ifdef WLAN_11R
const char FT_DAEMON_PROG[]	= "/bin/ftd";
const char FT_WLAN_IF[]		= "wlan0";
const char FT_CONF[]		= "/tmp/ft.conf";
const char FT_PID[]			= "/var/run/ft.pid";
#endif

#ifdef WLAN_11K
const char DOT11K_DAEMON_PROG[] = "/bin/dot11k_deamon";
#endif

#define IWCONTROLPID  "/var/run/iwcontrol.pid"
#if defined(CONFIG_RTL_92D_DMDP) || defined(WLAN_DUALBAND_CONCURRENT)
#define WLAN0_WLAN1_WSCDPID  "/var/run/wscd-wlan0-wlan1.pid"
#endif //CONFIG_RTL_92D_DMDP || WLAN_DUALBAND_CONCURRENT
#define WSCDPID "/var/run/wscd-%s.pid"
const char WSCD_FIFO[] = "/var/wscd-%s.fifo";
const char WSCD_CONF[] = "/var/wscd.conf";
#ifdef WLAN_WDS
const char WDSIF[]="%s-wds0";
#endif

#ifdef CONFIG_LUNA_DUAL_LINUX
const char WLAN1_MAC_FILE[]= "/var/wlan1_mac";
#endif

#ifdef WLAN_SMARTAPP_ENABLE
const char SMART_WLANAPP_PROG[]	= "/bin/smart_wlanapp";
const char SMART_WLANAPP_PID[]	= "/var/run/smart_wlanapp.pid";
#endif

int wlan_idx=0;	// interface index

static unsigned int useAuth_RootIf=0;
static int wlan_num=0;
/* 2010-10-27 krammer :  change to 16 for dual band*/
static char para_iwctrl[16][20];
static int is8021xEnabled(int vwlan_idx);
#ifdef WLAN_WPS_VAP
static int check_wps_enc(MIB_CE_MBSSIB_Tp Entry);
#endif
static void applyWlanLed(int idx);
static int check_iwcontrol_8021x(void);

const char *wlan_band[] = {
	0, "2.4 GHz (B)", "2.4 GHz (G)", "2.4 GHz (B+G)", 0
	, 0, 0, 0, "2.4 GHz (N)", 0, "2.4 GHz (G+N)", "2.4 GHz (B+G+N)", 0
};

const char *wlan_mode[] = {
	//"AP", "Client", "AP+WDS"
	"AP", "Client", "WDS", "AP+WDS"
};

const char *wlan_rate[] = {
	"1M", "2M", "5.5M", "11M", "6M", "9M", "12M", "18M", "24M", "36M", "48M", "54M"
	, "MCS0", "MCS1", "MCS2", "MCS3", "MCS4", "MCS5", "MCS6", "MCS7", "MCS8", "MCS9", "MCS10", "MCS11", "MCS12", "MCS13", "MCS14", "MCS15"
};

const char *wlan_auth[] = {
	"Open", "Shared", "Auto"
};

const char *wlan_preamble[] = {
	"Long", "Short"
};

const char *wlan_encrypt[] = {
	"None",
	"WEP",
	"WPA",
	"WPA2",
	"WPA2 Mixed",
#ifdef CONFIG_RTL_WAPI_SUPPORT
	"WAPI",
#else
	"",
#endif
};

const char *wlan_pskfmt[] = {
	"Passphrase", "Hex"
};

const char *wlan_wepkeylen[] = {
	"Disable", "64-bit", "128-bit"
};

const char *wlan_wepkeyfmt[] = {
	"ASCII", "Hex"
};

// Mason Yu. 201009_new_security
const char *wlan_Cipher[] = {
	//"TKIP", "AES", "Both"
	"TKIP", "AES", "TKIP+AES"
};

int getTxPowerHigh(int phyband)
{
	unsigned char vChar, txpower_high=0;
#ifdef WLAN_DUALBAND_CONCURRENT
	int orig_wlan_idx = wlan_idx;
	int i;
	for(i=0; i<NUM_WLAN_INTERFACE; i++){
		wlan_idx = i;
		mib_get(MIB_WLAN_PHY_BAND_SELECT, (void *)&vChar);
		if(phyband == vChar){
#endif
			mib_get(MIB_WLAN_TX_POWER_HIGH, &txpower_high);
#ifdef WLAN_DUALBAND_CONCURRENT
			break;
		}
	}
	wlan_idx = orig_wlan_idx;
#endif
	return txpower_high;

}
// 100mW = 20dB, 200mW=23dB
// 80mw = 19.03, (20-19.03)*2 = 2
int getTxPowerScale(int phyband, int mode)
{
#ifdef WLAN_TXPOWER_HIGH
	if(phyband == PHYBAND_2G)
	{	
		switch (mode)
		{
			case 0: //100% or 200%
				if(getTxPowerHigh(phyband))
					return -4; //200%
				return 0; //100%
			case 1: //80%
				return 2;
			case 2: //60%
				return 5;
			case 3: //35%
				return 9;
			case 4: //15%
				return 17;
		}
	}
	else{ //5G
		switch (mode)
		{
			case 0: //100% or 200%
				if(getTxPowerHigh(phyband))
					return -6; //200%
				return 0; //100%
			case 1: //80%
				return 2;
			case 2: //60%
				return 5;
			case 3: //35%
				return 9;
			case 4: //15%
				return 17;
		}
	}
#else
	switch (mode)
	{
		case 0: //100%
			return 0;
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		case 1: //80%
			return 2;
		case 2: //60%
			return 4;
		case 3: //40%
			return 8;
		case 4: //20%
			return 14;
#else
		case 1: //70%
			return 3;
		case 2: //50%
			return 6;
		case 3: //35%
			return 9;
		case 4: //15%
			return 17;
#endif
	}
#endif
}

int get_TxPowerValue(int phyband, int mode)
{
	// 2.4G: 100mW => 20 dbm ; 5G: 200mW => 23dbm
	int intVal = 0, power = 0;
	intVal = getTxPowerScale(phyband, mode);

	if (phyband == PHYBAND_2G) {
#if defined(CONFIG_YUEME)
		power = 23 - (intVal / 2);
#else
		power = 20 - (intVal / 2);
#endif
	}
	else if (phyband == PHYBAND_5G) {
		power = 23 - (intVal / 2);
	}
	return power;
}

void _gen_guest_mac(const unsigned char *base_mac, const int maxBss, const int guestNum, unsigned char *hwaddr)
{	
	memcpy(hwaddr,base_mac,MAC_ADDR_LEN);
	hwaddr[0] = 96 + (hwaddr[5]%(maxBss - 1) * 8);
	hwaddr[0] |= 0x2;
	hwaddr[5] = (hwaddr[5]&~(maxBss-1))|((maxBss-1)&(hwaddr[5]+guestNum));
}

#ifdef CONFIG_LUNA_DUAL_LINUX
static void get_wlan_mac(char *fname, char *strbuf)
{
	FILE *fp;
	int i=0;
	int temp;
	unsigned char mac[MAC_ADDR_LEN];
	fp = fopen(fname, "r");
	if(fp) {
		for(i=0;i<MAC_ADDR_LEN;i++){
			fscanf(fp, "%x", &temp);
			mac[i] = temp;
		}
		printf("%s %02x%02x%02x%02x%02x%02x\n", __FUNCTION__, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
		sprintf(strbuf, "%02x%02x%02x%02x%02x%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
		fclose(fp);
	}
	return;
}
#endif

#if defined(CONFIG_RTL_STA_CONTROL_SUPPORT) && defined(WLAN_DUALBAND_CONCURRENT)
// return value:
// 0  : one of wlan root interface is disabled
// 1 : both enable
unsigned int get_root_wlan_status(void)
{
	int i, orig_wlan_idx = wlan_idx;
	MIB_CE_MBSSIB_T Entry;
#ifdef YUEME_3_0_SPEC
	unsigned char no_wlan;
#endif
	for(i=0; i<NUM_WLAN_INTERFACE; i++) {
		wlan_idx = i;
#ifdef YUEME_3_0_SPEC
		mib_get(MIB_WLAN_DISABLED, (void *)&no_wlan);
		if(no_wlan == 1) {
			wlan_idx = orig_wlan_idx;
			return 0;
		}
#endif
		wlan_getEntry(&Entry, 0);
		if(Entry.wlanDisabled == 1) {
			wlan_idx = orig_wlan_idx;
			return 0;
		}
	}
	wlan_idx = orig_wlan_idx;
	return 1;
}
#endif

#if ((defined(CONFIG_WLAN_HAL_8814AE) || defined(CONFIG_RTL_8812_SUPPORT)) && !defined(CONFIG_ENABLE_EFUSE)) || defined(WLAN_DUALBAND_CONCURRENT)

#define B1_G1	40
#define B1_G2	48

#define B2_G1	56
#define B2_G2	64

#define B3_G1	104
#define B3_G2	112
#define B3_G3	120
#define B3_G4	128
#define B3_G5	136
#define B3_G6	144

#define B4_G1	153
#define B4_G2	161
#define B4_G3	169
#define B4_G4	177

void assign_diff_AC(unsigned char* pMib, unsigned char* pVal)
{
/*
	int i;
	printf("%s ", __FUNCTION__);
	for(i=0; i<14;i++)
		printf("%02x ", pVal[i]);
	printf("\n");
*/
	memset(pMib, 0, 35);
	memset((pMib+35), pVal[0], (B1_G1-35));
	memset((pMib+B1_G1), pVal[1], (B1_G2-B1_G1));
	memset((pMib+B1_G2), pVal[2], (B2_G1-B1_G2));
	memset((pMib+B2_G1), pVal[3], (B2_G2-B2_G1));
	memset((pMib+B2_G2), pVal[4], (B3_G1-B2_G2));
	memset((pMib+B3_G1), pVal[5], (B3_G2-B3_G1));
	memset((pMib+B3_G2), pVal[6], (B3_G3-B3_G2));
	memset((pMib+B3_G3), pVal[7], (B3_G4-B3_G3));
	memset((pMib+B3_G4), pVal[8], (B3_G5-B3_G4));
	memset((pMib+B3_G5), pVal[9], (B3_G6-B3_G5));
	memset((pMib+B3_G6), pVal[10], (B4_G1-B3_G6));
	memset((pMib+B4_G1), pVal[11], (B4_G2-B4_G1));
	memset((pMib+B4_G2), pVal[12], (B4_G3-B4_G2));
	memset((pMib+B4_G3), pVal[13], (B4_G4-B4_G3));
/*
	for(i=0; i<178;i++)
		printf("%02x", pMib[i]);
	printf("\n");
*/
}
#endif

int isValid_wlan_idx(int idx)
{
	if (idx >=0 && idx < NUM_WLAN_INTERFACE)
		return 1;
	else
		return 0;
	return 0;
}

enum {IWPRIV_GETMIB=1, IWPRIV_HS=2, IWPRIV_INT=4, IWPRIV_HW2G=8, IWPRIV_TXPOWER=16, IWPRIV_HWDPK=32};
int iwpriv_cmd(int type, ...)
{
	va_list ap;
	int k=0, i;
	char *s, *s2;
	char *argv[24];
	int status;
	unsigned char value[196];
	char parm[2048];
	unsigned char pMib[178];
	int mib_id, mode, intVal, dpk_len;
	char buf[32];
	unsigned char dpk_value[1024];

	TRACE(STA_SCRIPT, "%s ", IWPRIV);
	va_start(ap, type);
	
	s = va_arg(ap, char *); //wlan interface name
	argv[++k] = s;
	TRACE(STA_SCRIPT|STA_NOTAG, "%s ", s); 
	s = va_arg(ap, char *); //cmd, ie set_mib
	argv[++k] = s;
	TRACE(STA_SCRIPT|STA_NOTAG, "%s ", s);
	s = va_arg(ap, char *); //cmd detail

	if(type & IWPRIV_GETMIB){
		mib_id = va_arg(ap, int);
		mib_get(mib_id, (void *)value);
	}
	else{
		if(type & IWPRIV_HS){
			if(type & IWPRIV_HW2G)
				memcpy(value, va_arg(ap, char *), MAX_CHAN_NUM);
			else if(type & IWPRIV_HWDPK)
			{
				dpk_len = va_arg(ap, int);
				memcpy(dpk_value, va_arg(ap, char *), dpk_len);
			}
#if ((defined(CONFIG_WLAN_HAL_8814AE) || defined(CONFIG_RTL_8812_SUPPORT)) && !defined(CONFIG_ENABLE_EFUSE)) || defined(WLAN_DUALBAND_CONCURRENT)
			else
				memcpy(value, va_arg(ap, char *), MAX_5G_CHANNEL_NUM);
#endif
		}
	}

	if(!(type & IWPRIV_HS)){
		if(type & IWPRIV_GETMIB){
			if(type & IWPRIV_INT) //int
				snprintf(parm, sizeof(parm), "%s=%u", s, value[0]);
			else //string
				snprintf(parm, sizeof(parm), "%s=%s", s, value);
		}
		else{
			if(type & IWPRIV_INT){ //int
				intVal = va_arg(ap, int);
				snprintf(parm, sizeof(parm), "%s=%u", s, intVal);
			}
			else{ //string
				s2 = va_arg(ap, char *);
				snprintf(parm, sizeof(parm), "%s=%s", s, s2);
			}
		}
	}
	else{
		snprintf(parm, sizeof(parm), "%s=", s);
		if(type & IWPRIV_HW2G){ //2G
			if(type & IWPRIV_TXPOWER){
				mode = va_arg(ap, int);
				intVal = getTxPowerScale(PHYBAND_2G, mode);
				for(i=0; i<MAX_CHAN_NUM; i++) {
					if(value[i]!=0){
						if((value[i] - intVal)>=1)
							value[i] -= intVal;
						else
							value[i] = 1;
					}
					snprintf(buf, sizeof(buf), "%02x", value[i]);
					strcat(parm, buf);
					//snprintf(parm, sizeof(parm), "%s%02x", parm, value[i]);
				}
			}
			else{
				for(i=0; i<MAX_CHAN_NUM; i++) {
					snprintf(buf, sizeof(buf), "%02x", value[i]);
					strcat(parm, buf);
					//snprintf(parm, sizeof(parm), "%s%02x", parm, value[i]);
				}
			}
			
		}
		else if(type & IWPRIV_HWDPK){
			for(i=0; i<dpk_len; i++) {
				snprintf(buf, sizeof(buf), "%02x", dpk_value[i]);
				strcat(parm, buf);
				//snprintf(parm, sizeof(parm), "%s%02x", parm, dpk_value[i]);
			}
		}
#if ((defined(CONFIG_WLAN_HAL_8814AE) || defined(CONFIG_RTL_8812_SUPPORT)) && !defined(CONFIG_ENABLE_EFUSE)) || defined(WLAN_DUALBAND_CONCURRENT)
		else{ //5G

			if(type & IWPRIV_TXPOWER){
				mode = va_arg(ap, int);
				intVal = getTxPowerScale(PHYBAND_5G, mode);
				for(i=0; i<MAX_5G_CHANNEL_NUM; i++) {
					if(value[i]!=0){
						if((value[i] - intVal)>=1)
							value[i] -= intVal;
						else
							value[i] = 1;
					}
					snprintf(buf, sizeof(buf), "%02x", value[i]);
					strcat(parm, buf);
					//snprintf(parm, sizeof(parm), "%s%02x", parm, value[i]);
				}	
			}
			else{
				assign_diff_AC(pMib, value);
				for(i=0; i<=177; i++) {
					snprintf(buf, sizeof(buf), "%02x", pMib[i]);
					strcat(parm, buf);
					//snprintf(parm, sizeof(parm), "%s%02x", parm, pMib[i]);
				}
			}
				
			
		}
#endif
	}
	argv[++k] = parm;
	TRACE(STA_SCRIPT|STA_NOTAG, "%s ", argv[k]);
	TRACE(STA_SCRIPT|STA_NOTAG, "\n");
	argv[k+1] = NULL;
	status = do_cmd(IWPRIV, argv, 1);
	va_end(ap);

	return status;
}

#if 0
// Mason Yu. 201009_new_security
void MBSSID_GetRootEntry(MIB_CE_MBSSIB_T *Entry) {
	//Entry->idx = 0;

	mib_get(MIB_WLAN_ENCRYPT, &Entry->encrypt);
	mib_get(MIB_WLAN_ENABLE_1X, &Entry->enable1X);
	mib_get(MIB_WLAN_WEP, &Entry->wep);
	mib_get(MIB_WLAN_WPA_AUTH, &Entry->wpaAuth);
	mib_get(MIB_WLAN_WPA_PSK_FORMAT, &Entry->wpaPSKFormat);
	mib_get(MIB_WLAN_WPA_PSK, Entry->wpaPSK);
	mib_get(MIB_WLAN_RS_PORT, &Entry->rsPort);
	mib_get(MIB_WLAN_RS_IP, Entry->rsIpAddr);

	mib_get(MIB_WLAN_RS_PASSWORD, Entry->rsPassword);
	mib_get(MIB_WLAN_DISABLED, &Entry->wlanDisabled);
	mib_get(MIB_WLAN_SSID, Entry->ssid);
	mib_get(MIB_WLAN_MODE, &Entry->wlanMode);
	mib_get(MIB_WLAN_AUTH_TYPE, &Entry->authType);
	//added by xl_yue
	// Mason Yu. 201009_new_security
	mib_get( MIB_WLAN_WPA_CIPHER_SUITE, &Entry->unicastCipher);
	mib_get( MIB_WLAN_WPA2_CIPHER_SUITE, &Entry->wpa2UnicastCipher);
	mib_get( MIB_WLAN_WPA_GROUP_REKEY_TIME, &Entry->wpaGroupRekeyTime);

#ifdef CONFIG_RTL_WAPI_SUPPORT
	mib_get( MIB_WLAN_WAPI_PSK, Entry->wapiPsk);
	mib_get( MIB_WLAN_WAPI_PSKLEN, &Entry->wapiPskLen);
	mib_get( MIB_WLAN_WAPI_PSK_FORMAT, &Entry->wapiPskFormat);
	mib_get( MIB_WLAN_WAPI_AUTH, &Entry->wapiAuth);
	mib_get( MIB_WLAN_WAPI_ASIPADDR, Entry->wapiAsIpAddr);
	//mib_get( MIB_WLAN_WAPI_SEARCH_CERTINFO, Entry->wapiSearchCertInfo);
	//mib_get( MIB_WLAN_WAPI_SEARCH_CERTINDEX, &Entry->wapiSearchIndex);
	//mib_get( MIB_WLAN_WAPI_MCAST_REKEYTYPE, &Entry->wapiMcastkey);
	//mib_get( MIB_WLAN_WAPI_MCAST_TIME, &Entry->wapiMcastRekeyTime);
	//mib_get( MIB_WLAN_WAPI_MCAST_PACKETS, &Entry->wapiMcastRekeyPackets);
	//mib_get( MIB_WLAN_WAPI_UCAST_REKETTYPE, &Entry->wapiUcastkey);
	//mib_get( MIB_WLAN_WAPI_UCAST_TIME, &Entry->wapiUcastRekeyTime);
	//mib_get( MIB_WLAN_WAPI_UCAST_PACKETS, &Entry->wapiUcastRekeyPackets);
	//mib_get( MIB_WLAN_WAPI_CA_INIT, &Entry->wapiCAInit);

#endif

	// Mason Yu. 201009_new_security
	mib_get(MIB_WLAN_WEP_KEY_TYPE, &Entry->wepKeyType);      // wep Key Format
	mib_get(MIB_WLAN_WEP64_KEY1, Entry->wep64Key1);
	mib_get(MIB_WLAN_WEP128_KEY1, Entry->wep128Key1);
	mib_get(MIB_WLAN_BAND, &Entry->wlanBand);
#ifdef WLAN_11W
	mib_get(MIB_WLAN_DOTIEEE80211W, &Entry->dotIEEE80211W);
	mib_get(MIB_WLAN_SHA256, &Entry->sha256);
#endif
}
#endif
int wlan_getEntry(MIB_CE_MBSSIB_T *pEntry, int index)
{
	int ret;
	unsigned char vChar;
	WLAN_MODE_T root_mode;

	ret=1;
	ret = mib_chain_get(MIB_MBSSIB_TBL, 0, (void *)pEntry);
	root_mode = (WLAN_MODE_T)pEntry->wlanMode;
	if (index!=0) {
		ret=mib_chain_get(MIB_MBSSIB_TBL, index, (void *)pEntry);
		pEntry->wlanMode=root_mode;
#ifdef WLAN_UNIVERSAL_REPEATER
		if (index == WLAN_REPEATER_ITF_INDEX) {
			mib_get( MIB_REPEATER_ENABLED1, (void *)&vChar);
			pEntry->wlanDisabled= (vChar==0?1:0);
			if (root_mode==CLIENT_MODE)
				pEntry->wlanMode=AP_MODE;
			else
				pEntry->wlanMode=CLIENT_MODE;
		}
#endif
	}
	return ret;
}
#if 0
void MBSSID_SetRootEntry(MIB_CE_MBSSIB_T *Entry) {
	//Entry->idx = 0;

	mib_set(MIB_WLAN_ENCRYPT, &Entry->encrypt);
	mib_set(MIB_WLAN_ENABLE_1X, &Entry->enable1X);
	mib_set(MIB_WLAN_WEP, &Entry->wep);
	mib_set(MIB_WLAN_WPA_AUTH, &Entry->wpaAuth);
	mib_set(MIB_WLAN_WPA_PSK_FORMAT, &Entry->wpaPSKFormat);
	mib_set(MIB_WLAN_WPA_PSK, Entry->wpaPSK);
	mib_set(MIB_WLAN_RS_PORT, &Entry->rsPort);
	mib_set(MIB_WLAN_RS_IP, Entry->rsIpAddr);

	mib_set(MIB_WLAN_RS_PASSWORD, Entry->rsPassword);
	mib_set(MIB_WLAN_DISABLED, &Entry->wlanDisabled);
	mib_set(MIB_WLAN_SSID, Entry->ssid);
	mib_set(MIB_WLAN_MODE, &Entry->wlanMode);
	mib_set(MIB_WLAN_AUTH_TYPE, &Entry->authType);
	//added by xl_yue
	// Mason Yu. 201009_new_security
	mib_set( MIB_WLAN_WPA_CIPHER_SUITE, &Entry->unicastCipher);
	mib_set( MIB_WLAN_WPA2_CIPHER_SUITE, &Entry->wpa2UnicastCipher);
	mib_set( MIB_WLAN_WPA_GROUP_REKEY_TIME, &Entry->wpaGroupRekeyTime);

#ifdef CONFIG_RTL_WAPI_SUPPORT
	mib_set( MIB_WLAN_WAPI_PSK, Entry->wapiPsk);
	mib_set( MIB_WLAN_WAPI_PSKLEN, &Entry->wapiPskLen);
	mib_set( MIB_WLAN_WAPI_PSK_FORMAT, &Entry->wapiPskFormat);
	mib_set( MIB_WLAN_WAPI_AUTH, &Entry->wapiAuth);
	mib_set( MIB_WLAN_WAPI_ASIPADDR, Entry->wapiAsIpAddr);
	//mib_get( MIB_WLAN_WAPI_SEARCH_CERTINFO, Entry->wapiSearchCertInfo);
	//mib_get( MIB_WLAN_WAPI_SEARCH_CERTINDEX, &Entry->wapiSearchIndex);
	//mib_get( MIB_WLAN_WAPI_MCAST_REKEYTYPE, &Entry->wapiMcastkey);
	//mib_get( MIB_WLAN_WAPI_MCAST_TIME, &Entry->wapiMcastRekeyTime);
	//mib_get( MIB_WLAN_WAPI_MCAST_PACKETS, &Entry->wapiMcastRekeyPackets);
	//mib_get( MIB_WLAN_WAPI_UCAST_REKETTYPE, &Entry->wapiUcastkey);
	//mib_get( MIB_WLAN_WAPI_UCAST_TIME, &Entry->wapiUcastRekeyTime);
	//mib_get( MIB_WLAN_WAPI_UCAST_PACKETS, &Entry->wapiUcastRekeyPackets);
	//mib_get( MIB_WLAN_WAPI_CA_INIT, &Entry->wapiCAInit);

#endif

	// Mason Yu. 201009_new_security
	mib_set(MIB_WLAN_WEP_KEY_TYPE, &Entry->wepKeyType);      // wep Key Format
	mib_set(MIB_WLAN_WEP64_KEY1, Entry->wep64Key1);
	mib_set(MIB_WLAN_WEP128_KEY1, Entry->wep128Key1);
	mib_set(MIB_WLAN_BAND, &Entry->wlanBand);
#ifdef WLAN_11W
	mib_set(MIB_WLAN_DOTIEEE80211W, &Entry->dotIEEE80211W);
	mib_set(MIB_WLAN_SHA256, &Entry->sha256);
#endif
}
#endif
int wlan_setEntry(MIB_CE_MBSSIB_T *pEntry, int index)
{
	int ret=1;
	
	ret=mib_chain_update(MIB_MBSSIB_TBL, (void *)pEntry, index);
	
	return ret;
}


/////////////////////////////////////////////////////////////////////////////
static inline int
iw_get_ext(int                  skfd,           /* Socket to the kernel */
           const char *               ifname,         /* Device name */
           int                  request,        /* WE ID */
           struct iwreq *       pwrq)           /* Fixed part of the request */
{
  /* Set device name */
  strncpy(pwrq->ifr_name, ifname, IFNAMSIZ);
  /* Do the request */
  return(ioctl(skfd, request, pwrq));
}

int getWlStaInfo( char *interface,  WLAN_STA_INFO_Tp pInfo )
{
    int skfd;
    struct iwreq wrq;

    skfd = socket(AF_INET, SOCK_DGRAM, 0);

    /* Get wireless name */
    if ( iw_get_ext(skfd, interface, SIOCGIWNAME, &wrq) < 0)
    {
    	close( skfd );
      /* If no wireless name : no wireless extensions */
        return -1;
    }

    wrq.u.data.pointer = (caddr_t)pInfo;
    wrq.u.data.length = sizeof(WLAN_STA_INFO_T) * (MAX_STA_NUM+1);

    if (iw_get_ext(skfd, interface, SIOCGIWRTLSTAINFO, &wrq) < 0)
    {
    	close( skfd );
	return -1;
    }

    close( skfd );

    return 0;
}

int doWlKickOutDevice( char *interface,  unsigned char *mac_addr)
{
    int skfd;
    struct iwreq wrq;

    skfd = socket(AF_INET, SOCK_DGRAM, 0);

    /* Get wireless name */
    if ( iw_get_ext(skfd, interface, SIOCGIWNAME, &wrq) < 0)
    {
        close( skfd );
      /* If no wireless name : no wireless extensions */
        return -1;
    }

    wrq.u.data.pointer = (caddr_t)mac_addr;
    wrq.u.data.length = 12;

    if (iw_get_ext(skfd, interface, RTL8192CD_IOCTL_DEL_STA, &wrq) < 0)
    {
        close( skfd );
        return -1;
    }

    close( skfd );
    return 0;
}

void kickOutDevice(unsigned char *mac_addr, int ssid_idx, unsigned int *result, char *error)
{
	char interface_name[16];
	unsigned char mac_addr_str[12];
	WLAN_STA_INFO_T buff[MAX_STA_NUM + 1]={0};
	WLAN_STA_INFO_Tp pInfo;
	int i, found=0;

#ifdef WLAN_DUALBAND_CONCURRENT
	int orig_idx = wlan_idx;
	if(ssid_idx > WLAN_SSID_NUM){
		ssid_idx -= WLAN_SSID_NUM;
		wlan_idx = 1;
	}
	else
		wlan_idx = 0;
#endif

	if(ssid_idx==1)
		snprintf(interface_name, 16, "%s", (char *)getWlanIfName());
	else
		snprintf(interface_name, 16, "%s-vap%d", (char *)getWlanIfName(), ssid_idx-2);

#ifdef WLAN_DUALBAND_CONCURRENT
	wlan_idx = orig_idx;
#endif
	
	if (getWlStaInfo(interface_name, (WLAN_STA_INFO_Tp) buff) < 0) {
		printf("Read wlan sta info failed!\n");
		*result = 0;
		sprintf(error, "check sta info failed");
		return;
	}

	for (i = 1; i <= MAX_STA_NUM; i++) {
		pInfo = (WLAN_STA_INFO_Tp) &buff[i];
		if (pInfo->aid && (pInfo->flag & STA_INFO_FLAG_ASOC)) {
			if(!strncmp(pInfo->addr, mac_addr, 6)){
				found = 1;
				break;
			}
		}
	}
	if(found == 0){
		*result = 0;
		sprintf(error, "no sta exists");
		return;
	}

	sprintf(mac_addr_str, "%02x%02x%02x%02x%02x%02x", mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);

	doWlKickOutDevice(interface_name, mac_addr_str);

	if (getWlStaInfo(interface_name, (WLAN_STA_INFO_Tp) buff) < 0) {
		printf("Read wlan sta info failed!\n");
		*result = 0;
		sprintf(error, "check sta info failed");
		return;
	}

	found = 0;

	for (i = 1; i <= MAX_STA_NUM; i++) {
		pInfo = (WLAN_STA_INFO_Tp) &buff[i];
		if (pInfo->aid && (pInfo->flag & STA_INFO_FLAG_ASOC)) {
			if(!strncmp(pInfo->addr, mac_addr, 6)){
				found = 1;
				break;
			}
		}
	}
	if(found == 0){
		*result = 1; //SUCCESS
	}
	else{
		*result = 0; //FAILED
		sprintf(error, "del sta failed");
	}
	
}

int getWlEnc( char *interface , char *buffer, char *num)
{
    int skfd;
    struct iwreq wrq;

    skfd = socket(AF_INET, SOCK_DGRAM, 0);

    /* Get wireless name */
    if ( iw_get_ext(skfd, interface, SIOCGIWNAME, &wrq) < 0)
    {
    	close( skfd );
      /* If no wireless name : no wireless extensions */
        return -1;
    }

    wrq.u.data.pointer = (caddr_t)buffer;
    wrq.u.data.length = strlen(buffer);

    if (iw_get_ext(skfd, interface, RTL8192CD_IOCTL_GET_MIB, &wrq) < 0)
    {
    	close( skfd );
		return -1;
    }
	*num  = buffer[0];
    close( skfd );

    return 0;
}

int getWlWpaChiper( char *interface , char *buffer, int *num)
{
    int skfd;
    struct iwreq wrq;

    skfd = socket(AF_INET, SOCK_DGRAM, 0);

    /* Get wireless name */
    if ( iw_get_ext(skfd, interface, SIOCGIWNAME, &wrq) < 0)
    {
    	close( skfd );
      /* If no wireless name : no wireless extensions */
        return -1;
    }

    wrq.u.data.pointer = (caddr_t)buffer;
    wrq.u.data.length = strlen(buffer);

    if (iw_get_ext(skfd, interface, RTL8192CD_IOCTL_GET_MIB, &wrq) < 0)
    {
    	close( skfd );
		return -1;
    }
	memcpy(num, buffer, sizeof(int));
    close( skfd );

    return 0;
}

#ifdef WLAN_FAST_INIT
#ifdef WLAN_ACL
void set_wlan_acl(struct wifi_mib *pmib)
{
	MIB_CE_WLAN_AC_T Entry;
	int num=0, i;
	char vChar;

	// aclnum=0
	(&pmib->dot11StationConfigEntry)->dot11AclNum = 0;

	// aclmode
	mib_get(MIB_WLAN_AC_ENABLED, (void *)&vChar);
	(&pmib->dot11StationConfigEntry)->dot11AclMode = vChar;

	if (vChar){ // ACL enable
		if((num = mib_chain_total(MIB_WLAN_AC_TBL))==0)
			return;
		for (i=0; i<num; i++) {
			if (!mib_chain_get(MIB_WLAN_AC_TBL, i, (void *)&Entry))
				return;
			if(Entry.wlanIdx != wlan_idx)
				continue;
			
			// acladdr
			memcpy(&((&pmib->dot11StationConfigEntry)->dot11AclAddr[i][0]), &(Entry.macAddr[0]), 6);
			(&pmib->dot11StationConfigEntry)->dot11AclNum++;
		}
	}
}
#endif
#else
#ifdef WLAN_ACL
// return value:
// 0  : successful
// -1 : failed
int set_wlan_acl(char *ifname)
{
	unsigned char value[32];
	char parm[64];
	int num, i;
	MIB_CE_WLAN_AC_T Entry;
	int status=0;

	// aclnum=0
	status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", "aclnum=0");

	// aclmode
	mib_get(MIB_WLAN_AC_ENABLED, (void *)value);
	snprintf(parm, sizeof(parm), "aclmode=%u", value[0]);
	status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", parm);

	if (value[0] == 0) // ACL disabled
		return status;

	if ((num = mib_chain_total(MIB_WLAN_AC_TBL)) == 0)
		return status;

	for (i=0; i<num; i++) {
		if (!mib_chain_get(MIB_WLAN_AC_TBL, i, (void *)&Entry))
			return -1;
		if(Entry.wlanIdx != wlan_idx)
			continue;

		// acladdr
		snprintf(parm, sizeof(parm), "acladdr=%.2x%.2x%.2x%.2x%.2x%.2x",
			Entry.macAddr[0], Entry.macAddr[1], Entry.macAddr[2],
			Entry.macAddr[3], Entry.macAddr[4], Entry.macAddr[5]);
		status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", parm);
	}
	return status;
}
#endif
#endif
#if 0
#define RTL8185_IOCTL_READ_EEPROM	0x89f9
static int check_wlan_eeprom()
{
	int skfd,i;
	struct iwreq wrq;
	unsigned char tmp[162];
	char mode;
	char parm[64];
	char *argv[6];
	argv[1] = (char*)getWlanIfName();
	argv[2] = "set_mib";

	skfd = socket(AF_INET, SOCK_DGRAM, 0);
	/* Set device name */
	strncpy(wrq.ifr_name, (char *)getWlanIfName(), IFNAMSIZ);
	strcpy(tmp,"RFChipID");
	wrq.u.data.pointer = (caddr_t)&tmp;
	wrq.u.data.length = 10;
	ioctl(skfd, RTL8185_IOCTL_READ_EEPROM, &wrq);
	if(wrq.u.data.length>0){
		printf("read eeprom success!\n");
		//return 1;
	}
	else{
		printf("read eeprom fail!\n");
		if(skfd!=-1) close(skfd);
		return 0;
	}
	//set TxPowerCCK from eeprom
	strcpy(tmp,"TxPowerCCK");
	wrq.u.data.pointer = (caddr_t)&tmp;
	wrq.u.data.length = 20;
	ioctl(skfd, RTL8185_IOCTL_READ_EEPROM, &wrq);
	snprintf(parm, sizeof(parm), "TxPowerCCK=");
	if ( mib_get( MIB_TX_POWER, (void *)&mode) == 0) {
   		printf("Get MIB_TX_POWER error!\n");
	}

//added by xl_yue:
#ifdef WLAN_TX_POWER_DISPLAY
	if ( mode==0 ) {          // 100%
		for(i=0; i<=13; i++)
		{
	//		value[i] = 8;
			snprintf(parm, sizeof(parm), "%s%02x", parm, wrq.u.data.pointer[i]);
		}
	}else if ( mode==1 ) {    // 80%
		for(i=0; i<=13; i++)
		{
		    	wrq.u.data.pointer[i] -= 1;
			snprintf(parm, sizeof(parm), "%s%02x", parm, wrq.u.data.pointer[i]);
		}

	}else if ( mode==2 ) {    // 50%
		for(i=0; i<=13; i++)
		{
		    	wrq.u.data.pointer[i] -= 3;
			snprintf(parm, sizeof(parm), "%s%02x", parm, wrq.u.data.pointer[i]);
		}
	}else if ( mode==3 ) {    // 25%
		for(i=0; i<=13; i++)
		{
		   	wrq.u.data.pointer[i] -= 6;
			snprintf(parm, sizeof(parm), "%s%02x", parm, wrq.u.data.pointer[i]);
		}
	}else if ( mode==4 ) {    // 10%
		for(i=0; i<=13; i++)
		{
		   	wrq.u.data.pointer[i] -= 10;
			snprintf(parm, sizeof(parm), "%s%02x", parm, wrq.u.data.pointer[i]);
		}
	}
#else
	if ( mode==2 ) {          // 60mW
		for(i=0; i<=13; i++)
		{
	//		value[i] = 8;
			snprintf(parm, sizeof(parm), "%s%02x", parm, wrq.u.data.pointer[i]);
		}
	}else if ( mode==1 ) {    // 30mW
		for(i=0; i<=13; i++)
		{
		    	wrq.u.data.pointer[i] -= 3;
			snprintf(parm, sizeof(parm), "%s%02x", parm, wrq.u.data.pointer[i]);
		}
	}else if ( mode==0 ) {    // 15mW
		for(i=0; i<=13; i++)
		{
		   	wrq.u.data.pointer[i] -= 6;
			snprintf(parm, sizeof(parm), "%s%02x", parm, wrq.u.data.pointer[i]);
		}
	}
#endif
	argv[3] = parm;
	argv[4] = NULL;
	TRACE(STA_SCRIPT, "%s %s %s %s\n", IWPRIV, argv[1], argv[2], argv[3]);
	do_cmd(IWPRIV, argv, 1);

	strcpy(tmp,"TxPowerOFDM");
	wrq.u.data.pointer = (caddr_t)&tmp;
	wrq.u.data.length = 20;
	ioctl(skfd, RTL8185_IOCTL_READ_EEPROM, &wrq);
	snprintf(parm, sizeof(parm), "TxPowerOFDM=");
	if ( mib_get( MIB_TX_POWER, (void *)&mode) == 0) {
   		printf("Get MIB_TX_POWER error!\n");
	}

//added by xl_yue:
#ifdef WLAN_TX_POWER_DISPLAY
	if ( mode==0 ) {          // 100%
		for(i=0; i<=13; i++)
		{
	//		value[i] = 8;
			snprintf(parm, sizeof(parm), "%s%02x", parm, wrq.u.data.pointer[i]);
		}
	}else if ( mode==1 ) {    // 80%
		for(i=0; i<=13; i++)
		{
		    	wrq.u.data.pointer[i] -= 1;
			snprintf(parm, sizeof(parm), "%s%02x", parm, wrq.u.data.pointer[i]);
		}
	}else if ( mode==2 ) {    // 50%
		for(i=0; i<=13; i++)
		{
		    	wrq.u.data.pointer[i] -= 3;
			snprintf(parm, sizeof(parm), "%s%02x", parm, wrq.u.data.pointer[i]);
		}
	}else if ( mode==3 ) {    // 25%
		for(i=0; i<=13; i++)
		{
		   	wrq.u.data.pointer[i] -= 6;
			snprintf(parm, sizeof(parm), "%s%02x", parm, wrq.u.data.pointer[i]);
		}
	}else if ( mode==4 ) {    // 10%
		for(i=0; i<=13; i++)
		{
		   	wrq.u.data.pointer[i] -= 10;
			snprintf(parm, sizeof(parm), "%s%02x", parm, wrq.u.data.pointer[i]);
		}
	}
#else
	if ( mode==2 ) {          // 60mW
		for(i=0; i<=13; i++)
		{
	//		value[i] = 8;
			snprintf(parm, sizeof(parm), "%s%02x", parm, wrq.u.data.pointer[i]);
		}
	}else if ( mode==1 ) {    // 30mW
		for(i=0; i<=13; i++)
		{
		    	wrq.u.data.pointer[i] -= 3;
			snprintf(parm, sizeof(parm), "%s%02x", parm, wrq.u.data.pointer[i]);
		}
	}else if ( mode==0 ) {    // 15mW
		for(i=0; i<=13; i++)
		{
		   	wrq.u.data.pointer[i] -= 6;
			snprintf(parm, sizeof(parm), "%s%02x", parm, wrq.u.data.pointer[i]);
		}
	}
#endif
	argv[3] = parm;
	argv[4] = NULL;
	TRACE(STA_SCRIPT, "%s %s %s %s\n", IWPRIV, argv[1], argv[2], argv[3]);
	do_cmd(IWPRIV, argv, 1);

	close( skfd );
	return 1;
}
#endif
/* andrew: new test plan require N mode to avoid using TKIP. This function check the new band
   and unmask TKIP security if it's N mode.
*/
int wl_isNband(unsigned char band) {
	return (band >= 8);
}

void wl_updateSecurity(unsigned char band) {
	if (wl_isNband(band)) {
		MIB_CE_MBSSIB_T Entry;
		if(!mib_chain_get(MIB_MBSSIB_TBL, 0, &Entry))
			return;
		Entry.unicastCipher &= ~(WPA_CIPHER_TKIP);
		Entry.wpa2UnicastCipher &= ~(WPA_CIPHER_TKIP);
		mib_chain_update(MIB_MBSSIB_TBL, &Entry, 0);
	}
}

unsigned char wl_cipher2mib(unsigned char cipher) {
	unsigned char mib = 0;
	if (cipher & WPA_CIPHER_TKIP)
		mib |= 2;
	if (cipher & WPA_CIPHER_AES)
		mib |= 8;
	return mib;
}

static int _is_hex(char c)
{
    return (((c >= '0') && (c <= '9')) ||
            ((c >= 'A') && (c <= 'F')) ||
            ((c >= 'a') && (c <= 'f')));
}

static int string_to_hex(char *string, unsigned char *key, int len)
{
	char tmpBuf[4];
	int idx, ii=0;
	for (idx=0; idx<len; idx+=2) {
		tmpBuf[0] = string[idx];
		tmpBuf[1] = string[idx+1];
		tmpBuf[2] = 0;
		if ( !_is_hex(tmpBuf[0]) || !_is_hex(tmpBuf[1]))
			return 0;

		key[ii++] = (unsigned char) strtol(tmpBuf, (char**)NULL, 16);
	}
	return 1;
}

#ifdef WLAN_FAST_INIT
int setupWDS(struct wifi_mib *pmib)
{
#ifdef WLAN_WDS
	unsigned char value[128];
	char macaddr[16];
	char vChar, wds_enabled;
	char parm[128];
	char wds_num;
	char wdsPrivacy;
	WDS_T Entry;
	char wdsif[11];
	int i;
	int status = 0;

	mib_get(MIB_WLAN_MODE, (void *)&vChar);
	mib_get(MIB_WLAN_WDS_ENABLED, (void *)&wds_enabled);
	if (vChar != AP_WDS_MODE || wds_enabled == 0) {
		(&pmib->dot11WdsInfo)->wdsNum = 0;
		(&pmib->dot11WdsInfo)->wdsEnabled = 0;

		for (i=0; i<MAX_WDS_NUM; i++) {
			snprintf(wdsif, 10, (char *)WDSIF, (char*)getWlanIfName());
			wdsif[9] = '0' + i;
			wdsif[10] = '\0';
			//ifconfig wlanX-wdsX down
			status|=va_cmd(IFCONFIG, 2, 1, wdsif, "down");
			//brctl delif br0 wlanX-wdsX
			status|=va_cmd(BRCTL, 3, 1, "delif", (char *)BRIF, wdsif);
		}
		return 0;
	}

	// wds_pure
	(&pmib->dot11WdsInfo)->wdsPure = 0;

	// wds_enable
	mib_get(MIB_WLAN_WDS_ENABLED, (void *)&vChar);
	(&pmib->dot11WdsInfo)->wdsEnabled = vChar;
	(&pmib->dot11WdsInfo)->wdsNum = 0;

	//mib_get(MIB_WLAN_WDS_ENABLED, (void *)&vChar);
	//if(vChar==1){
		for (i=0; i<MAX_WDS_NUM; i++) {
			snprintf(wdsif, 10, (char *)WDSIF, (char*)getWlanIfName());

			wdsif[9] = '0' + i;
			wdsif[10] = '\0';
			//ifconfig wlanX-wdsX down
			status|=va_cmd(IFCONFIG, 2, 1, wdsif, "down");
			//brctl delif br0 wlanX-wdsX
			status|=va_cmd(BRCTL, 3, 1, "delif", (char *)BRIF, wdsif);
		}
	//}

	mib_get(MIB_WLAN_WDS_NUM, &wds_num);
	snprintf(wdsif, 10, (char *)WDSIF, (char*)getWlanIfName());
	(&pmib->dot11WdsInfo)->wdsNum = 0;

	for(i=0;i<wds_num;i++){
		if (!mib_chain_get(MIB_WDS_TBL, i, (void *)&Entry))
			continue;

		memcpy((&(&pmib->dot11WdsInfo)->entry[i])->macAddr, Entry.macAddr, 6);
		(&(&pmib->dot11WdsInfo)->entry[i])->txRate = Entry.fixedTxRate;
		(&pmib->dot11WdsInfo)->wdsNum++;
		//ifconfig wlanX-wdsX hw ether 00e04c867001
		getMIB2Str(MIB_ELAN_MAC_ADDR, macaddr);
#ifdef CONFIG_LUNA_DUAL_LINUX
		if(!strcmp(getWlanIfName(), "wlan1"))
			get_wlan_mac(WLAN1_MAC_FILE, macaddr);
#elif defined(CONFIG_RTL_92D_DMDP)
		if(wlan_idx == 1 && !useWlanIfVirtIdx())
			macaddr[5] += 5;
#endif
		wdsif[9] = '0'+i;
		wdsif[10] = '\0';
		status|=va_cmd(IFCONFIG, 4, 1, wdsif, "hw", "ether", macaddr);

		//brctl delif br0 wlanX-wdsX
		//va_cmd(BRCTL, 3, 1, "delif", (char *)BRIF, wdsif);
		//brctl addif br0 wlanX-wdsX
		status|=va_cmd(BRCTL, 3, 1, "addif", (char *)BRIF, wdsif);
#ifdef CONFIG_IPV6
		// Disable ipv6 in bridge
		setup_disable_ipv6(wdsif, 1);
#endif

		//ifconfig wlanX-wdsX up
		status|=va_cmd(IFCONFIG, 2, 1, wdsif, "up");
	}

	// wds_encrypt
	mib_get(MIB_WLAN_WDS_ENCRYPT, &vChar);
	if (vChar == WDS_ENCRYPT_DISABLED)//open
		wdsPrivacy = 0;
	else if (vChar == WDS_ENCRYPT_WEP64) {//wep 40
		wdsPrivacy = 1;
	}
	else if (vChar == WDS_ENCRYPT_WEP128) {//wep 104
		wdsPrivacy = 5;
	}
	else if (vChar == WDS_ENCRYPT_TKIP){//tkip
		wdsPrivacy = 2;
	}
	else if(vChar == WDS_ENCRYPT_AES){//ccmp
		wdsPrivacy = 4;
	}
	if(wdsPrivacy == 1 || wdsPrivacy == 5){
		mib_get(MIB_WLAN_WDS_WEP_KEY, (void *)value);
		if(wdsPrivacy == 1)
			string_to_hex((char *)value, (&pmib->dot11WdsInfo)->wdsWepKey, 10);
		else
			string_to_hex((char *)value, (&pmib->dot11WdsInfo)->wdsWepKey, 26);
		
	}
	else if(wdsPrivacy == 2|| wdsPrivacy == 4){
		mib_get(MIB_WLAN_WDS_PSK, (void *)value);
		strcpy((&pmib->dot11WdsInfo)->wdsPskPassPhrase, value);
	}

	(&pmib->dot11WdsInfo)->wdsPrivacy = wdsPrivacy;

	(&pmib->dot11WdsInfo)->wdsPriority = 1;

	//for MOD multicast-filter
	mib_get(MIB_WLAN_WDS_ENABLED, (void *)&vChar);
	if (vChar) {
		//brctl clrfltrport br0
		va_cmd(BRCTL,2,1,"clrfltrport",(char *)BRIF);
		//brctl setfltrport br0 11111
		va_cmd(BRCTL,3,1,"setfltrport",(char *)BRIF,"11111");
		//brctl setfltrport br0 55555
		va_cmd(BRCTL,3,1,"setfltrport",(char *)BRIF,"55555");
		//brctl setfltrport br0 2105
		va_cmd(BRCTL,3,1,"setfltrport",(char *)BRIF,"2105");
		//brctl setfltrport br0 2105
		va_cmd(BRCTL,3,1,"setfltrport",(char *)BRIF,"2107");
	}

	return status;
#else
	return 0;
#endif
}
#else
int setupWDS()
{
#ifdef WLAN_WDS
	unsigned char value[128];
	char macaddr[16];
	char vChar, wds_enabled;
	char parm[128];
	char wds_num;
	char wdsPrivacy;
	WDS_T Entry;
	char wdsif[11];
	int i;
	int status = 0;

	mib_get(MIB_WLAN_MODE, (void *)&vChar);
	mib_get(MIB_WLAN_WDS_ENABLED, (void *)&wds_enabled);
	if (vChar != AP_WDS_MODE || wds_enabled == 0) {
		status|=va_cmd(IWPRIV, 3, 1, (char*)getWlanIfName(), "set_mib", "wds_num=0");
		status|=va_cmd(IWPRIV, 3, 1, (char*)getWlanIfName(), "set_mib", "wds_enable=0");

		for (i=0; i<MAX_WDS_NUM; i++) {
			snprintf(wdsif, 10, (char *)WDSIF, (char*)getWlanIfName());
			wdsif[9] = '0' + i;
			wdsif[10] = '\0';
			//ifconfig wlanX-wdsX down
			status|=va_cmd(IFCONFIG, 2, 1, wdsif, "down");
			//brctl delif br0 wlanX-wdsX
			status|=va_cmd(BRCTL, 3, 1, "delif", (char *)BRIF, wdsif);
		}
		return 0;
	}

	// wds_pure
	status|=va_cmd(IWPRIV, 3, 1, (char*)getWlanIfName(), "set_mib", "wds_pure=0");

	// wds_enable
	mib_get(MIB_WLAN_WDS_ENABLED, (void *)&vChar);
	snprintf(parm,  sizeof(parm), "wds_enable=%u", vChar);
	status|=va_cmd(IWPRIV, 3, 1, (char*)getWlanIfName(), "set_mib", parm);
	
	status|=va_cmd(IWPRIV, 3, 1, (char*)getWlanIfName(), "set_mib", "wds_num=0");

	//mib_get(MIB_WLAN_WDS_ENABLED, (void *)&vChar);
	//if(vChar==1){
		for (i=0; i<MAX_WDS_NUM; i++) {
			snprintf(wdsif, 10, (char *)WDSIF, (char*)getWlanIfName());

			wdsif[9] = '0' + i;
			wdsif[10] = '\0';
			//ifconfig wlanX-wdsX down
			status|=va_cmd(IFCONFIG, 2, 1, wdsif, "down");
			//brctl delif br0 wlanX-wdsX
			status|=va_cmd(BRCTL, 3, 1, "delif", (char *)BRIF, wdsif);
		}
	//}

	mib_get(MIB_WLAN_WDS_NUM, &wds_num);
	snprintf(wdsif, 10, (char *)WDSIF, (char*)getWlanIfName());

	for(i=0;i<wds_num;i++){
		if (!mib_chain_get(MIB_WDS_TBL, i, (void *)&Entry))
			continue;
		snprintf(parm, sizeof(parm), "wds_add=%02x%02x%02x%02x%02x%02x,%u",
			Entry.macAddr[0], Entry.macAddr[1], Entry.macAddr[2],
			Entry.macAddr[3], Entry.macAddr[4], Entry.macAddr[5], Entry.fixedTxRate);
		status|=va_cmd(IWPRIV, 3, 1, (char*)getWlanIfName(), "set_mib", parm);
		//ifconfig wlanX-wdsX hw ether 00e04c867001
		getMIB2Str(MIB_ELAN_MAC_ADDR, macaddr);
#ifdef CONFIG_LUNA_DUAL_LINUX
		if(!strcmp(getWlanIfName(), "wlan1"))
			get_wlan_mac(WLAN1_MAC_FILE, macaddr);
#elif defined(CONFIG_RTL_92D_DMDP)
		if(wlan_idx == 1 && !useWlanIfVirtIdx())
			macaddr[5] += 5;
#endif
		wdsif[9] = '0'+i;
		wdsif[10] = '\0';
		status|=va_cmd(IFCONFIG, 4, 1, wdsif, "hw", "ether", macaddr);

		//brctl delif br0 wlanX-wdsX
		//va_cmd(BRCTL, 3, 1, "delif", (char *)BRIF, wdsif);
		//brctl addif br0 wlanX-wdsX
		status|=va_cmd(BRCTL, 3, 1, "addif", (char *)BRIF, wdsif);
#ifdef CONFIG_IPV6
		// Disable ipv6 in bridge
		setup_disable_ipv6(wdsif, 1);
#endif

		//ifconfig wlanX-wdsX up
		status|=va_cmd(IFCONFIG, 2, 1, wdsif, "up");
	}

	// wds_encrypt
	mib_get(MIB_WLAN_WDS_ENCRYPT, &vChar);
	if (vChar == WDS_ENCRYPT_DISABLED)//open
		wdsPrivacy = 0;
	else if (vChar == WDS_ENCRYPT_WEP64) {//wep 40
		wdsPrivacy = 1;
	}
	else if (vChar == WDS_ENCRYPT_WEP128) {//wep 104
		wdsPrivacy = 5;
	}
	else if (vChar == WDS_ENCRYPT_TKIP){//tkip
		wdsPrivacy = 2;
	}
	else if(vChar == WDS_ENCRYPT_AES){//ccmp
		wdsPrivacy = 4;
	}
	if(wdsPrivacy == 1 || wdsPrivacy == 5){
		mib_get(MIB_WLAN_WDS_WEP_KEY, (void *)value);
		snprintf(parm, sizeof(parm), "wds_wepkey=%s", value);
		status|=va_cmd(IWPRIV, 3, 1, (char*)getWlanIfName(), "set_mib", parm);
		
	}
	else if(wdsPrivacy == 2|| wdsPrivacy == 4){
		mib_get(MIB_WLAN_WDS_PSK, (void *)value);
		snprintf(parm, sizeof(parm), "wds_passphrase=%s", value);
		status|=va_cmd(IWPRIV, 3, 1, (char*)getWlanIfName(), "set_mib", parm);
	}
	snprintf(parm, sizeof(parm), "wds_encrypt=%u", wdsPrivacy);
	status|=va_cmd(IWPRIV, 3, 1, (char*)getWlanIfName(), "set_mib", parm);

	status|=va_cmd(IWPRIV, 3, 1, (char*)getWlanIfName(), "set_mib", "wds_priority=1");

	//for MOD multicast-filter
	mib_get(MIB_WLAN_WDS_ENABLED, (void *)&vChar);
	if (vChar) {
		//brctl clrfltrport br0
		va_cmd(BRCTL,2,1,"clrfltrport",(char *)BRIF);
		//brctl setfltrport br0 11111
		va_cmd(BRCTL,3,1,"setfltrport",(char *)BRIF,"11111");
		//brctl setfltrport br0 55555
		va_cmd(BRCTL,3,1,"setfltrport",(char *)BRIF,"55555");
		//brctl setfltrport br0 2105
		va_cmd(BRCTL,3,1,"setfltrport",(char *)BRIF,"2105");
		//brctl setfltrport br0 2105
		va_cmd(BRCTL,3,1,"setfltrport",(char *)BRIF,"2107");
	}

	return status;
#else
	return 0;
#endif
}
#endif
//krammer
#ifdef WLAN_MBSSID
static void _set_vap_para(const char* arg1, const char* arg2, config_wlan_ssid ssid_index){
	int i, start, end;
	char ifname[16];
	
	for(i=0; i<WLAN_MBSSID_NUM; i++){

		if(ssid_index != CONFIG_SSID_ALL && ssid_index != (i+1))
			continue;
		

		snprintf(ifname, 16, "%s-vap%d", (char *)getWlanIfName(), i);
		va_cmd(IWPRIV, 3, 1, ifname, arg1, arg2);
	}
}

#define set_vap_para(a, b, c) _set_vap_para(a, b, c)
#else
#define set_vap_para(a, b, c)
#endif

#ifdef WLAN_FAST_INIT
static void setupWLan_WPA(struct wifi_mib *pmib, int vwlan_idx)
{
	char parm[64];
	int vInt, status;
	MIB_CE_MBSSIB_T Entry;

	mib_chain_get(MIB_MBSSIB_TBL, vwlan_idx, (void *)&Entry);

	// encmode
	vInt = (int)Entry.encrypt;

	if (Entry.encrypt == WIFI_SEC_WEP)	// WEP mode
	{
		// psk_enable: 0
		(&pmib->dot1180211AuthEntry)->dot11EnablePSK = 0;
		if (Entry.wep == WEP64) {
			// 64 bits
			vInt = 1; // encmode = 1
			// wepkey1
			// Mason Yu. 201009_new_security.
			memcpy((&pmib->dot11DefaultKeysTable)->keytype,Entry.wep64Key1,5);
		}
		else {
			// 128 bits
			vInt = 5; // encmode = 5
			// wepkey1
			// Mason Yu. 201009_new_security.
			memcpy((&pmib->dot11DefaultKeysTable)->keytype,Entry.wep128Key1,13);
		}
	}
	// Kaohj --- this is for driver level security.
	// ignoring it if using userland 'auth' security
	#ifdef CONFIG_RTL_WAPI_SUPPORT
	else if (Entry.encrypt == WIFI_SEC_WAPI) {
		//char wapiAuth;
		vInt = 0; // encmode = 0 for WAPI
		(&pmib->wapiInfo)->wapiType = Entry.wapiAuth;
		// psk_enable: 0
		(&pmib->dot1180211AuthEntry)->dot11EnablePSK = 0;
		
		if (Entry.wapiAuth==2) { //PSK
			//char pskFormat, pskLen, pskValue[MAX_PSK_LEN];
			//mib_get(MIB_WLAN_WAPI_PSK_FORMAT, (void *)&pskFormat);
			//mib_get(MIB_WLAN_WAPI_PSK, (void *)pskValue);
			//mib_get(MIB_WLAN_WAPI_PSKLEN, (void *)&pskLen);


			if (Entry.wapiPskFormat) { // HEX
				int i;
				char hexstr[4];
				for (i=0;i<Entry.wapiPskLen;i++) {
					snprintf(hexstr, sizeof(hexstr), "%02x", Entry.wapiPsk[i]);
					strcat(parm, hexstr);
				}
				(&(&pmib->wapiInfo)->wapiPsk)->len = Entry.wapiPskLen;
				memcpy((&(&pmib->wapiInfo)->wapiPsk)->octet, parm, Entry.wapiPskLen*2);
				

			} else { // passphrase
				(&(&pmib->wapiInfo)->wapiPsk)->len = Entry.wapiPskLen;
				memcpy((&(&pmib->wapiInfo)->wapiPsk)->octet, Entry.wapiPsk, Entry.wapiPskLen);
			}
		} else { //AS

		}


	}
	#endif
	else if (Entry.encrypt >= WIFI_SEC_WPA) {	// WPA setup
		// Mason Yu. 201009_new_security. Start
		if (Entry.encrypt == WIFI_SEC_WPA
			|| Entry.encrypt == WIFI_SEC_WPA2_MIXED) {
			(&pmib->dot1180211AuthEntry)->dot11WPACipher = wl_cipher2mib(Entry.unicastCipher);
		} else {
			(&pmib->dot1180211AuthEntry)->dot11WPACipher = 0;
		}
		
		if (Entry.encrypt == WIFI_SEC_WPA2
			|| Entry.encrypt == WIFI_SEC_WPA2_MIXED) {
			(&pmib->dot1180211AuthEntry)->dot11WPA2Cipher = wl_cipher2mib(Entry.wpa2UnicastCipher);
		} else {
			(&pmib->dot1180211AuthEntry)->dot11WPA2Cipher = 0;
		}
		// Mason Yu. 201009_new_security. End

		if (!is8021xEnabled(vwlan_idx)) {
			// psk_enable: 1: WPA, 2: WPA2, 3: WPA+WPA2
			(&pmib->dot1180211AuthEntry)->dot11EnablePSK = Entry.encrypt/2;
			
			// passphrase
			strcpy((&pmib->dot1180211AuthEntry)->dot11PassPhrase, Entry.wpaPSK);
			
			(&pmib->dot1180211AuthEntry)->dot11GKRekeyTime = Entry.wpaGroupRekeyTime;
		}
		else {
			// psk_enable: 0
			(&pmib->dot1180211AuthEntry)->dot11EnablePSK = 0;
		}
		vInt = 2;
	}
	else {
		// psk_enable: 0
		(&pmib->dot1180211AuthEntry)->dot11EnablePSK = 0;
	}
	(&pmib->dot1180211AuthEntry)->dot11PrivacyAlgrthm = vInt;
}

#else
/*
 *	vwlan_idx:
 *	0:	Root
 *	1 ~ :	VAP, Repeater
 */
static int setupWLan_WPA(int vwlan_idx)
{
	char ifname[16];
	char parm[128];
	int vInt, status;
	MIB_CE_MBSSIB_T Entry;

#if defined(CONFIG_RTL_STA_CONTROL_SUPPORT) && defined(WLAN_DUALBAND_CONCURRENT)
	unsigned char wlan_sta_control=0;
	int orig_wlan_idx = wlan_idx;
	if(wlan_idx == 1 && vwlan_idx == 0){
		if(get_root_wlan_status()==1){
			mib_get(MIB_WIFI_STA_CONTROL, (void *)&wlan_sta_control);
		}
		if(wlan_sta_control==1)
			wlan_idx = 0;
	}
#endif

	mib_chain_get(MIB_MBSSIB_TBL, vwlan_idx, (void *)&Entry);
	
#if defined(CONFIG_RTL_STA_CONTROL_SUPPORT) && defined(WLAN_DUALBAND_CONCURRENT)
	if(wlan_sta_control==1 && vwlan_idx == 0){
		wlan_idx = orig_wlan_idx;
	}
#endif

	if (vwlan_idx==0) 
		strncpy(ifname, (char*)getWlanIfName(), 16);
	else {
		#ifdef WLAN_MBSSID
		if (vwlan_idx>=WLAN_VAP_ITF_INDEX && vwlan_idx<(WLAN_VAP_ITF_INDEX+WLAN_MBSSID_NUM))
			snprintf(ifname, 16, "%s-vap%d", (char *)getWlanIfName(), vwlan_idx-1);
		#endif
		#ifdef WLAN_UNIVERSAL_REPEATER
		if (vwlan_idx == WLAN_REPEATER_ITF_INDEX)
			snprintf(ifname, 16, "%s-vxd", (char *)getWlanIfName());
		#endif
	}

	// encmode
	vInt = (int)Entry.encrypt;

	if (Entry.encrypt == WIFI_SEC_WEP)	// WEP mode
	{
		// psk_enable: 0
		status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", "psk_enable=0");

		if (Entry.wep == WEP64) {
			// 64 bits
			vInt = 1; // encmode = 1
			// wepkey1
			// Mason Yu. 201009_new_security.
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
			snprintf(parm, sizeof(parm), "wepdkeyid=%hhu", Entry.wepDefaultKey);
			status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", parm);
			switch(Entry.wepDefaultKey)
			{
				case 0:
					snprintf(parm, sizeof(parm), "wepkey1=%02x%02x%02x%02x%02x", Entry.wep64Key1[0],
						Entry.wep64Key1[1], Entry.wep64Key1[2], Entry.wep64Key1[3], Entry.wep64Key1[4]);
					status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", parm);
					break;
				case 1:
					snprintf(parm, sizeof(parm), "wepkey2=%02x%02x%02x%02x%02x", Entry.wep64Key2[0],
						Entry.wep64Key2[1], Entry.wep64Key2[2], Entry.wep64Key2[3], Entry.wep64Key2[4]);
					status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", parm);
					break;
				case 2:
					snprintf(parm, sizeof(parm), "wepkey3=%02x%02x%02x%02x%02x", Entry.wep64Key3[0],
						Entry.wep64Key3[1], Entry.wep64Key3[2], Entry.wep64Key3[3], Entry.wep64Key3[4]);
					status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", parm);
					break;
				case 3:
					snprintf(parm, sizeof(parm), "wepkey4=%02x%02x%02x%02x%02x", Entry.wep64Key4[0],
						Entry.wep64Key4[1], Entry.wep64Key4[2], Entry.wep64Key4[3], Entry.wep64Key4[4]);
					status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", parm);
					break;
			}
#else
			snprintf(parm, sizeof(parm), "wepkey1=%02x%02x%02x%02x%02x", Entry.wep64Key1[0],
				Entry.wep64Key1[1], Entry.wep64Key1[2], Entry.wep64Key1[3], Entry.wep64Key1[4]);
			status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", parm);
#endif
		}
		else {
			// 128 bits
			vInt = 5; // encmode = 5
			// wepkey1
			// Mason Yu. 201009_new_security.
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
			snprintf(parm, sizeof(parm), "wepdkeyid=%hhu", Entry.wepDefaultKey);
			status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", parm);
			switch(Entry.wepDefaultKey)
			{
				case 0:
					snprintf(parm, sizeof(parm), "wepkey1=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
					Entry.wep128Key1[0], Entry.wep128Key1[1], Entry.wep128Key1[2], Entry.wep128Key1[3], Entry.wep128Key1[4],
					Entry.wep128Key1[5], Entry.wep128Key1[6], Entry.wep128Key1[7], Entry.wep128Key1[8], Entry.wep128Key1[9],
					Entry.wep128Key1[10], Entry.wep128Key1[11], Entry.wep128Key1[12]);
					status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", parm);
					break;
				case 1:
					snprintf(parm, sizeof(parm), "wepkey2=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
					Entry.wep128Key2[0], Entry.wep128Key2[1], Entry.wep128Key2[2], Entry.wep128Key2[3], Entry.wep128Key2[4],
					Entry.wep128Key2[5], Entry.wep128Key2[6], Entry.wep128Key2[7], Entry.wep128Key2[8], Entry.wep128Key2[9],
					Entry.wep128Key2[10], Entry.wep128Key2[11], Entry.wep128Key2[12]);
					status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", parm);
					break;
				case 2:
					snprintf(parm, sizeof(parm), "wepkey3=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
					Entry.wep128Key3[0], Entry.wep128Key3[1], Entry.wep128Key3[2], Entry.wep128Key3[3], Entry.wep128Key3[4],
					Entry.wep128Key3[5], Entry.wep128Key3[6], Entry.wep128Key3[7], Entry.wep128Key3[8], Entry.wep128Key3[9],
					Entry.wep128Key3[10], Entry.wep128Key3[11], Entry.wep128Key3[12]);
					status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", parm);
					break;
				case 3:
					snprintf(parm, sizeof(parm), "wepkey4=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
					Entry.wep128Key4[0], Entry.wep128Key4[1], Entry.wep128Key4[2], Entry.wep128Key4[3], Entry.wep128Key4[4],
					Entry.wep128Key4[5], Entry.wep128Key4[6], Entry.wep128Key4[7], Entry.wep128Key4[8], Entry.wep128Key4[9],
					Entry.wep128Key4[10], Entry.wep128Key4[11], Entry.wep128Key4[12]);
					status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", parm);
					break;
			}
#else
			snprintf(parm, sizeof(parm), "wepkey1=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
				Entry.wep128Key1[0], Entry.wep128Key1[1], Entry.wep128Key1[2], Entry.wep128Key1[3], Entry.wep128Key1[4],
				Entry.wep128Key1[5], Entry.wep128Key1[6], Entry.wep128Key1[7], Entry.wep128Key1[8], Entry.wep128Key1[9],
				Entry.wep128Key1[10], Entry.wep128Key1[11], Entry.wep128Key1[12]);
			status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", parm);
#endif
		}
	}
	// Kaohj --- this is for driver level security.
	// ignoring it if using userland 'auth' security
	#ifdef CONFIG_RTL_WAPI_SUPPORT
	else if (Entry.encrypt == WIFI_SEC_WAPI) {
		//char wapiAuth;
		vInt = 0; // encmode = 0 for WAPI
		snprintf(parm, sizeof(parm), "wapiType=%d", Entry.wapiAuth);
		status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", parm);

		// psk_enable: 0
		status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", "psk_enable=0");

		if (Entry.wapiAuth==2) { //PSK
			//char pskFormat, pskLen, pskValue[MAX_PSK_LEN];
			//mib_get(MIB_WLAN_WAPI_PSK_FORMAT, (void *)&pskFormat);
			//mib_get(MIB_WLAN_WAPI_PSK, (void *)pskValue);
			//mib_get(MIB_WLAN_WAPI_PSKLEN, (void *)&pskLen);


			if (Entry.wapiPskFormat) { // HEX
				int i;
				char hexstr[4];
				snprintf(parm, sizeof(parm), "wapiPsk=");
				for (i=0;i<Entry.wapiPskLen;i++) {
					snprintf(hexstr, sizeof(hexstr), "%02x", Entry.wapiPsk[i]);
					strcat(parm, hexstr);
				}
				strcat(parm, ",");
				snprintf(hexstr, sizeof(hexstr), "%x", Entry.wapiPskLen);
				strcat(parm, hexstr);
				status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", parm);

			} else { // passphrase
				snprintf(parm, sizeof(parm), "wapiPsk=%s,%x", Entry.wapiPsk, Entry.wapiPskLen);
				status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", parm);
			}
		} else { //AS

		}


	}
	#endif
	else if (Entry.encrypt >= WIFI_SEC_WPA) {	// WPA setup
		// Mason Yu. 201009_new_security. Start
		if (Entry.encrypt == WIFI_SEC_WPA
#ifndef NEW_WIFI_SEC
			|| Entry.encrypt == WIFI_SEC_WPA2_MIXED
#endif
			) {
			snprintf(parm, sizeof(parm), "wpa_cipher=%d", wl_cipher2mib(Entry.unicastCipher));
			status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", parm);
		}
#ifdef NEW_WIFI_SEC
		else if (Entry.encrypt == WIFI_SEC_WPA2_MIXED){
			snprintf(parm, sizeof(parm), "wpa_cipher=%d", wl_cipher2mib(WPA_CIPHER_MIXED));
			status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", parm);
		}
#endif
		else {
			snprintf(parm, sizeof(parm), "wpa_cipher=0");
			status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", parm);
		}
		
		if (Entry.encrypt == WIFI_SEC_WPA2
#ifndef NEW_WIFI_SEC
			|| Entry.encrypt == WIFI_SEC_WPA2_MIXED
#endif
			) {
			snprintf(parm, sizeof(parm), "wpa2_cipher=%d", wl_cipher2mib(Entry.wpa2UnicastCipher));
			status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", parm);
		}
#ifdef NEW_WIFI_SEC
		else if (Entry.encrypt == WIFI_SEC_WPA2_MIXED){
			snprintf(parm, sizeof(parm), "wpa2_cipher=%d", wl_cipher2mib(WPA_CIPHER_MIXED));
			status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", parm);
		}
#endif
		else {
			snprintf(parm, sizeof(parm), "wpa2_cipher=0");
			status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", parm);
		}
		// Mason Yu. 201009_new_security. End
		if (!is8021xEnabled(vwlan_idx)) {
			// psk_enable: 1: WPA, 2: WPA2, 3: WPA+WPA2
			snprintf(parm, sizeof(parm), "psk_enable=%d", Entry.encrypt/2);
			status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", parm);

			// passphrase
			snprintf(parm, sizeof(parm), "passphrase=%s", Entry.wpaPSK);
			status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", parm);

			snprintf(parm, sizeof(parm), "gk_rekey=%d", Entry.wpaGroupRekeyTime);
			status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", parm);
		}
		else {
			// psk_enable: 0
			status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", "psk_enable=0");
		}
		vInt = 2;
	}
	else {
		// psk_enable: 0
		status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", "psk_enable=0");
	}
#ifdef WLAN_11W		
	if (Entry.encrypt == WIFI_SEC_WPA2){
		snprintf(parm, sizeof(parm), "dot11IEEE80211W=%d", Entry.dotIEEE80211W);
		status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", parm);
		snprintf(parm, sizeof(parm), "enableSHA256=%d", Entry.sha256);
		status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", parm);
	}
	else{
		snprintf(parm, sizeof(parm), "dot11IEEE80211W=0");
		status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", parm);
		snprintf(parm, sizeof(parm), "enableSHA256=0");
		status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", parm);
	}
#endif
	snprintf(parm, sizeof(parm), "encmode=%u", vInt);
	status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", parm);
	return status;
}
#endif

#ifdef WLAN_11R
static int setupWLan_FT(int vwlan_idx)
{
	char ifname[16];
	char parm[64];
	int vInt, status;
	MIB_CE_MBSSIB_T Entry;

	mib_chain_get(MIB_MBSSIB_TBL, vwlan_idx, (void *)&Entry);
	
	if (vwlan_idx==0) 
		strncpy(ifname, (char*)getWlanIfName(), 16);
	else {
		#ifdef WLAN_MBSSID
		if (vwlan_idx>=WLAN_VAP_ITF_INDEX && vwlan_idx<(WLAN_VAP_ITF_INDEX+WLAN_MBSSID_NUM))
			snprintf(ifname, 16, "%s-vap%d", (char *)getWlanIfName(), vwlan_idx-1);
		#endif
		#ifdef WLAN_UNIVERSAL_REPEATER
		if (vwlan_idx == WLAN_REPEATER_ITF_INDEX)
			snprintf(ifname, 16, "%s-vxd", (char *)getWlanIfName());
		#endif
	}

	snprintf(parm, sizeof(parm), "ft_enable=%d", Entry.ft_enable);
	status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", parm);

	snprintf(parm, sizeof(parm), "ft_mdid=%s", Entry.ft_mdid);
	status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", parm);

	snprintf(parm, sizeof(parm), "ft_over_ds=%d", Entry.ft_over_ds);
	status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", parm);

	snprintf(parm, sizeof(parm), "ft_res_request=%d", Entry.ft_res_request);
	status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", parm);

	snprintf(parm, sizeof(parm), "ft_r0key_timeout=%d", Entry.ft_r0key_timeout);
	status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", parm);

	snprintf(parm, sizeof(parm), "ft_reasoc_timeout=%d", Entry.ft_reasoc_timeout);
	status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", parm);

	snprintf(parm, sizeof(parm), "ft_r0kh_id=%s", Entry.ft_r0kh_id);
	status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", parm);

	snprintf(parm, sizeof(parm), "ft_push=%d", Entry.ft_push);
	status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", parm);

	return status;
}

int genFtKhConfig()
{
	MIB_CE_WLAN_FTKH_T ent;
	int ii, i, entryNum;
	int j, wlanIdxBackup=wlan_idx;
	char ifname[17]={0};
	char tmpbuf[200], macStr[18]={0};
	int status=0, ishex;
	FILE *fp;
 	unsigned char enckey[35]={0};

	if((fp=fopen(FT_CONF, "w")) == NULL)
	{
		printf("%s: Cannot create %s!\n", __func__, FT_CONF);
		return -1;
	}

	for (j=0; j<NUM_WLAN_INTERFACE; j++) {
		wlan_idx = j;
		entryNum = mib_chain_total(MIB_WLAN_FTKH_TBL);
		for (i=0; i<entryNum; i++) {
			if (!mib_chain_get(MIB_WLAN_FTKH_TBL, i, (void *)&ent))
			{
				printf("%s: Get chain record error!\n", __func__);
				return -1;
			}
			if (ent.intfIdx==0)
				strncpy(ifname, (char*)getWlanIfName(), 16);
			else {
				#ifdef WLAN_MBSSID
				if (ent.intfIdx>=WLAN_VAP_ITF_INDEX && ent.intfIdx<(WLAN_VAP_ITF_INDEX+WLAN_MBSSID_NUM))
					snprintf(ifname, 16, "%s-vap%d", (char *)getWlanIfName(), ent.intfIdx-1);
				#endif
				#ifdef WLAN_UNIVERSAL_REPEATER
				if (ent.intfIdx == WLAN_REPEATER_ITF_INDEX)
					snprintf(ifname, 16, "%s-vxd", (char *)getWlanIfName());
				#endif
			}
			snprintf(macStr, sizeof(macStr), "%02x:%02x:%02x:%02x:%02x:%02x",
				ent.addr[0], ent.addr[1], ent.addr[2], ent.addr[3], ent.addr[4], ent.addr[5]);

			// check key format
			ishex = 1;
			if (strlen(ent.key) != 32) {
				ishex=0;
			}
			else
				for (ii=0; ii<32; ii++)
					if (!_is_hex(ent.key[ii])) {
						ishex = 0;
						break;
					}
			if (!ishex)
				snprintf(enckey, sizeof(enckey), "\"%s\"", ent.key);
			
			fprintf(fp, "r0kh=%s %s %s %s\n", macStr, ent.r0kh_id, ishex?ent.key:enckey, ifname);
			fprintf(fp, "r1kh=%s %s %s %s\n", macStr, macStr, ishex?ent.key:enckey, ifname);
		}
	}

	wlan_idx = wlanIdxBackup;
	fclose(fp);
	return 0;
}

int start_FT()
{
	MIB_CE_MBSSIB_T Entry;
	int vwlan_idx=0, i;
	int status=0;
	char wlanDisabled;
	char *cmd_opt[16];
	int cmd_cnt = 0;
	int idx;
	//char intfList[200]="";
	char intfList[((WLAN_MAX_ITF_INDEX+1)*2)][32]={0};
	int intfNum=0;
	int enablePush=0;
#if defined(CONFIG_RTL_92D_SUPPORT) || defined(WLAN_DUALBAND_CONCURRENT)
	int orig_wlan_idx=wlan_idx;
#endif

	genFtKhConfig();
	for(i = 0; i<NUM_WLAN_INTERFACE; i++) {
		wlan_idx = i;
#ifdef WLAN_MBSSID
		for (vwlan_idx=0; vwlan_idx<=NUM_VWLAN_INTERFACE; vwlan_idx++) {
#endif
			wlan_getEntry(&Entry, vwlan_idx);
			if (vwlan_idx==0) // root
				wlanDisabled = Entry.wlanDisabled;
			if (wlanDisabled || Entry.wlanDisabled)
				continue;
			if (Entry.wlanMode == CLIENT_MODE)
				continue;

			if ((Entry.encrypt==4||Entry.encrypt==6) && Entry.ft_enable) {
				if (vwlan_idx==0)
					snprintf(intfList[intfNum], sizeof(intfList[intfNum]), "%s", (char *)getWlanIfName());
				else
					snprintf(intfList[intfNum], sizeof(intfList[intfNum]), "%s-vap%d", (char *)getWlanIfName(), vwlan_idx-WLAN_VAP_ITF_INDEX);
				intfNum++;
				if (Entry.ft_push)
					enablePush = 1;
			}
#ifdef WLAN_MBSSID
		}
#endif
	}

	fprintf(stderr, "START 802.11r SETUP!\n");
	cmd_opt[cmd_cnt++] = "";

	if (intfNum) {
		cmd_opt[cmd_cnt++] = "-w";
		for (i=0; i<intfNum; i++)
			cmd_opt[cmd_cnt++] = (char *)intfList[i];

		cmd_opt[cmd_cnt++] = "-c";
		cmd_opt[cmd_cnt++] = (char *)FT_CONF;

		cmd_opt[cmd_cnt++] = "-pid";
		cmd_opt[cmd_cnt++] = (char *)FT_PID;

		cmd_opt[cmd_cnt] = 0;
		printf("CMD ARGS: ");
		for (idx=0; idx<cmd_cnt;idx++)
			printf("%s ", cmd_opt[idx]);
		printf("\n");

		status |= do_nice_cmd(FT_DAEMON_PROG, cmd_opt, 0);
	}

#if defined(CONFIG_RTL_92D_SUPPORT) || defined(WLAN_DUALBAND_CONCURRENT)
	wlan_idx = orig_wlan_idx;
#endif

	return status;
}
#endif

#ifdef WLAN_11K
static int setupWLan_dot11K(int vwlan_idx)
{
	char ifname[16];
	char parm[128];
	int vInt, status;
	MIB_CE_MBSSIB_T Entry;
	unsigned char phyband=0, roaming_enable=0;

	mib_chain_get(MIB_MBSSIB_TBL, vwlan_idx, (void *)&Entry);

	if (vwlan_idx==0)
		strncpy(ifname, (char*)getWlanIfName(), 16);
	else {
		#ifdef WLAN_MBSSID
		if (vwlan_idx>=WLAN_VAP_ITF_INDEX && vwlan_idx<(WLAN_VAP_ITF_INDEX+WLAN_MBSSID_NUM))
			snprintf(ifname, 16, "%s-vap%d", (char *)getWlanIfName(), vwlan_idx-1);
		#endif
		#ifdef WLAN_UNIVERSAL_REPEATER
		if (vwlan_idx == WLAN_REPEATER_ITF_INDEX)
			snprintf(ifname, 16, "%s-vxd", (char *)getWlanIfName());
		#endif
	}
	if(vwlan_idx == 0 && Entry.rm_activated == 0){
		mib_get(MIB_WLAN_PHY_BAND_SELECT, &phyband);
		mib_get(phyband==PHYBAND_5G? MIB_ROAMING5G_ENABLE:MIB_ROAMING2G_ENABLE, &roaming_enable);
		if(roaming_enable == 1)
			Entry.rm_activated = roaming_enable;
	}

	snprintf(parm, sizeof(parm), "rm_activated=%d", Entry.rm_activated);
	status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", parm);

	if(Entry.rm_activated){
		snprintf(parm, sizeof(parm), "rm_link_measure=1");
		status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", parm);

		snprintf(parm, sizeof(parm), "rm_beacon_passive=1");
		status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", parm);

		snprintf(parm, sizeof(parm), "rm_beacon_active=1");
		status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", parm);

		snprintf(parm, sizeof(parm), "rm_beacon_table=1");
		status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", parm);

		snprintf(parm, sizeof(parm), "rm_neighbor_report=1");
		status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", parm);

		snprintf(parm, sizeof(parm), "rm_ap_channel_report=1");
		status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", parm);
	}

	//if(Entry.wlanDisabled==0 && Entry.rm_activated)
	//	status|=va_niced_cmd(DOT11K_DAEMON_PROG, 2, 0, "-i", ifname);

	return status;
}
#endif

#ifdef WLAN_11V
static int setupWLan_dot11V(int vwlan_idx)
{
	char ifname[16];
	char parm[128];
	int vInt, status;
	MIB_CE_MBSSIB_T Entry;
	unsigned char phyband=0, roaming_enable=0;

	mib_chain_get(MIB_MBSSIB_TBL, vwlan_idx, (void *)&Entry);

	if (vwlan_idx==0)
		strncpy(ifname, (char*)getWlanIfName(), 16);
	else {
		#ifdef WLAN_MBSSID
		if (vwlan_idx>=WLAN_VAP_ITF_INDEX && vwlan_idx<(WLAN_VAP_ITF_INDEX+WLAN_MBSSID_NUM))
			snprintf(ifname, 16, "%s-vap%d", (char *)getWlanIfName(), vwlan_idx-1);
		#endif
		#ifdef WLAN_UNIVERSAL_REPEATER
		if (vwlan_idx == WLAN_REPEATER_ITF_INDEX)
			snprintf(ifname, 16, "%s-vxd", (char *)getWlanIfName());
		#endif
	}

	if(vwlan_idx == 0 && Entry.rm_activated == 0){
		mib_get(MIB_WLAN_PHY_BAND_SELECT, &phyband);
		mib_get(phyband==PHYBAND_5G? MIB_ROAMING5G_ENABLE:MIB_ROAMING2G_ENABLE, &roaming_enable);
		if(roaming_enable == 1)
			Entry.rm_activated = Entry.BssTransEnable = roaming_enable;
	}

	if(Entry.rm_activated){
		snprintf(parm, sizeof(parm), "BssTransEnable=%d", Entry.BssTransEnable);
		status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", parm);
#ifdef CONFIG_IEEE80211V_DB
		snprintf(parm, sizeof(parm), "BssDbEnable=%d", Entry.BssTransEnable);
		status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", parm);
#endif
	}
	else{
		snprintf(parm, sizeof(parm), "BssTransEnable=0");
		status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", parm);
#ifdef CONFIG_IEEE80211V_DB
		snprintf(parm, sizeof(parm), "BssDbEnable=0");
		status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", parm);
#endif
	}

	return status;
}
#endif

#ifdef WLAN_ROAMING
static int setupWLan_Roaming(int vwlan_idx)
{
	char ifname[16];
	char parm[128];
	int status=0;
	unsigned char enable, rssi_th1, rssi_th2;
	unsigned int start_time;
	unsigned char phyband;

	if(vwlan_idx != 0) //now support root only
		return 0;

	if (vwlan_idx==0)
		strncpy(ifname, (char*)getWlanIfName(), 16);
	else {
		#ifdef WLAN_MBSSID
		if (vwlan_idx>=WLAN_VAP_ITF_INDEX && vwlan_idx<(WLAN_VAP_ITF_INDEX+WLAN_MBSSID_NUM))
			snprintf(ifname, 16, "%s-vap%d", (char *)getWlanIfName(), vwlan_idx-1);
		#endif
		#ifdef WLAN_UNIVERSAL_REPEATER
		if (vwlan_idx == WLAN_REPEATER_ITF_INDEX)
			snprintf(ifname, 16, "%s-vxd", (char *)getWlanIfName());
		#endif
	}
	mib_get(MIB_WLAN_PHY_BAND_SELECT, &phyband);

	if(phyband==PHYBAND_5G){
		mib_get(MIB_ROAMING5G_ENABLE, &enable);
		mib_get(MIB_ROAMING5G_STARTTIME, &start_time);
		mib_get(MIB_ROAMING5G_RSSI_TH1, &rssi_th1);
		mib_get(MIB_ROAMING5G_RSSI_TH2, &rssi_th2);
	}
	else{
		mib_get(MIB_ROAMING2G_ENABLE, &enable);
		mib_get(MIB_ROAMING2G_STARTTIME, &start_time);
		mib_get(MIB_ROAMING2G_RSSI_TH1, &rssi_th1);
		mib_get(MIB_ROAMING2G_RSSI_TH2, &rssi_th2);
	}

	snprintf(parm, sizeof(parm), "roaming_enable=%hhu", enable);
	status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", parm);

	snprintf(parm, sizeof(parm), "roaming_start_time=%u", start_time);
	status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", parm);

	snprintf(parm, sizeof(parm), "roaming_rssi_th1=%hhu", rssi_th1);
	status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", parm);

	snprintf(parm, sizeof(parm), "roaming_rssi_th2=%hhu", rssi_th2);
	status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", parm);

	snprintf(parm, sizeof(parm), "roaming_wait_time=3");
	status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", parm);

	return status;
}
#endif

int start_smart_wlanapp(void)
{
	int status=0;
#ifdef WLAN_SMARTAPP_ENABLE
	int i=0, idx=0, j=0;
#ifdef WLAN_DUALBAND_CONCURRENT
	int orig_wlan_idx = wlan_idx;
#endif
	MIB_CE_MBSSIB_T Entry;
	char *cmd_opt[16];
	int cmd_cnt = 0;
	int intfNum=0;
	char intfList[((WLAN_MAX_ITF_INDEX+1)*2)][32]={0};
#if defined(YUEME_3_0_SPEC)
	unsigned char no_wlan;
#endif

	cmd_opt[cmd_cnt++] = "";
	cmd_opt[cmd_cnt++] = "-w";
	
	for(i = 0; i<NUM_WLAN_INTERFACE; i++){
		wlan_idx = i;
#if defined(YUEME_3_0_SPEC)
		if(mib_get(MIB_WLAN_DISABLED, (void *)&no_wlan) == 1){
			if(no_wlan == 1) //disabled, do nothing
				continue;
		}
#endif

		for(j = 0; j<= WLAN_MBSSID_NUM; j++){
			wlan_getEntry(&Entry, j);
			if(Entry.wlanDisabled==0){
				if(j==0)
					snprintf(intfList[intfNum], sizeof(intfList[intfNum]), "%s", (char *)getWlanIfName());
				else
					snprintf(intfList[intfNum], sizeof(intfList[intfNum]), "%s-vap%d", (char *)getWlanIfName(), j-WLAN_VAP_ITF_INDEX);
				cmd_opt[cmd_cnt++] = intfList[intfNum];
				intfNum++;
			}
		}
	}
#ifdef WLAN_DUALBAND_CONCURRENT
	wlan_idx = orig_wlan_idx;
#endif

	if(intfNum>0){
		cmd_opt[cmd_cnt] = 0;
		printf("CMD ARGS: ");
		for (idx=0; idx<cmd_cnt;idx++)
			printf("%s ", cmd_opt[idx]);
		printf("\n");
		//status |= do_nice_cmd(SMART_WLANAPP_PROG, cmd_opt, 0);
		status |= do_cmd(SMART_WLANAPP_PROG, cmd_opt, 0);
	}
#endif
	return status;
}

#ifdef WLAN_FAST_INIT
static void setupWLan_802_1x(struct wifi_mib * pmib, int vwlan_idx)
{
	char parm[64];
	int vInt, status;
	MIB_CE_MBSSIB_T Entry;

	mib_chain_get(MIB_MBSSIB_TBL, vwlan_idx, (void *)&Entry);

	// Set 802.1x flag
	vInt = (int)Entry.encrypt;

	if (vInt <= WIFI_SEC_WEP)
	{
		// 802_1x
		(&pmib->dot118021xAuthEntry)->dot118021xAlgrthm = Entry.enable1X;
	}
#ifdef CONFIG_RTL_WAPI_SUPPORT
	else if (vInt == WIFI_SEC_WAPI) 
		(&pmib->dot118021xAuthEntry)->dot118021xAlgrthm = 0;
#endif
	else
		(&pmib->dot118021xAuthEntry)->dot118021xAlgrthm = 1;
}
#else
/*
 *	vwlan_idx:
 *	0:	Root
 *	1 ~ :	VAP, Repeater
 */
static int setupWLan_802_1x(int vwlan_idx)
{
	char ifname[16];
	char parm[64];
	int vInt, status;
	MIB_CE_MBSSIB_T Entry;

	mib_chain_get(MIB_MBSSIB_TBL, vwlan_idx, (void *)&Entry);
	if (vwlan_idx==0) 
		strncpy(ifname, (char*)getWlanIfName(), 16);
	else {
		#ifdef WLAN_MBSSID
		if (vwlan_idx>=WLAN_VAP_ITF_INDEX && vwlan_idx<(WLAN_VAP_ITF_INDEX+WLAN_MBSSID_NUM))
			snprintf(ifname, 16, "%s-vap%d", (char *)getWlanIfName(), vwlan_idx-1);
		#endif
		#ifdef WLAN_UNIVERSAL_REPEATER
		if (vwlan_idx == WLAN_REPEATER_ITF_INDEX)
			snprintf(ifname, 16, "%s-vxd", (char *)getWlanIfName());
		#endif
	}

	// Set 802.1x flag
	vInt = (int)Entry.encrypt;

	if (vInt <= WIFI_SEC_WEP)
	{
		// 802_1x
		snprintf(parm, sizeof(parm), "802_1x=%u", Entry.enable1X);
		status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", parm);
	}
#ifdef CONFIG_RTL_WAPI_SUPPORT
	else if (vInt == WIFI_SEC_WAPI) 
		status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", "802_1x=0");
#endif
	else
		status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", "802_1x=1");
	
	return status;
}
#endif
#ifdef WLAN_FAST_INIT
static void setupWLan_dot11_auth(struct wifi_mib* pmib, int vwlan_idx)
{
	char parm[64];
	unsigned char auth;
	#ifdef CONFIG_WIFI_SIMPLE_CONFIG
	unsigned char wsc_disabled;
	#endif
	int vInt, status;
	MIB_CE_MBSSIB_T Entry;

	mib_chain_get(MIB_MBSSIB_TBL, vwlan_idx, (void *)&Entry);

	auth = Entry.authType;

	if (Entry.authType == AUTH_SHARED && Entry.encrypt != WIFI_SEC_WEP)
		// shared-key and not WEP enabled, force to open-system
		auth = (AUTH_TYPE_T)AUTH_OPEN;
	#ifdef CONFIG_RTL_WAPI_SUPPORT
	if (Entry.encrypt==WIFI_SEC_WAPI)
		auth = (AUTH_TYPE_T)AUTH_OPEN;
	else 
		(&pmib->wapiInfo)->wapiType = 0;
	#endif

	#ifdef CONFIG_WIFI_SIMPLE_CONFIG //cathy
	if (vwlan_idx == 0) // root
		//clear wsc_enable, this parameter will be set in wsc daemon
		(&pmib->wscEntry)->wsc_enable = 0;

	wsc_disabled = Entry.wsc_disabled;
	if(vwlan_idx == 0 && Entry.authType == AUTH_SHARED && Entry.encrypt == WIFI_SEC_WEP && wsc_disabled!=1)
		auth = (AUTH_TYPE_T)AUTH_BOTH;	//if root shared-key and wep/wps enable, force to open+shared system for wps
	#endif
	(&pmib->dot1180211AuthEntry)->dot11AuthAlgrthm = auth;

}
#else
/*
 *	vwlan_idx:
 *	0:	Root
 *	1 ~ :	VAP, Repeater
 */
static int setupWLan_dot11_auth(int vwlan_idx)
{
	char ifname[16];
	char parm[64];
	unsigned char auth;
	#ifdef CONFIG_WIFI_SIMPLE_CONFIG
	unsigned char wsc_disabled;
	#endif
	int vInt, status;
	MIB_CE_MBSSIB_T Entry;
	mib_chain_get(MIB_MBSSIB_TBL, vwlan_idx, (void *)&Entry);
	
	if (vwlan_idx==0)
		strncpy(ifname, (char*)getWlanIfName(), 16);
	else {
		#ifdef WLAN_MBSSID
		if (vwlan_idx>=WLAN_VAP_ITF_INDEX && vwlan_idx<(WLAN_VAP_ITF_INDEX+WLAN_MBSSID_NUM))
			snprintf(ifname, 16, "%s-vap%d", (char *)getWlanIfName(), vwlan_idx-1);
		#endif
		#ifdef WLAN_UNIVERSAL_REPEATER
		if (vwlan_idx == WLAN_REPEATER_ITF_INDEX)
			snprintf(ifname, 16, "%s-vxd", (char *)getWlanIfName());
		#endif
	}

	auth = Entry.authType;

	if (Entry.authType == AUTH_SHARED && Entry.encrypt != WIFI_SEC_WEP)
		// shared-key and not WEP enabled, force to open-system
		auth = (AUTH_TYPE_T)AUTH_OPEN;
	#ifdef CONFIG_RTL_WAPI_SUPPORT
	if (Entry.encrypt==WIFI_SEC_WAPI)
		auth = (AUTH_TYPE_T)AUTH_OPEN;
	else 
		status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", "wapiType=0");
	#endif

	#ifdef CONFIG_WIFI_SIMPLE_CONFIG //cathy
	#ifndef WLAN_WPS_VAP
	if (vwlan_idx == 0) // root
	#endif
		//clear wsc_enable, this parameter will be set in wsc daemon
		status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", "wsc_enable=0");

	wsc_disabled = Entry.wsc_disabled;
	if(vwlan_idx == 0 && Entry.authType == AUTH_SHARED && Entry.encrypt == WIFI_SEC_WEP && wsc_disabled!=1)
		auth = (AUTH_TYPE_T)AUTH_BOTH;	//if root shared-key and wep/wps enable, force to open+shared system for wps
	#endif
	snprintf(parm, sizeof(parm), "authtype=%u", auth);
	status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", parm);
	return status;
}
#endif
#ifdef WLAN_FAST_INIT
void setupWlanHWSetting(char *ifname, struct wifi_mib *pmib)
{
		unsigned char value[34];
#if defined(CONFIG_RTL_92D_SUPPORT) || defined(WLAN0_5G_SUPPORT) || defined(WLAN1_5G_SUPPORT)
#if defined(CONFIG_RTL_92D_SUPPORT)
		mib_get(MIB_WLAN_MAC_PHY_MODE, (void *)value);
		(&pmib->dot11RFEntry)->macPhyMode = value[0];
#endif
		mib_get(MIB_WLAN_PHY_BAND_SELECT, (void *)value);
		(&pmib->dot11RFEntry)->phyBandSelect = value[0];
#endif
#ifdef CONFIG_RTL_92D_SUPPORT
		mib_get(MIB_HW_11N_TRSWITCH, (void *)value);
		if(value[0] != 0) 
			(&pmib->dot11RFEntry)->trswitch = value[0];	
#endif

#ifdef WLAN_DUALBAND_CONCURRENT
		if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
			mib_get(MIB_HW_WLAN1_TX_POWER_CCK_A, (void *)value);
		else // wlan0
#endif
		mib_get(MIB_HW_TX_POWER_CCK_A, (void *)value);
	if(value[0]!=0){
		(&pmib->efuseEntry)->enable_efuse = 0;
		memcpy((&pmib->dot11RFEntry)->pwrlevelCCK_A, value, MAX_CHAN_NUM);
	}
	else
		(&pmib->efuseEntry)->enable_efuse = 1;

#ifdef WLAN_DUALBAND_CONCURRENT
	if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
		mib_get(MIB_HW_WLAN1_TX_POWER_CCK_B, (void *)value);
	else // wlan0
#endif
		mib_get(MIB_HW_TX_POWER_CCK_B, (void *)value);
	if(value[0]!=0)
		memcpy((&pmib->dot11RFEntry)->pwrlevelCCK_B, value, MAX_CHAN_NUM);
		
#ifdef WLAN_DUALBAND_CONCURRENT
	if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
		mib_get(MIB_HW_WLAN1_TX_POWER_HT40_1S_A, (void *)value);
	else // wlan0
#endif
		mib_get(MIB_HW_TX_POWER_HT40_1S_A, (void *)value);
	if(value[0]!=0)
		memcpy((&pmib->dot11RFEntry)->pwrlevelHT40_1S_A, value, MAX_CHAN_NUM);
		
#ifdef WLAN_DUALBAND_CONCURRENT
	if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
		mib_get(MIB_HW_WLAN1_TX_POWER_HT40_1S_B, (void *)value);
	else // wlan0
#endif
		mib_get(MIB_HW_TX_POWER_HT40_1S_B, (void *)value);
	if(value[0]!=0)
		memcpy((&pmib->dot11RFEntry)->pwrlevelHT40_1S_B, value, MAX_CHAN_NUM);	

#ifdef WLAN_DUALBAND_CONCURRENT
	if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
		mib_get(MIB_HW_WLAN1_TX_POWER_HT40_2S, (void *)value);
	else
#endif
		mib_get(MIB_HW_TX_POWER_HT40_2S, (void *)value);
		memcpy((&pmib->dot11RFEntry)->pwrdiffHT40_2S, value, MAX_CHAN_NUM);

#ifdef WLAN_DUALBAND_CONCURRENT
		if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
			mib_get(MIB_HW_WLAN1_TX_POWER_HT20, (void *)value);
		else
#endif
		mib_get(MIB_HW_TX_POWER_HT20, (void *)value);
		memcpy((&pmib->dot11RFEntry)->pwrdiffHT20, value, MAX_CHAN_NUM);

#ifdef WLAN_DUALBAND_CONCURRENT
	if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
		mib_get(MIB_HW_WLAN1_TX_POWER_DIFF_OFDM, (void *)value);
	else
#endif
		mib_get(MIB_HW_TX_POWER_DIFF_OFDM, (void *)value);
		memcpy((&pmib->dot11RFEntry)->pwrdiffOFDM, value, MAX_CHAN_NUM);

#ifdef WLAN_DUALBAND_CONCURRENT
	if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
		mib_get(MIB_HW_WLAN1_11N_TSSI1 , (void *) value);
	else // wlan0
#endif
		mib_get(MIB_HW_11N_TSSI1, (void *)value);

	if(value[0] != 0)
		(&pmib->dot11RFEntry)->tssi1 = value[0];
	
#ifdef WLAN_DUALBAND_CONCURRENT
	if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
		mib_get(MIB_HW_WLAN1_11N_TSSI2, (void *)value);
	else
#endif
		mib_get(MIB_HW_11N_TSSI2, (void *)value);	

	if(value[0] != 0)
		(&pmib->dot11RFEntry)->tssi2 = value[0];

#ifdef WLAN_DUALBAND_CONCURRENT
	if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
		mib_get(MIB_HW_WLAN1_11N_THER, (void *)value);
	else
#endif
		mib_get(MIB_HW_11N_THER, (void *)&value);

	if(value[0] != 0)
		(&pmib->dot11RFEntry)->ther = value[0];

#if defined (WLAN_DUALBAND_CONCURRENT)
	if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
		mib_get(MIB_HW_WLAN1_RF_XCAP, (void *)value);
	else
#endif
		mib_get(MIB_HW_RF_XCAP, (void *)value);
		(&pmib->dot11RFEntry)->xcap = value[0];
}
#else
int get_WlanHWMIB(int index, int wlan0_mib_id, int wlan1_mib_id, void *value)
{
#ifdef WLAN_DUALBAND_CONCURRENT
#ifndef SWAP_HW_WLAN_MIB_INDEX
	if(index == 0)
#else
	if(index == 1)
#endif
		return mib_get(wlan0_mib_id, (void *)value);
	else
		return mib_get(wlan1_mib_id, (void *)value);
#else
	return mib_get(wlan0_mib_id, (void *)value);
#endif
}
int setupWlanHWSetting(char *ifname)
{
	int status=0;
	unsigned char value[34];
	char parm[64];
	char mode=0;
	int mib_index = 0;
#ifdef WLAN_DUALBAND_CONCURRENT
	if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
		mib_index = 1;
#endif
	
	if ( mib_get( MIB_TX_POWER, (void *)&mode) == 0) {
   			printf("Get MIB_TX_POWER error!\n");
   			status=-1;
	}

	get_WlanHWMIB(mib_index, MIB_HW_TX_POWER_CCK_A, MIB_HW_WLAN1_TX_POWER_CCK_A, value);
#if 0
	#ifdef WLAN_DUALBAND_CONCURRENT
	if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
		mib_get(MIB_HW_WLAN1_TX_POWER_CCK_A, (void *)value);
	else // wlan0
	#endif
		mib_get(MIB_HW_TX_POWER_CCK_A, (void *)value);
#endif


	if(value[0] != 0) {
#ifdef CONFIG_ENABLE_EFUSE
		//disable efuse
		status|=va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "use_efuse=0");
#endif
		status|=iwpriv_cmd(IWPRIV_HS|IWPRIV_HW2G|IWPRIV_TXPOWER, getWlanIfName(), "set_mib", "pwrlevelCCK_A", value, mode);
	}
#ifdef CONFIG_ENABLE_EFUSE
	else {
		//enable efuse
		status|=va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "use_efuse=1");
	}
#endif

	get_WlanHWMIB(mib_index, MIB_HW_TX_POWER_CCK_B, MIB_HW_WLAN1_TX_POWER_CCK_B, value);
#if 0
	#ifdef WLAN_DUALBAND_CONCURRENT
	if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
		mib_get(MIB_HW_WLAN1_TX_POWER_CCK_B, (void *)value);
	else // wlan0
	#endif
		mib_get(MIB_HW_TX_POWER_CCK_B, (void *)value);
#endif

	if(value[0] != 0) 
		status|=iwpriv_cmd(IWPRIV_HS|IWPRIV_HW2G|IWPRIV_TXPOWER, getWlanIfName(), "set_mib", "pwrlevelCCK_B", value, mode);

#ifdef CONFIG_WLAN_HAL_8814AE
	get_WlanHWMIB(mib_index, MIB_HW_TX_POWER_CCK_C, MIB_HW_WLAN1_TX_POWER_CCK_C, value);
#if 0
#ifdef WLAN_DUALBAND_CONCURRENT
	if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
		mib_get(MIB_HW_WLAN1_TX_POWER_CCK_C, (void *)value);
	else // wlan0
#endif
		mib_get(MIB_HW_TX_POWER_CCK_C, (void *)value);
#endif

	if(value[0] != 0) 
		status|=iwpriv_cmd(IWPRIV_HS|IWPRIV_HW2G|IWPRIV_TXPOWER, getWlanIfName(), "set_mib", "pwrlevelCCK_C", value, mode);

	get_WlanHWMIB(mib_index, MIB_HW_TX_POWER_CCK_D, MIB_HW_WLAN1_TX_POWER_CCK_D, value);
#if 0
#ifdef WLAN_DUALBAND_CONCURRENT
	if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
		mib_get(MIB_HW_WLAN1_TX_POWER_CCK_D, (void *)value);
	else // wlan0
#endif
		mib_get(MIB_HW_TX_POWER_CCK_D, (void *)value);
#endif

	if(value[0] != 0) 
		status|=iwpriv_cmd(IWPRIV_HS|IWPRIV_HW2G|IWPRIV_TXPOWER, getWlanIfName(), "set_mib", "pwrlevelCCK_D", value, mode);
#endif //CONFIG_WLAN_HAL_8814AE


	get_WlanHWMIB(mib_index, MIB_HW_TX_POWER_HT40_1S_A, MIB_HW_WLAN1_TX_POWER_HT40_1S_A, value);
#if 0
	#ifdef WLAN_DUALBAND_CONCURRENT
	if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
		mib_get(MIB_HW_WLAN1_TX_POWER_HT40_1S_A, (void *)value);
	else // wlan0
	#endif
		mib_get(MIB_HW_TX_POWER_HT40_1S_A, (void *)value);
#endif

	if(value[0] != 0) 
		status|=iwpriv_cmd(IWPRIV_HS|IWPRIV_HW2G|IWPRIV_TXPOWER, getWlanIfName(), "set_mib", "pwrlevelHT40_1S_A", value, mode);

	get_WlanHWMIB(mib_index, MIB_HW_TX_POWER_HT40_1S_B, MIB_HW_WLAN1_TX_POWER_HT40_1S_B, value);
#if 0
	#ifdef WLAN_DUALBAND_CONCURRENT
	if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
		mib_get(MIB_HW_WLAN1_TX_POWER_HT40_1S_B, (void *)value);
	else // wlan0
	#endif
		mib_get(MIB_HW_TX_POWER_HT40_1S_B, (void *)value);
#endif

	if(value[0] != 0) 
		status|=iwpriv_cmd(IWPRIV_HS|IWPRIV_HW2G|IWPRIV_TXPOWER, getWlanIfName(), "set_mib", "pwrlevelHT40_1S_B", value, mode);

#ifdef CONFIG_WLAN_HAL_8814AE
	get_WlanHWMIB(mib_index, MIB_HW_TX_POWER_HT40_1S_C, MIB_HW_WLAN1_TX_POWER_HT40_1S_C, value);
#if 0
#ifdef WLAN_DUALBAND_CONCURRENT
	if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
		mib_get(MIB_HW_WLAN1_TX_POWER_HT40_1S_C, (void *)value);
	else // wlan0
#endif
		mib_get(MIB_HW_TX_POWER_HT40_1S_C, (void *)value);
#endif

	if(value[0] != 0) 
		status|=iwpriv_cmd(IWPRIV_HS|IWPRIV_HW2G|IWPRIV_TXPOWER, getWlanIfName(), "set_mib", "pwrlevelHT40_1S_C", value, mode);

	get_WlanHWMIB(mib_index, MIB_HW_TX_POWER_HT40_1S_D, MIB_HW_WLAN1_TX_POWER_HT40_1S_D, value);
#if 0	
#ifdef WLAN_DUALBAND_CONCURRENT
	if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
		mib_get(MIB_HW_WLAN1_TX_POWER_HT40_1S_D, (void *)value);
	else // wlan0
#endif
		mib_get(MIB_HW_TX_POWER_HT40_1S_D, (void *)value);
#endif

	if(value[0] != 0) 
		status|=iwpriv_cmd(IWPRIV_HS|IWPRIV_HW2G|IWPRIV_TXPOWER, getWlanIfName(), "set_mib", "pwrlevelHT40_1S_D", value, mode);
#endif //CONFIG_WLAN_HAL_8814AE

#if defined(CONFIG_WLAN_HAL_8192EE) || defined(WLAN_DUALBAND_CONCURRENT)
#if defined(WLAN0_5G_WLAN1_2G)
	if(wlan_idx==1)
#elif defined(WLAN_DUALBAND_CONCURRENT)
	if(wlan_idx==0)
#endif
{
	get_WlanHWMIB(mib_index, MIB_HW_TX_POWER_HT40_2S, MIB_HW_WLAN1_TX_POWER_HT40_2S, value);
#if 0
	#ifdef WLAN_DUALBAND_CONCURRENT
	if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
		mib_get(MIB_HW_WLAN1_TX_POWER_HT40_2S, (void *)value);
	else
	#endif
		mib_get(MIB_HW_TX_POWER_HT40_2S, (void *)value);
#endif

	// may be 0 for power difference
	//if(value[0] != 0) {
		status|=iwpriv_cmd(IWPRIV_HS|IWPRIV_HW2G, getWlanIfName(), "set_mib", "pwrdiffHT40_2S", value);
	//}

	get_WlanHWMIB(mib_index, MIB_HW_TX_POWER_HT20, MIB_HW_WLAN1_TX_POWER_HT20, value);
#if 0
	#ifdef WLAN_DUALBAND_CONCURRENT
	if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
		mib_get(MIB_HW_WLAN1_TX_POWER_HT20, (void *)value);
	else
	#endif
		mib_get(MIB_HW_TX_POWER_HT20, (void *)value);
#endif

	// may be 0 for power difference
	//if(value[0] != 0) {
		status|=iwpriv_cmd(IWPRIV_HS|IWPRIV_HW2G, getWlanIfName(), "set_mib", "pwrdiffHT20", value);
	//}

	get_WlanHWMIB(mib_index, MIB_HW_TX_POWER_DIFF_OFDM, MIB_HW_WLAN1_TX_POWER_DIFF_OFDM, value);
#if 0
	#ifdef WLAN_DUALBAND_CONCURRENT
	if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
		mib_get(MIB_HW_WLAN1_TX_POWER_DIFF_OFDM, (void *)value);
	else
	#endif
		mib_get(MIB_HW_TX_POWER_DIFF_OFDM, (void *)value);
#endif
		
	// may be 0 for power difference
	//if(value[0] != 0) {
		status|=iwpriv_cmd(IWPRIV_HS|IWPRIV_HW2G, getWlanIfName(), "set_mib", "pwrdiffOFDM", value);
	//}

}
#endif
#if defined(CONFIG_WLAN_HAL_8814AE) || (defined(CONFIG_RTL_8812_SUPPORT) && !defined(WLAN_DUALBAND_CONCURRENT))
	#if defined(WLAN0_5G_WLAN1_2G) || (defined(WLAN0_2G_WLAN1_5G) && defined(SWAP_HW_WLAN_MIB_INDEX))
	#if defined(WLAN0_5G_WLAN1_2G)
	if(wlan_idx==1){
	#elif (defined(WLAN0_2G_WLAN1_5G) && defined(SWAP_HW_WLAN_MIB_INDEX))
	if(wlan_idx==0){
	#endif
		mib_get(MIB_HW_WLAN1_TX_POWER_DIFF_20BW1S_OFDM1T_A, (void *)value);
		if(value[0] != 0)
			iwpriv_cmd(IWPRIV_HS|IWPRIV_HW2G, ifname, "set_mib", "pwrdiff_20BW1S_OFDM1T_A", value);

		mib_get(MIB_HW_WLAN1_TX_POWER_DIFF_40BW2S_20BW2S_A, (void *)value);
		if(value[0] != 0)
			iwpriv_cmd(IWPRIV_HS|IWPRIV_HW2G, ifname, "set_mib", "pwrdiff_40BW2S_20BW2S_A", value);

#if defined(CONFIG_WLAN_HAL_8814AE)
		mib_get(MIB_HW_WLAN1_TX_POWER_DIFF_40BW3S_20BW3S_A, (void *)value);
		if(value[0] != 0)
			iwpriv_cmd(IWPRIV_HS|IWPRIV_HW2G, ifname, "set_mib", "pwrdiff_40BW3S_20BW3S_A", value);
#endif

		mib_get(MIB_HW_WLAN1_TX_POWER_DIFF_20BW1S_OFDM1T_B, (void *)value);
		if(value[0] != 0)
			iwpriv_cmd(IWPRIV_HS|IWPRIV_HW2G, ifname, "set_mib", "pwrdiff_20BW1S_OFDM1T_B", value);

		mib_get(MIB_HW_WLAN1_TX_POWER_DIFF_40BW2S_20BW2S_B, (void *)value);
		if(value[0] != 0)
			iwpriv_cmd(IWPRIV_HS|IWPRIV_HW2G, ifname, "set_mib", "pwrdiff_40BW2S_20BW2S_B", value);

#if defined(CONFIG_WLAN_HAL_8814AE)
		mib_get(MIB_HW_WLAN1_TX_POWER_DIFF_40BW3S_20BW3S_B, (void *)value);
		if(value[0] != 0)
			iwpriv_cmd(IWPRIV_HS|IWPRIV_HW2G, ifname, "set_mib", "pwrdiff_40BW3S_20BW3S_B", value);
#endif

#if defined(CONFIG_WLAN_HAL_8814AE)
		mib_get(MIB_HW_WLAN1_TX_POWER_DIFF_20BW1S_OFDM1T_C, (void *)value);
		if(value[0] != 0)
			iwpriv_cmd(IWPRIV_HS|IWPRIV_HW2G, ifname, "set_mib", "pwrdiff_20BW1S_OFDM1T_C", value);

		mib_get(MIB_HW_WLAN1_TX_POWER_DIFF_40BW2S_20BW2S_C, (void *)value);
		if(value[0] != 0)
			iwpriv_cmd(IWPRIV_HS|IWPRIV_HW2G, ifname, "set_mib", "pwrdiff_40BW2S_20BW2S_C", value);

		mib_get(MIB_HW_WLAN1_TX_POWER_DIFF_40BW3S_20BW3S_C, (void *)value);
		if(value[0] != 0)
			iwpriv_cmd(IWPRIV_HS|IWPRIV_HW2G, ifname, "set_mib", "pwrdiff_40BW3S_20BW3S_C", value);

		mib_get(MIB_HW_WLAN1_TX_POWER_DIFF_20BW1S_OFDM1T_D, (void *)value);
		if(value[0] != 0)
			iwpriv_cmd(IWPRIV_HS|IWPRIV_HW2G, ifname, "set_mib", "pwrdiff_20BW1S_OFDM1T_D", value);

		mib_get(MIB_HW_WLAN1_TX_POWER_DIFF_40BW2S_20BW2S_D, (void *)value);
		if(value[0] != 0)
			iwpriv_cmd(IWPRIV_HS|IWPRIV_HW2G, ifname, "set_mib", "pwrdiff_40BW2S_20BW2S_D", value);

		mib_get(MIB_HW_WLAN1_TX_POWER_DIFF_40BW3S_20BW3S_D, (void *)value);
		if(value[0] != 0)
			iwpriv_cmd(IWPRIV_HS|IWPRIV_HW2G, ifname, "set_mib", "pwrdiff_40BW3S_20BW3S_D", value);
#endif
	}
	#elif defined(WLAN0_2G_WLAN1_5G) || !defined(WLAN_DUALBAND_CONCURRENT)
	#if defined(WLAN0_2G_WLAN1_5G)
	if(wlan_idx==0)
	#endif
	{
		mib_get(MIB_HW_TX_POWER_DIFF_20BW1S_OFDM1T_A, (void *)value);
		if(value[0] != 0)
			iwpriv_cmd(IWPRIV_HS|IWPRIV_HW2G, ifname, "set_mib", "pwrdiff_20BW1S_OFDM1T_A", value);

		mib_get(MIB_HW_TX_POWER_DIFF_40BW2S_20BW2S_A, (void *)value);
		if(value[0] != 0)
			iwpriv_cmd(IWPRIV_HS|IWPRIV_HW2G, ifname, "set_mib", "pwrdiff_40BW2S_20BW2S_A", value);

#if defined(CONFIG_WLAN_HAL_8814AE)
		mib_get(MIB_HW_TX_POWER_DIFF_40BW3S_20BW3S_A, (void *)value);
		if(value[0] != 0)
			iwpriv_cmd(IWPRIV_HS|IWPRIV_HW2G, ifname, "set_mib", "pwrdiff_40BW3S_20BW3S_A", value);
#endif
		
		mib_get(MIB_HW_TX_POWER_DIFF_20BW1S_OFDM1T_B, (void *)value);
		if(value[0] != 0)
			iwpriv_cmd(IWPRIV_HS|IWPRIV_HW2G, ifname, "set_mib", "pwrdiff_20BW1S_OFDM1T_B", value);

		mib_get(MIB_HW_TX_POWER_DIFF_40BW2S_20BW2S_B, (void *)value);
		if(value[0] != 0)
			iwpriv_cmd(IWPRIV_HS|IWPRIV_HW2G, ifname, "set_mib", "pwrdiff_40BW2S_20BW2S_B", value);

#if defined(CONFIG_WLAN_HAL_8814AE)
		mib_get(MIB_HW_TX_POWER_DIFF_40BW3S_20BW3S_B, (void *)value);
		if(value[0] != 0)
			iwpriv_cmd(IWPRIV_HS|IWPRIV_HW2G, ifname, "set_mib", "pwrdiff_40BW3S_20BW3S_B", value);
#endif

#ifdef defined(CONFIG_WLAN_HAL_8814AE)
		mib_get(MIB_HW_TX_POWER_DIFF_20BW1S_OFDM1T_C, (void *)value);
		if(value[0] != 0)
			iwpriv_cmd(IWPRIV_HS|IWPRIV_HW2G, ifname, "set_mib", "pwrdiff_20BW1S_OFDM1T_C", value);

		mib_get(MIB_HW_TX_POWER_DIFF_40BW2S_20BW2S_C, (void *)value);
		if(value[0] != 0)
			iwpriv_cmd(IWPRIV_HS|IWPRIV_HW2G, ifname, "set_mib", "pwrdiff_40BW2S_20BW2S_C", value);

		mib_get(MIB_HW_TX_POWER_DIFF_40BW3S_20BW3S_C, (void *)value);
		if(value[0] != 0)
			iwpriv_cmd(IWPRIV_HS|IWPRIV_HW2G, ifname, "set_mib", "pwrdiff_40BW3S_20BW3S_C", value);
		
		mib_get(MIB_HW_TX_POWER_DIFF_20BW1S_OFDM1T_D, (void *)value);
		if(value[0] != 0)
			iwpriv_cmd(IWPRIV_HS|IWPRIV_HW2G, ifname, "set_mib", "pwrdiff_20BW1S_OFDM1T_D", value);

		mib_get(MIB_HW_TX_POWER_DIFF_40BW2S_20BW2S_D, (void *)value);
		if(value[0] != 0)
			iwpriv_cmd(IWPRIV_HS|IWPRIV_HW2G, ifname, "set_mib", "pwrdiff_40BW2S_20BW2S_D", value);

		mib_get(MIB_HW_TX_POWER_DIFF_40BW3S_20BW3S_D, (void *)value);
		if(value[0] != 0)
			iwpriv_cmd(IWPRIV_HS|IWPRIV_HW2G, ifname, "set_mib", "pwrdiff_40BW3S_20BW3S_D", value);
#endif
		
	}
	#endif
#endif

	get_WlanHWMIB(mib_index, MIB_HW_11N_TSSI1, MIB_HW_WLAN1_11N_TSSI1, value);
#if 0
	#ifdef WLAN_DUALBAND_CONCURRENT
	if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
		mib_get(MIB_HW_WLAN1_11N_TSSI1 , (void *) value);
	else // wlan0
	#endif
		mib_get(MIB_HW_11N_TSSI1, (void *)value);
#endif

	if(value[0] != 0)
		status|=iwpriv_cmd(IWPRIV_INT, getWlanIfName(), "set_mib", "tssi1", value[0]);

	get_WlanHWMIB(mib_index, MIB_HW_11N_TSSI2, MIB_HW_WLAN1_11N_TSSI2, value);
#if 0
	#ifdef WLAN_DUALBAND_CONCURRENT
	if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
		mib_get(MIB_HW_WLAN1_11N_TSSI2, (void *)value);
	else
	#endif
		mib_get(MIB_HW_11N_TSSI2, (void *)value);
#endif

	if(value[0] != 0) 
		status|=iwpriv_cmd(IWPRIV_INT, getWlanIfName(), "set_mib", "tssi2", value[0]);

	get_WlanHWMIB(mib_index, MIB_HW_11N_THER, MIB_HW_WLAN1_11N_THER, value);

#if 0
	#ifdef WLAN_DUALBAND_CONCURRENT
	if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
		mib_get(MIB_HW_WLAN1_11N_THER, (void *)value);
	else
	#endif
		mib_get(MIB_HW_11N_THER, (void *)value);
#endif

	if(value[0] != 0) {
		snprintf(parm, sizeof(parm), "ther=%d", value[0]);
		status|=va_cmd(IWPRIV, 3, 1, (char *) getWlanIfName(), "set_mib", parm);
	}

	get_WlanHWMIB(mib_index, MIB_HW_RF_XCAP, MIB_HW_WLAN1_RF_XCAP, value);
#if 0	
#if defined (WLAN_DUALBAND_CONCURRENT)
	if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
		mib_get(MIB_HW_WLAN1_RF_XCAP, (void *)value);
	else
#endif
		mib_get(MIB_HW_RF_XCAP, (void *)value);
#endif

	status|=iwpriv_cmd(IWPRIV_INT, getWlanIfName(), "set_mib", "xcap", value[0]);

#if defined (WLAN_DUALBAND_CONCURRENT)
	if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
		mib_get(MIB_HW_WLAN1_COUNTRYCODE, (void *)value);
	else
#endif
		mib_get(MIB_HW_WLAN0_COUNTRYCODE, (void *)value);

	if(value[0] != 0) 
	{
		int i;
		char para2[64];		

		status|=iwpriv_cmd(IWPRIV_INT, getWlanIfName(), "set_mib", "countrycode", value[0]);
		for (i=0; i<=WLAN_MBSSID_NUM; i++) 
		{	
			snprintf(para2, sizeof(para2), "%s-vap%d", getWlanIfName(), i);
			status|=iwpriv_cmd(IWPRIV_INT, para2, "set_mib", "countrycode", value[0]);
		}
	}

#if defined (WLAN_DUALBAND_CONCURRENT)
        if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
                mib_get(MIB_HW_WLAN1_COUNTRYSTR, (void *)value);
        else
#endif
		mib_get(MIB_HW_WLAN0_COUNTRYSTR, (void *)value);
	if(value[0] != 0) 
	{
		int i;
		char parm[64], para2[64];		

		snprintf(parm, sizeof(parm), "countrystr=%s", value);
		status|=va_cmd(IWPRIV, 3, 1, (char *) getWlanIfName(), "set_mib", parm);
		for (i=0; i<=WLAN_MBSSID_NUM; i++) 
		{	
			snprintf(para2, sizeof(para2), "%s-vap%d", getWlanIfName(), i);
			status|=va_cmd(IWPRIV, 3, 1, para2, "set_mib", parm);
		}
	}
}
#endif
#ifdef WLAN_FAST_INIT
void setup8812Wlan(char *ifname, struct wifi_mib *pmib)
{
	unsigned char buf1[1024];
	struct Dot11RFEntry *rf_entry;
#if defined(WLAN0_5G_WLAN1_2G)
	if(!strcmp(ifname , WLANIF[0])) //wlan0:5G, wlan1:2G
#elif defined(WLAN0_2G_WLAN1_5G)
	if(!strcmp(ifname , WLANIF[1])) //wlan0:2G, wlan1:5G			
#endif
	{
#if ((defined(CONFIG_WLAN_HAL_8814AE) || defined(CONFIG_RTL_8812_SUPPORT)) && !defined(CONFIG_ENABLE_EFUSE)) || defined(WLAN_DUALBAND_CONCURRENT)

		rf_entry = &pmib->dot11RFEntry;

		mib_get(MIB_HW_TX_POWER_5G_HT40_1S_A, (void*) buf1);
		memcpy(rf_entry->pwrlevel5GHT40_1S_A, (unsigned char*) buf1, MAX_5G_CHANNEL_NUM);
		mib_get(MIB_HW_TX_POWER_5G_HT40_1S_B, (void*) buf1);
		memcpy(rf_entry->pwrlevel5GHT40_1S_B, (unsigned char*) buf1, MAX_5G_CHANNEL_NUM);
		// 5G
		mib_get(MIB_HW_TX_POWER_DIFF_5G_20BW1S_OFDM1T_A, (void *)buf1);
		assign_diff_AC(rf_entry->pwrdiff_5G_20BW1S_OFDM1T_A, (unsigned char*) buf1);	
		mib_get(MIB_HW_TX_POWER_DIFF_5G_40BW2S_20BW2S_A, (void *)buf1);
		assign_diff_AC(rf_entry->pwrdiff_5G_40BW2S_20BW2S_A, (unsigned char*)buf1);
		mib_get(MIB_HW_TX_POWER_DIFF_5G_80BW1S_160BW1S_A, (void *)buf1);
		assign_diff_AC(rf_entry->pwrdiff_5G_80BW1S_160BW1S_A, (unsigned char*)buf1);
		mib_get(MIB_HW_TX_POWER_DIFF_5G_80BW2S_160BW2S_A, (void *)buf1);
		assign_diff_AC(rf_entry->pwrdiff_5G_80BW2S_160BW2S_A, (unsigned char*)buf1);
	
		mib_get(MIB_HW_TX_POWER_DIFF_5G_20BW1S_OFDM1T_B, (void *)buf1);
		assign_diff_AC(rf_entry->pwrdiff_5G_20BW1S_OFDM1T_B, (unsigned char*)buf1);	
		mib_get(MIB_HW_TX_POWER_DIFF_5G_40BW2S_20BW2S_B, (void *)buf1);
		assign_diff_AC(rf_entry->pwrdiff_5G_40BW2S_20BW2S_B, (unsigned char*)buf1);
		mib_get(MIB_HW_TX_POWER_DIFF_5G_80BW1S_160BW1S_B, (void *)buf1);
		assign_diff_AC(rf_entry->pwrdiff_5G_80BW1S_160BW1S_B, (unsigned char*)buf1);
		mib_get(MIB_HW_TX_POWER_DIFF_5G_80BW2S_160BW2S_B, (void *)buf1);
		assign_diff_AC(rf_entry->pwrdiff_5G_80BW2S_160BW2S_B, (unsigned char*)buf1);
	
		// 2G
		mib_get(MIB_HW_TX_POWER_DIFF_20BW1S_OFDM1T_A, (void *)buf1);
		memcpy(rf_entry->pwrdiff_20BW1S_OFDM1T_A, buf1, MAX_CHAN_NUM); 
		mib_get(MIB_HW_TX_POWER_DIFF_40BW2S_20BW2S_A, (void *)buf1);
		memcpy(rf_entry->pwrdiff_40BW2S_20BW2S_A, buf1, MAX_CHAN_NUM);
	
		mib_get(MIB_HW_TX_POWER_DIFF_20BW1S_OFDM1T_B, (void *)buf1);
		memcpy(rf_entry->pwrdiff_20BW1S_OFDM1T_B, buf1, MAX_CHAN_NUM);
		mib_get(MIB_HW_TX_POWER_DIFF_40BW2S_20BW2S_B, (void *)buf1);
		memcpy(rf_entry->pwrdiff_40BW2S_20BW2S_B, buf1, MAX_CHAN_NUM);
#endif
				
	}
}
#else
int setup8812Wlan(	char *ifname)
{
	int i = 0 ;
	int status = 0 ;
	unsigned char value[196];
	char parm[1024];
	int intVal;
	char mode=0;
	int mib_index = 0;
#if defined(WLAN0_5G_WLAN1_2G)
	if(!strcmp(ifname , WLANIF[1])) //wlan0:5G, wlan1:2G
		return status;
#elif defined(WLAN0_2G_WLAN1_5G)
	if(!strcmp(ifname , WLANIF[0])) //wlan0:2G, wlan1:5G
		return status;
#endif
#ifdef WLAN_DUALBAND_CONCURRENT
	if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
		mib_index = 1;
#endif
#if ((defined(CONFIG_WLAN_HAL_8814AE) || defined(CONFIG_RTL_8812_SUPPORT) || defined(CONFIG_WLAN_HAL_8822BE)) && !defined(CONFIG_ENABLE_EFUSE)) || defined(WLAN_DUALBAND_CONCURRENT)
		unsigned char pMib[178];

		if ( mib_get( MIB_TX_POWER, (void *)&mode) == 0) {
   			printf("Get MIB_TX_POWER error!\n");
   			status=-1;
		}
		get_WlanHWMIB(mib_index, MIB_HW_TX_POWER_5G_HT40_1S_A, MIB_HW_WLAN1_TX_POWER_5G_HT40_1S_A, value);
#if 0		
		if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
			mib_get(MIB_HW_WLAN1_TX_POWER_5G_HT40_1S_A, (void *)value);
		else
			mib_get(MIB_HW_TX_POWER_5G_HT40_1S_A, (void *)value);
#endif
		//if(value[0] != 0)
		{
			iwpriv_cmd(IWPRIV_HS | IWPRIV_TXPOWER, ifname, "set_mib", "pwrlevel5GHT40_1S_A", value, mode);
		}

		get_WlanHWMIB(mib_index, MIB_HW_TX_POWER_5G_HT40_1S_B, MIB_HW_WLAN1_TX_POWER_5G_HT40_1S_B, value);
#if 0		
		if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
			mib_get(MIB_HW_WLAN1_TX_POWER_5G_HT40_1S_B, (void *)value);
		else
			mib_get(MIB_HW_TX_POWER_5G_HT40_1S_B, (void *)value);
#endif
		//if(value[0] != 0)
		{
			iwpriv_cmd(IWPRIV_HS | IWPRIV_TXPOWER, ifname, "set_mib", "pwrlevel5GHT40_1S_B", value , mode);
		}

		get_WlanHWMIB(mib_index, MIB_HW_TX_POWER_DIFF_5G_20BW1S_OFDM1T_A, MIB_HW_WLAN1_TX_POWER_DIFF_5G_20BW1S_OFDM1T_A, value);
#if 0
		if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
			mib_get(MIB_HW_WLAN1_TX_POWER_DIFF_5G_20BW1S_OFDM1T_A, (void *)value);
		else
			mib_get(MIB_HW_TX_POWER_DIFF_5G_20BW1S_OFDM1T_A, (void *)value);
#endif
		if(value[0] != 0)
			iwpriv_cmd(IWPRIV_HS, ifname, "set_mib", "pwrdiff_5G_20BW1S_OFDM1T_A", value);

		get_WlanHWMIB(mib_index, MIB_HW_TX_POWER_DIFF_5G_40BW2S_20BW2S_A, MIB_HW_WLAN1_TX_POWER_DIFF_5G_40BW2S_20BW2S_A, value);

#if 0
		if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
			mib_get(MIB_HW_WLAN1_TX_POWER_DIFF_5G_40BW2S_20BW2S_A, (void *)value);
		else
			mib_get(MIB_HW_TX_POWER_DIFF_5G_40BW2S_20BW2S_A, (void *)value);
#endif
		if(value[0] != 0)
			iwpriv_cmd(IWPRIV_HS, ifname, "set_mib", "pwrdiff_5G_40BW2S_20BW2S_A", value);


		get_WlanHWMIB(mib_index, MIB_HW_TX_POWER_DIFF_5G_80BW1S_160BW1S_A, MIB_HW_WLAN1_TX_POWER_DIFF_5G_80BW1S_160BW1S_A, value);
#if 0
		if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
			mib_get(MIB_HW_WLAN1_TX_POWER_DIFF_5G_80BW1S_160BW1S_A, (void *)value);
		else
			mib_get(MIB_HW_TX_POWER_DIFF_5G_80BW1S_160BW1S_A, (void *)value);
#endif
		if(value[0] != 0)
			iwpriv_cmd(IWPRIV_HS, ifname, "set_mib", "pwrdiff_5G_80BW1S_160BW1S_A", value);

		get_WlanHWMIB(mib_index, MIB_HW_TX_POWER_DIFF_5G_80BW2S_160BW2S_A, MIB_HW_WLAN1_TX_POWER_DIFF_5G_80BW2S_160BW2S_A, value);
#if 0
		if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
			mib_get(MIB_HW_WLAN1_TX_POWER_DIFF_5G_80BW2S_160BW2S_A, (void *)value);
		else
			mib_get(MIB_HW_TX_POWER_DIFF_5G_80BW2S_160BW2S_A, (void *)value);
#endif
		if(value[0] != 0)
			iwpriv_cmd(IWPRIV_HS, ifname, "set_mib", "pwrdiff_5G_80BW2S_160BW2S_A", value);

#if defined(CONFIG_WLAN_HAL_8814AE)
		get_WlanHWMIB(mib_index, MIB_HW_TX_POWER_DIFF_5G_40BW3S_20BW3S_A, MIB_HW_WLAN1_TX_POWER_DIFF_5G_40BW3S_20BW3S_A, value);
#if 0
		if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
			mib_get(MIB_HW_WLAN1_TX_POWER_DIFF_5G_40BW3S_20BW3S_A, (void *)value);
		else
			mib_get(MIB_HW_TX_POWER_DIFF_5G_40BW3S_20BW3S_A, (void *)value);
#endif
		if(value[0] != 0)
			iwpriv_cmd(IWPRIV_HS, ifname, "set_mib", "pwrdiff_5G_40BW3S_20BW3S_A", value);

		get_WlanHWMIB(mib_index, MIB_HW_TX_POWER_DIFF_5G_40BW4S_20BW4S_A, MIB_HW_WLAN1_TX_POWER_DIFF_5G_40BW4S_20BW4S_A, value);
#if 0
		if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
			mib_get(MIB_HW_WLAN1_TX_POWER_DIFF_5G_40BW4S_20BW4S_A, (void *)value);
		else
			mib_get(MIB_HW_TX_POWER_DIFF_5G_40BW4S_20BW4S_A, (void *)value);
#endif
		if(value[0] != 0)
			iwpriv_cmd(IWPRIV_HS, ifname, "set_mib", "pwrdiff_5G_40BW4S_20BW4S_A", value);

		get_WlanHWMIB(mib_index, MIB_HW_TX_POWER_DIFF_5G_80BW3S_160BW3S_A, MIB_HW_WLAN1_TX_POWER_DIFF_5G_80BW3S_160BW3S_A, value);
#if 0
		if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
			mib_get(MIB_HW_WLAN1_TX_POWER_DIFF_5G_80BW3S_160BW3S_A, (void *)value);
		else
			mib_get(MIB_HW_TX_POWER_DIFF_5G_80BW3S_160BW3S_A, (void *)value);
#endif
		if(value[0] != 0)
			iwpriv_cmd(IWPRIV_HS, ifname, "set_mib", "pwrdiff_5G_80BW3S_160BW3S_A", value);

		get_WlanHWMIB(mib_index, MIB_HW_TX_POWER_DIFF_5G_80BW4S_160BW4S_A, MIB_HW_WLAN1_TX_POWER_DIFF_5G_80BW4S_160BW4S_A, value);
#if 0
		if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
			mib_get(MIB_HW_WLAN1_TX_POWER_DIFF_5G_80BW4S_160BW4S_A, (void *)value);
		else
			mib_get(MIB_HW_TX_POWER_DIFF_5G_80BW4S_160BW4S_A, (void *)value);
#endif
		if(value[0] != 0)
			iwpriv_cmd(IWPRIV_HS, ifname, "set_mib", "pwrdiff_5G_80BW4S_160BW4S_A", value);
#endif

		get_WlanHWMIB(mib_index, MIB_HW_TX_POWER_DIFF_5G_20BW1S_OFDM1T_B, MIB_HW_WLAN1_TX_POWER_DIFF_5G_20BW1S_OFDM1T_B, value);
#if 0
		if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
			mib_get(MIB_HW_WLAN1_TX_POWER_DIFF_5G_20BW1S_OFDM1T_B, (void *)value);
		else
			mib_get(MIB_HW_TX_POWER_DIFF_5G_20BW1S_OFDM1T_B, (void *)value);
#endif
		if(value[0] != 0)
			iwpriv_cmd(IWPRIV_HS, ifname, "set_mib", "pwrdiff_5G_20BW1S_OFDM1T_B", value);

		get_WlanHWMIB(mib_index, MIB_HW_TX_POWER_DIFF_5G_40BW2S_20BW2S_B, MIB_HW_WLAN1_TX_POWER_DIFF_5G_40BW2S_20BW2S_B, value);
#if 0
		if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
			mib_get(MIB_HW_WLAN1_TX_POWER_DIFF_5G_40BW2S_20BW2S_B, (void *)value);
		else
			mib_get(MIB_HW_TX_POWER_DIFF_5G_40BW2S_20BW2S_B, (void *)value);
#endif
		if(value[0] != 0)
			iwpriv_cmd(IWPRIV_HS, ifname, "set_mib", "pwrdiff_5G_40BW2S_20BW2S_B", value);

		get_WlanHWMIB(mib_index, MIB_HW_TX_POWER_DIFF_5G_80BW1S_160BW1S_B, MIB_HW_WLAN1_TX_POWER_DIFF_5G_80BW1S_160BW1S_B, value);
#if 0
		if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
			mib_get(MIB_HW_WLAN1_TX_POWER_DIFF_5G_80BW1S_160BW1S_B, (void *)value);
		else
			mib_get(MIB_HW_TX_POWER_DIFF_5G_80BW1S_160BW1S_B, (void *)value);
#endif
		if(value[0] != 0)
			iwpriv_cmd(IWPRIV_HS, ifname, "set_mib", "pwrdiff_5G_80BW1S_160BW1S_B", value);

		get_WlanHWMIB(mib_index, MIB_HW_TX_POWER_DIFF_5G_80BW2S_160BW2S_B, MIB_HW_WLAN1_TX_POWER_DIFF_5G_80BW2S_160BW2S_B, value);
#if 0
		if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
			mib_get(MIB_HW_WLAN1_TX_POWER_DIFF_5G_80BW2S_160BW2S_B, (void *)value);
		else
			mib_get(MIB_HW_TX_POWER_DIFF_5G_80BW2S_160BW2S_B, (void *)value);
#endif
		if(value[0] != 0)
			iwpriv_cmd(IWPRIV_HS, ifname, "set_mib", "pwrdiff_5G_80BW2S_160BW2S_B", value);

#if defined(CONFIG_WLAN_HAL_8814AE)
		get_WlanHWMIB(mib_index, MIB_HW_TX_POWER_DIFF_5G_40BW3S_20BW3S_B, MIB_HW_WLAN1_TX_POWER_DIFF_5G_40BW3S_20BW3S_B, value);
#if 0
		if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
			mib_get(MIB_HW_WLAN1_TX_POWER_DIFF_5G_40BW3S_20BW3S_B, (void *)value);
		else
			mib_get(MIB_HW_TX_POWER_DIFF_5G_40BW3S_20BW3S_B, (void *)value);
#endif
		if(value[0] != 0)
			iwpriv_cmd(IWPRIV_HS, ifname, "set_mib", "pwrdiff_5G_40BW3S_20BW3S_B", value);

		get_WlanHWMIB(mib_index, MIB_HW_TX_POWER_DIFF_5G_40BW4S_20BW4S_B, MIB_HW_WLAN1_TX_POWER_DIFF_5G_40BW4S_20BW4S_B, value);
#if 0
		if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
			mib_get(MIB_HW_WLAN1_TX_POWER_DIFF_5G_40BW4S_20BW4S_B, (void *)value);
		else
			mib_get(MIB_HW_TX_POWER_DIFF_5G_40BW4S_20BW4S_B, (void *)value);
#endif
		if(value[0] != 0)
			iwpriv_cmd(IWPRIV_HS, ifname, "set_mib", "pwrdiff_5G_40BW4S_20BW4S_B", value);

		get_WlanHWMIB(mib_index, MIB_HW_TX_POWER_DIFF_5G_80BW3S_160BW3S_B, MIB_HW_WLAN1_TX_POWER_DIFF_5G_80BW3S_160BW3S_B, value);
#if 0
		if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
			mib_get(MIB_HW_WLAN1_TX_POWER_DIFF_5G_80BW3S_160BW3S_B, (void *)value);
		else
			mib_get(MIB_HW_TX_POWER_DIFF_5G_80BW3S_160BW3S_B, (void *)value);
#endif
		if(value[0] != 0)
			iwpriv_cmd(IWPRIV_HS, ifname, "set_mib", "pwrdiff_5G_80BW3S_160BW3S_B", value);

		get_WlanHWMIB(mib_index, MIB_HW_TX_POWER_DIFF_5G_80BW4S_160BW4S_B, MIB_HW_WLAN1_TX_POWER_DIFF_5G_80BW4S_160BW4S_B, value);
#if 0
		if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
			mib_get(MIB_HW_WLAN1_TX_POWER_DIFF_5G_80BW4S_160BW4S_B, (void *)value);
		else
			mib_get(MIB_HW_TX_POWER_DIFF_5G_80BW4S_160BW4S_B, (void *)value);
#endif
		if(value[0] != 0)
			iwpriv_cmd(IWPRIV_HS, ifname, "set_mib", "pwrdiff_5G_80BW4S_160BW4S_B", value);
#endif

#if 0
		// 2G
		mib_get(MIB_HW_TX_POWER_DIFF_20BW1S_OFDM1T_A, (void *)value);
		if(value[0] != 0)
			iwpriv_cmd(IWPRIV_HS|IWPRIV_HW2G, ifname, "set_mib", "pwrdiff_20BW1S_OFDM1T_A", value);

		mib_get(MIB_HW_TX_POWER_DIFF_40BW2S_20BW2S_A, (void *)value);
		if(value[0] != 0)
			iwpriv_cmd(IWPRIV_HS|IWPRIV_HW2G, ifname, "set_mib", "pwrdiff_40BW2S_20BW2S_A", value);

		mib_get(MIB_HW_TX_POWER_DIFF_20BW1S_OFDM1T_B, (void *)value);
		if(value[0] != 0)
			iwpriv_cmd(IWPRIV_HS|IWPRIV_HW2G, ifname, "set_mib", "pwrdiff_20BW1S_OFDM1T_B", value);

		mib_get(MIB_HW_TX_POWER_DIFF_40BW2S_20BW2S_B, (void *)value);
		if(value[0] != 0)
			iwpriv_cmd(IWPRIV_HS|IWPRIV_HW2G, ifname, "set_mib", "pwrdiff_40BW2S_20BW2S_B", value);
#endif
		
#endif
#if defined(CONFIG_WLAN_HAL_8814AE)
		get_WlanHWMIB(mib_index, MIB_HW_TX_POWER_5G_HT40_1S_C, MIB_HW_WLAN1_TX_POWER_5G_HT40_1S_C, value);
#if 0
		if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
			mib_get(MIB_HW_WLAN1_TX_POWER_5G_HT40_1S_C, (void *)value);
		else
			mib_get(MIB_HW_TX_POWER_5G_HT40_1S_C, (void *)value);
#endif
		//if(value[0] != 0)
		{
			iwpriv_cmd(IWPRIV_HS | IWPRIV_TXPOWER, ifname, "set_mib", "pwrlevel5GHT40_1S_C", value, mode);
		}

		get_WlanHWMIB(mib_index, MIB_HW_TX_POWER_5G_HT40_1S_D, MIB_HW_WLAN1_TX_POWER_5G_HT40_1S_D, value);
#if 0
		if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
			mib_get(MIB_HW_WLAN1_TX_POWER_5G_HT40_1S_D, (void *)value);
		else
			mib_get(MIB_HW_TX_POWER_5G_HT40_1S_D, (void *)value);
#endif
		//if(value[0] != 0)
		{
			iwpriv_cmd(IWPRIV_HS | IWPRIV_TXPOWER, ifname, "set_mib", "pwrlevel5GHT40_1S_D", value , mode);
		}

		get_WlanHWMIB(mib_index, MIB_HW_TX_POWER_DIFF_5G_20BW1S_OFDM1T_C, MIB_HW_WLAN1_TX_POWER_DIFF_5G_20BW1S_OFDM1T_C, value);
#if 0
		if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
			mib_get(MIB_HW_WLAN1_TX_POWER_DIFF_5G_20BW1S_OFDM1T_C, (void *)value);
		else
			mib_get(MIB_HW_TX_POWER_DIFF_5G_20BW1S_OFDM1T_C, (void *)value);
#endif
		if(value[0] != 0)
			iwpriv_cmd(IWPRIV_HS, ifname, "set_mib", "pwrdiff_5G_20BW1S_OFDM1T_C", value);

		get_WlanHWMIB(mib_index, MIB_HW_TX_POWER_DIFF_5G_40BW2S_20BW2S_C, MIB_HW_WLAN1_TX_POWER_DIFF_5G_40BW2S_20BW2S_C, value);
#if 0
		if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
			mib_get(MIB_HW_WLAN1_TX_POWER_DIFF_5G_40BW2S_20BW2S_C, (void *)value);
		else
			mib_get(MIB_HW_TX_POWER_DIFF_5G_40BW2S_20BW2S_C, (void *)value);
#endif
		if(value[0] != 0)
			iwpriv_cmd(IWPRIV_HS, ifname, "set_mib", "pwrdiff_5G_40BW2S_20BW2S_C", value);

		get_WlanHWMIB(mib_index, MIB_HW_TX_POWER_DIFF_5G_80BW1S_160BW1S_C, MIB_HW_WLAN1_TX_POWER_DIFF_5G_80BW1S_160BW1S_C, value);
#if 0
		if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
			mib_get(MIB_HW_WLAN1_TX_POWER_DIFF_5G_80BW1S_160BW1S_C, (void *)value);
		else
			mib_get(MIB_HW_TX_POWER_DIFF_5G_80BW1S_160BW1S_C, (void *)value);
#endif
		if(value[0] != 0)
			iwpriv_cmd(IWPRIV_HS, ifname, "set_mib", "pwrdiff_5G_80BW1S_160BW1S_C", value);

		get_WlanHWMIB(mib_index, MIB_HW_TX_POWER_DIFF_5G_80BW2S_160BW2S_C, MIB_HW_WLAN1_TX_POWER_DIFF_5G_80BW2S_160BW2S_C, value);
#if 0
		if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
			mib_get(MIB_HW_WLAN1_TX_POWER_DIFF_5G_80BW2S_160BW2S_C, (void *)value);
		else
			mib_get(MIB_HW_TX_POWER_DIFF_5G_80BW2S_160BW2S_C, (void *)value);
#endif
		if(value[0] != 0)
			iwpriv_cmd(IWPRIV_HS, ifname, "set_mib", "pwrdiff_5G_80BW2S_160BW2S_C", value);

		get_WlanHWMIB(mib_index, MIB_HW_TX_POWER_DIFF_5G_40BW3S_20BW3S_C, MIB_HW_WLAN1_TX_POWER_DIFF_5G_40BW3S_20BW3S_C, value);
#if 0
		if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
			mib_get(MIB_HW_WLAN1_TX_POWER_DIFF_5G_40BW3S_20BW3S_C, (void *)value);
		else
			mib_get(MIB_HW_TX_POWER_DIFF_5G_40BW3S_20BW3S_C, (void *)value);
#endif
		if(value[0] != 0)
			iwpriv_cmd(IWPRIV_HS, ifname, "set_mib", "pwrdiff_5G_40BW3S_20BW3S_C", value);

		get_WlanHWMIB(mib_index, MIB_HW_TX_POWER_DIFF_5G_40BW4S_20BW4S_C, MIB_HW_WLAN1_TX_POWER_DIFF_5G_40BW4S_20BW4S_C, value);
#if 0	
		if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
			mib_get(MIB_HW_WLAN1_TX_POWER_DIFF_5G_40BW4S_20BW4S_C, (void *)value);
		else
			mib_get(MIB_HW_TX_POWER_DIFF_5G_40BW4S_20BW4S_C, (void *)value);
#endif
		if(value[0] != 0)
			iwpriv_cmd(IWPRIV_HS, ifname, "set_mib", "pwrdiff_5G_40BW4S_20BW4S_C", value);

		get_WlanHWMIB(mib_index, MIB_HW_TX_POWER_DIFF_5G_80BW3S_160BW3S_C, MIB_HW_WLAN1_TX_POWER_DIFF_5G_80BW3S_160BW3S_C, value);
#if 0	
		if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
			mib_get(MIB_HW_WLAN1_TX_POWER_DIFF_5G_80BW3S_160BW3S_C, (void *)value);
		else
			mib_get(MIB_HW_TX_POWER_DIFF_5G_80BW3S_160BW3S_C, (void *)value);
#endif
		if(value[0] != 0)
			iwpriv_cmd(IWPRIV_HS, ifname, "set_mib", "pwrdiff_5G_80BW3S_160BW3S_C", value);

		get_WlanHWMIB(mib_index, MIB_HW_TX_POWER_DIFF_5G_80BW4S_160BW4S_C, MIB_HW_WLAN1_TX_POWER_DIFF_5G_80BW4S_160BW4S_C, value);
#if 0
		if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
			mib_get(MIB_HW_WLAN1_TX_POWER_DIFF_5G_80BW4S_160BW4S_C, (void *)value);
		else
			mib_get(MIB_HW_TX_POWER_DIFF_5G_80BW4S_160BW4S_C, (void *)value);
#endif
		if(value[0] != 0)
			iwpriv_cmd(IWPRIV_HS, ifname, "set_mib", "pwrdiff_5G_80BW4S_160BW4S_C", value);

		get_WlanHWMIB(mib_index, MIB_HW_TX_POWER_DIFF_5G_20BW1S_OFDM1T_D, MIB_HW_WLAN1_TX_POWER_DIFF_5G_20BW1S_OFDM1T_D, value);
#if 0
		if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
			mib_get(MIB_HW_WLAN1_TX_POWER_DIFF_5G_20BW1S_OFDM1T_D, (void *)value);
		else
			mib_get(MIB_HW_TX_POWER_DIFF_5G_20BW1S_OFDM1T_D, (void *)value);
#endif
		if(value[0] != 0)
			iwpriv_cmd(IWPRIV_HS, ifname, "set_mib", "pwrdiff_5G_20BW1S_OFDM1T_D", value);

		get_WlanHWMIB(mib_index, MIB_HW_TX_POWER_DIFF_5G_40BW2S_20BW2S_D, MIB_HW_WLAN1_TX_POWER_DIFF_5G_40BW2S_20BW2S_D, value);
#if 0
		if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
			mib_get(MIB_HW_WLAN1_TX_POWER_DIFF_5G_40BW2S_20BW2S_D, (void *)value);
		else
			mib_get(MIB_HW_TX_POWER_DIFF_5G_40BW2S_20BW2S_D, (void *)value);
#endif
		if(value[0] != 0)
			iwpriv_cmd(IWPRIV_HS, ifname, "set_mib", "pwrdiff_5G_40BW2S_20BW2S_D", value);

		get_WlanHWMIB(mib_index, MIB_HW_TX_POWER_DIFF_5G_80BW1S_160BW1S_D, MIB_HW_WLAN1_TX_POWER_DIFF_5G_80BW1S_160BW1S_D, value);
#if 0
		if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
			mib_get(MIB_HW_WLAN1_TX_POWER_DIFF_5G_80BW1S_160BW1S_D, (void *)value);
		else
			mib_get(MIB_HW_TX_POWER_DIFF_5G_80BW1S_160BW1S_D, (void *)value);
#endif
		if(value[0] != 0)
			iwpriv_cmd(IWPRIV_HS, ifname, "set_mib", "pwrdiff_5G_80BW1S_160BW1S_D", value);

		get_WlanHWMIB(mib_index, MIB_HW_TX_POWER_DIFF_5G_80BW2S_160BW2S_D, MIB_HW_WLAN1_TX_POWER_DIFF_5G_80BW2S_160BW2S_D, value);
#if 0	
		if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
			mib_get(MIB_HW_WLAN1_TX_POWER_DIFF_5G_80BW2S_160BW2S_D, (void *)value);
		else
			mib_get(MIB_HW_TX_POWER_DIFF_5G_80BW2S_160BW2S_D, (void *)value);
#endif
		if(value[0] != 0)
			iwpriv_cmd(IWPRIV_HS, ifname, "set_mib", "pwrdiff_5G_80BW2S_160BW2S_D", value);

		get_WlanHWMIB(mib_index, MIB_HW_TX_POWER_DIFF_5G_40BW3S_20BW3S_D, MIB_HW_WLAN1_TX_POWER_DIFF_5G_40BW3S_20BW3S_D, value);
#if 0
		if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
			mib_get(MIB_HW_WLAN1_TX_POWER_DIFF_5G_40BW3S_20BW3S_D, (void *)value);
		else
			mib_get(MIB_HW_TX_POWER_DIFF_5G_40BW3S_20BW3S_D, (void *)value);
#endif
		if(value[0] != 0)
			iwpriv_cmd(IWPRIV_HS, ifname, "set_mib", "pwrdiff_5G_40BW3S_20BW3S_D", value);

		get_WlanHWMIB(mib_index, MIB_HW_TX_POWER_DIFF_5G_40BW4S_20BW4S_D, MIB_HW_WLAN1_TX_POWER_DIFF_5G_40BW4S_20BW4S_D, value);
#if 0
		if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
			mib_get(MIB_HW_WLAN1_TX_POWER_DIFF_5G_40BW4S_20BW4S_D, (void *)value);
		else
			mib_get(MIB_HW_TX_POWER_DIFF_5G_40BW4S_20BW4S_D, (void *)value);
#endif
		if(value[0] != 0)
			iwpriv_cmd(IWPRIV_HS, ifname, "set_mib", "pwrdiff_5G_40BW4S_20BW4S_D", value);

		get_WlanHWMIB(mib_index, MIB_HW_TX_POWER_DIFF_5G_80BW3S_160BW3S_D, MIB_HW_WLAN1_TX_POWER_DIFF_5G_80BW3S_160BW3S_D, value);
#if 0
		if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
			mib_get(MIB_HW_WLAN1_TX_POWER_DIFF_5G_80BW3S_160BW3S_D, (void *)value);
		else
			mib_get(MIB_HW_TX_POWER_DIFF_5G_80BW3S_160BW3S_D, (void *)value);
#endif
		if(value[0] != 0)
			iwpriv_cmd(IWPRIV_HS, ifname, "set_mib", "pwrdiff_5G_80BW3S_160BW3S_D", value);

		get_WlanHWMIB(mib_index, MIB_HW_TX_POWER_DIFF_5G_80BW4S_160BW4S_D, MIB_HW_WLAN1_TX_POWER_DIFF_5G_80BW4S_160BW4S_D, value);
#if 0		
		if(strcmp(ifname ,WLANIF[1]) == 0) // wlan1
			mib_get(MIB_HW_WLAN1_TX_POWER_DIFF_5G_80BW4S_160BW4S_D, (void *)value);
		else
			mib_get(MIB_HW_TX_POWER_DIFF_5G_80BW4S_160BW4S_D, (void *)value);
#endif
		if(value[0] != 0)
			iwpriv_cmd(IWPRIV_HS, ifname, "set_mib", "pwrdiff_5G_80BW4S_160BW4S_D", value);

#if 0
		// 2G
		mib_get(MIB_HW_TX_POWER_DIFF_20BW1S_OFDM1T_C, (void *)value);
		if(value[0] != 0)
			iwpriv_cmd(IWPRIV_HS|IWPRIV_HW2G, ifname, "set_mib", "pwrdiff_20BW1S_OFDM1T_C", value);

		mib_get(MIB_HW_TX_POWER_DIFF_40BW2S_20BW2S_C, (void *)value);
		if(value[0] != 0)
			iwpriv_cmd(IWPRIV_HS|IWPRIV_HW2G, ifname, "set_mib", "pwrdiff_40BW2S_20BW2S_C", value);

		mib_get(MIB_HW_TX_POWER_DIFF_20BW1S_OFDM1T_D, (void *)value);
		if(value[0] != 0)
			iwpriv_cmd(IWPRIV_HS|IWPRIV_HW2G, ifname, "set_mib", "pwrdiff_20BW1S_OFDM1T_D", value);

		mib_get(MIB_HW_TX_POWER_DIFF_40BW2S_20BW2S_D, (void *)value);
		if(value[0] != 0)
			iwpriv_cmd(IWPRIV_HS|IWPRIV_HW2G, ifname, "set_mib", "pwrdiff_40BW2S_20BW2S_D", value);
#endif
			
#endif

	return status;
}
#endif
int setupWlanDPK()
{
	int status = 0;
#ifdef CONFIG_RF_DPK_SETTING_SUPPORT
#define LUT_2G_LEN 64
#define PWSF_2G_LEN 3
//#define DWORD_SWAP(dword) ((dword & 0x000000ff) << 24 | (dword & 0x0000ff00) << 8 |(dword & 0x00ff0000) >> 8 | (dword & 0xff000000) >> 24)
#if 0
#define LUT_SWAP(_DST_,_LEN_) \
		do{ \
			{ \
				int k; \
				for (k=0; k<_LEN_; k++) { \
				    _DST_[k] = DWORD_SWAP(_DST_[k]); \
				} \
			} \
		}while(0)
#else
#define LUT_SWAP(_DST_,_LEN_) do{}while(0)
#endif

	unsigned char phyband=0;
	unsigned int lut_val[PWSF_2G_LEN][LUT_2G_LEN];
	int i=0;
	char ifname[IFNAMSIZ];
	char parm[64];
	unsigned char value[1024], bDPPathAOK=0, bDPPathBOK=0;
	int len;
	mib_get(MIB_WLAN_PHY_BAND_SELECT, (void *)&phyband);
	if(phyband == PHYBAND_2G){

		strcpy(ifname, getWlanIfName());

		if(mib_get(MIB_HW_RF_DPK_DP_PATH_A_OK, (void *)&bDPPathAOK)){
			snprintf(parm, sizeof(parm), "bDPPathAOK=%d", bDPPathAOK);
			va_cmd(IWPRIV, 3, 1, ifname, "set_mib", parm);
		}
		if(mib_get(MIB_HW_RF_DPK_DP_PATH_B_OK, (void *)&bDPPathBOK)){
			snprintf(parm, sizeof(parm), "bDPPathBOK=%d", bDPPathBOK);
			va_cmd(IWPRIV, 3, 1, ifname, "set_mib", parm);
		}
		if(bDPPathAOK==1 && bDPPathBOK==1)
		{
			len = PWSF_2G_LEN;
		
			if(mib_get(MIB_HW_RF_DPK_PWSF_2G_A, (void *)value)){
				iwpriv_cmd(IWPRIV_HS|IWPRIV_HWDPK, ifname, "set_mib", "pwsf_2g_a", len, value);
			}

			if(mib_get(MIB_HW_RF_DPK_PWSF_2G_B, (void *)value)){
				iwpriv_cmd(IWPRIV_HS|IWPRIV_HWDPK, ifname, "set_mib", "pwsf_2g_b", len, value);
			}

			len = LUT_2G_LEN * 4;

			memset(lut_val, '\0', sizeof(lut_val));
			if(	mib_get(MIB_HW_RF_DPK_LUT_2G_EVEN_A0, (void *)value)){
				memcpy(lut_val[0], value, LUT_2G_LEN*4);
				LUT_SWAP(lut_val[0], LUT_2G_LEN);
				iwpriv_cmd(IWPRIV_HS|IWPRIV_HWDPK, ifname, "set_mib", "lut_2g_even_a0", len, lut_val[0]);
			}
			if(	mib_get(MIB_HW_RF_DPK_LUT_2G_EVEN_A1, (void *)value)){
				memcpy(lut_val[1], value, LUT_2G_LEN*4);
				LUT_SWAP(lut_val[1], LUT_2G_LEN);
				iwpriv_cmd(IWPRIV_HS|IWPRIV_HWDPK, ifname, "set_mib", "lut_2g_even_a1", len, lut_val[1]);
			}
			if(	mib_get(MIB_HW_RF_DPK_LUT_2G_EVEN_A2, (void *)value)){
				memcpy(lut_val[2], value, LUT_2G_LEN*4);
				LUT_SWAP(lut_val[2], LUT_2G_LEN);
				iwpriv_cmd(IWPRIV_HS|IWPRIV_HWDPK, ifname, "set_mib", "lut_2g_even_a2", len, lut_val[2]);
			}
			//for(i=0; i<PWSF_2G_LEN; i++)
			//	memcpy(value+i, lut_val[i], LUT_2G_LEN * 4);
			//iwpriv_cmd(IWPRIV_HS|IWPRIV_HWDPK, ifname, "set_mib", "lut_2g_even_a", len, value);

			memset(lut_val, '\0', sizeof(lut_val));
			if(	mib_get(MIB_HW_RF_DPK_LUT_2G_ODD_A0, (void *)value)){
				memcpy(lut_val[0], value, LUT_2G_LEN*4);
				LUT_SWAP(lut_val[0], LUT_2G_LEN);
				iwpriv_cmd(IWPRIV_HS|IWPRIV_HWDPK, ifname, "set_mib", "lut_2g_odd_a0", len, lut_val[0]);
			}
			if(	mib_get(MIB_HW_RF_DPK_LUT_2G_ODD_A1, (void *)value)){
				memcpy(lut_val[1], value, LUT_2G_LEN*4);
				LUT_SWAP(lut_val[1], LUT_2G_LEN);
				iwpriv_cmd(IWPRIV_HS|IWPRIV_HWDPK, ifname, "set_mib", "lut_2g_odd_a1", len, lut_val[1]);
			}
			if(	mib_get(MIB_HW_RF_DPK_LUT_2G_ODD_A2, (void *)value)){
				memcpy(lut_val[2], value, LUT_2G_LEN*4);
				LUT_SWAP(lut_val[2], LUT_2G_LEN);
				iwpriv_cmd(IWPRIV_HS|IWPRIV_HWDPK, ifname, "set_mib", "lut_2g_odd_a2", len, lut_val[2]);
			}
			//for(i=0; i<PWSF_2G_LEN; i++)
			//	memcpy(value+i, lut_val[i], LUT_2G_LEN * 4);
			//iwpriv_cmd(IWPRIV_HS|IWPRIV_HWDPK, ifname, "set_mib", "lut_2g_odd_a", len, lut_val);

			memset(lut_val, '\0', sizeof(lut_val));
			if(	mib_get(MIB_HW_RF_DPK_LUT_2G_EVEN_B0, (void *)value)){
				memcpy(lut_val[0], value, LUT_2G_LEN*4);
				LUT_SWAP(lut_val[0], LUT_2G_LEN);
				iwpriv_cmd(IWPRIV_HS|IWPRIV_HWDPK, ifname, "set_mib", "lut_2g_even_b0", len, lut_val[0]);
			}
			if(	mib_get(MIB_HW_RF_DPK_LUT_2G_EVEN_B1, (void *)value)){
				memcpy(lut_val[1], value, LUT_2G_LEN*4);
				LUT_SWAP(lut_val[1], LUT_2G_LEN);
				iwpriv_cmd(IWPRIV_HS|IWPRIV_HWDPK, ifname, "set_mib", "lut_2g_even_b1", len, lut_val[1]);
			}
			if(	mib_get(MIB_HW_RF_DPK_LUT_2G_EVEN_B2, (void *)value)){
				memcpy(lut_val[2], value, LUT_2G_LEN*4);
				LUT_SWAP(lut_val[2], LUT_2G_LEN);
				iwpriv_cmd(IWPRIV_HS|IWPRIV_HWDPK, ifname, "set_mib", "lut_2g_even_b2", len, lut_val[2]);
			}
			//for(i=0; i<PWSF_2G_LEN; i++)
			//	memcpy(value+i, lut_val[i], LUT_2G_LEN * 4);
			//iwpriv_cmd(IWPRIV_HS|IWPRIV_HWDPK, ifname, "set_mib", "lut_2g_even_b", len, lut_val);

			memset(lut_val, '\0', sizeof(lut_val));
			if(	mib_get(MIB_HW_RF_DPK_LUT_2G_ODD_B0, (void *)value)){
				memcpy(lut_val[0], value, LUT_2G_LEN*4);
				LUT_SWAP(lut_val[0], LUT_2G_LEN);
				iwpriv_cmd(IWPRIV_HS|IWPRIV_HWDPK, ifname, "set_mib", "lut_2g_odd_b0", len, lut_val[0]);
			}
			if(	mib_get(MIB_HW_RF_DPK_LUT_2G_ODD_B1, (void *)value)){
				memcpy(lut_val[1], value, LUT_2G_LEN*4);
				LUT_SWAP(lut_val[1], LUT_2G_LEN);
				iwpriv_cmd(IWPRIV_HS|IWPRIV_HWDPK, ifname, "set_mib", "lut_2g_odd_b1", len, lut_val[1]);
			}
			if(	mib_get(MIB_HW_RF_DPK_LUT_2G_ODD_B2, (void *)value)){
				memcpy(lut_val[2], value, LUT_2G_LEN*4);
				LUT_SWAP(lut_val[2], LUT_2G_LEN);
				iwpriv_cmd(IWPRIV_HS|IWPRIV_HWDPK, ifname, "set_mib", "lut_2g_odd_b2", len, lut_val[2]);
			}
			//for(i=0; i<PWSF_2G_LEN; i++)
			//	memcpy(value+i, lut_val[i], LUT_2G_LEN * 4);
			//iwpriv_cmd(IWPRIV_HS|IWPRIV_HWDPK, ifname, "set_mib", "lut_2g_odd_b", len, lut_val);
		}		
	}
#endif
	return status;
}
#if defined WLAN_QoS && (!defined (CONFIG_RTL8192CD) && !defined(CONFIG_RTL8192CD_MODULE) )
int setupWLanQos(char *argv[6])
{
	int i, status;
	unsigned char value[34];
	char parm[64];
	MIB_WLAN_QOS_T QOSEntry;

	for (i=0; i<4; i++) {
		if (!mib_chain_get(MIB_WLAN_QOS_AP_TBL, i, (void *)&QOSEntry)) {
  			printf("Error! Get MIB_WLAN_AP_QOS_TBL error.\n");
  			continue;
		}
		switch(i){
			case 0://VO
				value[0] = QOSEntry.txop;
				snprintf(parm,sizeof(parm),"vo_txop=%u",value[0]);
				argv[3]=parm;
				TRACE(STA_SCRIPT, "%s %s %s %s\n", IWPRIV, argv[1], argv[2], argv[3]);
				status|=do_cmd(IWPRIV, argv, 1);
				value[0] = QOSEntry.ecwmax;
				snprintf(parm,sizeof(parm),"vo_ecwmax=%u",value[0]);
				argv[3]=parm;
				TRACE(STA_SCRIPT, "%s %s %s %s\n", IWPRIV, argv[1], argv[2], argv[3]);
				status|=do_cmd(IWPRIV, argv, 1);
				value[0] = QOSEntry.ecwmin;
				snprintf(parm,sizeof(parm),"vo_ecwmin=%u",value[0]);
				argv[3]=parm;
				TRACE(STA_SCRIPT, "%s %s %s %s\n", IWPRIV, argv[1], argv[2], argv[3]);
				status|=do_cmd(IWPRIV, argv, 1);
				value[0] = QOSEntry.aifsn;
				snprintf(parm,sizeof(parm),"vo_aifsn=%u",value[0]);
				argv[3]=parm;
				TRACE(STA_SCRIPT, "%s %s %s %s\n", IWPRIV, argv[1], argv[2], argv[3]);
				status|=do_cmd(IWPRIV, argv, 1);
				break;
			case 1://VI
				value[0] = QOSEntry.txop;
				snprintf(parm,sizeof(parm),"vi_txop=%u",value[0]);
				argv[3]=parm;
				TRACE(STA_SCRIPT, "%s %s %s %s\n", IWPRIV, argv[1], argv[2], argv[3]);
				status|=do_cmd(IWPRIV, argv, 1);
				value[0] = QOSEntry.ecwmax;
				snprintf(parm,sizeof(parm),"vi_ecwmax=%u",value[0]);
				argv[3]=parm;
				TRACE(STA_SCRIPT, "%s %s %s %s\n", IWPRIV, argv[1], argv[2], argv[3]);
				status|=do_cmd(IWPRIV, argv, 1);
				value[0] = QOSEntry.ecwmin;
				snprintf(parm,sizeof(parm),"vi_ecwmin=%u",value[0]);
				argv[3]=parm;
				TRACE(STA_SCRIPT, "%s %s %s %s\n", IWPRIV, argv[1], argv[2], argv[3]);
				status|=do_cmd(IWPRIV, argv, 1);
				value[0] = QOSEntry.aifsn;
				snprintf(parm,sizeof(parm),"vi_aifsn=%u",value[0]);
				argv[3]=parm;
				TRACE(STA_SCRIPT, "%s %s %s %s\n", IWPRIV, argv[1], argv[2], argv[3]);
				status|=do_cmd(IWPRIV, argv, 1);
				break;
			case 2://BE
				value[0] = QOSEntry.txop;
				snprintf(parm,sizeof(parm),"be_txop=%u",value[0]);
				argv[3]=parm;
				TRACE(STA_SCRIPT, "%s %s %s %s\n", IWPRIV, argv[1], argv[2], argv[3]);
				status|=do_cmd(IWPRIV, argv, 1);
				value[0] = QOSEntry.ecwmax;
				snprintf(parm,sizeof(parm),"be_ecwmax=%u",value[0]);
				argv[3]=parm;
				TRACE(STA_SCRIPT, "%s %s %s %s\n", IWPRIV, argv[1], argv[2], argv[3]);
				status|=do_cmd(IWPRIV, argv, 1);
				value[0] = QOSEntry.ecwmin;
				snprintf(parm,sizeof(parm),"be_ecwmin=%u",value[0]);
				argv[3]=parm;
				TRACE(STA_SCRIPT, "%s %s %s %s\n", IWPRIV, argv[1], argv[2], argv[3]);
				status|=do_cmd(IWPRIV, argv, 1);
				value[0] = QOSEntry.aifsn;
				snprintf(parm,sizeof(parm),"be_aifsn=%u",value[0]);
				argv[3]=parm;
				TRACE(STA_SCRIPT, "%s %s %s %s\n", IWPRIV, argv[1], argv[2], argv[3]);
				status|=do_cmd(IWPRIV, argv, 1);
				break;
			case 3://BK
				value[0] = QOSEntry.txop;
				snprintf(parm,sizeof(parm),"bk_txop=%u",value[0]);
				argv[3]=parm;
				TRACE(STA_SCRIPT, "%s %s %s %s\n", IWPRIV, argv[1], argv[2], argv[3]);
				status|=do_cmd(IWPRIV, argv, 1);
				value[0] = QOSEntry.ecwmax;
				snprintf(parm,sizeof(parm),"bk_ecwmax=%u",value[0]);
				argv[3]=parm;
				TRACE(STA_SCRIPT, "%s %s %s %s\n", IWPRIV, argv[1], argv[2], argv[3]);
				status|=do_cmd(IWPRIV, argv, 1);
				value[0] = QOSEntry.ecwmin;
				snprintf(parm,sizeof(parm),"bk_ecwmin=%u",value[0]);
				argv[3]=parm;
				TRACE(STA_SCRIPT, "%s %s %s %s\n", IWPRIV, argv[1], argv[2], argv[3]);
				status|=do_cmd(IWPRIV, argv, 1);
				value[0] = QOSEntry.aifsn;
				snprintf(parm,sizeof(parm),"bk_aifsn=%u",value[0]);
				argv[3]=parm;
				TRACE(STA_SCRIPT, "%s %s %s %s\n", IWPRIV, argv[1], argv[2], argv[3]);
				status|=do_cmd(IWPRIV, argv, 1);
				break;
			default:
				break;
		}
	}

	//sta
	for (i=0; i<4; i++) {
		if (!mib_chain_get(MIB_WLAN_QOS_STA_TBL, i, (void *)&QOSEntry)) {
  			printf("Error! Get MIB_WLAN_STA_QOS_TBL error.\n");
  			continue;
		}
		switch(i){
			case 0://VO
				value[0] = QOSEntry.txop;
				snprintf(parm,sizeof(parm),"sta_vo_txop=%u",value[0]);
				argv[3]=parm;
				TRACE(STA_SCRIPT, "%s %s %s %s\n", IWPRIV, argv[1], argv[2], argv[3]);
				status|=do_cmd(IWPRIV, argv, 1);
				value[0] = QOSEntry.ecwmax;
				snprintf(parm,sizeof(parm),"sta_vo_ecwmax=%u",value[0]);
				argv[3]=parm;
				TRACE(STA_SCRIPT, "%s %s %s %s\n", IWPRIV, argv[1], argv[2], argv[3]);
				status|=do_cmd(IWPRIV, argv, 1);
				value[0] = QOSEntry.ecwmin;
				snprintf(parm,sizeof(parm),"sta_vo_ecwmin=%u",value[0]);
				argv[3]=parm;
				TRACE(STA_SCRIPT, "%s %s %s %s\n", IWPRIV, argv[1], argv[2], argv[3]);
				status|=do_cmd(IWPRIV, argv, 1);
				value[0] = QOSEntry.aifsn;
				snprintf(parm,sizeof(parm),"sta_vo_aifsn=%u",value[0]);
				argv[3]=parm;
				TRACE(STA_SCRIPT, "%s %s %s %s\n", IWPRIV, argv[1], argv[2], argv[3]);
				status|=do_cmd(IWPRIV, argv, 1);
				break;
			case 1://VI
				value[0] = QOSEntry.txop;
				snprintf(parm,sizeof(parm),"sta_vi_txop=%u",value[0]);
				argv[3]=parm;
				TRACE(STA_SCRIPT, "%s %s %s %s\n", IWPRIV, argv[1], argv[2], argv[3]);
				status|=do_cmd(IWPRIV, argv, 1);
				value[0] = QOSEntry.ecwmax;
				snprintf(parm,sizeof(parm),"sta_vi_ecwmax=%u",value[0]);
				argv[3]=parm;
				TRACE(STA_SCRIPT, "%s %s %s %s\n", IWPRIV, argv[1], argv[2], argv[3]);
				status|=do_cmd(IWPRIV, argv, 1);
				value[0] = QOSEntry.ecwmin;
				snprintf(parm,sizeof(parm),"sta_vi_ecwmin=%u",value[0]);
				argv[3]=parm;
				TRACE(STA_SCRIPT, "%s %s %s %s\n", IWPRIV, argv[1], argv[2], argv[3]);
				status|=do_cmd(IWPRIV, argv, 1);
				value[0] = QOSEntry.aifsn;
				snprintf(parm,sizeof(parm),"sta_vi_aifsn=%u",value[0]);
				argv[3]=parm;
				TRACE(STA_SCRIPT, "%s %s %s %s\n", IWPRIV, argv[1], argv[2], argv[3]);
				status|=do_cmd(IWPRIV, argv, 1);
				break;
			case 2://BE
				value[0] = QOSEntry.txop;
				snprintf(parm,sizeof(parm),"sta_be_txop=%u",value[0]);
				argv[3]=parm;
				TRACE(STA_SCRIPT, "%s %s %s %s\n", IWPRIV, argv[1], argv[2], argv[3]);
				status|=do_cmd(IWPRIV, argv, 1);
				value[0] = QOSEntry.ecwmax;
				snprintf(parm,sizeof(parm),"sta_be_ecwmax=%u",value[0]);
				argv[3]=parm;
				TRACE(STA_SCRIPT, "%s %s %s %s\n", IWPRIV, argv[1], argv[2], argv[3]);
				status|=do_cmd(IWPRIV, argv, 1);
				value[0] = QOSEntry.ecwmin;
				snprintf(parm,sizeof(parm),"sta_be_ecwmin=%u",value[0]);
				argv[3]=parm;
				TRACE(STA_SCRIPT, "%s %s %s %s\n", IWPRIV, argv[1], argv[2], argv[3]);
				status|=do_cmd(IWPRIV, argv, 1);
				value[0] = QOSEntry.aifsn;
				snprintf(parm,sizeof(parm),"sta_be_aifsn=%u",value[0]);
				argv[3]=parm;
				TRACE(STA_SCRIPT, "%s %s %s %s\n", IWPRIV, argv[1], argv[2], argv[3]);
				status|=do_cmd(IWPRIV, argv, 1);
				break;
			case 3://BK
				value[0] = QOSEntry.txop;
				snprintf(parm,sizeof(parm),"sta_bk_txop=%u",value[0]);
				argv[3]=parm;
				TRACE(STA_SCRIPT, "%s %s %s %s\n", IWPRIV, argv[1], argv[2], argv[3]);
				status|=do_cmd(IWPRIV, argv, 1);
				value[0] = QOSEntry.ecwmax;
				snprintf(parm,sizeof(parm),"sta_bk_ecwmax=%u",value[0]);
				argv[3]=parm;
				TRACE(STA_SCRIPT, "%s %s %s %s\n", IWPRIV, argv[1], argv[2], argv[3]);
				status|=do_cmd(IWPRIV, argv, 1);
				value[0] = QOSEntry.ecwmin;
				snprintf(parm,sizeof(parm),"sta_bk_ecwmin=%u",value[0]);
				argv[3]=parm;
				TRACE(STA_SCRIPT, "%s %s %s %s\n", IWPRIV, argv[1], argv[2], argv[3]);
				status|=do_cmd(IWPRIV, argv, 1);
				value[0] = QOSEntry.aifsn;
				snprintf(parm,sizeof(parm),"sta_bk_aifsn=%u",value[0]);
				argv[3]=parm;
				TRACE(STA_SCRIPT, "%s %s %s %s\n", IWPRIV, argv[1], argv[2], argv[3]);
				status|=do_cmd(IWPRIV, argv, 1);
				break;
			default:
				break;
		}
	}
	return status;
}
#endif

static int setupWLan_sta_control()
{
	int status=0;
#if defined(CONFIG_RTL_STA_CONTROL_SUPPORT) && defined(WLAN_DUALBAND_CONCURRENT)
	unsigned char wlan_sta_control=0;
	int orig_wlan_idx;
	MIB_CE_MBSSIB_T Entry;
	char parm[64];

	//set stactrl_enable
	if(get_root_wlan_status()==1)
		mib_get(MIB_WIFI_STA_CONTROL, (void *)&wlan_sta_control);
	snprintf(parm, sizeof(parm), "stactrl_enable=%hhu", wlan_sta_control);
	status|=va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", parm);

	//set ssid as the same as wlan0
	if(wlan_idx==1 && wlan_sta_control == 1){		
		orig_wlan_idx = wlan_idx;
		wlan_idx = 0;
		if(!mib_chain_get(MIB_MBSSIB_TBL, 0, (void *)&Entry))
			printf("Error! Get MIB_MBSSIB_TBL for root SSID error.\n");
		snprintf(parm, sizeof(parm), "ssid=%s", Entry.ssid);
		wlan_idx = orig_wlan_idx;
		status|=va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", parm);
	}
#endif
	return status;
}

static int vap_enable_status()
{
	int j;
	char intf_map=0;
	MIB_CE_MBSSIB_T Entry;
	for (j=1; j<=WLAN_MBSSID_NUM; j++) {
		if (!mib_chain_get(MIB_MBSSIB_TBL, j, (void *)&Entry)) {
				printf("Error! Get MIB_MBSSIB_TBL for VAP SSID error.\n");
		}

		if (!Entry.wlanDisabled) {
			intf_map |= (1 << j);
		}
	}
	return intf_map!=0;
}

void checkWlanSetting()
{
	MIB_CE_MBSSIB_T Entry;
	unsigned char vBandwidth = 0, phymode = 0, phyband = 0;
	
	if(!mib_chain_get(MIB_MBSSIB_TBL, 0, (void *)&Entry)){
		printf("Error! Get MIB_MBSSIB_TBL for root SSID error.\n");
		return ;
	}
	
	phymode = Entry.wlanBand;
	
	mib_get(MIB_WLAN_CHANNEL_WIDTH,(void *)&vBandwidth);
	mib_get(MIB_WLAN_PHY_BAND_SELECT, (void *)&phyband);
	
	if(phyband == PHYBAND_2G)
	{
		if(phymode == BAND_11B || phymode == BAND_11G || phymode == BAND_11BG )
		{
			if(vBandwidth != 0){
				vBandwidth = 0;
				mib_set(MIB_WLAN_CHANNEL_WIDTH,(void *)&vBandwidth);
			}
		}
	}
	else if(phyband == PHYBAND_5G)
	{
		if(phymode == BAND_11A)
		{
			if(vBandwidth != 0){
				vBandwidth = 0;
				mib_set(MIB_WLAN_CHANNEL_WIDTH,(void *)&vBandwidth);
			}
		}
		else if(phymode == BAND_5G_11AN || phymode == BAND_11N)
		{
			if(vBandwidth >= 2){
				vBandwidth = 0;
				mib_set(MIB_WLAN_CHANNEL_WIDTH,(void *)&vBandwidth);
			}
		}
	}
}

#ifdef WLAN_FAST_INIT
static int setupWLan(char *ifname, int vwlan_idx, config_wlan_ssid ssid_index)
{
	struct wifi_mib *pmib;
	int i, skfd, intVal;
	unsigned int vInt;
	unsigned short int sInt;
	unsigned char buf1[1024];
	unsigned char value[196];
	struct iwreq wrq, wrq_root;
	MIB_CE_MBSSIB_T Entry;
	unsigned char wlan_mode, vChar, band, phyband;
	int vap_enable=0;
#ifdef WLAN_UNIVERSAL_REPEATER
	char rpt_enabled;
#endif

	if(ssid_index != CONFIG_SSID_ALL && ssid_index != vwlan_idx)
		return 0;

    skfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(skfd < 0)
		return -1;

    // Get wireless name
    if ( iw_get_ext(skfd, ifname, SIOCGIWNAME, &wrq) < 0) {
      close( skfd );
      // If no wireless name : no wireless extensions
      return -1;
    }

	if ((pmib = (struct wifi_mib *)malloc(sizeof(struct wifi_mib))) == NULL) {
		printf("MIB buffer allocation failed!\n");
		close(skfd);
		return -1;
	}

	// Disable WLAN MAC driver and shutdown interface first
	//sprintf((char *)buf1, "ifconfig %s down", ifname);
	//system((char *)buf1);
	
	//va_cmd(IFCONFIG, 2, 1, ifname, "down");

	if (vwlan_idx == 0) {
		// shutdown all WDS interface
		#if 0 //def WLAN_WDS
		for (i=0; i<8; i++) {
			//sprintf((char *)buf1, "ifconfig %s-wds%d down", ifname, i);
			//system((char *)buf1);
			sprintf((char *)buf1, "%s-wds%d", ifname, i);
			va_cmd(IFCONFIG, 2, 1, buf1, "down");
		}
		#endif
		// kill wlan application daemon
		//sprintf((char *)buf1, "wlanapp.sh kill %s", ifname);
		//system((char *)buf1);
	}
	else { // virtual interface
		snprintf((char *)buf1, sizeof(buf1), "wlan%d", wlan_idx);
		strncpy(wrq_root.ifr_name, (char *)buf1, IFNAMSIZ);
		if (ioctl(skfd, SIOCGIWNAME, &wrq_root) < 0) {
			printf("Root Interface %s open failed!\n", buf1);
			free(pmib);
			close(skfd);
			return -1;
		}
	}

#if 0
	if (vwlan_idx == 0) {
		mib_get(MIB_HW_RF_TYPE, (void *)&vChar);
		if (vChar == 0) {
			printf("RF type is NULL!\n");
			free(pmib);
			close(skfd);
			return 0;
		}
	}
#endif
	
	checkWlanSetting();
	
	if(!mib_chain_get(MIB_MBSSIB_TBL, 0, (void *)&Entry))
		printf("Error! Get MIB_MBSSIB_TBL for root SSID error.\n");

	vChar = Entry.wlanDisabled;

	if (vChar == 1) {
		free(pmib);
		close(skfd);
		return 0;
	}

	// get mib from driver
	wrq.u.data.pointer = (caddr_t)pmib;
	wrq.u.data.length = sizeof(struct wifi_mib);

	if (vwlan_idx == 0) {
		if (ioctl(skfd, SIOCMIBINIT, &wrq) < 0) {
			printf("Get WLAN MIB failed!\n");
			free(pmib);
			close(skfd);
			return -1;
		}
	}
	else {
		wrq_root.u.data.pointer = (caddr_t)pmib;
		wrq_root.u.data.length = sizeof(struct wifi_mib);				
		if (ioctl(skfd, SIOCMIBINIT, &wrq_root) < 0) {
			printf("Get WLAN MIB failed!\n");
			free(pmib);
			close(skfd);
			return -1;
		}		
	}

	// check mib version
	if (pmib->mib_version != MIB_VERSION) {
		printf("WLAN MIB version mismatch!\n");
		free(pmib);
		close(skfd);
		return -1;
	}

	if (vwlan_idx > 0) {	
		//if not root interface, clone root mib to virtual interface
		wrq.u.data.pointer = (caddr_t)pmib;
		wrq.u.data.length = sizeof(struct wifi_mib);
		if (ioctl(skfd, SIOCMIBSYNC, &wrq) < 0) {
			printf("Set WLAN MIB failed!\n");
			free(pmib);
			close(skfd);
			return -1;
		}
	}	
	//pmib->miscEntry.func_off = 0;	
	if (!mib_chain_get(MIB_MBSSIB_TBL, vwlan_idx, (void *)&Entry)) {
			printf("Error! Get MIB_MBSSIB_TBL for VAP SSID error.\n");
		free(pmib);
		close(skfd);
		return -1;
	}
	


#ifdef WLAN_MBSSID
	if(vwlan_idx > 0 && vwlan_idx < WLAN_REPEATER_ITF_INDEX)
#endif
	{
		struct sockaddr hwaddr;
		getInAddr(ifname, HW_ADDR, &hwaddr);
		memcpy(&(pmib->dot11OperationEntry.hwaddr[0]), hwaddr.sa_data, 6);
	}
	if (vwlan_idx == 0) {	//root
		mib_get(MIB_WIFI_TEST, (void *)value);
		if(value[0])
			va_cmd(IWPRIV, 3, 1, ifname, "set_mib", "mp_specific=1");
		else
			va_cmd(IWPRIV, 3, 1, ifname, "set_mib", "mp_specific=0");
		
		mib_get(MIB_HW_REG_DOMAIN, (void *)&vChar);
		pmib->dot11StationConfigEntry.dot11RegDomain = vChar;

		//mib_get(MIB_HW_LED_TYPE, (void *)&vChar);
#if defined(CONFIG_RTL_92C_SUPPORT) || defined(CONFIG_RTL_92D_SUPPORT)
		pmib->dot11OperationEntry.ledtype = 11;	
#else
		pmib->dot11OperationEntry.ledtype = 3;	
#endif
	}

	wlan_mode = Entry.wlanMode;

	//SSID setting
	memset(pmib->dot11StationConfigEntry.dot11DesiredSSID, 0, 32);
	memset(pmib->dot11StationConfigEntry.dot11SSIDtoScan, 0, 32);
	
	if(vwlan_idx == 0 || (vwlan_idx > 0 && vwlan_idx < WLAN_REPEATER_ITF_INDEX && (wlan_mode == AP_MODE || wlan_mode == AP_WDS_MODE))){
		pmib->dot11StationConfigEntry.dot11DesiredSSIDLen = strlen((char *)Entry.ssid);
		memcpy(pmib->dot11StationConfigEntry.dot11DesiredSSID, Entry.ssid, strlen((char *)Entry.ssid));
		pmib->dot11StationConfigEntry.dot11SSIDtoScanLen = strlen((char *)Entry.ssid);
		memcpy(pmib->dot11StationConfigEntry.dot11SSIDtoScan, Entry.ssid, strlen((char *)Entry.ssid));
	}
#ifdef WLAN_UNIVERSAL_REPEATER
	else if(vwlan_idx == WLAN_REPEATER_ITF_INDEX){
		mib_get( MIB_REPEATER_ENABLED1, (void *)&rpt_enabled);
		if (rpt_enabled) {
			pmib->dot11StationConfigEntry.dot11DesiredSSIDLen = strlen((char *)Entry.ssid);
			memcpy(pmib->dot11StationConfigEntry.dot11DesiredSSID, Entry.ssid, strlen((char *)Entry.ssid));
			pmib->dot11StationConfigEntry.dot11SSIDtoScanLen = strlen((char *)Entry.ssid);
			memcpy(pmib->dot11StationConfigEntry.dot11SSIDtoScan, Entry.ssid, strlen((char *)Entry.ssid));
		}
	}
#endif

#ifdef WLAN_MBSSID
	if(vwlan_idx==0){		
		// opmode
		if (wlan_mode == CLIENT_MODE)
			vInt = 8;	// client
		else	// 0(AP_MODE) or 3(AP_WDS_MODE)
			vInt = 16;	// AP
		pmib->dot11OperationEntry.opmode = vInt;

		if(pmib->dot11OperationEntry.opmode & 0x00000010){// AP mode
			for (vwlan_idx = 1; vwlan_idx < (WLAN_MBSSID_NUM+1); vwlan_idx++) {
				mib_chain_get(MIB_MBSSIB_TBL, vwlan_idx, (void *)&Entry);
				if (Entry.wlanDisabled == 0)
					vap_enable++;
			}
			vwlan_idx = 0;
		}
		if (vap_enable && (wlan_mode ==  AP_MODE || wlan_mode ==  AP_WDS_MODE))	
			pmib->miscEntry.vap_enable=1;
		else
			pmib->miscEntry.vap_enable=0;
	}
#endif
#ifdef WLAN_UNIVERSAL_REPEATER
	// Repeater opmode
	if(vwlan_idx == WLAN_REPEATER_ITF_INDEX){
		if (rpt_enabled) {
			if (wlan_mode == CLIENT_MODE)
				vInt = 16;	// Repeater is AP
			else
				vInt = 8;	// Repeater is Client
				
			pmib->dot11OperationEntry.opmode = vInt;
		}
	}
#endif

	if (vwlan_idx == 0) //root
	{
		//hw setting
		setupWlanHWSetting(ifname, pmib);
		setup8812Wlan(ifname, pmib);

		// tw power scale
		mib_get(MIB_TX_POWER, (void *)&vChar);
		intVal = getTxPowerScale(vChar);

		if (intVal) {
			for (i=0; i<MAX_CHAN_NUM; i++) {
				if(pmib->dot11RFEntry.pwrlevelCCK_A[i] != 0){ 
					if ((pmib->dot11RFEntry.pwrlevelCCK_A[i] - intVal) >= 1)
						pmib->dot11RFEntry.pwrlevelCCK_A[i] -= intVal;
					else
						pmib->dot11RFEntry.pwrlevelCCK_A[i] = 1;
				}
				if(pmib->dot11RFEntry.pwrlevelCCK_B[i] != 0){ 
					if ((pmib->dot11RFEntry.pwrlevelCCK_B[i] - intVal) >= 1)
						pmib->dot11RFEntry.pwrlevelCCK_B[i] -= intVal;
					else
						pmib->dot11RFEntry.pwrlevelCCK_B[i] = 1;
				}
				if(pmib->dot11RFEntry.pwrlevelHT40_1S_A[i] != 0){ 
					if ((pmib->dot11RFEntry.pwrlevelHT40_1S_A[i] - intVal) >= 1)
						pmib->dot11RFEntry.pwrlevelHT40_1S_A[i] -= intVal;
					else
						pmib->dot11RFEntry.pwrlevelHT40_1S_A[i] = 1;
				}
				if(pmib->dot11RFEntry.pwrlevelHT40_1S_B[i] != 0){ 
					if ((pmib->dot11RFEntry.pwrlevelHT40_1S_B[i] - intVal) >= 1)
						pmib->dot11RFEntry.pwrlevelHT40_1S_B[i] -= intVal;
					else
						pmib->dot11RFEntry.pwrlevelHT40_1S_B[i] = 1;
				}
			}	
			
#if ((defined(CONFIG_WLAN_HAL_8814AE) || defined(CONFIG_RTL_8812_SUPPORT)) && !defined(CONFIG_ENABLE_EFUSE)) || defined(WLAN_DUALBAND_CONCURRENT)
			for (i=0; i<MAX_5G_CHANNEL_NUM; i++) {
				if(pmib->dot11RFEntry.pwrlevel5GHT40_1S_A[i] != 0){ 
					if ((pmib->dot11RFEntry.pwrlevel5GHT40_1S_A[i] - intVal) >= 1)
						pmib->dot11RFEntry.pwrlevel5GHT40_1S_A[i] -= intVal;
					else
						pmib->dot11RFEntry.pwrlevel5GHT40_1S_A[i] = 1;					
				}
				if(pmib->dot11RFEntry.pwrlevel5GHT40_1S_B[i] != 0){ 
					if ((pmib->dot11RFEntry.pwrlevel5GHT40_1S_B[i] - intVal) >= 1)
						pmib->dot11RFEntry.pwrlevel5GHT40_1S_B[i] -= intVal;
					else
						pmib->dot11RFEntry.pwrlevel5GHT40_1S_B[i] = 1;
				}
			}
#endif					
		}	
	
		mib_get(MIB_WLAN_BEACON_INTERVAL, (void *)&sInt);
		pmib->dot11StationConfigEntry.dot11BeaconPeriod = sInt;

		mib_get(MIB_WLAN_AUTO_CHAN_ENABLED, (void *)value);
		if(value[0])
			pmib->dot11RFEntry.dot11channel = 0;
		else{
			mib_get(MIB_WLAN_CHAN_NUM, (void *)value);
			pmib->dot11RFEntry.dot11channel = value[0];
		}
		band = Entry.wlanBand;
#ifdef WIFI_TEST	
		if(band == 4) {// WiFi-G
			pmib->dot11StationConfigEntry.dot11BasicRates = 0x15f;
			pmib->dot11StationConfigEntry.dot11SupportedRates = 0xfff;
		}
		else if (band == 5){ // WiFi-BG
			pmib->dot11StationConfigEntry.dot11BasicRates = 0x00f;
			pmib->dot11StationConfigEntry.dot11SupportedRates = 0xfff;
		}
		else
#endif
		{
			mib_get(MIB_WIFI_SUPPORT, (void*)value);
			if(value[0] == 1){
				if(band == 2) {// WiFi-G
					pmib->dot11StationConfigEntry.dot11BasicRates = 0x15f;
					pmib->dot11StationConfigEntry.dot11SupportedRates = 0xfff;
				}
				else if(band == 3){ // WiFi-BG
					pmib->dot11StationConfigEntry.dot11BasicRates = 0x00f;
					pmib->dot11StationConfigEntry.dot11SupportedRates = 0xfff;
				}
				else{
					mib_get(MIB_WLAN_BASIC_RATE, (void *)&sInt);
					pmib->dot11StationConfigEntry.dot11BasicRates = sInt;
					mib_get(MIB_WLAN_SUPPORTED_RATE, (void *)&sInt);
					pmib->dot11StationConfigEntry.dot11SupportedRates = sInt;
				}
			}
			else{
				mib_get(MIB_WLAN_BASIC_RATE, (void *)&sInt);
				pmib->dot11StationConfigEntry.dot11BasicRates = sInt;
				mib_get(MIB_WLAN_SUPPORTED_RATE, (void *)&sInt);
				pmib->dot11StationConfigEntry.dot11SupportedRates = sInt;
				
			}
		}

		mib_get(MIB_WLAN_INACTIVITY_TIME, (void *)&vInt);
		pmib->dot11OperationEntry.expiretime = vInt;
		mib_get(MIB_WLAN_PREAMBLE_TYPE, (void *)&vChar);
		pmib->dot11RFEntry.shortpreamble = vChar;
		vChar = Entry.hidessid;
		pmib->dot11OperationEntry.hiddenAP = vChar;
		mib_get(MIB_WLAN_DTIM_PERIOD, (void *)&vChar);
		pmib->dot11StationConfigEntry.dot11DTIMPeriod = vChar;

#ifdef WLAN_ACL
		set_wlan_acl(pmib);
#endif

#ifdef WLAN_WDS
		setupWDS(pmib);
#endif
	} // root
#ifdef WLAN_UNIVERSAL_REPEATER
	if(vwlan_idx == WLAN_REPEATER_ITF_INDEX && !rpt_enabled){}
#endif
	{
		//auth
		setupWLan_dot11_auth(pmib, vwlan_idx);
#ifdef WLAN_WPA
		setupWLan_WPA(pmib, vwlan_idx);
#endif
		setupWLan_802_1x(pmib, vwlan_idx);
	}	
#ifdef WLAN_UNIVERSAL_REPEATER
	if(vwlan_idx != WLAN_REPEATER_ITF_INDEX)
#endif
	{
		mib_get(MIB_WLAN_RTS_THRESHOLD, (void *)&sInt);
		pmib->dot11OperationEntry.dot11RTSThreshold = sInt;
		mib_get(MIB_WLAN_FRAG_THRESHOLD, (void *)&sInt);
		pmib->dot11OperationEntry.dot11FragmentationThreshold = sInt;
		
		// band
		if (!mib_chain_get(MIB_MBSSIB_TBL, vwlan_idx, (void *)&Entry)) {
				printf("Error! Get MIB_MBSSIB_TBL for VAP SSID error.\n");
		}
		band = Entry.wlanBand;
#ifdef WIFI_TEST
		if (band == 4) // WiFi-G
			band = 3; // 2.4 GHz (B+G)
		else if (band == 5) // WiFi-BG
			band = 3; // 2.4 GHz (B+G)
#endif
		mib_get(MIB_WIFI_SUPPORT, (void*)&vChar);
		if(vChar==1) {
			if(band == 2)
				band = 3;
		}
		if (band == 8) { //pure 11n
			mib_get(MIB_WLAN_PHY_BAND_SELECT, (void *)&phyband);
			if(phyband == PHYBAND_5G) {//5G
				band += 4; // a
				vChar = 4;
			}
			else{
				band += 3;	//b+g+n
				vChar = 3;
			}
		}
		else if (band == 2) {	//pure 11g
			band += 1;	//b+g
			vChar = 1;
		}
		else if (band == 10) {	//g+n
			band += 1;	//b+g+n
			vChar = 1;
		}
		else if(band == 64) {	//pure 11ac
			band += 12; 	//a+n
			vChar = 12;
		}
		else if(band == 72) {	//n+ac
			band += 4; 	//a
			vChar = 4;
		}
		else vChar = 0;

		pmib->dot11BssType.net_work_type = band;
		pmib->dot11StationConfigEntry.legacySTADeny = vChar;
		pmib->dot11nConfigEntry.dot11nLgyEncRstrct = 15;
		pmib->dot11OperationEntry.wifi_specific = 2;
		pmib->dot11ErpInfo.ctsToSelf = 1;
		
		if(vwlan_idx==0){
			value[0] = Entry.rateAdaptiveEnabled;
			if (value[0] == 0) {
				pmib->dot11StationConfigEntry.autoRate = 0;
				vInt = Entry.fixedTxRate;
				pmib->dot11StationConfigEntry.fixedTxRate = vInt;
			}
			else
				pmib->dot11StationConfigEntry.autoRate = 1;
			pmib->dot11OperationEntry.block_relay = Entry.userisolation;
			setup_wlan_block();

#ifdef WIFI_TEST
			band = Entry.wlanBand;
			if (band == 4 || band == 5) {// WiFi-G or WiFi-BG
				pmib->dot11OperationEntry.block_relay = 0;
				pmib->dot11OperationEntry.wifi_specific = 1;
			}
#endif
			//jim do wifi test tricky,
			//    1 for wifi logo test,
			//    0 for normal case...
			mib_get(MIB_WIFI_SUPPORT, (void*)&vChar);
			if(vChar==1){
				band = Entry.wlanBand;
				if (band == 2 || band == 3) {// WiFi-G or WiFi-BG
					pmib->dot11OperationEntry.block_relay = 0;
					pmib->dot11OperationEntry.wifi_specific = 1;
				}
				else {// WiFi-11N
				    printf("In MIB_WLAN_BAND = 2 or 3\n");
					pmib->dot11OperationEntry.block_relay = 0;
					pmib->dot11OperationEntry.wifi_specific = 2;
				}
			}
#ifdef WLAN_QoS			
			pmib->dot11QosEntry.dot11QosEnable = Entry.wmmEnabled;
#endif
		}
		else{
			pmib->dot11StationConfigEntry.autoRate = Entry.rateAdaptiveEnabled;
			if(Entry.rateAdaptiveEnabled == 0)
				pmib->dot11StationConfigEntry.fixedTxRate = Entry.fixedTxRate;
			pmib->dot11OperationEntry.hiddenAP = Entry.hidessid;
			pmib->dot11QosEntry.dot11QosEnable = Entry.wmmEnabled;
			pmib->dot11OperationEntry.block_relay = Entry.userisolation;	
		}
		
		mib_get(MIB_WLAN_PROTECTION_DISABLED, (void *)value);
		pmib->dot11StationConfigEntry.protectionDisabled = value[0];

		//Channel Width
		mib_get(MIB_WLAN_CHANNEL_WIDTH, (void *)value);
		pmib->dot11nConfigEntry.dot11nUse40M = value[0];

		//Conntrol Sideband
		if(value[0]==0) {	//20M
			pmib->dot11nConfigEntry.dot11n2ndChOffset = 0;
		}
		else {	//40M
			mib_get(MIB_WLAN_CONTROL_BAND, (void *)value);
			if(value[0]==0)	//upper
				pmib->dot11nConfigEntry.dot11n2ndChOffset = 1;
			else	//lower
				pmib->dot11nConfigEntry.dot11n2ndChOffset = 2;
#if defined(CONFIG_WLAN_HAL_8814AE) || defined (CONFIG_RTL_8812_SUPPORT) || defined(WLAN_DUALBAND_CONCURRENT)
			mib_get(MIB_WLAN_AUTO_CHAN_ENABLED, &vChar);
			mib_get(MIB_WLAN_CHAN_NUM, (void *)value);
			if(vChar == 0 && value[0] > 14){
				printf("!!! adjust 5G 2ndoffset for 8812 !!!\n");
				if(value[0]==36 || value[0]==44 || value[0]==52 || value[0]==60)
					pmib->dot11nConfigEntry.dot11n2ndChOffset = 2;
				else
					pmib->dot11nConfigEntry.dot11n2ndChOffset = 1;
				
			}
#endif
		}
		//11N Co-Existence
		mib_get(MIB_WLAN_11N_COEXIST, (void *)value);
		pmib->dot11nConfigEntry.dot11nCoexist = value[0];
		
		//short GI
		mib_get(MIB_WLAN_SHORTGI_ENABLED, (void *)value);
		pmib->dot11nConfigEntry.dot11nShortGIfor20M = value[0];
		pmib->dot11nConfigEntry.dot11nShortGIfor40M = value[0];

		//aggregation
		mib_get(MIB_WLAN_AGGREGATION, (void *)value);
		pmib->dot11nConfigEntry.dot11nAMPDU = (value[0])? 1:0;
		pmib->dot11nConfigEntry.dot11nAMSDU = 0;

	}
#ifdef CONFIG_RTL_WAPI_SUPPORT
	if(vwlan_idx==0){
		mib_get(MIB_WLAN_WAPI_UCAST_REKETTYPE, (void *)&vChar);
		pmib->wapiInfo.wapiUpdateUCastKeyType = vChar;
		if (vChar!=1) {
			mib_get(MIB_WLAN_WAPI_UCAST_TIME, (void *)&vInt);
			pmib->wapiInfo.wapiUpdateUCastKeyTimeout = vInt;
			mib_get(MIB_WLAN_WAPI_UCAST_PACKETS, (void *)&vInt);
			pmib->wapiInfo.wapiUpdateUCastKeyPktNum = vInt;
		}
		
		mib_get(MIB_WLAN_WAPI_MCAST_REKEYTYPE, (void *)&vChar);
		pmib->wapiInfo.wapiUpdateMCastKeyType = vChar;
		if (vChar!=1) {
			mib_get(MIB_WLAN_WAPI_MCAST_TIME, (void *)&vInt);
			pmib->wapiInfo.wapiUpdateMCastKeyTimeout = vInt;
			mib_get(MIB_WLAN_WAPI_MCAST_PACKETS, (void *)&vInt);
			pmib->wapiInfo.wapiUpdateMCastKeyPktNum = vInt;
		}
	}
#endif

	//sync mib
	wrq.u.data.pointer = (caddr_t)pmib;
	wrq.u.data.length = sizeof(struct wifi_mib);
	if (ioctl(skfd, SIOCMIBSYNC, &wrq) < 0) {
		printf("Set WLAN MIB failed!\n");
		free(pmib);
		close(skfd);
		return -1;
	}
	close(skfd);

	free(pmib);
	return 0;
}
#else
// return value:
// 0  : success
// -1 : failed
int setupWLan()
{
	char *argv[6];
	unsigned char value[34], phyband;
	char parm[64], para2[15];
	int i, vInt, autoRate, autoRateRoot;
	unsigned char intf_map=1;
	unsigned char wlan_mode;
#ifdef WLAN_RATE_PRIOR
	unsigned char rate_prior=0;
#endif
	// Added by Mason Yu for Set TxPower
	char mode=0;
	int status=0;
	unsigned char stringbuf[MAX_SSID_LEN + 1];
	unsigned char rootSSID[MAX_SSID_LEN + 1];
	int j=0;
	MIB_CE_MBSSIB_T Entry;
	int intVal;
#ifdef WLAN_UNIVERSAL_REPEATER
	char rpt_enabled;
#endif

	// ifconfig wlan0 hw ether 00e04c867002
	/*if (mib_get(MIB_WLAN_MAC_ADDR, (void *)value) != 0)
	{
		snprintf(macaddr, 13, "%02x%02x%02x%02x%02x%02x",
			value[0], value[1], value[2], value[3], value[4], value[5]);
		argv[1]=(char *)WLANIF;
		argv[2]="hw";
		argv[3]="ether";
		argv[4]=macaddr;
		argv[5]=NULL;
		TRACE(STA_SCRIPT, "%s %s %s %s %s\n", IFCONFIG, argv[1], argv[2], argv[3], argv[4]);
		do_cmd(IFCONFIG, argv, 1);
	}*/
	
	checkWlanSetting();

#ifdef WLAN_RATE_PRIOR	
	mib_get(MIB_WLAN_RATE_PRIOR, (void *)&rate_prior);
#endif

	if(!mib_chain_get(MIB_MBSSIB_TBL, 0, (void *)&Entry))
		printf("Error! Get MIB_MBSSIB_TBL for root SSID error.\n");

	wlan_mode = Entry.wlanMode;
#ifdef WLAN_UNIVERSAL_REPEATER
	mib_get( MIB_REPEATER_ENABLED1, (void *)&rpt_enabled);
#endif

	argv[1] = (char*)getWlanIfName();
	argv[2] = "set_mib";

	status|=iwpriv_cmd(IWPRIV_GETMIB | IWPRIV_INT, getWlanIfName(), "set_mib", "mp_specific", MIB_WIFI_TEST);
#if defined(CONFIG_YUEME) || defined(CONFIG_CMCC) || defined(CONFIG_CU)
	status|=va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "regdomain=13");
	status|=va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "txpwr_lmt_index=4");
#else
	status|=iwpriv_cmd(IWPRIV_GETMIB | IWPRIV_INT, getWlanIfName(), "set_mib", "regdomain", MIB_HW_REG_DOMAIN);
#endif

#if defined(CONFIG_RTL_92C_SUPPORT) || defined(CONFIG_RTL_92D_SUPPORT)
	status|=va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "led_type=11");
#else
	// e8 spec need led_type=7
	status|=va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "led_type=7");
#endif

#ifdef WLAN_LIFETIME
	mib_get(MIB_WLAN_LIFETIME, (void *)&intVal);
	status|=iwpriv_cmd(IWPRIV_INT, getWlanIfName(), "set_mib", "lifetime", intVal);
#endif

	// ssid
	// Modified by Mason Yu
	// Root AP's SSID
	snprintf(parm, sizeof(parm), "ssid=%s", Entry.ssid);
	status|=va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", parm);

#ifdef WLAN_MBSSID
	// VAP's SSID
	if (wlan_mode == AP_MODE || wlan_mode == AP_WDS_MODE) {
		for (j=1; j<=WLAN_MBSSID_NUM; j++) {
			if (!mib_chain_get(MIB_MBSSIB_TBL, j, (void *)&Entry)) {
  				printf("Error! Get MIB_MBSSIB_TBL for VAP SSID error.\n");
			}

 			//if ( Entry.wlanDisabled == 1 ) {
				snprintf(para2, sizeof(para2), "%s-vap%d", getWlanIfName(), j-1);
				snprintf(parm, sizeof(parm), "ssid=%s", Entry.ssid);
				status|=va_cmd(IWPRIV, 3, 1, para2, "set_mib", parm);
			//}

			if (!Entry.wlanDisabled) {
				intf_map |= (1 << j);
			}
		}
		argv[1] = (char*)getWlanIfName();
	}
#endif
#ifdef WLAN_UNIVERSAL_REPEATER
	if (rpt_enabled) {
		if (!mib_chain_get(MIB_MBSSIB_TBL, WLAN_REPEATER_ITF_INDEX, (void *)&Entry)) {
  			printf("Error! Get MIB_MBSSIB_TBL for VXD SSID error.\n");
		}

		snprintf(para2, sizeof(para2), "%s-vxd", getWlanIfName());
		snprintf(parm, sizeof(parm), "ssid=%s", Entry.ssid);
		status|=va_cmd(IWPRIV, 3, 1, para2, "set_mib", parm);
		argv[1] = (char*)getWlanIfName();
	}
#endif

	// opmode
	if (wlan_mode == CLIENT_MODE)
		vInt = 8;	// client
	else	// 0(AP_MODE) or 3(AP_WDS_MODE)
		vInt = 16;	// AP

	status|=iwpriv_cmd(IWPRIV_INT, getWlanIfName(), "set_mib", "opmode", vInt);

#ifdef WLAN_UNIVERSAL_REPEATER
	// Repeater opmode
	if (rpt_enabled) {
		if (wlan_mode == CLIENT_MODE)
			vInt = 16;	// Repeater is AP
		else
			vInt = 8;	// Repeater is Client
		snprintf(para2, sizeof(para2), "%s-vxd", getWlanIfName());
		status|=iwpriv_cmd(IWPRIV_INT, para2, "set_mib", "opmode", vInt);
		argv[1] = (char*)getWlanIfName();
	}
#endif

	//12/16/04' hrchen, only need to set once
	// Added by Mason Yu for Set TxPower
//#if defined(CONFIG_RTL_92D_SUPPORT) || defined(WLAN0_5G_SUPPORT) || defined(WLAN1_5G_SUPPORT)
#if defined(CONFIG_RTL_92D_SUPPORT)
	status|=iwpriv_cmd(IWPRIV_GETMIB|IWPRIV_INT, getWlanIfName(), "set_mib", "macPhyMode", MIB_WLAN_MAC_PHY_MODE);
#endif
	status|=iwpriv_cmd(IWPRIV_GETMIB|IWPRIV_INT, getWlanIfName(), "set_mib", "phyBandSelect", MIB_WLAN_PHY_BAND_SELECT);
//#endif
#ifdef CONFIG_RTL_92D_SUPPORT
	mib_get(MIB_HW_11N_TRSWITCH, (void *)value);
	if(value[0] != 0) 
		status|=iwpriv_cmd(IWPRIV_INT, getWlanIfName(), "set_mib", "trswitch", value[0]);
	
#endif //CONFIG_RTL_92D_SUPPORT

	status |= setupWlanHWSetting(getWlanIfName());

#if defined(CONFIG_WLAN_HAL_8814AE) || defined(CONFIG_RTL_8812_SUPPORT ) || defined(WLAN_DUALBAND_CONCURRENT)
	status |= setup8812Wlan(getWlanIfName());
#endif

	status |= setupWlanDPK();

	// bcnint
	mib_get(MIB_WLAN_BEACON_INTERVAL, (void *)value);
	vInt = (int)(*(unsigned short *)value);
	snprintf(parm, sizeof(parm), "bcnint=%u", vInt);
	status|=va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", parm);

	// channel
	mib_get(MIB_WLAN_AUTO_CHAN_ENABLED, (void *)value);
	if(value[0]){
		status|=va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "channel=0");
#if 0 //def CONFIG_YUEME //for auto channel in master channel, 2.4G (1, 6, 11)
		if(phyband == PHYBAND_5G) {//5G
			status|=va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "autoch_1611_enable=1");
		else
			status|=va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "autoch_1611_enable=1");
#endif
	}
	else
		status|=iwpriv_cmd(IWPRIV_GETMIB|IWPRIV_INT, getWlanIfName(), "set_mib", "channel", MIB_WLAN_CHAN_NUM);

#ifdef WIFI_TEST
	if(!mib_chain_get(MIB_MBSSIB_TBL, 0, (void *)&Entry))
		printf("Error! Get MIB_MBSSIB_TBL for root SSID error.\n");
	value[0] = Entry.wlanBand;
	if (value[0] == 4){ // WiFi-G
		snprintf(parm, sizeof(parm), "basicrates=%u", 0x15f);
		status|=va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", parm);
	}
	else if (value[0] == 5){ // WiFi-BG
		snprintf(parm, sizeof(parm), "basicrates=%u", 0x00f);
		status|=va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", parm);
	}
	else {
#endif
	//jim do wifi test tricky,
	//    1 for wifi logo test,
	//    0 for normal case...
	mib_get(MIB_WIFI_SUPPORT, (void*)value);
	if(value[0]==1){
		if(!mib_chain_get(MIB_MBSSIB_TBL, 0, (void *)&Entry))
			printf("Error! Get MIB_MBSSIB_TBL for root SSID error.\n");
		value[0] = Entry.wlanBand;
		if (value[0] == 2) {// WiFi-G
			snprintf(parm, sizeof(parm), "basicrates=%u", 0x15f);
			status|=va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", parm);
		}
		else if (value[0] == 3){// WiFi-BG
			snprintf(parm, sizeof(parm), "basicrates=%u", 0x00f);
			status|=va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", parm);
		}
		else {
			mib_get(MIB_WLAN_BASIC_RATE, (void *)value);
			vInt = (int)(*(unsigned short *)value);
			status|=iwpriv_cmd(IWPRIV_INT, getWlanIfName(), "set_mib", "basicrates", vInt);
		}
	}
	else{
		// basicrates
		mib_get(MIB_WLAN_BASIC_RATE, (void *)value);
		vInt = (int)(*(unsigned short *)value);
		status|=iwpriv_cmd(IWPRIV_INT, getWlanIfName(), "set_mib", "basicrates", vInt);
	}
#ifdef WIFI_TEST
	}
#endif

#ifdef WIFI_TEST
	if(!mib_chain_get(MIB_MBSSIB_TBL, 0, (void *)&Entry))
		printf("Error! Get MIB_MBSSIB_TBL for root SSID error.\n");
	value[0] = Entry.wlanBand;
	if (value[0] == 4) {// WiFi-G
		snprintf(parm, sizeof(parm), "oprates=%u", 0xfff);
		status|=va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", parm);
	}
	else if (value[0] == 5) {// WiFi-BG
		snprintf(parm, sizeof(parm), "oprates=%u", 0xfff);
		status|=va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", parm);
	}
	else {
#endif
	//jim do wifi test tricky,
	//    1 for wifi logo test,
	//    0 for normal case...
	mib_get(MIB_WIFI_SUPPORT, (void*)value);
	if(value[0]==1){
		if(!mib_chain_get(MIB_MBSSIB_TBL, 0, (void *)&Entry))
			printf("Error! Get MIB_MBSSIB_TBL for root SSID error.\n");
		value[0] = Entry.wlanBand;
		if (value[0] == 2) {// WiFi-G
			snprintf(parm, sizeof(parm), "oprates=%u", 0xfff);
			status|=va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", parm);
		}
		else if (value[0] == 3) {// WiFi-BG
			snprintf(parm, sizeof(parm), "oprates=%u", 0xfff);
			status|=va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", parm);
		}
		else {
			mib_get(MIB_WLAN_SUPPORTED_RATE, (void *)value);
			vInt = (int)(*(unsigned short *)value);
			status|=iwpriv_cmd(IWPRIV_INT, getWlanIfName(), "set_mib", "oprates", vInt);
		}
	}
	else{
		// oprates
		mib_get(MIB_WLAN_SUPPORTED_RATE, (void *)value);
		vInt = (int)(*(unsigned short *)value);
		status|=iwpriv_cmd(IWPRIV_INT, getWlanIfName(), "set_mib", "oprates", vInt);
	}
#ifdef WIFI_TEST
	}
#endif

	if(!mib_chain_get(MIB_MBSSIB_TBL, 0, (void *)&Entry))
		printf("Error! Get MIB_MBSSIB_TBL for root SSID error.\n");
	// autorate
	autoRateRoot = Entry.rateAdaptiveEnabled;
	snprintf(parm, sizeof(parm), "autorate=%u", autoRateRoot);
	status|=va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", parm);

	// rtsthres
	mib_get(MIB_WLAN_RTS_THRESHOLD, (void *)value);
	vInt = (int)(*(unsigned short *)value);
	snprintf(parm, sizeof(parm), "rtsthres=%u", vInt);
	status|=va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", parm);
	set_vap_para("set_mib", parm, CONFIG_SSID_ALL);

	// fragthres
	mib_get(MIB_WLAN_FRAG_THRESHOLD, (void *)value);
	vInt = (int)(*(unsigned short *)value);
	snprintf(parm, sizeof(parm), "fragthres=%u", vInt);
	status|=va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", parm);
	set_vap_para("set_mib", parm, CONFIG_SSID_ALL);

	// expired_time
	mib_get(MIB_WLAN_INACTIVITY_TIME, (void *)value);
	vInt = (int)(*(unsigned long *)value);
	snprintf(parm, sizeof(parm), "expired_time=%u", vInt);
	status|=va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", parm);

	// preamble
	status|=iwpriv_cmd(IWPRIV_GETMIB|IWPRIV_INT, getWlanIfName(), "set_mib", "preamble", MIB_WLAN_PREAMBLE_TYPE);

	// hiddenAP
	snprintf(parm, sizeof(parm), "hiddenAP=%u", Entry.hidessid);
	status|=va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", parm);

	// dtimperiod
	status|=iwpriv_cmd(IWPRIV_GETMIB|IWPRIV_INT, getWlanIfName(), "set_mib", "dtimperiod", MIB_WLAN_DTIM_PERIOD);

    //txbf must disable if enable antenna diversity
#if defined(WLAN_INTF_TXBF_DISABLE)
	if(wlan_idx == WLAN_INTF_TXBF_DISABLE)
		status|=va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "txbf=0");
#endif

#ifdef WLAN_ACL
	status|=set_wlan_acl(getWlanIfName());
#ifdef WLAN_MBSSID
		if (wlan_mode == AP_MODE || wlan_mode == AP_WDS_MODE) {
			for (j=1; j<=WLAN_MBSSID_NUM; j++){
				snprintf(para2, sizeof(para2), "%s-vap%d", getWlanIfName(), j-1);
				status|=set_wlan_acl(para2);
			}
		}
#endif
#ifdef WLAN_UNIVERSAL_REPEATER
		if (wlan_mode != WDS_MODE) {
			if (rpt_enabled){
				snprintf(para2, sizeof(para2), "%s-vxd", getWlanIfName());
				status|=set_wlan_acl(para2);
			}
		}
#endif
#endif

	unsigned char scWlanVal = 0;
	mib_get(PROVINCE_SICHUAN_WLAN_AUTO_CH_TIMEOUT, &scWlanVal);
	if(scWlanVal)
	{
		va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "autoch_timeout=900");
	}
	else
	{
		va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "autoch_timeout=0");
	}
#if defined(WLAN_DUALBAND_CONCURRENT) && defined(CONFIG_RTL_STA_CONTROL_SUPPORT)//Band steering
	unsigned char vuChar = 0;
	mib_get( MIB_WIFI_STA_CONTROL, (void *)&vuChar);
	if((mib_get( MIB_WIFI_STA_CONTROL, (void *)&vuChar) && vuChar)
		&& (mib_get(MIB_WLAN_BANDST_ENABLE, &vuChar) && vuChar))
	{
		snprintf(parm, sizeof(parm), "stactrl_enable=%d", (vuChar)?1:0);
		va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", parm);
		
		if(mib_get(MIB_WLAN_BANDST_RSSTHRDHIGH, &intVal))
		{
			intVal = intVal+100;
			snprintf(parm, sizeof(parm), "stactrl_rssi_th_high=%d", intVal);
			va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", parm);
		}
		
		if(mib_get(MIB_WLAN_BANDST_RSSTHRDLOW, &intVal))
		{
			intVal = intVal+100;
			snprintf(parm, sizeof(parm), "stactrl_rssi_th_low=%d", intVal);
			va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", parm);
		}
		
		if(mib_get(MIB_WLAN_BANDST_CHANNELUSETHRD, &intVal))
		{
			intVal = ((intVal*255)/100);
			snprintf(parm, sizeof(parm), "stactrl_ch_util_th=%d", intVal);
			va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", parm);
		}
		
		if(mib_get(MIB_WLAN_BANDST_STEERINGINTERVAL, &intVal))
		{
			snprintf(parm, sizeof(parm), "stactrl_steer_detect=%d", intVal);
			va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", parm);
		}
		
		if(mib_get(MIB_WLAN_BANDST_STALOADTHRESHOLD2G, &intVal))
		{
			snprintf(parm, sizeof(parm), "stactrl_sta_load_th_2g=%d", intVal);
			va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", parm);
		}
				
		mib_get(MIB_WLAN_PHY_BAND_SELECT, (void *)&phyband);
		snprintf(parm, sizeof(parm), "stactrl_prefer_band=%d", (phyband == PHYBAND_5G)?1:0);
		va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", parm);
	}
	else{
		va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "stactrl_enable=0");
	}
#endif
	// authtype
	// Modified by Mason Yu
	// Root AP's authtype
	setupWLan_dot11_auth(0);
#if defined(CONFIG_YUEME)
	setup_wlan_accessRule_netfilter(getWlanIfName(), &Entry);
#endif

#ifdef WLAN_MBSSID
	// VAP
	for (j=1; j<=WLAN_MBSSID_NUM; j++) {
		setupWLan_dot11_auth(j);
		if (!mib_chain_get(MIB_MBSSIB_TBL, j, (void *)&Entry)) {
  			printf("Error! Get MIB_MBSSIB_TBL for VAP SSID error.\n");
		}

		snprintf(para2, sizeof(para2), "%s-vap%d", getWlanIfName(), j-1);
		argv[1] = para2;

		//for wifi-vap band
		value[0] = Entry.wlanBand;
#ifdef WIFI_TEST
		if (value[0] == 4) // WiFi-G
			value[0] = 3; // 2.4 GHz (B+G)
		else if (value[0] == 5) // WiFi-BG
			value[0] = 3; // 2.4 GHz (B+G)
#endif
		unsigned char vChar;
		mib_get(MIB_WIFI_SUPPORT, (void*)&vChar);
		if(vChar==1) {
			if(value[0] == 2)
				value[0] = 3;
		}
#ifdef WLAN_RATE_PRIOR
		if(rate_prior == 0){
#endif
			if (value[0] == 8) { //pure 11n
				mib_get(MIB_WLAN_PHY_BAND_SELECT, (void *)&phyband);
				if(phyband == PHYBAND_5G) {//5G
					value[0] += 4; // a
					vChar = 4;
				}
				else{
					value[0] += 3;	//b+g+n
					vChar = 3;
				}
			}
			else if (value[0] == 2) {	//pure 11g
				value[0] += 1;	//b+g
				vChar = 1;
			}
			else if (value[0] == 10) {	//g+n
				value[0] += 1;	//b+g+n
				vChar = 1;
			}
			else if(value[0] == 64) {	//pure 11ac
				value[0] += 12; 	//a+n
				vChar = 12;
			}
			else if(value[0] == 72) {	//n+ac
				value[0] += 4; 	//a
				vChar = 4;
			}		
			else vChar = 0;
#ifdef WLAN_RATE_PRIOR
		}
		else{
			mib_get(MIB_WLAN_PHY_BAND_SELECT, (void *)&phyband);
			if(phyband == PHYBAND_5G) {//5G
				value[0] = 76; //pure 11ac
				vChar = 12;
			}
			else{
				value[0] = 11;	//pure 11n
				vChar = 3;
			}	
		}
#endif
		
		status |= iwpriv_cmd(IWPRIV_INT, para2, "set_mib", "band", value[0]); //802.11b:1, 802.11g:2, 802.11n:8

		// for wifi-vap autorate
		value[0] = Entry.rateAdaptiveEnabled;
		autoRate = (int)value[0];
		status |=iwpriv_cmd(IWPRIV_INT, para2, "set_mib", "autorate", autoRate);

		if (autoRate == 0) 
			// for wifi-vap fixrate
			status |=iwpriv_cmd(IWPRIV_INT, para2, "set_mib", "fixrate", Entry.fixedTxRate);

		//for wifi-vap hidden AP
		status|=iwpriv_cmd(IWPRIV_INT, para2, "set_mib", "hiddenAP", Entry.hidessid);

		// for wifi-vap WMM
		status|=iwpriv_cmd(IWPRIV_INT, para2, "set_mib", "qos_enable", Entry.wmmEnabled);

		//for wifi-vap max block_relay
		status|=iwpriv_cmd(IWPRIV_INT, para2, "set_mib", "block_relay", Entry.userisolation);

		//deny legacy
		status|=iwpriv_cmd(IWPRIV_INT, para2, "set_mib", "deny_legacy", vChar);
		
#ifdef WLAN_LIMITED_STA_NUM
		status|=iwpriv_cmd(IWPRIV_INT, para2, "set_mib", "stanum", Entry.stanum);
#endif
		
		//vap will follow root interface
		//txbf must disable if enable antenna diversity
#if 0// defined(CONFIG_SLOT_0_ANT_SWITCH) || defined(CONFIG_SLOT_1_ANT_SWITCH) || defined(CONFIG_YUEME)
		status|=iwpriv_cmd(IWPRIV_INT, para2, "set_mib", "txbf", 0);
#endif

#if defined(CONFIG_YUEME)
		setup_wlan_accessRule_netfilter(para2, &Entry);
#endif

	}
	argv[1] = (char*)getWlanIfName();
#endif
#ifdef WLAN_UNIVERSAL_REPEATER
	if (rpt_enabled) {
		setupWLan_dot11_auth(WLAN_REPEATER_ITF_INDEX);
	}
#endif // of WLAN_UNIVERSAL_REPEATER

#if defined WLAN_QoS && (!defined (CONFIG_RTL8192CD) && !defined(CONFIG_RTL8192CD_MODULE))
	status|=setupWLanQos(argv);
#endif

#ifdef WLAN_ROAMING
	setupWLan_Roaming(0);
#endif

#ifdef WLAN_WPA

	// Modified by Mason Yu
	// encmode
	// Root AP
	setupWLan_WPA(0); // Root
#ifdef WLAN_11R
	setupWLan_FT(0);
#endif
#ifdef WLAN_11K
	setupWLan_dot11K(0);
#endif
#ifdef WLAN_11V
	setupWLan_dot11V(0);
#endif

#ifdef WLAN_MBSSID
	// encmode
	for (j=1; j<=WLAN_MBSSID_NUM; j++) {
		setupWLan_WPA(j);
#ifdef WLAN_11R
		setupWLan_FT(j);
#endif
#ifdef WLAN_11K
		setupWLan_dot11K(j);
#endif
#ifdef WLAN_11V
		setupWLan_dot11V(j);
#endif
	}
#endif
#ifdef WLAN_UNIVERSAL_REPEATER
	if (rpt_enabled)
		setupWLan_WPA(WLAN_REPEATER_ITF_INDEX);
#endif

	// Modified by Mason Yu
	// Set 802.1x flag
	setupWLan_802_1x(0); // Root

#ifdef WLAN_MBSSID
	// Set 802.1x flag
	for (j=1; j<=WLAN_MBSSID_NUM; j++)
		setupWLan_802_1x(j); // VAP
#endif
#ifdef WLAN_UNIVERSAL_REPEATER
	if (rpt_enabled)
		setupWLan_802_1x(WLAN_REPEATER_ITF_INDEX); // Repeater
#endif

#endif // of WLAN_WPA

	if(!mib_chain_get(MIB_MBSSIB_TBL, 0, (void *)&Entry))
		printf("Error! Get MIB_MBSSIB_TBL for root SSID error.\n");
	// band
	value [0] = Entry.wlanBand;
#ifdef WIFI_TEST
	if (value[0] == 4) // WiFi-G
		value[0] = 3; // 2.4 GHz (B+G)
	else if (value[0] == 5) // WiFi-BG
		value[0] = 3; // 2.4 GHz (B+G)
#endif
	//jim do wifi test tricky,
	//    1 for wifi logo test,
	//    0 for normal case...
	unsigned char vChar;
	mib_get(MIB_WIFI_SUPPORT, (void*)&vChar);
	if(vChar==1){
		if(value[0] == 2)
			value[0] = 3;
	}

#ifdef WLAN_RATE_PRIOR
	if(rate_prior == 0){
#endif
		if(value[0] == 8) {	//pure 11n
			mib_get(MIB_WLAN_PHY_BAND_SELECT, (void *)&phyband);
			if(phyband == PHYBAND_5G) {//5G
				value[0] += 4; // a
				vChar = 4;
			}
			else{
				value[0] += 3;	//b+g+n
				vChar = 3;
			}
		}
		else if(value[0] == 2) {	//pure 11g
			value[0] += 1;	//b+g
			vChar = 1;
		}
		else if(value[0] == 10) {	//g+n
			value[0] += 1; 	//b+g+n
			vChar = 1;
		}
		else if(value[0] == 64) {	//pure 11ac
			value[0] += 12; 	//a+n
			vChar = 12;
		}
		else if(value[0] == 72) {	//n+ac
			value[0] += 4; 	//a
			vChar = 4;
		}
		else vChar = 0;
#ifdef WLAN_RATE_PRIOR
	}
	else{
		mib_get(MIB_WLAN_PHY_BAND_SELECT, (void *)&phyband);
		if(phyband == PHYBAND_5G) {//5G
			value[0] = 76; //pure 11ac
			vChar = 12;
		}
		else{
			value[0] = 11;	//pure 11n
			vChar = 3;
		}	
	}
#endif

	status|=iwpriv_cmd(IWPRIV_INT, getWlanIfName(), "set_mib", "band", value[0]); //802.11b:1, 802.11g:2, 802.11n:8

	//deny legacy
	status|=iwpriv_cmd(IWPRIV_INT, getWlanIfName(), "set_mib", "deny_legacy", vChar);

	// For TKIP g mode issue (WiFi Cert 4.2.44: Disallow TKIP with HT Rates Test). Added by Annie, 2010-06-29.
	va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "lgyEncRstrct=15");
	set_vap_para("set_mib","lgyEncRstrct=15", CONFIG_SSID_ALL);

	// For WiFi Test Plan. Added by Annie, 2010-06-29.
	va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "wifi_specific=2");
	set_vap_para("set_mib","wifi_specific=2", CONFIG_SSID_ALL);

	if (autoRateRoot == 0)
	{
		// fixrate
		snprintf(parm, sizeof(parm), "fixrate=%u", Entry.fixedTxRate);
		status|=va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", parm);
	}
//cathy, for multicast rate
#ifdef CONFIG_USB_RTL8187SU_SOFTAP
	mib_get(MIB_WLAN_MLCSTRATE, (void *)value);
	vInt = (int)(*(unsigned short *)value);
	snprintf(parm, sizeof(parm), "lowestMlcstRate=%u", vInt);
	status|=va_cmd(IWPRIV, (char *)getWlanIfName(), "set_mib", parm);
	set_vap_para(argv[2], argv[3], CONFIG_SSID_ALL);
#endif

#ifdef WLAN_WDS
	setupWDS();
#endif

//12/23/04' hrchen, these MIBs are for CLIENT mode, disable them
#if 0
	//12/16/04' hrchen, disable nat25_disable
	// nat25_disable
	value[0] = 0;
	sprintf(parm, "nat25_disable=%u", value[0]);
	argv[3] = parm;
	argv[4] = NULL;
	TRACE(STA_SCRIPT, "%s %s %s %s\n", IWPRIV, argv[1], argv[2], argv[3]);
	status|=do_cmd(IWPRIV, argv, 1);

	//12/16/04' hrchen, disable macclone_enable
	// macclone_enable
	value[0] = 0;
	sprintf(parm, "macclone_enable=%u", value[0]);
	argv[3] = parm;
	argv[4] = NULL;
	TRACE(STA_SCRIPT, "%s %s %s %s\n", IWPRIV, argv[1], argv[2], argv[3]);
	status|=do_cmd(IWPRIV, argv, 1);
#endif

#if 0
	//12/16/04' hrchen, debug flag
	// debug_err
	sprintf(parm, "debug_err=ffffffff");
	argv[3] = parm;
	argv[4] = NULL;
	TRACE(STA_SCRIPT, "%s %s %s %s\n", IWPRIV, argv[1], argv[2], argv[3]);
	status|=do_cmd(IWPRIV, argv, 1);
	// debug_info
	sprintf(parm, "debug_info=0");
	argv[3] = parm;
	argv[4] = NULL;
	TRACE(STA_SCRIPT, "%s %s %s %s\n", IWPRIV, argv[1], argv[2], argv[3]);
	status|=do_cmd(IWPRIV, argv, 1);
	// debug_warn
	sprintf(parm, "debug_warn=0");
	argv[3] = parm;
	argv[4] = NULL;
	TRACE(STA_SCRIPT, "%s %s %s %s\n", IWPRIV, argv[1], argv[2], argv[3]);
	status|=do_cmd(IWPRIV, argv, 1);
	// debug_trace
	sprintf(parm, "debug_trace=0");
	argv[3] = parm;
	argv[4] = NULL;
	TRACE(STA_SCRIPT, "%s %s %s %s\n", IWPRIV, argv[1], argv[2], argv[3]);
	status|=do_cmd(IWPRIV, argv, 1);
#endif

	//12/16/04' hrchen, for protection mode
	// cts2self
	status|=va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "cts2self=1");

	//12/16/04' hrchen, set 11g protection mode
	// disable_protection
	mib_get(MIB_WLAN_PROTECTION_DISABLED, (void *)value);
	snprintf(parm, sizeof(parm), "disable_protection=%u", value[0]);
	status|=va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", parm);
	set_vap_para("set_mib", parm, CONFIG_SSID_ALL);

	//12/16/04' hrchen, chipVersion
	// chipVersion
	/*
	sprintf(parm, "chipVersion=0");
	argv[3] = parm;
	argv[4] = NULL;
	TRACE(STA_SCRIPT, "%s %s %s %s\n", IWPRIV, argv[1], argv[2], argv[3]);
	status|=do_cmd(IWPRIV, argv, 1);
	*/

#if 0	// not necessary for AP
	//12/16/04' hrchen, defssid
	// defssid
	sprintf(parm, "defssid=\"defaultSSID\"");
	argv[3] = parm;
	argv[4] = NULL;
	TRACE(STA_SCRIPT, "%s %s %s %s\n", IWPRIV, argv[1], argv[2], argv[3]);
	status|=do_cmd(IWPRIV, argv, 1);
#endif

	//12/16/04' hrchen, set block relay
	// block_relay
	snprintf(parm, sizeof(parm), "block_relay=%u", Entry.userisolation);
	status|=va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", parm);
	setup_wlan_block();
	
#ifdef WIFI_TEST
	value[0] = Entry.wlanBand;
	if (value[0] == 4 || value[0] == 5) {// WiFi-G or WiFi-BG
		// block_relay=0
		status|=va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "block_relay=0");
		// wifi_specific=1
		status|=va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "wifi_specific=1");
	}
#endif
	//jim do wifi test tricky,
	//    1 for wifi logo test,
	//    0 for normal case...
	mib_get(MIB_WIFI_SUPPORT, (void*)value);
	if(value[0]==1){
		value[0] = Entry.wlanBand;
		if (value[0] == 2 || value[0] == 3) {// WiFi-G or WiFi-BG
			// block_relay=0
			status|=va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "block_relay=0");
			// wifi_specific=1
			status|=va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "wifi_specific=1");
		}
		else {// WiFi-11N
		    printf("In MIB_WLAN_BAND = 2 or 3\n");
			status|=va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "block_relay=0");
			// wifi_specific=2
			status|=va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "wifi_specific=2");
		}
	}

#ifdef WLAN_QoS
	value[0] = Entry.wmmEnabled;
	if(value[0]==0){
		va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "qos_enable=0");
		//set_vap_para("set_mib","qos_enable=0", CONFIG_SSID_ALL);
	}
	else if(value[0]==1){
		va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "qos_enable=1");
		//set_vap_para("set_mib","qos_enable=1", CONFIG_SSID_ALL);
	}

	// Kaohj -- not support in this moment
	#if 0
	//for wmm power saving
	mib_get(MIB_WLAN_APSD_ENABLE, (void *)value);
	if(value[0]==0)
		va_cmd(IWPRIV, 3, 1, (char *)WLANIF, "set_mib", "apsd_enable=0");
	else if(value[0]==1)
		va_cmd(IWPRIV, 3, 1, (char *)WLANIF, "set_mib", "apsd_enable=1");
	#endif
#endif

#ifdef WLAN_LIMITED_STA_NUM
	snprintf(parm, sizeof(parm), "stanum=%d", Entry.stanum);
	va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", parm);
#endif

#ifdef WLAN_RATE_PRIOR
	if(rate_prior==0){
#endif
		//Channel Width
		mib_get(MIB_WLAN_CHANNEL_WIDTH, (void *)value);
		if(value[0]==0)	// 20MHZ
		{
			va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "use40M=0");
			set_vap_para("set_mib", "use40M=0", CONFIG_SSID_ALL);
		}
		else if(value[0]==1)	// 40MHZ
		{
			va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "use40M=1");
			set_vap_para("set_mib", "use40M=1", CONFIG_SSID_ALL);
		}
		else	// 80MHZ
		{
			va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "use40M=2");
			set_vap_para("set_mib", "use40M=2", CONFIG_SSID_ALL);
		}
#ifdef WLAN_RATE_PRIOR
	}
	else{
		mib_get(MIB_WLAN_PHY_BAND_SELECT, (void *)&phyband);
		if(phyband == PHYBAND_5G) {//80Mz
			va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "use40M=2");
			set_vap_para("set_mib", "use40M=2", CONFIG_SSID_ALL);
		}
		else{
			va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "use40M=1");
			set_vap_para("set_mib", "use40M=1", CONFIG_SSID_ALL);
		}	
	}
#endif
	//Conntrol Sideband
	if(value[0]==0) {	//20M
		va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "2ndchoffset=0");
		set_vap_para("set_mib", "2ndchoffset=0", CONFIG_SSID_ALL);
	}
	else {	//40M
		mib_get(MIB_WLAN_CONTROL_BAND, (void *)value);
		if(value[0]==0){	//upper
			va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "2ndchoffset=1");
			set_vap_para("set_mib", "2ndchoffset=1", CONFIG_SSID_ALL);
		}
		else{		//lower
			va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "2ndchoffset=2");
			set_vap_para("set_mib", "2ndchoffset=2", CONFIG_SSID_ALL);
		}
#if defined(CONFIG_WLAN_HAL_8814AE) || defined (CONFIG_RTL_8812_SUPPORT) || defined(WLAN_DUALBAND_CONCURRENT)
		mib_get(MIB_WLAN_AUTO_CHAN_ENABLED, &vChar);
		mib_get(MIB_WLAN_CHAN_NUM, (void *)value);
		if(vChar == 0 && value[0] > 14)
		{
			printf("!!! adjust 5G 2ndoffset for 8812 !!!\n");
			if(value[0]==36 || value[0]==44 || value[0]==52 || value[0]==60){
				va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "2ndchoffset=2");
				set_vap_para("set_mib", "2ndchoffset=2", CONFIG_SSID_ALL);
			}
			else{
				va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "2ndchoffset=1");
				set_vap_para("set_mib", "2ndchoffset=1", CONFIG_SSID_ALL);
			}
		}
#endif
	}
#ifdef WLAN_RATE_PRIOR
	if(rate_prior==0){
#endif
		//11N Co-Existence
		mib_get(MIB_WLAN_11N_COEXIST, (void *)value);
		if(value[0]==0)
		{
			va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "coexist=0");
			set_vap_para("set_mib", "coexist=0", CONFIG_SSID_ALL);
		}
		else
		{
			va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "coexist=1");
			set_vap_para("set_mib", "coexist=1", CONFIG_SSID_ALL);

		}
#ifdef WLAN_RATE_PRIOR
	}
	else{
		mib_get(MIB_WLAN_PHY_BAND_SELECT, (void *)&phyband);
		if(phyband == PHYBAND_2G) {
			va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "coexist=1");
			set_vap_para("set_mib", "coexist=1", CONFIG_SSID_ALL);
		}
	}
#endif

	//short GI
#ifndef CONFIG_YUEME
	mib_get(MIB_WLAN_SHORTGI_ENABLED, (void *)value);
	if(value[0]==0) {
		va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "shortGI20M=0");
		set_vap_para("set_mib", "shortGI20M=0", CONFIG_SSID_ALL);
		va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "shortGI40M=0");
		set_vap_para("set_mib", "shortGI40M=0", CONFIG_SSID_ALL);
		va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "shortGI80M=0");
		set_vap_para("set_mib", "shortGI80M=0", CONFIG_SSID_ALL);
	}
	else {
#endif
		va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "shortGI20M=1");
		set_vap_para("set_mib", "shortGI20M=1", CONFIG_SSID_ALL);
		va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "shortGI40M=1");
		set_vap_para("set_mib", "shortGI40M=1", CONFIG_SSID_ALL);
		va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "shortGI80M=1");
		set_vap_para("set_mib", "shortGI80M=1", CONFIG_SSID_ALL);
#ifndef CONFIG_YUEME
	}
#endif

	//aggregation
	mib_get(MIB_WLAN_AGGREGATION, (void *)value);
	if(value[0]==0) {
		va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "ampdu=0");
		set_vap_para("set_mib", "ampdu=0", CONFIG_SSID_ALL);
#if !defined(CONFIG_YUEME) && !defined(CONFIG_CMCC) || defined(CONFIG_CU)
		va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "amsdu=0");
#endif
	}
	else {
		va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "ampdu=1");
		set_vap_para("set_mib", "ampdu=1", CONFIG_SSID_ALL);
#if !defined(CONFIG_YUEME) && !defined(CONFIG_CMCC) && !defined(CONFIG_CU)
		va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "amsdu=0");
#endif
	}
#if !defined(CONFIG_YUEME) && !defined(CONFIG_CMCC) && !defined(CONFIG_CU)
	set_vap_para("set_mib", "amsdu=0", CONFIG_SSID_ALL);
#endif

#if defined(CONFIG_YUEME)
	mib_get(MIB_WLAN_PHY_BAND_SELECT, (void *)&phyband);
	if(phyband == PHYBAND_5G) {
		va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "amsdu=2");
		set_vap_para("set_mib", "amsdu=2", CONFIG_SSID_ALL);
                //va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "countrystr=CN");
                va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "ldpc=1");
	}
	else{
		va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "amsdu=0");
		set_vap_para("set_mib", "amsdu=0", CONFIG_SSID_ALL);
                //va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "countrystr=US");
                va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "ldpc_92e=3");
	}
	va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "countrycode=1");
#elif defined(CONFIG_CMCC) || defined(CONFIG_CU)
	mib_get(MIB_WLAN_PHY_BAND_SELECT, (void *)&phyband);
	if(phyband == PHYBAND_5G) {
		va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "amsdu=2");
		set_vap_para("set_mib", "amsdu=2", CONFIG_SSID_ALL);
		va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "ldpc=3");
	}
	else{
		va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "amsdu=2");
		set_vap_para("set_mib", "amsdu=2", CONFIG_SSID_ALL);
		va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "ldpc_92e=3");
	}
	va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "txbf=1");
#endif

	if (wlan_mode == AP_MODE || wlan_mode == AP_WDS_MODE) {
		if (intf_map!=1) {
			va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "vap_enable=1");
		}
		else {
			va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "vap_enable=0");
		}
	}

#ifdef CONFIG_RTL_WAPI_SUPPORT
	mib_get(MIB_WLAN_WAPI_UCAST_REKETTYPE, (void *)&vChar);
	snprintf(parm, sizeof(parm), "wapiUCastKeyType=%d", vChar);
	status|=va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", parm);
	if (vChar!=1) {
		mib_get(MIB_WLAN_WAPI_UCAST_TIME, (void *)&vInt);
		snprintf(parm, sizeof(parm), "wapiUCastKeyTimeout=%d", vInt);
		status|=va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", parm);
		mib_get(MIB_WLAN_WAPI_UCAST_PACKETS, (void *)&vInt);
		snprintf(parm, sizeof(parm), "wapiUCastKeyPktNum=%d", vInt);
		status|=va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", parm);
	}
	

	mib_get(MIB_WLAN_WAPI_MCAST_REKEYTYPE, (void *)&vChar);
	snprintf(parm, sizeof(parm), "wapiMCastKeyType=%d", vChar);
	status|=va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", parm);
	if (vChar!=1) {
		mib_get(MIB_WLAN_WAPI_MCAST_TIME, (void *)&vInt);
		snprintf(parm, sizeof(parm), "wapiMCastKeyTimeout=%d", vInt);
		status|=va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", parm);
		mib_get(MIB_WLAN_WAPI_MCAST_PACKETS, (void *)&vInt);
		snprintf(parm, sizeof(parm), "wapiMCastKeyPktNum=%d", vInt);
		status|=va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", parm);
	}
#endif
//Note: supportedmcs is the rate we support, not to restrict only STAs with that rate can connect to us
#if 0 //def WLAN_RATE_PRIOR
	if(rate_prior==1){
		va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "supportedmcs=0xfff8");
		set_vap_para("set_mib", "supportedmcs=0xfff8", CONFIG_SSID_ALL);
	}
	else{
		va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "supportedmcs=0xffff");
		set_vap_para("set_mib", "supportedmcs=0xffff", CONFIG_SSID_ALL);
	}
#endif

	return status;
}

int setupWLanVap(config_wlan_ssid ssid_index)
{
	char *argv[6];
	unsigned char value[34], phyband;
	char parm[64], para2[15];
	int i, vInt, autoRate, autoRateRoot;
	unsigned char intf_map=1;
	unsigned char wlan_mode;
#ifdef WLAN_RATE_PRIOR
	unsigned char rate_prior=0;
#endif
	// Added by Mason Yu for Set TxPower
	char mode=0;
	int status=0;
	unsigned char stringbuf[MAX_SSID_LEN + 1];
	unsigned char rootSSID[MAX_SSID_LEN + 1];
	int j=0;
	MIB_CE_MBSSIB_T Entry;
	int intVal;
#ifdef WLAN_UNIVERSAL_REPEATER
	char rpt_enabled;
#endif

	// ifconfig wlan0 hw ether 00e04c867002
	/*if (mib_get(MIB_WLAN_MAC_ADDR, (void *)value) != 0)
	{
		snprintf(macaddr, 13, "%02x%02x%02x%02x%02x%02x",
			value[0], value[1], value[2], value[3], value[4], value[5]);
		argv[1]=(char *)WLANIF;
		argv[2]="hw";
		argv[3]="ether";
		argv[4]=macaddr;
		argv[5]=NULL;
		TRACE(STA_SCRIPT, "%s %s %s %s %s\n", IFCONFIG, argv[1], argv[2], argv[3], argv[4]);
		do_cmd(IFCONFIG, argv, 1);
	}*/

#ifdef WLAN_RATE_PRIOR	
	mib_get(MIB_WLAN_RATE_PRIOR, (void *)&rate_prior);
#endif

	if(!mib_chain_get(MIB_MBSSIB_TBL, 0, (void *)&Entry))
		printf("Error! Get MIB_MBSSIB_TBL for root SSID error.\n");

	wlan_mode = Entry.wlanMode;
#ifdef WLAN_UNIVERSAL_REPEATER
	mib_get( MIB_REPEATER_ENABLED1, (void *)&rpt_enabled);
#endif

#ifdef WLAN_MBSSID
	// VAP's SSID
	if (wlan_mode == AP_MODE || wlan_mode == AP_WDS_MODE) {
		for (j=1; j<=WLAN_MBSSID_NUM; j++) {
			
			if (!mib_chain_get(MIB_MBSSIB_TBL, j, (void *)&Entry)) {
  				printf("Error! Get MIB_MBSSIB_TBL for VAP SSID error.\n");
			}

			if (!Entry.wlanDisabled) {
				intf_map |= (1 << j);
			}

			if(ssid_index!=CONFIG_SSID_ALL && ssid_index!=j) {
				continue;
			}

 			//if ( Entry.wlanDisabled == 1 ) {
				snprintf(para2, sizeof(para2), "%s-vap%d", getWlanIfName(), j-1);
				snprintf(parm, sizeof(parm), "ssid=%s", Entry.ssid);
				status|=va_cmd(IWPRIV, 3, 1, para2, "set_mib", parm);
			//}
		}
		argv[1] = (char*)getWlanIfName();
	}
#endif
#ifdef WLAN_UNIVERSAL_REPEATER
	if (rpt_enabled) {
		if (!mib_chain_get(MIB_MBSSIB_TBL, WLAN_REPEATER_ITF_INDEX, (void *)&Entry)) {
  			printf("Error! Get MIB_MBSSIB_TBL for VXD SSID error.\n");
		}

		snprintf(para2, sizeof(para2), "%s-vxd", getWlanIfName());
		snprintf(parm, sizeof(parm), "ssid=%s", Entry.ssid);
		status|=va_cmd(IWPRIV, 3, 1, para2, "set_mib", parm);
		argv[1] = (char*)getWlanIfName();
	}
#endif

#ifdef WLAN_UNIVERSAL_REPEATER
	// Repeater opmode
	if (rpt_enabled) {
		if (wlan_mode == CLIENT_MODE)
			vInt = 16;	// Repeater is AP
		else
			vInt = 8;	// Repeater is Client
		snprintf(para2, sizeof(para2), "%s-vxd", getWlanIfName());
		status|=iwpriv_cmd(IWPRIV_INT, para2, "set_mib", "opmode", vInt);
		argv[1] = (char*)getWlanIfName();
	}
#endif

	// rtsthres
	mib_get(MIB_WLAN_RTS_THRESHOLD, (void *)value);
	vInt = (int)(*(unsigned short *)value);
	snprintf(parm, sizeof(parm), "rtsthres=%u", vInt);
	set_vap_para("set_mib", parm, ssid_index);

	// fragthres
	mib_get(MIB_WLAN_FRAG_THRESHOLD, (void *)value);
	vInt = (int)(*(unsigned short *)value);
	snprintf(parm, sizeof(parm), "fragthres=%u", vInt);
	set_vap_para("set_mib", parm, ssid_index);

#ifdef WLAN_ACL
#ifdef WLAN_MBSSID
	if (wlan_mode == AP_MODE || wlan_mode == AP_WDS_MODE) {
		for (j=1; j<=WLAN_MBSSID_NUM; j++){

			if(ssid_index!=CONFIG_SSID_ALL && ssid_index!=j) {
				continue;
			}
			
			snprintf(para2, sizeof(para2), "%s-vap%d", getWlanIfName(), j-1);
			status|=set_wlan_acl(para2);
		}
	}
#endif
#ifdef WLAN_UNIVERSAL_REPEATER
	if (wlan_mode != WDS_MODE) {
		if (rpt_enabled){
			snprintf(para2, sizeof(para2), "%s-vxd", getWlanIfName());
			status|=set_wlan_acl(para2);
		}
	}
#endif
#endif

#ifdef WLAN_MBSSID
	// VAP
	for (j=1; j<=WLAN_MBSSID_NUM; j++) {
		
		if(ssid_index!=CONFIG_SSID_ALL && ssid_index!=j) {
			continue;
		}
		
		setupWLan_dot11_auth(j);
		if (!mib_chain_get(MIB_MBSSIB_TBL, j, (void *)&Entry)) {
  			printf("Error! Get MIB_MBSSIB_TBL for VAP SSID error.\n");
		}

		snprintf(para2, sizeof(para2), "%s-vap%d", getWlanIfName(), j-1);
		argv[1] = para2;

		//for wifi-vap band
		value[0] = Entry.wlanBand;
#ifdef WIFI_TEST
		if (value[0] == 4) // WiFi-G
			value[0] = 3; // 2.4 GHz (B+G)
		else if (value[0] == 5) // WiFi-BG
			value[0] = 3; // 2.4 GHz (B+G)
#endif
		unsigned char vChar;
		mib_get(MIB_WIFI_SUPPORT, (void*)&vChar);
		if(vChar==1) {
			if(value[0] == 2)
				value[0] = 3;
		}
#ifdef WLAN_RATE_PRIOR
		if(rate_prior == 0){
#endif
			if (value[0] == 8) { //pure 11n
				mib_get(MIB_WLAN_PHY_BAND_SELECT, (void *)&phyband);
				if(phyband == PHYBAND_5G) {//5G
					value[0] += 4; // a
					vChar = 4;
				}
				else{
					value[0] += 3;	//b+g+n
					vChar = 3;
				}
			}
			else if (value[0] == 2) {	//pure 11g
				value[0] += 1;	//b+g
				vChar = 1;
			}
			else if (value[0] == 10) {	//g+n
				value[0] += 1;	//b+g+n
				vChar = 1;
			}
			else if(value[0] == 64) {	//pure 11ac
				value[0] += 12; 	//a+n
				vChar = 12;
			}
			else if(value[0] == 72) {	//n+ac
				value[0] += 4; 	//a
				vChar = 4;
			}		
			else vChar = 0;
#ifdef WLAN_RATE_PRIOR
		}
		else{
			mib_get(MIB_WLAN_PHY_BAND_SELECT, (void *)&phyband);
			if(phyband == PHYBAND_5G) {//5G
				value[0] = 76; //pure 11ac
				vChar = 12;
			}
			else{
				value[0] = 11;	//pure 11n
				vChar = 3;
			}	
		}
#endif
		
		status |= iwpriv_cmd(IWPRIV_INT, para2, "set_mib", "band", value[0]); //802.11b:1, 802.11g:2, 802.11n:8

		// for wifi-vap autorate
		value[0] = Entry.rateAdaptiveEnabled;
		autoRate = (int)value[0];
		status |=iwpriv_cmd(IWPRIV_INT, para2, "set_mib", "autorate", autoRate);

		if (autoRate == 0) 
			// for wifi-vap fixrate
			status |=iwpriv_cmd(IWPRIV_INT, para2, "set_mib", "fixrate", Entry.fixedTxRate);

		//for wifi-vap hidden AP
		status|=iwpriv_cmd(IWPRIV_INT, para2, "set_mib", "hiddenAP", Entry.hidessid);

		// for wifi-vap WMM
		status|=iwpriv_cmd(IWPRIV_INT, para2, "set_mib", "qos_enable", Entry.wmmEnabled);

		//for wifi-vap max block_relay
		status|=iwpriv_cmd(IWPRIV_INT, para2, "set_mib", "block_relay", Entry.userisolation);

		//deny legacy
		status|=iwpriv_cmd(IWPRIV_INT, para2, "set_mib", "deny_legacy", vChar);
		
#ifdef WLAN_LIMITED_STA_NUM
		status|=iwpriv_cmd(IWPRIV_INT, para2, "set_mib", "stanum", Entry.stanum);
#endif
		
		//txbf must disable if enable antenna diversity
#if defined(CONFIG_SLOT_0_ANT_SWITCH) || defined(CONFIG_SLOT_1_ANT_SWITCH) || defined(CONFIG_YUEME)
		status|=iwpriv_cmd(IWPRIV_INT, para2, "set_mib", "txbf", 0);
#endif
#if defined(CONFIG_YUEME)
		setup_wlan_accessRule_netfilter(para2, &Entry);
#endif

	}
	argv[1] = (char*)getWlanIfName();
#endif
#ifdef WLAN_UNIVERSAL_REPEATER
	if (rpt_enabled) {
		setupWLan_dot11_auth(WLAN_REPEATER_ITF_INDEX);
	}
#endif // of WLAN_UNIVERSAL_REPEATER

#ifdef WLAN_WPA
#ifdef WLAN_MBSSID
	// encmode
	for (j=1; j<=WLAN_MBSSID_NUM; j++) {

		if(ssid_index!=CONFIG_SSID_ALL && ssid_index!=j) {
			continue;
		}
		
		setupWLan_WPA(j);
#ifdef WLAN_11R
		setupWLan_FT(j);
#endif
#ifdef WLAN_11K
		setupWLan_dot11K(j);
#endif
#ifdef WLAN_11V
		setupWLan_dot11V(j);
#endif
	}
#endif
#ifdef WLAN_UNIVERSAL_REPEATER
	if (rpt_enabled)
		setupWLan_WPA(WLAN_REPEATER_ITF_INDEX);
#endif

#ifdef WLAN_MBSSID
	// Set 802.1x flag
	for (j=1; j<=WLAN_MBSSID_NUM; j++) {

		if(ssid_index!=CONFIG_SSID_ALL && ssid_index!=j) {
			continue;
		}
		
		setupWLan_802_1x(j); // VAP
	}
#endif
#ifdef WLAN_UNIVERSAL_REPEATER
	if (rpt_enabled)
		setupWLan_802_1x(WLAN_REPEATER_ITF_INDEX); // Repeater
#endif

#endif // of WLAN_WPA

	if(!mib_chain_get(MIB_MBSSIB_TBL, 0, (void *)&Entry))
		printf("Error! Get MIB_MBSSIB_TBL for root SSID error.\n");
	// band
	value [0] = Entry.wlanBand;
#ifdef WIFI_TEST
	if (value[0] == 4) // WiFi-G
		value[0] = 3; // 2.4 GHz (B+G)
	else if (value[0] == 5) // WiFi-BG
		value[0] = 3; // 2.4 GHz (B+G)
#endif
	//jim do wifi test tricky,
	//    1 for wifi logo test,
	//    0 for normal case...
	unsigned char vChar;
	mib_get(MIB_WIFI_SUPPORT, (void*)&vChar);
	if(vChar==1){
		if(value[0] == 2)
			value[0] = 3;
	}

#ifdef WLAN_RATE_PRIOR
	if(rate_prior == 0){
#endif
		if(value[0] == 8) {	//pure 11n
			mib_get(MIB_WLAN_PHY_BAND_SELECT, (void *)&phyband);
			if(phyband == PHYBAND_5G) {//5G
				value[0] += 4; // a
				vChar = 4;
			}
			else{
				value[0] += 3;	//b+g+n
				vChar = 3;
			}
		}
		else if(value[0] == 2) {	//pure 11g
			value[0] += 1;	//b+g
			vChar = 1;
		}
		else if(value[0] == 10) {	//g+n
			value[0] += 1; 	//b+g+n
			vChar = 1;
		}
		else if(value[0] == 64) {	//pure 11ac
			value[0] += 12; 	//a+n
			vChar = 12;
		}
		else if(value[0] == 72) {	//n+ac
			value[0] += 4; 	//a
			vChar = 4;
		}
		else vChar = 0;
#ifdef WLAN_RATE_PRIOR
	}
	else{
		mib_get(MIB_WLAN_PHY_BAND_SELECT, (void *)&phyband);
		if(phyband == PHYBAND_5G) {//5G
			value[0] = 76; //pure 11ac
			vChar = 12;
		}
		else{
			value[0] = 11;	//pure 11n
			vChar = 3;
		}	
	}
#endif
	set_vap_para("set_mib","lgyEncRstrct=15", ssid_index);

	// For WiFi Test Plan. Added by Annie, 2010-06-29.
	set_vap_para("set_mib","wifi_specific=2", ssid_index);
//cathy, for multicast rate
#ifdef CONFIG_USB_RTL8187SU_SOFTAP
	mib_get(MIB_WLAN_MLCSTRATE, (void *)value);
	vInt = (int)(*(unsigned short *)value);
	snprintf(parm, sizeof(parm), "lowestMlcstRate=%u", vInt);
	set_vap_para("set_mib", parm, ssid_index);
#endif

#ifdef WLAN_WDS
	setupWDS();
#endif

//12/23/04' hrchen, these MIBs are for CLIENT mode, disable them
#if 0
	//12/16/04' hrchen, disable nat25_disable
	// nat25_disable
	value[0] = 0;
	sprintf(parm, "nat25_disable=%u", value[0]);
	argv[3] = parm;
	argv[4] = NULL;
	TRACE(STA_SCRIPT, "%s %s %s %s\n", IWPRIV, argv[1], argv[2], argv[3]);
	status|=do_cmd(IWPRIV, argv, 1);

	//12/16/04' hrchen, disable macclone_enable
	// macclone_enable
	value[0] = 0;
	sprintf(parm, "macclone_enable=%u", value[0]);
	argv[3] = parm;
	argv[4] = NULL;
	TRACE(STA_SCRIPT, "%s %s %s %s\n", IWPRIV, argv[1], argv[2], argv[3]);
	status|=do_cmd(IWPRIV, argv, 1);
#endif

#if 0
	//12/16/04' hrchen, debug flag
	// debug_err
	sprintf(parm, "debug_err=ffffffff");
	argv[3] = parm;
	argv[4] = NULL;
	TRACE(STA_SCRIPT, "%s %s %s %s\n", IWPRIV, argv[1], argv[2], argv[3]);
	status|=do_cmd(IWPRIV, argv, 1);
	// debug_info
	sprintf(parm, "debug_info=0");
	argv[3] = parm;
	argv[4] = NULL;
	TRACE(STA_SCRIPT, "%s %s %s %s\n", IWPRIV, argv[1], argv[2], argv[3]);
	status|=do_cmd(IWPRIV, argv, 1);
	// debug_warn
	sprintf(parm, "debug_warn=0");
	argv[3] = parm;
	argv[4] = NULL;
	TRACE(STA_SCRIPT, "%s %s %s %s\n", IWPRIV, argv[1], argv[2], argv[3]);
	status|=do_cmd(IWPRIV, argv, 1);
	// debug_trace
	sprintf(parm, "debug_trace=0");
	argv[3] = parm;
	argv[4] = NULL;
	TRACE(STA_SCRIPT, "%s %s %s %s\n", IWPRIV, argv[1], argv[2], argv[3]);
	status|=do_cmd(IWPRIV, argv, 1);
#endif

	//12/16/04' hrchen, set 11g protection mode
	// disable_protection
	mib_get(MIB_WLAN_PROTECTION_DISABLED, (void *)value);
	snprintf(parm, sizeof(parm), "disable_protection=%u", value[0]);
	set_vap_para("set_mib", parm, ssid_index);

	//12/16/04' hrchen, chipVersion
	// chipVersion
	/*
	sprintf(parm, "chipVersion=0");
	argv[3] = parm;
	argv[4] = NULL;
	TRACE(STA_SCRIPT, "%s %s %s %s\n", IWPRIV, argv[1], argv[2], argv[3]);
	status|=do_cmd(IWPRIV, argv, 1);
	*/

#if 0	// not necessary for AP
	//12/16/04' hrchen, defssid
	// defssid
	sprintf(parm, "defssid=\"defaultSSID\"");
	argv[3] = parm;
	argv[4] = NULL;
	TRACE(STA_SCRIPT, "%s %s %s %s\n", IWPRIV, argv[1], argv[2], argv[3]);
	status|=do_cmd(IWPRIV, argv, 1);
#endif

#ifdef WLAN_RATE_PRIOR
	if(rate_prior==0){
#endif
		//Channel Width
		mib_get(MIB_WLAN_CHANNEL_WIDTH, (void *)value);
		if(value[0]==0)	// 20MHZ
		{
			set_vap_para("set_mib", "use40M=0", ssid_index);
		}
		else if(value[0]==1)	// 40MHZ
		{
			set_vap_para("set_mib", "use40M=1", ssid_index);
		}
		else	// 80MHZ
		{
			set_vap_para("set_mib", "use40M=2", ssid_index);
		}
#ifdef WLAN_RATE_PRIOR
	}
	else{
		mib_get(MIB_WLAN_PHY_BAND_SELECT, (void *)&phyband);
		if(phyband == PHYBAND_5G) {//80Mz
			set_vap_para("set_mib", "use40M=2", ssid_index);
		}
		else{
			set_vap_para("set_mib", "use40M=1", ssid_index);
		}	
	}
#endif
	//Conntrol Sideband
	if(value[0]==0) {	//20M
		set_vap_para("set_mib", "2ndchoffset=0", ssid_index);
	}
	else {	//40M
		mib_get(MIB_WLAN_CONTROL_BAND, (void *)value);
		if(value[0]==0){	//upper
			set_vap_para("set_mib", "2ndchoffset=1", ssid_index);
		}
		else{		//lower
			set_vap_para("set_mib", "2ndchoffset=2", ssid_index);
		}
#if defined(CONFIG_WLAN_HAL_8814AE) || defined (CONFIG_RTL_8812_SUPPORT) || defined(WLAN_DUALBAND_CONCURRENT)
		mib_get(MIB_WLAN_AUTO_CHAN_ENABLED, &vChar);
		mib_get(MIB_WLAN_CHAN_NUM, (void *)value);
		if(vChar == 0 && value[0] > 14)
		{
			printf("!!! adjust 5G 2ndoffset for 8812 !!!\n");
			if(value[0]==36 || value[0]==44 || value[0]==52 || value[0]==60){
				set_vap_para("set_mib", "2ndchoffset=2", ssid_index);
			}
			else{
				set_vap_para("set_mib", "2ndchoffset=1", ssid_index);
			}
		}
#endif
	}
#ifdef WLAN_RATE_PRIOR
	if(rate_prior==0){
#endif
		//11N Co-Existence
		mib_get(MIB_WLAN_11N_COEXIST, (void *)value);
		if(value[0]==0)
		{
			set_vap_para("set_mib", "coexist=0", ssid_index);
		}
		else
		{
			set_vap_para("set_mib", "coexist=1", ssid_index);

		}
#ifdef WLAN_RATE_PRIOR
	}
	else{
		mib_get(MIB_WLAN_PHY_BAND_SELECT, (void *)&phyband);
		if(phyband == PHYBAND_2G) {
			set_vap_para("set_mib", "coexist=1", ssid_index);
		}
	}
#endif

	//short GI
#ifndef CONFIG_YUEME
	mib_get(MIB_WLAN_SHORTGI_ENABLED, (void *)value);
	if(value[0]==0) {
		set_vap_para("set_mib", "shortGI20M=0", ssid_index);
		set_vap_para("set_mib", "shortGI40M=0", ssid_index);
		set_vap_para("set_mib", "shortGI80M=0", ssid_index);
	}
	else {
#endif
		set_vap_para("set_mib", "shortGI20M=1", ssid_index);
		set_vap_para("set_mib", "shortGI40M=1", ssid_index);
		set_vap_para("set_mib", "shortGI80M=1", ssid_index);
#ifndef CONFIG_YUEME
	}
#endif

	//aggregation
	mib_get(MIB_WLAN_AGGREGATION, (void *)value);
	if(value[0]==0) {
		set_vap_para("set_mib", "ampdu=0", ssid_index);
	}
	else {
		set_vap_para("set_mib", "ampdu=1", ssid_index);
	}
#if !defined(CONFIG_YUEME) && !defined(CONFIG_CMCC) && !defined(CONFIG_CU)
	set_vap_para("set_mib", "amsdu=0", ssid_index);
#endif

#if defined(CONFIG_YUEME) || defined(CONFIG_CMCC) || defined(CONFIG_CU)
	mib_get(MIB_WLAN_PHY_BAND_SELECT, (void *)&phyband);
	if(phyband == PHYBAND_5G) {
		set_vap_para("set_mib", "amsdu=2", ssid_index);
	}
	else{
		set_vap_para("set_mib", "amsdu=0", ssid_index);
	}
#endif
	
//Note: supportedmcs is the rate we support, not to restrict only STAs with that rate can connect to us
#if 0 //def WLAN_RATE_PRIOR
		if(rate_prior==1){
			set_vap_para("set_mib", "supportedmcs=0xfff8", ssid_index);
		}
		else{
			set_vap_para("set_mib", "supportedmcs=0xffff", ssid_index);
		}
#endif

	if (wlan_mode == AP_MODE || wlan_mode == AP_WDS_MODE) {
		if (intf_map!=1) {
			va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "vap_enable=1");
		}
		else {
			va_cmd(IWPRIV, 3, 1, (char *)getWlanIfName(), "set_mib", "vap_enable=0");
		}
	}

	return status;
}
#endif

unsigned int check_wlan_module(void)
{
	unsigned char vChar;
#ifdef YUEME_3_0_SPEC
	mib_local_mapping_get(MIB_WLAN_DISABLED, 0, (void *)&vChar);
	//if you want to check wlan1 please add following mib get and do your checking
	//you should avoid to use this function for YUEME 3.0 spec since wlan0/1 can be enable separately
	//mib_local_mapping_get(MIB_WLAN_DISABLED, 1, (void *)&vChar);
	//todo
#else
	mib_get(MIB_WIFI_MODULE_DISABLED, (void *)&vChar);
#endif
	if(vChar)
		return 0;
	else
		return 1;
}

// Added by Mason Yu
int stopwlan(config_wlan_target target, config_wlan_ssid ssid_index)
{
	int status = 0;
	int wirelessauthpid=0,iwcontrolpid=0, wscdpid=0, upnppid=0, run_mini_upnpd = 0;
#ifdef WLAN_11R
	int ftpid=0;
#endif
#ifdef WLAN_SMARTAPP_ENABLE
	int smart_wlanapp_pid=0;
#endif
	int AuthPid;
	int i,j, flags;
	unsigned char no_wlan;
	char s_auth_pid[32], s_auth_conf[32], s_auth_fifo[32];
#ifdef WLAN_11K
	int dot11kPid;
	char s_dot11k_pid[64];
#endif
	char s_ifname[16];
	char *argv[7];
#ifdef	WLAN_MBSSID
	MIB_CE_MBSSIB_T Entry;
#endif
#ifdef CONFIG_WIFI_SIMPLE_CONFIG
	char wscd_pid_name[32];
	char wscd_fifo_name[32];
#ifdef WLAN_WPS_VAP
	char wscd_conf_name[32];
#endif
#endif
	int orig_wlan_idx;
	unsigned char phy_band_select;

	orig_wlan_idx = wlan_idx;

	// Kill iwcontrol
#if defined(CONFIG_USER_MONITORD) && defined(CONFIG_YUEME)
	update_monitor_list_file("iwcontrol", 0);
#endif
	iwcontrolpid = read_pid((char*)IWCONTROLPID);
	if(iwcontrolpid > 0){
		kill(iwcontrolpid, 9);
		unlink(IWCONTROLPID);
	}

	// Kill Auth
	for(j=0;j<NUM_WLAN_INTERFACE;j++){
			wlan_idx = j;
        	mib_get( MIB_WLAN_PHY_BAND_SELECT, (void *)&phy_band_select);
        	if((target == CONFIG_WLAN_2G && phy_band_select == PHYBAND_5G)
        	|| (target == CONFIG_WLAN_5G && phy_band_select == PHYBAND_2G)) {
				continue;
        	}
        	for ( i=0; i<=NUM_VWLAN_INTERFACE; i++) {
        		if (i==0) {
					if(ssid_index == CONFIG_SSID_ALL || ssid_index == CONFIG_SSID_ROOT) {
	                    snprintf(s_ifname, sizeof(s_ifname), WLANIF[j]);
	        			snprintf(s_auth_pid, 32, "/var/run/auth-%s.pid", (char *)s_ifname);
	        			snprintf(s_auth_conf, 32, "/var/config/%s.conf", (char *)s_ifname);
	        			snprintf(s_auth_fifo, 32, "/var/auth-%s.fifo", (char *)s_ifname);
#ifdef WLAN_WPS_VAP
						snprintf(wscd_pid_name, 32, "/var/run/wscd-%s.pid", (char *)s_ifname);
	        			snprintf(wscd_conf_name, 32, "/var/wscd-%s.conf", (char *)s_ifname);
	        			snprintf(wscd_fifo_name, 32, "/var/wscd-%s.fifo", (char *)s_ifname);
#endif
#ifdef WLAN_11K
	        			snprintf(s_dot11k_pid, 64, "/var/run/dot11k-%s.pid", (char *)s_ifname);
#endif
					}
        		}
        		#ifdef	WLAN_MBSSID
        		if (i >= WLAN_VAP_ITF_INDEX && i < WLAN_VAP_ITF_INDEX+WLAN_MBSSID_NUM) {
					if(ssid_index == CONFIG_SSID_ALL || ssid_index == (i-WLAN_VAP_ITF_INDEX+1)) {
	                    snprintf(s_ifname, sizeof(s_ifname), "%s-vap", WLANIF[j]);
	        			snprintf(s_auth_pid, 32, "/var/run/auth-%s%d.pid", (char *)s_ifname, i-WLAN_VAP_ITF_INDEX);
	        			snprintf(s_auth_conf, 32, "/var/config/%s%d.conf", (char *)s_ifname, i-WLAN_VAP_ITF_INDEX);
	        			snprintf(s_auth_fifo, 32, "/var/auth-%s%d.fifo", (char *)s_ifname, i-WLAN_VAP_ITF_INDEX);
#ifdef WLAN_WPS_VAP
					snprintf(wscd_pid_name, 32, "/var/run/wscd-%s%d.pid", (char *)s_ifname, i-WLAN_VAP_ITF_INDEX);
	        			snprintf(wscd_conf_name, 32, "/var/wscd-%s%d.conf", (char *)s_ifname, i-WLAN_VAP_ITF_INDEX);
	        			snprintf(wscd_fifo_name, 32, "/var/wscd-%s%d.fifo", (char *)s_ifname, i-WLAN_VAP_ITF_INDEX);
#endif
#ifdef WLAN_11K
	        			snprintf(s_dot11k_pid, 64, "/var/run/dot11k-%s%d.pid", (char *)s_ifname, i-WLAN_VAP_ITF_INDEX);
#endif
					}
        		}
        		#endif
        		#ifdef WLAN_UNIVERSAL_REPEATER
        		if (i == WLAN_REPEATER_ITF_INDEX) {
                            snprintf(s_ifname, sizeof(s_ifname), "%s-vxd", WLANIF[j]);
        			snprintf(s_auth_pid, 32, "/var/run/auth-%s.pid", (char *)s_ifname);
        			snprintf(s_auth_conf, 32, "/var/config/%s.conf", (char *)s_ifname);
        			snprintf(s_auth_fifo, 32, "/var/auth-%s.fifo", (char *)s_ifname);
#ifdef WLAN_WPS_VAP
				snprintf(wscd_pid_name, 32, "/var/run/wscd-%s.pid", (char *)s_ifname);
        			snprintf(wscd_conf_name, 32, "/var/wscd-%s.conf", (char *)s_ifname);
        			snprintf(wscd_fifo_name, 32, "/var/wscd-%s.fifo", (char *)s_ifname);
#endif
#ifdef WLAN_11K
        			snprintf(s_dot11k_pid, 64, "/var/run/dot11k-%s.pid", (char *)s_ifname);
#endif
        		}
        		#endif
        		AuthPid = read_pid(s_auth_pid);
        		if(AuthPid > 0) {
        			kill(AuthPid, 9);
        			unlink(s_auth_conf);
        			unlink(s_auth_pid);
        			unlink(s_auth_fifo);
        		}
#ifdef WLAN_WPS_VAP
			wscdpid = read_pid(wscd_pid_name);
        		if(wscdpid > 0) {
					system("/bin/echo 0 > /proc/gpio");
        			kill(wscdpid, 9);
        			unlink(wscd_conf_name);
        			unlink(wscd_pid_name);
        			unlink(wscd_fifo_name);
        		}
#endif				
#ifdef WLAN_11K
			dot11kPid = read_pid(s_dot11k_pid);
			if(dot11kPid > 0)
				kill(dot11kPid, 9);
#endif
        	}
	}

#ifdef WLAN_SUPPORT
#ifdef WLAN_11R
	ftpid = read_pid(FT_PID);
	if(ftpid > 0) {
		kill(ftpid, 9);
		unlink(FT_PID);
		unlink(FT_CONF);
	}
#endif
#ifdef WLAN_SMARTAPP_ENABLE
	smart_wlanapp_pid = read_pid(SMART_WLANAPP_PID);
	if(smart_wlanapp_pid > 0) {
		kill(smart_wlanapp_pid, 9);
		unlink(SMART_WLANAPP_PID);
	}
#endif
#ifdef CONFIG_WIFI_SIMPLE_CONFIG // WPS
#ifndef WLAN_WPS_VAP
	// Kill wscd-wlan0.pid
	getWscPidName(wscd_pid_name);
	wscdpid = read_pid(wscd_pid_name);
	if(wscdpid > 0){
		system("/bin/echo 0 > /proc/gpio");
		kill(wscdpid, 9);
		unlink(wscd_pid_name);
		unlink(wscd_fifo_name);
		unlink(WSCD_CONF);
	}
#endif
	startSSDP();

#endif
#endif

	RTK_RG_Reset_SSID_shaping_rule();

#ifdef CONFIG_RTL_WAPI_SUPPORT
		system("killall aeUdpClient");
#endif // WAPI


        for(j=0;j<NUM_WLAN_INTERFACE;j++){
        	wlan_idx = j;
        	mib_get( MIB_WLAN_PHY_BAND_SELECT, (void *)&phy_band_select);
        	if((target == CONFIG_WLAN_2G && phy_band_select == PHYBAND_5G)
        	|| (target == CONFIG_WLAN_5G && phy_band_select == PHYBAND_2G)) {
				continue;
        	}
        	for ( i=0; i<=NUM_VWLAN_INTERFACE; i++) {
        		if (i==0){
					
					if(ssid_index != CONFIG_SSID_ALL && ssid_index != CONFIG_SSID_ROOT) {
						continue;
					}
					
                    snprintf(s_ifname, sizeof(s_ifname), "%s", WLANIF[j]);
        		}
        		#ifdef	WLAN_MBSSID
        		if (i >= WLAN_VAP_ITF_INDEX && i < WLAN_VAP_ITF_INDEX+WLAN_MBSSID_NUM) {

					if(ssid_index != CONFIG_SSID_ALL && ssid_index != (i-WLAN_VAP_ITF_INDEX+1)) {
						continue;
					}
					
                	snprintf(s_ifname, sizeof(s_ifname), "%s-vap%d", WLANIF[j], i-WLAN_VAP_ITF_INDEX);
        		}
        		#endif
        		#ifdef WLAN_UNIVERSAL_REPEATER
        		if (i == WLAN_REPEATER_ITF_INDEX)
                            snprintf(s_ifname, sizeof(s_ifname), "%s-vxd", WLANIF[j]);
        		#endif
        		if (getInFlags( s_ifname, &flags) == 1){
        			if (flags & IFF_UP){
        				status |= va_cmd(IFCONFIG, 2, 1, s_ifname, "down");
				#if defined(CONFIG_MASTER_WLAN0_ENABLE) && defined(CONFIG_SLAVE_WLAN1_ENABLE)
						if( strncmp(s_ifname, "wlan1", 5) || !strcmp(s_ifname, "wlan1"))
				#elif defined(CONFIG_SLAVE_WLAN1_ENABLE)
						if(!strcmp(s_ifname, WLANIF[0]))
				#endif
        				status|=va_cmd(BRCTL, 3, 1, "delif", (char *)BRIF, s_ifname);
        			}
        		}
        	}
        }
#ifdef WLAN_WISP
	int dhcp_pid;
	unsigned char value[32];
	char itf_name[IFNAMSIZ];
	getWispWanName(itf_name);
	//snprintf(value, 32, "%s.%s", (char*)DHCPC_PID, "wlan0");
	snprintf(value, 32, "%s.%s", (char*)DHCPC_PID, itf_name);
	dhcp_pid = read_pid((char*)value);
	if(dhcp_pid > 0){
		kill(dhcp_pid, SIGUSR1); //dhcp new
	}
#endif
	wlan_idx = orig_wlan_idx;
}

#define ConfigWlanLock "/var/run/configWlanLock"
#define LOCK_WLAN()	\
do {	\
	if ((lockfd = open(ConfigWlanLock, O_RDWR)) == -1) {	\
		perror("open wlan lockfile");	\
		return 0;	\
	}	\
	while (flock(lockfd, LOCK_EX)) { \
		if (errno != EINTR) \
			break; \
	}	\
} while (0)

#define UNLOCK_WLAN()	\
do {	\
	flock(lockfd, LOCK_UN);	\
	close(lockfd);	\
} while (0)


char* config_WLAN_action_type_to_str( int action_type, config_wlan_ssid ssid_index, char *ret )
{
	char action_type_str[128] = {0};
	char ssid_index_str[128] = {0};
	char band_type_str[32] = {0};
	
	switch( action_type )
	{
		case ACT_START:
#ifdef WLAN_DUALBAND_CONCURRENT
			sprintf(action_type_str, "WLAN start 2G+5G");
#else
			sprintf(action_type_str, "WLAN start");
#endif
			break;
		case ACT_RESTART:
#ifdef WLAN_DUALBAND_CONCURRENT
			sprintf(action_type_str, "WLAN restart 2G+5G");
#else
			sprintf(action_type_str, "WLAN restart");
#endif
			break;
		case ACT_STOP:
#ifdef WLAN_DUALBAND_CONCURRENT
			sprintf(action_type_str, "WLAN stop 2G+5G");
#else
			sprintf(action_type_str, "WLAN stop");
#endif
			break;
		case ACT_START_2G:
			sprintf(action_type_str, "WLAN start 2G");
			sprintf(band_type_str, "2G");
			break;
		case ACT_RESTART_2G:
			sprintf(action_type_str, "WLAN restart 2G");
			sprintf(band_type_str, "2G");
			break;
		case ACT_STOP_2G:
			sprintf(action_type_str, "WLAN stop 2G");
			sprintf(band_type_str, "2G");
			break;
		case ACT_START_5G:
			sprintf(action_type_str, "WLAN start 5G");
			sprintf(band_type_str, "5G");
			break;
		case ACT_RESTART_5G:
			sprintf(action_type_str, "WLAN restart 5G");
			sprintf(band_type_str, "5G");
			break;
		case ACT_STOP_5G:
			sprintf(action_type_str, "WLAN stop 5G");
			sprintf(band_type_str, "5G");
			break;			
#if defined(CONFIG_CMCC) || defined(CONFIG_CU) || defined(CONFIG_CU)
		case ACT_RESTART_AND_WPS:
			sprintf(action_type_str, "WLAN restart 2G+5G+WPS");
			break;
		case ACT_RESTART_WPS:
			sprintf(action_type_str, "WLAN restart WPS");
			break;
#endif
		default:
			sprintf(ret, "Invalid action_type !");
			return ret;
	}

	switch( ssid_index )
	{
		case CONFIG_SSID_ROOT:
			sprintf(ssid_index_str, "root (%s-1)", band_type_str);
			break;
		case CONFIG_SSID1:
		case CONFIG_SSID2:
		case CONFIG_SSID3:
		case CONFIG_SSID4:
		case CONFIG_SSID5:
		case CONFIG_SSID6:
		case CONFIG_SSID7:
			sprintf(ssid_index_str, "vap%d (%s-%d)", ssid_index-1, band_type_str, ssid_index+1);
			break;
		case CONFIG_SSID_ALL:
			sprintf(ssid_index_str, "all");
			break;
		default:
			sprintf(ret, "Invalid ssid_index !");
			return ret;
	}

	sprintf(ret, "%s %s", action_type_str, ssid_index_str);
	return ret;
	
}

int config_WLAN( int action_type, config_wlan_ssid ssid_index )
{
	int lockfd, orig_wlan_idx;
	char action_type_str[128] = {0};

	LOCK_WLAN();	
	AUG_PRT("%s %s\n", __func__, config_WLAN_action_type_to_str(action_type, ssid_index, action_type_str));
	syslog(LOG_INFO, "%s", config_WLAN_action_type_to_str(action_type, ssid_index, action_type_str));
	orig_wlan_idx = wlan_idx;
	switch( action_type )
	{
	case ACT_START:
		startWLan(CONFIG_WLAN_ALL, CONFIG_SSID_ALL);
#ifdef CONFIG_USER_FON
		startFonSpot();
#endif
		break;

	case ACT_RESTART:
		stopwlan(CONFIG_WLAN_ALL, CONFIG_SSID_ALL);
		startWLan(CONFIG_WLAN_ALL, CONFIG_SSID_ALL);
		break;

	case ACT_STOP:
		stopwlan(CONFIG_WLAN_ALL, CONFIG_SSID_ALL);
		break;

	case ACT_START_2G:
		startWLan(CONFIG_WLAN_2G, ssid_index);
		break;

	case ACT_RESTART_2G:
		stopwlan(CONFIG_WLAN_2G, ssid_index);
		startWLan(CONFIG_WLAN_2G, ssid_index);
		break;

	case ACT_STOP_2G:
		stopwlan(CONFIG_WLAN_2G, ssid_index);
		break;

	case ACT_START_5G:
		startWLan(CONFIG_WLAN_5G, ssid_index);
		break;

	case ACT_RESTART_5G:
		stopwlan(CONFIG_WLAN_5G, ssid_index);
		startWLan(CONFIG_WLAN_5G, ssid_index);
		break;

	case ACT_STOP_5G:
		stopwlan(CONFIG_WLAN_5G, ssid_index);
		break;
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		case ACT_RESTART_AND_WPS:
			stopwlan(CONFIG_WLAN_ALL, CONFIG_SSID_ALL);
			startWLan(CONFIG_WLAN_ALL, CONFIG_SSID_ALL);
			va_cmd("/bin/wscd", 3, 1, "-sig_pbc",getWlanIfName());
			printf("trigger PBC to %s\n",getWlanIfName());
			break;
#ifdef WLAN_WPS_VAP
		case ACT_RESTART_WPS:
			UNLOCK_WLAN();
			restartWPS(0);
			LOCK_WLAN();
			va_cmd("/bin/wscd", 3, 1, "-sig_pbc",getWlanIfName());
			printf("trigger PBC to %s\n",getWlanIfName());
			break;
#endif
#endif
	default:
		wlan_idx = orig_wlan_idx;
		UNLOCK_WLAN();
		return -1;
	}
	wlan_idx = orig_wlan_idx;
	UNLOCK_WLAN();
	return 0;
}

unsigned char get_wlan_phyband(void)
{
	unsigned char phyband=PHYBAND_2G;
#ifdef WLAN_DUALBAND_CONCURRENT
	mib_get(MIB_WLAN_PHY_BAND_SELECT, &phyband);
#endif
	return phyband;
}

// Wlan configuration
#ifdef WLAN_1x
static void WRITE_WPA_FILE(int fh, unsigned char *buf)
{
	if ( write(fh, buf, strlen(buf)) != strlen(buf) ) {
		printf("Write WPA config file error!\n");
		close(fh);
		//exit(1);
	}
}

// return value:
// 0  : success
// -1 : failed
#ifdef _PRMT_X_WLANFORISP_
static int generateWpaConf(char *outputFile, int isWds, MIB_CE_MBSSIB_T *Entry, MIB_WLANFORISP_T *wlan_isp_entry)
#else
static int generateWpaConf(char *outputFile, int isWds, MIB_CE_MBSSIB_T *Entry)
#endif
{
	int fh, intVal;
	unsigned char chVal, wep, encrypt, enable1x;
	unsigned char buf1[1024], buf2[1024];
	unsigned short sintVal;

	fh = open(outputFile, O_RDWR|O_CREAT|O_TRUNC);
	if (fh == -1) {
		printf("Create WPA config file error!\n");
		return -1;
	}
	if (!isWds) {

	encrypt = Entry->encrypt;
	snprintf(buf2, sizeof(buf2), "encryption = %d\n", encrypt);
	WRITE_WPA_FILE(fh, buf2);

	strcpy(buf1, Entry->ssid);
	snprintf(buf2, sizeof(buf2), "ssid = \"%s\"\n", buf1);
	WRITE_WPA_FILE(fh, buf2);

	enable1x = Entry->enable1X;
	snprintf(buf2, sizeof(buf2), "enable1x = %d\n", enable1x);
	WRITE_WPA_FILE(fh, buf2);

	//mib_get( MIB_WLAN_ENABLE_MAC_AUTH, (void *)&intVal);
	snprintf(buf2, sizeof(buf2), "enableMacAuth = %d\n", 0);
	WRITE_WPA_FILE(fh, buf2);

/*
	mib_get( MIB_WLAN_ENABLE_SUPP_NONWPA, (void *)&intVal);
	if (intVal)
		mib_get( MIB_WLAN_SUPP_NONWPA, (void *)&intVal);
*/

	snprintf(buf2, sizeof(buf2), "supportNonWpaClient = %d\n", 0);
	WRITE_WPA_FILE(fh, buf2);

	wep = Entry->wep;
	snprintf(buf2, sizeof(buf2), "wepKey = %d\n", wep);
	WRITE_WPA_FILE(fh, buf2);

/*
	if ( encrypt==1 && enable1x ) {
		if (wep == 1) {
			mib_get( MIB_WLAN_WEP64_KEY1, (void *)buf1);
			sprintf(buf2, "wepGroupKey = \"%02x%02x%02x%02x%02x\"\n", buf1[0],buf1[1],buf1[2],buf1[3],buf1[4]);
		}
		else {
			mib_get( MIB_WLAN_WEP128_KEY1, (void *)buf1);
			sprintf(buf2, "wepGroupKey = \"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\"\n",
				buf1[0],buf1[1],buf1[2],buf1[3],buf1[4],
				buf1[5],buf1[6],buf1[7],buf1[8],buf1[9],
				buf1[10],buf1[11],buf1[12]);
		}
	}
	else
*/
	strcpy(buf2, "wepGroupKey = \"\"\n");
	WRITE_WPA_FILE(fh, buf2);


#ifdef WLAN_11R
	if (Entry->wpaAuth == 1 && Entry->ft_enable)
		chVal = 3;
	else
#endif
	chVal = Entry->wpaAuth;
	snprintf(buf2, sizeof(buf2), "authentication = %d\n", chVal); //1: radius 2:PSK 3:FT
	WRITE_WPA_FILE(fh, buf2);

	chVal = Entry->unicastCipher;
	snprintf(buf2, sizeof(buf2), "unicastCipher = %d\n", chVal);
	WRITE_WPA_FILE(fh, buf2);

	chVal = Entry->wpa2UnicastCipher;
	snprintf(buf2, sizeof(buf2), "wpa2UnicastCipher = %d\n", chVal);
	WRITE_WPA_FILE(fh, buf2);

/*
	mib_get( MIB_WLAN_WPA2_PRE_AUTH, (void *)&intVal);
	sprintf(buf2, "enablePreAuth = %d\n", intVal);
	WRITE_WPA_FILE(fh, buf2);
*/

	chVal = Entry->wpaPSKFormat;
	if (chVal==0)
		snprintf(buf2, sizeof(buf2), "usePassphrase = 1\n");
	else
		snprintf(buf2, sizeof(buf2), "usePassphrase = 0\n");
	WRITE_WPA_FILE(fh, buf2);


	strcpy(buf1, Entry->wpaPSK);
	snprintf(buf2, sizeof(buf2), "psk = \"%s\"\n", buf1);
	WRITE_WPA_FILE(fh, buf2);

	mib_get( MIB_WLAN_WPA_GROUP_REKEY_TIME, (void *)&intVal);
	snprintf(buf2, sizeof(buf2), "groupRekeyTime = %d\n", intVal);
	WRITE_WPA_FILE(fh, buf2);

#if 1 // not support RADIUS

	sintVal = Entry->rsPort;
	snprintf(buf2, sizeof(buf2), "rsPort = %d\n", sintVal);
	WRITE_WPA_FILE(fh, buf2);

	*((unsigned long *)buf1) = *((unsigned long *)Entry->rsIpAddr);
	snprintf(buf2, sizeof(buf2), "rsIP = %s\n", inet_ntoa(*((struct in_addr *)buf1)));
	WRITE_WPA_FILE(fh, buf2);

	strcpy(buf1, Entry->rsPassword);
	snprintf(buf2, sizeof(buf2), "rsPassword = \"%s\"\n", buf1);
	WRITE_WPA_FILE(fh, buf2);

	mib_get( MIB_WLAN_RS_RETRY, (void *)&chVal);
	snprintf(buf2, sizeof(buf2), "rsMaxReq = %d\n", chVal);
	WRITE_WPA_FILE(fh, buf2);

	mib_get( MIB_WLAN_RS_INTERVAL_TIME, (void *)&sintVal);
	snprintf(buf2, sizeof(buf2), "rsAWhile = %d\n", sintVal);
	WRITE_WPA_FILE(fh, buf2);

#ifdef _PRMT_X_WLANFORISP_
	snprintf(buf2, sizeof(buf2), "accountRsEnabled = %d\n", wlan_isp_entry->RadiusAccountEnable);
	WRITE_WPA_FILE(fh, buf2);
#else
	mib_get( MIB_WLAN_ACCOUNT_RS_ENABLED, (void *)&chVal);
	snprintf(buf2, sizeof(buf2), "accountRsEnabled = %d\n", chVal);
	WRITE_WPA_FILE(fh, buf2);
#endif

	mib_get( MIB_WLAN_ACCOUNT_RS_PORT, (void *)&sintVal);
	snprintf(buf2, sizeof(buf2), "accountRsPort = %d\n", sintVal);
	WRITE_WPA_FILE(fh, buf2);

	mib_get( MIB_WLAN_ACCOUNT_RS_IP, (void *)buf1);
	snprintf(buf2, sizeof(buf2), "accountRsIP = %s\n", inet_ntoa(*((struct in_addr *)buf1)));
	WRITE_WPA_FILE(fh, buf2);

	mib_get( MIB_WLAN_ACCOUNT_RS_PASSWORD, (void *)buf1);
	snprintf(buf2, sizeof(buf2), "accountRsPassword = \"%s\"\n", buf1);
	WRITE_WPA_FILE(fh, buf2);

	mib_get( MIB_WLAN_ACCOUNT_UPDATE_ENABLED, (void *)&chVal);
	snprintf(buf2, sizeof(buf2), "accountRsUpdateEnabled = %d\n", chVal);
	WRITE_WPA_FILE(fh, buf2);

	mib_get( MIB_WLAN_ACCOUNT_UPDATE_DELAY, (void *)&sintVal);
	snprintf(buf2, sizeof(buf2), "accountRsUpdateTime = %d\n", sintVal);
	WRITE_WPA_FILE(fh, buf2);

	mib_get( MIB_WLAN_ACCOUNT_RS_RETRY, (void *)&chVal);
	snprintf(buf2, sizeof(buf2), "accountRsMaxReq = %d\n", chVal);
	WRITE_WPA_FILE(fh, buf2);

	mib_get( MIB_WLAN_ACCOUNT_RS_INTERVAL_TIME, (void *)&sintVal);
	snprintf(buf2, sizeof(buf2), "accountRsAWhile = %d\n", sintVal);
	WRITE_WPA_FILE(fh, buf2);
#endif

#ifdef WLAN_11W
	if (encrypt == WIFI_SEC_WPA2) {
		snprintf(buf2, sizeof(buf2), "ieee80211w = %d\n", Entry->dotIEEE80211W);
		WRITE_WPA_FILE(fh, buf2);
		snprintf(buf2, sizeof(buf2), "sha256 = %d\n", Entry->sha256);
		WRITE_WPA_FILE(fh, buf2);
	}
	else {
		snprintf(buf2, sizeof(buf2), "ieee80211w = %d\n", 0);
		WRITE_WPA_FILE(fh, buf2);
		snprintf(buf2, sizeof(buf2), "sha256 = %d\n", 0);
		WRITE_WPA_FILE(fh, buf2);
	}
#endif

#ifdef _PRMT_X_WLANFORISP_
#if 1 // force config, because need userId and called ID to register
		snprintf(buf2, sizeof(buf2), "rsNasId = \"%s\"\n", wlan_isp_entry->NasID);
		WRITE_WPA_FILE(fh, buf2);

		snprintf(buf2, sizeof(buf2), "EnableUserId = %d\n", 1);
		WRITE_WPA_FILE(fh, buf2);

		snprintf(buf2, sizeof(buf2), "EnableCalledId = %d\n", 1);
		WRITE_WPA_FILE(fh, buf2);
#else
		if(strlen(wlan_isp_entry->NasID)){
			strcpy(buf1, wlan_isp_entry->NasID);
			snprintf(buf2, sizeof(buf2), "rsNasId = \"%s\"\n", buf1);
			WRITE_WPA_FILE(fh, buf2);
		}

		snprintf(buf2, sizeof(buf2), "EnableUserId = %d\n", wlan_isp_entry->EnableUserId);
		WRITE_WPA_FILE(fh, buf2);

		snprintf(buf2, sizeof(buf2), "EnableCalledId = %d\n", wlan_isp_entry->EnableCalledId);
		WRITE_WPA_FILE(fh, buf2);
#endif
#endif
	}

	else {
#if 0 // not support WDS
#endif
	}

	close(fh);

	return 0;
}

static int is8021xEnabled(int vwlan_idx) {
#ifdef WLAN_1x
	MIB_CE_MBSSIB_T Entry;

	mib_chain_get(MIB_MBSSIB_TBL, vwlan_idx, (void *)&Entry);

	if (Entry.enable1X) {
		return 1;
	} else {
		if (Entry.encrypt >= WIFI_SEC_WPA) {
			///fprintf(stderr, "wpaAuth=%d\n", wpaAuth);
			if (WPA_AUTH_AUTO == Entry.wpaAuth)
				return 1;

		}
	}
#endif
	return 0;
}

#ifdef CONFIG_WIFI_SIMPLE_CONFIG // WPS
#define MIB_GET(id, val) do { \
		if (0==mib_get(id, (void *)val)) { \
		} \
	} while (0)

void sync_wps_config_mib()
{
	MIB_CE_MBSSIB_T Entry;

	mib_chain_get(MIB_MBSSIB_TBL, 0, (void *)&Entry);
	mib_get(MIB_WSC_CONFIGURED, &Entry.wsc_configured);
	mib_chain_update(MIB_MBSSIB_TBL, (void *)&Entry, 0);
}

int update_wps_from_mibtable(void)
{
	MIB_CE_MBSSIB_T Entry;
	int i, orig_idx;
	int lockfd;

	LOCK_WLAN();
	orig_idx = wlan_idx;

	for(i=0; i<NUM_WLAN_INTERFACE; i++){
		wlan_idx = i;
		mib_chain_get(MIB_MBSSIB_TBL, 0, (void *)&Entry);

		mib_get(MIB_WLAN_SSID, Entry.ssid);
		mib_get(MIB_WLAN_ENCRYPT, &Entry.encrypt);
		mib_get(MIB_WLAN_AUTH_TYPE, &Entry.authType);
		mib_get(MIB_WSC_AUTH, &Entry.wsc_auth);
		mib_get(MIB_WLAN_WPA_AUTH, &Entry.wpaAuth);
		mib_get(MIB_WLAN_WPA_PSK_FORMAT, &Entry.wpaPSKFormat);
		mib_get(MIB_WLAN_WPA_PSK, Entry.wpaPSK);
		mib_get(MIB_WSC_PSK, Entry.wscPsk);
		mib_get(MIB_WLAN_WPA_CIPHER_SUITE, &Entry.unicastCipher);
		mib_get(MIB_WLAN_WPA2_CIPHER_SUITE, &Entry.wpa2UnicastCipher);
		mib_get(MIB_WLAN_WEP, &Entry.wep);
		mib_get(MIB_WLAN_WEP_DEFAULT_KEY, &Entry.wepDefaultKey);
		mib_get(MIB_WLAN_WEP64_KEY1, Entry.wep64Key1);
		mib_get(MIB_WLAN_WEP64_KEY2, Entry.wep64Key2);
		mib_get(MIB_WLAN_WEP64_KEY3, Entry.wep64Key3);
		mib_get(MIB_WLAN_WEP64_KEY4, Entry.wep64Key4);
		mib_get(MIB_WLAN_WEP128_KEY1, Entry.wep128Key1);
		mib_get(MIB_WLAN_WEP128_KEY2, Entry.wep128Key2);
		mib_get(MIB_WLAN_WEP128_KEY3, Entry.wep128Key3);
		mib_get(MIB_WLAN_WEP128_KEY4, Entry.wep128Key4);
		mib_get(MIB_WLAN_WEP_KEY_TYPE, &Entry.wepKeyType);		// wep Key Format
		mib_get(MIB_WSC_ENC, &Entry.wsc_enc);

		mib_chain_update(MIB_MBSSIB_TBL, (void *)&Entry, 0);
		sync_wps_config_mib();
		mib_update(CURRENT_SETTING, CONFIG_MIB_ALL);
	}
	wlan_idx = orig_idx;
	UNLOCK_WLAN();
	return 0;
}

void update_wps_mib(void)
{
	MIB_CE_MBSSIB_T Entry;
	mib_chain_get(MIB_MBSSIB_TBL, 0, (void *)&Entry);
	
	mib_set(MIB_WLAN_ENCRYPT, &Entry.encrypt);
	mib_set(MIB_WLAN_ENABLE_1X, &Entry.enable1X);
	mib_set(MIB_WLAN_WEP, &Entry.wep);
	mib_set(MIB_WLAN_WPA_AUTH, &Entry.wpaAuth);
	mib_set(MIB_WLAN_WPA_PSK_FORMAT, &Entry.wpaPSKFormat);
	mib_set(MIB_WLAN_WPA_PSK, Entry.wpaPSK);
	mib_set(MIB_WLAN_RS_PORT, &Entry.rsPort);
	mib_set(MIB_WLAN_RS_IP, Entry.rsIpAddr);

	mib_set(MIB_WLAN_RS_PASSWORD, Entry.rsPassword);
	mib_set(MIB_WLAN_DISABLED, &Entry.wlanDisabled);
	mib_set(MIB_WLAN_SSID, Entry.ssid);
	mib_set(MIB_WLAN_MODE, &Entry.wlanMode);
	mib_set(MIB_WLAN_AUTH_TYPE, &Entry.authType);

	mib_set(MIB_WLAN_WPA_CIPHER_SUITE, &Entry.unicastCipher);
	mib_set(MIB_WLAN_WPA2_CIPHER_SUITE, &Entry.wpa2UnicastCipher);
	mib_set(MIB_WLAN_WPA_GROUP_REKEY_TIME, &Entry.wpaGroupRekeyTime);

	mib_set(MIB_WLAN_WEP_KEY_TYPE, &Entry.wepKeyType);      // wep Key Format
	mib_set(MIB_WLAN_WEP_DEFAULT_KEY, &Entry.wepDefaultKey);
	mib_set(MIB_WLAN_WEP64_KEY1, Entry.wep64Key1);
	mib_set(MIB_WLAN_WEP64_KEY2, Entry.wep64Key2);
	mib_set(MIB_WLAN_WEP64_KEY3, Entry.wep64Key3);
	mib_set(MIB_WLAN_WEP64_KEY4, Entry.wep64Key4);
	mib_set(MIB_WLAN_WEP128_KEY1, Entry.wep128Key1);
	mib_set(MIB_WLAN_WEP128_KEY2, Entry.wep128Key2);
	mib_set(MIB_WLAN_WEP128_KEY3, Entry.wep128Key3);
	mib_set(MIB_WLAN_WEP128_KEY4, Entry.wep128Key4);
	mib_set(MIB_WLAN_BAND, &Entry.wlanBand);
	mib_set(MIB_WSC_DISABLE, &Entry.wsc_disabled);
	//mib_set(MIB_WSC_CONFIGURED, &Entry.wsc_configured);
	mib_set(MIB_WSC_UPNP_ENABLED, &Entry.wsc_upnp_enabled);
	mib_set(MIB_WSC_AUTH, &Entry.wsc_auth);
	mib_set(MIB_WSC_ENC, &Entry.wsc_enc);
	mib_set(MIB_WSC_PSK, Entry.wscPsk);

}
#ifndef WLAN_WPS_VAP
int update_wps_configured(int reset_flag)
{
	char is_configured, encrypt1, encrypt2, auth, disabled, iVal, mode, format, encryptwps;
	char ssid1[100], ssid2[100];
	unsigned char tmpbuf[100];
#ifdef WPS20
	unsigned char wpsUseVersion;
#endif
	MIB_CE_MBSSIB_T Entry;
	int i=0, orig_wlan_idx;
	int lockfd;

	LOCK_WLAN();
	orig_wlan_idx = wlan_idx;

	for(i=0; i<NUM_WLAN_INTERFACE; i++)
	{
		wlan_idx = i;
		if(!mib_chain_get(MIB_MBSSIB_TBL, 0, &Entry))
			continue;
		
		update_wps_mib();

		//fprintf(stderr, "update_wps_configured(%d)\n", reset_flag);

		MIB_GET(MIB_WSC_CONFIGURED, (void *)&is_configured);
		MIB_GET(MIB_WLAN_MODE, (void *)&mode);

		if (!is_configured && mode == AP_MODE) {
			MIB_GET(MIB_WLAN_SSID, (void *)ssid1);
			mib_getDef(MIB_WLAN_SSID, (void *)ssid2);
			if (strcmp(ssid1, ssid2)) { // Magician: Fixed parsing error by Source Insight
				is_configured = 1;
				mib_set(MIB_WSC_CONFIGURED, (void *)&is_configured);
				Entry.wsc_configured = is_configured;

				MIB_GET(MIB_WSC_CONFIG_BY_EXT_REG, (void *)&iVal);
				if (is_configured && iVal == 0) {
					iVal = 1;
					mib_set(MIB_WSC_MANUAL_ENABLED, (void *)&iVal);
				}
				//return;
			}

			MIB_GET(MIB_WLAN_ENCRYPT, (void *)&encrypt1);
			mib_getDef(MIB_WLAN_ENCRYPT, (void *)&encrypt2);

			if (encrypt1 != encrypt2) {
				is_configured = 1;
				mib_set(MIB_WSC_CONFIGURED, (void *)&is_configured);
				Entry.wsc_configured = is_configured;
			}
		}
		mib_chain_update(MIB_MBSSIB_TBL, &Entry, 0);
		
		MIB_GET(MIB_WSC_DISABLE, (void *)&disabled);
#ifdef WPS20
		MIB_GET(MIB_WSC_VERSION, (void *)&wpsUseVersion);
		if (wpsUseVersion == 0 && disabled)
			continue;
#else
		if (disabled)
			continue;
#endif

		MIB_GET(MIB_WLAN_ENCRYPT, (void *)&encrypt1);
		if (encrypt1 == WIFI_SEC_NONE) {
			auth = WSC_AUTH_OPEN;
			encrypt2 = WSC_ENCRYPT_NONE;
		}
		else if (encrypt1 == WIFI_SEC_WEP) {
			auth = WSC_AUTH_OPEN;
			encrypt2 = WSC_ENCRYPT_WEP;
		}
		else if (encrypt1 == WIFI_SEC_WPA) {
			MIB_GET(MIB_WLAN_WPA_CIPHER_SUITE, (void *)&encryptwps);
			auth = WSC_AUTH_WPAPSK;
			encrypt2 = WSC_ENCRYPT_TKIPAES;
			if (encryptwps == WPA_CIPHER_AES)
				encrypt2 = WSC_ENCRYPT_AES;
			if (encryptwps == WPA_CIPHER_TKIP)
				encrypt2 = WSC_ENCRYPT_TKIP;
			if (encryptwps == WPA_CIPHER_MIXED)
				encrypt2 = WSC_ENCRYPT_TKIPAES;
		}
		else if (encrypt1 == WIFI_SEC_WPA2) {
			MIB_GET(MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&encryptwps);
			auth = WSC_AUTH_WPA2PSK;
			encrypt2 = WSC_ENCRYPT_TKIPAES;
			if (encryptwps == WPA_CIPHER_AES)
				encrypt2 = WSC_ENCRYPT_AES;
			if (encryptwps == WPA_CIPHER_TKIP)
				encrypt2 = WSC_ENCRYPT_TKIP;
			if (encryptwps == WPA_CIPHER_MIXED)
				encrypt2 = WSC_ENCRYPT_TKIPAES;
		}
		else {
			auth = WSC_AUTH_WPA2PSKMIXED;
			encrypt2 = WSC_ENCRYPT_TKIPAES;
	// sync with ap team at 2011-04-25, When mixed mode, if no WPA2-AES, try to use WPA-AES or WPA2-TKIP
	        	MIB_GET(MIB_WLAN_WPA_CIPHER_SUITE, (void *)&encrypt1);
	        	MIB_GET(MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&iVal);
			if (encrypt1 == iVal) {	//cathy, fix wps web bug when encryption is: WPA-AES+WPA2-AES / WPA-TKIP+WPA2-AES
				if (encrypt1 == WPA_CIPHER_TKIP)
					encrypt2 = WSC_ENCRYPT_TKIP;
				else if (encrypt1 == WPA_CIPHER_AES)
					encrypt2 = WSC_ENCRYPT_AES;
			}
			else if (!(iVal & WPA_CIPHER_AES)) {
				if (encrypt1 & WPA_CIPHER_AES) {
					encrypt2 = WSC_ENCRYPT_AES;
				}
			}
	//-------------------------------------------- david+2008-01-03
		}
		mib_set(MIB_WSC_AUTH, (void *)&auth);
		Entry.wsc_auth = auth;
		mib_set(MIB_WSC_ENC, (void *)&encrypt2);
		Entry.wsc_enc = encrypt2;

		MIB_GET(MIB_WLAN_ENCRYPT, (void *)&encrypt1);
		if (encrypt1 == WIFI_SEC_WPA || encrypt1 == WIFI_SEC_WPA2
			|| encrypt1 == WIFI_SEC_WPA2_MIXED) {
			MIB_GET(MIB_WLAN_WPA_AUTH, (void *)&format);
			if (format & 2) { // PSK
				MIB_GET(MIB_WLAN_WPA_PSK, (void *)tmpbuf);
				mib_set(MIB_WSC_PSK, (void *)tmpbuf);
				strcpy(Entry.wscPsk, tmpbuf);
			}
		}
		if (reset_flag) {
			reset_flag = 0;
			mib_set(MIB_WSC_CONFIG_BY_EXT_REG, (void *)&reset_flag);
		}

		MIB_GET(MIB_WSC_CONFIG_BY_EXT_REG, (void *)&iVal);
		if (is_configured && iVal == 0) {
			iVal = 1;
			mib_set(MIB_WSC_MANUAL_ENABLED, (void *)&iVal);
		}
		iVal = 0;
		if (mode == AP_MODE || mode == AP_WDS_MODE) {
			if (encrypt1 == WIFI_SEC_WEP || encrypt1 == WIFI_SEC_NONE) {
				MIB_GET(MIB_WLAN_ENABLE_1X, (void *)&encrypt2);
				if (encrypt2)
					iVal = 1;
			}
			else {
				MIB_GET(MIB_WLAN_WPA_AUTH, (void *)&encrypt2);
				if (encrypt2 == WPA_AUTH_AUTO)
					iVal = 1;
			}
		}
		else if (mode == CLIENT_MODE || mode == AP_WDS_MODE)
			iVal = 1;
		if (iVal) {
			iVal = 0;
			mib_set(MIB_WSC_MANUAL_ENABLED, (void *)&iVal);
			mib_set(MIB_WSC_CONFIGURED, (void *)&iVal);
			Entry.wsc_configured = iVal;
			mib_set(MIB_WSC_CONFIG_BY_EXT_REG, (void *)&iVal);
		}
		mib_chain_update(MIB_MBSSIB_TBL, &Entry, 0);
		sync_wps_config_mib();
	}
	wlan_idx = orig_wlan_idx;
	UNLOCK_WLAN();
	return 0;
}
#else
int update_wps_configured(int reset_flag)
{
	char is_configured, encrypt1, encrypt2, auth, disabled, iVal, mode, format, encryptwps;
	char ssid1[100], ssid2[100];
	unsigned char tmpbuf[100];
#ifdef WPS20
	unsigned char wpsUseVersion;
#endif
	MIB_CE_MBSSIB_T Entry, Entry_bk;
	int i, j, orig_wlan_idx;
	int lockfd;

	LOCK_WLAN();
	orig_wlan_idx = wlan_idx;

	for(j=0; j<NUM_WLAN_INTERFACE; j++)
	{
		wlan_idx = j;
		//fprintf(stderr, "update_wps_configured(%d)\n", reset_flag);
		for (i=0; i<=WLAN_MBSSID_NUM; i++) {
			wlan_getEntry(&Entry, i);
			mib_chain_backup_get(MIB_MBSSIB_TBL, i, &Entry_bk);
			//printf("ssid %s\n", Entry_bk.ssid);
			if (Entry.wlanDisabled)
				continue;

			is_configured = Entry.wsc_configured;
			MIB_GET(MIB_WLAN_MODE, (void *)&mode);

			if (!is_configured && mode == AP_MODE) {
				//MIB_GET(MIB_WLAN_SSID, (void *)ssid1);
				//mib_getDef(MIB_WLAN_SSID, (void *)ssid2);
				if (strcmp(Entry.ssid, Entry_bk.ssid)) { // Magician: Fixed parsing error by Source Insight
					is_configured = 1;

					Entry.wsc_configured = is_configured;

					MIB_GET(MIB_WSC_CONFIG_BY_EXT_REG, (void *)&iVal);
					if (is_configured && iVal == 0) {
						iVal = 1;
						mib_set(MIB_WSC_MANUAL_ENABLED, (void *)&iVal);
					}
					//return;
				}

				//MIB_GET(MIB_WLAN_ENCRYPT, (void *)&encrypt1);
				//mib_getDef(MIB_WLAN_ENCRYPT, (void *)&encrypt2);

				if (Entry.encrypt != Entry_bk.encrypt) {
					is_configured = 1;
					Entry.wsc_configured = is_configured;
				}
			}
			//mib_chain_update(MIB_MBSSIB_TBL, &Entry, 0);
			
			//MIB_GET(MIB_WSC_DISABLE, (void *)&disabled);
#ifdef WPS20
			MIB_GET(MIB_WSC_VERSION, (void *)&wpsUseVersion);
			if (wpsUseVersion == 0 && Entry.wsc_disabled)
				continue;
#else
			if (Entry.wsc_disabled)
				continue;
#endif

			//MIB_GET(MIB_WLAN_ENCRYPT, (void *)&encrypt1);
			encrypt1 = Entry.encrypt;
			if (encrypt1 == WIFI_SEC_NONE) {
				auth = WSC_AUTH_OPEN;
				encrypt2 = WSC_ENCRYPT_NONE;
			}
			else if (encrypt1 == WIFI_SEC_WEP) {
				auth = WSC_AUTH_OPEN;
				encrypt2 = WSC_ENCRYPT_WEP;
			}
			else if (encrypt1 == WIFI_SEC_WPA) {
				//MIB_GET(MIB_WLAN_WPA_CIPHER_SUITE, (void *)&encryptwps);
				encryptwps = Entry.unicastCipher;
				auth = WSC_AUTH_WPAPSK;
				encrypt2 = WSC_ENCRYPT_TKIPAES;
				if (encryptwps == WPA_CIPHER_AES)
					encrypt2 = WSC_ENCRYPT_AES;
				if (encryptwps == WPA_CIPHER_TKIP)
					encrypt2 = WSC_ENCRYPT_TKIP;
				if (encryptwps == WPA_CIPHER_MIXED)
					encrypt2 = WSC_ENCRYPT_TKIPAES;
			}
			else if (encrypt1 == WIFI_SEC_WPA2) {
				//MIB_GET(MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&encryptwps);
				encryptwps = Entry.wpa2UnicastCipher;
				auth = WSC_AUTH_WPA2PSK;
				encrypt2 = WSC_ENCRYPT_TKIPAES;
				if (encryptwps == WPA_CIPHER_AES)
					encrypt2 = WSC_ENCRYPT_AES;
				if (encryptwps == WPA_CIPHER_TKIP)
					encrypt2 = WSC_ENCRYPT_TKIP;
				if (encryptwps == WPA_CIPHER_MIXED)
					encrypt2 = WSC_ENCRYPT_TKIPAES;
			}
			else {
				auth = WSC_AUTH_WPA2PSKMIXED;
				encrypt2 = WSC_ENCRYPT_TKIPAES;
		// sync with ap team at 2011-04-25, When mixed mode, if no WPA2-AES, try to use WPA-AES or WPA2-TKIP
		        	//MIB_GET(MIB_WLAN_WPA_CIPHER_SUITE, (void *)&encrypt1);
		        	encrypt1 = Entry.unicastCipher;
		        	//MIB_GET(MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&iVal);
		        	iVal = Entry.wpa2UnicastCipher;
				if (encrypt1 == iVal) {	//cathy, fix wps web bug when encryption is: WPA-AES+WPA2-AES / WPA-TKIP+WPA2-AES
					if (encrypt1 == WPA_CIPHER_TKIP)
						encrypt2 = WSC_ENCRYPT_TKIP;
					else if (encrypt1 == WPA_CIPHER_AES)
						encrypt2 = WSC_ENCRYPT_AES;
				}
				else if (!(iVal & WPA_CIPHER_AES)) {
					if (encrypt1 & WPA_CIPHER_AES) {
						encrypt2 = WSC_ENCRYPT_AES;
					}
				}
		//-------------------------------------------- david+2008-01-03
			}
			//mib_set(MIB_WSC_AUTH, (void *)&auth);
			Entry.wsc_auth = auth;
			//mib_set(MIB_WSC_ENC, (void *)&encrypt2);
			Entry.wsc_enc = encrypt2;

			//MIB_GET(MIB_WLAN_ENCRYPT, (void *)&encrypt1);
				encrypt1 = Entry.encrypt;
			if (encrypt1 == WIFI_SEC_WPA || encrypt1 == WIFI_SEC_WPA2
				|| encrypt1 == WIFI_SEC_WPA2_MIXED) {
				//MIB_GET(MIB_WLAN_WPA_AUTH, (void *)&format);
				format = Entry.wpaAuth;
				if (format & 2) { // PSK
					//MIB_GET(MIB_WLAN_WPA_PSK, (void *)tmpbuf);
					strcpy(tmpbuf, Entry.wpaPSK);
					//mib_set(MIB_WSC_PSK, (void *)tmpbuf);
					strcpy(Entry.wscPsk, tmpbuf);
				}
			}
			if (reset_flag) {
				reset_flag = 0;
				mib_set(MIB_WSC_CONFIG_BY_EXT_REG, (void *)&reset_flag);
			}

			MIB_GET(MIB_WSC_CONFIG_BY_EXT_REG, (void *)&iVal);
			if (is_configured && iVal == 0) {
				iVal = 1;
				mib_set(MIB_WSC_MANUAL_ENABLED, (void *)&iVal);
			}
			iVal = 0;
			if (mode == AP_MODE || mode == AP_WDS_MODE) {
				if (encrypt1 == WIFI_SEC_WEP || encrypt1 == WIFI_SEC_NONE) {
					//MIB_GET(MIB_WLAN_ENABLE_1X, (void *)&encrypt2);
					encrypt2 = Entry.enable1X;
					if (encrypt2)
						iVal = 1;
				}
				else {
					//MIB_GET(MIB_WLAN_WPA_AUTH, (void *)&encrypt2);
					encrypt2 = Entry.wpaAuth;
					if (encrypt2 == WPA_AUTH_AUTO)
						iVal = 1;
				}
			}
			else if (mode == CLIENT_MODE || mode == AP_WDS_MODE)
				iVal = 1;
			if (iVal) {
				iVal = 0;
				mib_set(MIB_WSC_MANUAL_ENABLED, (void *)&iVal);
				//mib_set(MIB_WSC_CONFIGURED, (void *)&iVal);
				Entry.wsc_configured = iVal;
				mib_set(MIB_WSC_CONFIG_BY_EXT_REG, (void *)&iVal);
			}
			mib_chain_update(MIB_MBSSIB_TBL, (void *)&Entry, i);
			//sync_wps_config_mib();
		}
	}

	wlan_idx = orig_wlan_idx;
	UNLOCK_WLAN();
	return 0;
}
#endif
int start_WPS(int run_daemon)
{
#ifndef WLAN_WPS_VAP
	int status=0;
	unsigned char encrypt;
	int retry;
	unsigned char wsc_disable;
	unsigned char wlan_mode;
	unsigned char wlan_nettype;
	unsigned char wpa_auth;
	char *cmd_opt[16];
	int cmd_cnt = 0; int idx;
	int wscd_pid_fd = -1;
	int i;
	unsigned int enableWscIf = 0;
	int orig_wlan_idx;
	unsigned char no_wlan;
	char fifo_buf[32], fifo_buf2[32];
#if defined(CONFIG_RTL_92D_SUPPORT) || defined(WLAN_DUALBAND_CONCURRENT)
	char wlanBand2G5GSelect;
	orig_wlan_idx = wlan_idx;
#endif

#if 0 //def CONFIG_RTL_92D_DMDP
	unsigned char wlan0_mode, wlan1_mode, both_band_ap;
	unsigned char wlan_disabled_root, wlan_wsc_disabled;
	unsigned char wlan_wsc1_disabled;
	unsigned char wlan1_disabled_root;
	mib_get(MIB_WLAN_MODE, (void *)&wlan0_mode);
	mib_get(MIB_WLAN_DISABLED, (void *)&wlan_disabled_root);
	mib_get(MIB_WSC_DISABLE, (void *)&wlan_wsc_disabled);
	mib_get(MIB_WLAN1_MODE, (void *)&wlan1_mode);
	mib_get(MIB_WLAN1_DISABLED, (void *)&wlan1_disabled_root);
	mib_get(MIB_WLAN1_WSC_DISABLE, (void *)&wlan_wsc1_disabled);
	printf("wlan0_mode=%d wlan_disabled_root=%d wlan_wsc_disabled=%d\n", wlan0_mode, wlan_disabled_root, wlan_wsc_disabled);
	printf("wlan1_mode=%d wlan1_disabled_root=%d wlan_wsc1_disabled=%d\n", wlan1_mode, wlan1_disabled_root, wlan_wsc1_disabled);
	if (((wlan0_mode == AP_MODE) || (wlan0_mode == AP_WDS_MODE)) && ((wlan1_mode == 0) || (wlan1_mode == AP_WDS_MODE))
		&& (wlan_disabled_root == 0) && (wlan1_disabled_root == 0) && (wlan_wsc_disabled == 0) && (wlan_wsc1_disabled == 0))
		both_band_ap = 1;
#endif

	for(i = 0; i<NUM_WLAN_INTERFACE; i++){
		wlan_idx = i;

		mib_get(MIB_WSC_DISABLE, (void *)&wsc_disable);
		mib_get(MIB_WLAN_DISABLED, (void *)&no_wlan);
		mib_get(MIB_WLAN_MODE, (void *)&wlan_mode);
		mib_get(MIB_WLAN_NETWORK_TYPE, (void *)&wlan_nettype);
		mib_get(MIB_WLAN_WPA_AUTH, (void *)&wpa_auth);
		mib_get(MIB_WLAN_ENCRYPT, (void *)&encrypt);

		if(no_wlan || wsc_disable || is8021xEnabled(0))
			continue;
		else if(wlan_mode == CLIENT_MODE) {
			if(wlan_nettype != INFRASTRUCTURE)
				continue;
		}
		else if(wlan_mode == AP_MODE) {
			if((encrypt >= WIFI_SEC_WPA) && (wpa_auth == WPA_AUTH_AUTO))
				continue;
		}
		if(useWlanIfVirtIdx())
			enableWscIf |= 1;
		else
			enableWscIf |= (1<<i);
	}

	if(!enableWscIf)
		goto WSC_DISABLE;
	else
		useAuth_RootIf |= enableWscIf;

	if(run_daemon==0)
		goto WSC_DISABLE;

	fprintf(stderr, "START WPS SETUP!\n\n\n");
	cmd_opt[cmd_cnt++] = "";

	if (wlan_mode == CLIENT_MODE) {
		cmd_opt[cmd_cnt++] = "-mode";
		cmd_opt[cmd_cnt++] = "2";
	} else {
		cmd_opt[cmd_cnt++] = "-start";
	}

#if defined(CONFIG_RTL_92D_DMDP) || defined(WLAN_DUALBAND_CONCURRENT)
//	if (both_band_ap == 1)
	if(enableWscIf == 3){
		cmd_opt[cmd_cnt++] = "-both_band_ap";
		cmd_opt[cmd_cnt++] = "-w";
		cmd_opt[cmd_cnt++] = (char *)WLANIF[0];
	}
	else{
		if(enableWscIf & 1){
			cmd_opt[cmd_cnt++] = "-w";
			cmd_opt[cmd_cnt++] = (char *)WLANIF[0];
		}
		else{
			cmd_opt[cmd_cnt++] = "-w";
			cmd_opt[cmd_cnt++] = (char *)WLANIF[1];
		}
	}
#endif

	cmd_opt[cmd_cnt++] = "-c";
	cmd_opt[cmd_cnt++] = (char *)WSCD_CONF;
#if !defined(CONFIG_RTL_92D_DMDP) && !defined(WLAN_DUALBAND_CONCURRENT)
	cmd_opt[cmd_cnt++] = "-w";
	cmd_opt[cmd_cnt++] = (char *)WLANIF[0];
#endif
	//strcat(cmd, " -c /var/wscd.conf -w wlan0");

	if (enableWscIf & 1) { // use iwcontrol
		cmd_opt[cmd_cnt++] = "-fi";
		snprintf(fifo_buf, 32, (char *)WSCD_FIFO, WLANIF[0]);
		cmd_opt[cmd_cnt++] = (char *)fifo_buf;
		//strcat(cmd, " -fi /var/wscd-wlan0.fifo");
	}
#if defined(CONFIG_RTL_92D_DMDP) || defined(WLAN_DUALBAND_CONCURRENT)
	if (enableWscIf & 2){
		cmd_opt[cmd_cnt++] = "-fi2";
		snprintf(fifo_buf2, 32, (char *)WSCD_FIFO, WLANIF[1]);
		cmd_opt[cmd_cnt++] = (char *)fifo_buf2;
	}
#endif

	//cmd_opt[cmd_cnt++] = "-debug";
	//strcat(cmd, " -debug");
	//strcat(cmd, " &");
	#define TARGDIR "/var/wps/"
	#define SIMPLECFG "simplecfgservice.xml"
	//status |= va_cmd("/bin/flash", 3, 1, "upd-wsc-conf", "/etc/wscd.conf", "/var/wscd.conf");
	status |= va_cmd("/bin/mkdir", 2, 1, "-p", TARGDIR);
	status |= va_cmd("/bin/cp", 2, 1, "/etc/" SIMPLECFG, TARGDIR);

	cmd_opt[cmd_cnt] = 0;
	printf("CMD ARGS: ");
	for (idx=0; idx<cmd_cnt;idx++)
		printf("%s ", cmd_opt[idx]);
	printf("\n");

	status |= do_nice_cmd("/bin/wscd", cmd_opt, 0);

	if (enableWscIf & 1) {
		retry = 0;
		snprintf(fifo_buf, sizeof(fifo_buf), WSCD_FIFO, WLANIF[0]);
		while ((wscd_pid_fd = open((char *)fifo_buf, O_WRONLY|O_NONBLOCK)) == -1)
		{
			usleep(100000);
			retry ++;

			if (retry > 10) {
				printf("wscd fifo timeout, abort\n");
				break;
			}
		}

		if(wscd_pid_fd!=-1) close(wscd_pid_fd);/*jiunming, close the opened fd*/
	}
	
#if defined(CONFIG_RTL_92D_DMDP) || defined(WLAN_DUALBAND_CONCURRENT)
	if (enableWscIf & 2) {
		retry = 0;
		snprintf(fifo_buf, sizeof(fifo_buf), WSCD_FIFO, WLANIF[1]);
		while ((wscd_pid_fd = open((char *)fifo_buf, O_WRONLY|O_NONBLOCK)) == -1)
		{
			usleep(100000);
			retry ++;

			if (retry > 10) {
				printf("wscd fifo timeout, abort\n");
				break;
			}
		}

		if(wscd_pid_fd!=-1) close(wscd_pid_fd);
	}
#endif
	
WSC_DISABLE:
#if defined(CONFIG_RTL_92D_SUPPORT) || defined(WLAN_DUALBAND_CONCURRENT)
	wlan_idx = orig_wlan_idx;
#endif
	return status;
#else
	char wscd_pid_name[32];
	char wscd_fifo_name[32];
	char wscd_conf_name[32];
	int wsc_pid_fd=-1;

	MIB_CE_MBSSIB_T Entry;
	int orig_wlan_idx, i, j;
	char ifname[16];
	int status = 0;
	unsigned char wps_ssid;
	unsigned char vChar;
	unsigned char wsc_disable;
	unsigned char wlan_nettype;
	unsigned char wlan_mode;
#ifdef YUEME_3_0_SPEC
	unsigned char no_wlan;
#endif
	int retry=0;

	//wlan_num = 0; /*reset to 0,jiunming*/
	//useAuth_RootIf = 0;  /*reset to 0 */

#ifndef WLAN_WPS_MULTI_DAEMON	
	mib_get(MIB_WPS_ENABLE, &vChar);
	if(vChar == 0)
		goto no_wsc;
#endif
	
	orig_wlan_idx = wlan_idx;
	
	for(j=0;j<NUM_WLAN_INTERFACE;j++){
		wlan_idx = j;
#ifdef YUEME_3_0_SPEC
		mib_get(MIB_WLAN_DISABLED, (void *)&no_wlan);
		if(no_wlan)
			continue;
#endif
		for ( i=0; i<=NUM_VWLAN_INTERFACE; i++) {
	
			mib_chain_get(MIB_MBSSIB_TBL, i, (void *)&Entry);
			
			if (i==0) {
				strncpy(ifname, (char*)getWlanIfName(), 16);
			}
			else {
		#ifdef WLAN_MBSSID
				if (i>=WLAN_VAP_ITF_INDEX && i<(WLAN_VAP_ITF_INDEX+WLAN_MBSSID_NUM))
					snprintf(ifname, 16, "%s-vap%d", (char *)getWlanIfName(), i-1);
		#endif
		#ifdef WLAN_UNIVERSAL_REPEATER
				if (i == WLAN_REPEATER_ITF_INDEX) {
					snprintf(ifname, 16, "%s-vxd", (char *)getWlanIfName());
					mib_get( MIB_REPEATER_ENABLED1, (void *)&vChar);
					if (vChar)
						Entry.wlanDisabled=0;
					else
						Entry.wlanDisabled=1;
				}
		#endif
			}
						
			wsc_disable = check_wps_enc(&Entry)? 0:1;
	
			mib_get(MIB_WLAN_MODE, (void *)&wlan_mode);
			mib_get(MIB_WLAN_NETWORK_TYPE, (void *)&wlan_nettype);
			//mib_get(MIB_WLAN_WPA_AUTH, (void *)&wpa_auth);
			//mib_get(MIB_WLAN_ENCRYPT, (void *)&encrypt);
#ifndef WLAN_WPS_MULTI_DAEMON
			mib_get(MIB_WPS_SSID, &wps_ssid);
#endif
	
			if(Entry.wlanDisabled || wsc_disable)
				continue;
#ifdef WLAN_WPS_MULTI_DAEMON
			else if(Entry.wsc_disabled)
				continue;
#else
			else if(!check_is_wps_ssid(i, wps_ssid))
				continue;
#endif
			else if(wlan_mode == CLIENT_MODE) {
				if(wlan_nettype != INFRASTRUCTURE)
					continue;
			}
			else if(wlan_mode == AP_MODE) {
				if((Entry.encrypt >= WIFI_SEC_WPA) && (Entry.wpaAuth == WPA_AUTH_AUTO))
					continue;
			}

			if(run_daemon == 0)
				goto skip_running_wscd;

			snprintf(wscd_pid_name, 32, "/var/run/wscd-%s.pid", ifname);

			int wscd_pid = read_pid(wscd_pid_name);
			if(wscd_pid > 0 && kill(wscd_pid, 0)==0)
				goto skip_running_wscd;
			
			
			#define TARGDIR "/var/wps/"
			#define SIMPLECFG "simplecfgservice.xml"
			//status |= va_cmd("/bin/flash", 3, 1, "upd-wsc-conf", "/etc/wscd.conf", "/var/wscd.conf");
			status |= va_cmd("/bin/mkdir", 2, 1, "-p", TARGDIR);
			status |= va_cmd("/bin/cp", 2, 1, "/etc/" SIMPLECFG, TARGDIR);
			
			sprintf(wscd_conf_name, "/var/wscd-%s.conf", ifname);
			sprintf(wscd_fifo_name, "/var/wscd-%s.fifo", ifname);
			//status|=generateWpaConf(para_auth_conf, 0, &Entry);
			status|=WPS_updateWscConf("/etc/wscd.conf", wscd_conf_name, 0, &Entry, i, j);
			status|=va_niced_cmd("/bin/wscd", 7, 0, "-start", "-c", wscd_conf_name, "-w", ifname, "-fi", wscd_fifo_name);
			// fix the depency problem
			// check fifo
			retry = 10;
			while (--retry && ((wsc_pid_fd = open(wscd_fifo_name, O_WRONLY)) == -1))
			{
				usleep(30000);
			}
			retry = 10;
			
			while(--retry && (read_pid(wscd_pid_name) < 0))
			{
				//printf("WSCD is not running. Please wait!\n");
				usleep(300000);
			}
	
			if(wsc_pid_fd!=-1) close(wsc_pid_fd);/*jiunming, close the opened fd*/

skip_running_wscd:

			if (i == 0){ // Root
					/* 2010-10-27 krammer :  use bit map to record what wlan root interface is use for auth*/
			if(useWlanIfVirtIdx())
				useAuth_RootIf |= 1;
			else
				useAuth_RootIf |= (1<<wlan_idx);//bit 0 ==> wlan0, bit 1 ==>wlan1
			}
			else {
				strcpy(para_iwctrl[wlan_num], ifname);
				wlan_num++;
			}
	
		}
	}
	wlan_idx = orig_wlan_idx;
no_wsc:
	if(run_daemon == 1)
		startSSDP();
	return status;
	
#endif
}
#endif

#ifdef WLAN_WPS_VAP
//	do modify  for wps2.x
enum { 
	CONFIG_METHOD_ETH=0x2, 
	CONFIG_METHOD_PIN=0x4, 
	CONFIG_METHOD_DISPLAY=0x8  ,		
	CONFIG_METHOD_PBC=0x80, 
	CONFIG_METHOD_KEYPAD=0x100,
	CONFIG_METHOD_VIRTUAL_PBC=0x280	,
	CONFIG_METHOD_PHYSICAL_PBC=0x480,
	CONFIG_METHOD_VIRTUAL_PIN=0x2008,
	CONFIG_METHOD_PHYSICAL_PIN=0x4008
	};


enum { 
		MODE_AP_UNCONFIG=1, 			// AP unconfigured (enrollee)
		MODE_CLIENT_UNCONFIG=2, 		// client unconfigured (enrollee) 
		MODE_CLIENT_CONFIG=3,			// client configured (registrar) 
		MODE_AP_PROXY=4, 				// AP configured (proxy)
		MODE_AP_PROXY_REGISTRAR=5,		// AP configured (proxy and registrar)
		MODE_CLIENT_UNCONFIG_REGISTRAR=6		// client unconfigured (registrar)
};

enum { 
	WPS_AP_MODE=0, 
	WPS_CLIENT_MODE=1, 
	WPS_WDS_MODE=2, 
	WPS_AP_WDS_MODE=3 
};

#define WSC_WPA_TKIP		1
#define WSC_WPA_AES		2
#define WSC_WPA2_TKIP		4
#define WSC_WPA2_AES		8

//enum { ENCRYPT_NONE=1, ENCRYPT_WEP=2, ENCRYPT_TKIP=4, ENCRYPT_AES=8, ENCRYPT_TKIPAES=12 };


#define WRITE_WSC_PARAM(dst, tmp, str, val) {	\
	sprintf(tmp, str, val); \
	memcpy(dst, tmp, strlen(tmp)); \
	dst += strlen(tmp); \
}

static void convert_hex_to_ascii(unsigned long code, char *out)
{
	*out++ = '0' + ((code / 10000000) % 10);  
	*out++ = '0' + ((code / 1000000) % 10);
	*out++ = '0' + ((code / 100000) % 10);
	*out++ = '0' + ((code / 10000) % 10);
	*out++ = '0' + ((code / 1000) % 10);
	*out++ = '0' + ((code / 100) % 10);
	*out++ = '0' + ((code / 10) % 10);
	*out++ = '0' + ((code / 1) % 10);
	*out = '\0';
}

static int compute_pin_checksum(unsigned long int PIN)
{
	unsigned long int accum = 0;
	int digit;
	
	PIN *= 10;
	accum += 3 * ((PIN / 10000000) % 10); 	
	accum += 1 * ((PIN / 1000000) % 10);
	accum += 3 * ((PIN / 100000) % 10);
	accum += 1 * ((PIN / 10000) % 10); 
	accum += 3 * ((PIN / 1000) % 10); 
	accum += 1 * ((PIN / 100) % 10); 
	accum += 3 * ((PIN / 10) % 10);

	digit = (accum % 10);
	return (10 - digit) % 10;
}

enum { _ENCRYPT_DISABLED_=0, _ENCRYPT_WEP_=1, _ENCRYPT_WPA_=2, _ENCRYPT_WPA2_=4, _ENCRYPT_WPA2_MIXED_=6 };

static void convert_bin_to_str(unsigned char *bin, int len, char *out)
{
	int i;
	char tmpbuf[10];

	out[0] = '\0';

	for (i=0; i<len; i++) {
		sprintf(tmpbuf, "%02x", bin[i]);
		strcat(out, tmpbuf);
	}
}


int WPS_updateWscConf(char *in, char *out, int genpin, MIB_CE_MBSSIB_T *Entry, int vwlan_idx, int wlanIdx)
{
	int fh = -1;
	struct stat status;
	char *buf = NULL, *ptr;
	unsigned char intVal2, is_client, is_config, is_registrar, is_wep=0, wep_key_type=0, wep_transmit_key=0;
	unsigned char intVal, current_wps_version;
	unsigned char wlan_encrypt=0, wlan_wpa_cipher=0, wlan_wpa2_cipher=0;
	int config_method;
	unsigned char tmpbuf[100], tmp1[100];
	int len;
#if defined(CONFIG_RTL_92D_SUPPORT) || defined(FOR_DUAL_BAND)
	unsigned char wlanBand2G5GSelect;
	//int orig_wlan_idx; 
#endif

#ifdef FOR_DUAL_BAND
//	int wlan_idx_orig = wlan_idx;
#endif //FOR_DUAL_BAND
	/*
	if ( !mib_init()) {
		printf("Initialize AP MIB failed!\n");
		return -1;
	}
	*/
	fprintf(stderr, "Writing file %s...\n", out ? out : "");
	mib_get(MIB_WSC_PIN, (void *)tmpbuf);
	if (genpin || !strcmp(tmpbuf, "\x0")) {
		#include <sys/time.h>			
		struct timeval tod;
		unsigned long num;
		
		mib_get(MIB_ELAN_MAC_ADDR/*MIB_HW_NIC0_ADDR*/, (void *)&tmp1);			
		gettimeofday(&tod , NULL);
		tod.tv_sec += tmp1[4]+tmp1[5];		
		srand(tod.tv_sec);
		num = rand() % 10000000;
		num = num*10 + compute_pin_checksum(num);
		convert_hex_to_ascii((unsigned long)num, tmpbuf);

		mib_set(MIB_WSC_PIN, (void *)tmpbuf);
		mib_update(CURRENT_SETTING, CONFIG_MIB_ALL);	

		printf("Generated PIN = %s\n", tmpbuf);

		if (genpin)
			return 0;
	}
#ifdef FOR_DUAL_BAND
//	wlan_idx = 0;
#endif //FOR_DUAL_BAND
#if defined(CONFIG_RTL_92D_SUPPORT) || defined(FOR_DUAL_BAND)
	//orig_wlan_idx = wlan_idx;
	//wlan_idx = 0;
	//if (useWlanIfVirtIdx())
	//		wlan_idx = 1;
#endif
	if (stat(in, &status) < 0) {
		printf("stat() error [%s]!\n", in);
		//return -1;
		goto ERROR;
	}

	buf = malloc(status.st_size+2048);
	if (buf == NULL) {
		printf("malloc() error [%d]!\n", (int)status.st_size+2048);
		//return -1;
		goto ERROR;
	}

	ptr = buf;
	//mib_get(gMIB_WLAN_MODE, (void *)&is_client);
	is_client = Entry->wlanMode;

	is_config = Entry->wsc_configured;

	mib_local_mapping_get(MIB_WSC_REGISTRAR_ENABLED, wlanIdx, (void *)&is_registrar); //root
	if (is_client == WPS_CLIENT_MODE) {
		if (is_registrar)
			intVal = MODE_CLIENT_CONFIG;			
		else {
			if (!is_config)
				intVal = MODE_CLIENT_UNCONFIG;
			else
				intVal = MODE_CLIENT_CONFIG;
		}
	}
	else {
		is_registrar = 1; // always true in AP		
		if (!is_config)
			intVal = MODE_AP_UNCONFIG;
		else {
			if (is_registrar)
				intVal = MODE_AP_PROXY_REGISTRAR;
			else
				intVal = MODE_AP_PROXY;
		}		
	}
	WRITE_WSC_PARAM(ptr, tmpbuf, "mode = %d\n", intVal);

	if (is_client)
		intVal = 0;
	else
		intVal = Entry->wsc_upnp_enabled; //vap

#ifdef WLAN_WPS_MULTI_DAEMON
	if(!is_client){
		if(wlanIdx == 0) //check upnp enabled only for ssid-1
			intVal = Entry->wsc_upnp_enabled;
		else
			intVal = 0;
	}
#endif

	WRITE_WSC_PARAM(ptr, tmpbuf, "upnp = %d\n", intVal);

#ifdef WPS20
#ifdef WPS_VERSION_CONFIGURABLE
	if (mib_get(MIB_WSC_VERSION, (void *)&current_wps_version) == 0)
#endif
		current_wps_version = WPS_VERSION_V2;
#else
	current_wps_version = WPS_VERSION_V1;
#endif
	WRITE_WSC_PARAM(ptr, tmpbuf, "current_wps_version = %d\n", current_wps_version);

	intVal = 0;
	mib_local_mapping_get(MIB_WSC_METHOD, wlanIdx, (void *)&intVal); //root
#ifdef WPS20
	if (current_wps_version == WPS_VERSION_V2) {
		if (intVal == 1) //Pin
			config_method = CONFIG_METHOD_VIRTUAL_PIN;
		else if (intVal == 2) //PBC
			config_method = (CONFIG_METHOD_PHYSICAL_PBC | CONFIG_METHOD_VIRTUAL_PBC);
		else if (intVal == 3) //Pin+PBC
			config_method = (CONFIG_METHOD_VIRTUAL_PIN |  CONFIG_METHOD_PHYSICAL_PBC | CONFIG_METHOD_VIRTUAL_PBC);
	} else
#endif
	{
		//Ethernet(0x2)+Label(0x4)+PushButton(0x80) Bitwise OR
		if (intVal == 1) //Pin+Ethernet
			config_method = (CONFIG_METHOD_ETH | CONFIG_METHOD_PIN);
		else if (intVal == 2) //PBC+Ethernet
			config_method = (CONFIG_METHOD_ETH | CONFIG_METHOD_PBC);
		else if (intVal == 3) //Pin+PBC+Ethernet
			config_method = (CONFIG_METHOD_ETH | CONFIG_METHOD_PIN | CONFIG_METHOD_PBC);
	}
	
#ifdef CONFIG_YUEME
	config_method &= ~(CONFIG_METHOD_VIRTUAL_PIN | CONFIG_METHOD_PIN );
#endif

	WRITE_WSC_PARAM(ptr, tmpbuf, "config_method = %d\n", config_method);

#if 0 //def FOR_DUAL_BAND
	mib_get(gMIB_WSC_DISABLE, (void *)&intVal2);
	WRITE_WSC_PARAM(ptr, tmpbuf, "wlan0_wsc_disabled = %d\n", intVal2);
#endif
	
	intVal2 = Entry->wsc_auth;
	WRITE_WSC_PARAM(ptr, tmpbuf, "auth_type = %d\n", intVal2);

	intVal = Entry->wsc_enc;
	WRITE_WSC_PARAM(ptr, tmpbuf, "encrypt_type = %d\n", intVal);
	if (intVal == WSC_ENCRYPT_WEP)
		is_wep = 1;
	
	/*for detial mixed mode info*/
	wlan_encrypt = Entry->encrypt;
	//mib_get(gMIB_WLAN_ENCRYPT, (void *)&wlan_encrypt);
	wlan_wpa_cipher = Entry->unicastCipher;
	//mib_get(gMIB_WLAN_WPA_CIPHER_SUITE, (void *)&wlan_wpa_cipher);
	wlan_wpa2_cipher = Entry->wpa2UnicastCipher;
	//mib_get(gMIB_WLAN_WPA2_CIPHER_SUITE, (void *)&wlan_wpa2_cipher);
	
	intVal=0;	
	if(wlan_encrypt==6){	// mixed mode
		if(wlan_wpa_cipher==1){
			intVal |= WSC_WPA_TKIP;
		}else if(wlan_wpa_cipher==2){
			intVal |= WSC_WPA_AES;
		}else if(wlan_wpa_cipher==3){
			intVal |= (WSC_WPA_TKIP | WSC_WPA_AES);
		}
		if(wlan_wpa2_cipher==1){
			intVal |= WSC_WPA2_TKIP;
		}else if(wlan_wpa2_cipher==2){
			intVal |= WSC_WPA2_AES;
		}else if(wlan_wpa2_cipher==3){
			intVal |= (WSC_WPA2_TKIP | WSC_WPA2_AES);
		}
	}
	WRITE_WSC_PARAM(ptr, tmpbuf, "mixedmode = %d\n", intVal);
	/*for detial mixed mode info*/

	if (is_client) {
		mib_local_mapping_get(MIB_WLAN_NETWORK_TYPE, wlanIdx, (void *)&intVal); //root
		if (intVal == 0)
			intVal = 1;
		else
			intVal = 2;
	}
	else
		intVal = 1;
	WRITE_WSC_PARAM(ptr, tmpbuf, "connection_type = %d\n", intVal);

	mib_local_mapping_get(MIB_WSC_MANUAL_ENABLED, wlanIdx, (void *)&intVal); //root
	WRITE_WSC_PARAM(ptr, tmpbuf, "manual_config = %d\n", intVal);

	if (is_wep) { // only allow WEP in none-MANUAL mode (configured by external registrar)
		intVal = Entry->encrypt; 
		//mib_get(gMIB_WLAN_ENCRYPT, (void *)&intVal);
		if (intVal != _ENCRYPT_WEP_) {
			printf("WEP mismatched between WPS and host system\n");
			goto ERROR;
		}
		intVal = Entry->wep; 
		//mib_get(gMIB_WLAN_WEP, (void *)&intVal);
		if (intVal <= WEP_DISABLED || intVal > WEP128) {
			printf("WEP encrypt length error\n");
			goto ERROR;
		}
		wep_key_type = Entry->wepKeyType;
		//mib_get(gMIB_WLAN_WEP_KEY_TYPE, (void *)&wep_key_type);
		//mib_get(MIB_WLAN_WEP_DEFAULT_KEY, (void *)&wep_transmit_key);
		wep_transmit_key = Entry->wepDefaultKey;
		wep_transmit_key++;
		WRITE_WSC_PARAM(ptr, tmpbuf, "wep_transmit_key = %d\n", wep_transmit_key);
		if (intVal == WEP64) {
			strcpy(tmpbuf,Entry->wep64Key1);
			//mib_get(gMIB_WLAN_WEP64_KEY1, (void *)&tmpbuf);
			if (wep_key_type == KEY_ASCII) {
				memcpy(tmp1, tmpbuf, 5);
				tmp1[5] = '\0';
			}
			else {
				convert_bin_to_str(tmpbuf, 5, tmp1);
				tmp1[10] = '\0';
			}			
			WRITE_WSC_PARAM(ptr, tmpbuf, "network_key = %s\n", tmp1);
			
			//mib_get(gMIB_WLAN_WEP64_KEY2, (void *)&tmpbuf); //vap
			strcpy(tmpbuf,Entry->wep64Key2);
			if (wep_key_type == KEY_ASCII) {
				memcpy(tmp1, tmpbuf, 5);
				tmp1[5] = '\0';
			}
			else {
				convert_bin_to_str(tmpbuf, 5, tmp1);
				tmp1[10] = '\0';
			}			
			WRITE_WSC_PARAM(ptr, tmpbuf, "wep_key2 = %s\n", tmp1);

			//mib_get(gMIB_WLAN_WEP64_KEY3, (void *)&tmpbuf); //vap
			strcpy(tmpbuf,Entry->wep64Key3);
			if (wep_key_type == KEY_ASCII) {
				memcpy(tmp1, tmpbuf, 5);
				tmp1[5] = '\0';
			}
			else {
				convert_bin_to_str(tmpbuf, 5, tmp1);
				tmp1[10] = '\0';
			}			
			WRITE_WSC_PARAM(ptr, tmpbuf, "wep_key3 = %s\n", tmp1);


			//mib_get(gMIB_WLAN_WEP64_KEY4, (void *)&tmpbuf); //vap
			strcpy(tmpbuf,Entry->wep64Key4);
			if (wep_key_type == KEY_ASCII) {
				memcpy(tmp1, tmpbuf, 5);
				tmp1[5] = '\0';
			}
			else {
				convert_bin_to_str(tmpbuf, 5, tmp1);
				tmp1[10] = '\0';
			}			
			WRITE_WSC_PARAM(ptr, tmpbuf, "wep_key4 = %s\n", tmp1);

		}
		else {
			strcpy(tmpbuf, Entry->wep128Key1);
			//mib_get(gMIB_WLAN_WEP128_KEY1, (void *)&tmpbuf);
			if (wep_key_type == KEY_ASCII) {
				memcpy(tmp1, tmpbuf, 13);
				tmp1[13] = '\0';
			}
			else {
				convert_bin_to_str(tmpbuf, 13, tmp1);
				tmp1[26] = '\0';
			}
			WRITE_WSC_PARAM(ptr, tmpbuf, "network_key = %s\n", tmp1);

			//mib_get(gMIB_WLAN_WEP128_KEY2, (void *)&tmpbuf); //vap
			strcpy(tmpbuf, Entry->wep128Key2);
			if (wep_key_type == KEY_ASCII) {
				memcpy(tmp1, tmpbuf, 13);
				tmp1[13] = '\0';
			}
			else {
				convert_bin_to_str(tmpbuf, 13, tmp1);
				tmp1[26] = '\0';
			}
			WRITE_WSC_PARAM(ptr, tmpbuf, "wep_key2 = %s\n", tmp1);

			//mib_get(gMIB_WLAN_WEP128_KEY3, (void *)&tmpbuf); //vap
			strcpy(tmpbuf, Entry->wep128Key3);
			if (wep_key_type == KEY_ASCII) {
				memcpy(tmp1, tmpbuf, 13);
				tmp1[13] = '\0';
			}
			else {
				convert_bin_to_str(tmpbuf, 13, tmp1);
				tmp1[26] = '\0';
			}
			WRITE_WSC_PARAM(ptr, tmpbuf, "wep_key3 = %s\n", tmp1);

			//mib_get(gMIB_WLAN_WEP128_KEY4, (void *)&tmpbuf); //vap
			strcpy(tmpbuf, Entry->wep128Key4);
			if (wep_key_type == KEY_ASCII) {
				memcpy(tmp1, tmpbuf, 13);
				tmp1[13] = '\0';
			}
			else {
				convert_bin_to_str(tmpbuf, 13, tmp1);
				tmp1[26] = '\0';
			}
			WRITE_WSC_PARAM(ptr, tmpbuf, "wep_key4 = %s\n", tmp1);

		}
	}
	else {
		strcpy(tmp1, Entry->wpaPSK);
		//mib_get(gMIB_WLAN_WPA_PSK, (void *)&tmp1);		
		WRITE_WSC_PARAM(ptr, tmpbuf, "network_key = %s\n", tmp1);
	}

//	mib_get(gMIB_WLAN_SSID, (void *)&tmp1);	
//	WRITE_WSC_PARAM(ptr, tmpbuf, "ssid = %s\n", tmp1);	
	WRITE_WSC_PARAM(ptr, tmpbuf, "ssid = %s\n", Entry->ssid);	

#if 0	
//	}
//	else {			
		mib_get(MIB_WSC_PSK, (void *)&tmp1);
		WRITE_WSC_PARAM(ptr, tmpbuf, "network_key = %s\n", tmp1);		
		
		mib_get(MIB_WSC_SSID, (void *)&tmp1);
		WRITE_WSC_PARAM(ptr, tmpbuf, "ssid = %s\n", tmp1);
//	}
#endif

	mib_get(MIB_WSC_PIN, (void *)&tmp1);
	WRITE_WSC_PARAM(ptr, tmpbuf, "pin_code = %s\n", tmp1);

	mib_local_mapping_get(MIB_WLAN_CHAN_NUM, wlanIdx, (void *)&intVal);
	if (intVal > 14)
		intVal = 2;
	else
		intVal = 1;
	WRITE_WSC_PARAM(ptr, tmpbuf, "rf_band = %d\n", intVal);

#ifdef FOR_DUAL_BAND
#ifdef CONFIG_RTL_92D_DMDP
mib_get(MIB_WLAN_BAND2G5G_SELECT, (void *)&wlanBand2G5GSelect);
if(wlanBand2G5GSelect == BANDMODEBOTH){
#endif
	//wlan_idx = 1;

	WRITE_WSC_PARAM(ptr, tmpbuf, "#=====wlan1 start==========%d\n",intVal);

	mib_local_mapping_get(MIB_WSC_DISABLE, wlanIdx, (void *)&intVal2);
	WRITE_WSC_PARAM(ptr, tmpbuf, "wlan1_wsc_disabled = %d\n", intVal2);

	mib_local_mapping_get(MIB_WLAN_SSID, wlanIdx, (void *)&tmp1); 
	WRITE_WSC_PARAM(ptr, tmpbuf, "ssid2 = %s\n", tmp1);

	mib_local_mapping_get(MIB_WSC_AUTH, wlanIdx, (void *)&intVal2);
	WRITE_WSC_PARAM(ptr, tmpbuf, "auth_type2 = %d\n", intVal2);

	mib_local_mapping_get(MIB_WSC_ENC, wlanIdx, (void *)&intVal);
	WRITE_WSC_PARAM(ptr, tmpbuf, "encrypt_type2 = %d\n", intVal);
	if (intVal == ENCRYPT_WEP)
		is_wep = 1;
	
	/*for detial mixed mode info*/
	mib_local_mapping_get(MIB_WLAN_ENCRYPT, wlanIdx, (void *)&wlan_encrypt);
	mib_local_mapping_get(MIB_WLAN_WPA_CIPHER_SUITE, wlanIdx, (void *)&wlan_wpa_cipher);
	mib_local_mapping_get(MIB_WLAN_WPA2_CIPHER_SUITE, wlanIdx, (void *)&wlan_wpa2_cipher);
	
	intVal=0;	
	if(wlan_encrypt==6){	// mixed mode
		if(wlan_wpa_cipher==1){
			intVal |= WSC_WPA_TKIP;
		}else if(wlan_wpa_cipher==2){
			intVal |= WSC_WPA_AES;		
		}else if(wlan_wpa_cipher==3){
			intVal |= (WSC_WPA_TKIP | WSC_WPA_AES);		
		}
		if(wlan_wpa2_cipher==1){
			intVal |= WSC_WPA2_TKIP;
		}else if(wlan_wpa2_cipher==2){
			intVal |= WSC_WPA2_AES;		
		}else if(wlan_wpa2_cipher==3){
			intVal |= (WSC_WPA2_TKIP | WSC_WPA2_AES);		
		}		
	}
	WRITE_WSC_PARAM(ptr, tmpbuf, "mixedmode2 = %d\n", intVal);
	/*for detial mixed mode info*/
	
/* 
	mib_get(gMIB_WLAN_BAND2G5G_SELECT, (void *)&intVal);	// 0:2.4g  ; 1:5G   ; 2:both(dual band)
	if(intVal != 2) {
		intVal=1;
		WRITE_WSC_PARAM(ptr, tmpbuf, "wlan1_wsc_disabled = %d\n",intVal);
	}
	else {
		mib_get(gMIB_WSC_DISABLE, (void *)&intVal);
		WRITE_WSC_PARAM(ptr, tmpbuf, "wlan1_wsc_disabled = %d\n", intVal);	
	}
*/
	if (is_wep) { // only allow WEP in none-MANUAL mode (configured by external registrar)
		mib_local_mapping_get(MIB_WLAN_ENCRYPT, wlanIdx, (void *)&intVal);
		if (intVal != _ENCRYPT_WEP_) {
			printf("WEP mismatched between WPS and host system\n");
			goto ERROR;
		}
		mib_local_mapping_get(MIB_WLAN_WEP, wlanIdx, (void *)&intVal);
		if (intVal <= WEP_DISABLED || intVal > WEP128) {
			printf("WEP encrypt length error\n");
			goto ERROR;
		}
		mib_local_mapping_get(MIB_WLAN_WEP_KEY_TYPE, wlanIdx, (void *)&wep_key_type);
		mib_local_mapping_get(MIB_WLAN_WEP_DEFAULT_KEY, wlanIdx, (void *)&wep_transmit_key);
		wep_transmit_key++;
		WRITE_WSC_PARAM(ptr, tmpbuf, "wep_transmit_key2 = %d\n", wep_transmit_key);
		if (intVal == WEP64) {
			mib_local_mapping_get(MIB_WLAN_WEP64_KEY1, wlanIdx, (void *)&tmpbuf);
			if (wep_key_type == KEY_ASCII) {
				memcpy(tmp1, tmpbuf, 5);
				tmp1[5] = '\0';
			}
			else {
				convert_bin_to_str(tmpbuf, 5, tmp1);
				tmp1[10] = '\0';
			}			
			WRITE_WSC_PARAM(ptr, tmpbuf, "network_key2 = %s\n", tmp1);

			mib_local_mapping_get(MIB_WLAN_WEP64_KEY2, wlanIdx, (void *)&tmpbuf);
			if (wep_key_type == KEY_ASCII) {
				memcpy(tmp1, tmpbuf, 5);
				tmp1[5] = '\0';
			}
			else {
				convert_bin_to_str(tmpbuf, 5, tmp1);
				tmp1[10] = '\0';
			}			
			WRITE_WSC_PARAM(ptr, tmpbuf, "wep_key22 = %s\n", tmp1);

			mib_local_mapping_get(MIB_WLAN_WEP64_KEY3, wlanIdx, (void *)&tmpbuf);
			if (wep_key_type == KEY_ASCII) {
				memcpy(tmp1, tmpbuf, 5);
				tmp1[5] = '\0';
			}
			else {
				convert_bin_to_str(tmpbuf, 5, tmp1);
				tmp1[10] = '\0';
			}			
			WRITE_WSC_PARAM(ptr, tmpbuf, "wep_key32 = %s\n", tmp1);


			mib_local_mapping_get(MIB_WLAN_WEP64_KEY4, wlanIdx, (void *)&tmpbuf);
			if (wep_key_type == KEY_ASCII) {
				memcpy(tmp1, tmpbuf, 5);
				tmp1[5] = '\0';
			}
			else {
				convert_bin_to_str(tmpbuf, 5, tmp1);
				tmp1[10] = '\0';
			}			
			WRITE_WSC_PARAM(ptr, tmpbuf, "wep_key42 = %s\n", tmp1);
		}
		else {
			mib_local_mapping_get(MIB_WLAN_WEP128_KEY1, wlanIdx, (void *)&tmpbuf);
			if (wep_key_type == KEY_ASCII) {
				memcpy(tmp1, tmpbuf, 13);
				tmp1[13] = '\0';
			}
			else {
				convert_bin_to_str(tmpbuf, 13, tmp1);
				tmp1[26] = '\0';
			}
			WRITE_WSC_PARAM(ptr, tmpbuf, "network_key2 = %s\n", tmp1);

			mib_local_mapping_get(MIB_WLAN_WEP128_KEY2, wlanIdx, (void *)&tmpbuf);
			if (wep_key_type == KEY_ASCII) {
				memcpy(tmp1, tmpbuf, 13);
				tmp1[13] = '\0';
			}
			else {
				convert_bin_to_str(tmpbuf, 13, tmp1);
				tmp1[26] = '\0';
			}
			WRITE_WSC_PARAM(ptr, tmpbuf, "wep_key22 = %s\n", tmp1);

			mib_local_mapping_get(MIB_WLAN_WEP128_KEY3, wlanIdx, (void *)&tmpbuf);
			if (wep_key_type == KEY_ASCII) {
				memcpy(tmp1, tmpbuf, 13);
				tmp1[13] = '\0';
			}
			else {
				convert_bin_to_str(tmpbuf, 13, tmp1);
				tmp1[26] = '\0';
			}
			WRITE_WSC_PARAM(ptr, tmpbuf, "wep_key32 = %s\n", tmp1);

			mib_local_mapping_get(MIB_WLAN_WEP128_KEY4, wlanIdx, (void *)&tmpbuf);
			if (wep_key_type == KEY_ASCII) {
				memcpy(tmp1, tmpbuf, 13);
				tmp1[13] = '\0';
			}
			else {
				convert_bin_to_str(tmpbuf, 13, tmp1);
				tmp1[26] = '\0';
			}
			WRITE_WSC_PARAM(ptr, tmpbuf, "wep_key42 = %s\n", tmp1);
		}
	}
	else {
		mib_local_mapping_get(MIB_WLAN_WPA_PSK, wlanIdx, (void *)&tmp1);
		WRITE_WSC_PARAM(ptr, tmpbuf, "network_key2 = %s\n", tmp1);
		
	}
	intVal =2 ;
	WRITE_WSC_PARAM(ptr, tmpbuf, "#=====wlan1 end==========%d\n",intVal);
//	wlan_idx = 0;
#ifdef CONFIG_RTL_92D_DMDP
}
#endif
#endif //FOR_DUAL_BAND

/*
	mib_get(MIB_HW_MODEL_NUM, (void *)&tmp1);	
	WRITE_WSC_PARAM(ptr, tmpbuf, "model_num = \"%s\"\n", tmp1);	

	mib_get(MIB_HW_SERIAL_NUM, (void *)&tmp1);	
	WRITE_WSC_PARAM(ptr, tmpbuf, "serial_num = \"%s\"\n", tmp1);	
*/
	mib_get(MIB_SNMP_SYS_NAME, (void *)&tmp1);	
	WRITE_WSC_PARAM(ptr, tmpbuf, "device_name = \"%s\"\n", tmp1);	

	len = (int)(((long)ptr)-((long)buf));
	
	fh = open(in, O_RDONLY);
	if (fh == -1) {
		printf("open() error [%s]!\n", in);
		goto ERROR;
	}

	lseek(fh, 0L, SEEK_SET);
	if (read(fh, ptr, status.st_size) != status.st_size) {		
		printf("read() error [%s]!\n", in);
		//return -1;	
		goto ERROR;
	}
	close(fh);

	// search UUID field, replace last 12 char with hw mac address
	ptr = strstr(ptr, "uuid =");
	if (ptr) {
		char tmp2[100];
		mib_get(MIB_ELAN_MAC_ADDR/*MIB_HW_NIC0_ADDR*/, (void *)&tmp1);	
		convert_bin_to_str(tmp1, 6, tmp2);
		memcpy(ptr+27, tmp2, 12);		
	}

	fh = open(out, O_RDWR|O_CREAT|O_TRUNC);
	if (fh == -1) {
		printf("open() error [%s]!\n", out);
		//return -1;
		goto ERROR;
	}

	if (write(fh, buf, len+status.st_size) != len+status.st_size ) {
		printf("Write() file error [%s]!\n", out);
		goto ERROR;
	}

	unsigned int wps_timeout;
	mib_get(MIB_WPS_TIMEOUT, &wps_timeout);
	sprintf(tmpbuf, "pbc_walk_time = %u\n", wps_timeout);
	write(fh, tmpbuf, strlen(tmpbuf));

	close(fh);
	free(buf);
#if defined(CONFIG_RTL_92D_SUPPORT) || defined(FOR_DUAL_BAND)
	//wlan_idx = orig_wlan_idx;
#endif
#ifdef FOR_DUAL_BAND
//	wlan_idx = wlan_idx_orig;
#endif //FOR_DUAL_BAND
	return 0;

ERROR:
	if (buf) free(buf);
	if (-1 != fh) close(fh);
#if defined(CONFIG_RTL_92D_SUPPORT) || defined(FOR_DUAL_BAND)
	//wlan_idx = orig_wlan_idx;
#endif
#ifdef FOR_DUAL_BAND
//	wlan_idx = wlan_idx_orig;
#endif //FOR_DUAL_BAND
	return -1;
}
#endif

#ifdef _PRMT_X_WLANFORISP_
static int getWlanForISPEntry(int vwlan_idx, MIB_WLANFORISP_Tp pEntry)
{
	int i, total = mib_chain_total(MIB_WLANFORISP_TBL);
	int ssid_idx = wlan_idx*(1+WLAN_MBSSID_NUM)+(1+vwlan_idx);
		
	for(i=0; i<total; i++){
		if(mib_chain_get(MIB_WLANFORISP_TBL, i, pEntry)==0)
			continue;
		if(pEntry->SSID_IDX == ssid_idx){
			return 0;
		}
	}
	return -1;
}
#endif

/*
 *	vwlan_idx:
 *	0:	Root
 *	1 ~ 4:	VAP
 *	5:	Repeater
 */
static int wlanItfUpAndStartAuth(int vwlan_idx, config_wlan_ssid ssid_index)
{
	int auth_pid_fd=-1;
#if 0 //def WLAN_WPS_VAP
	int wsc_pid_fd=-1;
#endif
	int status=0;
	char ifname[16];
	char ifname2[16];
	char para_auth_conf[30];
	char para_auth_fifo[30];
#ifdef WLAN_WPS_VAP
	char wsc_conf[30];
	char wsc_fifo[30];
	char wscd_pid_name[32];
#endif
	MIB_CE_MBSSIB_T Entry;
#ifdef WLAN_UNIVERSAL_REPEATER
	char rpt_enabled;
#endif
#ifdef WLAN_WISP
	unsigned int wan_mode;
	char wlanmode;
	int wisp_wan_id;
#endif
#if 0 //def WLAN_WPS_VAP
	//unsigned char no_wlan;
	unsigned char encrypt;
	unsigned char wsc_disable;
	unsigned char wlan_mode;
	unsigned char wlan_nettype;
	unsigned char wpa_auth;
	unsigned char wps_ssid;
#endif

#ifdef _PRMT_X_WLANFORISP_
	MIB_WLANFORISP_T wlan_isp_entry;
#endif

#ifdef WLAN_FAST_INIT
		if(ssid_index != CONFIG_SSID_ALL && ssid_index != vwlan_idx)
			return 0;
#endif

	mib_chain_get(MIB_MBSSIB_TBL, vwlan_idx, (void *)&Entry);

	if (vwlan_idx==0) {
		strncpy(ifname, (char*)getWlanIfName(), 16);
	}
	else {
		#ifdef WLAN_MBSSID
		if (vwlan_idx>=WLAN_VAP_ITF_INDEX && vwlan_idx<(WLAN_VAP_ITF_INDEX+WLAN_MBSSID_NUM))
			snprintf(ifname, 16, "%s-vap%d", (char *)getWlanIfName(), vwlan_idx-1);
		#endif
		#ifdef WLAN_UNIVERSAL_REPEATER
		if (vwlan_idx == WLAN_REPEATER_ITF_INDEX) {
			snprintf(ifname, 16, "%s-vxd", (char *)getWlanIfName());
			mib_get( MIB_REPEATER_ENABLED1, (void *)&rpt_enabled);
			if (rpt_enabled)
				Entry.wlanDisabled=0;
			else
				Entry.wlanDisabled=1;
		}
		#endif
	}

	if (Entry.wlanDisabled == 0 || (vwlan_idx==0 
#if !defined(CONFIG_YUEME)
	&& vap_enable_status()
#endif
	))	// WLAN enabled
	{
#ifdef WLAN_WISP
	mib_get( MIB_WAN_MODE, (void *)&wan_mode);
	wlanmode = Entry.wlanMode;
#ifdef WLAN_UNIVERSAL_REPEATER
	mib_get( MIB_REPEATER_ENABLED1, (void *)&rpt_enabled);
#endif
	getWispWanID(&wisp_wan_id);
	if(!(wan_mode & MODE_Wlan) || wisp_wan_id!=wlan_idx
#ifdef WLAN_UNIVERSAL_REPEATER
		|| (vwlan_idx != WLAN_REPEATER_ITF_INDEX && (wlanmode==AP_MODE || wlanmode==AP_WDS_MODE) && rpt_enabled) //vxd is WISP interface, add root & vap to bridge
		//|| (vwlan_idx == WLAN_REPEATER_ITF_INDEX && wlanmode==CLIENT_MODE) //root is WISP interface, add vxd to bridge
#endif
	){
#endif
		// brctl addif br0 wlan0
#if defined(CONFIG_MASTER_WLAN0_ENABLE) && defined(CONFIG_SLAVE_WLAN1_ENABLE)
		if( strncmp(ifname, "wlan1", 5) || !strcmp(ifname, "wlan1") )
			status|=va_cmd(BRCTL, 3, 1, "addif", (char *)BRIF, ifname);
#elif defined(CONFIG_SLAVE_WLAN1_ENABLE)
		if( !strcmp(ifname, WLANIF[0]))
			status|=va_cmd(BRCTL, 3, 1, "addif", (char *)BRIF, ifname);
#else

		status|=va_cmd(BRCTL, 3, 1, "addif", (char *)BRIF, ifname);
#ifdef WLAN_WISP
		if(vwlan_idx == WLAN_REPEATER_ITF_INDEX)
			setWlanDevFlag(ifname, 0);
#endif
#endif
#ifdef WLAN_WISP
	}else{
		if(vwlan_idx == WLAN_REPEATER_ITF_INDEX)
			setWlanDevFlag(ifname, 1);
	}
#endif
#ifdef CONFIG_IPV6
		// Disable ipv6 in bridge
		setup_disable_ipv6(ifname, 1);
#endif
		if(vwlan_idx==0){
			if(Entry.wlanDisabled
#if !defined(CONFIG_YUEME)
			&& vap_enable_status()
#endif
			)
				status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", "func_off=1");
			else
				status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", "func_off=0");
		}
#ifdef CONFIG_YUEME
		if(vwlan_idx==0)
			applyWlanLed(wlan_idx);
#endif
		// ifconfig wlan0 up
		status|=va_cmd(IFCONFIG, 2, 1, ifname, "up");

#ifdef WLAN_1x
		snprintf(para_auth_conf, sizeof(para_auth_conf), "/var/config/%s.conf", ifname);
		snprintf(para_auth_fifo, sizeof(para_auth_fifo), "/var/auth-%s.fifo", ifname);
		if (is8021xEnabled(vwlan_idx)) // 802.1x enabled, auth is only used when 802.1x is enable since encryption is driver based in 11n driver
		{ // Magician: Fixed parsing error by Source Insight
#ifdef _PRMT_X_WLANFORISP_
			//for e8, auth only enable when WlanForISP is set.
			if(getWlanForISPEntry(vwlan_idx, &wlan_isp_entry)<0){
				printf("%s %d: WLANForISP not sync, please check!!\n", __func__, __LINE__);
				return -1;
			}		
			status|=generateWpaConf(para_auth_conf, 0, &Entry, &wlan_isp_entry);	
#ifdef CONFIG_YUEME
			strcpy(ifname2, "any");
#else	
			if(getWLANForISP_ifname(ifname2, &wlan_isp_entry)<0)
				strcpy(ifname2, LANIF);
#endif
#else
#ifdef CONFIG_YUEME
			strcpy(ifname2, "any");
#else
			status|=generateWpaConf(para_auth_conf, 0, &Entry);
			strcpy(ifname2, LANIF);
#endif

#endif
			status|=va_niced_cmd(AUTH_DAEMON, 4, 0, ifname, ifname2, "auth", para_auth_conf);
			// fix the depency problem
			// check fifo
			int i = 0;
			while ((auth_pid_fd = open(para_auth_fifo, O_WRONLY)) == -1 && i < 10)
 			{
				usleep(100000);
				i++;
			}
			if(auth_pid_fd!=-1) close(auth_pid_fd);/*jiunming, close the opened fd*/
			if (vwlan_idx == 0){ // Root
			        /* 2010-10-27 krammer :  use bit map to record what wlan root interface is use for auth*/
			if(useWlanIfVirtIdx())
				useAuth_RootIf |= 1;
			else
				useAuth_RootIf |= (1<<wlan_idx);//bit 0 ==> wlan0, bit 1 ==>wlan1
			}
			else {
				strcpy(para_iwctrl[wlan_num], ifname);
				wlan_num++;
			}
		}
#endif
		status = (status==-1)?-1:1;
	}
	else
		return 0;

}

#ifdef WLAN_WEB_REDIRECT  //jiunming,web_redirect
int start_wlan_web_redirect(){

	int status=0;
	char tmpbuf[MAX_URL_LEN];
	char ipaddr[16], ip_port[32], redir_server[33];

	ipaddr[0]='\0'; ip_port[0]='\0';redir_server[0]='\0';
	if (mib_get(MIB_ADSL_LAN_IP, (void *)tmpbuf) != 0)
	{
		strncpy(ipaddr, inet_ntoa(*((struct in_addr *)tmpbuf)), 16);
		ipaddr[15] = '\0';
		snprintf(ip_port, sizeof(ip_port), "%s:%d",ipaddr,8080);
	}//else ??

	if( mib_get(MIB_WLAN_WEB_REDIR_URL, (void*)tmpbuf) )
	{
		char *p=NULL, *end=NULL;

		p = strstr( tmpbuf, "http://" );
		if(p)
			p = p + 7;
		else
			p = tmpbuf;

		end = strstr( p, "/" );
		if(end)
			*end = '\0';

		snprintf( redir_server,32,"%s",p );
		redir_server[32]='\0';
	}//else ??

	// Enable Bridge Netfiltering
	//status|=va_cmd("/bin/brctl", 2, 0, "brnf", "on");

	//iptables -t nat -N Web_Redirect
	status|=va_cmd(IPTABLES, 4, 1, "-t", "nat","-N","Web_Redirect");

	//iptables -t nat -A Web_Redirect -d 192.168.1.1 -j RETURN
	status|=va_cmd(IPTABLES, 8, 1, "-t", "nat","-A","Web_Redirect",
		"-d", ipaddr, "-j", (char *)FW_RETURN);

	//iptables -t nat -A Web_Redirect -d 192.168.2.11 -j RETURN
	status|=va_cmd(IPTABLES, 8, 1, "-t", "nat","-A","Web_Redirect",
		"-d", redir_server, "-j", (char *)FW_RETURN);

	//iptables -t nat -A Web_Redirect -p tcp --dport 80 -j DNAT --to-destination 192.168.1.1:8080
	status|=va_cmd(IPTABLES, 12, 1, "-t", "nat","-A","Web_Redirect",
		"-p", "tcp", "--dport", "80", "-j", "DNAT",
		"--to-destination", ip_port);

	//iptables -t nat -A PREROUTING -p tcp --dport 80 -j Web_Redirect
	status|=va_cmd(IPTABLES, 12, 1, "-t", "nat","-A","PREROUTING",
		"-i", (char *)getWlanIfName(),
		"-p", "tcp", "--dport", "80", "-j", "Web_Redirect");

	return status;
}
#endif

#ifdef CONFIG_RTL_WAPI_SUPPORT

void wapi_cert_link_one(const char *name, const char *lnname) {
	char cmd[128];

	strcpy(cmd, "mkdir -p /var/myca/");
	system(cmd);


	strcpy(cmd, "ln -s ");
	strcat(cmd, name);
	strcat(cmd," ");
	strcat(cmd, lnname);
	system(cmd);
}

int start_aeUdpClient(void)
{
	int status=0;
	unsigned char tmpbuf[256], encrypt, wapiAuth;
	char ipaddr[16];
	extern void wapi_cert_link(void);
#ifdef WLAN_DUALBAND_CONCURRENT
	unsigned char encrypt_5g, wapiAuth_5g;
	MIB_CE_MBSSIB_T mEntry_5g;
#endif
	int i=0;

	MIB_CE_MBSSIB_T mEntry;
	wlan_idx=0;
	wlan_getEntry(&mEntry, 0);
	encrypt = mEntry.encrypt;
	wapiAuth = mEntry.wapiAuth;
#ifdef WLAN_DUALBAND_CONCURRENT
	wlan_idx=1;
	wlan_getEntry(&mEntry_5g, 0);
	encrypt_5g = mEntry_5g.encrypt;
	wapiAuth_5g = mEntry_5g.wapiAuth;
#endif

	system("/bin/killall aseUdpServer");
//	mib_get(MIB_WLAN_ENCRYPT, (void *)&encrypt);
//	mib_get(MIB_WLAN_WAPI_AUTH, (void *)&wapiAuth);
	if ((encrypt != WIFI_SEC_WAPI || wapiAuth != 1)
#ifdef WLAN_DUALBAND_CONCURRENT
            &&(encrypt_5g != WIFI_SEC_WAPI || wapiAuth_5g != 1)
#endif
            ) {
		goto OUT;
	}
#if 0
	wapi_cert_link_one(WAPI_CA4AP_CERT_SAVE, WAPI_CA4AP_CERT);
	wapi_cert_link_one(WAPI_AP_CERT_SAVE, WAPI_AP_CERT);

	if (mib_get(MIB_WLAN_WAPI_ASIPADDR, (void *)tmpbuf) == 0)
	{
		status = -1;
		goto OUT;
	}
#endif

	system("/bin/cp /bin/wifi_wapi /var -r");

	system("/bin/wifi_wapi/aseUdpServer & ");
	strncpy(ipaddr, inet_ntoa(*((struct in_addr *)mEntry.wapiAsIpAddr)), 16);

	memset(tmpbuf, 0, sizeof(tmpbuf));
	i=sprintf(tmpbuf+i, "/bin/wifi_wapi/aeUdpClient -d %s ",ipaddr);
#ifdef WLAN_DUALBAND_CONCURRENT
	if((encrypt == WIFI_SEC_WAPI && wapiAuth == 1)&&(encrypt_5g == WIFI_SEC_WAPI && wapiAuth_5g == 1))
		i=sprintf(tmpbuf+i, "-i wlan0,wlan1 &");
	else if(encrypt_5g == WIFI_SEC_WAPI && wapiAuth_5g == 1)	
		i=sprintf(tmpbuf+i, "-i wlan1 &");
	else if(encrypt == WIFI_SEC_WAPI && wapiAuth == 1)
#endif
		i=sprintf(tmpbuf+i, "-i wlan0 &");
	fprintf(stderr, "%s(%d): %s\n", __FUNCTION__,__LINE__, tmpbuf);
	system(tmpbuf);

OUT:
	return status;
}
#endif


int start_iwcontrol()
{
	int tmp, found = 0;
	int status = 0;
	char *argv[12];

	// When (1) WPS enabled or (2) Root AP's encryption is WPA/WPA2 without MBSSID,
	// we should start iwcontrol with wlan0 interface.
	int i = 0;
    char buf[8] = {0};
	for(i = 0; useAuth_RootIf; i++){
        	if ( useAuth_RootIf & 0x00000001) {
                      //snprintf(buf, sizeof(buf), "wlan%d", i);
                      snprintf(buf, sizeof(buf), WLANIF[i]);
        		for (tmp=0; tmp < wlan_num; tmp++) {
        			if (strcmp(para_iwctrl[tmp], buf)==0) {
        				found = 1;
        				break;
        			}
        		}
        		if (!found) {
        			strcpy(para_iwctrl[wlan_num], buf);
        			wlan_num++;
        		}
        	}
               useAuth_RootIf >>= 1;
	}
	printf("Total WPA/WPA2 number is %d\n", wlan_num);
	if(wlan_num>0){
		//printf("CMD ARGS: ");
		for(i=0; i<wlan_num; i++){
			argv[i+1] = para_iwctrl[i];
		//	printf("%s", argv[i+1]);
		}
		argv[i+1]=NULL;
		//printf("\n");
		status|=do_nice_cmd(IWCONTROL, argv, 0);
#if defined(CONFIG_USER_MONITORD) && defined(CONFIG_YUEME)
		update_monitor_list_file("iwcontrol", 1);
#endif		
	}

}

// return value:
// 0  : success
// -1 : failed
int startWLanOneTimeDaemon()
{
	int status=0;
#ifdef WLAN_11R
	status |= start_FT();
#endif
#ifdef WLAN_SMARTAPP_ENABLE
	status |= start_smart_wlanapp();
#endif
#ifdef CONFIG_WIFI_SIMPLE_CONFIG
	status |= start_WPS(1);
#endif
#ifdef WLAN_WEB_REDIRECT
	status |= start_wlan_web_redirect();
#endif
#ifdef CONFIG_RTL_WAPI_SUPPORT
	status |= start_aeUdpClient();
#endif

	return status;
}
#endif

#ifdef _PRMT_X_CMCC_WLANSHARE_
#define FW_BR_WLANSHARE "WLAN_SHARE"

static int get_bound_br_wan_by_ssid_index(int ssid_index, char *wan_ifname)
{
	MIB_CE_ATM_VC_T entry;
	int total = mib_chain_total(MIB_ATM_VC_TBL);
	int i;
	int base = PMAP_WLAN0, mask = 0;

	//calculate mask
#ifdef WLAN_DUALBAND_CONCURRENT
	if(ssid_index < 1 || ssid_index > 8)
		return -1;

	if(ssid_index > 4)
	{
#if (defined(CONFIG_YUEME) || defined(CONFIG_CMCC) || defined(CONFIG_CU))&& defined(CONFIG_LUNA_DUAL_LINUX)
		base = PMAP_WLAN0; //ssid 1-4 in wlan1, ssid 5-8 in wlan0
#else
		base = PMAP_WLAN1;
#endif
		ssid_index -= 4;
	}
#if (defined(CONFIG_YUEME) || defined(CONFIG_CMCC) || defined(CONFIG_CU))&& defined(CONFIG_LUNA_DUAL_LINUX)
	else
		base = PMAP_WLAN1; //ssid 1-4 in wlan1, ssid 5-8 in wlan0
#endif
	
#else
	if(ssid_index < 1 || ssid_index > 4)
		return -1;
#endif

	mask = (1 << (base + ssid_index - 1));

	for(i = 0 ; i < total; i++)
	{
		if(mib_chain_get(MIB_ATM_VC_TBL, i, &entry) == 0)
			continue;

		if(entry.cmode != CHANNEL_MODE_BRIDGE)
			continue;

		if(entry.itfGroup & mask)
		{
			if(ifGetName(entry.ifIndex, wan_ifname, IFNAMSIZ) != NULL)
				return 0;
		}
	}

	return -1;
}

void setup_wlan_share(void)
{
	int total = mib_chain_total(MIB_WLAN_SHARE_TBL);
	int i;
	MIB_CE_WLAN_SHARE_T entry;
	char ifname[IFNAMSIZ] = {0};
	int pid = -1;
	char wan_ifname[IFNAMSIZ] = {0};

	// Stop dhcp relay
	pid = read_pid("/var/run/dhcrelay.pid");
	if(pid > 0)
	{
		kill(pid, SIGTERM);
		usleep(200000);
	}

#ifdef CONFIG_RTK_L34_ENABLE
	RG_trap_dhcp_for_wlan_share(0, 0);
#endif

	// setup ebtables rules
	va_cmd(EBTABLES, 4, 1, "-t", "broute", "-N", FW_BR_WLANSHARE);
	va_cmd(EBTABLES, 5, 1, "-t", "broute", "-P", FW_BR_WLANSHARE, "RETURN");

	// ebtables -t broute -D BROUTING -p IPv4 --ip-proto udp --ip-sport 68 --ip-dport 67 -j WLAN_SHARE
	va_cmd(EBTABLES, 14, 1, "-t", "broute", "-D", "BROUTING", "-p", "IPv4", "--ip-proto", "udp",
					"--ip-sport", "68", "--ip-dport", "67", "-j", FW_BR_WLANSHARE);

	// ebtables -t broute -A BROUTING -p IPv4 --ip-proto udp --ip-sport 68 --ip-dport 67 -j WLAN_SHARE
	va_cmd(EBTABLES, 14, 1, "-t", "broute", "-A", "BROUTING", "-p", "IPv4", "--ip-proto", "udp",
					"--ip-sport", "68", "--ip-dport", "67", "-j", FW_BR_WLANSHARE);

	va_cmd(EBTABLES, 4, 1, "-t", "broute", "-F", FW_BR_WLANSHARE);

	for(i = 0 ; i < MAX_WLAN_SHARE ; i++)
	{
		if(mib_chain_get(MIB_WLAN_SHARE_TBL, i, &entry) == 0)
			continue;

		if(get_ifname_by_ssid_index(entry.ssid_idx, ifname) < 0)
		{
			fprintf(stderr, "Get SSID%d interface name faileld\n", entry.ssid_idx);
			continue;
		}

		if(entry.userid_enable && entry.userid[0] != '\0' && get_bound_br_wan_by_ssid_index(entry.ssid_idx, wan_ifname) == 0)
		{
			//ebtables -t broute -A WLAN_SHARE -i wlan0-vap0 -j DROP
			va_cmd(EBTABLES, 8, 1, "-t", "broute", "-A", FW_BR_WLANSHARE, "-i", ifname, "-j", "DROP");

			//dhcrelayV6 -i wlan0 -o nas0_0 -4 -r 09557700844
			va_cmd(DHCREALYV6, 7, 1, "-4", "-i", ifname, "-o", wan_ifname, "-r", entry.userid);

#ifdef CONFIG_RTK_L34_ENABLE
#if (defined(CONFIG_YUEME) || defined(CONFIG_CMCC) || defined(CONFIG_CU)) && defined(CONFIG_LUNA_DUAL_LINUX)
			if(entry.ssid_idx<=4) //ssid1~4 mapping to wlan1
				RG_trap_dhcp_for_wlan_share(1, entry.ssid_idx + 4);
			else ////ssid5~8 mapping to wlan0
				RG_trap_dhcp_for_wlan_share(1, entry.ssid_idx - 4);
#else
			RG_trap_dhcp_for_wlan_share(1, entry.ssid_idx);
#endif
#endif
		}

		// only support 1 instance currently.
		break;
	}
}
#endif



//--------------------------------------------------------
// Wireless LAN startup
// return value:
// 0  : not start by configuration
// 1  : successful
// -1 : failed
int startWLan(config_wlan_target target, config_wlan_ssid ssid_index)
{
	unsigned char no_wlan, wsc_disable, wlan_mode;
	int status=0, upnppid=0;
	char *argv[9];
#if defined(CONFIG_LUNA_DUAL_LINUX)
	int ping_ret = 0, ping_cnt = 0;
#endif
	unsigned char phy_band_select;
#if defined(CONFIG_CMCC) || defined(CONFIG_CU) || defined(YUEME_3_0_SPEC)
	unsigned char wlan_hw_diabled;
	unsigned char wlan_disabled_bit=0;
	int ret;
#endif

#if 0
	// Check wireless interface
	if (!getInFlags((char *)WLANIF, 0)) {
		printf("Wireless Interface Not Found !\n");
		return -1;	// interface not found
	}

	mib_get(MIB_WLAN_DISABLED, (void *)&no_wlan);
	if (no_wlan)
		return 0;

	//1/17/06' hrchen, always start WLAN MIB, for MP test will use
	// "ifconfig wlan0 up" to start WLAN
	// config WLAN
	status|=setupWLan();
#endif
	int i = 0, active_wlan = 0, j = 0, orig_wlan_idx;
	char ifname[16];
	MIB_CE_MBSSIB_T Entry;
#ifndef YUEME_3_0_SPEC
	if(!check_wlan_module())
		return 1;
#endif
	// Modified by Mason Yu
	wlan_num = 0; /*reset to 0,jiunming*/
	useAuth_RootIf = 0;  /*reset to 0 */
	orig_wlan_idx = wlan_idx;

	//process each wlan interface
	for(i = 0; i<NUM_WLAN_INTERFACE; i++){
		wlan_idx = i;
#if defined(CONFIG_CMCC) || defined(CONFIG_CU) || defined(YUEME_3_0_SPEC)
		mib_get(MIB_WLAN_DISABLED, (void *)&wlan_hw_diabled);
		if(wlan_hw_diabled) {
			wlan_disabled_bit |= (1<<i);
			continue;
		}
#endif
		if (!getInFlags((char *)getWlanIfName(), 0)) {
			printf("Wireless Interface Not Found !\n");
			status = -1;	// interface not found
			continue;
	    }
		mib_get( MIB_WLAN_PHY_BAND_SELECT, (void *)&phy_band_select);
		if((target == CONFIG_WLAN_2G && phy_band_select == PHYBAND_5G)
		  || (target == CONFIG_WLAN_5G && phy_band_select == PHYBAND_2G)) {
			continue;
		}
		mib_chain_get(MIB_MBSSIB_TBL, 0, &Entry);
#if !defined(CONFIG_YUEME)
		no_wlan = Entry.wlanDisabled;
		if (no_wlan)
			no_wlan = vap_enable_status()? 0:1;
		if (no_wlan)
			continue;
#endif

		#if defined(CONFIG_LUNA_DUAL_LINUX)
		#if defined(CONFIG_YUEME)
		if(wlan_idx == 0)
		#else
		if(wlan_idx == 1)
		#endif
		{
			ping_ret = system("ping -w 2 10.253.253.2 > /dev/null");
			while(ping_ret != -1 && ping_ret != 0 && ping_cnt++ < 3)
			{
				ping_ret = system("ping -w 2 10.253.253.2 > /dev/null");
				sleep(2);
			}
		}

		if(ping_ret != -1 && ping_ret != 0 && wlan_idx == 1)
		{
			printf("Slave can't connect \n");
			continue;
		}
		#endif

		//interface and root is enable, now we start
		active_wlan++;
#ifdef WLAN_FAST_INIT
		setupWLan(getWlanIfName(), 0, ssid_index);
#else
		if(ssid_index==CONFIG_SSID_ALL || ssid_index==CONFIG_SSID_ROOT) {
			status|=setupWLan();
		} else {
			status|=setupWLanVap(ssid_index);
		}
		status|=setupWLan_sta_control();
#endif		
		//ifconfig wlan up ,add into bridge and start [auth<-depend on interface, so run many times]
		status |= wlanItfUpAndStartAuth(0, ssid_index);
		wlan_mode = Entry.wlanMode;
#ifdef WLAN_MBSSID
		if (wlan_mode == AP_MODE || wlan_mode == AP_WDS_MODE) {
			for (j=1; j<=WLAN_MBSSID_NUM; j++){

				if(ssid_index!=CONFIG_SSID_ALL && ssid_index!=j) {
					continue;
				}
				
#ifdef WLAN_FAST_INIT
				snprintf(ifname, sizeof(ifname), "%s-vap%d", getWlanIfName(), j-1);
				setupWLan(ifname, j, ssid_index);
#endif
			    status |= wlanItfUpAndStartAuth(j, ssid_index);
			}
		}
#endif
#ifdef WLAN_UNIVERSAL_REPEATER
		if (wlan_mode != WDS_MODE) {
			char rpt_enabled;
			mib_get(MIB_REPEATER_ENABLED1, (void *)&rpt_enabled);
			if (rpt_enabled){
#ifdef WLAN_FAST_INIT
				snprintf(ifname, sizeof(ifname), "%s-vxd", getWlanIfName());
				setupWLan(ifname, WLAN_REPEATER_ITF_INDEX, ssid_index);
#endif
			    status |= wlanItfUpAndStartAuth(WLAN_REPEATER_ITF_INDEX, ssid_index);
			}
		}
#endif

	}
	wlan_idx = orig_wlan_idx;

#if defined(WLAN_DUALBAND_CONCURRENT) && defined(YUEME_3_0_SPEC)
	//disable one wlan interface, still run daemon for anthor wlan interface
	if(active_wlan==0 && ssid_index == CONFIG_SSID_ALL && target != CONFIG_WLAN_ALL && (wlan_disabled_bit == 1 || wlan_disabled_bit == (1<<1))){
		check_iwcontrol_8021x();
	}
	else
#endif
	if(!active_wlan){
		return status;
	}
	
	RTK_RG_Config_SSID_shaping_rule();

	//start wlan daemon at last due to these daemons only need one
	status|=startWLanOneTimeDaemon();
	status|=start_iwcontrol();
#ifdef _PRMT_X_CMCC_WLANSHARE_
	setup_wlan_share();
#endif

#ifdef WLAN_SUPPORT
#ifdef CONFIG_WIFI_SIMPLE_CONFIG
#ifndef WLAN_WPS_VAP
	orig_wlan_idx = wlan_idx;
	char wscd_pid_name[32];
	for(i = 0; i<NUM_WLAN_INTERFACE; i++){
		wlan_idx = i;
#if defined(CONFIG_CMCC) || defined(CONFIG_CU) || defined(YUEME_3_0_SPEC)
		mib_get(MIB_WLAN_DISABLED, (void *)&wlan_hw_diabled);
		if(wlan_hw_diabled) {
			continue;
		}
#endif
		mib_get( MIB_WLAN_PHY_BAND_SELECT, (void *)&phy_band_select);
		if((target == CONFIG_WLAN_2G && phy_band_select == PHYBAND_5G)
		  || (target == CONFIG_WLAN_5G && phy_band_select == PHYBAND_2G)) {
			continue;
		}
		mib_chain_get(MIB_MBSSIB_TBL, 0, &Entry);
		no_wlan = Entry.wlanDisabled;
		wsc_disable = Entry.wsc_disabled;
		//upnppid = read_pid((char*)MINI_UPNPDPID);	//cathy
		if( !no_wlan && !wsc_disable && !is8021xEnabled(0)) {
			int retry = 10;
			getWscPidName(wscd_pid_name);
			while(--retry && (read_pid(wscd_pid_name) < 0))
			{
				//printf("WSCD is not running. Please wait!\n");
				usleep(300000);
			}
			startSSDP();
			break;
		}
	}
	wlan_idx = orig_wlan_idx;
#endif
#endif
#endif


	// enable samba service to mount slave's /proc/wlan0 with master /proc/wlan1
#ifdef CONFIG_SLAVE_WLAN1_ENABLE
	// check wlan1 enable or disable ?
#ifdef WLAN_DUALBAND_CONCURRENT
	orig_wlan_idx = wlan_idx ;
    wlan_idx = 1;
#endif
#if defined(CONFIG_CMCC) || defined(CONFIG_CU) || defined(YUEME_3_0_SPEC)
	mib_get(MIB_WLAN_DISABLED, (void *)&wlan_hw_diabled);
	if(wlan_hw_diabled) {
#ifdef WLAN_DUALBAND_CONCURRENT
		wlan_idx = orig_wlan_idx;
#endif
		return status;
	}
#endif
	mib_get( MIB_WLAN_PHY_BAND_SELECT, (void *)&phy_band_select);
	if((target == CONFIG_WLAN_2G && phy_band_select == PHYBAND_5G)
	  || (target == CONFIG_WLAN_5G && phy_band_select == PHYBAND_2G)) {
#ifdef WLAN_DUALBAND_CONCURRENT
		wlan_idx = orig_wlan_idx;
#endif
		return status;
	}
	mib_chain_get(MIB_MBSSIB_TBL, 0, &Entry);
	no_wlan = Entry.wlanDisabled;
	if(no_wlan){
		no_wlan = vap_enable_status()? 0:1;
	}
	if(no_wlan != 1) // enable status , need mount proc/wlan1
	{
		//check mount already ?
		FILE *mount_fp;
		int need_mount = 0;
		char mount_buf[256];

		mount_fp = fopen("/proc/mounts", "r");
		if(mount_fp)
		{
			while (fgets(mount_buf, sizeof(mount_buf), mount_fp) != NULL)
			{
				if(strstr(mount_buf,  "10.253.253.2") > 0)
				{
					need_mount++;
				}
			}
			fclose(mount_fp);
		}
		// get slave ip
		if(need_mount < 5)
		{
			va_cmd("/bin/mount", 6 , 1 , "-t" ,"cifs", "//10.253.253.2/wlan" , "/proc/wlan1" , "-o", "username=admin");
			va_cmd("/bin/mount", 6 , 1 , "-t" ,"cifs", "//10.253.253.2/wlan-vap0" , "/proc/wlan1-vap0" , "-o", "username=admin");
			va_cmd("/bin/mount", 6 , 1 , "-t" ,"cifs", "//10.253.253.2/wlan-vap1" , "/proc/wlan1-vap1" , "-o", "username=admin");
			va_cmd("/bin/mount", 6 , 1 , "-t" ,"cifs", "//10.253.253.2/wlan-vap2" , "/proc/wlan1-vap2" , "-o", "username=admin");
			va_cmd("/bin/mount", 6 , 1 , "-t" ,"cifs", "//10.253.253.2/wlan-vap3" , "/proc/wlan1-vap3" , "-o", "username=admin");
			#ifdef CONFIG_RTL_REPEATER_MODE_SUPPORT
			va_cmd("/bin/mount", 6 , 1 , "-t" ,"cifs", "//10.253.253.2/wlan-vxd" , "/proc/wlan1-vxd" , "-o", "username=admin");
			#endif		
			va_cmd("/bin/mount", 6 , 1 , "-t" ,"cifs", "//10.253.253.2/slave-tmp" , "/tmp/slave" , "-o", "username=admin");
#if defined(CONFIG_LUNA_DUAL_LINUX) && (defined(CONFIG_CMCC) || defined(CONFIG_CU))
			va_cmd("/bin/mount", 6 , 1 , "-t" ,"cifs", "//10.253.253.2/wlan-event" , "/proc/osgi/wlan1" , "-o", "username=admin");
#endif
		}
	}
#ifdef WLAN_DUALBAND_CONCURRENT
	wlan_idx = orig_wlan_idx;
#endif

#endif

#if 0 //defined(SUPPORT_ACCESS_RIGHT) && defined(CONFIG_YUEME)
	setup_wlan_realtime_acl(0);
#endif

#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	setup_wlan_MAC_ACL();
#endif

#if defined(CONFIG_YUEME)
	setup_wlan_MAC_ACL();
	setup_wlan_accessRule();
#endif

#if (defined(CONFIG_CMCC) || defined(CONFIG_CU) || defined(CONFIG_YUEME)) && defined(CONFIG_RTK_L34_ENABLE)
	ssidisolation_portmap();
#endif

	return status;
}

int getMiscData(char *interface, struct _misc_data_ *pData)
{

    int skfd;
    struct iwreq wrq;

    skfd = socket(AF_INET, SOCK_DGRAM, 0);

    /* Get wireless name */
    if ( iw_get_ext(skfd, interface, SIOCGIWNAME, &wrq) < 0){
      /* If no wireless name : no wireless extensions */
	  	close(skfd);
        return -1;
    }

    wrq.u.data.pointer = (caddr_t)pData;
    wrq.u.data.length = sizeof(struct _misc_data_);

    if (iw_get_ext(skfd, interface, SIOCGMISCDATA, &wrq) < 0){
		close(skfd);
		return -1;
    }
    close(skfd);

    return 0;
}

int getWlStaNum( char *interface, int *num )
{
    int skfd;
    unsigned short staNum;
    struct iwreq wrq;

    skfd = socket(AF_INET, SOCK_DGRAM, 0);

    /* Get wireless name */
    if ( iw_get_ext(skfd, interface, SIOCGIWNAME, &wrq) < 0) {
      close( skfd );
      /* If no wireless name : no wireless extensions */
      return -1;
    }

    wrq.u.data.pointer = (caddr_t)&staNum;
    wrq.u.data.length = sizeof(staNum);

    if (iw_get_ext(skfd, interface, SIOCGIWRTLSTANUM, &wrq) < 0) {
      close( skfd );
      return -1;
    }

    *num  = (int)staNum;

    close( skfd );

    return 0;
}

void waitWlChannelSelect(char *ifname)
{
	unsigned char buffer[10];
	int skfd;
	struct iwreq wrq;
	int query_cnt = 0;
	do {            //wait for selecting channel	
		skfd = socket(AF_INET, SOCK_DGRAM, 0);
		strcpy(wrq.ifr_name, ifname);
		strcpy(buffer,"opmode");
		wrq.u.data.pointer = (caddr_t)buffer;
		wrq.u.data.length = sizeof(buffer);
		ioctl(skfd, RTL8192CD_IOCTL_GET_MIB, &wrq);
		close( skfd );
		sleep(1);
		query_cnt ++;
	}while(buffer[0] == 0x08 && query_cnt < 10);       //WIFI_WAIT_FOR_CHANNEL_SELECT 0x08000000 (8192cd.h)
}
int getWlChannel( char *interface, unsigned int *num)
{
    int skfd;
    struct iwreq wrq;
	unsigned char buffer[32]={0};

    skfd = socket(AF_INET, SOCK_DGRAM, 0);

    /* Get wireless name */
    if ( iw_get_ext(skfd, interface, SIOCGIWNAME, &wrq) < 0)
    {
    	close( skfd );
      /* If no wireless name : no wireless extensions */
        return -1;
    }
	strcpy(buffer,"channel");
    wrq.u.data.pointer = (caddr_t)buffer;
    wrq.u.data.length = 10;

    if (iw_get_ext(skfd, interface, RTL8192CD_IOCTL_GET_MIB, &wrq) < 0)
    {
    	close( skfd );
		return -1;
    }
	*num = (unsigned int)buffer[wrq.u.data.length - 1];
    close( skfd );

    return 0;
}


/////////////////////////////////////////////////////////////////////////////
#if defined(WLAN_CLIENT) || defined(CONFIG_USER_RTK_OMD)
int getWlSiteSurveyResult(char *interface, SS_STATUS_Tp pStatus )
{
    int skfd;
    struct iwreq wrq;

    skfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(skfd==-1)
		return -1;

    /* Get wireless name */
    if ( iw_get_ext(skfd, interface, SIOCGIWNAME, &wrq) < 0) {
       close( skfd );
      /* If no wireless name : no wireless extensions */
       return -1;
    }

    wrq.u.data.pointer = (caddr_t)pStatus;

    if ( pStatus->number == 0 )
    	wrq.u.data.length = sizeof(SS_STATUS_T);
    else
        wrq.u.data.length = sizeof(pStatus->number);

    if (iw_get_ext(skfd, interface, SIOCGIWRTLGETBSSDB, &wrq) < 0) {
      close( skfd );
      return -1;
    }

    close( skfd );

    return 0;
}
#endif

#if defined(WLAN_CLIENT)
/////////////////////////////////////////////////////////////////////////////
int getWlJoinRequest(char *interface, pBssDscr pBss, unsigned char *res)
{
    int skfd;
    struct iwreq wrq;

    skfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(skfd==-1)
		return -1;
    /* Get wireless name */
    if ( iw_get_ext(skfd, interface, SIOCGIWNAME, &wrq) < 0) {
      close( skfd );
      /* If no wireless name : no wireless extensions */
      return -1;
    }

    wrq.u.data.pointer = (caddr_t)pBss;
    wrq.u.data.length = sizeof(BssDscr);

    if (iw_get_ext(skfd, interface, SIOCGIWRTLJOINREQ, &wrq) < 0) {
      close( skfd );
      return -1;
    }

    close( skfd );

    *res = *((char *)wrq.u.data.pointer);

    return 0;
}

/////////////////////////////////////////////////////////////////////////////
int getWlJoinResult(char *interface, unsigned char *res)
{
    int skfd;
    struct iwreq wrq;

    skfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(skfd==-1)
		return -1;

    /* Get wireless name */
    if ( iw_get_ext(skfd, interface, SIOCGIWNAME, &wrq) < 0) {
      close( skfd );
      /* If no wireless name : no wireless extensions */
      return -1;
    }

    wrq.u.data.pointer = (caddr_t)res;
    wrq.u.data.length = 1;

    if (iw_get_ext(skfd, interface, SIOCGIWRTLJOINREQSTATUS, &wrq) < 0) {
      close( skfd );
      return -1;
    }

    close( skfd );

    return 0;
}
#endif


/////////////////////////////////////////////////////////////////////////////
int getWlSiteSurveyRequest(char *interface, int *pStatus)
{
    int skfd;
    struct iwreq wrq;
    unsigned char result;

    skfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(skfd==-1)
		return -1;

    /* Get wireless name */
    if ( iw_get_ext(skfd, interface, SIOCGIWNAME, &wrq) < 0) {
      close( skfd );
      /* If no wireless name : no wireless extensions */
      return -1;
    }

    wrq.u.data.pointer = (caddr_t)&result;
    wrq.u.data.length = sizeof(result);

    if (iw_get_ext(skfd, interface, SIOCGIWRTLSCANREQ, &wrq) < 0) {
      close( skfd );
      return -1;
    }

    close( skfd );

    if ( result == 0xff )
    	*pStatus = -1;
    else
	*pStatus = (int) result;

    return 0;
}

#if defined(WLAN_CLIENT)
void getSiteSurveyWlanNeighborAsync(char wlan_idx)
{
	char *argv[3]={0}, argv_buf[32];	
	char *envp[2]={0};
	const char filename[40];
	int pid;
	
	snprintf((char *)filename, sizeof(filename), "/bin/SiteSurveyWLANNeighbor");
	argv[0] = (char *)filename;
	snprintf(argv_buf, 32, "%d", wlan_idx);
	argv[1] = (char *)argv_buf;
	argv[2] = NULL;
	pid=fork();
	if(pid < 0) {
		AUG_PRT("fork() fail ! \n");
	} else if (pid == 0) {
		envp[0] = "PATH=/bin:/usr/bin:/etc:/sbin:/usr/sbin";
		envp[1] = NULL;
		execve(filename, argv, envp);		
		AUG_PRT("exec %s failed\n", filename);
		_exit(2);
	}
}
#endif	// of WLAN_CLIENT

/////////////////////////////////////////////////////////////////////////////
int getWlBssInfo(const char *interface, bss_info *pInfo)
{
    int skfd;
    struct iwreq wrq;

    skfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(skfd==-1)
		return -1;

    /* Get wireless name */
    if ( iw_get_ext(skfd, interface, SIOCGIWNAME, &wrq) < 0) {
      close( skfd );
      /* If no wireless name : no wireless extensions */
      return -1;
    }

    wrq.u.data.pointer = (caddr_t)pInfo;
    wrq.u.data.length = sizeof(bss_info);

    if (iw_get_ext(skfd, interface, SIOCGIWRTLGETBSSINFO, &wrq) < 0) {
      close( skfd );
      return -1;
    }

    close( skfd );

    return 0;
}

#ifdef WLAN_WDS
/////////////////////////////////////////////////////////////////////////////
int getWdsInfo(char *interface, char *pInfo)
{

    int skfd;
    struct iwreq wrq;

    skfd = socket(AF_INET, SOCK_DGRAM, 0);

    /* Get wireless name */
    if ( iw_get_ext(skfd, interface, SIOCGIWNAME, &wrq) < 0) {
      close( skfd );
      /* If no wireless name : no wireless extensions */
      return -1;
    }

    wrq.u.data.pointer = (caddr_t)pInfo;
    wrq.u.data.length = MAX_WDS_NUM*sizeof(WDS_INFO_T);

    if (iw_get_ext(skfd, interface, SIOCGIWRTLGETWDSINFO, &wrq) < 0) {
      close( skfd );
      return -1;
    }

    close( skfd );

    return 0;
}

#endif

int getWlVersion( char *interface, char *verstr )
{
    int skfd;
    unsigned char vernum[4];
    struct iwreq wrq;

    skfd = socket(AF_INET, SOCK_DGRAM, 0);

    /* Get wireless name */
    if ( iw_get_ext(skfd, interface, SIOCGIWNAME, &wrq) < 0) {
      close( skfd );
      /* If no wireless name : no wireless extensions */
      return -1;
    }

    memset(vernum, 0, 4);
    wrq.u.data.pointer = (caddr_t)&vernum[0];
    wrq.u.data.length = sizeof(vernum);

    if (iw_get_ext(skfd, interface, SIOCGIWRTLDRVVERSION, &wrq) < 0) {
      close( skfd );
      return -1;
    }

    close( skfd );

    sprintf(verstr, "%d.%d.%d", vernum[0], vernum[1], vernum[2]);

    return 0;
}

char *getWlanIfName_web(void)
{
	if(wlan_idx == 0)
		return (char *)WLANIF[0];
#if defined(CONFIG_RTL_92D_SUPPORT) || defined(WLAN_DUALBAND_CONCURRENT)
	else if(wlan_idx == 1)
		return (char *)WLANIF[1];
#endif //CONFIG_RTL_92D_SUPPORT

	printf("%s: Wrong wlan_idx!\n", __func__);

	return NULL;
}

char *getWlanIfName(void)
{
#ifdef CONFIG_RTL_92D_SUPPORT
	char wlanBand2G5GSelect;
	if(wlan_idx == 1){
		mib_get(MIB_WLAN_BAND2G5G_SELECT, (void *)&wlanBand2G5GSelect);
		if(wlanBand2G5GSelect == BANDMODESINGLE) {
			return (char *)WLANIF[0];
		}
	}
#endif //CONFIG_RTL_92D_SUPPORT

	return getWlanIfName_web();
}

char *getWlanIfNameByWlanIdx_web(int wlanIndex)
{
	if(wlanIndex == 0)
		return (char *)WLANIF[0];
#if defined(CONFIG_RTL_92D_SUPPORT) || defined(WLAN_DUALBAND_CONCURRENT)
	else if(wlanIndex == 1)
		return (char *)WLANIF[1];
#endif //CONFIG_RTL_92D_SUPPORT

	printf("%s: Wrong wlan_idx!\n", __func__);

	return NULL;
}

char *getWlanIfNameByWlanIdx(int wlanIndex)
{
#ifdef CONFIG_RTL_92D_SUPPORT
	char wlanBand2G5GSelect;
	if(wlanIndex == 1){
		mib_get(MIB_WLAN_BAND2G5G_SELECT, (void *)&wlanBand2G5GSelect);
		if(wlanBand2G5GSelect == BANDMODESINGLE) {
			return (char *)WLANIF[0];
		}
	}
#endif //CONFIG_RTL_92D_SUPPORT

	return getWlanIfNameByWlanIdx_web(wlanIndex);
}

int useWlanIfVirtIdx(void)
{
#ifdef CONFIG_RTL_92D_SUPPORT
	char wlanBand2G5GSelect, wlanBand2G5GSelect_single;
	mib_get(MIB_WLAN_BAND2G5G_SELECT, (void *)&wlanBand2G5GSelect);
	mib_get(MIB_WLAN_BAND2G5G_SINGLE_SELECT, (void *)&wlanBand2G5GSelect_single);
	if(wlanBand2G5GSelect == BANDMODESINGLE && wlanBand2G5GSelect_single == BANDMODE2G)
		return 1;
	else
#endif
		return 0;
}

void getWscPidName(char *wscd_pid_name)
{
#ifdef WLAN_WPS_VAP
#ifdef WLAN_WPS_MULTI_DAEMON
	int i=0, j=0;
	MIB_CE_MBSSIB_T Entry;
	char wscd_pid_file[32]={0};
	for(i=0; i<NUM_WLAN_INTERFACE; i++){
		for(j=0; j<NUM_VWLAN_INTERFACE; j++){
			mib_chain_local_mapping_get(MIB_MBSSIB_TBL, i, j, &Entry);
			if(i==0 && Entry.wsc_upnp_enabled){ //check upnp enabled only for ssid-1
				if(j==0){
					snprintf(wscd_pid_file, sizeof(wscd_pid_file), "/var/run/wscd-%s.pid", WLANIF[i]);
				}
				else
					snprintf(wscd_pid_file, sizeof(wscd_pid_file), "/var/run/wscd-%s-vap%d.pid", WLANIF[i], j-1);
				if(access(wscd_pid_file, F_OK)==0){
					strcpy(wscd_pid_name, wscd_pid_file);
					break;
				}
			}
		}
	}
	strcpy(wscd_pid_name, wscd_pid_file);
#else
	unsigned char vwlan_idx;
	int root_idx = 0;
	mib_get(MIB_WPS_SSID, &vwlan_idx);
	if(vwlan_idx>4){
		root_idx = 1;
		vwlan_idx-=4;
	}
	if(vwlan_idx==1)
		sprintf(wscd_pid_name, "/var/run/wscd-%s.pid", WLANIF[root_idx]);
	else
		sprintf(wscd_pid_name, "/var/run/wscd-%s-vap%hhu.pid", WLANIF[root_idx], vwlan_idx-2);
#endif
#else
	int orig_wlan_idx = wlan_idx;
#if defined(CONFIG_RTL_92D_DMDP) || defined(WLAN_DUALBAND_CONCURRENT)
	int pid;
	pid = read_pid((char *) WLAN0_WLAN1_WSCDPID);
	if (pid > 0) {
		sprintf(wscd_pid_name, "%s", WLAN0_WLAN1_WSCDPID);
		return; 
	}
	wlan_idx = 1;
	sprintf(wscd_pid_name, WSCDPID, getWlanIfName());
	pid = read_pid((char *) wscd_pid_name);
	if (pid > 0) {
		wlan_idx = orig_wlan_idx;
		return;
	}
#endif
	wlan_idx = 0;
	sprintf(wscd_pid_name, WSCDPID, getWlanIfName());
	wlan_idx = orig_wlan_idx;
#endif
}

//check flash config if wlan0 is up, called by BOA,
//0:down, 1:up
int wlan_is_up(void)
{
  int value=0;
  MIB_CE_MBSSIB_T Entry;
  mib_chain_get(MIB_MBSSIB_TBL,0,&Entry);
	
    if (Entry.wlanDisabled==0) {  // wlan0 is enabled
    	value=1;
    }
	return value;
}
#ifdef WLAN_WISP
void getWispWanID(int *idx)
{
	int i, mibtotal;
	MIB_CE_ATM_VC_T Entry;
	
	mibtotal = mib_chain_total(MIB_ATM_VC_TBL);
	for(i=0; i<mibtotal; i++)
	{
		if(!mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&Entry))
			continue;

		if(MEDIA_INDEX(Entry.ifIndex) == MEDIA_WLAN)
			break;
	}

	*idx = ETH_INDEX(Entry.ifIndex);
}

//return wisp wan interface name
void getWispWanName(char *name)
{
	int wisp_wan_id;
	getWispWanID(&wisp_wan_id);
	snprintf(name, IFNAMSIZ, "wlan%d-vxd", wisp_wan_id);
}
void setWlanDevFlag(char *ifname, int set_wan)
{
	char cmd_str[100];

	if(set_wan){
		snprintf(cmd_str, sizeof(cmd_str), "echo \"%s write 0x2000\" > /proc/netdev_flag", ifname);
		system(cmd_str);
	}
	else{
		snprintf(cmd_str, sizeof(cmd_str), "echo \"%s write 0x4000\" > /proc/netdev_flag", ifname);
		system(cmd_str);
		snprintf(cmd_str, sizeof(cmd_str), "ifconfig %s 0.0.0.0", ifname);
		system(cmd_str);
	}
}
#endif

#ifdef CONFIG_WIFI_SIMPLE_CONFIG //WPS
// this is a workaround for wscd to get MIB id without including "mib.h" (which causes compile error), andrew

const int gMIB_WSC_DISABLE			  = MIB_WSC_DISABLE;
const int gMIB_WSC_CONFIGURED         = MIB_WSC_CONFIGURED;
const int gMIB_WLAN_SSID              = MIB_WLAN_SSID;
const int gMIB_WSC_SSID               = MIB_WSC_SSID;
const int gMIB_WLAN_AUTH_TYPE         = MIB_WLAN_AUTH_TYPE;
const int gMIB_WLAN_ENCRYPT           = MIB_WLAN_ENCRYPT;
const int gMIB_WSC_AUTH               = MIB_WSC_AUTH;
const int gMIB_WLAN_WPA_AUTH          = MIB_WLAN_WPA_AUTH;
const int gMIB_WLAN_WPA_PSK           = MIB_WLAN_WPA_PSK;
const int gMIB_WLAN_WPA_PSK_FORMAT    = MIB_WLAN_WPA_PSK_FORMAT;
const int gMIB_WSC_PSK                = MIB_WSC_PSK;
const int gMIB_WLAN_WPA_CIPHER_SUITE  = MIB_WLAN_WPA_CIPHER_SUITE;
const int gMIB_WLAN_WPA2_CIPHER_SUITE = MIB_WLAN_WPA2_CIPHER_SUITE;
const int gMIB_WLAN_WEP               = MIB_WLAN_WEP;
const int gMIB_WLAN_WEP64_KEY1        = MIB_WLAN_WEP64_KEY1;
const int gMIB_WLAN_WEP64_KEY2        = MIB_WLAN_WEP64_KEY2;
const int gMIB_WLAN_WEP64_KEY3        = MIB_WLAN_WEP64_KEY3;
const int gMIB_WLAN_WEP64_KEY4        = MIB_WLAN_WEP64_KEY4;
const int gMIB_WLAN_WEP128_KEY1       = MIB_WLAN_WEP128_KEY1;
const int gMIB_WLAN_WEP128_KEY2       = MIB_WLAN_WEP128_KEY2;
const int gMIB_WLAN_WEP128_KEY3       = MIB_WLAN_WEP128_KEY3;
const int gMIB_WLAN_WEP128_KEY4       = MIB_WLAN_WEP128_KEY4;
const int gMIB_WLAN_WEP_DEFAULT_KEY   = MIB_WLAN_WEP_DEFAULT_KEY;
const int gMIB_WLAN_WEP_KEY_TYPE      = MIB_WLAN_WEP_KEY_TYPE;
const int gMIB_WSC_ENC                = MIB_WSC_ENC;
const int gMIB_WSC_CONFIG_BY_EXT_REG  = MIB_WSC_CONFIG_BY_EXT_REG;
const int gMIB_WSC_PIN = MIB_WSC_PIN;
const int gMIB_ELAN_MAC_ADDR = MIB_ELAN_MAC_ADDR;
const int gMIB_WLAN_MODE = MIB_WLAN_MODE;
const int gMIB_WSC_REGISTRAR_ENABLED = MIB_WSC_REGISTRAR_ENABLED;
const int gMIB_WLAN_CHAN_NUM = MIB_WLAN_CHAN_NUM;
const int gMIB_WSC_UPNP_ENABLED = MIB_WSC_UPNP_ENABLED;
const int gMIB_WSC_METHOD = MIB_WSC_METHOD;
const int gMIB_WSC_MANUAL_ENABLED = MIB_WSC_MANUAL_ENABLED;
const int gMIB_SNMP_SYS_NAME = MIB_SNMP_SYS_NAME;
const int gMIB_WLAN_NETWORK_TYPE = MIB_WLAN_NETWORK_TYPE;
const int gMIB_WLAN_WSC_VERSION	= MIB_WSC_VERSION;

#ifdef CONFIG_RTL_92D_SUPPORT
const int gMIB_WLAN_BAND2G5G_SELECT				= MIB_WLAN_BAND2G5G_SELECT;
#endif //CONFIG_RTL_92D_DMDP

int mib_update_all()
{
	return mib_update(CURRENT_SETTING, CONFIG_MIB_ALL);
}
#endif




#if	defined(CONFIG_LUNA_DUAL_LINUX)
static void createVWLAN_mac(char *name, unsigned char *mac)
{
	FILE *fp;

	fp = fopen(name, "w");
	if(fp) {
		fprintf(fp, "%x %x %x %x %x %x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
		fclose(fp);
	}
	return;
}

static int set_vwlan_hwaddr()
{
	unsigned char value[6];
	unsigned char ethaddr[6];
	char macaddr[13];
	int i;
#ifdef WLAN_MBSSID
	char para2[20];
#endif
	int hwaddr_ind = 1;

	if (mib_get(MIB_ELAN_MAC_ADDR, (void *)value) != 0)
	{

#ifdef WLAN_MBSSID
		setup_mac_addr(value, WLAN_MBSSID_NUM);
#endif
		setup_mac_addr(value, 1);
		snprintf(macaddr, 13, "%02x%02x%02x%02x%02x%02x",
		value[0], value[1], value[2], value[3], value[4], value[5]);
		va_cmd(IFCONFIG, 4, 1, "wlan1", "hw", "ether", macaddr);

		memcpy(ethaddr, value, 6);
#ifdef	WLAN_MBSSID
		hwaddr_ind += WLAN_MBSSID_NUM;
#endif
#if 0 //def WLAN_UNIVERSAL_REPEATER //	CONFIG_RTL_REPEATER_MODE_SUPPORT
		hwaddr_ind += 1;
#endif

#ifdef WLAN_WDS
		hwaddr_ind += (MAX_WDS_NUM);
#endif
		setup_mac_addr(ethaddr, hwaddr_ind);
	 	createVWLAN_mac((char *)WLAN1_MAC_FILE, ethaddr);

#ifdef WLAN_MBSSID
		// Set macaddr for VAP
		for (i=1; i<=WLAN_MBSSID_NUM; i++) {
			setup_mac_addr(value, 1);

			snprintf(macaddr, 13, "%02x%02x%02x%02x%02x%02x",
				value[0], value[1], value[2], value[3], value[4], value[5]);

			snprintf(para2, sizeof(para2), "wlan1-vap%d", i-1);

			va_cmd(IFCONFIG, 4, 1, para2, "hw", "ether", macaddr);
		}
#endif

	}
}
static int ping(char *ipaddr)
{
	char cmd[100];
	int status, ping_rtn;
	snprintf(cmd, sizeof(cmd), "ping -w 2 %s > /dev/null", ipaddr);

	status = system(cmd);
	ping_rtn = status;
	if (status != -1) {
		ping_rtn = WEXITSTATUS(status);
		printf("ping returned: %sConnected\n", ping_rtn ? "Not " : "");
	} else {
		fprintf(stderr, "The system(3) function returned -1\n");
	}
	return ping_rtn;
}
#if 0
static int ping_test(char *ipaddr)
{
	int status = 0;
	int num = 0;
	char disabled;
	int orig_idx = wlan_idx;
	status = ping(ipaddr);

	while(status){
		printf("Machine not reachable, status %d\n", status);
		sleep(2);
		status = ping(ipaddr);
		num++;
		if(num > 5) {
			disabled = 2;
			wlan_idx = 1;
			update_wlan_disable(disabled);
			wlan_idx = orig_idx;
			printf("Disable wlan1 interface\n");
			Commit();
			return status;
		}
	}
	printf("Could ping %s successfully, status %d\n", ipaddr, status);
	disabled = 0;
	wlan_idx = 1;
	update_wlan_disable(disabled);
	wlan_idx = orig_idx;
	Commit();
	return status;
}
#endif
int setup_vwlan()
{
#if defined(CONFIG_VIRTUAL_WLAN_DRIVER)
	unsigned char vCharget;
	int orig_idx = wlan_idx;
#endif

//	va_cmd(BRCTL, 3, 1, "addif", BRIF, "wlan1");
//	va_cmd(IFCONFIG, 2, 1, "wlan1", "up");
	va_cmd(IFCONFIG, 4, 1, "vwlan", "hw", "ether", CONFIG_DEFAULT_MASTER_IPC_MAC_ADDRESS);
	va_cmd(IFCONFIG, 4, 1, "vwlan", "10.253.253.1", "netmask", "255.255.255.252");
	va_cmd(IFCONFIG, 2, 1, "vwlan", "up");
	va_cmd("/bin/arp", 3, 1 , "-s", "10.253.253.2", CONFIG_DEFAULT_SLAVE_IPC_MAC_ADDRESS);
	system("ping -c 1 10.253.253.2 > /dev/null");
#if defined(CONFIG_VIRTUAL_WLAN_DRIVER) && defined(CONFIG_SLAVE_WLAN1_ENABLE)
	set_vwlan_hwaddr();
#endif
}

int update_vwlan_disable( char *interface, int disable )
{
	if (!disable){
		system("echo 2 > /proc/vwlan");
			return 1;
	}
	else{
		system("echo 3 > /proc/vwlan");
			return 1;
	}
	return -1;
}

#endif

int setup_wlan_block(void)
{
	unsigned char enable = 0;

	va_cmd(EBTABLES, 2, 1, "-F", "wlan_block");

	// Between ELAN & WIFI
	mib_get(MIB_WLAN_BLOCK_ETH2WIR, (void *)&enable);
#ifdef CONFIG_RTK_L34_ENABLE
	rg_eth2wire_block(enable);
#else
	if(enable)
	{
		va_cmd(EBTABLES, 8, 1, "-A", "wlan_block", "-i", "wlan+", "-o", "eth0.+", "-j", "DROP");
		va_cmd(EBTABLES, 8, 1, "-A", "wlan_block", "-i", "eth0.+", "-o", "wlan+", "-j", "DROP");
	}
#endif

#ifdef WLAN_MBSSID
	// Between MBSSIDs
	mib_get(MIB_WLAN_BLOCK_MBSSID, (void *)&enable);
	if(enable)
		va_cmd(EBTABLES, 8, 1, "-A", "wlan_block", "-i", "wlan+", "-o", "wlan+", "-j", "DROP");
#endif
	return 0;
}

#ifdef WIFI_TIMER_SCHEDULE
void updateWifiSchedCrondFile(char *pathname, int startup)
{
	char *strVal;
	int totalnum, i, j, first, crond_pid;
	FILE *fp, *getPIDS;
	char tmpbuf[100], buf[20], day_string[20], kill_cmd[100], filename[100];
	MIB_CE_WIFI_TIMER_EX_T Entry_ex;
	MIB_CE_WIFI_TIMER_T Entry;
	int wifiSchedFileExist = 0;
	unsigned char startHour, startMinute, endHour, endMinute;

	if(startup){
		snprintf(tmpbuf, 100, "mkdir -p %s", pathname);
		system(tmpbuf);
	}
	if ( !mib_get(MIB_SUSER_NAME, (void *)tmpbuf) ) {
		printf("ERROR: Get superuser name from MIB database failed.\n");
		return;
	}
	snprintf(filename, 100, "%s/%s", pathname, tmpbuf);

	crond_pid = read_pid("/var/run/crond.pid");
	if(crond_pid > 0){
		kill(crond_pid, 9);
		unlink("/var/run/crond.pid");
	}				
	
	fp = fopen(filename, "w");
	

	totalnum = mib_chain_total(MIB_WIFI_TIMER_EX_TBL);
	for(i=0; i<totalnum; i++){
		mib_chain_get(MIB_WIFI_TIMER_EX_TBL, i, &Entry_ex);
		
		first = 1;
		if(Entry_ex.day & (1<<7)){
			if(first){
				snprintf(day_string, 20, "0");
				first = 0;
			}
			else{
				sprintf(buf, ",0");
				strcat(day_string, buf);
				//snprintf(day_string, 20,"%s,0", day_string);
			}
		}
		for(j=1;j<7;j++){
			if(Entry_ex.day & (1<<j)){
				if(first){
					snprintf(day_string, 20, "%d", j);
					first = 0;
				}
				else{
					sprintf(buf, ",%d", j);
					strcat(day_string, buf);
					//snprintf(day_string, 20,"%s,%d", day_string, j);
				}
			}
		}
#ifdef _PRMT_X_CMCC_WLANSWITCHTC_
		if(Entry_ex.enable && strcmp(Entry_ex.Time, "")){
#else
		if(Entry_ex.enable){
#endif
			sscanf(Entry_ex.Time, "%hhu:%hhu", &startHour, &startMinute);
			snprintf(tmpbuf, 100, "%hhu %hhu * * %s /bin/config_wlan %d\n", startMinute, startHour, day_string, Entry_ex.onoff);
			fputs(tmpbuf,fp);
			if(wifiSchedFileExist == 0)
					wifiSchedFileExist = 1;
		}
	}

	totalnum = mib_chain_total(MIB_WIFI_TIMER_TBL);
	for(i=0; i<totalnum; i++){
		mib_chain_get(MIB_WIFI_TIMER_TBL, i, &Entry);
		if(Entry.enable){
			sscanf(Entry.startTime, "%hhu:%hhu", &startHour, &startMinute);
			snprintf(tmpbuf, 100, "%hhu %hhu */%hhu * * /bin/config_wlan 1\n", startMinute, startHour, Entry.controlCycle);
			fputs(tmpbuf,fp);
			sscanf(Entry.endTime, "%hhu:%hhu", &endHour, &endMinute);
			snprintf(tmpbuf, 100, "%hhu %hhu */%hhu * * /bin/config_wlan 0\n", endMinute, endHour, Entry.controlCycle);
			fputs(tmpbuf,fp);
			if(wifiSchedFileExist == 0)
					wifiSchedFileExist = 1;
		}
	}

	fclose(fp);

	if(wifiSchedFileExist) {
		// file is not empty
		va_cmd("/bin/crond", 0, 1);
	}
	else
		unlink(filename);
}
#endif

#ifdef WPS_QUERY
static int getIP(char *ip, char *mac)
{
	FILE *fp;
	char strbuf[256];
	char *ptr;
	int ret = -1;

	fp = fopen("/proc/net/arp", "r");
	if (fp == NULL){
		printf("read arp file fail!\n");
		return ret;
	}
	fgets(strbuf, sizeof(strbuf), fp);
	while (fgets(strbuf, sizeof(strbuf), fp)) {
		ptr=strstr(strbuf, mac);
		if(ptr!=NULL){
			sscanf(strbuf, "%s %*s %*s %*s %*s %*s", ip);
			printf("ip %s\n", ip);
			ret = 0;
			goto end;
		}
	}
end:
	fclose(fp);
	return ret;
}
int check_wps_dev_info(char *devinfo)
{
	FILE *fp;
	//FILE *fp2;
	char wps_dev_mac[20]={0};
	int lSize;
	char wps_dev_info[256] = {0};
	char ipaddr[20] = {0};
	int ret = -1;

	fp = fopen("/tmp/wps_dev_info", "r");

	if(fp){
		fscanf(fp, "%*[^:]:%[^;]", wps_dev_mac);
		ret = getIP(ipaddr, wps_dev_mac);
		// read wps dev info
		fseek (fp , 0 , SEEK_END);
		lSize = ftell (fp);
		rewind (fp);
		fread (wps_dev_info,1,lSize,fp);
		#if 0
		fp2 = fopen("/tmp/wps_dev_qry", "w");
		if(fp2){
			fprintf(fp2,"IP:%s;%s", ipaddr, wps_dev_info);
			fclose(fp2);
		}
		#endif
		sprintf(devinfo, "IP:%s;%s", ipaddr, wps_dev_info);
		fclose(fp);
	}
	return ret;
}

void run_wps_query(char *wps_status, char *devinfo)
{

	FILE *fp;
	int status;
	fp = fopen("/tmp/wscd_status", "r");
	if(fp){
		fscanf(fp, "%d", &status);
		fclose(fp);
		if(status == PROTOCOL_TIMEOUT)
			*wps_status = 3;
		else if(status == PROTOCOL_SUCCESS)
			*wps_status = 2;
		else if(status >= WSC_EAP_FAIL && status <= PROTOCOL_PIN_NUM_ERR || status == PROTOCOL_PBC_OVERLAPPING)
			*wps_status = 1;
		else
			*wps_status = 0;
		
		if(*wps_status == 2){
			if(check_wps_dev_info(devinfo)!=0){
				*wps_status = 0;
				devinfo = NULL;
			}
		}
		else
			devinfo = NULL;
	}
	else{
		*wps_status = 1; //failed
	}
}
int is_wps_running()
{

	FILE *fp;
	int status;
	fp = fopen("/tmp/wscd_status", "r");
	if(fp){
		fscanf(fp, "%d", &status);
		fclose(fp);
		if(status == PROTOCOL_TIMEOUT)
			return 0;
		else if(status == PROTOCOL_SUCCESS)
			return 0;
		else if(status >= WSC_EAP_FAIL && status <= PROTOCOL_PIN_NUM_ERR || status == PROTOCOL_PBC_OVERLAPPING)
			return 0;
		else
			return 1;//is running	
	}
	else{
		return 0;
	}
}

#endif
#ifdef WLAN_WPS_VAP
static char *get_token(char *data, char *token)
{
	char *ptr=data;
	int len=0, idx=0;

	while (*ptr && *ptr != '\n' ) {
		if (*ptr == '=') {
			if (len <= 1)
				return NULL;
			memcpy(token, data, len);

			/* delete ending space */
			for (idx=len-1; idx>=0; idx--) {
				if (token[idx] !=  ' ')
					break;
			}
			token[idx+1] = '\0';

			return ptr+1;
		}
		len++;
		ptr++;
	}
	return NULL;
}

static int get_value(char *data, char *value)
{
	char *ptr=data;
	int len=0, idx, i;

	while (*ptr && *ptr != '\n' && *ptr != '\r') {
		len++;
		ptr++;
	}

	/* delete leading space */
	idx = 0;
	while (len-idx > 0) {
		if (data[idx] != ' ')
			break;
		idx++;
	}
	len -= idx;

	/* delete bracing '"' */
	if (data[idx] == '"') {
		for (i=idx+len-1; i>idx; i--) {
			if (data[i] == '"') {
				idx++;
				len = i - idx;
			}
			break;
		}
	}

	if (len > 0) {
		memcpy(value, &data[idx], len);
		value[len] = '\0';
	}
	return len;
}
void sync_wps_config_parameter_to_flash(char *filename, char *wlan_interface_name)
{
	FILE *fp;
	int vwlan_idx;
	char tmpbuf[120];
	char line[400], token[40], value[300], *ptr;
	MIB_CE_MBSSIB_T Entry;
	unsigned char vChar;
	if( wlan_interface_name [5] == '-' && wlan_interface_name [6] == 'v' && wlan_interface_name [7] == 'a') {
		vwlan_idx = wlan_interface_name[9] - '0';
		vwlan_idx ++;
#ifdef WLAN_DUALBAND_CONCURRENT
		wlan_idx = wlan_interface_name[4]- '0';
#endif
	}
	else{
		vwlan_idx = 0;
#ifdef WLAN_DUALBAND_CONCURRENT
		wlan_idx = wlan_interface_name[4]- '0';
#endif
	}
	fp = fopen(filename, "r");
	if(fp){
		wlan_getEntry(&Entry, vwlan_idx);
		while (fgets(line, 200, fp)) {
			if (line[0] == '#')
				continue;
			ptr = get_token(line, token);
			if (ptr == NULL)
				continue;
			if (get_value(ptr, value)==0){
				continue;
			}
			else if (!strcmp(token, "WSC_CONFIGURED")) {
				Entry.wsc_configured = atoi(value);
			}
			else if (!strcmp(token, "SSID")) {
				strcpy(Entry.ssid, value);
			}
			else if (!strcmp(token, "AUTH_TYPE")) {
				Entry.authType = atoi(value);
			}
			else if (!strcmp(token, "WLAN_ENCRYPT")) {
				Entry.encrypt = atoi(value);
			}
			else if (!strcmp(token, "WSC_AUTH")) {
				Entry.wsc_auth = atoi(value);
			}
			else if (!strcmp(token, "WLAN_WPA_AUTH")) {
				Entry.wpaAuth = atoi(value);
			}
			else if (!strcmp(token, "WLAN_WPA_PSK")) {
				strcpy(Entry.wpaPSK, value);
			}
			else if (!strcmp(token, "WLAN_PSK_FORMAT")) {
				Entry.wpaPSKFormat = atoi(value);
			}
			else if (!strcmp(token, "WSC_PSK")) {
				strcpy(Entry.wscPsk, value);
			}
			else if (!strcmp(token, "WPA_CIPHER_SUITE")) {
				Entry.unicastCipher = atoi(value);
			}
			else if (!strcmp(token, "WPA2_CIPHER_SUITE")) {
				Entry.wpa2UnicastCipher = atoi(value);
			}
			else if (!strcmp(token, "WEP")) {
				Entry.wep = atoi(value);
			}
			else if (!strcmp(token, "WEP64_KEY1")) {
				strcpy(Entry.wep64Key1, value);
			}
			else if (!strcmp(token, "WEP128_KEY1")) {
				strcpy(Entry.wep128Key1, value);
			}
			else if (!strcmp(token, "WEP_DEFAULT_KEY")) {
				Entry.wepDefaultKey = atoi(value);
			}
			else if (!strcmp(token, "WEP_KEY_TYPE")) {
				Entry.wepKeyType = atoi(value);
			}
			else if (!strcmp(token, "WSC_ENC")) {
				Entry.wsc_enc = atoi(value);
			}
			else if (!strcmp(token, "WSC_CONFIGBYEXTREG")) {
				if(vwlan_idx == 0){
					vChar = atoi(value);
					mib_set(MIB_WSC_CONFIG_BY_EXT_REG, &vChar);
				}
			}
			
		}
		wlan_setEntry(&Entry, vwlan_idx);
#ifdef COMMIT_IMMEDIATELY
		Commit();
#endif
		fclose(fp);
	}
}
void set_wps_enable(unsigned char enable)
{
	unsigned char vChar;
	mib_get(MIB_WPS_ENABLE, &vChar);
	if(vChar != enable){
		vChar = enable;
		mib_set(MIB_WPS_ENABLE, &vChar);
#ifdef COMMIT_IMMEDIATELY
		Commit();
#endif
		config_WLAN(ACT_RESTART, CONFIG_SSID_ALL);
	}
}
void set_wps_ssid(unsigned char ssid_number)
{
	unsigned char vChar;
	mib_get(MIB_WPS_SSID, &vChar);
	if(vChar != ssid_number){
		vChar = ssid_number;
		mib_set(MIB_WPS_SSID, &vChar);
#ifdef COMMIT_IMMEDIATELY
		Commit();
#endif
		config_WLAN(ACT_RESTART, CONFIG_SSID_ALL);
	}
}
void set_wps_timeout(unsigned int wps_timeout)
{
	unsigned int intVal;
	mib_get(MIB_WPS_TIMEOUT, &intVal);
	if(intVal != wps_timeout){
		intVal = wps_timeout;
		mib_set(MIB_WPS_TIMEOUT, &intVal);
#ifdef COMMIT_IMMEDIATELY
		Commit();
#endif
		config_WLAN(ACT_RESTART, CONFIG_SSID_ALL);
	}
}
int check_is_wps_ssid(int vwlan_idx, unsigned char ssid_num)
{
#ifdef WLAN_DUALBAND_CONCURRENT
	if(ssid_num>WLAN_SSID_NUM)
	{
		if(wlan_idx==1){
			if(vwlan_idx == (ssid_num-(WLAN_SSID_NUM+1)))
				return 1;
		}
	}
	else{
		if(wlan_idx==0){
			if(vwlan_idx == (ssid_num-1))
				return 1;
		}
	}		
#else
	if(vwlan_idx == (ssid_num-1))
		return 1;
#endif
	return 0;
}
static int check_wps_enc(MIB_CE_MBSSIB_Tp Entry)
{
#ifdef WPS20
	unsigned char wpsUseVersion;
#ifdef WPS_VERSION_CONFIGURABLE
	if (mib_get(MIB_WSC_VERSION, (void *)&wpsUseVersion) == 0)
#endif
		wpsUseVersion = WPS_VERSION_V2;

	if(wpsUseVersion != 0){
		if(Entry->encrypt == WIFI_SEC_WEP || Entry->encrypt == WIFI_SEC_WPA)
			return 0;
		if(Entry->encrypt == WIFI_SEC_WPA2 && Entry->wpa2UnicastCipher == WPA_CIPHER_TKIP)
			return 0;
		if(Entry->encrypt == WIFI_SEC_WPA2_MIXED && Entry->unicastCipher == WPA_CIPHER_TKIP
			&& Entry->wpa2UnicastCipher == WPA_CIPHER_TKIP)
			return 0;
		if(Entry->hidessid)
			return 0;
#ifdef WLAN_1x
		if(Entry->enable1X || (Entry->encrypt >= WIFI_SEC_WPA && Entry->wpaAuth == WPA_AUTH_AUTO))
			return 0;
#endif
	}
#endif
	return 1;
}
int restartWPS(int ssid_idx)
{
	unsigned char vChar;
	int iwcontrolpid=0, wscdpid=0;
	int i,j;
	char s_ifname[16];
	char wscd_pid_name[32];
	char wscd_fifo_name[32];
	char wscd_conf_name[32];

	int wsc_pid_fd=-1;
	unsigned char encrypt;
	unsigned char wsc_disable;
	unsigned char wlan_mode;
	unsigned char wlan_nettype;
	unsigned char wpa_auth;
	unsigned char wps_ssid;
	MIB_CE_MBSSIB_T Entry;
	char ifname[16];
	int status = 0;
	int lockfd;
	int retry = 0;
#ifdef YUEME_3_0_SPEC
	unsigned char no_wlan;
#endif
#ifdef WLAN_WPS_MULTI_DAEMON
	int wlanIdx=-1, vwlan_idx=-1;
	int config_all=0;

#ifdef WLAN_DUALBAND_CONCURRENT
	if(ssid_idx>WLAN_SSID_NUM && ssid_idx<=WLAN_SSID_NUM*2){
		wlanIdx = 1;
		vwlan_idx = ssid_idx-(WLAN_SSID_NUM+1);
		config_all=0;
	}
	else 
#endif
	if(ssid_idx>0 && ssid_idx<=WLAN_SSID_NUM){
		wlanIdx = 0;
		vwlan_idx = ssid_idx-1;
		config_all=0;
	}
	else if(ssid_idx == 0){
		config_all = 1;
	}
	else
		return -1;
#endif
	printf("%s config_all %d  wlan_idx %d  vwlan_idx %d\n", __func__, config_all, wlanIdx, vwlan_idx);

	LOCK_WLAN();
	
	// Kill iwcontrol
#if defined(CONFIG_USER_MONITORD) && defined(CONFIG_YUEME)
	update_monitor_list_file("iwcontrol", 0);
#endif
	iwcontrolpid = read_pid((char*)IWCONTROLPID);
	if(iwcontrolpid > 0){
		kill(iwcontrolpid, 9);
		unlink(IWCONTROLPID);
	}

	for(j=0;j<NUM_WLAN_INTERFACE;j++){
			for ( i=0; i<=NUM_VWLAN_INTERFACE; i++) {
#ifdef WLAN_WPS_MULTI_DAEMON
				if(config_all==0 && (j!=wlanIdx || i!=vwlan_idx))
					continue;
#endif

				if (i==0) {
							 snprintf(s_ifname, sizeof(s_ifname), WLANIF[j]);
#ifdef WLAN_WPS_VAP
				snprintf(wscd_pid_name, 32, "/var/run/wscd-%s.pid", (char *)s_ifname);
					snprintf(wscd_conf_name, 32, "/var/wscd-%s.conf", (char *)s_ifname);
					snprintf(wscd_fifo_name, 32, "/var/wscd-%s.fifo", (char *)s_ifname);
#endif
				}
#ifdef	WLAN_MBSSID
				if (i >= WLAN_VAP_ITF_INDEX && i < WLAN_VAP_ITF_INDEX+WLAN_MBSSID_NUM) {
							snprintf(s_ifname, sizeof(s_ifname), "%s-vap", WLANIF[j]);
#ifdef WLAN_WPS_VAP
				snprintf(wscd_pid_name, 32, "/var/run/wscd-%s%d.pid", (char *)s_ifname, i-WLAN_VAP_ITF_INDEX);
					snprintf(wscd_conf_name, 32, "/var/wscd-%s%d.conf", (char *)s_ifname, i-WLAN_VAP_ITF_INDEX);
					snprintf(wscd_fifo_name, 32, "/var/wscd-%s%d.fifo", (char *)s_ifname, i-WLAN_VAP_ITF_INDEX);
#endif
				}
#endif
#ifdef WLAN_UNIVERSAL_REPEATER
				if (i == WLAN_REPEATER_ITF_INDEX) {
							snprintf(s_ifname, sizeof(s_ifname), "%s-vxd", WLANIF[j]);
#ifdef WLAN_WPS_VAP
				snprintf(wscd_pid_name, 32, "/var/run/wscd-%s.pid", (char *)s_ifname);
					snprintf(wscd_conf_name, 32, "/var/wscd-%s.conf", (char *)s_ifname);
					snprintf(wscd_fifo_name, 32, "/var/wscd-%s.fifo", (char *)s_ifname);
#endif
				}
#endif
#ifdef WLAN_WPS_VAP
				wscdpid = read_pid(wscd_pid_name);
				if(wscdpid > 0) {
					system("/bin/echo 0 > /proc/gpio");
					kill(wscdpid, 9);
					unlink(wscd_conf_name);
					unlink(wscd_pid_name);
					unlink(wscd_fifo_name);
					printf("%s: kill wscd for ifname %s", __func__, s_ifname);
					if(i != 0 && i != WLAN_REPEATER_ITF_INDEX)
						printf("%d\n", i-WLAN_VAP_ITF_INDEX);
					else
						printf("\n");
					while(kill(wscdpid, 0)==0){
						//printf("wait wscd to be killed\n");
						usleep(300000);
					}
					startSSDP();
				}
#endif				
			}
	}

	wlan_num = 0; /*reset to 0,jiunming*/
	useAuth_RootIf = 0;  /*reset to 0 */

#ifndef WLAN_WPS_MULTI_DAEMON
	mib_get(MIB_WPS_ENABLE, &vChar);
	if(vChar == 0)
		goto no_wsc;
#endif

	for(j=0;j<NUM_WLAN_INTERFACE;j++){
#ifdef YUEME_3_0_SPEC
		mib_local_mapping_get(MIB_WLAN_DISABLED, j, (void *)&no_wlan);
		if(no_wlan)
			continue;
#endif
		for ( i=0; i<=NUM_VWLAN_INTERFACE; i++) { 

			mib_chain_local_mapping_get(MIB_MBSSIB_TBL, j, i, (void *)&Entry);
			
			if (i==0) {
				strncpy(ifname, (char*)WLANIF[j], 16);
			}
			else {
				#ifdef WLAN_MBSSID
				if (i>=WLAN_VAP_ITF_INDEX && i<(WLAN_VAP_ITF_INDEX+WLAN_MBSSID_NUM))
					snprintf(ifname, 16, "%s-vap%d", (char *)WLANIF[j], i-1);
				#endif
				#ifdef WLAN_UNIVERSAL_REPEATER
				if (i == WLAN_REPEATER_ITF_INDEX) {
					snprintf(ifname, 16, "%s-vxd", (char *)WLANIF[j]);
					mib_local_mapping_get( MIB_REPEATER_ENABLED1, j, (void *)&vChar);
					if (vChar)
						Entry.wlanDisabled=0;
					else
						Entry.wlanDisabled=1;
				}
				#endif
			}
						
			wsc_disable = check_wps_enc(&Entry)? 0:1;

			mib_local_mapping_get(MIB_WLAN_MODE, j, (void *)&wlan_mode);
			mib_local_mapping_get(MIB_WLAN_NETWORK_TYPE, j, (void *)&wlan_nettype);
			//mib_get(MIB_WLAN_WPA_AUTH, (void *)&wpa_auth);
			//mib_get(MIB_WLAN_ENCRYPT, (void *)&encrypt);
#ifndef WLAN_WPS_MULTI_DAEMON
			mib_get(MIB_WPS_SSID, &wps_ssid);
#endif

			if(Entry.wlanDisabled || wsc_disable)
				continue;
#ifdef WLAN_WPS_MULTI_DAEMON
			else if(Entry.wsc_disabled)
				continue;
#else
			else if(!check_is_wps_ssid(i, wps_ssid))
				continue;
#endif
			else if(wlan_mode == CLIENT_MODE) {
				if(wlan_nettype != INFRASTRUCTURE)
					continue;
			}
			else if(wlan_mode == AP_MODE) {
				if((Entry.encrypt >= WIFI_SEC_WPA) && (Entry.wpaAuth == WPA_AUTH_AUTO))
					continue;
			}
			
			snprintf(wscd_pid_name, 32, "/var/run/wscd-%s.pid", ifname);

			int wscd_pid = read_pid(wscd_pid_name);
			if(wscd_pid > 0 && kill(wscd_pid, 0)==0)
				goto skip_running_wscd;
			
			sprintf(wscd_conf_name, "/var/wscd-%s.conf", ifname);
			sprintf(wscd_fifo_name, "/var/wscd-%s.fifo", ifname);
			//status|=generateWpaConf(para_auth_conf, 0, &Entry);
			status|=WPS_updateWscConf("/etc/wscd.conf", wscd_conf_name, 0, &Entry, i, j);
			status|=va_niced_cmd("/bin/wscd", 7, 0, "-start", "-c", wscd_conf_name, "-w", ifname, "-fi", wscd_fifo_name);
			// fix the depency problem
			// check fifo
			retry = 10;
			while (--retry && ((wsc_pid_fd = open(wscd_fifo_name, O_WRONLY)) == -1))
			{
				usleep(30000);
			}
			retry = 10;

			while(--retry && (read_pid(wscd_pid_name) < 0))
			{
				//printf("WSCD is not running. Please wait!\n");
				usleep(300000);
			}

			if(wsc_pid_fd!=-1) close(wsc_pid_fd);/*jiunming, close the opened fd*/

skip_running_wscd:

			if (i == 0){ // Root
				/* 2010-10-27 krammer :  use bit map to record what wlan root interface is use for auth*/
				if(useWlanIfVirtIdx())
					useAuth_RootIf |= 1;
				else
					useAuth_RootIf |= (1<<j);//bit 0 ==> wlan0, bit 1 ==>wlan1
			}
			else {
				strcpy(para_iwctrl[wlan_num], ifname);
				wlan_num++;
			}

		}
	}
no_wsc:
	startSSDP();
	check_iwcontrol_8021x();
	start_iwcontrol();
	UNLOCK_WLAN();
	return status;

}

#endif

static int check_iwcontrol_8021x(void)
{
#ifdef WLAN_1x
	int i,j;
	char ifname[IFNAMSIZ];
	MIB_CE_MBSSIB_T Entry;
	unsigned char vChar;

	for(j=0;j<NUM_WLAN_INTERFACE;j++){
#if defined(YUEME_3_0_SPEC)
		if(mib_local_mapping_get(MIB_WLAN_DISABLED, j, (void *)&vChar)==1){
			if(vChar == 1) //disabled, do nothing
				continue;
		}
#endif
		for ( i=0; i<=NUM_VWLAN_INTERFACE; i++) {
			
			if(mib_chain_local_mapping_get(MIB_MBSSIB_TBL, j, i, (void *)&Entry)==0){
				printf("Error! Get MIB_MBSSIB_TBL error.\n");
				continue;
			}

			if(Entry.wlanDisabled)
				continue;

			if(!(Entry.enable1X || (Entry.encrypt >= WIFI_SEC_WPA && WPA_AUTH_AUTO == Entry.wpaAuth))) //not 8021x enable
				continue;

			if (i==0) {
				strncpy(ifname, (char*)WLANIF[j], 16);
			}
			else {
#ifdef WLAN_MBSSID
				if (i>=WLAN_VAP_ITF_INDEX && i<(WLAN_VAP_ITF_INDEX+WLAN_MBSSID_NUM))
					snprintf(ifname, 16, "%s-vap%d", (char *)WLANIF[j], i-1);
#endif
#ifdef WLAN_UNIVERSAL_REPEATER
				if (i == WLAN_REPEATER_ITF_INDEX) {
					snprintf(ifname, 16, "%s-vxd", (char *)WLANIF[j]);
					mib_local_mapping_get( MIB_REPEATER_ENABLED1, j, (void *)&vChar);
					if (vChar)
						Entry.wlanDisabled=0;
					else{
						Entry.wlanDisabled=1;
						continue;
					}
				}
#endif
			}
		
			if (i == 0){ // Root
				/* 2010-10-27 krammer :  use bit map to record what wlan root interface is use for auth*/
				if(useWlanIfVirtIdx())
					useAuth_RootIf |= 1;
				else
					useAuth_RootIf |= (1<<j);//bit 0 ==> wlan0, bit 1 ==>wlan1
			}
			else {
				strcpy(para_iwctrl[wlan_num], ifname);
				wlan_num++;
			}	
		}
	}
#endif
	return 0;
}

void restart_iwcontrol(void)
{
	wlan_num = 0;
	useAuth_RootIf = 0;
	start_WPS(0);
	check_iwcontrol_8021x();
	start_iwcontrol();
}

/*----------------------------------------------------------------------------
 * Name:
 *      check_wlan_encrypt
 * Descriptions:
 *      check wlan encryption settings
 * Input:
 * Entry: MIB_CE_MBSSIB_Tp with new encryption settings
 * return:              
 * 0: ok
 * -1: something is invalid, may cause wlan setup error
 *---------------------------------------------------------------------------*/
int check_wlan_encrypt(MIB_CE_MBSSIB_Tp Entry)
{
	int len, keyLen;
	int i;
	char tmpBuf[100];
#if !defined(WLAN_WPS_VAP)
#ifdef WPS20
	unsigned char disableWps = 0;
#endif //WPS20
#endif

	if (Entry->encrypt == WIFI_SEC_NONE || Entry->encrypt == WIFI_SEC_WEP) {

		if (Entry->encrypt == WIFI_SEC_WEP) {
			if(Entry->enable1X != 1){
				// Mason Yu. 201009_new_security. If wireless do not use 802.1x for wep mode. We should set wep key and Authentication type.
				// (1) Authentication Type
				if(Entry->authType < AUTH_OPEN || Entry->authType > AUTH_BOTH)
					goto setErr_encrypt;

				// (2) Key Length
				if(Entry->wep < WEP64 || Entry->wep > WEP128)
					goto setErr_encrypt;

				// (3) Key Format
				if(Entry->wepKeyType < KEY_ASCII  || Entry->wepKeyType > KEY_HEX)
					goto setErr_encrypt;

				if (Entry->wep == WEP64) {

					keyLen = WEP64_KEY_LEN;
				
					if(strlen(Entry->wep64Key1) != keyLen)
						goto setErr_encrypt;
				}
				else {
				
					keyLen = WEP128_KEY_LEN;

					if(strlen(Entry->wep128Key1) != keyLen)
						goto setErr_encrypt;
				}

	#if !defined(WLAN_WPS_VAP)
				#ifdef WPS20
					Entry->wsc_disabled = 1;
				#endif
	#endif			
			}
			else if(Entry->enable1X){
				if(Entry->wep < WEP64 || Entry->wep > WEP128)
					goto setErr_encrypt;
			}
		}
	}
	else if(Entry->encrypt == WIFI_SEC_WPA || Entry->encrypt == WIFI_SEC_WPA2 || Entry->encrypt == WIFI_SEC_WPA2_MIXED) {	// WPA

		// Mason Yu. 201009_new_security. Set ciphersuite(wpa_cipher) for wpa/wpa mixed
		if ((Entry->encrypt == WIFI_SEC_WPA) || (Entry->encrypt == WIFI_SEC_WPA2_MIXED)) {

			if(Entry->unicastCipher < WPA_CIPHER_TKIP || Entry->unicastCipher > WPA_CIPHER_MIXED)
					goto setErr_encrypt;

#if !defined(WLAN_WPS_VAP)
			#ifdef WPS20
			if ((Entry->encrypt == WIFI_SEC_WPA) ||
				(Entry->encrypt == WIFI_SEC_WPA2_MIXED && Entry->unicastCipher == WPA_CIPHER_TKIP)) {	//disable wps if wpa only or tkip only
				disableWps = 1;
			}
			#endif
#endif
		}

		// Mason Yu. 201009_new_security. Set wpa2ciphersuite(wpa2_cipher) for wpa2/wpa mixed
		if ((Entry->encrypt == WIFI_SEC_WPA2) || (Entry->encrypt == WIFI_SEC_WPA2_MIXED)) {

			if(Entry->wpa2UnicastCipher < WPA_CIPHER_TKIP || Entry->wpa2UnicastCipher > WPA_CIPHER_MIXED)
					goto setErr_encrypt;

#if !defined(WLAN_WPS_VAP)
			#ifdef WPS20
			if (Entry->encrypt == WIFI_SEC_WPA2) {
				if (Entry->wpa2UnicastCipher == WPA_CIPHER_TKIP)
					disableWps = 1;
			}
			else { // mixed
				if (Entry->wpa2UnicastCipher == WPA_CIPHER_TKIP && disableWps)	//disable wps if wpa2 mixed + tkip only
					disableWps = 1;
				else
					disableWps = 0;
			}
			#endif //WPS20
#endif
		}
#if !defined(WLAN_WPS_VAP)
		#ifdef WPS20
		if (disableWps) {
			Entry->wsc_disabled = 1;
		}
		#endif //WPS20
#endif
		// pre-shared key
		if ( Entry->wpaAuth == WPA_AUTH_PSK ) {
			
			if(Entry->wpaPSKFormat < KEY_ASCII || Entry->wpaPSKFormat > KEY_HEX)
				goto setErr_encrypt;

			len = strlen(Entry->wpaPSK);

			if (Entry->wpaPSKFormat == KEY_HEX) { // hex
				if (len!=MAX_PSK_LEN || !string_to_hex(Entry->wpaPSK, tmpBuf, MAX_PSK_LEN)) {
					goto setErr_encrypt;
				}
			}
			else { // passphras
				if (len==0 || len > (MAX_PSK_LEN - 1) ) {
					goto setErr_encrypt;
				}
			}		
		}
		else if( Entry->wpaAuth == WPA_AUTH_AUTO){
			//need check ?
		}
	}
	else
		goto setErr_encrypt;

set_OK:
	return 0;

setErr_encrypt:
	return -1;
}
#if defined(CONFIG_RTL_STA_CONTROL_SUPPORT) && defined(WLAN_DUALBAND_CONCURRENT)
int SetOrCancelSameSSID(unsigned char sta_control) //update SSID & encryption
{
	MIB_CE_MBSSIB_T Entry24G, Entry5G;
	unsigned char ssid[MAX_SSID_LEN]={0};
	int ret=0;
	mib_chain_local_mapping_get(MIB_MBSSIB_TBL, 0, 0, &Entry24G);
	mib_chain_local_mapping_get(MIB_WLAN1_MBSSIB_TBL, 0, 0, &Entry5G);
	if(sta_control){
		strcpy(Entry5G.ssid, Entry24G.ssid);
		Entry5G.encrypt=Entry24G.encrypt;
		if(Entry24G.encrypt == WIFI_SEC_WEP){
			Entry5G.wep = Entry24G.wep;
			Entry5G.wepKeyType = Entry24G.wepKeyType;
			Entry5G.authType = Entry24G.authType;
			if(Entry24G.wep==WEP64){
				strncpy(Entry5G.wep64Key1, Entry24G.wep64Key1, WEP64_KEY_LEN);
			}
			else if(Entry24G.wep==WEP128){
				strncpy(Entry5G.wep128Key1, Entry24G.wep128Key1, WEP128_KEY_LEN);
			}
		}
		else if(Entry24G.encrypt>= WIFI_SEC_WPA){
			Entry5G.unicastCipher = Entry24G.unicastCipher;
			Entry5G.wpa2UnicastCipher = Entry24G.wpa2UnicastCipher;
			Entry5G.wpaAuth = Entry24G.wpaAuth;
			if(Entry24G.wpaAuth==WPA_AUTH_PSK){
				Entry5G.wpaPSKFormat = Entry24G.wpaPSKFormat;
				strncpy(Entry5G.wpaPSK, Entry24G.wpaPSK, MAX_PSK_LEN+1);
			}
		}
	}
	else{
		snprintf(ssid, MAX_SSID_LEN, "%s-5G", Entry24G.ssid);
		strcpy(Entry5G.ssid, ssid);
	}
	ret = mib_chain_local_mapping_update(MIB_WLAN1_MBSSIB_TBL, 0, &Entry5G, 0);
	return ret;
}
void setSameSSID(unsigned int ssidindex24, unsigned int ssidindex58, unsigned int *result, char *err)
{
	unsigned char wlan_sta_control;
	if(!(ssidindex24==1 && ssidindex58==(WLAN_SSID_NUM+1)))
	{
		*result = 1; //FAILED
		sprintf(err, "only support with root interface SSID index!");
		return;
	}
	if(	mib_get(MIB_WIFI_STA_CONTROL, (void *)&wlan_sta_control)==0)
	{
		*result = 1; //FAILED
		sprintf(err, "get SameSSIDStatus failed!");
		return;
	}
	if(wlan_sta_control == 0){
		wlan_sta_control = 1;
		if(mib_set(MIB_WIFI_STA_CONTROL, (void *)&wlan_sta_control)==0){
			*result = 1; //FAILED
			sprintf(err, "set SameSSIDStatus failed!");
			return;
		}
		SetOrCancelSameSSID(wlan_sta_control);
#ifdef COMMIT_IMMEDIATELY
		Commit();
#endif
#ifdef CONFIG_WIFI_SIMPLE_CONFIG
		update_wps_configured(0);
#endif 
		config_WLAN(ACT_RESTART, CONFIG_SSID_ALL);
		*result = 0; //SUCCESS
		sprintf(err, "success!");
		return;
	}
	else{
		*result = 1; //FAILED
		sprintf(err, "SameSSIDStatus is already true!");
		return;
	}
	
}
void cancelSameSSID(unsigned int *result, char *err)
{
	unsigned char wlan_sta_control;
	if(	mib_get(MIB_WIFI_STA_CONTROL, (void *)&wlan_sta_control)==0)
	{
		*result = 1; //FAILED
		sprintf(err, "get SameSSIDStatus failed!");
		return;
	}
	if(wlan_sta_control == 1){
		wlan_sta_control = 0;
		if(mib_set(MIB_WIFI_STA_CONTROL, (void *)&wlan_sta_control)==0){
			*result = 1; //FAILED
			sprintf(err, "set SameSSIDStatus failed!");
			return;
		}
		SetOrCancelSameSSID(wlan_sta_control);
#ifdef COMMIT_IMMEDIATELY
		Commit();
#endif
#ifdef CONFIG_WIFI_SIMPLE_CONFIG
		update_wps_configured(0);
#endif
		config_WLAN(ACT_RESTART, CONFIG_SSID_ALL);
		*result = 0; //SUCCESS
		sprintf(err, "success!");
		return;
	}
	else{
		*result = 1; //FAILED
		sprintf(err, "SameSSIDStatus is already false!");
		return;
	}
	
}

#endif

int get_wlan_net_device_stats(const char *ifname, struct net_device_stats *nds)
{
	FILE *fp = NULL;
	int num = 0;
	char wlan_path[128] = {0}, line[1024] = {0};
	snprintf(wlan_path, sizeof(wlan_path), "/proc/%s/stats", ifname);

	fp = fopen(wlan_path, "r");
	if (fp) {
		while (fgets(line, sizeof(line),fp)) {
			if (strstr(line, "rx_bytes")) {
				sscanf(line,"%*[^:]: %lu", &nds->rx_bytes);
				//fprintf(stderr, "[%s] ifname [%s], rx_bytes = %lu\n", __func__, ifname, nds->rx_bytes);
				num++;
			}
			else if(strstr(line, "rx_packets")) {
				sscanf(line,"%*[^:]: %lu", &nds->rx_packets);
				//fprintf(stderr, "[%s] ifname [%s], rx_packets = %lu\n", __func__, ifname, nds->rx_packets);
				num++;
			}
			else if(strstr(line, "rx_errors")) {
				sscanf(line,"%*[^:]: %lu", &nds->rx_errors);
				//fprintf(stderr, "[%s] ifname [%s], rx_errors = %lu\n", __func__, ifname, nds->rx_errors);
				num++;
			}
			else if(strstr(line, "rx_data_drops")) {
				sscanf(line,"%*[^:]: %lu", &nds->rx_dropped);
				//fprintf(stderr, "[%s] ifname [%s], rx_dropped = %lu\n", __func__, ifname, nds->rx_dropped);
				num++;
			}
			else if (strstr(line, "tx_bytes")) {
				sscanf(line,"%*[^:]: %lu", &nds->tx_bytes);
				//fprintf(stderr, "[%s] ifname [%s], tx_bytes = %lu\n", __func__, ifname, nds->tx_bytes);
				num++;
			}
			else if(strstr(line, "tx_packets")) {
				sscanf(line,"%*[^:]: %lu", &nds->tx_packets);
				//fprintf(stderr, "[%s] ifname [%s], tx_packets = %lu\n", __func__, ifname, nds->tx_packets);
				num++;
			}
			else if(strstr(line, "tx_fails")) {
				sscanf(line,"%*[^:]: %lu", &nds->tx_errors);
				//fprintf(stderr, "[%s] ifname [%s], tx_errors = %lu\n", __func__, ifname, nds->tx_errors);
				num++;
			}
			else if(strstr(line, "tx_drops")) {
				sscanf(line,"%*[^:]: %lu", &nds->tx_dropped);
				//fprintf(stderr, "[%s] ifname [%s], tx_dropped = %lu\n", __func__, ifname, nds->tx_dropped);
				num++;
			}
			if(num>7)
				break;
		}
		fclose(fp);
	}
	return 0;
}

#if (defined(CONFIG_CMCC) || defined(CONFIG_CU) || defined(CONFIG_YUEME)) && defined(CONFIG_RTK_L34_ENABLE)
int ssidisolation_portmap(void)
{
	unsigned char wlan_hw_diabled;
	MIB_CE_MBSSIB_T Entry;
	int i, j;

	for(i = 0; i<NUM_WLAN_INTERFACE; i++)
	{
		mib_local_mapping_get(MIB_WLAN_DISABLED, i, (void *)&wlan_hw_diabled);
		if(wlan_hw_diabled) {
			continue;
		}
		for ( j=0; j<=NUM_VWLAN_INTERFACE; j++) {
			if (!mib_chain_local_mapping_get(MIB_MBSSIB_TBL, i, j, (void *)&Entry)) {
				printf("Error! Get MIB_MBSSIB_TBL error.\n");
				continue;
			}
			RG_Wlan_Portisolation_Set(Entry.ssidisolation, ((i*(NUM_VWLAN_INTERFACE+1))+(j+1))); //wlan0
		}
	}
}
#endif

/*
 * ssid_index: 1~4 for single-band 1~8 for dual-band
 */
int get_ifname_by_ssid_index(int ssid_index, char *ifname)
{
	int max_ssid_index;
	
#ifdef WLAN_DUALBAND_CONCURRENT
	max_ssid_index = 8;
#else
	max_ssid_index = 4;
#endif
	if(ssid_index<1 || ssid_index>max_ssid_index)
		return -1;
		
	if(ssid_index==1)
		sprintf(ifname, "%s", WLANIF[0]);
	else if(ssid_index==5)
		sprintf(ifname, "%s", WLANIF[1]);
#ifdef WLAN_MBSSID
	else if(ssid_index<=4)
		sprintf(ifname, "%s-vap%d", WLANIF[0], ssid_index-2);
	else
		sprintf(ifname, "%s-vap%d", WLANIF[1], ssid_index-6);
#endif
	return 0;
}

#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
int ssid_index_to_wlan_index(int ssid_index)
{
	int wlanIndex=0;
	
	if(ssid_index<=4) 
	{
#if defined(WLAN0_5G_WLAN1_2G)
		wlanIndex = 1;
#elif defined(WLAN0_2G_WLAN1_5G)
		wlanIndex = 0;
#else
		wlanIndex = 0;
#endif
	}
#ifdef WLAN_DUALBAND_CONCURRENT
	else 
	{
#if defined(WLAN0_5G_WLAN1_2G)
		wlanIndex = 0;
#elif defined(WLAN0_2G_WLAN1_5G)
		wlanIndex = 1;
#endif
	}
#endif
	return wlanIndex;
}
#endif

// wl_ssid_idx == 0, set to all wlan ssid
int set_wlan_realtime_acl_mode(int wl_ssid_idx, int mode)
{
	int wlanIdx, wlanIdx_max, ssid_idx, ssid_idx_max;
	unsigned char acl_config = 0;
	char ifname[IFNAMSIZ];
	char parm[64];
	int status=0;
	FILE *fp =NULL;
	
	ssid_idx = wl_ssid_idx;
	if(ssid_idx <= 0){
		wlanIdx = 0;
#ifdef WLAN_DUALBAND_CONCURRENT
		wlanIdx_max=2;
#else
		wlanIdx_max=1;
#endif
		ssid_idx_max=WLAN_SSID_NUM;
		ssid_idx = 1;
	}
#ifdef WLAN_DUALBAND_CONCURRENT
	if(ssid_idx >WLAN_SSID_NUM){
		ssid_idx -= WLAN_SSID_NUM;
		ssid_idx_max = ssid_idx;
		wlanIdx = 1;
		wlanIdx_max = 2;
	}
#endif
	else
	{
		wlanIdx = 0;
		wlanIdx_max = 1;
		ssid_idx_max = ssid_idx;
	}

	for(; wlanIdx<wlanIdx_max; wlanIdx++)
	{
		for(; ssid_idx<=ssid_idx_max; ssid_idx++)
		{
			if(ssid_idx==1)
				snprintf(ifname, IFNAMSIZ, "%s", (char *)WLANIF[wlanIdx]);
			else
				snprintf(ifname, IFNAMSIZ, "%s-vap%d", (char *)WLANIF[wlanIdx], ssid_idx-2);
			
			acl_config = 0;
			snprintf(parm, sizeof(parm), "/sys/class/net/%s/operstate", ifname);
			if((fp = fopen(parm, "r"))){
				parm[0] = '\0';
				fgets(parm, sizeof(parm)-1,fp);	
				if(strncmp(parm, "down", 4)) acl_config = 1;
				fclose(fp);
			}
			if(acl_config){
				snprintf(parm, sizeof(parm), "aclmode=%d", mode);
				status|=va_cmd(IWPRIV, 3, 1, ifname, "set_mib", parm);
				//printf("======> %s %d set %s set_mib %s\n", __func__, __LINE__, ifname, parm);
			}
		}
	}
	return status;
}
int set_wlan_realtime_acl(int wl_ssid_idx, int action, unsigned char *macAddr)
{
	int i, wlanIdx, wlanIdx_max, ssid_idx, ssid_idx_max;
	unsigned char acl_config = 0;
	char ifname[IFNAMSIZ];
	char parm[64];
	int status=0;
	FILE *fp =NULL;

	ssid_idx = wl_ssid_idx;
	if(ssid_idx <= 0){
		wlanIdx = 0;
#ifdef WLAN_DUALBAND_CONCURRENT
		wlanIdx_max=2;
#else
		wlanIdx_max=1;
#endif
		ssid_idx_max=WLAN_SSID_NUM;
		ssid_idx = 1;
	}
#ifdef WLAN_DUALBAND_CONCURRENT
	if(ssid_idx >WLAN_SSID_NUM){
		ssid_idx -= WLAN_SSID_NUM;
		ssid_idx_max = ssid_idx;
		wlanIdx = 1;
		wlanIdx_max = 2;
	}
#endif
	else
	{
		wlanIdx = 0;
		wlanIdx_max = 1;
		ssid_idx_max = ssid_idx;
	}

	for(; wlanIdx<wlanIdx_max; wlanIdx++)
	{
		for(; ssid_idx<=ssid_idx_max; ssid_idx++)
		{
			if(ssid_idx==1)
				snprintf(ifname, IFNAMSIZ, "%s", (char *)WLANIF[wlanIdx]);
			else
				snprintf(ifname, IFNAMSIZ, "%s-vap%d", (char *)WLANIF[wlanIdx], ssid_idx-2);
			
			acl_config = 0;
			snprintf(parm, sizeof(parm), "/sys/class/net/%s/operstate", ifname);
			if((fp = fopen(parm, "r")))
			{
				parm[0] = '\0';
				fgets(parm, sizeof(parm)-1,fp);
				if(strncmp(parm, "down", 4)) acl_config = 1;
				fclose(fp);
			}
			if(acl_config)
			{
				if(action==2) //remove all
				{
					status|=va_cmd(IWPRIV, 2, 1, ifname, "clear_acl_table");
					//printf("======> %s %d clear_acl_table\n", __func__, __LINE__, ifname, parm);
				}
				else if(macAddr)
				{
					// acladdr
					snprintf(parm, sizeof(parm), "%.2x%.2x%.2x%.2x%.2x%.2x",
					macAddr[0], macAddr[1], macAddr[2],
					macAddr[3], macAddr[4], macAddr[5]);
					status|=va_cmd(IWPRIV, 3, 1, ifname, ((action==0)?"remove_acl_table":"add_acl_table"), parm);
					//printf("======> %s %d %s, %s, %s\n", __func__, __LINE__, ((action==0)?"remove_acl_table":"add_acl_table"), ifname, parm);
				}
			}
		}
	}
	
	return status;
}

#if defined(SUPPORT_ACCESS_RIGHT) && defined(CONFIG_YUEME)
int setup_wlan_realtime_acl(int wl_ssid_idx)
{
	int totalNum,index,status=0;
	MIB_LAN_HOST_ACCESS_RIGHT_T entry;

	totalNum = mib_chain_total(MIB_LAN_HOST_ACCESS_RIGHT_TBL);
	if(totalNum > 0){
		set_wlan_realtime_acl_mode(wl_ssid_idx, 2);
	}
	for(index=0; index<totalNum; index++)
	{
		mib_chain_get(MIB_LAN_HOST_ACCESS_RIGHT_TBL,index,&entry);
		if( entry.internetAccessRight == INTERNET_ACCESS_DENY)
		{
			status|=set_wlan_realtime_acl(wl_ssid_idx, 1, entry.mac);
		}
	}
	return status;
}
#endif

#if defined(CONFIG_YUEME)
int IpPortStrToSockaddr(char *str, ipPortRange *ipport)
{
	char *c, *tmp_port = NULL;
	char buf[65], *v2 = NULL;
	int port;
	if(str == NULL || ipport == NULL) return 0;

	memset(ipport, 0, sizeof(ipPortRange));
	ipport->sin_family = AF_INET;
	ipport->eth_protocol = 0x0800;
	if((c = strchr(str, ':'))){
		v2 = NULL;
		tmp_port = c+1;
		strncpy(buf, str, c-str);
		buf[c-str] = '\0';
		if((c = strchr(buf, '-'))){
			*c = '\0';
			v2 = c+1;
		}
		if(inet_aton(buf, (struct in_addr *)ipport->start_addr) == 0)
			return 0;
		if(v2){
			if(inet_aton(v2, (struct in_addr *)ipport->end_addr) == 0)
				return 0;
		}else
			memcpy(ipport->end_addr, ipport->start_addr, sizeof(ipport->end_addr));
	}
	
	if(tmp_port){
		v2 = NULL;
		strcpy(buf, tmp_port);
		if((c = strchr(buf, '-'))){
			*c = '\0';
			v2 = c+1;
		}
		port = atoi(buf);
		if(port<0 || port>65535) return 0;
		ipport->start_port = port;
		
		if(v2){
			port = atoi(buf);
			if(port<0 || port>65535) return 0;
			ipport->end_port = port;
		}
		else 
			ipport->end_port = ipport->start_port;
	}
	return 1;
}

int setup_wlan_accessRule_netfilter_init()
{
	//va_cmd(EBTABLES, 6, 1, "-D", "INPUT", "-i", "wlan+", "-j", "WLACL_INPUT");
	//va_cmd(EBTABLES, 6, 1, "-D", "FORWARD", "-i", "wlan+", "-j", "WLACL_FORWARD");
	
	//va_cmd(EBTABLES, 2, 1, "-X", "WLACL_INPUT");
	//va_cmd(EBTABLES, 2, 1, "-X", "WLACL_FORWARD");
	va_cmd(EBTABLES, 2, 1, "-N", "WLACL_INPUT");
	va_cmd(EBTABLES, 2, 1, "-N", "WLACL_FORWARD");
	va_cmd(EBTABLES, 3, 1, "-P", "WLACL_INPUT", "RETURN");
	va_cmd(EBTABLES, 3, 1, "-P", "WLACL_FORWARD", "RETURN");
	//va_cmd(EBTABLES, 3, 1, "-A", "INPUT", "--logical-in wlan+ -j WLACL_INPUT");
	//va_cmd(EBTABLES, 3, 1, "-A", "FORWARD", "--logical-in wlan+ -j WLACL_FORWARD");
	va_cmd(EBTABLES, 6, 1, "-A", "INPUT", "-i", "wlan+", "-j", "WLACL_INPUT");
	va_cmd(EBTABLES, 6, 1, "-A", "FORWARD", "-i", "wlan+", "-j", "WLACL_FORWARD");
	
	return 1;
}

#ifndef inet_ntoa_r
static unsigned int i2a(char* dest,unsigned int x) {
  register unsigned int tmp=x;
  register unsigned int len=0;
  if (x>=100) { *dest++=tmp/100+'0'; tmp=tmp%100; ++len; }
  if (x>=10) { *dest++=tmp/10+'0'; tmp=tmp%10; ++len; }
  *dest++=tmp+'0';
  return len+1;
}

char *inet_ntoa_r(struct in_addr in,char* buf) {
  unsigned int len;
  unsigned char *ip=(unsigned char*)&in;
  len=i2a(buf,ip[0]); buf[len]='.'; ++len;
  len+=i2a(buf+ len,ip[1]); buf[len]='.'; ++len;
  len+=i2a(buf+ len,ip[2]); buf[len]='.'; ++len;
  len+=i2a(buf+ len,ip[3]); buf[len]=0;
  return buf;
}
#endif

int setup_wlan_accessRule_netfilter(char *ifname, MIB_CE_MBSSIB_Tp pEntry)
{
	char chain_input[64], chain_forward[64];
	char port[32], addr[64];
	char *protocol[] = {"tcp","udp"};
	char *s, *s_tmp, *rule, *pcmd, *paddr;
	char *argv[24];
	int n, i;
	ipPortRange ipport;
	
	sprintf(chain_input, "WLACL_%s_INPUT", ifname);
	sprintf(chain_forward, "WLACL_%s_FORWARD", ifname);
	
	//sprintf(cmd, "--logical-in %s -j %s", ifname, chain_input);
	va_cmd(EBTABLES, 6, 1, "-D", "WLACL_INPUT", "-i", ifname, "-j", chain_input);
	//sprintf(cmd, "--logical-in %s -j %s", ifname, chain_forward);
	va_cmd(EBTABLES, 6, 1, "-D", "WLACL_FORWARD", "-i", ifname, "-j", chain_forward);
	
	va_cmd(EBTABLES, 2, 1, "-X", chain_input);
	va_cmd(EBTABLES, 2, 1, "-X", chain_forward);
	
	if(!pEntry->wlanDisabled && pEntry->accessRuleEnable)
	{
		va_cmd(EBTABLES, 2, 1, "-N", chain_input);
		va_cmd(EBTABLES, 2, 1, "-N", chain_forward);
		va_cmd(EBTABLES, 3, 1, "-P", chain_input, "RETURN");
		va_cmd(EBTABLES, 3, 1, "-P", chain_forward, "RETURN");
		
		//sprintf(cmd, "--logical-in %s -j %s", ifname, chain_input);
		va_cmd(EBTABLES, 6, 1, "-A", "WLACL_INPUT", "-i", ifname, "-j", chain_input);
		//sprintf(cmd, "--logical-in %s -j %s", ifname, chain_forward);
		va_cmd(EBTABLES, 6, 1, "-A", "WLACL_FORWARD", "-i", ifname, "-j", chain_forward);
		
		if(pEntry->accessRuleEnable == 1)
		{
			va_cmd(EBTABLES, 6, 1, "-A", chain_input, "-p", "arp", "-j", "ACCEPT");
			va_cmd(EBTABLES, 10, 1, "-A", chain_input, "-p", "IPv4", "--ip-proto", "udp", "--ip-dport", "67:68", "-j", "ACCEPT");
			va_cmd(EBTABLES, 10, 1, "-A", chain_input, "-p", "IPv4", "--ip-proto", "udp", "--ip-dport", "53", "-j", "ACCEPT");	
			va_cmd(EBTABLES, 4, 1, "-A", chain_input, "-j", "DROP");
			va_cmd(EBTABLES, 6, 1, "-A", chain_forward, "-p", "arp", "-j", "ACCEPT");
			va_cmd(EBTABLES, 6, 1, "-A", chain_forward, "-o", "nas+", "-j", "ACCEPT");
			va_cmd(EBTABLES, 4, 1, "-A", chain_forward, "-j", "DROP");
		}
		else if(pEntry->accessRuleEnable == 2)
		{
			va_cmd(EBTABLES, 6, 1, "-A", chain_input, "-p", "arp", "-j", "ACCEPT");
			va_cmd(EBTABLES, 10, 1, "-A", chain_input, "-p", "IPv4", "--ip-proto", "udp", "--ip-dport", "67:68", "-j", "ACCEPT");
			va_cmd(EBTABLES, 10, 1, "-A", chain_input, "-p", "IPv4", "--ip-proto", "udp", "--ip-dport", "53", "-j", "ACCEPT");
			va_cmd(EBTABLES, 6, 1, "-A", chain_forward, "-p", "arp", "-j", "ACCEPT");
			va_cmd(EBTABLES, 10, 1, "-A", chain_forward, "-p", "IPv4", "--ip-proto", "udp", "--ip-dport", "67:68", "-j", "ACCEPT");
			va_cmd(EBTABLES, 10, 1, "-A", chain_forward, "-p", "IPv4", "--ip-proto", "udp", "--ip-dport", "53", "-j", "ACCEPT");
			
			if(pEntry->allowedIPPort[0] && (rule = strdup(pEntry->allowedIPPort)))
			{
				s = rule;
				while(s = strtok_r(s, ",", &s_tmp))
				{
					if(IpPortStrToSockaddr(s, &ipport))
					{
						if(ipport.sin_family == AF_INET)
						{
							struct in_addr addr_v4 = *((struct in_addr *)&(ipport.start_addr));

							for(i=0; i<(sizeof(protocol)/sizeof(char*)); i++)
							{
								port[0] = 0;
								addr[0] = 0;
								paddr = NULL;
								memset(argv, 0, sizeof(argv));

								if(addr_v4.s_addr > 0) paddr = inet_ntoa_r(addr_v4, addr);
								if(ipport.start_port > 0) {
									pcmd = port;
									pcmd += sprintf(pcmd, "%u", ipport.start_port);
									if(ipport.end_port > ipport.start_port)
										sprintf(pcmd, ":%u", ipport.end_port);
								}
								if(port[0] == 0 && paddr == NULL) break;
								n = 0;
								argv[n++] = NULL;
								argv[n++] = "-A";
								argv[n++] = chain_input;
								argv[n++] = "-p";
								argv[n++] = "IPv4";
								if(*paddr)
								{
									argv[n++] = "--ip-dst";
									argv[n++] = paddr;
								}
								if(port[0])
								{
									argv[n++] = "--ip-proto";
									argv[n++] = protocol[i];
									argv[n++] = "--ip-dport";
									argv[n++] = port;
								}
								argv[n++] = "-j";
								argv[n++] = "ACCEPT";
								
								do_cmd(EBTABLES, argv, 1);
								argv[2] = chain_forward;
								do_cmd(EBTABLES, argv, 1);
							}
						}
					}
					s = s_tmp;
				}
				free(rule);
			}
			
			va_cmd(EBTABLES, 4, 1, "-A", chain_input, "-j", "DROP");
			va_cmd(EBTABLES, 4, 1, "-A", chain_forward, "-j", "DROP");
		}
	}
}

int setup_wlan_accessRule(void)
{
	int i,j, n;
	MIB_CE_MBSSIB_T Entry;
	char *s, *s_tmp;
	ipPortRange ipport;
	wl_ipport_rule *droprule, *arprule, *dhcprule, *dnsrule, *prule, *lprule;
	
	droprule = calloc(1, sizeof(wl_ipport_rule));
	droprule->action = 0;
	
	dnsrule = calloc(1, sizeof(wl_ipport_rule));
	dnsrule->action = 1;
	dnsrule->ipport.start_port = 53;
	dnsrule->ipport.end_port = 53;
	dnsrule->ipport.sin_family = AF_INET;
	dnsrule->ipport.eth_protocol = 0x0800;
	dnsrule->next = droprule;
	
	dhcprule = calloc(1, sizeof(wl_ipport_rule));
	dhcprule->action = 1;
	dhcprule->ipport.start_port = 67;
	dhcprule->ipport.end_port = 68;
	dhcprule->ipport.sin_family = AF_INET;
	dhcprule->ipport.eth_protocol = 0x0800;
	dhcprule->next = dnsrule;
	
	arprule = calloc(1, sizeof(wl_ipport_rule));
	arprule->action = 1;
	arprule->ipport.sin_family = AF_INET;
	arprule->ipport.eth_protocol = 0x0806;
	arprule->next = dhcprule;

	prule = arprule;
	
	for(i=0; i<NUM_WLAN_INTERFACE; i++)
	{
		for (j=0; j<=WLAN_MBSSID_NUM; j++) 
		{		
			if (!mib_chain_local_mapping_get(MIB_MBSSIB_TBL, i, j, (void *)&Entry)) {
				printf("Error! Get MIB_MBSSIB_TBL error.\n");
			}
			else
			{
				if (!Entry.wlanDisabled && Entry.accessRuleEnable)
				{
					dnsrule->wlan_idx_mask |= 1<<(i*WLAN_MBSSID_NUM+j);
					dhcprule->wlan_idx_mask |= 1<<(i*WLAN_MBSSID_NUM+j);
					arprule->wlan_idx_mask |= 1<<(i*WLAN_MBSSID_NUM+j);
					
					if(Entry.allowedIPPort[0] && Entry.accessRuleEnable == 2)
					{
						droprule->wlan_idx_mask |= 1<<(i*WLAN_MBSSID_NUM+j);
						
						s = Entry.allowedIPPort;
						while(s = strtok_r(s, ",", &s_tmp))
						{
							if(IpPortStrToSockaddr(s, &ipport))
							{
								lprule = prule;
								while(lprule)
								{
									if(!memcmp(&(lprule->ipport), &ipport, sizeof(ipport)))
									{
										lprule->wlan_idx_mask |= 1<<(i*WLAN_MBSSID_NUM+j);
										break;
									}
									lprule = lprule->next;
								}
								if(lprule == NULL)
								{
									lprule = calloc(1, sizeof(wl_ipport_rule));
									lprule->action = 1;
									memcpy(&(lprule->ipport), &ipport, sizeof(ipport));
									lprule->wlan_idx_mask |= 1<<(i*WLAN_MBSSID_NUM+j);
									lprule->next = prule;
									prule = lprule;
								}
							}
							s = s_tmp;
						}
					}
				}
			}
		}
	}
#ifdef CONFIG_RTK_L34_ENABLE
	if(RTK_RG_Wifi_AccessRule_ACL_Rule_set(prule) != 0){
		fprintf(stderr, "[%s@%d] ERROR! config RG rule\n", __FUNCTION__, __LINE__);
	}
#endif

	while(prule)
	{
		lprule = prule;
		prule = prule->next;
		free(lprule);
	}
	return 1;
}
#endif

#if defined(CONFIG_YUEME) || defined(CONFIG_CMCC) || defined(CONFIG_CU)
typedef struct macfilter_t{
	unsigned char mac[MAC_ADDR_LEN];
	unsigned char tail;
	struct macfilter_t *next;
}macfilter_s;

static int findMacFilterEntry(char *mac, macfilter_s *list)
{
	macfilter_s *t = list;
	while(t && t->tail == 0){
		if(!memcmp(mac, t->mac, MAC_ADDR_LEN))
			return 1;
		t = t->next;
	}
	return 0;
}

static void freeMacFilterList(macfilter_s *list)
{
	macfilter_s *t = list, *tmp;
	while(t && t->tail == 0){
		tmp = t;
		free(tmp);
		t = t->next;
	}
}

int setup_wlan_MAC_ACL(void)
{
	char parm[64], ifname[IFNAMSIZ];
#if defined(SUPPORT_ACCESS_RIGHT)
	MIB_LAN_HOST_ACCESS_RIGHT_T hostEntry;
#endif
	MIB_CE_MBSSIB_T wlEntry;
	MIB_CE_ROUTEMAC_T macEntry;
	macfilter_s whiteList, blackList, hostBlockList;
	macfilter_s *pwhiteList, *pblackList, *phostBlockList, *tmpList;
	int totalNum, index, i, j;
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	unsigned char macFilterEnable = 0;
	mib_get(MIB_MAC_FILTER_SRC_ENABLE, &macFilterEnable);
#endif

	
	pwhiteList = &whiteList; whiteList.tail = 1;
	pblackList = &blackList; blackList.tail = 1;
	phostBlockList = &hostBlockList; hostBlockList.tail = 1;
	
#if defined(SUPPORT_ACCESS_RIGHT)
	totalNum = mib_chain_total(MIB_LAN_HOST_ACCESS_RIGHT_TBL);
	for(i=0; i<totalNum; i++)
	{
		if(mib_chain_get(MIB_LAN_HOST_ACCESS_RIGHT_TBL,i,&hostEntry) &&
			hostEntry.internetAccessRight == INTERNET_ACCESS_DENY)
		{
			tmpList = calloc(1, sizeof(macfilter_s));
			if(tmpList)
			{
				memcpy(tmpList->mac, hostEntry.mac, MAC_ADDR_LEN);
				tmpList->next = phostBlockList;
				phostBlockList = tmpList;
			}
		}
	}
#endif

	totalNum = mib_chain_total(MIB_MAC_FILTER_ROUTER_TBL);
	for(i=0; i<totalNum; i++)
	{
		if(mib_chain_get(MIB_MAC_FILTER_ROUTER_TBL, i, &macEntry))
		{
#ifdef MAC_FILTER_BLOCKTIMES_SUPPORT
			if(macEntry.enable)
#endif
			{
				tmpList = calloc(1, sizeof(macfilter_s));
				if(tmpList)
				{
					convertMacFormat(macEntry.mac, tmpList->mac);
					if(macEntry.mode){
						tmpList->next = pwhiteList;
						pwhiteList = tmpList;
					}
					else{
						tmpList->next = pblackList;
						pblackList = tmpList;
					}
				}
			}
		}
	}
	
	for(i=0; i<NUM_WLAN_INTERFACE; i++)
	{
		for (j=0; j<=WLAN_MBSSID_NUM; j++) 
		{		
			if (!mib_chain_local_mapping_get(MIB_MBSSIB_TBL, i, j, (void *)&wlEntry)) {
				printf("Error! Get MIB_MBSSIB_TBL error.\n");
			}
			else if(!wlEntry.wlanDisabled)
			{
				if(j == 0)
					snprintf(ifname, IFNAMSIZ, "%s", (char *)WLANIF[i]);
				else
					snprintf(ifname, IFNAMSIZ, "%s-vap%d", (char *)WLANIF[i], j-1);

#ifdef CONFIG_YUEME
				if(wlEntry.macAccessMode == 1) //Black List
#elif defined(CONFIG_CMCC) || defined(CONFIG_CU)
				if(macFilterEnable == 1) //Black List
#endif
				{
					va_cmd(IWPRIV, 2, 1, ifname, "clear_acl_table");
					//printf("====> iwpriv %s clear_acl_table\n", ifname);
					snprintf(parm, sizeof(parm), "aclmode=2");
					va_cmd(IWPRIV, 3, 1, ifname, "set_mib", parm);
					//printf("====> iwpriv %s set_mib %s\n", ifname, parm);
					
					tmpList = pblackList;
					while(tmpList && tmpList->tail == 0)
					{
						snprintf(parm, sizeof(parm), "%.2x%.2x%.2x%.2x%.2x%.2x",
							tmpList->mac[0], tmpList->mac[1], tmpList->mac[2],
							tmpList->mac[3], tmpList->mac[4], tmpList->mac[5]);
						va_cmd(IWPRIV, 3, 1, ifname, "add_acl_table", parm);
						//printf("====> iwpriv %s add_acl_table %s\n", ifname, parm);
						tmpList = tmpList->next;
					}
					
					tmpList = phostBlockList;
					while(tmpList && tmpList->tail == 0)
					{
						if(!findMacFilterEntry(tmpList->mac, pblackList))
						{
							snprintf(parm, sizeof(parm), "%.2x%.2x%.2x%.2x%.2x%.2x",
								tmpList->mac[0], tmpList->mac[1], tmpList->mac[2],
								tmpList->mac[3], tmpList->mac[4], tmpList->mac[5]);
							va_cmd(IWPRIV, 3, 1, ifname, "add_acl_table", parm);
							//printf("====> iwpriv %s add_acl_table %s\n", ifname, parm);
						}
						tmpList = tmpList->next;
					}
				}
#ifdef CONFIG_YUEME
				else if(wlEntry.macAccessMode == 2) //White List
#elif defined(CONFIG_CMCC) || defined(CONFIG_CU)
				else if(macFilterEnable == 2) //White List
#endif
				{
					va_cmd(IWPRIV, 2, 1, ifname, "clear_acl_table");
					//printf("====> iwpriv %s clear_acl_table\n", ifname);
					snprintf(parm, sizeof(parm), "aclmode=1");
					va_cmd(IWPRIV, 3, 1, ifname, "set_mib", parm);
					//printf("====> iwpriv %s set_mib %s\n", ifname, parm);
					
					tmpList = pwhiteList;
					while(tmpList && tmpList->tail == 0)
					{
						if(!findMacFilterEntry(tmpList->mac, phostBlockList))
						{
							snprintf(parm, sizeof(parm), "%.2x%.2x%.2x%.2x%.2x%.2x",
								tmpList->mac[0], tmpList->mac[1], tmpList->mac[2],
								tmpList->mac[3], tmpList->mac[4], tmpList->mac[5]);
							va_cmd(IWPRIV, 3, 1, ifname, "add_acl_table", parm);
							//printf("====> iwpriv %s add_acl_table %s\n", ifname, parm);
						}
						tmpList = tmpList->next;
					}
				}
				else
				{
					va_cmd(IWPRIV, 2, 1, ifname, "clear_acl_table");
					//printf("====> iwpriv %s clear_acl_table\n", ifname);
					snprintf(parm, sizeof(parm), "aclmode=%d", (phostBlockList->tail) ? 0 : 2);
					va_cmd(IWPRIV, 3, 1, ifname, "set_mib", parm);
					//printf("====> iwpriv %s set_mib %s\n", ifname, parm);
					
					tmpList = phostBlockList;
					while(tmpList && tmpList->tail == 0)
					{
						snprintf(parm, sizeof(parm), "%.2x%.2x%.2x%.2x%.2x%.2x",
							tmpList->mac[0], tmpList->mac[1], tmpList->mac[2],
							tmpList->mac[3], tmpList->mac[4], tmpList->mac[5]);
						va_cmd(IWPRIV, 3, 1, ifname, "add_acl_table", parm);
						//printf("====> iwpriv %s add_acl_table %s\n", ifname, parm);
						tmpList = tmpList->next;
					}
				}
			}
		}
	}

	freeMacFilterList(pwhiteList);
	freeMacFilterList(pblackList);
	freeMacFilterList(phostBlockList);
	
	return 1;
}
#endif

#ifdef CONFIG_YUEME
int get_wlan_MAC_ACL_BlockTimes(const unsigned char *mac)
{
	int i, j;
	MIB_CE_MBSSIB_T wlEntry;
	char ifname[IFNAMSIZ], line[128] = {0}, file_block[64], *tmp;
	unsigned int blocktimes = 0, n;
	FILE *fp = NULL;
	
	for(i=0; i<NUM_WLAN_INTERFACE; i++)
	{
		for (j=0; j<=WLAN_MBSSID_NUM; j++) 
		{		
			if (mib_chain_local_mapping_get(MIB_MBSSIB_TBL, i, j, (void *)&wlEntry) 
				&& !wlEntry.wlanDisabled
				&& wlEntry.macAccessMode == 1 )
			{
				if(j == 0)
					snprintf(ifname, IFNAMSIZ, "%s", (char *)WLANIF[i]);
				else
					snprintf(ifname, IFNAMSIZ, "%s-vap%d", (char *)WLANIF[i], j-1);
				
				sprintf(file_block, "/tmp/%s_deny_sta_%02x%02x%02x%02x%02x%02x", ifname, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
				sprintf(line, "cat /proc/%s/mib_staconfig | grep %02x%02x%02x%02x%02x%02x > %s", 
								ifname, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], file_block);
				system(line);
				
				if((fp = fopen(file_block, "r")))
				{
					n = 0;
					line[0] = '\0';
					fgets(line, sizeof(line)-1, fp);
					tmp = strstr(line, "BlockTimes:");
					if(tmp){
						tmp+=11;
						n = strtoul(tmp, NULL, 0);
					}
					blocktimes += n;
					fclose(fp);
					unlink(file_block);
				}
			}
		}
	}
	
	return blocktimes;
}
#endif

int getWlanStatus(int idx)
{
	MIB_CE_MBSSIB_T Entry;
	int j=0;
	unsigned int intf_map=0;
	for (j=0; j<=WLAN_MBSSID_NUM; j++) {				
		if (!mib_chain_local_mapping_get(MIB_MBSSIB_TBL, idx, j, (void *)&Entry)) {
			printf("Error! Get MIB_MBSSIB_TBL error.\n");
		}
		else{
			if (!Entry.wlanDisabled) {
				intf_map |= (1 << j);
			}
		}
	}

	printf("%s %s!\n", WLANIF[idx], intf_map!=0? "enable":"disable");
	return intf_map!=0;
}

static void applyWlanLed(int idx)
{
#ifdef CONFIG_LED_INDICATOR_TIMER
	unsigned char led_status=1;
#endif
	char cmd_str[256]={0};
#ifdef CONFIG_LED_INDICATOR_TIMER
	mib_get(MIB_LED_STATUS, (void *)&led_status);
	if(led_status)
#endif
	{
#ifndef CONFIG_WIFI_LED_USE_SOC_GPIO
		if(getWlanStatus(idx))
			snprintf(cmd_str, sizeof(cmd_str), "echo 2 > /proc/%s/led", WLANIF[idx]);
		else
			snprintf(cmd_str, sizeof(cmd_str), "echo 0 > /proc/%s/led", WLANIF[idx]);
		printf("%s\n", cmd_str);
		system(cmd_str);		
#endif
	}
}

// led_mode: 0:led off   1:led on 2:led state restore
int set_wlan_led_status(int led_mode)
{
	int i=0;
	char cmd_str[256]={0};
	int led_value;
#ifdef CONFIG_LED_INDICATOR_TIMER
//	unsigned char led_status=1;
//	mib_get(MIB_LED_STATUS, (void *)&led_status);
#endif

	for(i=0; i<NUM_WLAN_INTERFACE; i++){
		if(led_mode == 0 || led_mode == 1){
			led_value = led_mode;
		}
		else if(led_mode == 2){
#ifdef CONFIG_LED_INDICATOR_TIMER
//			if(led_status)	//no control of led, check wlan status
#endif
			{
				if(getWlanStatus(i))
					led_value = 2;
				else
					led_value = 0; // set wifi led off when root is func_off and no vap interface up
			}
#ifdef CONFIG_LED_INDICATOR_TIMER
//			else //led_status==0
//				led_value = 0;
#endif
		}
#ifndef CONFIG_WIFI_LED_USE_SOC_GPIO		
		snprintf(cmd_str, sizeof(cmd_str), "echo %d > /proc/%s/led", led_value, WLANIF[i]);
		printf("%s\n", cmd_str);
		system(cmd_str);		
#endif
#ifdef CONFIG_SLAVE_WLAN1_ENABLE
		if(!strcmp("wlan1", WLANIF[i])){
			snprintf(cmd_str, sizeof(cmd_str), "echo %d >> /proc/%s/led", led_value, WLANIF[i]);
			printf("%s\n", cmd_str);
			system(cmd_str);
		}		
#endif
	}
	return 0;
}
#ifdef _PRMT_X_WLANFORISP_
int isWLANForISP(int vwlan_idx)
{
	int k, total = mib_chain_total(MIB_WLANFORISP_TBL);
	MIB_WLANFORISP_T Entry;
	
	for(k=0; k<total; k++){
		if(mib_chain_get(MIB_WLANFORISP_TBL, k, &Entry)==0)
			continue;
		if(Entry.SSID_IDX == (wlan_idx*(1+WLAN_MBSSID_NUM)+(vwlan_idx+1)))
			return 1;
	}
	return 0;
}
//update when MIB_WLANFORISP_TBL change
void update_WLANForISP_configured(void)
{
	int i, j, k, total = mib_chain_total(MIB_WLANFORISP_TBL);
	MIB_WLANFORISP_T Entry;
	MIB_CE_MBSSIB_T mEntry;
	int found=0, change_flag=0, change_update_flag=0;

	for(i=0; i<NUM_WLAN_INTERFACE;i++){
		for(j=0; j<=WLAN_MBSSID_NUM; j++){
			if(mib_chain_local_mapping_get(MIB_MBSSIB_TBL, i, j, &mEntry)==0)
				continue;
			found = 0;
			change_flag = 0;
			for(k=0; k<total; k++){
				if(mib_chain_get(MIB_WLANFORISP_TBL, k, &Entry)==0)
					continue;
				if(Entry.SSID_IDX == (i*(1+WLAN_MBSSID_NUM)+(j+1))){
					if(mEntry.encrypt==WIFI_SEC_NONE || mEntry.encrypt==WIFI_SEC_WEP){
						if(mEntry.enable1X == 0){
							mEntry.enable1X = 1;
							change_flag = 1;
						}
						if(mEntry.wpaAuth == WPA_AUTH_AUTO){
							mEntry.wpaAuth = WPA_AUTH_PSK;
							change_flag = 1;
						}
					}
					else if(mEntry.encrypt >= WIFI_SEC_WPA){
						if(mEntry.wpaAuth == WPA_AUTH_PSK){
							mEntry.wpaAuth = WPA_AUTH_AUTO;
							change_flag = 1;
						}
						if(mEntry.enable1X == 1){
							mEntry.enable1X = 0;
							change_flag = 1;
						}
					}
					if(strcmp(mEntry.ssid, Entry.SSID)){
						strcpy(mEntry.ssid, Entry.SSID);
						change_flag = 1;
					}
					if(strcmp(mEntry.rsPassword, Entry.RadiusKey)){
						strcpy(mEntry.rsPassword, Entry.RadiusKey);
						change_flag = 1;
					}
					if(*((unsigned long *)mEntry.rsIpAddr)!= *((unsigned long *)Entry.RadiusServer)){
						*((unsigned long *)mEntry.rsIpAddr) =  *((unsigned long *)Entry.RadiusServer);
						change_flag = 1;
					}
					found = 1;
					break;
				}
			}
			if(found==0){ //change back if entry is deleted
				if(mEntry.enable1X==1){
					mEntry.enable1X = 0;
					change_flag = 1;
				}
				if(mEntry.wpaAuth == WPA_AUTH_AUTO){
					mEntry.wpaAuth = WPA_AUTH_PSK;
					change_flag = 1;
				}
			}
			if(change_flag){
				mib_chain_local_mapping_update(MIB_MBSSIB_TBL, i, &mEntry, j);
				change_update_flag = 1;
			}
		}
	}
	if(change_update_flag){
#ifdef COMMIT_IMMEDIATELY
		Commit();
#endif		
	}
	return;
}
//sync when MIB_MBSSIB_TBL change
void sync_WLANForISP(int ssid_idx, MIB_CE_MBSSIB_T *Entry)
{
	int k, total = mib_chain_total(MIB_WLANFORISP_TBL);
	MIB_WLANFORISP_T wEntry;
	int change_flag=0;
	
	for(k=0; k<total; k++){
		if(mib_chain_get(MIB_WLANFORISP_TBL, k, &wEntry)==0)
			continue;
		if(wEntry.SSID_IDX == ssid_idx){
			if(strcmp(Entry->ssid, wEntry.SSID)){
				strcpy(wEntry.SSID, Entry->ssid);
				change_flag = 1;
			}
			if(Entry->encrypt==WIFI_SEC_NONE || Entry->encrypt==WIFI_SEC_WEP){
				if(Entry->enable1X == 0){
					Entry->enable1X = 1;
				}
				if(Entry->wpaAuth == WPA_AUTH_AUTO){
					Entry->wpaAuth = WPA_AUTH_PSK;
				}
			}
			else if(Entry->encrypt>=WIFI_SEC_WPA){
				if(Entry->wpaAuth == WPA_AUTH_PSK){
					Entry->wpaAuth = WPA_AUTH_AUTO;
				}
				if(Entry->enable1X == 1){
					Entry->enable1X = 0;
				}
			}
			break;
		}
	}
	if(change_flag)
		mib_chain_update(MIB_WLANFORISP_TBL, &wEntry, k);
}
int getWLANForISP_ifname(char *ifname, MIB_WLANFORISP_T *wlan_isp_entry)
{
	int entry_total= mib_chain_total(MIB_IP_ROUTE_TBL);
	int i=0;
	MIB_CE_IP_ROUTE_T entry;
	
	for(i=0; i<entry_total; i++){
		if(mib_chain_get(MIB_IP_ROUTE_TBL, i, &entry)==0){
			continue;
		}
		if(*((unsigned long *)wlan_isp_entry->RadiusServer)== *((unsigned long *)entry.destID)){
			if(ifGetName(entry.ifIndex, ifname, 16)){
				//printf("%s %d %s\n", __func__, __LINE__, ifname);
				return 0;
			}
			else{
				printf("%s %d ifGetName failed!\n",__func__, __LINE__);
				return -1;
			}
		}
	}
	printf("%s %d IP_ROUTE_TBL not found!\n",__func__, __LINE__);
	return -1;
}

#endif

/***
get_wlan_channel_scan_status
return:
	0 => error,
	1 => not compelete,
	2 => compelete
***/
int get_wlan_channel_scan_status(int idx)
{
	char buf[256] = {0};
	FILE *fp = NULL;
	int ret = 0;
	if(idx >= 0 && idx < (sizeof(WLANIF)/sizeof(char*))){
		//printf("%s: %s, idx = %d\n", __FUNCTION__, WLANIF[idx], idx);
		sprintf(buf, "/proc/%s/SS_Result", WLANIF[idx]);
		fp = fopen(buf, "r");
		if(fp){
			if(fgets(buf, sizeof(buf)-1, fp) != NULL){
				if(!strncmp(buf, "waitting", 8)){
					ret = 1;
				}
				else if(!strncmp(buf, " SiteSurvey result", 18)){
					if(fgets(buf, sizeof(buf)-1, fp) 
						&& fgets(buf, sizeof(buf)-1, fp)) // rechek line 3
					{
						/*if(!strncmp(buf, "none", 4)){
							ret = 1;
						}
						else*/
						{
							ret = 2;
						}
					}	
				}
			}
			fclose(fp);
		}
	}
out:
	//printf(">> %s: ret = %d\n", __FUNCTION__, ret);
	return ret;
}

/***
start_wlan_channel_scan
return:
	0 => error,
	1 => success,
***/
int start_wlan_channel_scan(int idx)
{
	int ret = 0, skfd;
	struct iwreq wrq;
	
	if(idx >= 0 && idx < (sizeof(WLANIF)/sizeof(char*)))
	{
		memset(&wrq, 0, sizeof(struct iwreq));
		skfd = socket(AF_INET, SOCK_DGRAM, 0);
		
		if ( iw_get_ext(skfd,(char*) WLANIF[idx], SIOCGIWNAME, &wrq) < 0)
		{
			close( skfd );
		  /* If no wireless name : no wireless extensions */
			printf("Error to get wlan(%s)\n", WLANIF[idx]);
			goto out;
		}
		
		wrq.u.data.pointer = NULL;
		wrq.u.data.length = 0;
		
		if(iw_get_ext(skfd,(char*) WLANIF[idx], SIOCSSREQ, &wrq) >= 0){
			ret = 1;
		}
		else{
			printf("Error to start channel scanning on wlan(%s)\n", WLANIF[idx]);
		}
	}
out:
	//printf(">> %s: ret = %d\n", __FUNCTION__, ret);
	return ret;
}


/***
get_wlan_channel_score
return:
	0 => error,
	1 => success,
***/
int get_wlan_channel_score(int idx, wlan_channel_info **chInfo, int *count)
{
	int ret = 0;
	int skfd,i,len,chCount = 0, channel, score;
	struct iwreq wrq;
	char buf[256] = {0}, *s1, *s2, *tmp_s;
	
	if(chInfo == NULL || count == NULL)
	{
		printf("%s: Error output argument\n", __FUNCTION__);
	}
	else if(idx >= 0 && idx < (sizeof(WLANIF)/sizeof(char*)))
	{
		//printf("%s: %s, idx = %d\n", __FUNCTION__, WLANIF[idx], idx);
		if(get_wlan_channel_scan_status(idx) == 2)
		{
			memset(&wrq, 0, sizeof(struct iwreq));
			skfd = socket(AF_INET, SOCK_DGRAM, 0);
			
			if ( iw_get_ext(skfd, WLANIF[idx], SIOCGIWNAME, &wrq) < 0)
			{
				close( skfd );
			  /* If no wireless name : no wireless extensions */
				printf("Error to get wlan(%s)\n", WLANIF[idx]);
				goto out;
			}
			
			wrq.u.data.pointer = (caddr_t)buf;
			wrq.u.data.length = 256;
			
			if(iw_get_ext(skfd, WLANIF[idx], SIOCGIWRTLSSSCORE, &wrq) >= 0)
			{
				len = strlen(buf);
				for(i = 0;i<len;i++)
					if(buf[i] == ':')
						chCount++;
				if(chCount){
					*chInfo = malloc(chCount*sizeof(wlan_channel_info));
					s1 = buf;
					i = 0;
					while((s2 = strtok_r(s1, " ", &tmp_s)) && i < chCount)
					{
						if(sscanf(s2, "ch%d:%d", &channel, &score) == 2){
							((*chInfo)+i)->channel = channel;
							((*chInfo)+i)->score = 100 - score;
							i++;
						}
						s1 = tmp_s;
					}
					if(i != 0){
						*count = i;
						ret = 1;
					}
					else{
						free(*chInfo);
						*chInfo = NULL;
						*count = 0;
					}
				}
			}
			else{
				printf("Error to get wlan(%s) channel scan score\n", WLANIF[idx]);
			}
			close( skfd );
		}
	}
out:
	//printf(">> %s: ret = %d\n", __FUNCTION__, ret);
	return ret;
}

/***
start_wlan_channel_scan
return:
	0 => error,
	1 => success,
***/
int switch_wlan_channel(int idx)
{
	int ret = 0;
	unsigned char vChar = 0;
	int skfd;
	struct iwreq wrq;
	
	if(idx >= 0 && idx < (sizeof(WLANIF)/sizeof(char*)))
	{
		if(idx == 0) mib_get(MIB_WLAN_AUTO_CHAN_ENABLED, &vChar);
		else mib_get(MIB_WLAN1_AUTO_CHAN_ENABLED, &vChar);
		
		if(vChar){
			memset(&wrq, 0, sizeof(struct iwreq));
			skfd = socket(AF_INET, SOCK_DGRAM, 0);
			
			if ( iw_get_ext(skfd, WLANIF[idx], SIOCGIWNAME, &wrq) < 0)
			{
				close( skfd );
			  /* If no wireless name : no wireless extensions */
				printf("Error to get wlan(%s)\n", WLANIF[idx]);
				goto out;
			}
			
			wrq.u.data.pointer = NULL;
			wrq.u.data.length = 0;
			
			if(iw_get_ext(skfd, WLANIF[idx], SIOC92DAUTOCH, &wrq) >= 0){
				ret = 1;
			}
			else{
				printf("Error to start channel scanning on wlan(%s)\n", WLANIF[idx]);
			}
		}
		else{
			printf("%s: %s no enable auto channel function !!!\n ", __FUNCTION__, WLANIF[idx]);
		}
	}
out:
	//printf(">> %s: ret = %d\n", __FUNCTION__, ret);
	return ret;
}
#ifdef WLAN_ROAMING
int doWlStartAPRSSIQueryRequest(char *ifname, unsigned char * macaddr,
                                    dot11k_beacon_measurement_req* beacon_req)
{
    int sock;
    struct iwreq wrq;
	int ret = -1;
    int err;
    int len = 0;
	unsigned char buf[MAC_ADDR_LEN+sizeof(dot11k_beacon_measurement_req)]={0};

    /*** Inizializzazione socket ***/
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        err = errno;
        printf("[%s %d]: Can't create socket for ioctl. %s(%d)", __FUNCTION__, __LINE__, ifname, err);
        goto out;
    }
    memcpy(buf, macaddr, MAC_ADDR_LEN);
    len += MAC_ADDR_LEN;
    memcpy(buf + len, beacon_req, sizeof(dot11k_beacon_measurement_req));
    len += sizeof(dot11k_beacon_measurement_req);

    /*** Inizializzazione struttura iwreq ***/
    memset(&wrq, 0, sizeof(wrq));
    strncpy(wrq.ifr_name, ifname, IFNAMSIZ);

    /*** give parameter and buffer ***/
    wrq.u.data.pointer = (caddr_t)buf;
    wrq.u.data.length = len;

    /*** ioctl ***/
    if(ioctl(sock, SIOC11KBEACONREQ, &wrq) < 0)
    {
        err = errno;
        printf("[%s %d]: %s ioctl Error.(%d)", __FUNCTION__, __LINE__, ifname, err);
        goto out;
    }
    ret = 0;

out:
    close(sock);
    return ret;
}

int getWlStartAPRSSIQueryResult(char *ifname, unsigned char *macaddr,
        unsigned char* measure_result, int *bss_num,
        dot11k_beacon_measurement_report *beacon_report)
{
    int sock;
    struct iwreq wrq;
    int ret = -1;
    int err;
	unsigned char buf[1+1+sizeof(dot11k_beacon_measurement_report)*MAX_BEACON_REPORT]={0};


    /*** Inizializzazione socket ***/
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        err = errno;
        printf("[%s %d]: Can't create socket for ioctl. %s(%d)", __FUNCTION__, __LINE__, ifname, err);
        goto out;
    }

    /*** Inizializzazione struttura iwreq ***/
    memset(&wrq, 0, sizeof(wrq));
    strncpy(wrq.ifr_name, ifname, IFNAMSIZ);

    memcpy(buf, macaddr, MAC_ADDR_LEN);
    /*** give parameter and buffer ***/
    wrq.u.data.pointer = (caddr_t)buf;
    wrq.u.data.length = MAC_ADDR_LEN;

    /*** ioctl ***/
    if(ioctl(sock, SIOC11KBEACONREP, &wrq) < 0)
    {
        err = errno;
        printf("[%s %d]: ioctl Error.%s(%d)", __FUNCTION__, __LINE__, ifname, err);
        goto out;
    }

    ret = 0;
    *measure_result = *(unsigned char *)wrq.u.data.pointer;
    if(*measure_result == MEASUREMENT_SUCCEED)
    {
        *bss_num = *((unsigned char *)wrq.u.data.pointer + 1);
        if(*bss_num)
        {
			memcpy(beacon_report, (unsigned char *)wrq.u.data.pointer + 2, wrq.u.data.length - 2);
        }
    }
out:
    close(sock);
    return ret;

}
int getWlStartSTABSSTransitionRequest(char *interface, unsigned char *mac_sta, unsigned int channel, unsigned char *bssid)
{
    int skfd;
    struct iwreq wrq;
	int ret=0;
	unsigned char buf[MAC_ADDR_LEN+1+MAC_ADDR_LEN]={0};
	unsigned char chan = channel;

	memcpy(buf, mac_sta, MAC_ADDR_LEN);
	memcpy(buf+MAC_ADDR_LEN, &chan, 1);
	memcpy(buf+MAC_ADDR_LEN+1, bssid, MAC_ADDR_LEN);

    skfd = socket(AF_INET, SOCK_DGRAM, 0);

    /* Get wireless name */
    if ( iw_get_ext(skfd, interface, SIOCGIWNAME, &wrq) < 0) {
      close( skfd );
      /* If no wireless name : no wireless extensions */
      return -1;
    }

    wrq.u.data.pointer = (caddr_t)buf;
    wrq.u.data.length = sizeof(buf);

    if (iw_get_ext(skfd, interface, SIOCGIROAMINGBSSTRANSREQ, &wrq) < 0) {
      close( skfd );
      return -1;
    }
    close( skfd );

	//printf("%s %d ret %d\n",__func__, __LINE__ ,buf[0]);
	//if(buf[0]==0)
	//	return -1;
    return 0;
}
int doWlSTARSSIQueryRequest(char *interface, unsigned int channel)
{
    int skfd;
    struct iwreq wrq;
	unsigned char chan=channel;

    skfd = socket(AF_INET, SOCK_DGRAM, 0);

    /* Get wireless name */
    if ( iw_get_ext(skfd, interface, SIOCGIWNAME, &wrq) < 0) {
      close( skfd );
      /* If no wireless name : no wireless extensions */
      return -1;
    }

    wrq.u.data.pointer = (caddr_t)&chan;
    wrq.u.data.length = sizeof(unsigned char);

    if (iw_get_ext(skfd, interface, RTK_IOCTL_START_SPECCHPROBE, &wrq) < 0) {
      close( skfd );
      return -1;
    }
#if 0
	if (iw_get_ext(skfd, interface, RTK_IOCTL_STARTPROBE, &wrq) < 0) {
      close( skfd );
      return -1;
    }
#endif
    close( skfd );

    return 0;
}
int getWlSTARSSIQueryResult(char *interface, void *sta_mac_rssi_info)
{
    int skfd;
	//sta_mac_rssi sta_query_info[MAX_PROBE_REQ_STA];
    struct iwreq wrq;

    skfd = socket(AF_INET, SOCK_DGRAM, 0);

    /* Get wireless name */
    if ( iw_get_ext(skfd, interface, SIOCGIWNAME, &wrq) < 0) {
      close( skfd );
      /* If no wireless name : no wireless extensions */
      return -1;
    }

    wrq.u.data.pointer = (caddr_t)sta_mac_rssi_info;
    wrq.u.data.length = sizeof(sta_mac_rssi)*MAX_PROBE_REQ_STA;

    if (iw_get_ext(skfd, interface, RTK_IOCTL_PROBEINFO, &wrq) < 0) {
      close( skfd );
      return -1;
    }

    close( skfd );

    return 0;
}
int stopWlSTARSSIQueryRequest(char *interface)
{
    int skfd;
    struct iwreq wrq;

    skfd = socket(AF_INET, SOCK_DGRAM, 0);

    /* Get wireless name */
    if ( iw_get_ext(skfd, interface, SIOCGIWNAME, &wrq) < 0) {
      close( skfd );
      /* If no wireless name : no wireless extensions */
      return -1;
    }

    //wrq.u.data.pointer = (caddr_t)sta_mac_info;
    //wrq.u.data.length = sizeof(sta_mac_rssi)*MAX_PROBE_REQ_STA;

    if (iw_get_ext(skfd, interface, RTK_IOCTL_STOPPROBE, &wrq) < 0) {
      close( skfd );
      return -1;
    }
#if 0
	if (iw_get_ext(skfd, interface, RTK_IOCTL_STARTPROBE, &wrq) < 0) {
      close( skfd );
      return -1;
    }
#endif
    close( skfd );

    return 0;
}
#endif

