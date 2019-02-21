/*
 *      Web server handler routines for wireless status
 *
 */

#include <string.h>
#include "../webs.h"
#include "webform.h"
#include "mib.h"
#include "utility.h"
#include "debug.h"
#include <linux/wireless.h>
#include "fmdefs.h"
#include <sys/ioctl.h>

static void getEncryption(MIB_CE_MBSSIB_T *Entry, char *buffer)
{
	switch (Entry->encrypt) {
		case WIFI_SEC_WEP:
			if (Entry->wep == WEP_DISABLED)
				strcpy(buffer, "Disabled");
			else if (Entry->wep == WEP64 )
				strcpy(buffer, "WEP 64bits");
			else if (Entry->wep == WEP128)
				strcpy(buffer, "WEP 128bits");
			else
				buffer[0] = '\0';
			break;
		case WIFI_SEC_NONE:
		case WIFI_SEC_WPA:
			strcpy(buffer, wlan_encrypt[Entry->encrypt]);
			break;
		case WIFI_SEC_WPA2:
			strcpy(buffer, wlan_encrypt[3]);
			break;
		case WIFI_SEC_WPA2_MIXED:
			strcpy(buffer, wlan_encrypt[4]);
			break;
#ifdef CONFIG_RTL_WAPI_SUPPORT
		case WIFI_SEC_WAPI:
			strcpy(buffer, wlan_encrypt[5]);
			break;
#endif
		default:
			strcpy(buffer, wlan_encrypt[0]);
	}
}

static void getTranSSID(char *buff, char *ssid)
{
	memset(buff, '\0', 200);
	memcpy(buff, ssid, MAX_SSID_LEN);
	translate_control_code(buff);
}

#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
const char *wl_auth_type[] = {"OPENSYSTEM", "SHAREDKEY", "BOTH"};
const char *wl_wep_keylen[] = {"", "WEP-64bits", "WEP-128bits"};

int wlStatus_parm(int eid, request * wp, int argc, char **argv)
{
	int i,j, intf_num = 0;
#ifdef WLAN_DUALBAND_CONCURRENT
	int orig_wlan_idx;
#endif
	unsigned char translate_ssid[200];
	unsigned char buffer[64];
	bss_info bss;
	MIB_CE_MBSSIB_T Entry;
	unsigned int channel;
	int nBytesSent = 0;
	unsigned char wlan_module_disabled=0, phyBandSelect=0;
	unsigned char cipher=0;
	unsigned char auto_channel=0;
	//_TRACE_CALL;

//	if (!wlan_is_up()) {
//		return -1;
//	}
	mib_get(MIB_WIFI_MODULE_DISABLED, (void *)&wlan_module_disabled);
	if(wlan_module_disabled==1)
		return -1;
	
#ifdef WLAN_DUALBAND_CONCURRENT
	orig_wlan_idx = wlan_idx;
#endif

	//process each wlan interface
	for (i = 0; i < NUM_WLAN_INTERFACE; i++) {
		wlan_idx = i;
		
		for (j = 0; j < WLAN_SSID_NUM; j++) {
			if(j==0){
				sprintf(buffer,"%s", getWlanIfName());
				mib_get(MIB_WLAN_AUTO_CHAN_ENABLED, (void *)&auto_channel);
				if(auto_channel)
					waitWlChannelSelect(buffer);
				if(getWlChannel(buffer, &channel)==0)
					nBytesSent += boaWrite(wp, "wlDefChannel[%d]=%d;\n", i, channel);
				else
					nBytesSent += boaWrite(wp, "wlDefChannel[%d]='N/A';\n", i);

#ifdef WLAN_DUALBAND_CONCURRENT
				mib_get(MIB_WLAN_PHY_BAND_SELECT, &phyBandSelect);
				boaWrite(wp, "Band2G5GSupport[%d]=%d;\n", i, phyBandSelect);
#endif
			}
			else
				sprintf(buffer, "%s-vap%d", getWlanIfName(), j-1);

			mib_chain_get(MIB_MBSSIB_TBL, j, (void *)&Entry);
			
			if (!Entry.wlanDisabled && getInFlags(buffer, 0)) {

				if (getWlBssInfo(buffer, &bss) < 0) {
					continue;
				}
				getTranSSID(translate_ssid, Entry.ssid);
				
				if(Entry.encrypt == WIFI_SEC_NONE){
					nBytesSent += boaWrite(wp, "wlan_parm.push(new it_nr(\"%d\""
						_PTS _PTI _PTI _PTI _PTI
						", new it(\"%s\", \"%02x:%02x:%02x:%02x:%02x:%02x\")"
						_PTI _PTS _PTS "));\n",
						intf_num, "ssid", translate_ssid,
						"ssid_idx", i*4+j+1,
						"hiddenssid", Entry.hidessid,
						"band", Entry.wlanBand,
						"disabled", Entry.wlanDisabled,
						"bssid", 
						bss.bssid[0], bss.bssid[1],
						bss.bssid[2], bss.bssid[3],
						bss.bssid[4], bss.bssid[5],
						"encrypt_state", Entry.encrypt == 0 ? 0:1,
						"auth_mode", "OPENSYSTEM",
						"encrypt_mode", "NONE");
				}
				else if(Entry.encrypt == WIFI_SEC_WEP){			
					nBytesSent += boaWrite(wp, "wlan_parm.push(new it_nr(\"%d\""
						_PTS _PTI _PTI _PTI _PTI 
						", new it(\"%s\", \"%02x:%02x:%02x:%02x:%02x:%02x\")" 
						_PTI _PTS _PTS "));\n",
						intf_num, "ssid", translate_ssid,
						"ssid_idx", i*4+j+1,
						"hiddenssid", Entry.hidessid,
						"band", Entry.wlanBand,
						"disabled", Entry.wlanDisabled,
						"bssid", 
						bss.bssid[0], bss.bssid[1],
						bss.bssid[2], bss.bssid[3],
						bss.bssid[4], bss.bssid[5],
						"encrypt_state", Entry.encrypt == 0 ? 0:1,
						"auth_mode", wl_auth_type[Entry.authType],
						"encrypt_mode", wl_wep_keylen[Entry.wep]);
				}
				else{
					if(Entry.encrypt == WIFI_SEC_WPA)
						cipher = Entry.unicastCipher;
					else if(Entry.encrypt == WIFI_SEC_WPA2)
						cipher = Entry.wpa2UnicastCipher;
					else
						cipher = (Entry.unicastCipher | Entry.wpa2UnicastCipher);
					nBytesSent += boaWrite(wp, "wlan_parm.push(new it_nr(\"%d\""
						_PTS _PTI _PTI _PTI _PTI 
						", new it(\"%s\", \"%02x:%02x:%02x:%02x:%02x:%02x\")" 
						_PTI _PTS _PTS "));\n",
						intf_num, "ssid", translate_ssid,
						"ssid_idx", i*4+j+1,
						"hiddenssid", Entry.hidessid,
						"band", Entry.wlanBand,
						"disabled", Entry.wlanDisabled,
						"bssid", 
						bss.bssid[0], bss.bssid[1],
						bss.bssid[2], bss.bssid[3],
						bss.bssid[4], bss.bssid[5],
						"encrypt_state", Entry.encrypt == 0 ? 0:1,
						"auth_mode", Entry.encrypt == WIFI_SEC_WPA2_MIXED ? "WPA-PSK/WPA2-PSK": 
						(Entry.encrypt == WIFI_SEC_WPA ? "WPA-PSK": "WPA2-PSK"),
						"encrypt_mode", cipher == WPA_CIPHER_MIXED? "TKIP+AES":
						(cipher == WPA_CIPHER_AES? "AES":"TKIP"));
				}

				intf_num++;
			}
		}
	}
#ifdef WLAN_DUALBAND_CONCURRENT
	wlan_idx = orig_wlan_idx;
#endif
check_err:
	//_TRACE_LEAVEL;
	return 0;
}

int wlStatus_parm_get(int eid, request * wp, int argc, char **argv, int band)
{
	int i,j, intf_num = 0;
#ifdef WLAN_DUALBAND_CONCURRENT
	int orig_wlan_idx;
#endif
	unsigned char translate_ssid[200];
	unsigned char buffer[64];
	bss_info bss;
	MIB_CE_MBSSIB_T Entry;
	unsigned int channel;
	int nBytesSent = 0;
	unsigned char wlan_module_disabled=0, phyBandSelect=0;
	unsigned char cipher=0;
	//_TRACE_CALL;

//	if (!wlan_is_up()) {
//		return -1;
//	}
	mib_get(MIB_WIFI_MODULE_DISABLED, (void *)&wlan_module_disabled);
	if(wlan_module_disabled==1)
		return -1;
	
#ifdef WLAN_DUALBAND_CONCURRENT
	orig_wlan_idx = wlan_idx;
#endif

	//process 2.4 wlan interface
		i=band;
		wlan_idx = band;
		
		for (j = 0; j < WLAN_SSID_NUM; j++) {
			if(j==0){
				sprintf(buffer,"%s", getWlanIfName());
				
				if(getWlChannel(buffer, &channel)==0)
					nBytesSent += boaWrite(wp, "wlDefChannel[%d]=%d;\n", 0, channel);
				else
					nBytesSent += boaWrite(wp, "wlDefChannel[%d]='N/A';\n", 0);

#ifdef WLAN_DUALBAND_CONCURRENT
				mib_get(MIB_WLAN_PHY_BAND_SELECT, &phyBandSelect);
				boaWrite(wp, "Band2G5GSupport[%d]=%d;\n", 0, phyBandSelect);
#endif
			}
			else
				sprintf(buffer, "%s-vap%d", getWlanIfName(), j-1);

			mib_chain_get(MIB_MBSSIB_TBL, j, (void *)&Entry);
			
			if (!Entry.wlanDisabled && getInFlags(buffer, 0)) {

				if (getWlBssInfo(buffer, &bss) < 0) {
					continue;
				}
				getTranSSID(translate_ssid, Entry.ssid);
				
				if(Entry.encrypt == WIFI_SEC_NONE){
					nBytesSent += boaWrite(wp, "wlan_parm.push(new it_nr(\"%d\""
						_PTS _PTI _PTI _PTI _PTI
						", new it(\"%s\", \"%02x:%02x:%02x:%02x:%02x:%02x\")"
						_PTI _PTS _PTS "));\n",
						intf_num, "ssid", translate_ssid,
						"ssid_idx", i*4+j+1,
						"hiddenssid", Entry.hidessid,
						"band", Entry.wlanBand,
						"disabled", Entry.wlanDisabled,
						"bssid", 
						bss.bssid[0], bss.bssid[1],
						bss.bssid[2], bss.bssid[3],
						bss.bssid[4], bss.bssid[5],
						"encrypt_state", Entry.encrypt == 0 ? 0:1,
						"auth_mode", "OPENSYSTEM",
						"encrypt_mode", "NONE");
				}
				else if(Entry.encrypt == WIFI_SEC_WEP){			
					nBytesSent += boaWrite(wp, "wlan_parm.push(new it_nr(\"%d\""
						_PTS _PTI _PTI _PTI _PTI 
						", new it(\"%s\", \"%02x:%02x:%02x:%02x:%02x:%02x\")" 
						_PTI _PTS _PTS "));\n",
						intf_num, "ssid", translate_ssid,
						"ssid_idx", i*4+j+1,
						"hiddenssid", Entry.hidessid,
						"band", Entry.wlanBand,
						"disabled", Entry.wlanDisabled,
						"bssid", 
						bss.bssid[0], bss.bssid[1],
						bss.bssid[2], bss.bssid[3],
						bss.bssid[4], bss.bssid[5],
						"encrypt_state", Entry.encrypt == 0 ? 0:1,
						"auth_mode", wl_auth_type[Entry.authType],
						"encrypt_mode", wl_wep_keylen[Entry.wep]);
				}
				else{
					if(Entry.encrypt == WIFI_SEC_WPA)
						cipher = Entry.unicastCipher;
					else if(Entry.encrypt == WIFI_SEC_WPA2)
						cipher = Entry.wpa2UnicastCipher;
					else
						cipher = (Entry.unicastCipher | Entry.wpa2UnicastCipher);
					nBytesSent += boaWrite(wp, "wlan_parm.push(new it_nr(\"%d\""
						_PTS _PTI _PTI _PTI _PTI 
						", new it(\"%s\", \"%02x:%02x:%02x:%02x:%02x:%02x\")" 
						_PTI _PTS _PTS "));\n",
						intf_num, "ssid", translate_ssid,
						"ssid_idx", i*4+j+1,
						"hiddenssid", Entry.hidessid,
						"band", Entry.wlanBand,
						"disabled", Entry.wlanDisabled,
						"bssid", 
						bss.bssid[0], bss.bssid[1],
						bss.bssid[2], bss.bssid[3],
						bss.bssid[4], bss.bssid[5],
						"encrypt_state", Entry.encrypt == 0 ? 0:1,
						"auth_mode", Entry.encrypt == WIFI_SEC_WPA2_MIXED ? "WPA-PSK/WPA2-PSK": 
						(Entry.encrypt == WIFI_SEC_WPA ? "WPA-PSK": "WPA2-PSK"),
						"encrypt_mode", cipher == WPA_CIPHER_MIXED? "TKIP+AES":
						(cipher == WPA_CIPHER_AES? "AES":"TKIP"));
				}

				intf_num++;
			}
		}
#ifdef WLAN_DUALBAND_CONCURRENT
	wlan_idx = orig_wlan_idx;
#endif
check_err:
	//_TRACE_LEAVEL;
	return 0;
}

int wlStatus_parm_24G(int eid, request * wp, int argc, char **argv)
{
	return wlStatus_parm_get(eid, wp, argc, argv, 0);
}

#ifdef WLAN_DUALBAND_CONCURRENT
int wlStatus_parm_5G(int eid, request * wp, int argc, char **argv)
{
	return wlStatus_parm_get(eid, wp, argc, argv, 1);
}
#endif //WLAN_DUALBAND_CONCURRENT
#else
int wlStatus_parm(int eid, request * wp, int argc, char **argv)
{
	bss_info bss;
	int nBytesSent = 0, i, k;
	int orig_wlan_idx;
	MIB_CE_MBSSIB_T Entry, Entry2;
	struct _misc_data_ misc_data;
	unsigned char buffer[64], buffer2[64], translate_ssid[200];
	unsigned char band, autort, hiddenSSID, wlan_disabled, phyBandSelect;
	unsigned int fixedTxRate;

	orig_wlan_idx = wlan_idx;

	for (i = 0; i < NUM_WLAN_INTERFACE; i++) {
		wlan_idx = i;

		wlan_getEntry(&Entry, 0);
		band = Entry.wlanBand;
		autort = Entry.rateAdaptiveEnabled;
		hiddenSSID = Entry.hidessid;
		wlan_disabled = Entry.wlanDisabled;
		fixedTxRate = Entry.fixedTxRate;
#if defined(CONFIG_RTL_92D_SUPPORT) || defined(WLAN0_5G_SUPPORT) || defined(WLAN1_5G_SUPPORT)
		mib_get(MIB_WLAN_PHY_BAND_SELECT, &phyBandSelect);
#else //CONFIG_RTL_92D_SUPPORT
		phyBandSelect = PHYBAND_2G;
#endif //CONFIG_RTL_92D_SUPPORT

		if (getWlBssInfo(getWlanIfName(), &bss) < 0) {
			wlan_idx = orig_wlan_idx;
			return -1;
		}
		getTranSSID(translate_ssid, bss.ssid);
		nBytesSent += boaWrite(wp,
				       "\tband[%d]=%d;\n\tssid_drv[%d]='%s';\n\twlanSsidAttr[%d]='%s';\n",
				       i, band, i, translate_ssid, i,
				       (hiddenSSID == 0) ? "Visual" : "Hidden");
		/* Encryption */
		getEncryption(&Entry, buffer);
		nBytesSent += boaWrite(wp, "\tencryptState[%d]='%s';\n",
				       i,
				       (Entry.encrypt ==
					0) ? INFO_DISABLED : INFO_ENABLED);

		nBytesSent += boaWrite(wp,
				       "\tchannel_drv[%d]='%d';\n",
				       i, bss.channel);
		nBytesSent += boaWrite(wp,
				       "\tbssid_drv[%d]='%02x:%02x:%02x:%02x:%02x:%02x';\n",
				       i, bss.bssid[0], bss.bssid[1],
				       bss.bssid[2], bss.bssid[3], bss.bssid[4],
				       bss.bssid[5]);

		nBytesSent += boaWrite(wp,
				       "\twlanDisabled[%d]=%d;\n",
				       i, wlan_disabled);

		nBytesSent += boaWrite(wp, "\tssid_alias[%d]='%s-%d';\n",
#ifdef YUEME_3_0_SPEC_SSID_ALIAS
								i, phyBandSelect==PHYBAND_2G? "2.4G":"5G", 1);
#else
								i, "SSID", 1 + i*WLAN_SSID_NUM);
#endif
#ifdef WLAN_RATE_PRIOR
		unsigned char vChar = 0;
		mib_get(MIB_WLAN_RATE_PRIOR, (void *)&vChar);
		nBytesSent += boaWrite(wp, "\twlan_rate_prior[%d]=%d;\n", i, vChar);
#else
		nBytesSent += boaWrite(wp, "\twlan_rate_prior[%d]=0;\n", i);
#endif
		struct iwreq wrq;
		int ret, idx;
#define RTL8185_IOCTL_GET_MIB	0x89f2
		idx = socket(AF_INET, SOCK_DGRAM, 0);
		strcpy(wrq.ifr_name, getWlanIfName());
		strcpy(buffer, "channel");
		wrq.u.data.pointer = (caddr_t) & buffer;
		wrq.u.data.length = 10;
		ret = ioctl(idx, RTL8185_IOCTL_GET_MIB, &wrq);
		close(idx);
		if (ret != -1)
			nBytesSent +=
			    boaWrite(wp, "\twlDefChannel[%d]=%d;\n", i,
				     buffer[wrq.u.data.length - 1]);
		else
			nBytesSent += boaWrite(wp, "\twlDefChannel[%d]='N/A'", i);

		nBytesSent += boaWrite(wp, "\ttxrate[%d]=%u;\n", i, fixedTxRate);

		nBytesSent += boaWrite(wp, "\tauto[%d]=%d;\n", i, autort);

		memset(&misc_data, 0, sizeof(struct _misc_data_));
		getMiscData(getWlanIfName(), &misc_data);
		nBytesSent += boaWrite(wp, "\trf_used[%d]=%u;\n", i, misc_data.mimo_tr_used);

		nBytesSent += boaWrite(wp,
				       "\tmssid_num=%d;\n", WLAN_MBSSID_NUM);
#ifdef WLAN_MBSSID
		/*-------------- VAP Interface ------------*/
		for (k = 0; k < WLAN_MBSSID_NUM; k++) {
			//wlan_idx = orig_wlan_idx;
			mib_chain_get(MIB_MBSSIB_TBL, WLAN_VAP_ITF_INDEX + k,
				      (void *)&Entry2);
			sprintf(buffer, "%s-vap%d", getWlanIfName(), k);
			if (getWlBssInfo(buffer, &bss) < 0)
				printf("getWlBssInfo failed\n");
			getTranSSID(translate_ssid, bss.ssid);
			nBytesSent += boaWrite(wp,
					       "\tmssid_ssid_drv[%d][%d]='%s';\n\tmssid_wlanSsidAttr[%d][%d]='%s';\n\tmssid_band[%d][%d]=%d;\n"
					       "\tmssid_disable[%d][%d]=%d;\n",
					       i, k, translate_ssid, i, k,
					       (Entry2.hidessid ==
						0) ? "Visual" : "Hidden", i, k,
					       Entry2.wlanBand, i, k,
					       Entry2.wlanDisabled);
			nBytesSent +=
			    boaWrite(wp,
				     "\tmssid_bssid_drv[%d][%d]='%02x:%02x:%02x:%02x:%02x:%02x';\n",
				     i, k, bss.bssid[0], bss.bssid[1],
				     bss.bssid[2], bss.bssid[3], bss.bssid[4],
				     bss.bssid[5]);
			/* VAP encryption */
			getEncryption(&Entry2, buffer2);
			nBytesSent +=
			    boaWrite(wp, "\tmssid_encryptState[%d][%d]='%s';\n",
				     i, k,
				     (Entry2.encrypt ==
				      0) ? INFO_DISABLED : INFO_ENABLED);
			nBytesSent += boaWrite(wp, "\tmssid_alias[%d][%d]='%s-%d';\n",
#ifdef YUEME_3_0_SPEC_SSID_ALIAS
						i, k, phyBandSelect==PHYBAND_2G? "2.4G":"5G", WLAN_VAP_ITF_INDEX + (k+1));
#else
						i, k, "SSID", WLAN_VAP_ITF_INDEX + (k+1) + i*WLAN_SSID_NUM);
#endif
		}
#endif
		nBytesSent +=
		    boaWrite(wp, "\tBand2G5GSupport[%d]=%d;\n", i, phyBandSelect);
	}
	wlan_idx = orig_wlan_idx;

	return nBytesSent;
}
#endif
