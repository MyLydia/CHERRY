#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <signal.h>
#include "utility.h"

#define SSID_INTERFACE_SHIFT_BIT 16

static void start_wifi(unsigned char start, unsigned int mask)
{
	unsigned char vChar;
	unsigned char wlanDisabled = start? 0:1;
	MIB_CE_MBSSIB_T Entry;
	int vcTotal, i, j;
	unsigned int need_config_root = 0;
	unsigned char phyband[2] = {0};
	//unsigned int wlan_dev_map=0;
	//unsigned int orig_ssid_enable_status, ssid_enable_status=0;
	//MIB_CE_ATM_VC_T vcEntry;
#if 0
#if defined(CONFIG_RTL_92D_SUPPORT) || defined(WLAN_DUALBAND_CONCURRENT)
	int orig_idx = wlan_idx;
#endif
	int i, j;
	for(i=0; i<NUM_WLAN_INTERFACE; i++){
		wlan_idx = i;
		mib_chain_get(MIB_MBSSIB_TBL, 0, (void *)&Entry);
		if(wlanDisabled != Entry.wlanDisabled){
			Entry.wlanDisabled = wlanDisabled;
			mib_chain_update(MIB_MBSSIB_TBL, (void *)&Entry, 0);
		}
		if(wlanDisabled==1){
			for(j=0; j<WLAN_MBSSID_NUM; j++){
				mib_chain_get(MIB_MBSSIB_TBL, j+1, (void *)&Entry);
				if(wlanDisabled != Entry.wlanDisabled){
					Entry.wlanDisabled = wlanDisabled;
					mib_chain_update(MIB_MBSSIB_TBL, (void *)&Entry, j+1);
				}
			}
		}

#ifdef CONFIG_WIFI_SIMPLE_CONFIG // WPS
		update_wps_configured(0);
#endif
	}
#if defined(CONFIG_RTL_92D_SUPPORT) || defined(WLAN_DUALBAND_CONCURRENT)
	wlan_idx = orig_idx;
#endif
#endif
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	mib_set(MIB_WIFI_MODULE_DISABLED, (void *)&wlanDisabled);
#else
//	mib_set(MIB_WIFI_MODULE_DISABLED, (void *)&wlanDisabled);
#if 0
	vcTotal = mib_chain_total(MIB_ATM_VC_TBL);

	for (i = 0; i < vcTotal; i++)
	{
		if (!mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&vcEntry))
				return -1;

		if(!(vcEntry.applicationtype & X_CT_SRV_INTERNET)){
			wlan_dev_map |= vcEntry.itfGroup;
		}
	}
#if defined(CONFIG_YUEME) && defined(CONFIG_LUNA_DUAL_LINUX)
	wlan_dev_map = (((wlan_dev_map & 0x3e00) >> 5) | ((wlan_dev_map & 0x1f0) << 5));
#endif
	//printf("wlan_dev_map = %u\n", wlan_dev_map);
#endif
	//mib_get(MIB_WIFI_SSID_ENABLE_STATUS, (void *)&orig_ssid_enable_status); ////0x10001, bit 0 ssid 2G-1, bit 16 ssid 5G-1
	
#if defined(CONFIG_RTL_92D_SUPPORT) || defined(WLAN_DUALBAND_CONCURRENT)
	int orig_idx = wlan_idx;
#endif

	for(i=0; i<NUM_WLAN_INTERFACE; i++){
		wlan_idx = i;

		mib_chain_get(MIB_MBSSIB_TBL, 0, (void *)&Entry);
#ifdef WLAN_DUALBAND_CONCURRENT
		mib_get(MIB_WLAN_PHY_BAND_SELECT, (void *)&phyband[i] );
#else
		phyband[i] = PHYBAND_2G;
#endif
		
		//if(wlanDisabled && !Entry.wlanDisabled)
		//	ssid_enable_status |= (1 << i*(SSID_INTERFACE_SHIFT_BIT));
			
		//if(!(wlan_dev_map & (1<<(PMAP_WLAN0 + i*5)))){
		if((mask & (1<<(i*SSID_INTERFACE_SHIFT_BIT)))){
			if(wlanDisabled != Entry.wlanDisabled){
				/*if((!wlanDisabled && (orig_ssid_enable_status &(1 << i*SSID_INTERFACE_SHIFT_BIT))) || wlanDisabled)*/
				{
					Entry.wlanDisabled = wlanDisabled;
					mib_chain_update(MIB_MBSSIB_TBL, (void *)&Entry, 0);
					need_config_root |= (1<<i);
				}
			}
		}
		
		for(j=0; j<WLAN_MBSSID_NUM; j++){
			
			mib_chain_get(MIB_MBSSIB_TBL, j+1, (void *)&Entry);

			//if(wlanDisabled && !Entry.wlanDisabled)
			//	ssid_enable_status |= (1 << ((j+1) + i*SSID_INTERFACE_SHIFT_BIT));
			
			//if(!(wlan_dev_map & (1<<(PMAP_WLAN0 + (j+1) + i*5)))){
			if((mask & (1<<(i*SSID_INTERFACE_SHIFT_BIT+(j+1))))){
				if(wlanDisabled != Entry.wlanDisabled){
					/*if((!wlanDisabled && (orig_ssid_enable_status &(1 << ((j+1)+ i*SSID_INTERFACE_SHIFT_BIT)))) || wlanDisabled)*/
					{
						Entry.wlanDisabled = wlanDisabled;
						mib_chain_update(MIB_MBSSIB_TBL, (void *)&Entry, j+1);
						if(!(need_config_root & (1<<i)))
							config_WLAN(phyband[i]==PHYBAND_2G? ACT_RESTART_2G: ACT_RESTART_5G, j+1);
					}
				}
			}
		}
	}
#if defined(CONFIG_RTL_92D_SUPPORT) || defined(WLAN_DUALBAND_CONCURRENT)
	wlan_idx = orig_idx;
#endif
#ifdef CONFIG_WIFI_SIMPLE_CONFIG // WPS
	//update_wps_configured(0);
#endif

	//if(wlanDisabled)
	//	mib_set(MIB_WIFI_SSID_ENABLE_STATUS, (void *)&ssid_enable_status);

#endif
#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif // of #if COMMIT_IMMEDIATELY

//	if(start==0)
//		config_WLAN(ACT_STOP, CONFIG_SSID_ALL);
//	else
//		config_WLAN(ACT_START, CONFIG_SSID_ALL);
#ifdef CONFIG_YUEME
#ifdef WLAN_DUALBAND_CONCURRENT
	if(need_config_root == 3)
		config_WLAN(ACT_RESTART, CONFIG_SSID_ALL);
	else if(need_config_root != 0){
		if(phyband[0]==PHYBAND_2G)
			config_WLAN(need_config_root==1 ? ACT_RESTART_2G:ACT_RESTART_5G, CONFIG_SSID_ALL);
		else
			config_WLAN(need_config_root==2 ? ACT_RESTART_2G:ACT_RESTART_5G, CONFIG_SSID_ALL);
	}
#else
	if(need_config_root)
		config_WLAN(ACT_RESTART, CONFIG_SSID_ALL);
#endif
#else
	config_WLAN(ACT_RESTART, CONFIG_SSID_ALL);
#endif

}

int main (int argc, char **argv)
{
	if(argc==3){
		if(!strcmp(argv[1],"0"))
			start_wifi(0, atoi(argv[2]));
		else
			start_wifi(1, atoi(argv[2]));
	}
	else{
		if(!strcmp(argv[1],"0"))
			//start_wifi(0, 0xffffffff);
			config_WLAN(ACT_STOP, CONFIG_SSID_ALL);
		else
			//start_wifi(1, 0xffffffff);
			config_WLAN(ACT_START, CONFIG_SSID_ALL);
	}
	return 0;
}


