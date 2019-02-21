#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <signal.h>
#include "utility.h"
#if defined(CONFIG_RTK_L34_ENABLE)
#include <rtk_rg_liteRomeDriver.h>
#else
#include "rtk/ponmac.h"
#include "rtk/gponv2.h"
#include "rtk/epon.h"
#include "hal/chipdef/chip.h"
#endif


//extern int wlan_idx;
#if !defined(CONFIG_RTK_L34_ENABLE)
#define WRITE_MEM32(addr, val)   (*(volatile unsigned int *)   (addr)) = (val)
#define READ_MEM32(addr)         (*(volatile unsigned int *)   (addr))
#endif

static void set_sleepmode(unsigned char enable)
{
	unsigned char vChar;
	unsigned char wlanDisabled = enable;
	//MIB_CE_MBSSIB_T Entry;
	int i;
	unsigned int cid, crev, csub;
#if defined(CONFIG_RTL_92D_SUPPORT) || defined(WLAN_DUALBAND_CONCURRENT)
	//int orig_idx = wlan_idx;
#endif

#if 0	
	for(i=0; i<NUM_WLAN_INTERFACE; i++)
	{
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
#endif
#ifdef YUEME_3_0_SPEC
	mib_local_mapping_set(MIB_WLAN_DISABLED, 0, (void *)&wlanDisabled);
#ifdef WLAN_DUALBAND_CONCURRENT
	mib_local_mapping_set(MIB_WLAN_DISABLED, 1, (void *)&wlanDisabled);
#endif
#else
	mib_set(MIB_WIFI_MODULE_DISABLED, (void *)&wlanDisabled);
#endif
	mib_set(MIB_RG_SLEEPMODE_ENABLE, (void *)&enable);

#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif

	if(enable==1)
	{
		//LED
		system("/bin/mpctl led off");
		//LAN
		#ifdef CONFIG_RTK_L34_ENABLE
		rtk_rg_switch_version_get(&cid, &crev, &csub);
		#else
		rtk_switch_version_get(&cid, &crev, &csub);
		#endif
		if(cid == RTL9607C_CHIP_ID)
		{
			switch (csub)
			{
				case 0x1://RTL9607C_CHIP_SUB_TYPE_RTL9603C_VA4:
				case 0x4://RTL9607C_CHIP_SUB_TYPE_RTL9603C_VA5:
				case 0x8://RTL9607C_CHIP_SUB_TYPE_RTL9603C_VA6:
					system("/bin/diag port set phy-force-power-down port 1-4 state enable");
					break;
				default:
					system("/bin/diag port set phy-force-power-down port 0-3 state enable");
					break;

			}
		}
		else
			system("/bin/diag port set phy-force-power-down port 0-3 state enable");

		//For Storage, Suspend the USB
		//system("echo 0 > /sys/bus/usb/devices/usb1/authorized");
		system("find /sys/bus/usb/devices/usb*/authorized -type f -exec sh -c 'echo 0 > {}' \\;");

		//WiFi
		//for(i=0; i<NUM_WLAN_INTERFACE; i++)
		{
			//wlan_idx = i;
			config_WLAN(ACT_STOP, CONFIG_SSID_ALL);
		}
	}
	else
	{
		//LED
		system("/bin/mpctl led restore");
		//LAN
		#ifdef CONFIG_RTK_L34_ENABLE
		rtk_rg_switch_version_get(&cid, &crev, &csub);
		#else
		rtk_switch_version_get(&cid, &crev, &csub);
		#endif
		if(cid == RTL9607C_CHIP_ID)
		{
			switch (csub)
			{
				case 0x1:
				case 0x4:
				case 0x8:
					system("/bin/diag port set phy-force-power-down port 1-4 state disable");
					break;
				default:
					system("/bin/diag port set phy-force-power-down port 0-3 state disable");
					break;
			}
		}
		else
			system("/bin/diag port set phy-force-power-down port 0-3 state disable");

		//For Storage, Resume the USB
		//system("echo 1 > /sys/bus/usb/devices/usb1/authorized");
		system("find /sys/bus/usb/devices/usb*/authorized -type f -exec sh -c 'echo 1 > {}' \\;");

		//WiFi
		//for(i=0; i<NUM_WLAN_INTERFACE; i++)
		{
			//wlan_idx = i;
			config_WLAN(ACT_START, CONFIG_SSID_ALL);
		}
	}

#if defined(CONFIG_RTL_92D_SUPPORT) || defined(WLAN_DUALBAND_CONCURRENT)
	//wlan_idx = orig_idx;
#endif

}


int main (int argc, char **argv)
{
	if(!strcmp(argv[1],"0")){
		set_sleepmode(0);
	}
	else{
		set_sleepmode(1);
	}
	return 0;
}


