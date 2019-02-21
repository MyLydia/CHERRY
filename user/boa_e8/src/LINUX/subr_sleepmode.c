/*
 *      Web server handler routines for LED Control and Timer
 *
 */

/*-- System inlcude files --*/
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/time.h>
/*-- Local inlcude files --*/
#include "mib.h"
#include "utility.h"

#if defined(CONFIG_RTK_L34_ENABLE)
#include <rtk_rg_liteRomeDriver.h>
#else
#include "rtk/ponmac.h"
#include "rtk/gpon.h"
#include "rtk/epon.h"
#include "hal/chipdef/chip.h"
#endif


extern int wlan_idx;
#if !defined(CONFIG_RTK_L34_ENABLE)
#define WRITE_MEM32(addr, val)   (*(volatile unsigned int *)   (addr)) = (val)
#define READ_MEM32(addr)         (*(volatile unsigned int *)   (addr))
#endif
/**
 * config_powersave - enable or diasble rg to powersave mode
 * @enable: enable the powersave mode or not. 0 - disable; 1 - enable
 *
 * Set rg to powersave mode or wake up it
 * enable == 1: enable powersave mode, disable Wifi/Storage/LAN/LED
 * enable == 0: disable powersave mode, enable Wifi/Storage/LAN/LED
 */
void config_sleepmode(int enable)
{
	unsigned char vChar;
	unsigned char wlanDisabled = enable;
	MIB_CE_MBSSIB_T Entry;
	int i, j;
	unsigned int value;
#if defined(CONFIG_RTL_92D_SUPPORT) || defined(WLAN_DUALBAND_CONCURRENT)
	int orig_idx = wlan_idx;
#endif
	unsigned int cid, crev, csub;
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
			printf("aaaa cid :%x , crev:%x , csub:%x \n" , cid,crev,csub);
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

		//Storage, Disable IP for USB
		system("echo 0 > /sys/bus/usb/devices/usb1/authorized");
		//WiFi
		for(i=0; i<NUM_WLAN_INTERFACE; i++)
		{
			wlan_idx = i;
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
		//Storage, Enable IP for USB
		system("echo 1 > /sys/bus/usb/devices/usb1/authorized");
		//WiFi
		for(i=0; i<NUM_WLAN_INTERFACE; i++)
		{
			wlan_idx = i;
			config_WLAN(ACT_START, CONFIG_SSID_ALL);
		}
	}

#if defined(CONFIG_RTL_92D_SUPPORT) || defined(WLAN_DUALBAND_CONCURRENT)
	wlan_idx = orig_idx;
#endif

}


/**
 * setPSModeSchedRule - set new config rule to powersave mode schedule
 * @action: 0 - add rule, 1 - delete rule
 * @weekday: bit array of weekday, bit 0: active right now, bit 1:Monday; bit 2:Tuesday; ...
 * @startHour: schedule hour
 * @startMin: schedule min
 * @active: 0 - leave sleep mode, 1 - enter sleep mode
 * @enable: whether the rule enable or not
 *
 * Interface for DBus(SET_SLEEP_STATUS)
 * Clear old rules and set new rules
 * Returns    0    -   success; 
 *               -1   -   Rule num beyond the limit 
 *               -2   -   Chain add fail
 */
int setSleepModeSchedRule(unsigned char action, unsigned char weekday, unsigned char startHour, 
	unsigned char startMin, unsigned char active, unsigned char enable)
{
	int i, total;
	MIB_CE_RG_SLEEPMODE_SCHED_T rule;
	int ret;

	total = mib_chain_total(MIB_SLEEP_MODE_SCHED_TBL);
	if((100 == total)&&(0 == action))
	{
		//Table full, can not add yet.
		return -1;
	}

	if(0 == action)
	{
		//add new rules
		memset(&rule, 0, sizeof(rule));
		rule.enable = enable;
		rule.onoff = active;
		rule.hour = startHour;
		rule.minute = startMin;
		rule.day = weekday;

		if(!mib_chain_add(MIB_SLEEP_MODE_SCHED_TBL, (void *)(&rule)))
		{
			//Chain Add Error
			return -2;
		}
	}
	else
	{
		//delete rule
		for(i = 0; i < total; i++)
		{
			memset(&rule, 0, sizeof(rule));
			mib_chain_get(MIB_SLEEP_MODE_SCHED_TBL, i, &rule);
			if((rule.onoff==active)
				&&(rule.hour==startHour)
				&&(rule.minute==startMin)
				&&(rule.day==weekday))
			{
				//exist
				mib_chain_delete(MIB_SLEEP_MODE_SCHED_TBL, i);
				break;
			}
		}
	}

#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif

	updateScheduleCrondFile("/var/spool/cron/crontabs", 0);
	return 0;
}


/**
 * getPSModeSchedRule - get config rule of powersave mode schedule
 * @rule: base addr of point of powersave entry array.
 * @count: the length of array
 *
 * Interface for DBus(GET_SLEEP_STATUS)
 * Get current rules
 * Returns    0    -   success; 
 *               -1   -   patameter is NULL pointer 
 *               -2   -   Chain Get fail
 */
int getSleepModeSchedRule(MIB_CE_RG_SLEEPMODE_SCHED_T** pPEntry, int* count)
{
	int i, totalEntry;
	MIB_CE_RG_SLEEPMODE_SCHED_T* pSleepModeEntry;

	if((pPEntry == NULL) || (count == NULL))
	{
		//Null pointer.
		return -1;
	}
	
	totalEntry = mib_chain_total(MIB_SLEEP_MODE_SCHED_TBL);
	*count = totalEntry;
	pSleepModeEntry = (MIB_CE_RG_SLEEPMODE_SCHED_T*) malloc(sizeof(MIB_CE_RG_SLEEPMODE_SCHED_T)*totalEntry);
	for(i = 0; i < totalEntry; i++)
	{
		memset(pSleepModeEntry+i, 0, sizeof(MIB_CE_RG_SLEEPMODE_SCHED_T));
		if(!mib_chain_get(MIB_SLEEP_MODE_SCHED_TBL, i, (void *)(pSleepModeEntry+i)))
		{
			//Chain Get Error
			free(pSleepModeEntry);
			return -2;
		}
	}
	*pPEntry = pSleepModeEntry;
	return 0;
}
