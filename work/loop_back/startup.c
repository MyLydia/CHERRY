/* startup.c - kaohj */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/ioctl.h>
//#include <net/if.h>
#include <net/route.h>
#include <linux/atm.h>
#include <linux/atmdev.h>
#include <crypt.h>
#ifdef EMBED
#include <linux/config.h>
#else
#include "../../../../include/linux/autoconf.h"
#endif
#include "../defs.h"

#include "mibtbl.h"
#include "utility.h"
#ifdef WLAN_SUPPORT

#include <linux/wireless.h>

#if defined(CONFIG_E8B) || defined(CONFIG_00R0)
#ifdef USE_LIBMD5
#include <libmd5wrapper.h>
#else
#include "../md5.h"
#endif //USE_LIBMD5
#endif

#endif

#include "debug.h"
// Mason Yu
#include "syslog.h"

#if defined(CONFIG_RTK_L34_ENABLE)
#include <rtk_rg_liteRomeDriver.h>
#else
#if defined(CONFIG_GPON_FEATURE)
#include "rtk/gpon.h"
#endif
#if defined(CONFIG_EPON_FEATURE)
#include "rtk/epon.h"
#endif
#endif

int startLANAutoSearch(const char *ipAddr, const char *subnet);
int isDuplicate(struct in_addr *ipAddr, const char *device);

#ifdef CONFIG_DEV_xDSL
//--------------------------------------------------------
// xDSL startup
// return value:
// 0  : not start by configuration
// 1  : successful
// -1 : failed
int startDsl()
{
	unsigned char init_line;
	unsigned short dsl_mode;
	int adslmode;
	int ret;

#ifdef CONFIG_VDSL
	//enable/disable dsl log
	system("/bin/adslctrl debug 9");
#endif /*CONFIG_VDSL*/


	ret = 1;
	if (mib_get(MIB_INIT_LINE, (void *)&init_line) != 0) {
		if (init_line == 1) {
			// start adsl
		  #ifdef CONFIG_VDSL
			adslmode=0;
		  #else
			mib_get(MIB_ADSL_MODE, (void *)&dsl_mode);
			adslmode=(int)(dsl_mode & (ADSL_MODE_GLITE|ADSL_MODE_T1413|ADSL_MODE_GDMT));	// T1.413 & G.dmt
		  #endif /*CONFIG_VDSL*/
			adsl_drv_get(RLCM_PHY_START_MODEM, (void *)&adslmode, 4);
			ret = setupDsl();

		  #if defined(CONFIG_USER_XDSL_SLAVE)
			adsl_slv_drv_get(RLCM_PHY_START_MODEM, (void *)&adslmode, 4);
			ret = setupSlvDsl();
		  #endif

		}
		else
			ret = 0;
	}
	else
		ret = -1;
	return ret;
}
#endif


//--------------------------------------------------------
// Find the minimun WLAN-side link MRU
// It is used to set the LAN-side MTU(MRU) for the
// path-mtu problem.
// RETURN: 0: if failed
//	 : others: the minimum MRU for the WLAN link
static int get_min_wan_mru()
{
	int vcTotal, i, pmtu;
	MIB_CE_ATM_VC_T Entry;

	vcTotal = mib_chain_total(MIB_ATM_VC_TBL);
	pmtu = 1500;

	for (i = 0; i < vcTotal; i++)
	{
		/* get the specified chain record */
		if (!mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&Entry))
			return 0;

		if (Entry.enable == 0)
			continue;

		if (Entry.mtu < pmtu)
			pmtu = Entry.mtu;
	}

	return pmtu;
}

//--------------------------------------------------------
// Ethernet LAN startup
// return value:
// 1  : successful
// -1 : failed
#define ConfigWlanLock "/var/run/configWlanLock"
//#ifdef CONFIG_RTL867X_VLAN_MAPPING
#define ConfigPmapLock "/var/run/configPmapLock"
//#endif

#if defined(CONFIG_LUNA) && defined(CONFIG_RTK_L34_ENABLE)
#include "rtusr_rg_api.h"
#endif

int startELan()
{
	unsigned char value[6];
	int vInt;
	char macaddr[13];
	char ipaddr[16];
	char subnet[16];
	char timeOut[6];
	int status=0;
	int i;
#if defined(CONFIG_IPV6)
	char tmpBuf[64];
#endif
#ifdef WLAN_MBSSID
	char para2[20];
#endif
//#ifdef WLAN_SUPPORT
	FILE *f;
//#endif
#ifdef CONFIG_RTK_L34_ENABLE
	int portid;	
#endif
	char sysbuf[128];
#if defined(CONFIG_USER_LAN_PORT_AS_ETH_WAN)
	int ethPhyPortId = -1;
	mib_get(MIB_ETH_WAN_PORT_PHY_INDEX, &ethPhyPortId);
#endif
#ifdef CONFIG_USER_DHCPCLIENT_MODE
	unsigned char cur_vChar;
#endif

#ifdef CONFIG_RTL8672NIC
#ifdef WIFI_TEST
	//for wifi test
	mib_get(MIB_WLAN_BAND, (void *)value);
	if(value[0]==4 || value[0]==5){//wifi
		status|=va_cmd("/bin/ethctl",2,1,"wifi","1");
	}
	else
#endif
	{
#ifdef WLAN_SUPPORT
	// to support WIFI logo test mode.....
	mib_get(MIB_WIFI_SUPPORT, (void*)value);
	if(value[0]==1)
	{
		MIB_CE_MBSSIB_T mEntry;
		wlan_getEntry(&mEntry, 0);
		if(mEntry.wlanBand==2 || mEntry.wlanBand==3)
			status|=va_cmd("/bin/ethctl",2,1,"wifi","1");
		else
			status|=va_cmd("/bin/ethctl",2,1,"wifi","0");
	}
	else
		status|=va_cmd("/bin/ethctl",2,1,"wifi","0");
#endif
	}
#endif

	if (mib_get(MIB_ELAN_MAC_ADDR, (void *)value) != 0)
	{
#ifdef WLAN_SUPPORT
		if((f = fopen(ConfigWlanLock, "w")) == NULL)
			return;
		fclose(f);
#endif
		snprintf(macaddr, 13, "%02x%02x%02x%02x%02x%02x",
			value[0], value[1], value[2], value[3], value[4], value[5]);
		for(i=0;i<ELANVIF_NUM;i++){
			status|=va_cmd(IFCONFIG, 4, 1, ELANVIF[i], "hw", "ether", macaddr);
		}
#if defined(CONFIG_RTL8681_PTM)
		status|=va_cmd(IFCONFIG, 4, 1, PTMIF, "hw", "ether", macaddr);
#endif
#ifdef CONFIG_USB_ETH
		status|=va_cmd(IFCONFIG, 4, 1, USBETHIF, "hw", "ether", macaddr);
#endif //CONFIG_USB_ETH
#ifdef WLAN_SUPPORT
		status|=va_cmd(IFCONFIG, 4, 1, WLANIF[0], "hw", "ether", macaddr);

#ifdef WLAN_MBSSID
		// Set macaddr for VAP
		for (i=1; i<=WLAN_MBSSID_NUM; i++) {
			setup_mac_addr(value, 1);

			snprintf(macaddr, 13, "%02x%02x%02x%02x%02x%02x",
				value[0], value[1], value[2], value[3], value[4], value[5]);

			sprintf(para2, "wlan0-vap%d", i-1);

			status|=va_cmd(IFCONFIG, 4, 1, para2, "hw", "ether", macaddr);
		}
#endif
#if defined(CONFIG_RTL_92D_DMDP) || (defined(WLAN_DUALBAND_CONCURRENT) && !defined(CONFIG_LUNA_DUAL_LINUX) && !defined(WLAN1_QTN))
		setup_mac_addr(value, 1);
		snprintf(macaddr, 13, "%02x%02x%02x%02x%02x%02x",
			value[0], value[1], value[2], value[3], value[4], value[5]);
		status|=va_cmd(IFCONFIG, 4, 1, WLANIF[1], "hw", "ether", macaddr);

#ifdef WLAN_MBSSID
		// Set macaddr for VAP
		for (i=1; i<=WLAN_MBSSID_NUM; i++) {
			setup_mac_addr(value, 1);

			snprintf(macaddr, 13, "%02x%02x%02x%02x%02x%02x",
				value[0], value[1], value[2], value[3], value[4], value[5]);

			sprintf(para2, "wlan1-vap%d", i-1);

			status|=va_cmd(IFCONFIG, 4, 1, para2, "hw", "ether", macaddr);
		}
#endif
#endif //CONFIG_RTL_92D_DMDP
#endif // WLAN_SUPPORT
	}
//#ifdef CONFIG_RTL867X_VLAN_MAPPING
	if((f = fopen(ConfigPmapLock, "w")) == NULL)
		return -1;
	fclose(f);
//#endif
	// ifconfig eth0 up
	//va_cmd(IFCONFIG, 2, 1, "eth0", "up");

	// brctl addbr br0
	status|=va_cmd(BRCTL, 2, 1, "addbr", (char*)BRIF);

	// ifconfig br0 hw ether
	if (mib_get(MIB_ELAN_MAC_ADDR, (void *)value) != 0)
	{
		snprintf(macaddr, 13, "%02x%02x%02x%02x%02x%02x",
		value[0], value[1], value[2], value[3], value[4], value[5]);
		va_cmd(IFCONFIG, 4, 1, BRIF, "hw", "ether", macaddr);
	}

#if defined(WLAN_SUPPORT) && defined(CONFIG_LUNA) && defined(CONFIG_RTL_MULTI_LAN_DEV)
	va_cmd(IFCONFIG, 4, 1, ELANIF, "hw", "ether", macaddr);
#endif


#if !defined(CONFIG_LUNA) && !defined(CONFIG_DSL_VTUO)
	//setup WAN to WAN blocking
	system("/bin/echo 1 > /proc/br_wanblocking");
#endif

	if (mib_get(MIB_BRCTL_STP, (void *)value) != 0)
	{
		vInt = (int)(*(unsigned char *)value);
		if (vInt == 0)	// stp off
		{
			// brctl stp br0 off
			status|=va_cmd(BRCTL, 3, 1, "stp", (char *)BRIF, "off");

			// brctl setfd br0 1
			//if forwarding_delay=0, fdb_get may fail in serveral seconds after booting
			status|=va_cmd(BRCTL, 3, 1, "setfd", (char *)BRIF, "1");
		}
		else		// stp on
		{
			// brctl stp br0 on
			status|=va_cmd(BRCTL, 3, 1, "stp", (char *)BRIF, "on");
		}
	}

	// brctl setageing br0 ageingtime
	if (mib_get(MIB_BRCTL_AGEINGTIME, (void *)value) != 0)
	{
		vInt = (int)(*(unsigned short *)value);
		snprintf(timeOut, 6, "%u", vInt);
		status|=va_cmd(BRCTL, 3, 1, "setageing", (char *)BRIF, timeOut);
	}
	for(i=0;i<ELANVIF_NUM;i++){
#if defined(CONFIG_RTK_L34_ENABLE) && defined(CONFIG_USER_LAN_PORT_AS_ETH_WAN)
		portid = RG_get_lan_phyPortId(i);
		if (portid != -1 && portid == ethPhyPortId)
			continue;
#endif
		status|=va_cmd(BRCTL, 3, 1, "addif", (char *)BRIF, ELANVIF[i]);

#if defined(CONFIG_RTK_L34_ENABLE) && defined(CONFIG_RTL_MULTI_LAN_DEV)
		portid = RG_get_lan_phyPortId(i);
		if(portid != -1){
			sprintf(sysbuf, "/bin/echo %d %s > /proc/rtl8686gmac/dev_port_mapping", portid, ELANVIF[i]);
			printf("system(): %s\n", sysbuf);
			system(sysbuf);
		}
#endif

#ifdef CONFIG_RTK_DEV_AP
#else
// Mason Yu
#ifdef NAT_LOOPBACK
		// Use hairpin_mode with caution, ex. flooding traffic would be looped
		// forever between two connected device where they are both in hairpin_mode.
		#if 0
		sprintf(sysbuf, "/bin/echo 1 >  /sys/class/net/br0/brif/%s/hairpin_mode", ELANVIF[i]);
		printf("system(): %s\n", sysbuf);
		system(sysbuf);
		#endif
#endif
#endif

#ifdef CONFIG_IPV6
		// Disable ipv6 for bridge interface
		setup_disable_ipv6(ELANVIF[i], 1);
#endif
	}

#if defined(WLAN_SUPPORT) && defined(CONFIG_LUNA) && defined(CONFIG_RTL_MULTI_LAN_DEV)
		status|=va_cmd(BRCTL, 3, 1, "addif", (char *)BRIF, ELANIF);
#endif
#if defined(CONFIG_RTL8681_PTM)
	status|=va_cmd(BRCTL, 3, 1, "addif", (char *)BRIF, PTMIF);
#endif
#ifdef CONFIG_USB_ETH
	status|=va_cmd(BRCTL, 3, 1, "addif", (char *)BRIF, USBETHIF);
#ifdef CONFIG_IPV6
	// Disable ipv6 for bridge interface
	setup_disable_ipv6(USBETHIF, 1);
#endif
#endif //CONFIG_USB_ETH

	/* Mason Yu. 2011/04/12
	 * In order to wait if the ALL LAN bridge ports is ready or not. Set dad probes amount to 4 for br0.
	 */
    /*
     * 2012/8/15
     * Since the eth0.2~5 up timing is tuned to must more later, so 4 is not enough, the first 5 NS
     * could not be send out until eth0.2~5 are up.
     */

	/* 2015/8/7 4 is enough now, change for IPv6 ready log test*/

	unsigned char val[64];
	snprintf(val, 64, "/bin/echo 4 > /proc/sys/net/ipv6/conf/%s/dad_transmits", (char*)BRIF);
	system(val);

#if defined(CONFIG_LUNA) && defined(CONFIG_RTK_L34_ENABLE)
	{
//		status|=va_cmd(IFCONFIG, 3, 1, (char*)LANIF,"up", ipaddr);
#if defined(CONFIG_GPON_FEATURE)
		unsigned int pon_mode = 0;
		mib_get(MIB_PON_MODE, &pon_mode);
		if(pon_mode != GPON_MODE) //GPON_MODE run initRGapi before run omci
#endif
			Init_rg_api();
		Init_RG_ELan(TagCPort, BridgeWan);
		RTK_RG_gatewayService_add(); //must add if enable DMZ
	}
#endif
	
#ifdef CONFIG_USER_DHCPCLIENT_MODE
	mib_get(MIB_DHCP_MODE, (void *)&cur_vChar);

	/* OTHER : assign static LAN ip 
	** DHCP_LAN_CLIENT : dynamic get LAN ip, so postpone to "/bin/diag port set phy-force-power-down port all state disable"
	*/
	if(cur_vChar != DHCP_LAN_CLIENT){
#endif
	// ifconfig LANIF LAN_IP netmask LAN_SUBNET
	if (mib_get(MIB_ADSL_LAN_IP, (void *)value) != 0)
	{
		strncpy(ipaddr, inet_ntoa(*((struct in_addr *)value)), 16);
		ipaddr[15] = '\0';
	}
	if (mib_get(MIB_ADSL_LAN_SUBNET, (void *)value) != 0)
	{
		strncpy(subnet, inet_ntoa(*((struct in_addr *)value)), 16);
		subnet[15] = '\0';
	}

	// get the minumum MRU for all WLAN-side link
	/* marked by Jenny
	vInt = get_min_wan_mru();
	if (vInt==0) */
		vInt = 1500;
	snprintf(value, 6, "%d", vInt);
	// set LAN-side MRU
	status|=va_cmd(IFCONFIG, 6, 1, (char*)LANIF, ipaddr, "netmask", subnet, "mtu", value);
#ifdef CONFIG_USER_DHCPCLIENT_MODE
	}
#endif

#ifdef CONFIG_SECONDARY_IP
	mib_get(MIB_ADSL_LAN_ENABLE_IP2, (void *)value);
	if (value[0] == 1) {
		// ifconfig LANIF LAN_IP netmask LAN_SUBNET
		if (mib_get(MIB_ADSL_LAN_IP2, (void *)value) != 0)
		{
			strncpy(ipaddr, inet_ntoa(*((struct in_addr *)value)), 16);
			ipaddr[15] = '\0';
		}
		if (mib_get(MIB_ADSL_LAN_SUBNET2, (void *)value) != 0)
		{
			strncpy(subnet, inet_ntoa(*((struct in_addr *)value)), 16);
			subnet[15] = '\0';
		}
		snprintf(value, 6, "%d", vInt);
		// set LAN-side MRU
		status|=va_cmd(IFCONFIG, 6, 1, (char*)"br0:0", ipaddr, "netmask", subnet, "mtu", value);
	}
#endif


#ifdef CONFIG_USER_DHCP_SERVER
	if (mib_get(MIB_ADSL_LAN_AUTOSEARCH, (void *)value) != 0)
	{
		if (value[0] == 1)	// enable LAN ip autosearch
		{
			// check if dhcp server on ? per TR-068, I-190
			// Modified by Mason Yu for dhcpmode
			// if (mib_get(MIB_ADSL_LAN_DHCP, (void *)value) != 0)
			if (mib_get(MIB_DHCP_MODE, (void *)value) != 0)
			{
				if (value[0] != DHCP_LAN_SERVER)	// dhcp server is disabled
				{
					usleep(2000000); // wait 2 sec for br0 ready
					startLANAutoSearch(ipaddr, subnet);
				}
			}
		}
	}
#endif

#if defined(CONFIG_IPV6)
#ifdef CONFIG_RTK_L34_ENABLE
	if (mib_get(MIB_LAN_IP_VERSION1, (void *)tmpBuf) !=0)
	{
		if (tmpBuf != 0) //enable ipv6
			setup_disable_ipv6(LANIF, 0);
		else //ipv4 only
			setup_disable_ipv6(LANIF, 1);
	}
#else
	setup_disable_ipv6(LANIF, 0);
#endif
	if (mib_get(MIB_IPV6_LAN_IP_ADDR, (void *)tmpBuf) != 0)
	{
		char cmdBuf[100]={0};
		sprintf(cmdBuf, "%s/%d", tmpBuf, 64);
		va_cmd(IFCONFIG, 3, 1, LANIF, ARG_ADD, cmdBuf);

		//fix two default IPv6 gateway in LAN, Alan
		delOrgLanLinklocalIPv6Address();
		
		/* Iulian Wu , enable IPv6 forwarding for br0*/	
		sprintf(cmdBuf, "echo 1 > /proc/sys/net/ipv6/conf/br0/forwarding", 64);
		system(cmdBuf);
	}

#ifdef CONFIG_00R0 //enable anycast address fe80:: for source address
	system("/bin/echo 1 > /proc/sys/net/ipv6/anycast_src_echo_reply");
#endif
#endif

	if (status)  //start fail
	    return -1;

	//start success
    return 1;
}

#if defined(CONFIG_RTL9600_SERIES) && defined(CONFIG_RTK_L34_ENABLE)
int stopELan(void)
{
#ifdef WLAN_MBSSID
	char para2[20];
#endif
	int status, i;

	for(i=0;i<ELANVIF_NUM;i++){
		status|=va_cmd(IFCONFIG, 2, 1, ELANVIF[i], "down");
	}
#if defined(CONFIG_RTL8681_PTM)
	status|=va_cmd(IFCONFIG, 2, 1, PTMIF, "down");
#endif
#ifdef CONFIG_USB_ETH
	status|=va_cmd(IFCONFIG, 2, 1, USBETHIF, "down");
#endif //CONFIG_USB_ETH
#ifdef WLAN_SUPPORT
#if	defined(CONFIG_YUEME) && defined(CONFIG_LUNA_DUAL_LINUX)
	status|=va_cmd(IFCONFIG, 2, 1, "wlan0", "down");
#else
	status|=va_cmd(IFCONFIG, 2, 1, WLANIF[0], "down");
#endif

#ifdef WLAN_MBSSID
	// Set macaddr for VAP
	for (i=1; i<=WLAN_MBSSID_NUM; i++) {
		sprintf(para2, "wlan0-vap%d", i-1);
		status|=va_cmd(IFCONFIG, 2, 1, para2, "down");
	}
#endif

#if defined(CONFIG_RTL_92D_DMDP) || (defined(WLAN_DUALBAND_CONCURRENT) && !defined(CONFIG_LUNA_DUAL_LINUX))
	status|=va_cmd(IFCONFIG, 2, 1, WLANIF[1], "down");
#ifdef WLAN_MBSSID
	// Set macaddr for VAP
	for (i=1; i<=WLAN_MBSSID_NUM; i++) {
		sprintf(para2, "wlan1-vap%d", i-1);
		status|=va_cmd(IFCONFIG, 2, 1, para2, "down");
	}
#endif
#endif //CONFIG_RTL_92D_DMDP
#endif

	status|=va_cmd(IFCONFIG, 2, 1, BRIF, "down");
	status|=va_cmd(BRCTL, 2, 1, "delbr", (char*)BRIF);
	
#if defined(CONFIG_LUNA) && defined(CONFIG_RTK_L34_ENABLE)
	{
		Flush_RTK_RG_gatewayService();
	}
#endif

	return status;
}

void startup_RG(void)
{
	unsigned char value[32];
	char vChar=0;
	int vInt;
	int i;
	
#if defined(CONFIG_LUNA) && defined(CONFIG_RTK_L34_ENABLE)
//	Init_RTK_RG_Device();
#endif

	if (-1==startELan())
		printf("startELan fail, plz check!\n");
#if defined(CONFIG_LUNA) && !defined(CONFIG_RTK_L34_ENABLE)
#if defined(CONFIG_RTL_MULTI_LAN_DEV) && defined(CONFIG_RTL8686) && !defined(CONFIG_RTK_L34_ENABLE)
	//without RG, default let switch forward packet.
	system("/bin/echo normal > /proc/rtl8686gmac/switch_mode");
#endif
#endif

	// check INIT_SCRIPT
	if (mib_get(MIB_INIT_SCRIPT, (void *)value) != 0)
	{
		vInt = (int)(*(unsigned char *)value);
	}
	else
		vInt = 1;

	if (vInt == 0)
	{
		 for(i=0;i<ELANVIF_NUM;i++){
#if defined(CONFIG_RTK_L34_ENABLE) && defined(CONFIG_ETH_WAN_PORT)
			 int ret,phyPortId;
			 ret = rtk_rg_switch_phyPortId_get(i, &phyPortId);
			 if(ret == 0 && phyPortId==CONFIG_ETH_WAN_PORT)
				 continue;
#endif
			va_cmd(IFCONFIG, 2, 1, ELANVIF[i], "up");
		}
#if defined(CONFIG_RTL8681_PTM)
		va_cmd(IFCONFIG, 2, 1, PTMIF, "up");
#endif
#ifdef CONFIG_USB_ETH
		va_cmd(IFCONFIG, 2, 1, USBETHIF, "up");
#endif //CONFIG_USB_ETH
		va_cmd(WEBSERVER, 0, 0);
		return 0;	// stop here
	}
#if defined(WLAN_SUPPORT) && defined(CONFIG_RTK_L34_ENABLE) && defined(CONFIG_RTL_MULTI_LAN_DEV)
	va_cmd(IFCONFIG, 2, 1, ELANIF, "up");
#endif

//root interface should be up first
#ifndef CONFIG_RTL_MULTI_LAN_DEV
	if (va_cmd(IFCONFIG, 2, 1, ELANIF, "up"))
		goto restartup_rg_fail;
#endif
#ifdef CONFIG_DEV_xDSL
	// Create in ra8670.c, dsl link status
	va_cmd(IFCONFIG, 2, 1, "atm0", "up");
#endif

	// start WAN interface ...
#if defined(CONFIG_LUNA) && defined(CONFIG_RTK_L34_ENABLE)
	Init_RG_ELan(UntagCPort, RoutingWan);
#endif

#ifdef CONFIG_RG_BRIDGE_PPP_STATUS
	//Add filter before start wan
	AddRTK_RG_Bridge_PPPSession_Filter();
#endif

#if defined(CONFIG_XDSL_CTRL_PHY_IS_SOC)
	for(i=0;i<ELANVIF_NUM;i++){
		if(va_cmd(IFCONFIG, 2, 1, ELANVIF[i], "up")){
			goto restartup_rg_fail;
		}
	}

	restartWAN(CONFIGALL, NULL);
#else
	restartWAN(CONFIGALL, NULL);

	system("/bin/diag port set phy-force-power-down port all state disable");

#ifdef CONFIG_E8B
	setupUniPortCapability();
#endif
	for(i=0;i<ELANVIF_NUM;i++){
#if defined(CONFIG_RTK_L34_ENABLE) && defined(CONFIG_ETH_WAN_PORT)
		int ret,phyPortId;
		ret = rtk_rg_switch_phyPortId_get(i, &phyPortId);
		if(ret == 0 && phyPortId==CONFIG_ETH_WAN_PORT)
			continue;
#endif
		if(va_cmd(IFCONFIG, 2, 1, ELANVIF[i], "up")){
			goto restartup_rg_fail;
		}
#if defined(CONFIG_RTK_L34_ENABLE) && defined(CONFIG_RTL_MULTI_LAN_DEV)
		restart_ethernet(i+1);
#endif
	}
#endif

#ifdef CONFIG_E8B
	 // Set MAC filter
#ifndef MAC_FILTER_SRC_ONLY
	setupMacFilterEbtables(); 
#endif
	setupMacFilterTables();
#endif

#if defined(CONFIG_RTL8681_PTM)
	if (va_cmd(IFCONFIG, 2, 1, PTMIF, "up"))
		goto restartup_rg_fail;
#endif
#ifdef CONFIG_USB_ETH
	if (va_cmd(IFCONFIG, 2, 1, USBETHIF, "up"))
		goto restartup_rg_fail;
#endif //CONFIG_USB_ETH

#ifdef ELAN_LINK_MODE_INTRENAL_PHY
	setupLinkMode_internalPHY();
#endif

#ifdef CONFIG_RTK_L34_ENABLE
	mib_get(MIB_DMZ_ENABLE, &vChar);
	if(vChar)
	{
		Flush_RTK_RG_gatewayService();
		RTK_RG_gatewayService_add();
	}
#endif

#ifdef _PRMT_X_CT_COM_PORTALMNT_
	setPortalMNT();
#endif

#ifdef CONFIG_USER_PPTP_CLIENT_PPTP
#ifdef CONFIG_RTK_L34_ENABLE
	RG_Preset_PPTP_Napt_Rule();
#endif
	pptp_take_effect();
#ifdef CONFIG_USER_PPTPD_PPTPD
	pptpd_take_effect();
#endif
#endif
#ifdef CONFIG_USER_L2TPD_L2TPD
#ifdef CONFIG_RTK_L34_ENABLE
	RG_Preset_L2TP_Napt_Rule();
#endif
	l2tp_take_effect();
#endif
#if defined(CONFIG_LUNA) && defined(CONFIG_RTK_L34_ENABLE)
	{
#if defined(CONFIG_GPON_FEATURE) || defined(CONFIG_EPON_FEATURE) || defined(CONFIG_FIBER_FEATURE)
		int pon_mode=0, acl_default=0;
		if (mib_get(MIB_PON_MODE, (void *)&pon_mode) != 0)
		{
#ifdef CONFIG_RTL9602C_SERIES
			acl_default = 1;
#endif
			if ((pon_mode != GPON_MODE) || acl_default == 1)
			{
				RG_del_All_Acl_Rules();
				RG_add_default_Acl_Qos();
			}
		}
#else
		RG_del_All_Acl_Rules();
		RG_add_default_Acl_Qos();
#endif
	}
#ifndef CONFIG_RTL9600_SERIES
	check_port_based_vlan_of_bridge_inet_wan();
#endif
#endif
	if(access("/var/run/lannetinfo.pid", 0)==0) {
		/* echo 1 > /proc/rg/gather_lanNetInfo */
		system("/bin/echo 1 > /proc/rg/gather_lanNetInfo");	
	}

	return 0;

restartup_rg_fail:
	printf("System startup RG failed !\n");
	return -1;
}
#endif

#if 0
int check_for_rip()
{
	unsigned int num;
	unsigned char uChar;
	MIB_CE_ATM_VC_Tp pEntry;

	// --- Check LAN side
	if (mib_get(MIB_ADSL_LAN_DHCP, (void *)&uChar) != 0)
	{
		if (uChar != 0)
			return 0;	// dhcp server not disabled
	}

	// --- Check WAN side
	if (mib_chain_total(MIB_ATM_VC_TBL) != 1)
		return 0;
	pEntry = (MIB_CE_ATM_VC_Tp) mib_chain_get(MIB_ATM_VC_TBL,0);
	if(!pEntry)
		return 0;
	if (pEntry->cmode != CHANNEL_MODE_RT1483 && pEntry->cmode != CHANNEL_MODE_IPOE)
		return 0;
	if(pEntry->napt != 0)
		return 0;	// napt not disabled
	if(pEntry->ipDhcp != 0)
		return 0;	// not fixed ip

	return 1;
}
#endif

// return value:
// 0  : not active
// 1  : successful
// -1 : startup failed
int setupService(void)
{
#ifdef REMOTE_ACCESS_CTL
	MIB_CE_ACC_T Entry;
#endif
	char *argv[15];
	int status=0;

#ifdef REMOTE_ACCESS_CTL
	if (!mib_chain_get(MIB_ACC_TBL, 0, (void *)&Entry))
		return 0;
#endif

	/* run as console web
	if (pEntry->web !=0) {
		// start webs
		va_cmd(WEBSERVER, 0, 0);
	}
	*/
	//if (pEntry->snmp !=0) {
		// start snmpd
		// Commented by Mason Yu
		// We use new version
		//va_cmd(SNMPD, 0, 0);
		// Add by Mason Yu for start SnmpV2Trap
#if defined(CONFIG_USER_SNMPD_SNMPD_V2CTRAP) || defined(CONFIG_USER_SNMPD_SNMPD_V3)
	char vChar;
	mib_get(MIB_SNMPD_ENABLE, (void *)&vChar);
	if(vChar==1)
		status = startSnmp();
#endif
	//}
	return status;
}

//--------------------------------------------------------
// Daemon startup
// return value:
// 1  : successful
// -1 : failed

#define WAIT_UNTIL_READY

int startDaemon(void)
{
	int pppd_fifo_fd=-1;
	int mpoad_fifo_fd=-1;
	int status=0, tmp_status;
	int k;
#ifndef WAIT_UNTIL_READY
	int mpoa_retry=0;
	int ppp_retry=0;
	int retry_limit = 5;
#endif /* WAIT_UNTIL_READY */

//#ifdef CONFIG_USER_XDSL_SLAVE
//	if( startSlv()<0 )
//		status=-1;
//#endif /*CONFIG_USER_XDSL_SLAVE*/

	//#ifndef CONFIG_ETHWAN
	#ifdef CONFIG_DEV_xDSL
	// start mpoad
	status|=va_cmd(MPOAD, 0, 0);

	// check if mpoad ready to serve
#ifdef WAIT_UNTIL_READY
	/* Wait until mpoad is ready */
	while ((mpoad_fifo_fd = open(MPOAD_FIFO, O_WRONLY)) == -1){
		;
	}
	close(mpoad_fifo_fd);
#else /*else WAIT_UNTIL_READY */
	
	/* Wait until timeout */
	tmp_status = status;
retry_mpoad:
	printf("[%s(%d)]status=%d, mpoa_retry=%d\n",__func__,__LINE__,status,mpoa_retry);
	for (k=0; k<=100; k++)
	{
		if ((mpoad_fifo_fd = open(MPOAD_FIFO, O_WRONLY))!=-1)
			break;
		usleep(30000);
	}

	if (mpoad_fifo_fd == -1)
	{
		mpoa_retry++;
		printf("open mpoad fifo failed !\n");
		status = -1;
		printf("[%s(%d)]status=%d, mpoa_retry=%d\n",__func__,__LINE__,status,mpoa_retry);
		if(mpoa_retry< retry_limit)
			goto retry_mpoad;
	}
	else{
		status = tmp_status;
		close(mpoad_fifo_fd);
	}
#endif /* endif WAIT_UNTIL_READY */
	#endif // CONFIG_DEV_xDSL

// Mason Yu. for IPv6
// To start DNSv6Relay, it will refer /proc/net/if_inet6.
// After the IPv6 IP is set, we can start the DNSRelay.
// Remove the following process to main().
#if 0
	if (startDnsRelay() == -1)
	{
		printf("start DNS relay failed !\n");
		status=-1;
	}
#endif

	// Marked by Mason Yu. try123. If combine DHCP Server and relay, we should start DHCPD on startRest().
#ifdef CONFIG_USER_DHCP_SERVER
#ifndef COMBINE_DHCPD_DHCRELAY
	tmp_status=setupDhcpd();
	if (tmp_status == 1)
	{
		status|=va_cmd(DHCPD, 1, 0, DHCPD_CONF);
	} else if (tmp_status==-1)
	    status = -1;
#endif
#endif

    // 2012/8/22
    // Move start_dhcpv6 to here because need to set IPv6 Global address
    // faster to pass the IPv6 core ready logo test.

	// Mason Yu.
#ifdef CONFIG_IPV6
#ifdef CONFIG_USER_DHCPV6_ISC_DHCP411
	start_dhcpv6(1);
#endif
#endif

#ifdef CONFIG_PPP
	// start spppd
	status|=va_cmd(SPPPD, 0, 0);

	// check if spppd ready to serve
#ifdef WAIT_UNTIL_READY
	/* Wait until spppd is ready */
	while ((pppd_fifo_fd = open(PPPD_FIFO, O_WRONLY)) == -1){
		;
	}
	close(pppd_fifo_fd);
#else	/* else WAIT_UNTIL_READY*/

	/* Wait until timeout */
	tmp_status = status;
retry_pppd:
	printf("[%s(%d)]status=%d, ppp_retry=%d\n",__func__,__LINE__,status,ppp_retry);
	for (k=0; k<=100; k++)
	{
		if ((pppd_fifo_fd = open(PPPD_FIFO, O_WRONLY))!=-1)
			break;
		usleep(30000);
	}

	if (pppd_fifo_fd == -1){
		ppp_retry++;
		status = -1;
		printf("[%s(%d)]status=%d, ppp_retry=%d\n",__func__,__LINE__,status,ppp_retry);
		if(ppp_retry < retry_limit)
			goto retry_pppd;
	}
	else{
		status = tmp_status;
		close(pppd_fifo_fd);
	}
#endif /* endif WAIT_UNTIL_READY */
#endif

#ifdef CONFIG_USER_WT_146
#define BFD_DAEMON "/bin/bfdmain"
#define BFD_SERVER_FIFO_NAME "/tmp/bfd_serv_fifo"
{
	int bfdmain_fifo_fd=-1;

	// start bfdmain
	status|=va_cmd(BFD_DAEMON, 0, 0);

	// check if bfdmain ready to serve
	//while ((bfdmain_fifo_fd = open(BFD_SERVER_FIFO_NAME, O_WRONLY)) == -1)
	for (k=0; k<=100; k++)
	{
		if ((bfdmain_fifo_fd = open(BFD_SERVER_FIFO_NAME, O_WRONLY))!=-1)
			break;
		usleep(30000);
	}

	if (bfdmain_fifo_fd == -1)
		status = -1;
	else
		close(bfdmain_fifo_fd);
}
#endif //CONFIG_USER_WT_146


#ifdef TIME_ZONE
#ifdef CONFIG_E8B
	status|=setupNtp(SNTP_ENABLED);
#else
	status|=startNTP();
#endif
#endif

	status|=setupService();
	// Kaohj -- move from startRest().
	// start webs
	status|=va_cmd(WEBSERVER, 0, 0);

	return status;
}

#ifdef ELAN_LINK_MODE_INTRENAL_PHY
// Added by Mason Yu
int setupLinkMode_internalPHY()
{
	restart_ethernet(1);
	return 1;

}
#endif

//--------------------------------------------------------
// LAN side IP autosearch using ARP
// Input: current IP address
// return value:
// 1  : successful
// -1 : failed
int startLANAutoSearch(const char *ipAddr, const char *subnet)
{
	unsigned char netip[4];
	struct in_addr *dst;
	int k, found;

	TRACE(STA_INFO, "Start LAN IP autosearch\n");
	dst = (struct in_addr *)netip;

	if (!inet_aton(ipAddr, dst)) {
		printf("invalid or unknown target %s", ipAddr);
		return -1;
	}

	if (isDuplicate(dst, LANIF)) {
		TRACE(STA_INFO, "Duplicate LAN IP found !\n");
		found = 0;
		inet_aton("192.168.1.254", dst);
		if (isDuplicate(dst, LANIF)) {
			netip[3] = 63;	// 192.168.1.63
			if (isDuplicate(dst, LANIF)) {
				// start from 192.168.1.253 and descending
				for (k=253; k>=1; k--) {
					netip[3] = k;
					if (!isDuplicate(dst, LANIF)) {
						// found it
						found = 1;
						TRACE(STA_INFO, "Change LAN ip to %s\n", inet_ntoa(*dst));
						break;
					}
				}
			}
			else {
				// found 192.168.1.63
				found = 1;
				TRACE(STA_INFO, "Change LAN ip to %s\n", inet_ntoa(*dst));
			}
		}
		else {
			// found 192.168.1.254
			found = 1;
			TRACE(STA_INFO, "Change LAN ip to %s\n", inet_ntoa(*dst));
		}

		if (!found) {
			printf("not available LAN IP !\n");
			return -1;
		}

		// ifconfig LANIF LAN_IP netmask LAN_SUBNET
		va_cmd(IFCONFIG, 4, 1, (char*)LANIF, inet_ntoa(*dst), "netmask", subnet);
	}

	return 1;
}

#if defined(CONFIG_RTL_IGMP_SNOOPING)
int setupIGMPSnoop()
{
	unsigned char mode;
	mib_get(MIB_MPMODE, (void *)&mode);
	if (mode&MP_IGMP_MASK){
		__dev_setupIGMPSnoop(1);
	} else {
		__dev_setupIGMPSnoop(0);
	}
	return 1;
}
#endif
#if defined(CONFIG_RTL_MLD_SNOOPING)
int setupMLDSnoop()
{
	unsigned char mode;
	mib_get(MIB_MPMODE, (void *)&mode);
	if (mode&MP_MLD_MASK){
		__dev_setupMLDSnoop(1);
	} else {
		__dev_setupMLDSnoop(0);
	}
	return 1;
}
#endif
//--------------------------------------------------------
// Final startup
// return value:
// 1  : successful
// -1 : failed
int startRest(void)
{
	int vcTotal, i;
	unsigned char autosearch, mode;
	MIB_CE_ATM_VC_T Entry;
	int status=0;

#ifdef CONFIG_IPV6
	char ipv6Enable =-1;
	char buf[64];
#endif

	// Kaohj -- move to startDaemon().
	//	When ppp up, it will send command to boa message queue,
	//	so we needs boa msgq to be enabled earlier.
/*
	// start snmpd
	va_cmd(SNMPD, 0, 0);
*/

	// Add static routes
	// Mason Yu. Init hash table for all routes on RIP
	// Move to startWan()
	//addStaticRoute();

	// Mason Yu. If combine DHCP Server and relay, we should start DHCPD here not on startDaemon().
#ifdef CONFIG_USER_DHCP_SERVER
#ifdef COMBINE_DHCPD_DHCRELAY
	int tmp_status;
	tmp_status=setupDhcpd();
	if (tmp_status == 1)
	{
		status|=va_cmd(DHCPD, 2, 0, "-S", DHCPD_CONF);
	} else if (tmp_status==-1)
	    status = -1;
#endif

	//Added by Mason Yu for start DHCP relay
	// We only can choice DHCP Server or Relay one.
	if (-1==startDhcpRelay())
	    return -1;
#endif

#if defined(CONFIG_RTL_IGMP_SNOOPING)
	setupIGMPSnoop();
#endif
#if defined(CONFIG_RTL_MLD_SNOOPING)
	setupMLDSnoop();
#endif

#ifdef NEW_PORTMAPPING
	setupnewEth2pvc();
#endif


#ifdef IP_QOS
	mib_get(MIB_MPMODE, (void *)&mode);
#ifdef QOS_DIFFSERV
	unsigned char qosDomain;
	mib_get(MIB_QOS_DIFFSERV, (void *)&qosDomain);
	if (qosDomain == 1)
		setupDiffServ();
	else {
#endif
	if (mode&MP_IPQ_MASK)
		setupIPQ();
#ifdef QOS_DIFFSERV
	}
#endif
#elif defined(NEW_IP_QOS_SUPPORT)
#ifdef CONFIG_E8B
	setupIPQ();
#else
	//ql 20081117 START for IP QoS
	setup_qos_setting();
#endif
#elif defined(CONFIG_USER_IP_QOS_3)
	setupIPQ();
#endif

#ifdef CONFIG_USER_IP_QOS
#ifdef CONFIG_HWNAT
	setWanIF1PMark();
#endif
#endif

	// ioctl for direct bridge mode, jiunming
	{
		unsigned char  drtbr_mode;
		if (mib_get(MIB_DIRECT_BRIDGE_MODE, (void *)&drtbr_mode) != 0)
		{
			__dev_setupDirectBridge( (int) drtbr_mode );
		}
	}

#ifdef CONFIG_E8B
	setupDos();  // Set DoS.
#else
#ifdef DOS_SUPPORT
	// for DOS support
	setup_dos_protection();
#endif
#endif

     #ifdef CONFIG_IGMP_FORBID

       unsigned char igmpforbid_mode;

	 if (!mib_get( MIB_IGMP_FORBID_ENABLE,  (void *)&igmpforbid_mode)){
		printf("igmp forbid  parameter failed!\n");
	}
	 if(1==igmpforbid_mode){
             __dev_igmp_forbid(1);
	 }
     #endif

#ifdef CONFIG_USER_SAMBA
	startSamba();
#endif // CONFIG_USER_SAMBA

#ifdef CONFIG_IPV6
	mib_get(MIB_V6_IPV6_ENABLE, (void *)&ipv6Enable);
	/* IulianWu, IPv6 enable/disable */
	snprintf(buf, sizeof(buf), "/bin/echo %d > /proc/sys/net/ipv6/conf/all/disable_ipv6", (ipv6Enable==1?0:1));
	system(buf);

	// Added by Mason Yu. for ipv6
#ifdef CONFIG_USER_IPV6READYLOGO_ROUTER
	if(ipv6Enable==1)
		printf("Init System OK for IPV6\n");    // Added by Mason Yu for p2r_test
#endif

#ifdef CONFIG_USER_IPV6READYLOGO_HOST
	if(ipv6Enable==1)
		printf("Init System OK for IPV6\n");	  // Added by Mason Yu for p2r_test
#endif
#endif
	// E8B forceportal
#ifdef _PRMT_X_CT_COM_PORTALMNT_
	setPortalMNT();
#endif

#if defined (WLAN_SUPPORT)
	mode = 0;
	mib_get(MIB_WIFI_TEST, (void *)&mode);
	if (mode == 1) {
		va_cmd("/bin/ifconfig", 2, 0, ELANIF, "192.168.1.6");	
		va_cmd("/bin/11N_UDPserver", 1, 0, "&");
	}
	#ifdef CONFIG_USER_WIRELESS_MP_MODE
	va_cmd("/bin/ifconfig", 2, 0, ELANIF, "192.168.1.6");
	va_cmd("/bin/11N_UDPserver", 1, 0, "&");
	#endif
#endif

#ifdef CONFIG_USER_Y1731
	Y1731_start(0);
#endif
#ifdef CONFIG_USER_8023AH
	EFM_8023AH_start(0);
#endif

#if defined(CONFIG_USER_RTK_LBD)
	setupLBD();
#endif

	return 1;
}

#if defined(CONFIG_USER_SNMPD_SNMPD_V2CTRAP) || defined(CONFIG_USER_SNMPD_SNMPD_V3)
// Added by Mason Yu
static int getSnmpConfig(void)
{

	//char *str1, *str2, *str3, *str4, *str5;
	unsigned char str[256];
	FILE *fp;

	fp=fopen("/tmp/snmp", "w+");


	mib_get(MIB_SNMP_SYS_DESCR, (void *)str);
	fprintf(fp, "%s\n", str);


	mib_get( MIB_SNMP_SYS_CONTACT,  (void *)str);
	fprintf(fp, "%s\n", str);


	mib_get( MIB_SNMP_SYS_NAME,  (void *)str);
	fprintf(fp, "%s\n", str);


	mib_get( MIB_SNMP_SYS_LOCATION,  (void *)str);
	fprintf(fp, "%s\n", str);


	mib_get( MIB_SNMP_SYS_OID,  (void *)str);
	fprintf(fp, "%s\n", str);


  	fclose(fp);
	return 0;
}
#endif

static int check_wan_mac()
{
#if defined(CONFIG_LUNA) && defined(GEN_WAN_MAC)
	//sync wan mac address from ELAN_MAC_ADDR
	int ret=0;
	int i, vcTotal;
	MIB_CE_ATM_VC_T Entry;
	char macaddr[MAC_ADDR_LEN], gen_macaddr[MAC_ADDR_LEN];

	mib_get(MIB_ELAN_MAC_ADDR, (void *)macaddr);

	vcTotal = mib_chain_total(MIB_ATM_VC_TBL);

	for (i = 0; i < vcTotal; i++)
	{
		if (!mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&Entry))
				return -1;

		if(MEDIA_INDEX(Entry.ifIndex) == MEDIA_ETH){

			memcpy(gen_macaddr, macaddr, MAC_ADDR_LEN);
			setup_mac_addr(gen_macaddr,WAN_HW_ETHER_START_BASE + ETH_INDEX(Entry.ifIndex)); 					
			//gen_macaddr[MAC_ADDR_LEN-1]+= (WAN_HW_ETHER_START_BASE + ETH_INDEX(Entry.ifIndex));
			if(memcmp(gen_macaddr, Entry.MacAddr, MAC_ADDR_LEN)){
				memcpy(Entry.MacAddr, gen_macaddr, MAC_ADDR_LEN);
				mib_chain_update(MIB_ATM_VC_TBL, (void *)&Entry, i);
				ret++;
			}
		}
	}
	if(!ret)
		return 0;

#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif

#endif
}

#ifdef CONFIG_USER_RTK_RECOVER_SETTING
char xml_line[1024];
mib_table_entry_T *mib_info;
int info_total;
static int get_line(char *s, int size, FILE *fp)
{
	char *pstr;
	
	while (1) {
		if (!fgets(s,size,fp))
			return -1;
		pstr = trim_white_space(s);
		if (strlen(pstr))
			break;
	}
	
	//printf("get line: %s\n", s);
	return 0;
}

/*
 *	0: not consist
 *	1: consist with system mib
 *	-1: error
 */
static int xml_table_check(char *line, CONFIG_DATA_T cnf_type)
{
	int i;
	char *ptoken;
	char *pname, *pvalue;
	const char empty_str[]="";
	mib_table_entry_T info_entry;
	unsigned char mibvalue[1024], svalue[2048];
	
	// get name
	ptoken = strtok(line, "\"");
	ptoken = strtok(0, "\"");
	pname = ptoken;
	//printf("name=%s\n", ptoken);
	
	for(i=0; i<info_total; i++){
		if (((mib_table_entry_T*)(mib_info+i))->mib_type != cnf_type)
			continue;
		if(!strcmp(((mib_table_entry_T*)(mib_info+i))->name, ptoken)){
			memcpy(&info_entry,(mib_table_entry_T*)(mib_info+i),sizeof(mib_table_entry_T));
			break;
		}
	}

	if(i>=info_total) {
		printf("%s: Invalid table entry name: %s\n", __FUNCTION__, ptoken);
		return -1;
	}
	
	// get value
	ptoken = strtok(0, "\"");
	ptoken = strtok(0, "\"");
	if (strtok(0, "\"")==NULL)
		ptoken = (char *)empty_str;
	pvalue = ptoken;
	//printf("xml value=%s\n", ptoken);
	mib_get(info_entry.id, (void *)mibvalue);
	
	mib_to_string(svalue, mibvalue, info_entry.type, info_entry.size);
	//printf("sys value=%s\n", svalue);
	if (!strncmp(pvalue, svalue, 512))
		return 1;
	else {
		printf("name=%s	value= [%s(xml), %s(sys)]\n", pname, pvalue, svalue);
		return 0;
	}
	return 0;
}

/*
 *	0: not consist
 *	1: consist with system mib
 *	-1: error
 */
static int xml_chain_check_real(FILE *fp)
{
	char *pstr, *ptoken;
	const char empty_str[]="";
	char *pname, *pvalue;
	
	while(!feof(fp)) {
		get_line(xml_line, sizeof(xml_line), fp);
		// remove leading space
		pstr = trim_white_space(xml_line);
		if (!strncmp(pstr, "</chain", 7)) {
			break; // end of chain object
		}
		// check OBJECT_T
		if (!strncmp(pstr, "<chain", 6)) {
			// get Object name
			ptoken = strtok(pstr, "\"");
			ptoken = strtok(0, "\"");
			//printf("obj_name=%s\n", ptoken);
			xml_chain_check_real(fp);
		}
		else {
			// get name
			ptoken = strtok(pstr, "\"");
			ptoken = strtok(0, "\"");
			pname = ptoken;
			//printf("name=%s\t\t", ptoken);
			
			// get value
			ptoken = strtok(0, "\"");
			ptoken = strtok(0, "\"");
			if (strtok(0, "\"")==NULL)
				ptoken = (char *)empty_str;
			pvalue = ptoken;
			//printf("value=%s\n", ptoken);
		}
	}
	return 1;
}

/*
 *	0: not consist
 *	1: consist with system mib
 *	-1: error
 */
static int xml_chain_check(char *line, FILE *fp)
{
	char *ptoken;
	
	// get chain name
	ptoken = strtok(line, "\"");
	ptoken = strtok(0, "\"");
	//printf("Chain name=%s\n", ptoken);
	xml_chain_check_real(fp);
	return 1;
}

/*
 *	0: not consist
 *	1: consist with system mib
 *	-1: error
 */
static int check_xml_value(char *line, CONFIG_DATA_T cnf_type, FILE *fp)
{
	int i, k;
	char str[32];
	int ret=0;

	// remove leading space
	i = 0; k = 0;
	while (line[i++]==' ')
		k++;
	sscanf(line, "%s", str);
	//printf("str=%s\n", str);
	if (!strcmp(str, "<Value")) {
		ret = xml_table_check(&line[k], cnf_type);
	}
	else if (!strcmp(str, "<chain")) {
		ret = xml_chain_check(&line[k], fp);
	}
	else {
		printf("Unknown statement: %s\n", line);
		ret = -1;
	}

	return ret;
}

/*	check consistency between xml file and system mib
 *
 *	0: not consistent
 *	1: consistent with system mib
 *	-1: error
 */
int check_xml_file(char *fname, CONFIG_DATA_T dtype)
{
	FILE *fp;
	int i, ret=0;
	char *pstr;
	CONFIG_DATA_T ftype;

#ifdef XOR_ENCRYPT
	xor_encrypt(fname, "/tmp/config_xor.xml");
	rename("/tmp/config_xor.xml", fname);
#endif
	
	if (!(fp = fopen(fname, "r"))) {
		return -1;
	}
	get_line(xml_line, sizeof(xml_line), fp);
	pstr = trim_white_space(xml_line);
	// Check for configuration type (cs or hs?).
	if(!strcmp(pstr, CONFIG_HEADER))
		ftype = CURRENT_SETTING;
	else if(!strcmp(pstr, CONFIG_HEADER_HS))
		ftype = HW_SETTING;
	else {
		printf("%s: Invalid config file(%s)!\n", __FUNCTION__, fname);
		fclose(fp);
		return -1;
	}
	if (ftype != dtype) {
		printf("%s: %s not in correct type.\n", __FUNCTION__, fname);
		fclose(fp);
		return -1;
	}
	
	info_total = mib_info_total();
	mib_info=(mib_table_entry_T *)malloc(sizeof(mib_table_entry_T)*info_total);

	for(i=0;i<info_total;i++){
		if(!mib_info_index(i,mib_info+i))
			break;
	}

	if(i<info_total){
		free(mib_info);
		fclose(fp);
		printf("%s: get mib info total entry error!\n", __FUNCTION__);
		return -1;
	}
	
	while(!feof(fp)) {
		get_line(xml_line, sizeof(xml_line), fp);//get one line from the file
		pstr = trim_white_space(xml_line);
		if(!strcmp(pstr, CONFIG_TRAILER) || !strcmp(pstr, CONFIG_TRAILER_HS))
			break; // end of configuration
		
		if ((ret=check_xml_value(pstr, dtype, fp)) != 1)
			break;
	}
	
	free(mib_info);
	fclose(fp);
	return ret;
}

/* Return backup xml file if not consistent with system mib */
unsigned int check_xml_backup()
{
	int iVal;
	unsigned int ret=0;
	char cmd_str[128];
	
	// check hs
	#ifndef FORCE_HS
	printf("Check HS XML backup ...\n");
	snprintf(cmd_str, 128, "/bin/gunzip -c %s > %s", OLD_SETTING_FILE_HS_GZ, TEMP_XML_FILE_HS);
	//printf("cmd: %s\n", cmd_str);
	system(cmd_str);
	iVal = check_xml_file(TEMP_XML_FILE_HS, HW_SETTING);
	unlink(TEMP_XML_FILE_HS);
	if (iVal != 1)
		ret |= HW_SETTING;
	#else // FORCE_HS
	printf("Skip checking HS XML backup ...\n");
	#endif
	
	// check cs
	printf("Check CS XML backup ...\n");
	snprintf(cmd_str, 128, "/bin/gunzip -c %s > %s", OLD_SETTING_FILE_GZ, TEMP_XML_FILE);
	//printf("cmd: %s\n", cmd_str);
	system(cmd_str);
	iVal = check_xml_file(TEMP_XML_FILE, CURRENT_SETTING);
	unlink(TEMP_XML_FILE);
	if (iVal != 1)
		ret |= CURRENT_SETTING;
	return ret;
}
#endif // of CONFIG_USER_RTK_RECOVER_SETTING

/*
 *	Disable PVCs before doing auto-pvc search.
 */
static void mibchain_clearPVC()
{
	unsigned int entryNum;
	int i;
	MIB_CE_ATM_VC_T tEntry;
	
	entryNum = mib_chain_total(MIB_ATM_VC_TBL);
	
	// clear atm pvc
	for (i=entryNum-1; i>=0; i--) {
		if(!mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&tEntry))
			continue;

		if(MEDIA_INDEX(tEntry.ifIndex) != MEDIA_ATM)
			continue;
		mib_chain_delete(MIB_ATM_VC_TBL, i);
	}
	return;
}

/*
 * system initialization, checking, setup, etc.
 */
static int sys_setup()
{
	key_t key;
	int qid, vInt, activePVC, ret;
	int i;
	MIB_CE_ATM_VC_T Entry;
	unsigned char value[32];
	FILE *fp;
	char userName[MAX_NAME_LEN], userPass[MAX_NAME_LEN];
	char *xpass;
#ifdef ACCOUNT_CONFIG
	MIB_CE_ACCOUNT_CONFIG_T entry;
	unsigned int totalEntry;
#endif
#ifdef CONFIG_USER_RTK_RECOVER_SETTING
	unsigned int dtype;
#endif
	unsigned char autosearch;
	char cmd[512];
	char devName[200];

	ret = 0;
	//----------------- check if configd is ready -----------------------
	key = ftok("/bin/init", 'r');
	for (i=0; i<=100; i++) {
		if (i==100) {
			printf("Error: configd not started !!\n");
			return 0;
		}
		if ((qid = msgget( key, 0660 )) == -1)
			usleep(30000);
		else
			break;
	}

	// Kaohj -- check consistency between MIB chain definition and descriptor.
	// startup process would be ceased if checking failed, programmer must review
	// all MIB chain descriptors in problem.
	if (mib_check_desc()==-1) {
		printf("Please check MIB chain descriptors !!\n");
		return -1;
	}
#ifdef CONFIG_USER_RTK_RECOVER_SETTING
	// Delay before writing to flash for system stability
	sleep(1);
	fp = fopen(FLASH_CHECK_FAIL, "r"); //only when current setting check is fail, sys restore to oldconfig
	if (fp) {
		fscanf(fp, "%d\n", &dtype);
		fclose(fp);
		unlink(FLASH_CHECK_FAIL);
		//printf("dtype=%d\n", dtype);
		if (dtype & CURRENT_SETTING) {
			// gzip: decompress file
			va_cmd("/bin/gunzip", 2, 1, "-f", OLD_SETTING_FILE_GZ);
			va_cmd("/bin/loadconfig", 2, 1, "-f", OLD_SETTING_FILE);
		}
		if (dtype & HW_SETTING) {
			// gzip: decompress file
			va_cmd("/bin/gunzip", 2, 1, "-f", OLD_SETTING_FILE_HS_GZ);
			va_cmd("/bin/loadconfig", 3, 1, "-f", OLD_SETTING_FILE_HS, "hs");
		}
	}
	
	if ((dtype=check_xml_backup()) != 0) {
		if (dtype & HW_SETTING) { //update hs setting in backup file
			printf("%s: hs xml not consistent, generate a new one.\n", __FUNCTION__);
			// generate a new backup xml
			va_cmd("/bin/saveconfig", 2, 1, "-s", "hs");
		}
		
		if (dtype & CURRENT_SETTING) { //update cs setting in backup file
			printf("%s: cs xml not consistent, generate a new one.\n", __FUNCTION__);
			// generate a new backup xml
			va_cmd("/bin/saveconfig", 2, 1, "-s", "cs");
		}
	}
	else
		printf("%s: xml check ok.\n", __FUNCTION__);
#endif

#ifdef _PRMT_USBRESTORE
	usbRestore();
#endif

	// Clear atm pvcs before doing auto-pvc.
	autosearch = 0;
	mib_get(MIB_ATM_VC_AUTOSEARCH, (void *)&autosearch);
	if (autosearch == 1)
		mibchain_clearPVC();

	//----------------
	// Mason Yu
#if defined(CONFIG_USER_SNMPD_SNMPD_V2CTRAP) || defined(CONFIG_USER_SNMPD_SNMPD_V3)
	getSnmpConfig();
#endif
	// ftpd: /etc/passwd & /tmp (as home dir)
	fp = fopen("/var/passwd", "w+");
#ifdef ACCOUNT_CONFIG
	totalEntry = mib_chain_total(MIB_ACCOUNT_CONFIG_TBL); /* get chain record size */
	for (i=0; i<totalEntry; i++) {
		if (!mib_chain_get(MIB_ACCOUNT_CONFIG_TBL, i, (void *)&entry)) {
			printf("ERROR: Get account configuration information from MIB database failed.\n");
			return;
		}
		strcpy(userName, entry.userName);
		strcpy(userPass, entry.userPassword);
		xpass = crypt(userPass, "$1$");
		if (xpass) {
			if (entry.privilege == (unsigned char)PRIV_ROOT)
				fprintf(fp, "%s:%s:0:0::%s:%s\n", userName, xpass, PW_HOME_DIR, PW_CMD_SHELL);
			else
				fprintf(fp, "%s:%s:1:0::%s:%s\n", userName, xpass, PW_HOME_DIR, PW_CMD_SHELL);
		}
	}
#endif
	mib_get( MIB_SUSER_NAME, (void *)userName );
	mib_get( MIB_SUSER_PASSWORD, (void *)userPass );
	xpass = crypt(userPass, "$1$");
	if (xpass)
		fprintf(fp, "%s:%s:0:0::%s:%s\n", userName, xpass, PW_HOME_DIR, PW_CMD_SHELL);

#ifndef CONFIG_00R0
	// Added by Mason Yu for others user
	mib_get( MIB_SUPER_NAME, (void *)userName );
	mib_get( MIB_SUPER_PASSWORD, (void *)userPass );
	xpass = crypt(userPass, "$1$");
	if (xpass)
		fprintf(fp, "%s:%s:0:0::%s:%s\n", userName, xpass, PW_HOME_DIR, PW_CMD_SHELL);
#endif

#if 0 // anonymous ftp
	// added for anonymous ftp
	fprintf(fp, "%s:%s:10:10::/tmp:/dev/null\n", "ftp", "x");
#endif
	fprintf(fp, "%s:%s:0:0::/tmp:/dev/null\n", "nobody", "x");

	mib_get( MIB_USER_NAME, (void *)userName );
	if (userName[0]) {
		mib_get( MIB_USER_PASSWORD, (void *)userPass );
		xpass = crypt(userPass, "$1$");
		if (xpass)
#if defined(CONFIG_00R0) //USER only can access Web, console/telnet/ftp will be blocked, IulianWu
			fprintf(fp, "%s:%s:1:0::%s:/dev/null\n", userName, xpass, PW_HOME_DIR);
#else
			fprintf(fp, "%s:%s:1:0::%s:%s\n", userName, xpass, PW_HOME_DIR, PW_CMD_SHELL);
#endif
	}

	fclose(fp);
	chmod(PW_HOME_DIR, 0x1fd);	// let owner and group have write access
	// Kaohj --- force kernel(linux-2.6) igmp version to 2
#if defined(_LINUX_2_6_) || defined(_LINUX_3_18_)
#ifdef FORCE_IGMP_V2
	fp = fopen((const char *)PROC_FORCE_IGMP_VERSION,"w");
	if(fp)
	{
		fprintf(fp, "%d", 2);
		fclose(fp);
	}
#endif
#endif

	check_wan_mac();
#ifdef WLAN_QTN
	createQTN_targetIPconf();
#endif

	/* pass device name to kernel */
	mib_get(MIB_DEVICE_NAME,(void *)devName);
	//DEBUG("*****devName=%s*****\n",devName);
	sprintf(cmd,"echo \"%s\" > /proc/sys/kernel/hostname",devName);
	system(cmd);

	return ret;
}

#ifdef CONFIG_USER_XDSL_SLAVE
int startSlv(void)
{
	int  sysret, ret=0;
	char sysbuf[128];

	sprintf( sysbuf, "/bin/ucrelay" );
	printf( "system(): %s\n", sysbuf );
	sysret=system( sysbuf );
	if( WEXITSTATUS(sysret)!=0 )
	{
		printf( "exec ucrelay failed!\n" );
		ret=-1;
	}

	if(ret==0)
	{
#if 1
		int i=3;
		while(i--)
		{
			sprintf( sysbuf, "/bin/ucstartslv" );
			printf( "system(): %s\n", sysbuf );
			sysret=system( sysbuf );
			if( WEXITSTATUS(sysret)!=0 )
			{
				printf( "call /bin/ucstartslv to init slave firmware failed!\n" );
				ret=-1;
			}else{
				ret=0;
				break;
			}
		}
#endif
	}
	return ret;
}
#endif /*CONFIG_USER_XDSL_SLAVE*/

#ifdef CONFIG_KEEP_BOOTCODE_CONFIG
#define BOOTCONF_START 0xbfc07f80
#define BOOTCONF_SIZE  0x40
#define BOOTCONF_MAGIC (('b'<<24) | ('t'<<16) | ('c'<<8) | ('f')) //0x62746366
#define BOOTCONF_PROCNAME	"/proc/bootconf"
struct bootconf
{
	unsigned long	magic;
	unsigned char	mac[6];
	unsigned short	flag;
	unsigned long	ip;
	unsigned long	ipmask;
	unsigned long	serverip;
	unsigned char	filename[24];
	unsigned char	res[16];
};
typedef struct bootconf bootconf_t, *bootconf_p;

static int bootconf_get_from_procfile(bootconf_t *p)
{
	FILE *f;
	int ret=-1;

	if(p==NULL) return ret;
	f=fopen( BOOTCONF_PROCNAME, "r" );
	if(f)
	{
		if( fread(p, 1, BOOTCONF_SIZE, f)==BOOTCONF_SIZE )
		{
			if(p->magic==BOOTCONF_MAGIC)
				ret=0;
			else
				printf( "%s: magic not match %08x\n", __FUNCTION__, p->magic );
		}else{
			printf( "%s: fread errno=%d\n", __FUNCTION__, errno );
		}
		fclose(f);
	}else{
		printf( "%s: can't open %s\n", __FUNCTION__, BOOTCONF_PROCNAME );
	}

	return ret;
}
static void bootconf_updatemib(void)
{
	bootconf_t bc;
	if( bootconf_get_from_procfile(&bc)==0 )
	{
		mib_set( MIB_ELAN_MAC_ADDR, bc.mac );
		mib_set( MIB_ADSL_LAN_IP, &bc.ip );
		mib_set( MIB_ADSL_LAN_SUBNET, &bc.ipmask );
	}else
		printf( "%s: call bootconf_getdata() failed!\n", __FUNCTION__);

	return;
}
#endif /*CONFIG_KEEP_BOOTCODE_CONFIG*/


#ifdef CONFIG_RTL8685_PTM_MII
const char PTMCTL[]="/bin/ptmctl";
int startPTM(void)
{
	int ret=-1;
	if (WAN_MODE & MODE_BOND){
		printf("PTM Bonding Mode!\n");
		if( va_cmd(PTMCTL, 1, 1, "set_sys") )
			goto ptmfail;
		if( va_cmd(PTMCTL, 3, 1, "set_hw", "bonding", "2") )
			goto ptmfail;
	} else {
		printf("PTM Non-Bonding Mode!\n");
		if( va_cmd(PTMCTL, 1, 1, "set_hw") )
			goto ptmfail;
	}

	//default fast path
	if( va_cmd(PTMCTL, 3, 1, "set_qmap", "7", "44444444") )
		goto ptmfail;

	ret=0;
ptmfail:
	return ret;
}

#if defined(CONFIG_USER_XDSL_SLAVE)
int startSlvPTM(void)
{
	int ret=-1;
	if (WAN_MODE & MODE_BOND){
		printf("PTM Bonding Mode!\n");
		if( va_cmd(PTMCTL, 3, 1, "-d", "/dev/ptm1", "set_sys") )
			goto ptmfail;
		if( va_cmd(PTMCTL, 5, 1, "-d", "/dev/ptm1", "set_hw", "bonding", "2") )
			goto ptmfail;
	} else {
		if( va_cmd(PTMCTL, 3, 1, "-d", "/dev/ptm1", "set_hw") )
			goto ptmfail;
	}

	//default fast path
	if( va_cmd(PTMCTL, 5, 1, "-d", "/dev/ptm1", "set_qmap", "7", "44444444") )
		goto ptmfail;

	ret=0;
ptmfail:
	return ret;
}
#endif /*CONFIG_USER_XDSL_SLAVE*/
#endif /*CONFIG_RTL8685_PTM_MII*/

#if defined(CONFIG_EPON_FEATURE)
int startEPON(void)
{
	int entryNum=4;
	unsigned int totalEntry;
	int index;
	int retVal;
	MIB_CE_MIB_EPON_LLID_T mib_llidEntry;
	rtk_epon_llid_entry_t llid_entry;
	char loid[100]={0};
	char passwd[100]={0};
	char oamcli_cmd[128]={0};

#if defined(CONFIG_RTK_L34_ENABLE)
	retVal = rtk_rg_epon_llidEntryNum_get(&entryNum);
	if(retVal != RT_ERR_OK)
		printf("%s-%d rtk_rg_epon_llidEntryNum_get error %d\n",__func__,__LINE__,retVal);
#else
	rtk_epon_llidEntryNum_get(&entryNum);
#endif
#if 0//QL LOID/LOID_PASSWD will be fetched from mib table by eponoamd, so dont set it again
#ifndef CONFIG_RTK_OAM_V1//martin zhu-2015.11.17---boa will set loid and passward in notify_eponoamd
	if(!mib_get(MIB_LOID, (void *)loid))
	{
		printf("Get EPON LOID Failed\n");
	}

	if(!mib_get(MIB_LOID_PASSWD,  (void *)passwd))
	{
		printf("Get EPON LOID Password Failed\n");
	}


	for(index=0;index<entryNum;index++)
	{
		sprintf(oamcli_cmd, "/bin/oamcli set ctc loid %d %s %s", index, loid,passwd);
		system(oamcli_cmd);
	}
#endif	//end of martin zhu-2015.11.7
#endif

	totalEntry = mib_chain_total(MIB_EPON_LLID_TBL); /* get chain record size */
	if(totalEntry == 0)
	{
		//First time to boot, the mib chain of LLID MAC table is empty.
		//need to create entry according to the LLID numbers chip supported.
		unsigned char mac[MAC_ADDR_LEN]={0x00,0x11,0x22,0x33,0x44,0x55};
        mib_get(MIB_ELAN_MAC_ADDR, (void *)mac);

		printf("First time to create EPON LLID MIB Table, now create %d entries.\n",entryNum);

		for(index=0;index<entryNum;index++)
		{
			int i;

			memset(&mib_llidEntry,0,sizeof(mib_llidEntry));

			//Add new EPON_LLID_ENTRY into mib chain
			memcpy(mib_llidEntry.macAddr,mac, MAC_ADDR_LEN);
			retVal = mib_chain_add(MIB_EPON_LLID_TBL, (unsigned char*)&mib_llidEntry);
			if (retVal == 0) {
				printf("Error!!!!!! %s:%s\n",__func__,"Error! Add chain record.");
				return -1;
			}
			else if (retVal == -1) {
				printf("Error!!!!!! %s:%s\n",__func__,"Error! Table Full.");
				return -1;
			}
			printf("Add EPON LLID default entry into MIB Table with mac %2x:%2x:%2x:%2x:%2x:%2x Success!\n",
					mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);

			//Now set into driver.
			memset(&llid_entry,0,sizeof(llid_entry));
			llid_entry.llidIdx = index;
#if defined(CONFIG_RTK_L34_ENABLE)
			rtk_rg_epon_llid_entry_get(&llid_entry);
#else
			rtk_epon_llid_entry_get(&llid_entry);
#endif
			for(i=0;i<MAC_ADDR_LEN;i++)
				llid_entry.mac.octet[i] = (unsigned char) mac[i];
#if defined(CONFIG_RTK_L34_ENABLE)
			rtk_rg_epon_llid_entry_set(&llid_entry);
#else
			rtk_epon_llid_entry_set(&llid_entry);
#endif
			mac[5]++;
		}

#ifdef COMMIT_IMMEDIATELY
		Commit();
#endif

	}
	else
	{
		if(totalEntry!= entryNum)
		{
			printf("Error! %s: Chip support LLID entry %d is not the same ad MIB entries nubmer %d\n",
				__func__,entryNum, totalEntry);
			return -1;
		}

		//EPON_LLID MIB Table is not empty, read from it and set to driver
		for(index=0;index<totalEntry;index++)
		{
			int i;
			if (mib_chain_get(MIB_EPON_LLID_TBL, index, (void *)&mib_llidEntry))
			{
				memset(&llid_entry,0,sizeof(llid_entry));
				llid_entry.llidIdx = index;
#if defined(CONFIG_RTK_L34_ENABLE)
				rtk_rg_epon_llid_entry_get(&llid_entry);
#else
				rtk_epon_llid_entry_get(&llid_entry);
#endif
				for(i=0;i<MAC_ADDR_LEN;i++)
					llid_entry.mac.octet[i] = (unsigned char) mib_llidEntry.macAddr[i];
#if defined(CONFIG_RTK_L34_ENABLE)
				rtk_rg_epon_llid_entry_set(&llid_entry);
#else
				rtk_epon_llid_entry_set(&llid_entry);
#endif
			}
			else
			{
				printf("Error: %s mib chain get error for index %d\n",__func__,index);
			}
		}
	}

	config_oam_vlancfg();
	
	return 0;

}
#endif

#if defined(CONFIG_GPON_FEATURE) || defined(CONFIG_EPON_FEATURE)
int startPON(void)
{
	unsigned int pon_mode;
	unsigned int pon_led_spec_type;
	int ret;

	if (mib_get(MIB_PON_MODE, (void *)&pon_mode) != 0)
	{
		if (pon_mode == EPON_MODE)
		{
#if defined(CONFIG_EPON_FEATURE)
			printf("set config for EPON\n");
			startEPON();
#endif
		}
#if defined(CONFIG_GPON_FEATURE) && defined(CONFIG_TR142_MODULE)
		else if(pon_mode==GPON_MODE)
		{
			set_wan_ponmac_qos_queue_num();
		}
#endif
	}

	if(mib_get(MIB_PON_LED_SPEC, (void *)&pon_led_spec_type) != 0){
		if((ret = rtk_pon_led_SpecType_set(pon_led_spec_type)) != 0)
			printf("rtk_pon_led_SpecType_set failed, ret = %d\n", ret);
		else
			printf("rtk_pon_led_SpecType_set %d\n", pon_led_spec_type);
	}
	else
		printf("MIB_PON_LED_SPEC get failed\n");
}
#endif


#if defined(CONFIG_USER_JAMVM) && defined (CONFIG_APACHE_FELIX_FRAMEWORK)
int startOsgi(void)
{
	FILE *fp_blist = NULL;
	FILE *fp_cnt = NULL;
	MIB_CE_OSGI_BUNDLE_T entry;
	int entry_cnt;
	int bundle_cnt;
	int idx, i , ignore;
	char osgi_cmd[512];
	char *ignore_bundle[] =
	{
		"System Bundle",
		"RealtekTCPSocketListener",
		"Apache Felix Bundle Repository",
		"Apache Felix Gogo Command",
		"Apache Felix Gogo Runtime",
		"Apache Felix Gogo Shell",
		"osgi.cmpn",
		"Apache Felix Declarative Services",
		"Apache Felix Http Jetty"
	};

	snprintf(osgi_cmd,512, "ls /usr/local/class/felix/bundle/*.jar | wc -l > /tmp/bundle_cnt\n");
	system(osgi_cmd);


	if (!(fp_cnt=fopen("/tmp/bundle_cnt", "r")))
	{
		return 0;
	}

	fscanf(fp_cnt, "%d\n", &bundle_cnt);

	if (!(fp_blist=fopen("/tmp/OSGI_STARTUP", "w")))
	{
		return 0;
	}

	entry_cnt = mib_chain_total(MIB_OSGI_BUNDLE_TBL);

	for(idx = 0 ; idx < entry_cnt; idx++)
	{
		if (!mib_chain_get(MIB_OSGI_BUNDLE_TBL, idx, (void *)&entry))
		{
			fclose(fp_blist);
			return 0;
		}
		for(i = 0 ; i < sizeof(ignore_bundle) / sizeof(ignore_bundle[0]); i++)
		{
			if(strcmp(ignore_bundle[i] , entry.bundle_name) == 0 )
			{
				ignore = 1;
				break;
			}
		}
		if(ignore == 1)
		{
			ignore = 0;
			continue;
		}
		else // write file
		{
			fprintf(fp_blist, "/var/config_osgi/%s,%d,%d\n", entry.bundle_file, entry.bundle_action,++bundle_cnt);
		}
	}

	unlink("/tmp/bundle_cnt");
	fclose(fp_blist);
	fclose(fp_cnt);

	return 1;
}
#endif

#if defined(WLAN_SUPPORT) && (defined(CONFIG_E8B) || defined(CONFIG_00R0))
//static char wifi_base64chars[64] = "abcdefghijklmnopqrstuvwxyz"
//                             "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./";

//remove 0/o/O, B/8, 1/l/I
static char wifi_base64chars[64] = "abcdefghijkmmnppqrstuvwxyz"
                              "ACCDEFGHJJKLMNPPQRSTUVWXYZZ223456799ab";

/*
 * Name: wifi_base64encode()
 *
 * Description: Encodes a buffer using BASE64.
 */
void wifi_base64encode(unsigned char *from, char *to, int len)
{
  while (len) {
    unsigned long k;
    int c;

    c = (len < 3) ? len : 3;
    k = 0;
    len -= c;
    while (c--)
      k = (k << 8) | *from++;
    *to++ = wifi_base64chars[ (k >> 18) & 0x3f ];
    *to++ = wifi_base64chars[ (k >> 12) & 0x3f ];
    *to++ = wifi_base64chars[ (k >> 6) & 0x3f ];
    *to++ = wifi_base64chars[ k & 0x3f ];
  }
  *to++ = 0;
}
void str_calculate(char *pass, char *passMD5, int len)
{
	char temps[0x100],*pwd;
	struct MD5Context mc;
 	unsigned char final[16];
	char encoded_passwd[0x40];
	//char *pass="user";
	int i;

  	/* Encode password ('pass') using one-way function and then use base64
	 encoding. */

	MD5Init(&mc);
	{

	//printf("calPasswdMD5: pass=%s\n", pass);
	MD5Update(&mc, pass, strlen(pass));
	}
	MD5Final(final, &mc);

	//strcpy(encoded_passwd,"$1$");
	wifi_base64encode(final, encoded_passwd, 16);
    //printf("encoded_passwd=%s for %s!!!!!!!!!!!!!\n",encoded_passwd, pass);

    strncpy(passMD5, encoded_passwd,len);
    passMD5[len]=0;

}

#if defined(WLAN_WPA) && defined(CONFIG_00R0)
int checkDefaultWPAKey(void)
{
	int status=0,i;
	char str_buf[256], cal_wpa_key[256], current_wpa_key[256];
	char str_cmd[256];
	MIB_CE_MBSSIB_T Entry;
	wlan_getEntry(&Entry, 0);

	if(!mib_get( MIB_HW_SERIAL_NUMBER,  (void *)str_buf)){
		return -1;
	}

	str_calculate(str_buf,cal_wpa_key, 20);

	//save default wpa key to file
	//sprintf(str_cmd,"echo %s>/var/wpakey",cal_wpa_key);
	//system(str_cmd);

	//if(!mib_get(MIB_WLAN_WPA_PSK, (void *)current_wpa_key)){
	//	return -1;
	//}

	if((!strcmp(Entry.wpaPSK,"0"))){
		//mib_set(MIB_WLAN_WPA_PSK, (void *)cal_wpa_key);
		strcpy(Entry.wpaPSK, cal_wpa_key);
		wlan_setEntry(&Entry, 0);
		mib_update(CURRENT_SETTING, CONFIG_MIB_ALL);
		update_wps_configured(0);
	}

	return status;
}
#endif
#endif

#if defined(WLAN_SUPPORT)

int checkDefaultSSID(void)
{
	int status=0;
	MIB_CE_MBSSIB_T Entry;
	unsigned char default_ssid[MAX_NAME_LEN];
	
	wlan_getEntry(&Entry, 0);
	
	mib_get(MIB_DEFAULT_WLAN_SSID, (void *)default_ssid);
		
	if(!strcmp(Entry.ssid,"0") && strlen(default_ssid) > 0){
		strcpy(Entry.ssid, default_ssid);
         printf("set default SSID %s\n",default_ssid);
         wlan_setEntry(&Entry, 0);
         mib_update(CURRENT_SETTING, CONFIG_MIB_ALL);
		
	}
	
	return status;
}
#endif

#ifdef CONFIG_TR142_MODULE
static void clear_wan_created_by_omci()
{
	int total, i;
	MIB_CE_ATM_VC_T entry;

	total = mib_chain_total(MIB_ATM_VC_TBL);

	for(i = total -1 ; i >= 0 ; i--)
	{
		if(mib_chain_get(MIB_ATM_VC_TBL, i, &entry)== 0)
			continue;

		if(entry.omci_configured == 1)
			mib_chain_delete(MIB_ATM_VC_TBL, i);
	}
}
#endif

int main(int argc, char *argv[])
{
	unsigned char value[32];
	int vInt;
#if defined(CONFIG_USER_SNMPD_SNMPD_V2CTRAP) || defined(CONFIG_USER_SNMPD_SNMPD_V3)
	int snmpd_pid;
#endif
	FILE *fp = NULL;
	int i;
#ifdef TIME_ZONE
	int my_pid;
#endif
#if defined(WLAN_SUPPORT)
	char wlan_failed = 0;
#endif
#ifdef CONFIG_USER_DHCPCLIENT_MODE
	unsigned char cur_vChar;
#endif

#if defined(CONFIG_RTL9600_SERIES) && defined(CONFIG_RTK_L34_ENABLE)
	if (argc==2 && !strcmp(argv[1], "RG")) {
		Init_rg_api();		
		restartOMCI();		
		clearAllRGAclFile();
		stopELan();
		startup_RG();
		return 0;
	}
#endif

	// set debug mode
	DEBUGMODE(STA_INFO|STA_SCRIPT|STA_WARNING|STA_ERR);
#ifdef CONFIG_KEEP_BOOTCODE_CONFIG
	bootconf_updatemib();
#endif /*CONFIG_KEEP_BOOTCODE_CONFIG*/

#if ! defined(_LINUX_2_6_) && defined(CONFIG_RTL_MULTI_WAN)
	initWANMode();
#endif

#if defined(CONFIG_DSL_ON_SLAVE)
	system("/bin/adslctrl InitSAR 1");
	printf("/bin/adslctrl InitSAR 1\n");
	sleep(1);
	system("/bin/adslctrl InitPTM 1");
	printf("/bin/adslctrl InitPTM 1\n");
	sleep(1);
#endif
	if (sys_setup() == -1)
		goto startup_fail;

#ifdef CONFIG_INIT_SCRIPTS
	printf("========== Initiating Starting Script =============\n");
	system("sh /var/config/start_script");
	printf("========== End Initiating Starting Script =============\n");
#endif

#if defined(CONFIG_LUNA) && defined(CONFIG_RTK_L34_ENABLE)
//	Init_RTK_RG_Device();
#endif
#ifdef CONFIG_USER_RTK_SYSLOG
	if(-1==startLog())
		goto startup_fail;
#endif
	if (-1==startELan())
		printf("startELan fail, plz check!\n");
#if defined(CONFIG_LUNA) && !defined(CONFIG_RTK_L34_ENABLE)
#if defined(CONFIG_RTL_MULTI_LAN_DEV) && defined(CONFIG_RTL8686) && !defined(CONFIG_RTK_L34_ENABLE)
	//without RG, default let switch forward packet.
	system("/bin/echo normal > /proc/rtl8686gmac/switch_mode");
#endif
#endif

//cxy 2016-6-21: this will cause ip range acl rule permit to be trap(hw not support any range ip acl rule)
#if 0//defined(CONFIG_LUNA) && defined(CONFIG_RTK_L34_ENABLE)
	//cxy 2015-1-13: enable ip range acl filter for any range not only ip/mask format
	system("echo 1 > /proc/rg/acl_drop_ip_range_rule_handle_by_sw");
	system("echo 1 > /proc/rg/acl_permit_ip_range_rule_handle_by_sw");
	//end of cxy 2015-1-13
#endif

	// check INIT_SCRIPT
	if (mib_get(MIB_INIT_SCRIPT, (void *)value) != 0)
	{
		vInt = (int)(*(unsigned char *)value);
	}
	else
		vInt = 1;

#if defined(CONFIG_USER_LAN_PORT_AS_ETH_WAN)
	int ethPhyPortId = -1;
	mib_get(MIB_ETH_WAN_PORT_PHY_INDEX, &ethPhyPortId);
#endif

	if (vInt == 0)
	{
		 for(i=0;i<ELANVIF_NUM;i++){
#if defined(CONFIG_RTK_L34_ENABLE) && defined(CONFIG_USER_LAN_PORT_AS_ETH_WAN)
			int portid = RG_get_lan_phyPortId(i);
			if (portid != -1 && portid == ethPhyPortId)
				 continue;
#endif
			va_cmd(IFCONFIG, 2, 1, ELANVIF[i], "up");
		}
#if defined(CONFIG_RTL8681_PTM)
		va_cmd(IFCONFIG, 2, 1, PTMIF, "up");
#endif
#ifdef CONFIG_USB_ETH
		va_cmd(IFCONFIG, 2, 1, USBETHIF, "up");
#endif //CONFIG_USB_ETH
		va_cmd(WEBSERVER, 0, 0);
		return 0;	// stop here
	}
#if defined(WLAN_SUPPORT) && defined(CONFIG_RTK_L34_ENABLE) && defined(CONFIG_RTL_MULTI_LAN_DEV)
	va_cmd(IFCONFIG, 2, 1, ELANIF, "up");
#endif

#if defined(WLAN_SUPPORT) && defined(CONFIG_RTL_MULTI_LAN_DEV) && defined(CONFIG_ARCH_RTL8198F)
	va_cmd(IFCONFIG, 2, 1, ELANIF, "up");
#endif

#ifdef CONFIG_TR142_MODULE
	clear_wan_created_by_omci();
#endif

#ifdef E8B_NEW_DIAGNOSE
	fp = fopen(INFORM_STATUS_FILE, "w");
	if (fp) {
		fprintf(fp, "%d:%s", NO_INFORM, E8B_START_STR);
		fclose(fp);
	}
#endif

	if (-1==startDaemon())
		goto startup_fail;

	//root interface should be up first
#ifndef CONFIG_RTL_MULTI_LAN_DEV
	if (va_cmd(IFCONFIG, 2, 1, ELANIF, "up"))
		goto startup_fail;
#endif
#ifdef CONFIG_DEV_xDSL
	// Create in ra8670.c, dsl link status
	va_cmd(IFCONFIG, 2, 1, "atm0", "up");
#ifdef CONFIG_USER_CMD_CLIENT_SIDE
	// Create in rtk_atm.c, ptm link status
	va_cmd(IFCONFIG, 2, 1, "ptm0", "up");
#endif
#endif

#ifdef CONFIG_USER_CMD_CLIENT_SIDE
	dsl_msg_set(SetDslBond, (WAN_MODE & MODE_BOND));
#else
#ifdef CONFIG_RTL8685_PTM_MII
	if( startPTM()<0 )
		goto startup_fail;

#if defined(CONFIG_USER_XDSL_SLAVE)
	if( startSlvPTM()<0 )
		goto startup_fail;
#endif /*CONFIG_USER_XDSL_SLAVE*/

#endif /*CONFIG_RTL8685_PTM_MII*/
#endif

#if defined(CONFIG_GPON_FEATURE) || defined(CONFIG_EPON_FEATURE)
	if( startPON()<0 )
		goto startup_fail;
#endif

#ifdef PORT_FORWARD_GENERAL
	clear_dynamic_port_fw(NULL);
#endif
	// start WAN interface ...
#if defined(CONFIG_LUNA) && defined(CONFIG_RTK_L34_ENABLE)
	Init_RG_ELan(UntagCPort, RoutingWan);
#endif

#if defined(CONFIG_LUNA) && defined(CONFIG_RTK_L34_ENABLE)
	//check default route before start WAN to avoid droute is missed.
	RG_check_Droute(0,NULL,NULL);
	RG_reset_static_route();
#endif

#if defined(CONFIG_USER_BRIDGE_GROUPING) && defined(CONFIG_LUNA) && defined(CONFIG_RTK_L34_ENABLE) // Rostelecom, Port Binding function
	unsigned int set_wanlist = 0;
	set_port_binding_mask(&set_wanlist);
#endif

#if defined(CONFIG_XDSL_CTRL_PHY_IS_SOC)
	for(i=0;i<ELANVIF_NUM;i++){
		if(va_cmd(IFCONFIG, 2, 1, ELANVIF[i], "up")){
			goto startup_fail;
		}
	}
	if (-1==startWan(CONFIGALL, NULL))
		goto startup_fail;
#if defined(CONFIG_RTL9607C) || defined(CONFIG_RTL8686)
	setupUniPortCapability();
#endif
#else
	if (-1==startWan(CONFIGALL, NULL))
		goto startup_fail;

	for(i=0;i<ELANVIF_NUM;i++){
#if defined(CONFIG_RTK_L34_ENABLE) && defined(CONFIG_USER_LAN_PORT_AS_ETH_WAN)
		int portid = RG_get_lan_phyPortId(i);
		if (portid != -1 && portid == ethPhyPortId)
			continue;
#endif
		if(va_cmd(IFCONFIG, 2, 1, ELANVIF[i], "up")){
			goto startup_fail;
		}
	}
#endif

// commserver should run after wan setting
#ifdef CONFIG_USER_CMD_CLIENT_SIDE
	/* it should enable switch before launch commserver */
	#ifdef CONFIG_SWITCH_INIT_LINKDOWN
	system("/bin/diag port set phy-force-power-down port all state disable");
	#endif

	if(va_cmd("/bin/ethctl", 3, 1, "ignsmux", "add", "0x8899"))
		goto startup_fail;
	if(va_cmd("/bin/ethctl", 3, 1, "ignsmux", "add", "0x884c"))
		goto startup_fail;

	if(va_cmd(CMDSERV_CTRLERD, 2, 0, "-i", CMD_CLIENT_MONITOR_INTF))
		goto startup_fail;

	sleep(4); // waiting DUT create commserv connection
#endif
#ifdef CONFIG_USER_CMD_SERVER_SIDE
	if(va_cmd(CMDSERV_ENDPTD, 4, 0, "-i", CMD_SERVER_MONITOR_INTF, "-c", "0"))
		goto startup_fail;

	sleep(4); // waiting DUT create commserv connection
#endif
#ifdef CONFIG_E8B
	 // Set MAC filter
#ifndef MAC_FILTER_SRC_ONLY
	setupMacFilterEbtables();
#endif
	setupMacFilterTables();
#endif
#ifdef CONFIG_USER_VLAN_ON_LAN
	setup_VLANonLAN(ADD_RULE);
#endif
#ifdef CONFIG_USER_BRIDGE_GROUPING
	setup_bridge_grouping(ADD_RULE);
#endif

    /*
     * 2012/8/15
     * Since now eth0.2~5 are up, change NS number to default number 1.
     */
	unsigned char val[64];
	snprintf(val, 64, "/bin/echo 1 > /proc/sys/net/ipv6/conf/%s/dad_transmits", (char*)BRIF);
	system(val);

#if defined(CONFIG_RTL8681_PTM)
	if (va_cmd(IFCONFIG, 2, 1, PTMIF, "up"))
		goto startup_fail;
#endif
#ifdef CONFIG_USB_ETH
	if (va_cmd(IFCONFIG, 2, 1, USBETHIF, "up"))
		goto startup_fail;
#endif //CONFIG_USB_ETH

	// restart USB to trigger hotplug add uevent
	/*  this method should enable "find" feature in busybox
	**  sd[a-z][0-9],sr[0-9],*lp[0-9] should same with mdev.conf
	 */
	system("find /sys/devices/platform -type d -name sd[a-z] -exec sh -c 'echo \"add\" >> \"$0\"/uevent' {} \\;");
	system("find /sys/devices/platform -type d -name sd[a-z][0-9] -exec sh -c 'echo \"add\" >> \"$0\"/uevent' {} \\;");	//for partition device
	system("find /sys/devices/platform -type d -name sr[0-9] -exec sh -c 'echo \"add\" >> \"$0\"/uevent' {} \\;");
	system("find /sys/devices/platform -type d -name *lp[0-9] -exec sh -c 'echo \"add\" >> \"$0\"/uevent' {} \\;");
//#ifndef CONFIG_ETHWAN
#ifdef CONFIG_DEV_xDSL
	if (-1==startDsl())
		goto startup_fail;
#endif

#ifdef ELAN_LINK_MODE_INTRENAL_PHY
	setupLinkMode_internalPHY();
#endif

#if	defined(CONFIG_LUNA_DUAL_LINUX)
	setup_vwlan();
#endif


#ifdef WLAN_SUPPORT
//#if defined(CONFIG_E8B) || defined(CONFIG_00R0)
#if 1
	//check default SSID and WPA key
	int orig_wlan_idx;
	orig_wlan_idx = wlan_idx;

	//process each wlan interface
	for(i = 0; i<NUM_WLAN_INTERFACE; i++){
		wlan_idx = i;
		if (!getInFlags((char *)getWlanIfName(), 0)) {
			printf("Wireless Interface Not Found !\n");
			continue;
	    }

#ifdef CONFIG_00R0
		checkDefaultSSID(NUM_WLAN_INTERFACE);
#else
		checkDefaultSSID();
#endif
#if defined(WLAN_WPA) && defined(CONFIG_00R0)
		checkDefaultWPAKey();
#endif
	}
	wlan_idx = orig_wlan_idx;
	//check default SSID and WPA key end

	//if (-1==startWLan())
	//	goto startup_fail;
	wlan_failed = startWLan();
#else
	//if (-1==startWLan())
	//	goto startup_fail;
	startWLan();
#endif
#ifdef WLAN_QTN
	if(ping_qtn_check()==0)
		startWLan_qtn();
#endif
#endif


#if (defined(CONFIG_RTL867X_NETLOG)  && defined (CONFIG_USER_NETLOGGER_SUPPORT))
        va_cmd(NETLOGGER,0,1);
#endif

#ifdef _CWMP_MIB_ /*jiunming, mib for cwmp-tr069*/
	if (-1==startCWMP())
		goto startup_fail;

#ifdef _PRMT_TR143_
	struct TR143_UDPEchoConfig echoconfig;
	UDPEchoConfigSave( &echoconfig );
	UDPEchoConfigStart( &echoconfig );
#endif //_PRMT_TR143_
#endif	//_CWMP_MIB_

	//ql 20081117 START init MIB_QOS_UPRATE before startup IP QoS
#ifdef NEW_IP_QOS_SUPPORT
	unsigned int up_rate=0;
	mib_set(MIB_QOS_UPRATE, (void *)&up_rate);
#endif

#if defined(WLAN_SUPPORT) 
	if(wlan_failed)
		syslog(LOG_ERR, "104012 WLAN start failed.");
#endif	
	if (-1==startRest())
		goto startup_fail;

#ifdef CONFIG_USER_WATCHDOG_WDG
    //start watchdog & kick every 5 seconds silently
	//va_cmd_no_echo("/bin/wdg", 2, 1, "timeout", "10");
	//va_cmd_no_echo("/bin/wdg", 2, 1, "start", "5");
#endif
#if 0
#ifdef CONFIG_USER_PPPOE_PROXY
       va_cmd("/bin/pppoe-server",0,1);
#endif
#endif
	//take effect
#ifdef CONFIG_XFRM
	ipsec_take_effect();
#endif
#ifdef CONFIG_USER_PPTP_CLIENT_PPTP
	pptp_take_effect();
#ifdef CONFIG_USER_PPTPD_PPTPD
	pptpd_take_effect();
#endif
#endif
#ifdef CONFIG_USER_L2TPD_L2TPD
	l2tp_take_effect();
#endif
#ifdef CONFIG_USER_L2TPD_LNS
	l2tpd_take_effect();
#endif
#ifdef CONFIG_NET_IPGRE
	gre_take_effect(0);
#endif

#if defined(CONFIG_LUNA) && defined(CONFIG_RTK_L34_ENABLE)
{
#if defined(CONFIG_IPV6)
	RTK_RG_FLUSH_Route_V6_RA_NS_ACL_FILE();
	RTK_RG_Set_ACL_Route_V6_RA_NS_Filter();	
#endif

#if defined(CONFIG_GPON_FEATURE) || defined(CONFIG_EPON_FEATURE) || defined(CONFIG_FIBER_FEATURE)
	int pon_mode, acl_default=0;
	if (mib_get(MIB_PON_MODE, (void *)&pon_mode) != 0)
	{
#ifdef CONFIG_RTL9602C_SERIES
		acl_default = 1;
#endif
		if ((pon_mode != GPON_MODE) || acl_default == 1)
		{
			RG_del_All_Acl_Rules();
			RG_add_default_Acl_Qos();
		}
	}
#else
	/*use for 8696*/
	RG_del_All_Acl_Rules();
	RG_add_default_Acl_Qos();
#endif
}
#ifndef CONFIG_RTL9600_SERIES
	check_port_based_vlan_of_bridge_inet_wan();
#endif
#endif

//star add: for ZTE LED request
// Kaohj --- TR068 Power LED
	unsigned char power_flag;
	fp = fopen("/proc/power_flag","w");
	if(fp)
	{
		power_flag = '0';
		fwrite(&power_flag,1,1,fp);
		fclose(fp);
	}

//#ifdef _CWMP_MIB_ /*jiunming, mib for cwmp-tr069*/
	/*when those processes created by startup are killed,
	  they will be zombie processes,jiunming*/
	signal(SIGCHLD, SIG_IGN);//add by star
//#endif

#if 1
#if defined(CONFIG_USER_SNMPD_SNMPD_V2CTRAP) || defined(CONFIG_USER_SNMPD_SNMPD_V3)
	// Mason Yu. System init status
	snmpd_pid = read_pid("/var/run/snmpd.pid");
	if (snmpd_pid > 0) {
		printf("Send signal to snmpd.\n");
		kill(snmpd_pid, SIGUSR1);
	}
#endif
#endif

	/*ql: 20081117 START startup qos here*/
#ifndef CONFIG_E8B
#ifdef NEW_IP_QOS_SUPPORT
#ifdef CONFIG_DEV_xDSL
	printf("start monitor QoS!\n");
	while(1)
	{
		signal(SIGCHLD, SIG_DFL);
		monitor_qos_setting();
		signal(SIGCHLD, SIG_IGN);
		usleep(5000000); // wait 5 sec
	}
#endif
#endif
#endif
	/*ql 20081117 END*/
	// Mason Yu. for IPv6
	// remove from startDaemon()
#if 0
	if (startDnsRelay() == -1)
	{
		printf("start DNS relay failed !\n");
	}
#endif
#ifdef CONFIG_USER_FON
	system("mkdir -p /var/spool/cron/crontabs");
	createChilliCronAdmin("/var/spool/cron/crontabs/admin");
	createChilliconf("/var/chilli.conf");
	createFonWhitelist("/tmp/whitelist.dnsmasq");
	startFonsmcd();
	startFonSpot();
#endif
#ifdef CONFIG_INIT_SCRIPTS
	printf("========== Initiating Ending Script =============\n");
	system("sh /var/config/end_script");
	printf("========== End Initiating Ending Script =============\n");
#endif


#if defined(CONFIG_USER_JAMVM) && defined (CONFIG_APACHE_FELIX_FRAMEWORK)
	if(startOsgi() == 0)
		printf("OSGi Start Error!!!\n");
#endif
#ifdef CONFIG_00R0
	int qosEnable = getQosEnable();
	if (qosEnable) { //Enable IPQos workaround , 
		RG_add_IPQos_WorkAround();
	}
#endif

#ifdef TIME_ZONE
	/********************** Important **************************************************
	/  If wan channel is ETHWAN, it will get ip address before system initation finished,
	/  we  kick sntpc to sync the time again
	/********************************************************************************/
	// kick sntpc to sync the time
	my_pid = read_pid(SNTPC_PID);
	if ( my_pid > 0) {
		kill(my_pid, SIGUSR1);
	}
#endif

	#ifdef CONFIG_RPS		
	system("sh /etc/scripts/rps.sh on");	
	#endif 
#ifndef CONFIG_USER_CMD_CLIENT_SIDE	// move to startWan()
	#ifdef CONFIG_SWITCH_INIT_LINKDOWN
	system("/bin/diag port set phy-force-power-down port all state disable");
	#endif
#endif

#ifdef CONFIG_USER_DHCPCLIENT_MODE
	mib_get(MIB_DHCP_MODE, (void *)&cur_vChar);

	//synamic get LAN ip should run after system("/bin/diag port set phy-force-power-down port all state disable");
	if(cur_vChar == DHCP_LAN_CLIENT){
		setupDHCPClient();
	}
#endif

#ifdef CONFIG_TR142_MODULE
	set_dot1p_value_byCF();
#endif
	/** To allow other threads to continue execution, the main thread should
	 ** terminate by calling pthread_exit() rather than exit(3). */
	pthread_exit(NULL);
	//return 0;	// child thread will exit with main thread exit, even child thread detech
startup_fail:
	va_cmd("/bin/boa",0,1);
	printf("System startup failed !\n");
	return -1;
}

