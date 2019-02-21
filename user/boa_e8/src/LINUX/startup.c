/* startup.c - kaohj */
#define _GNU_SOURCE

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
#include <linux/if.h>
#include <net/route.h>
#include <linux/atm.h>
#include <linux/atmdev.h>
#include <crypt.h>
#if __UCLIBC__
//UCLIBC toolchain
#else
#include <execinfo.h>
#endif
#include <signal.h>
#include <sched.h>
#include <pthread.h>
#include <sys/resource.h>

#ifdef EMBED
#include <linux/config.h>
#else
#include "../../../../include/linux/autoconf.h"
#endif
#include "../defs.h"

#include "options.h"
#include "mib.h"
#include "mibtbl.h"
#include "utility.h"
#ifdef WLAN_SUPPORT

#include <linux/wireless.h>

#ifdef CONFIG_E8B
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
#if defined(CONFIG_GPON_FEATURE) || defined(CONFIG_EPON_FEATURE)
#include <rtk_rg_liteRomeDriver.h>
#endif
#else
#if defined(CONFIG_GPON_FEATURE)
#include "rtk/gpon.h"
#endif
#if defined(CONFIG_EPON_FEATURE)
#include "rtk/epon.h"
#endif
#endif

#include "ipv6_info.h"
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>

#ifdef CONFIG_YUEME
#include <sys/stat.h>
#endif
#if defined(CONFIG_RTK_L34_ENABLE) && defined(CONFIG_USER_LAN_PORT_AS_ETH_WAN)
#include <rtk_rg_define.h>
#endif
#ifdef CONFIG_RTK_OMCI_V1
#include <omci_api.h>
#include <gos_type.h>
#endif
int startLANAutoSearch(const char *ipAddr, const char *subnet);
int isDuplicate(struct in_addr *ipAddr, const char *device);

#if __UCLIBC__
//UCLIBC toolchain
#else
void print_trace (void)
{
	void *array[100];
	size_t size;
	char **strings;
	size_t i;

	size = backtrace (array, 100);
	strings = backtrace_symbols (array, size);
	
	if (strings == NULL) {
		perror("backtrace_symbols");
		exit(EXIT_FAILURE);
	}
	printf ("Obtained %zd stack frames.\n", size);

	for (i = 0; i < size; i++){
		printf ("%s\n", strings[i]);
	}

	free (strings);
}

static void pSigHandler(int signo){
    print_trace();
    fflush(stdout);
	signal(signo, SIG_DFL);
    raise(signo);
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
#define ConfigVpnLock "/var/run/configVpnLock"
#define ConfigPmapLock "/var/run/configPmapLock"
#define LanHostPoliceCtrlSetupLock "/var/lanHostPoliceCtrlSetupLock"

#if defined(CONFIG_LUNA) && defined(CONFIG_RTK_L34_ENABLE)
#include "rtusr_rg_api.h"
#endif

int startELan()
{
	unsigned char value[6];
#ifdef WLAN_MBSSID
	unsigned char gen_wlan_mac[MAC_ADDR_LEN];
#endif
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
	FILE *f;
#ifdef CONFIG_RTK_L34_ENABLE
	int portid;
	char sysbuf[128], tmpbuf[128];;
#endif
#if defined(CONFIG_USER_LAN_PORT_AS_ETH_WAN)
	int ethPhyPortId = -1;
	mib_get(MIB_ETH_WAN_PORT_PHY_INDEX, &ethPhyPortId);
#endif


	if (mib_get(MIB_ELAN_MAC_ADDR, (void *)value) != 0)
	{
#ifdef WLAN_SUPPORT
		if((f = fopen(ConfigWlanLock, "w")) == NULL)
			return -1;
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
#if	defined(CONFIG_YUEME) && defined(CONFIG_LUNA_DUAL_LINUX)
		status|=va_cmd(IFCONFIG, 4, 1, "wlan0", "hw", "ether", macaddr);
#else
		status|=va_cmd(IFCONFIG, 4, 1, WLANIF[0], "hw", "ether", macaddr);
#endif

#ifdef WLAN_MBSSID
		// Set macaddr for VAP
		for (i=1; i<=WLAN_MBSSID_NUM; i++) {
			_gen_guest_mac(value, WLAN_MBSSID_NUM+1, i, gen_wlan_mac);

			snprintf(macaddr, 13, "%02x%02x%02x%02x%02x%02x",
				gen_wlan_mac[0], gen_wlan_mac[1], gen_wlan_mac[2], gen_wlan_mac[3], gen_wlan_mac[4], gen_wlan_mac[5]);

			sprintf(para2, "wlan0-vap%d", i-1);

			status|=va_cmd(IFCONFIG, 4, 1, para2, "hw", "ether", macaddr);
		}
#endif
#if defined(CONFIG_RTL_92D_DMDP) || (defined(WLAN_DUALBAND_CONCURRENT) && !defined(CONFIG_LUNA_DUAL_LINUX))
		setup_mac_addr(value, 1);
		snprintf(macaddr, 13, "%02x%02x%02x%02x%02x%02x",
			value[0], value[1], value[2], value[3], value[4], value[5]);
		status|=va_cmd(IFCONFIG, 4, 1, WLANIF[1], "hw", "ether", macaddr);

#ifdef WLAN_MBSSID
		// Set macaddr for VAP
		for (i=1; i<=WLAN_MBSSID_NUM; i++) {
			_gen_guest_mac(value, WLAN_MBSSID_NUM+1, i, gen_wlan_mac);

			snprintf(macaddr, 13, "%02x%02x%02x%02x%02x%02x",
				gen_wlan_mac[0], gen_wlan_mac[1], gen_wlan_mac[2], gen_wlan_mac[3], gen_wlan_mac[4], gen_wlan_mac[5]);

			sprintf(para2, "wlan1-vap%d", i-1);

			status|=va_cmd(IFCONFIG, 4, 1, para2, "hw", "ether", macaddr);
		}
#endif
#endif //CONFIG_RTL_92D_DMDP
#endif // WLAN_SUPPORT
	}

	if((f = fopen(ConfigPmapLock, "w")) == NULL)
		return -1;
	fclose(f);

#if defined(CONFIG_RTK_L34_ENABLE) && (defined(CONFIG_RTL9607C_SERIES) || defined(CONFIG_LUNA_G3_SERIES))
	if((f = fopen(LanHostPoliceCtrlSetupLock, "w")) == NULL)
		return -1;
	fclose(f);
#endif

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

#if defined(CONFIG_CMCC) || defined(CONFIG_CU) || defined(CONFIG_USER_LANNETINFO)	
#define NETDEV_PORT_MAPPING "/var/dev_port_mapping"
	unlink(NETDEV_PORT_MAPPING);
#endif
#ifdef CONFIG_E8B
	setupUniPortCapability();
#endif

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
#if defined(CONFIG_CMCC) || defined(CONFIG_CU) || defined(CONFIG_USER_LANNETINFO) //because the /proc/rtl8686gmac/dev_port_mapping can't read. so record here 
			sprintf(tmpbuf, "echo %s %d >> %s", ELANVIF[i], portid, NETDEV_PORT_MAPPING);
			printf("system(): %s\n", tmpbuf);
			system(tmpbuf);
#endif				
		}
#endif

#ifdef CONFIG_IPV6
		// Disable ipv6 for bridge interface
		setup_disable_ipv6((char*)ELANVIF[i], 1);
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
	unsigned char val[64];
	snprintf(val, 64, "/bin/echo 8 > /proc/sys/net/ipv6/conf/%s/dad_transmits", (char*)BRIF);
	system(val);

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

#if defined(CONFIG_LUNA) && defined(CONFIG_RTK_L34_ENABLE)
	{
//		status|=va_cmd(IFCONFIG, 3, 1, (char*)LANIF,"up", ipaddr);
#if defined(CONFIG_GPON_FEATURE)
		unsigned int pon_mode = 0;
		mib_get(MIB_PON_MODE, &pon_mode);
		if(pon_mode != GPON_MODE) //GPON_MODE run initRGapi before run omci
#endif
			Init_rg_api();
		//Init_RG_ELan(TagCPort, BridgeWan);
		Init_RG_ELan(UntagCPort, RoutingWan);
		RTK_RG_gatewayService_add(); //must add if enable DMZ
	}
#endif

	// get the minumum MRU for all WLAN-side link
	/* marked by Jenny
	vInt = get_min_wan_mru();
	if (vInt==0) */
		vInt = 1500;
	snprintf(value, 6, "%d", vInt);
	// set LAN-side MRU
	status|=va_cmd(IFCONFIG, 6, 1, (char*)LANIF, ipaddr, "netmask", subnet, "mtu", value);

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
				setup_disable_ipv6((char*)LANIF, 0);
			else //ipv4 only
				setup_disable_ipv6((char*)LANIF, 1);
		}
#else
		setup_disable_ipv6((char*)LANIF, 0);
#endif

	if (mib_get(MIB_IPV6_LAN_IP_ADDR, (void *)tmpBuf) != 0)
	{
		char cmdBuf[100]={0};
		sprintf(cmdBuf, "%s/%d", tmpBuf, 64);
		va_cmd(IFCONFIG, 3, 1, LANIF, ARG_ADD, cmdBuf);

		/* Iulian Wu , enable IPv6 forwarding for br0*/
		sprintf(cmdBuf, "echo 1 > /proc/sys/net/ipv6/conf/br0/forwarding", 64);
		system(cmdBuf);
	}
	delOrgLanLinklocalIPv6Address();
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

int startup_RG(void)
{
	unsigned char value[32];
	char vChar=0;
	int vInt;
	int i;

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
		va_niced_cmd(WEBSERVER, 0, 0);
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
#ifdef CONFIG_RTL8672_SAR
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
		//RTK_RG_USER_APP_ACL_Rule_Flush();
		//RTK_RG_USER_APP_ACL_Rule_Set();
	}
#endif

#if defined(CONFIG_LUNA) && defined(CONFIG_RTK_L34_ENABLE)
	Flush_RTK_RG_IPv4_IPv6_Vid_Binding_ACL();
	RTK_RG_Set_IPv4_IPv6_Vid_Binding_ACL();
	RG_del_PPPoE_Acl();
	RG_add_PPPoE_RB_passthrough_Acl();
	//RTK_RG_FLUSH_Bridge_DHCP_ACL_FILE();
	//RTK_RG_Set_ACL_Bridge_DHCP_Filter();
	RTK_RG_add_acl_rule_for_v6_icmp();
#if defined (CONFIG_EPON_FEATURE) || defined(CONFIG_GPON_FEATURE)
#ifdef CONFIG_RTL9600_SERIES
	unsigned int pon_mode;
	mib_get(MIB_PON_MODE, (void *)&pon_mode);
#ifdef CONFIG_EPON_FEATURE
	if(pon_mode == EPON_MODE)
	{	
		Flush_RTK_RG_Bridge_from_Lan_ACL();
		RTK_RG_Set_ACL_Bridge_from_Lan();
	}
#endif
#endif
#endif
//	remove code because wifi throughput not good (packet goto slowpath)
//	if(!check_user_is_registered())
//		enable_http_redirect2register_page(1);

	//RTK_RG_FLUSH_Route_V6_RA_NS_ACL_FILE();
	//RTK_RG_Set_ACL_Route_V6_RA_NS_Filter();
#ifdef CONFIG_RTL9602C_SERIES
	check_port_based_vlan_of_binding_bridge_inet_wan();
#endif
	RTK_RG_AccessWanLimit_Set();
#endif

#if defined(CONFIG_RTK_L34_ENABLE) && defined(CONFIG_LUNA)
	if(startFirewall() == 0)
		printf("Firewall Start Error !!\n");
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
		va_niced_cmd(WEBSERVER, 0, 0);
	}
	*/
	//if (pEntry->snmp !=0) {
		// start snmpd
		// Commented by Mason Yu
		// We use new version
		//va_niced_cmd(SNMPD, 0, 0);
		// Add by Mason Yu for start SnmpV2Trap
#ifdef CONFIG_USER_SNMPD_SNMPD_V2CTRAP
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
int startDaemon(void)
{
	int pppd_fifo_fd=-1;
	int mpoad_fifo_fd=-1;
	int status=0, tmp_status;
	int k;

#ifdef CONFIG_CMCC_IPV6_SECURITY_SUPPORT
	status |= va_cmd(IP6SEC, 0, 0);
#endif


// To start DNSv6Relay, it will refer /proc/net/if_inet6.
// After the IPv6 IP is set, we can start the DNSRelay.
// Remove the following process to main().
#if 1
	if (restart_dnsrelay() == -1)
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
		status|=va_niced_cmd(DHCPD, 1, 0, DHCPD_CONF);
	} else if (tmp_status==-1)
	    status = -1;
#endif
#endif

    // 2012/8/22
    // Move start_dhcpv6 to here because need to set IPv6 Global address
    // faster to pass the IPv6 core ready logo test.

	// Mason Yu.
#if defined(CONFIG_IPV6) && defined (CONFIG_USER_DHCPV6_ISC_DHCP411)
#ifndef SUPPORT_DHCPV6_RELAY
	restartDHCPV6Server();
#endif
#endif

#ifdef CONFIG_PPP
	// start spppd
	status|=va_niced_cmd(SPPPD, 0, 0);

	// check if spppd ready to serve
	//while ((pppd_fifo_fd = open(PPPD_FIFO, O_WRONLY)) == -1)
	for (k=0; k<=100; k++)
	{
		if ((pppd_fifo_fd = open(PPPD_FIFO, O_WRONLY))!=-1)
			break;
		usleep(30000);
	}

	if (pppd_fifo_fd == -1)
		status = -1;
	else
		close(pppd_fifo_fd);
#endif

#ifdef CONFIG_SUPPORT_AUTO_DIAG
#define AUTOSIMU_DAEMON "/bin/autoSimu"

	status|=va_niced_cmd(AUTOSIMU_DAEMON, 0, 0);

#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_DevicePacketLossEnable_
	va_niced_cmd("/bin/autoPing", 0, 0);
#endif

#endif

#ifdef CONFIG_USER_WT_146
#define BFD_DAEMON "/bin/bfdmain"
#define BFD_SERVER_FIFO_NAME "/tmp/bfd_serv_fifo"
{
	int bfdmain_fifo_fd=-1;

	// start bfdmain
	status|=va_niced_cmd(BFD_DAEMON, 0, 0);

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
	status|=va_niced_cmd(WEBSERVER, 0, 0);

#ifdef CONFIG_USER_MONITORD
	status |= va_niced_cmd("/bin/touch", 1, 0, MONITOR_LIST);
#if defined(CONFIG_USER_OPENJDK8) && (defined(CONFIG_CMCC) || defined(CONFIG_CU))
	{
		char buf[128] = {0};
		sprintf(buf, "echo 'osgi_server' > %s", MONITOR_LIST);
		system(buf);
		//sprintf(buf, "echo 'java' > %s", MONITOR_LIST);
		//system(buf);
	}
#endif
	{
		char buf[128] = {0};
		sprintf(buf, "echo 'systemd' >> %s", MONITOR_LIST);
		system(buf);
	}
#if 1
	status |= va_niced_cmd("/bin/monitord", 0, 0);
#else
	// Enable debug message
	status |= va_niced_cmd("/bin/monitord", 1, 0, "-d");
#endif
#endif

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
	va_niced_cmd(SNMPD, 0, 0);
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
		status|=va_niced_cmd(DHCPD, 2, 0, "-S", DHCPD_CONF);
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
	system("/bin/echo 0 > /sys/class/net/br0/bridge/multicast_snooping");

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


#ifndef NEW_PORTMAPPING
// Mason Yu. combine_1p_4p_PortMapping
#if (defined( ITF_GROUP_1P) && defined(ITF_GROUP))
	if (mode&MP_PMAP_MASK)
		setupEth2pvc();
#endif
#endif //NEW_PORTMAPPING

#ifndef CONFIG_KERNEL_4_4_x
	// ioctl for direct bridge mode, jiunming
	{
		unsigned char  drtbr_mode;
		if (mib_get(MIB_DIRECT_BRIDGE_MODE, (void *)&drtbr_mode) != 0)
		{
			__dev_setupDirectBridge( (int) drtbr_mode );
		}
	}
#endif

#ifdef CONFIG_E8B
#ifdef CONFIG_RTK_L34_ENABLE
	RTK_RG_FLUSH_DOS_FILTER_RULE();
#endif
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
#ifdef CONFIG_YUEME
	startNetlink();
#ifdef CONFIG_USER_SAMBA
	startSamba();
	smartHGU_Samba_Initialize();
#endif // CONFIG_USER_SAMBA
#else
#ifdef CONFIG_USER_SAMBA
	startSamba();
#endif // CONFIG_USER_SAMBA
#endif

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
	if (mode == 1)
		va_niced_cmd("/bin/11N_UDPserver", 1, 0, "&");
	#ifdef CONFIG_USER_WIRELESS_MP_MODE
	va_niced_cmd("/bin/11N_UDPserver", 1, 0, "&");
	#endif
#endif

#ifdef CONFIG_USER_Y1731
	Y1731_start(1);
#endif

#if defined(CONFIG_USER_RTK_LBD) && defined(CONFIG_E8B)
	setupLBD();
#endif

#if defined(CONFIG_CMCC_MULTICAST_CROSS_VLAN_SUPPORT) && defined(CONFIG_RTK_L34_ENABLE)
	set_multicast_cross_vlan();
#endif

	return 1;
}

#ifdef CONFIG_USER_SNMPD_SNMPD_V2CTRAP
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

static void check_wan_mac()
{
#if defined(CONFIG_LUNA) && defined(GEN_WAN_MAC)
	//sync wan mac address from ELAN_MAC_ADDR
	int ret=0;
	int i, vcTotal;
	MIB_CE_ATM_VC_T Entry;
	unsigned char macaddr[MAC_ADDR_LEN]={0}, gen_macaddr[MAC_ADDR_LEN]={0};

	mib_get(MIB_ELAN_MAC_ADDR, (void *)macaddr);

	vcTotal = mib_chain_total(MIB_ATM_VC_TBL);

	for (i = 0; i < vcTotal; i++)
	{
		if (!mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&Entry))
				return;

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
		return;

#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif

#endif
}

static void syncLOID()
{
#ifdef _PRMT_X_CT_COM_USERINFO_
        unsigned char loid[MAX_NAME_LEN];
        unsigned char password[MAX_NAME_LEN] = {0};
        unsigned char old_loid[MAX_NAME_LEN];
        unsigned char old_password[MAX_NAME_LEN]= {0};
        int changed = 0;
        unsigned int pon_mode;
        unsigned char reg_type;
        int entryNum =4;
        int index;
        char oamcli_cmd[128]={0};
		unsigned char password_hex[MAX_NAME_LEN]={0};
		unsigned char old_password_hex[MAX_NAME_LEN]={0};
#if defined(CONFIG_GPON_FEATURE) || defined(CONFIG_EPON_FEATURE)
		unsigned char pon_reg_mode=0;
#endif

        mib_get(PROVINCE_DEV_REG_TYPE, &reg_type);
        mib_get(MIB_LOID, loid);
        mib_get(MIB_LOID_OLD, old_loid);
        if(strcmp(loid, old_loid) != 0)
                changed = 1;

        mib_get(MIB_LOID_PASSWD, password);
        mib_get(MIB_LOID_PASSWD_OLD, old_password);
        if(strcmp(password, old_password) != 0)
                changed = 1;

		formatPloamPasswordToHex(password, password_hex);
		formatPloamPasswordToHex(old_password, old_password_hex);
        mib_get(MIB_PON_MODE, (void *)&pon_mode);
#if defined(CONFIG_GPON_FEATURE) || defined(CONFIG_EPON_FEATURE)		
		mib_get(MIB_PON_REG_MODE, (void *) &pon_reg_mode);
		if(pon_reg_mode==1 || pon_reg_mode==2)
		{
			if(reg_type != DEV_REG_TYPE_DEFAULT && strlen(loid)==0 )
				return;
			if(reg_type == DEV_REG_TYPE_DEFAULT && strlen(old_loid)==0 )
				return;
		}
#endif
			
        if(reg_type != DEV_REG_TYPE_DEFAULT)
        {
#if defined(CONFIG_GPON_FEATURE) || defined(CONFIG_EPON_FEATURE)
                if (pon_mode == EPON_MODE)
                {
#if defined(CONFIG_RTK_L34_ENABLE) && !defined(CONFIG_RG_G3_SERIES)
                        rtk_rg_epon_llidEntryNum_get(&entryNum);
#else
                        rtk_epon_llidEntryNum_get(&entryNum);
#endif

                        for(index=0;index<entryNum;index++)
                        {
                                sprintf(oamcli_cmd, "/bin/oamcli set ctc loid %d %s %s", index, loid,password);
                                //printf("%s %s\n", __func__, oamcli_cmd);
                                system(oamcli_cmd);
                                sprintf(oamcli_cmd, "/bin/oamcli trigger register %d", index);
                                //printf("%s %s\n", __func__, oamcli_cmd);
                                system(oamcli_cmd);
                        }
                }
                else if(pon_mode == GPON_MODE)
                {
	                if(strlen(loid))
	                {
	                 	sprintf(oamcli_cmd , "/bin/omcicli set loid %s %s ", loid, password);
	                        //printf("%s %d %s\n", __func__, __LINE__,oamcli_cmd);
	                        system(oamcli_cmd);
	                }
		        PON_OMCI_CMD_T msg;
			memset(&msg, 0, sizeof(msg));
			msg.cmd = PON_OMCI_CMD_LOIDAUTH_GET_RSP;
			if(omci_SendCmdAndGet(&msg) == GOS_OK)
		        	printf("OMCI APP LoID: %s\n", msg.value);
			if(strcmp(msg.value, loid) != 0)
			{
				sprintf(oamcli_cmd , "/bin/omcicli set loid %s %s ", loid, password);
				system(oamcli_cmd);
                        	system("/bin/diag gpon deactivate");
				system("/bin/diag gpon activate init-state o1");
			}
			#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
			system("/bin/diag gpon deactivate");
			memset(oamcli_cmd, 0, 128);
                        sprintf(oamcli_cmd , "/sbin/diag gpon set password-hex %s", password_hex);
			system(oamcli_cmd);
			system("/bin/diag gpon activate init-state o1");
			#endif
                }
#endif
                return;
        }

        if(changed)
        {
                mib_set(MIB_LOID, old_loid);
                mib_set(MIB_LOID_PASSWD, old_password);
#ifdef COMMIT_IMMEDIATELY
                Commit();
#endif
                if (mib_get(MIB_PON_MODE, (void *)&pon_mode) != 0)
                {
#if defined(CONFIG_GPON_FEATURE) || defined(CONFIG_EPON_FEATURE)
                        if (pon_mode == EPON_MODE)
                        {
#if defined(CONFIG_RTK_L34_ENABLE) && !defined(CONFIG_RG_G3_SERIES)
                                rtk_rg_epon_llidEntryNum_get(&entryNum);
#else
                                rtk_epon_llidEntryNum_get(&entryNum);
#endif

                                for(index=0;index<entryNum;index++)
                                {
                                        if(reg_type == DEV_REG_TYPE_DEFAULT)
                                                sprintf(oamcli_cmd, "/bin/oamcli set ctc loid %d %s %s", index, old_loid,old_password);
                                        else
                                                sprintf(oamcli_cmd, "/bin/oamcli set ctc loid %d %s %s", index, loid,password);
                                        //printf("%s %s\n", __func__, oamcli_cmd);
                                        system(oamcli_cmd);
                                        sprintf(oamcli_cmd, "/bin/oamcli trigger register %d", index);
                                        //printf("%s %s\n", __func__, oamcli_cmd);
                                        system(oamcli_cmd);
                                }
                        }
                        else if(pon_mode == GPON_MODE)
                        {
                                if(reg_type == DEV_REG_TYPE_DEFAULT)
                                {
                                	if(strlen(old_loid))
                                	{
                                        sprintf(oamcli_cmd , "/bin/omcicli set loid %s %s ", old_loid, old_password);
                                        //printf("%s %d %s\n", __func__, __LINE__,oamcli_cmd);
                                        system(oamcli_cmd);
                                	}

                                }
                                else
                                {
                                	if(strlen(loid))
                                	{
                                        sprintf(oamcli_cmd , "/bin/omcicli set loid %s %s ", loid, password);
                                        //printf("%s %d %s\n", __func__, __LINE__,oamcli_cmd);
                                        system(oamcli_cmd);
                                	}
                                }
			        PON_OMCI_CMD_T msg;
				memset(&msg, 0, sizeof(msg));
				msg.cmd = PON_OMCI_CMD_LOIDAUTH_GET_RSP;
				if(omci_SendCmdAndGet(&msg) == GOS_OK)
		        		printf("OMCI APP LoID: %s\n", msg.value);
				if(strcmp(msg.value, loid) != 0)
				{
                        		sprintf(oamcli_cmd , "/bin/omcicli set loid %s %s ", loid, password);
	                        	system(oamcli_cmd);
        	                	system("/bin/diag gpon deactivate");
                	        	system("/bin/diag gpon activate init-state o1");
				}
				#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
                                system("/bin/diag gpon deactivate");
				memset(oamcli_cmd, 0, 128);
				if(reg_type == DEV_REG_TYPE_DEFAULT)
                                        sprintf(oamcli_cmd , "/sbin/diag gpon set password-hex %s", old_password_hex);
                                else
                                        sprintf(oamcli_cmd , "/sbin/diag gpon set password-hex %s", password_hex);
				system(oamcli_cmd);
                                system("/bin/diag gpon activate init-state o1");
				#endif
                        }
#endif
                }
        }
#endif
}


static void check_user_password(void)
{
	unsigned char userPass[MAX_NAME_LEN], default_userPass[MAX_NAME_LEN];
	unsigned char changed = 0;
	
	mib_get(MIB_USER_PASSWORD,(void *)userPass );
	if(!strcmp(userPass, "0") || !strcmp(userPass,"useradmin")){
		mib_get(MIB_DEFAULT_USER_PASSWORD, (void *)default_userPass);
		mib_set(MIB_USER_PASSWORD, (void *)default_userPass);
		changed = 1;
	}

#ifdef TELNET_ACCOUNT_INDEPENDENT
	mib_get(MIB_TELNET_USER, userPass);
	if(userPass[0] == '\0')
	{
		mib_get(MIB_HW_TELNET_USER, userPass);
		mib_set(MIB_TELNET_USER, userPass);
		mib_get(MIB_HW_TELNET_PASSWD, userPass);
		mib_set(MIB_TELNET_PASSWD, userPass);
		changed = 1;
	}
#endif

	if(changed)
		Commit();
}

static void check_l2filter(void)
{
	int total = mib_chain_total(MIB_L2FILTER_TBL);
	int i;
	MIB_CE_L2FILTER_T entry;

	if(total >= L2FILTER_ENTRY_NUM)
		return;

	memset(&entry, 0, sizeof(MIB_CE_L2FILTER_T));

	for(i = total ; i < L2FILTER_ENTRY_NUM ; i++)
		mib_chain_add(MIB_L2FILTER_TBL, &entry);
}

#ifdef _PRMT_X_CMCC_LANINTERFACES_
static void check_elan_conf(void)
{
	int total = mib_chain_total(MIB_ELAN_CONF_TBL);
	int i;
	MIB_CE_ELAN_CONF_T entry;

	if(total >= CONFIG_LAN_PORT_NUM)
		return;

	memset(&entry, 0, sizeof(MIB_CE_ELAN_CONF_T));

	for(i = total ; i < CONFIG_LAN_PORT_NUM ; i++)
		mib_chain_add(MIB_ELAN_CONF_TBL, &entry);
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
	unsigned char enable=0; 
#ifdef ACCOUNT_CONFIG
	MIB_CE_ACCOUNT_CONFIG_T entry;
	unsigned int totalEntry;
#endif
	unsigned char province_sichuan_e8c_backdoor_enable = 0;
	mib_get(PROVINCE_SICHUAN_E8C_BACKDOOR_ENABLE, (void *)&province_sichuan_e8c_backdoor_enable);

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
		fclose(fp);
		unlink(FLASH_CHECK_FAIL);
		va_cmd("/bin/loadconfig", 2, 1, "-f", OLD_SETTING_FILE);
	}
#endif

#ifdef _PRMT_USBRESTORE
	usbRestore();
#endif

#ifdef _PRMT_X_CMCC_LANINTERFACES_
	check_l2filter();
	check_elan_conf();
#endif

	//----------------
	// Mason Yu
#ifdef CONFIG_USER_SNMPD_SNMPD_V2CTRAP
	getSnmpConfig();
#endif
	check_user_password();
	// ftpd: /etc/passwd & /tmp (as home dir)
	fp = fopen("/var/passwd", "w+");
#ifdef ACCOUNT_CONFIG
	totalEntry = mib_chain_total(MIB_ACCOUNT_CONFIG_TBL); /* get chain record size */
	for (i=0; i<totalEntry; i++) {
		if (!mib_chain_get(MIB_ACCOUNT_CONFIG_TBL, i, (void *)&entry)) {
			printf("ERROR: Get account configuration information from MIB database failed.\n");
			fclose(fp);
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

	// Added by Mason Yu for others user
#if !defined(CONFIG_CMCC) && !defined(CONFIG_CU)
	mib_get( MIB_SUPER_NAME, (void *)userName );
	mib_get( MIB_SUPER_PASSWORD, (void *)userPass );
	xpass = crypt(userPass, "$1$");
	if (xpass)
		fprintf(fp, "%s:%s:0:0::%s:%s\n", userName, xpass, PW_HOME_DIR, PW_CMD_SHELL);
#endif	
#if (!defined(CONFIG_CMCC) && !defined(CONFIG_CU)) || defined(CONFIG_CMCC_BACKDOOR)
	if(province_sichuan_e8c_backdoor_enable)
	{
		mib_get( MIB_HW_E8BDUSER_NAME, (void *)userName );
		if(userName[0] == '\0')
		{
			mib_get( MIB_E8BDUSER_NAME, (void *)userName );
			mib_get( MIB_E8BDUSER_PASSWORD, (void *)userPass );
		}
		else
			mib_get( MIB_HW_E8BDUSER_PASSWORD, (void *)userPass );

		xpass = crypt(userPass, "$1$");
		if (xpass)
			fprintf(fp, "%s:%s:0:0::%s:%s\n", userName, xpass, PW_HOME_DIR, PW_CMD_SHELL);
	}
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
#if !defined(CONFIG_CMCC) && !defined(CONFIG_CU)		
			fprintf(fp, "%s:%s:1:0::%s:%s\n", userName, xpass, PW_HOME_DIR, PW_CMD_SHELL);
#else
			fprintf(fp, "%s:%s:1:0::/tmp:/dev/null\n", userName, xpass);
#endif
	}
#ifdef CONFIG_USER_DBUS
	fprintf(fp, "%s:%s:0:0:root:%s:%s\n", "root", "x", PW_HOME_DIR, PW_CMD_SHELL);
#endif
	fclose(fp);

#ifdef CONFIG_USER_LXC
	fp = fopen("/var/group" , "a");
	if(fp)
	{
		fprintf(fp , "telecomadmin:x:0:telecomadmin\n");
		fprintf(fp , "root:x:0:root\n");
		fclose(fp);
	}
#endif

#ifdef CONFIG_USER_DBUS
	struct stat sb;
    	if (stat("/opt/upt/apps/etc/dbus-1/system.conf", &sb) == -1)
	{
        	printf("*** DBUS: USE default system.conf *** \n");
        	system("cp /etc/dbus-1/system.conf.def /opt/upt/apps/etc/dbus-1/system.conf");
	}
	va_niced_cmd("/usr/sbin/dbus-daemon", 1, 0, "--system");
#endif


	chmod(PW_HOME_DIR, 0x1fd);	// let owner and group have write access
	// Kaohj --- force kernel(linux-2.6) igmp version to 2
#if defined(_LINUX_2_6_) || defined(CONFIG_CMCC) || defined(CONFIG_CU)
#ifdef FORCE_IGMP_V2
	fp = fopen((const char *)PROC_FORCE_IGMP_VERSION,"w");
	if(fp)
	{
		fprintf(fp, "%d", 2);
		fclose(fp);
	}
#endif
#endif

#ifdef CONFIG_MULTI_FTPD_ACCOUNT
	ftpd_account_change();
#endif
#ifdef CONFIG_MULTI_SMBD_ACCOUNT
	smbd_account_change();
#endif

#ifdef CONFIG_YUEME
	smartHGU_ftpserver_init_api();
#endif
	check_wan_mac();

	syncLOID();
#ifdef _PRMT_X_CT_COM_ALARM_MONITOR_
	init_alarm_numbers();
#endif

#ifdef CONFIG_TR142_MODULE
	clear_wan_created_by_omci();
#endif

	mib_get( PROVINCE_GPON_FAKE_RANGING, (void *)&enable );
	if(enable)
	{
		if( va_cmd("/sbin/diag", 4, 1, "reg", "set", "0x705018", "0xcc19"))
			fprintf(stderr,"diag reg set failed...\n");
		if( va_cmd("/sbin/diag", 4, 1, "reg", "set","0x705040", "0x9032"))
			fprintf(stderr,"diag reg set failed...\n");
	}	

	return ret;
}


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
	unsigned char reg_type;

#if defined(CONFIG_RTK_L34_ENABLE) && !defined(CONFIG_RG_G3_SERIES)
	rtk_rg_epon_llidEntryNum_get(&entryNum);
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
				printf("Error!!!!!! %s:%s\n",__func__,Tadd_chain_error);
				return -1;
			}
			else if (retVal == -1) {
				printf("Error!!!!!! %s:%s\n",__func__,strTableFull);
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

	//set pon led show style(0: pon led down, 1: pon led blink) when epon oam is in silent mode
	mib_get(PROVINCE_DEV_REG_TYPE, &reg_type);
	if(reg_type == DEV_REG_TYPE_AH)
	{
		sprintf(oamcli_cmd, "/bin/oamcli set ctc ponLedInSilent 1");
		system(oamcli_cmd);
	}

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


#if defined(WLAN_SUPPORT) && defined(CONFIG_E8B)
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
#ifdef WLAN_WPA
int checkDefaultWPAKey(void)
{
	int status=0,i;
	char str_buf[256], cal_wpa_key[256], current_wpa_key[256];
	char str_cmd[256];
	MIB_CE_MBSSIB_T Entry;
	unsigned char default_wpakey[MAX_NAME_LEN];

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
	/*
	if((!strcmp(Entry.wpaPSK,"0"))){
		//mib_set(MIB_WLAN_WPA_PSK, (void *)cal_wpa_key);
		strcpy(Entry.wpaPSK, cal_wpa_key);
		wlan_setEntry(&Entry, 0);
		mib_update(CURRENT_SETTING, CONFIG_MIB_ALL);
		update_wps_configured(0);
	}
	*/
	mib_get(MIB_DEFAULT_WLAN_WPAKEY, (void *)default_wpakey);
	if((!strcmp(Entry.wpaPSK,"0")) && strlen(default_wpakey) > 0){
                //mib_set(MIB_WLAN_WPA_PSK, (void *)cal_wpa_key);
                strcpy(Entry.wpaPSK, default_wpakey);
                wlan_setEntry(&Entry, 0);
#ifdef CONFIG_USER_CUMANAGEDEAMON
		   mib_set(CU_SRVMGT_ORIGINAL_PSK,(void*)default_wpakey);
#endif
                mib_update(CURRENT_SETTING, CONFIG_MIB_ALL);
		printf("Set Default WPA Key to %s \n" , default_wpakey);
        }


	return status;
}
#endif
int checkDefaultSSID(void)
{
	int status=0;
	unsigned char devAddr[MAC_ADDR_LEN];
	MIB_CE_MBSSIB_T Entry;
	unsigned char default_ssid[MAX_NAME_LEN];
	unsigned char vChar = 1;
	wlan_getEntry(&Entry, 0);
#if defined(CONFIG_CT_AWIFI_JITUAN_FEATURE)
	char end_mac[5], cal_string[5];
	char tmp_SSID[256];
#endif

	//if SSID is default, set SSID ChinaNet-xxxx (xxxx is last 4 characters of ELAN mac address)
	//if(!mib_get( MIB_WLAN_SSID,  (void *)current_SSID)){
	//	return -1;
	//}
/*
	if(!strcmp(Entry.ssid,"0")){
		if (!mib_get(MIB_ELAN_MAC_ADDR, (void *)devAddr) ){
			return -1;
		}
		sprintf(end_mac,"%02X%02X",devAddr[4],devAddr[5]);

		//checkInvalidCharInSSID(end_string);
		str_calculate(end_mac, cal_string, 4);
		sprintf(tmp_SSID,"ChinaNet-%s", cal_string);
		//mib_set(MIB_WLAN_SSID, (void *)tmp_SSID);
		strcpy(Entry.ssid, tmp_SSID);
		printf("set default SSID %s\n",tmp_SSID);
		wlan_setEntry(&Entry, 0);
		mib_update(CURRENT_SETTING, CONFIG_MIB_ALL);
	}
*/
	mib_get(MIB_DEFAULT_WLAN_SSID, (void *)default_ssid);
	if(!strcmp(Entry.ssid,"0")){ 
            if(strlen(default_ssid) > 0){
				mib_get(MIB_WLAN_PHY_BAND_SELECT, (void *)&vChar);
				if(vChar==PHYBAND_5G)
					strcat(default_ssid, "-5G");
                strcpy(Entry.ssid, default_ssid);
                printf("set default SSID %s\n",default_ssid);
                wlan_setEntry(&Entry, 0);
                mib_update(CURRENT_SETTING, CONFIG_MIB_ALL);
        }
#if defined(CONFIG_CT_AWIFI_JITUAN_FEATURE)
            unsigned char functype=0;
            mib_get(AWIFI_PROVINCE_CODE, &functype);
            if(functype == AWIFI_ZJ){
			wlan_getEntry(&Entry, 1);
			if(strncmp(Entry.ssid, "aWiFi", 5) != 0){
				strcpy(Entry.ssid, "aWiFi");
				printf("set aWiFi default SSID aWiFi\n");
				wlan_setEntry(&Entry, 1);
				mib_update(CURRENT_SETTING, CONFIG_MIB_ALL);
			}
            }
#endif
    }

	return status;
}
#endif

#ifdef CONFIG_YUEME
static void update_dns_server_config()
{
	int i, total;
	MIB_CE_ATM_VC_T entry;

	total = mib_chain_total(MIB_ATM_VC_TBL);
	for(i = 0 ; i < total ; i++)
	{
		if(mib_chain_get(MIB_ATM_VC_TBL, i, &entry) == 0)
			continue;

		// get DNS server automatically
		if(entry.dnsMode == DNS_SET_BY_API)
		{
			entry.dnsMode = REQUEST_DNS;
			mib_chain_update(MIB_ATM_VC_TBL, &entry, i);
		}
#ifdef CONFIG_IPV6
		// get DNSv6 server automatically
		if(entry.dnsv6Mode == DNS_SET_BY_API)
		{
			entry.dnsv6Mode = REQUEST_DNS;
			mib_chain_update(MIB_ATM_VC_TBL, &entry, i);
		}
#endif
	}
}
#endif

static void clearIpv6_addr() //Clear Ipv6 address after reboot if not static address
{
	int vcTotal, i;
	MIB_CE_ATM_VC_T Entry;
	char wanif[IFNAMSIZ];

	vcTotal = mib_chain_total(MIB_ATM_VC_TBL);
	for (i = 0; i < vcTotal; i++)
	{
	/* get the specified chain record */
		if (!mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&Entry))
		return;

		if (Entry.enable == 0)
			continue;

		ifGetName(Entry.ifIndex,wanif,sizeof(wanif));
		if (((Entry.cmode == CHANNEL_MODE_IPOE) && ((DHCP_T)Entry.ipDhcp == DHCP_CLIENT)) ||
				(Entry.cmode == CHANNEL_MODE_PPPOE)) {
			memset(Entry.Ipv6Addr, 0, sizeof(Entry.Ipv6Addr));
			memset(Entry.RemoteIpv6Addr, 0, sizeof(Entry.RemoteIpv6Addr));
			mib_chain_update(MIB_ATM_VC_TBL, &Entry, i);
		}
	}
}

int main(int argc, char *argv[])
{
	unsigned char value[32];
	int vInt;
#ifdef CONFIG_USER_SNMPD_SNMPD_V2CTRAP
	int snmpd_pid;
#endif
	FILE *fp = NULL;
	int i;
#ifdef TIME_ZONE
	int my_pid;
#endif
#if defined(WLAN_SUPPORT) && defined(CONFIG_E8B)
	char wlan_failed = 0;
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

	setpriority(PRIO_PROCESS, getpid(), -18);

#if __UCLIBC__
	//UCLIBC toolchain
#else
	signal(SIGSEGV, pSigHandler);
	signal(SIGBUS, pSigHandler);
	signal(SIGABRT, pSigHandler);
#endif
#if 0 
    // koba
    cpu_set_t cpuMask;
    unsigned long len = sizeof (cpuMask);
    CPU_ZERO(&cpuMask);
    CPU_SET(0, &cpuMask);
    if(sched_setaffinity(getpid(), len, &cpuMask) == -1) 
    {
        printf ("Failed to set cpu afinity for startup\n");
        exit(1);
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

#if defined(CONFIG_LUNA) && defined(CONFIG_RTK_L34_ENABLE)
	system("diag l34 set ip-mcast-trans 15 pppoe-act remove");
#endif

//cxy 2016-6-21: this will cause ip range acl rule permit to be trap(hw not support any range ip acl rule)
#if 0//defined(CONFIG_LUNA) && defined(CONFIG_RTK_L34_ENABLE)
	//cxy 2015-1-13: enable ip range acl filter for any range not only ip/mask format
	system("echo 1 > /proc/rg/acl_drop_ip_range_rule_handle_by_sw");
	system("echo 1 > /proc/rg/acl_permit_ip_range_rule_handle_by_sw");
	//end of cxy 2015-1-13
#endif
#ifdef CONFIG_IPV6
	{
		char ipv6Enable =-1;
		char buf[64]={0};
	
		mib_get(MIB_V6_IPV6_ENABLE, (void *)&ipv6Enable);
		/* IulianWu, IPv6 enable/disable */
		snprintf(buf, sizeof(buf), "/bin/echo %d > /proc/sys/net/ipv6/conf/all/disable_ipv6", (ipv6Enable==1?0:1));
		system(buf);
	}
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
		va_niced_cmd(WEBSERVER, 0, 0);
		return 0;	// stop here
	}
#if defined(WLAN_SUPPORT) && defined(CONFIG_RTK_L34_ENABLE) && defined(CONFIG_RTL_MULTI_LAN_DEV)
	va_cmd(IFCONFIG, 2, 1, ELANIF, "up");
#endif

#ifdef E8B_NEW_DIAGNOSE
	fp = fopen(INFORM_STATUS_FILE, "w");
	if (fp) {
		fprintf(fp, "%d:%s", NO_INFORM, E8B_START_STR);
		fclose(fp);
	}
#endif

#ifdef SUPPORT_WEB_PUSHUP
	if(firmwareUpgradeConfigStatus()==FW_UPGRADE_STATUS_PROGGRESSING)
		firmwareUpgradeConfigStatusSet(FW_UPGRADE_STATUS_FAIL);
#endif

	if (-1==startDaemon())
		goto startup_fail;

	//root interface should be up first
#ifndef CONFIG_RTL_MULTI_LAN_DEV
	if (va_cmd(IFCONFIG, 2, 1, ELANIF, "up"))
		goto startup_fail;
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
	//Clear the RG index saved in mib
	clearRG_Wan_Index();
	Init_RG_ELan(UntagCPort, RoutingWan);
#endif

	clearIpv6_addr();

#if defined(CONFIG_LUNA) && defined(CONFIG_RTK_L34_ENABLE)
	//check default route before start WAN to avoid droute is missed.
	RG_check_Droute(0,NULL,NULL);
#endif

#ifdef CONFIG_YUEME
	update_dns_server_config();
#endif

#ifdef CONFIG_RG_BRIDGE_PPP_STATUS
	//Add filter before start wan
	AddRTK_RG_Bridge_PPPSession_Filter();
#endif

#ifdef CONFIG_USER_DBUS_CTC_IGD
	//after any mib update, before startWAN
	system("/bin/ctc-igd-server &");
#endif

#ifdef CONFIG_RG_SLEEPMODE_TIMER
{
	int totalnum;
	unsigned char enable=0;
	MIB_CE_RG_SLEEPMODE_SCHED_T sleepEntry;
	//in startup, we must reset SLEEPMODE, 
	//it will affect internet led
	mib_set(MIB_RG_SLEEPMODE_ENABLE, (void *)&enable);

	totalnum = mib_chain_total(MIB_SLEEP_MODE_SCHED_TBL);
	for(i=totalnum-1; i>=0; i--)
	{
		mib_chain_get(MIB_SLEEP_MODE_SCHED_TBL, i, &sleepEntry);
		if(1 == sleepEntry.day)
		{
AUG_PRT("mib del SLEEP_MODE_SCHED_TBL id=%d\n",i);		
			mib_chain_delete(MIB_SLEEP_MODE_SCHED_TBL, i);
#ifdef YUEME_3_0_SPEC
			mib_local_mapping_set(MIB_WLAN_DISABLED, 0, (void *)&enable);
#ifdef WLAN_DUALBAND_CONCURRENT
			mib_local_mapping_set(MIB_WLAN_DISABLED, 1, (void *)&enable);
#endif
#else
			mib_set(MIB_WIFI_MODULE_DISABLED, (void *)&enable);
#endif
		}		
	}
	#ifdef COMMIT_IMMEDIATELY
	Commit();
	#endif
}
#endif


	if (-1==startWan(CONFIGALL, NULL, 1))
		goto startup_fail;

	system("/bin/diag port set phy-force-power-down port all state disable");

	for(i=0;i<ELANVIF_NUM;i++){
#if defined(CONFIG_RTK_L34_ENABLE) && defined(CONFIG_USER_LAN_PORT_AS_ETH_WAN)
		int portid = RG_get_lan_phyPortId(i);
		if (portid != -1 && portid == ethPhyPortId)
			continue;
#endif
		if(va_cmd(IFCONFIG, 2, 1, ELANVIF[i], "up")){
			goto startup_fail;
		}
#if defined(CONFIG_RTK_L34_ENABLE) && defined(CONFIG_RTL_MULTI_LAN_DEV)
		restart_ethernet(i+1);
#endif
	}

#ifdef CONFIG_USER_LANNETINFO
	va_niced_cmd( "/bin/lanNetInfo", 0, 0 );
#endif


#if (defined(CONFIG_CMCC) || defined(CONFIG_CU)) && defined(CONFIG_IPV6)
	ipv6_binding_update();
	set_vlan_cfg_action(0, 0);
#endif

#if defined(CONFIG_IPV6) && defined (CONFIG_USER_DHCPV6_ISC_DHCP411)
#ifdef SUPPORT_DHCPV6_RELAY
	{
		/* dhcpv6 relay must start after starting wan interface */
		unsigned char vChar;
		mib_get(MIB_DHCPV6_MODE, (void *)&vChar);
		printf("%s mode[%d]\n", __func__, vChar);
		if(vChar == DHCP_LAN_RELAY)
		{
			startDhcpv6Relay();
		}
		else if(vChar != DHCP_LAN_NONE)
			restartDHCPV6Server();
	}
#endif
#endif

#ifdef CONFIG_E8B
	 // Set MAC filter
#ifndef MAC_FILTER_SRC_ONLY
	setupMacFilterEbtables();
#endif
	setupMacFilterTables();
#endif
#ifdef _PRMT_X_CMCC_LANINTERFACES_
	setupL2Filter();
	setupMACLimit();
#endif

    /*
     * 2012/8/15
     * Since now eth0.2~5 are up, change NS number to default number 1.
     */
	unsigned char val[64];
	snprintf(val, 64, "/bin/echo 1 > /proc/sys/net/ipv6/conf/%s/dad_transmits", (char*)BRIF);
	system(val);

#ifdef CONFIG_USB_ETH
	if (va_cmd(IFCONFIG, 2, 1, USBETHIF, "up"))
		goto startup_fail;
#endif //CONFIG_USB_ETH


//#ifndef CONFIG_ETHWAN

#ifdef ELAN_LINK_MODE_INTRENAL_PHY
	setupLinkMode_internalPHY();
#endif

#if	defined(CONFIG_LUNA_DUAL_LINUX)
	setup_vwlan();
#if defined(WLAN_DUALBAND_CONCURRENT)
	check_slave_wifi_en();
#endif
#endif

#ifdef WLAN_SUPPORT
#if defined(CONFIG_E8B)
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

		checkDefaultSSID();
#ifdef WLAN_WPA
		checkDefaultWPAKey();
#endif
	}
	wlan_idx = orig_wlan_idx;
#if defined(CONFIG_WIFI_SIMPLE_CONFIG)
#ifndef WLAN_WPS_VAP
	update_wps_configured(0);
#endif
#endif
	//check default SSID and WPA key end

#ifdef WLAN_WPS_VAP
	mib_backup(CONFIG_MIB_ALL);
	update_wps_configured(0);
#endif
	
	//if (-1==startWLan(CONFIG_WLAN_ALL, CONFIG_SSID_ALL))
	//	goto startup_fail;
	wlan_failed = startWLan(CONFIG_WLAN_ALL, CONFIG_SSID_ALL);
#else
	//if (-1==startWLan(CONFIG_WLAN_ALL, CONFIG_SSID_ALL))
	//	goto startup_fail;
	startWLan(CONFIG_WLAN_ALL, CONFIG_SSID_ALL);
#endif
#endif


#if (defined(CONFIG_RTL867X_NETLOG)  && defined (CONFIG_USER_NETLOGGER_SUPPORT))
        va_niced_cmd(NETLOGGER,0,1);
#endif

#ifdef CONFIG_USER_QUICKINSTALL
	va_niced_cmd( "/bin/Quickinstall", 0, 0 );
#endif

#ifdef CONFIG_USER_RTK_OMD
	// no need log reboot infomation by hardware reboot
	//if(is_terminal_reboot() )
	//	write_omd_reboot_log(TERMINAL_REBOOT);
	write_omd_reboot_log(REBOOT_FLAG);
	va_niced_cmd( "/bin/omd_main", 0, 0 );
#endif

//#ifdef CONFIG_USER_LANNETINFO
//	va_niced_cmd( "/bin/lanNetInfo", 0, 0 );
//#endif
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	va_niced_cmd( "/bin/WlanTaskDeamon", 0, 0 );
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

#ifdef CONFIG_USER_DBUS_PROXY
	if(!access("/tmp/.runRestore", F_OK)) unlink("/tmp/.runRestore");
	va_niced_cmd( "/bin/proxyDaemon", 0, 0 );
	va_niced_cmd( "/bin/reg_server", 0, 0 );
#endif
	//ql 20081117 START init MIB_QOS_UPRATE before startup IP QoS
#ifdef NEW_IP_QOS_SUPPORT
	unsigned int up_rate=0;
	mib_set(MIB_QOS_UPRATE, (void *)&up_rate);
#endif

#if defined(WLAN_SUPPORT) && defined(CONFIG_E8B)
	if(wlan_failed)
		syslog(LOG_ERR, "104012 WLAN start failed.");
#endif

#ifdef _PRMT_C_CU_LOGALARM_
	syslogAlarm(ALARM_REBOOT,ALARM_RECOVER,ALARM_MAJOR,"Device Reboot", 0);
#endif	

	if (-1==startRest())
		goto startup_fail;

#ifdef CONFIG_USER_WATCHDOG_WDG
    //start watchdog & kick every 5 seconds silently
	//va_cmd_no_echo("/bin/wdg", 2, 1, "timeout", "10");
	//va_cmd_no_echo("/bin/wdg", 2, 1, "start", "5");
#endif
	//take effect
#ifdef CONFIG_XFRM
	ipsec_take_effect();
#endif
#if defined(CONFIG_USER_PPTP_CLIENT_PPTP) && defined(CONFIG_USER_L2TPD_L2TPD)
	FILE *f;
	if((f = fopen(ConfigVpnLock, "w")) == NULL)
		return -1;
	fclose(f);
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
#ifdef CONFIG_USER_L2TPD_LNS
	l2tpd_take_effect();
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
#if !defined(CONFIG_CMCC) && !defined(CONFIG_CU)
	RTK_RG_USER_APP_ACL_Rule_Flush();
	RTK_RG_USER_APP_ACL_Rule_Set();
#endif
}
#endif
#if defined(CONFIG_LUNA) && defined(CONFIG_RTK_L34_ENABLE)
	check_v4_igmp_snooping();
	check_v6_mld_snooping();
	Flush_RTK_RG_IPv4_IPv6_Vid_Binding_ACL();
	RTK_RG_Set_IPv4_IPv6_Vid_Binding_ACL();
	RG_del_PPPoE_Acl();
	RG_add_PPPoE_RB_passthrough_Acl();
	RTK_RG_FLUSH_Bridge_DHCP_ACL_FILE();
	RTK_RG_Set_ACL_Bridge_DHCP_Filter();
	RTK_RG_add_acl_rule_for_v6_icmp();
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)	
	RG_Handle_Priority_Tag0_By_Port();
	//set unbinded port to vlan 9, to make unbinded port can access other binded port
	RG_set_unbinded_port_vlan();
	RGSyncIPv4_IPv6_Dual_WAN();
#endif	
#if defined (CONFIG_EPON_FEATURE) || defined(CONFIG_GPON_FEATURE)
#ifdef CONFIG_RTL9600_SERIES
	unsigned int pon_mode;
	mib_get(MIB_PON_MODE, (void *)&pon_mode);
#ifdef CONFIG_EPON_FEATURE
	if(pon_mode == EPON_MODE)
	{	
			Flush_RTK_RG_Bridge_from_Lan_ACL();
			RTK_RG_Set_ACL_Bridge_from_Lan();
	}
#endif
#endif
#endif
// 	remove code because wifi throughput not good (packet goto slowpath)
//	if(!check_user_is_registered())
//		enable_http_redirect2register_page(1);

 	//RTK_RG_FLUSH_Route_V6_RA_NS_ACL_FILE();
 	//RTK_RG_Set_ACL_Route_V6_RA_NS_Filter();
#ifndef CONFIG_RTL9600_SERIES
	check_port_based_vlan_of_binding_bridge_inet_wan();
#endif
#ifdef CONFIG_CTC_E8_CLIENT_LIMIT
        RTK_RG_AccessWanLimit_Set();
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
#ifdef CONFIG_YUEME
	va_niced_cmd("saf", 4, 0, "service", "8", "9", "10");
#endif 
//#ifdef _CWMP_MIB_ /*jiunming, mib for cwmp-tr069*/
	/*when those processes created by startup are killed,
	  they will be zombie processes,jiunming*/
	signal(SIGCHLD, SIG_IGN);//add by star
//#endif

#if 1
#ifdef CONFIG_USER_SNMPD_SNMPD_V2CTRAP
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
#endif
#endif
	/*ql 20081117 END*/
	// Mason Yu. for IPv6
	// remove from startDaemon()
#ifdef CONFIG_INIT_SCRIPTS
	printf("========== Initiating Ending Script =============\n");
	system("sh /var/config/end_script");
	printf("========== End Initiating Ending Script =============\n");
#endif

#if defined(CONFIG_CMCC_JAVA_THREAD_CPU_LIMIT)
        system("[ -f /var/osgi_app/bundle/com.realtek.cpulimit.jar ] || ln -s /usr/local/class/felix/bundle/com.realtek.cpulimit.jar /var/osgi_app/bundle/com.realtek.cpulimit.jar");
#endif
#ifdef CONFIG_USER_OPENJDK8
	setupOsgiAutoStart();
#endif



#if defined(CONFIG_RTK_L34_ENABLE) && defined(CONFIG_LUNA)
	if(startFirewall() == 0)
		printf("Firewall Start Error !!\n");
#endif

#ifdef CONFIG_NETFILTER_XT_MATCH_PSD
	setup_psd();
#endif

#ifdef CONFIG_USER_BEHAVIOR_ANALYSIS
	mkdir(SNORT_PATH, 0755);
	setup_behavior_analysis();
#endif

#ifdef CONFIG_USER_LXC
        va_cmd(EBTABLES, 7, 1, "-I", "FORWARD", "1", "-i", "veth+", "-j" ,"ACCEPT");
	va_cmd(EBTABLES, 7, 1, "-I", "FORWARD", "1", "-o", "veth+", "-j" ,"ACCEPT");
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
#ifdef BOOT_SELF_CHECK
	unsigned char functype=0;
	mib_get(PROVINCE_MISCFUNC_TYPE,&functype);
	if(functype == 1)
	{
		sleep(10);
		bootSelfCheck();
	}
#endif
#ifdef CONFIG_USER_MONITORD
#if defined(CONFIG_GPON_FEATURE)
	int ponMode=0;
	if (mib_get(MIB_PON_MODE, (void *)&ponMode) != 0)
	{
		if (ponMode == GPON_MODE)
		{
			/*TBD, enable this after RTK_RG_Sync_OMCI_WAN_INFO be modified*/
			update_monitor_list_file("omci_app", 1);
		}
	}
#endif
#endif

#if defined(CONFIG_YUEME) || defined(CONFIG_CMCC) || defined(CONFIG_CU)
	{
		unsigned char ledstate;
		unsigned char lightswitch;
		mib_get(PROVINCE_SICHUAN_LIGHTSWITCH_STATE, &lightswitch);
		if(!getLedStatus(&ledstate)) 
		{
			if(lightswitch)
				setLedStatus(1);
			else
				setLedStatus(ledstate);
		}
		
	}
#endif
	//system("/bin/diag port set phy-force-power-down port all state disable");
#ifdef CONFIG_E8B
        power_led_control_operation(PWR_LED_STOP_BLINKING);
        power_led_control_operation(PWR_LED_ON);
#endif
#if defined(WIFI_TIMER_SCHEDULE) || defined(CONFIG_LED_INDICATOR_TIMER) || defined(CONFIG_RG_SLEEPMODE_TIMER)
	updateScheduleCrondFile("/var/spool/cron/crontabs", 1);
#endif

#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_
	unsigned char scWlanScan = 0;
	mib_get(PROVINCE_SICHUAN_WLAN_SURVEY_TIME, &scWlanScan);
	if(scWlanScan)
	{
//		getAllWirelessChannelOnce();
	}
#endif

#if (defined(CONFIG_CMCC) || defined(CONFIG_CU)) && defined(WLAN_DUALBAND_CONCURRENT)
	system("echo  0 > /proc/rg/disableWifiTxDistributed");
	system("echo 2 > /proc/rg/smp_wifi_11ac_tx_cpu_from_cpu0");
	system("echo 2 > /proc/rg/smp_wifi_11ac_tx_cpu_from_cpu1");
	system("echo 2 > /proc/rg/smp_wifi_11ac_tx_cpu_from_cpu2");
	system("echo 2 > /proc/rg/smp_wifi_11ac_tx_cpu_from_cpu3");
#endif
#ifdef CONFIG_CT_AWIFI_JITUAN_SMARTWIFI
{
    unsigned char functype=0;
    mib_get(AWIFI_PROVINCE_CODE, &functype);
    if(functype == AWIFI_ZJ){
        system("ln -s /var/config/awifi/libhttpd.so /var/config/awifi/libhttpd.so.0");
        system("echo 3 > /proc/sys/net/ipv4/tcp_syn_retries");
        system("mkdir -p /var/spool/cron/crontabs");
        if(access("/var/config/awifi", F_OK) != 0)
            system("mkdir -p  /var/config/awifi");
    }
}
#endif

#ifdef CONFIG_CT_AWIFI_UPGRADE
{
    unsigned char functype=0;
    mib_get(AWIFI_PROVINCE_CODE, &functype);
    if(functype == AWIFI_ZJ){
    system("/bin/awifi_upgrade&");
    }
}
#endif
#ifdef CONFIG_YUEME
	startHomeNas();
#endif

	// restart USB to trigger hotplug add uevent
	/*  this method should enable "find" feature in busybox
	**  sd[a-z][0-9],sr[0-9],*lp[0-9] should same with mdev.conf
	 */
#if !defined(CONFIG_YUEME) || defined(CONFIG_LUNA_G3_SERIES) //yueme will do in other place, g3 force to do since no appframework
	system("find /sys/devices/platform -type d -name sd[a-z][0-9] -exec sh -c 'echo \"add\" >> \"$0\"/uevent' {} \\;");
	system("find /sys/devices/platform -type d -name sd[a-z] -exec sh -c 'echo \"add\" >> \"$0\"/uevent' {} \\;");
	system("find /sys/devices/platform -type d -name sr[0-9] -exec sh -c 'echo \"add\" >> \"$0\"/uevent' {} \\;");
	system("find /sys/devices/platform -type d -name *lp[0-9] -exec sh -c 'echo \"add\" >> \"$0\"/uevent' {} \\;");
#endif
#ifdef CONFIG_USER_LAN_BANDWIDTH_CONTROL
	apply_maxBandwidth();
#endif
#ifdef _PRMT_SC_CT_COM_InternetService_MAXSession_
	char cmdbuf[128]={0};
	unsigned int maxsession_enable;
	unsigned int maxsession_num;
	mib_get( MIB_NAPT_MAXSESSION_ENABLE, &maxsession_enable);
	if(maxsession_enable){
			mib_get( MIB_NAPT_MAXSESSION_NUM, &maxsession_num);
			snprintf(cmdbuf,sizeof(cmdbuf),"echo %u > /proc/rg/napt_access_limit_number",maxsession_num);
	}else{
			snprintf(cmdbuf,sizeof(cmdbuf),"echo -1 > /proc/rg/napt_access_limit_number");
	}				
	system(cmdbuf);
#endif

#ifdef STB_L2_FRAME_LOSS_RATE
		{
			unsigned char enable;
			mib_get(PROVINCE_SICHUAN_STB_FRAME_LOSS_RATE, &enable);
			if(enable)
			{
				va_cmd("/bin/stbL2Com",0,0);
			}
		}
#endif
	/** To allow other threads to continue execution, the main thread should
	 ** terminate by calling pthread_exit() rather than exit(3). */
	pthread_exit(NULL);
	//return 0;	// child thread will exit with main thread exit, even child thread detach

startup_fail:
	va_niced_cmd("/bin/boa",0,1);
	printf("System startup failed !\n");
	return -1;
}

