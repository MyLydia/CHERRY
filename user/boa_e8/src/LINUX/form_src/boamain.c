/*-----------------------------------------------------------------
 * File: boamain.c
 *-----------------------------------------------------------------*/

#include <string.h>
#include "webform.h"
#include "fmdefs.h"
#include "mib.h"
#include "../defs.h"
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
//xl_yue
#include "utility.h"
#include <linux/wireless.h>
#include "../ipv6_info.h"
#include "../../webs.h"
#include <sys/ioctl.h>
#include "../port.h"

/*+++++add by Jack for VoIP project 20/03/07+++++*/
#ifdef VOIP_SUPPORT
#include "web_voip.h"
#endif /*VOIP_SUPPORT*/
/*-----end-----*/
#include "multilang.h"
#ifdef CONFIG_RTK_L34_ENABLE
#include <rtk_rg_struct.h>
#endif

//#ifdef _USE_RSDK_WRAPPER_
void initSyslogPage(request * wp);
void initDgwPage(request * wp);
//#endif //_USE_RSDK_WRAPPER_
extern int terminalInspectionShow(int eid, request * wp, int argc, char **argv);
extern int showOLT_status(int eid, request * wp, int argc, char **argv);

void rtl8670_AspInit() {
   /*
 *	ASP script procedures and form functions.
 */
	// fm function for E8
	boaASPDefine("getInfo", getInfo);
#ifdef TERMINAL_INSPECTION_SC
		  boaASPDefine("terminalInspectionShow", terminalInspectionShow);
		  boaASPDefine("showOLT_status", showOLT_status);
#endif
   	boaASPDefine("gettopstyle", gettopstyle);
	boaASPDefine("getDefaultGWMask", getDefaultGWMask);
	boaASPDefine("getDefaultGW", getDefaultGW);
#ifdef CONFIG_IPV6
	boaASPDefine("getDefaultGW_ipv6", getDefaultGW_ipv6);
#endif

	boaASPDefine("listWanConfig", listWanConfig);
#ifdef CONFIG_IPV6
	boaASPDefine("listWanConfigIpv6", listWanConfigIpv6);
#endif
#ifdef SUPPORT_WAN_BANDWIDTH_INFO
	boaASPDefine("listWanBandwidth", listWanBandwidth);
#endif
	// Kaohj
	boaASPDefine("checkWrite", checkWrite);
	boaASPDefine("atmVcList2", atmVcList2);
	boaASPDefine("initPage", initPage);
	boaASPDefine("createMenuEx", createMenuEx);
#ifdef WLAN_SUPPORT
	boaFormDefine("formWlanSetup", formWlanSetup);
	boaASPDefine("wlStatsList", wlStatsList);
	boaASPDefine("wlStatus_parm", wlStatus_parm);
	boaASPDefine("wlan_interface_status", wlan_interface_status);
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	boaASPDefine("wlStatsList_24G", wlStatsList_24G);
	boaASPDefine("wlStatus_parm_24G", wlStatus_parm_24G);
	boaASPDefine("wlan_interface_status_24G", wlan_interface_status_24G);
#if	defined(WLAN_DUALBAND_CONCURRENT)
	boaASPDefine("wlStatsList_5G", wlStatsList_5G);
	boaASPDefine("wlStatus_parm_5G", wlStatus_parm_5G);
	boaASPDefine("wlan_interface_status_5G", wlan_interface_status_5G);
#endif
#endif
	boaASPDefine("wirelessClientList", wirelessClientList);
#ifdef WLAN_WPA
	boaFormDefine("formWlEncrypt", formWlEncrypt);
#endif
#ifdef WIFI_TIMER_SCHEDULE
	boaFormDefine("formWifiTimerEx", formWifiTimerEx);
	boaFormDefine("formWifiTimer", formWifiTimer);
	boaASPDefine("ShowWifiTimerMask", ShowWifiTimerMask);
#endif
#ifdef _PRMT_X_CMCC_WLANSHARE_
	boaFormDefine("formWlanShare", formWlanShare);
#endif
	boaFormDefine("formWlanRedirect", formWlanRedirect);
#ifdef WLAN_11R
	boaFormDefine("formFt", formFt);
	boaASPDefine("wlFtKhList", wlFtKhList);
	boaASPDefine("ShowDot11r", ShowDot11r);
#endif
#ifdef WLAN_11K
	boaASPDefine("ShowDot11k_v", ShowDot11k_v);
#endif
#endif
	boaASPDefine("E8BPktStatsList", E8BPktStatsList);
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	boaASPDefine("E8BLanDevList", E8BLanDevList);
#else
	boaASPDefine("E8BDhcpClientList", E8BDhcpClientList);
#endif
#ifdef CONFIG_USER_RTK_SYSLOG
	boaFormDefine("formSysLog", formSysLog);
	boaASPDefine("sysLogList", sysLogList);
	boaFormDefine("formSysLogConfig", formSysLogConfig);
#endif

#if defined(CONFIG_GPON_FEATURE) || defined(CONFIG_EPON_FEATURE)
	boaASPDefine("ponGetStatus", ponGetStatus);
#ifdef CONFIG_GPON_FEATURE
	boaASPDefine("showgpon_status", showgpon_status);
#endif

#ifdef CONFIG_EPON_FEATURE
	boaASPDefine("showepon_status", showepon_status);
#endif
#endif
#ifdef CONFIG_MCAST_VLAN
	boaASPDefine("listWanName", listWanName);
	boaFormDefine("formMcastVlanMapping", formMcastVlanMapping);
#endif

#ifdef USE_LOGINWEB_OF_SERVER
	boaFormDefine("formLogin", formLogin);					// xl_yue added,
	boaFormDefine("formLogout", formLogout);
	// Kaohj
	boaASPDefine("passwd2xmit", passwd2xmit);
#endif
	boaFormDefine("formUSBbak", formUSBbak);
	boaFormDefine("formUSBUmount", formUSBUmount);
	boaFormDefine("formReboot", formReboot);				// Commit/reboot Form
#ifdef _CWMP_MIB_
	boaFormDefine("formTR069Config", formTR069Config);
	boaFormDefine("formTR069CPECert", formTR069CPECert);
	boaFormDefine("formTR069CACert", formTR069CACert);
	boaFormDefine("formTR069CACertDel", formTR069CACertDel);
	boaFormDefine("formMidwareConfig", formMidwareConfig);

	boaASPDefine("TR069ConPageShow", TR069ConPageShow);
	boaASPDefine("TR069DumpCWMP", TR069DumpCWMP);
#endif
	boaFormDefine("formFinishMaintenance", formFinishMaintenance);
#ifdef E8B_NEW_DIAGNOSE
	boaASPDefine("dumpPingInfo", dumpPingInfo);
	boaFormDefine("formPing", formPing);		// Ping diagnostic Form
	boaASPDefine("createMenuDiag", createMenuDiag);
	boaFormDefine("formTr069Diagnose", formTr069Diagnose);
	boaASPDefine("dumpTraceInfo", dumpTraceInfo);
	boaFormDefine("formTracert", formTracert);
#ifdef CONFIG_SUPPORT_AUTO_DIAG
	boaFormDefine("formAutoDiag", formAutoDiag);
	boaFormDefine("formQOE", formQOE);
#endif
#endif
#if defined(CONFIG_ETHWAN)
	boaFormDefine("formEthernet", formEthernet);			// Ethernet Configuration Setting Form
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	boaFormDefine("formEthernet_cmcc", formEthernet_cmcc);			// Ethernet Configuration Setting Form
#endif
	boaASPDefine("initPageEth", initPageEth);
	boaASPDefine("initPageEth2", initPageEth2);
	boaASPDefine("initVlanRange", initVlanRange);	
	boaASPDefine("initPageQoSAPP", initPageQoSAPP);
#endif
	boaFormDefine("formWanRedirect", formWanRedirect);
	boaASPDefine("if_wan_list", ifwanList);
#ifdef CONFIG_USER_IGMPPROXY
	boaFormDefine("formIgmproxy", formIgmproxy);	// IGMP Configuration Form
	boaASPDefine("igmproxyList", igmproxyList);		// Mason Yu. IGMP Proxy for e8b
#endif
#ifdef CONFIG_IPV6
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	boaFormDefine("formlanipv6raconf", formlanipv6raconf);
	boaFormDefine("formlanipv6dhcp", formlanipv6dhcp);
#else//CONFIG_CMCC
	boaFormDefine("formlanipv6dns", formlanipv6dns);			    // set LAN(br0) IPv6 address
	boaFormDefine("formlanipv6", formlanipv6);			    // set LAN(br0) IPv6 address
	boaFormDefine("formlanipv6prefix", formlanipv6prefix);	// set LAN IPv6 prefix
#endif //CONFIG_CMCC
#ifdef CONFIG_USER_ECMH
	boaFormDefine("formMLDProxy", formMLDProxy);			// MLD Proxy Configuration Form
#endif
	boaFormDefine("formMLDSnooping", formMLDSnooping);		// formIgmpSnooping Configuration Form  // Mason Yu. MLD snooping for e8b
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	boaFormDefine("formIgmpMldSnooping", formIgmpMldSnooping);
	boaFormDefine("formIgmpMldProxy", formIgmpMldProxy);
#endif
#ifdef STB_L2_FRAME_LOSS_RATE
	boaASPDefine("initTermInsp", initTermInsp);
#endif

#ifdef CONFIG_USER_RADVD
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	boaFormDefine("formlanipv6raconf", formlanipv6raconf);			// RADVD Configuration Setting Form
#else//CONFIG_CMCC
	boaFormDefine("formRadvdSetup", formRadvdSetup);			// RADVD Configuration Setting Form
#endif//CONFIG_CMCC
#endif
#ifdef CONFIG_USER_DHCPV6_ISC_DHCP411
	boaFormDefine("formDhcpv6Server", formDhcpv6);			        // DHCPv6 Server Setting Form
#if 0 //iulian marked
	boaASPDefine("showDhcpv6SNameServerTable", showDhcpv6SNameServerTable);     // Name Server List for DHCPv6 Server
	boaASPDefine("showDhcpv6SDOMAINTable", showDhcpv6SDOMAINTable);             // Domian search List for DHCPv6 Server
#endif
#endif
#endif
	boaFormDefine("formRouting", formRoute);			// Routing Configuration Form
	boaASPDefine("showStaticRoute", showStaticRoute);
#if defined(CONFIG_IPV6) && (defined(CONFIG_CMCC) || defined(CONFIG_CU))
	boaFormDefine("formIPv6Routing", formIPv6Route);
	boaASPDefine("showIPv6StaticRoute", showIPv6StaticRoute);
#endif
	boaASPDefine("ShowDefaultGateway", ShowDefaultGateway);	// Jenny, for DEFAULT_GATEWAY_V2
	boaASPDefine("GetDefaultGateway", GetDefaultGateway);
	boaFormDefine("formRefleshRouteTbl", formRefleshRouteTbl);
	boaASPDefine("routeList", routeList);
#if defined(CONFIG_USER_ROUTED_ROUTED)
	boaFormDefine("formRip", formRip);			// RIP Configuration Form
	boaASPDefine("showRipIf", showRipIf);
#endif
	boaASPDefine("initPage", initPage);
	boaFormDefine("formIgmpSnooping", formIgmpSnooping);	// formIgmpSnooping Configuration Form  // Mason Yu. IGMP snooping for e8b

	boaFormDefine("formDhcpServer", formDhcpd);				// DHCP Server Setting Form
#ifdef CONFIG_CU
	boaFormDefine("formIpRange", formIpRange);
#endif
	boaASPDefine("dhcpClientList", dhcpClientList);
#if defined(CONFIG_USER_MINIUPNPD)
	boaFormDefine("formUpnp", formUpnp);
#endif
	// Magician E8B Security pages
	boaASPDefine("listWanif", listWanif);
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	boaASPDefine("listWanPath", listWanPath);
#endif
#ifdef URL_BLOCKING_SUPPORT
	boaASPDefine("initPageURL", initPageURL);
	boaFormDefine("formURL", formURL);                  // URL Configuration Form
#endif
#ifdef SUPPORT_DNS_FILTER
	boaASPDefine("initPageDNS", initPageDNS);
	boaFormDefine("formDNSFilter", formDNSFilter);
#endif
#ifdef CONFIG_LED_INDICATOR_TIMER 
	boaFormDefine("formLedTimer", formLedTimer);
#endif
	boaASPDefine("initPageFirewall", initPageFirewall);
	boaFormDefine("formFirewall", formFirewall);
	boaASPDefine("initPageDos", initPageDos);
	boaFormDefine("formDos", formDos);
	boaASPDefine("brgMacFilterList", brgMacFilterList);
	boaFormDefine("formBrgMacFilter", formBrgMacFilter);
	boaASPDefine("initPageMacFilter", initPageMacFilter);
	boaASPDefine("rteMacFilterList", rteMacFilterList);
	boaFormDefine("formRteMacFilter", formRteMacFilter);

#ifdef CONFIG_RG_SLEEPMODE_TIMER
	boaASPDefine("initPageSleepModeRule", initPageSleepModeRule);
	boaFormDefine("formSleepMode", formSleepMode);
#endif

#if  defined(CONFIG_USER_LAN_BANDWIDTH_MONITOR) && defined(CONFIG_USER_LANNETINFO)
	boaASPDefine("initPageLanBandwidthMonitor", initPageLanBandwidthMonitor);
	boaFormDefine("formBandwidthMonitor", formBandwidthMonitor);
#endif
#ifdef CONFIG_USER_LAN_BANDWIDTH_CONTROL
	boaASPDefine("initPageBandwidthControl", initPageBandwidthControl);
	boaFormDefine("formBandWidth", formBandWidth);
#endif
#ifdef CONFIG_USER_LANNETINFO
	boaASPDefine("initPageLanNetInfo", initPageLanNetInfo);
#endif
	boaASPDefine("bandwidthSelect", bandwidthSelect);
	boaASPDefine("initPagePortBWControl", initPagePortBWControl);
	boaFormDefine("formPortBandWidth", formPortBandWidth);
	
	boaASPDefine("ipPortFilterBlacklist", ipPortFilterBlacklist);
	boaASPDefine("ipPortFilterWhitelist", ipPortFilterWhitelist);
	boaFormDefine("formPortFilter", formPortFilter);
	boaASPDefine("ipPortFilterConfig", ipPortFilterConfig);
	boaFormDefine("formPortFilterWhite", formPortFilterWhite);
	boaFormDefine("formPortFilterBlack", formPortFilterBlack);
	boaFormDefine("formMacAddrBase", formMacAddrBase);
	boaASPDefine("showMACBaseTable", showMACBaseTable);
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	boaASPDefine("ipPortFilterBlacklistIn", ipPortFilterBlacklistIn);
	boaASPDefine("ipPortFilterBlacklistOut", ipPortFilterBlacklistOut);
	boaASPDefine("ipPortFilterWhitelistIn", ipPortFilterWhitelistIn);
	boaASPDefine("ipPortFilterWhitelistOut", ipPortFilterWhitelistOut);
	boaFormDefine("formPortFilterIn", formPortFilterIn);
	boaFormDefine("formPortFilterOut", formPortFilterOut);
	boaASPDefine("ipPortFilterDirConfig", ipPortFilterDirConfig);
	boaFormDefine("formPortFilterWhiteIn", formPortFilterWhiteIn);
	boaFormDefine("formPortFilterWhiteOut", formPortFilterWhiteOut);
	boaFormDefine("formPortFilterBlackIn", formPortFilterBlackIn);
	boaFormDefine("formPortFilterBlackOut", formPortFilterBlackOut);
	boaFormDefine("formPortFilterPort", formPortFilterPort);
	boaASPDefine("initPagePortFilter", initPagePortFilter);
#endif

#ifdef CONFIG_USER_DDNS
	boaFormDefine("formDDNS", formDDNS);
	boaASPDefine("showDNSTable", showDNSTable);
#endif
	//End Magician

	boaFormDefine("formDMZ", formDMZ);						// Firewall DMZ Setting Form

	boaASPDefine("initPageMgmUser", initPageMgmUser);

#ifdef VIRTUAL_SERVER_SUPPORT
	boaFormDefine("formVrtsrv", formVrtsrv);
	boaASPDefine("virtualSvrList", virtualSvrList);
	boaASPDefine("virtualSvrLeft", virtualSvrLeft);
#endif
#ifdef CONFIG_IP_NF_ALG_ONOFF
	boaFormDefine("formALGOnOff", formALGOnOff);
#endif

#ifdef _PRMT_X_CT_COM_USERINFO_
	boaFormDefine("formAccountReg", formAccountReg);
	boaFormDefine("formUserReg", formUserReg);
	boaFormDefine("formUserReg_inside_menu", formUserReg_inside_menu);
	boaASPDefine("UserRegMsg", UserRegMsg);
	boaASPDefine("UserRegMsgPassword", UserRegMsgPassword);
	boaASPDefine("initE8clientUserRegPage", initE8clientUserRegPage);
	boaASPDefine("getProvinceInfo", getProvinceInfo);
	boaASPDefine("regresultBodyStyle", regresultBodyStyle);
	boaASPDefine("regresultMainDivStyle", regresultMainDivStyle);
	boaASPDefine("regresultBlankDivStyle", regresultBlankDivStyle);
	boaASPDefine("regresultLoginStyle", regresultLoginStyle);
	boaASPDefine("regresultLoginFontStyle", regresultLoginFontStyle);
	boaASPDefine("e8clientAccountRegResult", e8clientAccountRegResult);
	boaASPDefine("e8clientAutorunAccountRegResult", e8clientAutorunAccountRegResult);
	boaASPDefine("UserAccountRegResult", UserAccountRegResult);
	boaASPDefine("checkPopupRegPage", checkPopupRegPage);
	boaASPDefine("UserInsideRegPage", UserInsideRegPage);
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	boaASPDefine("UserInsideRegLoidPage", UserInsideRegLoidPage);
#endif
#endif
	boaFormDefine("formPasswordSetup", formPasswordSetup);
#ifdef SUPPORT_PUSHWEB_FOR_FIRMWARE_UPGRADE
    boaFormDefine("formFirmwareUpgradeWarn", formFirmwareUpgradeWarn);
	boaASPDefine("initFirmwareUpgradeWarnPage", initFirmwareUpgradeWarnPage);
#endif

#ifdef TIME_ZONE
	// Mason Yu. 2630-e8b
	boaFormDefine("formTimezone", formTimezone);
	boaASPDefine("init_sntp_page", init_sntp_page);
	boaASPDefine("timeZoneList", timeZoneList);
#endif
#ifdef CONFIG_USER_MINIDLNA
	boaASPDefine("fmDMS_checkWrite", fmDMS_checkWrite);
	boaFormDefine("formDMSConf", formDMSConf);
#endif
	boaASPDefine("initPageStorage", initPageStorage);
	boaFormDefine("formStorage", formStorage);
	boaASPDefine("listUsbDevices", listUsbDevices);
#ifdef CONFIG_USER_PPTP_CLIENT_PPTP
	boaFormDefine("formPPtP", formPPtP);
	boaASPDefine("pptpWuiList", pptpWuiList);	
	boaASPDefine("pptpGdbusList", pptpGdbusList);
	boaASPDefine("pptpGdbusAttachList", pptpGdbusAttachList);
#endif //end of CONFIG_USER_PPTP_CLIENT_PPTP
#ifdef CONFIG_USER_L2TPD_L2TPD
	boaFormDefine("formL2TP", formL2TP);
	boaASPDefine("l2tpWuiList", l2tpWuiList);
	boaASPDefine("l2tpGdbusList", l2tpGdbusList);
	boaASPDefine("l2tpGdbusAttachList", l2tpGdbusAttachList);
#endif //end of CONFIG_USER_L2TPD_L2TPD
#if defined(CONFIG_RTL867X_VLAN_MAPPING) || defined(CONFIG_APOLLO_ROMEDRIVER)
	boaASPDefine("initPagePBind", initPagePBind);
	boaFormDefine("formVlanMapping", formVlanMapping);
#endif
#ifdef CONFIG_CMCC_MULTICAST_CROSS_VLAN_SUPPORT
	boaASPDefine("initCrossVlan", initCrossVlan);
	boaFormDefine("formCrossVlan", formCrossVlan);
#endif
	boaASPDefine("initdgwoption", initdgwoption);

//#ifdef NEW_IP_QOS_SUPPORT
	boaFormDefine("formQosPolicy", formQosPolicy);
#ifdef _PRMT_X_CT_COM_DATA_SPEED_LIMIT_
	boaASPDefine("initQosSpeedLimitRule",initQosSpeedLimitRule);
	boaFormDefine("formQosSpeedLimit", formQosSpeedLimit);
#endif
	boaASPDefine("initQueuePolicy", initQueuePolicy);
	boaASPDefine("ifWanList", ifWanList_tc);
	boaFormDefine("formQosTraffictl",formQosTraffictl);
	boaFormDefine("formQosTraffictlEdit",formQosTraffictlEdit);
	boaASPDefine("initTraffictlPage",initTraffictlPage);
	boaFormDefine("formQosRule",formQosRule);
	boaFormDefine("formQosRuleEdit",formQosRuleEdit);

	boaASPDefine("initConnType",initConnType);
	boaASPDefine("initQosRulePage",initQosRulePage);
	boaASPDefine("initRulePriority",initRulePriority);
	boaASPDefine("initOutif",initOutif);
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	boaASPDefine("initQosLanif",initQosLanif);
	boaFormDefine("formQosClassficationRuleEdit",formQosClassficationRuleEdit);
	boaASPDefine("getQosClassficaitonQueueArray", getQosClassficaitonQueueArray);
	boaASPDefine("getQosTypeQueueArray", getQosTypeQueueArray);
	boaASPDefine("getWANItfArray", getWANItfArray);
	boaASPDefine("initQosTypeLanif", initQosTypeLanif);
	boaFormDefine("formQosVlan",formQosVlan);
#endif


	boaASPDefine("ShowPortMapping", ShowPortMapping);

#ifdef CONFIG_USER_RTK_LBD
	boaASPDefine("initLBDPage", initLBDPage);
	boaFormDefine("formLBD",formLBD);
#endif
#ifdef WEB_UPGRADE
    boaFormDefine("formUpload", formUpload); // Management Upload Firmware Setting Form
#endif
#ifdef SUPPORT_WEB_PUSHUP
	boaFormDefine("formUpgradePop", formUpgradePop);
	boaFormDefine("formUpgradeRedirect", formUpgradeRedirect);
#endif
	boaFormDefine("formSaveConfig",formSaveConfig);
#ifdef CONFIG_RTL_WAPI_SUPPORT
	boaFormDefine("formSaveWapiCert", formSaveWapiCert);
#endif
	boaFormDefine("formVersionMod",formVersionMod);
	boaFormDefine("formExportOMCIlog", formExportOMCIlog);
	boaFormDefine("formImportOMCIShell", formImportOMCIShell);
	boaFormDefine("formTelnetEnable",formTelnetEnable);
	boaFormDefine("formpktmirrorEnable",formpktmirrorEnable);
	boaFormDefine("formPingWAN",formPingWAN);

#ifdef SUPPORT_LOID_BURNING
	boaFormDefine("form_loid_burning", form_loid_burning);
#endif

#if (defined(CONFIG_CMCC) || defined(CONFIG_CU))&&defined(CONFIG_USER_SAMBA)
	boaFormDefine("formSamba", formSamba);
#endif

#ifdef VOIP_SUPPORT
printf("web_voip_init()\n");
	extern int web_voip_init();
	web_voip_init();
#endif /*VOIP_SUPPORT*/
	boaASPDefine("multilang", multilang_asp);
	boaASPDefine("RestoreFactoryMode", RestoreFactoryMode);
#ifdef CONFIG_CT_AWIFI_JITUAN_FEATURE   //awifi
	boaFormDefine("formAwifiStation", formAwifiStation); 
	boaASPDefine("initAwifiNetwork", initAwifiNetwork);
	boaFormDefine("formAwifiNetwork", formAwifiNetwork); 
	boaASPDefine("initAwifiLanAuth", initAwifiLanAuth);
	boaFormDefine("formAwifiLanAuth", formAwifiLanAuth); 
	boaASPDefine("initAwifiSiteServer", initAwifiSiteServer);
	boaFormDefine("formAwifiSiteServer", formAwifiSiteServer); 
	boaASPDefine("initAwifiDefaultServer", initAwifiDefaultServer);
	boaFormDefine("formAwifiDefaultServer", formAwifiDefaultServer); 
	boaASPDefine("initAwifiUpdateCfg", initAwifiUpdateCfg);
	boaFormDefine("formAwifiUpdateCfg", formAwifiUpdateCfg); 	
#endif
#ifdef CONFIG_YUEME
	boaASPDefine("pluginLogList", pluginLogList);
	boaASPDefine("pluginModuleList", pluginModuleList);
	boaASPDefine("listPlatformService", listPlatformService);	
#endif
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	boaASPDefine("show_LAN_status_cmcc",show_LAN_status_cmcc);
#else
	boaASPDefine("show_LAN_status",show_LAN_status);
#endif
#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_SEREnable_
	boaASPDefine("showSER", showSER);
#endif
#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_ErrorCodeEnable_
	boaASPDefine("showErrorCode", showErrorCode);
#endif
#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_PLREnable_
	boaASPDefine("showPLR", showPLR);
#endif
#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_PacketLostEnable_
	boaASPDefine("showPacketLost", showPacketLost);
#endif
#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_RegisterNumberEnable_
	boaASPDefine("showRegisterNumberITMS", showRegisterNumberITMS);
#endif
#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_RegisterSuccessNumberEnable_
	boaASPDefine("showRegisterSuccNumITMS", showRegisterSuccNumITMS);
#endif
#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_RegisterNumberEnable_
	boaASPDefine("showDHCPRegisterNumber", showDHCPRegisterNumber);
#endif
#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_RegisterSuccessNumberEnable_
	boaASPDefine("showDHCPSuccessNumber", showDHCPSuccessNumber);
#endif

#if (defined(CONFIG_CMCC) || defined(CONFIG_CU)) && defined(CONFIG_IPV6)
	boaFormDefine("formIPv6Binding", formIPv6Binding);		//ipv6 address and port or vlan mapping
	boaASPDefine("showIPv6Binding", showIPv6Binding);
	boaFormDefine("formVlanCfg",formVlanCfg);
#endif
#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_LANxStateEnable_
	boaASPDefine("showLANxState", showLANxState);
#endif
#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_UpDataEnable_
	boaASPDefine("showUpData", showUpData);
#endif
#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_DownDataEnable_
	boaASPDefine("showDownData", showDownData);
#endif
#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_LANxWorkBandwidthEnable_
	boaASPDefine("showLANxWorkBandwidth", showLANxWorkBandwidth);
#endif
#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_AllDeviceNumberEnable_
	boaASPDefine("showAllDeviceNumber", showAllDeviceNumber);
#endif
#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_WLANDeviceMACEnable_
	boaASPDefine("showWLANDeviceMAC", showWLANDeviceMAC);
#endif
#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_LANDeviceMACEnable_
	boaASPDefine("showLANDeviceMAC", showLANDeviceMAC);
#endif
#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_DevicePacketLossEnable_
	boaASPDefine("showDevicePacketLoss", showDevicePacketLoss);
#endif
#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_CPURateEnable_
			boaASPDefine("showCPURate", showCPURate);
#endif
#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_MemRateEnable_
			boaASPDefine("showMemRate", showMemRate);
#endif
#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_DialingNumberEnable_
	boaASPDefine("showDialingNumber", showDialingNumber);
#endif
#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_DialingErrorEnable_
	boaASPDefine("showDialingError", showDialingError);
#endif
#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_TEMPEnable_
		boaASPDefine("showTEMP", showTEMP);
#endif
#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_OpticalInPowerEnable_
		boaASPDefine("showOpticalInPower", showOpticalInPower);
#endif
#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_OpticalOutPowerEnable_
		boaASPDefine("showOpticalOutPower", showOpticalOutPower);
#endif
#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_RoutingModeEnable_
		boaASPDefine("showRoutingMode", showRoutingMode);
#endif
#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_RegisterNumberEnable_	
		boaASPDefine("showRegisterOLTNumber", showRegisterOLTNumber);
#endif
#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_RegisterSuccessNumberEnable_
	boaASPDefine("showRegisterOLTSuccNumber", showRegisterOLTSuccNumber);
#endif
#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_MulticastNumberEnable_
		boaASPDefine("showMulticastNumber", showMulticastNumber);
#endif
#ifdef CONFIG_SUPPORT_CAPTIVE_PORTAL
	boaFormDefine("formURLRedirect", formURLRedirect);
#endif
}

#ifdef CONFIG_IPV6
#ifdef CONFIG_USER_RADVD
void initRadvdConfPage(request * wp)
{
	unsigned char vChar;

	mib_get( MIB_V6_PREFIX_ENABLE, (void *)&vChar);
	if( vChar == 1)
	{
		mib_get( MIB_V6_PREFIX_MODE, (void *)&vChar);
		boaWrite(wp, "%s.radvd.PrefixMode.value = %d;\n", DOCUMENT, vChar);
		boaWrite(wp, "updateInput();\n");
	}
}
#endif
#endif

void initLanPage(request * wp)
{
	unsigned char vChar;
#ifdef CONFIG_SECONDARY_IP
	char dhcp_pool;
#endif
#ifdef CONFIG_RTK_L34_ENABLE
	unsigned int port_mask;
	unsigned char prefix_len;
	struct ipv6_ifaddr ip6_addr[6];
	char tmpBuf[128];
#endif

#ifdef CONFIG_SECONDARY_IP
	mib_get( MIB_ADSL_LAN_ENABLE_IP2, (void *)&vChar);
	if (vChar!=0) {
		//boaWrite(wp, "%s.tcpip.enable_ip2.value = 1;\n", DOCUMENT);
		boaWrite(wp, "%s.tcpip.enable_ip2.checked = true;\n", DOCUMENT);
	}
	#ifndef DHCPS_POOL_COMPLETE_IP
	mib_get(MIB_ADSL_LAN_DHCP_POOLUSE, (void *)&dhcp_pool);
	boaWrite(wp, "%s.tcpip.dhcpuse[%d].checked = true;\n", DOCUMENT, dhcp_pool);
	#endif
	boaWrite(wp, "updateInput();\n");
#endif

#if defined(CONFIG_RTL_IGMP_SNOOPING)
	mib_get( MIB_MPMODE, (void *)&vChar);
	// bitmap for virtual lan port function
	// Port Mapping: bit-0
	// QoS : bit-1
	// IGMP snooping: bit-2
	boaWrite(wp, "%s.tcpip.snoop[%d].checked = true;\n", DOCUMENT, (vChar>>MP_IGMP_SHIFT)&0x01);
#ifdef CONFIG_IGMP_FORBID
	mib_get( MIB_IGMP_FORBID_ENABLE, (void *)&vChar);
	boaWrite(wp, "%s.tcpip.igmpforbid[%d].checked = true;\n", DOCUMENT, vChar);
#endif
#endif

#ifdef WLAN_SUPPORT
	mib_get( MIB_WLAN_BLOCK_ETH2WIR, (void *)&vChar);
	boaWrite(wp, "%s.tcpip.BlockEth2Wir[%d].checked = true;\n", DOCUMENT, vChar==0?0:1);
#endif

#ifdef CONFIG_RTK_L34_ENABLE
	mib_get(MIB_MAC_BASED_TAG_DECISION, (void *)&vChar);
	boaWrite(wp, "%s.tcpip.mac_based_tag_decision[%d].checked = true;\n", DOCUMENT, vChar==0?0:1);

	mib_get(MIB_LAN_PORT_MASK1, (void *)&port_mask);
	if(port_mask & (1<<RTK_RG_MAC_PORT0))
		boaWrite(wp, "%s.tcpip.chk_port_mask1[0].checked = true;\n", DOCUMENT);

	if(port_mask & (1<<RTK_RG_MAC_PORT1))
		boaWrite(wp, "%s.tcpip.chk_port_mask1[1].checked = true;\n", DOCUMENT);
#ifndef CONFIG_RTL9602C_SERIES
	if(port_mask & (1<<RTK_RG_MAC_PORT2))
		boaWrite(wp, "%s.tcpip.chk_port_mask1[2].checked = true;\n", DOCUMENT);

	if(port_mask & (1<<RTK_RG_MAC_PORT3))
		boaWrite(wp, "%s.tcpip.chk_port_mask1[3].checked = true;\n", DOCUMENT);
#endif
	mib_get(MIB_LAN_IP_VERSION1, (void *)&vChar);
	boaWrite(wp, "%s.tcpip.ip_version1.options[%d].selected = true;\n", DOCUMENT, vChar);

	if(vChar == 0) // IP version is IPv4
	{
		boaWrite(wp, "%s.tcpip.ipv6_mode1[0].disabled = true;\n", DOCUMENT);
		boaWrite(wp, "%s.tcpip.ipv6_mode1[1].disabled = true;\n", DOCUMENT);
		boaWrite(wp, "%s.tcpip.ipv6_addr1.disabled = true;\n", DOCUMENT);
		boaWrite(wp, "%s.tcpip.ipv6_prefix1.disabled = true;\n", DOCUMENT);
	}
#ifdef CONFIG_IPV6
	else if(vChar == 1) // IP version is IPv6
	{
		boaWrite(wp, "%s.tcpip.ip.disabled = true;\n", DOCUMENT);
		boaWrite(wp, "%s.tcpip.mask.disabled = true;\n", DOCUMENT);
	}

	mib_get(MIB_LAN_IPV6_MODE1, (void *)&vChar);
	boaWrite(wp, "%s.tcpip.ipv6_mode1[%d].checked = true;\n", DOCUMENT, vChar);

	if(vChar == 0)  // IPv6 mode is auto
	{
		boaWrite(wp, "%s.tcpip.ipv6_addr1.disabled = true;\n", DOCUMENT);
		boaWrite(wp, "%s.tcpip.ipv6_prefix1.disabled = true;\n", DOCUMENT);
		getifip6((char *)LANIF, IPV6_ADDR_UNICAST, ip6_addr, 6);
		inet_ntop(PF_INET6, &ip6_addr[0].addr, tmpBuf, 128);
		boaWrite(wp, "%s.tcpip.ipv6_addr1.value = \"%s\";\n", DOCUMENT, tmpBuf);
		boaWrite(wp, "%s.tcpip.ipv6_prefix1.value = \"%d\";\n", DOCUMENT, ip6_addr[0].prefix_len);
	}
	else
	{
		mib_get(MIB_LAN_IPV6_ADDR1, (void *)&ip6_addr[0].addr);
		mib_get(MIB_LAN_IPV6_PREFIX_LEN1, (void *)&vChar);
		inet_ntop(PF_INET6, &ip6_addr[0].addr, tmpBuf, 128);
		boaWrite(wp, "%s.tcpip.ipv6_addr1.value = \"%s\";\n", DOCUMENT, tmpBuf);
		boaWrite(wp, "%s.tcpip.ipv6_prefix1.value = \"%u\";\n", DOCUMENT, vChar);
	}
#else
	boaWrite(wp, "%s.getElementById(\"tr_ipv6_mode1\").style.display = \"none\";\n", DOCUMENT);
	boaWrite(wp, "%s.getElementById(\"tr_ipv6_addr1\").style.display = \"none\";\n", DOCUMENT);
	boaWrite(wp, "%s.getElementById(\"tr_ipv6_prefix1\").style.display = \"none\";\n", DOCUMENT);
	boaWrite(wp, "%s.tcpip.ip_version1.disabled = true;\n", DOCUMENT);
#endif

#ifdef CONFIG_SECONDARY_IP
	mib_get(MIB_LAN_PORT_MASK2, (void *)&port_mask);
	if(port_mask & (1<<RTK_RG_MAC_PORT0))
		boaWrite(wp, "%s.tcpip.chk_port_mask2[0].checked = true;\n", DOCUMENT);

	if(port_mask & (1<<RTK_RG_MAC_PORT1))
		boaWrite(wp, "%s.tcpip.chk_port_mask2[1].checked = true;\n", DOCUMENT);
#ifndef CONFIG_RTL9602C_SERIES
	if(port_mask & (1<<RTK_RG_MAC_PORT2))
		boaWrite(wp, "%s.tcpip.chk_port_mask2[2].checked = true;\n", DOCUMENT);

	if(port_mask & (1<<RTK_RG_MAC_PORT3))
		boaWrite(wp, "%s.tcpip.chk_port_mask2[3].checked = true;\n", DOCUMENT);
#endif
	mib_get(MIB_LAN_IP_VERSION2, (void *)&vChar);
	boaWrite(wp, "%s.tcpip.ip_version2.options[%d].selected = true;\n", DOCUMENT, vChar);

	if(vChar == 0) // IP version is IPv4
	{
		boaWrite(wp, "%s.tcpip.ipv6_mode2[0].disabled = true;\n", DOCUMENT);
		boaWrite(wp, "%s.tcpip.ipv6_mode2[1].disabled = true;\n", DOCUMENT);
		boaWrite(wp, "%s.tcpip.ipv6_addr2.disabled = true;\n", DOCUMENT);
		boaWrite(wp, "%s.tcpip.ipv6_prefix2.disabled = true;\n", DOCUMENT);
	}
#ifdef CONFIG_IPV6
	else if(vChar == 1) // IP version is IPv6
	{
		boaWrite(wp, "%s.tcpip.ip2.disabled = true;\n", DOCUMENT);
		boaWrite(wp, "%s.tcpip.mask2.disabled = true;\n", DOCUMENT);
	}

	mib_get(MIB_LAN_IPV6_MODE2, (void *)&vChar);
	boaWrite(wp, "%s.tcpip.ipv6_mode2[%d].checked = true;\n", DOCUMENT, vChar);

	if(vChar == 0) // IPv6 mode is auto
	{
		boaWrite(wp, "%s.tcpip.ipv6_addr2.disabled = true;\n", DOCUMENT);
		boaWrite(wp, "%s.tcpip.ipv6_prefix2.disabled = true;\n", DOCUMENT);
		getifip6((char *)LAN_ALIAS, IPV6_ADDR_UNICAST, ip6_addr, 6);
		inet_ntop(PF_INET6, &ip6_addr[0].addr, tmpBuf, 128);
		boaWrite(wp, "%s.tcpip.ipv6_addr2.value = \"%s\";\n", DOCUMENT, tmpBuf);
		boaWrite(wp, "%s.tcpip.ipv6_prefix2.value = \"%d\";\n", DOCUMENT, ip6_addr[0].prefix_len);
	}
	else
	{
		mib_get(MIB_LAN_IPV6_ADDR2, (void *)&ip6_addr[0].addr);
		mib_get(MIB_LAN_IPV6_PREFIX_LEN2, (void *)&vChar);
		inet_ntop(PF_INET6, &ip6_addr[0].addr, tmpBuf, 128);
		boaWrite(wp, "%s.tcpip.ipv6_addr2.value = \"%s\";\n", DOCUMENT, tmpBuf);
		boaWrite(wp, "%s.tcpip.ipv6_prefix2.value = \"%u\";\n", DOCUMENT, vChar);
	}
#endif

	// Magician: RG restriction, 2nd IP only support v4 currently.
	boaWrite(wp, "%s.tcpip.ip_version2.disabled = true;\n", DOCUMENT);
#endif
#endif
}

#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
void initIgmpMldSnoopPage(request * wp)
{
	unsigned char vChar;
	mib_get(MIB_IGMP_MLD_SNOOPING, &vChar);
	boaWrite(wp, "%s.igmpMldSnoop.chkIgmpMldSnp.checked = %s;\n", DOCUMENT, vChar?"true":"false");
}
void initIgmpMldProxyPage(request * wp)
{
	unsigned char vChar;
	mib_get(MIB_IGMP_MLD_PROXY, &vChar);
	boaWrite(wp, "%s.igmpMldProxy.chkIgmpMldProxy.checked = %s;\n", DOCUMENT, vChar?"true":"false");
}
#endif
// Mason Yu. IGMP snooping for e8b
void initIgmpsnoopPage(request * wp)
{
	unsigned char vChar;

#if defined(CONFIG_RTL_IGMP_SNOOPING)
	mib_get( MIB_MPMODE, (void *)&vChar);
	// bitmap for virtual lan port function
	// Port Mapping: bit-0
	// QoS : bit-1
	// IGMP snooping: bit-2
	boaWrite(wp, "%s.igmpsnoop.snoop[%d].checked = true;\n", DOCUMENT, (vChar>>MP_IGMP_SHIFT)&0x01);
#endif
}

//Martin ZHU US/DS Bandwidth Monitor
#ifdef CONFIG_USER_LAN_BANDWIDTH_MONITOR
void initBandwidthMonitorPage(request * wp)
{
	unsigned char vChar;
	mib_get( MIB_LANHOST_BANDWIDTH_MONITOR_ENABLE, (void *)&vChar);
	boaWrite(wp, "%s.bandwidthmonitor.monitor[%d].checked = true;\n", DOCUMENT, vChar);
}

void initBandwidthIntervalPage(request * wp)
{
	unsigned int bdw_interval;
	mib_get( MIB_LANHOST_BANDWIDTH_INTERVAL, (void *)&bdw_interval);
	boaWrite(wp, "%s.bandwidthmonitor.bdw_interval.value = %d;\n", DOCUMENT, bdw_interval);
}
#endif


#ifdef CONFIG_IPV6
void initMLDsnoopPage(request * wp)
{
	unsigned char vChar;
#if defined(CONFIG_RTL_IGMP_SNOOPING)
	mib_get( MIB_MPMODE, (void *)&vChar);
	// bitmap for virtual lan port function
	// Port Mapping: bit-0
	// QoS : bit-1
	// IGMP snooping: bit-2
	// MLD snooping: bit-3
	boaWrite(wp, "%s.mldsnoop.snoop[%d].checked = true;\n", DOCUMENT, (vChar>>MP_MLD_SHIFT)&0x01);
#endif
}
#endif


#ifdef PORT_TRIGGERING
int portTrgList(request * wp)
{
	unsigned int entryNum, i;
	MIB_CE_PORT_TRG_T Entry;
	char	*type, portRange[20], *ip;

	entryNum = mib_chain_total(MIB_PORT_TRG_TBL);

	boaWrite(wp,"<tr><td bgColor=#808080>%s</td><td bgColor=#808080>%s</td>"
		"<td bgColor=#808080>TCP %s</td><td bgColor=#808080>UDP %s</td><td bgColor=#808080>%s</td><td bgColor=#808080>%s</td></tr>\n",
	multilang_bpas("Name"), multilang_bpas("IP Address"), multilang_bpas("Port to Open"),
	multilang_bpas("Port to Open"), multilang_bpas("Enable"), multilang_bpas("Action"));

	for (i=0; i<entryNum; i++) {
		if (!mib_chain_get(MIB_PORT_TRG_TBL, i, (void *)&Entry))
		{
  			boaError(wp, 400, "Get chain record error!\n");
			return -1;
		}

		//Name
		boaWrite(wp,"<tr><td bgColor=#C0C0C0>%s</td>\n",Entry.name);

		//IP
		boaWrite(wp,"<td bgColor=#C0C0C0>%s</td>\n",inet_ntoa(*((struct in_addr *)Entry.ip)));

		//TCP port to open
		boaWrite(wp,"<td bgColor=#C0C0C0>%s</td>\n",Entry.tcpRange);

		//UDP port to open
		boaWrite(wp,"<td bgColor=#C0C0C0>%s</td>\n",Entry.udpRange);

		//Enable
		boaWrite(wp,"<td bgColor=#C0C0C0>%s</td>\n",(Entry.enable==1)?"Enable":"Disable");

		//Action
		boaWrite(wp,"<td bgColor=#C0C0C0>");
		boaWrite(wp,
		"<a href=\"#?edit\" onClick=\"editClick(%d)\">"
		"<image border=0 src=\"graphics/edit.gif\" alt=\"Post for editing\" /></a>", i);

		boaWrite(wp,
		"<a href=\"#?delete\" onClick=\"delClick(%d)\">"
		"<image border=0 src=\"graphics/del.gif\" alt=Delete /></td></tr>\n", i);
	}

	return 0;
}

int gm_postIndex=-1;

void initGamingPage(request * wp)
{
	char *ipaddr;
	char *idx;
	int del;
	char ipaddr2[16]={0};
	MIB_CE_PORT_TRG_T Entry;
	int found=0;

	ipaddr=boaGetVar(wp,"ip","");
	idx=boaGetVar(wp,"idx","");
	del=atoi(boaGetVar(wp,"del",""));

	if (gm_postIndex >= 0) { // post this entry
		if (!mib_chain_get(MIB_PORT_TRG_TBL, gm_postIndex, (void *)&Entry))
			found = 0;
		else
			found = 1;
		gm_postIndex = -1;
	}

	if(del!=0)
	{
		boaWrite(wp,
		"<body onLoad=\"document.formname.submit()\">");
	}
	else
	{
		boaWrite(wp,
		"<body bgcolor=\"#ffffff\" text=\"#000000\" onLoad=\"javascript:formLoad();\">");
		boaWrite(wp, "<blockquote><h2><font color=\"#0000FF\">%s%s</font></h2>\n",
		multilang_bpas("Port Triggering"), multilang_bpas(" Configuration"));
		boaWrite(wp, "<table border=0 width=850 cellspacing=4 cellpadding=0><tr><td><hr size=1 noshade align=top></td></tr>\n");
		//<b>%s Game Rule</b>%s",(strlen(idx)==0)?"Add":"Edit",(strlen(idx)==0)?"":" [<a href=\"gaming.asp\">Add New</a>]");
	}


	boaWrite(wp,
	"<form action=/boaform/formGaming method=POST name=formname>\n");

	if(del!=0)
	{
		int i=atoi(idx);
		boaWrite(wp,"<input type=hidden name=idx value=\"%d\">",i);
		boaWrite(wp,"<input type=hidden name=del value=1></form>");
		return;
	}

	boaWrite(wp,
	"<table width=850 cellSpacing=1 cellPadding=2 border=0>\n" \
	"<tr><font size=2><td bgColor=#808080>%s</td><td bgColor=#808080>%s</td><td bgColor=#808080>TCP %s</td><td bgColor=#808080>UDP %s</td><td bgColor=#808080>%s</td></tr>\n",
	multilang_bpas("Name"), multilang_bpas("IP Address"), multilang_bpas("Port to Open"),
	multilang_bpas("Port to Open"), multilang_bpas("Enable"));

	boaWrite(wp,
	"<tr><td bgColor=#C0C0C0><font size=2><input type=text name=\"game\" size=16  maxlength=20 value=\"%s\">&lt;&lt; <select name=\"gamelist\" onChange=\"javascript:changeItem();\"></select></td>" \
	"<td bgColor=#C0C0C0><input type=text name=\"ip\" size=12  maxlength=15 value=\"%s\"></td>" \
	"<td bgColor=#C0C0C0><input type=text name=\"tcpopen\" size=20  maxlength=31 value=\"%s\"></td>" \
	"<td bgColor=#C0C0C0><input type=text name=\"udpopen\" size=20  maxlength=31 value=\"%s\"></td>" \
	"<td bgColor=#C0C0C0><input type=checkbox name=\"open\" value=1 %s></td>" \
	"<input type=hidden name=idx value=%s>" \
	"</tr></table>\n",
	found ? (char *)Entry.name : "",
	found ? (char *)inet_ntoa(*((struct in_addr *)Entry.ip)) : "0.0.0.0",
	found ? (char *)Entry.tcpRange : "",
	found ? (char *)Entry.udpRange : "",
	found ? (Entry.enable == 1 ? multilang_bpas("Checked") :"") : "",
	(strlen(idx)==0)?"-1":idx
	);

	boaWrite(wp,
	"<input type=submit value=%s name=add onClick=\"return addClick()\">&nbsp;&nbsp;&nbsp;&nbsp;" \
	"<input type=submit value=%s name=modify onClick=\"return addClick()\">&nbsp;&nbsp;&nbsp;&nbsp;" \
	"<input type=reset value=%s><BR><BR>\n",
	multilang_bpas("Add"), multilang_bpas("Modify"), multilang_bpas("Reset"));
	boaWrite(wp,
	"<input type=hidden value=/gaming.asp name=submit-url>");

	boaWrite(wp,
	"<b>%s</b>\n" \
//	"<input type=hidden name=ms value=%d>\n" \
/*	"onSubmit=\"return checkRange();\"" \ */
	"<table cellSpacing=1 cellPadding=2 border=0>\n", multilang_bpas("Game Rules List"));

	portTrgList(wp);

	boaWrite(wp, "</form>\n");
}
#endif

#ifdef CONFIG_USER_ROUTED_ROUTED
void initRipPage(request * wp)
{
	if (ifWanNum("rt") ==0) {
		boaWrite(wp, "%s.rip.rip_on[0].disabled = true;\n", DOCUMENT);
		boaWrite(wp, "\t%s.rip.rip_on[1].disabled = true;\n", DOCUMENT);
		boaWrite(wp, "\t%s.rip.rip_ver.disabled = true;\n", DOCUMENT);
		boaWrite(wp, "\t%s.rip.rip_if.disabled = true;\n", DOCUMENT);
		boaWrite(wp, "\t%s.rip.ripAdd.disabled = true;\n", DOCUMENT);
		boaWrite(wp, "\t%s.rip.ripSet.disabled = true;\n", DOCUMENT);
		boaWrite(wp, "\t%s.rip.ripReset.disabled = true;", DOCUMENT);
	}
	boaWrite(wp, "\t%s.rip.ripDel.disabled = true;\n", DOCUMENT);
}
#endif

// Mason Yu. combine_1p_4p_PortMapping
#ifdef ITF_GROUP
void initPortMapPage(request * wp)
{
	unsigned char vChar;

	mib_get( MIB_MPMODE, (void *)&vChar);
	boaWrite(wp, "%s.eth2pvc.pmap[%d].checked = true;\n", DOCUMENT, (vChar>>MP_PMAP_SHIFT)&0x01);
}

#endif

#if defined(CONFIG_RTL_MULTI_LAN_DEV)
#ifdef ELAN_LINK_MODE
void initLinkPage(request * wp)
{
	unsigned int entryNum, i;
	MIB_CE_SW_PORT_T Entry;
	char ports[]="p0";

	entryNum = mib_chain_total(MIB_SW_PORT_TBL);

	if (entryNum >= SW_LAN_PORT_NUM)
		entryNum = SW_LAN_PORT_NUM;

	for (i=0; i<entryNum; i++) {
		if (mib_chain_get(MIB_SW_PORT_TBL, i, (void *)&Entry)) {
			ports[1]=i + '0';
			boaWrite(wp, "%s.link.%s.value = %d;\n", DOCUMENT, ports, Entry.linkMode);
		}
	}
}
#endif

#else
#ifdef ELAN_LINK_MODE_INTRENAL_PHY
void initLinkPage(request * wp)
{

	unsigned int entryNum, i;
	//MIB_CE_SW_PORT_T Entry;
	char ports[]="p0";
	unsigned char mode;

	//entryNum = mib_chain_total(MIB_SW_PORT_TBL);
	if (mib_get(MIB_ETH_MODE, &mode)) {
		boaWrite(wp, "%s.link.%s.value = %d;\n", DOCUMENT, ports, mode);
	}
}

#endif
#endif	// CONFIG_RTL_MULTI_LAN_DEV

void initIpQosPage(request * wp)
{
#if defined(IP_QOS) || defined(NEW_IP_QOS_SUPPORT)
	unsigned char vChar;
	unsigned int entryNum;
#ifdef NEW_IP_QOS_SUPPORT
	unsigned char policy;
#endif
#ifdef QOS_DIFFSERV
	unsigned char qosDomain;

	mib_get(MIB_QOS_DIFFSERV, (void *)&qosDomain);
	mib_get(MIB_MPMODE, (void *)&vChar);
	if (qosDomain == 1)
		boaWrite(wp, "%s.qos.qosen[0].checked = true;\n", DOCUMENT);
	else
		boaWrite(wp, "%s.qos.qosen[%d].checked = true;\n", DOCUMENT, (vChar>>MP_IPQ_SHIFT)&0x01);
#else

	mib_get( MIB_MPMODE, (void *)&vChar);
	boaWrite(wp, "%s.qos.qosen[%d].checked = true;\n", DOCUMENT, (vChar>>MP_IPQ_SHIFT)&0x01);
#endif

#ifdef NEW_IP_QOS_SUPPORT
	mib_get( MIB_QOS_POLICY, (void *)&policy);
	boaWrite(wp, "%s.qos.qosPolicy[%d].checked = true;\n", DOCUMENT, policy&0x01);
#endif
	/*
	if (!(vChar&0x02)) { // IP Qos not enabled
		boaWrite(wp, "%s.qos.sip.disabled = true;\n", DOCUMENT);
		boaWrite(wp, "%s.qos.smask.disabled = true;\n", DOCUMENT);
		boaWrite(wp, "%s.qos.dip.disabled = true;\n", DOCUMENT);
		boaWrite(wp, "%s.qos.dmask.disabled = true;\n", DOCUMENT);
		boaWrite(wp, "%s.qos.sport.disabled = true;\n", DOCUMENT);
		boaWrite(wp, "%s.qos.dport.disabled = true;\n", DOCUMENT);
		boaWrite(wp, "%s.qos.prot.disabled = true;\n", DOCUMENT);
		boaWrite(wp, "%s.qos.phyport.disabled = true;\n", DOCUMENT);
		boaWrite(wp, "%s.qos.out_if.disabled = true;\n", DOCUMENT);
		boaWrite(wp, "%s.qos.prio.disabled = true;\n", DOCUMENT);
		boaWrite(wp, "%s.qos.ipprio.disabled = true;\n", DOCUMENT);
		boaWrite(wp, "%s.qos.tos.disabled = true;\n", DOCUMENT);
		boaWrite(wp, "%s.qos.m1p.disabled = true;\n", DOCUMENT);
		boaWrite(wp, "%s.qos.addqos.disabled = true;\n", DOCUMENT);
	}
	*/
#ifdef QOS_SPEED_LIMIT_SUPPORT
	if ((vChar&0x02)) { // IP Qos  enabled
		boaWrite(wp,"document.getElementById('pvcbandwidth').style.display = 'block';\n");
		unsigned short bandwidth;
		mib_get(MIB_PVC_TOTAL_BANDWIDTH,&bandwidth);
		printf("bandwidth=%d\n",bandwidth);
		boaWrite(wp,"document.upbandwidthfm.upbandwidth.value=%d;",bandwidth);

	}
#endif
	if (ifWanNum("all") == 0)
		boaWrite(wp, "%s.qos.addqos.disabled = true;\n", DOCUMENT);

	entryNum = mib_chain_total(MIB_IP_QOS_TBL);
	if (entryNum == 0) {
		boaWrite(wp, "%s.qostbl.delSel.disabled = true;\n", DOCUMENT);
		boaWrite(wp, "%s.qostbl.delAll.disabled = true;\n", DOCUMENT);
	}


//#ifndef IP_QOS_VPORT
#ifndef CONFIG_RE8305
	mib_get( MIB_QOS_DOMAIN, (void *)&vChar);
	boaWrite(wp, "%s.qos.qosdmn.value = %d;\n", DOCUMENT, vChar);
#ifdef CONFIG_8021P_PRIO
	boaWrite(wp, "enable8021psetting();\n");
#endif
#endif
//#endif
#endif
}

#ifdef QOS_DIFFSERV
void initDiffservPage(request * wp)
{
	unsigned char vChar, phbclass;
	unsigned int entryNum, i;
	MIB_CE_IP_QOS_T Entry;

	mib_get(MIB_QOS_DIFFSERV, (void *)&vChar);
	mib_get(MIB_DIFFSERV_PHBCLASS, (void *)&phbclass);
	boaWrite(wp, "%s.diffserv.qoscap[%d].checked = true;\n", DOCUMENT, vChar);
	entryNum = mib_chain_total(MIB_IP_QOS_TBL);
	for (i=0; i<entryNum; i++) {
		if (!mib_chain_get(MIB_IP_QOS_TBL, i, (void *)&Entry)) {
  			boaError(wp, 400, "Get chain record error!\n");
			return;
		}
		if (Entry.enDiffserv == 0) // IP QoS entry
			continue;
		if (Entry.m_ipprio != phbclass) // only get active PHB class
			continue;
		boaWrite(wp, "%s.diffserv.totalbandwidth.value = %d;\n", DOCUMENT, Entry.totalBandwidth);
		boaWrite(wp, "%s.diffserv.htbrate.value = %d;\n", DOCUMENT, Entry.htbRate);
		boaWrite(wp, "%s.diffserv.latency.value = %d;\n", DOCUMENT, Entry.latency);
		boaWrite(wp, "%s.diffserv.phbclass.value = %d;\n", DOCUMENT, phbclass);
		boaWrite(wp, "%s.diffserv.interface.value = %d;\n", DOCUMENT, Entry.ifIndex);
		return;
	}
}
#endif

#if defined(IP_QOS) || defined(NEW_IP_QOS_SUPPORT)
void initQosQueue(request * wp)
{
	unsigned int entryNumAtmVC, j;
	MIB_CE_ATM_VC_T Entry_atmVC;
	int enable_IPQoS=0;
	char qosQueue[16],qosItfList[128];
	MEDIA_TYPE_T mType;

	qosItfList[0]='\0';
	entryNumAtmVC = mib_chain_total(MIB_ATM_VC_TBL);
	for (j=0; j<entryNumAtmVC; j++) {
		if (!mib_chain_get(MIB_ATM_VC_TBL, j, (void *)&Entry_atmVC))
			continue;
		if (Entry_atmVC.enableIpQos == 1 ) {
			mType = MEDIA_INDEX(Entry_atmVC.ifIndex);
			enable_IPQoS = 1;
			if (mType == MEDIA_ATM)
				sprintf(qosQueue,"%d,%d_%d",Entry_atmVC.ifIndex,Entry_atmVC.vpi,Entry_atmVC.vci);
			else if (mType == MEDIA_ETH)
				sprintf(qosQueue,"%d,%s%d",Entry_atmVC.ifIndex,ALIASNAME_NAS, ETH_INDEX(Entry_atmVC.ifIndex));			
			else
				sprintf(qosQueue,"%d,unknown%d",Entry_atmVC.ifIndex,ETH_INDEX(Entry_atmVC.ifIndex));

			if(strlen(qosItfList))
				strcat(qosItfList,";");
			strcat(qosItfList,qosQueue);
		}
	}
	boaWrite(wp,"qDesclist=\"%s\";\n",qosItfList);
	boaWrite(wp,"%s.qos.check.value=\"%d\";\n", DOCUMENT, enable_IPQoS);
}
#endif

void initOthersPage(request * wp)
{
	unsigned int vInt;
	unsigned char vChar;

#ifdef IP_PASSTHROUGH
	mib_get( MIB_IPPT_ITF, (void *)&vInt);
	//if (vInt == 0xff) {
	if (vInt == DUMMY_IFINDEX) {
		boaWrite(wp, "%s.others.ltime.disabled = true;\n", DOCUMENT);
		boaWrite(wp, "%s.others.lan_acc.disabled = true;\n", DOCUMENT);
	}

	mib_get( MIB_IPPT_LANACC, (void *)&vChar);
	if (vChar == 1)
		boaWrite(wp, "%s.others.lan_acc.checked = true\n", DOCUMENT);
#endif
}

#ifdef WLAN_SUPPORT

#ifdef WLAN_WPA
void initWlWpaPage(request * wp)
{
	unsigned char buffer[255];
	MIB_CE_MBSSIB_T Entry;
	mib_chain_get(MIB_MBSSIB_TBL, 0, &Entry);

	boaWrite(wp, "%s.formEncrypt.pskFormat.value = %d;\n", DOCUMENT, Entry.wpaPSKFormat);

#ifdef WLAN_1x
	if(Entry.wep!=0)
		boaWrite(wp, "%s.formEncrypt.wepKeyLen[%d].checked = true;\n", DOCUMENT, Entry.wep-1);

	if(Entry.enable1X==1)
		boaWrite(wp, "%s.formEncrypt.use1x.checked = true;\n", DOCUMENT);
	boaWrite(wp, "%s.formEncrypt.wpaAuth[%d].checked = true;\n", DOCUMENT, Entry.wpaAuth-1);
#else
	boaWrite(wp, "%s.formEncrypt.wpaAuth.disabled = true;\n", DOCUMENT);
	boaWrite(wp, "%s.formEncrypt.wepKeyLen.disabled = true;\n", DOCUMENT);
	boaWrite(wp, "%s.formEncrypt.use1x.disabled = true;\n", DOCUMENT);

#endif
}
#endif

void initWlBasicPage(request * wp)
{
	unsigned char vChar;
	MIB_CE_MBSSIB_T Entry;
	wlan_getEntry(&Entry, 0);

#ifdef WLAN_UNIVERSAL_REPEATER
	boaWrite(wp, "%s.getElementById(\"repeater_check\").style.display = \"\";\n", DOCUMENT);
	boaWrite(wp, "%s.getElementById(\"repeater_SSID\").style.display = \"\";\n", DOCUMENT);
#endif
	if (Entry.wlanDisabled!=0)
		// hidden type
		boaWrite(wp, "%s.wlanSetup.wlanDisabled.value = \"ON\";\n", DOCUMENT);
		// checkbox type
		//boaWrite(wp, "%s.wlanSetup.wlanDisabled.checked = true;\n", DOCUMENT);
	boaWrite(wp, "%s.wlanSetup.band.value = %d;\n", DOCUMENT, Entry.wlanBand-1);
	mib_get( MIB_WLAN_CHANNEL_WIDTH,(void *)&vChar);
	boaWrite(wp, "%s.wlanSetup.chanwid.value = %d;\n", DOCUMENT, vChar);
	mib_get( MIB_WLAN_CONTROL_BAND,(void *)&vChar);
	boaWrite(wp, "%s.wlanSetup.ctlband.value = %d;\n", DOCUMENT, vChar);
	mib_get( MIB_TX_POWER, (void *)&vChar);
	boaWrite(wp, "%s.wlanSetup.txpower.selectedIndex = %d;\n", DOCUMENT, vChar);

}

void initWlE8BasicPage(request * wp)
{
	int i;
#if defined(CONFIG_RTL_92D_SUPPORT) || defined(WLAN_DUALBAND_CONCURRENT)
	int orig_wlan_idx = wlan_idx;
#endif
	char ssid[36];
	char txPower;
	unsigned int vUInt;
	bss_info bss;

	//cathy
	unsigned char vChar,vChar2;
	unsigned char buffer[10];
	//unsigned char strbf[20];
#define RTL8185_IOCTL_GET_MIB 0x89f2
	int skfd;
	struct iwreq wrq;
	int ret;
	struct _misc_data_ misc_data;
	struct user_info * pUser_info;
	MIB_CE_MBSSIB_T Entry;
#if defined(WLAN_DUALBAND_CONCURRENT) && defined(CONFIG_RTL_STA_CONTROL_SUPPORT)
	unsigned char wlan_disabled=0;
	unsigned char wlan_phyband=0;
#endif
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	MIB_CE_MBSSIB_T Entry2;
	unsigned short uShort=0;
	struct stat run_status;
#endif

	pUser_info = search_login_list(wp);

#if defined(CONFIG_RTL_92D_SUPPORT)
	mib_get(MIB_WLAN_BAND2G5G_SELECT, (void *)&vChar);
	boaWrite(wp, "wlBandMode=%d;\n", vChar);
#elif defined(WLAN0_5G_SUPPORT) && !defined(WLAN_DUALBAND_CONCURRENT)
	boaWrite(wp, "wlBandMode=1;\n");
#endif

#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	for(i=0; i<NUM_WLAN_INTERFACE;i++){
		wlan_idx = i;

		if(!wlan_getEntry(&Entry, 0))
			continue;

		if(!wlan_getEntry(&Entry2, 1))
			continue;
#else
	for(i=0; i<=NUM_VWLAN_INTERFACE;i++){
		//wlan_idx = i;

		if(!wlan_getEntry(&Entry, i))
			continue;
		if((i!=0 
#ifdef CTCOM_WLAN_REQ
			&& Entry.instnum==0
#endif
		)
#ifdef _PRMT_X_WLANFORISP_
		|| ( i!=0 && isWLANForISP(i))
#endif
		)
			continue;
#endif
#if !defined(CONFIG_CMCC) && !defined(CONFIG_CU)
		if(pUser_info->priv)//admin
#endif
		{
			mib_get( MIB_WLAN_PHY_BAND_SELECT, (void *)&vChar);
			boaWrite(wp, "_Band2G5GSupport[%d]=%d;\n", i, vChar);
#if defined(WLAN_DUALBAND_CONCURRENT) && defined(CONFIG_RTL_STA_CONTROL_SUPPORT)
			wlan_phyband = vChar;
#endif
			#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
			boaWrite(wp, "_Band2G5GSupport[%d]=%d;\n", i+2, vChar);
			#endif

#ifdef WLAN_11K
			boaWrite(wp, "_wlan_11k[%d]=%u;\n", i, Entry.rm_activated);
			#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
			boaWrite(wp, "_wlan_11k[%d]=%u;\n", i+2, Entry2.rm_activated);
			#endif
#endif
#ifdef WLAN_11V
			boaWrite(wp, "_wlan_11v[%d]=%u;\n", i, Entry.BssTransEnable);
			#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
			boaWrite(wp, "_wlan_11v[%d]=%u;\n", i+2, Entry2.BssTransEnable);
			#endif
#endif
		}

		getWlBssInfo(getWlanIfName(), &bss);
		boaWrite(wp, "_bssid[%d]='%02x:%02x:%02x:%02x:%02x:%02x';\n",
			i, bss.bssid[0], bss.bssid[1], bss.bssid[2],
			bss.bssid[3], bss.bssid[4], bss.bssid[5]);
		#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		boaWrite(wp, "_bssid[%d]='%02x:%02x:%02x:%02x:%02x:%02x';\n",
			i+2, bss.bssid[0], bss.bssid[1], bss.bssid[2],
			bss.bssid[3], bss.bssid[4], bss.bssid[5]);
		#endif
		//	bssid
		//	mib_get(MIB_ELAN_MAC_ADDR, (void *)buffer);
		//	snprintf(strbf, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
		//				buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5]);
		//	boaWrite(wp, "_bssid[%d]='%s';\n", i, strbf);
		//	dbg("cgi_wlBssid = %s\n", (void *)strbf);

		//get wlanDisable
		vChar = Entry.wlanDisabled;
		boaWrite(wp, "_wlanEnabled[%d]=%s;\n", i, vChar ? "false" : "true");
		#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		vChar = Entry2.wlanDisabled;
		boaWrite(wp, "_wlanEnabled[%d]=%s;\n", i+2, vChar ? "false" : "true");
		#endif
		//dbg("MIB_WLAN_DISABLED=%d\n", wlanDisable);
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
#if defined(WLAN_DUALBAND_CONCURRENT) && defined(CONFIG_RTL_STA_CONTROL_SUPPORT)
		wlan_disabled|=vChar;
#endif
#endif

		//get hiddenSSID
		vChar = Entry.hidessid;
		boaWrite(wp, "_hiddenSSID[%d]=%s;\n", i, vChar ? "true" : "false");
		//dbg("MIB_WLAN_HIDDEN_SSID=%d\n",hiddenSSID);

		//get SSID
		boaWrite(wp, "_ssid[%d]='%s';\n", i, Entry.ssid);
		//dbg("MIB_WLAN_SSID=%s\n", ssid);

#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		vChar = Entry2.hidessid;
		boaWrite(wp, "_hiddenSSID[%d]=%s;\n", i+2, vChar ? "true" : "false");
		boaWrite(wp, "_ssid[%d]='%s';\n", i+2, Entry2.ssid);

		char ssid_tmp[33]; 
		char *ssidptr;
		unsigned char ssidprefix_enable = 0;
		mib_get(MIB_WEB_WLAN_SSIDPREFIX_ENABLE, &ssidprefix_enable);
		if (ssidprefix_enable == 1)
		{	
			strcpy(ssid_tmp, Entry.ssid);
			if(!strcmp(ssid_tmp,"0"))
				ssidptr = ssid_tmp;
			else
		#ifdef CONFIG_CU
				ssidptr = ssid_tmp+strlen("CU_");
		#else
				ssidptr = ssid_tmp+strlen("CMCC-");
		#endif
			boaWrite(wp, "_ssid[%d]='%s';\n", i, ssidptr);
		
			strcpy(ssid_tmp, Entry2.ssid);
			if(!strcmp(ssid_tmp,"0"))
				ssidptr = ssid_tmp;
			else
		#ifdef CONFIG_CU
				ssidptr = ssid_tmp+strlen("CU_");
		#else
				ssidptr = ssid_tmp+strlen("CMCC-");
		#endif
			boaWrite(wp, "_ssid[%d]='%s';\n", i+2, ssidptr);
		}
#endif

		//get wlTxPower
#if !defined(CONFIG_CMCC) && !defined(CONFIG_CU)
		if (pUser_info->priv) 
#endif
		{
			mib_get(MIB_TX_POWER, (void *)&txPower);
			boaWrite(wp, "_txpower[%d]=%d;\n", i, txPower);
			mib_get(MIB_WLAN_TX_POWER_HIGH, (void *)&txPower);
			boaWrite(wp, "_txpower_high[%d]=%d;\n", i, txPower);
			#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
			mib_get(MIB_TX_POWER, (void *)&txPower);
			boaWrite(wp, "_txpower[%d]=%d;\n", i+2, txPower);
			mib_get(MIB_WLAN_TX_POWER_HIGH, (void *)&txPower);
			boaWrite(wp, "_txpower_high[%d]=%d;\n", i+2, txPower);
			#endif
		}
		//dbg("MIB_TX_POWER=%d\n", txPower);

#if !defined(CONFIG_CMCC) && !defined(CONFIG_CU)
		if(pUser_info->priv)//admin
#endif
		{
			//get channel
			mib_get(MIB_WLAN_AUTO_CHAN_ENABLED, &vChar);
			if(vChar)
			{
				boaWrite(wp, "_chan[%d]=0;\n", i);
				#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
				boaWrite(wp, "_chan[%d]=0;\n", i+2);
				#endif
			}
			else{
				mib_get(MIB_WLAN_CHAN_NUM, (void *)&vChar);
				boaWrite(wp, "_chan[%d]=%d;\n", i, vChar);
				#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
				boaWrite(wp, "_chan[%d]=%d;\n", i+2, vChar);
				#endif
			}
			//dbg("MIB_WLAN_CHAN_NUM=%d\n", defChannel);

			//get 54TM mode
			vChar = Entry.wlanBand;
			//dbg("MIB_WLAN_BAND=%d\n", vChar);

			boaWrite(wp, "_band[%d]=%d;\n", i, vChar-1);
			#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
			vChar = Entry2.wlanBand;
			boaWrite(wp, "_band[%d]=%d;\n", i+2, vChar-1);
			#endif

			mib_get( MIB_WLAN_CHANNEL_WIDTH,(void *)&vChar);
			if(vChar==1){
				mib_get( MIB_WLAN_11N_COEXIST,(void *)&vChar2);
				if(vChar2)
					vChar=2;
			}
			boaWrite(wp, "_chanwid[%d]=%d;\n", i, vChar);
			#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
			boaWrite(wp, "_chanwid[%d]=%d;\n", i+2, vChar);
			#endif

			mib_get( MIB_WLAN_CONTROL_BAND,(void *)&vChar);
			boaWrite(wp, "_ctlband[%d]=%d;\n", i, vChar);
			#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
			boaWrite(wp, "_ctlband[%d]=%d;\n", i+2, vChar);
			#endif

#ifdef WLAN_QoS
			//get wlWme
			vChar = Entry.wmmEnabled;
			//boaWrite(wp, "wme = \"%d\";\n", vChar);
			//dbg("MIB_WLAN_QoS=%d\n", vChar);
#endif

			vUInt = Entry.fixedTxRate;
			boaWrite(wp, "_txRate[%d]=%u;\n", i,vUInt);

			vChar = Entry.rateAdaptiveEnabled;
			boaWrite(wp, "_auto[%d]=%d;\n", i,vChar);

			memset(&misc_data, 0, sizeof(struct _misc_data_));
			getMiscData(getWlanIfName(), &misc_data);
			boaWrite(wp, "_rf_used[%d]=%u;\n", i, misc_data.mimo_tr_used);

			mib_get( MIB_WLAN_SHORTGI_ENABLED, (void *)&vChar);
			boaWrite(wp, "_shortGI0[%d]=%d;\n", i, vChar);

#if defined(CONFIG_CMCC) || defined(CONFIG_CU)		
			vUInt = Entry2.fixedTxRate;
			boaWrite(wp, "_txRate[%d]=%u;\n", i+2,vUInt);
			vChar = Entry2.rateAdaptiveEnabled;
			boaWrite(wp, "_auto[%d]=%d;\n", i+2,vChar);
			boaWrite(wp, "_rf_used[%d]=%u;\n", i+2, misc_data.mimo_tr_used);
			mib_get( MIB_WLAN_SHORTGI_ENABLED, (void *)&vChar);
			boaWrite(wp, "_shortGI0[%d]=%d;\n", i+2, vChar);
			
			///////////////////
			vChar = Entry.wepDefaultKey;
			boaWrite(wp, "_defaultKeyidx[%d]=%d;\n", i, vChar);
			vChar = Entry2.wepDefaultKey;
			boaWrite(wp, "_defaultKeyidx[%d]=%d;\n", i+2, vChar);
			
			vChar = Entry.wsc_disabled;
			boaWrite(wp, "wscDisable[%d]=%d;\n", i, vChar);
			vChar = Entry2.wsc_disabled;
			boaWrite(wp, "wscDisable[%d]=%d;\n", i+2, vChar);

			/*WSC PBC*/
			vChar = stat("/var/cmcc_wsc_running", &run_status);

			if ( vChar == 0 ) 
			{
				vChar = 1;
			}else
				vChar = 0;
			boaWrite(wp, "_WPS_running[%d]=%d;\n", i, vChar);
			boaWrite(wp, "_WPS_running[%d]=%d;\n", i+2, vChar);
#endif
		}

#ifdef WLAN_RATE_PRIOR
		mib_get( MIB_WLAN_RATE_PRIOR, (void *)&vChar);
		boaWrite(wp, "_wlan_rate_prior[%d]=%d;\n", i, vChar);
#endif
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
#ifdef WLAN_RATE_PRIOR
		boaWrite(wp, "_wlan_rate_prior[%d]=%d;\n", i+2, vChar);
#endif
		mib_get(MIB_WLAN_BEACON_INTERVAL, (void *)&uShort);
		boaWrite(wp, "_wlan_beacon_interval[%d]=%hu;\n", i, uShort);
		boaWrite(wp, "_wlan_beacon_interval[%d]=%hu;\n", i+2, uShort);
		mib_get(MIB_WLAN_DTIM_PERIOD, (void *)&vChar);
		boaWrite(wp, "_wlan_dtim_period[%d]=%hhu;\n", i, vChar);
		boaWrite(wp, "_wlan_dtim_period[%d]=%hhu;\n", i+2, vChar);
#endif

	}

#ifdef WLAN_DUALBAND_CONCURRENT
#ifdef CONFIG_RTL_STA_CONTROL_SUPPORT
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	if(wlan_disabled==0){
		mib_get( MIB_WIFI_STA_CONTROL, (void *)&vChar);
		boaWrite(wp, "wlan_sta_control=%d;\n", vChar);
		boaWrite(wp,"%s.wlanSetup.wlanStaControl.checked = %s;\n",DOCUMENT, vChar? "true": "false");
	}
#else
	for(i=0; i<NUM_WLAN_INTERFACE;i++){
		wlan_idx = i;
#ifdef YUEME_3_0_SPEC
		mib_get(MIB_WLAN_DISABLED, (void *)&vChar);
		if(vChar){
			wlan_disabled|=vChar;
			continue;
		}
#endif
		if(wlan_getEntry(&Entry, 0)==1)
			wlan_disabled|=Entry.wlanDisabled;
	}

	mib_get( MIB_WIFI_STA_CONTROL, (void *)&vChar);
	boaWrite(wp, "wlan_sta_control=%d;\n", vChar);

	if(wlan_disabled==0){
		boaWrite(wp, "wlan_sta_control_enable=1;\n");
	}
	if(pUser_info->priv){//admin
		//if(wlan_phyband==PHYBAND_2G) //only show sta_control in 2G page
		//	boaWrite(wp, "%s.getElementById(\"wlStaControl\").style.display = \"\";\n", DOCUMENT);
		boaWrite(wp,"%s.wlanSetup.wlanStaControl.checked = %s;\n",DOCUMENT, vChar? "true": "false");
	}
#endif
#endif
#endif
#if defined(CONFIG_RTL_92D_SUPPORT) || defined(WLAN_DUALBAND_CONCURRENT)
	wlan_idx = orig_wlan_idx;
#endif

}


//#ifdef WLAN_WDS
void initWlWDSPage(request * wp){
	unsigned char disWlan,mode;
	MIB_CE_MBSSIB_T Entry;
	mib_chain_get(MIB_MBSSIB_TBL, 0, &Entry);
	disWlan = Entry.wlanDisabled;
	mode = Entry.wlanMode;
	if(disWlan || mode != AP_WDS_MODE){
		boaWrite(wp,"%s.formWlWdsAdd.wlanWdsEnabled.disabled = true;\n",DOCUMENT);
	}
}

void initWlSurveyPage(request * wp){
#ifdef WLAN_CLIENT
	boaWrite(wp,"%s.formWlSiteSurvey.refresh.disabled = false;\n",DOCUMENT);
#else
	boaWrite(wp,"%s.formWlSiteSurvey.refresh.disabled = true;\n",DOCUMENT);
#endif
}
//#endif

void initWlAdvPage(request * wp)
{
	unsigned char vChar;
#ifdef WIFI_TEST
	unsigned short vShort;
#endif
	MIB_CE_MBSSIB_T Entry;
	wlan_getEntry(&Entry, 0);
	mib_get( MIB_WLAN_PREAMBLE_TYPE, (void *)&vChar);
	boaWrite(wp, "%s.advanceSetup.preamble[%d].checked = true;\n", DOCUMENT, vChar);
	boaWrite(wp, "%s.advanceSetup.hiddenSSID[%d].checked = true;\n", DOCUMENT, Entry.hidessid);
	boaWrite(wp, "%s.advanceSetup.block[%d].checked = true;\n", DOCUMENT, Entry.userisolation==0?1:0);
	mib_get( MIB_WLAN_PROTECTION_DISABLED, (void *)&vChar);
	boaWrite(wp, "%s.advanceSetup.protection[%d].checked = true;\n", DOCUMENT, vChar);
	mib_get( MIB_WLAN_AGGREGATION, (void *)&vChar);
	boaWrite(wp, "%s.advanceSetup.aggregation[%d].checked = true;\n", DOCUMENT, vChar==0?1:0);
	mib_get( MIB_WLAN_SHORTGI_ENABLED, (void *)&vChar);
	boaWrite(wp, "%s.advanceSetup.shortGI0[%d].checked = true;\n", DOCUMENT, vChar==0?1:0);
#ifdef WLAN_QoS
	boaWrite(wp, "%s.advanceSetup.WmmEnabled[%d].checked = true;\n", DOCUMENT, Entry.wmmEnabled==0?1:0);
#endif
}

#ifdef WLAN_MBSSID
void initWLMBSSIDPage(request * wp)
{
	MIB_CE_MBSSIB_T Entry;
	int i=0;
	unsigned char vChar;

	if (mib_get(MIB_WLAN_BLOCK_MBSSID, (void *)&vChar) == 0) {
		printf("get MBSSID error!");
	}
	boaWrite(wp, "%s.WlanMBSSID.mbssid_block[%d].checked = true;\n", DOCUMENT, vChar);

	for (i=1; i<=4; i++) {
#if defined(CONFIG_CT_AWIFI_JITUAN_FEATURE)
        unsigned char functype=0;
        mib_get(AWIFI_PROVINCE_CODE, &functype);
        if(functype == AWIFI_ZJ){
		if(i == 1)
			continue;
        }
#endif
		if (!mib_chain_get(MIB_MBSSIB_TBL, i, (void *)&Entry)) {
  			printf("Error! Get MIB_MBSSIB_TBL(initWLMBSSIDPage) error.\n");
  			return;
		}
		boaWrite(wp, "%s.WlanMBSSID.wlAPIsolation_wl%d[%d].checked = true;\n", DOCUMENT, i-1, Entry.userisolation?0:1);
	}
}

void initWLMultiApPage(request * wp)
{
	MIB_CE_MBSSIB_T Entry;
	int i=0;
	unsigned char vChar;

	if (mib_get(MIB_WLAN_BLOCK_MBSSID, (void *)&vChar) == 0) {
		printf("get MBSSID error!");
	}
	boaWrite(wp, "%s.MultipleAP.mbssid_block[%d].checked = true;\n", DOCUMENT, vChar);

	for (i=1; i<=4; i++) {
		if (!mib_chain_get(MIB_MBSSIB_TBL, i, (void *)&Entry)) {
  			printf("Error! Get MIB_MBSSIB_TBL(initWLMultiApPage) error.\n");
  			return;
		}
		boaWrite(wp, "%s.MultipleAP.elements[\"wl_hide_ssid%d\"].selectedIndex = %d;\n", DOCUMENT, i, Entry.hidessid?0:1);
		boaWrite(wp, "%s.MultipleAP.elements[\"wl_access%d\"].selectedIndex = %d;\n", DOCUMENT, i, Entry.userisolation);
	}
}

#endif

extern void wapi_mod_entry(MIB_CE_MBSSIB_T *, char *, char *);
static void wlan_ssid_helper(MIB_CE_MBSSIB_Tp pEntry, char *psk, char *RsIp)
{
	int len;

	// wpaPSK
	for (len=0; len<strlen(pEntry->wpaPSK); len++)
		psk[len]='*';
	psk[len]='\0';

	// RsIp
	if ( ((struct in_addr *)pEntry->rsIpAddr)->s_addr == INADDR_NONE ) {
		sprintf(RsIp, "%s", "");
	} else {
		sprintf(RsIp, "%s", inet_ntoa(*((struct in_addr *)pEntry->rsIpAddr)));
	}
	#ifdef CONFIG_RTL_WAPI_SUPPORT
	if (pEntry->encrypt == WIFI_SEC_WAPI) {
		wapi_mod_entry(pEntry, psk, RsIp);
	}
	#endif
}

void initWlWpaMbssidPage(request * wp)
{
	MIB_CE_MBSSIB_T Entry;
	char strbuf[MAX_PSK_LEN+1], strbuf2[20];
	int isNmode;
	int i, k;
#if defined(CONFIG_RTL_92D_SUPPORT) || defined(WLAN_DUALBAND_CONCURRENT)
	char *strVal;
	int orig_wlan_idx = wlan_idx;
	strVal = boaGetVar(wp, "wlan_idx", "");
	if ( strVal[0] ) {
		//printf("wlan_idx=%d\n", strVal[0]-'0');
		wlan_idx = strVal[0]-'0';
	}
#endif

	k=0;
	for (i=0; i<=NUM_VWLAN_INTERFACE; i++) {
		wlan_getEntry(&Entry, i);
#ifdef CONFIG_YUEME
		if (i!=0 && Entry.instnum==0){
			k++;
			continue;
		}
#else
#if !defined(CONFIG_CMCC) && !defined(CONFIG_CU)
		if (Entry.wlanDisabled)
			continue;
#endif
#endif
		wlan_ssid_helper(&Entry, strbuf, strbuf2);
		boaWrite(wp, "_wlan_mode[%d]=%d;\n", k, Entry.wlanMode);
		boaWrite(wp, "\t_encrypt[%d]=%d;\n", k, Entry.encrypt);
		boaWrite(wp, "\t_enable1X[%d]=%d;\n", k, Entry.enable1X);
		boaWrite(wp, "\t_wpaAuth[%d]=%d;\n", k, Entry.wpaAuth);
		boaWrite(wp, "\t_wpaPSKFormat[%d]=%d;\n", k, Entry.wpaPSKFormat);
		//boaWrite(wp, "\t_wpaPSK[%d]='%s';\n", k, strbuf);
		boaWrite(wp, "\t_wpaPSK[%d]='%s';\n", k, Entry.wpaPSK);	//fix web check psk-key invalid problem
		boaWrite(wp, "\t_rsPort[%d]=%d;\n", k, Entry.rsPort);
		boaWrite(wp, "\t_rsIpAddr[%d]='%s';\n", k, strbuf2);
		boaWrite(wp, "\t_rsPassword[%d]='%s';\n", k, Entry.rsPassword);
		boaWrite(wp, "\t_uCipher[%d]=%d;\n", k, Entry.unicastCipher);
		boaWrite(wp, "\t_wpa2uCipher[%d]=%d;\n", k, Entry.wpa2UnicastCipher);
		boaWrite(wp, "\t_wepAuth[%d]=%d;\n", k, Entry.authType);
		boaWrite(wp, "\t_wepLen[%d]=%d;\n", k, Entry.wep);
		boaWrite(wp, "\t_wepKeyFormat[%d]=%d;\n\t", k, Entry.wepKeyType);
		isNmode=wl_isNband(Entry.wlanBand);
		boaWrite(wp, "\t_wlan_isNmode[%d]=%d;\n\t", k, isNmode);
#ifdef CONFIG_RTL_WAPI_SUPPORT
		boaWrite(wp, "\t_wapi_auth[%d]=%d;\n\t", k, Entry.wapiAuth);
		boaWrite(wp, "\t_wapi_auth_pskForm[%d]=%d;\n\t", k, Entry.wapiPskFormat);
		boaWrite(wp, "\t_wapi_auth_pskVal[%d]='%s';\n\t", k, Entry.wapiPsk);
#endif
		k++;
	}
#if defined(CONFIG_RTL_92D_SUPPORT) || defined(WLAN_DUALBAND_CONCURRENT)
	wlan_idx = orig_wlan_idx;
#endif

}

#ifdef WLAN_ACL
void initWlAclPage(request * wp)
{
	unsigned char vChar;
	MIB_CE_MBSSIB_T Entry;
	mib_chain_get(MIB_MBSSIB_TBL, 0, &Entry);

	if (Entry.wlanDisabled==0) // enabled
		boaWrite(wp,"wlanDisabled=0;\n");
	else // disabled
		boaWrite(wp,"wlanDisabled=1;\n");

	boaWrite(wp,"wlanMode=%d;\n", Entry.wlanMode);

	mib_get( MIB_WLAN_AC_ENABLED, (void *)&vChar);

	boaWrite(wp,"%s.formWlAcAdd.wlanAcEnabled.selectedIndex=%d\n", DOCUMENT, vChar);

}
#endif
#ifdef WIFI_TIMER_SCHEDULE
void initWlTimerExPage(request * wp)
{
	MIB_CE_WIFI_TIMER_EX_T Entry;
	int totalEntry, i;

	totalEntry = mib_chain_total(MIB_WIFI_TIMER_EX_TBL);
	for(i=0; i<totalEntry; i++)
	{
		mib_chain_get(MIB_WIFI_TIMER_EX_TBL, i, &Entry);
		boaWrite(wp, "\t_enable[%d]=%u;\n", i, Entry.enable);
		boaWrite(wp, "\t_onoff[%d]=%u;\n", i, Entry.onoff);
		boaWrite(wp, "\t_time[%d]=\"%s\";\n", i, Entry.Time);
		boaWrite(wp, "\t_day[%d]=%u;\n", i, Entry.day);
		boaWrite(wp, "\t_SSIDMask[%u]=%u;\n", i, Entry.SSIDMask);
	}
}
void initWlTimerPage(request * wp)
{
	MIB_CE_WIFI_TIMER_T Entry;
	int totalEntry, i;

	totalEntry = mib_chain_total(MIB_WIFI_TIMER_TBL);
	for(i=0; i<totalEntry; i++)
	{
		mib_chain_get(MIB_WIFI_TIMER_TBL, i, &Entry);
		boaWrite(wp, "\t_enable[%d]=%u;\n", i, Entry.enable);
		boaWrite(wp, "\t_startTime[%d]=\"%s\";\n", i, Entry.startTime);
		boaWrite(wp, "\t_endTime[%d]=\"%s\";\n", i, Entry.endTime);
		boaWrite(wp, "\t_controlCycle[%u]=%u;\n", i, Entry.controlCycle);
		boaWrite(wp, "\t_SSIDMask[%u]=%u;\n", i, Entry.SSIDMask);
	}
}
#endif
#ifdef _PRMT_X_CMCC_WLANSHARE_
void initWlSharePage(request * wp)
{
	MIB_CE_WLAN_SHARE_T Entry;
	int totalEntry, i;

	totalEntry = mib_chain_total(MIB_WLAN_SHARE_TBL);
	for(i=0; i<totalEntry; i++)
	{
		if(mib_chain_get(MIB_WLAN_SHARE_TBL, i, &Entry)==0)
			continue;

		boaWrite(wp, "\t_ssid_idx=%hhu;\n", Entry.ssid_idx);
		boaWrite(wp, "\t_userid_enable=\"%hhu\";\n", Entry.userid_enable);
		if(!strcmp(Entry.userid, ""))
			boaWrite(wp, "\t_userid=_text_hint;\n");
		else
			boaWrite(wp, "\t_userid=\"%s\";\n", Entry.userid);

		// only support 1 instance currently.
		break;
	}
}
#endif
#ifdef WLAN_11R
void initWlFtPage(request * wp)
{
	MIB_CE_MBSSIB_T Entry;
	char strbuf[MAX_PSK_LEN+1], strbuf2[20];
	int isNmode;
	int i, k;
	char wlanDisabled;

	k=0;
	for (i=0; i<1; i++) {
		wlan_getEntry(&Entry, i);
		if (i==0) // root
			wlanDisabled = Entry.wlanDisabled;
		if (Entry.wlanDisabled)
			continue;
		if (Entry.wlanMode == CLIENT_MODE)
			continue;
		wlan_ssid_helper(&Entry, strbuf, strbuf2);
		boaWrite(wp, "\t_encrypt[%d]=%d;\n", k, Entry.encrypt);

		boaWrite(wp, "\t_ft_enable[%d]=%d;\n", k, Entry.ft_enable);
		boaWrite(wp, "\t_ft_mdid[%d]=\"%s\";\n", k, Entry.ft_mdid);
		boaWrite(wp, "\t_ft_over_ds[%d]=%d;\n", k, Entry.ft_over_ds);
		boaWrite(wp, "\t_ft_res_request[%d]=%d;\n", k, Entry.ft_res_request);
		boaWrite(wp, "\t_ft_r0key_timeout[%d]=%d;\n", k, Entry.ft_r0key_timeout);
		boaWrite(wp, "\t_ft_reasoc_timeout[%d]=%d;\n", k, Entry.ft_reasoc_timeout);
		boaWrite(wp, "\t_ft_r0kh_id[%d]=\"%s\";\n", k, Entry.ft_r0kh_id);
		boaWrite(wp, "\t_ft_push[%d]=%d;\n", k, Entry.ft_push);
		boaWrite(wp, "\t_ft_kh_num[%d]=%d;\n", k, Entry.ft_kh_num);
		k++;
	}
	boaWrite(wp, "\tssid_num=%d;\n", k);

	if(wlanDisabled) {
		boaWrite(wp, "\t%s.getElementById(\"wlan_dot11r_table\").style.display = 'none';\n", DOCUMENT);
		boaWrite(wp, "\t%s.write(\"<font size=2> WLAN Disabled !</font>\")", DOCUMENT);
	}
	else {
		boaWrite(wp, "\t%s.getElementById(\"wlan_dot11r_table\").style.display = \"\";\n", DOCUMENT);
	}
}
#endif
#endif // of WLAN_SUPPORT

#ifdef CONFIG_LED_INDICATOR_TIMER
void initLEDTimerPage(request * wp)
{
	MIB_CE_DAY_SCHED_T Entry;
	int totalEntry, i;
	unsigned char status;

	totalEntry = mib_chain_total(MIB_LED_INDICATOR_TIMER_TBL);
	for(i=0; i<totalEntry; i++)
	{
		mib_chain_get(MIB_LED_INDICATOR_TIMER_TBL, i, &Entry);
		boaWrite(wp, "\t_enable[%d]=%u;\n", i, Entry.enable);
		boaWrite(wp, "\t_startTime[%d]=\"%d:%d\";\n", i, Entry.startHour, Entry.startMin);
		boaWrite(wp, "\t_endTime[%d]=\"%d:%d\";\n", i, Entry.endHour, Entry.endMin);
		boaWrite(wp, "\t_controlCycle[%u]=%u;\n", i, Entry.ctlCycle);
	}
	mib_get(MIB_LED_STATUS, (void *)&status);
	boaWrite(wp, "\t_ledsts=%u;\n",status);
}
#endif

#ifdef DIAGNOSTIC_TEST
void initDiagTestPage(request * wp)
{
	unsigned int inf;
	FILE *fp;

	if (fp = fopen("/tmp/diaginf", "r")) {
		fscanf(fp, "%d", &inf);
		if (inf != DUMMY_IFINDEX)
			boaWrite(wp, "%s.diagtest.wan_if.value = %d;\n", DOCUMENT, inf);
		fclose(fp);
		fp = fopen("/tmp/diaginf", "w");
		fprintf(fp, "%d", DUMMY_IFINDEX); // reset to dummy
		fclose(fp);
	}
}
#endif



int ShowDot11r(int eid, request * wp, int argc, char **argv)
{
#ifdef WLAN_11R
#ifdef CONFIG_YUEME
	boaWrite(wp,
		"<table width=\"400\" border=\"0\" cellpadding=\"4\" cellspacing=\"0\">" \
		"<tr><td width=\"45%%\">802.11r:</td>\n" \
		"\t\t\t<td colspan=\"2\">\n" \
		"\t\t\t<input type=\"button\" name=dot11rEnabled value='Fast Roaming' onClick='on_dot11r()'></td>\n" \
		"\t\t</tr></table>\n");
#else
	boaWrite(wp,
		"<tr><td width=\"26%%\">802.11r:</td>\n" \
		"\t\t\t<td>\n" \
		"\t\t\t<input type=\"button\" name=dot11rEnabled value='Fast Roaming' onClick='on_dot11r()'></td>\n" \
		"\t\t</tr>\n");
#endif
#endif
}

int ShowDot11k_v(int eid, request * wp, int argc, char **argv)
{
#ifdef WLAN_11K
#ifdef CONFIG_YUEME
	boaWrite(wp,
		"<table width=\"400\" border=\"0\" cellpadding=\"4\" cellspacing=\"0\">" \
		"<tr><td width=\"45%%\">802.11k:</td>\n" \
		"\t\t\t<td colspan=\"2\">\n" \
		"\t\t\t<input type=\"radio\" name=dot11kEnabled value=1 onClick='wlDot11kChange()'>ON\n" \
		"\t\t\t<input type=\"radio\" name=dot11kEnabled value=0 onClick='wlDot11kChange()'>OFF</td>\n" \
		"\t\t</tr></table>\n");
#else
	boaWrite(wp,
		"<tr><td width=\"26%%\">802.11k:</td>\n" \
		"\t\t\t<td>\n" \
		"\t\t\t<input type=\"radio\" name=dot11kEnabled value=1 onClick='wlDot11kChange()'>ON\n" \
		"\t\t\t<input type=\"radio\" name=dot11kEnabled value=0 onClick='wlDot11kChange()'>OFF</td>\n" \
		"\t\t</tr>\n");
#endif
#endif
#ifdef WLAN_11V
#ifdef CONFIG_YUEME
	boaWrite(wp,
		"<table width=\"400\" border=\"0\" cellpadding=\"4\" cellspacing=\"0\">" \
		"\t\t<tr id=\"dot11v\"  style=\"display:none\">\n" \
		"\t\t\t<td width=\"45%%\">802.11v:</td>\n" \
		"\t\t\t<td colspan=\"2\">\n" \
		"\t\t\t<input type=\"radio\" name=dot11vEnabled value=1>ON\n" \
		"\t\t\t<input type=\"radio\" name=dot11vEnabled value=0>OFF</td>\n" \
		"\t\t</tr></table>\n");
#else
	boaWrite(wp,
		"\t\t<tr id=\"dot11v\"  style=\"display:none\">\n" \
		"\t\t\t<td width=\"26%%\">802.11v:</td>\n" \
		"\t\t\t<td>\n" \
		"\t\t\t<input type=\"radio\" name=dot11vEnabled value=1>ON\n" \
		"\t\t\t<input type=\"radio\" name=dot11vEnabled value=0>OFF</td>\n" \
		"\t\t</tr>\n");
#endif
#endif
}

void initDhcpMode(request * wp)
{
	unsigned char vChar;
	char buf[16];

// Kaohj --- assign DHCP pool ip prefix; no pool prefix for complete IP pool
#ifdef DHCPS_POOL_COMPLETE_IP
	boaWrite(wp, "	pool_ipprefix='';\n");
#else
	getSYS2Str(SYS_DHCPS_IPPOOL_PREFIX, buf);
	boaWrite(wp, "	pool_ipprefix='%s';\n", buf);
#endif
// Kaohj
#ifdef DHCPS_DNS_OPTIONS
	boaWrite(wp, "	en_dnsopt=1;\n");
	mib_get(MIB_DHCP_DNS_OPTION, (void *)&vChar);
	boaWrite(wp, "	dnsopt=%d;\n", vChar);
#else
	boaWrite(wp, "	en_dnsopt=0;\n");
#endif
	mib_get(MIB_DHCP_MODE, (void *)&vChar);

	if(vChar == 1) vChar = 2;
	else if(vChar == 2) vChar = 1;

	boaWrite(wp, "	%s.dhcpd.uDhcpType[%d].checked = true;\n", DOCUMENT, vChar);
}

#ifdef CONFIG_IPV6
#ifdef CONFIG_USER_DHCPV6_ISC_DHCP411
void initDhcpv6Mode(request * wp)
{
	unsigned char vChar;
	char buf[16];

	mib_get( MIB_DHCPV6_MODE, (void *)&vChar);
	boaWrite(wp, "%s.dhcpd.dhcpdenable[%d].checked = true;\n", DOCUMENT, vChar);
}
#endif
#endif

void initDhcpMacbase(request * wp)
{
	char buf[16];
// Kaohj --- assign DHCP pool ip prefix; no pool prefix for complete IP pool
#ifdef DHCPS_POOL_COMPLETE_IP
	boaWrite(wp, "pool_ipprefix='';\n");
#else
	getSYS2Str(SYS_DHCPS_IPPOOL_PREFIX, buf);
	boaWrite(wp, "pool_ipprefix='%s';\n", buf);
#endif
}

/*ping_zhang:20090319 START:replace ip range with serving pool of tr069*/
#ifdef _PRMT_X_TELEFONICA_ES_DHCPOPTION_
#ifdef IMAGENIO_IPTV_SUPPORT
void initDhcpIPRange(request * wp)
{
	char buf[16];
	unsigned int i, entryNum;
	DHCPS_SERVING_POOL_T Entry;
	MIB_CE_DHCP_OPTION_T rsvOptEntry;
	char startIp[16], endIp[16];
/*ping_zhang:20090526 START:Add gateway for each ip range*/
	char gwIp[16];
/*ping_zhang:20090526 END*/
	int id=-1;

	entryNum = mib_chain_total(MIB_DHCPS_SERVING_POOL_TBL);
	boaWrite(wp, "var devname=new Array(%d), devtype=new Array(%d), startip=new Array(%d), endip=new Array(%d), gwip=new Array(%d), option=new Array(%d), opCode=new Array(%d), opStr=new Array(%d);\n",
			entryNum, entryNum, entryNum, entryNum, entryNum, entryNum, entryNum, entryNum);

// Kaohj --- assign DHCP pool ip prefix; no pool prefix for complete IP pool
#ifdef DHCPS_POOL_COMPLETE_IP
	boaWrite(wp, "pool_ipprefix='';\n");
#else
	getSYS2Str(SYS_DHCPS_IPPOOL_PREFIX, buf);
	boaWrite(wp, "pool_ipprefix='%s';\n", buf);
#endif

	for (i=0; i<entryNum; i++) {

		mib_chain_get(MIB_DHCPS_SERVING_POOL_TBL, i, (void *)&Entry);
		strcpy(startIp, inet_ntoa(*((struct in_addr *)Entry.startaddr)));
		strcpy(endIp, inet_ntoa(*((struct in_addr *)Entry.endaddr)));
/*ping_zhang:20090526 START:Add gateway for each ip range*/
		strcpy(gwIp, inet_ntoa(*((struct in_addr *)Entry.iprouter)));
/*ping_zhang:20090526 END*/

		boaWrite(wp, "devname[%d]=\'%s\';\n", i, Entry.poolname);
		boaWrite(wp, "devtype[%d]=\'%d\';\n", i, Entry.deviceType);
		boaWrite(wp, "startip[%d]=\'%s\';\n", i, startIp);
		boaWrite(wp, "endip[%d]=\'%s\';\n", i, endIp);
/*ping_zhang:20090526 START:Add gateway for each ip range*/
		boaWrite(wp, "gwip[%d]=\'%s\';\n", i, gwIp);
/*ping_zhang:20090526 END*/
		boaWrite(wp, "option[%d]=\'%s\';\n", i, Entry.vendorclass);
		boaWrite(wp, "opCode[%d]=\'%d\';\n", i, Entry.rsvOptCode);

		getSPDHCPRsvOptEntryByCode(Entry.InstanceNum, Entry.rsvOptCode, &rsvOptEntry, &id);
		if(id != -1)
			boaWrite(wp, "opStr[%d]=\'%s\';\n", i, rsvOptEntry.value);
		else
			boaWrite(wp, "opStr[%d]=\'\';\n");
	}
}
#endif
#endif
/*ping_zhang:20090319 END*/

#ifdef ADDRESS_MAPPING
#ifdef MULTI_ADDRESS_MAPPING
initAddressMap(request * wp)
{
	boaWrite(wp, "%s.addressMap.lsip.disabled = false;\n", DOCUMENT);
	boaWrite(wp, "%s.addressMap.leip.disabled = true;\n", DOCUMENT);
	boaWrite(wp, "%s.addressMap.gsip.disabled = false;\n", DOCUMENT);
	boaWrite(wp, "%s.addressMap.geip.disabled = true;\n", DOCUMENT);
	boaWrite(wp, "%s.addressMap.addressMapType.selectedIndex= 0;\n", DOCUMENT);
}
#else
initAddressMap(request * wp)
{
	unsigned char vChar;

	mib_get( MIB_ADDRESS_MAP_TYPE, (void *)&vChar);

	if(vChar == ADSMAP_NONE) {         // None
		boaWrite(wp, "%s.addressMap.lsip.disabled = true;\n", DOCUMENT);
		boaWrite(wp, "%s.addressMap.leip.disabled = true;\n", DOCUMENT);
		boaWrite(wp, "%s.addressMap.gsip.disabled = true;\n", DOCUMENT);
		boaWrite(wp, "%s.addressMap.geip.disabled = true;\n", DOCUMENT);
		boaWrite(wp, "%s.addressMap.addressMapType.selectedIndex= 0;\n", DOCUMENT);

	} else if (vChar == ADSMAP_ONE_TO_ONE) {  // One-to-One
		boaWrite(wp, "%s.addressMap.lsip.disabled = false;\n", DOCUMENT);
		boaWrite(wp, "%s.addressMap.leip.disabled = true;\n", DOCUMENT);
		boaWrite(wp, "%s.addressMap.gsip.disabled = false;\n", DOCUMENT);
		boaWrite(wp, "%s.addressMap.geip.disabled = true;\n", DOCUMENT);
		boaWrite(wp, "%s.addressMap.addressMapType.selectedIndex= 1;\n", DOCUMENT);

	} else if (vChar == ADSMAP_MANY_TO_ONE) {  // Many-to-One
		boaWrite(wp, "%s.addressMap.lsip.disabled = false;\n", DOCUMENT);
		boaWrite(wp, "%s.addressMap.leip.disabled = false;\n", DOCUMENT);
		boaWrite(wp, "%s.addressMap.gsip.disabled = false;\n", DOCUMENT);
		boaWrite(wp, "%s.addressMap.geip.disabled = true;\n", DOCUMENT);
		boaWrite(wp, "%s.addressMap.addressMapType.selectedIndex= 2;\n", DOCUMENT);

	} else if (vChar == ADSMAP_MANY_TO_MANY) {   // Many-to-Many
		boaWrite(wp, "%s.addressMap.lsip.disabled = false;\n", DOCUMENT);
		boaWrite(wp, "%s.addressMap.leip.disabled = false;\n", DOCUMENT);
		boaWrite(wp, "%s.addressMap.gsip.disabled = false;\n", DOCUMENT);
		boaWrite(wp, "%s.addressMap.geip.disabled = false;\n", DOCUMENT);
		boaWrite(wp, "%s.addressMap.addressMapType.selectedIndex= 3;\n", DOCUMENT);

	}
	// Masu Yu on True
	else if (vChar == ADSMAP_ONE_TO_MANY) {   // One-to-Many
		boaWrite(wp, "%s.addressMap.lsip.disabled = false;\n", DOCUMENT);
		boaWrite(wp, "%s.addressMap.leip.disabled = true;\n", DOCUMENT);
		boaWrite(wp, "%s.addressMap.gsip.disabled = false;\n", DOCUMENT);
		boaWrite(wp, "%s.addressMap.geip.disabled = false;\n", DOCUMENT);
		boaWrite(wp, "%s.addressMap.addressMapType.selectedIndex= 4;\n", DOCUMENT);

	}
}
#endif // MULTI_ADDRESS_MAPPING
#endif

#ifdef CONFIG_USER_ZEBRA_OSPFD_OSPFD
//ql
void initOspf(request * wp)
{
	unsigned char vChar;

#ifdef CONFIG_USER_ROUTED_ROUTED
	mib_get( MIB_RIP_ENABLE, (void *)&vChar );
	if (1 == vChar) {
		boaWrite(wp, "%s.rip.igp.selectedIndex = 0;\n", DOCUMENT);
		boaWrite(wp, "%s.rip.rip_on[1].checked = true;\n", DOCUMENT);
		return;
	}
	mib_get( MIB_OSPF_ENABLE, (void *)&vChar);
	if (1 == vChar) {
		boaWrite(wp, "%s.rip.igp.selectedIndex = 1;\n", DOCUMENT);
		boaWrite(wp, "%s.rip.rip_on[1].checked = true;\n", DOCUMENT);
		return;
	}
#else
	mib_get( MIB_OSPF_ENABLE, (void *)&vChar);
	if (1 == vChar) {
		boaWrite(wp, "%s.rip.igp.selectedIndex = 0;\n", DOCUMENT);
		boaWrite(wp, "%s.rip.rip_on[1].checked = true;\n", DOCUMENT);
		return;
	}
#endif
	//default
	boaWrite(wp, "%s.rip.igp.selectedIndex = 0;\n", DOCUMENT);
	boaWrite(wp, "%s.rip.rip_on[0].checked = true;\n", DOCUMENT);
}
#endif

#ifdef CONFIG_ETHWAN
void initEthWan(request * wp)
{
	MIB_CE_ATM_VC_T Entry;
	int index;
#ifdef CONFIG_IPV6
	unsigned char 	Ipv6AddrStr[INET6_ADDRSTRLEN], RemoteIpv6AddrStr[INET6_ADDRSTRLEN];
#endif

	index = getWanEntrybyMedia(&Entry, MEDIA_ETH);
	if (index == -1)
		printf("EthWan interface not found !\n");
	boaWrite(wp, "%s.ethwan.naptEnabled.checked = %s;\n", DOCUMENT, Entry.napt?"true":"false");
	boaWrite(wp, "%s.ethwan.igmpEnabled.checked = %s;\n", DOCUMENT, Entry.enableIGMP?"true":"false");
#ifdef CONFIG_USER_IP_QOS
	boaWrite(wp, "%s.ethwan.qosEnabled.checked = %s;\n", DOCUMENT, Entry.enableIpQos?"true":"false");
#endif

	boaWrite(wp, "%s.ethwan.ipMode[%d].checked = true;\n", DOCUMENT, Entry.ipDhcp == 0? 0:1);
	if(Entry.cmode == CHANNEL_MODE_IPOE){//mer
#ifdef CONFIG_IPV6
		if (Entry.IpProtocol & IPVER_IPV4) {
#endif
		if(Entry.ipDhcp == 0){//ip
			boaWrite(wp, "%s.ethwan.ip.value = \"%s\";\n", DOCUMENT, inet_ntoa(*((struct in_addr *)&Entry.ipAddr)));
			//printf("ip %s\n", Entry.ipAddr);
			boaWrite(wp, "%s.ethwan.remoteIp.value = \"%s\";\n", DOCUMENT, inet_ntoa(*((struct in_addr *)&Entry.remoteIpAddr)));
			boaWrite(wp, "%s.ethwan.netmask.value = \"%s\";\n", DOCUMENT, inet_ntoa(*((struct in_addr *)&Entry.netMask)));
		}
#ifdef CONFIG_IPV6
		}
#endif
	}
	else if(Entry.cmode == CHANNEL_MODE_PPPOE){//pppoe
		boaWrite(wp, "%s.ethwan.pppUserName.value = \"%s\";\n", DOCUMENT, Entry.pppUsername);
		boaWrite(wp, "%s.ethwan.pppPassword.value = \"%s\";\n", DOCUMENT, Entry.pppPassword);
		boaWrite(wp, "%s.ethwan.pppConnectType[%d].checked = true;\n", DOCUMENT, Entry.pppCtype);
		if(Entry.pppCtype == '1'){//connect on demand
			boaWrite(wp, "%s.ethwan.pppConnectType.value = \"%d\";\n", DOCUMENT, Entry.pppIdleTime);
		}
	}
	if (Entry.cmode != CHANNEL_MODE_BRIDGE)
		boaWrite(wp, "%s.ethwan.droute[%d].checked = true;\n", DOCUMENT, Entry.dgw);
#ifdef CONFIG_IPV6
	boaWrite(wp, "%s.ethwan.IpProtocolType.value=%d;\n", DOCUMENT, Entry.IpProtocol);
	if (Entry.AddrMode & 1)
		boaWrite(wp, "%s.ethwan.slacc.checked=true;\n", DOCUMENT);
	else
		boaWrite(wp, "%s.ethwan.slacc.checked=false;\n", DOCUMENT);
	if (Entry.AddrMode & 2)
		boaWrite(wp, "%s.ethwan.staticIpv6.checked=true;\n", DOCUMENT);
	else
		boaWrite(wp, "%s.ethwan.staticIpv6.checked=false;\n", DOCUMENT);
	inet_ntop(PF_INET6, Entry.Ipv6Addr, Ipv6AddrStr, sizeof(Ipv6AddrStr));
	inet_ntop(PF_INET6, Entry.RemoteIpv6Addr, RemoteIpv6AddrStr, sizeof(RemoteIpv6AddrStr));
	boaWrite(wp, "%s.ethwan.Ipv6Addr.value=\"%s\";\n", DOCUMENT, Ipv6AddrStr);
	boaWrite(wp, "%s.ethwan.Ipv6PrefixLen.value=%d;\n", DOCUMENT, Entry.Ipv6AddrPrefixLen);
	boaWrite(wp, "%s.ethwan.Ipv6Gateway.value=\"%s\";\n", DOCUMENT, RemoteIpv6AddrStr);
	if (Entry.Ipv6Dhcp)
		boaWrite(wp, "%s.ethwan.itfenable.checked=true;\n", DOCUMENT);
	else
		boaWrite(wp, "%s.ethwan.itfenable.checked=false;\n", DOCUMENT);
	if (Entry.Ipv6DhcpRequest&1)
		boaWrite(wp, "%s.ethwan.iana.checked=true;\n", DOCUMENT);
	else
		boaWrite(wp, "%s.ethwan.iana.checked=false;\n", DOCUMENT);
	if (Entry.Ipv6DhcpRequest&2)
		boaWrite(wp, "%s.ethwan.iapd.checked=true;\n", DOCUMENT);
	else
		boaWrite(wp, "%s.ethwan.iapd.checked=false;\n", DOCUMENT);
	boaWrite(wp, "ipver=%s.ethwan.IpProtocolType.value;\n", DOCUMENT);
#endif
}
#endif

#ifdef CONFIG_USER_PPTPD_PPTPD
void initPptp(request * wp)
{
	MIB_VPND_T entry;
	int total, i;
	char peeraddr[16];
	char localaddr[16];

	total = mib_chain_total(MIB_VPN_SERVER_TBL);
	for (i=0; i<total; i++) {
		if (!mib_chain_get(MIB_VPN_SERVER_TBL, i, &entry))
			continue;

		if (VPN_PPTP == entry.type)
			break;
	}

	if (i < total) {
		boaWrite(wp, "document.pptp.s_auth.selectedIndex=%d;\n", entry.authtype);
		boaWrite(wp, "\tdocument.pptp.s_enctype.selectedIndex=%d;\n", entry.enctype);
		sprintf(peeraddr, "%s", inet_ntoa(*(struct in_addr *)&entry.peeraddr));
		sprintf(localaddr, "%s", inet_ntoa(*(struct in_addr *)&entry.localaddr));
		boaWrite(wp, "\tdocument.pptp.peeraddr.value=\"%s\";\n", peeraddr);
		boaWrite(wp, "\tdocument.pptp.localaddr.value=\"%s\";\n", localaddr);
	}
}
#endif

#ifdef CONFIG_USER_L2TPD_LNS
void initL2tp(request * wp)
{
	MIB_VPND_T entry;
	int total, i;
	char peeraddr[16];
	char localaddr[16];

	total = mib_chain_total(MIB_VPN_SERVER_TBL);
	for (i=0; i<total; i++) {
		if (!mib_chain_get(MIB_VPN_SERVER_TBL, i, &entry))
			continue;

		if (VPN_L2TP == entry.type)
			break;
	}

	if (i < total) {
		boaWrite(wp, "document.l2tp.s_auth.selectedIndex=%d;\n", entry.authtype);
		boaWrite(wp, "\tdocument.l2tp.s_enctype.selectedIndex=%d;\n", entry.enctype);
		boaWrite(wp, "\tdocument.l2tp.s_tunnelAuth.checked=%s;\n", entry.tunnel_auth==1?"true":"false");
		boaWrite(wp, "\tdocument.l2tp.s_authKey.value=\"%s\";\n", entry.tunnel_key);
		sprintf(peeraddr, "%s", inet_ntoa(*(struct in_addr *)&entry.peeraddr));
		sprintf(localaddr, "%s", inet_ntoa(*(struct in_addr *)&entry.localaddr));
		boaWrite(wp, "\tdocument.l2tp.peeraddr.value=\"%s\";\n", peeraddr);
		boaWrite(wp, "\tdocument.l2tp.localaddr.value=\"%s\";\n", localaddr);
	}
}
#endif

#if (defined(CONFIG_CMCC) || defined(CONFIG_CU)) && defined(CONFIG_IPV6)
void initvlan4ipv6(request * wp)
{
	unsigned char vlan_enable;
	unsigned int ipv4_vlan_id, ipv6_vlan_id;

	mib_get(MIB_IPV6_VLAN_ENABLE, (void *)&vlan_enable);
	mib_get(MIB_IPV4_VLAN_ID, (void *)&ipv4_vlan_id);
	mib_get(MIB_IPV6_VLAN_ID, (void *)&ipv6_vlan_id);
	
	boaWrite(wp, "vlan_enbale=%d;\n", vlan_enable);
	boaWrite(wp, "_vlanid4v4=%d;\n", ipv4_vlan_id);
	boaWrite(wp, "_vlanid4v6=%d;\n", ipv6_vlan_id);
}
#endif

/////////////////////////////////////////////////////////////
// Kaohj
int initPage(int eid, request * wp, int argc, char **argv)
{
	char *name;

	if (boaArgs(argc, argv, "%s", &name) < 1) {
		boaError(wp, 400, "Insufficient args\n");
		return -1;
	}

	if ( !strcmp(name, "lan") )
		initLanPage(wp);
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	if ( !strcmp(name, "igmpMldSnooping") )    // Mason Yu. IGMP snooping for e8b
	{
		printf("initIgmpMldSnoopPage\n");
		initIgmpMldSnoopPage(wp);
	}
	if ( !strcmp(name, "igmpMldProxy") )    // Mason Yu. IGMP snooping for e8b
	{
		printf("initIgmpMldProxyPage\n");
		initIgmpMldProxyPage(wp);
	}
#endif
	if ( !strcmp(name, "igmpsnooping") )    // Mason Yu. IGMP snooping for e8b
	{
		printf("initIgmpsnoopPage\n");
		initIgmpsnoopPage(wp);
	}
	
#ifdef CONFIG_USER_LAN_BANDWIDTH_MONITOR	
	if ( !strcmp(name, "bandwidth_monitor") )    //Martin ZHU. US/DS bandwidth monitor for yueme
	{
		printf("initBandwidthMonitorPage\n");
		initBandwidthMonitorPage(wp);
	}

	if ( !strcmp(name, "bdw_interval") )    //Martin ZHU. US/DS bandwidth monitor for yueme
	{
		printf("initBandwidthIntervalPage\n");
		initBandwidthIntervalPage(wp);
	}	
#endif

#ifdef CONFIG_IPV6
#ifdef CONFIG_USER_RADVD
	if ( !strcmp(name, "radvd_conf") )
		initRadvdConfPage(wp);
#endif
	if ( !strcmp(name, "mldsnooping") )    // Mason Yu. MLD snooping
		initMLDsnoopPage(wp);
#endif
#ifdef PORT_TRIGGERING
	if ( !strcmp(name, "gaming") )
		initGamingPage(wp);
#endif
#ifdef CONFIG_USER_ROUTED_ROUTED
	if ( !strcmp(name, "rip") )
		initRipPage(wp);
#endif

// Mason Yu. combine_1p_4p_PortMapping
#ifdef ITF_GROUP
	if ( !strcmp(name, "portMap") )
		initPortMapPage(wp);
#endif

#if defined(CONFIG_RTL_MULTI_LAN_DEV)
#ifdef ELAN_LINK_MODE
	if ( !strcmp(name, "linkMode") )
		initLinkPage(wp);
#endif
#else
#ifdef ELAN_LINK_MODE_INTRENAL_PHY
	if ( !strcmp(name, "linkMode") )
		initLinkPage(wp);
#endif
#endif	// of CONFIG_RTL_MULTI_LAN_DEV

#if defined(IP_QOS) || defined(NEW_IP_QOS_SUPPORT)
	if ( !strcmp(name, "ipqos") )
		initIpQosPage(wp);
	if ( !strcmp(name, "qosQueue") )
		initQosQueue(wp);
#endif
#ifdef QOS_DIFFSERV
	if (!strcmp(name, "diffserv"))
		initDiffservPage(wp);
#endif
	if ( !strcmp(name, "others") )
		initOthersPage(wp);
#ifdef WLAN_SUPPORT
#ifdef WLAN_WPA
	if ( !strcmp(name, "wlwpa") )
		initWlWpaPage(wp);
#endif
	// Mason Yu. 201009_new_security
	if ( !strcmp(name, "wlwpa_mbssid") )
		initWlWpaMbssidPage(wp);
	if ( !strcmp(name, "wlbasic") )
		initWlBasicPage(wp);
	if ( !strcmp(name, "wle8basic") )
		initWlE8BasicPage(wp);
	if ( !strcmp(name, "wladv") )
		initWlAdvPage(wp);
#ifdef WLAN_MBSSID
	// Mason Yu
	if ( !strcmp(name, "wlmbssid") ) {
		initWLMBSSIDPage(wp);
	}
	if ( !strcmp(name, "wlmultipleap") ) {
		initWLMultiApPage(wp);
	}
#endif
#ifdef WLAN_WDS
	if ( !strcmp(name, "wlwds") )
		initWlWDSPage(wp);
#endif
#ifdef WLAN_CLIENT
	if ( !strcmp(name, "wlsurvey") )
		initWlSurveyPage(wp);

#endif
#ifdef WLAN_ACL
	if ( !strcmp(name, "wlactrl") )
		initWlAclPage(wp);
#endif
#ifdef WIFI_TIMER_SCHEDULE
	if ( !strcmp(name, "wltimerEx") )
		initWlTimerExPage(wp);
	if( !strcmp(name, "wltimer") )
		initWlTimerPage(wp);
#endif
#ifdef _PRMT_X_CMCC_WLANSHARE_
	if( !strcmp(name, "wlshare") )
		initWlSharePage(wp);
#endif
#ifdef WLAN_11R
	if ( !strcmp(name, "wlft") )
		initWlFtPage(wp);
#endif
#endif
#ifdef CONFIG_LED_INDICATOR_TIMER 
	if ( !strcmp(name, "ledtimer") )
	{
		initLEDTimerPage(wp);
	}
#endif

#ifdef DIAGNOSTIC_TEST
	if ( !strcmp(name, "diagTest") )
		initDiagTestPage(wp);
#endif

#ifdef DOS_SUPPORT
	if ( !strcmp(name, "dos") )
		initDosPage(wp);
#endif


#ifdef ADDRESS_MAPPING
	if( !strcmp(name, "addressMap"))
		initAddressMap(wp);
#endif

	if ( !strcmp(name, "dhcp-mode") )
		initDhcpMode(wp);
#ifdef CONFIG_IPV6
#ifdef CONFIG_USER_DHCPV6_ISC_DHCP411
	if ( !strcmp(name, "dhcpv6-mode") )
		initDhcpv6Mode(wp);
#endif
#endif
	if ( !strcmp(name, "dhcp-macbase") )
		initDhcpMacbase(wp);
#ifdef _PRMT_X_TELEFONICA_ES_DHCPOPTION_
#ifdef IMAGENIO_IPTV_SUPPORT
	if ( !strcmp(name, "dhcp-iprange") )
		initDhcpIPRange(wp);
#endif
#endif
//add by ramen
#ifdef CONFIG_IP_NF_ALG_ONOFF
if (!strcmp(name, "algonoff"))
	initAlgOnOff(wp);
#endif
#ifdef CONFIG_USER_ZEBRA_OSPFD_OSPFD
	if (!strcmp(name, "ospf"))
		initOspf(wp);
#endif
	if (!strcmp(name, "syslog"))
		initSyslogPage(wp);
#ifdef WEB_ENABLE_PPP_DEBUG
	if ( !strcmp(name, "pppSyslog") )
		initPPPSyslog(wp);
#endif
	if (!strcmp(name, "dgw"))
		initDgwPage(wp);
#ifdef CONFIG_ETHWAN
	if ( !strcmp(name, "ethwan") )
		initEthWan(wp);
#endif
#ifdef CONFIG_USER_PPTPD_PPTPD
	if (!strcmp(name, "pptp"))
		initPptp(wp);
#endif
#ifdef CONFIG_USER_L2TPD_LNS
	if (!strcmp(name, "l2tp"))
		initL2tp(wp);
#endif
#if (defined(CONFIG_CMCC) || defined(CONFIG_CU)) && defined(CONFIG_IPV6)
	if (!strcmp(name, "vlan4ipv6"))
		initvlan4ipv6(wp);
#endif

	return 0;
}

#ifdef DOS_SUPPORT
#define DOSENABLE	0x1
#define DOSSYSFLOODSYN	0x2
#define DOSSYSFLOODFIN	0x4
#define	DOSSYSFLOODUDP	0x8
#define DOSSYSFLOODICMP	0x10
#define DOSIPFLOODSYN	0x20
#define DOSIPFLOODFIN	0x40
#define DOSIPFLOODUDP	0x80
#define DOSIPFLOODICMP	0x100
#define DOSTCPUDPPORTSCAN 0x200
#define DOSPORTSCANSENSI  0x800000
#define DOSICMPSMURFENABLED	0x400
#define DOSIPLANDENABLED	0x800
#define DOSIPSPOOFENABLED	0x1000
#define DOSIPTEARDROPENABLED	0x2000
#define DOSPINTOFDEATHENABLED	0x4000
#define DOSTCPSCANENABLED	0x8000
#define DOSTCPSYNWITHDATAENABLED	0x10000
#define DOSUDPBOMBENABLED		0x20000
#define DOSUDPECHOCHARGENENABLED	0x40000
#define DOSSOURCEIPBLOCK		0x400000
void initDosPage(request * wp){
	unsigned int mode;

	mib_get( MIB_DOS_ENABLED, (void *)&mode);
	if (mode & DOSENABLE){
		boaWrite(wp, "%s.DosCfg.dosEnabled.checked = true;\n", DOCUMENT);
		if (mode & DOSSYSFLOODSYN)
			boaWrite(wp, "%s.DosCfg.sysfloodSYN.checked = true;\n", DOCUMENT);
		if (mode & DOSSYSFLOODFIN)
			boaWrite(wp, "%s.DosCfg.sysfloodFIN.checked = true;\n", DOCUMENT);
		if (mode & DOSSYSFLOODUDP)
			boaWrite(wp, "%s.DosCfg.sysfloodUDP.checked = true;\n", DOCUMENT);
		if (mode & DOSSYSFLOODICMP)
			boaWrite(wp, "%s.DosCfg.sysfloodICMP.checked = true;\n", DOCUMENT);
		if (mode & DOSIPFLOODSYN)
			boaWrite(wp, "%s.DosCfg.ipfloodSYN.checked = true;\n", DOCUMENT);
		if (mode & DOSIPFLOODFIN)
			boaWrite(wp, "%s.DosCfg.ipfloodFIN.checked = true;\n", DOCUMENT);
		if (mode & DOSIPFLOODUDP)
			boaWrite(wp, "%s.DosCfg.ipfloodUDP.checked = true;\n", DOCUMENT);
		if (mode & DOSIPFLOODICMP)
			boaWrite(wp, "%s.DosCfg.ipfloodICMP.checked = true;\n", DOCUMENT);
		if (mode & DOSTCPUDPPORTSCAN)
			boaWrite(wp, "%s.DosCfg.TCPUDPPortScan.checked = true;\n", DOCUMENT);
		if (mode & DOSPORTSCANSENSI)
			boaWrite(wp, "%s.DosCfg.portscanSensi.value = 1;\n", DOCUMENT);
		if (mode & DOSICMPSMURFENABLED)
			boaWrite(wp, "%s.DosCfg.ICMPSmurfEnabled.checked = true;\n", DOCUMENT);
		if (mode & DOSIPLANDENABLED)
			boaWrite(wp, "%s.DosCfg.IPLandEnabled.checked = true;\n", DOCUMENT);
		if (mode & DOSIPSPOOFENABLED)
			boaWrite(wp, "%s.DosCfg.IPSpoofEnabled.checked = true;\n", DOCUMENT);
		if (mode & DOSIPTEARDROPENABLED)
			boaWrite(wp, "%s.DosCfg.IPTearDropEnabled.checked = true;\n", DOCUMENT);
		if (mode & DOSPINTOFDEATHENABLED)
			boaWrite(wp, "%s.DosCfg.PingOfDeathEnabled.checked = true;\n", DOCUMENT);
		if (mode & DOSTCPSCANENABLED)
			boaWrite(wp, "%s.DosCfg.TCPScanEnabled.checked = true;\n", DOCUMENT);
		if (mode & DOSTCPSYNWITHDATAENABLED)
			boaWrite(wp, "%s.DosCfg.TCPSynWithDataEnabled.checked = true;\n", DOCUMENT);
		if (mode & DOSUDPBOMBENABLED)
			boaWrite(wp, "%s.DosCfg.UDPBombEnabled.checked = true;\n", DOCUMENT);
		if (mode & DOSUDPECHOCHARGENENABLED)
			boaWrite(wp, "%s.DosCfg.UDPEchoChargenEnabled.checked = true;\n", DOCUMENT);
		if (mode & DOSSOURCEIPBLOCK)
			boaWrite(wp, "%s.DosCfg.sourceIPblock.checked = true;\n", DOCUMENT);

	}
}
#endif

void initSyslogPage(request * wp)
{
	boaWrite(wp, "changelogstatus();");
}

void initDgwPage(request * wp)
{
#ifdef DEFAULT_GATEWAY_V2
	unsigned char dgwip[16];
	unsigned int dgw;
	mib_get(MIB_ADSL_WAN_DGW_ITF, (void *)&dgw);
	getMIB2Str(MIB_ADSL_WAN_DGW_IP, dgwip);
	boaWrite(wp, "\tdgwstatus = %d;\n", dgw);
	boaWrite(wp, "\tgtwy = '%s';\n", dgwip);
#endif
	boaWrite(wp, "%s.getElementById('vlan_show').style.display = 'none';\n", DOCUMENT);

	// Kaohj, differentiate user-level from admin-level
	if (strstr(wp->pathname, "web/admin/"))
		boaWrite(wp, "%s.adsl.add.disabled = true;\n", DOCUMENT);
	else
		boaWrite(wp, "%s.adsl.add.disabled = false;\n", DOCUMENT);
}

#ifdef WEB_ENABLE_PPP_DEBUG
void initPPPSyslog(request * wp)
{
	int enable = 0;
	FILE *fp;

	if (fp = fopen(PPP_SYSLOG, "r")) {
		fscanf(fp, "%d", &enable);
		fclose(fp);
	}
	boaWrite(wp, "%s.formSysLog.pppcap[%d].checked = true;\n", DOCUMENT, enable);
}
#endif

