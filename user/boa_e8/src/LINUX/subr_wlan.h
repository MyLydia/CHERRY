#ifndef SUBR_WLAN_H
#define SUBR_WLAN_H

#include "utility.h"
#include <ieee802_mib.h>

/* ------------- IOCTL STUFF FOR 802.1x DAEMON--------------------- */

#define RTL8192CD_IOCTL_GET_MIB 0x89f2
#define RTL8192CD_IOCTL_DEL_STA	0x89f7
#define SIOCGIWIND      0x89fc
#define SIOCGIWRTLSTAINFO  0x8B30
#define SIOCGIWRTLSTANUM                0x8B31  // get the number of stations in table
#define SIOCGIWRTLDRVVERSION            0x8B32
#define SIOCGIWRTLSCANREQ               0x8B33  // scan request
#define SIOCGIWRTLGETBSSDB              0x8B34  // get bss data base
#define SIOCGIWRTLJOINREQ               0x8B35  // join request
#define SIOCGIWRTLJOINREQSTATUS         0x8B36  // get status of join request
#define SIOCGIWRTLGETBSSINFO            0x8B37  // get currnet bss info
#define SIOCGIWRTLGETWDSINFO            0x8B38
#define SIOCMIBINIT             0x8B42
#define SIOCMIBSYNC             0x8B43
#define SIOCGMISCDATA   0x8B48  //get_misc_data
#define SIOC92DAUTOCH	0x8BC5 // manual auto channel
#define SIOCSSREQ		0x8B5C
#define SIOCGIWRTLSSSCORE	0x9002
#define SIOCGISETBCNVSIE	0x9003
#define SIOCGISETPRBVSIE	0x9004

#define RTK_IOCTL_STARTPROBE	0x8BF8
#define RTK_IOCTL_STOPPROBE	0x8BF9
#define RTK_IOCTL_PROBEINFO	0x8BFA
#define RTK_IOCTL_START_ALLCHPROBE	0x8BFB
#define RTK_IOCTL_START_SPECCHPROBE 0x8BFC

#define SIOCGIROAMINGBSSTRANSREQ	0x9007

#define SIOC11KBEACONREQ            0x8BD2
#define SIOC11KBEACONREP            0x8BD3

extern int wlan_idx;
extern const char *WLANIF[];
extern const char IWPRIV[];
extern const char AUTH_DAEMON[];
extern const char IWCONTROL[];
extern const char AUTH_PID[];
extern const char WLAN_AUTH_CONF[];
#ifdef WLAN_WDS
extern const char WDSIF[];
#endif
extern char *WLANAPIF[];

extern const char *wlan_band[];
extern const char *wlan_mode[];
extern const char *wlan_rate[];
extern const char *wlan_auth[];
extern const char *wlan_preamble[];
extern const char *wlan_encrypt[];
extern const char *wlan_pskfmt[];
extern const char *wlan_wepkeylen[];
extern const char *wlan_wepkeyfmt[];
extern const char *wlan_Cipher[];

#define MAX_REQUEST_IE_LEN          16
#define MAX_AP_CHANNEL_REPORT       4
#define MAX_AP_CHANNEL_NUM          8
#define MAX_BEACON_REPORT 			64
#define MAX_BEACON_SUBLEMENT_LEN           226
#define MAX_PROBE_REQ_STA 			64

#define SSID_LEN	32
#if defined(WLAN_CLIENT) || defined(CONFIG_USER_RTK_OMD)
#define	MAX_BSS_DESC	64
#define MESH_ID_LEN 32
typedef struct _OCTET_STRING {
    unsigned char *Octet;
    unsigned short Length;
} OCTET_STRING;
typedef enum _BssType {
    infrastructure = 1,
    independent = 2,
} BssType;
typedef	struct _IbssParms {
    unsigned short	atimWin;
} IbssParms;
//use ieee802_mib.h struct bss_desc instead
#if 0
typedef struct _BssDscr {
    unsigned char bdBssId[6];
    unsigned char bdSsIdBuf[SSID_LEN];
    OCTET_STRING  bdSsId;
    unsigned char	meshid[MESH_ID_LEN];
    unsigned char	*meshidptr;			// unused, for backward compatible
    unsigned short	meshidlen;
    BssType bdType;
    unsigned short bdBcnPer;			// beacon period in Time Units
    unsigned char bdDtimPer;			// DTIM period in beacon periods
    unsigned long bdTstamp[2];			// 8 Octets from ProbeRsp/Beacon
    IbssParms bdIbssParms;			// empty if infrastructure BSS
    unsigned short bdCap;				// capability information
    unsigned char ChannelNumber;			// channel number
    unsigned long bdBrates;
    unsigned long bdSupportRates;
    unsigned char bdsa[6];			// SA address
    unsigned char rssi, sq;			// RSSI and signal strength
    unsigned char network;			// 1: 11B, 2: 11G, 4:11G
    // P2P_SUPPORT
    unsigned char p2pdevname[33];
    unsigned char p2prole;
    unsigned short p2pwscconfig;
    unsigned char p2paddress[6];
    unsigned char stage;			//for V3.3
} BssDscr, *pBssDscr;
#endif
typedef struct bss_desc BssDscr, *pBssDscr;
typedef struct _sitesurvey_status {
    unsigned char number;
    unsigned char pad[3];
    BssDscr bssdb[MAX_BSS_DESC];
} __PACK__ SS_STATUS_T, *SS_STATUS_Tp;
typedef enum _Capability {
    cESS 		= 0x01,
    cIBSS		= 0x02,
    cPollable		= 0x04,
    cPollReq		= 0x01,
    cPrivacy		= 0x10,
    cShortPreamble	= 0x20,
} Capability;
typedef enum _Synchronization_Sta_State{
    STATE_Min		= 0,
    STATE_No_Bss	= 1,
    STATE_Bss		= 2,
    STATE_Ibss_Active	= 3,
    STATE_Ibss_Idle	= 4,
    STATE_Act_Receive	= 5,
    STATE_Pas_Listen	= 6,
    STATE_Act_Listen	= 7,
    STATE_Join_Wait_Beacon = 8,
    STATE_Max		= 9
} Synchronization_Sta_State;
#endif	// of WLAN_CLIENT


typedef enum _wlan_mac_state {
    STATE_DISABLED=0, STATE_IDLE, STATE_SCANNING, STATE_STARTED, STATE_CONNECTED, STATE_WAITFORKEY
} wlan_mac_state;

typedef enum _config_wlan_target {
    CONFIG_WLAN_ALL=0, CONFIG_WLAN_2G, CONFIG_WLAN_5G
} config_wlan_target;

typedef enum _config_wlan_ssid {
    CONFIG_SSID_ROOT=0, CONFIG_SSID1, CONFIG_SSID2, CONFIG_SSID3, CONFIG_SSID4, CONFIG_SSID5, CONFIG_SSID6, CONFIG_SSID7, CONFIG_SSID_ALL
} config_wlan_ssid;

typedef struct _bss_info {
    unsigned char state;
    unsigned char channel;
    unsigned char txRate;
    unsigned char bssid[6];
    unsigned char rssi, sq;	// RSSI  and signal strength
    unsigned char ssid[SSID_LEN+1];
} bss_info;

#ifdef WLAN_WDS
typedef enum _wlan_wds_state {
    STATE_WDS_EMPTY=0, STATE_WDS_DISABLED, STATE_WDS_ACTIVE
} wlan_wds_state;

typedef struct _WDS_INFO {
	unsigned char	state;
	unsigned char	addr[6];
	unsigned long	tx_packets;
	unsigned long	rx_packets;
	unsigned long	tx_errors;
	unsigned char	txOperaRate;
} WDS_INFO_T, *WDS_INFO_Tp;

#endif //WLAN_WDS

struct _misc_data_ {
	unsigned char	mimo_tr_hw_support;
	unsigned char	mimo_tr_used;
	unsigned char	resv[30];
};

#ifdef WPS_QUERY
enum {  NOT_USED=-1, 
		PROTOCOL_START=0, PROTOCOL_PBC_OVERLAPPING=1,
		PROTOCOL_TIMEOUT=2, PROTOCOL_SUCCESS=3 ,
		SEND_EAPOL_START, RECV_EAPOL_START, SEND_EAP_IDREQ, RECV_EAP_IDRSP, 
        SEND_EAP_START, SEND_M1, RECV_M1, SEND_M2, RECV_M2, RECV_M2D, SEND_M3, RECV_M3,
        SEND_M4, RECV_M4, SEND_M5, RECV_M5, SEND_M6, RECV_M6, SEND_M7, RECV_M7,
        SEND_M8, RECV_M8, PROC_EAP_ACK, WSC_EAP_FAIL, HASH_FAIL, HMAC_FAIL, PWD_AUTH_FAIL,
        PROTOCOL_PIN_NUM_ERR,  PROC_EAP_DONE, 
};      //PROTOCOL_TIMEOUT means fail
#endif

typedef struct _dot11k_ap_channel_report
{
    unsigned char len;
    unsigned char op_class;
    unsigned char channel[MAX_AP_CHANNEL_NUM];
}__PACK__ dot11k_ap_channel_report;

typedef enum {
    MEASUREMENT_UNKNOWN = 0,
    MEASUREMENT_PROCESSING = 1,
    MEASUREMENT_SUCCEED = 2,
    MEASUREMENT_INCAPABLE = 3,
    MEASUREMENT_REFUSED = 4,   
}MEASUREMENT_RESULT;

typedef struct _dot11k_beacon_measurement_req
{
    unsigned char op_class;
    unsigned char channel;
    unsigned short random_interval;    
    unsigned short measure_duration;    
    unsigned char mode;     
    unsigned char bssid[MAC_ADDR_LEN];
    char ssid[SSID_LEN+1];
    unsigned char report_detail; /* 0: no-fixed len field and element, 
                                                               1: all fixed len field and elements in Request ie,
                                                               2: all fixed len field and elements (default)*/
    unsigned char request_ie_len;
    unsigned char request_ie[MAX_REQUEST_IE_LEN];   
    dot11k_ap_channel_report ap_channel_report[MAX_AP_CHANNEL_REPORT];    
}__PACK__ dot11k_beacon_measurement_req;

typedef struct _dot11k_beacon_measurement_report_info
{
    unsigned char op_class;
    unsigned char channel;
    unsigned int  measure_time_hi;
    unsigned int  measure_time_lo;
    unsigned short measure_duration;
    unsigned char frame_info;
    unsigned char RCPI;
    unsigned char RSNI;
    unsigned char bssid[MAC_ADDR_LEN];
    unsigned char antenna_id;
    unsigned int  parent_tsf;
}__PACK__ dot11k_beacon_measurement_report_info;

typedef struct _dot11k_beacon_measurement_report
{
    dot11k_beacon_measurement_report_info info;
    unsigned char subelements_len;
    unsigned char subelements[MAX_BEACON_SUBLEMENT_LEN];
}__PACK__ dot11k_beacon_measurement_report;

typedef struct _sta_mac_rssi {
	unsigned char			channel;
	unsigned char			addr[MAC_ADDR_LEN];
	signed char			rssi;	
	unsigned char 			used;
	unsigned char 			Entry;
	unsigned char 			status;		
	unsigned long 				time_stamp; // jiffies time of last probe request
} sta_mac_rssi;

enum { WPS_VERSION_V1=0, WPS_VERSION_V2=1 };

#ifdef WLAN_SUPPORT
int getWlStaInfo( char *interface,  WLAN_STA_INFO_Tp pInfo );
#endif
void restartWlan(void);
int config_WLAN( int action_type, config_wlan_ssid ssid_index );

extern int wl_isNband(unsigned char band);
extern void wl_updateSecurity(unsigned char band);
extern unsigned char wl_cipher2mib(unsigned char cipher);

char *getWlanIfName(void);
void getWscPidName(char *wscd_pid_name);
void getWispWanName(char *name);
void setWlanDevFlag(char *ifname, int set_wan);
int setup_wlan_block(void);
#ifdef WLAN_WPS_VAP
void sync_wps_config_parameter_to_flash(char *filename, char *wlan_interface_name);
int check_is_wps_ssid(int vwlan_idx, unsigned char ssid_num);
#endif

#if (defined(CONFIG_CMCC) || defined(CONFIG_CU) || defined(CONFIG_YUEME)) && defined(CONFIG_RTK_L34_ENABLE)
int ssidisolation_portmap(void);
int setup_wlan_MAC_ACL(void);
#endif
#if defined(WLAN_CLIENT) || defined(CONFIG_USER_RTK_OMD)
int getWlJoinRequest(char *interface, pBssDscr pBss, unsigned char *res);
int getWlSiteSurveyResult(char *interface, SS_STATUS_Tp pStatus );
#endif
int getMiscData(char *interface, struct _misc_data_ *pData);
int get_wlan_net_device_stats(const char *ifname, struct net_device_stats *nds);
int getWlBssInfo(const char *interface, bss_info *pInfo);
int getWlJoinResult(char *interface, unsigned char *res);
int getWlSiteSurveyRequest(char *interface, int *pStatus);
int isValid_wlan_idx(int idx);
int setup_wlan_realtime_acl(int wl_ssid_idx);
int set_wlan_realtime_acl(int wl_ssid_idx, int action, unsigned char *macAddr);
int set_wlan_realtime_acl_mode(int wl_ssid_idx, int mode);
int startWLan(config_wlan_target target, config_wlan_ssid ssid_index);
int useWlanIfVirtIdx(void);
int wlan_getEntry(MIB_CE_MBSSIB_T *pEntry, int index);
int wlan_setEntry(MIB_CE_MBSSIB_T *pEntry, int index);
void getSiteSurveyWlanNeighborAsync(char wlan_idx);
#if defined(CONFIG_WIFI_SIMPLE_CONFIG)
int update_wps_from_mibtable(void);
int update_wps_configured(int reset_flag);
void update_wps_mib(void);
#ifdef WLAN_WPS_VAP
int WPS_updateWscConf(char *in, char *out, int genpin, MIB_CE_MBSSIB_T *Entry, int vwlan_idx, int wlanIdx);
#endif
#endif
int set_wlan_led_status(int led_mode);
#ifdef _PRMT_X_WLANFORISP_
int isWLANForISP(int vwlan_idx);
void update_WLANForISP_configured(void);
void sync_WLANForISP(int ssid_idx, MIB_CE_MBSSIB_T *Entry);
int getWLANForISP_ifname(char *ifname, MIB_WLANFORISP_T *wlan_isp_entry);
#endif
int check_wlan_encrypt(MIB_CE_MBSSIB_Tp Entry);
unsigned int check_wlan_module(void);
int get_TxPowerValue(int phyband, int mode);
unsigned char get_wlan_phyband(void);
#if defined(CONFIG_RTL_STA_CONTROL_SUPPORT) && defined(WLAN_DUALBAND_CONCURRENT)
unsigned int get_root_wlan_status(void);
int SetOrCancelSameSSID(unsigned char sta_control);
#endif
void restart_iwcontrol(void);

typedef struct _wlan_channel_info{
	unsigned int channel;
	unsigned int score;
}wlan_channel_info;

int get_wlan_MAC_ACL_BlockTimes(const unsigned char *mac);
void _gen_guest_mac(const unsigned char *base_mac, const int maxBss, const int guestNum, unsigned char *hwaddr);

#endif
