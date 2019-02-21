#ifndef SUBR_WLAN_H
#define SUBR_WLAN_H

#include <ieee802_mib.h>

/* ------------- IOCTL STUFF FOR 802.1x DAEMON--------------------- */

#define RTL8192CD_IOCTL_GET_MIB 0x89f2
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

extern int wlan_idx;
extern const char *WLANIF[];
extern const char IWPRIV[];
extern const char AUTH_DAEMON[];
extern const char IWCONTROL[];
extern const char AUTH_PID[];
extern const char WLAN_AUTH_CONF[];
extern const char *wlan_encrypt[];
#ifdef WLAN_WDS
extern const char WDSIF[];
#endif
extern char *WLANAPIF[];

extern const char *wlan_band[];
extern const char *wlan_mode[];
extern const char *wlan_rate[];
extern const char *wlan_auth[];
extern const char *wlan_preamble[];
//extern const char *wlan_encrypt[];
extern const char *wlan_pskfmt[];
extern const char *wlan_wepkeylen[];
extern const char *wlan_wepkeyfmt[];
extern const char *wlan_Cipher[];

#define SSID_LEN	32
#if defined(WLAN_CLIENT) || defined(WLAN_SITESURVEY)
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
#endif	// of WLAN_CLIENT || WLAN_SITESURVEY


typedef enum _wlan_mac_state {
    STATE_DISABLED=0, STATE_IDLE, STATE_SCANNING, STATE_STARTED, STATE_CONNECTED, STATE_WAITFORKEY
} wlan_mac_state;

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

#ifdef WLAN_SUPPORT
int getWlStaInfo( char *interface,  WLAN_STA_INFO_Tp pInfo );
#endif
void restartWlan(void);
int config_WLAN( int action_type );
#ifdef CONFIG_USER_FON
int setFonFirewall();
#endif

extern int wl_isNband(unsigned char band);
extern void wl_updateSecurity(unsigned char band);
extern unsigned char wl_cipher2mib(unsigned char cipher);

char *getWlanIfName(void);
void getWscPidName(char *wscd_pid_name);
void getWispWanName(char *name, int idx);
void setWlanDevFlag(char *ifname, int set_wan);
int setup_wlan_block(void);

typedef enum { WLAN_AGGREGATION_AMPDU=0, WLAN_AGGREGATION_AMSDU=1} WLAN_AGGREGATION_FLAG_T;

#ifdef RTK_SMART_ROAMING
#define CAPWAP_APP_VAR_DIR "/var/capwap"
#define CAPWAP_APP_ETC_DIR "/etc/capwap"
#define CAPWAP_APP_WLAN_CONFIG CAPWAP_APP_VAR_DIR"/wlan.config"
#define CAPWAP_APP_DHCP_CONFIG CAPWAP_APP_VAR_DIR"/dhcp_mode.config"
#define CAPWAP_APP_CAPWAP_CONFIG CAPWAP_APP_VAR_DIR"/capwap_mode.config"

#define CAPWAP_SMART_ROAM_SCRIPT CAPWAP_APP_VAR_DIR"/sr_script"	// hook point between sys and smart roaming daemon
#define CAPWAP_SR_AUTO_SYNC_CONFIG CAPWAP_APP_VAR_DIR"/wlan_auto_sync.config"	//smart roaming auto sync config file which used to update wlan setting.
#define CAPWAP_APPLY_CHANGE_NOTIFY_FILE CAPWAP_APP_VAR_DIR"/config_notify"

typedef enum {
    CAPWAP_DISABLE = 0,
    CAPWAP_WTP_ENABLE = (1<<0),
    CAPWAP_AC_ENABLE = (1<<1),
    CAPWAP_AUTO_CONFIG_ENABLE = (1<<2),
    CAPWAP_ROAMING_ENABLE = (1<<3),
    CAPWAP_11V_ENABLE = (1<<6)
} CAPWAP_MODE_T;

#define ROAMING_ENABLE	(CAPWAP_WTP_ENABLE | CAPWAP_AC_ENABLE | CAPWAP_ROAMING_ENABLE)

void update_RemoteAC_Config(void);
int setup_capwap_script(void);
int setupWLanRoaming(void);
void setup_capwap_config(void);
void stop_capwap(void);
void start_capwap(void);
#endif
#endif

