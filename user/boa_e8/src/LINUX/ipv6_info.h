#ifndef IPV6_INFO_H
#define IPV6_INFO_H

#define IPV6_BUF_SIZE_256 256
#define IPV6_BUF_SIZE_128 128

#include "mib.h"

typedef struct dnsV6Info {
	unsigned char mode;
	unsigned int wanconn;
	unsigned char nameServer[IPV6_BUF_SIZE_256];
	unsigned char leaseFile[IPV6_BUF_SIZE_128];
} DNS_V6_INFO_T, *DNS_V6_INFO_Tp;


typedef struct prefixV6Info {
	int	RNTime;
	int	RBTime;
	int	PLTime;
	int MLTime;
	unsigned char mode;
	unsigned int wanconn;
	unsigned char prefixIP[IP6_ADDR_LEN];
	unsigned char prefixLen;
	unsigned char leaseFile[IPV6_BUF_SIZE_128];
} PREFIX_V6_INFO_T, *PREFIX_V6_INFO_Tp;

void restartLanV6Server(void);
void restartRadvd(void);
void restartDHCPV6Server(void);
void setup_disable_ipv6(char *itf, int disable);
int ip6toPrefix(void *ip6, int plen, void *prefix);
int startIP_for_V6(MIB_CE_ATM_VC_Tp pEntry);
int stopIP_PPP_for_V6(MIB_CE_ATM_VC_Tp pEntry);
int restart_IPV6Filter(void);
int setupIPV6Filter(void);
int setup_default_IPV6Filter(void);
int get_dnsv6_info(DNS_V6_INFO_Tp dnsV6Info);
int get_prefixv6_info(PREFIX_V6_INFO_Tp prefixInfo);
int mac_meui64(char *src, char *dst);
int start_dhcpv6(int enable);
int start_dhcpv6_new(DNS_V6_INFO_Tp pDnsV6Info, PREFIX_V6_INFO_Tp pPrefixInfo);
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
int _get_prefixv6_info_radvd(PREFIX_V6_INFO_Tp prefixInfo);
#endif
int _get_prefixv6_info(PREFIX_V6_INFO_Tp prefixInfo);
#endif