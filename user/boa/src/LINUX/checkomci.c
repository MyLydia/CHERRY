#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
 
#ifdef EMBED
#include <linux/config.h>
#include <config/autoconf.h>
#else
#include "../../../../include/linux/autoconf.h"
#include "../../../../config/autoconf.h"
#endif
#include "utility.h"

int main (int argc, char **argv)
{
#if defined(CONFIG_LUNA) && defined(CONFIG_RTK_L34_ENABLE)
	int wanPhyPort;
	wanPhyPort = RG_get_wan_phyPortId();
	printf("wanPhyPort=%d\n",wanPhyPort);
	if(wanPhyPort!=-1){
		char sysbuf[128]={0};
		sprintf( sysbuf, "/bin/echo %d nas0 > /proc/rtl8686gmac/dev_port_mapping",wanPhyPort );
		system(sysbuf);
		printf("%s\n",sysbuf);
	}
#endif
#ifdef CONFIG_GPON_FEATURE
	unsigned int pon_mode = 0;
	mib_get(MIB_PON_MODE, &pon_mode);
	if(pon_mode==GPON_MODE)
		checkOMCI_startup();
	//printf("==== check omci mib\n");
#endif
	return 0;
}


