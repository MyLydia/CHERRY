#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "utility.h"
 
#ifdef EMBED
#include <linux/config.h>
#include <config/autoconf.h>
#else
#include "../../../../include/linux/autoconf.h"
#include "../../../../config/autoconf.h"
#endif
#if defined(CONFIG_LUNA) && defined(CONFIG_RTK_L34_ENABLE)
#include "rtusr_rg_api.h"
#endif

int main (int argc, char **argv)
{
#if defined(CONFIG_LUNA) && defined(CONFIG_RTK_L34_ENABLE)
#if defined(CONFIG_GPON_FEATURE)
	unsigned int pon_mode = 0;
	mib_get(MIB_PON_MODE, &pon_mode);
	if(pon_mode==GPON_MODE)
		Init_rg_api();
#endif
#endif
	return 0;
}

