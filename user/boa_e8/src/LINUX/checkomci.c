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
#ifdef CONFIG_GPON_FEATURE
	unsigned int pon_mode = 0;
	mib_get(MIB_PON_MODE, &pon_mode);
	if(pon_mode==GPON_MODE)
		checkOMCI_startup();
	//printf("==== check omci mib\n");
#endif
	return 0;
}


