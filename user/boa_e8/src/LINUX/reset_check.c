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


int main (int argc, char **argv)
{
#ifdef RESERVE_KEY_SETTING
	FILE *fp=NULL;
	int flag;
	fp = fopen(RESET_CS_FLAG_FILE, "r");
	if(fp)
	{
		if(fscanf(fp, "%d", &flag)==1){
			reset_check(flag);
		}
		fclose(fp);
		unlink(RESET_CS_FLAG_FILE);
	}
#endif
	return 0;
}

