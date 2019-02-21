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

#define GEN_FLASH_DEF_CS_FILE "/var/config/flash_def_cs"

int main (int argc, char **argv)
{
	FILE *fp=NULL;
	int fd;
	int flag=1;
	
	doPreRestoreFunc();
	
	fp = fopen(GEN_FLASH_DEF_CS_FILE, "w");
	if(fp){
		fprintf(fp, "%d", flag);
		printf("generate %s flag = %d\n", GEN_FLASH_DEF_CS_FILE, flag);
		fd = fileno(fp);
		fsync(fd);
		fclose(fp);
	}
	else
		printf("generate %s failed!\n", GEN_FLASH_DEF_CS_FILE, flag);

	return 0;
}

