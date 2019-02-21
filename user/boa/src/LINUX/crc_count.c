#include <stdio.h>
#include "utility.h"
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
int main(int argc, char **argv)
{
	/* iulian update crc32 to bootloader */
	char* fname = argv[1];
	char str_active[64];
	unsigned char buf1[1024] ;
	int fptr, active;
	unsigned long crc = crc32(0L, NULL, 0);
	char str_crcSum[16], sw_crcHeader[16];

	rtk_env_get("sw_active", str_active, sizeof(str_active));
	sscanf(str_active, "sw_active=%d", &active);
	sprintf(str_active, "%d", 1 - active);

	fptr = open(fname, O_RDONLY, 0);
	if (fptr != NULL) {
		while (read(fptr, buf1, sizeof(buf1)) > 0) {
				crc = crc32(crc, buf1, sizeof(buf1));
		}
		close(fptr);
	}
	else 
		printf("Update the crc32 failed !\n");
	
	sprintf(str_crcSum, "%x",crc);
	sprintf(sw_crcHeader, "%s%d", BOOTLOADER_SW_CRC, 1 - active);
	printf("Update the bootloader %s=%s \n", sw_crcHeader , str_crcSum );
	rtk_env_set(sw_crcHeader, str_crcSum, sizeof(str_crcSum));
	return 0;
}
