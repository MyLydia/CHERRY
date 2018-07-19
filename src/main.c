#include "main.h"

CHAR *strcpy(CHAR *str,const CHAR* dst)
{
	CHAR *tmp = str;
	assert((str != NULL) && (dst != NULL));
	
	while((*tmp++ = *dst++) != '\0')
		;	

	return str;
}

INT32 main(INT32 argc,CHAR* argv[])
{
	CHAR a[20] = {0};
	CHAR b[] = "world";
	printf("%s\n",strcpy(a,b));

	return 0;
 }
