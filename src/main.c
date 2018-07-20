#include "main.h"

CHAR *strncpy(CHAR *str,CHAR* dst,INT32 n)
{
	assert((str != NULL) && (dst != NULL));
	INT32 i;
	CHAR *tmp = str;
	
	for(i = 0 ; i < n; i++)
	{
		if(*dst == '\0')
			return str;
		else
			*tmp++ = *dst++;
	}
	return str;
}

INT32 main(void)
{
	CHAR a[20] = {0};
	CHAR b[20] = "hello world";

	printf("%s\n",strncpy(a,b,17));

	return 0;
}


