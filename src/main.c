#include "main.h"

CHAR *strncpy(CHAR *str,CHAR* dst,INT32 n)
{
	assert((str != NULL) && (dst != NULL));
	CHAR *tmp = str;
	
	while(n && (*tmp ++ = *dst ++) != '\0')
	{
		n--;
	}

	printf("n = %d\n",n);

	if(n)
	{
		while(--n)
			*str = '\0';	
	}

	return str;
}

INT32 main(void)
{
	CHAR a[20] = {0};
	CHAR b[20] = "hello world";

	printf("%s\n",strncpy(a,b,5));
	return 0;
}


