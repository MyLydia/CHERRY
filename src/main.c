#include "main.h"

INT32 strcmp(const CHAR *str,const CHAR* dst)
{
	int ret = 0;

	while(!(ret = *(unsigned char *)str - *(unsigned char *)dst) && *str)
	{
		str++;
		dst++;

		printf("str = %c\n",*str);
		printf("dst = %c\n",*dst);

	}

	if(ret < 0)
		return -1;
	else if(ret > 0)
		return 1;

	return 0;
}

INT32 main(void)
{
	CHAR a[20] = "hello";
	CHAR b[20] = "hello";
	
	printf("%d\n",strcmp(a,b));
}


