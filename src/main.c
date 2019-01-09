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
	char buf[1024]={0};
    int fd[2];
    int backfd;
    pipe(fd);
    backfd=dup(STDOUT_FILENO);
    dup2(fd[1],STDOUT_FILENO);
    system("date");
    
    read(fd[0],buf,1024);
 
    dup2(backfd,STDOUT_FILENO);
    printf("this is a test :%s",buf);

}


