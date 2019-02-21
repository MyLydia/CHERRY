#include <stdio.h>
#include <sys/signal.h>

#include <rtk/options.h>
#include <rtk/mib.h>
#include <rtk/sysconfig.h>
#include <rtk/utility.h>

#include <unistd.h>
#include <stdlib.h>
#include <string.h>

static void sigexit(int dummy)
{
	exit(0);
}

int main(int argc, char *argv[])
{
	int flag, login=0;
	char *gotpwd;

	char suusr[MAX_NAME_LEN]={0};
	char supass[MAX_NAME_LEN]={0};

	signal(SIGINT, SIG_IGN);
	signal(SIGCHLD, SIG_IGN);
	signal(SIGTERM, sigexit);
	signal(SIGHUP, sigexit);

	while ((flag = getopt(argc, argv, "l:")) != EOF) {
		switch (flag) {
			case 'l':
				login = 1;
				break;
			default:
				break;
		}
	}

#if 0
	mib_get(MIB_SUSER_NAME, (void*)suusr);
	mib_get(MIB_SUSER_PASSWORD, (void*)supass);
#else
	mib_get(MIB_HW_E8BDUSER_NAME, (void*)suusr);
	if(suusr[0] == '\0')
	{
		mib_get(MIB_E8BDUSER_NAME, (void*)suusr);
		mib_get(MIB_E8BDUSER_PASSWORD, (void*)supass);
	}
	else
		mib_get(MIB_HW_E8BDUSER_PASSWORD, (void*)supass);
#endif
	
	while (1) {
		printf("\e[1;1H\e[2JPassword: ");
		gotpwd = getpass("Password: ");

		if(!strcmp(gotpwd, supass))
		{
			printf("\e[1;1H\e[2J");
			va_cmd("/bin/sh", 0, 1);
			return 0;
		}else{
			printf("\e[1;1H\e[2J");
			printf("Error!\n\n");
			return 0;
		}
	}	

	return 0;
}
