#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "webs.h"
#include "port.h"
bool_t g_rSessionStart=FALSE;
time_t g_rexpire=0;

char *mgmtUserName() {
   return "user";
}

char *mgmtPassword()
{
	return "pass";
}

// These functions return the number of input items successfully matched and assigned, which can be fewer than provided for.
int boaArgs(int argc, char **argv, char *fmt, ...)
{
	va_list	ap;
	char *cp, **sp;
	int *ip;
	int argnum;
	int argok;
	unsigned int *uip;

	va_start(ap, fmt);

	if (argv == NULL)
		return 0;
	argok = 0;

	for (argnum = 0, cp = fmt; cp && *cp && argv[argnum]; )
	{
		if (*cp++ != '%')
			continue;

		switch (*cp)
		{
			case 'd':
				ip = va_arg(ap, int *);
				*ip = atoi(argv[argnum]);
				argok++;
				break;
			case 'u':
				uip = va_arg(ap, unsigned int *);
				*uip = atoi(argv[argnum]);
				argok++;
				break;
			case 's':
				sp = va_arg(ap, char **);
				*sp = argv[argnum];
				argok++;
				break;
			case '*':
				//printf("ignore it\n");
				break;
			default:
				break;
		}
		argnum++;
	}

	va_end(ap);
	return argok;
}

void boaError(request *wp, int code, char *fmt, ...)
{
   //printf("boaError: %s\n", fmt);
}

void boaDone(request *wp, int code) {
//   printf("boaDone\n");
}

void boaHeader(request* wp)
{
	boaWrite(wp, "<html>\n");
}

void boaFooter(request* wp)
{
	boaWrite(wp, "</html>\n");
}

int boaWrite(request * req, char * fmt, ...)
{
	static char buf[2048];
	va_list args;
	int ret = 0;

	va_start(args, fmt);
	ret += vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);
	boaWriteBlock(req, buf, strlen(buf));

	return ret;
}

int boaWriteDataNonBlock(request *req, char *msg, int msg_len)
{
   return boaWriteBlock(req,msg,msg_len);
}

int boaDeleteUser(char *user) {
   //printf("boaDeleteUser\n");
   return 0;
}

int boaDeleteAccessLimit(char *url) {
   //printf("boaDeleteAccessLimit\n");
   return 0;
}

int boaDeleteGroup(char *group) {
   //printf("boaDeleteGroup\n");
   return 0;
}

bool_t boaGroupExists(char *group) {
   //printf("boaGroupExists\n");
   return 0;
}

int boaAddGroup(char *group, short priv, void * am, bool_t prot, bool_t disabled) {
   //printf("boaAddGroup\n");
   return 0;
}

bool_t boaAccessLimitExists(char *url) {
   //printf("boaAccessLimitExists\n");
   return 0;
}

int boaAddAccessLimit(char *url, void * am, short secure, char *group) {
   //printf("boaAddAccessLimit\n");
   return 0;
}


int boaAddUser(char *user, char *pass, char *group, bool_t prot, bool_t disabled) {
   //printf("boaAddUser\n");
   return 0;
}

void error(char *file, int line, int etype, char *fmt, ...) {
   printf("error\n");
}

void boaFormDefineUserMgmt() {
   //printf("boaFormDefineUserMgmt\n");
}

