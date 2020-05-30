#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <linux/netlink.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if_arp.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/wait.h>


#define RT_TABLE_FILE_PATH          "rt_tables"
