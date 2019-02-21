/*
 *      Web server handler routines for System status
 *
 */

#include "../webs.h"
#include "webform.h"
#include "mib.h"
#include "utility.h"
#include "debug.h"
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_bridge.h>
#include "adsl_drv.h"
#include <stdio.h>
#include <fcntl.h>
#include "signal.h"
#include "../defs.h"
#include "multilang.h"

static const char IF_UP[] = "up";
static const char IF_DOWN[] = "down";
static const char IF_NA[] = "n/a";
#ifdef EMBED
#ifdef CONFIG_USER_PPPOMODEM
const char PPPOM_CONF[] = "/var/ppp/pppom.conf";
#endif //CONFIG_USER_PPPOMODEM
#endif

#if defined(CONFIG_RTL_8676HWNAT)
void formLANPortStatus(request * wp, char *path, char *query)
{
	char *submitUrl, *strSubmitR;
	strSubmitR = boaGetVar(wp, "refresh", "");
	// Refresh
	if (strSubmitR[0]) {
		goto setOk_filter;
	}

setOk_filter:
	submitUrl = boaGetVar(wp, "submit-url", "");
	if (submitUrl[0])
		boaRedirect(wp, submitUrl);
	else
		boaDone(wp, 200);
  	return;
}
void showLANPortStatus(int eid, request * wp, int argc, char **argv)
{
	int i;
	unsigned char strbuf[256];
	for(i=0; i<SW_LAN_PORT_NUM; i++){
		getLANPortStatus(i, strbuf);
#ifndef CONFIG_GENERAL_WEB
		boaWrite(wp,"<tr bgcolor=\"#EEEEEE\">\n"
	    "<td width=40%%><font size=2><b>LAN%d</b></td>\n"
	    "<td width=60%%><font size=2>%s</td>\n</tr>", i+1, strbuf);
#else
		boaWrite(wp,"<tr>\n"
	    "<td width=40%%>LAN%d</td>\n"
	    "<td width=60%%>%s</td>\n</tr>", i+1, strbuf);
#endif
	}
}
#endif

void formStatus(request * wp, char *path, char *query)
{
	char *submitUrl, *strSubmitR, tmpBuf[100];
#ifdef CONFIG_PPP
	char *strSubmitP;
	struct data_to_pass_st msg;
	char buff[256];
	unsigned int i, flag, inf;
	FILE *fp;
#endif
#ifdef CONFIG_USER_PPPOMODEM
	unsigned int cflag[MAX_PPP_NUM+MAX_MODEM_PPPNUM]={0};
#else
	unsigned int cflag[MAX_PPP_NUM]={0};
#endif //CONFIG_USER_PPPOMODEM

#ifdef CONFIG_PPP
	// Added by Jenny, for PPP connecting/disconnecting
#ifdef CONFIG_USER_PPPOMODEM
	for (i=0; i<(MAX_PPP_NUM+MAX_MODEM_PPPNUM); i++)
#else
	for (i=0; i<MAX_PPP_NUM; i++)
#endif //CONFIG_USER_PPPOMODEM
	{
		char tmp[15], tp[10];

		sprintf(tp, "ppp%d", i);
		if (find_ppp_from_conf(tp)) {
			if (fp=fopen("/tmp/ppp_up_log", "r")) {
				while ( fgets(buff, sizeof(buff), fp) != NULL ) {
					if(sscanf(buff, "%d %d", &inf, &flag) != 2)
						break;
					else {
						if (inf == i)
							cflag[i] = flag;
					}
				}
				fclose(fp);
			}
			sprintf(tmp, "submitppp%d", i);
			strSubmitP = boaGetVar(wp, tmp, "");
			if ( strSubmitP[0] ) {
				if ((strcmp(strSubmitP, multilang(LANG_CONNECT)) == 0)) {
					if (cflag[i]) {
						snprintf(msg.data, BUF_SIZE, "spppctl up %u", i);
						usleep(3000000);
						TRACE(STA_SCRIPT, "%s\n", msg.data);
						write_to_pppd(&msg);
							//add by ramen to resolve for clicking "connect" button twice.
					}
				} else if (strcmp(strSubmitP, multilang(LANG_DISCONNECT)) == 0) {

					snprintf(msg.data, BUF_SIZE, "spppctl down %u", i);
					TRACE(STA_SCRIPT, "%s\n", msg.data);
					write_to_pppd(&msg);
						//add by ramen to resolve for clicking "disconnect" button twice.
				} else {
					strcpy(tmpBuf, multilang(LANG_INVALID_PPP_ACTION));
					goto setErr_filter;
				}
			}
		}
	}
#endif

	strSubmitR = boaGetVar(wp, "refresh", "");
	// Refresh
	if (strSubmitR[0]) {
		goto setOk_filter;
	}

setOk_filter:
	submitUrl = boaGetVar(wp, "submit-url", "");
	if (submitUrl[0])
		boaRedirect(wp, submitUrl);
	else
		boaDone(wp, 200);
  	return;

setErr_filter:
	ERR_MSG(tmpBuf);
}

void formDate(request * wp, char *path, char *query)
{
	char *strVal, *submitUrl;
	time_t tm;
	struct tm tm_time;

	time(&tm);
	memcpy(&tm_time, localtime(&tm), sizeof(tm_time));

	strVal = boaGetVar(wp, "sys_month", "");
	if (strVal[0])
		tm_time.tm_mon = atoi(strVal);

	strVal = boaGetVar(wp, "sys_day", "");
	if (strVal[0])
		tm_time.tm_mday = atoi(strVal);

	strVal = boaGetVar(wp, "sys_year", "");
	if (strVal[0])
		tm_time.tm_year = atoi(strVal) - 1900;

	strVal = boaGetVar(wp, "sys_hour", "");
	if (strVal[0])
		tm_time.tm_hour = atoi(strVal);

	strVal = boaGetVar(wp, "sys_minute", "");
	if (strVal[0])
		tm_time.tm_min = atoi(strVal);

	strVal = boaGetVar(wp, "sys_second", "");
	if (strVal[0])
		tm_time.tm_sec = atoi(strVal);

	tm = mktime(&tm_time);

	if (stime(&tm) < 0) {
		perror("cannot set date");
	}

	OK_MSG1(multilang(LANG_SYSTEM_DATE_HAS_BEEN_MODIFIED_SUCCESSFULLY_PLEASE_REFLESH_YOUR_STATUS_PAGE), NULL);
	return;
}

int cpuUtility(int eid, request * wp, int argc, char **argv)
{
	int nBytesSent=0;
#ifdef CPU_UTILITY	
	unsigned char buffer[256+1]="";

	if (getSYS2Str(SYS_CPU_UTIL, buffer))
		sprintf(buffer, "");
#ifndef CONFIG_GENERAL_WEB
	nBytesSent += boaWrite(wp, "<tr bgcolor=\"#EEEEEE\">\n");
	nBytesSent += boaWrite(wp, "	<td width=40%%><font size=2><b>%s</b></td>\n", multilang(LANG_CPU_UTILITY));
	nBytesSent += boaWrite(wp, "	<td width=60%%><font size=2>%s</td>\n", buffer);
#else
	nBytesSent += boaWrite(wp, "<tr>\n");
	nBytesSent += boaWrite(wp, "    <th width=40%%>%s</th>\n", multilang(LANG_CPU_UTILITY));
	nBytesSent += boaWrite(wp, "    <td width=60%%>%s</td>\n", buffer);
#endif
	nBytesSent += boaWrite(wp, "</tr>\n");
#endif	
	return nBytesSent;
}

int memUtility(int eid, request * wp, int argc, char **argv)
{
	int nBytesSent=0;
#ifdef MEM_UTILITY	
	unsigned char buffer[256+1]="";
	
	if (getSYS2Str(SYS_MEM_UTIL, buffer))
		sprintf(buffer, "");
	
#ifndef CONFIG_GENERAL_WEB	
	nBytesSent += boaWrite(wp, "<tr bgcolor=\"#DDDDDD\">\n");
	nBytesSent += boaWrite(wp, "	<td width=40%%><font size=2><b>%s</b></td>\n", multilang(LANG_MEM_UTILITY));
	nBytesSent += boaWrite(wp, "	<td width=60%%><font size=2>%s</td>\n", buffer);
#else
	nBytesSent += boaWrite(wp, "<tr>\n");
	nBytesSent += boaWrite(wp, "    <th width=40%%>%s</th>\n", multilang(LANG_MEM_UTILITY));
	nBytesSent += boaWrite(wp, "    <td width=60%%>%s</td>\n", buffer);
#endif
	nBytesSent += boaWrite(wp, "</tr>\n");
#endif
	return nBytesSent;
}

#ifdef CONFIG_USER_PPPOMODEM
#undef FILE_LOCK
int wan3GTable(int eid, request * wp, int argc, char **argv)
{
	int nBytesSent=0;
#ifndef CONFIG_GENERAL_WEB
	
	nBytesSent += boaWrite(wp, "<br>\n");
	nBytesSent += boaWrite(wp, "<table width=600 border=0>\n");
	nBytesSent += boaWrite(wp, "  <tr>\n");
	nBytesSent += boaWrite(wp, "	<td width=100%% colspan=5 bgcolor=\"#008000\">\n"
								  " 	 <font color=\"#FFFFFF\" size=2><b>3G %s</b></font>\n"
								  "    </td>\n", multilang(LANG_CONFIGURATION));
	nBytesSent += boaWrite(wp, "  </tr>\n");
	nBytesSent += boaWrite(wp, "  <tr bgcolor=\"#808080\">\n"
								  "    <td width=\"15%%\" align=center><font size=2><b>%s</b></font></td>\n"
 	                              "    <td width=\"15%%\" align=center><font size=2><b>%s</b></font></td>\n"
 	                              "    <td width=\"25%%\" align=center><font size=2><b>%s</b></font></td>\n"
 	                              "    <td width=\"25%%\" align=center><font size=2><b>%s</b></font></td>\n"
 	                              "    <td width=\"20%%\" align=center><font size=2><b>%s</b></font></td>\n"
	                              "  </tr>\n",
#else
	nBytesSent += boaWrite(wp, "<div class=\"column\">\n");
	nBytesSent += boaWrite(wp, "<div class=\"column_title\">\n");
	nBytesSent += boaWrite(wp, "   <div class=\"column_title_left\"></div>\n"
	                              "      <p>3G %s</p>\n"
	                              "    <div class=\"column_title_right\"></div>\n", multilang(LANG_CONFIGURATION));
	nBytesSent += boaWrite(wp, "  </div>\n");

	nBytesSent += boaWrite(wp, "  <div class=\"data_common data_vertical\">\n"
								"<table>"
                              	      "    <th width=\"15%%\" align=center>%s</th>\n"
	                              "    <th width=\"15%%\" align=center>%s</th>\n"
	                              "    <th width=\"25%%\" align=center>%s</th>\n"
	                              "    <th width=\"25%%\" align=center>%s</th>\n"
	                              "    <th width=\"20%%\" align=center>%s</th>\n"
	                              "  </tr>\n",
#endif	              
				multilang(LANG_INTERFACE), multilang(LANG_PROTOCOL), multilang(LANG_IP_ADDRESS),
				multilang(LANG_GATEWAY), multilang(LANG_STATUS));

	{
		MIB_WAN_3G_T entry,*p;
		p=&entry;
		if( mib_chain_get( MIB_WAN_3G_TBL, 0, (void*)p) && p->enable )
		{
			int mppp_idx;
			char mppp_ifname[IFNAMSIZ];
			char mppp_protocol[10];
			char mppp_ipaddr[20];
			char mppp_remoteip[20];
			char *mppp_status;
			char mppp_uptime[20]="";
			char mppp_totaluptime[20]="";
			struct in_addr inAddr;
			int flags;
			char *temp;
			int pppConnectStatus, pppDod;
			FILE *fp;
			#ifdef FILE_LOCK
			struct flock flpom;
			int fdpom;
			#endif

			mppp_idx=MODEM_PPPIDX_FROM;
			sprintf( mppp_ifname, "ppp%d", mppp_idx );
			strcpy( mppp_protocol, "PPP" );

			if (getInAddr( mppp_ifname, IP_ADDR, (void *)&inAddr) == 1)
			{
				sprintf( mppp_ipaddr, "%s",   inet_ntoa(inAddr) );
				if (strcmp(mppp_ipaddr, "64.64.64.64") == 0)
					strcpy(mppp_ipaddr, "");
			}else
				strcpy( mppp_ipaddr, "" );

			if (getInAddr( mppp_ifname, DST_IP_ADDR, (void *)&inAddr) == 1)
			{
				struct in_addr gw_in;
				char gw_tmp[20];
				gw_in.s_addr=htonl(0x0a404040+mppp_idx);
				sprintf( gw_tmp, "%s",    inet_ntoa(gw_in) );

				sprintf( mppp_remoteip, "%s",   inet_ntoa(inAddr) );
				if( strcmp(mppp_remoteip, gw_tmp)==0 )
					strcpy(mppp_remoteip, "");
				else if (strcmp(mppp_remoteip, "64.64.64.64") == 0)
					strcpy(mppp_remoteip, "");
			}else
				strcpy( mppp_remoteip, "" );


			if (getInFlags( mppp_ifname, &flags) == 1)
			{
				if (flags & IFF_UP) {
					if (getInAddr(mppp_ifname, IP_ADDR, (void *)&inAddr) == 1) {
						temp = inet_ntoa(inAddr);
						if (strcmp(temp, "64.64.64.64"))
							mppp_status = (char *)IF_UP;
						else
							mppp_status = (char *)IF_DOWN;
					}else
						mppp_status = (char *)IF_DOWN;
				}else
					mppp_status = (char *)IF_DOWN;
			}else
				mppp_status = (char *)IF_NA;

			if (strcmp(mppp_status, (char *)IF_UP) == 0)
				pppConnectStatus = 1;
			else{
				pppConnectStatus = 0;
				mppp_ipaddr[0] = '\0';
				mppp_remoteip[0] = '\0';
			}

			if(p->backup || p->ctype==CONNECT_ON_DEMAND && p->idletime!=0) //added by paula, 3g backup PPP
				pppDod=1;
			else
				pppDod=0;

			#ifdef FILE_LOCK
			//file locking
			fdpom = open(PPPOM_CONF, O_RDWR);
			if (fdpom != -1) {
				flpom.l_type = F_WRLCK;
				flpom.l_whence = SEEK_SET;
				flpom.l_start = 0;
				flpom.l_len = 0;
				flpom.l_pid = getpid();
				if (fcntl(fdpom, F_SETLKW, &flpom) == -1)
					printf("pppom write lock failed\n");
				//printf( "wan3GTable: pppom write lock successfully\n" );
			}
			#endif
			if (!(fp=fopen(PPPOM_CONF, "r")))
				printf("%s not exists.\n", PPPOM_CONF);
			else {
				char	buff[256], tmp1[20], tmp2[20], tmp3[20], tmp4[20];

				fgets(buff, sizeof(buff), fp);
				if( fgets(buff, sizeof(buff), fp) != NULL )
				{
					if (sscanf(buff, "%s%*s%s%s", tmp1, tmp2, tmp3) != 3)
					{
						printf("Unsuported pppoa configuration format\n");
					}else {
						if( !strcmp(mppp_ifname,tmp1) )
						{
							strcpy(mppp_uptime, tmp2);
							strcpy(mppp_totaluptime, tmp3);
						}
					}
				}
				fclose(fp);
			}
			#ifdef FILE_LOCK
			//file unlocking
			if (fdpom != -1) {
				flpom.l_type = F_UNLCK;
				if (fcntl(fdpom, F_SETLK, &flpom) == -1)
					printf("pppom write unlock failed\n");
				close(fdpom);
				//printf( "wan3GTable: pppom write unlock successfully\n" );
			}
			#endif
#ifndef CONFIG_GENERAL_WEB
			nBytesSent += boaWrite(wp, "  <tr bgcolor=\"#EEEEEE\">\n"
			                              "    <td align=center width=\"15%%\"><font size=2>%s</td>\n"
			                              "    <td align=center width=\"15%%\"><font size=2>%s</td>\n"
			                              "    <td align=center width=\"25%%\"><font size=2>%s</td>\n"
			                              "    <td align=center width=\"25%%\"><font size=2>%s</td>\n",
			                              mppp_ifname, mppp_protocol, mppp_ipaddr, mppp_remoteip);

			nBytesSent += boaWrite(wp, "    <td align=center width=\"20%%\"><font size=2>%s %s / %s ",
								mppp_status, mppp_uptime, mppp_totaluptime );
			if(!pppDod)
			{
				nBytesSent += boaWrite(wp, "<input type=\"submit\" value=\"%s\" name=\"submit%s\">\n",
							(pppConnectStatus==1) ?
							multilang(LANG_DISCONNECT) : multilang(LANG_CONNECT), mppp_ifname);
			}
#else
			nBytesSent += boaWrite(wp, "  <tr>\n"
										  "    <td align=center width=\"15%%\">%s</td>\n"
										  "    <td align=center width=\"15%%\">%s</td>\n"
										  "    <td align=center width=\"25%%\">%s</td>\n"
										  "    <td align=center width=\"25%%\">%s</td>\n",					   
										  mppp_ifname, mppp_protocol, mppp_ipaddr, mppp_remoteip);

			nBytesSent += boaWrite(wp, "	<td align=center width=\"20%%\">%s %s / %s ",
								mppp_status, mppp_uptime, mppp_totaluptime );
			if(!pppDod)
			{
				nBytesSent += boaWrite(wp, "<input class=\"inner_btn\" type=\"submit\" value=\"%s\" name=\"submit%s\">\n",
							(pppConnectStatus==1) ?
							multilang(LANG_DISCONNECT) : multilang(LANG_CONNECT), mppp_ifname);
			}
#endif
			nBytesSent += boaWrite(wp, "	</td>\n");
			nBytesSent += boaWrite(wp, "  </tr>\n");
		}
	}

	nBytesSent += boaWrite(wp, "</table>");
#ifdef CONFIG_GENERAL_WEB
	nBytesSent += boaWrite(wp, "</div></div>");
#endif

	return nBytesSent;
}
#else
int wan3GTable(int eid, request * wp, int argc, char **argv)
{
	int nBytesSent=0;
	return nBytesSent;
}
#endif //CONFIG_USER_PPPOMODEM

#ifdef CONFIG_USER_PPTP_CLIENT_PPTP
int wanPPTPTable(int eid, request * wp, int argc, char **argv)
{
	int nBytesSent=0;
	MIB_PPTP_T Entry;
	unsigned int entryNum, i;

#ifndef CONFIG_GENERAL_WEB
	nBytesSent += boaWrite(wp, "<br>\n");
	nBytesSent += boaWrite(wp, "<table width=600 border=0>\n");
	nBytesSent += boaWrite(wp, "  <tr>\n");
	nBytesSent += boaWrite(wp, "    <td width=100%% colspan=5 bgcolor=\"#008000\">\n"
	                              "      <font color=\"#FFFFFF\" size=2><b>PPTP %s</b></font>\n"
	                              "    </td>\n", multilang(LANG_CONFIGURATION));
	nBytesSent += boaWrite(wp, "  </tr>\n");

	nBytesSent += boaWrite(wp, "  <tr bgcolor=\"#808080\">\n"
                              	      "    <td width=\"15%%\" align=center><font size=2><b>%s</b></font></td>\n"
	                              "    <td width=\"15%%\" align=center><font size=2><b>%s</b></font></td>\n"
	                              "    <td width=\"25%%\" align=center><font size=2><b>%s</b></font></td>\n"
	                              "    <td width=\"25%%\" align=center><font size=2><b>%s</b></font></td>\n"
	                              "    <td width=\"20%%\" align=center><font size=2><b>%s</b></font></td>\n"
	                              "  </tr>\n",
#else
	nBytesSent += boaWrite(wp, "<div class=\"column\">\n");
	nBytesSent += boaWrite(wp, "<div class=\"column_title\">\n");
	nBytesSent += boaWrite(wp, "   <div class=\"column_title_left\"></div>\n"
	                              "      <p>PPTP %s</p>\n"
	                              "    <div class=\"column_title_right\"></div>\n", multilang(LANG_CONFIGURATION));
	nBytesSent += boaWrite(wp, "  </div>\n");
	nBytesSent += boaWrite(wp, "  <div class=\"data_common data_vertical\">\n"
								"<table>");
	nBytesSent += boaWrite(wp, "  <tr>\n"
                              	      "    <th width=\"15%%\" align=center>%s</th>\n"
	                              "    <th width=\"15%%\" align=center>%s</th>\n"
	                              "    <th width=\"25%%\" align=center>%s</th>\n"
	                              "    <th width=\"25%%\" align=center>%s</th>\n"
	                              "    <th width=\"20%%\" align=center>%s</th>\n"
	                              "  </tr>\n",
#endif
				multilang(LANG_INTERFACE), multilang(LANG_PROTOCOL), multilang(LANG_IP_ADDRESS),
				multilang(LANG_GATEWAY), multilang(LANG_STATUS));

	entryNum = mib_chain_total(MIB_PPTP_TBL);
	for (i=0; i<entryNum; i++)
	{
		char mppp_ifname[IFNAMSIZ];
		char mppp_protocol[10];
		char mppp_ipaddr[20];
		char mppp_remoteip[20];
		char *mppp_status;
		struct in_addr inAddr;
		int flags;

		if (!mib_chain_get(MIB_PPTP_TBL, i, (void *)&Entry))
		{
			boaError(wp, 400, "Get chain record error!\n");
			return -1;
		}

		ifGetName(Entry.ifIndex, mppp_ifname, sizeof(mppp_ifname));
		strcpy( mppp_protocol, "PPP" );

		if (getInAddr( mppp_ifname, IP_ADDR, (void *)&inAddr) == 1)
		{
			sprintf( mppp_ipaddr, "%s",   inet_ntoa(inAddr) );
		}else
			strcpy( mppp_ipaddr, "" );

		if (getInAddr( mppp_ifname, DST_IP_ADDR, (void *)&inAddr) == 1)
		{
			sprintf( mppp_remoteip, "%s",   inet_ntoa(inAddr) );
		}else
			strcpy( mppp_remoteip, "" );

		if (getInFlags( mppp_ifname, &flags) == 1)
		{
			if (flags & IFF_UP) {
				mppp_status = (char *)IF_UP;
			}else
				mppp_status = (char *)IF_DOWN;
		}else
			mppp_status = (char *)IF_NA;
#ifndef CONFIG_GENERAL_WEB
		nBytesSent += boaWrite(wp, "  <tr bgcolor=\"#EEEEEE\">\n"
		                              "    <td align=center width=\"15%%\"><font size=2>%s</td>\n"
		                              "    <td align=center width=\"15%%\"><font size=2>%s</td>\n"
		                              "    <td align=center width=\"25%%\"><font size=2>%s</td>\n"
		                              "    <td align=center width=\"25%%\"><font size=2>%s</td>\n",
		                              mppp_ifname, mppp_protocol, mppp_ipaddr, mppp_remoteip);

		nBytesSent += boaWrite(wp, "    <td align=center width=\"20%%\"><font size=2>%s ",
							mppp_status );
#else
		nBytesSent += boaWrite(wp, "  <tr>\n"
		                              "    <td align=center width=\"15%%\">%s</td>\n"
		                              "    <td align=center width=\"15%%\">%s</td>\n"
		                              "    <td align=center width=\"25%%\">%s</td>\n"
		                              "    <td align=center width=\"25%%\">%s</td>\n",
		                              mppp_ifname, mppp_protocol, mppp_ipaddr, mppp_remoteip);

		nBytesSent += boaWrite(wp, "    <td align=center width=\"20%%\">%s ",
							mppp_status );
#endif
		nBytesSent += boaWrite(wp, "	</td>\n");
		nBytesSent += boaWrite(wp, "  </tr>\n");

	}
	nBytesSent += boaWrite(wp, "</table>");
#ifdef CONFIG_GENERAL_WEB
	nBytesSent += boaWrite(wp, "</div></div>");
#endif
	return nBytesSent;
}
#else
int wanPPTPTable(int eid, request * wp, int argc, char **argv)
{
	int nBytesSent=0;
	return nBytesSent;
}
#endif //CONFIG_USER_PPTP_CLIENT_PPTP

#ifdef CONFIG_USER_L2TPD_L2TPD
int wanL2TPTable(int eid, request * wp, int argc, char **argv)
{
	int nBytesSent=0;
	MIB_L2TP_T Entry;
	unsigned int entryNum, i;

#ifndef CONFIG_GENERAL_WEB
	nBytesSent += boaWrite(wp, "<br>\n");
	nBytesSent += boaWrite(wp, "<table width=600 border=0>\n");
	nBytesSent += boaWrite(wp, "  <tr>\n");
	nBytesSent += boaWrite(wp, "    <td width=100%% colspan=5 bgcolor=\"#008000\">\n"
	                              "      <font color=\"#FFFFFF\" size=2><b>L2TP %s</b></font>\n"
	                              "    </td>\n", multilang(LANG_CONFIGURATION));
	nBytesSent += boaWrite(wp, "  </tr>\n");

	nBytesSent += boaWrite(wp, "  <tr bgcolor=\"#808080\">\n"
                              	      "    <td width=\"15%%\" align=center><font size=2><b>%s</b></font></td>\n"
	                              "    <td width=\"15%%\" align=center><font size=2><b>%s</b></font></td>\n"
	                              "    <td width=\"25%%\" align=center><font size=2><b>%s %s</b></font></td>\n"
	                              "    <td width=\"25%%\" align=center><font size=2><b>%s %s</b></font></td>\n"
	                              "    <td width=\"20%%\" align=center><font size=2><b>%s</b></font></td>\n"
	                              "  </tr>\n",
#else
	nBytesSent += boaWrite(wp, "<div class=\"column\">\n");
	nBytesSent += boaWrite(wp, "<div class=\"column_title\">\n");
	nBytesSent += boaWrite(wp, "   <div class=\"column_title_left\"></div>\n"
	                              "      <p>L2TP %s</p>\n"
	                              "    <div class=\"column_title_right\"></div>\n", multilang(LANG_CONFIGURATION));
	nBytesSent += boaWrite(wp, "  </div>\n");
	nBytesSent += boaWrite(wp, "  <div class=\"data_common data_vertical\">\n"
								"<table>");
								
	nBytesSent += boaWrite(wp, "  <tr>\n"
                              	      "    <th width=\"15%%\" align=center>%s</th>\n"
	                              "    <th width=\"15%%\" align=center>%s</th>\n"
	                              "    <th width=\"25%%\" align=center>%s %s</th>\n"
	                              "    <th width=\"25%%\" align=center>%s %s</th>\n"
	                              "    <th width=\"20%%\" align=center>%s</th>\n"
	                              "  </tr>\n",
#endif
		multilang(LANG_INTERFACE), multilang(LANG_PROTOCOL), multilang(LANG_LOCAL),
		multilang(LANG_IP_ADDRESS), multilang(LANG_REMOTE), multilang(LANG_IP_ADDRESS),
		multilang(LANG_STATUS));

	entryNum = mib_chain_total(MIB_L2TP_TBL);
	for (i=0; i<entryNum; i++)
	{
		char mppp_ifname[IFNAMSIZ];
		char mppp_protocol[10];
		char mppp_ipaddr[20];
		char mppp_remoteip[20];
		char *mppp_status;
		struct in_addr inAddr;
		int flags;

		if (!mib_chain_get(MIB_L2TP_TBL, i, (void *)&Entry))
		{
			boaError(wp, 400, "Get chain record error!\n");
			return -1;
		}

		ifGetName(Entry.ifIndex, mppp_ifname, sizeof(mppp_ifname));
		strcpy( mppp_protocol, "PPP" );

		if (getInAddr( mppp_ifname, IP_ADDR, (void *)&inAddr) == 1)
		{
			sprintf( mppp_ipaddr, "%s",   inet_ntoa(inAddr) );
		}else
			strcpy( mppp_ipaddr, "" );

		if (getInAddr( mppp_ifname, DST_IP_ADDR, (void *)&inAddr) == 1)
		{
			sprintf( mppp_remoteip, "%s",   inet_ntoa(inAddr) );
		}else
			strcpy( mppp_remoteip, "" );

		if (getInFlags( mppp_ifname, &flags) == 1)
		{
			if (flags & IFF_UP) {
				mppp_status = (char *)IF_UP;
			}else
				mppp_status = (char *)IF_DOWN;
		}else
			mppp_status = (char *)IF_NA;
#ifndef CONFIG_GENERAL_WEB
		nBytesSent += boaWrite(wp, "  <tr bgcolor=\"#EEEEEE\">\n"
		                              "    <td align=center width=\"15%%\"><font size=2>%s</td>\n"
		                              "    <td align=center width=\"15%%\"><font size=2>%s</td>\n"
		                              "    <td align=center width=\"25%%\"><font size=2>%s</td>\n"
		                              "    <td align=center width=\"25%%\"><font size=2>%s</td>\n",
		                              mppp_ifname, mppp_protocol, mppp_ipaddr, mppp_remoteip);

		nBytesSent += boaWrite(wp, "    <td align=center width=\"20%%\"><font size=2>%s ",
							mppp_status );
#else
		nBytesSent += boaWrite(wp, "  <tr>\n"
		                              "    <td align=center width=\"15%%\">%s</td>\n"
		                              "    <td align=center width=\"15%%\">%s</td>\n"
		                              "    <td align=center width=\"25%%\">%s</td>\n"
		                              "    <td align=center width=\"25%%\">%s</td>\n",
		                              mppp_ifname, mppp_protocol, mppp_ipaddr, mppp_remoteip);

		nBytesSent += boaWrite(wp, "    <td align=center width=\"20%%\">%s ",
							mppp_status );
#endif

		nBytesSent += boaWrite(wp, "	</td>\n");
		nBytesSent += boaWrite(wp, "  </tr>\n");

	}
	nBytesSent += boaWrite(wp, "</table>");
#ifdef CONFIG_GENERAL_WEB
	nBytesSent += boaWrite(wp, "</div></div>");
#endif
	return nBytesSent;
}
#else
int wanL2TPTable(int eid, request * wp, int argc, char **argv)
{
	int nBytesSent=0;
	return nBytesSent;
}
#endif //CONFIG_USER_L2TPD_L2TPD

#ifdef CONFIG_NET_IPIP
int wanIPIPTable(int eid, request * wp, int argc, char **argv)
{
	int nBytesSent=0;
	MIB_IPIP_T Entry;
	unsigned int entryNum, i;

#ifndef CONFIG_GENERAL_WEB
	nBytesSent += boaWrite(wp, "<br>\n");
	nBytesSent += boaWrite(wp, "<table width=600 border=0>\n");
	nBytesSent += boaWrite(wp, "  <tr>\n");
	nBytesSent += boaWrite(wp, "    <td width=100%% colspan=5 bgcolor=\"#008000\">\n"
	                              "      <font color=\"#FFFFFF\" size=2><b>IPIP %s</b></font>\n"
	                              "    </td>\n", multilang(LANG_CONFIGURATION));
	nBytesSent += boaWrite(wp, "  </tr>\n");

	nBytesSent += boaWrite(wp, "  <tr bgcolor=\"#808080\">\n"
                              	      "    <td width=\"15%%\" align=center><font size=2><b>%s</b></font></td>\n"
	                              "    <td width=\"15%%\" align=center><font size=2><b>%s</b></font></td>\n"
	                              "    <td width=\"25%%\" align=center><font size=2><b>%s</b></font></td>\n"
	                              "    <td width=\"25%%\" align=center><font size=2><b>%s</b></font></td>\n"
	                              "    <td width=\"20%%\" align=center><font size=2><b>%s</b></font></td>\n"
	                              "  </tr>\n",
#else
	nBytesSent += boaWrite(wp, "<div class=\"column\">\n");
	nBytesSent += boaWrite(wp, "<div class=\"column_title\">\n");
	nBytesSent += boaWrite(wp, "   <div class=\"column_title_left\"></div>\n"
	                              "      <p>IPIP %s</p>\n"
	                              "    <div class=\"column_title_right\"></div>\n", multilang(LANG_CONFIGURATION));
	nBytesSent += boaWrite(wp, "  </div>\n");
	nBytesSent += boaWrite(wp, "  <div class=\"data_common data_vertical\">\n"
								"<table>"
	nBytesSent += boaWrite(wp, "  <tr>\n"
                              	      "    <th width=\"15%%\" align=center>%s</th>\n"
	                              "    <th width=\"15%%\" align=center>%s</th>\n"
	                              "    <th width=\"25%%\" align=center>%s</th>\n"
	                              "    <th width=\"25%%\" align=center>%s</th>\n"
	                              "    <th width=\"20%%\" align=center>%s</th>\n"
	                              "  </tr>\n",
#endif	                          
				multilang(LANG_INTERFACE), multilang(LANG_PROTOCOL), multilang(LANG_IP_ADDRESS),
				multilang(LANG_GATEWAY), multilang(LANG_STATUS));

	entryNum = mib_chain_total(MIB_IPIP_TBL);
	for (i=0; i<entryNum; i++)
	{
		char mppp_ifname[IFNAMSIZ];
		char mppp_protocol[10];
		char mppp_ipaddr[20];
		char mppp_remoteip[20];
		char *mppp_status;
		struct in_addr inAddr;
		int flags;

		if (!mib_chain_get(MIB_IPIP_TBL, i, (void *)&Entry))
		{
			boaError(wp, 400, "Get chain record error!\n");
			return -1;
		}

		snprintf(mppp_ipaddr, 20, "%s", inet_ntoa(*((struct in_addr *)&Entry.saddr)));
		snprintf(mppp_remoteip, 20, "%s", inet_ntoa(*((struct in_addr *)&Entry.daddr)));
		ifGetName(Entry.ifIndex, mppp_ifname, sizeof(mppp_ifname));
		strcpy( mppp_protocol, "IPinIP" );

		if (getInFlags( mppp_ifname, &flags) == 1)
		{
			if (flags & IFF_UP) {
				mppp_status = (char *)IF_UP;
			}else
				mppp_status = (char *)IF_DOWN;
		}else
			mppp_status = (char *)IF_DOWN;

#ifndef CONFIG_GENERAL_WEB
		nBytesSent += boaWrite(wp, "  <tr bgcolor=\"#EEEEEE\">\n"
		                              "    <td align=center width=\"15%%\"><font size=2>%s</td>\n"
		                              "    <td align=center width=\"15%%\"><font size=2>%s</td>\n"
		                              "    <td align=center width=\"25%%\"><font size=2>%s</td>\n"
		                              "    <td align=center width=\"25%%\"><font size=2>%s</td>\n",
		                              mppp_ifname, mppp_protocol, mppp_ipaddr, mppp_remoteip);

		nBytesSent += boaWrite(wp, "    <td align=center width=\"20%%\"><font size=2>%s ",
							mppp_status );
#else
		nBytesSent += boaWrite(wp, "  <tr>\n"
		                              "    <td align=center width=\"15%%\">%s</td>\n"
		                              "    <td align=center width=\"15%%\">%s</td>\n"
		                              "    <td align=center width=\"25%%\">%s</td>\n"
		                              "    <td align=center width=\"25%%\">%s</td>\n",
		                              mppp_ifname, mppp_protocol, mppp_ipaddr, mppp_remoteip);

		nBytesSent += boaWrite(wp, "    <td align=center width=\"20%%\">%s ",
							mppp_status );
#endif
		nBytesSent += boaWrite(wp, "	</td>\n");
		nBytesSent += boaWrite(wp, "  </tr>\n");

	}
	nBytesSent += boaWrite(wp, "</table>");
#ifdef CONFIG_GENERAL_WEB
	nBytesSent += boaWrite(wp, "</div></div>");
#endif
	return nBytesSent;
}
#else
int wanIPIPTable(int eid, request * wp, int argc, char **argv)
{
	int nBytesSent=0;
	return nBytesSent;
}
#endif //CONFIG_NET_IPIP

#ifdef CONFIG_00R0
#include <omci_api.h>

int get_OMCI_TR69_WAN_VLAN(int *vid, int *pri)
{
	int ret = 0;
 	PON_OMCI_CMD_T msg;

	memset(&msg, 0, sizeof(msg));
	//msg.cmd = PON_OMCI_CMD_TR69_WAN_VLAN_GET;

	if (omci_SendCmdAndGet(&msg) == GOS_OK) {
		printf("%s vid[%d] pri[%d]\n", __func__, msg.vid, msg.pri);
		*vid = msg.vid;
		*pri = msg.pri;
		ret = 1;
	}
	else
		ret = 0;

	return ret;
}

int getWanStatus(struct wstatus_info *sEntry, int max)
{
	unsigned int data, data2;
	char	buff[256], tmp1[20], tmp2[20], tmp3[20], tmp4[20];
	char	*temp;
	int in_turn=0, vccount=0, ifcount=0;
	int linkState, dslState=0, ethState=0;
	int i;
	FILE *fp;
#ifdef CONFIG_PPP
#if defined(EMBED)
	int spid;
#endif
#ifdef FILE_LOCK
	struct flock flpoe, flpoa;
	int fdpoe, fdpoa;
#endif
#endif
	Modem_LinkSpeed vLs;
	int entryNum;
	MIB_CE_ATM_VC_T tEntry;
	struct wstatus_info vcEntry[MAX_VC_NUM];

	memset(sEntry, 0, sizeof(struct wstatus_info)*max);
	memset(vcEntry, 0, sizeof(struct wstatus_info)*MAX_VC_NUM);
#if defined(EMBED) && defined(CONFIG_PPP)
	// get spppd pid
	spid = 0;
	if ((fp = fopen(PPP_PID, "r"))) {
		fscanf(fp, "%d\n", &spid);
		fclose(fp);
	}
	else
		printf("spppd pidfile not exists\n");

	if (spid) {
		struct data_to_pass_st msg;
		snprintf(msg.data, BUF_SIZE, "spppctl pppstatus %d", spid);
		TRACE(STA_SCRIPT, "%s\n", msg.data);
		write_to_pppd(&msg);
	}
#endif
	in_turn = 0;
#ifdef EMBED
#ifdef CONFIG_ATM_BR2684
#ifdef CONFIG_RTL_MULTI_PVC_WAN
	if( WAN_MODE & MODE_ATM )
	{
		entryNum = mib_chain_total(MIB_ATM_VC_TBL);
		for (i=0; i<entryNum; i++)
		{
			if(!mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&tEntry))
				continue;

			if(MEDIA_INDEX(tEntry.ifIndex) != MEDIA_ATM)
				continue;
			//czpinging, skipped the entry with Disabled Admin status
			if(tEntry.enable==0)
				continue;

			vcEntry[vccount].ifIndex = tEntry.ifIndex;
			ifGetName(tEntry.ifIndex, vcEntry[vccount].ifname, IFNAMSIZ);
			ifGetName(PHY_INTF(tEntry.ifIndex), vcEntry[vccount].devname, IFNAMSIZ);
			vcEntry[vccount].tvpi = tEntry.vpi;
			vcEntry[vccount].tvci = tEntry.vci;

			switch(tEntry.encap) {
				case ENCAP_VCMUX:
					strcpy(vcEntry[vccount].encaps, "VCMUX");
					break;
				case ENCAP_LLC:
					strcpy(vcEntry[vccount].encaps, "LLC");
					break;
				default:
					break;
			}

			switch(tEntry.cmode) {
				case CHANNEL_MODE_IPOE:
					strcpy(vcEntry[vccount].protocol, "IPoE");
					break;
				case CHANNEL_MODE_BRIDGE:
					strcpy(vcEntry[vccount].protocol, "Bridged");
					break;
				case CHANNEL_MODE_PPPOE:
					strcpy(vcEntry[vccount].protocol, "PPPoE");
					break;
				case CHANNEL_MODE_PPPOA:
					strcpy(vcEntry[vccount].protocol, "PPPoA");
					break;
				case CHANNEL_MODE_RT1483:
					strcpy(vcEntry[vccount].protocol, "RT1483");
					break;
				case CHANNEL_MODE_RT1577:
					strcpy(vcEntry[vccount].protocol, "RT1577");
					break;
				case CHANNEL_MODE_6RD:
					strcpy(vcEntry[vccount].protocol, "6rd");
					break;
				default:
					break;
			}
			strcpy(vcEntry[vccount].vpivci, "---");
			vccount++;
		}
	}
#else
	if (!(fp=fopen(PROC_NET_ATM_BR, "r")))
		printf("%s not exists.\n", PROC_NET_ATM_BR);
	else {
		while ( fgets(buff, sizeof(buff), fp) != NULL ) {
			if (in_turn==0)
				if(sscanf(buff, "%*s%s", tmp1)!=1) {
					printf("Unsuported pvc configuration format\n");
					break;
				}
				else {
					vccount ++;
					tmp1[strlen(tmp1)-1]='\0';
					strcpy(vcEntry[vccount-1].ifname, tmp1);
					strcpy(vcEntry[vccount-1].devname, tmp1);
				}
			else
				if(sscanf(buff, "%*s%s%*s%s", tmp1, tmp2)!=2) {
					printf("Unsuported pvc configuration format\n");
					break;
				}
				else {
					sscanf(tmp1, "0.%u.%u:", &vcEntry[vccount-1].tvpi, &vcEntry[vccount-1].tvci);
					sscanf(tmp2, "%u,", &data);
					strcpy(vcEntry[vccount-1].protocol, "");
					if (data==1 || data == 4)
						strcpy(vcEntry[vccount-1].encaps, "LLC");
					else if (data==0 || data==3)
						strcpy(vcEntry[vccount-1].encaps, "VCMUX");
					if (data==3 || data==4)
						strcpy(vcEntry[vccount-1].protocol, "rt1483");
					strcpy(vcEntry[vccount-1].vpivci, "---");
				}
			in_turn ^= 0x01;
		}
		fclose(fp);
	}
#endif
#endif
#ifdef CONFIG_ATM_CLIP
	if (!(fp=fopen(PROC_NET_ATM_CLIP, "r")))
		printf("%s not exists.\n", PROC_NET_ATM_CLIP);
	else {
		fgets(buff, sizeof(buff), fp);
		while ( fgets(buff, sizeof(buff), fp) != NULL ) {
			char *p = strstr(buff, "CLIP");
			if (p != NULL) {
				if (sscanf(buff, "%*d%u%u%*d%*d%*s%*d%*s%*s%s%s", &data, &data2, tmp1, tmp2) != 4) {
					printf("Unsuported 1577 configuration format\n");
					break;
				}
				else {
					vccount ++;
					sscanf(tmp1, "Itf:%s", tmp3);
					strcpy(vcEntry[vccount-1].ifname, strtok(tmp3, ","));
					strcpy(vcEntry[vccount-1].devname, vcEntry[vccount-1].ifname);
					sscanf(tmp2, "Encap:%s", tmp4);
					strcpy(vcEntry[vccount-1].encaps, strtok(tmp4, "/"));
					strcpy(vcEntry[vccount-1].protocol, "rt1577");
					vcEntry[vccount-1].tvpi = data;
					vcEntry[vccount-1].tvci = data2;
					strcpy(vcEntry[vccount-1].vpivci, "---");
				}
			}
		}
		fclose(fp);
	}
#endif


#ifdef CONFIG_PTMWAN
	if( WAN_MODE & MODE_PTM )
	{
		entryNum = mib_chain_total(MIB_ATM_VC_TBL);
		for (i=0; i<entryNum; i++)
		{
			if(!mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&tEntry))
				continue;

			if(MEDIA_INDEX(tEntry.ifIndex) != MEDIA_PTM)
				continue;

			//czpinging, skipped the entry with Disabled Admin status
			if(tEntry.enable==0)
				continue;

			vcEntry[vccount].ifIndex = tEntry.ifIndex;
			ifGetName(tEntry.ifIndex, vcEntry[vccount].ifname, IFNAMSIZ);
			ifGetName(PHY_INTF(tEntry.ifIndex), vcEntry[vccount].devname, IFNAMSIZ);
			strcpy(vcEntry[vccount].encaps, "---");
			switch(tEntry.cmode) {
				case CHANNEL_MODE_IPOE:
					strcpy(vcEntry[vccount].protocol, "IPoE");
					break;
				case CHANNEL_MODE_BRIDGE:
					strcpy(vcEntry[vccount].protocol, "Bridged");
					break;
				case CHANNEL_MODE_PPPOE:
					strcpy(vcEntry[vccount].protocol, "PPPoE");
					break;
				case CHANNEL_MODE_6RD:
					strcpy(vcEntry[vccount].protocol, "6rd");
					break;
				default:
					break;
			}
			strcpy(vcEntry[vccount].vpivci, "---");
			vccount++;
		}
	}
#endif // CONFIG_PTMWAN


#ifdef CONFIG_ETHWAN
	if( WAN_MODE & MODE_Ethernet )
	{
		entryNum = mib_chain_total(MIB_ATM_VC_TBL);
		for (i=0; i<entryNum; i++)
		{
			if(!mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&tEntry))
				continue;

			if(MEDIA_INDEX(tEntry.ifIndex) != MEDIA_ETH)
				continue;

			//czpinging, skipped the entry with Disabled Admin status
			if(tEntry.enable==0)
				continue;

			vcEntry[vccount].ifIndex = tEntry.ifIndex;
			ifGetName(tEntry.ifIndex, vcEntry[vccount].ifname, IFNAMSIZ);
			ifGetName(PHY_INTF(tEntry.ifIndex), vcEntry[vccount].devname, IFNAMSIZ);
			strcpy(vcEntry[vccount].encaps, "---");
			switch(tEntry.cmode) {
				case CHANNEL_MODE_IPOE:
					strcpy(vcEntry[vccount].protocol, "IPoE");
					break;
				case CHANNEL_MODE_BRIDGE:
					strcpy(vcEntry[vccount].protocol, "Bridged");
					break;
				case CHANNEL_MODE_PPPOE:
					strcpy(vcEntry[vccount].protocol, "PPPoE");
					break;
				case CHANNEL_MODE_6RD:
					strcpy(vcEntry[vccount].protocol, "6rd");
					break;
				default:
					break;
			}
			strcpy(vcEntry[vccount].vpivci, "---");
			vccount++;
		}
	}
#endif // CONFIG_ETHWAN

#ifdef WLAN_WISP
	if( WAN_MODE & MODE_Wlan )
	{
		entryNum = mib_chain_total(MIB_ATM_VC_TBL);
		for (i=0; i<entryNum; i++)
		{
			if(!mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&tEntry))
				continue;

			if(MEDIA_INDEX(tEntry.ifIndex) != MEDIA_WLAN)
				continue;

			//czpinging, skipped the entry with Disabled Admin status
			if(tEntry.enable==0)
				continue;

			vcEntry[vccount].ifIndex = tEntry.ifIndex;
			ifGetName(tEntry.ifIndex, vcEntry[vccount].ifname, IFNAMSIZ);
			ifGetName(PHY_INTF(tEntry.ifIndex), vcEntry[vccount].devname, IFNAMSIZ);
			strcpy(vcEntry[vccount].encaps, "---");
			switch(tEntry.cmode) {
				case CHANNEL_MODE_IPOE:
					strcpy(vcEntry[vccount].protocol, "IPoE");
					break;
				case CHANNEL_MODE_BRIDGE:
					strcpy(vcEntry[vccount].protocol, "Bridged");
					break;
				case CHANNEL_MODE_PPPOE:
					strcpy(vcEntry[vccount].protocol, "PPPoE");
					break;
				default:
					break;
			}
			strcpy(vcEntry[vccount].vpivci, "---");
			vccount++;
		}
	}
#endif

#ifdef CONFIG_PPP
#ifdef FILE_LOCK
	// file locking
	fdpoe = open(PPPOE_CONF, O_RDWR);
	if (fdpoe != -1) {
		flpoe.l_type = F_RDLCK;
		flpoe.l_whence = SEEK_SET;
		flpoe.l_start = 0;
		flpoe.l_len = 0;
		flpoe.l_pid = getpid();
		if (fcntl(fdpoe, F_SETLKW, &flpoe) == -1)
			printf("pppoe read lock failed\n");
	}

	fdpoa = open(PPPOA_CONF, O_RDWR);
	if (fdpoa != -1) {
		flpoa.l_type = F_RDLCK;
		flpoa.l_whence = SEEK_SET;
		flpoa.l_start = 0;
		flpoa.l_len = 0;
		flpoa.l_pid = getpid();
		if (fcntl(fdpoa, F_SETLKW, &flpoa) == -1)
			printf("pppoa read lock failed\n");
	}
#endif

#ifdef CONFIG_DEV_xDSL
	if (!(fp=fopen(PPPOA_CONF, "r")))
		printf("%s not exists.\n", PPPOA_CONF);
	else {
		fgets(buff, sizeof(buff), fp);
		while ( fgets(buff, sizeof(buff), fp) != NULL )
			if (sscanf(buff, "%s%u%u%*s%s%*s%*d%*d%*d%s%s", tmp1, &data, &data2, tmp2, tmp3, tmp4) != 6) {
				printf("Unsuported pppoa configuration format\n");
				break;
			}
			else {
				for (i=0; i<vccount; i++)
					if (strcmp(vcEntry[i].ifname, tmp1) == 0)
					{
						ifcount++;
						// ifIndex --- ppp index(no vc index)
						sEntry[ifcount-1].ifIndex = TO_IFINDEX(MEDIA_ATM, tmp1[3]-'0', DUMMY_VC_INDEX);
						strcpy(sEntry[ifcount-1].ifname, tmp1);
						strcpy(sEntry[ifcount-1].encaps, tmp2);
						strcpy(sEntry[ifcount-1].protocol, "PPPoA");
						sEntry[ifcount-1].tvpi = data;
						sEntry[ifcount-1].tvci = data2;
						sprintf(sEntry[ifcount-1].vpivci, "%u/%u", sEntry[ifcount-1].tvpi, sEntry[ifcount-1].tvci);
						strcpy(sEntry[ifcount-1].uptime, tmp3);
						strcpy(sEntry[ifcount-1].totaluptime, tmp4);
						break;
					}
			}
		fclose(fp);
	}
#endif

	if (!(fp=fopen(PPPOE_CONF, "r")))
		printf("%s not exists.\n", PPPOE_CONF);
	else {
		fgets(buff, sizeof(buff), fp);
		while ( fgets(buff, sizeof(buff), fp) != NULL )
			if(sscanf(buff, "%s%s%*s%*s%*s%s%s", tmp1, tmp2, tmp3, tmp4) != 4) {
				printf("Unsuported pppoe configuration format\n");
				break;
			}
			else
				for (i=0; i<vccount; i++)
#ifdef CONFIG_RTL_MULTI_PVC_WAN
					if (strcmp(vcEntry[i].ifname, tmp1) == 0)
#else
					if (strcmp(vcEntry[i].devname, tmp2) == 0)
#endif
					{
						ifcount++;
						// ifIndex --- ppp index + vc index
						if (!strncmp(vcEntry[i].devname,"vc",2))
						{
#ifdef CONFIG_RTL_MULTI_PVC_WAN
							sEntry[ifcount-1].ifIndex = TO_IFINDEX(MEDIA_ATM, tmp1[3]-'0', ((((vcEntry[i].devname[2]-'0') << 4) & 0xf0) | ((vcEntry[i].devname[4]-'0') & 0x0f)) );
#else
							sEntry[ifcount-1].ifIndex = TO_IFINDEX(MEDIA_ATM, tmp1[3]-'0', vcEntry[i].devname[2]-'0');
#endif
							sEntry[ifcount-1].tvpi = vcEntry[i].tvpi;
							sEntry[ifcount-1].tvci = vcEntry[i].tvci;
							sprintf(sEntry[ifcount-1].vpivci, "%u/%u", sEntry[ifcount-1].tvpi, sEntry[ifcount-1].tvci);
							//printf("***** sEntry[ifcount-1].ifIndex=0x%x\n", sEntry[ifcount-1].ifIndex);
						}
#if defined(CONFIG_ETHWAN) || defined(CONFIG_PTMWAN) || defined (WLAN_WISP)
						else {
							sEntry[ifcount-1].ifIndex = vcEntry[i].ifIndex;
							strcpy(sEntry[ifcount-1].vpivci, "---");
						}
#endif
						strcpy(sEntry[ifcount-1].ifname, tmp1);
#ifdef CONFIG_RTL_MULTI_PVC_WAN
						strcpy(sEntry[ifcount-1].devname, tmp2);
#else
						strcpy(sEntry[ifcount-1].devname, vcEntry[i].devname);
#endif
						strcpy(sEntry[ifcount-1].encaps, vcEntry[i].encaps);
						strcpy(sEntry[ifcount-1].protocol, "PPPoE");
						strcpy(sEntry[ifcount-1].uptime, tmp3);
						strcpy(sEntry[ifcount-1].totaluptime, tmp4);
						break;
					}
		fclose(fp);
	}
#ifdef FILE_LOCK
	// file unlocking
	if ((fdpoe != -1) && (fdpoa != -1)) {
		flpoe.l_type = flpoa.l_type = F_UNLCK;
		if (fcntl(fdpoe, F_SETLK, &flpoe) == -1)
			printf("pppoe read unlock failed\n");
		if (fcntl(fdpoa, F_SETLK, &flpoa) == -1)
			printf("pppoa read unlock failed\n");
		close(fdpoe);
		close(fdpoa);
	}
#endif
#endif

	for (i=0; i<vccount; i++) {
		int j, vcfound=0;
		for (j=0; j<ifcount; j++) {
#ifdef CONFIG_RTL_MULTI_PVC_WAN
			if (strcmp(vcEntry[i].ifname, sEntry[j].ifname) == 0)	// PPPoE-used device
#else
			if (strcmp(vcEntry[i].devname, sEntry[j].devname) == 0)	// PPPoE-used device
#endif
			{
				vcfound = 1;
				break;
			}
		}
		if (!vcfound) {	// VC not used for PPPoA/PPPoE, add to list
			ifcount++;
			// ifIndex --- vc index (no ppp index)
			if (!strncmp(vcEntry[i].devname,"vc",2)) {
#ifdef CONFIG_RTL_MULTI_PVC_WAN
				sEntry[ifcount-1].ifIndex = TO_IFINDEX(MEDIA_ATM, DUMMY_PPP_INDEX, ((((vcEntry[i].devname[2]-'0') << 4) & 0xf0) | ((vcEntry[i].devname[4]-'0') & 0x0f)) );
#else
				sEntry[ifcount-1].ifIndex = TO_IFINDEX(MEDIA_ATM, DUMMY_PPP_INDEX, vcEntry[i].ifname[2]-'0');
#endif
				sEntry[ifcount-1].tvpi = vcEntry[i].tvpi;
				sEntry[ifcount-1].tvci = vcEntry[i].tvci;
				sprintf(sEntry[ifcount-1].vpivci, "%u/%u", sEntry[ifcount-1].tvpi, sEntry[ifcount-1].tvci);
			}
#if defined(CONFIG_ETHWAN) || defined(CONFIG_PTMWAN) || defined (WLAN_WISP)
			else {
				sEntry[ifcount-1].ifIndex = vcEntry[i].ifIndex;
				strcpy(sEntry[ifcount-1].vpivci, "---");
			}
#endif
			strcpy(sEntry[ifcount-1].ifname, vcEntry[i].ifname);
			strcpy(sEntry[ifcount-1].devname, vcEntry[i].devname);
			strcpy(sEntry[ifcount-1].encaps, vcEntry[i].encaps);
			strcpy(sEntry[ifcount-1].protocol, vcEntry[i].protocol);
		}
	}

#endif

#ifdef CONFIG_DEV_xDSL
	// check for xDSL link
	if (!adsl_drv_get(RLCM_GET_LINK_SPEED, (void *)&vLs, RLCM_GET_LINK_SPEED_SIZE) || vLs.upstreamRate == 0)
		dslState = 0;
	else
		dslState = 1;
#endif
#if defined(CONFIG_ETHWAN) || defined(CONFIG_PTMWAN)
	// todo
	ethState = 1;
#endif

	if (ifcount > max)
		printf("WARNNING! status list overflow(%d).\n", ifcount);


	for (i=0; i<ifcount; i++) {
		struct in_addr inAddr;
		int flags;
		int totalNum, k;
		MIB_CE_ATM_VC_T entry;
		MEDIA_TYPE_T mType;

#ifdef EMBED
		// Kaohj --- interface name to be displayed
		totalNum = mib_chain_total(MIB_ATM_VC_TBL);

		for(k=0; k<totalNum; k++)
		{
			mib_chain_get(MIB_ATM_VC_TBL, k, (void *)&entry);

			if (sEntry[i].ifIndex == entry.ifIndex) {
				getDisplayWanName(&entry, sEntry[i].ifDisplayName);
				sEntry[i].cmode = entry.cmode;
#ifdef CONFIG_IPV6
				sEntry[i].ipver = entry.IpProtocol;
#endif
				sEntry[i].recordNum = k;

	
#ifdef CONFIG_00R0
				if ((entry.omci_configured == 1) && (entry.vid == 0) ) {
					int omci_vid = 0, omci_vprio = 0;
					if (get_OMCI_TR69_WAN_VLAN(&omci_vid, &omci_vprio) && omci_vid > 0) {
						sEntry[i].vid = omci_vid;
					}
				}
				else
#endif
					sEntry[i].vid = entry.vid;
				memcpy(sEntry[i].MacAddr,entry.MacAddr,MAC_ADDR_LEN);
				getServiceType(sEntry[i].serviceType,entry.applicationtype);
				break;
			}

		}
		if (getInAddr( sEntry[i].ifname, IP_ADDR, (void *)&inAddr) == 1)
		{
			temp = inet_ntoa(inAddr);
			if (getInFlags( sEntry[i].ifname, &flags) == 1)
				if ((strcmp(temp, "10.0.0.1") == 0) && flags & IFF_POINTOPOINT)	// IP Passthrough or IP unnumbered
					strcpy(sEntry[i].ipAddr, STR_UNNUMBERED);
				else if (strcmp(temp, "64.64.64.64") == 0)
					strcpy(sEntry[i].ipAddr, "");
				else
					strcpy(sEntry[i].ipAddr, temp);
		}
		else
#endif
			strcpy(sEntry[i].ipAddr, "");

#ifdef EMBED
		if (getInAddr( sEntry[i].ifname, DST_IP_ADDR, (void *)&inAddr) == 1)
		{
			temp = inet_ntoa(inAddr);
			if (strcmp(temp, "10.0.0.2") == 0)
				strcpy(sEntry[i].remoteIp, STR_UNNUMBERED);
			else if (strcmp(temp, "64.64.64.64") == 0)
				strcpy(sEntry[i].remoteIp, "");
			else
				strcpy(sEntry[i].remoteIp, temp);
			if (getInFlags( sEntry[i].ifname, &flags) == 1)
				if (flags & IFF_BROADCAST) {
					unsigned char value[32];
					snprintf(value, 32, "%s.%s", (char *)MER_GWINFO, sEntry[i].ifname);
					if (fp = fopen(value, "r")) {
						fscanf(fp, "%s\n", sEntry[i].remoteIp);
						//strcpy(sEntry[i].protocol, "mer1483");
						fclose(fp);
					}
					else
						strcpy(sEntry[i].remoteIp, "");
				}
		}
		else
#endif
			strcpy(sEntry[i].remoteIp, "");

		if (!strcmp(sEntry[i].protocol, ""))
		{
			//get channel mode
			switch(sEntry[i].cmode) {
			case CHANNEL_MODE_IPOE:
				strcpy(sEntry[i].protocol, "mer1483");
				break;
			case CHANNEL_MODE_BRIDGE:
				strcpy(sEntry[i].protocol, "br1483");
				break;
			case CHANNEL_MODE_6RD:
				strcpy(sEntry[i].protocol, "6rd");
				break;
			default:
				break;
			}
		}

		mType = MEDIA_INDEX(sEntry[i].ifIndex);
		if (mType == MEDIA_ATM)
			linkState = dslState;
		#ifdef CONFIG_PTMWAN
		else if (mType == MEDIA_PTM)
			linkState = dslState && ethState;//???
		#endif /*CONFIG_PTMWAN*/
		else if (mType == MEDIA_ETH)
			linkState = ethState;
#ifdef WLAN_WISP
		else if (mType == MEDIA_WLAN){
			char wisp_name[16];
			getWispWanName(wisp_name, ETH_INDEX(sEntry[i].ifIndex));
			linkState = get_net_link_status(wisp_name);
		}
#endif
		else
			linkState = 0;
		sEntry[i].link_state = linkState;
		// set status flag
		if (getInFlags( sEntry[i].ifname, &flags) == 1)
		{
			if (flags & IFF_UP) {
				if (!linkState) {
					sEntry[i].strStatus = (char *)IF_DOWN;
					sEntry[i].itf_state = 0;
				}
				else {
					if (sEntry[i].cmode == CHANNEL_MODE_BRIDGE) {
						sEntry[i].strStatus = (char *)IF_UP;
						sEntry[i].itf_state = 1;
					}
					else
						if (getInAddr(sEntry[i].ifname, IP_ADDR, (void *)&inAddr) == 1) {
							temp = inet_ntoa(inAddr);
							if (strcmp(temp, "64.64.64.64")) {
								sEntry[i].strStatus = (char *)IF_UP;
								sEntry[i].itf_state = 1;															}
							else {
								sEntry[i].strStatus = (char *)IF_DOWN;
								sEntry[i].itf_state = 0;
							}
						}
						else {
							sEntry[i].strStatus = (char *)IF_DOWN;
							sEntry[i].itf_state = 0;
						}
				}
			}
			else {
				sEntry[i].strStatus = (char *)IF_DOWN;
				sEntry[i].itf_state = 0;
			}
		}
		else {
			sEntry[i].strStatus = (char *)IF_NA;
			sEntry[i].itf_state = -1;
		}

		if (sEntry[i].cmode == CHANNEL_MODE_PPPOE || sEntry[i].cmode == CHANNEL_MODE_PPPOA) {
			if (sEntry[i].itf_state <= 0) {
				sEntry[i].ipAddr[0] = '\0';
				sEntry[i].remoteIp[0] = '\0';
			}
			if (entry.pppCtype == CONNECT_ON_DEMAND && entry.pppIdleTime != 0)
				sEntry[i].pppDoD = 1;
			else
				sEntry[i].pppDoD = 0;
		}

	}
	return ifcount;
}
#endif

// Jenny, current status
int wanConfList(int eid, request * wp, int argc, char **argv)
{
	int nBytesSent=0;
	int in_turn=0, ifcount=0;
	int i;
#ifdef CONFIG_00R0
	struct wstatus_info sEntry[MAX_VC_NUM+MAX_PPP_NUM]={0};
	char wanMac[30]={0};
#else
	struct wstatus_info sEntry[MAX_VC_NUM+MAX_PPP_NUM];
#endif
	
	ifcount = getWanStatus(sEntry, MAX_VC_NUM+MAX_PPP_NUM);
#ifndef CONFIG_GENERAL_WEB
	nBytesSent += boaWrite(wp, "<tr bgcolor=\"#808080\">"
	"<td width=\"8%%\" align=center><font size=2><b>%s</b></font></td>\n"
	"<td width=\"12%%\" align=center><font size=2><b>%s</b></font></td>\n"
	"<td width=\"12%%\" align=center><font size=2><b>%s</b></font></td>\n"
	"<td width=\"12%%\" align=center><font size=2><b>%s</b></font></td>\n"
#if defined(CONFIG_00R0) && defined(CONFIG_LUNA)
	"<td width=\"12%%\" align=center><font size=2><b>%s</b></font></td>\n"
#endif
	"<td width=\"22%%\" align=center><font size=2><b>%s</b></font></td>\n"
	"<td width=\"22%%\" align=center><font size=2><b>%s</b></font></td>\n"
	"<td width=\"12%%\" align=center><font size=2><b>%s</b></font></td></tr>\n",
#else
	nBytesSent += boaWrite(wp, "<tr>"
	"<th width=\"8%%\" align=center>%s</th>\n"
	"<th width=\"12%%\" align=center>%s</th>\n"
	"<th width=\"12%%\" align=center>%s</th>\n"
	"<th width=\"12%%\" align=center>%s</th>\n"
#if defined(CONFIG_00R0) && defined(CONFIG_LUNA)
	"<th width=\"12%%\" align=center>%s</th>\n"
#endif
	"<th width=\"22%%\" align=center>%s</th>\n"
	"<th width=\"22%%\" align=center>%s</th>\n"
	"<th width=\"12%%\" align=center>%s</th></tr>\n",
#endif
	multilang(LANG_INTERFACE), 
#if defined(CONFIG_LUNA)	
	multilang(LANG_VLAN_ID), 
#ifdef CONFIG_00R0
	multilang(LANG_MAC),
#endif
	multilang(LANG_CONNECTION_TYPE),
#else	
	multilang(LANG_VPI_VCI), multilang(LANG_ENCAPSULATION),
#endif	
	multilang(LANG_PROTOCOL), multilang(LANG_IP_ADDRESS), multilang(LANG_GATEWAY),
	multilang(LANG_STATUS));
	in_turn = 0;
	for (i=0; i<ifcount; i++) {
#ifndef CONFIG_GENERAL_WEB
		if (in_turn == 0)
			nBytesSent += boaWrite(wp, "<tr bgcolor=\"#EEEEEE\">\n");
		else
			nBytesSent += boaWrite(wp, "<tr bgcolor=\"#DDDDDD\">\n");
#else
		if (in_turn == 0)
			nBytesSent += boaWrite(wp, "<tr>\n");
#endif

#ifdef CONFIG_00R0
		//setup Mac
		sprintf(wanMac,"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",sEntry[i].MacAddr[0],sEntry[i].MacAddr[1],sEntry[i].MacAddr[2],sEntry[i].MacAddr[3],sEntry[i].MacAddr[4],sEntry[i].MacAddr[5]);
#endif
		in_turn ^= 0x01;
		nBytesSent += boaWrite(wp,
#ifndef CONFIG_GENERAL_WEB
		"<td align=center width=\"5%%\"><font size=2>%s</td>\n"
#if defined(CONFIG_LUNA)
		"<td align=center width=\"1%%\"><font size=2>%d</td>\n"
#ifdef CONFIG_00R0
		"<td align=center width=\"9%%\"><font size=2>%s</td>\n"
#endif
		"<td align=center width=\"9%%\"><font size=2>%s</td>\n"
#else
		"<td align=center width=\"5%%\"><font size=2>%s</td>\n"
		"<td align=center width=\"5%%\"><font size=2>%s</td>\n"
#endif		
		"<td align=center width=\"5%%\"><font size=2>%s</td>\n"
		"<td align=center width=\"10%%\"><font size=2>%s</td>\n"
		"<td align=center width=\"10%%\"><font size=2>%s</td>\n"
		"<td align=center width=\"23%%\"><font size=2>%s\n",
#else
		"<td align=center width=\"5%%\">%s</td>\n"
#if defined(CONFIG_LUNA)
		"<td align=center width=\"1%%\">%d</td>\n"
#ifdef CONFIG_00R0
		"<td align=center width=\"9%%\">%s</td>\n"
#endif
		"<td align=center width=\"9%%\">%s</td>\n"
#else
		"<td align=center width=\"5%%\">%s</td>\n"
		"<td align=center width=\"5%%\">%s</td>\n"
#endif		
		"<td align=center width=\"5%%\">%s</td>\n"
		"<td align=center width=\"10%%\">%s</td>\n"
		"<td align=center width=\"10%%\">%s</td>\n"
		"<td align=center width=\"23%%\">%s\n",
#endif
		sEntry[i].ifDisplayName,
#if defined(CONFIG_LUNA)
		sEntry[i].vid, 
#ifdef CONFIG_00R0
		wanMac, 
#endif
		sEntry[i].serviceType,
#else
		sEntry[i].vpivci, sEntry[i].encaps,
#endif		
		sEntry[i].protocol, sEntry[i].ipAddr, sEntry[i].remoteIp, sEntry[i].strStatus);
		if (sEntry[i].cmode == CHANNEL_MODE_PPPOE || sEntry[i].cmode == CHANNEL_MODE_PPPOA) { // PPP mode
			nBytesSent += boaWrite(wp, " %s / %s ", sEntry[i].uptime, sEntry[i].totaluptime);
			if (sEntry[i].link_state && !sEntry[i].pppDoD)
				if (sEntry[i].cmode == CHANNEL_MODE_PPPOE)
					nBytesSent += boaWrite(wp,
#ifndef CONFIG_GENERAL_WEB
					//"<input type=\"submit\" id=\"%s\" value=\"%s\" name=\"submit%s\" onClick=\"disButton('%s')\">",
					"<input type=\"submit\" id=\"%s\" value=\"%s\" name=\"submit%s\" onClick=\"disButton('%s'); return on_submit(this)\">",
#else
					//"<input class=\"inner_btn\" type=\"submit\" id=\"%s\" value=\"%s\" name=\"submit%s\" onClick=\"disButton('%s')\">",			
					"<input class=\"inner_btn\" type=\"submit\" id=\"%s\" value=\"%s\" name=\"submit%s\" onClick=\"disButton('%s'); return on_submit(this)\">", 		
#endif
					sEntry[i].ifname, (sEntry[i].itf_state==1) ? "Disconnect" : "Connect",
					sEntry[i].ifname,sEntry[i].ifname);
				else
					nBytesSent += boaWrite(wp,
#ifndef CONFIG_GENERAL_WEB
					//"<input type=\"submit\" value=\"%s\" name=\"submit%s\">"
					"<input type=\"submit\" value=\"%s\" name=\"submit%s\" onClick=\"return on_submit(this)\">"
#else
					//"<input class=\"inner_btn\" type=\"submit\" value=\"%s\" name=\"submit%s\">"
					"<input class=\"inner_btn\" type=\"submit\" value=\"%s\" name=\"submit%s\" onClick=\"return on_submit(this)\">"
#endif
					, (sEntry[i].itf_state==1) ? "Disconnect" : "Connect",
					sEntry[i].ifname);
		}
		nBytesSent += boaWrite(wp, "</td></tr>\n");
	}	
	return nBytesSent;
}

int DHCPSrvStatus(int eid, request * wp, int argc, char **argv)
{
	int nBytesSent=0;
#ifndef CONFIG_SFU
	char vChar = 0;
#ifdef CONFIG_USER_DHCP_SERVER
	if ( !mib_get( MIB_DHCP_MODE, (void *)&vChar) )
		return -1;
#endif
#ifndef CONFIG_GENERAL_WEB
	nBytesSent += boaWrite(wp,"<tr bgcolor=\"#EEEEEE\">\n"
				"<td width=\"40%%\">\n"
				"<font size=2><b>DHCP %s</b></td>\n<td width=\"60%%\">\n"
    				"<font size=2>%s</td></tr>\n",
      				multilang(LANG_SERVER),DHCP_LAN_SERVER == vChar?multilang(LANG_ENABLED): multilang(LANG_DISABLED));
#else
	nBytesSent += boaWrite(wp,"<tr>\n"
				"<th width=\"40%%\">DHCP %s</th>\n"
				"<td width=\"60%%\">%s</td>"
				"</tr>\n",multilang(LANG_SERVER),DHCP_LAN_SERVER == vChar?multilang(LANG_ENABLED): multilang(LANG_DISABLED));
#endif
#endif

	return nBytesSent;
}

#ifdef CONFIG_DEV_xDSL
#define FM_DSL_VER \
"<tr bgcolor=\"#DDDDDD\">" \
"<td width=40%%><font size=2><b>%s</b></td>" \
"<td width=60%%><font size=2>%s</td>" \
"</tr>"

int DSLVer(int eid, request * wp, int argc, char **argv)
{
	int nBytesSent = 0;
	char s_ver[64];

	if(!(WAN_MODE & MODE_ATM) && !(WAN_MODE & MODE_PTM))
		return 0;

	getAdslInfo(ADSL_GET_VERSION, s_ver, 64);
	nBytesSent += boaWrite(wp, (char *)FM_DSL_VER, multilang(LANG_DSP_VERSION) , s_ver);

#ifdef CONFIG_USER_XDSL_SLAVE
	getAdslSlvInfo(ADSL_GET_VERSION, s_ver, 64);
	nBytesSent += boaWrite(wp, (char *)FM_DSL_VER, multilang(LANG_DSP_SLAVE_VERSION), s_ver);
#endif /*CONFIG_USER_XDSL_SLAVE*/

  return nBytesSent;
}

int DSLStatus(int eid, request * wp, int argc, char **argv)
{
#ifndef CONFIG_GENERAL_WEB
	const char FM_DSL_STATUS[] =
		"<tr>\n"
		"<td width=100%% colspan=\"2\" bgcolor=\"#008000\"><font color=\"#FFFFFF\" size=2><b>%s</b></font></td>\n"
		"</tr>\n"
		"<tr bgcolor=\"#EEEEEE\">\n"
		"<td width=40%%><font size=2><b>Operational Status</b></td>\n"
		"<td width=60%%><font size=2>%s</td>\n"
		"</tr>\n"
		"<tr bgcolor=\"#DDDDDD\">\n"
		"<td width=40%%><font size=2><b>Upstream Speed</b></td>\n"
		"<td width=60%%><font size=2>%s&nbsp;kbps&nbsp;</td>\n"
		"</tr>\n"
		"<tr bgcolor=\"#EEEEEE\">\n"
		"<td width=40%%><font size=2><b>Downstream Speed</b></td>\n"
		"<td width=60%%><font size=2>%s&nbsp;kbps&nbsp;</td>\n"
		"</tr>\n";
#else
	const char FM_DSL_STATUS[] =
		"<div class=\"column\">\n"
		"	<div class=\"column_title\">\n"
		"		<div class=\"column_title_left\"></div>\n"
		"		<p>%s</p>\n"
		"		<div class=\"column_title_right\"></div>\n"
		"	</div>\n"
		"	<div class=\"data_common\">"
		"	<table>"
		"		<tr>\n"
		"			<th width=40%%>Operational Status</th>\n"
		"			<td width=60%%>%s</td>\n"
		"		</tr>\n"
		"		<tr>\n"
		"			<th width=40%%>Upstream Speed</td>\n"
		"			<td width=60%%>%s&nbsp;kbps&nbsp;</td>\n"
		"		</tr>\n"
		"		<tr>\n"
		"			<th width=40%%>Downstream Speed</td>\n"
		"			<td width=60%%>%s&nbsp;kbps&nbsp;</td>\n"
		"		</tr>\n"
		"	</table>\n"
		"	</div>\n"
		"</div>\n";
#endif

	int nBytesSent = 0;
	char o_status[64], u_speed[16], d_speed[16];

	if(!(WAN_MODE & MODE_ATM) && !(WAN_MODE & MODE_PTM))
		return 0;

	getSYS2Str(SYS_DSL_OPSTATE, o_status);
	getAdslInfo(ADSL_GET_RATE_US, u_speed, 16);
	getAdslInfo(ADSL_GET_RATE_DS, d_speed, 16);

	nBytesSent += boaWrite(wp, (char *)FM_DSL_STATUS, "DSL", o_status, u_speed, d_speed);

#ifdef LOOP_LENGTH_METER
		char distance[16];
		const char FM_DSL_STATUS_LLM[] = "<tr bgcolor=\"#DDDDDD\">\n"
		"<td width=40%%><font size=2><b>Distance Measurement</b></td>\n"
		"<td width=60%%><font size=2>%s&nbsp;(m)&nbsp;</td>\n"
		"</tr>\n";

	getAdslInfo(ADSL_GET_LOOP_LENGTH_METER, distance, 16);
	nBytesSent += boaWrite(wp, (char *)FM_DSL_STATUS_LLM, distance);
#endif

#ifdef CONFIG_USER_XDSL_SLAVE
	getSYS2Str(SYS_DSL_SLV_OPSTATE, o_status);
	getAdslSlvInfo(ADSL_GET_RATE_US, u_speed, 16);
	getAdslSlvInfo(ADSL_GET_RATE_DS, d_speed, 16);

	nBytesSent += boaWrite(wp, (char *)FM_DSL_STATUS, "DSL Slave", o_status, u_speed, d_speed);
#endif /*CONFIG_USER_XDSL_SLAVE*/

  return nBytesSent;
}
#endif

//#ifdef CONFIG_MCAST_VLAN
struct iptv_mcast_info {
	unsigned int ifIndex;	
	char servName[MAX_NAME_LEN];
	unsigned short vlanId;
	unsigned char enable;
};

#define _PTS			", new it(\"%s\", \"%s\")"
#define _PTI			", new it(\"%s\", %d)"
#define __PME(entry,name)               #name, entry.name


int listWanName(int eid, request * wp, int argc, char **argv)
{
	char ifname[IFNAMSIZ];
	int i, entryNum;
	MIB_CE_ATM_VC_T entry;
	struct iptv_mcast_info mEntry[MAX_VC_NUM + MAX_PPP_NUM] = { 0 };
	
	entryNum = mib_chain_total(MIB_ATM_VC_TBL);
	for (i = 0; i < entryNum; i++) {
		if (!mib_chain_get(MIB_ATM_VC_TBL, i, &entry)) {
			printf("get MIB chain error\n");
			return -1;
		}
		ifGetName(entry.ifIndex, ifname, sizeof(ifname));
		strcpy(mEntry[i].servName,ifname);
		mEntry[i].vlanId = entry.mVid;
		boaWrite(wp,
			 "links.push(new it_nr(\"%d\"" _PTS _PTI "));\n", i,
			 __PME(mEntry[i], servName), __PME(mEntry[i], vlanId));		
	}


}
//#endif

#ifdef CONFIG_00R0
int BootLoaderVersion(int eid, request * wp, int argc, char **argv)
{
	int nBytesSent=0;
	char boot_sw[128], sw_crc1[64], sw_crc2[64], boot_crc[64]={0};
	getSYS2Str(SYS_BOOTLOADER_FWVERSION, boot_sw);
	getSYS2Str(SYS_BOOTLOADER_CRC, boot_crc);
	
	if(boot_crc[0]==0){
		strcpy(boot_crc ,"89c17bda");//Backward compatiable for old bootloader, 89c17bda is calcuated by loader_R3576_9602_nand_demo_dual_boot.img
	}

	getSYS2Str(SYS_FWVERSION_SUM_1, sw_crc1);
	getSYS2Str(SYS_FWVERSION_SUM_2, sw_crc2);
	
	nBytesSent += boaWrite(wp,"<tr bgcolor=\"#DDDDDD\">"
			"<td width=\"40%%\"><font size=2><b>%s</b></td>\n"
			"<td width=\"60%%\"><font size=2>%s</td>\n</tr>\n"	
			"<tr bgcolor=\"#EEEEEE\">\n"
			"<td width=\"40%%\"><font size=2><b>%s</b></td>\n"
			"<td width=\"60%%\"><font size=2>%s</td>\n</tr>\n"	
			"<tr bgcolor=\"#DDDDDD\">\n"			
			"<td width=\"40%%\"><font size=2><b>%s</b></td>\n"
			"<td width=\"60%%\"><font size=2>%s</td>\n</tr>\n"
			"<tr bgcolor=\"#EEEEEE\">\n"
			"<td width=\"40%%\"><font size=2><b>%s</b></td>\n"
			"<td width=\"60%%\"><font size=2>%s</td>\n</tr> \n",
			multilang(LANG_BOOTLOADER_VERSION), boot_sw,
			multilang(LANG_BOOTLOADER_VERSION_SUM), boot_crc,
			multilang(LANG_FIRMWARE_VERSION_SUM_1), sw_crc1,
			multilang(LANG_FIRMWARE_VERSION_SUM_2), sw_crc2);

	return nBytesSent;
}

int GPONSerialNumber(int eid, request * wp, int argc, char **argv)
{
	int nBytesSent = 0;
	// Use hex number to display first 4 bytes of serial number.
	char sn[64] = {0}, tmpBuf[128] = {0};
	mib_get(MIB_GPON_SN, (void *)sn);
	sprintf(tmpBuf, "%02X%02X%02X%02X%s", sn[0], sn[1], sn[2], sn[3], &sn[4]);
	
	nBytesSent += boaWrite(wp,"<tr bgcolor=\"#EEEEEE\">"
			"<td width=\"40%%\"><font size=2><b>%s</b></td>\n"
			"<td width=\"60%%\"><font size=2>%s</td>\n</tr>\n",
			multilang(LANG_SERIAL_NUMBER), tmpBuf);

	return nBytesSent;
}

#endif

