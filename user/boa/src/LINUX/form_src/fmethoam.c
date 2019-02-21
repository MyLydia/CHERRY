/*
 *      Web server handler routines for other advanced stuffs
 *
 */


/*-- System inlcude files --*/
#include <string.h>
#include <sys/socket.h>
//#include <linux/if.h>
#include <signal.h>

/*-- Local inlcude files --*/
#include "../webs.h"
#include "webform.h"
#include "mib.h"
#include "utility.h"

const char RESOLV_LINKTRACE[] = "/var/resolv_linktrace.conf";

int getLinktraceMac(int eid, request * wp, int argc, char **argv) {
#if defined(CONFIG_USER_Y1731) 
	FILE *fp;
	char buffer[128], tmpbuf[64];
	int count = 0;	
	if ( (fp = fopen(RESOLV_LINKTRACE, "r")) == NULL ) {
		//printf("Unable to open resolv_linktrace.conf file\n");
		return -1;
	}

	while (fgets(buffer, sizeof(buffer), fp) != NULL) {		
		if (sscanf(buffer, "%s", tmpbuf) != 1) {
			continue;
		}

		if (count == 0)
			boaWrite(wp, "%s", tmpbuf);
		else
			boaWrite(wp, ", %s", tmpbuf);
		count ++;
	}
	fclose(fp);
#endif	
	return 0;
}
///////////////////////////////////////////////////////////////////
void formY1731(request * wp, char *path, char *query)
{
	char *str, *submitUrl, *strSetOAMD, *strLoopback, *strLinktrace;	
	char tmpBuf[100];
	unsigned char u8Val, level;
	unsigned short u16Val, u16vid;
	unsigned int ext_if, efm_8023ah_ext_if;
	char ifname[IFNAMSIZ] = {0};
	char *macaddr;
#ifndef NO_ACTION
	int pid;
#endif
#ifdef CONFIG_USER_8023AH
	str = boaGetVar(wp, "efm_8023ah_ext_if", "");
	mib_set(EFM_8023AH_WAN_INTERFACE, (void *)str);
#endif

#ifdef CONFIG_USER_Y1731	
	str = boaGetVar(wp, "ext_if", "");
	mib_set(Y1731_WAN_INTERFACE, (void *)str);	
	strncpy(ifname, str, sizeof(ifname));
		
	str = boaGetVar(wp, "meglevel", "7");	
	level = atoi(str);
	mib_set(Y1731_MEGLEVEL, (void *)&level);
	
	str = boaGetVar(wp, "vid", "101");	
	u16vid = atoi(str);
	mib_set(Y1731_VLANID, (void *)&u16vid);
#endif
		
	strSetOAMD = boaGetVar(wp, "save", "");
	if (strSetOAMD[0]) {
#ifdef CONFIG_USER_8023AH
		str = boaGetVar(wp, "oam8023ahMode", "");	
		u8Val = (str && str[0]) ? 1 : 0;
		mib_set(EFM_8023AH_MODE, (void *)&u8Val);
		
		str = boaGetVar(wp, "8023ahActive", "");
		u8Val = (str && str[0]) ? 1 : 0;
		mib_set(EFM_8023AH_ACTIVE, (void *)&u8Val);
#endif

#ifdef CONFIG_USER_Y1731
		str = boaGetVar(wp, "oamMode", "");	
		if (str[0]) {			
			u8Val = atoi(str);
		mib_set(Y1731_MODE, (void *)&u8Val);
		}
	
		str = boaGetVar(wp, "myid", "1");	
		u16Val = atoi(str);
		mib_set(Y1731_MYID, (void *)&u16Val);
	
		str = boaGetVar(wp, "megid", "rtkIgd");		
		mib_set(Y1731_MEGID, (void *)str);
	
		str = boaGetVar(wp, "loglevel", "medium");		
		mib_set(Y1731_LOGLEVEL, (void *)str);	
	
		str = boaGetVar(wp, "ccmenable", "");
		if (str[0]) {
			u8Val = (str && str[0]) ? 1 : 0;			
			mib_set(Y1731_ENABLE_CCM, (void *)&u8Val);	
		
		str = boaGetVar(wp, "ccminterval", "0");	
		u8Val = atoi(str);
		mib_set(Y1731_CCM_INTERVAL, (void *)&u8Val);
		}
		else {
			u8Val = 0;
			mib_set(Y1731_ENABLE_CCM, (void *)&u8Val);
			mib_set(Y1731_CCM_INTERVAL, (void *)&u8Val);
		}
#endif			
		
#ifdef COMMIT_IMMEDIATELY
		Commit();
#endif	
#ifdef CONFIG_USER_Y1731	
		Y1731_start(0);
#endif
#ifdef CONFIG_USER_8023AH		
		EFM_8023AH_start(0);
#endif
	}

#ifdef CONFIG_USER_Y1731	
	// (2) Send Loopback or Linktrace Test
	// Mason Yu.	
	strLoopback = boaGetVar(wp, "loopback", "");
	strLinktrace = boaGetVar(wp, "linktrace", "");
	if (strLoopback[0] || strLinktrace[0]) {
		FILE *fp, *pf;
		int i;
		char filename[32];
		char ifindex[10], levelStr[4], vidStr[5];
		char line[512] = {0}, cmd[512] = {0};
		char line2[512] = {0};
		int found=0;
		int exist=0;
		char foundMac[20]="";			
		char existMac[20]="";
		
		macaddr = boaGetVar(wp, "targetMac", "");
		
		snprintf(filename,32,"/sys/class/net/%s/ifindex", ifname);		
		if ((fp = fopen(filename, "r"))== NULL){
			printf("ERROR: open file %s error!\n", filename);
			return;
		}
		fscanf(fp, "%d\n", &i);
		fclose(fp);
		snprintf(ifindex, 10, "%d", i);
		snprintf(levelStr, 4 ,"%d", level);				
		snprintf(vidStr, 5 ,"%d", u16vid);
		
		printf("levelStr=%s, vidStr=%s, ifname=%s,  macaddr=%s, filename=%s, ifindex=%s\n", levelStr, vidStr, ifname, macaddr, filename, ifindex);
		
		if (strLoopback[0]) {
			//oamping -m 18:f1:45:25:08:04 -l 2 -f 29 -c 1 -v 101 > /tmp/oamping.tmp 2>&1			
			snprintf(cmd, sizeof(cmd), "oamping -m %s -l %s -f %s -c 1 -v %s > /tmp/oamping.tmp 2>&1", macaddr, levelStr, ifindex, vidStr);
			va_cmd("/bin/sh", 2, 1, "-c", cmd);

			pf = fopen("/tmp/oamping.tmp", "r");
			if(pf){
				boaHeader(wp);
				//boaWrite(wp, "<body><pre>\n");
				boaWrite(wp, "<body><blockquote><h4>OAM Loopback Test<br><br>");
				#if 0
				while(fgets(line, sizeof(line), pf)){
					printf("%s", line);
					boaWrite(wp, "%s", line);
				}
				#else
				while(fgets(line, sizeof(line), pf)){
					if(strstr(line, "LB RECV")) {						
						boaWrite(wp, "Loopback Test success!");
						found = 1;
					}
				}
	
				if (!found)
					boaWrite(wp, "Loopback Test failed!");
				#endif
				submitUrl = boaGetVar(wp, "submit-url", "");
	
				boaWrite(wp, "<form><input type=button value=\"%s\" OnClick=window.location.replace(\"%s\")></form></blockquote></body>", Tback, submitUrl);
		
				boaFooter(wp);
				boaDone(wp, 200);
				fclose(pf);
				unlink("/tmp/oamping.tmp");
			}		
			return;
		}
		
		if (strLinktrace[0]) {			
			unsigned char ttl;
			
			str = boaGetVar(wp, "ttl", "");
			if ( strcmp(str, "-1")== 0 )
				ttl = 0;
			else if (str[0]) {				
				ttl = atoi(str);				
			}			 
			
			FILE *macfp=fopen(RESOLV_LINKTRACE,"a+");		/*save the MAC into /var/resolv_linktrace.conf */
			
			//oamtrace -m 18:f1:45:25:08:04 -l 2 -f 29 > /tmp/oamtrace.tmp 2>&1
			if ( !ttl)					
				snprintf(cmd, sizeof(cmd), "oamtrace -m %s -l %s -f %s -v %s > /tmp/oamtrace.tmp 2>&1", macaddr, levelStr, ifindex, vidStr);
			else
				snprintf(cmd, sizeof(cmd), "oamtrace -m %s -l %s -f %s -t %d -v %s > /tmp/oamtrace.tmp 2>&1", macaddr, levelStr, ifindex, ttl, vidStr);
			va_cmd("/bin/sh", 2, 1, "-c", cmd);

			pf = fopen("/tmp/oamtrace.tmp", "r");
			if(pf){
				boaHeader(wp);
				//boaWrite(wp, "<body><pre>\n");
				boaWrite(wp, "<body><blockquote><h4>OAM Linktrace Test<br><br>");
				#if 0
				while(fgets(line, sizeof(line), pf)){
					printf("%s", line);
					boaWrite(wp, "%s", line);
				}
				#else
				while(fgets(line, sizeof(line), pf)){
					if(strstr(line, "Next MAC")) {                                                						
						boaWrite(wp, "Linktrace Test success!");
						found = 1;						
						if (sscanf(line, "Next MAC %s", foundMac) == 1) {
							foundMac[18]='\0';
							//printf("***** foundMac=%s\n", foundMac);
							
							while(fgets(line2, sizeof(line2), macfp)){
								if (sscanf(line2, "%s", existMac) == 1) {
									existMac[18]='\0';
									//printf("***** existMac=%s\n", existMac);
									if(strcmp(foundMac, existMac)==0) {
										exist = 1;
										//printf("***** MAC exist=%s\n", existMac);
									}
								}
							}
							if(!exist)
								fprintf(macfp, "%s\n", foundMac);
						}
					}
				}

				if (!found)
					boaWrite(wp, "Linktrace Test failed!");
				#endif
				submitUrl = boaGetVar(wp, "submit-url", "");
		
				boaWrite(wp, "<form><input type=button value=\"%s\" OnClick=window.location.replace(\"%s\")></form></blockquote></body>", Tback, submitUrl);
		
				boaFooter(wp);
				boaDone(wp, 200);
				fclose(pf);
				unlink("/tmp/oamtrace.tmp");
			}
			fclose(macfp);
			return;
		}				
		
	}
#endif	
	submitUrl = boaGetVar(wp, "submit-url", "");
	OK_MSG(submitUrl);
	return;

setErr_end:
	ERR_MSG(tmpBuf);
}


