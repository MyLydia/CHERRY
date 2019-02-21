/*
 *      Web server handler routines for TCP/IP stuffs
 *      Authors: David Hsu	<davidhsu@realtek.com.tw>
 *      Authors: Dick Tam	<dicktam@realtek.com.tw>
 *
 */


/*-- System inlcude files --*/
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <time.h>
#include <net/route.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <linux/if.h>

/*-- Local inlcude files --*/
#include "../webs.h"
#include "webform.h"
#include "mib.h"
#include "fmdefs.h"
#include "utility.h"
#ifdef CONFIG_MIDDLEWARE
#include <rtk/midwaredefs.h>
#endif

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>

#define	CONFIG_DIR	"/var/config"
#define CA_FNAME	CONFIG_DIR"/cacert.pem"
#define CERT_FNAME	CONFIG_DIR"/client.pem"
#define CWMP_PRMT_FILE	"/tmp/cwmp_prmt"
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
#define CA_STATUS_FILE	"/tmp/ca_status"
#endif

#define RECONNECT_MSG(url) { \
	boaHeader(wp); \
	boaWrite(wp, "<head><META http-equiv=content-type content=\"text/html; charset=gbk\"></head>");\
	boaWrite(wp, "<body><blockquote><h4>设定成功! " \
                "<form><input type=button value=\"  OK  \" OnClick=window.location.replace(\"%s\")></form></blockquote></body>", url);\
	boaFooter(wp); \
	boaDone(wp, 200); \
}


#define UPLOAD_MSG(url) { \
	boaHeader(wp); \
	boaWrite(wp, "<head><META http-equiv=content-type content=\"text/html; charset=gbk\"></head>");\
	boaWrite(wp, "<body><blockquote><h4>上传成功! " \
                "<form><input type=button value=\"  OK  \" OnClick=window.location.replace(\"%s\")></form></blockquote></body>", url);\
	boaFooter(wp); \
	boaDone(wp, 200); \
}

#define DEL_MSG(url) { \
	boaHeader(wp); \
	boaWrite(wp, "<head><META http-equiv=content-type content=\"text/html; charset=gbk\"></head>");\
	boaWrite(wp, "<body><blockquote><h4>删除成功! " \
                "<form><input type=button value=\"  OK  \" OnClick=window.location.replace(\"%s\")></form></blockquote></body>", url);\
	boaFooter(wp); \
	boaDone(wp, 200); \
}

//copy from fmmgmt.c
//find the start and end of the upload file.
FILE * uploadGetCert(request *wp, unsigned int *startPos, unsigned int *endPos)
{
	FILE *fp=NULL;
	struct stat statbuf;
	unsigned char c, *buf;
	char boundary[80];
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	char cmd[32] = {0};
#endif


	if (wp->method == M_POST)
	{
		int i;

		fstat(wp->post_data_fd, &statbuf);
		lseek(wp->post_data_fd, SEEK_SET, 0);

		printf("file size=%d\n",statbuf.st_size);
		fp=fopen(wp->post_file_name,"rb");
		if(fp==NULL) goto error;

		memset( boundary, 0, sizeof( boundary ) );
		if( fgets( boundary,80,fp )==NULL ) goto error;
		if( boundary[0]!='-' || boundary[1]!='-') 
		{
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
			snprintf(cmd, 32, "%s%s", "echo 1 > ", CA_STATUS_FILE);
			system(cmd);
#endif
			goto error;
		}

		i= strlen( boundary ) - 1;
		while( boundary[i]=='\r' || boundary[i]=='\n' )
		{
			boundary[i]='\0';
			i--;
		}
		printf( "boundary=%s\n", boundary );
	}
	else goto error;


   	//printf("_uploadGet\n");
   	do
   	{
		if(feof(fp))
		{
			printf("Cannot find start of file\n");
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
			snprintf(cmd, 32, "%s%s", "echo 1 > ", CA_STATUS_FILE);
			system(cmd);
#endif
			goto error;
		}
		c= fgetc(fp);
		if (c!=0xd)
			continue;
		c= fgetc(fp);
		if (c!=0xa)
			continue;
		c= fgetc(fp);
		if (c!=0xd)
			continue;
		c= fgetc(fp);
		if (c!=0xa)
			continue;
		break;
	}while(1);
	(*startPos)=ftell(fp);

   	if(fseek(fp,statbuf.st_size-0x200,SEEK_SET)<0)
	{
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
			snprintf(cmd, 32, "%s%s", "echo 1 > ", CA_STATUS_FILE);
			system(cmd);
#endif
      		goto error;
	}

	do
	{
		if(feof(fp))
		{
			printf("Cannot find end of file\n");
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
			snprintf(cmd, 32, "%s%s", "echo 1 > ", CA_STATUS_FILE);
			system(cmd);
#endif
			goto error;
		}
		c= fgetc(fp);
		if (c!=0xd)
			continue;
		c= fgetc(fp);
		if (c!=0xa)
			continue;

		{
			int i, blen;

			blen= strlen( boundary );
			for( i=0; i<blen; i++)
			{
				c= fgetc(fp);
				//printf("%c(%u)", c, c);
				if (c!=boundary[i])
				{
					ungetc( c, fp );
					break;
				}
			}
			//printf("\r\n");
			if( i!=blen ) continue;
		}

		break;
	}while(1);
	(*endPos)=ftell(fp)-strlen(boundary)-2;

   	return fp;
error:
   	return NULL;
}

///////////////////////////////////////////////////////////////////
void formTR069Config(request *wp, char *path, char *query)
{
	char *strData=NULL;
	char tmpStr[256 + 1]={0};
	char tmpBuf[100]={0};
	unsigned char vChar=0;
	unsigned char cwmp_flag = 0;
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	unsigned char gui_passauth_enable = 0;
#endif
	unsigned char informEnble=0;
	unsigned char old_informEnable = 0;
	unsigned int informInterval=0;
#ifdef CONFIG_MIDDLEWARE
	unsigned char tr069Enable;
	unsigned char lastValue,validValue;
	char *midwareAddr;
	unsigned int midwarePort,vInt;
#endif	//end of CONFIG_MIDDLEWARE
	// Mason Yu
	char changeflag = 0;
	char waitMwExit = 0;
	char hotSetMidware=0;

	strData = boaGetVar(wp,"applyTr069Config","");
	if (strData[0]){

		unsigned char configurable = 0;

		mib_get(CWMP_CONFIGURABLE, &configurable);
		if(configurable == 0)
			return;

		strData = boaGetVar(wp,"inform","");
		if (strData[0]) {
			//informEnble = (strData[0] == '0') ? 0 : 1;
			mib_get(CWMP_INFORM_ENABLE,&old_informEnable);
			informEnble = (strData[0] == '0') ? 0 :((strData[0] == '1') ? 1 : 2);
			if (!mib_set(CWMP_INFORM_ENABLE, &informEnble)) {
				strcpy(tmpBuf,strSetInformEnableerror);
				goto setErr_tr069;
			}
			if(old_informEnable != informEnble)//change infrom type, should restart cwmp to read gRandomInform
				changeflag = 1;
		}

		if (informEnble) {
			strData = boaGetVar(wp,"informInterval","");
			if (strData[0]) {
				informInterval = strtoul(strData, NULL, 0);

				if (!mib_set(CWMP_INFORM_INTERVAL, &informInterval)) {
					strcpy(tmpBuf,strSetInformIntererror);
					goto setErr_tr069;
				}
			}
		}

		strData = boaGetVar(wp,"acsURL","");
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		if (strData[0] || strlen(strData)==0) {
#else
		if (strData[0]){
			if (strlen(strData) == 0) {
				strcpy(tmpBuf,strACSURLWrong);
				goto setErr_tr069;
		}
#endif
	#ifndef _CWMP_WITH_SSL_
			if (strstr(strData, "https://")) {
				strcpy(tmpBuf,strSSLWrong);
				goto setErr_tr069;
			}
	#endif
			mib_get(CWMP_ACS_URL, tmpStr);
			printf("acs=%s | %s\n", tmpStr, strData);
			if (strcmp(tmpStr, strData))
			{
				mib_set(CWMP_ACS_URL_OLD, (void *)tmpStr);
			}

/*star:20100305 START add qos rule to set tr069 packets to the first priority queue*/
			storeOldACS();
/*star:20100305 END*/

			DelTR069WANInterface(Old_ACS_URL);  // Magician: Del pre-defined routing of TR-069 WAN interface, if ACS URL is changed.

			if (!mib_set(CWMP_ACS_URL, strData)) {
				strcpy(tmpBuf,strSetACSURLerror);
				goto setErr_tr069;
			}
#ifdef CONFIG_TR142_MODULE
			else
			{
				unsigned char from = CWMP_ACS_FROM_MIB;
	
				mib_set(RS_CWMP_USED_ACS_URL, (void *)strData);
				mib_set(RS_CWMP_USED_ACS_FROM, (void *)&from);
			}
#endif

			cmd_set_dns_config(NULL);
			restart_dnsrelay();
		}

		strData = boaGetVar(wp,"acsUser","");
		if (!mib_set(CWMP_ACS_USERNAME, strData)) {
			strcpy(tmpBuf,strSetUserNameerror);
			goto setErr_tr069;
		}

		strData = boaGetVar(wp,"acsPwd","");
		if (!mib_set(CWMP_ACS_PASSWORD, strData)) {
			strcpy(tmpBuf,strSetPasserror);
			goto setErr_tr069;
		}


		strData = boaGetVar(wp,"connReqUser","");
		//if (strData[0])
		{
			if (!mib_set( CWMP_CONREQ_USERNAME, strData)) {
				strcpy(tmpBuf,strSetConReqUsererror);
				goto setErr_tr069;
			}
		}

		strData = boaGetVar(wp,"connReqPwd","");
		//if (strData[0])
		{
			if (!mib_set(CWMP_CONREQ_PASSWORD, (void *)strData)) {
				strcpy(tmpBuf,strSetConReqPasserror);
				goto setErr_tr069;
			}
		}

		strData = boaGetVar(wp,"certauth","");
		if (strData[0]) {
			if (mib_get(CWMP_FLAG, &cwmp_flag)) {
				vChar = cwmp_flag;
				if (strData[0] == '0')
					cwmp_flag &= ~CWMP_FLAG_CERT_AUTH;
				else
					cwmp_flag |= CWMP_FLAG_CERT_AUTH;

				if(vChar != cwmp_flag)
				{
					changeflag = 1;
					if (!mib_set(CWMP_FLAG, &cwmp_flag)) {
						strcpy(tmpBuf,strSetCWMPFlagerror);
						goto setErr_tr069;
					}
				}
			} else {
				strcpy(tmpBuf,strGetCWMPFlagerror);
				goto setErr_tr069;
			}
		}

#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		strData = boaGetVar(wp,"passauth","");
		if (strData[0]) {
			gui_passauth_enable = (strData[0] == '0') ? 0 : 1;

			if (!mib_set(CWMP_GUI_PASSWORD_ENABLE, &gui_passauth_enable)) {
				strcpy(tmpBuf,strSetPassAuthEnableerror);
				goto setErr_tr069;
			}
		}

		unlink(CA_STATUS_FILE);

		mib_get( CWMP_FLAG, (void *)&vChar);
		if( !access("/var/config/cacert.pem", F_OK ) && (vChar & CWMP_FLAG_CERT_AUTH) )
		{
		snprintf(tmpBuf, 32, "%s%s", "echo 3 > ", CA_STATUS_FILE);
		system(tmpBuf);
		}
#endif
	}	//end if applyTr069Config

#ifdef _CWMP_WITH_SSL_
end_tr069:
#endif
	// Mason Yu
#ifdef APPLY_CHANGE
	
	if(changeflag == 1){
		if(cwmp_flag || (old_informEnable != informEnble)) 
		{
			off_tr069();
			sleep(3);

			if (-1 == startCWMP()) {
				strcpy(tmpBuf,"Start tr069 Fail *****");
				printf("Start tr069 Fail *****\n");
				goto setErr_tr069;
			}
		}
		else// disable TR069
		{  
			off_tr069();
		} 
	}
#endif	//end of APPLY_CHANGE

// Magician: Commit immediately
#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif

#if 0
	SetTR069WANInterface();
#endif

	strData = boaGetVar(wp,"submit-url","");
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	boaRedirect(wp, strData);
#else
	RECONNECT_MSG(strData);// display reconnect msg to remote
#endif

	return;

setErr_tr069:
	ERR_MSG(tmpBuf);
}

void formTR069CPECert(request *wp, char *path, char *query)
{
	char	*strData;
	char tmpBuf[100];
	FILE	*fp=NULL,*fp_input;
	unsigned char *buf;
	unsigned int startPos,endPos,nLen,nRead;
	if ((fp = uploadGetCert(wp, &startPos, &endPos)) == NULL)
	{
		strcpy(tmpBuf,strUploaderror);
 		goto setErr_tr069cpe;
 	}

	nLen = endPos - startPos;
	//printf("filesize is %d\n", nLen);
	buf = malloc(nLen+1);
	if (!buf)
	{
		strcpy(tmpBuf,strMallocFail);
 		goto setErr_tr069cpe;
 	}

	fseek(fp, startPos, SEEK_SET);
	nRead = fread((void *)buf, 1, nLen, fp);
	buf[nRead]=0;
	if (nRead != nLen)
 		printf("Read %d bytes, expect %d bytes\n", nRead, nLen);

	//printf("write to %d bytes from %08x\n", nLen, buf);

	fp_input=fopen(CERT_FNAME,"w");
	if (!fp_input)
		printf("create %s file fail!\n", CERT_FNAME);
	fprintf(fp_input,buf);
	printf("create file %s\n", CERT_FNAME);
	free(buf);
	fclose(fp_input);

#ifdef CONFIG_USER_FLATFSD_XXX
	if( va_niced_cmd( "/bin/flatfsd",1,1,"-s" ) )
		printf( "[%d]:exec 'flatfsd -s' error!",__FILE__ );
#endif

	off_tr069();

	if (startCWMP() == -1)
	{
		strcpy(tmpBuf,"Start tr069 Fail *****");
		printf("Start tr069 Fail *****\n");
		goto setErr_tr069cpe;
	}

	strData = boaGetVar(wp,"submit-url","/net_tr069.asp");
	UPLOAD_MSG(strData);// display reconnect msg to remote
	return;

setErr_tr069cpe:
	ERR_MSG(tmpBuf);
}

void formTR069CACert(request *wp, char *path, char *query)
{
	char	*strData;
	char	tmpBuf[128];
	FILE	*fp=NULL,*fp_input;
	unsigned char *buf;
	unsigned int startPos,endPos,nLen,nRead;
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	char cmd[32] = {0};
	unsigned char vChar;

	if (!mib_get( CWMP_FLAG, (void *)&vChar))
		printf("Get MIB failed...\n");

	if ((vChar & CWMP_FLAG_CERT_AUTH)==0)
	{
		snprintf(cmd, 32, "%s%s", "echo 2 > ", CA_STATUS_FILE);
		system(cmd);
		goto tr069ca_disabled;
	}else
	{
		snprintf(cmd, 32, "%s%s", "echo 3 > ", CA_STATUS_FILE);
		system(cmd);
	}
	
	fp = fopen(CA_FNAME, "r");
	if (!fp) 
	{
		snprintf(cmd, 32, "%s%s", "echo 4 > ", CA_STATUS_FILE);
		system(cmd);
	}
#endif

	if ((fp = uploadGetCert(wp, &startPos, &endPos)) == NULL)
	{
		strcpy(tmpBuf,strUploaderror);
 		goto setErr_tr069ca;
 	}

	nLen = endPos - startPos;
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	if(nLen > 2000)
	{
		snprintf(cmd, 32, "%s%s", "echo 5 > ", CA_STATUS_FILE);
		system(cmd);
		goto tr069ca_disabled;
	}
#endif
	//printf("filesize is %d\n", nLen);
	buf = malloc(nLen+1);
	if (!buf)
	{
		strcpy(tmpBuf,strMallocFail);
 		goto setErr_tr069ca;
 	}

	fseek(fp, startPos, SEEK_SET);
	nRead = fread((void *)buf, 1, nLen, fp);
	buf[nRead]=0;
	if (nRead != nLen)
 		printf("Read %d bytes, expect %d bytes\n", nRead, nLen);

	//printf("write to %d bytes from %08x\n", nLen, buf);

	fp_input=fopen(CA_FNAME,"w");
	if (!fp_input)
		printf("create %s file fail!\n", CA_FNAME );
	fprintf(fp_input,buf);
	printf("create file %s\n",CA_FNAME);
	free(buf);
	fclose(fp_input);

#ifdef CONFIG_USER_FLATFSD_XXX
	if( va_niced_cmd( "/bin/flatfsd",1,1,"-s" ) )
		printf( "[%d]:exec 'flatfsd -s' error!",__FILE__ );
#endif

	off_tr069();

	if (startCWMP() == -1)
	{
		strcpy(tmpBuf,"Start tr069 Fail *****");
		printf("Start tr069 Fail *****\n");
		goto setErr_tr069ca;
	}

#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	snprintf(cmd, 32, "%s%s", "echo 0 > ", CA_STATUS_FILE);
	system(cmd);
tr069ca_disabled:
	boaRedirect(wp, "/net_tr069_cmcc.asp");
#else
	strData = boaGetVar(wp,"submit-url","/net_certca.asp");
	UPLOAD_MSG(strData);// display reconnect msg to remote
#endif
	return;

setErr_tr069ca:
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	boaRedirect(wp, "/net_tr069_cmcc.asp");
	return;
#else
	ERR_MSG(tmpBuf);
#endif
}


void formTR069CACertDel(request *wp, char *path, char *query)
{
	char	*strData;
	char tmpBuf[100];
	FILE	*fp=NULL,*fp_input;
	unsigned char *buf;
	unsigned int startPos,endPos,nLen,nRead;

	unlink(CA_FNAME);

#ifdef CONFIG_USER_FLATFSD_XXX
	if( va_niced_cmd( "/bin/flatfsd",1,1,"-s" ) )
		printf( "[%d]:exec 'flatfsd -s' error!",__FILE__ );
#endif

	off_tr069();

	if (startCWMP() == -1)
	{
		strcpy(tmpBuf,"Start tr069 Fail *****");
		printf("Start tr069 Fail *****\n");
		goto setErr_tr069ca;
	}

	strData = boaGetVar(wp,"submit-url","/net_certca.asp");
	DEL_MSG(strData);// display reconnect msg to remote
	return;

setErr_tr069ca:
	ERR_MSG(tmpBuf);
}

void formMidwareConfig(request *wp, char *path, char *query)
{
	//We have no midleware currently.
	_COND_REDIRECT;
}

/*******************************************************/
/*show extra fileds at net_tr069.asp*/
/*******************************************************/
#ifdef _CWMP_WITH_SSL_
int ShowACSCertCPE(request *wp)
{
	int nBytesSent=0;
	unsigned char vChar=0;
	int isEnable=0;

	if ( mib_get( CWMP_FLAG, (void *)&vChar) )
		if ( (vChar & CWMP_FLAG_CERT_AUTH)!=0 )
			isEnable=1;

	nBytesSent += boaWrite(wp,"  <tr>\n");
	nBytesSent += boaWrite(wp,"      <td width=\"30%%\"><font size=2><b>ACS Certificates CPE:</b></td>\n");
	nBytesSent += boaWrite(wp,"      <td width=\"70%%\"><font size=2>\n");
	nBytesSent += boaWrite(wp,"      <input type=\"radio\" name=certauth value=0 %s >No&nbsp;&nbsp;\n", isEnable==0?"checked":"" );
	nBytesSent += boaWrite(wp,"      <input type=\"radio\" name=certauth value=1 %s >Yes\n", isEnable==1?"checked":"" );
	nBytesSent += boaWrite(wp,"      </td>\n");
	nBytesSent += boaWrite(wp,"  </tr>\n");

//		"\n"), isEnable==0?"checked":"", isEnable==1?"checked":"" );

	return nBytesSent;
}

int ShowMNGCertTable(request *wp)
{
	int nBytesSent=0;
	char buffer[256]="";

	getMIB2Str(CWMP_CERT_PASSWORD,buffer);

	nBytesSent += boaWrite(wp, "\n"
		"<table border=0 width=\"500\" cellspacing=4 cellpadding=0>\n"
		"  <tr><hr size=1 noshade align=top></tr>\n"
		"  <tr>\n"
		"      <td width=\"30%%\"><font size=2><b>Certificat Management:</b></td>\n"
		"      <td width=\"70%%\"><b></b></td>\n"
		"  </tr>\n"
		"\n");


	nBytesSent += boaWrite(wp, "\n"
		"  <tr>\n"
		"      <td width=\"30%%\"><font size=2><b>CPE Certificat Password:</b></td>\n"
		"      <td width=\"70%%\">\n"
		"		<form action=/boaform/admin/formTR069Config method=POST name=\"cpe_passwd\">\n"
		"		<input type=\"text\" name=\"certpw\" size=\"24\" maxlength=\"64\" value=\"%s\">\n"
		"		<input type=\"submit\" value=\"Apply\" name=\"CPE_Cert\">\n"
		"		<input type=\"reset\" value=\"Undo\" name=\"reset\">\n"
		"		<input type=\"hidden\" value=\"/net_tr069_sc.asp\" name=\"submit-url\">\n"
		"		</form>\n"
		"      </td>\n"
		"  </tr>\n"
		"\n", buffer);

	nBytesSent += boaWrite(wp, "\n"
		"  <tr>\n"
		"      <td width=\"30%%\"><font size=2><b>CPE Certificat:</b></td>\n"
		"      <td width=\"70%%\"><font size=2>\n"
		"           <form action=/boaform/admin/formTR069CPECert method=POST enctype=\"multipart/form-data\" name=\"cpe_cert\">\n"
		"           <input type=\"file\" name=\"binary\" size=24>&nbsp;&nbsp;\n"
		"           <input type=\"submit\" value=\"Upload\" name=\"load\">\n"
		"           </form>\n"
		"      </td>\n"
		"  </tr>\n"
		"\n");

	nBytesSent += boaWrite(wp, "\n"
		"  <tr>\n"
		"      <td width=\"30%%\"><font size=2><b>CA Certificat:</b></td>\n"
		"      <td width=\"70%%\"><font size=2>\n"
		"           <form action=/boaform/admin/formTR069CACert method=POST enctype=\"multipart/form-data\" name=\"ca_cert\">\n"
		"           <input type=\"file\" name=\"binary\" size=24>&nbsp;&nbsp;\n"
		"           <input type=\"submit\" value=\"Upload\" name=\"load\">\n"
		"           </form>\n"
		"      </td>\n"
		"  </tr>\n"
		"\n");

	nBytesSent += boaWrite(wp, "\n"
		"</table>\n"
		"\n");


	return nBytesSent;
}
#endif

#ifdef _INFORM_EXT_FOR_X_CT_
int ShowCTInformExt(request *wp)
{
	int nBytesSent=0;
	unsigned char vChar=0;
	int isEnable=0;

	if ( mib_get( CWMP_FLAG, (void *)&vChar) )
		if ( (vChar & CWMP_FLAG_CTINFORMEXT)!=0 )
			isEnable=1;

	nBytesSent += boaWrite(wp,"  <tr>\n");
	nBytesSent += boaWrite(wp,"      <td width=\"30%%\"><font size=2><b>CT Inform Extension:</b></td>\n");
	nBytesSent += boaWrite(wp,"      <td width=\"70%%\"><font size=2>\n");
	nBytesSent += boaWrite(wp,"      <input type=\"radio\" name=ctinformext value=0 %s >Disabled&nbsp;&nbsp;\n", isEnable==0?"checked":"" );
	nBytesSent += boaWrite(wp,"      <input type=\"radio\" name=ctinformext value=1 %s >Enabled\n", isEnable==1?"checked":"" );
	nBytesSent += boaWrite(wp,"      </td>\n");
	nBytesSent += boaWrite(wp,"  </tr>\n");

	return nBytesSent;
}
#endif

int TR069ConPageShow(int eid, request *wp, int argc, char **argv)
{
	int nBytesSent=0;
	char *name;

	if (boaArgs(argc, argv,"%s", &name) < 1) {
		boaError(wp, 400,strArgerror);
		return -1;
	}

#ifdef _CWMP_WITH_SSL_
	if ( !strcmp(name,"ShowACSCertCPE") )
		return ShowACSCertCPE( wp );
	else if ( !strcmp(name,"ShowMNGCertTable") )
		return ShowMNGCertTable( wp );
#endif
#ifdef _INFORM_EXT_FOR_X_CT_
	if ( !strcmp(name,"ShowCTInformExt") )
		return ShowCTInformExt( wp );
#endif

	if(!strcmp(name, "cwmp-configurable"))
	{
		unsigned char configurable = 0;
		unsigned int is_backdoor_login = is_backdoor_userlogin(wp);

		mib_get(CWMP_CONFIGURABLE, &configurable);
		if(configurable || is_backdoor_login)
			nBytesSent += boaWrite(wp,"1");
		else
			nBytesSent += boaWrite(wp,"0");
	}

	return nBytesSent;
}

int TR069DumpCWMP(int eid, request * wp, int argc, char **argv)
{
	int cwmp_msgid = 0;
	unsigned long size1 = 1, size2 = 2;
	struct stat st;
	struct cwmp_message cwmpmsg = {0};
	FILE *fp = NULL;
	char content;

	if((cwmp_msgid = msgget((key_t)1234, 0)) > 0 )
	{
		cwmpmsg.msg_type = MSG_PRINT_PRMT; 
		msgsnd(cwmp_msgid, (void *)&cwmpmsg, MSG_SIZE, 0);
	}
	else
	{
		fprintf(stderr, "Can't get cwmp msgQueue!\n");
		return -1;
	}

	while (size1 != size2)
	{
		sleep(1);
		stat(CWMP_PRMT_FILE, &st);
		size1 = st.st_size;
		sleep(1);
		stat(CWMP_PRMT_FILE, &st);
		size2 = st.st_size;
	}
        
	fp = fopen(CWMP_PRMT_FILE, "r");
	if(fp == NULL)
	{
		fprintf(stderr, "Open %s failed\n", CWMP_PRMT_FILE);
		return -1;
	}

	while (!feof(fp))
	{
		fscanf(fp, "%c", &content);

		boaWrite(wp, "%c", content);
	}
                
	fclose(fp);
	return 0;
}
