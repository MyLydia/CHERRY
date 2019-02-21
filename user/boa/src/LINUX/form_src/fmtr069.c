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

/*-- Local inlcude files --*/
#include "../webs.h"
#include "webform.h"
#include "mib.h"
#include "multilang.h"
#include "utility.h"

#define	CONFIG_DIR	"/var/config"
#define CA_FNAME	CONFIG_DIR"/cacert.pem"
#define CERT_FNAME	CONFIG_DIR"/client.pem"

#define UPLOAD_MSG(url) { \
	boaHeader(wp); \
	boaWrite(wp, "<body><blockquote><h4>Upload a file successfully!" \
                "<form><input type=button value=\"  OK  \" OnClick=window.location.replace(\"%s\")></form></blockquote></body>", url);\
	boaFooter(wp); \
	boaDone(wp, 200); \
}
//copy from fmmgmt.c
//find the start and end of the upload file.
FILE *uploadGetCert(request *wp, unsigned int *startPos, unsigned *endPos)
{
	FILE *fp=NULL;
	struct stat statbuf;
	unsigned char *buf;
	int c;
	char boundary[80];


	if (wp->method == M_POST)
	{
		int i;

		fstat(wp->post_data_fd, &statbuf);
		lseek(wp->post_data_fd, SEEK_SET, 0);

		printf("file size=%d\n",statbuf.st_size);
		fp=fopen(wp->post_file_name, "rb");
		if(fp==NULL) goto error;

		memset(boundary, 0, sizeof(boundary));
		if( fgets(boundary, 80, fp)==NULL ) goto error;
		if( boundary[0]!='-' || boundary[1]!='-') goto error;

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
		goto error;

	do
	{
		if(feof(fp))
		{
			printf("Cannot find end of file\n");
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

int obtainCWMPIpAclEntry(request * wp, MIB_CWMP_ACL_IP_Tp pEntry)
{
	char	*str;
	char tmpBuf[100];
	int isnet;
	struct sockaddr acl_ip;
	unsigned long mask, mbit;
	struct in_addr *addr;
	unsigned char aclmask[4]={0}, aclip[4];
	int totalEntry, i;
	MIB_CWMP_ACL_IP_T Entry;
	char *temp;
	long nAclip;
	unsigned short uPort;

	str = boaGetVar(wp, "aclIP", "");
	if (str[0]){
		if ((isnet = INET_resolve(str, &acl_ip)) < 0) {
			snprintf(tmpBuf, 100, "%s %s", strCantResolve, str);
			goto setErr_obtain;
		}

		// add into configuration (chain record)
		addr = (struct in_addr *)&(pEntry->ipAddr);
		*addr = ((struct sockaddr_in *)&acl_ip)->sin_addr;
	}

	str = boaGetVar(wp, "aclMask", "");
	if (str[0]) {
		if (!isValidNetmask(str, 0)) {
			strcpy(tmpBuf, strWrongMask);
			goto setErr_obtain;
		}
		inet_aton(str, (struct in_addr *)aclmask);
		inet_aton(str, (struct in_addr *)&mask);
		mbit=0;
		while (1) {
			if (mask&0x80000000) {
				mbit++;
				mask <<= 1;
			}
			else
				break;
		}
		pEntry->maskbit = mbit;
	}
	// Jenny, for checking duplicated acl IP address
	aclip[0] = pEntry->ipAddr[0] & aclmask[0];
	aclip[1] = pEntry->ipAddr[1] & aclmask[1];
	aclip[2] = pEntry->ipAddr[2] & aclmask[2];
	aclip[3] = pEntry->ipAddr[3] & aclmask[3];

	totalEntry = mib_chain_total(MIB_CWMP_ACL_IP_TBL);
	temp = inet_ntoa(*((struct in_addr *)aclip));
	nAclip = ntohl(inet_addr(temp));
	for (i=0; i<totalEntry; i++) {
		unsigned long v1, v2, pAclip;
		int m;
		if (!mib_chain_get(MIB_CWMP_ACL_IP_TBL, i, (void *)&Entry)) {
			strcpy(tmpBuf, strGetChainerror);
			goto setErr_obtain;
		}
		temp[0] = '\0';
		temp = inet_ntoa(*((struct in_addr *)Entry.ipAddr));
		v1 = ntohl(inet_addr(temp));
		v2 = 0xFFFFFFFFL;
		for (m=32; m>Entry.maskbit; m--) {
			v2 <<= 1;
			v2 |= 0x80000000;
		}
		pAclip = v1&v2;
		// If all parameters of Entry are all the same as new rule, drop this new rule.
		if (nAclip == pAclip) {
			strcpy(tmpBuf, Tinvalid_rule);
			goto setErr_obtain;
		}
	}	
	return 1;

setErr_obtain:
	ERR_MSG(tmpBuf);
	return 0;

}

int showCWMPACLTable(int eid, request * wp, int argc, char **argv)
{
	int nBytesSent=0;

	unsigned int entryNum, i;
	MIB_CWMP_ACL_IP_T Entry;
//#ifndef ACL_IP_RANGE
	struct in_addr dest;
//#endif
	char sdest[35]="";
	char service[128] ="";
	char port[64]="";
	char tmp_port[6]="";
	unsigned char testing_bit;

	entryNum = mib_chain_total(MIB_CWMP_ACL_IP_TBL);
#ifndef CONFIG_GENERAL_WEB
	nBytesSent += boaWrite(wp, "<tr><font size=1>"
	"<td align=center width=\"5%%\" bgcolor=\"#808080\">%s</td>\n"	
	"<td align=center width=\"20%%\" bgcolor=\"#808080\">%s</td></font></tr>\n",	
#else
	nBytesSent += boaWrite(wp, "<tr>"
	"<th align=center width=\"5%%\">%s</th>\n"	
	"<th align=center width=\"20%%\">%s</th></tr>\n",
#endif
	multilang(LANG_SELECT), multilang(LANG_IP_ADDRESS));

	for (i=0; i<entryNum; i++) {
		service[0] ='\0';
		port[0]='\0';

		if (!mib_chain_get(MIB_CWMP_ACL_IP_TBL, i, (void *)&Entry))
		{
  			boaError(wp, 400, "Get chain record error!\n");
			return -1;
		}

//#ifndef ACL_IP_RANGE
		dest.s_addr = *(unsigned long *)Entry.ipAddr;
		// inet_ntoa is not reentrant, we have to
		// copy the static memory before reuse it
		snprintf(sdest, sizeof(sdest), "%s/%d", inet_ntoa(dest), Entry.maskbit);		
//#endif
		nBytesSent += boaWrite(wp, "<tr>"
#ifndef CONFIG_GENERAL_WEB
		"<td align=center width=\"5%%\" bgcolor=\"#C0C0C0\"><input type=\"checkbox\" name=\"select%d\" value=\"ON\"></td>\n"		
		"<td align=center width=\"20%%\" bgcolor=\"#C0C0C0\" class=\"table_item\">%s</td>"
#else
		"<td align=center width=\"5%%\"><input type=\"checkbox\" name=\"select%d\" value=\"ON\"></td>\n"		
		"<td align=center width=\"20%%\">%s</td>"
#endif
		"</tr>\n",
		i, sdest);
	}
	return 0;
}

void formTR069Config(request * wp, char *path, char *query)
{
	char	*strData;
	char tmpBuf[100];
	unsigned char vChar;
	unsigned int cwmp_flag;
	int vInt;
	// Mason Yu
	char changeflag=0;
	unsigned char informEnble, aclEnable;
	unsigned int informInterv, tr069_itf, pre_tr069_itf;
	char cwmp_flag_value=1;
	char tmpStr[256+1];
	int cur_port;
	char isDisConReqAuth=0;
	FILE *fp;
	
#ifdef _CWMP_WITH_SSL_
	//CPE Certificat Password
	strData = boaGetVar(wp, "CPE_Cert", "");
	if( strData[0] )
	{
		strData = boaGetVar(wp, "certpw", "");

		changeflag = 1;
		if (!mib_set(CWMP_CERT_PASSWORD, (void *)strData))
		{
			strcpy(tmpBuf, strSetCerPasserror);
			goto setErr_tr069;
		}
		else
			printf("Debug Test!\n");
		goto end_tr069;
	}
#endif

	strData = boaGetVar(wp, "applyACL", "");
	if ( strData[0] ) {
		strData = boaGetVar(wp, "enable_acl", "");
		aclEnable = (strData[0]=='0')? 0:1;

		mib_get( CWMP_ACL_ENABLE, (void*)&vChar);
		if(vChar != aclEnable){
			if ( !mib_set( CWMP_ACL_ENABLE, (void *)&aclEnable)) {
				strcpy(tmpBuf, strSetInformEnableerror);
				goto setErr_tr069;
			}
		}
		goto end_tr069;
	}
	
	/* Delete selected IP */
	strData = boaGetVar(wp, "delIP", "");
	if (strData[0]) {
		char *strVal;
		unsigned int i;
		unsigned int idx;
		unsigned int totalEntry = mib_chain_total(MIB_CWMP_ACL_IP_TBL); /* get chain record size */
		unsigned int deleted = 0;		
		
		for (i=0; i<totalEntry; i++) {
			idx = totalEntry-i-1;
			snprintf(tmpBuf, 20, "select%d", idx);
			strVal = boaGetVar(wp, tmpBuf, "");
			if ( !gstrcmp(strVal, "ON") ) {
				deleted ++;				
				if(mib_chain_delete(MIB_CWMP_ACL_IP_TBL, idx) != 1) {
					strcpy(tmpBuf, Tdelete_chain_error);
					goto setErr_tr069;
				}
			}
		}
		if (deleted <= 0) {
			strcpy(tmpBuf, strNoItemSelectedToDelete);
			goto setErr_tr069;
		}
		goto end_tr069;
	}

	// Add
	strData = boaGetVar(wp, "addIP", "");
	if (strData[0]) {
		int mibtotal,i, intVal;
		MIB_CWMP_ACL_IP_T entry, tmpentry;

		memset(&entry, 0, sizeof(MIB_CWMP_ACL_IP_T));
		if ( !obtainCWMPIpAclEntry(wp, &entry))
			return;

		mibtotal = mib_chain_total(MIB_CWMP_ACL_IP_TBL);
		for(i=0;i<mibtotal;i++)
		{
			if(!mib_chain_get(MIB_CWMP_ACL_IP_TBL,i,(void*)&tmpentry))
				continue;
			if((*(int*)(entry.ipAddr))==(*(int*)(tmpentry.ipAddr)))
			{
				snprintf(tmpBuf, 100, strIpExist, strData);
				goto setErr_tr069;
			}
		}

		intVal = mib_chain_add(MIB_CWMP_ACL_IP_TBL, (unsigned char*)&entry);
		if (intVal == 0) {
			strcpy(tmpBuf, strAddChainerror);
			goto setErr_tr069;
		}
		else if (intVal == -1) {
			strcpy(tmpBuf, strTableFull);
			goto setErr_tr069;
		}
		goto end_tr069;
	}
	
	strData = boaGetVar(wp, "url", "");
	//if ( strData[0] )
	{
		if ( strlen(strData)==0 )
		{
			strcpy(tmpBuf, strACSURLWrong);
			goto setErr_tr069;
		}
#ifndef _CWMP_WITH_SSL_
		if ( strstr(strData, "https://") )
		{
			strcpy(tmpBuf, strSSLWrong);
			goto setErr_tr069;
		}
#endif
/*star:20100305 START add qos rule to set tr069 packets to the first priority queue*/
		storeOldACS();
/*star:20100305 END*/

		if ( !mib_set( CWMP_ACS_URL, (void *)strData))
		{
			strcpy(tmpBuf, strSetACSURLerror);
			goto setErr_tr069;
		}
#if defined(CONFIG_00R0) && defined(CONFIG_TR142_MODULE) && !defined(CONFIG_E8B)
		else
		{
			unsigned char from = CWMP_ACS_FROM_MIB;

			mib_set(RS_CWMP_USED_ACS_URL, (void *)strData);
			mib_set(RS_CWMP_USED_ACS_FROM, (void *)&from);
		}
#endif
#if defined(CONFIG_USER_DNSMASQ_DNSMASQ) || defined(CONFIG_USER_DNSMASQ_DNSMASQ245)
		cmd_set_dns_config(NULL);
		restart_dnsrelay();
#endif
	}

	strData = boaGetVar(wp, "username", "");
	//if ( strData[0] )
	{
		if ( !mib_set( CWMP_ACS_USERNAME, (void *)strData)) {
			strcpy(tmpBuf, strSetUserNameerror);
			goto setErr_tr069;
		}
	}

	strData = boaGetVar(wp, "password", "");
	//if ( strData[0] )
	{
		if ( !mib_set( CWMP_ACS_PASSWORD, (void *)strData)) {
			strcpy(tmpBuf, strSetPasserror);
			goto setErr_tr069;
		}
	}

	strData = boaGetVar(wp, "enable", "");
	if ( strData[0] ) {
		informEnble = (strData[0]=='0')? 0:1;

		mib_get( CWMP_INFORM_ENABLE, (void*)&vChar);
		if(vChar != informEnble){
			changeflag = 1;
			if ( !mib_set( CWMP_INFORM_ENABLE, (void *)&informEnble)) {
				strcpy(tmpBuf, strSetInformEnableerror);
				goto setErr_tr069;
			}
		}
	}

	strData = boaGetVar(wp, "interval", "");
	if ( strData[0] ) {
		informInterv = atoi(strData);

		if(informEnble == 1){
			mib_get( CWMP_INFORM_INTERVAL, (void*)&vInt);
			if(vInt != informInterv){
				changeflag = 1;
				if ( !mib_set( CWMP_INFORM_INTERVAL, (void *)&informInterv)) {
					strcpy(tmpBuf, strSetInformIntererror);
					goto setErr_tr069;
				}
			}
		}
	}

#ifdef _TR069_CONREQ_AUTH_SELECT_
	strData = boaGetVar(wp, "disconreqauth", "");
	if ( strData[0] ) {
		cwmp_flag=0;
		vChar=0;

		if( mib_get( CWMP_FLAG2, (void *)&cwmp_flag ) )
		{
			changeflag = 1;

			if(strData[0]=='0')
				cwmp_flag = cwmp_flag & (~CWMP_FLAG2_DIS_CONREQ_AUTH);
			else{
				cwmp_flag = cwmp_flag | CWMP_FLAG2_DIS_CONREQ_AUTH;
				isDisConReqAuth = 1;
			}

			if ( !mib_set( CWMP_FLAG2, (void *)&cwmp_flag)) {
				strcpy(tmpBuf, strSetCWMPFlagerror);
				goto setErr_tr069;
			}
		}else{
			strcpy(tmpBuf, strGetCWMPFlagerror);
			goto setErr_tr069;
		}
	}
#endif

	//if connection reuqest auth is enabled, don't handle conreqname & conreqpw to keep the old values
	if(!isDisConReqAuth)
	{
		strData = boaGetVar(wp, "conreqname", "");
		//if ( strData[0] )
		{
			if ( !mib_set( CWMP_CONREQ_USERNAME, (void *)strData)) {
				strcpy(tmpBuf, strSetConReqUsererror);
				goto setErr_tr069;
			}
		}

		strData = boaGetVar(wp, "conreqpw", "");
		//if ( strData[0] )
		{
			if ( !mib_set( CWMP_CONREQ_PASSWORD, (void *)strData)) {
				strcpy(tmpBuf, strSetConReqPasserror);
				goto setErr_tr069;
			}
		}
	}//if(isDisConReqAuth)

	strData = boaGetVar(wp, "conreqpath", "");
	//if ( strData[0] )
	{
		mib_get( CWMP_CONREQ_PATH, (void *)tmpStr);
		if (strcmp(tmpStr,strData)!=0){
			changeflag = 1;
			if ( !mib_set( CWMP_CONREQ_PATH, (void *)strData)) {
				strcpy(tmpBuf, multilang(LANG_SET_CONNECTION_REQUEST_PATH_ERROR));
				goto setErr_tr069;
			}
		}
	}

	strData = boaGetVar(wp, "conreqport", "");
	if ( strData[0] ) {
		cur_port = atoi(strData);
		mib_get( CWMP_CONREQ_PORT, (void *)&vInt);
		if ( vInt != cur_port ) {
			changeflag = 1;
			if ( !mib_set( CWMP_CONREQ_PORT, (void *)&cur_port)) {
				strcpy(tmpBuf, multilang(LANG_SET_CONNECTION_REQUEST_PORT_ERROR));
				goto setErr_tr069;
			}
		}
	}

/*for debug*/
	strData = boaGetVar(wp, "dbgmsg", "");
	if ( strData[0] ) {
		cwmp_flag=0;
		vChar=0;

		if( mib_get( CWMP_FLAG, (void *)&cwmp_flag ) )
		{
			if(strData[0]=='0')
				cwmp_flag = cwmp_flag & (~CWMP_FLAG_DEBUG_MSG);
			else
				cwmp_flag = cwmp_flag | CWMP_FLAG_DEBUG_MSG;

			if ( !mib_set( CWMP_FLAG, (void *)&cwmp_flag)) {
				strcpy(tmpBuf, strSetCWMPFlagerror);
				goto setErr_tr069;
			}
		}else{
			strcpy(tmpBuf, strGetCWMPFlagerror);
			goto setErr_tr069;
		}
	}

#ifdef _CWMP_WITH_SSL_
	strData = boaGetVar(wp, "certauth", "");
	if ( strData[0] ) {
		cwmp_flag=0;
		vChar=0;

		if( mib_get( CWMP_FLAG, (void *)&cwmp_flag ) )
		{
			if(strData[0]=='0')
				cwmp_flag = cwmp_flag & (~CWMP_FLAG_CERT_AUTH);
			else
				cwmp_flag = cwmp_flag | CWMP_FLAG_CERT_AUTH;

			changeflag = 1;
			if ( !mib_set( CWMP_FLAG, (void *)&cwmp_flag)) {
				strcpy(tmpBuf, strSetCWMPFlagerror);
				goto setErr_tr069;
			}
		}else{
			strcpy(tmpBuf, strGetCWMPFlagerror);
			goto setErr_tr069;
		}
	}
#endif

#ifdef _INFORM_EXT_FOR_X_CT_
	strData = boaGetVar(wp, "ctinformext", "");
	if ( strData[0] ) {
		cwmp_flag=0;
		vChar=0;

		if( mib_get( CWMP_FLAG, (void *)&cwmp_flag ) )
		{
			if(strData[0]=='0')
				cwmp_flag = cwmp_flag & (~CWMP_FLAG_CTINFORMEXT);
			else
				cwmp_flag = cwmp_flag | CWMP_FLAG_CTINFORMEXT;

			if ( !mib_set( CWMP_FLAG, (void *)&cwmp_flag)) {
				strcpy(tmpBuf, strSetCWMPFlagerror);
				goto setErr_tr069;
			}
		}else{
			strcpy(tmpBuf, strGetCWMPFlagerror);
			goto setErr_tr069;
		}
	}
#endif

	strData = boaGetVar(wp, "sendgetrpc", "");
	if ( strData[0] ) {
		cwmp_flag=0;
		vChar=0;

		if( mib_get( CWMP_FLAG, (void *)&cwmp_flag ) )
		{
			if(strData[0]=='0')
				cwmp_flag = cwmp_flag & (~CWMP_FLAG_SENDGETRPC);
			else
				cwmp_flag = cwmp_flag | CWMP_FLAG_SENDGETRPC;

			if ( !mib_set(CWMP_FLAG, (void *)&cwmp_flag)) {
				strcpy(tmpBuf, strSetCWMPFlagerror);
				goto setErr_tr069;
			}
		}else{
			strcpy(tmpBuf, strGetCWMPFlagerror);
			goto setErr_tr069;
		}
	}

	strData = boaGetVar(wp, "skipmreboot", "");
	if ( strData[0] ) {
		cwmp_flag=0;
		vChar=0;

		if( mib_get( CWMP_FLAG, (void *)&cwmp_flag ) )
		{
			if(strData[0]=='0')
				cwmp_flag = cwmp_flag & (~CWMP_FLAG_SKIPMREBOOT);
			else
				cwmp_flag = cwmp_flag | CWMP_FLAG_SKIPMREBOOT;

			if ( !mib_set( CWMP_FLAG, (void *)&cwmp_flag)) {
				strcpy(tmpBuf, strSetCWMPFlagerror);
				goto setErr_tr069;
			}
		}else{
			strcpy(tmpBuf, strGetCWMPFlagerror);
			goto setErr_tr069;
		}
	}

	strData = boaGetVar(wp, "delay", "");
	if ( strData[0] ) {
		cwmp_flag=0;
		vChar=0;

		if( mib_get( CWMP_FLAG, (void *)&cwmp_flag ) )
		{
			if(strData[0]=='0')
				cwmp_flag = cwmp_flag & (~CWMP_FLAG_DELAY);
			else
				cwmp_flag = cwmp_flag | CWMP_FLAG_DELAY;

			if ( !mib_set( CWMP_FLAG, (void *)&cwmp_flag)) {
				strcpy(tmpBuf, strSetCWMPFlagerror);
				goto setErr_tr069;
			}
		}else{
			strcpy(tmpBuf, strGetCWMPFlagerror);
			goto setErr_tr069;
		}
	}
	strData = boaGetVar(wp, "autoexec", "");
	if ( strData[0] ) {
		cwmp_flag=0;
		vChar=0;

		if( mib_get( CWMP_FLAG, (void *)&cwmp_flag ) )
		{
			if(strData[0]=='0') {
				if ( cwmp_flag & CWMP_FLAG_AUTORUN )
					changeflag = 1;

				cwmp_flag = cwmp_flag & (~CWMP_FLAG_AUTORUN);
				cwmp_flag_value = 0;
			}else {
				if ( !(cwmp_flag & CWMP_FLAG_AUTORUN) )
					changeflag = 1;

				cwmp_flag = cwmp_flag | CWMP_FLAG_AUTORUN;
				cwmp_flag_value = 1;
			}

			if ( !mib_set( CWMP_FLAG, (void *)&cwmp_flag)) {
				strcpy(tmpBuf, strSetCWMPFlagerror);
				goto setErr_tr069;
			}
		}else{
			strcpy(tmpBuf, strGetCWMPFlagerror);
			goto setErr_tr069;
		}
	}
/*end for debug*/

	/* EnableCWMP Parameter */
	strData = boaGetVar(wp, "enable_cwmp", "");
	if ( strData[0] )
	{
		cwmp_flag=0;

		if( mib_get( CWMP_FLAG2, (void *)&cwmp_flag ) )
		{
			if(strData[0]=='0')
				cwmp_flag |= CWMP_FLAG2_CWMP_DISABLE;
			else
				cwmp_flag &= ~CWMP_FLAG2_CWMP_DISABLE;

			if( !mib_set( CWMP_FLAG2, (void *)&cwmp_flag))
			{
				strcpy(tmpBuf, strSetCWMPFlagerror);
				goto setErr_tr069;
			}
		}else{
			strcpy(tmpBuf, strGetCWMPFlagerror);
			goto setErr_tr069;
		}
	}	

	strData = boaGetVar(wp, "tr069_itf", "");
	if(strData[0])
	{
		if(!mib_get(CWMP_WAN_INTERFACE, (void *)&pre_tr069_itf))
		{
			strcpy(tmpBuf, multilang(LANG_GET_WAN_INTERFACE_FAILED));
			goto setErr_tr069;
		}

		tr069_itf = atoi(strData);

		if( tr069_itf != pre_tr069_itf )
		{
			if(!mib_set(CWMP_WAN_INTERFACE, (void *)&tr069_itf))
			{
				strcpy(tmpBuf, multilang(LANG_SET_WAN_INTERFACE_FAILED));
				goto setErr_tr069;
			}
			changeflag = 1;
		}
	}

#ifdef CONFIG_CWMP_TR181_SUPPORT
	strData = boaGetVar(wp, "use_tr181", "");
	if ( strData[0] ) {
		cwmp_flag=0;
		vChar=0;

		if( mib_get( CWMP_FLAG2, (void *)&cwmp_flag ) )
		{
			changeflag = 1;

			if(strData[0]=='0')
				cwmp_flag &= ~CWMP_FLAG2_USE_TR181;
			else
				cwmp_flag |= CWMP_FLAG2_USE_TR181;

			if ( !mib_set( CWMP_FLAG2, (void *)&cwmp_flag)) {
				strcpy(tmpBuf, strSetCWMPFlagerror);
				goto setErr_tr069;
			}
		}else{
			strcpy(tmpBuf, strGetCWMPFlagerror);
			goto setErr_tr069;
		}
	}
#endif

end_tr069:
	// Mason Yu
	restart_cwmp_acl();
#ifdef APPLY_CHANGE
	if ( changeflag ) {
		if ( cwmp_flag_value == 0 ) {  // disable TR069
			off_tr069();
		} else {                       // enable TR069
			off_tr069();
/*star:20091229 START restart is too fast, then the new cwmp process will receive the signal SIGTERM, so we sleep 3 secs*/
			sleep(3);
/*star:20091229 END*/
			if (-1==startCWMP()){
				strcpy(tmpBuf, multilang(LANG_START_TR069_FAIL));
				printf("Start tr069 Fail *****\n");
				goto setErr_tr069;
			}
		}
	}
#endif

// Magician: Commit immediately
#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif

	strData = boaGetVar(wp, "submit-url", "");
	OK_MSG(strData);
	return;

setErr_tr069:
	ERR_MSG(tmpBuf);
}



void formTR069CPECert(request * wp, char *path, char *query)
{
	char	*strData;
	char tmpBuf[100];
	FILE	*fp=NULL,*fp_input=NULL;
	unsigned char *buf;
	unsigned int startPos,endPos,nLen,nRead;
	if ((fp = uploadGetCert(wp, &startPos, &endPos)) == NULL)
	{
		strcpy(tmpBuf, strUploaderror);
 		goto setErr_tr069cpe;
 	}

	nLen = endPos - startPos;
	//printf("filesize is %d\n", nLen);
	buf = malloc(nLen+1);
	if (!buf)
	{
		fclose(fp);
		strcpy(tmpBuf, strMallocFail);
 		goto setErr_tr069cpe;
 	}

	fseek(fp, startPos, SEEK_SET);
	nRead = fread((void *)buf, 1, nLen, fp);
	buf[nRead]=0;
	if (nRead != nLen)
 		printf("Read %d bytes, expect %d bytes\n", nRead, nLen);

	//printf("write to %d bytes from %08x\n", nLen, buf);

	fp_input=fopen(CERT_FNAME,"w");
	if (!fp_input){
		free(buf);
		fclose(fp);
		printf("create %s file fail!\n", CERT_FNAME);
 		goto setErr_tr069cpe;
	}
	fprintf(fp_input,buf);
	printf("create file %s\n", CERT_FNAME);
	free(buf);
	fclose(fp_input);

//ccwei_flatfsd
#ifdef CONFIG_USER_FLATFSD_XXX
	if( va_cmd( "/bin/flatfsd",1,1,"-s" ) )
		printf( "[%d]:exec 'flatfsd -s' error!",__FILE__ );
#endif
	off_tr069();

	if (startCWMP() == -1)
	{
		fclose(fp);
		strcpy(tmpBuf, multilang(LANG_START_TR069_FAIL));
		printf("Start tr069 Fail *****\n");
		goto setErr_tr069cpe;
	}

	strData = boaGetVar(wp, "submit-url", "/tr069config.asp");
	UPLOAD_MSG(strData);// display reconnect msg to remote
	fclose(fp);

	return;

setErr_tr069cpe:
	ERR_MSG(tmpBuf);
}


void formTR069CACert(request * wp, char *path, char *query)
{
	char	*strData;
	char tmpBuf[100];
	FILE	*fp=NULL,*fp_input=NULL;
	unsigned char *buf;
	unsigned int startPos,endPos,nLen,nRead;
	if ((fp = uploadGetCert(wp, &startPos, &endPos)) == NULL)
	{
		strcpy(tmpBuf, strUploaderror);
 		goto setErr_tr069ca;
 	}

	nLen = endPos - startPos;
	//printf("filesize is %d\n", nLen);
	buf = malloc(nLen+1);
	if (!buf)
	{
		fclose(fp);
		strcpy(tmpBuf, strMallocFail);
 		goto setErr_tr069ca;
 	}

	fseek(fp, startPos, SEEK_SET);
	nRead = fread((void *)buf, 1, nLen, fp);
	buf[nRead]=0;
	if (nRead != nLen)
 		printf("Read %d bytes, expect %d bytes\n", nRead, nLen);

	//printf("write to %d bytes from %08x\n", nLen, buf);

	fp_input=fopen(CA_FNAME,"w");
	if (!fp_input){
		free(buf);
		fclose(fp);
		printf("create %s file fail!\n", CA_FNAME );
		goto setErr_tr069ca;
	}
	fprintf(fp_input,buf);
	printf("create file %s\n",CA_FNAME);
	free(buf);
	fclose(fp_input);

//ccwei_flatfsd
#ifdef CONFIG_USER_FLATFSD_XXX
	if( va_cmd( "/bin/flatfsd",1,1,"-s" ) )
		printf( "[%d]:exec 'flatfsd -s' error!",__FILE__ );
#endif
	off_tr069();

	if (startCWMP() == -1)
	{
		strcpy(tmpBuf, multilang(LANG_START_TR069_FAIL));
		printf("Start tr069 Fail *****\n");
		fclose(fp);
		goto setErr_tr069ca;
	}
	fclose(fp);
	strData = boaGetVar(wp, "submit-url", "/tr069config.asp");
	UPLOAD_MSG(strData);// display reconnect msg to remote
	return;

setErr_tr069ca:
	ERR_MSG(tmpBuf);
}

/*******************************************************/
/*show extra fileds at tr069config.asp*/
/*******************************************************/
#ifdef _CWMP_WITH_SSL_
int ShowACSCertCPE(request * wp)
{
	int nBytesSent=0;
	unsigned char vChar=0;
	int isEnable=0;

	if ( mib_get( CWMP_FLAG, (void *)&vChar) )
		if ( (vChar & CWMP_FLAG_CERT_AUTH)!=0 )
			isEnable=1;

	nBytesSent += boaWrite(wp, "  <tr>\n");
	nBytesSent += boaWrite(wp, "      <td class=\"table_item\">ACS Certificates CPE:</td>\n");
	nBytesSent += boaWrite(wp, "      <td>\n");
	nBytesSent += boaWrite(wp, "      <input type=\"radio\" name=certauth value=0 %s >%s&nbsp;&nbsp;\n", isEnable==0?"checked":"" , multilang(LANG_NO));
	nBytesSent += boaWrite(wp, "      <input type=\"radio\" name=certauth value=1 %s >%s\n", isEnable==1?"checked":"" , multilang(LANG_YES));
	nBytesSent += boaWrite(wp, "      </td>\n");
	nBytesSent += boaWrite(wp, "  </tr>\n");

//		"\n"), isEnable==0?"checked":"", isEnable==1?"checked":"" );

	return nBytesSent;
}

int ShowMNGCertTable(request * wp)
{
	int nBytesSent=0;
	char buffer[256]="";

	getMIB2Str(CWMP_CERT_PASSWORD,buffer);

	nBytesSent += boaWrite(wp, "\n"
		"<table>\n"
		"  <tr><td><hr size=1 noshade align=top></td></tr>\n"
		"</table>\n"
		"<table>\n"
		"	<tr><th>\n"
		"		%s:\n"
		"	</th></tr>\n"
		"\n", multilang(LANG_CERTIFICATE_MANAGEMENT));

	nBytesSent += boaWrite(wp, "\n"
		"  <tr>\n"
		"      <th>CPE %s:</th>\n"
		"      <td>\n"
		"		<form action=/boaform/formTR069Config method=POST name=\"cpe_passwd\">\n"
		"		<input type=\"text\" name=\"certpw\" size=\"24\" maxlength=\"64\" value=\"%s\">\n"
		"		<input type=\"submit\" value=\"%s\" name=\"CPE_Cert\">\n"
		"		<input type=\"reset\" value=\"%s\" name=\"reset\">\n"
		"		<input type=\"hidden\" value=\"/tr069config.asp\" name=\"submit-url\">\n"
		"		</form>\n"
		"      </td>\n"
		"  </tr>\n"
		"\n", multilang(LANG_CERTIFICATE_PASSWORD), buffer, multilang(LANG_APPLY), multilang(LANG_UNDO));

	nBytesSent += boaWrite(wp, "\n"
		"  <tr>\n"
		"      <th>CPE %s:</th>\n"
		"      <td>\n"
		"           <form action=/boaform/formTR069CPECert method=POST enctype=\"multipart/form-data\" name=\"cpe_cert\">\n"
		"           <input type=\"file\" value=\"%s\" name=\"binary\" size=24>&nbsp;&nbsp;\n"
		"           <input type=\"submit\" value=\"%s\" name=\"load\">\n"
		"           </form>\n"
		"      </td>\n"
		"  </tr>\n"
		"\n", multilang(LANG_CERTIFICATE), multilang(LANG_CHOOSE_FILE), multilang(LANG_UPLOAD));

	nBytesSent += boaWrite(wp, "\n"
		"  <tr>\n"
		"      <th>CA %s:</th>\n"
		"      <td>\n"
		"           <form action=/boaform/formTR069CACert method=POST enctype=\"multipart/form-data\" name=\"ca_cert\">\n"
		"           <input type=\"file\" value=\"%s\" name=\"binary\" size=24>&nbsp;&nbsp;\n"
		"           <input type=\"submit\" value=\"%s\" name=\"load\">\n"
		"           </form>\n"
		"      </td>\n"
		"  </tr>\n"
		"\n", multilang(LANG_CERTIFICATE), multilang(LANG_CHOOSE_FILE), multilang(LANG_UPLOAD));

	nBytesSent += boaWrite(wp, "\n</table>\n\n");

	return nBytesSent;
}
#endif

#ifdef _INFORM_EXT_FOR_X_CT_
int ShowCTInformExt(request * wp)
{
	int nBytesSent=0;
	unsigned char vChar=0;
	int isEnable=0;

	if ( mib_get( CWMP_FLAG, (void *)&vChar) )
		if ( (vChar & CWMP_FLAG_CTINFORMEXT)!=0 )
			isEnable=1;

	nBytesSent += boaWrite(wp, "  <tr>\n");
	nBytesSent += boaWrite(wp, "      <td class=\"table_item\">CT Inform Extension:</td>\n");
	nBytesSent += boaWrite(wp, "      <td>\n");
	nBytesSent += boaWrite(wp, "      <input type=\"radio\" name=ctinformext value=0 %s >Disabled&nbsp;&nbsp;\n", isEnable==0?"checked":"" );
	nBytesSent += boaWrite(wp, "      <input type=\"radio\" name=ctinformext value=1 %s >Enabled\n", isEnable==1?"checked":"" );
	nBytesSent += boaWrite(wp, "      </td>\n");
	nBytesSent += boaWrite(wp, "  </tr>\n");

	return nBytesSent;
}
#endif

#ifdef _TR069_CONREQ_AUTH_SELECT_
int ShowAuthSelect(request * wp)
{
	int nBytesSent=0;
	unsigned int vUInt=0;
	int isDisable=0;

	if ( mib_get( CWMP_FLAG2, (void *)&vUInt) )
		if ( (vUInt & CWMP_FLAG2_DIS_CONREQ_AUTH)!=0 )
			isDisable=1;

	nBytesSent += boaWrite(wp, "  <tr>\n");
#ifndef CONFIG_GENERAL_WEB
	nBytesSent += boaWrite(wp, "      <td class=\"table_item\">%s:</td>\n", multilang(LANG_AUTHENTICATION));
#else
	nBytesSent += boaWrite(wp, "	  <th>%s:</th>\n", multilang(LANG_AUTHENTICATION));
#endif
	nBytesSent += boaWrite(wp, "      <td>\n");
	nBytesSent += boaWrite(wp, "      <input type=\"radio\" name=disconreqauth value=1 %s onClick=\"return authSel()\">%s&nbsp;&nbsp;\n", isDisable==1?"checked":"", multilang(LANG_DISABLED));
	nBytesSent += boaWrite(wp, "      <input type=\"radio\" name=disconreqauth value=0 %s onClick=\"return authSel()\">%s\n", isDisable==0?"checked":"", multilang(LANG_ENABLED));
	nBytesSent += boaWrite(wp, "      </td>\n");
	nBytesSent += boaWrite(wp, "  </tr>\n");

	return nBytesSent;
}
int ShowAuthSelFun(request * wp)
{
	int nBytesSent=0;
	nBytesSent += boaWrite(wp, "function authSel()\n");
	nBytesSent += boaWrite(wp, "{\n");
	nBytesSent += boaWrite(wp, "		if ( document.tr069.disconreqauth[0].checked ) {\n");
	nBytesSent += boaWrite(wp, "			disableTextField(document.tr069.conreqname);\n");
	nBytesSent += boaWrite(wp, "			disableTextField(document.tr069.conreqpw);\n");
	nBytesSent += boaWrite(wp, "		} else {\n");
	nBytesSent += boaWrite(wp, "			enableTextField(document.tr069.conreqname);\n");
	nBytesSent += boaWrite(wp, "			enableTextField(document.tr069.conreqpw);\n");
	nBytesSent += boaWrite(wp, "		}\n");
	nBytesSent += boaWrite(wp, "}\n");
	return nBytesSent;
}
#endif

#ifdef CONFIG_CWMP_TR181_SUPPORT
int ShowDataModels(request * wp)
{
	int nBytesSent=0;
	unsigned int vUInt=0;
	int isEnable=0;

	if ( mib_get( CWMP_FLAG2, (void *)&vUInt) )
		if ( (vUInt & CWMP_FLAG2_USE_TR181)!=0 )
			isEnable=1;

	nBytesSent += boaWrite(wp, "  <tr>\n");
#ifndef CONFIG_GENERAL_WEB
	nBytesSent += boaWrite(wp, "	  <td class=\"table_item\">Root Data Model:</td>\n");
#else
	nBytesSent += boaWrite(wp, "	  <th>Root Data Model:</th>\n");
#endif
	nBytesSent += boaWrite(wp, "	  <td>\n");
	nBytesSent += boaWrite(wp, "	  <input type=\"radio\" name=use_tr181 value=0 %s >TR-098&nbsp;&nbsp;\n", isEnable==0?"checked":"" );
	nBytesSent += boaWrite(wp, "	  <input type=\"radio\" name=use_tr181 value=1 %s >TR-181\n", isEnable==1?"checked":"" );
	nBytesSent += boaWrite(wp, "	  </td>\n");
	nBytesSent += boaWrite(wp, "  </tr>\n");

	return nBytesSent;
}
#endif

int TR069ConPageShow(int eid, request * wp, int argc, char **argv)
{
	int nBytesSent=0;
	char *name;

	if (boaArgs(argc, argv, "%s", &name) < 1) {
		boaError(wp, 400, strArgerror);
		return -1;
	}

#ifdef _CWMP_WITH_SSL_
	if ( !strcmp(name, "ShowACSCertCPE") )
		return ShowACSCertCPE( wp );
	else if ( !strcmp(name, "ShowMNGCertTable") )
		return ShowMNGCertTable( wp );
#endif
#ifdef _INFORM_EXT_FOR_X_CT_
	if ( !strcmp(name, "ShowCTInformExt") )
		return ShowCTInformExt( wp );
#endif
#ifdef _TR069_CONREQ_AUTH_SELECT_
	if ( !strcmp(name, "ShowAuthSelect") )
		return ShowAuthSelect( wp );
	if ( !strcmp(name, "ShowAuthSelFun") )
		return ShowAuthSelFun( wp );
	if ( !strcmp(name, "DisConReqName") ||
             !strcmp(name, "DisConReqPwd")   )
        {
		unsigned int vUInt=0;
		int isDisable=0;

		if ( mib_get( CWMP_FLAG2, (void *)&vUInt) )
			if ( (vUInt & CWMP_FLAG2_DIS_CONREQ_AUTH)!=0 )
				isDisable=1;
		if(isDisable) return boaWrite(wp, "disabled");
	}
#endif

#ifdef CONFIG_CWMP_TR181_SUPPORT
	if(strcmp(name, "ShowDataModels") == 0)
		return ShowDataModels(wp);
#endif

	return nBytesSent;
}

