#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <linux/config.h>

#include "fmdefs.h"
#include "mib.h"
#include "utility.h"


int initPageStorage(int eid, request * wp, int argc, char ** argv)
{
	//FTP服务器:
	unsigned char	ftpEnable = 0;
	int				errcode = 1, lineno = __LINE__;
#ifdef CONFIG_USER_FTPD_FTPD
	int cnt;
	MIB_CE_ACC_T accEntry={0};
	int acc_nums=mib_chain_total(MIB_ACC_TBL);
#else
	unsigned char ftp_enable = 0;
#endif

	_TRACE_CALL;

	/************Place your code here, do what you want to do! ************/
	//mib_get(MIB_BFTPD_ENABLE, (void *) &ftpEnable);
#ifdef CONFIG_USER_FTPD_FTPD
	for(cnt=0; cnt < acc_nums; cnt++)
	{
		memset(&accEntry, 0, sizeof(accEntry));
		mib_chain_get(MIB_ACC_TBL, cnt, (void*)&accEntry);
		if(accEntry.ftp & 0x2){//lan ftp enabled
			ftpEnable = 1;
			break;
		}
	}
#else
#ifdef FTP_SERVER_INTERGRATION
	mib_get(MIB_FTP_ENABLE, (void *)&ftp_enable);
#else
	mib_get(MIB_VSFTP_ENABLE, (void *)&ftp_enable);
#endif
	if (ftp_enable & 1)
		ftpEnable = 1;
#endif
	/************Place your code here, do what you want to do! ************/

	_PUT_BOOL(ftpEnable);

check_err:
	_TRACE_LEAVEL;
	return 0;
}

//网页提交action函数:
static unsigned char base64chars[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                              "abcdefghijklmnopqrstuvwxyz0123456789+/=";

static int base64charsIndex(unsigned char c){
	int i=0;
	while(i<65){
		if(base64chars[i]==c)
			return i;
		i++;
	}
}

void data_base64decode(unsigned char *input, unsigned char *output)
{
	unsigned char chr1, chr2, chr3;
	unsigned char enc1, enc2, enc3, enc4;
	int i=0, j=0, len;
	
	if(input == NULL || input[0] == 0 || output == NULL)
		return;
	
	len = strlen(input);
	if(len < 4) return ;

	for (i = 0; i < len - 3; i += 4) {
		enc1 = base64charsIndex(input[i+0]);
		enc2 = base64charsIndex(input[i+1]);
		enc3 = base64charsIndex(input[i+2]);
		enc4 = base64charsIndex(input[i+3]);

		output[j++] = ((enc1 << 2) | (enc2 >> 4));
		if (input[i+2] != base64chars[64])
			output[j++] = (((enc2 << 4) & 0xF0) | ((enc3 >> 2) & 0x0F));
		if (input[i+3] != base64chars[64])
			output [j++] = (((enc3 << 6) & 0xC0) | enc4);
	}
}

void  data_base64encode(unsigned char *input, unsigned char *output)
{
	unsigned char chr1, chr2, chr3;
	unsigned char enc1, enc2, enc3, enc4;
	int i=0, j=0, len=strlen(input);

	if(input == NULL || input[0] == 0 || output == NULL)
		return;

	for (i = 0; i <= len - 3; i += 3)
	{
		output[j++] = base64chars[(input[i] >> 2)];
		output[j++] = base64chars[((input[i] & 3) << 4) | (input[i+1] >> 4)];
		output[j++] = base64chars[((input[i+1] & 15) << 2) | (input[i+2] >> 6)];
		output[j++] = base64chars[input[i+2] & 63];
	}

	if (len % 3 == 2)
	{
		output[j++] = base64chars[(input[i] >> 2)];
		output[j++] = base64chars[((input[i] & 3) << 4) | (input[i+1] >> 4)];
		output[j++] = base64chars[((input[i+1] & 15) << 2)];
		output[j++] = base64chars[64];
	}
	else if (len % 3 == 1)
	{
		output[j++] = base64chars[(input[i] >> 2)];
		output[j++] = base64chars[((input[i] & 3) << 4)];
		output[j++] = base64chars[64];
		output[j++] = base64chars[64];
	}
}

int isUsbStoragePlugedIn(char *path)
{
	if(!path)
		return 0;
	
	if (!access(path, F_OK))
	{
		return 1;
	}

	return 0;
}

void formStorage(request * wp, char *path, char *query)
{
	char *strData;
	char tmpBuf[256] = {0};

	//存放目录:
	char *			psaveDir = NULL;
	char				argPath[64];
	//用户名:
	char			user[32];
	char				arguser[64];
	//密码:
	char			passwd[32];
	char				argpasswd[64];
	//端口:
	unsigned short	port = 0;
	char portstr[32]={0};
	//远程URL:
	char *			prmtURL = NULL;
	char*			stemp = "";
	int				errcode = 1, lineno = __LINE__;
	char ftpurl[136];
#if !defined(CONFIG_CMCC) && !defined(CONFIG_CU)
	char			storage_encode[32];
#endif
	char			devName[64] = {0};
	char			storagePath[128] = {0};

	_TRACE_CALL;

	user[0] = passwd[0] = 0;
	strcpy(argPath, "path=/mnt/");
	strcpy(arguser, "user=");
	strcpy(argpasswd, "passwd=");

	_GET_PSTR(saveDir, _NEED);
	strcat(argPath, psaveDir);

	_GET_STR(user, _OPT);
	if(user[0])
	{
		strcat(arguser, user);
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		_GET_STR(passwd, _OPT);
#else
		_GET_STR(storage_encode, _OPT);
		memset(passwd, 0, sizeof(passwd)); // data_base64decode does not pad NULL for us.
		data_base64decode(storage_encode, passwd);
#endif
		if(passwd[0])strcat(argpasswd, passwd);
	}

	_GET_INT(port, _OPT);
	snprintf(portstr,sizeof(portstr),"port=%d",port);
	//if(port == 0){lineno = __LINE__; goto check_err;}

	_GET_PSTR(rmtURL, _NEED);

	if( strstr(prmtURL, "ftp://") != prmtURL )
		sprintf(ftpurl, "ftp://%s", prmtURL);
	else
		sprintf(ftpurl, "%s", prmtURL);

	/************Place your code here, do what you want to do! ************/
	//call_cmd("/bin/wget_manage", 4, 0, arguser, argpasswd, argPath, prmtURL);
	errcode = call_cmd("/bin/wget_manage", 5, 1, arguser, argpasswd, argPath, ftpurl, portstr);
	/************Place your code here, do what you want to do! ************/

	sscanf(psaveDir, "%[^/]", devName);
	sprintf(storagePath, "/mnt/%s", devName);
	
	if(errcode == 0 && isUsbStoragePlugedIn(storagePath))
	{
		strData = boaGetVar(wp,"submit-url","");   // hidden page
		strcpy(tmpBuf,"下载成功！");
		OK_MSG1(tmpBuf, strData);
	}
	else
	{
		strcpy(tmpBuf,"下载失败！");
		ERR_MSG(tmpBuf);
	}
check_err:
	_TRACE_LEAVEL;
	return;
}

