
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
#include <net/if.h>


/*-- Local inlcude files --*/
#include "../webs.h"
#include "webform.h"
#include "mib.h"
#include "multilang.h"
#include "fmcatv.h"



int fmcatv_checkWrite(int eid, request * wp, int argc, char **argv)
{	

	
	char *name;	char tmpBuf[100];	
	char data_tmp[100]={0};	
	char passwd[100]={0};

	
	if (boaArgs(argc, argv, "%s", &name) < 1)    
	{   		
		boaError(wp, 400, "Insufficient args\n");		
		printf( "%s: error, line=%d\n", __FUNCTION__, __LINE__ );   		
		return -1;   	
	}	
	
	if(!strcmp(name, "uart_read")) 	
	{
		/*第一步：从串口中取得数据*/
		/*第二步：保存mib中*/
		main_uart(UART_READ,0,0);		 
	}


	/*第三步：取得mib中的数据到页面*/
	if(!strcmp(name, "dev_name")) 	  //名字
	{		
		printf("[%s:%d] name =%s\n",__func__,__LINE__,name);
		#if 0		
		if(!mib_get(MIB_CATV_DEV_NAME,  (void *)loid))		
		{	  		
			sprintf(tmpBuf, "%s (EPON LOID)",Tget_mib_error);			
			goto setErr;		
		}	
		#endif
		
		boaWrite(wp, "%s", "XF_JZSB_RT990");		
		return 0;	
	}
	
	if(!strcmp(name, "state"))	 //MIB_CATV_STATE  工作状态
	{
		#if 0
		printf("[%s:%d] name =%s\n",__func__,__LINE__,name);
		if(!mib_get(MIB_CATV_STATE,	(void *)data_tmp))		
		{			
			sprintf(tmpBuf, "%s (EPON LOID)",Tget_mib_error);			
			goto setErr;		
		}	
		printf("\n data_tmp = %s \n",data_tmp);
		boaWrite(wp, "%s", data_tmp);		
		#endif 		
		boaWrite(wp, "%s", "Normal");
		return 0;	
	}

	if(!strcmp(name, "receive_power"))	 //输入光功率
	{
		
		printf("[%s:%d] name =%s\n",__func__,__LINE__,name);
		if(!mib_get(MIB_CATV_RX_POWER,	(void *)data_tmp))		
		{			
			sprintf(tmpBuf, "%s (MIB_CATV_RX_POWER)",Tget_mib_error);			
			goto setErr;		
		}	
		printf("\n data_tmp = %s \n",data_tmp);
		boaWrite(wp, "%s", data_tmp);		
		return 0;	
	}	
	
	if(!strcmp(name, "transmit_power"))	 //输出光功率
	{
		
		printf("[%s:%d] name =%s\n",__func__,__LINE__,name);
		if(!mib_get(MIB_CATV_TX_POWER,	(void *)data_tmp))		
		{			
			sprintf(tmpBuf, "%s (MIB_CATV_TX_POWER)",Tget_mib_error);			
			goto setErr;		
		}	
		printf("\n data_tmp = %s \n",data_tmp);
		boaWrite(wp, "%s", data_tmp);		
		return 0;	
	}	

	if(!strcmp(name, "RF_power"))	  //输出电平
	{
		
		printf("[%s:%d] name =%s\n",__func__,__LINE__,name);
		if(!mib_get(MIB_CATV_DC_VCC,	(void *)data_tmp))		
		{			
			sprintf(tmpBuf, "%s (MIB_CATV_DC_VCC)",Tget_mib_error);			
			goto setErr;		
		}	
		printf("\n data_tmp = %s \n",data_tmp);
		boaWrite(wp, "%s", data_tmp);		
		return 0;	
	}	


	if(!strcmp(name, "temperature"))	 //温度
	{
		
		printf("[%s:%d] name =%s\n",__func__,__LINE__,name);
		if(!mib_get(MIB_CATV_TEMPERATURE,	(void *)data_tmp))		
		{			
			sprintf(tmpBuf, "%s (MIB_CATV_TEMPERATURE)",Tget_mib_error);			
			goto setErr;		
		}	
		printf("\n data_tmp = %s \n",data_tmp);
		boaWrite(wp, "%s", data_tmp);		
		return 0;	
	}	

	if(!strcmp(name, "work_mode"))	  //工作模式
	{
		
		printf("[%s:%d] name =%s\n",__func__,__LINE__,name);
		if(!mib_get(MIB_CATV_STATE,	(void *)data_tmp))		
		{			
			sprintf(tmpBuf, "%s (MIB_CATV_STATE)",Tget_mib_error);			
			goto setErr;		
		}	
		printf("\n data_tmp = %s \n",data_tmp);
		boaWrite(wp, "%s", data_tmp);		
		return 0;	
	}	

	if(!strcmp(name, "RF_att_set"))	  //输出电平衰减设置
	{
		
		printf("[%s:%d] name =%s\n",__func__,__LINE__,name);
		if(!mib_get(MIB_CATV_GAIN_CONTROL,	(void *)data_tmp))		
		{			
			sprintf(tmpBuf, "%s (MIB_CATV_GAIN_CONTROL)",Tget_mib_error);			
			goto setErr;		
		}	
		printf("\n data_tmp = %s \n",data_tmp);
		boaWrite(wp, "%s", data_tmp);		
		return 0;	
	}	

	if(!strcmp(name, "RF_switch"))	//射频输出开关 设置
	{
		
		printf("[%s:%d] name =%s\n",__func__,__LINE__,name);
		if(!mib_get(MIB_CATV_RF_ONOFF,	(void *)data_tmp))		
		{			
			sprintf(tmpBuf, "%s (MIB_CATV_RF_ONOFF)",Tget_mib_error);			
			goto setErr;		
		}	
		printf("\n data_tmp = %s \n",data_tmp);
		boaWrite(wp, "%s", data_tmp);		
		return 0;	
	}	
	if(!strcmp(name, "hd_version"))	  //硬件版本
	{
		#if 0
		printf("[%s:%d] name =%s\n",__func__,__LINE__,name);
		if(!mib_get(MIB_CATV_HARDWAREVERSION,	(void *)data_tmp))		
		{			
			sprintf(tmpBuf, "%s (EPON LOID)",Tget_mib_error);			
			goto setErr;		
		}	
		printf("\n data_tmp = %s \n",data_tmp);
		#endif 
		boaWrite(wp, "%s", "swV1.0");		
		return 0;	
	}	
	if(!strcmp(name, "sw_version"))	  //软件版本
	{
		
		printf("[%s:%d] name =%s\n",__func__,__LINE__,name);
		#if 0
		if(!mib_get(MIB_CATV_SOFTWAREVERSION,	(void *)data_tmp))		
		{			
			sprintf(tmpBuf, "%s (EPON LOID)",Tget_mib_error);			
			goto setErr;		
		}	
		printf("\n data_tmp = %s \n",data_tmp);
		boaWrite(wp, "%s", data_tmp);	
		#endif 
		boaWrite(wp, "%s", "hwV1.0");	
		return 0;	
	}

	return 0;
	
setErr:	
		ERR_MSG(tmpBuf);	
		return -1;
}

void formCatv(request * wp, char *path, char *query)
{
	char *strData;
	char *submitUrl;
	char *sWanName;
	int IgmpVlan;
	int IfIndex;
	int ifidx, entryNum, i, chainNum=-1;
	char tmpBuf[100];	
	MIB_CE_ATM_VC_T entry;	


	
	/* 第一步：发送给串口生效 */

	int RF_att_set_value= 0;
	int	RF_switch_value=0;

	strData = boaGetVar(wp, "RF_att_set", "");
	if ( strData[0] )	
	{		
		RF_att_set_value = atoi(strData);

		#if UART_DEBUG
		printf("===>[%s:%d] RF_att_set_value=%s\n",__func__,__LINE__,strData);		
		printf("\n RF_att_set_value = %d",RF_att_set_value);
		#endif 
		#if 0
		if(!mib_set(MIB_CATV_RF_ATT_SET, strData))		
		{			
			sprintf(tmpBuf, "%s (EPON LOID)",Tset_mib_error);			
			goto setErr;		
		}	
		#endif 
	}

	strData = boaGetVar(wp, "RF_switch", "");
	if ( strData[0] )	
	{		
		RF_switch_value = atoi(strData);
		if(RF_switch_value > 0)
			RF_switch_value = 3;
		#if UART_DEBUG
		printf("===>[%s:%d] RF_switch_value=%s\n",__func__,__LINE__,strData);	
		printf("\n RF_switch_value = %d",RF_switch_value);
		#endif 
		#if 0
		if(!mib_set(MIB_CATV_RF_ONOFF, strData))		
		{			
			sprintf(tmpBuf, "%s (EPON LOID)",Tset_mib_error);			
			goto setErr;		
	
		}	
		#endif 
	}
	main_uart(UART_WRITE,RF_att_set_value,RF_switch_value);	

#if 0
	strData = boaGetVar(wp, "receive_power", "");
	if ( strData[0] )	
	{		
		printf("===>[%s:%d] fmcatv=%s\n",__func__,__LINE__,strData);		
		if(!mib_set(MIB_CATV_RX_POWER, strData))		
		{			
			sprintf(tmpBuf, "%s (EPON LOID)",Tset_mib_error);			
			goto setErr;		
		}	
	}


	strData = boaGetVar(wp, "transmit_power", "");
	if ( strData[0] )	
	{		
		printf("===>[%s:%d] fmcatv=%s\n",__func__,__LINE__,strData);		
		if(!mib_set(MIB_CATV_TX_POWER, strData))		
		{			
			sprintf(tmpBuf, "%s (EPON LOID)",Tset_mib_error);			
			goto setErr;		
		}	
	}
	
	strData = boaGetVar(wp, "RF_power", "");
	if ( strData[0] )	
	{		
		printf("===>[%s:%d] fmcatv=%s\n",__func__,__LINE__,strData);		
		if(!mib_set(MIB_CATV_DC_VCC, strData))		
		{			
			sprintf(tmpBuf, "%s (EPON LOID)",Tset_mib_error);			
			goto setErr;		
		}	
	}


	strData = boaGetVar(wp, "temperature", "");
	if ( strData[0] )	
	{		
		printf("===>[%s:%d] fmcatv=%s\n",__func__,__LINE__,strData);		
		if(!mib_set(MIB_CATV_TEMPERATURE, strData))		
		{			
			sprintf(tmpBuf, "%s (EPON LOID)",Tset_mib_error);			
			goto setErr;		
		}	
	}


	strData = boaGetVar(wp, "work_mode", "");
	if ( strData[0] )	
	{		
		printf("===>[%s:%d] fmcatv=%s\n",__func__,__LINE__,strData);		
		if(!mib_set(MIB_CATV_STATE, strData))		
		{			
			sprintf(tmpBuf, "%s (EPON LOID)",Tset_mib_error);			
			goto setErr;		
		}	
	}

	strData = boaGetVar(wp, "RF_att_set", "");
	if ( strData[0] )	
	{		
		printf("===>[%s:%d] fmcatv=%s\n",__func__,__LINE__,strData);		
		if(!mib_set(MIB_CATV_RF_ATT_SET, strData))		
		{			
			sprintf(tmpBuf, "%s (EPON LOID)",Tset_mib_error);			
			goto setErr;		
		}	
	}


	strData = boaGetVar(wp, "RF_switch", "");
	if ( strData[0] )	
	{		
		printf("===>[%s:%d] fmcatv=%s\n",__func__,__LINE__,strData);		
		if(!mib_set(MIB_CATV_RF_ONOFF, strData))		
		{			
			sprintf(tmpBuf, "%s (EPON LOID)",Tset_mib_error);			
			goto setErr;		
		}	
	}
	strData = boaGetVar(wp, "hd_version", "");
	if ( strData[0] )	
	{		
		printf("===>[%s:%d] fmcatv=%s\n",__func__,__LINE__,strData);		
		if(!mib_set(MIB_CATV_HARDWAREVERSION, strData))		
		{			
			sprintf(tmpBuf, "%s (EPON LOID)",Tset_mib_error);			
			goto setErr;		
		}	
	}


	
	strData = boaGetVar(wp, "sf_version", "");
	if ( strData[0] )	
	{		
		printf("===>[%s:%d] fmcatv=%s\n",__func__,__LINE__,strData);		
		if(!mib_set(MIB_CATV_SOFTWAREVERSION, strData))		
		{			
			sprintf(tmpBuf, "%s (EPON LOID)",Tset_mib_error);			
			goto setErr;		
		}	
	}
#endif 
	
	
#if 0	
	ifidx = atoi(strData);
	strData = boaGetVar(wp, "mVlan", "");
	IgmpVlan = atoi(strData);
	sWanName = boaGetVar(wp, "WanName", "");
	IfIndex = getIfIndexByName(sWanName);


	entryNum = mib_chain_total(MIB_ATM_VC_TBL);
	for (i = 0; i < entryNum; i++) {
		if (!mib_chain_get(MIB_ATM_VC_TBL, i, &entry)) {
			printf("get MIB chain error\n");
			return;
		}
		if(IfIndex == entry.ifIndex){
			printf("%s-%d i=%x\n",__func__,__LINE__,i);
			chainNum = i;
			break;
		}
	}
	entry.mVid = IgmpVlan;
#endif 

#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif
#if 0
	back2add: /*mean user cancel modify, refresh web page again!*/
	submitUrl = boaGetVar(wp, "submit-url", "");   // hidden page
	if (submitUrl[0])
		boaRedirect(wp, submitUrl);
	else
		boaDone(wp, 200);
	return;


	setErr: 
			ERR_MSG(tmpBuf);


	strData = boaGetVar(wp, "submit-url", "");	
	OK_MSG(strData);		
	return;
#else 

setErr:	
	strData = boaGetVar(wp, "submit-url", "");	
	OK_MSG(strData);	

#endif 


}
//#endif



