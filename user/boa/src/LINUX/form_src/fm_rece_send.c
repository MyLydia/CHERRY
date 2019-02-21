
//串口相关的头文件  
#include<stdio.h>      /*标准输入输出定义*/  
#include<stdlib.h>     /*标准函数库定义*/  
#include<unistd.h>     /*Unix 标准函数定义*/  
#include<sys/types.h>   
#include<sys/stat.h>     
#include<fcntl.h>      /*文件控制定义*/  
#include<termios.h>    /*PPSIX 终端控制定义*/  
#include<errno.h>      /*错误号定义*/  
#include<string.h>  


/*-- Local inlcude files --*/
#include "../webs.h"
#include "webform.h"
#include "mib.h"
#include "multilang.h"

#include "fmcatv.h"



   


int fd;  
int len;						  
int i;
unsigned char rcv_buf[30]; 
unsigned char send_buf_16[6]={0x7e,0x01,0x30,0xa5,0x1,0x01};


unsigned char send_buf_look_cmd[6]={0x7e,0x01,0x35,0xA5,0x0,0xa5};  //查看catv实时参数

unsigned char send_buf_catv_open_cmd[6]={0x7e,0x01,0x51,0xA5,0x1,0x0};  //查看catv开 

unsigned char send_buf_catv_rf_set_cmd[6]={0x7e,0x01,0x61,0xA5,0x1,0xa};  //catv增益设置
unsigned char send_buf_catv_rf_look_cmd[6]={0x7e,0x01,0x61,0xA5,0x0,0xa};	//catv增益查询

unsigned char send_buf_catv_read_result[8]={0};//查询所有结果存放
unsigned char send_buf_catv_read_rf_result[1]={0};//查询增益结果存放




void display_chars(unsigned char * char_buf,int char_len)   
{
		#ifdef UART_DEBUG
		printf("\n display chars data is  ");
		int ii =0;
		for(; ii<char_len ; ii++ )
		{		
			printf("0x%x ",char_buf[ii]);
		}
		
		printf("\n");
		#endif
}
		
/******************************************************************* 
* 名称：            uart_open 
* 功能：            打开串口并返回串口设备文件描述 
* 入口参数：        fd    :文件描述符     port :串口号(ttyS0,ttyS1,ttyS2) 
* 出口参数：        正确返回为1，错误返回为0 
*******************************************************************/  
int uart_open(int fd,char* port)  
{  
     
	fd = open( port, O_RDWR|O_NOCTTY|O_NDELAY);  
	if (FALSE == fd)  
	{  
		perror("Can't Open Serial Port");  
		return(FALSE);  
	}  
	//恢复串口为阻塞状态                                 
	if(fcntl(fd, F_SETFL, 0) < 0)  
	{  
		printf("fcntl failed!\n");  
		return(FALSE);  
	}       
	else  
	{  
		printf("fcntl=%d\n",fcntl(fd, F_SETFL,0));  
	}  
	//测试是否为终端设备      
	if(0 == isatty(STDIN_FILENO))  
	{  
		printf("standard input is not a terminal device\n");  
		//return(FALSE);  
	}  
	else  
	{  
		printf("isatty success!\n");  
	}                
	printf("fd->open=%d\n",fd);  
	return fd;  
}  
/******************************************************************* 
* 名称：                uart_close 
* 功能：                关闭串口并返回串口设备文件描述 
* 入口参数：        fd    :文件描述符     port :串口号(ttyS0,ttyS1,ttyS2) 
* 出口参数：        void 
*******************************************************************/  
   
void uart_close(int fd)  
{  
	close(fd);  
}  
   
/******************************************************************* 
* 名称：            uart_set 
* 功能：            设置串口数据位，停止位和效验位 
* 入口参数：        fd        串口文件描述符 
*                   speed     串口速度 
*                   flow_ctrl   数据流控制 
*                   databits   数据位   取值为 7 或者8 
*                   stopbits   停止位   取值为 1 或者2 
*                   parity     效验类型 取值为N,E,O,,S 
*出口参数：         正确返回为1，错误返回为0 
*******************************************************************/  
int uart_set(int fd,int speed,int flow_ctrl,int databits,int stopbits,int parity)  
{  
     
	int   i;  
	int   status;  
	int   speed_arr[] = { B115200, B19200, B9600, B4800, B2400, B1200, B300};  
	int   name_arr[] = {115200,  19200,  9600,  4800,  2400,  1200,  300};  
           
	struct termios options;  
     
	/*tcgetattr(fd,&options)得到与fd指向对象的相关参数，并将它们保存于options,该函数还可以测试配置是否正确，该串口是否可用等。若调用成功，函数返回值为0，若调用失败，函数返回值为1. 
    */  
	if( tcgetattr( fd,&options)  !=  0)  
	{  
		perror("SetupSerial 1");      
		return(FALSE);   
	}  
    
    //设置串口输入波特率和输出波特率  
	for ( i= 0;  i < sizeof(speed_arr) / sizeof(int);  i++)  
	{  
		if  (speed == name_arr[i])  
		{               
			cfsetispeed(&options, speed_arr[i]);   
			cfsetospeed(&options, speed_arr[i]);    
		}  
	}       
     
    //修改控制模式，保证程序不会占用串口  
    options.c_cflag |= CLOCAL;  
    //修改控制模式，使得能够从串口中读取输入数据  
    options.c_cflag |= CREAD;  
    
    //设置数据流控制  
    switch(flow_ctrl)  
    {  
        
		case 0 ://不使用流控制  
              options.c_cflag &= ~CRTSCTS;  
              break;     
        
		case 1 ://使用硬件流控制  
              options.c_cflag |= CRTSCTS;  
              break;  
		case 2 ://使用软件流控制  
              options.c_cflag |= IXON | IXOFF | IXANY;  
              break;  
    }  
    //设置数据位  
    //屏蔽其他标志位  
    options.c_cflag &= ~CSIZE;  
    switch (databits)  
    {    
		case 5:  
              options.c_cflag |= CS5;  
              break;  
		case 6:  
              options.c_cflag |= CS6;  
              break;  
		case 7:      
              options.c_cflag |= CS7;  
              break;  
		case 8:      
              options.c_cflag |= CS8;  
              break;    
		default:     
              fprintf(stderr,"Unsupported data size\n");  
              return (FALSE);   
    }  
    //设置校验位  
    switch (parity)  
    {    
		case 'n':  
		case 'N': //无奇偶校验位。  
                 options.c_cflag &= ~PARENB;   
                 options.c_iflag &= ~INPCK;      
                 break;   
		case 'o':    
		case 'O'://设置为奇校验      
                 options.c_cflag |= (PARODD | PARENB);   
                 options.c_iflag |= INPCK;               
                 break;   
		case 'e':   
		case 'E'://设置为偶校验    
                 options.c_cflag |= PARENB;         
                 options.c_cflag &= ~PARODD;         
                 options.c_iflag |= INPCK;        
                 break;  
		case 's':  
		case 'S': //设置为空格   
                 options.c_cflag &= ~PARENB;  
                 options.c_cflag &= ~CSTOPB;  
                 break;   
        default:    
                 fprintf(stderr,"Unsupported parity\n");      
                 return (FALSE);   
    }   
    // 设置停止位   
    switch (stopbits)  
    {    
		case 1:     
                 options.c_cflag &= ~CSTOPB; break;   
		case 2:     
                 options.c_cflag |= CSTOPB; break;  
		default:     
                       fprintf(stderr,"Unsupported stop bits\n");   
                       return (FALSE);  
    }  
     
	//修改输出模式，原始数据输出  
	options.c_oflag &= ~OPOST;  
    
	options.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);  
	//options.c_lflag &= ~(ISIG | ICANON);  
     
    //设置等待时间和最小接收字符  
    options.c_cc[VTIME] = 1; /* 读取一个字符等待1*(1/10)s */    
    options.c_cc[VMIN] = 1; /* 读取字符的最少个数为1 */  
     
    //如果发生数据溢出，接收数据，但是不再读取 刷新收到的数据但是不读  
    tcflush(fd,TCIFLUSH);  
     
    //激活配置 (将修改后的termios数据设置到串口中）  
    if (tcsetattr(fd,TCSANOW,&options) != 0)    
	{  
		perror("com set error!\n");    
		return (FALSE);   
	}  
    return (TRUE);   
}  
/******************************************************************* 
* 名称：        uart_init() 
* 功能：        串口初始化 
* 入口参数：    fd: 文件描述符    
*               speed  :  串口速度 
*                         flow_ctrl  数据流控制 
*               databits  数据位   取值为 7 或者8 
*                         stopbits   停止位   取值为 1 或者2 
*                         parity     效验类型 取值为N,E,O,,S 
*                       
* 出口参数：        正确返回为1，错误返回为0 
*******************************************************************/  
int uart_init(int fd, int speed,int flow_ctrl,int databits,int stopbits,int parity)  
{  
    int err;  
    //设置串口数据帧格式  
    if (uart_set(fd,19200,0,8,1,'N') == FALSE)  
	{                                                           
		return FALSE;  
	}  
    else  
	{  
		return  TRUE;  
	}  
}  


/******************************************************************* 
* 名称：                  uart_recv 
* 功能：                接收串口数据 
* 入口参数：        fd                  :文件描述符     
*                              rcv_buf     :接收串口中数据存入rcv_buf缓冲区中 
*                              data_len    :一帧数据的长度 
* 出口参数：        正确返回为1，错误返回为0 
*******************************************************************/  
int uart_recv(int fd, unsigned char *rcv_buf,int data_len)  
{  
	int len,fs_sel;  
    fd_set fs_read;  
     
    struct timeval time;  
     
    FD_ZERO(&fs_read);  
    FD_SET(fd,&fs_read);  
     
    time.tv_sec = 10;  
    time.tv_usec = 0;  
     
    //使用select实现串口的多路通信  
    fs_sel = select(fd+1,&fs_read,NULL,NULL,&time);  
    printf("fs_sel = %d\n",fs_sel);  
    if(fs_sel)  
	{  
		len = read(fd,rcv_buf,data_len);  
		printf("I am right!(version1.2) len = %d fs_sel = %d\n",len,fs_sel);  
		return len;  
	}  
    else  
	{  
		printf("Sorry,I am wrong!");  
		return FALSE;  
	}       
}  
/******************************************************************** 
* 名称：                  uart_send 
* 功能：                发送数据 
* 入口参数：        fd                  :文件描述符     
*                              send_buf    :存放串口发送数据 
*                              data_len    :一帧数据的个数 
* 出口参数：        正确返回为1，错误返回为0 
*******************************************************************/  
int uart_send(int fd, unsigned char *send_buf,int data_len)  
{  
    int len = 0;  
     
    len = write(fd,send_buf,data_len);   
    if (len == data_len )  
	{  
		display_chars(send_buf,data_len);
		return len;  
	}       
    else     
	{  
                 
		tcflush(fd,TCOFLUSH);  
		return FALSE;  
	}    
	
}	


void uart_read()
{	
	if(1) 		
	{  
		for(i = 0;i < 1;i++)  
		{  
 			len = uart_send(fd,send_buf_16,6);  
			//len = uart_Send(fd,send_buf,10); 
			if(len > 0)  
				printf(" %d time send %d data successful\n",i,len);  
			else  
				printf("send data failed!\n");  
                            
			sleep(2);  
		}  
		printf("\n now rece chars:  \n");
		
		for(i = 0; i < 1;i++) 
		{    
			len = uart_recv(fd, rcv_buf,99);  
  			if(len > 0)  
			{  
				rcv_buf[len] = '\0';  
				printf("receive data is %s\n",rcv_buf);  
				printf("len = %d\n",len);  
				display_chars(rcv_buf,len);
				memcpy(send_buf_catv_read_result,&rcv_buf[5],8);
			}  
			else  
			{  
				printf("cannot receive data\n");  
			}
			 
		}              
		  
	} 
	
}

void save_mib(void)
{

    char rx_power_buffer[32]={0};
    char tx_power_buffer[32]={0};
    char gain_control_buffer[32];
	char tmpbuferr[100];
    //rx_power

	char tmp_buf[30]={0};
	
	#if UART_DEBUG
	printf("\n send_buf_catv_read_result[0] = %x\n",send_buf_catv_read_result[0]);
	printf("\n send_buf_catv_read_result[1] = %x\n",send_buf_catv_read_result[1]);
	printf("\n send_buf_catv_read_result[2] = %x\n",send_buf_catv_read_result[2]);
	printf("\n send_buf_catv_read_result[3] = %x\n",send_buf_catv_read_result[3]);
	printf("\n send_buf_catv_read_result[4] = %x\n",send_buf_catv_read_result[4]);
	printf("\n send_buf_catv_read_result[5] = %x\n",send_buf_catv_read_result[5]);
	printf("\n send_buf_catv_read_result[6] = %x\n",send_buf_catv_read_result[6]);
	printf("\n send_buf_catv_read_result[7] = %x\n",send_buf_catv_read_result[7]);
	#endif 


	memset(tmp_buf,0,30);	
	sprintf(tmp_buf,"-%.1f dB",(float)((0xff&(~((send_buf_catv_read_result[0]<<8)|send_buf_catv_read_result[1]))+1)*10)/100);
	if ( tmp_buf[0] )
	{
		#if UART_DEBUG
		printf("===>[%s:%d] fmcatv=%s\n",__func__,__LINE__,tmp_buf);	
		#endif 
		if(!mib_set(MIB_CATV_RX_POWER, tmp_buf))		
		{			
			sprintf(tmpbuferr, "%s (MIB_CATV_RX_POWER)",Tset_mib_error);	
			printf("tmpbuferr = %s",tmpbuferr );					
		}		
	}
	
	
	memset(tmp_buf,0,30);
	sprintf(tmp_buf,"-%.1f dB",(float)((0xff&(~((send_buf_catv_read_result[2]<<8)|send_buf_catv_read_result[3]))+1)*10)/100);
	if ( tmp_buf[0] )
	{
		#if UART_DEBUG
		printf("===>[%s:%d] fmcatv=%s\n",__func__,__LINE__,tmp_buf);	
		#endif 
		if(!mib_set(MIB_CATV_TX_POWER, tmp_buf))		
		{			
			sprintf(tmpbuferr, "%s (MIB_CATV_TX_POWER)",Tset_mib_error);			
			printf("tmpbuferr = %s",tmpbuferr );	
		}		
	}


	int Dc_vcc;
		
	Dc_vcc = send_buf_catv_read_result[4];
	memset(tmp_buf,0,30);
	sprintf(tmp_buf,"%d dBuV",Dc_vcc);
	
	if ( tmp_buf[0] )
	{
		#if UART_DEBUG
		printf("===>[%s:%d] fmcatv=%s\n",__func__,__LINE__,tmp_buf);	
		#endif 
		if(!mib_set(MIB_CATV_DC_VCC, tmp_buf))		
		{			
			sprintf(tmpbuferr, "%s (MIB_CATV_DC_VCC)",Tset_mib_error);			
			printf("tmpbuferr = %s",tmpbuferr );		
		}		
	}

	
	int temperature;	
	
	temperature = send_buf_catv_read_result[5];
	memset(tmp_buf,0,30);
	sprintf(tmp_buf,"%d °C",temperature);
	
	if ( tmp_buf[0] )
	{
		#if UART_DEBUG
		printf("===>[%s:%d] fmcatv=%s\n",__func__,__LINE__,tmp_buf);	
		#endif 
		if(!mib_set(MIB_CATV_TEMPERATURE, tmp_buf))		
		{			
			sprintf(tmpbuferr, "%s (MIB_CATV_DC_VCC)",Tset_mib_error);			
			printf("tmpbuferr = %s",tmpbuferr );		
		}		
	}

	int gain_control;	
	
	gain_control = send_buf_catv_read_result[6];
	memset(tmp_buf,0,30);
	sprintf(tmp_buf,"%d",gain_control);
	
	if ( tmp_buf[0] )
	{
		#if UART_DEBUG
		printf("===>[%s:%d] fmcatv=%s\n",__func__,__LINE__,tmp_buf);	
		#endif 
		if(!mib_set(MIB_CATV_GAIN_CONTROL, tmp_buf))		
		{			
			sprintf(tmpbuferr, "%s (MIB_CATV_GAIN_CONTROL)",Tset_mib_error);			
			printf("tmpbuferr = %s",tmpbuferr );		
		}		
	}

	int onoff;	
	
	onoff = send_buf_catv_read_result[7];
	memset(tmp_buf,0,30);
	sprintf(tmp_buf,"%d",onoff);
	
	if ( tmp_buf[0] )
	{
		#if UART_DEBUG
		printf("===>[%s:%d] fmcatv=%s\n",__func__,__LINE__,tmp_buf);	
		#endif 
		if(!mib_set(MIB_CATV_RF_ONOFF, tmp_buf))		
		{			
			sprintf(tmpbuferr, "%s (MIB_CATV_RF_ONOFF)",Tset_mib_error);			
			printf("tmpbuferr = %s",tmpbuferr );		
		}		
	}

}

void uart_write()
{

	for(i = 0;i < 1;i++)  
	{  
		len = uart_send(fd,send_buf_16,6);	 
		if(len > 0)  
			printf(" %d time send %d data successful\n",i,len);  
		else  
			printf("send data failed!\n");							
		sleep(2);  
	} 

}
int main_uart(int flag_w_r,int RF_att_set_value,int RF_switch_value)	
{  
                           
    int err;  

	fd = uart_open(fd,"/dev/ttyS2"); //打开串口，返回文件描述符 
	if(fd > 0)
	{
		printf("\n open the /dev/ttyS2 is OK \n");
	}
	else 
	{
		return 0;
	}
		
		
    err = uart_init(fd,19200,0,8,1,'N');  
	if(FALSE == err)
		printf("Set Port Exactly error !\n"); 
	else 	
		printf("Set Port Exactly ok !\n");  
	

	if(UART_READ == flag_w_r)
	{
		memset(send_buf_16,0,6);
		memcpy(send_buf_16,send_buf_look_cmd,6);
		uart_read();			
		uart_close(fd); 
		save_mib();
		
	}
	if(UART_WRITE == flag_w_r)
	{
		memset(send_buf_16,0,6);
		memcpy(send_buf_16,send_buf_catv_rf_set_cmd,6);
		send_buf_16[5] = RF_att_set_value;
		uart_write();		

		memset(send_buf_16,0,6);
		memcpy(send_buf_16,send_buf_catv_open_cmd,6);
		send_buf_16[5] = RF_switch_value;
		uart_write();	
		uart_close(fd); 		
	}	 
} 

