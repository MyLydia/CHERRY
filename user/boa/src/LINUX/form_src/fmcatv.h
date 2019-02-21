
typedef struct {
    int rx_power;
    int tx_power;
    char dc_vcc;
    char temperature;
    int gain_control;
    int onoff;
    int state;
    char HardwareVersion[32];
    char SoftwareVersion[32];
} MEC_TWM_RT_CATV;

#define ERR_MSG(msg)	{ \
    boaWrite(wp, "<html>\n"); \
    boaWrite(wp, "<body><blockquote><h4>%s</h4>\n", msg); \
    boaWrite(wp, "<form><input type=\"button\" onclick=\"history.go (-1)\" value=\"&nbsp;&nbsp;OK&nbsp;&nbsp\" name=\"OK\"></form></blockquote></body>"); \
    boaWrite(wp, "</html>\n"); \
}

#define UART_READ  1  
#define UART_WRITE 2 

//#define UART_DEBUG 1 

//宏定义  
//#define FALSE  -1  
//#define TRUE   0  

int main_uart(int flag_w_r,int RF_att_set_value,int RF_switch_value);	

