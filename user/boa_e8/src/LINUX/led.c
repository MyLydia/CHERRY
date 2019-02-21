#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/sysinfo.h>
#include <ctype.h>

#include "mib.h"
#include "sysconfig.h"
#include "mibtbl.h"
#include "utility.h"
#ifdef CONFIG_USER_RTK_VOIP
#include "voip_manager.h"
#include "voip_params.h"
#endif

const char LEDTEST_PID[] = "/var/run/ledtest.pid";

void usage(void);

#if 0
int getOUIfromMAC(char* oui)
{
        if (oui==NULL)
                return -1;
        unsigned char macAddr[MAC_ADDR_LEN];
        mib_get( MIB_ELAN_MAC_ADDR, (void *)macAddr);
        sprintf(oui,"%02X%02X%02X",macAddr[0],macAddr[1],macAddr[2]);
        return 0;
}
#endif

int main(int argc, char *argv[])
{
	int argNum=1;

	if (argc<=1)
		goto arg_err_rtn;
	if ( !strcmp(argv[argNum], "test") ) {
			argNum++;
				
		if ( !strcmp(argv[argNum], "start") ) {
			system("echo start > /proc/led_test");
			return 0;
		}
		else if (!strcmp(argv[argNum], "stop")) {
			int pid;
			pid = read_pid((char *)LEDTEST_PID);
			if(pid > 0)
			{
				//printf("kill ledtest process, pid:%d\n", pid);
				kill(pid, 9);
				unlink(LEDTEST_PID);
			}
			system("echo stop > /proc/led_test");
#ifdef CONFIG_USER_RTK_VOIP
			system("test -f /var/run/solar_control.fifo && echo L > /var/run/solar_control.fifo");
#endif
#ifdef CONFIG_USER_WIRELESS_TOOLS
			system("echo 2 > /proc/wlan0/led");
			system("echo 2 > /proc/wlan1/led");
			system("echo 2 >> /proc/wlan1/led");
#endif
#if defined(CONFIG_EPON_FEATURE)||defined(CONFIG_GPON_FEATURE)
#ifdef CONFIG_RTL9602C_SERIES
			set_pon_led_state(2);
			set_los_led_state(2);
#endif
#endif
					return 0;
		}
#ifdef CONFIG_USB_SUPPORT
		else if (!strcmp(argv[argNum], "usbtest")) {
	#ifdef CONFIG_APOLLO_MP_TEST
			int usbsum=0;
			struct usb_info usb1,usb2;
			memset(&usb1, 0, sizeof(usb1));
			memset(&usb2, 0, sizeof(usb2));
			getUSBDeviceInfo(&usbsum, &usb1, &usb2);
			if(usbsum == 0)
				printf("No USB device detected!\n");
			if(!strcmp(usb1.disk_status,"Mounted"))
				printf("USB2.0 has connected USB device successfully!\n");
			if(!strcmp(usb2.disk_status,"Mounted"))
				printf("USB3.0 has connected USB device successfully!\n");				
	#else
			if (isUsbDevDetected())
				printf("USB device has conneted successfully!\n");
			else
				printf("No USB device detected!\n");
	#endif
				return 0;
		}
#endif //end of CONFIG_USB_SUPPORT
		else if (!strcmp(argv[argNum], "ethstatus")) {
			system("echo ethstatus > /proc/led_test");
			system("cat /proc/led_test");
			return 0;
		}
		else if ( !strcmp(argv[argNum], "reset")) {
			//this is not a led test command, just to reset CS
			printf("RESET starting...\n");
#ifdef INCLUDE_DEFAULT_VALUE
			mib_init_mib_with_program_default(CURRENT_SETTING, FLASH_DEFAULT_TO_ALL);
#endif
			//reboot right now!
			cmd_reboot();
			return 0;
		}
		else if ( !strcmp(argv[argNum], "allledon")) {
			system("echo allledon > /proc/led_test");
#if defined(CONFIG_EPON_FEATURE)||defined(CONFIG_GPON_FEATURE)
#ifdef CONFIG_RTL9602C_SERIES
			set_pon_led_state(1);
			set_los_led_state(1);
#endif
#endif
#ifdef CONFIG_USER_RTK_VOIP
			rtk_SetLedDisplay( 0, 0, LED_ON );
			rtk_SetLedDisplay( 1, 0, LED_ON );
#endif
#if defined(CONFIG_PON_LED_PROFILE_DEMO_RTL9607_IAD_V00) || defined(CONFIG_PON_LED_PROFILE_DEMO_RTL9607_IAD_V01)
#if (defined(CONFIG_SLOT_0_8192EE) || defined(CONFIG_SLOT_1_8192EE))
			system("echo 1 > /proc/wlan0/led");
#endif
#elif defined(CONFIG_PON_LED_PROFILE_DEMO_RTL9602C)
#if (defined(CONFIG_SLOT_0_8192EE) || defined(CONFIG_SLOT_1_8192EE))
			system("echo 1 > /proc/wlan0/led");
#endif
#endif
			return 0;
		}
		else if ( !strcmp(argv[argNum], "allledoff")) {
			system("echo allledoff > /proc/led_test");
#if defined(CONFIG_EPON_FEATURE)||defined(CONFIG_GPON_FEATURE)
#ifdef CONFIG_RTL9602C_SERIES
			set_pon_led_state(0);
			set_los_led_state(0);
#endif
#endif
#ifdef CONFIG_USER_RTK_VOIP
			rtk_SetLedDisplay( 0, 0, LED_OFF );
			rtk_SetLedDisplay( 1, 0, LED_OFF );
#endif
#if defined(CONFIG_PON_LED_PROFILE_DEMO_RTL9607_IAD_V00) || defined(CONFIG_PON_LED_PROFILE_DEMO_RTL9607_IAD_V01)
#if (defined(CONFIG_SLOT_0_8192EE) || defined(CONFIG_SLOT_1_8192EE))
			system("echo 0 > /proc/wlan0/led");
#endif
#elif defined(CONFIG_PON_LED_PROFILE_DEMO_RTL9602C)
#if (defined(CONFIG_SLOT_0_8192EE) || defined(CONFIG_SLOT_1_8192EE))
			system("echo 0 > /proc/wlan0/led");
#endif
#endif			
			return 0;
		}
#ifndef CONFIG_RTL9601B_SERIES
		else if ( !strcmp(argv[argNum], "allgreenon")) {
			system("echo allgreenon > /proc/led_test");
			return 0;
		}
		else if ( !strcmp(argv[argNum], "allgreenoff")) {
			system("echo allgreenoff > /proc/led_test");
			return 0;
		}
		else if ( !strcmp(argv[argNum], "allredon")) {
			system("echo allredon > /proc/led_test");
			return 0;
		}
		else if ( !strcmp(argv[argNum], "allredoff")) {
			system("echo allredoff > /proc/led_test");
			return 0;
		}
#endif		
		else if ( !strcmp(argv[argNum], "set")) {
			char strCmd[50], tmpStr[50];
			memset(tmpStr, 0, sizeof(tmpStr));
			sprintf(tmpStr, "%s", argv[argNum]);
			argNum++;
			while (argNum<argc) {
				sprintf(tmpStr+strlen(tmpStr), " %s", argv[argNum]);
				argNum++;
			}
			if(strstr(tmpStr,"wlan0"))
				system("echo 1 > /proc/wlan0/led");
			else if(strstr(tmpStr,"wlan1"))
				system("echo 1 > /proc/wlan1/led");
#if defined(CONFIG_EPON_FEATURE)||defined(CONFIG_GPON_FEATURE)
#ifdef CONFIG_RTL9602C_SERIES
			else if(strstr(tmpStr,"los"))
				set_los_led_state(1);
			else if(strstr(tmpStr,"pon"))
				set_pon_led_state(1);
#endif
#endif
#if defined(CONFIG_USER_RTK_VOIP)
			else if (strstr(tmpStr,"fxs 1"))
				rtk_SetLedDisplay( 0, 0, LED_ON );
			else if (strstr(tmpStr,"fxs 2"))
				rtk_SetLedDisplay( 1, 0, LED_ON );
#endif
			else
			{
			sprintf(strCmd, "echo \"%s\" > /proc/led_test", tmpStr);
			//printf("cmd:%s\n", strCmd);
			system(strCmd);
			}
			return 0;
		}
		else if (!strcmp(argv[argNum], "get")) {
			int pid;
			pid = read_pid((char *)LEDTEST_PID);
			if(pid <= 0)
			{
				va_cmd("/bin/ledtest",0,0);
			}
			return 0;
		}
	}


	return 0;
	arg_err_rtn:
	usage();
	exit(1);

}

void usage(void)
{
#ifndef CONFIG_RTL9601B_SERIES
	printf("led test set power green\n");
	printf("led test set power red\n");
	printf("led test set internet green\n");
	printf("led test set internet red\n");
	printf("led test set lan 4\n");
	printf("led test set lan 3\n");
	printf("led test set lan 2\n");
#endif
	printf("led test start\n");
	printf("led test stop\n");
	printf("led test get\n");
	printf("led test set lan 1\n");
	printf("led test set pon\n");
	printf("led test set los\n");
	printf("led test set 1G\n");	
#ifndef CONFIG_RTL9601B_SERIES
	printf("led test set wlan0\n");
	printf("led test set wlan1\n");
	printf("led test set usbhost\n");
#endif
#ifdef CONFIG_RTK_VOIP
	printf("led test set fxs 1\n");
	printf("led test set fxs 2\n");
#endif

	printf("led test allledon\n");
	printf("led test allledoff\n");
}



