#include <sys/ioctl.h>
#include <netinet/if_ether.h>
#include <linux/if.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include "utility.h"

#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_AllWirelessChannelEnable_
#define MAX_CHANNEL_NUM 14
#endif

#define TP_THRESHOLD 1 //Mbps

void usage(void);

static int check_wlan_net_device_trx_stats(const char *ifname)
{
	FILE *fp = NULL;
	int num = 0;
	char wlan_path[128] = {0}, line[1024] = {0};
	unsigned long tx_average=0, rx_average=0; //byte
	unsigned long total; //Mbit
	snprintf(wlan_path, sizeof(wlan_path), "/proc/%s/stats", ifname);

	fp = fopen(wlan_path, "r");
	if (fp) {
		while (fgets(line, sizeof(line),fp)) {
			if (strstr(line, "tx_avarage")) {
				sscanf(line,"%*[^:]: %lu", &tx_average);
				//fprintf(stderr, "[%s] ifname [%s], tx_average = %lu byte\n", __func__, ifname, tx_average);
				num++;
			}
			else if(strstr(line, "rx_avarage")) {
				sscanf(line,"%*[^:]: %lu", &rx_average);
				//fprintf(stderr, "[%s] ifname [%s], rx_average = %lu byte\n", __func__, ifname, rx_average);
				num++;
			}
			
			if(num>=2)
				break;
		}
		fclose(fp);
	}
	total = (tx_average + rx_average) >> 17;
	//fprintf(stderr, "[%s] ifname [%s], total = %lu Mbps\n", __func__, ifname, total);
	if(total > TP_THRESHOLD)
		return 1;
	return 0;
}

int AllWirelessChannel(unsigned char best)
{
	unsigned char res;
	int wait_time;
	int status;
	char tmpBuf[100];
	int bssdb_idx;
	static SS_STATUS_T Status={0};
	FILE *fp_tmp = NULL;
	
	if(check_wlan_net_device_trx_stats(getWlanIfName()) == 1){
		printf("detect traffic > %d Mbps, skip SiteSurvey\n", TP_THRESHOLD);
		return 0;
	}
	// issue scan request
	wait_time = 0;
	while (1) {
		if ( getWlSiteSurveyRequest(getWlanIfName(),  &status) < 0 ) {
			printf("Site-survey request failed!");
			goto ss_err;
		}
		if (status != 0) {	// not ready
			if (wait_time++ > 5) {
				printf("scan request timeout!");
				goto ss_err;
			}
			sleep(1);
		}
		else
			break;
	}

	// wait until scan completely
	wait_time = 0;
	while (1) {
		Status.number=0;
		if ( getWlSiteSurveyResult(getWlanIfName(), (SS_STATUS_Tp)&Status) < 0 ) {
			strcpy(tmpBuf, "Read site-survey status failed!");
			goto ss_err;
		}
		if (Status.number == 0xff) {   // in progress
			if (wait_time++ > 10) {
				printf("scan timeout!");
				goto ss_err;
			}
			sleep(1);
		}
		else
			break;
	}
	
#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_
	if(!(fp_tmp = fopen("/var/wireless_neighbor_info", "w+")))
	{
		goto ss_err;
	}
#endif

	if(best)
	{
		printf("Best:\n");
		printf("Idx  Signal(dBm)\n");
		printf("----------------\n");	
		printf("%-5d%-8d\n", 0, Status.bssdb[0].rssi-100);
	}
	else
	{
#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_
#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_AllWirelessChannelEnable_
		int curChanIndex, chanIndex;
		unsigned int neighborNum[MAX_CHANNEL_NUM] = {0};
		for(bssdb_idx=0 ; bssdb_idx<Status.number ; bssdb_idx++)
		{
			curChanIndex = Status.bssdb[bssdb_idx].channel;
			if(curChanIndex > 13)
			{
				continue;
			}
			
			neighborNum[curChanIndex]++;
		}
		
		for(chanIndex=1 ; chanIndex<MAX_CHANNEL_NUM ; chanIndex++)
		{
			if(neighborNum[chanIndex])
			{
				fprintf(fp_tmp, "%d:%d+", chanIndex, neighborNum[chanIndex]);
			}
		}
#endif
#ifdef _PRMT_X_CT_COM_PERFORMANCE_REPORT_SUBITEM_BestWirelessChannelEnable_
		fprintf(fp_tmp, "##%d+%d", Status.bssdb[0].channel, Status.bssdb[0].rssi-100);
#endif
		fclose(fp_tmp);
#else
		printf("All:\n");
		printf("Idx  Signal(dBm)\n");
		printf("-----------------\n");

		for(bssdb_idx=0 ; bssdb_idx<Status.number ; bssdb_idx++)
		{		
			printf("%-5d%-8d\n", bssdb_idx, Status.bssdb[bssdb_idx].rssi-100);
		}
#endif		
	for(bssdb_idx=0 ; bssdb_idx<Status.number ; bssdb_idx++)
		{		
			printf("%-5d%-25s%02X:%02X:%02X:%02X:%02X:%02X %-7d%-5d%-5d%-5d\n"
			, bssdb_idx
			, Status.bssdb[bssdb_idx].ssid
			, Status.bssdb[bssdb_idx].bssid[0]
			, Status.bssdb[bssdb_idx].bssid[1]
			, Status.bssdb[bssdb_idx].bssid[2]
			, Status.bssdb[bssdb_idx].bssid[3]
			, Status.bssdb[bssdb_idx].bssid[4]
			, Status.bssdb[bssdb_idx].bssid[5]
			, Status.bssdb[bssdb_idx].bsstype
			, Status.bssdb[bssdb_idx].channel
			, Status.bssdb[bssdb_idx].network
			, Status.bssdb[bssdb_idx].rssi-100);
	
		}
	}
	
	return 0;
	
ss_err:
	return -1;

}

int main(int argc, char *argv[])
{
	int argIdx=1;
	

	if (argc<=1)
		goto arg_err_rtn;

	if(!strcmp(argv[argIdx], "all"))
	{
		if(AllWirelessChannel(0) == -1)
			goto arg_err_rtn;
	}
	else if(!strcmp(argv[argIdx], "best"))
	{
		if(AllWirelessChannel(1) == -1)
			goto arg_err_rtn;
	}
	else
	{
		if(strcmp(argv[argIdx], "--help"))
			printf("Invalid parameter!\n");
		goto arg_err_rtn;
	}

	return 0;

arg_err_rtn:
	usage();
	exit(1);
	
}

void usage(void)
{
	printf("Usage:\n");
	printf("	ShowWirelessChannel all\n");
	printf("	ShowWirelessChannel best\n");
}

