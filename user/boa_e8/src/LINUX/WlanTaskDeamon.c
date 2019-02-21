#include <sys/ioctl.h>
#include <netinet/if_ether.h>
#include <linux/if.h>
#include <sys/types.h>
#include <unistd.h>
#include "utility.h"
#include <sys/ipc.h>
#include <sys/shm.h>
#include <time.h>
#include <signal.h>

#define GUEST_SSID_REMAIN_DURATION_INFO		"/var/guest_ssid_remain_duration_info"
#define WLANTASKD_RUNFILE	"/var/run/WlanTaskDeamon.pid"

int get_guest_ssid_remain_duration(int if_wlan_index)
{
	int remain_duration;
	char file_name[125];
	char line[64];
	FILE *fp;
	int i;

	sprintf(file_name, "%s_wlan%d", GUEST_SSID_REMAIN_DURATION_INFO, i);
	if(!(fp = fopen(file_name, "r")))
		return -1;
	
	fgets(line, 12, fp);
	sscanf(line, "%d", &remain_duration);

	fclose(fp);
	return remain_duration;
}

int set_guest_ssid_remain_duration(int if_wlan_index, int val)
{
	char file_name[125];
	char buf[100];
	char line[64];
	FILE *fp;
	
	sprintf(file_name, "%s_wlan%d", GUEST_SSID_REMAIN_DURATION_INFO, if_wlan_index);	
	sprintf(buf, "/bin/echo %d > %s", val, file_name);
	system(buf);
	return 0;
}

int set_guest_ssid_remain_duration_shm(int if_wlan_index, int duration)
{
	char file_name[125];
	key_t shm_key;
	int shm_id; // shared memory ID
	int *shm_start; // attaching address

	sprintf(file_name, "%s_wlan%d", GUEST_SSID_REMAIN_DURATION_INFO, if_wlan_index);
	shm_key = ftok(file_name, 'o');
	if ((shm_id = shmget((key_t)shm_key, 32, 0644 | IPC_CREAT)) == -1) {
		perror("shmget");
		return -1;
	}
	//AUG_PRT("shm_id=%d shm_key=%d guest_ssid_remain_duration_str=%s\n", shm_id, shm_key, file_name);
	
	if ((shm_start = (int *)shmat ( shm_id , NULL , 0 ) )==(int *)(-1)) {
		perror("shmat");
		return -1;
	}
	
	AUG_PRT("initShm: shm_id=%d, shm_start=0x%x, *shm_start=%d\n", shm_id, shm_start, *shm_start);
	if(duration>=0)
	{
		*shm_start=duration;
	}
	
	shmdt(shm_start); // Detach shared memory segment.
	return 0;
}

int get_guest_ssid_remain_duration_shm(int if_wlan_index)
{
	char file_name[125];
	int remain_duration;
	key_t shm_key;
	int shm_id; // shared memory ID
	int *shm_start=NULL; // attaching address

	sprintf(file_name, "%s_wlan%d", GUEST_SSID_REMAIN_DURATION_INFO, if_wlan_index);
	shm_key = ftok(file_name, 'o');
	if ((shm_id = shmget((key_t)shm_key, 32, 0644 | IPC_CREAT)) == -1) {
		perror("shmget");
		return -1;
	}
	
	if ((shm_start = (int *)shmat ( shm_id , NULL , 0 ) )==(int *)(-1)) {
		perror("shmat");
		return -1;
	}
	
	if(shm_start != NULL){
		AUG_PRT("initShm: shm_id=%d, shm_start=0x%x, *shm_start=%d\n", shm_id, shm_start, *shm_start);
		remain_duration=*shm_start;
		shmdt(shm_start); // Detach shared memory segment.
		return remain_duration;
	}
	
	shmdt(shm_start); // Detach shared memory segment.
	return -1;
}

#if 0
void guest_ssid_routine(void)
{
	int current_remain_duration=0;
	char file_name[125];
	char guest_ssid; // ssid_index
	char ifname[16];
	char buf[100];
	int i;	
	
	for(i=0 ; i<2 ; i++)
	{
		wlan_idx = i;
		mib_get(MIB_WLAN_GUEST_SSID, (void *)&guest_ssid);

		if(guest_ssid)
		{
			if(guest_ssid==1)
				sprintf(ifname, "%s", WLANIF[1]);
			else if(guest_ssid==5)
				sprintf(ifname, "%s", WLANIF[0]);
#ifdef WLAN_MBSSID
			else if(guest_ssid<=4)
				sprintf(ifname, "wlan0-vap%d", guest_ssid-2);
			else
				sprintf(ifname, "wlan1-vap%d", guest_ssid-6);
#endif
			current_remain_duration=get_guest_ssid_remain_duration_shm(i);
			if(current_remain_duration>0)
			{
				if(current_remain_duration==1)
				{
					va_cmd(IWPRIV, 3, 1, ifname, "set_mib", "func_off=1");
					AUG_PRT("%s func_off! \n", ifname);
				}
				set_guest_ssid_remain_duration_shm(i, current_remain_duration-1);
				set_guest_ssid_remain_duration(i, current_remain_duration-1);
			}
		}
	}
}
#endif

static void log_pid()
{
	FILE *f;
	pid_t pid;
	char *pidfile = WLANTASKD_RUNFILE;

	pid = getpid();
	
	if((f = fopen(pidfile, "w")) == NULL)
		return;
	fprintf(f, "%d\n", pid);
	fclose(f);
}

static void update_wlan_guestssid_crontab(int signum)
{
	unsigned long guest_ssid_endtime;
	char guest_ssid; // ssid_index
	int duration, i;
	char ifname[16];
	char timeStr[200];
	char isGuestSsid;
	time_t tm;

#if defined(CONFIG_RTL_92D_SUPPORT) || defined(WLAN_DUALBAND_CONCURRENT)
	for(i=0 ; i<2 ; i++)
	{
		wlan_idx=i;
#endif
		isGuestSsid=0;
		mib_get(MIB_WLAN_GUEST_SSID, (void *)&guest_ssid);
		mib_get(MIB_WLAN_GUEST_SSID_DURATION, (void *)&duration);
		mib_get(MIB_WLAN_GUEST_SSID_ENDTIME, (void *)&guest_ssid_endtime);
		if(guest_ssid && duration)
			isGuestSsid=1;
		if(isGuestSsid)
		{
			time(&tm);
			if(!guest_ssid_endtime || guest_ssid_endtime < 31539661000) // time was not sync when OSGI API called && this guest SSID exist
			{
				tm += duration*60;
				guest_ssid_endtime = tm;
				strftime(timeStr, 200, "%a %b %e %H:%M:%S %Z %Y", localtime(&tm));
				get_ifname_by_ssid_index(guest_ssid, ifname);
				AUG_PRT("guest SSID ifname=%s will be down at %s \n", ifname, timeStr);
				// update the endtime after time is sync
				mib_set(MIB_WLAN_GUEST_SSID_ENDTIME, (void *)&guest_ssid_endtime);
#ifdef COMMIT_IMMEDIATELY
				Commit();
#endif
			}
			else if(guest_ssid_endtime < tm) // time was expired && this guest SSID exist
			{
				// Turn off the guest SSID directly by func_off=1
				get_ifname_by_ssid_index(guest_ssid, ifname);
				AUG_PRT("guest SSID ifname=%s has expired func_off=1 \n", ifname);
				va_cmd(IWPRIV, 3, 1, ifname, "set_mib", "func_off=1");
			}
		}
#if defined(CONFIG_RTL_92D_SUPPORT) || defined(WLAN_DUALBAND_CONCURRENT)
	}
#endif
#ifdef WIFI_TIMER_SCHEDULE
	updateScheduleCrondFile("/var/spool/cron/crontabs", 0);
#endif
}

void main(int argc, char *argv[])
{
	log_pid();
	signal(SIGUSR1, update_wlan_guestssid_crontab);
	while(1)
	{
		///--guest_ssid_routine();
		sleep(1000);
	}
}

