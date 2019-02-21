#ifndef HWNAT_IOCTL_C
#define HWNAT_IOCTL_C
#include <rtk/utility.h>
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include "hwnat_ioctl.h"

/*
 *	Return:
 *	>= 0 on success
 *	-1 on error
 */
int send_to_hwnat(hwnat_ioctl_cmd hifr)
{
	struct ifreq    ifr;
	int fd = -1;
	int ret;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(fd< 0){
		printf("Error!Socket create fail.\n");
		return 0;
	}

	strncpy(ifr.ifr_name, ELANVIF[0], IFNAMSIZ);
	ifr.ifr_data = (void *)&hifr;

	ret = ioctl(fd, RTL819X_IOCTL_HWNAT, &ifr);
	printf("%s: ret=%d\n", __FUNCTION__, ret);
	close(fd);
	if (ret < 0) {
		printf("%s: Error ioctl(RTL819X_IOCTL_HWNAT)!\n", __FUNCTION__);
	}
	return ret;
}

int send_extip_to_hwnat(char action, char *name, unsigned int ip)
{
	struct _hwnat_ioctl_cmd ioctl_arg;
	struct hwnat_ioctl_extip_cmd cmd_arg;

	cmd_arg.extip_rule.name = name;
	cmd_arg.extip_rule.action = action;
	cmd_arg.extip_rule.ip = ip;

	ioctl_arg.type = HWNAT_IOCTL_EXTIP_TYPE;
	ioctl_arg.data = &cmd_arg;

	send_to_hwnat(ioctl_arg);
	return 0;
}

/*
 *	ifname:
 *		"nas0", "ptm0", "eth0.2", "eth0.3" ...
 *	Return:
 *		>=	0 shapingRate
 *		-1	on error
 */
int hwnat_itf_get_ShapingRate(const char *ifname)
{
	hwnat_ioctl_cmd hifr;
	struct hwnat_ioctl_itf_cmd hwitfc;
	int ret;
	
	memset(&hwitfc, 0, sizeof(hwitfc));
	hifr.type = HWNAT_IOCTL_ITF_TYPE;
	hifr.data = (void *)&hwitfc;
	hwitfc.type = Get_ShapingRate_CMD;
	strcpy(hwitfc.ifname, ifname);
	ret = send_to_hwnat(hifr);
	if (ret < 0)
		return ret;
	return hwitfc.u.ShapingRate;
}

/*
 *	ifname:
 *		"nas0", "ptm0", "eth0.2", "eth0.3" ...
 *	Rate:
 *		-1	no shaping
 *		>=0	rate in bps
 *	Return:
 *		>= 0 on success
 *		-1 on error
 */
int hwnat_itf_set_ShapingRate(const char *ifname, int rate)
{
	hwnat_ioctl_cmd hifr;
	struct hwnat_ioctl_itf_cmd hwitfc;
	int ret;
	
	memset(&hwitfc, 0, sizeof(hwitfc));
	hifr.type = HWNAT_IOCTL_ITF_TYPE;
	hifr.data = (void *)&hwitfc;
	hwitfc.type = Set_ShapingRate_CMD;
	strcpy(hwitfc.ifname, ifname);
	hwitfc.u.ShapingRate = rate;
	ret = send_to_hwnat(hifr);
	if (ret < 0)
		printf("Set ShapingRate failed !\n");
	return ret;
}

/*
 *	ifname:
 *		"nas0", "ptm0", "eth0.2", "eth0.3" ...
 *	Return:
 *		>=0	Burst size in bytes
 *		-1	on error
 */
int hwnat_itf_get_ShapingBurstSize(const char *ifname)
{
	hwnat_ioctl_cmd hifr;
	struct hwnat_ioctl_itf_cmd hwitfc;
	int ret;
	
	memset(&hwitfc, 0, sizeof(hwitfc));
	hifr.type = HWNAT_IOCTL_ITF_TYPE;
	hifr.data = (void *)&hwitfc;
	hwitfc.type = Get_ShapingBurstSize_CMD;
	strcpy(hwitfc.ifname, ifname);
	ret = send_to_hwnat(hifr);
	if (ret < 0)
		return ret;
	return hwitfc.u.ShapingBurstSize;
}

/*
 *	ifname:
 *		"nas0", "ptm0", "eth0.2", "eth0.3" ...
 *	bsize:
 		Burst size in bytes
 *	Return:
 *		>=0	on success
 *		-1	on error
 */
int hwnat_itf_set_ShapingBurstSize(const char *ifname, unsigned int bsize)
{
	hwnat_ioctl_cmd hifr;
	struct hwnat_ioctl_itf_cmd hwitfc;
	int ret;
	
	memset(&hwitfc, 0, sizeof(hwitfc));
	hifr.type = HWNAT_IOCTL_ITF_TYPE;
	hifr.data = (void *)&hwitfc;
	hwitfc.type = Set_ShapingBurstSize_CMD;
	strcpy(hwitfc.ifname, ifname);
	hwitfc.u.ShapingBurstSize = bsize;
	ret = send_to_hwnat(hifr);
	if (ret < 0)
		printf("Set ShapingBurstSize failed !\n");
	return ret;
}

#endif
