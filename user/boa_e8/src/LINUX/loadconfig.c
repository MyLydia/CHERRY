/*
 * Load configuration file and update to the system
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "mibtbl.h"
#include "utility.h"

#if 0
#define DEBUGP	printf
#else
#define DEBUGP(format, args...)
#endif

#ifdef CONFIG_MIDDLEWARE
#include <rtk/midwaredefs.h>

static int sendMsg2MidProcess(struct mwMsg * pMsg)
{
	int spid;
	FILE * spidfile;
	int msgid;
	
	msgid = msgget((key_t)1357,  0666);
	if(msgid <= 0){
		fprintf(stdout,"LoadxmlCfg: get cwmp msgqueue error in %s!\n",__FUNCTION__);
		return -1;
	}

	/* get midware interface pid*/
	if ((spidfile = fopen(CWMP_MIDPROC_RUNFILE, "r"))) {
		fscanf(spidfile, "%d\n", &spid);
		fclose(spidfile);
	}else{
		fprintf(stdout,"LoadxmlCfg: midprocess pidfile not exists in %s\n",__FUNCTION__);
		return -1;
	}

	pMsg->msg_type = spid;
	pMsg->msg_datatype = MSG_MIDWARE;
	if(msgsnd(msgid, (void *)pMsg, MW_MSG_SIZE, 0) < 0){
		fprintf(stdout,"LoadxmlCfg: send message to midprocess error in %s!\n",__FUNCTION__);
		return -1;
	}
	
	return 0;
}

void sendSaveRebootMsg2MidProcess()
{
	struct mwMsg sendMsg;
	char * sendBuf = sendMsg.msg_data;
	
	*(sendBuf) = OP_SaveReboot;
	sendMsg2MidProcess(&sendMsg);
}
#endif	//end fo CONFIG_MIDDLEWARE


#define error -1
#define FMT_RAW		1
#define FMT_XML		2

void show_usage()
{
	fprintf(stderr, "Usage: loadconfig [ -f filename ] [ -t raw/xml ] [ cs/hs ]\n");
	fprintf(stderr, "Load file into system configuration.\n");
	fprintf(stderr, "Default options:\n");
	fprintf(stderr, "\t[ -f filename ] %s for cs; %s for hs\n", CONFIG_XMLFILE, CONFIG_XMLFILE_HS);
	fprintf(stderr, "\t[ -t raw/xml ] xml\n");
	fprintf(stderr, "\t[ cs/hs ] cs\n");
	fprintf(stderr, "Usage: loadconfig -c\n");
	fprintf(stderr, "Check validation of MIB descriptors.\n");
}

static int load_xml_file(const char *loadfile, CONFIG_DATA_T cnf_type)
{
	return _load_xml_file(loadfile, cnf_type, 1);
}

#if !defined(CONFIG_USER_XMLCONFIG) && !defined(CONFIG_USER_CONF_ON_XMLFILE)
static int load_raw_file(const char *loadfile, CONFIG_DATA_T cnf_type)
{
	FILE *fp;
	int ret = 0;
	unsigned int nLen, nRead;
	unsigned char *buf = NULL;
	struct stat st;

	if (stat(loadfile, &st)) {
		printf("User configuration file can not be stated: %s\n", loadfile);
		ret = error;
		goto ret;
	}
	nLen = st.st_size;

	if (!(fp = fopen(loadfile, "r"))) {
		printf("User configuration file can not be opened: %s\n", loadfile);
		ret = error;
		goto ret;
	}

	buf = malloc(nLen);
	if (buf == NULL) {
		printf("malloc failure!\n");
		ret = error;
		goto ret;
	}
	nRead = fread(buf, 1, nLen, fp);
	if (nRead != nLen) {
		printf("fread length mismatch!\n");
		ret = error;
		goto ret;
	}

	DECODE_DATA(buf + sizeof(PARAM_HEADER_T), nLen - sizeof(PARAM_HEADER_T));

	if (mib_update_from_raw(buf, nLen) != 1) {
		printf("Flash error!\n");
		ret = error;
		goto ret;
	}

ret:
	if (fp) {
		fclose(fp);
		fp = NULL;
	}

	free(buf);
	buf = NULL;

	/* No errors */
	if (ret == 0) {
		if (mib_load(cnf_type, CONFIG_MIB_ALL) == 0)
			ret = error;
	}

	return ret;
}
#else
static int load_raw_file(const char *loadfile, CONFIG_DATA_T cnf_type)
{
	printf("%s not supported\n", __FUNCTION__);

	return error;
}
#endif

int main(int argc, char **argv)
{
	int i;
	int opt;
	char userfile[64];
	char *loadfile;
	int filefmt;
	int desc_check;
	CONFIG_DATA_T dtype;

	desc_check = 0;
	loadfile = NULL;
	filefmt = FMT_XML;
	/* do normal option parsing */
	while ((opt = getopt(argc, argv, "f:t:ch")) > 0) {
		switch (opt) {
		case 'f':
			strncpy(userfile, optarg, sizeof(userfile));
			userfile[63] = '\0';
			loadfile = userfile;
			break;
		case 't':
			if (!strcmp("raw", optarg))
				filefmt = FMT_RAW;
			else if (!strcmp("xml", optarg))
				filefmt = FMT_XML;
			else {
				show_usage();
				return error;
			}
			break;
		case 'c':	// check chain member descriptor
			desc_check = 1;
			break;
		case 'h':
		default:
			show_usage();
			return error;
		}
	}

	if (argv[optind] == NULL) {
		dtype = CURRENT_SETTING;
	} else {
		if (!strcmp(argv[optind], "cs"))
			dtype = CURRENT_SETTING;
		else if (!strcmp(argv[optind], "hs"))
			dtype = HW_SETTING;
		else {
			show_usage();
			return error;
		}
	}

	// assign loadfile
	if (!loadfile) {
		switch (dtype) {
		case HW_SETTING:
			if (filefmt == FMT_XML)
				loadfile = (char *)CONFIG_XMLFILE_HS;
			else
				loadfile = (char *)CONFIG_RAWFILE_HS;
			break;
		case CURRENT_SETTING:
		default:
			if (filefmt == FMT_XML)
				loadfile = (char *)CONFIG_XMLFILE;
			else
				loadfile = (char *)CONFIG_RAWFILE;
			break;
		}
	}

	if (desc_check) {
		if (mib_check_desc() == 1)
			printf("Check ok !\n");
		else
			printf("Check failed !\n");
		return 0;
	}

	printf("Get user specific configuration file......\n\n");
	if (filefmt == FMT_XML)
		i = load_xml_file(loadfile, dtype);
	else
		i = load_raw_file(loadfile, dtype);

	if (i == 0)
#ifdef _PRMT_X_CT_COM_ALARM_MONITOR_
	{
#endif
		printf("Restore %s settings from config file successful! \n",
				dtype == CURRENT_SETTING ? "CS" : "HS");
#ifdef CONFIG_MIDDLEWARE
		printf("send saveReboot msg to midprocess\n");
		sendSaveRebootMsg2MidProcess();
#endif
#ifdef _PRMT_X_CT_COM_ALARM_MONITOR_
		clear_ctcom_alarm(CTCOM_ALARM_CONF_INVALID);
	} else {
		set_ctcom_alarm(CTCOM_ALARM_CONF_INVALID);
	}
#endif

	return i;
}
