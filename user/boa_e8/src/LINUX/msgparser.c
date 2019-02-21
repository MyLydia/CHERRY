/*
 *	msgparser.c -- Parser for an well-formed message
 */

#include "../msgq.h"
#include "mibtbl.h"
#include "utility.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ipc.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <signal.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <assert.h>
#ifdef EMBED
#include <config/autoconf.h>
#else
#include "../../../../config/autoconf.h"
#endif
#ifdef VOIP_SUPPORT
#include "web_voip.h"
#endif
#include <linux/version.h>
#if defined(CONFIG_USER_DHCPV6_ISC_DHCP411)
#include "subr_dhcpv6.h"
#endif

#include "ipv6_info.h"
#include <signal.h>
#include "mib_reserve.h"
#include <sys/types.h>
#include <sys/msg.h>
#include "mib.h"

#ifdef CONFIG_MTD_NAND
#include "rtl_flashdrv_api.h"
#endif
#ifdef CONFIG_RTK_L34_ENABLE
#include <rtk_rg_struct.h>
#endif
#define MAX_ARGS	3
#define MAX_ARG_LEN	32

#ifdef CONFIG_IPV6
#if defined(CONFIG_USER_DHCPV6_ISC_DHCP411)
static DLG_INFO_T dlg_info;
#endif
static DLG_INFO_T old_dlg_info={0};
#endif

extern int shm_id;
extern char *shm_start;
#ifdef CONFIG_USER_DBUS_CTC_IGD
extern int ctc_igd_shm_id;
extern char *ctc_igd_shm_start;
#endif
extern char g_upload_post_file_name[MAX_SEND_SIZE];
extern int g_upload_startPos;
extern int g_upload_fileSize;
extern int g_upload_needreboot;

static int parse_token(char *buf, char argv[MAX_ARGS][MAX_ARG_LEN+1]);
//static void cfg_get(int argc, char argv[MAX_ARGS][MAX_ARG_LEN+1], struct mymsgbuf *qbuf);
static void cfg_mib_get(struct mymsgbuf *qbuf);
//static void cfg_set(int argc, char argv[MAX_ARGS][MAX_ARG_LEN+1], struct mymsgbuf *qbuf);
static void cfg_mib_set(struct mymsgbuf *qbuf);
static void cfg_mib_info_id(struct mymsgbuf *qbuf);
static void cfg_mib_info_index(struct mymsgbuf *qbuf);
static void cfg_mib_info_total(struct mymsgbuf *qbuf);  // For Star Zhang's fast load
static void cfg_mib_backup(struct mymsgbuf *qbuf);
static void cfg_mib_backup_hs(struct mymsgbuf *qbuf);
static void cfg_mib_restore(struct mymsgbuf *qbuf);
static void cfg_mib_get_default(struct mymsgbuf *qbuf);
static void cfg_mib_swap(struct mymsgbuf *qbuf);
static void cfg_mib_to_default(struct mymsgbuf *qbuf);
static void cfg_mib_flash_to_default(struct mymsgbuf *qbuf);
#if (defined VOIP_SUPPORT) && (defined CONFIG_USER_XMLCONFIG)
static void cfg_mib_voip_to_default(struct mymsgbuf *qbuf);
#endif
/*
static void cfg_mib_size(struct mymsgbuf *qbuf);
static void cfg_mib_type(struct mymsgbuf *qbuf);
*/
static void cfg_chain_total(struct mymsgbuf *qbuf);
static void cfg_chain_get(struct mymsgbuf *qbuf);
static void cfg_chain_add(struct mymsgbuf *qbuf);
static void cfg_chain_delete(struct mymsgbuf *qbuf);
static void cfg_chain_clear(struct mymsgbuf *qbuf);
static void cfg_chain_update(struct mymsgbuf *qbuf);
static void cfg_chain_swap(struct mymsgbuf *qbuf);
static void cfg_chain_info_id(struct mymsgbuf *qbuf);
static void cfg_chain_info_index(struct mymsgbuf *qbuf);
static void cfg_chain_info_name(struct mymsgbuf *qbuf);
static void cfg_check_desc(struct mymsgbuf *qbuf);

static void cfg_mib_lock(struct mymsgbuf *qbuf);
static void cfg_mib_unlock(struct mymsgbuf *qbuf);
static void cfg_mib_update_from_raw(struct mymsgbuf *qbuf);
static void cfg_mib_read_to_raw(struct mymsgbuf *qbuf);
static void cfg_mib_update(struct mymsgbuf *qbuf);
static void cfg_mib_read_header(struct mymsgbuf *qbuf);
static void cfg_mib_reload(struct mymsgbuf *qbuf);
#ifdef EMBED
static void cfg_reboot(struct mymsgbuf *qbuf);
#ifdef CONFIG_IPV6
#if defined(CONFIG_USER_DHCPV6_ISC_DHCP411) && defined(CONFIG_USER_RADVD)
static void cfg_delegation(struct mymsgbuf *qbuf);
#endif
#if defined(CONFIG_USER_DHCPV6_ISC_DHCP411)
static void cfg_stop_delegation(struct mymsgbuf *qbuf);
static void cfg_get_PD_prefix_ip(struct mymsgbuf *qbuf);
static void cfg_get_PD_prefix_len(struct mymsgbuf *qbuf);
#endif
#endif
static void cfg_upload(struct mymsgbuf *qbuf);
static void cfg_killprocess(struct mymsgbuf *qbuf);
static void cfg_check_image(struct mymsgbuf *qbuf);
#ifdef CONFIG_USER_DDNS
static void cfg_ddns_ctrl(struct mymsgbuf *qbuf);
#endif
#endif
static void cfg_file2xml(struct mymsgbuf *qbuf);
static void cfg_xml2file(struct mymsgbuf *qbuf);
///added by ql
static void cfg_retrieve_table(struct mymsgbuf *qbuf);
static void cfg_retrieve_chain(struct mymsgbuf *qbuf);

static void cfg_update_PPPoE_session(struct mymsgbuf *qbuf);
static void cfg_mib_set_PPPoE(struct mymsgbuf *qbuf);

static void cfg_set_dns_config(struct mymsgbuf *qbuf);
static void cfg_set_dbus_register_pid(struct mymsgbuf *qbuf);
#if defined(CONFIG_IPV6) && defined(DUAL_STACK_LITE) &&defined(CONFIG_USER_DHCPV6_ISC_DHCP411)
static int cfg_got_aftr(struct mymsgbuf *qbuf);
#endif
#if defined(CONFIG_IPV6) && defined(DUAL_STACK_LITE)
static void cfg_dslite_aftr_static(struct mymsgbuf *qbuf);
#endif
static void cfg_chain_backup_get(struct mymsgbuf *qbuf);
#ifdef CONFIG_USER_DBUS_CTC_IGD
static void cfg_mib_backup_ctc(struct mymsgbuf *qbuf);
static void cfg_mib_restore_ctc(struct mymsgbuf *qbuf);
#endif
#ifdef VOIP_SUPPORT
int set_VoIP_proxy_dnscfg(FILE *dnsfp,char *dns_str,  char activeVOIP);
#endif

#if defined(CONFIG_IPV6) && defined(DUAL_STACK_LITE) &&defined(CONFIG_USER_DHCPV6_ISC_DHCP411)
static MIB_CE_ATM_VC_T * getATM_VC_ENTRY_byName(char *pIfname, int *entry_index);
#endif
static int fixUpDnsServer(char *itfname);

struct command
{
	int	needs_arg;
	int	cmd;
	void	(*func)(struct mymsgbuf *qbuf);
};

volatile int __mib_lock = 0;
MIB_T table_backup;
unsigned char *chain_backup = NULL;
unsigned int backupChainSize = 0;

#ifdef CONFIG_USER_DBUS_CTC_IGD
MIB_T ctc_table_backup;
unsigned char *ctc_chain_backup = NULL;
unsigned int ctc_backupChainSize = 0;
#endif

static struct command commands[] = {
	{1, CMD_MIB_GET, cfg_mib_get},
	{1, CMD_MIB_SET, cfg_mib_set},
	{1, CMD_MIB_INFO_ID, cfg_mib_info_id},
	{1, CMD_MIB_INFO_INDEX, cfg_mib_info_index},
	{1, CMD_MIB_INFO_TOTAL, cfg_mib_info_total},  // For Star Zhang's fast load
	{1, CMD_MIB_BACKUP, cfg_mib_backup},
	{1, CMD_MIB_RESTORE, cfg_mib_restore},
	{1, CMD_MIB_GET_DEFAULT, cfg_mib_get_default},
	{1, CMD_MIB_SWAP, cfg_mib_swap},
	{1, CMD_MIB_TO_DEFAULT, cfg_mib_to_default},
	{1, CMD_MIB_FLASH_TO_DEFAULT, cfg_mib_flash_to_default},
#if (defined VOIP_SUPPORT) && (defined CONFIG_USER_XMLCONFIG)
	{1, CMD_MIB_VOIP_TO_DEFAULT, cfg_mib_voip_to_default},
#endif
	/*
	{1, CMD_MIB_SIZE, cfg_mib_size},
	{1, CMD_MIB_TYPE, cfg_mib_type},
	*/
	{1, CMD_CHAIN_TOTAL, cfg_chain_total},
	{1, CMD_CHAIN_GET, cfg_chain_get},
	{1, CMD_CHAIN_ADD, cfg_chain_add},
	{1, CMD_CHAIN_DELETE, cfg_chain_delete},
	{1, CMD_CHAIN_CLEAR, cfg_chain_clear},
	{1, CMD_CHAIN_UPDATE, cfg_chain_update},
	{1, CMD_CHAIN_INFO_ID, cfg_chain_info_id},
	{1, CMD_CHAIN_INFO_INDEX, cfg_chain_info_index},
	{1, CMD_CHAIN_INFO_NAME, cfg_chain_info_name},
	{1, CMD_CHECK_DESC, cfg_check_desc},
	{1, CMD_CHAIN_SWAP, cfg_chain_swap},
	/*
	{1, CMD_CHAIN_SIZE, cfg_chain_size},
	*/
	{1, CMD_MIB_LOCK, cfg_mib_lock},
	{1, CMD_MIB_UNLOCK, cfg_mib_unlock},
#if !defined(CONFIG_USER_XMLCONFIG) && !defined(CONFIG_USER_CONF_ON_XMLFILE)
	{1, CMD_MIB_UPDATE_FROM_RAW, cfg_mib_update_from_raw},
	{1, CMD_MIB_READ_TO_RAW, cfg_mib_read_to_raw},
	{1, CMD_MIB_READ_HEADER, cfg_mib_read_header},
#endif
	{1, CMD_MIB_UPDATE, cfg_mib_update},
	{1, CMD_MIB_RELOAD, cfg_mib_reload},
#ifdef EMBED
	{1, CMD_REBOOT, cfg_reboot},
	{1, CMD_UPLOAD, cfg_upload},
	{1, CMD_KILLPROC, cfg_killprocess},
	{1, CMD_CHECK_IMAGE, cfg_check_image },
#ifdef CONFIG_USER_DDNS
	{1, CMD_DDNS_CTRL, cfg_ddns_ctrl },
#endif
	{1, CMD_FILE2XML, cfg_file2xml},
	{1, CMD_XML2FILE, cfg_xml2file},
#endif

#ifdef	RESERVE_KEY_SETTING
	{1, CMD_MIB_RETRIVE_TABLE, cfg_retrieve_table},
	{1, CMD_MIB_RETRIVE_CHAIN, cfg_retrieve_chain},
#endif
	{1, CMD_UPDATE_PPPOE_SESSION, cfg_update_PPPoE_session},
	{1, CMD_MIB_SAVE_PPPOE, cfg_mib_set_PPPoE},
#ifdef CONFIG_IPV6
#if defined(CONFIG_USER_DHCPV6_ISC_DHCP411) && defined(CONFIG_USER_RADVD)
	{1, CMD_DELEGATION, cfg_delegation},
#endif
#if defined(CONFIG_USER_DHCPV6_ISC_DHCP411)
	{1, CMD_STOP_DELEGATION, cfg_stop_delegation},
	{1, CMD_GET_PD_PREFIX_IP, cfg_get_PD_prefix_ip},
	{1, CMD_GET_PD_PREFIX_LEN, cfg_get_PD_prefix_len},
#endif
#endif
	{1, CMD_SET_DNS_CONFIG, cfg_set_dns_config},
#if defined(CONFIG_IPV6) && defined(DUAL_STACK_LITE) &&defined(CONFIG_USER_DHCPV6_ISC_DHCP411)
	{1, CMD_GOT_AFTR, (void*)cfg_got_aftr},
#endif
#if defined(CONFIG_IPV6) && defined(DUAL_STACK_LITE)
	{1, CMD_DSLITE_AFTR_STATIC, cfg_dslite_aftr_static},
#endif
	{1, CMD_MIB_CHAIN_BACKUP_GET, cfg_chain_backup_get},
#ifdef CONFIG_USER_DBUS_CTC_IGD
	{1, CMD_MIB_BACKUP_CTC, cfg_mib_backup_ctc},
	{1, CMD_MIB_RESTORE_CTC, cfg_mib_restore_ctc},
#endif
	{1, CMD_DBUS_REGISTER_PID, cfg_set_dbus_register_pid},
	{1, CMD_MIB_BACKUP_HS,  cfg_mib_backup_hs},

	{0, 0, NULL}
};

int msgProcess(struct mymsgbuf *qbuf)
{
  	int argc, c;
	char argv[MAX_ARGS][MAX_ARG_LEN+1];

	// response message type should be the client request magic number
	qbuf->mtype = qbuf->request;
	/*
	if ((argc=parse_token(qbuf->mtext, argv)) == 0)
		return 0;

	for(c=0; commands[c].name!=NULL; c++) {
		if(!strcmp(argv[0], commands[c].name)) {
			argc--;
			if(argc >= commands[c].num_string_arg)
				commands[c].func(argc, (char **)(&argv[1]), qbuf);
			break;
		}
	}
	*/
	for (c=0; commands[c].cmd!=0; c++) {
		if (qbuf->msg.cmd == commands[c].cmd) {
			commands[c].func(qbuf);
			break;
		}
	}
	return 0;
}

/******************************************************************************/
/*
 *	Token Parser -- parse tokens seperated by spaces on buf
 *	Return: number of tokens been parsed
 */

#if 0
static int parse_token(char *buf, char argv[MAX_ARGS][MAX_ARG_LEN+1])
{
  	int num, arg_idx, i;
  	char *arg_ptr;

	num = 0;
	arg_idx = 0;

	for(i=0; buf[i]!='\0'; i++) {
		if(buf[i]==' '){
			if (arg_idx != 0) {	// skip multiple spaces
				argv[num][arg_idx]='\0';
				num++;
				arg_idx=0;
				if (num == MAX_ARGS)
					break;
			}
		}
		else {
			if(arg_idx<MAX_ARG_LEN) {
				argv[num][arg_idx]=buf[i];
				arg_idx++;
			}
		}
	}

	if (arg_idx != 0) {
		argv[num][arg_idx]='\0';
		num++;
	}

	return num;
}
#endif

#ifdef CONFIG_USER_XMLCONFIG
static int xml_mib_update(CONFIG_DATA_T type, CONFIG_MIB_T flag)
{
	int ret=1;
	char param[6];

#ifdef CONFIG_YUEME
	if(access("/tmp/running_dbus_cts", F_OK)==0)
		return ret;
#endif

	printf("%s():...\n", __FUNCTION__);

	if (type == CURRENT_SETTING)
		strcpy (param, "-u cs");
	else if (type == HW_SETTING)
		strcpy (param, "-u hs");

	if (va_cmd (shell_name, 2, 0, "/etc/scripts/config_xmlconfig.sh", param) != MSG_SUCC) {
		printf ("[xmlconfig] mib update %s failed\n", param);
		ret = 0;
	}

	return ret;
}

#endif /*CONFIG_USER_XMLCONFIG */

static void cfg_mib_lock(struct mymsgbuf *qbuf)
{
	__mib_lock = 1;
	qbuf->request = MSG_SUCC;
}

static void cfg_mib_unlock(struct mymsgbuf *qbuf)
{
	__mib_lock = 0;
	qbuf->request = MSG_SUCC;
}

#if !defined(CONFIG_USER_XMLCONFIG) && !defined(CONFIG_USER_CONF_ON_XMLFILE)
static void cfg_mib_update_from_raw(struct mymsgbuf *qbuf)
{
	int len;

	qbuf->request = MSG_FAIL;
	len = qbuf->msg.arg1;

	//printf("update_from_raw: shm_id=%d; shm_start=0x%x\n", shm_id, shm_start);
	if(shm_start && _mib_update_from_raw(shm_start, len) == 1)
		qbuf->request = MSG_SUCC;
}

static void cfg_mib_read_to_raw(struct mymsgbuf *qbuf)
{
	CONFIG_DATA_T data_type;
	int len;

	qbuf->request = MSG_FAIL;
	data_type = (CONFIG_DATA_T)qbuf->msg.arg1;
	len = qbuf->msg.arg2;
	if (len > SHM_SIZE || shm_start == NULL)
		return;
	if (_mib_read_to_raw(data_type, shm_start, len)==1)
		qbuf->request = MSG_SUCC;
}

static void cfg_mib_read_header(struct mymsgbuf *qbuf)
{
	CONFIG_DATA_T data_type;

	data_type = (CONFIG_DATA_T)qbuf->msg.arg1;
	if(_mib_read_header(data_type, (PARAM_HEADER_Tp)qbuf->msg.mtext) != 1)
		qbuf->request = MSG_FAIL;
	else
		qbuf->request = MSG_SUCC;
}
#endif

static void cfg_mib_update(struct mymsgbuf *qbuf)
{
#ifdef CONFIG_USER_CWMP_TR069
	int cwmp_msgid;
	struct cwmp_message cwmpmsg;
#endif
	CONFIG_DATA_T data_type;
	CONFIG_MIB_T flag;

	qbuf->request = MSG_FAIL;

	data_type = (CONFIG_DATA_T)qbuf->msg.arg1;
	flag = (CONFIG_MIB_T)qbuf->msg.arg2;

#ifdef CONFIG_USER_XMLCONFIG
	if (xml_mib_update(data_type, flag))
		qbuf->request = MSG_SUCC;
#elif CONFIG_USER_CONF_ON_XMLFILE
	if (_mib_update(data_type) != 0)
		qbuf->request = MSG_SUCC;
#else
	if (data_type == CURRENT_SETTING) {
		if (flag == CONFIG_MIB_ALL) {
			if(_mib_update(data_type)!=0)
				qbuf->request = MSG_SUCC;
		}
		else if (flag == CONFIG_MIB_TABLE) {
			PARAM_HEADER_T header;
			unsigned int total_size, table_size;
			unsigned char *buf, *ptr;
			unsigned char *pMibTbl;

			if(__mib_header_read(data_type, &header) != 1)
				return;
			total_size = sizeof(PARAM_HEADER_T) + header.len;
			buf = (unsigned char *)malloc(total_size);
			if (buf == NULL)
				return;
			if(_mib_read_to_raw(data_type, buf, total_size) != 1) {
				free(buf);
				return;
			}
			ptr = buf + sizeof(PARAM_HEADER_T);
			// update the mib table only
			pMibTbl = __mib_get_mib_tbl(data_type);
			memcpy(ptr, pMibTbl, sizeof(MIB_T));
			__mib_content_encod_check(data_type, &header, ptr);
			// update header
			memcpy(buf, (unsigned char*)&header, sizeof(PARAM_HEADER_T));

			if(_mib_update_from_raw(buf, total_size) != 1) {
				free(buf);
				return;
			}
			free(buf);
			qbuf->request = MSG_SUCC;
		}
		else { // not support currently, Jenny added
				//jim we should check the size to make sure of no-exceeded flash range....
				//jim this will called by pppoe.c /pppoe_session_info();
			PARAM_HEADER_T header;
			unsigned int chainRecordSize, mibTblSize, totalSize;
			unsigned char *buf, *ptr;
			unsigned char* pVarLenTable = NULL;
		    	//printf("%s line %d\n", __FUNCTION__, __LINE__);
			if(__mib_header_read(data_type, &header) != 1)
				return;
		    	//printf("%s line %d\n", __FUNCTION__, __LINE__);
			mibTblSize = __mib_content_min_size(data_type);
			chainRecordSize = __mib_chain_all_table_size(data_type);
			header.len = chainRecordSize + mibTblSize;
			totalSize = sizeof(PARAM_HEADER_T) + header.len;
			buf = (unsigned char *)malloc(totalSize);
		    	//printf("%s line %d Totalsize=%d\n", __FUNCTION__, __LINE__, totalSize);
			if (buf == NULL)
				return;
			//jim
			if(totalSize > __mib_content_max_size(data_type))
			{
				printf("too large config paras to store! abadon!\n");
				free(buf);
				return;
			}
		    	//printf("%s line %d\n", __FUNCTION__, __LINE__);
			if(_mib_read_to_raw(data_type, buf, totalSize) != 1) {
				free(buf);
		    	//printf("%s line %d\n", __FUNCTION__, __LINE__);
				return;
			}
			ptr = &buf[sizeof(PARAM_HEADER_T)];	// point to start of MIB data
		    	//printf("%s line %d chainRecordSize=%d\n", __FUNCTION__, __LINE__, chainRecordSize);
			// update the chain record only
			if (chainRecordSize > 0) {
				pVarLenTable = &ptr[mibTblSize];	// point to start of variable length MIB data
				if(__mib_chain_record_content_encod(data_type, pVarLenTable, chainRecordSize) != 1) {
					free(buf);
		    	//printf("%s line %d\n", __FUNCTION__, __LINE__);
					return;
				}
			}
			__mib_content_encod_check(data_type, &header, ptr);
			// update header
			memcpy(buf, (unsigned char*)&header, sizeof(PARAM_HEADER_T));

		    	//printf("%s line %d\n", __FUNCTION__, __LINE__);
			if(_mib_update_from_raw(buf, totalSize) != 1) {
				free(buf);
		    	//printf("%s line %d\n", __FUNCTION__, __LINE__);
				return;
			}
			qbuf->request = MSG_SUCC;
		    	//printf("%s line %d\n", __FUNCTION__, __LINE__);
			free(buf);
		}
	}
	else {
		if(_mib_update(data_type)!=0)
			qbuf->request = MSG_SUCC;
	}
#endif

	if (qbuf->request == MSG_SUCC) {
#ifdef CONFIG_USER_CWMP_TR069
		if ((cwmp_msgid = msgget((key_t) 1234, 0)) > 0) {
			memset(&cwmpmsg, 0, sizeof(cwmpmsg));
			cwmpmsg.msg_type = MSG_ACTIVE_NOTIFY;
			cwmpmsg.msg_datatype = qbuf->msg.arg1;
			msgsnd(cwmp_msgid, &cwmpmsg, MSG_SIZE, IPC_NOWAIT);
		}
#endif

#ifdef CONFIG_USER_XMLCONFIG
#ifdef CONFIG_USER_FLATFSD_XXX
		va_niced_cmd("/bin/flatfsd", 1, 1, "-s");
#endif
#elif CONFIG_USER_RTK_RECOVER_SETTING
		// save config file to flash
		va_cmd("/bin/saveconfig", 1, 0, "-s");
#endif /*CONFIG_USER_XMLCONFIG */
	}
}

/* 2010-10-26 krammer :  */
static void cfg_mib_swap(struct mymsgbuf *qbuf)
{
	int id;

	qbuf->request = MSG_FAIL;

    if (__mib_lock) {
		qbuf->request = MSG_MIB_LOCKED;
		return;
	}

	if(_mib_swap(qbuf->msg.arg1, qbuf->msg.arg2)!=0)
		qbuf->request = MSG_SUCC;
}
/* 2010-10-26 krammer :  */

static void cfg_mib_to_default(struct mymsgbuf *qbuf)
{
	CONFIG_DATA_T data_type;
	qbuf->request = MSG_FAIL;
	data_type = (CONFIG_DATA_T)qbuf->msg.arg1;

	if (__mib_lock) {
		qbuf->request = MSG_MIB_LOCKED;
		return;
	}
	mib_init_mib_with_program_default(data_type, FLASH_DEFAULT_TO_MEMORY);
	qbuf->request = MSG_SUCC;
}

static void cfg_mib_flash_to_default(struct mymsgbuf *qbuf)
{
	CONFIG_DATA_T data_type;
	qbuf->request = MSG_FAIL;
	data_type = (CONFIG_DATA_T)qbuf->msg.arg1;

	if (__mib_lock) {
		qbuf->request = MSG_MIB_LOCKED;
		return;
	}
/* 2013/11 Jiachiam
   Only reset default to ram memory, not write back to flash.
   The latter task is performed by xmlconfig (write back to new xml file).
*/
#ifdef CONFIG_USER_XMLCONFIG
	mib_init_mib_with_program_default(data_type, FLASH_DEFAULT_TO_MEMORY);
#else
	switch (data_type) {
		case CURRENT_SETTING:
			va_cmd("/bin/flash", 2, 1, "default", "cs");
			break;
		case HW_SETTING:
			va_cmd("/bin/flash", 2, 1, "default", "hs");
			break;
		case DEFAULT_SETTING:
		default:
			printf("Not supported type to reset to default.\n");
			return;
	}
#endif /* CONFIG_USER_XMLCONFIG */
	qbuf->request = MSG_SUCC;
}

/** 2013/11 Jiachiam */
#if (defined VOIP_SUPPORT) && (defined CONFIG_USER_XMLCONFIG)
static void cfg_mib_voip_to_default(struct mymsgbuf *qbuf){

       voipCfgParam_t voipEntry;

       qbuf->request = MSG_FAIL;

       if (__mib_lock) {
               qbuf->request = MSG_MIB_LOCKED;
               return;
       }

       _mib_chain_clear(MIB_VOIP_CFG_TBL);
       flash_voip_default(&voipEntry);
       if (_mib_chain_add(MIB_VOIP_CFG_TBL, &voipEntry))
               qbuf->request = MSG_SUCC;

}
#endif /* VOIP_SUPPORT & CONFIG_USER_XMLCONFIG */

static void cfg_mib_get(struct mymsgbuf *qbuf)
{
	int id;

	qbuf->request = MSG_FAIL;

	if(_mib_get(qbuf->msg.arg1, (void *)qbuf->msg.mtext)!=0)
		qbuf->request = MSG_SUCC;
}



static void cfg_mib_get_default(struct mymsgbuf *qbuf)
{
	int id;

	qbuf->request = MSG_FAIL;

	if(_mib_getDef(qbuf->msg.arg1, (void *)qbuf->msg.mtext)!=0)
		qbuf->request = MSG_SUCC;
}

static void cfg_mib_set(struct mymsgbuf *qbuf)
{
#ifdef CONFIG_USER_CWMP_TR069
	int cwmp_msgid;
	struct cwmp_message cwmpmsg;
#endif
#ifdef CONFIG_USER_DBUS_CTC_IGD
	int cmp_result;
#endif

	qbuf->request = MSG_FAIL;

	if (__mib_lock) {
		qbuf->request = MSG_MIB_LOCKED;
		return;
	}

#ifdef CONFIG_USER_DBUS_CTC_IGD
	cmp_result = _mib_cmp(qbuf->msg.arg1, (void *)qbuf->msg.mtext);
#endif

	if (_mib_set(qbuf->msg.arg1, (void *)qbuf->msg.mtext) != 0) {
		qbuf->request = MSG_SUCC;
#ifdef CONFIG_USER_CWMP_TR069
		if (qbuf->msg.arg2) {
			if ((cwmp_msgid = msgget((key_t) 1234, 0)) > 0) {
				memset(&cwmpmsg, 0, sizeof(cwmpmsg));
				cwmpmsg.msg_type = MSG_USERDATA_CHANGE;
				cwmpmsg.msg_datatype = qbuf->msg.arg1;
				msgsnd(cwmp_msgid, &cwmpmsg, MSG_SIZE, IPC_NOWAIT);
			}
		}
#endif
#ifdef CONFIG_USER_DBUS_CTC_IGD
		memcpy((void *)qbuf->msg.mtext, &cmp_result, sizeof(int));
#endif
	}
}

static void cfg_mib_info_id(struct mymsgbuf *qbuf)
{
	int k;

	qbuf->request = MSG_FAIL;

	for (k=0; mib_table[k].id; k++) {
		if (mib_table[k].id == qbuf->msg.arg1)
			break;
	}

	if (mib_table[k].id == 0)
		return;

	memcpy((void *)qbuf->msg.mtext, (void *)&mib_table[k], sizeof(mib_table_entry_T));
	qbuf->request = MSG_SUCC;
}

static void cfg_mib_info_index(struct mymsgbuf *qbuf)
{
	int total;

	qbuf->request = MSG_FAIL;

	total = mib_table_size / sizeof(mib_table[0]);
	if (qbuf->msg.arg1 >= total)
		return;

	memcpy((void *)qbuf->msg.mtext, (void *)&mib_table[qbuf->msg.arg1],
	       sizeof(mib_table_entry_T));
	qbuf->request = MSG_SUCC;
}

// Apply Star Zhang's fast load
static void cfg_mib_info_total(struct mymsgbuf *qbuf)
{
	qbuf->request = MSG_FAIL;

	qbuf->msg.arg1 = mib_table_size / sizeof(mib_table[0]);

	qbuf->request = MSG_SUCC;
}
// The end of fast load
static void cfg_mib_backup_hs(struct mymsgbuf *qbuf)
{
	CONFIG_MIB_T type;
	unsigned char *pMibTbl;

	qbuf->request = MSG_FAIL;
	type = (CONFIG_MIB_T)qbuf->msg.arg1;
	printf("%s-%d: type=%d\n", __func__,__LINE__,type);

	if (type == CONFIG_MIB_ALL || type == CONFIG_MIB_TABLE) {
		pMibTbl = __mib_get_mib_tbl(HW_SETTING);
		memcpy(&table_backup, pMibTbl, sizeof(MIB_T));  //save setting
		printf("%s-%d: type=%d\n", __func__,__LINE__,type);		
	}
	printf("%s-%d: type=%d\n", __func__,__LINE__,type);

	qbuf->request = MSG_SUCC;

}

static void cfg_mib_backup(struct mymsgbuf *qbuf)
{
	CONFIG_MIB_T type;
	unsigned char *pMibTbl;

	qbuf->request = MSG_FAIL;
	type = (CONFIG_MIB_T)qbuf->msg.arg1;

	if (type == CONFIG_MIB_ALL || type == CONFIG_MIB_TABLE) {
		pMibTbl = __mib_get_mib_tbl(CURRENT_SETTING);
		memcpy(&table_backup, pMibTbl, sizeof(MIB_T));  //save setting
	}

	if (type == CONFIG_MIB_ALL || type == CONFIG_MIB_CHAIN)
	{
		backupChainSize = __mib_chain_all_table_size(CURRENT_SETTING);

		if(backupChainSize>0)
		{
			chain_backup = realloc(chain_backup, backupChainSize);
			if(__mib_chain_record_content_encod(CURRENT_SETTING, chain_backup, backupChainSize) != 1)
				return;
		}
	}
	else
		return;

	qbuf->request = MSG_SUCC;
}
#ifdef CONFIG_USER_DBUS_CTC_IGD
static void cfg_mib_backup_ctc(struct mymsgbuf *qbuf)
{
	CONFIG_MIB_T type;
	unsigned char *pMibTbl;

	qbuf->request = MSG_FAIL;
	type = (CONFIG_MIB_T)qbuf->msg.arg1;

	if (type == CONFIG_MIB_ALL || type == CONFIG_MIB_TABLE) {
		pMibTbl = __mib_get_mib_tbl(CURRENT_SETTING);
		memcpy(&ctc_table_backup, pMibTbl, sizeof(MIB_T));  //save setting
	}

	if (type == CONFIG_MIB_ALL || type == CONFIG_MIB_CHAIN)
	{
		ctc_backupChainSize = __mib_chain_all_table_size(CURRENT_SETTING);

		if(ctc_backupChainSize>0)
		{
			ctc_chain_backup = realloc(ctc_chain_backup, ctc_backupChainSize);
			if(__mib_chain_record_content_encod(CURRENT_SETTING, ctc_chain_backup, ctc_backupChainSize) != 1)
				return;
		}
	}
	else
		return;

	qbuf->request = MSG_SUCC;
}
#endif
//added by ql
#ifdef	RESERVE_KEY_SETTING
static void cfg_retrieve_table(struct mymsgbuf *qbuf)
{
	int id;

	qbuf->request = MSG_FAIL;
	id = qbuf->msg.arg1;

	mib_table_record_retrive(id);

	qbuf->request = MSG_SUCC;
}
static void cfg_retrieve_chain(struct mymsgbuf *qbuf)
{
	int id;

	qbuf->request = MSG_FAIL;
	id = qbuf->msg.arg1;

	mib_chain_record_retrive(id);

	qbuf->request = MSG_SUCC;
}
#endif

static void cfg_mib_restore(struct mymsgbuf *qbuf)
{
	CONFIG_MIB_T type;
	unsigned char *pMibTbl;

	qbuf->request = MSG_FAIL;
	type = (CONFIG_MIB_T)qbuf->msg.arg1;

	if (type == CONFIG_MIB_ALL || type == CONFIG_MIB_TABLE)
	{
		pMibTbl = __mib_get_mib_tbl(CURRENT_SETTING);
		memcpy(pMibTbl, &table_backup, sizeof(MIB_T));  //restore setting
	}

	if (type == CONFIG_MIB_ALL || type == CONFIG_MIB_CHAIN)
			{
		__mib_chain_all_table_clear(CURRENT_SETTING);
		if(backupChainSize > 0)
		{
			// parse variable length MIB data
			if( __mib_chain_record_content_decod(chain_backup, backupChainSize) != 1)
				return;
			}
		}
	else
		return;

	qbuf->request = MSG_SUCC;
}
#ifdef CONFIG_USER_DBUS_CTC_IGD
static void cfg_mib_restore_ctc(struct mymsgbuf *qbuf)
{
	CONFIG_MIB_T type;
	unsigned char *pMibTbl;

	qbuf->request = MSG_FAIL;
	type = (CONFIG_MIB_T)qbuf->msg.arg1;

	if (type == CONFIG_MIB_ALL || type == CONFIG_MIB_TABLE)
	{
		pMibTbl = __mib_get_mib_tbl(CURRENT_SETTING);
		memcpy(pMibTbl, &ctc_table_backup, sizeof(MIB_T));  //restore setting
	}

	if (type == CONFIG_MIB_ALL || type == CONFIG_MIB_CHAIN)
			{
		__mib_chain_all_table_clear(CURRENT_SETTING);
		if(ctc_backupChainSize > 0)
		{
			// parse variable length MIB data
			if( __mib_chain_record_content_decod(ctc_chain_backup, ctc_backupChainSize) != 1)
				return;
			}
		}
	else
		return;

	qbuf->request = MSG_SUCC;
}
#endif
static void cfg_chain_total(struct mymsgbuf *qbuf)
{
	qbuf->request = MSG_FAIL;

	qbuf->msg.arg1 = _mib_chain_total(qbuf->msg.arg1);
	qbuf->request = MSG_SUCC;
}

static void cfg_chain_get(struct mymsgbuf *qbuf)
{
	int index, entryNo;
	void *pEntry;

	qbuf->request = MSG_FAIL;
	index = __mib_chain_mib2tbl_id(qbuf->msg.arg1);
	if (index == -1)
		return;

	entryNo = atoi(qbuf->msg.mtext);
	pEntry = _mib_chain_get(qbuf->msg.arg1, entryNo);
	if (pEntry) {
		#ifdef USE_SHM
		memcpy(shm_start, pEntry, mib_chain_record_table[index].per_record_size);
		#else
		memcpy(qbuf->msg.mtext, pEntry, mib_chain_record_table[index].per_record_size);
		#endif
		qbuf->request = MSG_SUCC;
	}
	else
		qbuf->request = MSG_FAIL;
}

static void cfg_chain_backup_get(struct mymsgbuf *qbuf)
{
	int index, entryNo;
	void *pEntry;

	qbuf->request = MSG_FAIL;
	index = __mib_chain_mib2tbl_id(qbuf->msg.arg1);
	if (index == -1)
		return;

	entryNo = atoi(qbuf->msg.mtext);
	pEntry = __mib_chain_get_backup_record(qbuf->msg.arg1, entryNo, chain_backup, backupChainSize);
	if (pEntry) {
		#ifdef USE_SHM
		memcpy(shm_start, pEntry, mib_chain_record_table[index].per_record_size);
		#else
		memcpy(qbuf->msg.mtext, pEntry, mib_chain_record_table[index].per_record_size);
		#endif
		qbuf->request = MSG_SUCC;
	}
	else
		qbuf->request = MSG_FAIL;
}


static void cfg_chain_add(struct mymsgbuf *qbuf)
{
	qbuf->request = MSG_FAIL;

	if (__mib_lock) {
		qbuf->request = MSG_MIB_LOCKED;
		return;
	}

	#ifdef USE_SHM
	if (_mib_chain_add(qbuf->msg.arg1, shm_start)) {
	#else
	if (_mib_chain_add(qbuf->msg.arg1, qbuf->msg.mtext)) {
	#endif
		qbuf->request = MSG_SUCC;
	}
	else
		qbuf->request = MSG_FAIL;
}

static void cfg_chain_delete(struct mymsgbuf *qbuf)
{
	int entryNo;

	qbuf->request = MSG_FAIL;
	entryNo = atoi(qbuf->msg.mtext);

	if (__mib_lock) {
		qbuf->request = MSG_MIB_LOCKED;
		return;
	}

	if (_mib_chain_delete(qbuf->msg.arg1, entryNo)) {
		qbuf->request = MSG_SUCC;
	}
	else
		qbuf->request = MSG_FAIL;
}

static void cfg_chain_clear(struct mymsgbuf *qbuf)
{
	qbuf->request = MSG_FAIL;

	if (__mib_lock) {
		qbuf->request = MSG_MIB_LOCKED;
		return;
	}

	_mib_chain_clear(qbuf->msg.arg1);
	qbuf->request = MSG_SUCC;
}

static void cfg_chain_update(struct mymsgbuf *qbuf)
{
	int index;
	void *pEntry;
#ifdef CONFIG_USER_DBUS_CTC_IGD
	char *ctc_igd_shm_second;
#endif

	qbuf->request = MSG_FAIL;

	if (__mib_lock) {
		qbuf->request = MSG_MIB_LOCKED;
		return;
	}

	index = __mib_chain_mib2tbl_id(qbuf->msg.arg1);
	if (index == -1)
		return;
	pEntry = _mib_chain_get(qbuf->msg.arg1, qbuf->msg.arg2);

#ifdef CONFIG_USER_DBUS_CTC_IGD
	if (pEntry)
		memcpy(ctc_igd_shm_start, pEntry, mib_chain_record_table[index].per_record_size);

	//ctc_igd_shm_second = ctc_igd_shm_start+mib_chain_record_table[index].per_record_size;

	memcpy(ctc_igd_shm_start+mib_chain_record_table[index].per_record_size , shm_start, mib_chain_record_table[index].per_record_size);
#endif

	if (pEntry)
		#ifdef USE_SHM
		memcpy(pEntry, shm_start, mib_chain_record_table[index].per_record_size);
		#else
		memcpy(pEntry, qbuf->msg.mtext, mib_chain_record_table[index].per_record_size);
		#endif
	else
		return;
	#ifdef USE_SHM
	if (_mib_chain_update(qbuf->msg.arg1, shm_start, qbuf->msg.arg2)) {
	#else
	if (_mib_chain_update(qbuf->msg.arg1, qbuf->msg.mtext, qbuf->msg.arg2)) {
	#endif
		qbuf->request = MSG_SUCC;
	}
	else
		qbuf->request = MSG_FAIL;
}

/* cathy, to swap entry A and B of a chain */
static void cfg_chain_swap(struct mymsgbuf *qbuf)
{
	int index, id;
	void *pEntryA, *pEntryB, *tmpEntry;

	qbuf->request = MSG_FAIL;

	if (__mib_lock) {
		qbuf->request = MSG_MIB_LOCKED;
		return;
	}

	id = atoi(qbuf->msg.mtext);
	index = __mib_chain_mib2tbl_id(id);
	if (index == -1)
		return;

	pEntryA = _mib_chain_get(id, qbuf->msg.arg1);
	pEntryB = _mib_chain_get(id, qbuf->msg.arg2);

	if(!pEntryA || !pEntryB) {
		printf("%s: cannot find entry!\n", __func__);
		return;
	}

	tmpEntry = malloc(mib_chain_record_table[index].per_record_size);
	if(!tmpEntry) {
		printf("%s: cannot allocate memory!\n", __func__);
		return;
	}

	//swap pEntryA and pEntryB
	memcpy(tmpEntry, pEntryA, mib_chain_record_table[index].per_record_size);
	memcpy(pEntryA, pEntryB, mib_chain_record_table[index].per_record_size);
	memcpy(pEntryB, tmpEntry, mib_chain_record_table[index].per_record_size);

	free(tmpEntry);
	qbuf->request = MSG_SUCC;
}

static void cfg_chain_info_id(struct mymsgbuf *qbuf)
{
	int index;

	qbuf->request = MSG_FAIL;

	index = __mib_chain_mib2tbl_id(qbuf->msg.arg1);
	if (index == -1)
		return;

	memcpy((void *)qbuf->msg.mtext, (void *)&mib_chain_record_table[index], sizeof(mib_chain_record_table_entry_T));
	qbuf->request = MSG_SUCC;
}

static void cfg_chain_info_index(struct mymsgbuf *qbuf)
{
	int total;
	int i;

	qbuf->request = MSG_FAIL;

	for (i=0; mib_chain_record_table[i].id; i++);
	total = i+1;
	if (qbuf->msg.arg1>=total)
		return;

	memcpy((void *)qbuf->msg.mtext, (void *)&mib_chain_record_table[qbuf->msg.arg1], sizeof(mib_chain_record_table_entry_T));
	qbuf->request = MSG_SUCC;
}

static void cfg_chain_info_name(struct mymsgbuf *qbuf)
{
	int total;
	int i;

	qbuf->request = MSG_FAIL;

	for (i=0; mib_chain_record_table[i].id; i++) {
		if (!strcmp(mib_chain_record_table[i].name, qbuf->msg.mtext))
			break;
	}

	if (mib_chain_record_table[i].id == 0)
		return; // not found

	memcpy((void *)qbuf->msg.mtext, (void *)&mib_chain_record_table[i], sizeof(mib_chain_record_table_entry_T));
	qbuf->request = MSG_SUCC;
}

static int verify_desc(mib_chain_member_entry_T *rec_desc, char *name, int rec_size, int depth)
{
	int k, count_size, verdict;
	int ret;
	
	verdict = 1;
	
	if (!rec_desc) {
		printf("Error: Null MIB-chain(%s) record descriptor !\n", name);
		return -1;
	}
	
	k = 0; count_size = 0;
	while (rec_desc[k].name[0] != 0) {
		if (rec_desc[k].type == OBJECT_T) {
			ret = verify_desc(rec_desc[k].record_desc, rec_desc[k].name, rec_desc[k].size, depth+1);
			if (ret==-1)
				verdict = -1;
		}
		count_size += rec_desc[k].size;
		k++;
	}
	if (depth == 1) { // root chain rec_size is per-record size
		if (count_size != rec_size) {
			printf("Error: MIB chain %s descriptor not consistent with data structure !\n", name);
			verdict = -1;
		}
	}
	else { // child chain(object) rec_size is total object size(multiplier of count_size)
		if (rec_size%count_size) {
			printf("Error: MIB object %s descriptor not consistent with data structure !\n", name);
			verdict = -1;
		}
	}
	return verdict;
}

/*
 * Check the consistency between chain records and their record descriptors.
 * Return msg.arg1:
 *	1: checking ok
 *	-1: checking failed
 */
static void cfg_check_desc(struct mymsgbuf *qbuf)
{
	mib_chain_member_entry_T *rec_desc;
	int i, k, count_size, verdict, ret=1;

	qbuf->request = MSG_FAIL;
	verdict = 1;

	for (i=0; mib_chain_record_table[i].id; i++) {
		rec_desc = mib_chain_record_table[i].record_desc;
		if (!rec_desc) {
			printf("Error: Null MIB-chain(%s) record descriptor !\n", mib_chain_record_table[i].name);
			verdict = -1;
			continue;
		}
		ret=verify_desc(rec_desc, mib_chain_record_table[i].name, mib_chain_record_table[i].per_record_size, 1);
		if(ret==-1)
			verdict = -1;
	}

	printf("MIB chain descriptors checking (total %d) %s !\n", i, verdict==1?"ok":"failed");
	qbuf->msg.arg1 = verdict;
	qbuf->request = MSG_SUCC;
}

/*
 *	reload hs	---	reload hardware setting
 *	reload cs	---	reload current setting
 *	reload ds	---	reload default setting
 */
static void cfg_mib_reload(struct mymsgbuf *qbuf)
{
	CONFIG_DATA_T data_type;
	CONFIG_MIB_T flag;
	qbuf->request = MSG_FAIL;

	if (__mib_lock) {
		qbuf->request = MSG_MIB_LOCKED;
		return;
	}

#ifndef CONFIG_USER_XMLCONFIG
	data_type = (CONFIG_DATA_T)qbuf->msg.arg1;
	flag = (CONFIG_MIB_T)qbuf->msg.arg2;

	if (data_type == CURRENT_SETTING) {
		if (flag == CONFIG_MIB_ALL) {
			if(_mib_load(data_type)!=0)
				qbuf->request = MSG_SUCC;
		}
		else if (flag == CONFIG_MIB_TABLE) {
			if (mib_load_table(data_type)!=0)
				qbuf->request = MSG_SUCC;
		}
		else { // not support currently, Jenny added
			if (mib_load_chain(data_type)!=0)
				qbuf->request = MSG_SUCC;
		}
	}
	else {
		if(_mib_load(data_type)!=0)
			qbuf->request = MSG_SUCC;
	}
#else
	qbuf->request = MSG_SUCC;
#endif
}



#ifdef EMBED

#if (defined(CONFIG_USB_ARCH_HAS_XHCI) && defined(CONFIG_USB_XHCI_HCD))
void unbind_xhci_driver()
{

	/* This function is for USB XHCI driver unload, because some USB 3.0
	 * device need this step, then after  reboot could set configuration
	 * successfully
	 */
	if (0 == access("/sys/bus/usb/devices/1-2/driver/", F_OK)) {
		if(0 == access("/sys/bus/usb/devices/1-2/driver/1-2.1",F_OK))
		{
			printf("echo 1-2.1 >  /sys/bus/usb/devices/1-2/driver/unbind\n");
			system("echo 1-2.1 > /sys/bus/usb/devices/1-2/driver/unbind");
		}
		if(0 == access("/sys/bus/usb/devices/1-2/driver/1-2.2",F_OK))
		{
			printf("echo 1-2.2 >  /sys/bus/usb/devices/1-2/driver/unbind\n");
			system("echo 1-2.2 > /sys/bus/usb/devices/1-2/driver/unbind");
		}
		if(0 == access("/sys/bus/usb/devices/1-2/driver/1-2.3",F_OK))
		{
			printf("echo 1-2.3 >  /sys/bus/usb/devices/1-2/driver/unbind\n");
			system("echo 1-2.3 > /sys/bus/usb/devices/1-2/driver/unbind");
		}
		if(0 == access("/sys/bus/usb/devices/1-2/driver/1-2.4",F_OK))
		{
			printf("echo 1-2.4 >  /sys/bus/usb/devices/1-2/driver/unbind\n");
			system("echo 1-2.4 > /sys/bus/usb/devices/1-2/driver/unbind");
		}
		if(0==access("/sys/bus/usb/devices/1-2/driver/1-2", F_OK))
		{
			printf("echo 1-2 >  /sys/bus/usb/devices/1-2/driver/unbind\n");
			system("echo 1-2 > /sys/bus/usb/devices/1-2/driver/unbind");
		}
	}
}
#endif


static void *sysReboot(void *arg)
{

#ifdef CONFIG_E8B
	syslog(LOG_INFO, "104001 System reboot.");
#ifdef _PRMT_X_CT_COM_ALARM_MONITOR_
	set_ctcom_alarm(CTCOM_ALARM_DEV_RESTART);
#endif
#endif
#ifdef CONFIG_USER_RTK_OMD
	if(is_terminal_reboot() )
		write_omd_reboot_log(TERMINAL_REBOOT);
#ifdef CONFIG_CLASSFY_MAGICNUM_SUPPORT
	system("diag switch set magic-key 0xFFFFFFFF &> /dev/null");
#elif defined(CONFIG_LUNA_WDT_KTHREAD)
	system("echo clear > /proc/luna_watchdog/previous_wdt_reset");
#endif
#endif

	// wait for configuration write to flash in some cases.
	sleep(5);

#if (defined(CONFIG_USB_ARCH_HAS_XHCI) && defined(CONFIG_USB_XHCI_HCD))
	unbind_xhci_driver();
#endif

#ifdef CONFIG_PPP
	// Jenny, disconnect PPP before rebooting
	stopPPP();
#endif
#if defined(CONFIG_RTL867X_NETLOG) && defined(CONFIG_USER_NETLOGGER_SUPPORT)
	va_niced_cmd("/bin/netlogger", 1, 1, "disable");
#endif

#ifdef CONFIG_VIRTUAL_WLAN_DRIVER
	system("echo 1 > /proc/vwlan");
#endif

	sync();
	itfcfg("eth0", 0);
	itfcfg("wlan0", 0);

#ifdef E8B_NEW_DIAGNOSE
	FILE *fp1;
	int vint;
	int num = 0;
	while(1) {
		fp1 = fopen(REBOOT_DELAY_FILE, "r");
		if (fp1) {
			fscanf(fp1, "%d", &vint);
			fclose(fp1);
			if (vint == 0) {
				unlink(REBOOT_DELAY_FILE);
				break;
			}
		} else
			break;
		sleep(1);
		num ++;
		if (num >= 10)
			break;
	}
#endif
	/* reboot the system */
	reboot(RB_AUTOBOOT);

	return NULL;
}

static void cfg_reboot(struct mymsgbuf *qbuf)
{
	pthread_t ptRebootId;

	pthread_create(&ptRebootId, NULL, sysReboot, NULL);
	pthread_detach(ptRebootId);

	qbuf->request = MSG_SUCC;
}

#ifdef CONFIG_IPV6
#if defined(CONFIG_USER_DHCPV6_ISC_DHCP411)
int _option_name_server(FILE *fp)
{
	unsigned int entryNum, i;
	MIB_DHCPV6S_NAME_SERVER_Tp pEntry;
	unsigned char strAll[(MAX_V6_IP_LEN+2)*MAX_DHCPV6_CHAIN_ENTRY]="";

	entryNum = _mib_chain_total(MIB_DHCPV6S_NAME_SERVER_TBL);

	for (i=0; i<entryNum; i++) {
		unsigned char buf[MAX_V6_IP_LEN+2]="";

		pEntry = (MIB_DHCPV6S_NAME_SERVER_Tp) _mib_chain_get(MIB_DHCPV6S_NAME_SERVER_TBL, i);

		if ( i< (entryNum-1) )
		{
			sprintf(buf, "%s, ", pEntry->nameServer);
		} else
			sprintf(buf, "%s", pEntry->nameServer);
		strcat(strAll, buf);
	}

	if ( entryNum > 0 )
	{
		//printf("strAll=%s\n", strAll);
		fprintf(fp, "option dhcp6.name-servers %s;\n", strAll);
	}

	return 0;
}

int _option_domain_search(FILE *fp)
{
	unsigned int entryNum, i;
	MIB_DHCPV6S_DOMAIN_SEARCH_Tp pEntry;
	unsigned char strAll[(MAX_DOMAIN_LENGTH+4)*MAX_DHCPV6_CHAIN_ENTRY]="";

	entryNum = _mib_chain_total(MIB_DHCPV6S_DOMAIN_SEARCH_TBL);

	for (i=0; i<entryNum; i++) {
		unsigned char buf[MAX_DOMAIN_LENGTH+4]="";

		pEntry = (MIB_DHCPV6S_DOMAIN_SEARCH_Tp) _mib_chain_get(MIB_DHCPV6S_DOMAIN_SEARCH_TBL, i);

		if ( i< (entryNum-1) )
		{
			sprintf(buf, "\"%s\", ", pEntry->domain);
		} else
			sprintf(buf, "\"%s\"", pEntry->domain);
		strcat(strAll, buf);
	}

	if ( entryNum > 0 )
	{
		//printf("strAll(domain)=%s\n", strAll);
		fprintf(fp, "option dhcp6.domain-search %s;\n", strAll);
	}

	return 0;
}

#if 0
int _setup_dhcpdv6_conf(DLG_INFO_Tp pDLGInfo)
{
	FILE *fp;
	unsigned int DLTime, PFTime, RNTime, RBTime;
	unsigned char vChar;
	struct in6_addr ip6Addr, ip6Prefix;
	int k;
	unsigned char value[MAX_V6_IP_LEN];
	unsigned char value2[MAX_V6_IP_LEN];
	unsigned char value3[MAX_DUID_LEN];
	unsigned char 	Ipv6AddrStr[48];

	if ((fp = fopen(DHCPDV6_CONF_AUTO, "w")) == NULL)
	{
		printf("Open file %s failed !\n", DHCPDV6_CONF_AUTO);
		return;
	}

	fprintf(fp, "preferred-lifetime %u;\n", pDLGInfo->PLTime);
	fprintf(fp, "default-lease-time %u;\n", pDLGInfo->MLTime);
	fprintf(fp, "option dhcp-renewal-time %u;\n", pDLGInfo->RNTime);
	fprintf(fp, "option dhcp-rebinding-time %u;\n", pDLGInfo->RBTime);

#ifdef CONFIG_E8B
	//e8 need to set IPV6_LAN_IP_ADDR as DNSv6 server(DNSv6 relay)
	if ( !_mib_get(MIB_IPV6_LAN_IP_ADDR, (void *)Ipv6AddrStr)) {
		printf("Get IPV6_LAN_IP_ADDR mib error!");
	}
	else{
		fprintf(fp, "option dhcp6.name-servers %s;\n", Ipv6AddrStr);
	}
#else
	fprintf(fp, "option dhcp6.name-servers %s;\n", pDLGInfo->nameServer);
#endif
#if 0
	// Option dhcp6.name-servers
	_option_name_server(fp);

	// Option dhcp6.domain-search
	_option_domain_search(fp);

	// option dhcp6.client-id 00:01:00:01:00:04:93:e0:00:00:00:00:a2:a2;
	if ( !_mib_get(MIB_DHCPV6S_CLIENT_DUID, (void *)value3)) {
		printf("Get MIB_DHCPV6S_CLIENT_DUID mib error!");
		return -1;
	}
	if (value3[0]) {
		fprintf(fp, "option dhcp6.client-id %s;\n", value3);
	}
#endif
	// subnet6 3ffe:501:ffff:100::/64 {
	inet_ntop(PF_INET6, (struct in6_addr *)pDLGInfo->prefixIP, Ipv6AddrStr, sizeof(Ipv6AddrStr));
	fprintf(fp, "subnet6 %s/%d {\n", Ipv6AddrStr, pDLGInfo->prefixLen);
	fprintf(fp, "\trange6 %s/%d;\n", Ipv6AddrStr, pDLGInfo->prefixLen);
	fprintf(fp, "}\n");
	fclose(fp);

	if ((fp = fopen(DHCPDV6_LEASES, "w")) == NULL)
	{
		printf("Open file %s failed !\n", DHCPDV6_LEASES);
		return;
	}
	fclose(fp);

	return 1;

}

int _start_dhcpv6(int enable, DLG_INFO_Tp pDLGInfo)
{
	unsigned char value[64];
	unsigned char vChar;
	int tmp_status, status=0;
	unsigned int uInt, i;
	DHCP_TYPE_T mode;
	int dhcpserverpid=0;
	struct in6_addr ip6Addr, targetIp;
	unsigned char devAddr[MAC_ADDR_LEN];
	unsigned char meui64[8];

	mode = DHCP_LAN_NONE;
	if (_mib_get(MIB_DHCPV6_MODE, (void *)value) != 0)
	{
		mode = (DHCP_TYPE_T)(*(unsigned char *)value);
	}
	if ( (mode != DHCP_LAN_SERVER_AUTO) )
	{
		//Even the MODE is not auto, setup the config file for future usage
		tmp_status = _setup_dhcpdv6_conf(pDLGInfo);
		return 1;
	}

	dhcpserverpid = read_pid((char*)DHCPSERVER6PID);

	if(dhcpserverpid > 0)
	{
		kill(dhcpserverpid, SIGTERM);

		i = 0;
		while (kill(dhcpserverpid, 0) == 0 && i < 20) {
			usleep(100000); i++;
		}
		if(i >= 20 )
			kill(dhcpserverpid, SIGKILL);
		
		if(!access(DHCPSERVER6PID, F_OK)) unlink(DHCPSERVER6PID);
	}

	// Delete LAN IP which is set by manual
	_mib_get(MIB_DHCPV6S_PREFIX_LENGTH, (void *)&vChar);
	_mib_get(MIB_DHCPV6S_RANGE_START, (void *)ip6Addr.s6_addr);
	uInt = (int)vChar;
	if (uInt<=0 || uInt > 128) {
		printf("WARNNING! Prefix Length == %d\n", uInt);
		uInt = 64;
	}
	ip6toPrefix(&ip6Addr, uInt, &targetIp);
	_mib_get(MIB_ELAN_MAC_ADDR, (void *)devAddr);
	mac_meui64(devAddr, meui64);
	for (i=0; i<8; i++)
		targetIp.s6_addr[i+8] = meui64[i];
	inet_ntop(PF_INET6, &targetIp, value, sizeof(value));
	sprintf(value, "%s/%d", value, uInt);
	va_cmd(IFCONFIG, 3, 1, LANIF, "del", value);

	// Set LAN IP which is set by auto
	uInt = pDLGInfo->prefixLen;
	if (uInt<=0 || uInt > 128) {
		printf("WARNNING! Prefix Length == %d\n", uInt);
		uInt = 64;
	}
	ip6toPrefix((struct in6_addr *)pDLGInfo->prefixIP, uInt, &targetIp);
	_mib_get(MIB_ELAN_MAC_ADDR, (void *)devAddr);
	mac_meui64(devAddr, meui64);
	for (i=0; i<8; i++)
		targetIp.s6_addr[i+8] = meui64[i];
	inet_ntop(PF_INET6, &targetIp, value, sizeof(value));
	sprintf(value, "%s/%d", value, uInt);
	if (enable)
		va_cmd(IFCONFIG, 3, 1, LANIF, "add", value);


	if (!enable)
		return 1;

	tmp_status = _setup_dhcpdv6_conf(pDLGInfo);
	if (tmp_status == 1)
	{
		// dhcpd -6 -cf /var/dhcpdv6.conf -lf /var/dhcpd6.leases br0
		status = va_niced_cmd(DHCPDV6, 6, 0, "-6", "-cf", DHCPDV6_CONF_AUTO, "-lf", DHCPDV6_LEASES, BRIF);

		//while(read_pid((char*)DHCPSERVER6PID) < 0)
		//	usleep(250000);
	}
	else if (tmp_status == -1)
	 	status = -1;

	return status;
}

void _setup_radvd_conf(int resync, DLG_INFO_Tp pDLGInfo, DLG_INFO_Tp pOldDLGInfo)
{
	FILE *fp;
	unsigned char str[MAX_RADVD_CONF_PREFIX_LEN];
	unsigned char str2[MAX_RADVD_CONF_PREFIX_LEN];
	unsigned char vChar,vChar2;
	int radvdpid;
	unsigned char 	Ipv6AddrStr[48];
	unsigned char mode;
	unsigned char prefix_enable = 0;

	_mib_get(MIB_V6_PREFIX_MODE, (void *)&mode);
	if ( mode != 0 )   // It is Manual config.
		return;

	if ((fp = fopen(RADVD_CONF, "w")) == NULL)
	{
		printf("Open file %s failed !\n", RADVD_CONF);
		return;
	}

	fprintf(fp, "interface br0\n");
	fprintf(fp, "{\n");

	// AdvSendAdvert
	if ( !_mib_get( MIB_V6_SENDADVERT, (void *)&vChar) )
		printf("Get MIB_V6_SENDADVERT error!");
	if (0 == vChar)
		fprintf(fp, "\tAdvSendAdvert off;\n");
	else if (1 == vChar)
		fprintf(fp, "\tAdvSendAdvert on;\n");

	// MaxRtrAdvIntervalAct
	if ( !_mib_get(MIB_V6_MAXRTRADVINTERVAL, (void *)str)) {
		printf("Get MaxRtrAdvIntervalAct mib error!");
	}
	if (str[0]) {
		fprintf(fp, "\tMaxRtrAdvInterval %s;\n", str);
	}

	// MinRtrAdvIntervalAct
	if ( !_mib_get(MIB_V6_MINRTRADVINTERVAL, (void *)str)) {
		printf("Get MinRtrAdvIntervalAct mib error!");
	}
	if (str[0]) {
		fprintf(fp, "\tMinRtrAdvInterval %s;\n", str);
	}

	// AdvCurHopLimitAct
	if ( !_mib_get(MIB_V6_ADVCURHOPLIMIT, (void *)str)) {
		printf("Get AdvCurHopLimitAct mib error!");
	}
	if (str[0]) {
		fprintf(fp, "\tAdvCurHopLimit %s;\n", str);
	}

	// AdvDefaultLifetime
	if ( !_mib_get(MIB_V6_ADVDEFAULTLIFETIME, (void *)str)) {
		printf("Get AdvDefaultLifetime mib error!");
	}
	if (str[0]) {
		fprintf(fp, "\tAdvDefaultLifetime %s;\n", str);
	}

	// AdvReachableTime
	if ( !_mib_get(MIB_V6_ADVREACHABLETIME, (void *)str)) {
		printf("Get AdvReachableTime mib error!");
	}
	if (str[0]) {
		fprintf(fp, "\tAdvReachableTime %s;\n", str);
	}

	// AdvRetransTimer
	if ( !_mib_get(MIB_V6_ADVRETRANSTIMER, (void *)str)) {
		printf("Get AdvRetransTimer mib error!");
	}
	if (str[0]) {
		fprintf(fp, "\tAdvRetransTimer %s;\n", str);
	}

	// AdvLinkMTU
	if ( !_mib_get(MIB_V6_ADVLINKMTU, (void *)str)) {
		printf("Get AdvLinkMTU mib error!");
	}
	if (str[0]) {
		fprintf(fp, "\tAdvLinkMTU %s;\n", str);
	}

	// AdvManagedFlag
	if ( !_mib_get( MIB_V6_MANAGEDFLAG, (void *)&vChar) )
		printf("Get MIB_V6_MANAGEDFLAG error!");
	if (0 == vChar)
		fprintf(fp, "\tAdvManagedFlag off;\n");
	else if (1 == vChar)
		fprintf(fp, "\tAdvManagedFlag on;\n");

	// AdvOtherConfigFlag
	if ( !_mib_get( MIB_V6_OTHERCONFIGFLAG, (void *)&vChar) )
		printf("Get MIB_V6_OTHERCONFIGFLAG error!");
	if (0 == vChar)
		fprintf(fp, "\tAdvOtherConfigFlag off;\n");
	else if (1 == vChar)
		fprintf(fp, "\tAdvOtherConfigFlag on;\n");

	//NOTE: in radvd.conf
	//      Prefix/clients/route/RDNSS configurations must be given in exactly this order.

	// Prefix

	// ULA Prefix
	_mib_get (MIB_V6_ULAPREFIX_ENABLE, (void *)&vChar);
	if (vChar!=0) {
		unsigned char validtime[MAX_RADVD_CONF_PREFIX_LEN];
		unsigned char preferedtime[MAX_RADVD_CONF_PREFIX_LEN];

		if ( !_mib_get(MIB_V6_ULAPREFIX, (void *)str)       ||
	         !_mib_get(MIB_V6_ULAPREFIX_LEN, (void *)str2)  ||
	         !_mib_get(MIB_V6_ULAPREFIX_VALID_TIME, (void *)validtime)  ||
	         !_mib_get(MIB_V6_ULAPREFIX_PREFER_TIME, (void *)preferedtime)
			)
		{
			printf("Get ULAPREFIX mib error!");
		}
		else
		{
			unsigned char ip6Addr[IP6_ADDR_LEN];
			unsigned char devAddr[MAC_ADDR_LEN];
			unsigned char meui64[8];
			unsigned char value[64];
			int i;

			fprintf(fp, "\t\n");
			fprintf(fp, "\tprefix %s/%s\n", str, str2);
			fprintf(fp, "\t{\n");
			fprintf(fp, "\t\tAdvOnLink on;\n");
			fprintf(fp, "\t\tAdvAutonomous on;\n");
			fprintf(fp, "\t\tAdvValidLifetime %s;\n",validtime);
			fprintf(fp, "\t\tAdvPreferredLifetime %s;\n",preferedtime);
			fprintf(fp, "\t};\n");

			inet_pton(PF_INET6, str, (void *) ip6Addr);

			//setup LAN ULA v6 IP address according the ULA prefix + EUI64.
			_mib_get(MIB_ELAN_MAC_ADDR, (void *)devAddr);
			mac_meui64(devAddr, meui64);
			for (i=0; i<8; i++)
				ip6Addr[i+8] = meui64[i];
			inet_ntop(PF_INET6, &ip6Addr, value, sizeof(value));
			sprintf(value, "%s/%s", value, str2);

			printf("Set LAN ULA %s\n",value);
			va_cmd(IFCONFIG, 3, 1, LANIF, "del", value);
			va_cmd(IFCONFIG, 3, 1, LANIF, "add", value);
		}
	}

	_mib_get( MIB_V6_PREFIX_ENABLE, (void *)&vChar2);
    if( vChar2 == 1)
	{
		if(pOldDLGInfo){ //Make old prefix, let it be expired
			unsigned int twoHour=2*60*60;  //in seconds
			unsigned int validLifeTime = (pOldDLGInfo->MLTime<twoHour)?pOldDLGInfo->MLTime:twoHour;

			// Now deal with RFC6204, L-13:
			//			 If the delegated prefix changes, i.e., the current prefix is
			//           replaced with a new prefix without any overlapping time
			//           period, then the IPv6 CE router MUST immediately advertise the
			//           old prefix with a Preferred Lifetime of zero and a Valid
			//           Lifetime of the lower of the current Valid Lifetime and 2
			//           hours (which must be decremented in real time) in a Router
			//           Advertisement message as described in Section 5.5.3, (e) of
			//           [RFC4862].
			//
			fprintf(fp, "\t\n");
			inet_ntop(PF_INET6, (struct in6_addr *)pOldDLGInfo->prefixIP, Ipv6AddrStr, sizeof(Ipv6AddrStr));
			fprintf(fp, "\tprefix %s/%d\n", Ipv6AddrStr, pOldDLGInfo->prefixLen);
			fprintf(fp, "\t{\n");

			// AdvOnLink
			if ( !_mib_get( MIB_V6_ONLINK, (void *)&vChar) )
				printf("Get MIB_V6_ONLINK error!");
			if (0 == vChar)
				fprintf(fp, "\t\tAdvOnLink off;\n");
			else if (1 == vChar)
				fprintf(fp, "\t\tAdvOnLink on;\n");

			// AdvAutonomous
			if ( !_mib_get( MIB_V6_AUTONOMOUS, (void *)&vChar) )
				printf("Get MIB_V6_AUTONOMOUS error!");
			if (0 == vChar)
				fprintf(fp, "\t\tAdvAutonomous off;\n");
			else if (1 == vChar)
				fprintf(fp, "\t\tAdvAutonomous on;\n");

			fprintf(fp, "\t\tAdvValidLifetime %u;\n", validLifeTime);
			fprintf(fp, "\t\tAdvPreferredLifetime %u;\n", 0);
			fprintf(fp, "\t};\n");

		}

		_mib_get( MIB_V6_PREFIX_MODE, (void *)&vChar);
		if ( vChar == 1) {	// setup config without delegation
			struct  in6_addr ip6Addr;
			unsigned char devAddr[MAC_ADDR_LEN];
			unsigned char meui64[8];
			unsigned char value[64];
			int i;

			if ( !_mib_get(MIB_V6_PREFIX_IP, (void *)str)) {
				printf("Get Prefix_IP mib error!");
			}
			if ( !_mib_get(MIB_V6_PREFIX_LEN, (void *)str2)) {
				printf("Get Prefix_Length mib error!");
			}
			fprintf(fp, "\t\n");
			fprintf(fp, "\tprefix %s/%s\n", str, str2);
			fprintf(fp, "\t{\n");

			if(inet_pton(AF_INET6,str,&ip6Addr))
			{
				_mib_get(MIB_ELAN_MAC_ADDR, (void *)devAddr);
				mac_meui64(devAddr, meui64);
				for (i=0; i<8; i++)
					ip6Addr.s6_addr[i+8] = meui64[i];
				inet_ntop(PF_INET6, &ip6Addr, value, sizeof(value));
				sprintf(value, "%s/%s", value, str2);
				va_cmd(IFCONFIG, 3, 1, LANIF, "del", value);
				va_cmd(IFCONFIG, 3, 1, LANIF, "add", value);
			}
			prefix_enable = 1;
		}
		else if( pDLGInfo )  //vChar =0 (auto) and have delegation info
		{ 		// setup config with delegation
			unsigned char ip6Addr[IP6_ADDR_LEN];
			unsigned char devAddr[MAC_ADDR_LEN];
			unsigned char meui64[8];
			unsigned char value[64];
			static unsigned char previous_ip[64];
			int i;

			fprintf(fp, "\t\n");
			inet_ntop(PF_INET6, (struct in6_addr *)pDLGInfo->prefixIP, Ipv6AddrStr, sizeof(Ipv6AddrStr));
			fprintf(fp, "\tprefix %s/%d\n", Ipv6AddrStr, pDLGInfo->prefixLen);
			fprintf(fp, "\t{\n");

			//setup LAN v6 IP address according the prefix,then the IPv6 routing could be correct.
			memcpy(ip6Addr, (void *)pDLGInfo->prefixIP, IP6_ADDR_LEN);
			_mib_get(MIB_ELAN_MAC_ADDR, (void *)devAddr);
			mac_meui64(devAddr, meui64);
			for (i=0; i<8; i++)
				ip6Addr[i+8] = meui64[i];
			inet_ntop(PF_INET6, &ip6Addr, value, sizeof(value));
			sprintf(value, "%s/%d", value, pDLGInfo->prefixLen);

			//Note: Perfix may change, so need to remeber previous prefix
			//      then could delete the correct IP.
			va_cmd(IFCONFIG, 3, 1, LANIF, "del", previous_ip);
			va_cmd(IFCONFIG, 3, 1, LANIF, "add", value);
			memcpy(previous_ip,value,sizeof(previous_ip));
			prefix_enable =1;
		}

		if( prefix_enable)
		{
			// AdvOnLink
			if ( !_mib_get( MIB_V6_ONLINK, (void *)&vChar) )
				printf("Get MIB_V6_ONLINK error!");
			if (0 == vChar)
				fprintf(fp, "\t\tAdvOnLink off;\n");
			else if (1 == vChar)
				fprintf(fp, "\t\tAdvOnLink on;\n");

			// AdvAutonomous
			if ( !_mib_get( MIB_V6_AUTONOMOUS, (void *)&vChar) )
				printf("Get MIB_V6_AUTONOMOUS error!");
			if (0 == vChar)
				fprintf(fp, "\t\tAdvAutonomous off;\n");
			else if (1 == vChar)
				fprintf(fp, "\t\tAdvAutonomous on;\n");

			// AdvValidLifetime
			if ( pDLGInfo == 0 ) {
				if ( !_mib_get(MIB_V6_VALIDLIFETIME, (void *)str)) {
					printf("Get AdvValidLifetime mib error!");
				}
				if (str[0]) {
					fprintf(fp, "\t\tAdvValidLifetime %s;\n", str);
				}
			} else {
				fprintf(fp, "\t\tAdvValidLifetime %u;\n", pDLGInfo->MLTime);
			}

			// AdvPreferredLifetime
			if ( pDLGInfo == 0 ) {
				if ( !_mib_get(MIB_V6_PREFERREDLIFETIME, (void *)str)) {
					printf("Get AdvPreferredLifetime mib error!");
				}
				if (str[0]) {
					fprintf(fp, "\t\tAdvPreferredLifetime %s;\n", str);
				}
			} else {
				fprintf(fp, "\t\tAdvPreferredLifetime %u;\n", pDLGInfo->PLTime);
			}


			fprintf(fp, "\t};\n");

		}
	}


	// Let manual configurred Prefix expired.
	if ( !_mib_get(MIB_IPV6_LAN_PREFIX, (void *)str)) {
		printf("Get Prefix_IP mib error!");
	}
	if ( !_mib_get(MIB_IPV6_LAN_PREFIX_LEN, (void *)&vChar)) {
		printf("Get Prefix_Length mib error!");
	}

	if(str[0] && vChar!=0)
	{
		struct  in6_addr ip6Addr;
		unsigned char devAddr[MAC_ADDR_LEN];
		unsigned char meui64[8];
		unsigned char value[64];
		int i;

		fprintf(fp, "\t\n");
		fprintf(fp, "\tprefix %s/%d\n", str, vChar);
		fprintf(fp, "\t{\n");

		inet_pton(AF_INET6,str,&ip6Addr);
		_mib_get(MIB_ELAN_MAC_ADDR, (void *)devAddr);
		mac_meui64(devAddr, meui64);
		for (i=0; i<8; i++)
			ip6Addr.s6_addr[i+8] = meui64[i];
		inet_ntop(PF_INET6, &ip6Addr, value, sizeof(value));
		sprintf(value, "%s/%d", value, vChar);
		va_cmd(IFCONFIG, 3, 1, LANIF, "del", value);

		// AdvOnLink
		if ( !_mib_get( MIB_V6_ONLINK, (void *)&vChar) )
			printf("Get MIB_V6_ONLINK error!");
		if (0 == vChar)
			fprintf(fp, "\t\tAdvOnLink off;\n");
		else if (1 == vChar)
			fprintf(fp, "\t\tAdvOnLink on;\n");

		// AdvAutonomous
		if ( !_mib_get( MIB_V6_AUTONOMOUS, (void *)&vChar) )
			printf("Get MIB_V6_AUTONOMOUS error!");
		if (0 == vChar)
			fprintf(fp, "\t\tAdvAutonomous off;\n");
		else if (1 == vChar)
			fprintf(fp, "\t\tAdvAutonomous on;\n");

		// AdvValidLifetime
		fprintf(fp, "\t\tAdvValidLifetime 0;\n");

		// AdvPreferredLifetime
		fprintf(fp, "\t\tAdvPreferredLifetime 0;\n");

		fprintf(fp, "\t};\n");
	}


	//RDNSS
	if ( pDLGInfo == 0 ) {	// setup RDNSS without delegation: manual mode
		if ( !_mib_get(MIB_V6_RDNSS1, (void *)str)) {
			printf("Get RDNSS1 mib error!");
		}
		else if (str[0]) {
			fprintf(fp, "\n\tRDNSS %s\n", str);
			fprintf(fp, "\t{\n");
			fprintf(fp, "\t\tAdvRDNSSPreference 8;\n");
			fprintf(fp, "\t\tAdvRDNSSOpen off;\n");
			fprintf(fp, "\t};\n");
		}

		if ( !_mib_get(MIB_V6_RDNSS2, (void *)str)) {
			printf("Get RDNSS2 mib error!");
		}
		else if (str[0]) {
			fprintf(fp, "\n\tRDNSS %s\n", str);
			fprintf(fp, "\t{\n");
			fprintf(fp, "\t\tAdvRDNSSPreference 8;\n");
			fprintf(fp, "\t\tAdvRDNSSOpen off;\n");
			fprintf(fp, "\t};\n");
		}
	} else {
#ifndef CONFIG_E8B
		// setup RDNSS config with delegation : auto mode
		//pDLGInfo->nameServer 2001:b000:168::1,2001:b000:168::2;
		char *saveptr1=NULL,*token=NULL;
		char nameServer[200];

		strcpy(nameServer,pDLGInfo->nameServer);

		if(pDLGInfo->nameServer[0]){
			token = strtok_r(nameServer, ",;", &saveptr1);
			if(token){
				fprintf(fp, "\n\tRDNSS %s\n", token);
				fprintf(fp, "\t{\n");
				fprintf(fp, "\t\tAdvRDNSSPreference 8;\n");
				fprintf(fp, "\t\tAdvRDNSSOpen off;\n");
				fprintf(fp, "\t};\n");
			}
			token = strtok_r(NULL, ",;", &saveptr1);
			if(token){
				fprintf(fp, "\n\tRDNSS %s\n", token);
				fprintf(fp, "\t{\n");
				fprintf(fp, "\t\tAdvRDNSSPreference 8;\n");
				fprintf(fp, "\t\tAdvRDNSSOpen off;\n");
				fprintf(fp, "\t};\n");
			}
		}
#else // e8 need to set IPV6_LAN_IP_ADDR as DNSv6 server
		if ( !_mib_get(MIB_IPV6_LAN_IP_ADDR, (void *)str)) {
			printf("Get IPV6_LAN_IP_ADDR mib error!");
		}
		else{
			fprintf(fp, "\n\tRDNSS %s\n", str);
			fprintf(fp, "\t{\n");
			fprintf(fp, "\t\tAdvRDNSSPreference 8;\n");
			fprintf(fp, "\t\tAdvRDNSSOpen off;\n");
			fprintf(fp, "\t};\n");
		}
#endif
	}

	fprintf(fp, "};\n");
	fclose(fp);

	// Resync radvd.conf
	if ( resync == 1 ) {
		struct  in6_addr ip6Addr;
		unsigned char devAddr[MAC_ADDR_LEN];
		unsigned char meui64[8];
		unsigned char value[64];
		int i;

		//Make sure link local address exists,then radvd could be started.
		if(inet_pton(AF_INET6,"fe80::",&ip6Addr))

		{
			_mib_get(MIB_ELAN_MAC_ADDR, (void *)devAddr);
			mac_meui64(devAddr, meui64);
			for (i=0; i<8; i++)
				ip6Addr.s6_addr[i+8] = meui64[i];
			inet_ntop(PF_INET6, &ip6Addr, value, sizeof(value));
			sprintf(value, "%s/%s", value, "64");
		    printf("value=%s\n",value);
			va_cmd(IFCONFIG, 3, 1, LANIF, "del", value);
			va_cmd(IFCONFIG, 3, 1, LANIF, "add", value);
			sleep(3);  //Sleep for ready to send out ra right after sending signal to radvd
		}

		_mib_get(MIB_V6_RADVD_ENABLE, (void *)&vChar2);
		if (vChar2!=0){
			radvdpid = read_pid((char *)RADVD_PID);
			if (radvdpid > 0) {
				printf("Resync RADVD, radvdpid=%d\n",radvdpid);
				kill(radvdpid, SIGHUP);
			}
			if (radvdpid <= 0)
			{
				printf("New RADVD process!\n");
				#ifdef CONFIG_LUNA_G3_SERIES
				va_niced_cmd( "/bin/radvd", 2, 0, "-C", (char *)RADVD_CONF );
				#else
				va_niced_cmd( "/bin/radvd", 3, 0, "-s", "-C", (char *)RADVD_CONF );
				#endif
			}
		}
	}

	return;

}
#endif

int delLANIP(const char *fname)
{
	int ret=0;
	unsigned char value[64];
	unsigned int uInt, i;
	struct in6_addr targetIp;
	unsigned char devAddr[MAC_ADDR_LEN];
	unsigned char meui64[8];

	ret = getLeasesInfo(fname, &dlg_info);

	// found Prefix Delegation
	if ( ret == 1 ) {
		uInt = dlg_info.prefixLen;
		if (uInt<=0 || uInt > 128) {
			printf("WARNNING! Prefix Length == %d\n", uInt);
			uInt = 64;
		}
		ip6toPrefix((struct in6_addr *)dlg_info.prefixIP, uInt, &targetIp);
		_mib_get(MIB_ELAN_MAC_ADDR, (void *)devAddr);
		mac_meui64(devAddr, meui64);
		for (i=0; i<8; i++)
			targetIp.s6_addr[i+8] = meui64[i];
		inet_ntop(PF_INET6, &targetIp, value, sizeof(value));
		sprintf(value, "%s/%d", value, uInt);
		printf("Delete the previous LAN IP for Prefix Delegation\n");
		va_cmd(IFCONFIG, 3, 1, LANIF, "del", value);
	}
	return 1;
}

static void cfg_stop_delegation(struct mymsgbuf *qbuf)
{
	delLANIP(qbuf->msg.mtext);
	qbuf->request = MSG_SUCC;
}

static void cfg_get_PD_prefix_ip(struct mymsgbuf *qbuf)
{
	PREFIX_V6_INFO_T prefixInfo={0};

	_get_prefixv6_info(&prefixInfo);
	memcpy(qbuf->msg.mtext, prefixInfo.prefixIP, IP6_ADDR_LEN);
	qbuf->request = MSG_SUCC;
}

static void cfg_get_PD_prefix_len(struct mymsgbuf *qbuf)
{
	PREFIX_V6_INFO_T prefixInfo={0};

	_get_prefixv6_info(&prefixInfo);
	qbuf->msg.arg1 = prefixInfo.prefixLen;
	qbuf->request = MSG_SUCC;
}
#endif



#if defined(CONFIG_USER_DHCPV6_ISC_DHCP411) && defined(CONFIG_USER_RADVD)

//Helper function for DNSv6 mode
int _get_dnsv6_info(DNS_V6_INFO_Tp dnsV6Info)
{
	unsigned char ipv6DnsMode=0;
	unsigned char tmpBuf[100]={0},dnsv6_1[64]={0},dnsv6_2[64]={0} ;
	unsigned char leasefile[30];
	unsigned int wanconn=0;
	DLG_INFO_T dlgInfo={0};
	int entry_index=0;
	MIB_CE_ATM_VC_Tp pEntry;
	char* pIfname;
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	unsigned char ipv6PrefixMode=0;
#endif

	if(!dnsV6Info){
		printf("Error! NULL input dnsV6Info\n");
		goto setErr_ipv6;
	}
	if ( !_mib_get(MIB_LAN_DNSV6_MODE, (void *)&ipv6DnsMode)) {
		printf("Error!! get LAN IPv6 DNS Mode fail!");
		goto setErr_ipv6;
	}

	dnsV6Info->mode = ipv6DnsMode;
	
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	if ( !_mib_get(MIB_DHCPV6S_DNS_ASSIGN_MODE, (void *)&ipv6PrefixMode)) {
		printf("Error!! get LAN IPv6 Prefix Mode fail!");
		goto setErr_ipv6;
	}
	
	if(ipv6PrefixMode == DNS_CONF_MODE_STATIC){
		dnsV6Info->mode = IPV6_DNS_STATIC;
	}
#endif

	switch(dnsV6Info->mode)
	{
		case IPV6_DNS_HGWPROXY:
			if (!_mib_get(MIB_IPV6_LAN_IP_ADDR, (void *)tmpBuf)) {
				printf("Error!! Get LAN IPv6 Address fail!");
				goto setErr_ipv6;
			}
			if(tmpBuf[0])
				strcpy(dnsV6Info->nameServer,tmpBuf);

			printf("IPV6_DNS_HGWPROXY,with nameServer %s\n",dnsV6Info->nameServer);
			break;
		case IPV6_DNS_WANCONN:
			if (!_mib_get(MIB_DNSINFO_WANCONN, (void *)&wanconn)) {
				printf("Error!! Get DNS WANCONN fail!");
				goto setErr_ipv6;
			}

			if(wanconn)
				dnsV6Info->wanconn = wanconn;

			//printf("wanconn is %d=0x%x\n",wanconn,wanconn);
			ifGetName(dnsV6Info->wanconn, tmpBuf, sizeof(tmpBuf));
			snprintf(leasefile, 30, "/var/%s%s.leases", DHCPCV6STR, tmpBuf);
			pEntry= getATM_VC_ENTRY_byName(tmpBuf, &entry_index);
			if(!pEntry){
				printf("Find ATM_VC_TBL interface %s Fail!\n",tmpBuf);
				goto setErr_ipv6;
			}

			if(pEntry->dnsv6Mode==REQUEST_DNS){//DNS from DHCPv6 server
				if(getLeasesInfo(leasefile,&dlgInfo)){
					strcpy(dnsV6Info->nameServer,dlgInfo.nameServer);
					strncpy(dnsV6Info->leaseFile, leasefile, IPV6_BUF_SIZE_128);
				}
				else{
					printf("Error! Could not get delegation info from wanconn %s, file %s!\n", tmpBuf, leasefile);
					goto setErr_ipv6;
				}
			}
			else{ //DNS static
				//DNSV61,DNSV62 is in IA_6 format
				inet_ntop(PF_INET6,pEntry->Ipv6Dns1, tmpBuf, sizeof(tmpBuf));
				strcpy(dnsv6_1,tmpBuf);
				inet_ntop(PF_INET6,pEntry->Ipv6Dns2, tmpBuf, sizeof(tmpBuf));
				strcpy(dnsv6_2,tmpBuf);

				if(strcmp(dnsv6_1, "::") !=0 && strcmp(dnsv6_2, "::") !=0)
					snprintf(dnsV6Info->nameServer,IPV6_BUF_SIZE_256,"%s,%s",dnsv6_1,dnsv6_2);
				else if(strcmp(dnsv6_1, "::") !=0)
					snprintf(dnsV6Info->nameServer,IPV6_BUF_SIZE_256,"%s",dnsv6_1);
				else if(strcmp(dnsv6_2, "::") !=0)
					snprintf(dnsV6Info->nameServer,IPV6_BUF_SIZE_256,"%s",dnsv6_2);
			}
			printf("IPV6_DNS_WANCONN,with nameServer %s\n",dnsV6Info->nameServer);
			break;
		case IPV6_DNS_STATIC:
			if (!_mib_get(MIB_ADSL_WAN_DNSV61, (void *)dnsv6_1)) {
				printf("Error!! Get DNS Server Address 1 fail!");
				goto setErr_ipv6;
			}

			//DNSV61,DNSV62 is in IA_6 format
			inet_ntop(PF_INET6,dnsv6_1, tmpBuf, sizeof(tmpBuf));
			strcpy(dnsv6_1,tmpBuf);

			if (!_mib_get(MIB_ADSL_WAN_DNSV62, (void *)dnsv6_2)) {
				printf("Error!! Get DNS Server Address 2 fail!");
				goto setErr_ipv6;
			}
			inet_ntop(PF_INET6,dnsv6_2, tmpBuf, sizeof(tmpBuf));
			strcpy(dnsv6_2,tmpBuf);

			if(strcmp(dnsv6_1, "::") !=0 && strcmp(dnsv6_2, "::") !=0)
				snprintf(dnsV6Info->nameServer,IPV6_BUF_SIZE_256,"%s,%s",dnsv6_1,dnsv6_2);
			else if(strcmp(dnsv6_1, "::") !=0)
				snprintf(dnsV6Info->nameServer,IPV6_BUF_SIZE_256,"%s",dnsv6_1);
			else if(strcmp(dnsv6_2, "::") !=0)
				snprintf(dnsV6Info->nameServer,IPV6_BUF_SIZE_256,"%s",dnsv6_2);

			printf("IPV6_DNS_STATIC,with nameServer %s\n",dnsV6Info->nameServer);
			break;
		default:
			printf("Error! Should not go to here!!\n");
			goto setErr_ipv6;
	}

	return 0;

setErr_ipv6:
	return -1;
}

#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
//Helper function for PrefixV6 mode
int _get_prefixv6_info_radvd(PREFIX_V6_INFO_Tp prefixInfo)
{
	unsigned char ipv6PrefixMode=0, prefixLen;
	unsigned char tmpBuf[100]={0};
	unsigned char tmpBuf1[100]={0};
	unsigned char leasefile[30];
	unsigned int wanconn=0;
	DLG_INFO_T dlgInfo={0};

	if(!prefixInfo){
		printf("Error! NULL input prefixV6Info\n");
		goto setErr_ipv6;
	}
	if ( !_mib_get(MIB_PREFIXINFO_PREFIX_MODE, (void *)&ipv6PrefixMode)) {
		printf("Error!! get LAN IPv6 Prefix Mode fail!");
		goto setErr_ipv6;
	}

	prefixInfo->mode = ipv6PrefixMode;

	switch(prefixInfo->mode){
		case IPV6_PREFIX_DELEGATION:
			if (!_mib_get(MIB_PREFIXINFO_DELEGATED_WANCONN, (void *)&wanconn)) {
				printf("Error!! Get PREFIXINFO_DELEGATED WANCONN fail!");
				goto setErr_ipv6;
			}
			if(wanconn)
				prefixInfo->wanconn = wanconn;

			//printf("wanconn is %d=0x%x\n",wanconn,wanconn);
			ifGetName(prefixInfo->wanconn, tmpBuf, sizeof(tmpBuf));
			snprintf(leasefile, 30, "/var/%s%s.leases", DHCPCV6STR, tmpBuf);
			if(getLeasesInfo(leasefile,&dlgInfo)){
				memcpy(prefixInfo->prefixIP,dlgInfo.prefixIP,sizeof(prefixInfo->prefixIP));
				prefixInfo->prefixLen = dlgInfo.prefixLen;
				//     IPv6 network  may give prefix with length 56 by prefix delegation,
				//     but only prefix length = 64, SLAAC will work.
				//
				//Ref: rfc4862: Section 5.5.3.  Router Advertisement Processing
				//     If the sum of the prefix length and interface identifier length
				//     does not equal 128 bits, the Prefix Information option MUST be
				//     ignored.
				if( prefixInfo->prefixLen!=64 )
					prefixInfo->prefixLen=64;
				strncpy(prefixInfo->leaseFile, leasefile, IPV6_BUF_SIZE_128);
				prefixInfo->RNTime = dlgInfo.RNTime;
				prefixInfo->RBTime = dlgInfo.RBTime;
				prefixInfo->PLTime = dlgInfo.PLTime;
				prefixInfo->MLTime = dlgInfo.MLTime;
			}
			else{
				printf("Error! Could not get delegation info from wanconn %s, file %s!\n", tmpBuf, leasefile);
				goto setErr_ipv6;
			}
			inet_ntop(PF_INET6,prefixInfo->prefixIP, tmpBuf, sizeof(tmpBuf));
			//printf("IPV6_PREFIX_DELEGATION, with prefix %s/%d\n",tmpBuf,prefixInfo->prefixLen);
			break;
		case IPV6_PREFIX_STATIC:
			if (!_mib_get(MIB_V6_PREFIX_IP, (void *)tmpBuf)) { //STRING_T
				printf("Error!! Get MIB_IPV6_LAN_PREFIX fail!");
				goto setErr_ipv6;
			}

			if (!_mib_get(MIB_V6_PREFIX_LEN, (void *)tmpBuf1)) {
				printf("Error!! Get MIB_IPV6_LAN_PREFIX_LEN fail!");
				goto setErr_ipv6;
			}
			if(tmpBuf[0]){
				if ( !inet_pton(PF_INET6, tmpBuf, prefixInfo->prefixIP) )
					goto setErr_ipv6;
			}

			// AdvValidLifetime
			if ( !_mib_get(MIB_V6_VALIDLIFETIME, (void *)tmpBuf)) {
				printf("Get AdvValidLifetime mib error!");
				goto setErr_ipv6;
			}

			if(tmpBuf[0])
				prefixInfo->MLTime=atoi(tmpBuf);
				
			// AdvPreferredLifetime
			if ( !_mib_get(MIB_V6_PREFERREDLIFETIME, (void *)tmpBuf)) {
				printf("Get AdvPreferredLifetime mib error!");
				goto setErr_ipv6;
			}
			if(tmpBuf[0])
				prefixInfo->PLTime=atoi(tmpBuf);
			prefixInfo->prefixLen = atoi(tmpBuf1);
			inet_ntop(PF_INET6,prefixInfo->prefixIP, tmpBuf, sizeof(tmpBuf));
			printf("IPV6_PREFIX_STATIC, with prefix %s::/%d\n",tmpBuf,prefixInfo->prefixLen);
			break;
		case IPV6_PREFIX_PPPOE:
		case IPV6_PREFIX_NONE:
		default:
			printf("Error! Not support this mode %d!\n");
	}
	return 0;

setErr_ipv6:
	return -1;
}

//Helper function for PrefixV6 mode
int _get_prefixv6_info(PREFIX_V6_INFO_Tp prefixInfo)
{
	unsigned char ipv6PrefixMode=0, prefixLen;
	unsigned char tmpBuf[100]={0};
	unsigned char tmpBuf1[100]={0};
	unsigned char leasefile[30];
	unsigned int wanconn=0;
	DLG_INFO_T dlgInfo={0};

	if(!prefixInfo){
		printf("Error! NULL input prefixV6Info\n");
		goto setErr_ipv6;
	}
	if ( !_mib_get(MIB_DHCPV6S_DNS_ASSIGN_MODE, (void *)&ipv6PrefixMode)) {
		printf("Error!! get LAN IPv6 Prefix Mode fail!");
		goto setErr_ipv6;
	}

	prefixInfo->mode = ipv6PrefixMode;

	switch(prefixInfo->mode){
		case DNS_CONF_MODE_ONLY_DNS:
			break;
		case DNS_CONF_MODE_PREFIX_DNS:
			if (!_mib_get(MIB_PREFIXINFO_DELEGATED_WANCONN, (void *)&wanconn)) {
				printf("Error!! Get PREFIXINFO_DELEGATED WANCONN fail!");
				goto setErr_ipv6;
			}
			if(wanconn)
				prefixInfo->wanconn = wanconn;

			//printf("wanconn is %d=0x%x\n",wanconn,wanconn);
			ifGetName(prefixInfo->wanconn, tmpBuf, sizeof(tmpBuf));
			snprintf(leasefile, 30, "/var/%s%s.leases", DHCPCV6STR, tmpBuf);
			if(getLeasesInfo(leasefile,&dlgInfo)){
				memcpy(prefixInfo->prefixIP,dlgInfo.prefixIP,sizeof(prefixInfo->prefixIP));
				prefixInfo->prefixLen = dlgInfo.prefixLen;
				//     IPv6 network  may give prefix with length 56 by prefix delegation,
				//     but only prefix length = 64, SLAAC will work.
				//
				//Ref: rfc4862: Section 5.5.3.  Router Advertisement Processing
				//     If the sum of the prefix length and interface identifier length
				//     does not equal 128 bits, the Prefix Information option MUST be
				//     ignored.
				if( prefixInfo->prefixLen!=64 )
					prefixInfo->prefixLen=64;
				strncpy(prefixInfo->leaseFile, leasefile, IPV6_BUF_SIZE_128);
				prefixInfo->RNTime = dlgInfo.RNTime;
				prefixInfo->RBTime = dlgInfo.RBTime;
				prefixInfo->PLTime = dlgInfo.PLTime;
				prefixInfo->MLTime = dlgInfo.MLTime;
			}
			else{
				printf("Error! Could not get delegation info from wanconn %s, file %s!\n", tmpBuf, leasefile);
				goto setErr_ipv6;
			}
			inet_ntop(PF_INET6,prefixInfo->prefixIP, tmpBuf, sizeof(tmpBuf));
			//printf("IPV6_PREFIX_DELEGATION, with prefix %s/%d\n",tmpBuf,prefixInfo->prefixLen);
			break;
		case DNS_CONF_MODE_STATIC:
			if (!_mib_get(MIB_IPV6_LAN_PREFIX, (void *)tmpBuf)) { //STRING_T
				printf("Error!! Get MIB_IPV6_LAN_PREFIX fail!");
				goto setErr_ipv6;
			}

			if (!_mib_get(MIB_IPV6_LAN_PREFIX_LEN, (void *)&prefixLen)) {
				printf("Error!! Get MIB_IPV6_LAN_PREFIX_LEN fail!");
				goto setErr_ipv6;
			}
			if(tmpBuf[0]){
				if ( !inet_pton(PF_INET6, tmpBuf, prefixInfo->prefixIP) )
					goto setErr_ipv6;
			}
			prefixInfo->prefixLen = prefixLen;
			inet_ntop(PF_INET6,prefixInfo->prefixIP, tmpBuf, sizeof(tmpBuf));
			printf("IPV6_PREFIX_STATIC, with prefix %s::/%d\n",tmpBuf,prefixInfo->prefixLen);
			break;
		default:
			printf("Error! Not support this mode %d!\n");
	}
	return 0;

setErr_ipv6:
	return -1;
}
#else
//Helper function for PrefixV6 mode
int _get_prefixv6_info(PREFIX_V6_INFO_Tp prefixInfo)
{
	unsigned char ipv6PrefixMode=0, prefixLen;
	unsigned char tmpBuf[100]={0};
	unsigned char leasefile[30];
	unsigned int wanconn=0;
	DLG_INFO_T dlgInfo={0};

	if(!prefixInfo){
		printf("Error! NULL input prefixV6Info\n");
		goto setErr_ipv6;
	}
	if ( !_mib_get(MIB_PREFIXINFO_PREFIX_MODE, (void *)&ipv6PrefixMode)) {
		printf("Error!! get LAN IPv6 Prefix Mode fail!");
		goto setErr_ipv6;
	}

	prefixInfo->mode = ipv6PrefixMode;

	switch(prefixInfo->mode){
		case IPV6_PREFIX_DELEGATION:
			if (!_mib_get(MIB_PREFIXINFO_DELEGATED_WANCONN, (void *)&wanconn)) {
				printf("Error!! Get PREFIXINFO_DELEGATED WANCONN fail!");
				goto setErr_ipv6;
			}
			if(wanconn)
				prefixInfo->wanconn = wanconn;

			//printf("wanconn is %d=0x%x\n",wanconn,wanconn);
			ifGetName(prefixInfo->wanconn, tmpBuf, sizeof(tmpBuf));
			snprintf(leasefile, 30, "/var/%s%s.leases", DHCPCV6STR, tmpBuf);
			if(getLeasesInfo(leasefile,&dlgInfo)){
				memcpy(prefixInfo->prefixIP,dlgInfo.prefixIP,sizeof(prefixInfo->prefixIP));
				prefixInfo->prefixLen = dlgInfo.prefixLen;
				//     IPv6 network  may give prefix with length 56 by prefix delegation,
				//     but only prefix length = 64, SLAAC will work.
				//
				//Ref: rfc4862: Section 5.5.3.  Router Advertisement Processing
				//     If the sum of the prefix length and interface identifier length
				//     does not equal 128 bits, the Prefix Information option MUST be
				//     ignored.
				if( prefixInfo->prefixLen!=64 )
					prefixInfo->prefixLen=64;
				strncpy(prefixInfo->leaseFile, leasefile, IPV6_BUF_SIZE_128);
				prefixInfo->RNTime = dlgInfo.RNTime;
				prefixInfo->RBTime = dlgInfo.RBTime;
				prefixInfo->PLTime = dlgInfo.PLTime;
				prefixInfo->MLTime = dlgInfo.MLTime;
			}
			else{
				printf("Error! Could not get delegation info from wanconn %s, file %s!\n", tmpBuf, leasefile);
				goto setErr_ipv6;
			}
			inet_ntop(PF_INET6,prefixInfo->prefixIP, tmpBuf, sizeof(tmpBuf));
			//printf("IPV6_PREFIX_DELEGATION, with prefix %s/%d\n",tmpBuf,prefixInfo->prefixLen);
			break;
		case IPV6_PREFIX_STATIC:
			if (!_mib_get(MIB_IPV6_LAN_PREFIX, (void *)tmpBuf)) { //STRING_T
				printf("Error!! Get MIB_IPV6_LAN_PREFIX fail!");
				goto setErr_ipv6;
			}

			if (!_mib_get(MIB_IPV6_LAN_PREFIX_LEN, (void *)&prefixLen)) {
				printf("Error!! Get MIB_IPV6_LAN_PREFIX_LEN fail!");
				goto setErr_ipv6;
			}
			if(tmpBuf[0]){
				if ( !inet_pton(PF_INET6, tmpBuf, prefixInfo->prefixIP) )
					goto setErr_ipv6;
			}
			prefixInfo->prefixLen = prefixLen;
			inet_ntop(PF_INET6,prefixInfo->prefixIP, tmpBuf, sizeof(tmpBuf));
			printf("IPV6_PREFIX_STATIC, with prefix %s::/%d\n",tmpBuf,prefixInfo->prefixLen);
			break;
		case IPV6_PREFIX_PPPOE:
		case IPV6_PREFIX_NONE:
		default:
			printf("Error! Not support this mode %d!\n");
	}
	return 0;

setErr_ipv6:
	return -1;
}
#endif

int _isAnyPPPoEWan()
{
	unsigned int entryNum, i;
	MIB_CE_ATM_VC_Tp pEntry;

	entryNum = _mib_chain_total(MIB_ATM_VC_TBL);
	for (i=0; i<entryNum; i++) {
		if(!(pEntry = (typeof(pEntry))_mib_chain_get(MIB_ATM_VC_TBL,i)))
		{
  			printf("Get chain record error!\n");
			return -1;
		}

		if (pEntry->enable == 0)
			continue;

		if(pEntry->cmode == CHANNEL_MODE_PPPOE)
			return 1;
	}
	return 0;
}

int _setup_radvd_conf_new(DNS_V6_INFO_Tp pDnsV6Info, PREFIX_V6_INFO_Tp pPrefixInfo)
{
	FILE *fp;
	unsigned char str[MAX_RADVD_CONF_PREFIX_LEN];
	unsigned char str2[MAX_RADVD_CONF_PREFIX_LEN];
	unsigned char vChar,vChar2;
	int radvdpid;
	unsigned char 	Ipv6AddrStr[48];
	unsigned char mode;
	unsigned char prefix_enable = 0;

	if(!pDnsV6Info || !pPrefixInfo){
		printf("Error! NULL parameter input %s\n");
		return -1;
	}
#ifdef CONFIG_CMCC_IPV6_SECURITY_SUPPORT
	flush_old_ip6sec_prefix(RADVD_CONF,pPrefixInfo);
#endif
	if ((fp = fopen(RADVD_CONF, "w")) == NULL)
	{
		printf("Open file %s failed !\n", RADVD_CONF);
		return -1;
	}

	fprintf(fp, "interface br0\n");
	fprintf(fp, "{\n");

	// AdvSendAdvert
	if ( !_mib_get( MIB_V6_SENDADVERT, (void *)&vChar) )
		printf("Get MIB_V6_SENDADVERT error!");
	if (0 == vChar)
		fprintf(fp, "\tAdvSendAdvert off;\n");
	else if (1 == vChar)
		fprintf(fp, "\tAdvSendAdvert on;\n");

	// MaxRtrAdvIntervalAct
	if ( !_mib_get(MIB_V6_MAXRTRADVINTERVAL, (void *)str)) {
		printf("Get MaxRtrAdvIntervalAct mib error!");
	}
	if (str[0]) {
		fprintf(fp, "\tMaxRtrAdvInterval %s;\n", str);
	}

	// MinRtrAdvIntervalAct
	if ( !_mib_get(MIB_V6_MINRTRADVINTERVAL, (void *)str)) {
		printf("Get MinRtrAdvIntervalAct mib error!");
	}
	if (str[0]) {
		fprintf(fp, "\tMinRtrAdvInterval %s;\n", str);
	}

	// AdvCurHopLimitAct
	if ( !_mib_get(MIB_V6_ADVCURHOPLIMIT, (void *)str)) {
		printf("Get AdvCurHopLimitAct mib error!");
	}
	if (str[0]) {
		fprintf(fp, "\tAdvCurHopLimit %s;\n", str);
	}

	// AdvDefaultLifetime
	if ( !_mib_get(MIB_V6_ADVDEFAULTLIFETIME, (void *)str)) {
		printf("Get AdvDefaultLifetime mib error!");
	}
	if (str[0]) {
		fprintf(fp, "\tAdvDefaultLifetime %s;\n", str);
	}

	// AdvReachableTime
	if ( !_mib_get(MIB_V6_ADVREACHABLETIME, (void *)str)) {
		printf("Get AdvReachableTime mib error!");
	}
	if (str[0]) {
		fprintf(fp, "\tAdvReachableTime %s;\n", str);
	}

	// AdvRetransTimer
	if ( !_mib_get(MIB_V6_ADVRETRANSTIMER, (void *)str)) {
		printf("Get AdvRetransTimer mib error!");
	}
	if (str[0]) {
		fprintf(fp, "\tAdvRetransTimer %s;\n", str);
	}

	// AdvLinkMTU
	if ( !_mib_get(MIB_V6_ADVLINKMTU, (void *)str)) {
		printf("Get AdvLinkMTU mib error!");
	}
	if (str[0]) {
		int mtu = atoi(str);
		//Modify due to e8 Avalanche test , if MTU is specified (Like 1492), throughput will be bad.
		//But if there is PPPoE WAN, LAN PC should set the MTU, to prevent packet too big in IPv6.
		if( mtu>0 && _isAnyPPPoEWan())
		fprintf(fp, "\tAdvLinkMTU %s;\n", str);
		else
			fprintf(fp, "\tAdvLinkMTU 0;\n");
	}

	// AdvManagedFlag
	if ( !_mib_get( MIB_V6_MANAGEDFLAG, (void *)&vChar) )
		printf("Get MIB_V6_MANAGEDFLAG error!");
	if (0 == vChar)
		fprintf(fp, "\tAdvManagedFlag off;\n");
	else if (1 == vChar)
		fprintf(fp, "\tAdvManagedFlag on;\n");

	// AdvOtherConfigFlag
	if ( !_mib_get( MIB_V6_OTHERCONFIGFLAG, (void *)&vChar) )
		printf("Get MIB_V6_OTHERCONFIGFLAG error!");
	if (0 == vChar)
		fprintf(fp, "\tAdvOtherConfigFlag off;\n");
	else if (1 == vChar)
		fprintf(fp, "\tAdvOtherConfigFlag on;\n");

	//NOTE: in radvd.conf
	//      Prefix/clients/route/RDNSS configurations must be given in exactly this order.

	// Prefix

	// ULA Prefix
	_mib_get (MIB_V6_ULAPREFIX_ENABLE, (void *)&vChar);
	if (vChar!=0) {
		unsigned char validtime[MAX_RADVD_CONF_PREFIX_LEN];
		unsigned char preferedtime[MAX_RADVD_CONF_PREFIX_LEN];

		if ( !_mib_get(MIB_V6_ULAPREFIX, (void *)str)       ||
	         !_mib_get(MIB_V6_ULAPREFIX_LEN, (void *)str2)  ||
	         !_mib_get(MIB_V6_ULAPREFIX_VALID_TIME, (void *)validtime)  ||
	         !_mib_get(MIB_V6_ULAPREFIX_PREFER_TIME, (void *)preferedtime)
			)
		{
			printf("Get ULAPREFIX mib error!");
		}
		else
		{
			unsigned char ip6Addr[IP6_ADDR_LEN];
			unsigned char devAddr[MAC_ADDR_LEN];
			unsigned char meui64[8];
			unsigned char value[64];
			int i;

			fprintf(fp, "\t\n");
			fprintf(fp, "\tprefix %s/%s\n", str, str2);
			fprintf(fp, "\t{\n");
			fprintf(fp, "\t\tAdvOnLink on;\n");
			fprintf(fp, "\t\tAdvAutonomous on;\n");
			fprintf(fp, "\t\tAdvValidLifetime %s;\n",validtime);
			fprintf(fp, "\t\tAdvPreferredLifetime %s;\n",preferedtime);
			fprintf(fp, "\t};\n");

			inet_pton(PF_INET6, str, (void *) ip6Addr);

			//setup LAN ULA v6 IP address according the ULA prefix + EUI64.
			_mib_get(MIB_ELAN_MAC_ADDR, (void *)devAddr);
			mac_meui64(devAddr, meui64);
			for (i=0; i<8; i++)
				ip6Addr[i+8] = meui64[i];
			inet_ntop(PF_INET6, &ip6Addr, value, sizeof(value));
			sprintf(value, "%s/%s", value, str2);

			printf("Set LAN ULA %s\n",value);
			va_cmd(IFCONFIG, 3, 1, LANIF, "del", value);
			va_cmd(IFCONFIG, 3, 1, LANIF, "add", value);
#ifdef CONFIG_CMCC_IPV6_SECURITY_SUPPORT
			va_cmd(IP6SECCTRL,7,1,"-A","-a",str,"-l",str2,"-t",preferedtime);
#endif
		}
	}

	// Prefix
	if(pPrefixInfo->prefixIP[0] && pPrefixInfo->prefixLen)
	{
		struct  in6_addr ip6Addr;
		unsigned char devAddr[MAC_ADDR_LEN];
		unsigned char meui64[8];
		unsigned char value[64];
		static unsigned char previous_ip[64];
		unsigned char prefixBuf[100]={0};
		int i;

		inet_ntop(PF_INET6,pPrefixInfo->prefixIP, prefixBuf, sizeof(prefixBuf));
		fprintf(fp, "\t\n");
		fprintf(fp, "\tprefix %s/%d\n", prefixBuf, pPrefixInfo->prefixLen);
		fprintf(fp, "\t{\n");

		//setup LAN v6 IP address according the prefix,then the IPv6 routing could be correct.
		memcpy(ip6Addr.s6_addr,pPrefixInfo->prefixIP,8);
		_mib_get(MIB_ELAN_MAC_ADDR, (void *)devAddr);
		mac_meui64(devAddr, meui64);
		for (i=0; i<8; i++)
			ip6Addr.s6_addr[i+8] = meui64[i];
		inet_ntop(PF_INET6, &ip6Addr, value, sizeof(value));
		sprintf(value, "%s/%d", value, pPrefixInfo->prefixLen);

		//Note: Perfix may change, so need to remeber previous prefix
		//      then could delete the correct IP.
		va_cmd(IFCONFIG, 3, 1, LANIF, "del", previous_ip);
		va_cmd(IFCONFIG, 3, 1, LANIF, "add", value);
		memcpy(previous_ip,value,sizeof(previous_ip));

		// AdvOnLink
		if ( !_mib_get( MIB_V6_ONLINK, (void *)&vChar) )
			printf("Get MIB_V6_ONLINK error!");
		if (0 == vChar)
			fprintf(fp, "\t\tAdvOnLink off;\n");
		else if (1 == vChar)
			fprintf(fp, "\t\tAdvOnLink on;\n");

		// AdvAutonomous
		if ( !_mib_get( MIB_V6_AUTONOMOUS, (void *)&vChar) )
			printf("Get MIB_V6_AUTONOMOUS error!");
		if (0 == vChar)
			fprintf(fp, "\t\tAdvAutonomous off;\n");
		else if (1 == vChar)
			fprintf(fp, "\t\tAdvAutonomous on;\n");

		// AdvValidLifetime
			fprintf(fp, "\t\tAdvValidLifetime %u;\n", pPrefixInfo->MLTime);

		// AdvPreferredLifetime
			fprintf(fp, "\t\tAdvPreferredLifetime %u;\n", pPrefixInfo->PLTime);

		fprintf(fp, "\t\tDeprecatePrefix on;\n");
		fprintf(fp, "\t};\n");
#ifdef CONFIG_CMCC_IPV6_SECURITY_SUPPORT
		sprintf(value,"%d",pPrefixInfo->prefixLen);
		sprintf(str,"%d",pPrefixInfo->PLTime);
		va_cmd(IP6SECCTRL,7,1,"-A","-a",prefixBuf,"-l", value ,"-t", str);
#endif
	}

	//set RDNSS according to DNSv6 server setting
	if(pDnsV6Info && pDnsV6Info->nameServer){
		char *ptr=NULL;
		unsigned char nameServer[IPV6_BUF_SIZE_256];

		memcpy(nameServer,pDnsV6Info->nameServer,sizeof(nameServer));

		// Alan, Modify all ',' in string for RADVD CONF format
		//  Replace ',' in string to meet RADVD CONF format
		//	RDNSS ip [ip] [ip] {    list of rdnss specific options
		//	};
		ptr=nameServer;
		while(ptr=strchr(ptr,',')){
			*ptr++=' ';
		}

		fprintf(fp, "\n\tRDNSS %s\n", nameServer);
		fprintf(fp, "\t{\n");
		fprintf(fp, "\t\tAdvRDNSSPreference 8;\n");
		fprintf(fp, "\t\tAdvRDNSSOpen off;\n");
		fprintf(fp, "\t};\n");
	}

	fprintf(fp, "};\n");
	fclose(fp);

	return 0;

}

int _setup_dhcpdv6_conf_new(DNS_V6_INFO_Tp pDnsV6Info, PREFIX_V6_INFO_Tp pPrefixInfo)
//int _setup_dhcpdv6_conf_new(DLG_INFO_Tp pDLGInfo)
{
	FILE *fp;
	unsigned int DLTime, PFTime, RNTime, RBTime;
	unsigned char vChar;
	struct in6_addr ip6Addr, ip6Prefix;
	int k;
	unsigned char value[MAX_V6_IP_LEN];
	unsigned char value2[MAX_V6_IP_LEN];
	unsigned char value3[MAX_DUID_LEN];
	unsigned char value4[MAX_V6_IP_LEN];
	unsigned char 	Ipv6AddrStr[48];
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	unsigned char ipv6PrefixMode;
	_mib_get(MIB_DHCPV6S_DNS_ASSIGN_MODE, (void *)&ipv6PrefixMode);
#endif 

	if(!pDnsV6Info || !pPrefixInfo){
		printf("Error! Input data is NULL %s\n",__func__);
		return -1;
	}

	if ((fp = fopen(DHCPDV6_CONF, "w")) == NULL)
	{
		printf("Open file %s failed !\n", DHCPDV6_CONF);
		return -1;
	}

	// default-lease-time	
	_mib_get(MIB_DHCPV6S_DEFAULT_LEASE, (void *)&DLTime);
	fprintf(fp, "default-lease-time %u;\n", DLTime);
	
	// preferred-lifetime	
	_mib_get(MIB_DHCPV6S_PREFERRED_LIFETIME, (void *)&PFTime);
	fprintf(fp, "preferred-lifetime %u;\n", PFTime);
	
	// option dhcp-renewal-time	
	_mib_get(MIB_DHCPV6S_RENEW_TIME, (void *)&RNTime);
	fprintf(fp, "option dhcp-renewal-time %u;\n", RNTime);
	
	// option dhcp-rebinding-time	
	_mib_get(MIB_DHCPV6S_REBIND_TIME, (void *)&RBTime);
	fprintf(fp, "option dhcp-rebinding-time %u;\n", RBTime);

	// Option dhcp6.name-servers
	fprintf(fp, "option dhcp6.name-servers %s;\n", pDnsV6Info->nameServer);

	//subnet6 2001:b010:7030:1a01::/64 {
	//        range6 2001:b010:7030:1a01::/64;
	//	 (or) range6 low-address high-address;
	//        }

	//Add min_address & max_address
	_mib_get(MIB_DHCPV6S_MIN_ADDRESS, (void *)&value2);
	_mib_get(MIB_DHCPV6S_MAX_ADDRESS, (void *)&value4);


	if (pPrefixInfo->prefixIP[0] && pPrefixInfo->prefixLen) {
		struct  in6_addr ip6Addr, ip6Addr2;
		unsigned char minaddr[IP6_ADDR_LEN]={0},maxaddr[IP6_ADDR_LEN]={0};
		unsigned char devAddr[MAC_ADDR_LEN]={0};
		unsigned char meui64[8]={0};
		unsigned char prefixBuf[100]={0},tmpBuf[100]={0},tmpBuf2[100]={0};
		int i;

		inet_ntop(PF_INET6,pPrefixInfo->prefixIP, prefixBuf, sizeof(prefixBuf));
		printf("prefix is %s/%d\n",prefixBuf, pPrefixInfo->prefixLen);

		fprintf(fp, "subnet6 %s/%d {\n", prefixBuf, pPrefixInfo->prefixLen);
		//fprintf(fp, "\trange6 %s/%d;\n", value, vChar);

#if defined(CONFIG_CMCC) || defined(CONFIG_CU) 
		//if(ipv6PrefixMode!=DNS_CONF_MODE_ONLY_DNS){
			fprintf(fp, "\trange6 %s/%d;\n", prefixBuf,pPrefixInfo->prefixLen); 
		//}
#else
		//Merge the prefix & min/max address
		sprintf(tmpBuf,"::%s",value2);
		inet_pton(PF_INET6,tmpBuf,minaddr);

		sprintf(tmpBuf,"::%s",value4);
		inet_pton(PF_INET6,tmpBuf,maxaddr);

		for (i=0; i<8; i++){
			minaddr[i] = pPrefixInfo->prefixIP[i];
			maxaddr[i] = pPrefixInfo->prefixIP[i];
		}

		inet_ntop(PF_INET6,minaddr, tmpBuf, sizeof(tmpBuf));
		inet_ntop(PF_INET6,maxaddr, tmpBuf2, sizeof(tmpBuf2));

		printf("range6 %s%s;\n",tmpBuf,tmpBuf2);
		fprintf(fp, "\trange6 %s %s;\n", tmpBuf,tmpBuf2);
#endif
		fprintf(fp, "}\n");

		//setup br0 IPv6 IP according to this prefix
		memcpy(ip6Addr.s6_addr,pPrefixInfo->prefixIP,sizeof(ip6Addr.s6_addr));

		_mib_get(MIB_ELAN_MAC_ADDR, (void *)devAddr);
		mac_meui64(devAddr, meui64);
		for (i=0; i<8; i++)
			ip6Addr.s6_addr[i+8] = meui64[i];

		inet_ntop(PF_INET6, &ip6Addr, value, sizeof(value));
		sprintf(value, "%s/%d", value,pPrefixInfo->prefixLen);
		va_cmd(IFCONFIG, 3, 1, LANIF, "del", value);
		va_cmd(IFCONFIG, 3, 1, LANIF, "add", value);
	}

	fclose(fp);

	if ((fp = fopen(DHCPDV6_LEASES, "w")) == NULL)
	{
		printf("Open file %s failed !\n", DHCPDV6_LEASES);
		return -1;
	}
	fclose(fp);

	return 1;

}

//int _start_dhcpv6_new(int enable, DLG_INFO_Tp pDLGInfo)
int _start_dhcpv6_new(DNS_V6_INFO_Tp pDnsV6Info, PREFIX_V6_INFO_Tp pPrefixInfo)
{
	unsigned char value[64];
	unsigned char vChar;
	int tmp_status, status=0;
	unsigned int uInt, i;
	DHCP_TYPE_T mode;
	int dhcpserverpid=0;
	struct in6_addr ip6Addr, targetIp;
	unsigned char devAddr[MAC_ADDR_LEN];
	unsigned char meui64[8];
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	unsigned char ipv6PrefixMode=0;
	unsigned char ipv6PoolFormat=0;
#endif

	mode = DHCP_LAN_NONE;
	if (_mib_get(MIB_DHCPV6_MODE, (void *)value) != 0)
	{
		mode = (DHCP_TYPE_T)(*(unsigned char *)value);
	}

	dhcpserverpid = read_pid((char*)DHCPSERVER6PID);

	if(dhcpserverpid > 0)
	{
		kill(dhcpserverpid, SIGTERM);

		i = 0;
		while (kill(dhcpserverpid, 0) == 0 && i < 20) {
			usleep(100000); i++;
		}
		if(i >= 20 )
			kill(dhcpserverpid, SIGKILL);
		
		if(!access(DHCPSERVER6PID, F_OK)) unlink(DHCPSERVER6PID);
 	}

	// Delete LAN IP which is set by manual
	_mib_get(MIB_DHCPV6S_PREFIX_LENGTH, (void *)&vChar);
	_mib_get(MIB_DHCPV6S_RANGE_START, (void *)ip6Addr.s6_addr);
	uInt = (int)vChar;
	if (uInt<=0 || uInt > 128) {
		printf("WARNNING! Prefix Length == %d\n", uInt);
		uInt = 64;
	}

	ip6toPrefix(&ip6Addr, uInt, &targetIp);
	_mib_get(MIB_ELAN_MAC_ADDR, (void *)devAddr);
	mac_meui64(devAddr, meui64);
	for (i=0; i<8; i++)
		targetIp.s6_addr[i+8] = meui64[i];
	inet_ntop(PF_INET6, &targetIp, value, sizeof(value));
	sprintf(value, "%s/%d", value, uInt);
	va_cmd(IFCONFIG, 3, 1, LANIF, "del", value);

	// Set LAN IP which is set by auto
	uInt = pPrefixInfo->prefixLen;
	if (uInt<=0 || uInt > 128) {
		printf("WARNNING! Prefix Length == %d\n", uInt);
		uInt = 64;
	}
	ip6toPrefix((struct in6_addr *)pPrefixInfo->prefixIP, uInt, &targetIp);
	_mib_get(MIB_ELAN_MAC_ADDR, (void *)devAddr);
	mac_meui64(devAddr, meui64);
	for (i=0; i<8; i++)
		targetIp.s6_addr[i+8] = meui64[i];
	inet_ntop(PF_INET6, &targetIp, value, sizeof(value));
	sprintf(value, "%s/%d", value, uInt);
	va_cmd(IFCONFIG, 3, 1, LANIF, "add", value);

#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	_mib_get(MIB_DHCPV6S_DNS_ASSIGN_MODE, (void *)&ipv6PrefixMode);
	if(ipv6PrefixMode == DNS_CONF_MODE_STATIC){
		_mib_get(MIB_DHCPV6S_POOL_ADDR_FORMAT, (void *)&ipv6PoolFormat);
	}
#endif
	tmp_status = _setup_dhcpdv6_conf_new(pDnsV6Info, pPrefixInfo);
	if (tmp_status == 1)
	{
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		if(ipv6PoolFormat==IPV6_POOL_FORMAT_EUI64){
			// dhcpd -6 -cf /var/dhcpdv6.conf -lf /var/dhcpd6.leases br0
			status = va_niced_cmd(DHCPDV6, 8, 0, "-6", "-cf", DHCPDV6_CONF, "-lf", DHCPDV6_LEASES, "--pool6type", "1", BRIF);
		}
		else{
			// dhcpd -6 -cf /var/dhcpdv6.conf -lf /var/dhcpd6.leases br0
			status = va_niced_cmd(DHCPDV6, 6, 0, "-6", "-cf", DHCPDV6_CONF, "-lf", DHCPDV6_LEASES, BRIF);
		}
#else
		// dhcpd -6 -cf /var/dhcpdv6.conf -lf /var/dhcpd6.leases br0
		status = va_niced_cmd(DHCPDV6, 6, 0, "-6", "-cf", DHCPDV6_CONF, "-lf", DHCPDV6_LEASES, BRIF);
#endif
		//while(read_pid((char*)DHCPSERVER6PID) < 0)
		//	usleep(250000);
	}
	else if (tmp_status == -1)
	 	status = -1;

	return status;
}

#if defined(CONFIG_IPV6)
/************************************************
* Propose: _delOrgLanLinklocalIPv6Address
*
*    delete the original Link local IPv6 address
*      e.q: ifconfig br0 del fe80::2e0:4cff:fe86:5338/64 >/dev/null 2>&1
*    
*    When modify the function, please also modify delOrgLanLinklocalIPv6Address()
*    in src/linux/utility.c
* Parameter:
*	None
* Return:
*     None
* Author:
*     Alan
*************************************************/
void _delOrgLanLinklocalIPv6Address()
{
	unsigned char value[64];
	struct in6_addr ip6Addr, targetIp;
	unsigned char devAddr[MAC_ADDR_LEN];
	unsigned char *p = &targetIp.s6_addr[0];
	int i=0;
	char cmdBuf[256]={0};

	if (_mib_get(MIB_ELAN_MAC_ADDR, (void *)devAddr) != 0)
	{
		ipv6_linklocal_eui64(p, devAddr);
		inet_ntop(PF_INET6, &targetIp, value, sizeof(value));
		sprintf(cmdBuf, "%s %s %s %s/%d %s %s", IFCONFIG, LANIF, ARG_DEL, value, 64, hideErrMsg1, hideErrMsg2);
		//use system to prevent error message
		system(cmdBuf);
		//va_cmd(IFCONFIG, 5, 1, LANIF, ARG_DEL, value, hideErrMsg1, hideErrMsg2);
	}
}

/************************************************
* Propose: _setLanLinkLocalIPv6Address()
*    set the Link local IPv6 address
*      e.q: ifconfig br0 add fe80::1/64 >/dev/null 2>&1
*
*    When modify the function, please also modify setLanLinkLocalIPv6Address()
*    in src/linux/utility.c
* Parameter:
*	None
* Return:
*     None
* Author:
*     Alan
*************************************************/
void _setLanLinkLocalIPv6Address()
{
	unsigned char value[64];

	if (_mib_get(MIB_IPV6_LAN_IP_ADDR, (void *)value) != 0)
	{
		char cmdBuf[100]={0};
		sprintf(cmdBuf, "%s %s %s %s/%d %s %s", IFCONFIG, LANIF, ARG_ADD, value, 64, hideErrMsg1, hideErrMsg2);
		//use system to prevent error message
		system(cmdBuf);
		//va_cmd(IFCONFIG, 5, 1, LANIF, ARG_ADD, cmdBuf, hideErrMsg1, hideErrMsg2);
	}
}
#endif /* #if defined(CONFIG_IPV6) */

void _restartLanV6ServerByPD(char *leaseFile)
{
	DNS_V6_INFO_T dnsV6Info={0};
	PREFIX_V6_INFO_T prefixInfo={0};
	unsigned IPv6Enable=0,radvdEnable=0;
	int radvdpid;

	_get_dnsv6_info(&dnsV6Info);
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	_get_prefixv6_info_radvd(&prefixInfo);
#else
	_get_prefixv6_info(&prefixInfo);
#endif
	//fix two default IPv6 gateway in LAN, Alan
	_delOrgLanLinklocalIPv6Address();
	_setLanLinkLocalIPv6Address();

	//Since it's trigger from DHCPClient got prefix. Check if DNS or Prefix setting
	//is related to WANCONN and also is for this WAN.
	//( By check if leaseFile name is the same.)
	if( ( (dnsV6Info.mode==IPV6_DNS_WANCONN)&&(!strcmp(dnsV6Info.leaseFile, leaseFile)))
			||  ( (prefixInfo.mode==IPV6_PREFIX_DELEGATION)&&(!strcmp(prefixInfo.leaseFile, leaseFile))) ){

		_mib_get(MIB_V6_IPV6_ENABLE, (void *)&IPv6Enable);
		if(IPv6Enable){
			_mib_get(MIB_V6_RADVD_ENABLE, (void *)&radvdEnable);
			if(radvdEnable){
				_setup_radvd_conf_new(&dnsV6Info,&prefixInfo);
				radvdpid=read_pid((char *)RADVD_PID);
				if(radvdpid>0){ //TERM it, let previous prefix be deprecated.
					kill(radvdpid, SIGTERM);
				}
				#ifdef CONFIG_LUNA_G3_SERIES
				va_cmd( "/bin/radvd", 2, 0, "-C", (char *)RADVD_CONF );
				#else
				va_cmd( "/bin/radvd", 3, 0, "-s", "-C", (char *)RADVD_CONF );
				#endif

			}
			#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
			_get_prefixv6_info(&prefixInfo);
			#endif
			_start_dhcpv6_new(&dnsV6Info,&prefixInfo);
		}
	}
}


#ifndef CONFIG_E8B
#ifndef CONFIG_IPV6_OLD_FILTER
/*
 * Function updateIPV6FilterByPD
 *
 * Here will read MIB setting to setup IPv6 firewall rules.
 * 1. Flush all rules.
 * 2. Setup rules according to user setting with Delegated Prefix
 * 3. Setup default incoming/outgoing rules.
 *
 */
void updateIPV6FilterByPD(DLG_INFO_Tp pDLGInfo)
{
	char *argv[20];
	unsigned char value[32], byte;
	unsigned char ivalue;
	int vInt, i, total;
	MIB_CE_V6_IP_PORT_FILTER_Tp pIpEntry;
	char *policy, *filterSIP, *filterDIP, srcPortRange[12], dstPortRange[12];
	char SIPRange[110]={0};
	char DIPRange[110]={0};
	unsigned char prefixIp6Addr[IP6_ADDR_LEN];
	unsigned char newPrefixStr[MAX_V6_IP_LEN]={0};
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	unsigned char enable = 0;
#endif

	if(!pDLGInfo)
	{
		printf("Error! Invalid parameter pDLGInfo in %s\n",__func__);
	return;
	}

	printf("Update Firewall rule set by user.\n");
	// Delete ipfilter rule
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	va_cmd(IP6TABLES, 2, 1, "-F", (char *)FW_IPV6FILTER_IN);
	va_cmd(IP6TABLES, 2, 1, "-F", (char *)FW_IPV6FILTER_OUT);
#else
	va_cmd(IP6TABLES, 2, 1, "-F", (char *)FW_IPV6FILTER);
#endif

	// packet filtering
	// ip filtering
	total = _mib_chain_total(MIB_V6_IP_PORT_FILTER_TBL);

	// accept related
	// ip6tables -A ipv6filter -m state --state ESTABLISHED,RELATED -j RETURN
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	va_cmd(IP6TABLES, 8, 1, (char *)FW_ADD, (char *)FW_IPV6FILTER_IN, "-m", "state",
			"--state", "ESTABLISHED,RELATED", "-j", (char *)FW_RETURN);
	va_cmd(IP6TABLES, 8, 1, (char *)FW_ADD, (char *)FW_IPV6FILTER_OUT, "-m", "state",
			"--state", "ESTABLISHED,RELATED", "-j", (char *)FW_RETURN);
#else
	va_cmd(IP6TABLES, 8, 1, (char *)FW_ADD, (char *)FW_IPV6FILTER, "-m", "state",
			"--state", "ESTABLISHED,RELATED", "-j", (char *)FW_RETURN);
#endif
	// ip6tables -A ipv6filter -d ff00::/8 -j RETURN
	//va_cmd(IP6TABLES, 6, 1, (char *)FW_ADD, (char *)FW_IPV6FILTER, "-d",
	//	"ff00::/8", "-j", (char *)FW_RETURN);

	for (i = 0; i < total; i++)
	{
		pIpEntry= (typeof(pIpEntry))_mib_chain_get(MIB_V6_IP_PORT_FILTER_TBL, i);
		if(!pIpEntry)
		{
			printf("mib chain MIB_V6_IP_PORT_FILTER_TB get fail!\n");
			continue;
		}

		setEachIPv6FilterRuleByPD(pIpEntry, pDLGInfo);
	}

	// Kill all conntrack (to kill the established conntrack when change ip6tables rules)
	va_cmd("/bin/ethctl", 2, 0, "conntrack", "killall");

	//----------------------------------------------
	//   Now setup incoming/outgoing default rule
	//----------------------------------------------
	printf("Setup default Firewall rule.\n");
	if (_mib_get(MIB_V6_IPF_OUT_ACTION, (void *)&ivalue) != 0)
	{
		if (ivalue == 0)	// DROP
		{
			// ip6tables -A ipv6filter -i $LAN_IF -j DROP
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
			_mib_get(MIB_IPFILTER_OUT_ENABLE, (void*)&enable);
			if(enable==1){
				va_cmd(IP6TABLES, 4, 1, (char *)FW_ADD, (char *)FW_IPV6FILTER_OUT, "-j", (char *)FW_DROP);
			}
#else
			va_cmd(IP6TABLES, 6, 1, (char *)FW_ADD,
					(char *)FW_IPV6FILTER, (char *)ARG_I,
					(char *)LANIF, "-j", (char *)FW_DROP);
#endif
		}
	}

	if (_mib_get(MIB_V6_IPF_IN_ACTION, (void *)&ivalue) != 0)
	{
		if (ivalue == 0)	// DROP
		{
			// ip6tables -A ipv6filter ! -i $LAN_IF -j DROP
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
			_mib_get(MIB_IPFILTER_IN_ENABLE, (void*)&enable);
			if(enable==1){
				va_cmd(IP6TABLES, 4, 1, (char *)FW_ADD, (char *)FW_IPV6FILTER_IN, "-j", (char *)FW_DROP);
			}
#else
			va_cmd(IP6TABLES, 7, 1, (char *)FW_ADD, (char *)FW_IPV6FILTER, "!", (char *)ARG_I, (char *)LANIF, "-j", (char *)FW_DROP);
#endif
		}
	}
}
#endif
#endif

int doDelegation(const char *fname)
{
	int ret=0;
	char vChar=-1;

	printf("[%s:%d]\n",__func__,__LINE__);
	_restartLanV6ServerByPD((char*)fname);
#if 0
	_mib_get(MIB_V6_IPV6_ENABLE, (void *)&vChar);
	if (vChar == 0)
		return;

	ret = getLeasesInfo(fname, &dlg_info);

	if ( ret == 1 ) {
		unsigned char 	Ipv6AddrStr[48]={0},old_Ipv6AddrStr[48]={0};
		//     IPv6 network  may give prefix with length 56 by prefix delegation,
		//     but only prefix length = 64, SLAAC will work.
		//
		//Ref: rfc4862: Section 5.5.3.  Router Advertisement Processing
		//     If the sum of the prefix length and interface identifier length
		//     does not equal 128 bits, the Prefix Information option MUST be
		//     ignored.
		if( dlg_info.prefixLen!=64 )
			dlg_info.prefixLen=64;


		inet_ntop(PF_INET6, (struct in6_addr *)dlg_info.prefixIP, Ipv6AddrStr, sizeof(Ipv6AddrStr));
		inet_ntop(PF_INET6, (struct in6_addr *)old_dlg_info.prefixIP, old_Ipv6AddrStr, sizeof(Ipv6AddrStr));

		// Reset RADVD conf
		if( strcmp(old_Ipv6AddrStr,"::")!=0 && strcmp(Ipv6AddrStr,old_Ipv6AddrStr)!=0)
			_setup_radvd_conf(1, &dlg_info, &old_dlg_info);
		else
			_setup_radvd_conf(1, &dlg_info, NULL);

		memcpy(&old_dlg_info,&dlg_info,sizeof(old_dlg_info));
		// Reset DHCPDV6 conf
		_start_dhcpv6(1, &dlg_info);

#ifndef CONFIG_E8B
#ifndef CONFIG_IPV6_OLD_FILTER
		updateIPV6FilterByPD(&dlg_info);
#endif
#endif
		va_cmd("/bin/cp", 2, 1, fname, "/var/prefix_info");
	}
#endif
	return 1;
}

static void cfg_delegation(struct mymsgbuf *qbuf)
{
	doDelegation(qbuf->msg.mtext);
	qbuf->request = MSG_SUCC;
}
#endif
#endif // #ifdef CONFIG_IPV6

/*
 *	upload <filename>	---	upload firmware
 */
// Brian --- for debug
//FILE *myfp;
//const char ftpFile[]="/var/msglog";
//const char killFile[]="/var/killlog";
struct pidStruc {
	PID_SHIFT_T shift;
	char *pidFile;
};

static struct pidStruc killProcessFile[]=
{
#ifdef CONFIG_USER_MONITORD
	{PID_MONITORD, "monitord.pid"},
#endif
#if defined(CONFIG_USER_OPENJDK8) && (defined(CONFIG_CMCC) || defined(CONFIG_CU))
	{PID_JAVA, "java.pid"},
#endif
	{PID_DNSMASQ, "dnsmasq.pid"},
	{PID_SNMPD, "snmpd.pid"},
	{PID_WEB, "boa.pid"},
	{PID_CLI, "cli.pid"},
	{PID_DHCPD, "udhcpd.pid"},
	{PID_DHCPRELAY, "dhcrelay.pid"},
	{PID_TELNETD, "telnetd.pid"},
	{PID_FTPD, "ftpd.pid"},
	{PID_TFTPD, "tftpd.pid"},
	{PID_SSHD, "dropbear.pid"},
	{PID_SYSLOGD, "syslogd.pid"},
	{PID_KLOGD, "klogd.pid"},
	{PID_IGMPPROXY, "igmp_pid"},
	{PID_RIPD, "routed.pid"},
	{PID_WATCHDOGD, "wdg.pid"},
	{PID_SNTPD, "vsntp.pid"},
	{PID_MPOAD, "mpoad.pid"},
	{PID_SPPPD, "spppd.pid"},
	{PID_UPNPD, "linuxigd.pid"},
	{PID_UPDATEDD, "updatedd.pid"},
	{PID_CWMP, "cwmp.pid"}, /*tr069/cwmpClient pid,jiunming*/
	{PID_WSCD, "wscd-wlan0.pid"},
	{PID_MINIUPNPD, "mini_upnpd.pid"},
	{PID_SMBD, "smbd.pid"},
	{PID_NMBD, "nmbd.pid"},
#ifdef VOIP_SUPPORT
	{PID_VOIPGWDT, "voip_gwdt.pid"},
	{PID_SOLAR, "solar.pid"},
#endif
	{-1, 0}
};

#define CONF_PIDFILE_PATH  "/var/run"
#define SIGKILL		 9
#define SIGTERM		15
int g_killprocess=KILL_PROCESS_OFF;
static void cfg_killprocess(struct mymsgbuf *qbuf)
{
	int  spid, index;
	FILE *spidfile;
	unsigned int pidMask, thisPid;

	qbuf->request = MSG_FAIL;

	if (chdir (CONF_PIDFILE_PATH) < 0){
		return;
	}

#ifdef CONFIG_USER_WATCHDOG_WDG
	// Mason Yu
	va_cmd_no_echo("/bin/wdg", 1, 1, "off");
#endif

	pidMask = (unsigned int)qbuf->msg.arg1;

	for( index=0; killProcessFile[index].pidFile; index++ )
	{
		// check for process mask
		thisPid = 1 << killProcessFile[index].shift;
		if (!(thisPid & pidMask))
			continue;
		if ((spidfile = fopen( killProcessFile[index].pidFile, "r"))) {
			// Mason Yu
			if ( strcmp("updatedd.pid", killProcessFile[index].pidFile) == 0 ) {
				g_killprocess = KILL_PROCESS_ON;
			}

			fscanf(spidfile, "%d\n", &spid);
			fclose(spidfile);
			unlink(killProcessFile[index].pidFile);
			printf("kill=%s spid=%d\n", killProcessFile[index].pidFile, spid);
			//fprintf(myfp, "cfg_killprocess: kill=%s spid=%d\n", killProcessFile[index].pidFile, spid);
			//fflush(myfp);
			kill( spid, SIGTERM);
		}
	}

	qbuf->request = MSG_SUCC;
}

#include <linux/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#define SIOCETHTEST_SAVED 0x89a1

struct arg{
	unsigned char cmd;
	unsigned int cmd2;
	unsigned int cmd3;
	unsigned int cmd4;
}pass_arg_saved;

void reboot_by_watchdog()
{
	struct ifreq	ifr;
  	int fd=0;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
  	if(fd< 0){
		printf("Saved: Watchdog control fail!\n");
		goto fail;
  	}
	strncpy(ifr.ifr_name, "eth0", 16);
	ifr.ifr_data = (void *)&pass_arg_saved;

	pass_arg_saved.cmd=14;  //watchdog command
    	pass_arg_saved.cmd2=2;
    	pass_arg_saved.cmd3=0;

	ioctl(fd, SIOCETHTEST_SAVED, &ifr);
	close(fd);
fail:
	return;
}

#ifdef CONFIG_LUNA_FIRMWARE_UPGRADE_SUPPORT
static void fw_upload(const char *fname, int offset, int imgFileSize, int needreboot)
{
	int active, ret;
	char str_active[64], buf[256];

	struct stat st;
	char tmpfilep[] = "/tmp/imgXXXXXX";
	int src_fd=0, dst_fd=0;
	size_t count;

	if (stat(fname, &st)) {
		perror("stat");
		goto reboot;
	}

	/* copy the necessary part */
	if (offset != 0 || imgFileSize != st.st_size) {
		src_fd = open(fname, O_RDONLY);
		if (src_fd < 0) {
			perror("src_fd");
			goto reboot;
		}

		dst_fd = mkstemp(tmpfilep);
		if (dst_fd < 0) {
			perror("dst_fd");
			close(src_fd);
			goto reboot;
		}

		lseek(src_fd, offset, SEEK_SET);
		while (imgFileSize > 0) {
			count = (sizeof(buf) < imgFileSize) ? sizeof(buf) : imgFileSize;
			ret = read(src_fd, buf, count);
			assert(ret == count);

			count = ret;
			ret = write(dst_fd, buf, count);
			assert(ret == count);

			imgFileSize -= ret;
		}

		close(src_fd);
		close(dst_fd);
		fname = tmpfilep;
	}

	/* if active is '0' now, then '1' should be upgraded */
	rtk_env_get("sw_active", str_active, sizeof(str_active));
	sscanf(str_active, "sw_active=%d", &active);
	sprintf(str_active, "%d", 1 - active);
	snprintf(buf, sizeof(buf), "/etc/scripts/fwu_starter.sh %s %s", str_active, fname);
	/* To prevent system() to return ECHILD */
	signal(SIGCHLD, SIG_DFL);
	ret = system(buf);

	if (ret == 0 || ret == 2)	/* 2: Only framework upgraded */
	{
#ifdef CONFIG_USER_CWMP_TR069
		/* cwmpClient have set fault code to 9010, reset to 0 if sucess.*/
		/* Fix me if you have better idea. */
		unsigned int fault = 0;
		mib_set( CWMP_DL_FAULTCODE, &fault );
		mib_update(CURRENT_SETTING, CONFIG_MIB_ALL);
#endif
	}

	if(ret == 0)
	{
		//rtk_env_set("sw_updater", "web", strlen("web"));
		//rtk_env_set("sw_tryactive", str_active, sizeof(str_active));
		rtk_env_set("sw_updater", "web");
		rtk_env_set("sw_tryactive", str_active);
	}

reboot:
#ifdef SUPPORT_PUSHWEB_FOR_FIRMWARE_UPGRADE
	// Let dl_notify.asp have chance to re-load.
	printf("Wait 3 seconds for web refresh...\n");
	sleep(3);
#endif

		
#ifdef SUPPORT_WEB_PUSHUP
	if(firmwareUpgradeConfigStatus()==FW_UPGRADE_STATUS_PROGGRESSING)
		firmwareUpgradeConfigStatusSet(FW_UPGRADE_STATUS_SUCCESS);
#endif
	
	if(needreboot)
	{
		printf("The system is restarting ...\n");
		sysReboot(NULL);
	}
	else
	{
		printf("(needreboot=0) The system is not going to restart. \n");
#ifdef SUPPORT_PUSHWEB_FOR_FIRMWARE_UPGRADE
		unsigned int time=0;
#ifdef CONFIG_YUEME
		fwupgrade_pushweb_set(0, 500, 300, 100, 100, "http://192.168.1.1:8080/dl_notify.asp", time, -1);
#else
		fwupgrade_pushweb_set(0, 500, 300, 100, 100, "http://192.168.1.1/dl_notify.asp", time, -1);
#endif
#endif
	}
}
#else
static void fw_upload(const char *fname, int offset, int imgFileSize, int needreboot)
{
	int ret = -1;
	FILE *fp = NULL;
	struct stat st;
	int fsize;
	int hasHdr;
	IMGHDR imgHdr;
#ifdef CONFIG_DOUBLE_IMAGE
	int partCheck = 0;
#endif
#ifdef CONFIG_RTL8686
	char part_name[32];
	unsigned int image_len = 0;
#endif

// Kaohj -- TR068 Power LED
//star: for ZTE power LED request
	unsigned char power_flag;

	fp = fopen("/proc/power_flag", "w");
	if (fp) {
		power_flag = '1';
		fwrite(&power_flag, 1, 1, fp);
		fclose(fp);
		fp = NULL;
	}

#ifdef ENABLE_SIGNATURE
	offset += sizeof(SIGHDR);
	fsize = imgFileSize - sizeof(SIGHDR);
#else
	fsize = imgFileSize;
#endif

	if ((fp = fopen(fname, "rb")) == NULL) {
		fprintf(stderr, "File %s open fail\n", fname);
		goto ERROR_RET;
	}

	if (fstat(fileno(fp), &st) < 0)
		goto ERROR_RET;

	if (fseek(fp, offset, SEEK_SET) == -1)
		goto ERROR_RET;

	if (fsize <= 0)
		goto ERROR_RET;

	// simple check for image header. Making it backward compatible for now.
	// Andrew
#ifdef CONFIG_RTL8686
check_next_header:
	if (1 == fread(&imgHdr, sizeof(imgHdr), 1, fp)) {
		switch (imgHdr.key) {
		case APPLICATION_UBOOT:
			hasHdr = 1;
			strcpy(part_name, "boot");
			printf("%s-%d::find uboot img\n", __func__, __LINE__);
			break;
		case APPLICATION_UIMAGE:
			hasHdr = 1;
			strcpy(part_name, "linux");
			printf("%s-%d::find linux img\n", __func__, __LINE__);
			break;
		case APPLICATION_ROOTFS:
			hasHdr = 1;
			strcpy(part_name, "rootfs");
			printf("%s-%d::find rootfs img\n", __func__, __LINE__);
			break;
		default:
			hasHdr = 0;
			fseek(fp, offset, SEEK_SET);
			printf("img with unknown header! hasHdr=%d\n", hasHdr);
			break;
		}
		if (hasHdr) {
			image_len = imgHdr.length;
			printf("%s(%d)::image_len:%d\n", __func__,
			       __LINE__, image_len);
#ifndef CONFIG_ENABLE_KERNEL_FW_UPDATE
			fsize -= sizeof(IMGHDR);
#endif
		}
	} else {
		hasHdr = 0;
		if(fseek(fp, offset, SEEK_SET) ==  -1)
			printf("%s-%d fseek error\n",__func__,__LINE__);
		printf("img without header! hasHdr=%d\n", hasHdr);
	}
#else //CONFIG_RTL8686
	if ((1 == fread(&imgHdr, sizeof(imgHdr), 1, fp)) &&
	    (APPLICATION_IMAGE == imgHdr.key)) {
		hasHdr = 1;
		fsize -= sizeof(IMGHDR);
	} else {
		hasHdr = 0;
		if(fseek(fp, offset, SEEK_SET)==-1)
			printf("%s-%d fseek error\n",__func__,__LINE__);
	}
#endif /*CONFIG_RTL8686 */

	printf("filesize(Not include imgHdr(64 bytes))  = %d\n", fsize);
	printf("imgFileSize = %d\n", imgFileSize);

#ifdef CONFIG_ENABLE_KERNEL_FW_UPDATE
	do {
		char buf[128];
		int part = 1;

#ifdef CONFIG_PPP
		// Jenny, disconnect PPP before rebooting
		stopPPP();
#endif
#ifdef CONFIG_DOUBLE_IMAGE
		//printf("check current rootfs... ");
		//ql: check the run-time image block
		flash_read(&partCheck, PART_CHECK_OFFSET, sizeof(partCheck));

		printf("[%s(%d)] partCheck=0x%X\n",__func__,__LINE__,partCheck);
		__mib_flash_read(&partCheck, PART_CHECK_OFFSET, 4);
		if (!partCheck) {
			printf("latest is the first!\n");
			partCheck = 0xffffffff;
			flash_write(&partCheck, PART_CHECK_OFFSET, sizeof(partCheck));
			part = 2;
			printf("write second rootfs finished!\n");
		} else {
			printf("latest is the second!\n");
			partCheck = 0;
			flash_write(&partCheck, PART_CHECK_OFFSET, sizeof(partCheck));
			part = 1;
			printf("write first rootfs finished!\n");
		}
#endif /* CONFIG_DOUBLE_IMAGE */

		system("echo -n \"1321\" > /proc/fwupdate");
#ifdef CONFIG_RTL8686
		/* 8696 series take whole image as input */
		snprintf(buf, sizeof(buf), "echo -n \"%d;%s;%d;%d\" > /proc/fwupdate", offset, fname, part, fsize);
#else
		if (hasHdr) {
			snprintf(buf, sizeof(buf), "echo -n \"%d;%s;%d;%d\" > /proc/fwupdate", offset+sizeof(imgHdr), fname, part, fsize);
		}
		else {
			snprintf(buf, sizeof(buf), "echo -n \"%d;%s;%d;%d\" > /proc/fwupdate", offset, fname, part, fsize);
		}
#endif
		printf("cmd: %s\n", buf);
		fclose(fp);
		fp == NULL;
		system(buf);
		while (1);
	} while (0);
#else
#ifdef CONFIG_DOUBLE_IMAGE
	flash_read(&partCheck, PART_CHECK_OFFSET, sizeof(partCheck));

	if (!partCheck) {
		printf("latest is the first!\n");

		ret = flashdrv_filewrite(fp, fsize, g_fs_bak_offset);

		partCheck = 0xffffffff;

		flash_write(&partCheck, PART_CHECK_OFFSET, sizeof(partCheck));

		printf("write second rootfs finished!\n");
	} else {
		printf("latest is the second!\n");

		ret = flashdrv_filewrite(fp, fsize, g_rootfs_offset);
		
		partCheck = 0;

		flash_write(&partCheck, PART_CHECK_OFFSET, sizeof(partCheck));
		
		printf("write first rootfs finished!\n");
	}
#else	//!CONFIG_DOUBLE_IMAGE start
#ifdef CONFIG_RTL8686
	if (hasHdr) {
		ret = flash_filewrite(fp, image_len, part_name);
		fsize -= image_len;

		if (fsize > sizeof(imgHdr)) {
			goto check_next_header;
		}
	} else {
		printf("%s-%d:: can't find your image KEY! ret:%d\n", __func__,
		       __LINE__, ret);
	}
#else /* else CONFIG_RTL8686 */
	ret = flashdrv_filewrite(fp, fsize, g_rootfs_offset);
#endif /* CONFIG_RTL8686 */
#endif /* CONFIG_DOUBLE_IMAGE*/

	if (ret)
		printf("flash error!\n");
	else
		printf("flash write completed !!\n");

#endif //#ifdef CONFIG_ENABLE_KERNEL_FW_UPDATE
ERROR_RET:
	if(fp!=NULL)
		fclose(fp);
	unlink(fname);
#ifdef SUPPORT_WEB_PUSHUP
		if(firmwareUpgradeConfigStatus()==FW_UPGRADE_STATUS_PROGGRESSING)
			firmwareUpgradeConfigStatusSet(FW_UPGRADE_STATUS_SUCCESS);
#endif
		if(needreboot)
		{
			printf("The system is restarting ...\n");
			sysReboot(NULL);
		}
		else
		{
			printf("(needreboot=0) The system is not going to restart. \n");
#ifdef SUPPORT_PUSHWEB_FOR_FIRMWARE_UPGRADE
			unsigned int time=0;
#ifdef CONFIG_YUEME
			fwupgrade_pushweb_set(0, 500, 300, 100, 100, "http://192.168.1.1:8080/dl_notify.asp", time, -1);
#else
			fwupgrade_pushweb_set(0, 500, 300, 100, 100, "http://192.168.1.1/dl_notify.asp", time, -1);
#endif
#endif
		}
}
#endif

static void *fwUpload(void *data)
{
#ifdef CONFIG_USER_RTK_RECOVER_SETTING	// Save Setting to flatfsd(flash).
	va_cmd("/bin/saveconfig", 1, 1, "-s");
#endif
	/*
	 * Default value is PTHREAD_CANCEL_DEFERRED that
	 * a cancellation request is deferred until the thread
	 * next calls a function that is a cancellation point.
	 * Setting cancel type to PTHREAD_CANCEL_ASYNCHRONOUS is for
	 * the thread being canceled at any time.
	 */
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

	fw_upload(g_upload_post_file_name, g_upload_startPos, g_upload_fileSize, g_upload_needreboot);

	// We can use pthread_exit() or return to terminate this thread.
	pthread_exit(NULL);
}

static void cfg_upload(struct mymsgbuf *qbuf)
{
	static pthread_t ptUploadId;

	if (qbuf->msg.arg2 == 0) {
		printf("Cancel Upload therad\n");

		pthread_cancel(ptUploadId);
	} else {
		//tylo, telefonica LED flash while firmware upgrade
		if (access("/proc/fwupgrade_flag", F_OK) == 0)
			system("echo 1 > /proc/fwupgrade_flag");
		unlink("/var/log/messages");

		g_upload_startPos = qbuf->msg.arg1;
		g_upload_fileSize = qbuf->msg.arg2;
		g_upload_needreboot = qbuf->msg.arg3;
		strncpy(g_upload_post_file_name, qbuf->msg.mtext,
			MAX_SEND_SIZE);
		g_upload_post_file_name[MAX_SEND_SIZE - 1] = '\0';
		// To create Upload thread
		printf("Create Upload thread\n");

		pthread_create(&ptUploadId, NULL, fwUpload, NULL);
		pthread_detach(ptUploadId);
	}
	qbuf->request = MSG_SUCC;
}

static void cfg_check_image(struct mymsgbuf *qbuf)
{
	FILE	*fp=NULL;
	IMGHDR imgHdr;
	unsigned int csum;
	int nRead, total = 0;
	unsigned char buf[64];
	int offset, size, remain, block;
#ifdef CONFIG_RTL8686
	int err=-1;
#endif
#if defined(ENABLE_SIGNATURE)
	SIGHDR sigHdr;
	int i;
	unsigned int hdrChksum;
#endif

	qbuf->request = MSG_FAIL;
	offset = qbuf->msg.arg1;

	if ((fp = fopen (qbuf->msg.mtext, "rb")) == NULL) {
		printf("File %s open fail\n", qbuf->msg.mtext);
		return;
	}

	if (fseek(fp, offset, SEEK_SET)==-1) {
		//jim should delete below fclose, otherwise will be closed twice...
		//fclose(fp);
		goto M_ERROR;
	}
#if defined(ENABLE_SIGNATURE)
//ql add to check if the image is right.
	memset(&sigHdr, 0, sizeof(sigHdr));
	if (1 != fread(&sigHdr, sizeof(sigHdr), 1, fp)) {
		printf("failed to read signature\n");
		goto M_ERROR;
	}
#endif

	if (1!=fread(&imgHdr, sizeof(imgHdr), 1, fp)) {
		printf("Failed to read header\n");
		goto M_ERROR;
	}
#ifndef ENABLE_SIGNATURE_ADV
#ifdef ENABLE_SIGNATURE
	if (sigHdr.sigLen > SIG_LEN) {
		printf("signature length error\n");
		goto M_ERROR;
	}
	for (i=0; i<sigHdr.sigLen; i++)
		sigHdr.sigStr[i] = sigHdr.sigStr[i] - 10;
	if (strcmp(sigHdr.sigStr, SIGNATURE)) {
		printf("signature error\n");
		goto M_ERROR;
	}

	hdrChksum = sigHdr.chksum;
	hdrChksum = ipchksum(&imgHdr, sizeof(imgHdr), hdrChksum);
	if (hdrChksum) {
		printf("Checksum failed(msgparser cfg_check_image), size=%d, csum=%04xh\n", sigHdr.sigLen, hdrChksum);
		goto M_ERROR;
	}
#endif
#endif

#ifdef CONFIG_RTL8686
		switch(imgHdr.key){
			case APPLICATION_UBOOT:
			case APPLICATION_UIMAGE:
			case APPLICATION_ROOTFS:
				printf("%s-%d, got header::%x\n",__func__,__LINE__,imgHdr.key);
				err = 0;
				break;
			default:
				printf("%s-%d, Unknown header::%x\n",__func__,__LINE__,imgHdr.key);
				err = 1;
				break;
		}
		if(err)
			goto M_ERROR;
#else
	if (imgHdr.key != APPLICATION_IMAGE) {
		printf("Unknown header\n");
		goto M_ERROR;
	}
#endif

	csum = imgHdr.chksum;
	size = imgHdr.length;
	remain = size;

	while (remain > 0) {
		block = (remain > sizeof(buf)) ? sizeof(buf) : remain;
		nRead = fread(buf, 1, block, fp);
		if (nRead <= 0) {
			printf("read too short (remain=%d, block=%d)\n", remain, block);
			goto M_ERROR;
		}
		remain -= nRead;
		csum = ipchksum(buf, nRead,csum);
	}
#if 0
	csum = imgHdr.chksum;
	while (nRead = fread(buf, 1, sizeof(buf), fp)) {
		total += nRead;
		csum = ipchksum(buf, nRead, csum);
	}
#endif

	if (csum) {
		printf("Checksum failed(msgparser cfg_check_image2), size=%d, csum=%04xh\n", total, csum);
		goto M_ERROR;
	}
	qbuf->request = MSG_SUCC;

M_ERROR:
	fclose(fp);
	return;
}


#ifdef CONFIG_USER_DDNS
static void cfg_ddns_ctrl(struct mymsgbuf *qbuf)
{
	struct ddns_info tinfo;

	strcpy(tinfo.ifname, qbuf->msg.mtext);
	tinfo.ipversion= qbuf->msg.arg1;

	// Mason Yu.  create DDNS thread dynamically
	startDdnsc(tinfo);
	qbuf->request = MSG_SUCC;
	return;
}
#endif

// Kaohj -- transform received file to xml file
const char tmpxml[] = "/tmp/tmpdecryxor.xml";
static void cfg_file2xml(struct mymsgbuf *qbuf)
{
	FILE	*fpin=NULL;
	char LINE[256], str[64], str2[64];
	struct mymsgbuf myqbuf;
	MSGFile_T *pFile;

	qbuf->request = MSG_FAIL;

	pFile = (MSGFile_T *)&qbuf->msg.mtext[0];
	#ifdef XOR_ENCRYPT
	rename(pFile->fromName, tmpxml);
	xor_encrypt((char *)tmpxml, pFile->toName);
	unlink(tmpxml);
	#else
	if (strcmp(pFile->fromName, pFile->toName))
		rename(pFile->fromName, pFile->toName);
	#endif

	if ((fpin = fopen (pFile->toName, "rb")) == NULL)
		return;

	fseek(fpin, 0, SEEK_SET);
	fgets(LINE, sizeof(LINE), fpin);
	fclose(fpin);
	if (strncmp(LINE, CONFIG_HEADER, strlen(CONFIG_HEADER)) &&
		strncmp(LINE, CONFIG_HEADER_HS, strlen(CONFIG_HEADER_HS))) {
		// header error, not xml config file
		unlink(pFile->toName);
		return;
	}

	qbuf->request = MSG_SUCC;
}

// Kaohj -- transform xml file to backup file
static void cfg_xml2file(struct mymsgbuf *qbuf)
{
	struct mymsgbuf myqbuf;
	MSGFile_T *pFile;

	qbuf->request = MSG_FAIL;

	pFile = (MSGFile_T *)&qbuf->msg.mtext[0];
	#ifdef XOR_ENCRYPT
	rename(pFile->fromName, tmpxml);
	xor_encrypt((char *)tmpxml, pFile->toName);
	unlink(tmpxml);
	#else
	if (strcmp(pFile->fromName, pFile->toName))
		rename(pFile->fromName, pFile->toName);
	#endif

	qbuf->request = MSG_SUCC;
}

#ifndef _USE_RSDK_WRAPPER_
#include "../../../spppd/pppoe.h"
#endif  //_USE_RSDK_WRAPPER_
static void cfg_update_PPPoE_session(struct mymsgbuf *qbuf)
{
	PPPOE_SESSION_INFO *p = (PPPOE_SESSION_INFO *)qbuf->msg.mtext;
	unsigned int totalEntry;
	int i, found=0, selected=-1;
	MIB_CE_PPPOE_SESSION_Tp Entry;

	qbuf->request = MSG_FAIL;

	if (__mib_lock) {
		qbuf->request = MSG_MIB_LOCKED;
		return;
	}

	//update_PPPoE_session(p);
	totalEntry = _mib_chain_total(MIB_PPPOE_SESSION_TBL);
	for (i=0; i<totalEntry; i++) {
		selected = i;
		Entry = (typeof(Entry))_mib_chain_get(MIB_PPPOE_SESSION_TBL, i);
		if (!Entry) {
  			printf("Get chain record error!\n");
			return;
		}

		if (Entry->uifno == p->uifno)
		{
			found ++;
				break;
		}
	}

	if (found != 0) {
		Entry->sessionId = p->session;
		memcpy((unsigned char *)Entry->acMac, (unsigned char *)p->remote.sll_addr, 6);
			_mib_chain_update(MIB_PPPOE_SESSION_TBL, (void *)Entry, selected);
		}
	else {
		MIB_CE_PPPOE_SESSION_T entry;
		memset(&entry, 0, sizeof(entry));
		entry.uifno = p->uifno;
		memcpy((unsigned char *)entry.acMac, (unsigned char *)p->remote.sll_addr, 6);
		entry.sessionId = p->session;
		_mib_chain_add(MIB_PPPOE_SESSION_TBL, (void *)&entry);
	}

	qbuf->request = MSG_SUCC;
}

static void cfg_mib_set_PPPoE(struct mymsgbuf *qbuf)
{
	struct mymsgbuf myqbuf;
	PPPOE_SESSION_INFO *p = (PPPOE_SESSION_INFO *)qbuf->msg.mtext;

	qbuf->request = MSG_FAIL;

	if (__mib_lock) {
		qbuf->request = MSG_MIB_LOCKED;
		return;
	}

	myqbuf.msg.arg1 = CONFIG_MIB_CHAIN;
	cfg_mib_backup(&myqbuf);	// backup current MIB chain into system
	myqbuf.msg.arg1 = CURRENT_SETTING;
	myqbuf.msg.arg2 = CONFIG_MIB_CHAIN;
	cfg_mib_reload(&myqbuf);	//get MIB chain from flash
	myqbuf.msg.arg1 = (int)qbuf->msg.arg1;
	memcpy(myqbuf.msg.mtext, qbuf->msg.mtext, myqbuf.msg.arg1);
	cfg_update_PPPoE_session(&myqbuf);

	myqbuf.msg.arg1 = CURRENT_SETTING;
	myqbuf.msg.arg2 = CONFIG_MIB_CHAIN;
	cfg_mib_update(&myqbuf);

	myqbuf.msg.arg1 = CONFIG_MIB_CHAIN;
	cfg_mib_restore(&myqbuf);	// restore backup MIB chain
	myqbuf.msg.arg1 = (int)qbuf->msg.arg1;
	memcpy(myqbuf.msg.mtext, qbuf->msg.mtext, myqbuf.msg.arg1);
	cfg_update_PPPoE_session(&myqbuf);
	qbuf->request = MSG_SUCC;
}

#endif

int get_tr069_ifname()
{
#ifdef CONFIG_USER_RTK_WAN_CTYPE
	int total = _mib_chain_total(MIB_ATM_VC_TBL);
	int i;
	MIB_CE_ATM_VC_T *entry;
	struct in_addr inAddr;
	int flags = 0;
	char ifname[IFNAMSIZ];

	for(i = 0 ; i < total ; i++)
	{
		if(!(entry = (typeof(entry))_mib_chain_get(MIB_ATM_VC_TBL,i)))
		//if(mib_chain_get(MIB_ATM_VC_TBL, i, &entry)!=1)
			continue;

		if(entry->applicationtype & X_CT_SRV_TR069)
		{
			if(ifGetName( entry->ifIndex, ifname, IFNAMSIZ) == 0)
				continue;

			if (getInFlags( ifname, &flags) == 1 && flags & IFF_UP)
			{
				if (getInAddr(ifname, IP_ADDR, (void *)&inAddr) == 1) {
					//printf("***** Find a active TR069 on %s interface.\n", ifname);
					return 1;
				}
			}
		}
	}
	return 0;
#else
	return 0;
#endif
}

#ifdef VOIP_SUPPORT
int get_voip_ifname()
{
#ifdef CONFIG_USER_RTK_WAN_CTYPE
	int total = _mib_chain_total(MIB_ATM_VC_TBL);
	int i;
	MIB_CE_ATM_VC_T *entry;
	struct in_addr inAddr;
	int flags = 0;
	char ifname[IFNAMSIZ];

	for(i = 0 ; i < total ; i++)
	{
		if(!(entry = (MIB_CE_ATM_VC_T *)_mib_chain_get(MIB_ATM_VC_TBL,i)))
		//if(mib_chain_get(MIB_ATM_VC_TBL, i, &entry)!=1)
			continue;

		if(entry->applicationtype & X_CT_SRV_VOICE)
		{
			if(ifGetName( entry->ifIndex, ifname, IFNAMSIZ) == 0)
				continue;

			if (getInFlags( ifname, &flags) == 1 && flags & IFF_UP)
			{
				if (getInAddr(ifname, IP_ADDR, (void *)&inAddr) == 1) {
					//printf("***** Find a active VoIP on %s interface.\n", ifname);
					return 1;
				}
			}
		}
	}
	return 0;
#else
	return 0;
#endif
}
#endif

#if defined(CONFIG_E8B) && defined(TIME_ZONE)
extern inline unsigned int getNTPChannelIfindex();
inline unsigned int getNTPChannelIfindex()
{
	unsigned int if_wan = DUMMY_IFINDEX;

	//get interface name by if_wan
	_mib_get(MIB_NTP_IF_WAN, &if_wan);

	return if_wan;
}
#endif

//return 1: registered, return 0: failed.
static int _check_user_is_registered()
{
#if defined(_PRMT_X_CT_COM_USERINFO_) && defined(E8B_NEW_DIAGNOSE)
 	unsigned int regStatus;
	unsigned char no_pop;

	_mib_get(PROVINCE_NO_POPUP_REG_PAGE, &no_pop);
	_mib_get(CWMP_USERINFO_STATUS, &regStatus);

	if(regStatus == 0 || regStatus == 5 || no_pop)
		return 1;
#endif

	return 0;
}

#ifdef CONFIG_SUPPORT_PON_LINK_DOWN_PROMPT
static int getPONState()
{
	unsigned int pon_mode;
	rtk_gpon_fsm_status_t onu;
	rtk_epon_llid_entry_t llid_entry;
	_mib_get(MIB_PON_MODE, &pon_mode);

	if(pon_mode == GPON_MODE)
	{
#if defined(CONFIG_RTK_L34_ENABLE)
		rtk_rg_gpon_ponStatus_get(&onu);
#else
		rtk_gpon_ponStatus_get(&onu);
#endif
		if(onu == 5)
		{
			return 1;
		}
	}
	else if(pon_mode == EPON_MODE)
	{
#if defined(CONFIG_RTK_L34_ENABLE)
		rtk_rg_epon_llid_entry_get(&llid_entry);
#else
		rtk_epon_llid_entry_get(&llid_entry);
#endif
 		 if (llid_entry.valid)
	 	{
	        	int ret;

	        	ret = epon_getAuthState(llid_entry.llidIdx);
	       	 if (1 == ret)
	       	 {
				return 1;
	       	 }
		}
	}

	return 0;
}
#endif

#ifdef CTC_DNS_TUNNEL
void write_dns_tunnel_conf(FILE *fp)
{
	MIB_CE_DNS_TUNNEL_T *entry;
	int total, i;
	char *domain = NULL, ip_addr[40] = "";

	total = _mib_chain_total(MIB_DNS_TUNNEL_TBL);
	for(i = 0 ; i < total ; i++)
	{
		entry = (MIB_CE_DNS_TUNNEL_T *)_mib_chain_get(MIB_DNS_TUNNEL_TBL, i);
		if(entry == NULL)
			continue;

		if(inet_ntop(AF_INET, (void *)entry->server_ip, ip_addr, sizeof(ip_addr)) == NULL)
		{
			fprintf(stderr, "WARNNING: server_ip of index %d is invalid\n", i);
			continue;
		}

		fprintf(fp, "reg-server=/%s/%s\n", entry->domain, ip_addr);
	}
}
#endif

//ipv6
//inet_pton(AF_INET6, "2001:db8:8714:3a90::12", &(sa.sin6_addr));
//inet_ntop(AF_INET6, &(sa.sin6_addr), str, INET6_ADDRSTRLEN);
//ipv4
//inet_pton(AF_INET, "192.0.2.33", &(sa.sin_addr));
//inet_ntop(AF_INET, &(sa.sin_addr), str, INET_ADDRSTRLEN);
//check if input dns is ip or not, if dns is IPv6 addr --> do not write it into
//dnsmasq.conf, or it would have problem in voip service.
static void check_dnsIP(FILE *dnsfp, char *path, char *dns, char *buf, char *IP)
{
	struct sockaddr_in sa;
	struct sockaddr_in6 sa6;
#if 0	
	if(NULL != IP)
		AUG_PRT("path=%s, dns = %s, buf=%s, IP=%s\n",path,dns, buf, IP);		
	else
		AUG_PRT("path=%s, dns = %s, buf=%s\n",path,dns, buf);
#endif	
	if( (inet_pton(AF_INET, dns, &(sa.sin_addr)) != 1) && (inet_pton(AF_INET6, dns, &(sa6.sin6_addr)) != 1))
	{
		//AUG_PRT("===> %s\%s\n",dns, buf);
		if(NULL != IP)
			fprintf(dnsfp, path, dns, buf, IP);
		else
			fprintf(dnsfp, path, dns, buf);			
	}
}

// Mason Yu. for copy the ppp & dhcp nameserver to the /var/dnsmasq.conf
static int fixUpDnsServer(char *itfname)
{
	FILE *dnsfp=fopen(DNSMASQ_CONF,"w");		/*save the DNS config into dnsmasq.conf*/
	FILE *dns2fp=fopen(RESOLV_BACKUP,"w");		/*save the DNS config into /var/resolv_backup.conf */
	FILE *dbusdnsfp=fopen(DBUS_DNS_FILE,"w");
	unsigned int entryNum, i;
	MIB_CE_ATM_VC_T *Entry;
	char wanif[IFNAMSIZ];
	char buf[1024]={0};
	char dns1[16]={0};
	char dns2[16]={0};
	char vStr[256+1];
	char acsurl[256+1]={0};
	char ipAddr[16];
	unsigned int index = 0, ntpItf;
	char ntpURL1[32] = {0};
	char ntpURL2[32] = {0};
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	char ntpURL3[32] = {0};
	char ntpURL4[32] = {0};
	char ntpURL5[32] = {0};
#endif
	char activeTR069=HAVE_NONE, activeVOIP=HAVE_NONE;
	char* p = NULL;
	char dns[16]={0};
	int dnsnum=0, ifindex=0;
	char str_ipaddr[128] = {0};
	char str_netmask[10] = {0};
	char str_gateway[128] = {0};
	char dhcp_domain[MAX_NAME_LEN];

#ifdef CONFIG_SUPPORT_AUTO_DIAG
	char auto_diag_url[128];
	_mib_get(MIB_AUTO_DIAG_URL, (void *)auto_diag_url);
#endif

#ifdef _PRMT_X_CT_COM_QOE_
	unsigned char inform_type = 0;
	_mib_get(PROVINCE_CWMP_INFORM_TYPE, &inform_type);
	unsigned int qoe_applicationtype = 0;

	if (inform_type == CWMP_INFORM_TYPE_GUD) {
		qoe_applicationtype = X_CT_SRV_TR069;
	}
	else if (inform_type == CWMP_INFORM_TYPE_JSU) {
		qoe_applicationtype = X_CT_SRV_INTERNET;
	}
	else { // default
		qoe_applicationtype = X_CT_SRV_TR069;
	}

	char qoe_url[64+1] = {0};
	_mib_get(CWMP_CT_QOE_TESTDOWNLOADURL, (void *)qoe_url);
#endif

#ifdef _CWMP_MIB_
	char dhcp_acs[256+1] = {0};
#ifdef CONFIG_TR142_MODULE
	char omci_acs[256+1] = {0};

	_mib_get(RS_OMCI_ACS_URL, vStr);
	set_endpoint(omci_acs,vStr);
#endif
	_mib_get(CWMP_ACS_URL,(void*)vStr);
	set_endpoint(acsurl,vStr);
	_mib_get(RS_DHCP_ACS_URL, vStr);
	set_endpoint(dhcp_acs,vStr);
#endif



#ifdef TIME_ZONE
#ifdef CONFIG_E8B
	ntpItf = getNTPChannelIfindex();
#else
	_mib_get(MIB_NTP_EXT_ITF, (void *)&ntpItf);
#endif
	_mib_get(MIB_NTP_SERVER_HOST1, (void *)ntpURL1);
	_mib_get(MIB_NTP_SERVER_HOST2, (void *)ntpURL2);
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	_mib_get(MIB_NTP_SERVER_HOST3, (void *)ntpURL3);
	_mib_get(MIB_NTP_SERVER_HOST4, (void *)ntpURL4);
	_mib_get(MIB_NTP_SERVER_HOST5, (void *)ntpURL5);
#endif
#endif

	activeTR069 = get_tr069_ifname();
#ifdef VOIP_SUPPORT
	activeVOIP = get_voip_ifname();
#endif

	unsigned int ping_intf = 0;
	_mib_get(MIB_RS_PING_INTF, (void *)&ping_intf);

	char ping_host[256+1] = {0};
	_mib_get(MIB_RS_PING_HOST, (void *)ping_host);

	unsigned int traceroute_intf = 0;
	_mib_get(MIB_RS_TRACEROUTE_INTF, (void *)&traceroute_intf);

	char traceroute_host[256+1] = {0};
	_mib_get(MIB_RS_TRACEROUTE_HOST, (void *)traceroute_host);

#ifdef CONFIG_USER_BEHAVIOR_ANALYSIS
	unsigned int np_dns_intf = 0;
	char np_dns[32] = {0};
	_mib_get(MIB_RS_NP_DNS_INTF, (void *)&np_dns_intf);
	int np_total = 0, idx = 0;
	MIB_NETWORK_PERFORMANCE_T *NPEntry;
	np_total = _mib_chain_total(MIB_NETWORK_PERFORMANCE_TBL);
	for (idx = 0; idx < np_total; idx++) {
		if (!(NPEntry = _mib_chain_get(MIB_NETWORK_PERFORMANCE_TBL, idx)))
			continue;

		if (NPEntry->performance_type == NETWORK_PERFORMANCE_DNS_QUERY)
			break;
	}

	if (strlen(NPEntry->server)) {
		if (NPEntry->port > 0)
			sprintf(np_dns, "%s#%u", NPEntry->server, NPEntry->port);
		else
			sprintf(np_dns, "%s", NPEntry->server);
	}
#endif

	entryNum = _mib_chain_total(MIB_ATM_VC_TBL);
	if(dnsfp && dns2fp && dbusdnsfp){
		FILE* infdns;
		char value[64];
		//user=
		//group=
		fprintf(dnsfp, "user=\n");
		fprintf(dnsfp, "group=\n");
		// Reserve a static DNS host name for wpad (to disable 'wpad' global query for this domain),
		// as suggested in Microsoft article 934846.
		dhcp_domain[0]=0;
		_mib_get(MIB_ADSL_LAN_DHCP_DOMAIN, (void *)dhcp_domain);
		if (dhcp_domain[0])
			fprintf(dnsfp, "local=/wpad.%s/\n", dhcp_domain);

#ifdef CONFIG_USER_PPPOMODEM
		snprintf(value, 64, "%s.%s%u", (char *)PPP_RESOLV, "ppp", MODEM_PPPIDX_FROM);
		infdns=fopen(value,"r");
		if(infdns){
			while(!feof(infdns))
			{
				memset(buf,0,sizeof(buf));
				fgets(buf,sizeof(buf),infdns);

				if((strlen(buf)==0))
					break;

				// Backup to /var/resolv_backup.conf
				p = strchr(buf, '@');
				if (p) {
					memcpy(dns, buf, p-buf);
					dns[p-buf] = '\0';
					fprintf(dns2fp, "%s\n", dns);
				}
				fprintf(dnsfp, "server=%s", buf);
			}
			fclose(infdns);
		}
#endif

		for (i = 0; i < entryNum; i++) {
			struct in_addr inAddr;
			char ifname[IFNAMSIZ]="";

			/* Retrieve entry */
			if(!(Entry = (typeof(Entry))_mib_chain_get(MIB_ATM_VC_TBL,i))) {
				printf("fixUpDnsServer: cannot get ATM_VC_TBL(ch=%d) entry\n", i);
				fclose(dnsfp);
				fclose(dns2fp);
				fclose(dbusdnsfp);
				return -1;
			}

			ifGetName(Entry->ifIndex,wanif,sizeof(wanif));
			
#ifdef CONFIG_IPV6
			if ( Entry->IpProtocol & IPVER_IPV4 ) 
			{
#endif

				// (1) Merge DNS server for dynamical link and dnsMode = REQUEST_DNS
				if ((((DHCP_T)Entry->ipDhcp == DHCP_CLIENT || Entry->cmode == CHANNEL_MODE_PPPOE) && (Entry->dnsMode == REQUEST_DNS) ) || (Entry->cmode == CHANNEL_MODE_PPPOA) )
				{
					if ((DHCP_T)Entry->ipDhcp == DHCP_CLIENT)
						snprintf(value, 64, "%s.%s", (char *)DNS_RESOLV, wanif);
					if (Entry->cmode == CHANNEL_MODE_PPPOE || Entry->cmode == CHANNEL_MODE_PPPOA)
						snprintf(value, 64, "%s.%s", (char *)PPP_RESOLV, wanif);

					infdns=fopen(value,"r");
					if(infdns){
						while(!feof(infdns))
						{
							memset(buf,0,sizeof(buf));
							fgets(buf,sizeof(buf),infdns);

							if((strlen(buf)==0))
								break;

							// Backup to /var/resolv_backup.conf
							if (Entry->dgw == 1) {
								p = strchr(buf, '@');
								if (p) {
									memcpy(dns, buf, p-buf);
									dns[p-buf] = '\0';
									fprintf(dns2fp, "%s\n", dns);
									if(dnsnum==0){
										getIPaddrInfo(Entry, str_ipaddr, str_netmask, str_gateway);
										fprintf(dbusdnsfp, "%d,%d,%s,%s,%s,%d,%s,", Entry->ifIndex, IPVER_IPV4, str_ipaddr, str_netmask, str_gateway, Entry->dnsMode, dns);
									}
									else{
										fprintf(dbusdnsfp, "%s,", dns);
									}
									dnsnum++;
								}
							}
#ifdef TIME_ZONE
							// NTP bind this interface.
							if (ntpItf == Entry->ifIndex) {
								check_dnsIP(dnsfp, "server=/%s/%s", ntpURL1, buf, NULL);
								check_dnsIP(dnsfp, "server=/%s/%s", ntpURL2, buf, NULL);
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
								check_dnsIP(dnsfp, "server=/%s/%s", ntpURL3, buf, NULL);
								check_dnsIP(dnsfp, "server=/%s/%s", ntpURL4, buf, NULL);
								check_dnsIP(dnsfp, "server=/%s/%s", ntpURL5, buf, NULL);
#endif
							}
#endif

							if ((ping_intf == Entry->ifIndex) && strlen(ping_host)) {
								check_dnsIP(dnsfp, "server=/%s/%s", ping_host, buf, NULL);
							}

							if ((traceroute_intf == Entry->ifIndex) && strlen(traceroute_host)) {
								check_dnsIP(dnsfp, "server=/%s/%s", traceroute_host, buf, NULL);
							}
#ifdef CONFIG_USER_BEHAVIOR_ANALYSIS
							char np_buf[256] = {0};
							char *np_ptr = NULL;
							np_ptr = strchr(buf, '@');
							sprintf(np_buf, "%s%s", np_dns, np_ptr);
	
							if ((np_dns_intf == Entry->ifIndex) && strlen(NPEntry->diag_name) && np_buf[0] != '\0') {
								check_dnsIP(dnsfp, "server=/%s/%s", NPEntry->diag_name, np_buf, NULL);
							}
#endif
#ifdef CONFIG_USER_RTK_WAN_CTYPE
							if (Entry->applicationtype&X_CT_SRV_INTERNET)
								fprintf(dnsfp, "server=%s", buf);
							if (Entry->applicationtype&X_CT_SRV_TR069)
							{
								if(acsurl[0] != 0)
									check_dnsIP(dnsfp, "server=/%s/%s", acsurl, buf, NULL);
								if(dhcp_acs[0] != 0)
									check_dnsIP(dnsfp, "server=/%s/%s", dhcp_acs, buf, NULL);
#ifdef CONFIG_TR142_MODULE
								if(omci_acs[0] != 0)
									check_dnsIP(dnsfp, "server=/%s/%s", omci_acs, buf, NULL);
#endif
#ifdef CONFIG_SUPPORT_AUTO_DIAG
								if(auto_diag_url[0] != '\0')
									check_dnsIP(dnsfp, "server=/%s/%s", auto_diag_url, buf, NULL);
#endif

							}
#ifdef VOIP_SUPPORT
							if (Entry->applicationtype&X_CT_SRV_VOICE) {
								set_VoIP_proxy_dnscfg(dnsfp,buf,activeVOIP);
							}
#endif
#ifdef _PRMT_X_CT_COM_QOE_
							if (Entry->applicationtype & qoe_applicationtype) {
								if(qoe_url[0] != '\0')
									check_dnsIP(dnsfp, "server=/%s/%s", qoe_url, buf, NULL);
							}
#endif
#if defined(CONFIG_RTK_L34_ENABLE) && defined(DNSQUERY_PORT_BINDING)// DNS port binding
							if (Entry->applicationtype & (X_CT_SRV_INTERNET | X_CT_SRV_SPECIAL_SERVICE_ALL)) {
								if (Entry->itfGroup) {
									int j = 0, phyPortId = 0, ret = 0;
									unsigned char pmap[64] = {0};
									unsigned char re_map_tbl[4] = {0};
									_mib_get(MIB_PORT_REMAPPING, (void *)re_map_tbl);
#ifdef WLAN_SUPPORT
									for (j = 0; j < PMAP_WLAN1_VAP_END; j++)
									{
										if (((Entry->itfGroup >> j) & 1)) {
											if (j <= PMAP_ETH0_SW3) {
												//handle lan port mapping itfGroup bit 0~3
												ret = rtk_rg_switch_phyPortId_get(re_map_tbl[j], &phyPortId);
												if (ret == 0)
													sprintf(pmap, "%s%d,",pmap, phyPortId);
											}
											else {
												//handle wlan0 port mapping itfGroup bit 4~8,
												//handle wlan1 port mapping itfGroup bit 9~13
												sprintf(pmap, "%s%d,", pmap, j);
											}
										}
									}
									pmap[strlen(pmap) - 1] = '\0';
									fprintf(dnsfp, "server=$%s$%s", pmap, buf);
#else
									for (j = 0; j < SW_LAN_PORT_NUM; j++)
									{
										if (((Entry->itfGroup >> j) & 1)) {
											ret = rtk_rg_switch_phyPortId_get(re_map_tbl[j], &phyPortId);
											if (ret == 0)
												sprintf(pmap, "%s%d,", pmap, phyPortId);
										}
									}
									pmap[strlen(pmap) - 1] = '\0';
									fprintf(dnsfp, "server=$%s$%s", pmap, buf);
#endif
								}//itfGroup
							}
#endif

#else
							fprintf(dnsfp, "server=%s", buf);
#endif
						}
						fclose(infdns);
					}
					else
					{
						//when internet wan has no dns server and has port binding, we also need to give 0.0.0.0 dns server to this wan
#if defined(CONFIG_RTK_L34_ENABLE) && defined(DNSQUERY_PORT_BINDING)// DNS port binding
						if (Entry->applicationtype & (X_CT_SRV_INTERNET | X_CT_SRV_SPECIAL_SERVICE_ALL)) {
							if (Entry->itfGroup) {
								int j = 0, phyPortId = 0, ret = 0;
								unsigned char pmap[64] = {0};
								unsigned char re_map_tbl[4] = {0};

								getIPaddrInfo(Entry, str_ipaddr, str_netmask, str_gateway);
								_mib_get(MIB_PORT_REMAPPING, (void *)re_map_tbl);
#ifdef WLAN_SUPPORT
								for (j = 0; j < PMAP_WLAN1_VAP_END; j++)
								{
									if (((Entry->itfGroup >> j) & 1)) {
										if (j <= PMAP_ETH0_SW3) {
												//handle lan port mapping itfGroup bit 0~3
											ret = rtk_rg_switch_phyPortId_get(re_map_tbl[j], &phyPortId);
											if (ret == 0)
												sprintf(pmap, "%s%d,",pmap, phyPortId);
										}
										else {
											//handle wlan0 port mapping itfGroup bit 4~8,
											//handle wlan1 port mapping itfGroup bit 9~13
											sprintf(pmap, "%s%d,", pmap, j);
										}
									}
								}
								pmap[strlen(pmap) - 1] = '\0';
								sprintf(buf, "0.0.0.1@%s", str_ipaddr);
								buf[strlen(buf)] = '\0';
								//printf("\033[1;33;40m @@@@@@@@@@@@@@@@@########### pmap %s, buf %s, str_ipaddr %s\033[m\n", pmap, buf, str_ipaddr);
								if(str_ipaddr[0] != 0){
									//printf("\033[1;33;40m @@@@@@@@@@@@@@@@@########### write dns \033[m\n");
									fprintf(dnsfp, "server=$%s$%s\n", pmap, buf);
								}
#else
								for (j = 0; j < SW_LAN_PORT_NUM; j++)
								{
									if (((Entry->itfGroup >> j) & 1)) {
										ret = rtk_rg_switch_phyPortId_get(re_map_tbl[j], &phyPortId);
										if (ret == 0)
											sprintf(pmap, "%s%d,", pmap, phyPortId);
									}
								}
								pmap[strlen(pmap) - 1] = '\0';
								sprintf(buf, "0.0.0.1@%s", str_ipaddr);
								buf[strlen(buf) ] = '\0';
								//printf("\033[1;33;40m @@@@@@@@@@@@@@@@@########### pmap %s, buf %s, str_ipaddr %s\033[m\n", pmap, buf, str_ipaddr);
								if(str_ipaddr[0] != 0){
									//printf("\033[1;33;40m @@@@@@@@@@@@@@@@@########### write dns \033[m\n");
									fprintf(dnsfp, "server=$%s$%s\n", pmap, buf);
								}
#endif
							}//itfGroup
						}
#endif
#ifdef CONFIG_USER_RTK_WAN_CTYPE
						// If the TR069 interface is not ready but Inernet interface is ready, the DNS query from TR069 will go Internet channle.
						// So we should drop the DNS query from TR069.
						if (Entry->applicationtype&X_CT_SRV_TR069)
						{
							if(acsurl[0] != 0)
								fprintf(dnsfp, "local=/%s/\n", acsurl);
							if(dhcp_acs[0] != 0)
								fprintf(dnsfp, "local=/%s/\n", dhcp_acs);
#ifdef CONFIG_TR142_MODULE
							if(omci_acs[0] != 0)
								fprintf(dnsfp, "local=/%s/\n", omci_acs);
#endif
#ifdef CONFIG_SUPPORT_AUTO_DIAG
							if(auto_diag_url[0] != '\0')
								fprintf(dnsfp, "local=/%s/\n", auto_diag_url);
#endif
						}
#ifdef VOIP_SUPPORT
							if (Entry->applicationtype&X_CT_SRV_VOICE){
							//printf("fixUpDnsServer: DROP DNS query for Voice.\n");
							set_VoIP_proxy_dnscfg(dnsfp,NULL,activeVOIP);
						}
#endif
#ifdef _PRMT_X_CT_COM_QOE_
						if (Entry->applicationtype & qoe_applicationtype) {
							if(qoe_url[0] != '\0')
								fprintf(dnsfp, "local=/%s/\n", qoe_url);
						}
#endif
#endif
#ifdef TIME_ZONE
						// NTP bind this interface.
						// If the NTP interface is not ready but Inernet interface is ready, the DNS query from NTP will go Internet channle.
						// So we should drop the DNS query from NTP.
						if (ntpItf == Entry->ifIndex) {
							fprintf(dnsfp, "local=/%s/\n", ntpURL1);
							fprintf(dnsfp, "local=/%s/\n", ntpURL2);
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
							fprintf(dnsfp, "local=/%s/\n", ntpURL3);
							fprintf(dnsfp, "local=/%s/\n", ntpURL4);
							fprintf(dnsfp, "local=/%s/\n", ntpURL5);
#endif
						}
#endif
					}
				}

				if(dnsnum>0){
					fprintf(dbusdnsfp, "\n");
					dnsnum=0;
				}

				// (2) Merge DNS server for static link or if it is dynamical link with dnsMode=REQUEST_DNS_NONE|| DNS_SET_BY_API
				if ( ((Entry->cmode == CHANNEL_MODE_RT1483) || (Entry->cmode == CHANNEL_MODE_IPOE) || (Entry->cmode == CHANNEL_MODE_PPPOE)) && (Entry->dnsMode != REQUEST_DNS) )
				{
					if (((struct in_addr *)Entry->v4dns1)->s_addr != INADDR_NONE && ((struct in_addr *)Entry->v4dns1)->s_addr != 0)
					{
						strncpy(dns1, inet_ntoa(*((struct in_addr *)Entry->v4dns1)), 16);
						dns1[15] = '\0';
						// Backup to /var/resolv_backup.conf
						if (Entry->dgw == 1){
							fprintf(dns2fp, "%s\n", dns1);
							getIPaddrInfo(Entry, str_ipaddr, str_netmask, str_gateway);
							fprintf(dbusdnsfp, "%d,%d,%s,%s,%s,%d,%s,", Entry->ifIndex, IPVER_IPV4, str_ipaddr, str_netmask, str_gateway, Entry->dnsMode, dns1);
							dnsnum++;
						}
					}
					else
						dns1[0] = '\0';

					if (((struct in_addr *)Entry->v4dns2)->s_addr != INADDR_NONE && ((struct in_addr *)Entry->v4dns2)->s_addr != 0)
					{
						strncpy(dns2, inet_ntoa(*((struct in_addr *)Entry->v4dns2)), 16);
						dns2[15] = '\0';
						// Backup to /var/resolv_backup.conf
						if (Entry->dgw == 1){
							fprintf(dns2fp, "%s\n", dns2);
							fprintf(dbusdnsfp, "%s,", dns2);
							dnsnum++;
						}
					}
					else
						dns2[0] = '\0';

					if(dnsnum>0){
						fprintf(dbusdnsfp, "\n");
						dnsnum=0;
					}

					if ((DHCP_T)Entry->ipDhcp == DHCP_CLIENT || Entry->cmode == CHANNEL_MODE_IPOE)
					{
						ifGetName(Entry->ifIndex, ifname, sizeof(ifname));
						if (getInAddr(ifname, IP_ADDR, (void *)&inAddr) == 1)
							strcpy(ipAddr, (const char *)inet_ntoa(inAddr));
						else
							ipAddr[0] = '\0';
					}
					else
						strcpy(ipAddr, (const char *)inet_ntoa(*((struct in_addr *)Entry->ipAddr)));

#ifdef TIME_ZONE
					// NTP bind this interface.
					if (ntpItf == Entry->ifIndex)
					{
						if (ipAddr[0] != 0)
						{
							if (dns1[0]) {
								check_dnsIP(dnsfp, "server=/%s/%s@%s\n", ntpURL1, dns1, ipAddr);
								check_dnsIP(dnsfp, "server=/%s/%s@%s\n", ntpURL2, dns1, ipAddr);
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
								check_dnsIP(dnsfp, "server=/%s/%s@%s\n", ntpURL3, dns1, ipAddr);
								check_dnsIP(dnsfp, "server=/%s/%s@%s\n", ntpURL4, dns1, ipAddr);
								check_dnsIP(dnsfp, "server=/%s/%s@%s\n", ntpURL5, dns1, ipAddr);
#endif
							}
							if (dns2[0]) {
								check_dnsIP(dnsfp, "server=/%s/%s@%s\n", ntpURL1, dns2, ipAddr);
								check_dnsIP(dnsfp, "server=/%s/%s@%s\n", ntpURL2, dns2, ipAddr);
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
								check_dnsIP(dnsfp, "server=/%s/%s@%s\n", ntpURL3, dns2, ipAddr);
								check_dnsIP(dnsfp, "server=/%s/%s@%s\n", ntpURL4, dns2, ipAddr);
								check_dnsIP(dnsfp, "server=/%s/%s@%s\n", ntpURL5, dns2, ipAddr);
#endif
							}
							if (dns1[0]==0 && dns2[0]==0) {
								fprintf(dnsfp, "local=/%s/\n", ntpURL1);
								fprintf(dnsfp, "local=/%s/\n", ntpURL2);
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
								fprintf(dnsfp, "local=/%s/\n", ntpURL3);
								fprintf(dnsfp, "local=/%s/\n", ntpURL4);
								fprintf(dnsfp, "local=/%s/\n", ntpURL5);
#endif
							}
						}
						else
						{
							// If the NTP interface is not ready but Inernet interface is ready, the DNS query from NTP will go Internet channle.
							// So we should drop the DNS query from NTP.
							fprintf(dnsfp, "local=/%s/\n", ntpURL1);
							fprintf(dnsfp, "local=/%s/\n", ntpURL2);
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
							fprintf(dnsfp, "local=/%s/\n", ntpURL3);
							fprintf(dnsfp, "local=/%s/\n", ntpURL4);
							fprintf(dnsfp, "local=/%s/\n", ntpURL5);
#endif
						}
					}
#endif

					if ((ping_intf == Entry->ifIndex) && strlen(ping_host)) {
						if (ipAddr[0] != 0)
						{
							if (dns1[0])
								check_dnsIP(dnsfp, "server=/%s/%s@%s\n", ping_host, dns1, ipAddr);
							if (dns2[0])
								check_dnsIP(dnsfp, "server=/%s/%s@%s\n", ping_host, dns2, ipAddr);
							//if (dns1[0]==0 && dns2[0]==0)
								//fprintf(dnsfp, "local=/%s/\n", ping_host);
						}
					}

					if ((traceroute_intf == Entry->ifIndex) && strlen(traceroute_host)) {
						if (ipAddr[0] != 0)
						{
							if (dns1[0])
								check_dnsIP(dnsfp, "server=/%s/%s@%s\n", traceroute_host, dns1, ipAddr);
							if (dns2[0])
								check_dnsIP(dnsfp, "server=/%s/%s@%s\n", traceroute_host, dns2, ipAddr);
							//if (dns1[0]==0 && dns2[0]==0)
								//fprintf(dnsfp, "local=/%s/\n", traceroute_host);
						}
					}

#ifdef CONFIG_USER_BEHAVIOR_ANALYSIS
					if ((np_dns_intf == Entry->ifIndex) && strlen(NPEntry->diag_name) && np_dns[0] != '\0') {
						check_dnsIP(dnsfp, "server=/%s/%s@%s\n", NPEntry->diag_name, np_dns, ipAddr);
					}
#endif

#ifdef CONFIG_USER_RTK_WAN_CTYPE
					if ((Entry->applicationtype&X_CT_SRV_INTERNET) && (ipAddr[0] != 0))
					{
#if defined(CONFIG_RTK_L34_ENABLE) && defined(DNSQUERY_PORT_BINDING)
						if(Entry->itfGroup){
							int lan_phy,j;
							int phyPortId, ret;
							unsigned char pmap[64]={0};
							unsigned char re_map_tbl[4];
							_mib_get(MIB_PORT_REMAPPING, (void *)re_map_tbl);
												
#ifdef WLAN_SUPPORT
							for(j=0;j<PMAP_WLAN1_VAP_END;j++)
							{
								if(((Entry->itfGroup >> j) & 1)){
									if(j<=PMAP_ETH0_SW3){
										//handle lan port mapping itfGroup bit 0~3
										ret = rtk_rg_switch_phyPortId_get(re_map_tbl[j], &phyPortId);
										if(ret==0)
											sprintf(pmap, "%s%d,",pmap, phyPortId);
									}else{
										//handle wlan0 port mapping itfGroup bit 4~8,	   
										//handle wlan1 port mapping itfGroup bit 9~13	   
										sprintf(pmap, "%s%d,",pmap,j);
									}
								}
							}
							pmap[strlen(pmap) - 1] = '\0';
							if (dns1[0]){
								sprintf(buf, "%s@%s\n", dns1, ipAddr);
								fprintf(dnsfp, "server=$%s$%s",pmap,buf);
							}
							if (dns2[0]) {
								sprintf(buf, "%s@%s\n", dns2, ipAddr);
								fprintf(dnsfp, "server=$%s$%s",pmap,buf);
							}
#else
							//AUG_PRT("%s-%d %d:%d:%d:%d\n",__func__,__LINE__,re_map_tbl[0],re_map_tbl[1],re_map_tbl[2],re_map_tbl[3]);
							for(j=0;j<SW_LAN_PORT_NUM;j++)
							{
								if(((Entry->itfGroup >> j) & 1)){
									//lan_phy = RG_get_lan_phyPortId(j);
									ret = rtk_rg_switch_phyPortId_get(re_map_tbl[j], &phyPortId);
						//AUG_PRT("%s-%d server=$%d$%s\n",__func__,__LINE__, phyPortId, buf);
									if(ret==0)
										sprintf(pmap, "%s%d,",pmap, phyPortId);
						//AUG_PRT("%s-%d server=$%d$%s\n",__func__,__LINE__, phyPortId, buf);
								}
							}
							pmap[strlen(pmap) - 1] = '\0';
							if (dns1[0]){
								sprintf(buf, "%s@%s\n", dns1, ipAddr);
								fprintf(dnsfp, "server=$%s$%s",pmap,buf);
							}
							if (dns2[0]) {
								sprintf(buf, "%s@%s\n", dns2, ipAddr);
								fprintf(dnsfp, "server=$%s$%s",pmap,buf);
							}
													
#endif									
						}//itfGroup
#endif
						// server=/mason.test2/192.168.88.21@192.168.99.100
						if (dns1[0])
							fprintf(dnsfp, "server=%s@%s\n", dns1, ipAddr);
						if (dns2[0])
							fprintf(dnsfp, "server=%s@%s\n", dns2, ipAddr);
					}
					if (Entry->applicationtype&X_CT_SRV_TR069)
					{
						// server=/mason.test2/192.168.88.21@192.168.99.100
						if (ipAddr[0] != 0)
						{
							if(acsurl[0] != 0)
							{
								if (dns1[0])
									check_dnsIP(dnsfp, "server=/%s/%s@%s\n", acsurl, dns1, ipAddr);
								if (dns2[0])
									check_dnsIP(dnsfp, "server=/%s/%s@%s\n", acsurl, dns2, ipAddr);
								if (dns1[0]==0 && dns2[0]==0)
									fprintf(dnsfp, "local=/%s/\n", acsurl);
							}

							if(dhcp_acs[0] != 0)
							{
								if (dns1[0])
									check_dnsIP(dnsfp, "server=/%s/%s@%s\n", acsurl, dns1, ipAddr);
								if (dns2[0])
									check_dnsIP(dnsfp, "server=/%s/%s@%s\n", acsurl, dns2, ipAddr);
								if (dns1[0]==0 && dns2[0]==0)
									fprintf(dnsfp, "local=/%s/\n", acsurl);
							}
#ifdef CONFIG_TR142_MODULE
							if(omci_acs[0] != 0)
							{
								if (dns1[0])
									check_dnsIP(dnsfp, "server=/%s/%s@%s\n", acsurl, dns1, ipAddr);
								if (dns2[0])
									check_dnsIP(dnsfp, "server=/%s/%s@%s\n", acsurl, dns2, ipAddr);
								if (dns1[0]==0 && dns2[0]==0)
									fprintf(dnsfp, "local=/%s/\n", acsurl);
							}
#endif
#ifdef CONFIG_SUPPORT_AUTO_DIAG
							if(auto_diag_url[0] != '\0')
							{
								if (dns1[0])
									check_dnsIP(dnsfp, "server=/%s/%s@%s\n", auto_diag_url, dns1, ipAddr);
								if (dns2[0])
									check_dnsIP(dnsfp, "server=/%s/%s@%s\n", auto_diag_url, dns2, ipAddr);
								if (dns1[0]==0 && dns2[0]==0)
									fprintf(dnsfp, "local=/%s/\n", auto_diag_url);
							}
#endif
						}
						else
						{
							// If the TR069 interface is not ready but Inernet interface is ready, the DNS query from TR069 will go Internet channle.
							// So we should drop the DNS query from TR069.
							if (activeTR069 == HAVE_NONE)
							{
								fprintf(dnsfp, "local=/%s/\n", acsurl);
								fprintf(dnsfp, "local=/%s/\n", dhcp_acs);
#ifdef CONFIG_TR142_MODULE
								fprintf(dnsfp, "local=/%s/\n", omci_acs);
#endif
#ifdef CONFIG_SUPPORT_AUTO_DIAG
								if(auto_diag_url[0] != '\0')
									fprintf(dnsfp, "local=/%s/\n", auto_diag_url);
#endif
							}
						}
					}
#ifdef VOIP_SUPPORT
					if (Entry->applicationtype&X_CT_SRV_VOICE)
					{
						// server=/mason.test2/192.168.88.21@192.168.99.100
						if (ipAddr[0] != 0)
						{

							if (dns1[0]){
								memset(vStr,0,sizeof(vStr));
								sprintf(vStr,"%s@%s\n",dns1,ipAddr);
								set_VoIP_proxy_dnscfg(dnsfp,vStr,activeVOIP);
							}
							if (dns2[0]){
								memset(vStr,0,sizeof(vStr));
								sprintf(vStr,"%s@%s\n",dns2,ipAddr);
								set_VoIP_proxy_dnscfg(dnsfp,vStr,activeVOIP);

							}
							if (dns1[0]==0 && dns2[0]==0)
								set_VoIP_proxy_dnscfg(dnsfp,NULL,activeVOIP);
						}
						else
						{
							// If the VOIP interface is not ready but Inernet interface is ready, the DNS query from VOIP will go Internet channle.
							// So we should drop the DNS query from VOIP.
							set_VoIP_proxy_dnscfg(dnsfp,NULL,activeVOIP);
						}
					}
#endif //VOIP_SUPPORT
#ifdef _PRMT_X_CT_COM_QOE_
					if (Entry->applicationtype & qoe_applicationtype) {
						if (ipAddr[0] != 0 && qoe_url[0] != '\0')
						{
							if (dns1[0])
								check_dnsIP(dnsfp, "server=/%s/%s@%s\n", qoe_url, dns1, ipAddr);
							if (dns2[0])
								check_dnsIP(dnsfp, "server=/%s/%s@%s\n", qoe_url, dns2, ipAddr);
							if (dns1[0] == 0 && dns2[0] == 0)
								fprintf(dnsfp, "local=/%s/\n", qoe_url);
						}
						else
						{
							fprintf(dnsfp, "local=/%s/\n", qoe_url);
						}
					}
#endif
#if defined(CONFIG_RTK_L34_ENABLE) && defined(DNSQUERY_PORT_BINDING)// DNS port binding
					if (Entry->applicationtype & (X_CT_SRV_INTERNET | X_CT_SRV_SPECIAL_SERVICE_ALL)) {
						if (ipAddr[0] != 0 && Entry->itfGroup) {
							int j = 0, phyPortId = 0, ret = 0;
							unsigned char pmap[64] = {0};
							unsigned char re_map_tbl[4] = {0};
							_mib_get(MIB_PORT_REMAPPING, (void *)re_map_tbl);
#ifdef WLAN_SUPPORT
							for (j = 0; j < PMAP_WLAN1_VAP_END; j++)
							{
								if (((Entry->itfGroup >> j) & 1)) {
									if (j <= PMAP_ETH0_SW3) {
										//handle lan port mapping itfGroup bit 0~3
										ret = rtk_rg_switch_phyPortId_get(re_map_tbl[j], &phyPortId);
										if (ret == 0)
											sprintf(pmap, "%s%d,",pmap, phyPortId);
									}
									else {
										//handle wlan0 port mapping itfGroup bit 4~8,
										//handle wlan1 port mapping itfGroup bit 9~13
										sprintf(pmap, "%s%d,", pmap, j);
									}
								}
							}
							pmap[strlen(pmap) - 1] = '\0';
							if (dns1[0]) {
								sprintf(buf, "%s@%s\n", dns1, ipAddr);
								fprintf(dnsfp, "server=$%s$%s", pmap, buf);
							}
							if (dns2[0]) {
								sprintf(buf, "%s@%s\n", dns2, ipAddr);
								fprintf(dnsfp, "server=$%s$%s",pmap, buf);
							}
#else
							for (j = 0; j < SW_LAN_PORT_NUM; j++)
							{
								if (((Entry->itfGroup >> j) & 1)) {
									ret = rtk_rg_switch_phyPortId_get(re_map_tbl[j], &phyPortId);
									if (ret == 0)
										sprintf(pmap, "%s%d,", pmap, phyPortId);
								}
							}
							pmap[strlen(pmap) - 1] = '\0';
							if (dns1[0]) {
								sprintf(buf, "%s@%s\n", dns1, ipAddr);
								fprintf(dnsfp, "server=$%s$%s", pmap, buf);
							}
							if (dns2[0]) {
								sprintf(buf, "%s@%s\n", dns2, ipAddr);
								fprintf(dnsfp, "server=$%s$%s", pmap, buf);
							}
#endif
						}//itfGroup
					}
#endif

#else
					// server=192.168.77.20@192.168.2.1
					if (dns1[0])
						fprintf(dnsfp, "server=%s@%s\n", dns1, ipAddr);
					if (dns2[0])
						fprintf(dnsfp, "server=%s@%s\n", dns2, ipAddr);
#endif

				}
#ifdef CONFIG_IPV6		
			}
#endif

#ifdef CONFIG_IPV6
			if ( Entry->IpProtocol & IPVER_IPV6 ) 
			{
				//(3) Handle IPv6 DNS server
				// Only DHCPv6 is ran or static IPv6 is set.
				if ( (Entry->Ipv6Dhcp == 1) || ((Entry->Ipv6DhcpRequest & 0x2) == 0x2)
					|| Entry->AddrMode == IPV6_WAN_STATIC)
				{
					FILE* infdns;
					struct ipv6_ifaddr addr = {0};
					char file[64] = {0};
					char str_addr[128] = {0};
					char str_addr1[128] = {0};
					char str_addr2[128] = {0};
					char line[128] = {0};

					if(Entry->dnsv6Mode==REQUEST_DNS_NONE || Entry->dnsv6Mode==DNS_SET_BY_API || Entry->AddrMode == IPV6_WAN_STATIC){//dnsv6 server setting from user
						inet_ntop(AF_INET6, (struct in6_addr *)Entry->Ipv6Dns1, str_addr1, 64);
						inet_ntop(AF_INET6, (struct in6_addr *)Entry->Ipv6Dns2, str_addr2, 64);
						snprintf(file, 64, "%s.%s_static", (char *)DNS6_RESOLV, wanif);
						infdns=fopen(file,"w");
						if(infdns){
							if(Entry->Ipv6Dns1[0])
								fprintf(infdns, "%s\n", str_addr1);
							if(Entry->Ipv6Dns2[0])
								fprintf(infdns, "%s\n", str_addr2);
						}
						fclose(infdns);
					}
					else{ //dnsv6 server setting from dhcpv6 server
						snprintf(file, 64, "%s.%s", (char *)DNS6_RESOLV, wanif);
					}

					infdns=fopen(file,"r");
					if(infdns)
					{
						while(fgets(line,sizeof(line),infdns) != NULL)
						{
							char *new_line = NULL;

							new_line = strrchr(line, '\n');
							if(new_line)
								*new_line = '\0';

							if((strlen(line)==0))
								continue;

							// Backup to /var/resolv_backup.conf
							if (Entry->dgw == 1)
							{
								fprintf(dns2fp, "%s\n", line);
								if(dnsnum==0){
									getIPv6addrInfo(Entry, str_ipaddr, str_netmask, str_gateway);
									fprintf(dbusdnsfp, "%d,%d,%s,%s,%s,%d,%s,", Entry->ifIndex, IPVER_IPV6, str_ipaddr, str_netmask, str_gateway, Entry->dnsv6Mode, line);
								}
								else{
									fprintf(dbusdnsfp, "%s,", line);
								}
								dnsnum++;
							}

							// Only get first global IP address,
							// may have problem if this interface has multiple IP addresses.
							if(getifip6(wanif, IPV6_ADDR_UNICAST, &addr, 1) > 0)
							{
								inet_ntop(AF_INET6, &addr.addr, str_addr, 64);
								sprintf(buf, "%s@%s", line, str_addr);
							}
							else
								strcpy(buf, line);

#ifdef TIME_ZONE
							// NTP bind this interface.
							if (ntpItf == Entry->ifIndex)
							{
								check_dnsIP(dnsfp, "server=/%s/%s\n", ntpURL1, buf, NULL);
								check_dnsIP(dnsfp, "server=/%s/%s\n", ntpURL2, buf, NULL);
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
								check_dnsIP(dnsfp, "server=/%s/%s\n", ntpURL3, buf, NULL);
								check_dnsIP(dnsfp, "server=/%s/%s\n", ntpURL4, buf, NULL);
								check_dnsIP(dnsfp, "server=/%s/%s\n", ntpURL5, buf, NULL);
#endif
							}
#endif

							if ((ping_intf == Entry->ifIndex) && strlen(ping_host)) {
								check_dnsIP(dnsfp, "server=/%s/%s\n", ping_host, buf, NULL);
							}

							if ((traceroute_intf == Entry->ifIndex) && strlen(traceroute_host)) {
								check_dnsIP(dnsfp, "server=/%s/%s\n", traceroute_host, buf, NULL);
							}

#ifdef CONFIG_USER_BEHAVIOR_ANALYSIS
							char np_buf[256] = {0};
							char *np_ptr = NULL;
							np_ptr = strchr(buf, '@');
							sprintf(np_buf, "%s%s", np_dns, np_ptr);
							if ((np_dns_intf == Entry->ifIndex) && strlen(NPEntry->diag_name) && np_buf[0] != '\0') {
								check_dnsIP(dnsfp, "server=/%s/%s\n", NPEntry->diag_name, np_buf, NULL);
							}
#endif

#ifdef CONFIG_USER_RTK_WAN_CTYPE
							if (Entry->applicationtype&X_CT_SRV_INTERNET)
								fprintf(dnsfp, "server=%s\n", buf);
							if ((Entry->applicationtype&X_CT_SRV_TR069) && (acsurl[0] != 0))
								check_dnsIP(dnsfp, "server=/%s/%s\n", acsurl, buf, NULL);
#ifdef VOIP_SUPPORT
							if (Entry->applicationtype&X_CT_SRV_VOICE) {
								set_VoIP_proxy_dnscfg(dnsfp,buf,activeVOIP);
							}
#endif
#if defined(CONFIG_RTK_L34_ENABLE) && defined(DNSQUERY_PORT_BINDING)// DNS port binding
							if (Entry->applicationtype & (X_CT_SRV_INTERNET | X_CT_SRV_SPECIAL_SERVICE_ALL)) {
//printf("\n\n------------->Entry->itfGroup=0x%x Entry->vid=%d\n\n",Entry->itfGroup, Entry->vid);
								if (Entry->itfGroup) {
									int j = 0, phyPortId = 0, ret = 0;
									unsigned char pmap[64] = {0};
									unsigned char re_map_tbl[4] = {0};
									_mib_get(MIB_PORT_REMAPPING, (void *)re_map_tbl);
#ifdef WLAN_SUPPORT
									for (j = 0; j < PMAP_WLAN1_VAP_END; j++)
									{
										if (((Entry->itfGroup >> j) & 1)) {
											if (j <= PMAP_ETH0_SW3) {
												//handle lan port mapping itfGroup bit 0~3
												ret = rtk_rg_switch_phyPortId_get(re_map_tbl[j], &phyPortId);
												if (ret == 0)
													sprintf(pmap, "%s%d,",pmap, phyPortId);
											}
											else {
												//handle wlan0 port mapping itfGroup bit 4~8,
												//handle wlan1 port mapping itfGroup bit 9~13
												sprintf(pmap, "%s%d,", pmap, j);
											}
										}
									}
									pmap[strlen(pmap) - 1] = '\0';
									fprintf(dnsfp, "server=$%s$%s\n", pmap, buf);
#else
									for (j = 0; j < SW_LAN_PORT_NUM; j++)
									{
										if (((Entry->itfGroup >> j) & 1)) {
											ret = rtk_rg_switch_phyPortId_get(re_map_tbl[j], &phyPortId);
											if (ret == 0)
												sprintf(pmap, "%s%d,", pmap, phyPortId);
										}
									}
									pmap[strlen(pmap) - 1] = '\0';
									fprintf(dnsfp, "server=$%s$%s\n", pmap, buf);
#endif
								}//itfGroup
							}
#endif

#else
							fprintf(dnsfp, "server=%s\n", buf);
#endif
						}
						fclose(infdns);
					}
					if(dnsnum>0){
						fprintf(dbusdnsfp, "\n");
						dnsnum=0;
					}
				}
			}
#endif
		}
#ifdef CONFIG_SUPPORT_AUTO_DIAG 
		entryNum = _mib_chain_total(MIB_SIMU_ATM_VC_TBL);
		for (i = 0; i < entryNum; i++)
		{
			if(!(Entry = (MIB_CE_ATM_VC_Tp)_mib_chain_get(MIB_SIMU_ATM_VC_TBL,i)))
			{
				continue;
			}
#ifdef DUAL_STACK_LITE
			if(1==Entry->dslite_enable)
			{
				FILE* fp;
				int num;
				char addr[64]={0}, dns[64]={0}, aftr[64]={0}, buf[128];
				char strName[32];
				char strVal[64];
				struct ipv6_ifaddr ip6_addr;
				char filename[64];
				unsigned int ret;

				num=getifip6("ppp7", IPV6_ADDR_UNICAST, &ip6_addr, 1);
				if(!num)
				{
					//printf("[%s %d][SIMU]No ip6_addr on ppp7\n", __func__, __LINE__);
					break;
				}
				else
				{
					inet_ntop(AF_INET6, &ip6_addr.addr, addr, 64);
				}

				snprintf(filename, 64, "/var/%sppp7.leases", DHCPCV6STR);
				ret = getOptionFromleases(filename, NULL, dns, aftr);
				if(1==Entry->dslite_aftr_mode)
				{
					memcpy(aftr, Entry->dslite_aftr_hostname, 64);
					ret |= 4;
				}
				if(6==(ret&6))
				{
                    if(inet_pton(AF_INET6, aftr, &ip6_addr)!=1)
                    {
                        //if aftr is IPv6 Address, do not add to dnsmasq.conf
					    printf("[%s %d]server=/%s/%s@%s\n", __func__, __LINE__, aftr, dns, addr);
					    fprintf(dnsfp, "server=/%s/%s@%s\n", aftr, dns, addr);
                    }
				}
				else
				{
					printf("[%s %d]Add DNS failed, ret=%d.\n", __func__, __LINE__, ret);
				}
			}
#endif
		}
#endif
#ifdef CTC_DNS_TUNNEL
		write_dns_tunnel_conf(dnsfp);
#endif

#ifdef CONFIG_SUPPORT_PON_LINK_DOWN_PROMPT
		if((getPONState() == 0) || (_check_user_is_registered() == 0))
#else
		if(_check_user_is_registered() == 0)
#endif			
		{
			//If LOID is not registered
			unsigned char lan_ip[IP_ADDR_LEN] = {0};
			char lan_ip_str[INET_ADDRSTRLEN] = {0};
			char lan_ip6_str[MAX_V6_IP_LEN] = {0};


			_mib_get(MIB_ADSL_LAN_IP, lan_ip);
			if( NULL != inet_ntop(AF_INET, lan_ip, lan_ip_str, INET_ADDRSTRLEN))
				fprintf(dnsfp, "address=/#/%s\n", lan_ip_str);
			_mib_get(MIB_IPV6_LAN_IP_ADDR, lan_ip6_str);
			fprintf(dnsfp, "address=/#/%s\n", lan_ip6_str);
		}
		fclose(dnsfp);
		fclose(dns2fp);
		fclose(dbusdnsfp);
		dnsfp = dns2fp = dbusdnsfp = NULL;
		callDbusGetInfoCallbackFunc(DBUS_DNS);
	}
	if(dnsfp != NULL)
		fclose(dnsfp);
	if(dns2fp != NULL)
		fclose(dns2fp);
	if(dbusdnsfp != NULL)
		fclose(dbusdnsfp);

	return 1;
}

#ifdef VOIP_SUPPORT
int set_VoIP_proxy_dnscfg(FILE *dnsfp,char *dns_str, char activeVOIP)
{
	unsigned int totalEntry = 0;
	voipCfgParam_t * pCfg;
	voipCfgPortParam_t *VoIPport;
	int i,val;
	int x;

	//totalEntry = _mib_chain_total(MIB_VOIP_CFG_TBL);

	pCfg = (voipCfgParam_t *)_mib_chain_get(MIB_VOIP_CFG_TBL, 0);

	//printf("voip_flash get ok\n");

	for ( i=0; i<VOIP_PORTS; i++){
		VoIPport = &pCfg->ports[i];
		//printf("[%d] \n",i);
		for (x=0; x<MAX_PROXY; x++){
			/* sip proxy */
			if(VoIPport->proxies[x].enable & PROXY_ENABLED){
				//printf("server is %s\n",VoIPport->proxies[x].addr);
				if(strlen(VoIPport->proxies[x].addr)!=0){
					//write to file
					if(dns_str!=NULL)
						fprintf(dnsfp, "server=/%s/%s\n", VoIPport->proxies[x].addr, dns_str);
					else if (activeVOIP == HAVE_NONE)
						fprintf(dnsfp, "local=/%s/\n", VoIPport->proxies[x].addr);
				}

				/*sip outbound proxy */
				if(VoIPport->proxies[x].outbound_enable ==1){
					//printf("outbound server is %s\n",VoIPport->proxies[x].outbound_addr);
					if(strlen(VoIPport->proxies[x].outbound_addr)!=0){
					//write to file
						if(dns_str!=NULL)
							fprintf(dnsfp, "server=/%s/%s\n", VoIPport->proxies[x].outbound_addr, dns_str);
						else if (activeVOIP == HAVE_NONE)
							fprintf(dnsfp, "local=/%s/\n", VoIPport->proxies[x].outbound_addr);
					}
				}

			}

		}
   }
#ifdef CONFIG_USER_RTK_H248   
    /* H.248 */
	if(strlen(pCfg->mgc_ip)!=0){
		//write to file
		if(dns_str!=NULL)
			fprintf(dnsfp, "server=/%s/%s\n", pCfg->mgc_ip, dns_str);
    }
    if(strlen(pCfg->bak_mgc_ip)!=0){
		//write to file
		if(dns_str!=NULL)
			fprintf(dnsfp, "server=/%s/%s\n", pCfg->bak_mgc_ip, dns_str);
    }
#endif
}
#endif //VOIP_SUPPORT

void cfg_set_dns_config(struct mymsgbuf *qbuf)
{
	fixUpDnsServer(qbuf->msg.mtext);	// Mason Yu. config /var/dnsmasq.conf
	qbuf->request = MSG_SUCC;
}

#if defined(CONFIG_IPV6) && defined(DUAL_STACK_LITE) &&defined(CONFIG_USER_DHCPV6_ISC_DHCP411)
static MIB_CE_ATM_VC_T * getATM_VC_ENTRY_byName(char *pIfname, int *entry_index)
{
	unsigned int entryNum, i;
	char ifname[IFNAMSIZ];
	MIB_CE_ATM_VC_T *pEntry=NULL;

	entryNum = _mib_chain_total(MIB_ATM_VC_TBL);
	for (i=0; i<entryNum; i++) {
		pEntry = (typeof(pEntry))_mib_chain_get(MIB_ATM_VC_TBL, i);
		if(!pEntry){
  			printf("Get chain record error!\n");
			return (typeof(pEntry))-1;
		}

		if (pEntry->enable == 0)
			continue;

		ifGetName(pEntry->ifIndex,ifname,sizeof(ifname));

		if(!strcmp(ifname,pIfname)){
			break;
		}
	}

	if(i>= entryNum){
		//printf("not find this interface!\n");
		return NULL;
	}

	*entry_index=i;
	printf("Found %s in ATM_VC_TBL index %d\n", ifname, *entry_index);
	return pEntry;
}

#ifdef CONFIG_SUPPORT_AUTO_DIAG
static MIB_CE_ATM_VC_T * get_SIMU_DSLiteENTRY(int *entry_index)
{
	unsigned int entryNum, i;
	MIB_CE_ATM_VC_T *pEntry=NULL;

	entryNum = _mib_chain_total(MIB_SIMU_ATM_VC_TBL);
	for (i=0; i<entryNum; i++) 
	{
		pEntry = (MIB_CE_ATM_VC_T *)_mib_chain_get(MIB_SIMU_ATM_VC_TBL, i);
		if(!pEntry){
  			printf("Get chain record error!\n");
			continue;
		}

		if (pEntry->dslite_enable == 1)
		{
			*entry_index=i;
			return pEntry;
		}
	}

	return NULL;
}
#endif

int cfg_got_aftr(struct mymsgbuf *qbuf)
{
	char *saveptr = NULL;
	char *ifname=NULL,*aftr=NULL;
	int ret=-1;
	unsigned int pid;

	if(!qbuf || !qbuf->msg.mtext){
		printf("Error! data is NULL! %s\n",__func__);
		return -1;
	}

	//parse the ifname,aftr
	ifname=strtok_r(qbuf->msg.mtext,",",&saveptr);
#ifdef CONFIG_SUPPORT_AUTO_DIAG
	if((ifname)&&(!strncmp(ifname, "ppp7", 4)))
	{
		int entry_index=0;
		aftr=strtok_r(NULL,",",&saveptr);
		if(aftr){
			MIB_CE_ATM_VC_Tp pEntry;
			//Got ATM_VC_TBL index by ifname
			printf("[SIMU]Handle Aftr, ifname=[%s],aftr=[%s]\n",ifname,aftr);
			pEntry= get_SIMU_DSLiteENTRY(&entry_index);
			if(!pEntry){
				printf("[SIMU]Find SIMU_ATM_VC_TBL interface %s Fail!\n",ifname);
				goto DATAERROR;
			}

			//strcpy(pEntry->dslite_aftr_hostname,aftr);
			//printf("[SIMU]pEntry->dslite_aftr_hostname=%s, entry_index=%d\n",pEntry->dslite_aftr_hostname, entry_index);
			//_mib_chain_update(MIB_SIMU_ATM_VC_TBL, pEntry, entry_index);

			pid = read_pid("/var/run/autoSimu.pid");
			if (pid > 0){
				printf("[SIMU]Send signal USR2 to autoSimu pid %d\n",pid);
				kill(pid, SIGUSR2);
			}
		}
		else
			goto DATAERROR;
	}
	else
#endif
	if(ifname){
		int entry_index=0;
		aftr=strtok_r(NULL,",",&saveptr);
		if(aftr){
			MIB_CE_ATM_VC_Tp pEntry;
			//Got ATM_VC_TBL index by ifname
			printf("ifname=[%s],aftr=[%s]\n",ifname,aftr);
			pEntry= getATM_VC_ENTRY_byName(ifname, &entry_index);
			if(!pEntry){
				printf("Find ATM_VC_TBL interface %s Fail!\n",ifname);
				goto DATAERROR;
			}

			//printf("entry_index in mib=%d, pEntry->rg_wan_idx=%d\n",entry_index, pEntry->rg_wan_idx);
			//query_aftr(aftr,pEntry->dslite_aftr_addr);
			strcpy(pEntry->dslite_aftr_hostname,aftr);
			_mib_chain_update(MIB_ATM_VC_TBL,(unsigned char*)pEntry,entry_index);

			pid = read_pid("/var/run/systemd.pid");
			if ( pid > 0){
				printf("Send signal USR2 to systemd pid %d\n",pid);
				kill(pid, SIGUSR2);
			}
		}
		else
			goto DATAERROR;
	}
	else
		goto DATAERROR;

	qbuf->request = MSG_SUCC;
	return 0;

DATAERROR:
	printf("Handle AFTR information Error! %s\n",__func__);
	return -1;
}

#endif

#if defined(CONFIG_IPV6) && defined(DUAL_STACK_LITE)
// for static DS-Lite AFTR
void cfg_dslite_aftr_static(struct mymsgbuf *qbuf)
{
	qbuf->request = MSG_FAIL;
	if(!qbuf || !qbuf->msg.mtext){
		printf("Error! data is NULL! %s\n",__func__);
		return;
	}
	
	#if 0
	// aftr_info: "ifname,aftr_hostname"
	strncpy(aftr_info, qbuf->msg.mtext, 64);
	aftr_info[63] = '\0';
	do_dslite(&aftr_info[0]);
	#endif
	
	qbuf->request = MSG_SUCC;
}
#endif
void cfg_set_dbus_register_pid(struct mymsgbuf *qbuf)
{		
	registerDbusGetInfoCallbackFunc(DBUS_DNS, qbuf->msg.arg1, NULL);
	qbuf->request = MSG_SUCC;
}

