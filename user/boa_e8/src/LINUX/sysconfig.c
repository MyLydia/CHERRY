/*
 * sysconfig.c --- main file for configuration server API
 * --- By Kaohj
 */

#include "sysconfig.h"
#include "msgq.h"
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <sys/shm.h>
#include <sys/file.h>
#include <rtk/utility.h>
#ifdef EMBED
#include <config/autoconf.h>
#else
#include "../../../../config/autoconf.h"
#endif
#ifdef CONFIG_REMOTE_CONFIGD
#ifdef CONFIG_SPC
#include <linux/if_ether.h>
#endif
#endif

#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>

#ifdef WLAN_SUPPORT
extern int wlan_idx;
#endif

#ifdef CONFIG_USER_XMLCONFIG
const char LASTGOOD_FILE[] = "/var/config/lastgood.xml";
const char LASTGOOD_HS_FILE[] = "/var/config/lastgood_hs.xml";
#endif	/*CONFIG_USER_XMLCONFIG*/

#define CONF_SERVER_PIDFILE	"/var/run/configd.pid"
// Mason Yu. deadlock
#include <errno.h>
int lock_shm_by_flock()
{
	int lockfd;

	if ((lockfd = open(CONF_SERVER_PIDFILE, O_RDWR)) == -1) {
		perror("open shm lockfile");
		return lockfd;
	}
	while (flock(lockfd, LOCK_EX) == -1 && errno==EINTR) {
		printf("configd write lock failed by flock. errno=%d\n", errno);
	}
	return lockfd;
}

int unlock_shm_by_flock(int lockfd)
{
	while (flock(lockfd, LOCK_UN) == -1 && errno==EINTR) {
		printf("configd write unlock failed by flock. errno=%d\n", errno);
	}
	close(lockfd);
	return 0;
}

#ifdef CONFIG_USER_XMLCONFIG
int xml_mib_load(CONFIG_DATA_T type, CONFIG_MIB_T flag)
{
	int ret=1;

	printf("%s():...\n", __FUNCTION__);
	if (va_cmd(shell_name, 3, 1, "/etc/scripts/config_xmlconfig.sh", "-l", LASTGOOD_FILE) != MSG_SUCC) {
		printf("[xmlconfig] mib reload failed\n");
		ret = 0;
	}else
		printf("[xmlconfig] mib reload success\n");

	return ret;
}

int xml_mib_flash_to_default(CONFIG_DATA_T type)
{
	int ret=1;

	printf("%s():...\n", __FUNCTION__);
	if (va_cmd(shell_name, 2, 1, "/etc/scripts/config_xmlconfig.sh", "-d") != MSG_SUCC) {
		printf("[xmlconfig] mib reset_flash_to_default failed\n");
		ret = 0;
	}else
		printf("[xmlconfig] mib reset_flash_to_default success\n");

	return ret;
}
#endif	/*CONFIG_USER_XMLCONFIG*/

#ifdef WLAN_SUPPORT
/*
 *	Reorder mib id for wlan mib in case of multiple wlan interfaces.
 *	Return value: reordered wlan mib id based on wlan_idx, -1 on error.
 */
static int wlan_mib_id_reorder(int id)
{
	int mib_id=id;
	
	if (id > DUAL_WLAN_START_ID && id < DUAL_WLAN_END_ID) {
		mib_id = -1;
		if (isValid_wlan_idx(wlan_idx))
			mib_id = id + wlan_idx;
	}
	
	return mib_id;
}

static int wlan_mibchain_id_reorder(int id)
{
	int mib_id=id;
	
	if (id > DUAL_WLAN_CHAIN_START_ID && id < DUAL_WLAN_CHAIN_END_ID) {
		mib_id = -1;
		if (isValid_wlan_idx(wlan_idx))
			mib_id = id + wlan_idx;
	}
	
	return mib_id;
}
#endif

#include <sys/syscall.h>
static void sendcmd(struct mymsgbuf* qbuf)
{
	key_t key;
	int qid_snd, qid_rcv, cpid, ctgid, spid;

#ifdef EMBED
	/* Create unique key via call to ftok() */
	key = ftok("/bin/init", 's');
	if ((qid_snd = open_queue(key, MQ_GET)) == -1) {
		//perror("open_queue");
		return;
	}

	/* Create unique key via call to ftok() */
	key = ftok("/bin/init", 'r');
	if ((qid_rcv = open_queue(key, MQ_GET)) == -1) {
		//perror("open_queue");
		return;
	}

	// get client pid
	// Consider multi-thread environment, we use tid (thread id) as message id.
	cpid = (int)syscall(SYS_gettid);
	ctgid = (int)getpid();

	// get server pid
	// Mason Yu. Not use fopen()
	spid = MSG_CONFIGD_PID;

	send_message(qid_snd, spid, cpid, ctgid, &qbuf->msg);
	read_message(qid_rcv, qbuf, cpid);
#else
	memset(qbuf, 0, sizeof(struct mymsgbuf));
	qbuf->request = MSG_SUCC;
#endif
}

/*
 *	Get data from shared memory(shared memory --> ptr).
 *	-1 : error
 	 0 : successful
 */
static int get_shm_data(const char *ptr, int len)
{
	int shmid;
	char *shm_start;

	if (len > SHM_SIZE)
		return -1;
	if ((shmid = shmget((key_t)1234, SHM_SIZE, 0)) == -1)
		return -1;
	// Attach shared memory segment.
	if ((shm_start = (char *)shmat( shmid , NULL , 0 ))==(char *)-1)
		return -1;
	memcpy((void *)ptr, shm_start, len);
	// Detach shared memory segment.
	shmdt(shm_start);
	return 0;
}

/*
 *	Put data to shared memory(ptr --> shared memory).
 *	-1 : error
 *	 0 : successful
 */
static int put_shm_data(const char *ptr, int len)
{
	int shmid;
	char *shm_start;

	if ((shmid = shmget((key_t)1234, SHM_SIZE, 0)) == -1)
		return -1;
	// Attach shared memory segment.
	if ((shm_start = (char *)shmat( shmid , NULL , 0 ))==(char *)-1)
		return -1;
	if (len > SHM_SIZE)
		return -1;
	memcpy((void *)shm_start, ptr, len);
	// Detach shared memory segment.
	shmdt(shm_start);
	return 0;
}

#ifdef CONFIG_USER_DBUS_CTC_IGD
#include <sys/sysinfo.h>

int recv_ctc_igd(int qid, struct ctc_igd_msgbuf * qbuf, long type, int pid)
{
	int ret;
	struct sysinfo systeminfo;
	long time_start;
	sysinfo(&systeminfo);
	time_start=systeminfo.uptime;

	/* Read a message from the queue */
	//printf("Reading a message ...\n");
	qbuf->mtype = type;

read_retry:
	ret=msgrcv(qid, (struct ctc_igd_msgbuf *)qbuf,
		sizeof(struct ctc_igd_msgbuf *)-sizeof(long), type, 0);
	if (ret == -1 && errno == EINTR) {
		//printf("EINTR\n");
		if(kill(pid,0)==0){
			sysinfo(&systeminfo);
			if(systeminfo.uptime-time_start>120){
				fprintf( stderr, "%s timeout\n", __func__);
				return ret;
			}
			goto read_retry;
		}
	}
/*
	if (ret == -1) {
		switch (errno) {
			case E2BIG   :
				printf("E2BIG    \n");
				break;
			case EACCES :
				printf("EACCES  \n");
				break;
			case EFAULT   :
				printf("EFAULT   \n");
				break;
			case EIDRM  :
				printf("EIDRM  \n");
				break;
			case EINTR    :
				printf("EINTR    \n");
				break;
			case EINVAL   :
				printf("EINVAL   \n");
				break;
			case ENOMSG   :
				printf("ENOMSG   \n");
				break;
			default:
				printf("unknown\n");
		}
	}
	printf("Type: %ld Text: %s\n", qbuf->mtype, qbuf->mtext);
*/
	return ret;
}

static void notify_ctc_igd(struct ctc_igd_msgbuf * qbuf, int recv)
{
	int msgid, pid;
	key_t key;
	key = ftok( "/bin/ctc-igd-server", 'c');
	if((msgid = msgget(key, 0)) > 0)
	{
		qbuf->mtype = CTC_IGD_MSG_FROM_MIB;
		if(msgsnd(msgid, (void *)qbuf, sizeof(struct ctc_igd_msgbuf)-sizeof(long), 0) < 0)
			printf("%s %d error\n", __FUNCTION__, __LINE__);
		if(recv){
			pid = read_pid("/var/run/ctc-igd-server.pid");
			recv_ctc_igd(msgid, qbuf, CTC_IGD_MSG_RECV, pid);
		}
	}
}
static void notify_ctc_igd_server(MSG_T *mbuf, int index, int recv)
{
	struct ctc_igd_msgbuf cbuf;

	if(read_pid("/var/run/ctc-igd-server.pid") > 0){
		cbuf.type = mbuf->cmd;
		cbuf.mib_id = mbuf->arg1;
		cbuf.index = index;
		notify_ctc_igd(&cbuf, recv);
	}
}
#endif

int mib_lock()
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	int ret=1;

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_MIB_LOCK;
	sendcmd(&qbuf);
	if (qbuf.request != MSG_SUCC) {
		printf("mib lock failed\n");
		ret = 0;
	}

	return ret;
}

int mib_unlock()
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	int ret=1;

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_MIB_UNLOCK;
	sendcmd(&qbuf);
	if (qbuf.request != MSG_SUCC) {
		printf("mib lock failed\n");
		ret = 0;
	}

	return ret;
}

#if !defined(CONFIG_USER_XMLCONFIG) && !defined(CONFIG_USER_CONF_ON_XMLFILE)
/*
 *	Write the specified setting to flash.
 *	This function will also check the length and checksum.
 */
int mib_update_from_raw(unsigned char *ptr, int len)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	int ret, fd;

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_MIB_UPDATE_FROM_RAW;
	mymsg->arg1 = len;
	fd = lock_shm_by_flock();
	if (put_shm_data(ptr, len) < 0) {
		printf("Shared memory operation fail !\n");
		unlock_shm_by_flock(fd);
		return 0;
	}
	sendcmd(&qbuf);
	if (qbuf.request == MSG_SUCC) {
		ret = 1;
	} else {
		printf("mib update_from_raw failed\n");
		ret = 0;
	}
	unlock_shm_by_flock(fd);

	return ret;
}

/*
 *	Load flash setting to the specified pointer
 */
int mib_read_to_raw(CONFIG_DATA_T type, unsigned char* ptr, int len)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	int ret=1, fd;

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_MIB_READ_TO_RAW;
	mymsg->arg1=(int)type;
	mymsg->arg2=len;
	fd=lock_shm_by_flock();
	sendcmd(&qbuf);
	if (qbuf.request == MSG_SUCC) {
		if (get_shm_data(ptr, len)<0) {
			unlock_shm_by_flock(fd);
			return 0;
		}
		ret = 1;
	}
	else {
		printf("mib read_to_raw failed\n");
		ret = 0;
	}
	unlock_shm_by_flock(fd);

	return ret;
}

 /*
  *	Load flash header
  */
int mib_read_header(CONFIG_DATA_T type, PARAM_HEADER_Tp pHeader)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	int ret=1;

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_MIB_READ_HEADER;
	mymsg->arg1=(int)type;
	sendcmd(&qbuf);
	if (qbuf.request == MSG_SUCC) {
		memcpy((void *)pHeader, mymsg->mtext, sizeof(PARAM_HEADER_T));
		ret = 1;
	}
	else {
		printf("mib read header failed\n");
		ret = 0;
	}

	return ret;
}
#endif

int mib_update(CONFIG_DATA_T type, CONFIG_MIB_T flag)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	int ret = 1;

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_MIB_UPDATE;
	mymsg->arg1 = (int)type;
	mymsg->arg2 = (int)flag;

	sendcmd(&qbuf);
	if (qbuf.request != MSG_SUCC) {
		printf("mib update failed\n");
		ret = 0;
	}

	return ret;
}

#ifdef CONFIG_USER_XMLCONFIG
int mib_load(CONFIG_DATA_T type, CONFIG_MIB_T flag)
{
	return xml_mib_load(type, flag);
}
#else
int mib_load(CONFIG_DATA_T type, CONFIG_MIB_T flag)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	int ret=1;

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_MIB_RELOAD;
	mymsg->arg1=(int)type;
	mymsg->arg2=(int)flag;
	sendcmd(&qbuf);
	if (qbuf.request != MSG_SUCC) {
		printf("mib reload failed\n");
		ret = 0;
	}

	return ret;
}
#endif	/*CONFIG_USER_XMLCONFIG*/

/* 2010-10-26 krammer :  */
int mib_swap(int id, int id1)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	mib_table_entry_T info;
	int ret=1;

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_MIB_SWAP;
	mymsg->arg1=id;
	mymsg->arg2=id1;
	sendcmd(&qbuf);
	if (qbuf.request != MSG_SUCC) {
		printf("%s: Swap request failed! (id=%d, id1=%d)\n", __func__, id, id1);
		ret = 0;
	}
	return ret;
}

int mib_get(int id, void *value)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	mib_table_entry_T info;
	int ret;

#ifdef WLAN_SUPPORT
	id = wlan_mib_id_reorder(id);
	if (id == -1) {
		printf("%s: Invalid wlan_idx: %d\n", __FUNCTION__, wlan_idx);
		return 0;
	}
#endif

	if (!mib_info_id(id, &info))
		return 0;

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_MIB_GET;
	mymsg->arg1 = id;

	sendcmd(&qbuf);
	if (qbuf.request == MSG_SUCC) {
		memcpy(value, mymsg->mtext, info.size);
		ret = 1;
	} else {
		printf("%s: Get request failed! (id=%d)\n", __func__, id);
		ret = 0;
	}

	return ret;
}

/*
* mib_get() remove wlan_idx global mapping for dual wlan:
*  - to avoid race condiction while OSGI or other async execution(dbus) with config_Wlan()
*  - if someone want to set wlan associative mibs, and the action async with config_Wlan() (i.e no locked)
*    then you should call "local_mapping" mib API, except original mib API.
*/
int mib_local_mapping_get(int id, int wlanIdx, void *value)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	mib_table_entry_T info;
	int ret;
	
#ifdef WLAN_SUPPORT
	if (id > DUAL_WLAN_START_ID && id < DUAL_WLAN_END_ID)
		id += wlanIdx;
#endif
	
	if (!mib_info_id(id, &info)) {
		return 0;
	}

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_MIB_GET;
	mymsg->arg1 = id;

	sendcmd(&qbuf);
	if (qbuf.request == MSG_SUCC) {
		memcpy(value, mymsg->mtext, info.size);
		ret = 1;
	} else {
		printf("%s: Get request failed! (id=%d)\n", __func__, id);
		ret = 0;
	}

	return ret;
}

int mib_set(int id, void *value)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	mib_table_entry_T info;
	int ret = 1;

#ifdef WLAN_SUPPORT
	id = wlan_mib_id_reorder(id);
	if (id == -1) {
		printf("%s: Invalid wlan_idx: %d\n", __FUNCTION__, wlan_idx);
		return 0;
	}
#endif

	if (!mib_info_id(id, &info))
		return 0;

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_MIB_SET;
	mymsg->arg1 = id;
#ifdef CONFIG_USER_CWMP_TR069
	mymsg->arg2 = 1;
#endif
	memcpy(mymsg->mtext, value, info.size);

	sendcmd(&qbuf);
	if (qbuf.request != MSG_SUCC) {
		printf("%s: Set request failed! (id=%d)\n", __func__, id);
		ret = 0;
	}

#ifdef CONFIG_USER_DBUS_CTC_IGD
	int cmp_result;
	memcpy(&cmp_result, mymsg->mtext, sizeof(int));
	if(ret && cmp_result)
		notify_ctc_igd_server(mymsg, 0, 0);
#endif
#ifdef CONFIG_USER_DBUS_PROXY
	if (ret != 0)
	{
		send_notify_msg_dbusproxy(id, e_dbus_signal_mib_set, 0);
	}
#endif

	return ret;
}

/*
* mib_set() remove wlan_idx global mapping for dual wlan:
*  - to avoid race condiction while OSGI or other async execution(dbus) with config_Wlan()
*  - if someone want to set wlan associative mibs, and the action async with config_Wlan() (i.e no locked)
*    then you should call "local_mapping" mib API, except original mib API.
*/
int mib_local_mapping_set(int id, int wlanIdx, void *value)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	mib_table_entry_T info;
	int ret = 1;

#ifdef WLAN_SUPPORT
	if (id > DUAL_WLAN_START_ID && id < DUAL_WLAN_END_ID)
		id += wlanIdx;
#endif
	
	if (!mib_info_id(id, &info))
		return 0;

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_MIB_SET;
	mymsg->arg1 = id;
#ifdef CONFIG_USER_CWMP_TR069
	mymsg->arg2 = 1;
#endif
	memcpy(mymsg->mtext, value, info.size);

	sendcmd(&qbuf);
	if (qbuf.request != MSG_SUCC) {
		printf("%s: Set request failed! (id=%d)\n", __func__, id);
		ret = 0;
	}

#ifdef CONFIG_USER_DBUS_CTC_IGD
	int cmp_result;
	memcpy(&cmp_result, mymsg->mtext, sizeof(int));
	if(ret && cmp_result)
		notify_ctc_igd_server(mymsg, 0, 0);
#endif
#ifdef CONFIG_USER_DBUS_PROXY
	if (ret != 0)
	{
		send_notify_msg_dbusproxy(id, e_dbus_signal_mib_set, 0);
	}
#endif

	return ret;
}

// Magician: For cwmp_core use only, prevent loop messaging.
#ifdef CONFIG_USER_CWMP_TR069
int mib_set_cwmp(int id, void *value)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	mib_table_entry_T info;
	int ret = 1;

#ifdef WLAN_SUPPORT
	id = wlan_mib_id_reorder(id);
	if (id == -1) {
		printf("%s: Invalid wlan_idx: %d\n", __FUNCTION__, wlan_idx);
		return 0;
	}
#endif

	if (!mib_info_id(id, &info))
		return 0;

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_MIB_SET;
	mymsg->arg1 = id;
#ifdef CONFIG_USER_CWMP_TR069
	mymsg->arg2 = 0;
#endif
	memcpy(mymsg->mtext, value, info.size);

	sendcmd(&qbuf);
	if (qbuf.request != MSG_SUCC) {
		printf("%s: Set request failed! (id=%d)\n", __func__, id);
		ret = 0;
	}

	return ret;
}
#endif

int mib_sys_to_default(CONFIG_DATA_T type)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	int ret = 1;

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_MIB_TO_DEFAULT;
	mymsg->arg1 = (int)type;

	sendcmd(&qbuf);
	if (qbuf.request != MSG_SUCC) {
		printf("mib reset_sys_to_default failed\n");
		ret = 0;
	}

	return ret;
}

#ifdef CONFIG_USER_XMLCONFIG
int mib_flash_to_default(CONFIG_DATA_T type)
{
	int ret;

	ret = xml_mib_flash_to_default(type);
	return ret;
}
#else
int mib_flash_to_default(CONFIG_DATA_T type)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	int ret = 1;

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_MIB_FLASH_TO_DEFAULT;
	mymsg->arg1 = (int)type;

	sendcmd(&qbuf);
	if (qbuf.request != MSG_SUCC) {
		printf("mib reset_flash_to_default failed\n");
		ret = 0;
	}

	return ret;
}
#endif
// 2013/11 Jiachiam
#if (defined VOIP_SUPPORT) && (defined CONFIG_USER_XMLCONFIG)
int mib_voip_to_default()
{
       struct mymsgbuf qbuf;
       MSG_T *mymsg;
       int ret=1;

       mymsg = &qbuf.msg;
       mymsg->cmd = CMD_MIB_VOIP_TO_DEFAULT;
       sendcmd(&qbuf);
       if (qbuf.request != MSG_SUCC) {
               printf("mib reset_flash_to_default failed\n");
               return 0;
       }
       return ret;
}
#endif /* VOIP_SUPPORT &&  CONFIG_USER_XMLCONFIG*/

int mib_info_id(int id, mib_table_entry_T * info)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	int ret;

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_MIB_INFO_ID;
	mymsg->arg1 = id;

	sendcmd(&qbuf);
	if (qbuf.request == MSG_SUCC) {
		memcpy(info, mymsg->mtext, sizeof(mib_table_entry_T));
		ret = 1;
	} else {
		printf("%s: get mib info id failed! (id=%d)\n", __func__, id);
		ret = 0;
	}

	return ret;
}

int mib_getDef(int id, void *value)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	mib_table_entry_T info;
	int ret;

#ifdef WLAN_SUPPORT
	id = wlan_mib_id_reorder(id);
	if (id == -1) {
		printf("%s: Invalid wlan_idx: %d\n", __FUNCTION__, wlan_idx);
		return 0;
	}
#endif

	if (!mib_info_id(id, &info))
		return 0;

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_MIB_GET_DEFAULT;
	mymsg->arg1 = id;

	sendcmd(&qbuf);
	if (qbuf.request == MSG_SUCC) {
		memcpy(value, mymsg->mtext, info.size);
		ret = 1;
	} else {
		printf("%s: Get request failed! (id=%d)\n", __func__, id);
		ret = 0;
	}

	return ret;
}

int mib_info_index(int index, mib_table_entry_T *info)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	int ret=1;

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_MIB_INFO_INDEX;
	mymsg->arg1=index;
	sendcmd(&qbuf);
	if (qbuf.request != MSG_SUCC) {
		printf("%s: Get mib info index %d failed\n", __func__, index);
		ret = 0;
	}
	else
		memcpy((void *)info, (void *)mymsg->mtext, sizeof(mib_table_entry_T));

	return ret;
}

// Apply Star Zhang's fast load
int mib_info_total()
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	int ret=1;

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_MIB_INFO_TOTAL;
	sendcmd(&qbuf);
	if (qbuf.request != MSG_SUCC) {
		printf("get mib size failed\n");
		ret = 0;
	}
	else
		ret = qbuf.msg.arg1;

	return ret;
}
// The end of fast load
/*
 * type:
 * CONFIG_MIB_ALL:   all mib setting (table and chain)
 * CONFIG_MIB_TABLE: mib table
 * CONFIG_MIB_CHAIN: mib_chain
 */
int mib_backup_hs(CONFIG_MIB_T type)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	int ret=1;
	printf("%s-%d: type=%d\n", __func__,__LINE__,type);

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_MIB_BACKUP_HS;
	mymsg->arg1=(int)type;
	sendcmd(&qbuf);
	if (qbuf.request != MSG_SUCC) {
		printf("mib backup hs table failed\n");
		ret = 0;
	}else
		printf("mib backup hs table success\n");

	return ret;
}


/*
 * type:
 * CONFIG_MIB_ALL:   all mib setting (table and chain)
 * CONFIG_MIB_TABLE: mib table
 * CONFIG_MIB_CHAIN: mib_chain
 */
int mib_backup(CONFIG_MIB_T type)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	int ret=1;

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_MIB_BACKUP;
	mymsg->arg1=(int)type;
	sendcmd(&qbuf);
	if (qbuf.request != MSG_SUCC) {
		printf("mib backup table failed\n");
		ret = 0;
	}else
		printf("mib backup table success\n");

	return ret;
}

#ifdef CONFIG_USER_DBUS_CTC_IGD
int mib_backup_ctc(CONFIG_MIB_T type)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	int ret=1;

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_MIB_BACKUP_CTC;
	mymsg->arg1=(int)type;
	sendcmd(&qbuf);
	if (qbuf.request != MSG_SUCC) {
		printf("mib backup table failed\n");
		ret = 0;
	}else
		printf("mib backup table success\n");

	return ret;
}
#endif

//added by ql
#ifdef	RESERVE_KEY_SETTING
int mib_retrive_table(int id)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	int ret=1;

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_MIB_RETRIVE_TABLE;
	mymsg->arg1= id;
	sendcmd(&qbuf);
	if (qbuf.request != MSG_SUCC) {
		printf("mib retrieve table failed\n");
		ret = 0;
	}

	return ret;
}
int mib_retrive_chain(int id)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	int ret=1;

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_MIB_RETRIVE_CHAIN;
	mymsg->arg1= id;
	sendcmd(&qbuf);
	if (qbuf.request != MSG_SUCC) {
		printf("mib retrieve chain failed\n");
		ret = 0;
	}

	return ret;
}
#endif
/*
 * type:
 * CONFIG_MIB_ALL:   all mib setting (table and chain)
 * CONFIG_MIB_TABLE: mib table
 * CONFIG_MIB_CHAIN: mib_chain
 */
int mib_restore(CONFIG_MIB_T type)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	int ret=1;

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_MIB_RESTORE;
	mymsg->arg1=(int)type;
	sendcmd(&qbuf);
	if (qbuf.request != MSG_SUCC) {
		printf("mib restore table failed\n");
		ret = 0;
	}

	return ret;
}

#ifdef CONFIG_USER_DBUS_CTC_IGD
int mib_restore_ctc(CONFIG_MIB_T type)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	int ret=1;

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_MIB_RESTORE_CTC;
	mymsg->arg1=(int)type;
	sendcmd(&qbuf);
	if (qbuf.request != MSG_SUCC) {
		printf("mib restore table failed\n");
		ret = 0;
	}

	return ret;
}
#endif

int mib_chain_total(int id)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	int ret;

#ifdef WLAN_SUPPORT
	id = wlan_mibchain_id_reorder(id);
	if (id == -1) {
		printf("%s: Invalid wlan_idx: %d\n", __FUNCTION__, wlan_idx);
		return 0;
	}
#endif

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_CHAIN_TOTAL;
	mymsg->arg1 = id;

	sendcmd(&qbuf);
	if (qbuf.request == MSG_SUCC) {
		ret = qbuf.msg.arg1;
	} else {
		printf("get total failed\n");
		ret = 0;
	}

	return ret;
}

/*
* mib_chain_total() remove wlan_idx global mapping for dual wlan:
*  - to avoid race condiction while OSGI or other async execution(dbus) with config_Wlan()
*  - if someone want to set wlan associative mibs, and the action async with config_Wlan() (i.e no locked)
*    then you should call "local_mapping" mib API, except original mib API.
*/
int mib_chain_local_mapping_total(int id, int wlanIdx)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	int ret;

#ifdef WLAN_SUPPORT
	if (id > DUAL_WLAN_CHAIN_START_ID && id < DUAL_WLAN_CHAIN_END_ID)
		id += wlanIdx;
#endif
	
	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_CHAIN_TOTAL;
	mymsg->arg1 = id;

	sendcmd(&qbuf);
	if (qbuf.request == MSG_SUCC) {
		ret = qbuf.msg.arg1;
	} else {
		printf("get total failed\n");
		ret = 0;
	}

	return ret;
}

/* cathy, to swap recordNum1 and recordNum2 of a chain */
int mib_chain_swap(int id, unsigned int recordNum1, unsigned int recordNum2)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	mib_chain_record_table_entry_T info;
	int ret = 1;

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_CHAIN_SWAP;
	mymsg->arg1=recordNum1;
	mymsg->arg2=recordNum2;
	sprintf(mymsg->mtext, "%d", id);

	sendcmd(&qbuf);
	if (qbuf.request != MSG_SUCC) {
		printf("update chain failed\n");
		ret = 0;
	}

	return ret;
}

int mib_chain_get(int id, unsigned int recordNum, void *value)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	mib_chain_record_table_entry_T info;
	int ret;
	int size;
#ifdef USE_SHM
	// Mason Yu. deadlock
	int fd;
#endif

#ifdef WLAN_SUPPORT
	id = wlan_mibchain_id_reorder(id);
	if (id == -1) {
		printf("%s: Invalid wlan_idx: %d\n", __FUNCTION__, wlan_idx);
		return 0;
	}
#endif

	if (!mib_chain_info_id(id, &info))
		return 0;

	size = info.per_record_size;
#ifdef USE_SHM
	if (size >= SHM_SIZE) {
		printf("chain_get: chain record size(%d) overflow (max. %d).\n",
		       size, SHM_SIZE);
		return 0;
	}
#else
	if (size >= MAX_SEND_SIZE) {
		printf("chain_get: chain record size(%d) overflow (max. %d).\n",
		       size, MAX_SEND_SIZE);
		return 0;
	}
#endif

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_CHAIN_GET;
	mymsg->arg1 = id;
	sprintf(mymsg->mtext, "%u", recordNum);
#ifdef USE_SHM
	fd = lock_shm_by_flock();
#endif
	sendcmd(&qbuf);
	if (qbuf.request != MSG_SUCC) {
		printf("get chain failed\n");
		ret = 0;
	} else {
#ifdef USE_SHM
		if (get_shm_data(value, size) < 0)
			ret = 0;
		else
			ret = 1;
#else
		memcpy(value, mymsg->mtext, size);
		ret = 1;
#endif
	}
#ifdef USE_SHM
	unlock_shm_by_flock(fd);
#endif
	return ret;
}

/*
* mib_chain_get() remove wlan_idx global mapping for dual wlan:
*  - to avoid race condiction while OSGI or other async execution(dbus) with config_Wlan()
*  - if someone want to set wlan associative mibs, and the action async with config_Wlan() (i.e no locked)
*    then you should call "local_mapping" mib API, except original mib API.
*/
int mib_chain_local_mapping_get(int id, int wlanIdx, unsigned int recordNum, void *value)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	mib_chain_record_table_entry_T info;
	int ret;
	int size;
#ifdef USE_SHM
	// Mason Yu. deadlock
	int fd;
#endif

#ifdef WLAN_SUPPORT
	if (id > DUAL_WLAN_CHAIN_START_ID && id < DUAL_WLAN_CHAIN_END_ID)
		id += wlanIdx;
#endif

	if (!mib_chain_info_id(id, &info))
		return 0;

	size = info.per_record_size;
#ifdef USE_SHM
	if (size >= SHM_SIZE) {
		printf("chain_get: chain record size(%d) overflow (max. %d).\n",
		       size, SHM_SIZE);
		return 0;
	}
#else
	if (size >= MAX_SEND_SIZE) {
		printf("chain_get: chain record size(%d) overflow (max. %d).\n",
		       size, MAX_SEND_SIZE);
		return 0;
	}
#endif

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_CHAIN_GET;
	mymsg->arg1 = id;
	sprintf(mymsg->mtext, "%u", recordNum);
#ifdef USE_SHM
	fd = lock_shm_by_flock();
#endif
	sendcmd(&qbuf);
	if (qbuf.request != MSG_SUCC) {
		printf("get chain failed,id=%d,%s:%d\n",id,__func__,__LINE__);
		ret = 0;
	} else {
#ifdef USE_SHM
		if (get_shm_data(value, size) < 0)
			ret = 0;
		else
			ret = 1;
#else
		memcpy(value, mymsg->mtext, size);
		ret = 1;
#endif
	}
#ifdef USE_SHM
	unlock_shm_by_flock(fd);
#endif
	return ret;
}

int mib_chain_backup_get(int id, unsigned int recordNum, void *value)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	mib_chain_record_table_entry_T info;
	int ret;
	int size;
#ifdef USE_SHM
	// Mason Yu. deadlock
	int fd;
#endif

#ifdef WLAN_SUPPORT
	if (id > DUAL_WLAN_CHAIN_START_ID && id < DUAL_WLAN_CHAIN_END_ID)
		id += wlan_idx;
#endif

	if (!mib_chain_info_id(id, &info))
		return 0;

	size = info.per_record_size;
#ifdef USE_SHM
	if (size >= SHM_SIZE) {
		printf("chain_get: chain record size(%d) overflow (max. %d).\n",
		       size, SHM_SIZE);
		return 0;
	}
#else
	if (size >= MAX_SEND_SIZE) {
		printf("chain_get: chain record size(%d) overflow (max. %d).\n",
		       size, MAX_SEND_SIZE);
		return 0;
	}
#endif

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_MIB_CHAIN_BACKUP_GET;
	mymsg->arg1 = id;
	sprintf(mymsg->mtext, "%u", recordNum);
#ifdef USE_SHM
	fd = lock_shm_by_flock();
#endif
	sendcmd(&qbuf);
	if (qbuf.request != MSG_SUCC) {
		printf("get chain failed,id=%d,%s:%d\n",id,__func__,__LINE__);
		ret = 0;
	} else {
#ifdef USE_SHM
		if (get_shm_data(value, size) < 0)
			ret = 0;
		else
			ret = 1;
#else
		memcpy(value, mymsg->mtext, size);
		ret = 1;
#endif
	}
#ifdef USE_SHM
	unlock_shm_by_flock(fd);
#endif
	return ret;
}

/*
 * 0  : add fail
 * -1 : table full
 * 1  : successful
 */
int mib_chain_add(int id, void *ptr)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	mib_chain_record_table_entry_T info;
	int ret;
	int size;
#ifdef USE_SHM
	int fd;
#endif

	if (!mib_chain_info_id(id, &info))
		return 0;

	size = mib_chain_total(id);

#ifdef WLAN_SUPPORT
	id = wlan_mibchain_id_reorder(id);
	if (id == -1) {
		printf("%s: Invalid wlan_idx: %d\n", __FUNCTION__, wlan_idx);
		return 0;
	}
#endif

	ret = size + 1;
	if (info.table_size != -1 && size >= info.table_size)
		return -1;
	size = info.per_record_size;
#ifdef USE_SHM
	if (size >= SHM_SIZE) {
		printf("chain_add: chain record size(%d) overflow (max. %d).\n",
		       size, SHM_SIZE);
		return 0;
	}
#else
	if (size >= MAX_SEND_SIZE) {
		printf("chain_add: chain record size(%d) overflow (max. %d).\n",
		       size, MAX_SEND_SIZE);
		return 0;
	}
#endif

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_CHAIN_ADD;
	mymsg->arg1 = id;
#ifdef USE_SHM
	fd = lock_shm_by_flock();
	if (put_shm_data(ptr, size) < 0) {
		printf("Shared memory operation fail !\n");
		unlock_shm_by_flock(fd);
		return 0;
	}
#else
	memcpy(mymsg->mtext, ptr, size);
#endif

	sendcmd(&qbuf);
	if (qbuf.request != MSG_SUCC) {
		printf("add chain failed\n");
		ret = 0;
	}
#ifdef USE_SHM
	unlock_shm_by_flock(fd);
#endif

#ifdef CONFIG_USER_DBUS_CTC_IGD
	if(ret)
		notify_ctc_igd_server(mymsg, ret, 0);
#endif
#ifdef CONFIG_USER_DBUS_PROXY
	if (ret != 0)
	{
		send_notify_msg_dbusproxy(id, e_dbus_signal_mib_chain_add, 0);
	}
#endif
	return ret;
}

int mib_chain_delete(int id, unsigned int recordNum)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	int ret = 1;

#ifdef WLAN_SUPPORT
	id = wlan_mibchain_id_reorder(id);
	if (id == -1) {
		printf("%s: Invalid wlan_idx: %d\n", __FUNCTION__, wlan_idx);
		return 0;
	}
#endif

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_CHAIN_DELETE;
	mymsg->arg1 = id;
	sprintf(mymsg->mtext, "%u", recordNum);

	sendcmd(&qbuf);
	if (qbuf.request != MSG_SUCC) {
		printf("delete chain failed\n");
		ret = 0;
	}

#ifdef CONFIG_USER_DBUS_CTC_IGD
	if(ret)
		notify_ctc_igd_server(mymsg, recordNum, 0);
#endif
#ifdef CONFIG_USER_DBUS_PROXY
	if (ret != 0)
	{
		send_notify_msg_dbusproxy(id, e_dbus_signal_mib_chain_delete, recordNum);
	}
#endif

	return ret;
}

int mib_chain_clear(int id)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	int ret = 1;

#ifdef WLAN_SUPPORT
	id = wlan_mibchain_id_reorder(id);
	if (id == -1) {
		printf("%s: Invalid wlan_idx: %d\n", __FUNCTION__, wlan_idx);
		return 0;
	}
#endif

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_CHAIN_CLEAR;
	mymsg->arg1 = id;

	sendcmd(&qbuf);
	if (qbuf.request != MSG_SUCC) {
		printf("clear chain failed\n");
		ret = 0;
	}

	return ret;
}

int mib_chain_update(int id, void *ptr, unsigned int recordNum)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	mib_chain_record_table_entry_T info;
	int ret = 1;
	int size;
#ifdef USE_SHM
	int fd;
#endif

#ifdef WLAN_SUPPORT
	id = wlan_mibchain_id_reorder(id);
	if (id == -1) {
		printf("%s: Invalid wlan_idx: %d\n", __FUNCTION__, wlan_idx);
		return 0;
	}
#endif

	if (!mib_chain_info_id(id, &info))
		return 0;

	size = info.per_record_size;
#ifdef USE_SHM
	if (size >= SHM_SIZE) {
		printf
		    ("chain_update: chain record size(%d) overflow (max. %d).\n",
		     size, SHM_SIZE);
		return 0;
	}
#else
	if (size >= MAX_SEND_SIZE) {
		printf
		    ("chain_update: chain record size(%d) overflow (max. %d).\n",
		     size, MAX_SEND_SIZE);
		return 0;
	}
#endif

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_CHAIN_UPDATE;
	mymsg->arg1 = id;
	mymsg->arg2 = recordNum;
#ifdef USE_SHM
	fd = lock_shm_by_flock();
	if (put_shm_data(ptr, size) < 0) {
		printf("Shared memory operation fail !\n");
		unlock_shm_by_flock(fd);
		return 0;
	}
#else
	memcpy(mymsg->mtext, ptr, size);
#endif

	sendcmd(&qbuf);
	if (qbuf.request != MSG_SUCC) {
		printf("update chain failed\n");
		ret = 0;
	}
#ifdef CONFIG_USER_DBUS_CTC_IGD
	if(ret)
		notify_ctc_igd_server(mymsg, recordNum, 1);
#endif

#ifdef USE_SHM
	unlock_shm_by_flock(fd);
#endif

#ifdef CONFIG_USER_DBUS_PROXY 
        if (ret != 0)
        {
                //if (id != 393)
                {
                        send_notify_msg_dbusproxy(id, e_dbus_signal_mib_chain_update, recordNum);
                }
        }
#endif
	return ret;
}

/*
* mib_chain_update() remove wlan_idx global mapping for dual wlan:
*  - to avoid race condiction while OSGI or other async execution(dbus) with config_Wlan()
*  - if someone want to set wlan associative mibs, and the action async with config_Wlan() (i.e no locked)
*    then you should call "local_mapping" mib API, except original mib API.
*/
int mib_chain_local_mapping_update(int id, int wlanIdx, void *ptr, unsigned int recordNum)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	mib_chain_record_table_entry_T info;
	int ret = 1;
	int size;
#ifdef USE_SHM
	int fd;
#endif

#ifdef WLAN_SUPPORT
	if (id > DUAL_WLAN_CHAIN_START_ID && id < DUAL_WLAN_CHAIN_END_ID)
		id += wlanIdx;
#endif

	if (!mib_chain_info_id(id, &info))
		return 0;

	size = info.per_record_size;
#ifdef USE_SHM
	if (size >= SHM_SIZE) {
		printf
		    ("chain_update: chain record size(%d) overflow (max. %d).\n",
		     size, SHM_SIZE);
		return 0;
	}
#else
	if (size >= MAX_SEND_SIZE) {
		printf
		    ("chain_update: chain record size(%d) overflow (max. %d).\n",
		     size, MAX_SEND_SIZE);
		return 0;
	}
#endif

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_CHAIN_UPDATE;
	mymsg->arg1 = id;
	mymsg->arg2 = recordNum;
#ifdef USE_SHM
	fd = lock_shm_by_flock();
	if (put_shm_data(ptr, size) < 0) {
		printf("Shared memory operation fail !\n");
		unlock_shm_by_flock(fd);
		return 0;
	}
#else
	memcpy(mymsg->mtext, ptr, size);
#endif

	sendcmd(&qbuf);
	if (qbuf.request != MSG_SUCC) {
		printf("update chain failed\n");
		ret = 0;
	}
#ifdef CONFIG_USER_DBUS_CTC_IGD
	if(ret)
		notify_ctc_igd_server(mymsg, recordNum, 1);
#endif

#ifdef USE_SHM
	unlock_shm_by_flock(fd);
#endif

#ifdef CONFIG_USER_DBUS_PROXY 
        if (ret != 0)
        {
                //if (id != 393)
                {
                        send_notify_msg_dbusproxy(id, e_dbus_signal_mib_chain_update, recordNum);
                }
        }
#endif
	return ret;
}

int mib_chain_info_id(int id, mib_chain_record_table_entry_T * info)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	int ret;

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_CHAIN_INFO_ID;
	mymsg->arg1 = id;

	sendcmd(&qbuf);
	if (qbuf.request != MSG_SUCC) {
		printf("get mib chain info id failed,id=%d\n",id);
		ret = 0;
	} else {
		memcpy(info, mymsg->mtext,
		       sizeof(mib_chain_record_table_entry_T));
		ret = 1;
	}

	return ret;
}

int mib_chain_info_index(int index, mib_chain_record_table_entry_T *info)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	int ret=1;

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_CHAIN_INFO_INDEX;
	mymsg->arg1=index;
	sendcmd(&qbuf);
	if (qbuf.request != MSG_SUCC) {
		printf("get mib chain info index failed\n");
		ret = 0;
	}
	else
		memcpy((void *)info, (void *)mymsg->mtext, sizeof(mib_chain_record_table_entry_T));

	return ret;
}

int mib_chain_info_name(char *name, mib_chain_record_table_entry_T *info)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	int ret=1;

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_CHAIN_INFO_NAME;
	strncpy(mymsg->mtext, name, MAX_SEND_SIZE);
	sendcmd(&qbuf);
	if (qbuf.request != MSG_SUCC) {
		printf("get mib chain info name failed\n");
		ret = 0;
	}
	else
		memcpy((void *)info, (void *)mymsg->mtext, sizeof(mib_chain_record_table_entry_T));

	return ret;
}

/*
 *	0: Request fail
 *	1: descriptor checking successful
 *	-1: descriptor checking failed
 */
int mib_check_desc(void)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	int ret=1;

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_CHECK_DESC;
	sendcmd(&qbuf);
	if (qbuf.request != MSG_SUCC) {
		printf("Check mib chain descriptors failed\n");
		return 0;
	}

	ret = mymsg->arg1;
	return ret;
}

int cmd_reboot(void)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	int ret = 1;

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_REBOOT;

	sendcmd(&qbuf);
	if (qbuf.request != MSG_SUCC) {
		printf("reboot failed\n");
		ret = 0;
	}

	return ret;
}

#ifdef CONFIG_IPV6
#if defined(CONFIG_USER_DHCPV6_ISC_DHCP411) && defined(CONFIG_USER_RADVD)
int cmd_delegation(const char *fname)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	int ret=1;

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_DELEGATION;
	strncpy(mymsg->mtext, fname, MAX_SEND_SIZE-1);
	mymsg->mtext[MAX_SEND_SIZE-1] = '\0';
	sendcmd(&qbuf);
	if (qbuf.request != MSG_SUCC) {
		printf("Do Delegation failed\n");
		ret = 0;
	}

	return ret;
}
#endif

#if defined(CONFIG_USER_DHCPV6_ISC_DHCP411)
int cmd_stop_delegation(const char *fname)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	int ret=1;

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_STOP_DELEGATION;
	strncpy(mymsg->mtext, fname, MAX_SEND_SIZE-1);
	mymsg->mtext[MAX_SEND_SIZE-1] = '\0';
	sendcmd(&qbuf);
	if (qbuf.request != MSG_SUCC) {
		printf("Stop Delegation failed\n");
		ret = 0;
	}

	return ret;
}

int cmd_get_PD_prefix_ip(void *value)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	int ret=1;

    mymsg = &qbuf.msg;
    mymsg->cmd = CMD_GET_PD_PREFIX_IP;
	sendcmd(&qbuf);
	if (qbuf.request == MSG_SUCC) {
		memcpy(value, mymsg->mtext, IP6_ADDR_LEN);
		ret = 1;
	}
	else {
		printf("CMD_GET_PD_IP_PREFIX failed\n");
		ret = 0;
	}
	return ret;
}

int cmd_get_PD_prefix_len(void)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	int ret=1;

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_GET_PD_PREFIX_LEN;
	sendcmd(&qbuf);
	if (qbuf.request != MSG_SUCC) {
		printf("CMD_GET_PD_IP_PREFIX  failed\n");
		ret = 0;
	}
	else
		ret = qbuf.msg.arg1;
	return ret;
}
#endif
#endif  // #ifdef CONFIG_IPV6

int cmd_killproc(unsigned int mask)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	int ret=1;

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_KILLPROC;
	mymsg->arg1=mask;
	sendcmd(&qbuf);
	if (qbuf.request != MSG_SUCC) {
		printf("kill processes failed\n");
		ret = 0;
	}

	return ret;
}

int cmd_upload(const char *fname, int offset, int imgFileSize, int needreboot)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	int ret = 1;

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_UPLOAD;
	mymsg->arg2 = imgFileSize;
	mymsg->arg3 = needreboot;
	if (imgFileSize != 0) {
		mymsg->arg1 = offset;
		strncpy(mymsg->mtext, fname, MAX_SEND_SIZE - 1);
		mymsg->mtext[MAX_SEND_SIZE - 1] = '\0';
	}

	sendcmd(&qbuf);
	if (qbuf.request != MSG_SUCC) {
		printf("firmware upgrade failed\n");
#ifdef SUPPORT_WEB_PUSHUP
			firmwareUpgradeConfigStatusSet(FW_UPGRADE_STATUS_FAIL);
#endif
		ret = 0;
	}

	return ret;
}

#ifndef CONFIG_LUNA_FIRMWARE_UPGRADE_SUPPORT
int cmd_check_image(const char *fname, int offset)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	int ret = 1;

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_CHECK_IMAGE;
	mymsg->arg1 = offset;
	strncpy(mymsg->mtext, fname, MAX_SEND_SIZE - 1);
	mymsg->mtext[MAX_SEND_SIZE - 1] = '\0';

	sendcmd(&qbuf);
	if (qbuf.request != MSG_SUCC) {
		printf("firmware check failed\n");
		ret = 0;
	}

	return ret;
}
#endif

int cmd_start_autohunt()
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	int ret=1;

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_START_AUTOHUNT;
	sendcmd(&qbuf);
	if (qbuf.request != MSG_SUCC) {
		printf("start autohunt failed\n");
		ret = 0;
	}

	return ret;
}

// Aded by Mason Yu
#ifdef CONFIG_USER_DDNS
int cmd_ddnsctrl(const char *ifname, int mode)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	int ret=1;

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_DDNS_CTRL;
	strncpy(mymsg->mtext, ifname, MAX_SEND_SIZE-1);
	mymsg->mtext[MAX_SEND_SIZE-1] = '\0';
	// Mason Yu. Specify IP Address
	mymsg->arg1=mode;
	sendcmd(&qbuf);
	if (qbuf.request != MSG_SUCC) {
		printf("Start DDNSCtrl failed\n");
		ret = 0;
	}

	return ret;
}
#endif

// Kaohj -- Translating xml file
/*
 * Translate file (fname) to xml (xname)
 * fname: file name of the [encrypted] file (getting from outside world)
 * xname: file name of the xml-formatted file for local process
 */
int cmd_file2xml(const char *fname, const char *xname)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	int ret=1;
	MSGFile_T *pFile;

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_FILE2XML;
	pFile = (MSGFile_T *)&mymsg->mtext[0];
	strncpy(pFile->fromName, fname, 32);
	pFile->fromName[31] = '\0';
	strncpy(pFile->toName, xname, 32);
	pFile->toName[31] = '\0';
	mymsg->mtext[MAX_SEND_SIZE-1] = '\0';
	sendcmd(&qbuf);
	if (qbuf.request != MSG_SUCC) {
		printf("File to XML failed\n");
		ret = 0;
	}

	return ret;
}

/*
 * Translate xml (xname) to file (fname)
 * xname: file name of the local-generated xml-formatted file
 * fname: file name of the [encrypted] file (to be transferred)
 */
int cmd_xml2file(const char *xname, const char *fname)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	int ret=1;
	MSGFile_T *pFile;

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_XML2FILE;
	pFile = (MSGFile_T *)&mymsg->mtext[0];
	strncpy(pFile->fromName, xname, 32);
	pFile->fromName[31] = '\0';
	strncpy(pFile->toName, fname, 32);
	pFile->toName[31] = '\0';
	mymsg->mtext[MAX_SEND_SIZE-1] = '\0';
	sendcmd(&qbuf);
	if (qbuf.request != MSG_SUCC) {
		printf("XML to File failed\n");
		ret = 0;
	}

	return ret;
}

#ifdef CONFIG_RTL8676_CHECK_WIFISTATUS
/*
 * Sleep 3 seconds and Check Wi-Fi status.
 * If Wi-Fi start failed, restart Wi-Fi.
 */
int cmd_wlan_delay_restart()
{
	int retry = 0;
	int delay = 10;

	int i,j,k;

	while(retry < 3)
	{
		if(retry == 2)
			delay = 5;	  // delay 5 seconds in third try

		fprintf(stderr, "Delay %d seconds...\n", delay);
		//usleep(10000000);
		for(i=0;i<0x8fff;i++)
			for(j=0;j<0xfff;j++)
				k = j + i;
		// see if WLAN interface is ready or not
		if (!getInFlags((char *)getWlanIfName(), 0)) {
			retry++;
			fprintf(stderr, "WLAN interface is no ready, try again.\n");
			continue;	   //not ready, try again.
		}

		fprintf(stderr, "Restarting WLAN...\n");
		config_WLAN(ACT_RESTART);

		return 0;
	}
	return -1;
}
#endif

#if defined(CONFIG_IPV6) && defined(DUAL_STACK_LITE) &&defined(CONFIG_USER_DHCPV6_ISC_DHCP411)
int cmd_got_aftr(char *aftrinfo, int length)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	int ret = 1;

	if (length >= MAX_SEND_SIZE) {
		printf("cmd_got_aftr:  info size(%d) overflow (max. %d).\n", length, MAX_SEND_SIZE);
		return 0;
	}

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_GOT_AFTR;
	mymsg->arg1 = (int)length;
	strcpy(mymsg->mtext, aftrinfo);

	sendcmd(&qbuf);
	if (qbuf.request != MSG_SUCC) {
		printf("send cmd_god_aftr failed\n");
		ret = 0;
	}

	return ret;

}
#endif

#if defined(CONFIG_IPV6) && defined(DUAL_STACK_LITE)
int cmd_dslite_aftr_static(char *ifname, char *aftr)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	int ret = 1;
	
	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_DSLITE_AFTR_STATIC;
	sprintf(mymsg->mtext, "%s,%s", ifname, aftr);
	
	sendcmd(&qbuf);
	if (qbuf.request != MSG_SUCC) {
		printf("send cmd_dslite_aftr_static failed\n");
		ret = 0;
	}

	return ret;
}
#endif

int mib_set_PPPoE(int cmd, void *value, unsigned int length)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	int ret = 1;

	if (length >= MAX_SEND_SIZE) {
		printf("set_PPPoE: PPPoE session info size(%d) overflow (max. %d).\n", length, MAX_SEND_SIZE);
		return 0;
	}
	mymsg = &qbuf.msg;
	mymsg->cmd = cmd;
	mymsg->arg1 = (int)length;
	memcpy(mymsg->mtext, value, length);

	sendcmd(&qbuf);
	if (qbuf.request != MSG_SUCC) {
		printf("save PPPoE session failed\n");
		ret = 0;
	}

	return ret;
}

int cmd_set_dns_config(const char *ifname)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	int ret = 1;

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_SET_DNS_CONFIG;
	if (ifname != NULL)
	{
		strncpy(mymsg->mtext, ifname, MAX_SEND_SIZE-1);
		mymsg->mtext[MAX_SEND_SIZE-1] = '\0';
	}
	else
		mymsg->mtext[0] = '\0';

	sendcmd(&qbuf);
	if (qbuf.request != MSG_SUCC) {
		printf("%s failed\n", __FUNCTION__);
		ret = 0;
	}

	return ret;
}

int cmd_set_dbus_register_pid(int pid)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	int ret = 1;

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_DBUS_REGISTER_PID;
	mymsg->arg1 = pid;

	sendcmd(&qbuf);
	if (qbuf.request != MSG_SUCC) {
		printf("%s failed\n", __FUNCTION__);
		ret = 0;
	}

	return ret;
}

#ifdef CONFIG_REMOTE_CONFIGD
static int rconfigd_socket;
static size_t max_send_size;
static struct sockaddr_in *paddr;

#ifdef CONFIG_SPC
int rconfigd_init(void)
{
	rconfigd_socket = socket(PF_SPC, SOCK_DGRAM, 0);

	if (rconfigd_socket < 0) {
		perror("socket");
		return 0;
	}

	paddr = NULL;

	/* minus 1 for subtype */
	max_send_size = ETH_DATA_LEN - 1;
	if (max_send_size > sizeof(struct mymsgbuf))
		max_send_size = sizeof(struct mymsgbuf);

	return 1;
}
#else
int rconfigd_init(void)
{
	static struct sockaddr_in addr;
	int broadcast = 1;
	struct in_addr ip, subnet;

	rconfigd_socket = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);

	if (rconfigd_socket < 0) {
		perror("socket");
		return 0;
	}

	if (setsockopt(rconfigd_socket, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast)) < 0)
		fprintf(stderr, "%s:%d setsockopt: %s\n", __FUNCTION__, __LINE__, strerror(errno));

	mib_get(MIB_ADSL_LAN_IP, &ip);
	mib_get(MIB_ADSL_LAN_SUBNET, &subnet);

	addr.sin_addr.s_addr = ip.s_addr | ~subnet.s_addr;
	addr.sin_port = htons(8809);
	addr.sin_family = PF_INET;
	paddr = &addr;

	max_send_size = sizeof(struct mymsgbuf);

	return 1;
}
#endif

void rconfigd_exit(void)
{
	close(rconfigd_socket);
}

int mib_info_id_via_rconfigd(int id, mib_table_entry_T * info)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	int ret;

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_MIB_INFO_ID;
	mymsg->arg1 = id;

	sendto(rconfigd_socket, &qbuf, max_send_size, 0, (struct sockaddr *)paddr, sizeof(*paddr));
	recv(rconfigd_socket, &qbuf, sizeof(qbuf), 0);
	if (qbuf.request == MSG_SUCC) {
		memcpy(info, mymsg->mtext, sizeof(mib_table_entry_T));
		ret = 1;
	} else {
		printf("%s: get mib info id failed! (id=%d)\n", __func__, id);
		ret = 0;
	}

	return ret;
}

int mib_get_via_rconfigd(int id, void *value)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	mib_table_entry_T info;
	int ret;

	if (!mib_info_id_via_rconfigd(id, &info))
		return 0;

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_MIB_GET;
	mymsg->arg1 = id;

	sendto(rconfigd_socket, &qbuf, max_send_size, 0, (struct sockaddr *)paddr, sizeof(*paddr));
	recv(rconfigd_socket, &qbuf, sizeof(qbuf), 0);
	if (qbuf.request == MSG_SUCC) {
		memcpy(value, mymsg->mtext, info.size);
		ret = 1;
	} else {
		printf("%s: Get request failed! (id=%d)\n", __func__, id);
		ret = 0;
	}

	return ret;
}

int mib_set_via_rconfigd(int id, void *value)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	mib_table_entry_T info;
	int ret = 1;

	if (!mib_info_id_via_rconfigd(id, &info))
		return 0;

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_MIB_SET;
	mymsg->arg1 = id;
#ifdef CONFIG_USER_CWMP_TR069
	mymsg->arg2 = 1;
#endif
	memcpy(mymsg->mtext, value, info.size);

	sendto(rconfigd_socket, &qbuf, max_send_size, 0, (struct sockaddr *)paddr, sizeof(*paddr));
	recv(rconfigd_socket, &qbuf, sizeof(qbuf), 0);
	if (qbuf.request != MSG_SUCC) {
		printf("%s: Set request failed! (id=%d)\n", __func__, id);
		ret = 0;
	}

	return ret;
}

int mib_update_via_rconfigd(CONFIG_DATA_T type, CONFIG_MIB_T flag)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	int ret = 1;

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_MIB_UPDATE;
	mymsg->arg1 = (int)type;
	mymsg->arg2 = (int)flag;

	sendto(rconfigd_socket, &qbuf, max_send_size, 0, (struct sockaddr *)paddr, sizeof(*paddr));
	recv(rconfigd_socket, &qbuf, sizeof(qbuf), 0);
	if (qbuf.request != MSG_SUCC) {
		printf("mib update failed\n");
		ret = 0;
	}

	return ret;
}

int cmd_reboot_via_rconfigd(void)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	int ret = 1;

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_REBOOT;

	sendto(rconfigd_socket, &qbuf, max_send_size, 0, (struct sockaddr *)paddr, sizeof(*paddr));
	recv(rconfigd_socket, &qbuf, sizeof(qbuf), 0);
	if (qbuf.request != MSG_SUCC) {
		printf("reboot failed\n");
		ret = 0;
	}

	return ret;
}

int mib_chain_total_via_rconfigd(int id)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	int ret;

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_CHAIN_TOTAL;
	mymsg->arg1 = id;

	sendto(rconfigd_socket, &qbuf, max_send_size, 0, (struct sockaddr *)paddr, sizeof(*paddr));
	read(rconfigd_socket, &qbuf, sizeof(qbuf));
	if (qbuf.request == MSG_SUCC) {
		ret = qbuf.msg.arg1;
	} else {
		printf("get total failed\n");
		ret = 0;
	}

	return ret;
}

int mib_chain_info_id_via_rconfigd(int id, mib_chain_record_table_entry_T * info)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	int ret;

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_CHAIN_INFO_ID;
	mymsg->arg1 = id;

	sendto(rconfigd_socket, &qbuf, max_send_size, 0, (struct sockaddr *)paddr, sizeof(*paddr));
	read(rconfigd_socket, &qbuf, sizeof(qbuf));
	if (qbuf.request != MSG_SUCC) {
		printf("get mib chain info id failed\n");
		ret = 0;
	} else {
		memcpy(info, mymsg->mtext,
		       sizeof(mib_chain_record_table_entry_T));
		ret = 1;
	}

	return ret;
}

int mib_chain_get_via_rconfigd(int id, unsigned int recordNum, void *value)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	mib_chain_record_table_entry_T info;
	int ret;
	int size;

	if (!mib_chain_info_id_via_rconfigd(id, &info))
		return 0;

	size = info.per_record_size;
	if (size >= max_send_size) {
		printf("chain_get: chain record size(%d) overflow (max. %d).\n",
		       size, max_send_size);
		return 0;
	}

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_CHAIN_GET;
	mymsg->arg1 = id;
	sprintf(mymsg->mtext, "%u", recordNum);

	sendto(rconfigd_socket, &qbuf, max_send_size, 0, (struct sockaddr *)paddr, sizeof(*paddr));
	read(rconfigd_socket, &qbuf, sizeof(qbuf));
	if (qbuf.request != MSG_SUCC) {
		printf("get chain failed,id=%d,%s:%d\n",id,__func__,__LINE__);
		ret = 0;
	} else {
		memcpy(value, mymsg->mtext, size);
		ret = 1;
	}

	return ret;
}

int mib_chain_update_via_rconfigd(int id, void *ptr, unsigned int recordNum)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	mib_chain_record_table_entry_T info;
	int ret = 1;
	int size;

	if (!mib_chain_info_id_via_rconfigd(id, &info))
		return 0;

	size = info.per_record_size;
	if (size >= max_send_size) {
		printf
		    ("chain_update: chain record size(%d) overflow (max. %d).\n",
		     size, max_send_size);
		return 0;
	}

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_CHAIN_UPDATE;
	mymsg->arg1 = id;
	mymsg->arg2 = recordNum;
	memcpy(mymsg->mtext, ptr, size);

	sendto(rconfigd_socket, &qbuf, max_send_size, 0, (struct sockaddr *)paddr, sizeof(*paddr));
	recv(rconfigd_socket, &qbuf, sizeof(qbuf), 0);
	if (qbuf.request != MSG_SUCC) {
		printf("update chain failed\n");
		ret = 0;
	}

	return ret;
}

int mib_chain_add_via_rconfigd(int id, void *ptr)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	mib_chain_record_table_entry_T info;
	int ret;
	int size;

	if (!mib_chain_info_id_via_rconfigd(id, &info))
		return 0;

	size = mib_chain_total_via_rconfigd(id);
	ret = size + 1;
	if (info.table_size != -1 && size >= info.table_size)
		return -1;
	size = info.per_record_size;
	if (size >= max_send_size) {
		printf("chain_add: chain record size(%d) overflow (max. %d).\n",
		       size, max_send_size);
		return 0;
	}

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_CHAIN_ADD;
	mymsg->arg1 = id;
	memcpy(mymsg->mtext, ptr, size);

	sendto(rconfigd_socket, &qbuf, max_send_size, 0, (struct sockaddr *)paddr, sizeof(*paddr));
	recv(rconfigd_socket, &qbuf, sizeof(qbuf), 0);
	if (qbuf.request != MSG_SUCC) {
		printf("add chain failed\n");
		ret = 0;
	}

	return ret;
}

int mib_chain_delete_via_rconfigd(int id, unsigned int recordNum)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	int ret = 1;

#ifdef WLAN_SUPPORT
	id = wlan_mibchain_id_reorder(id);
	if (id == -1) {
		printf("%s: Invalid wlan_idx: %d\n", __FUNCTION__, wlan_idx);
		return 0;
	}
#endif

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_CHAIN_DELETE;
	mymsg->arg1 = id;
	sprintf(mymsg->mtext, "%u", recordNum);

	sendto(rconfigd_socket, &qbuf, max_send_size, 0, (struct sockaddr *)paddr, sizeof(*paddr));
	recv(rconfigd_socket, &qbuf, sizeof(qbuf), 0);
	if (qbuf.request != MSG_SUCC) {
		printf("delete chain failed\n");
		ret = 0;
	}

	return ret;
}

int mib_chain_clear_via_rconfigd(int id)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	int ret = 1;

#ifdef WLAN_SUPPORT
	id = wlan_mibchain_id_reorder(id);
	if (id == -1) {
		printf("%s: Invalid wlan_idx: %d\n", __FUNCTION__, wlan_idx);
		return 0;
	}
#endif

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_CHAIN_CLEAR;
	mymsg->arg1 = id;

	sendto(rconfigd_socket, &qbuf, max_send_size, 0, (struct sockaddr *)paddr, sizeof(*paddr));
	recv(rconfigd_socket, &qbuf, sizeof(qbuf), 0);
	if (qbuf.request != MSG_SUCC) {
		printf("clear chain failed\n");
		ret = 0;
	}

	return ret;
}

int mib_flash_to_default_via_rconfigd(CONFIG_DATA_T type)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	int ret = 1;

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_MIB_FLASH_TO_DEFAULT;
	mymsg->arg1 = (int)type;

	sendto(rconfigd_socket, &qbuf, max_send_size, 0, (struct sockaddr *)paddr, sizeof(*paddr));
	recv(rconfigd_socket, &qbuf, sizeof(qbuf), 0);
	if (qbuf.request != MSG_SUCC) {
		printf("mib reset_flash_to_default failed\n");
		ret = 0;
	}

	return ret;
}

int cmd_check_image_via_rconfigd(const char *fname, int offset)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	int ret = 1;

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_CHECK_IMAGE;
	mymsg->arg1 = offset;
	strncpy(mymsg->mtext, fname, MAX_SEND_SIZE - 1);
	mymsg->mtext[MAX_SEND_SIZE - 1] = '\0';

	sendto(rconfigd_socket, &qbuf, max_send_size, 0, (struct sockaddr *)paddr, sizeof(*paddr));
	recv(rconfigd_socket, &qbuf, sizeof(qbuf), 0);
	if (qbuf.request != MSG_SUCC) {
		printf("firmware check failed\n");
		ret = 0;
	}

	return ret;
}

int cmd_upload_via_rconfigd(const char *fname, int offset, int imgFileSize)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	int ret = 1;

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_UPLOAD;
	mymsg->arg2 = imgFileSize;
	if (imgFileSize != 0) {
		mymsg->arg1 = offset;
		strncpy(mymsg->mtext, fname, MAX_SEND_SIZE - 1);
		mymsg->mtext[MAX_SEND_SIZE - 1] = '\0';
	}

	sendto(rconfigd_socket, &qbuf, max_send_size, 0, (struct sockaddr *)paddr, sizeof(*paddr));
	recv(rconfigd_socket, &qbuf, sizeof(qbuf), 0);
	if (qbuf.request != MSG_SUCC) {
		printf("firmware upgrade failed\n");
		ret = 0;
	}

	return ret;
}


#endif

#if defined(CONFIG_USER_PPPOE_PROXY) || defined(CONFIG_USER_PPTP_CLIENT_PPTP)
int cmd_add_policy_routing_rule(int lan_unit, int wan_unit)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	int ret = 1;

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_ADD_POLICY_RULE;
	mymsg->arg1 = lan_unit;
	mymsg->arg2 = wan_unit;

	sendcmd(&qbuf);
	if (qbuf.request != MSG_SUCC) {
		printf("%s failed\n", __FUNCTION__);
		ret = 0;
	}

	return ret;
}

int cmd_del_policy_routing_rule(int lan_unit, int wan_uint)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	int ret = 1;

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_DEL_POLICY_RULE;
	mymsg->arg1 = lan_unit;
	mymsg->arg2 = wan_uint;

	sendcmd(&qbuf);
	if (qbuf.request != MSG_SUCC) {
		printf("%s failed\n", __FUNCTION__);
		ret = 0;
	}

	return ret;
}

int cmd_add_policy_routing_table(int wan_uint)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	int ret = 1;

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_ADD_POLICY_TABLE;
	mymsg->arg1 = wan_uint;

	sendcmd(&qbuf);
	if (qbuf.request != MSG_SUCC) {
		printf("%s failed\n", __FUNCTION__);
		ret = 0;
	}

	return ret;
}

int cmd_del_policy_routing_table(int wan_uint)
{
	struct mymsgbuf qbuf;
	MSG_T *mymsg;
	int ret = 1;

	mymsg = &qbuf.msg;
	mymsg->cmd = CMD_DEL_POLICY_TABLE;
	mymsg->arg1 = wan_uint;

	sendcmd(&qbuf);
	if (qbuf.request != MSG_SUCC) {
		printf("%s failed\n", __FUNCTION__);
		ret = 0;
	}

	return ret;
}
#endif
