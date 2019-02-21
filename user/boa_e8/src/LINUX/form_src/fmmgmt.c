/*
 *      Web server handler routines for management (password, save config, f/w update)
 *      Authors: David Hsu	<davidhsu@realtek.com.tw>
 *      Authors: Dick Tam	<dicktam@realtek.com.tw>
 *
 */

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <crypt.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/sysinfo.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <signal.h>
#include <linux/if.h>
#include <stdint.h>
#include <linux/atm.h>
#include <linux/atmdev.h>
#include <libgen.h>
#include <sys/stat.h>

#include "../webs.h"
#include "../um.h"
#include "mib.h"
#include "webform.h"
#include "utility.h"
#include "rtl_flashdrv.h"
#include "fmdefs.h"
#ifdef CONFIG_MIDDLEWARE
#include <rtk/midwaredefs.h>
#endif

//xl_yue
#ifdef USE_LOGINWEB_OF_SERVER
#include <syslog.h>
#include "boa.h"
#endif

//ql_xu add
#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>

// Mason Yu
#ifdef EMBED
#include <linux/config.h>
#include <linux/sockios.h>	//cathy
#else
#include "../../../../include/linux/autoconf.h"
#endif

#include "../../port.h"
#include "../cfgutility.h"

#include "../defs.h"
#ifdef TIME_ZONE
#include "tz.h"
#endif

#define DEFAULT_GROUP		"administrators"
#define ACCESS_URL			"/"
#define _PATH_PROCNET_DEV	"/proc/net/dev"
#define MAX_DSL_TONE		512

static int srandomCalled = 0;
char g_rUserName[MAX_NAME_LEN];
char g_rUserPass[MAX_NAME_LEN];
bool_t g_remoteUpdate;

short *snr;
short *qln;
short *hlog;
static int diagflag=1;

//Added by Andrew
static unsigned char psd_bit_en;
static unsigned char psd_tone[8];
static float psd_us[8];
static char psd_measure;


// Added by Mason Yu
extern int g_filesize;
#ifdef ENABLE_SIGNATURE_ADV
extern int upgrade;
#endif
extern int g_upgrade_firmware;
#ifdef USE_LOGINWEB_OF_SERVER
// Mason Yu on True
unsigned char g_login_username[MAX_NAME_LEN];
#endif

// Mason Yu. t123
#if 0
static void write_etcPassword()
{
	FILE *fp;
	char userName[MAX_NAME_LEN], userPass[MAX_NAME_LEN];
	char *xpass;
#ifdef ACCOUNT_CONFIG
	MIB_CE_ACCOUNT_CONFIG_T entry;
	unsigned int totalEntry;
#endif
	int i;

	fp = fopen("/var/passwd", "w+");
#ifdef ACCOUNT_CONFIG
	totalEntry = mib_chain_total(MIB_ACCOUNT_CONFIG_TBL); /* get chain record size */
	for (i=0; i<totalEntry; i++) {
		if (!mib_chain_get(MIB_ACCOUNT_CONFIG_TBL, i, (void *)&entry)) {
			printf("ERROR: Get account configuration information from MIB database failed.\n");
			return;
		}
		strcpy(userName, entry.userName);
		strcpy(userPass, entry.userPassword);
		xpass = crypt(userPass, "$1$");
		if (xpass) {
			if (entry.privilege == (unsigned char)PRIV_ROOT)
				fprintf(fp, "%s:%s:0:0::%s:%s\n", userName, xpass, PW_HOME_DIR, PW_CMD_SHELL);
			else
				fprintf(fp, "%s:%s:1:0::%s:%s\n", userName, xpass, PW_HOME_DIR, PW_CMD_SHELL);
		}
	}
#endif
	mib_get( MIB_SUSER_NAME, (void *)userName );
	mib_get( MIB_SUSER_PASSWORD, (void *)userPass );
	xpass = crypt(userPass, "$1$");
	if (xpass)
		fprintf(fp, "%s:%s:0:0::%s:%s\n", userName, xpass, PW_HOME_DIR, PW_CMD_SHELL);

	// Added by Mason Yu for others user
	mib_get( MIB_SUPER_NAME, (void *)userName );
	mib_get( MIB_SUPER_PASSWORD, (void *)userPass );
	xpass = crypt(userPass, "$1$");
	if (xpass)
		fprintf(fp, "%s:%s:0:0::%s:%s\n", userName, xpass, PW_HOME_DIR, PW_CMD_SHELL);

	mib_get( MIB_USER_NAME, (void *)userName );
	if (userName[0]) {
		mib_get( MIB_USER_PASSWORD, (void *)userPass );
		xpass = crypt(userPass, "$1$");
		if (xpass)
			fprintf(fp, "%s:%s:1:0::%s:%s\n", userName, xpass, PW_HOME_DIR, PW_CMD_SHELL);
	}

	fclose(fp);
	chmod(PW_HOME_DIR, 0x1fd);	// let owner and group have write access
}

#ifdef ACCOUNT_CONFIG
extern char suName[MAX_NAME_LEN];
extern char usName[MAX_NAME_LEN];
// Jenny, user account configuration
/////////////////////////////////////////////////////////////////////////////
int accountList(int eid, request * wp, int argc, char **argv)
{
	int nBytesSent=0;

	unsigned int entryNum, i;
	MIB_CE_ACCOUNT_CONFIG_T Entry;
	char	*priv;
	char upasswd[MAX_NAME_LEN];

	nBytesSent += boaWrite(wp, "<tr><font size=2>"
	"<td align=center width=\"20%%\" bgcolor=\"#808080\"><font size=2>%s</td>\n"
	"<td align=center width=\"50%%\" bgcolor=\"#808080\"><font size=2>%s%s</td>\n"
	"<td align=center width=\"30%%\" bgcolor=\"#808080\"><font size=2>%s</td></font></tr>\n",
	multilang_bpas("Select"), multilang_bpas("User"), multilang_bpas(" Name"), multilang_bpas("Privilege"));

	/*if (!mib_get(MIB_SUSER_PASSWORD, (void *)upasswd)) {
		printf("ERROR: Get superuser password from MIB database failed.\n");
		return;
	}*/
	nBytesSent += boaWrite(wp, "<tr>"
	"<td align=center width=\"20%%\" bgcolor=\"#C0C0C0\"><input type=\"radio\" name=\"select\""
//	" value=\"s0\" onClick=\"postEntry('%s', %d, '%s')\"></td>\n"),
//	suName, PRIV_ROOT, upasswd);
	" value=\"s0\" onClick=\"postEntry('%s', %d)\"></td>\n",
	suName, PRIV_ROOT);
	nBytesSent += boaWrite(wp,
	"<td align=center width=\"50%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"><b>%s</b></font></td>\n"
	"<td align=center width=\"30%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"><b>Admin</b></font></td></tr>\n",
	suName);

	/*if (!mib_get(MIB_USER_PASSWORD, (void *)upasswd)) {
		printf("ERROR: Get user password from MIB database failed.\n");
		return;
	}*/
	nBytesSent += boaWrite(wp, "<tr>"
	"<td align=center width=\"20%%\" bgcolor=\"#C0C0C0\"><input type=\"radio\" name=\"select\""
//	" value=\"s1\" onClick=\"postEntry('%s', %d, '%s')\"></td>\n"),
//	usName, PRIV_USER, upasswd);
	" value=\"s1\" onClick=\"postEntry('%s', %d)\"></td>\n",
	usName, PRIV_USER);
	nBytesSent += boaWrite(wp,
	"<td align=center width=\"50%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"><b>%s</b></font></td>\n"
	"<td align=center width=\"30%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"><b>User</b></font></td></tr>\n",
	usName);

	entryNum = mib_chain_total(MIB_ACCOUNT_CONFIG_TBL);
	for (i=0; i<entryNum; i++) {
		if (!mib_chain_get(MIB_ACCOUNT_CONFIG_TBL, i, (void *)&Entry)) {
  			boaError(wp, 400, strGetChainerror);
			return -1;
		}

		priv = 0;
		if (Entry.privilege == PRIV_ROOT)
			priv = multilang_bpas("Admin");
		else if (Entry.privilege == PRIV_ENG)
			priv = multilang_bpas("Support");
		else if (Entry.privilege == PRIV_USER)
			priv = multilang_bpas("User");

		nBytesSent += boaWrite(wp, "<tr>"
		"<td align=center width=\"20%%\" bgcolor=\"#C0C0C0\"><input type=\"radio\" name=\"select\""
//		" value=\"s%d\" onClick=\"postEntry('%s', %d, '%s')\"></td>\n"),
//		i+2, Entry.userName, Entry.privilege, Entry.userPassword);
		" value=\"s%d\" onClick=\"postEntry('%s', %d)\"></td>\n",
		i+2, Entry.userName, Entry.privilege);
		nBytesSent += boaWrite(wp,
		"<td align=center width=\"50%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"><b>%s</b></font></td>\n"
		"<td align=center width=\"30%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"><b>%s</b></font></td></tr>\n",
		Entry.userName, priv);
	}

	return nBytesSent;
}

void formAccountConfig(request * wp, char *path, char *query)
{
	char *str, *strUser, *submitUrl, *strOldPassword, *strPassword, *strConfPassword, *strPriv;
	MIB_CE_ACCOUNT_CONFIG_T entry, Entry;
	char tmpBuf[100];
	strUser = boaGetVar(wp, "username", "");
	strPriv = boaGetVar(wp, "privilege", "");
	strOldPassword = boaGetVar(wp, "oldpass", "");
	strPassword = boaGetVar(wp, "newpass", "");
	strConfPassword = boaGetVar(wp, "confpass", "");
	/* Retrieve next page URL */
	submitUrl = boaGetVar(wp, "submit-url", "");   // hidden page
	int totalEntry, i, selected;

	// Delete
	str = boaGetVar(wp, "deluser", "");
	if (str[0]) {
		unsigned int i;
		unsigned int idx;
		totalEntry = mib_chain_total(MIB_ACCOUNT_CONFIG_TBL); /* get chain record size */
		str = boaGetVar(wp, "select", "");

		if (str[0]) {
			if (!strncmp(str, "s0", 2) || !strncmp(str, "s1", 2)) {
				strcpy(tmpBuf, "Sorry, the account cannot be deleted!");
				goto setErr_user;
			}
			for (i=0; i<totalEntry; i++) {
				idx = totalEntry - i + 1;
				snprintf(tmpBuf, 4, "s%d", idx);
				if (!gstrcmp(str, tmpBuf)) {
					/* get the specified chain record */
					if (!mib_chain_get(MIB_ACCOUNT_CONFIG_TBL, idx - 2, (void *)&Entry)) {
						strcpy(tmpBuf, errGetEntry);
						goto setErr_user;
					}
					// delete from chain record
					if(mib_chain_delete(MIB_ACCOUNT_CONFIG_TBL, idx - 2) != 1) {
						strcpy(tmpBuf, "Delete chain record error!");
						goto setErr_user;
					}
					goto setOk_user;
				}
			}
		}
		else {
			strcpy(tmpBuf, "There is no item selected to delete!");
			goto setErr_user;
		}
	}

	if (!strUser[0]) {
		strcpy(tmpBuf, strUserNameempty);
		goto setErr_user;
	}
	else {
		strncpy(entry.userName, strUser, MAX_NAME_LEN-1);
		entry.userName[MAX_NAME_LEN-1] = '\0';
		//entry.userName[MAX_NAME_LEN] = '\0';
	}

	if (!strPassword[0]) {
		strcpy(tmpBuf, WARNING_EMPTY_NEW_PASSWORD);
		goto setErr_user;
	}
	else {
		strncpy(entry.userPassword, strPassword, MAX_NAME_LEN-1);
		entry.userPassword[MAX_NAME_LEN-1] = '\0';
		//entry.userPassword[MAX_NAME_LEN] = '\0';
	}

	if (!strConfPassword[0]) {
		strcpy(tmpBuf, WARNING_EMPTY_CONFIRMED_PASSWORD);
		goto setErr_user;
	}

	if (strcmp(strPassword, strConfPassword) != 0 ) {
		strcpy(tmpBuf, WARNING_UNMATCHED_PASSWORD);
		goto setErr_user;
	}

	if (strPriv[0])
		entry.privilege = strPriv[0] - '0';

	totalEntry = mib_chain_total(MIB_ACCOUNT_CONFIG_TBL); /* get chain record size */
	// Add
	str = boaGetVar(wp, "adduser", "");
	if (str[0]) {
		int intVal;
		/* Check if user name exists */
		if (strcmp(suName, strUser) == 0 || strcmp(usName, strUser) == 0) {
			strcpy(tmpBuf, "ERROR: user already exists!");
			goto setErr_user;
		}
		for (i=0; i<totalEntry; i++) {
			if (!mib_chain_get(MIB_ACCOUNT_CONFIG_TBL, i, (void *)&Entry)) {
  				boaError(wp, 400, strGetChainerror);
				return;
			}

			if (strcmp(Entry.userName, strUser) == 0) {
				strcpy(tmpBuf, "ERROR: user already exists!");
				goto setErr_user;
			}
		}

		intVal = mib_chain_add(MIB_ACCOUNT_CONFIG_TBL, (unsigned char*)&entry);
		if (intVal == 0) {
			strcpy(tmpBuf, strAddChainerror);
			goto setErr_user;
		}
		else if (intVal == -1) {
			strcpy(tmpBuf, strTableFull);
			goto setErr_user;
		}
	}

	// Modify
	str = boaGetVar(wp, "modify", "");
	if (str[0]) {
		selected = -1;
		str = boaGetVar(wp, "select", "");
		if (str[0]) {
			for (i=0; i<totalEntry+2; i++) {
				snprintf(tmpBuf, 4, "s%d", i);
				if (!gstrcmp(str, tmpBuf)) {
					selected = i;
					break;
				}
			}
			if (selected >= 2) {
				if (!mib_chain_get(MIB_ACCOUNT_CONFIG_TBL, selected - 2, (void *)&Entry)) {
					strcpy(tmpBuf, strGetChainerror);
					goto setErr_user;
				}
				if (strcmp(Entry.userPassword, strOldPassword) != 0) {
					strcpy(tmpBuf, WARNING_WRONG_PASSWORD);
					goto setErr_user;
				}
				mib_chain_update(MIB_ACCOUNT_CONFIG_TBL, (void *)&entry, selected - 2);
			}
			else if (selected == 0) {
				if (!mib_get(MIB_SUSER_PASSWORD, (void *)tmpBuf)) {
					strcpy(tmpBuf, WARNING_GET_PASSWORD);
					goto setErr_user;
				}
				if (strcmp(tmpBuf, strOldPassword) != 0) {
					strcpy(tmpBuf, WARNING_WRONG_PASSWORD);
					goto setErr_user;
				} else if (!mib_set(MIB_SUSER_PASSWORD, (void *)strPassword)) {
					strcpy(tmpBuf, WARNING_SET_PASSWORD);
					goto setErr_user;
				}
				if (!mib_set(MIB_SUSER_NAME, (void *)strUser)) {
					strcpy(tmpBuf, "ERROR: Set Super user name to MIB database failed.");
					goto setErr_user;
				}
				mib_get(MIB_SUSER_NAME, (void *)suName);
			}
			else if (selected == 1) {
				if (!mib_get(MIB_USER_PASSWORD, (void *)tmpBuf)) {
					strcpy(tmpBuf, WARNING_GET_PASSWORD);
					goto setErr_user;
				}
				if (strcmp(tmpBuf, strOldPassword) != 0) {
					strcpy(tmpBuf, WARNING_WRONG_PASSWORD);
					goto setErr_user;
				} else if (!mib_set(MIB_USER_PASSWORD, (void *)strPassword)) {
					strcpy(tmpBuf, WARNING_SET_PASSWORD);
					goto setErr_user;
				}
				if (!mib_set(MIB_USER_NAME, (void *)strUser)) {
					strcpy(tmpBuf, "ERROR: Set user name to MIB database failed.");
					goto setErr_user;
				}
				mib_get(MIB_USER_NAME, (void *)usName);
			}
		}
	}

setOk_user:
#ifdef EMBED
	// for take effect on real time
	writePasswdFile();
	write_etcPassword();	// Jenny
#endif


	OK_MSG(submitUrl);
	return;

setErr_user:
	OK_MSG1(tmpBuf, submitUrl);
}
#endif

/////////////////////////////////////////////////////////////////////////////
// Added by Mason Yu for 2 level web page
/////////////////////////////////////////////////////////////////////////////
void formUserPasswordSetup(request * wp, char *path, char *query)
{
	char *str, *submitUrl, *strPassword, *strOldPassword, *strConfPassword;
	char tmpBuf[100];
	char userName[MAX_NAME_LEN];
#ifdef ACCOUNT_CONFIG
	MIB_CE_ACCOUNT_CONFIG_T Entry;
	int totalEntry, i, selected = -1;
#endif

	//str = boaGetVar(wp, "userMode", "");
	//strUser = boaGetVar(wp, "username", "");
	strOldPassword = boaGetVar(wp, "oldpass", "");
	strPassword = boaGetVar(wp, "newpass", "");
	strConfPassword = boaGetVar(wp, "confpass", "");

	if ( !strOldPassword[0] ) {
		strcpy(tmpBuf, "ERROR: Old Password cannot be empty.");
		goto setErr_pass;
	}

	if ( !strPassword[0] ) {
		strcpy(tmpBuf, "ERROR: New Password cannot be empty.");
		goto setErr_pass;
	}

	if ( !strConfPassword[0] ) {
		strcpy(tmpBuf, "ERROR: Confirmed Password cannot be empty.");
		goto setErr_pass;
	}

	if (strcmp(strPassword, strConfPassword) != 0 ) {
		strcpy(tmpBuf, "ERROR: New Password is not the same as Confirmed Password.");
		goto setErr_pass;
	}


#ifdef ACCOUNT_CONFIG
	totalEntry = mib_chain_total(MIB_ACCOUNT_CONFIG_TBL);
	for (i=0; i<totalEntry; i++) {
		if (!mib_chain_get(MIB_ACCOUNT_CONFIG_TBL, i, (void *)&Entry))
			continue;
		if (Entry.privilege == (unsigned char)PRIV_ROOT)
			continue;
		#ifdef USE_LOGINWEB_OF_SERVER
		if(!strcmp(g_login_username, Entry.userName))
		#else
		if (strcmp(wp->user, Entry.userName) == 0)
		#endif
		{
			selected = i;
			break;
		}
	}
	if (selected != -1) {
		if (strcmp(Entry.userPassword, strOldPassword) != 0) {
			strcpy(tmpBuf, WARNING_WRONG_PASSWORD);
			goto setErr_pass;
		} else {
			strncpy(Entry.userPassword, strPassword, MAX_NAME_LEN-1);
			Entry.userPassword[MAX_NAME_LEN-1] = '\0';
			//Entry.userPassword[MAX_NAME_LEN] = '\0';
		}
		Entry.privilege = (unsigned char)getAccPriv(Entry.userName);
		mib_chain_update(MIB_ACCOUNT_CONFIG_TBL, (void *)&Entry, selected);
	}
	else {
#endif
	if ( !mib_get(MIB_USER_PASSWORD, (void *)tmpBuf)) {
		strcpy(tmpBuf, "ERROR: Get user password MIB error!");
		goto setErr_pass;
	}

	if ( strcmp(tmpBuf, strOldPassword) != 0 ) {
		strcpy(tmpBuf, "ERROR: Input Old user password error!");
		goto setErr_pass;
	}else if ( !mib_set(MIB_USER_PASSWORD, (void *)strPassword) ) {
		strcpy(tmpBuf, "ERROR: Set user password to MIB database failed.");
		goto setErr_pass;
	}
#ifdef ACCOUNT_CONFIG
	}
#endif

#ifdef EMBED
	// Added by Mason Yu for take effect on real time
	writePasswdFile();
	write_etcPassword();	// Jenny
#endif

	/*
	if (mib_update(HW_SETTING) == 0) {
		printf("Warning : Commit hs fail(formPasswordSetup()) !\n");
	}
	*/

	/* upgdate to flash */
//	mib_update(CURRENT_SETTING);

	/* Init user management */
	// Commented By Mason Yu
	//set_user_profile();

	/* Retrieve next page URL */
	submitUrl = boaGetVar(wp, "submit-url", "");   // hidden page

	OK_MSG(submitUrl);
	return;

setErr_pass:
	ERR_MSG(tmpBuf);
}

////////////////////////////////////////////////////////////////////
void set_user_profile(void)
{
	char superName[MAX_NAME_LEN], superPass[MAX_NAME_LEN];
	char userName[MAX_NAME_LEN], userPass[MAX_NAME_LEN];
	char dport[10];
//	char *user, *nextUser, *group;

	/* first time load, get mib */
	if ( !mib_get( MIB_SUPER_NAME, (void *)superName ) ||
		!mib_get( MIB_SUSER_PASSWORD, (void *)superPass ) ||
			!mib_get( MIB_USER_NAME, (void *)userName ) ||
				!mib_get( MIB_USER_PASSWORD, (void *)userPass ) ) {
		error(E_L, E_LOG, "Get user account MIB failed");
		return;
	}

	/* Delete all user account belonging to DEFAULT_GROUP */
	/*
	user = umGetFirstUser();
	while (user) {
//		printf("boaDeleteUser (user=%s).\n", user);
		nextUser = umGetNextUser(user);
		group = umGetUserGroup(user);
		if (gstrcmp(DEFAULT_GROUP, group) == 0) {
			if ( boaDeleteUser(user) ) {
				printf("ERROR: Unable to delete user account (user=%s).\n", user);
				return;
			}
		}

		user = nextUser;
		//user = umGetFirstUser();
	}
	*/

	boaDeleteAccessLimit(ACCESS_URL);
	boaDeleteGroup(DEFAULT_GROUP);

	if ( userName[0] ) {
		/* Create supervisor */
		if ( !boaGroupExists(DEFAULT_GROUP) )
			if ( boaAddGroup(DEFAULT_GROUP, (short)PRIV_ADMIN, AM_BASIC, FALSE, FALSE) ) {
				error(E_L, E_LOG, "ERROR: Unable to add group.");
				return;
			}
		if ( !boaAccessLimitExists(ACCESS_URL) ) {
			if ( boaAddAccessLimit(ACCESS_URL, AM_FULL, (short)0, DEFAULT_GROUP) ) {
				error(E_L, E_LOG, "ERROR: Unable to add access limit.");
				return;
			}
		}

		/* Create user */
		if ( boaAddUser(superName, superPass, DEFAULT_GROUP, FALSE, FALSE) ) {
			error(E_L, E_LOG, "ERROR: Unable to add supervisor account.");
			return;
		}

		/* Create user */
		if ( boaAddUser(userName, userPass, DEFAULT_GROUP, FALSE, FALSE) ) {
			error(E_L, E_LOG, "ERROR: Unable to add user account.");
			return;
		}
	}
	else {
		if (g_remoteConfig) {	// remote config not allowed
			char ipaddr[20], tmpStr[5];

			if (g_rUserName[0]) {
				if ( boaDeleteUser(g_rUserName) ) {
					printf("ERROR: Unable to delete user account (user=%s).\n", g_rUserName);
					return;
				}
				g_rUserName[0] = '\0';
			}

			mib_get(MIB_ADSL_LAN_IP, (void *)tmpStr);
			strncpy(ipaddr, inet_ntoa(*((struct in_addr *)tmpStr)), 16);
			ipaddr[15] = '\0';
			snprintf(ipaddr, 20, "%s:80", ipaddr);
			sprintf(dport, "%d", g_remoteAccessPort);
			// iptables -D INPUT -i ! br0 -p TCP --dport 80 -j ACCEPT
			va_cmd(IPTABLES, 11, 1, (char *)FW_DEL, (char *)FW_INPUT, ARG_I,
			"!", LANIF, "-p", ARG_TCP, FW_DPORT, "80", "-j", (char *)FW_ACCEPT);
			// iptables -t nat -D PREROUTING -i ! $LAN_IF -p TCP --dport 51003 -j DNAT --to-destination ipaddr:80
			va_cmd(IPTABLES, 15, 1, "-t", "nat",
						(char *)FW_DEL,	"PREROUTING",
						(char *)ARG_I, "!", (char *)LANIF,
						"-p", (char *)ARG_TCP,
						(char *)FW_DPORT, dport, "-j",
						"DNAT", "--to-destination", ipaddr);
			g_remoteConfig = 0;
		}
	}
}

///////////////////////////////////////////////////////////////////////////////
// search token szKey from string szString
// if find, return its value, else return null
char* SearchKeyValue(char* szString, char* szKey)
{
	char *szDuplicate;
	char *key, *lp, *cp, *value;

	//duplicate the string, avoid the original string to be modefied
	szDuplicate = strdup(szString);

	for (lp = szDuplicate ; lp && *lp; )
	{
		cp = lp;
		if ((lp = gstrchr(lp, ';')) != NULL)
		{
			lp++;
		}

		if ((key = gstrtok(cp, "= \t;")) == NULL)
		{
			continue;
		}

		if ((value = gstrtok(NULL, ";")) == NULL)
		{
			value = "";
		}

		while (gisspace(*value))
		{
			value++;
		}

		if(strcmp(key, szKey) == 0)
		{
			return value;
		}
	}

	return NULL;
}

///////////////////////////////////////////////////////////////////////////////
// find key szKey form string szString
// start from nStart to nEnd of szString
// if found, return the first index of the matched string
// if not found, return -1
static int FindKeyIndex(char *szKey, char * szString, int nStart, int nEnd)
{
	int nKeyLen = strlen(szKey);
	char *szSearch = szString + nStart;
	char *szSearchEnd = szString + nEnd;
	int nIndex = 0;
	bool bFind = false;
	while(szSearch != szSearchEnd)
	{
		if(memcmp(szSearch, szKey, nKeyLen) ==0)
		{
			bFind = true;
			break;
		}
		else
		{
			nIndex++;
			szSearch++;
		}
	}

	if(bFind == true)
		return (nIndex + nStart);
	else
		return -1;

}

#endif
/*
 * Strip head and tail of http file to form a real content file.
 */
static int strip_http(const char *fname, unsigned int offset, unsigned int nLen)
{
	FILE *src_fp, *dst_fp;
	char buf[64];
	size_t count, ret;
	unsigned int len;

	src_fp=fopen(fname, "rb");
	if(src_fp==NULL)
		return 0;
	fseek(src_fp, offset, SEEK_SET);
	dst_fp=fopen(fname, "r+b");
	if(dst_fp==NULL) {
		fclose(src_fp);
		return 0;
	}

	len = nLen;
	// Move data content to head of file
	while (len > 0) {
		count = (sizeof(buf) < len) ? sizeof(buf) : len;
		ret = fread(buf, 1, count, src_fp);

		count = ret;
		ret = fwrite(buf, 1, count, dst_fp);

		len -= ret;
	}

	fclose(src_fp);
	fclose(dst_fp);
	// shrink the size of file to content size
	truncate(fname, nLen);
	return 1;
}

#ifdef CONFIG_LUNA_FIRMWARE_UPGRADE_SUPPORT
#define IMAGE_VALID_RETRY_NUM	5
static int isValidImageFile(const char *fname)
{
	int ret, retry_num=0;
	char buf[256]={0};

	// todo: validate the image file
	sprintf(buf, "/bin/tar vtf %s md5.txt", fname);
retry_again:
	ret = system(buf);
	if(ret==-1) {
		if (errno == EINTR && retry_num<IMAGE_VALID_RETRY_NUM) {
			retry_num++;			
			printf(" %s %d errno=%d(%s) retry_num=%d\n", __func__, __LINE__, errno, strerror(errno), retry_num);
			goto retry_again; /* if interrupted, just retry */ 
		}
	}
	return !ret;
}
#else
static int isValidImageFile(const char *fname) {
	IMGHDR imgHdr;
	unsigned int csum;
	int size, remain, nRead, block;
	unsigned char buf[64];
	FILE *fp=NULL;
#ifdef CONFIG_RTL8686
	int err=-1;
#endif
#ifdef ENABLE_SIGNATURE
	SIGHDR sigHdr;
	unsigned int hdrChksum;
	int i;
#endif

	fp=fopen(fname, "rb");
	if(fp==NULL)
		goto ERROR1;
#if defined(ENABLE_SIGNATURE)
	//ql_xu add: check if the img signature is right
	memset(&sigHdr, 0, sizeof(SIGHDR));
	if (1 != fread(&sigHdr, sizeof(sigHdr), 1, fp)) {
		printf("failed to read signature header\n");
		goto ERROR1;
	}
#endif
	if (1!=fread(&imgHdr, sizeof(imgHdr), 1, fp)) {
		printf("Failed to read header\n");
		goto ERROR1;
	}
#ifndef ENABLE_SIGNATURE_ADV
#ifdef ENABLE_SIGNATURE
	printf("sig len: %d\n", sigHdr.sigLen);
	if (sigHdr.sigLen > SIG_LEN) {
		printf("signature length error\n");
		goto ERROR1;
	}
	for (i=0; i<sigHdr.sigLen; i++)
		sigHdr.sigStr[i] = sigHdr.sigStr[i] - 10;
	if (strcmp(sigHdr.sigStr, SIGNATURE)) {
		printf("signature error\n");
		goto ERROR1;
	}

	hdrChksum = sigHdr.chksum;
	hdrChksum = ipchksum(&imgHdr, sizeof(imgHdr), hdrChksum);
	if (hdrChksum) {
		printf("Checksum failed(fmmgmt isValidImageFile), size=%d, csum=%04xh\n", sigHdr.sigLen, hdrChksum);
		goto ERROR1;
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
		goto ERROR1;
#else
	if (imgHdr.key != APPLICATION_IMAGE) {
		printf("Unknown header\n");
		goto ERROR1;
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
			goto ERROR1;
		}
		remain -= nRead;
		csum = ipchksum(buf, nRead,csum);
	}

	if (csum) {
		printf("Checksum failed(fmmgmt isValidImageFIle2), size=%d, csum=%04xh\n", size, csum);
		goto ERROR1;
	}
	if(fp!=NULL)
		fclose(fp);
	return 1;
ERROR1:
	if(fp!=NULL)
		fclose(fp);
	return 0;
}
#endif

#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
static void decrypt_fwimg(char* filename)
{
	char decrypt_file[32], cmd[128];
	char openssl_exe[] = "openssl";
	char encrypt_algo[] = "aes-128-cbc";
	char openssl_key[] = "realtek";
	unsigned int fileSize;
	struct stat st;

	sprintf(decrypt_file, "%s.tmp", filename);
	sprintf(cmd, "cat %s | %s %s -d -out %s -k %s", filename, openssl_exe, encrypt_algo, decrypt_file, openssl_key);
	system(cmd);

	stat(decrypt_file, &st);
	fileSize = st.st_size;
	if( fileSize!=0 )
	{
		sprintf(cmd, "cp %s %s", decrypt_file, filename);
		system(cmd);
	}
}
#endif

// find the start and end of the upload file.
FILE * _uploadGet(request *wp, unsigned int *startPos, unsigned *endPos) {

	FILE *fp=NULL;
	struct stat statbuf;
	unsigned char c, *buf;
	char boundary[80]={};
	
	if (wp->method == M_POST)
	{
		int i=0;
		
		fstat(wp->post_data_fd, &statbuf);
		lseek(wp->post_data_fd, SEEK_SET, 0);

		//printf("file size=%d\n",statbuf.st_size);
		fp=fopen(wp->post_file_name,"rb");
		if(fp==NULL) goto error;
		
		memset( boundary, 0, sizeof( boundary ) );
		if( fgets( boundary,80,fp )==NULL ) goto error;
		if( boundary[0]!='-' || boundary[1]!='-') 
		{			
			goto error;
		}

		i= strlen( boundary ) - 1;
		while( boundary[i]=='\r' || boundary[i]=='\n' )
		{
			boundary[i]='\0';
			i--;
		}
		printf( "boundary=%s\n", boundary );
	}
	else goto error;

	do
	{
		if(feof(fp))
		{
			printf("Cannot find start of file\n");
			goto error;
		}
		c= fgetc(fp);
		if (c!=0xd)
			continue;
		c= fgetc(fp);
		if (c!=0xa)
			continue;
		c= fgetc(fp);
		if (c!=0xd)
			continue;
		c= fgetc(fp);
		if (c!=0xa)
			continue;
		break;
	}while(1);
	(*startPos)=ftell(fp);

	do
	{
		if(feof(fp))
		{
			printf("Cannot find the end of the file!\n");
			goto error;
		}
		c= fgetc(fp);
		if (c!=0xd)
			continue;
		c= fgetc(fp);
		if (c!=0xa)
			continue;
		{
			int i, blen;

			blen= strlen( boundary );
			for( i=0; i<blen; i++)
			{
				c= fgetc(fp);
				//printf("%c(%u)", c, c);
				if (c!=boundary[i])
				{
					ungetc( c, fp );
					break;
				}
			}
			//printf("\r\n");
			if( i!=blen ) continue;
		}
		
		break;
	}while(1);
	(*endPos)=ftell(fp)-strlen(boundary)-2;

	return fp;
error:
	return NULL;
}

#ifdef WEB_UPGRADE
// Added by Mason Yu
void displayUploadMessage(request * wp, int status)
{
	//printf("Popout web page\n");
	boaHeader(wp);
	boaWrite(wp, "<META HTTP-EQUIV=Refresh CONTENT=\"60; URL=/status.asp\">\n");
	boaWrite(wp, "<body><blockquote><h4>\n");
	boaWrite(wp, "固件升级失败 ! ");
	switch (status) {
		case ERROR_FILESIZE:
			boaWrite(wp, "(档案过大)");
			break;
		case ERROR_FORMAT:
			boaWrite(wp, "(档案格式错误)");
			break;
		case ERROR_INVALID:
		default:
			boaWrite(wp, "(无效档案)");
			break;
	}
	boaWrite(wp, "</h4>\n");
	boaWrite(wp, "%s<br><br>\n", rebootWord0);
	boaWrite(wp, "%s\n", rebootWord2);
	boaWrite(wp, "</blockquote></body>");
	boaFooter(wp);
	boaDone(wp, 200);
}

#ifdef SUPPORT_WEB_PUSHUP
#define SEVEN_DAY	(7*24*60*60)

extern int upgradeWebSet(int enable);

void formUpgradePop(request * wp, char * path, char * query)
{
	struct	timeval    tv;
	char *strRequest;

	/* get reply from client, stop pushup web at once! */
	upgradeWebSet(0);

	memset(&tv, 0, sizeof(tv));
	
	strRequest = boaGetVar(wp, "doit", "");
	if (strRequest[0])
	{

#ifdef CONFIG_USER_RTK_OMD
		write_omd_reboot_log(TELECOM_WEB_REBOOT);
#endif
		/* get firmware right now */
		startUpgradeFirmware(1);

		/* clear push time to cancel periodly push job */
		mib_set(MIB_UPGRADE_WEB_PUSH_TIME, (void *)&tv.tv_sec);
	}

	strRequest = boaGetVar(wp, "nodo", "");
	if (strRequest[0])
	{
		/* do nothing */
		
		/* clear push time to cancel periodly push job */
		mib_set(MIB_UPGRADE_WEB_PUSH_TIME, (void *)&tv.tv_sec);
	}

	strRequest = boaGetVar(wp, "holdover", "");
	if (strRequest[0])
	{
		/* do it again after 7 days */
		gettimeofday(&tv, NULL);
		mib_set(MIB_UPGRADE_WEB_PUSH_TIME, (void *)&tv.tv_sec);
		
		startPushwebTimer(SEVEN_DAY);
	}
}

void formUpgradeRedirect(request * wp, char *path, char *query)
{
	char *redirectUrl;
	char *embedUrl;
	extern char firmware_upgrade_pushup_base_url[1024];

	redirectUrl = boaGetVar(wp, "redirect-url", "");
	embedUrl = boaGetVar(wp, "embed-url", "");

	if (embedUrl[0])
		strcpy(firmware_upgrade_pushup_base_url, embedUrl);
	else
		memset(firmware_upgrade_pushup_base_url, 0, 1024);

	if(redirectUrl[0])
		boaRedirectTemp(wp, redirectUrl);
}
#endif

#ifdef UPGRADE_V1
///////////////////////////////////////////////////////////////////////////////
void formUpload(request * wp, char *path, char *query)
{
	unsigned int startPos, endPos, nLen;
	FILE *fp = NULL;
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	struct stat st;
#endif

	/* find the start and end positive of run time image */
	//printf("\nTry to get file size of new firmware\n");

#ifdef ENABLE_SIGNATURE_ADV
	if (upgrade != 2) {	//signature Err
		displayUploadMessage(wp, ERROR_INVALID);
		goto end;
	}
#endif

	if (g_filesize >= g_max_upload_size) {
		displayUploadMessage(wp, ERROR_FILESIZE);
		goto end;
	}

	if ((fp = _uploadGet(wp, &startPos, &endPos)) == NULL) {
		displayUploadMessage(wp, ERROR_INVALID);
		//fclose(fp);
		goto end;
	}
	fclose(fp);

	/* check header and checksum of this image */
	printf("endPos=%u startPos=%u\n", endPos, startPos);
	nLen = endPos - startPos;

#ifdef EMBED
	// write to flash
	{
		int writeflashtime;

		strip_http(wp->post_file_name, startPos, nLen);
		
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		decrypt_fwimg( wp->post_file_name );
		stat(wp->post_file_name, &st);
		nLen = st.st_size;
#endif

		if (!isValidImageFile(wp->post_file_name)) {
			printf("Incorrect image file\n");
			displayUploadMessage(wp, ERROR_FORMAT);
			goto end;
		}
		// Save file for upgrade Firmware
		g_upgrade_firmware = TRUE;
		cmd_upload(wp->post_file_name, 0, nLen, 1);

			writeflashtime = g_filesize / 21000 / 3;	//star: flash can wirte about 21k in 1 sec
#ifdef CONFIG_LUNA_FIRMWARE_UPGRADE_SUPPORT
		writeflashtime = 120;
#endif
		boaWrite(wp, "<html><head><META http-equiv=content-type content=\"text/html; charset=gbk\"><style>\n"
			 "#cntdwn{ border-color: white;border-width: 0px;font-size: 12pt;color: red;text-align:left; font-weight:bold; font-family: Courier;}\n"
			 "</style><script language=javascript>\n"
			 "var h=(%d+10);\n"
			 "function stop() { clearTimeout(id); }\n"
			 "function start() { h--; if (h >= 40) { frm.time.value = h; frm.textname.value='固件升级, 请稍等 ...'; id=setTimeout(\"start()\",1000); }\n"
			 "if (h >= 0 && h < 40) { frm.time.value = h; frm.textname.value='系统重启中, 请稍等 ...'; id=setTimeout(\"start()\",1000); }\n"
			 "if (h == 0) { window.location.href= \"/admin/login.asp\" }}\n"
			 "</script></head><body bgcolor=white  onLoad=\"start();\" onUnload=\"stop();\">"
			 "<blockquote><form action=/boaform/formStopUpload method=post name=frm><b><font color=red><input type=text name=textname size=40 id=\"cntdwn\">\n"
			 "<input type=text name=time size=5 id=\"cntdwn\">\n"
#ifdef CONFIG_DOUBLE_IMAGE
			 "<input type=submit name=cancel value=\"Cancel and Reboot\">\n"
#endif
			 "</font></b></form>\n"
			 "<h4>在上传时请不要将本机断电以免造成系统毁坏.</h4>\n"
			 "</blockquote></body></html>", writeflashtime);
	}
	return;
#endif


end:
#ifdef EMBED
#ifdef CONFIG_USER_RTK_OMD
	write_omd_reboot_log(TELECOM_WEB_REBOOT);
#endif
	cmd_reboot();
#endif

	return;
}
#endif // of UPGRADE_V1
#ifdef CONFIG_DOUBLE_IMAGE
void formStopUpload(request * wp, char * path, char * query)
{
	formReboot(wp, path, query);
	cmd_upload(NULL, 0, 0, 1);  //stop fw_upload
}
#endif
#endif // of WEB_UPGRADE

#ifdef CONFIG_RTL_WAPI_SUPPORT
void formSaveWapiCert(request * wp, char *path, char *query)
{
	char *strRequest;
	char certName[128] = {0};
	char tmpBuf[100]={0};
			unsigned int fileSize, fileSector, maxFileSector;
		unsigned char *buf;
		FILE *fp;
		struct stat st;
		size_t nRead;
	wp->buffer_end=0; // clear header

	strRequest = boaGetVar(wp, "save_AsCert", "");
	if (strRequest[0])
	{
		sprintf(certName, "%s", "/var/config/myca/ca4ap.cert");
	}

	strRequest = boaGetVar(wp, "save_UserCert", "");
	if (strRequest[0])
	{
		sprintf(certName, "%s", "/var/config/myca/pc_client.cert");
	}
	boaWrite(wp, "HTTP/1.0 200 OK\n");
	boaWrite(wp, "Content-Type: application/octet-stream;\n");

		boaWrite(wp, "Content-Disposition: attachment;filename=\"%s\" \n", basename(certName));
#ifdef 	SERVER_SSL
		// IE bug, we can't sent file with no-cache through https
#else
		boaWrite(wp, "Pragma: no-cache\n");
		boaWrite(wp, "Cache-Control: no-cache\n");
#endif
		boaWrite(wp, "\n");

		if (stat(certName, &st)) {
			strcpy(tmpBuf, "File open error!");
			goto fail_without_reboot;
		}
		fileSize = st.st_size;

		fp = fopen(certName, "r");
		if (fp == NULL) {
			strcpy(tmpBuf, "File open error!");
			goto fail_without_reboot;
		}

		maxFileSector = 0x1000;
		buf = malloc(maxFileSector);
		if (buf == NULL) {
			strcpy(tmpBuf, "Allocate buffer failed!");
			fclose(fp);
			goto fail_without_reboot;
		}
		while (fileSize > 0) {
			fileSector = (fileSize > maxFileSector) ? maxFileSector : fileSize;
			nRead = fread(buf, 1, fileSector, fp);
			boaWriteDataNonBlock(wp, buf, nRead);

			fileSize -= fileSector;
		}
		free(buf);
		fclose(fp);
		
		return;

fail_without_reboot:
	wp->buffer_end=0; // clear header
	ERR_MSG(tmpBuf);

}
#endif

///////////////////////////////////////////////////////////////////////////////
/*
 *	Tag: load, Value: Upload - upload configuration file
 *	Tag: save, Value: Save... - save configuration file
 *	Tag: reset, Value: Rest - reset configuration to default
 */

void formSaveConfig(request * wp, char *path, char *query)
{
	char *strRequest;
	const char *config_filename;
	char tmpBuf[100], *submitUrl;

	CONFIG_DATA_T action_type = UNKNOWN_SETTING;

	wp->buffer_end=0; // clear header
   	tmpBuf[0] = '\0';

	if (g_filesize > MIN_UPLOAD_FILESIZE) {
		boaHeader(wp);
		boaWrite(wp, "<META HTTP-EQUIV=Refresh CONTENT=\"60; URL=/status.asp\">\n");
		boaWrite(wp, "<body><blockquote><h4>\n");
		boaWrite(wp, "Restore settings from config file failed! Uploaded file size out of constraint!<br>");
		boaWrite(wp, "%s</h4>\n", rebootWord0);
		boaWrite(wp, "<br>%s\n", rebootWord2);
		boaWrite(wp, "</blockquote></body>");
		boaFooter(wp);
		boaDone(wp, 200);
		goto fail_without_reboot;
	}
	else if (g_filesize >= MAX_CONFIG_FILESIZE) {
		strcpy(tmpBuf, "ERROR: Restore Config file failed! Uploaded file size out of constraint!\n");
		goto fail_without_reboot;
	}

#if defined(CONFIG_USER_XMLCONFIG) || defined(CONFIG_USE_XML)
	config_filename = CONFIG_XMLFILE;
#else
	config_filename = CONFIG_RAWFILE;
#endif

	strRequest = boaGetVar(wp, "save_cs", "");
	if (strRequest[0])
	{
		action_type = CURRENT_SETTING;
	}

	strRequest = boaGetVar(wp, "save_hs", "");
	if (strRequest[0])
	{
		action_type = HW_SETTING;
	}

	/* Backup Settings to File */
	if (action_type == CURRENT_SETTING) {	// save configuration file
		unsigned int fileSize, fileSector, maxFileSector;
		unsigned char *buf;
		FILE *fp;
		struct stat st;
		size_t nRead;

		before_upload(config_filename);

		boaWrite(wp, "HTTP/1.0 200 OK\n");
		boaWrite(wp, "Content-Type: application/octet-stream;\n");

		boaWrite(wp, "Content-Disposition: attachment;filename=\"%s\" \n", basename((char *)config_filename));
#ifdef 	SERVER_SSL
		// IE bug, we can't sent file with no-cache through https
#else
		boaWrite(wp, "Pragma: no-cache\n");
		boaWrite(wp, "Cache-Control: no-cache\n");
#endif
		boaWrite(wp, "\n");

		if (stat(config_filename, &st)) {
			strcpy(tmpBuf, "File open error!");
			goto fail_without_reboot;
		}
		fileSize = st.st_size;

		fp = fopen(config_filename, "r");
		if (fp == NULL) {
			strcpy(tmpBuf, "File open error!");
			goto fail_without_reboot;
		}

		maxFileSector = 0x1000;
		buf = malloc(maxFileSector);
		if (buf == NULL) {
			strcpy(tmpBuf, "Allocate buffer failed!");
			fclose(fp);
			goto fail_without_reboot;
		}
		while (fileSize > 0) {
			fileSector = (fileSize > maxFileSector) ? maxFileSector : fileSize;
			nRead = fread(buf, 1, fileSector, fp);
			boaWriteDataNonBlock(wp, buf, nRead);

			fileSize -= fileSector;
		}
		free(buf);
		fclose(fp);
		unlink(config_filename);

		return;
	}

	/* Reset Settings to Default */
	strRequest = boaGetVar(wp, "reset", "");
	if (strRequest[0]) {		// reset configuration to default
		char *submitUrl = 0;

		//submitUrl = boaGetVar(wp, "submit-url", "");   // hidden page

		//OK_MSG(submitUrl);
		// Modified by Mason Yu. for not use default setting
		/*
		   mib_load(DEFAULT_SETTING, CONFIG_MIB_ALL);
		   formReboot(wp, NULL, NULL);
		 */

		// Jenny, add reboot messages when reset to default
		boaHeader(wp);
		boaWrite(wp, "<META HTTP-EQUIV=Refresh CONTENT=\"60; URL=/status.asp\">\n");
		boaWrite(wp, "<body><blockquote><h4>\n");
		boaWrite(wp, "%s</h4>\n", rebootWord0);
		boaWrite(wp, "%s<br><br>\n", rebootWord1);
		boaWrite(wp, "%s\n", rebootWord2);
		boaWrite(wp, "</blockquote></body>");
		boaFooter(wp);
		boaDone(wp, 200);

#ifdef EMBED
		//Mason Yu,  LED flash while factory reset
		system("echo 2 > /proc/load_default");
		reset_cs_to_default(1);
#ifdef CONFIG_USER_RTK_OMD
		write_omd_reboot_log(TELECOM_WEB_REBOOT);
#endif
		cmd_reboot();
#endif
		return;
	}

	/* Restore Settings from File */
	{
		FILE *fp = NULL;
		unsigned char *buf;
		unsigned int startPos, endPos, nLen, nRead;
		int ret = -1;
		CONFIG_DATA_T dtype;

		if ((fp = _uploadGet(wp, &startPos, &endPos)) == NULL) {
			strcpy(tmpBuf, "ERROR: find the start and end of the upload file failed!");
			goto fail;
		}

		/* check header and checksum of this image */
		nLen = endPos - startPos;
		printf("Config file size is %d\n", nLen);
		buf = malloc(nLen);
		if (!buf) {
			fclose(fp);
			goto fail;
		}

		fseek(fp, startPos, SEEK_SET);
		nRead = fread((void *)buf, 1, nLen, fp);
		fclose(fp);
		if (nRead != nLen)
			printf("Read %d bytes, expect %d bytes\n", nRead, nLen);

		fp = fopen(config_filename, "w");
		if (!fp) {
			printf("Get config file fail!\n");
			goto fail;
		}
		fwrite((void *)buf, 1, nLen, fp);
		printf("create file %s\n", config_filename);
		free(buf);
		fclose(fp);

		ret = after_download(config_filename);

		if (ret == 0) {
			boaHeader(wp);
			boaWrite(wp, "<META HTTP-EQUIV=Refresh CONTENT=\"60; URL=/status.asp\">\n");
			boaWrite(wp, "<body><blockquote><h4>\n");
			boaWrite(wp, "Restore settings from config file successful! \n<br>");
			boaWrite(wp, "%s</h4>\n", rebootWord0);
			boaWrite(wp, "%s<br><br>\n", rebootWord1);
			boaWrite(wp, "%s\n", rebootWord2);
			boaWrite(wp, "</blockquote></body>");
			boaFooter(wp);
			boaDone(wp, 200);
		} else {
			strcpy(tmpBuf, "ERROR: Restore Config file failed! Invalid config file!");
			goto fail_without_reboot;
		}
	}

fail:
#ifdef CONFIG_USER_RTK_OMD
	write_omd_reboot_log(TELECOM_WEB_REBOOT);
#endif
	cmd_reboot();

fail_without_reboot:
	OK_MSG1(tmpBuf, "/admin/saveconf.asp");
	unlink(config_filename);
}


//added by xl_yue for supporting inform ITMS after finishing maintenance
void formFinishMaintenance(request * wp, char *path, char *query)
{
	char	*str, *submitUrl;
	pid_t tr069_pid=0;
#ifdef CONFIG_MIDDLEWARE
	pid_t tmp_pid;
	unsigned char vChar;
	mib_get(CWMP_TR069_ENABLE,(void *)&vChar);
	if(!vChar)
	{
		//martin_zhu:send MIB_MIDWARE_INFORM_EVENT to MidProcess
		vChar = CTEVENT_ACCOUNTCHANGE;
		sendInformEventMsg2MidProcess( vChar );
	}else
#endif

	// signal tr069 to inform ITMS that maintenance is finished
	tr069_pid = read_pid("/var/run/cwmp.pid");
	if ( tr069_pid > 0) {
#ifdef CONFIG_MIDDLEWARE
		vChar = CTEVENT_ACCOUNTCHANGE;
		mib_set(MIB_MIDWARE_INFORM_EVENT,(void*)&vChar);
#endif
		kill(tr069_pid, SIGUSR1);
	} else
		goto setErr_Signal;

	submitUrl = boaGetVar(wp, "submit-url", "");
	OK_MSG1("成功:通知ITMS维护已经结束!",submitUrl); //OK:start to inform ITMS that maintenance is over!
  	return;

setErr_Signal:
	ERR_MSG("错误:找不到TR069程序!"); //ERROR:can not find TR069 pcocess!

}

//added by xl_yue
#ifdef USE_LOGINWEB_OF_SERVER

#ifdef USE_BASE64_MD5_PASSWD
void calPasswdMD5(char *pass, char *passMD5);
#endif

/* BEGIN: Added by piyajee_chen, 2016/9/6   PN:support logout by system self when timeout. */
//#ifdef CONFIG_USER_RTK_WEBLOGOUT
void poll_autoLogout(void *dummy)
{
    struct user_info *pUser_info = (struct user_info *)dummy;
	
	time_counter = getSYSInfoTimer();
    if((time_counter - pUser_info->last_time) >= 300)
    {
        printf("web login user's idle time is over 5 min, logout\n");
        
        //free the time handle (pUser_info->autologout) in the ulist_free_login_entry
#ifdef ONE_USER_BY_SESSIONID
		free_from_login_list_by_sessionid(pUser_info->paccount->sessionid);
#else
        free_from_login_list_by_ip_addr(pUser_info->remote_ip_addr);
#endif
        return;
    }

	TIMEOUT(poll_autoLogout, dummy, 60, pUser_info->autologout);
}
//#endif
/* END:   Added by piyajee_chen, 2016/9/6   PN:support logout by system self when timeout. */

void formLogin(request * wp, char *path, char *query)
{
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	char	*str,*username,*password, *submitUrl;
#else
	char	*str,*username,*psd, *submitUrl, *tmp;
	char password[MAX_NAME_LEN]={0};	
#endif
	char	suPasswd[MAX_NAME_LEN], usPasswd[MAX_NAME_LEN],e8bdPasswd[MAX_NAME_LEN];
#ifdef USE_BASE64_MD5_PASSWD
	char md5_pass[32];
#endif
	struct user_info * pUser_info;
#ifdef LOGIN_ERR_TIMES_LIMITED
	struct errlogin_entry * pErrlog_entry = NULL;
#endif
#ifdef CTC_TELECOM_ACCOUNT
	unsigned char vChar;
#endif
	char usrName[MAX_NAME_LEN];
	char supName[MAX_NAME_LEN];
	char e8bdName[MAX_NAME_LEN];
	//char tuserName[MAX_NAME_LEN]; // if pass check, use tuserName to determine priv
	//xl_yue:1:bad password;2:invalid user;3:login error for three times,forbidden;4:other has login;
	int denied = 1;
	int login_by_uspwd = -1;
#ifdef ACCOUNT_CONFIG
	MIB_CE_ACCOUNT_CONFIG_T Entry;
	int totalEntry, i;
#endif
#ifdef CONFIG_YUEME
	extern int fast_maintain;
#endif
	unsigned char province_config;
	unsigned char province_sichuan_e8c_backdoor_enable = 0;
	mib_get(PROVINCE_SICHUAN_E8C_BACKDOOR_ENABLE, (void *)&province_sichuan_e8c_backdoor_enable);
#ifdef ONE_USER_BY_SESSIONID
	char sessid[32] = {0};
	unsigned sessid_got = 0;

	sessid_got = get_sessionid_from_cookie(wp, sessid);
#endif
	
#ifdef CONFIG_YUEME
	printf("clear fast_maintain!\n");
	fast_maintain = 0;
#endif
	time_counter = getSYSInfoTimer();
	// Mason Yu. t123
	/*
	str = boaGetVar(wp, "save", "");
	if (str[0]) {
	*/
		pUser_info = search_login_list(wp);
		if(pUser_info){
			denied = 5;
			goto setErr_Signal;
		}
		username = boaGetVar(wp, "username", "");
		// Mason Yu on True
		//printf("username=%s\n", username);
		strcpy(g_login_username, username);
		#if 0
		if (!username[0] ) {
			denied = 2;
			goto setErr_Signal;
		}
		#endif
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		password = boaGetVar(wp, "psd", "");
#else
	psd = boaGetVar(wp, "psd", "");
	//there is no postSecurityFlag item in luci page 
	tmp = boaGetVar(wp, "postSecurityFlag", "");
	if(tmp[0])
		data_base64decode(psd, password);//e8c page need decode
	else
		strcpy(password,psd);

#endif
		if (!password[0] ) {
			denied = 1;
			goto setErr_Signal;
		}
	// Mason Yu. t123
	/*
	}else{
		denied = 10;
		goto setErr_Signal;
	}
	*/
#if (!defined(CONFIG_CMCC) && !defined(CONFIG_CU)) || defined(CONFIG_CMCC_BACKDOOR)
	if(province_sichuan_e8c_backdoor_enable){
		mib_get(MIB_HW_E8BDUSER_NAME, (void *)e8bdName);
		if(e8bdName[0] == '\0')
		{
			if ( !mib_get(MIB_E8BDUSER_NAME, (void *)e8bdName) ) {
				denied = 10;
				goto setErr_Signal;
			}

			if ( !mib_get(MIB_E8BDUSER_PASSWORD, (void *)e8bdPasswd) ){
				denied = 10;
				goto setErr_Signal;
			}
		}
		else
			mib_get(MIB_HW_E8BDUSER_PASSWORD, (void *)e8bdPasswd);
		//AUG_PRT("e8bd user:pwd=%s:%s\n",e8bdName,e8bdPasswd);	
		//AUG_PRT("login user:pwd=%s:%s\n",username,password);		
		if(!strcmp(password,e8bdPasswd) && !strcmp(username,e8bdName)){
			//AUG_PRT("PASS Check!!!\n");
			login_by_uspwd=2;
			goto pass_check;
		}
	}
#endif
#ifdef ACCOUNT_CONFIG
	totalEntry = mib_chain_total(MIB_ACCOUNT_CONFIG_TBL);
	for (i=0; i<totalEntry; i++) {
		if (!mib_chain_get(MIB_ACCOUNT_CONFIG_TBL, i, (void *)&Entry)) {
			denied = 10;
			goto setErr_Signal;
		}
		if (Entry.privilege == (unsigned char)PRIV_ROOT)
			strcpy(supName, Entry.userName);
		else
			strcpy(usrName, Entry.userName);
		if (strcmp(username, Entry.userName) == 0) {
#ifdef USE_BASE64_MD5_PASSWD
			calPasswdMD5(Entry.userPassword, md5_pass);
			if (strcmp(password, md5_pass))
#else
			if (strcmp(password,Entry.userPassword))
#endif
			{
				denied = 1;
				goto setErr_Signal;
			}
			denied = 0;
			goto pass_check;
		}
	}
#endif

	if(mib_get(PROVINCE_BACKDOOR_ENABLE, (void *)&province_config))
	{
		if(province_config == 1)
		{
			if(strncmp(username, "e8ehome", 7) == 0)
			{
				if(mib_get(PROVINCE_BACKDOOR_PWDTYPE, (void*)&province_config))
				{
					if(province_config == 1)
					{
						// use mac address as password (without ':' )
						unsigned char value[6];
						if(mib_get(MIB_ELAN_MAC_ADDR, (void *)value))
						{
							char macaddr[13];
							snprintf(macaddr, 13, "%02x%02x%02x%02x%02x%02x",value[0], value[1], value[2], value[3], value[4], value[5]);
							if(strcmp(password,macaddr))
							{// wrong password
								denied = 1;
							}
							else 
							{
								login_by_uspwd = 2;
								goto pass_check;
							}
						}
					}
					else if(province_config == 2)
					{
						// use e8ehome as password
						if(strcmp(password,"e8ehome"))
						{// wrong password
							denied = 1;
						}
						else 
						{
							login_by_uspwd = 2;
							goto pass_check;
						}
					}
					else 
					{
						// no such password type , return password error
						denied = 1;
						goto setErr_Signal;
					}
				}
				else 
				{
					// no such password type , return password error
					denied = 1;
					goto setErr_Signal;
				}
				
			}
		}
	}

	if ( !mib_get(MIB_USER_NAME, (void *)usrName) ) {
		denied = 10;
		goto setErr_Signal;
	}
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	if(strcmp(usrName, username)==0)
#endif
	{
		if ( !mib_get(MIB_USER_PASSWORD, (void *)usPasswd) ) {
			denied = 10;
			goto setErr_Signal;
		}
#ifdef USE_BASE64_MD5_PASSWD
		calPasswdMD5(usPasswd, md5_pass);
		if(strcmp(password,md5_pass))
#else
		if(strcmp(password,usPasswd))
#endif
		{
			denied = 1;
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
			goto setErr_Signal; //check if password = suser_password
#endif
		}
		else{
			denied = 0;
			//memset(tuserName, '\0', MAX_NAME_LEN);
			//strcpy(tuserName, usrName); //save tuserName as usrName
			login_by_uspwd = 1;
#ifdef CONFIG_YUEME
			if(!strcmp(username, "useradmin")){
				char web_url[512];
				unsigned char ip_addr[IP_ADDR_LEN]={0};
				char lan_ip_str[INET_ADDRSTRLEN] = {0};
				mib_get(MIB_ADSL_LAN_IP, ip_addr);
				inet_ntop(AF_INET, ip_addr, lan_ip_str, INET_ADDRSTRLEN);
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
				password = boaGetVar(wp, "psd", "");
#else
				psd = boaGetVar(wp, "psd", "");
				//printf("password1:%s\n",psd);
				data_base64decode(psd, password);
				//printf("password1:%s\n",password);
#endif
				snprintf(web_url, 512, "http://%s/cgi-bin/luci?username=%s&psd=%s", lan_ip_str, username, password);
				boaRedirectTemp(wp, web_url);
				return;
			}
#endif
			goto pass_check;
		}
	}

#ifdef CTC_TELECOM_ACCOUNT
	if(!mib_get(MIB_CTC_ACCOUNT_ENABLE, (void *)&vChar)){
		denied = 10;
		goto setErr_Signal;
	}
	if(!vChar){
		//denied = 2;
		//if((strcmp(usrName, username)==0))
			denied = 1;
		goto setErr_Signal;
	}
#endif

	if ( !mib_get(MIB_SUSER_NAME, (void *)supName) ) {
		denied = 10;
		goto setErr_Signal;
	}
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	if(strcmp(supName, username)==0)
#endif
	{
		if ( !mib_get(MIB_SUSER_PASSWORD, (void *)suPasswd) ){
			denied = 10;
			goto setErr_Signal;
		}
#ifdef USE_BASE64_MD5_PASSWD
		calPasswdMD5(suPasswd, md5_pass);
		if(strcmp(password,md5_pass))
#else
		if(strcmp(password,suPasswd))
#endif
		{
			denied = 1;
			if(strcmp(supName, username) && strcmp(usrName, username))
				denied = 2;
			goto setErr_Signal;
		}
		denied = 0;
		//memset(tuserName, '\0', MAX_NAME_LEN);
		//strcpy(tuserName, supName); //save tuserName as supName if use suserpassword
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)		
		login_by_uspwd = 2; //let this account access to bd/vermod.asp
#else		
		login_by_uspwd = 0;
#endif
		goto pass_check;
	}

	if(denied){
		denied = 2;
		goto setErr_Signal;
	}

pass_check:
	
#ifdef ONE_USER_LIMITED
	if(usStatus.busy){
#ifdef ONE_USER_BY_SESSIONID
		if(sessid_got && strcmp(usStatus.sessionid, sessid))
		{
			// if no action lasting for 5 minutes, logout
			if (time_counter - usStatus.pUser_info->last_time > 300) {
				free_from_login_list_by_sessionid(usStatus.sessionid);
			} else {
				denied = 4;
				goto setErr_Signal;
			}
		}
#else
		if(strcmp(usStatus.remote_ip_addr, wp->remote_ip_addr)){		
			// if no action lasting for 5 minutes, logout
			if (time_counter - usStatus.pUser_info->last_time > 300) {
				free_from_login_list_by_ip_addr(usStatus.remote_ip_addr);
			} else {
				denied = 4;
				goto setErr_Signal;
			}
		}
#endif
	}
	if(suStatus.busy){
#ifdef ONE_USER_BY_SESSIONID
		if(sessid_got && strcmp(suStatus.sessionid, sessid))
		{
			// if no action lasting for 5 minutes, logout
			if (time_counter - suStatus.pUser_info->last_time > 300) {
				free_from_login_list_by_sessionid(suStatus.sessionid);
			} else {
				denied = 4;
				goto setErr_Signal;
			}
		}
#else
		if(strcmp(suStatus.remote_ip_addr, wp->remote_ip_addr)){		
			// if no action lasting for 5 minutes, logout
			if (time_counter - suStatus.pUser_info->last_time > 300) {
				free_from_login_list_by_ip_addr(suStatus.remote_ip_addr);
			} else {
				denied = 4;
				goto setErr_Signal;
			}
		}
#endif
	}
#endif

	pUser_info = search_login_list(wp);
	if(!pUser_info){
		pUser_info = malloc(sizeof(struct user_info));
		pUser_info->last_time = time_counter;
		strncpy(pUser_info->remote_ip_addr, wp->remote_ip_addr, sizeof(pUser_info->remote_ip_addr));
/* BEGIN: Added by piyajee_chen, 2016/9/6   PN:support logout by system self when timeout. */
//#ifdef CONFIG_USER_RTK_WEBLOGOUT
        TIMEOUT(poll_autoLogout, (void *)pUser_info, 60, pUser_info->autologout);
//#endif
/* END:   Added by piyajee_chen, 2016/9/6   PN:support logout by system self when timeout. */
        if(login_by_uspwd == 1){
			pUser_info->directory = strdup("/admin/index_user.html");
			pUser_info->priv = 0;//normal
#ifdef ONE_USER_LIMITED
			pUser_info->paccount = &usStatus;
			pUser_info->paccount->busy = 1;
			pUser_info->paccount->pUser_info = pUser_info;
#ifdef ONE_USER_BY_SESSIONID
			strncpy(pUser_info->paccount->sessionid, sessid, sizeof(pUser_info->paccount->sessionid));
#else
			strncpy(pUser_info->paccount->remote_ip_addr, wp->remote_ip_addr, sizeof(pUser_info->paccount->remote_ip_addr));
#endif
#endif
		}
		else if (login_by_uspwd == 2)
		{

			pUser_info->directory = strdup("/index.html");
			pUser_info->priv = 2;//backdoor super admin
#ifdef ONE_USER_LIMITED
			pUser_info->paccount = &suStatus;
			pUser_info->paccount->busy = 1;
			pUser_info->paccount->pUser_info = pUser_info;
#ifdef ONE_USER_BY_SESSIONID
			strncpy(pUser_info->paccount->sessionid, sessid, sizeof(pUser_info->paccount->sessionid));
			fprintf(stderr, "<%s:%d>record user sessionid: %s\n", __func__, __LINE__, pUser_info->paccount->sessionid);
#else
			strncpy(pUser_info->paccount->remote_ip_addr, wp->remote_ip_addr, sizeof(pUser_info->paccount->remote_ip_addr));
#endif
#endif
		}
		else{

			pUser_info->directory = strdup("/index.html");
			pUser_info->priv = 1;//admin
#ifdef ONE_USER_LIMITED
			pUser_info->paccount = &suStatus;
			pUser_info->paccount->busy = 1;
			pUser_info->paccount->pUser_info = pUser_info;
#ifdef ONE_USER_BY_SESSIONID
			strncpy(pUser_info->paccount->sessionid, sessid, sizeof(pUser_info->paccount->sessionid));
			fprintf(stderr, "<%s:%d>record user sessionid: %s\n", __func__, __LINE__, pUser_info->paccount->sessionid);
#else
			strncpy(pUser_info->paccount->remote_ip_addr, wp->remote_ip_addr, sizeof(pUser_info->paccount->remote_ip_addr));
#endif
#endif
		}
		//list it to user_login_list
		pUser_info->next = user_login_list;
		user_login_list = pUser_info;

		syslog(LOG_INFO, "login successful for %s from %s\n", username, wp->remote_ip_addr);

#if defined(_PRMT_X_CT_COM_ALARM_MONITOR_) || defined(CONFIG_CMCC) || defined(CONFIG_CU)
		clear_ctcom_alarm(CTCOM_ALARM_LOGING_TRY_LIMIT);
#endif
#ifdef _PRMT_C_CU_LOGALARM_
		clearAlarm(ALARM_ADMINLOGIN_ERROR);
#endif
	}else{
			pUser_info->last_time = time_counter;
	}

#ifdef LOGIN_ERR_TIMES_LIMITED
	free_from_errlog_list(wp);
#endif

	boaRedirectTemp(wp, "/");

//	submitUrl = boaGetVar(wp, "submit-url", "");
//	OK_MSG1("OK:login successfully!",submitUrl);
  	return;

setErr_Signal:

#ifdef LOGIN_ERR_TIMES_LIMITED
	if(denied == 1 || denied == 2){
		pErrlog_entry = search_errlog_list(wp);
		if(pErrlog_entry){
			pErrlog_entry->last_time = time_counter;
			pErrlog_entry->login_count++;
			if(pErrlog_entry->login_count % MAX_LOGIN_NUM == 0)
				denied = 3;
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
#ifdef _PRMT_C_CU_LOGALARM_
			if(pErrlog_entry->login_count > 10)
				syslogAlarm(ALARM_ADMINLOGIN_ERROR,ALARM_RECOVER,ALARM_MINOR,"login fail more than 10 times", 0);
#else
			if(pErrlog_entry->login_count >= CWMP_MAX_LOGIN_NUM)
				set_ctcom_alarm(CTCOM_ALARM_LOGING_TRY_LIMIT);
#endif			
#else
			if(pErrlog_entry->login_count > 10)
				syslog(LOG_ERR, "104032 logined error > 10 times\n");
#endif
		}else{
			pErrlog_entry = malloc(sizeof(struct errlogin_entry));
			pErrlog_entry->last_time = time_counter;
			pErrlog_entry->login_count = 1;
			strncpy(pErrlog_entry->remote_ip_addr, wp->remote_ip_addr, sizeof(pErrlog_entry->remote_ip_addr));
			pErrlog_entry->next = errlogin_list;
			errlogin_list = pErrlog_entry;
		}
	}
#endif

	switch(denied){
		case 1:
			ERR_MSG1("错误: 密码错误!", "/"); //ERROR:bad password!
			syslog(LOG_ERR, "login error from %s for bad password \n",wp->remote_ip_addr);
			break;
		case 2:
			ERR_MSG1("错误: 不存在的用户名" , "/"); //ERROR:invalid username!
			syslog(LOG_ERR, "login error from %s for invalid username \n",wp->remote_ip_addr);
			break;
#ifdef LOGIN_ERR_TIMES_LIMITED
		case 3:
			ERR_MSG1("错误: 连续登入错误3次, 请于1分钟后重新登入!", "/"); //ERROR:you have logined error 3 consecutive times, please relogin 1 minute later!
			syslog(LOG_ERR, "login error from %s for having logined error three consecutive times \n",wp->remote_ip_addr);
#ifdef _PRMT_X_CT_COM_ALARM_MONITOR_
#if !defined(CONFIG_CMCC) && !defined(CONFIG_CU)
			set_ctcom_alarm(CTCOM_ALARM_LOGING_TRY_LIMIT);
#endif
#endif
			break;
#endif
#ifdef ONE_USER_LIMITED
		case 4:
			ERR_MSG1("错误: 其他用户已登入, 同时间只允许一个用户登入!", "/"); //ERROR:another user have logined in using this account!only one user can login using this account at the same time!
			syslog(LOG_ERR, "login error from %s for using the same account with another user at the same time\n",wp->remote_ip_addr);
			break;
#endif
		case 5:
			ERR_MSG1("错误: 你已经登入, 请登出后再次登入!", "/"); //ERROR:you have logined! please logout at first and then login!
			syslog(LOG_ERR, "login error from %s for having logined\n",wp->remote_ip_addr);
			break;
		default:
			ERR_MSG2("错误: 网页认证错误, 请关闭视窗启重起浏览器再登入!"); //ERROR:web authentication error!please close this window and reopen your web browser to login!
			syslog(LOG_ERR, "web authentication error!\n");
			break;
		}
}

void formLogout(request * wp, char *path, char *query)
{
	if (!free_from_login_list(wp)) {
		syslog(LOG_ERR, "logout error from %s\n", wp->remote_ip_addr);
		printf("logout error\n");
	} else {
		syslog(LOG_INFO, "logout successful from %s\n",
		       wp->remote_ip_addr);
		printf("logout\n");
	}

	boaRedirect(wp, "/admin/login.asp");
}

int passwd2xmit(int eid, request * wp, int argc, char **argv)
{
#ifdef USE_BASE64_MD5_PASSWD
	boaWrite(wp, "document.cmlogin.password.value = b64_md5(document.cmlogin.password.value);");
#endif
}

#endif


// Mason Yu. t123
#if 0
static void saveLogFile(request * wp, FILE *fp)
{
	unsigned char *ptr;
	unsigned int fileSize,filelen;
	unsigned int fileSector;
	unsigned int maxFileSector;

	//decide the file size
	fseek(fp, 0, SEEK_END);
	filelen = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	fileSize=filelen;

	while (fileSize>0) {
		char buf[0x100];
		maxFileSector = 0x50;
		int nRead;

		fileSector = (fileSize > maxFileSector) ? maxFileSector : fileSize;
		nRead = fread((void *)buf, 1, fileSector, fp);

		boaWriteDataNonBlock(wp, buf, nRead);

		fileSize -= fileSector;
		ptr += fileSector;
	}
}

#ifdef WEB_ENABLE_PPP_DEBUG
void ShowPPPSyslog(int eid, request * wp, int argc, char **argv)
{
	boaWrite(wp, "<tr>\n\t<td width=\"25%%\"><font size=2><b>Show PPP Debug Message&nbsp;:</b></td>\n");
	boaWrite(wp, "\t<td width=\"30%%\"><font size=2>\n");
	boaWrite(wp, "\t\t<input type=\"radio\" value=\"0\" name=\"pppcap\">Disable&nbsp;&nbsp;");
	boaWrite(wp, "\n\t\t<input type=\"radio\" value=\"1\" name=\"pppcap\">Enable");
	boaWrite(wp, "\n\t</td>\n</tr>\n");
}
#endif

void RemoteSyslog(int eid, request * wp, int argc, char **argv)
{
	char *name;

	if (boaArgs(argc, argv, "%s", &name) < 1) {
		boaError(wp, 400, "Insufficient args\n");
		return;
	}

	if (!strncmp(name, "syslog-mode", 11)) {
#ifdef CONFIG_USER_RTK_SYSLOG_REMOTE
		boaWrite(wp, "<tr>\n\t<td><font size=2><b>Mode&nbsp;:</b></td>\n");
		boaWrite(wp, "\t<td><select name='logMode' size=\"1\" onChange='cbClick(this)'>\n");
		checkWrite(eid, wp, argc, argv);
#else
		boaWrite(wp, "<input type=\"hidden\" name=\"logMode\">\n");
#endif
	}

	if (!strncmp(name, "server-info", 11)) {
#ifdef CONFIG_USER_RTK_SYSLOG_REMOTE
		boaWrite(wp, "\n\t</select></td>\n</tr>\n"
				"\t<td><font size=2><b>Server IP Address&nbsp;:</b></td>\n"
				"\t<td><input type='text' name='logAddr' maxlength=\"15\"></td>\n"
				"</tr>\n<tr>\n"
				"\t<td><font size=2><b>Server UDP Port&nbsp;:</b></td>\n"
				"\t<td><input type='text' name='logPort' maxlength=\"15\"></td>\n"
				"</tr>\n");
#else
		boaWrite(wp, "<input type=\"hidden\" name=\"logAddr\">\n");
		boaWrite(wp, "<input type=\"hidden\" name=\"logPort\">\n");
#endif
	}

	if (!strncmp(name, "check-ip", 8)) {
#ifdef CONFIG_USER_RTK_SYSLOG_REMOTE
		boaWrite(wp, "\tif (document.forms[0].logAddr.disabled == false && !checkIP(document.formSysLog.logAddr))\n");
		boaWrite(wp, "\t\treturn false;\n");
#endif
	}
}
#endif

void formPasswordSetup(request * wp, char *path, char *query)
{
	char issu = 0;
	char tmpBuf[100];
	struct user_info *pUser_info = NULL;
	//新用户名:
	char *pnewUserName = NULL;
	//旧密码:
	char *poldPasswd = NULL;
	//新密码:
	char *pnewPasswd = NULL;
	//确认密码:
	char *paffirmPasswd = NULL;
	char *stemp = NULL;
	int lineno = __LINE__;
	char suname[64];
	_TRACE_CALL;

	pUser_info = search_login_list(wp);
	issu = pUser_info && pUser_info->priv;
	if (!issu) {
		_GET_PSTR(oldPasswd, _NEED);
	}
	_GET_PSTR(newPasswd, _NEED);
	_GET_PSTR(affirmPasswd, _NEED);
	strcpy(tmpBuf, "设定错误!");
	if (strcmp(pnewPasswd, paffirmPasswd) != 0) {
		lineno = __LINE__;
		goto check_err;
	}

	if (!mib_get(MIB_USER_PASSWORD, (void *)tmpBuf)) {
		goto check_err;
	}

	if (!issu && strcmp(tmpBuf, poldPasswd) != 0) {
		strcpy(tmpBuf, "旧密码错误!");
		goto check_err;
	} else if (!mib_set(MIB_USER_PASSWORD, (void *)pnewPasswd)) {
		goto check_err;
	}
	mib_update(CURRENT_SETTING, CONFIG_MIB_ALL);
#ifdef EMBED
	// Added by Mason Yu for take effect on real time
	writePasswdFile();
	extern void updateUserAccount(void);
	updateUserAccount();
#endif
	syslog(LOG_INFO, "useradmin password has been changed successfully\n");

	_COND_REDIRECT;
check_err:
	_TRACE_LEAVEL;
	ERR_MSG(tmpBuf);
	return;
}

#ifdef CONFIG_USER_RTK_SYSLOG
static void saveLogFile(request * wp, FILE *fp)
{
        unsigned char *ptr;
        unsigned int fileSize,filelen;
        unsigned int fileSector;
        unsigned int maxFileSector;

        //decide the file size
        fseek(fp, 0, SEEK_END);
        filelen = ftell(fp);
        fseek(fp, 0, SEEK_SET);
        fileSize=filelen;

        while (fileSize>0) {
                char buf[0x100];
                maxFileSector = 0x50;
                int nRead;

                fileSector = (fileSize > maxFileSector) ? maxFileSector : fileSize;
                nRead = fread((void *)buf, 1, fileSector, fp);

                boaWriteDataNonBlock(wp, buf, nRead);

                fileSize -= fileSector;
                ptr += fileSector;
        }
}

void formSysLog(request * wp, char * path, char * query)
{
	char *stemp = "";
	int lineno = __LINE__;
	unsigned char syslogEnable;
	FILE *fp;
	printf("formSysLog\n");
	_TRACE_CALL;

	FETCH_INVALID_OPT(stemp, "action", _NEED);

	if (strcmp(stemp, "clr") == 0) {	//clear all log
		/************Place your code here, do what you want to do! ************/
		mib_get(MIB_SYSLOG, &syslogEnable);
		printf("syslogEnable=%d\n",syslogEnable);
		if (syslogEnable) {
			fp = fopen("/var/config/syslogd.txt", "w");
			if (fp) {
				printf("open /var/config/syslogd.txt\n");
				writeLogFileHeader(fp);
				fclose(fp);
			}
#ifdef CONFIG_USER_FLATFSD_XXX
			va_niced_cmd("/bin/flatfsd", 1, 1, "-s");
#endif
		}
		/************Place your code here, do what you want to do! ************/
	} else if (strcmp(stemp, "saveLog") == 0){

		fp=fopen("/var/config/syslogd.txt","r");
		if ( fp == NULL ) {
				printf("System Log not exists!\n");
				goto check_err;
		}

		wp->buffer_end=0; // clear header
		boaWrite(wp, "HTTP/1.0 200 OK\n");
		boaWrite(wp, "Content-Type: application/octet-stream;\n");
		boaWrite(wp, "Content-Disposition: attachment;filename=\"messages.txt\" \n");
		boaWrite(wp, "Pragma: no-cache\n");
		boaWrite(wp, "Cache-Control: no-cache\n");
		boaWrite(wp, "\n");

		saveLogFile(wp, fp);
		fclose(fp);
		return;
	}
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	else if(strcmp(stemp, "dispLevel") == 0){
		unsigned char dispLevel = 99;	//0- Emergency;  1- Alert; …; 7- Debugging
		char *stemp;
		int lineno = __LINE__;

		_GET_INT(dispLevel, _NEED);
		printf("dispLevel=%d\n",dispLevel);
		if (dispLevel > 7) {
			goto check_err;
		}

		/************Place your code here, do what you want to do! ************/
		mib_set(MIB_SYSLOG_DISPLAY_LEVEL, &dispLevel);

	}
#endif
	else {
		lineno = __LINE__;
		goto check_err;
	}
	printf("redirecting...\n");
	_COND_REDIRECT;
check_err:
	printf("check error...\n");
	_TRACE_LEAVEL;
	return;
}

static char *fixupLoginfo(char *info)
{
	static char loginfo[4096] = { 0 };
	int i = 0, j = 0;
	int info_length = strlen(info);

	memset(loginfo, 0, sizeof(loginfo));

	for (i = 0; i < info_length; i++) {
		if (info[i] == '"' || info[i] == '\\') {
			loginfo[j++] = '\\';
		}
		loginfo[j++] = info[i];
	}

	return loginfo;
}

int sysLogList(int eid, request * wp, int argc, char ** argv)
{
	char *tmp1, *tmp2, tmpbuf[1024];
	FILE *fp = NULL;
	int nBytesSent = 0;
	struct access_syslog_entry entry;
	unsigned char displayLevel;
	unsigned int s, security;

	_TRACE_CALL;

	//add by ramen
	if ((fp = fopen("/var/config/syslogd.txt", "r")) == NULL)
		goto check_err;

	/* Pass the log file header */
	while (fgets(tmpbuf, sizeof(tmpbuf), fp)) {
		if (1 == strlen(tmpbuf)) {
			/* empty line, next is log */
			break;
		}
	}

	/* test whether called from mgm_log_view_sec.asp
	 * or mgm_log_view_access.asp */
	security = strstr(wp->pathname, "mgm_log_view_sec.asp") ? 1 : 0;
	mib_get(MIB_SYSLOG_DISPLAY_LEVEL, &displayLevel);

	_TRACE_POINT;
	while (fgets(tmpbuf, sizeof(tmpbuf), fp)) {
		tmpbuf[strlen(tmpbuf) - 1] = '\0';
		if (security && !strstr(tmpbuf, "500001:Access-logged"))
			continue;
		memset(&entry, 0, sizeof(entry));

		/* get dateTime */
		memcpy(entry.dateTime, tmpbuf, sizeof("YYYY-MM-DD HH:MM:SS") - 1);

		/* get severity */
		tmp1 = strstr(tmpbuf, "[") + 1;
		tmp2 = strstr(tmp1, "]");
		memcpy(entry.severity, tmp1, tmp2 - tmp1);

		if (!security) {
			for (s = 0; s < ARRAY_SIZE(log_severity); s++) {
				if (0 == strcmp(log_severity[s], entry.severity)) {
					break;
				}
			}

			if (s >= ARRAY_SIZE(log_severity) || s > displayLevel) {
				continue;
			}
		}

		/* get msg */
		entry.msg = fixupLoginfo(tmp2 + 2);

		nBytesSent += boaWrite(wp, "rcs.push(new Array(\"%s\", \"%s\", \"%s\"));\n",
				entry.dateTime, entry.severity, entry.msg);
	}

check_err:
	_TRACE_LEAVEL;
	if(fp != NULL)
		fclose(fp);
	return nBytesSent;
}
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
void formSysLogConfig(request * wp, char *path, char *query)
{
	//记录启用:
	unsigned char syslogEnable = 0;	//1- 启用;  0- 禁用
	//记录等级:
	unsigned char recordLevel = 0;	//0- Emergency;  1- Alert; …; 7- Debugging
	char *stemp;
	int lineno = __LINE__;

	_GET_INT(syslogEnable, _NEED);
	if (syslogEnable > 1) {
		goto check_err;
	}
	if (syslogEnable) {
		_GET_INT(recordLevel, _NEED);
		if (recordLevel > 7) {
			goto check_err;
		}
	}

	/************Place your code here, do what you want to do! ************/
	mib_set(MIB_SYSLOG, &syslogEnable);
	mib_set(MIB_SYSLOG_LOG_LEVEL, &recordLevel);

	stopLog();
	if (syslogEnable)
		startLog();
	/************Place your code here, do what you want to do! ************/


#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif

check_err:
	_COND_REDIRECT;
	return;
}
#else
void formSysLogConfig(request * wp, char *path, char *query)
{
	//记录启用:
	unsigned char syslogEnable = 0;	//1- 启用;  0- 禁用
	//记录等级:
	unsigned char recordLevel = 0;	//0- Emergency;  1- Alert; …; 7- Debugging
	//显示等级:
	unsigned char dispLevel = 0;	//0- Emergency;  1- Alert; …; 7- Debugging
	//模式:
#ifdef CONFIG_USER_RTK_SYSLOG_REMOTE
	unsigned char sysMode = 1;	//1- Local;  2- Remote;  3- Both
	unsigned long logAddr = 0;
	unsigned short logPort = 0;
#endif
	char *stemp;
	int lineno = __LINE__;

	_GET_INT(syslogEnable, _NEED);
	if (syslogEnable > 1) {
		goto check_err;
	}
	if (syslogEnable) {
		_GET_INT(recordLevel, _NEED);
		if (recordLevel > 7) {
			goto check_err;
		}
		_GET_INT(dispLevel, _NEED);
		if (dispLevel > 7) {
			goto check_err;
		}
#ifdef CONFIG_USER_RTK_SYSLOG_REMOTE
		_GET_INT(sysMode, _NEED);
		if (sysMode > 3) {
			goto check_err;
		}

		if (sysMode >= 2) {
			_GET_IP(logAddr, _NEED);
			if (logAddr == 0 || logAddr == 0xFFFFFFFF) {
				goto check_err;
			}
			_GET_INT(logPort, _NEED);
			if (logPort == 0) {
				goto check_err;
			}
		}
#endif
	}

	/************Place your code here, do what you want to do! ************/
	mib_set(MIB_SYSLOG, &syslogEnable);
	mib_set(MIB_SYSLOG_LOG_LEVEL, &recordLevel);
	mib_set(MIB_SYSLOG_DISPLAY_LEVEL, &dispLevel);
#ifdef CONFIG_USER_RTK_SYSLOG_REMOTE
	mib_set(MIB_SYSLOG_MODE, &sysMode);
	if (sysMode >= 2) {
		mib_set(MIB_SYSLOG_SERVER_IP, &logAddr);
		mib_set(MIB_SYSLOG_SERVER_PORT, &logPort);
	}
#endif
	stopLog();
	if (syslogEnable)
		startLog();
	/************Place your code here, do what you want to do! ************/

	_COND_REDIRECT;

#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif

check_err:
	return;
}
#endif
#endif	// of CONFIG_USER_RTK_SYSLOG

#ifdef TIME_ZONE
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
static void chs_tz_mapping( int idx, char* chs_timeZone, int length)
{
	if (strncmp( get_tz_location(idx), "International Date Line West", 12 ) == 0)
		strncpy( chs_timeZone, "国际日期变更线(西)", length);
	else if (strncmp( get_tz_location(idx), "Midway Island, Samoa", 12 ) == 0)
		strncpy( chs_timeZone, "中途岛，萨摩亚", length);
	else if (strncmp( get_tz_location(idx), "Hawaii", 6 ) == 0)
		strncpy( chs_timeZone, "夏威夷", length);
	else if (strncmp( get_tz_location(idx), "Alaska", 6 ) == 0)
		strncpy( chs_timeZone, "阿拉斯加", length);
	else if (strncmp( get_tz_location(idx), "Pacific Time, Tijuana", 12 ) == 0)
		strncpy( chs_timeZone, "美国西部标准时间，提华纳", length );
	else if (strncmp( get_tz_location(idx), "Arizona, Mazatlan", 7 ) == 0)
		strncpy( chs_timeZone, "亚利桑那州，马萨特兰", length );
	else if (strncmp( get_tz_location(idx), "Chihuahua, La", 12 ) == 0)
		strncpy( chs_timeZone, "奇瓦瓦，拉巴斯", length );
	else if (strncmp( get_tz_location(idx), "Mountain Time", 12 ) == 0)
		strncpy( chs_timeZone, "山地时区(加拿大)", length );
	else if (strncmp( get_tz_location(idx), "Central America", 12 ) == 0)
		strncpy( chs_timeZone, "中美洲", length );
	else if (strncmp( get_tz_location(idx), "Central Time", 12 ) == 0)
		strncpy( chs_timeZone, "中央标准时间(用于美国和加拿大中部)", length );
	else if (strncmp( get_tz_location(idx), "Guadalajara, Mexico City, Monterrey", 12 ) == 0)
		strncpy( chs_timeZone, "瓜达拉哈拉，墨西哥城，蒙特雷", length );
	else if (strncmp( get_tz_location(idx), "Saskatchewan", 12 ) == 0)
		strncpy( chs_timeZone, "萨斯喀彻温省", length );
	else if (strncmp( get_tz_location(idx), "Bogota, Lima, Quito", 12 ) == 0)
		strncpy( chs_timeZone, "波哥大，利马，基多", length );
	else if (strncmp( get_tz_location(idx), "Eastern Time", 12 ) == 0)
		strncpy( chs_timeZone, "东部时间", length );
	else if (strncmp( get_tz_location(idx), "Indiana", 7 ) == 0)
		strncpy( chs_timeZone, "印第安那州", length );
	else if (strncmp( get_tz_location(idx), "Atlantic Time", 12 ) == 0)
		strncpy( chs_timeZone, "大西洋时间", length );
	else if (strncmp( get_tz_location(idx), "Caracas, La Paz", 12 ) == 0)
		strncpy( chs_timeZone, "加拉加斯，拉巴斯", length );
	else if (strncmp( get_tz_location(idx), "Santiago", 8 ) == 0)
		strncpy( chs_timeZone, "圣地亚哥", length );
	else if (strncmp( get_tz_location(idx), "Newfoundland", 12 ) == 0)
		strncpy( chs_timeZone, "纽芬兰", length );
	else if (strncmp( get_tz_location(idx), "Brasilia", 8 ) == 0)
		strncpy( chs_timeZone, "巴西利亚", length );
	else if (strncmp( get_tz_location(idx), "Buenos Aires, Georgetown", 12 ) == 0)
		strncpy( chs_timeZone, "布宜诺斯艾利斯，乔治敦", length );
	else if (strncmp( get_tz_location(idx), "Greenland", 9 ) == 0)
		strncpy( chs_timeZone, "格陵兰", length );
	else if (strncmp( get_tz_location(idx), "Mid-Atlantic", 12 ) == 0)
		strncpy( chs_timeZone, "中大西洋地区", length );
	else if (strncmp( get_tz_location(idx), "Azores", 6 ) == 0)
		strncpy( chs_timeZone, "亚述尔群岛", length );
	else if (strncmp( get_tz_location(idx), "Cape Verde Is.", 12 ) == 0)
		strncpy( chs_timeZone, "佛得角群岛", length );
	else if (strncmp( get_tz_location(idx), "Casablanca, Monrovia", 12 ) == 0)
		strncpy( chs_timeZone, "卡萨布兰卡，蒙罗维亚", length );
	else if (strncmp( get_tz_location(idx), "Greenwich Mean Time:", 12 ) == 0)
		strncpy( chs_timeZone, "格林尼治标准时间：都柏林，爱丁堡，里斯本,伦敦", length );
	else if (strncmp( get_tz_location(idx), "Amsterdam, Berlin, Bern, Rome", 12 ) == 0)
		strncpy( chs_timeZone, "阿姆斯特丹，柏林，伯尔尼, 罗马，斯德哥尔摩，维也纳", length );
	else if (strncmp( get_tz_location(idx), "Belgrade, Bratislava, Budapest", 12 ) == 0)
		strncpy( chs_timeZone, "贝尔格莱德，布拉迪斯拉发，卢布尔雅那，布拉格", length );
	else if (strncmp( get_tz_location(idx), "Brussels, Copenhagen, Madrid, Paris", 12 ) == 0)
		strncpy( chs_timeZone, "布鲁塞尔，哥本哈根，马德里，巴黎", length );
	else if (strncmp( get_tz_location(idx), "Sarajevo, Skopje, Warsaw, Zagreb", 12 ) == 0)
		strncpy( chs_timeZone, "萨拉热窝，斯科普里，华沙，萨格勒布", length );
	else if (strncmp( get_tz_location(idx), "West Central Africa", 12 ) == 0)
		strncpy( chs_timeZone, "中西非", length );
	else if (strncmp( get_tz_location(idx), "Athens, Istanbul, Minsk", 12 ) == 0)
		strncpy( chs_timeZone, "雅典，伊斯坦布尔，明斯克", length );
	else if (strncmp( get_tz_location(idx), "Bucharest", 9 ) == 0)
		strncpy( chs_timeZone, "布加勒斯特", length );
	else if (strncmp( get_tz_location(idx), "Cairo", 5 ) == 0)
		strncpy( chs_timeZone, "开罗", length );
	else if (strncmp( get_tz_location(idx), "Harare, Pretoria", 12 ) == 0)
		strncpy( chs_timeZone, "哈拉雷，比勒陀利亚", length );
	else if (strncmp( get_tz_location(idx), "Helsinki, Kyiv, Riga, Sofia", 8 ) == 0)
		strncpy( chs_timeZone, "赫尔辛基，基辅，里加，索非亚，塔林, 维尔纽斯", length );
	else if (strncmp( get_tz_location(idx), "Jerusalem", 9 ) == 0)
		strncpy( chs_timeZone, "耶路撒冷", length );
	else if (strncmp( get_tz_location(idx), "Baghdad", 7 ) == 0)
		strncpy( chs_timeZone, "巴格达", length );
	else if (strncmp( get_tz_location(idx), "Kuwait, Riyadh", 12 ) == 0)
		strncpy( chs_timeZone, "科威特，利雅得", length );
	else if (strncmp( get_tz_location(idx), "Moscow, St. Petersburg", 12 ) == 0)
		strncpy( chs_timeZone, "莫斯科，圣彼得堡，伏尔加格勒", length );
	else if (strncmp( get_tz_location(idx), "Nairobi", 7 ) == 0)
		strncpy( chs_timeZone, "奈洛比", length );
	else if (strncmp( get_tz_location(idx), "Tehran", 6 ) == 0)
		strncpy( chs_timeZone, "德黑兰", length );
	else if (strncmp( get_tz_location(idx), "Abu Dhabi, Muscat", 12 ) == 0)
		strncpy( chs_timeZone, "阿布扎比，马斯喀特", length );
	else if (strncmp( get_tz_location(idx), "Baku, Tbilisi, Yerevan", 12 ) == 0)
		strncpy( chs_timeZone, "巴库，第比利斯，耶烈万", length );
	else if (strncmp( get_tz_location(idx), "Kabul", 5 ) == 0)
		strncpy( chs_timeZone, "喀布尔", length );
	else if (strncmp( get_tz_location(idx), "Ekaterinburg", 12 ) == 0)
		strncpy( chs_timeZone, "叶卡特琳堡", length );
	else if (strncmp( get_tz_location(idx), "Islamabad, Karachi, Tashkent", 12 ) == 0)
		strncpy( chs_timeZone, "伊斯兰堡，卡拉奇，塔什干", length );
	else if (strncmp( get_tz_location(idx), "Chennai, Kolkata, Mumbai", 12 ) == 0)
		strncpy( chs_timeZone, "清奈，加尔各答，孟买，新德里", length );
	else if (strncmp( get_tz_location(idx), "Kathmandu", 9 ) == 0)
		strncpy( chs_timeZone, "加德满都", length );
	else if (strncmp( get_tz_location(idx), "Almaty, Novosibirsk", 12 ) == 0)
		strncpy( chs_timeZone, "阿拉木图，新西伯利亚", length );
	else if (strncmp( get_tz_location(idx), "Astana, Dhaka", 12 ) == 0)
		strncpy( chs_timeZone, "阿斯坦纳，达卡", length );
	else if (strncmp( get_tz_location(idx), "Sri Jayawardenepura", 12 ) == 0)
		strncpy( chs_timeZone, "斯里兰卡", length );
	else if (strncmp( get_tz_location(idx), "Yangon Rangoon", 7 ) == 0)
		strncpy( chs_timeZone, "仰光", length );
	else if (strncmp( get_tz_location(idx), "Bangkok, Hanoi, Jakarta", 12 ) == 0)
		strncpy( chs_timeZone, "曼谷，河内，雅加达", length );
	else if (strncmp( get_tz_location(idx), "Krasnoyarsk", 10 ) == 0)
		strncpy( chs_timeZone, "拉斯诺亚尔斯克", length );
	else if (strncmp( get_tz_location(idx), "Beijing, Chongquing, Hong Kong, Urumqi", 12 ) == 0)
		strncpy( chs_timeZone, "北京，重庆，香港，乌鲁木齐", length );
	else if (strncmp( get_tz_location(idx), "Irkutsk, Ulaan Bataar", 12 ) == 0)
		strncpy( chs_timeZone, "伊尔库次克，乌兰巴托", length );
	else if (strncmp( get_tz_location(idx), "Kuala Lumpur, Singapore", 12 ) == 0)
		strncpy( chs_timeZone, "吉隆坡，新加坡", length );
	else if (strncmp( get_tz_location(idx), "Perth", 5 ) == 0)
		strncpy( chs_timeZone, "珀斯", length );
	else if (strncmp( get_tz_location(idx), "Taipei", 6 ) == 0)
		strncpy( chs_timeZone, "台北", length );
	else if (strncmp( get_tz_location(idx), "Osaka, Sapporo, Tokyo", 12 ) == 0)
		strncpy( chs_timeZone, "大阪，札幌，东京", length );
	else if (strncmp( get_tz_location(idx), "Seoul", 5 ) == 0)
		strncpy( chs_timeZone, "首尔", length );
	else if (strncmp( get_tz_location(idx), "Yakutsk", 7 ) == 0)
		strncpy( chs_timeZone, "雅库茨克", length );
	else if (strncmp( get_tz_location(idx), "Adelaide", 7 ) == 0)
		strncpy( chs_timeZone, "阿德莱德", length );
	else if (strncmp( get_tz_location(idx), "Darwin", 6 ) == 0)
		strncpy( chs_timeZone, "达尔文", length );
	else if (strncmp( get_tz_location(idx), "Brisbane", 8 ) == 0)
		strncpy( chs_timeZone, "布里斯班", length );
	else if (strncmp( get_tz_location(idx), "Canberra, Melbourne, Sydney", 12 ) == 0)
		strncpy( chs_timeZone, "堪培拉，墨尔本，悉尼", length );
	else if (strncmp( get_tz_location(idx), "Guam, Port Moresby", 12 ) == 0)
		strncpy( chs_timeZone, "关岛，莫尔兹比港", length );
	else if (strncmp( get_tz_location(idx), "Hobart", 6 ) == 0)
		strncpy( chs_timeZone, "霍巴特", length );
	else if (strncmp( get_tz_location(idx), "Vladivostok", 11 ) == 0)
		strncpy( chs_timeZone, "符拉迪沃斯托克", length );
	else if (strncmp( get_tz_location(idx), "Magadan", 7 ) == 0)
		strncpy( chs_timeZone, "马加丹", length );
	else if (strncmp( get_tz_location(idx), "Solomon Is., New Caledonia", 12 ) == 0)
		strncpy( chs_timeZone, "所罗门群岛，新喀里多尼亚", length );
	else if (strncmp( get_tz_location(idx), "Auckland, Wellington", 12 ) == 0)
		strncpy( chs_timeZone, "奥克兰，惠灵顿", length );
	else if (strncmp( get_tz_location(idx), "Fiji, Kamchatka, Marshall Is.", 4 ) == 0)
		strncpy( chs_timeZone, "斐济，堪察加半岛，马绍尔群岛", length );
	else
		strcpy( chs_timeZone, get_tz_location(idx));
}
#endif

int timeZoneList(int eid, request * wp, int argc, char **argv)
{
	int nBytesSent = 0;
	unsigned int i, selected = 0;
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	char chs_timeZone[128];
#endif

	mib_get(MIB_NTP_TIMEZONE_DB_INDEX, &selected);

	for (i = 0; i < nr_tz; i++) {
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		memset( chs_timeZone, 0, sizeof(chs_timeZone));
		chs_tz_mapping( i, chs_timeZone, sizeof(chs_timeZone) );
		nBytesSent += boaWrite(wp, "<option value=\"%u\"%s>(GMT%s)%s</option>",
				i, (i == selected) ? " selected" : "", get_tz_utc_offset(i), chs_timeZone);
#else
		nBytesSent += boaWrite(wp, "<option value=\"%u\"%s>%s (GMT%s)</option>",
				i, (i == selected) ? " selected" : "",
				get_tz_location(i), get_tz_utc_offset(i));
#endif
	}

	return nBytesSent;
}
#endif

#if 0
#ifdef DOS_SUPPORT
void formDosCfg(request * wp, char *path, char *query)
{
	char	*submitUrl, *tmpStr;
	char	tmpBuf[100];
	unsigned int	floodCount=0,blockTimer=0;
	unsigned int	enabled = 0;

	submitUrl = boaGetVar(wp, "submit-url", "");   // hidden page

	mib_get(MIB_DOS_ENABLED, (void *)&enabled);

	tmpStr = boaGetVar(wp, "dosEnabled", "");
	if(!strcmp(tmpStr, "ON")) {
		enabled |= 1;

		tmpStr = boaGetVar(wp, "sysfloodSYN", "");
		if(!strcmp(tmpStr, "ON")) {
			enabled |= 2;
			tmpStr = boaGetVar(wp, "sysfloodSYNcount", "");
			string_to_dec(tmpStr,&floodCount);
			if ( mib_set(MIB_DOS_SYSSYN_FLOOD, (void *)&floodCount) == 0) {
				strcpy(tmpBuf, strSetDosSYSSYNFLOODErr);
				goto setErr;
			}
		}
		else{
			enabled &= ~2;
		}
		tmpStr = boaGetVar(wp, "sysfloodFIN", "");
		if(!strcmp(tmpStr, "ON")) {
			enabled |= 4;
			tmpStr = boaGetVar(wp, "sysfloodFINcount", "");
			string_to_dec(tmpStr,&floodCount);
			if ( mib_set(MIB_DOS_SYSFIN_FLOOD, (void *)&floodCount) == 0) {
				strcpy(tmpBuf, strSetDosSYSFINFLOODErr);
				goto setErr;
			}
		}
		else{
			enabled &= ~4;
		}
		tmpStr = boaGetVar(wp, "sysfloodUDP", "");
		if(!strcmp(tmpStr, "ON")) {
			enabled |= 8;
			tmpStr = boaGetVar(wp, "sysfloodUDPcount", "");
			string_to_dec(tmpStr,&floodCount);
			if ( mib_set(MIB_DOS_SYSUDP_FLOOD, (void *)&floodCount) == 0) {
				strcpy(tmpBuf, strSetDosSYSUDPFLOODErr);
				goto setErr;
			}
		}
		else{
			enabled &= ~8;
		}
		tmpStr = boaGetVar(wp, "sysfloodICMP", "");
		if(!strcmp(tmpStr, "ON")) {
			enabled |= 0x10;
			tmpStr = boaGetVar(wp, "sysfloodICMPcount", "");
			string_to_dec(tmpStr,&floodCount);
			if ( mib_set(MIB_DOS_SYSICMP_FLOOD, (void *)&floodCount) == 0) {
				strcpy(tmpBuf, strSetDosSYSICMPFLOODErr);
				goto setErr;
			}
		}
		else{
			enabled &= ~0x10;
		}
		tmpStr = boaGetVar(wp, "ipfloodSYN", "");
		if(!strcmp(tmpStr, "ON")) {
			enabled |= 0x20;
			tmpStr = boaGetVar(wp, "ipfloodSYNcount", "");
			string_to_dec(tmpStr,&floodCount);
			if ( mib_set(MIB_DOS_PIPSYN_FLOOD, (void *)&floodCount) == 0) {
				strcpy(tmpBuf, strSetDosPIPSYNFLOODErr);
				goto setErr;
			}
		}
		else{
			enabled &= ~0x20;
		}
		tmpStr = boaGetVar(wp, "ipfloodFIN", "");
		if(!strcmp(tmpStr, "ON")) {
			enabled |= 0x40;
			tmpStr = boaGetVar(wp, "ipfloodFINcount", "");
			string_to_dec(tmpStr,&floodCount);
			if ( mib_set(MIB_DOS_PIPFIN_FLOOD, (void *)&floodCount) == 0) {
				strcpy(tmpBuf, strSetDosPIPFINFLOODErr);
				goto setErr;
			}
		}
		else{
			enabled &= ~0x40;
		}
		tmpStr = boaGetVar(wp, "ipfloodUDP", "");
		if(!strcmp(tmpStr, "ON")) {
			enabled |= 0x80;
			tmpStr = boaGetVar(wp, "ipfloodUDPcount", "");
			string_to_dec(tmpStr,&floodCount);
			if ( mib_set(MIB_DOS_PIPUDP_FLOOD, (void *)&floodCount) == 0) {
				strcpy(tmpBuf, strSetDosPIPUDPFLOODErr);
				goto setErr;
			}
		}
		else{
			enabled &= ~0x80;
		}
		tmpStr = boaGetVar(wp, "ipfloodICMP", "");
		if(!strcmp(tmpStr, "ON")) {
			enabled |= 0x100;
			tmpStr = boaGetVar(wp, "ipfloodICMPcount", "");
			string_to_dec(tmpStr,&floodCount);
			if ( mib_set(MIB_DOS_PIPICMP_FLOOD, (void *)&floodCount) == 0) {
				strcpy(tmpBuf, strSetDosPIPICMPFLOODErr);
				goto setErr;
			}
		}
		else{
			enabled &= ~0x100;
		}
		tmpStr = boaGetVar(wp, "TCPUDPPortScan", "");
		if(!strcmp(tmpStr, "ON")) {
			enabled |= 0x200;

			tmpStr = boaGetVar(wp, "portscanSensi", "");
			if( tmpStr[0]=='1' ) {
				enabled |= 0x800000;
			}
			else{
				enabled &= ~0x800000;
			}
		}
		else{
			enabled &= ~0x200;
		}
		tmpStr = boaGetVar(wp, "ICMPSmurfEnabled", "");
		if(!strcmp(tmpStr, "ON")) {
			enabled |= 0x400;
		}
		else{
			enabled &= ~0x400;
		}
		tmpStr = boaGetVar(wp, "IPLandEnabled", "");
		if(!strcmp(tmpStr, "ON")) {
			enabled |= 0x800;
		}
		else{
			enabled &= ~0x800;
		}
		tmpStr = boaGetVar(wp, "IPSpoofEnabled", "");
		if(!strcmp(tmpStr, "ON")) {
			enabled |= 0x1000;
		}
		else{
			enabled &= ~0x1000;
		}
		tmpStr = boaGetVar(wp, "IPTearDropEnabled", "");
		if(!strcmp(tmpStr, "ON")) {
			enabled |= 0x2000;
		}
		else{
			enabled &= ~0x2000;
		}
		tmpStr = boaGetVar(wp, "PingOfDeathEnabled", "");
		if(!strcmp(tmpStr, "ON")) {
			enabled |= 0x4000;
		}
		else{
			enabled &= ~0x4000;
		}
		tmpStr = boaGetVar(wp, "TCPScanEnabled", "");
		if(!strcmp(tmpStr, "ON")) {
			enabled |= 0x8000;
		}
		else{
			enabled &= ~0x8000;
		}
		tmpStr = boaGetVar(wp, "TCPSynWithDataEnabled", "");
		if(!strcmp(tmpStr, "ON")) {
			enabled |= 0x10000;
		}
		else{
			enabled &= ~0x10000;
		}
		tmpStr = boaGetVar(wp, "UDPBombEnabled", "");
		if(!strcmp(tmpStr, "ON")) {
			enabled |= 0x20000;
		}
		else{
			enabled &= ~0x20000;
		}
		tmpStr = boaGetVar(wp, "UDPEchoChargenEnabled", "");
		if(!strcmp(tmpStr, "ON")) {
			enabled |= 0x40000;
		}
		else{
			enabled &= ~0x40000;
		}
		tmpStr = boaGetVar(wp, "sourceIPblock", "");
		if(!strcmp(tmpStr, "ON")) {
			enabled |= 0x400000;
			tmpStr = boaGetVar(wp, "IPblockTime", "");
			string_to_dec(tmpStr,&blockTimer);
			if ( mib_set(MIB_DOS_BLOCK_TIME, (void *)&blockTimer) == 0) {
				strcpy(tmpBuf, strSetDosIPBlockTimeErr);
				goto setErr;
			}
		}
		else{
			enabled &= ~0x400000;
		}
	}
	else
		enabled = 0;

	if ( mib_set(MIB_DOS_ENABLED, (void *)&enabled) == 0) {
		strcpy(tmpBuf, strSetDosEnableErr);
		goto setErr;
	}

	//apmib_update(CURRENT_SETTING);
#if defined(APPLY_CHANGE)
	setup_dos_protection();
#endif

#ifndef NO_ACTION
	run_init_script("all");
#endif

	submitUrl = boaGetVar(wp, "submit-url", "");   // hidden page
	OK_MSG(submitUrl);

	return;
setErr:
	ERR_MSG(tmpBuf);
}
#endif

#ifdef WEB_REDIRECT_BY_MAC
void formLanding(request * wp, char *path, char *query)
{
	char *submitUrl, *strLTime;
	unsigned int uLTime;

	strLTime = boaGetVar(wp, "interval", "");
	if ( strLTime[0] ) {
		sscanf(strLTime, "%u", &uLTime);
	}

	mib_set(MIB_WEB_REDIR_BY_MAC_INTERVAL, (void *)&uLTime);

	submitUrl = boaGetVar(wp, "submit-url", "");
	if (submitUrl[0])
		//boaRedirect(wp, submitUrl);
		OK_MSG(submitUrl);
	return;
}
#endif
#endif  // #if 0  // Mason Yu. t123

#ifdef E8B_NEW_DIAGNOSE
void formTr069Diagnose(request *wp, char *path, char *query)
{
	{
		/************Place your code here, do what you want to do! ************/
		pid_t  tr069_pid;
		unsigned int events;

#ifdef CONFIG_MIDDLEWARE
		pid_t tmp_pid;
		unsigned char vChar;
		mib_get(CWMP_TR069_ENABLE, (void *)&vChar);
		if (!vChar) {
		//Martin_zhu:send MIB_MIDWARE_INFORM_EVENT to MidProcess
			vChar = CTEVENT_SEND_INFORM;
			sendInformEventMsg2MidProcess( vChar );
		}
		else
#endif
		{
			tr069_pid = read_pid("/var/run/cwmp.pid");
			if ( tr069_pid > 0) {
#ifdef E8B_NEW_DIAGNOSE
				FILE *fp = NULL;
				fp = fopen(INFORM_STATUS_FILE, "w");
				if (fp) {
					fprintf(fp, "%d", INFORMING);
					fclose(fp);
				}
#endif
#ifdef CONFIG_MIDDLEWARE
				vChar = CTEVENT_SEND_INFORM;
				if(mib_set(MIB_MIDWARE_INFORM_EVENT, (void*)&vChar))
					kill(tr069_pid, SIGUSR1);
#else
				mib_get(CWMP_INFORM_EVENTCODE, &events);
				#define EC_PERIODIC 0x000004	// Must match the define in cwmp_rpc.h
				events |= EC_PERIODIC;
				mib_set(CWMP_INFORM_EVENTCODE, &events);
#endif
			}
		}
		/************Place your code here, do what you want to do! ************/
	}

	_COND_REDIRECT;
}
#endif

/*****************************
** 用户管理
*/
int initPageMgmUser(int eid, request * wp, int argc, char **argv)
{
	char issu = 0;
	struct user_info *pUser_info = NULL;
	int lineno = __LINE__;

	_TRACE_CALL;

	pUser_info = search_login_list(wp);
	issu = ((pUser_info && pUser_info->priv) ? 1 : 0);

	_PUT_BOOL(issu);

	_TRACE_LEAVEL;
	return 0;
}

#ifdef CONFIG_USER_RTK_ONUCOMM
#include "../../onucomm/onucomm.h"
#include <sys/socket.h>
#include <sys/un.h>
#define ONUCOMM_SOCK_FILE "/tmp/onucomm_sock"
static int onucomm_sock = 0;
static int onucomm_reset_loid(void)
{
    int ret;
    struct sockaddr_un srv_addr;
	char buf[1500] = {0};
    char recv_buf[256] = {0};
    int recv_len = 0;
    //creat unix socket
    onucomm_sock =socket(PF_UNIX,SOCK_STREAM,0);
    if(onucomm_sock < 0)
    {
        printf("cannot create communication socket\n");
        return -1;
    }   
    srv_addr.sun_family = AF_UNIX;
    strcpy(srv_addr.sun_path, ONUCOMM_SOCK_FILE);
    //connect server
	
retry:
    ret =  connect(onucomm_sock,(struct sockaddr*)&srv_addr,sizeof(srv_addr));
    if(ret == -1)
    {
		perror("Error ");
		if(errno == EINTR)
			goto retry;
        printf("cannot connect to the server\n");
        close(onucomm_sock);
        return -1;
    }
	printf("connect success\n");
	
	ONU_TLV_T *tlv = (ONU_TLV_T *)buf;
    tlv->type = ONU_DATA_TYPE_INFORM_LOID;
    strcpy(tlv->data, "");
    tlv->len = 0;
    write(onucomm_sock, buf, sizeof(ONU_TLV_T)+tlv->len); 
	if(onucomm_sock)
	{
		close(onucomm_sock);
		printf("close ok\n");
	}
    return 0;
}
#endif // CONFIG_USER_RTK_ONUCOMM

void formReboot(request * wp, char * path, char * query)
{
	int lineno = __LINE__;
	char *strReset;

	_TRACE_CALL;

	boaHeader(wp);
	//--- Add timer countdown
	#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	//CMCC need 90 seconds to restart system
		boaWrite(wp, "<head><META http-equiv=content-type content=\"text/html; charset=gbk\"><style>\n" \
        "#cntdwn{ border-color: white; border-width: 0px; font-size: 12pt; color: red; text-align:left; font-weight:bold; font-family: Courier;}\n" \
        "</style><script language=javascript>\n" \
        "var h = 91;\n" \
        "function stop() { clearTimeout(id); }\n"\
        "function start() { h--; if (h >= 0) { frm.time.value = h; frm.textname.value='设备重启中, 请稍候 ...'; id = setTimeout(\"start()\", 1000); }\n" \
        "if (h == 0) { window.location.reload(true); }}\n" \
        "</script></head>");
        boaWrite(wp,
        "<body bgcolor=white onLoad=\"start();\" onUnload=\"stop();\"><blockquote>" \
        "<form name=frm><b><font color=red><input type=text name=textname size=40 id=\"cntdwn\">\n" \
        "<input type=text name=time size=5 id=\"cntdwn\"></font></form></blockquote></body>" );
	#else
        boaWrite(wp, "<head><META http-equiv=content-type content=\"text/html; charset=gbk\"><style>\n" \
        "#cntdwn{ border-color: white; border-width: 0px; font-size: 12pt; color: red; text-align:left; font-weight:bold; font-family: Courier;}\n" \
        "</style><script language=javascript>\n" \
        "var h = 70;\n" \
        "function stop() { clearTimeout(id); }\n"\
        "function start() { h--; if (h >= 0) { frm.time.value = h; frm.textname.value='设备重启中, 请稍候 ...'; id = setTimeout(\"start()\", 1000); }\n" \
        "if (h == 0) { window.location.reload(true); }}\n" \
        "</script></head>");
        boaWrite(wp,
        "<body bgcolor=white onLoad=\"start();\" onUnload=\"stop();\"><blockquote>" \
        "<form name=frm><b><font color=red><input type=text name=textname size=40 id=\"cntdwn\">\n" \
        "<input type=text name=time size=5 id=\"cntdwn\"></font></form></blockquote></body>" );
	#endif
        //--- End of timer countdown
   	boaFooter(wp);
	boaDone(wp, 200);

	strReset = boaGetVar(wp, "reset", "");
#ifdef EMBED
	if (strReset[0]) {
#ifdef CONFIG_MIDDLEWARE
	unsigned char vChar;
	mib_get(CWMP_TR069_ENABLE, (void*)&vChar);
	if ( (vChar == 0)||(vChar == 2) ) {
		if( (sendSetDefaultFlagMsg2MidProcess() == 0)&&(sendSetDefaultRetMsg2MidIntf() == 0) )
		{
			sleep(10);	//wait reboot command from middleware
		}
	}
#endif	//end of CONFIG_MIDDLEWARE
		#ifdef CONFIG_USER_RTK_ONUCOMM
		if(atoi(strReset) == 3)
		{
			onucomm_reset_loid();
			sleep(10);
		}
		#endif //CONFIG_USER_RTK_ONUCOMM
		reset_cs_to_default(atoi(strReset));
#ifdef CONFIG_CT_AWIFI_JITUAN_SMARTWIFI		
        unsigned char functype=0;
        mib_get(AWIFI_PROVINCE_CODE, &functype);
        if(functype == AWIFI_ZJ){
		system("cp -f /var/config/awifi/awifi_bak.conf /var/config/awifi/awifi.conf");
		if(access("/var/config/awifi/binversion", F_OK) == 0)
			system("rm -f /var/config/awifi/binversion");
        }
#endif
	}
#endif

#ifdef CONFIG_USER_RTK_OMD
	write_omd_reboot_log(TELECOM_WEB_REBOOT);
#endif
	cmd_reboot();

check_err:
	_TRACE_LEAVEL;
	return;
}

/*****************************
** 日常应用
*/
/// This setting should sync with usbmount user tool
int listUsbDevices(int eid, request *wp, int argc, char ** argv)
{
	int errcode = 1, lineno = __LINE__;
	struct dirent **namelist;
	int i, n;

	_TRACE_CALL;

	n = scandir("/mnt", &namelist, usb_filter, alphasort);

	/* no match */
	if (n < 0)
		goto check_err;

	for (i = 0; i < n; i++) {
		boaWrite(wp, "push(new it_nr(\"%c\"" _PTS "));\n",
				namelist[i]->d_name[3],
				"path", namelist[i]->d_name);
		free(namelist[i]);
	}
	free(namelist);

check_err:
	_TRACE_LEAVEL;
	return 0;
}

/*****************************
**USB备份配置
*/
void formUSBbak(request * wp, char *path, char *query)
{
	//USB分区
#if !defined(CONFIG_CMCC) && !defined(CONFIG_CU)
	extern unsigned char g_csrf_token[];
#endif
	char *pusbdev = NULL, *stemp = NULL, dstname[64], usb_cfg_filename[32];
	int errcode = 1, lineno = __LINE__;
	int forcebackup = 0;	//jim used for remove exist config file in usb disk...
	int rv = 0;
	struct file_pipe pipe;
	unsigned char cpbuf[256];
	const char *config_filename;

	_TRACE_CALL;

	FETCH_INVALID_OPT(stemp, "action", _OPT);

	if (stemp && stemp[0]) {
		if (0 == strcmp(stemp, "en")) {
			/* setting config fast restore */
#ifdef _PRMT_USBRESTORE
			unsigned char cfgFastRestoreEnable;

			_GET_BOOL(cfgFastRestoreEnable, _NEED);

			if (mib_set
			    (MIB_USBRESTORE, (void *)&cfgFastRestoreEnable)) {
				mib_update(CURRENT_SETTING, CONFIG_MIB_ALL);
			} else {
				printf("set config fast restore failed!");
			}
#endif
			_COND_REDIRECT;
			return;
		}
	}

	if (isUSBMounted() <= 0)
		goto err_dir;

	_GET_PSTR(usbdev, _NEED);
	/************Place your code here, do what you want to do! ************/
	_GET_INT(forcebackup, _OPT);

	// create dir
	snprintf(dstname, sizeof(dstname), "/mnt/%s/%s/", pusbdev, BACKUP_DIRNAME);
	if (mkdir(dstname, 0755) && errno != EEXIST)
		goto err_dir;

	// make usb config filename (dst file)
	snprintf(usb_cfg_filename, sizeof(usb_cfg_filename), "ctce8.cfg");
	strncat(dstname, usb_cfg_filename, sizeof(usb_cfg_filename));

	// check if dst file exist..
	if (!access(dstname, F_OK)) {
		if (!forcebackup) {
			goto err_exist;
		} else {
			printf("%s: config file exist: %s\n", __FUNCTION__,
			       dstname);
			unlink(dstname);
		}
	}

	// prepare config file..
#if defined(CONFIG_USER_XMLCONFIG) || defined(CONFIG_USE_XML)
	config_filename = CONFIG_XMLFILE;
#else
	config_filename = CONFIG_RAWFILE;
#endif
	before_upload(config_filename);

	pipe.buffer = cpbuf;
	pipe.bufsize = sizeof(cpbuf);
	pipe.func = encode;

	rv = file_copy_pipe(config_filename, dstname, &pipe);
	unlink(config_filename);

	if (rv != 0) {
		goto err_file;
	}
	chmod(dstname, S_IRUSR);
	sync();			/* lijian: 20080716: flush inode of config file after chmod */

	errcode = 0;
	OK_MSG1("保存成功", "/mgm_dev_usbbak.asp")

check_err:
	_TRACE_LEAVEL;
	return;

err_exist:
	printf("file already exist, remove it first\n");

#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	boaWrite(wp, "<html>\
<head>\
<meta http-equiv=cache-control content=\"no-cache, must-revalidate\">\
<meta http-equiv=content-type content=\"text/html; charset=gbk\">\
<meta http-equiv=content-script-type content=text/javascript>\
<style type=text/css>\
@import url(/style/default.css);\
</style>\
<script language=\"javascript\" src=\"common.js\"></script>\
<body>\
<form action=\"/boaform/admin/formUSBbak\" method=\"post\">\
<table align=\"center\"><tr><td><font color=\"red\" size=2>配置文件备份已存在!</font></td></tr></table>\
<table align=center>\
<tr align=center>\
<td colspan=2 class=actionbuttons>\
<input type=\"hidden\" name=\"forcebackup\" value=\"1\" >\
<input type=\"hidden\" name=\"usbdev\" value=\"%s\" >\
<input type=\"submit\" value=\"删除后备份\"></td>\
<td colspan=2 class=actionbuttons><input type='button' onClick='history.back()' value='退出备份'></td>\
</tr>\
</table>\
</form>\
</body>\
</html>", pusbdev);
#else
#ifdef CONFIG_USER_BOA_CSRF
	boaWrite(wp, "<html>\
<head>\
<meta http-equiv=cache-control content=\"no-cache, must-revalidate\">\
<meta http-equiv=content-type content=\"text/html; charset=gbk\">\
<meta http-equiv=content-script-type content=text/javascript>\
<style type=text/css>\
@import url(/style/default.css);\
</style>\
<script language=\"javascript\" src=\"/common.js\"></script>\
<SCRIPT language=\"javascript\" type=\"text/javascript\">\
function on_submit()\
{\
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);\
	return true;\
}\
</SCRIPT>\
<body>\
<form action=\"/boaform/admin/formUSBbak\" method=\"post\">\
<table align=\"center\"><tr><td><font color=\"red\" size=2>配置文件备份已存在!</font></td></tr></table>\
<table align=center>\
<tr align=center>\
<td colspan=2 class=actionbuttons>\
<input type=\"hidden\" name=\"forcebackup\" value=\"1\" >\
<input type=\"hidden\" name=\"usbdev\" value=\"%s\" >\
<input type=\"submit\" value=\"删除后备份\" onClick=\"return on_submit()\"></td>\
<td colspan=2 class=actionbuttons><input type='button' onClick='history.back()' value='退出备份'></td>\
</tr>\
</table>\
<input type=\"hidden\" name=\"postSecurityFlag\" value=\"\">\
<input type='hidden' name='%s' value='%s' />\
</form>\
</body>\
</html>", pusbdev, CSRF_TOKEN_STRING, g_csrf_token);
#else
	boaWrite(wp, "<html>\
<head>\
<meta http-equiv=cache-control content=\"no-cache, must-revalidate\">\
<meta http-equiv=content-type content=\"text/html; charset=gbk\">\
<meta http-equiv=content-script-type content=text/javascript>\
<style type=text/css>\
@import url(/style/default.css);\
</style>\
<script language=\"javascript\" src=\"/common.js\"></script>\
<SCRIPT language=\"javascript\" type=\"text/javascript\">\
function on_submit()\
{\
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);\
	return true;\
}\
</SCRIPT>\
<body>\
<form action=\"/boaform/admin/formUSBbak\" method=\"post\">\
<table align=\"center\"><tr><td><font color=\"red\" size=2>配置文件备份已存在!</font></td></tr></table>\
<table align=center>\
<tr align=center>\
<td colspan=2 class=actionbuttons>\
<input type=\"hidden\" name=\"forcebackup\" value=\"1\" >\
<input type=\"hidden\" name=\"usbdev\" value=\"%s\" >\
<input type=\"submit\" value=\"删除后备份\" onClick=\"return on_submit()\"></td>\
<td colspan=2 class=actionbuttons><input type='button' onClick='history.back()' value='退出备份'></td>\
</tr>\
</table>\
<input type=\"hidden\" name=\"postSecurityFlag\" value=\"\">\
</form>\
</body>\
</html>", pusbdev);
#endif
#endif
	boaDone(wp, 200);
	return;

err_file:
	printf("fail to copy, disk full? code %d\n", rv);
	snprintf(dstname, sizeof dstname, "空间不够");
	_ERR_MSG(dstname);
	return;

err_dir:
	snprintf(dstname, sizeof dstname, "保存失败");
	_ERR_MSG(dstname);
	return;
}

/*****************************
**USB卸载
*/
void formUSBUmount(request * wp, char *path, char *query)
{
	char *pusbdev = NULL, dstname[64];
	int errcode = 1, lineno = __LINE__, ret;

	if (isUSBMounted() <= 0)
		goto err_dir;

	_GET_PSTR(usbdev, _NEED);

	// create dir
	snprintf(dstname, sizeof(dstname), "/mnt/%s", pusbdev);

	ret = umount2(dstname, MNT_DETACH);
	ret |= rmdir(dstname);

	if (ret)
		goto err_dir;

	OK_MSG1("卸载成功", "/mgm_dev_usb_umount.asp");
	return;

check_err:
err_dir:
	_ERR_MSG("卸载失败");
}

void formVersionMod(request *wp, char *path, char *query)
{
	char *strData;
	unsigned char str;
	unsigned int cnt;

	// manufacturer
	strData = boaGetVar(wp,"txt_mft","");
	if (strData[0])
	{
		if (!mib_set(RTK_DEVID_MANUFACTURER, strData)) {
			goto setErr;
		}
		else printf("Update Manufacturer to %s \n" , strData);
	}

	// OUI
	strData = boaGetVar(wp,"txt_oui","");
	if (strData[0])
	{
		if (!mib_set(RTK_DEVID_OUI, strData)) {
			goto setErr;
		}
		else printf("Update OUI to %s \n" , strData);
	}

	// Product Class
	strData = boaGetVar(wp,"txt_proclass","");
	if (strData[0])
	{
		if (!mib_set( RTK_DEVID_PRODUCTCLASS, strData)) {
			goto setErr;
		}
		else printf("Update Product Class to %s \n" , strData);
	}

	// HW Serial Number
	strData = boaGetVar(wp,"txt_serialno","");
	if (strData[0])
	{
		if (!mib_set(MIB_HW_SERIAL_NUMBER, (void *)strData)) {
			goto setErr;
		}
		else printf("Update Serial Number to %s \n" , strData);
	}

#ifdef CONFIG_USER_CWMP_TR069
	// Provisioning Code
	strData = boaGetVar(wp,"txt_provisioningcode","");
	if (strData[0])
	{
		if (!mib_set(CWMP_PROVISIONINGCODE, (void *)strData)) {
			goto setErr;
		}
		else printf("Update Provisioning Code to %s \n" , strData);
	}
#endif
	// Spec. Version
	strData = boaGetVar(wp,"txt_specver","");
	if (strData[0])
	{
		if (!mib_set(RTK_DEVINFO_SPECVER, (void *)strData)) {
			goto setErr;
		}
		else printf("Update Spec. Version to %s \n" , strData);
	}

	// Software Version
	strData = boaGetVar(wp,"txt_swver","");
	if (strData[0])
	{
		if (!mib_set(RTK_DEVINFO_SWVER, (void *)strData)) {
			goto setErr;
		}
		else printf("Update Software Version to %s \n" , strData);
	}

	// Hardware Version
	strData = boaGetVar(wp,"txt_hwver","");
	if (strData[0])
	{
		if (!mib_set(RTK_DEVINFO_HWVER, (void *)strData)) {
			goto setErr;
		}
		else printf("Update Hardware Version to %s \n" , strData);
	}
#if defined(CONFIG_GPON_FEATURE)
	//GPON SN
	strData = boaGetVar(wp,"txt_gponsn","");
	if (strData[0])
	{
		if (!mib_set(MIB_GPON_SN, (void *)strData)) {
			goto setErr;
		}
		else printf("Update GPON SN to %s \n" , strData);
	}
#endif
	// ELAN MAC Address
	strData = boaGetVar(wp,"txt_elanmac","");
	if (strData[0])
	{
		unsigned char mac[6];
		if ( !string_to_hex(strData, mac, 12)) {
			goto setErr;
		}
		if (!mib_set(MIB_ELAN_MAC_ADDR, (void *)mac)) {
			goto setErr;
		}
		else printf("Update ELAN MAC Address to %s \n" , strData);
	}

#ifdef _PRMT_X_CT_COM_MWBAND_
	// WAN LIMIT
	strData = boaGetVar(wp,"txt_wanlimit","");
	if(strData[0])
	{
		int limit = 0, enable = 1;

		limit = atoi(strData);
		if(limit == 0)
		{
			if (!mib_set(CWMP_CT_MWBAND_MODE, (void *)&limit))
			{
				goto setErr;
			}
			printf("Disable WAN Limit\n");
		}
		else
		{
			if (!mib_set(CWMP_CT_MWBAND_MODE, (void *)&enable))
				goto setErr;
			if (!mib_set(CWMP_CT_MWBAND_NUMBER, (void *)&limit))
				goto setErr;

			printf("Enable WAN Limit, num=%d\n", limit);
		}
	}
#endif

#ifdef _PRMT_X_CT_COM_USERINFO_
	// LOID Register Status
	strData = boaGetVar(wp,"txt_reg_status","");
	if (strData[0])
	{
		cnt = strtoul(strData,NULL,10);
		if (!mib_set(CWMP_USERINFO_STATUS, (void *)&cnt)) {
			goto setErr;
		}
		else printf("Update LOID Status to %d \n" , cnt);
	}

	// LOID Register Result
	strData = boaGetVar(wp,"txt_reg_result","");
	if (strData[0])
	{
		cnt = strtoul(strData,NULL,10);
		if (!mib_set(CWMP_USERINFO_RESULT, (void *)&cnt)) {
			goto setErr;
		}
		else printf("Update LOID Result to %d \n" , cnt);
	}
#endif
	// CWMP_CONFIGURABLE
	strData = boaGetVar(wp,"txt_cwmp_conf","");
	if (strData[0])
	{
		unsigned char enable = 0;

		enable = atoi(strData);
		if (!mib_set(CWMP_CONFIGURABLE, (void *)&enable)) {
			goto setErr;
		}
		else printf("Update CWMP_CONFIGURABLE to %d \n" , enable);
	}


	mib_update(CURRENT_SETTING, CONFIG_MIB_ALL);
	mib_update(HW_SETTING, CONFIG_MIB_ALL);


	strData = boaGetVar(wp, "submit-url", "");
	if (strData[0])
		boaRedirect(wp, strData);
	else
		boaDone(wp, 200);


	return;

setErr:
	ERR_MSG("Error Setting...");
}

void formImportOMCIShell(request * wp, char *path, char *query)
{
	char *strRequest;
	unsigned int maxFileSector;
	char tmpBuf[100], *submitUrl;
	struct stat statbuf;

	wp->buffer_end=0; // clear header
   	tmpBuf[0] = '\0';
	FILE	*fp=NULL,*fp_input;
	unsigned char *buf, c;
	unsigned int startPos,endPos,nLen,nRead;
	int ret=-1;

	if (wp->method == M_POST)
	{
		fstat(wp->post_data_fd, &statbuf);
		lseek(wp->post_data_fd, SEEK_SET, 0);
		fp=fopen(wp->post_file_name,"rb");
		if(fp==NULL) goto fail;
	}
	else goto fail;

	do
	{
		if(feof(fp))
		{
			printf("Cannot find start of file\n");
			goto fail;
		}
		c= fgetc(fp);
		if (c!=0xd) continue;
		c= fgetc(fp);
		if (c!=0xa) continue;
		c= fgetc(fp);
		if (c!=0xd) continue;
		c= fgetc(fp);
		if (c!=0xa) continue;
		break;
	}while(1);
	startPos=ftell(fp);
	if(fseek(fp,statbuf.st_size-0x100,SEEK_SET)<0)
		goto fail;
	do
	{
		if(feof(fp))
		{
			printf("Cannot find the end of the file!\n");
			goto fail;
		}
		c= fgetc(fp);
		if (c!='-') continue;
		c= fgetc(fp);
		if (c!='-') continue;
		c= fgetc(fp);
		if (c!='-') continue;
		c= fgetc(fp);
		if (c!='-') continue;
		break;
	}while(1);
	endPos=ftell(fp);
	endPos -= 6;  // Magician

	nLen = endPos - startPos;
	buf = malloc(nLen);
	if (!buf)
	{
		fclose(fp);
		goto end;
	}

	fseek(fp, startPos, SEEK_SET);
	nRead = fread((void *)buf, 1, nLen, fp);
	fclose(fp);
	if (nRead != nLen)
		printf("Read %d bytes, expect %d bytes\n", nRead, nLen);

	fp_input=fopen("/tmp/omcishell","w");
	if (!fp_input)
		printf("Get config file fail!\n");

	fwrite((void *)buf, 1, nLen, fp_input);
	printf("create file omcishell\n");
	free(buf);
	fclose(fp_input);
	system("/bin/sh /tmp/omcishell");
	strcpy(tmpBuf, "OK");
	OK_MSG1(tmpBuf, "/vermod.asp");
	return;
fail:
	if(fp!=NULL)
		fclose(fp);
	OK_MSG1(tmpBuf, "/vermod.asp");
end:

 	return;
}


void formExportOMCIlog(request * wp, char *path, char *query)
{
	char *strRequest;

	char tmpBuf[100], *submitUrl;
	PARAM_HEADER_T header;
	unsigned int maxFileSector = 1024;
	FILE *fp;

	unsigned char *ptr;
	unsigned int fileSize,filelen;
	unsigned int fileSector;
	unsigned char *buf;
	int ret;


	wp->buffer_end=0; // clear header
   	tmpBuf[0] = '\0';

	system("/bin/diag gpon deactivate");
	sleep(1);
	system("/bin/omcicli mib reset");
	sleep(1);
	system("/bin/omcicli set logfile 3 ffffffff");
	system("/bin/diag gpon activate init-state o1");

	ret = sleep(60);
	do
	{
		ret = sleep(ret);
	}while(ret > 0);

	system("/bin/omcicli set logfile 0");
	system("/bin/tar -cf /tmp/omcilog.tar /tmp/omcilog /tmp/omcilog.par");

	ret=-1;

	boaWrite(wp, "HTTP/1.0 200 OK\n");
	boaWrite(wp, "Content-Type: application/octet-stream;\n");

	boaWrite(wp, "Content-Disposition: attachment;filename=\"omcilog.tar\" \n");
#ifdef 	SERVER_SSL
	// IE bug, we can't sent file with no-cache through https
#else
	boaWrite(wp, "Pragma: no-cache\n");
	boaWrite(wp, "Cache-Control: no-cache\n");
#endif
	boaWrite(wp, "\n");


	fp=fopen("/tmp/omcilog.tar","r");

	//decide the file size
	fseek(fp, 0, SEEK_END);
	filelen = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	fileSize=filelen;
	buf = malloc(0x1000);
	if ( buf == NULL ) {
		strcpy(tmpBuf, "Allocate buffer failed!");
		fclose(fp);
		return;
	}
	while(fileSize>0)
	{
		int nRead;
		fileSector = (fileSize>maxFileSector)?maxFileSector:fileSize;
		nRead = fread((void *)buf, 1, fileSector, fp);
		buf[nRead] = 0;
		boaWriteDataNonBlock(wp, buf, nRead);

		fileSize -= fileSector;
		ptr += fileSector;
	}

	free(buf);
	fclose(fp);
 	return;
}
void formTelnetEnable(request * wp, char *path, char *query)
{
#ifdef REMOTE_ACCESS_CTL
	MIB_CE_ACC_T Entry;
	char *strVal;

	if (!mib_chain_get(MIB_ACC_TBL, 0, (void *)&Entry))
	{
		printf("[%s %d]mib_chain_get failed\n", __func__, __LINE__);
		goto set_failed;
	}
	else
	{
		strVal = boaGetVar(wp, "telneten", "");
		if(strVal[0] == '1')
		{
			Entry.telnet = 0x2;
		}
		else if(strVal[0] == '2')
		{
			Entry.telnet = 0x3;
		}
		else
		{
			Entry.telnet = 0x0;
		}
		filter_set_remote_access(0);
		mib_chain_update(MIB_ACC_TBL, (void *)&Entry, 0);
		if(strVal[0] == '2') Commit();
		filter_set_remote_access(1);
	}
#endif

	strVal = boaGetVar(wp, "submit-url", "");
	if (strVal[0])
		boaRedirect(wp, strVal);
	else
		boaDone(wp, 200);

	return;
	
set_failed:
	ERR_MSG("telnet set failed.");
}

void formPingWAN(request * wp, char *path, char *query)
{
#ifdef REMOTE_ACCESS_CTL
	MIB_CE_ACC_T Entry;
	char *strVal;

	if (!mib_chain_get(MIB_ACC_TBL, 0, (void *)&Entry))
	{
		printf("[%s %d]mib_chain_get failed\n", __func__, __LINE__);
		goto set_failed;
	}
	else
	{
		strVal = boaGetVar(wp, "ping_wan", "");
		fprintf(stderr, "[Koala] %s\n", strVal);
		if(strstr(strVal, "on"))
			Entry.icmp = 0x3;
		else
			Entry.icmp = 0x2;

		filter_set_remote_access(0);
		mib_chain_update(MIB_ACC_TBL, (void *)&Entry, 0);
		filter_set_remote_access(1);
	}
#endif

	strVal = boaGetVar(wp, "submit-url", "");
	if (strVal[0])
		boaRedirect(wp, strVal);
	else
		boaDone(wp, 200);

	return;
	
set_failed:
	ERR_MSG("telnet set failed.");
}


void formpktmirrorEnable(request * wp, char *path, char *query)
{
	char *strVal;
	strVal = boaGetVar(wp, "pktmirroren", "");
	if(strVal[0] == '0')
	{
		#ifdef CONFIG_RTL9600_SERIES
		#if CONFIG_LAN_PORT_NUM==2
		system("diag mirror set mirroring-port 3 mirrored-port 4 rx-mirror tx-mirror");
		#else
		system("diag mirror set mirroring-port 0 mirrored-port 4 rx-mirror tx-mirror");
		#endif
		#else // RTL9602C
		system("diag mirror set mirroring-port 1 mirrored-port 2 rx-mirror tx-mirror");
		#endif
	}
	else if(strVal[0] == '1')
	{
		#ifdef CONFIG_RTL9600_SERIES
		#if CONFIG_LAN_PORT_NUM==2
		system("diag mirror set mirroring-port 3 mirrored-port 4,6 rx-mirror tx-mirror");
		#else
		system("diag mirror set mirroring-port 0 mirrored-port 4,6 rx-mirror tx-mirror");
		#endif
		#else // RTL9602C
		system("diag mirror set mirroring-port 1 mirrored-port 2,3 rx-mirror tx-mirror");
		#endif
	}
	
    strVal = boaGetVar(wp, "submit-url", "");
	if (strVal[0])
		boaRedirect(wp, strVal);
	else
		boaDone(wp, 200);

	return;

set_failed:
        ERR_MSG("Mirror set failed.");
}
int RestoreFactoryMode(int eid, request * wp, int argc, char **argv)
{
	int nBytesSent = 0;
	unsigned char reg_type = DEV_REG_TYPE_DEFAULT;
	mib_get(PROVINCE_DEV_REG_TYPE, &reg_type);
	if(reg_type != DEV_REG_TYPE_AH){
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
		nBytesSent += boaWrite(wp, "<input class=\"btnsaveup\" type=\"submit\" value=\"恢复出厂配置\" onClick=\"return on_click_button(1)\">");
#elif defined(CONFIG_YUEME)
		nBytesSent += boaWrite(wp, "<input type=\"submit\" value=\"恢复出厂配置\" onClick=\"return on_click_button(3)\">");
#else
		nBytesSent += boaWrite(wp, "<input type=\"submit\" value=\"恢复出厂配置\" onClick=\"return on_click_button(3)\">");
#endif
	}
	else
		nBytesSent += boaWrite(wp, "</br>");
	return nBytesSent;
}

#ifdef CONFIG_YUEME
int pluginLogList(int eid, request * wp, int argc, char ** argv)
{
	char *tmp1, tmpbuf[1024], dateTime[32], pluginlog[1024];
	FILE *fp;
	int nBytesSent = 0;

	_TRACE_CALL;

	if ((fp = fopen("/tmp/plugin.log", "r")) == NULL)
		goto check_err;

	_TRACE_POINT;
	while (fgets(tmpbuf, sizeof(tmpbuf), fp)) {
		tmpbuf[strlen(tmpbuf) - 1] = '\0';

		memset(dateTime, '\0', 32);

		/* get dateTime */
		memcpy(dateTime, tmpbuf, sizeof("YYYY-MM-DD HH:MM:SS") - 1);

		tmp1 = tmpbuf + sizeof("YYYY-MM-DD HH:MM:SS");

		memset(pluginlog, '\0', 1024);
		
		memcpy(pluginlog, tmp1, strlen(tmpbuf) - sizeof("YYYY-MM-DD HH:MM:SS"));

		nBytesSent += boaWrite(wp, "rcs.push(new Array(\"%s\", \"%s\"));\n",
				dateTime, pluginlog);
	}

	fclose(fp);

check_err:
	_TRACE_LEAVEL;
	return nBytesSent;
}

int pluginModuleList(int eid, request * wp, int argc, char ** argv)
{
	char tmpbuf[1024], appname[1024];
	FILE *fp;
	int nBytesSent = 0;
	unsigned int sts;

	_TRACE_CALL;

	va_cmd("/bin/get_plugin_module", 0, 1);
	
	if ((fp = fopen("/tmp/applist_query", "r")) == NULL)
		goto check_err;

	_TRACE_POINT;
	while (fgets(tmpbuf, sizeof(tmpbuf), fp)) {
		tmpbuf[strlen(tmpbuf) - 1] = '\0';
		
		memset(appname, '\0', 1024);

		sscanf(tmpbuf, "%s %u", appname, &sts);

		nBytesSent += boaWrite(wp, "rcs.push(new Array(\"%s\", \"%s\"));\n",
				appname, sts? "RUNNING":"STOPPED");
	}
	fclose(fp);

check_err:
	_TRACE_LEAVEL;
	return nBytesSent;
}
#endif

