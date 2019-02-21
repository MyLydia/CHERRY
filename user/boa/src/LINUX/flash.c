#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include "utility.h"
#include "sysconfig.h"
#include "rtl_flashdrv_api.h"

#define error -1

#ifdef USE_11N_UDP_SERVER
static unsigned char udp_server_cmd = 0;

static int to_hex_string(char *string)
{
	char tostr[256];
	int i, k;

	for (i = 0, k = 0; i < 256 && string[i] != '\0'; i++) {
		if (string[i] != ',' && string[i] != ' ')
			tostr[k++] = string[i];
	}
	tostr[k] = '\0';
	strcpy(string, tostr);

	return 1;
}
#endif

static void showHelp(void)
{
	printf("Usage: flash cmd\n");
	printf("cmd:\n");
	printf("  info \t\t\t\tshow flash offset information.\n");
	printf("  loop \t\t\t\tenter a infinite loop.\n");
	printf("  get <MIB-NAME> [...] \t\tget the specific mib from flash memory.\n");
	printf("    Example:\n");
	printf("      get NTP_ENABLED \t\tget the specific mib table entry from flash memory.\n");
	printf("      get ATM_VC_TBL \t\tget all the specific mib chain records from flash memory.\n");
	printf("      get ATM_VC_TBL.NUM \tget the specific mib chain record size from flash memory.\n");
	printf("      get ATM_VC_TBL.0.ifIndex \tget the specific member of the mib chain record from flash memory.\n");
	printf("  set <MIB-NAME MIB-VALUE> [...]set the specific mib into flash memory.\n");
	printf("    Example:\n");
	printf("      set NTP_ENABLED 0 \tset the specific mib table entry into flash memory.\n");
	printf("      set ATM_VC_TBL.1.vpi 8 \tset the specific member of the mib chain recrod into flash memory.\n");
	printf("  add <MIB-CHAIN-NAME> [...] \tadd mib chain record(s) into flash memory.\n");
	printf("    Example:\n");
	printf("      add ATM_VC_TBL \t\tadd a mib chain record into flash memory.\n");
	printf("      add ATM_VC_TBL.2 \t\tadd mib chain record(s) into flash memory.\n");
	printf("  del <MIB-CHAIN-NAME> [...] \tdelete mib chain record(s) into flash memory.\n");
	printf("    Example:\n");
	printf("      del ATM_VC_TBL \t\tdelete the last mib chain record into flash memory.\n");
	printf("      del ATM_VC_TBL.2 \t\tdelete the specific mib chain record into flash memory.\n");
	printf("  all [cs|hs] \t\t\tdump all flash parameters.\n");
#if !defined(CONFIG_USER_XMLCONFIG) && !defined(CONFIG_USER_CONF_ON_XMLFILE)
#ifdef CAN_RW_FILE
	printf("  rds <FILENAME> \t\t\tread flash parameters from default settings to FILENAME.\n");
	printf("  rcs <FILENAME> \t\t\tread flash parameters from current settings to FILENAME.\n");
	printf("  rhs <FILENAME> \t\t\tread flash parameters from hardware settings to FILENAME.\n");
	printf("  wds <FILENAME> \t\t\twrite flash parameters from FILENAME to default settings.\n");
	printf("  wcs <FILENAME> \t\t\twrite flash parameters from FILENAME to current settings.\n");
	printf("  whs <FILENAME> \t\t\twrite flash parameters from FILENAME to hardware settings.\n");
#endif
	printf("  check \t\t\tcheck flash setting.\n");
	printf("  dump <cs/hs> \t\t\tdump flash setting.\n");
	printf("  reset \t\t\treset current setting to default.\n");
#endif
	printf("  default <cs/hs> \t\twrite program default value to flash.\n");
	printf("  clear \t\t\tclear flash setting.\n");
#ifdef VOIP_SUPPORT
	printf("  voip \t\t\t\tvoip setings.\n");
#endif /*VOIP_SUPPORT*/
	printf("  r <OFFSET> \t\t\tread flash from <OFFSET>.\n");
	printf("  w <OFFSET> <VALUE> \t\twrite flash to <OFFSET>.\n");
	printf("  erase <OFFSET> \t\terase flash from <OFFSET>.\n");
}

/*
 *	Copy or map mib name.
 *	Return mib_table index on success or -1 on error.
 */
static CONFIG_MIB_T mib_name_resolve(char *from, char *to)
{
	CONFIG_MIB_T ret;
	int i;
	char *end;

	if ((!strncmp(from, "HW_NIC0_ADDR", 12)) || (!strncmp(from, "HW_WLAN0_WLAN_ADDR", 18))) {
		strcpy(to, "ELAN_MAC_ADDR");
	} else if ((!strncmp(from, "HW_NIC1_ADDR", 12)) || (!strncmp(from, "HW_WLAN1_WLAN_ADDR", 18))) {
		strcpy(to, "ELAN_MAC_ADDR");
	} else
		strcpy(to, from);

	end = strchr(to, '.');

	if (end)
		*end = '\0';

	for (i = 0; mib_table[i].id; i++) {
		if (!strcmp(mib_table[i].name, to))
			break;
	}

	if (mib_table[i].id) {
		ret = CONFIG_MIB_TABLE;
		goto ret;
	}

	for (i = 0; mib_chain_record_table[i].id; i++) {
		if (!strcmp(mib_chain_record_table[i].name, to))
			break;
	}

	if (mib_chain_record_table[i].id) {
		ret = CONFIG_MIB_CHAIN;
		goto ret;
	}

	ret = CONFIG_MIB_ALL;
ret:
	/* restore the '.' */
	if (end)
		*end = '.';

	return ret;
}

/*
 * Get MIB Value
 */
static int mib_chain_get_by_name(char *name, char *value)
{
	int i, j, k, recordNum, total;
	int id = -1;
	mib_chain_member_entry_T *rec_desc;
	unsigned char *chainEntry;
	char *mib_chain_name, *record_num, *member;

	mib_chain_name = strtok(name, ".");
	record_num = strtok(NULL, ".");
	member = strtok(NULL, ".");
	
	if (mib_chain_name == NULL)
		return 0;

	for (i = 0; mib_chain_record_table[i].id; i++) {
		if (!strcmp(mib_chain_record_table[i].name, mib_chain_name)) {
			id = mib_chain_record_table[i].id;
			break;
		}
	}

	if (id == -1)
		return 0;

	total = _mib_chain_total(id);

	if (record_num) {
		if (!strcmp("NUM", record_num)) {
			sprintf(value, "%s.NUM=%d", mib_chain_name, total);
			return 1;
		}

		recordNum = strtoul(record_num, NULL, 0);
	} else {
		recordNum = -1;
	}
	value[0] = '\0';

	if (recordNum < total) {
		if (mib_chain_record_table[i].record_desc == NULL) {
			printf("Empty mib chain %s descriptor !\n", mib_chain_name);
			return 0;
		}

		rec_desc = mib_chain_record_table[i].record_desc;

		for (j = 0; j < total; j++) {
			if (j < recordNum)
				continue;

			chainEntry = _mib_chain_get(id, j);

			if (!member)
				printf("%s.%d:\n", mib_chain_name, j);

			for (k = 0; rec_desc[k].name[0]; k++) {
				if (member) {
					if (strcmp(member, rec_desc[k].name))
						continue;
					print_chain_member(stdout, "%s=%s\n", &rec_desc[k], chainEntry + rec_desc[k].offset, 0);
				}
				else
					print_chain_member(stdout, "%-18s = %s\n", &rec_desc[k], chainEntry + rec_desc[k].offset, 0);
			}

			/* OK, done */
			if (j == recordNum)
				break;

			printf("\n");
		}
	} else
		printf("out of range !\n");

	return 1;
}

static int mib_table_get_by_name(char *name, char *buffer)
{
	int i, id = -1;
	unsigned char mibvalue[1024];

	for (i = 0; mib_table[i].id; i++) {
		if (!strcmp(mib_table[i].name, name)) {
			id = mib_table[i].id;
			break;
		}
	}

	if (id == -1)
		return 0;

	memset(mibvalue, 0x00, sizeof(mibvalue));

	/* fails */
	if (_mib_get(id, mibvalue) == 0)
		return 0;

	mib_to_string(buffer, mibvalue, mib_table[i].type, mib_table[i].size);

#ifdef USE_11N_UDP_SERVER
	if (mib_table[i].type == BYTE_ARRAY_T && udp_server_cmd)
		to_hex_string(buffer);
#endif

	return 1;
}

/*
 *	Get mib_table index by mibname.
 *	Return mib_table index on success or -1 on error.
 */
static int mib_table_index(char *mibname)
{
	int index;

	for (index = 0; mib_table[index].id; index++) {
		if (!strcmp(mib_table[index].name, mibname))
			break;
	}
	if (mib_table[index].id == 0)
		index = -1;

	return index;
}

/*
 *	Get mib value according to av list.
 *	index: mib_table index
 *	count: argument count
 *	av: list of argument; first argument is mib_name
 *	value: return value
 */
static int mib_table_value_resolve(int index, int count, char **av, char *value)
{
	int avNum = 0;
	unsigned char pwr;

	value[0] = 0;

	if (mib_table[index].type == BYTE_ARRAY_T && !memcmp((av[avNum] + 9), "TX_POWER", 8) && count >= 15) {
		// wifi hw rf parameter; translate to HEX string
		//printf("get %s , count : %d , avNum : %d \n " , av[avNum], count, avNum);
		avNum++;
		while ((avNum < count) && (avNum < 200)) {
			pwr = strtoul(av[avNum++], NULL, 0);
			sprintf(value, "%s%02x", value, pwr);
		}
	} else {
		avNum++;
		strcpy(value, av[avNum++]);
	}

	return avNum;
}

/*
 * Set MIB Value
 */
static CONFIG_DATA_T mib_table_set_by_index(int index, char *buffer)
{
	int id;
	unsigned char mibvalue[1024];
	CONFIG_DATA_T cdtype;

	id = mib_table[index].id;
	cdtype = mib_table[index].mib_type;

	string_to_mib(mibvalue, buffer, mib_table[index].type, mib_table[index].size);

	if (_mib_set(id, mibvalue))
		return cdtype;
	else
		return 0;
}

static CONFIG_DATA_T mib_chain_set_by_name(char *name, char *buffer)
{
	int i, j, recordNum, total;
	int id = -1;
	mib_chain_member_entry_T *rec_desc;
	unsigned char *chainEntry;
	char *mib_chain_name, *record_num, *member;

	mib_chain_name = strtok(name, ".");
	record_num = strtok(NULL, ".");
	member = strtok(NULL, ".");
	
	if (mib_chain_name == NULL || record_num == NULL || member == NULL || buffer == NULL) {
		showHelp();
		return 0;
	}

	for (i = 0; mib_chain_record_table[i].id; i++) {
		if (!strcmp(mib_chain_record_table[i].name, mib_chain_name)) {
			id = mib_chain_record_table[i].id;
			break;
		}
	}

	if (id == -1)
		return 0;

	total = _mib_chain_total(id);

	recordNum = strtoul(record_num, NULL, 0);

	if (recordNum < total) {
		if (mib_chain_record_table[i].record_desc == NULL) {
			printf("Empty mib chain %s descriptor !\n", mib_chain_name);
			return 0;
		}

		rec_desc = mib_chain_record_table[i].record_desc;

		chainEntry = _mib_chain_get(id, recordNum);

		for (j = 0; rec_desc[j].name[0]; j++) {
			if (!strcmp(member, rec_desc[j].name)) {
				if (string_to_mib(chainEntry + rec_desc[j].offset, buffer, rec_desc[j].type, rec_desc[j].size))
					printf("Setting mib chain: %s.%s.%s fails !!\n",
							mib_chain_name, record_num, member);
				else
					printf("Setting mib chain: %s.%s.%s succeed !!\n",
							mib_chain_name, record_num, member);
				break;
			}
		}
	} else
		printf("out of range !\n");

	return mib_chain_record_table[i].mib_type;
}

static CONFIG_DATA_T mib_chain_add_by_name(char *name)
{
	int i, j, recordNum, total;
	int id = -1;
	unsigned char *chainEntry;
	char *mib_chain_name, *record_num;

	mib_chain_name = strtok(name, ".");
	record_num = strtok(NULL, ".");
	
	if (mib_chain_name == NULL) {
		showHelp();
		return 0;
	}

	for (i = 0; mib_chain_record_table[i].id; i++) {
		if (!strcmp(mib_chain_record_table[i].name, mib_chain_name)) {
			id = mib_chain_record_table[i].id;
			break;
		}
	}

	if (id == -1)
		return 0;

	total = _mib_chain_total(id);

	if (record_num)
		recordNum = strtoul(record_num, NULL, 0);
	else
		recordNum = total;

	chainEntry = calloc(1, mib_chain_record_table[i].per_record_size);

	if (chainEntry == NULL)
		return 0;

	for (j = total; j <= recordNum; j++) {
		if (_mib_chain_add(id, chainEntry) == 0) {
			printf("Adding mib chain: %s fails !!\n", mib_chain_name);
			free(chainEntry);
			return 0;
		}
	}

	free(chainEntry);

	total = _mib_chain_total(id);
	printf("%s.NUM=%d\n", mib_chain_name, total);

	return mib_chain_record_table[i].mib_type;
}

static CONFIG_DATA_T mib_chain_del_by_name(char *name)
{
	int i, recordNum, total;
	int id = -1;
	char *mib_chain_name, *record_num;

	mib_chain_name = strtok(name, ".");
	record_num = strtok(NULL, ".");
	
	if (mib_chain_name == NULL) {
		showHelp();
		return 0;
	}

	for (i = 0; mib_chain_record_table[i].id; i++) {
		if (!strcmp(mib_chain_record_table[i].name, mib_chain_name)) {
			id = mib_chain_record_table[i].id;
			break;
		}
	}

	if (id == -1)
		return 0;

	total = _mib_chain_total(id);

	if (record_num)
		recordNum = strtoul(record_num, NULL, 0);
	else
		recordNum = total - 1;

	if (_mib_chain_delete(id, recordNum) == 0) {
		printf("Deleting mib chain: %s, record number: %d fails !!\n", mib_chain_name, recordNum);
		return 0;
	}

	total = _mib_chain_total(id);
	printf("%s.NUM=%d\n", mib_chain_name, total);

	return mib_chain_record_table[i].mib_type;
}

/*
 * Get all MIB Value
 */
static void mib_get_all(void)
{
	int i, total;
	char buffer[2048];

	/* -------------------------------------------
	 *      mib chain
	 * -------------------------------------------*/
	printf("---------------------------------------------------------\n");
	printf("MIB Chain Information\n");
	printf("---------------------------------------------------------\n");
	printf("%4s %-26s %12s %5s %5s\n", "ID", "Name", "size/record", "Num", "Max");
	for (i = 0; mib_chain_record_table[i].id; i++) {
		total = _mib_chain_total(mib_chain_record_table[i].id);
		printf("%4d %-26s %12d %5d %5d\n", mib_chain_record_table[i].id,
		       mib_chain_record_table[i].name,
		       mib_chain_record_table[i].per_record_size, total,
		       mib_chain_record_table[i].table_size);
	}
	printf("Header length per Chain record: %d bytes\n", sizeof(MIB_CHAIN_RECORD_HDR_T));
	/* -------------------------------------------
	 *      mib table
	 * -------------------------------------------*/
	printf("\n---------------------------------------------------------\n");
	printf("MIB Table Information\n");
	printf("---------------------------------------------------------\n");
	for (i = 0; mib_table[i].id; i++) {
		if (mib_table[i].mib_type != RUNNING_SETTING
		    && mib_table_get_by_name(mib_table[i].name, buffer) != 0) {
			printf("%s=%s\n", mib_table[i].name, buffer);
		}
	}
	printf("---------------------------------------------------------\n");
	printf("Total size: %d bytes\n", sizeof(MIB_T));
}

static void mib_get_all_by_type(CONFIG_DATA_T data_type)
{
	int i;
	char buffer[2048];

	printf("\n---------------------------------------------------------\n");
	printf("MIB Table Information(%d)\n", data_type);
	printf("---------------------------------------------------------\n");
	for (i = 0; mib_table[i].id; i++) {
		if ((mib_table[i].mib_type & data_type) && mib_table_get_by_name(mib_table[i].name, buffer) != 0) {
			printf("%s=%s\n", mib_table[i].name, buffer);
		}
	}
}

#ifdef CAN_RW_FILE
#if !defined(CONFIG_USER_XMLCONFIG) && !defined(CONFIG_USER_CONF_ON_XMLFILE)
static int flash_read_to_file(CONFIG_DATA_T data_type, const char *filename)
{
	size_t len;
	unsigned char *buf;
	int fh, ret = 0;
	PARAM_HEADER_Tp pHeader = __mib_get_mib_header(data_type);

	fh = open(filename, O_CREAT | O_RDWR);
	if (fh == -1) {
		printf("open file fail!\n");
		return 0;
	}

	len = sizeof(PARAM_HEADER_T) + pHeader->len;	// total len = Header + MIB data
	buf = malloc(len);

	if (buf == NULL) {
		printf("malloc fail!\n");
		goto error;
	}

	switch (data_type) {
	case CURRENT_SETTING:
		if (flash_read(buf, g_cs_offset, len) == 0) {
			printf("flash read fail!\n");
			goto error;
		}
		break;
	case DEFAULT_SETTING:
		if (flash_read(buf, DEFAULT_SETTING_OFFSET, len) == 0) {
			printf("flash read fail!\n");
			goto error;
		}
		break;
	case HW_SETTING:
		if (flash_read(buf, HW_SETTING_OFFSET, len) == 0) {
			printf("flash read error!\n");
			goto error;
		}
		break;
	default:
		goto error;
	}

	lseek(fh, 0, SEEK_SET);

	if (write(fh, buf, len) != len) {
		printf("write file fail!\n");
		goto error;
	}

	ret = 1;
error:
	if (buf)
		free(buf);
	close(fh);
	sync();

	return ret;
}

static int flash_write_from_file(CONFIG_DATA_T data_type, char *filename)
{
	int fh, ret = 0;
	off_t size;
	unsigned char *buf;
	unsigned char *ptr;
	PARAM_HEADER_Tp pFileHeader;
	PARAM_HEADER_Tp pHeader = __mib_get_mib_header(data_type);

	fh = open(filename, O_RDONLY);
	if (fh == -1) {
		printf("open file fail!\n");
		return 0;
	}

	size = lseek(fh, 0, SEEK_END);
	lseek(fh, 0, SEEK_SET);

	buf = malloc(size);

	if (buf == NULL) {
		printf("malloc fail!\n");
		goto error;
	}

	if (read(fh, buf, size) != size) {
		printf("read file fail!\n");
		goto error;
	}

	pFileHeader = (PARAM_HEADER_Tp) buf;

	if (memcmp(pFileHeader->signature, pHeader->signature, SIGNATURE_LEN)) {
		printf("file signature error!\n");
		goto error;
	}

	if (pFileHeader->len != pHeader->len) {
		printf("file size mismatch!\n");
		goto error;
	}

	ptr = &buf[sizeof(PARAM_HEADER_T)];	// point to start of MIB data
	DECODE_DATA(ptr, pFileHeader->len);

	if (pFileHeader->checksum != CHECKSUM(ptr, pFileHeader->len)) {
		printf("checksum error!\n");
		goto error;
	}

	if (_mib_update_from_raw(buf, size) == 0) {
		printf("flash write error!\n");
		goto error;
	}

	ret = 1;
error:
	if (buf)
		free(buf);
	close(fh);

	return ret;
}
#endif
#endif // #ifdef CAN_RW_FILE

static int info_func(int argc, char *argv[])
{
#if !defined(CONFIG_USER_XMLCONFIG) && !defined(CONFIG_USER_CONF_ON_XMLFILE)
	printf("CS offset = %x\n", g_cs_offset);
	printf("DS offset = %x\n", DEFAULT_SETTING_OFFSET);
	printf("HS offset = %x\n", HW_SETTING_OFFSET);
	printf("WEB offset = %x\n", WEB_PAGE_OFFSET);
#endif
	// 20130315 W.H. Hung
#ifndef CONFIG_LUNA_FIRMWARE_UPGRADE_SUPPORT
	printf("CODE offset = %x\n", g_rootfs_offset);
#ifdef CONFIG_DOUBLE_IMAGE
	printf("CODE Backup offset = %x\n", g_fs_bak_offset);
#endif
#endif

	return 0;
}

static int loop_func(int argc, char *argv[])
{
	while (1);

	return 0;
}

static int get_func(int argc, char *argv[])
{
	int argNum, ret = 0;
	char mib[100];
	char buffer[2048];
	CONFIG_MIB_T flag;

	if (argc < 2) {
		showHelp();
		return error;
	}

	for (argNum = 1; argNum < argc; argNum++) {
		flag = mib_name_resolve(argv[argNum], mib);
#ifdef USE_11N_UDP_SERVER
		if (!strncmp(mib, "HW_WLAN", 7))
			udp_server_cmd = 1;
#endif
		if (flag == CONFIG_MIB_CHAIN && mib_chain_get_by_name(mib, buffer) != 0) {
			printf("%s\n", buffer);
		} else if (flag == CONFIG_MIB_TABLE && mib_table_get_by_name(mib, buffer) != 0) {
			printf("%s=%s\n", mib, buffer);
		} else {
			ret = error;
		}
#ifdef USE_11N_UDP_SERVER
		udp_server_cmd = 0;
#endif
	}

	return ret;
}

static int set_func(int argc, char *argv[])
{
	CONFIG_DATA_T tmpType = UNKNOWN_SETTING;
	CONFIG_DATA_T cdType = UNKNOWN_SETTING;
	int argNum, index, ret = 0;
	char mib[100];
	char buffer[2048];
	CONFIG_MIB_T flag;

	if (argc < 3) {
		showHelp();
		return error;
	}

	for (argNum = 1; (argNum + 1) < argc;) {
		flag = mib_name_resolve(argv[argNum], mib);

		if (flag == CONFIG_MIB_TABLE) {
			if ((index = mib_table_index(mib)) == -1) {
				printf("mib name error: %s\n", mib);
				return error;
			}

			argNum += mib_table_value_resolve(index, argc - argNum, &argv[argNum], buffer);

			if ((tmpType = mib_table_set_by_index(index, buffer)) != 0) {
				cdType |= tmpType;
				printf("set %s=%s\n", mib, buffer);
			} else {
				printf("set %s=%s fail!\n", mib, buffer);
				ret = error;
			}
		} else if (flag == CONFIG_MIB_CHAIN) {
			if ((tmpType = mib_chain_set_by_name(mib, argv[argNum + 1])) != 0) {
				cdType |= tmpType;
				printf("set %s=%s\n", argv[argNum], argv[argNum + 1]);
			} else {
				printf("set %s=%s fail!\n", argv[argNum], argv[argNum + 1]);
				ret = error;
			}

			argNum += 2;
		}
	}

	if ((cdType & CURRENT_SETTING) && _mib_update(CURRENT_SETTING) == 0) {
		printf("CS Flash error! \n");
		ret = error;
	}

	if ((cdType & HW_SETTING) && _mib_update(HW_SETTING) == 0) {
		printf("HS Flash error! \n");
		ret = error;
	}

	return ret;
}

static int add_del_func(int argc, char *argv[])
{
	CONFIG_DATA_T tmpType = UNKNOWN_SETTING;
	CONFIG_DATA_T cdType = UNKNOWN_SETTING;
	int argNum, ret = 0;
	char mib[100];
	CONFIG_MIB_T flag;
	CONFIG_DATA_T (*func)(char *);

	if (argc < 2) {
		showHelp();
		return error;
	}

	if (!strcmp(argv[0], "add"))
		func = mib_chain_add_by_name;
	else if (!strcmp(argv[0], "del"))
		func = mib_chain_del_by_name;
	else
		return error;

	for (argNum = 1; argNum < argc; argNum++) {
		flag = mib_name_resolve(argv[argNum], mib);

		if (flag == CONFIG_MIB_CHAIN) {
			if ((tmpType = func(mib)) != 0)
				cdType |= tmpType;
			else
				ret = error;
		}
	}

	if ((cdType & CURRENT_SETTING) && _mib_update(CURRENT_SETTING) == 0) {
		printf("CS Flash error! \n");
		ret = error;
	}

	if ((cdType & HW_SETTING) && _mib_update(HW_SETTING) == 0) {
		printf("HS Flash error! \n");
		ret = error;
	}

	return ret;
}

static int all_func(int argc, char *argv[])
{
	if (argc == 1) {
		mib_get_all();
	} else {
		if (!strcmp(argv[1], "hs"))
			mib_get_all_by_type(HW_SETTING);
		else if (!strcmp(argv[1], "cs"))
			mib_get_all_by_type(CURRENT_SETTING);
		else
			mib_get_all_by_type(UNKNOWN_SETTING);
	}

	return 0;
}

#if !defined(CONFIG_USER_XMLCONFIG) && !defined(CONFIG_USER_CONF_ON_XMLFILE)
#ifdef CAN_RW_FILE
static int rs_func(int argc, char *argv[])
{
	CONFIG_DATA_T data_type;
	int ret = 0;

	if (argc < 2) {
		showHelp();
		return error;
	}

	if (!strcmp(argv[0], "rds")) {
		data_type = DEFAULT_SETTING;
	} else if (!strcmp(argv[0], "rcs")) {
		data_type = CURRENT_SETTING;
	} else if (!strcmp(argv[0], "rhs")) {
		data_type = HW_SETTING;
	} else {
		return error;
	}

	if (flash_read_to_file(data_type, argv[1]) == 0) {
		printf("flash_read_to_file fail!\n");
		ret = error;
	}

	return ret;
}

static int ws_func(int argc, char *argv[])
{
	CONFIG_DATA_T data_type;
	int ret = 0;

	if (argc < 2) {
		showHelp();
		return error;
	}

	if (!strcmp(argv[0], "wds")) {
		data_type = DEFAULT_SETTING;
	} else if (!strcmp(argv[0], "wcs")) {
		data_type = CURRENT_SETTING;
	} else if (!strcmp(argv[0], "whs")) {
		data_type = HW_SETTING;
	} else {
		return error;
	}

	if (flash_write_to_file(data_type, argv[1]) == 0) {
		printf("flash_write_to_file fail!\n");
		ret = error;
	}

	return ret;
}
#endif

static int check_func(int argc, char *argv[])
{
	int i;
	PARAM_HEADER_T header;
	CONFIG_DATA_T data_type;
	char *pFlashBank;
	unsigned int fileSize = 0, reset_flash;
	unsigned char *pFile = NULL;
	unsigned char *pContent = NULL;
	// Kaohj, check for mib chain
	unsigned char *pVarLenTable = NULL;
	unsigned int contentMinSize = 0;
	unsigned int varLenTableSize = 0;
	unsigned int errCheck = 0;

	for (i = 0; i < 3; i++) {
		if (i == 0) {
			data_type = CURRENT_SETTING;
			pFlashBank = "CS_BANK";
		} else if (i == 1) {
			data_type = DEFAULT_SETTING;
			pFlashBank = "DS_BANK";

			// Added by Mason Yu. Not use default seetting.
			continue;
		} else if (i == 2) {
			data_type = HW_SETTING;
			pFlashBank = "HS_BANK";
#ifdef FORCE_HS
			continue;
#endif
		}
		reset_flash = 0;

check_flash:
		if (__mib_header_read(data_type, &header) != 1)
			goto flash_check_error;

		if (__mib_header_check(data_type, &header) != 1)
			goto flash_check_error;

		fileSize = header.len + sizeof(PARAM_HEADER_T);
		pFile = malloc(fileSize);
		if (pFile == NULL)
			goto error_return;

		if (__mib_file_read(data_type, pFile, fileSize) != 1) {
			free(pFile);
			goto flash_check_error;
		}

		pContent = &pFile[sizeof(PARAM_HEADER_T)];	// point to start of MIB data

		if (__mib_content_decod_check(data_type, &header, pContent) != 1) {
			free(pFile);
			goto flash_check_error;
		}
		// Kaohj, check for mib chain
		contentMinSize = __mib_content_min_size(data_type);
		varLenTableSize = header.len - contentMinSize;
		if (varLenTableSize > 0) {
			pVarLenTable = &pContent[contentMinSize];	// point to start of variable length MIB data

			// parse variable length MIB data
			if (__mib_chain_record_content_decod(pVarLenTable, varLenTableSize) != 1) {
				free(pFile);
				//printf("mib_chain_record decode fail !\n");
				goto flash_check_error;
			}
		}

		free(pFile);
		printf("%s ok! (minsize=%d, varsize=%d)\n", pFlashBank, contentMinSize, varLenTableSize);
		continue;
flash_check_error:
		if (!reset_flash) {	//not reset yet
			if (mib_init_mib_with_program_default(data_type, FLASH_DEFAULT_TO_AUGMENT)) {	//try to reset flash
				printf("%s check fail! Reset to default\n", pFlashBank);
				reset_flash = 1;
				errCheck |= data_type;
				goto check_flash;	//check again
			} else
				printf("%s reset to default fail.\n", pFlashBank);
		};
error_return:
		printf("%s fail!\n", pFlashBank);
		printf("flash_check=0\n");
		return -1;
	}
#ifdef CONFIG_USER_RTK_RECOVER_SETTING
	if (errCheck) {
		FILE *fp;
		fp = fopen(FLASH_CHECK_FAIL, "w");
		if (fp) {
			fprintf(fp, "%d\n", errCheck);
			fclose(fp);
		}
	}
#endif
	printf("flash_check=1\n");
	return 0;
}

static int dump_func(int argc, char *argv[])
{
	PARAM_HEADER_T header;
	unsigned int fileSize, i;
	unsigned char *pFile = NULL;
	CONFIG_DATA_T data_type;
	int file_offset, table_size;
	char tdata[SIGNATURE_LEN + 1];

	if (argc < 2) {
		printf("command error!\n");
		showHelp();
		return error;
	}

	if (!strcmp(argv[1], "ds")) {
		data_type = DEFAULT_SETTING;
		file_offset = DEFAULT_SETTING_OFFSET;
		table_size = sizeof(MIB_T);
	} else if (!strcmp(argv[1], "cs")) {
		data_type = CURRENT_SETTING;
		file_offset = g_cs_offset;
		table_size = sizeof(MIB_T);
	} else if (!strcmp(argv[1], "hs")) {
		data_type = HW_SETTING;
		file_offset = HW_SETTING_OFFSET;
		table_size = sizeof(HW_MIB_T);
	} else {
		return error;
	}

	if (__mib_header_read(data_type, &header) != 1)
		return error;

	fileSize = header.len + sizeof(PARAM_HEADER_T);
	pFile = malloc(fileSize);
	if (pFile == NULL)
		return error;

	if (__mib_file_read(data_type, pFile, fileSize) != 1) {
		free(pFile);
		return error;
	}

	printf("Header Length: %u\tData Length: %u (Table=%d, Chain=%d)\n",
			sizeof(PARAM_HEADER_T), header.len, table_size,
			header.len - table_size);
	for (i = 0; i < SIGNATURE_LEN; i++)
		tdata[i] = pFile[i];
	tdata[SIGNATURE_LEN] = '\0';
	printf("Signature: %s\nVersion: %hhu\nChecksum: 0x%.2x\nLength: %u\n",
			tdata, header.version, header.checksum, header.len);
	printf("------------------ Header+Data ------------------------\n");
	for (i = 0; i < fileSize; i += 16) {
		//printf("%d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d\n"
		printf
			("%.5x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x\n",
			 file_offset + i, pFile[i], pFile[i + 1],
			 pFile[i + 2], pFile[i + 3], pFile[i + 4],
			 pFile[i + 5], pFile[i + 6], pFile[i + 7],
			 pFile[i + 8], pFile[i + 9], pFile[i + 10],
			 pFile[i + 11], pFile[i + 12], pFile[i + 13],
			 pFile[i + 14], pFile[i + 15]);
	}

	free(pFile);

	return 0;
}

static int reset_func(int argc, char *argv[])
{
	int ret = 0;

	if (mib_reset(CURRENT_SETTING) != 0) {
		printf("reset current settings\n");
	} else {
		printf("reset current settings fail!\n");
		ret = error;
	}

	return ret;
}
#endif

static int default_func(int argc, char *argv[])
{
	if (argc < 2) {
		printf("command error!\n");
		showHelp();
		return error;
	}

	if (!strcmp(argv[1], "ds")) {
		mib_init_mib_with_program_default(DEFAULT_SETTING, FLASH_DEFAULT_TO_ALL);
	} else if (!strcmp(argv[1], "cs")) {
		mib_init_mib_with_program_default(CURRENT_SETTING, FLASH_DEFAULT_TO_ALL);
	} else if (!strcmp(argv[1], "hs")) {
		mib_init_mib_with_program_default(HW_SETTING, FLASH_DEFAULT_TO_ALL);
	}

	return 0;
}

static int clear_func(int argc, char *argv[])
{
#if defined(CONFIG_USER_XMLCONFIG)
	unlink(LASTGOOD_FILE);
	unlink(LASTGOOD_HS_FILE);
#elif defined(CONFIG_USER_CONF_ON_XMLFILE)
	unlink(CONF_ON_XMLFILE);
	unlink(CONF_ON_XMLFILE_HS);
#else
	unsigned char buf[] = "CLEAR";

	flash_write(buf, g_cs_offset, sizeof(buf));
	flash_write(buf, DEFAULT_SETTING_OFFSET, sizeof(buf));
	flash_write(buf, HW_SETTING_OFFSET, sizeof(buf));
#endif

	return 0;
}

#ifdef VOIP_SUPPORT
static int voip_func(int argc, char *argv[])
{
	return flash_voip_cmd(argc - 1, &argv[1]);
}
#endif

#ifdef USE_11N_UDP_SERVER	//cathy test
static int gethw_func(int argc, char *argv[])
{
	char mib[100];
	char buffer[2048];
	CONFIG_MIB_T flag;
	int argNum, ret = 0;

	if (argc < 2) {
		showHelp();
		return error;
	}

	udp_server_cmd = 1;
	for (argNum = 1; argNum < argc; argNum++) {
		flag = mib_name_resolve(argv[argNum], mib);

		if (flag == CONFIG_MIB_TABLE && mib_table_get_by_name(mib, buffer) != 0) {
			printf("%s=%s\n", argv[argNum], buffer);
		} else {
			ret = error;
		}
	}
	udp_server_cmd = 0;

	return ret;
}

static int sethw_func(int argc, char *argv[])
{
	CONFIG_DATA_T tmpType = UNKNOWN_SETTING;
	CONFIG_DATA_T cdType = UNKNOWN_SETTING;
	char mib[100];
	char buffer[2048];
	int index, argNum, ret = 0;

	if (argc < 3) {
		showHelp();
		return error;
	}

	for (argNum = 1; (argNum + 1) < argc;) {
		mib_name_resolve(argv[argNum], mib);

		if ((index = mib_table_index(mib)) == -1) {
			printf("mib name error: %s\n", mib);
			return error;
		}

		if (mib_table[index].mib_type != HW_SETTING) {
			printf("mib(%s) not in HW_SETTING.\n", mib);
			return error;
		}

		argNum += mib_table_value_resolve(index, argc - argNum, &argv[argNum], buffer);

		if ((tmpType = mib_table_set_by_index(index, buffer)) != 0) {
			cdType |= tmpType;
			printf("set %s=%s\n", mib, buffer);
		} else {
			printf("set %s=%s fail!\n", mib, buffer);
			ret = error;
		}
	}

	if ((cdType & CURRENT_SETTING) && _mib_update(CURRENT_SETTING) == 0) {
		printf("CS Flash error! \n");
		ret = error;
	}

	if ((cdType & HW_SETTING) && _mib_update(HW_SETTING) == 0) {
		printf("HS Flash error! \n");
		ret = error;
	}

	return ret;
}
#endif

static int r_func(int argc, char *argv[])
{
	unsigned int offset, mydata;
	int ret;

	if (argc < 2) {
		printf("command error!\n");
		showHelp();
		return error;
	}

	offset = strtoul(argv[1], NULL, 0);
	ret = flashdrv_read(&mydata, (void *)offset, sizeof(mydata));
	printf("data=0x%x\n", mydata);

	return ret;
}

static int w_func(int argc, char *argv[])
{
	unsigned int offset, fvalue;

	if (argc < 3) {
		printf("command error!\n");
		showHelp();
		return error;
	}

	offset = strtoul(argv[1], NULL, 0);
	fvalue = strtoul(argv[2], NULL, 0);
	printf("flash write 0x%x to 0x%x\n", fvalue,
			0xbfc00000 + offset);

	return flashdrv_write((void *)offset, &fvalue, sizeof(fvalue));
}

static int erase_func(int argc, char *argv[])
{
	unsigned int offset;

	if (argc < 2) {
		printf("command error!\n");
		showHelp();
		return error;
	}

	offset = strtoul(argv[1], NULL, 0);

	return flashdrv_erase((void *)offset);
}

struct {
	char *cmd_name;
	int (*cmd_func)(int argc, char *argv[]);
} cmd_table[] = {
	{ "info", info_func },
	{ "loop", loop_func },
	{ "get", get_func },
	{ "set", set_func },
	{ "add", add_del_func },
	{ "del", add_del_func },
	{ "all", all_func },
#if !defined(CONFIG_USER_XMLCONFIG) && !defined(CONFIG_USER_CONF_ON_XMLFILE)
#ifdef CAN_RW_FILE
	{ "rds", rs_func },
	{ "rcs", rs_func },
	{ "rhs", rs_func },
	{ "wds", ws_func },
	{ "wcs", ws_func },
	{ "whs", ws_func },
#endif
	{ "check", check_func },
	{ "dump", dump_func },
	{ "reset", reset_func },
#endif
	{ "default", default_func },
	{ "clear", clear_func },
#ifdef VOIP_SUPPORT
	{ "voip", voip_func },
#endif
#ifdef USE_11N_UDP_SERVER	//cathy test
	{ "gethw", gethw_func },
	{ "sethw", sethw_func },
#endif
	{ "w", w_func },
	{ "r", r_func },
	{ "erase", erase_func },
	{ 0 },
};

int main(int argc, char *argv[])
{
	int i, ret = 0;

	if (argc < 2) {
		showHelp();
		return error;
	}

	mib_init();

	for (i = 0; cmd_table[i].cmd_name; i++) {
		if (strcmp(cmd_table[i].cmd_name, argv[1]) == 0) {
			ret = cmd_table[i].cmd_func(argc - 1, argv + 1);
			break;
		}
	}

	if (cmd_table[i].cmd_name == NULL)
		showHelp();

	return ret;
}
