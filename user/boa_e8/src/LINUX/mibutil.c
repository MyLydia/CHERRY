#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "utility.h"

#define error -1

static void showHelp(void)
{
	printf("Usage: mib cmd\n");
	printf("cmd:\n");
	printf("  get <MIB-NAME> [...] \t\tget the specific mib from configd.\n");
	printf("    Example:\n");
	printf("      get NTP_ENABLED \t\tget the specific mib table entry from configd.\n");
	printf("      get ATM_VC_TBL \t\tget all the specific mib chain records from configd.\n");
	printf("      get ATM_VC_TBL.NUM \tget the specific mib chain record size from configd.\n");
	printf("      get ATM_VC_TBL.0.ifIndex \tget the specific member of the mib chain record from configd.\n");
	printf("  set <MIB-NAME MIB-VALUE> [...]set the specific mib into configd.\n");
	printf("    Example:\n");
	printf("      set NTP_ENABLED 0 \tset the specific mib table entry into configd.\n");
	printf("      set ATM_VC_TBL.1.vpi 8 \tset the specific member of the mib chain recrod into configd.\n");
	printf("  add <MIB-CHAIN-NAME> [...] \tadd mib chain record(s) into configd.\n");
	printf("    Example:\n");
	printf("      add ATM_VC_TBL \t\tadd a mib chain record into configd.\n");
	printf("      add ATM_VC_TBL.2 \t\tadd mib chain record(s) into configd.\n");
	printf("  del <MIB-CHAIN-NAME> [...] \tdelete mib chain record(s) into configd.\n");
	printf("    Example:\n");
	printf("      del ATM_VC_TBL \t\tdelete the last mib chain record into configd.\n");
	printf("      del ATM_VC_TBL.2 \t\tdelete the specific mib chain record into configd.\n");
	printf("  all [cs|hs|rs] \t\tdump all mib from configd.\n");
	printf("  commit [cs|hs] \t\tcommit all mib from configd into flash.\n");
#ifdef VOIP_SUPPORT
	printf("  voipshmupdate \t\tvoip shm update.\n");
#endif /*VOIP_SUPPORT*/
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

	total = mib_chain_total(id);

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

		chainEntry = malloc(mib_chain_record_table[i].per_record_size);
		if (chainEntry == NULL)
			return 0;

		for (j = 0; j < total; j++) {
			if (j < recordNum)
				continue;

			mib_chain_get(id, j, chainEntry);

			printf("%s.%d:\n", mib_chain_name, j);

			for (k = 0; rec_desc[k].name[0]; k++) {
				if (member && strcmp(member, rec_desc[k].name))
					continue;
				print_chain_member(stdout, "%-18s = %s\n", &rec_desc[k], chainEntry + rec_desc[k].offset, 0);
			}

			/* OK, done */
			if (j == recordNum)
				break;

			printf("\n");
		}

		free(chainEntry);
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
	if (mib_get(id, mibvalue) == 0)
		return 0;

	mib_to_string(buffer, mibvalue, mib_table[i].type, mib_table[i].size);

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

	if (mib_set(id, mibvalue))
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

	total = mib_chain_total(id);

	recordNum = strtoul(record_num, NULL, 0);

	if (recordNum < total) {
		if (mib_chain_record_table[i].record_desc == NULL) {
			printf("Empty mib chain %s descriptor !\n", mib_chain_name);
			return 0;
		}

		rec_desc = mib_chain_record_table[i].record_desc;

		chainEntry = malloc(mib_chain_record_table[i].per_record_size);
		if (chainEntry == NULL)
			return 0;

		mib_chain_get(id, recordNum, chainEntry);

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

		mib_chain_update(id, chainEntry, recordNum);

		free(chainEntry);
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

	total = mib_chain_total(id);

	if (record_num)
		recordNum = strtoul(record_num, NULL, 0);
	else
		recordNum = total;

	chainEntry = calloc(1, mib_chain_record_table[i].per_record_size);
	if (chainEntry == NULL)
		return 0;

	for (j = total; j <= recordNum; j++) {
		if (mib_chain_add(id, chainEntry) == 0) {
			printf("Adding mib chain: %s fails !!\n", mib_chain_name);
			free(chainEntry);
			return 0;
		}
	}

	free(chainEntry);

	total = mib_chain_total(id);
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

	total = mib_chain_total(id);

	if (record_num)
		recordNum = strtoul(record_num, NULL, 0);
	else
		recordNum = total - 1;

	if (mib_chain_delete(id, recordNum) == 0) {
		printf("Deleting mib chain: %s, record number: %d fails !!\n", mib_chain_name, recordNum);
		return 0;
	}

	total = mib_chain_total(id);
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
		total = mib_chain_total(mib_chain_record_table[i].id);
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
		if (mib_table_get_by_name(mib_table[i].name, buffer) != 0) {
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
		if (flag == CONFIG_MIB_CHAIN && mib_chain_get_by_name(mib, buffer) != 0) {
			printf("%s\n", buffer);
		} else if (flag == CONFIG_MIB_TABLE && mib_table_get_by_name(mib, buffer) != 0) {
			printf("%s=%s\n", mib, buffer);
		} else {
			ret = error;
		}
	}

	return ret;
}

static int set_func(int argc, char *argv[])
{
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

			if (mib_table_set_by_index(index, buffer) != 0) {
				printf("set %s=%s\n", mib, buffer);
			} else {
				printf("set %s=%s fail!\n", mib, buffer);
				ret = error;
			}
		} else if (flag == CONFIG_MIB_CHAIN) {
			if (mib_chain_set_by_name(mib, argv[argNum + 1]) != 0) {
				printf("set %s=%s\n", argv[argNum], argv[argNum + 1]);
			} else {
				printf("set %s=%s fail!\n", argv[argNum], argv[argNum + 1]);
				ret = error;
			}

			argNum += 2;
		}
	}

	return ret;
}

static int add_del_func(int argc, char *argv[])
{
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
			if (func(mib) == 0)
				ret = error;
		}
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
		else if (!strcmp(argv[1], "rs"))
			mib_get_all_by_type(RUNNING_SETTING);
		else
			mib_get_all_by_type(UNKNOWN_SETTING);
	}

	return 0;
}

static int commit_func(int argc, char *argv[])
{
	CONFIG_DATA_T data_type = UNKNOWN_SETTING;
	int ret = 0;

	if (argc == 1) {
		data_type = CURRENT_SETTING | HW_SETTING;
	} else {
		if (!strcmp(argv[1], "cs"))
			data_type |= CURRENT_SETTING;
		if (!strcmp(argv[1], "hs"))
			data_type |= HW_SETTING;
	}

	if ((data_type & CURRENT_SETTING) && !mib_update(CURRENT_SETTING, CONFIG_MIB_ALL)) {
		fprintf(stderr, "Update Current Setting failed!\n");
		ret = error;
	}

	if ((data_type & HW_SETTING) && !mib_update(HW_SETTING, CONFIG_MIB_ALL)) {
		fprintf(stderr, "Update Hardware Setting failed!\n");
		ret = error;
	}

	return ret;
}
#ifdef VOIP_SUPPORT	
extern int voip_flash_server_init_variables();
extern int voip_flash_server_update();
static int voipshmupdate_func(int argc, char *argv[])
{
	int ret;

	ret = voip_flash_server_init_variables();
	ret |= voip_flash_server_update();

	return 0;
}
#endif
struct {
	char *cmd_name;
	int (*cmd_func)(int argc, char *argv[]);
} cmd_table[] = {
	{ "get", get_func },
	{ "set", set_func },
	{ "add", add_del_func },
	{ "del", add_del_func },
	{ "all", all_func },
	{ "commit", commit_func },
#ifdef VOIP_SUPPORT
	{ "voipshmupdate", voipshmupdate_func },
#endif
	{ 0 },
};

int main(int argc, char *argv[])
{
	int i, ret = 0;

	if (argc <= 1) {
		showHelp();
		return error;
	}

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
