#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <sys/file.h>
#include "utility.h"

#if 0
#define DEBUGP	printf
#else
#define DEBUGP(format, args...)
#endif

#define error -1
#define chain_record_number	(MIB_CHAIN_TBL_END - CHAIN_ENTRY_TBL_ID + 1)
#define MAX_OBJ	8

struct chain_obj_s {
	char obj_name[32];
	int obj_per_size;
	int cur_num;
};

static unsigned char load_to_configd;
static const char empty_str[] = "";
static char LINE[1024];
static char chain_updated[chain_record_number];

static inline int MIB_SET(int id, void *value) 
{
	if (load_to_configd)
		return mib_set(id, value);
	else
		return _mib_set(id, value);
}

static inline void MIB_CHAIN_CLEAR(int id)
{
	if (load_to_configd)
		mib_chain_clear(id);
	else
		_mib_chain_clear(id);
}

static inline int MIB_CHAIN_ADD(int id, void *ptr)
{
	if (load_to_configd)
		return mib_chain_add(id, ptr);
	else
		return _mib_chain_add(id, ptr);
}

static char *get_line(FILE *fp, char *s, int size)
{
	char *pstr;

	while (1) {
		if (!fgets(s, size, fp))
			return NULL;
		pstr = trim_white_space(s);
		if (strlen(pstr))
			break;
	}

	return pstr;
}

static int table_setting(char *line, CONFIG_DATA_T cnf_type)
{
	int i;
	char *pname, *pvalue;
	unsigned char mibvalue[1024];

	// get name
	strtok(line, "\"");
	pname = strtok(NULL, "\"");
	DEBUGP("table name=%s\n", pname);

	for (i = 0; mib_table[i].id; i++) {
		if (mib_table[i].mib_type != cnf_type)
			continue;

		if (!strcmp(mib_table[i].name, pname))
			break;
	}

	if (mib_table[i].id == 0) {
		printf("%s: Invalid table entry name: %s\n", __FUNCTION__, pname);
		return error;
	}

	// get value
	strtok(NULL, "\"");
	pvalue = strtok(NULL, "\"");
	if (strtok(NULL, "\"") == NULL)
		pvalue = (char *)empty_str;
	DEBUGP("table value=%s\n", pvalue);

	if (string_to_mib(mibvalue, pvalue, mib_table[i].type, mib_table[i].size))
		return error;

	if (!MIB_SET(mib_table[i].id, mibvalue)) {
		printf("Set MIB[%s] error!\n", mib_table[i].name);
		return error;
	}

	return 0;
}

/* Get object info.
 * obj_info: object info list
 * desc: descriptor of this object
 * index: return the index of obj_info for this object.
 * Return:
 *	0: successful
 * 	-1: error
 */
static int get_object_info(struct chain_obj_s *obj_info, mib_chain_member_entry_T * desc, int *index)
{
	int found, i, k;
	mib_chain_member_entry_T * obj_desc;

	if (desc->record_desc == NULL)
		return error;

	// find object info.
	found = 0;
	for (k = 0; k < MAX_OBJ; k++) {
		if (obj_info[k].obj_name[0] == '\0')
			break;

		if (!strncmp(obj_info[k].obj_name, desc->name, sizeof(obj_info[k].obj_name))) {
			found = 1;
			break;
		}
	}

	if (k == MAX_OBJ) {
		printf("%s: data overflow !\n", __FUNCTION__);
		k = 0;
	}

	if (!found) {		// create one
		strncpy(obj_info[k].obj_name, desc->name, sizeof(obj_info[k].obj_name));

		obj_desc = desc->record_desc;

		obj_info[k].obj_per_size = 0;
		for (i = 0; obj_desc[i].name[0]; i++) {
			obj_info[k].obj_per_size += obj_desc[i].size;
		}

		obj_info[k].cur_num = 0;
	}
	*index = k;

	return 0;
}

/*
 * Return:
 *	-1 : error
 *	 0 : successful
 *	 1 : empty chain(object)
 */
static int put_value_object(FILE *fp, unsigned char *entry, mib_chain_member_entry_T * root_desc, mib_chain_member_entry_T * this_desc)
{
	int i, empty_chain, ret, index;
	char *pstr;
	struct chain_obj_s object_info[MAX_OBJ];
	char *pname, *pvalue;

	memset(object_info, 0, sizeof(object_info));

	empty_chain = 1;

	while (!feof(fp)) {
		pstr = get_line(fp, LINE, sizeof(LINE));

		if (!strncmp(pstr, "</chain", 7)) {
			break;	// end of chain object
		}

		if (this_desc == NULL)
			continue;

		// check OBJECT_T
		if (!strncmp(pstr, "<chain", 6)) {
			// get Object name
			strtok(pstr, "\"");
			pname = strtok(NULL, "\"");
			DEBUGP("obj_name=%s\n", pname);

			for (i = 0; this_desc[i].name[0]; i++) {
				if (!strcmp(this_desc[i].name, pname))
					break;
			}

			if (this_desc[i].name[0] == '\0') {
				printf("%s: Chain Object %s member %s descriptor not found !\n", __FUNCTION__, root_desc->name, pname);
				return error;
			}

			// get object info.
			ret = get_object_info(object_info, &this_desc[i], &index);
			if (ret)
				return error;

			ret = put_value_object(fp, entry + this_desc[i].offset + object_info[index].cur_num * object_info[index].obj_per_size,
					     &this_desc[i], this_desc[i].record_desc);
			if (ret == 0)
				object_info[index].cur_num++;
			else if (ret == error)
				return error;
		} else {
			// get name
			strtok(pstr, "\"");
			pname = strtok(NULL, "\"");
			DEBUGP("name=%s\n", pname);

			for (i = 0; this_desc[i].name[0]; i++) {
				if (!strcmp(this_desc[i].name, pname))
					break;
			}

			if (this_desc[i].name[0] == '\0') {
				printf("Chain %s member %s not found !\n", root_desc->name, pname);
				return error;
			}

			// get value
			strtok(NULL, "\"");
			pvalue = strtok(NULL, "\"");
			if (strtok(NULL, "\"") == NULL)
				pvalue = (char *)empty_str;
			DEBUGP("value=%s\n", pvalue);

			// put value
			ret = string_to_mib(entry + this_desc[i].offset, pvalue, this_desc[i].type, this_desc[i].size);
			if (ret == error) {
				printf("%s: Invalid chain member ! (name=\"%s\", value=\"%s\")\n", __FUNCTION__, pname, pvalue);
				return error;
			}
		}
		empty_chain = 0;
	}

	return empty_chain;
}

static int chain_setting(FILE *fp, char *line, CONFIG_DATA_T cnf_type)
{
	int i, empty_chain;
	char *ptoken;
	mib_chain_member_entry_T *rec_desc;
	mib_chain_member_entry_T root_desc;
	unsigned char *chainEntry;

	// get chain name
	strtok(line, "\"");
	ptoken = strtok(NULL, "\"");
	DEBUGP("Chain name=%s\n", ptoken);

	// get chain info
	for (i = 0; mib_chain_record_table[i].id; i++) {
		if (mib_chain_record_table[i].mib_type != cnf_type)
			continue;

		if (!strcmp(mib_chain_record_table[i].name, ptoken))
			break;
	}

	if (mib_chain_record_table[i].id == 0)
		return error; // not found

	// get chain descriptor
	rec_desc = mib_chain_record_table[i].record_desc;

	//clear orginal record
	if (chain_updated[mib_chain_record_table[i].id - CHAIN_ENTRY_TBL_ID] == 0) {
		MIB_CHAIN_CLEAR(mib_chain_record_table[i].id);	//clear chain record
		chain_updated[mib_chain_record_table[i].id - CHAIN_ENTRY_TBL_ID] = 1;
	}

	strncpy(root_desc.name, mib_chain_record_table[i].name, sizeof(root_desc.name));
	chainEntry = malloc(mib_chain_record_table[i].per_record_size);
	empty_chain = put_value_object(fp, chainEntry, &root_desc, rec_desc);

	if (empty_chain == 1) {
		DEBUGP("Empty Chain.\n");
		MIB_CHAIN_CLEAR(mib_chain_record_table[i].id);
	} else if (empty_chain == 0) {
		MIB_CHAIN_ADD(mib_chain_record_table[i].id, chainEntry);
	}
	free(chainEntry);

	return empty_chain;
}

static int update_setting(FILE *fp, char *line, CONFIG_DATA_T cnf_type)
{
	int ret = 0;

	if (!strncmp(line, "<Value", 6))
		ret = table_setting(line, cnf_type);
	else if (!strncmp(line, "<chain", 6))
		ret = chain_setting(fp, line, cnf_type);
	else {
		printf("Unknown statement: %s\n", line);
		ret = error;
	}

	return ret;
}

int _load_xml_file(const char *loadfile, CONFIG_DATA_T cnf_type, unsigned char flag)
{
	int ret = 0;
	char *pstr;
	FILE *fp;

	load_to_configd = flag;

#ifdef XOR_ENCRYPT
	xor_encrypt(loadfile, "/tmp/config_xor.xml");
	rename("/tmp/config_xor.xml", loadfile);
#endif

	if (!(fp = fopen(loadfile, "r"))) {
		printf("User configuration file can not be opened: %s\n", loadfile);
		ret = error;
		goto ret;
	}

	flock(fileno(fp), LOCK_SH);

	get_line(fp, LINE, sizeof(LINE));

	/* initialize chain update flags */
	memset(chain_updated, 0, sizeof(chain_updated));

	while (!feof(fp)) {
		pstr = get_line(fp, LINE, sizeof(LINE));	//get one line from the file
		if (!strcmp(pstr, CONFIG_TRAILER)
		    || !strcmp(pstr, CONFIG_TRAILER_HS))
			break;	// end of configuration

		if (update_setting(fp, pstr, cnf_type) < 0) {
			printf("update setting fail!\n");
			ret = error;
			break;
		}
	}

	flock(fileno(fp), LOCK_UN);

	fclose(fp);

	/* No errors */
	if (load_to_configd && ret == 0) {
		if (mib_update(cnf_type, CONFIG_MIB_ALL) == 0)
			ret = error;
	}

ret:
	return ret;
}

#define TAB_DEPTH(fp, x) 		\
do {					\
	int i;				\
	for (i = 0; i < x; i++)		\
		fprintf(fp, " ");	\
} while (0)

static unsigned char save_from_configd;
static char *FORMAT_STR = "<Value Name=\"%s\" Value=\"%s\"/>\n";

static inline int MIB_GET(int id, void *value)
{
	if (save_from_configd)
		return mib_get(id, value);
	else
		return _mib_get(id, value);
}

static inline unsigned int MIB_CHAIN_TOTAL(int id)
{
	if (save_from_configd)
		return mib_chain_total(id);
	else
		return _mib_chain_total(id);
}

#define MIB_CHAIN_GET(id, recordNum, chainEntry)		\
do {								\
	if (save_from_configd) {				\
		mib_chain_get(id, recordNum, chainEntry);	\
	} else {						\
		chainEntry = _mib_chain_get(id, recordNum);	\
	}							\
} while (0)

static void print_name_value(FILE *fp, char *format_str, char *name, void *addr, TYPE_T type, int size, int depth)
{
	char string[2048];

	mib_to_string(string, addr, type, size);
	TAB_DEPTH(fp, depth);
	fprintf(fp, format_str, name, string);
	DEBUGP(format_str, name, string);
}

static void print_chain_obj(FILE *fp, char *format_str, mib_chain_member_entry_T * desc, void *addr, int depth)
{
	mib_chain_member_entry_T * obj_desc;
	unsigned int entryNum;
	int i, k, unit_size;
	void *pObj;

	obj_desc = desc->record_desc;
	if (obj_desc == NULL)
		return;

	unit_size = 0;
	for (i = 0; obj_desc[i].name[0]; i++) {
		unit_size += obj_desc[i].size;
	}

	entryNum = desc->size / unit_size;

	for (i = 0; i < entryNum; i++) {
		TAB_DEPTH(fp, depth);
		fprintf(fp, "<chain chainName=\"%s\">\n", desc->name);
		DEBUGP("<chain chainName=\"%s\">\n", desc->name);

		pObj = addr + unit_size * i;
		for (k = 0; obj_desc[k].name[0]; k++) {
			print_chain_member(fp, format_str, &obj_desc[k], pObj + obj_desc[k].offset, depth + 1);
		}

		TAB_DEPTH(fp, depth);
		fprintf(fp, "</chain>\n");
		DEBUGP("</chain>\n");
	}
}

void print_chain_member(FILE *fp, char *format_str, mib_chain_member_entry_T * desc, void *addr, int depth)
{
	switch (desc->type) {
	case OBJECT_T:
		print_chain_obj(fp, format_str, desc, addr, depth);
		break;
	default:
		print_name_value(fp, format_str, desc->name, addr, desc->type, desc->size, depth);
		break;
	}
}

int _save_xml_file(const char *savefile, CONFIG_DATA_T cnf_type, unsigned char flag)
{
	int i, j, k;
	mib_chain_member_entry_T *rec_desc;
	unsigned int entryNum;
	unsigned char *chainEntry;
	void *buffer;
	FILE *fp;

	save_from_configd = flag;

	fp = fopen(savefile, "w");
	if (fp == NULL)
		return error;

	flock(fileno(fp), LOCK_EX);

	if (cnf_type == HW_SETTING) {
		fprintf(fp, "%s\n", CONFIG_HEADER_HS);
		DEBUGP("%s\n", CONFIG_HEADER_HS);
	} else {
		fprintf(fp, "%s\n", CONFIG_HEADER);
		DEBUGP("%s\n", CONFIG_HEADER);
	}

	// MIB Table
	buffer = NULL;
	for (i = 0; mib_table[i].id; i++) {
		if (mib_table[i].mib_type != cnf_type)
			continue;

		buffer = realloc(buffer, mib_table[i].size);

		MIB_GET(mib_table[i].id, buffer);
		print_name_value(fp, FORMAT_STR, mib_table[i].name, buffer, mib_table[i].type, mib_table[i].size, 0);
	}
	free(buffer);

	// MIB chain record
	for (i = 0; mib_chain_record_table[i].id; i++) {
		if (mib_chain_record_table[i].mib_type != cnf_type)
			continue;

		rec_desc = mib_chain_record_table[i].record_desc;
		if (rec_desc == NULL)
			entryNum = 0;
		else
			entryNum = MIB_CHAIN_TOTAL(mib_chain_record_table[i].id);

		DEBUGP("chain entry %d # %u\n", mib_chain_record_table[i].id, entryNum);

		if (entryNum == 0) {
			fprintf(fp, "<chain chainName=\"%s\">\n", mib_chain_record_table[i].name);
			DEBUGP("<chain chainName=\"%s\">\n", mib_chain_record_table[i].name);
			fprintf(fp, "</chain>\n");
			DEBUGP("</chain>\n");
		} else {
			if (save_from_configd) {
				chainEntry = malloc(mib_chain_record_table[i].per_record_size);
				if (chainEntry == NULL)
					return error;
			}

			for (j = 0; j < entryNum; j++) {
				fprintf(fp, "<chain chainName=\"%s\">\n", mib_chain_record_table[i].name);
				DEBUGP("<chain chainName=\"%s\">\n", mib_chain_record_table[i].name);

				MIB_CHAIN_GET(mib_chain_record_table[i].id, j, chainEntry);
				for (k = 0; rec_desc[k].name[0]; k++) {
					print_chain_member(fp, FORMAT_STR, &rec_desc[k], chainEntry + rec_desc[k].offset, 1);
				}

				fprintf(fp, "</chain>\n");
				DEBUGP("</chain>\n");
			}

			if (save_from_configd)
				free(chainEntry);
		}
	}

	if (cnf_type == HW_SETTING) {
		fprintf(fp, "%s\n", CONFIG_TRAILER_HS);
		DEBUGP("%s\n", CONFIG_TRAILER_HS);
	} else {
		fprintf(fp, "%s\n", CONFIG_TRAILER);
		DEBUGP("%s\n", CONFIG_TRAILER);
	}

	flock(fileno(fp), LOCK_UN);

	fclose(fp);

#ifdef XOR_ENCRYPT
	xor_encrypt(savefile, "/tmp/config_xor.xml");
	rename("/tmp/config_xor.xml", savefile);
#endif

	return 0;
}

