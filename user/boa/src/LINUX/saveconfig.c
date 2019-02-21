/*
 * Save system configuration to file
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include "mibtbl.h"
#include "utility.h"

#if 0
#define DEBUGP	printf
#else
#define DEBUGP(format, args...)
#endif

#define TAB_DEPTH(x) 			\
do {					\
	int i;				\
	for (i = 0; i < x; i++)		\
		fprintf(fp, " ");	\
} while (0)
		
#define error -1
#define FMT_RAW		1
#define FMT_XML		2

#define PATH_PID	"/var/run/saveconfig.pid"

void write_pid_file(void)
{
	FILE *pf;
	int pfdesc;
	char *pidfile = PATH_PID;
	int e;

	e = 0;
	while (!access(pidfile, F_OK) && e <= 20) {
		usleep(100000);
		e++;
	}

	pfdesc = open(pidfile, O_CREAT | O_TRUNC | O_WRONLY, 0644);

	if (pfdesc < 0) {
		printf("Can't create %s\n", pidfile);
		return;
	}

	pf = fdopen(pfdesc, "w");
	if (!pf)
		printf("Can't fdopen %s\n", pidfile);
	else {
		fprintf(pf, "%ld\n", (long)getpid());
		fclose(pf);
	}
}

void remove_pid_file ()
{
	unlink(PATH_PID);
}

void show_usage()
{
	fprintf(stderr,	"Usage: saveconfig [ -f filename ] [ -t raw/xml ] [ cs/hs ]\n");
	fprintf(stderr, "Save system configuration to file.\n");
	fprintf(stderr, "Default options:\n");
	fprintf(stderr, "\t[ -f filename ] %s for cs; %s for hs\n", CONFIG_XMLFILE, CONFIG_XMLFILE_HS);
	fprintf(stderr, "\t[ -t raw/xml ] xml\n");
	fprintf(stderr, "\t[ cs/hs ] cs\n");
	fprintf(stderr,	"Usage: saveconfig -c\n");
	fprintf(stderr, "Check validation of MIB descriptors.\n");
}

static int save_xml_file(const char *savefile, CONFIG_DATA_T cnf_type)
{
	return _save_xml_file(savefile, cnf_type, 1);
}

#if !defined(CONFIG_USER_XMLCONFIG) && !defined(CONFIG_USER_CONF_ON_XMLFILE)
static int save_raw_file(const char *savefile, CONFIG_DATA_T cnf_type)
{
	FILE *fp;
	PARAM_HEADER_T header;
	unsigned int fileSize;
	unsigned char *buf;

	fp = fopen(savefile, "w");
	if (mib_read_header(cnf_type, &header) != 1) {
		fclose(fp);
		return error;
	}

	fileSize = sizeof(PARAM_HEADER_T) + header.len;
	buf = malloc(fileSize);
	if (buf == NULL) {
		fclose(fp);
		return error;
	}

	printf("fileSize=%d\n", fileSize);
	if (mib_read_to_raw(cnf_type, buf, fileSize) != 1) {
		free(buf);
		fclose(fp);
		printf("ERROR: Flash read fail.");
		return error;
	}
	ENCODE_DATA(buf + sizeof(PARAM_HEADER_T), header.len);

	fwrite(buf, fileSize, 1, fp);
	free(buf);
	fclose(fp);

	return 0;
}
#else
static int save_raw_file(const char *savefile, CONFIG_DATA_T cnf_type)
{
	printf("%s not supported\n", __FUNCTION__);

	return error;
}
#endif

int main(int argc, char **argv)
{
	int ret;
	int opt;
	char userfile[64];
	char *savefile;
#ifdef CONFIG_USER_RTK_RECOVER_SETTING
	char *flashfile = NULL;
#endif
	int filefmt;
	int desc_check;
	int save_to_flash;
	CONFIG_DATA_T dtype;

	desc_check = 0;
	save_to_flash = 0;
	savefile = NULL;
	filefmt = FMT_XML;
	/* do normal option parsing */
	while ((opt = getopt(argc, argv, "f:t:csh")) > 0) {
		switch (opt) {
		case 'f':
			strncpy(userfile, optarg, sizeof(userfile));
			userfile[63] = '\0';
			savefile = userfile;
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
		case 'c':
			desc_check = 1;
			break;
		case 's':	// Save Setting to flatfsd(flash).
			save_to_flash = 1;
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

	// assign savefile & flashfile
	switch (dtype) {
	case HW_SETTING:
		if (!savefile) {
			if (filefmt == FMT_XML)
				savefile = (char *)CONFIG_XMLFILE_HS;
			else
				savefile = (char *)CONFIG_RAWFILE_HS;
		}
#ifdef CONFIG_USER_RTK_RECOVER_SETTING
		flashfile = OLD_SETTING_FILE_HS;
#endif
		break;
	case CURRENT_SETTING:
	default:
		if (!savefile) {
			if (filefmt == FMT_XML)
				savefile = (char *)CONFIG_XMLFILE;
			else
				savefile = (char *)CONFIG_RAWFILE;
		}
#ifdef CONFIG_USER_RTK_RECOVER_SETTING
		flashfile = OLD_SETTING_FILE;
#endif
		break;
	}

	// Check the consistency between chain record and chain descriptor
	if (desc_check) {
		if (mib_check_desc() == 1)
			printf("Check ok !\n");
		else
			printf("Check failed !\n");
		return 0;
	}

	write_pid_file();

	if (filefmt == FMT_XML)
		ret = save_xml_file(savefile, dtype);
	else			// FMT_RAW
		ret = save_raw_file(savefile, dtype);

	if (save_to_flash) {
#ifdef CONFIG_USER_RTK_RECOVER_SETTING	// Save Setting to flatfsd(flash)
		ret |= va_cmd("/bin/cp", 2, 1, savefile, flashfile);
		// gzip: compress config file to reduce file size.
		ret |= va_cmd("/bin/gzip", 2, 1, "-f", flashfile);
		//ccwei_flatfsd
#ifdef CONFIG_USER_FLATFSD_XXX
		ret |= va_cmd("/bin/flatfsd", 1, 1, "-s");
#endif
#endif
	}

	remove_pid_file();
	return ret;
}

