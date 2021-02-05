#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>
#include <ctype.h>

pid_t
get_pid_by_thrd_name(char *name)
{
	pid_t           pid = -1;
	DIR             *dir;
	struct dirent   *next;
	int cmp = 0;
	if ((dir = opendir("/proc")) == NULL) {
		perror("Cannot open /proc");
		return -1;
	}

	while ((next = readdir(dir)) != NULL) {
		FILE *fp;
		char filename[512];
		char buffer[256];

		/* If it isn't a number, we don't want it */
		if (!isdigit(*next->d_name))
			continue;
		sprintf(filename, "/proc/%s/comm", next->d_name);
		fp = fopen(filename, "r");
		if (!fp) {
			continue;
		}
		buffer[0] = '\0';
		fgets(buffer, 256, fp);
		fclose(fp);

		printf("buffer = %s\n",buffer);
		if (!(cmp = strncmp(name, buffer, strlen(name)))) {
			pid = strtol(next->d_name, NULL, 0);
			break;
		}
	}

	closedir(dir);
	return pid;
}

pid_t
get_pid_by_name(char *name)
{
	pid_t           pid = -1;
	DIR             *dir;
	struct dirent   *next;

	if ((dir = opendir("/proc")) == NULL) {
		perror("Cannot open /proc");
		return -1;
	}

	while ((next = readdir(dir)) != NULL) {
		FILE *fp;
		char filename[512];
		char buffer[256];

		/* If it isn't a number, we don't want it */
		if (!isdigit(*next->d_name))
			continue;

		sprintf(filename, "/proc/%s/cmdline", next->d_name);
		fp = fopen(filename, "r");
		if (!fp) {
			continue;
		}
		buffer[0] = '\0';
		fgets(buffer, 256, fp);
		fclose(fp);
	

		if (!strcmp(name, buffer)) {
			pid = strtol(next->d_name, NULL, 0);
			break;
		}
	}

	closedir(dir);
	return pid;
}

int main(void)
{
	
	//pid_t pid = get_pid_by_name("/usr/sbin/smbd");
	pid_t pid = get_pid_by_thrd_name("/usr/sbin/smbd");

	printf("pid = %d\n",pid);

	return 0;
}
