#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>
#include <ctype.h>
#include <unistd.h>

#define DEFAULT_CONF_FILE       "ate_default.cfg"
typedef enum {
    RTN_SUCCESS = 0,
    RTN_FAILED = 1,
    RTN_BUFFER = 2, 
    RTN_FORMAT_ERR = 3, 
    RTN_UNKNOW = 4
}rtn_type;

int syncfs(int fd);

rtn_type ate_set_apmib_common(char *name, char *value)
{
    int fd = 0;
    FILE *fd_conf = NULL;
    char sz_line[1024] = {0}, sz_new_line[1024] = {0};
    char p_new_file_cont[4096] = {0};
    rtn_type ret = RTN_FAILED;

    fd_conf = fopen(DEFAULT_CONF_FILE, "r");
    if(NULL == fd_conf)
    {
        printf("[ate_set_apmib_common]==>open conf file failed\n");
        return ret;
    }

    while(fgets(sz_line, sizeof(sz_line), fd_conf) != NULL)
    {
        if(NULL != strstr(sz_line, name))
        {
            memset(sz_new_line,  0x00, sizeof(sz_new_line));
            sprintf(sz_new_line, "%s=%s\n", name, value);
            ret = RTN_SUCCESS;
        }
        else
        {
            memset(sz_new_line, 0x00, sizeof(sz_new_line));
            sprintf(sz_new_line, "%s", sz_line);
        }
        strcat(p_new_file_cont, sz_new_line);
    }

    if(ret  != RTN_SUCCESS)
    {
        memset(sz_new_line,  0x00, sizeof(sz_new_line));
        sprintf(sz_new_line, "%s=%s\n", name, value);
        strcat(p_new_file_cont, sz_new_line);
        ret = RTN_SUCCESS;
    }
    fd = fileno(fd_conf);
    syncfs(fd);
    fclose(fd_conf);

    fd_conf = fopen(DEFAULT_CONF_FILE, "w+");
    fwrite(p_new_file_cont, strlen(p_new_file_cont), 1, fd_conf);
    fd = fileno(fd_conf);
    syncfs(fd);
    fclose(fd_conf);

    sync();
    return ret;
}

int ate_get_apmib_common(char *name, char *value)
{
    FILE *fd_conf = NULL;
    char sz_line[1024] = {0};
    char *p = NULL;
    int ret = 1;

    fd_conf = fopen(DEFAULT_CONF_FILE, "r");
    if(NULL == fd_conf)
    {
        printf("[GetValue]==>open conf file failed\n");
        return ret;
    }

    while(fgets(sz_line, sizeof(sz_line), fd_conf) != NULL)
    {
        if(NULL != strstr(sz_line, name))
        {
            p = strrchr(sz_line, '=');
            sprintf(value, "%s", p+1);
            if ((strlen(value) == 2 && value[0]==0x0d && value[1]==0x0a)) /*windows (\r\n)*/
            {
                value[strlen(value)-2] = '\0';
            }
            else if (strtok(value, "\r\n")) /*windows (string + \r\n)*/
            {
                ret = 0;
                break;
            }
            else if ((strlen(value) == 1 && value[0]==0x0a) || strchr(value, '\n')) /*unix (\n) or unix (string + \n)*/
            {
                value[strlen(value)-1] = '\0';
            }
            ret = 0;
            break;
        }
    }

    fclose(fd_conf);

    return ret;
}

int main(void)
{
	char value[128] ;	
	ate_set_apmib_common("name", "yuan");
	ate_set_apmib_common("age", "15");
	ate_set_apmib_common("sex", "man");
	
	ate_get_apmib_common("age", value);

	printf("value = %s\n",value);
	
	return 0;
}
