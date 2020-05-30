#include "common.h"

void do_system(const char* format, ...)
{
    char cmdstr[BUFSIZ];
    va_list   args;

    memset(cmdstr, 0, sizeof(cmdstr));

    va_start(args,format);
    vsnprintf(cmdstr, sizeof(cmdstr)-1, format,   args);
    va_end(args);

    system(cmdstr);
}


int netctrl_add_route_table(unsigned int tid, char *tname)
{
    char buf[256] = {0}, ctname[32] = {0};
    int itid = 0, ret = 0;
    FILE *fp = NULL;

    if (tid <= 0 || tid >= 255 || tname == NULL)
    {
        return -3;
    }

    if ((fp = fopen(RT_TABLE_FILE_PATH, "r")) != NULL)
    {
        while(fgets(buf, 256, fp) != NULL)
        {
            if(buf[0] == '#')
                continue;
            sscanf(buf, " %d %s ", &itid, ctname);
            if(itid == tid && !strcmp(ctname, tname))
            {
                ret = 0;
                goto out_fun;
            }
            else if(itid == tid)
            {
                ret = -1;
                goto out_fun;
            }
            else if(!strcmp(ctname, tname))
            {
                ret = -2;
                goto out_fun;
            }
        }
        do_system("echo '%d    %s' >> %s", tid, tname, RT_TABLE_FILE_PATH);
        ret = 0;
    }
    else
    {
        ret = -3;
    }

out_fun:
    if (NULL != fp)
    {
        fclose(fp);
    }

    return ret;
}


int main(void)
{

	netctrl_add_route_table(1, "cc");

	return 0;
}
