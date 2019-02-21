#include "mibtbl.h"
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <sys/shm.h>
#include <sys/file.h>
#include <rtk/utility.h>
#include <unistd.h>
#include <stdlib.h>
#ifdef EMBED
#include <config/autoconf.h>
#else
#include "../../../../config/autoconf.h"
#endif

void ftpServer_log (int level, const char *fmt, ...)
{
    char buf[2048];
    va_list args;
    va_start (args, fmt);
    vsnprintf (buf, sizeof (buf), fmt, args);
    va_end (args);

    syslog(level," ftpserver:%s\n", buf);
    printf("%s\r\n", buf);
}

#define FTPSERVER_CONF_FILE "/var/vsftpd.conf"
//#define FTPSERVER_CONF_FILE "./vsftpd.conf"
#define FTPSERVER_USERLIST_FILE "/var/ftp_userList"
void ftpserver_conf_init(FILE	*fptr)
{	
	/*listen_port=21
   *anonymous_enable=YES
   *ftp_username=telecomadmin
	 *anon_root=/mnt
	 *anon_upload_enable=NO
	 *anon_mkdir_write_enable=NO
	 *anon_other_write_enable=NO
	
	 *local_enable=YES
	 *write_enable=YES
	 *local_umask=022
	 *dirmessage_enable=YES
	 *xferlog_enable=YES
	 *connect_from_port_20=YES
	 *xferlog_std_format=YES
	 *listen=YES
	 *userlist_enable=YES
	 *userlist_deny=YES
	 *userlist_file=/etc/vsftpd.users
	
	 *secure_chroot_dir=/var/mnt/
	
	 *local_root=/var/mnt
	 *#nopriv_user=telecomadmin
	 *download_enable=YES
	
	 *guest_enable=YES
	 *guest_username=telecomadmin
	 *virtual_use_local_privs=YES
	 *#pam_service_name=vsftpd
	 *user_config_dir=/etc/vsftpd/vuser_conf
	
	
	 *ascii_upload_enable=YES
	 *ascii_download_enable=YES
	*/

	if(fptr == NULL)
	{
		ftpServer_log(LOG_ERR, "%s(%d):illegal file %s!", __FUNCTION__, __LINE__, FTPSERVER_CONF_FILE);
		return;
	}
	
	fputs("listen_port=21\n", fptr);
	fputs("ftp_username=telecomadmin\n", fptr);
	fputs("anon_root=/mnt\n", fptr);
	fputs("anon_upload_enable=YES\n", fptr);
	fputs("anon_mkdir_write_enable=YES\n", fptr);
	fputs("anon_other_write_enable=YES\n", fptr);
	fputs("local_enable=YES\n", fptr);
	fputs("write_enable=YES\n", fptr);
	fputs("local_umask=022\n", fptr);
	fputs("dirmessage_enable=YES\n", fptr);
	fputs("xferlog_enable=YES\n", fptr);
	fputs("connect_from_port_20=YES\n", fptr);
	fputs("xferlog_std_format=YES\n", fptr);
	fputs("listen=NO\n", fptr);
	//fputs("listen_ipv6=YES\n", fptr);
	fputs("listen_ipv6=NO\n", fptr);
	fputs("userlist_enable=YES\n", fptr);
	fputs("userlist_deny=YES\n", fptr);
	fputs("userlist_file=/etc/vsftpd.users\n", fptr);
	fputs("secure_chroot_dir=/mnt\n", fptr);
	fputs("local_root=/mnt/\n", fptr);
	fputs("download_enable=YES\n", fptr);
	fputs("guest_enable=YES\n", fptr);
	fputs("guest_username=telecomadmin\n", fptr);
	fputs("virtual_use_local_privs=YES\n", fptr);
	fputs("chroot_list_enable=NO\n", fptr);
	fputs("chroot_local_user=NO\n", fptr);
	fputs("user_config_dir=/etc/vsftpd/vuser_conf\n", fptr);
	fputs("ascii_upload_enable=YES\n", fptr);
	fputs("ascii_download_enable=YES\n", fptr);
	
	return;
}
/*初始化从MIB中读取数据然后初始化配置文件*/
#ifdef CONFIG_YUEME
void smartHGU_ftpserver_init_api(void)
{
	FILE *fptr = NULL;
	int num = 0;
    unsigned char annon = 0;
    unsigned char enable = 1;
    int total = 0;
    int i = 0,j=0;
    char cmd[64] = {0};
	char struseradmin[]="useradmin";
    MIB_CE_VSFTP_ACCOUNT_T  entry;
	MIB_CE_VSFTP_ACCOUNT_T  ftp_entry[6];
	/**add by wanghy at 20161114*/
	unsigned char userName[MAX_NAME_LEN], userPass[MAX_NAME_LEN], default_userPass[MAX_NAME_LEN];
	int sameUserNameFlags = 0;
	/**end add by wanghy at 20161114*/

    system("syslogd");

    sleep(1);

    memset(&entry, 0, sizeof(MIB_CE_VSFTP_ACCOUNT_T));

    fptr = fopen(FTPSERVER_CONF_FILE, "w+");
    if(fptr == NULL)
    {
         ftpServer_log(LOG_ERR, "%s(%d):create file %s error!", __FUNCTION__, __LINE__, FTPSERVER_CONF_FILE);
    }
    else
    {
         ftpserver_conf_init(fptr);
        /*MIB 读取Annonymous的值*/
        mib_get(MIB_VSFTP_ANNONYMOUS, (void *)&annon);
        ftpServer_log(LOG_INFO, "%s(%d):annon[%d]", __FUNCTION__, __LINE__, annon);
        if(annon == 0)
        {
             fputs("anonymous_enable=NO\n", fptr);
        }
        else
        {
             fputs("anonymous_enable=YES\n", fptr);
        }

        fclose(fptr);
    }


    fptr = fopen(FTPSERVER_USERLIST_FILE, "w+");
    if(fptr == NULL)
    {
         ftpServer_log(LOG_INFO, "%s(%d):create file %s error!", __FUNCTION__, __LINE__, FTPSERVER_USERLIST_FILE);
    }
    else
    {
         total = mib_chain_total(MIB_VSFTP_ACCOUNT_TBL);
         ftpServer_log(LOG_INFO, "%s(%d):total[%d]", __FUNCTION__, __LINE__, total);

         if(total == 0)
         {
            /*MIB读取用户名和密码列表,循环遍历将值写入配置文件中*/
            mib_get( MIB_USER_NAME, (void *)userName );
            if (userName[0])
            {
                mib_get(MIB_USER_PASSWORD,(void *)userPass );
                if((!strcmp(userPass, "0")) || (!strlen(userPass)))
                {
                     mib_get(MIB_DEFAULT_USER_PASSWORD, (void *)default_userPass);
                     memcpy(userPass, default_userPass, MAX_NAME_LEN);
                     ftpServer_log(LOG_INFO, "%s(%d):default_userPass[%s]", __FUNCTION__, __LINE__, default_userPass);
                }
            }
            ftpServer_log(LOG_INFO, "%s(%d):userName[%s]", __FUNCTION__, __LINE__, userName);
            ftpServer_log(LOG_INFO, "%s(%d):userPass[%s]", __FUNCTION__, __LINE__, userPass);

             entry.index = 1;
             strcpy(entry.username, userName);
             strcpy(entry.password, userPass);

             sprintf(cmd, "%s %s\n", entry.username, entry.password);
             ftpServer_log(LOG_INFO, "%s(%d):cmd[%s]", __FUNCTION__, __LINE__, cmd);
             fputs(cmd, fptr);

             if(! mib_chain_add(MIB_VSFTP_ACCOUNT_TBL, (unsigned char*)&entry))
             {
                 ftpServer_log(LOG_INFO, "%s(%d)  mib_chain_add error", __FUNCTION__, __LINE__);
             }
             else
    		    mib_update(CURRENT_SETTING, CONFIG_MIB_ALL);
         }
         else
         {
             for(i=0; i<total; i++)
             {
                 if (!mib_chain_get(MIB_VSFTP_ACCOUNT_TBL, i, (void *)&entry))
                    continue;
                 if((strlen(entry.username) == 0) || (strlen(entry.password) == 0))
                 {
                     ftpServer_log(LOG_ERR, "%s(%d):illegal username/password", __FUNCTION__, __LINE__);
                     continue;
                 }

				if(strcmp(struseradmin,entry.username) == 0)
				{
					ftpServer_log(LOG_INFO, "%s(%d):username[%s]", __FUNCTION__, __LINE__, entry.username);
					mib_get( MIB_USER_NAME, (void *)userName );
					if (userName[0])
					{
						mib_get(MIB_USER_PASSWORD,(void *)userPass );
						if((!strcmp(userPass, "0")) || (!strlen(userPass)))
						{
							 mib_get(MIB_DEFAULT_USER_PASSWORD, (void *)default_userPass);
							 memcpy(userPass, default_userPass, MAX_NAME_LEN);
						}
					}
					if(0 == strcmp(userName, entry.username) )
					{
						if(0 == strcmp(userPass, entry.password))
						{
							
						}
						else
						{
							strcpy(entry.password, userPass);
							ftpServer_log(LOG_INFO, "%s(%d):MIB_USER_PASSWORD[%s][%d]\n", __FUNCTION__, __LINE__, userPass, i);
							if ( !mib_chain_update(MIB_VSFTP_ACCOUNT_TBL, (void *)&entry, i))
							{
								printf("ftp_init__ERROR: set MIB_VSFTP_ACCOUNT_TBL to MIB database failed.\n");
								return;
							}
							mib_update(CURRENT_SETTING, CONFIG_MIB_CHAIN);
							ftpServer_log(LOG_INFO, "%s(%d):mib_update succ\n", __FUNCTION__, __LINE__);
						}
					}
				}

                 strcpy(ftp_entry[i].username,entry.username);
                 strcpy(ftp_entry[i].password,entry.password);

                if(i>0)
                {
                    for(j=0;j<i;j++)
                    {
                        if(strcmp(ftp_entry[j].username, entry.username) == 0)
                        {
                            if(strcmp(ftp_entry[j].password, entry.password) == 0)
                            {
                                sameUserNameFlags = 1;
                                break;
                            }
                        }
                    }
                }

                if(sameUserNameFlags == 0)
                {
                    sprintf(cmd, "%s %s\n", entry.username, entry.password);
                    ftpServer_log(LOG_INFO, "%s(%d):cmd[%s]", __FUNCTION__, __LINE__, cmd);
                    fputs(cmd, fptr);
                }

                sameUserNameFlags = 0;
             }
         }

         fclose(fptr);
    }


    fptr = fopen("/var/vsftpd.user_list", "w+");
    fclose(fptr);
    fptr = fopen("/var/vsftpd.users", "w+");
    fclose(fptr);
#if 1
   /*MIB查询enable值,看vsftpd服务是否使能*/
   mib_get(MIB_VSFTP_ENABLE, (void *)&enable);
   ftpServer_log(LOG_INFO, "%s(%d):enable[%d]", __FUNCTION__, __LINE__, enable);
   if(enable != 0)
   {
        system("vsftpd &");
   }
   if(enable == 1)
   {
        system("iptables -A ftp_account -i br0 -p TCP --dport 21 -j ACCEPT");
        system("iptables -A ftp_account -i nas+  -p TCP --dport 21 -j DROP");
        system("iptables -A ftp_account -i ppp+  -p TCP --dport 21 -j DROP");
        system("ip6tables -A ftp_account -i br0 -p TCP --dport 21 -j ACCEPT");
        system("ip6tables -A ftp_account -i nas+  -p TCP --dport 21 -j DROP");
        system("ip6tables -A ftp_account -i ppp+  -p TCP --dport 21 -j DROP");
   }
   else if(enable == 2)
   {
        system("iptables -A ftp_account -i br0 -p TCP --dport 21 -j DROP");
        system("iptables -A ftp_account -i nas+  -p TCP --dport 21 -j ACCEPT");
        system("iptables -A ftp_account -i ppp+  -p TCP --dport 21 -j ACCEPT");
        system("ip6tables -A ftp_account -i br0 -p TCP --dport 21 -j DROP");
        system("ip6tables -A ftp_account -i nas+  -p TCP --dport 21 -j ACCEPT");
        system("ip6tables -A ftp_account -i ppp+  -p TCP --dport 21 -j ACCEPT");
   }
   else if(enable == 3)
   {
        system("iptables -A ftp_account -i br0 -p TCP --dport 21 -j ACCEPT");/*avoid set enable=2*/
        system("iptables -A ftp_account -i nas+  -p TCP --dport 21 -j ACCEPT");
        system("iptables -A ftp_account -i ppp+  -p TCP --dport 21 -j ACCEPT");
        system("iptables -A ftp_account -i br0 -p TCP --dport 21 -j ACCEPT");/*avoid set enable=2*/
        system("iptables -A ftp_account -i nas+  -p TCP --dport 21 -j ACCEPT");
        system("iptables -A ftp_account -i ppp+  -p TCP --dport 21 -j ACCEPT");
   }
#endif // 0
	ftpServer_log(LOG_INFO, "%s(%d):", __FUNCTION__, __LINE__);
}
#else
void smartHGU_ftpserver_init_api(void)
{
	FILE *fptr = NULL;
	int num = 0;
       unsigned char annon = 0;
       unsigned char enable = 1;
       int total = 0;
       int i = 0,j=0;
       char cmd[64] = {0};
       MIB_CE_VSFTP_ACCOUNT_T  entry;
	MIB_CE_VSFTP_ACCOUNT_T  ftp_entry[6];
       	
	     system("syslogd");
	     
	     sleep(1);

       memset(&entry, 0, sizeof(MIB_CE_VSFTP_ACCOUNT_T));
	
       fptr = fopen(FTPSERVER_CONF_FILE, "w+");
       if(fptr == NULL)
       {
            ftpServer_log(LOG_ERR, "%s(%d):create file %s error!", __FUNCTION__, __LINE__, FTPSERVER_CONF_FILE);
       }
       else
       {
            ftpserver_conf_init(fptr);
           /*MIB 读取Annonymous的值*/
           mib_get(MIB_VSFTP_ANNONYMOUS, (void *)&annon);
           ftpServer_log(LOG_INFO, "%s(%d):annon[%d]", __FUNCTION__, __LINE__, annon);
           if(annon == 0)
           {
                fputs("anonymous_enable=NO\n", fptr);
           }
           else
           {
             fputs("anonymous_enable=YES\n", fptr);
           }

           fclose(fptr);
       }
	

       fptr = fopen(FTPSERVER_USERLIST_FILE, "w+");
       if(fptr == NULL)
       {
            ftpServer_log(LOG_INFO, "%s(%d):create file %s error!", __FUNCTION__, __LINE__, FTPSERVER_USERLIST_FILE);
       }
       else
       {
            /*MIB读取用户名和密码列表,循环遍历将值写入配置文件中*/
            total = mib_chain_total(MIB_VSFTP_ACCOUNT_TBL);
            ftpServer_log(LOG_INFO, "%s(%d):total[%d]", __FUNCTION__, __LINE__, total);
            for(i=0; i<total; i++)
            {
                if (!mib_chain_get(MIB_VSFTP_ACCOUNT_TBL, i, (void *)&entry))
                   continue;
                if((strlen(entry.username) == 0) || (strlen(entry.password) == 0))
                {
                	ftpServer_log(LOG_ERR, "%s(%d):illegal username/password", __FUNCTION__, __LINE__);
                	continue;
                }
		   strcpy(ftp_entry[i].username,entry.username);

			if(i>0)
			{
				for(j=0;j<i;j++)
				{
					if(strcmp(ftp_entry[j].username, entry.username) == 0)
					continue;
				}
			}
		   
                sprintf(cmd, "%s %s\n", entry.username, entry.password);
                ftpServer_log(LOG_INFO, "%s(%d):cmd[%s]", __FUNCTION__, __LINE__, cmd);
                fputs(cmd, fptr);
            }
            fclose(fptr);
       }

    		
			fptr = fopen("/var/vsftpd.user_list", "w+");
			fclose(fptr);
			fptr = fopen("/var/vsftpd.users", "w+");
			fclose(fptr);

       /*MIB查询enable值,看vsftpd服务是否使能*/
       mib_get(MIB_VSFTP_ENABLE, (void *)&enable);
       ftpServer_log(LOG_INFO, "%s(%d):enable[%d]", __FUNCTION__, __LINE__, enable);
       if(enable != 0)
       {
            system("vsftpd &");
       }
       if(enable == 2)
       {
       		system("iptables -A inacc -i br0 -p TCP --dport 21 -j DROP");
        	system("iptables -A inacc -i nas+  -p TCP --dport 21 -j ACCEPT");
        	system("iptables -A inacc -i ppp+  -p TCP --dport 21 -j ACCEPT");
       }
       else if(enable == 3)
       {
       		system("iptables -D inacc -i br0 -p TCP --dport 21 -j DROP");/*avoid set enable=2*/
        	system("iptables -A inacc -i nas+  -p TCP --dport 21 -j ACCEPT");
        	system("iptables -A inacc -i ppp+  -p TCP --dport 21 -j ACCEPT");
       }
	
	ftpServer_log(LOG_INFO, "%s(%d):", __FUNCTION__, __LINE__);
}
#endif

