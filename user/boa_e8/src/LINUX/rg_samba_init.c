#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <unistd.h>
#include "mib.h"
#include "utility.h"

#define __DEBUG__SAMBAINIT  
#ifdef __DEBUG__SAMBAINIT  
#define DEBUG(format,...) printf("File: "__FILE__", Line: %05d: "format"/n", __LINE__, ##__VA_ARGS__)  
#else  
#define DEBUG(format,...)  
#endif 

int Samba_Touch_Anonymous()
{
	FILE *fp;
	fp = fopen("/var/samba/config1","wb+");
	fprintf(fp,"%s\n","#");
	fprintf(fp,"%s\n","# Realtek Semiconductor Corp.");
	fprintf(fp,"%s\n","#");
	fprintf(fp,"%s\n","# Tony Wu (tonywu@realtek.com)");
	fprintf(fp,"%s\n","# Jan. 10, 2011\n");
	fprintf(fp,"\n");
	fprintf(fp,"%s\n","[global]");
	fprintf(fp,"%s\n","        # netbios name = Realtek");
	fprintf(fp,"%s\n","        # server string = Realtek Samba Server");
	fprintf(fp,"%s\n","        syslog = 10");
	fprintf(fp,"%s\n","        # encrypt passwords = true");
	fprintf(fp,"%s\n","        # passdb backend = smbpasswd");
	fprintf(fp,"%s\n","        socket options = TCP_NODELAY SO_RCVBUF=131072 SO_SNDBUF=131072 IPTOS_LOWDELAY");
	fprintf(fp,"%s\n","        # unix charset = ISO-8859-1");
	fprintf(fp,"%s\n","        # preferred master = no");
	fprintf(fp,"%s\n","        # domain master = no");
	fprintf(fp,"%s\n","        # local master = yes");
	fprintf(fp,"%s\n","        # os level = 20");
	fprintf(fp,"%s\n","        smb ports = 445");
	fprintf(fp,"%s\n","        disable netbios = yes");
	fprintf(fp,"%s\n","        security = share");
	fprintf(fp,"%s\n","#       encrypt passwords = true");
	fprintf(fp,"%s\n","        # guest account = admin");
	fprintf(fp,"%s\n","        deadtime = 15");
	fprintf(fp,"%s\n","        strict sync = no");
	fprintf(fp,"%s\n","        sync always = no");
	fprintf(fp,"%s\n","        dns proxy = no");
	fprintf(fp,"%s\n","        interfaces = lo, br0");
	fprintf(fp,"%s\n","#       usershare allow guests = no");

	fprintf(fp,"%s\n","        use sendfile = true");
	fprintf(fp,"%s\n","        write cache size = 8192000");
	fprintf(fp,"%s\n","        min receivefile size = 16384");
	fprintf(fp,"%s\n","        aio read size = 131072");
	fprintf(fp,"%s\n","        aio write size = 131072");
	fprintf(fp,"%s\n","        aio write behind = true");
	fprintf(fp,"%s\n","        read raw = yes");
	fprintf(fp,"%s\n","        write raw = yes");
	fprintf(fp,"%s\n","        getwd cache = yes");
	fprintf(fp,"%s\n","        oplocks = yes");
	fprintf(fp,"%s\n","        max xmit = 32768");
	fprintf(fp,"%s\n","        large readwrite = yes");

	fprintf(fp,"\n");
	fprintf(fp,"%s\n","[share]");
	fprintf(fp,"%s\n","        comment = realtek");
	fprintf(fp,"%s\n","        path = /mnt");
	fprintf(fp,"%s\n","#       valid users = useradmin");
	fprintf(fp,"%s\n","        public = yes");
	fprintf(fp,"%s\n","        writable = yes");
	fprintf(fp,"%s\n","        printable = no");
	fprintf(fp,"%s\n","        guest ok = yes");
	//	fprintf(fp,"\n");
	fclose(fp);
	return 0;
}

void Samba_Restart_Service(void)
{
	unsigned char samba_enable=0;
	mib_get(MIB_SMB_SERVER_ENABLE, (void *)&samba_enable);

	if(samba_enable != 0)
	{
		DEBUG("***Samba_Restart_Service****\n");
		char cmd[512];
		sprintf(cmd,"killall -SIGKILL smbd");
		system(cmd);
		va_niced_cmd("/bin/smbd", 3, 0, "-D", "-s", "/var/smb.conf");
	}
}

int Samba_Touch_UnAnonymous()
{
	FILE *fp;
	fp = fopen("/var/samba/config2","wb+");
	fprintf(fp,"%s\n","#");
	fprintf(fp,"%s\n","# Realtek Semiconductor Corp.");
	fprintf(fp,"%s\n","#");
	fprintf(fp,"%s\n","# Tony Wu (tonywu@realtek.com)");
	fprintf(fp,"%s\n","# Jan. 10, 2011\n");
	fprintf(fp,"\n");
	fprintf(fp,"%s\n","[global]");
	fprintf(fp,"%s\n","        # netbios name = Realtek");
	fprintf(fp,"%s\n","        # server string = Realtek Samba Server");
	fprintf(fp,"%s\n","        syslog = 1");
	fprintf(fp,"%s\n","        # encrypt passwords = true");
	fprintf(fp,"%s\n","        # passdb backend = smbpasswd");
	fprintf(fp,"%s\n","        socket options = TCP_NODELAY SO_RCVBUF=131072 SO_SNDBUF=131072 IPTOS_LOWDELAY");
	fprintf(fp,"%s\n","        # unix charset = ISO-8859-1");
	fprintf(fp,"%s\n","        # preferred master = no");
	fprintf(fp,"%s\n","        # domain master = no");
	fprintf(fp,"%s\n","        # local master = yes");
	fprintf(fp,"%s\n","        # os level = 20");
	fprintf(fp,"%s\n","        smb ports = 445");
	fprintf(fp,"%s\n","        disable netbios = yes");
	fprintf(fp,"%s\n","        security = user");
	fprintf(fp,"%s\n","        encrypt passwords = true");
	fprintf(fp,"%s\n","        # guest account = admin");
	fprintf(fp,"%s\n","        deadtime = 15");
	fprintf(fp,"%s\n","        strict sync = no");
	fprintf(fp,"%s\n","        sync always = no");
	fprintf(fp,"%s\n","        dns proxy = no");
	fprintf(fp,"%s\n","        interfaces = lo, br0");
	fprintf(fp,"%s\n","        usershare allow guests = no");

	fprintf(fp,"%s\n","        use sendfile = true");
	fprintf(fp,"%s\n","        write cache size = 8192000");
	fprintf(fp,"%s\n","        min receivefile size = 16384");
	fprintf(fp,"%s\n","        aio read size = 131072");
	fprintf(fp,"%s\n","        aio write size = 131072");
	fprintf(fp,"%s\n","        aio write behind = true");
	fprintf(fp,"%s\n","        read raw = yes");
	fprintf(fp,"%s\n","        write raw = yes");
	fprintf(fp,"%s\n","        getwd cache = yes");
	fprintf(fp,"%s\n","        oplocks = yes");
	fprintf(fp,"%s\n","        max xmit = 32768");
	fprintf(fp,"%s\n","        large readwrite = yes");
	
	fprintf(fp,"\n");
	fclose(fp);
	return 0;
}
int Samba_ENABLE()
{
	unsigned char samba_enable=1;
	mib_get(MIB_SMB_SERVER_ENABLE, (void *)&samba_enable);
	DEBUG("***samba_enable=%d***\n",samba_enable);
	if(samba_enable != 0)
		return 1;
	/*if (samba_enable == 0x0001)
	{
	//	system("/bin/smbd -D");
	//Local_Samba();
		return 1;
	}
	if (samba_enable == 0x0002)
	{
	//	system("/bin/smbd -D");
//	Remote_Samba();
//	Local_Samba_Disable_Remote();
		return 1;
	}
	if (samba_enable == 0x0003)
	{
	//	system("/bin/smbd -D");
	//Remote_Samba();
		return 1;
	}*/
	return 0;
}
int Samba_Anonymous()
{
	char cmd[512];
	unsigned char allowanonymous = 0;
	mib_get(MIB_SMB_ANNONYMOUS, (void *)&allowanonymous);
	DEBUG("***allowanonymous=%d***\n",allowanonymous);
	if(allowanonymous == 0)
	{
		sprintf(cmd,"rm -f /var/smb.conf && cp /var/samba/config2 /var/smb.conf");
		system(cmd);
		return 0;
	}
	else if (allowanonymous == 1)
	{
		sprintf(cmd,"rm -f /var/smb.conf && cp /var/samba/config1 /var/smb.conf");
		system(cmd);
		return 1;
	}
}
int add_smbd_default_account(char *username, char *passwd)
{
	MIB_CE_SMB_ACCOUNT_T entry;
	int mibtotal=0, i;

	if (!username || !passwd)//username should not be NULL
		return 0;
	
	memset(&entry, 0, sizeof(entry));
	snprintf(entry.username, MAX_NAME_LEN, "%s", username);
	snprintf(entry.password, MAX_NAME_LEN, "%s", passwd);

	if (!mib_chain_add(MIB_SMBD_ACCOUNT_TBL, (void *)&entry))
		return 0;

	return 1;
}
int Samba_User_Info(unsigned char allowanonymous)
{
	char cmd[512];
	int totalEntry=0;
	int i = 0;
	char struseradmin[]="useradmin";
	char strnobody[]="nobody";
	char strtelecom[]="telecomadmin";
	char stradsl[]="adsl";
	//	char str1[]=":$1$$m9g7v7tSyWPyjvelclu6D1:0:0::/tmp:/bin/sh";
	MIB_CE_SMB_ACCOUNT_T entry;
	FILE *fp_pass;
	char add_samba_user_cmd[1024] = "echo \"[share]\n	comment = Realtek\n	path = /mnt\n	valid users = ";
	int user_count = 0;
	char  usPasswd[MAX_NAME_LEN] = "";
	unsigned char userName[MAX_NAME_LEN], userPass[MAX_NAME_LEN], default_userPass[MAX_NAME_LEN], old_userPass[MAX_NAME_LEN];
	
	memset(&entry,0,sizeof(MIB_CE_SMB_ACCOUNT_T));
	totalEntry = mib_chain_total(MIB_SMBD_ACCOUNT_TBL);
	DEBUG("____________totalEntry[%d]\n", totalEntry);
	if(allowanonymous == 0)
	{
		DEBUG("_______samba __init user mode\n");
		sprintf(cmd,"rm -f /var/smb.conf && cp /var/samba/config2 /var/smb.conf");
		system(cmd);
	}
	if(0 == totalEntry)
	{
		DEBUG("__000000 user__mib__add useradmin\n");
		strncat(add_samba_user_cmd, "useradmin", strlen("useradmin"));
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
		add_smbd_default_account(userName, userPass);
		mib_update(CURRENT_SETTING, CONFIG_MIB_CHAIN);
		DEBUG("_________________mib_update succ\n");
		fp_pass = fopen("/tmp/.pass", "w"); 
		if(fp_pass == NULL )	  
		{		 
			return 1;
		}
		fprintf(fp_pass, "%s\n",userPass);
		fprintf(fp_pass, "%s\n",userPass);
		fclose(fp_pass);
		DEBUG("*******valid*str useradmin***\n");
		sprintf(cmd, "cat /tmp/.pass | pdbedit -a %s -t", userName);
		system(cmd);
	}
	for(i = 0;i<totalEntry;i++)
	{
		if(!mib_chain_get(MIB_SMBD_ACCOUNT_TBL,i,(void *)&entry))
		{
			DEBUG("*Get account configuration information from MIB database failed*\n");
			return 1;
		}
		DEBUG("****mib_chain_get111****%s %s**\n",entry.username,entry.password);
		//sprintf(cmd,"rm -f /var/smb.conf && cp /var/samba/config2 /var/smb.conf");
		//system(cmd);
		if(allowanonymous == 0)
		{
			strncat(add_samba_user_cmd, entry.username, MAX_NAME_LEN);
			++user_count;
			if(user_count == totalEntry)
			{
			}
			else
			{
				strncat(add_samba_user_cmd, ",", 1);
			}
		}
		
		if(strcmp(struseradmin,entry.username) == 0)
		{
			//add by zhaox
			DEBUG("____mib__add useradmin\n");
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
			for(i = 0;i<totalEntry;i++)
			{
				if (!mib_chain_get(MIB_SMBD_ACCOUNT_TBL, i, (void *)&entry))
				    continue;
				 if((strlen(entry.username) == 0) || (strlen(entry.password) == 0))
				 {
				     continue;
				 }
				 if(0 == strcmp(userName, entry.username) )
				 {
				 	if(0 == strcmp(userPass, entry.password))
				 	{
						
				 	}
					else
					{
						strcpy(entry.password, userPass);
						DEBUG("_________________MIB_USER_PASSWORD[%s][%d]\n", userPass, i);
						if ( !mib_chain_update(MIB_SMBD_ACCOUNT_TBL, (void *)&entry, i))
						{
							printf("samba_init__ERROR: set MIB_SMBD_ACCOUNT_TBL to MIB database failed.\n");
							return 1;
						}
						mib_update(CURRENT_SETTING, CONFIG_MIB_CHAIN);
						DEBUG("_________________mib_update succ\n");
					}
					fp_pass = fopen("/tmp/.pass", "w"); 
					if(fp_pass == NULL )	  
					{		 
						return 1;
					}
					fprintf(fp_pass, "%s\n",userPass);
					fprintf(fp_pass, "%s\n",userPass);
					fclose(fp_pass);
					DEBUG("*******valid*struseradmin***\n");
					sprintf(cmd, "cat /tmp/.pass | pdbedit -a %s -t", entry.username);
					system(cmd);
				 }
			}
			/*
			for(i = 0;i<totalEntry;i++)
			{
				if (!mib_chain_get(MIB_SMBD_ACCOUNT_TBL, i, (void *)&entry))
				    continue;
				printf("________[%d][%s][%s]\n", entry.index, entry.username, entry.password);
			}
			*/
		}
		else if(strcmp(strnobody,entry.username) == 0)
		{
			//add by zhaox
			fp_pass = fopen("/tmp/.pass", "w"); 
			if(fp_pass == NULL )	  
			{		 
				return 1;
			}
			fprintf(fp_pass, "%s\n",entry.password);
			fprintf(fp_pass, "%s\n",entry.password);
			fclose(fp_pass);
			DEBUG("*******valid*strnobody***\n");
			//sprintf(cmd,"smbpasswd %s %s",entry.username,entry.password);
			//sprintf(cmd, "cat /tmp/.pass | smbpasswd -a %s -s", entry.username);
			sprintf(cmd, "cat /tmp/.pass | pdbedit -a %s -t", entry.username);
			
			system(cmd);
			//Samba_Restart_Service();
		}
		else if(strcmp(strtelecom,entry.username) == 0)
		{
			//add by zhaox
			fp_pass = fopen("/tmp/.pass", "w"); 
			if(fp_pass == NULL )	  
			{		 
				return 1;
			}
			fprintf(fp_pass, "%s\n",entry.password);
			fprintf(fp_pass, "%s\n",entry.password);
			fclose(fp_pass);
			DEBUG("*******valid*strtelecom***\n");
			//sprintf(cmd,"smbpasswd %s %s",entry.username,entry.password);
			//sprintf(cmd, "cat /tmp/.pass | smbpasswd -a %s -s", entry.username);
			sprintf(cmd, "cat /tmp/.pass | pdbedit -a %s -t", entry.username);

			system(cmd);
			//Samba_Restart_Service();
		}
		else if(strcmp(stradsl,entry.username) == 0)
		{
			//add by zhaox
			fp_pass = fopen("/tmp/.pass", "w"); 
			if(fp_pass == NULL )	  
			{		 
				return 1;
			}
			fprintf(fp_pass, "%s\n",entry.password);
			fprintf(fp_pass, "%s\n",entry.password);
			fclose(fp_pass);
			DEBUG("*******valid*stradsl***\n");
			//sprintf(cmd,"smbpasswd %s %s",entry.username,entry.password);
			//sprintf(cmd, "cat /tmp/.pass | smbpasswd -a %s -s", entry.username);
			sprintf(cmd, "cat /tmp/.pass | pdbedit -a %s -t", entry.username);
			system(cmd);
			//Samba_Restart_Service();
		}
		else
		{
			DEBUG("*******valid****\n");
			sprintf(cmd,"echo \"%s:$1$$m9g7v7tSyWPyjvelclu6D1:0:0::/tmp:/bin/sh\" >> /var/passwd",entry.username);
			system(cmd);
			sprintf(cmd,"echo \"%s:$1$$m9g7v7tSyWPyjvelclu6D1:0:0::/tmp:/bin/sh\" >> /var/passwd.smb",entry.username);
			system(cmd);
			//add by zhaox
			fp_pass = fopen("/tmp/.pass", "w"); 
			if(fp_pass == NULL )	  
			{		 
				return 1;
			}
			fprintf(fp_pass, "%s\n",entry.password);
			fprintf(fp_pass, "%s\n",entry.password);
			fclose(fp_pass);
			//sprintf(cmd,"smbpasswd %s %s",entry.username,entry.password);
			//sprintf(cmd, "cat /tmp/.pass | smbpasswd -a %s -s", entry.username);
			sprintf(cmd, "cat /tmp/.pass | pdbedit -a %s -t", entry.username);
			system(cmd);
			//Samba_Restart_Service();
		}
	}

	if(allowanonymous == 0)
	{
		strncat(add_samba_user_cmd, "\n	public = yes\n	writable = yes\n	printable = no\n\" >> /var/smb.conf", 
			strlen("\n	public = yes\n	writable = yes\n	printable = no\n\" >> /var/smb.conf")+1);
		DEBUG("samba_init__DEBUG:[%s]\n", add_samba_user_cmd);
		system(add_samba_user_cmd);
	}

	Samba_Restart_Service();

	DEBUG("samba_init__DEBUG[Samba_User_Info return]\n"); 
	return 0;
}
int smartHGU_Samba_Initialize(void)
{
	char cmd1[512];
	char devName[200];
	mib_get(MIB_DEVICE_NAME,(void *)devName);
	DEBUG("*****devName=%s*****\n",devName);
	sprintf(cmd1,"echo \"%s\" > /proc/sys/kernel/hostname",devName);
	system(cmd1);
	sprintf(cmd1,"echo \"telecomadmin:$1$$AwK5ysgOLgsgOriKA.7a./:0:0::/tmp:/bin/sh\" >> /var/passwd.smb");
	system(cmd1);
	sprintf(cmd1,"echo \"adsl:$1$$m9g7v7tSyWPyjvelclu6D1:0:0::/tmp:/bin/sh\" >> /var/passwd.smb");
	system(cmd1);
	sprintf(cmd1,"touch /var/samba/smbpasswd /var/group");
	system(cmd1);
	
	Samba_Touch_Anonymous();
	Samba_Touch_UnAnonymous();

	if(Samba_Anonymous() == 0)
		Samba_User_Info(0);
	else
	{
		Samba_User_Info(1);
		//Samba_Restart_Service();
	}

	return 0;
}
