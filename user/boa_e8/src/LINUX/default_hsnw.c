#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include "options.h"
#include "../defines.h"
#include "mib.h"
#include "utility.h"
#include "sysconfig.h"

/*default hs, but reserve wlan hw settings*/
static int reserve_critical_hw_setting(void)
{

	int start, end, i;

	//first backup current setting	
	mib_backup_hs(CONFIG_MIB_ALL);

		// restore current to default
#ifdef CONFIG_USER_XMLCONFIG
	va_cmd("/etc/scripts/flash",2,1, "default", "hs");
#else
	mib_sys_to_default(HW_SETTING);
#endif
	
	mib_retrive_table(MIB_HW_REG_DOMAIN);

	//wlan calibration start.
	start = HS_ENTRY_ID + 29;
	//wlan calibration end.
	end = HS_ENTRY_ID + 215;
	printf("%s-%d start=%d, end=%d\n",__func__,__LINE__,start,end);
	for(i=start;i<=end;i++){
		mib_retrive_table(i);
	}

	// RF DPK start
	start = HS_ENTRY_ID + 230;
	// RF DPK end
	end   = HS_ENTRY_ID + 245;
	printf("RF DPK %s-%d start=%d, end=%d\n",__func__,__LINE__,start,end);
	for(i=start;i<=end;i++){
		mib_retrive_table(i);
	}

	return 0;
}



int main(int argc, char* argv[])
{
	int ret=0;

	reserve_critical_hw_setting();


#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif

	return ret;
}
