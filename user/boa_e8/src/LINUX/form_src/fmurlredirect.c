/*
 *      Web server handler routines for URL Redirect
 */
#include "options.h"

/*-- Local inlcude files --*/
#include "mib.h"
#include "fmdefs.h"

#ifdef CONFIG_SUPPORT_CAPTIVE_PORTAL
void formURLRedirect(request * wp, char *path, char *query)
{
	unsigned char urlredirect_enable=0; 	
	unsigned char vChar = 0;
	char *cp_url, *strVal, *submitUrl;

	_TRACE_CALL;

	strVal = boaGetVar(wp, "urlredirect_enable", "");
	if (strVal[0]) {
		if (strVal[0] == '0')
			urlredirect_enable = 0;
		else if(strVal[0] == '1')
			urlredirect_enable = 1;
	}

	mib_set(MIB_CAPTIVEPORTAL_ENABLE, (void *)&urlredirect_enable);

	cp_url = boaGetVar(wp, "redirect_url", "");
	if(cp_url)
	{
		mib_set( MIB_CAPTIVEPORTAL_URL, (void *)cp_url);
	}

	if(urlredirect_enable && cp_url && strlen(cp_url))
	{
//		start_captiveportal();
		enable_http_redirect2CaptivePortalURL(1);
	}
	else
		enable_http_redirect2CaptivePortalURL(0);

#ifdef COMMIT_IMMEDIATELY
	Commit();
#endif

	submitUrl = boaGetVar(wp, "submit-url", "");   // hidden page
	if (submitUrl[0])
		boaRedirect(wp, submitUrl);
	else
		boaDone(wp, 200);
	return;
	
check_err:
	_TRACE_LEAVEL;
	return ;
}
#endif

