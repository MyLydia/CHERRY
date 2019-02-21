/**
 @file		subr_pvcsearch.c
 @brief 	Auto-sense PVC function
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/atmdev.h>
#include "utility.h"
#include <rtk/linux/ra867x_atm.h>

#ifdef CONFIG_DEV_xDSL
#if defined(AUTO_PVC_SEARCH_TR068_OAMPING) || defined(AUTO_PVC_SEARCH_PURE_OAMPING) || defined(AUTO_PVC_SEARCH_AUTOHUNT)
#ifdef AUTO_PVC_SEARCH_AUTOHUNT
/*
 *	proc file to communicate with sar driver for auto-hunt
 *	Write:
 *	- a leading '0' and followed a pvc: stop auto-hunt.
 *		ex. "0 0,35"
 *	- a leading '1' and followed a list of pvc to hunt.
 *		ex. "1(0 35)(8 35)"
 *	Read on hunt success
 *	- "vpi,vci,framing,rfc_mode" tuple of the detected pvc.
 *		framing= 0: LLC_SNAP; 1: VC_MUX
 *		rfc_mode= 0: RFC1483_BRIDGED; 1: RFC1483_ROUTED; 2: RFC1577; 3: RFC2364; 4: RFC2516
 *		ex. "5,35,0,0"
 */
#define PROC_AUTOPVC_HUNT	"/proc/AUTO_PVC_SEARCH"

static void StartAutoHunt(void);
static void StopAutoHunt(int vpi,int vci);
#endif

/*
 *	status of auto-pvc
 *	format:
 *	"state:x OAMPing:y AutoHUNT:z
 *	
 *	where the meanning of y and z depend on the state(x) of auto-pvc
 *	x==0 : auto-pvc is stopped, y&z mean auto-search result.
 *		y&z: 0 for 'not found', 1 for 'found'
 *	x==1 : auto-pvc is running, y&z mean running status.
 *		y&z: 0 for deactive, 1 for active
 */
#define PATH_AUTOPVC_STATUS	"/tmp/autoPVC"

typedef enum {
	AUTOPVC_OAM,
	AUTOPVC_HUNT
} AUTOPVC_T;

AUTOPVC_T autopvc_target;
int autoHunt_found = 0;
int fin_AutoSearchPVC = 1;
int sok=0;

int setVC0Connection(unsigned int vpi, unsigned int vci, int encaps, int cmode);
void succ_AutoSearchPVC(void);
void stopAutoSearchPVC(void *dummy);

static void update_autopvc_state()
{
	FILE *fp;
	
	fp = fopen(PATH_AUTOPVC_STATUS, "w+");
	if(fp) {
		if (fin_AutoSearchPVC)
			fprintf(fp, "state:0 OAMPing:%d AutoHUNT:%d\n", sok, autoHunt_found);
		else
			fprintf(fp, "state:1 OAMPing:%d AutoHUNT:%d\n", autopvc_target==AUTOPVC_OAM?1:0, autopvc_target==AUTOPVC_HUNT?1:0);
		fclose(fp);
	}
}

static int doOAMLoopback(int vpi, int vci)
{
#ifdef EMBED
	int	skfd;
	struct atmif_sioc mysio;
	ATMOAMLBReq lbReq;
	ATMOAMLBState lbState;
	int finished_OAMLB;
	time_t currTime, preTime;

	if((skfd = socket(PF_ATMPVC, SOCK_DGRAM, 0)) < 0){
		perror("socket open error");
		return -1;
	}

	printf("%s(%d) vpi=%d vci=%d\n", __FUNCTION__, __LINE__, vpi, vci);
	memset(&lbReq, 0, sizeof(ATMOAMLBReq));
	memset(&lbState, 0, sizeof(ATMOAMLBState));
	lbReq.Scope = 0;	// Segment
	lbReq.vpi = vpi;
	lbReq.vci = vci;
	memset(lbReq.LocID, 0xff, 16);	// Loopback Location ID
	mysio.number = 0;	// ATM interface number
	mysio.arg = (void *)&lbReq;
	// Start the loopback test
	if (ioctl(skfd, ATM_OAM_LB_START, &mysio)<0) {
		perror("ioctl: ATM_OAM_LB_START failed !");
		close(skfd);
		return -1;
	}

	finished_OAMLB = 0;
	// Mason Yu. If receive a SIGALRM, the all timer will be disable.
	// So I use "time()" to schedule Timer.
	//signal(SIGALRM, lbTimeout);
	//alarm(MAXWAIT);

	// Mason Yu. I can not use "TIMEOUT()" to register timer.
	//TIMEOUT_F(oamLBTimeout, 0, 1, oamLoopBK_ch);
	time(&currTime);
	preTime = currTime;

	// Query the loopback status
	mysio.arg = (void *)&lbState;
	lbState.vpi = vpi;
	lbState.vci = vci;
	lbState.Tag = lbReq.Tag;

	while (1)
	{
		// Mason Yu. Use time() to schedule Timer.
		time(&currTime);
	    	if (currTime - preTime >= 1) {
	    		printf("This OAMLB is time out!\n");
	    		finished_OAMLB = 1;
	    	}

		if (finished_OAMLB)
			break;	// break for timeout

		if (ioctl(skfd, ATM_OAM_LB_STATUS, &mysio)<0) {
			perror("ioctl: ATM_OAM_LB_STATUS failed !");
			mysio.arg = (void *)&lbReq;
			ioctl(skfd, ATM_OAM_LB_STOP, &mysio);
			close(skfd);
			return -1;
		}

		if (lbState.count[0] > 0)
		{
			break;	// break for loopback success
		}
	}

	mysio.arg = (void *)&lbReq;
	// Stop the loopback test
	if (ioctl(skfd, ATM_OAM_LB_STOP, &mysio)<0) {
		perror("ioctl: ATM_OAM_LB_STOP failed !");
		close(skfd);
		return -1;
	}
	close(skfd);

	if (finished_OAMLB)
		return 0;	// failed
	else
		return 1;	// successful
#else
	return 1;
#endif
}

static int doOAMLoopback_F5_EndToEnd(int vpi, int vci)
{
#ifdef EMBED
	int	skfd;
	struct atmif_sioc mysio;
	ATMOAMLBReq lbReq;
	ATMOAMLBState lbState;
	int finished_OAMLB_F5_EndToEnd;
	time_t currTime, preTime;

	if((skfd = socket(PF_ATMPVC, SOCK_DGRAM, 0)) < 0){
		perror("socket open error(F5 End-To-End)");
		return -1;
	}

	printf("%s(%d) vpi=%d vci=%d\n", __FUNCTION__, __LINE__, vpi, vci);
	memset(&lbReq, 0, sizeof(ATMOAMLBReq));
	memset(&lbState, 0, sizeof(ATMOAMLBState));
	lbReq.Scope = 1;	// End-To-End
	lbReq.vpi = vpi;
	lbReq.vci = vci;
	memset(lbReq.LocID, 0xff, 16);	// Loopback Location ID
	mysio.number = 0;	// ATM interface number
	mysio.arg = (void *)&lbReq;
	// Start the loopback test
	if (ioctl(skfd, ATM_OAM_LB_START, &mysio)<0) {
		perror("ioctl: ATM_OAM_LB_START(F5 End-To-End) failed !");
		close(skfd);
		return -1;
	}

	finished_OAMLB_F5_EndToEnd = 0;
	// Mason Yu. If receive a SIGALRM, the all timer will be disable.
	// So I use "time()" to schedule Timer.
	//signal(SIGALRM, lbTimeout);
	//alarm(MAXWAIT);

	// Mason Yu. I can not use "TIMEOUT()" to register timer.
	//TIMEOUT_F(oamLBTimeout, 0, 1, oamLoopBK_ch);
	time(&currTime);
	preTime = currTime;

	// Query the loopback status
	mysio.arg = (void *)&lbState;
	lbState.vpi = vpi;
	lbState.vci = vci;
	lbState.Tag = lbReq.Tag;

	while (1)
	{
		// Mason Yu. Use time() to schedule Timer.
		time(&currTime);
	    	if (currTime - preTime >= 1) {
	    		printf("This OAMLB(F5 End-To-End) is time out!\n");
	    		finished_OAMLB_F5_EndToEnd = 1;
	    	}

		if (finished_OAMLB_F5_EndToEnd)
			break;	// break for timeout

		if (ioctl(skfd, ATM_OAM_LB_STATUS, &mysio)<0) {
			perror("ioctl: ATM_OAM_LB_STATUS(F5 End-To-End) failed !");
			mysio.arg = (void *)&lbReq;
			ioctl(skfd, ATM_OAM_LB_STOP, &mysio);
			close(skfd);
			return -1;
		}

		if (lbState.count[0] > 0)
		{
			break;	// break for loopback success
		}
	}

	mysio.arg = (void *)&lbReq;
	// Stop the loopback test
	if (ioctl(skfd, ATM_OAM_LB_STOP, &mysio)<0) {
		perror("ioctl: ATM_OAM_LB_STOP(F5 End-To-End) failed !");
		close(skfd);
		return -1;
	}
	close(skfd);

	if (finished_OAMLB_F5_EndToEnd)
		return 0;	// failed
	else
		return 1;	// successful
#else
	return 1;
#endif
}

// Timer for auto search PVC
#define MAX_PVC_SEARCH_PAIRS 16


#ifdef AUTO_PVC_SEARCH_TR068_OAMPING
typedef struct pvc_entry {
	unsigned long vpi;
	unsigned long vci;
} PVC_T;

PVC_T pvcList[] = {{0, 35}, {8, 35}, {0, 43}, {0, 51}, {0, 59},
	{8, 43}, {8, 51}, {8, 59}, {0}
};
#endif

void succ_AutoSearchPVC(void)
{
	fin_AutoSearchPVC = 1;
	UNTIMEOUT_F(stopAutoSearchPVC, 0, autoSearchPVC_ch);
	printf("***** Auto Search PVC is successful and stopped ! *****\n");
	syslog(LOG_INFO, "Auto Search PVC is successful and stopped !\n");
}

#ifdef AUTO_PVC_SEARCH_AUTOHUNT
static void StopSarAutoPvcSearch(int vpi,int vci)
{
	FILE *fp;
	if (fp=fopen(PROC_AUTOPVC_HUNT, "w") )
	{
//		printf("StopSarAutoPvcSearch: received (%d,%d) inform SAR driver stop auto-pvc-search\n", vpi,vci);

		fprintf( fp, "0 %d,%d\n", vpi,vci);
		fclose(fp);
	} else {
		printf("Open %s failed! Can't stop SAR driver doing auto-pvc-search\n", PROC_AUTOPVC_HUNT);
	}
}
#endif

// Mason Yu
#ifdef AUTO_PVC_SEARCH_TR068_OAMPING
static void startAutoPVCSearchTR068OAMPing_F5_Segment(MIB_CE_ATM_VC_Tp pEntry, unsigned long bitmap)
{
	int idx;
	unsigned long mask=1;
	unsigned long ovpi, ovci;
	unsigned char vChar;

	if (!pEntry || !pEntry->enable)
		goto search_table_tr068;

	printf("TR068 OAMPing(F5 Segment): start searching by default pvc(%d, %d)...\n", pEntry->vpi, pEntry->vci);

        if (doOAMLoopback(pEntry->vpi, pEntry->vci)!=1)
	{
		stopConnection(pEntry);

search_table_tr068:
		// start searching ...
		printf("TR068 OAMPing(F5 Segment): start searching by pvc list...\n");

		//Retrieve PVC list from Flash
		for (idx=0; pvcList[idx].vpi || pvcList[idx].vci; idx++) {
			if (bitmap & mask) {
				if (doOAMLoopback(pvcList[idx].vpi, pvcList[idx].vci)) {
					// That's it
					printf("TR068 OAMPing(F5 Segment):That's it! vpi=%d, vci=%d\n", pvcList[idx].vpi, pvcList[idx].vci);
					ovpi = pvcList[idx].vpi;
					ovci = pvcList[idx].vci;
					sok=1;
					break;
				}
			}
			mask <<= 1;
		}

		if (sok) { // search ok, set it
			// OAM ping is cell level, cannot tell framing and rfc_mode
			setVC0Connection(ovpi, ovci, ENCAP_LLC, CHANNEL_MODE_BRIDGE);
			succ_AutoSearchPVC();
		}
		else { // search failed, back to original
			printf("TR068 OAMPing(F5 Segment):Auto-search pvc failed !\n");
		}
	}
	else
	{
		printf("TR068 OAMPing(F5 Segment):first-pvc oam loopback ok!\n");
		sok=1;
#ifdef AUTO_PVC_SEARCH_AUTOHUNT
		StopAutoHunt(pEntry->vpi, pEntry->vci);
#endif
       		succ_AutoSearchPVC();
   }
}

static void startAutoPVCSearchTR068OAMPing_F5_EndToEnd(MIB_CE_ATM_VC_Tp pEntry, unsigned long bitmap)
{
	int idx;
	unsigned long mask=1;
	unsigned long ovpi, ovci;
	unsigned char vChar;

	if (!pEntry || !pEntry->enable)
		goto search_table_tr068;

	printf("TR068 OAMPing(F5 End-To-End): start searching by default pvc(%d, %d)...\n", pEntry->vpi, pEntry->vci);
	
        if (doOAMLoopback_F5_EndToEnd(pEntry->vpi, pEntry->vci)!=1)
	{
		stopConnection(pEntry);

search_table_tr068:
		// start searching ...
		printf("TR068 OAMPing(F5 End-To-End): start searching by pvc list...\n");

		//Retrieve PVC list from Flash
		for (idx=0; pvcList[idx].vpi || pvcList[idx].vci; idx++) {
			if (bitmap & mask) {
				if (doOAMLoopback_F5_EndToEnd(pvcList[idx].vpi, pvcList[idx].vci)) {
					// That's it
					printf("TR068 OAMPing(F5 End-To-End):That's it! vpi=%d, vci=%d\n", pvcList[idx].vpi, pvcList[idx].vci);
					ovpi = pvcList[idx].vpi;
					ovci = pvcList[idx].vci;
					sok=1;
					break;
				}
			}
			mask <<= 1;
		}

		if (sok) { // search ok, set it
			// OAM ping is cell level, cannot tell framing and rfc_mode
			setVC0Connection(ovpi, ovci, ENCAP_LLC, CHANNEL_MODE_BRIDGE);
			succ_AutoSearchPVC();
		}
		else { // search failed, back to original
			printf("TR068 OAMPing(F5 End-To-End):Auto-search pvc failed !\n");
		}
	}
	else
	{
		printf("TR068 OAMPing(F5 End-To-End):first-pvc oam loopback ok!\n");
		sok=1;
#ifdef AUTO_PVC_SEARCH_AUTOHUNT
		StopAutoHunt(pEntry->vpi, pEntry->vci);
#endif
       		succ_AutoSearchPVC();
   }
}
#endif // of AUTO_PVC_SEARCH_TR068_OAMPING

#ifdef AUTO_PVC_SEARCH_PURE_OAMPING
static void startAutoPVCSearchPureOAMPing_F5_Segment(MIB_CE_ATM_VC_Tp pEntry, unsigned long bitmap)
{
	int idx;
	unsigned long mask=1;
	unsigned char vChar;

	//  read PVC table from flash
	unsigned int entryNum, Counter;
	//MIB_AUTO_PVC_SEARCH_Tp entryP;
	MIB_AUTO_PVC_SEARCH_T Entry;
	entryNum = mib_chain_total(MIB_AUTO_PVC_SEARCH_TBL);
	if(entryNum > MAX_PVC_SEARCH_PAIRS)
		entryNum = MAX_PVC_SEARCH_PAIRS;


	if (!pEntry || !pEntry->enable)
		goto search_table;

	printf("Pure OAMping(F5 Segment): start searching by default pvc(%d, %d)...\n", pEntry->vpi, pEntry->vci);
        if (doOAMLoopback(pEntry->vpi, pEntry->vci)!=1)
	{
		stopConnection(pEntry);
search_table:
		// start searching ...
		printf("Pure OAMping(F5 Segment): start searching by pvc list...\n");

		//Retrieve PVC list
		for(Counter=0; Counter< entryNum; Counter++)
		{
			if (!mib_chain_get(MIB_AUTO_PVC_SEARCH_TBL, Counter, (void *)&Entry))
				continue;
			if (doOAMLoopback(Entry.vpi, Entry.vci)) {
				// That's it
				printf("Pure OAMping(F5 Segment):That's it! vpi=%d, vci=%d\n", Entry.vpi, Entry.vci);
#ifdef AUTO_PVC_SEARCH_AUTOHUNT
				printf("Pure OAMping(F5 Segment):Inform SAR driver to stop pvc search\n");
				StopAutoHunt(Entry.vpi, Entry.vci);
#endif
				sok=1;
				break;
			}

		}


		if (sok) { // search ok, set it
			// OAM ping is cell level, cannot tell framing and rfc_mode
			setVC0Connection(Entry.vpi, Entry.vci, ENCAP_LLC, CHANNEL_MODE_BRIDGE);
			succ_AutoSearchPVC();
		}
		else { // search failed, back to original
			printf("Pure OAMping(F5 Segment): Auto-search PVC failed !\n");
		}
	}
	else
	{
		printf("Pure OAMping(F5 Segment): first-pvc oam loopback ok!\n");
		sok=1;
#ifdef AUTO_PVC_SEARCH_AUTOHUNT
		StopAutoHunt(pEntry->vpi, pEntry->vci);
#endif
		succ_AutoSearchPVC();

	}
}

static void startAutoPVCSearchPureOAMPing_F5_EndToEnd(MIB_CE_ATM_VC_Tp pEntry, unsigned long bitmap)
{
	int idx;
	unsigned long mask=1;
	unsigned char vChar;

	//  read PVC table from flash
	unsigned int entryNum, Counter;
	//MIB_AUTO_PVC_SEARCH_Tp entryP;
	MIB_AUTO_PVC_SEARCH_T Entry;
	entryNum = mib_chain_total(MIB_AUTO_PVC_SEARCH_TBL);
	if(entryNum > MAX_PVC_SEARCH_PAIRS)
		entryNum = MAX_PVC_SEARCH_PAIRS;


	if (!pEntry || !pEntry->enable)
		goto search_table;

	printf("Pure OAMping(F5 End-To-End): start searching by default pvc(%d, %d)...\n", pEntry->vpi, pEntry->vci);
        if (doOAMLoopback_F5_EndToEnd(pEntry->vpi, pEntry->vci)!=1)
	{
		stopConnection(pEntry);
search_table:
		// start searching ...
		printf("Pure OAMping(F5 End-To-End): start searching by pvc list...\n");

		//Retrieve PVC list
		for(Counter=0; Counter< entryNum; Counter++)
		{
			if (!mib_chain_get(MIB_AUTO_PVC_SEARCH_TBL, Counter, (void *)&Entry))
				continue;
			if (doOAMLoopback_F5_EndToEnd(Entry.vpi, Entry.vci)) {
				// That's it
				printf("Pure OAMping(F5 End-To-End):That's it! vpi=%d, vci=%d\n", Entry.vpi, Entry.vci);
#ifdef AUTO_PVC_SEARCH_AUTOHUNT
				printf("Pure OAMping(F5 End-To-End):Inform SAR driver to stop pvc search\n");
				StopAutoHunt(Entry.vpi, Entry.vci);
#endif
				sok=1;
				break;
			}

		}


		if (sok) { // search ok, set it
			// OAM ping is cell level, cannot tell framing and rfc_mode
			setVC0Connection(Entry.vpi, Entry.vci, ENCAP_LLC, CHANNEL_MODE_BRIDGE);
			succ_AutoSearchPVC();
		}
		else { // search failed, back to original
			printf("Pure OAMping(F5 End-To-End): Auto-search PVC failed !\n");
		}
	}
	else
	{
		printf("Pure OAMping(F5 End-To-End): first-pvc oam loopback ok!\n");
		sok=1;
#ifdef AUTO_PVC_SEARCH_AUTOHUNT
		StopAutoHunt(pEntry->vpi, pEntry->vci);
#endif
		succ_AutoSearchPVC();

   }
}
#endif // of AUTO_PVC_SEARCH_PURE_OAMPING

static MIB_CE_ATM_VC_T vc0_Entry;

// Mason Yu
// If the configuration has include ch0, we just update ch0 with Searched VPI/VCI.
// If the configuration has not include ch0, we add a new entry(ch0) with Searched VPI/VCI.
int setVC0Connection(unsigned int vpi, unsigned int vci, int encaps, int cmode)
{
	MIB_CE_ATM_VC_T Entry;
	unsigned int entryNum, pvcIdx;
	int i, found;

	printf("%s(%d) (%d, %d)\n", __FUNCTION__, __LINE__, vpi, vci);
	entryNum = mib_chain_total(MIB_ATM_VC_TBL);
	found = 0;
	// find the first pvc entry to update
	for (i=0; i<entryNum; i++) {
		if(!mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&Entry))
			continue;

		if(MEDIA_INDEX(Entry.ifIndex) != MEDIA_ATM)
			continue;
		if (!found) { // first pvc found
			found = 1; pvcIdx = i;
			break;
		}
	}
	// delete duplicate pvc if any
	if (found) {
		for (i=entryNum-1; i>pvcIdx; i--) {
			if(!mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&Entry))
				continue;
        	
			if(MEDIA_INDEX(Entry.ifIndex) != MEDIA_ATM)
				continue;
			// delete duplicate pvc if any
			if (Entry.vpi == vpi && Entry.vci == vci) {
				stopConnection(&Entry);
				mib_chain_delete(MIB_ATM_VC_TBL, i);
			}
		}
	}
	
	/* Retrieve ch 0's entry */
	if (!found) {
		// The ch0 does not exist
		printf("%s: The ch0 does not exist, so add it.\n", __FUNCTION__);
		memset(&Entry, 0x00, sizeof(Entry));

		// todo: may need to specify other parameters
		Entry.ifIndex = TO_IFINDEX(MEDIA_ATM, DUMMY_PPP_INDEX, 0);
		Entry.vpi = vpi;
		Entry.qos = ATMQOS_UBR;
		Entry.vci = vci;
		Entry.pcr = ATM_MAX_US_PCR;
		Entry.encap = encaps;
		Entry.cmode = cmode;
		Entry.napt = 1;
		Entry.mtu = 1500;
		Entry.enable = 1;
		#ifdef CONFIG_USER_RTK_WAN_CTYPE
		Entry.applicationtype = X_CT_SRV_INTERNET;
		#endif
		#ifdef CONFIG_IPV6
		Entry.IpProtocol = IPVER_IPV4;
		#endif
		if (Entry.cmode == CHANNEL_MODE_PPPOE)
			Entry.ifIndex = TO_IFINDEX(MEDIA_ATM, 0, 0);
		if (Entry.cmode == CHANNEL_MODE_PPPOA)
			Entry.ifIndex = TO_IFINDEX(MEDIA_ATM, 0, DUMMY_VC_INDEX);

		/* create a new connection */
		if(mib_chain_add(MIB_ATM_VC_TBL, (unsigned char*)&Entry) <=0){
			printf("%s: Error! Add MIB_ATM_VC_TBL chain record for Auto PVC Search.\n", __FUNCTION__);
			return 0;
		}
		mib_update(CURRENT_SETTING, CONFIG_MIB_ALL);

	} else {
		// The ch0 exist
		// get the first pvc entry and update it.
		mib_chain_get(MIB_ATM_VC_TBL, pvcIdx, (void *)&Entry);
		deleteConnection(CONFIGONE, &Entry);

		Entry.vpi = vpi;
		Entry.vci = vci;

		mib_chain_update(MIB_ATM_VC_TBL, (void *)&Entry, pvcIdx);
		mib_update(CURRENT_SETTING, CONFIG_MIB_ALL);
	}
	restartWAN(CONFIGONE, &Entry);
}

#ifdef AUTO_PVC_SEARCH_AUTOHUNT
// autohunt found event handler
void register_pvc(int signum)
{
	FILE *fp;
	unsigned int vpi, vci, framing, rfc_mode, encaps, cmode;
	MIB_CE_ATM_VC_T Entry;

	printf("signal (%x) handler register_pvc got called\n", signum);
	if (fp=fopen(PROC_AUTOPVC_HUNT, "r") ) {
		fscanf( fp, "%d,%d,%d,%d", &vpi, &vci, &framing, &rfc_mode);
		printf("%s: (%d, %d, %d, %d)\n", __FUNCTION__, vpi, vci, framing, rfc_mode);
		fclose(fp);

		autoHunt_found = 1;  // Timer for auto search PVC
		encaps=(framing==LLC_SNAP? ENCAP_LLC:ENCAP_VCMUX);
		switch (rfc_mode) {
			case RFC1483_BRIDGED:
				cmode = CHANNEL_MODE_BRIDGE; // pppoe, ipoe ?
				break;
			case RFC1483_ROUTED:
				cmode = CHANNEL_MODE_RT1483;
				break;
			case RFC1577:
				cmode = CHANNEL_MODE_RT1577;
				break;
			case RFC2364:
				cmode = CHANNEL_MODE_PPPOA;
				break;
			case RFC2516:
				cmode = CHANNEL_MODE_PPPOE;
				break;
			default:
				cmode = CHANNEL_MODE_BRIDGE;
		}
		setVC0Connection(vpi, vci, encaps, cmode);
		succ_AutoSearchPVC();
	} else {
		printf("Open %s failed\n", PROC_AUTOPVC_HUNT);
	}
	update_autopvc_state();
}

#define MAX_PVC_SEARCH_PAIRS 16
static void StartAutoHunt(void)
{
	FILE *fp;

	//MIB_AUTO_PVC_SEARCH_Tp entryP;
	MIB_AUTO_PVC_SEARCH_T Entry;
	unsigned int entryNum,i;
	unsigned char tmp[12], tmpBuf[MAX_PVC_SEARCH_PAIRS*12];

	entryNum = mib_chain_total(MIB_AUTO_PVC_SEARCH_TBL);
	memset(tmpBuf, 0, sizeof(tmpBuf));
	for(i=0;i<entryNum; i++) {
		memset(tmp, 0, 12);
		if (!mib_chain_get(MIB_AUTO_PVC_SEARCH_TBL, i, (void *)&Entry))
			continue;
		sprintf(tmp,"(%d %d)", Entry.vpi, Entry.vci);
		strcat(tmpBuf, tmp);

	}

	if (fp=fopen(PROC_AUTOPVC_HUNT, "w") )
	{
		fprintf(fp, "1%s\n", tmpBuf);	//write pvc list stored in flash to SAR driver
		printf("%s(%d) ==> 1%s\n", __FUNCTION__, __LINE__, tmpBuf);

		fclose(fp);
	} else {
		printf("Open %s failed! Can't start SAR driver doing auto-pvc-search\n", PROC_AUTOPVC_HUNT);
	}

}

static void StopAutoHunt(int vpi,int vci)
{
	FILE *fp;
	
	if (fp=fopen(PROC_AUTOPVC_HUNT, "w") )
	{
		fprintf( fp, "0 %d,%d\n", vpi,vci);
		fclose(fp);
	} else {
		printf("Open %s failed! Can't stop SAR driver doing auto-pvc-search\n", PROC_AUTOPVC_HUNT);
	}
}

#endif
// Mason Yu. 20130304
static int AutoSearchPVC_Count = 1;
/*
 *	Called on timeout of INTERVAL_AUTOPVC
 */
void stopAutoSearchPVC(void *dummy)
{
	MIB_CE_ATM_VC_T Entry;
	FILE *fp;
	int state;
	long i;
	unsigned int entryNum, found;

	printf("\n***** Auto Search PVC timeout ! *****\n\n");
	syslog(LOG_INFO, "Auto Search PVC timeout");
	AutoSearchPVC_Count++;

	// Mason Yu. Delay 10 sec to make sure that the AutoHunt is finished.
	//for(i=0; i<100000000; i++);

	if ( sok == 0 && autoHunt_found == 0) {
		// auto-pvc search failed
		// Mason Yu. 20130304
		if ((AutoSearchPVC_Count <= COUNT_AUTOPVC) || (COUNT_AUTOPVC==0)) {
			printf("***** Auto Search PVC is fail and do again ! *****\n");
			startAutoSearchPVC();
		}
		else {
			printf("***** Auto Search PVC failed and stopped ! *****\n");
			// pvc-search timeout and failed.
			// find the first pvc entry to update
			entryNum = mib_chain_total(MIB_ATM_VC_TBL);
			found = 0;
			for (i=0; i<entryNum; i++) {
				if(!mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&Entry))
					continue;
        		
				if(MEDIA_INDEX(Entry.ifIndex) != MEDIA_ATM)
					continue;
				found = 1;
				break;
			}
        	
			#ifdef AUTO_PVC_SEARCH_AUTOHUNT
			StopAutoHunt(0, 0);
			#endif
        	
			// Reset ch0
			if (found)
				setVC0Connection(Entry.vpi, Entry.vci, ENCAP_LLC, CHANNEL_MODE_BRIDGE);
			fin_AutoSearchPVC = 1;
		}
	}
	fin_AutoSearchPVC = 1;
	update_autopvc_state();
}

int startAutoSearchPVC(void)
{
	unsigned char autosearch;
	int i;
	MIB_CE_ATM_VC_T Entry;

	if (!mib_get(MIB_ATM_VC_AUTOSEARCH, (void *)&autosearch))
		return 1;
	if (autosearch == 1)
	{
		unsigned long map = 0xffffffff;
		MIB_CE_ATM_VC_Tp pFirstEntry=NULL;
		unsigned int entryNum;
		// Timer for auto search PVC
		FILE *fp;
        
		printf("\n***** Auto Search PVC started *****\n\n");
		syslog(LOG_INFO, "Auto Search PVC started");
		fin_AutoSearchPVC = 0;
		sok = 0;
		autopvc_target = AUTOPVC_OAM;
		update_autopvc_state();
        
		// do first-pvc auto search per [TR-068, I-88]
		// Modified by Mason Yu
		entryNum = mib_chain_total(MIB_ATM_VC_TBL);
        
		for (i = 0; i < entryNum; i++)
		{
			unsigned long mask;
			int k;
        
			if (!mib_chain_get(MIB_ATM_VC_TBL, i, (void *)&Entry))
				return -1;
			if(MEDIA_INDEX(Entry.ifIndex) != MEDIA_ATM)
				continue;
			// Retrieve pvc list from flash
#ifdef AUTO_PVC_SEARCH_TR068_OAMPING
			mask = 1;
			for (k=0; pvcList[k].vpi || pvcList[k].vci; k++) {
				if (pvcList[k].vpi == Entry.vpi &&
					pvcList[k].vci == Entry.vci)
				{
					map ^= mask;	// set bit to zero
					break;
				}
				mask <<= 1;
			}
#endif
			if (pFirstEntry==NULL && Entry.enable) // get the first pvc
			{
				pFirstEntry = &Entry;
				// Added by Mason Yu
				break;
			}
		}
		
#ifdef AUTO_PVC_SEARCH_TR068_OAMPING
		startAutoPVCSearchTR068OAMPing_F5_Segment(pFirstEntry, map);
		if ( sok == 0 ) {
			startAutoPVCSearchTR068OAMPing_F5_EndToEnd(pFirstEntry, map);
		}
#elif defined(AUTO_PVC_SEARCH_PURE_OAMPING)
		startAutoPVCSearchPureOAMPing_F5_Segment(pFirstEntry, map);
		if ( sok == 0 ){
			startAutoPVCSearchPureOAMPing_F5_EndToEnd(pFirstEntry, map);
		}
#else
		printf("Just only do AutoHunt to find PVC\n");
#endif
		update_autopvc_state();


#ifdef AUTO_PVC_SEARCH_AUTOHUNT
		//OAM loopback not found, start SAR driver auto-pvc-search
		if(sok==0){
			printf("***** call SAR driver to start autoHunt ****\n");
			autopvc_target = AUTOPVC_HUNT;
			update_autopvc_state();
			// Kaohj
			StartAutoHunt();
		}
#endif
		// schedule for next run
		TIMEOUT_F(stopAutoSearchPVC, 0, INTERVAL_AUTOPVC, autoSearchPVC_ch);
	} else {
#ifdef AUTO_PVC_SEARCH_AUTOHUNT
		StopAutoHunt(0,0);
#endif
		return -1;
	}
	return 1;
}

#endif
#endif // of CONFIG_DEV_xDSL

