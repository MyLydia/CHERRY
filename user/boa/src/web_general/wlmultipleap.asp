<% SendWebHeadStr();%>
<title>Multiple AP</title>
<style>
.on {display:on}
.off {display:none}
</style>
<script>
var wlan_idx=<% checkWrite("wlan_idx"); %> ;
var WiFiTest=<% getInfo("WiFiTest"); %> ;
var val;
var bandIdx=new Array();
var virtual_bandIdx=new Array();
var virtual_wmm_enable=new Array();
var virtual_wlan_enable=new Array();
var virtual_access=new Array();
var aclist_index;
var mssid_num=<% checkWrite("wlan_mssid_num"); %>;
var fon=<%checkWrite("wlan_fon");%>;
var chanwid=<% getInfo("chanwid"); %>;

val =  <% checkWrite("mband"); %>;
if (val > 0) 
	val = val-1;
bandIdx[wlan_idx] = val;

if (mssid_num >= 1) {
	val = <% getVirtualIndex("band", "1"); %>;
	if (val > 0)
		val = val-1;
	virtual_bandIdx[1] = val;

	val = <% getVirtualIndex("wmmEnabled", "1"); %>;
	virtual_wmm_enable[1] = val;

	val = <% getVirtualIndex("wlanDisabled", "1"); %>;
	if (val) val = 0;
	else val = 1;
	virtual_wlan_enable[1] = val;

	val = <% getVirtualIndex("wlanAccess", "1"); %>;
	virtual_access[1] = val;
}
if (mssid_num > 1) {
	val = <% getVirtualIndex("band", "2"); %>;
	if (val > 0)
		val = val-1;
	virtual_bandIdx[2] = val;

	val = <% getVirtualIndex("wmmEnabled", "2"); %>;
	virtual_wmm_enable[2] = val;

	val = <% getVirtualIndex("wlanDisabled", "2"); %>;
	if (val) val = 0;
	else val = 1;
	virtual_wlan_enable[2] = val;

	val = <% getVirtualIndex("wlanAccess", "2"); %>;
	virtual_access[2] = val;
}
if (mssid_num > 1) {
	val = <% getVirtualIndex("band", "3"); %>;
	if (val > 0)
		val = val-1;
	virtual_bandIdx[3] = val;

	val = <% getVirtualIndex("wmmEnabled", "3"); %>;
	virtual_wmm_enable[3] = val;

	val = <% getVirtualIndex("wlanDisabled", "3"); %>;
	if (val) val = 0;
	else val = 1;
	virtual_wlan_enable[3] = val;

	val = <% getVirtualIndex("wlanAccess", "3"); %>;
	virtual_access[3] = val;
}
if (mssid_num > 1) {
	val = <% getVirtualIndex("band", "4"); %>;
	if (val > 0)
		val = val-1;
	virtual_bandIdx[4] = val;

	val = <% getVirtualIndex("wmmEnabled", "4"); %>;
	virtual_wmm_enable[4] = val;

	val = <% getVirtualIndex("wlanDisabled", "4"); %>;
	if (val) val = 0;
	else val = 1;
	virtual_wlan_enable[4] = val;

	val = <% getVirtualIndex("wlanAccess", "4"); %>;
	virtual_access[4] = val;
}

var rate_mask = [31,1,1,1,1,2,2,2,2,2,2,2,2,4,4,4,4,4,4,4,4,8,8,8,8,8,8,8,8,16,16,16,16,16,16,16,16];
var rate_name =["Auto","1M","2M","5.5M","11M","6M","9M","12M","18M","24M","36M","48M","54M", "MCS0", "MCS1"
				, "MCS2", "MCS3", "MCS4", "MCS5", "MCS6", "MCS7", "MCS8", "MCS9", "MCS10", "MCS11", "MCS12", "MCS13", "MCS14", "MCS15"
				, "MCS16", "MCS17", "MCS18", "MCS19", "MCS20", "MCS21", "MCS22", "MCS23"];
var vht_rate_name=["NSS1-MCS0","NSS1-MCS1","NSS1-MCS2","NSS1-MCS3","NSS1-MCS4",
		"NSS1-MCS5","NSS1-MCS6","NSS1-MCS7","NSS1-MCS8","NSS1-MCS9",
		"NSS2-MCS0","NSS2-MCS1","NSS2-MCS2","NSS2-MCS3","NSS2-MCS4",
		"NSS2-MCS5","NSS2-MCS6","NSS2-MCS7","NSS2-MCS8","NSS2-MCS9",
		"NSS3-MCS0","NSS3-MCS1","NSS3-MCS2","NSS3-MCS3","NSS3-MCS4",
		"NSS3-MCS5","NSS3-MCS6","NSS3-MCS7","NSS3-MCS8","NSS3-MCS9"];

function DisplayTxRate(v_index, band, auto, txrate, rf_num, channel_width)
{
	var mask, defidx, i, rate, vht_num;
	
	mask=0;
	if (auto)
		txrate=0;
	if (band & 1)
		mask |= 1;
	if ((band&2) || (band&4))
		mask |= 2;
	if (band & 8) {
		if (rf_num == 3)
			mask |= 28;
		else if (rf_num == 2)
			mask |= 12;	
		else
			mask |= 4;
	}
	if(band & 64){
		mask |= 16;
	}
	defidx=0;
	for (idx=0, i=0; i<rate_name.length; i++) {
		if (rate_mask[i] & mask) {
			if (i == 0)
				rate = 0;
			else
				rate = (1 << (i-1));
			if (txrate == rate)
				defidx = idx;
			else if (i>=29 && (txrate == ((1<<28)+(i-29))))
				defidx = idx;
			document.write('<option value="' + i + '">' + rate_name[i] + '\n');
			idx++;
		}
	}
	if(band & 64){
		vht_num = rf_num*10-1;
		for (i=0; i<=vht_num; i++) {
		
				rate = (((1 << 31)>>>0) + i);
				if (txrate == rate)
					defidx = idx;
				if(channel_width!=0 || (i!=9 && i!=19 && i!=29))//no MCS9 when 20M
				{
					document.write('<option value="' + (i+37) + '">' + vht_rate_name[i] + '\n');
					idx++;
				}
		}
	}
	document.MultipleAP.elements["TxRate"+v_index].selectedIndex=defidx;
}

function openWindow(url, windowName, wide, high) {
	if (document.all)
		var xMax = screen.width, yMax = screen.height;
	else if (document.layers)
		var xMax = window.outerWidth, yMax = window.outerHeight;
	else
		var xMax = 640, yMax=500;
	var xOffset = (xMax - wide)/2;
	var yOffset = (yMax - high)/3;

	var settings = 'width='+wide+',height='+high+',screenX='+xOffset+',screenY='+yOffset+',top='+yOffset+',left='+xOffset+', resizable=yes, toolbar=no,location=no,directories=no,status=no,menubar=no,scrollbars=yes';
	window.open(url, windowName, settings);
}

function open_client_table(id)
{
	aclist_index = id;
	openWindow('/admin/wlstatbl_vap.asp?id='+id, 'showWirelessClient', 700, 400);
}

function click_reset()
{
	location.reload(true);
/*
	for (i=1; i<=4; i++) {
		document.MultipleAP["wl_disable" + i].checked = (virtual_wlan_enable[i] ? true :  false);		
		UpdateVirtualStatus(document.MultipleAP, i);		
	}
*/
}

function saveChanges(form, wlan_id)
{
	var idx;
 	for (idx=1; idx<=4; idx++) {
		if (form.elements["wl_disable"+idx].checked) {
			ssid = form.elements["wl_ssid"+idx];		
			if (ssid.value == "") {
				alert("<% multilang(LANG_SSID_CANNOT_BE_EMPTY); %>");
				ssid.value = ssid.defaultValue;
				ssid.focus();
				return false;
			}	   	
			if (byteLength(ssid.value)>32) {
				alert("<% multilang(LANG_SSID_LENGTH_SHOULD_BE_MAXIMUM_32_OCTETS); %>");
				ssid.focus();
				return false;
			}
		}
		if(form.elements["wl_limitstanum"+idx].value == 1){
			if(!isNumber(form.elements["wl_stanum"+idx].value)){
				alert("<% multilang(LANG_INVALID_LIMIT_ASSOCIATED_CLIENT_NUMBER); %>");
				form.elements["wl_stanum"+idx].focus();
				return false;
			}
		}

	}
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
}

function showtxrate_updated_virtual(form, wlan_id, original_wmm_enable, channel_width)
{
  	var idx=0;
  	var i;
  	var txrate_str;
	var band, current_value, txrate_idx;
	var rf_num= <% checkWrite("rf_used"); %> ;

	txrate_idx = form.elements["TxRate"+wlan_id].selectedIndex;
	current_value = form.elements["TxRate"+wlan_id].options[txrate_idx].value;
	i = form.elements["wl_band"+wlan_id].selectedIndex;
	band = form.elements["wl_band"+wlan_id].options[i].value;
	form.elements["TxRate"+wlan_id].length=0;

 	form.elements["TxRate"+wlan_id].options[idx++] = new Option("Auto", "0", false, false);
	if (band == 0 || band ==2 || band ==10) {
		form.elements["TxRate"+wlan_id].options[idx++] = new Option("1M", "1", false, false);
		form.elements["TxRate"+wlan_id].options[idx++] = new Option("2M", "2", false, false);
		form.elements["TxRate"+wlan_id].options[idx++] = new Option("5.5M", "3", false, false);
		form.elements["TxRate"+wlan_id].options[idx++] = new Option("11M", "4", false, false);
	}
	if (band ==9 || band ==10 || band ==1 || band ==2 || band==3 || band==11 || band==75) {
		form.elements["TxRate"+wlan_id].options[idx++] = new Option("6M", "5", false, false);
		form.elements["TxRate"+wlan_id].options[idx++] = new Option("9M", "6", false, false);
		form.elements["TxRate"+wlan_id].options[idx++] = new Option("12M", "7", false, false);
		form.elements["TxRate"+wlan_id].options[idx++] = new Option("18M", "8", false, false);
		form.elements["TxRate"+wlan_id].options[idx++] = new Option("24M", "9", false, false);
		form.elements["TxRate"+wlan_id].options[idx++] = new Option("36M", "10", false, false);
		form.elements["TxRate"+wlan_id].options[idx++] = new Option("48M", "11", false, false);
		form.elements["TxRate"+wlan_id].options[idx++] = new Option("54M", "12", false, false);
	}
	if (band ==7 || band ==9 || band ==10 || band==11 || band==63 || band==71 || band==75) {
		if (band ==7 || band ==9 || band ==10 || band==11 || band==71 || band==75) {
			form.elements["TxRate"+wlan_id].options[idx++] = new Option("MCS0", "13", false, false);
			form.elements["TxRate"+wlan_id].options[idx++] = new Option("MCS1", "14", false, false);
			form.elements["TxRate"+wlan_id].options[idx++] = new Option("MCS2", "15", false, false);
			form.elements["TxRate"+wlan_id].options[idx++] = new Option("MCS3", "16", false, false);
			form.elements["TxRate"+wlan_id].options[idx++] = new Option("MCS4", "17", false, false);
			form.elements["TxRate"+wlan_id].options[idx++] = new Option("MCS5", "18", false, false);
			form.elements["TxRate"+wlan_id].options[idx++] = new Option("MCS6", "19", false, false);
			form.elements["TxRate"+wlan_id].options[idx++] = new Option("MCS7", "20", false, false);
			if (rf_num == 2) {
				form.elements["TxRate"+wlan_id].options[idx++] = new Option("MCS8", "21", false, false);
				form.elements["TxRate"+wlan_id].options[idx++] = new Option("MCS9", "22", false, false);
				form.elements["TxRate"+wlan_id].options[idx++] = new Option("MCS10", "23", false, false);
				form.elements["TxRate"+wlan_id].options[idx++] = new Option("MCS11", "24", false, false);
				form.elements["TxRate"+wlan_id].options[idx++] = new Option("MCS12", "25", false, false);
				form.elements["TxRate"+wlan_id].options[idx++] = new Option("MCS13", "26", false, false);
				form.elements["TxRate"+wlan_id].options[idx++] = new Option("MCS14", "27", false, false);
				form.elements["TxRate"+wlan_id].options[idx++] = new Option("MCS15", "28", false, false);
			}
			if (rf_num == 3) {
				form.elements["TxRate"+wlan_id].options[idx++] = new Option("MCS16", "29", false, false);
				form.elements["TxRate"+wlan_id].options[idx++] = new Option("MCS17", "30", false, false);
				form.elements["TxRate"+wlan_id].options[idx++] = new Option("MCS18", "31", false, false);
				form.elements["TxRate"+wlan_id].options[idx++] = new Option("MCS19", "32", false, false);
				form.elements["TxRate"+wlan_id].options[idx++] = new Option("MCS20", "33", false, false);
				form.elements["TxRate"+wlan_id].options[idx++] = new Option("MCS21", "34", false, false);
				form.elements["TxRate"+wlan_id].options[idx++] = new Option("MCS22", "35", false, false);
				form.elements["TxRate"+wlan_id].options[idx++] = new Option("MCS23", "36", false, false);
			}
		}

		if (band==63 || band==71 || band == 75) {
			form.elements["TxRate"+wlan_id].options[idx++] = new Option("NSS1-MCS0", "37", false, false);
			form.elements["TxRate"+wlan_id].options[idx++] = new Option("NSS1-MCS1", "38", false, false);
			form.elements["TxRate"+wlan_id].options[idx++] = new Option("NSS1-MCS2", "39", false, false);
			form.elements["TxRate"+wlan_id].options[idx++] = new Option("NSS1-MCS3", "40", false, false);
			form.elements["TxRate"+wlan_id].options[idx++] = new Option("NSS1-MCS4", "41", false, false);
			form.elements["TxRate"+wlan_id].options[idx++] = new Option("NSS1-MCS5", "42", false, false);
			form.elements["TxRate"+wlan_id].options[idx++] = new Option("NSS1-MCS6", "43", false, false);
			form.elements["TxRate"+wlan_id].options[idx++] = new Option("NSS1-MCS7", "44", false, false);
			form.elements["TxRate"+wlan_id].options[idx++] = new Option("NSS1-MCS8", "45", false, false);
			if(channel_width!=0)
				form.elements["TxRate"+wlan_id].options[idx++] = new Option("NSS1-MCS9", "46", false, false);
			if (rf_num == 2) {
				form.elements["TxRate"+wlan_id].options[idx++] = new Option("NSS2-MCS0", "47", false, false);
				form.elements["TxRate"+wlan_id].options[idx++] = new Option("NSS2-MCS1", "48", false, false);
				form.elements["TxRate"+wlan_id].options[idx++] = new Option("NSS2-MCS2", "49", false, false);
				form.elements["TxRate"+wlan_id].options[idx++] = new Option("NSS2-MCS3", "50", false, false);
				form.elements["TxRate"+wlan_id].options[idx++] = new Option("NSS2-MCS4", "51", false, false);
				form.elements["TxRate"+wlan_id].options[idx++] = new Option("NSS2-MCS5", "52", false, false);
				form.elements["TxRate"+wlan_id].options[idx++] = new Option("NSS2-MCS6", "53", false, false);
				form.elements["TxRate"+wlan_id].options[idx++] = new Option("NSS2-MCS7", "54", false, false);
				form.elements["TxRate"+wlan_id].options[idx++] = new Option("NSS2-MCS8", "55", false, false);
				if(channel_width!=0)
					form.elements["TxRate"+wlan_id].options[idx++] = new Option("NSS2-MCS9", "56", false, false);
			}
			if (rf_num == 3) {
				form.elements["TxRate"+wlan_id].options[idx++] = new Option("NSS2-MCS0", "57", false, false);
				form.elements["TxRate"+wlan_id].options[idx++] = new Option("NSS2-MCS1", "58", false, false);
				form.elements["TxRate"+wlan_id].options[idx++] = new Option("NSS2-MCS2", "59", false, false);
				form.elements["TxRate"+wlan_id].options[idx++] = new Option("NSS2-MCS3", "60", false, false);
				form.elements["TxRate"+wlan_id].options[idx++] = new Option("NSS2-MCS4", "61", false, false);
				form.elements["TxRate"+wlan_id].options[idx++] = new Option("NSS2-MCS5", "62", false, false);
				form.elements["TxRate"+wlan_id].options[idx++] = new Option("NSS2-MCS6", "63", false, false);
				form.elements["TxRate"+wlan_id].options[idx++] = new Option("NSS2-MCS7", "64", false, false);
				form.elements["TxRate"+wlan_id].options[idx++] = new Option("NSS2-MCS8", "65", false, false);
				if(channel_width!=0)
					form.elements["TxRate"+wlan_id].options[idx++] = new Option("NSS2-MCS9", "66", false, false);
			}
		}

		form.elements["wl_wmm_capable"+wlan_id].selectedIndex = 1;
		disableTextField(form.elements["wl_wmm_capable"+wlan_id]);
	}
	else {
		if (original_wmm_enable)
			form.elements["wl_wmm_capable"+wlan_id].selectedIndex = 1;
		else
			form.elements["wl_wmm_capable"+wlan_id].selectedIndex = 0;
		
		if (band == 7 || band == 9 || band == 10 || band == 11 || band == 63 || band == 71 || band == 75) {
			form.elements["wl_wmm_capable"+wlan_id].selectedIndex = 1;
			disableTextField(form.elements["wl_wmm_capable"+wlan_id]);
		}
		else
			enableTextField(form.elements["wl_wmm_capable"+wlan_id]);
	}
	form.elements["TxRate"+wlan_id].length = idx;

 	for (i=0; i<idx; i++) {
		txrate_str = form.elements["TxRate"+wlan_id].options[i].value;
		if (current_value == txrate_str)
			form.elements["TxRate"+wlan_id].selectedIndex = i;
		else
			form.elements["TxRate"+wlan_id].selectedIndex = 0;
	}
}

function showBand_MultipleAP(form, wlan_id, band_root, index_id)
{
	var idx = 0;
	var band_value = virtual_bandIdx[index_id];
/*
	if (band_root == 11) {	//11:5G
		form.elements["wl_band"+index_id].options[idx++] = new Option("5 GHz (A+N)", "11", false, false);
	}
	else {
		form.elements["wl_band"+index_id].options[idx++] = new Option("2.4 GHz (B)", "0", false, false);
		form.elements["wl_band"+index_id].options[idx++] = new Option("2.4 GHz (G)", "1", false, false);
		form.elements["wl_band"+index_id].options[idx++] = new Option("2.4 GHz (N)", "7", false, false);
		form.elements["wl_band"+index_id].options[idx++] = new Option("2.4 GHz (B+G)", "2", false, false);
		form.elements["wl_band"+index_id].options[idx++] = new Option("2.4 GHz (G+N)", "9", false, false);
		form.elements["wl_band"+index_id].options[idx++] = new Option("2.4 GHz (B+G+N)", "10", false, false);
	}
*/	
	if (band_root ==0) {
		form.elements["wl_band"+index_id].options[idx++] = new Option("2.4 GHz (B)", "0", false, false);
	}
	else if (band_root ==1) {
		form.elements["wl_band"+index_id].options[idx++] = new Option("2.4 GHz (G)", "1", false, false);
	}
	else if (band_root ==2) {
		form.elements["wl_band"+index_id].options[idx++] = new Option("2.4 GHz (B)", "0", false, false);
		form.elements["wl_band"+index_id].options[idx++] = new Option("2.4 GHz (G)", "1", false, false);
		form.elements["wl_band"+index_id].options[idx++] = new Option("2.4 GHz (B+G)", "2", false, false);
	}
	else if (band_root ==9) {
		form.elements["wl_band"+index_id].options[idx++] = new Option("2.4 GHz (G)", "1", false, false);
		form.elements["wl_band"+index_id].options[idx++] = new Option("2.4 GHz (N)", "7", false, false);
		form.elements["wl_band"+index_id].options[idx++] = new Option("2.4 GHz (G+N)", "9", false, false);
	}
	else if (band_root ==10) {
		form.elements["wl_band"+index_id].options[idx++] = new Option("2.4 GHz (B)", "0", false, false);
		form.elements["wl_band"+index_id].options[idx++] = new Option("2.4 GHz (G)", "1", false, false);
		form.elements["wl_band"+index_id].options[idx++] = new Option("2.4 GHz (B+G)", "2", false, false);
		form.elements["wl_band"+index_id].options[idx++] = new Option("2.4 GHz (N)", "7", false, false);
		form.elements["wl_band"+index_id].options[idx++] = new Option("2.4 GHz (G+N)", "9", false, false);
		form.elements["wl_band"+index_id].options[idx++] = new Option("2.4 GHz (B+G+N)", "10", false, false);
	}
	else if (band_root ==3) {
		form.elements["wl_band"+index_id].options[idx++] = new Option("5 GHz (A)", "3", false, false);
	}
	else if (band_root ==7) {
		var Band2G5GSupport=<% checkWrite("Band2G5GSupport"); %>;
		if(Band2G5GSupport==1)//2g
			form.elements["wl_band"+index_id].options[idx++] = new Option("2.4 GHz (N)", "7", false, false);
		else if(Band2G5GSupport==2)//5g
			form.elements["wl_band"+index_id].options[idx++] = new Option("5 GHz (N)", "7", false, false);
	}
	else if (band_root ==11) {
		form.elements["wl_band"+index_id].options[idx++] = new Option("5 GHz (A)", "3", false, false);
		form.elements["wl_band"+index_id].options[idx++] = new Option("5 GHz (N)", "7", false, false);
		form.elements["wl_band"+index_id].options[idx++] = new Option("5 GHz (A+N)", "11", false, false);
	}
	else if (band_root ==63) {
		form.elements["wl_band"+index_id].options[idx++] = new Option("5 GHz (AC)", "63", false, false);
	}
	else if (band_root ==71) {
		form.elements["wl_band"+index_id].options[idx++] = new Option("5 GHz (N)", "7", false, false);
		form.elements["wl_band"+index_id].options[idx++] = new Option("5 GHz (AC)", "63", false, false);
		form.elements["wl_band"+index_id].options[idx++] = new Option("5 GHz (N+AC)", "71", false, false);
	}
	else if (band_root ==75) {
		form.elements["wl_band"+index_id].options[idx++] = new Option("5 GHz (A)", "3", false, false);
		form.elements["wl_band"+index_id].options[idx++] = new Option("5 GHz (N)", "7", false, false);
		form.elements["wl_band"+index_id].options[idx++] = new Option("5 GHz (A+N)", "11", false, false);
		form.elements["wl_band"+index_id].options[idx++] = new Option("5 GHz (AC)", "63", false, false);
		form.elements["wl_band"+index_id].options[idx++] = new Option("5 GHz (N+AC)", "71", false, false);
		form.elements["wl_band"+index_id].options[idx++] = new Option("5 GHz (A+N+AC)", "75", false, false);
	}
	
	if (band_value > band_root)
		band_value = band_root;
	for (i=0 ; i<idx ; i++) {
		if (form.elements["wl_band"+index_id].options[i].value == band_value) {
			form.elements["wl_band"+index_id].selectedIndex = i;
			break;
		}
	}
}

function enableVirtualWLAN(form, virtual_id)
{
	enableTextField(form.elements["wl_band"+virtual_id]);
	enableTextField(form.elements["wl_ssid"+virtual_id]);
	enableTextField(form.elements["TxRate"+virtual_id]);
	enableTextField(form.elements["wl_hide_ssid"+virtual_id]);
/*
	if (form.elements["wl_band"+virtual_id].selectedIndex == 2 || 
		form.elements["wl_band"+virtual_id].selectedIndex >= 4) {
			form.elements["wl_wmm_capable"+virtual_id].selectedIndex = 1;		
			disableTextField(form.elements["wl_wmm_capable"+virtual_id]);
	}
	else 
		enableTextField(form.elements["wl_wmm_capable"+virtual_id]);
*/
	enableTextField(form.elements["wl_access"+virtual_id]);		
	enableTextField(form.elements["aclient"+virtual_id]);

	var i;
	i = form.elements["wl_band"+virtual_id].selectedIndex;
	band = form.elements["wl_band"+virtual_id].options[i].value;
	if(band ==7 || band ==9 || band ==10 || band==11 || band==63|| band==71|| band==75)
	{
		form.elements["wl_wmm_capable"+virtual_id].selectedIndex = 1;
		disableTextField(form.elements["wl_wmm_capable"+virtual_id]);
	}
	else
		enableTextField(form.elements["wl_wmm_capable"+virtual_id]);
	
	enableTextField(form.elements["wl_limitstanum"+virtual_id]);
	check_stanum(document.MultipleAP, virtual_id);

	enableTextField(form.elements["wl_txbf_ssid"+virtual_id]);
	UpdateTxBf(form, virtual_id);
	enableTextField(form.elements["wl_mc2u_ssid"+virtual_id]);
}

function disableVirtualWLAN(form, virtual_id)
{
	disableTextField(form.elements["wl_band"+virtual_id]);
	disableTextField(form.elements["wl_ssid"+virtual_id]);
	disableTextField(form.elements["TxRate"+virtual_id]);
	disableTextField(form.elements["wl_hide_ssid"+virtual_id]);
	disableTextField(form.elements["wl_wmm_capable"+virtual_id]);
	disableTextField(form.elements["wl_access"+virtual_id]);	
	disableTextField(form.elements["aclient"+virtual_id]);
	disableTextField(form.elements["wl_limitstanum"+virtual_id]);
	disableTextField(form.elements["wl_stanum"+virtual_id]);
	disableTextField(form.elements["wl_txbf_ssid"+virtual_id]);
	disableTextField(form.elements["wl_txbfmu_ssid"+virtual_id]);
	disableTextField(form.elements["wl_mc2u_ssid"+virtual_id]);
}

function UpdateVirtualStatus(form, virtual_id)
{
	if (!form.elements["wl_disable"+virtual_id].checked)
		disableVirtualWLAN(form, virtual_id);
	else
		enableVirtualWLAN(form, virtual_id);
}

function check_stanum(form, virtual_id)
{
	if (form.elements["wl_limitstanum"+virtual_id].value == 0)
		disableTextField(form.elements["wl_stanum"+virtual_id]);
	else
		enableTextField(form.elements["wl_stanum"+virtual_id]);
}

function UpdateTxBf(form, virtual_id)
{
	if (form.elements["wl_txbf_ssid"+virtual_id].value == 0)
		disableTextField(form.elements["wl_txbfmu_ssid"+virtual_id]);
	else
		enableTextField(form.elements["wl_txbfmu_ssid"+virtual_id]);
}

</script>
<style>
.intro_title {
    color: #a3238e;
    font-size: 16px;
    font-weight: bold;
}
.intro_content {
    color: #666;
    font-size: 12px;
}
a {
    color: #5e5e5e;
    text-decoration: none;
}
body {
    font: 9px Arial,toTahoma,Helvetica,sans-serif;
    background: #fff;
}
table,
th,
td,th {
 margin:0;
 padding: 2px 1px;
 font-weight: normal;
 border:1px solid #ccc;
 text-align:center;
}
table {
 border-collapse:collapse;
 border-spacing:0;
}
.table_data{font-size: 9px !important;}
.table_data table th, .table_data table td {
    font-size: 9px !important;
}
input[type="text"], input[type="password"], select {
    border: 1px solid #7e9db9;
    padding:  0 !important;
    margin-left: 0 !important;
    height: 22px;
    font-size: 9px !important;
    font-weight: normal;
}
input, select, textarea {
    -moz-box-sizing: border-box;
    -webkit-box-sizing: border-box;
    -ms-box-sizing: border-box;
    box-sizing: border-box;
    margin: 0 !important;
	font-size: 9px !important;
}
select {
 -webkit-appearance: none;
 font-size: 12px;
}
select option {
 font-size: 8px; 
}
</style>
</head>

<body>
<div class="intro_main ">
	<p class="intro_title">Multiple APs</p>
	<p class="intro_content">This page shows and updates the wireless setting for multiple APs.</p>
</div>
<br>
<form action=/boaform/formWlanMultipleAP method=POST name="MultipleAP">
<input type="hidden" value="<% checkWrite("wlan_idx"); %>" name="wlanIdx">		
	 <% checkWrite("blockingvap"); %>
<!--
	<tr>
		<td><b><% multilang(LANG_BLOCKING_BETWEEN_VAP); %>:</b></td>
		<td><input type="radio" name="mbssid_block" value="disable" ><% multilang(LANG_DISABLE); %>&nbsp;&nbsp;
		<input type="radio" name="mbssid_block" value="enable" ><% multilang(LANG_ENABLE); %></td>
	</tr>
-->
	<div class="table_data">
		<table> 
			<tr style="background:#e9e9e9;">
			   <th>No.</th>
			   <th>Enable</th>
			   <th <% checkWrite("wlan_qtn_hidden_function"); %>>Band</th>
			   <th>SSID</th>
			   <th <% checkWrite("wlan_qtn_hidden_function"); %> width="60">Data Rate</th>
			   <th>Broadcast SSID</th>
			   <th>WMM</th>
			   <th>Relay Blocking</th>   
			   <th id="wl_limit_stanum_div" style="display:none"><% multilang(LANG_STA_NUMBER); %></th>
			   <th>Active Client List</th>
			   <th id="wl_txbf_div" style="display:none"><% multilang(LANG_TXBF); %></th>
			   <th id="wl_txbfmu_div" style="display:none"><% multilang(LANG_TXBF_MU); %></th>
			   <th id="wl_mc2u_div" style="display:none"><% multilang(LANG_MC2U); %></th>
			</tr>
			<tr>
				<td>AP1</td>
				<td>
				<script type="text/javascript">
					var wlanDisabled = <% getVirtualIndex("wlanDisabled", "1"); %>;
					if (wlanDisabled == "0") {
						document.write('<input type="checkbox" name="wl_disable1" value="ON" onClick="UpdateVirtualStatus(document.MultipleAP, 1)" checked="checked">');
					}
					else {
						document.write('<input type="checkbox" name="wl_disable1" value="ON" onClick="UpdateVirtualStatus(document.MultipleAP, 1)">');
				}
			</script>
		</td>
		<td <% checkWrite("wlan_qtn_hidden_function"); %>>
			<select style="width:110" name=wl_band1 onChange="showtxrate_updated_virtual(document.MultipleAP, 1, virtual_wmm_enable[1] , chanwid)">
				<script>
					showBand_MultipleAP(document.MultipleAP, wlan_idx, bandIdx[wlan_idx], 1);
	     			</script>
			</select>
		</td>
		<td>
			<input type="text" name="wl_ssid1" size="7" maxlength="32" value="<% SSIDStr("vap0"); %>">
		</td>
		<td <% checkWrite("wlan_qtn_hidden_function"); %> width="60">
			<select name="TxRate1" width="60">
				<script>
		    			band = <% getVirtualIndex("band", "1"); %>;
		    			auto = <% getVirtualIndex("rateAdaptiveEnabled", "1"); %>;
	 	    			txrate = <% getVirtualIndex("fixTxRate", "1"); %>;
	 	    			rf_num = <% checkWrite("rf_used"); %>;		
					DisplayTxRate(1, band, auto, txrate, rf_num, chanwid);
				</script>
			</select>
		</td>
		<td>
			<select name=wl_hide_ssid1>
				<option value="1">Disabled</option>
				<option value="0">Enabled</option>
			</select>
		</td>
		<td>
			<select name=wl_wmm_capable1>
				<option value="0">Disabled</option>
				<option value="1">Enabled</option>
				<script>
					if (virtual_wmm_enable[1])
						document.MultipleAP.elements["wl_wmm_capable1"].selectedIndex=1;
					else
						document.MultipleAP.elements["wl_wmm_capable1"].selectedIndex=0;
				</script>
			</select>
		</td>
		<td>
			<select name=wl_access1>
				<option value="0">Disabled</option>
				<option value="1">Enabled</option>
			</select>
		</td>
		<td id="wl_limit_stanum_div1" style="display:none">
			<select name=wl_limitstanum1 onChange="check_stanum(document.MultipleAP, 1)">
				<option value="0">Disabled</option>
				<option value="1">Enabled</option>
			</select>
			<input type="text" name="wl_stanum1" size="3" maxlength="2">
		</td>	
		<td>
			<input type="hidden" value="1" name="vap">	
			<input type="button" value="Show" name="aclient1" onClick="open_client_table(1);">
	    </td>
		<td id="wl_txbf_div1" style="display:none" >
			<select name=wl_txbf_ssid1 onChange="UpdateTxBf(document.MultipleAP, 1)">
				<option value="0">Disabled</option>
				<option value="1">Enabled</option>
			</select>
		</td>
		<td id="wl_txbfmu_div1" style="display:none" >
			<select name=wl_txbfmu_ssid1>
				<option value="0">Disabled</option>
				<option value="1">Enabled</option>
			</select>
		</td>
		<td id="wl_mc2u_div1" style="display:none" >
			<select name=wl_mc2u_ssid1>
				<option value="1">Disabled</option>
				<option value="0">Enabled</option>
			</select>
		</td>
	</tr>
	<script>
		if (mssid_num == 1) {
			document.write("</table>\n");
			document.write("<span id = \"hide_div\" class = \"off\">\n");
			document.write("<table border=\"1\" width=700>\n");
		}
	</script>
	<tr>
		<td>AP2</td>
		<td>
			<script type="text/javascript">
				var wlanDisabled = <% getVirtualIndex("wlanDisabled", "2"); %>;
				if (wlanDisabled == "0") {
					document.write('<input type="checkbox" name="wl_disable2" value="ON" onClick="UpdateVirtualStatus(document.MultipleAP, 2)" checked="checked">');
				}
				else {
					document.write('<input type="checkbox" name="wl_disable2" value="ON" onClick="UpdateVirtualStatus(document.MultipleAP, 2)">');
				}
			</script>
		</td>
		<td <% checkWrite("wlan_qtn_hidden_function"); %> >
			<select style="width:110" name=wl_band2 onChange="showtxrate_updated_virtual(document.MultipleAP, 2, virtual_wmm_enable[2], chanwid)">
				<script>
					showBand_MultipleAP(document.MultipleAP, wlan_idx, bandIdx[wlan_idx], 2);
	     			</script>
			</select>
		</td>
		<td>
			<input type="text" name="wl_ssid2" size="7" maxlength="32" value="<% SSIDStr("vap1"); %>">
		</td>
		<td <% checkWrite("wlan_qtn_hidden_function"); %> width=60 >
			<select name="TxRate2">
				<script>
					band = <% getVirtualIndex("band", "2"); %>;
					auto = <% getVirtualIndex("rateAdaptiveEnabled", "2"); %>;
					txrate = <% getVirtualIndex("fixTxRate", "2"); %>;
					rf_num = <% checkWrite("rf_used"); %>;			

					DisplayTxRate(2, band, auto, txrate, rf_num, chanwid);
				</script>
			</select>
		</td>
		<td>
			<select name=wl_hide_ssid2>
				<option value="1">Disabled</option>
				<option value="0">Enabled</option>
			</select>
		</td>
		<td>
			<select name=wl_wmm_capable2>
				<option value="0">Disabled</option>
				<option value="1">Enabled</option>
				<script>
					if (virtual_wmm_enable[2])
						document.MultipleAP.elements["wl_wmm_capable2"].selectedIndex=1;
					else
						document.MultipleAP.elements["wl_wmm_capable2"].selectedIndex=0;
				</script>
			</select>
		</td>
		<td >
			<select name=wl_access2>
				<option value="0">Disabled</option>
				<option value="1">Enabled</option>
			</select>
		</td>	
		<td id="wl_limit_stanum_div2" style="display:none">
			<select name=wl_limitstanum2 onChange="check_stanum(document.MultipleAP, 2)">
				<option value="0">Disabled</option>
				<option value="1">Enabled</option>
			</select>
			<input type="text" name="wl_stanum2" size="3" maxlength="2">
		</td>
		<td>
			<input type="button" value="Show" name="aclient2" onClick="open_client_table(2);">
	    </td>
		<td id="wl_txbf_div2" style="display:none" >
			<select name=wl_txbf_ssid2 onChange="UpdateTxBf(document.MultipleAP, 2)">
				<option value="0">Disabled</option>
				<option value="1">Enabled</option>
			</select>
		</td>
		<td id="wl_txbfmu_div2" style="display:none" >
			<select name=wl_txbfmu_ssid2>
				<option value="0">Disabled</option>
				<option value="1">Enabled</option>
			</select>
		</td>
		<td id="wl_mc2u_div2" style="display:none">
			<select name=wl_mc2u_ssid2>
				<option value="1">Disabled</option>
				<option value="0">Enabled</option>
			</select>
		</td>
	</tr>
	<tr>
		<td>AP3</td>
		<td>
			<script type="text/javascript">
				var wlanDisabled = <% getVirtualIndex("wlanDisabled", "3"); %>;
				if (wlanDisabled == "0") {
					document.write('<input type="checkbox" name="wl_disable3" value="ON" onClick="UpdateVirtualStatus(document.MultipleAP, 3)" checked="checked">');
				}
				else {
					document.write('<input type="checkbox" name="wl_disable3" value="ON" onClick="UpdateVirtualStatus(document.MultipleAP, 3)">');
				}
			</script>
		</td>
		<td <% checkWrite("wlan_qtn_hidden_function"); %>>
			<select style="width:110" name=wl_band3 onChange="showtxrate_updated_virtual(document.MultipleAP, 3, virtual_wmm_enable[3], chanwid)">
				<script>
					showBand_MultipleAP(document.MultipleAP, wlan_idx, bandIdx[wlan_idx], 3);
	     			</script>
			</select>
		</td>
					<td>
			<input type="text" name="wl_ssid3" size="7" maxlength="32" value="<% SSIDStr("vap2"); %>">
		</td>
		<td <% checkWrite("wlan_qtn_hidden_function"); %> width=60>
			<select name="TxRate3">
				<script>
					band = <% getVirtualIndex("band", "3"); %>;
					auto = <% getVirtualIndex("rateAdaptiveEnabled", "3"); %>;
					txrate = <% getVirtualIndex("fixTxRate", "3"); %>;
					rf_num = <% checkWrite("rf_used"); %>;	

					DisplayTxRate(3, band, auto, txrate, rf_num, chanwid);
				</script>
			</select>
		</td>
					<td>
			<select name=wl_hide_ssid3>
				<option value="1">Disabled</option>
				<option value="0">Enabled</option>
			</select>
		</td>
					<td>
			<select name=wl_wmm_capable3>
				<option value="0">Disabled</option>
				<option value="1">Enabled</option>
				<script>
					if (virtual_wmm_enable[3])
						document.MultipleAP.elements["wl_wmm_capable3"].selectedIndex=1;
					else
						document.MultipleAP.elements["wl_wmm_capable3"].selectedIndex=0;
				</script>
			</select>
		</td>
					<td>
			<select name=wl_access3>
				<option value="0">Disabled</option>
				<option value="1">Enabled</option>
			</select>
		</td>	
		<td id="wl_limit_stanum_div3" style="display:none">
			<select name=wl_limitstanum3 onChange="check_stanum(document.MultipleAP, 3)">
				<option value="0">Disabled</option>
				<option value="1">Enabled</option>
			</select>
			<input type="text" name="wl_stanum3" size="3" maxlength="2">
		</td>
		<td>
			<input type="button" value="Show" name="aclient3" onClick="open_client_table(3);">
	      </td>
		<td id="wl_txbf_div3" style="display:none">
			<select name=wl_txbf_ssid3 onChange="UpdateTxBf(document.MultipleAP, 3)">
				<option value="0">Disabled</option>
				<option value="1">Enabled</option>
			</select>
		</td>
		<td id="wl_txbfmu_div3" style="display:none">
			<select name=wl_txbfmu_ssid3>
				<option value="0">Disabled</option>
				<option value="1">Enabled</option>
			</select>
		</td>
		<td id="wl_mc2u_div3" style="display:none">
			<select name=wl_mc2u_ssid3>
				<option value="1">Disabled</option>
				<option value="0">Enabled</option>
			</select>
		</td>
	</tr>
	<script>
	  if (fon == 1) {
		document.write("</table>\n");
		document.write("<span id = \"hide_div\" class = \"off\">\n");
		document.write("<table border=\"1\" width=700>\n");
	  }
	</script>
	<tr>
		<td>AP4</td>
		<td>
			<script type="text/javascript">
				var wlanDisabled = <% getVirtualIndex("wlanDisabled", "4"); %>;
				if (wlanDisabled == "0") {
					document.write('<input type="checkbox" name="wl_disable4" value="ON" onClick="UpdateVirtualStatus(document.MultipleAP, 4)" checked="checked">');
				}
				else {
					document.write('<input type="checkbox" name="wl_disable4" value="ON" onClick="UpdateVirtualStatus(document.MultipleAP, 4)">');
				}
			</script>
		</td>
		<td <% checkWrite("wlan_qtn_hidden_function"); %> >
			<select style="width:110" name=wl_band4 onChange="showtxrate_updated_virtual(document.MultipleAP, 4, virtual_wmm_enable[4], chanwid)">
				<script>
					showBand_MultipleAP(document.MultipleAP, wlan_idx, bandIdx[wlan_idx], 4);
	     			</script>
			</select>
		</td>
		<td>
			<input type="text" name="wl_ssid4" size="7" maxlength="32" value="<% SSIDStr("vap3"); %>">
		</td>
		<td <% checkWrite("wlan_qtn_hidden_function"); %> width = 60>
			<select name="TxRate4">
				<script>
					band = <% getVirtualIndex("band", "4"); %>;
					auto = <% getVirtualIndex("rateAdaptiveEnabled", "4"); %>;
					txrate = <% getVirtualIndex("fixTxRate", "4"); %>;
					rf_num = <% checkWrite("rf_used"); %>;	

					DisplayTxRate(4, band, auto, txrate, rf_num, chanwid);
				</script>
			</select>
		</td>
		<td>
			<select name=wl_hide_ssid4>
				<option value="1">Disabled</option>
				<option value="0">Enabled</option>
			</select>
		</td>
		<td>
			<select name=wl_wmm_capable4>
				<option value="0">Disabled</option>
				<option value="1">Enabled</option>
				<script>
					if (virtual_wmm_enable[4])
						document.MultipleAP.elements["wl_wmm_capable4"].selectedIndex=1;
					else
						document.MultipleAP.elements["wl_wmm_capable4"].selectedIndex=0;
				</script>
			</select>
		</td>
					<td>
			<select name=wl_access4>
					<option value="0">Disabled</option>
					<option value="1">Enabled</option>
				</select>
			</td>	
			<td id="wl_limit_stanum_div4" style="display:none" >
				<select name=wl_limitstanum4 onChange="check_stanum(document.MultipleAP, 4)">
					<option value="0">Disabled</option>
					<option value="1">Enabled</option>
				</select>
				<input type="text" name="wl_stanum4" size="3" maxlength="2">
			</td>
			<td>
				<input type="button" value="Show" name="aclient4" onClick="open_client_table(4);">
		      </td>
			<td id="wl_txbf_div4" style="display:none">
				<select name=wl_txbf_ssid4 onChange="UpdateTxBf(document.MultipleAP, 4)">
					<option value="0">Disabled</option>
					<option value="1">Enabled</option>
				</select>
			</td>
			<td id="wl_txbfmu_div4" style="display:none">
				<select name=wl_txbfmu_ssid4>
					<option value="0">Disabled</option>
					<option value="1">Enabled</option>
				</select>
			</td>
			<td id="wl_mc2u_div4" style="display:none">
				<select name=wl_mc2u_ssid4>
					<option value="1">Disabled</option>
					<option value="0">Enabled</option>
				</select>
			</td>
		</tr>
		<script>
			<% initPage("wlmultipleap"); %>	
			for (i=1; i<=mssid_num; i++)
				UpdateVirtualStatus(document.MultipleAP, i);

			if (mssid_num == 1 || fon == 1) {
				document.write("</table>\n");
				document.write("</span>\n");
				document.write("<table border=\"1\" width=700>\n");
			}	
		</script>
	</table>
</div>
								
<div class="btn_ctl">
	<input type="hidden" value="/admin/wlmultipleap.asp" name="submit-url">
	<input type="submit" value="Apply Changes"  onClick="return saveChanges(document.MultipleAP, wlan_idx)" class="link_bg">&nbsp;&nbsp;
	<input type="button" value="Reset" name="reset1" onClick="click_reset();" class="link_bg">&nbsp;&nbsp;  
	<!-- <input type="button" value=" Close " name="close" onClick="javascript: window.close();"> -->
	<input type="hidden" name="postSecurityFlag" value="">
</div>
</form>
<br><br>
</body>
</html>
