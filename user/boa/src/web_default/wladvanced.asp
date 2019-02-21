<html>
<! Copyright (c) Realtek Semiconductor Corp., 2003. All Rights Reserved. ->
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<title><% multilang(LANG_WLAN_ADVANCED_SETTINGS); %></title>
<link rel="stylesheet" type="text/css" href="common_style.css" />
<SCRIPT language="javascript" src="/common.js"></SCRIPT>
<script type="text/javascript" src="share.js">
</script>

<SCRIPT>
var rootBand=<% checkWrite("band"); %>;
var is_wlan_qtn = <% checkWrite("is_wlan_qtn"); %>;
function validateNum(str)
{
  for (var i=0; i<str.length; i++) {
   	if ( !(str.charAt(i) >='0' && str.charAt(i) <= '9')) {
		alert("<% multilang(LANG_INVALID_VALUE_IT_SHOULD_BE_IN_DECIMAL_NUMBER_0_9); %>");
		return false;
  	}
  }
  return true;
}
function saveChanges(obj)
{
  if ( validateNum(document.advanceSetup.fragThreshold.value) == 0 ) {
  	document.advanceSetup.fragThreshold.focus();
	return false;
  }
  num = parseInt(document.advanceSetup.fragThreshold.value);
  if (document.advanceSetup.fragThreshold.value == "" || num < 256 || num > 2346) {
  	alert("<% multilang(LANG_INVALID_VALUE_OF_FRAGMENT_THRESHOLD_INPUT_VALUE_SHOULD_BE_BETWEEN_256_2346_IN_DECIMAL); %>");
  	document.advanceSetup.fragThreshold.focus();
	return false;
  }

  if ( validateNum(document.advanceSetup.rtsThreshold.value) == 0 ) {
  	document.advanceSetup.rtsThreshold.focus();
	return false;
  }
  num = parseInt(document.advanceSetup.rtsThreshold.value);
  if (document.advanceSetup.rtsThreshold.value=="" || num > 2347) {
  	alert("<% multilang(LANG_INVALID_VALUE_OF_RTS_THRESHOLD_INPUT_VALUE_SHOULD_BE_BETWEEN_0_2347_IN_DECIMAL); %>");
  	document.advanceSetup.rtsThreshold.focus();
	return false;
  }

  if ( validateNum(document.advanceSetup.beaconInterval.value) == 0 ) {
  	document.advanceSetup.beaconInterval.focus();
	return false;
  }
  num = parseInt(document.advanceSetup.beaconInterval.value);
  if (document.advanceSetup.beaconInterval.value=="" || num < 20 || num > 1024) {
  	alert("<% multilang(LANG_INVALID_VALUE_OF_BEACON_INTERVAL_INPUT_VALUE_SHOULD_BE_BETWEEN_20_1024_IN_DECIMAL); %>");
  	document.advanceSetup.beaconInterval.focus();
	return false;

  }
  num = parseInt(document.advanceSetup.dtimPeriod.value);
  if (document.advanceSetup.dtimPeriod.value=="" || num < 1 || num > 255) {
	alert("<% multilang(LANG_INVALID_VALUE_OF_DTIM_PRERIOD_INPUT_VALUE_SHOULD_BE_BETWEEN_1_255_IN_DECIMAL); %>");
  	document.advanceSetup.dtimPeriod.focus();
	return false;

  }
  obj.isclick = 1;
  postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
  return true;
}

function wlDot11kChange()
{
	if(document.advanceSetup.elements.namedItem("dot11vEnabled")!= null){
		with (document.advanceSetup) {
			dot11v.style.display = dot11kEnabled[0].checked? "" : "none";
		}
	}
}

function wltxbfChange()
{
	if(document.advanceSetup.elements.namedItem("txbf")!= null){
		with (document.advanceSetup) {
			txbf_mu_div.style.display = txbf[0].checked? "" : "none";
		}
	}
}

function wlRoamingChange()
{
	if(document.advanceSetup.elements.namedItem("SR_AutoConfig_enable")!= null){
		with (document.advanceSetup) {
			SR_AutoConfig.style.display = smart_roaming_enable[0].checked? "" : "none";
		}
	}
}

function updateState()
{
  if (document.advanceSetup.wlanDisabled.value == "ON") {    
    disableTextField(document.advanceSetup.fragThreshold);
    disableTextField(document.advanceSetup.rtsThreshold);
    disableTextField(document.advanceSetup.beaconInterval);
    disableTextField(document.advanceSetup.txRate);
    disableRadioGroup(document.advanceSetup.preamble);
    disableRadioGroup(document.advanceSetup.hiddenSSID);
    disableRadioGroup(document.advanceSetup.block);
    disableRadioGroup(document.advanceSetup.protection);
    disableRadioGroup(document.advanceSetup.aggregation);
    disableRadioGroup(document.advanceSetup.shortGI0);
    if(document.advanceSetup.elements.namedItem("smart_roaming_enable")!= null)
        disableRadioGroup(document.advanceSetup.smart_roaming_enable);
    if(document.advanceSetup.elements.namedItem("txbf")!= null)
		disableRadioGroup(document.advanceSetup.txbf);
    if(document.advanceSetup.elements.namedItem("txbf_mu")!= null)
		disableRadioGroup(document.advanceSetup.txbf_mu);
    if(document.advanceSetup.elements.namedItem("mc2u_disable")!= null)
		disableRadioGroup(document.advanceSetup.mc2u_disable);
    disableRadioGroup(document.advanceSetup.WmmEnabled);
	if(document.advanceSetup.elements.namedItem("dot11kEnabled")!= null)
		disableRadioGroup(document.advanceSetup.dot11kEnabled);
	if(document.advanceSetup.elements.namedItem("dot11vEnabled")!= null)
		disableRadioGroup(document.advanceSetup.dot11vEnabled);
    disableButton(document.advanceSetup.save);
  }
  else if (document.advanceSetup.WmmEnabled) {
  	if (rootBand == 7 || rootBand == 9 || rootBand == 10 || rootBand == 11 || rootBand == 63 || rootBand == 71 || rootBand == 75) {
		document.advanceSetup.WmmEnabled[0].checked = true;
    		disableRadioGroup(document.advanceSetup.WmmEnabled);
  	}
  }
}

</SCRIPT>
<blockquote>
<body>
<h2 class="page_title"><% multilang(LANG_WLAN_ADVANCED_SETTINGS); %></h2>

<form action=/boaform/admin/formAdvanceSetup method=POST name="advanceSetup">
<table>
  <tr><td><font size=2>
 <% multilang(LANG_PAGE_DESC_WLAN_ADVANCE_SETTING); %>
  </font></td></tr>
  <tr><td><hr size=1 noshade align=top></td></tr>
</table>
<table>
	<input type=hidden name="wlanDisabled" value=<% wlanStatus(); %>>

    <tr <% checkWrite("wlan_qtn_hidden_function"); %>>
      <th><% multilang(LANG_FRAGMENT_THRESHOLD); %>:</th>
      <td><input type="text" name="fragThreshold" size="10" maxlength="4" value=<% getInfo("fragThreshold"); %>>(256-2346)</td>
    </tr>
    <tr>
      <th><% multilang(LANG_RTS_THRESHOLD); %>:</th>
      <td><input type="text" name="rtsThreshold" size="10" maxlength="4" value=<% getInfo("rtsThreshold"); %>>(0-2347)</td>
    </tr>
    <tr>
      <th><% multilang(LANG_BEACON_INTERVAL); %>:</th>
      <td><input type="text" name="beaconInterval" size="10" maxlength="4" value=<% getInfo("beaconInterval"); %>> (20-1024 <% multilang(LANG_MS); %>)</td>
    </tr>
    <tr>
      <th><% multilang(LANG_DTIM_PERIOD); %>:</th>
      <td><input type="text" name="dtimPeriod" size="10" maxlength="4" value=<% getInfo("dtimPeriod"); %>> (1-255)</td>
    </tr>

    <tr>
      <th><% multilang(LANG_DATA_RATE); %>:</th>
      <td><select size="1" name="txRate">
	<SCRIPT>
	<% checkWrite("wl_txRate"); %>

if(!is_wlan_qtn){
	rate_mask = [31,1,1,1,1,2,2,2,2,2,2,2,2,4,4,4,4,4,4,4,4,8,8,8,8,8,8,8,8,16,16,16,16,16,16,16,16];
	rate_name =["<% multilang(LANG_AUTO); %>","1M","2M","5.5M","11M","6M","9M","12M","18M","24M","36M","48M","54M", "MCS0", "MCS1",
		"MCS2", "MCS3", "MCS4", "MCS5", "MCS6", "MCS7", "MCS8", "MCS9", "MCS10", "MCS11", "MCS12", "MCS13", "MCS14", "MCS15",
		"MCS16", "MCS17", "MCS18", "MCS19", "MCS20", "MCS21", "MCS22", "MCS23"];
	vht_rate_name=["NSS1-MCS0","NSS1-MCS1","NSS1-MCS2","NSS1-MCS3","NSS1-MCS4",
		"NSS1-MCS5","NSS1-MCS6","NSS1-MCS7","NSS1-MCS8","NSS1-MCS9",
		"NSS2-MCS0","NSS2-MCS1","NSS2-MCS2","NSS2-MCS3","NSS2-MCS4",
		"NSS2-MCS5","NSS2-MCS6","NSS2-MCS7","NSS2-MCS8","NSS2-MCS9",
		"NSS3-MCS0","NSS3-MCS1","NSS3-MCS2","NSS3-MCS3","NSS3-MCS4",
		"NSS3-MCS5","NSS3-MCS6","NSS3-MCS7","NSS3-MCS8","NSS3-MCS9"];

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
				if(chanwid!=0 || (i!=9 && i!=19 && i!=29))//no MCS9 when 20M
				{
					document.write('<option value="' + (i+37) + '">' + vht_rate_name[i] + '\n');
					idx++;
				}
		}
	}
	document.advanceSetup.txRate.selectedIndex=defidx;
}
else{
	idx=0, i=0;
	document.write('<option value="' + (i) + '">' +'<% multilang(LANG_AUTO); %>'+ '\n');
	idx++;
	defidx=0;
	if ((band & 8) || (band&4)) {
		for (i=1; i<78; i++) { //MCS0~76
			if(i!=32){
				if ((txrate+1) == i && !auto)
					defidx = idx;
				document.write('<option value="' + (i) + '">MCS' +(i-1)+ '\n');
				idx++;
			}
				
		}
	}
	if(band & 64){
		for(j=1;j<5;j++){
			for(i=(j*100); i<(j*100+10);i++){
					if (txrate == i && !auto)
						defidx = idx;
					document.write('<option value="' + (i) + '">NSS'+j+'-MCS' +(i-j*100)+ '\n');
					idx++;
			}
		}
	}
	
	document.advanceSetup.txRate.selectedIndex=defidx;
}
	
	</SCRIPT>
	</select>
     </td>
   </tr>
   
  <!-- for WiFi test, start --
    <tr>
      <td width="30%"><font size=2><b><% multilang(LANG_TX_OPERATION_RATE); %>:</b></td>
      <td width="70%"><font size=2>
        <input type="checkbox" name="operRate1M" value="1M">1M&nbsp;&nbsp;&nbsp;
        <input type="checkbox" name="operRate2M" value="2M">2M&nbsp;&nbsp;
	<input type="checkbox" name="operRate5M" value="5M">5.5M&nbsp;&nbsp;
        <input type="checkbox" name="operRate11M" value="11M">11M&nbsp;&nbsp;
	<input type="checkbox" name="operRate6M" value="6M">6M&nbsp;&nbsp;
        <input type="checkbox" name="operRate9M" value="9M">9M&nbsp;&nbsp;
       <br>
        <input type="checkbox" name="operRate12M" value="12M">12M&nbsp;&nbsp;
        <input type="checkbox" name="operRate18M" value="18M">18M&nbsp;&nbsp;
	<input type="checkbox" name="operRate24M" value="24M">24M&nbsp;&nbsp;
        <input type="checkbox" name="operRate36M" value="36M">36M&nbsp;&nbsp;
	<input type="checkbox" name="operRate48M" value="48M">28M&nbsp;&nbsp;
        <input type="checkbox" name="operRate54M" value="54M">54M&nbsp;&nbsp; 
       </td>
    </tr>
    <tr>
      <td width="30%"><font size=2><b><% multilang(LANG_TX_BASIC_RATE); %>:</b></td>
      <td width="70%"><font size=2>
        <input type="checkbox" name="basicRate1M" value="1M">1M&nbsp;&nbsp;&nbsp;
        <input type="checkbox" name="basicRate2M" value="2M">2M&nbsp;&nbsp;
	<input type="checkbox" name="basicRate5M" value="5M">5.5M&nbsp;&nbsp;
        <input type="checkbox" name="basicRate11M" value="11M">11M&nbsp;&nbsp;
      	<input type="checkbox" name="basicRate6M" value="6M">6M&nbsp;&nbsp;
        <input type="checkbox" name="basicRate9M" value="9M">9M&nbsp;&nbsp;
       <br>
        <input type="checkbox" name="basicRate12M" value="12M">12M&nbsp;&nbsp;
        <input type="checkbox" name="basicRate18M" value="18M">18M&nbsp;&nbsp;
	<input type="checkbox" name="basicRate24M" value="24M">24M&nbsp;&nbsp;
        <input type="checkbox" name="basicRate36M" value="36M">36M&nbsp;&nbsp;
	<input type="checkbox" name="basicRate48M" value="48M">28M&nbsp;&nbsp;
        <input type="checkbox" name="basicRate54M" value="54M">54M&nbsp;&nbsp; 
       </td>        
    </tr>
    <tr>
      <td width="30%"><font size=2><b><% multilang(LANG_DTIM_PERIOD); %>:</b></td>
      <td width="70%"><font size=2><input type="text" name="dtimPeriod" size="5" maxlength="3" value=<% getInfo("dtimPeriod"); %>>(1-255)</td>
    </tr>

-- for WiFi test, end -->

    	<% write_wladvanced(); %>
	<% ShowWmm(); %>   
	<% ShowDot11k_v(); %>
	<% extra_wladvanced(); %>
  </table>
  <p>
  <input type="submit" value="<% multilang(LANG_APPLY_CHANGES); %>" name="save" onClick="return saveChanges(this)">&nbsp;&nbsp;
  <input type="hidden" value="/admin/wladvanced.asp" name="submit-url">
  <input type="hidden" value=<% checkWrite("wlan_idx"); %> name="wlan_idx">
  <input type="hidden" name="postSecurityFlag" value="">
  </p>
  <script>
	<% initPage("wladv"); %>
	updateState();
	wltxbfChange();
  	wlDot11kChange();
	wlRoamingChange();
  </script>
</form>
</blockquote>
</body>

</html>
