<% SendWebHeadStr();%>
<title><% multilang(LANG_WLAN_SECURITY_SETTINGS); %></title>

<style>
.on {display:on}
.off {display:none}	
.bggrey {
	BACKGROUND: #FFFFFF
}
</style>
<script>
var defPskLen, defPskFormat;

var ap_mode=0;

function get_by_id(id){
	with(document){
	return getElementById(id);
	}
}

function show_8021x_settings()
{
	var wlan_encmode = get_by_id("method");
	var enable_1x = get_by_id("use1x");
	var form1 = document.formEncrypt ;
	var dF=document.forms[0];
	if (enable_1x.checked) {		
		if (wlan_encmode.selectedIndex == 1)
			get_by_id("show_1x_wep").style.display = "";
		else 
			get_by_id("show_1x_wep").style.display = "none";
		get_by_id("setting_wep").style.display = "none";		
		get_by_id("show_8021x_eap").style.display = "";
		dF.auth_type[2].checked = true;
		dF.auth_type[0].disabled = true;
		dF.auth_type[1].disabled = true;
		dF.auth_type[2].disabled = true;
	}
	else {	
		if (wlan_encmode.selectedIndex == 1)
			get_by_id("setting_wep").style.display = "";	
		else	
			get_by_id("setting_wep").style.display = "none";	

		get_by_id("show_1x_wep").style.display = "none";			
		get_by_id("show_8021x_eap").style.display = "none";

		if(ap_mode!=1){//AP
			if (wlan_encmode.selectedIndex == 2 || wlan_encmode.selectedIndex == 3 || wlan_encmode.selectedIndex == 4){
				if(dF.wpaAuth[1].checked==true)
					get_by_id("show_8021x_eap").style.display = "none";
				else
					get_by_id("show_8021x_eap").style.display = "";
			}
		}else{//Router
			if (wlan_encmode.selectedIndex == 2 || wlan_encmode.selectedIndex == 3 || wlan_encmode.selectedIndex == 4 ){
				if(dF.wpaAuth[1].checked==true)
		get_by_id("show_8021x_eap").style.display = "none";
				else
					get_by_id("show_8021x_eap").style.display = "";
			}
		}		
		//get_by_id("show_8021x_eap").style.display = "none";
		//dF.auth_type[2].checked = true;
		dF.auth_type[0].disabled = false;
		dF.auth_type[1].disabled = false;
		dF.auth_type[2].disabled = false;
	}		
}

function show_wpa_settings()
{
	var dF=document.forms[0];
	var wep_type = get_by_id("method");
	var allow_tkip=0;
	if(wep_type.selectedIndex==2 || wep_type.selectedIndex==3)
		allow_tkip=0;
	else
		allow_tkip=1;
	get_by_id("show_wpa_psk1").style.display = "none";
	get_by_id("show_wpa_psk2").style.display = "none";	
	get_by_id("show_8021x_eap").style.display = "none";
//	get_by_id("show_pre_auth").style.display = "none";
	
	if (dF.wpaAuth[1].checked)
	{
		get_by_id("show_wpa_psk1").style.display = "";
		get_by_id("show_wpa_psk2").style.display = "";		
	}
	else{
		if (ap_mode != 1)
		get_by_id("show_8021x_eap").style.display = "";
//		if (wep_type.selectedIndex > 2) 
//			get_by_id("show_pre_auth").style.display = "";		
	}	
}

function show_wapi_settings()
{
        var dF=document.forms[0];
        var wep_type = get_by_id("method");
        
        get_by_id("show_wapi_psk1").style.display = "none";
        get_by_id("show_wapi_psk2").style.display = "none";
        get_by_id("show_8021x_wapi").style.display = "none";
//      get_by_id("show_pre_auth").style.display = "none";
        
        if (dF.wapiAuth[1].checked){
                get_by_id("show_wapi_psk1").style.display = "";
                get_by_id("show_wapi_psk2").style.display = "";
        }
        else{
                if (ap_mode != 1)
                {
                	get_by_id("show_8021x_wapi").style.display = "";
			if(''=='true')
			{
				get_by_id("show_8021x_wapi_local_as").style.display = "";
			}
			else
			{
				get_by_id("show_8021x_wapi_local_as").style.display = "none";
				dF.uselocalAS.checked=false;
			}
                }
		if (dF.wapiASIP.value == "192.168.1.1")
		{
			dF.uselocalAS.checked=true;
		}
//              if (wep_type.selectedIndex > 2) 
//                      get_by_id("show_pre_auth").style.display = "";          
        }
}

function show_wapi_ASip()
{
	var dF=document.forms[0];
	if (dF.uselocalAS.checked)
	{
		dF.wapiASIP.value = "192.168.1.1";
        }
	else
	{
		dF.wapiASIP.value = "";
	}
}

function show_authentication()
{	
	var wep_type = get_by_id("method");
	var enable_1x = get_by_id("use1x");	
	var form1 = document.formEncrypt ;

	get_by_id("show_wep_auth").style.display = "none";	
	get_by_id("setting_wep").style.display = "none";
	get_by_id("setting_wpa").style.display = "none";
	get_by_id("setting_wapi").style.display = "none";
//	get_by_id("show_pre_auth").style.display = "none";
	get_by_id("show_wpa_cipher").style.display = "none";
	get_by_id("show_wpa2_cipher").style.display = "none";
	get_by_id("enable_8021x").style.display = "none";
	get_by_id("show_8021x_eap").style.display = "none";
	get_by_id("show_8021x_wapi").style.display = "none";
	get_by_id("show_1x_wep").style.display = "none";
        get_by_id("show_wapi_psk1").style.display = "none";
        get_by_id("show_wapi_psk2").style.display = "none";
        get_by_id("show_8021x_wapi").style.display = "none";
	
	if (wep_type.selectedIndex == 1){
		get_by_id("show_wep_auth").style.display = "";		
		if (ap_mode == 1) 
			get_by_id("setting_wep").style.display = "";		
		else {
			get_by_id("enable_8021x").style.display = "";
			if(enable_1x.checked){		
				get_by_id("show_8021x_eap").style.display = "";
				get_by_id("show_1x_wep").style.display = "";
				get_by_id("setting_wep").style.display = "none";
			}else{		
				get_by_id("setting_wep").style.display = "";
			}
		}
	
	}else if (wep_type.selectedIndex > 1 && wep_type.selectedIndex < 5){
		get_by_id("setting_wpa").style.display = "";
		if (wep_type.selectedIndex == 2) {			
			get_by_id("show_wpa_cipher").style.display = "";
			if ( form1.isNmode.value == 1 ) {
				//alert("Select wpa");
				form1.ciphersuite_t.disabled = true;
				form1.wpa2ciphersuite_t.disabled = true;
			}
		}
		if(wep_type.selectedIndex ==3) {
			get_by_id("show_wpa2_cipher").style.display = "";
			if ( form1.isNmode.value == 1 ) {
				//alert("Select wpa2 and is Nmode");
				form1.ciphersuite_t.disabled = true;
				form1.wpa2ciphersuite_t.disabled = true;
			}
		}
		if(wep_type.selectedIndex ==4){
			get_by_id("show_wpa_cipher").style.display = "";
			get_by_id("show_wpa2_cipher").style.display = "";
			form1.ciphersuite_t.disabled = false;
			form1.wpa2ciphersuite_t.disabled = false;
		}		
		show_wpa_settings();
	}else if(wep_type.selectedIndex == 5 )
	{
		get_by_id("setting_wapi").style.display = "";
		show_wapi_settings();
	}
	
	if (wep_type.selectedIndex == 0) {
		if (ap_mode != 1) {
			get_by_id("enable_8021x").style.display = "";
			if(enable_1x.checked){		
				get_by_id("show_8021x_eap").style.display = "";
			}
			else {
				get_by_id("show_8021x_eap").style.display = "none";			
			}
		}
	}	
}

function setDefaultKeyValue(form, wlan_id)
{
  if (form.elements["length"+wlan_id].selectedIndex == 0) {
	if ( form.elements["format"+wlan_id].selectedIndex == 0) {
		form.elements["key"+wlan_id].maxLength = 5;
		form.elements["key"+wlan_id].value = "*****";
		
/*		
		form.elements["key1"+wlan_id].maxLength = 5;
		form.elements["key2"+wlan_id].maxLength = 5;
		form.elements["key3"+wlan_id].maxLength = 5;
		form.elements["key4"+wlan_id].maxLength = 5;
		form.elements["key1"+wlan_id].value = "*****";
		form.elements["key2"+wlan_id].value = "*****";
		form.elements["key3"+wlan_id].value = "*****";
		form.elements["key4"+wlan_id].value = "*****";
*/		
	}
	else {
		form.elements["key"+wlan_id].maxLength = 10;
		form.elements["key"+wlan_id].value = "**********";
		
/*		
		form.elements["key1"+wlan_id].maxLength = 10;
		form.elements["key2"+wlan_id].maxLength = 10;
		form.elements["key3"+wlan_id].maxLength = 10;
		form.elements["key4"+wlan_id].maxLength = 10;
		form.elements["key1"+wlan_id].value = "**********";
		form.elements["key2"+wlan_id].value = "**********";
		form.elements["key3"+wlan_id].value = "**********";
		form.elements["key4"+wlan_id].value = "**********";
*/
	}
  }
  else {
  	if ( form.elements["format"+wlan_id].selectedIndex == 0) {
		form.elements["key"+wlan_id].maxLength = 13;		
		form.elements["key"+wlan_id].value = "*************";		
/*		
		form.elements["key1"+wlan_id].maxLength = 13;
		form.elements["key2"+wlan_id].maxLength = 13;
		form.elements["key3"+wlan_id].maxLength = 13;
		form.elements["key4"+wlan_id].maxLength = 13;
		form.elements["key1"+wlan_id].value = "*************";
		form.elements["key2"+wlan_id].value = "*************";
		form.elements["key3"+wlan_id].value = "*************";
		form.elements["key4"+wlan_id].value = "*************";
*/		

	}
	else {
		form.elements["key"+wlan_id].maxLength = 26;
		form.elements["key"+wlan_id].value ="**************************";		
/*		
		form.elements["key1"+wlan_id].maxLength = 26;
		form.elements["key2"+wlan_id].maxLength = 26;
		form.elements["key3"+wlan_id].maxLength = 26;
		form.elements["key4"+wlan_id].maxLength = 26;
		form.elements["key1"+wlan_id].value ="**************************";
		form.elements["key2"+wlan_id].value ="**************************";
		form.elements["key3"+wlan_id].value ="**************************";
		form.elements["key4"+wlan_id].value ="**************************";
*/		
	}
  }
}
  
function updateWepFormat(form, wlan_id)
{
	if (form.elements["length" + wlan_id].selectedIndex == 0) {
		form.elements["format" + wlan_id].options[0].text = 'ASCII (5 characters)';
		form.elements["format" + wlan_id].options[1].text = 'Hex (10 characters)';
	}
	else {
		form.elements["format" + wlan_id].options[0].text = 'ASCII (13 characters)';
		form.elements["format" + wlan_id].options[1].text = 'Hex (26 characters)';
	}
	//form.elements["format" + wlan_id].selectedIndex =  wep_key_fmt;
	// Mason Yu. TBD
	//form.elements["format" + wlan_id].selectedIndex =  0;
	
	setDefaultKeyValue(form, wlan_id);
}

function saveChanges()
{
  form = document.formEncrypt;
  wpaAuth = form.wpaAuth;
  if (document.formEncrypt.method.selectedIndex>=2) {
        // Mason Yu. 201009_new_security. Start
        if (document.formEncrypt.method.selectedIndex ==2 || document.formEncrypt.method.selectedIndex ==4) {
        	if(form.ciphersuite_t.checked == false && form.ciphersuite_a.checked == false )
		{
			alert("<% multilang(LANG_WPA_CIPHER_SUITE_CAN_NOT_BE_EMPTY); %>");
			return false;
		}
        }
        
        if (document.formEncrypt.method.selectedIndex ==3 || document.formEncrypt.method.selectedIndex ==4) {
        	if(form.wpa2ciphersuite_t.checked == false && form.wpa2ciphersuite_a.checked == false )
		{
			alert("<% multilang(LANG_WPA2_CIPHER_SUITE_CAN_NOT_BE_EMPTY); %>");
			return false;
		}
        }
        // Mason Yu. 201009_new_security. End
         
	var str = document.formEncrypt.pskValue.value;
	if (document.formEncrypt.pskFormat.selectedIndex==1) {
		if (str.length != 64) {
			alert("<% multilang(LANG_PRE_SHARED_KEY_VALUE_SHOULD_BE_64_CHARACTERS); %>");
			document.formEncrypt.pskValue.focus();
			return false;
		}
		takedef = 0;
		if (defPskFormat == 1 && defPskLen == 64) {
			for (var i=0; i<64; i++) {
    				if ( str.charAt(i) != '*')
					break;
			}
			if (i == 64 )
				takedef = 1;
  		}
		if (takedef == 0) {
			for (var i=0; i<str.length; i++) {
    				if ( (str.charAt(i) >= '0' && str.charAt(i) <= '9') ||
					(str.charAt(i) >= 'a' && str.charAt(i) <= 'f') ||
					(str.charAt(i) >= 'A' && str.charAt(i) <= 'F') )
					continue;
				alert("<% multilang(LANG_INVALID_PRE_SHARED_KEY_VALUE_IT_SHOULD_BE_IN_HEX_NUMBER_0_9_OR_A_F); %>");
				document.formEncrypt.pskValue.focus();
				return false;
  			}
		}
	}
	else {
		if ( (document.formEncrypt.method.selectedIndex>=2 && wpaAuth[1].checked) ) {
		if (str.length < 8) {
			alert("<% multilang(LANG_PRE_SHARED_KEY_VALUE_SHOULD_BE_SET_AT_LEAST_8_CHARACTERS); %>");
			document.formEncrypt.pskValue.focus();
			return false;
		}
		if (str.length > 64) {
			alert("<% multilang(LANG_PRE_SHARED_KEY_VALUE_SHOULD_BE_LESS_THAN_64_CHARACTERS); %>");
			document.formEncrypt.pskValue.focus();
			return false;
		}
		if (checkString(document.formEncrypt.pskValue.value) == 0) {
			alert("<% multilang(LANG_INVALID_PRE_SHARED_KEY); %>");
			document.formEncrypt.pskValue.focus();
			return false;
		}
		}
	}
  }
   postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
   return true;
}


function postSecurity(encrypt, enable1X, wep, wpaAuth, wpaPSKFormat, wpaPSK, rsPort, rsIpAddr, rsPassword, ap, uCipher, wpa2uCipher, wepAuth, wepLen, wepKeyFormat) 
{	
	document.formEncrypt.method.value = encrypt;
	document.formEncrypt.pskFormat.value = wpaPSKFormat;
	document.formEncrypt.pskValue.value = wpaPSK;				
	document.formEncrypt.radiusIP.value = rsIpAddr;
	document.formEncrypt.radiusPort.value = rsPort;
	document.formEncrypt.radiusPass.value = rsPassword;
		
	if ( wep != 0 )
		document.formEncrypt.wepKeyLen[wep-1].checked = true;
	
	if (enable1X==1)
		document.formEncrypt.use1x.checked = true;		
	document.formEncrypt.wpaAuth[wpaAuth-1].checked = true;	
	
	// Mason Yu. 201009_new_security. Start
	document.formEncrypt.ciphersuite_t.checked = false;
	document.formEncrypt.ciphersuite_a.checked = false;
	if ( uCipher == 1 )
		document.formEncrypt.ciphersuite_t.checked = true;
	if ( uCipher == 2 )
		document.formEncrypt.ciphersuite_a.checked = true;
	if ( uCipher == 3 ) {
		document.formEncrypt.ciphersuite_t.checked = true;
		document.formEncrypt.ciphersuite_a.checked = true;
	}
	
	document.formEncrypt.wpa2ciphersuite_t.checked = false;
	document.formEncrypt.wpa2ciphersuite_a.checked = false;	
	if ( wpa2uCipher == 1 )
		document.formEncrypt.wpa2ciphersuite_t.checked = true;
	if ( wpa2uCipher == 2 )
		document.formEncrypt.wpa2ciphersuite_a.checked = true;
	if ( wpa2uCipher == 3 ) {
		document.formEncrypt.wpa2ciphersuite_t.checked = true;
		document.formEncrypt.wpa2ciphersuite_a.checked = true;
	}	

	document.formEncrypt.auth_type[wepAuth].checked = true;
	
	if ( wepLen == 0 )
		document.formEncrypt.length0.value = 1;
	else
		document.formEncrypt.length0.value = wepLen;
	
	document.formEncrypt.format0.value = wepKeyFormat+1;			
	show_authentication();
	// Mason Yu. 201009_new_security. End

	
        defPskLen = document.formEncrypt.pskValue.value.length;
	defPskFormat = document.formEncrypt.pskFormat.selectedIndex;
	updateWepFormat(document.formEncrypt, 0);
}

</script>

</head>

<body>
<div class="intro_main ">
	<p class="intro_title"><% multilang(LANG_WLAN_SECURITY_SETTINGS); %></p>
	<p class="intro_content"> <% multilang(LANG_PAGE_DESC_WLAN_SECURITY_SETTING); %></p>
</div>

<form action=/boaform/admin/formWlEncrypt method=POST name="formEncrypt">
<div class="data_common data_common_notitle">
<input type=hidden name="wlanDisabled" value=<% wlanStatus(); %>>
<input type=hidden name="isNmode" value=0 >  
<table>
	<tr>
		<th><% multilang(LANG_SSID); %> <% multilang(LANG_TYPE); %>:</th>
		<td>
			<% SSID_select(); %>
		</td>
	</tr>
	<tr>
      <th><% multilang(LANG_ENCRYPTION); %>:&nbsp;</th>
      <td>
        <select size="1" name="method" onChange="show_authentication()">
	  	<% checkWrite("wpaEncrypt"); %> 
        </select>
       </td>
    </tr>
    
</table>
</div>

<div class="data_common data_common_notitle">
<table>
    <tr id="enable_8021x" style="display:none">
		<th>802.1x <% multilang(LANG_AUTHENTICATION); %>:</th>
		<td>
			<input type="checkbox" id="use1x" name="use1x" value="ON" onClick="show_8021x_settings()">
		</td>
	</tr>
    
    <tr id="show_wep_auth" style="display:none">
		<th><% multilang(LANG_AUTHENTICATION); %>:</th>
		<td>
			<input name="auth_type" type=radio value="open"><% multilang(LANG_OPEN_SYSTEM); %>
			<input name="auth_type" type=radio value="shared"><% multilang(LANG_SHARED_KEY); %>
			<input name="auth_type" type=radio value="both"><% multilang(LANG_AUTO); %>
    	</td>
    </tr>	
	<div id="setting_wep" style="display:none">
		<input type="hidden" name="wepEnabled" value="ON" checked>
	    <tr>	
			<th><% multilang(LANG_KEY_LENGTH); %>:</th>
			<td>
				<select size="1" name="length0" id="key_length" onChange="updateWepFormat(document.formEncrypt, 0)">	
					 <option value=1> 64-bit</option>
					 <option value=2>128-bit</option>
				</select>
			</td>
		</tr>
		<tr>
			<th><% multilang(LANG_KEY_FORMAT); %>:</th>
			<td>
				<select id="key_format" name="format0" onChange="setDefaultKeyValue(document.formEncrypt, 0)">
				     	<option value="1">ASCII</option>
					<option value="2">Hex</option>					
				</select>
			</td>
		</tr>
		<tr>
			<th><% multilang(LANG_ENCRYPTION_KEY); %>:</th>
			<td>
				<input type="text" id="key" name="key0" maxlength="26" size="26" value="">
			</td>
		</tr> 				  
	</div>
	<tr id="setting_wpa" style="display:none">	
		<th><% multilang(LANG_AUTHENTICATION_MODE); %>:</th>
		<td>
			<input name="wpaAuth" type="radio" value="eap" onClick="show_wpa_settings()">Enterprise (RADIUS)
			<input name="wpaAuth" type="radio" value="psk" onClick="show_wpa_settings()">Personal (Pre-Shared Key)
		</td>
	</tr>  
	<tr id="show_wpa_cipher" style="display:none">
		<th>WPA <% multilang(LANG_CIPHER_SUITE); %>:</th>
		<td>
			<input type="checkbox" name="ciphersuite_t" value=1>TKIP&nbsp;
			<input type="checkbox" name="ciphersuite_a" value=1>AES
		</td>
	</tr> 	
	<tr id="show_wpa2_cipher" style="display:none">
		<th>WPA2 <% multilang(LANG_CIPHER_SUITE); %>:</th>
		<td>
			<input type="checkbox" name="wpa2ciphersuite_t" value=1>TKIP&nbsp;
			<input type="checkbox" name="wpa2ciphersuite_a" value=1>AES
		</td>
	</tr> 
	<tr id="show_wpa_psk1" style="display:none">				
		<th><% multilang(LANG_PRE_SHARED_KEY_FORMAT); %>:</th>
		<td>
			<select id="psk_fmt" name="pskFormat" onChange="">
			<option value="0">Passphrase</option>
			<option value="1">HEX (64 characters)</option>
			</select>
		</td>
	</tr>
	<tr id="show_wpa_psk2" style="display:none">
		<th><% multilang(LANG_PRE_SHARED_KEY); %>:</th>
		<td>
			<input type="password" name="pskValue" id="wpapsk" size="32" maxlength="64" value="">
		</td>
	</tr>
    <tr id="setting_wapi" style="display:none">
        <th><% multilang(LANG_AUTHENTICATION_MODE); %>:</th>
        <td>
            <input name="wapiAuth" type="radio" value="eap" onClick="show_wapi_settings()">Enterprise (AS Server)
            <input name="wapiAuth" type="radio" value="psk" onClick="show_wapi_settings()">Personal (Pre-Shared Key)
    	</td>
    </tr>
	<tr id="show_wapi_psk1" style="display:none">
		<th><% multilang(LANG_PRE_SHARED_KEY_FORMAT); %>:</th>
        <td>
        <select id="wapi_psk_fmt" name="wapiPskFormat" onChange="">
                <option value="0">Passphrase</option>
                <option value="1">HEX (64 characters)</option>
                </select>
        </td>
	</tr>
	<tr id="show_wapi_psk2" style="display:none">
		<th ><% multilang(LANG_PRE_SHARED_KEY); %>:</th>
		<td><input type="password" name="wapiPskValue" id="wapipsk" size="32" maxlength="64" value="">
		</td>
	</tr>
	<tr id="show_1x_wep" style="display:none">
		<th class="bgblue"><% multilang(LANG_KEY_LENGTH); %>:</th>
		<td>
			<input name="wepKeyLen" type="radio" value="wep64">64 Bits
			<input name="wepKeyLen" type="radio" value="wep128">128 Bits
		</td>
	</tr> 

	<div id="show_8021x_eap" style="display:none">
		<tr>
			<th >RADIUS <% multilang(LANG_SERVER); %> <% multilang(LANG_IP_ADDRESS); %>:</th>
			<td><input id="radius_ip" name="radiusIP" size="16" maxlength="15" value="0.0.0.0"></td>
		</tr>
		<tr>
			<th >RADIUS <% multilang(LANG_SERVER); %> <% multilang(LANG_PORT); %>:</th>
			<td><input type="text" id="radius_port" name="radiusPort" size="5" maxlength="5" value="1812"></td>
		</tr>
		<tr>
			<th class="bgblue">RADIUS <% multilang(LANG_SERVER); %> <% multilang(LANG_PASSWORD); %>:</th>
			<td><input type="password" id="radius_pass" name="radiusPass" size="32" maxlength="64" value="12345"></td>
		</tr>
	</div>
			
    <div id="show_8021x_wapi" style="display:none">
        <tr id="show_8021x_wapi_local_as" style="">
        	<th><% multilang(LANG_USE_LOCAL_AS_SERVER); %>:</th>
        	<td>
       	 		<input type="checkbox" id="uselocalAS" name="uselocalAS" value="ON" onClick="show_wapi_ASip()">
        	</td>
        </tr>
		<tr>
			<th>AS <% multilang(LANG_SERVER); %> <% multilang(LANG_IP_ADDRESS); %>:</th>
			<td>
				<input id="wapiAS_ip" name="wapiASIP" size="16" maxlength="15" value="0.0.0.0">
			</td>
		</tr>
	</div>        
  </table> 
</div>
<div class="btn_ctl">
	<input type="hidden" name="wlan_idx" value=<% checkWrite("wlan_idx"); %>>
	<input type=hidden value="/admin/wlwpa_mbssid.asp" name="submit-url">
	<input  class="link_bg" type=submit value="Apply Changes"  onClick="return saveChanges()">&nbsp;
	<input type="hidden" name="postSecurityFlag" value="">
</div>
  
<script> 
	<% initPage("wlwpa_mbssid"); %>
	show_authentication();
	defPskLen = document.formEncrypt.pskValue.value.length;
	defPskFormat = document.formEncrypt.pskFormat.selectedIndex;
	updateWepFormat(document.formEncrypt, 0);
</script>
</form>
</body>
</html>
