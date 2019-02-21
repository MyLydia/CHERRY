<%SendWebHeadStr(); %>
<title><% multilang(LANG_MAC_BASED_ASSIGNMENT); %></title>

<SCRIPT>
var pool_ipprefix;

function checkInputIP(client)
{
	var pool_ip, pool_ipstart, pool_ipend, mask;
	var i, mask_d, pool_start_d, pool_end_d;
	
	if (pool_ipprefix) {
		pool_ip = document.macBase.lan_ip.value;
		mask = document.macBase.lan_mask.value;
	}
	else {
		pool_ipstart = document.macBase.lan_dhcpRangeStart.value;
		pool_ipend = document.macBase.lan_dhcpRangeEnd.value;
		mask = document.macBase.lan_dhcpSubnetMask.value;
	}
	
	for( i=1;i<5;i++ ) {
		mask_d = getDigit(mask, i);
		pool_start_d = getDigit(pool_ipstart, i);
		pool_end_d = getDigit(pool_ipend, i);
		client_d = getDigit(client, i);
	
		if( (pool_start_d & mask_d) != (client_d & mask_d ) ) {
			return false;
		}
		if (client_d < pool_start_d || client_d > pool_end_d)
			return false;
	}
	
	if (pool_ipprefix) {
		if( (parseInt(document.macBase.lan_dhcpRangeStart.value, 10) > client_d) ||
			(parseInt(document.macBase.lan_dhcpRangeEnd.value, 10) < client_d) ) {
			return false;
		}
	}
	
	return true;
}

function addClick(obj)
{
	var str = document.macBase.hostMac.value;
	var macdigit = 0;

  	if ( str.length != 17) {
		alert("<% multilang(LANG_INPUT_HOST_MAC_ADDRESS_IS_NOT_COMPLETE_IT_SHOULD_BE_17_DIGITS_IN_HEX); %>");
		document.macBase.hostMac.focus();
		return false;
  	}	
 	
	if (document.macBase.hostMac.value=="") {
		alert("<% multilang(LANG_ENTER_HOST_MAC_ADDRES); %>");
		document.macBase.hostMac.focus();
		return false;
	}
	
	for (var i=0; i<str.length; i++) {
		if ((str.charAt(i) == 'f') || (str.charAt(i) == 'F'))
			macdigit ++;
		else
			continue;
	}
	if (macdigit == 12 || str == "00-00-00-00-00-00") {
		alert("<% multilang(LANG_INVALID_MAC_ADDRESS); %>");
		document.macBase.hostMac.focus();
		return false;
	}

	if (!checkHostIP(document.macBase.hostIp, 1))
		return false;
	
	if ( validateKey2( document.macBase.hostMac.value ) == 0 ) {
		alert("<% multilang(LANG_INVALID_HOST_MAC_ADDRESS_IT_SHOULD_BE_IN_HEX_NUMBER_0_9_OR_A_F_OR_A_F); %>");
		document.macBase.hostMac.focus();
		return false;
	}

	//cathy, for  bug B017
	if ( !checkInputIP(document.macBase.hostIp.value ) ) {
		alert("<% multilang(LANG_INVALID_IP_ADDRESS_IT_SHOULD_BE_IN_IP_POOL_RANGE); %>");
		document.macBase.hostIp.focus();
		return false;
	}
	
	if ( !checkDigitRangeforMac(document.macBase.hostMac.value,1,0,255) ) {
		alert("<% multilang(LANG_INVALID_SOURCE_RANGE_IN_1ST_HEX_NUMBER_OF_HOST_MAC_ADDRESS_IT_SHOULD_BE_0X00_0XFF); %>");
		document.macBase.hostMac.focus();
		return false;
	}
	
	if ( !checkDigitRangeforMac(document.macBase.hostMac.value,2,0,255) ) {
		alert("<% multilang(LANG_INVALID_SOURCE_RANGE_IN_2ND_HEX_NUMBER_OF_HOST_MAC_ADDRESS_IT_SHOULD_BE_0X00_0XFF); %>");
		document.macBase.hostMac.focus();
		return false;
	}
	
	if ( !checkDigitRangeforMac(document.macBase.hostMac.value,3,0,255) ) {
		alert("<% multilang(LANG_INVALID_SOURCE_RANGE_IN_3RD_HEX_NUMBER_OF_HOST_MAC_ADDRESS_IT_SHOULD_BE_0X00_0XFF); %>");
		document.macBase.hostMac.focus();
		return false;
	}
	
	if ( !checkDigitRangeforMac(document.macBase.hostMac.value,4,0,254) ) {
		alert("<% multilang(LANG_INVALID_SOURCE_RANGE_IN_4TH_HEX_NUMBER_OF_HOST_MAC_ADDRESS_IT_SHOULD_BE_0X00_0XFF); %>");
		document.macBase.hostMac.focus();
		return false;
	}
	
	if ( !checkDigitRangeforMac(document.macBase.hostMac.value,5,0,255) ) {
		alert("<% multilang(LANG_INVALID_SOURCE_RANGE_IN_5RD_HEX_NUMBER_OF_HOST_MAC_ADDRESS_IT_SHOULD_BE_0X00_0XFF); %>");
		document.macBase.hostMac.focus();
		return false;
	}
	
	if ( !checkDigitRangeforMac(document.macBase.hostMac.value,6,0,255) ) {
		alert("<% multilang(LANG_INVALID_SOURCE_RANGE_IN_6TH_HEX_NUMBER_OF_HOST_MAC_ADDRESS_IT_SHOULD_BE_0X00_0XFF); %>");
		document.macBase.hostMac.focus();
		return false;
	}

	obj.isclick = 1;
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	
	return true;
}

function on_submit(obj)
{
	obj.isclick = 1;
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	return true;
}
	
</SCRIPT>
</head>


<body>
<div class="intro_main ">
	<p class="intro_title"><% multilang(LANG_MAC_BASED_ASSIGNMENT); %></p>
	<p class="intro_content"> <% multilang(LANG_THIS_PAGE_IS_USED_TO_CONFIGURE_THE_STATIC_IP_BASE_ON_MAC_ADDRESS_YOU_CAN_ASSIGN_DELETE_THE_STATIC_IP_THE_HOST_MAC_ADDRESS_PLEASE_INPUT_A_STRING_WITH_HEX_NUMBER_SUCH_AS_00_D0_59_C6_12_43); %></p>
</div>

<form action=/boaform/formmacBase method=POST name="macBase">

<input type="hidden" name="lan_ip" value=<% getInfo("dhcplan-ip"); %>>
<input type="hidden" name="lan_mask" value=<% getInfo("dhcplan-subnet"); %>>
<input type="hidden" name="lan_dhcpRangeStart" value=<% getInfo("lan-dhcpRangeStart"); %>>
<input type="hidden" name="lan_dhcpRangeEnd" value=<% getInfo("lan-dhcpRangeEnd"); %>>
<input type="hidden" name="lan_dhcpSubnetMask" value=<% getInfo("lan-dhcpSubnetMask"); %>>

<div class="data_common data_common_notitle">
	<table>
		<tr>
			<th><% multilang(LANG_MAC_ADDRESS); %> (xx-xx-xx-xx-xx-xx): </th> 
			<td><input type="text" name="hostMac" size="20" maxlength="17">&nbsp;&nbsp;</td>
		</tr>
		<tr>
			<th><% multilang(LANG_ASSIGNED_IP_ADDRESS); %> (xxx.xxx.xxx.xxx): </th>
			<td><input type="text" name="hostIp" size="20" maxlength="15">&nbsp;&nbsp;</td>
		</tr>
	</table>
</div>

<div class="btn_ctl">
	<input class="link_bg" type="submit" value="<% multilang(LANG_ASSIGN); %> IP" name="addIP" onClick="return addClick(this)">&nbsp;&nbsp;
	<input class="link_bg" type="submit" value="<% multilang(LANG_DELETE_ASSIGNED_IP); %>" name="delIP" onClick="return on_submit(this)">&nbsp;&nbsp; 
	<input type="hidden" value="/macIptbl.asp" name="submit-url">
	<input class="link_bg" type="button" value="<% multilang(LANG_CLOSE); %>" name="close" onClick="javascript: window.close();">
</div>

<div class="column">
	<div class="column_title">
		<div class="column_title_left"></div>
			<p><% multilang(LANG_MAC_BASED_ASSIGNMENT); %><% multilang(LANG_TABLE_2); %></p>
		<div class="column_title_right"></div>
	</div>
	<div class="data_common">
		<table>
			<% showMACBaseTable(); %>
		</table>
	</div>
</div>

<input type="hidden" name="postSecurityFlag" value="">
<script>
	<% initPage("dhcp-macbase"); %>
</script>
</form>
</body>

</html>
