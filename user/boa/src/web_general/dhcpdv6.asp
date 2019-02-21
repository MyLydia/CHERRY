<%SendWebHeadStr(); %>
<title>DHCPv6 <% multilang(LANG_SETTINGS); %></title>

<SCRIPT>
function openWindow(url, windowName)
{
	var wide = 900;
	var high = 600;
	if (document.all)
		var xMax = screen.width, yMax = screen.height;
	else if (document.layers)
		var xMax = window.outerWidth, yMax = window.outerHeight;
	else
		var xMax = 640, yMax = 480;
	var xOffset = (xMax - wide) / 2;
	var yOffset = (yMax - high) / 3;

	var settings =
	    'width=' + wide + ',height=' + high + ',screenX=' + xOffset +
	    ',screenY=' + yOffset + ',top=' + yOffset + ',left=' + xOffset +
	    ', resizable=yes, toolbar=no,location=no,directories=no,status=no,menubar=no,scrollbars=yes';

	window.open(url, windowName, settings);
}

function showDhcpv6Svr()
{
	var html;

	if (document.dhcpd.dhcpdenable[0].checked == true)
		document.getElementById('displayDhcpSvr').innerHTML=
			'<div class="btn_ctl">'+
			'<input type="submit" value="<% multilang(LANG_APPLY_CHANGES); %>" name="save" class="link_bg" onClick="return on_submit(this)">&nbsp;&nbsp;'+
			'</div>';
	else if (document.dhcpd.dhcpdenable[1].checked == true)
		document.getElementById('displayDhcpSvr').innerHTML=
			'<div class="data_common data_common_notitle">'+
			'<table>'+
			'<tr><td colspan=2>'+
			'<% multilang(LANG_THIS_PAGE_IS_USED_TO_CONFIGURE_THE_UPPER_INTERFACE_SERVER_LINK_FOR_DHCPV6_RELAY); %>'+
			'</td></tr>'+
			'<tr>'+
			'<th width="30%"><% multilang(LANG_UPPER_INTERFACE); %>:</th>'+
			'<td>'+
			'<select name="upper_if">'+
			'<% if_wan_list("all2"); %>'+    	                           
			'</select>'+     	
			'</td>'+
			'</tr>'+			   
			'</table></div>'+		
			'<div class="btn_ctl">'+
			'<input type="submit" value="<% multilang(LANG_APPLY_CHANGES); %>" name="save" class="link_bg" onClick="return on_submit(this)">&nbsp;&nbsp;'+
			'</div>';
	else if (document.dhcpd.dhcpdenable[2].checked == true) {
		html=
			'<div class="data_common data_common_notitle">'+

			'<table>'+
			'<tr><td colspan=2>'+
			'<% multilang(LANG_ENABLE_THE_DHCPV6_SERVER_IF_YOU_ARE_USING_THIS_DEVICE_AS_A_DHCPV6_SERVER_THIS_PAGE_LISTS_THE_IP_ADDRESS_POOLS_AVAILABLE_TO_HOSTS_ON_YOUR_LAN_THE_DEVICE_DISTRIBUTES_NUMBERS_IN_THE_POOL_TO_HOSTS_ON_YOUR_NETWORK_AS_THEY_REQUEST_INTERNET_ACCESS); %>'+
			'</td></tr>'+
			'<tr>'+
			'<th width="30%"><% multilang(LANG_IP_POOL_RANGE); %>:</th>';
		html+=
			'<td width="70%"><input type="text" name="dhcpRangeStart" size=25 maxlength=39 value="<% getInfo("dhcpv6s_range_start"); %>">'+
			'<font face="Arial" size="5">-</font><input type="text" name="dhcpRangeEnd" size=25 maxlength=39 value="<% getInfo("dhcpv6s_range_end"); %>">&nbsp;';
		html+= '<input type="button" value="<% multilang(LANG_SHOW_CLIENT); %>" name="dhcpClientTblv6" onClick="openWindow(\'/dhcptblv6.asp\', \'\')" >'+
			'</td>'+
			'</tr>';

		html += '<tr>'+
			'<th width="30%"><% multilang(LANG_PREFIX_LENGTH); %>:</th>'+
			'<td width="70%">'+
			'<input type="text" name="prefix_len" size=10 maxlength=3 value="<% getInfo("dhcpv6s_prefix_length"); %>">'+
			'</td>'+
			'</tr>';
		html += '<tr>'+
			'<th width="30%"><% multilang(LANG_VALID_LIFETIME); %>:</th>'+
			'<td width="70%">'+
			'<input type="text" name="Dltime" size=10 maxlength=9 value="<% getInfo("dhcpv6s_default_LTime"); %>"><b> <% multilang(LANG_SECONDS); %></b>'+
			'</td>'+
			'</tr>'+
			'<tr>'+
			'<th width="30%"><% multilang(LANG_PREFERRED_LIFETIME); %>:</th>'+
			'<td width="70%">'+
			'<input type="text" name="PFtime" size=10 maxlength=9 value="<% getInfo("dhcpv6s_preferred_LTime"); %>"><b> <% multilang(LANG_SECONDS); %></b>'+
			'</td>'+
			'</tr>'+
			'<tr>'+
			'<th width="30%"><% multilang(LANG_RENEW_TIME); %>:</th>'+
			'<td width="70%">'+
			'<input type="text" name="RNtime" size=10 maxlength=9 value="<% getInfo("dhcpv6s_renew_time"); %>"><b> <% multilang(LANG_SECONDS); %></b>'+
			'</td>'+
			'</tr>'+
			'<tr>'+
			'<th width="30%"><% multilang(LANG_REBIND_TIME); %>:</th>'+
			'<td width="70%">'+
			'<input type="text" name="RBtime" size=10 maxlength=9 value="<% getInfo("dhcpv6s_rebind_time"); %>"><b> <% multilang(LANG_SECONDS); %></b>'+
			'</td>'+
			'</tr>'+
			'<tr>'+
			'<th width="30%"><% multilang(LANG_CLIENT); %> DUID:</th>'+
			'<td width="70%">'+
			'<input type="text" name="clientID" size=42 maxlength=41 value="<% getInfo("dhcpv6s_clientID"); %>">'+
			'</td>'+
			'</tr>'+							
			'</table></div>'+
			'<div class="btn_ctl">'+
			'<input type="submit" value="<% multilang(LANG_APPLY_CHANGES); %>" name="save" onClick="return saveChanges(this)" class="link_bg">&nbsp;&nbsp;'+
			'</div>'+

			'<div class="data_common data_common_notitle">'+
			'<table>'+
			'<tr>'+
			'<th width="30%"><% multilang(LANG_DOMAIN); %>:</th>'+
			'<td><input type="text" name="domainStr" size="15" maxlength="50">&nbsp;&nbsp;</td>'+
			'<td><input type="submit" value="<% multilang(LANG_ADD); %>" name="addDomain" class="inner_btn" onClick="return on_submit(this)">&nbsp;&nbsp;</td>'+
			'</tr>'+ 
			'</table>'+
			'</div>'+
			'<div class="column">'+
			'<div class="column_title">'+
			'<div class="column_title_left"></div>'+
			'<p><% multilang(LANG_DOMAIN_SEARCH_TABLE); %></p>'+
			'<div class="column_title_right"></div>'+
			'</div>'+
			'<div class="data_common data_vertical">'+
			'<table>'+
			<% showDhcpv6SDOMAINTable(); %>
			'</table>'+
			'</div></div>'+
			'<div class="btn_ctl">'+
			'<input type="submit" value="<% multilang(LANG_DELETE_SELECTED); %>" name="delDomain" class="link_bg" onClick="return on_submit(this)">&nbsp;&nbsp;'+
			'<input type="submit" value="<% multilang(LANG_DELETE_ALL); %>" name="delAllDomain" class="link_bg" onClick="return on_submit(this)">&nbsp;&nbsp;&nbsp;'+

			'</div>'+
			'<div class="data_common data_common_notitle">'+
			'<table>'+

			'<tr>'+
			'<th width="30%"><% multilang(LANG_NAME_SERVER); %> IP:</th>'+
			'<td><input type="text" name="nameServerIP" size="15" maxlength="40">&nbsp;&nbsp;</td>'+
			'<td><input type="submit" value="<% multilang(LANG_ADD); %>" name="addNameServer" class="inner_btn" onClick="return on_submit(this)">&nbsp;&nbsp;</td>'+
			'</tr>'+ 
			'</table>'+
			'</div>'+
			'<div class="column">'+
			'<div class="column_title">'+
			'<div class="column_title_left"></div>'+
			'<p><% multilang(LANG_NAME_SERVER_TABLE); %></p>'+
			'<div class="column_title_right"></div>'+
			'</div>'+
			'<div class="data_common data_vertical">'+
			'<table>'+
			<% showDhcpv6SNameServerTable(); %>
			'</table>'+
			'</div>'+	
			'<div class="btn_ctl">'+
			'<input class="link_bg" type="submit" value="<% multilang(LANG_DELETE_SELECTED); %>" name="delNameServer" <% multilang(LANG_NAME_SERVER_TABLE); %> onClick="return on_submit(this)">&nbsp;&nbsp;'+
			'<input class="link_bg" type="submit" value="<% multilang(LANG_DELETE_ALL); %>" name="delAllNameServer" <% multilang(LANG_NAME_SERVER_TABLE); %> onClick="return on_submit(this)">&nbsp;&nbsp;&nbsp;'+
			'</div>';
		document.getElementById('displayDhcpSvr').innerHTML=html;		
	}
	else if (document.dhcpd.dhcpdenable[3].checked == true)
		document.getElementById('displayDhcpSvr').innerHTML=
			'<div class="data_common data_common_notitle">'+
			'<table>'+
			'<tr><td>'+
			'<% multilang(LANG_AUTO_CONFIG_BY_PREFIX_DELEGATION_FOR_DHCPV6_SERVER); %>'+
			'</td></tr>'+
			'</table></div>'+			
			'<div class="btn_ctl">'+
			'<input type="button" value="<% multilang(LANG_SHOW_CLIENT); %>" name="dhcpClientTblv6" class="link_bg" onClick="openWindow(\'/dhcptblv6.asp\', \'\')" >&nbsp;&nbsp;'+
			'<input type="submit" value="<% multilang(LANG_APPLY_CHANGES); %>" name="save" class="link_bg" onClick="return on_submit(this)"></tr>'+
			'</div>';
}

function on_submit(obj)
{
	obj.isclick = 1;
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	return true;
}

function checkDigitRange_leaseTime(str, min)
{
  d = parseInt(str, 10);
  if ( d < min || d == 0)
      	return false;
  return true;
}

function validateKey_leasetime(str)
{
   for (var i=0; i<str.length; i++) {
    if ( (str.charAt(i) >= '0' && str.charAt(i) <= '9') ||
    		(str.charAt(i) == '-' ) )
			continue;
	return 0;
  }
  return 1;
}


function saveChanges(obj)
{
	if (document.dhcpd.dhcpRangeStart.value =="") {		
		alert('<% multilang(LANG_START_IP_ADDRESS_CANNOT_BE_EMPTY_FORMAT_IS_IPV6_ADDRESS_FOR_EXAMPLE_2000_0200_10); %>');
		document.dhcpd.dhcpRangeStart.value = document.dhcpd.dhcpRangeStart.defaultValue;
		document.dhcpd.dhcpRangeStart.focus();
		return false;
	} else {
		if ( validateKeyV6IP(document.dhcpd.dhcpRangeStart.value) == 0) {				
			alert('<% multilang(LANG_INVALID_START_IP); %>');
			document.dhcpd.dhcpRangeStart.focus();
			return false;
		}
	}
	
	if (document.dhcpd.dhcpRangeEnd.value =="") {		
		alert('<% multilang(LANG_END_IP_ADDRESS_CANNOT_BE_EMPTY_FORMAT_IS_IPV6_ADDRESS_FOR_EXAMPLE_2000_0200_20); %>');
		document.dhcpd.dhcpRangeEnd.value = document.dhcpd.dhcpRangeEnd.defaultValue;
		document.dhcpd.dhcpRangeEnd.focus();
		return false;
	} else {
		if ( validateKeyV6IP(document.dhcpd.dhcpRangeEnd.value) == 0) {				
			alert('<% multilang(LANG_INVALID_END_IP); %>');
			document.dhcpd.dhcpRangeEnd.focus();
			return false;
		}
	}
	
	if ( document.dhcpd.prefix_len.value=="") {		
		alert('<% multilang(LANG_PLEASE_INPUT_IP_PREFIX_LENGTH); %>');
		document.dhcpd.prefix_len.focus();
		return false;
	}
	if ( document.dhcpd.Dltime.value=="") {		
		alert('<% multilang(LANG_PLEASE_INPUT_DHCP_DEFAULT_LEASE_TIME); %>');
		document.dhcpd.Dltime.focus();
		return false;
	}
	if ( validateKey_leasetime( document.dhcpd.Dltime.value ) == 0 ) {		
		alert('<% multilang(LANG_INVALID_DHCP_SERVER_DEFAULT_LEASE_TIME_NUMBER); %>');
		document.dhcpd.Dltime.value = document.dhcpd.Dltime.defaultValue;
		document.dhcpd.Dltime.focus();
		return false;
	}
	if ( !checkDigitRange_leaseTime(document.dhcpd.Dltime.value, 0) ) {	  	
		alert('<% multilang(LANG_INVALID_DHCP_SERVER_DEFAULT_LEASE_TIME); %>');
		document.dhcpd.Dltime.value = document.dhcpd.Dltime.defaultValue;
		document.dhcpd.Dltime.focus();
		return false;
	}	 	
	
	if ( document.dhcpd.PFtime.value=="") {		
		alert('<% multilang(LANG_PLEASE_INPUT_DHCP_PREFERED_LIFETIME); %>');
		document.dhcpd.PFtime.focus();
		return false;
	}
	if ( validateKey_leasetime( document.dhcpd.PFtime.value ) == 0 ) {		
		alert('<% multilang(LANG_INVALID_DHCP_SERVER_PREFERED_LIFETIME_NUMBER); %>');
		document.dhcpd.PFtime.value = document.dhcpd.PFtime.defaultValue;
		document.dhcpd.PFtime.focus();
		return false;
	}
	if ( !checkDigitRange_leaseTime(document.dhcpd.PFtime.value, 0) ) {	  	
		alert('<% multilang(LANG_INVALID_DHCP_SERVER_PREFERED_LIFETIME); %>');
		document.dhcpd.PFtime.value = document.dhcpd.PFtime.defaultValue;
		document.dhcpd.PFtime.focus();
		return false;
	}
	if ( document.dhcpd.RNtime.value=="") {		
		alert('<% multilang(LANG_PLEASE_INPUT_DHCP_RENEW_TIME); %>');
		document.dhcpd.RNtime.focus();
		return false;
	}
	if ( document.dhcpd.RBtime.value=="") {
		alert('<% multilang(LANG_PLEASE_INPUT_DHCP_REBIND_TIME); %>');		
		document.dhcpd.RBtime.focus();
		return false;
	}
	if ( document.dhcpd.clientID.value=="") {		
		alert('<% multilang(LANG_PLEASE_INPUT_DHCP_CLIENT_OUID); %>');
		document.dhcpd.clientID.focus();
		return false;
	}

	obj.isclick = 1;
	postTableEncrypt(document.dhcpd.postSecurityFlag, document.dhcpd);
	return true;
}

function enabledhcpd()
{
	document.dhcpd.dhcpdenable[2].checked = true;
	//ip = ShowIP(document.dhcpd.lan_ip.value);
	showDhcpv6Svr();
}

function disabledhcpd()
{
	document.dhcpd.dhcpdenable[0].checked = true;
	showDhcpv6Svr();
}

function enabledhcprelay()
{
	document.dhcpd.dhcpdenable[1].checked = true;
	showDhcpv6Svr();
}

function autodhcpd()
{
	document.dhcpd.dhcpdenable[3].checked = true;
	showDhcpv6Svr();
}

</SCRIPT>
</head>

<body>
<div class="intro_main ">
	<p class="intro_title">DHCPv6 <% multilang(LANG_SETTINGS); %></p>
	<p class="intro_content"><% multilang(LANG_THIS_PAGE_IS_USED_TO_CONFIGURE_DHCPV6_SERVER_AND_DHCPV6_RELAY); %></p>
</div>

<form action=/boaform/formDhcpv6Server method=POST name="dhcpd">
	<div class="data_common data_common_notitle">
		<table border=0 width="500" cellspacing=4 cellpadding=0>
			<tr>
				<th width="20%">DHCPv6 <% multilang(LANG_MODE); %>: </th>
				<td>
					<% checkWrite("dhcpV6Mode"); %>
				</td>
			</tr>
		</table>
	</div>

	<div ID="displayDhcpSvr"></div>
	<input type="hidden" value="/dhcpdv6.asp" name="submit-url">
	<input type="hidden" name="postSecurityFlag" value="">
	<script>
		<% initPage("dhcpv6-mode"); %>
		showDhcpv6Svr();
	</script>
</form>
<br><br>
</body>
</html>
