<html>
<! Copyright (c) Realtek Semiconductor Corp., 2003. All Rights Reserved. ->
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<title>TR-069 <% multilang(LANG_CONFIGURATION); %></title>
<link rel="stylesheet" type="text/css" href="common_style.css" />
<script type="text/javascript" src="share.js">
</script>
<SCRIPT>
function resetClick()
{
   document.tr069.reset;
}

function periodicSel() {
	if ( document.tr069.enable[0].checked ) {
		disableTextField(document.tr069.interval);
	} else {
		enableTextField(document.tr069.interval);
	}
}

<% TR069ConPageShow("ShowAuthSelFun"); %>

function saveChanges()
{
  if (document.tr069.url.value=="") {
	alert("<% multilang(LANG_ACS_URL_CANNOT_BE_EMPTY); %>");
	document.tr069.url.value = document.tr069.url.defaultValue;
	document.tr069.url.focus();
	return false;
  }

	if (checkString(document.tr069.username.value) == 0) {
		alert("<% multilang(LANG_INVALID_USER_NAME); %>");
		document.tr069.username.focus();
		return false;
	}
	if (checkString(document.tr069.password.value) == 0) {
		alert("<% multilang(LANG_INVALID_PASSWORD); %>");
		document.tr069.password.focus();
		return false;
	}
  if (document.tr069.enable[1].checked) {
	if ( document.tr069.interval.value=="") {
		alert("<% multilang(LANG_PLEASE_INPUT_PERIODIC_INTERVAL_TIME_); %>");
		document.tr069.interval.focus();
		return false;
	}
	if ( validateKey( document.tr069.interval.value ) == 0 ) {
		alert("<% multilang(LANG_INTERVAL_SHOULD_BE_THE_DECIMAL_NUMBER_0_9); %>");
		document.tr069.interval.focus();
		return false;
	}
  }

	if (checkString(document.tr069.conreqname.value) == 0) {
		alert("<% multilang(LANG_INVALID_USER_NAME); %>");
		document.tr069.conreqname.focus();
		return false;
	}
	if (checkString(document.tr069.conreqpw.value) == 0) {
		alert("<% multilang(LANG_INVALID_PASSWORD); %>");
		document.tr069.conreqpw.focus();
		return false;
	}
	if (checkString(document.tr069.conreqpath.value) == 0) {
		alert("<% multilang(LANG_INVALID_PATH); %>");
		document.tr069.conreqpath.focus();
		return false;
	}
  if (document.tr069.conreqport.value=="") {
	alert("<% multilang(LANG_PLEASE_INPUT_THE_PORT_NUMBER_FOR_CONNECTION_REQUEST_); %>");
	document.tr069.conreqport.value = document.tr069.conreqport.defaultValue;
	document.tr069.conreqport.focus();
	return false;
  }
  if ( validateKey( document.tr069.conreqport.value ) == 0 ) {
	alert("<% multilang(LANG_INVALID_PORT_NUMBER_OF_CONNECTION_REQUEST_IT_SHOULD_BE_1_65535); %>");
	document.tr069.conreqport.value = document.tr069.conreqport.defaultValue;
	document.tr069.conreqport.focus();
	return false;
  }
  if ( !checkDigitRange(document.tr069.conreqport.value,1,1,65535) ) {
  	   	alert("<% multilang(LANG_INVALID_PORT_NUMBER_OF_CONNECTION_REQUEST_IT_SHOULD_BE_1_65535); %>");
	document.tr069.conreqport.value = document.tr069.conreqport.defaultValue;
	document.tr069.conreqport.focus();
	return false;
  }


  return true;
}

function addClick()
{
	if (!checkNetIP(document.tr069_acl.aclIP, 1))
		return false;
	if (!checkNetmask(document.tr069_acl.aclMask, 1))
		return false;
	return true;
}

</SCRIPT>
</head>

<body>
<blockquote>
<h2 class="page_title">TR-069 <% multilang(LANG_CONFIGURATION); %></h2>

<form action=/boaform/formTR069Config method=POST name="tr069">
<table>
  <tr><td>
    <% multilang(LANG_THIS_PAGE_IS_USED_TO_CONFIGURE_THE_TR_069_CPE_HERE_YOU_MAY_CHANGE_THE_SETTING_FOR_THE_ACS_S_PARAMETERS); %>
  </td></tr>
  <td><hr size=1 noshade align=top></td>
</table>

<table>
	<tr>
		<th><% multilang(LANG_TR069_DAEMON); %>:</th>
		<td>
		<input type="radio" name=autoexec value=1 <% checkWrite("tr069-autoexec-1"); %> ><% multilang(LANG_ENABLED); %>&nbsp;&nbsp;
		<input type="radio" name=autoexec value=0 <% checkWrite("tr069-autoexec-0"); %> ><% multilang(LANG_DISABLED); %>
		</td>
	</tr>
	<tr>
		<th><% multilang(LANG_ENABLE); %>CWMP<% multilang(LANG_PARAMETER); %>:</th>
		<td>
		<input type="radio" name=enable_cwmp value=1 <% checkWrite("tr069-enable-cwmp-1"); %> ><% multilang(LANG_ENABLED); %>&nbsp;&nbsp;
		<input type="radio" name=enable_cwmp value=0 <% checkWrite("tr069-enable-cwmp-0"); %> ><% multilang(LANG_DISABLED); %>
		</td>
	</tr>
	<% TR069ConPageShow("ShowDataModels"); %>
</table>
<div ID=WANshow style="display:none">

<table>
	<tr>
		<th><% multilang(LANG_WAN_INTERFACE); %>:</th>
		<td>
			<select name="tr069_itf">
				<option value=65535>&nbsp;</option>
				<% if_wan_list("rt"); %>
			</select>
		</td>
	</tr>
</table>
</div>
<table>
	<tr><td colspan=2><hr size=1 noshade align=top></td><td></td></tr>
	<tr>
		<th><% multilang(LANG_ACS); %>:</th>
	</tr>
	<tr>
		<th><% multilang(LANG_URL); %>:</th>
		<td><input type="text" name="url" size="32" maxlength="256" value=<% getInfo("acs-url"); %>></td>
	</tr>
	<tr>
		<th><% multilang(LANG_USER); %><% multilang(LANG_NAME); %>:</th>
		<td><input type="text" name="username" size="32" maxlength="256" value=<% getInfo("acs-username"); %>></td>
	</tr>
	<tr>
		<th><% multilang(LANG_PASSWORD); %>:</th>
		<td><input type="text" name="password" size="32" maxlength="256" value=<% getInfo("acs-password"); %>></td>
	</tr>
	<tr>
		<th><% multilang(LANG_PERIODIC_INFORM); %>:</th>
		<td>
		<input type="radio" name=enable value=0 <% checkWrite("tr069-inform-0"); %> onClick="return periodicSel()"><% multilang(LANG_DISABLED); %>&nbsp;&nbsp;
		<input type="radio" name=enable value=1 <% checkWrite("tr069-inform-1"); %> onClick="return periodicSel()"><% multilang(LANG_ENABLED); %></td>
	</tr>
	<tr>
		<th><% multilang(LANG_PERIODIC_INFORM_INTERVAL); %>:</th>
		<td><input type="text" name="interval" size="32" maxlength="10" value=<% getInfo("inform-interval"); %>  <% checkWrite("tr069-interval"); %> ></td>
	</tr>
</table>

<table>
	<td><hr size=1 noshade align=top></td>
	<tr>
  	<th>
			<% multilang(LANG_CONNECTION_REQUEST); %>:
  	</th>
  </tr>
</table>
<table>
	<% TR069ConPageShow("ShowAuthSelect"); %>
  <tr>
      <th><% multilang(LANG_USER); %><% multilang(LANG_NAME); %>:</th>
      <td><input type="text" name="conreqname" size="32" maxlength="256" value=<% getInfo("conreq-name"); %> <% TR069ConPageShow("DisConReqName"); %> ></td>
  </tr>
  <tr>
      <th><% multilang(LANG_PASSWORD); %>:</th>
      <td><input type="text" name="conreqpw" size="32" maxlength="256" value=<% getInfo("conreq-pw"); %> <% TR069ConPageShow("DisConReqPwd"); %> ></td>
  </tr>
  <tr>
      <th><% multilang(LANG_PATH); %>:</th>
      <td><input type="text" name="conreqpath" size="32" maxlength="31" value=<% getInfo("conreq-path"); %>></td>
  </tr>
  <tr>
      <th><% multilang(LANG_PORT); %>:</th>
      <td><input type="text" name="conreqport" size="32" maxlength="5" value=<% getInfo("conreq-port"); %>></td>
  </tr>
</table>

<!--
<table>
  <tr><hr size=1 noshade align=top></tr>
  <tr>
      <td class="table_title">Debug:</td>
  </tr>
  <% TR069ConPageShow("ShowACSCertCPE"); %>
  <tr>
      <td class="table_item">Show Message:</td>
      <td>
      <input type="radio" name=dbgmsg value=0 <% checkWrite("tr069-dbgmsg-0"); %> >Disabled&nbsp;&nbsp;
      <input type="radio" name=dbgmsg value=1 <% checkWrite("tr069-dbgmsg-1"); %> >Enabled
      </td>
  </tr>
  <tr>
      <td class="table_item">CPE Sends GetRPC:</td>
      <td>
      <input type="radio" name=sendgetrpc value=0 <% checkWrite("tr069-sendgetrpc-0"); %> >Disabled&nbsp;&nbsp;
      <input type="radio" name=sendgetrpc value=1 <% checkWrite("tr069-sendgetrpc-1"); %> >Enabled
      </td>
  </tr>
  <tr>
      <td class="table_item">Skip MReboot:</td>
      <td>
      <input type="radio" name=skipmreboot value=0 <% checkWrite("tr069-skipmreboot-0"); %> >Disabled&nbsp;&nbsp;
      <input type="radio" name=skipmreboot value=1 <% checkWrite("tr069-skipmreboot-1"); %> >Enabled
      </td>
  </tr>
  <tr>
      <td class="table_item>"Delay:</td>
      <td>
      <input type="radio" name=delay value=0 <% checkWrite("tr069-delay-0"); %> >Disabled&nbsp;&nbsp;
      <input type="radio" name=delay value=1 <% checkWrite("tr069-delay-1"); %> >Enabled
      </td>
  </tr>
  <tr>
      <td class="table_item">Auto-Execution:</td>
      <td>
      <input type="radio" name=autoexec value=0 <% checkWrite("tr069-autoexec-0"); %> >Disabled&nbsp;&nbsp;
      <input type="radio" name=autoexec value=1 <% checkWrite("tr069-autoexec-1"); %> >Enabled
      </td>
  </tr>
  <% TR069ConPageShow("ShowCTInformExt"); %>
</table>
-->
	<br>
	<input type="submit" value=<% multilang(LANG_APPLY_CHANGES); %> name="save" onClick="return saveChanges()">&nbsp;&nbsp;
	<input type="reset" value=<% multilang(LANG_UNDO); %> name="reset" onClick="resetClick()">
	<input type="hidden" value="/tr069config.asp" name="submit-url">
</form>
<% TR069ConPageShow("ShowMNGCertTable"); %>
<form action=/boaform/formTR069Config method=POST name="tr069_acl">
<table>
	<tr><td colspan=3><hr size=1 noshade align=top></td><td></td></tr>	
	<tr>
		<th><% multilang(LANG_ENABLE); %> CWMP WAN ACL:</th>
		<td>
		<input type="radio" name=enable_acl value=1 <% checkWrite("tr069-enable-acl-1"); %> ><% multilang(LANG_ENABLED); %>&nbsp;&nbsp;
		<input type="radio" name=enable_acl value=0 <% checkWrite("tr069-enable-acl-0"); %> ><% multilang(LANG_DISABLED); %>
		</td>
		<td><input type="submit" value="<% multilang(LANG_APPLY_CHANGES); %>" name="applyACL">&nbsp;&nbsp; </td>
	</tr>
	<tr>
		<th><% multilang(LANG_IP_ADDRESS); %>:</th>
		<td><input type="text" name="aclIP" size="15" maxlength="15"></td>
	</tr>  
  
	<tr>
		<th><% multilang(LANG_SUBNET_MASK); %>:</th>
		<td><input type="text" name="aclMask" size="15" maxlength="15"></td>      
	</tr>
	
	<tr>
		<td><input type="submit" value="<% multilang(LANG_ADD); %>" name="addIP" onClick="return addClick()">&nbsp;&nbsp;</td>
	</tr>
</table>
<table>
  <tr><td><hr size=1 noshade align=top></td></tr>
  <tr><th>CWMP WAN ACL <% multilang(LANG_TABLE); %>:</th></tr>
</table>
<table>
  <% showCWMPACLTable(); %>
</table>
<br>
      <input type="submit" value="<% multilang(LANG_DELETE_SELECTED); %>" name="delIP" onClick="return deleteClick()">&nbsp;&nbsp;      
      <input type="hidden" value="/tr069config.asp" name="submit-url">
</form>
<script>
	ifIdx = <% getInfo("tr069_wan_intf"); %>;
	document.tr069.tr069_itf.selectedIndex = -1;

	for( i = 0; i < document.tr069.tr069_itf.options.length; i++ )
	{
		if( ifIdx == document.tr069.tr069_itf.options[i].value )
			document.tr069.tr069_itf.selectedIndex = i;
	}
	<% DisplayTR069WAN() %>
</script>
</blockquote>
</body>
</html>
