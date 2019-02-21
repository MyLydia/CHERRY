<html>
<! Copyright (c) Realtek Semiconductor Corp., 2003. All Rights Reserved. ->
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<title>SNMP <% multilang(LANG_CONFIGURATION); %></title>
<link rel="stylesheet" type="text/css" href="common_style.css" />
<script type="text/javascript" src="share.js">
</script>
<SCRIPT language="javascript" src="/common.js"></SCRIPT>
<style>
th{
    text-align: left;
}
</style>
<SCRIPT>
<% initSnmpConfig(); %>

function saveChanges(obj)
{
	if (!checkHostIP(document.snmpTable.snmpTrapIpAddr, 1))
		return false;
 
	if ( validateKey( document.snmpTable.snmpSysObjectID.value ) == 0 ) {
		alert("Invalid Object ID value. It should be the decimal number (0-9) or '.'" );
		document.snmpTable.snmpSysObjectID.value = document.snmpTable.snmpSysObjectID.defaultValue;
		document.snmpTable.snmpSysObjectID.focus();
		return false;
	}
  
	// count the numbers of '.' on OID
	var i=0;
	var str=document.snmpTable.snmpSysObjectID.value;
	while (str.length!=0) {
		if ( str.charAt(0) == '.' ) {
			i++;
		}	
		str = str.substring(1);
	}
  
	if ( i!=6 ) {
		alert("Invalid Object ID value. It should be fill with OID string as 1.3.6.1.4.1.X");
		document.snmpTable.snmpSysObjectID.value = document.snmpTable.snmpSysObjectID.defaultValue;
		document.snmpTable.snmpSysObjectID.focus();
		return false;
	}  
  
	// Check if the OID's prefix is "1.3.6.1.4.1"
	var str2 = document.snmpTable.snmpSysObjectID.value.substring(0, 11);
	if( str2!="1.3.6.1.4.1" ) {
		alert("Invalid Object ID value. It should be fill with prefix OID string as 1.3.6.1.4.1");
		document.snmpTable.snmpSysObjectID.value = document.snmpTable.snmpSysObjectID.defaultValue;
		document.snmpTable.snmpSysObjectID.focus();
		return false;
	}
   
	if (checkString(document.snmpTable.snmpSysDescr.value) == 0) {
		alert('Invalid System Description.');
		document.snmpTable.snmpSysDescr.focus();
		return false;
	}
	if (checkString(document.snmpTable.snmpSysContact.value) == 0) {
		alert('Invalid System Contact.');
		document.snmpTable.snmpSysContact.focus();
		return false;
	}
	if (checkString(document.snmpTable.snmpSysName.value) == 0) {
		alert('Invalid System Name.');
		document.snmpTable.snmpSysName.focus();
		return false;
	}
	if (checkString(document.snmpTable.snmpSysLocation.value) == 0) {
		alert('Invalid System Location.');
		document.snmpTable.snmpSysLocation.focus();
		return false;
	}
	if (checkString(document.snmpTable.snmpCommunityRO.value) == 0) {
		alert('Invalid Community name (read-only).');
		document.snmpTable.snmpCommunityRO.focus();
		return false;
	}
	if (checkString(document.snmpTable.snmpCommunityRW.value) == 0) {
		alert('Invalid Community name (write-only).');
		document.snmpTable.snmpCommunityRW.focus();
		return false;
	}
  
	/* name of rouser and rwuser can't be same according to net-snmp spec */
	if(document.snmpTable.snmpv3ROName.value.length > 0 && document.snmpTable.snmpv3RWName.value.length > 0
		&& document.snmpTable.snmpv3ROName.value.length == document.snmpTable.snmpv3RWName.value.length)
	{
		if(document.snmpTable.snmpv3ROName.value == document.snmpTable.snmpv3RWName.value)
		{
			alert("name of snmpv3 read-only user and read-write user can't be same!");
			return false;
		}
	}
	if(document.snmpTable.snmpv3ROName.value.length > 0)
	{
		if(document.snmpTable.snmpv3ROAuth.value != 2 && document.snmpTable.snmpv3ROPwd.value.length < 8)
		{
			alert("snmpv3 read-only user password can't be less than 8 character!");
			return false;
		}
	}
	if(document.snmpTable.snmpv3RWName.value.length > 0)
	{
		if(document.snmpTable.snmpv3RWPwd.value.length < 8)
		{
			alert("snmpv3 read-write user password can't be less than 8 character!");
			return false;
		}
	}
	
	reLoadPage();
	obj.isclick = 1;
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	return true;
}

function versionChange()
{
	var snmpv2 = document.getElementById("snmpv2");
	var snmpv3 = document.getElementById("snmpv3");
	
	var version = document.snmpTable.snmpVersion.value;
	if(version == 1)
	{
		snmpv2.style.display="";
		snmpv3.style.display="none";
	}
	else if(version == 2)
	{
		snmpv3.style.display="";
		snmpv2.style.display="none";	
	}
	else
	{
		snmpv2.style.display="";
		snmpv3.style.display="";
	}
}

function snmpv3ROTypeChange()
{
	if(document.snmpTable.snmpv3ROAuth.value == 2)
	{
		document.snmpTable.snmpv3ROPwd.disabled = true;
	}
	else
	{
		document.snmpTable.snmpv3ROPwd.disabled = false;
	}
}

function init()
{
	document.snmpTable.snmpv3ROName.value = snmpv3ROName;
	document.snmpTable.snmpv3ROPwd.value = snmpv3ROPwd;
	document.snmpTable.snmpv3ROAuth.selectedIndex = snmpv3ROAuth;
	document.snmpTable.snmpv3RWName.value = snmpv3RWName;
	document.snmpTable.snmpv3RWPwd.value = snmpv3RWPwd;
	document.snmpTable.snmpv3RWAuth.selectedIndex = snmpv3RWAuth;
	document.snmpTable.snmpv3RWPrivacy.selectedIndex = snmpv3RWPrivacy;
	document.snmpTable.snmpVersion.value = snmpVersion;
	versionChange();
	snmpv3ROTypeChange();
}
</SCRIPT>

</head>

<body onload="init()">
<blockquote>
<h2 class="page_title">SNMP <% multilang(LANG_CONFIGURATION); %></h2>

<table>
  <tr><td><font size=2>
    <% multilang(LANG_THIS_PAGE_IS_USED_TO_CONFIGURE_THE_SNMP_HERE_YOU_MAY_CHANGE_THE_SETTINGS_FOR_SYSTEM_DESCRIPTION_TRAP_IP_ADDRESS_COMMUNITY_NAME_ETC); %>
  </font></td></tr>
  <tr><td><hr size=1 noshade align=top></td></tr>
</table>

<form action=/boaform/formSnmpConfig method=POST name="snmpTable">
<div>
<table>
	<tr>
		<th>SNMP:</th>
		<td>
			<input type="radio" value="0" name="snmp_enable" <% checkWrite("snmpd-on"); %> ><% multilang(LANG_DISABLE); %>&nbsp;&nbsp;
			<input type="radio" value="1" name="snmp_enable" <% checkWrite("snmpd-off"); %> ><% multilang(LANG_ENABLE); %>&nbsp;&nbsp;
		</td>     
	</tr> 
	<tr>
		<th><% multilang(LANG_SYSTEM_DESCRIPTION); %></th>
		<td><input type="text" name="snmpSysDescr" size="50" maxlength="64" value="<% getInfo("snmpSysDescr"); %>"></td>
	</tr>
	<tr>
		<th><% multilang(LANG_SYSTEM_CONTACT); %></th>
		<td><input type="text" name="snmpSysContact" size="50" maxlength="64" value="<% getInfo("snmpSysContact"); %>"></td>
	</tr>
	<tr>
		<th><% multilang(LANG_SYSTEM); %><% multilang(LANG_NAME); %></th>
		<td><input type="text" name="snmpSysName" size="50" maxlength="64" value="<% getInfo("snmpSysName"); %>"></td>
	</tr>
	<tr>
		<th><% multilang(LANG_SYSTEM_LOCATION); %></th>
		<td><input type="text" name="snmpSysLocation" size="50" maxlength="64" value="<% getInfo("snmpSysLocation"); %>"></td>
	</tr>
	<tr>
		<th><% multilang(LANG_SYSTEM_OBJECT_ID); %></th>
		<td><input type="text" name="snmpSysObjectID" size="50" maxlength="64" value="<% getInfo("snmpSysObjectID"); %>"></td>
	</tr>
	<tr>
		<th><% multilang(LANG_TRAP_IP_ADDRESS); %></th>
		<td><input type="text" name="snmpTrapIpAddr" size="15" maxlength="15" value=<% getInfo("snmpTrapIpAddr"); %>></td>
	</tr>
	<tr>
		<th>Snmp version</th>
		<td>
			<select name="snmpVersion" onchange="versionChange()">
				<option value="1">snmpv2</option>
				<option value="2">snmpv3</option>
				<option value="3">snmpv2 and snmpv3</option>
			</select>
		</td>
	</tr>
</table>
<div id="snmpv2">
<table>
	<tr>
        <th colspan="2">SNMP version 2 account</th>
	</tr>
	<tr>
		<th>Community name (read-only)</th>
		<td><input type="text" name="snmpCommunityRO" size="50" maxlength="64" value="<% getInfo("snmpCommunityRO"); %>"></td>
	</tr>
	<tr>
		<th>Community name (write-only)</th>
		<td><input type="text" name="snmpCommunityRW" size="50" maxlength="64" value="<% getInfo("snmpCommunityRW"); %>"></td>
	</tr>
</table>
</div>
<div id="snmpv3">
<table>
	<tr>
        <th colspan="2">SNMP version 3 account</th>
	</tr>
	<tr>
		<th>Snmpv3 read-only name</th>
		<td><input type="text" name="snmpv3ROName" size="50" maxlength="64" value="test"></td>
	</tr>
	<tr>
		<th>read-only auth type</th>
		<td>
			<select name="snmpv3ROAuth" onchange="snmpv3ROTypeChange()">
				<option value="0">MD5</option>
				<option value="1">SHA</option>
				<option value="2">No AUTH</option>
			</select>
		</td>
	</tr>
	<tr>
		<th>read-only password</th>
		<td><input type="password" name="snmpv3ROPwd" size="50" maxlength="64" value="test"></td>
	</tr>
	<tr>
		<th>Snmpv3 read-write name</th>
		<td><input type="text" name="snmpv3RWName" size="50" maxlength="64" value="client"></td>
	</tr>
	<tr>
		<th>read-write auth type</th>
		<td>
			<select name="snmpv3RWAuth">
				<option value="0">MD5</option>
				<option value="1">SHA</option>
			</select>
		</td>
	</tr>
	<tr>
		<th>read-write privacy type</th>
		<td>
			<select name="snmpv3RWPrivacy">
				<option value="0">DES</option>
				<option value="1">AES</option>
			</select>
		</td>
	</tr>
	<tr>
		<th>read-write password</th>
		<td><input type="password" name="snmpv3RWPwd" size="50" maxlength="64" value="test"></td>
	</tr>
</table>
</div>
</div>
<br>
    <input type="submit" value="<% multilang(LANG_APPLY_CHANGES); %>" name="save" onClick="return saveChanges(this)">&nbsp;&nbsp;
    <input type="reset" value="<% multilang(LANG_RESET); %>" name="reset">
    <input type="hidden" value="/snmpv3.asp" name="submit-url">
    <input type="hidden" name="postSecurityFlag" value="">
</form>
</body>

</html>
