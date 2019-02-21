<html>
<! Copyright (c) Realtek Semiconductor Corp., 2003. All Rights Reserved. ->
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<title><% multilang(LANG_SYSTEM_LOG); %></title>
<link rel="stylesheet" type="text/css" href="common_style.css"/>
<script type="text/javascript" src="share.js">
</script>
<script language="javascript">
var addr = '<% getInfo("syslog-server-ip"); %>';
var port = '<% getInfo("syslog-server-port"); %>';
function getLogPort() {
	var portNum = parseInt(port);
	if (isNaN(portNum) || portNum == 0)
		portNum = 514; // default system log server port is 514

	return portNum;
}

function hideInfo(hide) {
	var status = 'visible';

	if (hide == 1) {
		status = 'hidden';
		document.forms[0].logAddr.value = '';
		document.forms[0].logPort.value = '';
		changeBlockState('srvInfo', true);
	} else {
		changeBlockState('srvInfo', false);
		document.forms[0].logAddr.value = addr;
		document.forms[0].logPort.value = getLogPort();
	}
}

function hidesysInfo(hide) {
	var status = false;

	if (hide == 1) {
		status = true;
	}
	changeBlockState('sysgroup', status);
}

function changelogstatus() {
	with (document.forms[0]) {
		if (logcap[1].checked) {
			hidesysInfo(0);
			if (logMode.selectedIndex == 0) {
				hideInfo(1);
			} else {
				hideInfo(0);
			}
		} else {
			hidesysInfo(1);
			hideInfo(1);
		}
	}
}

function cbClick(obj) {
	var idx = obj.selectedIndex;
	var val = obj.options[idx].value;
	
	/* 1: Local, 2: Remote, 3: Both */
	if (val == 1)
		hideInfo(1);
	else
		hideInfo(0);
}

function check_enable()
{
	if (document.formSysLog.logcap[0].checked) {
		//disableTextField(document.formSysLog.msg);
		disableButton(document.formSysLog.refresh);		
	}
	else {
		//enableTextField(document.formSysLog.msg);
		enableButton(document.formSysLog.refresh);
	}
}               

/*function scrollElementToEnd (element) {
   if (typeof element.scrollTop != 'undefined' &&
       typeof element.scrollHeight != 'undefined') {
     element.scrollTop = element.scrollHeight;
   }
}*/

function saveClick()
{
	<% RemoteSyslog("check-ip"); %>
//	if (document.forms[0].logAddr.disabled == false && !checkIP(document.formSysLog.logAddr))
//		return false;
//	alert("Please commit and reboot this system for take effect the System log!");
	return true;
}

</script>
</head>

<body>
<blockquote>
<h2 class="page_title"><% multilang(LANG_SYSTEM_LOG); %></h2>
<form action=/boaform/admin/formSysLog method=POST name=formSysLog>
<table>
<tr><hr size=1 noshade align=top></tr>
<tr>
	<th><% multilang(LANG_SYSTEM_LOG); %>&nbsp;:</th>
	<td>
		<input type="radio" value="0" name="logcap" onClick='changelogstatus()' <% checkWrite("log-cap0"); %>><% multilang(LANG_DISABLE); %>&nbsp;&nbsp;
		<input type="radio" value="1" name="logcap" onClick='changelogstatus()' <% checkWrite("log-cap1"); %>><% multilang(LANG_ENABLE); %>
	</td>
</tr>    
<% ShowPPPSyslog("syslogppp"); %>		
<TBODY id='sysgroup'>
<tr>
	<th><% multilang(LANG_LOG_LEVEL); %>&nbsp;:</th>
	<td><select name='levelLog' size="1">
		<% checkWrite("syslog-log"); %>
	</select></td>
</tr>
<tr>
	<th><% multilang(LANG_DISPLAY_LEVEL); %>&nbsp;:</th>
	<td ><select name='levelDisplay' size="1">
		<% checkWrite("syslog-display"); %>
	</select></td>
</tr>
<% RemoteSyslog("syslog-mode"); %>
<tbody id='srvInfo'>
<% RemoteSyslog("server-info"); %>
</tbody>
</TBODY>
<tr>
	<td>	<input type="submit" value="<% multilang(LANG_APPLY_CHANGES); %>" name="apply" onClick="return saveClick()"></td>
</tr>
   
<tr>
	<th<% multilang(LANG_SAVE_LOG_TO_FILE); %>:</th>
	<td><input type="submit" value="<% multilang(LANG_SAVE); %>..." name="save_log"></td>
</tr>
<tr>
	<th><% multilang(LANG_CLEAR_LOG); %>:</th>
	<td><input type="submit" value="<% multilang(LANG_RESET); %>" name="clear_log"></td>
</tr>
</table>
<table>
<tr><hr size=1 noshade align=top></tr>
<tr>
	<th><% multilang(LANG_SYSTEM_LOG); %></th>
	<td><input type="button" value="Refresh" name="refresh" onClick="javascript: window.location.reload()"></td>
</tr>
<tr>
	<td>
	<div style="overflow: auto; height: 500px; width: 500px; PADDING-LEFT: 10px; PADDING-TOP: 10px; PADDING-RIGHT: 10px; PADDING-BOTTOM: 10px">
	<table><% sysLogList(); %></table>
	</td>
</tr>
</table>


<input type="hidden" value="/admin/syslog.asp" name="submit-url">
<script>
	check_enable();
	//scrollElementToEnd(this.formSysLog.msg);
</script>
</form>
<script>
	<% initPage("syslog"); %>
	<% initPage("pppSyslog"); %>
</script>
</blockquote>
</body>
</html>


