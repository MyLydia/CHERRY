<html>
<! Copyright (c) Realtek Semiconductor Corp., 2003. All Rights Reserved. ->
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<title><% multilang(LANG_SYSTEM_LOG); %></title>
<link rel="stylesheet" type="text/css" href="common_style.css"/>
<script type="text/javascript" src="share.js">
</script>
<SCRIPT language="javascript" src="/common.js"></SCRIPT>
<script>
function check_enable()
{
	if (document.formSysLog.logcap[0].checked) {
		disableTextField(document.formSysLog.msg);
		disableButton(document.formSysLog.refresh);		
	}
	else {
		enableTextField(document.formSysLog.msg);
		enableButton(document.formSysLog.refresh);
	}
}               

function scrollElementToEnd (element) {
   if (typeof element.scrollTop != 'undefined' &&
       typeof element.scrollHeight != 'undefined') {
     element.scrollTop = element.scrollHeight;
   }
}

function saveClick(obj)
{
	if (!checkIP(document.formSysLog.ip))
		return false;
		
	alert("<% multilang(LANG_PLEASE_COMMIT_AND_REBOOT_THIS_SYSTEM_FOR_TAKE_EFFECT_THE_SYSTEM_LOG); %>");
	obj.isclick = 1;
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
}

function on_submit(obj)
{
	obj.isclick = 1;
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	return true;
}

</script>
</head>

<body>
<blockquote>
<h2 class="page_title">System Log</h2>
<form action=/boaform/formSysLog method=POST name=formSysLog>
<table>
<tr>
	<th>System Log</th>
	<td>
		<input type="radio" value="0" name="logcap" <% checkWrite("log-cap0"); %>>Disable&nbsp;&nbsp;
		<input type="radio" value="1" name="logcap" <% checkWrite("log-cap1"); %>>Enable
	</td>
	<!--
	<td width="45%">	<input type="submit" value="Apply Changes" name="apply" onClick="return saveClick()"></td>
        -->
</tr>
<tr>
      	<th>Log Server(FTP Server):</th>
      	<td><input type="text" name="ip" size="15" maxlength="15" value=<% getInfo("log-server-ip"); %>></td>
</tr>

<tr>
      <th>User Name:</th>
      <td><input type="text" name="username" size="20" maxlength="30" value=<% getInfo("log-server-username"); %>></td>
</tr>

<tr>
      <th>Password:</th>
      <td><input type="password" name="passwd" size="20" maxlength="30"></td>
</tr>
    
<tr>
	<td><input type="submit" value="Apply Changes" name="apply" onClick="return saveClick(this)"></td>
</tr>
   
<tr>
	<th>Save Log to File:</th>
	<td><input type="submit" value="Save..." name="save_log" onClick="return on_submit(this)"></td>
</tr>
<tr>
	<th>Clear Log:</th>
	<td><input type="submit" value="Reset" name="clear_log" onClick="return on_submit(this)"></td>
</tr>
</table>
<textarea rows="15" name="msg" cols="80" wrap="virtual"><% sysLogList(); %></textarea>

<p>
<input type="button" value="Refresh" name="refresh" onClick="javascript: window.location.reload()">
<input type="hidden" value="/syslog_server.asp" name="submit-url">
<input type="hidden" name="postSecurityFlag" value="">
<script>
	check_enable();
	scrollElementToEnd(this.formSysLog.msg);
</script>
</form>
</blockquote>
</body>
</html>


