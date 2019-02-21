<%SendWebHeadStr(); %>
<title><% multilang(LANG_SYSTEM_LOG); %></title>

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
<div class="intro_main ">
	<p class="intro_title">System Log</p>
</div>

<form action=/boaform/formSysLog method=POST name=formSysLog>
<div class="data_common data_common_notitle">
	<table>
		<tr>
			<th width=30%>System Log:</th>
			<td>
				<input type="radio" value="0" name="logcap" <% checkWrite("log-cap0"); %>>Disable&nbsp;&nbsp;
				<input type="radio" value="1" name="logcap" <% checkWrite("log-cap1"); %>>Enable
			</td>
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
	</table>
</div>

<div class="btn_ctl">
	<input class="link_bg" type="submit" value="Apply Changes" name="apply" onClick="return saveClick(this)">
</div>

<div class="data_common data_common_notitle">
	<table>
		<tr>
			<th width=30%>Save Log to File:</th>
			<td><input class="inner_btn" type="submit" value="Save..." name="save_log" onClick="return on_submit(this)"></td>
		</tr>
		<tr>
			<th>Clear Log:</th>
			<td><input class="inner_btn" type="submit" value="Reset" name="clear_log" onClick="return on_submit(this)"></td>
		</tr>
	</table>
</div>
<textarea rows="15" name="msg" cols="80" wrap="virtual" width=100%><% sysLogList(); %></textarea>

<div class="btn_ctl">
	<input class="link_bg" type="button" value="Refresh" name="refresh" onClick="javascript: window.location.reload()">
	<input type="hidden" value="/syslog_server.asp" name="submit-url">
	<input type="hidden" name="postSecurityFlag" value="">
</div>
<script>
	check_enable();
	scrollElementToEnd(this.formSysLog.msg);
</script>
</form>
</body>
</html>


