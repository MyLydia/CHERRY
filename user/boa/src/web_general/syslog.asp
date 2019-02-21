<%SendWebHeadStr(); %>
<title><% multilang(LANG_SYSTEM_LOG); %></title>

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

function saveClick(obj)
{
	<% RemoteSyslog("check-ip"); %>
//	if (document.forms[0].logAddr.disabled == false && !checkIP(document.formSysLog.logAddr))
//		return false;
//	alert("Please commit and reboot this system for take effect the System log!");
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

</script>
</head>

<body>
<div class="intro_main ">
	<p class="intro_title"><% multilang(LANG_SYSTEM_LOG); %></p>
</div>

<form action=/boaform/formSysLog method=POST name=formSysLog>
<div class="data_common data_common_notitle">
	<table>
		<tr>
			<th width=30%><% multilang(LANG_SYSTEM_LOG); %>:&nbsp;</th>
			<td>
				<input type="radio" value="0" name="logcap" onClick='changelogstatus()' <% checkWrite("log-cap0"); %>><% multilang(LANG_DISABLE); %>&nbsp;&nbsp;
				<input type="radio" value="1" name="logcap" onClick='changelogstatus()' <% checkWrite("log-cap1"); %>><% multilang(LANG_ENABLE); %>
			</td>
		</tr>    
		<% ShowPPPSyslog("syslogppp"); %>		
		<TBODY id='sysgroup'>
			<tr>
				<th><% multilang(LANG_LOG_LEVEL); %>:&nbsp;</th>
				<td><select name='levelLog' size="1">
					<% checkWrite("syslog-log"); %>
				</select></td>
			</tr>
			<tr>
				<th><% multilang(LANG_DISPLAY_LEVEL); %>:&nbsp;</th>
				<td ><select name='levelDisplay' size="1">
					<% checkWrite("syslog-display"); %>
				</select></td>
			</tr>
			<% RemoteSyslog("syslog-mode"); %>
			<tbody id='srvInfo'>
				<% RemoteSyslog("server-info"); %>
			</tbody>
		</TBODY>
	</table>
</div>

<div class="btn_ctl">
	<input class="link_bg" type="submit" value="<% multilang(LANG_APPLY_CHANGES); %>" name="apply" onClick="return saveClick(this)">
</div>

<div class="data_common data_common_notitle">
	<table>
		<tr>
			<th width=30%><% multilang(LANG_SAVE_LOG_TO_FILE); %>:</th>
			<td><input class="inner_btn" type="submit" value="<% multilang(LANG_SAVE); %>..." name="save_log" onClick="return on_submit(this)"></td>
		</tr>
		<tr>
			<th><% multilang(LANG_CLEAR_LOG); %>:</th>
			<td><input class="inner_btn" type="submit" value="<% multilang(LANG_RESET); %>" name="clear_log" onClick="return on_submit(this)"></td>
		</tr>
	</table>
</div>


<div class="column">
	<div class="column_title">
		<div class="column_title_left"></div>
			<p><% multilang(LANG_SYSTEM_LOG); %></p>
		<div class="column_title_right"></div>
	</div>
	<div class="data_common">
		<table>
			<% sysLogList(); %>
		</table>
	</div>
</div>

<div class="btn_ctl">
	<input class="link_bg" type="button" value="Refresh" name="refresh" onClick="javascript: window.location.reload()">
	<input type="hidden" value="/syslog.asp" name="submit-url">
	<input type="hidden" name="postSecurityFlag" value="">
</div>
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


