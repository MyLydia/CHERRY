<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<!--系统默认模板-->
<html>
<head>
<title>系统访问日志</title>
<meta http-equiv=pragma content=no-cache>
<meta http-equiv=cache-control content="no-cache, must-revalidate">
<meta http-equiv=content-type content="text/html; charset=gbk">
<meta http-equiv=content-script-type content=text/javascript>
<!--系统公共css-->
<style type=text/css>
@import url(/style/default.css);
</style>
<!--系统公共脚本-->
<script language="javascript" src="common.js"></script>
<script language="javascript" type="text/javascript">

var rcs = new Array();
<% sysLogList(); %>
<% checkWrite("log-cap"); %>
/*
cgi.mf = "ASB";
cgi.pc = "V1.0";
cgi.sn = "03100200000100100000007404010203";
cgi.ip = "192.168.2.1";
cgi.hv = "V1.0";
cgi.sv = "RG100A_V1.0";
*/
/*
rcs.push(new Array("1900-01-07 01:26:37", "Informational", "kernel: Freeing unused kernel memory: 144k freed"));
rcs.push(new Array("1900-01-07 01:26:37", "Warning", "kernel: EHCI: port status=0x00001000"));
*/

/********************************************************************
**          on document load
********************************************************************/
function on_init()
{
	with (document.forms[0]) {
		logDisplay.innerHTML = "";
		if(!syslog){
			dispLevel.disabled = true;
			return;
		}
		for (var i = 0; i < rcs.length; i++) 
		logDisplay.innerHTML += rcs[i][0] + "&nbsp; [" + rcs[i][1] + "] &nbsp;" + rcs[i][2] + "\n";
	}
}
function on_submit(act)
{
	with (document.forms[0]) {
		action.value = act;
		submit();
	}
}
</script>
</head>

<!-------------------------------------------------------------------------------------->
<!--主页代码-->
<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000" onLoad="on_init();">
	<div align="left" style="padding-left:20px; padding-top:10px">
			<form id="form" action="/boaform/admin/formSysLog" method="post">
			<table cellspacing="0" cellpadding="2" border="0">
			<tbody>
				<tr>
					<td width="130">显示级别:</td>
					<td>
				  		<select name="dispLevel" size="1" style="width:120px " onchange="on_submit('dispLevel')">
						<% checkWrite("syslog-display"); %>
						</select>
					</td>
				</tr>
			<tr><td colspan="2">&nbsp;</td>
			</tr>
			<tr>
				<td colspan="2"><textarea id="logDisplay" name="logDisplay" style="WIDTH:453px;HEIGHT:521px;font:inherit;" wrap="hard" edit="OFF" readonly="readonly" wrap="OFF"></textarea>
				</td>
		  	</tr>
			</table>
			<div style="padding-left:280px">
				<Button class="btnsaveup" name="saverec" onClick="on_submit('saveLog');">保存日志 </button>
				<input type="button" class="BtnDel" name="clrrec" onClick="on_submit('clr');" value="清除日志">
			</div>
				<input type="hidden" id="action" name="action" value="none">
				<input type="hidden" name="submit-url" value="/mgm_log_view_cmcc.asp">
		</form>
	</div>
</body>
<%addHttpNoCache();%>
</html>
