<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<!--ϵͳĬ��ģ��-->
<html>
<head>
<title>д��ȼ�����</title>
<meta http-equiv=pragma content=no-cache>
<meta http-equiv=cache-control content="no-cache, must-revalidate">
<meta http-equiv=content-type content="text/html; charset=gbk">
<meta http-equiv=content-script-type content=text/javascript>
<!--ϵͳ����css-->
<style type=text/css>
@import url(/style/default.css);
</style>
<!--ϵͳ�����ű�-->
<script language="javascript" src="common.js"></script>
<script type="text/javascript" src="share.js"></script>
<script language="javascript" type="text/javascript">

/********************************************************************
**          on document update
********************************************************************/
function on_updatectrl() 
{
	with (document.forms[0]) {
		if (syslogEnable[0].checked) {
			recordLevel.disabled = true;
		} else {
			recordLevel.disabled = false;
		}
	}
}
function on_change()
{
		if (document.forms[0].syslogEnable[1].checked) {
			alert("ע��:���ڿ�����־��������������");
		}
	on_updatectrl();
}
/********************************************************************
**          on document submit
*******************************************************************/
function on_submit()
{
	with (document.forms[0]) {
		submit();
	}
}
</script>
</head>

<!-------------------------------------------------------------------------------------->
<!--��ҳ����-->
<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000">
	<blockquote>
		<div align="left" style="padding-left:20px; padding-top:5px">
			<form id="form" action="/boaform/admin/formSysLogConfig" method="post">
				<hr align="left" class="sep" size="1" width="90%">
				<table border="0" cellpadding="0" cellspacing="0">
				   <tr>
					  <td width="80">��־:</td>
					  <td><input name="syslogEnable" type="radio" value="0" onChange="on_change();" <% checkWrite("log-cap0"); %>>����</td>
					  <td><input name="syslogEnable" type="radio" value="1" onChange="on_change();"<% checkWrite("log-cap1"); %>>����</td>
				   </tr>
				   <tr><td colspan="2">&nbsp;</td>
				   </tr>
				   <tr>
					  <td>��־�ȼ�:</td>
					  <td colspan="2">
				  		<select name="recordLevel" size="1" style="width:120px ">
						<% checkWrite("syslog-log"); %>
						</select>
					 </td>
				   </tr>
				</table>
				</div>
				<hr align="left" class="sep" size="1" width="90%">
				<button class="btnsaveup" onClick="on_submit()">ȷ��</button>
				<button class="BtnCnl" onClick="location.reload(true)">ȡ��</button>
				<input type="hidden" name="submit-url" value="/mgm_log_cfg_cmcc.asp">
<script>
	on_updatectrl();
</script>			</form>
		</div>
	</blockquote>
</body>
<%addHttpNoCache();%>
</html>
