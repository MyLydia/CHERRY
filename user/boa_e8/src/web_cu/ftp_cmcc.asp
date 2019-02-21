<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<!--系统默认模板-->
<HTML>
<HEAD>
<TITLE>日常应用</TITLE>
<META http-equiv=pragma content=no-cache>
<META http-equiv=cache-control content="no-cache, must-revalidate">
<META http-equiv=content-type content="text/html; charset=gbk">
<META http-equiv=content-script-type content=text/javascript>
<!--系统公共css-->
<STYLE type=text/css>
@import url(/style/default.css);
</STYLE>
<!--系统公共脚本-->
<SCRIPT language="javascript" src="common.js"></SCRIPT>
<SCRIPT language="javascript" type="text/javascript">

var cgi = new Object();
<% initPageStorage(); %>

/********************************************************************
**          on document load
********************************************************************/
function on_init()
{
	sji_docinit(document, cgi);
	with(form)
	{
		tdftpEnable.innerHTML = cgi.ftpEnable ? "启用" : "禁用";
	}
}

/********************************************************************
**          on document submit
********************************************************************/
function on_submit(act) 
{
	with ( document.forms[0] ) 
	{
		if(act == "rl") 
		{
			var loc = "ftp_cmcc.asp";
			var code = "window.location.href=\"" + loc + "\"";
			eval(code);
			return;
		}
		submit();
	}
}
</SCRIPT>
</HEAD>

<!-------------------------------------------------------------------------------------->
<!--主页代码-->
<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000" onLoad="on_init();">
	<blockquote>
		<DIV align="left" style="padding-left:20px; padding-top:5px">
			<form id="form" action=/boaform/admin/formStorage method=POST>
				<b>服务状态<br><br>
				<table border="0" cellpadding="3" cellspacing="0">
					<tr>
						<td>FTP服务器:</td>
						<td id="tdftpEnable"></td>
					</tr>
					<tr>
						<td>FTP Client: TBD</td>
					</tr>
				</table>
				<br>
				<input type="button" class="btnsaveup" onClick ="on_submit('rl')" value="刷新本页">
				<input type="hidden" name="submit-url" value="">
			</form>
		</DIV>
	</blockquote>
</body>
<%addHttpNoCache();%>
</html>
