<!-- add by liuxiao 2008-01-16 -->
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<html>
<head>
<title>手动上报 Inform</title>
<meta http-equiv=pragma content=no-cache>
<meta http-equiv=cache-control content="no-cache, must-revalidate">
<meta http-equiv=content-type content="text/html; charset=gbk">
<style type=text/css>
@import url(/style/default.css);
</style>
<script language="javascript" src="common.js"></script>
<script language="javascript">


function update_status()
{
	if(document.getElementById("result").innerHTML == '<B><font color="#FF0000" size="-1">正在手动上报,请稍等...</font></B>')
		setTimeout('window.location.reload(true);', 3000);
	else if (document.getElementById("result").innerHTML == "Inform手动上报测试结果:未上报（网关正在启动）")
		setTimeout('window.location.reload(true);', 15000);
	else
		setTimeout('window.location.reload(true);', 8000);
}

</script>
</head>
<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000" onload="update_status();">
	<form id="form" action="/boaform/admin/formTr069Diagnose" method="post">
	<blockquote>
		<div align="left" style="padding-left:20px;"><br>
			<div align="left"><b>Inform手动上报</b></div>
			<br><input class="btnsaveup" type="submit" class="button" value="手动上报">
			<br>
				<tr>
					<br>
					<div id="result"><% getInfo("tr069Inform"); %></div>
				</tr>
			<br>
			<input type="hidden" name="submit-url" value="/diagnose_tr069_admin_cmcc_update.asp">
		</div>
	</blockquote>
	</form>
</body>
<%addHttpNoCache();%>
</html>
