<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<html>
<head>
<title>智能网关连接状态</title>
<meta http-equiv=pragma content=no-cache>
<meta http-equiv=cache-control content="no-cache, must-revalidate">
<meta http-equiv=content-type content="text/html; charset=utf-8">
<!--<meta http-equiv="refresh" content="5">-->
<meta http-equiv=content-script-type content=text/javascript>
<style type=text/css>
@import url(/style/default.css);
</style>
<script language="javascript" src="common.js"></script>
<script language="javascript" type="text/javascript">
var platform = new Array();
with(platform){<% listPlatformService(); %>}

function on_init()
{
	if (lstrc.rows) {
		while (lstrc.rows.length > 1)
			lstrc.deleteRow(1);
	}
	for (var i = 0; i < platform.length; i++) {
		var row = lstrc.insertRow(i + 1);

		row.nowrap = true;
		row.vAlign = "top";

		var cell = row.insertCell(0);
		cell.innerHTML = platform[i].name;
		cell = row.insertCell(1);
		cell.innerHTML = platform[i]["Server"];
		cell = row.insertCell(2);
		cell.innerHTML = platform[i]["Status"];
	}
}


</script>
</head>
<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000" onLoad="on_init();">
	<blockquote>
		<div align="left" style="padding-left:20px;"><br>
			<div align="left"><b>智能网关及应用管理平台的连接状态</b></div>
			<br>
			<table class="flat" id="lstrc" border="1" cellpadding="1" cellspacing="1">
			<tr>
			<td class="hdb" width="150px;">平台名称</td>
			<td class="hdb" width="150px;">平台地址</td>
			<td class="hdb" width="150px;">平台状态</td>
			</tr>
			</table>
			
		</div>
	</blockquote>
</body>
<%addHttpNoCache();%>
</html>

