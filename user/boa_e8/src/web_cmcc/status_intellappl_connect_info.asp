<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<html>
<head>
<title>智能网关连接状态</title>
<meta http-equiv=pragma content=no-cache>
<meta http-equiv=cache-control content="no-cache, must-revalidate">
<meta http-equiv=content-type content="text/html; charset=gbk">
<meta http-equiv="refresh" content="5">
<meta http-equiv=content-script-type content=text/javascript>
<style type=text/css>
@import url(/style/default.css);
</style>
<script language="javascript" src="common.js"></script>
</head>
<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000">
	<blockquote>
		<div align="left" style="padding-left:20px;"><br>
			<div align="left"><b>智能网关及应用管理平台的连接状态</b></div>
			<br>
			<table class="flat" border="1" cellpadding="1" cellspacing="1">
				<tr>
					<td class="hdb" width="150px;">分发平台连接情况</td>
					<td width="180px;"><% checkWrite("platform_dist_status");%></td>
				</tr>
				<tr>
					<td class="hdb" width="150px;">运营平台连接情况</td>
					<td  width="180px;"><% checkWrite("platform_oper_status");%></td>
				</tr>
				<tr>
					<td class="hdb" width="150px;">插件中心连接情况</td>
					<td width="180px;"><% checkWrite("platform_plugin_status");%></td>
				</tr>
			</table>
			
		</div>
	</blockquote>
</body>
<%addHttpNoCache();%>
</html>
