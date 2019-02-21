<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<html>
<head>
<title>中国电信</title>
<meta http-equiv=pragma content=no-cache>
<meta http-equiv=cache-control content="no-cache, must-revalidate">
<meta http-equiv=content-type content="text/html; charset=gbk">
<style type=text/css>
@import url(/style/default.css);
</style>
<script language="javascript" src="common.js"></script>
<script language="javascript" type="text/javascript">

var cgi = new Object();
<%initAwifiUpdateCfg();%>
	
function btnSave()
{
	with ( document.forms[0] ) {
		if (update_url.value.length > 64) 
		{
			alert('升级请求服务器 (' + update_url.value.length + ') 太长 [1-64].');
			return false;
		}
		if(!sji_checkhttpurl(update_url.value))
		{
			alert("升级请求服务器 是不合法的 URL!");
			return false;
		}
		if (ver_server.value.length > 64) 
		{
			alert('升级请求服务器 (' + ver_server.value.length + ') 太长 [1-64].');
			return false;
		}
		if(!sji_checkhttpurl(ver_server.value))
		{
			alert("升级请求服务器 是不合法的 URL!");
			return false;
		}
	}
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);

	document.AwifiUpdateCfg.submit();
}

function on_init()
{
	sji_docinit(document, cgi);
}

</script>
</head>
<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000" onLoad="on_init();">
<blockquote>
<form action="/boaform/admin/formAwifiUpdateCfg" method="post" name="AwifiUpdateCfg">
	<table class="text_location">
		<tr>
			<td>version</td>
			<td><input name="version" value="<% getInfo("awifi-version"); %>" type="text" disabled></td>
		</tr>
		<tr>
			<td>设备型号</td>
			<td><input name="model" value="<% getInfo("devModel"); %>" type="text" disabled></td>
		</tr>
		<tr>
			<td>供应商</td>
			<td><input name="provider" value="<% getInfo("providerName"); %>" type="text" disabled></td>
		</tr>
		<tr>
			<td>升级请求服务器</td>
			<td><input name="update_url" value="<% getInfo("upgradeURL"); %>" type="text"></td>
		</tr>
		<tr>
			<td>key</td>
			<td><input name="key" value="<% getInfo("applyID"); %>" type="text"></td>
		</tr>
		<tr>
			<td>版本上报服务器</td>
			<td><input name="ver_server" value="<% getInfo("reportURL"); %>" type="text"></td>
		</tr>
		<tr>
			<td>城市编码</td>
			<td><input name="encode" value="<% getInfo("city"); %>" type="text"></td>
		</tr>
		<tr>
			<td>
				<input name="savebtn" class="button" onclick="btnSave();" value="保存" type="button">
				<input type="hidden" name="submit-url" value="/awifi_update_config.asp">
				<input type="hidden" name="postSecurityFlag" value="">
			</td>
			<td></td>
		</tr>

	</table>
</form>
</blockquote>
</body>
<%addHttpNoCache();%>
</html>
