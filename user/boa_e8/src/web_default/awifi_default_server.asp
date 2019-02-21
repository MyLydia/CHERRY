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
<%initAwifiDefaultServer();%>
	
function btnSave()
{
	with ( document.forms[0] ) {
		if (reg_server.value.length > 64) 
		{
			alert('注册服务器的URL (' + reg_server.value.length + ') 太长 [1-64].');
			return false;
		}
		if(!sji_checkhttpurl(reg_server.value))
		{
			alert("注册服务器的URL 是不合法的 URL!");
			return false;
		}
		if (auth_server.value.length > 64) 
		{
			alert('认证服务器的URL (' + auth_server.value.length + ') 太长 [1-64].');
			return false;
		}
		if(!sji_checkhttpurl(auth_server.value))
		{
			alert("认证服务器的URL 是不合法的 URL!");
			return false;
		}
		if (portal_server.value.length > 64) 
		{
			alert('Portal服务器的URL (' + auth_server.value.length + ') 太长 [1-64].');
			return false;
		}
		if(!sji_checkhttpurl(portal_server.value))
		{
			alert("Portal服务器的URL 是不合法的 URL!");
			return false;
		}
		if (reg_port.value == "")
		{
			reg_port.value = 80; //设置默认端口号为80
		}
		else if (!sji_checkdigitrange(reg_port.value, 1, 65535))
		{
			alert( "注册端口号必须是非负整数,且确保范围在1～65535之间");
			return;
		}
		if (auth_port.value == "")
		{
			auth_port.value = 80; //设置默认端口号为80
		}
		else if (!sji_checkdigitrange(auth_port.value, 1, 65535))
		{
			alert( "认证端口号必须是非负整数,且确保范围在1～65535之间");
			return;
		}
		if (portal_port.value == "")
		{
			portal_port.value = 80; //设置默认端口号为80
		}
		else if (!sji_checkdigitrange(portal_port.value, 1, 65535))
		{
			alert( "Portal端口号必须是非负整数,且确保范围在1～65535之间");
			return;
		}
	}
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	
	document.AwifiDefaultServer.submit();
}

function on_init()
{
	sji_docinit(document, cgi);
}

</script>
</head>
<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000" onLoad="on_init();">
<blockquote>
<form action="/boaform/admin/formAwifiDefaultServer" method="post" name="AwifiDefaultServer">
	<table class="text_location">
		<tr>
			<td>注册服务器</td>
			<td><input name="reg_server"  type="text"></td>
		</tr>
		<tr>
			<td>注册端口</td>
			<td><input name="reg_port" type="text"></td>
		</tr>
		<tr>
			<td>认证服务器</td>
			<td><input name="auth_server" type="text"></td>
		</tr>
		<tr>
			<td>认证端口</td>
			<td><input name="auth_port" type="text"></td>
		</tr>
		<tr>
			<td>Portal服务器</td>
			<td><input name="portal_server" type="text"></td>
		</tr>
		<tr>
			<td>Portal端口</td>
			<td><input name="portal_port"  type="text"></td>
		</tr>
		<tr>
			<td>
				<input name="savebtn" class="button" onclick="btnSave();" value="保存" type="button">
				<input type="hidden" name="submit-url" value="/awifi_default_server.asp">
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
