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
<%initAwifiSiteServerConfig();%>

function btnSave()
{
	with ( document.forms[0] ) {
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
	}
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	document.AwifiSiteServer.submit();
}

function on_init()
{
	sji_docinit(document, cgi);
}

</script>
</head>
<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000" onLoad="on_init();">
<blockquote>
<form action="/boaform/admin/formAwifiSiteServerConfig" method="post" name="AwifiSiteServer">
	<table class="text_location">
		<tr>
			<td>认证服务器</td>
			<td><input name="auth_server" type="text"></td>
		</tr>
		<tr>
			<td>
				<input name="savebtn" class="button" onclick="btnSave();" value="保存" type="button">
				<input type="hidden" name="submit-url" value="/awifi_server_config.asp">
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
