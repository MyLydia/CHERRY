<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<html>
<head>
<title>�й�����</title>
<meta http-equiv=pragma content=no-cache>
<meta http-equiv=cache-control content="no-cache, must-revalidate">
<meta http-equiv=content-type content="text/html; charset=gbk">
<style type=text/css>
@import url(/style/default.css);
</style>
<script language="javascript" src="common.js"></script>
<script language="javascript" type="text/javascript">

var cgi = new Object();
<%initAwifiSiteServer();%>

function btnSave()
{
	with ( document.forms[0] ) {
		if (reg_server.value.length > 64) 
		{
			alert('ע���������URL (' + reg_server.value.length + ') ̫�� [1-64].');
			return false;
		}
		if(!sji_checkhttpurl(reg_server.value))
		{
			alert("ע���������URL �ǲ��Ϸ��� URL!");
			return false;
		}
		if (auth_server.value.length > 64) 
		{
			alert('��֤��������URL (' + auth_server.value.length + ') ̫�� [1-64].');
			return false;
		}
		if(!sji_checkhttpurl(auth_server.value))
		{
			alert("��֤��������URL �ǲ��Ϸ��� URL!");
			return false;
		}
		if (reg_port.value == "")
		{
			reg_port.value = 80; //����Ĭ�϶˿ں�Ϊ80
		}
		else if (!sji_checkdigitrange(reg_port.value, 1, 65535))
		{
			alert( "ע��˿ںű����ǷǸ�����,��ȷ����Χ��1��65535֮��");
			return;
		}
		if (auth_port.value == "")
		{
			auth_port.value = 80; //����Ĭ�϶˿ں�Ϊ80
		}
		else if (!sji_checkdigitrange(auth_port.value, 1, 65535))
		{
			alert( "��֤�˿ںű����ǷǸ�����,��ȷ����Χ��1��65535֮��");
			return;
		}
		
	}
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	document.AwifiSiteServer.submit();
}

function on_init()
{
	sji_docinit(document, cgi);
	document.AwifiSiteServer.reg_url.disabled=true;
	document.AwifiSiteServer.auth_url.disabled=true;
//	old_lan_ip = document.forms[0].uIp.value;
}

</script>
</head>
<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000" onLoad="on_init();">
<blockquote>
<form action="/boaform/admin/formAwifiSiteServer" method="post" name="AwifiSiteServer">
	<table class="text_location">
		<tr>
			<td>�汾��</td>
			<td><% getInfo("awifi-version"); %></td>
		</tr>
		<tr>
			<td>ע�������</td>
			<td><input name="reg_server"  type="text"></td>
		</tr>
		<tr>
			<td>ע��˿�</td>
			<td><input name="reg_port" type="text"></td>
		</tr>
		<tr>
			<td>ע��URL</td>
			<td><input name="reg_url" type="text"></td>
		</tr>
		<tr>
			<td>��֤������</td>
			<td><input name="auth_server" type="text"></td>
		</tr>
		<tr>
			<td>��֤�˿�</td>
			<td><input name="auth_port"type="text"></td>
		</tr>
		<tr>
			<td>��֤URL</td>
			<td><input name="auth_url" type="text" disabled></td>
		</tr>
		<tr>
			<td>
				<input name="savebtn" class="button" onclick="btnSave();" value="����" type="button">
				<input type="hidden" name="submit-url" value="/awifi_site_server.asp">
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
