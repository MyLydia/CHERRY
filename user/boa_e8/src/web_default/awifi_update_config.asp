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
<%initAwifiUpdateCfg();%>
	
function btnSave()
{
	with ( document.forms[0] ) {
		if (update_url.value.length > 64) 
		{
			alert('������������� (' + update_url.value.length + ') ̫�� [1-64].');
			return false;
		}
		if(!sji_checkhttpurl(update_url.value))
		{
			alert("������������� �ǲ��Ϸ��� URL!");
			return false;
		}
		if (ver_server.value.length > 64) 
		{
			alert('������������� (' + ver_server.value.length + ') ̫�� [1-64].');
			return false;
		}
		if(!sji_checkhttpurl(ver_server.value))
		{
			alert("������������� �ǲ��Ϸ��� URL!");
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
			<td>�豸�ͺ�</td>
			<td><input name="model" value="<% getInfo("devModel"); %>" type="text" disabled></td>
		</tr>
		<tr>
			<td>��Ӧ��</td>
			<td><input name="provider" value="<% getInfo("providerName"); %>" type="text" disabled></td>
		</tr>
		<tr>
			<td>�������������</td>
			<td><input name="update_url" value="<% getInfo("upgradeURL"); %>" type="text"></td>
		</tr>
		<tr>
			<td>key</td>
			<td><input name="key" value="<% getInfo("applyID"); %>" type="text"></td>
		</tr>
		<tr>
			<td>�汾�ϱ�������</td>
			<td><input name="ver_server" value="<% getInfo("reportURL"); %>" type="text"></td>
		</tr>
		<tr>
			<td>���б���</td>
			<td><input name="encode" value="<% getInfo("city"); %>" type="text"></td>
		</tr>
		<tr>
			<td>
				<input name="savebtn" class="button" onclick="btnSave();" value="����" type="button">
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
