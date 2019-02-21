<html>
<! Copyright (c) Realtek Semiconductor Corp., 2003. All Rights Reserved. ->
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<title>Samba<% multilang(LANG_CONFIGURATION); %></title>
<link rel="stylesheet" type="text/css" href="common_style.css" />
<script type="text/javascript" src="share.js">
</script>
<SCRIPT language="javascript" src="/common.js"></SCRIPT>
<script language="javascript">
var nbn = "<% getInfo("samba-netbios-name"); %>";
var ss = "<% getInfo("samba-server-string"); %>";

function changeSambaCap()
{
	with (document.formSamba) {
		if (sambaCap[0].checked) {
			/* Disable */
			netBIOSName.value = "";
			serverString.value = "";
			changeBlockState("conf", true);
		} else {
			/* Enable */
			netBIOSName.value = nbn;
			serverString.value = ss;
			changeBlockState("conf", false);
		}
	}
}

function on_submit()
{
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	return true;
}
</script>
</head>

<body onLoad="changeSambaCap();">
<blockquote>
<h2 class="page_title">Samba<% multilang(LANG_CONFIGURATION); %></h2>

<table>
	<tr><td><font size=2>
	<% multilang(LANG_THIS_PAGE_LET_USER_TO_CONFIG_SAMBA); %>
	</font></td></tr>
	<tr><td><hr size=1 noshade align=top></td></tr>
</table>

<form action=/boaform/formSamba method=post name="formSamba">
<table>
	<tr>
	<th>Samba&nbsp;:</th>
	<td>
		<input type="radio" value="0" name="sambaCap" onClick="changeSambaCap();" <% checkWrite("samba-cap0"); %>><% multilang(LANG_DISABLE); %>&nbsp;&nbsp;
		<input type="radio" value="1" name="sambaCap" onClick="changeSambaCap();" <% checkWrite("samba-cap1"); %>><% multilang(LANG_ENABLE); %>
	</td>
	</tr>
	<% checkWrite("smbSecurity"); %>
<tbody id="conf">
	<tr <% checkWrite("nmbd-cap"); %>>
	<th>NetBIOS <% multilang(LANG_NAME); %>&nbsp;:</th>
	<td><input type="text" name="netBIOSName" maxlength="15"><td>
	</tr>

	<tr>
	<th><% multilang(LANG_SERVER_STRING); %>&nbsp;:</th>
	<td><input type="text" name="serverString" maxlength="31"></td>
	</tr>
</tbody>
</table>
<br>
<input type="submit" value="<% multilang(LANG_APPLY_CHANGES); %>" onClick="return on_submit()">&nbsp;&nbsp;
<input type="hidden" value="/samba.asp" name="submit-url"> 
<input type="hidden" name="postSecurityFlag" value="">

</form>
</blockquote>
</body>
</html>
