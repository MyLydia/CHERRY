<html>
<! Copyright (c) Realtek Semiconductor Corp., 2003. All Rights Reserved. ->
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<title>Ping <% multilang(LANG_DIAGNOSTICS); %></title>
<link rel="stylesheet" type="text/css" href="common_style.css" />
<script type="text/javascript" src="share.js">
</script>
<SCRIPT language="javascript" src="/common.js"></SCRIPT>
<SCRIPT>
function goClick()
{
	if (!checkHostIP(document.ping.pingAddr, 1))
		return false;
/*	if (document.ping.pingAddr.value=="") {
		alert("Enter host address !");
		document.ping.pingAddr.focus();
		return false;
	}
	
	return true;*/
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
}
</SCRIPT>
</head>

<body>
<blockquote>
<h2 class="page_title">Ping <% multilang(LANG_DIAGNOSTICS); %></h2>

<form action=/boaform/formPing method=POST name="ping">
<table>
  <tr><td><font size=2>
    <% multilang(LANG_PAGE_DESC_ICMP_DIAGNOSTIC); %>
  </font></td></tr>
  <tr><td><hr size=1 noshade align=top></td></tr>
</table>
<table>

  <tr>
      <th><% multilang(LANG_HOST_ADDRESS); %>: </th>
      <td><input type="text" name="pingAddr" size="15" maxlength="30"></td>
  </tr>

</table>
  <br>
      <input type="submit" value=" <% multilang(LANG_GO); %>" onClick="return goClick()">
      <input type="hidden" value="/ping.asp" name="submit-url">
      <input type="hidden" name="postSecurityFlag" value="">
 </form>
</blockquote>
</body>

</html>
