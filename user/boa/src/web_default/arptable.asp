<html>
<! Copyright (c) Realtek Semiconductor Corp., 2006. All Rights Reserved. ->
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<title><% multilang(LANG_ARP_TABLE); %></title>
<link rel="stylesheet" type="text/css" href="common_style.css" />
<SCRIPT language="javascript" src="/common.js"></SCRIPT>
<SCRIPT>
function on_submit()
{
	document.forms[0].refresh.isclick = 1;
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	return true;
}
</SCRIPT>
</head>

<body>
<blockquote>
<h2 class="page_title"><% multilang(LANG_USER_LIST); %></h2>

<table>
  <tr><td><font size=2>
 <% multilang(LANG_PAGE_DESC_MAC_TABLE_INFO); %>
  </font></td></tr>
  <tr><td><hr size=1 noshade align=top></td></tr>
</table>


<form action=/boaform/formRefleshFdbTbl method=POST name="formFdbTbl">
<table>
<tr bgcolor=#7f7f7f> <th><% multilang(LANG_IP_ADDRESS); %></th>
<th><% multilang(LANG_MAC_ADDRESS); %></th>
<% ARPTableList(); %>
</table>

<input type="hidden" value="/arptable.asp" name="submit-url">
  <p><input type="submit" value="<% multilang(LANG_REFRESH); %>" name="refresh" onClick="return on_submit()">&nbsp;&nbsp;
  <input type="hidden" name="postSecurityFlag" value="">
</form>
</blockquote>
</body>

</html>
