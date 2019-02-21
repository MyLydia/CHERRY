<html>
<! Copyright (c) Realtek Semiconductor Corp., 2006. All Rights Reserved. ->
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<title><% multilang(LANG_LAN_DEVICE_TABLE); %></title>
<link rel="stylesheet" type="text/css" href="common_style.css" />
</head>

<body>
<blockquote>
<h2 class="page_title"><% multilang(LANG_LAN_USER_LIST); %></h2>

<table border=0 width="480" cellspacing=0 cellpadding=0>
  <tr><td><font size=2>
 <% multilang(LANG_PAGE_DEVICE_TABLE_INFO); %>
  </font></td></tr>
  <tr><td><hr size=1 noshade align=top></td></tr>
</table>


<form action=/boaform/formRefleshLanUserTbl method=POST name="formLANUserTbl">
<table>
<tr bgcolor=#7f7f7f> <td width="20%" class="table_item"><% multilang(LANG_IP_ADDRESS); %></td>
<td width="20%" class="table_item"><% multilang(LANG_MAC_ADDRESS); %></td>
<td width="20%" class="table_item"><% multilang(LANG_HOSTNAME); %></td>
<td width="20%" class="table_item"><% multilang(LANG_INTERFACE); %></td>
<% LanUserTableList(); %>
</table>

<input type="hidden" value="/landevice.asp" name="submit-url">
  <p><input type="submit" value="<% multilang(LANG_REFRESH); %>" name="refresh">&nbsp;&nbsp;
</form>
</blockquote>
</body>

</html>
