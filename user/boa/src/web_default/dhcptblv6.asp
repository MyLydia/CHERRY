<html>
<! Copyright (c) Realtek Semiconductor Corp., 2003. All Rights Reserved. ->
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<title><% multilang(LANG_ACTIVE_DHCPV6_CLIENTS); %></title>
<link rel="stylesheet" type="text/css" href="common_style.css" />
</head>

<body>
<blockquote>
<h2 class="page_title"><% multilang(LANG_ACTIVE_DHCPV6_CLIENTS); %></h2>

<table>
  <tr><td><font size=2>
  <% multilang(LANG_THIS_TABLE_SHOWS_THE_ASSIGNED_IP_ADDRESS_DUID_AND_TIME_EXPIRED_FOR_EACH_DHCP_LEASED_CLIENT); %>
  </font></td></tr>
  <tr><td><hr size=1 noshade align=top></td></tr>
</table>


<table border='1'>
<tr bgcolor=#7f7f7f> <th><% multilang(LANG_IP_ADDRESS); %></th>
<th><% multilang(LANG_DUID); %></th>
<th><% multilang(LANG_EXPIRED_TIME_SEC); %></th></tr>
<% dhcpClientListv6(); %>
</table>

<p>
<input type="button" value="<% multilang(LANG_REFRESH); %>" name="refresh" onClick="javascript: location.reload();">&nbsp;&nbsp;
<input type="button" value="<% multilang(LANG_CLOSE); %>" name="close" onClick="javascript: window.close();">
</p>
</blockquote>
</body>

</html>
