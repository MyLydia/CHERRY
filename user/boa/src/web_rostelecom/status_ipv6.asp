<html>
<! Copyright (c) Realtek Semiconductor Corp., 2003. All Rights Reserved. ->
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<title>IPv6 <% multilang(LANG_STATUS); %></title>
<link rel="stylesheet" type="text/css" href="common_style.css"/>
<script type="text/javascript" src="share.js">
</script>
</head>
<body>
<blockquote>

<h2 class="page_title">IPv6 <% multilang(LANG_STATUS); %></h2>

<table>
<tr><td><font size=2>
 <% multilang(LANG_THIS_PAGE_SHOWS_THE_CURRENT_SYSTEM_STATUS_OF_IPV6); %>
</font></td></tr>

<tr><td><hr size=1 noshade align=top><br></td></tr>
</table>

<table width=600>
  <tr>
    <th colspan="2" bgcolor="#008000"><font color="#FFFFFF"><% multilang(LANG_LAN); %><% multilang(LANG_CONFIGURATION); %></font></th>
  </tr>
  <tr bgcolor="#EEEEEE">
    <th><% multilang(LANG_IPV6_ADDRESS); %></th>
    <td><% getInfo("ip6_global"); %></td>
  </tr>
  <tr bgcolor="#DDDDDD">
    <th><% multilang(LANG_IPV6_LINK_LOCAL_ADDRESS); %></th>
    <td><font size=2><% getInfo("ip6_ll"); %></td>
  </tr>
</table>
<br>
<table width=400>
  <tr>
    <td colspan="2" bgcolor="#008000"><font color="#FFFFFF"><% multilang(LANG_PREFIX_DELEGATION); %></font></td>
  </tr>
  <tr>
    <th><% multilang(LANG_PREFIX); %></th>
    <td><% checkWrite("prefix_delegation_info"); %></td>
  </tr>
</table>
<br>
<form action=/boaform/admin/formStatus_ipv6 method=POST name="status_ipv6">
<table width=600>
 <tr>
    <td colspan=6 bgcolor="#008000"><font color="#FFFFFF"><% multilang(LANG_WAN); %><% multilang(LANG_CONFIGURATION); %></font></td>
  </tr>
  <% wanip6ConfList(); %>
</table>
  <input type="hidden" value="/admin/status_ipv6.asp" name="submit-url">
  <input type="submit" value="<% multilang(LANG_REFRESH); %>" name="refresh">&nbsp;&nbsp;
</form>
</blockquote>
</body>
</html>
