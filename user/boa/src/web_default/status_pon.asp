<html>
<! Copyright (c) Realtek Semiconductor Corp., 2003. All Rights Reserved. ->
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<title>PON <% multilang(LANG_STATUS); %></title>
<link rel="stylesheet" type="text/css" href="common_style.css"/>
<SCRIPT language="javascript" src="/common.js"></SCRIPT>
<script type="text/javascript" src="share.js"></script>
<script>
function on_submit()
{
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	return true;
}
</script>
</head>
<body>
<blockquote>

<h2 class="page_title">PON <% multilang(LANG_STATUS); %></h2>

<table>
<tr><td><font size=2>
 <% multilang(LANG_PAGE_DESC_PON_STATUS); %>
</font></td></tr>

<tr><td><hr size=1 noshade align=top><br></td></tr>
</table>

<table width=400>
  <tr>
    <td colspan="2" bgcolor="#008000"><font color="#FFFFFF"><% multilang(LANG_PON); %><% multilang(LANG_STATUS_1); %></font></td>
  </tr>
  <tr bgcolor="#DDDDDD">
    <th><% multilang(LANG_VENDOR_NAME); %></th>
    <td><% ponGetStatus("vendor-name"); %></td>
  </tr>
  <tr bgcolor="#DDDDDD">
    <th><% multilang(LANG_PART_NUMBER); %></th>
    <td><% ponGetStatus("part-number"); %></td>
  </tr>
  <tr bgcolor="#DDDDDD">
    <th><% multilang(LANG_TEMPERATURE); %></th>
    <td><% ponGetStatus("temperature"); %></td>
  </tr>
  <tr bgcolor="#DDDDDD">
    <th><% multilang(LANG_VOLTAGE); %></th>
    <td><% ponGetStatus("voltage"); %></td>
  </tr>
  <tr bgcolor="#DDDDDD">
    <th><% multilang(LANG_TX_POWER); %></th>
    <td><% ponGetStatus("tx-power"); %></td>
  </tr>
  <tr bgcolor="#DDDDDD">
    <th><% multilang(LANG_RX_POWER); %></th>
    <td><% ponGetStatus("rx-power"); %></td>
  </tr>
  <tr bgcolor="#DDDDDD">
    <th><% multilang(LANG_BIAS_CURRENT); %></th>
    <td><% ponGetStatus("bias-current"); %></td>
  </tr>
</table>
<br>
<table width=400>
  <% showgpon_status(); %> 
</table>
<table width=400>
  <% showepon_LLID_status(); %> 
</table>
<form action=/boaform/admin/formStatus_pon method=POST name="status_pon">
  <input type="hidden" value="/status_pon.asp" name="submit-url">
  <input type="submit" value="<% multilang(LANG_REFRESH); %>" onClick="return on_submit()">&nbsp;&nbsp;
  <input type="hidden" name="postSecurityFlag" value="">
</form>
</blockquote>
</body>
</html>
