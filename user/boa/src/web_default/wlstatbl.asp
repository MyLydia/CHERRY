<html>
<! Copyright (c) Realtek Semiconductor Corp., 2003. All Rights Reserved. ->
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<title><% multilang(LANG_ACTIVE_WLAN_CLIENTS); %></title>
<link rel="stylesheet" type="text/css" href="common_style.css" />
<SCRIPT language="javascript" src="/common.js"></SCRIPT>
<SCRIPT>
function on_submit()
{
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	return true;
}
</SCRIPT>
</head>

<body>
<blockquote>
<h2 class="page_title"><% multilang(LANG_ACTIVE_WLAN_CLIENTS); %></h2>


<table>
  <tr><td><font size=2>
 <% multilang(LANG_THIS_TABLE_SHOWS_THE_MAC_ADDRESS); %>
  </font></td></tr>
  <tr><td><hr size=1 noshade align=top></td></tr>
</table>
<form action=/boaform/admin/formWirelessTbl method=POST name="formWirelessTbl">
<table>
<tr bgcolor=#7f7f7f><th><% multilang(LANG_MAC_ADDRESS); %></th>
<td width="15%" class="table_item"><% multilang(LANG_TX_PACKETS); %></td>
<td width="15%" class="table_item"><% multilang(LANG_RX_PACKETS); %></td>
<td width="15%" class="table_item"><% multilang(LANG_TX_RATE_MBPS); %></td>
<td width="15%" class="table_item"><b><% multilang(LANG_POWER_SAVING); %></td>
<td width="15%" class="table_item"><b><% multilang(LANG_EXPIRED_TIME_SEC); %></td></tr>
<% wirelessClientList(); %>
</table>
<input type="hidden" name="wlan_idx" value=<% checkWrite("wlan_idx"); %>>
<input type="hidden" value="/admin/wlstatbl.asp" name="submit-url">
  <p><input type="submit" value="Refresh" onClick="return on_submit()">&nbsp;&nbsp;
  <input type="button" value=" Close " name="close" onClick="javascript: window.close();"></p>
  <input type="hidden" name="postSecurityFlag" value="">
</form>
</blockquote>
</body>

</html>
