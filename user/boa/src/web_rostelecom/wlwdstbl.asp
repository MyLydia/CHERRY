<html>
<! Copyright (c) Realtek Semiconductor Corp., 2003. All Rights Reserved. ->
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<title>WDS AP <% multilang(LANG_TABLE); %></title>
<link rel="stylesheet" type="text/css" href="common_style.css" />
</head>

<body>
<blockquote>
<h2 class="page_title">WDS AP <% multilang(LANG_TABLE); %></h2>


<table>
  <tr><td><font size=2>
 <% multilang(LANG_THIS_TABLE_SHOWS_THE_MAC_ADDRESS_TRANSMISSION_RECEPTION_PACKET_COUNTERS_AND_STATE_INFORMATION_FOR_EACH_CONFIGURED_WDS_AP); %>
  </font></td></tr>
  <tr><td><hr size=1 noshade align=top></td></tr>
</table>
<form action=/boaform/formWirelessTbl method=POST name="formWirelessTbl">
<table>
<tr bgcolor=#7f7f7f><th><% multilang(LANG_MAC_ADDRESS); %></th>
<td width="15%" class="table_item"><% multilang(LANG_TX_PACKETS); %></td>
<td width="15%" class="table_item"><% multilang(LANG_TX_ERRORS); %></td>
<td width="15%" class="table_item"><% multilang(LANG_RX_PACKETS); %></td>
<td width="25%" class="table_item"><% multilang(LANG_TX_RATE_MBPS); %></td></tr>
<% wdsList(); %>
</table>

<input type="hidden" name="wlan_idx" value=<% checkWrite("wlan_idx"); %>>
<input type="hidden" value="/wlwdstbl.asp" name="submit-url">
  <p><input type="submit" value="<% multilang(LANG_REFRESH); %>" name="refresh">&nbsp;&nbsp;
  <input type="button" value="<% multilang(LANG_CLOSE); %>" name="close" onClick="javascript: window.close();"></p>
</form>
</blockquote>
</body>

</html>
