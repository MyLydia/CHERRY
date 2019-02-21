<%SendWebHeadStr(); %>
<title><% multilang(LANG_ACTIVE_WLAN_CLIENTS); %></title>
<link rel="stylesheet" href="admin/content.css">
<SCRIPT>
function on_submit()
{
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	return true;
}
</SCRIPT>
</head>

<body>
<div class="intro_main ">
	<p class="intro_title"><% multilang(LANG_ACTIVE_WLAN_CLIENTS); %></p>
	<p class="intro_content"><% multilang(LANG_THIS_TABLE_SHOWS_THE_MAC_ADDRESS); %></p>
</div>

<form action=/boaform/admin/formWirelessTbl method=POST name="formWirelessTbl">
<div class="data_common data_vertical">
	<table>
		<tr><th width="25%"><% multilang(LANG_MAC_ADDRESS); %></th>
			<th width="15%"><% multilang(LANG_TX_PACKETS); %></th>
			<th width="15%"><% multilang(LANG_RX_PACKETS); %></th>
			<th width="15%"><% multilang(LANG_TX_RATE_MBPS); %></th>
			<th width="15%"><% multilang(LANG_POWER_SAVING); %></th>
			<th width="15%"><% multilang(LANG_EXPIRED_TIME_SEC); %></th>
		</tr>
		<% wirelessClientList(); %>
	</table>
</div>
<div class="btn_ctl">
	<input type="hidden" name="wlan_idx" value=<% checkWrite("wlan_idx"); %>>
	<input type="hidden" value="/admin/wlstatbl.asp" name="submit-url">
	<input type="submit" value="Refresh" onClick="return on_submit()" class="link_bg">&nbsp;&nbsp;
	<input type="button" value=" Close " name="close" onClick="javascript: window.close();" class="link_bg">
	<input type="hidden" name="postSecurityFlag" value="">
</div>
</form>
<br><br>
</body>
</html>
