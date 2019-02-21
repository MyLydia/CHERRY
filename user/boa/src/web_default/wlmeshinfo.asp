<html>
<! Copyright (c) Realtek Semiconductor Corp., 2003. All Rights Reserved. ->
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<title><% multilang(LANG_WLAN_MESH_ACCESS_CONTROL); %></title>
<link rel="stylesheet" type="text/css" href="common_style.css" />
<SCRIPT language="javascript" src="/common.js"></SCRIPT>
<script type="text/javascript" src="share.js">
</script>
<script>
function showProxiedMAC()
{
	openWindow('/wlmeshproxy.htm', 'formMeshProxyTbl',620,340 );
}

function on_submit()
{
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	return true;
}
</script>
</head>
<blockquote>
<h2 class="page_title">Wireless Mesh Network Information</h2>

<body>

  <form action=/boaform/admin/formWirelessTbl method=POST name="formWirelessTbl">
	<table border=0 width="540" cellspacing=4 cellpadding=0>
		<tr><font size=2>
			These information is only for more technically advanced users who have a sufficient knowledge about wireless mesh network
        	</font></tr>
		<tr><hr size=1 noshade align=top></tr>
	    <tr>
    	<font size=2><b>Root :&nbsp;&nbsp;&nbsp;&nbsp;</b>
	    <input type="text" name="rootmac" size="15" maxlength="13" value=" <% wlMeshRootInfo();  %>" disabled="true">
		</tr>
	</table>
	<br>
	<table border="0" width=540>
	<tr><font size=2><b>Neighbor Table</b></font></tr>
	<% wlMeshNeighborTable(); %>
	</table>
	<br>
	  <table border="0" width=540>
	  <tr><font size=2><b>Routing Table</b></font></tr>
	  <% wlMeshRoutingTable(); %>
	  </table>
	  <br>
  	  <table border="0" width=540>
	  <tr><font size=2><b>Portal Table</b></font></tr>
	  <% wlMeshPortalTable(); %>
	  </table>
	  <br><br>

	<table border="0" width=540>
	<tr><font size=2><b>Wireless Station List</b></font></tr>
	<tr class="tbl_head"><td align=center width="20%"><font size=2><b>MAC Address</b></td>
	<td align=center width="15%"><font size=2><b>Tx Packet</b></td>
	<td align=center width="15%"><font size=2><b>Rx Packet</b></td>
	<td align=center width="10%"><font size=2><b>Tx Rate (Mbps)</b></td>
	<td align=center width="10%"><font size=2><b>Power Saving</b></td>
	<td align=center width="15%"><font size=2><b>Expired Time (s)</b></td></tr>
	<% wirelessClientList(); %>
	</table>
	<br><br>

	  <table border="0" width=240>
	  <tr><font size=2><b>Proxy Table</b></font></tr>
	  <% wlMeshProxyTable(); %>
	  </table>
	<br><br>
	<input type="hidden" name="submit-url" value="/wlmeshinfo.asp">
	<input type="hidden" name="wlan_idx" value=<% checkWrite("wlan_idx"); %>>
	<input type="submit"  value="Refresh" onClick="return on_submit()">
	<input type="hidden" name="postSecurityFlag" value="">
	<br><br>
  </form>  
</body>
</blockquote>
</html>