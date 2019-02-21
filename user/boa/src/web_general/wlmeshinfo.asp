<%SendWebHeadStr(); %>
<title><% multilang(LANG_WLAN_MESH_ACCESS_CONTROL); %></title>

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

<body>
<div class="intro_main ">
	<p class="intro_title">Wireless Mesh Network Information</p>
	<p class="intro_content"> These information is only for more technically advanced users who have a sufficient knowledge about wireless mesh network</p>
</div>
<form action=/boaform/admin/formWirelessTbl method=POST name="formWirelessTbl">
<div class="data_common data_common_notitle">
	<table>
	    <tr>
			<th>Root:</th>
			<td>
		    	<input type="text" name="rootmac" size="15" maxlength="13" value=" <% wlMeshRootInfo();  %>" disabled="true">
		    </td>
		</tr>
	</table>
</div>

<div class="column">
	<div class="column_title">
		<div class="column_title_left"></div>
			<p>Neighbor Table</p>
		<div class="column_title_right"></div>
	</div>
	<div class="data_common data_vertical">
		<table>
			<% wlMeshNeighborTable(); %>
		</table>
	</div>
</div>

<div class="column">
	<div class="column_title">
		<div class="column_title_left"></div>
			<p>Routing Table</p>
		<div class="column_title_right"></div>
	</div>
	<div class="data_common data_vertical">
		<table>
			<% wlMeshRoutingTable(); %>
		</table>
	</div>
</div>

<div class="column">
	<div class="column_title">
		<div class="column_title_left"></div>
			<p>Portal Table</p>
		<div class="column_title_right"></div>
	</div>
	<div class="data_common data_vertical">
		<table>
			<% wlMeshPortalTable(); %>
		</table>
	</div>
</div>

<div class="column">
	<div class="column_title">
		<div class="column_title_left"></div>
			<p>Wireless Station List</p>
		<div class="column_title_right"></div>
	</div>
	<div class="data_common data_vertical">
		<table>
			<tr>
				<th align=center width="20%">MAC Address</b></th>
				<th align=center width="15%">Tx Packet</th>
				<th align=center width="15%">Rx Packet</th>
				<th align=center width="10%">Tx Rate (Mbps)</th>
				<th align=center width="10%">Power Saving</th>
				<th align=center width="15%">Expired Time (s)</th>
			</tr>
			<% wirelessClientList(); %>
		</table>
	</div>
</div>

<div class="column">
	<div class="column_title">
		<div class="column_title_left"></div>
			<p>Proxy Table</p>
		<div class="column_title_right"></div>
	</div>
	<div class="data_common data_vertical">
		<table>
			<% wlMeshProxyTable(); %>
		</table>
	</div>
</div>

<div class="btn_ctl">
	<input type="hidden" name="submit-url" value="/wlmeshinfo.asp">
	<input type="hidden" name="wlan_idx" value=<% checkWrite("wlan_idx"); %>>
	<input class="link_bg" type="submit"  value="Refresh" onClick="return on_submit()">
	<input type="hidden" name="postSecurityFlag" value="">
</div>
</form>  
</body>
</html>
