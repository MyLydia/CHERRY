<%SendWebHeadStr(); %>
<title><% multilang(LANG_ACTIVE_DHCPV6_CLIENTS); %></title>
</head>

<body>
<div class="intro_main ">
	<p class="intro_title"><% multilang(LANG_ACTIVE_DHCPV6_CLIENTS); %></p>
	<p class="intro_content"><% multilang(LANG_THIS_TABLE_SHOWS_THE_ASSIGNED_IP_ADDRESS_DUID_AND_TIME_EXPIRED_FOR_EACH_DHCP_LEASED_CLIENT); %></p>
</div>
<div class="data_common data_vertical">
	<table>
		<tr> 
			<th><% multilang(LANG_IP_ADDRESS); %></th>
			<th><% multilang(LANG_DUID); %></th>
			<th><% multilang(LANG_EXPIRED_TIME_SEC); %></th>
		</tr>
		<% dhcpClientListv6(); %>
	</table>
</div>
<div class="btn_ctl">
	<input class="link_bg" type="button" value="<% multilang(LANG_REFRESH); %>" name="refresh" onClick="javascript: location.reload();">&nbsp;&nbsp;
	<input class="link_bg" type="button" value="<% multilang(LANG_CLOSE); %>" name="close" onClick="javascript: window.close();">
</div>
</body>
</html>
