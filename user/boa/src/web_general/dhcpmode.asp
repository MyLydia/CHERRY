<%SendWebHeadStr(); %>
<title>DHCP <% multilang(LANG_MODE); %><% multilang(LANG_CONFIGURATION); %></title>

<SCRIPT>
function on_submit(obj)
{
	obj.isclick = 1;
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	return true;
}
</SCRIPT>
</head>

<body>
<div class="intro_main ">
	<p class="intro_title">DHCP <% multilang(LANG_MODE); %> <% multilang(LANG_CONFIGURATION); %></p>
	<p class="intro_content"> <% multilang(LANG_THIS_PAGE_IS_USED_TO_SET_AND_CONFIGURE_THE_DYNAMIC_HOST_CONFIGURATION_PROTOCOL_MODE_FOR_YOUR_DEVICE_WITH_DHCP_IP_ADDRESSES_FOR_YOUR_LAN_ARE_ADMINISTERED_AND_DISTRIBUTED_AS_NEEDED_BY_THIS_DEVICE_OR_AN_ISP_DEVICE); %></p>
</div>

<form action=/boaform/formDhcpMode method=POST name="dhcpmode">
<div class="data_common data_common_notitle">
<table>
	<tr>
		<th>DHCP <% multilang(LANG_MODE); %>:</th>
		<td>
			<% checkWrite("dhcpMode"); %>
		</td>
	</tr>
</table>
</div>

<div class="btn_ctl">
	<input class="link_bg" type="submit" value="<% multilang(LANG_APPLY_CHANGES); %>" name="save" onClick="return on_submit(this)">&nbsp;&nbsp;
	<input type="hidden" value="/dhcpmode.asp" name="submit-url">
	<input type="hidden" name="postSecurityFlag" value="">
</div>
</form>
<br><br>
</body>
</html>


