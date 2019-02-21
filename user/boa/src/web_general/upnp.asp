<% SendWebHeadStr();%>
<title>UPnP <% multilang(LANG_CONFIGURATION); %></title>
<SCRIPT>
function proxySelection()
{
	if (document.upnp.daemon[0].checked) {
		document.upnp.ext_if.disabled = true;

		if(typeof(document.upnp.tr_064_sw) != "undefined")
		{
			document.upnp.tr_064_sw[0].disabled = true;
			document.upnp.tr_064_sw[1].disabled = true;
		}
	}
	else {
		document.upnp.ext_if.disabled = false;

		if(typeof(document.upnp.tr_064_sw) != "undefined")
		{
			document.upnp.tr_064_sw[0].disabled = false;
			document.upnp.tr_064_sw[1].disabled = false;
		}
	}
}

function on_submit()
{
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	return true;
}
</SCRIPT>
</head>

<body>
<div class="intro_main ">
	<p class="intro_title">UPnP <% multilang(LANG_CONFIGURATION); %></p>
	<p class="intro_content"><% multilang(LANG_THIS_PAGE_IS_USED_TO_CONFIGURE_UPNP_THE_SYSTEM_ACTS_AS_A_DAEMON_WHEN_YOU_ENABLE_IT_AND_SELECT_WAN_INTERFACE_UPSTREAM_THAT_WILL_USE_UPNP); %></p>
</div>

<form action=/boaform/formUpnp method=POST name="upnp">
<div class="data_common data_common_notitle">
	<table>
		<tr>
			<th width="30%"><% multilang(LANG_UPNP); %>:</th>
			<td>
				<input type="radio" value="0" name="daemon" <% checkWrite("upnp0"); %> onClick="proxySelection()"><% multilang(LANG_DISABLE); %>&nbsp;&nbsp;
				<input type="radio" value="1" name="daemon" <% checkWrite("upnp1"); %> onClick="proxySelection()"><% multilang(LANG_ENABLE); %>
			</td>
		</tr>
		<% checkWrite("tr064_switch"); %>
		<tr>
			<th width="30%"><% multilang(LANG_WAN_INTERFACE); %>:</th>
			<td>
				<select name="ext_if" <% checkWrite("upnp0d"); %>>
					<% if_wan_list("rt"); %>
				</select>
			</td>
		</tr>
	</table>
</div>
<div class="btn_ctl">
	<input type="submit" value="<% multilang(LANG_APPLY_CHANGES); %>" class="link_bg" onClick="return on_submit()">
	<input type="hidden" value="/upnp.asp" name="submit-url">
	<input type="hidden" name="postSecurityFlag" value="">
</div>
<script>
	initUpnpDisable = document.upnp.daemon[0].checked;
	ifIdx = <% getInfo("upnp-ext-itf"); %>;
	document.upnp.ext_if.selectedIndex = -1;

	for( i = 0; i < document.upnp.ext_if.options.length; i++ )
	{
		if( ifIdx == document.upnp.ext_if.options[i].value )
			document.upnp.ext_if.selectedIndex = i;
	}

	proxySelection();
</script>
</form>
<br><br>
</body>
</html>
