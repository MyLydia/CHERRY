<% SendWebHeadStr();%>
<title><% multilang(LANG_EPON_SETTINGS); %></title>

<script>
function applyclick(F)
{
	var mac_addr = document.formepon_llid_mac_mapping.elements["mac_addr[]"];

	for(var i=0;i<mac_addr.length;i++)
	{
		if ( (mac_addr[i].value=="") || (mac_addr[i].value.indexOf(":")==-1) || (mac_addr[i].value.length!=17))
		{				
				alert('<% multilang(LANG_INVALID_MAC_ADDRESS); %>');
				mac_addr[i].focus();
				return false;
		}
	}

	postTableEncrypt(F.postSecurityFlag, F);

	return true;
}
</script>
</head>
<body>
<div class="intro_main ">
	<p class="intro_title"><% multilang(LANG_EPON_SETTINGS); %></p>
	<p class="intro_content"><% multilang(LANG_THIS_PAGE_IS_USED_TO_CONFIGURE_THE_PARAMETERS_FOR_EPON_NETWORK_ACCESS); %></p>
</div>

<form action=/boaform/admin/formeponConf method=POST name="formeponconf">
<div class="data_common data_common_notitle">
<table>
	<tr>
		<th width="40%"><% multilang(LANG_LOID); %>:</th>
		<td><input type="text" name="fmepon_loid" size="20" maxlength="20" value="<% fmepon_checkWrite("fmepon_loid"); %>"></td>
	</tr>
	<tr>
		<th width="40%"><% multilang(LANG_LOID_PASSWORD); %>:</th>
		<td><input type="text" name="fmepon_loid_password" size="20" maxlength="12" value="<% fmepon_checkWrite("fmepon_loid_password"); %>"></td>
	</tr>
</table>
</div>
<div class="btn_ctl clearfix">
	<input class="link_bg" type="submit" value="<% multilang(LANG_APPLY_CHANGES); %>" onclick="return applyclick(document.formeponconf)">&nbsp;&nbsp;
	<input type="hidden" value="/epon.asp" name="submit-url">
	<input type="hidden" name="postSecurityFlag" value="">
</div>
</form>

<form action=/boaform/admin/formepon_llid_mac_mapping method=POST name="formepon_llid_mac_mapping">
<div class="column" style="display:none">
	<div class="column_title">
		<div class="column_title_left"></div>
			<p><% multilang(LANG_LLID_MAC_MAPPING_TABLE); %></p>
		<div class="column_title_right"></div>
	</div>
	<div class="data_common data_vertical">
		<table>
			<% showepon_LLID_MAC(); %>
		</table>
	</div>
</div>
<div class="btn_ctl" style="display:none">
      <input class="link_bg" type="submit" value="<% multilang(LANG_APPLY_CHANGES); %>" onClick="return applyclick(document.formepon_llid_mac_mapping)">&nbsp;&nbsp;
      <input type="hidden" value="/epon.asp" name="submit-url">
      <input type="hidden" name="postSecurityFlag" value="">
</div>
</form>
<br><br>
</body>
</html>
