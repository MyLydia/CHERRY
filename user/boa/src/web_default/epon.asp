<html>
<! Copyright (c) Realtek Semiconductor Corp., 2003. All Rights Reserved. ->
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<title><% multilang(LANG_EPON_SETTINGS); %></title>
<link rel="stylesheet" type="text/css" href="common_style.css" />
<script type="text/javascript" src="share.js">
</script>
<SCRIPT language="javascript" src="/common.js"></SCRIPT>
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
<blockquote>
<h2 class="page_title"><% multilang(LANG_EPON_SETTINGS); %></h2>
<form action=/boaform/admin/formeponConf method=POST name="formeponconf">
<table>
  <tr><td><font size=2>
    <% multilang(LANG_THIS_PAGE_IS_USED_TO_CONFIGURE_THE_PARAMETERS_FOR_EPON_NETWORK_ACCESS); %>
  </font></td></tr>
  <tr><td><hr size=1 noshade align=top></td></tr>
</table>
<table>
  <tr>
      <th><% multilang(LANG_LOID); %>:</th>
      <td><input type="text" name="fmepon_loid" size="24" maxlength="24" value="<% fmepon_checkWrite("fmepon_loid"); %>"></td>
  </tr>
<tr>
      <th><% multilang(LANG_LOID_PASSWORD); %>:</th>
      <td><input type="text" name="fmepon_loid_password" size="12" maxlength="12" value="<% fmepon_checkWrite("fmepon_loid_password"); %>"></td>
  </tr>

</table>
      <input type="submit" value="<% multilang(LANG_APPLY_CHANGES); %>" onclick="return applyclick(document.formeponconf)">&nbsp;&nbsp;
      <input type="hidden" value="/epon.asp" name="submit-url">
      <input type="hidden" name="postSecurityFlag" value="">
</form>
<table>
  <tr><font size=2><b><% multilang(LANG_LLID_MAC_MAPPING_TABLE); %>:</b></font></tr>
<form action=/boaform/admin/formepon_llid_mac_mapping method=POST name="formepon_llid_mac_mapping">
  <% showepon_LLID_MAC(); %> <br>
<tr><td>
      <input type="submit" value="<% multilang(LANG_APPLY_CHANGES); %>" onClick="return applyclick(document.formepon_llid_mac_mapping)">&nbsp;&nbsp;
      <input type="hidden" value="/epon.asp" name="submit-url">
      <input type="hidden" name="postSecurityFlag" value="">
</td></tr>
</form>
</table>
</blockquote>
</body>
</html>
