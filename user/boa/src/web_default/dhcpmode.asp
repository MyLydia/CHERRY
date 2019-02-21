<html>
<! Copyright (c) Realtek Semiconductor Corp., 2003. All Rights Reserved. ->
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<title>DHCP <% multilang(LANG_MODE); %><% multilang(LANG_CONFIGURATION); %></title>
<link rel="stylesheet" type="text/css" href="common_style.css" />
<SCRIPT language="javascript" src="/common.js"></SCRIPT>
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
<blockquote>
<h2 class="page_title">DHCP <% multilang(LANG_MODE); %><% multilang(LANG_CONFIGURATION); %></h2>

<form action=/boaform/formDhcpMode method=POST name="dhcpmode">
<table>
  <tr><td><font size=2>
    <% multilang(LANG_THIS_PAGE_IS_USED_TO_SET_AND_CONFIGURE_THE_DYNAMIC_HOST_CONFIGURATION_PROTOCOL_MODE_FOR_YOUR_DEVICE_WITH_DHCP_IP_ADDRESSES_FOR_YOUR_LAN_ARE_ADMINISTERED_AND_DISTRIBUTED_AS_NEEDED_BY_THIS_DEVICE_OR_AN_ISP_DEVICE); %>
  </td></tr>
  <tr><td><hr size=1 noshade align=top></td></tr>
</table>

<table>
  <tr>
      <th>DHCP <% multilang(LANG_MODE); %>:</th>
      <td>
      <% checkWrite("dhcpMode"); %>
      </td>
  </tr>
</table>
  <br>
      <input type="submit" value="<% multilang(LANG_APPLY_CHANGES); %>" name="save" onClick="return on_submit(this)">&nbsp;&nbsp;
      <input type="hidden" value="/dhcpmode.asp" name="submit-url">
      <input type="hidden" name="postSecurityFlag" value="">
 </form>
</blockquote>
</body>

</html>


