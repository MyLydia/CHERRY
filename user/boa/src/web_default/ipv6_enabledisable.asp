<html>
<! Copyright (c) Realtek Semiconductor Corp., 2003. All Rights Reserved. ->
<HEAD>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<title>IPv6 Enable/Disable</title>
<title><% multilang(LANG_IPV6_E); %> <% multilang(LANG_CONFIGURATION); %></title>
<link rel="stylesheet" type="text/css" href="common_style.css"/>
<script type="text/javascript" src="share.js">
</script>
<SCRIPT language="javascript" src="/common.js"></SCRIPT>
<SCRIPT>
function on_submit()
{
	//obj.isclick = 1;
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	return true;
}
</SCRIPT>
</HEAD>

<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000">
  <blockquote>
	<h2 class="page_title"><% multilang(LANG_IPV6); %><% multilang(LANG_CONFIGURATION); %></h2>
	<DIV align="left" style="padding-left:20px; padding-top:5px">
		<form id="form" action=/boaform/admin/formIPv6EnableDisable method=POST name="ipv6enabledisable">			
			<table>
			<tr><td><font size=2><% multilang(LANG_THIS_PAGE_BE_USED_TO_CONFIGURE_IPV6_ENABLE_DISABLE); %></font></td></tr>
			<tr><td><hr size=1 noshade align=top></td></tr>
			</table>
			
			<table>
			  <tr>
			  	<th><% multilang(LANG_IPV6); %>:</th>
				<td>
	      		<input type="radio" value="0" name="ipv6switch" <% checkWrite("ipv6enabledisable0"); %> ><% multilang(LANG_DISABLE); %>&nbsp;&nbsp;
	      		<input type="radio" value="1" name="ipv6switch"<% checkWrite("ipv6enabledisable1"); %> ><% multilang(LANG_ENABLE); %></td>
			  </tr>
			  <tr>
			</table>
			<br><br>
			<input type="submit" class="button" value="<% multilang(LANG_APPLY_CHANGES); %>" onClick="return on_submit()">
			<input type="hidden" value="/ipv6_enabledisable.asp" name="submit-url">
			<input type="hidden" name="postSecurityFlag" value="">
		</form>
	</DIV>
  </blockquote>

</body>
</html>
