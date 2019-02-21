<html>
<! Copyright (c) Realtek Semiconductor Corp., 2003. All Rights Reserved. ->
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<title><% multilang(LANG_INTERFACE_STATISITCS); %></title>
<link rel="stylesheet" type="text/css" href="common_style.css"/>
<SCRIPT language="javascript" src="/common.js"></SCRIPT>
<script>
function resetClick() {
	with ( document.forms[0] ) {
		reset.value = 1;
		postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
		submit();
	}
}

function on_submit(obj)
{
	obj.isclick = 1;
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	return true;
}
</script>
</head>
<body>
<blockquote>
<h2 class="page_title"><% multilang(LANG_INTERFACE_STATISITCS); %></h2>

<table>
  <tr><td><font size=2>
 <% multilang(LANG_PAGE_DESC_PACKET_STATISTICS_INFO); %>
  </font></td></tr>
  <tr><td><hr size=1 noshade align=top></td></tr>
</table>
<form action=/boaform/formStats method=POST name="formStats">
<table style="border:2px solid;">
	<% pktStatsList(); %>
</table>
  <br>
  <br><br>
  <input type="hidden" value="/stats.asp" name="submit-url">
  <input type="submit" value="<% multilang(LANG_REFRESH); %>" name="refresh" onClick="return on_submit(this)">
  <input type="hidden" value="0" name="reset">
  <input type="button" onClick="resetClick(this)" value="<% multilang(LANG_RESET_STATISTICS); %>">
  <input type="hidden" name="postSecurityFlag" value="">
</form>
</blockquote>
</body>

</html>
