<html>
<! Copyright (c) Realtek Semiconductor Corp., 2003. All Rights Reserved. ->
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<title>ALG <% multilang(LANG_ON_OFF); %><% multilang(LANG_CONFIGURATION); %></title>
<link rel="stylesheet" type="text/css" href="common_style.css" />
<SCRIPT language="javascript" src="/common.js"></SCRIPT>
<script>
function AlgTypeStatus()
{
	<% checkWrite("AlgTypeStatus"); %>
	return true;
}

function on_submit()
{
	document.forms[0].apply.isclick = 1;
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	return true;
}
</script>
</head>

<body >
<blockquote>
<h2 class="page_title">ALG <% multilang(LANG_ON_OFF); %> <% multilang(LANG_CONFIGURATION); %></h2>

<table>
<tr><td colspan=4><font size=2>
	<% multilang(LANG_THIS_PAGE_IS_USED_TO_ENABLE_DISABLE_ALG_SERVICES); %>
	<br>
 </font></td></tr>
 <tr><td><hr size=1 noshade align=top></td></tr>
</table>
<table>
<form action=/boaform/formALGOnOff method=POST name=algof>
<table>
<tr>
<td><font size=2>ALG <% multilang(LANG_TYPE); %>:</font></td>
<td colspan="2">	
</td>
</tr>
<% checkWrite("GetAlgType"); %>	
<tr>
	<td ><input type=submit value="<% multilang(LANG_APPLY_CHANGES); %>" name=apply onClick="return on_submit()"></td>
  <td> <input type="hidden" value="/algonoff.asp" name="submit-url"></td>
  <td><input type="hidden" name="postSecurityFlag" value=""></td>
</tr>
</table>
</form>
<script>
AlgTypeStatus();
</script>
</table>
</blockquote>
</body>
</html>
