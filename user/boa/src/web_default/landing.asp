<html>
<! Copyright (c) Realtek Semiconductor Corp., 2003. All Rights Reserved. ->
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<title><% multilang(LANG_LANDING_PAGE); %><% multilang(LANG_CONFIGURATION); %></title>
<link rel="stylesheet" type="text/css" href="common_style.css"/>
<SCRIPT language="javascript" src="/common.js"></SCRIPT>
<script>
function saveClick()
{	
	alert('<% multilang(LANG_PLEASE_COMMIT_AND_REBOOT_THIS_SYSTEM_FOR_TAKE_EFFECT_THE_LANDING_PAGE); %>');
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
}

</script>

</head>

<body>
<blockquote>
<h2 class="page_title"><% multilang(LANG_LANDING_PAGE); %><% multilang(LANG_CONFIGURATION); %></h2>

<form action=/boaform/formLanding method=POST name="landing">
<table> 
  <tr><td><font size=2>
    <% multilang(LANG_THIS_PAGE_IS_USED_TO_CONFIGURE_THE_TIME_INTERVAL_OF_LANDING_PAGE); %>
  </font></td></tr>
  <tr><td><hr size=1 noshade align=top></td></tr>
</table>

<table> 
  <tr>
      <th><% multilang(LANG_TIME_INTERVAL); %>:</th>
      <td width="70%"><input type="text" name="interval" size="15" maxlength="15" value=<% getInfo("landing-page-time"); %>>(<% multilang(LANG_SECONDS); %>)</td>
  </tr>   
</table>
      <br>
      <input type="submit" value="<% multilang(LANG_APPLY_CHANGES); %>" onClick="return saveClick()">&nbsp;&nbsp;
      <input type="hidden" value="/landing.asp" name="submit-url">
	  <input type="hidden" name="postSecurityFlag" value="">

</form>
</blockquote>
</body>

</html>
