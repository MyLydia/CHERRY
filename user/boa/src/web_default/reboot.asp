<html>
<! Copyright (c) Realtek Semiconductor Corp., 2003. All Rights Reserved. ->
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<link rel="stylesheet" type="text/css" href="common_style.css" />
<title><% multilang(LANG_COMMIT_AND_REBOOT); %></title>
<SCRIPT language="javascript" src="/common.js"></SCRIPT>
<SCRIPT>
function saveClick()
{
   if ( !confirm('<% multilang(LANG_DO_YOU_REALLY_WANT_TO_COMMIT_THE_CURRENT_SETTINGS); %>') ) {
	return false;
  }
  else{
  	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	return true;
  }
}

function resetClick()
{
   if ( !confirm('<% multilang(LANG_DO_YOU_REALLY_WANT_TO_RESET_THE_CURRENT_SETTINGS_TO_DEFAULT); %>') ) {
	return false;
  }
  else
	return true;
}
</SCRIPT>
</head>

<body>
<blockquote>
<h2 class="page_title"><% multilang(LANG_COMMIT_AND_REBOOT); %></h2>

<form action=/boaform/admin/formReboot method=POST name="cmboot">
<table>
  <tr><td>
    <% multilang(LANG_THIS_PAGE_IS_USED_TO_COMMIT_CHANGES_TO_SYSTEM_MEMORY_AND_REBOOT_YOUR_SYSTEM); %>
  </td></tr>
  <tr><td><hr size=1 noshade align=top></td></tr>
</table>
<table>
<!--
  <tr>
      <td width="30%"><font size=2><b>Reboot from:</b>
      <select size="1" name="rebootMode">
           <option selected value=0>Last Configuration</option>
           <option value=1>Default Configuration</option>
           <option value=2>Upgrade Configuration</option>
      </select>
      </td>
  </tr>
-->
</table>
  <br>
      <input type="submit" value="<% multilang(LANG_COMMIT_AND_REBOOT); %>" onclick="return saveClick()">&nbsp;&nbsp;
<!--	// Jenny,  buglist B031, B032, remove reset to default button from commit/reboot webpage
      <input type="submit" value="Reset to Default" name="reset" onclick="return resetClick()">
      <input type="submit" value="Reboot" name="reboot">
      <input type="hidden" value="/reboot.asp" name="submit-url">
  <script>
-->
	<input type="hidden" name="postSecurityFlag" value="">
 </form>
</blockquote>
</body>

</html>
