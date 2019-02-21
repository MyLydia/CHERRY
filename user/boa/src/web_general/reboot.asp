<% SendWebHeadStr();%>
<title><% multilang(LANG_COMMIT_AND_REBOOT); %></title>

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
<div class="intro_main ">
	<p class="intro_title"><% multilang(LANG_COMMIT_AND_REBOOT); %></p>
	<p class="intro_content"><% multilang(LANG_THIS_PAGE_IS_USED_TO_COMMIT_CHANGES_TO_SYSTEM_MEMORY_AND_REBOOT_YOUR_SYSTEM); %></p>
</div>

<form action=/boaform/admin/formReboot method=POST name="cmboot">
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
<div class="data_common data_common_notitle">
	<table>
		<tr>
			<th width="30%"><% multilang(LANG_COMMIT_AND_REBOOT); %>:</th>
			<td>
				<input  class="inner_btn" type="submit" value="<% multilang(LANG_COMMIT_AND_REBOOT); %>" onclick="return saveClick()">
			</td>
		</tr>
	</table>
</div>
      
<!--	// Jenny,  buglist B031, B032, remove reset to default button from commit/reboot webpage
      <input type="submit" value="Reset to Default" name="reset" onclick="return resetClick()">
      <input type="submit" value="Reboot" name="reboot">
      <input type="hidden" value="/reboot.asp" name="submit-url">
  <script>
-->
<input type="hidden" name="postSecurityFlag" value="">
</form>
</body>
</html>
