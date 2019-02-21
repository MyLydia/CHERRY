<%SendWebHeadStr(); %>
<title><% multilang(LANG_PASSWORD); %><% multilang(LANG_WAN_CONFIGURATION); %></title>

<SCRIPT>
function saveChanges()
{
   if ( document.password.newpass.value != document.password.confpass.value) {	
	alert('<% multilang(LANG_PASSWORD_IS_NOT_MATCHED_PLEASE_TYPE_THE_SAME_PASSWORD_BETWEEN_NEW_AND_CONFIRMED_BOX); %>');
	document.password.newpass.focus();
	return false;
  }

  if ( document.password.newpass.value.length == 0 ) {	
	alert('<% multilang(LANG_PASSWORD_CANNOT_BE_EMPTY_PLEASE_TRY_IT_AGAIN); %>');
	document.password.newpass.focus();
	return false;
  }

  if (includeSpace(document.password.newpass.value)) {	
	alert('<% multilang(LANG_CANNOT_ACCEPT_SPACE_CHARACTER_IN_PASSWORD_PLEASE_TRY_IT_AGAIN); %>');
	document.password.newpass.focus();
	return false;
  }
  if (checkString(document.password.newpass.value) == 0) {	
	alert('<% multilang(LANG_INVALID_PASSWORD); %>');
	document.password.newpass.focus();
	return false;
  }
  postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
  return true;
}

</SCRIPT>
</head>

<BODY>
<div class="intro_main ">
	<p class="intro_title"><% multilang(LANG_PASSWORD); %> <% multilang(LANG_WAN_CONFIGURATION); %></p>
	<p class="intro_content"> This page is used to set the account to access the web server of ADSL Router.
 Empty user name and password will disable the protection.</p>
</div>

<form action=/boaform/admin/formUserPasswordSetup method=POST name="password">
<div class="data_common data_common_notitle">
<table>
	<tr>
      <th><% multilang(LANG_LOGIN_USER); %>:</th>
      <td><% getInfo("login-user"); %></td>
    </tr>
    <tr>
      <th><% multilang(LANG_OLD_PASSWORD); %>:</th>
      <td><input type="password" name="oldpass" size="20" maxlength="30"></td>
    </tr>
    <tr>
      <th><% multilang(LANG_NEW_PASSWORD); %>:</th>
      <td><input type="password" name="newpass" size="20" maxlength="30"></td>
    </tr>
    <tr>
      <th><% multilang(LANG_CONFIRMED_PASSWORD); %>:</th>
      <td><input type="password" name="confpass" size="20" maxlength="30"></td>
    </tr>
</table>
</div>
<div class="btn_ctl">
	<input type="hidden" value="/admin/user-password.asp" name="submit-url">
	<input class="link_bg" type="submit" value="<% multilang(LANG_APPLY_CHANGES); %>"  onClick="return saveChanges()">&nbsp;&nbsp;
	<input class="link_bg" type="reset" value="  <% multilang(LANG_RESET); %>  " name="reset">
	<input type="hidden" name="postSecurityFlag" value="">
</div>
</form>
</body>
</html>


