<html>
<! Copyright (c) Realtek Semiconductor Corp., 2003. All Rights Reserved. ->
<head>
<meta HTTP-EQUIV='Pragma' CONTENT='no-cache'>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<link rel="stylesheet" type="text/css" href="common_style.css" />
<title><% multilang(LANG_PASSWORD_CONFIGURATION); %></title>
<script type="text/javascript" src="share.js">
</script>
<SCRIPT>

function includeSpecialKey(str)
{
	for (var i = 0; i < str.length; i++)
	{
		if ((str.charAt(i) >= '!') && (str.charAt(i) <= '/'))
			return true;

		if ((str.charAt(i) >= ':') && (str.charAt(i) <= '@'))
			return true;

		if ((str.charAt(i) >= '[') && (str.charAt(i) <= '_'))
			return true;
	}
	return false;
}

function checkSuperUserPassword()
{
	//Rule to check is
	//3.	Superadmin GUI account ONT management requirements.
	//3.1.1.1.	Minimum requirements. 
	//3.1.1.1.1.	Length - not less than 12 symbols.
	//3.1.1.1.2.	Not less than 3 digits.
	//3.1.1.1.3.	Not less than 3 upper and low case letters.
	//3.1.1.1.4.	Special symbols must present.
	//

	if ( document.password.newpass.value != document.password.confpass.value) {
		alert("<% multilang(LANG_PASSWORD_IS_NOT_MATCHED_PLEASE_TYPE_THE_SAME_PASSWORD_BETWEEN_NEW_AND_CONFIRMED_BOX); %>");
		document.password.newpass.focus();
		return false;
	}

	if (	document.password.newpass.value.length == 0) {
		alert("<% multilang(LANG_PASSWORD_CANNOT_BE_EMPTY_PLEASE_TRY_IT_AGAIN); %>");
		document.password.newpass.focus();
		return false;
	}


	if (includeSpace(document.password.newpass.value)) {
		alert("<% multilang(LANG_CANNOT_ACCEPT_SPACE_CHARACTER_IN_PASSWORD_PLEASE_TRY_IT_AGAIN); %>");
		document.password.newpass.focus();
		return false;
	}

	if (checkSuperAdminPasswordValueComplex(document.password.newpass.value) == 0)
	{
		alert("<% multilang(LANG_PASSWORD_MUST_CONTAIN_AT_LEAST_3_BIG_LETTER_3_SMALL_LETTER_SPECIALY_KEY_AND_3_DIGIT_AND_SHOULD_BE_NOT_LESS_THAN_12_SYMBOLS); %>");
		document.password.newpass.focus();
			return false;
	}	
	if (includeSpecialKey(document.password.newpass.value)==false)
	{
		alert("<% multilang(LANG_PASSWORD_MUST_CONTAIN_AT_LEAST_3_BIG_LETTER_3_SMALL_LETTER_SPECIALY_KEY_AND_3_DIGIT_AND_SHOULD_BE_NOT_LESS_THAN_12_SYMBOLS); %>");
		document.password.newpass.focus();
			return false;
	}

	return true;
}

function checkUserPasword()
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
	if (checkAdminPasswordValueComplex(document.password.newpass.value) == 0)
	{
		alert("<% multilang(LANG_PASSWORD_MUST_CONTAIN_AT_LEAST_1_LETTER_AND_1_DIGIT_AND_SHOULD_BE_NOT_LESS_THAN_6_SYMBOLS); %>");
		document.password.newpass.focus();
		return false;
	}	
	if (includeSpecialKey(document.password.newpass.value))
	{
	 	alert("<% multilang(LANG_INCORRECT_SYMBOL_IF_SYMBOL_FOR_PASSWORD_IS_INCORRECT_OR_CYRILLIC_SYMBOLS_ARE_INSERTED); %>");
		document.password.newpass.focus();
		return false;
	}
	if (includeCyrillicKey(document.password.newpass.value))
	{
		alert("<% multilang(LANG_INCORRECT_SYMBOL_IF_SYMBOL_FOR_PASSWORD_IS_INCORRECT_OR_CYRILLIC_SYMBOLS_ARE_INSERTED); %>");
		document.password.newpass.focus();
		return false;
	}

  return true;
}

function saveChanges()
{

	if(document.password.userMode.value=="0")
		return checkSuperUserPassword();
	else
		return checkUserPasword();
}

</SCRIPT>
</head>

<BODY>
<blockquote>
<h2 class="page_title"><% multilang(LANG_PASSWORD_CONFIGURATION); %></font></h2>

<form action=/boaform/formPasswordSetup method=POST name="password">
 <table>
  <tr><td>
 <% multilang(LANG_PAGE_DESC_SET_ACCOUNT_PASSWORD); %>
  </td></tr>
  <tr><td><hr size=1 noshade align=top></td></tr>
  </table>

  <table>
    <tr>
      <th><% multilang(LANG_USER); %><% multilang(LANG_NAME); %>:</th>
      <td><select size="1" name="userMode">
      <% checkWrite("userMode"); %>
      </select>
      </td>
    </tr>
    <tr>
      <th><% multilang(LANG_OLD_PASSWORD); %>:</th>
      <td><input type="password" name="oldpass" size="20" maxlength="30"></td>
    </tr>
    <tr>
      <th><% multilang(LANG_NEW_PASSWORD); %>:</th>
      <td><font size=2><input type="password" name="newpass" size="20" maxlength="30"></td>
    </tr>
    <tr>
      <th><% multilang(LANG_CONFIRMED_PASSWORD); %>:</th>
      <td><input type="password" name="confpass" size="20" maxlength="30"></td>
    </tr>
  </table>
   <input type="hidden" value="/password.asp" name="submit-url">
  <p><input type="submit" value="<% multilang(LANG_APPLY_CHANGES); %>" name="save" onClick="return saveChanges()">&nbsp;&nbsp;
  <input type="reset" value="  <% multilang(LANG_RESET); %>  " name="reset"></p>
</form>
<blockquote>
</body>
</html>


