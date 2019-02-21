<%SendWebHeadStr(); %>
<meta HTTP-EQUIV='Pragma' CONTENT='no-cache'>
<title><% multilang(LANG_USER_ACCOUNT); %><% multilang(LANG_CONFIGURATION); %></title>

<SCRIPT>
selected=0;
sdefault = 0;

function saveChanges(obj)
{
  /*if (document.userconfig.username.value == "admin" ||
  		document.userconfig.username.value == "user") {
	alert("<% multilang(LANG_CONFLICT_USER_NAME); %>");
	document.userconfig.newpass.focus();
	return false;
  }*/
  if (document.userconfig.username.value.length > 0 &&
  		document.userconfig.newpass.value.length == 0) {
	alert("<% multilang(LANG_PASSWORD_CANNOT_BE_EMPTY_PLEASE_TRY_IT_AGAIN); %>");
	document.userconfig.newpass.focus();
	return false;
  }

   if (document.userconfig.newpass.value != document.userconfig.confpass.value) {
	alert("<% multilang(LANG_PASSWORD_IS_NOT_MATCHED_PLEASE_TYPE_THE_SAME_PASSWORD_BETWEEN__NEW_AND__CONFIRMED_BOX); %>");
	document.userconfig.newpass.focus();
	return false;
  }

  if (includeSpace(document.userconfig.username.value)) {
	alert("<% multilang(LANG_CANNOT_ACCEPT_SPACE_CHARACTER_IN_USER_NAME_PLEASE_TRY_IT_AGAIN); %>");
	document.userconfig.username.focus();
	return false;
  }
  if (checkString(document.userconfig.username.value) == 0) {
	alert("<% multilang(LANG_INVALID_USER_NAME); %>");
	document.userconfig.username.focus();
	return false;
  }

  if (includeSpace(document.userconfig.newpass.value)) {
	alert("<% multilang(LANG_CANNOT_ACCEPT_SPACE_CHARACTER_IN_PASSWORD_PLEASE_TRY_IT_AGAIN); %>");
	document.userconfig.newpass.focus();
	return false;
  }
  if (checkString(document.userconfig.newpass.value) == 0) {
	alert("<% multilang(LANG_INVALID_PASSWORD); %>");
	document.userconfig.newpass.focus();
	return false;
  }

  if (sdefault == 1)
		document.userconfig.privilege.disabled = false;
  obj.isclick = 1;
  postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
  return true;
}

function modifyClick(obj)
{
	if (!selected) {
		alert("<% multilang(LANG_PLEASE_SELECT_AN_ENTRY_TO_MODIFY); %>");
		return false;
	}

	/*if (document.userconfig.oldpass.value != document.userconfig.hiddenpass.value) {
		alert("<% multilang(LANG_INCORRECT_OLD_PASSWORD_PLEASE_TRY_IT_AGAIN); %>");
		document.userconfig.oldpass.focus();
		return false;
	}*/

	return saveChanges(obj);
}

function delClick(obj)
{
	if (!selected) {
		alert("<% multilang(LANG_PLEASE_SELECT_AN_ENTRY_TO_DELETE); %>");
		return false;
	}
	if (document.userconfig.username.value == document.userconfig.suser.value ||
  		document.userconfig.username.value == document.userconfig.nuser.value) {
		alert("<% multilang(LANG_THE_ACCOUNT_CANNOT_BE_DELETED); %>");
		return false;
	}
	obj.isclick = 1;
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	return true;
}

//function postEntry(user, priv, pass)
function postEntry(user, priv)
{
	document.userconfig.privilege.value = priv;
	if (user == document.userconfig.suser.value || user == document.userconfig.nuser.value) {
		document.userconfig.privilege.disabled = true;
		sdefault = 1;
		//document.userconfig.username.disabled = true;
	}
	else {
		document.userconfig.privilege.disabled = false;
		//document.userconfig.username.disabled = false;
	}
	document.userconfig.oldpass.disabled = false;
	document.userconfig.username.value = user;
//	document.userconfig.hiddenpass.value = pass;
	selected = 1;
}

function disablePriv()
{
	document.userconfig.privilege.value = 0;
	document.userconfig.privilege.disabled = true;
}

function resetConfig()
{
//	disablePriv();
	document.userconfig.privilege.value = 0;
	document.userconfig.privilege.disabled = false;
	document.userconfig.oldpass.disabled = true;
}

function checkAction()
{
//	disablePriv();
//	if (document.userconfig.hiddenpass.value.length == 0)
	if (!selected)
		document.userconfig.oldpass.disabled = true;
}
</SCRIPT>
</head>

<BODY>
<div class="intro_main ">
	<p class="intro_title"><% multilang(LANG_USER_ACCOUNT); %> <% multilang(LANG_CONFIGURATION); %></p>
	<p class="intro_content"> <% multilang(LANG_THIS_PAGE_IS_USED_TO_ADD_USER_ACCOUNT_TO_ACCESS_THE_WEB_SERVER_OF_THE_DEVICE_EMPTY_USER_NAME_OR_PASSWORD_IS_NOT_ALLOWED); %></p>
</div>

<form action=/boaform/formAccountConfig method=POST name="userconfig">
<div class="data_common data_common_notitle">
	<table>
		<tr>
			<th><% multilang(LANG_USER); %><% multilang(LANG_NAME); %>:</th>
			<td><input type="text" name="username" size="20" maxlength="30"></td>
		</tr>
		<tr>
			<th><% multilang(LANG_PRIVILEGE); %>:</th>
			<td>
				<select size="1" name="privilege">
					<option value="0"><% multilang(LANG_USER); %></option>
					<option value="1"><% multilang(LANG_SUPPORT); %></option>
					<option value="2"><% multilang(LANG_ADMIN); %></option>
				</select>
			</td>
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
	<input class="link_bg" type="submit" value="<% multilang(LANG_ADD); %>" name="adduser" onClick="return saveChanges(this)">
	<input class="link_bg" type="submit" value="<% multilang(LANG_MODIFY); %>" name="modify" onClick="return modifyClick(this)">
	<input class="link_bg" type="submit" value="<% multilang(LANG_DELETE); %>" name="deluser" onClick="return delClick(this)">
	<input class="link_bg" type="reset" value="<% multilang(LANG_RESET); %>" name="reset" onClick="resetConfig()"></p>
</div>

<div class="column">
	<div class="column_title">
		<div class="column_title_left"></div>
			<p><% multilang(LANG_USER_ACCOUNT); %><% multilang(LANG_TABLE_2); %></p>
		<div class="column_title_right"></div>
	</div>
	<div class="data_common">
		<table>
			<% accountList(); %>
		</table>
	</div>
</div>

<div class="btn_ctl">
   <input type="hidden" name="suser" value=<% getInfo("super-user"); %>>
   <input type="hidden" name="nuser" value=<% getInfo("normal-user"); %>>
   <input type="hidden" value="/userconfig.asp" name="submit-url">
   <input type="hidden" name="postSecurityFlag" value="">
</div>

<script>
	checkAction();
</script>  
</form>
</body>
</html>


