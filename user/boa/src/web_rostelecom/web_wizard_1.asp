<html>
<! Copyright (c) Realtek Semiconductor Corp., 2003. All Rights Reserved. ->
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<title>Html Wizard</title>
<link href="reset.css" rel="stylesheet" type="text/css" />
<link href="base.css" rel="stylesheet" type="text/css" />
<link href="style.css" rel="stylesheet" type="text/css" />
<script type="text/javascript" src="share.js"></script>

<SCRIPT>

var userpassFlag = 0;

function includeSpecialKey(str)
{
	for (var i = 0; i < str.length; i++)
	{
		if ((str.charAt(i) == ' ') || (str.charAt(i) == '%')
			|| ( str.charAt(i)== '\\' ) || ( str.charAt(i)== '\'' )
			|| (str.charAt(i) == '?') || (str.charAt(i) == '&') || (str.charAt(i) == '"')) 
		{
			return true;
		}
	}
	return false;
}

function saveCheck()
{
	if(userpassFlag == 1)
		return true;
	if (document.WebWizard1.newpass.value.length == 0) 
	{
		alert("<% multilang(LANG_PASSWORD_CANNOT_BE_EMPTY_PLEASE_TRY_IT_AGAIN); %>");
		document.WebWizard1.newpass.focus();
		return false;
	}
	if (document.WebWizard1.confirmpass.value.length == 0) 
	{
		alert("<% multilang(LANG_CONFIRM_PASSWORD_CANNOT_BE_EMPTY_PLEASE_TRY_IT_AGAIN); %>");
		document.WebWizard1.confirmpass.focus();
		return false;
	}
	if (document.WebWizard1.newpass.value != document.WebWizard1.confirmpass.value)
	{
		alert("<% multilang(LANG_PASSWORD_IS_NOT_MATCHED_PLEASE_TYPE_THE_SAME_PASSWORD_BETWEEN_NEW_AND_CONFIRMED_BOX); %>");   
		document.WebWizard1.newpass.focus();
		return false;
	}	
	if (includeSpecialKey(document.WebWizard1.newpass.value)) 
	{
		alert("<% multilang(LANG_INVALID_PASSWORD_PLEASE_TRY_IT_AGAIN); %>");                
		document.WebWizard1.newpass.focus();               
		return false;            
	}
	if (includeCyrillicKey(document.WebWizard1.newpass.value))
	{
		alert("<% multilang(LANG_INVALID_PASSWORD_PLEASE_TRY_IT_AGAIN); %>");                
		document.WebWizard1.newpass.focus();               
		return false;            
	}
	return true;
}

</SCRIPT>
</head>

<body>
	<div class="data_common data_common_notitle">
		<table>
			<tr class="data_prompt_info">
				<td colspan="2">
				<% multilang(LANG_THIS_ROUTER_IS_IDEAL_FOR_HOME_AND_SMALL_OFFICE_NETWORKS_MASTER_WIZARD_WILL_HELP_YOU_TO_CONFIGURE_INTERNET_CONNECTION); %>
				</td>
			</tr>
			<form action=/boaform/form2WebWizard1 method=POST name="WebWizard1">
			<tr id="userpassInfo" class="data_prompt_info" style="display:none;">
				<td colspan="2"><% multilang(LANG_FOR_YOUR_SAFETY_PLEASE_CHANGE_DEFAULT_CPE_PASSWORD_ENTER_NEW_PASSWORD_CONFIRM_IT_IN_THE_FORM_BELOW_AND_PRESS_OK); %>
				</td>
			</tr>
			<tr id="usernewpass" style="display:none;">
				<th width="25%"><% multilang(LANG_NEW_PASSWORD); %></th>
				<th>
				<input name="newpass" type="text"size="20" maxlength="30">
				</th>
			</tr>
			<tr id="userconfirmpass" style="display:none;">
				<th width="25%"><% multilang(LANG_CONFIRMED_PASSWORD); %></th>
				<th>
				<input name="confirmpass" type="text" size="20" maxlength="30">
				</th>
			</tr>
		</table>
	</div>
	<br>
	<div class="adsl clearfix btn_center">
		<input class="link_bg" type="submit" name="ok" value="OK" onClick="return saveCheck()" >
		<input type="hidden" value="/web_wizard_4.asp" name="submit-url">
	</div>
</form>
<script>
	if(userpassFlag == 0)
	{
		document.getElementById("userpassInfo").style.display = "";
		document.getElementById("usernewpass").style.display = "";
		document.getElementById("userconfirmpass").style.display = "";
	}
</script>
</body>

</html>
