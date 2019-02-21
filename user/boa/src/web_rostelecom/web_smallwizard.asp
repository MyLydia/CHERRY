<VWS_FUNCTION (void*)SendWebMetaNoRefreshStr();>
<VWS_FUNCTION (void*)SendWebCssStr();>
<title>Html Wizard</title>

<SCRIPT>
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
	if (document.RoseSmallWizard.newpass.value.length == 0) 
	{
		alert("<% multilang(LANG_PASSWORD_CANNOT_BE_EMPTY_PLEASE_TRY_IT_AGAIN); %>");
		document.RoseSmallWizard.newpass.focus();
		return false;
	}
	if (document.RoseSmallWizard.confirmpass.value.length == 0) 
	{
		alert("<% multilang(LANG_CONFIRM_PASSWORD_CANNOT_BE_EMPTY_PLEASE_TRY_IT_AGAIN); %>");
		document.RoseSmallWizard.confirmpass.focus();
		return false;
	}
	if(!checkDigitLetterExclude(document.RoseSmallWizard.newpass.value))
	{
		alert("<% multilang(LANG_ADMIN_PASWWORD_MUST_CONTAIN_AT_LEAST_ONE_DIGIT_09_AND_ONE_LETTER_AZ_AZ_AND_BE_NOT_LESS_THAN_5_SYMBOLS); %>");
		document.RoseSmallWizard.newpass.focus();
		return false;
	}
	if (document.RoseSmallWizard.newpass.value != document.RoseSmallWizard.confirmpass.value)
	{
		alert("<% multilang(LANG_PASSWORD_IS_NOT_MATCHED_PLEASE_TYPE_THE_SAME_PASSWORD_BETWEEN__NEW_AND__CONFIRMED_BOX); %>");   
		document.RoseSmallWizard.newpass.focus();
		return false;
	}	
	if (includeSpecialKey(document.RoseSmallWizard.newpass.value)) 
	{
		alert("<% multilang(LANG_INVALID_PASSWORD_PLEASE_TRY_IT_AGAIN); %>");                
		document.RoseSmallWizard.newpass.focus();               
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
				<td colspan="2"><% multilang(LANG_THIS_ROUTER_IS_IDEAL_FOR_HOME_AND_SMALL_OFFICE_NETWORKS_YOUR_DEVICE_IS_ALREADY_SET_UP_BUILTIN_QUICK_SETUP_WIZARD_WILL_HELP_YOU_COMPLETE_YOUR_PERSONAL_SETTINGS_PLEASE_FOLLOW_THE_INSTRUCTIONS); %>
				<br>
				<% multilang(LANG_FOR_YOUR_SECURITY_PLEASE_CHANGE_THE_PASSWORD_OF_THE_ROUTER_THE_DEFAULT_ENTER_THE_NEW_PASSWORD_AND_CONFIRM_IN_THE_BOX_BELOW_AND_CLICK_OK_TO_CONTINUE); %>
				</td>
			</tr>
	        <form action="form2RoseSmallWizard.cgi" method=POST name="RoseSmallWizard">
			<tr>
				<th width="25%"><% multilang(LANG_NEW_PASSWORD); %></th>
				<th>
				<input name="newpass" type="text"size="20" maxlength="30">
				</th>
			</tr>
			<tr>
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
		<input type="hidden" value="Send" name="submit.htm?rose_smallwizard.htm">
	</div>
</form>

</body>

</html>
