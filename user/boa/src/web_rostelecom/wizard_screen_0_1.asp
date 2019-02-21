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
	if (document.Wizard0_1.ploamcode.value=="") {		
		alert('<% multilang(LANG_PLOAM_PASSWORD_CANNOT_BE_EMPTY); %>');
		document.Wizard0_1.ploamcode.focus();
		return false;
	}
	if (includeSpace(document.Wizard0_1.ploamcode.value)) {		
		alert('<% multilang(LANG_CANNOT_ACCEPT_SPACE_CHARACTER_IN_PLOAM_PASSWORD); %>');
		document.Wizard0_1.ploamcode.focus();
		return false;
	}
	if (checkString(document.Wizard0_1.ploamcode.value) == 0) {		
		alert('<% multilang(LANG_INVALID_PLOAM_PASSWORD); %>');
		document.Wizard0_1.ploamcode.focus();
		return false;
	}
	if( !(document.Wizard0_1.ploamcode.value.length==10) )
	{		
		alert('<% multilang(LANG_PLOAM_PASSWORD_SHOULD_BE_10_CHARACTERS); %>');
		document.Wizard0_1.ploamcode.focus();
		return false;
	}

	return true;
}

function saveCheck()
{
	return true;
}

</SCRIPT>
</head>

<body>
<form action=/boaform/admin/formWizardScreen0_1 method=POST name="Wizard0_1">
<div class="data_common data_common_notitle">
	<table>
		<tr class="data_prompt_info">
			<td colspan="2" >
				<br>
				<% multilang(LANG_ENTER_PLOAM_PASSWORD); %>
				<br>
				<br>
			</td>
		</tr>
	</table>
	<table>
		<tr>
			<th width="25%"><% multilang(LANG_PLOAM_CODE); %></th>
			<th>
				<input name="ploamcode" type="text"size="20" maxlength="30">
			</th>
		</tr>
	</table>
</div>
<div class="adsl clearfix btn_center">
	<input class="link_bg" type="submit" name="setmanually" value="<% multilang(LANG_SET_DEVICE_MANUALLY); %>" onClick="return saveCheck2();" >
	<input class="link_bg" type="submit" name="continue" value="<% multilang(LANG_CONTINUE); %>" onClick="return saveCheck();" >
</div>
</form>
</body>
</html>
