<html>
<! Copyright (c) Realtek Semiconductor Corp., 2003. All Rights Reserved. ->
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<title>Html Wizard</title>
<link href="reset.css" rel="stylesheet" type="text/css" />
<link href="base.css" rel="stylesheet" type="text/css" />
<link href="style.css" rel="stylesheet" type="text/css" />
<script type="text/javascript" src="share.js"></script>
<script>
<% initWizardScreen4_2(); %>

function on_apply() {
}
</script>
</head>
<body>
<form action=/boaform/admin/formWizardScreen4_2 method=POST name="Wizard4_2">
<div class="data_common data_common_notitle">
	<table>
		<tr>			
			<td align="center">
				<font color="red" size="6"><% multilang(LANG_AUTOMATIC_CONFIGURE_FAILED); %></font>
			</td>
		</tr>
		<tr>			
			<td class="data_prompt_td_info">
				<% multilang(LANG_DEVICE_COULDN_T_ESTABLISH_CONNECTION_WITH_INTERNET_TO_CONTINUE_SETUP_PLEASE_GO_TO_WEBINTERFACE_OR_CONFIGURE_THE_SERVICES_MANUALLY); %>
			</td>
		</tr>
	</table>
</div>
<br>
<div class="adsl clearfix btn_center">
    <input class="link_bg" type="submit" name="exit" value="<% multilang(LANG_WIZARD_LINK_TO_WEB); %>" onClick="on_apply();">
</div>
</form>
</div>
</body>
</html>
