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

</SCRIPT>
</head>

<body>
<form action=/boaform/admin/formWizardScreen1_2 method=POST name="Wizard1_2">
<div class="data_common data_common_notitle">
	<table>
		<tr class="data_prompt_info">
			<td colspan="2" >
				<font size="4"><% multilang(LANG_THE_DEVICE_IS_CONNECTED_TO_GPON_NETWORK); %></font>
				<br>
				<% multilang(LANG_YOU_CAN_CONFIGURE_ROUTER_MANUALLY_OR_USING_SMART_WIZARD_FOR_QUICK_CONFIGURATION); %>
			</td>
		</tr>
	</table>
</div>
<div class="adsl clearfix btn_center">
	<input class="link_bg" type="submit" name="continue" value="<% multilang(LANG_WIZARD_LAUNCH_SMALL_WIZARD); %>">
	<input class="link_bg" type="submit" name="exit" value="<% multilang(LANG_MANUAL_SETUP); %>">
</div>
</form>
</body>
</html>
