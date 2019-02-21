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

</script>
</head>
<body>
<form action=/boaform/admin/formWizardScreen5_1 method=POST name="Wizard5_1">
<div class="data_common data_common_notitle">
	<table>
		<tr>			
			<td align="center">
				<font color="red" size="6"><% multilang(LANG_NO_CONNECTION); %></font>
			</td>
		</tr>
		<tr>			
			<td class="data_prompt_td_info">
				<% multilang(LANG_CHECK_IF_WAN_CABLE_IS_CONNECTED_AS_SHOWN_ON_A_PICTURE); %>
			</td>
		</tr>
		<tr>
			<td align="center">
				<img width="269" height="190" src="./graphics/connect.jpg">
			</td>
		</tr>
	</table>
</div>
<br>
<div class="adsl clearfix btn_center">
	<input class="link_bg" type="submit" name="continue" value="<% multilang(LANG_CONTINUE); %>">
	<input class="link_bg" type="submit" name="exit" value="<% multilang(LANG_MANUAL_SETUP); %>">
</div>
</form>
</body>
</html>
