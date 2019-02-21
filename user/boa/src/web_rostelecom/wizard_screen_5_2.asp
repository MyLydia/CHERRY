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
var devVer = "";
var swVer = "";
var macPppoe = "";
var power = "";
var devModel = "";
var servInfo = "";
var gponSn = "";
var omciStatus = "";

<% initWizardScreen5_2(); %>

function init()
{
	document.Wizard5_2.devVer.value = devVer;
	document.Wizard5_2.swVer.value = swVer;
	document.Wizard5_2.macPppoe.value = macPppoe;
	document.Wizard5_2.power.value = power;
	document.Wizard5_2.devModel.value = devModel;
	document.Wizard5_2.servInfo.value = servInfo;
	document.Wizard5_2.gponSn.value = gponSn;
	document.Wizard5_2.omciStatus.value = omciStatus;
}

function clickExit()
{
	return true;
}
</SCRIPT>
</head>
<body onload="init()">
<form action=/boaform/admin/formWizardScreen5_2 method=POST name="Wizard5_2">
<div class="data_common data_common_notitle">
	<table>
		<tr>			
			<td align="center">
				<font color="red" size="6"><% multilang(LANG_UNABLE_TO_CONNECT_TO_ROSTELECOM_NETWORK); %></font>
			</td>
		</tr>
		<tr>			
			<td class="data_prompt_td_info">
				<% multilang(LANG_THE_DEVICE_WAS_UNABLE_TO_CONNECT_TO_ROSTELECOM_NETWORK_PLEASE_CONTACT_TECHNICAL_SUPPORT__8_800_100_0800); %>
			</td>
		</tr>
	</table>
	<table>
		<tr>
			<th width="32%"><% multilang(LANG_DEVICE_VERSION); %></th>
			<th>
				<input name="devVer" type="text" size="20" maxlength="32" value="">
			</th>
			<th width="25%"><% multilang(LANG_MODEL); %></th>
			<th>
				<input name="devModel" type="text" size="20" maxlength="32" value="">
			</th>
		</tr>
		<tr>
			<th><% multilang(LANG_SOFTWARE_VERSION); %></th>
			<th>
				<input name="swVer" type="text" size="20" maxlength="64" value="">
			</th>
			<th><% multilang(LANG_SERVICE_INFORMATION); %></th>
			<th>
				<input name="servInfo" type="text" size="64" maxlength="128" value="">
			</th>
		</tr>
		<tr>
			<th><% multilang(LANG_PPPOECONNECTION_MACADDRESS); %></th>
			<th>
				<input name="macPppoe" type="text" size="20" maxlength="64" value="">
			</th>
			<th><% multilang(LANG_GPON_IDENTIFICATION_NUMBER); %></th>
			<th>
				<input name="gponSn" type="text" size="20" maxlength="64" value="">
			</th>
		</tr>
		<tr>
			<th><% multilang(LANG_SIGNAL_POWERDBM); %></th>
			<th>
				<input name="power" type="text" size="20" maxlength="64" value="">
			</th>
			<th><% multilang(LANG_OMCI_STATUS); %></th>
			<th>
				<input name="omciStatus" type="text" size="20" maxlength="64" value="">
			</th>
		</tr>
	</table>
</div>
<br>
<div class="adsl clearfix btn_center">
	<input class="link_bg" type="submit" name="exit" value="<% multilang(LANG_MANUAL_SETUP); %>" onClick="return clickExit();">
</div>
</form>
</body>
</html>
