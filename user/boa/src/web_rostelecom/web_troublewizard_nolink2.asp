<VWS_FUNCTION (void*)SendWebMetaStr();>
<VWS_FUNCTION (void*)SendWebCssStr();>
<title>Html Wizard</title>

</head>

<body>
	<div class="data_common data_common_notitle">
		<table>
			<tr class="data_prompt_info">
				<th colspan="4" style="color:red; font-size:20px;">
					<% multilang(LANG_PLEASE_CHECK_THE_CORRECTNESS_OF_SUPPORT_OF_JSC_ROSTELECOM); %>
				</th>
			</tr>
			<tr>
				<td colspan="4" class="data_prompt_td_info">
					<% multilang(LANG_NO_CONNECTION_TO_THE_INTERNET_TRY_AGAIN_LATER_IF_THE_PROBLEM_PERSISTS_CONTACT_TECHNICAL_SUPPORT_OF_JSC_ROSTELECOM); %>
				</td>
			</tr>
			<tr>
				<th width="25%" style="padding-top:50px;"><% multilang(LANG_DEVICE_MODEL); %></th>
				<td width="25%" style="padding-top:50px;">
				<VWS_SCREEN (char*)xscrnRoseModelName[];>
				</td>
				<th width="25%" style="padding-top:50px;"><% multilang(LANG_PPPOE_USER_NAME); %></th>
				<td width="25%" style="padding-top:50px;">
				<VWS_SCREEN (char*)xscrnRoseTroublePPPUsername[];>
				</td>
			</tr>
			<tr>
				<th width="25%"><% multilang(LANG_FIRMWARE_VERSION); %></th>
				<td>
				<VWS_SCREEN (char*)xscrnHwVersion[];>		
				</td>
				<th><% multilang(LANG_PPPOE_PASSWORD); %></th>
				<td>
				<VWS_SCREEN (char*)xscrnRoseTroublePPPPassword[];>
				</td>
			</tr>
			<tr>
				<th width="25%"><% multilang(LANG_SOFTWARE_VERSION); %></th>
				<td>
				<VWS_SCREEN (char*)xscrnAppVersion[];>			
				</td>
				<th><% multilang(LANG_SERVICE_INFORMATION); %></th>
				<td>
				<VWS_SCREEN (char*)xscrnRoseTroubleServiceInfo[];>
				</td>
			</tr>
			<tr>
				<th width="25%"><% multilang(LANG_MAC_ADDRESS); %></th>
				<td>
				<VWS_SCREEN (char*)xscrnRoseWANMAC[];>
				</td>
				<th><% multilang(LANG_SERIAL_NUMBER); %></th>
				<td>
				<VWS_SCREEN (char*)xscrnRoseSerial[];>
				</td>
			</tr>
		</table>
	</div>
	<br>
	<div class="adsl clearfix btn_center">
		<input class="link_bg" type="button" name="close" value="Configure device manually" onClick="top.location.href='index.htm';" >
	</div>

</body>

</html>
