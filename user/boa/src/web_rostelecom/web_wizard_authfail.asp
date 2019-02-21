<VWS_FUNCTION (void*)SendWebMetaStr();>
<VWS_FUNCTION (void*)SendWebCssStr();>
<title>Html Wizard</title>

<SCRIPT>
#if defined(CONFIG_ADSLUP) && defined(CONFIG_MULTI_ETHUP)
	<VWS_FUNCTION (void*) vmsGetPhytype(); >
#elif defined(CONFIG_ADSLUP)
	var wanphytype = 0;
#else
	var wanphytype = 1;
#endif
</SCRIPT>
</head>

<body>
	<div class="data_common data_common_notitle">
		<table>
#ifdef CONFIG_VENDOR_SAGEMCOM
			<tr class="data_prompt_info">
				<th colspan="4" style="color:red; font-size:20px;">
					<% multilang(LANG_INTERNET_IS_OK); %>
				</th>
			</tr>
			<tr>
				<td colspan="4" class="data_prompt_td_info">
					<% multilang(LANG_NO_CONNECTION_TO_THE_INTERNET_TRY_AGAIN_TRY_TO_CONNECT_LATER_IF_THE_PROBLEM_PERSISTS_CONTACT_TECHNICAL_SUPPORT_OF_JSC_ROSTELECOM); %>
			        </td>
			</tr>
#else
			<tr class="data_prompt_info">
				<th colspan="4" style="color:red; font-size:20px;">
					<% multilang(LANG_UNABLE_TO_CONNECT_NETWORK); %>
				</th>
			</tr>
			<tr>
				<td colspan="4" class="data_prompt_td_info">
<script>
#if defined(CONFIG_MULTI_ETHUP)
				if(wanphytype == 1)
					document.write("<% multilang(LANG_PLEASE_MAKE_SURE_THAT_ETHERNET_CABLE_CONNECTION_CONNECTED_PROPERLY_AS_SHOWN_BELOW_IF_THE_PROBLEM_PERSISTS_CONTACT_TECHNICAL_SUPPORT_OF_JSC_ROSTELECOM); %>");
#endif
#if defined(CONFIG_ADSLUP) && defined(CONFIG_MULTI_ETHUP)
				else
#endif
#if defined(CONFIG_ADSLUP)
				if(wanphytype == 0)
					document.write("<% multilang(LANG_PLEASE_MAKE_SURE_THAT_ADSL_CABLE_CONNECTION_CONNECTED_PROPERLY_AS_SHOWN_BELOW_IF_THE_PROBLEM_PERSISTS_CONTACT_TECHNICAL_SUPPORT_OF_JSC_ROSTELECOM); %>");
#endif
</script>
				</td>
			</tr>
#endif
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
#ifdef CONFIG_RESERVE_DEFAULT_MAC
				<VWS_SCREEN (char*)xscrnRoseReserveMAC[];>
#else
				<VWS_SCREEN (char*)xscrnRoseWANMAC[];>
#endif
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
	        <input class="link_bg" type="button" name="next" value="Next" onClick="window.location.href='rose_wizard_2.htm';">
		<input class="link_bg" type="button" name="close" value="Configure device manually" onClick="top.location.href='index.htm';" >
	</div>

</body>

</html>
