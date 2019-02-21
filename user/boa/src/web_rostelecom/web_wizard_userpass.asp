<VWS_FUNCTION (void*)SendWebMetaStr();>
<VWS_FUNCTION (void*)SendWebCssStr();>
<title>Html Wizard</title>
<SCRIPT>

#if defined(CONFIG_ADSLUP) && defined(CONFIG_MULTI_ETHUP)
	<VWS_FUNCTION (void*) vmsGetPhytype();>
#elif defined(CONFIG_ADSLUP)
	var wanphytype = 0;
#else
	var wanphytype = 1;
#endif
#ifdef CONFIG_MULTI_ETHUP
<VWS_FUNCTION (void*)getPPPVLANType();>
#endif

function checkPPPSetting()
{
	if(document.RoseWizardUserPass.pppusername.value == "")
	{
		alert("<% multilang(LANG_USER_NAME_CANNOT_BE_EMPTY); %>");
		document.RoseWizardUserPass.pppusername.focus();
		return false;
	}
#ifdef CONFIG_MULTI_ETHUP
	if(wanphytype == 1)
	{
		if(document.RoseWizardUserPass.ppp_vlan.value != "")
		{
			if(!validateDecimalDigit(document.RoseWizardUserPass.ppp_vlan.value) || !checkDigitRange(document.RoseWizardUserPass.ppp_vlan.value,1,1,4095))
			{
				alert("<% multilang(LANG_INCORRECT_VLAN_ID_SHOULE_BE_1_4095); %>");
				document.RoseWizardUserPass.ppp_vlan.focus();
				return false;
			}
		}
	}
#endif
	return true;
}

function onload()
{
#ifdef CONFIG_MULTI_ETHUP
	if(wanphytype == 1 && show_ppp_vlanid == 1)
		document.getElementById("vlanShow").style.display = "";
#endif
}
</SCRIPT>
</head>

<body onload="onload();">
<form action="form2RoseWizardUserPass.cgi" method=POST name="RoseWizardUserPass">
        <div id="pppoesetting">
	<div class="data_common data_common_notitle">
		<table>
			<tr>
				<th width="25%"><% multilang(LANG_ER_USERNAME); %></th>
				<th>
				<input type="text" name="pppusername">
				</th>
#ifdef CONFIG_MULTI_ETHUP
				<script>
					if(wanphytype == 1)
					{
						document.write("<td rowspan=\"3\" class=\"data_prompt_td_info\">");
					}
					else
					{
						document.write("<td rowspan=\"2\" class=\"data_prompt_td_info\">");
					}
				</script>
#else
				<td rowspan="2" class="data_prompt_td_info">
#endif
#ifdef CONFIG_VENDOR_BAUDTEC
					<% multilang(LANG_OR_691); %>
					<br>
					<% multilang(LANG_PLEASE_ENTER_LOGIN_AND_PASSWORD_FROM_YOUR_ISP); %>
#elif defined(CONFIG_RTC_LAB_TEST_SPECIAL)
					<% multilang(LANG_PPPOE_LOGIN_AND_OR_PASSWORD_IS_WRONG_PLEASE_CHECK_THE_LANGUAGE_PLEASE_CHECK_CAPSLOCK_KEY_CHECK_PPPOE_LOGIN_AND_PASSWORD_AND_TRY_AGAIN); %>
#else
					<% multilang(LANG_PLEASE_INPUT_USERNAME_AND_PASSWORD_RECEIVED_FROM_YOUR_ISP); %>
#endif
				</td>
			</tr>
			<tr>
				<th width="25%"><% multilang(LANG_ENTER_PASSWORD); %></th>
				<th>
				<input type="text" name="ppppassword">
				</th>
			</tr>
#ifdef CONFIG_MULTI_ETHUP
			<tr id="vlanShow" style="display:none;">
				<th width="25%"><% multilang(LANG_VLAN_ID); %></th>
				<th>
				<input type="text" name="vlanid">
				</th>
			</tr>
#endif			
		</table>
	</div>
	<br>
	<div class="adsl clearfix btn_center">
		<input class="link_bg" type="submit" name="continue" value="Next" onClick="return checkPPPSetting();">
	</div>
	</div>

	<input type="hidden" value="Send" name="submit.htm?rose_wizard_userpass.htm">
</form>
<SCRIPT>
</SCRIPT>

</body>

</html>

