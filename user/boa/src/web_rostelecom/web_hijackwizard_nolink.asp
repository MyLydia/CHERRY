<VWS_FUNCTION (void*)SendWebMetaStr();>
<VWS_FUNCTION (void*)SendWebCssStr();>
<title>Html Wizard</title>

<SCRIPT>
<VWS_FUNCTION (void*)getCurrentLinkState();>
function onload()
{
	if(currentLinkState == 0)
	{
		adslAttempts++;
		document.getElementById("adslAttempts").value = adslAttempts;
	}
}
</SCRIPT>
</head>

<body onload="onload();">
<form action="form2RoseHijackWizardNolink.cgi" method=POST name="RoseHijackWizardNolink">
	<div class="data_common data_common_notitle">
		<table>
			<tr class="data_prompt_info">
				<td colspan="2">
<script>
#if defined(CONFIG_MULTI_ETHUP)
					if(phytype == 1)
					{
						document.write("<% multilang(LANG_CONNECTION_LINE_ETHERNET_PLEASE_CHECK_THE_CORRECT_CONNECTION_OF_THE_ETHERNET_CABLE_AS_SHOWN_BELOW); %>")
					}
#endif
#if defined(CONFIG_MULTI_ETHUP) && defined(CONFIG_ADSLUP)
					else
#endif
#if defined(CONFIG_ADSLUP)
					if(phytype == 0)
					{
						document.write("<% multilang(LANG_CONNECTION_LINE_ADSL_PLEASE_CHECK_THE_CORRECT_CONNECTION_OF_THE_ADSL_CABLE_AS_SHOWN_BELOW); %>")
					}
#endif
</script>
				</td>
			</tr>
		</table>
		<table>
			<tr>
				<td colspan="2" style="text-align:center;">
					<VWS_FUNCTION (void*)getAdslConnJpg();>
				</td>
			</tr>
		</table>
	</div>
	<input type="hidden" name="adslAttempts" id="adslAttempts">
	<br>
	<div class="adsl clearfix btn_center">
		<input class="link_bg" type="submit" value="Continue">
		<!--<input class="link_bg" type="button" value="Manual configuration" onClick="window.location.href='rose_wizard_1.htm';">-->
		<input type="hidden" value="Send" name="submit.htm?rose_hijackwizard_nolink.htm">
	</div>
</form>

</body>

</html>

