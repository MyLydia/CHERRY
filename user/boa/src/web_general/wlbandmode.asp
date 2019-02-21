<%SendWebHeadStr(); %>
<title><% multilang(LANG_WIRELESS_BAND_MODE); %><% multilang(LANG_CONFIGURATION); %></title>

<SCRIPT>
function on_submit()
{
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	return true;
}
</SCRIPT>
</head>

<body>
<div class="intro_main ">
	<p class="intro_title"><% multilang(LANG_WIRELESS_BAND_MODE); %> <% multilang(LANG_CONFIGURATION); %></p>
	<p class="intro_content"> <% multilang(LANG_THIS_PAGE_IS_USED_TO_SWITCH_802_11N_SINGLE_BAND_OR_DUAL_BAND_RADIO_FREQUENCY); %></p>
</div>

<form action=/boaform/admin/formWlanBand2G5G method=POST name="fmWlBandMode">
<div class="data_common data_common_notitle">
	<table>
	<!--
		<tr>
			<td width ="35%" valign="top">
			<input type="radio" value="0" name="wlBandMode" onClick="" ></input>
			<font size=2> <b> 2.4GHz Only: </b> </font>
			</td>
			<td>
				<font size=2>This mode supports 802.11 b/g/n wireless network connection.</font>
			</td>
		</tr>
		<td colspan="2" height="10"></tr>
		<tr>
			<td width ="35%" valign="top">
			<input type="radio" value="1" name="wlBandMode" onClick="" ></input>
			<font size=2> <b> 5GHz Only: </b> </font>
			</td>
			<td>
				<font size=2>This mode supports both 802.11 a/n wireless network connection.</font>
			</td>
		</tr>
		<td colspan="2" height="10"></tr>
	-->	
		<tr>
			<th><% multilang(LANG_SIGNLE_BAND); %>:</th>
			<td>
				<input type="radio" value="1" name="wlBandMode" onClick="" ></input>&nbsp;&nbsp;&nbsp;&nbsp;
				<% multilang(LANG_THIS_MODE_CAN_SUPPORT_SINGLE_MODE_BY_2X2); %>
			</td>
		</tr>
		<% checkWrite("onoff_dmdphy_comment_start"); %> 
		<tr>
			<th><% multilang(LANG_DUAL_BAND); %>:</th>
			<td>
				<input type="radio" value="0" name="wlBandMode" onClick="" ></input>&nbsp;&nbsp;&nbsp;&nbsp;
				<% multilang(LANG_THIS_MODE_CAN_SIMULTANEOUSLY_SUPPORT_802_11_A_B_G_N_WIRELESS_NETWORK_CONNECTION); %>
			</td>
		</tr>
		<% checkWrite("onoff_dmdphy_comment_end"); %> 
	</table>
</div>

<script>
	wlBandMode = <% checkWrite("wlanBand2G5GSelect"); %> ;
	var radioIndex=0;
	while(document.fmWlBandMode.wlBandMode[radioIndex])
	{
		if(document.fmWlBandMode.wlBandMode[radioIndex].value == wlBandMode)
		{
			document.fmWlBandMode.wlBandMode[radioIndex].defaultChecked= true;
			document.fmWlBandMode.wlBandMode[radioIndex].checked= true;
			break;
		}
		radioIndex++;
	}
</script>

<div class="btn_ctl">
  <input type="hidden" value="/admin/wlbandmode.asp" name="submit-url">
  <input class="link_bg" type="submit" value="<% multilang(LANG_APPLY_CHANGES); %>" onClick="return on_submit()">
  <input class="link_bg" type="reset" value="<% multilang(LANG_RESET); %>" name="set" >
  <input type="hidden" name="postSecurityFlag" value="">
</div>
</form>
<br><br>
</body>

</html>
