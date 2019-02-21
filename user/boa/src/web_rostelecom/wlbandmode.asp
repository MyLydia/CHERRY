<html>
<! Copyright (c) Realtek Semiconductor Corp., 2003. All Rights Reserved. ->
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<title><% multilang(LANG_WIRELESS_BAND_MODE); %><% multilang(LANG_CONFIGURATION); %></title>
<link rel="stylesheet" type="text/css" href="common_style.css" />
</head>
<body>
<blockquote>
<h2 class="page_title"><% multilang(LANG_WIRELESS_BAND_MODE); %><% multilang(LANG_CONFIGURATION); %></font></h2>


<table>
  <tr><font size=2>
  <!--Support switchable 802.11n dual-band radio frequency (2.4GHz/5GHz). -->
  <% multilang(LANG_THIS_PAGE_IS_USED_TO_SWITCH_802_11N_SINGLE_BAND_OR_DUAL_BAND_RADIO_FREQUENCY); %>
  </tr>
  <tr><hr size=1 noshade align=top></tr>
</table>
<form action=/boaform/admin/formWlanBand2G5G method=POST name="fmWlBandMode">
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
		<th valign="top">
		<input type="radio" value="1" name="wlBandMode" onClick="" ></input>
		<% multilang(LANG_SIGNLE_BAND); %>: 
		</th>
		<td>
			<% multilang(LANG_THIS_MODE_CAN_SUPPORT_SINGLE_MODE_BY_2X2); %>
		</td>
	</tr>
	<tr><td colspan="2" height="10"></tr>
<% checkWrite("onoff_dmdphy_comment_start"); %> 
	<tr>
		<th valign="top">
		<input type="radio" value="0" name="wlBandMode" onClick="" ></input>
		<% multilang(LANG_DUAL_BAND); %>: 
		</th>
		<td>
			<% multilang(LANG_THIS_MODE_CAN_SIMULTANEOUSLY_SUPPORT_802_11_A_B_G_N_WIRELESS_NETWORK_CONNECTION); %>
		</td>
	</tr>
<% checkWrite("onoff_dmdphy_comment_end"); %> 

</table>
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
  <input type="hidden" value="/admin/wlbandmode.asp" name="submit-url">
  <p><input type="submit" value="<% multilang(LANG_APPLY_CHANGES); %>" name="apply">
&nbsp;&nbsp;
  <input type="reset" value="<% multilang(LANG_RESET); %>" name="set" >
&nbsp;&nbsp;
</form>
</blockquote>
</font>
</body>

</html>
