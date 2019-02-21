<% SendWebHeadStr();%>
<title><% multilang(LANG_WAN_MODE_SELECTION); %></title>
<script language="javascript">
function SubmitWANMode(obj)
{
	var wmmap = 0;

	with (document.forms[0])
	{	

		for(var i = 0; i < 5; i ++)
			if(wmchkbox[i].checked == true)
				//wmmap |= (0x1 << i);
				wmmap |= wmchkbox[i].value;
			
		if(wmmap == 0 || wmmap == wanmode)
			return false;
		wan_mode.value = wmmap;
	}
	if(confirm("<% multilang(LANG_IT_NEEDS_REBOOTING_TO_CHANGE_WAN_MODE); %>"))
	{	
		obj.isclick = 1;
		postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
		return true;
	}
	else
		return false;
}
</script>

</head>

<BODY>
<div class="intro_main ">
	<p class="intro_title"><% multilang(LANG_WAN_MODE); %></p>
	<p class="intro_content"><% multilang(LANG_THIS_PAGE_IS_USED_TO_CONFIGURE_WHICH_WAN_TO_USE_OF_YOUR_ROUTER); %></p>
</div>
<form action=/boaform/admin/formWanMode method=POST name="wanmode">
<div class="data_common data_common_notitle">
	<table>
		<tr>
			<th width="25%"><% multilang(LANG_WAN_MODE); %>:</th>
			<td>
				<span <% checkWrite("wan_mode_atm"); %>><input type="checkbox" value=1 name="wmchkbox">ATM&nbsp;&nbsp;</span>
				<span <% checkWrite("wan_mode_ethernet"); %>><input type="checkbox" value=2 name="wmchkbox">Ethernet&nbsp;&nbsp;</span>
				<span <% checkWrite("wan_mode_ptm"); %>><input type="checkbox" value=4 name="wmchkbox">PTM&nbsp;&nbsp;</span>
				<span <% checkWrite("wan_mode_bonding"); %>><input type="checkbox" value=8 name="wmchkbox">PTM BONDING&nbsp;&nbsp;</span>
				<span <% checkWrite("wan_mode_wireless"); %>><input type="checkbox" value=16 name="wmchkbox" <% ShowWanMode("wlan"); %>>Wireless</span>
				<input type="hidden" name="wan_mode" value=0>
				<input type="submit" value="Submit" name="submitwan" onClick="return SubmitWANMode(this)">
			</td>
		</tr>
	</table>
</div>
<div class="btn_ctl">
	<input type="hidden" value="/wanmode.asp" name="submit-url">
	<input type="hidden" name="postSecurityFlag" value="">
</div>
<script>
	var wanmode = <% getInfo("wan_mode"); %>;

	if((wanmode & 1) == 1)
		document.wanmode.wmchkbox[0].checked = true;

	if((wanmode & 2) == 2)
		document.wanmode.wmchkbox[1].checked = true;
	
	if((wanmode & 4) == 4){
		document.wanmode.wmchkbox[2].checked = true;
		if((wanmode & 8) == 8)
			document.wanmode.wmchkbox[3].checked = true;
	}

	if((wanmode & 16) == 16)
		document.wanmode.wmchkbox[4].checked = true;
</script>
</form>
</body>
</html>
