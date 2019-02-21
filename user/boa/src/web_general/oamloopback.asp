<% SendWebHeadStr();%>
<title><% multilang(LANG_ATM_LOOPBACK_DIAGNOSTICS); %></title>
<SCRIPT>
function isHexDecimal(num)
{
	var string="1234567890ABCDEF";
	if (string.indexOf(num.toUpperCase()) != -1)
	{
		return true;
	}

	return false;
}

function isValidID(val)
{
	for(var i=0; i < val.length; i++)
	{
		if  ((!isHexDecimal(val.charAt(i))))
		{
			return false;
		}
	}

	return true;
}

function goClick(obj)
{
	retval = isValidID(document.oamlb.oam_llid.value);
	if((document.oamlb.oam_llid.value=="")|| (retval==false))
	{
		alert("<% multilang(LANG_INVALID_LOOPBACK_LOCATION_ID); %>");
		document.oamlb.oam_llid.focus()
		return false
	}
	obj.isclick = 1;
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	
	return true;
}
</SCRIPT>
</head>

<body>
<div class="intro_main ">
	<p class="intro_title"><% multilang(LANG_ATM_LOOPBACK_DIAGNOSTICS); %> - <% multilang(LANG_CONNECTIVITY_VERIFICATION); %></p>
	<p class="intro_content"> <% multilang(LANG_CONNECTIVITY_VERIFICATION_IS_SUPPORTED_BY_THE_USE_OF_THE_ATM_OAM_LOOPBACK_CAPABILITY_FOR_BOTH_VP_AND_VC_CONNECTIONS_THIS_PAGE_IS_USED_TO_PERFORM_THE_VCC_LOOPBACK_FUNCTION_TO_CHECK_THE_CONNECTIVITY_OF_THE_VCC); %></p>
</div>

<form action=/boaform/formOAMLB method=POST name="oamlb">
<div class="data_common data_common_notitle">
	<table>
		<tr>
			<th><% multilang(LANG_SELECT); %> PVC:</th>
			<td><% oamSelectList(); %></td>
		</tr>
		<tr>
			<th><% multilang(LANG_FLOW_TYPE); %>:</th>
			<td>
				<input type="radio" value="3" name="oam_flow"><% multilang(LANG_F4_SEGMENT); %>&nbsp;&nbsp;
				<input type="radio" value="4" name="oam_flow" ><% multilang(LANG_F4_END_TO_END); %>&nbsp;&nbsp;
				<input type="radio" value="0" name="oam_flow" checked><% multilang(LANG_F5_SEGMENT); %>&nbsp;&nbsp;
				<input type="radio" value="1" name="oam_flow" ><% multilang(LANG_F5_END_TO_END); %>
			</td>
		</tr>
		<tr>
			<th><% multilang(LANG_LOOPBACK_LOCATION_ID); %></th>
			<td>
				<input type="text" name="oam_llid" value="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" size=40 maxlength=32 onFocus="this.select()">
			</td>
		</tr>
	</table>
</div>
<div class="btn_ctl">
	<input class="link_bg" type="submit" value=" <% multilang(LANG_GO); %> ! " name="go" onClick="return goClick(this)">
	<input type="hidden" value="/oamloopback.asp" name="submit-url">
	<input type="hidden" name="postSecurityFlag" value="">
</div>
</form>
<br><br>
</body>
</html>
