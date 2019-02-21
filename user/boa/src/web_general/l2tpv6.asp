<%SendWebHeadStr(); %>
<title>L2TP VPN <% multilang(LANG_CONFIGURATION); %></title>

<SCRIPT>
function checkTextStr(str)
{
	for (var i=0; i<str.length; i++) 
	{
		if ( str.charAt(i) == '%' || str.charAt(i) =='&' ||str.charAt(i) =='\\' || str.charAt(i) =='?' || str.charAt(i)=='"') 
			return false;			
	}
	return true;
}

function pppAuthChange()
{
	if (document.l2tp.auth.selectedIndex==3)
	{
		document.l2tp.enctype.disabled = false;
	}
	else
	{
		document.l2tp.enctype.disabled = true;
	}
}

function tunnelAuthChange()
{
	if (document.l2tp.tunnel_auth.checked)
		document.l2tp.tunnel_secret.disabled = false;
	else
		document.l2tp.tunnel_secret.disabled = true;
}

function connTypeChange()
{
	if(document.l2tp.pppconntype.selectedIndex==1)
	{
		document.l2tp.idletime.disabled=false;
	}else{
		document.l2tp.idletime.disabled=true;
	}
}

function l2tpSelection()
{
	if (document.l2tp.l2tpen[0].checked) {
		document.l2tp.IpProtocolType.disabled = true;
		document.l2tp.server.disabled = true;
		document.l2tp.tunnel_auth.disabled = true;
		document.l2tp.tunnel_secret.disabled = true;
		document.l2tp.auth.disabled = true;
		document.l2tp.username.disabled = true;
		document.l2tp.password.disabled = true;
		document.l2tp.pppconntype.disabled = true;
		document.l2tp.idletime.disabled = true;
		document.l2tp.mtu.disabled = true;
		document.l2tp.defaultgw.disabled = true;
		document.l2tp.addL2TP.disabled = true;
		document.l2tp.enctype.disabled = true;
	}
	else {
		document.l2tp.IpProtocolType.disabled = false;
		document.l2tp.server.disabled = false;
		document.l2tp.tunnel_auth.disabled = false;
		document.l2tp.tunnel_secret.disabled = false;
		document.l2tp.auth.disabled = false;
		document.l2tp.username.disabled = false;
		document.l2tp.password.disabled = false;
		document.l2tp.pppconntype.disabled = false;
		document.l2tp.idletime.disabled = false;
		document.l2tp.mtu.disabled = false;
		document.l2tp.defaultgw.disabled = false;
		document.l2tp.addL2TP.disabled = false;
		document.l2tp.enctype.disabled = false;
	}
	tunnelAuthChange();
	pppAuthChange();
	connTypeChange()
}

function onClickL2TPEnable()
{
	l2tpSelection();
	
	if (document.l2tp.l2tpen[0].checked)
		document.l2tp.lst.value = "disable";
	else
		document.l2tp.lst.value = "enable";
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	document.l2tp.submit();
}

function addL2TPItf(obj)
{
	if(document.l2tp.l2tpen[0].checked)
		return false;
	
	if (document.l2tp.server.value=="") {		
		alert('<% multilang(LANG_PLEASE_ENTER_L2TP_SERVER_ADDRESS); %>');
		document.l2tp.server.focus();
		return false;
	}

	if (document.l2tp.IpProtocolType.value == 2)
	{
		if (! isGlobalIpv6Address( document.l2tp.server.value) )
		{			
			alert('<% multilang(LANG_PLEASE_INPUT_IPV6_ADDRESS); %>');
			document.l2tp.server.focus();
			return false;
		}
	}
	else if (document.l2tp.IpProtocolType.value == 1)
	{
		if (!checkTextStr(document.l2tp.server.value))
		{			
			alert('<% multilang(LANG_PLEASE_INPUT_IPV4_ADDRESS); %>');
			document.l2tp.server.focus();
			return false;
		}
	}

	if (document.l2tp.tunnel_auth.checked)
	{
		if (document.l2tp.tunnel_secret.value=="")
		{			
			alert('<% multilang(LANG_PLEASE_ENTER_L2TP_TUNNEL_AUTHENTICATION_SECRET); %>');
			document.l2tp.tunnel_secret.focus();
			return false;
		}
		if(!checkTextStr(document.l2tp.tunnel_secret.value))
		{			
			alert('<% multilang(LANG_INVALID_VALUE_IN_TUNNEL_AUTHENTICATION_SECRET); %>');
			document.l2tp.tunnel_secret.focus();
			return false;		
		}
	}
	
	if (document.l2tp.auth.selectedIndex!=3)
	{
		if (document.l2tp.username.value=="")
		{			
			alert('<% multilang(LANG_PLEASE_ENTER_L2TP_CLIENT_USERNAME); %>');
			document.l2tp.username.focus();
			return false;
		}
		if(!checkTextStr(document.l2tp.username.value))
		{			
			alert('<% multilang(LANG_INVALID_VALUE_IN_USERNAME); %>');
			document.l2tp.username.focus();
			return false;		
		}
		if (document.l2tp.password.value=="") {			
			alert('<% multilang(LANG_PLEASE_ENTER_L2TP_CLIENT_PASSWORD); %>');
			document.l2tp.password.focus();
			return false;
		}
		if(!checkTextStr(document.l2tp.password.value))
		{
			alert('<% multilang(LANG_INVALID_VALUE_IN_PASSWORD); %>');
			document.l2tp.password.focus();
			return false;		
		}
	}

	if (document.l2tp.pppconntype.selectedIndex==1)
	{
		if (document.l2tp.idletime.value=="")
		{			
			alert('<% multilang(LANG_PLEASE_ENTER_L2TP_TUNNEL_IDLE_TIME); %>');
			document.l2tp.idletime.focus();
			return false;
		}
	}

	if (document.l2tp.mtu.value=="")
	{		
		alert('<% multilang(LANG_PLEASE_ENTER_L2TP_TUNNEL_MTU); %>');
		document.l2tp.mtu.focus();
		return false;
	}

	obj.isclick = 1;
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	
	return true;
}

function deleteClick(obj)
{
	if ( !confirm('<% multilang(LANG_CONFIRM_DELETE_ONE_ENTRY); %>') ) {
		return false;
	}
	else{
		obj.isclick = 1;
		postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
		return true;
	}
}
</SCRIPT>
</head>

<body>
<div class="intro_main ">
	<p class="intro_title">L2TP VPN <% multilang(LANG_CONFIGURATION); %></p>
	<p class="intro_content"> <% multilang(LANG_THIS_PAGE_IS_USED_TO_CONFIGURE_THE_PARAMETERS_FOR_L2TP_MODE_VPN); %></p>
</div>

<form action=/boaform/formL2TP method=POST name="l2tp">
<div class="data_common data_common_notitle">
	<table>
		<tr>
			<th>L2TP VPN:</th>
			<td>
				<input type="radio" value="0" name="l2tpen" <% checkWrite("l2tpenable0"); %> onClick="onClickL2TPEnable()"><% multilang(LANG_DISABLE); %>&nbsp;&nbsp;
				<input type="radio" value="1" name="l2tpen" <% checkWrite("l2tpenable1"); %> onClick="onClickL2TPEnable()"><% multilang(LANG_ENABLE); %>
			</td>
		</tr>
	</table>
</div>
<input type="hidden" id="lst" name="lst" value="">

<div class="data_common data_common_notitle">
	<table>
		<tr>
			<th>IP <% multilang(LANG_PROTOCOL); %>:</th>
			<td><select id="IpProtocolType" style="WIDTH: 130px" onChange="protocolChange()" name="IpProtocolType">
					<option value="1" > IPv4</option>
					<option value="2" > IPv6</option>
				</select>
			</td>
		</tr>
		<tr>
			<th><% multilang(LANG_SERVER); %>:</th>
			<td><input type="text" name="server" size="32" maxlength="256"></td>
		</tr>
		<tr>
			<th><% multilang(LANG_TUNNEL_AUTHENTICATION); %>:</th>
			<td><input type=checkbox name="tunnel_auth" value=1 onClick=tunnelAuthChange()></td>
		</tr>
		<tr>
			<th><% multilang(LANG_TUNNEL_AUTHENTICATION_SECRET); %>:</th>
			<td><input type="text" name="tunnel_secret" size="15" maxlength="35"></td>
		</tr>
		<tr>
			<th>PPP <% multilang(LANG_AUTHENTICATION); %>:</th>
			<td><select name="auth" onChange="pppAuthChange()">
					<option value="0"><% multilang(LANG_AUTO); %></option>
					<option value="1">PAP</option>
					<option value="2">CHAP</option>
					<option value="3">CHAPMSV2</option>
				</select>
			</td>
		</tr>
		<tr>
			<th>PPP <% multilang(LANG_ENCRYPTION); %>:</th>
			<td><select name="enctype" >
					<option value="0"><% multilang(LANG_NONE); %></option>
					<option value="1">MPPE</option>
					<option value="2">MPPC</option>
					<option value="3">MPPE&MPPC</option>
				</select>
			</td>
		</tr>
		<tr>
			<th><% multilang(LANG_USER); %><% multilang(LANG_NAME); %>:</th>
			<td><input type="text" name="username" size="15" maxlength="35"></td>
		</tr>
		<tr>
			<th><% multilang(LANG_PASSWORD); %>:</th>
			<td><input type="text" name="password" size="15" maxlength="35"></td>
		</tr>
		<tr>
			<th>PPP <% multilang(LANG_CONNECTION_TYPE); %>:</th>
			<td><select name="pppconntype" onChange="connTypeChange()">
					<option value="0"><% multilang(LANG_PERSISTENT); %></option>
					<option value="1"><% multilang(LANG_DIAL_ON_DEMAND); %></option>
					<option value="2"><% multilang(LANG_MANUAL); %></option>
					<option value="3"><% multilang(LANG_NONE); %></option>
				</select>
			</td>
		</tr>
		<tr>
			<th><% multilang(LANG_IDLE_TIME_MIN); %>:</th>
			<td><input type="text" name="idletime" size="32" maxlength="256"></td>
		</tr>
		<tr>
			<th>MTU:</th>
			<td><input type="text" name="mtu" size="32" maxlength="256" value="1458"></td>
		</tr>
		<tr>
			<th><% multilang(LANG_DEFAULT_GATEWAY); %>:</th>
			<td><input type="checkbox" name="defaultgw"></td>
		</tr>
	</table>
</div>

<div class="btn_ctl">
      <input class="link_bg" type="submit" value="<% multilang(LANG_APPLY_CHANGES); %>" name="addL2TP" onClick="return addL2TPItf(this)">&nbsp;&nbsp;
</div>

<div class="column">
	<div class="column_title">
		<div class="column_title_left"></div>
			<p>L2TP <% multilang(LANG_TABLE); %></p>
		<div class="column_title_right"></div>
	</div>
	<div class="data_common">
		<table>
			<tr>
				<th align=center width="3%"><% multilang(LANG_SELECT); %></th>
				<th align=center width="5%"><% multilang(LANG_INTERFACE); %></th>
				<th align=center width="5%"><% multilang(LANG_SERVER); %></th>
				<th align=center width="5%"><% multilang(LANG_TUNNEL_AUTHENTICATION); %></th>
				<th align=center width="5%">PPP <% multilang(LANG_AUTHENTICATION); %></th>
				<th align=center width="5%">MTU</th>
				<th align=center width="5%"><% multilang(LANG_DEFAULT_GATEWAY); %></th>
				<th align=center width="8%"><% multilang(LANG_ACTION); %></th>
			</tr>
			<% l2tpList(); %>
		</table>
	</div>
</div>

<div class="btn_ctl">
	<input class="link_bg" ype="submit" value="<% multilang(LANG_DELETE_SELECTED); %>" name="delSel" onClick="return deleteClick(this)">&nbsp;&nbsp;
	<input type="hidden" value="/l2tpv6.asp" name="submit-url">
	<input type="hidden" name="postSecurityFlag" value="">
</div>
<script>
	l2tpSelection();
</script>
</form> 
</body>
</html>
