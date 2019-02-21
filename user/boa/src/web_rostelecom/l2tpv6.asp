<html>
<! Copyright (c) Realtek Semiconductor Corp., 2003. All Rights Reserved. ->
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<title>L2TP VPN <% multilang(LANG_CONFIGURATION); %></title>
<link rel="stylesheet" type="text/css" href="common_style.css"/>
<script type="text/javascript" src="share.js">
</script>
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
	
	document.l2tp.submit();
}

function addL2TPItf()
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

	return true;
}

</SCRIPT>
</head>

<body>
<blockquote>
<h2 class="page_title">L2TP VPN <% multilang(LANG_CONFIGURATION); %></h2>

<form action=/boaform/formL2TP method=POST name="l2tp">
<table>
  <tr><font size=2>
    <% multilang(LANG_THIS_PAGE_IS_USED_TO_CONFIGURE_THE_PARAMETERS_FOR_L2TP_MODE_VPN); %>
  </tr>
  <tr><hr size=1 noshade align=top></tr>

  <tr>
      <th>L2TP VPN:</th>
      <td>
      	<input type="radio" value="0" name="l2tpen" <% checkWrite("l2tpenable0"); %> onClick="onClickL2TPEnable()"><% multilang(LANG_DISABLE); %>&nbsp;&nbsp;
     	<input type="radio" value="1" name="l2tpen" <% checkWrite("l2tpenable1"); %> onClick="onClickL2TPEnable()"><% multilang(LANG_ENABLE); %>
      </td>
  </tr>
</table>
<input type="hidden" id="lst" name="lst" value="">
<br>

<table>
  <tr>
    <th>IP <% multilang(LANG_PROTOCOL); %>:</th>
    <td><select id="IpProtocolType" style="WIDTH: 130px" onChange="protocolChange()" name="IpProtocolType">
      <option value="1" > IPv4</option>
      <option value="2" > IPv6</option>
	</select></td>
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

<table>
  </tr>
      <td><input type="submit" value="<% multilang(LANG_APPLY_CHANGES); %>" name="addL2TP" onClick="return addL2TPItf()">&nbsp;&nbsp;</td>
  </tr>
</table>
<br><br>

<table>
  <tr><font size=2><b>L2TP <% multilang(LANG_TABLE); %>:</b></font></tr>
  <tr>
    <td align=center width="3%" bgcolor="#808080"><font size=2><% multilang(LANG_SELECT); %></font></td>
    <td align=center width="5%" bgcolor="#808080"><font size=2><% multilang(LANG_INTERFACE); %></font></td>
    <td align=center width="5%" bgcolor="#808080"><font size=2><% multilang(LANG_SERVER); %></font></td>
    <td align=center width="5%" bgcolor="#808080"><font size=2><% multilang(LANG_TUNNEL_AUTHENTICATION); %></font></td>
    <td align=center width="5%" bgcolor="#808080"><font size=2>PPP <% multilang(LANG_AUTHENTICATION); %></font></td>
    <td align=center width="5%" bgcolor="#808080"><font size=2>MTU</font></td>
    <td align=center width="5%" bgcolor="#808080"><font size=2><% multilang(LANG_DEFAULT_GATEWAY); %></font></td>
    <td align=center width="8%" bgcolor="#808080"><font size=2><% multilang(LANG_ACTION); %></font></td>
  </tr>
	<% l2tpList(); %>
</table>
<br>
<input type="submit" value="<% multilang(LANG_DELETE_SELECTED); %>" name="delSel" onClick="return deleteClick()">&nbsp;&nbsp;
<input type="hidden" value="/l2tpv6.asp" name="submit-url">
<script>
	l2tpSelection();
</script>
</form>
</blockquote>
</body>
</html>
