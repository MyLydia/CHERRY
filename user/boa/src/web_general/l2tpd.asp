<%SendWebHeadStr(); %>
<title>L2TP VPN <% multilang(LANG_CONFIGURATION); %></title>

<SCRIPT>
function checkTextStr(obj)
{
	if(obj.value.length > 30){		
		alert('<% multilang(LANG_LENGTH_SHOULD_LESS_THEN_32); %>');
		obj.focus();
		return false;
	}
		
	for (var i=0; i<obj.value.length; i++) 
	{
		if ( obj.value.charAt(i) == '%' || obj.value.charAt(i) =='&' ||obj.value.charAt(i) =='\\' || obj.value.charAt(i) =='?' || obj.value.charAt(i)=='"') 
		{			
			alert('<% multilang(LANG_INVALID_CHARACTER_IN_TEXT_AERA); %>');
			obj.focus();
			return false;
		}
	}
	return true;
}

function l2tpSelection()
{
	if (document.l2tp.l2tpen[0].checked) {
		document.l2tp.s_auth.disabled = true;
		document.l2tp.s_enctype.disabled = true;
		document.l2tp.peeraddr.disabled = true;
		document.l2tp.localaddr.disabled = true;
		document.l2tp.addServer.disabled = true;
		document.l2tp.s_name.disabled = true;
		document.l2tp.tunnelen.disabled = true;
		document.l2tp.s_tunnelAuth.disabled = true;
		document.l2tp.s_authKey.disabled = true;
		document.l2tp.s_username.disabled = true;
		document.l2tp.s_password.disabled = true;
		document.l2tp.addAccount.disabled = true;
		document.l2tp.delSelAccount.disabled = true;
		document.l2tp.saveAccount.disabled = true;
		document.l2tp.c_name.disabled = true;
		document.l2tp.server.disabled = true;
		document.l2tp.username.disabled = true;
		document.l2tp.password.disabled = true;
		document.l2tp.tunnel_auth.disabled = true;
		document.l2tp.tunnel_secret.disabled = true;
		document.l2tp.auth.disabled = true;
		document.l2tp.enctype.disabled = true;
		document.l2tp.pppconntype.disabled = true;
		document.l2tp.idleTime.disabled = true;
		document.l2tp.mtu.disabled = true;
		document.l2tp.defaultgw.disabled = true;
		document.l2tp.addClient.disabled = true;
		document.l2tp.delSelClient.disabled = true;
	}
	else {
		document.l2tp.s_auth.disabled = false;
		document.l2tp.s_enctype.disabled = false;
		document.l2tp.peeraddr.disabled = false;
		document.l2tp.localaddr.disabled = false;
		document.l2tp.addServer.disabled = false;
		document.l2tp.s_name.disabled = false;
		document.l2tp.tunnelen.disabled = false;
		document.l2tp.s_tunnelAuth.disabled = false;
		document.l2tp.s_authKey.disabled = false;
		document.l2tp.s_username.disabled = false;
		document.l2tp.s_password.disabled = false;
		document.l2tp.addAccount.disabled = false;
		document.l2tp.delSelAccount.disabled = false;
		document.l2tp.saveAccount.disabled = false;
		document.l2tp.c_name.disabled = false;
		document.l2tp.server.disabled = false;
		document.l2tp.username.disabled = false;
		document.l2tp.password.disabled = false;
		document.l2tp.tunnel_auth.disabled = false;
		document.l2tp.tunnel_secret.disabled = true;
		document.l2tp.auth.disabled = false;
		document.l2tp.enctype.disabled = false;
		document.l2tp.pppconntype.disabled = false;
		document.l2tp.idleTime.disabled = false;
		document.l2tp.mtu.disabled = false;
		document.l2tp.defaultgw.disabled = false;
		document.l2tp.addClient.disabled = false;
		document.l2tp.delSelClient.disabled = false;
	}
}


function serverAuthClick()
{
	if (document.l2tp.s_auth.value==3) {
		document.l2tp.s_enctype.disabled = false;
	}else
		document.l2tp.s_enctype.disabled = true;
}

function clientAuthClick()
{
	if (document.l2tp.auth.value==3) {
		document.l2tp.enctype.disabled = false;
	}else
		document.l2tp.enctype.disabled = true;
}

function connTypeChange()
{	
	document.l2tp.defaultgw.checked = false;
	document.l2tp.defaultgw.disabled = false;	
	if(document.l2tp.pppconntype.selectedIndex==1)
	{
		document.l2tp.idletime.disabled=false;		
		document.l2tp.defaultgw.checked = true;
		document.l2tp.defaultgw.disabled = true;
	}else{
		document.l2tp.idletime.disabled=true;		
	}
}

function onClickL2tpEnable()
{
	l2tpSelection();
	document.l2tp.lst.value = "enable";
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	document.l2tp.submit();
}

function onClickServerTunnelAuth()
{
	if(document.l2tp.s_tunnelAuth.checked)
		document.l2tp.s_authKey.disabled = false;
	else
		document.l2tp.s_authKey.disabled = true;
}

function onClickClientTunnelAuth()
{
	if(document.l2tp.tunnel_auth.checked)
		document.l2tp.tunnel_secret.disabled = false;
	else
		document.l2tp.tunnel_secret.disabled = true;
}

function setL2tpServer(obj)
{
	if(document.l2tp.l2tpen[0].checked)
		return false;

	if (document.l2tp.peeraddr.value=="") {		
		alert('<% multilang(LANG_PLEASE_ENTER_PEER_START_ADDRESS); %>');
		document.l2tp.peeraddr.focus();
		return false;
	}
	if (!checkHostIP(document.l2tp.peeraddr, 0))
		return false;

	if (document.l2tp.localaddr.value=="") {		
		alert('<% multilang(LANG_PLEASE_ENTER_LOCAL_ADDRESS); %>');
		document.l2tp.localaddr.focus();
		return false;
	}
	if (!checkHostIP(document.l2tp.localaddr, 0))
		return false;

	obj.isclick = 1;
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	
	return true;
}

function addL2tpAccount(obj)
{
	if(document.l2tp.l2tpen[0].checked)
		return false;
	
	if (document.l2tp.s_name.value=="") {		
		alert('<% multilang(LANG_PLEASE_ENTER_L2TP_SERVER_RULE_NAME); %>');
		document.l2tp.s_name.focus();
		return false;
	}

	if(document.l2tp.s_tunnelAuth.checked){
		if(document.l2tp.s_authKey.value ==""){			
			alert('<% multilang(LANG_PLEASE_ENTER_L2TP_TUNNEL_AUTHKEY); %>');
			document.l2tp.s_authKey.focus();
			return false;
		}
		if(!checkTextStr(document.l2tp.s_authKey))
		{
			return false;		
		}
	}

	if (document.l2tp.s_username.value=="")
	{		
		alert('<% multilang(LANG_PLEASE_ENTER_L2TP_SERVER_USERNAME); %>');
		document.l2tp.s_username.focus();
		return false;
	}
	if(!checkTextStr(document.l2tp.s_username))
	{
		return false;		
	}
	
	if (document.l2tp.s_password.value=="") {		
		alert('<% multilang(LANG_PLEASE_ENTER_L2TP_SERVER_PASSWORD); %>');
		document.l2tp.s_password.focus();
		return false;
	}
	if(!checkTextStr(document.l2tp.s_password))
	{
		return false;		
	}

	obj.isclick = 1;
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	
	return true;
}

function addL2tpClient(obj)
{
	if(document.l2tp.l2tpen[0].checked)
		return false;
	if (document.l2tp.c_name.value=="") {		
		alert('<% multilang(LANG_PLEASE_ENTER_L2TP_CLIENT_RULE_NAME); %>');
		document.l2tp.c_name.focus();
		return false;
	}
	if (document.l2tp.server.value=="") {		
		alert('<% multilang(LANG_PLEASE_ENTER_L2TP_SERVER_ADDRESS); %>');
		document.l2tp.server.focus();
		return false;
	}
	
	if(!checkTextStr(document.l2tp.server))
	{
		return false;		
	}

	if (document.l2tp.username.value=="")
	{		
		alert('<% multilang(LANG_PLEASE_ENTER_L2TP_CLIENT_USERNAME); %>');
		document.l2tp.username.focus();
		return false;
	}
	if(!checkTextStr(document.l2tp.username))
	{
		return false;		
	}
	if (document.l2tp.password.value=="") {		
		alert('<% multilang(LANG_PLEASE_ENTER_L2TP_CLIENT_PASSWORD); %>');
		document.l2tp.password.focus();
		return false;
	}
	if(!checkTextStr(document.l2tp.password))
	{
		return false;		
	}

	if(document.l2tp.tunnel_auth.checked){
		if(document.l2tp.tunnel_secret.value ==""){			
			alert('<% multilang(LANG_PLEASE_ENTER_L2TP_TUNNEL_AUTHKEY); %>');
			document.l2tp.tunnel_secret.focus();
			return false;
		}
		if(!checkTextStr(document.l2tp.tunnel_secret))
		{
			return false;		
		}
	}

	if (document.l2tp.mtu.value=="") {               
		alert('<% multilang(LANG_PLEASE_ENTER_L2TP_CLIENT_MTU); %>');
                document.l2tp.mtu.focus();
                return false;
        }

	obj.isclick = 1;
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	
	return true;
}

function on_submit(obj)
{
	obj.isclick = 1;
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	return true;
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
	      	<input type="radio" value="0" name="l2tpen" <% checkWrite("l2tpenable0"); %> onClick="onClickL2tpEnable()"><% multilang(LANG_DISABLE); %>&nbsp;&nbsp;
	     	<input type="radio" value="1" name="l2tpen" <% checkWrite("l2tpenable1"); %> onClick="onClickL2tpEnable()"><% multilang(LANG_ENABLE); %>
	      </td>
	  </tr>
	</table>
	<input type="hidden" id="lst" name="lst" value="">
</div>

<div class="column">
	<div class="column_title">
		<div class="column_title_left"></div>
			<p>L2TP Server</p>
		<div class="column_title_right"></div>
	</div>
	<div class="data_common">
		<table>
			<tr>
				<th>Auth. Type:</th>
				<td>
					<select name="s_auth" onClick="serverAuthClick()">
						<option value="0">Auto</option>
						<option value="1">PAP</option>
						<option value="2">CHAP</option>
						<option value="3">MS-CHAPV2</option>
					</select>
				</td>
			</tr>
			<tr>
				<th>Encryption Mode:</th>
				<td>
					<select name="s_enctype" >
						<option value="0"><% multilang(LANG_NONE); %></option>
						<option value="1">MPPE</option>
						<option value="2">MPPC</option>
						<option value="3">MPPE&MPPC</option>
					</select>
				</td>
			</tr>
			<tr>
				<th>Tunnel with Auth:</th>
				<td><input type="checkbox" name="s_tunnelAuth" value="1" onClick="onClickServerTunnelAuth()"></td>
			</tr>
			<tr>
				<th>Auth. Key:</th>
				<td><input type="text" name="s_authKey" size="16" maxlength="256"></td>
			</tr>
			<tr>
				<th>Peer Address:</th>
				<td>start from:<input type="text" name="peeraddr" size="16" maxlength="80"></td>
			</tr>
			<tr>
				<th>Local Address:</th>
				<td><input type="text" name="localaddr" size="16" maxlength="80"></td>
			</tr>
		</table>
	</div>
</div>

<div class="btn_ctl">
	<input class="link_bg" type="submit" value="Apply" name="addServer" onClick="return setL2tpServer(this)">
</div>

<div class="column">
	<div class="column_title">
		<div class="column_title_left"></div>
			<p>Server Account</p>
		<div class="column_title_right"></div>
	</div>
	<div class="data_common">
		<table>
			<tr>
				<th>Name:</th>
				<td><input type="text" name="s_name" size="16" maxlength="256"></td>
			</tr>
			<tr>
				<th>Tunnel:</th>
				<td>
					<input type="radio" value="0" name="tunnelen"><% multilang(LANG_DISABLE); %>&nbsp;&nbsp;
					<input type="radio" value="1" name="tunnelen" checked><% multilang(LANG_ENABLE); %>
				</td>
			</tr>
			<tr>
				<th>Username:</th>
				<td><input type="text" name="s_username" size="16" maxlength="256"></td>
			</tr>
			<tr>
				<th>Password:</th>
				<td><input type="text" name="s_password" size="16" maxlength="256"></td>
			</tr>	
		</table>
	</div>
</div>
<div class="btn_ctl">
	<input class="link_bg" type="submit" value="Add" name="addAccount" onClick="return addL2tpAccount(this)">
</div>

<div class="column">
	<div class="column_title">
		<div class="column_title_left"></div>
			<p>L2TP Server Table</p>
		<div class="column_title_right"></div>
	</div>
	<div class="data_common">
		<table>
			<tr>
				<th align=center><% multilang(LANG_SELECT); %></th>
				<th align=center><% multilang(LANG_NAME); %></th>
				<th align=center><% multilang(LANG_ENABLE); %></th>
				<th align=center><% multilang(LANG_USERNAME); %></th>
				<th align=center><% multilang(LANG_PASSWORD); %></th>
			</tr>
			<% l2tpServerList(); %>
		</table>
	</div>
</div>

<div class="column">
	<div class="column_title">
		<div class="column_title_left"></div>
			<p>L2TP Client</p>
		<div class="column_title_right"></div>
	</div>
	<div class="data_common">
		<table>
			<tr>
				<th>Name:</th>
				<td><input type="text" name="c_name" size="16" maxlength="256"></td>
			</tr>
			<tr>
				<th>Server Address:</th>
				<td><input type="text" name="server" size="16" maxlength="256"></td>
			</tr>
			<tr>
				<th>Username:</th>
				<td><input type="text" name="username" size="16" maxlength="256"></td>
			</tr>
			<tr>
				<th>Password:</th>
				<td><input type="text" name="password" size="16" maxlength="256"></td>
			</tr>
			<tr>
				<th>Tunnel with Auth:</th>
				<td><input type="checkbox" name="tunnel_auth" value="1" onClick="onClickClientTunnelAuth()"></td>
			</tr>
			<tr>
				<th>Auth. Key:</th>
				<td><input type="text" name="tunnel_secret" size="16" maxlength="256"></td>
			</tr>
			<tr>
				<th>Auth. Type:</th>
				<td>
					<select name="auth" onClick="clientAuthClick()">
						<option value="0">Auto</option>
						<option value="1">PAP</option>
						<option value="2">CHAP</option>
						<option value="3">MS-CHAPV2</option>
					</select>
				</td>
			</tr>
			<tr>
				<th>Encryption Mode:</th>
				<td>
					<select name="enctype" >
						<option value="0"><% multilang(LANG_NONE); %></option>
						<option value="1">MPPE</option>
						<option value="2">MPPC</option>
						<option value="3">MPPE&MPPC</option>
					</select>
				</td>
			</tr>
			<tr>
				<th>PPP Connection Type:</th>
				<td>
					<select name="pppconntype" onChange="connTypeChange()">
						<option value="0"><% multilang(LANG_PERSISTENT); %></option>
						<option value="1"><% multilang(LANG_DIAL_ON_DEMAND); %></option>
						<option value="2"><% multilang(LANG_MANUAL); %></option>
						<option value="3"><% multilang(LANG_NONE); %></option>
					</select>
				</td>
			</tr>
			<tr>
				<th>Idle Time (min):</th>
				<td><input type="text" name="idleTime" size="16" maxlength="256"></td>
			</tr>
			<tr>
				<th>MTU:</td>
				<td><input type="text" name="mtu" size="16" maxlength="256"></td>
			</tr>
			<tr>
				<th>Default Gateway:</th>
				<td><input type="checkbox" name="defaultgw"></td>
			</tr>
		</table>
	</div>
</div>

<div class="btn_ctl">
	<input class="link_bg" type="submit" value="Add" name="addClient" onClick="return addL2tpClient(this)">
</div>

<div class="column">
	<div class="column_title">
		<div class="column_title_left"></div>
			<p>L2TP Client Table</p>
		<div class="column_title_right"></div>
	</div>
	<div class="data_common">
		<table>
			<tr>
				<th align=center width="3%"><% multilang(LANG_SELECT); %></th>
				<th align=center width="5%"><% multilang(LANG_NAME); %></th>
				<th align=center width="5%"><% multilang(LANG_SERVER); %></th>
				<th align=center width="5%"><% multilang(LANG_TUNNEL_AUTH); %></th>
				<th align=center width="5%"><% multilang(LANG_PPP_AUTH); %></th>
				<th align=center width="5%">MTU</th>
				<th align=center width="5%"><% multilang(LANG_DEFAULT_GATEWAY); %></th>
				<th align=center width="8%"><% multilang(LANG_ACTION); %></th>
			</tr>
			<% l2tpList(); %>
		</table>
	</div>
</div>

<div class="btn_ctl">
	<input class="link_bg" type="submit" value="<% multilang(LANG_DELETE_SELECTED); %>" name="delSelClient" onClick="return on_submit(this)">&nbsp;&nbsp;
	<input type="hidden" value="/l2tpd.asp" name="submit-url">
	<input type="hidden" name="postSecurityFlag" value="">
</div>
<script>
	<% initPage("l2tp"); %>
	l2tpSelection();
</script>
</form>
</body>
</html>
