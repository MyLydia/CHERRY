<%SendWebHeadStr(); %>
<title>PPTP VPN <% multilang(LANG_CONFIGURATION); %></title>

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

function pptpSelection()
{
	if (document.pptp.pptpen[0].checked) {
		document.pptp.s_auth.disabled = true;
		document.pptp.s_enctype.disabled = true;
		document.pptp.s_name.disabled = true;
		document.pptp.peeraddr.disabled = true;
		document.pptp.localaddr.disabled = true;
		document.pptp.tunnelen.disabled = true;
		document.pptp.s_username.disabled = true;
		document.pptp.s_password.disabled = true;
		document.pptp.delSelAccount.disabled = true;
		document.pptp.saveAccount.disabled = true;
		document.pptp.addServer.disabled = true;
		document.pptp.addAccount.disabled = true;
		document.pptp.c_name.disabled = true;
		document.pptp.c_username.disabled = true;
		document.pptp.c_password.disabled = true;
		document.pptp.c_auth.disabled = true;
		document.pptp.c_enctype.disabled = true;
		document.pptp.defaultgw.disabled = true;
		document.pptp.addClient.disabled = true;
		document.pptp.delSelClient.disabled = true;
	}
	else {
		document.pptp.s_auth.disabled = false;
		document.pptp.s_enctype.disabled = false;
		document.pptp.s_name.disabled = false;
		document.pptp.peeraddr.disabled = false;
		document.pptp.localaddr.disabled = false;
		document.pptp.tunnelen.disabled = false;
		document.pptp.s_username.disabled = false;
		document.pptp.s_password.disabled = false;
		document.pptp.addServer.disabled = false;
		document.pptp.addAccount.disabled = false;
		document.pptp.delSelAccount.disabled = false;
		document.pptp.saveAccount.disabled = false;
		document.pptp.c_name.disabled = false;
		document.pptp.c_username.disabled = false;
		document.pptp.c_password.disabled = false;
		document.pptp.c_auth.disabled = false;
		document.pptp.c_enctype.disabled = false;
		document.pptp.defaultgw.disabled = false;
		document.pptp.addClient.disabled = false;
		document.pptp.delSelClient.disabled = false;
	}
}


function serverEncryClick()
{
	if (document.pptp.s_auth.value==3) {
		document.pptp.s_enctype.disabled = false;
	}else
		document.pptp.s_enctype.disabled = true;
}

function clientEncryClick()
{
	if (document.pptp.c_auth.value==3) {
		document.pptp.c_enctype.disabled = false;
	}else
		document.pptp.c_enctype.disabled = true;
}

function onClickPPtpEnable()
{
	pptpSelection();
	document.pptp.lst.value = "enable";
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	document.pptp.submit();
}

function setPptpServer(obj)
{
	if(document.pptp.pptpen[0].checked)
		return false;

	if (document.pptp.peeraddr.value=="") {
		alert("<% multilang(LANG_PLEASE_ENTER_PEER_START_ADDRESS); %>");
		document.pptp.peeraddr.focus();
		return false;
	}
	if (!checkHostIP(document.pptp.peeraddr, 0))
		return false;

	if (document.pptp.localaddr.value=="") {
		alert("<% multilang(LANG_PLEASE_ENTER_LOCAL_ADDRESS); %>");
		document.pptp.localaddr.focus();
		return false;
	}
	if (!checkHostIP(document.pptp.localaddr, 0))
		return false;

	obj.isclick = 1;
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	
	return true;
}

function addPptpAccount(obj)
{
	if(document.pptp.pptpen[0].checked)
		return false;
	
	if (document.pptp.s_name.value=="") {
		alert("<% multilang(LANG_PLEASE_ENTER_PPTP_SERVER_RULE_NAME); %>");
		document.pptp.c_name.focus();
		return false;
	}

	if (document.pptp.s_username.value=="")
	{
		alert("<% multilang(LANG_PLEASE_ENTER_PPTP_SERVER_USERNAME); %>");
		document.pptp.s_username.focus();
		return false;
	}
	if(!checkTextStr(document.pptp.s_username.value))
	{
		alert("<% multilang(LANG_INVALID_VALUE_IN_USERNAME); %>");
		document.pptp.s_username.focus();
		return false;		
	}
	
	if (document.pptp.s_password.value=="") {
		alert("<% multilang(LANG_PLEASE_ENTER_PPTP_SERVER_PASSWORD); %>");
		document.pptp.s_password.focus();
		return false;
	}
	if(!checkTextStr(document.pptp.s_password.value))
	{
		alert("<% multilang(LANG_INVALID_VALUE_IN_PASSWORD); %>");
		document.pptp.s_password.focus();
		return false;		
	}

	obj.isclick = 1;
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	
	return true;
}

function addPptpClient(obj)
{
	if(document.pptp.pptpen[0].checked)
		return false;

	if (document.pptp.c_name.value=="") {
		alert("<% multilang(LANG_PLEASE_ENTER_PPTP_CLIENT_RULE_NAME); %>");
		document.pptp.c_name.focus();
		return false;
	}

	if (document.pptp.c_addr.value=="") {
		alert("<% multilang(LANG_PLEASE_ENTER_PPTP_SERVER_ADDRESS); %>");
		document.pptp.c_addr.focus();
		return false;
	}
	
	if(!checkTextStr(document.pptp.c_addr.value))
	{
		alert("<% multilang(LANG_INVALID_VALUE_IN_SERVER_ADDRESS); %>");
		document.pptp.c_addr.focus();
		return false;		
	}
	
	if (document.pptp.c_username.value=="")
	{
		alert("<% multilang(LANG_PLEASE_ENTER_PPTP_CLIENT_USERNAME); %>");
		document.pptp.c_username.focus();
		return false;
	}
	if(!checkTextStr(document.pptp.c_username.value))
	{
		alert("<% multilang(LANG_INVALID_VALUE_IN_USERNAME); %>");
		document.pptp.c_username.focus();
		return false;		
	}
	if (document.pptp.c_password.value=="") {
		alert("<% multilang(LANG_PLEASE_ENTER_PPTP_CLIENT_PASSWORD); %>");
		document.pptp.c_password.focus();
		return false;
	}
	if(!checkTextStr(document.pptp.c_password.value))
	{
		alert("<% multilang(LANG_INVALID_VALUE_IN_PASSWORD); %>");
		document.pptp.c_password.focus();
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
	<p class="intro_title">PPTP VPN <% multilang(LANG_CONFIGURATION); %></p>
	<p class="intro_content"> <% multilang(LANG_THIS_PAGE_IS_USED_TO_CONFIGURE_THE_PARAMETERS_FOR_PPTP_MODE_VPN); %></p>
</div>

<form action=/boaform/formPPtP method=POST name="pptp">
<div class="data_common data_common_notitle">
	<table>
		<tr>
			<th>PPTP VPN:</th>
			<td>
				<input type="radio" value="0" name="pptpen" <% checkWrite("pptpenable0"); %> onClick="onClickPPtpEnable()"><% multilang(LANG_DISABLE); %>&nbsp;&nbsp;
				<input type="radio" value="1" name="pptpen" <% checkWrite("pptpenable1"); %> onClick="onClickPPtpEnable()"><% multilang(LANG_ENABLE); %>
			</td>
		</tr>
	</table>
</div>
<input type="hidden" id="lst" name="lst" value="">

<div class="column">
	<div class="column_title">
		<div class="column_title_left"></div>
			<p>PPTP Server</p>
		<div class="column_title_right"></div>
	</div>
	<div class="data_common">
		<table>
			<tr>
				<th>Auth. Type:</th>
				<td>
					<select name="s_auth" onClick="serverEncryClick()">
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
				<th>Peer Address:</th>
				<!--<td>start from:-->
				<td><input type="text" name="peeraddr" size="16" maxlength="80"></td>
			</tr>
			<tr>
				<th>Local Address:</th>
				<td><input type="text" name="localaddr" size="16" maxlength="80"></td>
			</tr>
			
		</table>
	</div>
</div>

<div class="btn_ctl">
	<input class="link_bg" type="submit" value="Apply" name="addServer" onClick="return setPptpServer(this)">
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
	<input class="link_bg" type="submit" value="Add" name="addAccount" onClick="return addPptpAccount(this)">
</div>

<div class="column">
	<div class="column_title">
		<div class="column_title_left"></div>
			<p>PPTP Server Table</p>
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
			<% pptpServerList(); %>
		</table>
	</div>
</div>

<div class="btn_ctl">
	<input class="link_bg" type="submit" value="<% multilang(LANG_DELETE_SELECTED); %>" name="delSelAccount" onClick="return on_submit(this)">&nbsp;&nbsp;
	<input class="link_bg" type="submit" value="<% multilang(LANG_SAVE); %>" name="saveAccount" onClick="return on_submit(this)">
</div>

<div class="column">
	<div class="column_title">
		<div class="column_title_left"></div>
			<p>PPTP Client</p>
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
				<td><input type="text" name="c_addr" size="16" maxlength="256"></td>
			</tr>
			<tr>
				<th>Username:</th>
				<td><input type="text" name="c_username" size="16" maxlength="256"></td>
			</tr>
			<tr>
				<th>Password:</th>
				<td><input type="text" name="c_password" size="16" maxlength="256"></td>
			</tr>
			<tr>
				<th>Auth. Type:</th>
				<td>
					<select name="c_auth" onClick="clientEncryClick()">
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
					<select name="c_enctype" >
						<option value="0"><% multilang(LANG_NONE); %></option>
						<option value="1">MPPE</option>
						<option value="2">MPPC</option>
						<option value="3">MPPE&MPPC</option>
					</select>
				</td>
			</tr>
			<tr>
				<th>Default Gateway:</th>
				<td><input type="checkbox" name="defaultgw"></td>
			</tr>
		</table>
	</div>
</div>

<div class="btn_ctl">		
	<input class="link_bg" type="submit" value="Add" name="addClient" onClick="return addPptpClient(this)">
</div>

<div class="column">
	<div class="column_title">
		<div class="column_title_left"></div>
			<p>PPTP Client Table</p>
		<div class="column_title_right"></div>
	</div>
	<div class="data_common">
		<table>
			<tr>
				<th align=center><% multilang(LANG_SELECT); %></th>
				<th align=center><% multilang(LANG_INTERFACE); %></th>
				<th align=center><% multilang(LANG_SERVER); %></th>
				<th align=center><% multilang(LANG_ACTION); %></th>
			</tr>
			<% pptpList(); %>
		</table>
	</div>
</div>

<div class="btn_ctl">
	<input class="link_bg" type="submit" value="<% multilang(LANG_DELETE_SELECTED); %>" name="delSelClient" onClick="return on_submit(this)">&nbsp;&nbsp;
	<input type="hidden" value="/pptpd.asp" name="submit-url">
	<input type="hidden" name="postSecurityFlag" value="">
</div>

<script>
	<% initPage("pptp"); %>
	pptpSelection();
</script>
</form>
</body>
</html>
