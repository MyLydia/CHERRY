<% SendWebHeadStr();%>
<title>RIP <% multilang(LANG_CONFIGURATION); %></title>

<SCRIPT>
var ifnum;

function selected()
{
	document.rip.ripDel.disabled = false;
}

function resetClicked()
{
	document.rip.ripDel.disabled = true;
}

function disableDelButton()
{
	if (verifyBrowser() != "ns") {
		disableButton(document.rip.ripDel);
		disableButton(document.rip.ripDelAll);
	}
}

function on_submit(obj)
{
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
        
function deleteAllClick(obj)
{
	if ( !confirm('Do you really want to delete the all entries?') ) {
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
	<p class="intro_title">RIP <% multilang(LANG_CONFIGURATION); %></p>
	<p class="intro_content"><% multilang(LANG_ENABLE_THE_RIP_IF_YOU_ARE_USING_THIS_DEVICE_AS_A_RIP_ENABLED_DEVICE_TO_COMMUNICATE_WITH_OTHERS_USING_THE_ROUTING_INFORMATION_PROTOCOL_THIS_PAGE_IS_USED_TO_SELECT_THE_INTERFACES_ON_YOUR_DEVICE_IS_THAT_USE_RIP_AND_THE_VERSION_OF_THE_PROTOCOL_USED); %></p>
</div>

<form action=/boaform/formRip method=POST name="rip">
<div class="data_common data_common_notitle">
	<table>
		<tr>
			<th><% multilang(LANG_RIP); %>:</th>
			<td>
				<input type="radio" value="0" name="rip_on" <% checkWrite("rip-on-0"); %> ><% multilang(LANG_DISABLE); %>&nbsp;&nbsp;
				<input type="radio" value="1" name="rip_on" <% checkWrite("rip-on-1"); %> ><% multilang(LANG_ENABLE); %>&nbsp;&nbsp;
			</td>
			<td width="50%"><input type="submit" value="<% multilang(LANG_APPLY_CHANGES); %>" name="ripSet" class="inner_btn" onClick="return on_submit(this)"></td>
		</tr>
	</table>
</div>
<div class="data_common data_common_notitle">
	<table> 
		<tr>
			<th width="30%"><% multilang(LANG_INTERFACE); %>:</th>
			<td>
				<select name="rip_if">
				<option value="65535">br0</option>
				<% if_wan_list("rt"); %>
				</select>
			</td>
		</tr>
		
		<tr>
			<th width="30%"><% multilang(LANG_RECEIVE_MODE); %>:</th>
			<td>
				<select size="1" name="receive_mode">
				<option value="0"><% multilang(LANG_NONE); %></option>
				<option value="1">RIP1</option>
				<option value="2">RIP2</option>
				<option value="3"><% multilang(LANG_BOTH); %></option>
				</select>
			</td>
		</tr>
		
		<tr>
			<th width="30%"><% multilang(LANG_SEND_MODE); %>:</th>
			<td>
				<select size="1" name="send_mode">
				<option value="0"><% multilang(LANG_NONE); %></option>
				<option value="1">RIP1</option>
				<option value="2">RIP2</option>
				<option value="4">RIP1COMPAT</option>
			</select>
			</td>
		</tr>
	</table>
</div>
<div class="btn_ctl">	
	<input type="submit" value="<% multilang(LANG_ADD); %>" name="ripAdd" class="link_bg" onClick="return on_submit(this)"></td>
</div>

<div class="column">
	<div class="column_title">
		<div class="column_title_left"></div>
			<p><% multilang(LANG_RIP_CONFIG_TABLE); %></p>
		<div class="column_title_right"></div>
	</div>
	<div class="data_common data_vertical">
		<table>
			<% showRipIf(); %>
		</table>
	</div>
</div>
<div class="btn_ctl">
	<input type="submit" value="<% multilang(LANG_DELETE_SELECTED); %>" name="ripDel" onClick="return deleteClick(this)" class="link_bg">&nbsp;&nbsp;  
	<input type="submit" value="<% multilang(LANG_DELETE_ALL); %>" name="ripDelAll" onClick="return deleteAllClick(this)" class="link_bg">&nbsp;&nbsp;&nbsp;
	<input type="hidden" value="/rip.asp" name="submit-url">
	<input type="hidden" name="postSecurityFlag" value="">
</div>
	<script>
		<% checkWrite("ripNum"); %>
	</script>
</form>
<br><br>
</body>

</html>
