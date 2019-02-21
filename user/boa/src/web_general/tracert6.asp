<% SendWebHeadStr();%>
<title>Tracert6 <% multilang(LANG_DIAGNOSTICS); %></title>
<script>
function on_Apply() 
{ 	
	if(document.getElementById('traceAddr').value == "")
	{
		alert("Should input a domain or ip address!");
		document.getElementById('traceAddr').focus();
		return false;
	}
	return true;
}
</script>
</head>

<body>
<div class="intro_main ">
	<p class="intro_title">Traceroute6 <% multilang(LANG_DIAGNOSTICS); %></p>
	<p class="intro_content"><% multilang(LANG_PAGE_DESC_TRACERT6_DIAGNOSTIC); %></p>
</div>
<form id="form" action=/boaform/formTracert6 method=POST>
<div class="data_common data_common_notitle">
	<table>
		<tr>
			<th width="30%"><% multilang(LANG_HOST_ADDRESS); %>: </th>
			<td width="70%"><input type="text" id="traceAddr" name="traceAddr" size="30" maxlength="50"></td>
		</tr>
		<tr>
			<th width="30%">NumberOfTries:</th>
			<td width="70%"><input type="text" id="trys" name="trys" size="5" maxlength="5" value="3"></td>
		</tr>
		<tr>
			<th width="30%">Timeout:</th>
			<td width="70%"><input type="text" id="timeout" name="timeout" size="10" maxlength="10" value="5">s</td>
		</tr>
		<tr>
			<th width="30%">Datasize:</th>
			<td width="70%"><input type="text" id="datasize" name="datasize" size="10" maxlength="10" value="38">Bytes</td>
		</tr>
		<tr>
			<th width="30%">MaxHopCount:</th>
			<td width="70%"><input type="text" id="maxhop" name="maxhop" size="10" maxlength="10" value="30"></td>
		</tr>
		<tr>
			<th width="30%"><% multilang(LANG_WAN_INTERFACE); %>: </th>
			<td width="70%"><select name="wanif"><% if_wan_list("rtv6-any-vpn"); %></select></td>
		</tr>
	</table>
</div>
<div class="btn_ctl">
	<input class="link_bg" type="submit" value=" <% multilang(LANG_GO); %>" name="go" onClick="return on_Apply()">
	<input type="hidden" value="/tracert6.asp" name="submit-url">
</div>
</form>

    <br><br>
</body>
</html>