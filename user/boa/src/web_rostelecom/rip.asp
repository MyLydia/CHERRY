<html>
<! Copyright (c) Realtek Semiconductor Corp., 2003. All Rights Reserved. ->
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<title>RIP <% multilang(LANG_CONFIGURATION); %></title>
<link rel="stylesheet" type="text/css" href="common_style.css" />
<script type="text/javascript" src="share.js">
</script>
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
</SCRIPT>
</head>

<body>
<blockquote>
<h2 class="page_title">RIP <% multilang(LANG_CONFIGURATION); %></h2>

<form action=/boaform/admin/formRip method=POST name="rip">
<table>
  <tr><td><font size=2>
    <% multilang(LANG_ENABLE_THE_RIP_IF_YOU_ARE_USING_THIS_DEVICE_AS_A_RIP_ENABLED_DEVICE_TO_COMMUNICATE_WITH_OTHERS_USING_THE_ROUTING_INFORMATION_PROTOCOL_THIS_PAGE_IS_USED_TO_SELECT_THE_INTERFACES_ON_YOUR_DEVICE_IS_THAT_USE_RIP_AND_THE_VERSION_OF_THE_PROTOCOL_USED); %>
  </font></td></tr>
  <tr><td><hr size=1 noshade align=top></td></tr>
</table>
<table>
	<tr>
		<th><% multilang(LANG_RIP); %>:</th>
		<td>
			<input type="radio" value="0" name="rip_on" <% checkWrite("rip-on-0"); %> ><% multilang(LANG_DISABLE); %>&nbsp;&nbsp;
			<input type="radio" value="1" name="rip_on" <% checkWrite("rip-on-1"); %> ><% multilang(LANG_ENABLE); %>&nbsp;&nbsp;
		</td>
		<td><input type="submit" value="<% multilang(LANG_APPLY_CHANGES); %>" name="ripSet"></td>
	</tr>
</table>
<table>
	<tr><td><hr size=1 noshade align=top></td></tr>
</table>

<table> 
	<tr>
		<th><% multilang(LANG_INTERFACE); %>:</th>
		<td>
			<select name="rip_if">
			<option value="65535">br0</option>
			<% if_wan_list("rt"); %>
			</select>
		</td>
	</tr>
	
	<tr>
		<th><% multilang(LANG_RECEIVE_MODE); %>:</th>
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
		<th><% multilang(LANG_SEND_MODE); %>:</th>
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
	<br>
	<td><input type="submit" value="<% multilang(LANG_ADD); %>" name="ripAdd"></td>

<table>
	<tr><td><hr size=1 noshade align=top></td></tr>
	<tr><th><% multilang(LANG_RIP_CONFIG_TABLE); %>:</th></tr>
</table>
<table>
	<% showRipIf(); %>
</table>

	<br>
	<input type="submit" value="<% multilang(LANG_DELETE_SELECTED); %>" name="ripDel" onClick="return deleteClick()">&nbsp;&nbsp;  
	<input type="submit" value="<% multilang(LANG_DELETE_ALL); %>" name="ripDelAll" onClick="return deleteAllClick()">&nbsp;&nbsp;&nbsp;
	<input type="hidden" value="/admin/rip.asp" name="submit-url">
	<script>
		<% checkWrite("ripNum"); %>
	</script>
</form>
</blockquote>
</body>

</html>
