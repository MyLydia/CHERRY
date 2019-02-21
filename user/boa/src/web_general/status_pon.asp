<% SendWebHeadStr();%>
<title>PON <% multilang(LANG_STATUS); %></title>
<script>
function on_submit()
{
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	return true;
}
</script>
</head>

<body>
<div class="intro_main ">
	<p class="intro_title">PON <% multilang(LANG_STATUS); %></p>
	<p class="intro_content"><% multilang(LANG_PAGE_DESC_PON_STATUS); %></p>
</div>

<div class="column">
	<div class="column_title">
		<div class="column_title_left"></div>
			<p><% multilang(LANG_PON); %><% multilang(LANG_STATUS_1); %></p>
		<div class="column_title_right"></div>
	</div>
	<div class="data_common">
		<table>
			<tr>
				<th width=40%><% multilang(LANG_VENDOR_NAME); %></th>
				<td width=60%><% ponGetStatus("vendor-name"); %></td>
			</tr>
			<tr>
				<th width=40%><% multilang(LANG_PART_NUMBER); %></th>
				<td width=60%><% ponGetStatus("part-number"); %></td>
			</tr>
			<tr>
				<th width=40%><% multilang(LANG_TEMPERATURE); %></th>
				<td width=60%><% ponGetStatus("temperature"); %></td>
			</tr>
			<tr>
				<th width=40%><% multilang(LANG_VOLTAGE); %></th>
				<td width=60%><% ponGetStatus("voltage"); %></td>
			</tr>
			<tr>
				<th width=40%><% multilang(LANG_TX_POWER); %></th>
				<td width=60%><% ponGetStatus("tx-power"); %></td>
			<tr>
				<th width=40%><% multilang(LANG_RX_POWER); %></th>
				<td width=60%><% ponGetStatus("rx-power"); %></td>
			</tr>
			<tr >
				<th width=40%><% multilang(LANG_BIAS_CURRENT); %></th>
				<td width=60%><% ponGetStatus("bias-current"); %></td>
			</tr>
		</table>
	</div>
</div>
<div class="column">
  <% showgpon_status(); %> 
</div>
<div class="column">
  <% showepon_LLID_status(); %> 
</div>
<form action=/boaform/admin/formStatus_pon method=POST name="status_pon">
	<div class="btn_ctl">
		<input type="hidden" value="/status_pon.asp" name="submit-url">
		<input class="link_bg" type="submit" value="<% multilang(LANG_REFRESH); %>" onClick="return on_submit()">&nbsp;&nbsp;
		<input type="hidden" name="postSecurityFlag" value="">
	</div> 
</form>
<br><br>
</body>
</html>
