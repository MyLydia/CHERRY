<html>
<%SendWebHeadStr(); %>
<title><% multilang(LANG_LAN_DEVICE_TABLE); %></title>
 
<SCRIPT>
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
	<p class="intro_title"><% multilang(LANG_LAN_USER_LIST); %></p>
	<p class="intro_content"> <% multilang(LANG_PAGE_DEVICE_TABLE_INFO); %></p>
</div>

<form action=/boaform/formRefleshLanUserTbl method=POST name="formLANUserTbl">
<div class="data_vertical data_common_notitle">
	<div class="data_common ">
		<table>
			<tr><th width="20%"><% multilang(LANG_IP_ADDRESS); %></th>
				<th width="20%"><% multilang(LANG_MAC_ADDRESS); %></th>
				<th width="20%"><% multilang(LANG_HOSTNAME); %></th>
				<th width="20%"><% multilang(LANG_INTERFACE); %></th>
			</tr>
			<% LanUserTableList(); %>
		</table>
	</div>
</div>

<div class="btn_ctl">
	<input type="hidden" value="/landevice.asp" name="submit-url">
	<input class="link_bg" type="submit" value="<% multilang(LANG_REFRESH); %>" name="refresh" onClick="return on_submit(this)">
	<input type="hidden" name="postSecurityFlag" value="">
</div>
</form>
</body>

</html>
