<%SendWebHeadStr(); %>
<META HTTP-EQUIV=Refresh CONTENT="10; URL=lan_port_status.asp">
<title><% multilang(LANG_LAN_PORT_STATUS); %></title>

<script>
function on_submit(obj)
{
	obj.isclick = 1;
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	return true;
}
</script>
</head>

<body>
<div class="intro_main ">
	<p class="intro_title"><% multilang(LANG_LAN_PORT_STATUS); %></p>
	<p class="intro_content"> <% multilang(LANG_THIS_PAGE_SHOWS_THE_CURRENT_LAN_PORT_STATUS); %></p>
</div>

<form action=/boaform/admin/formLANPortStatus method=POST name="status3">
<div class="column">
	<div class="column_title">
		<div class="column_title_left"></div>
			<p><% multilang(LANG_LAN_PORT_STATUS); %></p>
		<div class="column_title_right"></div>
	</div>
	<div class="data_common">
		<table>
			<% showLANPortStatus(); %>
		</table>
	</div>
</div>

<div class="btn_ctl">
	<input type="hidden" value="/lan_port_status.asp" name="submit-url">
	<input class="link_bg" type="submit" value="Refresh" name="refresh" onClick="return on_submit(this)">&nbsp;&nbsp;
	<input type="hidden" name="postSecurityFlag" value="">
</div>
</form>
</body>
</html>
