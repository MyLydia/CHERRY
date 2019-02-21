<% SendWebHeadStr();%>
<title><% multilang(LANG_INTERFACE_STATISITCS); %></title>

<script>
function resetClick() {
	with ( document.forms[0] ) {
		reset.value = 1;
		postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
		submit();
	}
}

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
<p class="intro_title"><% multilang(LANG_INTERFACE_STATISITCS); %></p>
<p class="intro_content"><% multilang(LANG_PAGE_DESC_PACKET_STATISTICS_INFO); %></p>
</div>
<form action=/boaform/formStats method=POST name="formStats">
<div class="column">
	<div class="column_title">
		<div class="column_title_left"></div>
			<p><% multilang(LANG_INTERFACE_STATISITCS); %></p>
		<div class="column_title_right"></div>
	</div>
	<div class="data_common data_vertical">
		<table>
	<% pktStatsList(); %>
</table>
	</div>
</div>
<div class="btn_ctl">
  <input type="hidden" value="/stats.asp" name="submit-url">
  <input type="submit" value="<% multilang(LANG_REFRESH); %>" name="refresh" onClick="return on_submit(this)" class="link_bg">
  <input type="hidden" value="0" name="reset">
  <input type="button" onClick="resetClick(this)" value="<% multilang(LANG_RESET_STATISTICS); %>" class="link_bg">
  <input type="hidden" name="postSecurityFlag" value="">
  </div>
</form>
<br><br>
</body>

</html>
