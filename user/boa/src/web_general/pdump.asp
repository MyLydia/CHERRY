<%SendWebHeadStr(); %>
<title><% multilang(LANG_PACKET_DUMP); %></title>
<script>
function on_submit(obj)
{
	obj.isclick = 1;
	postTableEncrypt(document.ping.postSecurityFlag, document.ping);
	return true;
}

function on_submit2(obj)
{
	obj.isclick = 1;
	postTableEncrypt(document.ping2.postSecurityFlag, document.ping2);
	return true;
}
</script>
</head>

<body>
<div class="intro_main ">
	<p class="intro_title"><% multilang(LANG_PACKET_DUMP); %></p>
	<p class="intro_content"> <% multilang(LANG_THIS_PAGE_IS_USED_TO_START_OR_STOP_A_WIRESHARK_PACKET_CAPTURE); %><br>
    <% multilang(LANG_YOU_NEED_TO_RETURN_TO_THIS_PAGE_TO_STOP_IT); %></p>
    <a href ="http:\\www.tcpdump.org\tcpdump_man.html" target="blank"><% multilang(LANG_CLICK_HERE_FOR_THE_DOCUMENTATION_OF_THE_ADDITIONAL_ARGUMENTS); %></a>
</div>

<form action=/boaform/formCapture method=POST name="ping">
<div class="data_common data_common_notitle">
	<table>
		<tr>
			<th><% multilang(LANG_ADDITIONAL_ARGUMENTS); %>:</th>
			<td><input type="text" name="tcpdumpArgs" value="-s 1500" size="50" maxlength="50"></td>
				<input type="hidden" value="yes" name="dostart">
		</tr>
	</table>
</div>

<div class="btn_ctl">
	<input class="link_bg" type="submit" value="<% multilang(LANG_START); %>" name="start" onClick="return on_submit(this)">
	<input type="hidden" value="/pdump.asp" name="submit-url">
	<input type="hidden" name="postSecurityFlag" value="">
</div>
</form>

<form action=/boaform/formCapture method=POST name="ping2">
	<div class="btn_ctl">
		<input class="link_bg" type="submit" value="<% multilang(LANG_STOP); %>" name="stop" onClick="return on_submit2(this)">
		<input type="hidden" value="/pdump.asp" name="submit-url">
		<input type="hidden" value="no" name="dostart">
		<input type="hidden" name="postSecurityFlag" value="">
	</div>
</form>
</body>

</html>
