<%SendWebHeadStr(); %>
<title><% multilang(LANG_REMOTE_ACCESS); %><% multilang(LANG_CONFIGURATION); %></title>

<script>
function addClick(obj)
{
	dTelnet = getDigit(document.acc.w_telnet_port.value, 1);
	dFtp = getDigit(document.acc.w_ftp_port.value, 1);
	dWeb = getDigit(document.acc.w_web_port.value, 1);
	if (dTelnet == dFtp || dTelnet == dWeb) {
		alert("<% multilang(LANG_DUPLICATED_PORT_NUMBER); %>");
		document.acc.w_telnet_port.focus();
		return false;
	}
	if (dFtp == dWeb) {
		alert("<% multilang(LANG_DUPLICATED_PORT_NUMBER); %>");
		document.acc.w_ftp_port.focus();
		return false;
	}

	if (document.acc.w_telnet.checked) {
		if (document.acc.w_telnet_port.value=="") {
			alert("<% multilang(LANG_PORT_RANGE_CANNOT_BE_EMPTY_YOU_SHOULD_SET_A_VALUE_BETWEEN_1_65535); %>");
			document.acc.w_telnet_port.focus();
			return false;
		}
		if ( validateKey( document.acc.w_telnet_port.value ) == 0 ) {
			alert("<% multilang(LANG_INVALID_PORT_NUMBER_IT_SHOULD_BE_THE_DECIMAL_NUMBER_0_9); %>");
			document.acc.w_telnet_port.focus();
			return false;
		}
		//d1 = getDigit(document.acc.w_telnet_port.value, 1);
		//if (d1 > 65535 || d1 < 1) {
		if (dTelnet > 65535 || dTelnet < 1) {
			alert("<% multilang(LANG_INVALID_PORT_NUMBER_YOU_SHOULD_SET_A_VALUE_BETWEEN_1_65535); %>");
			document.acc.w_telnet_port.focus();
			return false;
		}
  }

	if (document.acc.w_ftp.checked) {
		if (document.acc.w_ftp_port.value=="") {
			alert("<% multilang(LANG_PORT_RANGE_CANNOT_BE_EMPTY_YOU_SHOULD_SET_A_VALUE_BETWEEN_1_65535); %>");
			document.acc.w_ftp_port.focus();
			return false;
		}
		if ( validateKey( document.acc.w_ftp_port.value ) == 0 ) {
			alert("<% multilang(LANG_INVALID_PORT_NUMBER_IT_SHOULD_BE_THE_DECIMAL_NUMBER_0_9); %>");
			document.acc.w_ftp_port.focus();
			return false;
		}
		//d1 = getDigit(document.acc.w_ftp_port.value, 1);
		//if (d1 > 65535 || d1 < 1) {
		if (dFtp > 65535 || dFtp < 1) {
			alert("<% multilang(LANG_INVALID_PORT_NUMBER_YOU_SHOULD_SET_A_VALUE_BETWEEN_1_65535); %>");
			document.acc.w_ftp_port.focus();
			return false;
		}
	}

	if (document.acc.w_web.checked) {
		if (document.acc.w_web_port.value=="") {
			alert("<% multilang(LANG_PORT_RANGE_CANNOT_BE_EMPTY_YOU_SHOULD_SET_A_VALUE_BETWEEN_1_65535); %>");
			document.acc.w_web_port.focus();
			return false;
		}
		if ( validateKey( document.acc.w_web_port.value ) == 0 ) {
			alert("<% multilang(LANG_INVALID_PORT_NUMBER_IT_SHOULD_BE_THE_DECIMAL_NUMBER_0_9); %>");
			document.acc.w_web_port.focus();
			return false;
		}
		//d1 = getDigit(document.acc.w_web_port.value, 1);
		//if (d1 > 65535 || d1 < 1) {
		if (dWeb > 65535 || dWeb < 1) {
			alert("<% multilang(LANG_INVALID_PORT_NUMBER_YOU_SHOULD_SET_A_VALUE_BETWEEN_1_65535); %>");
			document.acc.w_web_port.focus();
			return false;
		}
	}

	obj.isclick = 1;
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	return true;

}

</script>
</head>

<body>
<div class="intro_main ">
	<p class="intro_title"><% multilang(LANG_REMOTE_ACCESS); %> <% multilang(LANG_CONFIGURATION); %></p>
	<p class="intro_content"> <% multilang(LANG_THIS_PAGE_IS_USED_TO_ENABLE_DISABLE_MANAGEMENT_SERVICES_FOR_THE_LAN_AND_WAN); %></p>
</div>

<form action=/boaform/formSAC method=POST name=acc>
<div class="data_vertical data_common_notitle">
	 <div class="data_common ">
		<table>
		<tr>
			<th align=left><% multilang(LANG_SERVICE); %><% multilang(LANG_NAME); %></th>
			<th align=center><% multilang(LANG_LAN); %></th>
			<th align=center><% multilang(LANG_WAN); %></th>
			<th align=center><% multilang(LANG_WAN_PORT); %></th>
		</tr>
		<% rmtaccItem(); %>
		</table>
	</div>
</div>

<div class="btn_ctl">
	<input class="link_bg" type="submit" value="<% multilang(LANG_APPLY_CHANGES); %>" name="set" onClick="return addClick(this)">
	<input type="hidden" value="/rmtacc.asp" name="submit-url">
	<input type="hidden" name="postSecurityFlag" value="">
</div>
<script>
	<% accPost(); %>
</script>
</form>
</blockquote>
</body>
</html>
