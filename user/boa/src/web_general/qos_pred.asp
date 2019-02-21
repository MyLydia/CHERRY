<%SendWebHeadStr(); %>
<title><% multilang(LANG_IP_PRECEDENCE_PRIORITY_SETTINGS); %></title>

<SCRIPT>
function on_submit(obj)
{
	obj.isclick = 1;
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	return true;
}
</SCRIPT>
</head>
<BODY>
<div class="intro_main ">
	<p class="intro_title"><% multilang(LANG_IP_PRECEDENCE_PRIORITY_SETTINGS); %></p>
	<p class="intro_content"> <% multilang(LANG_THIS_PAGE_IS_USED_TO_CONFIG_IP_PRECEDENCE_PRIORITY); %></p>
</div>

<form action=/boaform/formIPQoS method=POST name=qos_set1p>
<div class="column">
	<div class="column_title">
		<div class="column_title_left"></div>
			<p><% multilang(LANG_IP_PRECEDENCE_RULE); %></p>
		<div class="column_title_right"></div>
	</div>
	<div class="data_common">
		<table>
			<% settingpred(); %>
		</table>
	</div>
</div>

<div class="btn_ctl">	
	<input type="hidden" value="/qos_pred.asp" name="submit-url">
	<input class="link_bg" type="submit" value="<% multilang(LANG_MODIFY); %>" name=setpred onClick="return on_submit(this)">
	<input class="link_bg" type="button" value="<% multilang(LANG_CLOSE); %>" name="close" onClick="javascript: window.close();">
	<input type="hidden" name="postSecurityFlag" value="">
</div>
</form>
</body>
</html>

