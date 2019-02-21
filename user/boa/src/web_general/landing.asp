<%SendWebHeadStr(); %>
<title><% multilang(LANG_LANDING_PAGE); %><% multilang(LANG_CONFIGURATION); %></title>

<script>
function saveClick()
{	
	alert('<% multilang(LANG_PLEASE_COMMIT_AND_REBOOT_THIS_SYSTEM_FOR_TAKE_EFFECT_THE_LANDING_PAGE); %>');
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
}

</script>
</head>

<body>
<div class="intro_main ">
	<p class="intro_title"><% multilang(LANG_LANDING_PAGE); %> <% multilang(LANG_CONFIGURATION); %></p>
	<p class="intro_content"> <% multilang(LANG_THIS_PAGE_IS_USED_TO_CONFIGURE_THE_TIME_INTERVAL_OF_LANDING_PAGE); %></p>
</div>

<form action=/boaform/formLanding method=POST name="landing">
<div class="data_common data_common_notitle">
	<table> 
		<tr>
			<th><% multilang(LANG_TIME_INTERVAL); %>:</th>
			<td width="70%"><input type="text" name="interval" size="15" maxlength="15" value=<% getInfo("landing-page-time"); %>>(<% multilang(LANG_SECONDS); %>)</td>
		</tr>   
	</table>
</div>
<div class="btn_ctl">
	<input class="link_bg" type="submit" value="<% multilang(LANG_APPLY_CHANGES); %>" onClick="return saveClick()">&nbsp;&nbsp;
	<input type="hidden" value="/landing.asp" name="submit-url">
	<input type="hidden" name="postSecurityFlag" value="">
</div>
</form>
</body>

</html>
