<%SendWebHeadStr(); %>
<title>ALG <% multilang(LANG_ON_OFF); %><% multilang(LANG_CONFIGURATION); %></title>

<script>
function AlgTypeStatus()
{
	<% checkWrite("AlgTypeStatus"); %>
	return true;
}

function on_submit()
{
	document.forms[0].apply.isclick = 1;
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	return true;
}
</script>
</head>

<body>
<div class="intro_main ">
	<p class="intro_title">ALG <% multilang(LANG_ON_OFF); %> <% multilang(LANG_CONFIGURATION); %></p>
	<p class="intro_content"><% multilang(LANG_THIS_PAGE_IS_USED_TO_ENABLE_DISABLE_ALG_SERVICES); %></p>
</div>

<form action=/boaform/formALGOnOff method=POST name=algof>
	<div class="column_title column">
		<div class="column_title_left"></div>
			<p>ALG <% multilang(LANG_TYPE); %></p>
		<div class="column_title_right"></div>
	</div>
	<div class="data_common data_vertical">
		<table>
			<% checkWrite("GetAlgType"); %>	
		</table>
	</div>
	<div class="btn_ctl">
		<input class="link_bg" type=submit value="<% multilang(LANG_APPLY_CHANGES); %>" name=apply onClick="return on_submit()">
		<input type="hidden" value="/algonoff.asp" name="submit-url">
		<input type="hidden" name="postSecurityFlag" value="">
	</div>
</form>
<script>
AlgTypeStatus();
</script>
</table>
<br><br>
</body>
</html>
