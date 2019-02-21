<%SendWebHeadStr(); %>
<title><% multilang(LANG_LOGOUT); %></title>
<SCRIPT language="javascript" src="/common.js"></SCRIPT>
<SCRIPT>
function confirmadminlogout()
{
	if ( !confirm('<% multilang(LANG_DO_YOU_CONFIRM_TO_LOGOUT); %>') ) {
		return false;
	}
	else
	{
		document.forms[0].adminlogout.isclick = 1;
		postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
		return true;
	}
}
</SCRIPT>
</head>

<body>
<div class="intro_main ">
	<p class="intro_title"><% multilang(LANG_LOGOUT); %></p>
	<p class="intro_content"> <% multilang(LANG_THIS_PAGE_IS_USED_TO_LOGOUT_FROM_THE_DEVICE); %></p>
</div>

<form action=/boaform/formAdminLogout method=POST name="cmadminlogout">
<div class="btn_ctl">
	<input class="link_bg" type="submit" value="<% multilang(LANG_LOGOUT); %>" name="adminlogout" onclick="return confirmadminlogout()">&nbsp;&nbsp;
	<input type="hidden" value="/admin/adminlogout.asp" name="submit-url">
	<input type="hidden" name="postSecurityFlag" value="">
</div>
</form>
<br><br>
</body>
</html>

