<%SendWebHeadStr(); %>
<title><% multilang(LANG_LOGOUT); %></title>
<SCRIPT>
function confirmlogout(obj)
{
   if ( !confirm('<% multilang(LANG_DO_YOU_CONFIRM_TO_LOGOUT); %>') ) {
	return false;
  }
  else {
 	obj.isclick = 1;
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

<form action=/boaform/admin/formLogout method=POST name="cmlogout">

<div class="btn_ctl">
      <input class="link_bg" type="submit" value="<% multilang(LANG_LOGOUT); %>" name="save" onclick="return confirmlogout(this)">&nbsp;&nbsp;
      <input type="hidden" value="/admin/logout.asp" name="submit-url">
      <input type="hidden" name="postSecurityFlag" value="">
</div>
</form>
</body>

</html>

