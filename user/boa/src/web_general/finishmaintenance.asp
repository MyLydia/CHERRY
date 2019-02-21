<%SendWebHeadStr(); %>
<title><% multilang(LANG_FINISH_MAINTENANCE); %></title>
<!--<link rel="stylesheet" href="admin/content.css">-->

<SCRIPT>
function confirmfinsih(obj)
{
   if ( !confirm('do you confirm the maintenance is over?') ) {
	return false;
  }
  else{
  	obj.isclick = 1;
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	return true;
  }
}
</SCRIPT>
</head>

<body>
<div class="intro_main ">
	<p class="intro_title"><% multilang(LANG_FINISH_MAINTENANCE); %></p>
	<p class="intro_content"> <% multilang(LANG_THIS_PAGE_IS_USED_TO_INFORM_ITMS_THAT_MAINTENANCE_IS_FINISHED_AND_THEN_ITMS_MAY_CHANGE_THIS_GATEWAY_S_PASSWORD); %></p>
</div>

<form action=/boaform/formFinishMaintenance method=POST name="cmfinish">

<div class="btn_ctl">
      <input class="link_bg" type="submit" value="<% multilang(LANG_FINISH_MAINTENANCE); %>" name="finish" onclick="return confirmfinsih(this)">&nbsp;&nbsp;
      <input type="hidden" value="/finishmaintenance.asp" name="submit-url">
      <input type="hidden" name="postSecurityFlag" value="">
</div>
</form>
<br><br>
</body>

</html>
