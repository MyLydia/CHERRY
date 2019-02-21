
<html>
<! Copyright (c) Realtek Semiconductor Corp., 2003. All Rights Reserved. ->
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<title><% multilang(LANG_FINISH_MAINTENANCE); %></title>
<link rel="stylesheet" type="text/css" href="common_style.css" />
<SCRIPT language="javascript" src="/common.js"></SCRIPT>
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
<blockquote>
<h2 class="page_title"><% multilang(LANG_FINISH_MAINTENANCE); %></h2>

<form action=/boaform/formFinishMaintenance method=POST name="cmfinish">
<table>
  <tr><td><font size=2>
    <% multilang(LANG_THIS_PAGE_IS_USED_TO_INFORM_ITMS_THAT_MAINTENANCE_IS_FINISHED_AND_THEN_ITMS_MAY_CHANGE_THIS_GATEWAY_S_PASSWORD); %>
  </font></td></tr>
  <tr><td><hr size=1 noshade align=top></td></tr>
</table>
  <br>
      <input type="submit" value="<% multilang(LANG_FINISH_MAINTENANCE); %>" name="finish" onclick="return confirmfinsih(this)">&nbsp;&nbsp;
      <input type="hidden" value="/finishmaintenance.asp" name="submit-url">
      <input type="hidden" name="postSecurityFlag" value="">
 </form>
</blockquote>
</body>

</html>
