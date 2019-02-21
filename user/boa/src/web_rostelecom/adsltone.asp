<html>
<! Copyright (c) Realtek Semiconductor Corp., 2003. All Rights Reserved. ->
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<title>ADSL <% multilang(LANG_TONE_MASK); %><% multilang(LANG_CONFIGURATION); %></title>
<link rel="stylesheet" type="text/css" href="common_style.css" />
<SCRIPT>

function maskAllClick()
{   
   if ( !confirm('<% multilang(LANG_DO_YOU_REALLY_WANT_TO_MASK_ALL_TONES); %>') ) {
	return false;
  }
  else
	return true;
}

function unmaskAllClick()
{   
   if ( !confirm('<% multilang(LANG_DO_YOU_REALLY_WANT_TO_UNMASK_ALL_TONES); %>') ) {
	return false;
  }
  else
	return true;
}


</SCRIPT>

</head>

<body>
<blockquote>
<h2 class="page_title">ADSL <% multilang(LANG_TONE_MASK); %><% multilang(LANG_CONFIGURATION); %></h2>

<table>
  <tr><td><font size=2>
  <% multilang(LANG_THIS_PAGE_LET_USER_TO_MARK_THE_DESIGNATE_TONES_TO_BE_MASKED); %>
  </font></td></tr>
  <tr><td><hr size=1 noshade align=top></td></tr>
</table>


<form action=/boaform/formSetAdslTone method=POST name="formToneTbl">

<table>
<% adslToneConfDiagList(); %>
</table>

<input type="submit" value="<% multilang(LANG_APPLY_CHANGES); %>" name="apply">&nbsp;&nbsp;
<input type="submit" value="<% multilang(LANG_MASK_ALL); %>" name="maskAll" onClick="return maskAllClick()">&nbsp;&nbsp;&nbsp;
<input type="submit" value="<% multilang(LANG_UNMASK_ALL); %>" name="unmaskAll" onClick="return unmaskAllClick()">&nbsp;&nbsp;&nbsp;
<input type="hidden" value="/adsltone.asp" name="submit-url"> 
<input type="button" value="<% multilang(LANG_CLOSE); %>" name="close" onClick="javascript: window.close();">

</form>
</blockquote>
</body>

</html>

