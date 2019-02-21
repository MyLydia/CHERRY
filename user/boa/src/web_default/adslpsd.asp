<html>
<! Copyright (c) Realtek Semiconductor Corp., 2003. All Rights Reserved. ->
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<title>ADSL <% multilang(LANG_PSD_MASK); %><% multilang(LANG_CONFIGURATION); %></title>
<link rel="stylesheet" type="text/css" href="common_style.css" />

</head>

<body>
<blockquote>
<h2 class="page_title">ADSL <% multilang(LANG_PSD_MASK); %><% multilang(LANG_CONFIGURATION); %></h2>

<table>
  <tr><font size=2>
  <% multilang(LANG_THIS_PAGE_LET_USER_TO_SET_PSD_MASK); %>
  </tr>
  <tr><hr size=1 noshade align=top></tr>
</table>


<form action=/boaform/formSetAdslPSD method=POST name="formPSDTbl">

<table>
<% adslPSDMaskTbl(); %>
</table>

<input type="submit" value="<% multilang(LANG_APPLY_CHANGES); %>" name="apply">&nbsp;&nbsp;
<input type="hidden" value="/adslpsd.asp" name="submit-url"> 
<input type="button" value="<% multilang(LANG_CLOSE); %>" name="close" onClick="javascript: window.close();">

</form>
</blockquote>
</body>

</html>

