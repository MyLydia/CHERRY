<html>
<! Copyright (c) Realtek Semiconductor Corp., 2003. All Rights Reserved. ->
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<title><% multilang(LANG_MULTI_LANGUAL_SETTINGS); %></title>
<link rel="stylesheet" type="text/css" href="common_style.css"/>
</head>

<body>
<blockquote>
<h2 class="page_title"><% multilang(LANG_MULTI_LANGUAL_SETTINGS); %></h2>

<form id="multilangform"action=/boaform/langSel method=POST name="mlSet">
<table>
  <tr><td><font size=2>
    <% multilang(LANG_PAGE_DESC_MULTI_LANGUAL); %>
  </font></td></tr>
</table>

<table width=80%>
  <tr><th><% multilang(LANG_LANGUAGE_SELECT); %>:</th>
      <td ><select size="1" name="selinit"><% checkWrite("selinit"); %></select></td>
  </tr>
  <tr><td colspan=2><hr size=1 noshade align=top></td></tr>
</table>
  <br>
  <input type="submit" value="<% multilang(LANG_UPDATE_SELECTED_LANGUAGE); %>" onclick="parent.location.reload();">
</form>
</blockquote>
</body>

</html>
