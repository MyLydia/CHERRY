<html>
<! Copyright (c) Realtek Semiconductor Corp., 2003. All Rights Reserved. ->
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<title><% multilang(LANG_FRAMEWORK_INFO); %></title>
<link rel="stylesheet" type="text/css" href="common_style.css" />

</head>
<body>
<blockquote>

<h2 class="page_title"><% multilang(LANG_FRAMEWORK_INFO); %></h2>

<table>
<tr><td><font size=2>
 <% multilang(LANG_THIS_PAGE_SHOWS_THE_OSGI_FRAMWEORK_OF_THE_DEVICE); %>
</font></td></tr>

<tr><td><hr size=1 noshade align=top><br></td></tr>
</table>

<form action=/boaform/admin/formStatus method=POST name="status2">
<table width=400 border=0>
  <tr>
    <th colspan="2" bgcolor="#008000"><font color="#FFFFFF"><% multilang(LANG_OSGI_FRAMEWORK_INFORMATION); %></font></th>
  </tr>
  <tr bgcolor="#EEEEEE">
    <th><% multilang(LANG_FRAMEWORK_NAME); %></th>
    <td><% getOSGIInfo("fwname"); %></td>
  </tr>
  <tr bgcolor="#EEEEEE">
    <th><% multilang(LANG_FRAMEWORK_VERSION); %></th>
    <td><% getOSGIInfo("fwver"); %></td>
  </tr>
   <tr bgcolor="#EEEEEE">
    <th><% multilang(LANG_FRAMEWORK_STATUS); %></th>
    <td><% getOSGIInfo("fwstatus"); %></td>
  </tr>
</table>
</br>
 <% getOSGIBundleList("0"); %>
</form>
<br>


</blockquote>

</body>

</html>
