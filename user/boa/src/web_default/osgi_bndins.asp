<html>
<! Copyright (c) Realtek Semiconductor Corp., 2003. All Rights Reserved. ->
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<title><% multilang(LANG_BUNDLE_INSTALLATION); %></title>
<link rel="stylesheet" type="text/css" href="common_style.css" />
<script>

function uploadClick()
{		
   	if (document.saveConfig.binary.value.length == 0) {
		alert('<% multilang(LANG_CHOOSE_FILE); %>!');
		document.saveConfig.binary.focus();
		return false;
	}
	return true;
}

</script>

</head>
<body>
<blockquote>
<h2 class="page_title"><% multilang(LANG_BUNDLE_INSTALLATION); %></h2>
  <table>
  <tr><td><font size=2>
 <% multilang(LANG_THIS_PAGE_ALLOWS_YOU_TO_INSTALL_NEW_BUNDLE); %>
  </font></td></tr>
  <tr><td><hr size=1 noshade align=top></td></tr>
  </table>

  <table width=500>
  
  <form action=/boaform/formOsgiUpload enctype="multipart/form-data" method=POST name="saveConfig">
  <tr>
    <th><% multilang(LANG_INSTALL_BUNDLE_FROM_FILE); %>:</th>
    <td><input type="file" value="<% multilang(LANG_CHOOSE_FILE); %>" name="binary" size=24></td>
  </tr>  
  <tr>
    <th></th>
    <td><input type="submit" value="<% multilang(LANG_INSTALL); %>" name="load" onclick="return uploadClick()"></td>
    <input type="hidden" value="/osgi_bndins.asp" name="submit-url">
  </tr>  
  </form> 
  
</table>
</blockquote>
</body>
</html>
