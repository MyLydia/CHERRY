<html>
<! Copyright (c) Realtek Semiconductor Corp., 2003. All Rights Reserved. ->
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<link rel="stylesheet" type="text/css" href="common_style.css" />
<title><% multilang(LANG_BACKUP_AND_RESTORE_SETTINGS); %></title>
<SCRIPT language="javascript" src="/common.js"></SCRIPT>
<script>
function resetClick(obj)
{
	if(confirm("<% multilang(LANG_DO_YOU_REALLY_WANT_TO_RESET_THE_CURRENT_SETTINGS_TO_FACTORY_DEFAULT); %>"))
	{
		obj.isclick = 1;
		postTableEncrypt(document.resetConfig.postSecurityFlag, document.resetConfig);
		return true;
	}
	else
		return false;
}

function uploadClick()
{		
   	if (document.saveConfig.binary.value.length == 0) {
		alert('<% multilang(LANG_CHOOSE_FILE); %>!');
		document.saveConfig.binary.focus();
		return false;
	}
	return true;
}

function on_submit(obj)
{
	obj.isclick = 1;
	postTableEncrypt(document.saveCSConfig.postSecurityFlag, document.saveCSConfig);
	return true;
}
</script>

</head>
<body>
<blockquote>
<h2 class="page_title"><% multilang(LANG_BACKUP_AND_RESTORE_SETTINGS); %></font></h2>
  <table>
  <tr><td>
 <% multilang(LANG_THIS_PAGE_ALLOWS_YOU_TO_BACKUP_CURRENT_SETTINGS_TO_A_FILE_OR_RESTORE_THE_SETTINGS_FROM_THE_FILE_WHICH_WAS_SAVED_PREVIOUSLY_BESIDES_YOU_COULD_RESET_THE_CURRENT_SETTINGS_TO_FACTORY_DEFAULT); %>
  </td></tr>
  <tr><td><hr size=1 noshade align=top></td></tr>
  </table>

  <table>
  <form action=/boaform/formSaveConfig method=POST name="saveCSConfig">
  <tr>
    <th><% multilang(LANG_BACKUP_SETTINGS_TO_FILE); %>:</th>
    <td>
      <input type="submit" value="<% multilang(LANG_BACKUP); %>..." name="save_cs" onClick="return on_submit(this)">
      <input type="hidden" name="postSecurityFlag" value="">
    </td>
   </tr>  
  </form>  

  <!--
  <form action=/boaform/formSaveConfig method=POST name="saveHSConfig">
  <tr>
    <td class="table_item"><% multilang(LANG_BACKUP_HARDWARE_SETTINGS_TO_FILE); %>:</td>
    <td>
      <input type="submit" value="<% multilang(LANG_BACKUP); %>..." name="save_hs">
    </td>
  </form>  
  -->
  
  <form action=/boaform/formSaveConfig enctype="multipart/form-data" method=POST name="saveConfig">
  <tr>
    <th><% multilang(LANG_RESTORE_SETTINGS_FROM_FILE); %>:</th>
    <td><input type="file" value="<% multilang(LANG_CHOOSE_FILE); %>" name="binary" size=24></td>
    <td><input type="submit" value="<% multilang(LANG_RESTORE); %>" name="load" onclick="return uploadClick()"></td>
    <input type="hidden" value="/saveconf.asp" name="submit-url">
  </tr>  
  </form> 
  
  <form action=/boaform/formSaveConfig method=POST name="resetConfig">
  <tr>
    <th><% multilang(LANG_RESET_SETTINGS_TO_DEFAULT); %>:</th>
    <td>
    <input type="submit" value="<% multilang(LANG_RESET); %>" name="reset" onclick="return resetClick(this)"></td>
    <input type="hidden" value="/saveconf.asp" name="submit-url">
    <input type="hidden" name="postSecurityFlag" value="">
   </tr>
  </form>
</table>
</blockquote>
</body>
</html>
