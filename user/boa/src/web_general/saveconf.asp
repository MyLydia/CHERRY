<% SendWebHeadStr();%>
<title><% multilang(LANG_BACKUP_AND_RESTORE_SETTINGS); %></title>

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
<div class="intro_main ">
    <p class="intro_title"><% multilang(LANG_BACKUP_AND_RESTORE_SETTINGS); %></p>
    <p class="intro_content"> <% multilang(LANG_THIS_PAGE_ALLOWS_YOU_TO_BACKUP_CURRENT_SETTINGS_TO_A_FILE_OR_RESTORE_THE_SETTINGS_FROM_THE_FILE_WHICH_WAS_SAVED_PREVIOUSLY_BESIDES_YOU_COULD_RESET_THE_CURRENT_SETTINGS_TO_FACTORY_DEFAULT); %></p>
</div>

<form action=/boaform/formSaveConfig method=POST name="saveCSConfig">
<div class="data_common data_common_notitle">
	<table>
<tr>
<th width="40%"><% multilang(LANG_BACKUP_SETTINGS_TO_FILE); %>:</th>
<td width="60%">
  <input  class="inner_btn" type="submit" value="<% multilang(LANG_BACKUP); %>..." name="save_cs" onClick="return on_submit(this)">
  <input type="hidden" name="postSecurityFlag" value="">
</td>
</tr>  
	</table>
</div>
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
<div class="data_common data_common_notitle">
	<table>
		<tr>
			<th width="40%"><% multilang(LANG_RESTORE_SETTINGS_FROM_FILE); %>:</th>
			<td width="60%">
				<input type="file" value="<% multilang(LANG_CHOOSE_FILE); %>" name="binary" size=24>&nbsp;&nbsp;&nbsp;&nbsp;
				<input class="inner_btn" type="submit" value="<% multilang(LANG_RESTORE); %>" name="load" onclick="return uploadClick()">
			</td>
			<input type="hidden" value="/saveconf.asp" name="submit-url" >
		</tr>  
	</table>
</div>
</form> 
  
<form action=/boaform/formSaveConfig method=POST name="resetConfig">
<div class="data_common data_common_notitle">
	<table>
		<tr>
			<th width="40%"><% multilang(LANG_RESET_SETTINGS_TO_DEFAULT); %>:</th>
			<td width="60%">
				<input class="inner_btn" type="submit" value="<% multilang(LANG_RESET); %>" name="reset" onclick="return resetClick(this)">
				<input class="inner_btn" type="hidden" value="/saveconf.asp" name="submit-url">
			</td>
			<input type="hidden" name="postSecurityFlag" value="">
		</tr>
	</table>
</div>
</form>
</body>
</html>
