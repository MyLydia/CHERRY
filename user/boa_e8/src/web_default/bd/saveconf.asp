<html>
<! Copyright (c) Realtek Semiconductor Corp., 2003. All Rights Reserved. ->
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<title>Backup and Restore Settings</title>
<SCRIPT language="javascript" src="../common.js"></SCRIPT>
<script>
function resetClick()
{
	document.resetConfig.reset.isclick = 1;
	postTableEncrypt(document.resetConfig.postSecurityFlag, document.resetConfig);
	
	return confirm("Do you really want to reset the current settings to factory default?");
}

function uploadClick()
{		
   	if (document.saveConfig.binary.value.length == 0) {
		alert("Choose File!");
		document.saveConfig.binary.focus();
		return false;
	}
	document.saveConfig.load.isclick = 1;
	
	return true;
}

function on_submit()
{
	document.saveCSConfig.save_cs.isclick = 1;
	postTableEncrypt(document.saveCSConfig.postSecurityFlag, document.saveCSConfig);
	return true;
}

</script>

</head>
<body>
<blockquote>
<!--<h2><font color="#0000FF">Backup and Restore Settings</font></h2>
  <table border="0" cellspacing="4" width="500">
  <tr><td><font size=2>
 This page allows you to backup current settings to a file or restore the settings from the file which was saved previously. Besides, you could reset the current settings to factory default.
  </font></td></tr>
  <tr><td><hr size=1 noshade align=top></td></tr>
  </table>-->

  <table border="0" cellspacing="4" width="500">
  <form action=/boaform/formSaveConfig method=POST name="saveCSConfig">
  <tr>
    <td width="40%"><font size=2><b>Backup Settings to File:</b></font></td>
    <td width="30%"><font size=2>
      <input type="submit" value="Backup..." name="save_cs" onclick="return on_submit()">
    </font></td>
    <input type="hidden" name="postSecurityFlag" value="">
  </tr>
  </form>  

  <form action=/boaform/formSaveConfig enctype="multipart/form-data" method=POST name="saveConfig">
  <tr>
    <td width="40%"><font size=2><b>Restore Settings from File:</b></font></td>
    <td width="30%"><font size=2><input type="file" value="Choose File" name="binary" size=24></font></td>
    <td width="20%"><font size=2><input type="submit" value="Restore" name="load" onclick="return uploadClick()"></font></td>
    <input type="hidden" value="/saveconf.asp" name="submit-url">
  </tr>  
  </form> 
  
  <form action=/boaform/formSaveConfig method=POST name="resetConfig">
  <tr>
    <td width="70%"><font size=2><b>Reset Settings to Default:</b></font></td>
    <td width="30%"><font size=2>
    <input type="submit" value="Reset" name="reset" onclick="return resetClick()"></font></td>
    <input type="hidden" value="/saveconf.asp" name="submit-url">
    <input type="hidden" name="postSecurityFlag" value="">
   </tr>
  </form>
</table>
</blockquote>
</body>
</html>
