<html>
<! Copyright (c) Realtek Semiconductor Corp., 2017. All Rights Reserved. ->
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<title><% multilang(LANG_WLAN_MESH_SETTINGS); %></title>
<link rel="stylesheet" type="text/css" href="common_style.css" />
<script type="text/javascript" src="share.js"></script>
<script>

//var isNewMeshUI =  <% getIndex("isNewMeshUI"); %> ;
var wlanDisabled;
var wlanMode;
var mesh_enable;
var mesh_id;
var mesh_wpaPSK;
var encrypt;
var psk_format;
var crossband;
    

function enable_allEncrypt()
{
  form = document.formMeshSetup ;
  enableTextField(form.elements["mesh_method"]);
  enableTextField(form.elements["mesh_pskFormat"]);
  enableTextField(form.elements["mesh_pskValue"]);
  //enableButton(document.formEncrypt.save);
  //enableButton(document.formEncrypt.reset);  
}

function disable_allEncrypt()
{
  form = document.formMeshSetup ;
  disableTextField(form.elements["mesh_method"]);
  disableTextField(form.elements["mesh_pskFormat"]);
  disableTextField(form.elements["mesh_pskValue"]);
  //disableButton(document.formEncrypt.save);
  //disableButton(document.formEncrypt.reset);  
}

function disable_wpa()
{
  form = document.formMeshSetup ;
  disableTextField(form.elements["mesh_pskFormat"]);
  disableTextField(form.elements["mesh_pskValue"]);
}

function enable_wpa()
{  
  form = document.formMeshSetup ;
  enableTextField(form.elements["mesh_pskFormat"]);
  enableTextField(form.elements["mesh_pskValue"]);
}

function checkState()
{
  form = document.formMeshSetup ;
  	if (form.elements["mesh_method"].selectedIndex==1)
  		enable_wpa();
  	else
  		disable_wpa();

}

function switch_Mesh(option)
{
	form = document.formMeshSetup;

	if( option == 1 )	//switch ON
	{
		enableButton(document.formMeshSetup.meshID);
		if( mesh_enable == 0 )
        {
            disableButton(document.formMeshSetup.showACL);
            disableButton(document.formMeshSetup.showInfo);
        }
		else
		{
			enableButton(document.formMeshSetup.showACL);
                        enableButton(document.formMeshSetup.showInfo);
		}
		enableButton(document.formMeshSetup.reset);
  		enableTextField(form.elements["mesh_method"]);
		checkState();
		enableRadioGroup(document.formMeshSetup.elements["mesh_crossband"]);
	}
	else
	{
		disableButton(document.formMeshSetup.meshID);
		disableButton(document.formMeshSetup.showACL);
		disableButton(document.formMeshSetup.showInfo);
		disableButton(document.formMeshSetup.reset);
		disable_allEncrypt();
		disableRadioGroup(document.formMeshSetup.elements["mesh_crossband"]);
	}
}

function updateState2()
{
	if( wlanMode <4 || wlanDisabled )
	{		
		disableButton(document.formMeshSetup.save);
		disableButton(document.formMeshSetup.reset);	
		disableButton(document.formMeshSetup.meshID);
		disableButton(document.formMeshSetup.showACL);
		disableButton(document.formMeshSetup.showInfo);
		disableTextField(document.formMeshSetup.wlanMeshEnable);
		disable_allEncrypt();
		disableRadioGroup(document.formMeshSetup.elements["mesh_crossband"]);
		return;
	}
	else
	{
		enableTextField(document.formMeshSetup.wlanMeshEnable);
		switch_Mesh(document.formMeshSetup.wlanMeshEnable.checked);
	}
}

function saveChanges_mesh(form, wlan_id)
{
	method = form.elements["mesh_method"] ;
	if (method.selectedIndex == 1 )
		return check_wpa_psk(form, form.wlan_idx);
	return true;
}

function showMeshACLClick(url)
{
	//openWindow(url, 'showMeshACL',620,340 );
	document.location.href = url;
}

function showMeshInfoClick(url)
{
	//openWindow(url, 'showMeshInfo',620,340 );
	document.location.href = url;
}

function LoadSetting()
{
    
    if( encrypt == 4 )
        document.formMeshSetup.elements["mesh_method"].selectedIndex=1;
    else
        document.formMeshSetup.elements["mesh_method"].selectedIndex=0;

	/*
	if(<% getInfo("isMeshCrossbandDefined"); %> == 1) {	
		document.getElementById("meshcrossband").style.display = "";
		if( crossband == 1)
			document.formMeshSetup.elements["mesh_crossband"][0].checked = true;
		else
			document.formMeshSetup.elements["mesh_crossband"][1].checked = true;
	}
	else {
		document.getElementById("meshcrossband").style.display = "none";
	}
	*/
	document.formMeshSetup.meshID.value = mesh_id; 
	document.formMeshSetup.mesh_pskValue.value = mesh_wpaPSK;
	document.formMeshSetup.wlanMeshEnable.checked = mesh_enable? true: false;
    updateState2();
}

</script>
</head>
<body onload="LoadSetting()">
<blockquote>
<h2 class="page_title">Wireless Mesh Network Setting</h2>
<table border=0 width="550" cellspacing=4 cellpadding=0>
<tr><font size=2>
	  Mesh network uses wireless media to communicate with other APs, like the Ethernet does.
	  To do this, you must set these APs in the same channel with the same Mesh ID.
	  The APs should be under AP+MESH/MESH mode.
</font></tr>

<form action=/boaform/admin/formMeshSetup method=POST name="formMeshSetup">
<tr><hr size=1 noshade align=top><br></tr>
<!-- new feature:Mesh enable/disable -->
<tr><font size=2><b>
<input type="checkbox" name="wlanMeshEnable" value="ON" onClick="updateState2()">&nbsp;&nbsp;Enable Mesh</b></tr>
<!--<script type="text/javascript">
	if ( mesh_enable ) {	
		document.write('<input type="checkbox" name="wlanMeshEnable" value="ON" onClick="updateState2()" checked="checked">&nbsp;&nbsp;Enable Mesh</b></tr>');
	}
	else {
		document.write('<input type="checkbox" name="wlanMeshEnable" value="ON" onClick="updateState2()">&nbsp;&nbsp;Enable Mesh</b></tr>');
	}
</script> -->
<table width="550" border="0" cellpadding="0" cellspacing="0">
  <tr>
 	<td width="35%"><font size=2><b>Mesh ID:</b></td>
 	<td width="65%"><input type="text" name="meshID" size="33" maxlength="32"></td>
	</tr>
  <tr>
  <td width="35%"><font size="2"><b>Encryption:&nbsp;</b></td>
  <td width="65%"><font size="2"><select size="1" name="mesh_method" onChange="checkState()" >
    <option value="0">None</option>
    <option value="4">WPA2 (AES)</option>
    </select></font></td>
  </tr>
  <tr>
  <td width="35%"><font size="2"><b>Pre-Shared Key Format:</b></font> </td>
  <td width="65%"><font size="2"><select size="1" name="mesh_pskFormat">
    <option value="0">Passphrase</option>
    <option value="1">Hex (64 characters)</option>
    </select></font></td>
  </tr>
  <tr>
    <td width="35%"><font size="2"><b>Pre-Shared Key:</b></font> </td>
    <td width="65%"><font size="2"><input type="password" name="mesh_pskValue" size="40" maxlength="64"></font></td>
  </tr>
  <tr id="meshcrossband" style="display:none">
  <td width="35%"><font size="2"><b>Mesh Crossband:&nbsp;</b></td>
  <td width="65%"><font size="1">
    <input type="radio" name="mesh_crossband" value="1" >Enabled&nbsp;&nbsp;
     <input type="radio" name="mesh_crossband" value="0" >Disabled
    </font></td>
  </tr>
</table>
    
	<br>
	<input type="hidden" name="wlan_idx" value=<% checkWrite("wlan_idx"); %>>
	<input type="hidden" value="/wlmesh.asp" name="submit-url">
	<input type="submit" value="Apply Changes" name="save" onClick="return saveChanges_mesh(document.formMeshSetup, wlan_idx)">&nbsp;&nbsp;
<!--	<input type="reset" value="  Reset  " name="reset" OnClick="checkState()" >&nbsp;&nbsp;&nbsp;&nbsp; -->
<!--
    <input type="submit" value="Save" name="save" onClick="return saveChanges_mesh(document.formMeshSetup, wlan_idx)">&nbsp;&nbsp;
	<input type="submit" value="Save & Apply" name="save_apply" onClick="return saveChanges_mesh(document.formMeshSetup, wlan_idx)">&nbsp;&nbsp;
	<input type="reset" value="  Reset  " name="reset" OnClick="checkState()" >&nbsp;&nbsp;&nbsp;&nbsp;
-->
	<input type="button" value="Set Access Control" name="showACL" onClick="showMeshACLClick('/boaform/admin/formWirelessTbl?submit-url=/wlmeshACL.asp&wlan_idx=<% checkWrite("wlan_idx"); %>')">&nbsp;
	<input type="button" value="Show Advanced Information" name="showInfo" onClick="showMeshInfoClick('/boaform/admin/formWirelessTbl?submit-url=/wlmeshinfo.asp&wlan_idx=<% checkWrite("wlan_idx"); %>')">&nbsp;&nbsp;
</tr>
<script>
	<% initPage("wlmesh"); %>
</script>
</form>
</table>  

</body>
</blockquote>
</html>
