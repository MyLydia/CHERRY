<%SendWebHeadStr(); %>
<title><% multilang(LANG_WLAN_MESH_SETTINGS); %></title>

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
		//enableButton(document.formMeshSetup.reset);
  		enableTextField(form.elements["mesh_method"]);
		checkState();
		enableRadioGroup(document.formMeshSetup.elements["mesh_crossband"]);
	}
	else
	{
		disableButton(document.formMeshSetup.meshID);
		disableButton(document.formMeshSetup.showACL);
		disableButton(document.formMeshSetup.showInfo);
		//disableButton(document.formMeshSetup.reset);
		disable_allEncrypt();
		disableRadioGroup(document.formMeshSetup.elements["mesh_crossband"]);
	}
}

function updateState2()
{
	if( wlanMode <4 || wlanDisabled )
	{		
		disableButton(document.formMeshSetup.save);
		//disableButton(document.formMeshSetup.reset);	
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
	form.save.isclick = 1;
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	return true;
}

function check_wpa_psk(form, wlan_id)
{
	//missing this function, need to add content
  form.save.isclick = 1;
  postTableEncrypt(form.postSecurityFlag, form);
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
<div class="intro_main ">
	<p class="intro_title">Wireless Mesh Network Setting</p>
	<p class="intro_content">  Mesh network uses wireless media to communicate with other APs, like the Ethernet does.
	  To do this, you must set these APs in the same channel with the same Mesh ID.
	  The APs should be under AP+MESH/MESH mode.</p>
</div>

<form action=/boaform/admin/formMeshSetup method=POST name="formMeshSetup">
<div class="data_common data_common_notitle">
	<table>
	<!-- new feature:Mesh enable/disable -->
		<tr>
			<th>Enable Mesh:</th>
			<td><input type="checkbox" name="wlanMeshEnable" value="ON" onClick="updateState2()">
			</td>
		</tr>
	<!--<script type="text/javascript">
		if ( mesh_enable ) {	
			document.write('<input type="checkbox" name="wlanMeshEnable" value="ON" onClick="updateState2()" checked="checked">&nbsp;&nbsp;Enable Mesh</b></tr>');
		}
		else {
			document.write('<input type="checkbox" name="wlanMeshEnable" value="ON" onClick="updateState2()">&nbsp;&nbsp;Enable Mesh</b></tr>');
		}
	</script> -->
	</table>
</div>

<div class="data_common data_common_notitle">
	<table>
		<tr>
			<th width="35%">Mesh ID:</th>
			<td width="65%"><input type="text" name="meshID" size="33" maxlength="32"></td>
		</tr>
		<tr>
			<th width="35%">Encryption:</th>
			<td width="65%"><select size="1" name="mesh_method" onChange="checkState()" >
				<option value="0">None</option>
				<option value="4">WPA2 (AES)</option>
			</select></td>
		</tr>
		<tr>
			<th width="35%">Pre-Shared Key Format:</th>
			<td width="65%"><select size="1" name="mesh_pskFormat">
				<option value="0">Passphrase</option>
				<option value="1">Hex (64 characters)</option>
			</select></td>
		</tr>
		<tr>
			<th width="35%">Pre-Shared Key:</th>
			<td width="65%"><input type="password" name="mesh_pskValue" size="40" maxlength="64"></font></td>
		</tr>
		<tr id="meshcrossband" style="display:none">
			<th width="35%">Mesh Crossband:</th>
			<td width="65%">
				<input type="radio" name="mesh_crossband" value="1" >Enabled&nbsp;&nbsp;
				<input type="radio" name="mesh_crossband" value="0" >Disabled
			</td>
		</tr>
	</table>
</div>

<div class="btn_ctl">
	<input type="hidden" name="wlan_idx" value=<% checkWrite("wlan_idx"); %>>
	<input type="hidden" value="/wlmesh.asp" name="submit-url">
	<input class="link_bg" name="save" type="submit" value="Apply Changes"  onClick="return saveChanges_mesh(document.formMeshSetup, wlan_idx)">&nbsp;&nbsp;
<!--	<input type="reset" value="  Reset  " name="reset" OnClick="checkState()" >&nbsp;&nbsp;&nbsp;&nbsp; -->
<!--
    <input type="submit" value="Save" name="save" onClick="return saveChanges_mesh(document.formMeshSetup, wlan_idx)">&nbsp;&nbsp;
	<input type="submit" value="Save & Apply" name="save_apply" onClick="return saveChanges_mesh(document.formMeshSetup, wlan_idx)">&nbsp;&nbsp;
	<input type="reset" value="  Reset  " name="reset" OnClick="checkState()" >&nbsp;&nbsp;&nbsp;&nbsp;
-->
	<input class="link_bg" type="button" value="Set Access Control" name="showACL" onClick="showMeshACLClick('/boaform/admin/formWirelessTbl?submit-url=/wlmeshACL.asp&wlan_idx=<% checkWrite("wlan_idx"); %>')">&nbsp;
	<input class="link_bg" type="button" value="Show Advanced Information" name="showInfo" onClick="showMeshInfoClick('/boaform/admin/formWirelessTbl?submit-url=/wlmeshinfo.asp&wlan_idx=<% checkWrite("wlan_idx"); %>')">&nbsp;&nbsp;
	<input type="hidden" name="postSecurityFlag" value="">
</div>
<script>
	<% initPage("wlmesh"); %>
</script>
</form>
</table>  

</body>
</html>
