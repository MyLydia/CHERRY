<%SendWebHeadStr(); %>
<title><% multilang(LANG_WLAN_MESH_ACCESS_CONTROL); %></title>

<script>
function skip () { this.blur(); }
function addClick(obj)
{
//  var str = document.formMeshACLAdd.mac.value;

// if (!document.formMeshACLAdd.wlanAcEnabled.checked)
//  if (!document.formMeshACLAdd.wlanAcEnabled.selectedIndex)
//	return true;

	if (!checkMac(document.formMeshACLAdd.mac, 1))
		return false;

	obj.isclick = 1;
	postTableEncrypt(document.formMeshACLAdd.postSecurityFlag, document.formMeshACLAdd);
	return true;
/*  if ( str.length == 0)
  	return true;

  if ( str.length < 12) {
	alert("<% multilang(LANG_INVALID_MAC_ADDR_NOT_COMPLETE); %>");
	document.formMeshACLAdd.mac.focus();
	return false;
  }

  for (var i=0; i<str.length; i++) {
    if ( (str.charAt(i) >= '0' && str.charAt(i) <= '9') ||
			(str.charAt(i) >= 'a' && str.charAt(i) <= 'f') ||
			(str.charAt(i) >= 'A' && str.charAt(i) <= 'F') )
			continue;

	alert("<% multilang(LANG_INVALID_MAC_ADDRESS_IT_SHOULD_BE_IN_HEX_NUMBER_0_9_OR_A_F_); %>");
	document.formMeshACLAdd.mac.focus();
	return false;
  }
  return true;*/
}

function disableDelButton()
{
	disableButton(document.formMeshACLDel.deleteSelFilterMac);
	disableButton(document.formMeshACLDel.deleteAllFilterMac);
}

function enableAc()
{
  enableTextField(document.formMeshACLAdd.mac);
}

function disableAc()
{
  disableTextField(document.formMeshACLAdd.mac);
}

function updateState()
{
  if(wlanDisabled || wlanMode == 1 || wlanMode ==2){
	disableDelButton();
	//disableButton(document.formMeshACLDel.reset);
	disableButton(document.formMeshACLAdd.reset);
	disableButton(document.formMeshACLAdd.setFilterMode);
	disableButton(document.formMeshACLAdd.addFilterMac);
  	disableTextField(document.formMeshACLAdd.wlanAcEnabled);
  	disableAc();
  } 
  else{
    if (document.formMeshACLAdd.wlanAcEnabled.selectedIndex) {
	enableButton(document.formMeshACLAdd.reset);
	enableButton(document.formMeshACLAdd.addFilterMac);
 	enableAc();
    }
    else {
	disableButton(document.formMeshACLAdd.reset);
	disableButton(document.formMeshACLAdd.addFilterMac);
  	disableAc();
    }
  }
}

function on_submit(obj)
{
	obj.isclick = 1;
	postTableEncrypt(document.formMeshACLAdd.postSecurityFlag, document.formMeshACLAdd);
	return true;
}

function deleteClick(obj)
{
	if ( !confirm('<% multilang(LANG_CONFIRM_DELETE_ONE_ENTRY); %>') ) {
		return false;
	}
	else{
		obj.isclick = 1;
		postTableEncrypt(document.formMeshACLDel.postSecurityFlag, document.formMeshACLDel);
		return true;
	}
}
        
function deleteAllClick(obj)
{
	if ( !confirm('Do you really want to delete the all entries?') ) {
		return false;
	}
	else{
		obj.isclick = 1;
		postTableEncrypt(document.formMeshACLDel.postSecurityFlag, document.formMeshACLDel);
		return true;
	}
}
</script>
</head>
<body>
<div class="intro_main ">
	<p class="intro_title"><% multilang(LANG_WLAN_MESH_ACCESS_CONTROL); %></p>
	<p class="intro_content"> <% multilang(LANG_PAGE_DESC_WLAN_MESH_ACCESS_CONTROL); %></p>
</div>

<form action=/boaform/admin/formMeshACLSetup method=POST name="formMeshACLAdd">
<div class="data_common data_common_notitle">
	<table>
		<tr>
		   <th>
		   	<% multilang(LANG_MODE); %>: &nbsp;&nbsp;&nbsp;&nbsp;
		   </th>
		   <td>
			<select size="1" name="wlanAcEnabled" onclick="updateState()">
		          <option value=0 ><% multilang(LANG_DISABLED); %></option>
		          <option value=1 selected ><% multilang(LANG_ALLOW_LISTED); %></option>
		          <option value=2 ><% multilang(LANG_DENY_LISTED); %></option>
		        </select>
		   </td>
		   <td><input class="inner_btn" type="submit" value="<% multilang(LANG_APPLY_CHANGES); %>" name="setFilterMode" onClick="return on_submit(this)">&nbsp;&nbsp;</td>
		</tr>
	</table>
</div>

<div class="data_common data_common_notitle">
	<table>
		<tr><th><% multilang(LANG_MAC_ADDRESS); %>: </th>
			<td><input type="text" name="mac" size="15" maxlength="12">
		     &nbsp;&nbsp;(ex. 00E086710502)</td></tr>
	</table>
</div>

<div class="btn_ctl">
	<input class="link_bg" type="submit" value="<% multilang(LANG_ADD); %>" name="addFilterMac" onClick="return addClick(this)">&nbsp;&nbsp;
	<input class="link_bg" type="reset" value="<% multilang(LANG_RESET); %>" name="reset">&nbsp;&nbsp;&nbsp;
	<input type="hidden" value="/wlmeshACL.asp" name="submit-url">
	<input type="hidden" name="wlan_idx" value=<% checkWrite("wlan_idx"); %>>
	<input type="hidden" name="postSecurityFlag" value="">
</div>
</form>

<form action=/boaform/admin/formMeshACLSetup method=POST name="formMeshACLDel">
<div class="column">
	<div class="column_title">
		<div class="column_title_left"></div>
			<p><% multilang(LANG_CURRENT_ACCESS_CONTROL_LIST); %></p>
		<div class="column_title_right"></div>
	</div>
	<div class="data_common">
		<table>
			<% wlMeshAcList(); %>
		</table>
	</div>
</div>

<div class="btn_ctl">
	<input class="link_bg" type="submit" value="<% multilang(LANG_DELETE_SELECTED); %>" name="deleteSelFilterMac" onClick="return deleteClick(this)">&nbsp;&nbsp;
	<input class="link_bg" type="submit" value="<% multilang(LANG_DELETE_ALL); %>" name="deleteAllFilterMac" onClick="return deleteAllClick(this)">&nbsp;&nbsp;&nbsp;
	<input type="hidden" value="/wlmeshACL.asp" name="submit-url">
	<input type="hidden" name="wlan_idx" value=<% checkWrite("wlan_idx"); %>>
	<input type="hidden" name="postSecurityFlag" value="">
</div>
 <script>
 	<% checkWrite("wlanMeshAclNum"); %>
	<% initPage("wlmeshactrl"); %>
	updateState();
 </script>
</form>

</body>
</html>
