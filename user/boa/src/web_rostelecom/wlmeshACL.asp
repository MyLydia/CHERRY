<html>
<! Copyright (c) Realtek Semiconductor Corp., 2003. All Rights Reserved. ->
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<title><% multilang(LANG_WLAN_MESH_ACCESS_CONTROL); %></title>
<link rel="stylesheet" type="text/css" href="common_style.css" />
<script type="text/javascript" src="share.js">
</script>
<script>

function skip () { this.blur(); }
function addClick()
{
//  var str = document.formMeshACLAdd.mac.value;

// if (!document.formMeshACLAdd.wlanAcEnabled.checked)
//  if (!document.formMeshACLAdd.wlanAcEnabled.selectedIndex)
//	return true;

	if (!checkMac(document.formMeshACLAdd.mac, 1))
		return false;
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

</script>
</head>
<body>
<blockquote>
<h2 class="page_title"><% multilang(LANG_WLAN_MESH_ACCESS_CONTROL); %></h2>
<form action=/boaform/admin/formMeshACLSetup method=POST name="formMeshACLAdd">
<table>
<tr><td><font size=2>
 <% multilang(LANG_PAGE_DESC_WLAN_MESH_ACCESS_CONTROL); %>
</font></td></tr>
<tr><td><hr size=1 noshade align=top></td></tr>
</table>

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
   <td><input type="submit" value="<% multilang(LANG_APPLY_CHANGES); %>" name="setFilterMode">&nbsp;&nbsp;</td>
</tr>
</table>
<td>

<table>
<tr><td colspan=2><hr size=1 noshade align=top></td></tr>
<tr><th><% multilang(LANG_MAC_ADDRESS); %>: </th>
	<td><input type="text" name="mac" size="15" maxlength="12">
     &nbsp;&nbsp;(ex. 00E086710502)</td></tr>
<tr>
     <td><input type="submit" value="<% multilang(LANG_ADD); %>" name="addFilterMac" onClick="return addClick()">&nbsp;&nbsp;
        <input type="reset" value="<% multilang(LANG_RESET); %>" name="reset">&nbsp;&nbsp;&nbsp;
        <input type="hidden" value="/wlmeshACL.asp" name="submit-url">
        <input type="hidden" name="wlan_idx" value=<% checkWrite("wlan_idx"); %>>
     </td></tr>
</table>
</form>
<form action=/boaform/admin/formMeshACLSetup method=POST name="formMeshACLDel">
  <table>
  <tr><font size=2><b><% multilang(LANG_CURRENT_ACCESS_CONTROL_LIST); %>:</b></font></tr>
  <% wlMeshAcList(); %>
  </table>
  <br>
  <input type="submit" value="<% multilang(LANG_DELETE_SELECTED); %>" name="deleteSelFilterMac" onClick="return deleteClick()">&nbsp;&nbsp;
  <input type="submit" value="<% multilang(LANG_DELETE_ALL); %>" name="deleteAllFilterMac" onClick="return deleteAllClick()">&nbsp;&nbsp;&nbsp;
  <input type="hidden" value="/wlmeshACL.asp" name="submit-url">
  <input type="hidden" name="wlan_idx" value=<% checkWrite("wlan_idx"); %>>
 <script>
 	<% checkWrite("wlanMeshAclNum"); %>
	<% initPage("wlmeshactrl"); %>
	updateState();
 </script>
</form>

</blockquote>
</body>
</html>
