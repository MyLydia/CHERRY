<% SendWebHeadStr();%>
<title><% multilang(LANG_WLAN_ACCESS_CONTROL); %></title>

<script>
function skip () { this.blur(); }
function addClick(obj)
{
//  var str = document.formWlAcAdd.mac.value;

// if (!document.formWlAcAdd.wlanAcEnabled.checked)
//  if (!document.formWlAcAdd.wlanAcEnabled.selectedIndex)
//	return true;

	if (!checkMac(document.formWlAcAdd.mac, 1))
		return false;
	obj.isclick = 1;
	postTableEncrypt(document.formWlAcAdd.postSecurityFlag, document.formWlAcAdd);
	return true;
/*  if ( str.length == 0)
  	return true;

  if ( str.length < 12) {
	alert("<% multilang(LANG_INVALID_MAC_ADDR_NOT_COMPLETE); %>");
	document.formWlAcAdd.mac.focus();
	return false;
  }

  for (var i=0; i<str.length; i++) {
    if ( (str.charAt(i) >= '0' && str.charAt(i) <= '9') ||
			(str.charAt(i) >= 'a' && str.charAt(i) <= 'f') ||
			(str.charAt(i) >= 'A' && str.charAt(i) <= 'F') )
			continue;

	alert("<% multilang(LANG_INVALID_MAC_ADDRESS_IT_SHOULD_BE_IN_HEX_NUMBER_0_9_OR_A_F_); %>");
	document.formWlAcAdd.mac.focus();
	return false;
  }
  return true;*/
}

function disableDelButton()
{
	disableButton(document.formWlAcDel.deleteSelFilterMac);
	disableButton(document.formWlAcDel.deleteAllFilterMac);
}

function enableAc()
{
  enableTextField(document.formWlAcAdd.mac);
}

function disableAc()
{
  disableTextField(document.formWlAcAdd.mac);
}

function updateState()
{
  if(wlanDisabled || wlanMode == 1 || wlanMode ==2){
	disableDelButton();
	//disableButton(document.formWlAcDel.reset);
	disableButton(document.formWlAcAdd.reset);
	disableButton(document.formWlAcAdd.setFilterMode);
	disableButton(document.formWlAcAdd.addFilterMac);
  	disableTextField(document.formWlAcAdd.wlanAcEnabled);
  	disableAc();
  } 
  else{
    if (document.formWlAcAdd.wlanAcEnabled.selectedIndex) {
	enableButton(document.formWlAcAdd.reset);
	enableButton(document.formWlAcAdd.addFilterMac);
 	enableAc();
    }
    else {
	disableButton(document.formWlAcAdd.reset);
	disableButton(document.formWlAcAdd.addFilterMac);
  	disableAc();
    }
  }
}

function on_submit(obj)
{
	obj.isclick = 1;
	postTableEncrypt(document.formWlAcAdd.postSecurityFlag, document.formWlAcAdd);
	return true;
}

function deleteClick(obj)
{
	if ( !confirm('<% multilang(LANG_CONFIRM_DELETE_ONE_ENTRY); %>') ) {
		return false;
	}
	else{
		obj.isclick = 1;
		postTableEncrypt(document.formWlAcDel.postSecurityFlag, document.formWlAcDel);
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
		postTableEncrypt(document.formWlAcDel.postSecurityFlag, document.formWlAcDel);
		return true;
	}
}

</script>
</head>

<body>
<div class="intro_main ">
	<p class="intro_title"><% multilang(LANG_WLAN_ACCESS_CONTROL); %></p>
	<p class="intro_content"><% multilang(LANG_PAGE_DESC_WLAN_ALLOW_DENY_LIST); %></p>
</div>
<form action=/boaform/admin/formWlAc method=POST name="formWlAcAdd">
<div class="data_common data_common_notitle">
	<table>
		<tr>
			<th width="30%">
				<% multilang(LANG_MODE); %>: &nbsp;&nbsp;&nbsp;&nbsp;
			</th>
			<td>
			<select size="1" name="wlanAcEnabled" onclick="updateState()">
				<option value=0 ><% multilang(LANG_DISABLED); %></option>
				<option value=1 selected ><% multilang(LANG_ALLOW_LISTED); %></option>
				<option value=2 ><% multilang(LANG_DENY_LISTED); %></option>
			</select>
			</td>
			<td><input type="submit" value="<% multilang(LANG_APPLY_CHANGES); %>" name="setFilterMode" class="inner_btn" onClick="return on_submit(this)">&nbsp;&nbsp;</td>
		</tr>
	</table>
</div>

<div class="data_common data_common_notitle">
	<table>
		<tr>
			<th width="30%"><% multilang(LANG_MAC_ADDRESS); %>: </th>
			<td>
				<input type="text" name="mac" size="15" maxlength="12">&nbsp;&nbsp;(ex. 00E086710502)
			</td>
		</tr>
	</table>
</div>
<div class="btn_ctl">
	<input type="submit" value="<% multilang(LANG_ADD); %>" name="addFilterMac" onClick="return addClick(this)" class="link_bg">&nbsp;&nbsp;
	<input type="reset" value="<% multilang(LANG_RESET); %>" name="reset" class="link_bg">&nbsp;&nbsp;&nbsp;
	<input type="hidden" value="/admin/wlactrl.asp" name="submit-url">
	<input type="hidden" name="wlan_idx" value=<% checkWrite("wlan_idx"); %>>
	<input type="hidden" name="postSecurityFlag" value="">
</div>   

</form>
<form action=/boaform/admin/formWlAc method=POST name="formWlAcDel">
<div class="column">
	<div class="column_title">
		<div class="column_title_left"></div>
			<p><% multilang(LANG_CURRENT_ACCESS_CONTROL_LIST); %></p>
		<div class="column_title_right"></div>
	</div>
	<div class="data_common data_vertical">
		<table border="0" width=440>
			<% wlAcList(); %>
		</table>
	</div>
</div>
<div class="btn_ctl">
	<input type="submit" value="<% multilang(LANG_DELETE_SELECTED); %>" name="deleteSelFilterMac" onClick="return deleteClick(this)" class="link_bg">&nbsp;&nbsp;
	<input type="submit" value="<% multilang(LANG_DELETE_ALL); %>" name="deleteAllFilterMac" onClick="return deleteAllClick(this)" class="link_bg">&nbsp;&nbsp;&nbsp;
	<input type="hidden" value="/admin/wlactrl.asp" name="submit-url">
	<input type="hidden" name="wlan_idx" value=<% checkWrite("wlan_idx"); %>>
	<input type="hidden" name="postSecurityFlag" value="">
</div>
<script>
	<% checkWrite("wlanAcNum"); %>
	<% initPage("wlactrl"); %>
	updateState();
</script>
<br><br>
</form>
</body>
</html>
