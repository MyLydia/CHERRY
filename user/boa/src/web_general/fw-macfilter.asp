<%SendWebHeadStr(); %>

<title>MAC <% multilang(LANG_FILTERING); %></title>
<script>
function skip () { this.blur(); }
function addClick(obj)
{
//  if (document.formFilterAdd.srcmac.value=="" )
//	return true;
  if (document.formFilterAdd.srcmac.value=="" && document.formFilterAdd.dstmac.value=="") {	
	alert('<% multilang(LANG_INPUT_MAC_ADDRESS); %>');
	return false;
  }

	if (document.formFilterAdd.srcmac.value != "") {
		if (!checkMac(document.formFilterAdd.srcmac, 0))
			return false;
	}
	if (document.formFilterAdd.dstmac.value != "") {
		if (!checkMac(document.formFilterAdd.dstmac, 0))
			return false;
	}
	obj.isclick = 1;
	postTableEncrypt(document.formFilterAdd.postSecurityFlag, document.formFilterAdd);
	
	return true;
/*  var str = document.formFilterAdd.srcmac.value;
  if ( str.length < 12) {
	alert("Input MAC address is not complete. It should be 12 digits in hex.");
	document.formFilterAdd.srcmac.focus();
	return false;
  }

  for (var i=0; i<str.length; i++) {
    if ( (str.charAt(i) >= '0' && str.charAt(i) <= '9') ||
			(str.charAt(i) >= 'a' && str.charAt(i) <= 'f') ||
			(str.charAt(i) >= 'A' && str.charAt(i) <= 'F') )
			continue;

	alert("Invalid MAC address. It should be in hex number (0-9 or a-f).");
	document.formFilterAdd.srcmac.focus();
	return false;
  }
  return true;*/
}

function disableDelButton()
{
  if (verifyBrowser() != "ns") {
	disableButton(document.formFilterDel.deleteSelFilterMac);
	disableButton(document.formFilterDel.deleteAllFilterMac);
  }
}

function on_submit(obj)
{
	obj.isclick = 1;
	postTableEncrypt(document.formFilterDefault.postSecurityFlag, document.formFilterDefault);
	return true;
}

function deleteClick(obj)
{
	if ( !confirm('<% multilang(LANG_CONFIRM_DELETE_ONE_ENTRY); %>') ) {
		return false;
	}
	else{
		obj.isclick = 1;
		postTableEncrypt(document.formFilterDel.postSecurityFlag, document.formFilterDel);
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
		postTableEncrypt(document.formFilterDel.postSecurityFlag, document.formFilterDel);
		return true;
	}
}
</script>
</head>

<body>
<div class="intro_main ">
	<p class="intro_title"><% multilang(LANG_MAC_FILTERING_FOR_BRIDGE_MODE); %></p>
	<p class="intro_content"> <% multilang(LANG_PAGE_DESC_LAN_TO_INTERNET_DATA_PACKET_FILTER_TABLE); %></p>
</div>


<form action=/boaform/admin/formFilter method=POST name="formFilterDefault">
<div class="data_common data_common_notitle">
	<table>
		<tr>
			<th width="30%"><% multilang(LANG_OUTGOING_DEFAULT_ACTION); %>:&nbsp;&nbsp;</th>
		   	<td width="70%">
				<input type="radio" name="outAct" value=0 <% checkWrite("macf_out_act0"); %>><% multilang(LANG_DENY); %>&nbsp;&nbsp;
			   	<input type="radio" name="outAct" value=1 <% checkWrite("macf_out_act1"); %>><% multilang(LANG_ALLOW); %>&nbsp;&nbsp;
			</td>
		</tr>
		<tr>
			<th width="30%"><% multilang(LANG_INCOMING_DEFAULT_ACTION); %>:&nbsp;&nbsp;</th>
			<td width="70%">
				<input type="radio" name="inAct" value=0 <% checkWrite("macf_in_act0"); %>><% multilang(LANG_DENY); %>&nbsp;&nbsp;
			   	<input type="radio" name="inAct" value=1 <% checkWrite("macf_in_act1"); %>><% multilang(LANG_ALLOW); %>&nbsp;&nbsp;
			</td>
		</tr>
	</table>
</div>
<div class="btn_ctl">
	<input class="link_bg" type="submit" value="<% multilang(LANG_APPLY_CHANGES); %>" name="setMacDft" onClick="return on_submit(this)">&nbsp;&nbsp;
	<input type="hidden" value="/admin/fw-macfilter.asp" name="submit-url">
	<input type="hidden" name="postSecurityFlag" value="">
</div>
</form>



<form action=/boaform/admin/formFilter method=POST name="formFilterAdd">
<div class="data_common data_common_notitle">
<table>
	<tr>
		<th width="30%">
			<% multilang(LANG_DIRECTION); %>: 
		</th>
		<td>
			<select name=dir>
				<option select value=0><% multilang(LANG_OUTGOING); %></option>
				<option value=1><% multilang(LANG_INCOMING); %></option>
			</select>
		</td>
	</tr>
	<tr>
		<th>
			<% multilang(LANG_SOURCE); %> <% multilang(LANG_MAC_ADDRESS); %>: 
		</th>
		<td>
			<input type="text" name="srcmac" size="15" maxlength="12" style="text-transform: uppercase"></input>
		</td>
	</tr>
	<tr>
		<th><% multilang(LANG_DESTINATION); %> <% multilang(LANG_MAC_ADDRESS); %>: </th>
	    <td>
	        <input type="text" name="dstmac" size="15" maxlength="12" style="text-transform: uppercase"></input>
		</td>
	</tr>
	<tr>
		<th><% multilang(LANG_RULE_ACTION); %>:</th>
		<td>
			<input type="radio" name="filterMode" value="Deny" checked>&nbsp;&nbsp;<% multilang(LANG_DENY); %>
			<input type="radio" name="filterMode" value="Allow">&nbsp;&nbsp;<% multilang(LANG_ALLOW); %>
		</td>
	</tr>
	</table>
</div>	

<div class="btn_ctl">
	<input class="link_bg" type="submit" value="<% multilang(LANG_ADD); %>" name="addFilterMac" onClick="return addClick(this)">
	<input type="hidden" value="/admin/fw-macfilter.asp" name="submit-url">
	<input type="hidden" name="postSecurityFlag" value=""></font>
</div>
</form>

<form action=/boaform/formFilter method=POST name="formFilterDel">
<div class="column">
	<div class="column_title">
		<div class="column_title_left"></div>
			<p><% multilang(LANG_CURRENT_FILTER_TABLE); %></p>
		<div class="column_title_right"></div>
	</div>
	<div class="data_common data_vertical">
		<table>
			<% macFilterList(); %>
		</table>
	</div>
</div>

<div class="btn_ctl">
	<input class="link_bg" type="submit" value="<% multilang(LANG_DELETE_SELECTED); %>" name="deleteSelFilterMac" onClick="return deleteClick(this)">&nbsp;&nbsp;
	<input class="link_bg" type="submit" value="<% multilang(LANG_DELETE_ALL); %>" name="deleteAllFilterMac" onClick="return deleteAllClick(this)">&nbsp;&nbsp;&nbsp;
	<input type="hidden" value="/admin/fw-macfilter.asp" name="submit-url">
	<input type="hidden" name="postSecurityFlag" value="">
</div>
<script>
	<% checkWrite("macFilterNum"); %>
</script>
</form>

</body>
</html>
