<% SendWebHeadStr();%>
<title>SNMP <% multilang(LANG_CONFIGURATION); %></title>
<SCRIPT>
function saveChanges(obj)
{
  //if (!checkIP(document.snmpTable.snmpTrapIpAddr))	// Jenny, sync check IP function
  if (!checkHostIP(document.snmpTable.snmpTrapIpAddr, 1))
	return false;
  /*
  if (document.snmpTable.snmpTrapIpAddr.value=="") {
	alert("<% multilang(LANG_TRAP_IP_ADDRESS_CANNOT_BE_EMPTY_IT_SHOULD_BE_FILLED_WITH_4_DIGIT_NUMBERS_AS_XXX_XXX_XXX_XXX); %>");
	document.snmpTable.snmpTrapIpAddr.value = document.snmpTable.snmpTrapIpAddr.defaultValue;
	document.snmpTable.snmpTrapIpAddr.focus();
	return false;
  }
  if ( validateKey( document.snmpTable.snmpTrapIpAddr.value ) == 0 ) {
	alert("<% multilang(LANG_INVALID_IPV4_ADDR_SHOULD_BE_DECIMAL_NUM); %>");
	document.snmpTable.snmpTrapIpAddr.value = document.snmpTable.snmpTrapIpAddr.defaultValue;
	document.snmpTable.snmpTrapIpAddr.focus();
	return false;
  }
  if( IsLoopBackIP( document.snmpTable.snmpTrapIpAddr.value)==1 ) {
		alert("<% multilang(LANG_INVALID_TRAP_IP_ADDRESS_VALUE); %>");
		document.snmpTable.snmpTrapIpAddr.focus();
		return false;
  }
  if ( !checkDigitRange(document.snmpTable.snmpTrapIpAddr.value,1,0,223) ) {
      	alert("<% multilang(LANG_INVALID_TRAP_IP_ADDRESS_RANGE_IN_1ST_DIGIT_IT_SHOULD_BE_0_223); %>");
	document.snmpTable.snmpTrapIpAddr.value = document.snmpTable.snmpTrapIpAddr.defaultValue;
	document.snmpTable.snmpTrapIpAddr.focus();
	return false;
  }
  if ( !checkDigitRange(document.snmpTable.snmpTrapIpAddr.value,2,0,255) ) {
      	alert("<% multilang(LANG_INVALID_TRAP_IP_ADDRESS_RANGE_IN_2ND_DIGIT_IT_SHOULD_BE_0_255); %>");
	document.snmpTable.snmpTrapIpAddr.value = document.snmpTable.snmpTrapIpAddr.defaultValue;
	document.snmpTable.snmpTrapIpAddr.focus();
	return false;
  }
  if ( !checkDigitRange(document.snmpTable.snmpTrapIpAddr.value,3,0,255) ) {
      	alert("<% multilang(LANG_INVALID_TRAP_IP_ADDRESS_RANGE_IN_3RD_DIGIT_IT_SHOULD_BE_0_255); %>");
	document.snmpTable.snmpTrapIpAddr.value = document.snmpTable.snmpTrapIpAddr.defaultValue;
	document.snmpTable.snmpTrapIpAddr.focus();
	return false;
  }
  if ( !checkDigitRange(document.snmpTable.snmpTrapIpAddr.value,4,1,254) ) {
      	alert("<% multilang(LANG_INVALID_TRAP_IP_ADDRESS_RANGE_IN_4TH_DIGIT_IT_SHOULD_BE_1_254); %>");
	document.snmpTable.snmpTrapIpAddr.value = document.snmpTable.snmpTrapIpAddr.defaultValue;
	document.snmpTable.snmpTrapIpAddr.focus();
	return false;
  }
  */
  if ( validateKey( document.snmpTable.snmpSysObjectID.value ) == 0 ) {
	alert("<% multilang(LANG_INVALID_OBJECT_ID_VALUE_IT_SHOULD_BE_THE_DECIMAL_NUMBER_0_9); %>");
	document.snmpTable.snmpSysObjectID.value = document.snmpTable.snmpSysObjectID.defaultValue;
	document.snmpTable.snmpSysObjectID.focus();
	return false;
  }
  
  // count the numbers of '.' on OID
  var i=0;
  var str=document.snmpTable.snmpSysObjectID.value;
  while (str.length!=0) {
	if ( str.charAt(0) == '.' ) {
		i++;
	}	
	str = str.substring(1);
  }
  
  //document.write(i);
  if ( i!=6 ) {
  	alert("<% multilang(LANG_INVALID_OBJECT_ID_VALUE_IT_SHOULD_BE_FILL_WITH_OID_STRING_AS_1_3_6_1_4_1_X); %>");
  	document.snmpTable.snmpSysObjectID.value = document.snmpTable.snmpSysObjectID.defaultValue;
	document.snmpTable.snmpSysObjectID.focus();
  	return false;
  }  
  
  // Check if the OID's prefix is "1.3.6.1.4.1"
  var str2 = document.snmpTable.snmpSysObjectID.value.substring(0, 11);
  //document.write(str2);	
  if( str2!="1.3.6.1.4.1" ) {
  	alert("<% multilang(LANG_INVALID_OBJECT_ID_VALUE_IT_SHOULD_BE_FILL_WITH_PREFIX_OID_STRING_AS_1_3_6_1_4_1); %>");
  	document.snmpTable.snmpSysObjectID.value = document.snmpTable.snmpSysObjectID.defaultValue;
	document.snmpTable.snmpSysObjectID.focus();
	return false;
  }
  
  
  if (checkString(document.snmpTable.snmpSysDescr.value) == 0) {
	alert("<% multilang(LANG_INVALID_SYSTEM_DESCRIPTION); %>");
	document.snmpTable.snmpSysDescr.focus();
	return false;
  }
  if (checkString(document.snmpTable.snmpSysContact.value) == 0) {
	alert("<% multilang(LANG_INVALID_SYSTEM_CONTACT); %>");
	document.snmpTable.snmpSysContact.focus();
	return false;
  }
  if (checkString(document.snmpTable.snmpSysName.value) == 0) {
	alert("<% multilang(LANG_INVALID_SYSTEM_NAME); %>");
	document.snmpTable.snmpSysName.focus();
	return false;
  }
  if (checkString(document.snmpTable.snmpSysLocation.value) == 0) {
	alert("<% multilang(LANG_INVALID_SYSTEM_LOCATION_); %>");
	document.snmpTable.snmpSysLocation.focus();
	return false;
  }
  if (checkString(document.snmpTable.snmpCommunityRO.value) == 0) {
	alert("<% multilang(LANG_INVALID_COMMUNITY_NAME_READ_ONLY); %>");
	document.snmpTable.snmpCommunityRO.focus();
	return false;
  }
  if (checkString(document.snmpTable.snmpCommunityRW.value) == 0) {
	alert("<% multilang(LANG_INVALID_COMMUNITY_NAME_WRITE_ONLY); %>");
	document.snmpTable.snmpCommunityRW.focus();
	return false;
  }

 obj.isclick = 1;
 postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	
 return true;
}

</SCRIPT>

</head>

<body>
<div class="intro_main ">
	<p class="intro_title">SNMP <% multilang(LANG_CONFIGURATION); %></p>
	<p class="intro_content"><% multilang(LANG_THIS_PAGE_IS_USED_TO_CONFIGURE_THE_SNMP_HERE_YOU_MAY_CHANGE_THE_SETTINGS_FOR_SYSTEM_DESCRIPTION_TRAP_IP_ADDRESS_COMMUNITY_NAME_ETC); %></p>
</div>

<form action=/boaform/formSnmpConfig method=POST name="snmpTable">
<div class="data_common data_common_notitle">
	<table>
		<tr>
		  <th width="40%">SNMP:</th>
		  <td width="60%">
		  	<input type="radio" value="0" name="snmp_enable" <% checkWrite("snmpd-on"); %> ><% multilang(LANG_DISABLE); %>&nbsp;&nbsp;
		 	<input type="radio" value="1" name="snmp_enable" <% checkWrite("snmpd-off"); %> ><% multilang(LANG_ENABLE); %>&nbsp;&nbsp;
		  </td>     
		</tr>
		<tr>
		  <th width="40%"><% multilang(LANG_SYSTEM_DESCRIPTION); %>:</th>
		  <td width="60%"><input type="text" name="snmpSysDescr" size="50" maxlength="64" value="<% getInfo("snmpSysDescr"); %>"></td>
		</tr>
		<tr>
		  <th width="40%"><% multilang(LANG_SYSTEM_CONTACT); %>:</th>
		  <td width="60%"><input type="text" name="snmpSysContact" size="50" maxlength="64" value="<% getInfo("snmpSysContact"); %>"></td>
		</tr>
		<tr>
		  <th width="40%"><% multilang(LANG_SYSTEM); %><% multilang(LANG_NAME); %>:</th>
		  <td width="60%"><input type="text" name="snmpSysName" size="50" maxlength="64" value="<% getInfo("snmpSysName"); %>"></td>
		</tr>
		<tr>
		  <th width="40%"><% multilang(LANG_SYSTEM_LOCATION); %>:</th>
		  <td width="60%"><input type="text" name="snmpSysLocation" size="50" maxlength="64" value="<% getInfo("snmpSysLocation"); %>"></td>
		</tr>
		<tr>
		  <th width="40%"><% multilang(LANG_SYSTEM_OBJECT_ID); %>:</th>
		  <td width="60%"><input type="text" name="snmpSysObjectID" size="50" maxlength="64" value="<% getInfo("snmpSysObjectID"); %>"></td>
		</tr>
		<tr>
		  <th width="40%"><% multilang(LANG_TRAP_IP_ADDRESS); %>:</th>
		  <td width="60%"><input type="text" name="snmpTrapIpAddr" size="15" maxlength="15" value=<% getInfo("snmpTrapIpAddr"); %>></td>
		</tr>
		<tr>
		  <th width="40%"><% multilang(LANG_COMMUNITY_NAME_READ_ONLY); %>:</th>
		  <td width="60%"><input type="text" name="snmpCommunityRO" size="50" maxlength="64" value="<% getInfo("snmpCommunityRO"); %>"></td>
		</tr>
		<tr>
		  <th width="40%"><% multilang(LANG_COMMUNITY_NAME_WRITE_ONLY); %>:</th>
		  <td width="60%"><input type="text" name="snmpCommunityRW" size="50" maxlength="64" value="<% getInfo("snmpCommunityRW"); %>"></td>
		</tr>
	</table>
</div>
<div class="btn_ctl">
      <input class="link_bg" type="submit" value="<% multilang(LANG_APPLY_CHANGES); %>" name="save" onClick="return saveChanges(this)">&nbsp;&nbsp;
      <input class="link_bg" type="reset" value="<% multilang(LANG_RESET); %>" name="reset">
      <input type="hidden" value="/snmp.asp" name="submit-url">
      <input type="hidden" name="postSecurityFlag" value="">
</div>
 </form>
</body>

</html>
