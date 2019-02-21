<html>
<! Copyright (c) Realtek Semiconductor Corp., 2003. All Rights Reserved. ->
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<title><% multilang(LANG_NAT_IP_FORWARDING); %></title>
<link rel="stylesheet" type="text/css" href="common_style.css" />
<SCRIPT language="javascript" src="common.js"></SCRIPT>
<script type="text/javascript" src="share.js">
</script>
<script>
function addClick(obj)
{
  if (!document.formIPFwAdd.enabled.checked){
	obj.isclick = 1;
	postTableEncrypt(document.formIPFwAdd.postSecurityFlag, document.formIPFwAdd);
	return true;
  }
  if (document.formIPFwAdd.l_ip.value=="" && document.formIPFwAdd.r_ip.value=="" ){
	obj.isclick = 1;
	postTableEncrypt(document.formIPFwAdd.postSecurityFlag, document.formIPFwAdd);
	return true;
  	}
  if (document.formIPFwAdd.l_ip.value=="") {	
	alert('<% multilang(LANG_EMPTY_LOCAL_IP_ADDRESS); %>');
	document.formIPFwAdd.l_ip.focus();
	return false;
  }
  if ( validateKey( document.formIPFwAdd.l_ip.value ) == 0 ) {	
	alert('<% multilang(LANG_INVALID_LOCAL_IP_ADDRESS_VALUE_); %>');
	document.formIPFwAdd.l_ip.focus();
	return false;
  }
  if ( !checkDigitRange(document.formIPFwAdd.l_ip.value,1,0,255) ) {      
	alert('<% multilang(LANG_INVALID_LOCAL_IP_ADDRESS_RANGE_IN_1ST_DIGIT); %>');
	document.formIPFwAdd.l_ip.focus();
	return false;
  }
  if ( !checkDigitRange(document.formIPFwAdd.l_ip.value,2,0,255) ) {      	
	alert('<% multilang(LANG_INVALID_LOCAL_IP_ADDRESS_RANGE_IN_2ND_DIGIT); %>');
	document.formIPFwAdd.l_ip.focus();
	return false;
  }
  if ( !checkDigitRange(document.formIPFwAdd.l_ip.value,3,0,255) ) {      	
	alert('<% multilang(LANG_INVALID_LOCAL_IP_ADDRESS_RANGE_IN_3RD_DIGIT); %>');
	document.formIPFwAdd.l_ip.focus();
	return false;
  }
  if ( !checkDigitRange(document.formIPFwAdd.l_ip.value,4,1,254) ) {      	
	alert('<% multilang(LANG_INVALID_LOCAL_IP_ADDRESS_RANGE_IN_4TH_DIGIT); %>');
	document.formIPFwAdd.l_ip.focus();
	return false;
  }

  if (document.formIPFwAdd.r_ip.value=="") {	
	alert('<% multilang(LANG_EMPTY_EXTERNAL_IP_ADDRESS); %>');
	document.formIPFwAdd.r_ip.focus();
	return false;
  }
  if ( validateKey( document.formIPFwAdd.r_ip.value ) == 0 ) {	
	alert('<% multilang(LANG_INVALID_EXTERNAL_IP_ADDRESS_VALUE_); %>');
	document.formIPFwAdd.r_ip.focus();
	return false;
  }
  if ( !checkDigitRange(document.formIPFwAdd.r_ip.value,1,0,255) ) {      
	alert('<% multilang(LANG_INVALID_EXTERNAL_IP_ADDRESS_RANGE_IN_1ST_DIGIT); %>');
	document.formIPFwAdd.r_ip.focus();
	return false;
  }
  if ( !checkDigitRange(document.formIPFwAdd.r_ip.value,2,0,255) ) {      	
	alert('<% multilang(LANG_INVALID_EXTERNAL_IP_ADDRESS_RANGE_IN_2ND_DIGIT); %>');
	document.formIPFwAdd.r_ip.focus();
	return false;
  }
  if ( !checkDigitRange(document.formIPFwAdd.r_ip.value,3,0,255) ) {      	
	alert('<% multilang(LANG_INVALID_EXTERNAL_IP_ADDRESS_RANGE_IN_3RD_DIGIT); %>');
	document.formIPFwAdd.r_ip.focus();
	return false;
  }
  if ( !checkDigitRange(document.formIPFwAdd.r_ip.value,4,1,254) ) {      
	alert('<% multilang(LANG_INVALID_EXTERNAL_IP_ADDRESS_RANGE_IN_4TH_DIGIT); %>');
	document.formIPFwAdd.r_ip.focus();
	return false;
  }

   obj.isclick = 1;
   postTableEncrypt(document.formIPFwAdd.postSecurityFlag, document.formIPFwAdd);

   return true;
}

function disableDelButton()
{
  if (verifyBrowser() != "ns") {
	disableButton(document.formIPFwDel.delSelEntry);
	disableButton(document.formIPFwDel.delAllEntry);
  }
}

function updateState()
{
  if (document.formIPFwAdd.enabled.checked) {
 	enableTextField(document.formIPFwAdd.l_ip);
	enableTextField(document.formIPFwAdd.r_ip);
  }
  else {
 	disableTextField(document.formIPFwAdd.l_ip);
	disableTextField(document.formIPFwAdd.r_ip);
  }
}

function deleteClick(obj)
{
	if ( !confirm('<% multilang(LANG_CONFIRM_DELETE_ONE_ENTRY); %>') ) {
		return false;
	}
	else{
		obj.isclick = 1;
		postTableEncrypt(document.formIPFwDel.postSecurityFlag, document.formIPFwDel);
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
		postTableEncrypt(document.formIPFwDel.postSecurityFlag, document.formIPFwDel);
		return true;
	}
}
</script>
</head>

<body>
<blockquote>
<h2 class="page_title"><% multilang(LANG_NAT_IP_FORWARDING); %></h2>

<table>
<tr><td><font size=2>
 <% multilang(LANG_ENTRIES_IN_THIS_TABLE_ALLOW_YOU_TO_AUTOMATICALLY_REDIRECT_TRAFFIC_TO_A_SPECIFIC_MACHINE_BEHIND_THE_NAT_FIREWALL_THESE_SETTINGS_ARE_ONLY_NECESSARY_IF_YOU_WISH_TO_HOST_SOME_SORT_OF_SERVER_LIKE_A_WEB_SERVER_OR_MAIL_SERVER_ON_THE_PRIVATE_LOCAL_NETWORK_BEHIND_YOUR_GATEWAY_S_NAT_FIREWALL); %>
</font></td></tr>
<tr><td><hr size=1 noshade align=top></td></tr>
</table>

<table>

<form action=/boaform/formIPFw method=POST name="formIPFwAdd">

<tr><font size=2><b>
   	<input type="checkbox" name="enabled" value="ON" <% checkWrite("ipFwEn"); %>
   	 ONCLICK=updateState()>&nbsp;&nbsp;<% multilang(LANG_ENABLE); %> <% multilang(LANG_NAT_IP_FORWARDING); %><br>
    </b></font>
</tr>

<tr>
    <th><% multilang(LANG_LOCAL); %> <% multilang(LANG_IP_ADDRESS); %>: </th>
    <td><input type="text" name="l_ip" size="10" maxlength="15"></td>
</tr>
<tr>
    <th><% multilang(LANG_EXTERNAL); %> <% multilang(LANG_IP_ADDRESS); %>: </th>
    <td><input type="text" name="r_ip" size="10" maxlength="15"></td>
</tr>
<tr><td>
  <input type="submit" value="<% multilang(LANG_APPLY_CHANGES); %>" name="addEntry" onClick="return addClick(this)">&nbsp;&nbsp;
  <input type="hidden" value="/fw-ipfw.asp" name="submit-url">
  <input type="hidden" name="postSecurityFlag" value="">
</td></tr>
  <script> updateState(); </script>
</form>
</table>


<br>
<form action=/boaform/formIPFw method=POST name="formIPFwDel">
<table>
  <tr><font size=2><b><% multilang(LANG_CURRENT_NAT_IP_FORWARDING_TABLE); %>:</b></font></tr>
  <% ipFwList(); %>
</table>

 <br><input type="submit" value="<% multilang(LANG_DELETE_SELECTED); %>" name="delSelEntry" onClick="return deleteClick(this)">&nbsp;&nbsp;
     <input type="submit" value="<% multilang(LANG_DELETE_ALL); %>" name="delAllEntry" onClick="return deleteAllClick(this)">&nbsp;&nbsp;&nbsp;
     <input type="reset" value="<% multilang(LANG_RESET); %>" name="reset">
 <script>
   	<% checkWrite("ipFwNum"); %>
 </script>
     <input type="hidden" value="/fw-ipfw.asp" name="submit-url">
     <input type="hidden" name="postSecurityFlag" value="">
</form>

</td></tr></table>

</blockquote>
</body>
</html>

