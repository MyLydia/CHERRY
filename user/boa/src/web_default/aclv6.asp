<html>
<! Copyright (c) Realtek Semiconductor Corp., 2003. All Rights Reserved. ->
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<title>IPv6 ACL <% multilang(LANG_CONFIGURATION); %></title>
<link rel="stylesheet" type="text/css" href="common_style.css" />
<script type="text/javascript" src="share.js">
</script>
<SCRIPT language="javascript" src="/common.js"></SCRIPT>
<SCRIPT>
function addClick(obj)
{
	if (document.acl.sip6Start.value == "" && document.acl.sip6PrefixLen.value == "") {
		alert("Source IP and PrefixLen can't be empty");
		document.acl.sip6Start.focus();
		return false;
	}
	
	with ( document.forms[0] )	{
	if(sip6Start.value != ""){
		if (! isGlobalIpv6Address(sip6Start.value) && interface.value == 1){
			alert("Invalid Source IPv6 Start address!");
			document.acl.sip6Start.focus();
			return false;
		}
		if ( sip6PrefixLen.value != "" ) {
			if ( validateKey( document.acl.sip6PrefixLen.value ) == 0 ) {
				alert("Invalid Source IPv6 prefix length! It must be 0-9!");
				document.acl.sip6PrefixLen.focus();
				return false;
			}
			
			var prefixlen= getDigit(sip6PrefixLen.value, 1);
			if (prefixlen > 128 || prefixlen < 0) {
				alert("Invalid Source IPv6 prefix length! It must be 0-128!");
				document.acl.sip6PrefixLen.focus();
				return false;
			}
		}
	}				
	}
	obj.isclick = 1;
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);

	return true;
}


	
function disableDelButton()
{
  if (verifyBrowser() != "ns") {
	disableButton(document.acl.delIP);	
  }
}

function intfchange(obj)
{
	with ( document.forms[0] ) 
	{
		if(obj.value == "0")
		{
			if (document.getElementById) {  // DOM3 = IE5, NS6
				document.getElementById('serviceLANID').style.display = 'block';
				document.getElementById('serviceLANID2').style.display = 'block';
				document.getElementById('serviceWANID').style.display = 'none';
			}
			else {
				if (document.layers == false) { // IE4
					document.all.serviceLANID.style.display = 'block';
					document.all.serviceLANID2.style.display = 'block';
					document.all.serviceWANID.style.display = 'none';
				}
			}
		}
		else
		{
			if (document.getElementById){ // DOM3 = IE5, NS6
				document.getElementById('serviceLANID').style.display = 'none';
				document.getElementById('serviceLANID2').style.display = 'none';
				document.getElementById('serviceWANID').style.display = 'block';
			}
			else {
				if (document.layers == false) { // IE4
					document.all.serviceLANID.style.display = 'none';
					document.all.serviceLANID2.style.display = 'none';
					document.all.serviceWANID.style.display = 'block';
				}
			}
		}
	}
}

function serviceChange ()
{	
	
		if (document.acl.l_any.checked)
		{
			if (document.getElementById) {  // DOM3 = IE5, NS6				
				document.getElementById('serviceLANID2').style.display = 'none';
			}
			else {
				if (document.layers == false) { // IE4					
					document.all.serviceLANID2.style.display = 'none';
				}
			}
		}
		else
		{
			if (document.getElementById){ // DOM3 = IE5, NS6				
				document.getElementById('serviceLANID2').style.display = 'block';
			}
			else {
				if (document.layers == false) { // IE4					
					document.all.serviceLANID2.style.display = 'block';
				}
			}
		}
	
}

function on_submit(obj)
{
	obj.isclick = 1;
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	return true;
}
function deleteClick(obj)
{
	if ( !confirm('<% multilang(LANG_CONFIRM_DELETE_ONE_ENTRY); %>') ) {
		return false;
	}
	else{
		obj.isclick = 1;
		postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
		return true;
	}
}
</SCRIPT>
</head>

<body>
<blockquote>
<h2><font color="#0000FF">IPv6 ACL <% multilang(LANG_CONFIGURATION); %></font></h2>

<form action=/boaform/admin/formV6ACL method=POST name="acl">
<table>
  <tr><td>
    <% multilang(LANG_THIS_PAGE_IS_USED_TO_CONFIGURE_THE_IPV6_ADDRESS_FOR_ACCESS_CONTROL_LIST_IF_ACL_IS_ENABLED_ONLY_THE_IP_ADDRESS_IN_THE_ACL_TABLE_CAN_ACCESS_CPE_HERE_YOU_CAN_ADD_DELETE_THE_IP_ADDRESS); %>
  </td></tr>
  <tr><td><hr size=1 noshade align=top></td></tr>
</table>
<table>
  <tr>
      <td><b>IPv6 ACL <% multilang(LANG_CAPABILITY); %>:</b></td>
      <td>
      	<input type="radio" value="0" name="aclcap" <% checkWrite("v6-acl-cap0"); %>><% multilang(LANG_DISABLE); %>&nbsp;&nbsp;
     	<input type="radio" value="1" name="aclcap" <% checkWrite("v6-acl-cap1"); %>><% multilang(LANG_ENABLE); %>
      </td>
      <td><input type="submit" value="<% multilang(LANG_APPLY_CHANGES); %>" name="apply" onClick="return on_submit(this)">&nbsp;&nbsp; </td>
  </tr> 
</table>
 
 
<table>
  <tr><td><hr size=1 noshade align=top></td></tr>
</table>
<table> 
  <br>
  <tr>
      <td><b><% multilang(LANG_ENABLE); %>:</b></td>
      <td><input type="checkbox" name="enable" value="1" checked></td>
  </tr>
  
  <tr>
      <td><b><% multilang(LANG_INTERFACE); %>:</b></td>
      <td>
      <select size="1" name="interface" onChange="intfchange(this)">     
      <option value="0"><% multilang(LANG_LAN); %></option>
      <option value="1"><% multilang(LANG_WAN); %></option>
      </select>
      </td>
  </tr>

   <tr>
	  <td><b><% multilang(LANG_SOURCE); %> <% multilang(LANG_TIP_ADDR); %>:</b></td>
	  <td><input type="text" size="16" name="sip6Start"></td>   
   </tr>
	
   <tr>
	  <td><b><% multilang(LANG_SOURCE); %> <% multilang(LANG_PREFIX_LENGTH); %>:</b></td>
	  <td><input type="text" size="16" name="sip6PrefixLen"></td>
   </tr>	
  
</table>

<br>

<% showLANV6ACLItem(); %>
<% showWANV6ACLItem(); %>

<table>
  <tr>
	<td><input type="submit" value="<% multilang(LANG_ADD); %>" name="addIP" onClick="return addClick(this)">&nbsp;&nbsp;</td>
  </tr>
</table>

  <!--input type="submit" value="Update" name="updateACL" onClick="return addClick()">&nbsp;&nbsp;
  </tr-->
  
<table>
  <tr><td><hr size=1 noshade align=top></td></tr>
  <tr><td><b>IPv6 ACL <% multilang(LANG_TABLE); %>:</b></td></tr>
</table>
<table>
  <% showV6ACLTable(); %>
</table>
  <br>
      <input type="submit" value="<% multilang(LANG_DELETE_SELECTED); %>" name="delIP" onClick="return deleteClick(this)">&nbsp;&nbsp;      
      <input type="hidden" value="/aclv6.asp" name="submit-url">
      <input type="hidden" name="postSecurityFlag" value="">
 <script>
 	<% checkWrite("v6aclNum"); %>
  </script>
</form>
</blockquote>
</body>

</html>
