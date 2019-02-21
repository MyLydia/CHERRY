<html>
<! Copyright (c) Realtek Semiconductor Corp., 2003. All Rights Reserved. ->
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<title>IPIP VPN <% multilang(LANG_CONFIGURATION); %></title>
<link rel="stylesheet" type="text/css" href="common_style.css"/>
<script type="text/javascript" src="share.js">
</script>
<SCRIPT language="javascript" src="/common.js"></SCRIPT>
<SCRIPT>
function checkTextStr(str)
{
	for (var i=0; i<str.length; i++) 
	{
		if ( str.charAt(i) == '%' || str.charAt(i) =='&' ||str.charAt(i) =='\\' || str.charAt(i) =='?' || str.charAt(i)=='"') 
			return false;			
	}
	return true;
}

function ipipSelection()
{
	if (document.ipip.ipipen[0].checked) {		
		document.ipip.remote.disabled = true;
		document.ipip.local.disabled = true;
		document.ipip.defaultgw.disabled = true;
		document.ipip.addIPIP.disabled = true;
	}
	else {		
		document.ipip.remote.disabled = false;
		document.ipip.local.disabled = false;
		document.ipip.defaultgw.disabled = false;
		document.ipip.addIPIP.disabled = false;
	}
}

function onClickIPIPEnable()
{
	ipipSelection();
	
	if (document.ipip.ipipen[0].checked)
		document.ipip.lst.value = "disable";
	else
		document.ipip.lst.value = "enable";
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	document.ipip.submit();
}

function addIPIPItf(obj)
{
	if (document.ipip.ipipen[0].checked)
		return false;
	/*
	if (document.ipip.tun_name.value=="") {
		alert("Please enter tunnel name!");
		document.ipip.tun_name.focus();
		return false;
	}

	// tunnel name can not begin with "p". which is for ppp connection.
	if (!checkTextStr(document.ipip.tun_name.value) || (document.ipip.tun_name.value.charAt(0) == 'p'))
	{
		alert("Invalid value in tunnel name!");
		document.ipip.tun_name.focus();
		return false;

	}
	*/
	
	if (!checkHostIP(document.ipip.remote, 1))
	{		
		alert('<% multilang(LANG_INVALID_VALUE_IN_REMOTE_ADDRESS); %>');
		document.ipip.remote.focus();
		return false;
	}

	if (!checkHostIP(document.ipip.local, 1))
	{		
		alert('<% multilang(LANG_INVALID_VALUE_IN_LOCAL_ADDRESS); %>');
		document.ipip.local.focus();
		return false;
	}
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
<h2 class="page_title">IPIP VPN <% multilang(LANG_CONFIGURATION); %></h2>

<form action=/boaform/formIPIP method=POST name="ipip">
<table>
  <tr><font size=2>
    <% multilang(LANG_THIS_PAGE_IS_USED_TO_CONFIGURE_THE_PARAMETERS_FOR_IPIP_MODE_VPN); %>
  </tr>
  <tr><hr size=1 noshade align=top></tr>

  <tr>
      <th>IPIP VPN:
      	<input type="radio" value="0" name="ipipen" <% checkWrite("ipipenable0"); %> onClick="onClickIPIPEnable()"><% multilang(LANG_DISABLE); %>&nbsp;&nbsp;
     	<input type="radio" value="1" name="ipipen" <% checkWrite("ipipenable1"); %> onClick="onClickIPIPEnable()"><% multilang(LANG_ENABLE); %>
 	</th>
  </tr>
</table>
<input type="hidden" id="lst" name="lst" value="">
<br>

<table>
  <tr>
    <th><% multilang(LANG_LOCAL); %> <% multilang(LANG_IP_ADDRESS); %>:</th>
    <td><input type="text" name="local" size="20" maxlength="30"></td>
  </tr>
  <tr>
    <th><% multilang(LANG_REMOTE); %> <% multilang(LANG_IP_ADDRESS); %>:</th>
    <td><input type="text" name="remote" size="20" maxlength="30"></td>
  </tr>
  <tr>
    <th><% multilang(LANG_DEFAULT_GATEWAY); %>:</th>
    <td><input type="checkbox" name="defaultgw"></td>
</table>

<table>
  </tr>
      <td><input type="submit" value="<% multilang(LANG_APPLY_CHANGES); %>" name="addIPIP" onClick="return addIPIPItf(this)">&nbsp;&nbsp;</td>
  </tr>
</table>
<br><br>

<table>
  <tr><font size=2><b>IPIP <% multilang(LANG_TABLE); %>:</b></font></tr>
  <tr>
    <td bgcolor="#808080"><% multilang(LANG_SELECT); %></td>
    <td bgcolor="#808080"><% multilang(LANG_NAME); %></td>
    <td bgcolor="#808080"><% multilang(LANG_LOCAL); %></td>
    <td bgcolor="#808080"><% multilang(LANG_REMOTE); %></td>
    <td bgcolor="#808080"><% multilang(LANG_DEFAULT_GATEWAY); %></td>
    <td bgcolor="#808080"><% multilang(LANG_ACTION); %></td>
  </tr>
	<% ipipList(); %>
</table>
<br>
<input type="submit" value="Delete Selected" name="delSel" onClick="return deleteClick(this)">&nbsp;&nbsp;
<input type="hidden" value="/ipip.asp" name="submit-url">
<input type="hidden" name="postSecurityFlag" value="">
<script>
	ipipSelection();
</script>
</form>
</blockquote>
</body>
</html>
