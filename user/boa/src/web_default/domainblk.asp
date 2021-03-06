<html>
<! Copyright (c) Realtek Semiconductor Corp., 2003. All Rights Reserved. ->
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<title><% multilang(LANG_DOMAIN_BLOCKING); %><% multilang(LANG_CONFIGURATION); %></title>
<link rel="stylesheet" type="text/css" href="common_style.css" />
<script type="text/javascript" src="share.js">
</script>
<SCRIPT language="javascript" src="/common.js"></SCRIPT>
<SCRIPT>

function addClick(obj)
{
	if (document.domainblk.blkDomain.value=="") {		
		alert('<% multilang(LANG_PLEASE_ENTER_THE_BLOCKED_DOMAIN); %>');
		document.domainblk.blkDomain.focus();
		return false;
	}
	
	if ( document.domainblk.blkDomain.value.length == 0 ) {		
		if ( !confirm('<% multilang(LANG_DOMAIN_STRING_IS_EMPTY_NPLEASE_ENTER_THE_BLOCKED_DOMAIN); %>') ) {
			document.domainblk.blkDomain.focus();
			return false;
  		}
		else{
			obj.isclick = 1;
			postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
			return true;
		}
  	}
  	
  	if ( includeSpace(document.domainblk.blkDomain.value)) {		
		alert('<% multilang(LANG_CANNOT_ACCEPT_SPACE_CHARACTER_IN_BLOCKED_DOMAIN_PLEASE_TRY_IT_AGAIN); %>');
		document.domainblk.blkDomain.focus();
		return false;
 	}
	if (checkString(document.domainblk.blkDomain.value) == 0) {		
		alert('<% multilang(LANG_INVALID_BLOCKED_DOMAIN); %>');
		document.domainblk.blkDomain.focus();
		return false;
	}
  	obj.isclick = 1;
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	return true;
}

function on_submit(obj)
{
	obj.isclick = 1;
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	return true;
}
	
function disableDelButton()
{
  if (verifyBrowser() != "ns") {
	disableButton(document.domainblk.delDomain);
	disableButton(document.domainblk.delAllDomain);
  }
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
        
function deleteAllClick(obj)
{
	if ( !confirm('Do you really want to delete the all entries?') ) {
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
<h2 class="page_title"><% multilang(LANG_DOMAIN_BLOCKING); %><% multilang(LANG_CONFIGURATION); %></h2>

<form action=/boaform/formDOMAINBLK method=POST name="domainblk">
<table>
  <tr><td><font size=2>
    <% multilang(LANG_THIS_PAGE_IS_USED_TO_CONFIGURE_THE_BLOCKED_DOMAIN_HERE_YOU_CAN_ADD_DELETE_THE_BLOCKED_DOMAIN); %>
  </font></td></tr>
  <tr><td><hr size=1 noshade align=top></td></tr>
</table>
<table>
  
  <tr>
	<th><% multilang(LANG_DOMAIN_BLOCKING); %>:</th>
	<td><font size=2>
		<input type="radio" value="0" name="domainblkcap" <% checkWrite("domainblk-cap0"); %>><% multilang(LANG_DISABLE); %>&nbsp;&nbsp;
		<input type="radio" value="1" name="domainblkcap" <% checkWrite("domainblk-cap1"); %>><% multilang(LANG_ENABLE); %>
	</td>
	<td><input type="submit" value="<% multilang(LANG_APPLY_CHANGES); %>" name="apply" onClick="return on_submit(this)">&nbsp;&nbsp;</td>
  </tr>  
</table>

<table>
  <tr><td><hr size=1 noshade align=top></td></tr>
</table>

	<font size=2><b><% multilang(LANG_DOMAIN); %>:</b>
	<input type="text" name="blkDomain" size="15" maxlength="50">&nbsp;&nbsp;
	<input type="submit" value="<% multilang(LANG_ADD); %>" name="addDomain" onClick="return addClick(this)">
<br>
<br>
<table>
  <tr><font size=2><b><% multilang(LANG_DOMAIN_BLOCKING); %><% multilang(LANG_CONFIGURATION); %>:</b></font></tr>
  <% showDOMAINBLKTable(); %>
</table>
<br>
	<input type="submit" value="<% multilang(LANG_DELETE_SELECTED); %>" name="delDomain" onClick="return deleteClick(this)">&nbsp;&nbsp;
	<input type="submit" value="<% multilang(LANG_DELETE_ALL); %>" name="delAllDomain" onClick="return deleteAllClick(this)">&nbsp;&nbsp;&nbsp;
	<input type="hidden" value="/domainblk.asp" name="submit-url">
	<input type="hidden" name="postSecurityFlag" value="">
 <script>
 	<% checkWrite("domainNum"); %>
  </script>
</form>
</blockquote>
</body>

</html>
