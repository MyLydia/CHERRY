<html>
<! Copyright (c) Realtek Semiconductor Corp., 2003. All Rights Reserved. ->
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<title><% getWanIfDisplay(); %> <% multilang(LANG_WAN); %></title>
<script type="text/javascript" src="share.js">
</script>
<script type="text/javascript" src="base64_code.js"></script>
<script language="javascript">

var initConnectMode;
var pppConnectStatus=0;


var curlink = null;

var cgi = new Object();
var links = new Array();

with(links){<% initPageWaneth(); %>}


function isAllStar(str)
{
  for (var i=0; i<str.length; i++) {
  	if ( str.charAt(i) != '*' ) {
	  return false;
	}
  }
  return true;
}
function disableUsernamePassword()
{
	//avoid sending username/password without encode
	disableTextField(document.ethwan.pppUserName);
	if(!isAllStar(document.ethwan.pppPassword.value))
		disableTextField(document.ethwan.pppPassword);
}

function applyCheck1()
{
	var tmplst = "";

	with ( document.forms[0] )
	{	
		curlink = links[lkname.value];

		if ( curlink.cmode == 2 ) {

			if (document.ethwan.pppUserName.value=="") {			
				alert('<% multilang(LANG_PPP_USER_NAME_CANNOT_BE_EMPTY); %>');
				document.ethwan.pppUserName.focus();
				return false;
			}
			if (includeSpace(document.ethwan.pppUserName.value)) {			
				alert('<% multilang(LANG_CANNOT_ACCEPT_SPACE_CHARACTER_IN_PPP_USER_NAME); %>');
				document.ethwan.pppUserName.focus();
				return false;
			}
			if (checkString(document.ethwan.pppUserName.value) == 0) {			
				alert('<% multilang(LANG_INVALID_PPP_USER_NAME); %>');
				document.ethwan.pppUserName.focus();
				return false;
			}
			document.ethwan.encodePppUserName.value=encode64(document.ethwan.pppUserName.value);
			
			if (document.ethwan.pppPassword.value=="") {			
				alert('<% multilang(LANG_PPP_PASSWORD_CANNOT_BE_EMPTY); %>');
				document.ethwan.pppPassword.focus();
				return false;
			}

			if(!isAllStar(document.ethwan.pppPassword.value)){
				if (includeSpace(document.ethwan.pppPassword.value)) {				
					alert('<% multilang(LANG_CANNOT_ACCEPT_SPACE_CHARACTER_IN_PPP_PASSWORD); %>');
					document.ethwan.pppPassword.focus();
					return false;
				}
				if (checkString(document.ethwan.pppPassword.value) == 0) {				
					alert('<% multilang(LANG_INVALID_PPP_PASSWORD); %>');
					document.ethwan.pppPassword.focus();
					return false;
				}
				document.ethwan.encodePppPassword.value=encode64(document.ethwan.pppPassword.value);
			}
		}

		document.ethwan.lst.value = curlink.name;

		//avoid sending username/password without encode
		disableUsernamePassword();
	}
	return true;
	
}

function setPPPConnected()
{
	pppConnectStatus = 1;
}

function enable_pppObj()
{
	enableTextField(document.ethwan.pppUserName);
	enableTextField(document.ethwan.pppPassword);
}

function pppSettingsEnable()
{
	document.getElementById('tbl_ppp').style.display='block';
	enable_pppObj();
}

function disable_pppObj()
{
	disableTextField(document.ethwan.pppUserName);
	disableTextField(document.ethwan.pppPassword);
}

function pppSettingsDisable()
{
	document.getElementById('tbl_ppp').style.display='none';
	disable_pppObj();
}


function on_linkchange(itlk)
{
	with ( document.forms[0] )
	{
		if (itlk.cmode == 0) {
			document.ethwan.naptEnabled.disabled = true;
			document.ethwan.igmpEnabled.disabled = true;
			document.ethwan.ripv2Enabled.disabled = true;
			document.ethwan.droute[0].disabled = true;
			document.ethwan.droute[1].disabled = true;
		}
		else{
			document.ethwan.naptEnabled.disabled = false;
			document.ethwan.igmpEnabled.disabled = false;
			document.ethwan.ripv2Enabled.disabled = false;
			document.ethwan.droute[0].disabled = false;
			document.ethwan.droute[1].disabled = false;		
		}
		
		if (itlk.cmode == 2)
		{
			pppSettingsEnable();
			pppUserName.value = decode64(itlk.pppUsername);
			pppPassword.value = itlk.pppPassword;
		}
		else 
		{
			pppSettingsDisable();
		}
		
		//checkbox
		if (itlk.napt == 1)
			naptEnabled.checked = true;
		else
			naptEnabled.checked = false;
		if (itlk.enableIGMP == 1)
			igmpEnabled.checked = true;
		else
			igmpEnabled.checked = false;
		if (itlk.enableRIPv2 == 1)
			ripv2Enabled.checked = true;
		else
			ripv2Enabled.checked = false;
			
		//radio
		if (itlk.dgw == 1)
			droute[1].checked = true;
		else
			droute[0].checked = true;
		//ctype
		ctype.value = itlk.applicationtype;
	}
}

function on_ctrlupdate()
{
	with ( document.forms[0] )
	{
		curlink = links[lkname.value];
		on_linkchange(curlink);
	}
}

function on_init()
{
	sji_docinit(document, cgi);

	with ( document.forms[0] )
	{
		for(var k in links)
		{
			var lk = links[k];
			lkname.options.add(new Option(lk.name, k));
		}
		if(links.length > 0) lkname.selectedIndex = 0;
		on_ctrlupdate();
	}
}

</script>

</head>
<BODY onLoad="on_init();">
<blockquote>
<h2><font color="#0000FF"><% getWanIfDisplay(); %> <% multilang(LANG_WAN_PPPOE); %></font></h2>
<form action=/boaform/admin/formWanEth_admin method=POST name="ethwan">
<table border="0" cellspacing="4" width="800">
  <tr><td><font size=2>
    <% multilang(LANG_PAGE_DESC_CONFIGURE_PARAMETERS); %><% getWanIfDisplay(); %><% multilang(LANG_WAN_PPPOE); %>
  </font></td></tr>
  <tr><td><hr size=1 noshade align=top></td></tr>
</table>

<table border=0 width="800" cellspacing=4 cellpadding=0>
	<tr>
		<td>
			<select name="lkname" onChange="on_ctrlupdate()" size="1">
		</td>
	</tr>
</table>
<% ShowPPPIPSettings_admin(); %>

<table border=0 width="400" cellspacing=4 cellpadding=0>
  <tr><td><font size="2">
    <b><% multilang(LANG_ENABLE_NAPT); %>: </b></td>
    <td><input type="checkbox" name="naptEnabled" size="2" maxlength="2" value="ON" onclick="naptClicked()">
  </font></td></tr>

  <tr><td><font size="2">
    <b><% multilang(LANG_DEFAULT_ROUTE); %>: </b></font></td>
  <td><input type="radio" value="0" name="droute"><% multilang(LANG_DISABLE); %>
    <input type="radio" value="1" name="droute" checked=""><% multilang(LANG_ENABLE); %>
  </td></tr>

  <tr><td><font size="2">
    <b><% multilang(LANG_ENABLE_IGMP_PROXY); %>: </b></td>
  <td><input type="checkbox" name="igmpEnabled" size="2" maxlength="2" value="ON"></font>
  </td></tr>

  <tr><td><font size="2">
    <b><% multilang(LANG_ENABLE_RIPV2); %>: </b></td>
  <td><input type="checkbox" name="ripv2Enabled" size="2" maxlength="2" value="ON"></font>
  </td></tr>

  <tr><td><font size="2">
    <b><% multilang(LANG_CONNECTION_TYPE); %>: </b></td>
  <td><select size="1" name="ctype">
        <option value="4">Other</option>
        <option value="1">TR069</option>
        <option value="2">INTERNET</option>
        <option value="3">INTERNET_TR069</option>
        <option value="8">VOICE</option>
        <option value="9">VOICE_TR069</option>
        <option value="10">VOICE_INTERNET</option>
        <option value="11">VOICE_INTERNET_TR069</option>
    </select>
  </font></td></tr>
</table>

<BR>
<input type="hidden" value="/admin/pppoe-wan.asp" name="submit-url">
<input type="hidden" id="lst" name="lst" value="">
<input type="hidden" id="encodePppUserName" name="encodePppUserName" value="">
<input type="hidden" id="encodePppPassword" name="encodePppPassword" value="">
<input type="submit" value="<% multilang(LANG_APPLY_CHANGES); %>" name="apply" onClick="return applyCheck1()">&nbsp; &nbsp; &nbsp; &nbsp;
<input type="hidden" name="itfGroup" value=0>
<BR>
</form>
</blockquote>
</body>
</html>
