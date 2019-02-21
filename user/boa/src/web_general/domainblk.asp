<%SendWebHeadStr(); %>
<title><% multilang(LANG_DOMAIN_BLOCKING); %><% multilang(LANG_CONFIGURATION); %></title>

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
<div class="intro_main ">
	<p class="intro_title"><% multilang(LANG_DOMAIN_BLOCKING); %> <% multilang(LANG_CONFIGURATION); %></p>
	<p class="intro_content"><% multilang(LANG_THIS_PAGE_IS_USED_TO_CONFIGURE_THE_BLOCKED_DOMAIN_HERE_YOU_CAN_ADD_DELETE_THE_BLOCKED_DOMAIN); %></p>
</div>
<form action=/boaform/formDOMAINBLK method=POST name="domainblk">
<div class="data_common data_common_notitle">
	<table>
		<tr>
			<th width="30%"><% multilang(LANG_DOMAIN_BLOCKING); %>:</th>
			<td width="30%">
				<input type="radio" value="0" name="domainblkcap" <% checkWrite("domainblk-cap0"); %>><% multilang(LANG_DISABLE); %>&nbsp;&nbsp;
				<input type="radio" value="1" name="domainblkcap" <% checkWrite("domainblk-cap1"); %>><% multilang(LANG_ENABLE); %>
			</td>
		<td width="40%"><input class="inner_btn" type="submit" value="<% multilang(LANG_APPLY_CHANGES); %>" name="apply" onClick="return on_submit(this)">&nbsp;&nbsp;</td>
		</tr>  
	</table>
</div>
<div class="data_common data_common_notitle">
	<table>
		<tr>
			<th width="30%"><% multilang(LANG_DOMAIN); %>:</th>
			<td width="30%">
			<input type="text" name="blkDomain" size="15" maxlength="50">
			</td>
			<td width="40%">
			<input class="inner_btn" type="submit" value="<% multilang(LANG_ADD); %>" name="addDomain" onClick="return addClick(this)">
			</td>
		</tr>
	</table>
</div>
<div class="column clearfix column_title">
	<div class="column_title_left"></div>
		<p><% multilang(LANG_DOMAIN_BLOCKING); %> <% multilang(LANG_CONFIGURATION); %></p>
	<div class="column_title_right"></div>
</div>
<div class="data_common data_vertical">
	<table>
	  <% showDOMAINBLKTable(); %>
	</table>
</div>
<div class="btn_ctl">
	<input class="link_bg" type="submit" value="<% multilang(LANG_DELETE_SELECTED); %>" name="delDomain" onClick="return deleteClick(this)">&nbsp;&nbsp;
	<input class="link_bg" type="submit" value="<% multilang(LANG_DELETE_ALL); %>" name="delAllDomain" onClick="return deleteAllClick(this)">&nbsp;&nbsp;&nbsp;
	<input type="hidden" value="/domainblk.asp" name="submit-url">
	<input type="hidden" name="postSecurityFlag" value="">
</div>
<script>
	<% checkWrite("domainNum"); %>
</script>
</form>
</body>
</html>
