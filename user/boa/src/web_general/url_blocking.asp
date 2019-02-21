<%SendWebHeadStr(); %>
<title>URL <% multilang(LANG_BLOCKING); %><% multilang(LANG_CONFIGURATION); %></title>

<SCRIPT>
function addClick()
{	
	return true;
}

function addFQDNClick(obj)
{	
	if (document.url.urlFQDN.value=="") {
		alert("<% multilang(LANG_PLEASE_ENTER_THE_BLOCKED_FQDN); %>");
		document.url.urlFQDN.focus();
		return false;
	}
	if (document.url.urlFQDN.value.length == 0 ) {
		if (!confirm('<% multilang(LANG_FQDN_IS_EMPTY_NPLEASE_ENTER_THE_BLOCKED_FQDN); %>') ) {
			document.url.urlFQDN.focus();
			return false;
  		}
		else{
			obj.isclick = 1;
			postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
			return true;
		}
  	}
  	if (includeSpace(document.url.urlFQDN.value)) {
		alert("<% multilang(LANG_CANNOT_ACCEPT_SPACE_CHARACTER_IN_BLOCKED_FQDN_PLEASE_TRY_IT_AGAIN); %>");
		document.url.urlFQDN.focus();
		return false;
 	}
	if (checkString(document.url.urlFQDN.value) == 0) {
		alert("<% multilang(LANG_INVALID_BLOCKED_FQDN); %>");
		document.url.urlFQDN.focus();
		return false;
	}
	obj.isclick = 1;
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	return true;
}

function addKeywordClick(obj)
{	
	if (document.url.Keywd.value=="") {
		alert("<% multilang(LANG_PLEASE_ENTER_THE_BLOCKED_KEYWORD); %>");
		document.url.Keywd.focus();
		return false;
	}
	if (document.url.Keywd.value.length == 0 ) {
		if (!confirm('<% multilang(LANG_KEYWORD_IS_EMPTY_NPLEASE_ENTER_THE_BLOCKED_KEYWORD); %>') ) {
			document.url.Keywd.focus();
			return false;
  		}
		else{
			obj.isclick = 1;
			postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
			return true;
		}
  	}
  	if (includeSpace(document.url.Keywd.value)) {
		alert("<% multilang(LANG_CANNOT_ACCEPT_SPACE_CHARACTER_IN_BLOCKED_KEYWORD_PLEASE_TRY_IT_AGAIN); %>");
		document.url.Keywd.focus();
		return false;
 	}
	if (checkString(document.url.Keywd.value) == 0) {
		alert("<% multilang(LANG_INVALID_BLOCKED_KEYWORD); %>");
		document.url.Keywd.focus();
		return false;
	}
	obj.isclick = 1;
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	return true;
}
	
function disableDelFQDNButton()
{
  if (verifyBrowser() != "ns") {
	disableButton(document.url.delFQDN);
	disableButton(document.url.delFAllQDN);
  }
}
	
function disableDelKeywdButton()
{
  if (verifyBrowser() != "ns") {
	disableButton(document.url.delKeywd);
	disableButton(document.url.delAllKeywd);
  }
}

function on_submit(obj)
{
	obj.isclick = 1;
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	return true;
}
</SCRIPT>
</head>

<body>
<div class="intro_main ">
	<p class="intro_title">URL <% multilang(LANG_BLOCKING); %></p>
	<p class="intro_content"> <% multilang(LANG_THIS_PAGE_IS_USED_TO_CONFIGURE_THE_BLOCKED_FQDN_SUCH_AS_TW_YAHOO_COM_AND_FILTERED_KEYWORD_HERE_YOU_CAN_ADD_DELETE_FQDN_AND_FILTERED_KEYWORD); %></p>
</div>

<form action=/boaform/formURL method=POST name="url">
<div class="data_common data_common_notitle">
	<table>
		<tr>
			<th width="30%">URL <% multilang(LANG_BLOCKING); %>:</th>
			<td width="30%">
				<input type="radio" value="0" name="urlcap" <% checkWrite("url-cap0"); %>><% multilang(LANG_DISABLE); %>&nbsp;&nbsp;
				<input type="radio" value="1" name="urlcap" <% checkWrite("url-cap1"); %>><% multilang(LANG_ENABLE); %>&nbsp;&nbsp;
			</td>
			<td width="40%">
				<input class="inner_btn" type="submit" value="<% multilang(LANG_APPLY_CHANGES); %>" name="apply" onClick="return on_submit(this)">&nbsp;&nbsp;
			</td>
		</tr>       
	</table>
</div>
<div class="data_common data_common_notitle">
	<table>
		<tr>	
			<th width="30%"><% multilang(LANG_FQDN); %>: <input type="text" name="urlFQDN" size="15" maxlength="125"></th>
			<td width="40%">
				<input class="inner_btn" type="submit" value="<% multilang(LANG_ADD); %>" name="addFQDN" onClick="return addFQDNClick(this)">
			</td>
		</tr>
	</table>
</div>
<div class="column clearfix column_title">
	<div class="column_title_left"></div>
		<p>URL <% multilang(LANG_BLOCKING); %> <% multilang(LANG_TABLE_2); %></p>
	<div class="column_title_right"></div>
</div>
<div class="data_common data_vertical">
	<table>
		<% showURLTable(); %>
	</table>
</div>
<div class="btn_ctl">
	<input class="link_bg" type="submit" value="<% multilang(LANG_DELETE_SELECTED); %>" name="delFQDN" onClick="return deleteClick(this)">&nbsp;&nbsp;
	<input class="link_bg" type="submit" value="<% multilang(LANG_DELETE_ALL); %>" name="delFAllQDN" onClick="return deleteAllClick(this)"></td>
</div>

<script>
	<% checkWrite("FQDNNum"); %>
</script>
<div class="data_common data_common_notitle">
	<table> 
		<tr>
			<th width="30%"><% multilang(LANG_KEYWORD); %>: <input type="text" name="Keywd" size="15" maxlength="18">&nbsp;&nbsp;</th>
			<td width="40%">
				<input class="inner_btn" type="submit" value="<% multilang(LANG_ADD); %>" name="addKeywd" onClick="return addKeywordClick(this)">
			</td>
		</tr>
	</table>
</div>
<div class="column clearfix column_title">
	<div class="column_title_left"></div>
		<p><% multilang(LANG_KEYWORD_FILTERING_TABLE); %></p>
	<div class="column_title_right"></div>
</div>
<div class="data_common data_vertical">
	<table>
		<% showKeywdTable(); %>
	</table>
</div>
<div class="btn_ctl">
<input class="link_bg" type="submit" value="<% multilang(LANG_DELETE_SELECTED); %>" name="delKeywd" onClick="return deleteClick(this)">&nbsp;&nbsp;
<input class="link_bg" type="submit" value="<% multilang(LANG_DELETE_ALL); %>" name="delAllKeywd" onClick="return deleteAllClick(this)">&nbsp;&nbsp;&nbsp;
<input type="hidden" value="/url_blocking.asp" name="submit-url">
<input type="hidden" name="postSecurityFlag" value="">
</div>
 <script>
 	<% checkWrite("keywdNum"); %>
  </script>
</form>
</body>
</html>
