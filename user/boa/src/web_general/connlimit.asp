<%SendWebHeadStr(); %>
<title><% multilang(LANG_CONNECTION_LIMIT); %></title>
<script>
function skip () { this.blur(); }

function addClick()
{

  if (document.formConnLimitAdd.connLimitcap[0].checked)
  	return false;
 
 if (document.formConnLimitAdd.ip.value=="") {	
	alert('<% multilang(LANG_IP_ADDRESS_CANNOT_BE_EMPTY_IT_SHOULD_BE_FILLED_WITH_4_DIGIT_NUMBERS_AS_XXX_XXX_XXX_XXX); %>');
	document.formConnLimitAdd.ip.focus();
	return false;
  }
   	
   	num1 = parseInt(document.formConnLimitAdd.tcpconnlimit.value,10);
   	num4 = parseInt(document.formConnLimitAdd.udpconnlimit.value,10);
   	num2 = parseInt(document.formConnLimitAdd.connnum.value,10);
   	num3 = parseInt(document.formConnLimitAdd.protocol.value,10);
   	if ((num1!=0)&&( num3 == 0) && ( num2 > num1)){   		
		alert('<% multilang(LANG_MAX_LIMITATION_PORTS_SHOULD_BE_LOWER_THAN_GLOBAL_TCP_CONNECTION_LIMIT); %>');
   		document.formConnLimitAdd.connnum.focus();
   		return false;
   	}
   	else if ((num4 != 0)&&( num3 == 1)&&( num2 > num4)){   		
		alert('<% multilang(LANG_MAX_LIMITATION_PORTS_SHOULD_BE_LOWER_THAN_GLOBAL_UDP_CONNECTION_LIMIT); %>');
   		document.formConnLimitAdd.connnum.focus();
   		return false;
   	}


  if ( !checkDigitRange(document.formConnLimitAdd.ip.value,1,0,255) ) {      	
	alert('<% multilang(LANG_INVALID_IP_ADDRESS_RANGE_IN_1ST_DIGIT_IT_SHOULD_BE_0_255); %>');
	document.formConnLimitAdd.ip.focus();
	return false;
  }
  if ( !checkDigitRange(document.formConnLimitAdd.ip.value,2,0,255) ) {      	
	alert('<% multilang(LANG_INVALID_IP_ADDRESS_RANGE_IN_2ND_DIGIT_IT_SHOULD_BE_0_255); %>');
	document.formConnLimitAdd.ip.focus();
	return false;
  }
  if ( !checkDigitRange(document.formConnLimitAdd.ip.value,3,0,255) ) {      
	alert('<% multilang(LANG_INVALID_IP_ADDRESS_RANGE_IN_3RD_DIGIT_IT_SHOULD_BE_0_255); %>');
	document.formConnLimitAdd.ip.focus();
	return false;
  }
  if ( !checkDigitRange(document.formConnLimitAdd.ip.value,4,1,254) ) {      	
	alert('<% multilang(LANG_INVALID_IP_ADDRESS_RANGE_IN_4TH_DIGIT_IT_SHOULD_BE_1_254); %>');
	document.formConnLimitAdd.ip.focus();
	return false;
  }   
  document.formConnLimitAdd.addconnlimit.isclick = 1;
  postTableEncrypt(document.formConnLimitAdd.postSecurityFlag, document.formConnLimitAdd);
  return true;
}

function disableDelButton()
{

  if (verifyBrowser() != "ns") {
	disableButton(document.formConnLimitDel.deleteSelconnLimit);
	disableButton(document.formConnLimitDel.deleteAllconnLimit);
  }

}

function updateState()
{
	
//  if (document.formConnLimitAdd.enabled.checked) {
  if (document.formConnLimitAdd.connLimitcap[1].checked) {
 	enableTextField(document.formConnLimitAdd.ip);
	enableTextField(document.formConnLimitAdd.protocol);
	enableTextField(document.formConnLimitAdd.connnum);	
	//enableTextField(document.formConnLimitAdd.cnlm_enable);
  }
  else {
 	disableTextField(document.formConnLimitAdd.ip);
	disableTextField(document.formConnLimitAdd.protocol);
	disableTextField(document.formConnLimitAdd.connnum);
	//disableTextField(document.formConnLimitAdd.cnlm_enable);
  }

}

function applyClick()
{
	document.formConnLimitAdd.apply.isclick = 1;
	postTableEncrypt(document.formConnLimitAdd.postSecurityFlag, document.formConnLimitAdd);
	return true;
}

function deleteClick()
{
	if ( !confirm('<% multilang(LANG_CONFIRM_DELETE_ONE_ENTRY); %>') ) {
		return false;
	}
	else{
		document.formConnLimitDel.deleteSelconnLimit.isclick = 1;
		postTableEncrypt(document.formConnLimitDel.postSecurityFlag, document.formConnLimitDel);
		return true;
	}		
}
        
function deleteAllClick()
{
	if ( !confirm('Do you really want to delete the all entries?') ) {
		return false;
	}
	else{
		document.formConnLimitDel.deleteAllconnLimit.isclick = 1;
		postTableEncrypt(document.formConnLimitDel.postSecurityFlag, document.formConnLimitDel);
		return true;
	}		
}

function on_submit(obj)
{
	obj.isclick = 1;
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	return true;
}

</script>
</head>

<body>
<div class="intro_main ">
	<p class="intro_title"><% multilang(LANG_CONNECTION_LIMIT); %></p>
	<p class="intro_content"> <% multilang(LANG_ENTRIES_IN_THIS_TABLE_ALLOW_YOU_TO_LIMIT_THE_NUMBER_OF_TCP_UDP_PORTS_USED_BY_INTERNAL_USERS); %></p>
</div>

<form action=/boaform/formConnlimit method=POST name="formConnLimitAdd">
<div class="data_common data_common_notitle">
<table>
	<tr>
		<th><% multilang(LANG_CONNECTION_LIMIT); %>:</th>
		<td>
			<input type="radio" value="0" name="connLimitcap" <% checkWrite("connLimit-cap0"); %> onClick="updateState()"><% multilang(LANG_DISABLE); %>&nbsp;&nbsp;
			<input type="radio" value="1" name="connLimitcap" <% checkWrite("connLimit-cap1"); %> onClick="updateState()"><% multilang(LANG_ENABLE); %>&nbsp;&nbsp;
		</td>
	</tr>
	<tr>
		<th><% multilang(LANG_GLOBAL); %> TCP <% multilang(LANG_CONNECTION_LIMIT); %>:</th>
		<td>
			<input type="text" name="tcpconnlimit" size="4" maxlength="4" value=<% getInfo("connLimit-tcp"); %>> &nbsp;(<% multilang(LANG_0_FOR_NO_LIMIT); %>) &nbsp;
		</td>
	</tr>
	<tr>
		<th><% multilang(LANG_GLOBAL); %> UDP <% multilang(LANG_CONNECTION_LIMIT); %>:</th>
		<td>
			<input type="text" name="udpconnlimit" size="4" maxlength="4" value=<% getInfo("connLimit-udp"); %> > &nbsp;(<% multilang(LANG_0_FOR_NO_LIMIT); %>) &nbsp;
		</td>
	</tr>
</table>
</div>	
<div class="btn_ctl">
	<input class="link_bg" type="submit" value="<% multilang(LANG_APPLY_CHANGES); %>" name="apply" onClick="return on_submit(this)">&nbsp;&nbsp;
	<input type="hidden" value="/connlimit.asp" name="submit-url">
</div>

<div class="data_common data_common_notitle">
	<table>
		<tr>
			<th><% multilang(LANG_PROTOCOL); %>:</th>
			<td>
				<select name="protocol">
					<option select value=0>TCP</option>
					<option value=1>UDP</option>
				</select>&nbsp;			
			</td>
		</tr>
		<tr>
			<th><% multilang(LANG_LOCAL); %> <% multilang(LANG_IP_ADDRESS); %>:&nbsp;</th>
			<td><input type="text" name="ip" size="10" maxlength="15">&nbsp;&nbsp;&nbsp;</td>
		</tr>
		<tr>
			<th><% multilang(LANG_MAX_LIMITATION_PORTS); %>:</th>
			<td>
				<input type="text" name="connnum" size="3" maxlength="5">
			</td>
		</tr>
	</table>
</div>
<div class="btn_ctl">
	<input class="link_bg" type="submit" value="<% multilang(LANG_ADD); %>" name="addconnlimit" onClick="return addClick()">
	<input type="hidden" value="/fw-portfw.asp" name="submit-url">
</div>
	
<input type="hidden" name="postSecurityFlag" value="">
<script> updateState(); </script>
</form>

<form action=/boaform/formConnlimit method=POST name="formConnLimitDel">
<div class="column">
	<div class="column_title">
		<div class="column_title_left"></div>
		<p><% multilang(LANG_CURRENT_CONNECTION_LIMIT_TABLE); %></p>
		<div class="column_title_right"></div>
	</div>
	<div class="data_common">
		<table>
			<% connlmitList(); %>
		</table>
	</div>
</div>

<div class="btn_ctl">
	<input class="link_bg" type="submit" value="<% multilang(LANG_DELETE_SELECTED); %>" name="deleteSelconnLimit" onClick="return deleteClick()">&nbsp;&nbsp;
	<input class="link_bg" type="submit" value="<% multilang(LANG_DELETE_ALL); %>" name="deleteAllconnLimit" onClick="return deleteAllClick()">&nbsp;&nbsp;&nbsp;
	<input type="hidden" value="/connlimit.asp" name="submit-url">
	<input type="hidden" name="postSecurityFlag" value="">
</div>
	<script>
	<% checkWrite("connLimitNum"); %>
	</script>
</form>
</body>
</html>
