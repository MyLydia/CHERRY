<%SendWebHeadStr(); %>
<title>IP QoS <% multilang(LANG_CLASSIFICATION); %></title>

<script>
function adminClick()
{
	var i, num;
	num = document.qos.elements.length;
	if (document.qos.qosen[0].checked) {
		for (i=2; i<num; i++) {
			document.qos[i].disabled = true;
		}
		document.qos.admin.disabled = false;
		document.qos[num-1].disabled = false;
	}
	else {
		for (i=2; i<num; i++) {
			document.qos[i].disabled = false;
		}
		if (document.qos.prot.value != 1 && document.qos.prot.value != 2) {
			document.qos.sport.disabled = true;
			document.qos.dport.disabled = true;
		}
		if (document.qos.dscpenable[0].checked) {
			document.qos.dscp.disabled = true;
			document.qos.ipprio.disabled = false;
			document.qos.tos.disabled = false;
		}
		else {
			document.qos.dscp.disabled = false;
			document.qos.ipprio.disabled = true;
			document.qos.tos.disabled = true;
		}
	}
}               
                
function addClick(obj)
{               
	if (document.qos.sip.value == "" && document.qos.smask.value == "" && document.qos.sport.value == ""
		&& document.qos.dip.value == "" && document.qos.dmask.value == "" && document.qos.dport.value == ""
		&& document.qos.prot.value == 0 && document.qos.phyport.value == 0) {		
		alert('<% multilang(LANG_TRAFFIC_CLASSIFICATION_RULES_CAN_T_BE_EMPTY); %>');
		document.qos.sip.focus();
		return false;
	}

	//var i;  
	        
	if ( document.qos.sip.value!="" ) {
		if (!checkHostIP(document.qos.sip, 0))
			return false;
		if ( document.qos.smask.value != "" ) {
			if (!checkNetmask(document.qos.smask, 0))
				return false;
		}
		/*if ( validateKey( document.qos.sip.value ) == 0 ) {
			alert("Invalid source IP address.");
			document.qos.sip.focus();
			return false;
		}
		for (i=1; i<=4; i++) {
			if ( !checkDigitRange(document.qos.sip.value,i,0,255) ) {
				alert('Invalid source IP address.');
				document.qos.sip.focus();
				return false;
			}
		}
		
		if ( document.qos.smask.value!="" ) {
			if ( validateKey( document.qos.smask.value ) == 0 ) {
				alert("Invalid source IP mask.");
				document.qos.smask.focus();
				return false;
			}
			for (i=1; i<=4; i++) {
				if ( !checkDigitRange(document.qos.smask.value,i,0,255) ) {
					alert('Invalid source IP mask.');
					document.qos.smask.focus();
					return false;
				}
			}
		}*/
	}
	
	if ( document.qos.dip.value!="" ) {
		if (!checkHostIP(document.qos.dip, 0))
			return false;
		if ( document.qos.dmask.value != "" ) {
			if (!checkNetmask(document.qos.dmask, 0))
				return false;
		}
		/*if ( validateKey( document.qos.dip.value ) == 0 ) {
			alert("Invalid destination IP address.");
			document.qos.dip.focus();
			return false;
		}
		for (i=1; i<=4; i++) {
			if ( !checkDigitRange(document.qos.dip.value,i,0,255) ) {
				alert('Invalid destinationIP address.');
				document.qos.dip.focus();
				return false;
			}
		}
		
		if ( document.qos.dmask.value!="" ) {
			if ( validateKey( document.qos.dmask.value ) == 0 ) {
				alert("Invalid destination IP mask.");
				document.qos.dmask.focus();
				return false;
			}
			for (i=1; i<=4; i++) {
				if ( !checkDigitRange(document.qos.dmask.value,i,0,255) ) {
					alert('Invalid destination IP mask.');
					document.qos.dmask.focus();
					return false;
				}
			}
		}*/
	}
	
	if ( document.qos.sport.value!="" ) {
		if ( validateKey( document.qos.sport.value ) == 0 ) {
			alert('<% multilang(LANG_INVALID_SOURCE_PORT); %>');
			document.qos.sport.focus();
			return false;
		}
		
		d1 = getDigit(document.qos.sport.value, 1);
		if (d1 > 65535 || d1 < 1) {
			alert('<% multilang(LANG_INVALID_SOURCE_PORT_NUMBER); %>');
			document.qos.sport.focus();
			return false;
		}
	}
	
	if ( document.qos.dport.value!="" ) {
		if ( validateKey( document.qos.dport.value ) == 0 ) {
			alert('<% multilang(LANG_INVALID_DESTINATION_PORT); %>');
			document.qos.dport.focus();
			return false;
		}
		
		d1 = getDigit(document.qos.dport.value, 1);
		if (d1 > 65535 || d1 < 1) {
			alert('<% multilang(LANG_INVALID_DESTINATION_PORT_NUMBER); %>');
			document.qos.dport.focus();
			return false;
		}
	}
	
	if( document.qos.queuekey.value ==-1) {		
		alert('<% multilang(LANG_PLEASE_SELECT_QUEUE); %>');
		document.qos.queuekey.focus();
		return false;
	}

	obj.isclick = 1;
	postTableEncrypt(document.qos.postSecurityFlag, document.qos);
	
	return true;
}

function dscpClick()
{
	if (document.qos.dscpenable[0].checked) {
		document.qos.dscp.disabled = true;
		document.qos.ipprio.disabled = false;
		document.qos.tos.disabled = false;
	}
	else {
		document.qos.dscp.disabled = false;
		document.qos.ipprio.disabled = true;
		document.qos.tos.disabled = true;
	}
}           

function deleteClick(obj)
{
	if ( !confirm('<% multilang(LANG_CONFIRM_DELETE_ONE_ENTRY); %>') ) {
		return false;
	}
	else{
		obj.isclick = 1;
		postTableEncrypt(document.qostbl.postSecurityFlag, document.qostbl);
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
		postTableEncrypt(document.qostbl.postSecurityFlag, document.qostbl);
		return true;
	}
}

function on_submit(obj)
{
	obj.isclick = 1;
	postTableEncrypt(document.qos.postSecurityFlag, document.qos);
	return true;
}

</script>
</head>

<body>
<div class="intro_main ">
	<p class="intro_title">IP QoS <% multilang(LANG_CLASSIFICATION); %></p>
	<p class="intro_content"> <% multilang(LANG_CONFIGURATION_OF_CLASSIFICATION_TABLE_FOR_IPQOS); %></p>
</div>

<form action=/boaform/formIPQoS method=POST name=qos>
<div class="data_common data_common_notitle">
	<table>
		<tr>
			<th>IP QoS:</th>
			<td><input type="radio" name=qosen value=0 onClick="return adminClick()"><% multilang(LANG_DISABLED); %>&nbsp;&nbsp;
				<input type="radio" name=qosen value=1 onClick="return adminClick()"><% multilang(LANG_ENABLED); %>
			</td>
		</tr>
		<tr>
			<% dft_qos(); %>
		</tr>
	</table>
</div>
<div class="btn_ctl">
	<input class="link_bg" type=submit value="<% multilang(LANG_APPLY_CHANGES); %>" name=admin onClick="return on_submit(this)">
</div>

<div class="column">
	<div class="column_title">
		<div class="column_title_left"></div>
			<p><% multilang(LANG_SPECIFY_TRAFFIC_CLASSIFICATION_RULES); %></p>
		<div class="column_title_right"></div>
	</div>
	<div class="data_common">
		<table>
			<tr>
				<th><% multilang(LANG_SOURCE); %> IP:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; 
					<input type=text name=sip size=20 maxlength=15></th>
				<th><% multilang(LANG_NETMASK); %>: 
					<input type=text name=smask size=20 maxlength=15></th>
				<th><% multilang(LANG_PORT); %>: 
					<input type=text name=sport size=6 maxlength=5></th>
			</tr>
			<tr>
				<th><% multilang(LANG_DESTINATION); %> IP: 
					<align=left><input type=text name=dip size=20 maxlength=15></th>
				<th><align=left><% multilang(LANG_NETMASK); %>: 
					<align=left><input type=text name=dmask size=20 maxlength=15></th>
				<th><align=left><% multilang(LANG_PORT); %>: 
					<align=left><input type=text name=dport size=6 maxlength=5></th>
			</tr>
			<tr>
				<th><% multilang(LANG_PROTOCOL); %>:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; 
					<select name=prot onClick="return adminClick()">
					<option value=0></option>
					<option value=1>TCP</option>
					<option value=2>UDP</option>
					<option value=3>ICMP</option>
				</select></th>
				<th><% multilang(LANG_PHYSICAL_PORT); %>:
					<select name=phyport>
					<option value=0></option>
					<% if_lan_list("all"); %>
				</select>
				</th>
			</tr>
			<% pr_egress(); %>
		</table>
	</div>
</div>

<div class="column">
	<div class="column_title">
		<div class="column_title_left"></div>
			<p><% multilang(LANG_CLASSIFICATION_RESULTS); %></p>
		<div class="column_title_right"></div>
	</div>
	<div class="data_common">
		<table>
			<tr>
				<th><% multilang(LANG_CLASSQUEUE); %>:
					<% pq_egress(); %>
				</th>
				<th>802.1p_Mark:
					<select name=m1p>
						<option value=0></option>
						<option value=1>0</option>
						<option value=2>1</option>
						<option value=3>2</option>
						<option value=4>3</option>
						<option value=5>4</option>
						<option value=6>5</option>
						<option value=7>6</option>
						<option value=8>7</option>
					</select>
				</th>
			</tr>
			<% mark_dscp(); %>
		</table>
	</div>
</div>

<div class="btn_ctl">
	<input class="link_bg" type="submit" value="<% multilang(LANG_ADD); %>" name=addqos onClick="return addClick(this)"></td>
	<input type="hidden" value="/ipqos.asp" name="submit-url">
	<input type="hidden" name="postSecurityFlag" value="">
</div>
</form>


<form action=/boaform/formIPQoS method=POST name=qostbl>
<div class="column">
	<div class="column_title">
		<div class="column_title_left"></div>
			<p>IP QoS <% multilang(LANG_RULES); %></p>
		<div class="column_title_right"></div>
	</div>
	<div class="data_common">
		<table>
			<% ipQosList(); %>
  		</table>
  	</div>
</div>
<div class="btn_ctl">  
  <input class="link_bg" type="submit" value="<% multilang(LANG_DELETE_SELECTED); %>" name=delSel onClick="return deleteClick(this)">&nbsp;&nbsp;
  <input class="link_bg" type="submit" value="<% multilang(LANG_DELETE_ALL); %>" name=delAll onClick="return deleteAllClick(this)">&nbsp;&nbsp;&nbsp;
  <input type="hidden" value="/ipqos.asp" name="submit-url">
  <input type="hidden" name="postSecurityFlag" value="">
</div>
</form>
<script>
	<% initPage("ipqos"); %>
	adminClick();
</script>
</body>
</html>
