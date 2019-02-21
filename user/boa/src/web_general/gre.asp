<%SendWebHeadStr(); %>
<title>GRE Configuration</title>

<SCRIPT>

function postEntry(enable, name, ip1, ip2, csum, seq, key, keyValue, dscp, vlanID, uprate, downrate)
{	
	if (enable)
		document.gre.tunnelEn[0].checked = true;
	else
		document.gre.tunnelEn[1].checked = true;
	
	if (csum)
		document.gre.csumEn[0].checked = true;
	else
		document.gre.csumEn[1].checked = true;
	
	if (seq)
		document.gre.seqEn[0].checked = true;
	else
		document.gre.seqEn[1].checked = true;	
	
	if (key)
		document.gre.keyEn[0].checked = true;
	else
		document.gre.keyEn[1].checked = true;
	
	if (keyValue)
		document.gre.keyValue.value = keyValue;
	else
		document.gre.keyValue.value = "";
	
	if (dscp)
		document.gre.mdscp.value = dscp;
	else
		document.gre.mdscp.value = "";
		
	document.gre.grename.value = name;
	document.gre.greIP1.value = ip1;
	document.gre.greIP2.value = ip2;
	if (vlanID)
		document.gre.grevid.value = vlanID;
	else
		document.gre.grevid.value = "";
	if (uprate)
		document.gre.uprate.value = uprate;
	else
		document.gre.uprate.value = "";
	if (downrate)
		document.gre.downrate.value = downrate;
	else
		document.gre.downrate.value = "";
}

function saveChanges(obj)
{
	if (checkString(document.gre.grename.value) == 0) {
		alert('Invalid GRE Name.');
		document.gre.grename.focus();
		return false;
	}
    
	if (document.gre.greIP1.value=="") {
		alert("Endpoint is empty");
		document.gre.greIP1.focus();
		return false;
	}
	
  	if (includeSpace(document.gre.greIP1.value)) {
		alert("Can't accept space character in Endpoint.");
		document.gre.greIP1.focus();
		return false;
 	}
	if (checkString(document.gre.greIP1.value) == 0) {
		alert("Invalid value in Endpoint Address");
		document.gre.greIP1.focus();
		return false;
	}
	
	if (document.gre.greIP2.value=="") {
		alert("Backup Endpoint is empty");
		document.gre.greIP2.focus();
		return false;
	}
	
  	if (includeSpace(document.gre.greIP2.value)) {
		alert("Can't accept space character in Backup Endpoint.");
		document.gre.greIP2.focus();
		return false;
 	}
	if (checkString(document.gre.greIP2.value) == 0) {
		alert("Invalid value in Backup Endpoint Address");
		document.gre.greIP2.focus();
		return false;
	}
	
	if (checkDigit(document.gre.grevid.value) == 0) {
		alert('VLAN ID should be a number.');
		document.gre.grevid.focus();
		return false;
	}
    
	if (document.gre.grevid.value !="" ) {
		if ((document.gre.grevid.value<1 || document.gre.grevid.value>4094)) {  
			alert('VLAN ID must be 1~4094');
			document.gre.grevid.focus();
			return false;
		}
	}
	
	if (document.gre.uprate.value !="" ) {
		if (document.gre.uprate.value<1 ) {  
			alert('Up BandWidth must be > 1');
			document.gre.uprate.focus();
			return false;
		}
	}
	
	if (checkDigit(document.gre.uprate.value) == 0) {
		alert('Up BandWidth should be a number.');
		document.gre.uprate.focus();
		return false;
	}
	
	if (document.gre.downrate.value !="" ) {
		if (document.gre.downrate.value<1 ) {  
			alert('Down BandWidth must be > 1');
			document.gre.downrate.focus();
			return false;
		}
	}
	
	if (checkDigit(document.gre.downrate.value) == 0) {
		alert('Down BandWidth should be a number.');
		document.gre.downrate.focus();
		return false;
	}
	
	if (document.gre.keyValue.value !="" ) {
		if (document.gre.keyValue.value<0 ) {  
			alert('keyValue must be > 0');
			document.gre.keyValue.focus();
			return false;
		}
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

</SCRIPT>
</head>

<body>
<div class="intro_main ">
	<p class="intro_title">GRE Configuration</p>
	<p class="intro_content"> <% multilang(LANG_THIS_PAGE_IS_USED_TO_CONFIGURE_THE_PARAMETERS_FOR_GRE); %></p>
</div>

<form action=/boaform/formGRE method=POST name="gre">
<div class="data_common data_common_notitle">
	<table>
		<tr>
			<th width=30%>GRE:</td>
			<td>
				<input type="radio" name="greEn" value="1" <% checkWrite("gre-on-1"); %> ><% multilang(LANG_ENABLED); %>&nbsp;&nbsp;
				<input type="radio" name="greEn" value="0" <% checkWrite("gre-on-0"); %> ><% multilang(LANG_DISABLED); %>
			</td>
			<td><input class="inner_btn" type="submit" value=<% multilang(LANG_APPLY_CHANGES); %> name="greSet" onClick="return on_submit(this)"></td>
		</tr>	
	</table>
</div>

<div class="data_common data_common_notitle">
	<table>
		<tr>
			<th width=30%><% multilang(LANG_NAME); %>:</th>
			<td width=70%><input type="text" name="grename" size="32" maxlength="256"></td>
		</tr>
		<tr>
			<th width=30%><% multilang(LANG_ADMIN_STATUS); %>:</th>
			<td width=70%>
				<input type="radio" value="1" name="tunnelEn" ><% multilang(LANG_ENABLE); %>&nbsp;&nbsp;
				<input type="radio" value="0" name="tunnelEn" ><% multilang(LANG_DISABLE); %>
			</td>
		</tr>
		<tr>
			<th width=30%>Checksum:</th>
			<td width=70%>
				<input type="radio" value="1" name="csumEn" ><% multilang(LANG_ENABLE); %>&nbsp;&nbsp;
				<input type="radio" value="0" name="csumEn" ><% multilang(LANG_DISABLE); %>
			</td>
		</tr>
		<tr>
			<th width=30%>Sequencing:</th>
			<td width=70%>
				<input type="radio" value="1" name="seqEn" ><% multilang(LANG_ENABLE); %>&nbsp;&nbsp;
				<input type="radio" value="0" name="seqEn" ><% multilang(LANG_DISABLE); %>
			</td>
		</tr>	
		<tr>
			<th width=30%>Key:</th>
			<td width=70%>
				<input type="radio" value="1" name="keyEn" ><% multilang(LANG_ENABLE); %>&nbsp;&nbsp;
				<input type="radio" value="0" name="keyEn" ><% multilang(LANG_DISABLE); %>
			</td>
		</tr>
		<tr>
			<th width=30%>Key value:</th>
			<td width=70%><input type="text" name="keyValue" id="keyValue" size="6" maxlength="10"></td>
		</tr>
		<tr>
			<th width=30%>DSCP:</th>
			<td width=70%>
				<select name="mdscp" id="mdscp" size="1">
					<option value="0"></option>
					<option value="1">default(000000)</option>
					<option value="57">AF13(001110)</option>
					<option value="49">AF12(001100)</option>
					<option value="33">CS1(001000)</option>
					<option value="89">AF23(010110)</option>
					<option value="81">AF22(010100)</option>
					<option value="73">AF21(010010)</option>
					<option value="65">CS2(010000)</option>				
					<option value="121">AF33(011110)</option>
					<option value="113">AF32(011100)</option>
					<option value="105">AF31(011010)</option>
					<option value="97">CS3(011000)</option>
					<option value="153">AF43(100110)</option>
					<option value="145">AF42(100100)</option>
					<option value="137">AF41(100010)</option>
					<option value="129">CS4(100000)</option>
					<option value="185">EF(101110)</option>
					<option value="161">CS5(101000)</option>
					<option value="193">CS6(110000)</option>
					<option value="225">CS7(111000)</option>				
				</select>
			</td>
		</tr>
		<tr>
			<th width=30%>GRE Endpoint:</th>
			<td width=70%><input type="text" name="greIP1" size="15" maxlength="125"></td>
		</tr>
		<tr>
			<th>GRE Backup Endpoint:</th>
			<td width=70%><input type="text" name="greIP2" size="15" maxlength="125"></td>
		</tr>
		<tr>
			<th width=30%>802.1Q <% multilang(LANG_VLAN_ID); %> :</th>
			<td width=70%><input type="text" name="grevid" id="grevid" size="6" maxlength="4">(1-4094),empty means no VLAN tag</td>
		</tr>
		<tr>
			<th width=30%>Up Bandwidth:</th>
			<td width=70%><input type="text" name="uprate" id="uprate" size="6" maxlength="5">kbps,empty means no limitation</td>
		</tr>
		<tr>
			<th width=30%>Down Bandwidth:</th>
			<td width=70%><input type="text" name="downrate" id="downrate" size="6" maxlength="5">kbps,empty means no limitation</td>
		</tr>
	</table>
</div>
<div class="btn_ctl">
	<input class="link_bg" type="submit" value=<% multilang(LANG_ADD); %> name="add" onClick="return saveChanges(this)">
	<input class="link_bg" type="submit" value=<% multilang(LANG_MODIFY); %> name="modify"P onClick="return saveChanges(this)">
	<input class="link_bg" type="submit" value=<% multilang(LANG_REMOVE); %> name="delgre" onClick="return saveChanges(this)">
	<input type="hidden" value="/gre.asp" name="submit-url">	
</div>

<div class="column">
	<div class="column_title">
		<div class="column_title_left"></div>
			<p>GRE <% multilang(LANG__TABLE); %></p>
		<div class="column_title_right"></div>
	</div>
	<div class="data_common">
		<table>
			<% showGRETable(); %>
		</table>
	</div>
</div>
<input type="hidden" name="postSecurityFlag" value="">
<script>
</script>
</form>
</body>
</html>
