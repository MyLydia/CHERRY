<%SendWebHeadStr(); %>
<title>IPv6 IP/Port <% multilang(LANG_FILTERING); %></title>

<script>
function skip () { this.blur(); }

function on_init()
{
	directionSelection();
	document.formFilterAdd.saType.selectedIndex = 0;
	saTypeSelect();
	document.formFilterAdd.daType.selectedIndex = 0;
	daTypeSelect();
}

function protocolSelection()
{
	if ( document.formFilterAdd.protocol.selectedIndex == 2 )
	{
		document.formFilterAdd.sfromPort.disabled = true;
		document.formFilterAdd.stoPort.disabled = true;
		document.formFilterAdd.dfromPort.disabled = true;
		document.formFilterAdd.dtoPort.disabled = true;
	}
	else 
	{
		document.formFilterAdd.sfromPort.disabled = false;
		document.formFilterAdd.stoPort.disabled = false;
		document.formFilterAdd.dfromPort.disabled = false;
		document.formFilterAdd.dtoPort.disabled = false;
	}
}

function directionSelection()
{
	if ( document.formFilterAdd.dir.selectedIndex == 0 )
	{
		//outgoing
		document.formFilterAdd.sIfId6Start.disabled = false;
		document.formFilterAdd.dIfId6Start.disabled = true;
		document.formFilterAdd.dIfId6Start.value = "";
	}
	else
	{
		//incoming
		document.formFilterAdd.sIfId6Start.disabled = true;
		document.formFilterAdd.sIfId6Start.value = "";
		document.formFilterAdd.dIfId6Start.disabled = false;

	}
}
function saTypeSelect()
{
	if(document.formFilterAdd.saType.selectedIndex == 0)
	{
		document.getElementById("sifid").style.display = "none";
		document.getElementById("sip6").style.display = "";
		document.getElementById("sip6prefix").style.display = "";
	}
	else if(document.formFilterAdd.saType.selectedIndex == 1)
	{
		document.getElementById("sifid").style.display = "";
		document.getElementById("sip6").style.display = "none";
		document.getElementById("sip6prefix").style.display = "none";
	}
}
function daTypeSelect()
{
	if(document.formFilterAdd.daType.selectedIndex == 0)
	{
		document.getElementById("difid").style.display = "none";
		document.getElementById("dip6").style.display = "";
		document.getElementById("dip6prefix").style.display = "";
	}
	else if(document.formFilterAdd.daType.selectedIndex == 1)
	{
		document.getElementById("difid").style.display = "";
		document.getElementById("dip6").style.display = "none";
		document.getElementById("dip6prefix").style.display = "none";
	}
}
function checkIpv6AddressPrefixEmpty(type)
{
	if(type&1)//check src
	{
		if (document.formFilterAdd.sip6Start.value == "")
			return true;
	}
	else if(type&2)//check dst
	{
		if (document.formFilterAdd.dip6Start.value == "")
			return true;
	}
}
function checkIpv6AddressPrefix(type)
{

	if(type&1)//check src
	{
		with ( document.forms[1] )	{
			if(sip6Start.value != ""){
				if (! isGlobalIpv6Address(sip6Start.value) ){			
					alert('<% multilang(LANG_INVALID_SOURCE_IPV6_START_ADDRESS); %>');
					document.formFilterAdd.sip6Start.focus();
					return false;
				}
				if ( sip6PrefixLen.value != "" ) {
					if ( validateKey( document.formFilterAdd.sip6PrefixLen.value ) == 0 ) {				
						alert('<% multilang(LANG_INVALID_SOURCE_IPV6_PREFIX_LENGTH_IT_MUST_BE_0_9); %>');
						document.formFilterAdd.sip6PrefixLen.focus();
						return false;
					}

					var prefixlen= getDigit(sip6PrefixLen.value, 1);
					if (prefixlen > 64 || prefixlen < 0) {				
						alert('<% multilang(LANG_INVALID_SOURCE_IPV6_PREFIX_LENGTH_IT_MUST_BE_0_64); %>');
						document.formFilterAdd.sip6PrefixLen.focus();
						return false;
					}
				}
			}
		}		
	}
	if(type&2)//check dst
	{	
		with ( document.forms[1] )	{
			if(dip6Start.value != ""){
				if (! isGlobalIpv6Address(dip6Start.value) ){			
					alert('<% multilang(LANG_INVALID_DESTINATION_IPV6_START_ADDRESS); %>');
					document.formFilterAdd.dip6Start.focus();
					return false;
				}
				if ( dip6PrefixLen.value != "" ) {
					if ( validateKey( document.formFilterAdd.dip6PrefixLen.value ) == 0 ) {				
						alert('<% multilang(LANG_INVALID_DESTINATION_IPV6_PREFIX_LENGTH_IT_MUST_BE_0_9); %>');
						document.formFilterAdd.dip6PrefixLen.focus();
						return false;
					}

					var prefixlen= getDigit(dip6PrefixLen.value, 1);
					if (prefixlen > 64 || prefixlen < 0) {				
						alert('<% multilang(LANG_INVALID_DESTINATION_IPV6_PREFIX_LENGTH_IT_MUST_BE_0_64); %>');
						document.formFilterAdd.dip6PrefixLen.focus();
						return false;
					}
				}
			}
		}			
	}
	return true;
}

function checkIpv6InterfaceIDEmpty(type)
{
	if (type&1)
	{
		if(document.formFilterAdd.sIfId6Start.value == "")
			return true;
	}
	if (type&2)
	{
		if(document.formFilterAdd.dIfId6Start.value == "")
			return true;
	}
}

function checkIpv6InterfaceID(type)
{
	var ifid_regex = /[0-9A-F]{1,4}:[0-9A-F]{1,4}:[0-9A-F]{1,4}:[0-9A-F]{1,4}/i;

	with ( document.forms[1] ) 
	{
		if(type&1)
		{
			if(sIfId6Start.value != "")
			{
				if (!sIfId6Start.value.match(ifid_regex) ){
					alert('<% multilang(LANG_INVALID_SOURCE_IPV6_INTERFACE_ID_START_ADDRESS); %>');
					document.formFilterAdd.sIfId6Start.focus();
					return false;
				}
			}
		}
		if(type&2)
		{
			if(dIfId6Start.value != "")
			{
				if (!dIfId6Start.value.match(ifid_regex) ){
					alert('<% multilang(LANG_INVALID_DESTINATION_IPV6_START_ADDRESS); %>');
					document.formFilterAdd.dIfId6Start.focus();
					return false;
				}
			}
		}

	}

	return true;
}

function checkIpv6PortEmpty(type)
{
	if ( (type&1) && (document.formFilterAdd.sfromPort.value =="" || document.formFilterAdd.stoPort.value == "")) 
		return true;

	if ( (type&2) && (document.formFilterAdd.dfromPort.value =="" || document.formFilterAdd.dtoPort.value == ""))
		return true;
}

function checkIpv6Port(type)
{
	if(type&1)
	{
		if ( document.formFilterAdd.sfromPort.value!="" ) 
		{
			if ( validateKey( document.formFilterAdd.sfromPort.value ) == 0 ) 
			{
				alert('<% multilang(LANG_INVALID_SOURCE_PORT); %>');
				document.formFilterAdd.sfromPort.focus();
				return false;
			}
			d1 = getDigit(document.formFilterAdd.sfromPort.value, 1);
			if (d1 > 65535 || d1 < 1) 
			{
				alert('<% multilang(LANG_INVALID_SOURCE_PORT_NUMBER); %>');
				document.formFilterAdd.sfromPort.focus();
				return false;
			}
		}
		if ( document.formFilterAdd.stoPort.value!="" ) 
		{
			if ( validateKey( document.formFilterAdd.stoPort.value ) == 0 ) 
			{
				alert('<% multilang(LANG_INVALID_SOURCE_PORT); %>');
				document.formFilterAdd.stoPort.focus();
				return false;
			}
			d1 = getDigit(document.formFilterAdd.stoPort.value, 1);
			if (d1 > 65535 || d1 < 1) 
			{
				alert('<% multilang(LANG_INVALID_SOURCE_PORT_NUMBER); %>');
				document.formFilterAdd.stoPort.focus();
				return false;
			}
		}
		
	}
	if(type&2)
	{
		if ( document.formFilterAdd.dfromPort.value!="" ) 
		{
		   if ( validateKey( document.formFilterAdd.dfromPort.value ) == 0 ) 
		   {
				alert('<% multilang(LANG_INVALID_DESTINATION_PORT); %>');
				document.formFilterAdd.dfromPort.focus();
				return false;
		   }
		   d1 = getDigit(document.formFilterAdd.dfromPort.value, 1);
		   if (d1 > 65535 || d1 < 1) 
		   {
				alert('<% multilang(LANG_INVALID_DESTINATION_PORT_NUMBER); %>');
				document.formFilterAdd.dfromPort.focus();
				return false;
		   }
		}
		if ( document.formFilterAdd.dtoPort.value!="" ) 
		{
			if ( validateKey( document.formFilterAdd.dtoPort.value ) == 0 ) 
			{
				 alert('<% multilang(LANG_INVALID_DESTINATION_PORT); %>');
				 document.formFilterAdd.dtoPort.focus();
				 return false;
			}
			d1 = getDigit(document.formFilterAdd.dtoPort.value, 1);
			if (d1 > 65535 || d1 < 1) 
			{
				 alert('<% multilang(LANG_INVALID_DESTINATION_PORT_NUMBER); %>');
				 document.formFilterAdd.dtoPort.focus();
				 return false;
			}
		}
	}
	return true;
}
function addClick(obj)
{
	var checkAddressType = 0;
	var checkIfidType = 0;
	var checkPortType = 3;
	var Src_Dst_All_Empty = 0;

	if(document.formFilterAdd.saType.selectedIndex == 0)
		checkAddressType += 1;
	if(document.formFilterAdd.daType.selectedIndex == 0)
		checkAddressType += 2;

	if(document.formFilterAdd.saType.selectedIndex == 1)
		checkIfidType += 1;
	if(document.formFilterAdd.daType.selectedIndex == 1)
		checkIfidType += 2;

	if(document.formFilterAdd.protocol.selectedIndex == 2)
		checkPortType = 0;//ICMPV6,don't check port
		
	if(checkAddressType != 0 && checkIfidType != 0)
	{
		if(checkIpv6AddressPrefixEmpty(checkAddressType)&& checkIpv6InterfaceIDEmpty(checkIfidType))			
			Src_Dst_All_Empty = 1;
	}
	else if(checkAddressType != 0)
	{
		if(checkIpv6AddressPrefixEmpty(1) && checkIpv6AddressPrefixEmpty(2))			
			Src_Dst_All_Empty = 1;		
	}
	else if(checkIfidType != 0)
	{
		if(checkIpv6InterfaceIDEmpty(1) && checkIpv6InterfaceIDEmpty(2))			
			Src_Dst_All_Empty = 1;		
	}	
	
	if(Src_Dst_All_Empty == 1)
	{
		if(checkPortType == 0)//ICMPV6
		{
			alert('<% multilang(LANG_INPUT_FILTER_RULE_IS_NOT_VALID); %>');
			return false;
		}
		else//TCP/UDP 
		{
			if(checkIpv6PortEmpty(1)&& checkIpv6PortEmpty(2))
			{
				alert('<% multilang(LANG_INPUT_FILTER_RULE_IS_NOT_VALID); %>');
				return false;
			}
		}	
	}
	
	if(checkAddressType != 0 && checkIpv6AddressPrefix(checkAddressType) == false)
		return false;
	if(checkIfidType != 0 && checkIpv6InterfaceID(checkIfidType) == false)
		return false;		
	if(checkPortType !=0 && checkIpv6Port(checkPortType) == false)
		return false;

	obj.isclick = 1;
	postTableEncrypt(document.formFilterAdd.postSecurityFlag, document.formFilterAdd);
	return true;
}

function disableDelButton()
{
  if (verifyBrowser() != "ns") {
	disableButton(document.formFilterDel.deleteSelFilterIpPort);
	disableButton(document.formFilterDel.deleteAllFilterIpPort);
  }
}

function on_submit(obj)
{
	obj.isclick = 1;
	postTableEncrypt(document.formFilterDefault.postSecurityFlag, document.formFilterDefault);
	return true;
}

function deleteClick(obj)
{
	if ( !confirm('<% multilang(LANG_CONFIRM_DELETE_ONE_ENTRY); %>') ) {
		return false;
	}
	else{
		obj.isclick = 1;
		postTableEncrypt(document.formFilterDel.postSecurityFlag, document.formFilterDel);
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
		postTableEncrypt(document.formFilterDel.postSecurityFlag, document.formFilterDel);
		return true;
	}
}
</script>
</head>

<body onLoad="on_init();">

<div class="intro_main ">
	<p class="intro_title">IPv6 IP/Port <% multilang(LANG_FILTERING); %></p>
	<p class="intro_content"> <% multilang(LANG_PAGE_DESC_DATA_PACKET_FILTER_TABLE); %></p>
</div>

<form action=/boaform/formFilterV6 method=POST name="formFilterDefault">
<div class="data_common data_common_notitle">
	<table>	
		<tr>
			<th width="30%"><% multilang(LANG_DEFAULT_ACTION); %>:&nbsp;&nbsp;</th>
			<td><input type="radio" name="outAct" value=0 <% checkWrite("v6_ipf_out_act0"); %>><% multilang(LANG_DENY); %>&nbsp;&nbsp;
	   			<input type="radio" name="outAct" value=1 <% checkWrite("v6_ipf_out_act1"); %>><% multilang(LANG_ALLOW); %>&nbsp;&nbsp;</td>
			<td><input class="inner_btn" type="submit" value="<% multilang(LANG_APPLY_CHANGES); %>" name="setDefaultAction" onClick="return on_submit(this)">&nbsp;&nbsp;
				<input type="hidden" value="/fw-ipportfilter-v6_IfId_rg.asp" name="submit-url">
				<input type="hidden" name="postSecurityFlag" value="">
			</td>
		</tr>
	</table>
</div>
</form>


<form action=/boaform/formFilterV6 method=POST name="formFilterAdd">
<div class="data_common data_common_notitle">
	<table>
		<tr>
			<th width="30%"><% multilang(LANG_DIRECTION); %>: </th>
			<td>
				<select name="dir" onChange="directionSelection()">
					<option select value=0><% multilang(LANG_OUTGOING); %></option>
					<option value=1><% multilang(LANG_INCOMING); %></option>
				</select>&nbsp;&nbsp;
			</td>
		</tr>
		<tr>
			<th><% multilang(LANG_PROTOCOL); %>: </th>
			<td>
				<select name="protocol" onChange="protocolSelection()">
				<option select value=1>TCP</option>
				<option value=2>UDP</option>
				<option value=3>ICMPV6</option>
				</select>&nbsp;&nbsp;
			</td>
		</tr>
		<tr>
			<th width="30%">
				<% multilang(LANG_RULE_ACTION); %>:
			</th>
			<td width="70%">
				<input type="radio" name="filterMode" value="Deny" checked>&nbsp;<% multilang(LANG_DENY); %>
				<input type="radio" name="filterMode" value="Allow">&nbsp;&nbsp;<% multilang(LANG_ALLOW); %>
			</td>
		</tr>
	</table>
</div>
<div class="data_common data_common_notitle">
<table>
   <tr>
		<th width="30%"><% multilang(LANG_SOURCE); %> :</th>
		<td>
			<select name="saType" onChange="saTypeSelect()">
			<option select value=1><% multilang(LANG_IP_ADDRESS); %>+<% multilang(LANG_PREFIX_LENGTH); %></option>
			<option value=2>PD+<% multilang(LANG_INTERFACE_ID); %></option>
			</select>
		</td>
   </tr>
   <tr id="sifid">
	  <th><% multilang(LANG_SOURCE); %> <% multilang(LANG_INTERFACE_ID); %>:</th> 
	  <td><input type="text" size="16" name="sIfId6Start" style="width:150px"> </td>
   </tr>
   <tr id="sip6">
	  <th><% multilang(LANG_SOURCE); %> <% multilang(LANG_IP_ADDRESS); %>:</th>
	  <td><input type="text" size="16" name="sip6Start" style="width:150px">
   </tr>
   <tr id="sip6prefix">
	  <th><% multilang(LANG_SOURCE); %> <% multilang(LANG_PREFIX_LENGTH); %>:</th>
	  <td><input type="text" size="16" name="sip6PrefixLen" style="width:150px"></td>
   </tr> 
   <tr>
		<th><% multilang(LANG_DESTINATION); %> :</th>
		<td>
			<select name="daType" onChange="daTypeSelect()">
			<option select value=1><% multilang(LANG_IP_ADDRESS); %>+<% multilang(LANG_PREFIX_LENGTH); %></option>
			<option value=2>PD+<% multilang(LANG_INTERFACE_ID); %></option>
			</select>
		</td>
   </tr>
   <tr id="difid">
	  <th><% multilang(LANG_DESTINATION); %> <% multilang(LANG_INTERFACE_ID); %>:</th>
	  <td><input type="text" size="16" name="dIfId6Start" style="width:150px"> </td>
   </tr>
   <tr id="dip6">
	  <th><% multilang(LANG_DESTINATION); %> <% multilang(LANG_IP_ADDRESS); %>:</th>
	  <td><input type="text" size="16" name="dip6Start" style="width:150px">
   </tr>
   <tr id="dip6prefix">
	  <th><% multilang(LANG_DESTINATION); %> <% multilang(LANG_PREFIX_LENGTH); %>:</th>
	  <td><input type="text" size="16" name="dip6PrefixLen" style="width:150px"></td>
   </tr>
   <tr>
	  <th><% multilang(LANG_SOURCE); %> <% multilang(LANG_PORT); %>:</th>
	  <td><input type="text" size="6" name="sfromPort" style="width:150px"> - <input type="text" size="6" name="stoPort" style="width:150px"></td>
   </tr>
   <tr>
	  <th><% multilang(LANG_DESTINATION); %> <% multilang(LANG_PORT); %>:</th>
	  <td><input type="text" size="6" name="dfromPort" style="width:150px"> - <input type="text" size="6" name="dtoPort" style="width:150px"></td>
   </tr>
</table>

</div>
<div class="btn_ctl">
	<input class="link_bg" type="submit" value="<% multilang(LANG_ADD); %>" name="addFilterIpPort" onClick="return addClick(this)">
	<input type="hidden" value="/fw-ipportfilter-v6_IfId_rg.asp" name="submit-url">
	<input type="hidden" name="postSecurityFlag" value="">
</div>
</form>

<form action=/boaform/formFilterV6 method=POST name="formFilterDel">
<div class="column">
	<div class="column_title">
		<div class="column_title_left"></div>
			<p><% multilang(LANG_CURRENT_FILTER_TABLE); %></p>
		<div class="column_title_right"></div>
	</div>
	<div class="data_common data_vertical">
		<table>
			<% ipPortFilterListV6(); %>
		</table>
	</div>
</div>
<div class="btn_ctl">
	<input class="link_bg" type="submit" value="<% multilang(LANG_DELETE_SELECTED); %>" name="deleteSelFilterIpPort" onClick="return deleteClick(this)">&nbsp;&nbsp;
	<input class="link_bg" type="submit" value="<% multilang(LANG_DELETE_ALL); %>" name="deleteAllFilterIpPort" onClick="return deleteAllClick(this)">&nbsp;&nbsp;&nbsp;
	<input type="hidden" value="/fw-ipportfilter-v6_IfId_rg.asp" name="submit-url">
	<input type="hidden" name="postSecurityFlag" value="">
</div>	
<script>
	<% checkWrite("ipFilterNumV6"); %>
</script>
</form>
</body>
</html>
