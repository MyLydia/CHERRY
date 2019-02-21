<%SendWebHeadStr(); %>
<title><% multilang(LANG_ADD_IP_QOS_TRAFFIC_SHAPING_RULE); %></title>
<script language="javascript" type="text/javascript">
//var waniflst = new it_nr("waniflst");
//<% ifWanList_tc(); %>

function on_init_page() {
	//with(document.forms[0]) {
	//for(var i in waniflst){
	//	if(i == "name"||i=="undefined" ||(typeof waniflst[i] != "string" && typeof waniflst[i] != "number")) continue;
	//	inflist.options.add(new Option(waniflst[i],i));
	//}
	//}
	
	if ( <% checkWrite("IPv6Show"); %> )
	{
		if (document.getElementById)  // DOM3 = IE5, NS6
		{
			document.getElementById('ipprotbl').style.display = 'block';						
		}
		else {
			if (document.layers == false) // IE4
			{
				document.all.ipprotbl.style.display = 'block';						
			}
		}
	}
	
	if ( <% checkWrite("TrafficShapingByVid"); %> )
	{
		if (document.getElementById)  // DOM3 = IE5, NS6
		{
			document.getElementById('vidDiv').style.display = 'block';						
		}
		else {
			if (document.layers == false) // IE4
			{
				document.all.vidDiv.style.display = 'block';						
			}
		}	
	}
	
	
	if ( <% checkWrite("TrafficShapingBySsid"); %> )
	{
		if (document.getElementById)  // DOM3 = IE5, NS6
		{
			document.getElementById('ssidDiv').style.display = 'block';						
		}
		else {
			if (document.layers == false) // IE4
			{
				document.all.ssidDiv.style.display = 'block';						
			}
		}	
	}
}

function on_apply() {
	with(document.forms[0]) {
		if (inflist.value == " ")
		{
			inflist.focus();
			alert("<% multilang(LANG_WAN_INTERFACE_NOT_ASSIGNED); %>");
			return;
		}
		if(srcip.value != "" && sji_checkip(srcip.value) == false)
		{
			srcip.focus();
			alert("<% multilang(LANG_SOURCE_IP_INVALID); %>");
			return;
		}
		
		if(dstip.value != "" && sji_checkip(dstip.value) == false)
		{
			dstip.focus();
			alert("<% multilang(LANG_DESTINATION_IP_INVALID); %>");
			return;
		}
		
		if(srcnetmask.value != "" && sji_checkip(srcnetmask.value) == false)
		{
			srcnetmask.focus();
			alert("<% multilang(LANG_SOURCE_IP_MASK_INVALID); %>");
			return;
		}
		
		if(dstnetmask.value != "" && sji_checkip(dstnetmask.value) == false)
		{
			dstnetmask.focus();
			alert("<% multilang(LANG_DESTINATION_IP_MASK_INVALID); %>");
			return;
		}
		if(sport.value <0 || sport.value > 65536)
		{
			sport.focus();
			alert("<% multilang(LANG_SOURCE_PORT_INVALID); %>");
			return;
		}
		if (sport.value > 0 && sport.value < 65535)
		{
			if (protolist.value!= 1 && protolist.value!= 2 && protolist.value!= 4) {
				sport.focus();
				alert("<% multilang(LANG_PLEASE_ASSIGN_TCP_UDP); %>");
				return;
			}
		}
		if(dport.value <0 || dport.value > 65536)
		{
			dport.focus();
			alert("<% multilang(LANG_DESTINATION_PORT_INVALID); %>");
			return;
		}
		if (dport.value > 0 && dport.value<65535)
		{
			if (protolist.value!= 1 && protolist.value!= 2 && protolist.value!= 4) {
				dport.focus();
				alert("<% multilang(LANG_PLEASE_ASSIGN_TCP_UDP); %>");
				return;
			}
		}
		if(rate.value<0)
		{
			rate.focus();
			alert("<% multilang(LANG_UPLINK_RATE_INVALID); %>");
			return;
		}		

		
		if ( <% checkWrite("IPv6Show"); %> ) {
			// For IPv6
			if(document.forms[0].IpProtocolType.value == 2) {
				if(sip6.value != ""){
					if (! isGlobalIpv6Address(sip6.value) ){
						alert("<% multilang(LANG_INVALID_SOURCE_IPV6_ADDRESS); %>");
						return;
					}
					if ( sip6PrefixLen.value != "" ) {
						var prefixlen= getDigit(sip6PrefixLen.value, 1);
						if (prefixlen > 128 || prefixlen <= 0) {
							alert("<% multilang(LANG_INVALID_SOURCE_IPV6_PREFIX_LENGTH); %>");
							return;
						}
					}
				}
				
				if(dip6.value != ""){
					if (! isGlobalIpv6Address(dip6.value) ){
						alert("<% multilang(LANG_INVALID_DESTINATION_IPV6_ADDRESS); %>");
						return;
					}
					if ( dip6PrefixLen.value != "" ) {
						var prefixlen= getDigit(dip6PrefixLen.value, 1);
						if (prefixlen > 128 || prefixlen <= 0) {
							alert("<% multilang(LANG_INVALID_DESTINATION_IPV6_PREFIX_LENGTH); %>");
							return;
						}
					}
				}
			}
		}
		
		lst.value ="dummy=dummy&";
		
		if ( <% checkWrite("TrafficShapingByVid"); %> )
		{
		
			if( vlanID.value<0 || vlanID.value > 4095){
				alert("<% multilang(LANG_INCORRECT_VLAN_ID_SHOULE_BE_1_4095); %>");
				return;	
			}
		
			lst.value += "vlanID="+vlanID.value+"&";
		}	
		
		if ( <% checkWrite("TrafficShapingBySsid"); %> )
		{
				lst.value += "ssid="+ssid.value+"&";
		}	
		
		// For IPv4 and IPv6
		if ( <% checkWrite("IPv6Show"); %> ) {
			// For IPv4
			if(document.forms[0].IpProtocolType.value == 1){				
				lst.value = lst.value +"inf="+inflist.value+"&proto="+protolist.value+"&IPversion="+IpProtocolType.value+"&srcip="+srcip.value+"&srcnetmask="+srcnetmask.value+
					"&dstip="+dstip.value+"&dstnetmask="+dstnetmask.value+"&sport="+sport.value+"&dport="+dport.value+"&rate="+rate.value+"&direction="+direction.value;
			}
			// For IPv6
			else if (document.forms[0].IpProtocolType.value == 2) {				
				lst.value = lst.value +"inf="+inflist.value+"&proto="+protolist.value+"&IPversion="+IpProtocolType.value+"&sip6="+sip6.value+"&sip6PrefixLen="+sip6PrefixLen.value+
					"&dip6="+dip6.value+"&dip6PrefixLen="+dip6PrefixLen.value+"&sport="+sport.value+"&dport="+dport.value+"&rate="+rate.value+"&direction="+direction.value;
			}
		}
		// For IPv4 only
		else
		{
				lst.value = lst.value +"inf="+inflist.value+"&proto="+protolist.value+"&srcip="+srcip.value+"&srcnetmask="+srcnetmask.value+
					"&dstip="+dstip.value+"&dstnetmask="+dstnetmask.value+"&sport="+sport.value+"&dport="+dport.value+"&rate="+rate.value+"&direction="+direction.value;
		}		
		
		postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
		
		submit();				
	}
}

function protocolChange()
{	
	// If protocol is IPv4 only.
	if(document.forms[0].IpProtocolType.value == 1){			
		if (document.getElementById)  // DOM3 = IE5, NS6
		{
			document.getElementById('ip4tbl').style.display = 'block';
			document.getElementById('ip6tbl').style.display = 'none';						
		}
		else {
			if (document.layers == false) // IE4
			{
				document.all.ip4tbl.style.display = 'block';
				document.all.ip6tbl.style.display = 'none';						
			}
		}			
	}
	// If protocol is IPv6 only.
	else if(document.forms[0].IpProtocolType.value == 2){			
		if (document.getElementById)  // DOM3 = IE5, NS6
		{
			document.getElementById('ip4tbl').style.display = 'none';
			document.getElementById('ip6tbl').style.display = 'block';						
		}
		else {
			if (document.layers == false) // IE4
			{
				document.all.ip4tbl.style.display = 'none';
				document.all.ip6tbl.style.display = 'block';						
			}
		}
	}	
}

</script>
</head>
<body onLoad="on_init_page();">
<div class="intro_main ">
	<p class="intro_title">Add IP QoS Traffic Shaping Rule</p>
	<p class="intro_content"> </p>
</div>

<form id="form" action="/boaform/admin/formQosTraffictlEdit" method="post">	
<div id='ipprotbl' style="display:none" class="data_common data_common_notitle">
	<table>								
		<tr><th width="30%">IP <% multilang(LANG_VERSION); %>:</th>
			<td width="70%"><select id="IpProtocolType" onChange="protocolChange()" name="IpProtocolType">						
				<option value="1" > IPv4</option>
				<option value="2" > IPv6</option>
				</select>
			</td>
		</tr>					
	</table>
</div>
	
<div id='qos_direction'  style="display:<% check_display("qos_direction"); %>" class="data_common data_common_notitle"> 
	<table>		
		<tr>
			<th width="30%"><% multilang(LANG_DIRECTION);%>:</th>
			<td width="70%">
	  			<select name="direction">
					<option value="0"><% multilang(LANG_UPSTREAM);%></option>
					<option value="1"><% multilang(LANG_DOWNSTREAM);%> </option>
	  			</select>
			</td>	
		</tr>		
	</table>	
</div>

<div id='vidDiv' style="display:none" class="data_common data_common_notitle">			
	<table>			
		<tr>
			 <th width="30%"><% multilang(LANG_VLAN); %> ID:</th>
			<td width="70%"><input type="text" name="vlanID" size="4" style="width:80px"> </td>
		</tr>				
	</table>
</div>
	
<div id='ssidDiv' style="display:none" class="data_common data_common_notitle">			
	<table>			
		<tr>
			 <th><% multilang(LANG_SSID); %> ID:</th>
			 <td><font size=2><select name="ssid"> <% ssid_list("ssid"); %> </select> </td>
		</tr>				
	</table>
</div>			

<div class="data_common data_common_notitle">
	<table>		
		<tr> 
			<th><div id='wan_interface'  style="display:<% check_display("wan_interface"); %>" ><% multilang(LANG_INTERFACE); %>:</div></th>
			<td><div id='wan_interface_value'  style="display:<% check_display("wan_interface"); %>" ><select id="inflist"><% if_wan_list("queueITF-without-Any"); %></select></div></td>
		</tr>
		<tr>
			<th width="30%"><% multilang(LANG_PROTOCOL); %>:</th>
			<td width="70%">
	  			<select name="protolist">
					<option value="0"><% multilang(LANG_NONE); %></option>							
					<option value="1">TCP </option>
					<option value="2">UDP </option>
					<option value="3">ICMP</option>
<!--							<option value="4">TCP/UDP</option> -->
      			</select>
			</td>
		</tr>
	</table>
</div>	

<div id='ip4tbl' style="display:block;" class="data_common data_common_notitle">
	<table>
		<tr>
			<th><% multilang(LANG_SOURCE); %> IP:</th>
			<td><input type="text" name="srcip" size="15" maxlength="15" style="width:150px"></td>
		</tr>
		<tr>
			<th><% multilang(LANG_SOURCE_MASK); %>:</th>
			<td><input type="text" name="srcnetmask" size="15" maxlength="15" style="width:150px"></td>
		</tr>
		<tr>
			<th><% multilang(LANG_DESTINATION); %> IP:</th>
			<td><input type="text" name="dstip" size="15" maxlength="15" style="width:150px"></td>
		</tr>
		<tr>
			<th><% multilang(LANG_DESTINATION_MASK); %>:</th>
			<td><input type="text" name="dstnetmask" size="15" maxlength="15" style="width:150px"></td>
		</tr>
	</table>
</div>
	
<div id='ip6tbl' style="display:none;" class="data_common data_common_notitle">
	<table>
		<tr>
			<th><% multilang(LANG_SOURCE); %> IP:</th>
			<td><input type="text" name="sip6" size="26" maxlength="39" style="width:150px"></td>
		</tr>
		<tr>
	  		<th><% multilang(LANG_SOURCE_PREFIX_LENGTH); %>:</th>
			<td><input type="text" name="sip6PrefixLen" size="15" maxlength="15" style="width:150px"></td>
		</tr>
		<tr>
			 <th><% multilang(LANG_DESTINATION); %> IP:</th>
			<td><input type="text" name="dip6" size="26" maxlength="39" style="width:150px"></td>
		</tr>
		<tr>
	  		<th><% multilang(LANG_DESTINATION_PREFIX_LENGTH); %>:</th>
			<td><input type="text" name="dip6PrefixLen" size="15" maxlength="15" style="width:150px"></td>
		</tr>
	</table>
</div>

<div class="data_common data_common_notitle">	
	<table>
		<tr>
			<th width="30%"><% multilang(LANG_SOURCE_PORT); %>:</th>
			<td width="70%"><input type="text" name="sport" size="6" style="width:80px"></td>
		</tr>
		<tr>
	  		<th><% multilang(LANG_DESTINATION_PORT); %>:</th>
			<td><input type="text" name="dport" size="6" style="width:80px"></td>
		</tr>
		
		<tr>
			 <th><% multilang(LANG_RATE_LIMIT); %>:</th>
			<td><input type="text" name="rate" size="6" style="width:80px"> kb/s</td>
		</tr>
	</table>
</div>
<div class="btn_ctl">
	<input class="link_bg" type="button" name="return" value="<% multilang(LANG_CLOSE); %>" onClick="location.href='/net_qos_traffictl.asp';">
	<input class="link_bg" type="button" name="apply" value="<% multilang(LANG_APPLY_CHANGES); %>" onClick="on_apply();">
	<input type="hidden" name="lst" id="lst" value="">
	<input type="hidden" name="submit-url" value="/net_qos_traffictl.asp">
	<input type="hidden" name="postSecurityFlag" value="">
</div>
</form>
</body>
</html>
