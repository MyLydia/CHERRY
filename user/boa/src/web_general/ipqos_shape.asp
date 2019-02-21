<%SendWebHeadStr(); %>
<title>IP QoS <% multilang(LANG_TRAFFIC_SHAPING); %></title>

<META http-equiv=pragma content=no-cache>
<META http-equiv=cache-control content="no-cache, must-revalidate">
<META http-equiv=content-script-type content=text/javascript>

<script>

var protos = new Array("-", "ICMP", "TCP", "UDP", "TCP/UDP");
var traffictlRules = new Array();
var totalBandwidth;
var totalBandWidthEn;

function it_nr(id, inf, proto, sport, dport, srcip, dstip, uprate) {
  this.id = id;
  this.inf = inf;
  this.proto = proto;
  this.sport = sport;
  this.dport = dport;
  this.srcip = srcip;
  this.dstip = dstip;
  this.uprate = uprate;
}

<% initTraffictlPage(); %>

function on_chkdel(index) {
	if(index<0 || index>=traffictlRules.length)
		return;
	traffictlRules[index].select = !traffictlRules[index].select;
}

/********************************************************************
**          on document load
********************************************************************/
function on_init_page(){
	
	with(document.forms[0]) {
		if (totalBandWidthEn==0)
			totalbandwidth.value = "";
		else
			totalbandwidth.value = totalBandwidth;
		
		if(traffictl_tbl.rows){
			while(traffictl_tbl.rows.length > 1) 
				traffictl_tbl.deleteRow(1);
		}

		for(var i = 0; i < traffictlRules.length; i++)
		{
			var row = traffictl_tbl.insertRow(i + 1);
		
			row.nowrap = true;
			row.vAlign = "center";
			row.align = "left";

			var cell = row.insertCell(0);
			cell.style.color = "#404040";
			cell.align = "center";
			cell.innerHTML = traffictlRules[i].id;
			cell = row.insertCell(1);
			cell.style["color"] = "#404040";
			cell.align = "center";
			cell.innerHTML = traffictlRules[i].inf;
			cell = row.insertCell(2);
			cell.style["color"] = "#404040";
			cell.align = "center";
			cell.innerHTML = protos[traffictlRules[i].proto];
			cell = row.insertCell(3);
			cell.style["color"] = "#404040";
			cell.align = "center";
			if (traffictlRules[i].sport == "0")
				cell.innerHTML = "-";
			else
				cell.innerHTML = traffictlRules[i].sport;
			cell = row.insertCell(4);
			cell.style["color"] = "#404040";
			cell.align = "center";
			if (traffictlRules[i].dport == "0")
				cell.innerHTML = "-";
			else
				cell.innerHTML = traffictlRules[i].dport;
			cell = row.insertCell(5);
			cell.style["color"] = "#404040";
			cell.align = "center";
			if ((traffictlRules[i].srcip == "0.0.0.0/32") || (traffictlRules[i].srcip == "0.0.0.0"))
				cell.innerHTML = "-";
			else
				cell.innerHTML = traffictlRules[i].srcip;
			cell = row.insertCell(6);
			cell.style["color"] = "#404040";
			cell.align = "center";
			if ((traffictlRules[i].dstip == "0.0.0.0/32") || (traffictlRules[i].dstip == "0.0.0.0"))
				cell.innerHTML = "-";
			else
				cell.innerHTML = traffictlRules[i].dstip;
			cell = row.insertCell(7);
			cell.style["color"] = "#404040";
			cell.align = "center";
			cell.innerHTML = traffictlRules[i].uprate;
			cell = row.insertCell(8);
			cell.style["color"] = "#404040";
			cell.align = "center";
			cell.innerHTML = "<input type=\"checkbox\" onClick=\"on_chkdel(" + i + ");\">";
		}
	}
}


//apply total bandwidth limit
function on_apply_bandwidth(obj){
	
	with(document.forms[0]) {
		var sbmtstr = "applybandwidth&bandwidth=";
		var bandwidth = -1;
		if (totalbandwidth.value != "") {
			bandwidth = parseInt(totalbandwidth.value);
			if(bandwidth<0 || bandwidth >Number.MAX_VALUE)
				return;
			sbmtstr += bandwidth;
		} else {
			sbmtstr += 0;
		}
		lst.value = sbmtstr;
		obj.isclick = 1;
		postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
		submit();
	}
}

//submit traffic shaping rules
function on_submit(obj){
	var sbmtstr = "applysetting#id=";
	var firstFound = true;
	for(var i=0; i<traffictlRules.length; i++)
	{
		if(traffictlRules[i].select)
		{
			if(!firstFound)
				sbmtstr += "|";
			else
				firstFound = false;
			sbmtstr += traffictlRules[i].id;
		}
	}
	document.forms[0].lst.value = sbmtstr;
	obj.isclick = 1;
	postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
	document.forms[0].submit();
}

function onSelProt()
{
	with(document.forms[0]) {
		if (protolist.selectedIndex >= 2)
		{
			sport.disabled = false;
			dport.disabled = false;
		} else {
			sport.disabled = true;
			dport.disabled = true;
		}
	}
}

function on_Add()
{
	if (document.getElementById){  // DOM3 = IE5, NS6
		document.getElementById('tcrule').style.display = 'block';
	} else {
		if (document.layers == false) {// IE4
			document.all.tcrule.style.display = 'block';
		}
	}
	onSelProt();
}

function on_apply(obj) {
	var sbmtstr = "addsetting#";
	
	with(document.forms[0]) {
		if ((srcip.value=="") && (dstip.value=="") && (sport.value=="") && (dport.value=="") && 
			(protolist.value==0))
		{
			alert("please assign at least one condition!");			
			return;
		}
		
		if (inflist.value == 0)
		{
			inflist.focus();			
			alert('<% multilang(LANG_WAN_INTERFACE_NOT_ASSIGNED); %>');
			return;
		}

		if(srcip.value != "" && checkIP(srcip) == false)
		{
			srcip.focus();
			return;
		}
		
		if(dstip.value != "" && checkIP(dstip) == false)
		{
			dstip.focus();
			return;
		}
		
		if(srcnetmask.value != "" && checkMask(srcnetmask) == false)
		{
			srcnetmask.focus();
			return;
		}
		
		if(dstnetmask.value != "" && checkMask(dstnetmask) == false)
		{
			dstnetmask.focus();
			return;
		}
		if(sport.value <0 || sport.value > 65536)
		{
			sport.focus();			
			alert('<% multilang(LANG_SOURCE_PORT_INVALID); %>');
			return;
		}
		if (sport.value > 0 && sport.value < 65535)
		{
			if (protolist.value < 2) {
				sport.focus();				
				alert('<% multilang(LANG_PLEASE_ASSIGN_TCP_UDP); %>');
				return;
			}
		}
		if(dport.value <0 || dport.value > 65536)
		{
			dport.focus();			
			alert('<% multilang(LANG_DESTINATION_PORT_INVALID); %>');
			return;
		}
		if (dport.value > 0 && dport.value<65535)
		{
			if (protolist.value < 2) {
				dport.focus();				
				alert('<% multilang(LANG_PLEASE_ASSIGN_TCP_UDP); %>');
				return;
			}
		}
		if(uprate.value<0)
		{
			uprate.focus();			
			alert('<% multilang(LANG_UPLINK_RATE_INVALID); %>');
			return;
		}
		sbmtstr += "inf="+inflist.value+"&proto="+protolist.value+"&srcip="+srcip.value+"&srcnetmask="+srcnetmask.value+
			"&dstip="+dstip.value+"&dstnetmask="+dstnetmask.value+"&sport="+sport.value+"&dport="+dport.value+"&uprate="+uprate.value;
		lst.value = sbmtstr;
		obj.isclick = 1;
		postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
		submit();
	}
}

</script>
</head>

<body onLoad="on_init_page();">
<div class="intro_main ">
	<p class="intro_title">IP QoS <% multilang(LANG_TRAFFIC_SHAPING); %></p>
	<p class="intro_content"> <% multilang(LANG_ENTRIES_IN_THIS_TABLE_ARE_USED_FOR_TRAFFIC_CONTROL); %></p>
</div>

<form action="/boaform/formQosShape" method="post" name="qosShape">
<div class="data_common data_common_notitle">
	<table>
		<tr>
			<th><% multilang(LANG_TOTAL_BANDWIDTH_LIMIT); %>:</th>
			<td>
				<input type="text" id="totalbandwidth" size="6" maxlength="6" value="1024">Kb
			</td>
		</tr>
	</table>
</div>

<div id="traffictl_tbl" class="data_vertical data_common_notitle">
	 <div class="data_common ">
		<table>
			<tr>
				<th>ID</th>
				<th><% multilang(LANG_WAN_INTERFACE); %></th>
				<th><% multilang(LANG_PROTOCOL); %></th>
				<th><% multilang(LANG_SOURCE); %> Port</th>
				<th><% multilang(LANG_DESTINATION); %> Port</th>
				<th><% multilang(LANG_SOURCE); %> IP</th>
				<th><% multilang(LANG_DESTINATION); %> IP</th>
				<th><% multilang(LANG_RATE); %>(kb/s)</th>
				<th><% multilang(LANG_DELETE); %></th>
			</tr>
		</table>
	</div>
</div>

<div class="btn_ctl">
	<input class="link_bg" type="button" onClick="on_Add()" value="<% multilang(LANG_ADD); %>">
	<input class="link_bg" type="button" onClick="on_submit(this);" value="<% multilang(LANG_APPLY_CHANGES); %>">
	<input class="link_bg" type="button" onClick="on_apply_bandwidth(this);" value="<% multilang(LANG_APPLY_TOTAL_BANDWIDTH_LIMIT); %>">
</div>

<div id="tcrule" style="display:none">
	<div class="data_common data_common_notitle">
		<table>		
			<tr>
				<th>Interface:</th>
				<td>
				  <select id="inflist">
				    <option value=0> </option>
				    <% if_wan_list("rt"); %>
				  </select>
				</td>
			</tr>
			<tr>
				<th>Protocol:</th>
				<td>
					<select name="protolist" onClick="return onSelProt()">
						<option value="0">NONE</option>
						<option value="1">ICMP</option>
						<option value="2">TCP </option>
						<option value="3">UDP </option>
						<option value="4">TCP/UDP</option>
					</select>
				</td>
			</tr>
			<tr>
				<th>Src IP:</th>
				<td><input type="text" name="srcip" size="15" maxlength="15" style="width:150px"></td>
			</tr>
			<tr>
				<th>Src Mask:</th>
				<td><input type="text" name="srcnetmask" size="15" maxlength="15" style="width:150px"></td>
			</tr>
			<tr>
				<th>Dst IP:</th>
				<td><input type="text" name="dstip" size="15" maxlength="15" style="width:150px"></td>
			</tr>
			<tr>
				<th>Dst Mask:</th>
				<td><input type="text" name="dstnetmask" size="15" maxlength="15" style="width:150px"></td>
			</tr>
			<tr>
				<th>Src Port:</th>
				<td><input type="text" name="sport" size="6" style="width:80px"></td>
			</tr>
			<tr>
				<th>Dst Port:</th>
				<td><input type="text" name="dport" size="6" style="width:80px"></td>
			</tr>
			<tr>
				<th>uplink rate:</th>
				<td><input type="text" name="uprate" size="6" style="width:80px">kb/s</td>
			</tr>
		</table>
	</div>
	<div class="btn_ctl">
		<input class="link_bg" type="button" name="apply" value="save" onClick="on_apply(on_submit);">
	</div>
</div>
<input type="hidden" id="lst" name="lst" value="">
<input type="hidden" name="submit-url" value="/ipqos_shape.asp">
<input type="hidden" name="postSecurityFlag" value="">
</form>
</body>
</html>

