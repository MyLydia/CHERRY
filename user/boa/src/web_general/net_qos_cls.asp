<%SendWebHeadStr(); %>
<TITLE>QoS <% multilang(LANG_CLASSIFICATION); %></TITLE>
<style>
#pull_arrow {
    background-color: #ccc;
    border: 2px outset #efefef;
    cursor: pointer;
    float: left;
    padding: 1px 2px 2px 0;
}

#QoSList_Block {
    background-color: #ffffff;
    border: 1px outset #999;
    display: none;
    height: 400px;
    margin-left: 1px;
    margin-top: 25px;
    overflow-y: auto;
    padding: 1px;
    position: absolute;
    text-align: left;
    z-index: 200;
	left: 8px;
	top: 38px;
}

.position_a{
	position: relative;
}

</style>

<SCRIPT language="javascript" type="text/javascript">

var dscps = new it_nr("dscplst", 
 new it(0, ""),
 new it(1, "Default(000000)"), 
 new it(57,  "AF13(001110)"), 
 new it(49,  "AF12(001100)"), 
 new it(41,  "AF11(001010)"),
 new it(33,  "CS1(001000)"),
 new it(89,  "AF23(010110)"),
 new it(81,  "AF22(010100)"),
 new it(73,  "AF21(010010)"),
 new it(65,  "CS2(010000)"),
 new it(121, "AF33(011110)"),
 new it(113, "AF32(011100)"),
 new it(105, "AF31(011010)"),
 new it(97,  "CS3(011000)"),
 new it(153, "AF43(100110)"),
 new it(145, "AF42(100100)"),
 new it(137, "AF41(100010)"),
 new it(129, "CS4(100000)"),
 new it(185, "EF(101110)"),
 new it(161, "CS5(101000)"),
 new it(193, "CS6(110000)"),
 new it(225, "CS7(111000)")
);

var iffs = new Array("", "LAN_1", "LAN_2", "LAN_3", "LAN_4");
<!--var protos = new Array("", "ICMP", "TCP", "UDP", "TCP/UDP");-->
var protos = new Array("", "TCP", "UDP", "ICMP", "TCP/UDP");
var rules = new Array();
<% initQosRulePage(); %>

function button_onoff_image(enable)
{
	if (enable)
		return "image src='graphics/button-on.png'";
	else
		return "image src='graphics/button-off.png'";
}

function button_onoff_html(index, item)
{
	var str;
	
	str = "<"+button_onoff_image(rules[index].state)+" onClick=on_onoffClick("+index+","+item+"); />";
	return str;
}

function on_chkclick(index)
{
	if(index < 0 || index >= rules.length)
		return; 
	rules[index].select = !rules[index].select;
}

function on_onedit(index)
{
	if(index < 0 || index >= rules.length)
		return;
	window.location.href = "net_qos_cls_edit.asp?rule_index="+rules[index].index+"&rule=" + rules[index].enc();
}

function on_onoffClick(index, item)
{
	if(index < 0 || index >= rules.length)
		return;
	rules[index].state = !rules[index].state;
	if (rules[index].state != 0)
		lstrc.rows[index+2].bgColor = "#FFFFFF";
	else
		lstrc.rows[index+2].bgColor = "#EEEEEE";
	lstrc.rows[index+2].cells[item].innerHTML = button_onoff_html(index, item);
}

/********************************************************************
**          on document load
********************************************************************/
function on_init()
{
	if(lstrc.rows){while(lstrc.rows.length > 2) lstrc.deleteRow(2);}
	for(var i = 0; i < rules.length; i++)
	{

		//var bcheck = " ";
		var account = 0;
		var row = lstrc.insertRow(i + 2);
		var strprio = "";
		row.nowrap = true;
		row.vAlign = "center";
		row.align = "left";

		var cell = row.insertCell(account);
		account = account +1;
		cell.innerHTML = rules[i].index;
		cell = row.insertCell(account);
		account = account +1;
		cell.innerHTML = rules[i].name;
		cell = row.insertCell(account);
		account = account +1;
		cell.innerHTML = rules[i].qos_order;
		/*
		cell = row.insertCell(account);
		account = account +1;
		if(rules[i].mvid==0)
			cell.innerHTML = "<br>";
		else
			cell.innerHTML = rules[i].mvid;
		*/
		
		cell = row.insertCell(account);
		account = account +1;
		if (rules[i].mdscp != "0") {
			cell.innerHTML = "0x"+(rules[i].mdscp-1).toString(16);
		} else
			cell.innerHTML = " <br>";		

		cell = row.insertCell(account);
		account = account +1;
		if (rules[i].m1p != "0") {
			cell.innerHTML = rules[i].m1p-1;
		} else
			cell.innerHTML = "<br> ";
		

		cell = row.insertCell(account);
		account = account +1;
		cell.innerHTML = rules[i].prio;

		cell = row.insertCell(account);
		account = account +1;
		cell.innerHTML = rules[i].wanifname;

		cell = row.insertCell(account);
		account = account +1;
		switch(rules[i].ipqos_rule_type)
		{
			case 0:
				cell.innerHTML =  "<b>Port Base<br></b>";
				switch(rules[i].phypt)
				{
					case 1:	
						cell.innerHTML +=  "LAN1<br>";
						break;
					case 2:	
						cell.innerHTML +=  "LAN2<br>";
						break;
					case 3:	
						cell.innerHTML +=  "LAN3<br>";
						break;
					case 4:	
						cell.innerHTML +=  "LAN4<br>";
						break;
				}
				break;
			case 1:
				cell.innerHTML =  "<b>EtherType Base<br></b>";
				cell.innerHTML +="0x"+rules[i].ethType;
				break;
			case 2:
				cell.innerHTML =  "<b>IP/Protocol Base<br></b>";
				
				switch(rules[i].proto)
				{
					case 0:
						break;
					case 1:
						cell.innerHTML+= "Protocol: "+  "TCP<br>";
						break;
					case 2:
						cell.innerHTML+= "Protocol: "+  "UDP<br>";
						break;
					case 3:
						cell.innerHTML+= "Protocol: "+  "ICMP<br>";
						break;
					case 4:
						cell.innerHTML+= "Protocol: "+  "TCP/UDP<br>";
						break;
				}
				if(rules[i].dscp == 0)
					;
				else
						cell.innerHTML+= "DSCP: "+dscps[rules[i].dscp]+"<br>";
				switch(rules[i].IpProtocolType)
				{
					case 1:
						if(rules[i].sip!= "0.0.0.0")
							{
								cell.innerHTML += "Source IP:        "+  rules[i].sip+"<br>";
								cell.innerHTML += "Source Mask:        "+  rules[i].smsk+"<br>";
							}
						if(rules[i].dip!= "0.0.0.0")
							{
								cell.innerHTML += "Destination IP:        "+  rules[i].dip+"<br>";
								cell.innerHTML += "Destination Mask:        "+  rules[i].dmsk+"<br>";
							}
						break;
					case 2:
						if (rules[i].sip6 != "::")
							{	
								if(rules[i].sip6PrefixLen == "")
									cell.innerHTML += "Source IP:        "+  rules[i].sip6+"<br>";
								else
									cell.innerHTML += "Source IP:        "+   rules[i].sip6 + "/" + rules[i].sip6PrefixLen+"<br>";		
							}
						break;	
				}
				if(rules[i].spts != "0" || rules[i].spte != "0")
					{
						cell.innerHTML+= "Source Port: ";
						if(rules[i].spte == "0")
							cell.innerHTML+=rules[i].spts + ":"+"<br>";
						else
							cell.innerHTML+=rules[i].spts + ":" + rules[i].spte+"<br>";
					}
				if(rules[i].dpts != "0" || rules[i].dpte != "0")
					{
						cell.innerHTML+= "Destination Port: ";
						if(rules[i].dpte == "0")
							cell.innerHTML+=rules[i].dpts + ":"+"<br>";
						else
							cell.innerHTML+=rules[i].dpts + ":" + rules[i].dpte+"<br>";
					}
				break;
			case 3:
				cell.innerHTML =  "<b>MAC Address Base<br></b>";
				cell.innerHTML += "Source MAC:        "+  ((rules[i].smac=="00:00:00:00:00:00")?"":rules[i].smac)+"<br>";
				cell.innerHTML += "Destination MAC:"+  ((rules[i].dmac=="00:00:00:00:00:00")?"":rules[i].dmac)+"<br>";
				break;
			case 4:
				cell.innerHTML =  "<b>DHCP Option Base<br></b>";      
				if(typeof rules[i].dhcpopt_type_select !== "undefined")
				{
					switch(rules[i].dhcpopt_type_select)
					{
						case "0":  //option 60
							cell.innerHTML +=  "Option 60<br>";      	
							cell.innerHTML +=  "Vendor Class ID:"+rules[i].opt60_vendorclass;      
							break;
						case "1":  //option 61
							cell.innerHTML +=  "Option 61<br>";      	
							switch(rules[i].dhcpopt61_DUID_select)
							{
								case "0":
									cell.innerHTML +=  "DUID Type: DUID_LLT<br>";      
									cell.innerHTML +=  "IAID: "+rules[i].opt61_iaid+"<br>";      
									cell.innerHTML +=  "Hardware Type:"+rules[i].duid_hw_type+"<br>";      
									cell.innerHTML +=  "Time"+rules[i].duid_time+"<br>";  
									cell.innerHTML +=  "Link-layer Address"+rules[i].duid_mac+"<br>";  
									break;	
								case "1":
									cell.innerHTML +=  "DUID Type: DUID_EN<br>";      
									cell.innerHTML +=  "IAID: "+rules[i].opt61_iaid+"<br>";      
									cell.innerHTML +=  "Enterprise Number: "+rules[i].duid_ent_num+"<br>";      
									cell.innerHTML +=  "Identifier: "+rules[i].duid_ent_id+"<br>";  
									break;
								case "2":
									cell.innerHTML +=  "DUID Type: DUID_LL<br>";      
									cell.innerHTML +=  "IAID: "+rules[i].opt61_iaid+"<br>";     
									cell.innerHTML +=  "Hardware Type: "+rules[i].duid_hw_type+"<br>";       
									cell.innerHTML +=  "Link-layer Address: "+rules[i].duid_mac+"<br>";  
									break;
							}
							break;
						case "2":  //option 125
							cell.innerHTML +=  "Option 125<br>";      	
							cell.innerHTML +=  "Enterprise Number: "+rules[i].opt125_ent_num+"<br>";     
							cell.innerHTML +=  "Manufacturer OUI: "+rules[i].opt125_manufacturer+"<br>";     
							cell.innerHTML +=  "Product Class: "+rules[i].opt125_product_class+"<br>";     
							cell.innerHTML +=  "Model Name: "+rules[i].opt125_model+"<br>";     
							cell.innerHTML +=  "Serial Number: "+rules[i].opt125_serial+"<br>";   
							break;														
					}
				}
				break;
			default:
				break;
		}		
		cell = row.insertCell(account);
		account = account +1;
		cell.align = "center";
		cell.innerHTML = "<input type=\"checkbox\" onClick=\"on_chkclick(" + i + ");\">";
		cell = row.insertCell(account);
		account = account +1;
		cell.align = "center";
		cell.innerHTML = "<input type=\"button\" onClick=\"on_onedit(" + i + ");\" value=\"Edit\">";
		cell = row.insertCell(account);
		account = account +1;
		cell.innerHTML = button_onoff_html(i, account);
		if (rules[i].state != 0)
			row.bgColor = "#FFFFFF";
		else
			row.bgColor = "#EEEEEE";
	}
}

function rc2string(it)
{
	return it.index + "," + Number(it.state) + "," + Number(it.select);// + "|" + it.tporte + "|" + it.oprotocol + "|" + it.oportb + "|" + it.oporte; 
}

/********************************************************************
**          on document submit
********************************************************************/
function on_submit() 
{
	var tmplst = "";
	var first = true;

	if (rules.length == 0)
		return;
	
	with ( document.forms[0] ) 
	{
		for(var i = 0; i < rules.length; i++)
		{
			if(first)
			{
				first = false;
			}
			else 
			{
				tmplst += "&";
			}
			tmplst += rc2string(rules[i]);
		}
		lst.value = tmplst;
		
		postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
		
		submit();
	}
}

</SCRIPT>
</HEAD>

<body onLoad="on_init();">
<div class="intro_main ">
	<p class="intro_title">QoS <% multilang(LANG_CLASSIFICATION); %></p>
	<p class="intro_content"> <% multilang(LANG_PAGE_DESC_CLASSICY_QOS_RULE); %><font color="red">(<% multilang(LANG_PAGE_DESC_CLASSICY_QOS_RULE_EXTRA); %>)</font></p>
</div>

<form id="form" action="/boaform/admin/formQosRule" method="post">
<div class="data_common data_common_notitle">
	<div class="data_common data_vertical">
		<table id="lstrc" >
			<tr>
				<th colspan="2">&nbsp;</th>
				<th colspan="3" align="center"><% multilang(LANG_MARK); %></th>
				<th colspan="3"><% multilang(LANG_CLASSIFICATION_RULES); %></th>
				<th colspan="3" align="center">&nbsp;</th>
			</tr>
			<tr>
				<td><% multilang(LANG_ID); %></td>
				<td><% multilang(LANG_NAME); %></td>
				<td>Order</td>
				<!--<td><% multilang(LANG_VLAN_ID); %></td>-->
				<td>DSCP <% multilang(LANG_MARK); %></td>
				<td><% multilang(LANG_802_1P); %></td>         
				<td> <% multilang(LANG_QUEUE); %></td>
				<td> <% multilang(LANG_WANIF); %></td>
				<td><% multilang(LANG_RULE_DETAIL); %></td>					
				<td><% multilang(LANG_DELETE); %></td>
				<td><% multilang(LANG_EDIT); %></td>	
				<td>&nbsp;</td>
			</tr>
		</table>
	</div>
</div>
<div class=btn_ctl>
	<input class=link_bg type="button" class="button" onClick="location.href='net_qos_cls_edit.asp';" value="<% multilang(LANG_ADD); %>">
	<input class=link_bg type="button" class="button" onClick="on_submit();" value="<% multilang(LANG_APPLY_CHANGES); %>">
	<input type="hidden" id="lst" name="lst" value="">
	<input type="hidden" name="submit-url" value="/net_qos_cls.asp">
	<input type="hidden" name="postSecurityFlag" value="">
</div>
</form>
</body>
</html>
