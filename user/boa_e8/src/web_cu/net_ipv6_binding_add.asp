
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<!--系统默认模板-->
<HTML>
<HEAD>
<TITLE>IPv6地址绑定</TITLE>
<style type="text/css">
        .child { position: absolute; bottom: 20; left:50%; margin-left:-150px; }
</style>
<META http-equiv=pragma content=no-cache>
<META http-equiv=cache-control content="no-cache, must-revalidate">
<META http-equiv=content-type content="text/html; charset=gbk">
<META http-equiv=content-script-type content=text/javascript>
<!--系统公共css-->
<STYLE type=text/css>
@import url(/style/default.css);
</STYLE>
<!--系统公共脚本-->
<SCRIPT language="javascript" src="common.js"></SCRIPT>
<script type="text/javascript" src="share.js"></script>
<STYLE type=text/css>
@import url(/style/default.css);
</STYLE>
<SCRIPT language="javascript" type="text/javascript">
//var vlan_mapping_interface = <% checkWrite("vlan_mapping_interface"); %>;
var vlan_mapping_interface = ["LAN1","LAN2","LAN3","LAN4","SSID1","SSID2"];

<% initVlanRange(); %>

function getIpv6BindRadioValue()
{	
	for(var i = 0; i < document.ipv6binding.bindmode.length; i++ )
	{
		if(document.ipv6binding.bindmode[i].checked){
			return document.ipv6binding.bindmode[i].value;
		}
	}
	return -1;
}

function addClickv6()
{
    //check destination
    var ipAddr = document.ipv6binding.addr.value;
	if ( validateKeyV6IP( ipAddr ) == 0 ) {
           if(! validateKeyV6Prefix( ipAddr) )
           {
				alert("不是有效的 ipv6 网域!");
				document.ipv6binding.addr.focus();
				return false;
		   }
	}
    else if (! isGlobalIpv6Address( ipAddr) )
	{
		alert("destNet 不是有效的 ipv6 主机!");
		document.ipv6binding.addr.focus();
		return false;
	}

	if (( document.ipv6binding.prefixLen.value == '')
	|| (!isNumber(document.ipv6binding.prefixLen.value))
	|| (parseInt(document.ipv6binding.prefixLen.value) > 128)
	|| (parseInt(document.ipv6binding.prefixLen.value) <= 0))
	{
		alert('前缀长度错误!');
		document.ipv6binding.prefixLen.focus();
		return false;
	}
	if(getIpv6BindRadioValue() == 1)
	{
		if (document.ipv6binding.vlan_id.value == "" )
		{
			alert("vlan id不能为空！");
			return false;
		}
		if (!isNumber(document.ipv6binding.vlan_id.value) ||
			(parseInt(document.ipv6binding.vlan_id.value, 10) >4095 ||parseInt(document.ipv6binding.vlan_id.value, 10)<0 )			)
		{
			alert("vlan id的范围是0~4095！");
			return false;
		}
	}
	
	return true;
}

function backMain()
{
	//changeListMenu(0);
	window.location.href='/net_ipv6_binding.asp';
}

function checkChange(cb)
{
	if(cb.checked==true){
		cb.value = 1;
	}
	else{
		cb.value = 0;
	}
}	

function changeMode(id)
{
	var _port = document.getElementById( "id_port" );
	var _vlan = document.getElementById( "id_vlan" );
	if(id == 0)
	{
		_port.style.display = "block";
		_vlan.style.display = "none";
	}
	else
	{
		_port.style.display = "none";
		_vlan.style.display = "block";
	}
}

function addline(index)
{
	var newline;
	var mode= getValue('Mode'+index);
	newline = document.getElementById('Special_Table').insertRow(-1);
	newline.nowrap = true;
	newline.vAlign = "top";
	newline.align = "center";
	newline.onclick = function() {ModifyInstance(this, index)};
	newline.setAttribute("class","white");
	newline.setAttribute("className","white");
	newline.insertCell(-1).innerHTML = convertDisplay(index, 0);
	newline.insertCell(-1).innerHTML = convertDisplay(mode,1);
	newline.insertCell(-1).innerHTML = (mode==0)?"--":convertDisplay(index, 2);
}

function showPortList()
{
	//var num = getValue('if_instnum');
	var num = vlan_mapping_interface.length;
	var port = vlan_mapping_interface;
	var x=document.getElementById("portList");
  
	if (num!=0) {
		for (var i=0; i<num; i++) {
			if (port[i] == "SSID_DISABLE") {
				continue;
			}
			var option=document.createElement("option");
			option.text=port[i];
			option.value = i;
			x.add(option,null);
		}
	}
}

function on_init()
{
	showPortList();
}


</SCRIPT>
</head>

<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000" onLoad="on_init();">
<blockquote>
<DIV align="left" style="padding-left:20px; padding-top:5px">
<form action=/boaform/formIPv6Binding method=POST name="ipv6binding">
<div class="tip" style="width:90% ">
	<br><br>	
</div>
<table border=0 width="600" cellspacing=4 cellpadding=0>
  <tr>
      <td width="30%">IPv6地址:</td>
      <td width="70%"><input type="text" name="addr" size="64" maxlength="64"></td>
  </tr>
  <tr>
      <td width="30%">前缀长度:</td>
      <td width="70%"><input type="text" name="prefixLen" size="64" maxlength="64" value="128"></td>
  </tr>
  <tr>
      <td width="30%">绑定模式:</td>
      <td width=350>
	      <input type="radio" name="bindmode" value=0 checked="checked" onclick="changeMode(0)">端口绑定&nbsp;&nbsp;
	      <input type="radio" name="bindmode" value=1 onclick="changeMode(1)">VLAN绑定</td>
  </tr>
</table>
<table id="id_port" style="display:block" border=0 width="600" cellspacing=4 cellpadding=0>
  <tr>
      <td width="30%">端口号:</td>
      <td width="70%">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
      <select name="portList" id="portList" >
      </select></td>
  </tr>
</table>
<table id="id_vlan" style="display:none" border=0 width="600" cellspacing=4 cellpadding=0>
  <tr>
      <td width="30%">VLAN ID:</td>
      <td width="70%"><input type="text" name="vlan_id" size="64" maxlength="64"></td>
  </tr>
</table>
 
 <div class="child">
  <tr>
  <center>
		<input class="btnsaveup"  type="submit" value="确定" name="addV6Route" onClick="return addClickv6()">&nbsp;&nbsp;
		<input class="btndeleup_2"  type="button" value="取消" name="delV6Route" onclick="backMain()">&nbsp;&nbsp;
		<input type="hidden" value="/net_ipv6_binding.asp" name="submit-url">
  </center>
  </tr>
 </div>
</form>
</DIV>
</blockquote>
</body>

</html>
