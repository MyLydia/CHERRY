<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<!--系统默认模板-->
<HTML>
<HEAD>
<TITLE>IPv6 静态路由</TITLE>
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
function postGW( enable, destNet, prefixLen, nextHop, interface, select )
{
	document.route.enable.checked = enable;
	document.route.destNet.value=destNet;
	document.route.prefixLen.value=prefixLen;
	document.route.nextHop.value=nextHop;
	document.route.interface.value=interface;	
	document.route.select_id.value=select;	
}

function checkDest(ip, mask)
{
	var i, dip, dmask, nip;

	for (i=1; i<=4; i++) {
		dip = getDigit(ip.value, i);
		dmask = getDigit(mask.value,  i);
		nip = dip & dmask;
		if (nip != dip)
			return true;
	}
	return false;
}

function addClick()
{
	/*if (document.route.destNet.value=="") {
		alert("Enter Destination Network ID !");
		document.route.destNet.focus();
		return false;
	}
	
	if ( validateKey( document.route.destNet.value ) == 0 ) {
		alert("Invalid Destination value.");
		document.route.destNet.focus();
		return false;
	}
	if ( !checkDigitRange(document.route.destNet.value,1,0,255) ) {
		alert('Invalid Destination range in 1st digit. It should be 0-255.');
		document.route.destNet.focus();
		return false;
	}
	if ( !checkDigitRange(document.route.destNet.value,2,0,255) ) {
		alert('Invalid Destination range in 2nd digit. It should be 0-255.');
		document.route.destNet.focus();
		return false;
	}
	if ( !checkDigitRange(document.route.destNet.value,3,0,255) ) {
		alert('Invalid Destination range in 3rd digit. It should be 0-255.');
		document.route.destNet.focus();
		return false;
	}
	if ( !checkDigitRange(document.route.destNet.value,4,0,254) ) {
		alert('Invalid Destination range in 4th digit. It should be 0-254.');
		document.route.destNet.focus();
		return false;
	}
	
	if (document.route.subMask.value=="") {
		alert("Enter Subnet Mask !");
		document.route.subMask.focus();
		return false;
	}
	
	if ( validateKey( document.route.subMask.value ) == 0 ) {
		alert("Invalid Subnet Mask value.");
		document.route.subMask.focus();
		return false;
	}
	if ( !checkDigitRange(document.route.subMask.value,1,0,255) ) {
		alert('Invalid Subnet Mask range in 1st digit. It should be 0-255.');
		document.route.subMask.focus();
		return false;
	}
	if ( !checkDigitRange(document.route.subMask.value,2,0,255) ) {
		alert('Invalid Subnet Mask range in 2nd digit. It should be 0-255.');
		document.route.subMask.focus();
		return false;
	}
	if ( !checkDigitRange(document.route.subMask.value,3,0,255) ) {
		alert('Invalid Subnet Mask range in 3rd digit. It should be 0-255.');
		document.route.subMask.focus();
		return false;
	}
	if ( !checkDigitRange(document.route.subMask.value,4,0,255) ) {
		alert('Invalid Subnet Mask range in 4th digit. It should be 0-255.');
		document.route.subMask.focus();
		return false;
	}
	if (document.route.interface.value==65535) {
	if (document.route.nextHop.value=="" ) {
		alert("Enter Next Hop IP or select a GW interface!");
		document.route.nextHop.focus();
		return false;
	}
	
	if ( validateKey( document.route.nextHop.value ) == 0 ) {
		alert("Invalid Next Hop value.");
		document.route.nextHop.focus();
		return false;
	}
	if ( !checkDigitRange(document.route.nextHop.value,1,0,255) ) {
		alert('Invalid Next Hop range in 1st digit. It should be 0-255.');
		document.route.nextHop.focus();
		return false;
	}
	if ( !checkDigitRange(document.route.nextHop.value,2,0,255) ) {
		alert('Invalid Next Hop range in 2nd digit. It should be 0-255.');
		document.route.nextHop.focus();
		return false;
	}
	if ( !checkDigitRange(document.route.nextHop.value,3,0,255) ) {
		alert('Invalid Next Hop range in 3rd digit. It should be 0-255.');
		document.route.nextHop.focus();
		return false;
	}
	if ( !checkDigitRange(document.route.nextHop.value,4,1,254) ) {
		alert('Invalid Next Hop range in 4th digit. It should be 1-254.');
		document.route.nextHop.focus();
		return false;
	}*/

    //check destination
	if ( validateKeyV6IP( document.route.destNet.value ) == 0 ) {
           if(! validateKeyV6Prefix( document.route.destNet.value) )
           {
				alert("destNet 不是有效的 ipv6 网域!");
				document.route.destNet.focus();
				return false;
		   }
	}
    else if (! isGlobalIpv6Address( document.route.destNet.value) )
	{
		alert("destNet 不是有效的 ipv6 主机!");
		document.route.destNet.focus();
		return false;
	}

	if (( document.route.prefixLen.value == '')
	|| (!isNumber(document.route.prefixLen.value))
	|| (parseInt(document.route.prefixLen.value) > 128)
	|| (parseInt(document.route.prefixLen.value) < 0))
	{
		alert('前缀长度错误!');
		document.route.prefixLen.focus();
		return false;
	}

    //check Next Hop
	if (document.route.nextHop.value=="" ) {
		alert("输入Next Hop IP 或选择一个 GW 界面!");
		document.route.nextHop.focus();
		return false;
	}

	if ( validateKeyV6IP( document.route.nextHop.value ) == 0 ) {
		alert("Next Hop的值无效");
		document.route.nextHop.focus();
		return false;
	}
    else
	{
		if (! isUnicastIpv6Address( document.route.nextHop.value) ){
			alert("Next Hop不是有效的全球和单播 ipv6 地址!");
			document.route.nextHop.focus();
			return false;
		}
	}
/*
	if ( !checkDigitRange(document.route.metric.value,1,0,16) ) {
		alert('Metric无效. 合理范围是 0~16.');
		document.route.metric.focus();
		return false;
	}
*/
	
	return true;
}

function routeClick(url)
{
	var wide=600;
	var high=400;
	if (document.all)
		var xMax = screen.width, yMax = screen.height;
	else if (document.layers)
		var xMax = window.outerWidth, yMax = window.outerHeight;
	else
	   var xMax = 640, yMax=480;
	var xOffset = (xMax - wide)/2;
	var yOffset = (yMax - high)/3;

	var settings = 'width='+wide+',height='+high+',screenX='+xOffset+',screenY='+yOffset+',top='+yOffset+',left='+xOffset+', resizable=yes, toolbar=no,location=no,directories=no,status=no,menubar=no,scrollbars=yes';

	window.open( url, 'RouteTbl', settings );
}
	
</SCRIPT>
</head>

<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000">
<blockquote>
<DIV align="left" style="padding-left:20px; padding-top:5px">

<form action=/boaform/formIPv6Routing method=POST name="route">
<div class="tip" style="width:90% ">
	<b>路由 -- IPv6 静态路由</b><br><br>	
</div>
<table border=0 width="600" cellspacing=4 cellpadding=0>
  <tr><hr class="sep" size=1 noshade align=top></tr>
  <tr>
      <td width="30%">使能:</td>
      <td width="70%"><input type="checkbox" name="enable" value="1" checked></td>
  </tr>
  <tr>
      <td width="30%">目的:</td>
      <td width="70%"><input type="text" name="destNet" size="64" maxlength="64"></td>
  </tr>
  <tr>
      <td width="30%">前缀长度:</td>
      <td width="70%"><input type="text" name="prefixLen" size="64" maxlength="64"></td>
  </tr>
  <tr>
      <td width="30%">网关:</td>
      <td width="70%"><input type="text" name="nextHop" size="64" maxlength="64"></td>
  </tr>
  <!--<tr>
      <td width="30%">Metric:</td>
      <td width="70%"><input type="text" name="metric" size="5" maxlength="5"></td>
  </tr>-->
  <tr>
      <td width="30%">接口:</td>
      <td width="70%"><select name="interface">
          <%  if_wan_list("rtv6-any-vpn");%>
      	</select></td>
  </tr>
  <input type="hidden" value="" name="select_id">
</table>
  <input class="btnaddup"  type="submit" value="添加" name="addV6Route" onClick="return addClick()">&nbsp;&nbsp;
  <input class="btnsaveup"  type="submit" value="更新" name="updateV6Route" onClick="return addClick()">&nbsp;&nbsp;
  <input class="btndeleup"  type="submit" value="删除" name="delV6Route" onClick="return deleteClick()">&nbsp;&nbsp;
  <!--<input class="btnaddup"  type="button" value="显示路由" name="showRoute" onClick="routeClick('/routetbl.asp')">-->
  </tr>
  <tr><hr class="sep" size=1 noshade align=top></tr>
<table border=0 width="600" cellspacing=4 cellpadding=0>
  <tr>IPv6 静态路由表:</tr>
  <% showIPv6StaticRoute(); %>
</table>
  <br>
      <input type="hidden" value="/routing_ipv6.asp" name="submit-url">
		<!--
		<% GetDefaultGateway(); %>
		-->
</form>
</DIV>
</blockquote>
</body>

</html>
