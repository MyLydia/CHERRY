<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<!--ϵͳĬ��ģ��-->
<HTML>
<HEAD>
<TITLE>��̬·��</TITLE>
<style type="text/css">
        .child { position: absolute; bottom: 20; left:50%; margin-left:-150px; }
</style>
<META http-equiv=pragma content=no-cache>
<META http-equiv=cache-control content="no-cache, must-revalidate">
<META http-equiv=content-type content="text/html; charset=gbk">
<META http-equiv=content-script-type content=text/javascript>
<!--ϵͳ����css-->
<STYLE type=text/css>
@import url(/style/default.css);
</STYLE>
<!--ϵͳ�����ű�-->
<SCRIPT language="javascript" src="common.js"></SCRIPT>
<script type="text/javascript" src="share.js"></script>
<STYLE type=text/css>
@import url(/style/default.css);
</STYLE>
<SCRIPT language="javascript" type="text/javascript">

function postGWv6( enable, destNet, prefixLen, nextHop, interface, select )
{
	document.routev6.enable.checked = enable;
	document.routev6.destNet.value=destNet;
	document.routev6.prefixLen.value=prefixLen;
	document.routev6.nextHop.value=nextHop;
	document.routev6.interface.value=interface;	
	document.routev6.select_id.value=select;	
}

function addClickv6()
{
    //check destination
	if ( validateKeyV6IP( document.routev6.destNet.value ) == 0 ) {
           if(! validateKeyV6Prefix( document.routev6.destNet.value) )
           {
				alert("destNet ������Ч�� ipv6 ����!");
				document.routev6.destNet.focus();
				return false;
		   }
	}
    else if (! isGlobalIpv6Address( document.routev6.destNet.value) )
	{
		alert("destNet ������Ч�� ipv6 ����!");
		document.routev6.destNet.focus();
		return false;
	}

	if (( document.routev6.prefixLen.value == '')
	|| (!isNumber(document.routev6.prefixLen.value))
	|| (parseInt(document.routev6.prefixLen.value) > 128)
	|| (parseInt(document.routev6.prefixLen.value) < 0))
	{
		alert('ǰ׺���ȴ���!');
		document.routev6.prefixLen.focus();
		return false;
	}

    //check Next Hop
	if(document.routev6.nextHopEnable.checked==true)
	{
		if (document.routev6.nextHop.value=="" ) {
			alert("����Next Hop IP ��ѡ��һ�� GW ����!");
			document.routev6.nextHop.focus();
			return false;
		}

		if ( validateKeyV6IP( document.routev6.nextHop.value ) == 0 ) {
			alert("Next Hop��ֵ��Ч");
			document.routev6.nextHop.focus();
			return false;
		}
		else
		{
			if (! isUnicastIpv6Address( document.routev6.nextHop.value) ){
				alert("Next Hop������Ч��ȫ��͵��� ipv6 ��ַ!");
				document.routev6.nextHop.focus();
				return false;
			}
		}
	}
	changeListMenu(0);
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

function changeListMenu(isIpv6)
{
	var i=0;
	var lstmenu = parent.document.getElementById("lstmenu").rows[0].cells[0];
	if ( isIpv6 )
	{
		lstmenu.innerHTML = "<br><p>&nbsp;&nbsp;<a id=\"thirdmenufont"+i+"\" onClick=\"on_thirdmenu(" + i + ")\"; style=\"color:#fff45c\" href=\"" + "routing_cmcc.asp" + "\", target=\"contentIframe\">" + "IPv6��̬·��" + "</a></p>";
	}
	else
	{
		lstmenu.innerHTML = "<br><p>&nbsp;&nbsp;<a id=\"thirdmenufont"+i+"\" onClick=\"on_thirdmenu(" + i + ")\"; style=\"color:#fff45c\" href=\"" + "routing_cmcc.asp" + "\", target=\"contentIframe\">" + "��̬·��" + "</a></p>";
	}
}


function backMain()
{
	changeListMenu(0);
	window.location.href='/routing_cmcc.asp';
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
</SCRIPT>
</head>

<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000">
<blockquote>
<DIV align="left" style="padding-left:20px; padding-top:5px">
<form action=/boaform/formIPv6Routing method=POST name="routev6">
<div class="tip" style="width:90% ">
	<br><br>	
</div>
<table border=0 width="600" cellspacing=4 cellpadding=0>
  <tr>
      <td width="30%">��̬·��:</td>
      <td width="70%"><input type="checkbox" name="enable" value="1" checked>ʹ��</td>
  </tr>
  <tr>
      <td width="30%">Ŀ�������ַ:</td>
      <td width="70%"><input type="text" name="destNet" size="64" maxlength="64"></td>
  </tr>
  <tr>
      <td width="30%">ǰ׺����:</td>
      <td width="70%"><input type="text" name="prefixLen" size="64" maxlength="64"></td>
  </tr>
  <tr>
      <td width="30%"><input type="checkbox" name="nextHopEnable" value=0 onChange="checkChange(this)">Ĭ������</td>
      <td width="70%"><input type="text" name="nextHop" size="64" maxlength="64"></td>
  </tr>
  <tr>
      <td width="30%">ʹ�ýӿ�:</td>
      <td width="70%"><select name="interface">
          <%  if_wan_list("rtv6");%>
      	</select></td>
  </tr>
  <input type="hidden" value="" name="select_id">
</table>
 <div class="child">
  <tr>
  <center>
		<input class="btnsaveup"  type="submit" value="ȷ��" name="addV6Route" onClick="return addClickv6()">&nbsp;&nbsp;
		<input class="btndeleup_2"  type="button" value="ȡ��" name="delV6Route" onclick="backMain()">&nbsp;&nbsp;
		<input type="hidden" value="/routing_cmcc.asp" name="submit-url">
  </center>
  </tr>
 </div>
</form>
</DIV>
</blockquote>
</body>

</html>
